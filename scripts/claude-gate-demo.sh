#!/usr/bin/env bash
# Runs the Claude Code shim-presence lab fixture end to end and asserts
# every step.
#
# Builds barmkin into a temporary directory and serves `barmkin monitor`
# there, in a deployment laid out for the current user. Each simulated tool
# call feeds one PreToolUse hook input to the managed `barmkin gate`. When
# the shim is "loaded", the session is registered and the call
# pre-registered as the shim's hooks module does it (the same content-free
# register and preregister requests of internal/proto, sent with curl over
# the socket), with the pre-registration still in flight as the gate
# starts. It shows that a call without a live pre-registration (no shim,
# broken shim, replayed, expired, malformed, refused posture, monitor down)
# is denied with exit 2, and that a pre-registered call reaches the monitor
# and is allowed. Exits non-zero on the first unexpected result. Nothing
# outside the temporary directory is touched.
#
# The shim module itself only runs inside Claude Code: its own tests run
# under `claude plugin test` (make shim-test), and scripts/claude-lock-lab.sh
# runs it in live sessions under the full managed lock.
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in curl go; do
	command -v "$tool" >/dev/null || { echo "SKIP: $tool not found" >&2; exit 77; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/bmk.XXXXXX")
# Unix socket paths are limited to ~108 bytes.
if (( ${#work} > 80 )); then
	rmdir "$work"
	work=$(mktemp -d /tmp/bmk.XXXXXX)
fi
# The monitor's deployment: a runtime directory for the socket and a state
# directory for the journal, both the service user's (here, this user).
mkdir -m 0750 "$work/run"
mkdir -m 0700 "$work/state"
sock=$work/run/monitor.sock
ttl=1s
pid=

cleanup() {
	[[ -n $pid ]] && kill -KILL "$pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

# expect <exit-code> <reason|-> <label> <command...>
# Checks the exit code and, unless "-", the reason in the gate's output.
expect() {
	local want=$1 reason=$2 label=$3 out got
	shift 3
	set +e
	out=$("$@" 2>&1)
	got=$?
	set -e
	printf '  %-46s exit=%d  %s\n' "$label" "$got" "${out//$'\n'/ | }"
	if [[ $got != "$want" ]]; then
		echo "FAIL: $label: want exit $want, got $got" >&2
		exit 1
	fi
	if [[ $reason != - && $out != *"\"reason\":\"$reason\""* ]]; then
		echo "FAIL: $label: want reason $reason" >&2
		exit 1
	fi
}

# post <op> <body> [socket]: one contract request; prints the HTTP status
# and the body.
post() {
	curl -sS --max-time 2 --unix-socket "${3:-$sock}" -H 'content-type: application/json' \
		-w ' %{http_code}' --data "$2" "http://barmkin/v1/$1"
}

start_monitor() {
	"$work/barmkin" monitor -socket "$sock" -state-dir "$work/state" -client-group "$(id -gn)" \
		-preregister-ttl "$ttl" 2>>"$work/monitor.log" &
	pid=$!
	for _ in $(seq 50); do
		[[ $(post health '{"version":1}' 2>/dev/null) == *'"state":"ok"'*' 200' ]] && return 0
		sleep 0.1
	done
	echo "FAIL: monitor did not answer on $sock" >&2
	sed 's/^/  /' "$work/monitor.log" >&2
	exit 1
}

# hook <session> <call>: a PreToolUse hook input as Claude Code sends it.
hook() {
	printf '{"session_id":"%s","tool_use_id":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo demo-content"},"cwd":"%s","permission_mode":"default"}' \
		"$1" "$2" "$work"
}

gate() { "$work/barmkin" gate -socket "$sock"; }

# shim_session <session> [socket] [sandboxed]: registers the session as the
# shim does at session start, with the posture it reads from settings.
shim_session() {
	post register "{\"version\":1,\"host\":\"claude_code\",\"session\":\"$1\",\"root\":\"$1\",\"fresh\":true,\"posture\":{\"sandbox_enabled\":${3:-true},\"allow_all_unix_sockets\":false}}" "${2:-$sock}"
}

# shim <session> <call> [socket]: pre-registers the call as the shim module
# does. Like the shim, it never fails the call itself.
shim() {
	post preregister "{\"version\":1,\"host\":\"claude_code\",\"session\":\"$1\",\"call\":\"$2\"}" "${3:-$sock}" >/dev/null 2>&1 || true
}

# call_without_shim <input>: only the managed gate runs (plugin not loaded).
call_without_shim() { gate <<<"$1"; }

# call_with_shim <session> <call> [shim-socket]: the shim pre-registers the
# call and the gate starts while that request may still be in flight.
call_with_shim() {
	local sp rc=0
	shim "$1" "$2" "${3:-}" &
	sp=$!
	gate <<<"$(hook "$1" "$2")" || rc=$?
	wait "$sp"
	return "$rc"
}

echo "== build"
go build -o "$work/barmkin" .
echo "  $work/barmkin"

echo "== start monitor (pre-registration TTL $ttl)"
start_monitor

echo "== shim not loaded"
expect 2 unknown-session     "session never registered denies"            call_without_shim "$(hook sess-a toolu_01)"

echo "== shim loaded"
[[ $(shim_session sess-a) == *'"untrusted":"none"'*' 200' ]] || { echo "FAIL: sess-a did not register clean" >&2; exit 1; }
expect 0 -                   "pre-registered call allows"                 call_with_shim sess-a toolu_02
expect 0 -                   "next pre-registered call allows"            call_with_shim sess-a toolu_03
expect 2 unregistered        "replayed call denies (pre-registration used)" call_without_shim "$(hook sess-a toolu_03)"
expect 2 unregistered        "call the shim never saw denies"             call_without_shim "$(hook sess-a toolu_04)"
expect 2 unknown-session     "same call id, other session, denies"        call_without_shim "$(hook sess-b toolu_02)"

echo "== shim broken (wrong socket)"
expect 2 unregistered        "unregistered call denies"                   call_with_shim sess-a toolu_05 "$work/elsewhere.sock"

echo "== pre-registration expires"
shim sess-a toolu_06
sleep 1.5
expect 2 unregistered        "call pre-registered ${ttl} ago denies"      call_without_shim "$(hook sess-a toolu_06)"

echo "== posture refused"
[[ $(shim_session sess-u "" false) == *'"error":"posture_refused"'*' 403' ]] || { echo "FAIL: an unsandboxed session registered" >&2; exit 1; }
expect 2 unknown-session     "unsandboxed session's call denies"          call_with_shim sess-u toolu_07

echo "== malformed hook input"
expect 2 malformed-request   "no tool_use_id denies"                      call_without_shim '{"session_id":"sess-a","tool_name":"Bash"}'
expect 2 malformed-request   "malformed tool_use_id denies"               call_without_shim "$(hook sess-a 'toolu 08')"
expect 2 malformed-request   "not JSON denies"                            call_without_shim 'Bash: ls'

echo "== gate misconfigured"
expect 2 monitor-unavailable "no socket configured denies"                env -u BARMKIN_MONITOR_SOCKET "$work/barmkin" gate <<<"$(hook sess-a toolu_09)"

echo "== monitor down (SIGKILL)"
kill -KILL "$pid"
wait "$pid" 2>/dev/null || true
pid=
rm -f "$sock"
expect 2 monitor-unavailable "pre-registered call denies while down"      call_with_shim sess-a toolu_10

echo "== monitor restarted"
start_monitor
[[ $(shim_session sess-a) == *'"untrusted":"monitor_restart"'*' 200' ]] ||
	{ echo "FAIL: after an unclean stop, sess-a must come back tainted by monitor_restart" >&2; exit 1; }
echo "  sess-a registers again with its untrusted leg raised by monitor_restart"
expect 0 -                   "pre-registered call allows again"           call_with_shim sess-a toolu_11
expect 2 unregistered        "unknown call still denies"                  call_without_shim "$(hook sess-a toolu_12)"

echo "== monitor log"
sed 's/^/  /' "$work/monitor.log"

kill -TERM "$pid"
wait "$pid"
pid=
echo "PASS: barmkin Claude Code gate demo"
