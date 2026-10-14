#!/usr/bin/env bash
# Runs the Claude Code shim-presence lab fixture end to end and asserts
# every step.
#
# Builds barmkin and barmkin-monitor into a temporary directory and serves
# the monitor there. Each simulated tool call feeds one PreToolUse hook
# input to the managed `barmkin gate` and, when the shim plugin is
# "loaded", to the plugin's own hook command at the same time, as Claude
# Code does. It shows that a call without a live shim registration
# (no shim, broken shim, replayed, expired, malformed, monitor down) is
# denied with exit 2, and that a registered call reaches the monitor and
# is allowed. Exits non-zero on the first unexpected result. Nothing
# outside the temporary directory is touched.
set -euo pipefail

cd "$(dirname "$0")/.."
repo=$PWD
plugin=$repo/plugins/claude-code/barmkin-shim

work=$(mktemp -d "${TMPDIR:-/tmp}/bmk.XXXXXX")
# Unix socket paths are limited to ~108 bytes.
if (( ${#work} > 80 )); then
	rmdir "$work"
	work=$(mktemp -d /tmp/bmk.XXXXXX)
fi
sock=$work/monitor.sock
journal=$work/taint.journal
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

start_monitor() {
	"$work/barmkin-monitor" serve -socket "$sock" -journal "$journal" -presence-ttl "$ttl" 2>>"$work/serve.log" &
	pid=$!
	for _ in $(seq 50); do
		"$work/barmkin-monitor" decide -socket "$sock" -session ready-probe -operation routine >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	echo "FAIL: monitor did not answer on $sock" >&2
	exit 1
}

# hook <session> <call>: a PreToolUse hook input as Claude Code sends it.
hook() {
	printf '{"session_id":"%s","tool_use_id":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo demo-content"},"cwd":"%s","permission_mode":"default"}' \
		"$1" "$2" "$work"
}

# The plugin's own hook command, exactly as hooks/hooks.json declares it.
shim_cmd=$(node -e '
	const h = require(process.argv[1]).hooks.PreToolUse
	if (h.length !== 1 || h[0].matcher !== "*" || h[0].hooks.length !== 1) process.exit(1)
	console.log(h[0].hooks[0].command)' "$plugin/hooks/hooks.json")

gate() { "$work/barmkin" gate -socket "$sock"; }
shim() { CLAUDE_PLUGIN_ROOT=$plugin BARMKIN_MONITOR_SOCKET=${1:-$sock} sh -c "$shim_cmd"; }

# call_without_shim <input>: only the managed gate runs (plugin not loaded).
call_without_shim() { gate <<<"$1"; }

# call_with_shim <input> [shim-socket]: the shim's hook and the managed gate
# run in parallel on the same input, as Claude Code runs matching hooks.
call_with_shim() {
	local sp rc=0
	shim "${2:-}" <<<"$1" &
	sp=$!
	gate <<<"$1" || rc=$?
	wait "$sp"
	return "$rc"
}

echo "== build"
go build -o "$work/barmkin" .
go build -o "$work/barmkin-monitor" ./cmd/barmkin-monitor
echo "  $work/barmkin  $work/barmkin-monitor"
echo "  shim hook: $shim_cmd"

echo "== start monitor (presence TTL $ttl)"
start_monitor

echo "== shim not loaded"
expect 2 unregistered        "unknown call, no shim, denies"              call_without_shim "$(hook sess-a toolu_01)"

echo "== shim loaded"
expect 0 -                   "registered call allows"                     call_with_shim "$(hook sess-a toolu_02)"
expect 0 -                   "next registered call allows"                call_with_shim "$(hook sess-a toolu_03)"
expect 2 unregistered        "replayed call denies (registration used)"   call_without_shim "$(hook sess-a toolu_03)"
expect 2 unregistered        "same call id, other session, denies"        call_without_shim "$(hook sess-b toolu_02)"

echo "== shim broken (wrong socket)"
expect 2 unregistered        "unregistered call denies"                   call_with_shim "$(hook sess-a toolu_04)" "$work/elsewhere.sock"

echo "== registration expires"
shim <<<"$(hook sess-a toolu_05)"
sleep 1.5
expect 2 expired             "call registered ${ttl} ago denies"          call_without_shim "$(hook sess-a toolu_05)"

echo "== malformed hook input"
expect 2 malformed-request   "no tool_use_id denies"                      call_with_shim '{"session_id":"sess-a","tool_name":"Bash"}'
expect 2 malformed-request   "malformed tool_use_id denies"               call_with_shim "$(hook sess-a 'toolu 06')"
expect 2 malformed-request   "not JSON denies"                            call_with_shim 'Bash: ls'

echo "== gate misconfigured"
expect 2 monitor-unavailable "no socket configured denies"                env -u BARMKIN_MONITOR_SOCKET "$work/barmkin" gate <<<"$(hook sess-a toolu_07)"

echo "== monitor down (SIGKILL)"
kill -KILL "$pid"
wait "$pid" 2>/dev/null || true
pid=
expect 2 monitor-unavailable "registered call denies while down"          call_with_shim "$(hook sess-a toolu_08)"

echo "== monitor restarted"
start_monitor
expect 0 -                   "registered call allows again"               call_with_shim "$(hook sess-a toolu_09)"
expect 2 unregistered        "unknown call still denies"                  call_without_shim "$(hook sess-a toolu_10)"

echo "== monitor log"
sed 's/^/  /' "$work/serve.log"

kill -TERM "$pid"
wait "$pid"
pid=
echo "PASS: barmkin Claude Code gate demo"
