#!/usr/bin/env bash
# Runs the barmkin monitor demo end to end and asserts every step.
#
# Builds barmkin-monitor into a temporary directory, serves contract v1 on
# a Unix socket there, and shows that malformed, unknown, and unavailable
# requests deny, and that a taint survives a SIGKILL and restart. Exits
# non-zero on the first unexpected result. Nothing outside the temporary
# directory is touched.
set -euo pipefail

cd "$(dirname "$0")/.."

work=$(mktemp -d "${TMPDIR:-/tmp}/bmk.XXXXXX")
# Unix socket paths are limited to ~108 bytes.
if (( ${#work} > 80 )); then
	rmdir "$work"
	work=$(mktemp -d /tmp/bmk.XXXXXX)
fi
bin=$work/barmkin-monitor
sock=$work/monitor.sock
journal=$work/taint.journal
pid=

cleanup() {
	[[ -n $pid ]] && kill -KILL "$pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

# expect <exit-code> <reason|-> <label> <command...>
# Checks the exit code and, unless "-", the reason in the JSON reply.
expect() {
	local want=$1 reason=$2 label=$3 out got
	shift 3
	set +e
	out=$("$@" 2>&1)
	got=$?
	set -e
	printf '  %-44s exit=%d  %s\n' "$label" "$got" "${out//$'\n'/ | }"
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
	"$bin" serve -socket "$sock" -journal "$journal" 2>>"$work/serve.log" &
	pid=$!
	# A crashed monitor leaves its socket file behind, so wait for a real
	# answer rather than for the file to exist.
	for _ in $(seq 50); do
		decide ready-probe routine >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	echo "FAIL: monitor did not answer on $sock" >&2
	exit 1
}

decide() { "$bin" decide -socket "$sock" -session "$1" -operation "$2"; }
send() { "$bin" send -socket "$sock" -path "$1" -body "$2"; }

echo "== build"
go build -o "$bin" ./cmd/barmkin-monitor
echo "  $bin"

echo "== start monitor (journal: $journal)"
start_monitor

echo "== clean session"
expect 0 ok                  "routine in sess-a allows"                 decide sess-a routine
expect 0 ok                  "protected in sess-a allows"               decide sess-a protected

echo "== malformed and unknown requests deny"
expect 2 malformed-request   "invalid JSON"                             send /v1/decide '{"version":1,'
expect 2 malformed-request   "unknown field (content smuggling)"        send /v1/decide '{"version":1,"session":"sess-a","operation":"routine","command":"ls"}'
expect 2 unsupported-version "unsupported version"                      send /v1/decide '{"version":2,"session":"sess-a","operation":"routine"}'
expect 2 unknown-operation   "unknown operation"                        decide sess-a launch-missiles
expect 2 unknown-endpoint    "unknown endpoint"                         send /v1/override '{"version":1}'
expect 1 unknown-source      "unknown taint source is not recorded"     "$bin" taint -socket "$sock" -session sess-a -source vibes

echo "== taint sess-a through the supported flow"
expect 0 ok                  "taint sess-a (untrusted-input)"           "$bin" taint -socket "$sock" -session sess-a
expect 2 tainted             "protected in sess-a denies"               decide sess-a protected
expect 0 ok                  "routine in sess-a still allows"           decide sess-a routine
expect 0 ok                  "protected in sess-b allows"               decide sess-b protected

echo "== a second monitor cannot take the journal"
expect 1 -                   "second serve on same journal"             "$bin" serve -socket "$work/other.sock" -journal "$journal"

echo "== crash the monitor (SIGKILL)"
kill -KILL "$pid"
wait "$pid" 2>/dev/null || true
pid=
expect 2 monitor-unavailable "unavailable monitor denies routine"       decide sess-b routine
expect 2 monitor-unavailable "unavailable monitor denies protected"     decide sess-b protected

echo "== restart on the same journal"
start_monitor
expect 2 tainted             "protected in sess-a still denies"         decide sess-a protected
expect 0 ok                  "routine in sess-a allows"                 decide sess-a routine
expect 0 ok                  "protected in sess-b allows"               decide sess-b protected

echo "== journal"
sed 's/^/  /' "$journal"
echo "== monitor log"
sed 's/^/  /' "$work/serve.log"

kill -TERM "$pid"
wait "$pid"
pid=
echo "PASS: barmkin monitor demo"
