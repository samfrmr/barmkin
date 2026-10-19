#!/usr/bin/env bash
# Checks an installed barmkin monitor and managed Claude Code seat, as root,
# on the host it was installed on. packaging/test/ubuntu.sh and the NixOS
# test in packaging/nixos run it.
#
#   checks.sh installed <client-user> <outsider-user>
#   checks.sh admin <client-user> <outsider-user>
#   checks.sh no-admin
#   checks.sh fingerprint
#   checks.sh absent [--keep-state]
#
# installed checks the deployment (owners and modes of the socket, the
# journal and their directories, the managed settings and the gate's uid
# pin), that only the client group reaches the socket, and then, with the
# gate command the managed settings hold, run as the client user:
#   - a call the shim pre-registered is allowed;
#   - a session whose posture is insecure is refused, and its calls denied;
#   - the monitor refuses an insecure deployment of itself;
#   - a protocol-version mismatch is denied, by the monitor, the gate and,
#     when Node 22.18+ is on PATH, the shim's own client, with upgrade text;
#   - a socket served by another uid is denied by the pinned gate;
#   - after a SIGKILL, systemd restarts the monitor, the session comes back
#     tainted by monitor_restart, and pre-registered calls are allowed again.
# admin checks the opt-in administrative socket: it is root's, in a
# directory only root can enter, and neither user reaches it; the client
# socket answers none of its paths; root's `barmkin monitor-admin clear`
# refuses without a terminal or when the lineage id is not typed back; and a
# confirmed clear lowers a tainted lineage, makes its session register again,
# keeps the cleared raise in the journal and survives a restart.
# no-admin checks that there is no administrative socket: the default.
# fingerprint prints the installed state, for comparing two installs.
# absent checks that nothing is left after an uninstall; --keep-state allows
# the state directory (NixOS keeps a StateDirectory).
# Every check prints one line; the first failure exits 1.
set -euo pipefail

readonly unit=barmkin-monitor.service
readonly settings=/etc/claude-code/managed-settings.json
readonly runtime_dir=/run/barmkin
readonly socket=$runtime_dir/monitor.sock
readonly state_dir=/var/lib/barmkin
readonly journal=$state_dir/journal
readonly admin_unit=barmkin-monitor-admin.socket
readonly admin_dir=/run/barmkin-admin
readonly admin_socket=$admin_dir/admin.sock

ok() { echo "ok   - $*"; }
fail() { echo "FAIL - $*" >&2; exit 1; }

# modes <path> <want>: owner, group, octal mode and type, as stat prints them.
modes() {
	local got
	got=$(stat -c '%U:%G %a %F' "$1")
	[[ $got == "$2" ]] || fail "$1 is '$got', want '$2'"
	ok "$1 $got"
}

# root_only <path>: path, and everything under it, is owned by root and
# writable by nobody else.
root_only() {
	local bad
	bad=$(find "$1" ! -user root -o ! -group root -o -perm /022 -o -type l)
	[[ -z $bad ]] || fail "not root-owned and read-only to others: $bad"
	ok "$1 $(stat -c '%U:%G %a %F' "$1"), and everything under it, root-owned and read-only to others"
}

# json_string <key> <file>: the first value of a string key in a JSON file.
json_string() { grep -o "\"$1\": *\"[^\"]*\"" "$2" | head -1 | sed 's/.*: *"\(.*\)"/\1/'; }

# post <user> <op> <body> [socket]: one contract request as user; prints the
# body and the HTTP status.
post() { post_path "$1" "/v1/$2" "$3" "${4:-$socket}"; }

# post_path <user> <path> <body> <socket>: a request to any path.
post_path() {
	runuser -u "$1" -- curl -sS --max-time 3 --unix-socket "$4" \
		-H 'content-type: application/json' -w ' %{http_code}' --data "$3" "http://barmkin$2"
}

# expect_post <want-substring> <label> <post args...>
expect_post() {
	local want=$1 label=$2 got
	shift 2
	got=$(post "$@" 2>&1) || true
	[[ $got == *"$want"* ]] || fail "$label: got '$got', want '$want'"
	ok "$label: $got"
}

register() { # register <session> <sandboxed> <all-sockets> [version]
	printf '{"version":%s,"host":"claude_code","session":"%s","root":"%s","fresh":true,"posture":{"sandbox_enabled":%s,"allow_all_unix_sockets":%s}}' \
		"${4:-1}" "$1" "$1" "$2" "$3"
}
preregister() { printf '{"version":1,"host":"claude_code","session":"%s","call":"%s"}' "$1" "$2"; }
hook() {
	printf '{"session_id":"%s","tool_use_id":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"true"},"cwd":"/","permission_mode":"default"}' "$1" "$2"
}

# expect_gate <exit> <reason|-> <label> <user> <session> <call> [gate args...]
# Runs the managed settings' gate command as user, with gate args appended.
expect_gate() {
	local want=$1 reason=$2 label=$3 user=$4 session=$5 call=$6 out rc=0
	shift 6
	out=$(runuser -u "$user" -- "${gate[@]}" "$@" <<<"$(hook "$session" "$call")" 2>&1) || rc=$?
	[[ $rc == "$want" ]] || fail "$label: gate exit $rc, want $want: $out"
	[[ $reason == - || $out == *"\"reason\":\"$reason\""* ]] || fail "$label: want reason $reason: $out"
	ok "$label: exit $rc ${out//$'\n'/ | }"
}

main_pid() { systemctl show -p MainPID --value "$unit"; }

wait_for_health() {
	for _ in $(seq 100); do
		[[ $(post "$1" health '{"version":1}' 2>/dev/null) == *'"state":"ok"'*' 200' ]] && return 0
		sleep 0.1
	done
	fail "the monitor did not answer on $socket"
}

# standin <user> <socket> <status line> <body>: a fake monitor on socket,
# served by user, giving every request the same reply. The socket's
# directory must be writable by user.
standin() {
	local user=$1 sock=$2 reply
	reply=$(mktemp "$scratch/reply.XXXXXX")
	printf 'HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
		"$3" "${#4}" "$4" >"$reply"
	chmod 0644 "$reply"
	runuser -u "$user" -- socat "UNIX-LISTEN:$sock,fork,mode=0666" SYSTEM:"head -c 1 >/dev/null; cat $reply" 2>/dev/null &
	standin_pids+=($!)
	for _ in $(seq 50); do
		[[ -S $sock ]] && return 0
		sleep 0.1
	done
	fail "stand-in did not listen on $sock"
}

cleanup() {
	local p
	for p in "${standin_pids[@]}"; do kill "$p" 2>/dev/null || true; done
	[[ -n ${scratch:-} ]] && rm -rf "$scratch"
	return 0
}

cmd_installed() {
	local client=$1 outsider=$2 monitor_uid bin marketplace pid restarts node out
	# Sessions unique to this run, as the state directory may outlive one.
	local s
	s=pkg-$$-$(date +%s)
	standin_pids=()
	trap cleanup EXIT
	monitor_uid=$(id -u barmkin)

	echo "== deployment"
	systemctl is-active --quiet "$unit" || fail "$unit is not active"
	pid=$(main_pid)
	[[ $(stat -c %U "/proc/$pid") == barmkin ]] || fail "the monitor (pid $pid) does not run as barmkin"
	ok "$unit active, pid $pid running as barmkin (uid $monitor_uid)"
	modes "$runtime_dir" "barmkin:barmkin-clients 750 directory"
	modes "$socket" "barmkin:barmkin-clients 660 socket"
	modes "$state_dir" "barmkin:barmkin-clients 700 directory"
	modes "$journal" "barmkin:barmkin-clients 600 regular file"
	modes "$settings" "root:root 644 regular file"

	read -r -a gate <<<"$(json_string command "$settings")"
	bin=${gate[0]}
	marketplace=$(json_string path "$settings")
	root_only "$bin"
	root_only "$marketplace"
	[[ ${gate[*]:1} == "gate -socket $socket -monitor-uid $monitor_uid" ]] ||
		fail "managed gate command is '${gate[*]}', want it pinned to uid $monitor_uid"
	ok "managed gate: ${gate[*]}"
	grep -Eq '"allowManagedHooksOnly": *true' "$settings" || fail "managed settings do not set allowManagedHooksOnly"
	grep -Eq '"allowUnsandboxedCommands": *false' "$settings" || fail "managed settings allow unsandboxed commands"
	! grep -q allowAllUnixSockets "$settings" || fail "managed settings mention allowAllUnixSockets"
	ok "managed settings keep the lock: allowManagedHooksOnly, sandbox without unsandboxed commands"

	echo "== socket access"
	expect_post '"state":"ok"' "client $client reaches the monitor" "$client" health '{"version":1}'
	out=$(post "$outsider" health '{"version":1}' 2>&1) && fail "outsider $outsider reached the monitor: $out"
	ok "outsider $outsider cannot connect: ${out//$'\n'/ }"

	echo "== shim and gate"
	expect_post '"untrusted":"none"' "fresh sandboxed session registers clean" "$client" register "$(register "$s-a" true false)"
	expect_gate 2 unregistered "call the shim never pre-registered denies" "$client" "$s-a" toolu_01
	expect_post ' 200' "shim pre-registers a call" "$client" preregister "$(preregister "$s-a" toolu_02)"
	expect_gate 0 - "pre-registered call allows" "$client" "$s-a" toolu_02
	expect_gate 2 unregistered "replayed call denies" "$client" "$s-a" toolu_02

	echo "== insecure posture"
	expect_post '"error":"posture_refused"' "unsandboxed session is refused" "$client" register "$(register "$s-u" false false)"
	expect_post '"error":"posture_refused"' "allowAllUnixSockets session is refused" "$client" register "$(register "$s-v" true true)"
	post "$client" preregister "$(preregister "$s-u" toolu_03)" >/dev/null 2>&1 || true
	expect_gate 2 unknown-session "refused session's call denies" "$client" "$s-u" toolu_03

	echo "== insecure deployment"
	scratch=$(mktemp -d /tmp/barmkin-checks.XXXXXX)
	chmod 0755 "$scratch"
	install -d -o barmkin -g barmkin-clients -m 0750 "$scratch/run"
	install -d -o barmkin -g barmkin-clients -m 0755 "$scratch/state-open"
	install -d -o barmkin -g barmkin-clients -m 0700 "$scratch/state"
	install -d -o barmkin -g barmkin-clients -m 0770 "$scratch/run-open"
	refuse() { # refuse <want> <label> <user> <monitor args...>
		local want=$1 label=$2 user=$3 out rc=0
		shift 3
		out=$(runuser -u "$user" -- timeout 5 "$bin" monitor -client-group barmkin-clients "$@" 2>&1) || rc=$?
		[[ $rc == 1 && $out == *"$want"* ]] || fail "$label: exit $rc: $out"
		ok "$label: $out"
	}
	refuse "refusing to run as root" "monitor refuses to run as root" root \
		-socket "$scratch/run/m.sock" -state-dir "$scratch/state"
	refuse "has mode 0755" "monitor refuses a state directory others can read" barmkin \
		-socket "$scratch/run/m.sock" -state-dir "$scratch/state-open"
	refuse "has mode 0770" "monitor refuses a runtime directory its group can write" barmkin \
		-socket "$scratch/run-open/m.sock" -state-dir "$scratch/state"
	refuse "monitor.lock" "a second monitor cannot take the installed state" barmkin \
		-socket "$scratch/run/m.sock" -state-dir "$state_dir"

	echo "== protocol version mismatch"
	expect_post '"error":"version_mismatch"' "monitor denies a client of contract version 2" "$client" register "$(register "$s-w" true false 2)"
	standin barmkin "$scratch/run/v2.sock" "400 Bad Request" '{"version":2,"error":"version_mismatch"}'
	expect_gate 2 version-mismatch "gate denies a monitor of contract version 2" "$client" "$s-a" toolu_04 -socket "$scratch/run/v2.sock"
	node=$(command -v node || true)
	if [[ -n $node ]] && "$node" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a == 22 && b >= 18) ? 0 : 1)'; then
		# shellcheck disable=SC2016 # JavaScript, not shell
		out=$(runuser -u "$client" -- "$node" --input-type=module -e '
			import { request } from "node:http"
			const [dir, socketPath] = process.argv.slice(1)
			const m = await import(dir + "/barmkin-shim/hooks/lib/monitor.ts")
			const p = await import(dir + "/barmkin-shim/hooks/lib/proto.ts")
			const body = m.encodeBody("register", { version: p.VERSION, host: "claude_code", session: "pkg-x", root: "pkg-x", fresh: true, posture: { sandbox_enabled: true, allow_all_unix_sockets: false } })
			const { status, text } = await new Promise((resolve, reject) => {
				const req = request(m.monitorUrl("register"), { method: "POST", socketPath, timeout: 2000 }, (res) => {
					let text = ""
					res.on("data", (c) => (text += c))
					res.on("end", () => resolve({ status: res.statusCode, text }))
				})
				req.on("error", reject)
				req.end(body)
			})
			const answer = m.interpretReply("register", status, text)
			console.log(answer.ok ? "registered" : answer.failure + ": " + m.describeFailure(answer.failure))
		' "$marketplace" "$scratch/run/v2.sock" 2>&1) || true
		[[ $out == "version_mismatch: "*"upgrade the shim and the monitor together"* ]] ||
			fail "installed shim's client against a version 2 monitor: $out"
		ok "installed shim's client denies a monitor of contract version 2: $out"
	else
		echo "skip - no Node 22.18+ on PATH: the installed shim's client is not run"
	fi
	install -d -o "$client" -m 0755 "$scratch/squat"
	standin "$client" "$scratch/squat/monitor.sock" "200 OK" '{"version":1,"verdict":"allow"}'
	expect_gate 2 monitor-uid-mismatch "pinned gate denies a socket served by another uid" "$client" "$s-a" toolu_05 -socket "$scratch/squat/monitor.sock"

	echo "== recovery after SIGKILL"
	expect_post '"untrusted":"none"' "fresh session registers clean" "$client" register "$(register "$s-k" true false)"
	restarts=$(systemctl show -p NRestarts --value "$unit")
	kill -KILL "$pid"
	ok "sent SIGKILL to the monitor (pid $pid)"
	for _ in $(seq 100); do
		[[ $(main_pid) != "$pid" && $(main_pid) != 0 ]] && break
		sleep 0.1
	done
	wait_for_health "$client"
	[[ $(systemctl show -p NRestarts --value "$unit") == $((restarts + 1)) ]] || fail "systemd did not restart the monitor once"
	ok "systemd restarted the monitor: pid $(main_pid), NRestarts $((restarts + 1))"
	modes "$socket" "barmkin:barmkin-clients 660 socket"
	modes "$journal" "barmkin:barmkin-clients 600 regular file"
	expect_post '"untrusted":"monitor_restart"' "session comes back tainted by monitor_restart" "$client" register "$(register "$s-k" true false)"
	expect_post ' 200' "shim pre-registers a call" "$client" preregister "$(preregister "$s-k" toolu_06)"
	expect_gate 0 - "pre-registered call allows again" "$client" "$s-k" toolu_06
	expect_gate 2 unregistered "call the shim never pre-registered still denies" "$client" "$s-k" toolu_07
	echo "PASS: installed"
}

cmd_admin() {
	local client=$1 outsider=$2 s bin u out rc uid pid clear
	s=adm-$$-$(date +%s)
	uid=$(id -u "$client")
	read -r -a gate <<<"$(json_string command "$settings")"
	bin=${gate[0]}

	echo "== administrative socket"
	systemctl is-active --quiet "$admin_unit" || fail "$admin_unit is not active"
	pid=$(main_pid)
	[[ $(tr '\0' ' ' <"/proc/$pid/cmdline") == *"-admin-socket $admin_socket"* ]] || fail "the monitor was not started with -admin-socket"
	ok "$admin_unit active, and the monitor (pid $pid) serves it"
	modes "$admin_dir" "root:root 700 directory"
	modes "$admin_socket" "root:root 600 socket"
	for u in "$client" "$outsider"; do
		out=$(post_path "$u" /admin/v1/list '{"version":1}' "$admin_socket" 2>&1) && fail "$u reached the administrative socket: $out"
		ok "$u cannot reach the administrative socket: ${out//$'\n'/ }"
	done
	expect_post '"untrusted":"none"' "fresh session registers clean" "$client" register "$(register "$s" true false)"
	expect_post '"untrusted":"fetch"' "a fetch taints it" "$client" observe "{\"version\":1,\"host\":\"claude_code\",\"session\":\"$s\",\"source\":\"fetch\"}"
	clear='{"version":1,"uid":'$uid',"host":"claude_code","lineage":"'$s'","epoch":0,"legs":{"untrusted":"fetch","sensitive":"none"},"reason":"reviewed_safe"}'
	for p in /admin/v1/clear /v1/clear; do
		out=$(post_path "$client" "$p" "$clear" "$socket" 2>&1) || true
		[[ $out == *'"error":"bad_request"'*' 400' ]] || fail "the client socket answered $p: $out"
		ok "the client socket refuses $p: $out"
	done

	echo "== monitor-admin"
	out=$("$bin" monitor-admin list 2>&1) || fail "monitor-admin list: $out"
	grep -Eq "^$s +$uid +claude_code +0 +fetch \(" <<<"$out" || fail "monitor-admin list does not show $s tainted by fetch: $out"
	ok "root lists the lineage: $(grep "^$s" <<<"$out")"
	out=$(runuser -u "$client" -- "$bin" monitor-admin list 2>&1) && fail "a client ran monitor-admin list: $out"
	ok "a client cannot list: $out"
	local args=(monitor-admin clear -uid "$uid" -host claude_code -lineage "$s" -reason reviewed_safe)
	rc=0
	out=$("$bin" "${args[@]}" </dev/null 2>&1) || rc=$?
	[[ $rc == 1 && $out == *"needs a terminal"* ]] || fail "clear without a terminal: exit $rc: $out"
	ok "clear without a terminal is refused: $out"
	rc=0
	out=$(printf 'yes\n' | script -qec "$bin ${args[*]}" /dev/null 2>&1) || rc=$?
	[[ $rc == 1 && $out == *"nothing was cleared"* ]] || fail "clear without the lineage typed back: exit $rc: $out"
	ok "clear without the lineage id typed back is refused"
	expect_post '"untrusted":"fetch"' "the refused clears changed nothing" "$client" status "$(status_body "$s")"
	rc=0
	out=$(printf '%s\n' "$s" | script -qec "$bin ${args[*]}" /dev/null 2>&1) || rc=$?
	[[ $rc == 0 && $out == *"Cleared."* && $out == *"does not remove untrusted material already in an AI"* ]] ||
		fail "a confirmed clear: exit $rc: $out"
	ok "a confirmed clear from a terminal, with the conversation warning"
	journalctl -u "$unit" --no-pager -q | grep -q "root cleared lineage $s of uid $uid" || fail "the clear is not in the monitor's log"
	ok "the clear is in the monitor's log"
	expect_post '"error":"unknown_session"' "the session must register again" "$client" status "$(status_body "$s")"
	expect_post '"untrusted":"none"' "it registers again, clean" "$client" register "$(register "$s" true false)"
	grep -q "\"kind\":\"raise\".*\"root\":\"$s\".*\"source\":\"fetch\"" "$journal" || fail "the cleared raise is gone from the journal"
	grep -q "\"kind\":\"clear\".*\"root\":\"$s\".*\"epoch\":1,\"reason\":\"reviewed_safe\"" "$journal" || fail "no clear record in the journal"
	ok "the journal keeps the cleared raise and the clear"
	systemctl restart "$unit"
	wait_for_health "$client"
	expect_post '"untrusted":"none"' "the clear survives a restart" "$client" status "$(status_body "$s")"
	echo "PASS: admin"
}

status_body() { printf '{"version":1,"host":"claude_code","session":"%s"}' "$1"; }

cmd_no_admin() {
	local pid
	pid=$(main_pid)
	[[ $(tr '\0' ' ' <"/proc/$pid/cmdline") != *"-admin-socket"* ]] || fail "the monitor was started with -admin-socket"
	! systemctl is-active --quiet "$admin_unit" || fail "$admin_unit is active"
	# systemd removes the socket on stop; NixOS may leave its empty root-only
	# directory until reboot.
	[[ ! -e $admin_socket ]] || fail "$admin_socket exists"
	ok "no administrative socket: the taint is sticky"
}

cmd_fingerprint() {
	local gate f
	read -r -a gate <<<"$(json_string command "$settings")"
	for f in "$runtime_dir" "$socket" "$state_dir" "$journal" "$settings" "${gate[0]}"; do
		stat -c '%n %U:%G %a %F' "$f"
	done
	find "$(json_string path "$settings")" -printf '%p %U:%G %m %s\n' | sort
	sha256sum "$settings" "${gate[0]}" "$(systemctl show -p FragmentPath --value "$unit")"
	getent passwd barmkin
	getent group barmkin-clients
	systemctl is-enabled "$unit"
	systemctl is-active "$admin_unit" || true
	[[ ! -e $admin_socket ]] || stat -c '%n %U:%G %a %F' "$admin_dir" "$admin_socket"
	echo "monitor pid $(main_pid)"
}

cmd_absent() {
	local keep_state=${1:-}
	! systemctl is-active --quiet "$unit" || fail "$unit is still active"
	[[ $(systemctl show -p LoadState --value "$unit") == not-found ]] || fail "$unit is still installed"
	ok "$unit is not installed"
	! getent passwd barmkin >/dev/null || fail "user barmkin still exists"
	! getent group barmkin-clients >/dev/null || fail "group barmkin-clients still exists"
	ok "user barmkin and group barmkin-clients are gone"
	for f in "$settings" "$runtime_dir" /usr/local/bin/barmkin /opt/barmkin; do
		[[ ! -e $f && ! -L $f ]] || fail "$f is still there"
	done
	ok "managed settings, runtime directory, binary and marketplace are gone"
	[[ $(systemctl show -p LoadState --value "$admin_unit") == not-found && ! -e $admin_socket ]] ||
		fail "the administrative socket is still there"
	ok "the administrative socket is gone"
	if [[ $keep_state != --keep-state ]]; then
		[[ ! -e $state_dir ]] || fail "$state_dir is still there"
		ok "$state_dir is gone"
	fi
	echo "PASS: absent"
}

case ${1:-} in
installed) [[ $# == 3 ]] || { echo "usage: $0 installed <client> <outsider>" >&2; exit 2; }; cmd_installed "$2" "$3" ;;
admin) [[ $# == 3 ]] || { echo "usage: $0 admin <client> <outsider>" >&2; exit 2; }; cmd_admin "$2" "$3" ;;
no-admin) cmd_no_admin ;;
fingerprint) cmd_fingerprint ;;
absent) cmd_absent "${2:-}" ;;
*) echo "usage: $0 installed <client> <outsider> | admin <client> <outsider> | no-admin | fingerprint | absent [--keep-state]" >&2; exit 2 ;;
esac
