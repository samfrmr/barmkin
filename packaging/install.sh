#!/usr/bin/env bash
# Installs or uninstalls the root-managed barmkin monitor and the managed
# Claude Code seat on a systemd host such as Ubuntu or Debian. NixOS uses the
# module in packaging/nixos instead.
#
#   packaging/install.sh install [--binary PATH] [--client USER]... [--admin-socket]
#                                [--jev-proxy] [--jev-caller USER]...
#   packaging/install.sh uninstall
#   packaging/install.sh render-settings --monitor-uid UID
#
# install, as root:
#   - creates the system group barmkin-clients and the system user barmkin
#     (primary group barmkin-clients, no home, no login shell), and adds each
#     --client user to the group;
#   - installs the binary (default: ./barmkin, built with CGO_ENABLED=0) as
#     /usr/local/bin/barmkin, and the shim's marketplace as
#     /opt/barmkin/plugins/claude-code, all root-owned;
#   - installs packaging/systemd/barmkin-monitor.service, then enables and
#     starts it, restarting it only when the binary or the unit changed;
#   - writes /etc/claude-code/managed-settings.json from
#     plugins/claude-code/managed-settings.example.json, with the gate pinned
#     to the barmkin user's uid (-monitor-uid);
#   - only with --admin-socket: installs packaging/systemd/barmkin-monitor-admin.socket
#     and the drop-in barmkin-monitor.service.d/admin.conf, which give the
#     monitor its root-only administrative socket for `barmkin monitor-admin`.
#     Without it, install removes them if an earlier install put them there,
#     so the taint is sticky again.
#   - installs the root policy the shims read, /etc/barmkin/policy.yaml, from
#     packaging/policy.yaml when there is none, root-owned with mode 0644 in a
#     root-owned 0755 /etc/barmkin. A policy root has edited is kept as it is
#     (its owner and mode are put right); an unedited default is updated.
#   - only with --jev-proxy: creates the system group barmkin-jev-clients,
#     adds each --jev-caller user to it, and installs and starts
#     packaging/systemd/barmkin-jevproxy.service, the root-owned proxy that
#     holds the OpenRouter API key for Jev calls so no agent-uid component
#     does (see "Jev proxy" in README.md). It does NOT provision the key
#     file: create /etc/barmkin/jev-openrouter.key yourself, root-owned,
#     mode 0600, before the unit can start (ConditionPathExists refuses it
#     otherwise). Without --jev-proxy, install removes the unit and group if
#     an earlier install put them there; it never removes the key file.
# Running it again changes nothing that is already in place. It refuses to
# replace managed settings it did not write, and a policy path or directory
# that is a symlink.
#
# uninstall, as root, stops and removes the service, the administrative
# socket, its state and runtime directories, the files above, the user and
# the group. It also removes the Jev proxy unit, group and runtime
# directory if present, but never the key file. It leaves managed settings
# it did not write, and a policy root has edited, in place. Running it
# again is a no-op.
#
# render-settings prints the managed settings install would write for a
# monitor running as UID.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

readonly service_user=barmkin
readonly client_group=barmkin-clients
readonly unit_name=barmkin-monitor.service
readonly bin=/usr/local/bin/barmkin
readonly unit=/etc/systemd/system/$unit_name
readonly admin_unit_name=barmkin-monitor-admin.socket
readonly admin_unit=/etc/systemd/system/$admin_unit_name
readonly admin_dropin_dir=/etc/systemd/system/$unit_name.d
readonly admin_dropin=$admin_dropin_dir/admin.conf
readonly admin_dir=/run/barmkin-admin
readonly prefix=/opt/barmkin
readonly marketplace=$prefix/plugins/claude-code
readonly settings_record=$prefix/managed-settings.sha256
readonly settings=/etc/claude-code/managed-settings.json
readonly state_dir=/var/lib/barmkin
readonly runtime_dir=/run/barmkin
readonly socket=$runtime_dir/monitor.sock
readonly recipe=$repo/plugins/claude-code/managed-settings.example.json
readonly gate_command="$bin gate -socket $socket"
readonly policy_dir=/etc/barmkin
readonly policy=$policy_dir/policy.yaml
readonly policy_default=$repo/packaging/policy.yaml
readonly policy_record=$prefix/policy.sha256

readonly jev_caller_group=barmkin-jev-clients
readonly jevproxy_unit_name=barmkin-jevproxy.service
readonly jevproxy_unit=/etc/systemd/system/$jevproxy_unit_name
readonly jevproxy_runtime_dir=/run/barmkin-jevproxy
readonly jevproxy_socket=$jevproxy_runtime_dir/jevproxy.sock
readonly jev_key=$policy_dir/jev-openrouter.key

say() { echo "[barmkin] $*"; }
die() { echo "[barmkin] error: $*" >&2; exit 1; }

usage() {
	sed -n '6,8s/^#   //p' "${BASH_SOURCE[0]}" >&2
	exit 2
}

# render_settings <uid>: the recipe, with the gate pinned to the monitor's uid.
render_settings() {
	local uid=$1 out
	[[ $uid =~ ^[0-9]+$ ]] || die "the monitor uid must be a number, not '$uid'"
	out=$(sed "s|\"command\": \"$gate_command\"|\"command\": \"$gate_command -monitor-uid $uid\"|" "$recipe")
	[[ $(grep -c -- "\"command\": \"$gate_command -monitor-uid $uid\"" <<<"$out") == 1 ]] ||
		die "$recipe does not have exactly one gate command '$gate_command' to pin"
	printf '%s\n' "$out"
}

sha() { sha256sum | cut -d' ' -f1; }

require_host() {
	[[ $EUID -eq 0 ]] || die "run as root"
	[[ ! -e /etc/NIXOS ]] || die "on NixOS, import packaging/nixos/module.nix and set services.barmkin.enable instead"
	if [[ ! -d /run/systemd/system ]] || ! command -v systemctl >/dev/null; then
		die "systemd is not running"
	fi
}

# put <src> <dst> <mode>: installs src as the root-owned file dst, replacing
# it atomically. Succeeds only when dst changed.
put() {
	local src=$1 dst=$2 mode=$3
	if [[ -f $dst && ! -L $dst ]] && cmp -s "$src" "$dst" && [[ $(stat -c '%u:%g %a' "$dst") == "0:0 ${mode#0}" ]]; then
		return 1
	fi
	install -o root -g root -m "$mode" "$src" "$dst.barmkin-new"
	mv -f "$dst.barmkin-new" "$dst"
}

# install_marketplace: the shim's marketplace, without its tests and dev
# files, root-owned and read-only to everyone else. Succeeds only when it
# changed.
install_marketplace() {
	local stage src=$repo/plugins/claude-code
	stage=$(mktemp -d)
	mkdir -p "$stage/claude-code/barmkin-shim"
	cp -R "$src/.claude-plugin" "$stage/claude-code/"
	cp -R "$src/barmkin-shim/.claude-plugin" "$src/barmkin-shim/hooks" "$src/barmkin-shim/types" "$stage/claude-code/barmkin-shim/"
	chown -R root:root "$stage/claude-code"
	find "$stage/claude-code" -type d -exec chmod 0755 {} +
	find "$stage/claude-code" -type f -exec chmod 0644 {} +
	install -d -o root -g root -m 0755 "$prefix" "$prefix/plugins"
	if [[ -d $marketplace && ! -L $marketplace ]] && diff -r "$stage/claude-code" "$marketplace" >/dev/null &&
		[[ -z $(find "$marketplace" \( -type d ! -perm 0755 \) -o \( -type f ! -perm 0644 \) -o ! -user root -o ! -group root -o -type l) ]]; then
		rm -rf "$stage"
		return 1
	fi
	rm -rf "$marketplace.barmkin-new"
	mv "$stage/claude-code" "$marketplace.barmkin-new"
	rm -rf "$stage" "$marketplace"
	mv "$marketplace.barmkin-new" "$marketplace"
}

# install_settings <uid>: writes the managed settings, unless a file this
# installer did not write is already there.
install_settings() {
	local want have recorded tmp
	tmp=$(mktemp)
	render_settings "$1" >"$tmp"
	want=$(sha <"$tmp")
	if [[ -L $settings ]]; then
		rm -f "$tmp"
		die "$settings is a symlink; remove it and run again"
	elif [[ -e $settings ]]; then
		have=$(sha <"$settings")
		recorded=$(cat "$settings_record" 2>/dev/null || true)
		if [[ $have != "$want" && $have != "$recorded" ]]; then
			rm -f "$tmp"
			die "$settings exists and was not written by this installer; barmkin's managed settings replace the whole file, so move it aside and run again"
		fi
	fi
	install -d -o root -g root -m 0755 "$(dirname "$settings")"
	if put "$tmp" "$settings" 0644; then say "managed settings → $settings (gate pinned to uid $1)"; fi
	printf '%s\n' "$want" >"$tmp"
	put "$tmp" "$settings_record" 0644 || true
	rm -f "$tmp"
}

# remove_admin: takes the administrative socket away from the monitor, then
# stops and removes it. The drop-in goes first, so stopping the socket does
# not stop the monitor that required it. Succeeds only when something was
# removed; the caller restarts the monitor.
remove_admin() {
	local removed=1
	if [[ -e $admin_dropin ]]; then
		rm -f "$admin_dropin"
		rmdir "$admin_dropin_dir" 2>/dev/null || true
		systemctl daemon-reload
		removed=0
	fi
	if [[ -e $admin_unit ]] || systemctl cat "$admin_unit_name" >/dev/null 2>&1; then
		systemctl stop "$admin_unit_name" 2>/dev/null || true
	fi
	if [[ -e $admin_unit ]]; then
		rm -f "$admin_unit"
		systemctl daemon-reload
		removed=0
	fi
	systemctl reset-failed "$admin_unit_name" 2>/dev/null || true
	[[ -e $admin_dir ]] && rm -rf "$admin_dir"
	return $removed
}

# install_jevproxy: the root-owned Jev proxy unit and its caller group.
# Never touches the key file: the operator provisions it out of band.
# Succeeds only when something changed; the caller reloads and restarts.
install_jevproxy() {
	local c changed=1
	getent group "$jev_caller_group" >/dev/null || { groupadd --system "$jev_caller_group"; say "group $jev_caller_group created"; }
	for c in "${jev_callers[@]}"; do
		id -u "$c" >/dev/null 2>&1 || die "no such user: $c"
		if ! id -nG "$c" | tr ' ' '\n' | grep -qx "$jev_caller_group"; then
			usermod -aG "$jev_caller_group" "$c"
			say "user $c added to $jev_caller_group (log in again to take it)"
		fi
	done
	if put "$repo/packaging/systemd/$jevproxy_unit_name" "$jevproxy_unit" 0644; then
		say "unit → $jevproxy_unit"
		changed=0
	fi
	if [[ ! -e $jev_key ]]; then
		say "WARNING: $jev_key does not exist yet; create it root-owned, mode 0600, before the unit can start"
	fi
	return $changed
}

# remove_jevproxy: takes the Jev proxy away, stopping and removing its
# unit, runtime directory and caller group. Never removes the key file.
# Succeeds only when something was removed.
remove_jevproxy() {
	local removed=1
	if [[ -e $jevproxy_unit ]] || systemctl cat "$jevproxy_unit_name" >/dev/null 2>&1; then
		systemctl disable --now --quiet "$jevproxy_unit_name" 2>/dev/null || true
	fi
	if [[ -e $jevproxy_unit ]]; then
		rm -f "$jevproxy_unit"
		systemctl daemon-reload
		removed=0
	fi
	systemctl reset-failed "$jevproxy_unit_name" 2>/dev/null || true
	[[ -e $jevproxy_runtime_dir ]] && { rm -rf "$jevproxy_runtime_dir"; removed=0; }
	if getent group "$jev_caller_group" >/dev/null; then
		groupdel "$jev_caller_group"
		removed=0
	fi
	return $removed
}

# wait_for_jevproxy: the proxy is up once it answers GET /healthz with ok
# on its socket.
wait_for_jevproxy() {
	for _ in $(seq 100); do
		if [[ -S $jevproxy_socket ]] && printf 'GET /healthz HTTP/1.0\r\n\r\n' |
			timeout 2 socat -t 2 - "UNIX-CONNECT:$jevproxy_socket" 2>/dev/null | grep -q '"state":"ok"'; then
			return 0
		fi
		sleep 0.1
	done
	systemctl --no-pager status "$jevproxy_unit_name" >&2 || true
	die "the Jev proxy does not answer on $jevproxy_socket"
}

# check_policy_path: install stops, before it changes anything, at a policy
# path the shims would refuse.
check_policy_path() {
	[[ ! -L $policy_dir ]] || die "$policy_dir is a symlink; the shims refuse one, so remove it and run again"
	[[ ! -e $policy_dir || -d $policy_dir ]] || die "$policy_dir is not a directory; remove it and run again"
	[[ ! -L $policy ]] || die "$policy is a symlink; the shims refuse one, so remove it and run again"
	[[ ! -e $policy || -f $policy ]] || die "$policy is not a regular file; remove it and run again"
}

# install_policy: the root policy the shims read. A missing one is the packaged
# default; an unedited default (its hash is the one recorded at the last
# install) is updated; one root has edited keeps its content. Every one ends
# root-owned, mode 0644, in a root-owned 0755 directory: the shims refuse a
# policy anyone else can write.
install_policy() {
	local want have recorded
	check_policy_path
	if [[ ! -d $policy_dir || $(stat -c '%u:%g %a' "$policy_dir") != "0:0 755" ]]; then
		install -d -o root -g root -m 0755 "$policy_dir"
		say "policy directory → $policy_dir"
	fi
	want=$(sha <"$policy_default")
	have=$( [[ -f $policy ]] && sha <"$policy" || true)
	recorded=$(cat "$policy_record" 2>/dev/null || true)
	if [[ -z $have || $have == "$want" || $have == "$recorded" ]]; then
		if put "$policy_default" "$policy" 0644; then say "default policy → $policy"; fi
	else
		if [[ $(stat -c '%u:%g %a' "$policy") != "0:0 644" ]]; then
			chown root:root "$policy"
			chmod 0644 "$policy"
			say "policy $policy kept, made root-owned with mode 0644"
		fi
	fi
	printf '%s\n' "$want" >"$policy_record.barmkin-new"
	if cmp -s "$policy_record.barmkin-new" "$policy_record"; then
		rm -f "$policy_record.barmkin-new"
	else
		chmod 0644 "$policy_record.barmkin-new"
		mv -f "$policy_record.barmkin-new" "$policy_record"
	fi
}

# wait_for_monitor: the monitor is up once it answers health with ok on its
# socket. A socket file alone can be left over from a run that failed.
wait_for_monitor() {
	local health='{"version":1}'
	for _ in $(seq 100); do
		if [[ -S $socket ]] && printf 'POST /v1/health HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s' \
			"${#health}" "$health" | timeout 2 socat -t 2 - "UNIX-CONNECT:$socket" 2>/dev/null | grep -q '"state":"ok"'; then
			return 0
		fi
		sleep 0.1
	done
	systemctl --no-pager status "$unit_name" >&2 || true
	die "the monitor does not answer on $socket"
}

cmd_install() {
	local binary=$repo/barmkin clients=() c gid restart=0 reload=0 admin=0 admin_changed=0
	local jev_proxy=0 jev_callers=() jevproxy_changed=1 jevproxy_restart=0
	while (($#)); do
		case $1 in
		--binary) binary=${2:?--binary needs a path}; shift 2 ;;
		--client) clients+=("${2:?--client needs a user}"); shift 2 ;;
		--admin-socket) admin=1; shift ;;
		--jev-proxy) jev_proxy=1; shift ;;
		--jev-caller) jev_callers+=("${2:?--jev-caller needs a user}"); shift 2 ;;
		*) usage ;;
		esac
	done
	require_host
	[[ -x /usr/bin/bwrap && -x /usr/bin/socat ]] ||
		die "the managed sandbox needs /usr/bin/bwrap and /usr/bin/socat: apt-get install -y bubblewrap socat"
	[[ -f $binary && -x $binary ]] || die "no barmkin binary at $binary; build it with: CGO_ENABLED=0 go build -o barmkin ."
	"$binary" monitor -h >/dev/null 2>&1 || die "$binary has no monitor subcommand"
	if ((jev_proxy)); then
		"$binary" jev-proxy -h >/dev/null 2>&1 || die "$binary has no jev-proxy subcommand"
	fi
	for c in "${clients[@]}"; do
		id -u "$c" >/dev/null 2>&1 || die "no such user: $c"
	done
	check_policy_path

	getent group "$client_group" >/dev/null || { groupadd --system "$client_group"; say "group $client_group created"; }
	gid=$(getent group "$client_group" | cut -d: -f3)
	if ! getent passwd "$service_user" >/dev/null; then
		useradd --system --gid "$client_group" --no-create-home --home-dir /nonexistent \
			--shell /usr/sbin/nologin --comment "barmkin monitor" "$service_user"
		say "user $service_user created"
	fi
	[[ $(id -g "$service_user") == "$gid" ]] ||
		die "user $service_user exists with another primary group; its primary group must be $client_group"
	for c in "${clients[@]}"; do
		if ! id -nG "$c" | tr ' ' '\n' | grep -qx "$client_group"; then
			usermod -aG "$client_group" "$c"
			say "user $c added to $client_group (log in again to take it)"
		fi
	done

	if put "$binary" "$bin" 0755; then say "binary → $bin"; restart=1; fi
	if install_marketplace; then say "shim marketplace → $marketplace"; fi
	if put "$repo/packaging/systemd/$unit_name" "$unit" 0644; then
		say "unit → $unit"
		reload=1
	fi
	if ((admin)); then
		install -d -o root -g root -m 0755 "$admin_dropin_dir"
		if put "$repo/packaging/systemd/$admin_unit_name" "$admin_unit" 0644; then admin_changed=1; fi
		if put "$repo/packaging/systemd/barmkin-monitor-admin.conf" "$admin_dropin" 0644; then admin_changed=1; fi
		if ((admin_changed)); then
			say "administrative socket → $admin_dir/admin.sock (root only: barmkin monitor-admin)"
			reload=1
		fi
	elif remove_admin; then
		say "administrative socket removed"
		restart=1
	fi
	if ((reload)); then
		systemctl daemon-reload
		restart=1
	fi
	install_settings "$(id -u "$service_user")"
	install_policy

	systemctl enable --quiet "$unit_name"
	if ((restart)) && systemctl is-active --quiet "$unit_name"; then
		systemctl restart "$unit_name"
		say "monitor restarted"
	elif ! systemctl is-active --quiet "$unit_name"; then
		systemctl start "$unit_name"
		say "monitor started"
	fi
	wait_for_monitor
	say "monitor serving on $socket as $service_user"

	if ((jev_proxy)); then
		if install_jevproxy; then jevproxy_changed=0; fi
		systemctl daemon-reload
		systemctl enable --quiet "$jevproxy_unit_name"
		if [[ -e $jev_key ]]; then
			if ((jevproxy_changed == 0)) && systemctl is-active --quiet "$jevproxy_unit_name"; then
				systemctl restart "$jevproxy_unit_name"
				jevproxy_restart=1
			elif ! systemctl is-active --quiet "$jevproxy_unit_name"; then
				systemctl start "$jevproxy_unit_name"
				jevproxy_restart=1
			fi
			if ((jevproxy_restart)); then wait_for_jevproxy; fi
			say "Jev proxy serving on $jevproxy_socket as root"
		else
			say "Jev proxy unit installed but not started: provision $jev_key first, then systemctl start $jevproxy_unit_name"
		fi
	elif remove_jevproxy; then
		say "Jev proxy removed"
	fi
}

cmd_uninstall() {
	local have recorded rendered=
	(($# == 0)) || usage
	require_host
	if [[ -e $unit ]] || systemctl cat "$unit_name" >/dev/null 2>&1; then
		systemctl disable --now --quiet "$unit_name" 2>/dev/null || true
	fi
	if [[ -e $unit ]]; then
		rm -f "$unit"
		systemctl daemon-reload
		say "service removed"
	fi
	systemctl reset-failed "$unit_name" 2>/dev/null || true
	if remove_admin; then say "administrative socket removed"; fi
	if remove_jevproxy; then say "Jev proxy removed (the key file, if any, was left in place)"; fi

	if [[ -f $settings && ! -L $settings ]]; then
		have=$(sha <"$settings")
		recorded=$(cat "$settings_record" 2>/dev/null || true)
		if getent passwd "$service_user" >/dev/null; then
			rendered=$(render_settings "$(id -u "$service_user")" | sha)
		fi
		if [[ $have == "$recorded" || $have == "$rendered" ]]; then
			rm -f "$settings"
			rmdir "$(dirname "$settings")" 2>/dev/null || true
			say "managed settings removed"
		else
			say "left $settings in place: this installer did not write it"
		fi
	fi
	if [[ -f $policy && ! -L $policy ]]; then
		have=$(sha <"$policy")
		recorded=$(cat "$policy_record" 2>/dev/null || true)
		if [[ $have == "$recorded" || $have == "$(sha <"$policy_default")" ]]; then
			rm -f "$policy"
			say "policy removed"
		else
			say "left $policy in place: root has edited it"
		fi
	fi
	rmdir "$policy_dir" 2>/dev/null || true
	[[ -e $prefix ]] && { rm -rf "$prefix"; say "removed $prefix"; }
	[[ -e $bin ]] && { rm -f "$bin"; say "removed $bin"; }
	[[ -e $state_dir ]] && { rm -rf "$state_dir"; say "removed $state_dir"; }
	[[ -e $runtime_dir ]] && rm -rf "$runtime_dir"
	if getent passwd "$service_user" >/dev/null; then
		userdel "$service_user"
		say "user $service_user removed"
	fi
	if getent group "$client_group" >/dev/null; then
		groupdel "$client_group"
		say "group $client_group removed"
	fi
	return 0
}

case ${1:-} in
install) shift; cmd_install "$@" ;;
uninstall) shift; cmd_uninstall "$@" ;;
render-settings)
	[[ ${2:-} == --monitor-uid && $# == 3 ]] || usage
	render_settings "$3"
	;;
*) usage ;;
esac
