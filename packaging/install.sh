#!/usr/bin/env bash
# Installs or uninstalls the root-managed barmkin monitor and the managed
# Claude Code seat on a systemd host such as Ubuntu or Debian. NixOS uses the
# module in packaging/nixos instead.
#
#   packaging/install.sh install [--binary PATH] [--client USER]...
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
#     to the barmkin user's uid (-monitor-uid).
# Running it again changes nothing that is already in place. It refuses to
# replace managed settings it did not write.
#
# uninstall, as root, stops and removes the service, its state and runtime
# directories, the files above, the user and the group. It leaves managed
# settings it did not write in place. Running it again is a no-op.
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
readonly prefix=/opt/barmkin
readonly marketplace=$prefix/plugins/claude-code
readonly settings_record=$prefix/managed-settings.sha256
readonly settings=/etc/claude-code/managed-settings.json
readonly state_dir=/var/lib/barmkin
readonly runtime_dir=/run/barmkin
readonly socket=$runtime_dir/monitor.sock
readonly recipe=$repo/plugins/claude-code/managed-settings.example.json
readonly gate_command="$bin gate -socket $socket"

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
	local binary=$repo/barmkin clients=() c gid restart=0
	while (($#)); do
		case $1 in
		--binary) binary=${2:?--binary needs a path}; shift 2 ;;
		--client) clients+=("${2:?--client needs a user}"); shift 2 ;;
		*) usage ;;
		esac
	done
	require_host
	[[ -x /usr/bin/bwrap && -x /usr/bin/socat ]] ||
		die "the managed sandbox needs /usr/bin/bwrap and /usr/bin/socat: apt-get install -y bubblewrap socat"
	[[ -f $binary && -x $binary ]] || die "no barmkin binary at $binary; build it with: CGO_ENABLED=0 go build -o barmkin ."
	"$binary" monitor -h >/dev/null 2>&1 || die "$binary has no monitor subcommand"
	for c in "${clients[@]}"; do
		id -u "$c" >/dev/null 2>&1 || die "no such user: $c"
	done

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
		systemctl daemon-reload
		restart=1
	fi
	install_settings "$(id -u "$service_user")"

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
