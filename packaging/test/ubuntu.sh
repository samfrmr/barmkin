#!/usr/bin/env bash
# Installs and uninstalls the managed barmkin monitor with packaging/install.sh
# on clean Ubuntu releases, each booted with systemd in a disposable
# privileged container, and runs packaging/test/checks.sh there.
#
#   packaging/test/ubuntu.sh [release...]     default: 24.04 22.04
#
# For each release, from the stock ubuntu image plus systemd, curl and the
# sandbox helpers (bubblewrap, socat), it:
#   - installs, and checks the deployment, the gate, posture refusal,
#     version-mismatch denial and recovery after SIGKILL (checks.sh installed);
#   - installs again, and checks that nothing changed, the monitor included;
#   - opts in to the administrative socket (--admin-socket), checks it
#     (checks.sh admin), that installing again changes nothing, and that a
#     SIGKILL restart keeps it; then opts out again and checks it is gone;
#   - checks that install refuses managed settings it did not write;
#   - uninstalls, twice, and checks that nothing is left (checks.sh absent);
#   - installs once more and checks again.
# Needs docker and go; exits 77 without them. Exits non-zero on the first
# failure. Nothing outside the containers and a temporary directory changes.
set -euo pipefail

cd "$(dirname "$0")/../.."

for tool in docker go; do
	command -v "$tool" >/dev/null || { echo "SKIP: $tool not found" >&2; exit 77; }
done
releases=("$@")
((${#releases[@]})) || releases=(24.04 22.04)

work=$(mktemp -d "${TMPDIR:-/tmp}/barmkin-ubuntu.XXXXXX")
container=
cleanup() {
	[[ -n $container ]] && docker rm -f "$container" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

echo "== build (static)"
CGO_ENABLED=0 go build -o "$work/barmkin" .

run_in() { docker exec "$container" "$@"; }
step() { echo; echo "== ubuntu $release: $*"; }

for release in "${releases[@]}"; do
	image=barmkin-packaging-test:ubuntu-$release
	step "image"
	docker build -q -t "$image" - <<EOF >/dev/null
FROM ubuntu:$release
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus curl ca-certificates bubblewrap socat \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty.target systemd-logind.service console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
	echo "  $image"

	container=$(docker run -d --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
		-v "$PWD:/src:ro" -v "$work/barmkin:/build/barmkin:ro" "$image")
	for _ in $(seq 100); do
		state=$(run_in systemctl is-system-running 2>/dev/null || true)
		[[ $state == running || $state == degraded ]] && break
		sleep 0.2
	done
	# shellcheck disable=SC2016 # expanded in the container
	echo "  booted: $(run_in sh -c '. /etc/os-release; echo "$PRETTY_NAME"'), systemd $(run_in systemctl --version | head -1 | cut -d' ' -f2), $state"
	run_in useradd --create-home alice
	run_in useradd --create-home mallory

	step "install"
	run_in /src/packaging/install.sh install --binary /build/barmkin --client alice
	run_in /src/packaging/test/checks.sh installed alice mallory

	step "install again (idempotent)"
	before=$(run_in /src/packaging/test/checks.sh fingerprint)
	run_in /src/packaging/install.sh install --binary /build/barmkin --client alice
	after=$(run_in /src/packaging/test/checks.sh fingerprint)
	if [[ $before != "$after" ]]; then
		diff <(echo "$before") <(echo "$after") || true
		echo "FAIL: a second install changed the installed state" >&2
		exit 1
	fi
	echo "ok   - nothing changed, monitor included: $(tail -1 <<<"$after")"

	step "opt in to the administrative socket"
	run_in /src/packaging/test/checks.sh no-admin
	run_in /src/packaging/install.sh install --binary /build/barmkin --client alice --admin-socket
	run_in /src/packaging/test/checks.sh admin alice mallory
	before=$(run_in /src/packaging/test/checks.sh fingerprint)
	run_in /src/packaging/install.sh install --binary /build/barmkin --client alice --admin-socket
	after=$(run_in /src/packaging/test/checks.sh fingerprint)
	if [[ $before != "$after" ]]; then
		diff <(echo "$before") <(echo "$after") || true
		echo "FAIL: a second install with --admin-socket changed the installed state" >&2
		exit 1
	fi
	echo "ok   - installing again changed nothing"
	run_in /src/packaging/test/checks.sh installed alice mallory
	run_in /src/packaging/test/checks.sh admin alice mallory

	step "opt out of the administrative socket"
	run_in /src/packaging/install.sh install --binary /build/barmkin --client alice
	run_in /src/packaging/test/checks.sh no-admin
	run_in /src/packaging/test/checks.sh installed alice mallory

	step "managed settings it did not write"
	run_in sh -c 'echo "{}" >/etc/claude-code/managed-settings.json'
	if out=$(run_in /src/packaging/install.sh install --binary /build/barmkin 2>&1); then
		echo "FAIL: install replaced managed settings it did not write" >&2
		exit 1
	fi
	echo "ok   - install refuses: ${out##*$'\n'}"
	out=$(run_in /src/packaging/install.sh uninstall)
	[[ $out == *"left /etc/claude-code/managed-settings.json in place"* ]] ||
		{ echo "FAIL: uninstall removed managed settings it did not write: $out" >&2; exit 1; }
	[[ $(run_in cat /etc/claude-code/managed-settings.json) == "{}" ]] || { echo "FAIL: foreign managed settings changed" >&2; exit 1; }
	echo "ok   - uninstall leaves them in place"
	run_in rm /etc/claude-code/managed-settings.json
	run_in rmdir /etc/claude-code
	run_in /src/packaging/test/checks.sh absent

	step "install, uninstall, uninstall again"
	run_in /src/packaging/install.sh install --binary /build/barmkin --client alice --admin-socket
	run_in /src/packaging/install.sh uninstall
	run_in /src/packaging/test/checks.sh absent
	run_in /src/packaging/install.sh uninstall
	run_in /src/packaging/test/checks.sh absent

	step "reinstall after uninstall"
	run_in /src/packaging/install.sh install --binary /build/barmkin --client alice
	run_in /src/packaging/test/checks.sh installed alice mallory

	docker rm -f "$container" >/dev/null
	container=
done
echo
echo "PASS: packaging on ubuntu ${releases[*]}"
