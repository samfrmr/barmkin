# barmkin built from this checkout: the static binary, the monitor's
# systemd unit pointing at it, and the Claude Code shim's marketplace. The
# opt-in administrative socket and its drop-in are kept apart, in
# share/barmkin/systemd, so they are installed only when module.nix's
# services.barmkin.adminSocket.enable links them in.
{ lib, buildGoModule }:

let
  root = ../..;
  shim = root + "/plugins/claude-code/barmkin-shim";
in
buildGoModule {
  pname = "barmkin";
  version = "1.0.0";

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/go.mod")
      (root + "/go.sum")
      (lib.fileset.fileFilter (f: f.hasExt "go") root)
      (root + "/packaging/systemd/barmkin-monitor.service")
      (root + "/packaging/systemd/barmkin-monitor-admin.socket")
      (root + "/packaging/systemd/barmkin-monitor-admin.conf")
      (root + "/plugins/claude-code/.claude-plugin")
      (shim + "/.claude-plugin")
      (shim + "/hooks")
      (shim + "/types")
    ];
  };
  vendorHash = "sha256-g+yaVIx4jxpAQ/+WrGKxhVeliYx7nLQe/zsGpxV4Fn4=";

  subPackages = [ "." ];
  env.CGO_ENABLED = "0";
  ldflags = [ "-s" "-w" ];
  # go test needs node, curl and the claude CLI; run it from the checkout.
  doCheck = false;

  postInstall = ''
    install -Dm0644 packaging/systemd/barmkin-monitor.service $out/lib/systemd/system/barmkin-monitor.service
    substituteInPlace $out/lib/systemd/system/barmkin-monitor.service \
      --replace-fail /usr/local/bin/barmkin $out/bin/barmkin
    install -Dm0644 packaging/systemd/barmkin-monitor-admin.socket $out/share/barmkin/systemd/barmkin-monitor-admin.socket
    install -Dm0644 packaging/systemd/barmkin-monitor-admin.conf $out/share/barmkin/systemd/barmkin-monitor.service.d/admin.conf
    substituteInPlace $out/share/barmkin/systemd/barmkin-monitor.service.d/admin.conf \
      --replace-fail /usr/local/bin/barmkin $out/bin/barmkin
    mkdir -p $out/share/barmkin/plugins
    cp -R plugins/claude-code $out/share/barmkin/plugins/
  '';

  meta = {
    description = "Regex guardrail for AI coding agents, with the barmkin monitor and its Claude Code shim";
    license = lib.licenses.mit;
    mainProgram = "barmkin";
  };
}
