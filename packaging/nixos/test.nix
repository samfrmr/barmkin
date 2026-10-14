# A NixOS VM test of module.nix, with packaging/test/checks.sh:
#
#   nix-build packaging/nixos/test.nix
#
# On a clean NixOS VM with services.barmkin enabled, it checks the deployment,
# the gate, posture refusal, version-mismatch denial (the installed shim's own
# client included) and recovery after SIGKILL. It then checks that switching
# to the same configuration changes nothing, that switching to one without
# the module (twice) leaves nothing but the state directory, and that
# switching back installs it again.
{ pkgs ? import <nixpkgs> { } }:

pkgs.testers.runNixOSTest {
  name = "barmkin-managed";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ./module.nix ];
    services.barmkin = {
      enable = true;
      clients = [ "alice" ];
    };
    users.users.alice.isNormalUser = true;
    users.users.mallory.isNormalUser = true;
    environment.systemPackages = [ pkgs.curl pkgs.socat pkgs.nodejs_24 ];
    specialisation.uninstalled.configuration.services.barmkin.enable = lib.mkForce false;
  };

  testScript = ''
    checks = "bash ${../test/checks.sh}"
    installed = "/run/booted-system/bin/switch-to-configuration test"
    uninstalled = "/run/booted-system/specialisation/uninstalled/bin/switch-to-configuration test"

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("barmkin-monitor.service")

    with subtest("installed"):
        print(machine.succeed(f"{checks} installed alice mallory"))

    with subtest("switching again changes nothing"):
        before = machine.succeed(f"{checks} fingerprint")
        machine.succeed(installed)
        after = machine.succeed(f"{checks} fingerprint")
        print(after)
        assert before == after, f"a second switch changed the installed state:\n{before}\n---\n{after}"

    with subtest("uninstalled, twice"):
        machine.succeed(uninstalled)
        print(machine.succeed(f"{checks} absent --keep-state"))
        machine.succeed(uninstalled)
        print(machine.succeed(f"{checks} absent --keep-state"))

    with subtest("installed again"):
        machine.succeed(installed)
        machine.wait_for_unit("barmkin-monitor.service")
        print(machine.succeed(f"{checks} installed alice mallory"))
  '';
}
