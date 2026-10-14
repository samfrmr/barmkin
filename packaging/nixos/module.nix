# The root-managed barmkin monitor and the managed Claude Code seat on NixOS:
# the counterpart of packaging/install.sh.
#
#   imports = [ ./packaging/nixos/module.nix ];
#   services.barmkin = { enable = true; clients = [ "alice" ]; };
#
# services.barmkin.adminSocket.enable (off by default) also installs the
# root-only administrative socket, barmkin-monitor-admin.socket, with the
# drop-in that hands it to the monitor, and puts barmkin on the system PATH
# for root's `barmkin monitor-admin`. Without it, nothing lowers a leg.
#
# It declares the system group barmkin-clients (with the clients as members)
# and the system user barmkin, runs packaging/systemd/barmkin-monitor.service
# from the package, and writes /etc/claude-code/managed-settings.json from
# plugins/claude-code/managed-settings.example.json with the gate, the shim's
# marketplace and the sandbox helpers pointing into the Nix store, and the
# gate pinned to the barmkin user's uid. It also writes the root policy the
# shims read, /etc/barmkin/policy.yaml (services.barmkin.policy, by default
# packaging/policy.yaml), as a root-owned 0644 copy rather than a link into
# the store, since the shims refuse a symbolic link.
#
# Switching to a configuration without it uninstalls: the unit, the managed
# settings, the policy, the user and the group go. Like any systemd StateDirectory,
# /var/lib/barmkin stays.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.barmkin;

  socket = "/run/barmkin/monitor.sock";
  recipe = lib.importJSON ../../plugins/claude-code/managed-settings.example.json;
  recipeGate = "/usr/local/bin/barmkin gate -socket ${socket}";
  gate = "${lib.getExe cfg.package} gate -socket ${socket} -monitor-uid ${toString cfg.uid}";

  # The opt-in administrative socket unit and the monitor's drop-in, from
  # the package, as a unit package of their own.
  adminUnits = pkgs.runCommand "barmkin-admin-units" { } ''
    mkdir -p $out/lib/systemd/system
    cp -R ${cfg.package}/share/barmkin/systemd/. $out/lib/systemd/system/
  '';

  pinGate = hook: if hook.command or null == recipeGate then hook // { command = gate; } else hook;
  preToolUse = map (entry: entry // { hooks = map pinGate entry.hooks; }) recipe.hooks.PreToolUse;
  gates = lib.filter (hook: hook.command or null == gate) (lib.concatMap (entry: entry.hooks) preToolUse);

  managedSettings = lib.recursiveUpdate recipe {
    sandbox = {
      bwrapPath = lib.getExe' pkgs.bubblewrap "bwrap";
      socatPath = lib.getExe' pkgs.socat "socat";
    };
    hooks.PreToolUse = preToolUse;
    extraKnownMarketplaces.barmkin-local.source.path = "${cfg.package}/share/barmkin/plugins/claude-code";
  };
in
{
  options.services.barmkin = {
    enable = lib.mkEnableOption "the barmkin monitor and the managed Claude Code seat";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The barmkin package: binary, monitor unit and Claude Code shim marketplace.";
    };

    uid = lib.mkOption {
      type = lib.types.ints.between 1 999;
      default = 917;
      description = ''
        The uid of the barmkin service user. The managed gate is pinned to it
        (-monitor-uid), so it is fixed when the configuration is built.
      '';
    };

    adminSocket.enable = lib.mkEnableOption ''
      the monitor's root-only administrative socket, through which root's
      `barmkin monitor-admin clear` lowers one lineage's legs from a terminal.
      Off by default, so the taint is sticky. Clearing monitor state does not
      remove untrusted material already in an AI conversation
    '';

    policy = lib.mkOption {
      type = lib.types.path;
      default = ../policy.yaml;
      defaultText = lib.literalExpression "./packaging/policy.yaml";
      description = ''
        The root policy the barmkin shims read at /etc/barmkin/policy.yaml. It
        can only add redaction rules, injection phrases, secret paths and
        outward-effect commands to the built-in ones; see packaging/policy.yaml
        for the schema. A policy the shims cannot check makes them deny every
        step they guard.
      '';
    };

    clients = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "alice" ];
      description = "Users added to barmkin-clients, the group allowed to connect to the monitor socket.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.length gates == 1;
        message = "services.barmkin: ${toString ../../plugins/claude-code/managed-settings.example.json} must have exactly one PreToolUse command '${recipeGate}' to pin";
      }
    ];

    users.groups.barmkin-clients.members = cfg.clients;
    users.users.barmkin = {
      isSystemUser = true;
      inherit (cfg) uid;
      group = "barmkin-clients";
      description = "barmkin monitor";
    };

    systemd.packages = [ cfg.package ] ++ lib.optional cfg.adminSocket.enable adminUnits;
    environment.systemPackages = lib.optional cfg.adminSocket.enable cfg.package;
    systemd.services.barmkin-monitor.wantedBy = [ "multi-user.target" ];

    environment.etc."claude-code/managed-settings.json" = {
      text = builtins.toJSON managedSettings;
      mode = "0644";
    };

    # A mode makes a copy, owned by root, not a link into the store.
    environment.etc."barmkin/policy.yaml" = {
      source = cfg.policy;
      mode = "0644";
    };
  };
}
