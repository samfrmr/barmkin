# The root-managed barmkin monitor and the managed Claude Code seat on NixOS:
# the counterpart of packaging/install.sh.
#
#   imports = [ ./packaging/nixos/module.nix ];
#   services.barmkin = { enable = true; clients = [ "alice" ]; };
#
# It declares the system group barmkin-clients (with the clients as members)
# and the system user barmkin, runs packaging/systemd/barmkin-monitor.service
# from the package, and writes /etc/claude-code/managed-settings.json from
# plugins/claude-code/managed-settings.example.json with the gate, the shim's
# marketplace and the sandbox helpers pointing into the Nix store, and the
# gate pinned to the barmkin user's uid.
#
# Switching to a configuration without it uninstalls: the unit, the managed
# settings, the user and the group go. Like any systemd StateDirectory,
# /var/lib/barmkin stays.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.barmkin;

  socket = "/run/barmkin/monitor.sock";
  recipe = lib.importJSON ../../plugins/claude-code/managed-settings.example.json;
  recipeGate = "/usr/local/bin/barmkin gate -socket ${socket}";
  gate = "${lib.getExe cfg.package} gate -socket ${socket} -monitor-uid ${toString cfg.uid}";

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

    systemd.packages = [ cfg.package ];
    systemd.services.barmkin-monitor.wantedBy = [ "multi-user.target" ];

    environment.etc."claude-code/managed-settings.json" = {
      text = builtins.toJSON managedSettings;
      mode = "0644";
    };
  };
}
