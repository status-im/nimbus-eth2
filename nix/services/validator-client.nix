{ packages }:

{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption mkIf
    types filterAttrs escapeShellArgs literalExpression
    optionals optionalString;

  cfg = config.services.nimbus-validator-client;
  system = pkgs.stdenv.hostPlatform.system;

  toml = pkgs.formats.toml {};
  removeNull = k: v: v != null;
  cleanSettings = filterAttrs removeNull cfg.settings;
  configFile = toml.generate "nimbus-validator-client.toml" cleanSettings;
in {
  options = {
    services = {
      nimbus-validator-client = {
        enable = mkEnableOption "Nimbus Eth2 Validator Client service.";

        package = mkOption {
          type = types.package;
          default = packages.${system}.validator_client;
          defaultText = literalExpression "inputs.nimbus-eth2.packages.${system}.validator-client";
          description = lib.mdDoc "Package to use as Go Ethereum node.";
        };

        extraArgs = mkOption {
          type = types.listOf types.str;
          description = lib.mdDoc "Additional arguments passed to node.";
          default = [];
        };

        settings = mkOption {
          description = "TOML config file settings for Nimbus Eth2 validator client.";
          default = {};
          type = types.submodule {
            freeformType = toml.type;
            options = {
              data-dir = mkOption {
                type = types.str;
                default = "%S/nimbus-validator-client";
                description = "Directory for client keys and slashing DB.";
              };

              log-level = mkOption {
                type = types.str;
                default = "info";
                description = "Logging level for the node.";
              };

              log-format = mkOption {
                type = types.str;
                default = "auto";
                description = "Logging formatting (auto, colors, nocolors, json).";
              };

              doppelganger-detection = mkOption {
                type = types.bool;
                default = true;
                description = ''
                  Protection against slashing due to double-voting.
                  Means you will miss two attestations when restarting.
                '';
              };

              beacon-node = mkOption {
                type = types.listOf types.str;
                default = [];
                description = "URL addresses to one or more beacon node HTTP REST APIs [=$defaultBeaconNodeUri].";
              };

              payload-builder = mkOption {
                type = types.nullOr types.bool;
                default = null;
                description = "Enable usage of beacon node with external payload builder (BETA) [=false].";
              };

              web3-signer-url = mkOption {
                type = types.listOf types.str;
                default = [];
                description = "Remote Web3Signer URLs that will be used as a source of validators.";
              };

              # INFO: Shorter than slot time (12s) makes little sense. There's also some overhead.
              web3-signer-update-interval = mkOption {
                type = types.int;
                default = 3600;
                description = "Number of seconds between validator list updates [=3600].";
              };

              suggested-fee-recipient = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Suggested fee recipient.";
              };

              keymanager = mkEnableOption "Enable the REST keymanager API";

              keymanager-port = mkOption {
                type = types.port;
                default = 5062;
                description = "Listening port for the REST keymanager API";
              };

              keymanager-address = mkOption {
                type = types.nullOr types.str;
                default = "127.0.0.1";
                description = "Listening port for the REST keymanager API";
              };

              keymanager-allow-origin = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = ''
                  Limit the access to the Keymanager API to a particular hostname
                  (for CORS-enabled clients such as browsers).
                '';
              };

              keymanager-token-file = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "A file specifying the authorizition token required for accessing the keymanager";
              };

              metrics = mkEnableOption "Nimbus Eth2 metrics endpoint";

              metrics-address = mkOption {
                type = types.str;
                default = "127.0.0.1";
                description = "Metrics address for validator-client.";
              };

              metrics-port = mkOption {
                type = types.port;
                default = 8008;
                description = "Metrics port for validator client.";
              };
            };
          };
        };
      };
    };
  };

  config = mkIf cfg.enable {
    environment.etc."ethereum/nimbus-validator-client.toml".source = configFile;

    systemd.services.nimbus-validator-client = {
      enable = true;
      serviceConfig = {
        LimitNOFILE = 16384;
        DynamicUser = true;

        # Hardening measures
        PrivateTmp = "true";
        ProtectSystem = "full";
        NoNewPrivileges = "true";
        PrivateDevices = "true";
        MemoryDenyWriteExecute = "true";
        WorkingDirectory = "%S/nimbus-validator-client";
        StateDirectory = "nimbus-validator-client";
        LoadCredential = optionals (cfg.settings.keymanager-token-file != null) [
          "keymanager-token-file:${cfg.settings.keymanager-token-file}"
        ];

        Restart = "on-failure";
        RestartPreventExitStatus = "129";
        ExecStart = let
          keymanagerTokenFlag = optionalString (cfg.settings.keymanager-token-file != null)
            "--keymanager-token-file=%d/keymanager-token-file";
        in ''
          ${cfg.package}/bin/nimbus_validator_client \
            --data-dir=${cfg.settings.data-dir} \
            --config-file=${configFile} ${keymanagerTokenFlag} \
            ${escapeShellArgs cfg.extraArgs}
        '';
      };
      wants = ["network-online.target"];
      after = ["network-online.target"];
      wantedBy = ["multi-user.target"];
    };
  };
}
