{ packages }:

{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption mkIf
    types filterAttrs escapeShellArgs literalExpression
    optionals optionalAttrs optionalString;

  cfg = config.services.nimbus-beacon-node;
  system = pkgs.stdenv.hostPlatform.system;

  toml = pkgs.formats.toml { };
  removeNull = k: v: v != null;
  cleanSettings = filterAttrs removeNull cfg.settings;
  configFile = toml.generate "nimbus-beacon-node.toml" cleanSettings;
in {
  options = {
    services = {
      nimbus-beacon-node = {
        enable = mkEnableOption "Nimbus Eth2 Beacon Node service.";

        package = mkOption {
          type = types.package;
          default = packages.${system}.beacon_node;
          defaultText = literalExpression "inputs.nimbus-eth2.packages.${system}.beacon-node";
          description = lib.mdDoc "Package to use as Go Ethereum node.";
        };

        extraArgs = mkOption {
          type = types.listOf types.str;
          description = lib.mdDoc "Additional arguments passed to node.";
          default = [];
        };

        settings = mkOption {
          description = "TOML config file settings for Nimbus Eth2 beacon node.";
          default = {};
          type = types.submodule {
            freeformType = toml.type;
            options = {
              data-dir = mkOption {
                type = types.path;
                default = "/var/lib/nimbus-beacon-node";
                description = "Directory for Nimbus Eth2 blockchain data.";
              };

              era-dir = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Directory for Nimbus Eth2 ERA files.";
              };

              network = mkOption {
                type = types.str;
                default = "mainnet";
                description = "Name of Eth2 network to connect to.";
              };

              graffiti = mkOption {
                type = types.str;
                default = "nimbus-beacon-node";
                description = "Name of Eth2 network to connect to.";
              };

              genesis-state = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "SSZ file specifying the genesis state of the network";
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

              num-threads = mkOption {
                type = types.int;
                default = 0;
                description = "Number of worker threads. Use 0 to detect CPU cores.";
              };

              nat = mkOption {
                type = types.str;
                default = "any";
                example = "extip:12.34.56.78";
                description = "Way to detect public IP address of the node to advertise.";
              };

              web3-url = mkOption {
                type = types.listOf types.str;
                default = [];
                description = "URL for the Web3 RPC endpoint.";
              };

              jwt-secret = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Path of JWT secret for Auth RPC endpoint.";
              };

              subscribe-all-subnets = mkOption {
                type = types.bool;
                default = false;
                description = "Subscribe to all attestation subnet topics.";
              };

              doppelganger-detection = mkOption {
                type = types.bool;
                default = true;
                description = ''
                  Protection against slashing due to double-voting.
                  Means you will miss two attestations when restarting.
                '';
              };

              suggested-fee-recipient = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = ''
                  Wallet address where transaction fee tips - priority fees,
                  unburnt portion of gas fees - will be sent.
                '';
              };

              tcp-port = mkOption {
                type = types.int;
                default = 9000;
                description = "Listen port for libp2p protocol.";
              };

              udp-port = mkOption {
                type = types.int;
                default = 9000;
                description = "Listen port for libp2p protocol.";
              };

              metrics = mkEnableOption "Nimbus Eth2 metrics endpoint";

              metrics-address = mkOption {
                type = types.str;
                default = "127.0.0.1";
                description = "Metrics address for beacon node.";
              };

              metrics-port = mkOption {
                type = types.int;
                default = 9100;
                description = "Metrics port for beacon node.";
              };

              rest = mkEnableOption "Nimbus Eth2 REST API";

              rest-address = mkOption {
                type = types.str;
                default = "127.0.0.1";
                description = "Listening address of the REST API server";
              };

              rest-port = mkOption {
                type = types.int;
                default = 5052;
                description = "Port for the REST API server";
              };

              payload-builder = mkEnableOption "Nimbus Eth2 REST API";

              payload-builder-url = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "URL of builder API endpoint.";
              };

              local-block-value-boost = mkOption {
                type = types.int;
                default = 10;
                description = "Bump exec layer builder bid comparison by a percentage.";
              };
            };
          };
        };
      };
    };
  };

  config = mkIf cfg.enable {
    environment.etc."ethereum/nimbus-beacon-node.toml".source = configFile;

    systemd.services.nimbus-beacon-node = {
      enable = true;
      serviceConfig = {
        DynamicUser = true;

        # Hardening measures
        PrivateTmp = "true";
        ProtectSystem = "full";
        NoNewPrivileges = "true";
        PrivateDevices = "true";
        MemoryDenyWriteExecute = "true";
        WorkingDirectory = "%S/nimbus-beacon-node";
        StateDirectory = "nimbus-beacon-node";
        LoadCredential = optionals (cfg.settings.jwt-secret != null) [
          "jwt-secret:${cfg.settings.jwt-secret}"
        ];

        Restart = "on-failure";
        ExecStart = let
          jwtFlag = optionalString (cfg.settings.jwt-secret != null)
            "--jwt-secret=%d/jwt-secret";
        in ''
          ${cfg.package}/bin/nimbus_beacon_node \
            --config-file=${configFile} ${jwtFlag} \
            ${escapeShellArgs cfg.extraArgs}
        '';
      };
      wantedBy = [ "multi-user.target" ];
      requires = [ "network.target" ];
    };
  };
}
