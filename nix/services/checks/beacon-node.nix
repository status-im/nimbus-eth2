{ self, pkgs, ... }:

pkgs.testers.runNixOSTest {
  name = "nimbus-beacon-node-check";

  nodes.machine = {
    imports = [ self.nixosModules.beacon-node ];

    services.nimbus-beacon-node = {
      enable = true;
      settings = {
        rest = true;
        metrics = true;
        # Avoid wasting time on Genesis download
        genesis-state = toString (pkgs.fetchurl {
          url = "https://github.com/eth-clients/hoodi/releases/download/genesis/genesis.ssz";
          sha256 = "sha256-f0IlfvaeBVSWyWSnU7sH5UABzNV6tGfvctZ68Ia8/Oc=";
        });
      };
    };
  };

  testScript = { nodes, ... }: with nodes.machine.services.nimbus-beacon-node.settings; ''
    machine.wait_for_unit("nimbus-beacon-node.service")

    # Port checks
    machine.wait_for_open_port(${toString rest-port})
    machine.wait_for_open_port(${toString metrics-port})
    machine.wait_for_open_port(${toString tcp-port})
    machine.wait_for_open_port(${toString udp-port})

    # API checks
    machine.succeed("curl -fsS localhost:${toString rest-port}/eth/v1/node/health")
    machine.succeed("curl -fsS localhost:${toString metrics-port}/metrics | grep -E '^beacon_'")
  '';
}
