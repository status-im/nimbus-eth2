{ self, pkgs, ... }:

pkgs.testers.runNixOSTest {
  name = "nimbus-validator-client-check";

  nodes.machine = {
    imports = [ self.nixosModules.validator-client ];

    services.nimbus-validator-client = {
      enable = true;
      settings.keymanager = true;
    };
  };

  testScript = { nodes, ... }: with nodes.machine.services.nimbus-validator-client.settings; ''
    machine.wait_for_unit("nimbus-validator-client.service")

    # Port checks
    machine.wait_for_open_port(${toString keymanager-port})
    machine.wait_for_open_port(${toString metrics-port})

    # API checks
    machine.succeed("curl -fsS localhost:${toString metrics-port}/metrics | grep -E '^beacon_'")
    machine.succeed("curl -fsS localhost:${toString keymanager-port}/eth/v1/keystores")
  '';
}
