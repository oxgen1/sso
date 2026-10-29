# NixOS VM test for nixosModules.sso: the hardened unit starts with the CA key
# from LoadCredential, answers the device flow, the enroll wrapper works for
# root only, and the audit chain of the run verifies. No browser: passkeys
# are covered by the Go tests.
# Run with: nix build .#checks.x86_64-linux.sso -L
{ pkgs, module, package }:

let
  # A throwaway CA. Its key is in the Nix store, which is fine for a test.
  ca = pkgs.runCommand "sso-test-ca" { } ''
    ${package}/bin/sso ca init --name "test CA" --years 1 --out $out
  '';
in
pkgs.testers.runNixOSTest {
  name = "sso";

  nodes.machine = {
    imports = [ module ];

    services.sso = {
      enable = true;
      rpId = "auth.jack.farm";
      origin = "https://id.auth.jack.farm";
      caCertificate = "${ca}/ca.pem";
      caKeyFile = "/run/keys/sso-ca.key";
      users.jack = {
        roles = [ "write" ];
        services = [ "statusd" ];
      };
    };

    # Where a secrets tool would put the key: root-only, outside the store.
    systemd.tmpfiles.rules = [
      "d /run/keys 0750 root root -"
      "C /run/keys/sso-ca.key 0400 root root - ${ca}/ca.key"
    ];
    systemd.services.sso = {
      after = [ "systemd-tmpfiles-setup.service" ];
      requires = [ "systemd-tmpfiles-setup.service" ];
    };

    users.users.member.isNormalUser = true;
    environment.systemPackages = [ pkgs.openssl ];
  };

  testScript = ''
    import json

    machine.wait_for_unit("sso.service")
    machine.wait_for_open_port(9300)

    with subtest("sign-in page"):
        machine.succeed("curl -sf http://127.0.0.1:9300/signin | grep -q '<title>Sign in'")

    with subtest("device flow starts, as farm login will"):
        machine.succeed(
            "openssl ecparam -name prime256v1 -genkey -noout -out /tmp/dev.key"
            " && openssl req -new -key /tmp/dev.key -subj / -sha256 -outform DER -out /tmp/dev.csr"
        )
        out = json.loads(machine.succeed(
            "curl -sf http://127.0.0.1:9300/device/code -d client_id=farm"
            " -d csr=$(basenc --base64url -w0 /tmp/dev.csr | tr -d =)"
        ))
        assert out["verification_uri"] == "https://id.auth.jack.farm/device", out

    with subtest("sudo sso enroll works for root only"):
        link = machine.succeed("sso enroll jack")
        assert "https://id.auth.jack.farm/enroll/jack." in link, link
        machine.fail("runuser -u member -- sso enroll jack")

    with subtest("the unit is sandboxed and not root"):
        user = machine.succeed("systemctl show -p User --value sso").strip()
        assert user != "root", user
        # The threshold is in tenths: 15 fails above an exposure of 1.5.
        machine.succeed("systemd-analyze security sso.service --threshold=15 --no-pager >&2")

    with subtest("the audit chain of the run verifies"):
        machine.succeed("systemctl stop sso")
        report = machine.succeed("journalctl -u sso -o cat | sso audit verify -")
        print(report)
        assert " in 1 chains" in report and "no audit_stop" not in report, report
  '';
}
