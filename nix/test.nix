# NixOS VM test for nixosModules.sso: the hardened unit starts, makes its CA
# at first boot (or takes a given one through LoadCredential), answers the
# device flow, the enroll wrapper works for root only, and the audit chain of
# the run verifies. No browser: passkeys are covered by the Go tests.
# Run with: nix build .#checks.x86_64-linux.sso -L
{ pkgs, module, package }:

let
  # A CA made ahead, as with a secrets tool. Its key is in the Nix store,
  # which is fine for a test.
  ca = pkgs.runCommand "sso-test-ca" { } ''
    ${package}/bin/sso ca init --name "test CA" --years 1 --out $out
  '';

  common = {
    imports = [ module ];
    services.sso = {
      enable = true;
      rpId = "auth.jack.farm";
      origin = "https://id.auth.jack.farm";
      users.jack = {
        roles = [ "write" ];
        services = [ "statusd" ];
      };
    };
    users.users.member.isNormalUser = true;
    environment.systemPackages = [ pkgs.openssl ];
  };
in
pkgs.testers.runNixOSTest {
  name = "sso";

  # The CA is made at first boot.
  nodes.machine = {
    imports = [ common ];
    services.sso.generatedCA.name = "farm1 SSO CA";
  };

  # The CA is given, from where a secrets tool would put the key.
  nodes.given = {
    imports = [ common ];
    services.sso = {
      caCertificate = "${ca}/ca.pem";
      caKeyFile = "/run/keys/sso-ca.key";
    };
    systemd.tmpfiles.rules = [
      "d /run/keys 0750 root root -"
      "C /run/keys/sso-ca.key 0400 root root - ${ca}/ca.key"
    ];
    systemd.services.sso = {
      after = [ "systemd-tmpfiles-setup.service" ];
      requires = [ "systemd-tmpfiles-setup.service" ];
    };
  };

  testScript = ''
    import json

    start_all()
    for m in (machine, given):
        m.wait_for_unit("sso.service")
        m.wait_for_open_port(9300)

    with subtest("the CA is made once, root-only, and never replaced"):
        machine.succeed("test $(stat -c %a:%U /var/lib/sso-ca) = 700:root")
        machine.succeed("test $(stat -c %a:%U /var/lib/sso-ca/ca.key) = 600:root")
        subject = machine.succeed("openssl x509 -in /var/lib/sso-ca/ca.pem -noout -subject")
        assert "farm1 SSO CA" in subject, subject
        before = machine.succeed("sha256sum /var/lib/sso-ca/ca.key /var/lib/sso-ca/ca.pem")
        machine.succeed("systemctl restart sso-ca.service sso.service")
        machine.wait_for_open_port(9300)
        assert machine.succeed("sha256sum /var/lib/sso-ca/ca.key /var/lib/sso-ca/ca.pem") == before

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

    with subtest("sudo sso enroll works for root only, with either CA"):
        for m in (machine, given):
            link = m.succeed("sso enroll jack")
            assert "https://id.auth.jack.farm/enroll/jack." in link, link
            m.fail("runuser -u member -- sso enroll jack")

    with subtest("the unit is sandboxed and not root"):
        user = machine.succeed("systemctl show -p User --value sso").strip()
        assert user != "root", user
        # The threshold is in tenths: 15 fails above an exposure of 1.5.
        machine.succeed("systemd-analyze security sso.service --threshold=15 --no-pager >&2")

    with subtest("the audit chain of the run verifies"):
        machine.succeed("systemctl stop sso")
        report = machine.succeed("journalctl -u sso -o cat | sso audit verify -")
        print(report)
        # Two runs: before and after the restart above.
        assert " in 2 chains" in report and "no audit_stop" not in report and "line " not in report, report
  '';
}
