# Setup

How to run the SSO: the IdP, users and passkeys, and the first sign-in. Connecting services, web apps and clients is in [integration.md](integration.md); the reasoning behind all of it is in [design.md](design.md).

> **Status:** written ahead of the code, as the finished system should work. Built so far: `lib/httpsig`, `lib/cert`, `lib/assertion`, configuration loading, `sso ca init` and `sso config check`. Option names, commands and paths may still change; where they do, the code wins and this file gets fixed.

## Pieces

| Piece | Runs on | Talks to |
|---|---|---|
| `sso` (IdP and CA) | its own host or VM | browsers (passkey sign-in, approvals), `mvm` (device flow), `sso-proxy` (code exchange) |
| `sso-proxy` | the host running Caddy for web apps | Caddy (`forward_auth`), the IdP |
| services (statusd, …) | anywhere | nobody: they verify requests with the CA certificate alone |
| `mvm` | your laptop | the IdP once a day, then services directly |

The IdP is only needed to sign in and to approve destructive actions. If it's down, certificates already issued keep working until they expire.

## Before you start

1. **A domain you control.** The examples use `jack.farm`. The passkey RP ID is `auth.jack.farm`, and the IdP is served at `https://id.auth.jack.farm`. Nothing else is hosted under `*.auth.jack.farm`: any page there could ask for a passkey assertion.
2. **A browser-trusted certificate** for `*.auth.jack.farm`, through DNS-01 so the host name stays out of Certificate Transparency logs. WebAuthn refuses to run on a page without one.
3. **DNS** for `id.auth.jack.farm`, resolving on the LAN and over WireGuard. It doesn't need to be public.
4. **NTP** on every host and laptop. Signatures are accepted for ±5 minutes around the verifier's clock.
5. **Two authenticators per user** (two YubiKeys, or a YubiKey and a phone passkey). There's no password, TOTP or email fallback, so the second one is the recovery plan.

## Create the CA

Once, on a trusted machine:

```sh
sso ca init --name "farm1 SSO CA" --years 5 --out ./ca
# ./ca/ca.pem   public, goes into the Nix configuration of every service
# ./ca/ca.key   private, goes into your secrets tool, never into the Nix store
```

Put `ca.key` in agenix or sops-nix so it appears on the IdP host as a root-only file. The module passes it to the service with systemd `LoadCredential`, so the `sso` process reads it without having file-system access to it. Commit `ca.pem` next to your host configuration; it isn't secret.

## Example 1: one host, one user

The smallest useful setup: the IdP runs on `farm-1` next to statusd, one user, writes over WireGuard.

```
 laptop 10.100.0.10 ──wg0──▶ farm-1 10.100.0.1
                               ├─ Caddy :443   id.auth.jack.farm ──▶ sso 127.0.0.1:9300
                               ├─ statusd :9020 on the LAN (reads)
                               └─ statusd :9021 on wg0 (reads and writes)
```

```nix
# farm-1, in the host's flake modules
{ config, ... }:
{
  imports = [ sso.nixosModules.sso ];

  services.sso = {
    enable = true;
    rpId = "auth.jack.farm";
    origin = "https://id.auth.jack.farm";
    listenAddress = "127.0.0.1:9300";        # Caddy terminates TLS in front
    caCertificate = ./sso/ca.pem;
    caKeyFile = config.age.secrets.sso-ca-key.path;

    users.jack = {
      roles = [ "write" ];
      services = [ "statusd" ];
      passkeys = [
        # Pasted from `sso enroll jack`, see below.
        { name = "yubikey-5c"; id = "kO3v…"; publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"; }
        { name = "yubikey-nano"; id = "p9Xa…"; publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"; }
      ];
    };
  };

  services.caddy.virtualHosts."id.auth.jack.farm".extraConfig = ''
    tls /var/lib/acme/auth.jack.farm/cert.pem /var/lib/acme/auth.jack.farm/key.pem
    reverse_proxy 127.0.0.1:9300
  '';
}
```

statusd's side of this example is in [integration.md](integration.md#statusd).

With no `admin` role, jack can read and do ordinary writes but no destructive actions, which is a reasonable start.

## Example 2: dedicated IdP, two users, web apps

The IdP gets its own microvm so the CA key isn't on the host that runs everything else. Two users: jack does everything; `guest` can only look at Grafana, and only from the LAN.

```
 laptop 10.100.0.10 ──wg0──┐
                           ▼
 farm-1 10.100.0.1 ── wg0 ── sso VM 10.100.0.2 (Caddy :443 + sso :9300)
   ├─ statusd :9020 LAN, :9021 wg0
   ├─ Caddy :443 grafana.jack.farm ── forward_auth ──▶ sso-proxy 127.0.0.1:9310
   │                               └─ reverse_proxy ─▶ grafana 10.0.0.71:3000
   └─ microvms …
```

```nix
# The sso microvm
{ config, ... }:
{
  imports = [ sso.nixosModules.sso ];

  services.sso = {
    enable = true;
    rpId = "auth.jack.farm";
    origin = "https://id.auth.jack.farm";
    listenAddress = "127.0.0.1:9300";
    caCertificate = ./sso/ca.pem;
    caKeyFile = config.age.secrets.sso-ca-key.path;

    users.jack = {
      roles = [ "admin" "write" ];
      services = [ "statusd" "grafana" ];
      sources = [ "10.100.0.0/24" "10.0.0.0/24" ];   # WireGuard and the LAN
      passkeys = [
        { name = "yubikey-5c"; id = "kO3v…"; publicKey = "MFkw…"; }
        { name = "pixel"; id = "Zt8q…"; publicKey = "MFkw…"; }
      ];
    };

    users.guest = {
      roles = [ ];
      services = [ "grafana" ];
      sources = [ "10.0.0.0/24" ];                   # LAN only
      passkeys = [
        { name = "iphone"; id = "c2Vj…"; publicKey = "MFkw…"; }
        { name = "yubikey"; id = "dGhp…"; publicKey = "MFkw…"; }
      ];
    };

    # Web apps that sign in through sso-proxy. Each gets a redirect URI the
    # IdP will send authorization codes to, and nothing else.
    clients.grafana.redirectUri = "https://grafana.jack.farm/.sso/callback";

    audit.retentionDays = 90;   # how long client IPs are kept
  };

  networking.firewall.interfaces.wg0.allowedTCPPorts = [ 443 ];
  networking.firewall.interfaces.eth0.allowedTCPPorts = [ 443 ];
}
```

The web-app side (Caddy and `sso-proxy` on `farm-1`) is in [integration.md](integration.md#web-apps-behind-caddy).

### What the options mean

| Option | Meaning |
|---|---|
| `rpId` | The WebAuthn RP ID. Every passkey is bound to it for good: changing it means re-enrolling everyone. |
| `origin` | The exact origin of the IdP. Services check passkey assertions against it. |
| `caCertificate`, `caKeyFile` | The CA pair from `sso ca init`. The key is read through `LoadCredential`. |
| `users.<name>.roles` | Sorted into the certificate. `write` allows writes; `admin` plus a passkey touch allows destructive actions. Roles apply to every service in `services`. |
| `users.<name>.services` | The services the certificate is valid for. A service rejects any certificate that doesn't name it (`scope`). |
| `users.<name>.sources` | Optional CIDR prefixes. If set, services reject the certificate from any other address (`scope`). |
| `users.<name>.passkeys` | Public keys from `sso enroll`. Not secret. |
| `clients.<name>.redirectUri` | A web app behind `sso-proxy`. The name is also the service name its sessions are scoped to. |
| `audit.retentionDays` | How long audit records keep the client IP. |

Certificate lifetime (8 h), the signature profile and the algorithm are fixed in the library, not options.

## Enroll passkeys

On the IdP host:

```sh
sudo sso enroll jack
# Enrollment link for jack, valid 10 minutes, single use:
#   https://id.auth.jack.farm/enroll/7Hq2…
```

Open the link on the device whose passkey you're registering (or with the YubiKey plugged in), touch the key, and give it a name. The page prints a snippet:

```nix
{ name = "yubikey-5c"; id = "kO3v…"; publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"; }
```

Paste it into `users.jack.passkeys` and deploy. Until you do, the passkey can't sign in: the IdP has no user database, only the Nix configuration. Repeat for the second authenticator.

To remove a lost authenticator, delete its line and deploy. Certificates already issued with it keep their passkey list until they expire (at most 8 h); for an immediate cut-off, rotate the CA (below).

## First sign-in

From the laptop, over WireGuard:

```sh
mvm login
# Open https://id.auth.jack.farm/device and enter WDJB-MJHT
# Waiting for approval…
# Signed in as jack until 18:04 (statusd; roles: write)
```

Approve on the page with a passkey. `mvm` made a fresh key pair for this login; the private key never leaves `~/.local/state/mvm/` (mode 0600), and the certificate next to it is valid for 8 hours. Then:

```sh
mvm req GET /v1/status
mvm req POST /v1/microvms/web/restart
```

## Check it's working

```sh
journalctl -u sso -o cat | jq 'select(.log == "audit")'
```

Each sign-in shows up as a `login` record and an `issue` record with the certificate serial. Every later request a service accepts or rejects carries the same serial, so `cert_serial` ties a service's audit log back to the sign-in.

## Operations

### Reading a rejection

Services answer a rejected request with only the HTTP status. The reason is in their audit log:

| Reason | Usually means | Do |
|---|---|---|
| `expired` / `not_yet_valid` | Clock skew over 5 minutes, or a request held back and resent | Check NTP on both ends |
| `before_start` | A write signed before the service restarted | Retry; `mvm` re-signs automatically |
| `authority` | The client used a host name or port the service doesn't list | Add it to the service's authorities, or fix the client's URL |
| `cert_expired` | The 8 h are up | `mvm login` |
| `scope` | Wrong service, or a source address outside `sources` | Check `users.<name>.services` and `sources`; are you on WireGuard? |
| `cert` | Not from this CA, or not the certificate profile | Usually a service with a stale `ca.pem` after rotation |
| `sig_mismatch` | Wrong key, or the two sides built different signature bases | Compare `base_sha256` in the service log with `mvm`'s output: different hashes mean canonicalization, equal hashes mean the key |
| `digest` | The body changed in transit | A proxy rewriting bodies |
| `replay` | The same signed request seen twice | Expected if something retries blindly; otherwise investigate |
| `nonce_full` | The nonce cache is full of live entries | Possible flood of valid writes; check the audit log for whose |
| `role` | Signed fine, but the certificate lacks `write` (or `admin` for destructive) | Add the role to `users.<name>.roles` if intended |
| `assertion_missing` | A destructive request without approval | Use `mvm req`, which asks for approval |
| `assertion_challenge` | The passkey approved a different request | The approval page and the service built different bases, or an approval was reused |
| `assertion_origin` | Approved somewhere other than `https://id.auth.jack.farm` | Investigate: some other page asked for a passkey |
| `assertion_flags` | No user verification (PIN or biometric) | Set a PIN on the authenticator |
| `assertion_credential` | The passkey isn't in the certificate | Enrolled after this certificate was issued: `mvm login` |
| `assertion_rp`, `assertion_type`, `assertion_sig_mismatch`, `assertion_malformed` | Not an approval from our page | Investigate |

For a `sig_mismatch` you can't explain, turn on the service's debug flag to log full signature bases, then replay one offline with `mvm verify base.txt`.

### Rotating the CA

The emergency stop: after it, every certificate in circulation is useless.

1. `sso ca init --out ./ca-new`, and put the new key in your secrets tool.
2. Set `caCertificate` and `caKeyFile` on the IdP, and the new `ca.pem` on **every** service. Deploy them together.
3. Everyone runs `mvm login` again; web sessions sign in again silently.

Passkeys are unaffected: they belong to the RP ID, not to the CA.

### Backups

Nothing on the IdP needs backing up except the CA key, and even that can be replaced by rotating. Users, roles and passkeys are in the Nix configuration; sessions are in memory. The audit log is shipped off the host by journald.
