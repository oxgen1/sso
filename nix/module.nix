{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.sso;

  # Option for option the JSON that internal/config reads.
  configJSON = pkgs.writeText "sso.json" (builtins.toJSON {
    inherit (cfg) rpId origin listenAddress;
    caCertificate = "${cfg.caCertificate}";
    users = lib.mapAttrs (_: u: { inherit (u) roles services sources passkeys; }) cfg.users;
    clients = lib.mapAttrs (_: c: { inherit (c) redirectUri; }) cfg.clients;
    audit = { inherit (cfg.audit) retentionDays; };
  });

  # A mistake in the configuration fails the build, not the first sign-in.
  configFile = pkgs.runCommand "sso-config" { } ''
    ${lib.getExe' cfg.package "sso"} config check ${configJSON}
    cp ${configJSON} $out
  '';

  # sso on PATH, with the configuration and the CA key filled in for enroll,
  # so `sudo sso enroll jack` works on the host.
  wrapper = pkgs.writeShellScriptBin "sso" ''
    if [ "''${1-}" = enroll ]; then
      shift
      exec ${lib.getExe' cfg.package "sso"} enroll --ca-key ${lib.escapeShellArg cfg.caKeyFile} ${configFile} "$@"
    fi
    exec ${lib.getExe' cfg.package "sso"} "$@"
  '';

  passkey = types.submodule {
    options = {
      name = mkOption { type = types.str; description = "Name given at enrollment."; };
      id = mkOption { type = types.str; description = "Credential ID, unpadded base64url."; };
      publicKey = mkOption { type = types.str; description = "SubjectPublicKeyInfo, standard base64."; };
    };
  };

  user = types.submodule {
    options = {
      roles = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "write" ];
        description = "Roles in the user's certificates: write, admin.";
      };
      services = mkOption {
        type = types.listOf types.str;
        example = [ "statusd" ];
        description = "Services the user's certificates are valid for.";
      };
      sources = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "10.100.0.0/24" ];
        description = "CIDR prefixes the certificates may be used from. Empty means any address.";
      };
      passkeys = mkOption {
        type = types.listOf passkey;
        default = [ ];
        description = "Passkeys from `sso enroll`, pasted from the snippet it prints. Not secret.";
      };
    };
  };
in
{
  options.services.sso = {
    enable = mkEnableOption "the SSO IdP and CA";

    package = mkOption {
      type = types.package;
      description = "sso package. The flake's nixosModules.sso sets this.";
    };

    rpId = mkOption {
      type = types.str;
      example = "auth.jack.farm";
      description = "WebAuthn RP ID. Every passkey is bound to it for good: changing it means enrolling everyone again.";
    };

    origin = mkOption {
      type = types.str;
      example = "https://id.auth.jack.farm";
      description = "The IdP's exact origin, under rpId.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1:9300";
      description = ''
        Loopback address and port for the reverse proxy in front, which
        terminates TLS. The IdP takes the client address from X-Forwarded-For
        only on loopback, so the proxy has to be on the same host.
      '';
    };

    caCertificate = mkOption {
      type = types.path;
      example = lib.literalExpression "./sso/ca.pem";
      description = "CA certificate from `sso ca init`. Public.";
    };

    caKeyFile = mkOption {
      type = types.str;
      example = "/run/agenix/sso-ca-key";
      description = ''
        CA private key from `sso ca init`, as a root-only file from a secrets
        tool. A string, so it never gets copied into the Nix store. The service
        reads it through LoadCredential.
      '';
    };

    users = mkOption {
      type = types.attrsOf user;
      default = { };
      description = "Users, by name. The IdP has no other user database.";
    };

    clients = mkOption {
      type = types.attrsOf (types.submodule {
        options.redirectUri = mkOption {
          type = types.str;
          example = "https://grafana.jack.farm/.sso/callback";
          description = "The only URI the IdP sends this app's authorization codes to.";
        };
      });
      default = { };
      description = "Web apps that sign in through the IdP, by name. The name is also their service name.";
    };

    audit.retentionDays = mkOption {
      type = types.ints.positive;
      default = 90;
      description = "How long audit records keep client addresses.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.hasPrefix "127." cfg.listenAddress || lib.hasPrefix "[::1]:" cfg.listenAddress;
        message = "services.sso.listenAddress must be a loopback address, with the reverse proxy on the same host.";
      }
      {
        assertion = lib.hasPrefix "/" cfg.caKeyFile && !lib.hasPrefix builtins.storeDir cfg.caKeyFile;
        message = "services.sso.caKeyFile must be an absolute path outside the Nix store.";
      }
    ];

    environment.systemPackages = [ wrapper ];

    systemd.services.sso = {
      description = "SSO IdP and CA";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${lib.getExe' cfg.package "sso"} serve ${configFile}";
        LoadCredential = [ "ca.key:${cfg.caKeyFile}" ];
        Restart = "on-failure";
        DynamicUser = true;

        # Only the reverse proxy on this host connects, and the IdP connects
        # to nothing. journald is a Unix socket and isn't affected.
        IPAddressDeny = "any";
        IPAddressAllow = [ "localhost" ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];

        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateUsers = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RemoveIPC = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
        # The Go runtime calls setrlimit at startup (in @resources). Return
        # EPERM, which Go ignores, instead of killing the process.
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";
      };
    };
  };
}
