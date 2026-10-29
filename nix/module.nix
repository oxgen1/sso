{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.sso;
  sso = lib.getExe' cfg.package "sso";

  # With neither caCertificate nor caKeyFile set, the CA is made on the host
  # at first boot and its key never leaves it.
  generated = cfg.caCertificate == null && cfg.caKeyFile == null;
  caDir = "/var/lib/sso-ca";
  keyFile = if generated then "${caDir}/ca.key" else cfg.caKeyFile;

  # Option for option the JSON that internal/config reads, with the CA
  # certificate at caPath.
  configJSON = name: caPath: pkgs.writeText name (builtins.toJSON {
    inherit (cfg) rpId origin listenAddress;
    caCertificate = caPath;
    users = lib.mapAttrs (_: u: { inherit (u) roles services sources passkeys; }) cfg.users;
    clients = lib.mapAttrs (_: c: { inherit (c) redirectUri; }) cfg.clients;
    audit = { inherit (cfg.audit) retentionDays; };
  });

  # A generated CA doesn't exist at build time, so the check uses a
  # throwaway one; everything else is checked as deployed.
  checkCA = pkgs.runCommand "sso-check-ca" { } "${sso} ca init --name check --years 1 --out $out";
  checked = name: caPath: pkgs.runCommand name { } ''
    ${sso} config check ${configJSON "sso-check.json" (if generated then "${checkCA}/ca.pem" else caPath)}
    cp ${configJSON "${name}.json" caPath} $out
  '';

  # A mistake in the configuration fails the build, not the first sign-in.
  # The service reads a generated certificate through LoadCredential, as its
  # directory is root's.
  serveConfig = checked "sso-config" (if generated then "/run/credentials/sso.service/ca.pem" else "${cfg.caCertificate}");
  enrollConfig = if generated then checked "sso-enroll-config" "${caDir}/ca.pem" else serveConfig;

  # sso on PATH, with the configuration and the CA key filled in for enroll,
  # so `sudo sso enroll jack` works on the host.
  wrapper = pkgs.writeShellScriptBin "sso" ''
    if [ "''${1-}" = enroll ]; then
      shift
      exec ${sso} enroll --ca-key ${lib.escapeShellArg keyFile} ${enrollConfig} "$@"
    fi
    exec ${sso} "$@"
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
      type = types.nullOr types.path;
      default = null;
      example = lib.literalExpression "./sso/ca.pem";
      description = ''
        CA certificate from `sso ca init`. Public. Leave this and caKeyFile
        unset to have the CA made in ${caDir} at first boot (see generatedCA).
      '';
    };

    caKeyFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/agenix/sso-ca-key";
      description = ''
        CA private key from `sso ca init`, as a root-only file from a secrets
        tool. A string, so it never gets copied into the Nix store. The service
        reads it through LoadCredential.
      '';
    };

    generatedCA = {
      name = mkOption {
        type = types.str;
        default = "SSO CA";
        description = "Common name of a CA made at first boot.";
      };
      years = mkOption {
        type = types.ints.positive;
        default = 5;
        description = "Lifetime of a CA made at first boot.";
      };
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
        assertion = (cfg.caCertificate == null) == (cfg.caKeyFile == null);
        message = "services.sso: set both caCertificate and caKeyFile, or neither to make the CA at first boot.";
      }
      {
        assertion = generated || (lib.hasPrefix "/" keyFile && !lib.hasPrefix builtins.storeDir keyFile);
        message = "services.sso.caKeyFile must be an absolute path outside the Nix store.";
      }
    ];

    environment.systemPackages = [ wrapper ];

    # Makes the CA once; an existing one is never touched. Copy ca.pem from
    # here into the configuration of every service that trusts it.
    systemd.services.sso-ca = mkIf generated {
      description = "Make the SSO CA";
      unitConfig.ConditionPathExists = "!${keyFile}";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.escapeShellArgs [ sso "ca" "init" "--name" cfg.generatedCA.name "--years" (toString cfg.generatedCA.years) "--out" caDir ];
        PrivateNetwork = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib" ];
      };
    };

    systemd.services.sso = {
      description = "SSO IdP and CA";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ] ++ lib.optional generated "sso-ca.service";
      requires = lib.optional generated "sso-ca.service";
      serviceConfig = {
        ExecStart = "${sso} serve ${serveConfig}";
        LoadCredential = [ "ca.key:${keyFile}" ] ++ lib.optional generated "ca.pem:${caDir}/ca.pem";
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
