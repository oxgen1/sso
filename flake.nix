{
  description = "Single sign-on for the farm-1 homelab";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system} = {
        sso = pkgs.buildGoModule {
          pname = "sso";
          version = "0.1.0";
          src = self;
          # Update after changing go.mod: set to lib.fakeHash, build, copy the "got:" hash.
          vendorHash = "sha256-aAWoy8ZH4fLcYz/l9ZuY6hO/YrErt3/YVfcFaPrXprE=";
          subPackages = [ "cmd/sso" ];
          env.CGO_ENABLED = 0;
          ldflags = [ "-s" "-w" ];
          # The default checkPhase only tests subPackages. Run every test, lib's
          # module too, so a failure breaks the build.
          checkPhase = ''
            runHook preCheck
            go test ./...
            (cd lib && go test ./...)
            runHook postCheck
          '';
          meta.mainProgram = "sso";
        };
        default = self.packages.${system}.sso;
      };

      nixosModules.sso = { lib, pkgs, ... }: {
        imports = [ ./nix/module.nix ];
        services.sso.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.sso;
      };

      checks.${system} = {
        # Go unit tests (run in the package's checkPhase).
        unit = self.packages.${system}.sso;
        sso = import ./nix/test.nix {
          inherit pkgs;
          module = self.nixosModules.sso;
          package = self.packages.${system}.sso;
        };
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          go
          gopls
          delve
          gotools
          golangci-lint
          govulncheck
        ];
        CGO_ENABLED = "0";
      };
    };
}
