{
  description = "Single sign-on for the farm-1 homelab";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
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
