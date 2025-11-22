{
  description = "Ultimate Bug Scanner - flake packaging, dev shell, and NixOS module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSystem = f:
        builtins.listToAttrs (map (system: { name = system; value = f system; }) systems);
    in {
      packages = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          version = builtins.replaceStrings ["\n" "\r"] ["" ""] (builtins.readFile ./VERSION);
        in {
          default = pkgs.stdenv.mkDerivation {
            pname = "ultimate-bug-scanner";
            version = version;
            src = ./.;
            dontConfigure = true;
            dontBuild = true;
            installPhase = ''
              install -Dm755 ubs $out/bin/ubs
              install -Dm644 README.md $out/share/doc/ultimate_bug_scanner/README.md
            '';
            meta = with pkgs.lib; {
              description = "Ultimate Bug Scanner meta-runner";
              homepage = "https://github.com/Dicklesworthstone/ultimate_bug_scanner";
              license = licenses.mit;
              maintainers = [];
              platforms = systems;
            };
          };
        });

      apps = forEachSystem (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/ubs";
          args = [ "--help" ];
        };
      });

      devShells = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = pkgs.lib;
          uvPkg = if pkgs ? uv then pkgs.uv else null;
        in {
          default = pkgs.mkShell {
            packages = with pkgs;
              [ bashInteractive shellcheck git cmake python3 jq ripgrep ]
              ++ lib.optional (uvPkg != null) uvPkg;
          };
        });

      nixosModules.ubs = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.ubs;
        in {
          options.programs.ubs = {
            enable = lib.mkEnableOption "Ultimate Bug Scanner";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              description = "Package providing the ubs meta-runner.";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
            environment.variables.UBS_NO_AUTO_UPDATE = lib.mkDefault "1";
          };
        };

      formatter = forEachSystem (system:
        let pkgs = import nixpkgs { inherit system; }; in pkgs.nixpkgs-fmt);
    };
}
