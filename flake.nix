{
  description = "Ultimate Bug Scanner - flake packaging, dev shell, and NixOS module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

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
            nativeBuildInputs = [ pkgs.makeWrapper ];
            buildInputs = [ pkgs.bash ];
            installPhase = ''
              runHook preInstall
              install -Dm755 ubs $out/libexec/ubs/ubs
              # The verified loader executes these exact bytes. Keep this
              # non-executable so patchShebangs cannot change its checksum.
              install -Dm644 ubs-daemon $out/libexec/ubs/ubs-daemon
              daemon_declaration="$(grep '^UBS_DAEMON_SHA256=' $out/libexec/ubs/ubs)"
              daemon_sha="$(sha256sum $out/libexec/ubs/ubs-daemon | cut -d' ' -f1)"
              test "$daemon_declaration" = "UBS_DAEMON_SHA256=\"$daemon_sha\""
              makeWrapper $out/libexec/ubs/ubs $out/bin/ubs \
                --run "$daemon_declaration" \
                --prefix PATH : ${pkgs.lib.makeBinPath [
                  pkgs.bash pkgs.coreutils pkgs.curl pkgs.git pkgs.jq
                  pkgs.ripgrep pkgs.python314 pkgs.findutils pkgs.gnused
                  pkgs.gawk pkgs.gnugrep pkgs.unzip
                ]} \
                --set-default UBS_NO_AUTO_UPDATE 1
              install -Dm644 README.md $out/share/doc/ultimate_bug_scanner/README.md
              runHook postInstall
            '';
            doInstallCheck = true;
            installCheckPhase = ''
              runHook preInstallCheck
              cmp ubs-daemon $out/libexec/ubs/ubs-daemon
              test ! -L $out/libexec/ubs/ubs-daemon
              grep -Fx "$(grep '^UBS_DAEMON_SHA256=' $out/libexec/ubs/ubs)" $out/bin/ubs
              $out/bin/ubs serve --help
              $out/bin/ubs --client --help
              # A runner-only payload must fail to load the canonical service.
              mkdir missing-daemon
              cp $out/libexec/ubs/ubs missing-daemon/ubs
              if UBS_PYTHON=${pkgs.python314}/bin/python3 missing-daemon/ubs serve --help; then
                echo "Runner-only package unexpectedly loaded the service" >&2
                exit 1
              else
                test "$?" -eq 2
              fi
              runHook postInstallCheck
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
              [ bashInteractive shellcheck git cmake python314 jq ripgrep ]
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
