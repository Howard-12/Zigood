{
  description = "zigood";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  inputs.zig_overlay.url = "github:mitchellh/zig-overlay";
  inputs.zig_overlay.inputs.flake-utils.follows = "flake-utils";

  inputs.zls.url = "github:zigtools/zls";

  outputs = input@{ self, nixpkgs, flake-utils, zig_overlay, zls, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { system = system; };

        # compiler version
        zig_version = "0.14.1";
        zig = zig_overlay.packages.${system}.${zig_version};
      in {
        devShell = pkgs.mkShell {
          buildInputs = [
            zls.packages.${system}.default
            zig
          ];

          shellHook = ''
            echo 'zig' "$(zig version)"
          '';
        };
      }
    );
}
