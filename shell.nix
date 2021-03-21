with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "wireguard";
  buildInputs = [ stack
                  gnumake
                ];
}
