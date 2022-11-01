{ pkgs ? import <nixpkgs> {} }:

with pkgs;

mkShell {
  buildInputs = [ cargo rustc rustfmt openssl pkg-config ];
}
