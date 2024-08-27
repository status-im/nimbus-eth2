{ pkgs ? import <nixpkgs> { } }:

let

  inherit (pkgs.lib) fileContents last splitString flatten remove;
  inherit (builtins) map match;
in {
  findKeyValue = regex: sourceFile:
    let
      linesFrom = file: splitString "\n" (fileContents file);
      matching = regex: lines: map (line: match regex line) lines;
      extractMatch = matches: last (flatten (remove null matches));
    in
      extractMatch (matching regex (linesFrom sourceFile));
}
