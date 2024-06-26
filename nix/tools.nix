{ pkgs ? import <nixpkgs> { } }:

let

  inherit (pkgs.lib) fileContents last splitString flatten remove;
  inherit (builtins) map match;
in {
  findKeyValue = regex: sourceFile:
    let
      linesFrom = sourceFile: splitString "\n" (fileContents sourceFile);
      matching = regex: lines: map (line: match regex line) lines;
      extractMatch = matches: last (flatten (remove null matches));
    in
      extractMatch (matching regex (linesFrom sourceFile));
}
