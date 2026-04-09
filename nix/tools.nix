{ pkgs ? import <nixpkgs> { } }:

let

  inherit (pkgs.lib) fileContents last splitString flatten remove;
  inherit (builtins) map match;
in {
  findKeyValue = regex: sourceFile:
    let
      linesFrom = file: splitString "\n" (fileContents file);
      matching = regex: lines: map (line: match regex line) lines;
      extractMatch = matches:
        let xs = flatten (remove null matches);
        in if xs == [] then
          throw "findKeyValue: no match for regex '${regex}' in ${toString sourceFile}"
        else
          last xs;
    in
      extractMatch (matching regex (linesFrom sourceFile));
}
