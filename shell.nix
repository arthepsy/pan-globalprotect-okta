with (import <nixpkgs> {});

mkShell {
  buildInputs = [
    openconnect
    (python.withPackages (pypkgs: with pypkgs; [
      lxml
      requests
    ]))
  ];
}
