# ctrl-exec packages for Nix: ctrl-exec-agent and ctrl-exec-dispatcher, built
# from one source tree. Mirrors install.sh / debian/rules: the Perl library is
# installed under $out/lib/ctrl-exec, the bin scripts get `use lib` and
# $VERSION patched, the executor is compiled from src/ with the Makefile.
{ lib
, stdenv
, perl
, perlPackages
, openssl
, libcap
, makeWrapper
}:

let
  version = lib.removeSuffix "\n" (builtins.readFile ../VERSION);

  # Only what the build needs: keeps the store path (and so a rebuild) from
  # changing when docs, tests, the website or scratch directories change.
  src = lib.cleanSourceWith {
    src = ../.;
    name = "ctrl-exec-source";
    filter = path: type:
      let rel = lib.removePrefix (toString ../. + "/") (toString path);
      in builtins.any (p: rel == p || lib.hasPrefix (p + "/") rel) [
        "bin" "lib" "src" "man" "etc" "Makefile" "VERSION"
      ];
  };

  # Perl modules that are not part of core perl (debian/control, install.sh).
  agentPerl = with perlPackages; [ JSON IOSocketSSL NetSSLeay ];
  dispatcherPerl = agentPerl ++ (with perlPackages; [ LWP LWPProtocolHttps ]);

  mkCtrlExec = { pname, description, perlDeps, bins, shortName, withExecutor, manPages }:
    stdenv.mkDerivation {
      inherit pname version src;

      nativeBuildInputs = [ makeWrapper ];
      buildInputs = [ perl ] ++ lib.optional withExecutor libcap;

      dontConfigure = true;
      # Only the agent builds the executor (the Makefile's one target).
      dontBuild = !withExecutor;
      buildPhase = ''
        runHook preBuild
        make CC=$CC CFLAGS="-O2 -Wall -Wextra"
        runHook postBuild
      '';

      installPhase = ''
        runHook preInstall

        # Shared library, as install.sh's install_lib: modules under
        # $out/lib/ctrl-exec, plus the VERSION file Exec::API reports.
        mkdir -p $out/lib/ctrl-exec $out/bin
        cp -r lib/. $out/lib/ctrl-exec/
        printf '%s\n' '${version}' > $out/lib/ctrl-exec/VERSION

        # Exec::API reads these two fixed paths; point them at the store.
        substituteInPlace $out/lib/ctrl-exec/Exec/API.pm \
          --replace-fail '/usr/local/lib/ctrl-exec' "$out/lib/ctrl-exec"

        for b in ${lib.concatStringsSep " " bins}; do
          install -Dm755 bin/$b $out/bin/$b
          substituteInPlace $out/bin/$b \
            --replace-fail 'use lib "$Bin/../lib";' 'use lib "'$out'/lib/ctrl-exec";' \
            --replace-fail "our \$VERSION = 'UNINSTALLED';" "our \$VERSION = '${version}';"
          patchShebangs $out/bin/$b
          # Non-core Perl modules and openssl (called by name for pairing,
          # renewal and CA work) for the program itself. Scripts the agent
          # runs get their own fixed environment, not this one.
          wrapProgram $out/bin/$b \
            --prefix PERL5LIB : ${perlPackages.makePerlPath (perlPackages.requiredPerlModules perlDeps)} \
            --prefix PATH : ${lib.makeBinPath [ openssl ]}
        done
        ln -s ${builtins.head bins} $out/bin/${shortName}

        for m in ${lib.concatStringsSep " " manPages}; do
          install -Dm644 man/$m -t $out/share/man/man8
        done
        for c in ${lib.concatStringsSep " " bins}; do
          install -Dm644 etc/bash-completion/$c -t $out/share/bash-completion/completions
        done
        ln -s ${builtins.head bins} $out/share/bash-completion/completions/${shortName}

        install -Dm644 etc/agent.conf.example etc/scripts.conf.example \
          -t $out/share/ctrl-exec/examples
        ${lib.optionalString withExecutor ''
          install -Dm755 src/ctrl-exec-executor $out/bin/ctrl-exec-executor
        ''}

        runHook postInstall
      '';

      meta = {
        inherit description;
        homepage = "https://github.com/OpenDigitalCC/ctrl-exec";
        license = lib.licenses.agpl3Only;
        platforms = lib.platforms.linux;
        mainProgram = builtins.head bins;
      };
    };
in
{
  ctrl-exec-agent = mkCtrlExec {
    pname = "ctrl-exec-agent";
    description = "ctrl-exec agent: runs allowlisted scripts for a dispatcher over mTLS";
    perlDeps = agentPerl;
    bins = [ "ctrl-exec-agent" ];
    shortName = "cea";
    withExecutor = true;
    manPages = [ "ctrl-exec-agent.8" "cea.8" ];
  };

  ctrl-exec-dispatcher = mkCtrlExec {
    pname = "ctrl-exec-dispatcher";
    description = "ctrl-exec dispatcher (ced) and API server";
    perlDeps = dispatcherPerl;
    bins = [ "ctrl-exec-dispatcher" "ctrl-exec-api" ];
    shortName = "ced";
    withExecutor = false;
    manPages = [ "ctrl-exec-dispatcher.8" "ced.8" "ctrl-exec-api.8" ];
  };
}
