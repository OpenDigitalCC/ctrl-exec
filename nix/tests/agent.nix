# NixOS VM test for services.ctrl-exec-agent: pairing with a real dispatcher,
# a direct run, a run under a profile through the executor, and adoption of a
# renewed certificate.
#
# Scripts use only absolute paths (#!/bin/sh and /run/current-system/sw/bin/...):
# the test must not depend on script_path being honoured by the agent.
{ pkgs, lib, ... }:

let
  packages = pkgs.callPackage ../package.nix { };

  hello = pkgs.writeText "hello.sh" ''
    #!/bin/sh
    echo "hello from $(/run/current-system/sw/bin/id -un)"
  '';

  whoami = pkgs.writeText "whoami.sh" ''
    #!/bin/sh
    echo "profile-run user=$(/run/current-system/sw/bin/id -un) uid=$(/run/current-system/sw/bin/id -u)"
  '';
in
{
  name = "ctrl-exec-agent";

  nodes.dispatcher = { pkgs, ... }: {
    environment.systemPackages = [ packages.ctrl-exec-dispatcher pkgs.openssl ];
    users.groups.ctrl-exec = { };
    users.users.ctrl-exec = { isSystemUser = true; group = "ctrl-exec"; };
    networking.firewall.allowedTCPPorts = [ 7444 ];
  };

  nodes.agent = { pkgs, ... }: {
    imports = [ ../module.nix ];

    services.ctrl-exec-agent = {
      enable = true;
      package = packages.ctrl-exec-agent;
      openFirewall = true;
      # The copied-out scripts must satisfy the strict ownership check.
      settings.script_ownership = "strict";
      scripts.hello.source = hello;
    };

    users.users.testuser = { isNormalUser = true; };
    # Only for the test's own certificate checks: the agent finds openssl
    # through its wrapper, not through the system PATH.
    environment.systemPackages = [ pkgs.openssl ];

    # Second configuration: executor on, one script under a non-default profile.
    specialisation.executor.configuration = {
      services.ctrl-exec-agent = {
        executor.enable = true;
        profiles.svc.run_as = "testuser";
        scripts.whoami = { source = whoami; options.profile = "svc"; };
      };
    };
  };

  testScript = ''
    start_all()
    dispatcher.wait_for_unit("multi-user.target")
    agent.wait_for_unit("multi-user.target")

    with subtest("module layout: copied files, not store links"):
        agent.succeed("test -f /opt/ctrl-exec-scripts/hello")
        agent.fail("test -L /opt/ctrl-exec-scripts/hello")
        assert agent.succeed("stat -c '%F %U:%G %a' /opt/ctrl-exec-scripts/hello").strip() == "regular file root:root 755"
        assert agent.succeed("stat -c '%U:%G %a' /opt/ctrl-exec-scripts").strip() == "root:root 755"
        # Not the store file: a copy.
        agent.succeed("cmp /opt/ctrl-exec-scripts/hello ${hello}")
        for f in ["agent.conf", "scripts.conf"]:
            agent.fail(f"test -L /etc/ctrl-exec-agent/{f}")
            assert agent.succeed(f"stat -c '%F %U:%G %a' /etc/ctrl-exec-agent/{f}").strip() == "regular file root:ctrl-exec-agent 640"
        assert agent.succeed("stat -c '%U:%G %a' /etc/ctrl-exec-agent").strip() == "root:ctrl-exec-agent 750"
        assert agent.succeed("stat -c '%U:%G %a' /var/lib/ctrl-exec-agent").strip() == "ctrl-exec-agent:ctrl-exec-agent 750"
        agent.succeed("grep -qx 'script_path = /run/wrappers/bin:/run/current-system/sw/bin' /etc/ctrl-exec-agent/agent.conf")
        agent.fail("grep executor_socket /etc/ctrl-exec-agent/agent.conf")
        agent.succeed("grep -qx 'hello = /opt/ctrl-exec-scripts/hello' /etc/ctrl-exec-agent/scripts.conf")
        agent.fail("systemctl cat ctrl-exec-executor.service")
        print(agent.succeed("cea --version"))

    with subtest("unpaired agent refuses to start and does not loop"):
        agent.wait_until_succeeds("systemctl is-failed ctrl-exec-agent.service")

    with subtest("dispatcher CA and certificate"):
        dispatcher.succeed("mkdir -p /etc/ctrl-exec-dispatcher /var/lib/ctrl-exec")
        dispatcher.succeed("""cat > /etc/ctrl-exec-dispatcher/ctrl-exec.conf <<'EOF'
    cert = /etc/ctrl-exec-dispatcher/dispatcher.crt
    key  = /etc/ctrl-exec-dispatcher/dispatcher.key
    ca   = /etc/ctrl-exec-dispatcher/ca.crt
    cert_days = 365
    EOF""")
        dispatcher.succeed("ced setup-ca")
        dispatcher.succeed("ced setup-ctrl-exec")
        print(dispatcher.succeed("ced pairing-mode start"))

    with subtest("pairing"):
        agent.succeed("(ctrl-exec-agent request-pairing --dispatcher dispatcher > /tmp/pair.log 2>&1 &) ; sleep 1")
        dispatcher.wait_until_succeeds("ced list-requests | grep -q agent", timeout=60)
        reqs = dispatcher.succeed("ced list-requests")
        print(reqs)
        # first data row: ID HOSTNAME SOURCE-IP REVERSE-DNS(...) CODE (v2)
        row = [l for l in reqs.splitlines() if l.startswith(tuple("0123456789abcdef")) and "(v2)" in l][0]
        reqid = row.split()[0]
        code = row.split()[-2]
        dispatcher.succeed(f"ced approve {reqid}")
        agent.wait_until_succeeds("test -f /etc/ctrl-exec-agent/agent.crt", timeout=60)
        # The agent prints the code it computed (buffered until it exits).
        agent.wait_until_succeeds(f"grep -q 'Pairing code: {code}' /tmp/pair.log", timeout=60)
        agent.succeed("test -f /etc/ctrl-exec-agent/agent.key -a -f /etc/ctrl-exec-agent/ca.crt")
        dispatcher.succeed("ced pairing-mode stop")

    with subtest("agent serves; direct run (executor off)"):
        agent.succeed("systemctl start ctrl-exec-agent.service")
        agent.wait_for_open_port(7443)
        dispatcher.succeed("ced ping agent")
        out = dispatcher.succeed("ced run agent hello")
        print(out)
        assert "hello from ctrl-exec-agent" in out, out

    with subtest("executor and a non-default profile"):
        agent.succeed("/run/booted-system/specialisation/executor/bin/switch-to-configuration test")
        agent.wait_for_unit("ctrl-exec-executor.service")
        agent.wait_for_unit("ctrl-exec-agent.service")
        agent.succeed("grep -qx 'executor_socket = /run/ctrl-exec-agent/exec.sock' /etc/ctrl-exec-agent/agent.conf")
        agent.succeed("test -S /run/ctrl-exec-agent/exec.sock")
        agent.wait_for_open_port(7443)
        out = dispatcher.succeed("ced run agent whoami")
        print(out)
        assert "user=testuser" in out, out
        # default profile (run_as nobody) through the executor
        out = dispatcher.succeed("ced run agent hello")
        assert "hello from nobody" in out, out
        assert agent.succeed("stat -c '%F %U:%G %a' /opt/ctrl-exec-scripts/whoami").strip() == "regular file root:root 755"

    with subtest("adopt a staged renewed certificate"):
        before = agent.succeed("openssl x509 -in /etc/ctrl-exec-agent/agent.crt -noout -serial")
        # Renewal is due when the agent cert's remaining validity is below
        # cert_days / 2. A fresh agent cert lives about 3 years, so a larger
        # cert_days makes it due now, without moving the clock.
        dispatcher.succeed("sed -i 's/^cert_days.*/cert_days = 3000/' /etc/ctrl-exec-dispatcher/ctrl-exec.conf")
        print(dispatcher.succeed("ced maintain"))
        agent.wait_until_succeeds("test -f /var/lib/ctrl-exec-agent/agent.crt.staged")
        agent.succeed("cea cert-staged")
        agent.succeed("systemctl start ctrl-exec-agent-renew.service")
        agent.wait_for_unit("ctrl-exec-agent.service")
        agent.wait_for_open_port(7443)
        agent.fail("test -f /var/lib/ctrl-exec-agent/agent.crt.staged")
        after = agent.succeed("openssl x509 -in /etc/ctrl-exec-agent/agent.crt -noout -serial")
        assert before != after, "certificate was not replaced"
        dispatcher.succeed("ced ping agent")
        assert "user=testuser" in dispatcher.succeed("ced run agent whoami")
        agent.succeed("systemctl list-timers ctrl-exec-agent-renew.timer | grep -q ctrl-exec-agent-renew")
  '';
}
