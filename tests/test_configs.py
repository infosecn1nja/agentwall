"""Configuration/regression tests for the deployed files (no live services needed).

These encode the P0 operational fixes so they cannot silently regress:
  * docker-compose scorer command must not smuggle YAML comments into argv
  * systemd unit must be dry-run by default
  * nginx/Apache must write the xff= field the scorer parses
  * nginx-lua must authenticate to Redis and use the shared pure module
  * fail2ban jails must have an ignoreip skeleton
  * preflight.sh must be syntactically valid
"""
import os
import shlex
import tempfile
import shutil
import subprocess
import unittest

import support

ROOT = support.ROOT


def read(relpath):
    with open(ROOT / relpath, encoding="utf-8") as fh:
        return fh.read()


def active_lines(text):
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


class ComposeTests(unittest.TestCase):
    def setUp(self):
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest("PyYAML not installed")
        self.config = yaml.safe_load(read("deploy/docker-compose.yml"))

    def test_scorer_command_has_no_yaml_comment_tokens(self):
        command = self.config["services"]["scorer"]["command"]
        tokens = command if isinstance(command, list) else shlex.split(command)
        self.assertNotIn("#", tokens)
        self.assertFalse([t for t in tokens if t.startswith("Phase")], tokens)

    def test_scorer_command_is_a_valid_dry_run_invocation(self):
        command = self.config["services"]["scorer"]["command"]
        tokens = command if isinstance(command, list) else shlex.split(command)
        args = support.scale.build_argparser().parse_args(tokens)
        self.assertFalse(args.enforce, "compose must default to dry-run")
        self.assertEqual(support.scale.validate_args(args), [])

    def test_redis_requires_a_password_and_is_not_public(self):
        redis_service = self.config["services"]["redis"]
        command = " ".join(redis_service.get("command", []))
        self.assertIn("requirepass", command)
        for published in redis_service.get("ports", []):
            self.assertTrue(str(published).startswith("127.0.0.1:"), published)

    def test_scorer_waits_for_healthy_redis(self):
        depends = self.config["services"]["scorer"].get("depends_on", {})
        self.assertIn("redis", depends)


class SystemdTests(unittest.TestCase):
    def setUp(self):
        self.text = read("deploy/agentwall-scorer.service")
        self.exec_lines = [line for line in self.text.splitlines()
                           if line.strip().startswith("ExecStart")]

    def test_active_execstart_is_dry_run(self):
        self.assertTrue(self.exec_lines)
        for line in self.exec_lines:
            active = line.split("ExecStart", 1)[1]
            self.assertNotIn("--enforce", active,
                             "the shipped unit must not enforce before the shadow phase")

    def test_unit_uses_env_file_for_secrets(self):
        self.assertIn("EnvironmentFile", self.text)

    def test_unit_reads_nginx_logs_and_writes_state(self):
        self.assertIn("SupplementaryGroups", self.text)
        self.assertIn("ReadWritePaths", self.text)


class WafTests(unittest.TestCase):
    def test_nginx_log_format_carries_xff(self):
        text = read("waf/nginx-agentwall.conf")
        self.assertIn('xff="$http_x_forwarded_for"', text)
        self.assertIn("log_format agentwall", text)
        self.assertIn("real_ip_header", text)

    def test_nginx_probe_map_covers_decoded_uri(self):
        text = read("waf/nginx-agentwall.conf")
        self.assertIn("$uri", text)
        self.assertIn("$query_string", text)

    def test_apache_log_format_carries_xff_and_is_enabled(self):
        text = read("waf/apache-agentwall.conf")
        self.assertIn("xff=", text)
        self.assertIn("X-Forwarded-For", text)
        customlogs = [line for line in active_lines(text) if line.strip().startswith("CustomLog")]
        self.assertTrue(customlogs, "CustomLog must be enabled")
        self.assertIn("agentwall_access.log", customlogs[0])


class LuaTests(unittest.TestCase):
    def test_common_module_and_auth_exist(self):
        self.assertTrue((ROOT / "nginx-lua/agentwall_common.lua").is_file())
        for name in ("nginx-lua/agentwall_redis_block.lua", "nginx-lua/agentwall_challenge_block.lua"):
            text = read(name)
            self.assertIn("agentwall_common", text)
            active = [line for line in text.splitlines()
                      if "auth(" in line and not line.lstrip().startswith("--")]
            self.assertTrue(active, "{} must authenticate to Redis".format(name))

    def test_lua_files_load(self):
        lua = shutil.which("lua")
        if not lua:
            self.skipTest("lua binary not found")
        for path in sorted((ROOT / "nginx-lua").glob("*.lua")):
            result = subprocess.run(
                [lua, "-e", 'assert(loadfile("{}"))'.format(path)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, "{}: {}".format(path, result.stderr))


class Fail2banTests(unittest.TestCase):
    def test_jails_have_ignoreip(self):
        for path in sorted((ROOT / "fail2ban/jail.d").glob("*.local")):
            text = read(path.relative_to(ROOT))
            self.assertIn("ignoreip", text, str(path))
            self.assertIn("banaction", text, str(path))

    def test_readme_documents_real_ip_requirement(self):
        text = read("fail2ban/README.md")
        self.assertIn("real_ip", text)
        self.assertIn("X-Forwarded-For", text)


class DocsTests(unittest.TestCase):
    def test_deployment_runbook_is_consistent_with_the_fixed_configs(self):
        text = read("deploy/DEPLOYMENT-production.md")
        self.assertNotIn("fail2ban-agentwall.md", text, "stale file reference")
        self.assertNotIn("command: >", text, "stale broken compose snippet")
        self.assertIn("preflight.sh", text)
        self.assertIn("tests/run-tests.sh", text)
        self.assertIn("AGENTWALL_CHAL_SECRET", text)
        self.assertIn("NoNewPrivileges", text)

    def test_root_readme_documents_verification_and_compose_env_location(self):
        text = read("README.md")
        self.assertIn("tests/run-tests.sh", text)
        self.assertIn("deploy/preflight.sh", text)
        self.assertIn("deploy/.env", text)


class ProductionAssetTests(unittest.TestCase):
    """Lock in the production-ready assets: complete nginx config, observability,
    CI, Linux validation, secret generation and log rotation."""

    def test_complete_nginx_config_wires_the_enforcement_layer(self):
        self.assertTrue((ROOT / "deploy/nginx.conf.example").is_file())
        text = read("deploy/nginx.conf.example")
        for needle in ("real_ip_header", "access_by_lua_file", "lua_shared_dict",
                       'xff="$http_x_forwarded_for"', "limit_req_zone", "proxy_pass",
                       "app_backend"):
            self.assertIn(needle, text)

    def test_prometheus_rules_are_present_and_complete(self):
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest("PyYAML not installed")
        rules = yaml.safe_load(read("deploy/prometheus/agentwall.rules.yml"))
        alerts = [rule for group in rules["groups"] for rule in group["rules"]]
        self.assertGreaterEqual(len(alerts), 15)
        names = {rule["alert"] for rule in alerts}
        self.assertIn("AgentWallScorerDown", names)
        for rule in alerts:
            self.assertIn("expr", rule)
            self.assertIn(rule["labels"]["severity"], ("critical", "warning", "info"))
            self.assertIn("summary", rule["annotations"])
        scrape = yaml.safe_load(read("deploy/prometheus/scrape.example.yml"))
        self.assertIn("scrape_configs", scrape)

    def test_ci_runs_the_production_gates(self):
        text = read(".github/workflows/ci.yml")
        for needle in ("tests/run-tests.sh", "deploy/preflight.sh",
                       "tests/e2e-real/run.sh", "deploy/validate-linux.sh"):
            self.assertIn(needle, text)

    def test_linux_validator_and_secret_tooling_are_executable(self):
        for rel in ("deploy/validate-linux.sh", "deploy/gen-secrets.sh",
                    "deploy/preflight.sh", "tests/run-tests.sh",
                    "tests/e2e-real/run.sh"):
            path = ROOT / rel
            self.assertTrue(path.is_file(), rel)
            self.assertTrue(os.access(path, os.X_OK), "{} must be executable".format(rel))
        secrets = read("deploy/gen-secrets.sh")
        self.assertIn("umask 077", secrets)
        self.assertIn("AGENTWALL_CHAL_SECRET", secrets)

    def test_agent_default_signatures_are_shipped_in_every_layer(self):
        for rel in ("waf/nginx-agentwall.conf", "waf/apache-agentwall.conf",
                    "deploy/nginx.conf.example", "scorer/agentwall_scorer.py",
                    "nginx-lua/agentwall_common.lua"):
            text = read(rel)
            for marker in ("artex-enrich", "nuclei", "sqlmap", "ffuf"):
                self.assertIn(marker, text, "{} lacks {}".format(rel, marker))

    def test_agent_validation_profiles_are_shipped(self):
        run = read("tests/e2e-real/run.sh")
        self.assertIn("AGENT_UAS", run)
        self.assertIn("strix", run.lower())
        self.assertIn("artex-enrich", run)
        self.assertIn("STRIX", read("tests/e2e-real/report.py"))
        doc = read("docs/AGENT-VALIDATION.md")
        self.assertIn("usestrix/strix", doc)
        self.assertIn("jiwoochris/artex-global", doc)

    def test_logrotate_reopens_nginx_and_keeps_the_path(self):
        text = read("deploy/logrotate/agentwall")
        self.assertIn("USR1", text)
        self.assertIn("create 0640", text)
        self.assertIn("postrotate", text)


class EnvContractTests(unittest.TestCase):
    """A missing `env NAME;` silently makes Lua fall back to defaults (the
    headless mode default is `mark`, so enforcement would silently not happen)."""

    def _lua_env_vars(self):
        import re
        lua = read("nginx-lua/agentwall_common.lua")
        return sorted(set(re.findall(r'"(AGENTWALL_[A-Z0-9_]+)"', lua)))

    def test_all_lua_env_vars_are_declared_in_the_production_nginx_config(self):
        cfg = read("deploy/nginx.conf.example")
        missing = [name for name in self._lua_env_vars()
                   if "env {};".format(name) not in cfg]
        self.assertFalse(missing, "deploy/nginx.conf.example is missing: {}".format(missing))

    def test_e2e_harness_declares_the_same_env_vars(self):
        harness = read("tests/e2e-real/run.sh")
        missing = [name for name in self._lua_env_vars()
                   if "env {};".format(name) not in harness]
        self.assertFalse(missing, "tests/e2e-real/run.sh is missing: {}".format(missing))


class PreflightTests(unittest.TestCase):
    def test_preflight_exists_and_is_valid_bash(self):
        path = ROOT / "deploy/preflight.sh"
        self.assertTrue(path.is_file())
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def _run_preflight(self, line):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write(line + "\n")
            path = fh.name
        try:
            return subprocess.run(
                ["bash", str(ROOT / "deploy/preflight.sh"), "--log", path,
                 "--use-xff", "--skip-redis"],
                capture_output=True, text=True, cwd=str(ROOT),
            )
        finally:
            os.unlink(path)

    def test_preflight_passes_on_a_well_formed_xff_log(self):
        # Regression: `printf | grep -q` under `set -o pipefail` yields SIGPIPE
        # and made this check fail even when xff="..." was present.
        line = ('203.0.113.7 - - [27/Oct/2026:20:46:24 +0700] "GET / HTTP/1.1" 200 5 "-" '
                '"curl/8.4.0" rt=0.001 urt=0.001 ua_flag=0 probe=0 xff="198.51.100.9"')
        result = self._run_preflight(line)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("FAIL=0", result.stdout)

    def test_preflight_fails_when_use_xff_but_the_log_lacks_xff(self):
        line = ('203.0.113.7 - - [27/Oct/2026:20:46:24 +0700] "GET / HTTP/1.1" 200 5 "-" '
                '"curl/8.4.0" rt=0.001 urt=0.001 ua_flag=0 probe=0')
        result = self._run_preflight(line)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no xff", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
