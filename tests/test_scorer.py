"""Unit tests for the scale-aware scorer (scorer/agentwall_scorer.py).

Run with:  python3 -m unittest discover -s tests -p 'test_*.py' -v
No third-party dependency is needed: river is stubbed in tests/support.py.
"""
import os
import pickle
import tempfile
import unittest

import support

s = support.scale
v1 = support.legacy

T0 = 1_800_000_000.0


def ev(ts=T0, status=200, path="/", is_auth=False, is_static=False, is_probe=False,
       ua_flag=False, is_browser=True, is_tool=False, has_ref=True, xff=None, ip="203.0.113.7",
       is_oob=False):
    return {
        "ip": ip, "xff": xff, "ts": ts, "status": status, "path": path,
        "ua": "", "is_auth": is_auth, "is_static": is_static, "is_probe": is_probe,
        "is_oob": is_oob,
        "ua_flag": ua_flag, "is_browser": is_browser, "is_tool": is_tool, "has_ref": has_ref,
    }


class ParseLineTests(unittest.TestCase):
    NGINX = ('203.0.113.7 - - [27/Oct/2026:20:46:24 +0700] "GET /admin/login?next=/x HTTP/1.1" '
             '401 153 "-" "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36" '
             'rt=0.001 urt=0.001 ua_flag=0 probe=0 xff="198.51.100.9, 10.0.0.5"')

    def test_without_xff_uses_socket_ip(self):
        event = s.parse_line(self.NGINX, use_xff=False)
        self.assertEqual(event["ip"], "203.0.113.7")
        self.assertEqual(event["xff"], "198.51.100.9, 10.0.0.5")
        self.assertEqual(event["status"], 401)
        self.assertTrue(event["is_auth"])
        self.assertTrue(event["is_browser"])
        self.assertFalse(event["is_tool"])
        self.assertFalse(event["has_ref"])

    def test_xff_from_untrusted_peer_never_spoofs(self):
        # Direct client (not a trusted proxy) sends a forged XFF: the socket peer
        # must win, regardless of what the left-most hop claims.
        event = s.parse_line(self.NGINX, use_xff=True,
                             trusted_proxies=s.parse_trusted_proxies("10.0.0.0/8"))
        self.assertEqual(event["ip"], "203.0.113.7")

    def test_xff_trusted_proxy_uses_rightmost_untrusted_hop(self):
        # Our edge (10.0.0.5) appends the real client; a spoofed 127.0.0.1 at the
        # left must be ignored.
        line = ('10.0.0.5 - - [27/Oct/2026:20:46:24 +0700] "GET / HTTP/1.1" 200 1 "-" "curl/8" '
                'rt=0 urt=0 ua_flag=0 probe=0 xff="127.0.0.1, 198.51.100.9"')
        event = s.parse_line(line, use_xff=True,
                             trusted_proxies=s.parse_trusted_proxies("10.0.0.0/8"))
        self.assertEqual(event["ip"], "198.51.100.9")

    def test_xff_all_hops_trusted_falls_back_to_socket(self):
        line = ('10.0.0.5 - - [27/Oct/2026:20:46:24 +0700] "GET / HTTP/1.1" 200 1 "-" "curl/8" '
                'rt=0 urt=0 ua_flag=0 probe=0 xff="10.1.2.3"')
        event = s.parse_line(line, use_xff=True,
                             trusted_proxies=s.parse_trusted_proxies("10.0.0.0/8"))
        self.assertEqual(event["ip"], "10.0.0.5")

    def test_combined_format_fallback(self):
        line = ('198.51.100.9 - - [27/Oct/2026:20:46:24 +0700] "GET /?id=1%27%20or%201%3D1 HTTP/1.1" '
                '200 12 "-" "sqlmap/1.8"')
        event = s.parse_line(line)
        self.assertIsNotNone(event)
        self.assertFalse(event["is_browser"])
        self.assertTrue(event["is_tool"])
        self.assertTrue(event["is_probe"])  # encoded query decoded by the access log? see regex below

    def test_xff_dash_keeps_socket_ip(self):
        line = ('203.0.113.7 - - [27/Oct/2026:20:46:24 +0700] "GET / HTTP/1.1" 200 1 "-" "curl/8" '
                'rt=0 urt=0 ua_flag=0 probe=0 xff="-"')
        self.assertEqual(s.parse_line(line, use_xff=True)["ip"], "203.0.113.7")

    def test_xff_mapped_ipv4_is_canonicalised(self):
        line = ('10.0.0.5 - - [27/Oct/2026:20:46:24 +0700] "GET / HTTP/1.1" 200 1 "-" "curl/8" '
                'rt=0 urt=0 ua_flag=0 probe=0 xff="::ffff:192.0.2.5"')
        self.assertEqual(
            s.parse_line(line, use_xff=True,
                        trusted_proxies=s.parse_trusted_proxies("10.0.0.0/8"))["ip"],
            "192.0.2.5")

    def test_garbage_line_returns_none(self):
        self.assertIsNone(s.parse_line("not an access log line"))
        self.assertIsNone(s.parse_line(""))


class IpKeyTests(unittest.TestCase):
    def test_expected_keys(self):
        cases = [
            ("203.0.113.7", 64, "203.0.113.7"),
            ("::ffff:192.0.2.5", 64, "192.0.2.5"),
            ("2001:0DB8:0:0:1:0:0:1", 64, "2001:db8::"),
            ("2001:db8:1:2:3:4:5:6", 128, "2001:db8:1:2:3:4:5:6"),
            ("2a00:1450:4001:82b::200e", 64, "2a00:1450:4001:82b::"),
            ("::1", 64, "::"),
            ("2001:db8:1:2:7fff::1", 65, "2001:db8:1:2::"),
            ("2001:db8:1:2:8000::1", 65, "2001:db8:1:2:8000::"),
            ("not-an-ip", 64, None),
        ]
        for ip, prefix, expected in cases:
            with self.subTest(ip=ip, prefix=prefix):
                self.assertEqual(s.ip_key(ip, prefix), expected)

    def test_rotation_inside_slash64_collapses_to_one_key(self):
        a = s.ip_key("2001:db8:1:2::1", 64)
        b = s.ip_key("2001:db8:1:2:ffff:aaaa:bbbb:cccc", 64)
        self.assertEqual(a, b)


class FeatureTests(unittest.TestCase):
    def make(self, n=20, **overrides):
        window = s.IPWindow()
        for i in range(n):
            kwargs = dict(ev(ts=T0 + i * 0.5, path="/x{}".format(i), status=404,
                             is_browser=False, is_tool=True, has_ref=False))
            kwargs.update(overrides)
            window.add(kwargs, 60)
        return window

    def test_scanner_shape(self):
        window = self.make()
        x, stats, hard = window.features()
        self.assertAlmostEqual(x["miss_ratio"], 1.0)
        self.assertAlmostEqual(x["uniq_ratio"], 1.0)
        self.assertAlmostEqual(x["regularity"], 1.0)
        self.assertAlmostEqual(stats["tool_ratio"], 1.0)
        self.assertFalse(hard)  # no probe/auth and no deny -> the model must catch it

    def test_browser_shape_is_human(self):
        window = s.IPWindow()
        for i in range(20):
            static = i % 2 == 0
            window.add(ev(ts=T0 + i * 3.0, path="/style.css" if static else "/page",
                          is_static=static, status=200, is_browser=True,
                          is_tool=False, has_ref=True), 60)
        x, stats, hard = window.features()
        self.assertFalse(hard)
        self.assertGreater(s.humanness(stats, "web"), 0.7)

    def test_multistage_hard_signal(self):
        window = s.IPWindow()
        window.add(ev(ts=T0 + 0, path="/a", status=404, is_browser=False), 60)
        window.add(ev(ts=T0 + 1, path="/b", status=404, is_browser=False), 60)
        window.add(ev(ts=T0 + 2, path="/c", status=404, is_browser=False), 60)
        window.add(ev(ts=T0 + 3, path="/?q=union select", status=404, is_probe=True,
                      is_browser=False), 60)
        window.add(ev(ts=T0 + 4, path="/login", status=200, is_auth=True), 60)
        x, stats, hard = window.features()
        self.assertEqual(x["multistage"], 1.0)
        self.assertTrue(hard)

    def test_empty_window(self):
        self.assertEqual(s.IPWindow().features(), (None, None, False))


class HumannessTests(unittest.TestCase):
    def test_web_profile_maximum(self):
        stats = {"static_ratio": 1.0, "referer_ratio": 1.0, "browser_ratio": 1.0,
                 "tool_ratio": 0.0, "miss_ratio": 0.0, "probe_ratio": 0.0}
        self.assertAlmostEqual(s.humanness(stats, "web"), 1.0)

    def test_web_profile_tool_is_non_human(self):
        stats = {"static_ratio": 0.0, "referer_ratio": 0.0, "browser_ratio": 0.0,
                 "tool_ratio": 1.0, "miss_ratio": 0.0, "probe_ratio": 0.0}
        self.assertEqual(s.humanness(stats, "web"), 0.0)

    def test_api_profile_does_not_require_static_assets(self):
        stats = {"static_ratio": 0.0, "referer_ratio": 0.0, "browser_ratio": 0.1,
                 "tool_ratio": 0.1, "miss_ratio": 0.0, "probe_ratio": 0.0}
        self.assertGreater(s.humanness(stats, "api"), 0.7)
        self.assertLess(s.humanness(stats, "web"), 0.3)

    def test_clamped_to_unit_interval(self):
        stats = {"static_ratio": 1.0, "referer_ratio": 1.0, "browser_ratio": 1.0,
                 "tool_ratio": 0.0, "miss_ratio": 0.0, "probe_ratio": 0.0}
        self.assertLessEqual(s.humanness(stats, "web"), 1.0)
        stats["probe_ratio"] = 1.0
        self.assertGreaterEqual(s.humanness(stats, "web"), 0.0)


class SuspicionTests(unittest.TestCase):
    X = {"persistence": 1.0, "probe_ratio": 1.0, "miss_ratio": 1.0, "multistage": 1.0}

    def test_human_ceiling_limits_suspicion(self):
        # A perfect human-ness score cannot add anomaly evidence, but the boost
        # terms still apply (0.4 max).
        self.assertAlmostEqual(s.compute_suspicion(self.X, 1.0, 1.0), 0.4)

    def test_fully_non_human_max(self):
        self.assertAlmostEqual(s.compute_suspicion(self.X, 0.0, 1.0), 1.0)

    def test_bounds(self):
        for human in (0.0, 0.25, 0.5, 1.0):
            for anomaly in (0.0, 0.5, 1.0):
                score = s.compute_suspicion(self.X, human, anomaly)
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 1.0)


class PopulationEligibilityTests(unittest.TestCase):
    def test_only_human_like_non_hard_events_calibrate_population(self):
        self.assertTrue(s.population_eligible(0.80, False, 0.55))
        self.assertFalse(s.population_eligible(0.54, False, 0.55))
        self.assertFalse(s.population_eligible(0.80, True, 0.55))
        self.assertFalse(s.population_eligible(0.20, False, 0.55))


class QuantileTests(unittest.TestCase):
    def test_quantiles_and_readiness(self):
        pop = s.PopulationQuantiles(window=100, recompute_every=1, qs=(0.5, 0.9))
        for value in range(1, 101):
            pop.update(float(value))
        self.assertAlmostEqual(pop.get(0.5), 51.0)   # idx = int(0.5*100) = 50
        self.assertAlmostEqual(pop.get(0.9), 91.0)   # idx = int(0.9*100) = 90
        self.assertTrue(pop.ready(100))
        self.assertFalse(pop.ready(101))

    def test_empty_returns_none(self):
        self.assertIsNone(s.PopulationQuantiles(qs=(0.99,)).get(0.99))

    def test_zero_quantile_is_not_mistaken_for_missing(self):
        pop = s.PopulationQuantiles(window=10, recompute_every=1, qs=(0.0,))
        for _ in range(10):
            pop.update(0.0)
        self.assertEqual(pop.get(0.0), 0.0)


class DecideTests(unittest.TestCase):
    def make(self):
        return s.IPWindow()

    def decide(self, w, now, **kwargs):
        params = dict(suspicion=0.9, humanness_score=0.1, hard=False, now=now,
                      cooldown=120.0, grace=120.0, block_cut=0.55, watch_cut=0.40,
                      human_floor=0.55)
        params.update(kwargs)
        return s.decide(w, **params)

    def test_next_action(self):
        w = self.make()
        self.assertEqual(self.decide(w, T0), "challenge")
        w.last_challenge = T0
        w.challenged_at = T0
        self.assertIsNone(self.decide(w, T0 + 60))      # inside grace + cooldown
        self.assertEqual(self.decide(w, T0 + 120), "block")  # grace elapsed

    def test_hard_signal_blocks_immediately_and_is_debounced(self):
        w = self.make()
        self.assertEqual(self.decide(w, T0, hard=True), "block")
        w.last_block = T0
        self.assertIsNone(self.decide(w, T0 + 30, hard=True))
        self.assertEqual(self.decide(w, T0 + 120, hard=True), "block")

    def test_human_floor_never_blocks_on_percentile(self):
        self.assertIsNone(self.decide(self.make(), T0, humanness_score=0.56))

    def test_watch_branch_and_debounce(self):
        w = self.make()
        self.assertEqual(self.decide(w, T0, suspicion=0.45), "watch")
        w.last_watch = T0
        self.assertIsNone(self.decide(w, T0 + 10, suspicion=0.45))
        self.assertEqual(self.decide(w, T0 + 120, suspicion=0.45), "watch")

    def test_below_watch_is_no_action(self):
        self.assertIsNone(self.decide(self.make(), T0, suspicion=0.2))


class StateTests(unittest.TestCase):
    def test_roundtrip_and_no_tmp_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "model.pkl")
            model = {"anything": [1, 2, 3]}
            s.save_state(model, path)
            self.assertTrue(os.path.exists(path))
            self.assertEqual(s.load_state(path), model)
            self.assertEqual([n for n in os.listdir(os.path.dirname(path)) if ".tmp." in n], [])

    def test_corrupt_state_starts_fresh_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "model.pkl")
            with open(path, "wb") as fh:
                fh.write(b"this is not a pickle")
            self.assertIsNone(s.load_state(path))

    def test_state_file_is_written_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "model.pkl")
            s.save_state({"x": 1}, path)
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600, oct(mode))

    def test_symlinked_state_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target.pkl")
            with open(target, "wb") as fh:
                import pickle
                pickle.dump({"legacy": True}, fh)
            link = os.path.join(tmp, "link.pkl")
            os.symlink(target, link)
            self.assertIsNone(s.load_state(link))

    def test_legacy_bare_model_checkpoint_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "model.pkl")
            with open(path, "wb") as fh:
                pickle.dump({"legacy": True}, fh)
            self.assertEqual(s.load_state(path), {"legacy": True})

    def test_missing_state_is_none(self):
        self.assertIsNone(s.load_state("/nonexistent/does-not-exist.pkl"))
        self.assertIsNone(s.load_state(None))


class ValidationTests(unittest.TestCase):
    def parse(self, argv):
        parser = s.build_argparser()
        return parser, parser.parse_args(argv)

    def errors(self, argv):
        parser, args = self.parse(argv)
        return s.validate_args(args)

    def test_defaults_valid(self):
        self.assertEqual(self.errors(["--log", "/tmp/x.log"]), [])

    def test_enforce_needs_a_backend(self):
        errors = self.errors(["--log", "x", "--enforce"])
        self.assertTrue(any("--enforce requires" in e for e in errors))

    def test_enforce_and_dry_run_conflict(self):
        errors = self.errors(["--log", "x", "--enforce", "--dry-run", "--backend", "redis"])
        self.assertTrue(any("mutually exclusive" in e for e in errors))

    def test_percentile_order(self):
        errors = self.errors(["--log", "x", "--p-block", "0.5", "--p-watch", "0.95"])
        self.assertTrue(any("p-block" in e for e in errors))

    def test_bad_ranges(self):
        for argv in (["--log", "x", "--ipv6-prefix", "200"],
                     ["--log", "x", "--metrics-port", "99999"],
                     ["--log", "x", "--challenge-grace", "0"],
                     ["--log", "x", "--human-floor", "1.5"]):
            self.assertTrue(self.errors(argv), argv)

    def test_use_xff_requires_trusted_proxies(self):
        self.assertTrue(self.errors(["--log", "x", "--use-xff"]))
        self.assertFalse(self.errors([
            "--log", "x", "--use-xff", "--trust-proxies", "10.0.0.0/8,192.0.2.0/24"]))
        self.assertTrue(self.errors([
            "--log", "x", "--use-xff", "--trust-proxies", "not-a-cidr"]))

    def test_full_command_line_parses(self):
        parser, args = self.parse([
            "--log", "/var/log/nginx/agentwall_access.log", "--enforce",
            "--backend", "redis", "--profile", "api", "--ipv6-prefix", "64",
            "--metrics-port", "9101", "--metrics-bind", "0.0.0.0",
            "--fail2ban-sudo", "--state", "/var/lib/agentwall/model.pkl",
        ])
        self.assertTrue(args.enforce)
        self.assertEqual(args.profile, "api")
        self.assertEqual(args.metrics_port, 9101)
        self.assertEqual(s.validate_args(args), [])


class ActionerTests(unittest.TestCase):
    class FakeRedis:
        def __init__(self, value):
            self.value = value

        def exists(self, key):
            return self.value

    class BrokenRedis:
        def exists(self, key):
            raise RuntimeError("redis is down")

    def make_actioner(self, redis_client):
        act = object.__new__(s.Actioner)
        act.redis = redis_client
        act.metrics = None
        act._err_last = {}
        act.backend = "redis"
        act.enforce = True
        return act

    def test_headless_marker_is_read_from_redis(self):
        self.assertTrue(self.make_actioner(self.FakeRedis(1)).is_headless("203.0.113.7"))
        self.assertFalse(self.make_actioner(self.FakeRedis(0)).is_headless("203.0.113.7"))
        self.assertFalse(self.make_actioner(None).is_headless("203.0.113.7"))

    def test_headless_marker_redis_error_fails_open(self):
        self.assertFalse(self.make_actioner(self.BrokenRedis()).is_headless("203.0.113.7"))


class GoodBotQueueTests(unittest.TestCase):
    def test_saturated_fcrdns_queue_sheds_instead_of_queueing(self):
        verifier = s.GoodBotVerifier(workers=1, max_pending=1)
        self.assertTrue(verifier._pending.acquire(blocking=False))
        try:
            self.assertFalse(verifier.is_good_bot("203.0.113.9", "Mozilla/5.0 Googlebot/2.1"))
        finally:
            verifier._pending.release()
        self.assertIn("203.0.113.9", verifier.cache)

    def test_fcrdns_lookup_releases_its_slot(self):
        verifier = s.GoodBotVerifier(workers=1, max_pending=1)
        original = s.GoodBotVerifier._verify
        s.GoodBotVerifier._verify = staticmethod(lambda ip: True)
        try:
            self.assertTrue(verifier.is_good_bot("203.0.113.10", "Mozilla/5.0 Googlebot/2.1"))
        finally:
            s.GoodBotVerifier._verify = original
        self.assertTrue(verifier._pending.acquire(blocking=False))
        verifier._pending.release()


class BatchAndModelTests(unittest.TestCase):
    def test_read_once_yields_all_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "log")
            with open(path, "w") as fh:
                fh.write("a\nb\n")
            self.assertEqual(list(s.read_once(path)), ["a\n", "b\n"])

    def test_hst_defaults_are_production_sane(self):
        args = s.build_argparser().parse_args(["--log", "x"])
        # river defaults: 25/15 made ~1.6M nodes (~500MB, <500 ev/s)
        self.assertEqual((args.hst_trees, args.hst_height, args.hst_window), (10, 8, 250))
        self.assertEqual(s.validate_args(args), [])

    def test_hst_bad_geometry_rejected(self):
        self.assertTrue(s.validate_args(s.build_argparser().parse_args(
            ["--log", "x", "--hst-trees", "0"])))
        self.assertTrue(s.validate_args(s.build_argparser().parse_args(
            ["--log", "x", "--hst-height", "25"])))
        self.assertTrue(s.validate_args(s.build_argparser().parse_args(
            ["--log", "x", "--hst-window", "5"])))

    def test_once_flag_parses(self):
        args = s.build_argparser().parse_args(["--log", "x", "--once"])
        self.assertTrue(args.once)


class OobDetectionTests(unittest.TestCase):
    """OOB interaction callbacks are a hard, single-request attack signal."""

    def line(self, path, ref="-"):
        return ('203.0.113.9 - - [27/Oct/2026:20:46:24 +0700] "GET {} HTTP/1.1" '
                '200 5 "{}" "Mozilla/5.0" rt=0.001 urt=0.001 ua_flag=0 probe=0 '
                'xff="-"').format(path, ref)

    def test_oob_in_query_sets_probe_and_oob(self):
        for host in ("http://x.oast.fun/a", "y.burpcollaborator.net",
                     "z.oastify.com", "sub.dnslog.cn", "p.ceye.io",
                     "http://q.interact.sh/x"):
            e = s.parse_line(self.line("/api/fetch?url=" + host))
            self.assertTrue(e["is_oob"], host)
            self.assertTrue(e["is_probe"], host)

    def test_oob_in_referer(self):
        e = s.parse_line(self.line("/", ref="http://x.oast.fun/cb"))
        self.assertTrue(e["is_oob"])

    def test_url_encoded_probe_still_detected(self):
        e = s.parse_line(self.line("/x?u=%2E%2E%2Fetc%2Fpasswd"))
        self.assertTrue(e["is_probe"])

    def test_benign_traffic_is_not_oob(self):
        for path in ("/search?q=weather", "/articles/union-contract-review",
                     "/products?sort=price"):
            e = s.parse_line(self.line(path))
            self.assertFalse(e["is_oob"], path)
            self.assertFalse(e["is_probe"], path)

    def test_single_oob_event_is_a_hard_signal(self):
        w = s.IPWindow()
        for i in range(12):
            w.add(ev(ts=T0 + i, status=200, path="/p%d" % i), 120)
        w.add(ev(ts=T0 + 20, status=200, path="/fetch", is_oob=True, is_probe=True), 120)
        _, _, hard = w.features()
        self.assertTrue(hard)


class AuthPathTests(unittest.TestCase):
    """AUTH_RE must match whole auth path segments only (no /authors, /tokenomics)."""

    def test_auth_segments_match(self):
        for path in ("/login", "/login.php", "/auth", "/auth/callback", "/api/oauth/token",
                     "/admin/login?next=/x", "/password/reset", "/verify", "/2fa;jsessionid=1"):
            self.assertTrue(s.AUTH_RE.search(path), path)

    def test_lookalike_paths_do_not_match(self):
        for path in ("/authors/jane", "/tokenomics", "/verify-email-preview", "/loginhelp",
                     "/blog/authentication-guide", "/otpauth-explained"):
            self.assertIsNone(s.AUTH_RE.search(path), path)


class HeadlessModeTests(unittest.TestCase):
    def test_default_is_mark(self):
        old = os.environ.pop("AGENTWALL_HEADLESS_MODE", None)
        try:
            args = s.build_argparser().parse_args(["--log", "x"])
        finally:
            if old is not None:
                os.environ["AGENTWALL_HEADLESS_MODE"] = old
        self.assertEqual(args.headless_mode, "mark")

    def test_env_sets_mode_and_bad_env_is_rejected(self):
        old = os.environ.get("AGENTWALL_HEADLESS_MODE")
        try:
            os.environ["AGENTWALL_HEADLESS_MODE"] = "BLOCK"
            args = s.build_argparser().parse_args(["--log", "x"])
            self.assertEqual(args.headless_mode, "block")
            self.assertEqual(s.validate_args(args), [])
            os.environ["AGENTWALL_HEADLESS_MODE"] = "wat"
            args = s.build_argparser().parse_args(["--log", "x"])
            self.assertTrue(any("headless-mode" in e for e in s.validate_args(args)))
        finally:
            if old is None:
                os.environ.pop("AGENTWALL_HEADLESS_MODE", None)
            else:
                os.environ["AGENTWALL_HEADLESS_MODE"] = old

    def test_cli_flag(self):
        args = s.build_argparser().parse_args(["--log", "x", "--headless-mode", "block"])
        self.assertEqual(args.headless_mode, "block")


class FakeRedisStore:
    """Tiny in-memory stand-in for redis.Redis used by the main-loop tests."""

    def __init__(self):
        self.data = {}

    @classmethod
    def from_url(cls, *args, **kwargs):
        return cls._instance

    def ping(self):
        return True

    def set(self, key, value, ex=None):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)

    def exists(self, key):
        return 1 if key in self.data else 0


class MainLoopHeadlessTests(unittest.TestCase):
    """End-to-end through main(): the Lua headless marker must only hard-block in
    --headless-mode block (mark mode is the shadow default)."""

    IP = "203.0.113.31"

    def _run(self, headless_mode):
        import sys
        import types
        store = FakeRedisStore()
        FakeRedisStore._instance = store
        fake = types.ModuleType("redis")
        fake.Redis = FakeRedisStore
        saved = sys.modules.get("redis")
        sys.modules["redis"] = fake
        # Pre-set the marker: the Lua layer wrote it while the key was challenged.
        store.data["agentwall:headless:" + self.IP] = "1"
        lines = []
        for i in range(30):
            lines.append(
                '{ip} - - [27/Oct/2026:20:46:{sec:02d} +0700] "GET /probe{i} HTTP/1.1" 404 12 '
                '"-" "curl/8.4.0" rt=0.001 urt=0.001 ua_flag=0 probe=1 xff="-"'.format(
                    ip=self.IP, sec=i, i=i))
        try:
            with tempfile.TemporaryDirectory() as tmp:
                log = os.path.join(tmp, "access.log")
                with open(log, "w") as fh:
                    fh.write("\n".join(lines) + "\n")
                s.main(["--log", log, "--once", "--enforce", "--backend", "redis",
                        "--headless-mode", headless_mode, "--warmup", "0",
                        "--min-events", "1", "--cooldown", "0",
                        "--challenge-grace", "100000", "--floor-block", "0.05",
                        "--floor-watch", "0.01", "--no-verify-bots",
                        "--log-level", "CRITICAL"])
        finally:
            if saved is None:
                sys.modules.pop("redis", None)
            else:
                sys.modules["redis"] = saved
        return store

    def test_mark_mode_does_not_block_on_marker(self):
        store = self._run("mark")
        self.assertIn("agentwall:challenge:" + self.IP, store.data,
                      "precondition: the scorer must have challenged the key")
        self.assertNotIn("agentwall:block:" + self.IP, store.data)

    def test_block_mode_blocks_on_marker(self):
        store = self._run("block")
        self.assertIn("agentwall:block:" + self.IP, store.data)


class TailPermissionTests(unittest.TestCase):
    def test_unreadable_log_is_retried_not_fatal(self):
        calls = {"n": 0}
        real_open = open

        def flaky_open(path, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] < 3:
                raise PermissionError(13, "Permission denied", path)
            return real_open(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "access.log")
            with real_open(path, "w") as fh:
                fh.write("x\n")
            sleeps = []
            import builtins
            builtins.open = flaky_open
            try:
                fh = s._open_log(path, sleep=sleeps.append)
            finally:
                builtins.open = real_open
            try:
                self.assertEqual(fh.read(), "x\n")
            finally:
                fh.close()
        self.assertEqual(len(sleeps), 2)


class AllowlistTests(unittest.TestCase):
    def test_cidr_and_bad_entry(self):
        allow = s.Allowlist(["10.0.0.0/8", "::1/128", "not-a-cidr", "  "])
        self.assertTrue(allow.allows("10.1.2.3"))
        self.assertTrue(allow.allows("::1"))
        self.assertFalse(allow.allows("203.0.113.7"))
        self.assertFalse(allow.allows("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
