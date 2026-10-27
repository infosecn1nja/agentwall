"""Shared test helpers: load the scorer without requiring river/redis to be installed."""
import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCORER_DIR = ROOT / "scorer"


def _stub_river():
    """The scorer hard-requires river at import time; stub it for unit tests."""
    if "river" in sys.modules:
        return
    try:
        import river  # noqa: F401  (real dependency available)
        return
    except ImportError:
        pass

    river = types.ModuleType("river")
    anomaly = types.ModuleType("river.anomaly")

    class HalfSpaceTrees:  # minimal score-then-learn dummy
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def score_one(self, x):
            return 0.5

        def learn_one(self, x):
            return None

    anomaly.HalfSpaceTrees = HalfSpaceTrees
    river.anomaly = anomaly
    sys.modules["river"] = river
    sys.modules["river.anomaly"] = anomaly


_stub_river()


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCORER_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scale = _load("agentwall_scale_under_test", "agentwall_scorer.py")
legacy = _load("agentwall_v1_under_test", "agentwall_scorer_v1.py")
