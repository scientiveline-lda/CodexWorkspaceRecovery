"""Persist repeatable unit/integration evidence; fixtures only."""

import argparse
import hashlib
import json
import sys
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_ids(suite):
    result = []
    for item in suite:
        result.extend(test_ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return sorted(result)


def release_success(result, expected, discovered):
    return (
        result.wasSuccessful()
        and not result.skipped
        and not result.expectedFailures
        and not result.unexpectedSuccesses
        and expected == discovered
        and result.testsRun == len(expected)
        and len(expected) == len(set(expected))
        and bool(expected)
    )


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.evidence = []

    def startTest(self, test):
        self.started = time.monotonic()
        super().startTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self.evidence.append(
            {
                "test": test.id(),
                "status": "passed",
                "seconds": round(time.monotonic() - self.started, 4),
            }
        )

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.evidence.append({"test": test.id(), "status": "failed"})

    def addError(self, test, err):
        super().addError(test, err)
        self.evidence.append({"test": test.id(), "status": "error"})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.evidence.append({"test": test.id(), "status": "skipped", "reason": reason})


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--inventory", default=str(ROOT / "tests/required-tests.json"))
    a = p.parse_args()
    start = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    discovered = test_ids(suite)
    expected = json.loads(Path(a.inventory).read_text(encoding="utf-8"))["tests"]
    if discovered != expected or not expected:
        target = Path(a.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "passed": False,
                    "status": "failed",
                    "reason": "required_test_inventory_mismatch",
                    "missing": sorted(set(expected) - set(discovered)),
                    "unexpected": sorted(set(discovered) - set(expected)),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        raise SystemExit(1)
    result = unittest.TextTestRunner(verbosity=1, resultclass=EvidenceResult).run(suite)
    report = {
        "created_at": datetime.now(UTC).isoformat(),
        "python": sys.version.split()[0],
        "application_module": __import__("cwm").__file__,
        "tests": result.testsRun,
        "passed": release_success(result, expected, discovered),
        "required_inventory_sha256": hashlib.sha256(Path(a.inventory).read_bytes()).hexdigest(),
        "application_sha256": hashlib.sha256(
            Path(__import__("cwm").__file__).read_bytes()
        ).hexdigest(),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "seconds": round(time.monotonic() - start, 3),
        "cases": result.evidence,
        "scope": "synthetic fixtures and real local crypto/Git tools; not production account certification",
    }
    target = Path(a.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    raise SystemExit(0 if report["passed"] else 1)
