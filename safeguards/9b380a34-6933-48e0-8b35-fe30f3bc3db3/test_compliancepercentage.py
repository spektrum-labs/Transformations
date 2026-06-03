"""Regression tests for the compliancepercentage transformation (LABS-2842).

Plain-python tests (no pytest dependency). Run directly:

    python test_compliancepercentage.py

Covers:
- Suppressed Security Hub findings are excluded from the score (the bug).
- Findings are deduped per security control (resource-level duplicates).
- CIS and FSBP scores are scoped to their own associated standard.
- Legacy / non Security Hub inputs (no AssociatedStandards) still score.
"""

import copy
import importlib.util
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location(
    "compliancepercentage", os.path.join(HERE, "compliancepercentage.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def _result(payload):
    return mod.transform(payload)["transformedResponse"]


def _cis_finding(control_id, status="PASSED", workflow="RESOLVED",
                 standards=("cis-aws-foundations-benchmark/v/1.4.0",), finding_id=None):
    return {
        "Compliance": {
            "Status": status,
            "SecurityControlId": control_id,
            "AssociatedStandards": [{"StandardsId": "standards/" + s} for s in standards],
        },
        "RecordState": "ACTIVE",
        "Workflow": {"Status": workflow},
        "Id": finding_id or f"finding/{control_id}/{status}/{workflow}",
    }


def test_sample_payload_excludes_suppressed():
    """The ticket payload should report 100% — IAM.6 FAILED is SUPPRESSED."""
    with open(os.path.join(HERE, "sample_response.json")) as f:
        payload = json.load(f)
    res = _result(payload)
    assert res["CIScompliancePercentage"] == 100, res
    assert res["compliancePercentage"] == 100, res
    # 20 findings -> IAM.6 suppressed dropped, S3.5 (x4) + RDS.3 (x2) deduped.
    assert res["totalFailed"] == 0, res
    assert res["totalFindings"] == 15, res


def test_unsuppressed_failure_counts():
    """A genuine (non-suppressed) failed control must lower the score."""
    findings = [
        _cis_finding("IAM.6", status="FAILED", workflow="NEW"),
        _cis_finding("Config.1", status="PASSED"),
        _cis_finding("S3.5", status="PASSED"),
        _cis_finding("RDS.3", status="PASSED"),
    ]
    res = _result({"Findings": findings})
    assert res["CIScompliancePercentage"] == 75, res
    assert res["totalFailed"] == 1, res
    assert res["totalFindings"] == 4, res


def test_dedup_per_control_failure():
    """A control fails if any of its resource findings fail; duplicates collapse."""
    findings = [
        _cis_finding("S3.5", status="PASSED", finding_id="a"),
        _cis_finding("S3.5", status="FAILED", finding_id="b"),  # one resource fails
        _cis_finding("Config.1", status="PASSED"),
    ]
    res = _result({"Findings": findings})
    # Two controls: S3.5 (fails) and Config.1 (passes) -> 50%.
    assert res["CIScompliancePercentage"] == 50, res
    assert res["totalFindings"] == 2, res


def test_cis_and_fsbp_scored_independently():
    """CIS and FSBP keys must reflect their own standard, not be aliases."""
    findings = [
        # CIS-only control that fails -> drags CIS down, not FSBP.
        _cis_finding("IAM.6", status="FAILED", workflow="NEW",
                     standards=("cis-aws-foundations-benchmark/v/1.4.0",)),
        # FSBP-only control that passes.
        _cis_finding("EC2.1", status="PASSED",
                     standards=("aws-foundational-security-best-practices/v/1.0.0",)),
    ]
    res = _result({"Findings": findings})
    assert res["CIScompliancePercentage"] == 0, res
    assert res["compliancePercentage"] == 100, res


def test_legacy_input_without_standards():
    """Inputs lacking AssociatedStandards fall back to standard-agnostic scoring."""
    findings = [
        {"Compliance": {"Status": "PASSED", "SecurityControlId": "X.1"}},
        {"Compliance": {"Status": "FAILED", "SecurityControlId": "X.2"}},
    ]
    res = _result({"Findings": findings})
    assert res["CIScompliancePercentage"] == 50, res
    assert res["compliancePercentage"] == 50, res


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:  # pragma: no cover
            failures += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
