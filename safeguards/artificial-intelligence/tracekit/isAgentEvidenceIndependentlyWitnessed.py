"""
Transformation: isAgentEvidenceIndependentlyWitnessed
Vendor: Tracekit  |  Category: Artificial Intelligence

Criterion: every bundle's checkpoint was cosigned by enough witnesses the customer does not control, under the trust config Spektrum pinned: assurance witnessed or witnessed+monitored.

Data source: Spektrum's own verification of the customer's Tracekit evidence bundles (.tkb), not a vendor API.
The customer pushes the bundles their Tracekit signer exported; Integration-Service
(src/services/tracekit_evidence.py) runs `tracekit verify --json` (tracekit-ai 1.4.2) on each one against the trust
config Spektrum pinned when the customer connected, keeps a summary and discards the bundle. This transform reads
the summaries of the bundles in the evaluation window:
  {"truncated": false, "bundles": [{"bundleSha256", "verifiedAt", "verifierVersion", "exitCode",
                 "integrity": "verified" | "open" | "failed" | "unverifiable" | "unusable",
                 "assurance": "dev" | "local" | "witnessed" | "witnessed+monitored" | "none",
                 "isolation": {"same-user" | "separate-user" | "remote" | "unknown": runs}, "runCount",
                 "passedChecks": [...], "failedChecks": [...], "warningChecks": [...]}]}
Verifier vocabulary: https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md

Every criterion needs EVERY bundle in the window to have verified intact: a record that failed, could not be
verified, or belongs to a run that never closed shows nothing, so one such bundle makes the criterion false.
Fails closed: an error body, no bundles, a bundle summary missing a field, a verified summary with a non-zero exit
code, a failed or warning check name outside tracekit-ai 1.4.2's vocabulary, or a window not marked
"truncated": false (more failing bundles than Integration-Service returns) returns None (not measured).
  isAgentEvidenceIndependentlyWitnessed = true when every bundle verified intact with assurance
  witnessed or witnessed+monitored.
Spektrum's trust config classes any witness the customer runs as operator, so only a witness outside the customer's control lifts a run above local. Records after the last cosigned checkpoint are not covered by the witness.
"""
import json
from datetime import datetime

KEY = "isAgentEvidenceIndependentlyWitnessed"
VENDOR = "Tracekit"
CATEGORY = "Artificial Intelligence"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None}, validation=validation, api_errors=[reason], fail_reasons=[reason])


def is_error_body(data):
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors"):
        return True
    status = data.get("statusCode") or data.get("status_code") or data.get("status")
    if isinstance(status, int) and status >= 400:
        return True
    return False


def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        input = json.loads(input) if input.strip() else None
    return extract_input(input)


INTEGRITY_VALUES = ["verified", "open", "failed", "unverifiable", "unusable"]
# Every line tracekit-ai 1.4.2's v2 verifier can report (tracekit/verify/v2.py). A failed or
# warning line outside it comes from a verifier these criteria were not written against.
KNOWN_CHECKS = ["approvals by agents", "approvals by people", "args source", "break-glass approvals",
                "bundle readable", "bundle structure", "checkpoint", "constraints", "content vault",
                "coverage", "coverage matrix", "external decisions", "fail-open classes", "findings",
                "findings counted", "format bridge", "gaps", "gateway amendments", "harness", "held calls",
                "incident policies", "incidents", "inclusion", "isolation", "key assurance", "keys",
                "log tail", "manifest", "monitor", "not interpreted", "observers", "openshell policy",
                "policy", "policy snapshot", "principals", "rekor anchor", "replay runs", "reviews",
                "reviews counted", "revocations", "run chain", "run parts", "run-set", "signatures",
                "tenant-level gaps", "tiers", "trust config", "witness quorum"]
ASSURANCE_VALUES = ["dev", "local", "witnessed", "witnessed+monitored", "none"]


def as_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def bundle_summary(item):
    """A well-formed bundle summary, or None."""
    if not isinstance(item, dict):
        return None
    integrity = item.get("integrity")
    assurance = item.get("assurance")
    isolation = item.get("isolation")
    runs = as_count(item.get("runCount"))
    exit_code = as_count(item.get("exitCode"))
    passed = item.get("passedChecks")
    failed = item.get("failedChecks")
    warned = item.get("warningChecks")
    if integrity not in INTEGRITY_VALUES or assurance not in ASSURANCE_VALUES or runs is None:
        return None
    if exit_code is None or (integrity in ["verified", "open"] and exit_code != 0):
        return None
    for names in [passed, failed, warned]:
        if not isinstance(names, list):
            return None
    for name in failed + warned:
        if name not in KNOWN_CHECKS:
            return None
    if not isinstance(isolation, dict):
        return None
    counts = {}
    for label in isolation:
        n = as_count(isolation[label])
        if n is None:
            return None
        counts[str(label)] = n
    if sum(counts.values()) != runs:
        return None
    return {"integrity": integrity, "assurance": assurance, "isolation": counts, "runCount": runs,
            "passedChecks": [str(c) for c in passed], "failedChecks": [str(c) for c in failed],
            "warningChecks": [str(c) for c in warned]}


def bundles_of(data):
    if not isinstance(data, dict) or not isinstance(data.get("bundles"), list):
        return None
    out = []
    for item in data["bundles"]:
        summary = bundle_summary(item)
        if summary is None:
            return None
        out.append(summary)
    return out


def intact(bundle):
    return bundle["integrity"] == "verified" and not bundle["failedChecks"] and bundle["runCount"] > 0


WITNESSED = ["witnessed", "witnessed+monitored"]


def meets(bundle):
    return bundle["assurance"] in WITNESSED


MEETS_TEXT = "were cosigned by an independent witness"
RECOMMENDATION = (
    "Have each checkpoint cosigned by a witness outside your control (Spektrum's, or a public one) and "
    "export runs after the next checkpoint."
)


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("The Tracekit evidence summary returned an error", validation)
        if isinstance(data, dict) and data.get("truncated", False) is not False:
            return not_measured("More failing Tracekit bundles were received than the window holds", validation)
        bundles = bundles_of(data)
        if bundles is None:
            return not_measured("No well-formed Tracekit bundle summaries were provided", validation)
        if not bundles:
            return not_measured("No Tracekit evidence bundles were received in the evaluation window", validation)
        runs = 0
        intact_count = 0
        meeting = 0
        for bundle in bundles:
            runs = runs + bundle["runCount"]
            if intact(bundle):
                intact_count = intact_count + 1
                if meets(bundle):
                    meeting = meeting + 1
        passed = meeting == len(bundles)
        result = {KEY: passed, "bundleCount": len(bundles), "verifiedBundleCount": intact_count,
                  "runCount": runs}
        summary = {"bundleCount": len(bundles), "verifiedBundleCount": intact_count, "meetingBundleCount": meeting,
                   "runCount": runs}
        line = (str(meeting) + " of " + str(len(bundles)) + " Tracekit evidence bundles (" + str(runs)
                + " agent runs) " + MEETS_TEXT + "; " + str(intact_count) + " verified intact")
        if passed:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=summary)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=summary,
                               recommendations=[RECOMMENDATION])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
