"""
Transformation: hardenedBaselineCompliance
Vendor: Microsoft Defender for Endpoint  |  Category: Endpoint Security
Evaluates: Impact-weighted security baseline compliance across all endpoints.

Data source: MDE Advanced Hunting API
  - POST /api/advancedqueries/run
  - Query: DeviceTvmSecureConfigurationAssessment joined with KB table
  - Computes per-device impact-weighted compliance, then aggregates fleet-wide

The query evaluates ~38 curated baseline SCIDs across these categories:
  - EDR Sensor (scid-2000, 2001, 2002)
  - Antivirus (scid-2010, 2011, 2012, 2013, 2014, 2016, 90, 92, 89)
  - Firewall (scid-2070, 2071, 2072, 2073)
  - Credential Guard (scid-2080)
  - BitLocker (scid-2090)
  - Network Protection (scid-96)
  - LSA Protection (scid-25)
  - Controlled Folder Access (scid-2021)
  - ASR Rules (scid-2500 through 2515)

Returns:
  - AvgWeightedScore: fleet-wide average (0-100), weighted by SCID impact
  - MedianScore: median device score
  - DevicesAbove80: count of devices meeting 80%+ compliance
  - DevicesBelow50: count of devices critically below baseline

The hardenedBaselineCompliance value is the AvgWeightedScore rounded to
the nearest integer. A passing threshold of 70 is applied — above 70 means
the fleet's hardened baseline is in acceptable posture.
"""
import json
from datetime import datetime

PASS_THRESHOLD = 70


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "hardenedBaselineCompliance", "vendor": "Microsoft Defender for Endpoint", "category": "Endpoint Security"}
        }
    }


def safe_float(val, default=0.0):
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def safe_int(val, default=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def extract_query_results(data):
    """Extract Advanced Hunting query results from various response shapes."""
    # Standard AH response: { "Results": [...] }
    if isinstance(data, dict):
        results = data.get("Results", data.get("results", []))
        if isinstance(results, list) and results:
            return results
        # Nested in Schema/Results structure
        if "Schema" in data and "Results" in data:
            return data["Results"] if isinstance(data["Results"], list) else []
    if isinstance(data, list) and data:
        return data
    return []


def evaluate(data):
    """Evaluate fleet-wide hardened baseline compliance from AH query results."""
    try:
        results = extract_query_results(data)

        if not results:
            return {"hardenedBaselineCompliance": "0", "error": "No results returned from baseline compliance query"}

        # The query returns a single summary row with aggregate fields
        row = results[0] if isinstance(results, list) else results

        if not isinstance(row, dict):
            return {"hardenedBaselineCompliance": "0", "error": "Unexpected result format"}

        avg_score = safe_float(row.get("AvgWeightedScore", 0))
        median_score = safe_float(row.get("MedianScore", 0))
        min_score = safe_float(row.get("MinScore", 0))
        max_score = safe_float(row.get("MaxScore", 0))
        devices_above_80 = safe_int(row.get("DevicesAbove80", 0))
        devices_below_50 = safe_int(row.get("DevicesBelow50", 0))
        total_devices = safe_int(row.get("TotalDevices", 0))
        avg_compliant = safe_int(row.get("AvgCompliantChecks", 0))
        avg_total = safe_int(row.get("AvgTotalChecks", 0))

        compliance_score = round(avg_score)
        meets_baseline = compliance_score >= PASS_THRESHOLD

        above_80_pct = round(devices_above_80 * 100.0 / total_devices, 1) if total_devices > 0 else 0
        below_50_pct = round(devices_below_50 * 100.0 / total_devices, 1) if total_devices > 0 else 0

        findings = []
        findings.append(f"Fleet average baseline score: {avg_score}% (threshold: {PASS_THRESHOLD}%)")
        findings.append(f"Median device score: {median_score}%, range: {min_score}% - {max_score}%")
        findings.append(f"{devices_above_80}/{total_devices} devices ({above_80_pct}%) score above 80%")
        if devices_below_50 > 0:
            findings.append(f"{devices_below_50}/{total_devices} devices ({below_50_pct}%) are critically below 50%")
        findings.append(f"Average {avg_compliant}/{avg_total} baseline checks compliant per device")

        return {
            "hardenedBaselineCompliance": str(compliance_score),
            "meetsBaseline": meets_baseline,
            "avgWeightedScore": avg_score,
            "medianScore": median_score,
            "minScore": min_score,
            "maxScore": max_score,
            "devicesAbove80Pct": devices_above_80,
            "devicesBelow50Pct": devices_below_50,
            "totalDevices": total_devices,
            "avgCompliantChecks": avg_compliant,
            "avgTotalChecks": avg_total,
            "passThreshold": PASS_THRESHOLD,
            "findings": findings
        }
    except Exception as e:
        return {"hardenedBaselineCompliance": "0", "error": str(e)}


def transform(input):
    criteriaKey = "hardenedBaselineCompliance"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, "0")
        meets_baseline = eval_result.get("meetsBaseline", False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error" and k != "meetsBaseline"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if meets_baseline:
            pass_reasons.append(f"{criteriaKey} check passed — fleet score {result_value}% meets {PASS_THRESHOLD}% threshold")
            avg = eval_result.get("avgWeightedScore", 0)
            total = eval_result.get("totalDevices", 0)
            above80 = eval_result.get("devicesAbove80Pct", 0)
            pass_reasons.append(f"{above80}/{total} devices score above 80% compliance")
            median = eval_result.get("medianScore", 0)
            pass_reasons.append(f"Median device score: {median}%")
        else:
            fail_reasons.append(f"{criteriaKey} check failed — fleet score {result_value}% below {PASS_THRESHOLD}% threshold")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            below50 = eval_result.get("devicesBelow50Pct", 0)
            if below50 > 0:
                total = eval_result.get("totalDevices", 0)
                fail_reasons.append(f"{below50}/{total} devices are critically below 50% baseline compliance")
            min_score = eval_result.get("minScore", 0)
            fail_reasons.append(f"Lowest device score: {min_score}%")
            recommendations.append("Review per-SCID compliance using the getBaselineComplianceBySCID endpoint to identify the weakest controls")
            recommendations.append("Prioritize Tier 1 SCIDs: EDR sensor (2000-2002), antivirus (2010-2013), firewall profiles (2070-2073), BitLocker (2090)")
            recommendations.append("Enable Attack Surface Reduction rules (scid-2500 through 2515) across all managed devices")
            recommendations.append("Use the getBaselineComplianceByDevice endpoint to identify the lowest-scoring devices for targeted remediation")

        return create_response(
            result={criteriaKey: result_value, "meetsBaseline": meets_baseline, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "meetsBaseline": meets_baseline, "totalDevices": extra_fields.get("totalDevices", 0), "avgWeightedScore": extra_fields.get("avgWeightedScore", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: "0"},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
