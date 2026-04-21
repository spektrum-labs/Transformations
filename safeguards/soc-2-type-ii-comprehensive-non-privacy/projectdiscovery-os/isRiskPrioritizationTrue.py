"""
Transformation: isRiskPrioritizationTrue
Vendor: ProjectDiscovery OS  |  Category: soc-2-type-ii-comprehensive-non-privacy
Evaluates: Whether vulnerability scan findings include CVSS score and EPSS score
           metadata, confirming that risk-based prioritization of vulnerabilities
           is active across scan results.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_iter in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRiskPrioritizationTrue", "vendor": "ProjectDiscovery OS", "category": "soc-2-type-ii-comprehensive-non-privacy"}
        }
    }


def get_results_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def safe_float(val):
    if val is None:
        return None
    try:
        return float(val)
    except Exception:
        return None


def evaluate(data):
    try:
        results = get_results_list(data)
        total_results = len(results)

        if total_results == 0:
            out = {}
            out["isRiskPrioritizationTrue"] = False
            out["totalResultsChecked"] = 0
            out["resultsWithCvss"] = 0
            out["resultsWithEpss"] = 0
            out["resultsWithBothScores"] = 0
            out["scoreInPercentage"] = 0
            out["error"] = "No scan results found to evaluate risk prioritization"
            return out

        cvss_count = 0
        epss_count = 0
        both_count = 0
        severity_counts = {}

        for finding in results:
            if not isinstance(finding, dict):
                continue
            info = finding.get("info", {})
            if not isinstance(info, dict):
                info = {}
            classification = info.get("classification", {})
            if not isinstance(classification, dict):
                classification = {}

            has_cvss = False
            has_epss = False

            cvss_score = safe_float(classification.get("cvss-score", None))
            if cvss_score is not None:
                has_cvss = True

            cvss_metrics = classification.get("cvss-metrics", None)
            if cvss_metrics:
                has_cvss = True

            epss_val = safe_float(classification.get("epss-score", classification.get("epss-percentile", None)))
            if epss_val is not None:
                has_epss = True

            if has_cvss:
                cvss_count = cvss_count + 1
            if has_epss:
                epss_count = epss_count + 1
            if has_cvss and has_epss:
                both_count = both_count + 1

            severity = str(info.get("severity", "unknown")).lower()
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] = severity_counts[severity] + 1

        prioritized_count = cvss_count if cvss_count >= epss_count else epss_count
        score = 0
        if total_results > 0:
            score = int((prioritized_count * 100) / total_results)

        is_prioritized = prioritized_count > 0

        out = {}
        out["isRiskPrioritizationTrue"] = is_prioritized
        out["totalResultsChecked"] = total_results
        out["resultsWithCvss"] = cvss_count
        out["resultsWithEpss"] = epss_count
        out["resultsWithBothScores"] = both_count
        out["scoreInPercentage"] = score
        out["severityBreakdown"] = severity_counts
        return out
    except Exception as e:
        out = {}
        out["isRiskPrioritizationTrue"] = False
        out["error"] = str(e)
        return out


def transform(input):
    criteriaKey = "isRiskPrioritizationTrue"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            pass_reasons.append("Results with CVSS score: " + str(eval_result.get("resultsWithCvss", 0)))
            pass_reasons.append("Results with EPSS score: " + str(eval_result.get("resultsWithEpss", 0)))
            pass_reasons.append("Coverage score: " + str(eval_result.get("scoreInPercentage", 0)) + "%")
            sev = eval_result.get("severityBreakdown", {})
            if sev:
                for sev_key in sev:
                    additional_findings.append(sev_key + " severity findings: " + str(sev[sev_key]))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Use Nuclei templates that include CVE classifications with CVSS and EPSS metadata for risk-based prioritization")
            recommendations.append("Enable vulnerability prioritization features in ProjectDiscovery Cloud Platform settings")

        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=result_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
