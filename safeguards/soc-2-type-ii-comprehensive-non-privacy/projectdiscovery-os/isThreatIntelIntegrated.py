"""
Transformation: isThreatIntelIntegrated
Vendor: ProjectDiscovery OS  |  Category: soc-2-type-ii-comprehensive-non-privacy
Evaluates: Whether scan results contain threat intelligence data fields such as
           CVE IDs, CVSS metrics, EPSS percentile scores, and KEV tags.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isThreatIntelIntegrated", "vendor": "ProjectDiscovery OS", "category": "soc-2-type-ii-comprehensive-non-privacy"}
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


def evaluate(data):
    try:
        results = get_results_list(data)
        total_results = len(results)

        if total_results == 0:
            out = {}
            out["isThreatIntelIntegrated"] = False
            out["totalResultsChecked"] = 0
            out["resultsWithThreatIntel"] = 0
            out["scoreInPercentage"] = 0
            out["error"] = "No scan results found to evaluate threat intel integration"
            return out

        intel_count = 0
        cve_count = 0
        epss_count = 0
        kev_count = 0
        cvss_count = 0

        for finding in results:
            if not isinstance(finding, dict):
                continue
            info = finding.get("info", {})
            if not isinstance(info, dict):
                info = {}
            classification = info.get("classification", {})
            if not isinstance(classification, dict):
                classification = {}

            found_intel = False

            cve_ids = classification.get("cve-id", None)
            if cve_ids:
                has_cve = False
                if isinstance(cve_ids, list) and len(cve_ids) > 0:
                    has_cve = True
                elif isinstance(cve_ids, str) and cve_ids.strip():
                    has_cve = True
                if has_cve:
                    cve_count = cve_count + 1
                    found_intel = True

            cvss_val = classification.get("cvss-score", classification.get("cvss-metrics", None))
            if cvss_val is not None:
                cvss_count = cvss_count + 1
                found_intel = True

            epss_val = classification.get("epss-score", classification.get("epss-percentile", None))
            if epss_val is not None:
                epss_count = epss_count + 1
                found_intel = True

            tags = info.get("tags", "")
            if isinstance(tags, list):
                for tag in tags:
                    if str(tag).lower() in ["kev", "cisa-kev"]:
                        kev_count = kev_count + 1
                        found_intel = True
                        break
            elif isinstance(tags, str):
                if "kev" in tags.lower():
                    kev_count = kev_count + 1
                    found_intel = True

            if found_intel:
                intel_count = intel_count + 1

        score = 0
        if total_results > 0:
            score = int((intel_count * 100) / total_results)

        is_integrated = intel_count > 0

        out = {}
        out["isThreatIntelIntegrated"] = is_integrated
        out["totalResultsChecked"] = total_results
        out["resultsWithThreatIntel"] = intel_count
        out["scoreInPercentage"] = score
        out["resultsWithCveIds"] = cve_count
        out["resultsWithCvssData"] = cvss_count
        out["resultsWithEpssData"] = epss_count
        out["resultsWithKevTags"] = kev_count
        return out
    except Exception as e:
        out = {}
        out["isThreatIntelIntegrated"] = False
        out["error"] = str(e)
        return out


def transform(input):
    criteriaKey = "isThreatIntelIntegrated"
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
            pass_reasons.append("Findings with threat intel data: " + str(eval_result.get("resultsWithThreatIntel", 0)) + " of " + str(eval_result.get("totalResultsChecked", 0)))
            if eval_result.get("resultsWithCveIds", 0) > 0:
                additional_findings.append("CVE-linked findings: " + str(eval_result.get("resultsWithCveIds", 0)))
            if eval_result.get("resultsWithCvssData", 0) > 0:
                additional_findings.append("CVSS-scored findings: " + str(eval_result.get("resultsWithCvssData", 0)))
            if eval_result.get("resultsWithEpssData", 0) > 0:
                additional_findings.append("EPSS-enriched findings: " + str(eval_result.get("resultsWithEpssData", 0)))
            if eval_result.get("resultsWithKevTags", 0) > 0:
                additional_findings.append("KEV-tagged findings: " + str(eval_result.get("resultsWithKevTags", 0)))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure scans use Nuclei templates that map to CVE IDs, CVSS scores, and EPSS data")
            recommendations.append("Include community Nuclei templates from the nuclei-templates library which carry CVE classification metadata")

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
