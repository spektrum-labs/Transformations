import json
from datetime import datetime, timedelta


def extract_input(input_data):
    """Extract (data, validation) from either the enriched or the legacy input format."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Build the standard 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
        "vendor": "Cisco Umbrella",
        "category": "Network Security",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def as_list(data, item_key="items"):
    """Return the list of records regardless of how far the platform unwrapped the response.

    Token-Service walks response/result/apiResponse/Output/data before the transform runs,
    so a {"data": [...]} envelope can arrive already reduced to a bare list.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in (item_key, "items", "data", "records"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


CRITERIA_KEY = "maliciousDomainBlockRate"

# Umbrella tags each reporting category with a type; "security" marks the threat
# categories. Two security categories are advisory rather than confirmed-malicious
# and are commonly allowed on purpose, so counting them would understate a
# correctly configured estate.
ADVISORY_CATEGORIES = ("dynamicdns", "newlyseendomains")


def normalise(value):
    return str(value or "").strip().lower().replace(" ", "").replace("-", "").replace("_", "")


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        data, validation = extract_input(input)
        rows = as_list(data)
        rows = [r for r in rows if isinstance(r, dict)]

        threat_rows, advisory_rows = [], []
        for row in rows:
            category = row.get("category") or {}
            if not isinstance(category, dict):
                continue
            if normalise(category.get("type")) != "security":
                continue
            if normalise(category.get("label")) in ADVISORY_CATEGORIES:
                advisory_rows.append(row)
            else:
                threat_rows.append(row)

        requests = 0
        blocked = 0
        breakdown = []
        for row in threat_rows:
            summary = row.get("summary") or {}
            row_requests = summary.get("requests") or 0
            row_blocked = summary.get("requestsblocked") or 0
            requests += row_requests
            blocked += row_blocked
            breakdown.append({
                "category": (row.get("category") or {}).get("label"),
                "requests": row_requests,
                "blocked": row_blocked,
            })

        rate = round(blocked / requests * 100, 2) if requests else 0.0

        result = {
            CRITERIA_KEY: rate,
            "threatRequests": requests,
            "threatRequestsBlocked": blocked,
            "threatRequestsAllowed": requests - blocked,
            "threatCategoriesEvaluated": len(threat_rows),
            "advisoryCategoriesExcluded": len(advisory_rows),
            "categoryBreakdown": breakdown,
        }

        pass_reasons, fail_reasons, recommendations = [], [], []
        if not threat_rows:
            fail_reasons.append(
                "No security-type categories were present in the DNS category summary, so the "
                "malicious-domain block rate could not be computed. This usually means the "
                "request limit truncated the category list before the low-volume threat "
                "categories were reached.")
            recommendations.append(
                "Confirm the summaries-by-category request uses a large enough limit to "
                "include security-type categories.")
        elif requests == 0:
            pass_reasons.append(
                "No DNS requests to malicious categories were observed in the reporting "
                "window across %d threat category/categories." % len(threat_rows))
            result[CRITERIA_KEY] = 100.0
        elif blocked >= requests:
            pass_reasons.append(
                "All %d DNS request(s) to malicious categories were blocked (100%%) across "
                "%d threat category/categories." % (requests, len(threat_rows)))
        else:
            leaked = [b for b in breakdown if b["requests"] > b["blocked"]]
            fail_reasons.append(
                "%d of %d DNS request(s) to malicious categories were blocked (%.2f%%); "
                "%d request(s) to known-malicious destinations were allowed through."
                % (blocked, requests, rate, requests - blocked))
            for item in leaked[:5]:
                fail_reasons.append(
                    "%s: %d request(s), %d blocked"
                    % (item["category"], item["requests"], item["blocked"]))
            recommendations.append(
                "Review the Umbrella policy for the categories above so all confirmed-malicious "
                "traffic is blocked rather than allowed.")

        findings = []
        for row in advisory_rows:
            summary = row.get("summary") or {}
            findings.append(
                "Advisory category '%s' excluded from the rate: %s request(s), %s blocked."
                % ((row.get("category") or {}).get("label"),
                   summary.get("requests"), summary.get("requestsblocked")))

        return create_response(
            result=result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"threatRequests": requests, "threatRequestsBlocked": blocked},
            additional_findings=findings,
            metadata={"transformationId": CRITERIA_KEY})
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: 0.0}, transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % e],
            metadata={"transformationId": CRITERIA_KEY})
