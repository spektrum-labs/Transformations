"""Transformation: expiredPackageLicensesCount - Salesforce, REST query on PackageLicense
(SELECT Id, NamespacePrefix, Status, ExpirationDate, AllowedLicenses, UsedLicenses FROM PackageLicense).

Counts installed package licences whose Status is Expired. An expired package licence leaves an installed app
unlicensed and unsupported. Measured only on a complete query result; an org with no package licence reads as zero.
The count is reported only when every record carried a Status, else not measured (None): a count beside a missing Status
is only a lower bound.
"""
import json
from datetime import datetime


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
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


WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode") or cur.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the pagination block stays visible and a partial read is caught.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def parse_time(text):
    """Naive-UTC datetime from an ISO-8601 string, or None."""
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        return datetime.fromisoformat(text[:19])
    except Exception:
        return None


def pct(part, whole):
    return round(100.0 * part / whole, 2) if whole else None


VENDOR = "Salesforce"


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "partner"},
    )


def complete_records(input, sobject):
    """(records, None) for a complete Tooling API query result, else (None, problem).

    Complete means: Salesforce's query envelope (records + totalSize + done) with done true and
    every record present, each typed as `sobject` in attributes.type.
    """
    box, problem = find_key(raw_body(input), "records")
    if problem is not None:
        return None, "Salesforce returned an error instead of a query result: " + problem
    if box is None or not isinstance(box.get("records"), list):
        return None, "No Salesforce query result in the response; nothing to evaluate."
    total = box.get("totalSize")
    if isinstance(total, bool) or not isinstance(total, int) or box.get("done") is not True:
        return None, "The query result has no totalSize or is not done (more records remain); a partial read is not scored."
    records = [r for r in box["records"] if isinstance(r, dict)]
    if len(records) < total:
        return None, "Read " + str(len(records)) + " of " + str(total) + " records; a partial read is not scored."
    for r in records:
        attrs = r.get("attributes") if isinstance(r.get("attributes"), dict) else {}
        if attrs.get("type") not in (None, sobject):
            return None, "The query returned " + str(attrs.get("type")) + " records, not " + sobject + "."
    return records, None


def transform(input):
    key = "expiredPackageLicensesCount"
    validation = extract_validation(input)
    records, problem = complete_records(input, "PackageLicense")
    if problem is not None:
        return not_measured(key, problem, validation)
    expired = []
    unknown = 0
    for r in records:
        status = str(r.get("Status") or "").strip().lower()
        if status == "":
            unknown = unknown + 1
        elif status == "expired":
            expired.append(r)
    if unknown > 0:
        # a count beside licences with no Status is only a lower bound, and an inclusive lessThan would pass on it
        return not_measured(key, str(unknown) + " package licence(s) carry no Status, so the count of expired packages (at least "
                            + str(len(expired)) + ") cannot be shown exactly.", validation)
    names = [str(r.get("NamespacePrefix") or r.get("Id") or "unnamed") for r in expired][:25]
    text = str(len(expired)) + " of " + str(len(records)) + " installed package licences are expired."
    return create_response(
        result={key: len(expired), "packageLicensesRead": len(records), "expiredPackages": names},
        validation=validation,
        pass_reasons=[text] if not expired else [],
        fail_reasons=[text] if expired else [],
        recommendations=["Renew or uninstall the expired packages (Setup > Installed Packages)."] if expired else [],
        input_summary={"packageLicensesRead": len(records), "expired": len(expired)},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "partner"},
    )
