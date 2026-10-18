"""Transformation: protectedDomainsCount - Fortinet FortiMail, method getProtectedDomains.

GET /api/v1/Domain/ lists the protected domains configured on the appliance. Fortinet's REST reference
documents the resource ("domain", protected domain settings) and the login; the list shape (a "collection"
array of entries with mkey, maindomain, is_subdomain, is_association, ...) is the one Fortinet's own
FortiSOAR connector documents for "Get Configured Domains".

Returns the number of protected domains: every entry of the collection that is not a domain association
(an association is an alias of another listed domain and protects nothing on its own).
None (not measured, dataCollection error) when the body is an error, an auth envelope, or has no
"collection" list. An empty collection is a measured 0: FortiMail answers 403, not an empty list,
to an administrator whose access profile cannot read domains.

Not proved: that mail for these domains is routed through the appliance, or that a restricted (per-domain)
administrator sees every domain.
"""
import json
from datetime import datetime


KEY = "protectedDomainsCount"
WRAPPERS = ["apiResponse", "api_response", "result", "response", "Output", "data"]
TRUE_WORDS = ["1", "true", "yes", "on", "enable", "enabled"]


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
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


def raw_body(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and "data" in input_data:
        return input_data.get("data")
    return input_data


def truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in TRUE_WORDS
    return False


def error_text(cur):
    """The error an Integration-Service envelope or FortiMail body reports, or None."""
    if cur.get("error") is True or cur.get("errorType"):
        return str(cur.get("message") or cur.get("errorType") or "error")[:300]
    for name in ["statusCode", "status_code"]:
        code = cur.get(name)
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "HTTP " + str(code)
    if isinstance(cur.get("error"), (dict, str)) and cur.get("error"):
        return json.dumps(cur.get("error"))[:300]
    return None


def find_collection(obj):
    """(entries, error) from the domain list body; (None, None) when no collection list is present."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if isinstance(cur.get("collection"), list):
            return cur.get("collection"), None
        problem = error_text(cur)
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


def not_measured(problem, validation):
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=["Not measured: " + problem],
        api_errors=[problem],
        metadata={"transformationId": KEY, "vendor": "Fortinet", "product": "FortiMail", "category": "Email Security"},
    )


def transform(input):
    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        validation = extract_validation(input)
        entries, error = find_collection(raw_body(input))
        if error is not None:
            return not_measured("FortiMail domain list returned an error: " + error, validation)
        if entries is None:
            return not_measured("No domain collection in the FortiMail response; nothing to count.", validation)
        domains = []
        associations = 0
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("mkey"):
                continue
            if truthy(entry.get("is_association")):
                associations = associations + 1
                continue
            domains.append(str(entry.get("mkey")))
        count = len(domains)
        if count > 0:
            passed = ["FortiMail protects " + str(count) + " domain(s)."]
            failed = []
        else:
            passed = []
            failed = ["No protected domain is configured on the FortiMail appliance."]
        return create_response(
            result={KEY: count, "domainAssociationCount": associations},
            validation=validation,
            pass_reasons=passed,
            fail_reasons=failed,
            recommendations=[] if count > 0 else ["Add the organisation's mail domains under Domain & User > Domain."],
            input_summary={"entries": len(entries), "protectedDomains": count, "associations": associations},
            metadata={"transformationId": KEY, "vendor": "Fortinet", "product": "FortiMail", "category": "Email Security"},
        )
    except Exception as e:
        return create_response(
            result={KEY: None},
            transformation_errors=[str(e)],
            api_errors=["Transformation error: " + str(e)],
            fail_reasons=["Not measured: transformation error"],
            metadata={"transformationId": KEY, "vendor": "Fortinet", "product": "FortiMail", "category": "Email Security"},
        )
