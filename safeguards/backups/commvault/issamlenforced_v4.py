"""Transformation: issamlenforced_v4 - Commvault (Command Center REST API). Not measured (None) on any body that proves nothing."""
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


VENDOR = "Commvault"


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )


def commvault_error(cur):
    """Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
    if not isinstance(cur, dict):
        return None
    code = cur.get("errorCode")
    if code not in (None, 0, "0"):
        return "Commvault error " + str(code) + ": " + str(cur.get("errorMessage") or cur.get("errorString") or "")[:200]
    errs = cur.get("errList")
    if isinstance(errs, list) and len(errs) > 0:
        return "Commvault errList: " + json.dumps(errs[0])[:200]
    err = cur.get("error")
    if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
        return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")[:200]
    return None


def commvault_box(input, wanted):
    """(container, problem): the dict carrying `wanted` through IS wrappers, or why there is none."""
    body = raw_body(input)
    if isinstance(body, str):
        text = body.strip()
        if text.startswith("<"):
            return None, "Commvault answered with HTML or XML, not JSON (the method must send Accept: application/json)."
    box, problem = find_key(body, wanted)
    if problem is not None:
        return None, problem
    if box is None:
        return None, None
    problem = commvault_error(box)
    if problem is not None:
        return None, problem
    return box, None


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def truthy(value):
    if isinstance(value, bool):
        return value
    n = as_int(value)
    if n is not None:
        return n != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "enabled")
    return False


# Method: getSAMLEnforcement (workflow)
#   1. GET {serverUrl}/V4/IdentityServers -> identityServers[] {id, name, type (SAML, ACTIVE_DIRECTORY, ...), configured}
#   2. GET {serverUrl}/V4/SAML/{name} per identity server, collected under samlApps[]:
#      {name, enabled, associations: {emailSuffixes[], domains[], companies[], userGroups[]}}
# Spec: Commvault's published V4 OpenAPI 3 document (github.com/Commvault/CVPowershellSDKV2, OpenAPI3.yaml):
#   operations GetIdentityServers and GetSAMLApp, schemas IdentityServer, SAML, SAMLAssociations.
#
# isSAMLEnforced = True when an ENABLED SAML app is associated with users (email suffixes, domains,
# companies or user groups), so those users are sent to the identity provider at login. A SAML app
# with no associations redirects nobody and does not count. False when the identity servers were read
# and no enabled, associated SAML app exists (including no SAML server at all).
# None on a missing, partial or error read.


def associated(app):
    assoc = app.get("associations")
    if not isinstance(assoc, dict):
        return []
    found = []
    for field in ["emailSuffixes", "domains", "companies", "userGroups"]:
        value = assoc.get(field)
        if isinstance(value, list) and len(value) > 0:
            found.append(field)
    return found


def transform(input):
    key = "isSAMLEnforced"
    validation = extract_validation(input)
    box, problem = commvault_box(input, "identityServers")
    if problem is not None:
        return not_measured(key, "Commvault returned an error instead of the identity servers: " + problem, validation)
    if box is None or not isinstance(box.get("identityServers"), list):
        return not_measured(key, "No Commvault identity server list in the response; nothing to evaluate.", validation)
    servers = [s for s in box.get("identityServers") if isinstance(s, dict)]
    saml = [s for s in servers if str(s.get("type") or "").upper() == "SAML"]
    apps = box.get("samlApps")
    if saml and not isinstance(apps, list):
        return not_measured(key, "SAML identity servers are listed but their SAML app details were not read.", validation)
    apps = [a for a in (apps or []) if isinstance(a, dict)]
    for app in apps:
        problem = commvault_error(app)
        if problem is not None:
            return not_measured(key, "A SAML app detail read failed: " + problem, validation)
    names = [str(s.get("name")) for s in saml]
    detailed = [a for a in apps if str(a.get("name")) in names]
    if len(detailed) < len(saml):
        return not_measured(key, "Read " + str(len(detailed)) + " SAML app details for " + str(len(saml)) + " SAML identity servers; a partial read is not scored.", validation)
    enforcing = []
    for app in detailed:
        if app.get("enabled") is True and associated(app):
            enforcing.append(str(app.get("name")) + " (" + ", ".join(associated(app)) + ")")
    ok = len(enforcing) > 0
    if ok:
        text = "Enabled SAML app(s) with user associations: " + "; ".join(enforcing[:10]) + "."
    elif not saml:
        text = "No SAML identity server is configured in the CommCell (" + str(len(servers)) + " identity servers)."
    else:
        text = "No SAML app is both enabled and associated with users (" + str(len(saml)) + " SAML identity servers)."
    return create_response(
        result={key: ok, "samlServers": len(saml), "enforcingApps": len(enforcing)},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text],
        recommendations=[] if ok else ["Enable a SAML app in Command Center (Manage > Security > Identity servers) and associate it with your users' email suffixes, domains or user groups."],
        input_summary={"identityServers": len(servers), "samlServers": names[:25]},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )
