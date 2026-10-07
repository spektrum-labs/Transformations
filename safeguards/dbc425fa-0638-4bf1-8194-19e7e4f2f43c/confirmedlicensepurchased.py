"""
Transformation: confirmedLicensePurchased
Vendor: Google Workspace
Category: Email Security

Evidence (either shape; the definition decides which it sends):
  * getWorkspaceLicenses (current): Enterprise License Manager
      GET https://licensing.googleapis.com/apps/licensing/v1/product/Google-Apps/users?customerId=...
    scope https://www.googleapis.com/auth/apps.licensing. Body: {"items": [{"productId", "skuId",
    "skuName", "userId"}], "nextPageToken"}.
  * getLicenseStatus (previous): Cloud Identity gmail.* policies, as
      {"licensePurchased": <policies[0] as bool>, "policies": {"policies": [...]}}.

Rule (fail closed):
  * Licensing shape: true when at least one assignment has productId "Google-Apps" (Google
    Workspace). An empty list fails. SKU names and counts are reported; user identities never are.
  * Policy shape (PROXY, weaker): true only when a returned policy's policyQuery names a
    Google Workspace licence ('/product/Google-Apps/sku/...'), i.e. Google scopes a Gmail
    setting to a Workspace SKU the tenant holds. "Some Gmail policy exists" no longer passes.
  * A Google error, a missing scope ("scope not granted") or an unreadable body is a
    data-collection error (unevaluated), never a pass.
"""

import json
import re
from datetime import datetime, timezone

CRITERIA_KEY = "confirmedLicensePurchased"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/apps.licensing"
POLICY_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
WORKSPACE_PRODUCT = "Google-Apps"
SKU_NAMES = {
    "1010020027": "Business Starter", "1010020028": "Business Standard", "1010020025": "Business Plus",
    "1010020026": "Enterprise Standard", "1010020020": "Enterprise Plus", "1010020029": "Enterprise Starter",
    "1010060003": "Enterprise Essentials", "1010020030": "Frontline Starter", "1010020031": "Frontline Standard",
    "1010020034": "Frontline Plus", "1010070001": "Education Fundamentals", "1010310005": "Education Standard",
    "1010310008": "Education Plus",
}


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "Google Workspace",
                "category": "Email Security"
            }
        }
    }


SCOPE_HINTS = ["scope_not_granted", "access_denied", "unauthorized_client",
               "insufficient authentication scopes", "access_token_scope_insufficient",
               "request had insufficient authentication"]


def error_text(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if data is None:
        return "No response body"
    if isinstance(data, str):
        return "Empty response body" if data.strip() == "" else ""
    if not isinstance(data, dict):
        return ""
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return " ".join(str(x) for x in [value.get("code") or "", value.get("status") or "",
                                             value.get("message") or ""] if x) or str(value)
        parts = [str(x) for x in [data.get("message"), data.get("vendorAuthError"),
                                  data.get("error_description")] if x]
        return " ".join(parts) if parts else str(value)
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s %s" % (code, data.get("message") or "")
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return ""


def vendor_error(data):
    """A clear reason when the body is an error, else None. A missing scope in the customer's
    domain-wide delegation grant is named as such, never read as a finding."""
    text = error_text(data)
    if not text:
        return None
    low = text.lower()
    if "missing_credentials" in low:
        return "Google Workspace admin email (subject) is not connected"
    for hint in SCOPE_HINTS:
        if hint in low:
            return ("scope not granted: add %s to Spektrum's domain-wide delegation grant "
                    "(client ID 117073617964097263607) in the Google Admin console. Google said: %s"
                    % (REQUIRED_SCOPE, text[:240]))
    if "service_disabled" in low or "has not been used in project" in low:
        return "Google API not enabled for Spektrum's service account project: %s" % text[:240]
    return text[:300]


def is_true(value):
    """Google bodies reach us with booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def parse_time(value):
    if value is None or str(value).strip() == "":
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def find_dict_with(data, key, depth=0):
    """The first dict (breadth-first through dict values, depth-limited) that has `key`."""
    frontier = [data]
    for level in range(5):
        next_frontier = []
        for node in frontier:
            if isinstance(node, dict):
                if key in node:
                    return node
                for value in node.values():
                    if isinstance(value, dict):
                        next_frontier.append(value)
        frontier = next_frontier
    return None


def not_measured(reason, validation, recommendation=None, result_extra=None):
    result = {CRITERIA_KEY: False}
    for k in (result_extra or {}):
        result[k] = result_extra[k]
    return create_response(
        result=result,
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        recommendations=[recommendation] if recommendation else []
    )


def evaluate_licensing(body, validation):
    items = body.get("items") or []
    if not isinstance(items, list):
        return not_measured("licence assignment list could not be read", validation)
    counts = {}
    for item in items:
        if not isinstance(item, dict) or item.get("productId") != WORKSPACE_PRODUCT:
            continue
        sku = str(item.get("skuId") or "")
        name = str(item.get("skuName") or SKU_NAMES.get(sku) or sku or "unknown SKU")
        counts[name] = counts.get(name, 0) + 1
    total = sum(counts.values())
    summary = {"workspaceAssignments": total, "skus": counts, "morePages": bool(body.get("nextPageToken"))}
    if total > 0:
        listed = ", ".join("%s x%d%s" % (k, counts[k], "+" if summary["morePages"] else "") for k in sorted(counts))
        return create_response(result={CRITERIA_KEY: True, "workspaceAssignments": total}, validation=validation,
                               pass_reasons=["Google Workspace licences are assigned: %s" % listed],
                               input_summary=summary)
    return create_response(result={CRITERIA_KEY: False, "workspaceAssignments": 0}, validation=validation,
                           fail_reasons=["No Google Workspace (Google-Apps) licence assignments were returned"],
                           recommendations=["Confirm the tenant holds a Google Workspace subscription and licences are assigned"],
                           input_summary=summary)


def evaluate_policy_proxy(data, validation):
    policies_body = data.get("policies")
    if isinstance(policies_body, dict):
        error = vendor_error(policies_body)
        if error is not None:
            return not_measured(error.replace(REQUIRED_SCOPE, POLICY_SCOPE), validation)
        policies = policies_body.get("policies") or []
    elif isinstance(policies_body, list):
        policies = policies_body
    else:
        return not_measured("policy list was not returned", validation)
    skus = {}
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
        for sku in re.findall(r"/product/Google-Apps/sku/([0-9]+)", str(query.get("query") or "")):
            skus[sku] = SKU_NAMES.get(sku, sku)
    summary = {"policies": len(policies), "workspaceSkus": sorted(skus.values()), "evidence": "policy proxy"}
    if skus:
        return create_response(result={CRITERIA_KEY: True}, validation=validation,
                               pass_reasons=["PROXY: Gmail policies are scoped to Google Workspace licence(s) %s held by the tenant" % ", ".join(sorted(skus.values()))],
                               recommendations=["Grant apps.licensing so the licence is read from the Licensing API directly"],
                               input_summary=summary)
    return create_response(result={CRITERIA_KEY: False}, validation=validation,
                           fail_reasons=["PROXY: no returned Gmail policy names a Google Workspace licence (%d policies)" % len(policies)],
                           recommendations=["Grant apps.licensing so the licence is read from the Licensing API directly"],
                           input_summary=summary)


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if isinstance(data, dict) and "result" in data and isinstance(data.get("result"), (dict, list)):
            data = data["result"]

        error = vendor_error(data)
        if error is not None:
            return not_measured(error, validation, "Check Spektrum's domain-wide delegation grant and re-evaluate")
        if not isinstance(data, dict):
            return not_measured("licence response could not be read", validation)
        licensing = data if str(data.get("kind", "")).startswith("licensing#") or "items" in data else find_dict_with(data, "items")
        if isinstance(licensing, dict) and (str(licensing.get("kind", "")).startswith("licensing#") or "items" in licensing):
            return evaluate_licensing(licensing, validation)
        if "policies" in data:
            return evaluate_policy_proxy(data, validation)
        if str(data.get("kind", "")).startswith("licensing#"):
            return evaluate_licensing(data, validation)
        return not_measured("response is neither a Licensing API list nor the policy proxy", validation)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
