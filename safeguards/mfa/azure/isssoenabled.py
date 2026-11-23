"""
Transformation: isSSOEnabled
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management
API: GET https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,appDisplayName,servicePrincipalType,
     preferredSingleSignOnMode,accountEnabled&$top=999   (Application.Read.All or Directory.Read.All)
Docs: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list
      https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal
      (preferredSingleSignOnMode: "password", "saml", "notSupported" or "oidc"; null when not configured)

Question (CIS 5.6 / 6.7): is Entra ID actually used as the single sign-on provider for enterprise applications?

Counted: enabled service principals (accountEnabled is not false) whose preferredSingleSignOnMode is "saml"
or "oidc" (federated single sign-on). Password-vaulted ("password") apps are reported separately and not
counted, because the user still holds a per-app password.
Caveat: an OIDC app registered without preferredSingleSignOnMode set is not counted, so a FAIL means no
SAML/OIDC-flagged enterprise app exists; open the evidence before treating it as a finding.

Output (numbers first): ssoApplicationCount, samlApplicationCount, oidcApplicationCount,
passwordSsoApplicationCount, servicePrincipalCount; isSSOEnabled = ssoApplicationCount >= 1.

Fails closed (None with dataCollection.status "error"): an error body, a body that is not a service principal
collection, an empty list (every tenant has service principals, so empty proves nothing), or a partial page
(@odata.nextLink) on which no SSO application was found.
"""
import json
from datetime import datetime

KEY = "isSSOEnabled"
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data"]


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "azure_isssoenabled",
                         "vendor": "Microsoft Entra ID", "category": "Identity and Access Management"},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None, "ssoApplicationCount": None}, validation=validation,
                           api_errors=[reason], fail_reasons=[reason])


def unwrap(data):
    for attempt in range(6):
        if isinstance(data, (str, bytes)):
            try:
                data = json.loads(data)
            except ValueError:
                return None
        if not isinstance(data, dict) or "value" in data:
            return data
        moved = False
        for key in WRAPPERS:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                moved = True
                break
        if not moved:
            return data
    return data


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        validation = {"status": "unknown", "errors": [], "warnings": []}
        data = input
        if isinstance(input, dict) and "data" in input and "validation" in input:
            data = input.get("data")
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
        data = unwrap(data)
        if not isinstance(data, dict) or data.get("error") or data.get("errors"):
            return not_measured("No service principal list was returned (error or unrecognised body)", validation)
        items = data.get("value")
        if not isinstance(items, list):
            return not_measured("No service principal list was returned", validation)
        principals = [p for p in items if isinstance(p, dict) and p.get("id")]
        if not principals:
            return not_measured("The service principal list was empty; every tenant has service principals, so this "
                                "proves nothing", validation)
        partial = bool(data.get("@odata.nextLink"))
        saml = []
        oidc = []
        password = 0
        for sp in principals:
            if sp.get("accountEnabled") is False:
                continue
            mode = str(sp.get("preferredSingleSignOnMode") or "").lower()
            name = str(sp.get("appDisplayName") or sp.get("appId") or sp.get("id"))
            if mode == "saml":
                saml.append(name)
            elif mode == "oidc":
                oidc.append(name)
            elif mode == "password":
                password = password + 1
        count = len(saml) + len(oidc)
        if count == 0 and partial:
            return not_measured("Only a partial page of service principals was returned and none uses SAML or OIDC single "
                                "sign-on", validation)
        result = {
            KEY: count >= 1,
            "ssoApplicationCount": count,
            "samlApplicationCount": len(saml),
            "oidcApplicationCount": len(oidc),
            "passwordSsoApplicationCount": password,
            "servicePrincipalCount": len(principals),
        }
        summary = {"servicePrincipalCount": len(principals), "partialPage": partial}
        if count >= 1:
            return create_response(result, validation,
                                   pass_reasons=[str(count) + " enterprise application(s) sign in through Entra ID single "
                                                 "sign-on (SAML " + str(len(saml)) + ", OIDC " + str(len(oidc)) + "): "
                                                 + ", ".join((saml + oidc)[:10])],
                                   input_summary=summary)
        return create_response(result, validation,
                               fail_reasons=["No enabled enterprise application is configured for SAML or OIDC single "
                                             "sign-on through Entra ID"],
                               recommendations=["Configure SAML or OIDC single sign-on for enterprise applications in "
                                                "Entra ID > Enterprise applications"],
                               input_summary=summary)
    except Exception as e:
        return not_measured("Transformation error: " + str(e))
