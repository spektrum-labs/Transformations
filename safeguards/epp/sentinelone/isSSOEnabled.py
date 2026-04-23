"""\nTransformation: isSSOEnabled\nVendor: SentinelOne  |  Category: epp\nEvaluates: Check if Single Sign-On (SSO/SAML) is enabled for the SentinelOne management console\n"""
import json
from datetime import datetime


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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "SentinelOne", "category": "epp"}
        }
    }


def safe_dict(val):
    """Return val if it is a dict, otherwise return an empty dict."""
    return val if isinstance(val, dict) else {}


def evaluate(data):
    """
    SentinelOne /web/api/v2.1/sso returns a dict under the 'data' key.
    After extract_input unwraps wrapper keys, 'data' may be:
      - A dict with SSO configuration fields (standard shape).
      - A list of SSO config objects (rare, but handle it).
    Primary indicator: 'enabled' field (bool or string bool).
    Secondary indicators: presence of 'idpMetadataUrl' or 'idpSSOUrl'
    suggests SSO has been configured even if 'enabled' is absent.
    """
    criteria_key = "isSSOEnabled"

    # Normalise: if data is a list take the first element
    sso_data = data
    if isinstance(data, list):
        if len(data) == 0:
            return {criteria_key: None, "error": "required fields missing from API response: enabled, idpMetadataUrl, idpSSOUrl"}
        sso_data = data[0] if isinstance(data[0], dict) else {}
    elif not isinstance(data, dict):
        return {criteria_key: None, "error": "required fields missing from API response: enabled, idpMetadataUrl, idpSSOUrl"}

    # Check for the 'data' sub-key (returnSpec wraps under 'data')
    if "data" in sso_data and isinstance(sso_data.get("data"), dict):
        sso_data = sso_data["data"]
    elif "data" in sso_data and isinstance(sso_data.get("data"), list):
        inner = sso_data["data"]
        if len(inner) == 0:
            return {criteria_key: None, "error": "required fields missing from API response: enabled, idpMetadataUrl, idpSSOUrl"}
        sso_data = inner[0] if isinstance(inner[0], dict) else {}

    # Guard: if we have no recognisable fields at all, return None
    known_fields = ["enabled", "idpMetadataUrl", "idpSSOUrl", "idpUrl", "metadataUrl", "spEntityId", "isEnabled"]
    has_any_field = False
    for field in known_fields:
        if field in sso_data:
            has_any_field = True
            break

    if not has_any_field:
        return {criteria_key: None, "error": "required fields missing from API response: enabled, idpMetadataUrl, idpSSOUrl"}

    # Primary: explicit 'enabled' or 'isEnabled' flag
    raw_enabled = sso_data.get("enabled", sso_data.get("isEnabled", None))
    if raw_enabled is not None:
        if isinstance(raw_enabled, str):
            is_enabled = raw_enabled.lower() in ("1", "true", "yes")
        else:
            is_enabled = bool(raw_enabled)
        idp_url = sso_data.get("idpSSOUrl", sso_data.get("idpMetadataUrl", sso_data.get("idpUrl", sso_data.get("metadataUrl", ""))))
        entity_id = sso_data.get("spEntityId", "")
        return {
            criteria_key: is_enabled,
            "idpConfigured": bool(idp_url),
            "spEntityId": entity_id if entity_id else "not set"
        }

    # Secondary: if 'enabled' is absent but IDP URL is present, infer SSO is configured
    idp_url = sso_data.get("idpSSOUrl", sso_data.get("idpMetadataUrl", sso_data.get("idpUrl", sso_data.get("metadataUrl", ""))))
    entity_id = sso_data.get("spEntityId", "")
    if idp_url:
        return {
            criteria_key: True,
            "idpConfigured": True,
            "spEntityId": entity_id if entity_id else "not set",
            "inferredFromIdpUrl": True
        }

    # spEntityId present but no idp url — SSO partially configured but not provably enabled
    if entity_id:
        return {
            criteria_key: False,
            "idpConfigured": False,
            "spEntityId": entity_id,
            "inferredFromIdpUrl": False
        }

    return {criteria_key: None, "error": "required fields missing from API response: enabled, idpMetadataUrl, idpSSOUrl"}


def transform(input):
    criteria_key = "isSSOEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, None)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteria_key and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value is True:
            pass_reasons.append("SSO is enabled on the SentinelOne management console")
            if eval_result.get("idpConfigured"):
                pass_reasons.append("IdP URL is configured, indicating an active SSO integration")
            if eval_result.get("spEntityId") and eval_result.get("spEntityId") != "not set":
                pass_reasons.append("SP Entity ID is set: " + str(eval_result.get("spEntityId")))
            if eval_result.get("inferredFromIdpUrl"):
                additional_findings.append("SSO enabled state was inferred from the presence of an IdP URL because the 'enabled' field was absent")
        elif result_value is False:
            fail_reasons.append("SSO is not enabled on the SentinelOne management console")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable SSO/SAML under Settings > Integrations > SSO in the SentinelOne console")
            recommendations.append("Configure an Identity Provider (IdP) such as Okta, Azure AD, or similar")
        else:
            fail_reasons.append("Could not determine SSO status — required fields were absent from the API response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the API token belongs to an Account Admin or Global Admin with SSO visibility")
            recommendations.append("Verify the /web/api/v2.1/sso endpoint is accessible with the provided credentials")

        return create_response(
            result={criteria_key: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteria_key: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
