"""
Transformation: isSAMLEnforced
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether SAML Single Sign-On (SSO) is configured and enforced on the Rubrik cluster.
"""
import json
from datetime import datetime


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSAMLEnforced", "vendor": "Rubrik", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            if isinstance(data, list) and len(data) > 0:
                return {"isSAMLEnforced": True, "samlConfigCount": len(data), "entityId": "Multiple", "ssoEnabled": True}
            return {"isSAMLEnforced": False, "error": "Unexpected response format"}

        if "isSamlEnabled" in data:
            enabled = bool(data["isSamlEnabled"])
            enforced = bool(data.get("enforced", data.get("isEnforced", enabled)))
            entity_id = str(data.get("samlEntityId", data.get("entityId", data.get("issuer", "Unknown"))))
            sso_url = str(data.get("ssoUrl", data.get("samlSsoUrl", data.get("signOnUrl", ""))))
            return {"isSAMLEnforced": enabled and enforced, "ssoEnabled": enabled, "isEnforced": enforced, "entityId": entity_id, "ssoUrl": sso_url}

        if "samlSsoEnabled" in data:
            enabled = bool(data["samlSsoEnabled"])
            enforced = bool(data.get("enforced", data.get("isEnforced", enabled)))
            entity_id = str(data.get("entityId", data.get("samlEntityId", "Unknown")))
            return {"isSAMLEnforced": enabled and enforced, "ssoEnabled": enabled, "isEnforced": enforced, "entityId": entity_id}

        if "ssoEnabled" in data:
            enabled = bool(data["ssoEnabled"])
            enforced = bool(data.get("enforced", data.get("isEnforced", enabled)))
            entity_id = str(data.get("entityId", "Unknown"))
            return {"isSAMLEnforced": enabled and enforced, "ssoEnabled": enabled, "isEnforced": enforced, "entityId": entity_id}

        if "entityId" in data or "samlEntityId" in data:
            entity_id = str(data.get("entityId", data.get("samlEntityId", "Unknown")))
            enabled = bool(data.get("enabled", data.get("isEnabled", True)))
            enforced = bool(data.get("enforced", data.get("isEnforced", enabled)))
            cert = str(data.get("certificate", data.get("samlCertificate", data.get("cert", ""))))
            has_cert = len(cert) > 0
            return {"isSAMLEnforced": enabled and enforced and has_cert, "ssoEnabled": enabled, "isEnforced": enforced, "entityId": entity_id, "hasCertificate": has_cert}

        if "data" in data and isinstance(data["data"], list):
            providers = data["data"]
            saml_providers = [p for p in providers if isinstance(p, dict) and (
                p.get("type", "").upper() == "SAML" or
                "entityId" in p or "samlEntityId" in p or "samlCertificate" in p
            )]
            if len(saml_providers) > 0:
                first = saml_providers[0]
                entity_id = str(first.get("entityId", first.get("samlEntityId", "Unknown")))
                return {"isSAMLEnforced": True, "samlProviderCount": len(saml_providers), "entityId": entity_id, "ssoEnabled": True}
            return {"isSAMLEnforced": False, "samlProviderCount": 0, "ssoEnabled": False}

        auth_type = str(data.get("authType", data.get("authDomainType", data.get("authenticationType", "")))).upper()
        if "SAML" in auth_type:
            return {"isSAMLEnforced": True, "authType": auth_type, "ssoEnabled": True}
        if auth_type and auth_type not in ["", "LOCAL", "LDAP", "UNKNOWN"]:
            return {"isSAMLEnforced": False, "authType": auth_type, "ssoEnabled": False}

        return {"isSAMLEnforced": False, "error": "Could not determine SAML status from response"}
    except Exception as e:
        return {"isSAMLEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSAMLEnforced"
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("SAML Single Sign-On is configured and enforced on the Rubrik cluster")
            if "entityId" in extra_fields:
                additional_findings.append("SAML Entity ID: " + str(extra_fields["entityId"]))
            if "ssoUrl" in extra_fields and extra_fields["ssoUrl"]:
                additional_findings.append("SSO URL: " + str(extra_fields["ssoUrl"]))
            if "samlProviderCount" in extra_fields:
                additional_findings.append("SAML providers configured: " + str(extra_fields["samlProviderCount"]))
        else:
            fail_reasons.append("SAML is not enforced on the Rubrik cluster")
            if extra_fields.get("ssoEnabled") is False:
                fail_reasons.append("SSO is not enabled")
            if extra_fields.get("isEnforced") is False:
                fail_reasons.append("SSO is configured but not enforced (local login is still permitted)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure SAML SSO integration in Rubrik cluster settings under Access Management > SSO")
            recommendations.append("Enable enforcement so that all users authenticate via the SAML identity provider")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "ssoEnabled": extra_fields.get("ssoEnabled", False), "isEnforced": extra_fields.get("isEnforced", False)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
