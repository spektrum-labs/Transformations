"""
Transformation: isSAMLEnforced
Vendor: Sophos  |  Category: Backups
Evaluates: Verifies that SAML/SSO-based authentication is enforced for Sophos
Central administrative access by inspecting global endpoint protection settings.
"""
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSAMLEnforced", "vendor": "Sophos", "category": "Backups"}
        }
    }


def scan_dict_for_saml(d, depth):
    if depth <= 0:
        return False, []
    found_keys = []
    for key in d:
        key_lower = key.lower()
        if "saml" in key_lower or "sso" in key_lower or "singlesign" in key_lower or "federatedauth" in key_lower:
            found_keys.append(key)
        val = d[key]
        if isinstance(val, dict):
            sub_found, sub_keys = scan_dict_for_saml(val, depth - 1)
            if sub_found:
                for sk in sub_keys:
                    found_keys.append(key + "." + sk)
        if isinstance(val, str):
            val_lower = val.lower()
            if "saml" in val_lower or "sso" in val_lower:
                found_keys.append(key + "='" + val + "'")
        if isinstance(val, bool) and val:
            if "saml" in key_lower or "sso" in key_lower or "auth" in key_lower:
                found_keys.append(key + "=true")
    return len(found_keys) > 0, found_keys


def evaluate(data):
    try:
        tamper_protection = data.get("tamperProtectionEnabled", False)
        settings_data = data.get("data", {})

        saml_enforced = False
        saml_indicators = []

        if isinstance(settings_data, dict):
            found, keys = scan_dict_for_saml(settings_data, 5)
            if found:
                saml_enforced = True
                for k in keys:
                    saml_indicators.append("Setting found: " + k)

        top_level_saml = False
        for key in data:
            key_lower = key.lower()
            if "saml" in key_lower or "sso" in key_lower or "singlesignon" in key_lower:
                top_level_saml = True
                saml_indicators.append("Top-level key: " + key)

        if top_level_saml:
            saml_enforced = True

        return {
            "isSAMLEnforced": saml_enforced,
            "tamperProtectionEnabled": tamper_protection,
            "samlIndicatorsFound": len(saml_indicators),
            "samlIndicators": saml_indicators
        }
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

        indicators = extra_fields.get("samlIndicators", [])

        if result_value:
            pass_reasons.append("SAML/SSO authentication configuration detected in Sophos Central settings")
            for ind in indicators:
                pass_reasons.append(ind)
        else:
            fail_reasons.append("No SAML/SSO enforcement indicators found in Sophos Central endpoint settings")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure SAML/SSO enforcement in Sophos Central via Global Settings > Login Settings")
            recommendations.append("Integrate Sophos Central with your identity provider (IdP) to enforce federated authentication")
            additional_findings.append("tamperProtectionEnabled: " + str(extra_fields.get("tamperProtectionEnabled", False)))

        result_dict = {"isSAMLEnforced": result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"samlIndicatorsFound": extra_fields.get("samlIndicatorsFound", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
