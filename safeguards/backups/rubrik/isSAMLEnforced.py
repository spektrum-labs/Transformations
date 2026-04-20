"""
Transformation: isSAMLEnforced
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether at least one SAML SSO configuration exists in RSC with isSsoEnabled
set to true, confirming that SAML-based authentication is enforced.
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
                "transformationId": "isSAMLEnforced",
                "vendor": "Rubrik",
                "category": "Backup"
            }
        }
    }


def evaluate(data):
    try:
        configs = []
        raw_configs = data.get("configs", [])
        if isinstance(raw_configs, list) and len(raw_configs) > 0:
            configs = raw_configs
        if not configs:
            saml_data = data.get("samlSso", [])
            if isinstance(saml_data, list):
                configs = saml_data

        total_configs = len(configs)
        enabled_configs = []
        disabled_configs = []

        for cfg in configs:
            if not isinstance(cfg, dict):
                continue
            name = cfg.get("name", "unknown")
            sso_enabled = cfg.get("isSsoEnabled", False)
            if sso_enabled is True:
                enabled_configs.append(name)
            else:
                disabled_configs.append(name)

        enabled_count = len(enabled_configs)
        is_enforced = enabled_count > 0

        sp_initiated = [
            cfg.get("name", "unknown") for cfg in configs
            if isinstance(cfg, dict) and cfg.get("spInitiatedSsoEnabled") is True
        ]

        return {
            "isSAMLEnforced": is_enforced,
            "totalSamlConfigs": total_configs,
            "enabledSamlConfigs": enabled_count,
            "enabledConfigNames": enabled_configs,
            "disabledConfigNames": disabled_configs,
            "spInitiatedConfigs": len(sp_initiated)
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        if result_value:
            pass_reasons.append(
                "SAML SSO is enforced: " +
                str(eval_result.get("enabledSamlConfigs", 0)) +
                " SSO configuration(s) have isSsoEnabled set to true"
            )
            names = eval_result.get("enabledConfigNames", [])
            if names:
                findings.append("Enabled SAML configurations: " + ", ".join(names))
            if eval_result.get("spInitiatedConfigs", 0) > 0:
                findings.append(
                    str(eval_result.get("spInitiatedConfigs", 0)) +
                    " configuration(s) also have SP-initiated SSO enabled"
                )
            disabled = eval_result.get("disabledConfigNames", [])
            if disabled:
                findings.append("SAML configurations present but disabled: " + ", ".join(disabled))
        else:
            if eval_result.get("totalSamlConfigs", 0) == 0:
                fail_reasons.append("No SAML SSO configurations found in RSC")
            else:
                fail_reasons.append(
                    str(eval_result.get("totalSamlConfigs", 0)) +
                    " SAML configuration(s) found but none have isSsoEnabled set to true"
                )
                disabled = eval_result.get("disabledConfigNames", [])
                if disabled:
                    findings.append("Disabled SAML configurations: " + ", ".join(disabled))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Configure and enable at least one SAML SSO integration in Rubrik Security Cloud "
                "(Settings > Users and Access > SSO) and set isSsoEnabled to true to enforce "
                "SAML-based authentication for all RSC users."
            )
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={
                "totalSamlConfigs": eval_result.get("totalSamlConfigs", 0),
                "enabledSamlConfigs": eval_result.get("enabledSamlConfigs", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
