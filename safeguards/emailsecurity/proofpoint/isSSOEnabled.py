"""
Transformation: isSSOEnabled
Vendor: Proofpoint  |  Category: emailsecurity
Evaluates: Check the Azure settings response to verify that Single Sign-On (SSO) is
configured and enabled for the organization (getAzureSettings).
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
                "transformationId": "isSSOEnabled",
                "vendor": "Proofpoint",
                "category": "emailsecurity"
            }
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"isSSOEnabled": False, "error": "Unexpected data format"}

        azure = data.get("azure", {})
        if not isinstance(azure, dict):
            azure = {}

        sso_enabled = data.get("sso_enabled", azure.get("sso_enabled", None))
        saml_enabled = data.get("saml_enabled", azure.get("saml_enabled", None))
        azure_ad_sso = data.get("azure_ad_sso", azure.get("azure_ad_sso", None))
        federated_auth = data.get("federated_auth_enabled", azure.get("federated_auth_enabled", None))

        is_enabled = (
            bool(sso_enabled) or
            bool(saml_enabled) or
            bool(azure_ad_sso) or
            bool(federated_auth)
        )

        return {
            "isSSOEnabled": is_enabled,
            "ssoEnabled": sso_enabled,
            "samlEnabled": saml_enabled,
            "azureAdSsoEnabled": azure_ad_sso
        }
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSSOEnabled"
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
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Single Sign-On (SSO) is configured and enabled via Azure settings")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("Single Sign-On (SSO) is not confirmed as enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Configure Azure AD SSO integration in Proofpoint Essentials to enforce centralized identity management"
            )
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
