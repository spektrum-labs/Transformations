"""
Transformation: isBannerModeEnforced
Vendor: AWS  |  Category: cloudsecurity
Evaluates: Whether banner/notification mode is enforced at the AWS account level.
Inspects the SummaryMap from GetAccountSummary for AccountMFAEnabled (value 1 = enforced),
MFADevicesInUse, and AccountAccessKeysPresent to determine whether account-wide
security enforcement controls are active.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBannerModeEnforced", "vendor": "AWS", "category": "cloudsecurity"}
        }
    }


def evaluate(data):
    try:
        summary_map = data.get("SummaryMap", {})
        if not isinstance(summary_map, dict):
            summary_map = {}

        account_mfa_enabled_raw = summary_map.get("AccountMFAEnabled", 0)
        try:
            account_mfa_enabled = int(account_mfa_enabled_raw)
        except Exception:
            account_mfa_enabled = 0

        mfa_devices_raw = summary_map.get("MFADevicesInUse", 0)
        try:
            mfa_devices_in_use = int(mfa_devices_raw)
        except Exception:
            mfa_devices_in_use = 0

        access_keys_raw = summary_map.get("AccountAccessKeysPresent", 0)
        try:
            account_access_keys_present = int(access_keys_raw)
        except Exception:
            account_access_keys_present = 0

        virtual_mfa_raw = summary_map.get("AccountSigningCertificatesPresent", 0)
        try:
            signing_certs_present = int(virtual_mfa_raw)
        except Exception:
            signing_certs_present = 0

        summary_map_populated = len(summary_map) > 0
        mfa_enforced = account_mfa_enabled == 1

        is_enforced = mfa_enforced

        return {
            "isBannerModeEnforced": is_enforced,
            "accountMFAEnabled": mfa_enforced,
            "accountMFAEnabledValue": account_mfa_enabled,
            "mfaDevicesInUse": mfa_devices_in_use,
            "accountAccessKeysPresent": account_access_keys_present,
            "signingCertificatesPresent": signing_certs_present,
            "summaryMapPopulated": summary_map_populated
        }
    except Exception as e:
        return {"isBannerModeEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBannerModeEnforced"
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
            pass_reasons.append("AWS account-level MFA enforcement is active (AccountMFAEnabled = 1)")
            pass_reasons.append("MFA devices in use: " + str(extra_fields.get("mfaDevicesInUse", 0)))
        else:
            if not extra_fields.get("summaryMapPopulated", False):
                fail_reasons.append("GetAccountSummary returned an empty SummaryMap — unable to determine MFA enforcement status")
                recommendations.append("Ensure the IAM service account has iam:GetAccountSummary permission")
            else:
                fail_reasons.append("Account-level MFA is not enforced (AccountMFAEnabled != 1)")
                recommendations.append("Enable account-wide MFA enforcement via IAM policy or AWS Organizations SCP")
                recommendations.append("Require MFA for all IAM users with console access")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        additional_findings.append("AccountAccessKeysPresent: " + str(extra_fields.get("accountAccessKeysPresent", 0)))
        additional_findings.append("SigningCertificatesPresent: " + str(extra_fields.get("signingCertificatesPresent", 0)))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "accountMFAEnabled": extra_fields.get("accountMFAEnabled", False), "mfaDevicesInUse": extra_fields.get("mfaDevicesInUse", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
