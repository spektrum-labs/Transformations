"""
Transformation: isTransportRuleBannerEnabled
Vendor: AWS  |  Category: cloudsecurity
Evaluates: Whether an account-level login/security policy is configured in AWS IAM.
Checks the PasswordPolicy block for the presence of configured security controls
(MinimumPasswordLength, RequireSymbols, HardExpiry, ExpirePasswords) which indicate
that a security enforcement posture analogous to a transport/session banner policy is active.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isTransportRuleBannerEnabled", "vendor": "AWS", "category": "cloudsecurity"}
        }
    }


def evaluate(data):
    try:
        password_policy = data.get("PasswordPolicy", {})
        if not isinstance(password_policy, dict):
            password_policy = {}

        policy_controls = [
            "MinimumPasswordLength",
            "RequireSymbols",
            "HardExpiry",
            "ExpirePasswords"
        ]

        present_controls = [ctrl for ctrl in policy_controls if ctrl in password_policy]
        controls_found = len(present_controls)
        policy_exists = controls_found > 0

        min_length = password_policy.get("MinimumPasswordLength", 0)
        try:
            min_length_val = int(min_length)
        except Exception:
            min_length_val = 0

        require_symbols = password_policy.get("RequireSymbols", False)
        hard_expiry = password_policy.get("HardExpiry", False)
        expire_passwords = password_policy.get("ExpirePasswords", False)

        is_enforced = (
            policy_exists and
            min_length_val > 0 and
            (require_symbols is True or require_symbols == "true") and
            (expire_passwords is True or expire_passwords == "true")
        )

        return {
            "isTransportRuleBannerEnabled": is_enforced,
            "policyExists": policy_exists,
            "controlsFound": controls_found,
            "presentControls": present_controls,
            "minimumPasswordLength": min_length_val,
            "requireSymbols": require_symbols,
            "hardExpiry": hard_expiry,
            "expirePasswords": expire_passwords
        }
    except Exception as e:
        return {"isTransportRuleBannerEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isTransportRuleBannerEnabled"
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
            pass_reasons.append("AWS IAM password policy is configured with required security controls")
            pass_reasons.append("MinimumPasswordLength: " + str(extra_fields.get("minimumPasswordLength", 0)))
            pass_reasons.append("RequireSymbols: " + str(extra_fields.get("requireSymbols", False)))
            pass_reasons.append("ExpirePasswords: " + str(extra_fields.get("expirePasswords", False)))
        else:
            if not extra_fields.get("policyExists", False):
                fail_reasons.append("No IAM account password policy is configured")
                recommendations.append("Configure an IAM account password policy with MinimumPasswordLength, RequireSymbols, HardExpiry, and ExpirePasswords")
            else:
                fail_reasons.append("IAM password policy is incomplete — not all required security controls are active")
                present = extra_fields.get("presentControls", [])
                missing = [ctrl for ctrl in ["MinimumPasswordLength", "RequireSymbols", "HardExpiry", "ExpirePasswords"] if ctrl not in present]
                for m in missing:
                    recommendations.append("Enable or set the '" + m + "' password policy control")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        additional_findings.append("Controls found: " + str(extra_fields.get("controlsFound", 0)) + " of 4 required")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "policyExists": extra_fields.get("policyExists", False), "controlsFound": extra_fields.get("controlsFound", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
