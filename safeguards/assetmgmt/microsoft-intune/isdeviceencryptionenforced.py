import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

    for _ in range(3):
        if not isinstance(data, dict):
            break
        unwrapped = False
        for key in ["api_response", "response", "result", "apiResponse", "Output"]:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                unwrapped = True
                break
        if not unwrapped:
            break

    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    if pass_reasons is None:
        pass_reasons = []
    if fail_reasons is None:
        fail_reasons = []
    if recommendations is None:
        recommendations = []
    if transformation_errors is None:
        transformation_errors = []
    if api_errors is None:
        api_errors = []
    if additional_findings is None:
        additional_findings = []
    if input_summary is None:
        input_summary = {}

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if api_errors else "success",
                "errors": api_errors
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors,
                "inputSummary": input_summary
            },
            "evaluation": {
                "passReasons": pass_reasons,
                "failReasons": fail_reasons,
                "recommendations": recommendations,
                "additionalFindings": additional_findings
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "schemaVersion": "1.0",
                "transformationId": "isDeviceEncryptionEnforced",
                "vendor": "Microsoft Intune",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    """
    Checks compliance policies for device encryption requirements.

    Looks for compliance policies that require BitLocker (Windows) or
    FileVault (macOS) encryption. Platform-specific policy types include
    windows10CompliancePolicy, macOSCompliancePolicy, etc.

    Returns true if at least one policy requires device encryption.
    Returns false if no encryption requirements are found in any policy.
    """
    criteriaKey = "isDeviceEncryptionEnforced"

    ENCRYPTION_FIELDS = [
        "bitLockerEnabled",
        "storageRequireEncryption",
        "requireDeviceEncryption",
        "encryptionRequired",
        "storageRequireDeviceEncryption",
        "fileVaultEnabled"
    ]

    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            policies = data.get("value", data.get("policies", []))
            if isinstance(policies, dict):
                policies = [policies]

        if not isinstance(policies, list):
            policies = []

        encryption_policies = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue

            for field in ENCRYPTION_FIELDS:
                value = policy.get(field)
                if value is True or value == "true" or value == "True":
                    encryption_policies.append({
                        "name": policy.get("displayName", "Unknown"),
                        "field": field,
                        "type": policy.get("@odata.type", "unknown")
                    })
                    break

        is_enforced = len(encryption_policies) > 0

        if is_enforced:
            policy_names = [p["name"] for p in encryption_policies]
            pass_reasons.append(
                "%d compliance policy(ies) require device encryption: %s"
                % (len(encryption_policies), ", ".join(policy_names))
            )
        else:
            fail_reasons.append(
                "No compliance policies found that require device encryption"
            )
            recommendations.append(
                "Create compliance policies in Intune that require BitLocker "
                "(Windows) and/or FileVault (macOS) encryption to protect "
                "data at rest on managed devices"
            )

        input_summary = {
            "totalPolicies": len(policies),
            "encryptionPolicies": len(encryption_policies)
        }

        return create_response(
            result={criteriaKey: is_enforced},
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
            fail_reasons=["Transformation error: %s" % str(e)]
        )
