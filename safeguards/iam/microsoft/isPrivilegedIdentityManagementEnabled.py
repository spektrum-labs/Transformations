"""
Transformation: isPrivilegedIdentityManagementEnabled
Vendor: Microsoft  |  Category: iam
Evaluates: Whether Azure AD Privileged Identity Management (PIM) is enabled and active,
           detected via the Microsoft Graph privilegedAccess / roleEligibilitySchedules API.
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
                "transformationId": "isPrivilegedIdentityManagementEnabled",
                "vendor": "Microsoft",
                "category": "iam"
            }
        }
    }


def evaluate(data):
    """
    Core evaluation logic for isPrivilegedIdentityManagementEnabled.

    Handles three Microsoft Graph API response shapes:

    Shape 1 — Privileged Access resource object (GET /beta/privilegedAccess/aadRoles):
        {"id": "aadRoles", "displayName": "Azure AD roles", "status": "Active"}
        => PIM is enabled when status == "Active" (case-insensitive).

    Shape 2 — Role settings list (GET /beta/privilegedAccess/aadRoles/settings):
        {"value": [{"id": "...", "isEnabled": true, ...}, ...]}
        => PIM is enabled when at least one setting has isEnabled == true.

    Shape 3 — Role eligibility schedules (GET /v1.0/roleManagement/directory/roleEligibilitySchedules):
        {"value": [{"id": "...", "roleDefinitionId": "...", "principalId": "...", ...}, ...]}
        => Presence of the reachable API endpoint (even with an empty value list) means PIM
           is licensed; a non-empty list confirms active use. We treat API accessibility as
           enabled, and surface the assignment count as additional context.

    Error responses from Microsoft Graph are treated as PIM disabled.
    """
    criteriaKey = "isPrivilegedIdentityManagementEnabled"

    try:
        # Guard: explicit Graph API error object
        api_error = data.get("error", None)
        if api_error:
            if isinstance(api_error, dict):
                error_code = api_error.get("code", "UnknownError")
                error_msg = api_error.get("message", "No message provided")
            else:
                error_code = str(api_error)
                error_msg = str(api_error)
            return {
                criteriaKey: False,
                "detectionMethod": "errorResponse",
                "errorCode": error_code,
                "errorMessage": error_msg
            }

        # Shape 1: top-level "status" field — privilegedAccess resource object
        if "status" in data and "value" not in data:
            status_val = data.get("status", "")
            status_str = str(status_val).lower() if status_val else ""
            is_enabled = status_str in ("active", "enabled", "provisioned")
            return {
                criteriaKey: is_enabled,
                "rawStatus": str(status_val),
                "detectionMethod": "privilegedAccessStatusField"
            }

        # Shape 2 & 3: list response with "value" array
        value = data.get("value", None)
        if value is not None and isinstance(value, list):
            total = len(value)

            # Shape 2: settings objects carry an "isEnabled" field
            settings_items = [item for item in value if "isEnabled" in item]
            if settings_items:
                enabled_settings = [item for item in settings_items if item.get("isEnabled", False)]
                enabled_count = len(enabled_settings)
                is_enabled = enabled_count > 0
                return {
                    criteriaKey: is_enabled,
                    "totalSettings": total,
                    "enabledSettingsCount": enabled_count,
                    "detectionMethod": "roleSettingsIsEnabledField"
                }

            # Shape 3: eligibility schedule objects (no isEnabled field)
            # Reachable API == PIM licensed; non-empty list == PIM actively used
            is_enabled = True  # API is accessible = PIM is licensed and active
            return {
                criteriaKey: is_enabled,
                "totalEligibleRoleAssignments": total,
                "detectionMethod": "roleEligibilitySchedules"
            }

        # Shape 1 variant: top-level "isEnabled" boolean directly on the object
        if "isEnabled" in data:
            is_enabled_val = data.get("isEnabled", False)
            return {
                criteriaKey: bool(is_enabled_val),
                "isEnabled": is_enabled_val,
                "detectionMethod": "topLevelIsEnabledField"
            }

        # Fallback: if the response has content and no error, treat as enabled
        if data:
            return {
                criteriaKey: True,
                "detectionMethod": "nonEmptyResponseFallback"
            }

        # Empty / null data
        return {
            criteriaKey: False,
            "detectionMethod": "noData"
        }

    except Exception as e:
        return {criteriaKey: False, "error": str(e)}


def transform(input):
    criteriaKey = "isPrivilegedIdentityManagementEnabled"
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

        extra_fields = {
            k: v for k, v in eval_result.items()
            if k != criteriaKey and k != "error"
        }

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        detection_method = eval_result.get("detectionMethod", "unknown")
        additional_findings.append("Detection method: " + detection_method)

        if result_value:
            pass_reasons.append("Privileged Identity Management (PIM) is enabled and active in Azure AD.")

            if detection_method == "privilegedAccessStatusField":
                pass_reasons.append(
                    "PIM privilegedAccess resource status is: " + str(eval_result.get("rawStatus", ""))
                )
            elif detection_method == "roleSettingsIsEnabledField":
                pass_reasons.append(
                    str(eval_result.get("enabledSettingsCount", 0)) +
                    " of " +
                    str(eval_result.get("totalSettings", 0)) +
                    " PIM role settings have isEnabled=true."
                )
            elif detection_method == "roleEligibilitySchedules":
                total_assignments = eval_result.get("totalEligibleRoleAssignments", 0)
                pass_reasons.append(
                    "PIM API is accessible with " +
                    str(total_assignments) +
                    " eligible role assignment(s) detected."
                )
            elif detection_method == "topLevelIsEnabledField":
                pass_reasons.append("PIM isEnabled flag is set to true.")
            elif detection_method == "nonEmptyResponseFallback":
                pass_reasons.append(
                    "PIM API returned a non-empty response, indicating PIM is available."
                )
        else:
            fail_reasons.append("Privileged Identity Management (PIM) does not appear to be enabled.")

            if detection_method == "errorResponse":
                fail_reasons.append(
                    "Microsoft Graph API returned an error: [" +
                    str(eval_result.get("errorCode", "")) +
                    "] " +
                    str(eval_result.get("errorMessage", ""))
                )
                recommendations.append(
                    "Verify that the service principal has the 'PrivilegedAccess.Read.AzureAD' or "
                    "'RoleManagement.Read.Directory' Microsoft Graph permission."
                )
            elif detection_method == "privilegedAccessStatusField":
                fail_reasons.append(
                    "PIM privilegedAccess resource status is: " + str(eval_result.get("rawStatus", ""))
                )
            elif detection_method == "roleSettingsIsEnabledField":
                fail_reasons.append("No PIM role settings have isEnabled=true.")
            elif detection_method == "noData":
                fail_reasons.append("No data was returned by the API.")
                recommendations.append(
                    "Ensure the Microsoft Graph API call for PIM is configured and returning data."
                )

            if detection_method not in ("errorResponse",):
                recommendations.append(
                    "Enable Azure AD Privileged Identity Management via the Azure Portal under "
                    "Azure Active Directory > Identity Governance > Privileged Identity Management."
                )
            recommendations.append(
                "Ensure an Azure AD P2 or Microsoft Entra ID Governance license is active, "
                "as PIM requires a premium license."
            )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
