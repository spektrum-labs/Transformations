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
                "transformationId": "isPatchManagementEnabled",
                "vendor": "Microsoft Intune",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    """
    Checks for Windows Update for Business (WUfB) update ring configuration
    profiles, indicating patch management governance is in place.

    Looks for device configurations with @odata.type containing
    'windowsUpdateForBusiness' or display names suggesting update management.

    Returns true if at least one WUfB update ring policy exists.
    Returns false if no update management configuration is found.
    """
    criteriaKey = "isPatchManagementEnabled"

    WUFB_ODATA_TYPES = [
        "windowsUpdateForBusinessConfiguration",
        "windowsUpdateForBusiness"
    ]

    UPDATE_NAME_KEYWORDS = [
        "update ring", "windows update", "patch", "wufb",
        "quality update", "feature update", "driver update"
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

        configs = []
        if isinstance(data, list):
            configs = data
        elif isinstance(data, dict):
            configs = data.get("value", data.get("configurations", []))
            if isinstance(configs, dict):
                configs = [configs]

        if not isinstance(configs, list):
            configs = []

        update_configs = []
        for config in configs:
            if not isinstance(config, dict):
                continue

            odata_type = str(config.get("@odata.type", "")).lower()
            display_name = str(config.get("displayName", "")).lower()

            is_wufb = any(wt in odata_type for wt in WUFB_ODATA_TYPES)
            has_update_name = any(kw in display_name for kw in UPDATE_NAME_KEYWORDS)

            if is_wufb or has_update_name:
                update_configs.append({
                    "name": config.get("displayName", "Unknown"),
                    "type": odata_type
                })

        is_enabled = len(update_configs) > 0

        if is_enabled:
            config_names = [c["name"] for c in update_configs]
            pass_reasons.append(
                "%d Windows Update for Business configuration(s) found: %s"
                % (len(update_configs), ", ".join(config_names))
            )
        else:
            fail_reasons.append(
                "No Windows Update for Business (WUfB) update ring "
                "configurations found in Intune"
            )
            recommendations.append(
                "Create Windows Update ring policies in Intune to manage "
                "quality and feature update deferral, scheduling, and "
                "enforcement across managed devices"
            )

        input_summary = {
            "totalConfigProfiles": len(configs),
            "updateConfigurations": len(update_configs)
        }

        return create_response(
            result={criteriaKey: is_enabled},
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
