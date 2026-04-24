"""\nTransformation: isContinuousDiscoveryEnabled\nVendor: ITG  |  Category: networksecurity\nEvaluates: Ensures a list of device configurations is returned from IT Glue.\nA populated configurations list confirms that network asset discovery and\ndocumentation is actively occurring within the platform.\n"""
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
                "transformationId": "isContinuousDiscoveryEnabled",
                "vendor": "ITG",
                "category": "networksecurity"
            }
        }
    }


def evaluate(data):
    """
    Pass when the configurations endpoint returns a non-empty list of device
    configuration records, confirming that network asset discovery and
    documentation is actively occurring within IT Glue.
    """
    try:
        configurations = data.get("data", None)

        if configurations is None:
            return {
                "isContinuousDiscoveryEnabled": False,
                "error": "No 'data' key found in API response from getConfigurations",
                "configurationCount": 0,
                "activeConfigurationCount": 0,
                "organizationsCovered": 0
            }

        if not isinstance(configurations, list):
            return {
                "isContinuousDiscoveryEnabled": False,
                "error": "Expected 'data' to be a list, but received an unexpected format",
                "configurationCount": 0,
                "activeConfigurationCount": 0,
                "organizationsCovered": 0
            }

        config_count = len(configurations)

        if config_count > 0:
            active_count = 0
            organization_ids = []
            for cfg in configurations:
                if not isinstance(cfg, dict):
                    continue
                attrs = cfg.get("attributes", {})
                if isinstance(attrs, dict):
                    status = attrs.get("configuration-status", "")
                    if isinstance(status, str) and status.lower() == "active":
                        active_count = active_count + 1
                    org_id = attrs.get("organization-id", None)
                    if org_id is not None and org_id not in organization_ids:
                        organization_ids.append(org_id)

            return {
                "isContinuousDiscoveryEnabled": True,
                "configurationCount": config_count,
                "activeConfigurationCount": active_count,
                "organizationsCovered": len(organization_ids)
            }

        return {
            "isContinuousDiscoveryEnabled": False,
            "configurationCount": 0,
            "activeConfigurationCount": 0,
            "organizationsCovered": 0,
            "error": (
                "IT Glue configurations list is empty; "
                "no network asset discovery activity is recorded in the platform"
            )
        }

    except Exception as e:
        return {
            "isContinuousDiscoveryEnabled": False,
            "error": str(e),
            "configurationCount": 0,
            "activeConfigurationCount": 0,
            "organizationsCovered": 0
        }


def transform(input):
    criteriaKey = "isContinuousDiscoveryEnabled"
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
        additional_findings = []

        if result_value:
            config_count = extra_fields.get("configurationCount", 0)
            active_count = extra_fields.get("activeConfigurationCount", 0)
            orgs_covered = extra_fields.get("organizationsCovered", 0)
            pass_reasons.append(
                "IT Glue configurations endpoint returned " + str(config_count) +
                " configuration record(s), confirming continuous network asset discovery is active"
            )
            if active_count > 0:
                additional_findings.append(
                    str(active_count) + " configuration(s) have an 'active' status"
                )
            if orgs_covered > 0:
                additional_findings.append(
                    "Configurations span " + str(orgs_covered) + " unique organization(s)"
                )
        else:
            fail_reasons.append(
                "IT Glue configurations endpoint did not return any device configuration records; "
                "continuous network asset discovery cannot be confirmed"
            )
            if "error" in eval_result:
                fail_reasons.append("Detail: " + eval_result["error"])
            recommendations.append(
                "Ensure that at least one device or network asset configuration has been "
                "documented in IT Glue under Configurations"
            )
            recommendations.append(
                "Review IT Glue documentation for enabling and using the Configurations module: "
                "https://www.itglue.com"
            )
            recommendations.append(
                "Verify that the API key has read access to the Configurations endpoint"
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "criteriaKey": criteriaKey,
                "resultValue": result_value,
                "configurationCount": extra_fields.get("configurationCount", 0),
                "activeConfigurationCount": extra_fields.get("activeConfigurationCount", 0),
                "organizationsCovered": extra_fields.get("organizationsCovered", 0)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
