"""
Transformation: isMDREnabled
Vendor: Expel  |  Category: mdr
Evaluates: Check that the organization's entitlement attributes include MDR in the
service_types or service_offerings array, confirming that the Managed Detection and
Response service is enabled for this organization.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMDREnabled", "vendor": "Expel", "category": "mdr"}
        }
    }


def check_mdr_in_list(items):
    for item in items:
        if not isinstance(item, str):
            item = str(item)
        if "mdr" in item.lower() or "managed detection" in item.lower() or "detection and response" in item.lower():
            return True
    return False


def evaluate(data):
    try:
        organizations = data.get("data", [])
        if not isinstance(organizations, list):
            organizations = []

        total_orgs = len(organizations)
        mdr_enabled_orgs = []
        found_service_types = []
        found_service_offerings = []

        for org in organizations:
            if not isinstance(org, dict):
                continue
            attributes = org.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}

            service_types = attributes.get("service_types", [])
            service_offerings = attributes.get("service_offerings", [])
            entitlements = attributes.get("entitlements", {})
            if not isinstance(service_types, list):
                service_types = []
            if not isinstance(service_offerings, list):
                service_offerings = []
            if not isinstance(entitlements, dict):
                entitlements = {}

            ent_service_types = entitlements.get("service_types", [])
            ent_service_offerings = entitlements.get("service_offerings", [])
            if not isinstance(ent_service_types, list):
                ent_service_types = []
            if not isinstance(ent_service_offerings, list):
                ent_service_offerings = []

            all_types = service_types + ent_service_types
            all_offerings = service_offerings + ent_service_offerings

            has_mdr = check_mdr_in_list(all_types) or check_mdr_in_list(all_offerings)

            if has_mdr:
                org_name = attributes.get("name", org.get("id", "unknown"))
                mdr_enabled_orgs.append(org_name)
                for st in all_types:
                    if st not in found_service_types:
                        found_service_types.append(st)
                for so in all_offerings:
                    if so not in found_service_offerings:
                        found_service_offerings.append(so)

        mdr_enabled = len(mdr_enabled_orgs) > 0

        return {
            "isMDREnabled": mdr_enabled,
            "totalOrganizations": total_orgs,
            "mdrEnabledOrganizations": len(mdr_enabled_orgs),
            "mdrEnabledOrgNames": mdr_enabled_orgs,
            "detectedServiceTypes": found_service_types,
            "detectedServiceOfferings": found_service_offerings
        }
    except Exception as e:
        return {"isMDREnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMDREnabled"
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

        total_orgs = eval_result.get("totalOrganizations", 0)
        mdr_count = eval_result.get("mdrEnabledOrganizations", 0)
        mdr_names = eval_result.get("mdrEnabledOrgNames", [])
        service_types = eval_result.get("detectedServiceTypes", [])
        service_offerings = eval_result.get("detectedServiceOfferings", [])

        if result_value:
            pass_reasons.append("MDR service is enabled for " + str(mdr_count) + " organization(s).")
            for name in mdr_names:
                additional_findings.append("MDR-enabled organization: " + str(name))
            if service_types:
                additional_findings.append("Detected service types: " + ", ".join([str(s) for s in service_types]))
            if service_offerings:
                additional_findings.append("Detected service offerings: " + ", ".join([str(s) for s in service_offerings]))
        else:
            fail_reasons.append("MDR service type or offering not found in any organization's entitlement attributes.")
            if total_orgs == 0:
                fail_reasons.append("No organization records were returned from the Expel API.")
            recommendations.append("Ensure the Expel MDR service is enabled for the organization. Check service_types and service_offerings in Workbench organization settings.")

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalOrganizations": total_orgs, "mdrEnabledOrganizations": mdr_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
