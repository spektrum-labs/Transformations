"""
Transformation: confirmedLicensePurchased
Vendor: Expel  |  Category: mdr
Evaluates: Verify that the Expel organization record contains active entitlements or SKUs,
confirming a valid Expel MDR license has been purchased. A non-empty skus array or
service_offerings list in the entitlement attributes indicates a purchased license.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Expel", "category": "mdr"}
        }
    }


def evaluate(data):
    try:
        organizations = data.get("data", [])
        if not isinstance(organizations, list):
            organizations = []

        total_orgs = len(organizations)
        licensed_orgs = []

        for org in organizations:
            if not isinstance(org, dict):
                continue
            attributes = org.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}

            skus = attributes.get("skus", [])
            service_offerings = attributes.get("service_offerings", [])
            entitlements = attributes.get("entitlements", {})
            if not isinstance(skus, list):
                skus = []
            if not isinstance(service_offerings, list):
                service_offerings = []
            if not isinstance(entitlements, dict):
                entitlements = {}

            entitlement_skus = entitlements.get("skus", [])
            entitlement_offerings = entitlements.get("service_offerings", [])
            if not isinstance(entitlement_skus, list):
                entitlement_skus = []
            if not isinstance(entitlement_offerings, list):
                entitlement_offerings = []

            has_skus = len(skus) > 0 or len(entitlement_skus) > 0
            has_offerings = len(service_offerings) > 0 or len(entitlement_offerings) > 0

            if has_skus or has_offerings:
                org_name = attributes.get("name", org.get("id", "unknown"))
                licensed_orgs.append(org_name)

        confirmed = len(licensed_orgs) > 0

        return {
            "confirmedLicensePurchased": confirmed,
            "totalOrganizations": total_orgs,
            "licensedOrganizations": len(licensed_orgs),
            "licensedOrgNames": licensed_orgs
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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
        licensed_count = eval_result.get("licensedOrganizations", 0)
        licensed_names = eval_result.get("licensedOrgNames", [])

        if result_value:
            pass_reasons.append("Expel MDR license confirmed: " + str(licensed_count) + " organization(s) have active SKUs or service offerings.")
            for name in licensed_names:
                additional_findings.append("Licensed organization: " + str(name))
        else:
            fail_reasons.append("No active Expel MDR license found. No organizations have non-empty skus or service_offerings.")
            if total_orgs == 0:
                fail_reasons.append("No organization records were returned from the Expel API.")
            recommendations.append("Verify that an Expel MDR license has been purchased and that the organization's skus or service_offerings fields are populated in Workbench.")

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalOrganizations": total_orgs, "licensedOrganizations": licensed_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
