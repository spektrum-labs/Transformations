"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft Entra ID (Azure AD)
Category: Licensing

Method: GET https://graph.microsoft.com/v1.0/organization (Organization.Read.All).
True only when the tenant's organization record carries an ENABLED Entra ID P1 or P2 service plan
in assignedPlans (service "AADPremiumService", or servicePlanId AAD_PREMIUM 41781fb2-... /
AAD_PREMIUM_P2 eec0eb4f-...). Every tenant has an organization record and Entra ID Free, so the
record existing (the old affirmative_signal rule) proved only that the call succeeded.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Generic",
                "category": "Licensing"
            }
        }
    }


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    premium_plan_ids = ("41781fb2-bc02-4b7c-bd55-b576c07bb09d", "eec0eb4f-6444-4f95-aba0-50c24d67f998")
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
        if isinstance(data, dict) and data.get("error"):
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                api_errors=["Microsoft Graph returned an error for /organization"],
                fail_reasons=["The organization record could not be read"]
            )
        orgs = data.get("value") if isinstance(data, dict) and "value" in data else data
        if isinstance(orgs, dict):
            orgs = [orgs]
        if not isinstance(orgs, list):
            orgs = []
        orgs = [o for o in orgs if isinstance(o, dict) and isinstance(o.get("assignedPlans"), list)]
        if not orgs:
            return create_response(
                result={criteriaKey: False, "premiumPlansEnabled": 0},
                validation=validation,
                fail_reasons=["No organization record with assignedPlans was returned; the licence is not evidenced"],
                recommendations=["Grant Organization.Read.All so the tenant's assigned plans can be read"]
            )
        enabled_premium = []
        suspended_premium = []
        for org in orgs:
            for plan in org.get("assignedPlans"):
                if not isinstance(plan, dict):
                    continue
                service = str(plan.get("service") or "")
                plan_id = str(plan.get("servicePlanId") or "").lower()
                if service != "AADPremiumService" and plan_id not in premium_plan_ids:
                    continue
                status = str(plan.get("capabilityStatus") or "").lower()
                if status == "enabled":
                    enabled_premium.append(plan_id or service)
                else:
                    suspended_premium.append(plan_id + " (" + status + ")")
        is_licensed = len(enabled_premium) > 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_licensed:
            pass_reasons.append(str(len(enabled_premium)) + " enabled Entra ID P1/P2 service plan(s) assigned to the tenant")
        elif suspended_premium:
            fail_reasons.append("Entra ID P1/P2 plans are present but not enabled: " + ", ".join(suspended_premium[:5]))
            recommendations.append("Renew the Entra ID P1/P2 subscription")
        else:
            fail_reasons.append("No Entra ID P1/P2 plan is assigned to the tenant (Entra ID Free only)")
            recommendations.append("License Entra ID P1 or P2 (standalone or through Microsoft 365 E3/E5/Business Premium)")
        return create_response(
            result={criteriaKey: is_licensed, "premiumPlansEnabled": len(enabled_premium)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"premiumPlansEnabled": len(enabled_premium), "premiumPlansNotEnabled": len(suspended_premium)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
