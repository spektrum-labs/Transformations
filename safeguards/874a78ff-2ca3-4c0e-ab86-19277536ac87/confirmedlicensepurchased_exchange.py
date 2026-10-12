"""
Transformation: confirmedLicensePurchased (Exchange Online mailbox licence)
Vendor: Microsoft 365
Category: Email Security / Licensing

Method: GET https://graph.microsoft.com/v1.0/subscribedSkus (Organization.Read.All).
True only when at least one subscribed SKU is ENABLED (capabilityStatus "Enabled", prepaidUnits.enabled
> 0) and carries an Exchange Online mailbox service plan (servicePlanName EXCHANGE_S_* or EXCHANGE_B_*,
excluding EXCHANGE_S_FOUNDATION, which ships inside non-mail SKUs such as Power BI, and archive-only
plans) whose provisioning is not Disabled. Exchange Online includes Exchange Online Protection, the
email-security baseline this integration evaluates. Any subscribedSkus body with a row (the old
affirmative_signal rule) passed on free SKUs every tenant carries.
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
                "vendor": "Microsoft",
                "category": "Licensing"
            }
        }
    }



def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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
        if isinstance(data, dict) and ("PSError" in data or data.get("error")):
            raw = str(data.get("PSError") or data.get("error"))
            api_error, recommendation = parse_api_error(raw, source="Microsoft Graph")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not read subscribed SKUs"],
                recommendations=[recommendation]
            )
        skus = data.get("value") if isinstance(data, dict) else data
        if not isinstance(skus, list):
            skus = []
        skus = [s for s in skus if isinstance(s, dict) and isinstance(s.get("servicePlans"), list)]
        if not skus:
            return create_response(
                result={criteriaKey: False, "exchangeSkus": []},
                validation=validation,
                fail_reasons=["No subscribed SKU with service plans was returned; the licence is not evidenced"],
                recommendations=["Grant Organization.Read.All so subscribedSkus can be read"]
            )
        licensed = []
        inactive = []
        for sku in skus:
            plans = []
            for plan in sku.get("servicePlans"):
                if not isinstance(plan, dict):
                    continue
                name = str(plan.get("servicePlanName") or "").upper()
                if not (name.startswith("EXCHANGE_S_") or name.startswith("EXCHANGE_B_")):
                    continue
                if name == "EXCHANGE_S_FOUNDATION" or "ARCHIVE" in name:
                    continue
                if str(plan.get("provisioningStatus") or "").lower() == "disabled":
                    continue
                plans.append(name)
            if not plans:
                continue
            units = sku.get("prepaidUnits") if isinstance(sku.get("prepaidUnits"), dict) else {}
            try:
                enabled_units = int(units.get("enabled") or 0)
            except (TypeError, ValueError):
                enabled_units = 0
            part = str(sku.get("skuPartNumber") or sku.get("skuId") or "unknown")
            if str(sku.get("capabilityStatus") or "").lower() == "enabled" and enabled_units > 0:
                licensed.append(part)
            else:
                inactive.append(part + " (" + str(sku.get("capabilityStatus")) + ", " + str(enabled_units) + " units)")
        is_licensed = len(licensed) > 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_licensed:
            pass_reasons.append("Enabled Exchange Online subscription(s): " + ", ".join(licensed[:5]))
        elif inactive:
            fail_reasons.append("Exchange Online subscriptions are present but not active: " + ", ".join(inactive[:5]))
            recommendations.append("Renew the Microsoft 365 / Exchange Online subscription")
        else:
            fail_reasons.append("No subscribed SKU carries an Exchange Online mailbox plan")
            recommendations.append("License Exchange Online (standalone or through a Microsoft 365 plan)")
        return create_response(
            result={criteriaKey: is_licensed, "exchangeSkus": licensed},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"skuCount": len(skus), "exchangeSkusEnabled": len(licensed), "exchangeSkusInactive": len(inactive)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
