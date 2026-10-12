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

Not evaluated (None, with a collection error) whenever the body does not prove the answer: a vendor or Graph
error body, a body with no SKU rows, a page that continues (a next-page link that is not null or empty) or a row the code cannot read when
no enabled mailbox plan was seen elsewhere, malformed or unreadable input, and failed input validation. A row the
code cannot read is one without service plans, a plan without a name, or a row with a mailbox plan whose status or
enabled unit count is missing or not readable. A SKU list that was read whole and holds no enabled Exchange
mailbox plan is a real False. An enabled mailbox plan that was read stays True beside any of the above.
"""

import json
from datetime import datetime

NEXT_LINK_KEYS = ("@odata.nextLink", "odata.nextLink", "nextLink")
WRAPPER_KEYS = ("api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data")


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

def not_evaluated(validation, api_error, fail_reason, recommendation, transformation_errors=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={"confirmedLicensePurchased": None},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[api_error],
        fail_reasons=[fail_reason],
        recommendations=[recommendation]
    )


def has_next_link(body, depth=0):
    """True when the body, or a wrapper layer around it, carries a next-page link: the read is then partial.

    Only a null or empty-text link means the read is complete. Any other value (text, an object, a list, a number,
    a flag) is a continuation that was not followed, so the read is partial."""
    if not isinstance(body, dict) or depth > 3:
        return False
    for key in NEXT_LINK_KEYS:
        if key in body and body[key] is not None and body[key] != "":
            return True
    for key in WRAPPER_KEYS:
        if has_next_link(body.get(key), depth + 1):
            return True
    return False


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_evaluated(
                validation,
                "Could not read subscribed SKUs: input validation failed",
                "Input validation failed",
                "Re-evaluate this check once the subscribedSkus read succeeds"
            )
        if isinstance(data, dict) and ("PSError" in data or data.get("error")):
            raw = str(data.get("PSError") or data.get("error"))
            api_error, recommendation = parse_api_error(raw, source="Microsoft Graph")
            return not_evaluated(
                {"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_error,
                "Could not read subscribed SKUs",
                recommendation
            )
        rows = data.get("value") if isinstance(data, dict) else data
        if not isinstance(rows, list) or len(rows) == 0:
            # No SKU rows is both a tenant that holds none and a read that returned nothing, so it proves nothing.
            return not_evaluated(
                validation,
                "The subscribedSkus read returned no SKU rows",
                "No subscribed SKU was returned, so the licence could not be evaluated",
                "Verify the integration can read subscribedSkus (Organization.Read.All), then re-evaluate this check"
            )
        partial = has_next_link(input)
        skus = [s for s in rows if isinstance(s, dict) and isinstance(s.get("servicePlans"), list)]
        unreadable = len(rows) - len(skus)
        licensed = []
        inactive = []
        for sku in skus:
            plans = []
            for plan in sku.get("servicePlans"):
                if not isinstance(plan, dict):
                    unreadable += 1
                    continue
                raw_name = plan.get("servicePlanName")
                if not isinstance(raw_name, str) or raw_name.strip() == "":
                    unreadable += 1
                    continue
                name = raw_name.strip().upper()
                if not (name.startswith("EXCHANGE_S_") or name.startswith("EXCHANGE_B_")):
                    continue
                if name == "EXCHANGE_S_FOUNDATION" or "ARCHIVE" in name:
                    continue
                if str(plan.get("provisioningStatus") or "").lower() == "disabled":
                    continue
                plans.append(name)
            if not plans:
                continue
            part = str(sku.get("skuPartNumber") or sku.get("skuId") or "unknown")
            status = sku.get("capabilityStatus")
            if not isinstance(status, str) or status.strip() == "":
                unreadable += 1
                continue
            if status.strip().lower() != "enabled":
                # The status alone proves the subscription is not active.
                inactive.append(part + " (" + status.strip() + ")")
                continue
            units = sku.get("prepaidUnits")
            enabled_units = units.get("enabled") if isinstance(units, dict) else None
            if not isinstance(enabled_units, int) or isinstance(enabled_units, bool):
                unreadable += 1
                continue
            if enabled_units > 0:
                licensed.append(part)
            else:
                inactive.append(part + " (" + status.strip() + ", 0 units)")
        is_licensed = len(licensed) > 0
        if not is_licensed and partial:
            # A page that continues holds SKUs that were not read, so the absence of a mailbox plan proves nothing.
            return not_evaluated(
                validation,
                "The subscribedSkus read is incomplete: more pages exist than were read",
                "More subscribed SKU pages exist than were read, so the absence of a mailbox plan is not proven",
                "Re-evaluate this check once every subscribedSkus page can be read"
            )
        if not is_licensed and unreadable > 0:
            # A row or plan the code cannot read may be the mailbox plan, so its absence from the answer proves nothing.
            return not_evaluated(
                validation,
                "Could not read every subscribed SKU",
                "Not every subscribed SKU could be read, so the absence of a mailbox plan is not proven",
                "Verify the integration can read subscribedSkus (Organization.Read.All), then re-evaluate this check"
            )
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_licensed:
            pass_reasons.append("Enabled Exchange Online subscription(s): " + ", ".join(licensed[:5]))
            if partial or unreadable > 0:
                pass_reasons.append("Not every subscribed SKU was read; an enabled mailbox plan that was read proves the licence")
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
            input_summary={"skuCount": len(skus), "exchangeSkusEnabled": len(licensed), "exchangeSkusInactive": len(inactive), "unreadable": unreadable, "moreSkuPages": partial}
        )
    except Exception as e:
        message = str(e)[:200]  # the text reaches the stored result, so a long one is cut
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            "Could not evaluate the response",
            f"Transformation error: {message}",
            "Re-evaluate this check once the subscribedSkus read succeeds",
            transformation_errors=[message]
        )
