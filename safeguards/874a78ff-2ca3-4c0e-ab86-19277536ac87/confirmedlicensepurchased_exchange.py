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

Purchased, not trial or free. subscribedSkus carries no trial flag, so the two-read wiring also reads
GET https://graph.microsoft.com/v1.0/directory/subscriptions (Organization.Read.All, the same permission) and the
workflow hands both bodies over as {"subscribedSkus": <body>, "subscriptions": <body>}. With that wiring a mailbox
SKU counts only when one of its companySubscription rows (matched on skuId) is status "Enabled" with isTrial false.
A trial-only or not-enabled mailbox SKU is a measured False. A mailbox SKU whose subscription row is missing or
unreadable, an empty or error subscriptions body, or a subscriptions page that continues is Not evaluated unless a
paid mailbox SKU was read. No-cost SKUs that carry a real mailbox plan (developer sandboxes, Office 365 A1) never
count as purchased, in either wiring. The older single read (the bare subscribedSkus body) is still read as before
and says in its pass reason that the trial status was not read.
"""

import json
from datetime import datetime

NEXT_LINK_KEYS = ("@odata.nextLink", "odata.nextLink", "nextLink")
WRAPPER_KEYS = ("api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data")
SKUS_KEY = "subscribedSkus"
SUBSCRIPTIONS_KEY = "subscriptions"
# No-cost SKUs that include an Exchange Online mailbox plan: the Microsoft 365 / Office 365 developer sandboxes and
# the free Office 365 A1 education plans. A mailbox from one of these was not purchased.
FREE_SKU_PARTS = ("DEVELOPERPACK", "DEVELOPERPACK_E5", "STANDARDWOFFPACK_FACULTY", "STANDARDWOFFPACK_STUDENT")


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


def subscription_verdict(sku_id, rows):
    """Whether the companySubscription rows for one SKU show it is paid: "paid", "unpaid" or "unreadable".

    Paid means at least one subscription for the SKU is Enabled and not a trial (isTrial is the boolean false).
    A SKU with no subscription row, or a row whose status or trial flag cannot be read, cannot be shown paid."""
    if not isinstance(sku_id, str) or sku_id.strip() == "":
        return "unreadable"
    matching = [r for r in rows if isinstance(r, dict) and str(r.get("skuId") or "").strip().lower() == sku_id.strip().lower()]
    if not matching:
        return "unreadable"
    unreadable = False
    for row in matching:
        status = row.get("status")
        trial = row.get("isTrial")
        if not isinstance(status, str) or status.strip() == "" or not isinstance(trial, bool):
            unreadable = True
            continue
        if status.strip().lower() == "enabled" and trial is False:
            return "paid"
    return "unreadable" if unreadable else "unpaid"


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
        # Two-read wiring: the workflow stores subscribedSkus and directory/subscriptions under their own keys.
        combined = isinstance(data, dict) and SKUS_KEY in data
        subscriptions = data.get(SUBSCRIPTIONS_KEY) if combined else None
        if combined:
            data = data.get(SKUS_KEY)
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
        partial = has_next_link(data if combined else input)
        skus = [s for s in rows if isinstance(s, dict) and isinstance(s.get("servicePlans"), list)]
        unreadable = len(rows) - len(skus)
        enabled_mail = []
        inactive = []
        free = []
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
            if part.strip().upper() in FREE_SKU_PARTS:
                # A no-cost SKU carries a real mailbox plan, but nothing was purchased.
                free.append(part)
                continue
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
                enabled_mail.append((part, sku.get("skuId")))
            else:
                inactive.append(part + " (" + status.strip() + ", 0 units)")

        trial_checked = False
        subscriptions_partial = False
        trial_unreadable = 0
        if combined:
            # The trial flag lives on directory/subscriptions (companySubscription.isTrial), not on subscribedSkus.
            sub_rows = subscriptions.get("value") if isinstance(subscriptions, dict) else subscriptions
            sub_error = isinstance(subscriptions, dict) and ("PSError" in subscriptions or subscriptions.get("error"))
            if isinstance(sub_rows, list) and len(sub_rows) > 0 and not sub_error:
                trial_checked = True
                subscriptions_partial = has_next_link(subscriptions)
                licensed = []
                for part, sku_id in enabled_mail:
                    verdict = subscription_verdict(sku_id, sub_rows)
                    if verdict == "paid":
                        licensed.append(part)
                    elif verdict == "unpaid":
                        inactive.append(part + " (trial or not enabled)")
                    else:
                        trial_unreadable += 1
            else:
                licensed = []
                trial_unreadable = len(enabled_mail)
        else:
            licensed = [part for part, _ in enabled_mail]

        is_licensed = len(licensed) > 0
        if not is_licensed and (partial or subscriptions_partial):
            # A page that continues holds rows that were not read, so the absence of a paid mailbox plan proves nothing.
            return not_evaluated(
                validation,
                "The subscribedSkus or subscriptions read is incomplete: more pages exist than were read",
                "More pages exist than were read, so the absence of a paid mailbox plan is not proven",
                "Re-evaluate this check once every page can be read"
            )
        if not is_licensed and (unreadable > 0 or trial_unreadable > 0):
            # A row the code cannot read, or a mailbox SKU whose trial status cannot be read, may be the paid plan.
            return not_evaluated(
                validation,
                "Could not read every subscribed SKU and its subscription",
                "Not every mailbox SKU could be shown paid or unpaid, so the licence is not proven",
                "Verify the integration can read subscribedSkus and directory/subscriptions (Organization.Read.All), then re-evaluate this check"
            )
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_licensed:
            if trial_checked:
                pass_reasons.append("Paid (not trial), enabled Exchange Online subscription(s): " + ", ".join(licensed[:5]))
            else:
                pass_reasons.append("Enabled Exchange Online subscription(s): " + ", ".join(licensed[:5]))
                pass_reasons.append("Trial status was not read: wire directory/subscriptions to tell a trial from a purchase")
            if partial or unreadable > 0 or subscriptions_partial or trial_unreadable > 0:
                pass_reasons.append("Not every row was read; a paid mailbox plan that was read proves the licence")
        elif inactive or free:
            if inactive:
                fail_reasons.append("Exchange Online subscriptions are present but not purchased and active: " + ", ".join(inactive[:5]))
            if free:
                fail_reasons.append("Only no-cost SKUs carry a mailbox plan: " + ", ".join(free[:5]))
            recommendations.append("Purchase or renew a Microsoft 365 / Exchange Online subscription")
        else:
            fail_reasons.append("No subscribed SKU carries an Exchange Online mailbox plan")
            recommendations.append("License Exchange Online (standalone or through a Microsoft 365 plan)")
        return create_response(
            result={criteriaKey: is_licensed, "exchangeSkus": licensed},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"skuCount": len(skus), "exchangeSkusEnabled": len(licensed), "exchangeSkusInactive": len(inactive),
                           "freeMailboxSkus": len(free), "unreadable": unreadable, "moreSkuPages": partial,
                           "trialStatusRead": trial_checked, "trialStatusUnreadable": trial_unreadable}
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
