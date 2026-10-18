"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: Azure Recovery Services
Category: Backup / Data Protection

True when at least one protected item (a VM, file share or database) in a Recovery Services vault is
actively protected. The check cannot tell which systems are critical, so it proves "something is being
backed up", not coverage of a named set of systems.

Data source: the per-vault protected items list (Azure Backup protectedItems read), merged under
"protectedItems" as a list of pages, each {"value": [...]}, or a single {"value": [...]} page.

Not evaluated (None, with a collection error) whenever the body does not prove the answer: no vault was
read, a vault's list is an error body, is incomplete (nextLink) or holds an entry the code cannot read, and
the input failed validation. A vault that was read and holds no actively protected item is a real False.
When an active item was seen but some list could not be read, the answer stays True (a seen item proves it)
and no total is given, because a count of the items that were seen would be an undercount.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isBackupEnabledForCriticalSystems"

# Azure uses 'Protected', 'ProtectionConfigured' (protectionState) and 'Healthy' (protectionStatus).
ACTIVE_STATUSES = ("protected", "protectionconfigured", "healthy")


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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": CRITERIA_KEY, "vendor": "Azure", "category": "Backup"}
        }
    }


def not_evaluated(validation, api_error, fail_reason, recommendation, transformation_errors=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={CRITERIA_KEY: None},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[api_error],
        fail_reasons=[fail_reason],
        recommendations=[recommendation]
    )


def read_pages(data):
    """The per-vault pages of the protected items read, or None when the body is not that read."""
    if not isinstance(data, dict):
        return None
    if "protectedItems" in data:
        entries = data["protectedItems"]
    elif "value" in data:
        entries = [data]
    else:
        return None
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return None
    return entries


def transform(input):
    """Evaluates whether Azure Backup actively protects at least one item in the vaults that were read."""
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(
                validation,
                "Could not read the response: input validation failed",
                "Input validation failed",
                "Re-evaluate this check once the Azure Backup read succeeds"
            )

        pages = read_pages(data)
        if pages is None:
            return not_evaluated(
                validation,
                "Could not read protected items",
                "Protected items were not returned, so this check could not be evaluated",
                "Verify the Azure Backup connection can read Recovery Services vaults, then re-evaluate this check"
            )
        if len(pages) == 0:
            # The vault listing is empty both when no vault exists and when the subscription cannot be read.
            return not_evaluated(
                validation,
                "No Recovery Services vault was read",
                "No vault was read, so this check could not be evaluated",
                "Verify the Azure Backup connection can read the subscriptions that hold the vaults, then re-evaluate this check"
            )

        unreadable = 0
        total_items = 0
        active_items = []
        for page in pages:
            if isinstance(page, list):
                page = {"value": page}
            if not isinstance(page, dict) or "error" in page or not isinstance(page.get("value"), list):
                unreadable += 1
                continue
            if page.get("nextLink"):
                # More items exist than were read, so an absence of active items proves nothing.
                unreadable += 1
            for item in page["value"]:
                if not isinstance(item, dict) or not isinstance(item.get("properties"), dict):
                    unreadable += 1
                    continue
                total_items += 1
                props = item["properties"]
                status = str(props.get("protectionStatus") or props.get("protectionState") or "").lower()
                if status in ACTIVE_STATUSES:
                    active_items.append(item.get("name", "Unknown"))

        if len(active_items) == 0 and unreadable > 0:
            return not_evaluated(
                validation,
                "Could not read every protected items list",
                "Not every vault's protected items could be read, so the absence of protected items is not proven",
                "Verify the Azure Backup connection can read protected items in every vault, then re-evaluate this check"
            )

        found = len(active_items) > 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if found and unreadable > 0:
            # Proven by an item that was seen; the totals would be undercounts, so none is given.
            pass_reasons.append(
                f"At least {len(active_items)} actively protected item(s) seen; not every protected items list could be read, so no total is given"
            )
            return create_response(
                result={CRITERIA_KEY: True, "protectedItemsCount": None, "totalItems": None},
                validation=validation,
                pass_reasons=pass_reasons,
                input_summary={"activeProtectedItemsSeen": len(active_items), "itemsSeen": total_items, "unreadable": unreadable, "vaultPagesRead": len(pages)}
            )
        if found:
            pass_reasons.append(f"Backups enabled for {len(active_items)} protected items across the vaults that were read")
        else:
            fail_reasons.append("No actively protected backup items found")
            recommendations.append("Enable Azure Backup protection for all critical VMs, databases, and storage accounts")

        return create_response(
            result={CRITERIA_KEY: found, "protectedItemsCount": len(active_items), "totalItems": total_items},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"activeProtectedItems": len(active_items), "totalItems": total_items, "vaultPagesRead": len(pages)}
        )

    except Exception as e:
        message = str(e)[:200]  # the text reaches the stored result, so a long one is cut
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            "Could not evaluate the response",
            f"Transformation error: {message}",
            "Re-evaluate this check once the Azure Backup read succeeds",
            transformation_errors=[message]
        )
