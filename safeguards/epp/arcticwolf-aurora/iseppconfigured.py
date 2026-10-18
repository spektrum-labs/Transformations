"""isEPPConfigured for Arctic Wolf Aurora Endpoint Defense.

Input: the extended device list, GET {baseURL}/devices/v2/extended (scope device:list), read through the
paging envelope: page_items[], plus total_number_of_items. The vendor documents policy on each device as the
assigned policy's ID and name (the page does not name the sub-fields, so only whether a value is present is
read). Page:
https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api/device-api/get-devices-extended

True when there is at least one device and every device has a policy assigned. This is a weak control
signal: a device with no explicit assignment normally sits on the tenant's default policy, so a False means
something unusual, a True does not prove the policy is a good one.

Fail closed:
* not a device list, or devices with no policy field in any record (the plain list view): a data-collection
  error (Not evaluated), never False;
* a partial read (fewer records than total_number_of_items): a device without a policy still fails, but
  "every device" cannot be proven from some of them, so a would-be pass is reported as Not evaluated.
"""

import json
from datetime import datetime

DOCS = "https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api/device-api/get-devices-extended"


def unwrap(value):
    """The engine hands the method's response in one of a few envelopes; peel them, never invent data."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if isinstance(value, bytes):
        try:
            value = json.loads(value.decode("utf-8"))
        except ValueError:
            return None
    if isinstance(value, dict) and "data" in value and "validation" in value:
        value = value.get("data")
    for unused in range(3):
        if isinstance(value, dict):
            for key in ("apiResponse", "api_response", "response", "result", "Output"):
                if key in value and isinstance(value.get(key), (dict, list)):
                    value = value[key]
                    break
            else:
                break
    return value


def devices(body):
    """The device records, or None when the reply is not a device list."""
    if isinstance(body, dict):
        body = body.get("page_items")
    if isinstance(body, list):
        return [d for d in body if isinstance(d, dict)]
    return None


def is_partial(body, read):
    """True when the vendor's own total says more devices exist than were read."""
    total = body.get("total_number_of_items") if isinstance(body, dict) else None
    return isinstance(total, int) and not isinstance(total, bool) and total > read


def has_policy(device):
    policy = device.get("policy")
    if isinstance(policy, str):
        return bool(policy.strip())
    # a placeholder such as {"id": null, "name": null} is no assignment: some value must be there
    return isinstance(policy, dict) and any(isinstance(v, str) and v.strip() for v in policy.values())


def response(key, passed, summary, pass_reasons=None, fail_reasons=None, errors=None):
    return {
        "transformedResponse": {key: bool(passed)},
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors or []},
            "validation": {"status": "passed" if not errors else "failed", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": key, "vendor": "Arctic Wolf Aurora (Cylance)", "category": "Endpoint Security",
                         "source": DOCS},
        },
    }


def transform(input):
    key = "isEPPConfigured"
    body = unwrap(input)
    found = devices(body)
    if found is None:
        return response(key, False, {}, fail_reasons=["No device list returned"], errors=["unreadable response"])
    if not found:
        return response(key, False, {"devices": 0}, fail_reasons=["No devices returned"])
    if not any("policy" in d for d in found):
        return response(key, False, {"devices": len(found)}, fail_reasons=["Device records carry no policy field"],
                        errors=["policy missing from every device: not the extended device list"])
    unassigned = [d for d in found if not has_policy(d)]
    summary = {"devices": len(found), "devicesWithoutPolicy": len(unassigned)}
    if unassigned:
        return response(key, False, summary, fail_reasons=[f"{len(unassigned)} of {len(found)} device(s) have no policy"])
    if is_partial(body, len(found)):
        summary["totalDevices"] = body.get("total_number_of_items")
        return response(key, False, summary,
                        fail_reasons=["Only part of the device list was read; every device cannot be confirmed"],
                        errors=[f"partial read: {len(found)} of {body.get('total_number_of_items')} devices"])
    return response(key, True, summary, pass_reasons=[f"All {len(found)} device(s) have a policy assigned"])
