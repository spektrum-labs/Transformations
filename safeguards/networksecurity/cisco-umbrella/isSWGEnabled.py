import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    # listRoamingComputers can return either:
    #  - a JSON array of device records (documented shape), or
    #  - a dict envelope with a "data" list, or
    #  - (as captured on this tenant) a columnar dict of empty arrays
    #    keyed by field name (an artifact of an empty fleet capture).
    items = []
    if isinstance(input, list):
        items = input
    elif isinstance(data.get("data"), list):
        items = data.get("data") or []
    elif isinstance(data, list):
        items = data
    else:
        # columnar / empty-fleet shape: {"originId": [], "swgStatus": [], ...}
        # if every value is a list, and any is non-empty, reconstruct records;
        # otherwise treat as an empty fleet.
        list_fields = {k: v for k, v in data.items() if isinstance(v, list)}
        if list_fields:
            max_len = max((len(v) for v in list_fields.values()), default=0)
            if max_len > 0:
                for i in range(max_len):
                    record = {}
                    for k, v in list_fields.items():
                        record[k] = v[i] if i < len(v) else None
                    items.append(record)

    total_devices = len(items)

    def is_swg_active(status):
        if status is None:
            return False
        if isinstance(status, bool):
            return status
        s = str(status).strip().lower()
        return s in ("enabled", "active", "on", "true", "1", "synced")

    swg_enabled_devices = [
        d for d in items
        if is_swg_active(d.get("swgStatus")) or is_swg_active(d.get("lastSyncSwgStatus"))
    ]
    swg_enabled_count = len(swg_enabled_devices)

    if total_devices == 0:
        result = {
            "isSWGEnabled": False,
            "swgEnabledDevices": 0,
            "totalDevices": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                "No roaming computer records were returned by listRoamingComputers, so "
                "no device could be confirmed to have full-proxy SWG (swgStatus) enabled."
            ],
            recommendations=[
                "Verify roaming devices are enrolled and check the Umbrella dashboard "
                "under Deployments > Core Identities > Roaming Computers to confirm SWG "
                "module status is being reported."
            ],
            input_summary={"totalDevices": 0, "swgEnabledDevices": 0},
            metadata={
                "transformationId": "isSWGEnabled",
                "vendor": "Cisco Umbrella",
                "category": "Network Security",
            },
        )

    is_enabled = swg_enabled_count > 0
    result = {
        "isSWGEnabled": is_enabled,
        "swgEnabledDevices": swg_enabled_count,
        "totalDevices": total_devices,
    }

    if is_enabled:
        sample = swg_enabled_devices[0]
        pass_reasons = [
            f"{swg_enabled_count} of {total_devices} roaming computers report an "
            f"active swgStatus/lastSyncSwgStatus (e.g. device "
            f"'{sample.get('name', sample.get('originId'))}' has swgStatus="
            f"'{sample.get('swgStatus')}'), indicating full-proxy Secure Web "
            f"Gateway inspection is enabled beyond DNS-layer-only filtering."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_devices} roaming computers report an enabled "
            f"swgStatus/lastSyncSwgStatus value; devices appear to be using "
            f"DNS-layer-only filtering rather than full-proxy SWG inspection."
        ]
        recommendations = [
            "Enable the Secure Web Gateway (full-proxy HTTPS inspection) module in "
            "the roaming client policy for managed devices via Umbrella Deployments "
            "settings."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total_devices, "swgEnabledDevices": swg_enabled_count},
        metadata={
            "transformationId": "isSWGEnabled",
            "vendor": "Cisco Umbrella",
            "category": "Network Security",
        },
    )
