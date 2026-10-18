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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


WINDOWS_CLASSES = ["WINDOWS_WORKSTATION", "WINDOWS_SERVER"]


def as_list(value):
    return value if isinstance(value, list) else []


def get_antivirus_rows(data):
    av = data.get("antivirus")
    if isinstance(av, dict):
        return av.get("results"), True
    if isinstance(av, list):
        return av, True
    return None, False


def transform(input):
    """isRealTimeProtectionEnabled for NinjaOne, judged on Windows devices only.

    NinjaOne reads antivirus state from Windows Security Center. productState=ON is the
    Security Center "enabled" state of the AV product, which is its real-time (on-access)
    protection. NinjaOne documents antivirus monitoring as Windows-only; on macOS its
    antivirus-status rows are not trustworthy (measured 2026-09-25 at Spektrum Labs: four
    Macs reported "SOPHOS Central" productState=OFF while Sophos Central's own API
    reported the Sophos Anti-Virus service running on the same machines). So macOS,
    Linux and mobile devices are reported as not evaluable. They are never counted as
    protected or as unprotected.

    Input: the isRealTimeProtectionEnabled workflow merges two methods:
        {"antivirus": {"cursor": ..., "results": [...]},   # getAntivirusStatusReport
         "devices": [...]}                                  # getDevicesDetailed
    Both are required: without the device list the platform of an antivirus row is unknown.
    """
    data, validation = extract_input(input)
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}
    data = data if isinstance(data, dict) else {}

    av_rows, has_av = get_antivirus_rows(data)
    devices_raw = data.get("devices")
    has_devices = isinstance(devices_raw, list)
    av_rows = as_list(av_rows)
    devices = as_list(devices_raw)

    windows_ids = []
    other_counts = {}
    for d in devices:
        if not isinstance(d, dict) or d.get("id") is None:
            continue
        node_class = d.get("nodeClass") or "UNKNOWN"
        if node_class in WINDOWS_CLASSES:
            windows_ids.append(str(d.get("id")))
        else:
            other_counts[node_class] = other_counts.get(node_class, 0) + 1

    on_products = {}
    reported_ids = set()
    for row in av_rows:
        if not isinstance(row, dict) or row.get("deviceId") is None:
            continue
        device_id = str(row.get("deviceId"))
        reported_ids.add(device_id)
        if row.get("productState") == "ON":
            names = on_products.get(device_id) or []
            names.append(row.get("productName") or "unknown product")
            on_products[device_id] = names

    protected = [i for i in windows_ids if i in on_products]
    unprotected = [i for i in windows_ids if i not in on_products]
    not_reporting = [i for i in unprotected if i not in reported_ids]
    unevaluable = sum(other_counts.values())

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if not has_av or not has_devices:
        missing = []
        if not has_av:
            missing.append("antivirus-status report (key 'antivirus')")
        if not has_devices:
            missing.append("device list (key 'devices')")
        is_enabled = False
        fail_reasons.append(
            "Input is missing the " + " and the ".join(missing) + ". Both are needed to tell "
            "which antivirus rows belong to Windows devices, so real-time protection cannot be judged."
        )
        recommendations.append(
            "Check that the isRealTimeProtectionEnabled workflow runs getAntivirusStatusReport "
            "(output key 'antivirus') and getDevicesDetailed (output key 'devices'), and that the "
            "NinjaOne credential can read both."
        )
    elif len(windows_ids) == 0:
        is_enabled = False
        fail_reasons.append(
            f"No Windows devices in the NinjaOne device list ({len(devices)} devices). NinjaOne reads "
            "antivirus state only from Windows Security Center, so real-time protection cannot be "
            "proven for this fleet through NinjaOne."
        )
        recommendations.append(
            "Prove real-time protection from the antivirus vendor's own integration instead."
        )
    elif len(unprotected) == 0:
        is_enabled = True
        sample = [f"device {i}: {', '.join(on_products[i][:2])}" for i in protected[:5]]
        pass_reasons.append(
            f"All {len(windows_ids)} Windows devices report at least one antivirus product with "
            f"productState=ON in Windows Security Center ({'; '.join(sample)})."
        )
    else:
        is_enabled = False
        fail_reasons.append(
            f"{len(unprotected)} of {len(windows_ids)} Windows devices report no antivirus product with "
            f"productState=ON (device IDs: {unprotected[:10]}"
            + (f"; {len(not_reporting)} of them have no antivirus-status row at all" if not_reporting else "")
            + ")."
        )
        recommendations.append(
            "Turn on real-time protection for the antivirus product on the affected Windows devices, "
            "or confirm in NinjaOne why Windows Security Center reports it off."
        )

    if unevaluable > 0 and has_av and has_devices:
        additional_findings.append(
            f"{unevaluable} non-Windows device(s) were not evaluated ({other_counts}). NinjaOne's "
            "antivirus state comes from Windows Security Center; for macOS, Linux and mobile devices "
            "real-time protection must be proven by the antivirus vendor's own integration."
        )

    result = {
        "isRealTimeProtectionEnabled": is_enabled,
        "windowsDevices": len(windows_ids),
        "windowsDevicesProtected": len(protected),
        "devicesNotEvaluated": unevaluable,
    }

    input_summary = {
        "totalDevices": len(devices),
        "windowsDevices": len(windows_ids),
        "windowsDevicesProtected": len(protected),
        "windowsDevicesWithoutAntivirusRow": len(not_reporting),
        "nonWindowsDevicesByClass": other_counts,
        "antivirusRows": len(av_rows),
        "hasAntivirusReport": has_av,
        "hasDeviceList": has_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary=input_summary,
        metadata={
            "transformationId": "isRealTimeProtectionEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
