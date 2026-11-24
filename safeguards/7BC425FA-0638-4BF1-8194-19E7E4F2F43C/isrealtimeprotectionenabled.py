"""
Transformation: isRealTimeProtectionEnabled
Vendor: Microsoft Defender for Endpoint  |  Category: Endpoint Security
Evaluates: Whether real-time protection is active across all devices

Data source: Advanced Hunting API (POST /api/advancedqueries/run)
Query: DeviceTvmSecureConfigurationAssessment
       | where ConfigurationId == 'scid-2012'
       | project DeviceId, DeviceName, ConfigurationId, IsCompliant, IsApplicable
Permission: AdvancedQuery.Read.All

scid-2011 is "Update Microsoft Defender Antivirus definitions", NOT real-time protection (that is scid-2012);
this file counts whatever rows its method returns, so the method query decides what is measured.

realTimeProtectionCompliancePercentage: floor(100 * protected / applicable), the same key and rounding the
One-Click file (microsoft_endpoint_scid_compliance.py) returns, so one requirement bar reads both. An
applicable device whose state cannot be read (IsCompliant / avMode null, "None" or missing) stays in the
denominator and never counts as protected, so the share can only understate coverage.

isRealTimeProtectionEnabled keeps its old meaning (true when at least one applicable device is protected);
requirements that need fleet coverage read the percentage instead.

Not evaluated (both values None, dataCollection status "error", with the reason): an empty or unrecognised
body, no applicable device with a readable state, rows for a configuration other than scid-2012, or a
transformation error. Never False: those bodies show nothing about whether protection is on.
"""
import json
from datetime import datetime

#: Whole-number share (rounded down) of applicable devices with real-time protection on. The bar lives in the
#: requirement; isRealTimeProtectionEnabled below keeps its old meaning.
PERCENT_KEY = "realTimeProtectionCompliancePercentage"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRealTimeProtectionEnabled", "vendor": "Microsoft Defender for Endpoint", "category": "Endpoint Security"}
        }
    }


def to_bool(val):
    """Convert various truthy representations to bool."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


def read_flag(val):
    """True / False from a boolean-ish compliance state, or None when the state is unreadable (null, "None", other)."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return True if val == 1 else (False if val == 0 else None)
    if isinstance(val, str):
        text = val.strip().lower()
        if text in ("true", "1", "yes"):
            return True
        if text in ("false", "0", "no"):
            return False
    return None


def read_av_mode(val):
    """True / False from a machines-API avMode, or None when it is missing or empty."""
    if val is None or (isinstance(val, str) and not val.strip()):
        return None
    return str(val).strip().lower() in ("active", "sensorenabled")


def extract_devices(data):
    """Extract device records from Advanced Hunting or legacy response formats."""
    if isinstance(data, dict):
        if "Results" in data:
            results = data["Results"]
            return results if isinstance(results, list) else []
        if "value" in data:
            value = data["value"]
            return value if isinstance(value, list) else []
        return [data]
    if isinstance(data, list):
        return data
    return []


def evaluate(data):
    """Evaluate real-time protection across all devices.

    Supports two response formats:
    1. Advanced Hunting (scid-2012): IsCompliant field per device
    2. Legacy machines API: avMode field per device

    Returns {PERCENT_KEY: None, "error": reason} when no applicable device's state can be read.
    """
    devices = extract_devices(data)
    if not devices:
        return {"isRealTimeProtectionEnabled": None, PERCENT_KEY: None,
                "error": "The response lists no device, so real-time protection cannot be read"}

    total = 0
    protected = 0
    unreadable = 0
    non_compliant_devices = []

    for device in devices:
        if not isinstance(device, dict):
            continue

        device_name = device.get("DeviceName") or device.get("computerDnsName") or "Unknown"

        # Advanced Hunting format (scid-2012): IsCompliant
        if "IsCompliant" in device:
            if not to_bool(device.get("IsApplicable", True)):
                continue
            state = read_flag(device.get("IsCompliant"))
        # Legacy machines API format: avMode
        elif "avMode" in device:
            state = read_av_mode(device.get("avMode"))
        else:
            continue
        if state is None:
            unreadable += 1
            continue
        total += 1
        if state:
            protected += 1
        else:
            non_compliant_devices.append(device_name)

    if total == 0:
        if unreadable:
            reason = (str(unreadable) + " applicable device(s) report no readable real-time protection state "
                      "(null or missing), so real-time protection cannot be read")
        else:
            reason = "No applicable device carries real-time protection data, so real-time protection cannot be read"
        return {"isRealTimeProtectionEnabled": None, PERCENT_KEY: None, "unreadableDevices": unreadable,
                "error": reason}

    return {
        "isRealTimeProtectionEnabled": protected > 0,
        # Unreadable devices stay in the denominator and never count as protected, so the share is a floor.
        PERCENT_KEY: (protected * 100) // (total + unreadable),
        "scoreInPercentage": round((protected / total) * 100, 2),
        "totalDevices": total,
        "realTimeProtectedCount": protected,
        "unreadableDevices": unreadable,
        "nonCompliantDevices": non_compliant_devices[:20]
    }


#: The id the method used to query by mistake, and what it really measures. Its rows are not evidence for this
#: check: they read Not evaluated until the method queries scid-2012.
RETIRED_SCID = "scid-2011"


#: The only configuration id this check reads from advanced-hunting rows.
EXPECTED_SCID = "scid-2012"


def retired_rows(data):
    """True when any row evaluate() would count carries a configuration id other than EXPECTED_SCID (the retired
    id, or any other, or an advanced-hunting row with no id at all). Machines-API rows carry neither
    ConfigurationId nor IsCompliant and are unaffected."""
    rows = extract_devices(data)
    if not isinstance(rows, list):
        return False
    for row in rows:
        if isinstance(row, dict) and ("ConfigurationId" in row or "IsCompliant" in row):
            if str(row.get("ConfigurationId") or "").strip().lower() != EXPECTED_SCID:
                return True
    return False


def transform(input):
    criteriaKey = "isRealTimeProtectionEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if retired_rows(data):
            reason = ("The query read a configuration other than " + EXPECTED_SCID + " (for example " + RETIRED_SCID + ", Defender Antivirus definitions up to date), not real-time protection (scid-2012), so "
                      "these rows are not evidence for this check")
            return create_response(
                result={criteriaKey: None, PERCENT_KEY: None},
                validation=validation,
                fail_reasons=[reason],
                recommendations=["Point the Windows Defender method at scid-2012 (real-time protection)"],
                api_errors=[reason],
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        if result_value is None:
            reason = eval_result.get("error") or "Real-time protection state could not be read"
            return create_response(
                result={criteriaKey: None, **extra_fields},
                validation=validation,
                fail_reasons=[reason],
                api_errors=[reason],
                input_summary={criteriaKey: None, **extra_fields},
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            recommendations.append("Enable real-time protection on all devices via Microsoft Defender for Endpoint")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        reason = f"Transformation error: {str(e)}"
        return create_response(
            result={criteriaKey: None, PERCENT_KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[reason],
            api_errors=[reason]
        )
