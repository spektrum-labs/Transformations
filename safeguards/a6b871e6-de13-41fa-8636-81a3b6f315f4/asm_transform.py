"""
Transformation: asm_transform
Vendor: Qualys
Category: Security / Attack Surface Management

Transforms Attack Surface Management data to check if ASM is enabled and logging.

Handles two response formats:
1. SCHEDULE_SCAN_LIST_OUTPUT - from getScheduledScans API (an ACTIVE schedule is the
   positive signal; error, empty or unrecognised bodies are Not evaluated)
2. HOST_LIST_VM_DETECTION_OUTPUT - from getVulnerabilities/getPatchableDetections API
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
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

    return data, {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
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
                "transformationId": "asm_transform",
                "vendor": "Qualys",
                "category": "Attack Surface Management"
            }
        }
    }


# Qualys VM API v2 names the schedule list root SCHEDULE_SCAN_LIST_OUTPUT
# (schedule_scan_list_output.dtd). The previous code looked only for
# SCHEDULED_SCAN_LIST_OUTPUT, which Qualys never sends, so a real schedule list fell
# through to the generic fallback and read False. Both spellings are accepted.
SCHEDULE_LIST_KEYS = ("SCHEDULE_SCAN_LIST", "SCHEDULED_SCAN_LIST")


def schedule_root(data):
    """Return (root, legacy). legacy marks the old SCHEDULED_ spelling."""
    if "SCHEDULE_SCAN_LIST_OUTPUT" in data:
        return data["SCHEDULE_SCAN_LIST_OUTPUT"], False
    if "SCHEDULED_SCAN_LIST_OUTPUT" in data:
        return data["SCHEDULED_SCAN_LIST_OUTPUT"], True
    return None, False


def scan_is_active(scan):
    if not isinstance(scan, dict):
        return False
    value = scan.get("ACTIVE")
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 1
    return isinstance(value, str) and value.strip() == "1"


def check_scheduled_scans(root):
    """Read a Qualys schedule list.

    Returns (verdict, scan_count, active_count). verdict is None when the body is not a
    readable schedule list (no RESPONSE), so the caller reports Not evaluated.
    """
    if not isinstance(root, dict):
        return None, 0, 0
    response = root.get("RESPONSE")
    if not isinstance(response, dict):
        return None, 0, 0
    scan_list = None
    for key in SCHEDULE_LIST_KEYS:
        if key in response:
            scan_list = response[key]
            break
    scans = []
    if isinstance(scan_list, dict):
        scans = scan_list.get("SCAN", [])
    if isinstance(scans, dict):
        scans = [scans]
    if not isinstance(scans, list):
        scans = []
    active_count = len([scan for scan in scans if scan_is_active(scan)])
    # Qualys omits SCHEDULE_SCAN_LIST when there are no schedules: a readable answer of
    # "nothing scheduled", which is a real negative. Schedules that exist but are all
    # deactivated are also a real negative. Only an ACTIVE schedule is a positive signal.
    return active_count > 0, len(scans), active_count


def simple_return_error(data):
    """VM API v2 errors arrive as SIMPLE_RETURN.RESPONSE.CODE (e.g. 2000 bad login)."""
    root = data.get("SIMPLE_RETURN")
    if not isinstance(root, dict):
        return ""
    response = root.get("RESPONSE")
    if not isinstance(response, dict):
        return ""
    code = response.get("CODE")
    if code is None or code == "":
        return ""
    return str(code)


def check_vm_detections(data):
    """Check HOST_LIST_VM_DETECTION_OUTPUT for detection activity."""
    output = data.get("HOST_LIST_VM_DETECTION_OUTPUT", {})
    response = output.get("RESPONSE", {})
    host_list = response.get("HOST_LIST", None)

    if host_list is None:
        return False, False, 0, 0

    hosts = host_list.get("HOST", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    host_count = len(hosts)
    detection_count = 0
    for host in hosts:
        detection_list = host.get("DETECTION_LIST", {})
        if not detection_list:
            continue
        detections = detection_list.get("DETECTION", [])
        if isinstance(detections, dict):
            detections = [detections]
        detection_count = detection_count + len(detections)

    has_hosts = host_count > 0
    has_detections = detection_count > 0
    return has_hosts, has_detections, host_count, detection_count


def not_evaluated(validation, reason, recommendation=None, api_errors=None):
    """None reads Unevaluated downstream: a body that proves nothing is not a control that is off."""
    return create_response(
        result={"isASMEnabled": None, "isASMLoggingEnabled": None},
        validation=validation,
        fail_reasons=[reason],
        recommendations=[recommendation] if recommendation else [],
        api_errors=api_errors,
        input_summary={"asmEnabled": None, "asmLoggingEnabled": None}
    )


def is_error_envelope(data):
    if data.get("error") or data.get("errors"):
        return True
    message = data.get("message")
    return isinstance(message, str) and message.startswith("Integration execution error")


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(validation, "Input validation failed")

        if not isinstance(data, dict) or not data:
            return not_evaluated(validation, "Empty or unreadable Qualys body; ASM not evaluated")

        has_explicit_flag = isinstance(data.get("isASMEnabled"), bool) or isinstance(data.get("isASMLoggingEnabled"), bool)

        if is_error_envelope(data) and not has_explicit_flag:
            return not_evaluated(
                validation, "Error communicating with Qualys API; ASM not evaluated",
                "Verify the Qualys API credentials and base URL are correct",
                api_errors=["Qualys call returned an error"]
            )

        error_code = simple_return_error(data)
        if error_code:
            return not_evaluated(
                validation, "Qualys returned error code " + error_code + "; ASM not evaluated",
                "Verify the Qualys API user's credentials and API access permission",
                api_errors=["Qualys SIMPLE_RETURN code " + error_code]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        is_asm_enabled = None
        is_asm_logging_enabled = None
        recognised = False
        scan_count = 0
        active_count = 0
        logging_from_schedule = False

        # Explicit flags, when a caller supplies them, decide.
        if isinstance(data.get("isASMEnabled"), bool):
            is_asm_enabled = data["isASMEnabled"]
            recognised = True
        if isinstance(data.get("isASMLoggingEnabled"), bool):
            is_asm_logging_enabled = data["isASMLoggingEnabled"]
            recognised = True

        root, legacy_spelling = schedule_root(data)
        if root is not None:
            verdict, scan_count, active_count = check_scheduled_scans(root)
            if legacy_spelling and verdict is not None:
                # The old spelling kept its old rule (any schedule counts) so no body that
                # passed before stops passing. Qualys itself never sends this spelling.
                verdict = scan_count > 0
            if verdict is not None:
                recognised = True
                # An active schedule means Qualys launches the scan and keeps its results
                # in the scan history, which the subscription cannot switch off; that is
                # the same evidence for both keys.
                if verdict:
                    is_asm_enabled = True
                    if is_asm_logging_enabled is not True:
                        logging_from_schedule = True
                    is_asm_logging_enabled = True
                else:
                    if is_asm_enabled is None:
                        is_asm_enabled = False
                    if is_asm_logging_enabled is None:
                        is_asm_logging_enabled = False

        if "HOST_LIST_VM_DETECTION_OUTPUT" in data:
            recognised = True
            has_hosts, has_detections, host_count, detection_count = check_vm_detections(data)
            if has_hosts:
                is_asm_enabled = True
            elif is_asm_enabled is None:
                is_asm_enabled = False
            if has_detections:
                is_asm_logging_enabled = True
                logging_from_schedule = False
            elif is_asm_logging_enabled is None:
                is_asm_logging_enabled = False

        if not recognised:
            # Kept from the previous rule so no body that passed before stops passing: a
            # body that positively evidences the control still reads True. Anything else
            # the transform cannot read is Not evaluated, never False by default.
            if affirmative_signal(data):
                is_asm_enabled = True
                is_asm_logging_enabled = True
            else:
                return not_evaluated(validation, "Unrecognised Qualys body; ASM not evaluated")

        additional_findings = []

        if is_asm_enabled:
            if active_count:
                pass_reasons.append("Attack Surface Management is enabled (" + str(active_count) + " active scheduled scan(s))")
            else:
                pass_reasons.append("Attack Surface Management is enabled")
        elif is_asm_enabled is False:
            if scan_count:
                fail_reasons.append("Attack Surface Management is not enabled: every scheduled scan is deactivated")
            else:
                fail_reasons.append("Attack Surface Management is not enabled")
            recommendations.append("Enable Attack Surface Management for visibility into your external attack surface")
        else:
            fail_reasons.append("Attack Surface Management not evaluated")

        if is_asm_logging_enabled and logging_from_schedule:
            logging_reason = ("Logging inferred: Qualys keeps results for scans launched by an active schedule ("
                              + str(active_count) + " active schedules); this is not a direct logging setting")
            pass_reasons.append(logging_reason)
            additional_findings.append({
                "metric": "isASMLoggingEnabled",
                "status": "pass",
                "reason": logging_reason
            })
        elif is_asm_logging_enabled:
            additional_findings.append({
                "metric": "isASMLoggingEnabled",
                "status": "pass",
                "reason": "ASM logging is enabled"
            })
        elif is_asm_logging_enabled is False:
            additional_findings.append({
                "metric": "isASMLoggingEnabled",
                "status": "fail",
                "reason": "ASM logging is not enabled",
                "recommendation": "Enable ASM logging for audit and compliance"
            })
        else:
            additional_findings.append({
                "metric": "isASMLoggingEnabled",
                "status": "not_evaluated",
                "reason": "ASM logging not evaluated"
            })

        return create_response(
            result={
                "isASMEnabled": is_asm_enabled,
                "isASMLoggingEnabled": is_asm_logging_enabled
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "asmEnabled": is_asm_enabled,
                "asmLoggingEnabled": is_asm_logging_enabled,
                "scheduledScans": scan_count,
                "activeScheduledScans": active_count
            }
        )

    except Exception as e:
        return create_response(
            result={"isASMEnabled": None, "isASMLoggingEnabled": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )


def affirmative_signal(data):
    """True only when the payload POSITIVELY evidences the control.

    Replaces `data is not None`, which asked whether a response arrived rather than what
    it said -- so any 2xx body, including one describing the control as OFF, satisfied the
    criterion and no input could ever make it false. Measured 2026-09-21.

    Deliberately conservative, in this order:
      * an unreadable, empty or error body           -> False
      * an explicit OFF among the recognised keys    -> False   (beats any other signal)
      * an explicit ON among the recognised keys     -> True
      * a non-empty population of records/settings   -> True
      * anything unrecognised                        -> False  (never True by default)
    """
    if isinstance(data, list):
        # A top-level JSON array is a population of records, as {"items": [...]} already is,
        # unless an element is an error object (Okta answers errors as {"errorCode": ...}).
        for item in data:
            if isinstance(item, dict) and (item.get("error") or item.get("errors") or item.get("errorCode") or item.get("errorSummary") or item.get("errorMessage")):
                return False
        data = {"items": [item for item in data if item]}
    if not isinstance(data, dict) or not data:
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault", "PSError"):
        if data.get(key):
            return False
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "enforced", "isEnforced", "loggingEnabled", "status", "state", "licensed",
               "licensePurchased", "subscribed", "subscription")
    present = [data[k] for k in on_keys if k in data]
    off_words = ("false", "disabled", "off", "inactive", "none", "expired", "cancelled")
    on_words = ("true", "enabled", "on", "active", "success", "ok", "valid", "licensed")
    for value in present:
        if value is False:
            return False
        if isinstance(value, str) and value.strip().lower() in off_words:
            return False
    for value in present:
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in on_words:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return True
    for key in ("value", "items", "data", "records", "results", "logs", "events", "policies",
                "settings", "configurations", "devices", "agents", "users", "licenses"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    return False
