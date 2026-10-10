"""Transformation: isMdmManaged (NinjaOne, GET /v2/devices-detailed).

Criterion: every mobile device that NinjaOne reports is enrolled in and managed by NinjaOne MDM.

Data source: getDevicesDetailed, the device list that the other NinjaOne transforms read. The platform has
already scoped it to the organisations in the connection's organization filter (df=org!=...), so every device in
the list is in scope and nothing here filters by organization. A bare array is what the method returns; the
wrappers {"data": [...]}, {"devices": [...]} and {"result": [...]} are accepted too.

Fields read (all on each device record):
  nodeClass       APPLE_IOS, APPLE_IPADOS and ANDROID are the mobile classes (NinjaOne public API enum).
  approvalStatus  PENDING, STAGED, APPROVED or DECOMMISSIONED (NinjaOne public API enum). A mobile device appears
                  in NinjaOne only after MDM enrolment; NinjaOne documents a PENDING device as dormant, with no
                  data monitored or managed, so only APPROVED means NinjaOne MDM is managing the device.

There is no dedicated MDM, supervision or compliance flag in the device list or in the public device schema, so
approvalStatus is the enrolment state this reads. STAGED and DECOMMISSIONED are treated as not managed (not
APPROVED); NinjaOne's wording for those two states on mobile devices is not published, which is why they can only
ever lower the answer. A status outside the four documented values, or a missing one, makes the whole answer
None (not evaluated).

Answer:
  True   at least one mobile device is present and every one of them is APPROVED.
  False  a mobile device is present that is not APPROVED, or no mobile device is present at all.
  None   (dataCollection.status "error") for an API error body, an empty or unrelated body, a device list that
         shows it is incomplete, a device with no readable nodeClass, or a mobile device with no readable
         approvalStatus. A partial read is never judged.

What it proves: N mobile devices enrolled in NinjaOne MDM are managed. What it cannot prove: that no unmanaged
mobile device reaches company data. NinjaOne lists only devices that are enrolled in it.
"""
import json
from datetime import datetime

KEY = "isMdmManaged"
VENDOR = "NinjaOne"
CATEGORY = "epp"

MOBILE_NODE_CLASSES = ("APPLE_IOS", "APPLE_IPADOS", "ANDROID")
MANAGED_STATUSES = ("APPROVED",)
UNMANAGED_STATUSES = ("PENDING", "STAGED", "DECOMMISSIONED")

LIMIT_NOTE = (
    "This reports which mobile devices enrolled in NinjaOne MDM are managed. It cannot see mobile devices that are "
    "not enrolled in NinjaOne, so a pass does not prove that no unmanaged device reaches company data."
)

LIST_KEYS = ("devices", "data", "results", "result", "items", "value", "api_response", "response", "apiResponse",
             "Output", "rawResponse")
WRAPPER_KEYS = ("api_response", "response", "result", "apiResponse", "Output", "rawResponse")
INCOMPLETE_FLAGS = ("hasMore", "has_more", "truncated", "partial", "isPartial", "incomplete")
NEXT_MARKERS = ("nextPageToken", "next_page_token", "nextCursor", "next_cursor", "nextPage", "next_page", "next")


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats.

    Only an object wrapper is unwrapped here. A list under a wrapper key is left in place so that the paging flags
    beside it (hasMore, nextPageToken, cursor) stay readable; device_list() finds the list.
    """
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for i in range(3):
            unwrapped = False
            for key in WRAPPER_KEYS:
                if key in data and isinstance(data.get(key), dict):
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
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
        "transformationId": KEY,
        "vendor": VENDOR,
        "category": CATEGORY,
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


def not_measured(reason, validation=None):
    """Not evaluated: no value, and the reason on the channel the evaluator reads."""
    return create_response(result={KEY: None}, validation=validation, api_errors=[reason], fail_reasons=[reason])


def is_error_body(data):
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors"):
        return True
    if data.get("success") is False:
        return True
    for field in ("statusCode", "status_code", "status"):
        status = data.get(field)
        if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
            return True
    return False


def device_list(data):
    """The device records in a body, or None when the body is not a device list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                return value
    return None


def completeness_problem(data, received):
    """A reason the list is a partial read, or None. A bare array cannot show it; a wrapper can."""
    if not isinstance(data, dict):
        return None
    for flag in INCOMPLETE_FLAGS:
        if data.get(flag) is True:
            return "NinjaOne marked the device list incomplete (" + flag + ")"
    for marker in NEXT_MARKERS:
        if data.get(marker):
            return "NinjaOne returned a continuation marker (" + marker + "), so more devices exist than were read"
    cursor = data.get("cursor")
    if isinstance(cursor, dict) and "count" in cursor:
        count = cursor.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return "The device list cursor carries a count that is not a whole number"
        if count > received:
            return "NinjaOne reported " + str(count) + " devices but only " + str(received) + " were returned"
    return None


def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        input = json.loads(input) if input.strip() else None
    return extract_input(input)


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("NinjaOne returned an error instead of the device list", validation)
        devices = device_list(data)
        if devices is None:
            return not_measured("No device list was returned by getDevicesDetailed", validation)
        if len(devices) == 0:
            return not_measured("getDevicesDetailed returned no device records, so mobile device management could not be verified", validation)
        problem = completeness_problem(data, len(devices))
        if problem:
            return not_measured(problem + "; a partial device list is not judged", validation)

        mobile = 0
        managed = 0
        unmanaged = 0
        for device in devices:
            if not isinstance(device, dict):
                return not_measured("The device list holds a record that is not an object", validation)
            node_class = device.get("nodeClass")
            if not isinstance(node_class, str) or not node_class.strip():
                return not_measured("A device record has no readable nodeClass, so whether it is mobile cannot be told", validation)
            if node_class.strip().upper() not in MOBILE_NODE_CLASSES:
                continue
            mobile = mobile + 1
            status = device.get("approvalStatus")
            status = status.strip().upper() if isinstance(status, str) else ""
            if status in MANAGED_STATUSES:
                managed = managed + 1
            elif status in UNMANAGED_STATUSES:
                unmanaged = unmanaged + 1
            else:
                return not_measured("A mobile device has no readable approvalStatus, so its management state cannot be told", validation)

        result = {
            KEY: mobile > 0 and unmanaged == 0,
            "totalMobileDevices": mobile,
            "managedMobileDeviceCount": managed,
            "unmanagedMobileDeviceCount": unmanaged,
            "devicesReported": len(devices),
        }
        summary = {
            "devicesReported": len(devices),
            "totalMobileDevices": mobile,
            "managedMobileDeviceCount": managed,
            "unmanagedMobileDeviceCount": unmanaged,
        }
        if mobile > 0 and unmanaged == 0:
            return create_response(
                result=result, validation=validation, input_summary=summary,
                pass_reasons=[
                    "All " + str(mobile) + " mobile devices (iOS, iPadOS, Android) in the NinjaOne device list report "
                    "approvalStatus APPROVED, which is the state of a device NinjaOne MDM has enrolled and manages. " + LIMIT_NOTE
                ],
            )
        if mobile == 0:
            return create_response(
                result=result, validation=validation, input_summary=summary,
                fail_reasons=[
                    "None of the " + str(len(devices)) + " devices in the NinjaOne device list is a mobile device "
                    "(iOS, iPadOS or Android), so no mobile device is enrolled in NinjaOne MDM."
                ],
                recommendations=["Enroll company mobile devices in NinjaOne MDM, or manage them in another device management tool."],
            )
        return create_response(
            result=result, validation=validation, input_summary=summary,
            fail_reasons=[
                str(unmanaged) + " of " + str(mobile) + " mobile devices in NinjaOne are not managed (approvalStatus is "
                "PENDING, STAGED or DECOMMISSIONED rather than APPROVED); " + str(managed) + " are managed."
            ],
            recommendations=["Complete enrolment for pending mobile devices in NinjaOne, or remove devices that are no longer in use."],
        )
    except Exception as e:
        return create_response(
            result={KEY: None}, transformation_errors=[str(e)],
            api_errors=["Transformation error: " + str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
