# isbackuptypesscheduled.py - Keepit
#
# Method: getScheduleConfig (Integration-Service workflow, results merged into one object)
#   1. listDevices          -> GET {serverUrl}/users/{accountId}/devices
#   2. listDeviceAttributes -> GET {serverUrl}/users/{accountId}/devices/{guid}/attributes, once
#      per cloud connector (workflow "iterate" over devices.cloud), collected under
#      "deviceAttributes"
#   3. getResources         -> GET {serverUrl}/users/{accountId}/resources
# Docs:   https://developers.keepit.com/api/data-protection/connectors#list-device-attributes
#           "backup_interval (ISO 8601 duration between automatic backups)", "disable_auto_backup
#           (flag to suppress scheduled backups)"; schema "attributes": attribute/name, value
#         https://developers.keepit.com/resource-names
#           backup-interval, type duration, "Time between two consequent backup operations"

import json
import re


def transform(input):
    """
    True when every cloud connector runs on Keepit's automatic schedule: no
    disable_auto_backup flag is set on it, and it has a positive backup interval (its own
    backup_interval attribute, else the product's backup-interval resource).

    Proves: each connector is on a recurring schedule rather than manual runs only.
    Does not prove: that the scheduled runs succeed (see backupSuccessRatePercentage). A
    disable_auto_backup value that is not a recognisable true/false, a missing or
    unparseable interval, a connector whose attributes were not read, or an unreadable body
    answers false.
    """
    key = "isBackupTypesScheduled"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("raw XML body was not parsed by Integration-Service")
            return json.loads(text)
        return value

    def listify(value):
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return value
        return [value]

    def unwrap(value, marker):
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def read_resources(data):
        """name -> <limit> text from GET /users/{accountId}/resources, or (None, reason)."""
        if not isinstance(data, dict) or "resources" not in data:
            return None, "Response has no <resources> element (the /resources call did not run)"
        res = data.get("resources")
        if res is None or res == "":
            res = {}
        if not isinstance(res, dict):
            return None, "<resources> element has an unexpected shape"
        out = {}
        for r in listify(res.get("resource")):
            if isinstance(r, dict) and r.get("name"):
                limit = r.get("limit")
                out[str(r.get("name")).strip()] = None if limit is None else str(limit).strip()
        return out, None

    def duration_days(text):
        """ISO 8601 duration (the documented "duration" resource type, e.g. P1Y, P30D, PT4H) in
        days, with a year as 365 and a month as 30 days. Anything else, and a zero duration
        (whose meaning Keepit does not document), returns None: unknown, never a pass."""
        if text is None:
            return None
        m = re.match(r"^P(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)W)?(?:(\d+(?:\.\d+)?)D)?(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$", str(text).strip().upper())
        if not m or str(text).strip().upper() in ["P", "PT"] or str(text).strip().upper().endswith("T"):
            return None
        parts = [float(g) if g else 0.0 for g in m.groups()]
        days = parts[0] * 365 + parts[1] * 30 + parts[2] * 7 + parts[3] + parts[4] / 24.0 + parts[5] / 1440.0 + parts[6] / 86400.0
        if days <= 0:
            return None
        return days

    try:
        data = unwrap(parse_input(input), "devices")
        if not isinstance(data, dict):
            return {key: False, "reason": "Response is not an object"}
        if data.get("error") is True:
            return {key: False, "reason": "Integration-Service returned an error envelope"}
        if "devices" not in data:
            return {key: False, "reason": "Response has no <devices> element, so no connector could be read"}
        if "deviceAttributes" not in data:
            return {key: False, "reason": "Response has no deviceAttributes (the per-connector /attributes step did not run)"}
        resources, problem = read_resources(data)
        if resources is None:
            return {key: False, "reason": problem}
        devices = data.get("devices")
        if devices is None or devices == "":
            devices = {}
        if not isinstance(devices, dict):
            return {key: False, "reason": "<devices> element has an unexpected shape"}
        clouds = [c for c in listify(devices.get("cloud")) if isinstance(c, dict)]
        bodies = listify(data.get("deviceAttributes"))
        if len(clouds) == 0:
            return {key: False, "reason": "The account has no cloud connectors, so nothing is scheduled"}
        if len(bodies) != len(clouds):
            return {key: False, "reason": "Read /attributes for " + str(len(bodies)) + " connectors but listDevices returned " + str(len(clouds))}
        product_interval = resources.get("backup-interval")
        scheduled = []
        not_scheduled = []
        for i in range(len(clouds)):
            c = clouds[i]
            kind = str(c.get("type") or "")
            name = str(c.get("name") or c.get("guid") or "")
            label = name + " (" + kind + ")" if kind else name
            body = unwrap(bodies[i], "attributes")
            if not isinstance(body, dict) or "attributes" not in body or body.get("error") is True:
                return {key: False, "reason": "Connector " + label + ": /attributes body has no <attributes> element"}
            attrs_el = body.get("attributes")
            if attrs_el is None or attrs_el == "":
                attrs_el = {}
            if not isinstance(attrs_el, dict):
                return {key: False, "reason": "Connector " + label + ": <attributes> has an unexpected shape"}
            attrs = {}
            for a in listify(attrs_el.get("attribute")):
                if isinstance(a, dict) and a.get("name"):
                    attrs[str(a.get("name")).strip()] = a.get("value")
            flag = str(attrs.get("disable_auto_backup") if attrs.get("disable_auto_backup") is not None else "").strip().lower()
            if "disable_auto_backup" in attrs and flag not in ["false", "0", "no", "true", "1", "yes"]:
                not_scheduled.append({"connector": label, "why": "disable_auto_backup has an unrecognised value"})
                continue
            if flag in ["true", "1", "yes"]:
                not_scheduled.append({"connector": label, "why": "disable_auto_backup is set"})
                continue
            if attrs.get("backup_interval") not in [None, ""]:
                interval, source = str(attrs.get("backup_interval")).strip(), "connector backup_interval"
            else:
                interval, source = product_interval, "product backup-interval"
            days = duration_days(interval)
            if days is None:
                not_scheduled.append({"connector": label, "why": "no readable backup interval (" + source + ": " + str(interval) + ")"})
                continue
            scheduled.append({"connector": label, "interval": interval, "source": source})
        result = len(not_scheduled) == 0
        if result:
            reason = "All " + str(len(clouds)) + " cloud connectors run on an automatic backup interval"
        else:
            reason = str(len(not_scheduled)) + " of " + str(len(clouds)) + " cloud connectors are not on a readable automatic schedule"
        return {key: result, "reason": reason, "scheduledConnectors": scheduled, "unscheduledConnectors": not_scheduled}
    except Exception as e:
        return {key: False, "error": str(e)}
