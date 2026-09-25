# isbackupimmutable.py - NetBackup (Cohesity NetBackup, formerly Veritas NetBackup)
#
# Method: getSecurityStatus
#         GET {serverUrl}/netbackup/security/status (data.attributes.securitySettingsDetail.<setting>
#         {currentConfigState, ...}): the Security Risk dashboard's current configuration.
# Spec:   NetBackup REST API reference (https://sort.veritas.com/public/documents/nbu/11.0/windowsandunix/productguides/html/getting-started/)
# Auth:   NetBackup API key in the Authorization header; it acts with the RBAC roles of the user it belongs to.

import json
from datetime import datetime, timezone, timedelta


def transform(input):
    """
    Returns isBackupImmutable = True when every active backup storage is immutable: totalImmutableBackupStorages
    equals totalActiveBackupStorages and is above 0 (WORM storage units and WORM tape pools; "active" = a backup in
    the last 31 days). One WORM target among several is False.
    """
    key = "isBackupImmutable"
    SETTING = "isImmutableBackupStorageConfigured"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
        return value

    def jsonapi(input, want_list):
        """The JSON:API document (with IS wrappers removed); (doc, None) or (None, reason)."""
        data = parse_input(input)
        for depth in range(4):
            if not isinstance(data, dict):
                return None, "Response is not an object"
            if data.get("error") or data.get("errors") or data.get("errorCode"):
                return None, "Integration-Service or NetBackup returned an error envelope"
            inner = data.get("data")
            if want_list and isinstance(inner, list):
                return data, None
            if not want_list and isinstance(inner, dict) and isinstance(inner.get("attributes"), dict):
                return data, None
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(data.get(wrapper), dict):
                    data = data[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return None, "Response is not the expected NetBackup JSON:API document"

    try:
        doc, problem = jsonapi(input, False)
        if doc is None:
            return {key: False, "reason": problem}
        detail = doc["data"]["attributes"].get("securitySettingsDetail")
        if not isinstance(detail, dict):
            return {key: False, "reason": "securitySettingsDetail is missing"}
        setting = detail.get(SETTING)
        if not isinstance(setting, dict) or "currentConfigState" not in setting:
            return {key: False, "reason": SETTING + " is not reported by this NetBackup version"}
        state = setting.get("currentConfigState")

        imm = setting.get("totalImmutableBackupStorages")
        act = setting.get("totalActiveBackupStorages")
        if not (isinstance(imm, int) or isinstance(imm, float)) or not (isinstance(act, int) or isinstance(act, float)) or isinstance(imm, bool) or isinstance(act, bool):
            return {key: False, "reason": "Immutable storage totals are not reported"}
        if act <= 0:
            return {key: False, "reason": "No active backup storage in the last 31 days"}
        if imm >= act:
            return {key: True, "reason": "All " + str(int(act)) + " active backup storages are immutable (WORM)"}
        return {key: False, "reason": str(int(imm)) + " of " + str(int(act)) + " active backup storages are immutable"}
    except Exception as e:
        return {key: False, "error": str(e)}
