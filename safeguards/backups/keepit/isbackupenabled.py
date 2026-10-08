# isbackupenabled.py - Keepit
#
# Method: listDevices -> GET {serverUrl}/users/{accountId}/devices
# Docs:   https://developers.keepit.com/api/data-protection/connectors#list-devices
#         schema "devices" (https://developers.keepit.com/api/data-protection/~schemas#devices)
#
# Keepit answers in XML only. Integration-Service parses application/xml with xmltodict, so the
# body arrives as {"devices": {"cloud": {...} | [{...}, ...], "pc": ...}}. One element becomes a
# dict, several become a list, an empty <devices/> becomes None, and booleans arrive as the
# strings "true"/"false".

import json
from datetime import datetime, timezone

KEY = "isBackupEnabled"
METHOD = "listDevices"


def transform_bare(input):
    """
    True when the Keepit account has at least one cloud connector (Microsoft 365, Entra ID,
    Google Workspace, Salesforce, ...) that Keepit reports as enabled (<enabled>true</enabled>)
    and that is not scheduled for deletion (no <deletion-deadline>).

    Proves: a SaaS backup connector exists and is switched on in Keepit.
    Does not prove: that its backup jobs succeed, how often they run, or which users,
    mailboxes or sites the connector covers. A connector whose <enabled> element is absent
    is not counted (the schema marks it optional). An unreadable body, an error envelope or an
    unexpected <devices> shape answers None (not measured); an empty <devices/> answers false.
    """
    key = "isBackupEnabled"

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

    def as_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low == "true":
                return True
            if low == "false":
                return False
        return None

    try:
        data = parse_input(input)
        for wrapper in ["response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data and "devices" not in data:
                data = data[wrapper]

        if not isinstance(data, dict) or "devices" not in data:
            return {key: None, "reason": "Response has no <devices> element, so no connector could be read"}
        if data.get("error") is True:
            return {key: None, "reason": "Integration-Service returned an error envelope"}

        devices = data.get("devices")
        if devices is None or devices == "":
            devices = {}
        if not isinstance(devices, dict):
            return {key: None, "reason": "<devices> element has an unexpected shape"}

        clouds = [c for c in listify(devices.get("cloud")) if isinstance(c, dict)]
        enabled = []
        disabled = []
        unstated = []
        pending_deletion = []
        for c in clouds:
            name = str(c.get("name") or c.get("guid") or "")
            kind = str(c.get("type") or "")
            label = name + " (" + kind + ")" if kind else name
            if c.get("deletion-deadline"):
                pending_deletion.append(label)
                continue
            state = as_bool(c.get("enabled"))
            if state is True:
                enabled.append(label)
            elif state is False:
                disabled.append(label)
            else:
                unstated.append(label)

        result = len(enabled) > 0
        if result:
            reason = str(len(enabled)) + " of " + str(len(clouds)) + " cloud connectors are enabled and not scheduled for deletion"
        elif len(clouds) == 0:
            reason = "The account has no cloud connectors"
        else:
            reason = "No cloud connector is enabled: " + str(len(disabled)) + " disabled, " + str(len(pending_deletion)) + " scheduled for deletion, " + str(len(unstated)) + " without an <enabled> element"

        return {
            key: result,
            "reason": reason,
            "cloudConnectorCount": len(clouds),
            "enabledConnectors": enabled,
            "disabledConnectors": disabled,
            "connectorsPendingDeletion": pending_deletion,
            "connectorsWithoutEnabledElement": unstated,
        }
    except Exception as e:
        return {key: None, "error": str(e)}


def envelope(key, method, bare):
    """Wrap a bare result in the platform envelope.

    Whether the criterion was measured is read from its value alone: None means the body could
    not answer the check, so dataCollection reports an error and Token-Service does not grade
    it. Every other value, including a measured False, reports success.
    """
    value = bare.get(key)
    reason = str(bare.get("reason") or bare.get("error") or "The response could not answer this check")
    measured = value is not None
    passed = value is True or value == "confirmed"
    return {
        "transformedResponse": bare,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Keepit", "product": "Keepit", "method": method,
                         "evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0"},
        },
    }


def transform(input):
    """transform_bare() in the platform envelope; a None criterion reports a dataCollection error."""
    return envelope(KEY, METHOD, transform_bare(input))
