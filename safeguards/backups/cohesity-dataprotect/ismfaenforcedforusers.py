# ismfaenforcedforusers.py - Cohesity DataProtect (Helios / Cohesity Data Cloud)
#
# Method: getMfaPreferences
#         GET {serverUrl}/v2/mcm/mfa (deploymentType HeliosSaas|HeliosOnPrem; heliosSaasConfig.mfaStatus
#         OptIn|OptOut|Pending|Unknown; heliosOnPremConfig.mfa boolean)
# Schema: Cohesity Helios v2 OpenAPI, https://developer.cohesity.com/apidocs/helios/v2-api/
# Auth:   header apiKey (a Helios API key; it acts with the roles of the user it belongs to).

import json
from datetime import datetime, timezone


def transform(input):
    """
    Returns isMFAEnforcedForUsers = True when account-level MFA is on: Helios SaaS mfaStatus "OptIn", or Helios
    on-prem heliosOnPremConfig.mfa true. OptOut, Pending, Unknown or any unreadable body is False.
    """
    key = "isMFAEnforcedForUsers"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
        return value

    def body_with(input, markers):
        """The response object holding every marker key, with IS wrappers removed; (body, None) or (None, reason)."""
        data = parse_input(input)
        for depth in range(4):
            if not isinstance(data, dict):
                return None, "Response is not an object"
            if data.get("error") or data.get("errors") or data.get("errorCode"):
                return None, "Integration-Service or Helios returned an error envelope"
            if all([m in data for m in markers]):
                return data, None
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result", "data"]:
                if isinstance(data.get(wrapper), dict):
                    data = data[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return None, "Response carries no " + " / ".join(markers)

    def groups_in(body):
        """Active, not paused, not deleted protection groups; (groups, None) or (None, reason)."""
        pgs = body.get("protectionGroups")
        if pgs is None:
            pgs = []
        if not isinstance(pgs, list):
            return None, "protectionGroups has an unexpected shape"
        if body.get("paginationCookie"):
            return None, "Helios returned only the first page of protection groups"
        live = []
        for g in pgs:
            if not isinstance(g, dict):
                return None, "protectionGroups holds a non-object"
            if g.get("isDeleted") is True or g.get("isActive") is False or g.get("isPaused") is True:
                continue
            live.append(g)
        return live, None

    def last_backup(g):
        run = g.get("lastRun")
        if not isinstance(run, dict):
            return None
        info = run.get("localBackupInfo")
        if not isinstance(info, dict):
            return None
        return info

    try:
        body, problem = body_with(input, ["deploymentType"])
        if body is None:
            return {key: False, "reason": problem}
        kind = body.get("deploymentType")
        if kind == "HeliosSaas":
            cfg = body.get("heliosSaasConfig")
            status = cfg.get("mfaStatus") if isinstance(cfg, dict) else None
            if status == "OptIn":
                return {key: True, "reason": "Helios SaaS account MFA status is OptIn"}
            return {key: False, "reason": "Helios SaaS account MFA status is " + str(status)}
        if kind == "HeliosOnPrem":
            cfg = body.get("heliosOnPremConfig")
            on = cfg.get("mfa") if isinstance(cfg, dict) else None
            if on is True:
                return {key: True, "reason": "Helios on-prem MFA is enabled"}
            return {key: False, "reason": "Helios on-prem MFA is " + str(on)}
        return {key: False, "reason": "Unrecognised deploymentType " + str(kind)}
    except Exception as e:
        return {key: False, "error": str(e)}
