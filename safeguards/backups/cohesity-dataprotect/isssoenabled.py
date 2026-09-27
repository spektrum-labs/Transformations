# isssoenabled.py - Cohesity DataProtect (Helios / Cohesity Data Cloud)
#
# Method: getIdps
#         GET {serverUrl}/v2/mcm/idps (idps[].isEnabled, name, domain)
# Schema: Cohesity Helios v2 OpenAPI, https://developer.cohesity.com/apidocs/helios/v2-api/
# Auth:   header apiKey (a Helios API key; it acts with the roles of the user it belongs to).

import json
from datetime import datetime, timezone


def transform(input):
    """
    Returns isSSOEnabled = True when at least one SAML identity provider configured in Helios has isEnabled true.
    Does not prove that local login is disabled. False on any unreadable body.
    """
    key = "isSSOEnabled"

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
        body, problem = body_with(input, ["idps"])
        if body is None:
            return {key: False, "reason": problem}
        idps = body.get("idps")
        if idps is None:
            idps = []
        if not isinstance(idps, list):
            return {key: False, "reason": "idps has an unexpected shape"}
        on = [str(i.get("domain") or i.get("name")) for i in idps if isinstance(i, dict) and i.get("isEnabled") is True]
        if not on:
            return {key: False, "reason": "No enabled SAML identity provider (" + str(len(idps)) + " configured)"}
        return {key: True, "reason": "Enabled SAML identity providers: " + ", ".join(on)}
    except Exception as e:
        return {key: False, "error": str(e)}
