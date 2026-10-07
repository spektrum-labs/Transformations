# isdatasovereigntyregionenforced.py - Keepit
#
# Method: getResources -> GET {serverUrl}/users/{accountId}/resources
# Docs:   https://developers.keepit.com/api/products/resources#list-resources
#           "There will be a resource record for every resource that exists on the currently
#           valid configuration of the product"; schema "user-resources": name, type, limit
#         https://developers.keepit.com/resource-names
#           multigeo, boolean, "Allow to use multi geolocations for the backups"
#
# A Keepit account lives in one regional data center (the per-region API host in the
# integration's serverUrl setting, e.g. de-fr, us-dc, au-sy). Backups leave that region only
# when the product allows multiple geolocations.

import json


def transform(input):
    """
    True when the account's product configuration carries the multigeo resource and it is
    false: backups may not use more than one geolocation, so they stay in the account's
    regional data center.

    Proves: Keepit's own product configuration forbids multi-geolocation backup.
    Does not prove: which region that is (it is the serverUrl host, not an API field).
    multigeo true, multigeo absent from the configuration, an unrecognised value, or an
    unreadable body answers false.
    """
    key = "isDataSovereigntyRegionEnforced"

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

    try:
        data = unwrap(parse_input(input), "resources")
        if isinstance(data, dict) and data.get("error") is True:
            return {key: False, "reason": "Integration-Service returned an error envelope"}
        resources, problem = read_resources(data)
        if resources is None:
            return {key: False, "reason": problem}
        if "multigeo" not in resources:
            return {key: False, "reason": "The product configuration has no multigeo resource, so single-region storage is not proven", "resourceCount": len(resources)}
        raw = resources.get("multigeo")
        low = str(raw or "").strip().lower()
        if low in ["false", "0"]:
            return {key: True, "reason": "multigeo is false: the product does not allow backups in more than one geolocation", "multigeo": raw}
        if low in ["true", "1"]:
            return {key: False, "reason": "multigeo is true: the product allows backups in more than one geolocation", "multigeo": raw}
        return {key: False, "reason": "multigeo has an unrecognised value", "multigeo": raw}
    except Exception as e:
        return {key: False, "error": str(e)}
