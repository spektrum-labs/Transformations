# localstorageutilizationpercentage.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getDiskStorage -> GET {serverUrl}/V4/Storage/Disk (Accept: application/json)
# Docs:   https://github.com/Commvault/CVPowershellSDKV2/blob/main/OpenAPI3.yaml (Commvault's published V4 OpenAPI 3 spec)
#         operation GetDiskStorages: diskStorage[].capacity and freeSpace ("Provided in megabytes").
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    localStorageUtilizationPercentage = (capacity - freeSpace) / capacity x 100 summed over every disk
    storage pool (2 dp). None on an unreadable body, no disk pool, or a pool without numeric capacity.
    """
    key = "localStorageUtilizationPercentage"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("XML body; the method must send Accept: application/json")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        # Integration-Service may hand the body back under one of its envelopes.
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

    def vendor_error(d):
        """A reason string when the body is an Integration-Service or Commvault error, else None.
        Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        code = d.get("errorCode")
        if code not in (None, 0, "0"):
            return "Commvault error " + str(code) + ": " + str(d.get("errorMessage") or "")
        errs = d.get("errList")
        if isinstance(errs, list) and len(errs) > 0:
            return "Commvault errList: " + str(errs[0])[:200]
        err = d.get("error")
        if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
            return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")
        return None

    def as_int(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        return None

    try:
        data = unwrap(parse_input(input), "diskStorage")
        problem = vendor_error(data)
        if problem:
            return {key: None, "reason": problem}
        pools = data.get("diskStorage")
        if not isinstance(pools, list):
            return {key: None, "reason": "Response has no diskStorage list"}
        if len(pools) == 0:
            return {key: None, "reason": "No disk storage pool exists"}
        cap = 0
        free = 0
        for p in pools:
            c = as_int(p.get("capacity")) if isinstance(p, dict) else None
            f = as_int(p.get("freeSpace")) if isinstance(p, dict) else None
            if c is None or f is None or c < 0 or f < 0:
                return {key: None, "reason": "A disk pool has no numeric capacity or freeSpace: " + str(p.get("name") if isinstance(p, dict) else p)}
            cap = cap + c
            free = free + f
        if cap <= 0:
            return {key: None, "reason": "Disk pools report zero total capacity"}
        pct = round((cap - free) * 100.0 / cap, 2)
        return {key: pct, "reason": str(len(pools)) + " disk pools: " + str(cap - free) + " of " + str(cap) + " MB used", "poolCount": len(pools)}
    except Exception as e:
        return {key: None, "error": str(e)}
