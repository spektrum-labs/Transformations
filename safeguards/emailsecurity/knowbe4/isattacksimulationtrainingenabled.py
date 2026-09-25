# isattacksimulationtrainingenabled.py - KnowBe4 (Email Security, 8a2164ea)
#
# Method: getPhishingSecurityTests -> GET {serverUrl}/v1/phishing/security_tests (page/per_page, all pages)
# Docs:   https://developer.knowbe4.com/rest/reporting (spec /elvis-swagger.yml)
#           /v1/phishing/security_tests "retrieves a list of all phishing security tests"
#           PST.started_at "Date and time the phishing security test started"

import json
import datetime


def transform(input):
    """
    True when at least one phishing security test started in the last 90 days: simulated
    phishing is actually running, not merely configured once. False on an empty list, on
    tests that are all older, or on any unreadable body.
    """
    key = "isAttackSimulationTrainingEnabled"
    window_days = 90

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    def unwrap(value):
        for depth in range(4):
            if not isinstance(value, dict):
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(w), (dict, list)):
                    value = value[w]
                    moved = True
                    break
            if not moved:
                break
        return value

    def when(text):
        if not isinstance(text, str) or not text:
            return None
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        return t

    try:
        data = unwrap(parse(input))
        if not isinstance(data, list):
            return {key: False, "reason": "Response is not a KnowBe4 phishing security test list"}
        now = datetime.datetime.now(datetime.timezone.utc)
        recent = 0
        for t in data:
            if not isinstance(t, dict):
                continue
            started = when(t.get("started_at"))
            if started is not None and (now - started).days <= window_days and started <= now:
                recent = recent + 1
        if recent:
            return {key: True, "reason": "Phishing security tests started in the last 90 days", "recentTests": recent, "totalTests": len(data)}
        return {key: False, "reason": "No phishing security test started in the last 90 days", "totalTests": len(data)}
    except Exception as e:
        return {key: False, "error": str(e)}
