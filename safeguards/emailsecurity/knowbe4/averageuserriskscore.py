# averageuserriskscore.py - KnowBe4 (Email Security, 8a2164ea)
#
# Method: getActiveUsers -> GET {serverUrl}/v1/users?status=active (page/per_page, all pages)
# Docs:   https://developer.knowbe4.com/rest/reporting (spec /elvis-swagger.yml)
#           /v1/users "retrieves a list of all users"; status=active "Returns a list of all active users"
#           User.current_risk_score, e.g. 45.742

import json


def transform(input):
    """
    Mean of current_risk_score across active users that carry a numeric score, to 2 decimals.

    None when the body is not a user list, the list is empty, or no user carries a score
    (an anonymized console returns no per-user data).
    """
    key = "averageUserRiskScore"

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
            for w in ["apiResponse", "_response_data", "response", "result", "users"]:
                if isinstance(value.get(w), (dict, list)):
                    value = value[w]
                    moved = True
                    break
            if not moved:
                break
        return value

    try:
        data = unwrap(parse(input))
        if not isinstance(data, list):
            return {key: None, "reason": "Response is not a KnowBe4 user list"}
        scores = []
        for u in data:
            if not isinstance(u, dict):
                return {key: None, "reason": "User list holds a non-object item"}
            s = u.get("current_risk_score")
            if isinstance(s, (int, float)) and not isinstance(s, bool):
                scores.append(float(s))
        if not scores:
            return {key: None, "reason": "No active user carries a numeric current_risk_score", "userCount": len(data)}
        return {key: round(sum(scores) / len(scores), 2), "usersScored": len(scores), "userCount": len(data)}
    except Exception as e:
        return {key: None, "error": str(e)}
