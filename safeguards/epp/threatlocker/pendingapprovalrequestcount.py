# pendingapprovalrequestcount.py - ThreatLocker (Endpoint Security, 69b438a1)
#
# Method: getPendingApprovalCount -> GET {serverUrl}/portalapi/ApprovalRequest/ApprovalRequestGetCount
#         ?includeChildOrganizations=true
# Docs:   https://threatlocker.kb.help/portalapiapprovalrequest/ (ApprovalRequestGetCount)
#           "this API will only get the count of Approval Requests with a status of "Pending" and
#           return it as an Integer". Approval Requests cover Application Control, Elevation Control
#           and Storage Control. Permission: View Approvals

import json


def transform(input):
    """
    The number of Pending approval requests ThreatLocker reports for the organization (and its
    child organizations). None when the body is not a non-negative integer.
    """
    key = "pendingApprovalRequestCount"

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    try:
        data = parse(input)
        for depth in range(4):
            if not isinstance(data, dict):
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if w in data:
                    data = parse(data[w])
                    moved = True
                    break
            if not moved:
                break
        if isinstance(data, bool) or not isinstance(data, int) or data < 0:
            return {key: None, "reason": "Response is not the documented integer count"}
        return {key: data}
    except Exception as e:
        return {key: None, "error": str(e)}
