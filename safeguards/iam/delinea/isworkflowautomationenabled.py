# isworkflowautomationenabled.py - Delinea Secret Server (REST API v1)
#
# Method: getWorkflowTemplates -> GET {secretServerUrl}/api/v1/workflows/templates?filter.workflowType=AccessRequest&take=100
# Docs:   Secret Server REST API reference 12.1.2, PagingOfWorkflowTemplateDetailModel:
#         {records: [{workflowTemplateId, name, active, workflowType: AccessRequest|SecretEraseRequest}], hasNext, total}
# Auth:   Delinea Platform OAuth2 client credentials (POST {serverUrl}/identity/api/oauth2/token/xpmplatform, scope
#         xpmheadless); the same bearer token is accepted by the tenant's Secret Server (docs.delinea.com
#         /online-help/platform-api/secret-server-apis-from-platform.htm).

import json


def transform(input):
    """
    isWorkflowAutomationEnabled = true when at least one ACTIVE access-request workflow template exists, so access
    requests and approvals run through a defined workflow. False when none is active, or on any error body.
    """
    key = "isWorkflowAutomationEnabled"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("HTML or XML body; expected JSON from the Delinea API")
            return json.loads(text)
        return value

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

    def vendor_error(d):
        """A reason when the body is an Integration-Service or Delinea error, else None."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        if d.get("success") is False:
            return "Delinea reported success=false: " + str(d.get("message") or d.get("Message") or "")[:200]
        if d.get("errorCode"):
            return "Delinea error " + str(d.get("errorCode")) + ": " + str(d.get("message") or "")[:200]
        status = d.get("status")
        if isinstance(status, int) and status >= 400:
            return "Delinea HTTP " + str(status) + ": " + str(d.get("title") or d.get("detail") or "")[:200]
        return None

    try:
        data = unwrap(parse_input(input), "records")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        records = data.get("records")
        if not isinstance(records, list):
            return {key: False, "reason": "Response has no records list"}
        active = [r for r in records if isinstance(r, dict) and r.get("active") is True
                  and str(r.get("workflowType")) == "AccessRequest"]
        if len(active) > 0:
            return {key: True, "reason": str(len(active)) + " active access-request workflow template(s)",
                    "templates": [str(r.get("name")) for r in active][:25]}
        if data.get("hasNext") is True:
            return {key: False, "reason": "No active template on the first page and more pages were not read"}
        return {key: False, "reason": "No active access-request workflow template", "templates": len(records)}
    except Exception as e:
        return {key: False, "error": str(e)}
