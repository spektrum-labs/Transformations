# islifecyclemanagementenabled.py - Okta
#
# Method: getApplications -> GET /api/v1/apps   (scope okta.apps.read)
# Docs:   https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/#tag/Application/operation/listApplications
#         Application.features: "Enabled app features" (PUSH_NEW_USERS, PUSH_USER_DEACTIVATION,
#         IMPORT_NEW_USERS, ...), Application.status ACTIVE|INACTIVE
#
# Replaces a read of /api/v1/org/factors (the workflow routed this key to the MFA factor catalogue)
# through affirmative_signal, which could never be True for that list.


def transform(input):
    """
    isLifeCycleManagementEnabled is True when Okta automates both ends of the account lifecycle
    for at least one ACTIVE app:
      * joiner: some ACTIVE app has PUSH_NEW_USERS (Okta creates accounts downstream) or
        IMPORT_NEW_USERS (an HR or directory source feeds Okta);
      * leaver: some ACTIVE app has PUSH_USER_DEACTIVATION (Okta deactivates the downstream
        account when the Okta user is deactivated).

    Fails closed on an error body, a non-list body, or no apps.
    Does not prove: that every app is provisioned (apps without these features keep manual
    accounts), or how quickly leavers are deactivated in Okta itself. /api/v1/apps is paged (default
    page 20); a later page can only add evidence, never remove it, so paging cannot cause a false pass.
    """
    import json
    from datetime import datetime

    key = "isLifeCycleManagementEnabled"

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def respond(value, passes, fails, summary, errors):
        return {
            "transformedResponse": {key: value},
            "additionalInfo": {
                "dataCollection": {"status": "success", "errors": []},
                "validation": {"status": "error" if errors else "success", "errors": [], "warnings": []},
                "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails,
                               "recommendations": [] if value else ["Enable provisioning with user deactivation (Push New Users + Deactivate Users) on your core apps"],
                               "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                             "transformationId": key, "vendor": "Okta", "category": "Identity"},
            },
        }

    try:
        data = input
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data)
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data:
                data = data[wrapper]
        if isinstance(data, dict):
            for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
                if data.get(k):
                    return respond(False, [], ["Okta returned an error: " + as_text(data.get(k))[:200]], {}, [])
            return respond(False, [], ["Response is not a list of apps"], {}, [])
        if not isinstance(data, list):
            return respond(False, [], ["Response is not a list of apps"], {}, [])
        apps = [a for a in data if isinstance(a, dict) and as_text(a.get("status")).upper() == "ACTIVE"]
        if not apps:
            return respond(False, [], ["No active apps were returned"], {"appsReturned": len(data)}, [])

        joiner = []
        leaver = []
        for app in apps:
            features = app.get("features") if isinstance(app.get("features"), list) else []
            names = [as_text(f).upper() for f in features]
            label = as_text(app.get("label")) or as_text(app.get("name"))
            if "PUSH_NEW_USERS" in names or "IMPORT_NEW_USERS" in names:
                joiner.append(label)
            if "PUSH_USER_DEACTIVATION" in names:
                leaver.append(label)
        summary = {"activeApps": len(apps), "joinerAutomatedApps": joiner, "leaverAutomatedApps": leaver}
        fails = []
        if not joiner:
            fails.append("No active app creates or imports accounts automatically")
        if not leaver:
            fails.append("No active app deactivates downstream accounts automatically")
        if fails:
            return respond(False, [], fails, summary, [])
        return respond(True, ["Automated provisioning: " + ", ".join(joiner[:5]) + "; automated deprovisioning: " + ", ".join(leaver[:5])],
                       [], summary, [])
    except Exception as e:
        return respond(False, [], ["Transformation error: " + str(e)], {}, [str(e)])
