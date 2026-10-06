"""
Transformation: areAdminAccountsSeparate
Vendor: Okta  |  Integrations: Okta (SSWS API token) and Okta - Application (OAuth service app)
Category: Identity and Access Management

Claim (IAM-004 Admin Account Segmentation): every account holding a privileged role in the identity
provider is a dedicated admin account, separate from the person's everyday account: no mailbox and no
productivity licence. Pass = isEquals true.

WHY THIS FILE WAS REWRITTEN. The previous version inspected profile.login values in the user roster for
admin-looking names ("admin", "adm-", ...). A naming convention is not a control: it never read who
holds an admin role, so an everyday account named "jdoe" holding Super Administrator could pass, and a
roster with no admin-looking names failed. This version reads the role holders and what each one uses.

WHAT "SEPARATE" MEANS IN OKTA. Okta has no mailbox of its own: a person's mailbox and productivity suite
are Okta apps (Microsoft Office 365, Google Workspace) assigned to their Okta account. So an Okta admin
account that is also assigned Office 365 or Google Workspace is the account that person reads mail and
works in every day, with admin rights attached: a measured fail. An admin account assigned neither is
a dedicated admin account. Other apps (Slack, Salesforce, Box, ...) are not mailbox or productivity
suites; they are reported as a finding and do not change the verdict. Whether an account is "the
person's primary account" cannot be read from Okta beyond this: the API has no link between two
accounts of one person, and login naming is exactly the heuristic this file replaces.

EVIDENCE. One Integration-Service workflow (getAdminAppAssignments) merges two Okta Management API reads:
  adminAssignees  GET /api/v1/iam/assignees/users ("List all users with role assignments",
                  listUsersWithRoleAssignments): {"value": [{"id", "orn", "_links"}], "_links": {"next"}}.
                  Paged by _links.next.href; with reportPagination IS sets
                  paginationStats.adminAssignees.paginationTruncated (and top-level paginationTruncated
                  when the list was cut off). OAuth scope okta.roles.read.
  adminAppLinks   GET /api/v1/users/{id}/appLinks per admin ("List all assigned app links": every app
                  assigned directly or through group membership), INDEX-ALIGNED with adminAssignees.value:
                  [{"id", "appName", "label", "appInstanceId", "appAssignmentId", "hidden", ...}].
                  With continueOnItemError a failed read is {"error": true, "statusCode", "item", "errorType"};
                  with maxItems the list stops at the cap and iterateTruncated is set. OAuth scope
                  okta.users.read.
Productivity apps are matched on the OIN appName: "office365" (Microsoft Office 365) and "google"
(Google Workspace; Okta's own example labels it "Google Apps Mail").

SCOPES. An SSWS API token is not scoped (it acts with its admin's rights), so the Okta definition needs no
change of credentials. The Okta - Application (OAuth) definition needs okta.roles.read for the first
read; it is requested on that method only, so an org that has not granted it gets "not evaluated" for
this check and nothing else changes. okta.users.read is already granted.

FAIL CLOSED. Null, {}, an error envelope, no admin role assignment list (for example okta.roles.read
not granted), an empty admin list (every org has a Super Administrator), app-link reads missing, capped,
failed or out of line with the admin list, or an IS build that does not report whether the admin list
was read in full, returns areAdminAccountsSeparate = None with a dataCollection error ("not evaluated").
One admin shown to hold Office 365 or Google Workspace is a measured fail, whatever else is partial,
unless the pairing of admins and app-link reads cannot be trusted, in which case nothing is concluded.
"""
import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('areAdminAccountsSeparate',)

KEY = "areAdminAccountsSeparate"
META = {"transformationId": KEY, "vendor": "Okta", "category": "iam"}
PRODUCTIVITY_APP_NAMES = ["office365", "google"]
WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output"]
MAX_NAMED = 20
MAX_AFFECTED = 50


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for attempt in range(3):
            unwrapped = False
            for key in WRAPPER_KEYS:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    response_metadata.update(META)
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def read_error(block):
    """A short reason when a read came back as an error instead of data, else None."""
    if not isinstance(block, dict):
        return None
    marked = block.get("vendorErrorAsResponse")
    if isinstance(marked, dict):
        return "Okta answered HTTP " + str(marked.get("status"))[:8]
    if block.get("error") or block.get("errorCode"):
        code = block.get("statusCode") or block.get("status_code") or block.get("errorCode") or ""
        return "the read returned an error " + str(code)[:20]
    for key in ["statusCode", "status_code"]:
        code = block.get(key)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Okta answered HTTP " + str(code)
    return None


def is_item_error(entry):
    return isinstance(entry, dict) and entry.get("error") is True


def link_list(entry):
    """One admin's app links, or None when the slot is not an app-link list."""
    if isinstance(entry, list):
        if all(isinstance(e, dict) for e in entry):
            return entry
        return None
    if isinstance(entry, dict) and not read_error(entry):
        for wrap in ("value", "data", "apiResponse", "rawResponse"):
            if isinstance(entry.get(wrap), list) and all(isinstance(e, dict) for e in entry.get(wrap)):
                return entry.get(wrap)
    return None


def flag(data, top_key, stats_key, output_key):
    """True / False from a workflow marker, or None when this IS build did not report it."""
    if data.get(top_key) is True:
        return True
    stats = data.get(stats_key)
    block = stats.get(output_key) if isinstance(stats, dict) else None
    if isinstance(block, dict) and isinstance(block.get(top_key), bool):
        return block.get(top_key)
    return None


def misalignment(data, rows, slots, reads_cut):
    """Why the index pairing of admins and app-link slots cannot be trusted, or None when it can."""
    if len(slots) > len(rows):
        return str(len(slots)) + " app-link results for " + str(len(rows)) + " admins"
    if reads_cut is not True:
        if len(slots) < len(rows):
            return str(len(slots)) + " app-link results for " + str(len(rows)) + " admins with no read cap"
        stats = data.get("iterateStats")
        block = stats.get("adminAppLinks") if isinstance(stats, dict) else None
        total = block.get("itemsTotal") if isinstance(block, dict) else None
        if isinstance(total, int) and not isinstance(total, bool) and total != len(rows):
            return "the workflow iterated " + str(total) + " admins but listed " + str(len(rows))
    for index, entry in enumerate(slots):
        row = rows[index]
        admin_id = str(row.get("id") or "").strip() if isinstance(row, dict) else ""
        if not admin_id:
            continue
        if is_item_error(entry):
            item = entry.get("item")
            if isinstance(item, str) and item.strip() and item.strip() != admin_id:
                return "a failed read names a different user than the admin in its position"
            continue
        links = link_list(entry)
        for link in links or []:
            owner = str(link.get("id") or "").strip()
            # An AssignedAppLink's id is the user's id (00u...) in Okta's own example.
            if owner.startswith("00u") and owner != admin_id:
                return "an app link belongs to a different user than the admin in its position"
    return None


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def not_evaluated(validation, reason, summary=None, findings=None):
    return create_response(
        result={KEY: None, "adminCount": None, "adminsWithProductivityApps": None},
        validation=validation, api_errors=[reason],
        fail_reasons=["Admin account separation was not evaluated: " + reason],
        recommendations=["Grant the Okta integration okta.roles.read (OAuth) or use an API token, so the admin role "
                         "holders and their assigned apps can be read in full"],
        input_summary=summary or {}, additional_findings=findings or [])


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_evaluated(validation, "input validation failed: " + "; ".join(validation.get("errors", [])))
        if not isinstance(data, dict) or "adminAssignees" not in data:
            reason = read_error(data) if isinstance(data, dict) else None
            return not_evaluated(validation, (reason + ": " if reason else "") + "no admin role assignment list "
                                 "(GET /api/v1/iam/assignees/users) in the response, so who holds an Okta admin role "
                                 "is unknown")

        block = data.get("adminAssignees")
        rows = block.get("value") if isinstance(block, dict) else (block if isinstance(block, list) else None)
        if isinstance(block, dict) and read_error(block):
            return not_evaluated(validation, "the admin role assignments were not read (" + read_error(block)
                                 + "); the OAuth integration needs okta.roles.read")
        if not isinstance(rows, list):
            return not_evaluated(validation, "the admin role assignments were not read; the OAuth integration needs "
                                             "okta.roles.read")
        if not rows:
            return not_evaluated(validation, "Okta returned no users holding an admin role; every org has a Super "
                                             "Administrator, so the list cannot be complete")

        slots = data.get("adminAppLinks")
        if not isinstance(slots, list):
            return not_evaluated(validation, "the admins' assigned app links (GET /api/v1/users/{id}/appLinks) were "
                                             "not read")

        list_cut = flag(data, "paginationTruncated", "paginationStats", "adminAssignees")
        reads_cut = flag(data, "iterateTruncated", "iterateStats", "adminAppLinks")
        misaligned = misalignment(data, rows, slots, reads_cut)
        if misaligned:
            return not_evaluated(validation, "the per-admin app-link reads are out of line with the admin list ("
                                 + misaligned + "), so no app can be matched to its admin",
                                 {"adminsListed": len(rows), "appLinkSlots": len(slots)})

        everyday = []
        other_apps = {}
        dedicated = 0
        unreadable = 0
        for index, row in enumerate(rows):
            admin_id = str(row.get("id") or "").strip()[:64] if isinstance(row, dict) else ""
            if not admin_id:
                unreadable = unreadable + 1
                continue
            entry = slots[index] if index < len(slots) else None
            links = None if (entry is None or is_item_error(entry)) else link_list(entry)
            if links is None:
                unreadable = unreadable + 1
                continue
            names = [str(link.get("appName") or "").strip().lower() for link in links]
            productivity = [n for n in names if n in PRODUCTIVITY_APP_NAMES]
            if productivity:
                everyday.append(admin_id + " (" + ", ".join(sorted(set(productivity))) + ")")
            else:
                dedicated = dedicated + 1
                for n in names:
                    if n:
                        other_apps[n] = True

        assessed = len(everyday) + dedicated
        summary = {"adminsListed": len(rows), "adminsAssessed": assessed, "dedicatedAdmins": dedicated,
                   "adminsWithProductivityApps": len(everyday), "adminsUnreadable": unreadable,
                   "adminListComplete": list_cut is False, "appLinkReadsCapped": reads_cut is True,
                   "affectedAccounts": everyday[:MAX_AFFECTED], "affectedAccountCount": len(everyday)}
        findings = []
        if other_apps:
            findings.append("Dedicated admin accounts are assigned other (non-mailbox, non-productivity) apps: "
                            + name_list(sorted(other_apps)))

        if everyday:
            reason = (str(len(everyday)) + " of " + str(assessed) + " Okta admin account(s) assessed are also "
                      "assigned Microsoft Office 365 or Google Workspace, so they are everyday mailbox accounts "
                      "rather than dedicated admin accounts (Okta user ids): " + name_list(everyday))
            if list_cut is not False or reads_cut is True or unreadable:
                reason = reason + "; not every admin could be read, so more may be affected"
            return create_response(
                result={KEY: False, "adminCount": assessed, "adminsWithProductivityApps": len(everyday)},
                validation=validation, fail_reasons=[reason],
                recommendations=["Give each administrator a separate Okta admin account with no Office 365 or Google "
                                 "Workspace assignment, and remove admin roles from everyday accounts"],
                input_summary=summary, additional_findings=findings)

        whys = []
        if list_cut is None:
            whys.append("this Integration-Service build did not report whether the admin list was read in full")
        elif list_cut:
            whys.append("the admin role assignment list was cut off before its last page")
        if reads_cut is True:
            whys.append("the per-admin app-link reads were capped before every admin was read")
        if unreadable:
            whys.append(str(unreadable) + " admin(s)' assigned apps could not be read")
        if whys:
            return not_evaluated(validation, "no admin read so far holds Office 365 or Google Workspace, but "
                                 + "; ".join(whys), summary, findings)

        return create_response(
            result={KEY: True, "adminCount": assessed, "adminsWithProductivityApps": 0},
            validation=validation,
            pass_reasons=["All " + str(assessed) + " Okta admin account(s) are dedicated: none is assigned Microsoft "
                          "Office 365 or Google Workspace"],
            input_summary=summary, additional_findings=findings)
    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return create_response(
            result={KEY: None, "adminCount": None, "adminsWithProductivityApps": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[message], api_errors=[message], fail_reasons=[message])
