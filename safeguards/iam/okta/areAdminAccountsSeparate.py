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

A PASS NEEDS EVIDENCE THAT COULD HAVE FAILED. "No admin holds a mailbox app" means something only when
the organisation's mailbox is reached through Okta at all. Many orgs master mail in Entra ID or Google
directly, or never federate it; there every admin would read "dedicated" while nothing was learned. So
True is returned only with one of these, strongest first:
  * sampleUserAppLinks (optional, PREFERRED) holds a productivity app link for a user who is not an
    admin: the suite IS assigned to everyday users through Okta;
  * orgApps (optional) holds an ACTIVE productivity app (see MATCHING) that carries an assignment signal
    showing it is assigned to at least one user (assignedUserCount > 0, or a non-empty
    _embedded.users / assignedUsers list, e.g. merged from GET /api/v1/apps/{id}/users?limit=1);
  * orgApps holds an ACTIVE productivity app that carries no assignment signal (a signal field that is
    present but malformed counts as "no user", not as "no signal"). This is the weakest
    evidence: it shows only that an active productivity app EXISTS in Okta, not that everyday users
    reach their mailbox through it, and the pass reason says exactly that.
An org app whose assignment signal shows NO user is not evidence. Otherwise the result is None (not
evaluated): the org's mailbox app is not shown to be in Okta, so separation cannot be shown from Okta
(judge it in the Entra ID or Google Workspace integration).

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
  orgApps         OPTIONAL. GET /api/v1/apps?filter=status eq "ACTIVE" (listApplications, scope
                  okta.apps.read): [{"id", "name", "label", "status", "signOnMode"}], or {"value": [...]}.
                  Only rows with status ACTIVE count. Optional per-row assignment signal (read when
                  present): assignedUserCount, or _embedded.users / assignedUsers. Missing, failed or
                  partial: it gives no evidence (a partial list that already shows an active productivity
                  app is still evidence).
  sampleUserAppLinks
                  OPTIONAL. GET /api/v1/users/{id}/appLinks for a page of ACTIVE users (for example
                  GET /api/v1/users?filter=status eq "ACTIVE"&limit=200, iterated): a list of app-link
                  lists, the same shape as adminAppLinks. A slot whose echoed item or link id names an
                  admin is skipped. Because a pass is only reached after EVERY admin was read and none
                  holds a productivity app, a productivity link anywhere in this sample belongs to a
                  non-admin user.
Neither optional field is produced by the getAdminAppAssignments workflow as first specified; when both
are absent the check is not evaluated rather than passed.

MATCHING. An app link (appName, label) or an org app (name, label) is a productivity app when:
  * its OIN name is exactly "office365" (Microsoft Office 365) or "google" (Google Workspace; Okta's own
    example labels it "Google Apps Mail"), case-insensitive; or
  * its name or label contains, as whole words (case-insensitive; any non-alphanumeric character,
    including "_", separates words), one of: office 365, microsoft 365, google workspace, g suite, gmail,
    the run-together forms office365, microsoft365, gsuite, googleworkspace, or the qualified Exchange /
    Outlook phrases exchange online, microsoft exchange, exchange server, microsoft outlook, outlook web,
    outlook com, owa; or
  * its whole name or label is just "Exchange" or "Outlook". A bare "exchange" or "outlook" inside a
    longer label is NOT matched: "Partner Exchange" or "Data Exchange" is not a mailbox, and matching it
    would make it false pass evidence in orgApps and a false fail on an admin.
This catches custom SAML / WS-Fed / bookmark apps such as "Microsoft 365 (SAML)", "Exchange Online" or
appName "contoso_microsoft365_1". A bare "google" in a label is NOT matched (Google Analytics, Google
Cloud are not mailboxes).

PAIRING. adminAppLinks is paired with adminAssignees.value by position. When a slot echoes the user it
was read for (an IS item-error record's "item", or a "userId" on the slot), a mismatch with the admin in
that position makes the pairing untrusted and nothing is concluded. An AssignedAppLink's own "id" equals
the user's id in Okta's example payload, but the schema does not promise it, so a link id that differs
from its admin's id is a hint: reported as a finding while only SOME slots mismatch. When no slot echoes
a user and EVERY slot that carries a 00u link id mismatches its admin, the reads are most likely not the
admins' at all, so the verdict is withheld (None).

SCOPES. An SSWS API token is not scoped (it acts with its admin's rights), so the Okta definition needs no
change of credentials. The Okta - Application (OAuth) definition needs okta.roles.read for the first
read; it is requested on that method only, so an org that has not granted it gets "not evaluated" for
this check and nothing else changes. okta.users.read is already granted.

FAIL CLOSED. Null, {}, an error envelope, no admin role assignment list (for example okta.roles.read
not granted), an empty admin list (every org has a Super Administrator), app-link reads missing, capped,
failed or out of line with the admin list (by count, iterateStats.itemsTotal or an echoed user id), an
IS build that does not report whether the admin list was read in full, or no evidence that the org's
productivity suite is assigned through Okta, returns areAdminAccountsSeparate = None with a
dataCollection error ("not evaluated"). One admin shown to hold a productivity app is a measured fail,
whatever else is partial, unless the pairing of admins and app-link reads cannot be trusted, in which
case nothing is concluded.

LIMITS.
  * Group-granted admin roles: an admin who holds a role only through group membership is judged only if
    GET /api/v1/iam/assignees/users lists that user. Okta documents the endpoint as "users with role
    assignments"; whether it includes group-granted roles is UNVERIFIED against a live tenant. If it does
    not, such admins are not judged and nothing in the read says so.
  * Mailbox apps assigned outside Okta, or under names none of the MATCHING terms cover, are not seen.
"""
import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('areAdminAccountsSeparate',)

KEY = "areAdminAccountsSeparate"
META = {"transformationId": KEY, "vendor": "Okta", "category": "iam"}
PRODUCTIVITY_OIN_NAMES = ["office365", "google"]
PRODUCTIVITY_TERMS = ["office 365", "microsoft 365", "google workspace", "g suite", "gmail",
                      "office365", "microsoft365", "gsuite", "googleworkspace",
                      "exchange online", "microsoft exchange", "exchange server", "microsoft outlook", "outlook web",
                      "outlook com", "owa"]
# Ambiguous alone ("Partner Exchange", "Data Exchange"): a match only when they are the whole name or label.
WHOLE_LABEL_TERMS = ["exchange", "outlook"]
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


def words(text):
    """Lower-case whole words of a name or label; any non-alphanumeric character separates words."""
    chars = []
    for ch in str(text or "").lower():
        chars.append(ch if ch.isalnum() else " ")
    return "".join(chars).split()


def productivity_match(app_name, label):
    """What makes an app a mailbox / productivity app (its OIN name or the matched term), or ""."""
    name = str(app_name or "").strip().lower()
    if name in PRODUCTIVITY_OIN_NAMES:
        return name
    for text in [app_name, label]:
        joined = " ".join(words(text))
        if joined in WHOLE_LABEL_TERMS:
            return joined
        padded = " " + joined + " "
        for term in PRODUCTIVITY_TERMS:
            if " " + term + " " in padded:
                return term
    return ""


def app_display(app_name, label):
    name = str(app_name or "").strip().lower()
    if name in PRODUCTIVITY_OIN_NAMES:
        return name
    return str(label or app_name or "unnamed app").strip()[:60]


def echoed_id(entry):
    """The user id a slot says it was read for (IS item-error "item", or "userId"), else ""."""
    if not isinstance(entry, dict):
        return ""
    for key in ["item", "userId"]:
        value = entry.get(key)
        if isinstance(value, dict):
            value = value.get("userId") or value.get("id")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def misalignment(data, rows, slots, reads_cut):
    """Why the position pairing of admins and app-link slots cannot be trusted, or None when it can."""
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
        echoed = echoed_id(entry)
        if admin_id and echoed and echoed != admin_id:
            return "a read names a different user than the admin in its position"
    if not [entry for entry in slots if echoed_id(entry)]:
        mismatched, carrying = link_id_hints(rows, slots)
        if carrying and mismatched == carrying:
            return ("every one of the " + str(carrying) + " app-link read(s) that carry a user id (00u...) names a "
                    "different user than the admin in its position, and no read echoes its user")
    return None


def link_id_hints(rows, slots):
    """(mismatched, carrying): slots whose app links carry a 00u... id, and how many of those differ from
    the admin in that position.

    Okta's example AssignedAppLink carries the user's id, but the schema does not promise it, so a partial
    mismatch is a hint for the operator. Only a mismatch on every id-carrying slot (with no echoed user
    anywhere) withholds the verdict; see misalignment()."""
    mismatched = 0
    carrying = 0
    for index, entry in enumerate(slots):
        if index >= len(rows) or is_item_error(entry) or echoed_id(entry):
            continue
        row = rows[index]
        admin_id = str(row.get("id") or "").strip() if isinstance(row, dict) else ""
        if not admin_id:
            continue
        owners = [str(link.get("id") or "").strip() for link in link_list(entry) or []]
        owners = [o for o in owners if o.startswith("00u")]
        if not owners:
            continue
        carrying = carrying + 1
        if [o for o in owners if o != admin_id]:
            mismatched = mismatched + 1
    return mismatched, carrying


def assignment_signal(app):
    """True / False when an org app row says whether any user is assigned to it, None when it does not say.

    A signal field that is PRESENT but malformed (a non-numeric or bool count, a non-list users value) is
    read as False: the row claims to say something about assignment and cannot be trusted to say "assigned",
    so the app is not evidence. A numeric string count ("0", "3") or a whole float is converted."""
    if "assignedUserCount" in app:
        count = app.get("assignedUserCount")
        if isinstance(count, str) and count.strip().isdigit():
            count = int(count.strip())
        if isinstance(count, float) and count == int(count):
            count = int(count)
        if isinstance(count, int) and not isinstance(count, bool):
            return count > 0
        return False
    for holder, key in [(app.get("_embedded"), "users"), (app, "assignedUsers")]:
        if isinstance(holder, dict) and key in holder:
            users = holder.get(key)
            return isinstance(users, list) and len(users) > 0
    if "_embedded" in app and not isinstance(app.get("_embedded"), dict):
        return False
    return None


def org_suite_apps(data):
    """(assigned, unsignalled) active productivity apps in the optional orgApps read, or None when not read.

    assigned: the row shows at least one assigned user. unsignalled: the row says nothing about assignment.
    A row whose signal shows no assigned user is in neither list (it is not evidence)."""
    block = data.get("orgApps")
    if isinstance(block, dict):
        if read_error(block):
            return None
        block = block.get("value")
    if not isinstance(block, list):
        return None
    assigned = []
    unsignalled = []
    for app in block:
        if not isinstance(app, dict) or str(app.get("status") or "").strip().upper() != "ACTIVE":
            continue
        if not productivity_match(app.get("name"), app.get("label")):
            continue
        signal = assignment_signal(app)
        if signal is True:
            assigned.append(app_display(app.get("name"), app.get("label")))
        elif signal is None:
            unsignalled.append(app_display(app.get("name"), app.get("label")))
    return assigned, unsignalled


def sample_suite_users(data, admin_ids):
    """How many non-admin users in the optional sampleUserAppLinks read hold a productivity app, or None."""
    slots = data.get("sampleUserAppLinks")
    if not isinstance(slots, list):
        return None
    count = 0
    for entry in slots:
        if is_item_error(entry) or echoed_id(entry) in admin_ids:
            continue
        links = link_list(entry)
        if not links:
            continue
        owners = [str(link.get("id") or "").strip() for link in links]
        if [o for o in owners if o and o in admin_ids]:
            continue
        if [link for link in links if productivity_match(link.get("appName"), link.get("label"))]:
            count = count + 1
    return count


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def not_evaluated(validation, reason, summary=None, findings=None, recommendations=None):
    return create_response(
        result={KEY: None, "adminCount": None, "adminsWithProductivityApps": None},
        validation=validation, api_errors=[reason],
        fail_reasons=["Admin account separation was not evaluated: " + reason],
        recommendations=recommendations or [
            "Grant the Okta integration okta.roles.read (OAuth) or use an API token, so the admin role holders and "
            "their assigned apps can be read in full"],
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
            productivity = []
            names = []
            for link in links:
                if productivity_match(link.get("appName"), link.get("label")):
                    productivity.append(app_display(link.get("appName"), link.get("label")))
                else:
                    names.append(str(link.get("appName") or "").strip().lower()[:60])
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
        hinted = link_id_hints(rows, slots)[0]
        if hinted:
            findings.append(str(hinted) + " app-link read(s) carry a link id (00u...) different from the admin in "
                            "their position. Okta does not document AssignedAppLink.id as the user id, so admins "
                            "and reads are paired by workflow order and this is reported as a hint only")
        if other_apps:
            findings.append("Dedicated admin accounts are assigned other (non-mailbox, non-productivity) apps: "
                            + name_list(sorted(other_apps)))

        if everyday:
            reason = (str(len(everyday)) + " of " + str(assessed) + " Okta admin account(s) assessed are also "
                      "assigned a mailbox or productivity app (Microsoft 365 / Office 365, Exchange, Outlook, "
                      "Google Workspace or Gmail), so they are everyday mailbox accounts rather than dedicated "
                      "admin accounts (Okta user ids): " + name_list(everyday))
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
            return not_evaluated(validation, "no admin read so far holds a mailbox or productivity app, but "
                                 + "; ".join(whys), summary, findings)

        admin_ids = {}
        for row in rows:
            if isinstance(row, dict) and str(row.get("id") or "").strip():
                admin_ids[str(row.get("id")).strip()] = True
        org_apps = org_suite_apps(data)
        assigned_apps = org_apps[0] if org_apps is not None else []
        unsignalled_apps = org_apps[1] if org_apps is not None else []
        sample_users = sample_suite_users(data, admin_ids)
        summary["orgProductivityApps"] = None if org_apps is None else len(assigned_apps) + len(unsignalled_apps)
        summary["orgProductivityAppsWithAssignments"] = None if org_apps is None else len(assigned_apps)
        summary["nonAdminUsersWithProductivityApps"] = sample_users
        # Strongest evidence first: everyday users holding the suite, then an assigned org app, then an app
        # that only exists.
        evidence = []
        if sample_users:
            evidence.append(str(sample_users) + " non-admin user(s) read are assigned a productivity app through "
                            "Okta")
        if assigned_apps:
            evidence.append("active productivity app(s) in Okta are assigned to users: "
                            + name_list(sorted(set(assigned_apps))))
        if unsignalled_apps and not (sample_users or assigned_apps):
            evidence.append("an active productivity app exists in Okta (" + name_list(sorted(set(unsignalled_apps)))
                            + "); whether everyday users are assigned to it was not read")
        summary["suiteEvidence"] = ("nonAdminUsers" if sample_users else "assignedOrgApp" if assigned_apps
                                    else "activeOrgApp" if unsignalled_apps else None)
        if not evidence:
            read = []
            read.append("orgApps not read" if org_apps is None
                        else "no active productivity app in orgApps, or only ones shown to have no assigned user")
            read.append("sampleUserAppLinks not read" if sample_users is None
                        else "no non-admin user in sampleUserAppLinks holds one")
            return not_evaluated(
                validation, "no admin holds a mailbox or productivity app, but the org's mail app is not shown to "
                "be assigned through Okta (" + "; ".join(read) + "), so separation cannot be shown: an everyday "
                "account would look the same", summary, findings,
                ["If the organisation's mailbox (Microsoft 365, Google Workspace) is assigned through Okta, add the "
                 "org app list (GET /api/v1/apps, okta.apps.read) to the workflow as orgApps; otherwise judge admin "
                 "separation in the mailbox provider's own integration"])

        return create_response(
            result={KEY: True, "adminCount": assessed, "adminsWithProductivityApps": 0},
            validation=validation,
            pass_reasons=["All " + str(assessed) + " Okta admin account(s) are dedicated: none is assigned a mailbox "
                          "or productivity app, while " + "; ".join(evidence)],
            input_summary=summary, additional_findings=findings)
    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return create_response(
            result={KEY: None, "adminCount": None, "adminsWithProductivityApps": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[message], api_errors=[message], fail_reasons=[message])
