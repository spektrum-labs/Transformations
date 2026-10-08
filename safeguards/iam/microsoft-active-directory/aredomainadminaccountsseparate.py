# aredomainadminaccountsseparate.py - Microsoft Active Directory (on-premises domain)
#
# Method: getDomainAdminsSnapshot (Integration-Service), one read of the Domain Admins snapshot the Spektrum
# Connector (or the read-only collection script) pushes. The collector's AD account is a plain Domain Users
# member; every attribute below is readable by Authenticated Users by default.
#
# Snapshot shape (schema "spektrum.ad.v1"), domainAdmins:
#   membersComplete  true only when the collector expanded every nested group and did not hit a page cap
#   members[]        one flat record per effective member (nested groups already expanded):
#                    sam, sid, type ("user" | "computer" | "group"), enabled, hasMailbox (msExchMailboxGuid
#                    present or msExchRecipientTypeDetails is a mailbox type), exchangeAttributesReadable,
#                    mailAttribute (the AD "mail" value or null), isBuiltInAdministrator, viaGroup
# The AD-side analogue of a productivity licence / enabled Exchange plan is an Exchange mailbox. A "mail"
# attribute alone is a finding, not a fail (J.J. ruling, 3 Oct 2026).


def transform(input):
    """
    areDomainAdminAccountsSeparate - True only when at least one ENABLED USER is an effective member of
    Domain Admins, the mailbox state of every such member was read, and none has an Exchange mailbox.

    False when any enabled member has an Exchange mailbox: a daily-use mailbox account that also holds
    Domain Admin is not a separate administrative account. The reason names the accounts and the count.

    A member with only a "mail" attribute is a finding (listed in additionalFindings), never a fail.
    Disabled accounts are not judged. Computer accounts and groups are reported as findings.

    Not evaluated (None) when there is no member list, the list is incomplete or capped, no enabled user
    is in it, or no member fails and one or more members' mailbox state could not be read.
    """
    import json
    from datetime import datetime, timezone

    key = "areDomainAdminAccountsSeparate"

    def as_dict(value):
        if isinstance(value, dict):
            return value
        return {}

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def respond(value, extra, passes, fails, summary, errors, findings):
        body = {key: None if errors else value}
        for name in extra:
            body[name] = extra[name]
        return {
            "transformedResponse": body,
            "additionalInfo": {
                "dataCollection": {"status": "error" if errors else "success", "errors": errors},
                "validation": {"status": "unknown", "errors": [], "warnings": []},
                "transformation": {"status": "success", "errors": [], "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails,
                               "recommendations": [], "additionalFindings": findings},
                "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                             "transformationId": key, "vendor": "Microsoft",
                             "product": "Active Directory",
                             "category": "Identity and Access Management"},
            },
        }

    def not_evaluated(reason, extra=None, summary=None, findings=None):
        return respond(None, extra or {}, [], [reason], summary or {}, [reason], findings or [])

    def looks_separate(sam):
        text = sam.lower()
        for prefix in ["adm-", "adm_", "a-", "a_", "admin-", "admin_", "da-", "da_"]:
            if text.startswith(prefix):
                return True
        for suffix in ["-adm", "_adm", "-a", "_a", "-admin", "_admin"]:
            if text.endswith(suffix):
                return True
        return False

    try:
        data = input
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data) if data.strip() else None
        for depth in range(6):
            unwrapped = False
            for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
                if isinstance(data, dict) and wrapper in data and "domainAdmins" not in data:
                    data = data[wrapper]
                    unwrapped = True
                    break
            if not unwrapped:
                break
        if not isinstance(data, dict):
            return not_evaluated("Response is not an Active Directory snapshot")
        if data.get("error") or data.get("errors") or data.get("errorMessage"):
            return not_evaluated("The snapshot service returned an error instead of the Domain Admins list")
        admins = data.get("domainAdmins")
        if not isinstance(admins, dict) or not isinstance(admins.get("members"), list):
            return not_evaluated("The snapshot carries no Domain Admins member list, so the read cannot be shown to have run")
        if admins.get("membersComplete") is not True:
            return not_evaluated("The Domain Admins member list is incomplete (nested groups not fully expanded or capped), "
                                 "so not every administrator was read")

        members = [m for m in admins.get("members") if isinstance(m, dict)]
        users = []
        findings = []
        unclassified = []
        for member in members:
            kind = as_text(member.get("type")).lower()
            name = as_text(member.get("sam")) or as_text(member.get("sid")) or "an account with no name"
            if kind == "computer":
                findings.append("Computer account " + name + " is a Domain Admins member")
                continue
            if kind == "group":
                findings.append("Group " + name + " is listed as a Domain Admins member and was not expanded")
                continue
            if member.get("enabled") is False:
                continue
            if kind == "user" and member.get("enabled") is True:
                users.append(member)
                continue
            # Unrecognised type or an enabled flag that is not a boolean: never dropped silently.
            if member.get("hasMailbox") is True:
                users.append(member)
            else:
                unclassified.append(name)
                findings.append(name + " has an unrecognised account type or no enabled flag and was not judged")

        if not users and unclassified:
            return not_evaluated("Members with an unrecognised type or enabled flag could not be judged: "
                                 + ", ".join(unclassified[:20]), {"domainAdminMembers": len(members), "judgedMembers": 0},
                                 {"membersRead": len(members)}, findings)
        if not users:
            return not_evaluated("No enabled user account is an effective Domain Admins member, so there is nothing to judge",
                                 {"domainAdminMembers": len(members), "judgedMembers": 0},
                                 {"membersRead": len(members)}, findings)

        with_mailbox = []
        mail_only = []
        unreadable = []
        not_pattern = []
        for member in users:
            name = as_text(member.get("sam")) or as_text(member.get("sid")) or "an account with no name"
            readable = member.get("exchangeAttributesReadable") is True
            if member.get("hasMailbox") is True:
                with_mailbox.append(name)
            elif not readable:
                unreadable.append(name)
            elif as_text(member.get("mailAttribute")):
                mail_only.append(name)
            if not looks_separate(name) and member.get("isBuiltInAdministrator") is not True:
                not_pattern.append(name)
        if mail_only:
            findings.append("Mail attribute set but no mailbox (finding, not a fail): " + ", ".join(mail_only[:20]))
        if not_pattern:
            findings.append("Not following a separate-admin naming pattern: " + ", ".join(not_pattern[:20]))

        total = len(users)
        extra = {"domainAdminMembers": len(members), "judgedMembers": total,
                 "membersWithMailbox": len(with_mailbox), "membersWithMailOnly": len(mail_only)}
        summary = {"membersRead": len(members), "enabledUsersJudged": total}
        if with_mailbox:
            percent = int(100 * len(with_mailbox) / total)
            return respond(False, extra, [],
                           [str(len(with_mailbox)) + " of " + str(total) + " enabled Domain Admins members (" + str(percent)
                            + "%) have an Exchange mailbox, so they are daily-use accounts: " + ", ".join(with_mailbox[:20])],
                           summary, [], findings)
        if unreadable or unclassified:
            return not_evaluated("Could not judge: " + ", ".join((unreadable + unclassified)[:20]), extra, summary, findings)
        return respond(True, extra,
                       ["None of " + str(total) + " enabled Domain Admins members has an Exchange mailbox"], [],
                       summary, [], findings)
    except Exception as e:
        return not_evaluated("Could not evaluate the Domain Admins snapshot: the response has an unexpected shape")
