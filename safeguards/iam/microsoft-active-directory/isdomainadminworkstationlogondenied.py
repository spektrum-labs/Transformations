# isdomainadminworkstationlogondenied.py - Microsoft Active Directory (on-premises domain)
#
# Method: getLogonRightsSnapshot (Integration-Service), one read of the logon-rights snapshot the Spektrum
# Connector (or the read-only collection script) pushes. Collected with a Domain Users account: GPO objects,
# OU gPLink attributes and SYSVOL GptTmpl.inf files are readable by Authenticated Users by default.
#
# Snapshot shape (schema "spektrum.ad.v1"):
#   domainSid                   e.g. S-1-5-21-1-2-3 (Domain Admins is <domainSid>-512)
#   logonRights.gposComplete    true only when every GPO in the domain was read
#   logonRights.gpos[]          displayName, enabled (computer settings on), appliesTo ("authenticated" |
#                               "filtered" | "unknown"), wmiFiltered, denyInteractive[], denyRemoteInteractive[]
#                               (SIDs as strings, or {sid, containsDomainAdmins}), links[{scopeDn, enabled, enforced}]
#   logonRights.ouInheritanceReadable   true when workstationOus carries the inheritance picture
#   logonRights.workstationOus[]        dn, enabledWorkstations, inheritanceBlockedAt[] (DNs at or above the OU,
#                                       up to the domain root, where Block Inheritance is set)
# Domain controllers and member servers are out of scope: the check speaks for workstations only.


def transform(input):
    """
    isDomainAdminWorkstationLogonDenied - True only when every enabled workstation sits in an OU where an
    enabled, unfiltered GPO denies Domain Admins BOTH "Deny log on locally" and "Deny log on through Remote
    Desktop Services" (Microsoft tier-0 guidance denies both).

    False when the whole GPO set was read and either no GPO denies Domain Admins both rights, or at least one
    enabled workstation is not covered. The verdict travels with its denominator: workstationsCovered of
    workstationsTotal and coveragePercentage.

    Not evaluated (None) when the GPO set is incomplete, the domain SID or workstation picture is missing or
    unreadable, there are no enabled workstations, or the only GPOs that could cover the rest are security- or
    WMI-filtered so their scope cannot be resolved.
    """
    import json
    from datetime import datetime, timezone

    key = "isDomainAdminWorkstationLogonDenied"

    def as_dict(value):
        if isinstance(value, dict):
            return value
        return {}

    def as_list(value):
        if isinstance(value, list):
            return value
        return []

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

    def under(dn, parent):
        return as_text(dn).lower().endswith("," + as_text(parent).lower())

    def same(a, b):
        return as_text(a).lower() == as_text(b).lower()

    def denies(entries, admin_sid):
        for entry in as_list(entries):
            if isinstance(entry, dict):
                if as_text(entry.get("sid")).lower() == admin_sid.lower() or entry.get("containsDomainAdmins") is True:
                    return True
            elif as_text(entry).lower() == admin_sid.lower():
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
                if isinstance(data, dict) and wrapper in data and "logonRights" not in data:
                    data = data[wrapper]
                    unwrapped = True
                    break
            if not unwrapped:
                break
        if not isinstance(data, dict):
            return not_evaluated("Response is not an Active Directory snapshot")
        if data.get("error") or data.get("errors") or data.get("errorMessage"):
            return not_evaluated("The snapshot service returned an error instead of the logon-rights data")
        rights = data.get("logonRights")
        domain_sid = as_text(data.get("domainSid"))
        if not isinstance(rights, dict) or not isinstance(rights.get("gpos"), list) or not domain_sid:
            return not_evaluated("The snapshot carries no GPO logon-rights data or no domain SID, so the read cannot be shown to have run")
        if rights.get("gposComplete") is not True:
            return not_evaluated("The GPO list is incomplete, so a GPO that denies logon could be missing")

        admin_sid = domain_sid + "-512"
        clean = []
        filtered = []
        findings = []
        for gpo in as_list(rights.get("gpos")):
            if not isinstance(gpo, dict) or gpo.get("enabled") is not True:
                continue
            name = as_text(gpo.get("displayName")) or "a GPO with no name"
            local = denies(gpo.get("denyInteractive"), admin_sid)
            remote = denies(gpo.get("denyRemoteInteractive"), admin_sid)
            if local and remote:
                if gpo.get("appliesTo") == "authenticated" and gpo.get("wmiFiltered") is not True:
                    clean.append(gpo)
                else:
                    filtered.append(name)
            elif local or remote:
                findings.append("GPO " + name + " denies Domain Admins only "
                                + ("locally" if local else "through Remote Desktop Services") + ", not both")

        ous = [o for o in as_list(rights.get("workstationOus")) if isinstance(o, dict)]
        total = 0
        for ou in ous:
            count = ou.get("enabledWorkstations")
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                total = total + count
        picture = rights.get("ouInheritanceReadable") is True and len(ous) > 0 and total > 0

        if not clean and not filtered:
            extra = {"workstationsTotal": total if picture else None, "workstationsCovered": 0,
                     "coveragePercentage": 0 if picture else None}
            return respond(False, extra, [],
                           ["No enabled GPO denies Domain Admins both local and Remote Desktop Services logon on workstations"],
                           {"gposRead": len(as_list(rights.get("gpos")))}, [], findings)
        if not picture:
            return not_evaluated("The workstation OU picture is missing or unreadable, or there are no enabled workstations, "
                                 "so coverage cannot be measured", {}, {"workstationOus": len(ous)}, findings)

        covered = 0
        uncovered = []
        for ou in ous:
            count = ou.get("enabledWorkstations")
            if not (isinstance(count, int) and not isinstance(count, bool) and count > 0):
                continue
            dn = as_text(ou.get("dn"))
            blocked = [as_text(b) for b in as_list(ou.get("inheritanceBlockedAt"))]
            hit = False
            for gpo in clean:
                for link in as_list(gpo.get("links")):
                    if not isinstance(link, dict) or link.get("enabled") is not True:
                        continue
                    scope = as_text(link.get("scopeDn"))
                    if same(scope, dn):
                        hit = True
                    elif under(dn, scope):
                        stopped = False
                        for b in blocked:
                            if under(b, scope) or (same(b, dn) and not same(b, scope)):
                                stopped = True
                        if not stopped or link.get("enforced") is True:
                            hit = True
            if hit:
                covered = covered + count
            else:
                uncovered.append(dn + " (" + str(count) + ")")
        percent = int(100 * covered / total)
        extra = {"workstationsTotal": total, "workstationsCovered": covered, "coveragePercentage": percent}
        summary = {"workstationOus": len(ous), "denyingGpos": len(clean), "filteredDenyingGpos": len(filtered)}
        if covered == total:
            return respond(True, extra,
                           ["Domain Admins are denied local and Remote Desktop Services logon on all " + str(total)
                            + " enabled workstations"], [], summary, [], findings)
        if filtered:
            return not_evaluated("Uncovered workstation OUs may be covered by security- or WMI-filtered GPO(s) whose scope "
                                 "cannot be resolved: " + ", ".join(filtered[:10]), extra, summary, findings)
        return respond(False, extra, [],
                       [str(total - covered) + " of " + str(total) + " enabled workstations (" + str(100 - percent)
                        + "%) are not covered by a GPO that denies Domain Admins logon: " + ", ".join(uncovered[:20])],
                       summary, [], findings)
    except Exception as e:
        return not_evaluated("Could not evaluate the logon-rights snapshot: the response has an unexpected shape")
