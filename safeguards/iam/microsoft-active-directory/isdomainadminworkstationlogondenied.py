# isdomainadminworkstationlogondenied.py - Microsoft Active Directory (on-premises domain)
#
# Method: getLogonRightsSnapshot (Integration-Service), one read of the logon-rights snapshot the Spektrum
# Connector (or the read-only collection script) pushes. Collected with a Domain Users account: GPO objects,
# OU gPLink attributes and SYSVOL GptTmpl.inf files are readable by Authenticated Users by default.
#
# Snapshot shape (schema "spektrum.ad.v1"):
#   domainSid                   e.g. S-1-5-21-1-2-3 (Domain Admins is <domainSid>-512)
#   logonRights.gposComplete    true only when every GPO in the domain was read
#   logonRights.gpos[]          EVERY GPO that defines either right (not only those denying Domain Admins): displayName, enabled (computer settings on), appliesTo ("authenticated" |
#                               "filtered" | "unknown"), wmiFiltered, denyInteractive[], denyRemoteInteractive[]
#                               (SIDs as strings, or {sid, containsDomainAdmins}), links[{scopeDn, enabled, enforced, linkOrder}]
#   logonRights.ouInheritanceReadable   true when workstationOus carries the inheritance picture
#   logonRights.workstationOus[]        dn, enabledWorkstations, inheritanceBlockedAt[] (DNs at or above the OU,
#                                       up to the domain root, where Block Inheritance is set)
# Domain controllers and member servers are out of scope: the check speaks for workstations only.


def transform(input):
    """
    isDomainAdminWorkstationLogonDenied - True only when, for every enabled workstation OU, the GPO that WINS each
    of "Deny log on locally" and "Deny log on through Remote Desktop Services" denies Domain Admins.

    User Rights Assignments do not merge across GPOs: only the winning GPO's list applies. Precedence per right:
    among enforced links the one highest in the hierarchy wins; otherwise the link nearest the OU wins; ties break by
    linkOrder (lowest first). A baseline GPO linked at the OU that sets the right without Domain Admins therefore
    overrides a tier-0 deny linked at the domain root, and that OU is NOT covered. Inheritance blocking removes
    non-enforced links above the blocking OU.

    False when the whole GPO set was read and either no GPO denies Domain Admins both rights, or at least one enabled
    workstation OU's winning GPO does not deny them. The verdict travels with its denominator: workstationsCovered of
    workstationsTotal and coveragePercentage.

    Not evaluated (None) when the GPO set is incomplete, the domain SID or workstation picture is missing or
    unreadable, there are no enabled workstations, or no failure is measured and which GPO wins cannot be resolved
    (security- or WMI-filtered GPO defining the right, or tied links with no linkOrder).
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
        findings = []
        gpos = [g for g in as_list(rights.get("gpos")) if isinstance(g, dict) and g.get("enabled") is True]
        # Per right, the GPOs that DEFINE it (a non-empty list). User Rights Assignments do not merge: only the winning
        # GPO's list applies, so a baseline GPO that sets "Deny log on locally: Guests" overrides a deny linked higher up.
        rights_fields = ["denyInteractive", "denyRemoteInteractive"]
        any_denying = False
        for g in gpos:
            name = as_text(g.get("displayName")) or "a GPO with no name"
            local = denies(g.get("denyInteractive"), admin_sid)
            remote = denies(g.get("denyRemoteInteractive"), admin_sid)
            if local and remote:
                any_denying = True
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

        if not any_denying:
            extra = {"workstationsTotal": total if picture else None, "workstationsCovered": 0,
                     "coveragePercentage": 0 if picture else None}
            return respond(False, extra, [],
                           ["No enabled GPO denies Domain Admins both local and Remote Desktop Services logon on workstations"],
                           {"gposRead": len(as_list(rights.get("gpos")))}, [], findings)
        if not picture:
            return not_evaluated("The workstation OU picture is missing or unreadable, or there are no enabled workstations, "
                                 "so coverage cannot be measured", {}, {"workstationOus": len(ous)}, findings)

        def depth(dn):
            return len(as_text(dn).split(","))

        def verdict_for(ou, field):
            # "deny" | "other" | "unknown" for one right on one OU: which GPO wins, and does it deny Domain Admins.
            dn = as_text(ou.get("dn"))
            blocked = [as_text(b) for b in as_list(ou.get("inheritanceBlockedAt"))]
            candidates = []
            for g in gpos:
                if not as_list(g.get(field)):
                    continue
                for link in as_list(g.get("links")):
                    if not isinstance(link, dict) or link.get("enabled") is not True:
                        continue
                    scope = as_text(link.get("scopeDn"))
                    if same(scope, dn):
                        reach = True
                    elif under(dn, scope):
                        stopped = False
                        for b in blocked:
                            if under(b, scope):
                                stopped = True
                        reach = (not stopped) or link.get("enforced") is True
                    else:
                        reach = False
                    if not reach:
                        continue
                    order = link.get("linkOrder")
                    if isinstance(order, bool) or not isinstance(order, int):
                        order = None
                    candidates.append({"gpo": g, "enforced": link.get("enforced") is True, "depth": depth(scope), "order": order})
            if not candidates:
                return "none"
            for c in candidates:
                if c["gpo"].get("appliesTo") != "authenticated" or c["gpo"].get("wmiFiltered") is True:
                    return "unknown"
            enforced = [c for c in candidates if c["enforced"]]
            if enforced:
                best = min([c["depth"] for c in enforced])
                pool = [c for c in enforced if c["depth"] == best]
            else:
                best = max([c["depth"] for c in candidates])
                pool = [c for c in candidates if c["depth"] == best]
            winner = pool[0]
            if len(pool) > 1:
                orders = [c["order"] for c in pool]
                if None in orders or len(set(orders)) < len(orders):
                    return "unknown"
                winner = pool[orders.index(min(orders))]
            if denies(winner["gpo"].get(field), admin_sid):
                return "deny"
            return "other"

        covered = 0
        uncovered = []
        unresolved = []
        for ou in ous:
            count = ou.get("enabledWorkstations")
            if not (isinstance(count, int) and not isinstance(count, bool) and count > 0):
                continue
            dn = as_text(ou.get("dn"))
            verdicts = [verdict_for(ou, f) for f in rights_fields]
            if verdicts[0] == "deny" and verdicts[1] == "deny":
                covered = covered + count
            elif "unknown" in verdicts and "other" not in verdicts and "none" not in verdicts:
                unresolved.append(dn + " (" + str(count) + ")")
            else:
                uncovered.append(dn + " (" + str(count) + ")")
        percent = int(100 * covered / total)
        extra = {"workstationsTotal": total, "workstationsCovered": covered, "coveragePercentage": percent}
        summary = {"workstationOus": len(ous), "gposRead": len(gpos)}
        if covered == total:
            return respond(True, extra,
                           ["Domain Admins are denied local and Remote Desktop Services logon on all " + str(total)
                            + " enabled workstations (the winning GPO for each right denies them)"], [], summary, [], findings)
        if uncovered:
            return respond(False, extra, [],
                           [str(total - covered) + " of " + str(total) + " enabled workstations ("
                            + str(100 - percent) + "%) are not covered by a winning GPO that denies Domain Admins logon: "
                            + ", ".join(uncovered[:20])], summary, [], findings)
        return not_evaluated("Which GPO wins could not be resolved (security- or WMI-filtered GPO, or link order missing) for: "
                             + ", ".join(unresolved[:20]), extra, summary, findings)
    except Exception as e:
        return not_evaluated("Could not evaluate the logon-rights snapshot: the response has an unexpected shape")
