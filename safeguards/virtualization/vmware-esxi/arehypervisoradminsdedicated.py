# arehypervisoradminsdedicated.py - VMware ESXi (standalone hosts, not managed by vCenter)
#
# Method: getEsxiSnapshot (Integration-Service), one read of the snapshot the Spektrum Connector pushes after
# reading each standalone host through the host's own vSphere API with a read-only local role.
#
# Snapshot shape (schema "spektrum.esxi.v1"):
#   hostsComplete  true only when every standalone host the connector is configured for was read
#   hosts[]        hostName, lockdownMode ("disabled" | "normal" | "strict" | "unknown"), permissionsComplete,
#                  permissions[{principal{type,name,domain}, role{id,name,adminCapable}, object{type,id}, propagating}],
#                  roles[{id,name,adminCapable}], localAccounts[{name,hasShell}]
#   directory      optional {"name@domain": {found, enabled, hasMailbox}} enrichment for named principals
# Scope: the standalone ESXi hosts the connector read. Says nothing about vCenter-managed hosts.


def transform(input):
    """
    areHypervisorAdminsDedicated (VMware ESXi) - True only when at least one standalone host was read, every host's
    permission list is complete, and on EVERY host every administrator principal is shown to be dedicated.

    An administrator assignment is a role that is Admin (id "-1" or named Admin) or flagged adminCapable, on the
    root folder or any propagating object.

    Shared root login: when root is the only administrator on a host and lockdown mode is "disabled", the host FAILS
    (a shared credential is the only way in and nothing restricts it). With lockdown normal or strict it is a finding,
    not a fail. Root next to named administrators is a finding. Root alone gives the host nothing to judge, so the
    result is not evaluated unless a failure is measured elsewhere.

    False when on any host an administrator assignment goes to a broad group (Domain Users, Everyone, Authenticated
    Users, Users, Domain Computers), to a named user whose directory record shows an Exchange mailbox, or when root is
    the only administrator with lockdown disabled. A GROUP is never dedicated by its name. A named user is dedicated
    when the directory record is found and shows no mailbox, or the name has a clear admin affix (adm-, admin-,
    a- prefix; -adm, -admin suffix). The built-in dcui and vpxuser accounts are system accounts and not judged.

    Not evaluated (None) when no host was read, hostsComplete or a host's permissionsComplete is not true, a role
    cannot be resolved, or no failure is measured and one or more principals are neither shown dedicated nor shared.

    Returns hostsJudged and hostsFailed beside the verdict.
    """
    import json
    from datetime import datetime, timezone

    key = "areHypervisorAdminsDedicated"

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
                             "transformationId": key, "vendor": "VMware by Broadcom",
                             "product": "VMware ESXi",
                             "category": "Virtualization"},
            },
        }

    def not_evaluated(reason, extra=None, summary=None, findings=None):
        return respond(None, extra or {}, [], [reason], summary or {}, [reason], findings or [])

    broad = ["domain users", "everyone", "authenticated users", "users", "domain computers", "all users"]
    system_accounts = ["dcui", "vpxuser"]
    scoped_types = ["folder", "datacenter", "clustercomputeresource", "hostsystem", "root"]
    system_roles = ["-1", "-2", "-3", "-4", "-5"]

    def follows_convention(name):
        text = name.lower()
        for prefix in ["adm-", "adm_", "admin-", "admin_", "a-", "a_"]:
            if text.startswith(prefix) and len(text) > len(prefix):
                return True
        for suffix in ["-adm", "_adm", "-admin", "_admin"]:
            if text.endswith(suffix) and len(text) > len(suffix):
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
                if isinstance(data, dict) and wrapper in data and "hosts" not in data:
                    data = data[wrapper]
                    unwrapped = True
                    break
            if not unwrapped:
                break
        if not isinstance(data, dict):
            return not_evaluated("Response is not an ESXi snapshot")
        if data.get("error") or data.get("errors") or data.get("errorMessage"):
            return not_evaluated("The snapshot service returned an error instead of the ESXi host data")
        hosts = data.get("hosts")
        if not isinstance(hosts, list):
            return not_evaluated("The snapshot carries no ESXi host list, so the read cannot be shown to have run")
        if len(hosts) == 0:
            return not_evaluated("No standalone ESXi host was read, so there is nothing to judge")

        directory = as_dict(data.get("directory"))

        def record(p):
            for k in [p["name"] + "@" + p["domain"], p["domain"] + "\\" + p["name"]]:
                if k.lower() in directory:
                    return as_dict(directory[k.lower()])
            for k in directory:
                if as_text(k).lower() in [(p["name"] + "@" + p["domain"]).lower(), (p["domain"] + "\\" + p["name"]).lower()]:
                    return as_dict(directory[k])
            return {}

        failed_hosts = []
        unknown_hosts = []
        passed_hosts = 0
        findings = []
        all_complete = data.get("hostsComplete") is True
        for host in hosts:
            host = as_dict(host)
            hname = as_text(host.get("hostName")) or "a host with no name"
            if host.get("permissionsComplete") is not True or not isinstance(host.get("permissions"), list):
                unknown_hosts.append(hname + " (permission list incomplete)")
                continue
            roles = {}
            for r in as_list(host.get("roles")):
                if isinstance(r, dict):
                    roles[as_text(r.get("id"))] = r
            unresolved = []

            def admin_role(role):
                role = as_dict(role)
                rid = as_text(role.get("id"))
                known = as_dict(roles.get(rid))
                name = as_text(role.get("name") or known.get("name")).lower()
                if rid == "-1" or name == "admin":
                    return True
                if role.get("adminCapable") is True or known.get("adminCapable") is True:
                    return True
                if role.get("adminCapable") is False or known.get("adminCapable") is False:
                    return False
                if rid in system_roles:
                    return False
                if rid not in unresolved:
                    unresolved.append(rid)
                return None

            principals = {}
            for a in host.get("permissions"):
                a = as_dict(a)
                if admin_role(a.get("role")) is not True:
                    continue
                obj = as_dict(a.get("object"))
                if as_text(obj.get("type")).lower() not in scoped_types and a.get("propagating") is not True:
                    continue
                principal = as_dict(a.get("principal"))
                name = as_text(principal.get("name"))
                if not name:
                    continue
                domain = as_text(principal.get("domain"))
                label = (domain + "\\" + name) if domain else name
                principals[(as_text(principal.get("type")).upper() + ":" + label).lower()] = {"label": label, "name": name, "domain": domain,
                                             "type": as_text(principal.get("type")).upper()}

            lockdown = as_text(host.get("lockdownMode")).lower()
            others = []
            has_root = False
            host_fail = []
            host_unknown = []
            for lowered in principals:
                p = principals[lowered]
                low = p["name"].lower()
                if low in system_accounts and p["type"] != "GROUP":
                    continue
                if low == "root" and p["type"] != "GROUP" and p["domain"] == "":
                    has_root = True
                    continue
                others.append(p)
            for p in others:
                low = p["name"].lower()
                if "\\" in low:
                    low = low.rsplit("\\", 1)[1]
                is_group = p["type"] == "GROUP"
                is_user = p["type"] == "USER"
                if low in broad:
                    host_fail.append(p["label"] + " (broad group: every member is an administrator)")
                    continue
                rec = record(p)
                if rec.get("found") is True and rec.get("hasMailbox") is True:
                    host_fail.append(p["label"] + " (has an Exchange mailbox: daily-use account)")
                elif is_user and rec.get("found") is True and rec.get("hasMailbox") is False and rec.get("enabled") is not False:
                    pass
                elif is_user and follows_convention(p["name"]):
                    findings.append(hname + ": " + p["label"] + " judged dedicated by naming convention only (no directory record)")
                else:
                    host_unknown.append(p["label"] + (" (group: members not read)" if is_group else ""))
            if has_root and not others:
                if lockdown == "disabled" and not unresolved:
                    host_fail.append("root is the only administrator and lockdown mode is disabled: a shared root login is the only way in")
                elif lockdown == "disabled":
                    host_unknown.append("root looks like the only administrator but a custom role could not be resolved")
                elif lockdown in ["normal", "strict"]:
                    findings.append(hname + ": root is the only administrator (shared break-glass login); lockdown mode is " + lockdown)
                    host_unknown.append("no named administrator to judge (root only)")
                else:
                    host_unknown.append("root is the only administrator and lockdown mode is unknown")
            elif has_root:
                findings.append(hname + ": root holds Administrator beside named administrators (shared break-glass login)")
            if not has_root and not others and len(unresolved) == 0:
                host_unknown.append("no administrator assignment found among the permissions read")
            if unresolved and not host_fail:
                host_unknown.append("custom role(s) not resolvable: " + ", ".join(unresolved[:10]))
            if host_fail:
                failed_hosts.append(hname + ": " + "; ".join(host_fail[:10]))
            elif host_unknown:
                unknown_hosts.append(hname + ": " + "; ".join(host_unknown[:10]))
            else:
                passed_hosts = passed_hosts + 1

        extra = {"hostsJudged": passed_hosts + len(failed_hosts), "hostsFailed": len(failed_hosts), "hostsNotEvaluated": len(unknown_hosts)}
        summary = {"hostsRead": len(hosts), "hostsPassed": passed_hosts}
        if failed_hosts:
            return respond(False, extra, [],
                           [str(len(failed_hosts)) + " of " + str(len(hosts)) + " standalone ESXi hosts have non-dedicated administrators: "
                            + " | ".join(failed_hosts[:10])], summary, [], findings)
        if not all_complete:
            return not_evaluated("Not every configured ESXi host was read (hostsComplete is not true)", extra, summary, findings)
        if unknown_hosts:
            return not_evaluated("Cannot show administrators are dedicated on: " + " | ".join(unknown_hosts[:10]), extra, summary, findings)
        return respond(True, extra,
                       ["Administrators are dedicated accounts on all " + str(len(hosts)) + " standalone ESXi hosts"], [],
                       summary, [], findings)
    except Exception as e:
        return not_evaluated("Could not evaluate the ESXi snapshot: the response has an unexpected shape")
