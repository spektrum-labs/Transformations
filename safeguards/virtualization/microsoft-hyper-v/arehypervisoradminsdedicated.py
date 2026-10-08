# arehypervisoradminsdedicated.py - Microsoft Hyper-V (hosts the Spektrum Connector runs on)
#
# Method: getHypervSnapshot (Integration-Service): the latest snapshot the Spektrum Connector pushed.
# The connector runs ON the Hyper-V host and reads local state with a fixed set of read-only PowerShell cmdlets
# (Get-LocalGroupMember for "Hyper-V Administrators" and "Administrators"; Get-SCUserRole when a VMM console
# and a read-only VMM role are present). No remoting, no writes.
#
# Snapshot shape (schema "spektrum.hyperv.v1"):
#   hostsComplete  true only when every host the connector is responsible for was read
#   hosts[]        hostName, hyperVRoleInstalled, administrators{complete, members[{name, domain, type, source,
#                  enabled, isBuiltInAdministrator}]}, scvmm{present, complete, roles[{name, profile,
#                  members[{name, domain, type}]}]}
#   directory      optional {"name@domain": {found, enabled, hasMailbox}} for admin principals


def transform(input):
    """
    areHypervisorAdminsDedicated - True only when at least one Hyper-V host was read completely and EVERY
    administrator principal on EVERY host is shown to be a dedicated account.

    Administrators are the members of "Hyper-V Administrators" and of the local "Administrators" group, plus members of
    SCVMM user roles whose profile (matched case-insensitively) is Administrator, DelegatedAdmin / DelegatedAdministrator
    or FabricAdministrator. A tenant administrator manages tenant VMs, not the fabric, so that profile is not an admin
    role.

    False when an administrator is a broad group (Domain Users, Everyone, Authenticated Users, Users, Domain
    Computers) or a named user whose directory record shows an Exchange mailbox (a daily-use account).

    A named user is dedicated when the directory record is found and shows no mailbox, or the name has a clear
    admin affix (adm-, admin- prefix; -adm, -admin suffix). A GROUP is never dedicated by its name. NT AUTHORITY\\
    Authenticated Users, INTERACTIVE, NETWORK and the other well-known broad groups are broad groups, not system
    identities.
    Not judged here: SYSTEM, LOCAL SERVICE, NETWORK SERVICE and NT SERVICE\\* identities, disabled accounts, the built-in Administrator (a
    finding: shared break-glass), and the Domain Admins / Enterprise Admins groups (a finding: the Active Directory
    check judges that group's membership).

    Not evaluated (None) when the host list or a host's administrator list is incomplete, the Hyper-V role is not
    installed on a host, an SCVMM role has an unrecognised profile, SCVMM was present but not read completely, or an administrator can be neither shown
    dedicated nor shown shared. A measured failure on any host still gives False.

    Scope: the Hyper-V hosts the connector read. Says nothing about VMware, vCenter or other hypervisors.
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
                             "transformationId": key, "vendor": "Microsoft",
                             "product": "Hyper-V", "category": "Virtualization"},
            },
        }

    def not_evaluated(reason, extra=None, summary=None, findings=None):
        return respond(None, extra or {}, [], [reason], summary or {}, [reason], findings or [])

    broad = ["domain users", "everyone", "authenticated users", "users", "domain computers", "all users",
             "interactive", "network", "remote interactive logon", "anonymous logon"]
    domain_admin_groups = ["domain admins", "enterprise admins"]

    def follows_convention(name):
        text = name.lower()
        for prefix in ["adm-", "adm_", "admin-", "admin_"]:
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
        for _ in range(6):
            unwrapped = False
            for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
                if isinstance(data, dict) and wrapper in data and "hosts" not in data:
                    data = data[wrapper]
                    unwrapped = True
                    break
            if not unwrapped:
                break
        if not isinstance(data, dict):
            return not_evaluated("Response is not a Hyper-V snapshot")
        if data.get("error") or data.get("errors") or data.get("errorMessage") or data.get("error_type"):
            return not_evaluated("The snapshot service returned an error instead of the Hyper-V data")
        if not isinstance(data.get("hosts"), list):
            return not_evaluated("The snapshot carries no Hyper-V host list, so the read cannot be shown to have run")
        if data.get("hostsComplete") is not True:
            return not_evaluated("The host list is incomplete, so not every Hyper-V host was read")
        hosts = [h for h in data.get("hosts") if isinstance(h, dict)]
        if len(hosts) != len(data.get("hosts")):
            return not_evaluated("The host list holds an entry that is not a host record, so not every host was read")
        if not hosts:
            return not_evaluated("No Hyper-V host is in the snapshot, so there is nothing to judge")

        directory = {}
        raw_dir = as_dict(data.get("directory"))
        for k in raw_dir:
            directory[as_text(k).lower()] = as_dict(raw_dir[k])

        def record(name, domain):
            keys = [name + "@" + domain, domain + "\\" + name]
            if not domain:
                keys.append(name)
            for k in keys:
                if k.lower() in directory:
                    return directory[k.lower()]
            return {}

        findings = []
        failed = []
        unknown = []
        judged_hosts = 0
        failed_hosts = []
        principals_judged = 0

        for host in hosts:
            host_name = as_text(host.get("hostName")) or "a host with no name"
            host_fail = []
            host_unknown = []
            if host.get("hyperVRoleInstalled") is not True:
                unknown.append(host_name + " (Hyper-V role not shown as installed)")
                continue
            admins = as_dict(host.get("administrators"))
            if admins.get("complete") is not True or not isinstance(admins.get("members"), list):
                unknown.append(host_name + " (administrator list incomplete)")
                continue
            raw_scvmm = host.get("scvmm")
            if not isinstance(raw_scvmm, dict) or not isinstance(raw_scvmm.get("present"), bool):
                unknown.append(host_name + " (SCVMM state unreadable)")
                continue
            scvmm = raw_scvmm
            if scvmm.get("present") is True and scvmm.get("complete") is not True:
                unknown.append(host_name + " (SCVMM roles present but not fully read)")
                continue

            entries = []
            entry_unknown = []
            for m in admins.get("members"):
                if isinstance(m, dict):
                    entries.append(m)
                else:
                    entry_unknown.append("an administrator entry that is not a member record")
            if scvmm.get("present") is True:
                if not isinstance(scvmm.get("roles"), list):
                    entry_unknown.append("the SCVMM role list is not a list")
                for role in as_list(scvmm.get("roles")):
                    role = as_dict(role)
                    profile = as_text(role.get("profile")).lower()
                    if profile in ["administrator", "delegatedadmin", "delegatedadministrator", "fabricadministrator"]:
                        if not isinstance(role.get("members"), list):
                            entry_unknown.append("SCVMM role " + (as_text(role.get("name")) or "with no name") + " (member list missing)")
                        for m in as_list(role.get("members")):
                            if isinstance(m, dict):
                                entries.append(m)
                            else:
                                entry_unknown.append("an SCVMM role member that is not a member record")
                    elif profile not in ["readonlyadmin", "readonlyadministrator", "selfserviceuser", "tenantadmin", "tenantadministrator"]:
                        entry_unknown.append("SCVMM role " + (as_text(role.get("name")) or "with no name") + " (unrecognised profile)")

            host_unknown.extend(entry_unknown)
            if not entries:
                host_unknown.append("no administrator is listed (the local Administrators group is never empty)")
            seen = []
            for m in entries:
                name = as_text(m.get("name"))
                domain = as_text(m.get("domain"))
                if not name:
                    host_unknown.append("an administrator with no name")
                    continue
                label = (domain + "\\" + name) if domain else name
                if label.lower() in seen:
                    continue
                seen.append(label.lower())
                kind = as_text(m.get("type")).lower()
                low = name.lower()
                dom = domain.lower()
                if low in broad:
                    host_fail.append(label + " (broad group: every member is an administrator)")
                    continue
                if dom == "nt service" or (dom == "nt authority" and low in ["system", "local service", "network service"]):
                    continue
                if m.get("enabled") is False:
                    continue
                if m.get("isBuiltInAdministrator") is True:
                    findings.append(host_name + ": built-in Administrator is an administrator (shared break-glass account): keep it sealed and monitored")
                    continue
                if kind == "group" and low in domain_admin_groups:
                    findings.append(host_name + ": " + label + " is an administrator; its membership is judged by the Active Directory check")
                    continue
                if kind not in ["user", "group", "computer"]:
                    host_unknown.append(label + " (unrecognised account type)")
                    continue
                if kind == "computer":
                    host_unknown.append(label + " (computer account)")
                    continue
                rec = record(name, domain)
                if rec.get("found") is True and rec.get("hasMailbox") is True:
                    host_fail.append(label + " (has an Exchange mailbox: daily-use account)")
                elif kind == "user" and rec.get("found") is True and rec.get("hasMailbox") is False and rec.get("enabled") is not False:
                    principals_judged = principals_judged + 1
                elif kind == "user" and follows_convention(name):
                    principals_judged = principals_judged + 1
                    findings.append(host_name + ": " + label + " judged dedicated by naming convention only (no directory record)")
                else:
                    host_unknown.append(label)

            judged_hosts = judged_hosts + 1
            if host_fail:
                failed_hosts.append(host_name)
                failed.append(host_name + ": " + "; ".join(host_fail[:20]))
            if host_unknown:
                unknown.append(host_name + ": " + ", ".join(host_unknown[:20]))

        extra = {"hostsRead": len(hosts), "hostsJudged": judged_hosts, "hostsFailed": len(failed_hosts),
                 "adminPrincipalsJudged": principals_judged}
        summary = {"hostsInSnapshot": len(hosts)}
        if failed:
            return respond(False, extra, [],
                           [str(len(failed_hosts)) + " of " + str(len(hosts)) + " Hyper-V hosts have administrators who are not dedicated: "
                            + " | ".join(failed[:10])], summary, [], findings)
        if unknown:
            return not_evaluated("Cannot show these administrators are dedicated, or a host was not fully read: "
                                 + " | ".join(unknown[:10]), extra, summary, findings)
        if principals_judged == 0:
            return not_evaluated("No administrator principal was judged, so there is nothing to show", extra, summary, findings)
        return respond(True, extra,
                       ["No administrator on the " + str(len(hosts)) + " Hyper-V host(s) read is a broad group or a daily-use account, and every named administrator is shown dedicated"], [],
                       summary, [], findings)
    except Exception:
        return not_evaluated("Could not evaluate the Hyper-V snapshot: the response has an unexpected shape")
