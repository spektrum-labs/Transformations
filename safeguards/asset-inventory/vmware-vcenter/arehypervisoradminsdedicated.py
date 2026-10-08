# arehypervisoradminsdedicated.py - VMware vCenter Server
#
# Method: listPermissions (Integration-Service), one read-only call:
#   POST https://{vcenter}/api/vcenter/authorization/permissions?action=list   (vSphere Automation API 9.0+)
# and, for vCenter 7/8 (no REST permission list), the snapshot the Spektrum Connector pushes after reading
# AuthorizationManager.RetrieveAllPermissions over the vSphere SOAP API inside the customer network.
#
# Input shapes accepted (both proven by the unit tests):
#   * REST 9.0 list result: {"items": [{"permission": id, "info": {"object": {"type","id"},
#     "principal": {"type": "USER"|"GROUP", "name", "domain"}, "role": {"role": "-1"} or "-1", "propagating": bool}}],
#     "marker": optional}
#   * connector snapshot (schema "spektrum.vcenter.v1"): {"permissionsComplete": true, "permissions": [{"principal",
#     "role": {"id","name","privileges"}, "object", "propagating"}], "roles": [{"id","name","privileges"}],
#     "ssoAdministrators": [{"name","domain","type"}], "directory": {"user@domain": {"found","enabled","hasMailbox"}}}
# System role ids: Admin is "-1".


def transform(input):
    """
    areHypervisorAdminsDedicated - True only when at least one administrator assignment exists on this vCenter
    and EVERY administrator principal is shown to be dedicated.

    An administrator assignment is a role that is Admin (id "-1" or named Admin) or carries
    Authorization.ModifyPermissions, on a folder, datacenter, cluster or host, or any propagating object. Members of
    the SSO Administrators group count.

    False when an administrator assignment goes to a broad group (Domain Users, Everyone, Authenticated Users, Users,
    Domain Computers) or to a named user whose directory record shows an Exchange mailbox (a daily-use account).

    A named user is dedicated when the directory record is found and shows no mailbox, or the name follows an admin
    naming convention (adm-, -adm, a-, -a, admin tokens). The built-in administrator@vsphere.local is a finding (shared
    break-glass), and solution users (vpxd-, vsphere-webclient-, machine- ...) are not people and are not judged.

    Not evaluated (None) when no permission list was read or it is partial, or no administrator is judged, or one or
    more administrators are neither shown dedicated nor shown shared: "cannot show they are dedicated".

    Scope: this vCenter only. ESXi hosts managed outside it are not covered.
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
                             "product": "VMware vCenter Server",
                             "category": "Asset Inventory"},
            },
        }

    def not_evaluated(reason, extra=None, summary=None, findings=None):
        return respond(None, extra or {}, [], [reason], summary or {}, [reason], findings or [])

    broad = ["domain users", "everyone", "authenticated users", "users", "domain computers", "all users"]
    solution_prefixes = ["vpxd-", "vsphere-webclient-", "machine-", "vpxd-extension-", "wcp-", "vslm-", "hvc-",
                         "topologysvc-", "vstatsuser-", "vcls-", "vmware-vsan-", "lookupsvc-"]
    scoped_types = ["folder", "datacenter", "clustercomputeresource", "hostsystem", "root", "vcenter"]

    def tokens(name):
        text = name.lower()
        for sep in ["-", "_", ".", " "]:
            text = text.replace(sep, " ")
        return [t for t in text.split(" ") if t]

    def follows_convention(name):
        parts = tokens(name)
        if not parts:
            return False
        for t in parts:
            if t in ["adm", "admin", "vcadmin", "vadmin", "da"]:
                return True
        if parts[0] == "a" or parts[-1] == "a":
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
                if isinstance(data, dict) and wrapper in data and "items" not in data and "permissions" not in data:
                    data = data[wrapper]
                    unwrapped = True
                    break
            if not unwrapped:
                break
        if isinstance(data, list):
            data = {"items": data}
        if not isinstance(data, dict):
            return not_evaluated("Response is not a vCenter permission list")
        if data.get("error") or data.get("errors") or data.get("errorMessage") or data.get("error_type"):
            return not_evaluated("vCenter returned an error instead of the permission list")

        assignments = []
        if isinstance(data.get("permissions"), list):
            if data.get("permissionsComplete") is not True:
                return not_evaluated("The permission list is incomplete, so not every administrator was read")
            for p in data.get("permissions"):
                if isinstance(p, dict):
                    assignments.append(p)
        elif isinstance(data.get("items"), list):
            if as_text(data.get("marker")):
                return not_evaluated("The permission list is one page of several (marker present), so not every administrator was read")
            for item in data.get("items"):
                info = as_dict(as_dict(item).get("info"))
                role = info.get("role")
                if isinstance(role, dict):
                    role = {"id": role.get("role", role.get("id")), "name": role.get("name")}
                else:
                    role = {"id": role, "name": None}
                assignments.append({"principal": info.get("principal"), "role": role,
                                    "object": info.get("object"), "propagating": info.get("propagating")})
        else:
            return not_evaluated("Response carries no permission list, so the read cannot be shown to have run")

        roles = {}
        for r in as_list(data.get("roles")):
            if isinstance(r, dict):
                roles[as_text(r.get("id"))] = r

        def admin_role(role):
            role = as_dict(role)
            rid = as_text(role.get("id"))
            known = as_dict(roles.get(rid))
            name = as_text(role.get("name") or known.get("name")).lower()
            privileges = as_list(role.get("privileges")) + as_list(known.get("privileges"))
            if rid == "-1" or name == "admin":
                return True
            for p in privileges:
                if as_text(p).lower() == "authorization.modifypermissions":
                    return True
            return False

        principals = {}
        for a in assignments:
            if not admin_role(a.get("role")):
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
            principals[label.lower()] = {"label": label, "name": name, "domain": domain,
                                         "type": as_text(principal.get("type")).upper()}
        for s in as_list(data.get("ssoAdministrators")):
            s = as_dict(s)
            name = as_text(s.get("name"))
            if name:
                domain = as_text(s.get("domain"))
                label = (domain + "\\" + name) if domain else name
                principals[label.lower()] = {"label": label, "name": name, "domain": domain,
                                             "type": as_text(s.get("type")).upper()}

        directory = as_dict(data.get("directory"))

        def record(p):
            for k in [p["name"] + "@" + p["domain"], p["domain"] + "\\" + p["name"], p["name"]]:
                if k.lower() in directory:
                    return as_dict(directory[k.lower()])
            for k in directory:
                if as_text(k).lower() in [(p["name"] + "@" + p["domain"]).lower(), (p["domain"] + "\\" + p["name"]).lower()]:
                    return as_dict(directory[k])
            return {}

        dedicated = []
        failed = []
        unknown = []
        findings = []
        skipped = 0
        for lowered in principals:
            p = principals[lowered]
            name = p["name"]
            low = name.lower()
            is_group = p["type"] == "GROUP"
            if (not is_group) and p["domain"].lower() == "vsphere.local":
                solution = False
                for prefix in solution_prefixes:
                    if low.startswith(prefix):
                        solution = True
                if solution:
                    skipped = skipped + 1
                    continue
            if low in broad:
                failed.append(p["label"] + " (broad group: every member is an administrator)")
                continue
            if (not is_group) and low == "administrator" and p["domain"].lower() == "vsphere.local":
                findings.append("administrator@vsphere.local holds Administrator: shared break-glass account, keep it sealed and monitored")
                continue
            rec = record(p)
            if rec.get("found") is True and rec.get("hasMailbox") is True:
                failed.append(p["label"] + " (has an Exchange mailbox: daily-use account)")
            elif (not is_group) and rec.get("found") is True and rec.get("hasMailbox") is False and rec.get("enabled") is not False:
                dedicated.append(p["label"])
            elif follows_convention(name):
                dedicated.append(p["label"])
                findings.append(p["label"] + " judged dedicated by naming convention only (no directory record)")
            else:
                unknown.append(p["label"])

        judged = len(dedicated) + len(failed) + len(unknown)
        extra = {"adminPrincipals": judged, "dedicatedAdminPrincipals": len(dedicated),
                 "nonDedicatedAdminPrincipals": len(failed)}
        summary = {"permissionsRead": len(assignments), "solutionUsersSkipped": skipped}
        if failed:
            return respond(False, extra, [],
                           [str(len(failed)) + " of " + str(judged) + " vCenter administrator principals are not dedicated: "
                            + "; ".join(failed[:20])], summary, [], findings)
        if judged == 0:
            return not_evaluated("No administrator assignment was found among the permissions read, so there is nothing to judge",
                                 extra, summary, findings)
        if unknown:
            return not_evaluated("Cannot show these administrators are dedicated (no directory record, no admin naming convention): "
                                 + ", ".join(unknown[:20]), extra, summary, findings)
        return respond(True, extra,
                       ["All " + str(judged) + " vCenter administrator principals are dedicated accounts"], [],
                       summary, [], findings)
    except Exception as e:
        return not_evaluated("Could not evaluate the vCenter permission list: the response has an unexpected shape")
