"""
Transformation: epp_transform (CrowdStrike)
Vendor: CrowdStrike Falcon
Category: Endpoint Security

Evaluates safeguard types coverage based on CrowdStrike Falcon API endpoints response data
and assigns a score from 0 to 100 for each safeguard type.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "epp_transform",
                "vendor": "CrowdStrike Falcon",
                "category": "Endpoint Security"
            }
        }
    }


def transform(endpoints_response, debug=False):
    try:
        if isinstance(endpoints_response, str):
            endpoints_response = json.loads(endpoints_response)
        elif isinstance(endpoints_response, bytes):
            endpoints_response = json.loads(endpoints_response.decode("utf-8"))

        data, validation = extract_input(endpoints_response)

        if validation.get("status") == "failed":
            return unevaluated("Input validation failed: nothing was measured", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # A DEFAULT OF True ON BOTH BRANCHES MEANT NOTHING COULD DISCONFIRM THIS. The line
        # read `data.get("isEPPConfigured", True) if isinstance(data, dict) else True`, so a
        # body missing the key reported endpoint protection CONFIGURED, and a body that was
        # not a dict at all -- null, a bare string, an unparsed response -- did too, via the
        # else. Measured 2026-09-21: transform(None) returned isEPPConfigured true across
        # all six copies of this file. The key is absent from every real vendor payload
        # this transform handles; it is a passthrough for a caller-supplied hint, and its
        # absence is the normal case, which made True the answer almost every time.
        #
        # Absence of the hint is now resolved from what WAS read: endpoint protection is
        # configured if any coverage was actually observed. An unreadable body observes
        # nothing and is False.
        if not isinstance(data, dict) or not data:
            isEPPConfigured = False
        elif "isEPPConfigured" in data:
            isEPPConfigured = bool(data.get("isEPPConfigured"))
        else:
            isEPPConfigured = epp_coverage_observed(data)

        # Handle different possible response structures from CrowdStrike API
        devices = []
        if isinstance(data, dict):
            if "resources" in data:
                if len(data["resources"]) > 0 and isinstance(data["resources"][0], dict):
                    devices = data["resources"]
                else:
                    devices = data.get("devices", [])
            elif "items" in data:
                devices = data.get("items", [])
            else:
                devices = data.get("devices", [])
        elif isinstance(data, list):
            devices = data

        # Fail closed (2026-10-02): a body that is not a device list proves nothing about the
        # estate, so every key is None with a dataCollection error (Unevaluated), never False and
        # never True. See no_device_evidence for the cases.
        problem = no_device_evidence(data, devices)
        if problem:
            return unevaluated(problem, validation)

        total_endpoints = len(devices)
        total_computers = 0
        total_servers = 0
        total_mobile_devices = 0
        total_cloud_endpoints = 0
        mdr_configured_count = 0

        safeguard_counters = {
            "Endpoint Protection": 0,
            "Endpoint Security": 0,
            "Server Protection": 0,
            "MDR": 0,
            "Network Protection": 0,
            "Cloud Security": 0,
            "Mobile Protection": 0,
            "Email Security": 0,
            "Phishing Protection": 0,
            "Zero Trust Network Access": 0,
            "Encryption": 0
        }

        for idx, device in enumerate(devices):
            device_status_raw = device.get("status") or device.get("Status") or ""
            device_status = str(device_status_raw).lower() if device_status_raw else ""
            sensor_version = device.get("agent_version") or device.get("agentVersion") or device.get("sensor_version") or device.get("sensorVersion") or ""
            system_product_name_raw = device.get("system_product_name") or device.get("systemProductName") or ""
            system_product_name = str(system_product_name_raw).lower() if system_product_name_raw else ""
            os_version_raw = device.get("os_version") or device.get("osVersion") or ""
            os_version = str(os_version_raw).lower() if os_version_raw else ""
            product_type_desc_raw = device.get("product_type_desc") or device.get("productTypeDesc") or ""
            product_type_desc = str(product_type_desc_raw).lower() if product_type_desc_raw else ""

            is_server = "server" in system_product_name or "server" in os_version or product_type_desc == "server"
            is_mobile = "ios" in os_version or "android" in os_version or "mobile" in system_product_name.lower() or product_type_desc == "mobile"
            endpoint_type = "server" if is_server else ("mobile" if is_mobile else "computer")

            status_lower = str(device_status).lower() if device_status else ""
            has_valid_status = device_status and status_lower not in ["offline", ""] and status_lower in ["normal", "contained", "containment_pending"]

            device_policies = device.get("device_policies") or device.get("devicePolicies") or {}
            prevention_policies = device_policies.get("prevention") or {}
            prevention_applied = prevention_policies.get("applied", False)

            has_active_sensor = has_valid_status and ((sensor_version and len(str(sensor_version).strip()) > 0) or prevention_applied)

            policy_id = prevention_policies.get("policy_id") or prevention_policies.get("policyId")
            applied = prevention_policies.get("applied", False)
            has_prevention_policy = bool((bool(prevention_policies) and prevention_policies != {}) and (bool(policy_id) or applied or len(prevention_policies) > 0))

            has_network_protection = has_prevention_policy or device.get("prevention_policy_assigned", False) or (device.get("network_interfaces", []) != [] and has_active_sensor)

            cloud_instance_id = device.get("instance_id") or device.get("cloud_instance_id")
            cloud_provider = device.get("cloud_provider") or device.get("service_provider")
            is_cloud = bool(cloud_instance_id or cloud_provider)

            rtr_state_raw = device.get("rtr_state") or device.get("rtrState") or ""
            rtr_state = str(rtr_state_raw).lower() if rtr_state_raw else ""
            licenses = device.get("licenses") or device.get("Licenses") or []
            license_str = " ".join([str(l).lower() for l in licenses]) if licenses else ""

            has_mdr = rtr_state == "enabled" or "overwatch" in license_str or "insight" in license_str or (has_active_sensor and has_prevention_policy)

            if endpoint_type == "computer":
                total_computers += 1
            elif endpoint_type == "server":
                total_servers += 1
            elif endpoint_type == "mobile":
                total_mobile_devices += 1

            if is_cloud:
                total_cloud_endpoints += 1

            has_epp = bool(has_active_sensor and has_prevention_policy)

            if endpoint_type == "computer" and has_epp:
                safeguard_counters["Endpoint Protection"] = safeguard_counters["Endpoint Protection"] + 1
                safeguard_counters["Endpoint Security"] = safeguard_counters["Endpoint Security"] + 1

            if endpoint_type == "server" and has_epp:
                safeguard_counters["Server Protection"] = safeguard_counters["Server Protection"] + 1

            if has_network_protection:
                safeguard_counters["Network Protection"] = safeguard_counters["Network Protection"] + 1

            if is_cloud and has_epp:
                safeguard_counters["Cloud Security"] = safeguard_counters["Cloud Security"] + 1

            if endpoint_type == "mobile" and has_active_sensor:
                safeguard_counters["Mobile Protection"] = safeguard_counters["Mobile Protection"] + 1

            email_policies = device_policies.get("email", {})
            if email_policies and email_policies != {}:
                safeguard_counters["Email Security"] = safeguard_counters["Email Security"] + 1

            url_policies = device_policies.get("url", {})
            has_url_policy = ((url_policies and url_policies != {} and (url_policies.get("policy_id") or url_policies.get("applied", False))) or device.get("threat_intel_enabled", False))
            if has_url_policy:
                safeguard_counters["Phishing Protection"] = safeguard_counters["Phishing Protection"] + 1

            zta_status = device.get("zero_trust_assessment", {})
            zta_enabled = ((zta_status and isinstance(zta_status, dict) and zta_status.get("enabled", False)) or device.get("zt_assessment_enabled", False))
            if zta_enabled:
                safeguard_counters["Zero Trust Network Access"] = safeguard_counters["Zero Trust Network Access"] + 1

            disk_encryption = device.get("disk_encryption", {})
            if disk_encryption.get("status") == "encrypted" or device.get("encryption_status") == "encrypted":
                safeguard_counters["Encryption"] = safeguard_counters["Encryption"] + 1

            if has_mdr:
                safeguard_counters["MDR"] = safeguard_counters["MDR"] + 1

            if device_mdr_configured(device):
                mdr_configured_count = mdr_configured_count + 1

        coverage_scores = {}
        coverage_scores["Endpoint Protection"] = round((safeguard_counters["Endpoint Protection"] / total_computers) * 100 if total_computers > 0 else 0)
        coverage_scores["Endpoint Security"] = round((safeguard_counters["Endpoint Security"] / total_computers) * 100 if total_computers > 0 else 0)
        coverage_scores["Server Protection"] = round((safeguard_counters["Server Protection"] / total_servers) * 100 if total_servers > 0 else 0)
        coverage_scores["MDR"] = round((safeguard_counters["MDR"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Network Protection"] = round((safeguard_counters["Network Protection"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Cloud Security"] = round((safeguard_counters["Cloud Security"] / total_cloud_endpoints) * 100 if total_cloud_endpoints > 0 else 0)
        coverage_scores["Mobile Protection"] = round((safeguard_counters["Mobile Protection"] / total_mobile_devices) * 100 if total_mobile_devices > 0 else 0)
        coverage_scores["Email Security"] = round((safeguard_counters["Email Security"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Phishing Protection"] = round((safeguard_counters["Phishing Protection"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Zero Trust Network Access"] = round((safeguard_counters["Zero Trust Network Access"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Encryption"] = round((safeguard_counters["Encryption"] / total_endpoints) * 100 if total_endpoints > 0 else 0)

        coverage_scores["isEPPEnabled"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPDeployed"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPLoggingEnabled"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPEnabledForCriticalSystems"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEDRDeployed"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEndpointSecurityEnabled"] = coverage_scores["Endpoint Security"] > 0
        coverage_scores["isMDREnabled"] = coverage_scores["MDR"] > 0
        coverage_scores["isMDRLoggingEnabled"] = coverage_scores["MDR"] > 0
        # isMDRConfigured is a measurement, not a copy of isMDREnabled (rtr_state alone counts
        # every host): the share of hosts on which Falcon Complete / OverWatch can actually act --
        # a live sensor with the prevention AND remote-response policies applied -- against the
        # threshold. Unanswered (None) when nothing was measured: no device list, or a list
        # shorter than meta.pagination.total (a sample is not the estate).
        reported_total = reported_device_total(data)
        if total_endpoints == 0 or (reported_total is not None and reported_total > total_endpoints):
            coverage_scores["mdrConfiguredPercentage"] = None
            coverage_scores["isMDRConfigured"] = None
        else:
            coverage_scores["mdrConfiguredPercentage"] = round(mdr_configured_count * 100.0 / total_endpoints, 2)
            coverage_scores["isMDRConfigured"] = coverage_scores["mdrConfiguredPercentage"] >= MDR_CONFIGURED_THRESHOLD
        # Alerting is active whenever at least one endpoint is actively protected
        # (sensor + prevention policy) or covered by MDR, since those devices
        # generate and forward detections/alerts. Server- or MDR-only fleets must
        # still count, so this is not gated on Endpoint Protection alone.
        coverage_scores["isAlertingEnabled"] = (
            coverage_scores["Endpoint Protection"] > 0
            or coverage_scores["Server Protection"] > 0
            or coverage_scores["MDR"] > 0
        )
        coverage_scores["requiredCoveragePercentage"] = coverage_scores["MDR"]
        coverage_scores["requiredConfigurationPercentage"] = coverage_scores["MDR"]
        coverage_scores["isEPPConfigured"] = isEPPConfigured

        if coverage_scores["isEPPEnabled"]:
            pass_reasons.append(f"Endpoint protection enabled: {coverage_scores['Endpoint Protection']}% coverage")
        else:
            fail_reasons.append("Endpoint protection not deployed or not reporting data")
            recommendations.append("Deploy CrowdStrike Falcon sensor to all computers")

        if coverage_scores["Server Protection"] > 0:
            pass_reasons.append(f"Server protection: {coverage_scores['Server Protection']}% coverage")

        if coverage_scores["isMDREnabled"]:
            pass_reasons.append(f"MDR enabled: {coverage_scores['MDR']}% coverage")

        if coverage_scores["isMDRConfigured"] is True:
            pass_reasons.append(
                f"MDR configured: {mdr_configured_count} of {total_endpoints} hosts have a live sensor with prevention "
                f"and remote-response policies applied ({coverage_scores['mdrConfiguredPercentage']}%)"
            )
        elif coverage_scores["isMDRConfigured"] is False:
            fail_reasons.append(
                f"MDR not fully configured: {mdr_configured_count} of {total_endpoints} hosts have a live sensor with "
                f"prevention and remote-response policies applied ({coverage_scores['mdrConfiguredPercentage']}%, "
                f"threshold {MDR_CONFIGURED_THRESHOLD}%)"
            )
            recommendations.append(
                "Apply a prevention policy and a Real Time Response policy to every host group, and bring hosts in "
                "reduced functionality mode or not reporting back to a normal sensor state"
            )
        else:
            fail_reasons.append("isMDRConfigured not measured: no device list, or the device list was truncated")

        if coverage_scores["isAlertingEnabled"]:
            pass_reasons.append("Alerting enabled: protected endpoints/servers/MDR generate detections")
        else:
            fail_reasons.append("Alerting not enabled: no protected endpoint, server, or MDR coverage detected")

        return create_response(
            result=coverage_scores,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalEndpoints": total_endpoints,
                "totalComputers": total_computers,
                "totalServers": total_servers,
                "safeguardCounters": safeguard_counters
            }
        )

    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return unevaluated(message, {"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[message])


#: share of hosts that must be ready for MDR response for isMDRConfigured to hold
MDR_CONFIGURED_THRESHOLD = 95.0


def flag_true(value):
    """CrowdStrike policy flags arrive as booleans or as the strings "True"/"False"."""
    return value is True or str(value).strip().lower() == "true"


def device_mdr_configured(device):
    """A live sensor (status normal, not reduced functionality mode, agent_version and last_seen
    present) with both the prevention and the remote_response policy applied."""
    if not isinstance(device, dict):
        return False
    rfm = str(device.get("reduced_functionality_mode") or "").strip().lower()
    if device.get("status") != "normal" or rfm in ("yes", "true") or not device.get("agent_version") or not device.get("last_seen"):
        return False
    policies = device.get("device_policies")
    if not isinstance(policies, dict):
        return False
    prevention = policies.get("prevention") if isinstance(policies.get("prevention"), dict) else {}
    response = policies.get("remote_response") if isinstance(policies.get("remote_response"), dict) else {}
    return flag_true(prevention.get("applied")) and flag_true(response.get("applied"))


def reported_device_total(data):
    """meta.pagination.total as an int, or None when the response does not carry one."""
    meta = data.get("meta") if isinstance(data, dict) else None
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    if not isinstance(pagination, dict):
        return None
    try:
        return int(str(pagination.get("total")).strip())
    except (TypeError, ValueError):
        return None


def epp_coverage_observed(data):
    """True when the payload actually evidences endpoint protection on something.

    Deliberately narrow: it looks for a non-empty population of devices/agents/hosts, or
    an explicit enabled/installed flag. An error envelope carries none of these, so it
    resolves False rather than inheriting the old optimistic default.
    """
    if not isinstance(data, dict):
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault"):
        if data.get(key):
            return False
    for key in ("devices", "agents", "hosts", "endpoints", "resources", "items", "data"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    for key in ("isEnabled", "enabled", "installed", "protectionEnabled", "eppEnabled"):
        if data.get(key) is True:
            return True
    return False


# ---- fail-closed guard (2026-10-02) ------------------------------------------------------------
# The CrowdStrike - MDR definition routed isBehavioralMonitoringValid, isEDRDeployed, isEPPDeployed,
# isEPPConfigured and the patch / removable-media keys to this file through getLicenseStatus
# (GET /installation-tokens/entities/customer-settings/v1). That body carries one settings record
# under "resources", which the device loop counted as one unprotected host: every coverage key read
# False ("0 of 1 hosts"), isEPPConfigured read True (any non-empty resources list), and
# isBehavioralMonitoringValid, which this file never emitted, failed with the whole response as its
# value. A read that is not a device list is now Unevaluated for every key.

#: keys this transformation answers from a device list
DEVICE_KEYS = ("Endpoint Protection", "Endpoint Security", "Server Protection", "MDR", "Network Protection",
               "Cloud Security", "Mobile Protection", "Email Security", "Phishing Protection",
               "Zero Trust Network Access", "Encryption", "isEPPEnabled", "isEPPDeployed",
               "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems", "isEDRDeployed",
               "isEndpointSecurityEnabled", "isMDREnabled", "isMDRLoggingEnabled", "mdrConfiguredPercentage",
               "isMDRConfigured", "isAlertingEnabled", "requiredCoveragePercentage",
               "requiredConfigurationPercentage", "isEPPConfigured")

#: keys a definition routes here that a device list cannot answer; None on the no-evidence path
UNMEASURED_KEYS = ("isBehavioralMonitoringValid", "isPatchManagementEnabled", "isPatchManagementValid",
                   "isRemovableMediaControlled")

#: fields a Falcon host record (GET /devices/combined/devices/v1) carries; one marks a record as a host
DEVICE_FIELDS = ("device_id", "deviceId", "hostname", "agent_version", "agentVersion", "sensor_version",
                 "platform_name", "os_version", "osVersion", "device_policies", "devicePolicies",
                 "last_seen", "first_seen", "product_type_desc", "system_product_name", "mac_address",
                 "local_ip", "reduced_functionality_mode")


def is_device_record(item):
    """True when `item` reads as a Falcon host record."""
    if not isinstance(item, dict):
        return False
    for name in DEVICE_FIELDS:
        if name in item:
            return True
    return False


def vendor_error(data):
    """Why `data` is a CrowdStrike or platform error envelope, or None."""
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus"):
        code = data.get(name)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "CrowdStrike returned HTTP " + str(code)
    errors = data.get("errors") or data.get("error") or data.get("errorMessage")
    if errors:
        first = errors[0] if isinstance(errors, list) else errors
        if isinstance(first, dict):
            first = first.get("message") or first.get("code") or "error"
        return "CrowdStrike returned an error: " + str(first)[:200]
    return None


def no_device_evidence(data, devices):
    """Why this read proves nothing about the estate, or None when it is a usable device list."""
    if not isinstance(data, (dict, list)) or not data:
        return "CrowdStrike returned no body: nothing was measured"
    problem = vendor_error(data)
    if problem:
        return problem
    if not devices:
        return ("CrowdStrike returned no host records. A failed or partial read returns an empty "
                "list, so zero hosts is not evidence either way")
    recognised = 0
    for device in devices:
        if is_device_record(device):
            recognised = recognised + 1
    if recognised == 0:
        return ("The response carries no Falcon host records (for example the customer-settings "
                "body of getLicenseStatus): nothing was measured")
    return None


def unevaluated(problem, validation=None, transformation_errors=None):
    """Every key as None plus a dataCollection error: reads Unevaluated, never True or False."""
    result = {}
    for key in DEVICE_KEYS + UNMEASURED_KEYS:
        result[key] = None
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        transformation_errors=transformation_errors,
    )
