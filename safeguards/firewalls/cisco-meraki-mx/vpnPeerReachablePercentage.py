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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    networks = data.get("apiResponse")
    if networks is None:
        networks = data.get("data")
    if not isinstance(networks, list):
        networks = []

    total_peers = 0
    reachable_peers = 0
    unreachable_names = []
    network_names_seen = []

    for net in networks:
        if not isinstance(net, dict):
            continue
        net_name = net.get("networkName") or net.get("networkId") or "unknown-network"
        network_names_seen.append(net_name)
        meraki_peers = net.get("merakiVpnPeers") or []
        third_party_peers = net.get("thirdPartyVpnPeers") or []
        all_peers = list(meraki_peers) + list(third_party_peers)
        for peer in all_peers:
            if not isinstance(peer, dict):
                continue
            total_peers = total_peers + 1
            reachability = peer.get("reachability")
            if reachability == "reachable":
                reachable_peers = reachable_peers + 1
            else:
                peer_name = peer.get("name") or peer.get("publicIp") or "unknown-peer"
                unreachable_names.append(f"{net_name}:{peer_name}({reachability})")

    if total_peers == 0:
        percentage = 0.0
    else:
        percentage = round((reachable_peers / total_peers) * 100.0, 2)

    input_summary = {
        "networksInspected": len(network_names_seen),
        "totalVpnPeers": total_peers,
        "reachablePeers": reachable_peers,
    }

    if total_peers == 0:
        pass_reasons = []
        fail_reasons = ["No VPN peers (Meraki or third-party) were found in merakiVpnPeers/thirdPartyVpnPeers across any of the inspected networks, so reachability cannot be confirmed."]
        recommendations = ["Configure site-to-site VPN peers on the appliance networks so reachability can be measured."]
    elif reachable_peers == total_peers:
        pass_reasons = [f"All {total_peers} configured VPN peers across {len(network_names_seen)} network(s) report reachability='reachable'."]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = [f"{reachable_peers} of {total_peers} configured VPN peers report reachability='reachable'."] if reachable_peers > 0 else []
        fail_reasons = [f"{total_peers - reachable_peers} of {total_peers} VPN peers are not reachable: {', '.join(unreachable_names[:10])}"]
        recommendations = ["Investigate unreachable VPN peers listed in failReasons; verify tunnel configuration, public IP reachability, and firewall rules on both ends of the tunnel."]

    result = {
        "vpnPeerReachablePercentage": percentage,
        "totalVpnPeers": total_peers,
        "reachablePeers": reachable_peers,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "vpnPeerReachablePercentage",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
