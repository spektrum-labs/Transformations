import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    """Create the standardized 5-section transformation response."""
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
    if not isinstance(data, dict):
        data = {}

    networks = data.get("apiResponse")
    if networks is None:
        networks = data.get("data")
    if not isinstance(networks, list):
        networks = []

    total_peers = 0
    reachable_peers = 0
    unreachable_names = []
    reachable_names = []
    networks_with_peers = 0

    for net in networks:
        if not isinstance(net, dict):
            continue
        network_name = net.get("networkName") or net.get("networkId") or "unknown-network"
        meraki_peers = net.get("merakiVpnPeers") or []
        third_peers = net.get("thirdPartyVpnPeers") or []
        peers = list(meraki_peers) + list(third_peers)
        if peers:
            networks_with_peers = networks_with_peers + 1
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            total_peers = total_peers + 1
            reachability = peer.get("reachability") or "unknown"
            peer_name = peer.get("name") or "unnamed-peer"
            if reachability == "reachable":
                reachable_peers = reachable_peers + 1
                reachable_names.append(f"{network_name}:{peer_name}")
            else:
                unreachable_names.append(f"{network_name}:{peer_name}:{reachability}")

    vpn_tunnel_established = reachable_peers > 0

    input_summary = {
        "networksEvaluated": len(networks),
        "networksWithConfiguredPeers": networks_with_peers,
        "totalPeers": total_peers,
        "reachablePeers": reachable_peers,
    }

    if total_peers == 0:
        return create_response(
            result={
                "vpnTunnelEstablished": False,
                "totalPeers": 0,
                "reachablePeers": 0,
            },
            validation=validation,
            fail_reasons=[
                "No merakiVpnPeers or thirdPartyVpnPeers were found in any of the "
                f"{len(networks)} network(s) returned by getOrganizationApplianceVpnStatuses, "
                "so no site-to-site VPN tunnel is configured."
            ],
            recommendations=[
                "Configure an Auto VPN or third-party VPN peer on at least one MX network "
                "so a site-to-site tunnel can be established and monitored."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "vpnTunnelEstablished", "vendor": "Cisco Meraki MX", "category": "firewalls"},
        )

    if vpn_tunnel_established:
        sample = ", ".join(reachable_names[:5])
        return create_response(
            result={
                "vpnTunnelEstablished": True,
                "totalPeers": total_peers,
                "reachablePeers": reachable_peers,
            },
            validation=validation,
            pass_reasons=[
                f"{reachable_peers} of {total_peers} configured VPN peer(s) report "
                f"reachability='reachable' (e.g. {sample})."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "vpnTunnelEstablished", "vendor": "Cisco Meraki MX", "category": "firewalls"},
        )
    else:
        sample = ", ".join(unreachable_names[:5])
        return create_response(
            result={
                "vpnTunnelEstablished": False,
                "totalPeers": total_peers,
                "reachablePeers": reachable_peers,
            },
            validation=validation,
            fail_reasons=[
                f"All {total_peers} configured VPN peer(s) report a non-reachable state "
                f"(e.g. {sample}); no tunnel is currently established."
            ],
            recommendations=[
                "Investigate the unreachable third-party or Auto VPN peers (check IPsec "
                "configuration, public IP reachability, and firewall rules) to restore the "
                "site-to-site tunnel."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "vpnTunnelEstablished", "vendor": "Cisco Meraki MX", "category": "firewalls"},
        )
