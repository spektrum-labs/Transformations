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
    data = data if isinstance(data, dict) else {}

    tunnels = []

    # Case 1: standard "data" wrapper containing a list of tunnel objects
    raw_data = data.get("data")
    if isinstance(raw_data, list) and len(raw_data) > 0 and isinstance(raw_data[0], dict):
        tunnels = raw_data

    if not tunnels:
        # Case 2: columnar shape - parallel arrays keyed by field name
        # (this is the shape actually captured from this tenant)
        id_list = data.get("id") if isinstance(data.get("id"), list) else []
        name_list = data.get("name") if isinstance(data.get("name"), list) else []
        site_list = data.get("siteOriginId") if isinstance(data.get("siteOriginId"), list) else []
        client_list = data.get("client") if isinstance(data.get("client"), list) else []
        transport_list = data.get("transport") if isinstance(data.get("transport"), list) else []
        service_list = data.get("serviceType") if isinstance(data.get("serviceType"), list) else []
        cidr_list = data.get("networkCIDRs") if isinstance(data.get("networkCIDRs"), list) else []
        meta_list = data.get("meta") if isinstance(data.get("meta"), list) else []
        created_list = data.get("createdAt") if isinstance(data.get("createdAt"), list) else []
        modified_list = data.get("modifiedAt") if isinstance(data.get("modifiedAt"), list) else []

        max_len = max(
            len(id_list), len(name_list), len(site_list), len(client_list),
            len(transport_list), len(service_list), len(cidr_list),
            len(meta_list), len(created_list), len(modified_list)
        )

        built = []
        i = 0
        while i < max_len:
            item = {}
            if i < len(id_list):
                item["id"] = id_list[i]
            if i < len(name_list):
                item["name"] = name_list[i]
            if i < len(site_list):
                item["siteOriginId"] = site_list[i]
            if i < len(client_list):
                item["client"] = client_list[i]
            if i < len(transport_list):
                item["transport"] = transport_list[i]
            if i < len(service_list):
                item["serviceType"] = service_list[i]
            if i < len(cidr_list):
                item["networkCIDRs"] = cidr_list[i]
            if i < len(meta_list):
                item["meta"] = meta_list[i]
            if i < len(created_list):
                item["createdAt"] = created_list[i]
            if i < len(modified_list):
                item["modifiedAt"] = modified_list[i]
            built.append(item)
            i = i + 1
        tunnels = built

    total_tunnels = len(tunnels)

    # Determine "established" tunnels: a tunnel is considered established/configured
    # if it has an id and (where available) transport protocol data.
    established_tunnels = []
    for t in tunnels:
        if not isinstance(t, dict):
            continue
        has_id = t.get("id") is not None and t.get("id") != ""
        transport = t.get("transport")
        has_transport = False
        if isinstance(transport, dict):
            has_transport = bool(transport.get("protocol"))
        elif transport:
            has_transport = True
        if has_id:
            established_tunnels.append(t)

    has_tunnels = len(established_tunnels) > 0

    input_summary = {
        "totalTunnelRecords": total_tunnels,
        "establishedTunnelCount": len(established_tunnels),
    }

    if has_tunnels:
        sample_names = [t.get("name") for t in established_tunnels[:3] if isinstance(t, dict)]
        pass_reasons = [
            f"Found {len(established_tunnels)} provisioned network tunnel(s) via listNetworkTunnels "
            f"(deployments/v2/tunnels), including {sample_names}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "listNetworkTunnels (deployments/v2/tunnels) returned zero tunnel records for this "
            "organization, indicating no IPsec/GRE tunnel from any branch site to Umbrella's cloud "
            "has been established."
        ]
        recommendations = [
            "Provision at least one IPsec or GRE tunnel from a branch site router/firewall to "
            "Umbrella's cloud via Admin > Deployments > Network Tunnels, and confirm the tunnel "
            "reaches an established state."
        ]

    result = {
        "hasNetworkTunnelsConfigured": has_tunnels,
        "totalTunnels": total_tunnels,
        "establishedTunnels": len(established_tunnels),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "hasNetworkTunnelsConfigured",
            "vendor": "Cisco Umbrella",
            "category": "networksecurity",
        },
    )
