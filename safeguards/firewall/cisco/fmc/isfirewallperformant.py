"""
Transformation: isFirewallPerformant
Vendor: Cisco FMC  |  Category: Firewall
Evaluates: CPU and RAM usage are below 50% utilization and interface statistics indicate healthy performance
Data source: FMC Health Metrics API (/health/metrics) with cpu, mem, and interface metrics (queryFunction:avg)
"""
import json
from datetime import datetime

CPU_THRESHOLD = 50.0
MEMORY_THRESHOLD = 50.0


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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallPerformant", "vendor": "Cisco FMC", "category": "Firewall"}
        }
    }


def get_metric_average(metric_items):
    """Extract average metric value from health metrics response items."""
    if not metric_items:
        return None
    values = []
    for item in metric_items:
        data_points = item.get('values', []) or item.get('dataPoints', [])
        for point in data_points:
            value = point[1] if isinstance(point, list) else point.get('value', 0)
            try:
                values.append(float(value))
            except (ValueError, TypeError):
                continue
    if not values:
        return None
    return sum(values) / len(values)


def evaluate_device_metrics(cpu_data, memory_data, interface_data):
    """Evaluate a single device's health metrics."""
    cpu_usage = None
    memory_usage = None

    if cpu_data:
        items = cpu_data.get('items', []) if isinstance(cpu_data, dict) else cpu_data
        if isinstance(items, list):
            cpu_usage = get_metric_average(items)

    if memory_data:
        items = memory_data.get('items', []) if isinstance(memory_data, dict) else memory_data
        if isinstance(items, list):
            memory_usage = get_metric_average(items)

    interface_healthy = True
    interface_errors = []
    if interface_data:
        items = interface_data.get('items', []) if isinstance(interface_data, dict) else interface_data
        if isinstance(items, list):
            for item in items:
                metric_name = item.get('metric', {}).get('name', '') if isinstance(item.get('metric'), dict) else ''
                if 'error' in metric_name.lower() or 'drop' in metric_name.lower():
                    error_val = get_metric_average([item])
                    if error_val is not None and error_val > 0:
                        interface_healthy = False
                        interface_errors.append({"metric": metric_name, "value": error_val})

    cpu_ok = cpu_usage is not None and cpu_usage < CPU_THRESHOLD
    memory_ok = memory_usage is not None and memory_usage < MEMORY_THRESHOLD

    return {
        "cpuUsage": cpu_usage,
        "cpuOk": cpu_ok,
        "memoryUsage": memory_usage,
        "memoryOk": memory_ok,
        "interfaceHealthy": interface_healthy,
        "interfaceErrors": interface_errors
    }


def evaluate(data):
    """Evaluate health metrics across all devices."""
    try:
        cpu_metrics = data.get('cpuMetrics', [])
        memory_metrics = data.get('memoryMetrics', [])
        interface_metrics = data.get('interfaceMetrics', [])

        if not cpu_metrics and not memory_metrics:
            return {"isFirewallPerformant": False, "error": "No health metrics data available"}

        cpu_list = cpu_metrics if isinstance(cpu_metrics, list) else [cpu_metrics]
        memory_list = memory_metrics if isinstance(memory_metrics, list) else [memory_metrics]
        interface_list = interface_metrics if isinstance(interface_metrics, list) else [interface_metrics]

        device_count = max(len(cpu_list), len(memory_list))
        all_performant = True
        device_results = []

        for i in range(device_count):
            cpu_data = cpu_list[i] if i < len(cpu_list) else None
            mem_data = memory_list[i] if i < len(memory_list) else None
            iface_data = interface_list[i] if i < len(interface_list) else None

            result = evaluate_device_metrics(cpu_data, mem_data, iface_data)
            device_performant = result["cpuOk"] and result["memoryOk"] and result["interfaceHealthy"]

            if not device_performant:
                all_performant = False

            device_results.append({
                "cpuUsage": result["cpuUsage"],
                "memoryUsage": result["memoryUsage"],
                "interfaceHealthy": result["interfaceHealthy"],
                "performant": device_performant
            })

        return {
            "isFirewallPerformant": all_performant,
            "devicesEvaluated": device_count,
            "cpuThreshold": CPU_THRESHOLD,
            "memoryThreshold": MEMORY_THRESHOLD,
            "deviceResults": device_results
        }
    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}


def transform(input):
    criteriaKey = "isFirewallPerformant"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            device_results = extra_fields.get("deviceResults", [])
            for i, dr in enumerate(device_results):
                pass_reasons.append(f"Device {i+1}: CPU {dr['cpuUsage']:.1f}%, Memory {dr['memoryUsage']:.1f}%")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            device_results = extra_fields.get("deviceResults", [])
            for i, dr in enumerate(device_results):
                if not dr.get("performant"):
                    if dr.get("cpuUsage") is not None and dr["cpuUsage"] >= CPU_THRESHOLD:
                        fail_reasons.append(f"Device {i+1}: CPU usage {dr['cpuUsage']:.1f}% exceeds {CPU_THRESHOLD}% threshold")
                    if dr.get("memoryUsage") is not None and dr["memoryUsage"] >= MEMORY_THRESHOLD:
                        fail_reasons.append(f"Device {i+1}: Memory usage {dr['memoryUsage']:.1f}% exceeds {MEMORY_THRESHOLD}% threshold")
                    if not dr.get("interfaceHealthy"):
                        fail_reasons.append(f"Device {i+1}: Interface errors detected")
            recommendations.append("Investigate devices with high CPU/memory utilization or interface errors")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, "devicesEvaluated": extra_fields.get("devicesEvaluated", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
