import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Nutanix Hypervisor (Network Security)"""
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Invalid input")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        result = False

        # Nutanix clusters/list returns entities with resource utilization stats
        entities = data.get("entities", [])
        if isinstance(entities, list) and len(entities) > 0:
            all_healthy = True
            for entity in entities:
                if isinstance(entity, dict):
                    status = entity.get("status", {})
                    if isinstance(status, dict):
                        resources = status.get("resources", {})
                        stats = resources.get("stats", {})
                        cpu = stats.get("hypervisor_cpu_usage_ppm", None)
                        mem = stats.get("hypervisor_memory_usage_ppm", None)
                        if cpu is not None and mem is not None:
                            try:
                                # ppm = parts per million; 500000 = 50%
                                if float(cpu) >= 500000 or float(mem) >= 500000:
                                    all_healthy = False
                                    break
                            except (ValueError, TypeError):
                                all_healthy = False
                                break
            if all_healthy:
                result = True
        elif isinstance(data, dict) and data.get("status", "").lower() in ("ok", "healthy"):
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
