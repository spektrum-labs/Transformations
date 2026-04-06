import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Exchange Online (Email Security)"""
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict): return parsed
                except: pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except: raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes): return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict): return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        skus = data.get("value", [])
        if isinstance(skus, list):
            for sku in skus:
                if isinstance(sku, dict):
                    capability = sku.get("capabilityStatus", "")
                    sku_name = sku.get("skuPartNumber", "").lower()
                    exchange_skus = ("exchangeonline", "exchange_s_enterprise", "exchange_s_standard", "o365_business", "spe_e3", "spe_e5", "enterprisepack")
                    if isinstance(capability, str) and capability.lower() == "enabled":
                        if any(ex in sku_name for ex in exchange_skus):
                            result = True
                            break
            if not result and len(skus) > 0:
                first_status = skus[0].get("capabilityStatus", "")
                if isinstance(first_status, str) and first_status.lower() == "enabled":
                    result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
