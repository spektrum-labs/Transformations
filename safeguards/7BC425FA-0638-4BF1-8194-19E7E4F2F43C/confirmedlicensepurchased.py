def transform(input):
    """
    Evaluates if the license has been purchased for endpoint protection

    Parameters:
        input (dict): The JSON data containing machine information.

    Returns:
        dict: A dictionary summarizing the license information.

    Comments:
        Searches for SKUs that contain the following strings:
        "MDE", "ATP", "DEFENDER", 
        "SPE_E3" = Microsoft 365 E3

        For additional information:
        https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
        or download a csv version of this information:
        https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv
    """

    # modify assignment to match specific criteriaKey
    criteriaKey = "confirmedLicensePurchased"

    # default criteriaKey value
    criteriaValue = False

    try:
        if 'value' in input:
            data = input.get("value", [])
        
        defender_skus = []
        for sku in data:
            sku_part = sku.get("skuPartNumber", "").upper()
            if any(keyword in sku_part for keyword in ["MDE", "ATP", "DEFENDER", "SPE_E3"]):
                defender_skus.append({
                    "SkuPartNumber": sku.get("skuPartNumber"),
                    "SkuId": sku.get("skuId"),
                    "CapabilityStatus": sku.get("capabilityStatus"),
                    "ConsumedUnits": sku.get("consumedUnits"),
                    "PrepaidUnits": sku.get("prepaidUnits")
                })
                criteriaValue = True

        ### # Uncomment to view matching license detail   
        ### if (defender_skus):
        ###     print(defender_skus)
        ### else:
        ###     print("No matching skus found")

        return {criteriaKey: criteriaValue}
    
    except Exception as e:
        return {criteriaKey: False, "error": str(e)}