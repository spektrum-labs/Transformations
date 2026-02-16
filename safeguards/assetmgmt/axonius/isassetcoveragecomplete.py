def transform(input):
    """
    Validates that asset coverage meets minimum thresholds

    Parameters:
        input (dict): The JSON data containing Axonius devices API response

    Returns:
        dict: A dictionary with the isAssetCoverageComplete evaluation result
    """

    criteria_key = "isAssetCoverageComplete"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        coverage_complete = False
        coverage_details = {}

        # Check device data
        assets = input.get('assets', input.get('data', input.get('devices', [])))
        if isinstance(assets, list):
            total_assets = len(assets)
            coverage_details['totalAssets'] = total_assets

            # Check how many have adapters/sources
            covered = 0
            for asset in assets:
                adapters = asset.get('adapters', asset.get('specific_data', []))
                if isinstance(adapters, list) and len(adapters) > 0:
                    covered += 1
                elif isinstance(asset, dict) and len(asset) > 2:
                    covered += 1

            coverage_details['coveredAssets'] = covered
            if total_assets > 0:
                coverage_pct = (covered / total_assets) * 100
                coverage_details['coveragePercentage'] = round(coverage_pct, 1)
                coverage_complete = coverage_pct >= 80
            else:
                coverage_details['coveragePercentage'] = 0
        elif 'page' in input:
            # Paginated response
            total = input['page'].get('totalResources', 0)
            coverage_details['totalAssets'] = total
            coverage_complete = total > 0

        return {
            criteria_key: coverage_complete,
            **coverage_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
