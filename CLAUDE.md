# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains Python transformation logic that converts third-party API responses into standardized values for the Spektrum security compliance network. Each transformation processes vendor-specific API data and returns JSON that can be evaluated by Third Party Requirements tokens.

## Testing Transformations

Run a transformation locally against sample API response data:
```bash
python local_tester.py <transformation_file_or_url.py> <sample_response.json>
```

Example:
```bash
python local_tester.py safeguards/4BC425FA-0638-4BF1-8194-19E7E4F2F43C/backup_transform.py sample_response.json
```

## Architecture

### Directory Structure
- `safeguards/` - Contains all transformation logic organized by Safeguard Reference Number (SRN)
- Each SRN directory (UUID format) contains transformation files for a specific vendor/integration
- `safeguards/backups/` - Contains backup-related transformations with vendor subdirectories (e.g., `datto/`)

### Transformation Pattern
Every transformation file must implement a `transform(input)` function that:
1. Accepts JSON input (string, bytes, or dict) from a third-party API
2. Handles nested response wrappers (`response`, `result`, `apiResponse`)
3. Returns a dict with boolean flags and/or numeric scores
4. Returns an error dict on failure: `{"criteriaKey": False, "error": str(e)}`

### Common Input Parsing Pattern
Most transformations include this helper to handle various input formats:
```python
def _parse_input(input):
    if isinstance(input, str):
        return json.loads(input)
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")
```

### Return Value Conventions
- Boolean criteria keys use camelCase: `isMFAEnforcedForUsers`, `isBackupEnabled`, `isBackupEncrypted`
- Scores returned as percentages (0-100): `scoreInPercentage`
- Count metrics: `count` (compliant items), `total` (total items)

### Naming Conventions
- Transformation files are lowercase with underscores: `mfa_transform.py`, `backup_transform.py`
- Criteria check files match the criteria key: `ismfaenforcedforusers.py`, `isbackupenabled.py`
- Each SRN directory typically contains:
  - A main `*_transform.py` file
  - Individual criteria check files (e.g., `confirmedlicensepurchased.py`)
