#!/usr/bin/env python3
"""
Generate Pydantic schemas for all safeguard transformations.
Uses API response files to inform schema structure where available.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def get_safeguard_dirs(safeguards_path: Path) -> List[Path]:
    """Get all safeguard directories including nested ones."""
    dirs = []
    for item in safeguards_path.iterdir():
        if item.is_dir() and item.name not in ('__pycache__', 'common'):
            # Check if it's a UUID directory or has nested structure
            if item.name.lower() != 'schemas':
                # Check for nested vendor directories
                nested_dirs = list(item.rglob('*_transform.py'))
                if nested_dirs:
                    # Find the deepest directory containing transforms
                    for nd in nested_dirs:
                        dirs.append(nd.parent)
                elif any(item.glob('*.py')):
                    dirs.append(item)
    return list(set(dirs))


def get_transformations(safeguard_dir: Path) -> List[Path]:
    """Get all transformation Python files in a safeguard directory."""
    transforms = []
    for f in safeguard_dir.glob('*.py'):
        if f.name not in ('__init__.py',) and not f.name.startswith('__'):
            transforms.append(f)
    return transforms


def get_api_responses(safeguard_dir: Path) -> Dict[str, Path]:
    """Get API response files mapped by criteria key."""
    api_dir = safeguard_dir / 'api_responses'
    responses = {}
    if api_dir.exists():
        for f in api_dir.glob('*.json'):
            # Parse filename: {Category}_{Vendor}_{CriteriaKey}_{SRN}.json
            parts = f.stem.split('_')
            if len(parts) >= 4:
                criteria_key = '_'.join(parts[2:-1])
                responses[criteria_key.lower()] = f
    return responses


def extract_transform_name(transform_path: Path) -> str:
    """Extract the transformation name from the file path."""
    name = transform_path.stem
    # Remove common suffixes
    for suffix in ('_transform', '_schema'):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name


def analyze_api_response(response_path: Path) -> Dict[str, Any]:
    """Analyze API response structure to inform schema."""
    try:
        with open(response_path) as f:
            data = json.load(f)

        # Get the actual response data (unwrap api_response.result)
        if 'api_response' in data:
            data = data['api_response']
        if 'result' in data:
            data = data['result']
        elif 'response' in data:
            data = data['response']

        return {
            'structure': data,
            'top_level_keys': list(data.keys()) if isinstance(data, dict) else [],
        }
    except Exception as e:
        return {'error': str(e), 'structure': {}, 'top_level_keys': []}


def python_type_from_value(value: Any, depth: int = 0) -> str:
    """Infer Python/Pydantic type from a JSON value."""
    if value is None:
        return 'Optional[Any]'
    if isinstance(value, bool):
        return 'Optional[bool]'
    if isinstance(value, int):
        return 'Optional[int]'
    if isinstance(value, float):
        return 'Optional[float]'
    if isinstance(value, str):
        return 'Optional[str]'
    if isinstance(value, list):
        if len(value) > 0:
            inner = python_type_from_value(value[0], depth + 1)
            return f'Optional[List[{inner}]]'
        return 'Optional[List[Any]]'
    if isinstance(value, dict):
        return 'Optional[Dict[str, Any]]'
    return 'Optional[Any]'


def generate_schema_from_api_response(
    transform_name: str,
    api_response: Dict[str, Any],
    criteria_key: str
) -> str:
    """Generate Pydantic schema code from API response analysis."""

    class_name = ''.join(word.capitalize() for word in transform_name.replace('_', ' ').split()) + 'Input'

    structure = api_response.get('structure', {})
    top_keys = api_response.get('top_level_keys', [])

    # Generate field definitions
    fields = []
    for key in top_keys:
        value = structure.get(key)
        field_type = python_type_from_value(value)
        fields.append(f'    {key}: {field_type} = None')

    if not fields:
        fields = ['    pass']

    schema_code = f'''"""Schema for {transform_name} transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class {class_name}(BaseModel):
    """
    Expected input schema for the {transform_name} transformation.
    Criteria key: {criteria_key}
    """

{chr(10).join(fields)}

    class Config:
        extra = "allow"
'''
    return schema_code


def generate_basic_schema(transform_name: str) -> str:
    """Generate a basic schema when no API response is available."""

    class_name = ''.join(word.capitalize() for word in transform_name.replace('_', ' ').split()) + 'Input'

    schema_code = f'''"""Schema for {transform_name} transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class {class_name}(BaseModel):
    """
    Expected input schema for the {transform_name} transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
'''
    return schema_code


def generate_init_file(schemas: List[str]) -> str:
    """Generate __init__.py content for schemas package."""
    imports = []
    exports = []

    for schema_name in sorted(schemas):
        class_name = ''.join(word.capitalize() for word in schema_name.replace('_', ' ').split()) + 'Input'
        imports.append(f'from .{schema_name} import {class_name}')
        exports.append(f'    "{class_name}",')

    return f'''"""Pydantic schemas for transformation inputs."""

{chr(10).join(imports)}

__all__ = [
{chr(10).join(exports)}
]
'''


def process_safeguard(
    safeguard_dir: Path,
    unmatched_log: List[str]
) -> Tuple[int, int]:
    """Process a single safeguard directory and generate schemas."""

    schemas_dir = safeguard_dir / 'schemas'
    schemas_dir.mkdir(exist_ok=True)

    # Get transformations and API responses
    transforms = get_transformations(safeguard_dir)
    api_responses = get_api_responses(safeguard_dir)

    # Track what we've matched
    matched_responses = set()
    schema_names = []

    schemas_created = 0

    for transform in transforms:
        transform_name = transform.stem

        # Skip if schema already exists
        schema_path = schemas_dir / f'{transform_name}.py'
        if schema_path.exists():
            schema_names.append(transform_name)
            continue

        # Try to find matching API response
        criteria_key = transform_name.lower()

        if criteria_key in api_responses:
            response_path = api_responses[criteria_key]
            matched_responses.add(criteria_key)
            api_analysis = analyze_api_response(response_path)
            schema_code = generate_schema_from_api_response(
                transform_name, api_analysis, criteria_key
            )
        else:
            schema_code = generate_basic_schema(transform_name)

        # Write schema file
        with open(schema_path, 'w') as f:
            f.write(schema_code)

        schema_names.append(transform_name)
        schemas_created += 1

    # Log unmatched API responses
    unmatched = set(api_responses.keys()) - matched_responses
    for key in unmatched:
        unmatched_log.append(f'{safeguard_dir.name}: {api_responses[key].name}')

    # Generate __init__.py
    if schema_names:
        init_path = schemas_dir / '__init__.py'
        with open(init_path, 'w') as f:
            f.write(generate_init_file(schema_names))

    return schemas_created, len(unmatched)


def main():
    """Main entry point."""
    safeguards_path = Path('safeguards')

    if not safeguards_path.exists():
        print('Error: safeguards directory not found')
        return

    # Collect all safeguard directories
    safeguard_dirs = []

    # UUID-based directories
    for item in safeguards_path.iterdir():
        if item.is_dir() and item.name not in ('__pycache__', 'common', 'backups', 'epp', 'firewall'):
            if any(item.glob('*.py')):
                safeguard_dirs.append(item)

    # Nested directories
    for nested in ['backups/datto', 'epp/crowdstrike', 'firewall/cisco/fmc']:
        nested_path = safeguards_path / nested
        if nested_path.exists() and any(nested_path.glob('*.py')):
            safeguard_dirs.append(nested_path)

    print(f'Found {len(safeguard_dirs)} safeguard directories')

    unmatched_log = []
    total_schemas = 0
    total_unmatched = 0

    for safeguard_dir in sorted(safeguard_dirs):
        print(f'Processing: {safeguard_dir.name}...')
        schemas, unmatched = process_safeguard(safeguard_dir, unmatched_log)
        total_schemas += schemas
        total_unmatched += unmatched
        if schemas > 0:
            print(f'  Created {schemas} schemas')
        if unmatched > 0:
            print(f'  {unmatched} unmatched API responses')

    # Write unmatched log
    log_path = safeguards_path / 'unmatched_api_responses.log'
    with open(log_path, 'w') as f:
        f.write('# Unmatched API Responses Log\n')
        f.write('# These API response files do not have corresponding transformation files.\n\n')
        for entry in sorted(unmatched_log):
            f.write(f'{entry}\n')

    print(f'\nSummary:')
    print(f'  Total schemas created: {total_schemas}')
    print(f'  Total unmatched API responses: {total_unmatched}')
    print(f'  Unmatched log written to: {log_path}')


if __name__ == '__main__':
    main()
