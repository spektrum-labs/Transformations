# Used to test a raw API response against a transformation locally
# Replicates the Token-Service src.utils.evaluate pipeline:
#   1. Parse/unwrap API response (_parse_api_response_for_transformer)
#   2. Load schema from schemas/ subdirectory (SchemaValidator)
#   3. Validate input against schema
#   4. Detect new format (extract_input pattern) and create enriched input
#   5. Execute transform()

#!/usr/bin/env python3
import sys
import json
import importlib.util
import os
import ast
import tempfile
import requests
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

try:
    from pydantic import BaseModel, Field, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False


def is_url(string):
    """Check if the given string is a URL."""
    try:
        result = urllib.parse.urlparse(string)
        return all([result.scheme, result.netloc])
    except:
        return False


def download_transformation(url):
    """Download a Python transformation file from a URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp_file:
            temp_file.write(response.content)
            return temp_file.name
    except Exception as e:
        raise Exception(f"Failed to download transformation from URL: {e}")


def load_transformation_module(file_path):
    """Dynamically load a Python module from a file path."""
    module_name = os.path.basename(file_path).replace('.py', '')
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None:
        raise ImportError(f"Could not load spec for module from {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_data_json(file_path):
    """Load and parse a JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Replicates Token-Service: codeexecutor._parse_api_response_for_transformer
# ---------------------------------------------------------------------------
def parse_api_response_for_transformer(input_data):
    """
    Parse API response data to extract the actual payload for transformation.
    Mirrors Token-Service src/utils/codeexecutor.py _parse_api_response_for_transformer.
    """
    def _parse_single_input(data):
        if isinstance(data, str):
            if not data.strip():
                return data
            try:
                parsed = ast.literal_eval(data)
                if isinstance(parsed, (dict, list)):
                    return parsed
            except (ValueError, SyntaxError):
                pass
            try:
                return json.loads(data)
            except (json.JSONDecodeError, ValueError):
                return data
        elif isinstance(data, bytes):
            try:
                return json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return data.decode("utf-8", errors="replace")
        elif isinstance(data, (dict, list, int, float, bool)) or data is None:
            return data
        else:
            return str(data)

    current_data = _parse_single_input(input_data)

    # Navigate through common response wrapper structures
    navigation_keys = ['response', 'result', 'apiResponse', 'Output', 'data']
    for key in navigation_keys:
        if isinstance(current_data, dict) and key in current_data:
            current_data = _parse_single_input(current_data[key])

    return current_data


# ---------------------------------------------------------------------------
# Replicates Token-Service: codeexecutor._transformation_uses_new_format
# ---------------------------------------------------------------------------
def transformation_uses_new_format(code):
    """Check if transformation code handles new enriched input format."""
    new_format_indicators = [
        'input["data"]',
        "input['data']",
        'input.get("data"',
        "input.get('data'",
        "extract_input(",
    ]
    return any(indicator in code for indicator in new_format_indicators)


# ---------------------------------------------------------------------------
# Replicates Token-Service: schema_validator.SchemaValidator
# ---------------------------------------------------------------------------
def load_and_validate_schema(schema_file_path, parsed_data):
    """
    Load a Pydantic schema from file and validate data against it.
    Mirrors Token-Service src/utils/schema_validator.py SchemaValidator.
    """
    if not PYDANTIC_AVAILABLE:
        return None, {
            "status": "skipped",
            "errors": [],
            "warnings": ["Pydantic not installed - schema validation skipped"]
        }

    if not schema_file_path or not os.path.exists(schema_file_path):
        return None, {
            "status": "skipped",
            "errors": [],
            "warnings": ["No schema available for validation"]
        }

    try:
        with open(schema_file_path, 'r') as f:
            schema_code = f.read()
    except Exception as e:
        return None, {
            "status": "error",
            "errors": [f"Failed to read schema file: {e}"],
            "warnings": []
        }

    # Build namespace matching Token-Service SCHEMA_GLOBALS
    import builtins
    from typing import Union
    def _safe_import(name, *args, **kwargs):
        """Limited import that only allows __future__ (needed for annotations)."""
        if name == "__future__":
            import __future__
            return __future__
        raise ImportError(f"Import not allowed in schema: {name}")

    namespace = {
        "BaseModel": BaseModel,
        "Field": Field,
        "Optional": Optional,
        "Dict": Dict,
        "List": list,
        "Any": Any,
        "Union": Union,
        "__name__": "__schema__",
        "__builtins__": {
            "str": str, "int": int, "float": float, "bool": bool,
            "list": list, "dict": dict, "tuple": tuple, "set": set,
            "None": None, "True": True, "False": False,
            "isinstance": isinstance, "len": len,
            "__build_class__": builtins.__build_class__,
            "__import__": _safe_import,
        }
    }

    # Strip imports (Token-Service strips all imports from schema code)
    import re
    schema_code = re.sub(r'from\s+[\w.]+\s+import\s+\([^)]*\)', '', schema_code, flags=re.DOTALL)
    schema_code = re.sub(r'from\s+[\w.]+\s+import\s+[^\n(]+\n', '\n', schema_code)
    schema_code = re.sub(r'^import\s+[\w.,\s]+$', '', schema_code, flags=re.MULTILINE)

    # Prepend future annotations
    if not schema_code.strip().startswith("from __future__"):
        schema_code = "from __future__ import annotations\n" + schema_code

    try:
        exec(schema_code, namespace, namespace)

        # Rebuild Pydantic models
        for name, obj in namespace.items():
            if isinstance(obj, type) and issubclass(obj, BaseModel) and obj is not BaseModel:
                try:
                    obj.model_rebuild(_types_namespace=namespace)
                except Exception:
                    pass

        # Find the *Input class
        input_class = None
        for name, obj in namespace.items():
            if (name.endswith("Input") and isinstance(obj, type) and issubclass(obj, BaseModel)):
                input_class = obj
                break

        if input_class is None:
            return None, {
                "status": "skipped",
                "errors": [],
                "warnings": ["No *Input class found in schema code"]
            }

    except Exception as e:
        return None, {
            "status": "error",
            "errors": [f"Failed to load schema class: {e}"],
            "warnings": []
        }

    # Validate data against schema
    try:
        input_class.model_validate(parsed_data)
        return input_class, {
            "status": "passed",
            "errors": [],
            "warnings": []
        }
    except ValidationError as e:
        errors = []
        for err in e.errors():
            location = " → ".join(str(x) for x in err.get("loc", []))
            message = err.get("msg", "Unknown error")
            if location:
                errors.append(f"{location}: {message}")
            else:
                errors.append(message)
        return input_class, {
            "status": "failed",
            "errors": errors,
            "warnings": []
        }
    except Exception as e:
        return input_class, {
            "status": "error",
            "errors": [f"Validation error: {str(e)}"],
            "warnings": []
        }


def derive_schema_path(transformation_file):
    """Derive schema file path from transformation file path (mirrors URL-based schema lookup)."""
    dir_path = os.path.dirname(transformation_file)
    filename = os.path.basename(transformation_file)
    schema_path = os.path.join(dir_path, "schemas", filename)
    return schema_path if os.path.exists(schema_path) else None


def main():
    if len(sys.argv) != 3:
        print("Usage: python local_tester.py <transformation_file_or_url.py> <data.json>")
        sys.exit(1)

    transformation_source = sys.argv[1]
    data_file = sys.argv[2]
    temp_file = None

    # Check if the transformation source is a URL
    if is_url(transformation_source):
        try:
            print(f"Downloading transformation from URL: {transformation_source}")
            temp_file = download_transformation(transformation_source)
            transformation_file = temp_file
            print(f"Downloaded transformation to temporary file: {temp_file}")
        except Exception as e:
            print(f"Error downloading transformation: {e}")
            sys.exit(1)
    else:
        transformation_file = transformation_source

    # Load the transformation module
    try:
        transformation_module = load_transformation_module(transformation_file)
        print(f"Successfully loaded transformation from {transformation_source}")
    except Exception as e:
        print(f"Error loading transformation: {e}")
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)
        sys.exit(1)

    # Load the data
    try:
        data = load_data_json(data_file)
        print(f"Successfully loaded data from {data_file}")
    except Exception as e:
        print(f"Error loading data: {e}")
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)
        sys.exit(1)

    # Check if the module has a transform method
    if not hasattr(transformation_module, 'transform'):
        print(f"Error: Transformation does not contain a 'transform' function")
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Step 1: Parse/unwrap API response (mirrors Token-Service pipeline)
    # -----------------------------------------------------------------------
    parsed_data = parse_api_response_for_transformer(data)
    print(f"\n--- API Response Parsing ---")
    print(f"Original input type: {type(data).__name__}, keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
    print(f"Parsed data type: {type(parsed_data).__name__}, keys: {list(parsed_data.keys()) if isinstance(parsed_data, dict) else 'N/A'}")

    # -----------------------------------------------------------------------
    # Step 2: Schema validation
    # -----------------------------------------------------------------------
    schema_path = derive_schema_path(transformation_file)
    print(f"\n--- Schema Validation ---")
    if schema_path:
        print(f"Schema found: {schema_path}")
    else:
        print(f"No schema found at: {os.path.join(os.path.dirname(transformation_file), 'schemas', os.path.basename(transformation_file))}")

    schema_class, validation_result = load_and_validate_schema(schema_path, parsed_data)
    print(f"Validation status: {validation_result['status']}")
    if validation_result.get('errors'):
        for err in validation_result['errors']:
            print(f"  ERROR: {err}")
    if validation_result.get('warnings'):
        for warn in validation_result['warnings']:
            print(f"  WARNING: {warn}")

    # -----------------------------------------------------------------------
    # Step 3: Detect format and create enriched input
    # -----------------------------------------------------------------------
    with open(transformation_file, 'r') as f:
        transformation_code = f.read()

    uses_new_format = transformation_uses_new_format(transformation_code)
    print(f"\n--- Input Format ---")
    print(f"Uses new enriched format: {uses_new_format}")

    if uses_new_format:
        transform_input = {"data": parsed_data, "validation": validation_result}
        print(f"Wrapping as enriched input: {{\"data\": <parsed_data>, \"validation\": <validation_result>}}")
    else:
        transform_input = parsed_data
        print(f"Using parsed data directly (legacy format)")

    # -----------------------------------------------------------------------
    # Step 4: Execute transformation
    # -----------------------------------------------------------------------
    try:
        print(f"\n--- Transformation Result ---")
        result = transformation_module.transform(transform_input)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error during transformation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)


if __name__ == "__main__":
    main()
