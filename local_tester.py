# Used to test a raw API response against a transformation locally

#!/usr/bin/env python3
import sys
import json
import importlib.util
import os

def load_transformation_module(file_path):
    """
    Dynamically load a Python module from a file path.
    """
    module_name = os.path.basename(file_path).replace('.py', '')
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None:
        raise ImportError(f"Could not load spec for module from {file_path}")
    
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_data_json(file_path):
    """
    Load and parse a JSON file.
    """
    with open(file_path, 'r') as f:
        return json.load(f)

def main():
    if len(sys.argv) != 3:
        print("Usage: python tester.py <transformation_file.py> <data.json>")
        sys.exit(1)
    
    transformation_file = sys.argv[1]
    data_file = sys.argv[2]
    
    # Load the transformation module
    try:
        transformation_module = load_transformation_module(transformation_file)
        print(f"Successfully loaded transformation from {transformation_file}")
    except Exception as e:
        print(f"Error loading transformation: {e}")
        sys.exit(1)
    
    # Load the data
    try:
        data = load_data_json(data_file)
        print(f"Successfully loaded data from {data_file}")
    except Exception as e:
        print(f"Error loading data: {e}")
        sys.exit(1)
    
    # Check if the module has a transform method
    if not hasattr(transformation_module, 'transform'):
        print(f"Error: {transformation_file} does not contain a 'transform' function")
        sys.exit(1)
    
    # Run the transform method
    try:
        result = transformation_module.transform(data)
        print("\nTransformation result:")
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error during transformation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
