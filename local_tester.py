# Used to test a raw API response against a transformation locally

#!/usr/bin/env python3
import sys
import json
import importlib.util
import os
import tempfile
import requests
import urllib.parse

def is_url(string):
    """
    Check if the given string is a URL.
    """
    try:
        result = urllib.parse.urlparse(string)
        return all([result.scheme, result.netloc])
    except:
        return False

def download_transformation(url):
    """
    Download a Python transformation file from a URL.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        # Create a temporary file to store the downloaded code
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp_file:
            temp_file.write(response.content)
            return temp_file.name
    except Exception as e:
        raise Exception(f"Failed to download transformation from URL: {e}")

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
    
    # Run the transform method
    try:
        result = transformation_module.transform(data)
        print("\nTransformation result:")
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error during transformation: {e}")
        sys.exit(1)
    finally:
        # Clean up the temporary file if it exists
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)

if __name__ == "__main__":
    main()
