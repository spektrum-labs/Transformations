# Transformations

The **Transformations** repository contains logic used to transform third-party API responses into values that can be evaluated by a Third Party Requirements token within the **Spektrum** network. This repository is designed to standardize the process of transforming various API responses into a format that Spektrum can understand and use.

## Purpose

The primary purpose of this repository is to provide a common framework for transforming data from third-party vendors into the required format. Each transformation logic is encapsulated in a separate file, allowing easy integration and customization for various vendors.

## Directory Structure

The directory structure follows a clear hierarchy to organize transformation logic:

```
Transformations
│── safeguards
│   └── SRN/
│       └── srn_transform.py
│   └── …
│   └── SRN2/
│       │── srn2_transform.py
│       └── …
└── …
```

- **Safeguards**: This directory contains safeguard logic files that implement rules to ensure data integrity and compliance during transformations.
- **Vendor Directories**: Each vendor (e.g., Vendor1, Vendor2) has its own subdirectory, where transformation logic specific to that vendor resides.

## File Implementation

Each file within the repository must implement a method called `transform`, which will:
- Accept a JSON input (typically the third-party API response).
- Return a JSON object with the transformed results that can be evaluated by the Third Party Requirements token in the Spektrum network.

Example of a transformation implementation:

```python
def transform(input_json):
    # Implement transformation logic here
    transformed_data = {
        "key": "transformed_value"
    }
    return transformed_data