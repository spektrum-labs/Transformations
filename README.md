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

## Safeguard Registry

Quick reference for safeguard directories by category and vendor:

### Attack Surface Management
| Vendor | Safeguard SRN |
|--------|---------------|
| Qualys, Inc. | [A6B871E6-DE13-41FA-8636-81A3B6F315F4](safeguards/a6b871e6-de13-41fa-8636-81a3b6f315f4/) |

### Backups
| Vendor | Safeguard SRN |
|--------|---------------|
| AWS | [4BC425FA-0638-4BF1-8194-19E7E4F2F43C](safeguards/4BC425FA-0638-4BF1-8194-19E7E4F2F43C/) |
| Azure | [729CEBC6-8ABD-4511-AC85-1455A690EEBE](safeguards/729cebc6-8abd-4511-ac85-1455a690eebe/) |

### Compliance Management
| Vendor | Safeguard SRN |
|--------|---------------|
| KnowBe4, Inc. | [52BEAA98-6CED-4A84-B6D5-FAEA40E0FFEF](safeguards/52beaa98-6ced-4a84-b6d5-faea40e0ffef/) |

### Cyber Risk Quantification (CRQ)
| Vendor | Safeguard SRN |
|--------|---------------|
| Bitsight | [8F2E8F1F-005E-4254-B400-58B1DABE055E](safeguards/8f2e8f1f-005e-4254-b400-58b1dabe055e/) |

### Email Security
| Vendor | Safeguard SRN |
|--------|---------------|
| Google | [DBC425FA-0638-4BF1-8194-19E7E4F2F43C](safeguards/dbc425fa-0638-4bf1-8194-19e7e4f2f43c/) |
| Microsoft | [874A78FF-2CA3-4C0E-AB86-19277536AC87](safeguards/874a78ff-2ca3-4c0e-ab86-19277536ac87/) |
| Trend Micro | [0C281CE9-8024-4D70-AC85-D923A6B9635C](safeguards/0C281CE9-8024-4D70-AC85-D923A6B9635C/) |

### Endpoint Security
| Vendor | Safeguard SRN |
|--------|---------------|
| Halcyon | [BBC425FA-0638-4BF1-8194-19E7E4F2F43C](safeguards/BBC425FA-0638-4BF1-8194-19E7E4F2F43C/) |
| Microsoft | [7BC425FA-0638-4BF1-8194-19E7E4F2F43C](safeguards/7BC425FA-0638-4BF1-8194-19E7E4F2F43C/) |
| NinjaOne | [CAC4B80F-A930-415E-B1E3-DE285FE78452](safeguards/cac4b80f-a930-415e-b1e3-de285fe78452/) |
| SentinelOne | [2BC425FA-0638-4BF1-8194-19E7E4F2F43C](safeguards/2BC425FA-0638-4BF1-8194-19E7E4F2F43C/) |

### Firewall
| Vendor | Safeguard SRN |
|--------|---------------|
| Cato Networks | [9B5D9E9C-A713-451C-826C-A57BB4322576](safeguards/9B5D9E9C-A713-451C-826C-A57BB4322576/) |
| Cloudflare, Inc. | [2B2849D8-2FEA-4CAE-9A3C-8B315280752A](safeguards/2B2849D8-2FEA-4CAE-9A3C-8B315280752A/) |
| Fortinet | [0450D686-D997-4E20-B82F-827F61CB8371](safeguards/0450D686-D997-4E20-B82F-827F61CB8371/) |

### MDR
| Vendor | Safeguard SRN |
|--------|---------------|
| Sophos | [1BC425FA-0638-4BF1-8194-19E7E4F2F43C](safeguards/1BC425FA-0638-4BF1-8194-19E7E4F2F43C/) |

### Multifactor Authentication
| Vendor | Safeguard SRN |
|--------|---------------|
| Azure | [D9B6F27A-2E67-4B55-A09E-0784C5DE9ABD](safeguards/d9b6f27a-2e67-4b55-a09e-0784c5de9abd/) |
| Duo | [A2ABBCF5-6693-4B14-8329-8721302A4EF7](safeguards/a2abbcf5-6693-4b14-8329-8721302a4ef7/) |

### Network Security
| Vendor | Safeguard SRN |
|--------|---------------|
| Cisco | [182A41F5-BA7F-42C9-A3CD-7AA8399F5037](safeguards/182a41f5-ba7f-42c9-a3cd-7aa8399f5037/) |

> **Note:** The full registry is also available in [safeguards/registry.json](safeguards/registry.json)

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
```

# Testing locally

The local_tester.py was created to easily download a raw response and then use the transformationLogic URL to run a raw response through a transformer.  This can be used locally with Python by downloading the raw response and locating the URL (or file location) of the transformer in question, then by running:

```python
python local_tester.py <url or file path of transformer> <file path to raw response>