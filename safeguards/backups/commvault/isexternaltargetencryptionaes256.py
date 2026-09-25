# isexternaltargetencryptionaes256.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getStorageEncryption (Integration-Service workflow)
#   1. getDiskStorage        -> GET {serverUrl}/V4/Storage/Disk
#   2. getDiskStorageDetail  -> GET {serverUrl}/V4/Storage/Disk/{id}, once per pool (iterate diskStorage), under diskStorageDetails
#   3. getCloudStorage       -> GET {serverUrl}/V4/Storage/Cloud
#   4. getCloudStorageDetail -> GET {serverUrl}/V4/Storage/Cloud/{id}, once per pool (iterate cloudStorage), under cloudStorageDetails
# Docs:   https://github.com/Commvault/CVPowershellSDKV2/blob/main/OpenAPI3.yaml (Commvault's published V4 OpenAPI 3 spec)
#         GetDiskStorageDetails / GetCloudStorageById: encryption.encrypt, encryption.cipher (BlowFish, AES, DES3,
#         GOST, Serpent, Twofish), encryption.keyLength.
# A pool list whose detail bodies are missing or a different count is refused (part of the estate unread).
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    isExternalTargetEncryptionAES256 = true when at least one cloud storage pool exists and every one is
    encrypted with cipher "AES" and keyLength 256. false otherwise.
    """
    key = "isExternalTargetEncryptionAES256"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("XML body; the method must send Accept: application/json")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        # Integration-Service may hand the body back under one of its envelopes.
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def vendor_error(d):
        """A reason string when the body is an Integration-Service or Commvault error, else None.
        Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        code = d.get("errorCode")
        if code not in (None, 0, "0"):
            return "Commvault error " + str(code) + ": " + str(d.get("errorMessage") or "")
        errs = d.get("errList")
        if isinstance(errs, list) and len(errs) > 0:
            return "Commvault errList: " + str(errs[0])[:200]
        err = d.get("error")
        if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
            return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")
        return None

    def as_int(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        return None

    def pools(data, list_key, detail_key):
        """(details, None) or (None, reason): the detail body of every pool in data[list_key]."""
        listed = data.get(list_key)
        if not isinstance(listed, list):
            return None, "Response has no " + list_key + " list"
        if len(listed) == 0:
            return [], None
        details = data.get(detail_key)
        if isinstance(details, dict):
            details = [details]
        if not isinstance(details, list) or len(details) != len(listed):
            n = len(details) if isinstance(details, list) else 0
            return None, "Read " + str(n) + " " + detail_key + " bodies for " + str(len(listed)) + " pools"
        out = []
        for i in range(len(details)):
            b = unwrap(details[i], "encryption")
            problem = vendor_error(b)
            if problem:
                return None, list_key + " pool " + str(listed[i].get("name") if isinstance(listed[i], dict) else i) + ": " + problem
            if not isinstance(b.get("encryption"), dict):
                return None, list_key + " pool " + str(b.get("name") or i) + " detail has no encryption object"
            out.append(b)
        return out, None

    def read_all(input):
        data = unwrap(parse_input(input), "diskStorage")
        problem = vendor_error(data)
        if problem:
            return None, None, problem
        disk, problem = pools(data, "diskStorage", "diskStorageDetails")
        if disk is None:
            return None, None, problem
        cloud, problem = pools(data, "cloudStorage", "cloudStorageDetails")
        if cloud is None:
            return None, None, problem
        return disk, cloud, None

    def encrypted(b):
        return b["encryption"].get("encrypt") is True

    try:
        disk, cloud, problem = read_all(input)
        if problem:
            return {key: False, "reason": problem}
        if len(cloud) == 0:
            return {key: False, "reason": "No cloud storage pool exists"}
        bad = []
        for b in cloud:
            e = b["encryption"]
            if not encrypted(b) or str(e.get("cipher") or "").upper() != "AES" or as_int(e.get("keyLength")) != 256:
                bad.append(str(b.get("name") or b.get("id")) + " (" + str(e.get("cipher")) + " " + str(e.get("keyLength")) + ")")
        if bad:
            return {key: False, "reason": str(len(bad)) + " of " + str(len(cloud)) + " cloud storage pools are not AES-256", "pools": bad[:25]}
        return {key: True, "reason": "All " + str(len(cloud)) + " cloud storage pools use AES-256"}
    except Exception as e:
        return {key: False, "error": str(e)}
