"""Netwrix Auditor checks that could never pass: each read a name nothing defined.

isLogIngestActionActive and isRetentionCompliant used timezone (and timedelta) after importing
only datetime; isDataSourcesConfigured used MIN_DATA_SOURCES and KNOWN_DATA_SOURCES, never
defined. Any non-empty record list raised NameError, swallowed into a failed verdict. Behind
that, isLogIngestActionActive returned its verdict under a different key than transform()
reads, and isRetentionCompliant would have passed on ANY record, however recent.

Every body below is synthetic and runs the file as production does, under the RestrictedPython
mirror in tools/restricted_sandbox.py, past the line that used to raise.
"""
import importlib.util
import json
import pathlib
import unittest
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).parent
ROOT = HERE.resolve().parents[2]


def _tool(name):
    spec = importlib.util.spec_from_file_location("nx_" + name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SANDBOX = _tool("restricted_sandbox")
NAMES = _tool("check_sandbox_names")
FILES = {"islogingestactionactive.py": "isLogIngestActionActive",
         "isretentioncompliant.py": "isRetentionCompliant",
         "isdatasourcesconfigured.py": "isDataSourcesConfigured"}


def run(filename, body):
    out = SANDBOX.load((HERE / filename).read_text(), "<transformation>")["transform"](body)
    return out


def when(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).isoformat().replace("+00:00", "Z")


def record(ts, source="Active Directory"):
    return {"Action": "Modified", "DataSource": source, "Item": "example-item", "When": ts}


class Netwrix(unittest.TestCase):
    def verdict(self, filename, body):
        out = run(filename, body)
        text = json.dumps(out, default=str)
        self.assertNotIn("is not defined", text, text)
        self.assertEqual(out["additionalInfo"]["transformation"]["status"], "success", text)
        return out["transformedResponse"][FILES[filename]]

    def test_no_undefined_names(self):
        provided = NAMES.provided_names()
        for f in FILES:
            self.assertEqual(NAMES.undefined_names((HERE / f).read_text(), provided), {}, f)

    # isLogIngestActionActive
    def test_recent_record_shows_ingestion(self):
        body = {"ActivityRecordList": [record(when(hours=2)), record(when(days=9))]}
        self.assertIs(self.verdict("islogingestactionactive.py", body), True)

    def test_naive_recent_timestamp_counts(self):
        naive = (datetime.now(timezone.utc) - timedelta(hours=3)).replace(tzinfo=None).isoformat()
        self.assertIs(self.verdict("islogingestactionactive.py", {"ActivityRecordList": [record(naive)]}), True)

    def test_only_old_records_fail(self):
        self.assertIs(self.verdict("islogingestactionactive.py", {"ActivityRecordList": [record(when(days=5))]}), False)

    def test_future_dated_record_is_not_evidence(self):
        self.assertIs(self.verdict("islogingestactionactive.py", {"ActivityRecordList": [record(when(days=-3))]}), False)

    # isRetentionCompliant
    def test_record_older_than_180_days_passes(self):
        body = {"ActivityRecordList": [record(when(days=200)), record(when(days=10))]}
        self.assertIs(self.verdict("isretentioncompliant.py", body), True)

    def test_only_recent_records_fail(self):
        self.assertIs(self.verdict("isretentioncompliant.py", {"ActivityRecordList": [record(when(days=30))]}), False)

    def test_unreadable_timestamps_fail(self):
        self.assertIs(self.verdict("isretentioncompliant.py", {"ActivityRecordList": [record("yesterday")]}), False)

    # isDataSourcesConfigured
    def test_two_distinct_sources_pass(self):
        body = {"ActivityRecordList": [record(when(hours=1), "Active Directory"),
                                       record(when(hours=1), "Exchange Online"),
                                       record(when(hours=1), "Windows File Servers")]}
        out = run("isdatasourcesconfigured.py", body)
        self.assertIs(self.verdict("isdatasourcesconfigured.py", body), True)
        self.assertEqual(out["transformedResponse"]["categoriesFound"], ["email", "fileStorage", "identity"])

    def test_one_source_fails(self):
        body = {"ActivityRecordList": [record(when(hours=1)), record(when(hours=2))]}
        self.assertIs(self.verdict("isdatasourcesconfigured.py", body), False)


if __name__ == "__main__":
    unittest.main()
