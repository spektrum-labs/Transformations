"""Bodies that prove nothing must read as not measured; real bodies must still be graded.

Token-Service grades a criterion unless additionalInfo.dataCollection.status is "error", so every
unmeasured path must return the key as None WITH a dataCollection error (value-keyed envelope).
A well-formed body that says "off" must still return False + "success", and one that says "on"
True + "success". Synthetic data only.
"""
import base64
import importlib.util
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("nm_azure_729_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


NO_EVIDENCE = [
    ("empty_dict", lambda: {}),
    ("empty_list", lambda: []),
    ("null", lambda: None),
    ("not_available", lambda: {"status": "Not Available"}),
    ("refusal_401", lambda: {"error": True, "statusCode": 401, "message": "invalid api key"}),
    ("refusal_403", lambda: {"error": {"type": "permission_error", "message": "Missing required scopes"}}),
    ("aws_access_denied", lambda: {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}),
    ("poisoned", lambda: Poisoned()),
]


def days_ago(n, fmt="%Y-%m-%dT%H:%M:%SZ"):
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime(fmt)


def b64json(obj):
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


ANY_VALUE = object()

FILES = [
    ("isbackupenabled", "isBackupEnabled"),
    ("is_backup_enabled_for_critical_systems", "isBackupEnabledForCriticalSystems"),
    ("is_backup_logging_enabled", "isBackupLoggingEnabled"),
    ("is_backup_tested", "isBackupTested"),
    ("is_backup_types_scheduled", "isBackupTypesScheduled"),
]

EXTRA_UNMEASURED = {
    # arg_rows_empty: zero Resource Graph rows is RBAC-ambiguous and is not measured.
    # See CONTRIBUTING.md, "Azure Resource Graph: zero rows is not a proven empty set".
    "isbackupenabled": [("data_without_rows", lambda: {"data": {"columns": []}}),
                        ("arg_rows_empty", lambda: {"data": {"rows": []}}),
                        # Vault rows prove a vault exists, not that anything is backed up.
                        ("vault_rows_only", lambda: {"data": {"rows": [["vault-1"]]}}),
                        ("vault_rows_with_diagnostic_settings",
                         lambda: {"data": {"rows": [{"vaultType": "RecoveryServicesVault", "name": "vault-1",
                                                     "diagnosticSettings": {"hasDiagnosticSettings": True}}]}}),
                        ("no_vault_pages", lambda: {"protectedItems": []})],
    "is_backup_types_scheduled": [("data_without_rows", lambda: {"data": {"columns": []}}),
                                  ("arg_rows_empty", lambda: {"data": {"rows": []}})],
    "is_backup_tested": [("arg_rows_empty", lambda: {"data": {"columns": [{"name": "name"}], "rows": []}})],
    "is_backup_logging_enabled": [("diagnostic_settings_stub", lambda: {"diagnosticSettings": [{"status": "Not Available"}]})],
}


def auto_backups(group):
    return {"dbBackups": {"DescribeDBInstanceAutomatedBackupsResponse": {
        "DescribeDBInstanceAutomatedBackupsResult": {"DBInstanceAutomatedBackups": group}}}}


def setting(enabled):
    return {"value": [{"name": "s1", "properties": {
        "logs": [{"category": "AzureBackupReport", "enabled": enabled}], "workspaceId": "/workspaces/w1"}}]}


def restore(status):
    return {"value": [{"id": "j1", "properties": {"operation": "Restore", "status": status, "endTime": days_ago(20)}}]}


MEASURED = {
    "isbackupenabled": [
        # Backup is enabled only when a protected item is actively protected.
        ("active_protected_item", lambda: {"protectedItems": [{"value": [
            {"name": "vm-1", "properties": {"protectionStatus": "Healthy"}}]}]}, True),
        ("vault_read_with_no_active_item", lambda: {"protectedItems": [{"value": [
            {"name": "vm-1", "properties": {"protectionState": "ProtectionStopped"}}]}]}, False),
        ("vault_read_with_no_items", lambda: {"value": []}, False),
    ],
    "is_backup_enabled_for_critical_systems": [
        ("no_automated_backups", lambda: auto_backups({}), False),
        ("one_automated_backup", lambda: auto_backups({"DBInstanceAutomatedBackup": {"DBInstanceIdentifier": "db1"}}), True),
    ],
    "is_backup_logging_enabled": [
        ("no_settings", lambda: {"value": []}, False),
        ("log_category_disabled", lambda: setting(False), False),
        ("log_category_enabled", lambda: setting(True), True),
    ],
    "is_backup_tested": [
        ("no_restore_jobs", lambda: {"value": []}, False),
        ("failed_restore", lambda: restore("Failed"), False),
        ("successful_restore", lambda: restore("Completed"), True),
    ],
    "is_backup_types_scheduled": [
        # A row that CAME BACK and reports zero protected items is a measured False: that
        # vault was read. Only the empty rows array is ambiguous.
        ("zero_protected_items", lambda: {"data": {"rows": [{"properties": {"protectedItemsCount": 0}}]}}, False),
        ("protected_items", lambda: {"data": {"rows": [{"properties": {"protectedItemsCount": 3}}]}}, True),
    ],
}


def run(name, key, body):
    out = load(name).transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]


class NotMeasuredIsNotGraded(unittest.TestCase):
    def test_no_evidence_reads_as_not_measured(self):
        for name, key in FILES:
            for case, body in NO_EVIDENCE + EXTRA_UNMEASURED.get(name, []):
                with self.subTest(transform=name, body=case):
                    value, collection = run(name, key, body())
                    self.assertIsNone(value)
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])
                    self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))

    def test_measured_answers_are_still_graded(self):
        for name, key in FILES:
            for case, body, expected in MEASURED.get(name, []):
                with self.subTest(transform=name, body=case):
                    value, collection = run(name, key, body())
                    if expected is ANY_VALUE:
                        self.assertIsNotNone(value)
                    else:
                        self.assertIs(value, expected)
                    self.assertEqual(collection["status"], "success")
                    self.assertEqual(collection["errors"], [])

    def test_every_file_has_a_measured_case(self):
        for name, _key in FILES:
            self.assertTrue(MEASURED.get(name), name)


SAFEGUARDS = os.path.dirname(HERE)
AZURE = os.path.join(SAFEGUARDS, "backups", "azure")

# Every Azure Resource Graph reader in the tree, both the 729 set and its drifted copies
# under backups/azure. The census is asserted complete by
# test_no_resource_graph_reader_is_missing_from_this_list below, so a new one cannot be
# added outside the rule without this file failing. The two isbackupenabled files are not listed
# any more: they no longer read the Resource Graph vault table (rows of vaults prove nothing about
# backup); they read protected items, and their zero-rows and vault-rows bodies are covered by
# EXTRA_UNMEASURED above and by backups/azure/test_false_pass_azure_backup.py.
ARG_ROWS_READERS = [
    ("729/confirmedlicensepurchased", "confirmedLicensePurchased", os.path.join(HERE, "confirmedlicensepurchased.py")),
    ("729/is_backup_encrypted", "isBackupEncrypted", os.path.join(HERE, "is_backup_encrypted.py")),
    ("729/is_backup_immutable", "isBackupImmutable", os.path.join(HERE, "is_backup_immutable.py")),
    ("729/is_backup_tested", "isBackupTested", os.path.join(HERE, "is_backup_tested.py")),
    ("729/is_backup_types_scheduled", "isBackupTypesScheduled", os.path.join(HERE, "is_backup_types_scheduled.py")),
    ("azure/backupfrequency", "backupFrequency", os.path.join(AZURE, "backupfrequency.py")),
    ("azure/is_backup_encrypted", "isBackupEncrypted", os.path.join(AZURE, "is_backup_encrypted.py")),
    ("azure/is_backup_immutable", "isBackupImmutable", os.path.join(AZURE, "is_backup_immutable.py")),
    ("azure/is_backup_tested", "isBackupTested", os.path.join(AZURE, "is_backup_tested.py")),
    ("azure/is_backup_types_scheduled", "isBackupTypesScheduled", os.path.join(AZURE, "is_backup_types_scheduled.py")),
]


def load_path(label, path):
    spec = importlib.util.spec_from_file_location("arg_rows_" + label, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ZeroResourceGraphRowsIsNotMeasured(unittest.TestCase):
    """One rule for every Resource Graph reader here, so the next reader cannot differ.

    Resource Graph is RBAC-scoped. A wholly unreadable scope answers 403, but a PARTIALLY
    readable one answers 200 carrying only the readable subset and, in Microsoft's words,
    "without any indication that the result might be partial"
    (learn.microsoft.com/azure/governance/resource-graph/overview#permissions-in-azure-resource-graph).
    Zero rows is therefore equally "there are none" and "the vaults are in a subscription
    this principal cannot read", so it may not be reported as a measured answer.
    """

    VALIDATION = {"status": "passed", "errors": [], "warnings": []}

    EMPTY_ROWS = [
        ("flat", {"columns": [{"name": "result"}], "rows": [], "totalRecords": 0}),
        ("nested", {"data": {"columns": [{"name": "result"}], "rows": [], "totalRecords": 0}}),
        ("rows_only", {"data": {"rows": []}}),
    ]

    def test_every_resource_graph_reader_treats_zero_rows_alike(self):
        for label, key, path in ARG_ROWS_READERS:
            module = load_path(label, path)
            for shape, body in self.EMPTY_ROWS:
                with self.subTest(transform=label, shape=shape):
                    out = module.transform({"data": body, "validation": self.VALIDATION})
                    collection = out["additionalInfo"]["dataCollection"]
                    self.assertIsNone(out["transformedResponse"][key],
                                      label + " reported a measured answer from zero Resource Graph rows")
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])

    def test_the_rule_does_not_leak_to_arm_list_endpoints(self):
        """An ARM list 403s on an unreadable scope, so ITS empty list is a proven empty set."""
        module = load_path("is_backup_tested", os.path.join(HERE, "is_backup_tested.py"))
        out = module.transform({"data": {"value": []}, "validation": self.VALIDATION})
        self.assertIs(out["transformedResponse"]["isBackupTested"], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_no_resource_graph_reader_is_missing_from_this_list(self):
        """The rule is only as good as the census, so the census is asserted, not sampled.

        A transform is a Resource Graph reader when it names Resource Graph AND reads a
        "rows" key. That pair is what distinguishes the Azure files from Datto BCDR, whose
        own envelope also carries data.rows, and from the EPP checks, which merely list
        "rows" among candidate container keys. Any new one must be added here, which forces
        whoever adds it to decide what it does with zero rows.
        """
        listed = set()
        for _, _, path in ARG_ROWS_READERS:
            listed.add(os.path.realpath(path))
        found = set()
        for folder, _, names in os.walk(SAFEGUARDS):
            for name in names:
                if not name.endswith(".py") or name.startswith("test_") or name == "__init__.py":
                    continue
                if os.path.basename(folder) == "schemas":
                    continue
                path = os.path.join(folder, name)
                with open(path, encoding="utf-8") as handle:
                    source = handle.read()
                if '"rows"' in source and "esource Graph" in source:
                    found.add(os.path.realpath(path))
        missing = sorted(os.path.relpath(p, SAFEGUARDS) for p in found - listed)
        self.assertEqual(missing, [], "Resource Graph readers not covered by the zero-rows rule: "
                                      + ", ".join(missing))
        stale = sorted(os.path.relpath(p, SAFEGUARDS) for p in listed - found)
        self.assertEqual(stale, [], "listed but no longer a Resource Graph reader: " + ", ".join(stale))

    def test_a_row_that_came_back_still_answers(self):
        """Only the EMPTY rows array is ambiguous; a row that was read is evidence."""
        module = load_path("is_backup_types_scheduled", os.path.join(HERE, "is_backup_types_scheduled.py"))
        out = module.transform({"data": {"data": {"rows": [{"properties": {"protectedItemsCount": 0}}]}},
                                "validation": self.VALIDATION})
        self.assertIs(out["transformedResponse"]["isBackupTypesScheduled"], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")


# The restore-job read is iterated once per vault, so the stored body is one ARM answer per
# vault under restoreJobResults: {"restoreJobResults": [{"value": [...]}, {"value": [...]}]}.
ARM_ERROR = {"error": {"code": "AuthorizationFailed",
                       "message": "The client does not have authorization to perform this action"}}
HTTP_FORBIDDEN = {"statusCode": 403, "message": "Forbidden"}
IS_BACKUP_TESTED_COPIES = [
    ("729/is_backup_tested", os.path.join(HERE, "is_backup_tested.py")),
    ("azure/is_backup_tested", os.path.join(AZURE, "is_backup_tested.py")),
]


def vault_read(*entries):
    return {"restoreJobResults": list(entries)}


def vault_with(*statuses, age=20):
    jobs = []
    for index, status in enumerate(statuses):
        jobs.append({"id": "job-" + str(index), "properties": {
            "operation": "Restore", "status": status, "endTime": days_ago(age)}})
    return {"value": jobs}


NEXT_PAGE = "https://management.azure.com/subscriptions/s/restoreJobs?$skiptoken=page2"


def paged(*statuses, key="nextLink", nested=None, age=20):
    """One vault's first page of restore jobs with a link to the next page (or a skip token)."""
    page = vault_with(*statuses, age=age)
    if nested:
        return {nested: dict(page, **{key: NEXT_PAGE})}
    page[key] = NEXT_PAGE
    return page


PAGE_LINK_KEYS = ["nextLink", "@odata.nextLink", "skipToken", "$skipToken"]


def job_list(*statuses, age=20):
    """The jobs themselves, with no vault wrapper around them."""
    return vault_with(*statuses, age=age)["value"]


VAULT_READ_SHAPES = [
    ("bare", lambda body: body),
    ("enveloped", lambda body: {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}),
    ("json_text", json.dumps),
]

# bodies where at least one vault's restore jobs were not read and no read vault shows a recent
# successful restore: absence of a restore is not proven, so there is no verdict
VAULT_READ_NOT_MEASURED = [
    ("zero_vaults_read", lambda: vault_read()),
    ("only_an_arm_error", lambda: vault_read(ARM_ERROR)),
    ("arm_error_beside_an_empty_vault", lambda: vault_read(vault_with(), ARM_ERROR)),
    ("arm_error_before_an_empty_vault", lambda: vault_read(ARM_ERROR, vault_with())),
    ("arm_error_beside_a_failed_restore", lambda: vault_read(vault_with("Failed"), ARM_ERROR)),
    ("arm_error_beside_a_stale_success", lambda: vault_read(vault_with("Completed", age=400), ARM_ERROR)),
    ("http_refusal_beside_an_empty_vault", lambda: vault_read(vault_with(), HTTP_FORBIDDEN)),
    ("text_entry_beside_an_empty_vault", lambda: vault_read(vault_with(), "Forbidden")),
    ("null_entry_beside_an_empty_vault", lambda: vault_read(vault_with(), None)),
    ("empty_entry_beside_an_empty_vault", lambda: vault_read(vault_with(), {})),
    ("entry_without_a_job_list", lambda: vault_read(vault_with(), {"value": "not a list"})),
    # a vault answered with a first page and a link to the next: the later pages were not read
    ("first_page_with_a_failed_restore", lambda: vault_read(paged("Failed"))),
    ("first_page_with_no_jobs", lambda: vault_read(paged())),
    ("first_page_with_a_stale_success", lambda: vault_read(paged("Completed", age=400))),
    ("first_page_beside_an_empty_vault", lambda: vault_read(vault_with(), paged("Failed"))),
    ("first_page_under_apiresponse", lambda: vault_read({"apiResponse": paged("Failed")})),
    ("first_page_under_data", lambda: vault_read({"data": paged("Failed")})),
    ("first_page_in_the_returnspec_shape", lambda: vault_read(
        {"restoreJobs": job_list("Failed"), "apiResponse": paged("Failed")})),
    # a list entry that is empty or holds an error is not a read vault (a failed call can leave [] behind)
    ("empty_list_entry", lambda: vault_read([])),
    ("empty_list_entry_beside_an_empty_vault", lambda: vault_read(vault_with(), [])),
    ("list_entry_holding_an_arm_error", lambda: vault_read(vault_with(), [ARM_ERROR])),
    ("list_entry_holding_text", lambda: vault_read(vault_with(), ["Forbidden"])),
    ("list_entry_of_jobs_and_an_error", lambda: vault_read(vault_with(), job_list("Failed") + [ARM_ERROR])),
    # a single restore-job list with no vault wrapper, and a next page
    ("bare_list_with_a_next_page", lambda: paged("Failed")),
    ("bare_empty_list_with_a_next_page", lambda: paged()),
    ("bare_list_in_apiresponse_with_a_next_page", lambda: {"apiResponse": paged("Failed")}),
    # job objects listed directly under restoreJobResults are one vault's list, and an error beside them is unread
    ("flat_failed_job_beside_an_arm_error", lambda: vault_read(*(job_list("Failed") + [ARM_ERROR]))),
    # job objects directly under restoreJobResults plus a next-page link: only the first page was read
    ("flat_failed_job_with_a_next_link", lambda: dict(vault_read(*job_list("Failed")), nextLink=NEXT_PAGE)),
    ("flat_failed_jobs_with_a_next_link", lambda: dict(vault_read(*job_list("Failed", "Failed")), nextLink=NEXT_PAGE)),
    ("flat_stale_success_with_a_next_link", lambda: dict(vault_read(*job_list("Completed", age=400)), nextLink=NEXT_PAGE)),
    ("flat_failed_job_with_a_next_link_under_apiresponse",
     lambda: {"apiResponse": dict(vault_read(*job_list("Failed")), nextLink=NEXT_PAGE)}),
    ("flat_failed_job_with_a_next_link_under_data",
     lambda: {"data": dict(vault_read(*job_list("Failed")), nextLink=NEXT_PAGE)}),
]
for _key in PAGE_LINK_KEYS:
    VAULT_READ_NOT_MEASURED.append(("first_page_with_" + _key, lambda _key=_key: vault_read(paged("Failed", key=_key))))
    VAULT_READ_NOT_MEASURED.append(("first_page_with_" + _key + "_under_apiresponse",
                                    lambda _key=_key: vault_read(paged("Failed", key=_key, nested="apiResponse"))))
    VAULT_READ_NOT_MEASURED.append(("bare_list_with_" + _key, lambda _key=_key: paged("Failed", key=_key)))
    VAULT_READ_NOT_MEASURED.append(("flat_failed_job_with_" + _key,
                                    lambda _key=_key: dict(vault_read(*job_list("Failed")), **{_key: NEXT_PAGE})))

# bodies where every vault was read: a missing restore is a measured negative, a recent
# successful one a measured positive
VAULT_READ_MEASURED = [
    ("one_vault_no_restore_jobs", lambda: vault_read(vault_with()), False),
    ("two_vaults_no_restore_jobs", lambda: vault_read(vault_with(), vault_with()), False),
    ("only_a_failed_restore", lambda: vault_read(vault_with("Failed")), False),
    ("only_a_stale_success", lambda: vault_read(vault_with("Completed", age=400)), False),
    ("a_recent_success", lambda: vault_read(vault_with("Completed")), True),
    ("a_recent_success_with_warnings", lambda: vault_read(vault_with("CompletedWithWarnings")), True),
    ("a_success_in_the_second_vault", lambda: vault_read(vault_with(), vault_with("Completed")), True),
    # a restore that did run proves recoverability even when another vault could not be read
    ("a_success_beside_an_arm_error", lambda: vault_read(vault_with("Completed"), ARM_ERROR), True),
    ("a_success_beside_an_http_refusal", lambda: vault_read(HTTP_FORBIDDEN, vault_with("Completed")), True),
    # the returnSpec shape of an entry: the job list under restoreJobs and again under apiResponse
    ("returnspec_entry_no_jobs", lambda: vault_read({"restoreJobs": [], "apiResponse": {"value": []}}), False),
    ("returnspec_entry_success", lambda: vault_read({"restoreJobs": vault_with("Completed")["value"],
                                                     "apiResponse": vault_with("Completed")}), True),
    # a seen success is proof even when its page has a next page, or another vault was not read
    ("success_on_a_first_page", lambda: vault_read(paged("Completed")), True),
    ("success_on_a_first_page_beside_an_arm_error", lambda: vault_read(paged("Completed"), ARM_ERROR), True),
    ("success_on_a_bare_first_page", lambda: paged("Completed"), True),
    ("success_on_a_bare_first_page_with_a_skip_token", lambda: paged("Completed", key="$skipToken"), True),
    # an empty or null next-page link means the answer is complete
    ("empty_next_link", lambda: vault_read(dict(vault_with(), nextLink="")), False),
    ("null_next_link", lambda: vault_read(dict(vault_with("Failed"), nextLink=None)), False),
    ("null_skip_token", lambda: vault_read(dict(vault_with(), skipToken=None)), False),
    ("empty_next_link_with_a_success", lambda: vault_read(dict(vault_with("Completed"), nextLink="")), True),
    ("bare_empty_next_link", lambda: dict(vault_with(), nextLink=""), False),
    # a list entry of job objects is one read vault
    ("list_entry_of_failed_jobs", lambda: vault_read(job_list("Failed")), False),
    ("list_entry_with_a_success", lambda: vault_read(job_list("Failed", "Completed")), True),
    # job objects listed directly under restoreJobResults are the jobs of one vault, read
    ("flat_failed_job", lambda: vault_read(*job_list("Failed")), False),
    ("flat_failed_jobs", lambda: vault_read(*job_list("Failed", "Failed")), False),
    ("flat_failed_and_completed_jobs", lambda: vault_read(*job_list("Failed", "Completed")), True),
    ("flat_stale_success", lambda: vault_read(*job_list("Completed", age=400)), False),
    # a flat list whose success was seen stays True even with a next page; an empty or null link is complete
    ("flat_success_with_a_next_link", lambda: dict(vault_read(*job_list("Failed", "Completed")), nextLink=NEXT_PAGE), True),
    ("flat_failed_job_with_an_empty_next_link", lambda: dict(vault_read(*job_list("Failed")), nextLink=""), False),
    ("flat_failed_job_with_a_null_next_link", lambda: dict(vault_read(*job_list("Failed")), nextLink=None), False),
    ("flat_failed_job_with_a_null_skip_token", lambda: dict(vault_read(*job_list("Failed")), skipToken=None), False),
]


class RestoreJobsAreReadPerVault(unittest.TestCase):
    """isBackupTested grades the vaults it read and says nothing about the ones it could not.

    The vault list is a Resource Graph read, so zero vaults is not a proven empty set (see
    CONTRIBUTING.md, "Azure Resource Graph: zero rows is not a proven empty set"). A vault whose
    restore jobs came back as an error says nothing about that vault, so "no restore job" is not
    proven while one is unread. A restore that did succeed is proof whatever else failed to read.
    """

    def verdict(self, path, body):
        out = load_path("is_backup_tested_vaults", path).transform(body)
        return out["transformedResponse"]["isBackupTested"], out["additionalInfo"]

    def test_a_vault_that_was_not_read_is_not_a_verdict(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            for shape, wrap in VAULT_READ_SHAPES:
                for case, body in VAULT_READ_NOT_MEASURED:
                    with self.subTest(transform=label, shape=shape, body=case):
                        value, info = self.verdict(path, wrap(body()))
                        self.assertIsNone(value)
                        self.assertEqual(info["dataCollection"]["status"], "error")
                        self.assertTrue(info["dataCollection"]["errors"])
                        self.assertTrue(all(isinstance(e, str) and e for e in info["dataCollection"]["errors"]))

    def test_vaults_that_were_read_are_still_graded(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            for shape, wrap in VAULT_READ_SHAPES:
                for case, body, expected in VAULT_READ_MEASURED:
                    with self.subTest(transform=label, shape=shape, body=case):
                        value, info = self.verdict(path, wrap(body()))
                        self.assertIs(value, expected)
                        self.assertEqual(info["dataCollection"]["status"], "success")
                        self.assertEqual(info["dataCollection"]["errors"], [])

    def test_the_reason_counts_the_vaults_that_were_not_read(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            with self.subTest(transform=label):
                _, info = self.verdict(path, vault_read(vault_with(), ARM_ERROR, HTTP_FORBIDDEN))
                self.assertIn("2 of 3", " ".join(info["dataCollection"]["errors"]))
                _, info = self.verdict(path, vault_read())
                self.assertIn("no vault", " ".join(info["dataCollection"]["errors"]).lower())

    def test_a_success_beside_an_unread_vault_says_so(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            with self.subTest(transform=label):
                value, info = self.verdict(path, vault_read(vault_with("Completed"), ARM_ERROR))
                self.assertIs(value, True)
                self.assertEqual(info["transformation"]["inputSummary"]["vaultsNotRead"], 1)
                self.assertTrue(any("not read" in f for f in info["evaluation"]["additionalFindings"]))

    def test_a_page_with_a_next_page_counts_as_not_read_in_full(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            for shape, wrap in VAULT_READ_SHAPES:
                with self.subTest(transform=label, shape=shape):
                    value, info = self.verdict(path, wrap(vault_read(paged("Failed"), vault_with())))
                    self.assertIsNone(value)
                    errors = " ".join(info["dataCollection"]["errors"])
                    self.assertIn("1 of 2", errors)
                    self.assertIn("in full", errors)
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsRead"], 1)
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsNotRead"], 1)

    def test_a_success_on_a_first_page_stays_true_and_says_so(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            with self.subTest(transform=label):
                value, info = self.verdict(path, vault_read(paged("Failed", "Completed")))
                self.assertIs(value, True)
                self.assertEqual(info["transformation"]["inputSummary"]["vaultsNotRead"], 1)
                self.assertTrue(any("not read" in f for f in info["evaluation"]["additionalFindings"]))

    def test_job_objects_directly_under_restore_job_results_are_one_vault(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            for shape, wrap in VAULT_READ_SHAPES:
                with self.subTest(transform=label, shape=shape):
                    value, info = self.verdict(path, wrap(vault_read(*job_list("Failed"))))
                    self.assertIs(value, False)
                    self.assertEqual(info["dataCollection"]["status"], "success")
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsRead"], 1)
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsNotRead"], 0)
                    value, info = self.verdict(path, wrap(vault_read(*job_list("Failed", "Completed"))))
                    self.assertIs(value, True)
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsNotRead"], 0)
                    self.assertFalse(any("not read" in f for f in info["evaluation"]["additionalFindings"]))

    def test_a_flat_list_with_a_next_link_is_not_read_in_full(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            for shape, wrap in VAULT_READ_SHAPES:
                with self.subTest(transform=label, shape=shape):
                    body = dict(vault_read(*job_list("Failed")), nextLink=NEXT_PAGE)
                    value, info = self.verdict(path, wrap(body))
                    self.assertIsNone(value)
                    self.assertEqual(info["dataCollection"]["status"], "error")
                    self.assertIn("1 of 1", " ".join(info["dataCollection"]["errors"]))
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsRead"], 0)
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsNotRead"], 1)
                    body = dict(vault_read(*job_list("Failed", "Completed")), nextLink=NEXT_PAGE)
                    value, info = self.verdict(path, wrap(body))
                    self.assertIs(value, True)
                    self.assertEqual(info["transformation"]["inputSummary"]["vaultsNotRead"], 1)
                    self.assertTrue(any("not read" in f for f in info["evaluation"]["additionalFindings"]))

    def test_a_single_arm_list_is_still_one_read_vault(self):
        """The per-vault rule leaves a bare ARM list alone: its empty list stays a measured False."""
        for label, path in IS_BACKUP_TESTED_COPIES:
            for shape, wrap in VAULT_READ_SHAPES:
                with self.subTest(transform=label, shape=shape):
                    value, info = self.verdict(path, wrap({"value": []}))
                    self.assertIs(value, False)
                    self.assertEqual(info["dataCollection"]["status"], "success")


class LongPoison(Poisoned):
    """Like Poisoned, but the error text is 500 characters long."""

    def boom(self, *args, **kwargs):
        raise RuntimeError("x" * 500)

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom


class ErrorTextIsCapped(unittest.TestCase):
    """An exception message copied into a reason is cut to 200 characters."""

    LIMIT = 200
    VALIDATION = {"status": "passed", "errors": [], "warnings": []}

    def strings(self, node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for value in node.values():
                yield from self.strings(value)
        elif isinstance(node, list):
            for value in node:
                yield from self.strings(value)

    def assert_capped(self, out):
        text = list(self.strings(out))
        self.assertTrue(any("xxx" in line for line in text), "the error text should still be shown")
        for line in text:
            self.assertLessEqual(line.count("x"), self.LIMIT, line[:80])

    def test_is_backup_tested_caps_the_error_text(self):
        for label, path in IS_BACKUP_TESTED_COPIES:
            with self.subTest(transform=label):
                out = load_path("is_backup_tested_long", path).transform(
                    {"data": LongPoison(), "validation": self.VALIDATION})
                self.assertIsNone(out["transformedResponse"]["isBackupTested"])
                self.assert_capped(out)

    def test_backupfrequency_caps_the_error_text(self):
        module = load_path("backupfrequency_long", os.path.join(AZURE, "backupfrequency.py"))
        out = module.transform({"data": LongPoison(), "validation": self.VALIDATION})
        self.assertIsNone(out["transformedResponse"]["backupFrequency"])
        self.assert_capped(out)

    def test_backupfrequency_evaluate_caps_the_error_text(self):
        module = load_path("backupfrequency_long_eval", os.path.join(AZURE, "backupfrequency.py"))
        out = module.evaluate(LongPoison())
        self.assertIsNone(out["backupFrequency"])
        self.assertLessEqual(out["error"].count("x"), self.LIMIT)
        self.assertIn("xxx", out["error"])


def policy_row(name, schedule, vault="vault-a"):
    return {"name": name, "vaultName": vault, "scheduleType": schedule, "hasSchedule": schedule != ""}


class BackupFrequencyStatesTheRealCount(unittest.TestCase):
    """The pass reason says how many policies meet daily, never "All" when some do not."""

    VALIDATION = {"status": "passed", "errors": [], "warnings": []}

    def run_rows(self, rows):
        module = load_path("backupfrequency_count", os.path.join(AZURE, "backupfrequency.py"))
        out = module.transform({"data": {"rows": [[row] for row in rows]}, "validation": self.VALIDATION})
        return out["transformedResponse"], out["additionalInfo"]

    def test_all_policies_meeting_daily_reads_all(self):
        result, info = self.run_rows([policy_row("p1", "Daily"), policy_row("p2", "Hourly"), policy_row("p3", "Daily")])
        self.assertIs(result["backupFrequency"], True)
        self.assertEqual(info["evaluation"]["passReasons"], ["All 3 backup policies meet daily or better frequency"])

    def test_some_policies_meeting_daily_reads_the_count_not_all(self):
        rows = [policy_row("p" + str(n), "Daily") for n in range(5)] + [policy_row("weekly-one", "Weekly")]
        result, info = self.run_rows(rows)
        # the verdict is unchanged: at least one policy meeting daily still reads True
        self.assertIs(result["backupFrequency"], True)
        self.assertEqual(info["dataCollection"]["status"], "success")
        reasons = " ".join(info["evaluation"]["passReasons"])
        self.assertIn("5 of 6 backup policies meet daily or better frequency", reasons)
        self.assertNotIn("All", reasons)
        self.assertEqual(result["policiesFailingFrequency"], ["weekly-one (vault-a: weekly)"])

    def test_one_policy_meeting_daily_among_many_reads_the_count(self):
        result, info = self.run_rows([policy_row("p1", "Daily"), policy_row("p2", "Weekly"), policy_row("p3", "")])
        self.assertIs(result["backupFrequency"], True)
        self.assertIn("1 of 3 backup policies meet daily or better frequency", " ".join(info["evaluation"]["passReasons"]))

    def test_a_single_policy_response_does_not_claim_a_count(self):
        module = load_path("backupfrequency_single", os.path.join(AZURE, "backupfrequency.py"))
        body = {"properties": {"schedulePolicy": {"scheduleFrequencyInMins": 1440}}}
        out = module.transform({"data": body, "validation": self.VALIDATION})
        self.assertIs(out["transformedResponse"]["backupFrequency"], True)
        reasons = " ".join(out["additionalInfo"]["evaluation"]["passReasons"])
        self.assertNotIn("All 0", reasons)
        self.assertNotIn(" 0 ", reasons)

    def test_no_policy_meeting_daily_still_fails(self):
        result, info = self.run_rows([policy_row("p1", "Weekly"), policy_row("p2", "")])
        self.assertIs(result["backupFrequency"], False)
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertEqual(info["evaluation"]["passReasons"], [])
        self.assertIn("Policies not meeting daily frequency", " ".join(info["evaluation"]["failReasons"]))


if __name__ == "__main__":
    unittest.main()
