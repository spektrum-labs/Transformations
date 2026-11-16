"""openCriticalDependabotAlertsCount on a list Integration-Service reads through the Link header.

The org Dependabot alerts list pages only through ``Link: <...>; rel="next"``. Integration-Service now
follows it and hands over every page as one list; a read it cut off is marked paginationTruncated (or
truncated), beside the body or in response_metadata. A cut-off read, or exactly one full page with no sign
of paging, gives no count. Synthetic alerts only.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEY = "openCriticalDependabotAlertsCount"


def run(body):
    spec = importlib.util.spec_from_file_location("gh_paging_" + KEY, HERE / (KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = module.transform(body)
    return out["transformedResponse"][KEY], out


def alerts(n, critical_open=0):
    rows = []
    for i in range(n):
        crit = i < critical_open
        rows.append({"number": i + 1, "state": "open" if crit else "dismissed",
                     "security_vulnerability": {"severity": "critical" if crit else "high"},
                     "dependency": {"package": {"name": "pkg%d" % (i % 3)}},
                     "repository": {"full_name": "org/r%d" % (i % 4)}})
    return rows


def test_a_paged_list_longer_than_one_page_is_counted():
    value, out = run(alerts(230, critical_open=7))
    assert value == 7
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_a_paged_list_with_nothing_critical_open_is_zero():
    assert run(alerts(230))[0] == 0


def test_short_list_and_empty_list_are_complete():
    assert run(alerts(99, critical_open=2))[0] == 2
    assert run([])[0] == 0


def test_exactly_one_full_page_is_withheld():
    value, out = run(alerts(100, critical_open=3))
    assert value is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "one full page" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("wrap", [
    lambda rows: {"apiResponse": rows, "response_metadata": {"paginationTruncated": True}},
    lambda rows: {"apiResponse": rows, "paginationTruncated": True},
    lambda rows: {"response": rows, "truncated": "true"},
])
def test_a_cut_off_read_gives_no_count(wrap):
    value, out = run(wrap(alerts(230, critical_open=7)))
    assert value is None
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "not read to the end" in reason
    assert "@" not in reason


@pytest.mark.parametrize("flag", [False, "false", None])
def test_a_false_marker_changes_nothing(flag):
    body = {"apiResponse": alerts(230, critical_open=7), "response_metadata": {"paginationTruncated": flag}}
    assert run(body)[0] == 7


@pytest.mark.parametrize("body", [None, {"message": "Not Found"}, "not json", {"apiResponse": {"error": True}}])
def test_unreadable_bodies_give_no_count(body):
    assert run(body)[0] is None
