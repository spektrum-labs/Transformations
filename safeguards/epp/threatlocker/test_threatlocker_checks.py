"""ThreatLocker pendingApprovalRequestCount on the documented ApprovalRequestGetCount body (an integer)."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("tl_pending", HERE / "pendingapprovalrequestcount.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
transform = module.transform


@pytest.mark.parametrize("body,expected", [(0, 0), (7, 7), ("7", 7), ({"apiResponse": 3}, 3), ({"_response_data": 0}, 0)])
def test_count(body, expected):
    assert transform(body)["pendingApprovalRequestCount"] == expected


@pytest.mark.parametrize("body", [{}, None, "{}", "", True, -1, 2.5, {"error": True, "statusCode": 401}, {"hello": "world"}, [1]])
def test_fail_closed(body):
    assert transform(body)["pendingApprovalRequestCount"] is None
