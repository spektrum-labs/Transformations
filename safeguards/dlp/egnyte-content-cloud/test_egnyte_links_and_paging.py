"""Egnyte Content Cloud: publicLinksWithoutExpiryCount, and the partial-read guard on
isSSOEnabled and isPublicSharingRestricted.

GET /pubapi/v2/users returns at most 100 users per call (totalResults covers the domain);
GET /pubapi/v2/links at most 500 (count is the rows in the response, no total). Until the
collector reads every page, a verdict over the first page is a verdict over part of the
estate, so a read that cannot show it is complete returns null, never a pass.
Bodies follow Egnyte's documented shapes (developers.egnyte.com Links API v2, Users API v2).
"""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("egnyte_" + name, HERE / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EXPIRY = load("publicLinksWithoutExpiryCount")
SSO = load("isSSOEnabled")
SHARING = load("isPublicSharingRestricted")

NO_EVIDENCE = [
    {}, None, "", "{}", [],
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"statusCode": 403, "error": "Forbidden"},
    {"errorMessage": "Developer Inactive", "status": 403},
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"links": []},          # no count: not demonstrably the links response
    {"count": 0},           # no links array
]


def link(i, accessibility, **extra):
    base = {"id": "L%d" % i, "path": "/Shared/f%d" % i, "type": "file",
            "accessibility": accessibility, "created_by": "admin",
            "creation_date": "2026-03-13T06:15:27+0000"}
    base.update(extra)
    return base


def links_body(links, **extra):
    body = {"links": links, "count": len(links)}
    body.update(extra)
    return body


def expiry(body):
    return EXPIRY.transform(body)["transformedResponse"]["publicLinksWithoutExpiryCount"]


# -- publicLinksWithoutExpiryCount ------------------------------------------------------

def test_every_unauthenticated_link_expires_counts_zero():
    body = links_body([
        link(1, "anyone", expiry_date="2026-12-31T06:59:59+0000"),
        link(2, "password", expiry_clicks=4),
        link(3, "domain"),       # needs an Egnyte login: not counted
        link(4, "recipients"),   # named recipients: not counted
    ])
    assert expiry(body) == 0


def test_anyone_and_password_links_without_expiry_are_counted():
    body = links_body([
        link(1, "anyone"),
        link(2, "password", expiry_date=""),
        link(3, "anyone", expiry_clicks=2),
        link(4, "domain"),
    ])
    out = EXPIRY.transform(body)
    assert out["transformedResponse"]["publicLinksWithoutExpiryCount"] == 2
    assert [l["path"] for l in out["transformedResponse"]["publicLinksWithoutExpiry"]] == ["/Shared/f1", "/Shared/f2"]
    assert out["additionalInfo"]["evaluation"]["failReasons"]


def test_domain_with_no_links_is_a_measured_zero():
    assert expiry({"links": [], "count": 0}) == 0


def test_no_evidence_is_null():
    for body in NO_EVIDENCE:
        assert expiry(body) is None, body


def test_unclassifiable_link_is_null():
    assert expiry(links_body([link(1, "anyone", expiry_clicks=1), link(2, "")])) is None
    assert expiry({"links": ["L1"], "count": 1}) is None


def test_partial_read_is_null():
    assert expiry(links_body([link(1, "domain")], total_count=5)) is None
    full_page = [link(i, "domain") for i in range(100)]
    assert expiry(links_body(full_page)) is None           # today's count=100, one call
    full_max = [link(i, "domain") for i in range(500)]
    assert expiry(links_body(full_max)) is None            # Egnyte's max page, one call


def test_merged_pages_are_counted():
    # The collector merges every page into links; count is the last page's rows.
    merged = [link(i, "domain") for i in range(536)] + [link(999, "anyone")]
    assert expiry({"links": merged, "count": 37}) == 1


def test_string_body_is_decoded():
    assert expiry('{"links": [], "count": 0}') == 0


# -- partial-read guard on the existing checks ------------------------------------------

def users_body(users, total=None):
    return {"totalResults": len(users) if total is None else total, "itemsPerPage": len(users),
            "startIndex": 1, "resources": users}


def sso(body):
    return SSO.transform(body)["transformedResponse"]["isSSOEnabled"]


def sharing(body):
    return SHARING.transform(body)["transformedResponse"]["isPublicSharingRestricted"]


def test_sso_complete_read_still_judged():
    users = [{"id": 1, "userName": "a", "active": True, "authType": "sso"},
             {"id": 2, "userName": "b", "active": True, "authType": "ad"}]
    assert sso(users_body(users)) is True
    users[1]["authType"] = "egnyte"
    assert sso(users_body(users)) is False


def test_sso_first_page_of_a_larger_domain_is_null():
    users = [{"id": i, "userName": "u%d" % i, "active": True, "authType": "sso"} for i in range(100)]
    out = SSO.transform(users_body(users, total=250))
    assert out["transformedResponse"]["isSSOEnabled"] is None
    assert not out["additionalInfo"]["evaluation"]["passReasons"]


def test_sharing_complete_read_still_judged():
    assert sharing(links_body([link(1, "domain"), link(2, "password")])) is True
    assert sharing(links_body([link(1, "anyone")])) is False
    assert sharing({"links": [], "count": 0}) is True


def test_sharing_partial_read_is_null():
    assert sharing(links_body([link(1, "domain")], total_count=7)) is None
    assert sharing(links_body([link(i, "domain") for i in range(100)])) is None
    merged = [link(i, "domain") for i in range(537)]
    assert sharing({"links": merged, "count": 37}) is True
