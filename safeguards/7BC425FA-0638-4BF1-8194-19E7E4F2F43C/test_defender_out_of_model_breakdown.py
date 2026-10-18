"""requiredCoveragePercentage: the devices outside the eligible population are reported by reason.

The criterion divides protected devices by ELIGIBLE devices, and that is unchanged here. What was
missing is why the rest of the inventory is outside that denominator: one undifferentiated
"ineligible" figure lumped three unlike populations together. An Unsupported device is often not an
endpoint at all (network gear, IoT); an InsufficientInfo device may be an unmanaged workstation; an
excluded device was hidden from the figure by an admin. They are now split by reason inside
additionalInfo.exposure, where the transform also declares the population it divided by, so a
reader never has to infer the denominator. transformedResponse is untouched.

The contract these tests pin:
- the criterion's value is unchanged: protected / eligible;
- excluded + unsupported + insufficientInfo + unreadable + eligible == the whole inventory;
- the exposure declaration names the population and agrees with the working figures;
- a body that proves nothing carries no exposure declaration.

Synthetic data only.
"""
import importlib.util
from pathlib import Path

KEY = "requiredCoveragePercentage"


def load():
    spec = importlib.util.spec_from_file_location(
        "rcp_breakdown", Path(__file__).with_name("requiredcoveragepercentage.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def machine(status="Onboarded", excluded=False, platform="Windows11"):
    return {"osPlatform": platform, "onboardingStatus": status, "healthStatus": "Active",
            "isExcluded": excluded}


def inventory():
    """Six onboarded, two eligible but not onboarded, three Unsupported, two InsufficientInfo, one
    excluded by an admin: fourteen devices, eight eligible, six protected."""
    return {"value": (
        [machine() for _ in range(6)]
        + [machine("CanBeOnboarded") for _ in range(2)]
        + [machine("Unsupported", platform="Linux") for _ in range(3)]
        + [machine("InsufficientInfo", platform="Unknown") for _ in range(2)]
        + [machine(excluded=True)]
    )}


def test_criterion_value_is_still_protected_over_eligible():
    out = load().transform(inventory())
    response = out["transformedResponse"]
    assert response[KEY] == 75  # 6 of 8 eligible
    assert response["eligibleDevices"] == 8
    assert response["protectedDevices"] == 6
    assert response["allDevices"] == 14


def test_out_of_model_devices_are_split_by_reason():
    out_of_model = load().transform(inventory())["additionalInfo"]["exposure"]["outOfModel"]
    assert out_of_model == {"excluded": 1, "unsupported": 3, "insufficientInfo": 2, "unreadable": 0}


def test_the_scored_surface_is_unchanged():
    """The breakdown lives in additionalInfo only; transformedResponse gains no key."""
    response = load().transform(inventory())["transformedResponse"]
    for key in ("excludedDevices", "unsupportedDevices", "insufficientInfoDevices", "exposure"):
        assert key not in response


def test_the_partition_accounts_for_every_device():
    exposure = load().transform(inventory())["additionalInfo"]["exposure"]
    out_of_model = exposure["outOfModel"]
    assert (exposure["denominator"] + out_of_model["excluded"] + out_of_model["unsupported"]
            + out_of_model["insufficientInfo"] + out_of_model["unreadable"]) == exposure["inventoryTotal"]


def test_exposure_declaration_names_its_population_and_matches_the_figures():
    out = load().transform(inventory())
    exposure = out["additionalInfo"]["exposure"]
    response = out["transformedResponse"]
    assert exposure["criteriaKey"] == KEY
    assert exposure["exposureClass"] == "coverage"
    assert "eligible" in exposure["population"]
    assert exposure["denominator"] == response["eligibleDevices"]
    assert exposure["covered"] == response["protectedDevices"]
    assert exposure["inventoryTotal"] == response["allDevices"]


def test_a_non_dict_entry_is_counted_as_unreadable_not_dropped():
    body = inventory()
    body["value"].append("not-a-device")
    exposure = load().transform(body)["additionalInfo"]["exposure"]
    assert exposure["outOfModel"]["unreadable"] == 1
    assert exposure["inventoryTotal"] == 15


def test_a_body_that_proves_nothing_declares_no_exposure():
    module = load()
    for body in ({}, None, {"error": {"message": "invalid credentials"}}, {"value": []}):
        out = module.transform(body)
        assert out["transformedResponse"][KEY] is None
        assert "exposure" not in out["additionalInfo"]
