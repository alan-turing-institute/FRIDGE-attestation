"""Nested policy checks against synthetic JWT claims, without key lookup."""

import copy

import jwt
import pytest
import yaml
import verification_app.guest_verification_app as guest_app


@pytest.fixture
def claims():
    return {
        "iss": "https://attestation.example",
        "tdx": {
            "attester_type": "TDX",
            "dbgstat": "disabled",
            "tdx_collateral": {"fmspc": "example", "tcbevaluationdatanumber": 22},
        },
        "appraisal": {"method": "default", "ver": 2},
    }


def check(claims, policy):
    token = jwt.encode(
        claims, "synthetic-test-secret-at-least-32-bytes", algorithm="HS256"
    )
    return guest_app.check_policies(token, policy)


@pytest.mark.parametrize(
    "policy",
    [
        {"tdx": {"attester_type": "TDX"}},
        {"tdx": {"tdx_collateral": {"tcbevaluationdatanumber": 22}}},
        {
            "tdx": {"attester_type": "TDX", "dbgstat": "disabled"},
            "appraisal": {"ver": 2},
        },
        {"tdx": {}},
    ],
)
def test_mandatory_nested_subset(claims, policy):
    assert check(claims, {"mandatory": policy})


@pytest.mark.parametrize("actual", [None, "TDX", [], 0, False])
@pytest.mark.parametrize("section", ["mandatory", "optional"])
def test_present_container_must_be_a_mapping(actual, section):
    policy = {"mandatory": {}}
    policy[section] = {"tdx": {"attester_type": "TDX"}}
    assert not check({"tdx": actual}, policy)


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"tdx": {}},
        {"tdx": {"attester_type": "SGX"}},
        {"tdx": {"attester_type": None}},
    ],
)
def test_mandatory_nested_field_is_required(claims):
    assert not check(claims, {"mandatory": {"tdx": {"attester_type": "TDX"}}})


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"tdx": {}},
        {"tdx": {"unrelated": 1}},
        {"tdx": {"attester_type": "TDX", "unrelated": 1}},
    ],
)
def test_optional_absent_fields_are_allowed_at_each_depth(claims):
    assert check(
        claims, {"mandatory": {}, "optional": {"tdx": {"attester_type": "TDX"}}}
    )


@pytest.mark.parametrize(
    "claims,expected",
    [
        ({"tdx": {"attester_type": "SGX"}}, False),
        ({"tdx": {"attester_type": None}}, False),
        ({"tdx": {"attester_type": "TDX", "dbgstat": "enabled"}}, False),
        ({"tdx": {"attester_type": "TDX", "dbgstat": "disabled"}}, True),
    ],
)
def test_present_optional_siblings_must_match(claims, expected):
    policy = {
        "mandatory": {},
        "optional": {"tdx": {"attester_type": "TDX", "dbgstat": "disabled"}},
    }
    assert check(claims, policy) is expected


@pytest.mark.parametrize("section", ["mandatory", "optional"])
@pytest.mark.parametrize(
    "expected,actual,matches",
    [
        (None, None, True),
        ("TDX", "TDX", True),
        (22, 22, True),
        ("22", 22, False),
        ([1, 2], [1, 2], True),
        ([1, 2], [2, 1], False),
        ([{"x": 1}], [{"x": 1, "extra": 2}], False),
    ],
)
def test_leaf_comparisons_keep_exact_existing_semantics(
    section, expected, actual, matches
):
    policy = {"mandatory": {}}
    policy[section] = {"nested": {"value": expected}}
    assert check({"nested": {"value": actual, "extra": 0}}, policy) is matches


@pytest.mark.parametrize(
    "mandatory", [{"missing": None}, {"tdx": {"missing": None}}, {"missing": {}}]
)
def test_mandatory_null_and_empty_mapping_still_require_presence(mandatory):
    assert not check({"tdx": {}}, {"mandatory": mandatory})


@pytest.mark.parametrize("section", ["mandatory", "optional"])
@pytest.mark.parametrize("invalid", [None, [], "tdx", 0])
def test_policy_sections_must_be_mappings(section, invalid):
    policy = {"mandatory": {}}
    policy[section] = invalid
    with pytest.raises(TypeError, match="dictionaries"):
        check({}, policy)


def test_nested_policy_file_and_inputs_unchanged(tmp_path, claims):
    policy = {
        "mandatory": {
            "tdx": {
                "attester_type": "TDX",
                "tdx_collateral": {"tcbevaluationdatanumber": 22},
            }
        },
        "optional": {"appraisal": {"ver": 2, "missing": None}},
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    loaded = guest_app.read_policies_from_file(path)
    before_policy, before_claims = copy.deepcopy(loaded), copy.deepcopy(claims)

    assert check(claims, loaded)
    assert loaded == before_policy
    assert claims == before_claims
    loaded["mandatory"]["tdx"]["attester_type"] = "SGX"
    assert not check(claims, loaded)
