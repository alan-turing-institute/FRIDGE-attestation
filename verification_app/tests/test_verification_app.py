import copy
from unittest.mock import Mock

import jwt
import pytest
import verification_app.guest_verification_app as guest_app
from cryptography.hazmat.primitives.asymmetric import rsa

# Make common dicts for mock token and key payloads
TOKEN_HEADERS = {
    "alg": "RS256",
    "typ": "JWT",
}

TOKEN_PAYLOAD = {
    "iss": "https://dummy-website.ac.uk",
    "x-ms-attestation-type": "azurevm",
    "x-ms-azurevm-dbvalidated": True,
    "x-ms-azurevm-osdistro": "Ubuntu",
}

JWK_PAYLOAD = {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "alg": "RS256"
}

BASE_POLICIES = {
    "mandatory": {
        "iss": "https://dummy-website.ac.uk",
        "x-ms-azurevm-dbvalidated": True,
    },
    "optional": {
        "x-ms-attestation-type": "azurevm",
    }
}

class KeyObject:
    """
    Wrapper object to hold key information during tests for encoding and decoding JWTs
    """
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 2048,
        )
        self.public_key = self.private_key.public_key()

    def return_key(self,*args):
        key = Mock()
        key.key = self.public_key
        return key

@pytest.fixture
def key_object():
    ### Fixture to generate keys we can refer back to during tests
    keys = KeyObject()
    jwt.PyJWKClient.get_signing_key_from_jwt = Mock(side_effect=keys.return_key)
    return keys

def temp_token(private_key,payload,headers):
    ### Generate a temporary token using a given key, payloads and header
    return jwt.encode(payload,private_key,headers=headers,algorithm="RS256")

class TestVerificationApp:
    """
    A series of tests for the guest verification app
    """

    @pytest.mark.parametrize(
        "field_name, field_value, return_value, error",
        [
            ("", "", True, ""), # Good case
            ("exp", "1792090396", False, "Signature has expired"), # out of date signature
            ("nbf", "2000000000", False, "token is not yet valid")
        ]
    )
    def test_verify_token(self, key_object, capsys, field_name, field_value, return_value, error):
        ### Check that our tokens verify and fail as appropriate

        # Create the token payload using parametrised input
        token_payload = copy.deepcopy(TOKEN_PAYLOAD)
        if field_name:
            token_payload[field_name] = field_value

        token = temp_token(key_object.private_key,token_payload,TOKEN_HEADERS)

        # Run verify_signature on it
        return_val = guest_app.verify_signature(token)

        assert return_val == return_value

        # If we expect is to fail, check that the error message agrees with the failure
        if return_value == 1:
            captured = capsys.readouterr()
            assert error in captured.out

        jwt.PyJWKClient.get_signing_key_from_jwt.assert_called_once()

    def test_throws_on_garbage(self):
        ### Check that a nonsensical token in throws

        token_in = "Some none base64 string"

        # This bad token fails
        with pytest.raises(TypeError, match="Did not receive a valid token"):
            guest_app.verify_signature(token_in)

    def test_read_claims_from_token(self, key_object):
        ### Test that we get the claims we expect from a token

        # Get a token
        token_payload = TOKEN_PAYLOAD
        token = temp_token(key_object.private_key,token_payload,TOKEN_HEADERS)

        claims = guest_app.retrieve_claims_from_token(token)
        assert claims == TOKEN_PAYLOAD

        # Check a nonsense string won't decode
        with pytest.raises(jwt.exceptions.DecodeError):
            claims = guest_app.retrieve_claims_from_token("fake.fake.fake")

    def test_read_policy_correctly(self, pytestconfig):
        ### Check we get a correct dictionary from a good policy file
        policy_path = pytestconfig.rootdir / "verification_app" / "tests" / "data" / "good_file.yaml"
        policies = guest_app.read_policies_from_file(policy_path)

        assert isinstance(policies,dict)

        assert "mandatory" in policies
        assert "optional" in policies

        assert policies["optional"] == {"fake-entry": "not_real"}
        assert policies["mandatory"] == {
            "iss": "https://sharedeus2.eus2.attest.azure.net",
            "x-ms-attestation-type": "azurevm",
            "x-ms-azurevm-attestation-protocol-ver": "2.0",
        }

    @pytest.mark.parametrize(
        "policy_file, expected_error",
        [
            ("not_yaml.txt", TypeError),
            ("empty_file.yaml", TypeError),
            ("missing_file.yaml", FileNotFoundError),
            ("no_mandatory.yaml", ValueError),
        ]
    )
    def test_read_policy_failures(self, pytestconfig, policy_file, expected_error):
        ### Test we read policy files correctly
        policy_path = pytestconfig.rootdir / "verification_app" / "tests" / "data" / policy_file
        with pytest.raises(expected_error):
             guest_app.read_policies_from_file(policy_path)

    @pytest.mark.parametrize(
        "policy_type, field_name, field_value, expect_pass",
        [
            ("","",None,True), # Use the default policy
            # Check two correct policies still pass
            ("mandatory", "x-ms-azurevm-osdistro", "Ubuntu", True),
            ("optional", "x-ms-azurevm-osdistro", "Ubuntu", True),
            # Policy with incorrect entry fails, optional and mandatory
            ("mandatory", "x-ms-attestation-type", "Ubuntu", False),
            ("optional", "x-ms-attestation-type", "Ubuntu", False),
            # Missing entry fails for mandatory but passes for optional
            ("mandatory", "not-real", "fake", False),
            ("optional", "not-real", "fake", True),

        ]
    )
    def test_check_policies(self, key_object, policy_type, field_name, field_value, expect_pass):
        ### Test the check policies function

        # Load policies
        policies = copy.deepcopy(BASE_POLICIES)
        # Add parameterised inputs to policy
        if policy_type:
            policies[policy_type][field_name] = field_value

        # Get a token
        token_payload = TOKEN_PAYLOAD
        token = temp_token(key_object.private_key,token_payload,TOKEN_HEADERS)

        # Test policy on this token
        assert guest_app.check_policies(token,policies) == expect_pass

    def test_check_policies_error_handling(self, key_object):

        # Get a token
        token_payload = TOKEN_PAYLOAD
        token = temp_token(key_object.private_key,token_payload,TOKEN_HEADERS)

        # No mandatory policies
        policies = {"optional": {"test":"nope"}}

        with pytest.raises(AttributeError, match = "missing a mandatory set of rules"):
            guest_app.check_policies(token,policies)

        # Will pass without any payload as long as mandatory is there
        # Also passes with optional not in keyset
        policies = {"mandatory": {}}
        guest_app.check_policies(token,policies)

        # Completely the wrong datatype will fail
        policies = "Policiy string"
        with pytest.raises(TypeError, match = "Policies must be passed as a dictionary"):
            guest_app.check_policies(token,policies)
