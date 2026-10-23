from unittest.mock import Mock

import jwt
import pytest
import verification_app.guest_verification_app as guest_app
from cryptography.hazmat.primitives.asymmetric import rsa

# Make common dicts for mock token and key payloads
TOKEN_HEADERS = {
    "alg": "RS256",
    "typ":"JWT",
}

TOKEN_PAYLOAD = {
    "iss":"https://dummy-website.ac.uk"
}

JWK_PAYLOAD = {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "alg": "RS256"
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
        token_payload = TOKEN_PAYLOAD
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

    def test_fails_on_garbage(self, capsys):
        ### Check that a nonsensical token in fails

        token_in = "Some none base64 string"

        return_val = guest_app.verify_signature(token_in)

        # This bad token fails
        assert not return_val

        # Check we are failing at the correct point
        captured = capsys.readouterr()
        assert "Did not receive a valid token" in captured.out

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
