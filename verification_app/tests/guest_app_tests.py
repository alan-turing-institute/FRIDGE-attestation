import pytest
import jwt

from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric import rsa

import verification_app.guest_verification_app as guest_app


# Make common dicts for mock token and key payloads
TOKEN_HEADERS = {
    "alg": "RS256",
    "typ":"JWT",
}

TOKEN_PAYLOAD = {
    "iss":"dummy-website.ac.uk"
}

JWK_PAYLOAD = {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "alg": "RS256"
}

class Key_Object:
    """
    Wrapper object to hold key information during tests for encoding and decoding JWTs
    """
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 2048,
        )
        self.public_key = self.private_key.public_key()

    def return_key(self,token=""):
        key = Mock()
        key.key = self.public_key
        return key
    
@pytest.fixture()
def key_object():
    ### Fixture to generate keys we can refer back to during tests
    keys = Key_Object()
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
            ("","",0,""), # Good case
            ("exp","1792090396",1,"Signature has expired"), # out of date signature
            ("nbf","2000000000",1,"token is not yet valid")
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

        
