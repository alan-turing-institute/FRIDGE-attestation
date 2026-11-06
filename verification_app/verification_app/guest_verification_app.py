"""
guest_verification_app.py - Verify a JWT from its signature
Right now, take in a token from a file or a string in CLI,
Could add ability to call the AttestationClient directly to acquire own token.
Token can be checked against a yaml policy file using the -p option pointing to the file.
This file can contain mandatory policies that *must* be present and correct in the token,
and *optional* policies, that if present must be correct.
Space is left to add information to node.
"""

import argparse
import sys

import jwt
import yaml


def read_token_from_file(filename) -> str:
    ### Reads a JWT from filename
    with open(filename) as f:
         return f.read()

def verify_signature(token) -> bool:
    ### Verify the JWT's signature using the issuing authority

    # Get the address of the signing authority and encryption algorithm used.
    # Don't verify yet.
    try:
        algo = jwt.get_unverified_header(token)["alg"]
        iss = jwt.decode(token, algorithms=[algo], options={"verify_signature": False})["iss"]

    except jwt.exceptions.DecodeError as err:
        error_msg = "Did not receive a valid token"
        raise TypeError(error_msg) from err

    # Get the associated key from the issuing authority
    key = jwt.PyJWKClient(f"{iss}/certs").get_signing_key_from_jwt(token)

    # Now we can verify the token
    # Decoding with the key throws an exception if verification fails
    try:
        jwt.decode(token, key.key, algorithms=[algo])
    except jwt.exceptions.InvalidTokenError as e:
        # Catch the exception when the token cannot be verified
        print(f"Warning, the token could not be verified for the following reason: {e}")
        return False
    return True

def retrieve_claims_from_token(token) -> dict:
    ### Get the token claims without verification
    return jwt.decode(token, options={"verify_signature": False})

def read_policies_from_file(policy_file) -> dict:
    ### Extract policy from yaml file
    with open(policy_file) as f:
        policy_dict = yaml.safe_load(f)#, Loader=yaml.FullLoader)
    if not isinstance(policy_dict, dict):
        error_msg = f"({policy_file} did not contain valid YAML"
        raise TypeError(error_msg)
    if "mandatory" not in policy_dict:
        error_msg = "Missing mandatory policies"
        raise ValueError(error_msg)
    return policy_dict

def _matches_policy(claims: dict, policies: dict, required: bool) -> bool:
    """Match specified fields recursively, leaving other token claims unrestricted."""
    for key, expected in policies.items():
        if key not in claims:
            if required:
                return False
            continue
        actual = claims[key]
        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                return False
            if not _matches_policy(actual, expected, required):
                return False
        elif actual != expected:
            return False
    return True


def check_policies(token, policy_dict) -> bool:
    ### Check the token against our desired policies

    if not isinstance(policy_dict, dict):
        error_msg = "Policies must be passed as a dictionary"
        raise TypeError(error_msg)
    if "mandatory" not in policy_dict:
        error_msg = "Policies are missing a mandatory set of rules"
        raise AttributeError(error_msg)

    # Split policies into mandatory and optional
    mandatory_policies = policy_dict["mandatory"]
    optional_policies = policy_dict["optional"] if "optional" in policy_dict else {}

    if not isinstance(mandatory_policies, dict) or not isinstance(optional_policies, dict):
        raise TypeError("Mandatory and optional policy sections must be dictionaries")

    claims = retrieve_claims_from_token(token)

    # Mandatory fields must exist; optional fields are checked wherever present.
    passes_mandatory = _matches_policy(claims, mandatory_policies, required=True)
    passes_optional = _matches_policy(claims, optional_policies, required=False)
    return(passes_mandatory and passes_optional)


def parse_args():
    args = argparse.ArgumentParser(description="Run the guest's verification app")
    args.add_argument("-f", "--file", default="", help="A file with a b64 coded JWT")
    args.add_argument("-s", "--string", default="", help="A JWT string input")
    args.add_argument("-v", "--verify_signature", default=True, action="store_false", help="Use this flag to skip verification step")
    args.add_argument("-p", "--policy", default="", help="Policy file to compare to attestation")
    return args.parse_args()

def main():

    args = parse_args()
    # Get the token
    token = ""
    if args.string:
        token = args.string
    elif args.file:
        token = read_token_from_file(args.file)
    else:
        print("Please provide a JWT either from file (-f) or with a string (-s)")
        sys.exit(1)

    # Verify the token from signature
    if args.verify_signature and not verify_signature(token):
        print ("Token failed to verify. Exiting")
        sys.exit(1)

    # Compare token to policy here.
    if args.policy:
        policies = read_policies_from_file(args.policy)
        if not check_policies(token, policies):
            print ("Token fails policies!")
            sys.exit(1)

    # Then add to the node information?

if __name__ == "__main__":
    main()
