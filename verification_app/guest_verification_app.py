#!/usr/bin env python3
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
import json
import jwt
import sys
import yaml

def read_token_from_file(filename) -> str:
    ### Reads the token from the file
    token_coded = ""
    
    with open(filename,"r") as f:
        token_coded = f.read()

    return token_coded
    
def verify_signature(token) -> int:
    ### Verify the JWT's signature using the issuing authority

    # Get the address of the signing authority and encryption algorithm used.
    # Don't verify yet.
    try:
        algo = jwt.get_unverified_header(token)["alg"]
        iss = jwt.decode(token, algorithms=[algo], options={"verify_signature": False})["iss"]

        
    except jwt.exceptions.DecodeError:
        print("Did not receive a valid token")
        return 1

    # Get the associated key from the issuing authority
    key = jwt.PyJWKClient(f"{iss}/certs").get_signing_key_from_jwt(token)

    # Now we can verify the token
    # Decoding with the key throws an exception if verification fails
    try:
        jwt.decode(token, key.key, algorithms=[algo])
    except jwt.exceptions.InvalidTokenError as e:
        # Catch the exception when the token cannot be verified
        print(f"Warning, the token could not be verified for the following reason: {e}")
        return 1
    return 0

def retrieve_claims_from_token(token) -> dict:
    # Get the token claims without verification
    return jwt.decode(token, options={"verify_signature": False})

def check_policies(token, policies) -> bool:
    ### Check the token against our desired policies

    # Extract policies from file
    mandatory_policies = {}
    optional_policies = {}
    with open(policies,"r") as f:
        policy_dict = yaml.load(f, Loader=yaml.FullLoader)
        mandatory_policies = policy_dict["mandatory"]
        optional_policies = policy_dict["optional"]        

    claims = retrieve_claims_from_token(token)

    # Check all values of the policy are equivalent in the claim
    passes_mandatory = all(claims.get(key) == val for key, val in mandatory_policies.items())
    passes_optional = all(claims.get(key) == val for key, val in optional_policies.items() if key in claims.keys())
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
    if args.string: token = args.string
    elif args.file: token = read_token_from_file(args.file)
    else:
        print("Please provide a JWT either from file (-f) or with a string (-s)")
        sys.exit(1)

    # Verify the token from signature
    if args.verify_signature and verify_signature(token):
        print ("Token failed to verify. Exiting")
        sys.exit(1)

    # Compare token to policy here.
    if args.policy:
        if not check_policies(token, args.policy):
            print ("Token fails policies!")
            sys.exit(1)
    
    # Then add to the node information?
    
if __name__ == "__main__":
    main()
