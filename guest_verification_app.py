#!/usr/bin env python3
"""
guest_verification_app.py - Verify a JWT from its signature
Right now, take in a token from a file or a string in CLI,
Could add ability to call the AttestationClient directly to acquire own token.
Space is left to compare against policy and add information to node.
"""

import argparse
import json
import jwt
import sys

def read_token_from_file(filename):
    ### Reads the token from the file
    token_coded = ""
    
    with open(filename,"r") as f:
        token_coded = f.read()

    return token_coded
    

def verify_signature(token):
    ### Verify the JWT's signature using the issuing authority

    # Get the address of the signing authority. Don't verify yet
    try:
        iss = jwt.decode(token, options={"verify_signature": False})["iss"]
    except DecodeError:
        print("Dio not receive a valid token")
        return 1

    # Get the associated key from the issuing authority
    key = jwt.PyJWKClient(f"{iss}/certs").get_signing_key_from_jwt(token)

    # Now we can verify the token
    # Decoding with the key throws an exception if verification fails
    try:
        jwt.decode(token, key.key, algorithms=["RS256"])
    except jwt.exceptions.InvalidTokenError as e:
        # Catch the exception when the token cannot be verified
        print(f"Warning, the token could not be verified for the following reason: {e}")
        return 1
    return 0

def parse_args():
    args = argparse.ArgumentParser(description="Run the guest's verification app")
    args.add_argument("-f", "--file", default="", help="A file with a b64 coded JWT")
    args.add_argument("-s", "--string", default="", help="A JWT string input")
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
    if verify_signature(token):
        print ("Token failed to verify. Exiting")
        sys.exit(1)

    # Compare token to policy here.

    # Then add to the node information?
    
if __name__ == "__main__":
    main()
