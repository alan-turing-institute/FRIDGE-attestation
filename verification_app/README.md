# Guest Verification Library

## Rego policy information

Find below an example Rego policy with some annotations and lessons learned:

```sh
package attestation

# We set allow to true only if no violations are found.
default allow := false

allow if {
    count(violations) == 0
}

# If the named variable doesn't appear in the object, it defaults to 'undefined'.
# Contrary to what one might believe, that doesn't cause these rules to automatically fail.
# Surely undefined != "azurevm", but apparently not. In order to make sure a field is present,
# we need the `_ = x[k]` line first.

# Test mandatory string case
violations contains msg0 if { 

	# Check the mandatory option exists
    not _ = input["x-ms-attestation-type"]
    msg0 := "Missing attestation type"
}
{
    # Check the input is correct
    not input["x-ms-attestation-type"] == "azurevm"
    msg0 := sprintf(Incorrect attestation type: %v", [input["x-ms-attestation-type"]])
}

# The rest of the policies, because they lack this mandatory check, will not fail if 
# they are not present in the claim. This is important and should be considered when defining a policy.

# Test nested case
violations contains msg1 if {
    not input["x-ms-azurevm-attested-pcr-values"].pcr0 == "demo_text"
    msg1 := sprintf(PCR0 value is incorrect: %v",  [input["x-ms-azurevm-attested-pcr-values"].pcr0])
}

violations contains msg2 if {
    not input.optional == "pass"
    msg2 := sprintf(Optional argument is incorrent: %v", [input.optional])
}

result := {
    "allow": allow,
    "violations": violations
}
```

`contains` is a keyword that adds the psotfix (e.g. msg0) to the prefix (e.g. violations) `if` the following is true.
So in this case, we're using `contains` to add a message about what fails the validation policy to our output.

Rego supports accessing data either in `collection.subcollection_1.subcollection_2.data` or `collection["subcollection_1"]["subcollection_2"]["data"]` form.
If, however, any of those names have alphanumeric symbols in them (e.g. `-`, `+` etc.) it will interpret them as an equation in the first form.
So if you need any of those characters in your data name, like we do in attestation reports all over the place, use the latter version.

Mixes are also allowed, as demonstrated in the above example policy.
