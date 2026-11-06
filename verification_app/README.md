# Guest Verification Library


## Nested claim policies

The `mandatory` and `optional` sections are mappings. They can contain nested
mappings that mirror the token's claim structure. Only fields named in the policy
are checked; extra claims do not cause a mismatch.

```yaml
mandatory:
  tdx:
    attester_type: TDX
    dbgstat: disabled
    tdx_collateral:
      tcbevaluationdatanumber: 22
optional:
  appraisal:
    method: default
```

Every mandatory field must be present at each level and match its expected value.
This also applies to a policy value of `null`: the claim must exist and be null.
An empty mandatory mapping requires a mapping at that key, but does not constrain
its contents.

Optional fields may be absent at any depth. Present optional fields must match,
and a present value must be a mapping when its policy is a mapping. For example,
`appraisal: {}` passes the optional rule above, but `appraisal: null` or
`appraisal: {method: other}` does not.

Scalar and list values retain exact equality matching. Lists are compared as
whole values, including order and any mappings inside them; they are not treated
as subsets or positional nested policies. Neither claims nor policies are modified.

`check_policies` checks claims only. The command-line application's existing
signature-verification step is unchanged and still runs before policy checking
by default. These rules do not change signing keys, issuer discovery or token
signature verification.
