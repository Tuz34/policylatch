# Policy diff simulation

`policy-diff` evaluates the same bounded AIA-50 fixture corpus against two local
policies. It executes no command, tool, hook, or network request.

```bash
policylatch policy-diff \
  --before policy-before.yaml \
  --after policy-after.yaml \
  --fixtures examples/policy-tests \
  --fail-on deny-to-allow \
  --format markdown
```

Fixtures are sorted by filename before evaluation, and every `_...` metadata key
is removed by the shared policy-test contract before it reaches the evaluator.
The report classifies all allow/warn/deny transitions as unchanged, tightening,
or relaxation.

## CI gates

- `none`: never fail because of a transition.
- `deny-to-allow`: fail only on the largest relaxation.
- `deny-relaxation`: fail on deny→warn or deny→allow.
- `any-relaxation`: fail on every lower-severity after decision.

A failed selected gate exits `2`; a passed gate exits `0`. The report decision
still describes simulation risk independently of the configured gate.

## Redacted explanation

Each side of every fixture transition carries only a decision receipt
fingerprint. Policy hashes and include/profile provenance are included, but raw
fixture values and rule patterns are not. Rule entries are represented by
fingerprints.

The rule summary counts added, removed, corpus-ineffective, and shadowed entries.
"Ineffective" means no supplied fixture produced that exact finding, not that the
rule can never match. Counterexample suggestions ask for a new synthetic fixture;
PolicyLatch never writes or promotes a policy automatically.

Simulation is evidence about the supplied corpus only. It is not a proof that a
policy is secure or bypass-free.
