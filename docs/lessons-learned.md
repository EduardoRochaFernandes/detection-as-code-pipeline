# Lessons Learned

An honest retro. This file is meant to be rewritten in your own voice as you
actually build the lab — the entries below are the real design decisions and
trade-offs baked into the current repo, which are true and defensible today.

## What worked
- **The seam paid off.** Putting all "how do we evaluate a rule?" logic behind
  `run_query_against_fixture` meant the tests never had to know whether a live
  SIEM or an in-memory matcher answered the question. The strategy-1 → strategy-2
  upgrade is a one-function change.
- **Fixture-based CI is fast and deterministic.** 80 checks in <1 second, no
  flaky container startup, no external services. That reliability is what makes
  the fail-closed gate trustworthy instead of a coin flip.
- **Writing docs surfaced bugs.** Documenting the rules made two silent-YAML
  problems obvious: a duplicate `CommandLine|contains` key in the LSASS rule and
  an accidental AND (instead of OR) between two user-agent conditions in the C2
  rule. Both were fixed before they could pass a false test.

## What I'd change / what is deliberately limited
- **Home-lab false-positive rates are not representative.** The clean baseline
  is a handful of tidy events. Real enterprise noise (NAT egress IPs, deployment
  tooling, EDR reading LSASS) would trip several of these rules until tuned. The
  project proves the *mechanism* of FP regression testing, not enterprise-grade
  tuning.
- **No true sequence/timing correlation.** "Failed-then-success" brute force,
  impossible-travel logon, and C2 beaconing jitter all need stateful correlation
  the stateless matcher can't do. Rather than fake it, those rules cover the
  high-signal stateless slice and the correlation variants are on the roadmap.
- **Deployment is artifact-gated, not fully automated.** GitHub-hosted runners
  can't reach a laptop lab, so CI publishes a validated artifact and deploy is
  manual (or via a self-hosted runner). Stated plainly instead of pretending the
  cloud pushes to the lab.

## The false-positive test earning its keep (demo)
To show the gate is real, add a deliberately over-broad rule (e.g. drop the
`selection_img` guard from the PowerShell rule so it matches *any* process with a
`bypass` string) and watch `test_false_positive_baseline.py` go red before it can
deploy. Revert it and the pipeline goes green again. That before/after is the
single most convincing 20 seconds of a demo.
