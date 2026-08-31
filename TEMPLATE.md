# Using this template

The `template` repository is the base for every hoardCTI repository. It provides
a standard baseline of security controls, review workflow, and community health
files so that each new repository starts compliant instead of catching up later.

hoardCTI is an open-source threat intelligence feed. Organisations act on what
we publish, so the integrity of our repositories is part of the product.

## What you get

| Area | Files |
| --- | --- |
| Secret detection | [`.github/workflows/secret-scan.yml`](.github/workflows/secret-scan.yml), [`.github/scripts/secret_scan.py`](.github/scripts/secret_scan.py) + tests |
| Review scope control | [`.github/workflows/pr-size-check.yml`](.github/workflows/pr-size-check.yml) |
| Baseline CI | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (workflow lint, workflow security audit, dependency review, Python lint/audit, scanner tests) |
| Workflow security audit | [`.github/zizmor.yml`](.github/zizmor.yml) |
| Supply-chain posture | [`.github/workflows/scorecard.yml`](.github/workflows/scorecard.yml) |
| Commit history hygiene | [`.github/workflows/pr-title.yml`](.github/workflows/pr-title.yml) |
| Review ownership | [`.github/CODEOWNERS`](.github/CODEOWNERS) |
| Dependency updates | [`.github/dependabot.yml`](.github/dependabot.yml) |
| Issue and PR intake | [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE), [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) |
| Policy | [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), [`LICENSE`](LICENSE) |
| Formatting and lint config | [`.editorconfig`](.editorconfig), [`.gitignore`](.gitignore), [`pyproject.toml`](pyproject.toml) |
| Repository settings | [`.github/settings.yml`](.github/settings.yml) (documentation of required settings) |

## Setup checklist

On first push, the [template cleanup workflow](.github/workflows/template-cleanup.yml)
strips the template banner from `README.md`, substitutes the repository name,
and deletes itself along with this file. Everything below is manual.

### 1. Fill in the placeholders

Every spot needing attention is marked `TEMPLATE:`. Find them all:

```bash
grep -rn "TEMPLATE:" --exclude-dir=.git .
```

At minimum:

- [ ] `README.md` — description, installation, usage, development commands
- [ ] `.github/CODEOWNERS` — real teams (each needs **write** access, or GitHub silently ignores it)
- [ ] `SECURITY.md` — security contact address and supported-versions table
- [ ] `CODE_OF_CONDUCT.md` — conduct contact address
- [ ] `.github/ISSUE_TEMPLATE/config.yml` — URLs point at `hoardcti/template`; repoint them
- [ ] `.github/dependabot.yml` — uncomment the ecosystems this repository actually uses
- [ ] `.gitignore` — trim the languages that do not apply, but keep the secrets section
- [ ] `pyproject.toml` — keep for Python repositories, delete for others; add `[project]` if packaged
- [ ] `.github/workflows/ci.yml` — agree a dependency licence policy, then uncomment `deny-licenses`
- [ ] `LICENSE` — confirm GPL-3.0 is right for this repository (see *Licensing* below)

### 2. Enable repository security settings

These are **not** files and are not copied by GitHub's template mechanism. Set
them in **Settings → Code security**, or apply them org-wide as a security
configuration:

- [ ] **Secret scanning** — the primary credential control
- [ ] **Push protection** — blocks the push instead of reporting afterwards
- [ ] **Dependabot alerts** and **security updates**
- [ ] **Private vulnerability reporting** — required by `SECURITY.md`
- [ ] **CodeQL / code scanning** — default setup is fine for most repositories

The bundled `secret_scan.py` is a safety net, not a substitute. Native secret
scanning validates candidates against the issuing provider and blocks at push
time; a workflow can only report after the fact.

### 3. Apply the branch ruleset

`main` must be protected. See [`.github/settings.yml`](.github/settings.yml) for
the exact configuration to apply — that file documents the required settings in
a reviewable form. Apply it with the [Probot settings app][probot] if the org
has it installed, or by hand under **Settings → Rules → Rulesets**.

[probot]: https://github.com/apps/settings

Required on `main`:

- [ ] Require a pull request before merging, with **1+ approval**
- [ ] Require review from **Code Owners**
- [ ] Dismiss stale approvals when new commits are pushed
- [ ] Require status checks to pass: `Scan pull request diff`, `Lint workflows`, `Audit workflow security`, `Review dependency changes`, `Check title format`, `Secret scanner tests`, `Check PR size`
      (do **not** require the language-conditional jobs — see the note in `.github/settings.yml`)
- [ ] Require branches to be up to date before merging
- [ ] Require conversation resolution
- [ ] Block force pushes and deletions

### 4. Other settings

- [ ] Enable **Discussions** if you referenced it in `ISSUE_TEMPLATE/config.yml`, or remove that link
- [ ] Set **Actions → Workflow permissions** to *Read repository contents* (workflows here request what they need per job)
- [ ] Restrict Actions to *actions created by GitHub* plus explicitly allowed actions
- [ ] Add repository topics and a description
- [ ] Add the OpenSSF Scorecard badge to `README.md` once the first Scorecard run completes

### 5. Verify

Open a throwaway pull request and confirm CI, the size check, and the secret
scan all run and report. Do this before the repository takes real contributions.

## Design notes

Things that look unusual here are deliberate.

**Actions are pinned to commit SHAs, not tags.** Tags are mutable. Anyone who
compromises an upstream action repository can repoint `v4` at malicious code and
it lands in every workflow that trusts the tag. Dependabot keeps the pins
current using the `# vX.Y.Z` comment beside each SHA. A threat intelligence
provider should not be exposed to a supply-chain vector it warns others about.

**`pr-size-check.yml` uses `pull_request_target`.** Under `pull_request`, pull
requests from forks receive a read-only token, so labelling and commenting fail
with 403 — on an open-source repository, that is the normal contribution path.
`pull_request_target` gets a writable token, at the cost of running in the base
repository's context. That is safe **only** because the workflow never checks
out or executes pull request code. Do not add a checkout step to it.

**The secret scanner allowlists the matched value, not the line.** An earlier
version tested the whole line against `test|example|...`, so a variable named
`latest_token` suppressed the real credential beside it. Suppression is now
either an explicit `pragma: allowlist secret` comment, a known vendor dummy
value, or a placeholder inside the matched text.

**Findings are masked.** Workflow logs on a public repository are world-readable,
so printing a matched secret would republish the credential the check exists to
catch. Only a short provider-identifying prefix survives.

**High-confidence rules always fire.** Provider-formatted tokens are reported
even inside `tests/` and `docs/`. Only shape-based heuristics (generic
`password = "..."` assignments, high-entropy strings) relax there.

**Hex secrets do not trip the entropy check.** Shannon entropy of hex maxes out
at 4.0 bits/character, below the 4.5 threshold. Hex-encoded credentials are
covered by the named rules and nothing else — do not assume otherwise when
adding detections.

**actionlint and zizmor are not redundant.** actionlint checks that workflows
are *correct* (bad syntax, invalid expressions, shell mistakes). zizmor checks
that they are *safe* (template injection, credential persistence, dangerous
triggers, over-broad permissions). Both run. zizmor is what would catch a future
contributor adding a checkout step to the `pull_request_target` workflow, which
is the failure mode that design is exposed to.

**zizmor suppressions live in `.github/zizmor.yml`, with reasons.** They are kept
out of the workflow files so the action SHA comments stay clean for Dependabot.
Never add one without writing down why the finding is not exploitable — an
unexplained suppression is how a real issue gets buried.

**Language jobs skip rather than fail.** `ci.yml` detects toolchains and gates
the Python jobs on the result, so a Go or TypeScript repository is not forced to
carry them. For the same reason those jobs are deliberately absent from the
required status checks — a required check that never runs can block merges
permanently.

**`pip-audit` needs real dependency metadata.** The template's `pyproject.toml`
carries tool configuration only, with no `[project]` table, so the audit job
correctly skips here. It activates once a repository declares actual
dependencies.

## Licensing

The template ships **GPL-3.0**. Confirm it suits each repository rather than
inheriting it by default.

GPL-3.0 is strong copyleft: organisations distributing software that
incorporates this code must release their combined work under the GPL too. Many
enterprise legal policies prohibit consuming GPL code in products they ship,
which can work against an "enterprise-ready" positioning. A common split is
AGPL-3.0 for a hosted service, and a permissive licence (Apache-2.0, MIT) for
client libraries and SDKs meant to be embedded.

This is a decision for the maintainers, not a default to accept silently. If you
change it, replace `LICENSE`, update the licence section in `README.md`, and be
aware that relicensing later requires the agreement of all copyright holders.

## Keeping repositories in sync

GitHub's template mechanism is a one-time copy — later template improvements do
not reach repositories already created. When you change something here that
matters (a scanner fix, a workflow hardening), open follow-up pull requests
against the active repositories, or promote the shared parts into a reusable
workflow in a central repository that others call.
