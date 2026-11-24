# CRA Readiness Assessment — ni/grpc-device

| Field | Value |
|---|---|
| Repository | https://github.com/ni/grpc-device |
| Milestone | M4 (Dec 21, 2026 – Jan 8, 2027) |
| Tracking | Azure DevOps Epic 4022537 |
| Assessed commit | `ec68a1c8` — "[RFmx][EVDO] Adding support for EVDO Personality in gRPC (#1300)" (2026-11-05) |
| Assessment date | 2026-11-24 |
| Method | Static review of a local clone (files, workflows, git history). Repository settings (rulesets, alerts, secret scanning) could not be read and must be confirmed by a GitHub admin on `ni/grpc-device`. |
| Owner / Reviewer / Security contact | _TBD by NI_ (CODEOWNERS lists @astarche, @reckenro, @etm-mboehme) |

## Summary

| # | Requirement area | Initial status | Current status (branch `cra/security-hardening`) | Remaining / who acts |
|---|---|---|---|---|
| 1 | Dangerous Workflows | ❌ Gaps found | 🟡 Partly fixed | NI decision on self-hosted runners for fork PRs; optional SHA pinning |
| 2 | Binary Artifacts | ✅ Compliant | ✅ Compliant | Owner to confirm test-cert justification |
| 3 | Branch Protection | ❓ Not verifiable | ❓ Unchanged | NI admin: ruleset |
| 4 | Code Reviews | ❓ Not verifiable | ❓ Unchanged | NI admin: ruleset |
| 5 | Maintenance | ✅ Actively maintained | ✅ Unchanged | Owner to confirm |
| 6 | Token Permissions | ❌ Gaps found | ✅ Fixed | Confirm workflows still run after merge |
| 7 | Dependency Updates | ❌ Not configured | ✅ Configured | First update PRs appear after merge; record findings |
| 8 | Vulnerability Reporting | ❓ Not verifiable | ❓ Unchanged | NI admin: enable Dependabot alerts, then report |
| 9 | SAST | ❌ Not configured | ✅ Configured | First scan after merge; triage and report findings |
| 10 | SBOM | ❌ Not configured | ✅ Configured | NI: confirm format and whether to publish with releases |
| 11 | Security Policy | ✅ Compliant | ✅ Compliant | Confirm shown on Security tab |
| 12 | CI Tests | ⚠️ Run on PRs | ⚠️ Unchanged | NI admin: mark as required status checks |
| 13 | Documentation | ✅ Compliant | ✅ Compliant | Owner to review |
| 14 | License | ✅ Present | ✅ Present | NI to confirm approval |
| 15 | Secret Scanning & Push Protection | ❓ Not verifiable | ❓ Unchanged | NI admin: enable and review alerts |

**Totals now:** 10 compliant or configured · 1 partly fixed (area 1) · 4 waiting on GitHub admin settings (3, 4, 8, 15) and area 12's required checks.

## Remediation log

Changes on branch `cra/security-hardening` (commit `3c60cfc5`). Not yet merged; workflows not yet run on GitHub.

| # | Area | Issue | Fix | File(s) |
|---|---|---|---|---|
| 1 | Token Permissions | 13 of 14 workflows had no `permissions` and used the repository's default token permissions | Added top-level `permissions: contents: read` to every workflow | all 14 files in `.github/workflows/` |
| 2 | Token Permissions | Issue-sync workflow received a `GITHUB_TOKEN` it does not use | `permissions: {}` | `sync_github_issues_to_azdo.yml` |
| 3 | Token Permissions | Write access not scoped to the jobs that need it | Job-level `contents: write` for release creation; `issues: write` for the Linux RT issue job; documented ceiling on `pr.yml`'s `run_ci` job | `ci.yml`, `create_release.yml`, `validate_linux_rt.yml`, `pr.yml` |
| 4 | Dangerous Workflows | `${{ }}` expressions inlined into shell script | Moved into `env:` variables | `validate_linux_rt.yml` (2 steps), `sync_github_issues_to_azdo.yml` |
| 5 | Dangerous Workflows | `${{ }}` expressions inlined into `github-script` JavaScript | Passed via `env:` and read with `process.env` | `validate_linux_rt.yml` |
| 6 | Dangerous Workflows | `workflow_run` trigger did not check what started the CI run | Job runs only for `workflow_dispatch`, or when the CI run was a `push` from this repository | `trigger_azdo_ci.yml` |
| 7 | Dependency Updates | No Dependabot or Renovate configuration | Dependabot for github-actions, pip (`/`), pip/Poetry (`/examples`), gitsubmodule; 7-day cooldown; open-PR limits | `.github/dependabot.yml` (new) |
| 8 | SAST | No static analysis | CodeQL for C/C++ (repository CMake build), Python and Actions; runs on PRs, pushes to `main`/`releases/**`, and weekly | `.github/workflows/codeql.yml` (new) |
| 9 | SBOM | No SBOM | SPDX 2.3 generator covering the server, pinned submodules (including nested) and Python build tools; workflow uploads it as an artifact | `utils/generate_sbom.py`, `.github/workflows/generate_sbom.yml` (new) |

**Still open in the repository (not changed):**
- Fork PRs still run system tests on the self-hosted `grpcbot-win-10` runner (area 1, high). Needs an NI decision.
- Third-party actions still referenced by tag rather than commit SHA (area 1, medium). Optional.

**Verification done:** all workflow files and `dependabot.yml` parse as valid YAML; effective permissions checked per workflow; `utils/generate_sbom.py` run locally produced a valid SPDX JSON document (17 packages without nested submodules initialized).

---

## 1. Dangerous Workflows — ❌ → 🟡 partly fixed (see Remediation log #4–6)

14 workflows in `.github/workflows/`. Triggers: `pull_request` (pr.yml), `push` (ci.yml, validate_linux_rt.yml), `issues`/`issue_comment` (sync_github_issues_to_azdo.yml), `workflow_run` (trigger_azdo_ci.yml), and `workflow_call`/`workflow_dispatch` for the rest.

| Finding | Location | Risk | Proposed action |
|---|---|---|---|
| No `pull_request_target` workflows | — | None | ✅ No action |
| **Fork PRs run on self-hosted runners.** `pr.yml` → `ci.yml` → `run_win_system_tests.yml` runs on `[self-hosted, windows, x64, grpcbot-win-10]` for every PR, including from forks. PR-supplied binaries execute on NI hardware. | `pr.yml`, `ci.yml:407-409`, `run_win_system_tests.yml:10-14` | **High** | **NI decision:** set org/repo "Require approval for all outside collaborators" for fork PR workflows, and/or skip self-hosted jobs when `github.event.pull_request.head.repo.full_name != github.repository`. |
| `workflow_run` trigger does not verify the triggering event/repo. Branch filter `main`/`releases/**` matches on branch *name* only. Mitigated today because the PR path invokes CI via `workflow_call` (run name "PR", not "CI"). | `trigger_azdo_ci.yml:4-11, 42, 65` | Low–Medium | Add `github.event.workflow_run.event == 'push'` and `github.event.workflow_run.head_repository.full_name == 'ni/grpc-device'` to the job condition. |
| GitHub expressions inlined into shell scripts | `validate_linux_rt.yml:55`, `validate_linux_rt.yml:60`, `sync_github_issues_to_azdo.yml:19,21` | Low (values are tags/booleans, not attacker-controlled free text) | Move values into `env:` and reference as `$VAR`. |
| Third-party actions referenced by mutable tag (only 1 of 15 pinned to SHA) | all workflows | Medium (supply chain, OpenSSF "Pinned-Dependencies") | Pin to full commit SHA with `# vX` comment; Dependabot keeps them updated. |
| Untrusted build/test vs. secret-using jobs | `trigger_azdo_ci.yml`, `sync_github_issues_to_azdo.yml`, `create_release.yml` | — | Already separated: secret-using workflows do not run on `pull_request`. ✅ |

## 2. Binary Artifacts — ✅

- `git ls-files` contains no `.exe .dll .so .o .a .lib .pdb .obj .dylib .whl .jar .nupkg .zip .tar .gz` files.
- Build outputs are produced by CI (`build_cmake.yml`, `build_nilrt.yml`) and uploaded as workflow artifacts / release assets.
- `.gitignore` already excludes `/bin/`, `/build/`, CMake outputs, `__pycache__/`, `.venv`.
- `generated/` contains generated **source** (allowed; CI verifies it matches codegen with `git diff --exit-code`).
- Note for record: `source/tests/assets/certs/test_server_privatekey.pem`, `test_server_self_signed_crt.pem`, `test_client_self_signed_crt.pem` are **self-signed test certificates used only by the TLS test suite** — not production secrets. Record as not-applicable for area 15 with this justification (owner to confirm).

## 3. Branch Protection — ❓ (admin)

Cannot be read from a clone. Default branch: `main`; release branches: `releases/**` (from `ci.yml`).

Action for NI admin: create a ruleset targeting `main` and `releases/**` with: PR required, required status checks (see area 12), block force push, block deletion. Enable only after CI checks pass. Evidence: export of ruleset JSON + screenshot of rejected direct push.

## 4. Code Reviews — ❓ (admin)

`CODEOWNERS` exists and covers the whole repo (`* @astarche @reckenro @etm-mboehme`). Whether approval is enforced cannot be verified from a clone. Recent history shows PR-numbered merges (e.g. #1300, #1295, #1293), indicating a PR workflow is followed.

Action for NI admin: in the same ruleset require ≥1 approval (optionally "Require review from Code Owners"), bypass list empty. Evidence: a PR blocked from merge without approval.

## 5. Maintenance — ✅

| Metric | Value |
|---|---|
| Last commit | 2026-11-05 (`ec68a1c8`) |
| Commits since 2026-01-01 | 46 |
| Last release | _Verify on GitHub Releases (tags not present in local clone)_ |
| Open issues with no response | _Verify on GitHub Issues_ |

Repository is actively developed. Owner to confirm active maintenance; no archival flag needed.

## 6. Token Permissions — ❌ → ✅ fixed (see Remediation log #1–3)

Only `create_release.yml` declares `permissions` (job-level `contents: write`). All other workflows use the repository default `GITHUB_TOKEN` permissions. No `write-all` found.

Proposed changes:

| Workflow | Top level | Job-level write needed |
|---|---|---|
| ci.yml, pr.yml, build_cmake.yml, build_nilrt.yml, create_client_artifacts.yml, run_*_system_tests.yml, validate_*.yml (except linux_rt), trigger_azdo_ci.yml | `contents: read` | none |
| create_release.yml | `contents: read` | `contents: write` (already present) — caller `ci.yml` must also grant it |
| validate_linux_rt.yml | `contents: read` | `issues: write` (creates issue via `JasonEtco/create-an-issue`) |
| sync_github_issues_to_azdo.yml | `permissions: {}` | none (uses `secrets.GH_REPO_TOKEN` / `AZDO_WORK_ITEM_TOKEN`, not `GITHUB_TOKEN`) |

Verification: run CI on the PR and a `workflow_dispatch` of `create_release` on a fork.

## 7. Dependency Updates — ❌ → ✅ configured (see Remediation log #7)

No `.github/dependabot.yml` or Renovate config in the repo. (`sync_github_issues_to_azdo.yml` excludes a "Dependency Dashboard" issue, suggesting Renovate may have been used via an org-level app — NI to confirm.)

Ecosystems present:

| Ecosystem | Location |
|---|---|
| github-actions | `.github/workflows/` |
| pip | `/python_build_requirements.txt`, `/pyproject.toml` |
| pip (poetry) | `/examples/pyproject.toml`, `/examples/poetry.lock` |
| gitsubmodule | `.gitmodules` — grpc, json, utfcpp, grpc-sideband, googletest, spdlog, ni-apis |

Proposed: add `dependabot.yml` covering all four, `cooldown.default-days: 7`, `open-pull-requests-limit` 5 per ecosystem, weekly schedule. Compatibility fixes are out of scope per SOW.

## 8. Vulnerability Reporting — ❓ (admin)

Requires Dependabot alerts enabled in repo settings. Note: C/C++ dependencies come in as git submodules, which the dependency graph does **not** scan for vulnerabilities; the report should note this limitation (and the SBOM in area 10 can be used for manual/OSV checks).

Action: enable alerts → export open alerts (severity, package, fixed version) → write report with N/A justifications → send to NI.

## 9. SAST — ❌ → ✅ configured (see Remediation log #8)

No CodeQL or other SAST workflow present.

Proposed: `codeql.yml` on `pull_request`, `push` to `main`, and weekly schedule, languages `c-cpp` (manual build using the repo's CMake on ubuntu-22.04) and `python` (`source/codegen`, `examples`), plus `actions`. Consideration: full build compiles the gRPC submodule (long runtime) — NI may accept `build-mode: none` for C/C++ to reduce cost. Triage first scan; list critical/high separately.

## 10. SBOM — ❌ → ✅ configured (see Remediation log #9)

No SBOM generation. Most native dependencies are git submodules (not visible to package-manifest scanners). Third-party components are documented in `ThirdPartyNotices.txt`.

Proposed: workflow generating SPDX (or CycloneDX) covering Python manifests + submodules (name, URL, pinned commit), uploaded as an artifact. **NI decision:** format, and whether to attach to releases via `create_release.yml`.

## 11. Security Policy — ✅

`SECURITY.md` at repo root is the NI template ("Begin NI SECURITY.md V1.0"). Checklist:

- [x] Directs reports to security@ni.com
- [x] Says not to use public GitHub issues
- [x] States coordinated vulnerability disclosure process
- [x] Asks for issue type, impact and reproduction steps
- [x] Links https://ni.com/security
- [x] References NI PGP key
- [x] Explanatory text
- [ ] Confirm displayed on GitHub Security tab (admin/visual check)

## 12. CI Tests — ⚠️

- `pr.yml` triggers on every PR (`opened, synchronize, reopened`) and calls `ci.yml`.
- `build_cmake.yml` runs `ctest -E System` (unit + integration tests) on Windows and Ubuntu; codegen drift check (`git diff --exit-code`); `validate_python.yml` lints and validates examples; `validate_imported_protos.yml` validates protos.
- System tests run on self-hosted hardware (see area 1).

Action for NI admin: add as required status checks — e.g. "Windows Build", "Ubuntu Build", "NILRT Cross Compile", "Validate Python Code", "Validate Imported Proto Files" (exact names as shown on a PR). Save a passing run as evidence.

## 13. Documentation — ✅

`README.md` includes: purpose ("NI gRPC Device Server and Client APIs", supported drivers), usage (Downloading a Release, Running the gRPC Server, Creating a gRPC Client, TLS), and build ("Building Locally", with wiki link). Also `CONTRIBUTING.md`. Owner to review for accuracy.

## 14. License — ✅

Top-level `LICENSE`: MIT, "Copyright (c) 2022, National Instruments Corp." `ThirdPartyNotices.txt` present. NI to confirm MIT is an approved Emerson T&M license (and whether the copyright holder line should be updated).

## 15. Secret Scanning & Push Protection — ❓ (admin)

Settings cannot be read from a clone. Only key-like files tracked are the test certificates noted in area 2.

Action: enable secret scanning + push protection; run a full-history scan (e.g. gitleaks/trufflehog on a clone) to supplement GitHub alerts; report any real secret to NI immediately for rotation; save settings + alert list as evidence.

---

## Decisions needed from NI

1. Policy for fork PRs reaching self-hosted runners (area 1).
2. Named owner, reviewer, security contact; GitHub admin who will apply settings.
3. CodeQL C/C++ build mode: full CMake build vs. `build-mode: none` (area 9).
4. SBOM format and whether to publish with releases (area 10).
5. Confirm MIT license approval (area 14) and whether Renovate is already enabled at org level (area 7).

## PR contents

Implemented on branch `cra/security-hardening` (see Remediation log):

- [x] Least-privilege `permissions` in all workflows (area 6)
- [x] `env:` instead of inline expressions; `workflow_run` event/repo guard (area 1)
- [ ] Pin actions to commit SHAs (area 1, optional, not done)
- [x] `.github/dependabot.yml` (area 7)
- [x] `.github/workflows/codeql.yml` (area 9)
- [x] SBOM generator and workflow (area 10)

Rollback: revert the PR; no repository settings are changed by it.
