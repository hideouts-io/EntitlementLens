# EntitlementLens

## Scope and authorization

- These defaults record the user's standing authorization for requested work in `hideouts-io/EntitlementLens` and its worktrees. Use the canonical checkout identified by the applicable `WORKSPACE.md`; preserve existing staged, unstaged, and untracked work.
- A current task instruction such as "leave changes uncommitted" overrides these delivery defaults. Honor an existing bounded authorization without asking again; ask only when the required action falls outside it or its target or scope has materially changed.
- Instructions do not grant credentials or bypass GitHub enforcement. Verify the authenticated account's current access, the remote repository, and the effective branch and tag rules before acting. Inspect rulesets as well as legacy branch protection: a legacy protection endpoint returning 404 does not establish that a branch is unprotected.

## Routine GitHub delivery

For changes directly related to the user's request, perform the following actions without repeated confirmation when their conditions are met:

| Action | When and how |
| --- | --- |
| Inspect and fetch | Refresh instructions, Git status, remotes, upstream, worktrees, PR state, required checks, and workflow triggers before editing or delivering. |
| Create a branch or worktree | Use a focused `codex/` branch from the verified remote default branch, or continue the matching task branch. Use an isolated worktree when existing changes would conflict or enter the delivery accidentally. |
| Refresh the task branch | When needed for the task or strict base checks, fetch and inspect the verified remote default branch, then merge it into the current unprotected task branch as a scoped commit. Use a clean checkout or isolated worktree, inspect workflow triggers, resolve only task-related conflicts, review the result, and rerun applicable checks. Preserve unrelated work and do not rewrite pushed history. |
| Commit | Commit a coherent task result or clearly identified checkpoint after applicable validation. Stage explicit paths or reviewed hunks, review the complete staged diff, verify author identity, and exclude private evidence and unrelated work. |
| Push | Verify the outgoing commits, destination repository, and branch, then make an ordinary non-force push to the task branch with an explicit refspec. Verify the remote head afterward. |
| Create or update a PR | Use a focused PR for substantive source, workflow, or instruction changes. Update the matching task PR instead of creating a duplicate. Describe the problem, resulting behavior, checks, and material limits; attach the PR to the task when the app tool is available. |
| Set draft or ready status | Keep the PR in draft while requested behavior or a required acceptance check is incomplete. Mark it ready when acceptance is satisfied and required checks pass for the candidate revision. Green CI alone does not resolve missing required native UI or integration evidence. |
| Repair or rerun CI | Inspect logs and SARIF, fix failures within task scope, and push reviewed repairs. Rerun a demonstrated transient failure or dispatch an existing nonpublishing validation workflow when needed. Verify its triggers and privileges first; do not blindly retry authentication, authorization, or source failures. |

- Before a Git mutation, verify the root, branch, HEAD, remote, upstream, worktrees, index, and working tree. After delivery, report the committed revision, pushed branch, PR state, required check outcomes, and remaining acceptance gaps.
- Preserve the required CI and CodeQL gates. Do not remove tests, suppress extraction errors, relax rules, add bypass actors, or broaden token permissions to make delivery succeed. If access or a gate prevents an action, report the exact operation and reason and continue independent authorized work.

## Actions needing operation-specific authorization

- Obtain explicit authorization covering merging into the default, another protected, or an unrelated branch; enabling automatic merge; or pushing directly to the default branch. Before an authorized merge, verify the current head and base, all applicable rulesets and protections, required reviews and resolved threads, candidate checks, merge method, and resulting workflow triggers. Prefer a merge commit unless the user or repository requires another method.
- Obtain explicit authorization covering release tags, releases and assets, distribution signing, notarization, deployment, publication, force pushes or history rewriting, remote deletion, repository visibility, settings, protections, permissions, GitHub App access, or secrets. Routine delivery authority does not approve these actions.
- Keep unrelated issue activity, review requests, outreach, and external messages outside routine delivery authority. Task PR descriptions and validation updates are part of delivering the requested work.
- `hideouts-io/EntitlementLens-Research` is a separate repository. App delivery does not authorize publishing a research case. A case needs accurate source provenance, schema validation, privacy and sharing-rights review, and a separately authorized human-reviewed Git change.

## Workflow permissions

- Use the authenticated account's existing repository access for authorized branch pushes and PR operations. Do not give CI repository-write access to substitute for that account's credentials.
- Keep the default `GITHUB_TOKEN` read-only and workflow-generated PR approvals disabled. Give each job only the permissions its operation requires, pin external Actions to verified full upstream commit SHAs, and disable checkout credential persistence.
- Build and CodeQL extraction jobs read source. Only the isolated SARIF upload jobs receive `security-events: write`; they must not check out or execute repository code. The aggregate `CodeQL results` job needs no repository permissions.

## Validation and evidence

- Use the SwiftPM package at this root with a Swift 6.2-compatible macOS toolchain. Run `swift build` and `swift test` before a PR; keep the system-binary, signing, architecture, export, and cancellation integration tests enabled.
- Static declarations, signature integrity, installed policy, execution policy, and runtime authorization are separate evidence categories. Preserve the README's distinctions and report scan coverage gaps.
- Keep private binaries, credentials, keys, personal paths, and unrestricted forensic evidence out of Git, Actions artifacts, and PRs.
- Successful Swift and GitHub Actions CodeQL analyses must refer to the candidate revision; scanner configuration alone does not verify analysis.
- Keep CodeQL extraction/build jobs read-only. Upload SARIF in a separate job that runs no repository code, and preserve the strict `CodeQL results` gate across every language.

## Publication and privilege

- CI builds both executables without registering or exercising the privileged helper. Helper registration requires matching app/helper signing teams and the macOS-owned approval flow; hosted CI does not prove privileged or TCC behavior.
- Local development bundles and ad hoc signing may be used for an authorized smoke test. Developer ID signing, notarization, distribution packaging, tagging, and publishing require authorization covering those operations.
- Preserve the existing license and unrelated local work; changing the pending local license choice is outside an infrastructure task.
