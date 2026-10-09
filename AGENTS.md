# EntitlementLens

## Validation and evidence

- Use the SwiftPM package at this root with a Swift 6.2-compatible macOS toolchain. Run `swift build` and `swift test` before a PR; keep the system-binary, signing, architecture, export, and cancellation integration tests enabled.
- Static declarations, signature integrity, installed policy, execution policy, and runtime authorization are separate evidence categories. Preserve the README's distinctions and report scan coverage gaps.
- Keep private binaries, credentials, keys, personal paths, and unrestricted forensic evidence out of Git, Actions artifacts, and PRs.
- Successful Swift and GitHub Actions CodeQL analyses must refer to the candidate revision; scanner configuration alone does not verify analysis.
- Keep CodeQL extraction/build jobs read-only. Upload SARIF in a separate job that runs no repository code, and preserve the strict `CodeQL results` gate across every language.

## Publication and privilege

- CI builds both executables without registering or exercising the privileged helper. Helper registration requires matching app/helper signing teams and the macOS-owned approval flow; hosted CI does not prove privileged or TCC behavior.
- Local ad hoc signing is not Developer ID signing or notarization. Packaging, signing for distribution, tagging, and publishing require authorization covering those operations.
- Preserve the existing license and unrelated local work; changing the pending local license choice is outside an infrastructure task.
