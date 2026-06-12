# Repository Guidance

## Changelog

- Maintain `CHANGELOG.md` for every logical user-visible change, release,
  packaging update, public API change, documentation change, example update, and
  book-publishing workflow change.
- Add entries in the same change that introduces the behavior. Group entries by
  release version and then by the date the logical change landed.
- If a change is not part of a released version yet, add it under `Unreleased`.
  When preparing a release, move the relevant `Unreleased` entries under the new
  version section and keep the dates attached to the actual work.
- Keep changelog entries concise and outcome-focused. Mention verification or
  publishing only when it is part of the delivered behavior.

## Prompt-Boundary Commits

- Before starting work requested by a new user prompt, conclude any finished
  unit of work already in the working tree: add or update its `CHANGELOG.md`
  entry, verify the relevant checks, and commit it separately.
- Keep commits separated by logical unit of work. Do not mix a previous
  completed change with newly requested work just because both are present in
  the same working tree.
- If a new prompt arrives while a previous unit is still in progress, first
  bring that unit to a clean stopping point and commit it when it is complete;
  then begin the new prompt as its own change with its own changelog entry.

## Auxiliary Artifacts

- Ignore auxiliary artifacts created while testing, rendering, inspecting, or
  validating repository behavior. Prefer adding narrow generated-artifact paths
  to the user's global ignore file when the artifacts are local tooling output
  rather than project source.
- Do not commit temporary screenshots, rasterized previews, extracted packages,
  scratch PDFs, logs, or other local verification outputs unless the user
  explicitly asks for them to become tracked fixtures or documentation assets.
