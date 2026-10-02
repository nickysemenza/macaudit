# Bounded registry license sidecar

This directory preserves upstream license files and notices omitted from the
specific registry crate archives listed in `manifest.json`. It is not a general
SPDX-text substitute, a wildcard version fallback, or a license-compliance
sign-off. No package source, notices generator, or lockfile is changed here.

## Manifest contract

`manifest.json` has `schema_version: 1` and two maps:

- `packages` is keyed by the exact string `name@version`. Each entry records the
  package's original Cargo license expression and registry source, the archive
  SHA-256 from `Cargo.lock`, its upstream repository and pinned revision, source
  verification evidence, and an ordered `license_files` array.
- `files` is keyed by repository-root-relative path. Each record contains the
  preserved file's SHA-256 and one or more immutable upstream source URLs,
  revisions, and original paths. Shared files are reused only after comparing
  their bytes at every applicable package revision.

Resolve `license_files` against the repository root, not this directory or the
working directory. Look up the exact package name and version only when the
package does not already ship license files. Do not use another version, infer
a file from the SPDX identifier, or scan unrelated sidecar directories. Check
the registry source and file hashes before consuming a fallback. The archive
checksum also permits checking that the entry describes the locked archive.

For example, the `anes@0.1.6` entry points to
`docs/licenses/anes/LICENSE-APACHE` and `docs/licenses/anes/LICENSE-MIT`.
`r-efi` deliberately points to `AUTHORS`: the complete MIT alternative and its
copyright notices are in that original upstream file, not a `LICENSE` file.

`license_text_status` distinguishes:

- `complete`: the full original text for `preserved_license` is preserved. For
  `r-efi`, this means the MIT alternative, not separate complete Apache/LGPL
  texts. Its original multi-license grants remain in `AUTHORS` unchanged.
- `notice-only`: the full original upstream licensing notice is preserved, but
  the license terms/attribution are not verified as complete. These entries must
  remain visible as limitations; a nonempty fallback is not proof of complete
  license terms.

## Provenance and scope

All 24 selected `.crate` archive SHA-256 values were checked against `Cargo.lock`.
For the 21 crates with `.cargo_vcs_info.json`, the upstream `Cargo.toml` at the
recorded SHA was compared byte-for-byte with the packaged `Cargo.toml.orig`.
The legacy `anes` VCS file has no package path; its matching manifest is in
`anes/Cargo.toml`.

Three archives omit `.cargo_vcs_info.json`:

- Both `winapi-*-pc-windows-gnu@0.4.0` archives match upstream commit
  `9497609ef44cc9bcd16cd2411c0ee6ccaf5483aa`: all 1,390 i686 and 1,419 x86_64
  original package files, including import libraries, match Git blob hashes.
  Generated `Cargo.toml` and Cargo cache bookkeeping are excluded; the packaged
  `Cargo.toml.orig` is compared with upstream `Cargo.toml`.
- `rustls-platform-verifier-android@0.1.1` has byte-identical Rust source and
  original manifest at `da3d9c36f48fb9f8f97e94f132fdab67ab0fc75b`. Its packaged
  AAR also matches the upstream backfilled artifact at
  `a9c4a842e44e41b0ff0ef0ec12486853ce81f34c`; the manifest records the artifact
  path, Git blob hash, and SHA-256. The archived Maven group directory is
  `org/rustls`, while the older package directory is `rustls`; identical bytes,
  not directory naming or a coincidentally named release tag, establish the
  artifact match.

These are verified source-content matches, not assertions that these commits
were the actual publishing commits. Publishing SHAs cannot be recovered from
the three archives themselves.

The eight `uniffi*` registry crates at 0.32.2 share one upstream revision and
license. JNI and WezTerm family files are reused only where the originals are
byte-identical across their distinct recorded revisions. License/notice files
are copied without adding copyright holders, dates, headers, or substituted
license templates. Provenance lives in the manifest, not inside those files.

## Unverifiable full-text cases

`objc2@0.6.4`, `objc2-encode@4.1.0`, and `objc2-foundation@0.3.2` each declare
MIT. At their exact recorded revisions the repository's `LICENSE.md` explains
that licensing and discusses Apple SDK-derived code, but supplies neither the
MIT terms nor a project copyright notice. The original notice is identical at
all three revisions and is preserved in `objc2/LICENSE.md`; the entries are
explicitly marked `notice-only`. No historical project's attribution or generic
MIT template is substituted. The upstream Apple SDK discussion is preserved,
not interpreted as an independent permission grant.

## Updating

New versions require fresh inspection of their packaged source, Cargo metadata,
and VCS metadata. Retrieve files from the corresponding authoritative pinned
source, verify the source/archive and file hashes, and add exact-version entries.
Keep unresolved provenance or missing license terms explicit rather than
silently accepting another revision or inventing attribution.
