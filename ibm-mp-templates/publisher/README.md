# Publisher tools

Run from `ibm-mp-templates/` with Python 3.9+ and Terraform **>=1.13.4, <1.14.0**. The IBM provider is pinned to **2.4.0**.

```sh
python3 -m unittest discover -s publisher/tests -p 'test_*.py'
python3 publisher/check_asav.py --terraform terraform
python3 publisher/check_ftdv.py --terraform terraform
python3 publisher/check_fmcv.py --terraform terraform
python3 publisher/package_asav.py
python3 publisher/package_ftdv.py
python3 publisher/package_fmcv.py
```

Checks build/extract into isolated temporary directories and run fmt/init/validate plus product-specific mock tests. They do not deploy resources or establish live image access. FTDv/FMCv also test an unresolved-reference deployment guard and use synthetic default/alternate references only in temporary mock copies. Image-selection tests do not pin the shipped image label; package tests initialize a controlled changelog fixture. Builders are covered by direct and symlink tests that reject output under any deployment module. Provider installation may need network access. ASAv supports `--installed-providers`; FTDv/FMCv support an empty `--work-dir` outside the repository. Keep generated logs and evidence outside the repository.

Initialization uses standard `terraform init` in the temporary extracted copy so Terraform can record the current platform’s provider content checksum after verifying the package against the committed checksums. The provider version remains pinned; source lock files and release archives are never modified by these checks. See [Terraform dependency lock files](https://developer.hashicorp.com/terraform/language/files/dependency-lock).

Builders produce deterministic `root/` payloads containing 14 allowlisted module files plus the canonical repository `LICENSE` and `NOTICE` (16 files total). They read and hash both legal files from the repository root. Builders validate changelog history, image references, relative links, and round-trip hashes. They reject unexpected files and symlinks, refuse overwrites, and write `.tgz`, `.sha256`, and `.verification.json` under `tf-releases/PRODUCT/`. Use `--revision N` to append a package revision to the dotted Software version, or `--filename` for a custom basename. Both options are optional and mutually exclusive. Use `--output-dir` for an external destination and `--version` to check the newest changelog entry. Builders reject output inside deployment modules under `solutions/`.

FTDv/FMCv share `package_product.py` and `check_product.py`, with small product wrappers. ASAv retains its existing builder and check runner so its release behavior remains independent. Each runner selects only its own Terraform tests. Unresolved FTDv/FMCv image references block a normal build; `--draft` permits a labelled local review archive whose filename must begin `DRAFT-`. Keep such drafts outside committed release folders. Reports describe local package checks, not IBM validation/approval.

## Catalog reference inspection

```sh
python3 publisher/inspect_catalog.py ftdv
python3 publisher/inspect_catalog.py fmcv --authenticated --output /private/tmp/new-fmcv-evidence.json
```

The helper supports FTDv/FMCv. Anonymous reads check public access; `--authenticated` uses the current IBM CLI identity for selected-account access. Tokens stay in memory and curl stdin, outside arguments/output/evidence; TLS verification remains enabled. Authenticated success establishes caller access, not all-user availability. Anonymous HTTP 403 does not disprove access for allowed accounts. The helper never changes image JSON; review the exact references before editing it. Optional output must be a new private evidence file outside the repository.

## Qualification boundaries

FTDv/FMCv were source-qualified on 18 November 2026 with Terraform 1.13.5 / IBM 2.4.0 in `us-east-1` and `us-south-1`:

| Check | FTDv | FMCv |
|---|---|---|
| Default profile / Secure Boot | `cx3d-4x10` / true | `bx3d-8x40` / false |
| Image / guest | Label 10.1.1.1 / guest 10.1.1 Build 1 | Same |
| Management / Day-0 | Supplied and omitted Day-0 initial access | Supplied and omitted Day-0; separate manual CLI/web setup when omitted |
| Functionality | Registration, policy deployment and bidirectional allow/block traffic through all three data ports | Licensing evaluation, device registration and policy deployment |
| Lifecycle | No-op/tags/FIP toggle and Day-0 VSI replacement | No-op/tags/FIP toggle |
| Cleanup | Owned resources removed | Owned resources removed |

These results cover the recorded source tests. Validate the exact Partner Center archive separately. All-profile and all-region coverage, image upgrades, FMCv VSI replacement, recovery, HA, performance, and advanced threat qualification need separate tests. Keep detailed logs and account or resource inventories outside public source.

FMCv VSI replacement, image migration and backup/restore recovery are explicitly excluded from the initial qualified scope. This does not remove the customer's need to establish backups.

See the [shared publisher guide](../SOFTWARE-TERRAFORM-PACKAGING.md).

## Pull request checks

The repository workflow `IBM Terraform PR checks` runs on PRs targeting `cisco-secure-firewall-ibm-marketplace` and on relevant pushes to that branch. It runs Python regression tests, verifies retained artifact triplets, and runs isolated fmt/init/validate/mock checks for all three products on Linux with Terraform 1.13.5 and the committed provider lock files. Checkout uses a full commit SHA with credentials persistence disabled and read-only token permissions. The workflow uses mocks without IBM credentials or live resources.

`python3 publisher/verify_releases.py` checks each retained TGZ against its own checksum and manifest. Add `--changed-since origin/cisco-secure-firewall-ibm-marketplace` to also compare new or changed triplets against the module files and canonical `LICENSE` and `NOTICE` in your checkout. CI uses the PR base or previous push revision for this comparison when available. Retained releases keep their original payload when source advances.

## Release artifacts

Find retained archives, checksums, and verification reports in [`tf-releases/`](../tf-releases/). Use the module changelog for release history and the verification report for the exact archive filename and hash.

### Catalog handoff

After the archive merges, refresh the local `origin/cisco-secure-firewall-ibm-marketplace` ref. Provide the exact integration commit and archive path relative to the Git repository root.

```sh
python3 publisher/prepare_catalog_handoff.py "$ARCHIVE_REPO_PATH" \
  --commit "$INTEGRATION_COMMIT_SHA" --output /private/tmp/catalog-readme.md
```

The helper verifies the checked-out triplet against the commit and prints the commit-pinned raw URL and SHA-256. It writes the Catalog-ready README to a new temporary file, converting bundled relative links into commit-pinned GitHub links. Omit `--output` to print the README. Verify the downloaded archive against the digest before importing it. Follow the [Partner Center workflow](../SOFTWARE-TERRAFORM-PACKAGING.md#2-partner-center-import-and-configuration) for import and validation.
