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

Builders produce deterministic `root/` payloads containing 14 allowlisted module files plus the canonical repository `LICENSE` and `NOTICE` (16 files total). The legal text is read from repository root at build time; module directories do not maintain duplicate copies. New manifests hash both legal files and record their repository-relative origin. They validate changelog history, image references, relative links and round-trip hashes; reject unexpected files/symlinks; refuse overwrites; and write `.tgz`, `.sha256` and `.verification.json` under `tf-releases/PRODUCT/`. `--filename` customizes the basename; `--output-dir` changes the external destination; `--version` checks equality with the newest changelog entry. Every builder rejects output inside any deployment module under `solutions/`, including symlink aliases and custom-source descendants.

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

These results do not establish Partner Center validation, all-profile/region coverage, image upgrades, FMCv VSI replacement, recovery, HA/performance or advanced threat qualification. ASAv deployment HCL and its historical submitted release are preserved from the merged base; a fresh candidate includes the approved README and packaging updates. This does not rerun or extend its historical cloud qualification. Keep detailed test logs, planning checklists and account/resource inventories outside public source.

FMCv VSI replacement, image migration and backup/restore recovery are explicitly excluded from the initial qualified scope. This does not remove the customer's need to establish backups.

See the [shared publisher guide](../SOFTWARE-TERRAFORM-PACKAGING.md).

## Pull request checks

The repository workflow `IBM Terraform PR checks` runs on PRs targeting `cisco-secure-firewall-ibm-marketplace`, on relevant pushes to that branch, or by manual dispatch. It runs Python regression tests, verifies retained artifact triplets, and runs isolated fmt/init/validate/mock checks for all three products on Linux with Terraform1.13.5 and the committed provider lock files. Checkout is pinned to a full commit SHA with credentials persistence disabled; token permissions are read-only. No configured IBM credentials, PAT or cloud deployment secrets are required, and no live resources are created.

`python3 publisher/verify_releases.py` checks each retained TGZ against its own checksum/manifest. Historical release bytes remain valid when source documentation advances; this check does not claim that every historical archive equals current source or is IBM-validated. Build and validate the exact new candidate before onboarding it. Hosted workflow execution starts only after this workflow is pushed and a supported event occurs.

## ASAv candidate and pending Catalog update

The fresh ASAv candidate is [`asav-ibm-tf-9-2410-1-114026-20261119.tgz`](../tf-releases/asav/asav-ibm-tf-9-2410-1-114026-20261119.tgz), version **9.2410.1**, with 16 files including the approved README changes and canonical `LICENSE`/`NOTICE`. Its checksum and verification report are stored beside it. The historical submitted 14-file TGZ/checksum/report remain unchanged.

**Still pending:** commit/push the reviewed candidate when authorized, import it through the supported Catalog draft/revision workflow, and rerun exact-archive Partner Center validation. A local build does not update the existing Catalog version or extend its prior validation. `verify_releases.py` keeps the Catalog-update reminder visible for the retained historical archive. New schema 2 archives include legal files and their provenance hashes.
