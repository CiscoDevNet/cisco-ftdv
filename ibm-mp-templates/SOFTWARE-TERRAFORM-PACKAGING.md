# Software Terraform publisher guide

Use **Software → Terraform**. Customer installation instructions are in the separate [ASAv](solutions/asav-ibm-tf/README.md), [FTDv](solutions/ftdv-ibm-tf/README.md) and [FMCv](solutions/fmcv-ibm-tf/README.md) module READMEs. Run publisher commands from `ibm-mp-templates/`.

## Product contracts

| Product | Package/listing version | Image selector label | Interfaces | Default profile / Secure Boot |
|---|---|---|---|---|
| ASAv | 9.2410.1 | 9.24.10.1 | Management eth0; data eth1/eth2 | `cx3d-2x5` / true |
| FTDv | 10.11.1 | 10.1.1.1 | Data eth0/eth1/eth3; management eth2; Diagnostic OFF | `cx3d-4x10` / true |
| FMCv | 10.11.1 | 10.1.1.1 | Management eth0 | `bx3d-8x40` / false |

Common behavior follows ASAv: reuse existing RG/VPC/subnets/SGs/key, customer-unique prefix without random suffix, one required string `ssh_key_id`, optional sensitive raw Day-0, optional management FIP false by default, native VNIs, HTTP metadata/hop limit 1, and `ibm_is_instance.catalog_offering.version_crn` from product image JSON. The image digest is reference metadata; the archive SHA-256 is a different checksum.

Intentional differences: FTDv has three data NICs with spoofing true/filtering disabled, while its management NIC and FMCv use false/Auto. ASAv retains its all-interface defaults. FTDv/FMCv accept raw JSON rather than ASA commands; their boot volumes inherit image minimums (100/250 GB respectively), and explicitly enable boot-volume auto-deletion. They also guard verified reference/access-scope metadata for selected-account releases. These differences are product-specific; do not mechanically copy ASAv settings.

FTDv raw Day-0 may optionally include supported FMC registration fields. Terraform does not create an FMC, call its API or complete manager-side Add Device. FMC licensing/evaluation initialization is required before registration. See the module operations guides for bootstrap, connectivity, licensing and no-Day-0 setup details.

## Package boundary

New TGZs contain exactly one `root/` directory and 16 files: 14 module files (seven `.tf` files, provider lock file, README, image JSON, changelog, Day-0 example and two documentation assets) plus `LICENSE` and `NOTICE` copied byte-for-byte from repository root. `README.md` is beside `main.tf`. Product files differ: ASAv ships an ASA text example and routing guide; FTDv/FMCv ship JSON examples and operations guides.

The repository-root legal files remain the single source; `package_legal.py` reads them at build time and rejects missing, empty or symlinked files. Module directories retain their strict 14-file allowlists. Verification reports record 16 archived-file hashes, legal-file provenance and packaging schema 2.

Publisher tools/tests, repository/project READMEs, planning notes, state, credentials, provider caches, logs and private account evidence stay outside the archive. Builders enforce an exact file allowlist and reject unexpected module files or symlinks. See [IBM archive guidance](https://cloud.ibm.com/docs/sell?topic=sell-repo-upload-error).

**Pending ASAv Catalog update:** the fresh 16-file ASAv candidate has been generated with the approved README corrections and legal files; see the [candidate status](publisher/README.md#asav-candidate-and-pending-catalog-update). The historical submitted TGZ/checksum/report remain unchanged. Import the reviewed candidate through the supported Catalog draft/revision workflow and rerun exact-archive Partner Center validation when resumed. Do not overwrite the old URL or assume its prior validation covers new bytes. Keep the import/validation action open until completed.

## 1. Pre-publication: checks and release artifacts

Use Python 3.9+ and Terraform **>=1.13.4, <1.14.0**; IBM provider is pinned to **2.4.0**:

```sh
python3 -m unittest discover -s publisher/tests -p 'test_*.py'
python3 publisher/check_asav.py --terraform terraform
python3 publisher/check_ftdv.py --terraform terraform
python3 publisher/check_fmcv.py --terraform terraform
python3 publisher/package_asav.py
python3 publisher/package_ftdv.py
python3 publisher/package_fmcv.py
```

Check runners use isolated temporary copies and product-specific mock tests; they never deploy resources. Provider installation needs registry access or a verified local mirror/cache. ASAv supports `--installed-providers`; FTDv/FMCv support an empty `--work-dir` outside the repository. See [publisher tools and tested coverage](publisher/README.md). Local checks and source deployments do not establish Catalog validation.

Builders need no cloud credentials. They produce a TGZ plus sibling `.sha256` and `.verification.json` under `tf-releases/PRODUCT/`:

```text
asav/asav-ibm-tf-9-2410-1-HHMMSS-YYYYMMDD.tgz
ftdv/ftdv-ibm-tf-10-11-1-HHMMSS-YYYYMMDD.tgz
fmcv/fmcv-ibm-tf-10-11-1-HHMMSS-YYYYMMDD.tgz
```

Filename time uses Asia/Kolkata, six-digit HHMMSS. Source-identical builds produce identical archive bytes regardless of filename/time. Existing artifact names are never overwritten. Preserve published triplets; keep superseded unpublished builds and `DRAFT-` review copies outside the committed release folders. Every builder rejects custom output inside any deployment module under `solutions/`, including paths reached through symlinks.

For a custom name or temporary destination:

```sh
PRODUCT_OUT="$(mktemp -d /private/tmp/ibm-tf-release.XXXXXX)"
python3 publisher/package_ftdv.py --filename ftdv-review.tgz --output-dir "$PRODUCT_OUT"
tar -tzf "$PRODUCT_OUT/ftdv-review.tgz"
(cd "$PRODUCT_OUT" && shasum -a 256 -c ftdv-review.sha256)
```

`--version` is an equality check against the changelog, not an override. Unresolved FTDv/FMCv references block normal packaging; `--draft` permits clearly labelled local review output only. A verification report describes exact archive bytes and project-relative source, not IBM approval.

### Version and image maintenance

Prepend each dated `version MAJOR.MINOR.PATCH` entry to the **top** of the module's `changelog.txt`. The builder reads the first entry and validates the entire history: unique, numerically descending three-component versions, valid English-month dates and a Changes heading. Length does not change selection. Suffixes such as `-v1` are not supported; agree the next IBM Software version before shipping a template-only revision.

Edit only the selected product's `solutions/PRODUCT-ibm-tf/PRODUCT-images.json` for compatible image-list changes:

| Action | Required change |
|---|---|
| Add | Add a new label with verified package version, exact version CRN/locator/digest, nullable plan CRN, supported regions/profiles and boolean Secure Boot modes. FTDv/FMCv also record verified reference/access scope and boot minimum. |
| Remove | Choose a retained default before deleting a label. Preserve the old package for deployments still selecting it. |
| Update | Prefer a new label for a different image. Correct metadata from verified evidence; do not silently retarget a historical label. |
| Default | Change `default_version` intentionally. Null/unpinned inputs follow that packaged default and may select a different image. |

For FTDv/FMCv, `python3 publisher/inspect_catalog.py PRODUCT --authenticated --output /private/tmp/new-catalog-evidence.json` reads using the current CLI identity; omit authentication for public reads. Selected-account success does not prove public availability. Keep this evidence outside Git. Do not invent CRNs or assume publication changes them.

Then update the changelog, check/build and review the Catalog form's image choices/default separately. New bootstrap/NIC/metadata contracts require code and qualification changes. A removed selected label can block planning/destroy until the original package or a valid reference is restored.

### Product release checklist

For each new FTDv/FMCv release, retain dated evidence outside the repository:

- Verify the exact backing VSI CRN/locator/digest and access for the intended consumers.
- Run isolated checks and test the agreed profile/zone/firmware scope, metadata, interface roles and initial access with supplied/omitted Day-0.
- Verify product management and relevant registration/policy/traffic behavior; test no-op, tag and management-FIP changes and complete owned-resource cleanup.
- Inspect the final archive/README and validate those exact bytes through Partner Center with runtime1.13, reviewed form/IAM/content/legal/BYOL and the intended audience.
- State qualification exclusions explicitly. FMCv VSI replacement, image migration and backup/restore recovery are outside the initial qualified scope; do not imply that generic change-impact guidance qualifies these operations.

### Source licensing and Catalog agreements

IBM's onboarding guide asks for URLs to additional agreements customers must accept; its archive-format guide requires a single root directory, not a fixed file count or a prescribed LICENSE filename. IBM platform terms, the vendor's product EULA/BYOL terms and the repository's source-code license are separate layers. Review the applicable source-license and attribution distribution obligations with the owner; Catalog import/approval is not a substitute for that decision. The implementation retains the existing Apache-2.0 license and Cisco notice unchanged and bundles both in new archives. This preserves their text without claiming ownership clearance for other material or changing appliance BYOL terms.

## 2. Partner Center import and configuration

1. Review/commit/push the source and curated product archive. Use its immutable raw URL or a GitHub Release asset URL; a GitHub `blob` URL serves HTML. An automatic whole-repository source archive is not the curated module payload.
2. Download the chosen URL to a temporary directory and compare SHA-256. Record source commit, URL and digest. For private source, configure supported PAT/Secrets Manager access and assign a credential renewal owner; do not assume import removes future fetch requirements.
3. Import into the corresponding **Software → Terraform** offering with the dotted changelog version. Enable the Terraform runtime override and select **1.13**. Verify the actual patch satisfies `version.tf` in Schematics logs; `TF_VERSION` is legacy metadata, not the executable selector.
4. Review required/sensitive/advanced inputs and output descriptions using the table below. Configure IAM requirements for the actual deployment identity.
5. Preview rendered README/relative images, architecture media, documentation/support and legal terms. Maintain product/card/About/Pricing/BYOL fields separately; README/HCL does not automatically fill Partner Center marketing metadata. Each Terraform offer needs its reviewed BYOL plan and Software-version association. Current backing-image `plan_crn=null` behavior is separate from this UI configuration.
6. Validate the exact imported archive and inspect logs/guest readiness. Complete applicable cost/compliance/requirements reviews before removing validation-owned resources. An old validation badge does not validate new archive bytes.

Raw URL pattern after the archive is committed and pushed:

```text
https://raw.githubusercontent.com/CiscoDevNet/cisco-ftdv/COMMIT_SHA/ibm-mp-templates/tf-releases/PRODUCT/FILE.tgz
```

### Runtime and input configuration

| Input/configuration | Review |
|---|---|
| `resource_group_name`, `vpc_id`, subnet/SG IDs | Required existing resources in the correct region/VPC/zone; RG name is not an RG ID. |
| `ssh_key_id` | Required single string, no array or default account key. Guest user/key setup remains separate. |
| `prefix` | Customer supplies a unique prefix; no random suffix. |
| `PRODUCT_image_version` | Visible optional string; show the JSON default and retained label choices. Catalog does not synchronize them automatically. |
| `instance_profile`, `region`, `enable_secure_boot` | Review product/image and live placement compatibility; configured choices are not proof of exhaustive guest qualification. |
| `user_data` | Optional sensitive/password input with a suitable secure multiline widget. Raw ASA text for ASAv; raw JSON object for FTDv/FMCv; never Base64. Secrets can remain in state. |
| `create_management_floating_ip` | Default false. Before enabling, restrict SG/ACL/guest management access. |
| Forwarding | Retain ASAv defaults and FTDv data spoofing true/filtering disabled. Management-only FMCv has no forwarding controls. A boot-only false override does not qualify forwarding. |
| Internal compatibility controls | Keep `TF_VERSION` and metadata compatibility settings out of the normal form; avoid an unnecessary API-key override when runtime IAM is available. |

Keep Terraform keys/types intact. The observed Software input editor did not provide a separate reliable friendly-name field; use clear descriptions and verify actual customer rendering. Imported form configuration and README prose do not automatically synchronize.

### Catalog IAM requirements

Adding IAM declarations documents requirements; it does **not** grant policies. Identify the actual runtime user/service ID/trusted profile or explicit API-key identity. ASAv's reviewed declaration uses these service names; adapt actual scopes and actions to each product:

| Service in version form | Service ID | Platform role | Service role |
|---|---|---|---|
| Virtual Private Cloud | `is.vpc` | Operator | — |
| Subnet | `is.subnet` | Editor | — |
| Security Group for VPC | `is.security-group` | Operator | — |
| SSH Key for VPC | `is.key` | Viewer | — |
| Virtual Network Interface | `is.virtual-network-interface` | Administrator | — |
| Virtual Server for VPC | `is.instance` | Editor | — |
| Block Storage for VPC | `is.volume` | Editor | — |
| Floating IP for VPC | `is.floating-ip` | Editor | — |
| Image Service for VPC | `is.image` | Operator | — |
| Schematics | `schematics` | — | Manager |
| Instance Management | `globalcatalog-instance` | Editor | — |

This is a reviewed deployment declaration, not a proven minimum custom role. Floating-IP access applies when enabled. Native VNI spoofing/protocol filtering requires the corresponding VNI management actions; an older instance-only IP Spoofing Operator role is insufficient. Subnet permission must cover reserved-IP allocation. FMCv does not require spoofing=true, so assess its narrower needs separately.

Outside the version form, verify resource-group read access and access to reused resources in other groups, applicable Catalog Management (`globalcatalog-collection`) Viewer access, and backing image entitlement/visibility. The form's Personal Catalog Administrator/Service Configuration Reader options must not be substituted for Viewer. No separate `globalcatalog` requirement is established merely by using a `globalcatalog-collection` version CRN. Customers obtain BYOL entitlements separately.

ASAv's intended spoofing=true configuration was successfully validated through Catalog on 17 November 2026 after the permission grant; earlier false-only validation/permission-blocked notes are historical. That result does not automatically validate a new archive or other products. FTDv/FMCv real IaaS tests used their intended per-role flags; each new Terraform offer still needs exact-archive Catalog validation.

## 3. Lifecycle qualification and cleanup

Use a disposable lab with permitted IAM; these commands create/change/delete resources when executed. Keep inputs, credentials, backups, plans and state protected outside Git. Use the matching module README to prepare real `lab.tfvars` and optional customized Day-0. Do not put `file()` expressions in `.tfvars`.

```sh
# Set PRODUCT to asav, ftdv or fmcv before running.
PRODUCT=ftdv
PROJECT_ROOT="$PWD"
umask 077
PRODUCT_LAB="$(mktemp -d /private/tmp/ibm-tf-lifecycle.XXXXXX)"
cp -R "$PROJECT_ROOT/solutions/$PRODUCT-ibm-tf/." "$PRODUCT_LAB/"
cd "$PRODUCT_LAB"
terraform version
terraform init -backend=false -lockfile=readonly
# Create protected lab.tfvars and optional day0.json/day0.txt here.
# export TF_VAR_user_data="$(cat day0.json)"  # raw JSON for FTDv/FMCv; text for ASAv
terraform plan -var-file=lab.tfvars -out=deploy.tfplan
terraform show -no-color deploy.tfplan
terraform apply deploy.tfplan
terraform output
terraform plan -var-file=lab.tfvars -detailed-exitcode
```

Exit code 0 means no change, 2 means changes and 1 means error. Verify guest version, Day-0, management, interface mapping and intended forwarding flags. FMCv can take 30 minutes to initialize; initialize its licensing before FTDv registration. For FTDv, verify registration/policy and bidirectional allowed/blocked traffic through all three data ports before diverting production traffic.

Review saved plans for tag and optional-management-FIP updates. Confirm FIP-only changes retain the VSI. Example:

```sh
terraform plan -var-file=lab.tfvars -var='create_management_floating_ip=true' -out=fip-on.tfplan
terraform show -no-color fip-on.tfplan
terraform apply fip-on.tfplan
```

Persist intended inputs before checking drift. For profile/image/Day-0 changes, review one change at a time, preserve backups and schedule downtime. The pinned provider can replace the VSI for Catalog-image or Day-0 changes; inspect the actual plan and cleanup of old resources. Retain the matching source/state/backend and original valid image references.

Before destroy, remove dependent customer routes or managed-device dependencies and record exact owned IDs. Then:

```sh
terraform plan -destroy -var-file=lab.tfvars -out=destroy.tfplan
terraform show -no-color destroy.tfplan
terraform apply destroy.tfplan
terraform state list
unset TF_VAR_user_data
```

Verify every owned instance, boot volume, VNI, reserved private IP and optional FIP is gone using exact-ID API/CLI reads. Authentication errors do not prove deletion. Preserve shared VPCs, subnets, SGs, keys, gateways and images; keep state until cleanup is confirmed. Do not release unrelated public-gateway IPs. Detailed source qualification limits are in [publisher coverage](publisher/README.md); HA/performance, recovery and untested upgrade combinations require their own evidence before support claims.

## 4. Approval, publication and recipient verification

Ensure each intended consumer can access the backing VSI version. Selected-account access supports a pilot in allowed accounts; before broader public Terraform release, extend backing VSI availability accordingly (public and hidden is the planned path). Git visibility, VSI visibility and Terraform-offer visibility are independent.

Finish the product/version/pricing approvals and publish only to the authorized audience. From a recipient account, verify tile access, image/form defaults, README/media/legal/BYOL, deploy/management/functionality, a controlled update/no-op and complete destroy. Record published offering/version IDs, source commit, immutable URL/checksum and release owner. Keep detailed logs and private account records outside this repository.

## References

[IBM onboarding/validation](https://cloud.ibm.com/docs/sell?topic=sell-sw-validate), [README outline](https://cloud.ibm.com/media/docs/downloads/software/sw-readme-tab-template.md), [IAM roles/actions](https://cloud.ibm.com/docs/iam?topic=iam-iam-service-roles-actions), [selected-account publication](https://cloud.ibm.com/docs/account?topic=account-catalog-other-publish), [managed runtime constraints](https://cloud.ibm.com/docs/schematics?topic=schematics-version-constraints).
