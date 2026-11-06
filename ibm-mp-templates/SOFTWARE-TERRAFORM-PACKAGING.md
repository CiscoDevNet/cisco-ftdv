# ASAv Software Terraform publisher guide

Use **Software → Terraform**. The customer deployment guide is
[`solutions/asav-ibm-tf/README.md`](solutions/asav-ibm-tf/README.md).
This guide covers package creation, image-version maintenance and lifecycle checks.
Run its commands from the IBM project directory, `ibm-mp-templates/`.

## Package boundary

The `.tgz` contains one top-level `root/` folder holding all 14 customer files,
as required by [IBM's archive guidance](https://cloud.ibm.com/docs/sell?topic=sell-repo-upload-error).
`README.md` stays beside `main.tf` inside that folder:

```text
root/
├── .terraform.lock.hcl
├── README.md
├── asav-images.json
├── bootstrap/asav-day0.example.txt
├── changelog.txt
├── data.tf
├── docs/asav-existing-vpc.png
├── docs/routing-guide.md
├── locals.tf
├── main.tf
├── outputs.tf
├── provider.tf
├── variables.tf
└── version.tf
```

Publisher scripts/tests, this guide and the repository/project overview READMEs
stay outside the archive. The builder rejects unexpected module files and symlinks, ignores Finder
metadata, verifies local links/JSON, the single-folder layout and archive hashes,
and refuses overwrites. The layout adds one directory entry to the 14 file entries.
Keep state, plans, active `.tfvars`, credentials and logs outside the module.

## Local checks and build

Run from `ibm-mp-templates/`, using Python 3.9+ and Terraform **>= 1.13.4, < 1.14.0**:

```bash
python3 -m unittest discover -s publisher/tests -p 'test_*.py'
python3 publisher/check_asav.py --terraform terraform
python3 publisher/package_asav.py
```

`check_asav.py` builds/extracts into a temporary directory, then runs from its `root/`
folder to check formatting,
initialization with the committed lock file, validation and mocked-provider tests.
Mocks do not deploy IBM resources. Provider installation needs network access or
an existing cache; `--installed-providers /path/to/.terraform/providers` can reuse
an installed provider directory. The provider is pinned to **2.4.0**.

The package builder needs no IBM credentials. It writes the `.tgz`, `.sha256` and
`.verification.json` directly into `tf-releases/asav/`. The version comes from the
latest entry in the module's `changelog.txt` (initial version `1.0.0`).

Verification reports record the source relative to this IBM project and the
archive filename, so moving the artifact triplet does not leave absolute paths
from the build machine. For a custom `--source` outside the project, the report
records only its directory name; `source_path_base` identifies that case.

```text
asav-ibm-tf-<version-with-hyphens>-<HHMMSS>-<YYYYMMDD>.tgz
asav-ibm-tf-1-0-0-180500-20261105.tgz  # example
```

Time/date use **Asia/Kolkata (UTC+05:30)**; `HHMMSS` has six digits. A filename's
clock is build time, not changelog or publication time. Source-identical builds
have identical archive bytes even when filenames differ.

Optional custom filename/destination:

```bash
ASAV_OUT="$(mktemp -d /private/tmp/asav-ibm-tf-release.XXXXXX)"
python3 publisher/package_asav.py \
  --filename asav-review.tgz --output-dir "$ASAV_OUT"
tar -tzf "$ASAV_OUT/asav-review.tgz"
(
  cd "$ASAV_OUT"
  shasum -a 256 -c asav-review.sha256
)
```

`--filename` accepts a safe `.tgz` basename; use `--output-dir` for its directory.
`--version` is an optional equality check against the changelog, not an override.
Existing archive/sidecar names are never overwritten; a same-second collision
needs a different name or a later build time. Inspect the file list/checksum before
uploading. The verification report records a local build, not IBM approval.
`tar -tzf` must show only `root/` and entries beneath it, including
`root/main.tf` and `root/README.md`. Keep older flat-layout builds outside the
active release directory; rebuild them before using them for an IBM import.

## Partner Center import and configuration

1. Commit and push the generated deployment `.tgz`, then use its commit-pinned
   `raw.githubusercontent.com` URL (accepted by this validation workflow), or
   upload it as a GitHub Release asset and use that download URL. Record the source
   commit, URL and SHA-256. A GitHub `blob` URL serves HTML. The repository's automatic
   source archive includes publisher files and is not the curated module package.
2. In **Partner Center → product → Software → Import a version**, select Terraform,
   enter the asset URL and the dotted changelog version. For private source,
   configure supported read-only token/Secrets Manager access separately from
   deployment IAM. Assign a credential renewal owner.
3. Review deployment values, required/sensitive/advanced settings, output
   descriptions and IAM. Match image choices/defaults to `asav-images.json`;
   dropdowns are not synchronized automatically. Confirm the actual workspace
   uses a Terraform patch satisfying **>= 1.13.4, < 1.14.0** and IBM provider
   **2.4.0**. Enable the runtime override and enter **1.13**; confirm the actual
   patch in the job logs. `TF_VERSION` is legacy metadata, not a runtime selector.
   The API-key override is optional.
4. Preview the imported README and links, complete applicable BYOL/license and
   product fields, then run the version's validation workflow. Retain logs and
   remove validation resources. Public publication follows IBM approval; initial
   selected-account sharing uses the chosen eligible version state.

[IBM import/configuration/validation](https://cloud.ibm.com/docs/sell?topic=sell-sw-validate),
[version sharing states](https://cloud.ibm.com/docs/account?topic=account-catalog-share-overview),
[public approval/publication](https://cloud.ibm.com/docs/sell?topic=sell-terraform-publish).

| Artifact | Customer-facing purpose |
|---|---|
| Module `README.md` | Installation guidance rendered in the imported Readme view. Keep IBM's required lifecycle headings and verify rendering after import. |
| Terraform variables/outputs | Deployment schema; review its presentation in the imported version. |
| Partner Center fields | Product card, About, Support, Pricing, BYOL/legal, media and visibility. They are maintained separately from source prose. |

The packaged diagram supports the README. Listing media needs its own configured
hosted URL. There is no active DA manifest or automatic README-to-marketing sync.
See [IBM's README outline](https://cloud.ibm.com/media/docs/downloads/software/sw-readme-tab-template.md).

### Terraform runtime mismatch during validation

The 2026-11-06 Partner Center job ran `terraform1.13` with Terraform **1.13.5**.
Package 1.0.0 required exactly 1.13.4, so `init` stopped before provisioning.
Package **1.0.1** accepts `>= 1.13.4, < 1.14.0`. Keep provider 2.4.0 pinned and
leave the `TF_VERSION` metadata input out of the customer form; it accepts legacy
1.13 patch labels but does not select the executable.

For a retry, publish the new archive under a new filename/commit and import it as
a new draft version (package version **1.0.1**). Reuse the reviewed input/IAM
configuration and validation values, select runtime series **1.13**, then rerun
validation. A retry against the unchanged 1.0.0 archive retains its exact-version
failure. Preserve the original archive and the failed job logs.

Package 1.0.1 also replaces the draft's `ssh_key_ids` array with the required
`ssh_key_id` string. When copying deployment values from the old draft, omit the
old parameter and add `ssh_key_id` from the new source. Keep it required, visible
and without a default resource ID. Update validation JSON/tfvars from
`"ssh_key_ids": ["KEY_ID"]` to `"ssh_key_id": "KEY_ID"`. The module resolves one
regional key registration and supplies the provider's one-element key list
internally. The Day-0 key/user setup remains separate.

[IBM managed runtime constraints](https://cloud.ibm.com/docs/schematics?topic=schematics-version-constraints),
[Terraform version constraint syntax](https://developer.hashicorp.com/terraform/language/expressions/version-constraints).

The same job's cart preparation reported `No README file is found`, while the
archive contains `root/README.md` beside `root/main.tf`. This warning is separate
from the Core-version failure. Check the Catalog **Edit readme** preview and the
Schematics **Readme** view after reimport; README rendering remains pending.
Keep the single `root/` archive layout while investigating the preview.

### Catalog IAM requirements

Recorded from the configured Software → Terraform version form on **2026-11-06**.
These are declared installation requirements; adding them does not grant IAM
policies. The deployment identity must have the corresponding access.

In **Configure version → Define IAM access**, add the following entries. A dash
means leave that role field unselected. Use **All resources** for this reusable
catalog declaration; scope actual IAM policies to permitted deployment resources.

| Service name in the version form | Service ID | Platform role | Service role |
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

Floating-IP permissions apply when that option is enabled. Image permissions
apply where image use is IAM-controlled; catalog availability and entitlement
must also be checked. Exact component names and built-in role actions are in
[IBM's IAM reference](https://cloud.ibm.com/docs/iam?topic=iam-iam-service-roles-actions).

The default VNI IP-spoofing setting needs the VNI Administrator action; the older
instance IP Spoofing Operator role alone does not cover it. Subnet Editor covers
the subnet-update action used to allocate the VNIs' reserved IPs. See
[VNI creation authorization](https://cloud.ibm.com/apidocs/vpc/latest#create-virtual-network-interface).

#### Access handled outside this version form

- Assign **Catalog Management → Viewer** (`globalcatalog-collection`) on the
  intended private catalog through **Manage → Access (IAM)**. The version form
  labeled this service **Personal Catalog** and offered only Administrator and
  Service Configuration Reader (`ConfigReader`). Omit that declaration rather
  than substituting either role for Viewer. This is an observed form limitation;
  the actual catalog Viewer prerequisite still applies. Follow
  [IBM's catalog-access instructions](https://cloud.ibm.com/docs/account?topic=account-catalog-access).
- Ensure Viewer access on the deployment resource group itself and, for private
  catalog access, its resource group. These groups can differ. Also cover the
  existing VPC, subnet, security-group and SSH-key resources if they are in other
  groups. See [resource-group access](https://cloud.ibm.com/docs/iam?topic=iam-assign-access-resources).
- Keep the selected ASAv Catalog version accessible to the deployment identity;
  customers obtain ASAv BYOL entitlement separately. No separate **Global Catalog**
  (`globalcatalog`) requirement is declared for this package; it uses an existing
  `globalcatalog-collection` version CRN. Reassess if that dependency changes.

Status: **11 declarations configured in the supplied screenshots; effective IAM
and complete deployment/update/destroy validation remain pending for this imported
version.** During validation, identify the actual user/service ID/trusted profile
used by Schematics, or the explicit API-key override if supplied. Retain any denied
actions and their resource scopes; this table is not a proven minimum custom role.

## Release history

```text
tf-releases/
└── asav/
    ├── asav-...tgz
    ├── asav-...sha256
    └── asav-...verification.json
```

New ASAv builds go directly into the product directory. Replace the example stem
with the generated filename and run from `ibm-mp-templates/` to inspect a build:

```bash
ASAV_STEM='asav-ibm-tf-1-0-0-180500-20261105'  # actual filename stem
(
  cd tf-releases/asav
  shasum -a 256 -c "$ASAV_STEM.sha256"
  tar -tzf "$ASAV_STEM.tgz"
)
```

Preserve retained artifact triplets and never overwrite published assets.
Product-folder placement identifies ASAv, not publication or validation status;
the report records a local build. Record release confirmation using the Git
release/tag, source URL and IBM Catalog version. Future products use sibling
`ftdv/` and `fmcv/` folders. Back up superseded unpublished builds outside this
project before cleaning them up. No nested candidate/uploaded folders or upload
ledger are needed.

Keep changelog entries newest first, with increasing unique `major.minor.patch`
versions. Dates accept abbreviated/full English months; use `Changes` or
`Changes:`. Initial format:

```text
######################################################################
2026-Nov-05
version 1.0.0
Changes
Initial TF template creation
######################################################################
```

For each subsequent shipped change, prepend a new dated version/change entry;
freeze released entries and assets. Software package versions are separate from
VSI package and ASAv image versions. Retain the source tag/commit, release URL,
SHA-256 and Partner Center version identifier with your release records, and keep
an external backup of published assets.

## Maintain image versions in one file

Edit [`solutions/asav-ibm-tf/asav-images.json`](solutions/asav-ibm-tf/asav-images.json).
Terraform reads it directly; no generator runs during deployment.

| Change | Exact data edit |
|---|---|
| Add | Add `releases[image_label]` with verified Catalog version/locator, `version_crn`, `catalog_sha256`, nullable `plan_crn`, supported regions/profiles and boolean Secure Boot modes. Change `default_version` only when intended. |
| Remove | Set the default to a retained entry first, then delete the label. Preserve the original package for deployments that still select it. |
| Update | Prefer a new label for a different image CRN. Correct reference metadata from verified facts; do not silently retarget a historical label. |

Then update the changelog for the next release, run checks/build, and review the
imported form's image choices/default. Compatible image-list changes need only
this JSON deployment-data edit; a new NIC, metadata or bootstrap contract needs
additional code/qualification. Region/profile input defaults are separate.

Omitted/null labels follow the packaged default. A default change can select a
new image for unpinned deployments; a removed label fails validation and can block
planning/destroy until the original package or valid reference is restored.
`catalog_sha256` is reference/output metadata, not a downloaded-image hash check.
The builder checks structure, not live availability or entitlement.

## Deploy, update and destroy qualification commands

Use a disposable lab with permitted IAM. These commands create/change/delete
resources when run; they are instructions, not evidence of an executed test.
Use environment authentication (`IC_API_KEY` or `IBMCLOUD_API_KEY`) and the pinned
runtime. Keep guest backups, inputs, plans and state protected.

### Prepare and deploy

From the IBM project directory (`ibm-mp-templates/`):

```bash
ASAV_REPO="$PWD"
umask 077
ASAV_LAB="$(mktemp -d /private/tmp/asav-ibm-tf-lifecycle.XXXXXX)"
cp -R "$ASAV_REPO/solutions/asav-ibm-tf/." "$ASAV_LAB/"
cd "$ASAV_LAB"
terraform version
terraform init -backend=false -lockfile=readonly
```

Create `lab.tfvars` with real existing lab resource IDs and a unique prefix:

```hcl
region                       = "us-east"
resource_group_name          = "REPLACE_RESOURCE_GROUP"
prefix                       = "asav-unique-lab"
vpc_id                       = "REPLACE_VPC_ID"
management_subnet_id         = "REPLACE_MANAGEMENT_SUBNET"
data_subnet_1_id             = "REPLACE_DATA_1_SUBNET"
data_subnet_2_id             = "REPLACE_DATA_2_SUBNET"
management_security_group_id = "REPLACE_MANAGEMENT_SG"
data_security_group_1_id     = "REPLACE_DATA_1_SG"
data_security_group_2_id     = "REPLACE_DATA_2_SG"
ssh_key_id                   = "REPLACE_KEY_ID"
asav_image_version           = "REPLACE_RETAINED_LABEL_FROM_JSON"
```

Customize `day0.txt` for the matching management key/user. `.tfvars` does not
support `file()` calls; pass raw Day-0 through the sensitive variable instead:

```bash
chmod 600 lab.tfvars day0.txt
export TF_VAR_user_data="$(cat day0.txt)"
terraform plan -var-file=lab.tfvars -out=deploy.tfplan
terraform show -no-color deploy.tfplan
terraform apply deploy.tfplan
terraform output
terraform plan -var-file=lab.tfvars -detailed-exitcode
```

Detailed exit code **0** is no change, **2** is changes and **1** is an error.
Check guest version, hostname, SSH/AAA, interfaces and Day-0. Record instance,
boot-volume, VNI, reserved-IP and FIP IDs before cleanup.

### Updates

Review/apply one change at a time. Example tag and management-FIP tests:

```bash
terraform plan -var-file=lab.tfvars \
  -var='tags=["cisco","asav","lifecycle-test"]' -out=tags.tfplan
terraform show -no-color tags.tfplan
terraform apply tags.tfplan
terraform plan -var-file=lab.tfvars \
  -var='create_management_floating_ip=true' -out=fip-on.tfplan
terraform show -no-color fip-on.tfplan
terraform apply fip-on.tfplan
terraform plan -var-file=lab.tfvars \
  -var='create_management_floating_ip=false' -out=fip-off.tfplan
terraform show -no-color fip-off.tfplan
terraform apply fip-off.tfplan
```

Restrict management SG access before enabling a FIP. Confirm FIP-only updates
retain the VSI ID. Command-line overrides are temporary; persist intended final
values in the inputs before checking for drift.

For profile, image or Day-0 changes, edit one input and review a saved plan before
applying. Use only currently supported labels/profiles; a second-image test needs
a real qualified JSON entry. Catalog image/Day-0 changes replace the VSI with the
pinned provider. Record identity changes, downtime, guest configuration/recovery
and volume/VNI/FIP cleanup. Retain the same workspace/state throughout.

### Destroy and verify

Remove customer routes that depend on the firewall. Retain the matching source,
credentials and variables; restore the original package if its selected label
was removed.

```bash
terraform plan -destroy -var-file=lab.tfvars -out=destroy.tfplan
terraform show -no-color destroy.tfplan
terraform apply destroy.tfplan
terraform state list
unset TF_VAR_user_data
```

Reconcile recorded IDs against the IBM API; existing networks must remain.
Authentication/permission errors are not proof of deletion. Repeat VNI/private-IP
checks for all three interfaces and FIP checks only when one was created:

```bash
ibmcloud is instance REPLACE_INSTANCE_ID
ibmcloud is volume REPLACE_BOOT_VOLUME_ID
ibmcloud is virtual-network-interface REPLACE_VNI_ID
ibmcloud is subnet-reserved-ip REPLACE_SUBNET_ID REPLACE_RESERVED_IP_ID
ibmcloud is floating-ip REPLACE_FIP_ID
```

Keep state/workspace until no managed resources remain and inventory is confirmed.
Data-source state records can remain after destroy.

### Imported version and customer path

Use the imported version's **Validate** workflow and inspect its logs. Confirm
actual runtime/provider, identity, rendered inputs, guest readiness and cleanup.
Then verify selected-recipient discovery/access and installation. Read-only aids:

```bash
ibmcloud schematics version
ibmcloud schematics workspace get --id REPLACE_WORKSPACE_ID --output JSON
```

For private source, test fresh installs and revalidation/update after expiry or
rotation using dedicated test credentials. Record when source fetches occur and
how access is restored; do not assume import makes a PAT permanently unnecessary.
Keep repository tokens out of Terraform inputs and user-data.

### Evidence boundaries

Source boot/no-change/destroy tests and mocked tests do not qualify every managed
update, failure recovery, image-managed key injection, omitted-Day-0 path or
region/profile combination. Full forwarding/NAT/policy and throughput need
topology-specific tests. HA and four/five NICs are outside this package.
Additional engineering checks are separate from IBM's onboarding requirements;
record the actual release coverage without claiming unperformed tests.
