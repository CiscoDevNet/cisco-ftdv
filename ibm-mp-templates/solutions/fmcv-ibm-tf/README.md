# Cisco Secure Firewall Management Center Virtual — existing VPC

Deploy one single-interface FMCv from an exact Cisco VSI Catalog version into an existing IBM Cloud VPC. Obtain BYOL entitlement and eligible Cisco support separately.

**Qualification snapshot, 18 November 2026:** exact hidden VSI package 10.11.1 was consumed successfully in `us-east-1` and `us-south-1` using `bx3d-8x40`. Guest version: 10.1.1 Build 1. Management access and FTDv registration/policy deployment were verified. The backing offering currently requires selected-account access. Other image/profile/region combinations and Partner Center validation are separate qualification steps.

Initial package/listing version: **10.11.1**, aligned with the VSI package. The selector label **10.1.1.1** follows the backing image label; use that label for `fmcv_image_version`, not the package version. Guest-reported build and image label must be checked separately.

![FMCv architecture](docs/fmcv-existing-vpc.png)

| IBM interface | Intended guest role |
|---|---|
| eth0 (primary) | Management |

FMCv is a management appliance. It has one management NIC and does not serve as a transit firewall. Deploy managed FTDv firewalls separately.

## Before you begin

Prepare an existing resource group, VPC, one subnet ID and one SG selection, and one regional VPC SSH-key registration. All subnets must be in the same VPC/zone. SGs can be reused where appropriate. Check quota, subnet free IPs, image access and profile availability. Use a unique `prefix` (1–35 lowercase letters, digits or hyphens, starting with a letter; no consecutive/trailing hyphens). No random suffix is added.

### IAM and authentication

The deployment identity needs access to read the resource group, existing VPC/subnets/SGs/key/profiles and selected Catalog version, and to create/update/delete the VSI, boot volume, VNIs and optional floating IP. For Catalog deployment it also needs the applicable Schematics and Instance Management access. Scope permissions to the intended resources. This module creates no IAM policy.

The management VNI uses IP spoofing false, protocol state filtering auto and infrastructure NAT enabled. No forwarding variables or route-next-hop outputs are exposed.

Use provider runtime/environment credentials (local `IC_API_KEY` or `IBMCLOUD_API_KEY`); `ibmcloud_api_key` is an optional sensitive override. Keep credentials out of Git and variable files you publish. See [IBM provider authentication](https://cloud.ibm.com/docs/ibm-cloud-provider-for-terraform?topic=ibm-cloud-provider-for-terraform-provider-reference).

### Day-0 and first access

`user_data` accepts an optional raw JSON **object**, not Base64 or a JSON-encoded string. Null/blank omits it. Customize [the example](bootstrap/fmcv-day0.example.json); replace placeholders before use. It is a schema example, not a complete secure appliance configuration. No shared password is supplied.

Customize the image-supported JSON, for example `AdminPassword` and `Hostname`. For unattended bootstrap, supply a strong `AdminPassword` and your hostname in Day-0. If Day-0 is absent, the qualified image accepts the registered SSH key but requires interactive CLI password setup. Its web-admin account is separate; complete web access using the image-supported setup procedure. See [Cisco's documented web-admin password procedure](https://www.cisco.com/c/en/us/support/docs/security/firesight-management-center/118631-technote-firesight-00.html). Do not assume a CLI password change updates the web account. The module does not configure FMC licensing, add managed devices or push policy. Before adding FTDv devices, initialize the applicable Smart Licensing or evaluation mode in FMC; a running FMC alone is insufficient for registration.

Selecting `ssh_key_id` supplies one IBM key registration to the VSI; guest SSH behavior remains image-specific. Do not assume that this alone configures a guest account. `user_data` is sensitive in Terraform but secrets may remain in state. Protect workspace/state access.

This image baseline uses metadata enabled over **HTTP**, response hop limit 1. Before first boot, allow outbound TCP 80 from the management interface to `169.254.169.254/32`. A missing metadata path can prevent first-boot configuration; reboot is not a reliable bootstrap retry. Restrict inbound SSH (22) and HTTPS (443) to approved sources as needed. The template does not add SG/ACL rules; a floating IP alone does not enable guest login. Allow the FMC–FTDv management connection between their management addresses (default TCP 8305; see [Cisco registration prerequisites](https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/215540-configure-verify-and-troubleshoot-firep.html)). Provide routes and SG/ACL access to your chosen DNS/NTP servers and the Cisco HTTPS licensing/update endpoints required by enabled features.

### Image and runtime choices

[fmcv-images.json](fmcv-images.json) is the single release catalog. Null `fmcv_image_version` uses its default; an explicit retained label pins an image. Its region/profile/firmware lists are compatibility declarations, not proof that every combination was guest-tested. Planning also checks live profile NIC capacity, zone and Secure Boot support. Defaults: `region="us-east"`, `instance_profile="bx3d-8x40"`, `enable_secure_boot=false`, private management. Washington profile check (13 November 2026): the third-generation entries were available; the fourth-generation entries were unavailable there. Other regions/zones must be checked live.

Initial minimum boot volume: **250 GB**, inherited from the selected image; no extra data volume is created.

Use Terraform **>=1.13.4, <1.14.0** and IBM provider **2.4.0**. In Catalog select runtime series **1.13**; Schematics selects its patch. `TF_VERSION` is compatibility metadata, not an executable selector. See [variables.tf](variables.tf) for the complete schema.

## Required resources

Existing: resource group, VPC, one subnet ID and one SG selection, and one **string** `ssh_key_id` (no array brackets). Owned: one VSI/boot volume, one VNI with its primary reserved IP, and optionally one management floating IP. Existing VPCs, subnets, SGs, ACLs, keys, gateways and route tables are read only and survive destruction.

## Installing the software

1. Select the reviewed Software/Terraform version and configure its workspace/identity.
2. Supply existing-resource IDs, a unique prefix, compatible profile/image and optional customized Day-0.
3. Review the plan and cost estimate. Apply only after image access and prerequisites are verified.
4. Allow first-boot initialization to finish before testing login. In the initial qualification, FMCv took about 26 minutes to expose SSH/HTTPS; allow at least 30 minutes before diagnosing slow startup. Check instance health, management access, `show version`, actual interface roles and first-boot logs. Confirm the requested hostname/configuration and image build.
5. Configure licensing, management/policy and backups. Read [the operations guide](docs/operations-guide.md). Running status alone does not establish appliance readiness.

For local use, keep input files/state outside the module. Example inputs (replace every placeholder):

```hcl
resource_group_name = "REPLACE_EXISTING_RG_NAME"
vpc_id = "REPLACE_VPC_ID"
region = "us-east"
prefix = "fmcv-unique-deployment"
management_subnet_id = "REPLACE_MGMT_SUBNET_ID"
management_security_group_id = "REPLACE_MGMT_SG_ID"
ssh_key_id = "REPLACE_REGIONAL_KEY_ID"
```

```sh
terraform init
terraform plan -var-file=/secure/path/deployment.tfvars -out=/secure/path/deployment.tfplan
terraform apply /secure/path/deployment.tfplan
terraform output
```

### Production configuration

This package is a single appliance, without HA, autoscaling, multi-zone failover or automatic policy registration. Establish monitoring, backup/recovery, licensing, guest hardening and a management path. Add devices, configure policies and protect management access separately. Size for the supported device/event capacity of the chosen image/profile. Keep the same backend, state, inputs and source version for later operations.

Outputs include identity/status, zone, selected image metadata, interface map and management IPs, plus an HTTPS URL only when public management is enabled. See [outputs.tf](outputs.tf).

## Upgrading to a new version

**Initial qualified scope:** deployment, management access, device registration/policy deployment, no-op/tag/floating-IP updates and destruction. FMCv VSI replacement, image migration and backup/restore recovery are explicitly outside this release's qualified scope. The following change-impact guidance is not evidence that those recovery operations have been qualified.

See [changelog.txt](changelog.txt). Adopt new source in the existing workspace/state and inspect the plan. Package version and guest software upgrade are separate. Null image input follows the new packaged default; retain an explicit label to pin an image. Do not retarget an existing label silently.

The pinned provider marks Catalog version and user-data changes for VSI replacement; subnet/VNI changes can replace resources, and profile changes can interrupt service. Preserve configuration/licensing/backups and schedule a maintenance window. No automatic rollback or zero-downtime upgrade is provided. Keep the original archive and a valid image reference for recovery and destroy.

## Uninstalling the software

Preserve backups and consider managed-device dependencies before removal. Use the original workspace/backend and inputs:

```sh
terraform plan -destroy -var-file=/secure/path/deployment.tfvars -out=/secure/path/destroy.tfplan
terraform apply /secure/path/destroy.tfplan
terraform state list
```

Expected owned resources are removed, including the boot volume, optional FIP, standalone VNIs and their reserved IPs. Confirm this in the target region and check for billable remnants after errors; do not delete shared resources. Never discard state to resolve a failed destroy. Repeat the cleanup verification when qualifying a new package version.

## Support

Use your Cisco support entitlement for appliance software and IBM Cloud support for infrastructure/Schematics. See [Cisco FMCv documentation](https://www.cisco.com/c/en/us/support/security/defense-center-virtual-appliance/series.html). Include sanitized version, image reference and deployment diagnostics; never send secrets or private keys.

## Source license

These Terraform deployment templates are licensed under Apache License 2.0. The deployment archive includes the repository's `LICENSE` and `NOTICE` files. Cisco appliance software images, BYOL entitlements and support remain subject to their applicable Cisco terms; the template source license does not change those terms.
