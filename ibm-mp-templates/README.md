# Cisco Secure Firewall Terraform packages for IBM Cloud

Independent **Software → Terraform** packages reuse existing resource groups, VPCs, subnets, security groups and one regional SSH-key registration. Each creates one appliance, its boot volume and native virtual network interfaces, with an optional management floating IP. Customers obtain applicable BYOL entitlements separately; customer routes and guest policy remain separate.

| Product | Customer deployment guide | Fixed interface layout | Initial package / image label |
|---|---|---|---|
| ASAv | [asav-ibm-tf](solutions/asav-ibm-tf/README.md) | Management eth0; data eth1/eth2 | 9.2410.1 / 9.24.10.1 |
| FTDv | [ftdv-ibm-tf](solutions/ftdv-ibm-tf/README.md) | Data eth0/eth1/eth3; management eth2; Diagnostic OFF | 10.11.1 / 10.1.1.1 |
| FMCv | [fmcv-ibm-tf](solutions/fmcv-ibm-tf/README.md) | One management NIC, eth0 | 10.11.1 / 10.1.1.1 |

All packages require Terraform **>= 1.13.4, < 1.14.0** and IBM provider **2.4.0**. Select runtime series **1.13** in Catalog and verify the managed patch in validation logs. Provide a customer-unique prefix and one required `ssh_key_id` string. Guest SSH/bootstrap remains product-specific: ASAv accepts raw ASA Day-0 text; FTDv/FMCv accept optional sensitive raw JSON. FTDv JSON may optionally include image-supported FMC registration fields; manager-side device addition remains separate.

FTDv/FMCv source qualification on 18 November 2026 covered Washington/Dallas with default profiles, management, registration/policy, controlled traffic, selected lifecycle operations and complete cleanup. Their backing VSI versions currently require selected-account access. Other combinations and each final archive's Partner Center validation require separate verification. See [publisher tools and coverage](publisher/README.md).

**Pending ASAv Catalog update:** a fresh 16-file ASAv candidate has been generated with the README and legal-file updates. Its import and exact-archive Partner Center validation remain pending. The historical submitted TGZ/checksum/report are preserved unchanged; the local build does not update the existing Catalog version. See the [ASAv candidate status](publisher/README.md#asav-candidate-and-pending-catalog-update).

## Building release packages

Run from this directory using Python 3.9+:

```sh
python3 publisher/package_asav.py
python3 publisher/package_ftdv.py
python3 publisher/package_fmcv.py
```

Each builder selects the topmost dated version in the module's `changelog.txt`, validates the newest-first history and writes a TGZ, SHA-256 checksum and verification report directly into `tf-releases/PRODUCT/`. New archives contain one `root/` folder and exactly 16 files: 14 module files plus byte-identical copies of the repository-root `LICENSE` and `NOTICE`, with `README.md` beside `main.tf`. Publisher tools, tests, plans, state and local evidence stay outside the customer archive.

```text
publisher/                  # builders, check runners, tests and Catalog helper
solutions/asav-ibm-tf/       # ASAv customer files
solutions/ftdv-ibm-tf/       # FTDv customer files
solutions/fmcv-ibm-tf/       # FMCv customer files
tf-releases/asav/            # retained ASAv artifact triplets
tf-releases/ftdv/            # FTDv artifact triplets
tf-releases/fmcv/            # FMCv artifact triplets
```

See [packaging and lifecycle commands](SOFTWARE-TERRAFORM-PACKAGING.md) and [Catalog IAM requirements](SOFTWARE-TERRAFORM-PACKAGING.md#catalog-iam-requirements). An artifact's directory or filename does not establish IBM validation or publication. Keep private operational evidence and credentials outside this repository.
