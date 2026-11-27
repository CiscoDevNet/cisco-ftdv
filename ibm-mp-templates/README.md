# Cisco Secure Firewall Terraform packages for IBM Cloud

Independent **Software → Terraform** packages reuse existing resource groups, VPCs, subnets, security groups and one regional SSH-key registration. Each creates one appliance, its boot volume and native virtual network interfaces, with an optional management floating IP. Customers obtain applicable BYOL entitlements separately; customer routes and guest policy remain separate.

| Product | Customer deployment guide | Fixed interface layout |
|---|---|---|
| ASAv | [asav-ibm-tf](solutions/asav-ibm-tf/README.md) | Management eth0; data eth1/eth2 |
| FTDv | [ftdv-ibm-tf](solutions/ftdv-ibm-tf/README.md) | Data eth0/eth1/eth3; management eth2; Diagnostic OFF |
| FMCv | [fmcv-ibm-tf](solutions/fmcv-ibm-tf/README.md) | One management NIC, eth0 |

Check each module's `version.tf` for its Terraform and IBM provider requirements. Select a compatible runtime series in Catalog and verify the managed patch in the validation logs. Set a deployment-unique `resource_name_prefix` and provide one `ssh_key_id` string. Existing Terraform callers can use `prefix` as a compatibility alias. ASAv accepts raw ASA Day-0 text. FTDv and FMCv accept optional sensitive raw JSON. FTDv JSON can include image-supported FMC registration fields, with device addition handled on FMC.

See [publisher tools and qualification coverage](publisher/README.md). Each module's changelog records package versions, and its image metadata records the supported VSI images.

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
