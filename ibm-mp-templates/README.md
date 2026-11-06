# Cisco Secure Firewall Terraform packages for IBM Cloud

This directory contains the IBM Cloud Marketplace Terraform project: customer solutions, publisher tools and release artifacts. It currently includes ASAv; future FTDv and FMCv packages can use sibling solution and release directories.

## ASAv deployment package

Deploy one three-interface ASAv into an existing IBM Cloud VPC using a Cisco VSI Catalog image. Customers obtain ASAv BYOL entitlement separately.

Terraform creates the VSI, boot volume, three virtual network interfaces and an optional management floating IP. Existing resource groups, VPCs, subnets, security groups and SSH keys are reused. Customer routes and guest firewall policy are managed separately.

The customer module is `solutions/asav-ibm-tf/`. Terraform must satisfy `>= 1.13.4, < 1.14.0`; the IBM provider is pinned to `2.4.0`. Select the `1.13` runtime series in the Catalog version settings and verify the managed patch in the validation logs.

Provide one existing regional SSH-key registration through the required `ssh_key_id` string input. Configure guest SSH access separately using the module's Day-0 guidance.

### Resources

* ASAv: [Deployment Guide](solutions/asav-ibm-tf/README.md)     |     [Architecture Diagram](solutions/asav-ibm-tf/docs/asav-existing-vpc.png)     |     [Routing Guide](solutions/asav-ibm-tf/docs/routing-guide.md)
* Configuration: [Day-0 Example](solutions/asav-ibm-tf/bootstrap/asav-day0.example.txt)     |     [Image Versions](solutions/asav-ibm-tf/asav-images.json)     |     [Changelog](solutions/asav-ibm-tf/changelog.txt)

## Building release packages

Run from this directory, `ibm-mp-templates/`, using Python 3.9+:

```bash
python3 publisher/package_asav.py
```

The builder reads the module's `changelog.txt` and writes a `.tgz`, SHA-256 checksum and verification report directly into `tf-releases/asav/`. The archive contains one `root/` folder holding the 14 customer files, with `README.md` beside `main.tf`. Publisher tools and the repository/project overview READMEs stay outside the deployment archive.

The verification report uses a project-relative source path and archive filename. Product-folder placement identifies the product; release confirmation is recorded separately through the Git release/tag and IBM Catalog version.

### Resources

* Publishing: [Packaging and Lifecycle Guide](SOFTWARE-TERRAFORM-PACKAGING.md)     |     [Catalog IAM Setup](SOFTWARE-TERRAFORM-PACKAGING.md#catalog-iam-requirements)     |     [ASAv Release Artifacts](tf-releases/asav/)

The publisher guide contains validation, custom-filename, image-maintenance and release commands. The ASAv deployment guide contains the customer installation, update and removal instructions.
