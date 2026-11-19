# Cisco Secure Firewall IBM Cloud Marketplace Templates

This branch maintains Cisco Secure Firewall Terraform templates and release packages for IBM Cloud Marketplace using **Software → Terraform**. Changes are developed against `cisco-secure-firewall-ibm-marketplace`, independently of the repository's `master` branch.

## IBM Cloud Terraform Packages

The IBM project is contained in `ibm-mp-templates/`:

* `publisher/` contains package builders, isolated validation tools and tests.
* `solutions/` contains customer deployment templates and documentation.
* `tf-releases/` contains deployment archives and their checksums/verification reports, organized by product.

ASAv, FTDv and FMCv use existing customer infrastructure and optional public management. They are separate deployment packages; the FTDv package does not create an FMCv. Source qualification and IBM Catalog approval are separate steps.

### Resources

* IBM project: [Code](ibm-mp-templates/) | [README](ibm-mp-templates/README.md) | [Packaging and Lifecycle Guide](ibm-mp-templates/SOFTWARE-TERRAFORM-PACKAGING.md)
* ASAv: [Code](ibm-mp-templates/solutions/asav-ibm-tf/) | [Deployment Guide](ibm-mp-templates/solutions/asav-ibm-tf/README.md)
* FTDv: [Code](ibm-mp-templates/solutions/ftdv-ibm-tf/) | [Deployment Guide](ibm-mp-templates/solutions/ftdv-ibm-tf/README.md)
* FMCv: [Code](ibm-mp-templates/solutions/fmcv-ibm-tf/) | [Deployment Guide](ibm-mp-templates/solutions/fmcv-ibm-tf/README.md)

## Contributions and Repository Notices

See the [Contributing Guide](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), [License](LICENSE) and [Notice](NOTICE).
