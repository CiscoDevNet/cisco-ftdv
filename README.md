# Cisco Secure Firewall IBM Cloud Marketplace Templates

This branch is dedicated to maintaining Cisco Secure Firewall Terraform templates and release packages for IBM Cloud Marketplace using the **Software → Terraform** delivery method. IBM templates are maintained on `cisco-secure-firewall-ibm-marketplace` independently of the repository's `master` branch.

## IBM Cloud Terraform Packages

The IBM project is contained in `ibm-mp-templates/`:

* `publisher/` contains package-building and local validation tools.
* `solutions/` contains customer deployment templates and documentation.
* `tf-releases/` contains generated deployment archives and release artifacts.

ASAv is currently included. FTDv and FMCv packages can be added later. See the IBM project README for package details and the publisher guide for build and release commands.

### Resources

* IBM project: [Code](ibm-mp-templates/)     |     [README](ibm-mp-templates/README.md)     |     [Packaging and Lifecycle Guide](ibm-mp-templates/SOFTWARE-TERRAFORM-PACKAGING.md)
* ASAv: [Code](ibm-mp-templates/solutions/asav-ibm-tf/)     |     [Deployment Guide](ibm-mp-templates/solutions/asav-ibm-tf/README.md)

## Contributions and Repository Notices

See the [Contributing Guide](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), [License](LICENSE) and [Notice](NOTICE).
