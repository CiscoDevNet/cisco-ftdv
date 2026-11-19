# FMCv operations guide

## Network ownership

The module never changes customer routes, SG rules, ACLs, gateways or shared subnets. Optional public management targets the management VNI (eth0) only. Maintain a private/VPN path when public management is off. Check metadata, DNS, NTP, licensing and management egress before first boot.

## Central management

Configure the FMC management hostname/address, licensed capacity, administrator roles, backups and event retention. Add devices through an approved workflow and confirm policy deployment. This package performs no registration or FMC API automation.

## Reserved-IP verification

The primary reserved IP is allocated automatically with each VNI, following the ASAv baseline. Verify its actual `auto_delete` value through the subnet reserved-IP API and confirm its absence after destroy. IBM provider 2.4.0 can refresh the nested VNI `primary_ip.auto_delete` field as false even when the reserved-IP API reports true; explicitly configuring that nested flag causes a persistent plan difference. The module therefore omits that override. The standalone VNI remains explicitly managed by Terraform (`auto_delete=false`), and its reserved IP must disappear when that VNI is destroyed.

## Initial access when Day-0 is omitted

Allow initialization to finish, then connect as `admin` using the registered SSH key and set a strong CLI password when prompted. The web-admin account is separate. Cisco documents the supported `expert` / `sudo usertool.pl -p` procedure for setting its password in [Reset a Lost Web Interface Admin Password](https://www.cisco.com/c/en/us/support/docs/security/firesight-management-center/118631-technote-firesight-00.html). Use your own protected password; then verify HTTPS login independently. Supplying `AdminPassword` and `Hostname` in Day-0 is the tested unattended bootstrap path.
