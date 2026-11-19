# FTDv operations guide

## Network ownership

The module never changes customer routes, SG rules, ACLs, gateways or shared subnets. Optional public management targets the management VNI (eth2) only. Maintain a private/VPN path when public management is off. Check metadata, DNS, NTP, licensing and management egress before first boot. Initial FTDv metadata requests may traverse a data NIC before management is configured: prepare TCP 80 egress to 169.254.169.254/32 in all selected SGs/ACL paths unless a narrower image-specific path has been qualified.

## Transit routing

`route_next_hops` supplies the private addresses of data-1, data-2 and data-3 for a separately reviewed routing design. Configure FTDv interface addresses/zones, routing, policy and NAT first. Avoid routing management/bootstrap traffic through an unconfigured firewall. Ensure return paths are symmetric; inspect SGs, ACLs and protocol state filtering. IP spoofing alone does not enable forwarding. Test controlled bidirectional traffic before changing production routes.

## Reserved-IP verification

The primary reserved IP is allocated automatically with each VNI, following the ASAv baseline. Verify its actual `auto_delete` value through the subnet reserved-IP API and confirm its absence after destroy. IBM provider 2.4.0 can refresh the nested VNI `primary_ip.auto_delete` field as false even when the reserved-IP API reports true; explicitly configuring that nested flag causes a persistent plan difference. The module therefore omits that override. The standalone VNI remains explicitly managed by Terraform (`auto_delete=false`), and its reserved IP must disappear when that VNI is destroyed.
