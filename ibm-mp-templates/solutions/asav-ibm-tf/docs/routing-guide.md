# Post-deployment routing

This Terraform module does not create or modify VPC route tables or routes. Routing depends on the customer topology, return path, and ASAv policy.

After deployment, use:

```text
terraform output interface_map
terraform output route_next_hops
```

| Output | ASAv interface | Customer-defined use |
|---|---|---|
| `route_next_hops.data_1` | `GigabitEthernet0/0` | Data-1 next hop |
| `route_next_hops.data_2` | `GigabitEthernet0/1` | Data-2 next hop |

Before adding a route:

1. confirm `Management0/0`, `GigabitEthernet0/0`, and `GigabitEthernet0/1` are operational after initial boot or any restart;
2. identify the source subnet and its attached route table;
3. use the narrowest approved destination CIDR;
4. choose the ASAv next hop reachable from that source subnet;
5. verify the reverse route;
6. verify security groups, ACLs, ASAv access policy, NAT, and routing in both directions;
7. record the rollback route and maintenance window.

Do not begin with a shared `0.0.0.0/0` route. Validate symmetric forwarding with a limited test destination first.

With the default inputs, all three VNIs allow IP spoofing and have protocol state filtering disabled. `enable_infrastructure_nat = true` is an IBM VPC attachment property; it does not create an ASAv NAT rule, public gateway, floating IP, or route.

References:

- [IBM VPC custom routes](https://cloud.ibm.com/docs/vpc?topic=vpc-about-custom-routes)
- [Create an IBM VPC route](https://cloud.ibm.com/docs/vpc?topic=vpc-create-vpc-route)
- [IBM VPC IP spoofing](https://cloud.ibm.com/docs/vpc?topic=vpc-ip-spoofing-about)
- [Cisco ASA 9.24 routing](https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config/route-overview.html)
- [Cisco ASA 9.24 firewall, ACL, and NAT](https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config.html)
