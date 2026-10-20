# FTDv Python Autoscale for Azure

This directory contains the Azure Python autoscale implementation for Cisco FTDv.

## Layout

```text
autoscale/azure/
├── arm-templates/
├── function-app/
├── logic-app/
├── README.md
└── make.py
```

## Build

Run the package builder from this directory:

```bash
python3 make.py build
```

The build creates `target/` with:

```text
target/
├── arm-templates/
├── autoscale_function.zip
└── logic_app.txt
```

`autoscale_function.zip` is the Azure Functions package. The ARM templates in
`arm-templates/` deploy the autoscale infrastructure, including the Function App,
Logic App, load balancers, VMSS, and related networking resources.

The build uses a temporary staging directory while installing Python
dependencies. It does not leave a `target/package/` directory behind.

## Interface Layout

The ARM templates expose `numberOfInterfaces`, `diagnostic`, and ten subnet
fields.

For GWLB templates, `numberOfInterfaces` defaults to `3`, with a minimum of `3`
and a maximum of `10`:

```text
subnet1 = management
subnet2 = diagnostic slot / NIC 2
subnet3 = outside/data / NIC 3
```

For NLB templates, `numberOfInterfaces` defaults to `4`, with a minimum of `3`
and a maximum of `10`:

```text
subnet1 = management
subnet2 = diagnostic slot / NIC 2 (not used when numberOfInterfaces = 3)
subnet3 = inside / NIC 3 (NIC 2 when numberOfInterfaces = 3)
subnet4 = outside / NIC 4 (NIC 3 when numberOfInterfaces = 3)
```

When `numberOfInterfaces` is `3`, no diagnostic NIC is created and `subnet2` is
not used; NLB uses NIC1 management, NIC2 inside, and NIC3 outside.

Additional subnet fields are optional additional data-interface subnets and are
used only when `numberOfInterfaces` is high enough to require them. For example,
GWLB with `numberOfInterfaces=5` requires `subnet4` and `subnet5`; NLB with
`numberOfInterfaces=5` requires `subnet5`.

`diagnostic` accepts `ON` or `OFF` and defaults to `OFF`. It controls the
diagnostic value written to FTDv day0 custom data. `ON` enables the diagnostic
slot on subnet2/NIC2. `OFF` leaves diagnostic disabled and data traffic starts
from subnet3/NIC3.

FTDv 10.0.0 and later images can use the default three-interface deployment.
For older FTDv images that require at least four VM interfaces, set
`numberOfInterfaces` to `4` or higher and provide the corresponding optional
subnet values.

Set `registrationUsingPublicFMCIP` to `YES` when `fmcIpAddress` is the FMC public
IP. In that mode the functions configure FTD manager registration with that FMC
IP, register FTDs in FMC by their public management IP, and allow the FMC public
IP in the FTD management NSG.

Use `performanceTier` to select the FMC registration performance tier, such as
`FTDv30`, `FTDv50`, or `FTDvU`. This is separate from `licenseCapability`, which
controls license capabilities such as `BASE`, `MALWARE`, `URLFilter`, and
`THREAT`.

## Clean

```bash
python3 make.py clean
```

## License

This project is licensed under the Apache License, Version 2.0. See
[`LICENSE`](../../../LICENSE) for details.
