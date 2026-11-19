"""Synthetic local-test references ONLY; never deploy or publish these fixtures."""
import copy
import json
import re


def install_fixture(module, product, *, alternate=False):
    path = module / (product + "-images.json")
    catalog = json.loads(path.read_text())
    text = (module / "locals.tf").read_text()
    cid = re.search(rf'{product}_catalog_id\s*=\s*"([^"]+)"', text)[1]
    oid = re.search(rf'{product}_catalog_offering_id\s*=\s*"([^"]+)"', text)[1]
    vid = "11111111-1111-4111-8111-111111111111-global"
    for entry in catalog["releases"].values():
        entry.update(
            version_crn=f"crn:v1:bluemix:public:globalcatalog-collection:global::{cid}:version:{oid}/{vid}",
            catalog_version_locator=cid + "." + vid,
            catalog_reference_verified=True,
            reference_access_scope="public",
        )
    if alternate:
        entry = copy.deepcopy(catalog["releases"][catalog["default_version"]])
        alt_vid = "22222222-2222-4222-8222-222222222222-global"
        entry.update(
            version_crn=f"crn:v1:bluemix:public:globalcatalog-collection:global::{cid}:version:{oid}/{alt_vid}",
            catalog_version_locator=cid + "." + alt_vid,
        )
        catalog["releases"]["__mock_alternate__"] = entry
    path.write_text(json.dumps(catalog, indent=2) + "\n")
