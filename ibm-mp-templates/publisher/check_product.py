#!/usr/bin/env python3
"""Isolated Terraform checks: mocks only; no cloud resources or authentication."""
import argparse,json,os,re,shutil,subprocess,tarfile,tempfile
from pathlib import Path
from package_product import build
from tests.fixture_catalog import install_fixture

def main(product=None):
    parser=argparse.ArgumentParser(description=__doc__)
    if product is None: parser.add_argument("product",choices=("ftdv","fmcv"))
    parser.add_argument("--terraform",default="terraform")
    parser.add_argument("--work-dir",type=Path,help="New evidence directory outside the repository")
    args=parser.parse_args(); product=product or args.product
    project=Path(__file__).resolve().parents[1]
    source=project/"solutions"/(product+"-ibm-tf")
    work=args.work_dir.resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix=product+"-tf-check-"))
    if work.is_relative_to(project.parent):
        parser.error("Evidence must stay outside the repository")
    work.mkdir(parents=True,exist_ok=True)
    if list(work.iterdir()): parser.error("Evidence directory must be empty")
    env=dict(os.environ,CHECKPOINT_DISABLE="1",TF_IN_AUTOMATION="1")
    # No inherited cloud secrets are needed by mock tests.
    for key in list(env):
        if key.startswith(("IC_","IBMCLOUD_","IAM_","TF_VAR_")): env.pop(key)
    results=[]
    def command(label,*args):
        result=subprocess.run([args_tf,*args],cwd=module,env=env,capture_output=True,text=True)
        output=result.stdout+result.stderr
        (work/(label+".log")).write_text(output)
        item={"check":label,"exit_code":result.returncode}
        match=re.search(r"(\d+) passed, (\d+) failed",output)
        if match: item.update(passed=int(match[1]),failed=int(match[2]))
        results.append(item)
        (work/"checks.json").write_text(json.dumps({"product":product,"results":results,"fixture_scope":"Synthetic public reference is installed only in the temporary mock-test copy; no live Catalog/guest/lifecycle qualification."},indent=2)+"\n")
        print(label+": "+("PASS" if result.returncode==0 else "FAIL"),flush=True)
        if result.returncode: print(output); raise SystemExit(result.returncode)
    args_tf=args.terraform
    archive,_,_=build(source,work/"package",product=product,draft=True)
    module=work/"extracted"/"root"; module.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        for entry in tar.getmembers():
            if entry.isfile():
                target=module/Path(entry.name).relative_to("root")
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(tar.extractfile(entry).read())
    tests=module/"tests";tests.mkdir()
    shutil.copyfile(project/"publisher/tests"/(product+"-publication-gate.tftest.hcl"),tests/"gate.tftest.hcl")
    command("fmt","fmt","-check","-recursive","-no-color")
    # Learn verified platform checksums only in this isolated extracted copy.
    command("init","init","-backend=false","-input=false","-no-color")
    command("validate","validate","-json")
    catalog=json.loads((module/(product+"-images.json")).read_text())
    # Exercise the guard even after real references have been filled. Only the
    # isolated temporary copy is made unverified for this negative test.
    pending=json.loads(json.dumps(catalog))
    for entry in pending["releases"].values():
        entry.update(catalog_reference_verified=False,reference_access_scope="unverified",version_crn=None,catalog_version_locator=None)
    (module/(product+"-images.json")).write_text(json.dumps(pending,indent=2)+"\n")
    command("publication-gate","test","-no-color")
    (tests/"gate.tftest.hcl").unlink()
    install_fixture(module,product,alternate=True)
    shutil.copyfile(project/"publisher/tests"/(product+".tftest.hcl"),tests/"product.tftest.hcl")
    command("mock-tests","test","-no-color")
    print("Evidence: "+str(work/"checks.json"))
    return 0

if __name__=="__main__": raise SystemExit(main())
