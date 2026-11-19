import importlib.util,json,sys,shutil,subprocess,tarfile,tempfile,unittest
from unittest import mock
from datetime import datetime,timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import package_product
from package_product import build,check_source,files_for,archive_files_for,read_latest_changelog
from tests.fixture_catalog import install_fixture
PROJECT=Path(__file__).resolve().parents[2]

class ProductPackages(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="cisco-products-package-test-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
    def source(self,p):
        dest=self.root/p
        shutil.copytree(PROJECT/"solutions"/(p+"-ibm-tf"),dest)
        (dest/"changelog.txt").write_text("2026-Nov-13\nversion 1.2.3\nChanges\nControlled package-test fixture\n")
        return dest
    def pending_source(self, product):
        source=self.source(product)
        path=source/(product+"-images.json");data=json.loads(path.read_text())
        for entry in data["releases"].values():
            entry.update(catalog_reference_verified=False,reference_access_scope="unverified",version_crn=None,catalog_version_locator=None)
        path.write_text(json.dumps(data,indent=2)+"\n")
        return source
    def test_pending_blocks_release_both_products(self):
        for p in ("ftdv","fmcv"):
            with self.subTest(product=p),self.assertRaisesRegex(ValueError,"Catalog VSI version reference pending"):
                build(self.pending_source(p),self.root/"out",product=p)
    def test_draft_manifest_and_exact_payload_both_products(self):
        for p in ("ftdv","fmcv"):
            with self.subTest(product=p):
                archive,sha,report=build(self.pending_source(p),self.root/p/"../out"/p,product=p,draft=True)
                self.assertTrue(archive.name.startswith("DRAFT-"))
                data=json.loads(report.read_text())
                self.assertEqual(data["status"],"DRAFT_NOT_FOR_IBM_IMPORT")
                self.assertFalse(data["catalog_references_verified"])
                self.assertEqual(len(data["files_sha256"]),16)
                with tarfile.open(archive) as tar:
                    self.assertEqual([x.name for x in tar.getmembers()],["root"]+["root/"+x for x in sorted(archive_files_for(p))])
                    self.assertEqual(tar.extractfile("root/README.md").read(),(self.root/p/"README.md").read_bytes())
    def test_verified_fixture_reproducible_bytes(self):
        for p in ("ftdv","fmcv"):
            with self.subTest(product=p):
                source=self.source(p);install_fixture(source,p)
                kwargs=dict(product=p,build_time=datetime(2026,11,13,10,11,12,tzinfo=timezone.utc))
                a,_,_=build(source,self.root/"one"/p,**kwargs)
                b,_,_=build(source,self.root/"two"/p,**kwargs)
                self.assertEqual(a.read_bytes(),b.read_bytes())
                self.assertEqual(a.name,p+"-ibm-tf-1-2-3-154112-20261113.tgz")
    def test_custom_name_and_no_overwrite(self):
        source=self.source("fmcv")
        a,_,_=build(source,self.root/"out",product="fmcv",draft=True,filename="DRAFT-custom.tgz")
        self.assertEqual(a.name,"DRAFT-custom.tgz")
        with self.assertRaisesRegex(ValueError,"overwrite"):
            build(source,self.root/"out",product="fmcv",draft=True,filename=a.name)
    def test_draft_cannot_look_like_release(self):
        with self.assertRaisesRegex(ValueError,"Draft filenames"):
            build(self.source("fmcv"),self.root/"out",product="fmcv",draft=True,filename="release.tgz")
    def test_no_unsafe_output_path(self):
        source=self.source("fmcv")
        for name in ("../escape.tgz","/tmp/escape.tgz","DRAFT/escape.tgz"):
            with self.subTest(name=name),self.assertRaises(ValueError):
                build(source,self.root/"out",product="fmcv",draft=True,filename=name)
        with self.assertRaisesRegex(ValueError,"outside"):
            build(source,source/"output",product="fmcv",draft=True)
    def test_unexpected_state_rejected(self):
        source=self.source("ftdv");(source/"terraform.tfstate").write_text("{}")
        with self.assertRaisesRegex(ValueError,"unexpected"):
            check_source(source,"ftdv",draft=True)
    def test_symlink_rejected(self):
        source=self.source("fmcv");(source/"link").symlink_to(source/"README.md")
        with self.assertRaisesRegex(ValueError,"Symlinks"):
            check_source(source,"fmcv",draft=True)
    def test_broken_link_rejected(self):
        source=self.source("ftdv")
        with (source/"README.md").open("a") as f:f.write("\n[bad](missing.md)\n")
        with self.assertRaisesRegex(ValueError,"Broken"):
            check_source(source,"ftdv",draft=True)
    def test_wrong_offering_or_locator_rejected(self):
        source=self.source("fmcv");install_fixture(source,"fmcv")
        path=source/"fmcv-images.json";original=json.loads(path.read_text())
        for field in ("version_crn","catalog_version_locator"):
            data=json.loads(json.dumps(original));data["releases"][data["default_version"]][field]="wrong"
            path.write_text(json.dumps(data))
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,"unapproved"):
                check_source(source,"fmcv")
    def test_digest_and_compatibility_rejected(self):
        source=self.source("ftdv");path=source/"ftdv-images.json";original=json.loads(path.read_text())
        for field,value in (("catalog_sha256","bad"),("supported_regions",[]),("secure_boot_modes",["true"]),("minimum_boot_volume_gb",0)):
            data=json.loads(json.dumps(original));data["releases"][data["default_version"]][field]=value
            path.write_text(json.dumps(data))
            with self.subTest(field=field),self.assertRaises(ValueError):check_source(source,"ftdv",draft=True)
    def test_changelog_uses_first_of_long_history(self):
        path=self.root/"changelog.txt"
        path.write_text("".join(f"2026-Nov-13\nversion 10.11.{i}\nChanges\nEntry {i}\n" for i in range(100,-1,-1)))
        self.assertEqual(read_latest_changelog(path)["version"],"10.11.100")
    def test_changelog_not_newest_first_rejected(self):
        path=self.root/"changelog.txt"
        path.write_text("2026-Nov-13\nversion 10.11.1\nChanges\nOne\n2026-Nov-12\nversion 10.11.2\nChanges\nTwo\n")
        with self.assertRaisesRegex(ValueError,"newest first"):read_latest_changelog(path)
    def test_selected_account_reference_is_a_candidate_not_global_access(self):
        source=self.source("ftdv");install_fixture(source,"ftdv")
        path=source/"ftdv-images.json";data=json.loads(path.read_text())
        data["releases"][data["default_version"]]["reference_access_scope"]="selected_accounts"
        path.write_text(json.dumps(data))
        _,_,report=build(source,self.root/"candidate",product="ftdv")
        result=json.loads(report.read_text())
        self.assertEqual(result["reference_access_scopes"],["selected_accounts"])
        self.assertEqual(result["status"],"local_candidate_not_uploaded_or_IBM_validated")
    def test_verified_reference_requires_known_scope(self):
        source=self.source("fmcv");install_fixture(source,"fmcv")
        path=source/"fmcv-images.json";data=json.loads(path.read_text())
        for scope in ("unverified","unknown"):
            data["releases"][data["default_version"]]["reference_access_scope"]=scope
            path.write_text(json.dumps(data))
            with self.subTest(scope=scope),self.assertRaisesRegex(ValueError,"access scope"):
                check_source(source,"fmcv")
    def test_version_override_must_match(self):
        with self.assertRaisesRegex(ValueError,"latest changelog"):
            build(self.source("fmcv"),self.root/"out","1.0.0",product="fmcv",draft=True)

    def test_changelog_bump_controls_filename(self):
        source=self.source("fmcv")
        path=source/"changelog.txt"
        path.write_text("2026-Nov-18\nversion 1.2.4\nChanges\nNext fixture version\n"+path.read_text())
        archive,_,report=build(source,self.root/"out",product="fmcv")
        self.assertTrue(archive.name.startswith("fmcv-ibm-tf-1-2-4-"))
        self.assertEqual(json.loads(report.read_text())["software_package_version"],"1.2.4")

    def test_image_add_default_remove(self):
        for product in ("ftdv","fmcv"):
            with self.subTest(product=product):
                source=self.source(product)
                path=source/(product+"-images.json")
                catalog=json.loads(path.read_text())
                old_default=catalog["default_version"]
                catalog["releases"]["__review_next__"]=dict(catalog["releases"][old_default])
                catalog["default_version"]="__review_next__"
                path.write_text(json.dumps(catalog))
                _,_,report=build(source,self.root/"added"/product,product=product)
                self.assertEqual(json.loads(report.read_text())["default_image_label"],"__review_next__")
                del catalog["releases"][old_default]
                path.write_text(json.dumps(catalog))
                _,_,report=build(source,self.root/"removed"/product,product=product)
                data=json.loads(report.read_text())
                self.assertEqual(data["default_image_label"],"__review_next__")
                self.assertNotIn(old_default,data["packaged_image_labels"])

    def test_package_output_rejects_other_modules_and_symlinks(self):
        source=self.source("fmcv")
        project=self.root/"fake-project"
        for product in ("asav","ftdv","fmcv","future"):
            output=project/"solutions"/(product+"-ibm-tf")/"review"
            with self.subTest(product=product),mock.patch.object(package_product,"PROJECT_ROOT",project),self.assertRaisesRegex(ValueError,"outside"):
                build(source,output,product="fmcv")
            self.assertFalse(output.exists())
        target=project/"solutions/asav-ibm-tf"
        target.mkdir(parents=True)
        alias=self.root/"output-alias"
        alias.symlink_to(target,target_is_directory=True)
        with mock.patch.object(package_product,"PROJECT_ROOT",project),self.assertRaisesRegex(ValueError,"outside"):
            build(source,alias/"review",product="fmcv")

    def test_checkers_reject_work_inside_repository(self):
        project=self.root/"fake-repo/ibm-mp-templates"
        shutil.copytree(PROJECT/"publisher",project/"publisher",ignore=shutil.ignore_patterns("__pycache__"))
        for product in ("ftdv","fmcv"):
            for relative in ("solutions/asav-ibm-tf/review","solutions/future-ibm-tf/review","publisher/evidence"):
                output=project/relative
                with self.subTest(product=product,relative=relative):
                    result=subprocess.run([sys.executable,str(project/"publisher"/("check_"+product+".py")),"--work-dir",str(output)],capture_output=True,text=True)
                    self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                    self.assertIn("outside the repository",result.stderr)
                    self.assertFalse(output.exists())

if __name__=="__main__":unittest.main()
