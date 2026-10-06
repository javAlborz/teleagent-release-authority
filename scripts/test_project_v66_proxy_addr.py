#!/usr/bin/python3 -I
import base64,hashlib,importlib.util,io,json,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
S=importlib.util.spec_from_file_location('proxy_addr_projection',Path(__file__).with_name('project-v66-proxy-addr.py'))
M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
def fixture(extra=None,change=None,link=False):
 metadata={'name':'proxy-addr','version':'2.0.8','dependencies':M.DEPENDENCIES,**(change or {})}
 files={'package/package.json':json.dumps(metadata).encode(),'package/index.js':b'x',**(extra or {})}
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w:gz') as archive:
  for name,body in files.items():
   member=tarfile.TarInfo(name);member.size=len(body)
   if link and name=='package/index.js':member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd';member.size=0
   archive.addfile(member,io.BytesIO(body))
 body=out.getvalue();return body,base64.b64encode(hashlib.sha512(body).digest()).decode()
class Tests(unittest.TestCase):
 def test_integrity_checked_before_parsing(self):
  body,digest=fixture();self.assertEqual(len(M.verified_files(body,digest)),2)
  with self.assertRaises(ValueError):M.verified_files(body+b'x',digest)
 def test_unsafe_members_refused(self):
  for args in [{'extra':{'package/../escape':b'x'}},{'extra':{'/package/absolute':b'x'}},{'link':True},{'extra':{'package/oversized':b'x'*(512*1024+1)}}]:
   with self.subTest(args=list(args)),self.assertRaises(ValueError):M.verified_files(*fixture(**args))
 def test_new_dependencies_versions_or_install_hooks_refused(self):
  for change in [{'version':'2.0.0'},{'dependencies':{'surprise':'*'}},{'scripts':{'install':'run'}}]:
   with self.assertRaises(ValueError):M.verified_files(*fixture(change=change))
 def test_projection_refuses_bad_lock_before_changing_only_proxy_addr(self):
  with tempfile.TemporaryDirectory() as folder:
   base=Path(folder);root=base/'deps';target=root/'voice-app/node_modules/proxy-addr';target.mkdir(parents=True)
   (target/'package.json').write_text('{"version":"2.0.7"}')
   neighbor=target.parent/'keep';neighbor.write_text('unchanged')
   app=base/'app';(app/'voice-app').mkdir(parents=True)
   lock=app/'voice-app/package-lock.json'
   entry={'version':'2.0.8','resolved':M.URL,'integrity':'sha512-'+M.INTEGRITY,'dependencies':M.DEPENDENCIES}
   lock.write_text(json.dumps({'packages':{'node_modules/proxy-addr':{**entry,'version':'wrong'}}}))
   archive=base/'input';archive.write_bytes(b'fixture')
   with patch.object(M,'verified_files',return_value=M.verified_files(*fixture())):
    with self.assertRaises(ValueError):M.project(archive,root,app,'voice-app')
    self.assertEqual(json.loads((target/'package.json').read_text())['version'],'2.0.7')
    lock.write_text(json.dumps({'packages':{'node_modules/proxy-addr':entry}}))
    M.project(archive,root,app,'voice-app')
   self.assertEqual(json.loads((target/'package.json').read_text())['version'],'2.0.8')
   self.assertEqual(neighbor.read_text(),'unchanged')
if __name__=='__main__':unittest.main()
