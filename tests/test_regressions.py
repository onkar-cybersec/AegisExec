"""Independent regressions for the reviewed trust boundaries."""
import argparse
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock
from aegisexec.paths import PathValidator, PathValidationError, SnapshotError, create_sanitized_workspace_snapshot
from aegisexec.audit import AuditLogger, AuditError
from aegisexec.schemas import validate_action_request, SchemaValidationError
from aegisexec.sandbox import BubblewrapExecutor, check_bwrap_support
from aegisexec.report import parse_audit_log, generate_html_report, MAX_LINE_BYTES
from aegisexec.cli import cmd_init

class TestInputRegressions(unittest.TestCase):
    def test_report_rejects_oversized_single_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path=os.path.join(directory,'audit.jsonl')
            with open(path,'wb') as f: f.write(b'x'*(MAX_LINE_BYTES+1))
            with self.assertRaises(ValueError): parse_audit_log(path)
    def test_report_html_escapes_dynamic_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path=os.path.join(directory,'audit.jsonl')
            with open(path,'w') as f: json.dump({'operation':'<script>alert(1)</script>','reason_code':'<img src=x onerror=alert(1)>'},f)
            report=generate_html_report(path)
            self.assertNotIn('<script>alert(1)</script>',report)
            self.assertIn('&lt;script&gt;',report)
    def test_init_refuses_existing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path=os.path.join(directory,'policy.json')
            with open(path,'w') as f: f.write('ORIGINAL')
            self.assertEqual(cmd_init(argparse.Namespace(directory=directory)),2)
            with open(path) as f: self.assertEqual(f.read(),'ORIGINAL')
    def test_direct_dict_byte_limit(self):
        request={'schema_version':'1.0','request_id':'r','operation':'read_text','parameters':{'path':'x'},'context':{'metadata':{'large':'x'*1100000}}}
        with self.assertRaises(SchemaValidationError): validate_action_request(request)
    def test_cycle_rejected(self):
        request={}; request['context']=request
        with self.assertRaises(SchemaValidationError): validate_action_request(request)
    def test_audit_does_not_preserve_identifiers_or_unknown_reasons(self):
        token='UNIQUE_PRIVATE_TOKEN_998877'
        entry=AuditLogger().log('POLICY_CHECK','d',token,token,'DENIED',token,[],{'path':token})
        self.assertNotIn(token,json.dumps(entry))

@unittest.skipUnless(os.name=='posix','POSIX descriptor tests require Linux')
class TestFileRegressions(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=self.temp.name
        self.validator=PathValidator(self.root)
        with open(os.path.join(self.root,'safe.txt'),'w') as f: f.write('SAFE')
    def tearDown(self): self.temp.cleanup()
    def test_fifo_rejected_without_waiting_for_writer(self):
        os.mkfifo(os.path.join(self.root,'fifo'))
        with self.assertRaises(PathValidationError): self.validator.open_relative_file_fd('fifo')
    def test_hardlink_alias_rejected(self):
        os.link(os.path.join(self.root,'safe.txt'),os.path.join(self.root,'alias'))
        with self.assertRaises(PathValidationError): self.validator.open_relative_file_fd('alias')
    def test_parent_symlink_rejected(self):
        os.mkdir(os.path.join(self.root,'data'))
        os.symlink(os.path.join(self.root,'data'),os.path.join(self.root,'alias'))
        with self.assertRaises(PathValidationError): self.validator.list_dir_bounded('alias')
    def test_nested_allowlist_excludes_root_files_and_siblings(self):
        os.makedirs(os.path.join(self.root,'data','allowed'))
        for path in ['data/outside.txt','data/allowed/note.txt']:
            with open(os.path.join(self.root,path),'w') as f: f.write(path)
        snap=create_sanitized_workspace_snapshot(self.root,allowed_subpaths=['data/allowed'])
        try:
            self.assertFalse(os.path.exists(os.path.join(snap,'safe.txt')))
            self.assertFalse(os.path.exists(os.path.join(snap,'data','outside.txt')))
            self.assertTrue(os.path.exists(os.path.join(snap,'data','allowed','note.txt')))
        finally: shutil.rmtree(snap)
    def test_snapshot_actual_bytes_are_bounded(self):
        with self.assertRaises(SnapshotError): create_sanitized_workspace_snapshot(self.root,max_total_bytes=3)
    def test_listing_excludes_credentials_and_symlinks(self):
        with open(os.path.join(self.root,'.env'),'w') as f: f.write('secret')
        os.symlink('/etc',os.path.join(self.root,'external'))
        entries=self.validator.list_dir_bounded('.',include_hidden=True)
        self.assertEqual([e['name'] for e in entries],['safe.txt'])
    def test_snapshot_file_swapped_to_external_symlink(self):
        real_open=os.open
        def swapped(path,flags,*args,**kwargs):
            if path=='safe.txt' and 'dir_fd' in kwargs:
                os.unlink(os.path.join(self.root,'safe.txt'))
                os.symlink('/etc/passwd',os.path.join(self.root,'safe.txt'))
            return real_open(path,flags,*args,**kwargs)
        with mock.patch('aegisexec.paths.os.open',side_effect=swapped):
            with self.assertRaises(SnapshotError): create_sanitized_workspace_snapshot(self.root)
    def test_audit_symlink_refuses_before_execution(self):
        os.symlink(os.path.join(self.root,'safe.txt'),os.path.join(self.root,'audit'))
        with self.assertRaises(AuditError):
            AuditLogger(os.path.join(self.root,'audit')).log('CHECK','d','r','read_text','DENIED','test',[],{})
        with open(os.path.join(self.root,'safe.txt')) as f: self.assertEqual(f.read(),'SAFE')

class TestRuntimeRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ok,reason=check_bwrap_support()
        if not ok:
            if os.environ.get('REQUIRE_SANDBOX')=='1': raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=self.temp.name
    def tearDown(self): self.temp.cleanup()
    def test_combined_output_and_invalid_utf8_never_expand_budget(self):
        res=BubblewrapExecutor(self.root,max_output_bytes=15).execute_python(code="import os; os.write(1,b'\\xff'*8); os.write(2,b'B'*100)")
        self.assertEqual(res['status'],'OUTPUT_LIMIT_EXCEEDED')
        self.assertLessEqual(len((res['stdout']+res['stderr']).encode()),15)
    def test_multibyte_output_flood_bounded_in_bytes(self):
        res=BubblewrapExecutor(self.root,max_output_bytes=17).execute_python(code="print('🔒'*1000)")
        self.assertEqual(res['status'],'OUTPUT_LIMIT_EXCEEDED')
        self.assertLessEqual(len((res['stdout']+res['stderr']).encode()),17)
    def test_child_subprocess_output_is_capped(self):
        code="import subprocess; subprocess.run(['/usr/bin/python3','-c',\"print('Z'*50000)\"] )"
        res=BubblewrapExecutor(self.root,max_output_bytes=128).execute_python(code=code)
        self.assertEqual(res['status'],'OUTPUT_LIMIT_EXCEEDED')
        self.assertLessEqual(len((res['stdout']+res['stderr']).encode()),128)
    def test_script_path_and_arguments(self):
        with open(os.path.join(self.root,'task.py'),'w') as f: f.write('import sys; print(sys.argv[1])')
        res=BubblewrapExecutor(self.root).execute_python(script_workspace_rel_path='task.py',script_args=['hello'])
        self.assertEqual(res['exit_code'],0)
        self.assertEqual(res['stdout'].strip(),'hello')
    def test_detached_child_actually_disappears(self):
        marker='aegis_child_'+uuid.uuid4().hex
        code="import subprocess,time; subprocess.Popen(['/usr/bin/python3','-c','import time; time.sleep(60)',"+repr(marker)+"],start_new_session=True); time.sleep(60)"
        result={}
        def run(): result.update(BubblewrapExecutor(self.root,timeout_seconds=2).execute_python(code=code))
        thread=threading.Thread(target=run)
        thread.start()
        def matching():
            for pid in os.listdir('/proc'):
                if not pid.isdigit(): continue
                try:
                    with open('/proc/'+pid+'/cmdline','rb') as f:
                        if marker.encode() in f.read(8192): return True
                except OSError: pass
            return False
        seen=False
        deadline=time.monotonic()+1.5
        while time.monotonic()<deadline:
            if matching(): seen=True; break
            time.sleep(.02)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(seen,'The child must exist for this cleanup test to be meaningful')
        self.assertEqual(result['status'],'TIMEOUT')
        time.sleep(.1)
        self.assertFalse(matching(),'Detached sandbox child survived timeout')
