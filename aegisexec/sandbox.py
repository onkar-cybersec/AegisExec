"""Linux-only namespace executor with host-owned deadlines and byte budgets."""
from __future__ import annotations
import math
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from .paths import create_sanitized_workspace_snapshot, SnapshotError

FIXED_BWRAP_PATH='/usr/bin/bwrap'
class SandboxError(Exception): pass
class SandboxPrerequisiteError(SandboxError): pass

def find_bwrap():
    try:
        info=os.stat(FIXED_BWRAP_PATH)
        if info.st_uid==0 and not info.st_mode & 0o022 and stat.S_ISREG(info.st_mode) and os.access(FIXED_BWRAP_PATH,os.X_OK):
            return FIXED_BWRAP_PATH
    except OSError: pass
    return None

def _runtime():
    args=['--ro-bind','/usr','/usr']
    for path in ('/lib','/lib64','/bin'):
        if os.path.exists(path): args+=['--ro-bind',path,path]
    return args

def check_bwrap_support():
    if not sys.platform.startswith('linux'): return False,'Linux namespaces are required'
    binary=find_bwrap()
    if not binary: return False,'Trusted /usr/bin/bwrap is unavailable'
    try:
        result=subprocess.run([binary,'--unshare-all','--new-session','--die-with-parent','--cap-drop','ALL',*_runtime(),'--proc','/proc','--dev','/dev','--clearenv','/usr/bin/true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        return (True,'Bubblewrap namespace probe passed') if result.returncode==0 else (False,'Namespace probe failed; host policy remains unchanged')
    except (OSError,subprocess.TimeoutExpired): return False,'Namespace probe unavailable'

class BubblewrapExecutor:
    def __init__(self,workspace_dir,python_bin='/usr/bin/python3',timeout_seconds=30.0,max_output_bytes=65536,max_memory_mb=256,allowed_subpaths=None,denied_patterns=None):
        if python_bin!='/usr/bin/python3': raise SandboxError('Only the fixed system interpreter is supported')
        if isinstance(timeout_seconds,bool) or not isinstance(timeout_seconds,(int,float)) or not math.isfinite(timeout_seconds) or not 0<timeout_seconds<=300: raise SandboxError('Invalid deadline')
        if type(max_output_bytes) is not int or not 0<max_output_bytes<=10*1024*1024: raise SandboxError('Invalid output budget')
        if type(max_memory_mb) is not int or not 16<=max_memory_mb<=4096: raise SandboxError('Invalid address-space budget')
        self.workspace_dir=os.path.abspath(workspace_dir)
        self.timeout_seconds=timeout_seconds
        self.max_output_bytes=max_output_bytes
        self.max_memory_mb=max_memory_mb
        self.allowed_subpaths=allowed_subpaths or []
        self.denied_patterns=denied_patterns or []
        self.worker_script=os.path.join(os.path.dirname(__file__),'worker.py')

    def execute_python(self,code=None,script_workspace_rel_path=None,script_args=None):
        supported,reason=check_bwrap_support()
        if not supported: raise SandboxPrerequisiteError(reason)
        if (code is None)==(script_workspace_rel_path is None): raise SandboxError('Exactly one code source is required')
        if code is not None and (not isinstance(code,str) or len(code.encode('utf-8'))>1024*1024): raise SandboxError('Code input exceeds limit')
        if script_args and (len(script_args)>100 or any(not isinstance(a,str) or '\x00' in a or len(a)>4096 for a in script_args)): raise SandboxError('Invalid arguments')
        snapshot=None
        proc=None
        selector=selectors.DefaultSelector()
        start=time.monotonic()
        try:
            try:
                snapshot=create_sanitized_workspace_snapshot(self.workspace_dir,self.allowed_subpaths,self.denied_patterns)
            except SnapshotError as exc: raise SandboxError(str(exc)) from None
            # The launch file is separate from agent data and is mounted read-only.
            with tempfile.TemporaryDirectory(prefix='aegis_launch_') as launch:
                if script_workspace_rel_path is None:
                    launch_file=os.path.join(launch,'request.py')
                    with open(launch_file,'x',encoding='utf-8') as handle: handle.write(code)
                    script='/opt/request.py'
                else:
                    from .paths import PathValidator
                    fd,_=PathValidator(snapshot).open_relative_file_fd(script_workspace_rel_path)
                    os.close(fd)
                    script='/workspace/'+script_workspace_rel_path
                cmd=[FIXED_BWRAP_PATH,'--unshare-all','--new-session','--die-with-parent','--cap-drop','ALL',*_runtime(),'--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',snapshot,'/workspace','--chdir','/workspace','--ro-bind',self.worker_script,'/opt/worker.py']
                if script_workspace_rel_path is None: cmd+=['--ro-bind',launch_file,script]
                cmd+=['--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','/usr/bin/python3','-I','-u','/opt/worker.py','--max-memory-mb',str(self.max_memory_mb),'--cpu-seconds',str(math.ceil(self.timeout_seconds)),'--code-file',script,'--',*(script_args or [])]
                proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin'})
                for name,pipe in [('stdout',proc.stdout),('stderr',proc.stderr)]:
                    os.set_blocking(pipe.fileno(),False)
                    selector.register(pipe,selectors.EVENT_READ,name)
                output={'stdout':bytearray(),'stderr':bytearray()}
                used=0
                status=None
                deadline=time.monotonic()+self.timeout_seconds
                while selector.get_map() or proc.poll() is None:
                    left=deadline-time.monotonic()
                    if left<=0:
                        status='TIMEOUT'
                        break
                    for key,_ in selector.select(min(left,0.1)):
                        try: chunk=os.read(key.fileobj.fileno(),4096)
                        except BlockingIOError: continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        remain=self.max_output_bytes-used
                        accepted=chunk[:remain]
                        output[key.data].extend(accepted)
                        used+=len(accepted)
                        if len(chunk)>remain:
                            status='OUTPUT_LIMIT_EXCEEDED'
                            break
                    if status: break
                if status:
                    self._kill(proc)
                else:
                    proc.wait(timeout=1)
                    status='COMPLETED' if proc.returncode==0 else 'FAILED'
                # Drop incomplete/invalid UTF-8 rather than expand replacement characters beyond budget.
                return {'status':status,'exit_code':124 if status=='TIMEOUT' else 137 if status=='OUTPUT_LIMIT_EXCEEDED' else proc.returncode,
                        'stdout':output['stdout'].decode('utf-8',errors='ignore'),'stderr':output['stderr'].decode('utf-8',errors='ignore'),
                        'stdout_truncated':status=='OUTPUT_LIMIT_EXCEEDED','stderr_truncated':status=='OUTPUT_LIMIT_EXCEEDED',
                        'duration_ms':round((time.monotonic()-start)*1000,2),'sandbox_enforced':status!='FAILED'}
        finally:
            selector.close()
            if proc:
                if proc.poll() is None: self._kill(proc)
                for pipe in (proc.stdout,proc.stderr): pipe.close()
            if snapshot: shutil.rmtree(snapshot)

    @staticmethod
    def _kill(proc):
        try: os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        proc.wait(timeout=2)
