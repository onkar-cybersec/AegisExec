"""Descriptor-rooted access; workspace must contain only shareable data."""
from __future__ import annotations
import os, shutil, stat, tempfile
BLOCKED_PATH_FRAGMENTS = frozenset({'.ssh','.aws','.azure','.gcp','.kube','.gnupg','.docker','.netrc','.git','id_rsa','id_ed25519','id_ecdsa','authorized_keys','known_hosts','credentials','.bash_history','.zsh_history'})
BLOCKED_FILENAMES = frozenset({'secrets.json','service_account.json','shadow','sudoers'})
BLOCKED_EXACT_EXTENSIONS = frozenset({'.pem','.key','.p12','.pfx','.pkcs12'})
class PathValidationError(Exception): pass
class SnapshotError(Exception): pass

def is_sensitive_name(name):
    low = name.lower()
    return low in BLOCKED_PATH_FRAGMENTS or low in BLOCKED_FILENAMES or low.startswith('.env') or os.path.splitext(low)[1] in BLOCKED_EXACT_EXTENSIONS

def validate_raw_path_string(path):
    if not isinstance(path,str) or not path.strip() or len(path)>4096:
        raise PathValidationError('Invalid relative path')
    if '\x00' in path:
        raise PathValidationError('Null byte injection denied')
    if '\\' in path or os.path.isabs(path):
        raise PathValidationError('Absolute paths are forbidden; use POSIX workspace-relative paths')
    parts=path.split('/')
    if '..' in parts:
        raise PathValidationError("Raw directory traversal token '..' detected")
    return [p for p in parts if p not in ('','.')] 

def _directory(parent,name):
    return os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)

def _root(path):
    if os.name!='posix' or not hasattr(os,'O_NOFOLLOW'):
        raise PathValidationError('Filesystem execution requires POSIX descriptor support')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in os.path.abspath(path).split('/'):
            if part:
                child=_directory(fd,part)
                os.close(fd)
                fd=child
        return fd
    except BaseException:
        os.close(fd)
        raise PathValidationError('Workspace root contains an unavailable or unsafe component') from None

class PathValidator:
    def __init__(self,workspace_root,allowed_subpaths=None,denied_patterns=None):
        self.workspace_root=os.path.abspath(workspace_root)
        self.allowed_subpaths=[validate_raw_path_string(p) for p in (allowed_subpaths or [])]
        self.denied_patterns=denied_patterns or []
    def _allowed(self,parts,ancestor=False):
        rel='/'.join(parts)
        if any(is_sensitive_name(p) for p in parts) or any(p in rel for p in self.denied_patterns): return False
        return not self.allowed_subpaths or any(parts[:len(a)]==a or (ancestor and a[:len(parts)]==parts) for a in self.allowed_subpaths)
    def verify_subpath_policy(self,components):
        if not self._allowed(components): raise PathValidationError('Path is sensitive or excluded by workspace policy')
    def _open(self,parts,directory=False):
        self.verify_subpath_policy(parts)
        fd=_root(self.workspace_root)
        try:
            for part in (parts if directory else parts[:-1]):
                child=_directory(fd,part)
                os.close(fd)
                fd=child
            if directory:
                result,fd=fd,None
                return result
            if not parts: raise PathValidationError('A regular file path is required')
            result=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            info=os.fstat(result)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
                os.close(result)
                raise PathValidationError('Special files and hardlink aliases are denied')
            return result
        except OSError:
            raise PathValidationError('Path is missing or contains an unsafe component') from None
        finally:
            if fd is not None: os.close(fd)
    def open_relative_file_fd(self,target_path):
        parts=validate_raw_path_string(target_path)
        return self._open(parts),'/'.join(parts)
    def list_dir_bounded(self,target_path,max_depth=1,include_hidden=False,max_entries=500):
        parts=validate_raw_path_string(target_path)
        fd=self._open(parts,directory=True)
        results=[]
        visited=0
        def walk(dirfd,prefix,depth):
            nonlocal visited
            with os.scandir(dirfd) as entries:
                for entry in entries:
                    visited+=1
                    if visited>2000 or len(results)>=max_entries: return
                    rel=prefix+[entry.name]
                    if not self._allowed(parts+rel) or (not include_hidden and entry.name.startswith('.')): continue
                    info=os.stat(entry.name,dir_fd=dirfd,follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child=_directory(dirfd,entry.name)
                        try:
                            results.append({'name':entry.name,'type':'directory','rel_path':'/'.join(rel)})
                            if depth<max_depth: walk(child,rel,depth+1)
                        finally: os.close(child)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
                        results.append({'name':entry.name,'type':'file','rel_path':'/'.join(rel),'bytes':info.st_size})
        try:
            walk(fd,[],0)
            return results
        except OSError:
            raise PathValidationError('Directory changed during safe traversal') from None
        finally: os.close(fd)

def create_sanitized_workspace_snapshot(workspace_root,allowed_subpaths=None,denied_patterns=None,max_total_bytes=50*1024*1024,max_files=2000):
    validator=PathValidator(workspace_root,allowed_subpaths,denied_patterns)
    destination=tempfile.mkdtemp(prefix='aegis_snapshot_')
    total_bytes=0
    visited=0
    def copy(dirfd,parts,depth):
        nonlocal total_bytes,visited
        if depth>16: raise SnapshotError('Snapshot maximum directory depth exceeded')
        with os.scandir(dirfd) as entries:
            for entry in entries:
                visited+=1
                if visited>max_files: raise SnapshotError('Snapshot entry quota exceeded')
                rel=parts+[entry.name]
                if not validator._allowed(rel,ancestor=True): continue
                info=os.stat(entry.name,dir_fd=dirfd,follow_symlinks=False)
                dst=os.path.join(destination,*rel)
                if stat.S_ISLNK(info.st_mode): raise SnapshotError('Symlink rejected in workspace snapshot')
                if stat.S_ISDIR(info.st_mode):
                    child=_directory(dirfd,entry.name)
                    try:
                        os.mkdir(dst,0o700)
                        copy(child,rel,depth+1)
                    finally: os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    if not validator._allowed(rel): continue
                    src=os.open(entry.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dirfd)
                    try:
                        opened=os.fstat(src)
                        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1: raise SnapshotError('Special file or hardlink alias rejected')
                        with open(dst,'xb') as out:
                            while True:
                                chunk=os.read(src,min(65536,max_total_bytes-total_bytes+1))
                                if not chunk: break
                                total_bytes+=len(chunk)
                                if total_bytes>max_total_bytes: raise SnapshotError('Snapshot byte quota exceeded')
                                out.write(chunk)
                    finally: os.close(src)
                else: raise SnapshotError('Special file rejected in workspace snapshot')
    rootfd=None
    try:
        rootfd=_root(workspace_root)
        copy(rootfd,[],0)
        return destination
    except BaseException as exc:
        shutil.rmtree(destination)
        if isinstance(exc,(SnapshotError,KeyboardInterrupt,SystemExit)): raise
        raise SnapshotError('Workspace changed or contains an unsafe component') from None
    finally:
        if rootfd is not None: os.close(rootfd)
