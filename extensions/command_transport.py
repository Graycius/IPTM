"""Bounded argv-only execution shared by privileged IPTM domain adapters.

A partial or oversized response is never returned as a valid observation.
No shell, no automatic retry of a mutating command. A timeout does not prove
that a command had no effect; callers retain their existing rollback duties.
"""
from __future__ import annotations
import codecs
import contextlib
import fcntl
import pathlib
import stat
import locale
import math
import os
import selectors
import signal
import subprocess
import time

MAX_STDOUT = 16 * 1024 * 1024
MAX_STDERR = 2 * 1024 * 1024
MAX_STATE_BYTES = 64 * 1024 * 1024

class OutputLimitError(OSError):
    def __init__(self, stream, prefix=b''):
        super().__init__('Output comando oltre il limite consentito')
        self.stream = stream
        self.prefix = prefix


def capture(argv, *, timeout, stdout_limit=MAX_STDOUT, stderr_limit=MAX_STDERR, env=None, encoding=None, retain_prefix=False, text=True, input_data=None, pass_fds=()):
    if not isinstance(argv, (list, tuple)) or not argv or not all(
        isinstance(arg, str) and '\0' not in arg for arg in argv
    ) or not argv[0]:
        raise ValueError('Argomenti comando non validi')
    if isinstance(timeout, bool) or not isinstance(timeout, (int,float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Timeout non valido')
    if any(type(n) is not int or not 0 < n <= MAX_STDOUT for n in (stdout_limit, stderr_limit)):
        raise ValueError('Limite output non valido')
    if input_data is not None and (not isinstance(input_data, bytes) or len(input_data)>MAX_STDOUT):
        raise ValueError('Input binario non valido o troppo grande')
    if not isinstance(pass_fds, tuple) or any(type(fd) is not int or fd<3 for fd in pass_fds):
        raise ValueError('Descrittori non validi')
    if encoding is not None:
        codecs.lookup(encoding)
    deadline = time.monotonic() + timeout
    with subprocess.Popen(argv, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True, env=env, pass_fds=pass_fds) as process:
        buffers = [bytearray(), bytearray()]
        limits = (stdout_limit, stderr_limit)
        try:
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                offset=0
                if process.stdin is not None:
                    if input_data:
                        os.set_blocking(process.stdin.fileno(), False)
                        selector.register(process.stdin, selectors.EVENT_WRITE, 2)
                    else:
                        process.stdin.close()
                while selector.get_map():
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    events = selector.select(remaining)
                    if not events:
                        # A selector can wake early (e.g. a signal). Only the
                        # monotonic deadline determines expiry.
                        continue
                    for key, _ in events:
                        i = key.data
                        if i == 2:
                            try:
                                offset += os.write(key.fd, memoryview(input_data)[offset:offset+65536])
                            except (BlockingIOError, InterruptedError):
                                continue
                            except BrokenPipeError:
                                offset=len(input_data)
                            if offset == len(input_data):
                                selector.unregister(key.fileobj)
                                process.stdin.close()
                            continue
                        try:
                            chunk = os.read(key.fd, min(65536, limits[i]-len(buffers[i])+1))
                        except (BlockingIOError, InterruptedError):
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            buffers[i].extend(chunk)
                            if len(buffers[i]) > limits[i]:
                                raise OutputLimitError(i, bytes(buffers[i][:limits[i]]) if retain_prefix else b'')
            code = process.wait(timeout=max(0, deadline-time.monotonic()))
        except BaseException:
            # Terminate descendants retaining either pipe, even if the leader has exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                process.wait()
            raise
    if not text:
        return subprocess.CompletedProcess(argv, code, *(bytes(buf) for buf in buffers))
    encoding = encoding or locale.getpreferredencoding(False)
    decoded = [bytes(buf).decode(encoding, errors='replace').replace('\r\n','\n').replace('\r','\n') for buf in buffers]
    return subprocess.CompletedProcess(argv, code, *decoded)


def open_directory(path):
    """Open each path component without following links; caller closes fd."""
    path = pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Percorso directory non assoluto o ambiguo')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def acquire_domain_lock(path, *, owner=0, nonblocking=False):
    """One protected flock implementation for driver and watchdog processes.

    Existing lock path and lifetime are preserved. Never truncate, chmod or
    unlink an existing lock. The parent must be controlled by owner (a sticky
    shared directory such as /run/lock is accepted for an owner-owned file).
    A caller must close the returned descriptor to release the lock.
    """
    path = pathlib.Path(path)
    if not path.name:
        raise ValueError('Nome lock non valido')
    dfd = open_directory(path.parent)
    fd = None
    try:
        meta = os.fstat(dfd)
        if meta.st_uid != owner or (meta.st_mode & 0o022 and not meta.st_mode & stat.S_ISVTX):
            raise ValueError('Directory lock non protetta')
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        def checked():
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_nlink != 1 or st.st_mode & 0o077:
                raise ValueError('Lock non regolare o non protetto')
            entry = os.stat(path.name, dir_fd=dfd, follow_symlinks=False)
            if (st.st_dev, st.st_ino) != (entry.st_dev, entry.st_ino):
                raise ValueError('Lock sostituito durante acquisizione')
        checked()
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        checked()
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dfd)


@contextlib.contextmanager
def domain_lock(path, *, owner=0, nonblocking=False):
    fd = acquire_domain_lock(path, owner=owner, nonblocking=nonblocking)
    try:
        yield fd
    finally:
        os.close(fd)


def read_private_json(path, *, limit=2*1024*1024, owner=0):
    """Read a private JSON object from one verified descriptor, never a FIFO/symlink.

    Missing files are distinct from malformed or inaccessible files. Limit the
    actual read, not only the observed file size; reject concurrent in-place writes.
    Atomic replacement may safely return the old, complete snapshot.
    """
    import json
    import stat
    if type(limit) is not int or not 1 <= limit <= MAX_STATE_BYTES:
        raise ValueError('Limite documento non valido')
    path=pathlib.Path(path)
    try:
        dfd=open_directory(path.parent)
    except FileNotFoundError:
        return None
    try:
        try:
            fd=os.open(path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError:
            return None
    finally:
        os.close(dfd)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_nlink!=1 or before.st_mode&0o077 or before.st_size>limit:
            raise ValueError('Documento privato non sicuro')
        data=stream.read(limit+1)
        after=os.fstat(stream.fileno())
        if len(data)>limit or len(data)!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise ValueError('Documento modificato durante la lettura')
    doc=json.loads(data)
    if not isinstance(doc,dict):raise ValueError('Documento JSON non valido: atteso oggetto')
    return doc


class StatePublishError(OSError):
    """Publication may have occurred: a failed directory fsync is not rollback."""
    def __init__(self, path, published, cause):
        super().__init__(f"Scrittura stato {path}: {'pubblicato, durabilità non verificata' if published else 'non pubblicato'}: {cause}")
        self.published = published


def durable_replace(path, data, *, mode=0o600, owner=0, group=None, create_only=False):
    """Publish bytes on one verified directory descriptor, with durable rename.

    Callers own domain locks and recovery policy. This primitive does not
    serialize read/modify/write operations or promise a rollback after rename.
    Never traverse symlinks, overwrite special files or shared hardlinks.
    """
    import pathlib
    import secrets
    import stat
    path = pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.name:
        raise ValueError('Percorso stato non assoluto o ambiguo')
    if (not isinstance(data, bytes) or type(mode) is not int or not 0 <= mode <= 0o777 or mode & 0o022
            or group is not None and (type(group) is not int or group < 0)):
        raise ValueError('Contenuto o permessi non validi')
    dfd = open_directory(path.parent)
    name = None
    published = False
    try:
        meta = os.fstat(dfd)
        if meta.st_uid != owner or meta.st_mode & 0o022:
            raise ValueError('Directory stato non protetta')
        def target():
            try: st = os.stat(path.name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError: return None
            if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_nlink != 1 or st.st_mode & 0o022:
                raise ValueError('Destinazione stato non regolare o non protetta')
            return (st.st_dev, st.st_ino, st.st_ctime_ns)
        previous = target()
        if create_only and previous is not None:
            raise FileExistsError(str(path))
        candidate = '.iptm-state-' + secrets.token_hex(16)
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        name = candidate
        with os.fdopen(fd, 'wb') as stream:
            if group is not None:
                os.fchown(stream.fileno(), owner, group)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if target() != previous:
            raise ValueError('Destinazione cambiata durante la preparazione')
        if create_only:
            # Linux renameat2(RENAME_NOREPLACE) commits without a hardlink window.
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            rename = getattr(libc, 'renameat2', None)
            if rename is None:
                raise OSError('renameat2 non disponibile: pubblicazione esclusiva rifiutata')
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            if rename(dfd, os.fsencode(name), dfd, os.fsencode(path.name), 1) != 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err), str(path))
        else:
            os.replace(name, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)
        published = True
        os.fsync(dfd)
    except OSError as exc:
        raise StatePublishError(path, published, exc) from exc
    finally:
        if name is not None:
            try: os.unlink(name, dir_fd=dfd)
            except FileNotFoundError: pass
        os.close(dfd)


def durable_json(path, obj, *, ensure_ascii=True):
    import json
    if not isinstance(obj, dict):
        raise ValueError('Stato JSON non valido: atteso oggetto')
    data = json.dumps(obj, sort_keys=True, ensure_ascii=ensure_ascii, allow_nan=False).encode('utf-8')
    durable_replace(path, data)


def durable_unlink(path, *, owner=0):
    """Remove one private regular state entry and sync its directory.

    Caller holds its domain lock; never use for arbitrary service files.
    """
    path=pathlib.Path(path)
    dfd=open_directory(path.parent)
    try:
        meta=os.fstat(dfd)
        if meta.st_uid!=owner or meta.st_mode&0o022:
            raise ValueError('Directory stato non protetta')
        try: st=os.stat(path.name,dir_fd=dfd,follow_symlinks=False)
        except FileNotFoundError:return False
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=owner or st.st_nlink!=1 or st.st_mode&0o022:
            raise ValueError('File stato non protetto')
        os.unlink(path.name,dir_fd=dfd)
        os.fsync(dfd)
        return True
    finally:os.close(dfd)


SOFTWARE_TRANSACTION_LOCK = pathlib.Path('/run/iptm-software-update.lock')

@contextlib.contextmanager
def transaction_gate(*, gate=None, domain=None, recovery=False):
    """Root admission before domain lock; recovery may bypass admission but
    still takes the domain lock. Never held across interactive confirmation.
    """
    gate=SOFTWARE_TRANSACTION_LOCK if gate is None else pathlib.Path(gate)
    with contextlib.ExitStack() as stack:
        if not recovery:
            stack.enter_context(domain_lock(gate,nonblocking=True))
        if domain is not None:
            if pathlib.Path(domain)==gate:raise ValueError('Lock di dominio uguale al coordinatore')
            fd=stack.enter_context(domain_lock(domain,nonblocking=True))
        else:fd=None
        yield fd


@contextlib.contextmanager
def operation_admission(action, mutations, *, gate=None):
    """CLI admission for explicitly enumerated mutations. Status and recovery
    do not take this gate; domain locking remains the responsibility of callers.
    No environment-variable or client-controlled bypass of privileged admission.
    """
    if action in mutations:
        with transaction_gate(gate=gate):
            yield
    else:
        yield


# Single explicit admission policy for CLI mutation boundaries. A driver may
# have internal operations (e.g. recovery, observation, postinstall) that
# deliberately do not acquire the software gate. Argument validation stays
# with each privileged driver; this registry is not an authorization system.
MUTATION_POLICY = {
    'qos_engine': frozenset({'adaptive-disable','adaptive-enable','adaptive-tick','apply','auto-disable','auto-enable','auto-tick','calibrate-start','disable','stage'}),
    'qos_policy': frozenset({'apply','disable','stage'}),
    'nm_control': frozenset({'activate-trial','apply','delete-inactive','stage'}),
    'fabric_runtime': frozenset({'apply'}),
    'network_alias_trial': frozenset({'apply'}),
    'network_runtime': frozenset({'apply','dhcp-stage','stage'}),
    'dns_tls_guard': frozenset({'apply','compat-apply'}),
    'security_stack': frozenset({'crowdsec-stage','suricata-stage','crowdsec-apply','suricata-apply'}),
    'sqm_uplink': frozenset({'apply','apply-multi'}),
    'multinic_manager': frozenset({'save','clear','legacy-retire'}),
    'antidpi_live': frozenset({'start','persist-enable'}),
    'antidpi_sources': frozenset({'start','apply'}),
    'zapret_manager': frozenset({'configure','install','install-latest'}),
    'zapret2_manager': frozenset({'configure','install-latest'}),
    'pihole_credentials': frozenset({'save','clear'}),
}


@contextlib.contextmanager
def driver_admission(driver, args, *, gate=None):
    if driver not in MUTATION_POLICY:
        raise ValueError('Driver senza policy di ammissione')
    operation = args[0] if args else ''
    if ((driver == 'network_runtime' and operation == 'pihole-bind') or
            (driver == 'sqm_uplink' and operation == 'reconcile')):
        operation = args[1] if len(args) > 1 else ''
    with operation_admission(operation, MUTATION_POLICY[driver], gate=gate):
        yield
