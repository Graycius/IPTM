#!/usr/bin/env python3
"""IPTM local, opt-in HTTP(S) inspection: mitmproxy + ClamAV clamd INSTREAM.

No content is persisted. Works ONLY for consenting clients explicitly configured to use
this proxy; CA trust must be installed voluntarily. Not a network-wide packet scanner.
"""
import os
import json
import pathlib
import stat
import ipaddress
import socket
import struct
import zlib

from mitmproxy import http

MAX_BYTES = 16 * 1024 * 1024
CLAMD_SOCKET = os.environ.get('IPTM_CLAMD_SOCKET', '/run/clamav/clamd.ctl')
# Fail closed by default: do not run an unauthenticated Internet-facing open proxy.
_ALLOWED_CIDRS = [x for x in os.environ.get('IPTM_ALLOWED_CLIENTS','').split(',') if x.strip()]
try:
    ALLOWED_CLIENTS = [ipaddress.ip_network(net.strip(), strict=True) for net in _ALLOWED_CIDRS]
except ValueError as exc:
    raise RuntimeError('IPTM_ALLOWED_CLIENTS non valido') from exc

# Per-device and per-destination opt-in policy; missing/unsafe profile denies all.
def load_policy():
    path=pathlib.Path('/etc/iptables-manager/traffic-optin.json')
    if not path.is_file() or path.is_symlink():return ([],[],set())
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077 or st.st_size>8192:
        return ([],[],set())
    try:
        policy=json.loads(path.read_text())
        if policy.get('version')!=1 or policy.get('mode')!='explicit-local':return ([],[],set())
        clients=[ipaddress.ip_address(x) for x in policy['clients']]
        if any(x.version!=4 or not x.is_private or x.is_loopback for x in clients):return ([],[],set())
        hosts=[str(x).lower() for x in policy['hosts']]
        if any(not h or '..' in h or not all(c.isalnum() or c in '.-' for c in h) for h in hosts):return ([],[],set())
        ports=set(policy['ports'])
        if not ports or not ports.issubset({80,443}):return ([],[],set())
        return (clients,hosts,ports)
    except Exception:
        return ([],[],set())

OPTIN_CLIENTS,OPTIN_HOSTS,OPTIN_PORTS=load_policy()

class ScanError(Exception):
    pass


def decode_bounded(raw: bytes, encoding: str, limit: int = MAX_BYTES) -> bytes:
    if len(raw) > limit:
        raise ScanError('dimensione superiore al limite di scansione')
    encoding = encoding.strip().lower()
    if encoding in ('', 'identity'):
        return raw
    if encoding not in ('gzip', 'deflate'):
        raise ScanError('codifica HTTP non ispezionabile: ' + encoding[:24])
    try:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == 'gzip' else zlib.MAX_WBITS)
        out = dec.decompress(raw, limit + 1)
        if len(out) > limit or dec.unconsumed_tail:
            raise ScanError('contenuto decompresso troppo grande')
        out += dec.flush(limit + 1 - len(out))
        if len(out) > limit or not dec.eof or dec.unused_data:
            raise ScanError('contenuto compresso incompleto o troppo grande')
        return out
    except zlib.error as exc:
        raise ScanError('contenuto compresso non verificabile') from exc


def scan_clamd(content: bytes, socket_path: str = CLAMD_SOCKET) -> tuple[str, str]:
    """Return (clean|infected|error, reason), fail closed on daemon failures."""
    if len(content) > MAX_BYTES:
        return ('error', 'limite dimensioni')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(8.0)
            sock.connect(socket_path)
            sock.sendall(b'zINSTREAM\0')
            for i in range(0, len(content), 65536):
                chunk = content[i:i + 65536]
                sock.sendall(struct.pack('!I', len(chunk)) + chunk)
            sock.sendall(b'\0\0\0\0')
            ans = bytearray()
            while len(ans) < 4096:
                ch = sock.recv(4096 - len(ans))
                if not ch:
                    break
                ans.extend(ch)
                if b'\0' in ch or b'\n' in ch:
                    break
            result = bytes(ans).split(b'\0')[0].decode('utf-8', 'replace').strip()
        if result.endswith(' FOUND'):
            return ('infected', result[:300])
        if result.endswith(' OK'):
            return ('clean', 'OK')
        return ('error', 'risposta antivirus inattesa')
    except (OSError, TimeoutError):
        return ('error', 'servizio antivirus non disponibile')


class IPTMTrafficAV:
    @staticmethod
    def authorized(flow: http.HTTPFlow) -> bool:
        try:
            peer = flow.client_conn.peername
            if not peer:
                return False
            addr = ipaddress.ip_address(str(peer[0]).split('%', 1)[0])
            return addr in OPTIN_CLIENTS and (not ALLOWED_CLIENTS or any(addr in network for network in ALLOWED_CLIENTS))
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def destination_allowed(flow: http.HTTPFlow) -> bool:
        try:
            host=str(flow.request.host).lower().rstrip('.')
            port=int(flow.request.port)
            return port in OPTIN_PORTS and any(host==suffix or host.endswith('.'+suffix) for suffix in OPTIN_HOSTS)
        except (ValueError,TypeError,AttributeError):
            return False

    def http_connect(self, flow: http.HTTPFlow) -> None:
        # CONNECT must be rejected before a TLS tunnel is opened to the target.
        if not self.authorized(flow) or not self.destination_allowed(flow):
            self.block(flow, 403, 'Client o destinazione non autorizzati')

    def request(self, flow: http.HTTPFlow) -> None:
        if not self.authorized(flow) or not self.destination_allowed(flow):
            self.block(flow, 403, 'Client o destinazione non autorizzati')
            return
        # Most servers comply; bounded decoder handles gzip/deflate if they don't.
        flow.request.headers['Accept-Encoding'] = 'identity'
        raw = flow.request.raw_content
        if raw is None:
            self.block(flow, 503, 'Richiesta non disponibile per la scansione')
            return
        if not raw:
            return
        try:
            content = decode_bounded(raw, flow.request.headers.get('content-encoding', ''))
        except ScanError:
            self.block(flow, 413, 'Richiesta troppo grande o non verificabile (16 MiB)')
            return
        status, _detail = scan_clamd(content)
        if status == 'infected':
            self.block(flow, 403, 'Invio bloccato dall’antivirus locale')
        elif status != 'clean':
            self.block(flow, 503, 'Antivirus non disponibile: richiesta bloccata')

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.authorized(flow) or not self.destination_allowed(flow):
            self.block(flow, 403, 'Client o destinazione non autorizzati')
            return
        if flow.response is None:
            return
        raw = flow.response.raw_content
        if raw is None:
            self.block(flow, 503, 'Risposta non disponibile per la scansione')
            return
        try:
            content = decode_bounded(raw, flow.response.headers.get('content-encoding', ''))
        except ScanError:
            self.block(flow, 502, 'Contenuto non verificabile o troppo grande (16 MiB)')
            return
        status, _detail = scan_clamd(content)
        if status == 'infected':
            self.block(flow, 403, 'Contenuto bloccato dall’antivirus locale')
        elif status != 'clean':
            self.block(flow, 503, 'Antivirus non disponibile: contenuto bloccato')

    @staticmethod
    def block(flow: http.HTTPFlow, code: int, message: str) -> None:
        flow.response = http.Response.make(code, message.encode('utf-8'), {
            'content-type': 'text/plain; charset=utf-8',
            'cache-control': 'no-store',
            'x-content-type-options': 'nosniff',
        })


addons = [IPTMTrafficAV()]
