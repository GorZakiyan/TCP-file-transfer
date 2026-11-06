#!/usr/bin/env python3
"""Integration tests using real processes, TCP links and captured frame edits."""
import os
from pathlib import Path
import socket
import select
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def connect(p):
    for _ in range(100):
        try:
            return socket.create_connection(('127.0.0.1', p), timeout=2)
        except ConnectionRefusedError:
            time.sleep(.02)
    raise RuntimeError('Server did not start')

def start(name, *args, ready=True):
    p = subprocess.Popen([str(ROOT / name), *map(str, args)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ready and name != 'sender':
        try:
            readable, _, _ = select.select([p.stderr], [], [], 5)
            if not readable or not p.stderr.readline().startswith(b'Listening on '):
                raise RuntimeError(f'{name} did not become ready')
        except BaseException:
            stop(p)
            raise
    return p

def finish(p, success):
    _, err = p.communicate(timeout=10)
    assert (p.returncode == 0) == success, (p.args, p.returncode, err)

def stop(p):
    if p.poll() is None:
        p.terminate()
    p.communicate(timeout=5)

def plain(data):
    return b''.join(struct.pack('!I', len(data[i:i+1024])) + data[i:i+1024]
                    for i in range(0, len(data), 1024)) + b'\0' * 4

def pipeline(folder, label, data):
    src, dst = folder / (label + '.in'), folder / (label + '.out')
    if data is not None:
        src.write_bytes(data)
    a, b, c = port(), port(), port()
    procs = []
    try:
        procs.append(start('listener', '127.0.0.1', c, dst))
        procs.append(start('decoder', '127.0.0.1', b, '127.0.0.1', c, folder/'test.key'))
        procs.append(start('encoder', '127.0.0.1', a, '127.0.0.1', b, folder/'test.key'))
        procs.append(start('sender', src, '127.0.0.1', a))
        for p in reversed(procs):
            finish(p, True)
        assert src.read_bytes() == dst.read_bytes()
        assert not list(folder.glob('*.part'))
        print('PASS:', label, 'matching input/output', len(dst.read_bytes()), 'bytes')
    finally:
        for p in procs:
            stop(p)

def capture(folder):
    """Capture an actual encoder transfer for adversarial tests."""
    a = port()
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0)); server.listen()
        b = server.getsockname()[1]
        enc = start('encoder', '127.0.0.1', a, '127.0.0.1', b, folder/'test.key')
        try:
            with connect(a) as s:
                s.sendall(plain(b'authenticated data' * 200))
            server.settimeout(5)
            conn, _ = server.accept()
            with conn:
                chunks = []
                while True:
                    data = conn.recv(4096)
                    if not data: break
                    chunks.append(data)
            finish(enc, True)
            return b''.join(chunks)
        finally:
            stop(enc)

def reject_encrypted(folder, label, wire, key):
    a = port()
    # A listening sentinel proves the decoder does not even connect downstream.
    with socket.socket() as sentinel:
        sentinel.bind(('127.0.0.1', 0)); sentinel.listen(); sentinel.settimeout(.15)
        b = sentinel.getsockname()[1]
        dec = start('decoder', '127.0.0.1', a, '127.0.0.1', b, key)
        try:
            with connect(a) as s:
                try: s.sendall(wire)
                except (BrokenPipeError, ConnectionResetError): pass
            finish(dec, False)
            try:
                conn, _ = sentinel.accept(); conn.close()
                raise AssertionError('Decoder forwarded unverified transfer')
            except socket.timeout:
                pass
            print('PASS:', label, 'rejected without forwarding')
        finally:
            stop(dec)

def interrupted_plain(folder, role):
    a, b = port(), port()
    dst = folder / 'preserved.out'; dst.write_bytes(b'previous output')
    args = (['127.0.0.1', a, dst] if role == 'listener' else
            ['127.0.0.1', a, '127.0.0.1', b, folder/'test.key'])
    with socket.socket() as server:
        if role == 'encoder':
            server.bind(('127.0.0.1', b)); server.listen()
        p = start(role, *args)
        try:
            with connect(a) as s:
                s.sendall(struct.pack('!I', 3) + b'abc') # no END
            finish(p, False)
            assert dst.read_bytes() == b'previous output'
            assert not list(folder.glob('*.part'))
            print('PASS:', role, 'interrupted plaintext rejected; prior output preserved')
        finally:
            stop(p)

def main():
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        (folder/'test.key').write_bytes(os.urandom(32))
        (folder/'wrong.key').write_bytes(os.urandom(32))
        for label, data in [('text', b'Hello Linux!\n' * 300),
                            ('binary', bytes(range(256))*37),
                            ('empty', b''), ('automatic-sample', None),
                            ('one-byte', b'x'), ('1023-bytes', b'x'*1023),
                            ('1024-bytes', b'x'*1024), ('1025-bytes', b'x'*1025)]:
            pipeline(folder, label, data)
        wire = capture(folder)
        reject_encrypted(folder, 'wrong key', wire, folder/'wrong.key')
        changed = bytearray(wire); changed[12] ^= 1
        reject_encrypted(folder, 'modified ciphertext', changed, folder/'test.key')
        changed = bytearray(wire); changed[8:12] = struct.pack('!I', 1023)
        reject_encrypted(folder, 'modified length AAD', changed, folder/'test.key')
        changed = bytearray(wire); changed[-1] ^= 1
        reject_encrypted(folder, 'modified END tag', changed, folder/'test.key')
        changed = bytearray(wire); changed[0] ^= 1
        reject_encrypted(folder, 'modified nonce salt', changed, folder/'test.key')
        first_size = 4 + struct.unpack('!I', wire[8:12])[0] + 16
        first = wire[8:8+first_size]
        second = wire[8+first_size:8+2*first_size]
        reject_encrypted(folder, 'reordered frames',
                         wire[:8]+second+first+wire[8+2*first_size:], folder/'test.key')
        reject_encrypted(folder, 'duplicated frame',
                         wire[:8]+first+wire[8:], folder/'test.key')
        for label, partial in [('missing END', wire[:-20]),
                               ('partial frame', wire[:25]), ('partial salt', wire[:4])]:
            reject_encrypted(folder, label, partial, folder/'test.key')
        interrupted_plain(folder, 'listener')
        interrupted_plain(folder, 'encoder')
        for size in (0, 31, 33):
            key = folder/'invalid.key'; key.write_bytes(b'x' * size)
            for role in ('encoder', 'decoder'):
                p = start(role, '127.0.0.1', port(), '127.0.0.1', port(), key, ready=False)
                try: finish(p, False)
                finally: stop(p)
        print('PASS: encoder/decoder reject keys of 0, 31 and 33 bytes')
        # A partial header/payload must also remove listener temporary output.
        for payload in [b'\0\0', struct.pack('!I', 10)+b'ab', struct.pack('!I', 1025)]:
            a = port(); dst = folder/'preserved.out'
            p = start('listener', '127.0.0.1', a, dst)
            try:
                with connect(a) as s: s.sendall(payload)
                finish(p, False)
                assert dst.read_bytes() == b'previous output'
                assert not list(folder.glob('*.part'))
            finally: stop(p)
        print('PASS: partial plaintext header/payload and oversized length rejected')
    print('ALL TESTS PASSED')

if __name__ == '__main__':
    main()
