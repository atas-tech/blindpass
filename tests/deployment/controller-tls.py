#!/usr/bin/env python3
"""P06-T01–T04: actual controller HTTPS, fail-closed config and bounded IO."""
import argparse
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time


def request(address, context, path='/readyz', timeout=2, method='GET'):
    with socket.create_connection(address, timeout=timeout) as transport:
        with context.wrap_socket(transport, server_hostname='localhost') as stream:
            stream.sendall(f'{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'.encode())
            data = b''
            while chunk := stream.recv(65536):
                data += chunk
    head, body = data.split(b'\r\n\r\n', 1)
    return int(head.split()[1]), head.lower(), body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=Path('target/debug/blindpass-controller'))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='blindpass-p06-tls-') as temporary:
        root = Path(temporary)
        for name in ['keys', 'data', 'run']:
            (root / name).mkdir(mode=0o700)
        for name, byte in [('root-secret', b'R'), ('agent-jwt-secret', b'A'), ('issuer-key', b'I')]:
            path = root / 'keys' / name
            path.write_bytes(byte * 32)
            path.chmod(0o600)
        key, cert = root / 'tls.key', root / 'tls.crt'
        other_key = root / 'other.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:FALSE',
                        '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                        '-out', str(other_key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for path in [key, cert, other_key]:
            path.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            address = reservation.getsockname()
        env = {
            'BLINDPASS_KEYS_DIR': str(root / 'keys'),
            'BLINDPASS_DATA_DIR': str(root / 'data'),
            'BLINDPASS_ADMIN_SOCKET_PATH': str(root / 'run/admin.sock'),
            'BLINDPASS_LISTEN': f'{address[0]}:{address[1]}',
            'BLINDPASS_PUBLIC_URL': 'https://localhost',
            'BLINDPASS_UI_BASE_URL': 'https://localhost',
            'BLINDPASS_TLS_CERT_FILE': str(cert),
            'BLINDPASS_TLS_KEY_FILE': str(key),
        }
        bad_pem = root / 'bad.pem'
        bad_pem.write_bytes(b'P06-DUMMY-PRIVATE-CANARY-invalid-pem')
        bad_pem.chmod(0o600)
        variants = []
        for missing in ['BLINDPASS_TLS_CERT_FILE', 'BLINDPASS_TLS_KEY_FILE']:
            variant = dict(env)
            del variant[missing]
            variants.append(variant)
        for field, value in [('BLINDPASS_TLS_KEY_FILE', str(bad_pem)), ('BLINDPASS_TLS_CERT_FILE', str(bad_pem)),
                             ('BLINDPASS_TLS_KEY_FILE', str(other_key)), ('BLINDPASS_PUBLIC_URL', 'http://localhost'),
                             ('BLINDPASS_UI_BASE_URL', 'http://localhost')]:
            variants.append({**env, field: value})
        exposed = root / 'exposed.key'
        exposed.write_bytes(key.read_bytes())
        exposed.chmod(0o644)
        variants.append({**env, 'BLINDPASS_TLS_KEY_FILE': str(exposed)})
        linked = root / 'linked.key'
        linked.symlink_to(key)
        variants.append({**env, 'BLINDPASS_TLS_KEY_FILE': str(linked)})
        for variant in variants:
            output = subprocess.run([str(binary), 'serve'], env=variant, capture_output=True, timeout=3)
            assert output.returncode != 0
            assert str(root).encode() not in output.stderr
            assert b'P06-DUMMY-PRIVATE-CANARY' not in output.stderr
            assert b'PRIVATE KEY-----' not in output.stderr
            assert not (root / 'data/controller.db').exists(), 'bad TLS touched state'
        print('PASS P06-T01 invalid/incomplete/mismatched/unsafe TLS refuses before state access', flush=True)

        output = subprocess.run([str(binary), 'migrate'], env=env, capture_output=True, timeout=10)
        assert output.returncode == 0, 'valid TLS configuration denied'
        context = ssl.create_default_context(cafile=str(cert))
        held = []
        with (root / 'server.log').open('wb') as log:
            server = subprocess.Popen([str(binary), 'serve'], env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while True:
                    assert server.poll() is None, 'HTTPS server exited'
                    try:
                        status, headers, body = request(address, context)
                        break
                    except (ConnectionRefusedError, ConnectionResetError):
                        assert time.monotonic() < deadline, 'HTTPS startup exceeded 5 seconds'
                        time.sleep(0.02)
                assert status == 200 and json.loads(body) == {'ok': True, 'checks': {'database': 'up'}}
                assert b'strict-transport-security: max-age=31536000' in headers
                pages = []
                for path in ['/', '/?id=p06-dummy&metadata_sig=p06-dummy&submit_sig=p06-dummy']:
                    status, headers, body = request(address, context, path)
                    assert status == 200 and b'<!doctype html>' in body.lower()
                    assert b'content-security-policy:' in headers
                    pages.append(body)
                assert pages[0] != pages[1], 'input route served the console shell'
                with socket.create_connection(address, timeout=2) as transport:
                    transport.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n')
                    try:
                        assert b'HTTP/1.1 200' not in transport.recv(1024)
                    except ConnectionResetError:
                        pass
                print('PASS P06-T02 verified HTTPS readiness and embedded UI/CSP/HSTS; plaintext rejected', flush=True)
                probe_env = {**env, 'BLINDPASS_HEALTH_CA_FILE': str(cert),
                             'BLINDPASS_HEALTH_TLS_NAME': 'localhost'}
                probe = subprocess.run([str(binary), 'healthcheck'], env=probe_env,
                                       capture_output=True, timeout=3)
                assert probe.returncode == 0 and not probe.stdout and not probe.stderr, 'verified readiness probe failed'
                for changes in [{'BLINDPASS_HEALTH_TLS_NAME': 'wrong.invalid'},
                                {'BLINDPASS_HEALTH_CA_FILE': str(bad_pem)}]:
                    probe = subprocess.run([str(binary), 'healthcheck'], env={**probe_env, **changes},
                                           capture_output=True, timeout=3)
                    assert probe.returncode != 0 and not probe.stdout
                    assert probe.stderr == b'blindpass-controller: readiness probe failed\n'
                print('PASS P06-H03 actual TLS probe verifies CA and name; wrong trust/name fail safely', flush=True)
                for expected in [401, 401, 401, 401, 401, 429]:
                    assert request(address, context, '/api/v2/agents/token', method='POST')[0] == expected, 'TLS lost transport-peer rate limiting'

                held.append(socket.create_connection(address, timeout=2))
                started = time.monotonic()
                assert request(address, context)[0] == 200
                assert time.monotonic() - started < 2, 'one slow handshake blocked serving'
                for _ in range(63):
                    held.append(socket.create_connection(address, timeout=2))
                # A saturated handshake set must free slots after the fixed
                # timeout. The verified client is allowed 2s scheduling slack.
                started = time.monotonic()
                assert request(address, context, timeout=7)[0] == 200
                elapsed = time.monotonic() - started
                assert elapsed < 7, 'handshake saturation failed to recover'
                for transport in held:
                    transport.settimeout(2)
                    assert transport.recv(1) == b'', 'incomplete handshake outlived timeout'
                    transport.close()
                held.clear()
                print(f'PASS P06-T03 one stalled handshake isolated; 64 stalled peers drained, recovery {elapsed:.3f}s (<7s)', flush=True)

                held.append(socket.create_connection(address, timeout=2))
                started = time.monotonic()
                server.send_signal(signal.SIGTERM)
                assert server.wait(timeout=10) == 0
                print(f'PASS P06-T04 SIGTERM with stalled handshake, shutdown {time.monotonic()-started:.3f}s (<10s)', flush=True)
            finally:
                for transport in held:
                    transport.close()
                if server.poll() is None:
                    server.kill()
                    server.wait()
        contents = (root / 'server.log').read_bytes()
        assert b'PRIVATE KEY-----' not in contents and b'P06-DUMMY-PRIVATE-CANARY' not in contents
        assert str(root).encode() not in contents


if __name__ == '__main__':
    main()
