#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07-D6: `nginx -t` on the configs P07 cares about, in a disposable container.

Checks (1) the legacy browser-ui image config rendered by render-nginx-conf.mjs for a reviewed
HTTPS API origin and the same-origin form, (2) the shipped edge example
(deploy/proxy/nginx.conf.example) exactly as the Compose profile harness uses it, and (3) that
the renderer refuses a loopback, plain-http, wildcard, userinfo and path origin. The nginx here is
the one in the disposable helper image (not the runtime image's nginx:1.29-alpine, which is not
present on this host): a syntax result, not a behaviour result. No dependency is added.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
failures = []


def check(name, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + name + (' :: ' + detail if detail and not ok else ''), flush=True)
    if not ok:
        failures.append(name)


def nginx_test(helper, directory, main_config):
    result = subprocess.run(['docker', 'run', '--rm', '--mount', 'type=bind,src=' + str(directory) + ',dst=/fixture,readonly',
                             helper, 'nginx', '-t', '-c', '/fixture/' + main_config], capture_output=True, text=True, timeout=60)
    return result.returncode == 0, (result.stdout + result.stderr)[-400:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--helper-image', default='blindpass-p06-edge:local')
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='p07-nginx-') as directory:
        root = Path(directory)
        (root / 'html').mkdir()
        template = ROOT / 'packages/browser-ui/nginx.conf.template'
        renderer = ROOT / 'packages/browser-ui/scripts/render-nginx-conf.mjs'
        # Negative control: the same check must fail on a broken config, or a pass proves nothing.
        (root / 'bad.conf').write_text('events {}\nhttp {\n    server { listen 80; add_header X; bogus_directive on; }\n}\n')
        ok, _ = nginx_test(arguments.helper_image, root, 'bad.conf')
        check('negative control: nginx -t rejects a broken config', not ok)
        for label, origin in (('reviewed https origin', 'https://blindpass.example'), ('same-origin', '')):
            rendered = root / 'default.conf'
            done = subprocess.run(['node', str(renderer), str(template), origin, str(rendered)], capture_output=True, text=True)
            check('render browser-ui config for ' + label, done.returncode == 0, done.stderr)
            if done.returncode != 0:
                continue
            text = rendered.read_text()
            expected = "connect-src 'self' https://blindpass.example;" if origin else "connect-src 'self';"
            check('rendered CSP carries exactly the reviewed connect source (' + label + ')', expected in text and '__CONNECT_SRC__' not in text)
            (root / 'main.conf').write_text('events {}\nhttp {\n    include /fixture/default.conf;\n    default_type text/html;\n}\n')
            # nginx wants the document root only at request time; the syntax test needs the include path.
            ok, output = nginx_test(arguments.helper_image, root, 'main.conf')
            check('nginx -t on the rendered browser-ui config (' + label + ')', ok, output)
        for label, origin, extra in (('loopback', 'http://127.0.0.1:3100', []), ('plain http', 'http://api.example', []), ('wildcard', 'https://*.example', []),
                                     ('userinfo', 'https://user:pw@api.example', []), ('path', 'https://api.example/v1', [])):
            done = subprocess.run(['node', str(renderer), str(template), origin, str(root / 'refused.conf'), *extra], capture_output=True, text=True)
            check('renderer refuses a ' + label + ' API origin without echoing it', done.returncode == 1 and origin.split('//')[-1] not in done.stderr, done.stderr)
        # Shipped edge example, as the profile harness wraps it.
        nginx = (ROOT / 'deploy/proxy/nginx.conf.example').read_text().replace('127.0.0.1:3200', 'controller:3200').replace('/etc/nginx/blindpass/', '/fixture/')
        (root / 'edge.conf').write_text('events {}\nhttp {\n' + nginx + '\n}\n')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=blindpass.example',
                        '-addext', 'subjectAltName=DNS:blindpass.example,DNS:input.example', '-keyout', str(root / 'private-key.pem'),
                        '-out', str(root / 'fullchain.pem')], capture_output=True, check=True)
        for name in ('fullchain.pem', 'private-key.pem'):
            (root / name).chmod(0o644)
        # nginx resolves the upstream name at configuration time; give the fixture a resolvable one.
        (root / 'edge.conf').write_text((root / 'edge.conf').read_text().replace('controller:3200', '127.0.0.1:3200'))
        ok, output = nginx_test(arguments.helper_image, root, 'edge.conf')
        check('nginx -t on the shipped edge example (nginx.conf.example) with the profile paths', ok, output)
        text = (root / 'edge.conf').read_text()
        check('the shipped edge writes no request or error logs in either server block', text.count('access_log off;') >= 2 and text.count('error_log /dev/null crit;') >= 2)
        check('the shipped edge adds HSTS without includeSubDomains or preload and hides the upstream value',
              text.count('add_header Strict-Transport-Security "max-age=31536000" always;') == 2 and 'includeSubDomains' not in text and 'preload' not in text and text.count('proxy_hide_header Strict-Transport-Security;') == 2)
    print(f'{"FAILED" if failures else "ok"}: {len(failures)} failures')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
