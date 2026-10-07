#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P07 request probe, run inside a disposable container on the Compose edge network.

Each container has its own static address, so the shipped nginx edge forwards a
distinct X-Forwarded-For to the controller (S05 distributed-source guessing).
Prints one sanitized JSON line per attempt: status, error code and Retry-After.
Credentials come from environment variables and are never printed.
"""
import argparse
import http.client
import json
import os
import secrets
import ssl
import sys

EDGE = os.environ.get('P07_EDGE_ADDRESS', '172.29.86.3')
HOST = 'blindpass.example'


def post(path, body, headers):
    context = ssl.create_default_context(cafile='/probe/fullchain.pem')
    connection = http.client.HTTPSConnection(EDGE, 443, context=context, timeout=45)
    # Connect to the edge address but validate and send the configured name.
    connection.sock = context.wrap_socket(__import__('socket').create_connection((EDGE, 443), timeout=45),
                                          server_hostname=HOST)
    token = secrets.token_hex(16)
    values = {'Host': HOST, 'Origin': 'https://' + HOST, 'Content-Type': 'application/json',
              'X-CSRF-Token': token, 'Cookie': 'bp_csrf=' + token, **headers}
    connection.request('POST', path, json.dumps(body), values)
    response = connection.getresponse()
    raw = response.read()
    try:
        error = json.loads(raw).get('error')
    except ValueError:
        error = None
    return {'status': response.status, 'error': error, 'retry_after': response.getheader('Retry-After'),
            'hsts': response.getheader('Strict-Transport-Security')}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    login = sub.add_parser('login')
    login.add_argument('--users', required=True, help='comma separated usernames, cycled')
    login.add_argument('--attempts', type=int, required=True)
    login.add_argument('--password-env', required=True)
    bootstrap = sub.add_parser('bootstrap')
    bootstrap.add_argument('--attempts', type=int, required=True)
    bootstrap.add_argument('--token-env')
    bootstrap.add_argument('--username', default='p07admin')
    bootstrap.add_argument('--password-env', default='P07_PW')
    arguments = parser.parse_args()
    results = []
    if arguments.command == 'login':
        users = arguments.users.split(',')
        password = os.environ[arguments.password_env]
        for index in range(arguments.attempts):
            result = post('/api/v3/admin/session/login',
                          {'username': users[index % len(users)], 'password': password}, {})
            results.append(result)
            print(json.dumps({'i': index + 1, **result}), flush=True)
    else:
        for index in range(arguments.attempts):
            token = os.environ[arguments.token_env] if arguments.token_env else secrets.token_hex(32)
            result = post('/api/v3/admin/bootstrap',
                          {'username': arguments.username, 'display_name': 'P07 operator',
                           'password': os.environ[arguments.password_env]},
                          {'x-blindpass-bootstrap-token': token})
            results.append(result)
            print(json.dumps({'i': index + 1, **result}), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
