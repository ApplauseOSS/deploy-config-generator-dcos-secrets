#!/usr/bin/env python

import argparse
import hashlib
import json
import os
import re
import requests
import shutil
import subprocess
import sys
import tempfile
import time


DEBUG = False
BASE_URL = None
TOKEN = None


def api_request(endpoint, method='GET', data=None):
    url = '%s/%s' % (BASE_URL.rstrip('/'), endpoint)
    headers = {
        'Authorization': 'token=%s' % TOKEN,
    }
    method = method.upper()
    r = None
    if method == 'GET':
        r = requests.get(url, headers=headers, params=data)
    elif method == 'PUT':
        r = requests.put(url, headers=headers, json=data)
    elif method == 'PATCH':
        r = requests.patch(url, headers=headers, json=data)
    else:
        raise Exception('Unsupported method: %s' % method)
    if DEBUG:
        print('Request:')
        print('%s %s' % (method, url))
        print('Headers:')
        print(r.request.headers)
        print('Body:')
        print(r.request.body)
        print('')
        print('Response:')
        print('Status: %d' % r.status_code)
        print('Body:')
        print(r.text)
    return r


def get_secret(secret_name):
    r = api_request('secrets/v1/secret/default/%s' % secret_name)
    return r.json().get('value', None)


def create_secret(secret_name, value):
    r = api_request('secrets/v1/secret/default/%s' % secret_name, method='PUT', data={'value': value})
    if r.status_code == 201:
        return True
    return False


def update_secret(secret_name, value):
    r = api_request('secrets/v1/secret/default/%s' % secret_name, method='PATCH', data={'value': value})
    if r.status_code == 204:
        return True
    return False


def create_service_account(account_name, public_key):
    r = api_request('acs/api/v1/users/%s' % account_name, method='PUT', data={'public_key': public_key})
    if r.status_code == 201:
        return True
    return False


def generate_password():
    now = time.time()
    return hashlib.md5(str(now)).hexdigest()


def generate_keypair():
    tmpdir = tempfile.mkdtemp()
    if DEBUG:
        print('Creating private key at %s/private.pem' % tmpdir)
    subprocess.check_call('openssl genrsa -out %s/private.pem 2048' % tmpdir, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if DEBUG:
        print('Creating public key at %s/public.pem' % tmpdir)
    subprocess.check_call('openssl rsa -in %s/private.pem -outform PEM -pubout -out %s/public.pem' % (tmpdir, tmpdir), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    private_key = open('%s/private.pem' % tmpdir).read()
    public_key = open('%s/public.pem' % tmpdir).read()
    if DEBUG:
        print('Removing temporary directory %s' % tmpdir)
    shutil.rmtree(tmpdir)
    return (private_key, public_key)


def main():
    global DEBUG, TOKEN, BASE_URL

    parser = argparse.ArgumentParser(description='Manage DC/OS secrets')
    parser.add_argument(
        '-t', '--token',
        dest='token',
        help='Authentication token (core.dcos_acs_token) for DC/OS'
    )
    parser.add_argument(
        '-u', '--url',
        dest='url',
        help='Base URL (core.dcos_url) for DC/OS'
    )
    parser.add_argument(
        '-d', '--debug',
        dest='debug',
        default=False,
        action='store_true',
        help='Enable debug output',
    )
    parser.add_argument(
        'secrets_file',
        help='Path to secrets.json file',
    )
    args = parser.parse_args()

    DEBUG = args.debug
    TOKEN = args.token
    BASE_URL = args.url

    if not TOKEN or not BASE_URL:
        print('You must provide a base URL and auth token')
        sys.exit(1)

    data = None
    try:
        with open(args.secrets_file) as f:
            data = json.load(f)
        if not isinstance(data, (list, dict)):
            raise Exception('secrets file should contain a list or dict')
        if not isinstance(data, list):
            data = [data]
    except Exception as e:
        print('Failed to read secrets file: %s' % str(e))
        sys.exit(1)

    for secret in data:
        print('Processing secret: %s' % secret['name'])
        if secret['type'] == 'password':
            # Get current secret value, if any
            current_value = get_secret(secret['name'])
            if secret.get('env_var', None):
                # Use value from specified Terraform output
                if not (secret['env_var'] in os.environ):
                    print('Unknown environment variable: %s' % secret['env_var'])
                    sys.exit(1)
                value = os.environ[secret['env_var']]
                if current_value is None:
                    print('Secret does not exist...creating secret')
                    if not create_secret(secret['name'], value):
                        print('Failed to set secret')
                        sys.exit(1)
                elif current_value != value:
                    print('Secret already exists...updating secret')
                    if not update_secret(secret['name'], value):
                        print('Failed to set secret')
                        sys.exit(1)
                else:
                    print('Secret already exists...nothing to do')
            else:
                if current_value is None:
                    value = generate_password()
                    print('Secret does not exist...creating random secret')
                    if not create_secret(secret['name'], value):
                        print('Failed to set secret')
                        sys.exit(1)
                else:
                    print('Secret already exists...nothing to do')
        elif secret['type'] == 'service_account':
            current_value = get_secret(secret['name'])
            if current_value is None:
                private_key, public_key = generate_keypair()
                account_name = re.sub('[^-_a-zA-Z0-9]', '_', secret['name'])
                if not create_service_account(account_name, public_key):
                    print('Failed to create service account')
                    sys.exit(1)
                # This matches the structure created by the 'dcos security secrets create-sa-secret' command
                secret_data = {
                    'login_endpoint': 'https://leader.mesos/acs/api/v1/auth/login',
                    'private_key': private_key,
                    'scheme': 'RS256',
                    'uid': account_name,
                }
                if not create_secret(secret['name'], json.dumps(secret_data)):
                    print('Failed to create secret')
                    sys.exit(1)
        else:
            print('Unsupported secret type: %s' % secret['type'])
            sys.exit(1)


if __name__ == '__main__':
    main()
