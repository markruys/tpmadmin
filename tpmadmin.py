#! /usr/bin/env python3

"""Team Password Manager administration via the API.
See http://teampasswordmanager.com/docs/api/ for specification.

Created 2015 by Mark Ruys <mark.ruys@peercode.nl>, Peercode BV
"""

__version__ = '1.0'

import json
import hmac
import hashlib
import time
import requests

class TPMException(Exception):
    pass

class TPM:

  private_key = False
  public_key = False
  username = False
  password = False
  unlock_reason = False

  def __init__(self, url, version):
    self.api = 'api/' + version
    self.base_url = url

  def hmac(self, private_key, public_key):
    self.private_key = private_key
    self.public_key = public_key

  def httpbasic(self, username, password):
    self.username = username
    self.password = password

  def unlock(self, reason):
    self.unlock_reason = reason

  def request(self, path, action, data=''):
    head = self.base_url + '/' + self.api
    if path.startswith(head): path = path[len(head):]
    if not path.startswith(self.api): path = self.api + path

    if data:
      data = json.dumps(data)

    headers = {
      'Content-Type': 'application/json; charset=utf-8',
      'User-Agent': 'TPM-admin/' + __version__
    }

    if self.private_key and self.public_key:
      timestamp = str(int(time.time()))
      unhashed = path + timestamp + data
      hash = hmac.new(str.encode(self.private_key), msg=unhashed.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
      headers['X-Public-Key'] = self.public_key
      headers['X-Request-Hash'] = hash
      headers['X-Request-Timestamp'] = timestamp

    if self.username and self.password:
      auth = requests.auth.HTTPBasicAuth(self.username, self.password)
    else:
      auth = False

    if self.unlock_reason:
      headers['X-Unlock-Reason'] = self.unlock_reason

    url = self.base_url + '/' + path
    try:
      if action == 'get':
        self.req = requests.get(url, headers=headers, auth=auth)
      elif action == 'post':
        self.req = requests.post(url, headers=headers, auth=auth, data=data)
      result = self.req.json()

      if 'error' in result and result['error']:
        raise TPMException(result['message'])

    except requests.exceptions.RequestException as e:
      raise TPMException("Connection error for " + url)

    except ValueError as e:
      if self.req.status_code == 403:
        raise TPMException(url + " forbidden")
      elif self.req.status_code == 404:
        raise TPMException(url + " not found")
      else:
        raise TPMException(self.req.text)

    return result

  def post(self, path, data):
    return self.request(path, 'post', data)

  def get(self, path):
    return self.request(path, 'get')

  def get_collection(self, path):

    while True:

      for item in self.get(path):
        yield item

      if self.req.links and self.req.links['next'] and self.req.links['next']['rel'] == 'next':
        path = self.req.links['next']['url']
      else:
        break

def main():
  try:
    import sys
    import argparse

    parser = argparse.ArgumentParser(
      description='Team Password Manager administration',
      epilog='Use either private/public key (preferred) or username/password authentication.')
    parser.add_argument('--mode', choices=['export'], required=True,
                        help='export: exports all passwords in a CSV format')
    parser.add_argument('--url', dest='url', required=True,
                       help='URL of TPM like https://tpm.mydomain.com/')
    parser.add_argument('--private-key', dest='private_key',
                       help='private key from the user settings in TPM', metavar='KEY')
    parser.add_argument('--public-key', dest='public_key',
                       help='public key from the user settings in TPM', metavar='KEY')
    parser.add_argument('--user', dest='user',
                       help='username to log into TPM')
    parser.add_argument('--password', dest='password',
                       help='password to log into TPM')
    parser.add_argument('--unlock', dest='unlock',
                       help='unlock passwords', metavar='REASON')
    args = parser.parse_args()

    tpm = TPM(args.url if args.url.endswith("/index.php") else (args.url + "index.php") if args.url.endswith("/") else (args.url + "/index.php"), 'v4')
    if args.private_key and args.public_key:
      tpm.hmac(args.private_key, args.public_key)
    elif args.user and args.password:
      tpm.httpbasic(args.user, args.password)
    else:
      raise TPMException('No authentication specified (user/password or private/public key)')
    if args.unlock:
      tpm.unlock(args.unlock)

#     print(tpm.post('/projects.json', {'name': 'This is a new project', 'parent_id': 0}))

    if args.mode == 'export':
      import csv

      headers = [
        ('name', 'Name'),
        ('username', 'Username'),
        ('email', 'E-mail'),
        ('password', 'Password'),
      ]
      output_header = True

      for item in tpm.get_collection('/passwords.json'):

        password = tpm.get('/passwords/' + str(item['id']) + '.json')

        if output_header:
          writer = csv.writer(sys.stdout, delimiter="\t")
          writer.writerow([header[1] for header in headers])
          output_header = False

        writer.writerow([password.get(header[0], '') for header in headers])

  except TPMException as e:
    print(e)
    sys.exit(1)

if __name__ == "__main__":
  main()

