#!/usr/bin/env python3

import requests
import base64
import hashlib
import zipfile
import os
import glob
import subprocess as sp
from netifaces import interfaces, ifaddresses, AF_INET6
from uuid import getnode as get_mac

get_base_auth = lambda username, password: base64.b64encode('{}:{}'.format(username, password).encode()).decode('utf8')

ip6 = ''
for intercafe in interfaces():
    if ifaddresses(intercafe).get(AF_INET6):
        ip6 = ifaddresses(intercafe)[AF_INET6][0].get('addr')
        break

mac = hex(get_mac())[2:]


def zip_file(fname):
    wd = os.getcwd()
    rel_fname = os.path.basename(fname)
    os.chdir(os.path.dirname(os.path.abspath(fname)))
    zipname = ''.join(rel_fname.split('.')[:-1]) + '.zip'
    with zipfile.ZipFile(zipname, "w", zipfile.ZIP_DEFLATED) as compressed:
        compressed.write(rel_fname)
    os.chdir(wd)
    return zipname


def zip_folder(folder):
    wd = os.getcwd()
    os.chdir(folder)
    flist = glob.glob('./*')
    zipname = folder.split('/')[-1] + '.zip'
    with zipfile.ZipFile(zipname, "w", zipfile.ZIP_DEFLATED) as compressed:
        for fname in flist:
            compressed.write(fname)
    compressed.close()
    sp.call(['mv', zipname, os.path.join(wd, zipname)])
    os.chdir(wd)
    return zipname


def get_checksum(fname):
    with open(fname, 'rb') as f:
        hash = hashlib.sha256(f.read()).hexdigest().upper()
    final_hash = hashlib.sha256(hash.upper().encode()).hexdigest().upper()
    return(final_hash)


def get_checksum_from_zip(zipfname):
    with zipfile.ZipFile(zipfname) as compressed:
        hashes = ''
        for included in compressed.infolist():
            print(included.filename)
            with compressed.open(included.filename) as f:
                content = f.read()
                hashes += hashlib.sha256(content).hexdigest().upper()
        return hashlib.sha256(hashes.upper().encode()).hexdigest().upper()


def get_b64_content(zipfname):
    return base64.b64encode(open(zipfname, 'rb').read()).decode()

def upload_file(client_id, secret_key, client_name, email, fname):
    zipped = zip_file(fname)
    headers = {
        "cache-control": "no-cache",
        "authorization": "Basic {}".format(get_base_auth(client_id, secret_key)),
        "Accept": "application/json, application/xml, text/json, text/x-json, text/javascript, text/xml",
        "User-Agent": "RestSharp 104.1.0.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "www.apimall.acra.gov.sg",
        "Connection": "Keep-Alive"
    }
    oauth_resp = requests.post('https://www.apimall.acra.gov.sg/authorizeServer/oauth/token',
                               data='grant_type=client_credentials', headers=headers)
    print(json.dumps(oauth_resp.json(), indent=2))
    headers = {
        "Accept": "application/json",
        "token": oauth_resp.json().get('access_token'),
        "cache-control": "no-cache",
        "User-Agent": "BizFinx",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "www.apimall.acra.gov.sg"
    }
    data = {
        "IsBulkUpload": True,
        "lstFiles": [{
            "OriginalFileName": zipped,
            "FileCheckSum": get_checksum(fname),
            "FileBytes": get_b64_content(zipped)
        }],
        "SessionToken": oauth_resp.json().get('access_token'),
        "Email": email,
        "SenderPlaceholder": "MultiUploadToolSPH",
        "Placeholder1": "{}&{}".format(ip6, mac),
        "Placeholder2": client_name
    }
    resp = requests.post('https://www.apimall.acra.gov.sg//api/acra/xbrl/MultiUploadFileForValidation', json=data,
                         headers=headers)
    return resp.json()

def upload_folder(client_id, secret_key, client_name, email, folder):
    zipped = zip_folder(folder)
    headers = {
        "cache-control": "no-cache",
        "authorization": "Basic {}".format(get_base_auth(client_id, secret_key)),
        "Accept": "application/json, application/xml, text/json, text/x-json, text/javascript, text/xml",
        "User-Agent": "RestSharp 104.1.0.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "www.apimall.acra.gov.sg",
        "Connection": "Keep-Alive"
    }
    oauth_resp = requests.post('https://www.apimall.acra.gov.sg/authorizeServer/oauth/token',
                               data='grant_type=client_credentials', headers=headers)
    print(json.dumps(oauth_resp.json(), indent=2))
    headers = {
        "Accept": "application/json",
        "token": oauth_resp.json().get('access_token'),
        "cache-control": "no-cache",
        "User-Agent": "BizFinx",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "www.apimall.acra.gov.sg"
    }
    data = {
        "IsBulkUpload": True,
        "lstFiles": [{
            "OriginalFileName": zipped,
            "FileCheckSum": get_checksum_from_zip(zipped),
            "FileBytes": get_b64_content(zipped)
        }],
        "SessionToken": oauth_resp.json().get('access_token'),
        "Email": email,
        "SenderPlaceholder": "MultiUploadToolSPH",
        "Placeholder1": "{}&{}".format(ip6, mac),
        "Placeholder2": client_name
    }
    resp = requests.post('https://www.apimall.acra.gov.sg//api/acra/xbrl/MultiUploadFileForValidation', json=data,
                         headers=headers)
    return resp.json()


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument('--client-id', action="store", dest="client_id", nargs='?', const=1, required=True)
    parser.add_argument('--secret-key', action="store", dest="secret_key", nargs='?', const=1, required=True)
    parser.add_argument('--client-name', action="store", dest="client_name", nargs='?', const=1, required=True)
    parser.add_argument('--email', action="store", dest="email", nargs='?', const=1, required=True)
    parser.add_argument('--file', action="store", dest="file", nargs='?', const=1)
    parser.add_argument('--folder', action="store", dest="file", nargs='?', const=1)
    args = parser.parse_args()
    if args.file:
        resp = upload_file(args.client_id, args.secret_key, args.client_name, args.email, args.file)
        print(json.dumps(resp, indent=2))
    elif args.folder:
        resp = upload_folder(args.client_id, args.secret_key, args.client_name, args.email, args.folder)
        print(json.dumps(resp, indent=2))
    else:
        print('One of --file or --folder parameters required.')

