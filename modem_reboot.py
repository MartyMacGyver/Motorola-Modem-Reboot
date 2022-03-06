#!/usr/bin/env python3

'''


'''

import hmac
import time
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEBUG = False
default_user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.34 Safari/537.36'


class SurfboardHNAP:
    payload_login = {
        'Login': {
            'Action': '',
            'Username': '',
            'LoginPassword': '',
            'PrivateLogin': 'LoginPassword',
            'Captcha': '',
        }
    }

    payload_basic_status = {
        'GetMultipleHNAPs': {
            'GetHomeConnection': '',
            'GetHomeAddress': '',
        }
    }

    payload_software_status = {
        'GetMultipleHNAPs': {
            'GetMotoStatusSoftware': '',
            'GetMotoStatusXXX': '',
        }
    }

    payload_conn_details = {
        'GetMultipleHNAPs': {
            'GetMotoStatusStartupSequence': '',
            'GetMotoStatusConnectionInfo': '',
            'GetMotoStatusDownstreamChannelInfo': '',
            'GetMotoStatusUpstreamChannelInfo': '',
            'GetMotoLagStatus': '',
        }
    }

    payload_status_log = {
        'GetMultipleHNAPs': {
            'GetMotoStatusLog': '',
            'GetMotoStatusLogXXX': '',
        }
    }

    payload_security = {
        'GetMultipleHNAPs': {
            'GetMotoStatusSecAccount': '',
            'GetMotoStatusSecXXX': '',
        }
    }

    payload_reboot = {
        'SetStatusSecuritySettings': {
            'MotoStatusSecurityAction': '1',
            'MotoStatusSecXXX': 'XXX',
        }
    }

    def __init__(self, host):
        self.host = host
        self.privatekey = None
        self.cookie_id = None
        self.s = requests.Session()

    def generate_keys(self, challenge, pubkey, password):
        privatekey = hmac.new(pubkey+password, challenge, digestmod='md5').hexdigest().upper()
        passkey = hmac.new(privatekey.encode(), challenge, digestmod='md5').hexdigest().upper()
        self.privatekey = privatekey
        return (privatekey, passkey)

    def generate_hnap_auth(self, operation):
        privkey = self.privatekey
        curtime = str(int(time.time() * 1000))
        auth_key = curtime + '"http://purenetworks.com/HNAP1/{}"'.format(operation)
        privkey = privkey.encode()
        auth = hmac.new(privkey, auth_key.encode(), digestmod='md5')
        hnap_auth = auth.hexdigest().upper() + ' ' + curtime
        if DEBUG:
            print(hnap_auth)
        return hnap_auth

    def _login_request(self):
        url = f'https://{host}/HNAP1/'
        headers = {
            # 'User-Agent': default_user_agent,
            # 'Content-Type': 'application/json; charset=UTF-8',
            # 'Accept': 'application/json, text/javascript, */*; q=0.01',
            # 'X-Requested-With': 'XMLHttpRequest',
            'SOAPAction': '"http://purenetworks.com/HNAP1/Login"',
        }
        payload = self.payload_login
        payload['Login']['Action'] = 'request'
        payload['Login']['Username'] = 'admin'

        r = self.s.post(url, headers=headers, json=payload, stream=True)
        if DEBUG:
            print(f"_login_request ends with {r} {r.text}")
        return r

    def _login_real(self, cookie_id, privatekey, passkey):
        host = self.host
        url = f'https://{host}/HNAP1/'
        auth = self.generate_hnap_auth('Login')
        headers = {
            'HNAP_AUTH': auth,
            # 'User-Agent': default_user_agent,
            # 'Content-Type': 'application/json; charset=UTF-8',
            # 'Accept': 'application/json, text/javascript, */*; q=0.01',
            # 'X-Requested-With': 'XMLHttpRequest',
            'SOAPAction': '"http://purenetworks.com/HNAP1/Login"',
        }
        cookies = {
            'uid': f'{cookie_id}',
            'PrivateKey': f'{privatekey}',
        }
        payload = self.payload_login
        payload['Login']['Action'] = 'login'
        payload['Login']['Username'] = 'admin'
        payload['Login']['LoginPassword'] = f'{passkey}'

        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        return r

    def login(self, password, noverify):
        if noverify:
            self.s.verify = False
        r = self._login_request()
        lrdata = json.loads(r.text)['LoginResponse']
        cookie_id = lrdata['Cookie']
        pubkey = lrdata['PublicKey']
        challenge = lrdata['Challenge']
        if DEBUG:
            print(f'lrdata = {lrdata}')

        self.cookie_id = cookie_id

        privkey, passkey = self.generate_keys(
            challenge.encode(),
            pubkey.encode(),
            password.encode(),
        )
        if DEBUG:
            print(privkey, passkey)
        r = self._login_real(cookie_id, privkey, passkey)
        return r

    def get_multiple(self, payload=payload_basic_status):
        host = self.host
        cookie_id = self.cookie_id
        privatekey = self.privatekey

        url = f'https://{host}/HNAP1/'
        auth = self.generate_hnap_auth('GetMultipleHNAPs')
        headers = {
            'HNAP_AUTH': auth,
            # 'User-Agent': default_user_agent,
            # 'Content-Type': 'application/json; charset=UTF-8',
            # 'Accept': 'application/json, text/javascript, */*; q=0.01',
            'SOAPACTION': '"http://purenetworks.com/HNAP1/GetMultipleHNAPs"',
            # 'Referer': f'https://{host}/MotoSecurity.html',
        }

        cookies = {
            'uid': f'{cookie_id}',
            'PrivateKey': f'{privatekey}'
        }

        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        if DEBUG:
            print(f'get_status ends with {r} {r.text}')
        return r

    def get_security(self):
        host = self.host
        cookie_id = self.cookie_id
        privatekey = self.privatekey

        url = f'https://{host}/HNAP1/'
        auth = self.generate_hnap_auth('GetMultipleHNAPs')
        headers = {
            'HNAP_AUTH': auth,
            # 'User-Agent': default_user_agent,
            # 'Content-Type': 'application/json',
            # 'Accept': 'application/json',
            'SOAPACTION': '"http://purenetworks.com/HNAP1/GetMultipleHNAPs"',
            # 'Referer': f'https://{host}/MotoSecurity.html',
            # 'Origin': f'https://{host}',
            # 'Cookie': 'uid={}; PrivateKey={}'.format(cookie_id, privatekey),
            # 'Accept-Encoding': 'gzip, deflate',
            # 'Accept-Language': 'en-US,en-XA;q=0.9,en;q=0.8'
        }

        cookies = {
            'uid': f'{cookie_id}',
            'PrivateKey': f'{privatekey}',
        }
        payload = self.payload_security

        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        if DEBUG:
            print(f"get_security ends with {r} {r.text}")
        return r

    def reboot(self):
        host = self.host
        cookie_id = self.cookie_id
        privatekey = self.privatekey

        url = f'https://{host}/HNAP1/'
        auth = self.generate_hnap_auth('SetStatusSecuritySettings')
        headers = {
            'HNAP_AUTH': auth,
            # 'User-Agent': default_user_agent,
            # 'Content-Type': 'application/json; charset=UTF-8',
            # 'Accept': 'application/json, text/javascript, */*; q=0.01',
            # 'X-Requested-With': 'XMLHttpRequest',
            'SOAPAction': '"http://purenetworks.com/HNAP1/SetStatusSecuritySettings"'}

        cookies = {
            'uid': f'{cookie_id}',
            'PrivateKey': f'{privatekey}',
        }
        payload = self.payload_reboot
        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        if DEBUG:
            print(f"reboot ends with {r} {r.text}")
        return r


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='192.168.100.1',
                        help='Hostname or IP of your modem (Default: 192.168.100.1)')
    parser.add_argument('--password', default='motorola',
                        help='Admin password (Default: motorola)')
    parser.add_argument('--dryrun', '-d', action='store_true',
                        help="Logs in but doesn't reboot")
    parser.add_argument('--noverify', '-n', action='store_true',
                        help="Disable certificate verification")
    return parser.parse_args()


if __name__ == '__main__':
    args = get_arguments()
    host = args.host
    password = args.password

    h = SurfboardHNAP(host=host)
    r = h.login(password, args.noverify)
    print(f'login: {r}')
    r = h.get_multiple(payload=h.payload_basic_status)
    print(f'basic_status: {r} {r.text}')
    r = h.get_multiple(payload=h.payload_software_status)
    print(f'software_status: {r} {r.text}')
    r = h.get_multiple(payload=h.payload_conn_details)
    print(f'conn_details: {r} {r.text}')
    r = h.get_multiple(payload=h.payload_status_log)
    print(f'status_log: {r} {r.text}')
    r = h.get_security()
    print(f'get_security: {r} {r.text}')
    if not args.dryrun:
        r = h.reboot()
        print(f'reboot: {r} {r.text}')
        r = h.get_security()
        print(f'get_security: {r} {r.text}')
