##!/usr/bin/python
#-*- coding:utf-8 -*-
import requests
import sys


headers = {
    'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
    'Accept': "*/*",
    'Content-Type': "application/json",
    'X-Requested-With': "XMLHttpRequest",
    'Connection': "close",
    'Cache-Control': "no-cache"
}

def poc(url, timeout=10):
    vulurl = url + "/invoker/readonly"
    try:
        r = requests.post(vulurl, headers=headers, verify=False, timeout=timeout)
        e = r.status_code
        if e == 500:
            print ("[+] Target "+url+" Find CVE-2017-12149  EXP:https://github.com/zhzyker/exphub")
            return True, 'JBoss CVE-2017-12149: 存在漏洞'
        else:
            print ("[-] Target "+url+" Not CVE-2017-12149 Good Luck")
            return False, 'JBoss CVE-2017-12149: 安全'
    except Exception as e:
        print ("[-] Target "+url+" Not CVE-2017-12149 Good Luck")
        return False, f'JBoss CVE-2017-12149: 扫描失败 - {str(e)}'

if __name__ == "__main__":
    poc("http://127.0.0.1:8080/")

