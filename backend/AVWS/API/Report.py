#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
AWVS Report API 类

提供与 AWVS 报告 API 交互的功能,包括获取报告列表、生成报告、获取报告状态和下载报告
"""


import time
import requests
from .Base import Base


class Report(Base):

    """
    AWVS 报告 API 类

    用于获取和生成 AWVS 扫描报告
    """

    def __init__(self, api_base_url, api_key):
        """
        初始化 Report API 类

        Args:
            api_base_url: AWVS API 基础 URL
            api_key: AWVS API 密钥
        """
        super().__init__(api_base_url, api_key)
        self.logger = self.get_logger

    def get_all(self):
        """
        获取所有报告

        Returns:
            dict: 包含所有报告信息的字典,失败返回 None
        """
        try:
            response = requests.get(
                self.report_api, 
                headers=self.auth_headers, 
                verify=False,
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            self.logger.error(f'Get All Reports Failed: {str(e)}', exc_info=True)
            return None

    def generate(self, template_id, list_type, id_list):
        """
        生成报告

        Args:
            template_id: 报告模板 ID 或模板名称键值
            list_type: 列表类型(如 'scans' 或 'targets')
            id_list: ID 列表

        Returns:
            str: 成功返回 report_id，失败返回 None
        """
        template_uuid = self.report_template_dict.get(template_id, template_id)
        
        data = {
            'template_id': template_uuid,
            'source': {
                'list_type': list_type,
                'id_list': id_list
            }
        }
        
        try:
            response = requests.post(
                self.report_api, 
                json=data, 
                headers=self.auth_headers, 
                verify=False,
                timeout=60
            )
            
            if response.status_code in [200, 201]:
                location = response.headers.get('Location', '')
                if location:
                    report_id = location.split('/')[-1]
                    self.logger.info(f'报告生成请求成功，report_id: {report_id}')
                    return report_id
                
                try:
                    result = response.json()
                    report_id = result.get('report_id')
                    if report_id:
                        return report_id
                except:
                    pass
                
                self.logger.warning('报告生成请求成功，但无法获取 report_id')
                return None
            
            self.logger.error(f'报告生成失败: HTTP {response.status_code}, 响应: {response.text[:200]}')
            return None
            
        except Exception as e:
            self.logger.error(f'Generate Report Failed: {str(e)}', exc_info=True)
            return None

    def get(self, report_id):
        """
        获取指定报告的信息

        Args:
            report_id: 报告 ID

        Returns:
            dict: 包含报告信息的字典,失败返回 None
        """
        try:
            url = f"{self.report_api}/{report_id}"
            response = requests.get(
                url, 
                headers=self.auth_headers, 
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            
            self.logger.error(f'获取报告信息失败: HTTP {response.status_code}')
            return None
            
        except Exception as e:
            self.logger.error(f'Get Report Failed: {str(e)}', exc_info=True)
            return None

    def get_status(self, report_id):
        """
        获取报告生成状态

        Args:
            report_id: 报告 ID

        Returns:
            str: 报告状态 (processing/completed/failed)，失败返回 None
        """
        report_data = self.get(report_id)
        if report_data:
            return report_data.get('status', 'unknown')
        return None

    def wait_for_completion(self, report_id, max_wait=120, interval=3):
        """
        等待报告生成完成

        Args:
            report_id: 报告 ID
            max_wait: 最大等待时间(秒)
            interval: 检查间隔(秒)

        Returns:
            bool: 成功返回 True，超时或失败返回 False
        """
        elapsed = 0
        while elapsed < max_wait:
            status = self.get_status(report_id)
            
            if status == 'completed':
                self.logger.info(f'报告 {report_id} 生成完成')
                return True
            elif status == 'failed':
                self.logger.error(f'报告 {report_id} 生成失败')
                return False
            
            time.sleep(interval)
            elapsed += interval
            
        self.logger.warning(f'等待报告 {report_id} 生成超时')
        return False

    def download(self, report_id, format='html'):
        """
        下载报告

        Args:
            report_id: 报告 ID
            format: 报告格式 (html/pdf)

        Returns:
            bytes: 报告内容，失败返回 None
        """
        try:
            download_url = f"{self.api_base_url}/reports/download/{report_id}.{format}"
            
            self.logger.info(f'开始下载报告: {download_url}')
            
            response = requests.get(
                download_url, 
                headers=self.auth_headers, 
                verify=False,
                timeout=120
            )
            
            if response.status_code == 200:
                self.logger.info(f'报告下载成功，大小: {len(response.content)} bytes')
                return response.content
            
            self.logger.error(f'下载报告失败: HTTP {response.status_code}, URL: {download_url}')
            return None
            
        except Exception as e:
            self.logger.error(f'Download Report Failed: {str(e)}', exc_info=True)
            return None

    def delete(self, report_id):
        """
        删除报告

        Args:
            report_id: 报告 ID

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        try:
            url = f"{self.report_api}/{report_id}"
            response = requests.delete(
                url, 
                headers=self.auth_headers, 
                verify=False,
                timeout=30
            )
            
            if response.status_code in [200, 204]:
                self.logger.info(f'报告 {report_id} 删除成功')
                return True
            
            self.logger.error(f'删除报告失败: HTTP {response.status_code}')
            return False
            
        except Exception as e:
            self.logger.error(f'Delete Report Failed: {str(e)}', exc_info=True)
            return False
