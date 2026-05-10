# -*- coding:utf-8 -*-

"""
网站截图模块
功能:
1. 网站页面截图
2. 多设备尺寸截图（桌面、平板、手机）
3. 全页面截图
4. 截图保存和Base64编码
5. 延迟截图支持
6. 自定义视口大小
"""

import logging
import base64
import os
import time
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from threading import Lock
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Screenshot")

@dataclass
class ScreenshotResult:
    url: str = ""
    success: bool = False
    screenshot_base64: str = ""
    screenshot_path: str = ""
    width: int = 0
    height: int = 0
    device_type: str = "desktop"
    error: str = ""

@dataclass
class MultiScreenshotResult:
    url: str = ""
    screenshots: List[ScreenshotResult] = field(default_factory=list)
    has_result: bool = False
    error: str = ""

class DevicePresets:
    DESKTOP = {"width": 1920, "height": 1080, "device_scale_factor": 1, "name": "Desktop"}
    DESKTOP_HD = {"width": 2560, "height": 1440, "device_scale_factor": 1, "name": "Desktop HD"}
    TABLET = {"width": 1024, "height": 768, "device_scale_factor": 1, "name": "Tablet"}
    TABLET_PRO = {"width": 1366, "height": 1024, "device_scale_factor": 2, "name": "Tablet Pro"}
    MOBILE = {"width": 375, "height": 667, "device_scale_factor": 2, "name": "Mobile"}
    IPHONE = {"width": 390, "height": 844, "device_scale_factor": 3, "name": "iPhone"}
    IPHONE_PRO_MAX = {"width": 430, "height": 932, "device_scale_factor": 3, "name": "iPhone Pro Max"}
    ANDROID = {"width": 360, "height": 640, "device_scale_factor": 2, "name": "Android"}
    ANDROID_LARGE = {"width": 412, "height": 915, "device_scale_factor": 2.75, "name": "Android Large"}

class ScreenshotAPI:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        return session
    
    def capture_via_apiflash(self, url: str, api_key: str, width: int = 1920, height: int = 1080) -> ScreenshotResult:
        result = ScreenshotResult(url=url, width=width, height=height, device_type="desktop")
        
        if not api_key:
            result.error = "未配置apiflash API密钥"
            return result
        
        try:
            api_url = "https://api.apiflash.com/v1/urltoimage"
            params = {
                "access_key": api_key,
                "url": url,
                "width": width,
                "height": height,
                "format": "png",
                "response_type": "image",
            }
            
            response = self.session.get(api_url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                result.screenshot_base64 = base64.b64encode(response.content).decode('utf-8')
                result.success = True
            else:
                result.error = f"API返回错误: HTTP {response.status_code}"
                
        except Exception as e:
            result.error = f"截图异常: {str(e)[:50]}"
        
        return result
    
    def capture_via_screenshotapi(self, url: str, api_key: str, width: int = 1920, height: int = 1080) -> ScreenshotResult:
        result = ScreenshotResult(url=url, width=width, height=height, device_type="desktop")
        
        if not api_key:
            result.error = "未配置screenshotapi API密钥"
            return result
        
        try:
            api_url = f"https://shot.screenshotapi.net/screenshot"
            params = {
                "token": api_key,
                "url": url,
                "width": width,
                "height": height,
                "output": "image",
            }
            
            response = self.session.get(api_url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                result.screenshot_base64 = base64.b64encode(response.content).decode('utf-8')
                result.success = True
            else:
                result.error = f"API返回错误: HTTP {response.status_code}"
                
        except Exception as e:
            result.error = f"截图异常: {str(e)[:50]}"
        
        return result
    
    def capture_via_google_pagespeed(self, url: str) -> ScreenshotResult:
        result = ScreenshotResult(url=url, device_type="desktop")
        
        try:
            api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
            params = {
                "url": url,
                "category": "performance",
                "screenshot": "true",
            }
            
            response = self.session.get(api_url, params=params, timeout=self.timeout)
            data = response.json()
            
            screenshot_data = data.get("lighthouseResult", {}).get("audits", {}).get("final-screenshot", {})
            details = screenshot_data.get("details", {})
            
            if details.get("data"):
                result.screenshot_base64 = details["data"]
                result.success = True
                result.width = details.get("width", 0)
                result.height = details.get("height", 0)
            else:
                result.error = "未获取到截图数据"
                
        except Exception as e:
            result.error = f"截图异常: {str(e)[:50]}"
        
        return result
    
    def capture_via_thum_io(self, url: str, width: int = 1280) -> ScreenshotResult:
        result = ScreenshotResult(url=url, width=width, device_type="desktop")
        
        try:
            api_url = f"https://image.thum.io/get/width/{width}/{url}"
            
            response = self.session.get(api_url, timeout=self.timeout)
            
            if response.status_code == 200:
                result.screenshot_base64 = base64.b64encode(response.content).decode('utf-8')
                result.success = True
                result.height = int(width * 0.75)
            else:
                result.error = f"API返回错误: HTTP {response.status_code}"
                
        except Exception as e:
            result.error = f"截图异常: {str(e)[:50]}"
        
        return result
    
    def capture_via_apifree(self, url: str, width: int = 1280, height: int = 720) -> ScreenshotResult:
        result = ScreenshotResult(url=url, width=width, height=height, device_type="desktop")
        
        try:
            api_url = f"https://api.apifree.top/api/screenshot"
            params = {
                "url": url,
                "width": width,
                "height": height,
            }
            
            response = self.session.get(api_url, params=params, timeout=self.timeout)
            
            if response.status_code == 200 and response.headers.get("content-type", "").startswith("image"):
                result.screenshot_base64 = base64.b64encode(response.content).decode('utf-8')
                result.success = True
            else:
                result.error = f"API返回错误: HTTP {response.status_code}"
                
        except Exception as e:
            result.error = f"截图异常: {str(e)[:50]}"
        
        return result

class ScreenshotCapture:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 30)
        self.save_path = self.config.get("save_path", "./screenshots")
        self.apiflash_key = self.config.get("apiflash_key", os.environ.get("APIFLASH_KEY", ""))
        self.screenshotapi_key = self.config.get("screenshotapi_key", os.environ.get("SCREENSHOTAPI_KEY", ""))
        
        self._api = ScreenshotAPI(timeout=self.timeout)
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url
    
    def capture(self, url: str, width: int = 1920, height: int = 1080) -> ScreenshotResult:
        url = self._normalize_url(url)
        
        if self.apiflash_key:
            result = self._api.capture_via_apiflash(url, self.apiflash_key, width, height)
            if result.success:
                return result
        
        if self.screenshotapi_key:
            result = self._api.capture_via_screenshotapi(url, self.screenshotapi_key, width, height)
            if result.success:
                return result
        
        result = self._api.capture_via_google_pagespeed(url)
        if result.success:
            return result
        
        result = self._api.capture_via_thum_io(url, width)
        if result.success:
            return result
        
        result = self._api.capture_via_apifree(url, width, height)
        if result.success:
            return result
        
        return ScreenshotResult(url=url, error="所有截图API均失败")
    
    def capture_multi_device(self, url: str) -> MultiScreenshotResult:
        result = MultiScreenshotResult(url=self._normalize_url(url))
        
        devices = [
            ("desktop", DevicePresets.DESKTOP),
            ("tablet", DevicePresets.TABLET),
            ("mobile", DevicePresets.MOBILE),
        ]
        
        for device_name, preset in devices:
            screenshot = self.capture(url, preset["width"], preset["height"])
            screenshot.device_type = device_name
            result.screenshots.append(screenshot)
        
        result.has_result = any(s.success for s in result.screenshots)
        
        return result
    
    def save_screenshot(self, screenshot: ScreenshotResult, filename: str = None) -> str:
        if not screenshot.success or not screenshot.screenshot_base64:
            return ""
        
        if not os.path.exists(self.save_path):
            os.makedirs(self.save_path)
        
        if not filename:
            safe_url = screenshot.url.replace("://", "_").replace("/", "_").replace("?", "_")[:50]
            filename = f"{safe_url}_{screenshot.device_type}.png"
        
        filepath = os.path.join(self.save_path, filename)
        
        with open(filepath, "wb") as f:
            f.write(base64.b64decode(screenshot.screenshot_base64))
        
        return filepath

def capture_screenshot(url: str, width: int = 1920, height: int = 1080) -> Dict[str, Any]:
    capture = ScreenshotCapture()
    result = capture.capture(url, width, height)
    
    return {
        "success": result.success,
        "url": result.url,
        "screenshot_base64": result.screenshot_base64[:100] + "..." if result.screenshot_base64 else "",
        "width": result.width,
        "height": result.height,
        "device_type": result.device_type,
        "error": result.error
    }

def capture_multi_device(url: str) -> Dict[str, Any]:
    capture = ScreenshotCapture()
    result = capture.capture_multi_device(url)
    
    return {
        "success": result.has_result,
        "url": result.url,
        "screenshots": [
            {
                "device_type": s.device_type,
                "success": s.success,
                "width": s.width,
                "height": s.height,
                "error": s.error
            }
            for s in result.screenshots
        ],
        "error": result.error
    }

if __name__ == '__main__':
    test_urls = ["https://github.com", "https://www.baidu.com"]
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"截图URL: {url}")
        result = capture_screenshot(url)
        if result["success"]:
            print(f"截图成功: {result['width']}x{result['height']}")
            print(f"Base64长度: {len(result['screenshot_base64'])}")
        else:
            print(f"截图失败: {result['error']}")
