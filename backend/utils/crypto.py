# -*- coding:utf-8 -*-

"""
数据加解密工具模块
功能:
1. 对称加密 (AES-CBC, AES-GCM, ChaCha20, Fernet)
2. 非对称加密 (RSA)
3. 哈希算法 (MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2)
4. 编码算法 (Base64, URL编码, Hex)
5. 消息认证码 (HMAC)
6. 密码哈希 (PBKDF2, bcrypt, Argon2)
7. JWT令牌
8. 密码强度检测
9. 随机数生成
"""

import base64
import hashlib
import hmac
import secrets
import re
import string
from typing import Optional, Tuple, Union, Dict, Any
from dataclasses import dataclass


@dataclass
class CryptoResult:
    success: bool
    data: Optional[bytes] = None
    error: str = ""


@dataclass
class PasswordStrength:
    score: int
    level: str
    suggestions: list


class HashUtils:
    """哈希算法工具类"""
    
    @staticmethod
    def md5(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def md5_file(filepath: str) -> str:
        hash_obj = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    @staticmethod
    def sha1(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha1(data).hexdigest()
    
    @staticmethod
    def sha256(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def sha512(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha512(data).hexdigest()
    
    @staticmethod
    def sha3_256(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha3_256(data).hexdigest()
    
    @staticmethod
    def sha3_512(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha3_512(data).hexdigest()
    
    @staticmethod
    def blake2b(data: Union[str, bytes], digest_size: int = 64) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.blake2b(data, digest_size=digest_size).hexdigest()
    
    @staticmethod
    def blake2s(data: Union[str, bytes], digest_size: int = 32) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.blake2s(data, digest_size=digest_size).hexdigest()
    
    @staticmethod
    def hash_file(filepath: str, algorithm: str = "sha256") -> str:
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }
        if algorithm not in algorithms:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        hash_obj = algorithms[algorithm]()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()


class EncodeUtils:
    """编码工具类"""
    
    @staticmethod
    def base64_encode(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return base64.b64encode(data).decode("utf-8")
    
    @staticmethod
    def base64_decode(data: str) -> bytes:
        return base64.b64decode(data)
    
    @staticmethod
    def base64url_encode(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")
    
    @staticmethod
    def base64url_decode(data: str) -> bytes:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    
    @staticmethod
    def hex_encode(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return data.hex()
    
    @staticmethod
    def hex_decode(data: str) -> bytes:
        return bytes.fromhex(data)
    
    @staticmethod
    def url_encode(data: str) -> str:
        from urllib.parse import quote
        return quote(data, safe="")
    
    @staticmethod
    def url_decode(data: str) -> str:
        from urllib.parse import unquote
        return unquote(data)
    
    @staticmethod
    def rot13(data: str) -> str:
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)


class AESCipher:
    """AES对称加密类"""
    
    def __init__(self, key: Optional[bytes] = None):
        self.key = key or secrets.token_bytes(32)
    
    def _get_crypto(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.backends import default_backend
            return Cipher, algorithms, modes, padding, default_backend
        except ImportError:
            raise ImportError("请安装 cryptography: pip install cryptography")
    
    @staticmethod
    def generate_key(bits: int = 256) -> bytes:
        if bits not in [128, 192, 256]:
            raise ValueError("密钥长度必须是128、192或256位")
        return secrets.token_bytes(bits // 8)
    
    def encrypt_cbc(self, plaintext: Union[str, bytes], key: Optional[bytes] = None) -> Dict[str, bytes]:
        Cipher, algorithms, modes, padding, default_backend = self._get_crypto()
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        
        key = key or self.key
        iv = secrets.token_bytes(16)
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return {"iv": iv, "ciphertext": ciphertext, "key": key}
    
    def decrypt_cbc(self, iv: bytes, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        Cipher, algorithms, modes, padding, default_backend = self._get_crypto()
        
        key = key or self.key
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_gcm(self, plaintext: Union[str, bytes], key: Optional[bytes] = None, 
                    associated_data: Optional[bytes] = None) -> Dict[str, bytes]:
        Cipher, algorithms, modes, padding, default_backend = self._get_crypto()
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        
        key = key or self.key
        nonce = secrets.token_bytes(12)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {"nonce": nonce, "ciphertext": ciphertext, "tag": encryptor.tag, "key": key}
    
    def decrypt_gcm(self, nonce: bytes, ciphertext: bytes, tag: bytes, 
                    key: Optional[bytes] = None, associated_data: Optional[bytes] = None) -> bytes:
        Cipher, algorithms, modes, padding, default_backend = self._get_crypto()
        
        key = key or self.key
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def encrypt(self, plaintext: Union[str, bytes], key: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        result = self.encrypt_cbc(plaintext, key)
        return result["iv"], result["ciphertext"], result["key"]
    
    def decrypt(self, iv: bytes, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        return self.decrypt_cbc(iv, ciphertext, key)


class ChaCha20Cipher:
    """ChaCha20流加密类"""
    
    def __init__(self, key: Optional[bytes] = None):
        self.key = key or secrets.token_bytes(32)
    
    def _get_crypto(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
            from cryptography.hazmat.backends import default_backend
            return Cipher, algorithms, default_backend
        except ImportError:
            raise ImportError("请安装 cryptography: pip install cryptography")
    
    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)
    
    def encrypt(self, plaintext: Union[str, bytes], key: Optional[bytes] = None) -> Dict[str, bytes]:
        Cipher, algorithms, default_backend = self._get_crypto()
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        
        key = key or self.key
        nonce = secrets.token_bytes(16)
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {"nonce": nonce, "ciphertext": ciphertext, "key": key}
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        Cipher, algorithms, default_backend = self._get_crypto()
        
        key = key or self.key
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext


class FernetCipher:
    """Fernet对称加密类 (简单易用)"""
    
    def __init__(self, key: Optional[bytes] = None):
        self.key = key
    
    def _get_fernet(self):
        try:
            from cryptography.fernet import Fernet
            return Fernet
        except ImportError:
            raise ImportError("请安装 cryptography: pip install cryptography")
    
    @staticmethod
    def generate_key() -> bytes:
        try:
            from cryptography.fernet import Fernet
            return Fernet.generate_key()
        except ImportError:
            raise ImportError("请安装 cryptography: pip install cryptography")
    
    def encrypt(self, plaintext: Union[str, bytes], key: Optional[bytes] = None) -> bytes:
        Fernet = self._get_fernet()
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        
        key = key or self.key
        if not key:
            raise ValueError("需要提供密钥")
        
        f = Fernet(key)
        return f.encrypt(plaintext)
    
    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        Fernet = self._get_fernet()
        
        key = key or self.key
        if not key:
            raise ValueError("需要提供密钥")
        
        f = Fernet(key)
        return f.decrypt(ciphertext)


class RSACipher:
    """RSA非对称加密类"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._private_key = None
        self._public_key = None
    
    def _get_rsa(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.backends import default_backend
            return rsa, padding, hashes, serialization, default_backend
        except ImportError:
            raise ImportError("请安装 cryptography: pip install cryptography")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        rsa, padding, hashes, serialization, default_backend = self._get_rsa()
        
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
        
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt(self, plaintext: Union[str, bytes], public_key_pem: Optional[bytes] = None) -> bytes:
        rsa, padding, hashes, serialization, default_backend = self._get_rsa()
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        
        if public_key_pem:
            public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        else:
            public_key = self._public_key
        
        if not public_key:
            raise ValueError("需要提供公钥")
        
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, private_key_pem: Optional[bytes] = None) -> bytes:
        rsa, padding, hashes, serialization, default_backend = self._get_rsa()
        
        if private_key_pem:
            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
        else:
            private_key = self._private_key
        
        if not private_key:
            raise ValueError("需要提供私钥")
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    def sign(self, message: Union[str, bytes], private_key_pem: Optional[bytes] = None) -> bytes:
        rsa, padding, hashes, serialization, default_backend = self._get_rsa()
        
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        if private_key_pem:
            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
        else:
            private_key = self._private_key
        
        if not private_key:
            raise ValueError("需要提供私钥")
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify(self, message: Union[str, bytes], signature: bytes, 
               public_key_pem: Optional[bytes] = None) -> bool:
        rsa, padding, hashes, serialization, default_backend = self._get_rsa()
        
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        if public_key_pem:
            public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        else:
            public_key = self._public_key
        
        if not public_key:
            raise ValueError("需要提供公钥")
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


class HMACUtils:
    """HMAC消息认证码工具类"""
    
    @staticmethod
    def hmac_sha256(key: Union[str, bytes], message: Union[str, bytes]) -> str:
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()
    
    @staticmethod
    def hmac_sha512(key: Union[str, bytes], message: Union[str, bytes]) -> str:
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")
        return hmac.new(key, message, hashlib.sha512).hexdigest()
    
    @staticmethod
    def hmac_md5(key: Union[str, bytes], message: Union[str, bytes]) -> str:
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")
        return hmac.new(key, message, hashlib.md5).hexdigest()
    
    @staticmethod
    def verify_hmac(key: Union[str, bytes], message: Union[str, bytes], 
                    expected_hmac: str, algorithm: str = "sha256") -> bool:
        if algorithm == "sha256":
            computed = HMACUtils.hmac_sha256(key, message)
        elif algorithm == "sha512":
            computed = HMACUtils.hmac_sha512(key, message)
        elif algorithm == "md5":
            computed = HMACUtils.hmac_md5(key, message)
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
        return hmac.compare_digest(computed, expected_hmac)


class PasswordHasher:
    """密码哈希工具类"""
    
    @staticmethod
    def pbkdf2_hmac(password: str, salt: Optional[bytes] = None, 
                    iterations: int = 100000, hash_name: str = "sha256") -> Tuple[str, bytes]:
        if salt is None:
            salt = secrets.token_bytes(16)
        
        if isinstance(password, str):
            password = password.encode("utf-8")
        
        dk = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations)
        return dk.hex(), salt
    
    @staticmethod
    def verify_pbkdf2(password: str, stored_hash: str, salt: bytes, 
                       iterations: int = 100000, hash_name: str = "sha256") -> bool:
        computed_hash, _ = PasswordHasher.pbkdf2_hmac(password, salt, iterations, hash_name)
        return hmac.compare_digest(computed_hash, stored_hash)
    
    @staticmethod
    def bcrypt_hash(password: str, rounds: int = 12) -> str:
        try:
            import bcrypt
        except ImportError:
            raise ImportError("请安装 bcrypt: pip install bcrypt")
        
        if isinstance(password, str):
            password = password.encode("utf-8")
        
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password, salt).decode("utf-8")
    
    @staticmethod
    def bcrypt_verify(password: str, hashed: str) -> bool:
        try:
            import bcrypt
        except ImportError:
            raise ImportError("请安装 bcrypt: pip install bcrypt")
        
        if isinstance(password, str):
            password = password.encode("utf-8")
        if isinstance(hashed, str):
            hashed = hashed.encode("utf-8")
        
        return bcrypt.checkpw(password, hashed)
    
    @staticmethod
    def argon2_hash(password: str) -> str:
        try:
            import argon2
        except ImportError:
            raise ImportError("请安装 argon2-cffi: pip install argon2-cffi")
        
        hasher = argon2.PasswordHasher()
        return hasher.hash(password)
    
    @staticmethod
    def argon2_verify(password: str, hashed: str) -> bool:
        try:
            import argon2
        except ImportError:
            raise ImportError("请安装 argon2-cffi: pip install argon2-cffi")
        
        hasher = argon2.PasswordHasher()
        try:
            hasher.verify(hashed, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False


class PasswordStrengthChecker:
    """密码强度检测类"""
    
    @staticmethod
    def check(password: str) -> PasswordStrength:
        score = 0
        suggestions = []
        
        if len(password) < 8:
            suggestions.append("密码长度应至少8个字符")
        elif len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            suggestions.append("添加小写字母")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            suggestions.append("添加大写字母")
        
        if re.search(r'\d', password):
            score += 1
        else:
            suggestions.append("添加数字")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            suggestions.append("添加特殊字符")
        
        common_passwords = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "login"
        ]
        if password.lower() in common_passwords:
            score = 0
            suggestions = ["避免使用常见密码"]
        
        if re.search(r'(.)\1{2,}', password):
            score -= 1
            suggestions.append("避免连续重复字符")
        
        if re.search(r'(123|abc|qwe|asd)', password.lower()):
            score -= 1
            suggestions.append("避免连续字符序列")
        
        score = max(0, min(5, score))
        
        levels = {
            0: "非常弱",
            1: "弱",
            2: "一般",
            3: "中等",
            4: "强",
            5: "非常强"
        }
        
        return PasswordStrength(
            score=score,
            level=levels.get(score, "未知"),
            suggestions=suggestions
        )


class JWTUtils:
    """JWT令牌工具类"""
    
    @staticmethod
    def encode(payload: dict, secret: str, algorithm: str = "HS256", 
               expires_in: int = 3600) -> str:
        import json
        import time
        
        header = {"alg": algorithm, "typ": "JWT"}
        
        payload = payload.copy()
        if "exp" not in payload:
            payload["exp"] = int(time.time()) + expires_in
        if "iat" not in payload:
            payload["iat"] = int(time.time())
        
        header_b64 = EncodeUtils.base64url_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = EncodeUtils.base64url_encode(json.dumps(payload, separators=(',', ':')))
        
        message = f"{header_b64}.{payload_b64}"
        
        if algorithm == "HS256":
            signature = HMACUtils.hmac_sha256(secret, message)
        elif algorithm == "HS512":
            signature = HMACUtils.hmac_sha512(secret, message)
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        signature_b64 = EncodeUtils.base64url_encode(signature)
        
        return f"{message}.{signature_b64}"
    
    @staticmethod
    def decode(token: str, secret: str, algorithm: str = "HS256", 
               verify_exp: bool = True) -> dict:
        import json
        import time
        
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("无效的JWT格式")
        
        header_b64, payload_b64, signature_b64 = parts
        
        message = f"{header_b64}.{payload_b64}"
        
        if algorithm == "HS256":
            expected_signature = HMACUtils.hmac_sha256(secret, message)
        elif algorithm == "HS512":
            expected_signature = HMACUtils.hmac_sha512(secret, message)
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        provided_signature = EncodeUtils.base64url_decode(signature_b64).decode("utf-8")
        
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise ValueError("签名验证失败")
        
        payload = json.loads(EncodeUtils.base64url_decode(payload_b64))
        
        if verify_exp and "exp" in payload and payload["exp"] < int(time.time()):
            raise ValueError("Token已过期")
        
        return payload
    
    @staticmethod
    def decode_without_verify(token: str) -> dict:
        import json
        
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("无效的JWT格式")
        
        header = json.loads(EncodeUtils.base64url_decode(parts[0]))
        payload = json.loads(EncodeUtils.base64url_decode(parts[1]))
        
        return {"header": header, "payload": payload}


class CryptoUtils:
    """加密工具类"""
    
    @staticmethod
    def generate_random_bytes(length: int) -> bytes:
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_random_string(length: int, charset: Optional[str] = None) -> str:
        if charset is None:
            charset = string.ascii_letters + string.digits
        return "".join(secrets.choice(charset) for _ in range(length))
    
    @staticmethod
    def generate_password(length: int = 16, include_special: bool = True) -> str:
        charset = string.ascii_letters + string.digits
        if include_special:
            charset += "!@#$%^&*"
        
        password = []
        password.append(secrets.choice(string.ascii_lowercase))
        password.append(secrets.choice(string.ascii_uppercase))
        password.append(secrets.choice(string.digits))
        if include_special:
            password.append(secrets.choice("!@#$%^&*"))
        
        for _ in range(length - len(password)):
            password.append(secrets.choice(charset))
        
        secrets.SystemRandom().shuffle(password)
        return "".join(password)
    
    @staticmethod
    def generate_uuid() -> str:
        import uuid
        return str(uuid.uuid4())
    
    @staticmethod
    def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def derive_key(password: str, salt: bytes, length: int = 32, 
                   iterations: int = 100000) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=length
        )
