import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES, DES3,DES
import random
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
'''AES_CBC'''
class AESCipher_CBC: 
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        self.iv = get_random_bytes(AES.block_size)  # 随机生成IV
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        encrypted_data = cipher.encrypt(raw)
        return self.iv + encrypted_data

    def decrypt(self, msg):
        self.iv = msg[:AES.block_size]  # 从加密数据中提取IV
        encrypted_data = msg[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return self._unpad(decrypted_data)

    def _pad(self, data):
        try:
            return pad(data, AES.block_size)
        except Exception as e:
            print(f"Error in AES padding: {e}")
            pass

    @staticmethod
    def _unpad(data):
        try:
            return unpad(data, AES.block_size)
        except Exception as e:
            print(f"Error in AES unpadding: {e}")
            pass

'''3DES_CBC'''
class TripleDESCipher_CBC:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        self.iv = get_random_bytes(DES3.block_size)  # 随机生成IV
        raw = self._pad(raw)
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv=self.iv)
        encrypted_data = cipher.encrypt(raw)
        return self.iv + encrypted_data

    def decrypt(self, msg):
        self.iv = msg[:DES3.block_size]  # 从加密数据中提取IV
        encrypted_data = msg[DES3.block_size:]
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv=self.iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return self._unpad(decrypted_data)

    def _pad(self, data):
        try:
            return pad(data, DES3.block_size)
        except Exception as e:
            print(f"Error in 3DES padding: {e}")
            pass

    @staticmethod
    def _unpad(data):
        try:
            return unpad(data, DES3.block_size)
        except Exception as e:
            print(f"Error in 3DES unpadding: {e}")
            pass

'''DES_CBC'''
class DESCipher_CBC:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        self.iv = get_random_bytes(DES.block_size)  # 随机生成IV
        raw = self._pad(raw)
        cipher = DES.new(self.key, DES.MODE_CBC, iv=self.iv)
        encrypted_data = cipher.encrypt(raw)
        return self.iv + encrypted_data

    def decrypt(self, msg):
        self.iv = msg[:DES.block_size]  # 从加密数据中提取IV
        encrypted_data = msg[DES.block_size:]
        cipher = DES.new(self.key, DES.MODE_CBC, iv=self.iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return self._unpad(decrypted_data)

    def _pad(self, data):
        try:
            return pad(data, DES.block_size)
        except Exception as e:
            print(f"Error in DES padding: {e}")
            pass

    @staticmethod
    def _unpad(data):
        try:
            return unpad(data, DES.block_size)
        except Exception as e:
            print(f"Error in DES unpadding: {e}")
            pass
        
'''AES_ECB'''
class AESCipher_ECB:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        # # create an AES cipher with the key and IV
        cipher = AES.new(self.key, AES.MODE_ECB)
        # # encode the encrypted raw data and return
        return cipher.encrypt(raw)

    def decrypt(self, msg):
        # create a new cipher for the given pair of key and iv
        decipher = AES.new(self.key, AES.MODE_ECB)
        # decrypt the encrypted data
        plain = decipher.decrypt(msg)
        # unpad the plain text to its original form
        return self._unpad(plain)

    def _pad(self, string):
        try:
            x = len(string) % AES.block_size
            pad = AES.block_size - x
            random_pad = bytes(random.sample(range(255), pad-1))
            string += random_pad + bytes([pad])
            return string
        except Exception as e:
            print(f"Error in AES : {e}")
            pass

    @staticmethod
    def _unpad(string):
        return string[:-string[-1]]
    
    
