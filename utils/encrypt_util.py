# -*- coding: UTF-8 -*-
"""
@Author: zhHuang
@Date: 2023/1/5
"""
import os
import zlib
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES, DES3, PKCS1_v1_5
from typing import Union, Tuple


sym_list = ["AES", "DES", "DES3"]  # 可选用的对称加密方法


class Cryptor:

    def __init__(self, sym_encrypt_type: str) -> None:
        assert sym_encrypt_type in sym_list, 'sym_encrypt_type must be in ["AES", "DES", "DES3"]!'

        # 对称加密的方法
        if sym_encrypt_type == 'DES':
            self.sym_encryption = DES
        elif sym_encrypt_type == 'DES3':
            self.sym_encryption = DES3
        else:
            self.sym_encryption = AES

        # 对称加密密钥的长度
        self.sym_key_len = 16 if sym_encrypt_type in ['AES', 'DES3'] else 8  # 对称加密密钥的长度

    def mixed_encrypt(self, data: Union[str, bytes], rsa_public_key: bytes) -> bytes:
        """对称加密数据，RSA加密密钥"""
        if isinstance(data, str):
            data = data.encode()

        # 对称加密并压缩
        data_enc, sym_key = self.sym_encrypt(data)
        data_enc = self.zip_data(data_enc)

        # 将对称加密的密钥用RSA加密
        sym_key_enc = self.rsa_encrypt(sym_key, rsa_public_key)

        # 将加密后的数据和加密后的密钥拼接在一起
        ciphertext = data_enc + sym_key_enc

        return ciphertext

    def mixed_decrypt(self, ciphertext: Union[str, bytes], rsa_private_key) -> bytes:
        """解密经 mixed_encrypt 方法加密的数据"""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()

        # 分离出数据和密钥
        data_enc, sym_key_enc = ciphertext[:-256], ciphertext[-256:]

        # RSA解密对称加密的密钥
        sym_key = self.rsa_decrypt(sym_key_enc, rsa_private_key)

        # 解压并解密对称加密的数据
        data_enc = self.unzip(data_enc)
        data = self.sym_decrypt(data_enc, sym_key)

        return data

    def sym_encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        """对称加密数据"""
        data = self.__padding(data)  # 对数据补零至长度为密钥长度的整数倍
        sym_key = Random.get_random_bytes(self.sym_key_len)  # 随机生成一次性密钥
        sym = self.sym_encryption.new(sym_key, self.sym_encryption.MODE_ECB)
        data_encrypted = sym.encrypt(data)  # 使用对称加密方法加密数据
        return data_encrypted, sym_key  # 返回加密后的数据以及一次性密钥

    def sym_decrypt(self, data_enc: bytes, key: bytes) -> bytes:
        """解密对称加密的数据"""
        sym = self.sym_encryption.new(key, self.sym_encryption.MODE_ECB)
        data = sym.decrypt(data_enc)  # 解密数据
        data = self.__unpadding(data)  # 去除掉数据前补的零
        return data

    def rsa_encrypt(self, data: bytes, key: bytes) -> bytes:
        """RSA加密数据"""
        cipher = PKCS1_v1_5.new(RSA.importKey(key))
        data_encrypted = cipher.encrypt(data)
        return data_encrypted

    def rsa_decrypt(self, data_enc: bytes, key: bytes) -> bytes:
        """解密RSA加密的数据"""
        cipher = PKCS1_v1_5.new(RSA.importKey(key))
        data = cipher.decrypt(data_enc, Random.new().read)
        return data

    @staticmethod
    def zip_data(data: bytes) -> bytes:
        """压缩数据"""
        return zlib.compress(data)

    @staticmethod
    def unzip(data: bytes) -> bytes:
        """解压缩数据"""
        return zlib.decompress(data)

    def __padding(self, data: bytes) -> bytes:
        """对数据补零至长度为密钥长度的整数倍"""
        while len(data) % self.sym_key_len != 0:
            data = b'\x00' + data
        return data

    @staticmethod
    def __unpadding(data: bytes) -> bytes:
        """去掉明文前补的零'\x00'"""
        while data[0:1] == b'\x00':
            data = data[1:]
        return data


def gen_rsa_key(save_dir: str) -> None:
    """生成一对密钥并保存至 save_dir 文件夹中"""
    key = RSA.generate(2048, Random.new().read)
    private_key, public_key = key.exportKey(), key.public_key().exportKey()
    private_key_path = os.path.join(save_dir, 'private_key.txt')
    public_key_path = os.path.join(save_dir, 'public_key.txt')
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    with open(public_key_path, 'wb') as f:
        f.write(public_key)
