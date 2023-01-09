# -*- coding: UTF-8 -*-
"""
@Author: zhHuang
@Date: 2023/1/7
"""
import os
from configparser import ConfigParser
import argparse

from utils import OSSBucket, Cryptor, gen_rsa_key


def main(args):
    # 创建RSA密钥对
    if args.rsa_key_dir is not None:
        print('\n创建RSA密钥...\n')
        gen_rsa_key(args.rsa_key_dir)

    # 加密并上传文件或下载并解密文件
    if args.upload:
        upload(args.source_file, args.target_dir, args)
        print('加密并上传成功！')
    else:
        download(args.source_file, args.target_dir, args)
        print('下载并解密成功！')


def upload(local_file_path: str, oss_dir_path: str, args) -> None:
    """将本地文件加密并上传至阿里云服务器中"""
    assert os.path.exists(local_file_path), 'The file does not exist, please check whether the file path is correct!'

    # 载入RSA公钥
    rsa_public_key = b''
    with open(args.rsa_public_key_path, 'rb') as f:
        for x in f:
            rsa_public_key += x

    # 载入待上传文件
    data = b''
    with open(local_file_path, 'rb') as f:
        for x in f:
            data += x

    # 加密文件
    cryptor = Cryptor(args.encrypt_type)
    data_enc = cryptor.mixed_encrypt(data, rsa_public_key)

    # 将加密后的文件上传至阿里云服务器
    bucket = OSSBucket(args.access_key_id, args.access_key_secret, args.endpoint, args.bucket_name)
    bucket.upload_bytes(data_enc, oss_dir_path + '/' + os.path.basename(local_file_path) + '.txt')


def download(oss_file_path: str, local_dir_path: str, args) -> None:
    """将阿里云服务器中的文件下载至本地并解密"""
    bucket = OSSBucket(args.access_key_id, args.access_key_secret, args.endpoint, args.bucket_name)
    assert bucket.bucket.object_exists(oss_file_path),\
        'The file does not exist, please check whether the file path is correct!'

    # 将阿里云服务器中的文件下载到本地
    file_name = oss_file_path.split('/')[-1]
    local_file_path = os.path.join(local_dir_path, file_name)
    bucket.download(oss_file_path, local_file_path)

    # 载入加密文件
    data_enc = b''
    with open(local_file_path, 'rb') as f:
        for x in f:
            data_enc += x

    # 载入RSA私钥
    rsa_private_key = b''
    with open(args.rsa_private_key_path, 'rb') as f:
        for x in f:
            rsa_private_key += x

    # 解密数据
    cryptor = Cryptor(args.encrypt_type)
    data = cryptor.mixed_decrypt(data_enc, rsa_private_key)

    # 保存解密后的文件
    os.remove(local_file_path)
    with open(local_file_path[:-4], 'wb') as f:
        f.write(data)


def str2bool(s: str) -> bool:
    assert s in ['True', 'true', 'False', 'false']
    return s.lower() == 'true'


if __name__ == '__main__':
    cfg = ConfigParser()
    cfg.read('./config.cfg')

    parser = argparse.ArgumentParser(description='文件云端加密存储')
    parser.add_argument('-U', '--upload', required=True, type=str2bool,
                        help='True则为上传文件，False则为下载文件')
    parser.add_argument('-S', '--source_file', required=True, type=str,
                        help='待上传文件或待下载文件路径（文件）')
    parser.add_argument('-T', '--target_dir', required=True, type=str,
                        help='文件上传或文件下载的目标文件夹路径（文件夹）')
    parser.add_argument('-E', '--encrypt_type', default='DES', type=str,
                        help='文件加密方式')
    parser.add_argument('-K', '--rsa_key_dir', default=None, type=str,
                        help='创建RSA密钥并保存至该文件夹中，若为None则不新创建密钥')
    parser.add_argument('-i', '--access_key_id', default=cfg['oss']['access_key_id'], type=str)
    parser.add_argument('-s', '--access_key_secret', default=cfg['oss']['access_key_secret'], type=str)
    parser.add_argument('-e', '--endpoint', default=cfg['oss']['endpoint'], type=str)
    parser.add_argument('-b', '--bucket_name', default=cfg['oss']['bucket_name'], type=str)
    parser.add_argument('-u', '--rsa_public_key_path', default=cfg["rsa"]['rsa_public_key_path'], type=str)
    parser.add_argument('-r', '--rsa_private_key_path', default=cfg["rsa"]['rsa_private_key_path'], type=str)
    args = parser.parse_args()

    main(args)
