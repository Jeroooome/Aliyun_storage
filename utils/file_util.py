# -*- coding: UTF-8 -*-
"""
@Author: zhHuang
@Date: 2023/1/5
"""
import oss2


class OSSBucket:

    def __init__(self,
                 access_key_id: str,
                 access_key_secret: str,
                 endpoint: str,
                 bucket_name: str) -> None:
        self.auth = oss2.Auth(access_key_id, access_key_secret)
        self.bucket = oss2.Bucket(self.auth, endpoint, bucket_name)

    def upload_bytes(self, data: bytes, oss_file_root: str) -> None:
        """将bytes上传至oss中，存储为txt文件"""
        self.bucket.put_object(oss_file_root, data)

    def download(self, oss_file_root: str, local_file_root: str) -> None:
        """下载oss中的文件至本地"""
        if self.bucket.object_exists(oss_file_root):
            self.bucket.get_object_to_file(oss_file_root, local_file_root)
        else:
            print('待下载文件不存在！')
