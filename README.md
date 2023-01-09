### 一、设置阿里云服务器账户

修改配置文件config.cfg，将[oss]中的参数修改成自己的阿里云服务器账户信息

### 二、上传文件文法

将本地文件上传至阿里云服务器中，无论什么格式的文件加密后都以**txt文件格式**存储，例：本地文件test.jpg,上传至阿里云后文件名为test.jpg.txt

`python main.py -U True -S [本地待上传文件路径] -T [阿里云文件夹路径] -E [加密方法] -K[RSA密钥地址]`

- 本地待上传文件路径：是一个**文件**的路径，不是文件夹

- 阿里云文件夹路径：是目标**文件夹**路径，不是文件名

- 加密方式：文件加密的方式，在“DES”，“DES3”，“AES”中选择

- RSA密钥路径：是一个文件夹路径，创建一个新的RSA密钥并保存在此文件夹中。**若已经有RSA密钥，则不用键入该参数**

### 三、下载文件方法

`python main.py -U False -S [阿里云待下载文件路径] -T [本地文件夹路径] -E [加密方法]`

- 阿里云待下载文件路径：是一个**文件**的路径，不是文件夹，且文件名是以.txt结尾

- 本地文件夹路径：是目标**文件夹**路径，不是文件名

- 加密方式：文件加密的方式，在“DES”，“DES3”，“AES”中选择