---
title: 防SSH爆破自动封禁IP脚本
date: 2024-01-10 22:21:25
tags: python
categories: Python武器库 #分类
description: 防SSH爆破自动封禁IP脚本 #描述
top_img: /img/005.jpg #顶部背景图
cover: /img/6.jpg #文章封面
---

# 防SSH爆破自动封禁IP脚本

## 一、相关知识

### 1、ssh爆破后的痕迹残留

我们可以在Centos系统的 /var/log/secure（Debian 是/var/log/auth.log文件） 文件中看到有关ssh 的登陆信息，共有如下三种情况：

```
登陆成功：Accepted password for root from 192.168.44.1 port 50854 ssh2
登陆失败：Failed password for root from 192.168.44.1 port 50854 ssh2
用户不存在：Invalid user test from 192.168.31.50 port 54169
```

### 2、如何封禁IP

有关IP封禁的黑白名单文件：

```
IP黑名单：/etc/hosts.deny
IP白名单：/etc/hosts.allow
```

示例：

```
sshd:192.168.31.50		#封禁192.168.31.50这个IP的sshd服务
all:192.168.31.50		#封禁192.168.31.50这个IP的所有服务
```

## 二、Python防SSH爆破脚本

1、以下皆以Centos系统为例，我们可以利用多进程实时监控/ var/log/secure 

```
# 读取安全日志
popen = subprocess.Popen('tail -f ' + logFile, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# 开始监控
while True:
    time.sleep(0.1)
    line = popen.stdout.readline().strip()
    if line:
    	pass
```

2、遇到不存在的用户尝试登陆的时候直接封IP

```
abnormal_invalid_user = re.search('Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)', str(line))
abnormal_failed_password = re.search('Failed password for \w+ from (\d+\.\d+\.\d+\.\d+)', str(line))
if abnormal_invalid_user and not denyDict.get(abnormal_invalid_user.group(1)):
	subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(abnormal_invalid_user.group(1), hostDeny))
	denyDict[abnormal_invalid_user.group(1)] = time.time()
	time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
	print('{} --- ip:{} 因为登陆错误用户名 被拉入黑名单'.format(time_str, abnormal_invalid_user.group(1)))
```

3、遇到正确的用户的名，但是密码失败次数超过上限封IP

```
elif abnormal_failed_password:
	ip = abnormal_failed_password.group(1)
	tempIP[ip] = tempIP.get(ip, 0) + 1
	if tempIP[ip] > password_wrong_num and not denyDict.get(ip):
		subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny))
		denyDict[ip] = time.time()
		time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
		print('{} --- ip:{} 因为密码错误次数超过上限 被拉入黑名单'.format(time_str, ip))
```

4、检查解封，达到限制的时间之后解封IP

```
# 检查黑名单中的IP地址是否超过解封时间，若超过则解封
end_time = time.time()
for ip, start_time in list(denyDict.items()):  # 使用list()将字典项转换为列表项以避免在迭代时修改字典大小
    if end_time - start_time > unblock_time:
        subprocess.getoutput('sed -i "/^sshd:{}/d" {}'.format(ip, hostDeny))
        denyDict.pop(ip)  # 使用 pop() 方法从字典中彻底删除指定键值对
        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        print('{} --- ip:{} 已从黑名单中解封'.format(time_str, ip))
```

## 三、完整脚本代码

如下violate_blastIP.py 脚本代码：

```
import time
import re
import subprocess
from multiprocessing import Process

logFile = '/var/log/secure'     # 安全日志文件路径
hostDeny = '/etc/hosts.deny'    # 黑名单文件路径
password_wrong_num = 3      # 密码错误次数阈值
unblock_time = 10 * 60 * 60  # 解封时间：10小时

# 获取已经加入黑名单的IP，转换为字典
def getDenyIP():
    denyDict = {}
    with open(hostDeny, 'r') as file:  # 使用with语句以确保文件在使用后被正确关闭
        for ip in file.readlines():
            abnormal = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip)
            if abnormal:
                denyDict[abnormal.group(1)] = time.time()
    return denyDict

# 监控方法
def monitorLog(logFile):
    # 统计密码错误的次数
    tempIP = {}
    # 获取已经进入黑名单的IP
    denyDict = getDenyIP()
    # 读取安全日志
    popen = subprocess.Popen('tail -f ' + logFile, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # 开始监控
    print("------ SSH防爆破脚本开启 ------")
    while True:
        time.sleep(0.1)
        line = popen.stdout.readline().strip()
        if line:
            abnormal_invalid_user = re.search('Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)', str(line))
            abnormal_failed_password = re.search('Failed password for \w+ from (\d+\.\d+\.\d+\.\d+)', str(line))
            if abnormal_invalid_user and not denyDict.get(abnormal_invalid_user.group(1)):
                subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(abnormal_invalid_user.group(1), hostDeny))
                denyDict[abnormal_invalid_user.group(1)] = time.time()
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                print('{} --- ip:{} 因为登陆错误用户名 被拉入黑名单'.format(time_str, abnormal_invalid_user.group(1)))
            elif abnormal_failed_password:
                ip = abnormal_failed_password.group(1)
                tempIP[ip] = tempIP.get(ip, 0) + 1
                if tempIP[ip] > password_wrong_num and not denyDict.get(ip):
                    subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny))
                    denyDict[ip] = time.time()
                    time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    print('{} --- ip:{} 因为密码错误次数超过上限 被拉入黑名单'.format(time_str, ip))
        
        # 检查黑名单中的IP地址是否超过解封时间，若超过则解封
        end_time = time.time()
        for ip, start_time in list(denyDict.items()):  # 使用list()将字典项转换为列表项以避免在迭代时修改字典大小
            if end_time - start_time > unblock_time:
                subprocess.getoutput('sed -i "/^sshd:{}/d" {}'.format(ip, hostDeny))
                denyDict.pop(ip)  # 使用 pop() 方法从字典中彻底删除指定键值对
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                print('{} --- ip:{} 已从黑名单中解封'.format(time_str, ip))

if __name__ == '__main__':
    monitorLog(logFile)
```

## 四、封禁效果

![1](1.png)

![2](2.png)

如下：IP192.168.31.50 被封禁ssh服务![3](3.png)

![4](4.png)

超过设定的时间将会自动解除封禁：![5](5.png)