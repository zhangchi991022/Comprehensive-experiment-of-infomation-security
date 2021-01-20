# Kali通过跳板控制远程靶机

## 攻击思路：

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/1.PNG)

## 漏洞利用

### **CVE-2019-7238Nexus Repository Manager 3 RCE**：

**漏洞原理介绍：**

Nexus Repository Manager 3 是一款软件仓库，可以用来存储和分发Maven、NuGET等软件源仓库。其3.14.0及之前版本中，存在一处基于OrientDB自定义函数的任意JEXL表达式执行功能，而这处功能存在未授权访问漏洞，将可以导致任意命令执行漏洞。

**漏洞触发条件：**

登陆，admin admin123，在上传的位置随便传一个jar 的包。

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/2.png)

*漏洞触发成功需要保证仓库里至少有一个包存在*

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/3.png)

*通过攻击机操作以上四步，就成功拿到跳板机**shell**，**CVE-2019-7238**漏洞利用完成。CVE-2019-7238.py是该漏洞的利用脚本*

### CVE-2020-11651：

**漏洞原理介绍：**

 在 CVE-2020-11651 认证绕过漏洞中，攻击者通过构造恶意请求，可以绕过 Salt Master 的验证逻辑，调用相关未授权函数功能，从而可以造成远程命令执行漏洞：

ClearFuncs类会处理非认证的请求和暴露_send_pub()方法，可以用来直接在master publish服务器上对消息进行排队。这些消息可以用来触发minion来以root权限运行任意命令。

ClearFuncs类还会暴露 _prep_auth_info()方法，该方法会返回用来认证master服务器上本地root用户的命令的root key。然后root key就可以远程调用master 服务器的管理命令。这种无意的暴露提供给远程非认证的攻击者对salt master的与root权限等价的访问权限。

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/4.png)

通过这两行代码进行认证，就可以拿到root权限，其中CVE-2020-11651.py是该漏洞的利用脚本。

## 攻击检测思路：

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/5.png)

1、基于异常流量的监测

1.1跳板机检测：入口流量检测（suricata+splunk前端）

Suricata是一个免费、开源、成熟、快速、健壮的网络威胁检测引擎。Suricata引擎能够进行实时入侵检测(IDS)、内联入侵预防(IPS)、网络安全监控(NSM)和离线pcap处理。通过对不同协议的流量进行规则匹配来对异常流量进行检测，这次实验我们主要用到了IDS的功能，在规则文档里通过tcp协议流量的规则里的content字段的控制检测SQL注入里常见的“1=”，达到流量过滤的目的。

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/6.png)

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/7.png)

1.2靶机检测：出口流量检测（out.py）

使用python scapy抓取了白名单以外所有的流量发送，并使用lsof根据发送流量的端口号提取发送进程信息，最后将发报的进程及发报的目标ip全都报警出来以供防护与攻击溯源。

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/8.png)

2、基于主机行为检测：文件目录监控（filesys.py：watchdog插件）

该脚本读取config.conf配置文件内的敏感目录，可同时对多个目录及目录下文件进行监控。监控的内容包括文件的新建、删除、移动及修改。

![image](https://github.com/zhangchi991022/Comprehensive-experiment-of-infomation-security/blob/main/image/9.PNG)

