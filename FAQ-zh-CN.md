* [自定义dnslog配置方法(URL型)](#0x01设置域名类型dnslog平台)
* [自定义dnslog配置方法(IP型)](#0x02设置ip类型dnslog平台)
* [扫描无动静或`send to log4j2 Scanner`无效](#10-为什么扫描没有动静)

## 1-如何使用
 0x01 去[releases](https://github.com/f0ng/log4j2burpscanner/releases/)下载最新插件
 
 0x02 加载完插件后，如果提示默认dnslog可以访问[https://log.xn--9tr.com](https://log.xn--9tr.com)，则可以不用设置其他dnslog
 
 0x03 如果默认dnslog访问不了，那么就需要去配置[ceye.io](https://ceye.io)，记得将isceye设置为true，然后填上token、ceye.io的地址，保存配置
 
 0x04 如果需要内网dnslog，那么将isceye设置为false， 将内网dnslog填入privatednslogurl，内网dnslog查看的地址填入privatednsResponseurl，保存配置

## 2-自定义ceye发现没有效果?
 0x01 可能由于对界面处理得不是很好，导致按钮那里可能按下去没有触发事件，多按几次，可以去Extender→output页面查看保存是否成功
 
<img src="https://user-images.githubusercontent.com/48286013/145739783-e6b491ca-4959-4744-a1fe-4b15fb8287e2.png" width="800" height="150" />

 0x02 isceye参数需要改为true
 
<img src="https://user-images.githubusercontent.com/48286013/145739853-58f0130c-b841-45ca-8559-6feea6e97efa.png" width="650" height="130" />

## 3-默认dnslog平台访问不了是否影响结果?
 只要配置了ceye，默认dnslog访问不了不会影响结果
 
<img src="https://user-images.githubusercontent.com/48286013/145744984-1a2bd55d-8348-4863-8b68-bd0af03aa716.png" width="600" height="200" />
<img src="https://user-images.githubusercontent.com/48286013/145741263-14f6ec28-0fda-4211-ae3b-d67eed41d1db.png" width="650" height="200" />

## 4-为什么有些站点检测不出来?
 0x01 有些时候由于添加的请求头过多，导致服务器处理请求过慢，或造成无法响应，可以通过控制请求头参数进行控制，如自定义参数全部不勾选

 0x02 由于网络环境与dnslog的问题，导致请求不能及时响应，可以更换自定义dnslog尝试
 
 0x03 目标机器的dns查询较慢，导致dnslog平台没有及时收到请求，从而不报告漏洞
 
 0x04 如果都不是以上原因，且在logger里没有看到扫描请求包，可以提交issue

## 5-为什么有些请求不会扫描?（加载了插件，没有进行扫描）
 0x01 本插件是通过Passive接口进行扫描，如果第一次扫描过了，第二次再次加载插件，是默认不会扫描的，需要右键数据包，进行`send to log4j2 scanner`即可
 
 0x02 检查数据包的host是否在白名单内
 
 0x03 检查`passive`是否开启。（Dashborad模块内开启）
 
 0x04 可以点击按钮`test dnslog delay`测试当前环境，如果没有配置ceye和自定义dnslog的话，会使用默认dnslog，但是默认dnslog有时会加载不出来，就会导致不进行扫描

## 6-导入插件报错：java.lang.NullPointerException: Cannot invoke "burp.IHttpRequestResponse.getHttpService()" because "this.currentlyDisplayedItem" is null之类
 0x01 burp的jdk版本太高，可以尝试降低burp的jdk版本，位置在Extender→Options→Java Environment→Folder for loading library JAR files(optional)→Select folder，作者的jdk版本在1.8_231
 
 0x02 自行编译插件即可，下载源码，输入命令mvn package

## 7-如何编译?(编译导入报错与启动burp的jdk版本、Burp Extender模块jdk版本都有关系)
 下载源码至本地，命令行输入，mvn package，即可在target得到jar，使用burp导入jar即可
 
![image](https://user-images.githubusercontent.com/48286013/146297735-1e19be83-2111-46e1-9e08-83697762ea7e.png)

## 8-dnslog配图教程
 ### 0x01设置域名类型dnslog平台
 
 根据默认dnslog平台，github: [DNSLog-Platform-Golang](https://github.com/yumusb/DNSLog-Platform-Golang)
 
 ### 0x001 获取dnslog与token
 
 首先访问搭建好的dnslog平台这里举例为 `http://1.1.1.1` ，获取dnslog记录域名，如`test.f0ng.cn`，再获取dnslog平台的token，如`f0ngf0ng`
 
 ### 0x002 填写配置
 
 `privatednslogurl`设置为`test.f0ng.cn`
 
 由于默认dnslog平台特性，获取响应的记录格式为`http://域名/yourtoken`，所以这里我设置`privatednsResponseurl`为`http://1.1.1.1/f0ngf0ng`即可
 
  <img src="https://user-images.githubusercontent.com/48286013/146548135-143782d0-c8ad-4b53-bcec-436b4af4235d.png" width="600" height="500" />
  
 ### 0x003 保存配置
 点击Save按钮，保存配置，即可

 ### 0x02设置IP类型dnslog平台 
 ###  准确一点，应该是IP类型的监控平台。
 
  设置`privatednslogurl`为内网可以访问到的域名即可，如`127.0.0.1:8001`，记得勾选isip，标明dnslog属性为ip

   <img src="https://user-images.githubusercontent.com/48286013/146288432-c14f8a7d-9ae6-4b3d-b9ea-0a50b82c94f8.png" width="650" height="400" />
   
   
 ## 9-为什么扫到的漏洞没有数字对参数进行标识？
 原因：可能设置了`isip`属性，导致payload不对参数标识
 解决：将`isip`的勾选去掉

## 10-为什么扫描没有动静
### 或者(`send to log4j2 scanner`没有动静)

 原因在于jdk版本太高的问题，经测试，和`Extender`→`Options`→`Java Environment`→`Folder for loading library JAR files(optional)`→`Select folder`的jdk版本有关
 
 0x01 如果`Java Environment`的jdk过高，经测试15的jdk是不行的，一些新版本jdk，如14 13可能也不行，换老版本jdk；大版本号低，小版本号高不一定可以，如1.8_301可能也成功不了，可以试试测试成功的指定jdk版本，如1.8_231，1.8_151是可以成功的
 
 jdk15 失败
 ![image](https://user-images.githubusercontent.com/48286013/146948810-b086f42b-f1c7-4054-aef6-09f841c4919f.png)
 
 jdk8 成功
 ![image](https://user-images.githubusercontent.com/48286013/146949149-30e34036-6474-4e52-a1f9-a16db3cbaf5c.png)

## 11-`dnsldaprmi`参数如何填写

- 可以填写`dns:`的绕过方式，如`dns${::-:}`;
- 也可以填写`dns://`的绕过方式，如`dns${::-:}/${::-}/`

## 12-`jndiparams`参数如何填写

- 填写`jndi:`的绕过方式，如`j$%7b::-n%7ddi:`等


# 参数说明
主要是三个模块

#### dnslog configuration
- 0x01 log4j2 Passive Scanner 为被动扫描开关，勾选就会进行被动扫描，不勾选就不会扫描
- 0x02 isuseceye 是否使用ceye.io的平台
- 0x03 ceyetoken ceye.io的用户token
- 0x04 ceyednslog ceye.io的用户记录域名
- 0x05 isuseprivatedns 是否使用自定义dnslog
- 0x06 isip 自定义dnslog是否为ip(主要针对内网的ip监听)
- 0x07 privatednslogurl 自定义的dnslog记录域名
- 0x08 privatednsResponseurl 自定义dnslog记录域名响应查看地址，详细自定义dnslog配置可以到[此处](https://github.com/f0ng/log4j2burpscanner/blob/main/FAQ-zh-CN.md#0x01%E8%AE%BE%E7%BD%AE%E5%9F%9F%E5%90%8D%E7%B1%BB%E5%9E%8Bdnslog%E5%B9%B3%E5%8F%B0)查看
- 0x09 Save configuration 保存配置
- 0x10 Restore/Loading latest params 恢复默认参数
- 0x11 Test dnslog delay 测试与dnslog的延迟
- 0x12 use`[${::-.}]`replace`.`  是否使用`${::-.}`替换`.`

##### custom params
- 0x01 jndiparam 传入的jndi参数，可以使用类似于`j${::-n}di:`进行替换，达到bypass效果
- 0x02 dnsldaprmi 可选，传入dns、ldap、rmi三个参数
- 0x03 white lists 白名单，可使用通配符进行配置，如`*.gov.cn`、`*.edu.cn`也可以设置成指定的域名后缀结尾，如`qq.com`，这样任何以qq.com结尾的域名都不会进行扫描
- 0x04 headers lists 自定义请求头的参数名
- 0x05 test UserAgentTokenXff 是否测试User-Agent、token(包含jwt一些关键字) 、常见XFF头参数等
- 0x06 test Xfflists 是否测试所有xff头参数
- 0x07 test Cookie 是否测试所有Cookie
- 0x08 test RefererOrigin 是否测试Referer、Origin参数
- 0x09 test Contenttype 是否测试Contenttype参数
- 0x010 test Accept 是否测试Accept等参数

##### custom params2
- 0x01 jndiparams 主动扫描时用到的jndi参数，可以使用类似于`j${::-n}di:`进行替换，达到bypass效果，换行隔开
