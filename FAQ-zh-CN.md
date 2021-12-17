* [自定义dnslog配置方法(URL型)](#0x01设置域名类型dnslog平台)
* [自定义dnslog配置方法(IP型)](#0x02设置ip类型dnslog平台)

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
 0x01 有些时候由于添加的请求头过多，导致服务器处理请求过慢，或造成无法响应，可以通过控制请求头参数进行控制，如下设置
 
 自定义参数全部不勾选

 0x02 由于网络环境与dnslog的问题，导致请求不能及时响应，可以更换自定义dnslog尝试
 0x03 如果都不是以上原因，且在logger里没有看到扫描请求包，可以提交issue

## 5-为什么有些请求不会扫描?
 本插件是通过Passive接口进行扫描，如果第一次扫描过了，第二次再次加载插件，需要右键数据包，进行passive scan即可

## 6-导入插件报错：java.lang.NullPointerException: Cannot invoke "burp.IHttpRequestResponse.getHttpService()" because "this.currentlyDisplayedItem" is null之类
 0x01 burp的jdk版本太高，可以尝试降低burp的jdk版本，位置在Extender→Options→Java Environment→Folder for loading library JAR files(optional)→Select folder，作者的jdk版本在1.8_231
 
 0x02 自行编译插件即可，下载源码，输入命令mvn package

## 7-如何编译?
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
 ### 设置`privatednslogurl`为内网可以访问到的域名即可，如`127.0.0.1:8001`，记得勾选isip，标明dnslog属性为ip

   <img src="https://user-images.githubusercontent.com/48286013/146288432-c14f8a7d-9ae6-4b3d-b9ea-0a50b82c94f8.png" width="650" height="400" />
   
 
