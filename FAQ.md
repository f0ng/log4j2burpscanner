## 1.如何使用？
### 0x01 去[releases](https://github.com/f0ng/log4j2burpscanner/releases/)下载最新插件
### 0x02 加载完插件后，如果提示默认dnslog可以访问[https://log.xn--9tr.com](https://log.xn--9tr.com)，则可以不用设置其他dnslog
### 0x03 如果默认dnslog访问不了，那么就需要去配置[ceye.io](https://ceye.io)，记得将isceye设置为true，然后填上token、ceye.io的地址，保存配置
### 0x04 如果需要内网dnslog，那么将isceye设置为false， 将内网dnslog填入privatednslogurl，内网dnslog查看的地址填入privatednsResponseurl，保存配置

## 2.自定义ceye发现没有效果？
### 0x01 可能由于对界面处理得不是很好，导致按钮那里可能按下去没有触发事件，多按几次，可以去Extender→output页面查看保存是否成功
<img src="https://user-images.githubusercontent.com/48286013/145739783-e6b491ca-4959-4744-a1fe-4b15fb8287e2.png" width="800" height="150" />

### 0x02 isceye参数需要改为true
<img src="https://user-images.githubusercontent.com/48286013/145739853-58f0130c-b841-45ca-8559-6feea6e97efa.png" width="650" height="130" />


## 3.默认dnslog平台访问不了是否影响结果？
### 只要配置了ceye，默认dnslog访问不了不会影响结果
<img src="https://user-images.githubusercontent.com/48286013/145744984-1a2bd55d-8348-4863-8b68-bd0af03aa716.png" width="600" height="200" />
<img src="https://user-images.githubusercontent.com/48286013/145741263-14f6ec28-0fda-4211-ae3b-d67eed41d1db.png" width="650" height="200" />

## 4.为什么有些站点检测不出来？
### 0x01 有些时候由于添加的请求头过多，导致服务器处理请求过慢，或造成无法响应，可以通过控制请求头参数进行控制，如下设置
#### isuseUserAgentTokenXff=0
#### isuseXfflists=0
#### isuseAllCookie=0

### 0x02 由于网络环境与dnslog的问题，导致请求不能及时响应，可以更换自定义dnslog尝试
### 0x03 如果都不是以上原因，且在logger里没有看到扫描请求包，可以提交issue

## 5.为什么有些请求不会扫描？
### 本插件是通过Passive接口进行扫描，如果第一次扫描过了，第二次再次加载插件，是不会再次扫描，需要重启burp即可

## 6.导入插件报错：java.lang.NullPointerException: Cannot invoke "burp.IHttpRequestResponse.getHttpService()" because "this.currentlyDisplayedItem" is null之类
### 0x01 burp的jdk版本太高，可以尝试降低burp的jdk版本，位置在Extender→Options→Java Environment→Folder for loading library JAR files(optional)→Select folder，作者的jdk版本在1.8_231
### 0x02 自行编译插件即可，下载源码，输入命令mvn package
