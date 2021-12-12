
# 0.12更新
 1.增加body={"a":"1","b":"22222"}格式、body={"params":{"a":"1","b":"22222"}}格式识别发送payload
 
 2.支持自定义dnslog，默认dns记录为log.xn--9tr.com，可以在配置处设置是否启用ceye、ceye token以及ceye地址。按钮在按钮界面，点击以后需要去插件加载页面查看是否保存成功，如果出现 "Save Success!" 则为保存成功。设置了isceye为true，则默认dnslog取消。(该更新是为了保证在log.xn--9tr.com网站挂了的情况下还可以进行漏洞探测，默认情况下还是log.xn--9tr.com网站)
![image](https://user-images.githubusercontent.com/48286013/145709297-7788a8c0-9660-4d26-918e-4d8a32774b62.png)
 3.payload处添加路径，更为精准定位漏洞点，如test.com/login存在漏洞，那么payload记录地址为test.com.login.dnslog
![image](https://user-images.githubusercontent.com/48286013/145709437-58b32654-d028-4c9e-af89-920ba7e79f7b.png)

# log4j2burpscanner
CVE-2021-44228，log4j2 burp插件 Java版本，dnslog选取了非dnslog.cn域名
效果如下：

靶场的 （靶场比较慢，但是互联网资产是没问题的，原因应该在于靶场对于其他请求头的处理不好，或者请求头过大，导致靶场反应较慢，多等等即可）
![image](https://user-images.githubusercontent.com/48286013/145667667-c32ea0de-19c2-45b1-9617-ab743b8431f3.png)

![image](https://user-images.githubusercontent.com/48286013/145667703-62ffb1ea-763a-44ae-a5e0-22a545db01b5.png)


试了两个SRC的站点
![image](https://user-images.githubusercontent.com/48286013/145667530-feb801ec-6e20-4020-8a11-c7e1af8673ce.png)

加载后，会给出一个url，访问就可以查看dns的记录，当然，插件本身自带检查dns记录，这里只起后续方便查看的作用
![image](https://user-images.githubusercontent.com/48286013/145698319-e93ec2c8-9789-4d10-a926-d7f3f071e5a5.png)


# 特点如下：
## 0x01 基于Cookie字段、XFF头字段、UA头字段发送payload
## 0x02 基于域名的唯一性，将host带入dnslog中

插件主要识别五种形式：

1.get请求，a=1&b=2&c=3  

2.post请求，a=1&b=2&c=3  

3.post请求，{“a”:”1”,”b”:”22222”}

4.post请求，a=1&param={“a”:”1”,”b”:”22222”}

5.post请求，{"params":{"a":"1","b":"22222"}}


# 注：
如果需要在repeater里进行测试

需要打开dashbord→Live passive crawl from Proxy and Repeater→勾选repeater

需要打开dashbord→Live audit from Proxy and Repeater→勾选repeater
![image](https://user-images.githubusercontent.com/48286013/145667621-449187be-d259-4567-8c1d-1619e0009411.png)

![image](https://user-images.githubusercontent.com/48286013/145667631-301fb788-30da-42b9-b038-98fa71ef835a.png)


# 免责声明
请勿将本项目技术或代码应用在恶意软件制作、软件著作权/知识产权盗取或不当牟利等非法用途中。实施上述行为或利用本项目对非自己著作权所有的程序进行数据嗅探将涉嫌违反《中华人民共和国刑法》第二百一十七条、第二百八十六条，《中华人民共和国网络安全法》《中华人民共和国计算机软件保护条例》等法律规定。本项目提及的技术仅可用于私人学习测试等合法场景中，任何不当利用该技术所造成的刑事、民事责任均与本项目作者无关。
