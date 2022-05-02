# JUST FOR TESTING，DON'T ATTACK ANYONE
# JUST FOR TESTING，DON'T ATTACK ANYONE
# JUST FOR TESTING，DON'T ATTACK ANYONE
## [FAQ](https://github.com/f0ng/log4j2burpscanner/blob/main/FAQ.md) Frequently Asked Questions
## how to use? [releases](https://github.com/f0ng/log4j2burpscanner/releases/) download the latest plugin
### [简体中文](https://github.com/f0ng/log4j2burpscanner/blob/main/README-zh-CN.md)|English
### default dnslog https://dns.xn--9tr.com/   github: [DNSLog-Platform-Golang](https://github.com/yumusb/DNSLog-Platform-Golang)

# 0.19 update
## 2022-05-02
1.add polling dnslog query including active scanning and passive scanning
<img width="758" alt="image" src="https://user-images.githubusercontent.com/48286013/166197475-ef6f7c94-955d-4299-be31-6dc7304f47a6.png">

# 0.18 update
## 2021-12-25
1.`Send to log4j2 Scanner`the bypass payload of `jndi:` is used for testing. at now it includes the following three types`j${::-n}di:`、 `jn${env::-}di:`、`j${sys:k5:-nD}${lower:i${web:k5:-:}}`

# 0.17 update
## 2021-12-19

 1.add passive switch `log4j2 Passive Scanner`，add log4j2 Scanner menu button `Send to log4j2 Scanner`
 <img src="https://user-images.githubusercontent.com/48286013/146666473-83b53bfe-7a41-4379-b22c-a1085125e2e7.png" width="700" height="120" />
 
 <img src="https://user-images.githubusercontent.com/48286013/146666487-5be3cfad-fd5c-42d5-ad43-f13e1c2fdac5.png" width="600" height="200" />

 2.update payload param，add random character string，distinguish between the same site and the same path, optimization `%20` problem
 
 3.recognize `multipart/form-data` type、`xml` type
 
 fix parameter issue for creating initial `properties` file

# 0.16 update
## 2021-12-15
 1.change the UI page
 
  <img src="https://user-images.githubusercontent.com/48286013/146201676-362ea520-a77d-47ab-b3c9-3ff239d41fa7.png" width="650" height="350" />
  <img src="https://user-images.githubusercontent.com/48286013/146190519-cfb006a9-84aa-44c2-9c47-452d8d6798be.png" width="600" height="280" />

 2.add isip param(for the case that there is no domain name and only IP detection in the intranet) but  this kind of test has no parameter point digital ID and no host

   If there are no other good intranet dnslog tools to replace, you can link the tools of KpLi0rn https://github.com/KpLi0rn/Log4j2Scan

   <img src="https://user-images.githubusercontent.com/48286013/146288249-ad4e2e08-c034-455e-a436-9ed97813096e.png" width="700" height="400" />
   <img src="https://user-images.githubusercontent.com/48286013/146288272-377ce1ee-bedd-4e81-8732-5c9dbf19597f.png" width="800" height="200" />
   <img src="https://user-images.githubusercontent.com/48286013/146288432-c14f8a7d-9ae6-4b3d-b9ea-0a50b82c94f8.png" width="650" height="400" />
   <img src="https://user-images.githubusercontent.com/48286013/146191640-0c9036d5-0ff9-4cef-8ba0-11c384f5f148.png" width="600" height="330" />
   
# 0.15 update
## 2021-12-14
 1.add dnsldaprmi param (dns、ldap、rmi) default dns
 
 2.add isContenttypeRefererOrigin param 、isAccept param
 
   isContenttypeRefererOrigin param(whether test Content-Type、Referer、Origin)default off
   
   isAccept param(whether test Accept-Language、Accept、Accept-Encoding)default off

 3.add bypass `jndi:` ,but the effect is not good,use with caution
 
  `jndi:` bypass methods https://twitter.com/ymzkei5/status/1469765165348704256
 * jn${env::-}di:
 * jn${date:}di${date:':'}
 * j${k8s:k5:-ND}i${sd:k5:-:}
 * j${main:\\k5:-Nd}i${spring:k5:-:}
 * j${sys:k5:-nD}${lower:i${web:k5:-:}}
 * j${::-nD}i${::-:}
 * j${EnV:K5:-nD}i:
 * j${loWer:Nd}i${uPper::}
 
 4.add `log.xn--9tr.com` to the white list
 
 ## In addition, you need to click this button to obtain the latest configuration parameters

 <img src="https://user-images.githubusercontent.com/48286013/145962694-65bc6943-5b60-41b0-8edb-cde9b087c597.png" width="600" height="300" />

 <img src="https://user-images.githubusercontent.com/48286013/145962761-5c15d967-2085-48d8-ac93-b33c88d9fc3f.png" width="700" height="300" />

# 0.14 update
## 2021-12-13

 1.add bypass rc1,add space to the payload

 2.more accurate

 3.add Intranet dnslog api，can customize the ceye.io api or other apis，including internal networks

  Param 1：isprivatedns(whether to use private dns api)

  Param 2：privatednslogurl(internal dnslog address)

  Param 3：privatednslogurl(internal dnslog response address)

 4.add controllable params to control the payload

  Param 4：isuseUserAgenttokenXff(whether test User-agent、token、X-Forward-for、X-Client-IP) default on

  Param 5：isuseXfflists(whether test xff lists，including others xff)default off

  Param 6：isuseAllCookie(whether test all cookie)default on

# Remember to click restore default button to get the latest dnslog params



0x01 More accurate

<img src="https://user-images.githubusercontent.com/48286013/145826369-f5b2276f-1cb2-4ccd-ae03-353d2220cd34.png" width="700" height="600" />

0x02 Add Intranet dnslog api，can customize the ceye.io api or other apis，including internal networks

Since I don't have an intranet dnslog address，here I use ceye.io to test

<img src="https://user-images.githubusercontent.com/48286013/145832488-b1ab43d9-63db-47ae-a909-13ab18627687.png" width="600" height="200" />

Just ensure the connectivity between intranet and Intranet dnslog address, intranet and dnslog response address

<img src="https://user-images.githubusercontent.com/48286013/145834006-e1cb7e93-1054-427b-83e9-406ad200d81d.png" width="600" height="400" />

0x03 Add controllable params to control the payload

<img src="https://user-images.githubusercontent.com/48286013/145836830-06d3851c-5ce3-4dc5-9e52-b2c3715c71bb.png" width="600" height="450" />

Fix problem：
Due to the vulnerability of the sub domain name, the primary domain name will also report the vulnerability

# 0.13 update

  1.add request headers

["X-Forwarded-For","X-Forwarded","Forwarded-For","Forwarded","X-Requested-With","X-Requested-With", "X-Forwarded-Host","X-remote-IP","X-remote-addr","True-Client-IP","X-Client-IP","Client-IP","X-Real-IP","Ali-CDN-Real-IP","Cdn-Src-Ip","Cdn-Real-Ip","CF-Connecting-IP","X-Cluster-Client-IP","WL-Proxy-Client-IP", "Proxy-Client-IP","Fastly-Client-Ip","True-Client-Ip","X-Originating-IP", "X-Host","X-Custom-IP-Authorization","X-original-host","If-Modified-Since"]

# 0.12 update
 1.add recognizable format  

body={"a":"1","b":"22222"}

body={"params":{"a":"1","b":"22222"}})

 2.add ceye.io api（https://ceye.io）,can customize the ceye API，click the button to save configuration，the Extender output page will be display the results such as "Save Success!".Remember to set isceye property to true,otherwise ceye will fail

 3.more accurate（hostName + path）
![image](https://user-images.githubusercontent.com/48286013/145709437-58b32654-d028-4c9e-af89-920ba7e79f7b.png)

Fix problem：
windows path problem

# log4j2burpscanner
CVE-2021-44228，log4j2 RCE Burp Suite Passive Scanner，and u can customize the ceye.io api or other apis，including internal networks

![image](https://user-images.githubusercontent.com/48286013/145667667-c32ea0de-19c2-45b1-9617-ab743b8431f3.png)

![image](https://user-images.githubusercontent.com/48286013/145667703-62ffb1ea-763a-44ae-a5e0-22a545db01b5.png)

Two SRC（Security Response Center） sites were tested
![image](https://user-images.githubusercontent.com/48286013/145667530-feb801ec-6e20-4020-8a11-c7e1af8673ce.png)

After loading，a url will appear，access it to see the dnslog request，of course，the plugin has its own DNS check record，this is only for the convenience of subsequent viewing
![image](https://user-images.githubusercontent.com/48286013/145698319-e93ec2c8-9789-4d10-a926-d7f3f071e5a5.png)


# characteristics：
## 0x01 Cookie、XFF、UA payload
## 0x02 Domain name based uniqueness，add host to dnslog payload

Plug ins mainly identify seven forms：

1.get method，a=1&b=2&c=3  

2.post method，a=1&b=2&c=3  

3.post method，{“a”:”1”,”b”:”22222”}

4.post method，a=1&param={“a”:”1”,”b”:”22222”}

5.post method，{"params":{"a":"1","b":"22222"}}

6.post method，body={"a":"1","b":"22222"}

7.post method，body={"params":{"a":"1","b":"22222"}}


# 
if u need to test in the repeater

open dashbord→Live passive crawl from Proxy and Repeater→tick repeater

open dashbord→Live audit from Proxy and Repeater→tick repeater
![image](https://user-images.githubusercontent.com/48286013/145667621-449187be-d259-4567-8c1d-1619e0009411.png)

![image](https://user-images.githubusercontent.com/48286013/145667631-301fb788-30da-42b9-b038-98fa71ef835a.png)


# Disclaimers
This tool is only for learning, research and self-examination. It should not be used for illegal purposes. All risks arising from the use of this tool have nothing to do with me!



![f](https://starchart.cc/f0ng/log4j2burpscanner.svg)
