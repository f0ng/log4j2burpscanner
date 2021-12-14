# [FAQ](https://github.com/f0ng/log4j2burpscanner/blob/main/FAQ.md) Frequently Asked Questions
### English|[简体中文](https://github.com/f0ng/log4j2burpscanner/blob/main/README.md)

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
![image](https://user-images.githubusercontent.com/48286013/145709297-7788a8c0-9660-4d26-918e-4d8a32774b62.png)
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