## 1.How to use？
### 0x01 [releases](https://github.com/f0ng/log4j2burpscanner/releases/) download the latest plugin
### 0x02 After loading the plugin，if the default dnslog can be accessed[https://log.xn--9tr.com](https://log.xn--9tr.com)，thus do not need to set other dnslogs
### 0x03 If the https://log.xn--9tr.com is inaccessible，then  you need to configure [ceye.io](https://ceye.io)，remember to set isceye property to true，fill in token、ceye.io address，save the configuration
### 0x04 If intranet dnslog is required，remember set isceye property to false， fill in privatednslogurl（private dnslog address），privatednsResponseurl（private dnslog reponse address)，save the configuration

## 2.The ceye api doesn't work？
### 0x01 Press the Save button several times，the Extender output (Extender→output) page will be display the results such as "Save Success!".
<img src="https://user-images.githubusercontent.com/48286013/145739783-e6b491ca-4959-4744-a1fe-4b15fb8287e2.png" width="800" height="150" />

### 0x02 set isceye property to true
<img src="https://user-images.githubusercontent.com/48286013/145739853-58f0130c-b841-45ca-8559-6feea6e97efa.png" width="650" height="130" />


## 3.If the default dnslog platform cannot be accessed, does it affect the results？
### As long as ceye is configured, the default dnslog cannot be accessed, and the result will not be affected
<img src="https://user-images.githubusercontent.com/48286013/145744984-1a2bd55d-8348-4863-8b68-bd0af03aa716.png" width="600" height="200" />
<img src="https://user-images.githubusercontent.com/48286013/145741263-14f6ec28-0fda-4211-ae3b-d67eed41d1db.png" width="650" height="200" />

## 4.Why can't some sites be detected？
### 0x01 Sometimes, because too many request headers are added, the server processes the request too slowly or cannot respond. You can control it by controlling the request header parameters, as shown in the following settings
#### isuseUserAgentTokenXff=0(whether test User-agent、token、X-Forward-for、X-Client-IP)
#### isuseXfflists=0(whether test xff lists，including others xff)
#### isuseAllCookie=0(whether test all cookie)

### 0x02 Due to the problems of network environment and dnslog, the request cannot be responded in time. You can try to replace the custom dnslog platform

### 0x03 If it is not the above reasons and the scan request package is not seen in the logger, you can submit the issue

## 5.Why are some requests not scanned？
### This plugin is scanned through the passive interface. If you use this plugin for the first time and load it again for the second time, it will not be scanned again. You need to restart burp
