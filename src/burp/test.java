package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.util.Iterator;
import java.util.Map;

public class test {

    public static void main(String[] args) {
//        String requri = "/index.php?a=1&b=2&c=3";
        String vulnurl = "test.com";
//        String cookie_total = "";
//
//        String[] requris = requri.split("\\?");
//        String[] requries = requris[1].split("&");
//
//        for(String uri_single:requries) {
//            String[] uri_single_lists = uri_single.split("=");
//            cookie_total = cookie_total + uri_single_lists[0] + "="  + vulnurl +  "&" ;
//        }
//        cookie_total = cookie_total.substring(0,cookie_total.length()-1);
//        System.out.println(requris[0] + "?" + cookie_total);



        //双重json
        String body = "";
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
            System.out.println(jsonObject.getString(key));
        }
        System.out.println(jsonObject);

        if (body.contains("\":{"))
            System.out.println("666666");



//        String body = "{\"a\":\"1\",\"b\":\"22222\"}";
//        JSONObject jsonObject = JSON.parseObject(body);
//        for (String key:jsonObject.keySet()) {
//            jsonObject.put(key, vulnurl);
//        }
//        System.out.println(jsonObject);

//        String body = "a=1&param={\"a\":\"1\",\"b\":\"22222\"}";
//        String body_total = "";
//        String[] bodys_single = body.split("&");
//        for(String body_single:bodys_single) {
//            if (body_single.contains("{")){
//                String[] body_single_lists = body_single.split("=");
//                JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
//                for (String key:jsonObject.keySet()) {
//                    jsonObject.put(key, vulnurl);
//                }
//                body_total = body_total + body_single_lists[0] + "=" + jsonObject.toString() + "&";
//            }else {
//                String[] body_single_lists = body_single.split("=");
//                body_total = body_total + body_single_lists[0] + "=" + vulnurl + "&";
//            }
//        }
//        body_total = body_total.substring(0,body_total.length()-1);
//        body =  body_total;
//        System.out.println(body);
    }
}
