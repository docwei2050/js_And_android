package com.zhy.http.okhttp.builder;

import android.text.TextUtils;

import com.zhy.http.okhttp.log.RSA;
import com.zhy.http.okhttp.request.GetRequest;
import com.zhy.http.okhttp.request.RequestCall;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by zhy on 15/12/14.
 */
public class GetBuilder extends OkHttpRequestBuilder implements HasParamsable
{
    @Override
    public RequestCall build()
    {
        if (params != null)
        {
            url = appendParams(url, params);
        }
        return new GetRequest(url, tag, params, headers).build();
    }
    protected String appendParams(String url, Map<String, String> params)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(url + "?");
        if (params != null && !params.isEmpty())
        {
            for (String key : params.keySet())
            {
                sb.append(key).append("=").append(params.get(key)).append("&");
            }
        }

        sb = sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    @Override
    public GetBuilder url(String url)
    {
        url=perfromEncryptRequest(url);
        this.url = url;
        return this;
    }
    private String perfromEncryptRequest(String url) {
            //加密拼接的参数
            if(url.contains("userId=")){
                url=encryptAndReplace(url,"userId");
            }
            if(url.contains("password=")){
                url=encryptAndReplace(url,"password");
            }
            if(url.contains("roUserId")){
                url=encryptAndReplace(url,"roUserId");
            }
           return url;
    }
    private String encryptAndReplace(String url,String content) {
        if(url.contains(content+"=")){
            String[] var1=url.split("\\?");
            String[] var2=var1[1].split("&");
            String value=null;
            for(int i=0;i<var2.length;i++){
                if(var2[i].contains(content+"=")){
                    String[] var3=var2[i].split("=");
                    value=var3[1];
                }
            }
            String newValue=null;
            try {
                newValue= RSA.RSAEncodeSection(value);
            } catch (Exception e) {
                e.printStackTrace();
            }
            url=url.replace(content+"="+value,content+"="+newValue);
        }
        return url;
    }
    @Override
    public GetBuilder tag(Object tag)
    {
        this.tag = tag ;
        return this;
    }

    @Override
    public GetBuilder params(Map<String, String> params)
    {
        this.params = params;
        return this;
    }

    @Override
    public GetBuilder addParams(String key, String val)
    {
        if (this.params == null)
        {
            params = new LinkedHashMap<>();
        }
        params.put(key, TextUtils.isEmpty(val) ? "" : val);
        return this;
    }

    @Override
    public GetBuilder headers(Map<String, String> headers)
    {
        this.headers = headers;
        return this;
    }

    @Override
    public GetBuilder addHeader(String key, String val)
    {
        if (this.headers == null)
        {
            headers = new LinkedHashMap<>();
        }
        headers.put(key, val);
        return this;
    }
}
