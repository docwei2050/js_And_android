package com.zhy.http.okhttp.builder;

import android.text.TextUtils;

import com.zhy.http.okhttp.log.RSA;
import com.zhy.http.okhttp.request.PostFormRequest;
import com.zhy.http.okhttp.request.RequestCall;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Created by zhy on 15/12/14.
 */
public class PostFormBuilder extends OkHttpRequestBuilder implements HasParamsable
{
    private List<FileInput> files = new ArrayList<>();

    @Override
    public RequestCall build()
    {
        return new PostFormRequest(url, tag, params, headers, files).build();
    }

    public PostFormBuilder files(String key, Map<String, File> files)
    {
        for (String filename : files.keySet())
        {
            this.files.add(new FileInput(key, filename, files.get(filename)));
        }
        return this;
    }

    public PostFormBuilder addFile(String name, String filename, File file)
    {
        files.add(new FileInput(name, filename, file));
        return this;
    }

    public static class FileInput
    {
        public String key;
        public String filename;
        public File file;

        public FileInput(String name, String filename, File file)
        {
            this.key = name;
            this.filename = filename;
            this.file = file;
        }

        @Override
        public String toString()
        {
            return "FileInput{" +
                    "key='" + key + '\'' +
                    ", filename='" + filename + '\'' +
                    ", file=" + file +
                    '}';
        }
    }

    //
    @Override
    public PostFormBuilder url(String url)
    {
        this.url = url;
        return this;
    }

    @Override
    public PostFormBuilder tag(Object tag)
    {
        this.tag = tag;
        return this;
    }

    @Override
    public PostFormBuilder params(Map<String, String> params)
    {
        this.params = params;
        Set<Map.Entry<String, String>> entrySet = this.params.entrySet();
        for(Map.Entry<String, String> ds:entrySet){
            if ("userId".equals(ds.getKey())) {
                this.params.put(ds.getKey(), encryptValue(ds.getValue()));
            }
            if("roUserId".equals(ds.getKey())){
                this.params.put(ds.getKey(),encryptValue(ds.getValue()));
            }
            if("password".equals(ds.getKey())){
                this.params.put(ds.getKey(),encryptValue(ds.getValue()));
            }

        }
        return this;
    }

    private String encryptValue(String content) {
            String newValue=null;
            try {
                newValue= RSA.RSAEncodeSection(content);
            } catch (Exception e) {
                e.printStackTrace();
            }
          return newValue;
    }


    @Override
    public PostFormBuilder addParams(String key, String val)
    {
        if (this.params == null)
        {
            params = new LinkedHashMap<>();
        }
        if("userId".equals(key)){
            params.put(key,TextUtils.isEmpty(val) ? "" : encryptValue(val));
        }else if("roUserId".equals(key)){
            params.put(key,TextUtils.isEmpty(val) ? "" : encryptValue(val));
        }else if("password".equals(key)){
            params.put(key,TextUtils.isEmpty(val) ? "" : encryptValue(val));
        }else{
            params.put(key,TextUtils.isEmpty(val) ? "" :val);
        }
        return this;
    }

    @Override
    public PostFormBuilder headers(Map<String, String> headers)
    {
        this.headers = headers;
        return this;
    }


    @Override
    public PostFormBuilder addHeader(String key, String val)
    {
        if (this.headers == null)
        {
            headers = new LinkedHashMap<>();
        }
        headers.put(key, val);
        return this;
    }


}
