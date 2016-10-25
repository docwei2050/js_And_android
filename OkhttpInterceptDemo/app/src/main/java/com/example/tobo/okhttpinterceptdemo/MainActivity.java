package com.example.tobo.okhttpinterceptdemo;

import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;

import com.zhy.http.okhttp.OkHttpUtils;
import com.zhy.http.okhttp.callback.Callback;

import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import okhttp3.Call;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
    }

    private void initView() {
        OkHttpUtils.getInstance().debug("OkHttpUtils").setConnectTimeout(10, TimeUnit.SECONDS);
        OkHttpUtils.getInstance().setConnectTimeout(15, TimeUnit.SECONDS);
        OkHttpUtils.getInstance().setReadTimeout(20,TimeUnit.SECONDS);
        OkHttpUtils.getInstance().setWriteTimeout(20,TimeUnit.SECONDS);
        //使用https，但是默认信任全部证书
        OkHttpUtils.getInstance().setCertificates();
    }
    public void getClick(View view){
        String url="http://httpbin.org/get?userId=hhhh&roUserId=123456&password=15014598&fileId=yun";
        OkHttpUtils.get().url(url).build().execute(new Callback() {
            @Override
            public Object parseNetworkResponse(Response response) throws Exception {
                Object object=response;
                return object;
            }

            @Override
            public void onError(Call call, Exception e) {
                if(e!=null) {
                    System.out.println(e.toString());
                }
            }

            @Override
            public void onResponse(Object response) {
                if(response!=null) {
                    System.out.println(response.toString());
                }
            }
        });

    }
    public void postClick(View view){
        String url="http://httpbin.org/post";
        Map<String, String> param = new HashMap<>();
        param.put("userId", "hhhh");
        param.put("password","123456");
        OkHttpUtils.post().params(param).addParams("userId","hhhh").addParams("ro","userName")
                .addParams("phone", android.os.Build.BOARD)
                .addParams("model",android.os.Build.MODEL)
                .addParams("fileId","yun")
                .url(url).build().execute(new Callback() {
            @Override
            public Object parseNetworkResponse(Response response) throws Exception {
                Object object=response;
                return object;
            }

            @Override
            public void onError(Call call, Exception e) {
                if(e!=null) {
                    System.out.println(e.toString());
                }
            }

            @Override
            public void onResponse(Object response) {
                if(response!=null) {
                    System.out.println(response.toString());
                }
            }
        });

    }
    //获取app打包时间
    public  String getAppBuildTime() {
        String result = "";
        try {
            ApplicationInfo ai = getPackageManager().getApplicationInfo(getPackageName(), 0);
            ZipFile zf = new ZipFile(ai.sourceDir);
            ZipEntry ze = zf.getEntry("META-INF/MANIFEST.MF");
            long time = ze.getTime();
            SimpleDateFormat formatter = (SimpleDateFormat) SimpleDateFormat.getInstance();
            formatter.applyPattern("yyyy/MM/dd HH:mm:ss");
            result = formatter.format(new java.util.Date(time));
            zf.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
}
