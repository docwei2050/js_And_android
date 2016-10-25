package com.zhy.http.okhttp.log;

import android.annotation.SuppressLint;
import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * User: 李永昌(ex-liyongchang001@pingan.com.cn)
 * Date: 2016-04-29
 * Time: 18:04
 * FIXME
 */
public class RSA {
    public static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeabYScyccBwY6ieOcVkz/8RwQZS" +
            "RQxpaVf+rIv3/k9+yxxBtKeK9F8yP3JDTZCr2mYXNlgdBU0OfX6472JrrQaHx5HF6pEjcVUzX34QsfoD+Z4e4zczktg1DEhVo2" +
            "B7S3p7Rn9VPTTDfVB4s3x0sSge3goqRm1gwJCLaCZqeK+QIDAQAB";
    public static final String PRIVATE_KEY = "";

    public static String SHA1(String inStr) {
        MessageDigest md = null;
        String outStr = null;
        try {
            md = MessageDigest.getInstance("SHA-1"); // 选择SHA-1，也可以选择MD5
            byte[] digest = md.digest(inStr.getBytes()); // 返回的是byet[]，要转化为String存储比较方便
            outStr = bytetoString(digest);
        } catch (NoSuchAlgorithmException e) {
        }
        return outStr;
    }

    @SuppressLint("DefaultLocale")
    public static String bytetoString(byte[] digest) {
        String str = "";
        String tempStr = "";

        for (int i = 1; i < digest.length; i++) {
            tempStr = (Integer.toHexString(digest[i] & 0xff));
            if (tempStr.length() == 1) {
                str = str + "0" + tempStr;
            } else {
                str = str + tempStr;
            }
        }
        return str.toLowerCase();
    }

    /**
     * 用公钥加密（短字符串加密）
     *
     * @param str
     * @return
     */
    public static String RSAEncode(String str) {
        if (str == null) {
            return null;
        } else if ("".equals(str)) {
            return "";
        }
        try {
            RSAPublicKey rsaPublicKey = loadPublicKey(PUBLIC_KEY);
            byte[] binaryData = encrypt(rsaPublicKey, str.getBytes());
            String base64String = Base64.encodeToString(binaryData,0);
            return base64String;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr
     *            公钥数据字符串
     * @throws Exception
     *             加载公钥时产生的异常
     */
    public static RSAPublicKey loadPublicKey(String publicKeyStr)
            throws Exception {
        try {
            // BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = Base64.decode(publicKeyStr.getBytes(),0);
            // byte[] buffer= base64Decoder.decodeBuffer(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 加密过程
     *
     * @param publicKey
     *            公钥
     * @param plainTextData
     *            明文数据
     * @return
     * @throws Exception
     *             加密过程中的异常信息
     */
    public static byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData)
            throws Exception {
        if (publicKey == null) {
            throw new Exception("加密公钥为空, 请设置");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");// , new
            // BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] output = cipher.doFinal(plainTextData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        }
    }

    /**
     * 用公钥解密(只可用于短字符串解密，未使用)
     *
     * @param data
     *            要解密的字节数组
     * @param key
     *            公钥字符串
     * @return
     * @throws Exception
     */
    private static String RSADecode(byte[] data, String key) throws Exception {
        byte[] keyBytes = Base64.decode(key.getBytes(),0);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        byte[] output = cipher.doFinal(data);
        String string = new String(output);
        return string;
    }

    /**
     * 用公钥解密（只可用于短字符串解密，未使用,解密请使用RSADecodeSection方法）
     *
     * @param data
     * @return
     * @throws Exception
     */
    public static String RSADecode(String data) throws Exception {
        if (data == null) {
            return null;
        } else if ("".equals(data)) {
            return "";
        }
        return RSADecode(Base64.decode(data.getBytes(),0), PUBLIC_KEY);
    }

    /**
     * 公钥分段加密（字符串分段加密，目前只用于特殊长字段的加密）
     *
     * @param str
     * @return
     * @throws Exception
     */
    public static String RSAEncodeSection(String str) throws Exception {
        if (str == null) {
            return null;
        } else if ("".equals(str)) {
            return "";
        }
        byte[] bytes = RSAUtils.encryptByPublicKey(str.getBytes(), PUBLIC_KEY);
        String encode = Base64.encodeToString(bytes,0);
        return encode;
    }

    /**
     * 公钥分段解密（可用于长字符串分段解密）
     *
     * @param data
     * @return
     * @throws Exception
     */
    public static String RSADecodeSection(String data) throws Exception {
        if (data == null) {
            return null;
        } else if ("".equals(data)) {
            return "";
        }
        byte[] bytes = RSAUtils.decryptByPublicKey(
                Base64.decode(data.getBytes(),0), PUBLIC_KEY);
        return new String(bytes);
    }
}
