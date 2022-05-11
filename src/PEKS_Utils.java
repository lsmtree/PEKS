package src;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PEKS_Utils {

    //MD5 hash
    public static byte[] MD5HASH(String str) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        //为MD5哈希创建 MessageDigest 实例
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        //加盐
//        SecureRandom secureRandom = new SecureRandom();
//        byte[] salt = new byte[16];
//        secureRandom.nextBytes(salt);
//        messageDigest.update(salt);

        //通过str更新messageDigest
        messageDigest.update(str.getBytes("UTF-8"));
        //get hashBytes
        byte[] hashBytes = messageDigest.digest();
        //convert hash bytes to hex format
        StringBuilder builder = new StringBuilder();
        for(byte b: hashBytes) {
            builder.append(String.format("%02x",b));
        }
        //16进制的哈希值转为 byte数组
        String res =  builder.toString();
//        System.out.println("res:"+res);
//        System.out.println("res length:"+res.length());
        res = res.toUpperCase();
        int length = res.length() / 2;
        char[] hexChars = res.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }


    //SHA256
    public static byte[] SHA256(String str) {
        MessageDigest messageDigest;
        byte[] res = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            res = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return res;
    }

    //char To byte
    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }
}
