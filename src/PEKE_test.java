package src;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class PEKE_test {
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //生成双线性映射
        Pairing pairing = PairingFactory.getPairing("a.properties");

        PEKS peks = new PEKS();
        //PEKS 初始化
        peks.Setup(pairing);

        String w = "abc";
        String w1 = "abcd";

        //加密
        PEKS.C c = null;
        c = peks.Enc(peks.pk, w);

        //生成陷门
        PEKS.TD td = null;
        PEKS.TD td1 = null;
        td = peks.TdGen(peks.pk, peks.sk, w);
        td1 = peks.TdGen(peks.pk, peks.sk, w1);

        //搜索
        boolean res = peks.Test(peks.pk, td, c);
        boolean res1 = peks.Test(peks.pk, td1, c);

        //搜索结果测试
        System.out.println(res);
        System.out.println(res1);

    }
}
