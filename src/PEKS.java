package src;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class PEKS {

    //公钥
    class PK {
        Element g;
        Element h;
        Pairing pairing;
    }
    //私钥
    class SK {
        Element alpha;
    }
    //密文
    class C {
        Element c1;
        Element c2;
    }
    //陷门
    class TD {
        Element tdoor;
    }

    SK sk = new SK();
    PK pk = new PK();

    /*
     *   系统初始设置
     *   Input: /\
     *   Output: sk, pk
     * */
    public void Setup(Pairing pairing) {
        //生成随机 g1 Zr
        Element g1 = pairing.getG1().newRandomElement();
        Element alpha = pairing.getZr().newRandomElement();
        //设置公私钥
        Element h = g1.duplicate().powZn(alpha);
        pk.g = g1;
        pk.h = h;
        pk.pairing = pairing;
        sk.alpha = alpha;
    }

    /*
     *   加密
     *   Input: 密文关键字 w
     *   Output: 密文 C
     * */
    public C Enc(PK pk, String w) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //生成r
        Element r = pk.pairing.getZr().newRandomElement();
        //生成t
        Element h1w = pk.pairing.getG1().newElement().setFromHash(PEKS_Utils.MD5HASH(w),0, PEKS_Utils.MD5HASH(w).length);
        Element hr = pk.h.duplicate().powZn(r);
        Element t = pk.pairing.pairing(h1w, hr).getImmutable();
        //生成C
        Element c1 = pk.g.duplicate().powZn(r);
        Element c2 = pk.pairing.getG2().newElement().setFromHash(PEKS_Utils.SHA256(t.toString()), 0, PEKS_Utils.SHA256(t.toString()).length);

        C c = new C();
        c.c1 = c1;
        c.c2 = c2;
        return c;
    }

    /*
     *   陷门生成
     *   Input: sk, w
     *   Output: td
     * */
    public TD TdGen(PK pk, SK sk, String w) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        Element h1w = pk.pairing.getG1().newElement().setFromHash(PEKS_Utils.MD5HASH(w),0, PEKS_Utils.MD5HASH(w).length);
        Element td= h1w.duplicate().powZn(sk.alpha);
        TD t = new TD();
        t.tdoor = td;
        return t;
    }

    /*
     *   测试
     *   Input: td,c
     *   Output: boolean
     * */
    public boolean Test(PK pk, TD td, C c) {
        Element tdc1 = pk.pairing.pairing(td.tdoor, c.c1).getImmutable();
        Element flag = pk.pairing.getG2().newElement().setFromHash(PEKS_Utils.SHA256(tdc1.toString()), 0, PEKS_Utils.SHA256(tdc1.toString()).length);
        if (flag.equals(c.c2)) {
            return true;
        }else
            return false;
    }
}
