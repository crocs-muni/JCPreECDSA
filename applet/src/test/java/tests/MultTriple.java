package tests;

import cz.muni.fi.crocs.rcard.client.Util;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

public class MultTriple {
    public BigInteger a, b, c;

    public MultTriple(BigInteger a, BigInteger b, BigInteger c) {
        this.a = a;
        this.b = b;
        this.c = c;
    }

    public static MultTriple[] generate(int number) {
        BigInteger[] as = new BigInteger[number];
        BigInteger[] bs = new BigInteger[number];
        BigInteger[] cs = new BigInteger[number];
        BigInteger asum = BigInteger.ZERO;
        BigInteger bsum = BigInteger.ZERO;
        BigInteger csum = BigInteger.ZERO;
        for (int i = 0; i < number; ++i) {
            as[i] = ProtocolManager.randomBigInt(32);
            asum = asum.add(as[i]);
            bs[i] = ProtocolManager.randomBigInt(32);
            bsum = bsum.add(bs[i]);
            cs[i] = ProtocolManager.randomBigInt(32);
            csum = csum.add(cs[i]);
        }
        cs[number - 1] = asum.multiply(bsum).subtract(csum.subtract(cs[number - 1])).mod(ProtocolManager.G.getCurve().getOrder());

        MultTriple[] triples = new MultTriple[number];
        for (int i = 0; i < number; ++i) {
            triples[i] = new MultTriple(as[i], bs[i], cs[i]);
        }
        return triples;
    }

    private static byte[] encrypt(byte[] key, byte[] iv, byte[] message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] ct = cipher.doFinal(message);
        return Util.concat(iv, ct);
    }

    private static byte[] mac(byte[] key, byte[] message) throws Exception {
        CMac mac = new CMac(new AESEngine());
        mac.init(new KeyParameter(key));
        mac.update(message, 0, message.length);
        byte[] out = new byte[16];
        mac.doFinal(out, 0);
        return out;
    }

    public byte[] wrap(byte[] encKey, byte[] macKey, byte[] iv) throws Exception {
        byte[] payload = ProtocolManager.encodeBigInteger(a);
        payload = Util.concat(payload, ProtocolManager.encodeBigInteger(b));
        payload = Util.concat(payload, ProtocolManager.encodeBigInteger(c));
        payload = encrypt(encKey, iv, payload);
        return Util.concat(payload, mac(macKey, payload));
    }
}
