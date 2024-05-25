package tests;

import cz.muni.fi.crocs.rcard.client.Util;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

public class PreSignature {
    public BigInteger u, v, o;

    public PreSignature(BigInteger u, BigInteger v, BigInteger o) {
        this.u = u;
        this.v = v;
        this.o = o;
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
        byte[] payload = ProtocolManager.encodeBigInteger(u);
        payload = Util.concat(payload, ProtocolManager.encodeBigInteger(v));
        payload = Util.concat(payload, ProtocolManager.encodeBigInteger(o));
        payload = encrypt(encKey, iv, payload);
        return Util.concat(payload, mac(macKey, payload));
    }
}
