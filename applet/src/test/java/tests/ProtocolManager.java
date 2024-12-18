package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;
import jcpreecdsa.Consts;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.*;
import java.util.Random;

public class ProtocolManager {
    public final CardManager cm;

    public final static ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    public final static ECPoint G = ecSpec.getG();
    private final static Random rnd = new Random();

    public ProtocolManager(CardManager cm) {
        this.cm = cm;
    }

    public ECPoint setup(byte[] encKey, byte[] macKey) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SETUP,
                0,
                0,
                Util.concat(encKey, macKey)
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    public ECPoint setup(byte[] encKey, byte[] macKey, BigInteger secretKey, BigInteger omegaKey, BigInteger deltaKey) throws Exception {
        byte[] data = Util.concat(encKey, macKey);
        data = Util.concat(data, ProtocolManager.encodeBigInteger(secretKey));
        data = Util.concat(data, ProtocolManager.encodeBigInteger(omegaKey));
        data = Util.concat(data, ProtocolManager.encodeBigInteger(deltaKey));
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SETUP,
                1,
                0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    public BigInteger sign(byte[] message, byte[] preSignature) throws Exception {
        byte[] data = Util.concat(message, preSignature);
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SIGN,
                0,
                0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return new BigInteger(1, responseAPDU.getData());
    }

    public void setT(byte[] triple) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SET_T,
                0,
                0,
                triple
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
    }

    public void setU(byte[] triple) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SET_U,
                0,
                0,
                triple
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
    }

    public byte[] sign1(byte[] message, BigInteger a1, BigInteger b1, BigInteger t1c) throws Exception {
        byte[] data = Util.concat(message, encodeBigInteger(a1));
        data = Util.concat(data, encodeBigInteger(b1));
        data = Util.concat(data, encodeBigInteger(t1c));
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SIGN1,
                0,
                0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return responseAPDU.getData();
    }

    public byte[] sign2(BigInteger a1hat, BigInteger b1hat, BigInteger c1hat, ECPoint R, BigInteger commitment) throws Exception {
        byte[] data = Util.concat(encodeBigInteger(a1hat), encodeBigInteger(b1hat));
        data = Util.concat(data, encodeBigInteger(c1hat));
        data = Util.concat(data, R.getEncoded(false));
        data = Util.concat(data, encodeBigInteger(commitment));
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SIGN2,
                0,
                0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return responseAPDU.getData();
    }

    public byte[] sign3(ECPoint R1hat) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCPREECDSA,
                Consts.INS_SIGN3,
                0,
                0,
                R1hat.getEncoded(false)
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return responseAPDU.getData();
    }

    public static BigInteger hash(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] h = digest.digest(message);
        return new BigInteger(1, h);
    }

    public static BigInteger randomBigInt(int bytes) {
        return new BigInteger(bytes * 8, rnd);
    }

    public static byte[] encodeBigInteger(BigInteger x) {
        byte[] encoded = Util.trimLeadingZeroes(x.toByteArray());
        assert encoded.length <= 32;
        while (encoded.length != 32) {
            encoded = Util.concat(new byte[1], encoded);
        }
        return encoded;
    }

    public static byte[] rawToDer(BigInteger r, BigInteger s) {
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        int totalLength = rBytes.length + sBytes.length + 4 + 2; // 4 bytes for the DER tags and lengths, and 2 bytes for each integer tag and its length
        byte[] der = new byte[totalLength];

        der[0] = 0x30; // DER sequence tag
        der[1] = (byte) (totalLength - 2); // length of sequence

        der[2] = 0x02; // DER integer tag
        der[3] = (byte) rBytes.length; // length of r
        System.arraycopy(rBytes, 0, der, 4, rBytes.length);

        int offset = 4 + rBytes.length;
        der[offset] = 0x02; // DER integer tag
        der[offset + 1] = (byte) sBytes.length; // length of s
        System.arraycopy(sBytes, 0, der, offset + 2, sBytes.length);

        return der;
    }

    public static boolean verifySignature(ECPoint pk, byte[] message, byte[] signature) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ECPublicKeySpec pkSpec = new ECPublicKeySpec(pk, ProtocolManager.ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        ecdsa.initVerify(kf.generatePublic(pkSpec));
        ecdsa.update(message);

        return ecdsa.verify(signature);
    }
}
