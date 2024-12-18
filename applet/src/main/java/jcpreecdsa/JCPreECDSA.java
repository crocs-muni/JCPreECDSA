package jcpreecdsa;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
import jcpreecdsa.jcmathlib.*;


public class JCPreECDSA extends Applet {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    private ResourceManager rm;
    private ECCurve curve;
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    public final RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    private Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    private Signature mac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    private AESKey encKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    private AESKey macKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    private byte[] lastIv = new byte[16];
    private byte[] m = new byte[32];

    private BigNat bn1, bn2, bn3;
    private ECPoint point;
    private ECPoint publicKey;
    private BigNat secretKey;
    private BigNat omegaKey;
    private BigNat deltaKey;
    private byte[] t = new byte[192];
    private byte[] u = new byte[192];
    private BigNat c2hat, a2hat, b2hat, pres2;
    private ECPoint R2hat;
    private byte[] comm = new byte[32];
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);

    private boolean initialized = false;
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCPreECDSA(bArray, bOffset, bLength);
    }

    public JCPreECDSA(byte[] buffer, short offset, byte length) {
        OperationSupport.getInstance().setCard(CARD_TYPE);
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != Consts.CLA_JCPREECDSA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        if (!initialized)
            initialize();

        try {
            switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Consts.INS_SETUP:
                    setup(apdu);
                    break;
                case Consts.INS_SIGN:
                    sign(apdu);
                    break;
                case Consts.INS_SET_T:
                    setT(apdu);
                    break;
                case Consts.INS_SET_U:
                    setU(apdu);
                    break;
                case Consts.INS_SIGN1:
                    sign1(apdu);
                    break;
                case Consts.INS_SIGN2:
                    sign2(apdu);
                    break;
                case Consts.INS_SIGN3:
                    sign3(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Consts.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Consts.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Consts.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Consts.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Consts.SW_Exception);
        }
    }

    public boolean select() {
        if (initialized)
            curve.updateAfterReset();
        return true;
    }

    public void deselect() {}

    private void initialize() {
        if (initialized)
            ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

        rm = new ResourceManager((short) 256);
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);

        bn1 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bn2 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bn3 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        point = new ECPoint(curve);

        secretKey = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        omegaKey = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        deltaKey = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        publicKey = new ECPoint(curve);

        c2hat = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        a2hat = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        b2hat = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        pres2 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        R2hat = new ECPoint(curve);

        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 16B encKey || 16B macKey (|| 32B secretKey || 32B omegaKey )
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        encKey.setKey(apduBuffer, ISO7816.OFFSET_CDATA);
        macKey.setKey(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 16));
        mac.init(macKey, Signature.MODE_VERIFY);
        Util.arrayFillNonAtomic(lastIv, (short) 0, (short) lastIv.length, (byte) 0);

        if (p1 == (byte) 0) {
            random.generateData(ramArray, (short) 0, (short) 32);
            secretKey.fromByteArray(ramArray, (short) 0, (short) 32);
            omegaKey.zero();
            deltaKey.zero();
        } else {
            secretKey.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
            omegaKey.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 32);
            deltaKey.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) 32);
        }
        publicKey.setW(curve.G, (short) 0, (short) curve.G.length);
        publicKey.multiplication(secretKey);

        apdu.setOutgoingAndSend((short) 0, publicKey.getW(apduBuffer, (short) 0));
    }

    private void sign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 32B MSG || 16B IV || 32B k || 32B z || 16B MAC

        if (Util.arrayCompare(lastIv, (short) 0, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 16) != -1) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_REUSE);
        }
        if (!mac.verify(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) (64 + 16), apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16 + 64), (short) 16)) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_INVALID);
        }
        Util.arrayCopyNonAtomic(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), lastIv, (short) 0, (short) 16);

        md.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32, ramArray, (short) 0);
        bn1.fromByteArray(ramArray, (short) 0, (short) 32);

        // decrypt in place
        cipher.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 16);
        cipher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16), (short) 64, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16));

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16), (short) 32);
        bn1.modMult(bn2, curve.rBN);

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 * 2 + 16), (short) 32);
        bn1.modAdd(bn2, curve.rBN);

        bn1.copyToByteArray(apduBuffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, (short) 32);
    }

    private void sign1(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 32B m || 32B a1 || 32B b1 || 32B t1.c

        md.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32, ramArray, (short) 0);
        Util.arrayCopyNonAtomic(ramArray, (short) 0, m, (short) 0, (short) 32);

        // c = t1.c + t2.c
        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 3 * 32), (short) 32);
        bn3.fromByteArray(t, (short) 64, (short) 32);
        bn3.modAdd(bn1, curve.rBN);
        bn2.clone(bn3);
        bn2.modInv(curve.rBN); // c^-1

        // R2 = c^-1 * t_2.b * G
        point.setW(curve.G, (short) 0, (short) curve.G.length);
        point.multiplication(bn2);
        R2hat.copy(point);
        point.multiplication(t, (short) 32, (short) 32);

        // c2hat = t2.z - delta2 * c
        c2hat.fromByteArray(t, (short) 160, (short) 32);
        bn2.clone(bn3);
        bn2.modMult(deltaKey, curve.rBN);
        c2hat.modSub(bn2, curve.rBN);

        // a1
        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
        // b1
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 2 * 32), (short) 32);
        // copy c to output
        bn3.copyToByteArray(apduBuffer, (short) 64);

        // a = a1 + t2.a - u2.a
        bn3.fromByteArray(t, (short) 0, (short) 32);
        bn1.modAdd(bn3, curve.rBN);
        bn3.fromByteArray(u, (short) 0, (short) 32);
        bn1.modSub(bn3, curve.rBN);

        // b = b1 + x2 - u2.b
        bn2.modAdd(secretKey, curve.rBN);
        bn3.fromByteArray(u, (short) 32, (short) 32);
        bn2.modSub(bn3, curve.rBN);

        // a2hat = t2.x - u2.x - delta2 * a
        a2hat.fromByteArray(t, (short) (32 * 3), (short) 32);
        bn3.fromByteArray(u, (short) (32 * 3), (short) 32);
        a2hat.modSub(bn3, curve.rBN);
        bn3.clone(bn1);
        bn3.modMult(deltaKey, curve.rBN);
        a2hat.modSub(bn3, curve.rBN);

        // b2hat = omega2 - u2.y - delta2 * b
        b2hat.clone(omegaKey);
        bn3.fromByteArray(u, (short) (32 * 4), (short) 32);
        b2hat.modSub(bn3, curve.rBN);
        bn3.clone(bn2);
        bn3.modMult(deltaKey, curve.rBN);
        b2hat.modSub(bn3, curve.rBN);

        // s2' = u2.c + a * u2.b + b * u2.a
        pres2.fromByteArray(u, (short) (32 * 2), (short) 32);
        bn3.fromByteArray(u, (short) 32, (short) 32);
        bn3.modMult(bn1, curve.rBN);
        pres2.modAdd(bn3, curve.rBN);
        bn3.fromByteArray(u, (short) 0, (short) 32);
        bn3.modMult(bn2, curve.rBN);
        pres2.modAdd(bn3, curve.rBN);

        bn1.copyToByteArray(apduBuffer, (short) 0); // copy a to output
        bn2.copyToByteArray(apduBuffer, (short) 32); // copy b to output
        point.getW(apduBuffer, (short) 96); // copy R2 to output

        md.reset();
        a2hat.copyToByteArray(ramArray, (short) 0);
        md.update(ramArray, (short) 0, (short) 32);
        b2hat.copyToByteArray(ramArray, (short) 0);
        md.update(ramArray, (short) 0, (short) 32);
        c2hat.copyToByteArray(ramArray, (short) 0);
        md.doFinal(ramArray, (short) 0, (short) 32, apduBuffer, (short) (96 + 65));
        apdu.setOutgoingAndSend((short) 0, (short) (96 + 65 + 32));
    }

    private void sign2(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 32B a1hat || 32B b1hat || 32B c1hat || 65B R || H(R1hat)
        Util.arrayCopyNonAtomic(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 3 * 32 + 65), comm, (short) 0, (short) 32);

        // Rx * s2'
        bn3.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 3 * 32 + 1), (short) 32);
        pres2.modMult(bn3, curve.rBN);

        bn1.fromByteArray(t, (short) (4 * 32), (short) 32);
        R2hat.multiplication(bn1);
        point.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) 65);
        point.multiplication(deltaKey);
        point.negate();
        R2hat.add(point);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32);
        bn1.add(a2hat);
        if (!bn1.equals(curve.rBN)) {
            ISOException.throwIt(Consts.E_MAC_INVALID);
        }

        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
        bn1.add(b2hat);
        if (!bn1.equals(curve.rBN)) {
            ISOException.throwIt(Consts.E_MAC_INVALID);
        }

        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 32);
        bn1.add(c2hat);
        if (!bn1.equals(curve.rBN)) {
            ISOException.throwIt(Consts.E_MAC_INVALID);
        }

        a2hat.copyToByteArray(apduBuffer, (short) 0);
        b2hat.copyToByteArray(apduBuffer, (short) 32);
        c2hat.copyToByteArray(apduBuffer, (short) 64);
        R2hat.getW(apduBuffer, (short) 96);
        apdu.setOutgoingAndSend((short) 0, (short) (96 + 65));
    }

    private void sign3(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 65B R1hat

        md.reset();
        md.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short) 65, ramArray, (short) 0);
        if (Util.arrayCompare(comm, (short) 0, ramArray, (short) 0, (short) 32) != 0) {
            ISOException.throwIt(Consts.E_COMMITMENT_INVALID);
        }

        point.setW(apduBuffer, ISO7816.OFFSET_CDATA, (short) 65);
        point.negate();
        if (!point.isEqual(R2hat)) {
            ISOException.throwIt(Consts.E_MAC_INVALID);
        }

        // H(m) * t2.a
        bn1.fromByteArray(m, (short) 0, (short) 32);
        bn2.fromByteArray(t, (short) 0, (short) 32);
        bn1.modMult(bn2, curve.rBN);

        // s2 = H(m) * t2.a + s2'
        pres2.modAdd(bn1, curve.rBN);

        apdu.setOutgoingAndSend((short) 0, pres2.copyToByteArray(apduBuffer, (short) 0));
    }

    private void setT(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 16B IV || 32B a || 32B b || 32B c || 32B x || 32B y || 32B z || 16B MAC

        if (Util.arrayCompare(lastIv, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA, (short) 16) != -1) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_REUSE);
        }
        if (!mac.verify(apduBuffer, ISO7816.OFFSET_CDATA, (short) (16 + 192), apduBuffer, (short) (ISO7816.OFFSET_CDATA + 16 + 192), (short) 16)) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_INVALID);
        }

        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, lastIv, (short) 0, (short) 16);

        // decrypt and store
        cipher.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, ISO7816.OFFSET_CDATA, (short) 16);
        cipher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 16), (short) 192, t, (short) 0);

        apdu.setOutgoing();
    }

    private void setU(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 16B IV || 32B a || 32B b || 32B c || 32B x || 32B y || 32B z || 16B MAC

        if (Util.arrayCompare(lastIv, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA, (short) 16) != -1) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_REUSE);
        }
        if (!mac.verify(apduBuffer, ISO7816.OFFSET_CDATA, (short) (16 + 192), apduBuffer, (short) (ISO7816.OFFSET_CDATA + 16 + 192), (short) 16)) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_INVALID);
        }

        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, lastIv, (short) 0, (short) 16);

        // decrypt and store
        cipher.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, ISO7816.OFFSET_CDATA, (short) 16);
        cipher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 16), (short) 192, u, (short) 0);

        apdu.setOutgoing();
    }
}
