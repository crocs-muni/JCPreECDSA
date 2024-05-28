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
    private byte[] k2 = new byte[32];

    private BigNat bn1, bn2, bn3;
    private ECPoint point;
    private ECPoint publicKey;
    private BigNat secretKey;
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);

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
                case Consts.INS_SIGN1:
                    sign1(apdu);
                    break;
                case Consts.INS_SIGN2:
                    sign2(apdu);
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
        publicKey = new ECPoint(curve);

        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 16B encKey || 16B macKey
        encKey.setKey(apduBuffer, ISO7816.OFFSET_CDATA);
        macKey.setKey(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 16));
        mac.init(macKey, Signature.MODE_VERIFY);
        Util.arrayFillNonAtomic(lastIv, (short) 0, (short) lastIv.length, (byte) 0);

        random.generateData(ramArray, (short) 0, (short) 32);
        secretKey.fromByteArray(ramArray, (short) 0, (short) 32);
        publicKey.setW(curve.G, (short) 0, (short) curve.G.length);
        publicKey.multiplication(secretKey);

        apdu.setOutgoingAndSend((short) 0, publicKey.getW(apduBuffer, (short) 0));
    }

    private void sign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 32B MSG || 16B IV || 32B u1 || 32B v1 * Rx || 32B o1 || 16B MAC

        if (Util.arrayCompare(lastIv, (short) 0, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 16) != -1) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_REUSE);
        }
        if (!mac.verify(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) (96 + 16), apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16 + 96), (short) 16)) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_INVALID);
        }
        Util.arrayCopyNonAtomic(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), lastIv, (short) 0, (short) 16);

        md.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32, ramArray, (short) 0);
        bn1.fromByteArray(ramArray, (short) 0, (short) 32);

        // decrypt in place
        cipher.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 16);
        cipher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16), (short) 96, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16));

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 * 3 + 16), (short) 32);
        bn1.modMult(bn2, curve.rBN);

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 * 2 + 16), (short) 32);
        bn1.modAdd(bn2, curve.rBN);

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 16), (short) 32);

        // w1 = H(m) * o1 + v1 * R.x
        bn1.copyToByteArray(apduBuffer, (short) 0);
        // u1
        bn2.copyToByteArray(apduBuffer, (short) 32);

        apdu.setOutgoingAndSend((short) 0, (short) 64);
    }

    private void sign1(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 32B MSG || 32B t1c || 16B IV || 32B a || 32B b || 32B c || 16B MAC

        if (Util.arrayCompare(lastIv, (short) 0, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 16) != -1) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_REUSE);
        }
        if (!mac.verify(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) (96 + 16), apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64 + 16 + 96), (short) 16)) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_INVALID);
        }
        Util.arrayCopyNonAtomic(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), lastIv, (short) 0, (short) 16);

        md.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32, ramArray, (short) 0);
        Util.arrayCopyNonAtomic(ramArray, (short) 0, m, (short) 0, (short) 32);

        // decrypt in place
        cipher.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 16);
        cipher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64 + 16), (short) 96, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64 + 16));

        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64 + 16 + 64), (short) 32);
        bn1.copyToByteArray(apduBuffer, (short) 0); // WARNING: first 32 bytes of APDU are rewritten now on
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
        bn1.modAdd(bn2, curve.rBN);
        bn1.modInv(curve.rBN);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64 + 16 + 32), (short) 32);

        // R2 = c^-1*b2*G
        point.setW(curve.G, (short) 0, (short) curve.G.length);
        point.multiplication(bn1);
        point.multiplication(bn2);
        Util.arrayCopyNonAtomic(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64 + 16), k2, (short) 0, (short) 32);
        point.getW(apduBuffer, (short) 32);

        apdu.setOutgoingAndSend((short) 0, (short) (65 + 32));
    }

    private void sign2(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 32B Rx || 32B a1 || 32B b1 || 16B IV || 32B a || 32B b || 32B c || 16B MAC

        if (Util.arrayCompare(lastIv, (short) 0, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) 16) != -1) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_REUSE);
        }
        if (!mac.verify(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) (96 + 16), apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96 + 16 + 96), (short) 16)) {
            ISOException.throwIt(Consts.E_PRESIGNATURE_INVALID);
        }

        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, ramArray, (short) 0, (short) 32); // Rx

        // decrypt in place
        cipher.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) 16);
        cipher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96 + 16), (short) 96, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96 + 16));

        bn3.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96 + 16), (short) 32);
        bn3.modAdd(bn1, curve.rBN);
        bn2.fromByteArray(k2, (short) 0, (short) 32);
        bn3.modAdd(bn2, curve.rBN);
        bn3.copyToByteArray(apduBuffer, (short) 0);

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 32);
        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96 + 16 + 32), (short) 32);
        bn2.modAdd(bn1, curve.rBN);
        bn2.modAdd(secretKey, curve.rBN);
        bn2.copyToByteArray(apduBuffer, (short) 32);

        bn3.modMult(secretKey, curve.rBN);
        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96 + 16), (short) 32);
        bn2.modMult(bn1, curve.rBN);
        bn3.modSub(bn2, curve.rBN);
        bn1.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96 + 16 + 64), (short) 32);
        bn3.modAdd(bn1, curve.rBN);

        bn2.fromByteArray(ramArray, (short) 0, (short) 32);
        bn3.modMult(bn2, curve.rBN);

        bn1.fromByteArray(m, (short) 0, (short) 32);
        bn2.fromByteArray(k2, (short) 0, (short) 32);
        bn1.modMult(bn2, curve.rBN);
        bn1.modAdd(bn3, curve.rBN);
        bn1.copyToByteArray(apduBuffer, (short) 64);

        apdu.setOutgoingAndSend((short) 0, (short) 96);
    }
}
