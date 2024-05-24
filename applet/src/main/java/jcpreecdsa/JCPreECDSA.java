package jcpreecdsa;

import javacard.framework.*;
import javacard.security.*;
import jcpreecdsa.jcmathlib.*;


public class JCPreECDSA extends Applet {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    private ResourceManager rm;
    private ECCurve curve;
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    private BigNat bn1, bn2;
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
                case Consts.INS_RESET:
                    reset(apdu);
                    break;
                case Consts.INS_SIGN:
                    sign(apdu);
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

        initialized = true;
    }

    private void reset(APDU apdu) {
        apdu.setOutgoing();
    }

    private void sign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer(); // 32B MSG || u1 || v1 * Rx || o1

        md.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32, ramArray, (short) 0);
        bn1.fromByteArray(ramArray, (short) 0, (short) 32);

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) 32);
        bn1.modMult(bn2, curve.rBN);

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 32);
        bn1.modAdd(bn2, curve.rBN);

        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);

        bn1.copyToByteArray(apduBuffer, (short) 0);
        bn2.copyToByteArray(apduBuffer, (short) 32);

        // w1 = H(m) * o1 + v1 * R.x
        // return w1, u1
        apdu.setOutgoingAndSend((short) 0, (short) 64);
    }
}
