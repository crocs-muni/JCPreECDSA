package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;

public class AppletTest extends BaseTest {
    public AppletTest() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(false);
    }

    @Test
    public void testSign() throws Exception {
        BigInteger q = ProtocolManager.G.getCurve().getOrder();

        ProtocolManager pm = new ProtocolManager(connect());

        // Trusted precomputation
        BigInteger x1 = ProtocolManager.randomBigInt(32);
        BigInteger x2 = ProtocolManager.randomBigInt(32);
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];

        ECPoint X = ProtocolManager.G.multiply(x1).add(ProtocolManager.G.multiply(x2));

        BigInteger[] Rxs = new BigInteger[100];
        PreSignature[] localPreSignatures = new PreSignature[100];
        byte[][] cardPreSignatures = new byte[128][100];

        for(int i = 0; i < 100; ++i) {
            byte[] iv = new byte[16];
            iv[15] = (byte) i;

            BigInteger r1 = ProtocolManager.randomBigInt(32);
            BigInteger r2 = ProtocolManager.randomBigInt(32);
            BigInteger o1 = ProtocolManager.randomBigInt(32);
            BigInteger o2 = ProtocolManager.randomBigInt(32);
            ECPoint R = ProtocolManager.G.multiply(r1).add(ProtocolManager.G.multiply(r2));
            BigInteger Rx = R.normalize().getRawXCoord().toBigInteger();

            BigInteger u1 = ProtocolManager.randomBigInt(32);
            BigInteger u2 = r1.add(r2).multiply(o1.add(o2)).subtract(u1).mod(q);

            BigInteger v1 = ProtocolManager.randomBigInt(32);
            BigInteger v2 = x1.add(x2).multiply(o1.add(o2)).subtract(v1).mod(q);

            BigInteger v1r = v1.multiply(Rx).mod(q);
            BigInteger v2r = v2.multiply(Rx).mod(q);

            PreSignature localPreSignature = new PreSignature(u1, v1r, o1);
            PreSignature cardPreSignature = new PreSignature(u2, v2r, o2);

            Rxs[i] = Rx;
            localPreSignatures[i] = localPreSignature;
            cardPreSignatures[i] = cardPreSignature.wrap(encKey, macKey, iv);
        }


        // Untrusted signing
        for(int i = 0; i < 100; ++i) {
            BigInteger m = ProtocolManager.hash(new byte[32]);

            byte[] w1u1 = pm.sign(
                    new byte[32],
                    cardPreSignatures[i]
            );
            BigInteger w1 = new BigInteger(1, Arrays.copyOfRange(w1u1, 0, 32));
            BigInteger u1 = new BigInteger(1, Arrays.copyOfRange(w1u1, 32, 64));

            BigInteger w2 = m.multiply(localPreSignatures[i].o).add(localPreSignatures[i].v).mod(q);

            BigInteger u = u1.add(localPreSignatures[i].u).mod(q);
            BigInteger w = w1.add(w2).mod(q);
            BigInteger s = w.multiply(u.modInverse(q)).mod(q);

            byte[] signature = ProtocolManager.rawToDer(Rxs[i], s);

            Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
        }
    }
}
