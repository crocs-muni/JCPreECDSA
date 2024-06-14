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
    public void testPreSignatures() throws Exception {
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
        byte[][] cardPreSignatures = new byte[100][128];

        for(int i = 0; i < 100; ++i) {
            byte[] iv = new byte[16];
            iv[15] = (byte) (i + 1);

            BigInteger k1 = ProtocolManager.randomBigInt(32);
            BigInteger k2 = ProtocolManager.randomBigInt(32);
            BigInteger k = k1.add(k2).mod(q);
            ECPoint R = ProtocolManager.G.multiply(k.modInverse(q));
            BigInteger Rx = R.normalize().getAffineXCoord().toBigInteger();

            BigInteger y1 = ProtocolManager.randomBigInt(32);
            BigInteger y2 = x1.add(x2).multiply(k).subtract(y1).mod(q);

            BigInteger z1 = Rx.multiply(y1).mod(q);
            BigInteger z2 = Rx.multiply(y2).mod(q);


            PreSignature localPreSignature = new PreSignature(k1, z1);
            PreSignature cardPreSignature = new PreSignature(k2, z2);

            Rxs[i] = Rx;
            localPreSignatures[i] = localPreSignature;
            cardPreSignatures[i] = cardPreSignature.wrap(encKey, macKey, iv);
        }

        pm.setup(encKey, macKey);

        // Untrusted signing
        for(int i = 0; i < 100; ++i) {
            BigInteger m = ProtocolManager.hash(new byte[32]);

            BigInteger s2 = pm.sign(
                    new byte[32],
                    cardPreSignatures[i]
            );

            BigInteger s1 = m.multiply(localPreSignatures[i].k).add(localPreSignatures[i].z).mod(q);
            BigInteger s = s1.add(s2).mod(q);

            byte[] signature = ProtocolManager.rawToDer(Rxs[i], s);

            Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
        }
    }

    @Test
    public void testMultTriples() throws Exception {
        BigInteger q = ProtocolManager.G.getCurve().getOrder();

        ProtocolManager pm = new ProtocolManager(connect());
        BigInteger delta1 = ProtocolManager.randomBigInt(32);
        BigInteger delta2 = ProtocolManager.randomBigInt(32);
        BigInteger delta = delta1.add(delta2).mod(q);

        BigInteger x1 = ProtocolManager.randomBigInt(32);
        BigInteger x2 = ProtocolManager.randomBigInt(32);
        BigInteger omega1 = ProtocolManager.randomBigInt(32);
        BigInteger omega2 = x1.add(x2).multiply(delta1.add(delta2)).subtract(omega1).mod(q);
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] iv = new byte[16];
        iv[15] = 1;

        assert pm.setup(encKey, macKey, x2, omega2, delta2).equals(ProtocolManager.G.multiply(x2));

        ECPoint X = ProtocolManager.G.multiply(x1).add(ProtocolManager.G.multiply(x2));

        // Trusted precomputation
        MultTriple[] t1s = new MultTriple[10];
        MultTriple[] t2s = new MultTriple[10];
        MultTriple[] u1s = new MultTriple[10];
        MultTriple[] u2s = new MultTriple[10];
        byte[][] wts = new byte[10][224];
        byte[][] wus = new byte[10][224];
        for (int i = 0; i < 10; ++i) {
            MultTriple[] tmp = MultTriple.generate(2, delta);
            t1s[i] = tmp[0];
            t2s[i] = tmp[1];
            iv[15] = (byte) (2 * i + 1);
            wts[i] = tmp[1].wrap(encKey, macKey, iv);
            tmp = MultTriple.generate(2, delta);
            u1s[i] = tmp[0];
            u2s[i] = tmp[1];
            iv[15] = (byte) (2 * i + 2);
            wus[i] = tmp[1].wrap(encKey, macKey, iv);
        }

        for(int i = 0; i < 10; ++i) {
            // Host sends t2, u2 to card
            pm.setT(wts[i]);
            pm.setU(wus[i]);

            BigInteger a1 = t1s[i].a.subtract(u1s[i].a).mod(q);
            BigInteger b1 = x1.subtract(u1s[i].b).mod(q);
            // Host sends m, t1.c, a1, b1 to card
            byte[] recv = pm.sign1(new byte[32], a1, b1, t1s[i].c);
            // Card sends a, b, c, R2, and H(a2hat, b2hat, c2hat)
            BigInteger a = new BigInteger(1, Arrays.copyOfRange(recv, (short) 0, (short) 32));
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(recv, (short) 32, (short) 64));
            BigInteger c = new BigInteger(1, Arrays.copyOfRange(recv, (short) 64, (short) 96));
            ECPoint R2 = ProtocolManager.G.getCurve().decodePoint(Arrays.copyOfRange(recv, (short) 96, (short) (96 + 65)));
            byte[] comm = Arrays.copyOfRange(recv, (short) (96 + 65), (short) (96 + 65 + 32));

            ECPoint R = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t1s[i].b).add(R2);
            BigInteger Rx = R.normalize().getRawXCoord().toBigInteger();
            BigInteger a1hat = t1s[i].x.subtract(u1s[i].x).subtract(delta1.multiply(a)).mod(q);
            BigInteger b1hat = omega1.subtract(u1s[i].y).subtract(delta1.multiply(b)).mod(q);
            BigInteger c1hat = (t1s[i].z.subtract(delta1.multiply(c)).mod(q));
            ECPoint R1hat = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t1s[i].y).subtract(R.multiply(delta1));

            // Host sends a1hat, b1hat, c1hat, R, H(R1hat)
            recv = pm.sign2(a1hat, b1hat, c1hat, R, ProtocolManager.hash(R1hat.getEncoded(false)));
            // Card sends a2hat, b2hat, c2hat, R2hat
            BigInteger a2hat = new BigInteger(1, Arrays.copyOfRange(recv, 0, 32));
            BigInteger b2hat = new BigInteger(1, Arrays.copyOfRange(recv, 32, 64));
            BigInteger c2hat = new BigInteger(1, Arrays.copyOfRange(recv, 64, 96));
            ECPoint R2hat = ProtocolManager.G.getCurve().decodePoint(Arrays.copyOfRange(recv, 96, 96 + 65));

            assert ProtocolManager.hash(Arrays.copyOfRange(recv, (short) 0, (short) 96)).equals(new BigInteger(1, comm));
            assert R1hat.equals(R2hat.negate());
            assert a1hat.add(a2hat).mod(q).equals(BigInteger.ZERO);
            assert b1hat.add(b2hat).mod(q).equals(BigInteger.ZERO);
            assert c1hat.add(c2hat).mod(q).equals(BigInteger.ZERO);

            // Host sends R1hat
            recv = pm.sign3(R1hat);
            // Card sends s2
            BigInteger s2 = new BigInteger(1, recv);

            // Host finalizes signature
            BigInteger s1_prime = u1s[i].c.add(u1s[i].b.multiply(a)).add(u1s[i].a.multiply(b)).add(a.multiply(b)).mod(q);
            BigInteger s1 = ProtocolManager.hash(new byte[32]).multiply(t1s[i].a).add(Rx.multiply(s1_prime)).mod(q);
            BigInteger s = s1.add(s2).mod(q);

            byte[] signature = ProtocolManager.rawToDer(Rx, s);
            Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
        }
    }
}
