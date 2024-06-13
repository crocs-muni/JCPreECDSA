package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.Util;
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
        byte[][] cardPreSignatures = new byte[100][128];

        for(int i = 0; i < 100; ++i) {
            byte[] iv = new byte[16];
            iv[15] = (byte) (i + 1);

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

        pm.setup(encKey, macKey);


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

    @Test
    public void testTripleSign() throws Exception {
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

            // Host sends t1.c to card
            byte[] recv = pm.sign1(new byte[32], t1s[i].c);
            // Card sends c, R2, and H(c2hat)
            BigInteger c = new BigInteger(1, Arrays.copyOfRange(recv, (short) 0, (short) 32));
            ECPoint R2 = ProtocolManager.G.getCurve().decodePoint(Arrays.copyOfRange(recv, (short) 32, (short) 32 + 65));
            byte[] comm1 = Arrays.copyOfRange(recv, (short) (32 + 65), (short) (32 + 65 + 32));

            ECPoint R = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t1s[i].b).add(R2);
            BigInteger Rx = R.normalize().getRawXCoord().toBigInteger();
            BigInteger c1hat = (t1s[i].z.subtract(delta1.multiply(c)).mod(q));
            ECPoint R1hat = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t1s[i].y).subtract(R.multiply(delta1));

            BigInteger a1 = t1s[i].a.subtract(u1s[i].a).mod(q);
            BigInteger b1 = x1.subtract(u1s[i].b).mod(q);

            // Host sends a1, b1, R, H(c1hat, R1hat)
            recv = pm.sign2(a1, b1, R, ProtocolManager.hash(Util.concat(ProtocolManager.encodeBigInteger(c1hat), R1hat.getEncoded(false))));
            // Card sends a, b, c2hat, H(a2hat, b2hat, R2hat)
            BigInteger a = new BigInteger(1, Arrays.copyOfRange(recv, (short) 0, (short) 32));
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(recv, (short) 32, (short) 64));
            BigInteger c2hat = new BigInteger(1, Arrays.copyOfRange(recv, 64, 96));
            byte[] comm2 = Arrays.copyOfRange(recv, (short) 96, (short) 128);

            assert ProtocolManager.hash(ProtocolManager.encodeBigInteger(c2hat)).equals(new BigInteger(1, comm1));
            assert c1hat.add(c2hat).mod(q).equals(BigInteger.ZERO);
            BigInteger a1hat = t1s[i].x.subtract(u1s[i].x).subtract(delta1.multiply(a)).mod(q);
            BigInteger b1hat = omega1.subtract(u1s[i].y).subtract(delta1.multiply(b)).mod(q);

            // Host sends c1hat, R1hat, H(a1hat, b1hat)
            recv = pm.sign3(c1hat, R1hat, ProtocolManager.hash(Util.concat(ProtocolManager.encodeBigInteger(a1hat), ProtocolManager.encodeBigInteger(b1hat))));
            // Card sends a2hat, b2hat, R2hat
            BigInteger a2hat = new BigInteger(1, Arrays.copyOfRange(recv, 0, 32));
            BigInteger b2hat = new BigInteger(1, Arrays.copyOfRange(recv, 32, 64));
            ECPoint R2hat = ProtocolManager.G.getCurve().decodePoint(Arrays.copyOfRange(recv, 64, 64 + 65));

            assert ProtocolManager.hash(Util.concat(ProtocolManager.encodeBigInteger(a2hat), ProtocolManager.encodeBigInteger(b2hat), R2hat.getEncoded(false))).equals(new BigInteger(1, comm2));
            assert R1hat.equals(R2hat.negate());
            assert a1hat.add(a2hat).mod(q).equals(BigInteger.ZERO);
            assert b1hat.add(b2hat).mod(q).equals(BigInteger.ZERO);

            // Host sends a1hat, b1hat
            recv = pm.sign4(a1hat, b1hat);
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
