package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
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
        BigInteger mac = ProtocolManager.randomBigInt(32);

        BigInteger x1 = ProtocolManager.randomBigInt(32);
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] iv = new byte[16];
        iv[15] = 1;

        ECPoint X = ProtocolManager.G.multiply(x1).add(pm.setup(encKey, macKey));

        // Trusted precomputation
        MultTriple[] ts = new MultTriple[200];
        byte[][] wts = new byte[200][128];
        for (int i = 0; i < 200; ++i) {
            MultTriple[] tmp = MultTriple.generate(2, mac);
            ts[i] = tmp[0];
            iv[15] = i < 127 ? (byte) (i + 1) : (byte) 0;
            iv[14] = i >= 127 ? (byte) (i + 1 - 127) : (byte) 0;
            wts[i] = tmp[1].wrapShort(encKey, macKey, iv);
        }

        // Untrusted signing
        for (int i = 0; i < 100; ++i) {
            // Host sends t1.c and t2 to card
            byte[] out = pm.sign1(new byte[32], ts[2 * i].c, wts[2 * i]);
            // Card sends t2.c and R2 back
            BigInteger t2c = new BigInteger(1, Arrays.copyOfRange(out, 0, 32));
            ECPoint R2 = ProtocolManager.ecSpec.getCurve().decodePoint(Arrays.copyOfRange(out, 32, 32 + 65));

            BigInteger c = ts[2 * i].c.add(t2c).mod(q);
            ECPoint R1 = ProtocolManager.G.multiply(c.modInverse(q).multiply(ts[2 * i].b));
            BigInteger k1 = ts[2 * i].a;
            ECPoint R = R1.add(R2);
            BigInteger Rx = R.normalize().getRawXCoord().toBigInteger();

            BigInteger a1 = ts[2 * i + 1].a.add(k1).mod(q);
            BigInteger b1 = ts[2 * i + 1].b.add(x1).mod(q);

            // Host sends R, u2, a1, b1 to the card
            out = pm.sign2(Rx, a1, b1, wts[2 * i + 1]);
            // Card sends a, b, s2 to host
            BigInteger a = new BigInteger(1, Arrays.copyOfRange(out, (short) 0, (short) 32));
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(out, (short) 32, (short) 64));
            BigInteger s2 = new BigInteger(1, Arrays.copyOfRange(out, (short) 64, (short) 96));

            // Host finalizes signature
            BigInteger kx1 = a.multiply(x1).subtract(b.multiply(ts[2 * i + 1].a)).add(ts[2 * i + 1].c).mod(q);
            BigInteger s1 = ProtocolManager.hash(new byte[32]).multiply(k1).add(Rx.multiply(kx1)).mod(q);
            BigInteger s = s1.add(s2).mod(q);

            byte[] signature = ProtocolManager.rawToDer(Rx, s);
            Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
        }
    }

    @Test
    public void testMaliciousTripleSign() throws Exception {
        BigInteger q = ProtocolManager.G.getCurve().getOrder();

        ProtocolManager pm = new ProtocolManager(connect());
        BigInteger mac1 = ProtocolManager.randomBigInt(32);
        BigInteger mac2 = ProtocolManager.randomBigInt(32);
        BigInteger mac = mac1.add(mac2).mod(q);

        BigInteger x1 = ProtocolManager.randomBigInt(32);
        BigInteger x2 = ProtocolManager.randomBigInt(32);
        BigInteger omega1 = ProtocolManager.randomBigInt(32);
        BigInteger omega2 = x1.add(x2).multiply(mac1.add(mac2)).subtract(omega1).mod(q);
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] iv = new byte[16];
        iv[15] = 1;

        ECPoint X = ProtocolManager.G.multiply(x1).add(ProtocolManager.G.multiply(x2));

        // Trusted precomputation
        MultTriple[] t1s = new MultTriple[100];
        MultTriple[] t2s = new MultTriple[100];
        MultTriple[] u1s = new MultTriple[100];
        MultTriple[] u2s = new MultTriple[100];
        for (int i = 0; i < 100; ++i) {
            MultTriple[] tmp = MultTriple.generate(2, mac);
            t1s[i] = tmp[0];
            t2s[i] = tmp[1];
            tmp = MultTriple.generate(2, mac);
            u1s[i] = tmp[0];
            u2s[i] = tmp[1];
        }

        int i = 0;
        // Host sends t2, u2 to card

        // Host sends t1.c to card
        BigInteger c = t1s[i].c.add(t2s[i].c).mod(q);
        ECPoint R2 = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t2s[i].b);
        BigInteger c2hat = t2s[i].z.subtract(mac2.multiply(c)).mod(q);
        // Card sends t2.c, R2, and H(c2hat)

        ECPoint R = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t1s[i].b).add(R2);
        BigInteger Rx = R.normalize().getRawXCoord().toBigInteger();
        BigInteger c1hat = (t1s[i].z.subtract(mac1.multiply(c)).mod(q));
        ECPoint R1hat = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t1s[i].y).subtract(R.multiply(mac1));

        BigInteger a1 = t1s[i].a.subtract(u1s[i].a).mod(q);
        BigInteger b1 = x1.subtract(u1s[i].b).mod(q);
        // Host sends a1, b1, R, H(c1hat, R1hat)

        ECPoint R2hat = ProtocolManager.G.multiply(c.modInverse(q)).multiply(t2s[i].y).subtract(R.multiply(mac2));
        BigInteger a = a1.add(t2s[i].a).subtract(u2s[i].a).mod(q);
        BigInteger b = b1.add(x2).subtract(u2s[i].b).mod(q);

        BigInteger a2hat = t2s[i].x.subtract(u2s[i].x).subtract(mac2.multiply(a)).mod(q);
        BigInteger b2hat = omega2.subtract(u2s[i].y).subtract(mac2.multiply(b)).mod(q);
        // Card sends a, b, c2hat, H(R2hat, a2hat, b2hat)

        BigInteger a1hat = t1s[i].x.subtract(u1s[i].x).subtract(mac1.multiply(a)).mod(q);
        BigInteger b1hat = omega1.subtract(u1s[i].y).subtract(mac1.multiply(b)).mod(q);
        // Host sends c1hat, R1hat, H(a1hat, b1hat)

        assert c1hat.add(c2hat).mod(q).equals(BigInteger.ZERO);
        assert R1hat.equals(R2hat.negate());
        // Card sends R2hat, a2hat, b2hat

        assert R1hat.equals(R2hat.negate());
        assert a1hat.add(a2hat).mod(q).equals(BigInteger.ZERO);
        assert b1hat.add(b2hat).mod(q).equals(BigInteger.ZERO);
        // Host sends a1hat, b1hat

        assert a1hat.add(a2hat).mod(q).equals(BigInteger.ZERO);
        assert b1hat.add(b2hat).mod(q).equals(BigInteger.ZERO);
        BigInteger s2_prime = u2s[i].c.add(u2s[i].b.multiply(a)).add(u2s[i].a.multiply(b)).mod(q);
        BigInteger s2 = ProtocolManager.hash(new byte[32]).multiply(t2s[i].a).add(Rx.multiply(s2_prime)).mod(q);
        // Card sends s2


        // Host finalizes signature
        BigInteger s1_prime = u1s[i].c.add(u1s[i].b.multiply(a)).add(u1s[i].a.multiply(b)).add(a.multiply(b)).mod(q);
        BigInteger s1 = ProtocolManager.hash(new byte[32]).multiply(t1s[i].a).add(Rx.multiply(s1_prime)).mod(q);
        BigInteger s = s1.add(s2).mod(q);

        byte[] signature = ProtocolManager.rawToDer(Rx, s);
        Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
    }
}
