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
        BigInteger r1 = ProtocolManager.randomBigInt(32);
        BigInteger r2 = ProtocolManager.randomBigInt(32);
        BigInteger o1 = ProtocolManager.randomBigInt(32);
        BigInteger o2 = ProtocolManager.randomBigInt(32);
        BigInteger x1 = ProtocolManager.randomBigInt(32);
        BigInteger x2 = ProtocolManager.randomBigInt(32);

        ECPoint X = ProtocolManager.G.multiply(x1).add(ProtocolManager.G.multiply(x2));
        ECPoint R = ProtocolManager.G.multiply(r1).add(ProtocolManager.G.multiply(r2));
        BigInteger Rx = R.normalize().getRawXCoord().toBigInteger();

        BigInteger u1 = ProtocolManager.randomBigInt(32);
        BigInteger u2 = r1.add(r2).multiply(o1.add(o2)).subtract(u1).mod(q);

        BigInteger v1 = ProtocolManager.randomBigInt(32);
        BigInteger v2 = x1.add(x2).multiply(o1.add(o2)).subtract(v1).mod(q);

        // Untrusted signing
        BigInteger m = ProtocolManager.hash(new byte[32]);

        // BigInteger w1 = m.multiply(o1).add(Rx.multiply(v1)).mod(q);
        byte[] w1u1 = pm.sign(
                new byte[32],
                new byte[16], // key
                new byte[16], // iv
                u1,
                v1.multiply(Rx).mod(q),
                o1
        );
        BigInteger w1 = new BigInteger(1, Arrays.copyOfRange(w1u1, 0, 32));
        u1 = new BigInteger(1, Arrays.copyOfRange(w1u1, 32, 64));

        BigInteger w2 = m.multiply(o2).add(Rx.multiply(v2)).mod(q);

        BigInteger u = u1.add(u2).mod(q);
        BigInteger w = w1.add(w2).mod(q);
        BigInteger s = w.multiply(u.modInverse(q)).mod(q);

        byte[] signature = ProtocolManager.rawToDer(Rx, s);

        Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
    }
}
