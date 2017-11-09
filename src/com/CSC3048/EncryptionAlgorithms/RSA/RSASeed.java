package com.CSC3048.EncryptionAlgorithms.RSA;

import java.math.BigInteger;

/**
 * Wrapper class used to seed the RSA algorithm for the purposes of the demo
 */
public class RSASeed {
    private final BigInteger q;
    private final BigInteger p;
    private final BigInteger d;

    public RSASeed(int p, int q, int d){
        this.p=BigInteger.valueOf(p);
        this.q=BigInteger.valueOf(q);
        this.d=BigInteger.valueOf(d);

    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getD() {
        return d;
    }
}
