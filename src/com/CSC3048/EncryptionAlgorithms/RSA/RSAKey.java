package com.CSC3048.EncryptionAlgorithms.RSA;

import java.math.BigInteger;

/**
 * Wrapper class to hold the public / private keys in the format <e,n> or <d,n> with getters and setters to be used by the caller
 */
public class RSAKey implements java.io.Serializable{
	private BigInteger key;
	private BigInteger n;

	public RSAKey(BigInteger key, BigInteger n){
		this.key = key;
		this.n = n;
	}

	public BigInteger getKey() {
		return key;
	}

	public void setKey(BigInteger key) {
		this.key = key;
	}

	public BigInteger getN() {
		return n;
	}

	public void setN(BigInteger n) {
		this.n = n;
	}

	@Override
	public String toString() {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append(key.toString());
		stringBuilder.append(n.toString());
		return stringBuilder.toString();
	}
}
