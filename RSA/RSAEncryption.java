package com.CSC3048.EncryptionAlgorithms.RSA;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

public class RSAEncryption  {

	private BigInteger p;
	private BigInteger q;
	private BigInteger w;
	private BigInteger privateKey;
	private BigInteger publicKey;
	private BigInteger n;

	/**
	 * Default constructor used when keys are already known and new keys do not need to be generated
	 */
	public RSAEncryption(){

	}

	/**
	 * Constructor used when new keys are to be generated
	 * @param bits - Maximum number of bits each key should be able to represented by
	 */
	public RSAEncryption(int bits){
		generateKeys(bits);
	}

	/**
	 * Constructor used for the demo
	 * @param seed - RSASeed Object, contains a value for p, q and d sets keys appropriately
	 */
	public RSAEncryption(RSASeed seed){
		generateSeededKeys(seed);
	}

	/**
	 * Generate new private and public keys
	 * @param bits - Maximum number of bits each key should be able to represented by
	 */
	private void generateKeys(int bits){
		SecureRandom rand = new SecureRandom();
		setP(newRandomPrime(bits/2));
		setQ(newRandomPrime(bits/2));
		while(getQ().compareTo(getP())==0){
			setQ(newRandomPrime(bits/2));
		}
		n = calculateN();
		w = calculateW();
		privateKey = calculatePrivateKey(rand);
		publicKey = calculatePublicKey(getPrivateKeyPair().getKey(),w);
		if(publicKey.compareTo(BigInteger.ZERO) <=0){
			generateKeys(bits);
		}
	}

	/**
	 * Generate seeded keys, p q and d are already set by the seed so e is calculated
	 * @param seed
	 */
	private void generateSeededKeys(RSASeed seed){
		SecureRandom rand = new SecureRandom();
		setP(seed.getP());
		setQ(seed.getQ());
		setPrivateKey(seed.getD());
		n = calculateN();
		w = calculateW();
		privateKey = getPrivateKeyPair().getKey();
		publicKey = calculatePublicKey(getPrivateKeyPair().getKey(),w);
	}

	/**
	 * Calculate public key using iterative extended euclids algorithm
	 * @param d - private key
	 * @param w - totient of d
	 * @return BigInteger value of the public key (e)
	 */
	private BigInteger calculatePublicKey(BigInteger d, BigInteger w) {
		BigInteger temp,
				e1 = BigInteger.ZERO,
				e2 = BigInteger.valueOf(1),
				remainder = BigInteger.valueOf(-1),
				v1 = BigInteger.valueOf(-1);

		while (w != BigInteger.ZERO) {
			remainder = d.mod(w);
			v1 = d.divide(w);
			d = w;
			w = remainder;
			temp = e1;
			e1 = e2.subtract(v1.multiply(e1));
			e2 = temp;
		}

		return e2;
	}

	/**
	 * Multiply p and q to calculate value for n
	 * @return - product of p and q
	 */
	private BigInteger calculateN(){
		return getP().multiply(getQ());
	}

	/**
	 * Multiply p-1 and q-1 to calculate value for n
	 * @return - product of p-1 and q-1
	 */
	private BigInteger calculateW(){
		BigInteger pMinus1 = getP().subtract(BigInteger.ONE);
		BigInteger qMinus1 = getQ().subtract(BigInteger.ONE);
		return pMinus1.multiply(qMinus1);
	}

	/**
	 * Encrypts plaintext using specified key
	 * @param plainText - plaintext to be encrypted
	 * @param keyPair - RSAKey obj containing public or private key to be used for encryption
	 *                   this allows multiple modes of operation for RSA
	 * @return ciphertext in the form of space delimited numbers
	 */
	public String encrypt(String plainText, RSAKey keyPair) {
		char[] textToEncrypt = plainText.toCharArray();
		String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789,;"; //How can we handle numbers?
		String ciphertext = "";

		for (int i = 0; i < textToEncrypt.length; i += 2) {
			char char1 = textToEncrypt[i];
			String plaintextEncoded = "";

			plaintextEncoded += BigInteger.valueOf(alphabet.indexOf(char1) + 1);

			if (i != textToEncrypt.length - 1) {
				char char2 = textToEncrypt[i + 1];
				BigInteger index = BigInteger.valueOf(alphabet.indexOf(char2) + 1);
				plaintextEncoded += String.format("%02d", index);
			}

			ciphertext += expBySquaring(new BigInteger(plaintextEncoded), keyPair);


			ciphertext += " ";
		}
		return ciphertext;
	}

	/**
	 * Decrypts ciphertext using specified key
	 * @param cipherText - ciphertext in the form of space delimited numbers
	 * @param keyPair - RSAKey obj containing public or private key to be used for encryption
	 *                   this allows multiple modes of operation for RSA
	 * @return plaintext String
	 */
	public String decrypt(String cipherText, RSAKey keyPair) {

		String[] encryptedText = cipherText.split(" ");
		String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789,;";
		String[] plaintextEncoded = new String[encryptedText.length];
		String plaintext = "";

		for(int i =0; i< encryptedText.length; i++){
			plaintextEncoded[i] = expBySquaring(new BigInteger(encryptedText[i]), keyPair).toString();
		}

		ArrayList<Integer> splitBlocks = blockSplit(plaintextEncoded);

		for(int index: splitBlocks){
			plaintext += alphabet.charAt(index-1);

		}

		return plaintext;
	}

	/**
	 * Split the paired encoded letters eg. 'ma' = '1301'
	 * @param plaintextEncoded - array containing paired encoding values
	 * @return ArrayList of separated encoding values
	 */
	private ArrayList<Integer> blockSplit(String[] plaintextEncoded) {
		ArrayList<Integer> result = new ArrayList();

		for(int i=0; i< plaintextEncoded.length; i++){
			if(plaintextEncoded[i].length() == 1 || plaintextEncoded[i].length() == 2){
				result.add(Integer.parseInt(plaintextEncoded[i]));
			}else if(plaintextEncoded[i].length() == 3){
				result.add(Integer.parseInt(plaintextEncoded[i].substring(0, 1)));
				result.add(Integer.parseInt(plaintextEncoded[i].substring(1, 3)));
			}else{
				result.add(Integer.parseInt(plaintextEncoded[i].substring(0, 2)));
				result.add(Integer.parseInt(plaintextEncoded[i].substring(2, 4)));
			}
		}
		return result;
	}

	/**
	 * Exponentiation by squaring and dividing - used to find the mod inverse of a number
	 *
	 * @param text - encoded plaintext value
	 * @param keyPair - Public or private key to be used for the calculation
	 * @return
	 */
	private BigInteger expBySquaring(BigInteger text, RSAKey keyPair) {
		String sKey = keyPair.getKey().toString(2);
		BigInteger c = BigInteger.ONE;
		for(int j = 0; j< sKey.length(); j++){
			c = (c.multiply(c)).mod(keyPair.getN());
			if(sKey.charAt(j) =='1'){
				c = c.multiply(text).mod(keyPair.getN());
			}
		}
		return c;

	}

	/**
	 * Calculate private key so that it is less than w and gcd(d,w) = 1
	 * @param rand - SecureRandom used for generating a large, random prime number
	 * @return
	 */
	private BigInteger calculatePrivateKey(SecureRandom rand){
		BigInteger d = BigInteger.probablePrime(getW().bitLength(), rand);
		while(d.compareTo(getW()) != -1){
			d = BigInteger.probablePrime(getW().bitLength(), rand);
		}
		return d;
	}

	/**
	 * Gets value of p
	 * @return value of p
	 */
	private BigInteger getP() {
		return p;
	}

	/**
	 * Gets value of q
	 * @return value of q
	 */
	private BigInteger getQ() {
		return q;
	}

	/**
	 * Gets value of n
	 * @return value of n
	 */
	private BigInteger getN() {
		return n;
	}

	/**
	 * Gets value of w
	 * @return value of w
	 */
	private BigInteger getW(){
		return w;
	}

	/**
	 * Gets public key pair
	 * @return RSAKey obj which encapsulates the public keypair
	 */
	public RSAKey getPublicKeyPair(){
		return new RSAKey(publicKey,getN());
	}

	/**
	 * Gets private key pair
	 * @return RSAKey obj which encapsulates the private keypair
	 */
	public RSAKey getPrivateKeyPair(){
		return new RSAKey(privateKey,getN());
	}

	/**
	 * Sets value of p
	 * @param p - new value of p
	 */
	private void setP(BigInteger p) {
		this.p = p;
	}

	/**
	 * Sets value of q
	 * @param q - new value of q
	 */
	private void setQ(BigInteger q) {
		this.q = q;
	}

	/**
	 * Sets value of d
	 * @param privateKey - new value of d
	 */
	private void setPrivateKey(BigInteger privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * Generate new random prime number
	 * @return random prime number
	 */
	private BigInteger newRandomPrime(int bits) {
		SecureRandom rand = new SecureRandom();
		return BigInteger.probablePrime(bits, rand);
	}
}
