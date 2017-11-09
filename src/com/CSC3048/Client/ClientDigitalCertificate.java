package com.CSC3048.Client;

import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;
import com.CSC3048.TTP.DigitalCertificate;

/**
 * Digital certificate based of the Standard X.509 certificate format.
 */
public class ClientDigitalCertificate implements DigitalCertificate, java.io.Serializable {

    /**
     * Version of certificate that is published by the CA
     */
    private int version;

    /**
     * Information about the subject (owner). IP Address/
     */
    private String identificationInformation = "127.0.0.1";

    /**
     * RSA by default as this is the only asymmetric algorithm implemented
     */
    private RSAKey publicKey;

    /**
     * The official name of the granting certification authority.
     */
    private String certificateAuthorityName;

    /**
     * The digital signature is the result of the subjects publicKey hashed with the HA-2
     * Algorithm and encrypted with the CA's private key.
     * This means that the verification of the signature will be as follows:
     * - Receive the public key of the CA
     * - Receive the certificate of the subject (owner, server or client in our case)
     * - Hash the subjects attached public key as hash1.
     * - Decrypt the signature using the CA's public key to get hash2/
     * - Check to see if hash1 == hash2. If they do then the certificate is legitimate.
     * If not then the certificate can be discarded and connection with party terminated.
     */
    private String digitalSignature;

    public ClientDigitalCertificate(){
    }

    public String getIdentificationInformation() {
        return identificationInformation;
    }

    public void setIdentificationInformation(String identificationInformation) {
        this.identificationInformation = identificationInformation;
    }

    @Override
    public RSAKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAKey publicKey) {
        this.publicKey = publicKey;
    }

    public String getCertificateAuthorityName() {
        return certificateAuthorityName;
    }

    public void setCertificateAuthorityName(String certificateAuthorityName) {
        this.certificateAuthorityName = certificateAuthorityName;
    }

    public String getDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(String digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(version);
        stringBuilder.append(identificationInformation);
        stringBuilder.append(publicKey.toString());
        stringBuilder.append(certificateAuthorityName);
        return stringBuilder.toString();
    }
}
