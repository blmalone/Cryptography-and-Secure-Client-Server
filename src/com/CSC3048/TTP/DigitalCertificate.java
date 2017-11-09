package com.CSC3048.TTP;

import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;

/**
 * Digital certificate based of the Standard X.509 certificate format.
 */
public interface DigitalCertificate {

    String getIdentificationInformation();

    void setIdentificationInformation(String identificationInformation);

    RSAKey getPublicKey();

    void setPublicKey(RSAKey publicKey);

    String getCertificateAuthorityName();

    void setCertificateAuthorityName(String certificateAuthorityName);

    String getDigitalSignature();

    void setDigitalSignature(String digitalSignature);

    int getVersion();

    void setVersion(int version);

    /**
     * Won't act as a default method as Java restricts multiple inheritance.
     * We should override the toString method for every object that will be placed
     * in the StandardMessage body. Helps with retrieving the hash for digital
     * signature verification.
     */
    @Override
    String toString();
}
