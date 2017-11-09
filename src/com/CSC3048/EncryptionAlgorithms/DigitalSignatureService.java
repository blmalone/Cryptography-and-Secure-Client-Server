package com.CSC3048.EncryptionAlgorithms;

import com.CSC3048.EncryptionAlgorithms.HA2.HA2Encryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAEncryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;
import com.CSC3048.TTP.DigitalCertificate;
import com.CSC3048.TTP.QUBCertificateAuthority;
import com.CSC3048.Utils.StandardMessage;

/**
 * Tasked with the signing and verification of digital signatures on both
 * Digital Certificates and Messages between parties.
 */
public class DigitalSignatureService {

    private QUBCertificateAuthority qubCertificateAuthority;
    private RSAEncryption rsaEncryption;

    public DigitalSignatureService() {
        qubCertificateAuthority = new QUBCertificateAuthority();
        rsaEncryption = new RSAEncryption();
    }

    public DigitalCertificate submitApplicationToCertificationAuthority(DigitalCertificate digitalCertificate) {
        return qubCertificateAuthority.acceptApplication(digitalCertificate);
    }

    public boolean verifyCertificate(DigitalCertificate digitalCertificate) {
        return verifySignature(digitalCertificate.getDigitalSignature(), digitalCertificate.getPublicKey().toString(),
                qubCertificateAuthority.getPublicKey());
    }

    public boolean verifyStandardMessage(StandardMessage standardMessage, RSAKey publicKey) {
        return verifySignature(standardMessage.getDIGITAL_SIGNATURE(), standardMessageToString(standardMessage),
                publicKey);
    }

    private String standardMessageToString(StandardMessage standardMessage) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(standardMessage.getSOURCE_PORT_NUMBER());
        stringBuilder.append(standardMessage.getDESTINATION_PORT_NUMBER());
        stringBuilder.append(standardMessage.getTIME_TO_LIVE().toString());
        stringBuilder.append(standardMessage.isCERTIFICATE());
        stringBuilder.append(standardMessage.getDATA().toString());
        return stringBuilder.toString();
    }

    /**
     * Generate a digital signature by signing a Standard Message
     * @param message - digital signature will be attached to this message
     * @param privateKey - the private key of the message sender
     * @return - a digital signature
     */
    public String signMessage(StandardMessage message, RSAKey privateKey) {
        //Perform hash function on the object.
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(message.getSOURCE_PORT_NUMBER());
        stringBuilder.append(message.getDESTINATION_PORT_NUMBER());
        stringBuilder.append(message.getTIME_TO_LIVE().toString());
        stringBuilder.append(message.isCERTIFICATE());
        stringBuilder.append(message.getDATA().toString());
        //Hash the Standard Message contents
        String hashedStandardMessage = HA2Encryption.hashCode(stringBuilder.toString());
        //Encrypting the hashed standard message with private key so that it can be decrypted with public key.
        return rsaEncryption.encrypt(hashedStandardMessage.substring(hashedStandardMessage.length()-2,
                hashedStandardMessage.length()), privateKey);
    }

    private boolean verifySignature(String signature, String dataToCompare, RSAKey pubKeyOfSender){
        String hashCodeOfData = HA2Encryption.hashCode(dataToCompare);
        //Decrypting the Signature data
        String hashFromSignature = rsaEncryption.decrypt(signature, pubKeyOfSender);
        if (hashCodeOfData.substring(hashCodeOfData.length()-2,
                hashCodeOfData.length()).equals(hashFromSignature)) {
            return true;
        }
        return false;
    }
}
