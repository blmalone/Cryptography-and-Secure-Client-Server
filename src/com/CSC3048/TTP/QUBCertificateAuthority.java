package com.CSC3048.TTP;

import com.CSC3048.EncryptionAlgorithms.HA2.HA2Encryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAEncryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;

import java.math.BigInteger;

/**
 * This class outlines the basic functionality of a Certificate Authority.
 * Possible to be implemented as its own secure server that accepts requests for
 * certificates. For demonstrating purposes, subjects of the CA will inherently know
 * the public key of the CA that is needed for certificate verification.
 */
public class QUBCertificateAuthority {

    /**
     * Official CA Name
     */
    private final String officialName = "QUB Certification Authority";

    /**
     * This is kept secret and only the Certification Authority should ever know this.
     * If compromised, all credibility of the CA's certificates is lost. Parties will not
     * accept certificates signed by 'QUB Certification Authority' in such an event.
     */
    private RSAKey privateKey;

    /**
     * The publicly available, well known, public key of the CA.
     * Subjects and parties alike will use this to verify if a certificate
     * was indeed issued by the TTP i.e. QUBCertificateAuthority.
     */
    private RSAKey publicKey;

    private RSAEncryption rsaEncryption;

    public QUBCertificateAuthority() {
        rsaEncryption = new RSAEncryption();
        privateKey = new RSAKey(
                new BigInteger("1107663187548968391450622175967918117778849664042208667983142601265767" +
                "00484985302128800648193053945583727356471912859580712539505821711712194173219325301832211158396" +
                "77721212870884342678092199295489781236046867355456825424310067929587364234866906390048400712175" +
                "8439067998073344371733821639984658655080816216677"),
                new BigInteger("130800175227007972788590324608067568334523327049227145978525422830949259" +
                "30749580119585849319098754199860273945428277833286625346131410639430713450585987964629858832547" +
                "42378575103776234104547231275159517871435334391163677339166193949924600742479204157053810553094" +
                "45885460250494194995289345892649306919297133757"));
        publicKey = new RSAKey(
                new BigInteger("49269721647310719144816337293772485923140881383041728936612357988614402" +
                "43189063473171136098717544486520329132599787657575899421355968845519107993643492961091628294071" +
                "54132588214438259132112492054955640051605195326956316602904178452245868509898956611131255691220" +
                "82458380050210147693530954390677049081733632877"),
                new BigInteger("1308001752270079727885903246080675683345233270492271459785254228309492593" +
                "07495801195858493190987541998602739454282778332866253461314106394307134505859879646298588325474" +
                "23785751037762341045472312751595178714353343911636773391661939499246007424792041570538105530944" +
                "5885460250494194995289345892649306919297133757"));
    }


    /**
     * Accepts an application for a digital certificate by a subject. The CA authority can perform their
     * own internal checks at this point to be able to say with confidence that the subject receiving the
     * certificate is who they claim to be. In reality this method would be asynchronous and the subject wouldn't
     * pause the calling thread to wait for a response. It makes sense for this example to be synchronous.
     *
     * @param partiallyCompleteDigitalCertificate - subject submits a digital certificate with all their credentials
     *                                            filled in. Few fields are left blank for the CA to complete
     * @return - null if the application is rejected, otherwise a valid Digital Certificate.
     */
    public DigitalCertificate acceptApplication(DigitalCertificate partiallyCompleteDigitalCertificate) {
        //Perform what would be internal checks....
        return registerCertificate(partiallyCompleteDigitalCertificate);
    }

    /**
     * Register a certificate for subject (owner) after internal investigation on subject
     * has been conducted by the CA.
     *
     * @param digitalCertificate - contains information needed for registration
     * @return - DigitalCertificate
     */
    private DigitalCertificate registerCertificate(DigitalCertificate digitalCertificate) {
        //Hashing the public key on the certificate
        String hashCodeSubjectPubKey = HA2Encryption.hashCode(digitalCertificate.getPublicKey().toString());

        //Encrypting result with private key of CA
        String encryptedHash =
                rsaEncryption.encrypt(
                        hashCodeSubjectPubKey.substring(hashCodeSubjectPubKey.length()-2,
                                hashCodeSubjectPubKey.length()),
                        privateKey);

        //Adding to the digital signature field of the certificate
        digitalCertificate.setDigitalSignature(encryptedHash);

        //Filling remaining fields. Would usually fill domain of subject but not for this example
        digitalCertificate.setCertificateAuthorityName(officialName);
        digitalCertificate.setVersion(1);

        return digitalCertificate;
    }

    /**
     * Only one public accessor for this class. It will allow subjects to obtain the public key.
     * Private key of the service is not accessible by any other party.
     * @return - public key of CA
     */
    public RSAKey getPublicKey() {
        return publicKey;
    }
}
