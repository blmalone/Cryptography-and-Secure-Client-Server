package com.CSC3048.Utils;

import java.util.Date;

/**
 * This object will the marshaled to a stream of bytes before being sent to a party.
 * It will then be unmarshalled from a byte stream back to the StandardMessage object that
 * both parties know how to interact with.
 */
public class StandardMessage implements java.io.Serializable {

    /**
     * Port of sending party
     */
    private int SOURCE_PORT_NUMBER;
    /**
     * Port of receiving party
     */
    private int DESTINATION_PORT_NUMBER;
    /**
     * The amount of time a StandardMessage lives for.
     * After it expires the receiving party will not longer accept it.
     */
    private Date TIME_TO_LIVE;
    /**
     * Flag set if the message contains a certificate in the Data field.
     */
    private boolean CERTIFICATE;
    /**
     * Data in the body of the message. Anything placed in here should override the inherited toString() method.
     * Helps with signature verification and signing.
     */
    private Object DATA;
    /**
     * Digital Signature for the Standard Message. Ensures data integrity.
     */
    private String DIGITAL_SIGNATURE;

    public StandardMessage(int source_port_number, int destination_port_number,
                           boolean certificate, Object data) {
        SOURCE_PORT_NUMBER = source_port_number;
        DESTINATION_PORT_NUMBER = destination_port_number;
        TIME_TO_LIVE = new Date();
        CERTIFICATE = certificate;
        DATA = data;
    }

    public int getSOURCE_PORT_NUMBER() {
        return SOURCE_PORT_NUMBER;
    }

    public void setSOURCE_PORT_NUMBER(int SOURCE_PORT_NUMBER) {
        this.SOURCE_PORT_NUMBER = SOURCE_PORT_NUMBER;
    }

    public int getDESTINATION_PORT_NUMBER() {
        return DESTINATION_PORT_NUMBER;
    }

    public void setDESTINATION_PORT_NUMBER(int DESTINATION_PORT_NUMBER) {
        this.DESTINATION_PORT_NUMBER = DESTINATION_PORT_NUMBER;
    }

    public Date getTIME_TO_LIVE() {
        return TIME_TO_LIVE;
    }

    public boolean isCERTIFICATE() {
        return CERTIFICATE;
    }

    public void setCERTIFICATE(boolean CERTIFICATE) {
        this.CERTIFICATE = CERTIFICATE;
    }

    public Object getDATA() {
        return DATA;
    }

    public void setDATA(Object DATA) {
        this.DATA = DATA;
    }

    public String getDIGITAL_SIGNATURE() {
        return DIGITAL_SIGNATURE;
    }

    public void setDIGITAL_SIGNATURE(String DIGITAL_SIGNATURE) {
        this.DIGITAL_SIGNATURE = DIGITAL_SIGNATURE;
    }
}
