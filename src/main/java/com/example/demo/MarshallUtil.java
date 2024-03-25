package com.example.demo;


import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.Signature;
import org.w3c.dom.Element;

/*
 * 마샬러 : opensaml 객체를 DomElement 객체로 변환함
 */
public class MarshallUtil {

    public static Element marshallSaml(Response samlresponse) throws Exception{
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(samlresponse);
        return marshaller.marshall(samlresponse);
	} 

	public static Element marshallSignature(Signature signature) throws Exception{
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signature);
        return marshaller.marshall(signature);
	}

	public static Element marshallAssertion(Assertion assertion) throws Exception{
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
		return marshaller.marshall(assertion);
	}
    
    public static Element marshallSamlObject(XMLObject xmlObject) throws Exception {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
        return marshaller.marshall(xmlObject);
    }
}
