package com.example.demo;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 * 언마샬러 : Document나 Element 객체를 opensaml 라이브러리의 saml객체로 변환함
 */
public class UnmarshallUtil {
    
	public static AuthnRequest unmarshallSaml(Document document) throws Exception{
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();

		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
		if (unmarshaller == null) {
			throw new InsufficientAuthenticationException("Unsuccessful to unmarshal assertion string");
		  } 
		XMLObject samlRequestElement = unmarshaller.unmarshall(document.getDocumentElement());
		
		AuthnRequest samlRequest = (AuthnRequest)samlRequestElement;
		
		return  samlRequest;
	}

	public static Assertion unmarshallAssertion(Element element) throws Exception{
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		Assertion restoredAssertion = (Assertion) unmarshaller.unmarshall(element);
		return restoredAssertion;
	}

	public static Response unmarshallResponse(Element element) throws Exception{
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		Response restoredResponse = (Response) unmarshaller.unmarshall(element);
		return restoredResponse;
	}
}
