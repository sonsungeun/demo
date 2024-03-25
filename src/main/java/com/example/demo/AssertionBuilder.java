package com.example.demo;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.RandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import java.util.UUID;


public class AssertionBuilder {

	private static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

	@SuppressWarnings("unchecked")
    static <T> T buildSAMLObject(final Class<T> objectClass, QName qName) {
        return (T) builderFactory.getBuilder(qName).buildObject(qName);
    }	
	
	public static Assertion buildAssertion(String destinationUrl, String inResponseToId, Issuer samlIssuer1, DateTime issueTime){

		// saml assertion 빌더 생성
		Assertion samlAssertion = buildSAMLObject(Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);

		// samlAssertion 속성 설정
		samlAssertion.setID(new RandomIdentifierGenerator().generateIdentifier());
		samlAssertion.setIssueInstant(issueTime);

		// authnstatement 빌더 생성
        AuthnStatement authnStatement = buildSAMLObject(AuthnStatement.class, AuthnStatement.DEFAULT_ELEMENT_NAME);

        authnStatement.setAuthnInstant(issueTime);
		authnStatement.setSessionNotOnOrAfter(issueTime.plusHours(10)); // issuetime+10시간
        authnStatement.setSessionIndex(UUID.randomUUID().toString().replace("-",""));

        AuthnContext authnContext = buildSAMLObject(AuthnContext.class, AuthnContext.DEFAULT_ELEMENT_NAME);

        AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class, AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        
		authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnStatement.setAuthnContext(authnContext);
        samlAssertion.getAuthnStatements().add(authnStatement);
		
		// Conditions 객체 생성
		Conditions conditions = new ConditionsBuilder().buildObject();
		conditions.setNotOnOrAfter(issueTime.minusSeconds(2).plusMinutes(1)); // issueTime +1분
		conditions.setNotBefore(issueTime.minusSeconds(2)); // issueTime -2초
		
		AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class, AudienceRestriction.DEFAULT_ELEMENT_NAME);
		Audience audience = buildSAMLObject(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
        audience.setAudienceURI("https://fisco.authentication.jp10.hana.ondemand.com");// https://fisco.authentication.jp10.hana.ondemand.com
		audienceRestriction.getAudiences().add(audience);
        
		conditions.getAudienceRestrictions().add(audienceRestriction);

		samlAssertion.setConditions(conditions);

		// attributeStatement 추가
		AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();

		Attribute attribute_Gruops = new AttributeBuilder().buildObject();
		attribute_Gruops.setName("Groups");

		XSAnyBuilder xsAnyBuilder = new XSAnyBuilder();
		XSAny attributeValue_Groups = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
		attributeValue_Groups.setTextContent("sac");
		attributeValue_Groups.getNamespaceManager().registerNamespace(createNamespace("xs","http://www.w3.org/2001/XMLSchema"));
		attributeValue_Groups.getNamespaceManager().registerNamespace(createNamespace("xsi","http://www.w3.org/2001/XMLSchema-instance"));
        attributeValue_Groups.getUnknownAttributes().put(new QName("http://www.w3.org/2001/XMLSchema-instance", "type", "xsi"), "xs:string");
		

		attribute_Gruops.getAttributeValues().add(attributeValue_Groups);
		attributeStatement.getAttributes().add(attribute_Gruops);
		samlAssertion.getAttributeStatements().add(attributeStatement);
		

		// Subject 빌더 생성
		Subject samlSubject = buildSAMLObject(Subject.class, Subject.DEFAULT_ELEMENT_NAME);

		// SubjectConfirmation 빌더 생성
		SubjectConfirmation samlSubjectConfirmation = buildSAMLObject(SubjectConfirmation.class, SubjectConfirmation.DEFAULT_ELEMENT_NAME);

		// SubjectConfirmationData 빌더 생성
		SubjectConfirmationData samlSubjectConfirmationData = buildSAMLObject(SubjectConfirmationData.class, SubjectConfirmationData.DEFAULT_ELEMENT_NAME);

		samlSubjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		samlSubjectConfirmationData.setNotOnOrAfter(issueTime.minusSeconds(2).plusMinutes(5)); 		// issuetime -2초 + 5분
		samlSubjectConfirmationData.setRecipient(destinationUrl);		// endpoint url
		samlSubjectConfirmationData.setInResponseTo(inResponseToId);	// samlrequest id
		samlSubjectConfirmation.setSubjectConfirmationData(samlSubjectConfirmationData);

		samlSubject.getSubjectConfirmations().add(samlSubjectConfirmation);


		// NameID 빌더 생성
		NameID samlNameID = buildSAMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		samlNameID.setValue("YTANK"); // 실제 로그인 할 nameId값 설정
		samlNameID.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
		samlNameID.setNameQualifier("https://saml.sogang.ac.kr");
		samlNameID.setSPNameQualifier("https://fisco.authentication.jp10.hana.ondemand.com");
		samlSubject.setNameID(samlNameID);
		samlAssertion.setSubject(samlSubject);
		samlAssertion.setIssuer(samlIssuer1);

		return samlAssertion;
	}

    public static Namespace createNamespace(String prefix, String uri){
		Namespace namespace = new Namespace(uri,prefix);
		return namespace;
	}

}
