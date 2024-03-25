package com.example.demo;

import static com.example.demo.SigningUtilForPem.*;
import static com.example.demo.SignatureBuilder.*;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.RandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.credential.Credential;

import jakarta.servlet.http.HttpServletRequest;


/*  samlresponse에 필수로 설정되어야 할 값 : 
    x509인증서(필수),
    Issuer(Idpmetadata와 동일한),
    InResponseTo(samlrequest의 Id), 
    Status(사용자 인증 완료된 상태이면 "urn:oasis:names:tc:SAML:2.0:status:Success" 로 설정해야 함)
    Assertion - 유효기간, 서명
    Binding - HttpRedirect
*/
@SuppressWarnings("unchecked")
public class SamlResponseBuilder {
    public static Response buildSamlResponse(HttpServletRequest request, AuthnRequest samlrequest) throws Exception{
		String destinationUrl = samlrequest.getAssertionConsumerServiceURL();	//ACS URL
		// String destinationUrl = "https://sis334.sogansg.ac.kr/sap/saml2/sp/acs/100";
		String inResponseToId = samlrequest.getID();
		DateTime issueTime = new DateTime().plusMinutes(1);


		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		// saml response 빌더 생성
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>)builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response samlResponse = responseBuilder.buildObject();

		// Status 빌더 생성
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
		Namespace statusCodeNamespace = new Namespace("urn:oasis:names:tc:SAML:2.0:protocol","saml2p");
		status.getNamespaceManager().registerNamespaceDeclaration(statusCodeNamespace);
        statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");	// 사용자 인증 무조건 성공이라고 가정
		statusCode.getNamespaceManager().registerNamespaceDeclaration(statusCodeNamespace);
		status.setStatusCode(statusCode);

		// Issuer 빌더 생성
		SAMLObjectBuilder<Issuer> issuerBuilder1 = (SAMLObjectBuilder<Issuer>)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		SAMLObjectBuilder<Issuer> issuerBuilder2 = (SAMLObjectBuilder<Issuer>)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer samlIssuer1, samlIssuer2;
		samlIssuer1 = issuerBuilder1.buildObject();
		samlIssuer2 = issuerBuilder2.buildObject();
		samlIssuer1.setValue("https://saml.sogang.ac.kr");
		samlIssuer2.setValue("https://saml.sogang.ac.kr"); // IDP 메타데이터와 동일한 값의 Issuer 설정 
		
		Assertion samlAssertion = AssertionBuilder.buildAssertion(destinationUrl, inResponseToId, samlIssuer1,issueTime);

		Credential credential = getX509CredentialForResponse();
		signAssertion(samlAssertion, credential);

		// samlResponse 속성 설정
		samlResponse.getAssertions().add(samlAssertion);
		samlResponse.setID(new RandomIdentifierGenerator().generateIdentifier());
		samlResponse.setIssueInstant(issueTime);
		samlResponse.setIssuer(samlIssuer2);
		samlResponse.setInResponseTo(inResponseToId); //saml request의 ID
		samlResponse.setStatus(status);
		samlResponse.setDestination(destinationUrl);

		return samlResponse;
	}
}
