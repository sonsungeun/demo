package com.example.demo;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Inflater;
import java.security.MessageDigest;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

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
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerImpl;
import org.opensaml.ws.wssecurity.Reference;
import org.opensaml.ws.wssecurity.impl.ReferenceBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.keyinfo.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.ContentReference;
import org.opensaml.xml.signature.DigestMethod;
import org.opensaml.xml.signature.Exponent;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyValue;
import org.opensaml.xml.signature.Modulus;
import org.opensaml.xml.signature.RSAKeyValue;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.Transforms;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExponentBuilder;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.KeyValueBuilder;
import org.opensaml.xml.signature.impl.ModulusBuilder;
import org.opensaml.xml.signature.impl.RSAKeyValueBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.TransformBuilder;
import org.opensaml.xml.signature.impl.TransformsBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.joda.time.DateTime;

import org.opensaml.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.example.demo.SigningUtilForPem;

@RestController
@ComponentScan(basePackages = {"com.example.demo"})
@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class DemoApplication {
	// @Value("${sp.metadata.ACS}")
	// private static String ACSEndpoint;

	private final Logger log = LoggerFactory.getLogger(getClass());	

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
		try {
			// OpenSAML 초기화 (마샬러 사용을 위해 초기화 필요)
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@RequestMapping(value = "/login")
	public String index(){
		return "redirect:/main";
	}

	@RequestMapping(value = "/setCookie",method = RequestMethod.POST)
	public void setUserInfoCookies(HttpServletRequest req, HttpServletResponse res) throws Exception{
		log.info("#################LOG#################"+req.getParameter("UserName")+" : 로그인한 유저명");
		
		//URLEncoder.encode(req.getParameter("UserName"), "UTF-8")
		Cookie coo = new Cookie("user", req.getParameter("UserName"));
		//테스트용으로 세션쿠키 시간 설정
		coo.setMaxAge(1*60*60*24);
		res.addCookie(coo);

		res.sendRedirect("main.html");
	}

	@RequestMapping(value = "/sso/sacsso",method = RequestMethod.POST)
	public void redirectSPEndPoint(HttpServletRequest req, HttpServletResponse res) throws Exception{
		// https://fisco.jp10.hcs.cloud.sap/sap/fpa/ui/app.html#/home
		res.sendRedirect("https://fisco.jp10.hcs.cloud.sap/sap/fpa/ui/app.html#/home");
	}

	// samlrequest 파싱 및 samlresponse 생성
	@RequestMapping(value = "/sso/getSamlRedirect", method = RequestMethod.GET, produces = "application/x-www-form-urlencoded; charset=UTF-8")	
	public ModelAndView getSamlRequest(HttpServletRequest servletRequest,HttpServletResponse servletResponse,@RequestParam("SAMLRequest") String request, @RequestParam("RelayState") String relaystate, @RequestParam("SigAlg") String sigAlg, @RequestParam("Signature") String signature) throws Exception{

		ModelAndView modelAndView = new ModelAndView("samlResponse");
		SigningUtilForPem pem = new SigningUtilForPem();
		
		// 1. samlrequest 디코딩
		String decodedSamlRequest = decodingHttpRequestParams(request);

		// 2. 디코딩 된 데이터 xml 개체로 파싱
		Document document = parseingStringToXmldocument(decodedSamlRequest);
		
		// 3. samlrequest 정보 담긴 객체 생성
		AuthnRequest samlRequest = unmarshallSaml(document);

		// 4. samlresponse 생성
		Response samlResponse = setSamlResponse(servletRequest, samlRequest);
		String ACSUrl = samlResponse.getDestination();
		// System.out.println("ACSUrl@@@@@@@@@"+ACSUrl);
		// URL ACSUrl = new URL(samlResponse.getDestination());
		
		// Signature samlSignature =newSignature();
		// samlResponse.setSignature(samlSignature);

		// 5. 마샬,String 으로 변환 후 Base64 인코딩
		Element samlElement = marshallSaml(samlResponse);
		// Element samlElement = encryptSamlResponse(samlResponse,pem.getPublicKeyFromPEM());
		
		// Signer.signObject(samlSignature);

		String samlResponseString = elementToString(samlElement);
		String encodedResponse = Base64.encodeBytes(samlResponseString.getBytes(),Base64.DONT_BREAK_LINES);
		// String urlEncodedResponse = URLEncoder.encode(encodedResponse, StandardCharsets.UTF_8.toString());


		// sp로 http-post ver.2
		// HTML Form 데이터 생성
		// Map<Object, Object> formData = new HashMap<>();
		// formData.put("SAMLResponse", encodedResponse);
		
		// sendHttpPost(ACSUrl, formData);
		modelAndView.addObject("SAMLResponse", encodedResponse);
		modelAndView.addObject("ACSUrl", ACSUrl);
		modelAndView.addObject("RelayState", relaystate);

		// sp로 리다이렉트
		// servletResponse.sendRedirect(samlResponse.getDestination());
		return modelAndView;
	}

	// private static Element encryptSamlResponse(SAMLObject samlObject, java.security.PublicKey publicKey) throws Exception {
	// // Convert the SAML Response to a DOM Element
	// Element responseElement = Configuration.getMarshallerFactory().getMarshaller(samlObject).marshall(samlObject);

	// // Encryption parameters
	// EncryptionParameters encParams = new EncryptionParameters();
	// encParams.setAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

	// // Key encryption parameters
	// KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
	// BasicCredential credentialForEncrypt = new BasicCredential();
	// credentialForEncrypt.setPublicKey(publicKey);
	// kekParams.setEncryptionCredential(credentialForEncrypt);

	// // Create XMLCipher
	// XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
	// xmlCipher.init(XMLCipher.ENCRYPT_MODE, null); // Use a random key for the symmetric encryption

	// // Set key encryption parameters
	// xmlCipher.setKEK(kekParams);

	// // Set encryption parameters
	// xmlCipher.setParams(encParams);

	// // Create EncryptedData
	// EncryptedData encryptedData = (EncryptedData) xmlCipher.getEncryptedData();

	// // Set the KeyInfo for EncryptedData
	// KeyInfoGeneratorManager keyInfoGeneratorManager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
	// KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(encryptedData);
	// KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
	// KeyInfo keyInfo = keyInfoGenerator.generate(encryptedData, new BasicX509Credential(publicKey));
	// encryptedData.setKeyInfo(keyInfo);

	// // Encrypt the content
	// xmlCipher.doFinal(responseElement.getOwnerDocument(), responseElement, true);

	// return responseElement;
	// }




	// xml -> AuthnRequest 언마샬
	public AuthnRequest unmarshallSaml(Document document) throws Exception{
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();

		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
		if (unmarshaller == null) {
			throw new InsufficientAuthenticationException("Unsuccessful to unmarshal assertion string");
		  } 
		XMLObject samlRequestElement = unmarshaller.unmarshall(document.getDocumentElement());
		
		AuthnRequest samlRequest = (AuthnRequest)samlRequestElement;
		
		// log.info("\n++++++++++++requestID++++++++++++++++\n"+samlRequest.getID());
		// log.info("\n++++++++++++destination++++++++++++++++\n"+samlRequest.getDestination());
		// log.info("\n++++++++++++Issuer++++++++++++++++\n"+samlRequest.getIssuer());

		return  samlRequest;
	}

	public Assertion unmarshallAssertion(Element element) throws Exception{
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		Assertion restoredAssertion = (Assertion) unmarshaller.unmarshall(element);
		return restoredAssertion;
	}

	public Response unmarshallResponse(Element element) throws Exception{
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		Response restoredResponse = (Response) unmarshaller.unmarshall(element);
		return restoredResponse;
	}


	// Http POST 요청 보내기
	public static void sendHttpPost(String url, Map<Object, Object> data) throws Exception {
        // HttpClient 생성
        HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build();
		// HttpClient httpClient = HttpClient.newHttpClient();

        // 전송할 데이터를 문자열로 변환
        StringBuilder postData = new StringBuilder();
        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(entry.getKey().toString(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(entry.getValue().toString(), "UTF-8"));
        }

		System.out.println("포스트데이터출력@@@@@@@@@@@@@@@@@@@@@@@@@@@@"+postData);
        // HTTP POST 요청 설정
		HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(postData.toString()))
                .build();
        // HTTP POST 요청 보내기
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // 응답 출력
        // 응답 헤더 가져오기
        Map<String, List<String>> headers = response.headers().map();

        // 모든 헤더 출력
        headers.forEach((key, values) -> {
            System.out.println(key + ": " + String.join(", ", values));
        });

        // Location 헤더 값 출력
        List<String> locationHeader = headers.get("Location");
        if (locationHeader != null && !locationHeader.isEmpty()) {
            String location = locationHeader.get(0);
            System.out.println("Location: " + location);
        } else{
			System.out.println("Location header is not present or empty.");
		}

		// 응답 출력
		System.out.println("응답 body\n" +response.body());
    }

	// response -> xml 마샬
	public Element marshallSaml(Response samlresponse) throws Exception{
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(samlresponse);
        return marshaller.marshall(samlresponse);
	} 

	public Element marshallSignature(Signature signature) throws Exception{
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signature);
        return marshaller.marshall(signature);
	}

	public Element marshallAssertion(Assertion assertion) throws Exception{
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
		return marshaller.marshall(assertion);
	}
	

	// XML Element -> String
	public String elementToString(Element element) {
		log.info("\n################생성된 RESONSE###############\n"+XMLHelper.nodeToString(element));
        return XMLHelper.nodeToString(element);
    }

	// Httpredirect 로 받은 samlrequest를 디코딩
	public String decodingHttpRequestParams(String encodedValues) throws Exception{		
		// base64 디코딩
		String base64EncodedString = encodedValues.replaceAll("[^a-zA-Z0-9+/=]", "");
		byte[] decodedBytes = java.util.Base64.getDecoder().decode(base64EncodedString);
		
		// Deflate 디코딩
		Inflater inflater = new Inflater(true);
		inflater.setInput(decodedBytes,0,decodedBytes.length);
		byte[] result = new byte[1024];
		int resultLength = inflater.inflate(result);
		inflater.end();

		String decodedSamlRequest = new String(result,0,resultLength,"UTF-8");
		log.info("\n+++++++++++++++SP로부터 온 REQUSET++++++++++++++++++++++\n"+decodedSamlRequest);
		return decodedSamlRequest;
	}

	// 디코딩된 request를 xml로 파싱
	public Document parseingStringToXmldocument(String requestString) throws Exception {
		// Opensaml parser pool 사용
		ParserPool parserPool = new BasicParserPool();
		// string -> byteinputstream
		ByteArrayInputStream is = new ByteArrayInputStream(requestString.getBytes());
		// xml도큐먼트 생성
		Document document = parserPool.parse(is);
		if (document.getDocumentElement() == null) {
			log.info("\n 도큐먼트가 Null 입니다\n");
		}
		return document;
	}

	/*  samlresponse에 필수로 설정되어야 할 값 : 
		x509인증서(필수),
		Issuer(Idpmetadata와 동일한),
		InResponseTo(samlrequest의 Id), 
		Status(사용자 인증 완료된 상태이면 "urn:oasis:names:tc:SAML:2.0:status:Success" 로 설정해야 함)
		Assertion - 유효기간, 서명
		Binding - HttpRedirect
	*/
	@SuppressWarnings("unchecked")
	public Response setSamlResponse(HttpServletRequest request, AuthnRequest samlrequest) throws Exception{
		String destinationUrl = samlrequest.getAssertionConsumerServiceURL();	//ACS URL
		// String destinationUrl = "https://sis334.sogansg.ac.kr:8443/sap/saml2/sp/acs/100";
		String inResponseToId = samlrequest.getID();

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		// saml response 빌더 생성
		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>)builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response samlResponse = responseBuilder.buildObject();

		// Status 빌더 생성
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");	// 사용자 인증 무조건 성공이라고 가정
		status.setStatusCode(statusCode);

		// Issuer 빌더 생성
		SAMLObjectBuilder<Issuer> issuerBuilder1 = (SAMLObjectBuilder<Issuer>)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		SAMLObjectBuilder<Issuer> issuerBuilder2 = (SAMLObjectBuilder<Issuer>)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer samlIssuer1, samlIssuer2;
		samlIssuer1 = issuerBuilder1.buildObject();
		// samlIssuer1 = issuerBuilder1.buildObject("", "Issuer", "");
		// samlIssuer1 = (Issuer)new org.opensaml.ws.wstrust.impl.IssuerImpl("", "", "");
		// Issuer1(assertion issuer) 에서 xmlns:saml2 요소 제거		
		// Element domIssuer1 = ((IssuerImpl)samlIssuer1).getDOM();
		// if(domIssuer1 != null){
		// 	domIssuer1.removeAttribute("xmlns:saml2");
		// 	samlIssuer1.setDOM(domIssuer1);
		// }else{
		// 	System.out.println("DOM of samlIssuer1 is null");
		// }
		// domIssuer1.removeAttribute("xmlns:saml2");
		// samlIssuer1 = (Issuer) Configuration.getUnmarshallerFactory().getUnmarshaller(domIssuer1).unmarshall(domIssuer1);
		samlIssuer2 = issuerBuilder2.buildObject();

		// samlIssuer1.setValue(samlrequest.getIssuer().toString()); // saml request의 issuer 
		// log.info("####################CHK#######################"+samlrequest.getIssuer().getValue());
		// samlIssuer1.setValue(samlrequest.getIssuer().getValue()); // saml request의 issuer 
		// samlIssuer2.setValue("https://fisco.authentication.jp10.hana.ondemand.com");
		samlIssuer1.setValue("https://saml.sogang.ac.kr:8443");
		samlIssuer2.setValue("https://saml.sogang.ac.kr:8443"); // IDP 메타데이터와 동일한 값의 Issuer 설정 

		Assertion samlAssertion = buildAssertion(destinationUrl, inResponseToId, samlIssuer1);
		// Assertion signedAssertion = newSignature(samlAssertion);
		samlAssertion.setSignature(newSignature());

		// samlResponse 속성 설정
		samlResponse.getAssertions().add(samlAssertion);
		// samlResponse.getAssertions().add(signedAssertion);
		samlResponse.setID(new RandomIdentifierGenerator().generateIdentifier());
		samlResponse.setIssueInstant(samlrequest.getIssueInstant());
		samlResponse.setIssuer(samlIssuer2);
		// samlResponse.setIssuer(samlIssuer1);
		samlResponse.setInResponseTo(inResponseToId); //saml request의 ID
		samlResponse.setStatus(status);
		samlResponse.setDestination(destinationUrl);

        // SAML Response에 서명 추가
		// Signature sig = newSignature();
        // samlResponse.setSignature(newSignature());
		Configuration.getMarshallerFactory().getMarshaller(samlResponse).marshall(samlResponse);
		// Element samlElement = marshallAssertion(samlAssertion);
		Signer.signObject(samlAssertion.getSignature());

		return samlResponse;

	}

	public Assertion buildAssertion(String destinationUrl, String inResponseToId, Issuer samlIssuer1){
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		// saml assertion 빌더 생성
		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>)builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion samlAssertion = assertionBuilder.buildObject();

		// samlAssertion 속성 설정
		samlAssertion.setID(new RandomIdentifierGenerator().generateIdentifier());
		samlAssertion.setIssueInstant(new DateTime());

		// authnstatement 빌더 생성
		SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        AuthnStatement authnStatement = authnStatementBuilder.buildObject();

        authnStatement.setAuthnInstant(DateTime.now().minusSeconds(50));
        authnStatement.setSessionIndex(UUID.randomUUID().toString().replace("-",""));

		SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContext authnContext = authnContextBuilder.buildObject();

 	    SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
        
		authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnStatement.setAuthnContext(authnContext);
        samlAssertion.getAuthnStatements().add(authnStatement);
		
		
		// condition 설정
		// 현재 시간에서 특정 시간만큼의 유효 기간 설정 (예: 1일)
		DateTime currentTime = new DateTime();
		DateTime notOnOrAfter = currentTime.plusMinutes(10);
		DateTime notBefore = currentTime.minusMinutes(10);

		// Conditions 객체 생성
		Conditions conditions = new ConditionsBuilder().buildObject();
		conditions.setNotOnOrAfter(notOnOrAfter);
		conditions.setNotBefore(notBefore);
		
		AudienceRestriction audienceRestriction = (AudienceRestriction) Configuration.getBuilderFactory()
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME)
                .buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		Audience audience = (Audience) Configuration.getBuilderFactory()
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME)
                .buildObject(Audience.DEFAULT_ELEMENT_NAME);
        audience.setAudienceURI("https://fisco.authentication.jp10.hana.ondemand.com");// https://fisco.authentication.jp10.hana.ondemand.com
		audienceRestriction.getAudiences().add(audience);
        
		conditions.getAudienceRestrictions().add(audienceRestriction);

		samlAssertion.setConditions(conditions);

		// attributeStatement 추가
		AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();

		Attribute attribute_Gruops = new AttributeBuilder().buildObject();
		attribute_Gruops.setName("Groups");

		Attribute attribute_UserID = new AttributeBuilder().buildObject();
		attribute_UserID.setName("UserID");

		XSAnyBuilder xsAnyBuilder = new XSAnyBuilder();
		XSAny attributeValue_Groups = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
		attributeValue_Groups.setTextContent("sac");
		attributeValue_Groups.getNamespaceManager().registerNamespace(createNamespace("xs","http://www.w3.org/2001/XMLSchema"));
		attributeValue_Groups.getNamespaceManager().registerNamespace(createNamespace("xsi","http://www.w3.org/2001/XMLSchema-instance"));
        attributeValue_Groups.getUnknownAttributes().put(new QName("http://www.w3.org/2001/XMLSchema-instance", "type", "xsi"), "xs:string");
		
		XSAny attributeValue_UserID = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
		attributeValue_UserID.setTextContent("HKIM");
		attributeValue_UserID.getNamespaceManager().registerNamespace(createNamespace("xs","http://www.w3.org/2001/XMLSchema"));
		attributeValue_UserID.getNamespaceManager().registerNamespace(createNamespace("xsi","http://www.w3.org/2001/XMLSchema-instance"));
        attributeValue_UserID.getUnknownAttributes().put(new QName("http://www.w3.org/2001/XMLSchema-instance", "type", "xsi"), "xs:string");

		attribute_Gruops.getAttributeValues().add(attributeValue_Groups);
		attribute_UserID.getAttributeValues().add(attributeValue_UserID);

		attributeStatement.getAttributes().add(attribute_Gruops);
		attributeStatement.getAttributes().add(attribute_UserID);

		samlAssertion.getAttributeStatements().add(attributeStatement);
		

		// Subject 빌더 생성
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>)builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject samlSubject = subjectBuilder.buildObject();

		// SubjectConfirmation 빌더 생성
		SAMLObjectBuilder<SubjectConfirmation> subjectConfirmBuilder = (SAMLObjectBuilder<SubjectConfirmation>)builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation samlSubjectConfirmation = subjectConfirmBuilder.buildObject();

		// SubjectConfirmationData 빌더 생성
		SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>)builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData samlSubjectConfirmationData = subjectConfirmDataBuilder.buildObject();		

		samlSubjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		samlSubjectConfirmationData.setNotOnOrAfter(notOnOrAfter); 		// 현재 시간에서 특정 시간만큼의 유효 기간 설정 (예: 1일)
		samlSubjectConfirmationData.setRecipient(destinationUrl);		// endpoint url
		samlSubjectConfirmationData.setInResponseTo(inResponseToId);	// samlrequest id
		samlSubjectConfirmation.setSubjectConfirmationData(samlSubjectConfirmationData);

		samlSubject.getSubjectConfirmations().add(samlSubjectConfirmation);


		// NameID 빌더 생성
		SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>)builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID samlNameID = nameIdBuilder.buildObject();
		samlNameID.setValue("HKIM"); // 실제 로그인 할 nameId값 설정
		samlNameID.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
		samlNameID.setNameQualifier("https://saml.sogang.ac.kr:8443");
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

	// XMLObject를 DOM Element로 변환하는 함수
    public static Element marshallSamlObject(XMLObject xmlObject) {
        Element element = null;
        try {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
            element = marshaller.marshall(xmlObject);
        } catch (MarshallingException e) {
            // 처리 코드 추가
            e.printStackTrace();
        }
        return element;
    }


	public Signature newSignature() throws Exception {
		SigningUtilForPem pem = new SigningUtilForPem();

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		SignatureBuilder signatureBuilder = (SignatureBuilder)builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
		Signature signature = signatureBuilder.buildObject();

		// KeyInfo 생성
		KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder)builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = keyInfoBuilder.buildObject();

		// 개인키로 서명
		BasicCredential credential = new BasicCredential();
		credential.setPrivateKey(pem.getPrivateKeyFromPEM());
		credential.setPublicKey(pem.getPublicKeyFromPEM());
		// credential2.setPublicKey(pem.getPublicKeyFromPEM());
		// System.out.println("Signing Credential ----------------------"+credential.getPrivateKey());
		// signature.setSigningCredential(credential2);

		// 인증서를 담은 개인키 서명
		signature.setSigningCredential(credential);

		// 서명에 정규화방법, 서명 알고리즘 추가
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);


		// 보안이슈로 modulus, exponent값 직접 설정은 권장되지 않음
		// 공개키로 서명
		// KeyValueBuilder keyValueBuilder = (KeyValueBuilder)builderFactory.getBuilder(KeyValue.DEFAULT_ELEMENT_NAME);
		// KeyValue keyValue = keyValueBuilder.buildObject();

		// RSAKeyValueBuilder rsaKeyValueBuilder = (RSAKeyValueBuilder)builderFactory.getBuilder(RSAKeyValue.DEFAULT_ELEMENT_NAME);
		// RSAKeyValue rsaKeyValue = rsaKeyValueBuilder.buildObject();

		// ModulusBuilder modulusBuilder = (ModulusBuilder)builderFactory.getBuilder(Modulus.DEFAULT_ELEMENT_NAME);
		// Modulus modulus = modulusBuilder.buildObject();
		// // modulus.setValue(Base64.encodeBytes(pem.getPublicKeyFromPEM().getEncoded()));
		// modulus.setValue(Base64.encodeBytes(pem.getModulus()).replace("\r", "").replace("\n", ""));

		// ExponentBuilder exponentBuilder = (ExponentBuilder)builderFactory.getBuilder(Exponent.DEFAULT_ELEMENT_NAME);
		// Exponent exponent = exponentBuilder.buildObject();
		// // exponent.setValue(Base64.encodeBytes(pem.getPublicKeyFromPEM().getEncoded()));
		// exponent.setValue(Base64.encodeBytes(pem.getExponent()).replace("\r", "").replace("\n", ""));

		// rsaKeyValue.setModulus(modulus);
        // rsaKeyValue.setExponent(exponent);
		
		// keyValue.setRSAKeyValue(rsaKeyValue);
        // keyInfo.getKeyValues().add(keyValue);


		// X.509 데이터 생성
		X509DataBuilder x509DataBuilder = (X509DataBuilder) builderFactory.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = x509DataBuilder.buildObject();

		// X.509 인증서 추가
		X509CertificateBuilder x509CertificateBuilder = (X509CertificateBuilder) builderFactory.getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = x509CertificateBuilder.buildObject();
		try {
			BasicX509Credential certifi = pem.getX509CredentialForResponse();
			x509Certificate.setValue(Base64.encodeBytes(certifi.getEntityCertificate().getEncoded(),Base64.DONT_BREAK_LINES));
			// x509Certificate.setValue(Base64.encodeBytes(certifi.getEntityCertificate().getEncoded()));
			System.out.println("BasicX509 ParsedCertificate================\n"+java.util.Base64.getEncoder().encodeToString(certifi.getEntityCertificate().getEncoded()));
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		x509Data.getX509Certificates().add(x509Certificate);

		// KeyInfo에 X.509 데이터 추가
		keyInfo.getX509Datas().add(x509Data);

		// 서명에 KeyInfo 추가
		signature.setKeyInfo(keyInfo);


		//서명에 정규화방법, 서명 알고리즘 추가
		signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
		signature.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		
		return signature;
	}

	public Signature newSignature(Assertion assertion) throws Exception {
		SigningUtilForPem pem = new SigningUtilForPem();

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		SignatureBuilder signatureBuilder = (SignatureBuilder)builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
		Signature signature = signatureBuilder.buildObject();

		// KeyInfo 생성
		KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder)builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = keyInfoBuilder.buildObject();

		// 개인키로 서명
		BasicCredential credential = new BasicCredential();
		credential.setPrivateKey(pem.getPrivateKeyFromPEM());
		credential.setPublicKey(pem.getPublicKeyFromPEM());

		// 인증서를 담은 개인키 서명
		signature.setSigningCredential(credential);

		// 서명에 정규화방법, 서명 알고리즘 추가
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);


		// X.509 데이터 생성
		X509DataBuilder x509DataBuilder = (X509DataBuilder) builderFactory.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = x509DataBuilder.buildObject();

		// X.509 인증서 추가
		X509CertificateBuilder x509CertificateBuilder = (X509CertificateBuilder) builderFactory.getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = x509CertificateBuilder.buildObject();
		try {
			BasicX509Credential certifi = pem.getX509CredentialForResponse();
			x509Certificate.setValue(Base64.encodeBytes(certifi.getEntityCertificate().getEncoded(),Base64.DONT_BREAK_LINES));
			// x509Certificate.setValue(Base64.encodeBytes(certifi.getEntityCertificate().getEncoded()));
			// System.out.println("BasicX509 ParsedCertificate================\n"+java.util.Base64.getEncoder().encodeToString(certifi.getEntityCertificate().getEncoded()));
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		x509Data.getX509Certificates().add(x509Certificate);

		// KeyInfo에 X.509 데이터 추가
		keyInfo.getX509Datas().add(x509Data);
		

		// 서명에 KeyInfo 추가
		signature.setKeyInfo(keyInfo);

		//서명에 정규화방법, 서명 알고리즘 추가
		signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
		signature.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

		// assertion.setSignature(signature);
		// Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
		// Signer.signObject(signature);
		// Assertion signedAssertion = unmarshallAssertion(marshAssertion);
		
		return signature;
	}


	public String calculateSHA256DigestValue(String data) throws Exception {
		MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
		byte[] digestBytes = sha256Digest.digest(data.getBytes("UTF-8"));
		return org.apache.commons.codec.binary.Base64.encodeBase64String(digestBytes);
	}
}