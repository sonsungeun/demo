package com.example.demo;

import static com.example.demo.SigningUtilForPem.getX509CredentialForResponse;

import java.security.cert.CertificateEncodingException;

import javax.xml.namespace.QName;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;

public class SignatureBuilder {

    private static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    @SuppressWarnings("unchecked")
    static <T> T buildSAMLObject(final Class<T> objectClass, QName qName) {
        return (T) builderFactory.getBuilder(qName).buildObject(qName);
    }

	public static void signAssertion(SignableXMLObject signableXMLObject, Credential signingCredential)
		throws Exception{
		
		Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = buildSAMLObject(KeyInfo.class, KeyInfo.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);
		
		// X.509 데이터 생성
		X509Data x509Data = buildSAMLObject(X509Data.class, X509Data.DEFAULT_ELEMENT_NAME);

		// X.509 인증서 추가
		X509Certificate x509Certificate = buildSAMLObject(X509Certificate.class, X509Certificate.DEFAULT_ELEMENT_NAME);
		try {
			BasicX509Credential certifi = getX509CredentialForResponse();
			x509Certificate.setValue(Base64.encodeBytes(certifi.getEntityCertificate().getEncoded(),Base64.DONT_BREAK_LINES));
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		x509Data.getX509Certificates().add(x509Certificate);

		// KeyInfo에 X.509 데이터 추가
		keyInfo.getX509Datas().add(x509Data);
		

		// 서명에 KeyInfo 추가
		signature.setKeyInfo(keyInfo);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        signableXMLObject.setSignature(signature);

        Configuration.getMarshallerFactory().getMarshaller(signableXMLObject).marshall(signableXMLObject);
        Signer.signObject(signature);
	}
}
