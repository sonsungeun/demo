package com.example.demo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.owasp.esapi.errors.CertificateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


@SuppressWarnings("unused")
@Component
public class SigningUtilForPem {

    public static final Logger log = LoggerFactory.getLogger(SigningUtilForPem.class);

    public static PrivateKey getPrivateKeyFromPEM() throws Exception{

       Path pemFilePath = Paths.get("C:\\demo\\src\\main\\resources\\private_key_pcks8.pem");

       String pemContent = Files.readString(pemFilePath);

       String base64Key = pemContent
               .replace("-----BEGIN PRIVATE KEY-----", "")
               .replace("-----END PRIVATE KEY-----", "")
               .replaceAll("\\s", "");
                              
        byte[] decodedBytes = Base64.getDecoder().decode(base64Key);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return privateKey;
    }

    public static PublicKey getPublicKeyFromPEM() throws Exception{

       Path pemFilePath = Paths.get("C:\\demo\\src\\main\\resources\\public_key.pem");

       String pemContent = Files.readString(pemFilePath);

       String base64Key = pemContent
               .replace("-----BEGIN PUBLIC KEY-----", "")
               .replace("-----END PUBLIC KEY-----", "")
               .replaceAll("\\s", "");
             
        byte[] decodedBytes = Base64.getDecoder().decode(base64Key);

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(publicKeySpec);
    }

    private static X509Certificate getCertificateFromPEM() throws Exception {

        Path pemFilePath = Paths.get("C:\\demo\\src\\main\\resources\\x509certificate.pem");

        String pemContent = Files.readString(pemFilePath);

        String base64Key = pemContent
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "")
                .replaceAll("\\n", "");

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        byte[] certificateData = Base64.getDecoder().decode(base64Key);
        return (X509Certificate) certFactory.generateCertificate(new java.io.ByteArrayInputStream(certificateData));
    }


    public static BasicX509Credential getX509Credential() throws Exception{
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(getCertificateFromPEM());
        return credential;
    } 
    
    public static BasicX509Credential getX509CredentialForResponse() throws Exception{
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(getCertificateFromPEM());
        credential.setPrivateKey(getPrivateKeyFromPEM());
        return credential;
    } 
    

    // public static void printX509Credential() throws Exception{
    //     BasicX509Credential credential = getX509Credential();
    //     StringBuilder sb = new StringBuilder();
    //     sb.append("Entity Certificate:\n")
    //         .append(credential.getEntityCertificate())
    //         .append("\n")
    //         .append("PrivateKey:\n")
    //         .append(credential.getPrivateKey());
    //     System.out.println(sb.toString());
    // }   

}
