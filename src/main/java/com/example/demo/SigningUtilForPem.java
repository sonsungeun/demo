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


@Component
public class SigningUtilForPem {
    public final Logger log = LoggerFactory.getLogger(SigningUtilForPem.class);
    
	// private String pemX509Certificate = "-----BEGIN CERTIFICATE-----\n" + //
    //             "MIICyjCCAjOgAwIBAgIJALQugdsrpI6pMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n" + //
    //             "BAYTAktSMQ4wDAYDVQQIDAVTRU9VTDEPMA0GA1UEBwwGU09HQU5HMRMwEQYDVQQK\n" + //
    //             "DApVTklWRVJTSVRZMQ0wCwYDVQQLDARURVNUMQ8wDQYDVQQDDAZURVNURVIxGTAX\n" + //
    //             "BgkqhkiG9w0BCQEWClRFU1RFUi5jb20wHhcNMjQwMjE0MDYwNzEyWhcNMjQwMzE1\n" + //
    //             "MDYwNzEyWjB+MQswCQYDVQQGEwJLUjEOMAwGA1UECAwFU0VPVUwxDzANBgNVBAcM\n" + //
    //             "BlNPR0FORzETMBEGA1UECgwKVU5JVkVSU0lUWTENMAsGA1UECwwEVEVTVDEPMA0G\n" + //
    //             "A1UEAwwGVEVTVEVSMRkwFwYJKoZIhvcNAQkBFgpURVNURVIuY29tMIGfMA0GCSqG\n" + //
    //             "SIb3DQEBAQUAA4GNADCBiQKBgQDFaPjDjhNHvG4QnFbsEjJStfzrD97ZUHY7A9BR\n" + //
    //             "mXQqvGng6wzhdUkNBtZtsJcFdFIdbpP2R8/k7BH8ux0SXO3bAz2e4f9o6Okh02d7\n" + //
    //             "36PeAMsJL2tWUXMdOENMgBhrbbtMWs3xApMJ3PciKoh8QeiHNhTxGt20ymkI5CP5\n" + //
    //             "IZPDiwIDAQABo1AwTjAdBgNVHQ4EFgQUsBAts/M/+PC23gISCVlD5Z89ItMwHwYD\n" + //
    //             "VR0jBBgwFoAUsBAts/M/+PC23gISCVlD5Z89ItMwDAYDVR0TBAUwAwEB/zANBgkq\n" + //
    //             "hkiG9w0BAQsFAAOBgQCmVSmzkBBTVy9HfV3b1rYFRfZvRlDATsIJLq442IjlTZKz\n" + //
    //             "gLixtrMmBJfjz/5U2X7Sez9Jks8CuUUH6CtqeaTkMZV3t00voLd4lF2L9WCLmnID\n" + //
    //             "M5owrYN7btt7yAo4NYPpikorvkuqjWGGPBmTP+q/d6v0eSkkPI2n97rkQaGfAg==\n" + //
    //             "-----END CERTIFICATE-----";
    private String pemX509Certificate = "-----BEGIN CERTIFICATE-----\n" + //
                "MIIDZzCCAk+gAwIBAgIJAO2dH1KbTAp/MA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNV\n" + //
                "BAYTAktSMQ4wDAYDVQQIDAVTRU9VTDEPMA0GA1UECgwGU09HQU5HMRowGAYDVQQD\n" + //
                "DBFzYW1sLnNvZ2FuZy5hYy5rcjAeFw0yNDAzMDQwMjE1MDJaFw0yNTAzMDQwMjE1\n" + //
                "MDJaMEoxCzAJBgNVBAYTAktSMQ4wDAYDVQQIDAVTRU9VTDEPMA0GA1UECgwGU09H\n" + //
                "QU5HMRowGAYDVQQDDBFzYW1sLnNvZ2FuZy5hYy5rcjCCASIwDQYJKoZIhvcNAQEB\n" + //
                "BQADggEPADCCAQoCggEBAMmmdbTAd9WeMqZlGKn46/cu8F/IWgxsC0VHGguDPzaT\n" + //
                "eV/ElCprBY+uCsZP8G6tI/WY22xaT3YlNygRo4gHojQRRoDBgoKNqGaUalLfu6Pa\n" + //
                "kTgpSyHe+EUYhTEkioqC7UlSNNmDJ/2+rjeee9sz6+fxv6eMCj1h1ELPjUxPSoNo\n" + //
                "6k0ir/6FOelEAikaVOMNcXN6OnFFQTCDvuGxLznb2bGoAf9D+JLTmI+mqG3TDBzt\n" + //
                "YenlPAQj+eQE2hbsVIx1qQKgqkGWqMvLgqNMfJ/p+YOwPNu2XnqxPjTufQG3vJEZ\n" + //
                "sPgLKKps0USYerTDUGNjBkHQf56BVufDKssVzh1SerECAwEAAaNQME4wHQYDVR0O\n" + //
                "BBYEFLRaozAn/fa/MrRCDRzgqK1de60YMB8GA1UdIwQYMBaAFLRaozAn/fa/MrRC\n" + //
                "DRzgqK1de60YMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB5qxOE1\n" + //
                "i3imyAVG+axNnORYhLGOTvI6z+YKjzvM2sN3hqWWw2lhm7lAVIfw8yRq+8HEmPqJ\n" + //
                "InBgfuvIInHDlybW8mb0Z6J1glQ4fTG7BVJJUfBV3rYmj2ndcPY+qemEm+OmntgD\n" + //
                "UjrTb3K8BJRpp+2mp/qR+O4z5Z5iqur7TAlqrnpf1Xm87gDzuafF3RNbrcrnOov3\n" + //
                "v26z/mp3FN5TmpSiyUMLZ0/RdVV7jxkSkcIMkzqvZ+7QqWAYfoljXmk7S4PlSKkz\n" + //
                "7FfUuNmoPIL+rbUXzvTgJZ3atyX7oEKU+a3NPbjJKa5rC7T7xnV/pLFs6W35csk6\n" + //
                "Ju/JoI8135we6Zw=\n" + //
                "-----END CERTIFICATE-----\n" + //
                "";
    
    public PublicKey publicKey = null;
    public PrivateKey privateKey = null;


    public static void main(String[] args) throws Exception {
        // PEM 문자열에서 개인 키와 인증서 생성
        // PrivateKey privateKey = getPrivateKeyFromPEM(pemPrivateKey);
        // X509Certificate certificate = getCertificateFromPEM(pemX509Certificate);

        // // BasicX509Credential 생성
        // BasicX509Credential credential = new BasicX509Credential();
        // credential.setEntityCertificate(certificate);
        // credential.setPrivateKey(privateKey);
        // System.out.println(decodePemKeytoDer(pemPublicKey).toString());

    }


    // private PrivateKey getPrivateKeyFromPEM() throws Exception{
    //     try (PEMParser pemParser = new PEMParser(new StringReader(pemPrivateKey))) {
    //         JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    //         Object pemObject = pemParser.readObject();
    //         if (pemObject instanceof PEMKeyPair) {
    //             return converter.getKeyPair((PEMKeyPair) pemObject).getPrivate();
    //         } else if (pemObject instanceof PrivateKeyInfo) {
    //             return converter.getPrivateKey((PrivateKeyInfo) pemObject);
    //         } else {
    //             throw new RuntimeException("예기치 않은 PEM 객체 유형: " + pemObject.getClass().getName());
    //         }
    //     } catch (Exception e) {
    //         throw new RuntimeException("PEM에서 개인 키를 구문 분석하는 데 실패했습니다", e);
    //     }
    // }

    public PrivateKey getPrivateKeyFromPEM() throws Exception{
       // Replace with the path to your PEM file
       Path pemFilePath = Paths.get("C:\\OpenSSL\\bin\\private_key_pcks8.pem");

       // Read the content of the PEM file
       String pemContent = Files.readString(pemFilePath);

       // Extract Base64 encoded key content (remove headers, footers, and newlines)
       String base64Key = pemContent
               .replace("-----BEGIN PRIVATE KEY-----", "")
               .replace("-----END PRIVATE KEY-----", "")
               .replaceAll("\\s", "");
               
               
        byte[] decodedBytes = Base64.getDecoder().decode(base64Key);


        // privateKey 객체로 변환
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        // X509EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(decodedBytes);

        log.info("Print PrivateKey ======================="+Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        
        return privateKey;
    }

    public PublicKey getPublicKeyFromPEM() throws Exception{
       // Replace with the path to your PEM file
       Path pemFilePath = Paths.get("C:\\OpenSSL\\bin\\public_key.pem");

       // Read the content of the PEM file
       String pemContent = Files.readString(pemFilePath);

       // Extract Base64 encoded key content (remove headers, footers, and newlines)
       String base64Key = pemContent
               .replace("-----BEGIN PUBLIC KEY-----", "")
               .replace("-----END PUBLIC KEY-----", "")
               .replaceAll("\\s", "");
             
        byte[] decodedBytes = Base64.getDecoder().decode(base64Key);

        // PublicKey 객체로 변환
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // System.out.println("Print PublicKey ======================="+publicKeySpec);

        return keyFactory.generatePublic(publicKeySpec);
    }

    public byte[] getModulus() throws Exception{
        // Replace with the path to your PEM file
        Path pemFilePath = Paths.get("C:\\OpenSSL\\bin\\public_key.pem");

        // Read the content of the PEM file
        String pemContent = Files.readString(pemFilePath);

        // Extract Base64 encoded key content (remove headers, footers, and newlines)
        String base64Key = pemContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "")
                .replaceAll("\\n", "");

        // Decode Base64 to get the key bytes
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        // Generate X509EncodedKeySpec from key bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // Get KeyFactory instance for RSA
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");

        // Generate RSAPublicKey from X509EncodedKeySpec
        PublicKey publicKey = keyFactoryRSA.generatePublic(keySpec);

        // Get modulus and exponent
        byte[] modulus = ((java.security.interfaces.RSAPublicKey) publicKey).getModulus().toByteArray();
        // System.out.println("modulus ---------------------"+Base64.getEncoder().encodeToString(modulus));
        return modulus;
    }

    public byte[] getExponent() throws Exception{
        // Replace with the path to your PEM file
        Path pemFilePath = Paths.get("C:\\OpenSSL\\bin\\public_key.pem");

        // Read the content of the PEM file
        String pemContent = Files.readString(pemFilePath);

        // Extract Base64 encoded key content (remove headers, footers, and newlines)
        String base64Key = pemContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "")
                .replaceAll("\\n", "");

        // Decode Base64 to get the key bytes
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        // Generate X509EncodedKeySpec from key bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // Get KeyFactory instance for RSA
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");

        // Generate RSAPublicKey from X509EncodedKeySpec
        PublicKey publicKey = keyFactoryRSA.generatePublic(keySpec);

        // Get modulus and exponent
        byte[] exponent = ((java.security.interfaces.RSAPublicKey) publicKey).getPublicExponent().toByteArray();
        // System.out.println("exponent ---------------------"+Base64.getEncoder().encodeToString(exponent));
        return exponent;
    }

    private X509Certificate getCertificateFromPEM() throws Exception {
        pemX509Certificate = pemX509Certificate
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "")
                .replaceAll("\\n", "");

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        byte[] certificateData = Base64.getDecoder().decode(pemX509Certificate);
        System.out.println("Parsed Certificate============================\n"+Base64.getEncoder().encodeToString(certificateData)); // 여기까진 데이터 똑같이 파싱됨
        return (X509Certificate) certFactory.generateCertificate(new java.io.ByteArrayInputStream(certificateData));
    }

    // private X509Certificate getCertificateFromPEM() throws Exception {
    //     CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    //     FileInputStream fileInputStream = new FileInputStream("C:\\OpenSSL\\bin\\certificate.pem");
    //     X509Certificate cer = (X509Certificate)certificateFactory.generateCertificate(fileInputStream);
    //     return cer;
    // }

    public BasicX509Credential getX509Credential() throws Exception{
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(getCertificateFromPEM());
        // credential.setPrivateKey(getPrivateKeyFromPEM());
        // credential.setPrivateKey(credential.getPrivateKey());
        return credential;
    } 
    
    public BasicX509Credential getX509CredentialForResponse() throws Exception{
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(getCertificateFromPEM());
        credential.setPrivateKey(getPrivateKeyFromPEM());
        // credential.setPrivateKey(credential.getPrivateKey());
        return credential;
    } 
    

    public void printX509Credential() throws Exception{
        BasicX509Credential credential = getX509Credential();
        StringBuilder sb = new StringBuilder();
        sb.append("Entity Certificate:\n")
            .append(credential.getEntityCertificate())
            .append("\n")
            .append("PrivateKey:\n")
            .append(credential.getPrivateKey());
        System.out.println(sb.toString());
    }   

}
