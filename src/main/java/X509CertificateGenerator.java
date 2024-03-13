import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.Base64.InputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;


//X.509인증서 생성 코드 : AES-128, 인증서 유효기간(1년), BASE64인코딩
@Component
public class X509CertificateGenerator {
    private static final Logger log = LoggerFactory.getLogger(X509CertificateGenerator.class);
    
	public static String x509Certificate = "MIICyjCCAjOgAwIBAgIJALQugdsrpI6pMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAktSMQ4wDAYDVQQIDAVTRU9VTDEPMA0GA1UEBwwGU09HQU5HMRMwEQYDVQQKDApVTklWRVJTSVRZMQ0wCwYDVQQLDARURVNUMQ8wDQYDVQQDDAZURVNURVIxGTAXBgkqhkiG9w0BCQEWClRFU1RFUi5jb20wHhcNMjQwMjE0MDYwNzEyWhcNMjQwMzE1MDYwNzEyWjB";

    public static void main(String[] args) throws Exception {

        // X.509 인증서 생성
        // String generatedCertificate = generateX509Certificate();

        // 생성된 인증서 출력
        // System.out.println("Encrypted X.509 Certificate:\n" + generatedCertificate);
    
        readCertificate();
    }

    // public static String generateAndEncryptX509Certificate(SecretKey aesKey) throws Exception {

    //     Date startDate = new Date();
    //     Date endDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000L); // 현재로부터 1년 뒤

    //     //인증서 키 생성(비대칭키)
    //     KeyPair keyPair = generateKeyPair();
        
    //     // Key 확인
    //     log.info("######## 인증서 KEY(Public) : "+keyPair.getPublic());
    //     log.info("######## 인증서 KEY(Private) : "+keyPair.getPrivate());


    //     // 인증서 서명(자체서명)
    //     X500Name issuerName = new X500Name("CN=SelfSignedIssuer");
    //     BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

    //     X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
    //             issuerName, serialNumber, startDate, endDate,
    //             new X500Name("CN=Subject"), keyPair.getPublic());

    //     // 확장 정보 추가 (여기서는 키 식별자를 사용한 예시)
    //     // JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    //     // certificateBuilder.addExtension(extUtils.createSubjectKeyIdentifier(keyPair.getPublic()),false,);

    //     // 자체 서명
    //     ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

    //     X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

    //     // X509CertificateHolder를 X509Certificate로 변환
    //     JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    //     X509Certificate x509Certificate = certificateConverter.getCertificate(certificateHolder);

    //     // 인증서를 바이트로 변환
    //     byte[] certificateBytes = x509Certificate.getEncoded();

    //     // AES 알고리즘으로 암호화
    //     byte[] encryptedBytes = encryptWithAES(certificateBytes, aesKey);

    //     // Base64로 인코딩
    //     return Base64.encodeBase64String(encryptedBytes);
    // }


    // 자체 서명된 인증서 생성
    public static String generateX509Certificate() throws Exception {

        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000L); // 현재로부터 1년 뒤

        //인증서 키 생성(비대칭키)
        KeyPair keyPair = generateKeyPair();
        
        // Key 확인
        log.info("######## 인증서 KEY(Public) : "+keyPair.getPublic());
        log.info("######## 인증서 KEY(Private) : "+keyPair.getPrivate());


        // 인증서 서명(자체서명)
        X500Name issuerName = new X500Name("CN=SelfSignedIssuer");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        // 인증서 빌더 생성(공개키로 자체 서명)
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serialNumber, startDate, endDate,
                new X500Name("CN=Subject"), keyPair.getPublic());

        // 서명 생성(개인키로 인증서 서명)
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        // X509CertificateHolder를 X509Certificate로 변환
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        X509Certificate x509Certificate = certificateConverter.getCertificate(certificateHolder);
        
        // 인증서를 바이트로 변환
        byte[] certificateBytes = x509Certificate.getEncoded();

        // AES 알고리즘으로 암호화
        // byte[] encryptedBytes = encryptWithAES(certificateBytes, aesKey);

        // 해당 인증서를 파일로 저장
        saveCertificateToFile(x509Certificate, "C:\\demo\\src\\main\\resources\\static\\certificate.cer");

        // Base64로 인코딩
        return Base64.encodeBase64String(certificateBytes);        
    }


    // saml respond용 x509인증서 생성
    public static X509Credential generateSamlX509Credential(X509Certificate x509Certificate, KeyPair keyPair){
        BasicX509Credential credential =new BasicX509Credential();
        credential.setEntityCertificate(x509Certificate);
        credential.setPublicKey(keyPair.getPublic());
        credential.setSecretKey((SecretKey)keyPair.getPrivate());

        return credential;
    }

    // 인증서를 파일로 저장
     private static void saveCertificateToFile(X509Certificate certificate, String filePath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(certificate.getEncoded());
        }
    }


    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // AES-128 키
        
        return keyGenerator.generateKey();
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // RSA 키 길이 설정
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptWithAES(byte[] data, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(data);
    }

    public static X509Certificate readCertificate(){
        X509Certificate certificate = null;
        try {
            // FileInputStream fis = new FileInputStream("c:\\demo\\src\\main\\resources\\static\\certificate.cer");
            ByteArrayInputStream is = new java.io.ByteArrayInputStream(x509Certificate.getBytes());
            InputStream fis = new InputStream(is);
            CertificateFactory cFactory = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cFactory.generateCertificate(fis);
            fis.close();
            
            log.info("\n######FIS TEST 발행자 아이디: "+certificate.getIssuerUniqueID());
            log.info("\n######FIS TEST 공개키: "+certificate.getPublicKey());
            log.info("\n######FIS TEST 알고리즘명: "+certificate.getSigAlgName());
            log.info("\n######FIS TEST 버전: "+certificate.getVersion());
            log.info("\n######FIS TEST 서명자: "+certificate.getSigAlgName());
            log.info("\n######FIS TEST 서명: "+certificate.getSignature().toString());
            log.info("\n######FIS TEST 주제 아이디: "+certificate.getSubjectUniqueID());

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch(IOException e){
            e.printStackTrace();;
        }

        return certificate;

    }
}
