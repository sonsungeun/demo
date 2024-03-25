package com.example.demo;

import java.util.zip.Inflater;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DecodeUtil {

    private static final Logger log = LoggerFactory.getLogger(DecodeUtil.class);	

    // Httpredirect 로 받은 samlrequest를 디코딩
    public static String decodingHttpRequestParams(String encodedValues) throws Exception{		
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
}
