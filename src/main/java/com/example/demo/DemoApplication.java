package com.example.demo;

import static com.example.demo.SamlResponseBuilder.*;
import static com.example.demo.SamlRequestHandler.*;


import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.w3c.dom.Element;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@ComponentScan(basePackages = {"com.example.demo"})
@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class DemoApplication {

	private final Logger log = LoggerFactory.getLogger(getClass());	

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
		try {
			// OpenSAML 초기화 (마샬러 사용을 위해 초기화 필요)
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
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
	public ModelAndView getSamlRequest(@RequestParam("SAMLRequest") String request, @RequestParam("RelayState") String relaystate, @RequestParam("SigAlg") String sigAlg, @RequestParam("Signature") String signature) throws Exception{

		ModelAndView modelAndView = new ModelAndView("samlResponse");
		
		// samlrequest 파싱
		AuthnRequest samlRequest = extractSamlRequestContext(request);

		// samlresponse 생성
		Response samlResponse = buildSamlResponse(samlRequest);
		String ACSUrl = samlResponse.getDestination();

		// 5. 마샬,String 으로 변환 후 Base64 인코딩
		Element samlElement = MarshallUtil.marshallSaml(samlResponse);
		String samlResponseString = XMLHelper.nodeToString(samlElement);
		String encodedResponse = Base64.encodeBytes(samlResponseString.getBytes(),Base64.DONT_BREAK_LINES);

		modelAndView.addObject("SAMLResponse", encodedResponse);
		modelAndView.addObject("ACSUrl", ACSUrl);
		modelAndView.addObject("RelayState", relaystate);

		return modelAndView;
	}
}