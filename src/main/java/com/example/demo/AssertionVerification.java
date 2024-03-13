package com.example.demo;

import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.opensaml.xml.security.x509.X509Util;
import org.opensaml.xml.security.*;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;

import java.io.StringReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.List;

import javax.xml.transform.TransformerException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

public class AssertionVerification {
    
    // public static void validateAssertion(Assertion assertion, BasicX509Credential credential) {
    //     try {
    //         // Validate the Signature of the Assertion
    //         validateAssertionSignature(assertion, credential);

    //         // Additional validation logic for the assertion can be added here

    //         System.out.println("Assertion is valid!");
    //     } catch (ValidationException e) {
    //         System.out.println("Assertion validation failed: " + e.getMessage());
    //     } catch (TransformerException | MarshallingException | SecurityException e) {
    //         e.printStackTrace();
    //     }
    // }

    // private static void validateAssertionSignature(Assertion assertion, BasicX509Credential credential)
    //         throws ValidationException, TransformerException, MarshallingException, SecurityException {
    //     // Get the Signature from the Assertion
    //     Signature signature = assertion.getSignature();

    //     // Create a ValidatorSuite for the Signature
    //     ValidatorSuiteBuilder<Signature> validatorSuiteBuilder = ValidatorSuiteFactory.getSignatureValidatorSuiteBuilder();
    //     ValidatorSuite<Signature> validatorSuite = validatorSuiteBuilder.buildValidatorSuite();
        
    //     // Validate the Signature
    //     validatorSuite.validate(signature);

    //     // Additional validation logic for the signature can be added here

    //     // Validate the Signature using a SignatureValidator
    //     SignatureValidator signatureValidator = new SignatureValidator(credential);
    //     signatureValidator.validate(signature);
    // }

    // public static void main(String[] args) {
    //     // Assume you have an Assertion and BasicX509Credential objects
    //     Assertion assertion = ...;  // Your Assertion object
    //     BasicX509Credential credential = ...;  // Your BasicX509Credential object

    //     // Validate the Assertion
    //     validateAssertion(assertion, credential);
    // }
    // }


    
}

