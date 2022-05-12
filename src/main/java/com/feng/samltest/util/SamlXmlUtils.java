package com.feng.samltest.util;

import com.feng.samltest.constant.SamlConstants;
import com.feng.samltest.exception.SamlException;
import com.feng.samltest.sp.HSM;
import com.feng.samltest.sp.SamlResponseStatus;
import com.feng.samltest.sp.SchemaFactory;
import com.feng.samltest.sp.XMLErrorAccumulatorHandler;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Period;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.joda.time.format.ISOPeriodFormat;
import org.joda.time.format.PeriodFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.*;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import javax.xml.xpath.*;
import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;


/**
 * Util class of OneLogin's Java Toolkit.
 * <p>
 * A class that contains several auxiliary methods related to the SAML protocol
 */
public final class SamlXmlUtils {

    /**
     * Private property to construct a logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SamlXmlUtils.class);

    private static final DateTimeFormatter DATE_TIME_FORMAT = ISODateTimeFormat.dateTimeNoMillis().withZoneUTC();
    private static final DateTimeFormatter DATE_TIME_FORMAT_MILLS = ISODateTimeFormat.dateTime().withZoneUTC();
    public static final String UNIQUE_ID_PREFIX = "SUPOS_";
    /**
     * Indicates if JAXP 1.5 support has been detected.
     */
    private static boolean JAXP_15_SUPPORTED = isJaxp15Supported();

    private static final Set<String> DEPRECATED_ALGOS = new HashSet<>(Arrays.asList(SamlConstants.RSA_SHA1, SamlConstants.DSA_SHA1));

    static {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        org.apache.xml.security.Init.init();
    }

    private SamlXmlUtils() {
        //not called
    }

    /**
     * Method which uses the recommended way ( https://docs.oracle.com/javase/tutorial/jaxp/properties/error.html )
     * of checking if JAXP is equal or greater than 1.5 options are supported. Needed if the project which uses
     * this library also has Xerces in it's classpath.
     * <p>
     * If for whatever reason this method cannot determine if JAXP 1.5 properties are supported it will indicate the
     * options are supported. This way we don't accidentally disable configuration options.
     *
     * @return
     */
    public static boolean isJaxp15Supported() {
        boolean supported = true;

        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            SAXParser parser = spf.newSAXParser();
            parser.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "file");
        } catch (SAXException ex) {
            String err = ex.getMessage();
            if (err.contains("Property 'http://javax.xml.XMLConstants/property/accessExternalDTD' is not recognized.")) {
                //expected, jaxp 1.5 not supported
                supported = false;
            }
        } catch (Exception e) {
            LOGGER.info("An exception occurred while trying to determine if JAXP 1.5 options are supported.", e);
        }

        return supported;
    }

    /**
     * This function load an XML string in a save way. Prevent XEE/XXE Attacks
     *
     * @param xml String. The XML string to be loaded.
     * @return The result of load the XML at the Document or null if any error occurs
     */
    public static Document loadXML(String xml) {
        try {
            if (xml.contains("<!ENTITY")) {
                throw new SamlException("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks");
            }
            return convertStringToDocument(xml);
        } catch (SamlException e) {
            LOGGER.debug("Load XML error due SamlException.", e);
        } catch (Exception e) {
            LOGGER.debug("Load XML error: " + e.getMessage(), e);
        }

        return null;
    }

    private static XPathFactory getXPathFactory() {
        try {
            /*
             * Since different environments may return a different XPathFactoryImpl, we should try to initialize the factory
             * using specific implementation that way the XML is parsed in an expected way.
             *
             * We should use the standard XPathFactoryImpl that comes standard with Java.
             *
             * NOTE: We could implement a check to see if the "javax.xml.xpath.XPathFactory" System property exists and is set
             *       to a value, if people have issues with using the specified implementor. This would allow users to always
             *       override the implementation if they so need to.
             */
            return XPathFactory.newInstance(XPathFactory.DEFAULT_OBJECT_MODEL_URI, "com.sun.org.apache.xpath.internal.jaxp.XPathFactoryImpl", ClassLoader.getSystemClassLoader());
        } catch (XPathFactoryConfigurationException e) {
            LOGGER.debug("Error generating XPathFactory instance: " + e.getMessage(), e);
        }

        /*
         * If the expected XPathFactory did not exist, we fallback to loading the one defined as the default.
         *
         * If this is still throwing an error, the developer can set the "javax.xml.xpath.XPathFactory" system property
         * to specify the default XPathFactoryImpl implementation to use. For example:
         *
         * -Djavax.xml.xpath.XPathFactory:http://java.sun.com/jaxp/xpath/dom=net.sf.saxon.xpath.XPathFactoryImpl
         * -Djavax.xml.xpath.XPathFactory:http://java.sun.com/jaxp/xpath/dom=com.sun.org.apache.xpath.internal.jaxp.XPathFactoryImpl
         *
         */
        return XPathFactory.newInstance();
    }


    /**
     * Extracts a node from the DOMDocument
     *
     * @param dom     The DOMDocument
     * @param query   Xpath Expression
     * @param context Context Node (DomElement)
     * @return DOMNodeList The queried node
     * @throws XPathExpressionException
     */
    public static NodeList query(Document dom, String query, Node context) throws XPathExpressionException {
        NodeList nodeList;
        XPath xpath = getXPathFactory().newXPath();
        xpath.setNamespaceContext(new NamespaceContext() {

            @Override
            public String getNamespaceURI(String prefix) {
                String result = null;
                if (prefix.equals("samlp") || prefix.equals("samlp2")) {
                    result = SamlConstants.NS_SAMLP;
                } else if (prefix.equals("saml") || prefix.equals("saml2")) {
                    result = SamlConstants.NS_SAML;
                } else if (prefix.equals("ds")) {
                    result = SamlConstants.NS_DS;
                } else if (prefix.equals("xenc")) {
                    result = SamlConstants.NS_XENC;
                } else if (prefix.equals("md")) {
                    result = SamlConstants.NS_MD;
                }
                return result;
            }

            @Override
            public String getPrefix(String namespaceURI) {
                return null;
            }

            @SuppressWarnings("rawtypes")
            @Override
            public Iterator getPrefixes(String namespaceURI) {
                return null;
            }
        });

        if (context == null) {
            nodeList = (NodeList) xpath.evaluate(query, dom, XPathConstants.NODESET);
        } else {
            nodeList = (NodeList) xpath.evaluate(query, context, XPathConstants.NODESET);
        }
        return nodeList;
    }

    /**
     * Extracts a node from the DOMDocument
     *
     * @param dom   The DOMDocument
     * @param query Xpath Expression
     * @return DOMNodeList The queried node
     * @throws XPathExpressionException
     */
    public static NodeList query(Document dom, String query) throws XPathExpressionException {
        return query(dom, query, null);
    }

    /**
     * This function attempts to validate an XML against the specified schema.
     *
     * @param xmlDocument The XML document which should be validated
     * @param schemaUrl   The schema filename which should be used
     * @return found errors after validation
     */
    public static boolean validateXML(Document xmlDocument, URL schemaUrl) {
        try {

            if (xmlDocument == null) {
                throw new IllegalArgumentException("xmlDocument was null");
            }

            Schema schema = SchemaFactory.loadFromUrl(schemaUrl);
            Validator validator = schema.newValidator();

            if (JAXP_15_SUPPORTED) {
                // Prevent XXE attacks
                validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            }

            XMLErrorAccumulatorHandler errorAcumulator = new XMLErrorAccumulatorHandler();
            validator.setErrorHandler(errorAcumulator);

            Source xmlSource = new DOMSource(xmlDocument);
            validator.validate(xmlSource);

            final boolean isValid = !errorAcumulator.hasError();
            if (!isValid) {
                LOGGER.warn("Errors found when validating SAML response with schema: " + errorAcumulator.getErrorXML());
            }
            return isValid;
        } catch (Exception e) {
            LOGGER.warn("Error executing validateXML: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Converts an XML in string format in a Document object
     *
     * @param xmlStr The XML string which should be converted
     * @return the Document object
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    public static Document convertStringToDocument(String xmlStr) throws ParserConfigurationException, SAXException, IOException {
        return parseXML(new InputSource(new StringReader(xmlStr)));
    }

    /**
     * Parse an XML from input source to a Document object
     *
     * @param inputSource The InputSource with the XML string which should be converted
     * @return the Document object
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    public static Document parseXML(InputSource inputSource) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory docfactory = DocumentBuilderFactory.newInstance();
        docfactory.setNamespaceAware(true);

        // do not expand entity reference nodes
        docfactory.setExpandEntityReferences(false);

        docfactory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage", XMLConstants.W3C_XML_SCHEMA_NS_URI);

        // Add various options explicitly to prevent XXE attacks.
        // (adding try/catch around every setAttribute just in case a specific parser does not support it.
        try {
            // do not include external general entities
            docfactory.setAttribute("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
        } catch (Throwable e) {
        }
        try {
            // do not include external parameter entities or the external DTD subset
            docfactory.setAttribute("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
        } catch (Throwable e) {
        }
        try {
            docfactory.setAttribute("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
        } catch (Throwable e) {
        }
        try {
            docfactory.setAttribute("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);
        } catch (Throwable e) {
        }
        try {
            // ignore the external DTD completely
            docfactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd", Boolean.FALSE);
        } catch (Throwable e) {
        }
        try {
            // build the grammar but do not use the default attributes and attribute types information it contains
            docfactory.setAttribute("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", Boolean.FALSE);
        } catch (Throwable e) {
        }
        try {
            docfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (Throwable e) {
        }

        DocumentBuilder builder = docfactory.newDocumentBuilder();
        XMLErrorAccumulatorHandler errorAcumulator = new XMLErrorAccumulatorHandler();
        builder.setErrorHandler(errorAcumulator);
        Document doc = builder.parse(inputSource);

        // Loop through the doc and tag every element with an ID attribute
        // as an XML ID node.
        XPath xpath = getXPathFactory().newXPath();
        XPathExpression expr;
        try {
            expr = xpath.compile("//*[@ID]");

            NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
            for (int i = 0; i < nodeList.getLength(); i++) {
                Element elem = (Element) nodeList.item(i);
                Attr attr = (Attr) elem.getAttributes().getNamedItem("ID");
                elem.setIdAttributeNode(attr, true);
            }
        } catch (XPathExpressionException e) {
            return null;
        }

        return doc;
    }

    /**
     * Converts an XML in Document format in a String
     *
     * @param doc  The Document object
     * @param c14n If c14n transformation should be applied
     * @return the Document object
     */
    public static String convertDocumentToString(Document doc, Boolean c14n) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (c14n) {
            XMLUtils.outputDOMc14nWithComments(doc, baos);
        } else {
            XMLUtils.outputDOM(doc, baos);
        }

        return SamlXmlUtils.toStringUtf8(baos.toByteArray());
    }

    /**
     * Converts an XML in Document format in a String without applying the c14n transformation
     *
     * @param doc The Document object
     * @return the Document object
     */
    public static String convertDocumentToString(Document doc) {
        return convertDocumentToString(doc, false);
    }

    /**
     * Returns a certificate in String format (adding header and footer if required)
     *
     * @param cert  A x509 unformatted cert
     * @param heads True if we want to include head and footer
     * @return X509Certificate $x509 Formated cert
     */
    public static String formatCert(String cert, Boolean heads) {
        String x509cert = StringUtils.EMPTY;

        if (cert != null) {
            x509cert = cert.replace("\\x0D", "").replace("\r", "").replace("\n", "").replace(" ", "");

            if (!StringUtils.isEmpty(x509cert)) {
                x509cert = x509cert.replace("-----BEGINCERTIFICATE-----", "").replace("-----ENDCERTIFICATE-----", "");

                if (heads) {
                    x509cert = "-----BEGIN CERTIFICATE-----\n" + chunkString(x509cert, 64) + "-----END CERTIFICATE-----";
                }
            }
        }
        return x509cert;
    }

    /**
     * Returns a private key (adding header and footer if required).
     *
     * @param key   A private key
     * @param heads True if we want to include head and footer
     * @return Formated private key
     */
    public static String formatPrivateKey(String key, boolean heads) {
        String xKey = StringUtils.EMPTY;

        if (key != null) {
            xKey = key.replace("\\x0D", "").replace("\r", "").replace("\n", "").replace(" ", "");

            if (!StringUtils.isEmpty(xKey)) {
                if (xKey.startsWith("-----BEGINPRIVATEKEY-----")) {
                    xKey = xKey.replace("-----BEGINPRIVATEKEY-----", "").replace("-----ENDPRIVATEKEY-----", "");

                    if (heads) {
                        xKey = "-----BEGIN PRIVATE KEY-----\n" + chunkString(xKey, 64) + "-----END PRIVATE KEY-----";
                    }
                } else {

                    xKey = xKey.replace("-----BEGINRSAPRIVATEKEY-----", "").replace("-----ENDRSAPRIVATEKEY-----", "");

                    if (heads) {
                        xKey = "-----BEGIN RSA PRIVATE KEY-----\n" + chunkString(xKey, 64) + "-----END RSA PRIVATE KEY-----";
                    }
                }
            }
        }

        return xKey;
    }

    /**
     * chunk a string
     *
     * @param str       The string to be chunked
     * @param chunkSize The chunk size
     * @return the chunked string
     */
    private static String chunkString(String str, int chunkSize) {
        String newStr = StringUtils.EMPTY;
        int stringLength = str.length();
        for (int i = 0; i < stringLength; i += chunkSize) {
            if (i + chunkSize > stringLength) {
                chunkSize = stringLength - i;
            }
            newStr += str.substring(i, chunkSize + i) + '\n';
        }
        return newStr;
    }


    /**
     * Load X.509 certificate
     *
     * @param certString certificate in string format
     * @return Loaded Certificate. X509Certificate object
     * @throws CertificateException
     */
    public static X509Certificate loadCert(String certString) throws CertificateException {
        certString = formatCert(certString, true);
        X509Certificate cert;

        try {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalArgumentException e) {
            cert = null;
        }
        return cert;
    }

    /**
     * Load private key
     *
     * @param keyString private key in string format
     * @return Loaded private key. PrivateKey object
     * @throws GeneralSecurityException
     */
    public static PrivateKey loadPrivateKey(String keyString) throws GeneralSecurityException {
        String extractedKey = formatPrivateKey(keyString, false);
        extractedKey = chunkString(extractedKey, 64);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PrivateKey privKey;
        try {
            byte[] encoded = Base64.decodeBase64(extractedKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            privKey = kf.generatePrivate(keySpec);
        } catch (IllegalArgumentException e) {
            privKey = null;
        }

        return privKey;
    }

    /**
     * Calculates the fingerprint of a x509cert
     *
     * @param x509cert x509 certificate
     * @param alg      Digest Algorithm
     * @return the formated fingerprint
     */
    public static String calculateX509Fingerprint(X509Certificate x509cert, String alg) {
        String fingerprint = StringUtils.EMPTY;

        try {
            byte[] dataBytes = x509cert.getEncoded();
            if (alg == null || alg.isEmpty() || alg.equals("SHA-1") || alg.equals("sha1")) {
                fingerprint = DigestUtils.sha1Hex(dataBytes);
            } else if (alg.equals("SHA-256") || alg.equals("sha256")) {
                fingerprint = DigestUtils.sha256Hex(dataBytes);
            } else if (alg.equals("SHA-384") || alg.equals("sha384")) {
                fingerprint = DigestUtils.sha384Hex(dataBytes);
            } else if (alg.equals("SHA-512") || alg.equals("sha512")) {
                fingerprint = DigestUtils.sha512Hex(dataBytes);
            } else {
                LOGGER.debug("Error executing calculateX509Fingerprint. alg " + alg + " not supported");
            }
        } catch (Exception e) {
            LOGGER.debug("Error executing calculateX509Fingerprint: " + e.getMessage(), e);
        }
        return fingerprint.toLowerCase();
    }


    /**
     * Returns String Base64 decoded and inflated
     *
     * @param input String input
     * @return the base64 decoded and inflated string
     */
    public static String base64decodedInflated(String input) {
        if (input.isEmpty()) {
            return input;
        }
        // Base64 decoder
        byte[] decoded = Base64.decodeBase64(input);

        // Inflater
        try {
            Inflater decompresser = new Inflater(true);
            decompresser.setInput(decoded);
            byte[] result = new byte[1024];
            String inflated = "";
            long limit = 0;
            while (!decompresser.finished() && limit < 150) {
                int resultLength = decompresser.inflate(result);
                limit += 1;
                inflated += new String(result, 0, resultLength, "UTF-8");
            }
            decompresser.end();
            return inflated;
        } catch (Exception e) {
            return new String(decoded);
        }
    }

    /**
     * Returns String Deflated and base64 encoded
     *
     * @param input String input
     * @return the deflated and base64 encoded string
     * @throws IOException
     */
    public static String deflatedBase64encoded(String input) throws IOException {
        // Deflater
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
        deflaterStream.write(input.getBytes(StandardCharsets.UTF_8));
        deflaterStream.finish();
        // Base64 encoder
        return new String(Base64.encodeBase64(bytesOut.toByteArray()));
    }

    /**
     * Returns String base64 encoded
     *
     * @param input Stream input
     * @return the base64 encoded string
     */
    public static String base64encoder(byte[] input) {
        return toStringUtf8(Base64.encodeBase64(input));
    }

    /**
     * Returns String base64 encoded
     *
     * @param input String input
     * @return the base64 encoded string
     */
    public static String base64encoder(String input) {
        return base64encoder(toBytesUtf8(input));
    }

    /**
     * Returns String base64 decoded
     *
     * @param input Stream input
     * @return the base64 decoded bytes
     */
    public static byte[] base64decoder(byte[] input) {
        return Base64.decodeBase64(input);
    }

    /**
     * Returns String base64 decoded
     *
     * @param input String input
     * @return the base64 decoded bytes
     */
    public static byte[] base64decoder(String input) {
        return base64decoder(toBytesUtf8(input));
    }

    /**
     * Returns String URL encoded
     *
     * @param input String input
     * @return the URL encoded string
     */
    public static String urlEncoder(String input) {
        if (input != null) {
            try {
                return URLEncoder.encode(input, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                LOGGER.error("URL encoder error.", e);
                throw new IllegalArgumentException();
            }
        } else {
            return null;
        }
    }

    /**
     * Returns String URL decoded
     *
     * @param input URL encoded input
     * @return the URL decoded string
     */
    public static String urlDecoder(String input) {
        if (input != null) {
            try {
                return URLDecoder.decode(input, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                LOGGER.error("URL decoder error.", e);
                throw new IllegalArgumentException();
            }
        } else {
            return null;
        }
    }

    /**
     * Generates a signature from a string
     *
     * @param text          The string we should sign
     * @param key           The private key to sign the string
     * @param signAlgorithm Signature algorithm method
     * @return the signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] sign(String text, PrivateKey key, String signAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (signAlgorithm == null) {
            signAlgorithm = SamlConstants.RSA_SHA1;
        }

        Signature instance = Signature.getInstance(signatureAlgConversion(signAlgorithm));
        instance.initSign(key);
        instance.update(text.getBytes());
        byte[] signature = instance.sign();

        return signature;
    }

    /**
     * Converts Signature algorithm method name
     *
     * @param sign signature algorithm method
     * @return the converted signature name
     */
    public static String signatureAlgConversion(String sign) {
        String convertedSignatureAlg = "";

        if (sign == null) {
            convertedSignatureAlg = "SHA1withRSA";
        } else if (sign.equals(SamlConstants.DSA_SHA1)) {
            convertedSignatureAlg = "SHA1withDSA";
        } else if (sign.equals(SamlConstants.RSA_SHA256)) {
            convertedSignatureAlg = "SHA256withRSA";
        } else if (sign.equals(SamlConstants.RSA_SHA384)) {
            convertedSignatureAlg = "SHA384withRSA";
        } else if (sign.equals(SamlConstants.RSA_SHA512)) {
            convertedSignatureAlg = "SHA512withRSA";
        } else {
            convertedSignatureAlg = "SHA1withRSA";
        }

        return convertedSignatureAlg;
    }

    /**
     * Validate the signature pointed to by the xpath
     *
     * @param doc         The document we should validate
     * @param cert        The public certificate
     * @param fingerprint The fingerprint of the public certificate
     * @param alg         The signature algorithm method
     * @param xpath       the xpath of the ds:Signture node to validate
     * @return True if the signature exists and is valid, false otherwise.
     */
    public static boolean validateSign(final Document doc, final X509Certificate cert, final String fingerprint,
                                       final String alg, final String xpath) {
        try {
            final NodeList signatures = query(doc, xpath);
            return signatures.getLength() == 1 && validateSignNode(signatures.item(0), cert, fingerprint, alg);
        } catch (XPathExpressionException e) {
            LOGGER.warn("Failed to find signature nodes", e);
        }
        return false;
    }

    /**
     * Validate the signature pointed to by the xpath
     *
     * @param doc         The document we should validate
     * @param certList    The public certificates
     * @param fingerprint The fingerprint of the public certificate
     * @param alg         The signature algorithm method
     * @param xpath       the xpath of the ds:Signture node to validate
     * @return True if the signature exists and is valid, false otherwise.
     */
    public static boolean validateSign(final Document doc, final List<X509Certificate> certList, final String fingerprint,
                                       final String alg, final String xpath) {
        return validateSign(doc, certList, fingerprint, alg, xpath, false);
    }

    /**
     * Validate the signature pointed to by the xpath
     *
     * @param doc                 The document we should validate
     * @param certList            The public certificates
     * @param fingerprint         The fingerprint of the public certificate
     * @param alg                 The signature algorithm method
     * @param xpath               the xpath of the ds:Signture node to validate
     * @param rejectDeprecatedAlg Flag to invalidate or not Signatures with deprecated alg
     * @return True if the signature exists and is valid, false otherwise.
     */
    public static boolean validateSign(final Document doc, final List<X509Certificate> certList, final String fingerprint,
                                       final String alg, final String xpath, final Boolean rejectDeprecatedAlg) {
        try {
            final NodeList signatures = query(doc, xpath);

            if (signatures.getLength() == 1) {
                final Node signNode = signatures.item(0);

                Map<String, Object> signatureData = getSignatureData(signNode, alg, rejectDeprecatedAlg);
                if (signatureData.isEmpty()) {
                    return false;
                }
                XMLSignature signature = (XMLSignature) signatureData.get("signature");
                X509Certificate extractedCert = (X509Certificate) signatureData.get("cert");
                String extractedFingerprint = (String) signatureData.get("fingerprint");

                if (certList == null || certList.isEmpty()) {
                    return validateSignNode(signature, null, fingerprint, extractedCert, extractedFingerprint);
                } else {
                    Boolean certMatches = false;
                    for (X509Certificate cert : certList) {
                        if (cert != null && extractedFingerprint != null) {
                            if (extractedFingerprint.equals(calculateX509Fingerprint(cert, alg))) {
                                certMatches = true;

                                if (validateSignNode(signature, cert, null, null, null)) {
                                    return true;
                                }
                            } else {
                                continue;
                            }
                        } else {
                            if (validateSignNode(signature, cert, fingerprint, extractedCert, extractedFingerprint)) {
                                return true;
                            }
                        }
                    }
                    if (certMatches == false) {
                        LOGGER.warn("Certificate used in the document does not match any registered certificate");
                    }
                }
            }
        } catch (XPathExpressionException e) {
            LOGGER.warn("Failed to find signature nodes", e);
        }
        return false;
    }

    /**
     * Validate signature (Metadata).
     *
     * @param doc         The document we should validate
     * @param cert        The public certificate
     * @param fingerprint The fingerprint of the public certificate
     * @param alg         The signature algorithm method
     * @return True if the sign is valid, false otherwise.
     */
    public static Boolean validateMetadataSign(Document doc, X509Certificate cert, String fingerprint, String alg) {
        return validateMetadataSign(doc, cert, fingerprint, alg, false);
    }

    /**
     * Validate signature (Metadata).
     *
     * @param doc                 The document we should validate
     * @param cert                The public certificate
     * @param fingerprint         The fingerprint of the public certificate
     * @param alg                 The signature algorithm method
     * @param rejectDeprecatedAlg Flag to invalidate or not Signatures with deprecated alg
     * @return True if the sign is valid, false otherwise.
     */
    public static Boolean validateMetadataSign(Document doc, X509Certificate cert, String fingerprint, String alg, Boolean rejectDeprecatedAlg) {
        NodeList signNodesToValidate;
        try {
            signNodesToValidate = query(doc, "/md:EntitiesDescriptor/ds:Signature");

            if (signNodesToValidate.getLength() == 0) {
                signNodesToValidate = query(doc, "/md:EntityDescriptor/ds:Signature");

                if (signNodesToValidate.getLength() == 0) {
                    signNodesToValidate = query(doc, "/md:EntityDescriptor/md:SPSSODescriptor/ds:Signature|/md:EntityDescriptor/IDPSSODescriptor/ds:Signature");
                }
            }

            if (signNodesToValidate.getLength() > 0) {
                for (int i = 0; i < signNodesToValidate.getLength(); i++) {
                    Node signNode = signNodesToValidate.item(i);
                    if (!validateSignNode(signNode, cert, fingerprint, alg, rejectDeprecatedAlg)) {
                        return false;
                    }
                }
                return true;
            }
        } catch (XPathExpressionException e) {
            LOGGER.warn("Failed to find signature nodes", e);
        }
        return false;
    }

    /**
     * Extract signature data from a DOM {@link Node}.
     *
     * @param signNode The signed node
     * @param alg      The signature algorithm method
     * @return a Map containing the signature data (actual signature, certificate, fingerprint)
     */
    private static Map<String, Object> getSignatureData(Node signNode, String alg) {
        return getSignatureData(signNode, alg, false);
    }

    /**
     * Extract signature data from a DOM {@link Node}.
     *
     * @param signNode            The signed node
     * @param alg                 The signature algorithm method
     * @param rejectDeprecatedAlg Whether to ignore signature if a deprecated algorithm is used
     * @return a Map containing the signature data (actual signature, certificate, fingerprint)
     */
    private static Map<String, Object> getSignatureData(Node signNode, String alg, Boolean rejectDeprecatedAlg) {
        Map<String, Object> signatureData = new HashMap<>();
        try {
            Element sigElement = (Element) signNode;
            XMLSignature signature = new XMLSignature(sigElement, "", true);

            String sigMethodAlg = signature.getSignedInfo().getSignatureMethodURI();
            if (!isAlgorithmWhitelisted(sigMethodAlg)) {
                throw new Exception(sigMethodAlg + " is not a valid supported algorithm");
            }

            if (SamlXmlUtils.mustRejectDeprecatedSignatureAlgo(sigMethodAlg, rejectDeprecatedAlg)) {
                return signatureData;
            }

            signatureData.put("signature", signature);

            String extractedFingerprint = null;
            X509Certificate extractedCert = null;
            KeyInfo keyInfo = signature.getKeyInfo();
            if (keyInfo != null && keyInfo.containsX509Data()) {
                extractedCert = keyInfo.getX509Certificate();
                extractedFingerprint = calculateX509Fingerprint(extractedCert, alg);

                signatureData.put("cert", extractedCert);
                signatureData.put("fingerprint", extractedFingerprint);
            } else {
                LOGGER.debug("No KeyInfo or not x509CertificateData");
            }
        } catch (Exception e) {
            LOGGER.warn("Error executing getSignatureData: " + e.getMessage(), e);
        }
        return signatureData;
    }

    public static Boolean mustRejectDeprecatedSignatureAlgo(String signAlg, Boolean rejectDeprecatedAlg) {
        if (DEPRECATED_ALGOS.contains(signAlg)) {
            String errorMsg = "Found a deprecated algorithm " + signAlg + " related to the Signature element,";
            if (rejectDeprecatedAlg) {
                LOGGER.error(errorMsg + " rejecting it");
                return true;
            } else {
                LOGGER.info(errorMsg + " consider requesting a more robust algorithm");
            }
        }
        return false;
    }

    /**
     * Validate signature of the Node.
     *
     * @param signNode    The document we should validate
     * @param cert        The public certificate
     * @param fingerprint The fingerprint of the public certificate
     * @param alg         The signature algorithm method
     * @return True if the sign is valid, false otherwise.
     * @throws Exception
     */
    public static Boolean validateSignNode(Node signNode, X509Certificate cert, String fingerprint, String alg) {
        return validateSignNode(signNode, cert, fingerprint, alg, false);
    }

    /**
     * Validate signature of the Node.
     *
     * @param signNode            The document we should validate
     * @param cert                The public certificate
     * @param fingerprint         The fingerprint of the public certificate
     * @param alg                 The signature algorithm method
     * @param rejectDeprecatedAlg Flag to invalidate or not Signatures with deprecated alg
     * @return True if the sign is valid, false otherwise.
     * @throws Exception
     */
    public static Boolean validateSignNode(Node signNode, X509Certificate cert, String fingerprint, String alg, Boolean rejectDeprecatedAlg) {
        Map<String, Object> signatureData = getSignatureData(signNode, alg, rejectDeprecatedAlg);
        if (signatureData.isEmpty()) {
            return false;
        }

        XMLSignature signature = (XMLSignature) signatureData.get("signature");
        X509Certificate extractedCert = (X509Certificate) signatureData.get("cert");
        String extractedFingerprint = (String) signatureData.get("fingerprint");

        return validateSignNode(signature, cert, fingerprint, extractedCert, extractedFingerprint);
    }

    /**
     * Validate signature of the Node.
     *
     * @param signature            XMLSignature we should validate
     * @param cert                 The public certificate
     * @param fingerprint          The fingerprint of the public certificate
     * @param extractedCert        The cert extracted from the signNode
     * @param extractedFingerprint The fingerprint extracted from the signNode
     * @return True if the sign is valid, false otherwise.
     */
    public static Boolean validateSignNode(XMLSignature signature, X509Certificate cert, String fingerprint, X509Certificate extractedCert, String extractedFingerprint) {
        Boolean res = false;
        try {
            if (cert != null) {
                res = signature.checkSignatureValue(cert);
            } else if (extractedCert != null && fingerprint != null && extractedFingerprint != null) {
                Boolean fingerprintMatches = false;
                for (String fingerprintStr : fingerprint.split(",")) {
                    if (extractedFingerprint.equalsIgnoreCase(fingerprintStr.trim())) {
                        fingerprintMatches = true;
                        if (res = signature.checkSignatureValue(extractedCert)) {
                            break;
                        }
                    }
                }
                if (fingerprintMatches == false) {
                    LOGGER.warn("Fingerprint of the certificate used in the document does not match any registered fingerprints");
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Error executing validateSignNode: " + e.getMessage(), e);
        }
        return res;
    }

    /**
     * Whitelist the XMLSignature algorithm
     *
     * @param alg The signature algorithm method
     * @return True if the sign is valid, false otherwise.
     */
    public static boolean isAlgorithmWhitelisted(String alg) {
        Set<String> whiteListedAlgorithm = new HashSet<String>();
        whiteListedAlgorithm.add(SamlConstants.DSA_SHA1);
        whiteListedAlgorithm.add(SamlConstants.RSA_SHA1);
        whiteListedAlgorithm.add(SamlConstants.RSA_SHA256);
        whiteListedAlgorithm.add(SamlConstants.RSA_SHA384);
        whiteListedAlgorithm.add(SamlConstants.RSA_SHA512);

        Boolean whitelisted = false;
        if (whiteListedAlgorithm.contains(alg)) {
            whitelisted = true;
        }

        return whitelisted;
    }

    /**
     * Decrypt an encrypted element.
     *
     * @param encryptedDataElement The encrypted element.
     * @param inputKey             The private key to decrypt.
     */
    public static void decryptElement(Element encryptedDataElement, PrivateKey inputKey) {
        try {
            XMLCipher xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);

            validateEncryptedData(encryptedDataElement);

            xmlCipher.setKEK(inputKey);
            xmlCipher.doFinal(encryptedDataElement.getOwnerDocument(), encryptedDataElement, false);
        } catch (Exception e) {
            LOGGER.warn("Error executing decryption: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts the encrypted element using an HSM.
     *
     * @param encryptedDataElement The encrypted element.
     * @param hsm                  The HSM object.
     * @throws Exception
     */
    public static void decryptUsingHsm(Element encryptedDataElement, HSM hsm) {
        try {
            validateEncryptedData(encryptedDataElement);

            XMLCipher xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);

            hsm.setClient();

            NodeList encryptedKeyNodes = ((Element) encryptedDataElement.getParentNode()).getElementsByTagNameNS(SamlConstants.NS_XENC, "EncryptedKey");
            EncryptedKey encryptedKey = xmlCipher.loadEncryptedKey((Element) encryptedKeyNodes.item(0));
            byte[] encryptedBytes = base64decoder(encryptedKey.getCipherData().getCipherValue().getValue());

            byte[] decryptedKey = hsm.unwrapKey(encryptedKey.getEncryptionMethod().getAlgorithm(), encryptedBytes);

            SecretKey encryptionKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");

            xmlCipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);
            xmlCipher.setKEK(encryptionKey);
            xmlCipher.doFinal(encryptedDataElement.getOwnerDocument(), encryptedDataElement, false);
        } catch (Exception e) {
            LOGGER.warn("Error executing decryption: " + e.getMessage(), e);
        }
    }

    /**
     * Validates the encrypted data and checks whether it contains a retrieval
     * method to obtain the encrypted key or not.
     *
     * @param encryptedDataElement The encrypted element.
     */
    private static void validateEncryptedData(Element encryptedDataElement) throws SamlException {
        /* Check if we have encryptedData with a KeyInfo that contains a RetrievalMethod to obtain the EncryptedKey.
           xmlCipher is not able to handle that so we move the EncryptedKey inside the KeyInfo element and
           replacing the RetrievalMethod.
        */

        NodeList keyInfoInEncData = encryptedDataElement.getElementsByTagNameNS(SamlConstants.NS_DS, "KeyInfo");
        if (keyInfoInEncData.getLength() == 0) {
            throw new SamlException("No KeyInfo inside EncryptedData element");
        }

        NodeList childs = keyInfoInEncData.item(0).getChildNodes();
        for (int i = 0; i < childs.getLength(); i++) {
            if (childs.item(i).getLocalName() != null && childs.item(i).getLocalName().equals("RetrievalMethod")) {
                Element retrievalMethodElem = (Element) childs.item(i);
                if (!retrievalMethodElem.getAttribute("Type").equals("http://www.w3.org/2001/04/xmlenc#EncryptedKey")) {
                    throw new SamlException("Unsupported Retrieval Method found");
                }

                String uri = retrievalMethodElem.getAttribute("URI").substring(1);

                NodeList encryptedKeyNodes = ((Element) encryptedDataElement.getParentNode()).getElementsByTagNameNS(SamlConstants.NS_XENC, "EncryptedKey");
                for (int j = 0; j < encryptedKeyNodes.getLength(); j++) {
                    if (((Element) encryptedKeyNodes.item(j)).getAttribute("Id").equals(uri)) {
                        keyInfoInEncData.item(0).replaceChild(encryptedKeyNodes.item(j), childs.item(i));
                    }
                }
            }
        }
    }

    /**
     * Clone a Document object.
     *
     * @param source The Document object to be cloned.
     * @return the clone of the Document object
     * @throws ParserConfigurationException
     */
    public static Document copyDocument(Document source) throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        Node originalRoot = source.getDocumentElement();

        Document copiedDocument = db.newDocument();
        Node copiedRoot = copiedDocument.importNode(originalRoot, true);
        copiedDocument.appendChild(copiedRoot);

        return copiedDocument;
    }

    /**
     * Signs the Document using the specified signature algorithm with the private key and the public certificate.
     *
     * @param document      The document to be signed
     * @param key           The private key
     * @param certificate   The public certificate
     * @param signAlgorithm Signature Algorithm
     * @return the signed document in string format
     * @throws XMLSecurityException
     * @throws XPathExpressionException
     */
    public static String addSign(Document document, PrivateKey key, X509Certificate certificate, String signAlgorithm) throws XMLSecurityException, XPathExpressionException {
        return addSign(document, key, certificate, signAlgorithm, SamlConstants.SHA1);
    }

    /**
     * Signs the Document using the specified signature algorithm with the private key and the public certificate.
     *
     * @param document        The document to be signed
     * @param key             The private key
     * @param certificate     The public certificate
     * @param signAlgorithm   Signature Algorithm
     * @param digestAlgorithm Digest Algorithm
     * @return the signed document in string format
     * @throws XMLSecurityException
     * @throws XPathExpressionException
     */
    public static String addSign(Document document, PrivateKey key, X509Certificate certificate, String signAlgorithm, String digestAlgorithm) throws XMLSecurityException, XPathExpressionException {
        // Check arguments.
        if (document == null) {
            throw new IllegalArgumentException("Provided document was null");
        }

        if (document.getDocumentElement() == null) {
            throw new IllegalArgumentException("The Xml Document has no root element.");
        }

        if (key == null) {
            throw new IllegalArgumentException("Provided key was null");
        }

        if (certificate == null) {
            throw new IllegalArgumentException("Provided certificate was null");
        }

        if (signAlgorithm == null || signAlgorithm.isEmpty()) {
            signAlgorithm = SamlConstants.RSA_SHA1;
        }
        if (digestAlgorithm == null || digestAlgorithm.isEmpty()) {
            digestAlgorithm = SamlConstants.SHA1;
        }

        document.normalizeDocument();

        String c14nMethod = SamlConstants.C14NEXC;

        // Signature object
        XMLSignature sig = new XMLSignature(document, null, signAlgorithm, c14nMethod);

        // Including the signature into the document before sign, because
        // this is an envelop signature
        Element root = document.getDocumentElement();
        document.setXmlStandalone(false);

        // If Issuer, locate Signature after Issuer, Otherwise as first child.
        NodeList issuerNodes = SamlXmlUtils.query(document, "//saml:Issuer", null);
        Element elemToSign = null;
        if (issuerNodes.getLength() > 0) {
            Node issuer = issuerNodes.item(0);
            root.insertBefore(sig.getElement(), issuer.getNextSibling());
            elemToSign = (Element) issuer.getParentNode();
        } else {
            NodeList entitiesDescriptorNodes = SamlXmlUtils.query(document, "//md:EntitiesDescriptor", null);
            if (entitiesDescriptorNodes.getLength() > 0) {
                elemToSign = (Element) entitiesDescriptorNodes.item(0);
            } else {
                NodeList entityDescriptorNodes = SamlXmlUtils.query(document, "//md:EntityDescriptor", null);
                if (entityDescriptorNodes.getLength() > 0) {
                    elemToSign = (Element) entityDescriptorNodes.item(0);
                } else {
                    elemToSign = root;
                }
            }
            root.insertBefore(sig.getElement(), elemToSign.getFirstChild());
        }

        String id = elemToSign.getAttribute("ID");

        String reference = id;
        if (!id.isEmpty()) {
            elemToSign.setIdAttributeNS(null, "ID", true);
            reference = "#" + id;
        }

        // Create the transform for the document
        Transforms transforms = new Transforms(document);
        transforms.addTransform(SamlConstants.ENVSIG);
        transforms.addTransform(c14nMethod);
        sig.addDocument(reference, transforms, digestAlgorithm);

        // Add the certification info
        sig.addKeyInfo(certificate);

        // Sign the document
        sig.sign(key);

        return convertDocumentToString(document, true);
    }

    /**
     * Signs a Node using the specified signature algorithm with the private key and the public certificate.
     *
     * @param node            The Node to be signed
     * @param key             The private key
     * @param certificate     The public certificate
     * @param signAlgorithm   Signature Algorithm
     * @param digestAlgorithm Digest Algorithm
     * @return the signed document in string format
     * @throws ParserConfigurationException
     * @throws XMLSecurityException
     * @throws XPathExpressionException
     */
    public static String addSign(Node node, PrivateKey key, X509Certificate certificate, String signAlgorithm, String digestAlgorithm) throws ParserConfigurationException, XPathExpressionException, XMLSecurityException {
        // Check arguments.
        if (node == null) {
            throw new IllegalArgumentException("Provided node was null");
        }

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        Node newNode = doc.importNode(node, true);
        doc.appendChild(newNode);

        return addSign(doc, key, certificate, signAlgorithm, digestAlgorithm);
    }

    /**
     * Signs a Node using the specified signature algorithm with the private key and the public certificate.
     *
     * @param node          The Node to be signed
     * @param key           The private key
     * @param certificate   The public certificate
     * @param signAlgorithm Signature Algorithm
     * @return the signed document in string format
     * @throws ParserConfigurationException
     * @throws XMLSecurityException
     * @throws XPathExpressionException
     */
    public static String addSign(Node node, PrivateKey key, X509Certificate certificate, String signAlgorithm) throws ParserConfigurationException, XPathExpressionException, XMLSecurityException {
        return addSign(node, key, certificate, signAlgorithm, SamlConstants.SHA1);
    }

    /**
     * Validates signed binary data (Used to validate GET Signature).
     *
     * @param signedQuery The element we should validate
     * @param signature   The signature that will be validate
     * @param cert        The public certificate
     * @param signAlg     Signature Algorithm
     * @return the signed document in string format
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static Boolean validateBinarySignature(String signedQuery, byte[] signature, X509Certificate cert, String signAlg) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Boolean valid = false;
        try {
            String convertedSigAlg = signatureAlgConversion(signAlg);

            Signature sig = Signature.getInstance(convertedSigAlg); //, provider);
            sig.initVerify(cert.getPublicKey());
            sig.update(signedQuery.getBytes());

            valid = sig.verify(signature);
        } catch (Exception e) {
            LOGGER.warn("Error executing validateSign: " + e.getMessage(), e);
        }
        return valid;
    }

    /**
     * Validates signed binary data (Used to validate GET Signature).
     *
     * @param signedQuery The element we should validate
     * @param signature   The signature that will be validate
     * @param certList    The List of certificates
     * @param signAlg     Signature Algorithm
     * @return the signed document in string format
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static Boolean validateBinarySignature(String signedQuery, byte[] signature, List<X509Certificate> certList, String signAlg) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Boolean valid = false;

        String convertedSigAlg = signatureAlgConversion(signAlg);
        Signature sig = Signature.getInstance(convertedSigAlg); //, provider);

        for (X509Certificate cert : certList) {
            try {
                sig.initVerify(cert.getPublicKey());
                sig.update(signedQuery.getBytes());
                valid = sig.verify(signature);
                if (valid) {
                    break;
                }
            } catch (Exception e) {
                LOGGER.warn("Error executing validateSign: " + e.getMessage(), e);
            }
        }
        return valid;
    }

    /**
     * Get Status from a Response
     *
     * @param dom The Response as XML
     * @return SamlResponseStatus
     */
    public static SamlResponseStatus getStatus(String statusXpath, Document dom) throws SamlException {
        try {
            NodeList statusEntry = SamlXmlUtils.query(dom, statusXpath, null);
            if (statusEntry.getLength() != 1) {
                throw new SamlException("Missing Status on response");
            }
            NodeList codeEntry = SamlXmlUtils.query(dom, statusXpath + "/samlp:StatusCode", (Element) statusEntry.item(0));

            if (codeEntry.getLength() == 0) {
                throw new SamlException("Missing Status Code on response");
            }
            String stausCode = codeEntry.item(0).getAttributes().getNamedItem("Value").getNodeValue();
            SamlResponseStatus status = new SamlResponseStatus(stausCode);

            NodeList subStatusCodeEntry = SamlXmlUtils.query(dom, statusXpath + "/samlp:StatusCode/samlp:StatusCode", (Element) statusEntry.item(0));
            if (subStatusCodeEntry.getLength() > 0) {
                String subStatusCode = subStatusCodeEntry.item(0).getAttributes().getNamedItem("Value").getNodeValue();
                status.setSubStatusCode(subStatusCode);
            }

            NodeList messageEntry = SamlXmlUtils.query(dom, statusXpath + "/samlp:StatusMessage", (Element) statusEntry.item(0));
            if (messageEntry.getLength() == 1) {
                status.setStatusMessage(messageEntry.item(0).getTextContent());
            }

            return status;
        } catch (XPathExpressionException e) {
            String error = "Unexpected error in getStatus." + e.getMessage();
            LOGGER.error(error);
            throw new IllegalArgumentException(error);
        }
    }

    /**
     * Generates a nameID.
     *
     * @param value  The value
     * @param spnq   SP Name Qualifier
     * @param format SP Format
     * @param nq     Name Qualifier
     * @param cert   IdP Public certificate to encrypt the nameID
     * @return Xml contained in the document.
     */
    public static String generateNameId(String value, String spnq, String format, String nq, X509Certificate cert) {
        String res = null;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().newDocument();
            Element nameId = doc.createElement("saml:NameID");

            if (spnq != null && !spnq.isEmpty()) {
                nameId.setAttribute("SPNameQualifier", spnq);
            }
            if (format != null && !format.isEmpty()) {
                nameId.setAttribute("Format", format);
            }
            if ((nq != null) && !nq.isEmpty()) {
                nameId.setAttribute("NameQualifier", nq);
            }

            nameId.appendChild(doc.createTextNode(value));
            doc.appendChild(nameId);

            if (cert != null) {
                // We generate a symmetric key
                Key symmetricKey = generateSymmetricKey();

                // cipher for encrypt the data
                XMLCipher xmlCipher = XMLCipher.getInstance(SamlConstants.AES128_CBC);
                xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

                // cipher for encrypt the symmetric key
                XMLCipher keyCipher = XMLCipher.getInstance(SamlConstants.RSA_1_5);
                keyCipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());

                // encrypt the symmetric key
                EncryptedKey encryptedKey = keyCipher.encryptKey(doc, symmetricKey);

                // Add keyinfo inside the encrypted data
                EncryptedData encryptedData = xmlCipher.getEncryptedData();
                KeyInfo keyInfo = new KeyInfo(doc);
                keyInfo.add(encryptedKey);
                encryptedData.setKeyInfo(keyInfo);

                // Encrypt the actual data
                xmlCipher.doFinal(doc, nameId, false);

                // Building the result
                res = "<saml:EncryptedID>" + convertDocumentToString(doc) + "</saml:EncryptedID>";
            } else {
                res = convertDocumentToString(doc);
            }
        } catch (Exception e) {
            LOGGER.error("Error executing generateNameId: " + e.getMessage(), e);
        }
        return res;
    }

    /**
     * Generates a nameID.
     *
     * @param value  The value
     * @param spnq   SP Name Qualifier
     * @param format SP Format
     * @param cert   IdP Public certificate to encrypt the nameID
     * @return Xml contained in the document.
     */
    public static String generateNameId(String value, String spnq, String format, X509Certificate cert) {
        return generateNameId(value, spnq, format, null, cert);
    }

    /**
     * Generates a nameID.
     *
     * @param value  The value
     * @param spnq   SP Name Qualifier
     * @param format SP Format
     * @return Xml contained in the document.
     */
    public static String generateNameId(String value, String spnq, String format) {
        return generateNameId(value, spnq, format, null);
    }

    /**
     * Generates a nameID.
     *
     * @param value The value
     * @return Xml contained in the document.
     */
    public static String generateNameId(String value) {
        return generateNameId(value, null, null, null);
    }

    /**
     * Method to generate a symmetric key for encryption
     *
     * @return the symmetric key
     * @throws Exception
     */
    private static SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    /**
     * Generates a unique string (used for example as ID of assertions)
     *
     * @param prefix Prefix for the Unique ID.
     *               Use property <code>onelogin.saml2.unique_id_prefix</code> to set this.
     * @return A unique string
     */
    public static String generateUniqueID(String prefix) {
        if (prefix == null || StringUtils.isEmpty(prefix)) {
            prefix = SamlXmlUtils.UNIQUE_ID_PREFIX;
        }
        return prefix + UUID.randomUUID();
    }

    /**
     * Generates a unique string (used for example as ID of assertions)
     *
     * @return A unique string
     */
    public static String generateUniqueID() {
        return generateUniqueID(null);
    }

    /**
     * Interprets a ISO8601 duration value relative to a current time timestamp.
     *
     * @param duration The duration, as a string.
     * @return int The new timestamp, after the duration is applied.
     * @throws IllegalArgumentException
     */
    public static long parseDuration(String duration) throws IllegalArgumentException {
        TimeZone timeZone = DateTimeZone.UTC.toTimeZone();
        return parseDuration(duration, Calendar.getInstance(timeZone).getTimeInMillis() / 1000);
    }

    /**
     * Interprets a ISO8601 duration value relative to a given timestamp.
     *
     * @param durationString The duration, as a string.
     * @param timestamp      The unix timestamp we should apply the duration to.
     * @return the new timestamp, after the duration is applied In Seconds.
     * @throws IllegalArgumentException
     */
    public static long parseDuration(String durationString, long timestamp) throws IllegalArgumentException {
        boolean haveMinus = false;

        if (durationString.startsWith("-")) {
            durationString = durationString.substring(1);
            haveMinus = true;
        }

        PeriodFormatter periodFormatter = ISOPeriodFormat.standard().withLocale(new Locale("UTC"));
        Period period = periodFormatter.parsePeriod(durationString);

        DateTime dt = new DateTime(timestamp * 1000, DateTimeZone.UTC);

        DateTime result;
        if (haveMinus) {
            result = dt.minus(period);
        } else {
            result = dt.plus(period);
        }
        return result.getMillis() / 1000;
    }

    /**
     * @return the unix timestamp that matches the current time.
     */
    public static Long getCurrentTimeStamp() {
        DateTime currentDate = new DateTime(DateTimeZone.UTC);
        return currentDate.getMillis() / 1000;
    }

    /**
     * Compare 2 dates and return the the earliest
     *
     * @param cacheDuration The duration, as a string.
     * @param validUntil    The valid until date, as a string
     * @return the expiration time (timestamp format).
     */
    public static long getExpireTime(String cacheDuration, String validUntil) {
        long expireTime = 0;
        try {
            if (cacheDuration != null && !StringUtils.isEmpty(cacheDuration)) {
                expireTime = parseDuration(cacheDuration);
            }

            if (validUntil != null && !StringUtils.isEmpty(validUntil)) {
                DateTime dt = SamlXmlUtils.parseDateTime(validUntil);
                long validUntilTimeInt = dt.getMillis() / 1000;
                if (expireTime == 0 || expireTime > validUntilTimeInt) {
                    expireTime = validUntilTimeInt;
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error executing getExpireTime: " + e.getMessage(), e);
        }
        return expireTime;
    }

    /**
     * Compare 2 dates and return the the earliest
     *
     * @param cacheDuration The duration, as a string.
     * @param validUntil    The valid until date, as a timestamp
     * @return the expiration time (timestamp format).
     */
    public static long getExpireTime(String cacheDuration, long validUntil) {
        long expireTime = 0;
        try {
            if (cacheDuration != null && !StringUtils.isEmpty(cacheDuration)) {
                expireTime = parseDuration(cacheDuration);
            }

            if (expireTime == 0 || expireTime > validUntil) {
                expireTime = validUntil;
            }
        } catch (Exception e) {
            LOGGER.error("Error executing getExpireTime: " + e.getMessage(), e);
        }
        return expireTime;
    }

    /**
     * Create string form time In Millis with format yyyy-MM-ddTHH:mm:ssZ
     *
     * @param timeInMillis The time in Millis
     * @return string with format yyyy-MM-ddTHH:mm:ssZ
     */
    public static String formatDateTime(long timeInMillis) {
        return DATE_TIME_FORMAT.print(timeInMillis);
    }

    /**
     * Create string form time In Millis with format yyyy-MM-ddTHH:mm:ssZ
     *
     * @param time   The time
     * @param millis Defines if the time is in Millis
     * @return string with format yyyy-MM-ddTHH:mm:ssZ
     */
    public static String formatDateTime(long time, boolean millis) {
        if (millis) {
            return DATE_TIME_FORMAT_MILLS.print(time);
        } else {
            return formatDateTime(time);
        }
    }

    /**
     * Create calendar form string with format yyyy-MM-ddTHH:mm:ssZ // yyyy-MM-ddTHH:mm:ss.SSSZ
     *
     * @param dateTime string with format yyyy-MM-ddTHH:mm:ssZ // yyyy-MM-ddTHH:mm:ss.SSSZ
     * @return datetime
     */
    public static DateTime parseDateTime(String dateTime) {
        DateTime parsedData;
        try {
            parsedData = DATE_TIME_FORMAT.parseDateTime(dateTime);
        } catch (Exception e) {
            return DATE_TIME_FORMAT_MILLS.parseDateTime(dateTime);
        }
        return parsedData;
    }

    /**
     * Escape a text so that it can be safely used within an XML element contents or attribute value.
     *
     * @param text the text to escape
     * @return the escaped text (<code>null</code> if the input is <code>null</code>)
     */
    public static String toXml(String text) {
        return StringEscapeUtils.escapeXml10(text);
    }

    private static String toStringUtf8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] toBytesUtf8(String str) {
        return str.getBytes(StandardCharsets.UTF_8);
    }
}
