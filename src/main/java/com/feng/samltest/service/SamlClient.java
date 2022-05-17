package com.feng.samltest.service;

import com.feng.samltest.browser.BrowserUtils;
import com.feng.samltest.constant.NameIdFormatsEnum;
import com.feng.samltest.constant.SamlBindingEnum;
import com.feng.samltest.constant.SamlConstants;
import com.feng.samltest.dto.SamlLogoutResponse;
import com.feng.samltest.dto.SamlResponse;
import com.feng.samltest.exception.SamlException;
import com.feng.samltest.util.ValidatorTool;
import com.feng.samltest.util.XMLHelper;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.core.xml.schema.impl.XSStringImpl;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.keyinfo.impl.ChainingKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.springframework.core.io.DefaultResourceLoader;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import static com.feng.samltest.constant.NameIdFormatsEnum.UN_SPECIFIED;

@Slf4j
public class SamlClient {

    private static final String HTTP_REQ_SAML_PARAM = "SAMLRequest";
    private static final String HTTP_RESP_SAML_PARAM = "SAMLResponse";

    private static boolean initializedOpenSaml = false;
    private BasicParserPool domParser;

    private String relyingPartyIdentifier;
    private String assertionConsumerServiceUrl;
    private String identityProviderUrl;
    private String responseIssuer;
    private List<Credential> credentials;
    private DateTime now; // used for testing only
    private long notBeforeSkew = 0L;
    private SamlBindingEnum samlBindingEnum;
    private BasicX509Credential spCredential;
    private List<Credential> additionalSpCredentials = new ArrayList<>();

    /**
     * Returns the url where SAML requests should be posted.
     *
     * @return the url where SAML requests should be posted.
     */
    public String getIdentityProviderUrl() {
        return identityProviderUrl;
    }

    /**
     * Sets the date that will be considered as now. This is only useful for testing.
     *
     * @param now the date to use for now.
     */
    public void setDateTimeNow(DateTime now) {
        this.now = now;
    }

    /**
     * Sets by how much the current time can be before the assertion's notBefore.
     * <p>
     * Used to mitigate clock differences between the identity provider and relying party.
     *
     * @param notBeforeSkew non-negative amount of skew (in milliseconds) to allow between the
     *                      current time and the assertion's notBefore date. Default: 0
     */
    public void setNotBeforeSkew(long notBeforeSkew) {
        if (notBeforeSkew < 0) {
            throw new IllegalArgumentException("Saml Skew must be non-negative");
        }
        this.notBeforeSkew = notBeforeSkew;
    }

    public SamlClient() {
    }

    /**
     * 使用显式参数构造 SAML 客户端
     *
     * @param relyingPartyIdentifier      依赖方的标识符。
     * @param assertionConsumerServiceUrl 身份提供者将发回 SAML 响应的 URL。
     * @param identityProviderUrl         将提交 SAML 请求的 url。
     * @param responseIssuer              SAML 响应的预期颁发者 ID
     * @param certificates                用于验证响应的 base-64 编码证书列表
     * @param samlBindingEnum             客户端应该使用什么类型的 SAML 绑定
     */
    public SamlClient(
            String relyingPartyIdentifier,
            String assertionConsumerServiceUrl,
            String identityProviderUrl,
            String responseIssuer,
            List<X509Certificate> certificates,
            SamlBindingEnum samlBindingEnum)
            throws SamlException {

        ensureOpenSamlIsInitialized();

        if (relyingPartyIdentifier == null) {
            throw new IllegalArgumentException("relyingPartyIdentifier");
        }
        if (identityProviderUrl == null) {
            throw new IllegalArgumentException("identityProviderUrl");
        }
        if (responseIssuer == null) {
            throw new IllegalArgumentException("responseIssuer");
        }
        if (certificates == null || certificates.isEmpty()) {
            throw new IllegalArgumentException("certificates");
        }

        this.relyingPartyIdentifier = relyingPartyIdentifier;
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
        this.identityProviderUrl = identityProviderUrl;
        this.responseIssuer = responseIssuer;
        credentials = certificates.stream().map(SamlClient::getCredential).collect(Collectors.toList());
        this.samlBindingEnum = samlBindingEnum;
        this.domParser = createDOMParser();
    }

    public static SamlClient fromMetadata(
            String relyingPartyIdentifier,
            String assertionConsumerServiceUrl,
            Reader metadata,
            SamlBindingEnum samlBindingEnum)
            throws SamlException {
        return fromMetadata(
                relyingPartyIdentifier, assertionConsumerServiceUrl, metadata, samlBindingEnum, null);
    }

    public static SamlClient fromMetadata(
            String relyingPartyIdentifier,
            String assertionConsumerServiceUrl,
            Reader metadata,
            SamlBindingEnum samlBindingEnum,
            List<X509Certificate> certificates)
            throws SamlException {
        return fromMetadata(
                relyingPartyIdentifier, assertionConsumerServiceUrl, null, metadata, samlBindingEnum, certificates);
    }

    /**
     * 使用从身份提供者获得的 XML 元数据构造 SAML 客户端。
     */
    public static SamlClient fromMetadata(
            String relyingPartyIdentifier,
            String assertionConsumerServiceUrl,
            String identityProviderUrl,
            Reader metadata,
            SamlBindingEnum samlBindingEnum,
            List<X509Certificate> certificates)
            throws SamlException {
        // 初始化 OpenSAML
        ensureOpenSamlIsInitialized();
        // 创建原数据解析器
        DOMMetadataResolver metadataResolver = createMetadataResolver(skipBom(metadata));
        // 元数据 xml
        EntityDescriptor entityDescriptor = getEntityDescriptor(metadataResolver);
        // IDP信息
        IDPSSODescriptor idpSsoDescriptor = getIDPSSODescriptor(entityDescriptor);
        if (idpSsoDescriptor.getSingleSignOnServices() != null && !idpSsoDescriptor.getSingleSignOnServices().isEmpty()) {
            // IDP 单点登录信息
            SingleSignOnService idpBinding = getIdpBinding(idpSsoDescriptor, samlBindingEnum);
            // IDP URL
            if (StringUtils.isBlank(identityProviderUrl)) {
                identityProviderUrl = idpBinding.getLocation();
            }
        }
        // 拿签名证书
        List<X509Certificate> x509Certificates = getCertificates(idpSsoDescriptor);

        // 外部提供了证书则添加，有些元数据中不内嵌证书
        if (certificates != null) {
            x509Certificates.addAll(certificates);
        }

        // 响应者信息，即IDP信息
        String responseIssuer = entityDescriptor.getEntityID();

        return new SamlClient(
                relyingPartyIdentifier,
                assertionConsumerServiceUrl,
                identityProviderUrl,
                responseIssuer,
                x509Certificates,
                samlBindingEnum);
    }

    /**
     * Decodes and validates an SAML response returned by an identity provider.
     *
     * @param encodedResponse the encoded response returned by the identity provider.
     * @param method          The HTTP method used by the request
     * @return An {@link SamlResponse} object containing information decoded from the SAML response.
     * @throws SamlException if the signature is invalid, or if any other error occurs.
     */
    public SamlResponse decodeAndValidateSamlResponse(String encodedResponse, String method)
            throws SamlException {
        //解码响应，并组装成xml对象
        Response response = (Response) parseResponse(encodedResponse, method);

        try {
            // 解码加密的断言
            decodeEncryptedAssertion(response);
        } catch (DecryptionException e) {
            throw new SamlException("Saml Cannot decrypt the assertion", e);
        }
        //检验响应 (断言 / 签名 / 约束)
        ValidatorTool.validate(response, responseIssuer, credentials, this.now, notBeforeSkew);

        Assertion assertion = response.getAssertions().get(0);
        return new SamlResponse(assertion);
    }

    /**
     * Redirects an {@link HttpServletResponse} to the configured identity provider.
     *
     * @param response   The {@link HttpServletResponse}.
     * @param relayState Optional relay state that will be passed along.
     * @throws IOException   thrown if an IO error occurs.
     * @throws SamlException thrown is an unexpected error occurs.
     */
    public void redirectToIdentityProvider(HttpServletResponse response, String relayState)
            throws IOException, SamlException {
        Map<String, String> values = new HashMap<>();
        values.put("SAMLRequest", getSamlRequest());
        if (relayState != null) {
            values.put("RelayState", relayState);
        }

        BrowserUtils.postUsingBrowser(identityProviderUrl, response, values);
    }

    /**
     * Processes a POST containing the SAML response.
     *
     * @param request the {@link HttpServletRequest}.
     * @return An {@link SamlResponse} object containing information decoded from the SAML response.
     * @throws SamlException thrown is an unexpected error occurs.
     */
    public SamlResponse processPostFromIdentityProvider(HttpServletRequest request)
            throws SamlException {
        String encodedResponse = request.getParameter(HTTP_RESP_SAML_PARAM);
        return decodeAndValidateSamlResponse(encodedResponse, request.getMethod());
    }


    /**
     * Wrap a {@link Reader Reader} to skip a BOM if it is present.
     * OpenSaml won't accept a metadata file if it starts with a BOM.
     *
     * @param metadata The metadata with optional BOM
     * @return A {@link Reader} which will never return a BOM
     */
    private static InputStream skipBom(Reader metadata) throws SamlException {
        try {
            InputStream metadataInputStream;
            metadataInputStream =
                    IOUtils.toInputStream(IOUtils.toString(metadata), StandardCharsets.UTF_8);

            return new BOMInputStream(metadataInputStream, false);
        } catch (IOException e) {
            throw new SamlException("Saml Couldn't skipBom", e);
        }
    }

    /**
     * Decode Base64, then decode if needed
     *
     * @param encodedResponse a Base64 String with optionally deflated xml
     * @param method          The HTTP method used by the request
     * @return A Reader with decoded and inflated xml
     */
    private static Reader decodeAndInflate(String encodedResponse, String method) {
        // 解码
        ByteArrayInputStream afterB64Decode =
                new ByteArrayInputStream(Base64.decodeBase64(encodedResponse));

        if ("GET".equals(method)) {
            // If the request was a GET request, the value will have been deflated
            // get请求的话，该值会被压缩
            InputStream afterInflate = new InflaterInputStream(afterB64Decode, new Inflater(true));
            return new InputStreamReader(afterInflate, StandardCharsets.UTF_8);
        } else {
            return new InputStreamReader(afterB64Decode, StandardCharsets.UTF_8);
        }
    }

    private synchronized static void ensureOpenSamlIsInitialized() throws SamlException {
        if (!initializedOpenSaml) {
            try {
                InitializationService.initialize();
                initializedOpenSaml = true;
            } catch (Throwable ex) {
                throw new SamlException("Saml Error while initializing the Open SAML library", ex);
            }
        }
    }

    private static BasicParserPool createDOMParser() throws SamlException {
        BasicParserPool basicParserPool = new BasicParserPool();
        try {
            basicParserPool.initialize();
        } catch (ComponentInitializationException e) {
            throw new SamlException("Saml Failed to create an XML parser");
        }
        return basicParserPool;
    }

    private static DOMMetadataResolver createMetadataResolver(InputStream metadata)
            throws SamlException {
        try {
            BasicParserPool parser = createDOMParser();
            Document metadataDocument = parser.parse(metadata);
            DOMMetadataResolver resolver = new DOMMetadataResolver(metadataDocument.getDocumentElement());
            resolver.setId(UUID.randomUUID().toString());
            resolver.initialize();
            return resolver;
        } catch (ComponentInitializationException | XMLParserException ex) {
            throw new SamlException("Saml Cannot parse Metadata", ex);
        }
    }

    private static EntityDescriptor getEntityDescriptor(DOMMetadataResolver metadata) throws SamlException {
        List<EntityDescriptor> entityDescriptors = new ArrayList<>();
        metadata.forEach(entityDescriptors::add);
        if (entityDescriptors.size() != 1) {
            throw new SamlException("Saml Bad entity descriptor count: " + entityDescriptors.size());
        }
        return entityDescriptors.get(0);
    }

    private static IDPSSODescriptor getIDPSSODescriptor(EntityDescriptor entityDescriptor) throws SamlException {
        IDPSSODescriptor idpssoDescriptor =
                entityDescriptor.getIDPSSODescriptor(SamlConstants.NS_SAMLP);
        if (idpssoDescriptor == null) {
            throw new SamlException("Saml Cannot retrieve IDP SSO descriptor");
        }
        return idpssoDescriptor;
    }

    private static SingleSignOnService getIdpBinding(
            IDPSSODescriptor idpSsoDescriptor, SamlBindingEnum samlBindingEnum) throws SamlException {
        return idpSsoDescriptor
                .getSingleSignOnServices()
                .stream()
                .filter(x -> x.getBinding().equals(samlBindingEnum.getFormat()))
                .findAny()
                .orElseThrow(() -> new SamlException("Saml Cannot find HTTP-POST SSO binding in metadata"));
    }

    private static List<X509Certificate> getCertificates(IDPSSODescriptor idpSsoDescriptor)
            throws SamlException {

        List<X509Certificate> certificates;
        try {
            certificates = idpSsoDescriptor
                    .getKeyDescriptors()
                    .stream()
                    .filter(x -> x.getUse() == UsageType.SIGNING)
                    .flatMap(SamlClient::getDatasWithCertificates)
                    .map(SamlClient::getFirstCertificate)
                    .collect(Collectors.toList());

        } catch (Exception e) {
            throw new SamlException("Saml Exception in getCertificates", e);
        }
        return certificates;
    }

    private static Stream<X509Data> getDatasWithCertificates(KeyDescriptor descriptor) {
        return descriptor
                .getKeyInfo()
                .getX509Datas()
                .stream()
                .filter(d -> d.getX509Certificates().size() > 0);
    }

    private static X509Certificate getFirstCertificate(X509Data data) {
        try {
            org.opensaml.xmlsec.signature.X509Certificate cert =
                    data.getX509Certificates().stream().findFirst().orElse(null);
            if (cert != null) {
                return KeyInfoSupport.getCertificate(cert);
            }
        } catch (CertificateException e) {
            log.error("Saml Exception in getFirstCertificate", e);
        }

        return null;
    }

    private static Credential getCredential(X509Certificate certificate) {
        BasicX509Credential credential = new BasicX509Credential(certificate);
        credential.setCRLs(Collections.emptyList());
        return credential;
    }

    /**
     * Decodes and validates an SAML response returned by an identity provider.
     *
     * @param encodedResponse the encoded response returned by the identity provider.
     * @param method          The HTTP method used by the request
     * @return An {@link SamlResponse} object containing information decoded from the SAML response.
     * @throws SamlException if the signature is invalid, or if any other error occurs.
     */
    public SamlLogoutResponse decodeAndValidateSamlLogoutResponse(
            String encodedResponse, String method) throws SamlException {
        // 将字符串解析为 登出xml响应对象
        LogoutResponse logoutResponse = (LogoutResponse) parseResponse(encodedResponse, method);
        // 验证
        ValidatorTool.validate(logoutResponse, responseIssuer, credentials);

        return new SamlLogoutResponse(logoutResponse.getStatus());
    }

    /**
     * Decodes and validates an SAML logout request send by an identity provider.
     *
     * @param encodedRequest the encoded request send by the identity provider.
     * @param nameID         The user to logout
     * @param method         The HTTP method used by the request
     * @throws SamlException if the signature is invalid, or if any other error occurs.
     */
    public void decodeAndValidateSamlLogoutRequest(
            String encodedRequest, String nameID, String method) throws SamlException {
        // 解码 request
        LogoutRequest logoutRequest = (LogoutRequest) parseResponse(encodedRequest, method);
        // 校验
        ValidatorTool.validate(logoutRequest, responseIssuer, credentials, nameID);
    }

    /**
     * Set service provider keys.
     *
     * @param publicKey  the public key
     * @param privateKey the private key
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     */
    @Deprecated
    public void setSPKeys(String publicKey, String privateKey) throws SamlException {
        this.spCredential = generateBasicX509Credential(publicKey, privateKey);
    }

    public void setSPKeysNew(String publicKey, String privateKey) throws SamlException {
        this.spCredential = generateBasicX509CredentialNew(publicKey, privateKey);
    }

    /**
     * generate an X509Credential from the provided key and cert.
     *
     * @param publicKey  the public key
     * @param privateKey the private key
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     */
    @Deprecated
    public BasicX509Credential generateBasicX509Credential(String publicKey, String privateKey) throws SamlException {
        if (publicKey == null || privateKey == null) {
            throw new SamlException("Saml No credentials provided");
        }
        PrivateKey pk = loadPrivateKey(privateKey);
        X509Certificate cert = loadCertificate(publicKey);
        return new BasicX509Credential(cert, pk);
    }

    public BasicX509Credential generateBasicX509CredentialNew(String publicKey, String privateKey) throws SamlException {
        if (publicKey == null || privateKey == null) {
            throw new SamlException("Saml No credentials provided");
        }
        PrivateKey pk = loadPrivateKeyNew(privateKey);
        X509Certificate cert = loadCertificateNew(publicKey);
        return new BasicX509Credential(cert, pk);
    }

    /**
     * Set service provider keys.
     *
     * @param certificate the certificate
     * @param privateKey  the private key
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     */
    public void setSPKeys(X509Certificate certificate, PrivateKey privateKey) throws SamlException {
        if (certificate == null || privateKey == null) {
            throw new SamlException("Saml No credentials provided");
        }
        spCredential = new BasicX509Credential(certificate, privateKey);
    }

    /**
     * Add an additional service provider certificate/key pair for decryption.
     *
     * @param publicKey  the public key
     * @param privateKey the private key
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     */
    @Deprecated
    public void addAdditionalSPKey(String publicKey, String privateKey) throws SamlException {
        additionalSpCredentials.add(generateBasicX509Credential(publicKey, privateKey));
    }

    public void addAdditionalSPKey(X509Certificate certificate, PrivateKey privateKey) throws SamlException {
        additionalSpCredentials.add(new BasicX509Credential(certificate, privateKey));
    }

    /**
     * Remove all additional service provider decryption certificate/key pairs.
     */
    public void clearAdditionalSPKeys() throws SamlException {
        additionalSpCredentials = new ArrayList<>();
    }

    /**
     * Gets attributes from the IDP Response
     *
     * @param response the response
     * @return the attributes
     */
    public static Map<String, String> getAttributes(SamlResponse response) {
        HashMap<String, String> map = new HashMap<>();
        if (response == null) {
            return map;
        }
        List<AttributeStatement> attributeStatements = response.getAssertion().getAttributeStatements();
        if (attributeStatements == null) {
            return map;
        }

        for (AttributeStatement statement : attributeStatements) {
            for (Attribute attribute : statement.getAttributes()) {
                XMLObject xmlObject = attribute.getAttributeValues().get(0);
                if (xmlObject instanceof XSStringImpl) {
                    map.put(attribute.getName(), ((XSStringImpl) xmlObject).getValue());
                } else {
                    map.put(attribute.getName(), ((XSAnyImpl) xmlObject).getTextContent());
                }
            }
        }
        return map;
    }

    /**
     * Create a minimal SAML request
     *
     * @param defaultElementName The SomeClass.DEFAULT_ELEMENT_NAME we'll be casting this object into
     */
    private RequestAbstractType getBasicSamlRequest(QName defaultElementName) {
        // 构建一个request xml
        RequestAbstractType request = (RequestAbstractType) buildSamlObject(defaultElementName);
        request.setID("supos_" + UUID.randomUUID());
        // 支支持2.0
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(DateTime.now());
        // 构建断言/issuer
        Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(relyingPartyIdentifier);
        request.setIssuer(issuer);
        return request;
    }

    /**
     * Convert a SAML request to a base64-encoded String
     *
     * @param request The request to encode
     * @throws SamlException if marshalling the request fails
     */
    private String marshallAndEncodeSamlObject(RequestAbstractType request) throws SamlException {
        byte[] bytes;
        try {
            // 生成 xml
            StringWriter stringWriter = marshallXmlObject(request);
            log.info("Saml Issuing SAML request: " + stringWriter);

            bytes = stringWriter.toString().getBytes(StandardCharsets.UTF_8);
//            if (SamlIdpBindingEnum.Redirect.equals(samlBinding)) {
//                // 如果是重定向，压缩下请求数据
//                bytes = compress(bytes);
//            }
//        } catch (IOException e) {
//            e.printStackTrace();

        } catch (MarshallingException e) {
            throw new SamlException("Saml Error while marshalling SAML request to XML", e);
        }
        return Base64.encodeBase64String(bytes);
    }

    public String getSamlRequest() throws SamlException {
        return getSamlRequest(UN_SPECIFIED);
    }

    public String getSamlRequest(NameIdFormatsEnum formatEnum) throws SamlException {
        // 构建认证的 request
        AuthnRequest request = (AuthnRequest) getBasicSamlRequest(AuthnRequest.DEFAULT_ELEMENT_NAME);
        // 指定地址
        request.setProtocolBinding(samlBindingEnum.getFormat());
        request.setDestination(identityProviderUrl);
        request.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
        // todo 构建 nameID
        NameIDPolicy nameIDPolicy = (NameIDPolicy) buildSamlObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIDPolicy.setFormat(formatEnum.getFormat());
        nameIDPolicy.setAllowCreate(true);
        request.setNameIDPolicy(nameIDPolicy);
        // 加签请求，SP需要有证书
        signSAMLObject(request);
        // 拿到一个编码后的request字符串
        return marshallAndEncodeSamlObject(request);
    }

    /**
     * Gets the encoded logout request.
     *
     * @param nameId the name id
     * @return the logout request
     * @throws SamlException the saml exception
     */
    public String getLogoutRequest(String nameId) throws SamlException {
        // 构建一个登出 request
        LogoutRequest request = (LogoutRequest) getBasicSamlRequest(LogoutRequest.DEFAULT_ELEMENT_NAME);
        request.setDestination(identityProviderUrl);
        // 构建nameId
        NameID nid = (NameID) buildSamlObject(NameID.DEFAULT_ELEMENT_NAME);
//        nid.setFormat(UN_SPECIFIED.getFormat());
        nid.setValue(nameId);
        request.setNameID(nid);
        // 加签
        signSAMLObject(request);
        // 编码返回字符串
        return marshallAndEncodeSamlObject(request);
    }

    /**
     * Gets saml logout response.
     *
     * @param status the status code @See StatusCode.java
     * @return saml logout response
     * @throws SamlException the saml exception
     */
    public String getSamlLogoutResponse(final String status) throws SamlException {
        return getSamlLogoutResponse(status, null);
    }

    /**
     * Gets saml logout response.
     *
     * @param status  the status code @See StatusCode.java
     * @param statMsg the status message
     * @return saml logout response
     * @throws SamlException the saml exception
     */
    public String getSamlLogoutResponse(final String status, final String statMsg)
            throws SamlException {
        // 构建登出的response
        LogoutResponse response = (LogoutResponse) buildSamlObject(LogoutResponse.DEFAULT_ELEMENT_NAME);
        //todo ADFS needs IDs to start with a letter
        response.setID("z" + UUID.randomUUID());

        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(DateTime.now());
        // 构建断言/issuer
        Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(relyingPartyIdentifier);
        response.setIssuer(issuer);

        // 构建状态码
        Status stat = (Status) buildSamlObject(Status.DEFAULT_ELEMENT_NAME);

        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        if (statMsg != null) {
            // 构建状态消息
            StatusMessage statMessage = new StatusMessageBuilder().buildObject();
            statMessage.setMessage(statMsg);
            stat.setStatusMessage(statMessage);
        }
        response.setStatus(stat);
        // 在响应中添加签名
        signSAMLObject(response);

        StringWriter stringWriter;
        try {
            // 构建成String
            stringWriter = marshallXmlObject(response);
        } catch (MarshallingException ex) {
            throw new SamlException("Saml Error while marshalling SAML request to XML", ex);
        }

        log.info("Saml Issuing SAML Logout request: " + stringWriter);

        return Base64.encodeBase64String(stringWriter.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Processes a POST containing the SAML logout request.
     *
     * @param request the {@link HttpServletRequest}.
     * @param nameID  the user to log out.
     * @throws SamlException thrown is an unexpected error occurs.
     */
    public void processLogoutRequestPostFromIdentityProvider(
            HttpServletRequest request, String nameID) throws SamlException {
        String encodedResponse = request.getParameter(HTTP_REQ_SAML_PARAM);
        decodeAndValidateSamlLogoutRequest(encodedResponse, nameID, request.getMethod());
    }

    /**
     * Processes a POST containing the SAML response.
     *
     * @param request the {@link HttpServletRequest}.
     * @return An {@link SamlResponse} object containing information decoded from the SAML response.
     * @throws SamlException thrown is an unexpected error occurs.
     */
    public SamlLogoutResponse processPostLogoutResponseFromIdentityProvider(
            HttpServletRequest request) throws SamlException {
        String encodedResponse = request.getParameter(HTTP_RESP_SAML_PARAM);
        return decodeAndValidateSamlLogoutResponse(encodedResponse, request.getMethod());
    }

    /**
     * Redirects an {@link HttpServletResponse} to the configured identity provider.
     *
     * @param response   The {@link HttpServletResponse}.
     * @param relayState Optional relay state that will be passed along.
     * @param nameId     the user to log out.
     * @throws IOException   thrown if an IO error occurs.
     * @throws SamlException thrown is an unexpected error occurs.
     */
    public void redirectToIdentityProvider(
            HttpServletResponse response, String relayState, String nameId)
            throws IOException, SamlException {
        Map<String, String> values = new HashMap<>();
        values.put("SAMLRequest", getLogoutRequest(nameId));
        if (relayState != null) {
            values.put("RelayState", relayState);
        }
        BrowserUtils.postUsingBrowser(identityProviderUrl, response, values);
    }

    /**
     * Redirect to identity provider logout.
     *
     * @param response   the response
     * @param statusCode the status code
     * @param statMsg    the stat msg
     * @throws IOException   the io exception
     * @throws SamlException the saml exception
     */
    public void redirectToIdentityProviderLogout(
            HttpServletResponse response, String statusCode, String statMsg)
            throws IOException, SamlException {
        Map<String, String> values = new HashMap<>();
        values.put(HTTP_RESP_SAML_PARAM, getSamlLogoutResponse(statusCode, statMsg));
        BrowserUtils.postUsingBrowser(identityProviderUrl, response, values);
    }

    private static XMLObject buildSamlObject(QName qname) {
        return XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(qname)
                .buildObject(qname);
    }

    /**
     * Decode the encrypted assertion.
     *
     * @param response the response
     * @throws DecryptionException the decryption exception
     */
    private void decodeEncryptedAssertion(Response response) throws DecryptionException {
        if (response.getEncryptedAssertions().size() == 0) {
            return;
        }
        for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
            // 添加SP端配置好的证书
            List<KeyInfoCredentialResolver> resolverChain = new ArrayList<>();
            if (spCredential != null) {
                resolverChain.add(new StaticKeyInfoCredentialResolver(spCredential));
            }
            if (!additionalSpCredentials.isEmpty()) {
                resolverChain.add(new CollectionKeyInfoCredentialResolver(additionalSpCredentials));
            }
            // 创建解密器
            Decrypter decrypter =
                    new Decrypter(
                            null,
                            new ChainingKeyInfoCredentialResolver(resolverChain),
                            new InlineEncryptedKeyResolver());
            decrypter.setRootInNewDocument(true);
            // 解密被加密的断言
            Assertion decryptedAssertion = decrypter.decrypt(encryptedAssertion);
            response.getAssertions().add(decryptedAssertion);
        }
    }

    /**
     * Load an X.509 certificate
     *
     * @param filename The path of the certificate
     */
    @Deprecated
    public X509Certificate loadCertificate(String filename) throws SamlException {
        try (FileInputStream fis = new FileInputStream(filename);
             BufferedInputStream bis = new BufferedInputStream(fis)) {

            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            return (X509Certificate) cf.generateCertificate(bis);

        } catch (FileNotFoundException e) {
            throw new SamlException("Saml Public key file doesn't exist", e);
        } catch (Exception e) {
            throw new SamlException("Saml Couldn't load public key", e);
        }
    }

    public X509Certificate loadCertificateNew(String fileName) throws SamlException {
        try (InputStream inputStream = new DefaultResourceLoader().getResource(fileName).getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);

        } catch (FileNotFoundException e) {
            throw new SamlException("Saml Private key file doesn't exist", e);
        } catch (Exception e) {
            throw new SamlException("Saml Couldn't load private key", e);
        }
    }

    /**
     * Load a PKCS8 key
     *
     * @param filename The path of the key
     */
    @Deprecated
    private PrivateKey loadPrivateKey(String filename) throws SamlException {
        try (RandomAccessFile raf = new RandomAccessFile(filename, "r")) {
            byte[] buf = new byte[(int) raf.length()];
            raf.readFully(buf);
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePrivate(kspec);

        } catch (FileNotFoundException e) {
            throw new SamlException("Saml Private key file doesn't exist", e);
        } catch (Exception e) {
            throw new SamlException("Saml Couldn't load private key", e);
        }
    }

    /**
     * Load a PKCS8 key
     */
    private PrivateKey loadPrivateKeyNew(String fileName) throws SamlException {
        try (InputStream inputStream = new DefaultResourceLoader().getResource(fileName).getInputStream()) {
            byte[] bytes = IOUtils.toByteArray(inputStream);
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePrivate(kspec);

        } catch (FileNotFoundException e) {
            throw new SamlException("Saml Private key file doesn't exist", e);
        } catch (Exception e) {
            throw new SamlException("Saml Couldn't load private key", e);
        }
    }

    private StringWriter marshallXmlObject(XMLObject object) throws MarshallingException {
        StringWriter stringWriter = new StringWriter();
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
        Element dom = marshaller.marshall(object);
        XMLHelper.writeNode(dom, stringWriter);
        return stringWriter;
    }

    private SAMLObject parseResponse(String encodedResponse, String method) throws SamlException {
        log.info("Saml Validating SAML response " + encodedResponse);
        try {
            // 解码，转化成xml对象
            Document responseDocument = domParser.parse(decodeAndInflate(encodedResponse, method));
            return (SAMLObject)
                    XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                            .getUnmarshaller(responseDocument.getDocumentElement())
                            .unmarshall(responseDocument.getDocumentElement());
        } catch (UnmarshallingException | XMLParserException ex) {
            throw new SamlException("Saml Cannot decode xml encoded response", ex);
        }
    }

    /**
     * Sign a SamlObject with default settings.
     * Note that this method is a no-op if spCredential is unset.
     */
    private void signSAMLObject(SignableSAMLObject samlObject) throws SamlException {
        if (spCredential != null) {
            try {
                // 在响应中构建签名信息
                SignatureBuilder signer = new SignatureBuilder();
                Signature signature = signer.buildObject(Signature.DEFAULT_ELEMENT_NAME);
                // 设置签名算法
                signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
                signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
                // sp端证书
                X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
                x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
                x509KeyInfoGeneratorFactory.setEmitPublicKeyValue(true);
                x509KeyInfoGeneratorFactory.setEmitKeyNames(true);
                KeyInfo keyInfo = x509KeyInfoGeneratorFactory.newInstance().generate(spCredential);
                signature.setKeyInfo(keyInfo);
                signature.setSigningCredential(spCredential);
                samlObject.setSignature(signature);

                // 实际签名操作
                SignatureSigningParameters signingParameters = new SignatureSigningParameters();
                // 设置签名算法
                signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
                signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
                // sp端证书
                signingParameters.setKeyInfoGenerator(x509KeyInfoGeneratorFactory.newInstance());
                signingParameters.setSigningCredential(spCredential);
                // 对saml进行签名
                SignatureSupport.signObject(samlObject, signingParameters);
            } catch (MarshallingException | SignatureException | SecurityException e) {
                throw new SamlException("Saml Failed to sign request", e);
            }
        }
    }

    private static byte[] compress(byte[] bytes) throws IOException {
        int len;
        Deflater defl = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        defl.setInput(bytes);
        defl.finish();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] outputByte = new byte[1024];
        try {
            while (!defl.finished()) {
                // 压缩并将压缩后的内容输出到字节输出流bos中
                len = defl.deflate(outputByte);
                bos.write(outputByte, 0, len);
            }
            defl.end();

        } finally {
            bos.close();
        }
        return bos.toByteArray();
    }
}
