package com.feng.samltest.util;

import com.feng.samltest.exception.SamlException;
import com.feng.samltest.valid.LogoutRequestSchemaValidator;
import com.feng.samltest.valid.ResponseSchemaValidator;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import java.util.List;

/**
 * The type Validator utils.
 */
public class ValidatorTool {

    /**
     * Validate response.
     *
     * @param response       the response
     * @param responseIssuer the response issuer
     * @throws SamlException the saml exception
     */
    private static void validateResponse(StatusResponseType response, String responseIssuer)
            throws SamlException {
        try {
            // 验空和版本
            new ResponseSchemaValidator().validate(response);
        } catch (SamlException e) {
            throw new SamlException("The response schema validation failed", e);
        }
        // 响应方是否匹配 元数据中的IDP信息
        validateIssuer(response, responseIssuer);
    }

    /**
     * Validate status.
     *
     * @param response the response
     * @throws SamlException the saml exception
     */
    private static void validateStatus(StatusResponseType response) throws SamlException {

        String statusCode = response.getStatus().getStatusCode().getValue();

        if (!StatusCode.SUCCESS.equals(statusCode)) {
            throw new SamlException("Invalid status code: " + statusCode);
        }
    }

    /**
     * Validate issuer.
     *
     * @param response       the response
     * @param responseIssuer the response issuer
     * @throws SamlException the saml exception
     */
    private static void validateIssuer(StatusResponseType response, String responseIssuer)
            throws SamlException {
        // 响应方是否匹配 元数据中的IDP信息
        if (!response.getIssuer().getValue().equals(responseIssuer)) {
            throw new SamlException("The response issuer didn't match the expected value");
        }
    }

    /**
     * Validate issuer.
     *
     * @param request       the response
     * @param requestIssuer the request issuer
     * @throws SamlException the saml exception
     */
    private static void validateIssuer(RequestAbstractType request, String requestIssuer)
            throws SamlException {
        if (!request.getIssuer().getValue().equals(requestIssuer)) {
            throw new SamlException("The request issuer didn't match the expected value");
        }
    }

    /**
     * Validate assertion.
     *
     * @param response       the response
     * @param responseIssuer the response issuer
     * @param now            the current date time (for unit test only)
     * @param notBeforeSkew  the notBeforeSkew
     * @throws SamlException the saml exception
     */
    private static void validateAssertion(
            Response response, String responseIssuer, DateTime now, long notBeforeSkew)
            throws SamlException {
        // 断言只能存在1个
        if (response.getAssertions().size() != 1) {
            throw new SamlException("The response doesn't contain exactly 1 assertion");
        }
        // 断言中的发行人和元数据中不一致
        Assertion assertion = response.getAssertions().get(0);
        if (!assertion.getIssuer().getValue().equals(responseIssuer)) {
            throw new SamlException("The assertion issuer didn't match the expected value");
        }
        // naemID
        if (assertion.getSubject().getNameID() == null) {
            throw new SamlException(
                    "The NameID value is missing from the SAML response; this is likely an IDP configuration issue");
        }
        // 时间校验
//    enforceConditions(assertion.getConditions(), now, notBeforeSkew);
    }

    /**
     * Enforce conditions.
     *
     * @param conditions    the conditions
     * @param _now          the current date time (for unit test only)
     * @param notBeforeSkew the notBeforeSkew
     * @throws SamlException the saml exception
     */
    private static void enforceConditions(Conditions conditions, DateTime _now, long notBeforeSkew)
            throws SamlException {
        DateTime now = _now != null ? _now : DateTime.now();

        DateTime notBefore = conditions.getNotBefore();
        DateTime skewedNotBefore = notBefore.minus(notBeforeSkew);
        if (now.isBefore(skewedNotBefore)) {
            throw new SamlException("The assertion cannot be used before " + notBefore.toString());
        }

        DateTime notOnOrAfter = conditions.getNotOnOrAfter();
        if (now.isAfter(notOnOrAfter)) {
            throw new SamlException("The assertion cannot be used after  " + notOnOrAfter.toString());
        }
    }

    /**
     * Validate signature.
     *
     * @param response    the response
     * @param credentials the credentials
     * @throws SamlException the saml exception
     */
    private static void validateSignature(SignableSAMLObject response, List<Credential> credentials)
            throws SamlException {
        // 响应中存在签名，则用元数据中的证书进行验签
        if (response.getSignature() != null && !validate(response.getSignature(), credentials)) {
            throw new SamlException("The response signature is invalid");
        }
    }

    /**
     * Validate assertion signature.
     *
     * @param response    the response
     * @param credentials the credentials
     * @throws SamlException the saml exception
     */
    private static void validateAssertionSignature(Response response, List<Credential> credentials)
            throws SamlException {
        Signature assertionSignature = response.getAssertions().get(0).getSignature();

        if (response.getSignature() == null && assertionSignature == null) {
            throw new SamlException("响应和断言中都不存在签名");
        }

        if (assertionSignature != null && !validate(assertionSignature, credentials)) {
            throw new SamlException("断言中的签名解签失败");
        }
    }

    /**
     * Validate boolean.
     *
     * @param signature   the signature
     * @param credentials the credentials
     * @return the boolean
     */
    private static boolean validate(Signature signature, List<Credential> credentials) {
        if (signature == null) {
            return false;
        }

        // It's fine if any of the credentials match the signature
        return credentials
                .stream()
                .anyMatch(
                        credential -> {
                            try {
                                SignatureValidator.validate(signature, credential);
                                return true;
                            } catch (SignatureException ex) {
                                return false;
                            }
                        });
    }

    /**
     * Validate.
     *
     * @param response       the response
     * @param responseIssuer the response issuer
     * @param credentials    the credentials
     * @param now            the current date time (for unit test only)
     * @param notBeforeSkew  the notBeforeSkew
     * @throws SamlException the saml exception
     */
    public static void validate(
            Response response,
            String responseIssuer,
            List<Credential> credentials,
            DateTime now,
            long notBeforeSkew)
            throws SamlException {
        validateResponse(response, responseIssuer);
        validateAssertion(response, responseIssuer, now, notBeforeSkew);
        validateSignature(response, credentials);
        validateAssertionSignature(response, credentials);
    }

    /**
     * Validate.
     *
     * @param logoutRequest  the response
     * @param responseIssuer the response issuer
     * @param credentials    the credentials
     * @throws SamlException the saml exception
     */
    public static void validate(
            LogoutRequest logoutRequest,
            String responseIssuer,
            List<Credential> credentials,
            String nameID)
            throws SamlException {
        validateLogoutRequest(logoutRequest, responseIssuer, nameID);
        validateSignature(logoutRequest, credentials);
    }

    /**
     * Validate.
     *
     * @param response       the response
     * @param responseIssuer the response issuer
     * @param credentials    the credentials
     * @throws SamlException the saml exception
     */
    public static void validate(
            LogoutResponse response, String responseIssuer, List<Credential> credentials)
            throws SamlException {
        validateResponse(response, responseIssuer);
        validateSignature(response, credentials);
    }

    /**
     * Validate response.
     *
     * @param response       the response
     * @param responseIssuer the response issuer
     * @throws SamlException the saml exception
     */
    private static void validateResponse(Response response, String responseIssuer)
            throws SamlException {
        try {
            // 验空和版本
            new ResponseSchemaValidator().validate(response);
        } catch (SamlException ex) {
            throw new SamlException("The response schema validation failed", ex);
        }
        // 响应方是否匹配 元数据中的IDP信息
        validateIssuer(response, responseIssuer);
        // 状态码是否正确
        validateStatus(response);
    }

    /**
     * Validate response.
     *
     * @param request       the request
     * @param requestIssuer the response issuer
     * @throws SamlException the saml exception
     */
    private static void validateLogoutRequest(
            LogoutRequest request, String requestIssuer, String nameID) throws SamlException {
        try {
            // 验空、版本、标识id
            new LogoutRequestSchemaValidator().validate(request);
        } catch (SamlException ex) {
            throw new SamlException("The request schema validation failed", ex);
        }
        validateIssuer(request, requestIssuer);
        validateNameId(request, nameID);
    }

    /**
     * Validate the logout request name id.
     *
     * @param request the request
     * @param nameID  the name id
     * @throws SamlException the saml exception
     */
    private static void validateNameId(LogoutRequest request, String nameID) throws SamlException {
        if (nameID == null || !nameID.equals(request.getNameID().getValue())) {
            throw new SamlException("The nameID of the logout request is incorrect");
        }
    }
}
