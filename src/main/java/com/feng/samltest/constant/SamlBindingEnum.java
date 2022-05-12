package com.feng.samltest.constant;

public enum SamlBindingEnum {
    HTTP_POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
    HTTP_REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
    HTTP_ARTIFACT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"),
    SOAP("urn:oasis:names:tc:SAML:2.0:bindings:SOAP"),
    DEFLATE("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"),
    ;

    private final String format;

    SamlBindingEnum(String format) {
        this.format = format;
    }

    public String getFormat() {
        return format;
    }
}
