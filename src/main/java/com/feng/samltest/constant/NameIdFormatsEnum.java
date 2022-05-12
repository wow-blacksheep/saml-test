package com.feng.samltest.constant;

import com.google.common.collect.Lists;

import java.util.List;

public enum NameIdFormatsEnum {

    EMAIL_ADDRESS("email_address", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
    X509_SUBJECT_NAME("x509_subject_name", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"),
    WINDOWS_DOMAIN_QUALIFIED_NAME("windows_domain_qualified_name", "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"),
    UN_SPECIFIED("un_specified", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),

    KERBEROS("kerberos", "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"),
    ENTITY("entity", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"),
    TRANSIENT("transient", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
    PERSISTENT("persistent", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
    ENCRYPTED("encrypted", "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"),
    ;

    private final String alias;
    private final String format;

    NameIdFormatsEnum(String alias, String format) {
        this.alias = alias;
        this.format = format;
    }

    public String getFormatByAlias(String alias) {
        for (NameIdFormatsEnum value : NameIdFormatsEnum.values()) {
            if (value.alias.equalsIgnoreCase(alias)) {
                return value.format;
            }
        }
        return UN_SPECIFIED.format;
    }

    public List<String> getAvalidFormat() {
        return Lists.newArrayList(UN_SPECIFIED.alias);
    }

    public String getAlias() {
        return alias;
    }

    public String getFormat() {
        return format;
    }
}
