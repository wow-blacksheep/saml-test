package com.feng.samltest.constant;

import com.google.common.collect.Lists;

import java.util.List;

public enum PrincipalTypeEnum {
    Subject_NameID("Subject NameID"),
    ;

    private final String format;

    PrincipalTypeEnum(String format) {
        this.format = format;
    }

    public List<String> getAvalidFormat() {
        return Lists.newArrayList(Subject_NameID.format);
    }

    public String getFormat() {
        return format;
    }
}
