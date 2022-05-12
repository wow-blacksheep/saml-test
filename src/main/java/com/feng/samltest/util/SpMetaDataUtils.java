package com.feng.samltest.util;

import com.feng.samltest.sp.SettingsBuilder;

import java.util.Map;

public class SpMetaDataUtils {

    public static String generate(Map<String, Object> samlData) throws Exception {
        return new SettingsBuilder()
                .setSamlData(samlData)
                .build()
                .getSPMetadata();
    }
}
