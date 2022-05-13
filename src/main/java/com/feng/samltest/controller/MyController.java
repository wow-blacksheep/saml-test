package com.feng.samltest.controller;

import com.feng.samltest.exception.SamlException;
import com.feng.samltest.service.SamlClient;
import com.feng.samltest.util.SamlXmlTool;
import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static com.feng.samltest.constant.NameIdFormatsEnum.UN_SPECIFIED;
import static com.feng.samltest.constant.SamlBindingEnum.HTTP_POST;

@Controller
public class MyController {

    @RequestMapping("login")
    public String login() {
        return "login.html";
    }

    @RequestMapping("logout")
    public String logout() {
        return "logout.html";
    }

    @GetMapping("third/authorize")
    @ResponseBody
    public String authorizeByGet() {
        return "authorizeByGet 方式被回调";
    }

    @PostMapping("third/authorize")
    @ResponseBody
    public String authorizeByPost() {
        return "authorizeByPost 方式被回调";
    }

    @RequestMapping("upload")
    @ResponseBody
    public String upload(MultipartFile fileUpload) throws IOException, SamlException {
        String s = SamlXmlTool.base64encoder(fileUpload.getBytes());
        byte[] bytes = SamlXmlTool.base64decoder(s);
        InputStream input = new ByteArrayInputStream(bytes);
        InputStreamReader inputStreamReader = new InputStreamReader(input, StandardCharsets.UTF_8);

        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx",
                "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize",
                inputStreamReader,
                HTTP_POST,
                null);
        return "login.html";
    }

}
