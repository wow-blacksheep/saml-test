package com.feng.samltest.controller;

import com.alibaba.fastjson.JSON;
import com.feng.samltest.constant.NameIdFormatsEnum;
import com.feng.samltest.exception.SamlException;
import com.feng.samltest.service.SamlClient;
import com.feng.samltest.sp.Saml2Settings;
import com.feng.samltest.sp.SettingsBuilder;
import com.feng.samltest.util.SamlXmlTool;
import com.feng.samltest.vo.SpMetadataVo;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.feng.samltest.constant.SamlBindingEnum.HTTP_POST;
import static com.feng.samltest.sp.SettingsBuilder.*;

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

    @GetMapping(value = "spMetadata", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getSpMetadata(@RequestParam("redirectUrl") String redirectUrl,
                                @RequestParam(value = "spEntityId",required = false) String spEntityId,
                                @RequestParam("logoutUrl") String logoutUrl,
                                @RequestParam("nameIdFormatType") String nameIdFormatType) throws CertificateEncodingException, SamlException {

        Map<String, Object> samlData = new LinkedHashMap<>();
        samlData.put(SP_ENTITYID_PROPERTY_KEY, null == spEntityId ? redirectUrl : spEntityId);
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, redirectUrl);
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, logoutUrl);
        samlData.put(SP_NAMEIDFORMAT_PROPERTY_KEY, NameIdFormatsEnum.getFormatByAlias(nameIdFormatType));
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY, HTTP_POST.getFormat());
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, HTTP_POST.getFormat());
        samlData.put(SECURITY_AUTHREQUEST_SIGNED, "true");

        Saml2Settings settings = new SettingsBuilder()
                .setSamlData(samlData)
                .build();

        String file = this.getClass().getResource("/saml-public-key-supos.crt").getFile();
        X509Certificate x509Certificate = new SamlClient().loadCertificate(file);
        settings.setSpX509cert(x509Certificate);
        return settings.getSPMetadata();
    }

    @GetMapping
    @ResponseBody
    public String requetParamTest(@RequestParam("redirectUrl") String redirectUrl, String a) {
        return String.format("%s---------%s", redirectUrl, a);
    }

    @PostMapping
    @ResponseBody
    public String haha(SpMetadataVo vo,
                       HttpServletRequest request,
                       @RequestHeader(value = "xxx") String xxx,
                       @RequestHeader(value = "User-Agent") String userAgent,
                       @CookieValue(name = "zzz")String zzz) {
        System.out.println(xxx);
        System.out.println(zzz);
        System.out.println(userAgent);
        return String.format("%s---------%s", JSON.toJSONString(vo), JSON.toJSONString(request.getHeaderNames()));
    }
}
