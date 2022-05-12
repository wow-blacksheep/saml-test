package com.feng.samltest;

import com.feng.samltest.constant.SamlBindingEnum;
import com.feng.samltest.dto.SamlResponse;
import com.feng.samltest.exception.SamlException;
import com.feng.samltest.service.SamlClient;
import com.feng.samltest.util.SpMetaDataUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.feng.samltest.constant.NameIdFormatsEnum.PERSISTENT;
import static com.feng.samltest.constant.NameIdFormatsEnum.UN_SPECIFIED;
import static com.feng.samltest.constant.SamlBindingEnum.HTTP_REDIRECT;
import static com.feng.samltest.sp.SettingsBuilder.*;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KeyCloakTest {

    private static Reader getXml(String name) {
        return getXml(name, StandardCharsets.UTF_8);
    }

    private static Reader getXml(String name, Charset charset) {
        return new InputStreamReader(SamlClientTest.class.getResourceAsStream("/" + name), charset);
    }

    @Test
    public void autheRequest() throws SamlException {
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx",
                "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize",
                getXml("129IDPdescriptor.xml"),
                SamlBindingEnum.HTTP_POST,
                null);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());
          String samlRequest = client.getSamlRequest(UN_SPECIFIED);
        System.out.println(samlRequest);
        //todo MyController.login
    }

    @Test
    public void decodeAutheResponse() throws SamlException {
        //todo MyController.authorizeByPost
        //todo MyController.authorizeByGet

        String s = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIERlc3RpbmF0aW9uPSJodHRwOi8vMTkyLjE2OC4xOC4xMjk6ODA4MC9pbnRlci1hcGkvYXV0aC92MS90aGlyZC9hdXRob3JpemUiIElEPSJJRF8zYTM5NDg0My05MzIxLTQ3NjMtOTA3MC1jNjJlYzI5MGYxYjYiIEluUmVzcG9uc2VUbz0ic3Vwb3NfYzczNTRiYWEtMDkwMy00ZTc3LTlmMjgtY2VjNzkxN2Y5MmVlIiBJc3N1ZUluc3RhbnQ9IjIwMjItMDUtMTBUMDU6MjM6NTIuMDQ1WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXI+aHR0cDovLzE5Mi4xNjguMTguMTI5OjgwODAvYXV0aC9yZWFsbXMvZHQ8L3NhbWw6SXNzdWVyPjxkc2lnOlNpZ25hdHVyZSB4bWxuczpkc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHNpZzpTaWduZWRJbmZvPjxkc2lnOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHNpZzpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzaWc6UmVmZXJlbmNlIFVSST0iI0lEXzNhMzk0ODQzLTkzMjEtNDc2My05MDcwLWM2MmVjMjkwZjFiNiI+PGRzaWc6VHJhbnNmb3Jtcz48ZHNpZzpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkc2lnOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHNpZzpUcmFuc2Zvcm1zPjxkc2lnOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkc2lnOkRpZ2VzdFZhbHVlPjBLR3JNci9hUElwMXRvS1FkV1JyQTlHcDRucEd4VW1IL0ZPTEIrN1VFNkU9PC9kc2lnOkRpZ2VzdFZhbHVlPjwvZHNpZzpSZWZlcmVuY2U+PC9kc2lnOlNpZ25lZEluZm8+PGRzaWc6U2lnbmF0dXJlVmFsdWU+bEdPY1pEdkFIdmNnZHRNM1NGNjN5YzlUZWgvY1ZFZVRMd3dwL3krKytiNEI2UXB4VUc4YWxjS1JBSEkvYVJRUndOQUVQaDQzTlhpZ1A5b1NFaXl3SkUveGp2TWgydDJJQkRnemRETmRpTmF4YkpReVRhWWIweWowQWcvb2VocVFBcU8zUUlWZS9BNWlobnA2eVRqM0FiNmVxTnhDOU1HWm9ybXd3WW4vNG9aNUZqN3dHZklGZ0YrNlk4UUVLSGtYS0ZoOFV4NDcvMGlKTENsUjBybzhTMTFWemVOYitsYWZaZTdLM21XaWpLS29GQ1ZLclFtVUFnNUlZb0RZcGpqeVBoQWtuTTJKdUlMM20zcmdBRitSMG5hQURZTC9keDk5SmxtSmpGLzhTTFJxYStmdk1nTDduS2ZKMnVRQXYzOFdvTzd5WDZDWkl1ZHd1N2lMYXljTERnPT08L2RzaWc6U2lnbmF0dXJlVmFsdWU+PGRzaWc6S2V5SW5mbz48ZHNpZzpLZXlOYW1lPnB6WGl5dFhUdlVWbHphOWhQLW1lN0RRc0tteW9GTEtKYUd4TkcwRDN1Sk08L2RzaWc6S2V5TmFtZT48ZHNpZzpYNTA5RGF0YT48ZHNpZzpYNTA5Q2VydGlmaWNhdGU+TUlJQ21UQ0NBWUVDQmdGMEM4YThvakFOQmdrcWhraUc5dzBCQVFzRkFEQVFNUTR3REFZRFZRUUREQVZ6ZFhCdmN6QWVGdzB5TURBNE1qQXhNakE0TWpkYUZ3MHpNREE0TWpBeE1qRXdNRGRhTUJBeERqQU1CZ05WQkFNTUJYTjFjRzl6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0a3ZvWHM3b0ZCYWVVUytJNkhhMVNGYno0b3dRUDRZWjBhZi91akRBajBCV2JIQmJHUVhiT3dTci9LdzZlRlB6eHoyQmZRVHZydGFBdEFvbzUvL1pTNlM4d3NHZlhud1Nra1h5TVlyeWUrT0pmc0NHSHYwRmZTYlN2ZnM2QWdwKzhFOUEvU2NCL2ZML2tNdnZWeHZyKzFMZVhyOEtjNFI1d295ZGFIdG80Q2pENml4N0piZmFxK1VWUzdSVDJURStUR0JqcGJjVWZ4Y2V5Z1ZhWDhsdDdzNDh6MGRjd2c4Z0pFazRNd0lWQ0M1aUE0NHRaUzNiWEJMQlVhWnN4NFZDNWRLKzRjNVBYTkRBRFdIWEtGMncrVTcwTW9CNXZTUjVSekFEV081c2xRZjJoM1Z0MkhiN2NGUGRoR0JvV3pyVGZtZHpSTStLaWk4YmZMeHJZcHoyV1FJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNmbmJDT0xWQmZSSDROcXhwUDZJZFlEREZDZ0g1WDR5MFZHck9sRndOdHljSlRiY2lSRk1PajJyelVhdEVzMDBXSDd1VWlQWDEzTEl1blFSaXFyZnRnMkorbTB5Szg0RDNVQjIyUlVQc01MSHRwYTZiSUpiak1pUzFXZWV6UGd5UFZndnY0Q1paSGlaVzNhcTcwSUtqVzM3Umt3TGdzUGd5RUNRQkI5Q2hQRHRFR0Fja2tEK0F0TGR1YVRxMTFtYzRtRkM1OTdCMmRwVTFRTzNPZ3VwZC9oL0tHSXUyVGlYR0tJWUx4eGtxb1hzc3dBcG9uU0ZtRThiOGgzWHJQNjZ0NFRiaGZhVTNOTy9sVWJ2M0RsMktrdFFrcWN3enpUZ3l0YnkrY1FSS29Ja24vcnB1KzdxbUZzdysxR2tKUW55VUExZHRCQ2RMOTRGeTJjSnJyVHpKeDwvZHNpZzpYNTA5Q2VydGlmaWNhdGU+PC9kc2lnOlg1MDlEYXRhPjxkc2lnOktleVZhbHVlPjxkc2lnOlJTQUtleVZhbHVlPjxkc2lnOk1vZHVsdXM+dGt2b1hzN29GQmFlVVMrSTZIYTFTRmJ6NG93UVA0WVowYWYvdWpEQWowQldiSEJiR1FYYk93U3IvS3c2ZUZQenh6MkJmUVR2cnRhQXRBb281Ly9aUzZTOHdzR2ZYbndTa2tYeU1ZcnllK09KZnNDR0h2MEZmU2JTdmZzNkFncCs4RTlBL1NjQi9mTC9rTXZ2Vnh2cisxTGVYcjhLYzRSNXdveWRhSHRvNENqRDZpeDdKYmZhcStVVlM3UlQyVEUrVEdCanBiY1VmeGNleWdWYVg4bHQ3czQ4ejBkY3dnOGdKRWs0TXdJVkNDNWlBNDR0WlMzYlhCTEJVYVpzeDRWQzVkSys0YzVQWE5EQURXSFhLRjJ3K1U3ME1vQjV2U1I1UnpBRFdPNXNsUWYyaDNWdDJIYjdjRlBkaEdCb1d6clRmbWR6Uk0rS2lpOGJmTHhyWXB6MldRPT08L2RzaWc6TW9kdWx1cz48ZHNpZzpFeHBvbmVudD5BUUFCPC9kc2lnOkV4cG9uZW50PjwvZHNpZzpSU0FLZXlWYWx1ZT48L2RzaWc6S2V5VmFsdWU+PC9kc2lnOktleUluZm8+PC9kc2lnOlNpZ25hdHVyZT48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJJRF8wYjVjNWZhYi1hMzEyLTRlZjktOWI0MC1kNGQ3NWU4MzgyOTAiIElzc3VlSW5zdGFudD0iMjAyMi0wNS0xMFQwNToyMzo1Mi4wNDVaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3Vlcj5odHRwOi8vMTkyLjE2OC4xOC4xMjk6ODA4MC9hdXRoL3JlYWxtcy9kdDwvc2FtbDpJc3N1ZXI+PHNhbWw6U3ViamVjdD48c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDp1bnNwZWNpZmllZCI+YWRtaW48L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89InN1cG9zX2M3MzU0YmFhLTA5MDMtNGU3Ny05ZjI4LWNlYzc5MTdmOTJlZSIgTm90T25PckFmdGVyPSIyMDIyLTA1LTEwVDA1OjI4OjUwLjA0NVoiIFJlY2lwaWVudD0iaHR0cDovLzE5Mi4xNjguMTguMTI5OjgwODAvaW50ZXItYXBpL2F1dGgvdjEvdGhpcmQvYXV0aG9yaXplIi8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjItMDUtMTBUMDU6MjM6NTAuMDQ1WiIgTm90T25PckFmdGVyPSIyMDIyLTA1LTEwVDA1OjI0OjUwLjA0NVoiPjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWw6QXVkaWVuY2U+aHR0cDovLzE5Mi4xNjguMTguMTI5OjgwODAveHh4PC9zYW1sOkF1ZGllbmNlPjwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDpDb25kaXRpb25zPjxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyMi0wNS0xMFQwNToyMzo1Mi4wNDVaIiBTZXNzaW9uSW5kZXg9IjY0ZGY2ZjE5LTY2ZjEtNDM5My04ODQ5LTRlMjhkZDJjMzU2ODo6ODA4MjQwNTctMDJmZS00MDJhLTlkZjMtMTc4YjllZDQ4NmFmIiBTZXNzaW9uTm90T25PckFmdGVyPSIyMDIzLTA1LTEwVDA1OjIzOjUyLjA0NVoiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3Nlczp1bnNwZWNpZmllZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+";
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx", "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize", getXml("129IDPdescriptor.xml"), SamlBindingEnum.HTTP_POST);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());
        SamlResponse post = client.decodeAndValidateSamlResponse(s, "POST");
        String nameID = post.getNameID();
        System.out.println(nameID);
    }

    @Test
    public void logoutRequest() throws SamlException {
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx", "http://192.168.18.129:8080/inter-api/auth/logout", getXml("129IDPdescriptor.xml"), SamlBindingEnum.HTTP_POST);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());
        String samlRequest = client.getLogoutRequest("admin");
        System.out.println(samlRequest);
    }


    @Test
    public void generateMetaData() throws Exception {
        Map<String, Object> samlData = new LinkedHashMap<>();
        samlData.put(SP_ENTITYID_PROPERTY_KEY, "http://192.168.18.129:8080/xxx");
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize");
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, "http://192.168.18.129:8080/inter-api/auth/logout");
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY, HTTP_REDIRECT.getFormat());
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, HTTP_REDIRECT.getFormat());
        samlData.put(SP_NAMEIDFORMAT_PROPERTY_KEY, PERSISTENT.getFormat());
        samlData.put(SP_X509CERT_PROPERTY_KEY,
                "MIIDZTCCAk2gAwIBAgIUYtJGqYO6YHccBfKct0M8XQdr7p0wDQYJKoZIhvcNAQEL" +
                        "BQAwQjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE" +
                        "CgwTRGVmYXVsdCBDb21wYW55IEx0ZDAeFw0yMjA1MDkwNzI4MjhaFw0yMzA1MDkw" +
                        "NzI4MjhaMEIxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAa" +
                        "BgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IB" +
                        "DwAwggEKAoIBAQClzWo7sNlRQwWrtSNv3g3BtTSOCtUCRrrHCB1Wv2uIODhpmRX+" +
                        "/rr+UVhDCot7K1uTis6llx6L0+gRIMEXTiUXnxWEBJXK4QAbp8VMH7NYAzMzZFSD" +
                        "/Y+akJxOsTqJCapu5A41jfeBlaoqAK74J95qeYN07PgfdE4/wo85CGuvivN6qPBZ" +
                        "k5C+GH4xSEb/BDQ83ByVLDSgTrLKEpcTwFckTZTWFPwia/uyGCm+mBdYqP+e4+oq" +
                        "nQIdfzvEyvI0ZAlnRgp1nheZV2Jlo+SKGWBYr9Jjy6jhpdWxeLZiddeZ3isZ5BZf" +
                        "I70lqTQfvdRz51FbK6uqgqfjNeSIpoO5oXffAgMBAAGjUzBRMB0GA1UdDgQWBBRS" +
                        "0mbFqjbGvnbvVq2GMsxlp6eW3TAfBgNVHSMEGDAWgBRS0mbFqjbGvnbvVq2GMsxl" +
                        "p6eW3TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBG1aHG1zPw" +
                        "9IGHH7kxUXD/ViGAgK4r7BOdGYd2Qb7pJSACkFEm1elXmzAfVHHdS4MgA1wyu6nu" +
                        "cmtZFGyWWJQMmOHpJzdS6l/HPwRwmBahbDQxeJsrYVyArpPsqk1DZhM/GR/hPmdF" +
                        "gKbd8s5SOz+Pm8xKct/b0oudYSqXwVu2xqmev8C2NpiUxmu53ZiHgn0TEME32Qy9" +
                        "NeQBxS/FobEe5OBC4980Mogny8RCegf6QHyobPizbdXYlDSuDw/xY6aHT9kaIDlg" +
                        "SedjtciHVzGn/ME3cvLCb8ao90AAXNaB9YxdQPyK24QoU4UySIrkNlk2uvo2yoGg" +
                        "+s1Lhjabr7me");
        samlData.put(SECURITY_AUTHREQUEST_SIGNED, "true");

        String spMetadata = SpMetaDataUtils.generate(samlData);
        System.out.println(spMetadata);
    }
}
