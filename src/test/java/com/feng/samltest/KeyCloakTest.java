package com.feng.samltest;

import com.feng.samltest.constant.SamlBindingEnum;
import com.feng.samltest.dto.SamlLogoutResponse;
import com.feng.samltest.dto.SamlResponse;
import com.feng.samltest.exception.SamlException;
import com.feng.samltest.service.SamlClient;
import com.feng.samltest.sp.Saml2Settings;
import com.feng.samltest.sp.SettingsBuilder;
import com.feng.samltest.util.SamlXmlTool;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.*;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import sun.misc.BASE64Encoder;
import sun.security.x509.X509CertImpl;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.feng.samltest.constant.NameIdFormatsEnum.PERSISTENT;
import static com.feng.samltest.constant.NameIdFormatsEnum.UN_SPECIFIED;
import static com.feng.samltest.constant.SamlBindingEnum.HTTP_POST;
import static com.feng.samltest.sp.SettingsBuilder.*;
import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KeyCloakTest {

    private static Reader getXml(String name) {
        return getXml(name, StandardCharsets.UTF_8);
    }

    private static Reader getXml(String name, Charset charset) {
        return new InputStreamReader(SamlClientTest.class.getResourceAsStream("/" + name), charset);
    }

    /**
     * 构建认证请求
     */
    @Test
    public void autheRequest() throws SamlException {
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx",
                "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize",
                getXml("129IDPdescriptor.xml"),
//                getXml("federation_metadata_new.xml"),
                HTTP_POST,
                null);
//
//        client.setSPKeys(
//                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
//                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());

        client.setSPKeysNew("classpath:saml-public-key-supos.crt","classpath:saml-private-key-supos.pk8");
        String samlRequest = client.getSamlRequest(UN_SPECIFIED);
        System.out.println(samlRequest);
        //todo MyController.login

        //万华  jycong  密码1
        // 万华 登出：https://samqas.whchem.com/logout.html
    }

    /**
     * 解码登入认证响应
     */
    @Test
    public void decodeAutheResponse() throws SamlException {
        //todo MyController.authorizeByPost
        //todo MyController.authorizeByGet

        String s = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgRGVzdGluYXRpb249Imh0dHA6Ly8xOTIuMTY4LjE4LjEyOTo4MDgwL2ludGVyLWFwaS9hdXRoL3YxL3RoaXJkL2F1dGhvcml6ZSIgSUQ9IkZJTVJTUF9iNzQ4MDZkNS0wMTgwLTE2YjgtYTcyYi1iMGVmMTUyMzExYTciIEluUmVzcG9uc2VUbz0ic3Vwb3NfNzIwOTJjNmItYWI3YS00ZDk5LWFjZjgtOGZiNDVjYzNkYzI5IiBJc3N1ZUluc3RhbnQ9IjIwMjItMDUtMTJUMDc6NTk6NTJaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly9zYW1xYXMud2hjaGVtLmNvbS9pc2FtbW1wcy9zcHMvc2FtbG1tcHMvc2FtbDIwPC9zYW1sOklzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiPjwvc2FtbHA6U3RhdHVzQ29kZT48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24gSUQ9IkFzc2VydGlvbi11dWlkYjc0ODA2YzQtMDE4MC0xNmQ3LWEwZWQtYjBlZjE1MjMxMWE3IiBJc3N1ZUluc3RhbnQ9IjIwMjItMDUtMTJUMDc6NTk6NTJaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly9zYW1xYXMud2hjaGVtLmNvbS9pc2FtbW1wcy9zcHMvc2FtbG1tcHMvc2FtbDIwPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBJZD0idXVpZGI3NDgwNmM5LTAxODAtMWMzNi1hNjViLWIwZWYxNTIzMTFhNyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjwvZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZD48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiI+PC9kczpTaWduYXR1cmVNZXRob2Q+PGRzOlJlZmVyZW5jZSBVUkk9IiNBc3NlcnRpb24tdXVpZGI3NDgwNmM0LTAxODAtMTZkNy1hMGVkLWIwZWYxNTIzMTFhNyI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOlRyYW5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48eGMxNG46SW5jbHVzaXZlTmFtZXNwYWNlcyB4bWxuczp4YzE0bj0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIiBQcmVmaXhMaXN0PSJzYW1sIHhzIHhzaSI+PC94YzE0bjpJbmNsdXNpdmVOYW1lc3BhY2VzPjwvZHM6VHJhbnNmb3JtPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ij48L2RzOkRpZ2VzdE1ldGhvZD48ZHM6RGlnZXN0VmFsdWU+U3I5VUd0QURzd1RTMXJZbHVoRmJmTEFhczd0K2lwL2ZMT2F4d1I2VU5mRT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+T3cxcnNPTU9MOU80S04wbUFxSnJaWFlWY2dzSUZ4Qml0cVAvemF1ZEtGR1c0SEN4b2E5dm5ZbDdNejBPSnRLamc1VUVnY01HLzJjQkx1dkxDeVJnWEFsekk3ZXp3ZmxaZ0l4VC82YzBXT1VaVlQ4bDBWcHNWZk92UmJOQm5JdE9rTGlwbVB1WUt6a0ZYUHhHMk1VWG5TcWQ5bDR1UjBmVXVQRlVzK3Z4bFZrPTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJQjVUQ0NBVTZnQXdJQkFnSUlSNXUydVdoMWhLWXdEUVlKS29aSWh2Y05BUUVMQlFBd0V6RVJNQThHQTFVRUF4TUlWVUZRVVVGVE1ERXdIaGNOTVRneE1EQTVNRE15TlRJeVdoY05Nemd4TURJMU1ETXlOVEl5V2pBVE1SRXdEd1lEVlFRREV3aFZRVkJSUVZNd01UQ0JuekFOQmdrcWhraUc5dzBCQVFFRkFBT0JqUUF3Z1lrQ2dZRUF3Y3VzTWZzdUJCeVdaSFl2RHpvVy9rL2JHWWtEWjg4TDI5T1FyYzJOMGxoTXc2bncveERaL050Q2FtK3dWRG9hWEQzWG10SklWWVZJVmFjVlgrY041STBpNDJJZFRDRU1hRStCZE5MNVVuSEMyckxBMllaalRhRk4xUVFrVHlKVEpILzdySDRMV0F4NFVIbGVCcnRjZzB1eWNQcFk4OXdLcmxiQ2M3QTdlV2NDQXdFQUFhTkNNRUF3SFFZRFZSME9CQllFRlBuMEhSYkJid05ZZEZ3Smo3UURUd3N5NCt3NE1COEdBMVVkSXdRWU1CYUFGUG4wSFJiQmJ3TllkRndKajdRRFR3c3k0K3c0TUEwR0NTcUdTSWIzRFFFQkN3VUFBNEdCQUNoWCtUbkxVUVN3ekZuaWZMb3lobnRxNnptazZJUFF2QTlQRFFCMkVXVmhiVFZoOHpRUFVsR2FSVkpGemREQUtUWnExT2k0WUo0QlFXdktvamVHdGFHd2doaTdOVlhaa1BCMFlCc0VqeGltOHRUekJMbEc3dFd4dTZhTC8rYTZFVFV5Nmt4TW85b0U3SUkyeFhQdDB6cnVMMmwyWXR2akY4enZFeUdudTRYNTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+anljb25nPC9zYW1sOk5hbWVJRD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJzdXBvc183MjA5MmM2Yi1hYjdhLTRkOTktYWNmOC04ZmI0NWNjM2RjMjkiIE5vdE9uT3JBZnRlcj0iMjAyMi0wNS0xMlQwODowNDo1MloiIFJlY2lwaWVudD0iaHR0cDovLzE5Mi4xNjguMTguMTI5OjgwODAvaW50ZXItYXBpL2F1dGgvdjEvdGhpcmQvYXV0aG9yaXplIj48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGE+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjItMDUtMTJUMDc6NTQ6NTJaIiBOb3RPbk9yQWZ0ZXI9IjIwMjItMDUtMTJUMDg6MDQ6NTJaIj48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPmh0dHA6Ly8xOTIuMTY4LjE4LjEyOTo4MDgwL3h4eDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjItMDUtMTJUMDc6NTk6NTJaIiBTZXNzaW9uSW5kZXg9InV1aWRiNzQ2MGNhNy0wMTgwLTFhZWYtYTNjZC1iMGVmMTUyMzExYTciIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMjItMDUtMTJUMDg6NTk6NTJaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJlbWFpbEFkZHJlc3MiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmp5Y29uZ0B3aGNoZW0uY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0FVVEhfTUVUSE9EIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5wYXNzd29yZDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ0YWd2YWx1ZV91c2VyX3Nlc3Npb25faWQiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPlZVRlFVVUZUTURFdGQyVmljMlZoYkRFQV9ZbnkrZUFBQUFBSUFBQUEwZUw1OFltaktKVGlmZndBQVREQnNNakl6WkN0bFowbERWV1l3YkU5NVlVVXpRekp5TDFKYWJXSk9ValYyTTNWMGFqQjRkVlZaT1dOMlNWZFBZWEZKUFE9PTpkZWZhdWx0PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX1BSSU5DSVBBTF9VVUlEIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4wMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDA8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfUU9QX0lORk8iIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPlNTSzogVExTVjEyOiA5Qzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9QUklOQ0lQQUxfRE9NQUlOIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5EZWZhdWx0PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFVVEhFTlRJQ0FUSU9OX0xFVkVMIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4xPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX1JFR0lTVFJZX0lEIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj51aWQ9anljb25nLGNuPXVzZXJzLGRjPXdhbmh1YSxkYz1jb208L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfTkVUV09SS19BRERSRVNTX1NUUiIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+MTAuMTAuMjI5LjEyNTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJtb2JpbGVOdW1iZXIiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjE4MTUzNTE5NzE3PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0FVVEhOTUVDSF9JTkZPIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5MREFQIFJlZ2lzdHJ5PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX1BSSU5DSVBBTF9OQU1FIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5qeWNvbmc8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfSVBfRkFNSUxZIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5BRl9JTkVUPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InRhZ3ZhbHVlX3Nlc3Npb25faW5kZXgiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjMzY2MwOGQyLWQxYzktMTFlYy1iZDNlLTAwNTA1NjkxM2NmOTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9ORVRXT1JLX0FERFJFU1NfQklOIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4weDBhMGFlNTdkPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0JST1dTRVJfSU5GTyIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMS4wLjQ5NTEuNTQgU2FmYXJpLzUzNy4zNjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9WRVJTSU9OIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4weDAwMDAwOTA1PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlNNU19TRVNTSU9OX1JFQUxNIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5JU0FNLURpc3RyaWJ1dGVkLVNlc3Npb24tQ2FjaGU8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfTUVDSF9JRCIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+SVZfTERBUF9WMy4wPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0FVVEhaTl9JRCIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dWlkPWp5Y29uZyxjbj11c2VycyxkYz13YW5odWEsZGM9Y29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InRhZ3ZhbHVlX21heF9jb25jdXJyZW50X3dlYl9zZXNzaW9ucyIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dW5zZXQ8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idGFndmFsdWVfbG9naW5fdXNlcl9uYW1lIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5qeWNvbmc8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L3NhbWw6QXR0cmlidXRlU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=";
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx",
                "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize",
                getXml("129IDPdescriptor.xml"),
//                getXml("federation_metadata_new.xml"),
                HTTP_POST);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());
        SamlResponse post = client.decodeAndValidateSamlResponse(s, "POST");
        String nameID = post.getNameID();
        System.out.println(nameID);
    }

    /**
     * 构建登出参数
     */
    @Test
    public void logoutRequest() throws SamlException {
        String samlRequest = getLogoutRequest();
        System.out.println(samlRequest);
    }

    /**
     * 服务端登出测试
     */
    @Test
    public void logoutTest() throws SamlException {
        HttpHeaders headers = new HttpHeaders();
        //  请勿轻易改变此提交方式，大部分的情况下，提交方式都是表单提交
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        //  封装参数，千万不要替换为Map与HashMap，否则参数无法传递
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        //  也支持中文
        params.add("SAMLRequest", getLogoutRequest());
        params.add("RelayState", "123456");

        String url = "http://192.168.18.129:8080/auth/realms/dt/protocol/saml";
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);

        RestTemplate client = new RestTemplate();
        //  执行HTTP请求
        ResponseEntity<String> response = client.exchange(url, HttpMethod.POST, requestEntity, String.class);
        String body = response.getBody();

        System.out.println(body);

        // 万华 注销地址：https://samuat.whchem.com/logout.html
//        ResponseEntity<String> responseEntity = client.getForEntity("https://samuat.whchem.com/logout.html", String.class);
//        String body2 = responseEntity.getBody();
//        int statusCodeValue2 = responseEntity.getStatusCodeValue();
    }

    private String getLogoutRequest() throws SamlException {
        // 万华 注销地址：https://samuat.whchem.com/logout.html


        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx",
                "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize",
                getXml("129IDPdescriptor.xml"),
//                getXml("federation_metadata_new.xml"),
                HTTP_POST,
                null);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());

//        String samlRequest = client.getLogoutRequest("jycong");
        return client.getLogoutRequest("admin");
    }


    /**
     * 解码登出响应
     */
    @Test
    public void decodeLgoutResponse() throws SamlException {
        String a = "PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBEZXN0aW5hdGlvbj0iaHR0cDovLzE5Mi4xNjguMTguMTI5OjgwODAvaW50ZXItYXBpL2F1dGgvbG9nb3V0IiBJRD0iSURfMzkyOWI0MDItMDJjMS00MGVjLWIxZWEtYjExZjIxNjJlYzA5IiBJblJlc3BvbnNlVG89InN1cG9zX2QzYWYzM2U3LWFlNjAtNDM0Mi1iZTc3LTQwYjhiOTQwMmQyNyIgSXNzdWVJbnN0YW50PSIyMDIyLTA1LTE1VDA0OjEyOjIwLjcwOFoiIFZlcnNpb249IjIuMCI+PElzc3Vlcj5odHRwOi8vMTkyLjE2OC4xOC4xMjk6ODA4MC9hdXRoL3JlYWxtcy9kdDwvSXNzdWVyPjxkc2lnOlNpZ25hdHVyZSB4bWxuczpkc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHNpZzpTaWduZWRJbmZvPjxkc2lnOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHNpZzpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzaWc6UmVmZXJlbmNlIFVSST0iI0lEXzM5MjliNDAyLTAyYzEtNDBlYy1iMWVhLWIxMWYyMTYyZWMwOSI+PGRzaWc6VHJhbnNmb3Jtcz48ZHNpZzpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkc2lnOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHNpZzpUcmFuc2Zvcm1zPjxkc2lnOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkc2lnOkRpZ2VzdFZhbHVlPjBHdEZETGw2Vzg1dllwN3JtRFhadkNYcEVUOERhWVE4ZGk1UGsyT1VYSGc9PC9kc2lnOkRpZ2VzdFZhbHVlPjwvZHNpZzpSZWZlcmVuY2U+PC9kc2lnOlNpZ25lZEluZm8+PGRzaWc6U2lnbmF0dXJlVmFsdWU+am1GbmZpTEt3Y3NPS3hjVDVJbFpuaXdEMWZ2L3hST1FqQVBZNHZuNWlEU01TaVFFUkJBYXloeDRHNVhxMEczUnpqQ0gxUnp5anl0b004OG1Fencxd3pUclRsM1I5VGtwL2MzYnpKdHNSOE4va1N3TEU0U0RtVFo0QkJlcWZSYUZzbXFEMGE2VXFkdEZCMWtsY1FvcmtoVkxoTU40SmtoY2FMa2hjL0tKQWFMSHRTcVlEY3RlbmxSbkVmNXRtZ2lwTU9YOTF0VzZTME9jbXVsZlRNV3BMNCtwYW9LYTFVTnFGT1pBbGtlR3hzaGk2OHZSRjd3dGpMVTlJL1ppa01FbXcybUtGakFzRXFpaGRBMUFoNlVSS2ZYVWF4d1RiNi9JdXVXQWhQSUkrVmQ1NU10K1o0WCtSVS8xNUZjM1ZwT1RGblVzWmJudnpIS3RoaGM2eTNQdXlnPT08L2RzaWc6U2lnbmF0dXJlVmFsdWU+PGRzaWc6S2V5SW5mbz48ZHNpZzpLZXlOYW1lPnB6WGl5dFhUdlVWbHphOWhQLW1lN0RRc0tteW9GTEtKYUd4TkcwRDN1Sk08L2RzaWc6S2V5TmFtZT48ZHNpZzpYNTA5RGF0YT48ZHNpZzpYNTA5Q2VydGlmaWNhdGU+TUlJQ21UQ0NBWUVDQmdGMEM4YThvakFOQmdrcWhraUc5dzBCQVFzRkFEQVFNUTR3REFZRFZRUUREQVZ6ZFhCdmN6QWVGdzB5TURBNE1qQXhNakE0TWpkYUZ3MHpNREE0TWpBeE1qRXdNRGRhTUJBeERqQU1CZ05WQkFNTUJYTjFjRzl6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0a3ZvWHM3b0ZCYWVVUytJNkhhMVNGYno0b3dRUDRZWjBhZi91akRBajBCV2JIQmJHUVhiT3dTci9LdzZlRlB6eHoyQmZRVHZydGFBdEFvbzUvL1pTNlM4d3NHZlhud1Nra1h5TVlyeWUrT0pmc0NHSHYwRmZTYlN2ZnM2QWdwKzhFOUEvU2NCL2ZML2tNdnZWeHZyKzFMZVhyOEtjNFI1d295ZGFIdG80Q2pENml4N0piZmFxK1VWUzdSVDJURStUR0JqcGJjVWZ4Y2V5Z1ZhWDhsdDdzNDh6MGRjd2c4Z0pFazRNd0lWQ0M1aUE0NHRaUzNiWEJMQlVhWnN4NFZDNWRLKzRjNVBYTkRBRFdIWEtGMncrVTcwTW9CNXZTUjVSekFEV081c2xRZjJoM1Z0MkhiN2NGUGRoR0JvV3pyVGZtZHpSTStLaWk4YmZMeHJZcHoyV1FJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNmbmJDT0xWQmZSSDROcXhwUDZJZFlEREZDZ0g1WDR5MFZHck9sRndOdHljSlRiY2lSRk1PajJyelVhdEVzMDBXSDd1VWlQWDEzTEl1blFSaXFyZnRnMkorbTB5Szg0RDNVQjIyUlVQc01MSHRwYTZiSUpiak1pUzFXZWV6UGd5UFZndnY0Q1paSGlaVzNhcTcwSUtqVzM3Umt3TGdzUGd5RUNRQkI5Q2hQRHRFR0Fja2tEK0F0TGR1YVRxMTFtYzRtRkM1OTdCMmRwVTFRTzNPZ3VwZC9oL0tHSXUyVGlYR0tJWUx4eGtxb1hzc3dBcG9uU0ZtRThiOGgzWHJQNjZ0NFRiaGZhVTNOTy9sVWJ2M0RsMktrdFFrcWN3enpUZ3l0YnkrY1FSS29Ja24vcnB1KzdxbUZzdysxR2tKUW55VUExZHRCQ2RMOTRGeTJjSnJyVHpKeDwvZHNpZzpYNTA5Q2VydGlmaWNhdGU+PC9kc2lnOlg1MDlEYXRhPjxkc2lnOktleVZhbHVlPjxkc2lnOlJTQUtleVZhbHVlPjxkc2lnOk1vZHVsdXM+dGt2b1hzN29GQmFlVVMrSTZIYTFTRmJ6NG93UVA0WVowYWYvdWpEQWowQldiSEJiR1FYYk93U3IvS3c2ZUZQenh6MkJmUVR2cnRhQXRBb281Ly9aUzZTOHdzR2ZYbndTa2tYeU1ZcnllK09KZnNDR0h2MEZmU2JTdmZzNkFncCs4RTlBL1NjQi9mTC9rTXZ2Vnh2cisxTGVYcjhLYzRSNXdveWRhSHRvNENqRDZpeDdKYmZhcStVVlM3UlQyVEUrVEdCanBiY1VmeGNleWdWYVg4bHQ3czQ4ejBkY3dnOGdKRWs0TXdJVkNDNWlBNDR0WlMzYlhCTEJVYVpzeDRWQzVkSys0YzVQWE5EQURXSFhLRjJ3K1U3ME1vQjV2U1I1UnpBRFdPNXNsUWYyaDNWdDJIYjdjRlBkaEdCb1d6clRmbWR6Uk0rS2lpOGJmTHhyWXB6MldRPT08L2RzaWc6TW9kdWx1cz48ZHNpZzpFeHBvbmVudD5BUUFCPC9kc2lnOkV4cG9uZW50PjwvZHNpZzpSU0FLZXlWYWx1ZT48L2RzaWc6S2V5VmFsdWU+PC9kc2lnOktleUluZm8+PC9kc2lnOlNpZ25hdHVyZT48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48L3NhbWxwOkxvZ291dFJlc3BvbnNlPg==";
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx",
                "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize",
                getXml("129IDPdescriptor.xml"),
                HTTP_POST);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());


        SamlLogoutResponse response = client.decodeAndValidateSamlLogoutResponse(a, "POST");
        boolean valid = response.isValid();
        System.out.println(valid);
    }


    /**
     * 字符串公钥
     * 生成SP元数据文件测试
     */
    @Test
    public void getSpMetadata() throws Exception {
        Map<String, Object> samlData = getStringObjectMap();
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

        Saml2Settings settings = new SettingsBuilder()
                .setSamlData(samlData)
                .build();
        String spMetadata = settings.getSPMetadata();
        System.out.println(spMetadata);
    }

    /**
     * 加载公钥
     * 生成SP元数据文件测试
     */
    @Test
    public void loadCrt() throws IOException, CertificateException, SamlException {
        Map<String, Object> samlData = getStringObjectMap();
        Saml2Settings settings = new SettingsBuilder()
                .setSamlData(samlData)
                .build();

        String file = this.getClass().getResource("/saml-public-key-supos.crt").getFile();
        X509Certificate x509Certificate = new SamlClient().loadCertificate(file);
        settings.setSpX509cert(x509Certificate);

        String spMetadata = settings.getSPMetadata();
        System.out.println(spMetadata);
    }

    private Map<String, Object> getStringObjectMap() {
        Map<String, Object> samlData = new LinkedHashMap<>();
        samlData.put(SP_ENTITYID_PROPERTY_KEY, "http://192.168.18.129:8080/xxx");
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize");
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, "http://192.168.18.129:8080/inter-api/auth/logout");
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY, HTTP_POST.getFormat());
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, HTTP_POST.getFormat());
        samlData.put(SP_NAMEIDFORMAT_PROPERTY_KEY, PERSISTENT.getFormat());
        samlData.put(SECURITY_AUTHREQUEST_SIGNED, "true");
        return samlData;
    }
    private static final DateTime ASSERTION_DATE_HUB =
            new DateTime(2018, 8, 16, 6, 54, 0, DateTimeZone.UTC);

    private static final String AN_ENCODED_RESPONSE_HUB =
            "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWwycDpSZXNwb25zZSBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zcHRlc3QuaWFtc2hvd2Nhc2UuY29tL2FjcyIgSUQ9Il8yMDA0NjEzYi1mZDdjLTRkMTctYjAwNy03NGIyN2JmYzhiODIiIEluUmVzcG9uc2VUbz0iYWU4ZDY3N2JlN2U0ZjNiNzcxZjU2NjljMDgwNzcyZGEyNWM1Y2I0YjYiIElzc3VlSW5zdGFudD0iMjAxOC0wOC0xNlQwNjo1NDo0OS44NjZaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5qZXRicmFpbnMuY29tL2h1Yjwvc2FtbDI6SXNzdWVyPjxzYW1sMnA6U3RhdHVzPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpBc3NlcnRpb24gSUQ9Il9lZTk0MzI0Yy0yNWViLTQ3YzktOWZiNi1kZjk2NTRhNjFiOTkiIElzc3VlSW5zdGFudD0iMjAxOC0wOC0xNlQwNjo1NDo0OS44NjZaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiPjxzYW1sMjpJc3N1ZXI+amV0YnJhaW5zLmNvbS9odWI8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48ZHM6UmVmZXJlbmNlIFVSST0iI19lZTk0MzI0Yy0yNWViLTQ3YzktOWZiNi1kZjk2NTRhNjFiOTkiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjxlYzpJbmNsdXNpdmVOYW1lc3BhY2VzIFByZWZpeExpc3Q9InhzIiB4bWxuczplYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm0+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT54NEJwcE12eis0aGt2NEdTQSt6WGRTOFJrZE09PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPkpCNjZqUll1NlpRdXBqSG0vSVJDM3ZOcDRiZ1IrQlV0UHRES3FQT2ZOb2FzS1J5c3MycHdERHNkODc0RGxkaGVMNy9YYkZ6RWdZT2R4ZkM3Z1V5S2laYVJTM0NGcHlTWkx0d0pDUE51aEJsMStLZEgraU9KTkZYYnVGakFoQmtCWXU4SklQTWt3UUVNSlhCTFZtSTdicXZIdFNqbmd3bnNkTXFqQ01TcnFRVlBtVmJhZXZReTlJUFhZOUFJQ05WWk4xYXJGUUZIZ3k5Qzh5STlkalZqbCtGMTdmeE1iL2pEZU4yTVI3NUJyUE5UM2p3dnNHamhQWGtuTzlwcWlNREZTV2NQVlhiUGtmaStPNTFiWDFudVdnWnpFTlhieUltZ2R2TXBaSzNUTVpLZVdLbjNIRDl2anJaVjdGTnYydkdJbE4zRUlTVlBNcUdvQVJlRHJpYVg5dz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlET2pDQ0FpSUNDUUN0TEhCMmNuNFZNREFOQmdrcWhraUc5dzBCQVFzRkFEQmZNUXN3Q1FZRFZRUUdFd0pFUlRFTU1Bb0dBMVVFCkNBd0RUbEpYTVJFd0R3WURWUVFIREFoTmRXVnVjM1JsY2pFaE1COEdBMVVFQ2d3WVEyOXVjMlZ1YzJVZ1EyOXVjM1ZzZEdsdVp5QkgKYldKSU1Rd3dDZ1lEVlFRTERBTkVSVll3SGhjTk1UZ3dPREUwTVRJeE5EUTBXaGNOTVRrd09ERTBNVEl4TkRRMFdqQmZNUXN3Q1FZRApWUVFHRXdKRVJURU1NQW9HQTFVRUNBd0RUbEpYTVJFd0R3WURWUVFIREFoTmRXVnVjM1JsY2pFaE1COEdBMVVFQ2d3WVEyOXVjMlZ1CmMyVWdRMjl1YzNWc2RHbHVaeUJIYldKSU1Rd3dDZ1lEVlFRTERBTkVSVll3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXcKZ2dFS0FvSUJBUUN5anRkSWo5azIvRHFrdXliUTZYZkFodVNYeEh0UFZHM2F4bGl4NGJmTk1MVXQ0RGRtVTVDY2hqWisrdXV0bTdTNApvMUp6SWpaalUzdHczcTcxMzl1cnRvZWNvTGdxbWQzM1NoRXlRU0swSVE1Qmdodnp3bTRGWVlWdUdKZnhmQm0xY0FHVzVyNkFNbkF3CmhJRDRYeW9UdDFKUGVjaTZGMU9VRHdaN3oxdUdabFREbEUrY25CMHIxeXhYZW5pVUlwam15MW93Z3Nyb09POUJ1ejRiV0JyUE5pU1UKdkFHU05TVWRuZElhMi9WRCsrK0R2U2RpQU9DdUZCTWw3VUxUMCtpemVYelhBVGZlUUU1QTVEUjhzdHBpcHI4aEJiV0NQS1NHTHI3YQowZGh5TVZDUXRnQ2xMOFlGY0JVOWx4Ti9MS2h1Y0dDamRjWW9MVG56NmtlSDY3THJBZ01CQUFFd0RRWUpLb1pJaHZjTkFRRUxCUUFECmdnRUJBQ2dVRlR5TlQyNXdETXhoTjU1SUJOcFRmbk0zck45bjlUZWsrRUxzdGZjMXdhVlVmblR0VGl1MHlZTy9jMDR6aEttWUphQWsKNzBGS1pKUUtJRU1rbTk1UDVxMkk5MWpJR01PaGJiL21EL3ZCL2lUdHI1U1hYZWFyQ0Z4ZFFKSzVEaUUzZnVQVDQzempDVXVZTHJNVQpGWWFrV0FDRm56aUhZbGtPMWJLdUNwVGtob2JSbFJ4RWI1TW1KL1FVTnV1RTlLV3JUMGw4bVdTeWRGS2ZkckFUMDR2NTJ0TnR4TGV4CkVZa1pCT0xIczAwdDJObzRHK2dkWWJ2NEt4MmlubTllanZHdldTTnlMRHRiZHM0ek83VjRXNVNqZzRITXp2Z3c4c2hvN2FqSEVvd1IKMzRJTVk0bVZYdnlFdmUvR3lsT0EwRDIyRE5UR0NxdmNvV2ZWSTBzSXRVST08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDI6U3ViamVjdD48c2FtbDI6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj50ZXN0QHRlc3QudGxkPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJhZThkNjc3YmU3ZTRmM2I3NzFmNTY2OWMwODA3NzJkYTI1YzVjYjRiNiIgTm90T25PckFmdGVyPSIyMDE4LTA4LTE2VDA2OjU2OjQ5Ljg2NloiIFJlY2lwaWVudD0iaHR0cHM6Ly9zcHRlc3QuaWFtc2hvd2Nhc2UuY29tL2FjcyIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q+PHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE4LTA4LTE2VDA2OjUzOjQ5Ljg2NloiIE5vdE9uT3JBZnRlcj0iMjAxOC0wOC0xNlQwNjo1Njo0OS44NjZaIj48c2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDI6QXVkaWVuY2U+SUFNU2hvd2Nhc2U8L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM+PHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxOC0wOC0xNlQwNjo1NDo0OS44NjZaIiBTZXNzaW9uSW5kZXg9Il9lYThiYWM3Yy05YmYyLTQ2MWUtYTQxYi1kN2M5ZDA1NTJkNzMiPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50PjxzYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJ1aWQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj50ZXN0PC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48c2FtbDI6QXR0cmlidXRlIE5hbWU9ImRpc3BsYXlOYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+VGVzdCBVc2VyPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48c2FtbDI6QXR0cmlidXRlIE5hbWU9Im1haWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj50ZXN0QHRlc3QudGxkPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48L3NhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWwyOkFzc2VydGlvbj48L3NhbWwycDpSZXNwb25zZT4=";


    /**
     * 测试字符串转证书是否异常
     */
    @Test
    public void testStringCrtConvert() throws Throwable {
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        Certificate crt = cf.generateCertificate(KeyCloakTest.class.getResourceAsStream("/hub.crt"));

//        String certEntry = "MIIDOjCCAiICCQCtLHB2cn4VMDANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJXMREwDwYDVQQHDAhNdWVuc3RlcjEhMB8GA1UECgwYQ29uc2Vuc2UgQ29uc3VsdGluZyBHbWJIMQwwCgYDVQQLDANERVYwHhcNMTgwODE0MTIxNDQ0WhcNMTkwODE0MTIxNDQ0WjBfMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJXMREwDwYDVQQHDAhNdWVuc3RlcjEhMB8GA1UECgwYQ29uc2Vuc2UgQ29uc3VsdGluZyBHbWJIMQwwCgYDVQQLDANERVYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyjtdIj9k2/DqkuybQ6XfAhuSXxHtPVG3axlix4bfNMLUt4DdmU5CchjZ++uutm7S4o1JzIjZjU3tw3q7139urtoecoLgqmd33ShEyQSK0IQ5Bghvzwm4FYYVuGJfxfBm1cAGW5r6AMnAwhID4XyoTt1JPeci6F1OUDwZ7z1uGZlTDlE+cnB0r1yxXeniUIpjmy1owgsroOO9Buz4bWBrPNiSUvAGSNSUdndIa2/VD+++DvSdiAOCuFBMl7ULT0+izeXzXATfeQE5A5DR8stpipr8hBbWCPKSGLr7a0dhyMVCQtgClL8YFcBU9lxN/LKhucGCjdcYoLTnz6keH67LrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACgUFTyNT25wDMxhN55IBNpTfnM3rN9n9Tek+ELstfc1waVUfnTtTiu0yYO/c04zhKmYJaAk70FKZJQKIEMkm95P5q2I91jIGMOhbb/mD/vB/iTtr5SXXearCFxdQJK5DiE3fuPT43zjCUuYLrMUFYakWACFnziHYlkO1bKuCpTkhobRlRxEb5MmJ/QUNuuE9KWrT0l8mWSydFKfdrAT04v52tNtxLexEYkZBOLHs00t2No4G+gdYbv4Kx2inm9ejvGvWSNyLDtbds4zO7V4W5Sjg4HMzvgw8sho7ajHEowR34IMY4mVXvyEve/GylOA0D22DNTGCqvcoWfVI0sItUI=";
        Certificate cert = getHubXmlCert();

        ArrayList<X509Certificate> certificates = new ArrayList<>();
        certificates.add((X509Certificate) cert);

        SamlClient client =
                SamlClient.fromMetadata(
                        "myidentifier",
                        "http://some/url",
                        getXml("hub.xml"),
                        SamlBindingEnum.HTTP_POST,
                        certificates);
        client.setDateTimeNow(ASSERTION_DATE_HUB);
        SamlResponse response = client.decodeAndValidateSamlResponse(AN_ENCODED_RESPONSE_HUB, "POST");
        System.out.println(response.getNameID());
        assertEquals("test@test.tld", response.getNameID());
    }

    private Certificate getHubXmlCert() throws CertificateException {
        String certEntry = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDOjCCAiICCQCtLHB2cn4VMDANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJE\n" +
                "RTEMMAoGA1UECAwDTlJXMREwDwYDVQQHDAhNdWVuc3RlcjEhMB8GA1UECgwYQ29u\n" +
                "c2Vuc2UgQ29uc3VsdGluZyBHbWJIMQwwCgYDVQQLDANERVYwHhcNMTgwODE0MTIx\n" +
                "NDQ0WhcNMTkwODE0MTIxNDQ0WjBfMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJX\n" +
                "MREwDwYDVQQHDAhNdWVuc3RlcjEhMB8GA1UECgwYQ29uc2Vuc2UgQ29uc3VsdGlu\n" +
                "ZyBHbWJIMQwwCgYDVQQLDANERVYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
                "AoIBAQCyjtdIj9k2/DqkuybQ6XfAhuSXxHtPVG3axlix4bfNMLUt4DdmU5CchjZ+\n" +
                "+uutm7S4o1JzIjZjU3tw3q7139urtoecoLgqmd33ShEyQSK0IQ5Bghvzwm4FYYVu\n" +
                "GJfxfBm1cAGW5r6AMnAwhID4XyoTt1JPeci6F1OUDwZ7z1uGZlTDlE+cnB0r1yxX\n" +
                "eniUIpjmy1owgsroOO9Buz4bWBrPNiSUvAGSNSUdndIa2/VD+++DvSdiAOCuFBMl\n" +
                "7ULT0+izeXzXATfeQE5A5DR8stpipr8hBbWCPKSGLr7a0dhyMVCQtgClL8YFcBU9\n" +
                "lxN/LKhucGCjdcYoLTnz6keH67LrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACgU\n" +
                "FTyNT25wDMxhN55IBNpTfnM3rN9n9Tek+ELstfc1waVUfnTtTiu0yYO/c04zhKmY\n" +
                "JaAk70FKZJQKIEMkm95P5q2I91jIGMOhbb/mD/vB/iTtr5SXXearCFxdQJK5DiE3\n" +
                "fuPT43zjCUuYLrMUFYakWACFnziHYlkO1bKuCpTkhobRlRxEb5MmJ/QUNuuE9KWr\n" +
                "T0l8mWSydFKfdrAT04v52tNtxLexEYkZBOLHs00t2No4G+gdYbv4Kx2inm9ejvGv\n" +
                "WSNyLDtbds4zO7V4W5Sjg4HMzvgw8sho7ajHEowR34IMY4mVXvyEve/GylOA0D22\n" +
                "DNTGCqvcoWfVI0sItUI=\n" +
                "-----END CERTIFICATE-----";
        return SamlXmlTool.getCertificate(certEntry);
    }


    /**
     * 测试证书转字符串是否异常
     */
    @Test
    public void testCrtConvertString() throws Throwable {
        // 从idp文件中取出的签名证书
        String newCert = "MIICmTCCAYECBgF0C8a8ojANBgkqhkiG9w0BAQsFADAQMQ4wDAYDVQQDDAVzdXBvczAeFw0yMDA4MjAxMjA4MjdaFw0zMDA4MjAxMjEwMDdaMBAxDjAMBgNVBAMMBXN1cG9zMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkvoXs7oFBaeUS+I6Ha1SFbz4owQP4YZ0af/ujDAj0BWbHBbGQXbOwSr/Kw6eFPzxz2BfQTvrtaAtAoo5//ZS6S8wsGfXnwSkkXyMYrye+OJfsCGHv0FfSbSvfs6Agp+8E9A/ScB/fL/kMvvVxvr+1LeXr8Kc4R5woydaHto4CjD6ix7Jbfaq+UVS7RT2TE+TGBjpbcUfxceygVaX8lt7s48z0dcwg8gJEk4MwIVCC5iA44tZS3bXBLBUaZsx4VC5dK+4c5PXNDADWHXKF2w+U70MoB5vSR5RzADWO5slQf2h3Vt2Hb7cFPdhGBoWzrTfmdzRM+Kii8bfLxrYpz2WQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCfnbCOLVBfRH4NqxpP6IdYDDFCgH5X4y0VGrOlFwNtycJTbciRFMOj2rzUatEs00WH7uUiPX13LIunQRiqrftg2J+m0yK84D3UB22RUPsMLHtpa6bIJbjMiS1WeezPgyPVgvv4CZZHiZW3aq70IKjW37RkwLgsPgyECQBB9ChPDtEGAckkD+AtLduaTq11mc4mFC597B2dpU1QO3Ogupd/h/KGIu2TiXGKIYLxxkqoXsswAponSFmE8b8h3XrP66t4TbhfaU3NO/lUbv3Dl2KktQkqcwzzTgytby+cQRKoIkn/rpu+7qmFsw+1GkJQnyUA1dtBCdL94Fy2cJrrTzJx";
        Certificate certificate = SamlXmlTool.getCertificate(newCert);
        List<X509Certificate> list = new ArrayList<>();
        list.add((X509Certificate) certificate);
        // 测试时，清空原idp文件中读取的证书
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx",
                "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize",
                getXml("129IDPdescriptor.xml"),
                HTTP_POST,
                list);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());



        String responseStr = "PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBEZXN0aW5hdGlvbj0iaHR0cDovLzE5Mi4xNjguMTguMTI5OjgwODAvaW50ZXItYXBpL2F1dGgvbG9nb3V0IiBJRD0iSURfMzkyOWI0MDItMDJjMS00MGVjLWIxZWEtYjExZjIxNjJlYzA5IiBJblJlc3BvbnNlVG89InN1cG9zX2QzYWYzM2U3LWFlNjAtNDM0Mi1iZTc3LTQwYjhiOTQwMmQyNyIgSXNzdWVJbnN0YW50PSIyMDIyLTA1LTE1VDA0OjEyOjIwLjcwOFoiIFZlcnNpb249IjIuMCI+PElzc3Vlcj5odHRwOi8vMTkyLjE2OC4xOC4xMjk6ODA4MC9hdXRoL3JlYWxtcy9kdDwvSXNzdWVyPjxkc2lnOlNpZ25hdHVyZSB4bWxuczpkc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHNpZzpTaWduZWRJbmZvPjxkc2lnOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHNpZzpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzaWc6UmVmZXJlbmNlIFVSST0iI0lEXzM5MjliNDAyLTAyYzEtNDBlYy1iMWVhLWIxMWYyMTYyZWMwOSI+PGRzaWc6VHJhbnNmb3Jtcz48ZHNpZzpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkc2lnOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHNpZzpUcmFuc2Zvcm1zPjxkc2lnOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkc2lnOkRpZ2VzdFZhbHVlPjBHdEZETGw2Vzg1dllwN3JtRFhadkNYcEVUOERhWVE4ZGk1UGsyT1VYSGc9PC9kc2lnOkRpZ2VzdFZhbHVlPjwvZHNpZzpSZWZlcmVuY2U+PC9kc2lnOlNpZ25lZEluZm8+PGRzaWc6U2lnbmF0dXJlVmFsdWU+am1GbmZpTEt3Y3NPS3hjVDVJbFpuaXdEMWZ2L3hST1FqQVBZNHZuNWlEU01TaVFFUkJBYXloeDRHNVhxMEczUnpqQ0gxUnp5anl0b004OG1Fencxd3pUclRsM1I5VGtwL2MzYnpKdHNSOE4va1N3TEU0U0RtVFo0QkJlcWZSYUZzbXFEMGE2VXFkdEZCMWtsY1FvcmtoVkxoTU40SmtoY2FMa2hjL0tKQWFMSHRTcVlEY3RlbmxSbkVmNXRtZ2lwTU9YOTF0VzZTME9jbXVsZlRNV3BMNCtwYW9LYTFVTnFGT1pBbGtlR3hzaGk2OHZSRjd3dGpMVTlJL1ppa01FbXcybUtGakFzRXFpaGRBMUFoNlVSS2ZYVWF4d1RiNi9JdXVXQWhQSUkrVmQ1NU10K1o0WCtSVS8xNUZjM1ZwT1RGblVzWmJudnpIS3RoaGM2eTNQdXlnPT08L2RzaWc6U2lnbmF0dXJlVmFsdWU+PGRzaWc6S2V5SW5mbz48ZHNpZzpLZXlOYW1lPnB6WGl5dFhUdlVWbHphOWhQLW1lN0RRc0tteW9GTEtKYUd4TkcwRDN1Sk08L2RzaWc6S2V5TmFtZT48ZHNpZzpYNTA5RGF0YT48ZHNpZzpYNTA5Q2VydGlmaWNhdGU+TUlJQ21UQ0NBWUVDQmdGMEM4YThvakFOQmdrcWhraUc5dzBCQVFzRkFEQVFNUTR3REFZRFZRUUREQVZ6ZFhCdmN6QWVGdzB5TURBNE1qQXhNakE0TWpkYUZ3MHpNREE0TWpBeE1qRXdNRGRhTUJBeERqQU1CZ05WQkFNTUJYTjFjRzl6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0a3ZvWHM3b0ZCYWVVUytJNkhhMVNGYno0b3dRUDRZWjBhZi91akRBajBCV2JIQmJHUVhiT3dTci9LdzZlRlB6eHoyQmZRVHZydGFBdEFvbzUvL1pTNlM4d3NHZlhud1Nra1h5TVlyeWUrT0pmc0NHSHYwRmZTYlN2ZnM2QWdwKzhFOUEvU2NCL2ZML2tNdnZWeHZyKzFMZVhyOEtjNFI1d295ZGFIdG80Q2pENml4N0piZmFxK1VWUzdSVDJURStUR0JqcGJjVWZ4Y2V5Z1ZhWDhsdDdzNDh6MGRjd2c4Z0pFazRNd0lWQ0M1aUE0NHRaUzNiWEJMQlVhWnN4NFZDNWRLKzRjNVBYTkRBRFdIWEtGMncrVTcwTW9CNXZTUjVSekFEV081c2xRZjJoM1Z0MkhiN2NGUGRoR0JvV3pyVGZtZHpSTStLaWk4YmZMeHJZcHoyV1FJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNmbmJDT0xWQmZSSDROcXhwUDZJZFlEREZDZ0g1WDR5MFZHck9sRndOdHljSlRiY2lSRk1PajJyelVhdEVzMDBXSDd1VWlQWDEzTEl1blFSaXFyZnRnMkorbTB5Szg0RDNVQjIyUlVQc01MSHRwYTZiSUpiak1pUzFXZWV6UGd5UFZndnY0Q1paSGlaVzNhcTcwSUtqVzM3Umt3TGdzUGd5RUNRQkI5Q2hQRHRFR0Fja2tEK0F0TGR1YVRxMTFtYzRtRkM1OTdCMmRwVTFRTzNPZ3VwZC9oL0tHSXUyVGlYR0tJWUx4eGtxb1hzc3dBcG9uU0ZtRThiOGgzWHJQNjZ0NFRiaGZhVTNOTy9sVWJ2M0RsMktrdFFrcWN3enpUZ3l0YnkrY1FSS29Ja24vcnB1KzdxbUZzdysxR2tKUW55VUExZHRCQ2RMOTRGeTJjSnJyVHpKeDwvZHNpZzpYNTA5Q2VydGlmaWNhdGU+PC9kc2lnOlg1MDlEYXRhPjxkc2lnOktleVZhbHVlPjxkc2lnOlJTQUtleVZhbHVlPjxkc2lnOk1vZHVsdXM+dGt2b1hzN29GQmFlVVMrSTZIYTFTRmJ6NG93UVA0WVowYWYvdWpEQWowQldiSEJiR1FYYk93U3IvS3c2ZUZQenh6MkJmUVR2cnRhQXRBb281Ly9aUzZTOHdzR2ZYbndTa2tYeU1ZcnllK09KZnNDR0h2MEZmU2JTdmZzNkFncCs4RTlBL1NjQi9mTC9rTXZ2Vnh2cisxTGVYcjhLYzRSNXdveWRhSHRvNENqRDZpeDdKYmZhcStVVlM3UlQyVEUrVEdCanBiY1VmeGNleWdWYVg4bHQ3czQ4ejBkY3dnOGdKRWs0TXdJVkNDNWlBNDR0WlMzYlhCTEJVYVpzeDRWQzVkSys0YzVQWE5EQURXSFhLRjJ3K1U3ME1vQjV2U1I1UnpBRFdPNXNsUWYyaDNWdDJIYjdjRlBkaEdCb1d6clRmbWR6Uk0rS2lpOGJmTHhyWXB6MldRPT08L2RzaWc6TW9kdWx1cz48ZHNpZzpFeHBvbmVudD5BUUFCPC9kc2lnOkV4cG9uZW50PjwvZHNpZzpSU0FLZXlWYWx1ZT48L2RzaWc6S2V5VmFsdWU+PC9kc2lnOktleUluZm8+PC9kc2lnOlNpZ25hdHVyZT48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48L3NhbWxwOkxvZ291dFJlc3BvbnNlPg==";
        SamlLogoutResponse response = client.decodeAndValidateSamlLogoutResponse(responseStr, "POST");
        boolean valid = response.isValid();
        System.out.println(valid);
    }

    /**
     * 测试获取 resource 目录下的文件资源
     */
    @Test
    public void getResource() throws IOException {

        String file = this.getClass().getResource("/saml-public-key-supos.crt").getFile();
        System.out.println(file);

        InputStream file2 = this.getClass().getClassLoader().getResourceAsStream("classpath:saml-public-key-supos.crt");
        InputStreamReader reader = new InputStreamReader(file2);
        System.out.println(file2);
    }
}