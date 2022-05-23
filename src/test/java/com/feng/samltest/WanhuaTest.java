package com.feng.samltest;

import com.feng.samltest.dto.SamlLogoutResponse;
import com.feng.samltest.exception.SamlException;
import com.feng.samltest.service.SamlClient;
import com.feng.samltest.util.SamlXmlTool;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static com.feng.samltest.constant.SamlBindingEnum.HTTP_POST;

@SpringBootTest
@RunWith(SpringRunner.class)
public class WanhuaTest {

    private static Reader getXml(String name) {
        return getXml(name, StandardCharsets.UTF_8);
    }

    private static Reader getXml(String name, Charset charset) {
        return new InputStreamReader(WanhuaTest.class.getResourceAsStream("/" + name), charset);
    }

    private InputStreamReader idpMetaDataConvert(String idpMetaDataString) {
        byte[] bytes = SamlXmlTool.base64decoder(idpMetaDataString);
        InputStream input = new ByteArrayInputStream(bytes);
        InputStreamReader inputStreamReader = new InputStreamReader(input, StandardCharsets.UTF_8);
        return inputStreamReader;
    }

    @Test
    public void test1() throws SamlException {
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.53:8080/inter-api/auth/v1/third/authorize/saml",
                "http://192.168.18.53:8080/inter-api/auth/v1/third/authorize/saml",
                idpMetaDataConvert(idpMetaDataString),
                HTTP_POST,
                null);

        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());


        SamlLogoutResponse response = client.decodeAndValidateSamlLogoutResponse(responseBase64, "POST");
        boolean valid = response.isValid();
        System.out.println(valid);
    }


    String responseBase64 = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDph" +
            "c3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9j" +
            "b2wiIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNp" +
            "PSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgRGVzdGluYXRpb249" +
            "Imh0dHA6Ly8xOTIuMTY4LjE4LjUzOjgwODAvaW50ZXItYXBpL2F1dGgvdjEvdGhpcmQvYXV0aG9y" +
            "aXplL3NhbWwiIElEPSJGSU1SU1BfZTQ5NjA4Y2YtMDE4MC0xMjE1LWEyNWItYjBlZjE1MjMxMWE3" +
            "IiBJblJlc3BvbnNlVG89InN1cG9zXzI5ZTEwMzdhLTY3NTMtNGQ0My04MTI3LWVlOTUzNDI1YWM3" +
            "MyIgSXNzdWVJbnN0YW50PSIyMDIyLTA1LTIxVDAzOjA3OjU5WiIgVmVyc2lvbj0iMi4wIj48c2Ft" +
            "bDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1h" +
            "dDplbnRpdHkiPmh0dHBzOi8vc2FtcWFzLndoY2hlbS5jb20vaXNhbW1tcHMvc3BzL3NhbWxtbXBz" +
            "L3NhbWwyMDwvc2FtbDpJc3N1ZXI+PHNhbWxwOlN0YXR1cz48c2FtbHA6U3RhdHVzQ29kZSBWYWx1" +
            "ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIj48L3NhbWxwOlN0" +
            "YXR1c0NvZGU+PC9zYW1scDpTdGF0dXM+PHNhbWw6QXNzZXJ0aW9uIElEPSJBc3NlcnRpb24tdXVp" +
            "ZGU0OTYwOGJlLTAxODAtMWQ2ZC04OTY5LWIwZWYxNTIzMTFhNyIgSXNzdWVJbnN0YW50PSIyMDIy" +
            "LTA1LTIxVDAzOjA3OjU5WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46" +
            "b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHBzOi8vc2Ft" +
            "cWFzLndoY2hlbS5jb20vaXNhbW1tcHMvc3BzL3NhbWxtbXBzL3NhbWwyMDwvc2FtbDpJc3N1ZXI+" +
            "PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2ln" +
            "IyIgSWQ9InV1aWRlNDk2MDhjMy0wMTgwLTE1MmYtYmE3My1iMGVmMTUyMzExYTciPjxkczpTaWdu" +
            "ZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53" +
            "My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNhbm9uaWNhbGl6YXRpb25NZXRob2Q+" +
            "PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQv" +
            "eG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiPjwvZHM6U2lnbmF0dXJlTWV0aG9kPjxkczpSZWZlcmVu" +
            "Y2UgVVJJPSIjQXNzZXJ0aW9uLXV1aWRlNDk2MDhiZS0wMTgwLTFkNmQtODk2OS1iMGVmMTUyMzEx" +
            "YTciPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3Lncz" +
            "Lm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSI+PC9kczpUcmFuc2Zvcm0+" +
            "PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4" +
            "Yy1jMTRuIyI+PHhjMTRuOkluY2x1c2l2ZU5hbWVzcGFjZXMgeG1sbnM6eGMxNG49Imh0dHA6Ly93" +
            "d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgUHJlZml4TGlzdD0ic2FtbCB4cyB4c2ki" +
            "PjwveGMxNG46SW5jbHVzaXZlTmFtZXNwYWNlcz48L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9y" +
            "bXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQv" +
            "eG1sZW5jI3NoYTI1NiI+PC9kczpEaWdlc3RNZXRob2Q+PGRzOkRpZ2VzdFZhbHVlPmxUWW5jaFd1" +
            "WWEzdFJ3c2lnSDNoWXIvQXdvQmZHWW5xNWhmUzlQV1hVazg9PC9kczpEaWdlc3RWYWx1ZT48L2Rz" +
            "OlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmdnbW1zc2FTK3FB" +
            "V2psNHhZbWlybzRMb2tLeEo2QnV4YUEveDlUNU9VUjlYOVluQ2JKaExyeU00alVlWmg4MkhPbFQw" +
            "UGhqRllnaHYvRXBDU3JUZG93dHhEaDlUT2QxU01CWVVobExWL1ZHcS9UTU5NYm9Jbys3MDRLQitY" +
            "b1d5clgybWNPcU5Sd2I5eStQeGVQWm5HUGVjUXg0Y0hDekVLaUlKSU8xT2FHND08L2RzOlNpZ25h" +
            "dHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1J" +
            "SUI1VENDQVU2Z0F3SUJBZ0lJUjV1MnVXaDFoS1l3RFFZSktvWklodmNOQVFFTEJRQXdFekVSTUE4" +
            "R0ExVUVBeE1JVlVGUVVVRlRNREV3SGhjTk1UZ3hNREE1TURNeU5USXlXaGNOTXpneE1ESTFNRE15" +
            "TlRJeVdqQVRNUkV3RHdZRFZRUURFd2hWUVZCUlFWTXdNVENCbnpBTkJna3Foa2lHOXcwQkFRRUZB" +
            "QU9CalFBd2dZa0NnWUVBd2N1c01mc3VCQnlXWkhZdkR6b1cvay9iR1lrRFo4OEwyOU9RcmMyTjBs" +
            "aE13Nm53L3hEWi9OdENhbSt3VkRvYVhEM1htdEpJVllWSVZhY1ZYK2NONUkwaTQySWRUQ0VNYUUr" +
            "QmROTDVVbkhDMnJMQTJZWmpUYUZOMVFRa1R5SlRKSC83ckg0TFdBeDRVSGxlQnJ0Y2cwdXljUHBZ" +
            "ODl3S3JsYkNjN0E3ZVdjQ0F3RUFBYU5DTUVBd0hRWURWUjBPQkJZRUZQbjBIUmJCYndOWWRGd0pq" +
            "N1FEVHdzeTQrdzRNQjhHQTFVZEl3UVlNQmFBRlBuMEhSYkJid05ZZEZ3Smo3UURUd3N5NCt3NE1B" +
            "MEdDU3FHU0liM0RRRUJDd1VBQTRHQkFDaFgrVG5MVVFTd3pGbmlmTG95aG50cTZ6bWs2SVBRdkE5" +
            "UERRQjJFV1ZoYlRWaDh6UVBVbEdhUlZKRnpkREFLVFpxMU9pNFlKNEJRV3ZLb2plR3RhR3dnaGk3" +
            "TlZYWmtQQjBZQnNFanhpbTh0VHpCTGxHN3RXeHU2YUwvK2E2RVRVeTZreE1vOW9FN0lJMnhYUHQw" +
            "enJ1TDJsMll0dmpGOHp2RXlHbnU0WDU8L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRh" +
            "PjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBG" +
            "b3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPmp5Y29uZzwvc2Ft" +
            "bDpOYW1lSUQ+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1l" +
            "czp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIElu" +
            "UmVzcG9uc2VUbz0ic3Vwb3NfMjllMTAzN2EtNjc1My00ZDQzLTgxMjctZWU5NTM0MjVhYzczIiBO" +
            "b3RPbk9yQWZ0ZXI9IjIwMjItMDUtMjFUMDM6MTI6NTlaIiBSZWNpcGllbnQ9Imh0dHA6Ly8xOTIu" +
            "MTY4LjE4LjUzOjgwODAvaW50ZXItYXBpL2F1dGgvdjEvdGhpcmQvYXV0aG9yaXplL3NhbWwiPjwv" +
            "c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YT48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj48" +
            "L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyMi0wNS0yMVQwMzow" +
            "Mjo1OVoiIE5vdE9uT3JBZnRlcj0iMjAyMi0wNS0yMVQwMzoxMjo1OVoiPjxzYW1sOkF1ZGllbmNl" +
            "UmVzdHJpY3Rpb24+PHNhbWw6QXVkaWVuY2U+aHR0cDovLzE5Mi4xNjguMTguNTM6ODA4MC9pbnRl" +
            "ci1hcGkvYXV0aC92MS90aGlyZC9hdXRob3JpemUvc2FtbDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6" +
            "QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVu" +
            "dCBBdXRobkluc3RhbnQ9IjIwMjItMDUtMjFUMDM6MDc6NTlaIiBTZXNzaW9uSW5kZXg9InV1aWRl" +
            "NDk2MDc5Ny0wMTgwLTFiZDAtYTBkMC1iMGVmMTUyMzExYTciIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9" +
            "IjIwMjItMDUtMjFUMDQ6MDc6NTlaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250" +
            "ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dv" +
            "cmQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6" +
            "QXV0aG5TdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBO" +
            "YW1lPSJlbWFpbEFkZHJlc3MiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFj" +
            "Y2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmp5" +
            "Y29uZ0B3aGNoZW0uY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNh" +
            "bWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0FVVEhfTUVUSE9EIiBOYW1lRm9ybWF0PSJ1cm46" +
            "aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4" +
            "c2k6dHlwZT0ieHM6c3RyaW5nIj5sdHBhPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRy" +
            "aWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InRhZ3ZhbHVlX3VzZXJfc2Vzc2lvbl9pZCIgTmFt" +
            "ZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0" +
            "cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+VlVGUVVVRlRNREV0ZDJWaWMyVmhiREVB" +
            "X1lvaFhqd0FBQUFJQUFBQTBqMWVJWW1pekJqeWZmd0FBWnpka2JHeHJTV1ZaZEc5cVdXZDROMUJZ" +
            "Um5SRmRFMXRNMjVXVmxabWNWTXZibGQ2VmsxV2JuTnlORWh4Vm1wdWVXbFpQUT09OmRlZmF1bHQ8" +
            "L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFt" +
            "ZT0iQVpOX0NSRURfUFJJTkNJUEFMX1VVSUQiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRG" +
            "SU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpz" +
            "dHJpbmciPjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMDwvc2FtbDpBdHRyaWJ1" +
            "dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9R" +
            "T1BfSU5GTyIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdl" +
            "ciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+U1NLOiBUTFNWMTI6" +
            "IDlDPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRl" +
            "IE5hbWU9IkFaTl9DUkVEX1BSSU5DSVBBTF9ET01BSU4iIE5hbWVGb3JtYXQ9InVybjppYm06bmFt" +
            "ZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBl" +
            "PSJ4czpzdHJpbmciPkRlZmF1bHQ8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0" +
            "ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVVUSEVOVElDQVRJT05fTEVWRUwiIE5hbWVGb3JtYXQ9" +
            "InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZh" +
            "bHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjA8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0" +
            "dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfUkVHSVNUUllfSUQiIE5hbWVG" +
            "b3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJp" +
            "YnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVpZD1qeWNvbmcsY249dXNlcnMsZGM9d2Fu" +
            "aHVhLGRjPWNvbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0" +
            "dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9ORVRXT1JLX0FERFJFU1NfU1RSIiBOYW1lRm9ybWF0PSJ1" +
            "cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1" +
            "ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4xMC4xMC4yMjkuMTI1PC9zYW1sOkF0dHJpYnV0ZVZhbHVl" +
            "Pjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Im1vYmlsZU51bWJlciIgTmFt" +
            "ZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0" +
            "cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+MTgxNTM1MTk3MTc8L3NhbWw6QXR0cmli" +
            "dXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURf" +
            "QVVUSE5NRUNIX0lORk8iIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vz" +
            "c21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPkxUUEEg" +
            "VG9rZW48L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1" +
            "dGUgTmFtZT0iQVpOX0NSRURfUFJJTkNJUEFMX05BTUUiIE5hbWVGb3JtYXQ9InVybjppYm06bmFt" +
            "ZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBl" +
            "PSJ4czpzdHJpbmciPmp5Y29uZzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRl" +
            "PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9JUF9GQU1JTFkiIE5hbWVGb3JtYXQ9InVy" +
            "bjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVl" +
            "IHhzaTp0eXBlPSJ4czpzdHJpbmciPkFGX0lORVQ8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1s" +
            "OkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idGFndmFsdWVfc2Vzc2lvbl9pbmRleCIg" +
            "TmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6" +
            "QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+MzgwNzVjYzYtZDhiMy0xMWVjLWJk" +
            "M2UtMDA1MDU2OTEzY2Y5PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNh" +
            "bWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX05FVFdPUktfQUREUkVTU19CSU4iIE5hbWVGb3Jt" +
            "YXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0" +
            "ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjB4MGEwYWU1N2Q8L3NhbWw6QXR0cmlidXRlVmFs" +
            "dWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfQlJPV1NF" +
            "Ul9JTkZPIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2Vy" +
            "Ij48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5Nb3ppbGxhLzUuMCAo" +
            "V2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBs" +
            "aWtlIEdlY2tvKSBDaHJvbWUvMTAxLjAuMC4wIFNhZmFyaS81MzcuMzY8L3NhbWw6QXR0cmlidXRl" +
            "VmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfVkVS" +
            "U0lPTiIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+" +
            "PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+MHgwMDAwMDkwNTwvc2Ft" +
            "bDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJT" +
            "TVNfU0VTU0lPTl9SRUFMTSIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNj" +
            "ZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+SVNB" +
            "TS1EaXN0cmlidXRlZC1TZXNzaW9uLUNhY2hlPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpB" +
            "dHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX01FQ0hfSUQiIE5hbWVGb3Jt" +
            "YXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0" +
            "ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPklWX0xEQVBfVjMuMDwvc2FtbDpBdHRyaWJ1dGVW" +
            "YWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9BVVRI" +
            "Wk5fSUQiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIi" +
            "PjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVpZD1qeWNvbmcsY249" +
            "dXNlcnMsZGM9d2FuaHVhLGRjPWNvbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmli" +
            "dXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ0YWd2YWx1ZV9tYXhfY29uY3VycmVudF93ZWJfc2Vz" +
            "c2lvbnMiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIi" +
            "PjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVuc2V0PC9zYW1sOkF0" +
            "dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InRhZ3Zh" +
            "bHVlX2xvZ2luX3VzZXJfbmFtZSIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6" +
            "YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+" +
            "anljb25nPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYW1sOkF0dHJp" +
            "YnV0ZVN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+";


    String idpMetaDataString = "PG1kOkVudGl0eURlc2NyaXB0b3IgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDptZXRhZGF0YSIgeG1sbnM6bWQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDptZXRhZGF0YSIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiIGVudGl0eUlEPSJodHRwOi8vMTkyLjE2OC4xOC41Mzo4MDgwL2F1dGgvcmVhbG1zL2R0Ij48bWQ6SURQU1NPRGVzY3JpcHRvciBXYW50QXV0aG5SZXF1ZXN0c1NpZ25lZD0idHJ1ZSIgcHJvdG9jb2xTdXBwb3J0RW51bWVyYXRpb249InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+PG1kOktleURlc2NyaXB0b3IgdXNlPSJzaWduaW5nIj48ZHM6S2V5SW5mbz48ZHM6S2V5TmFtZT5welhpeXRYVHZVVmx6YTloUC1tZTdEUXNLbXlvRkxLSmFHeE5HMEQzdUpNPC9kczpLZXlOYW1lPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUNtVENDQVlFQ0JnRjBDOGE4b2pBTkJna3Foa2lHOXcwQkFRc0ZBREFRTVE0d0RBWURWUVFEREFWemRYQnZjekFlRncweU1EQTRNakF4TWpBNE1qZGFGdzB6TURBNE1qQXhNakV3TURkYU1CQXhEakFNQmdOVkJBTU1CWE4xY0c5ek1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdGt2b1hzN29GQmFlVVMrSTZIYTFTRmJ6NG93UVA0WVowYWYvdWpEQWowQldiSEJiR1FYYk93U3IvS3c2ZUZQenh6MkJmUVR2cnRhQXRBb281Ly9aUzZTOHdzR2ZYbndTa2tYeU1ZcnllK09KZnNDR0h2MEZmU2JTdmZzNkFncCs4RTlBL1NjQi9mTC9rTXZ2Vnh2cisxTGVYcjhLYzRSNXdveWRhSHRvNENqRDZpeDdKYmZhcStVVlM3UlQyVEUrVEdCanBiY1VmeGNleWdWYVg4bHQ3czQ4ejBkY3dnOGdKRWs0TXdJVkNDNWlBNDR0WlMzYlhCTEJVYVpzeDRWQzVkSys0YzVQWE5EQURXSFhLRjJ3K1U3ME1vQjV2U1I1UnpBRFdPNXNsUWYyaDNWdDJIYjdjRlBkaEdCb1d6clRmbWR6Uk0rS2lpOGJmTHhyWXB6MldRSURBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFDZm5iQ09MVkJmUkg0TnF4cFA2SWRZRERGQ2dINVg0eTBWR3JPbEZ3TnR5Y0pUYmNpUkZNT2oycnpVYXRFczAwV0g3dVVpUFgxM0xJdW5RUmlxcmZ0ZzJKK20weUs4NEQzVUIyMlJVUHNNTEh0cGE2YklKYmpNaVMxV2VlelBneVBWZ3Z2NENaWkhpWlczYXE3MElLalczN1Jrd0xnc1BneUVDUUJCOUNoUER0RUdBY2trRCtBdExkdWFUcTExbWM0bUZDNTk3QjJkcFUxUU8zT2d1cGQvaC9LR0l1MlRpWEdLSVlMeHhrcW9Yc3N3QXBvblNGbUU4YjhoM1hyUDY2dDRUYmhmYVUzTk8vbFVidjNEbDJLa3RRa3Fjd3p6VGd5dGJ5K2NRUktvSWtuL3JwdSs3cW1Gc3crMUdrSlFueVVBMWR0QkNkTDk0RnkyY0pyclR6Sng8L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L21kOktleURlc2NyaXB0b3I+PG1kOkFydGlmYWN0UmVzb2x1dGlvblNlcnZpY2UgQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOlNPQVAiIExvY2F0aW9uPSJodHRwOi8vMTkyLjE2OC4xOC41Mzo4MDgwL2F1dGgvcmVhbG1zL2R0L3Byb3RvY29sL3NhbWwvcmVzb2x2ZSIgaW5kZXg9IjAiLz48bWQ6U2luZ2xlTG9nb3V0U2VydmljZSBCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBMb2NhdGlvbj0iaHR0cDovLzE5Mi4xNjguMTguNTM6ODA4MC9hdXRoL3JlYWxtcy9kdC9wcm90b2NvbC9zYW1sIi8+PG1kOlNpbmdsZUxvZ291dFNlcnZpY2UgQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUmVkaXJlY3QiIExvY2F0aW9uPSJodHRwOi8vMTkyLjE2OC4xOC41Mzo4MDgwL2F1dGgvcmVhbG1zL2R0L3Byb3RvY29sL3NhbWwiLz48bWQ6U2luZ2xlTG9nb3V0U2VydmljZSBCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1BcnRpZmFjdCIgTG9jYXRpb249Imh0dHA6Ly8xOTIuMTY4LjE4LjUzOjgwODAvYXV0aC9yZWFsbXMvZHQvcHJvdG9jb2wvc2FtbCIvPjxtZDpOYW1lSURGb3JtYXQ+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6cGVyc2lzdGVudDwvbWQ6TmFtZUlERm9ybWF0PjxtZDpOYW1lSURGb3JtYXQ+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50PC9tZDpOYW1lSURGb3JtYXQ+PG1kOk5hbWVJREZvcm1hdD51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDp1bnNwZWNpZmllZDwvbWQ6TmFtZUlERm9ybWF0PjxtZDpOYW1lSURGb3JtYXQ+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzPC9tZDpOYW1lSURGb3JtYXQ+PG1kOlNpbmdsZVNpZ25PblNlcnZpY2UgQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCIgTG9jYXRpb249Imh0dHA6Ly8xOTIuMTY4LjE4LjUzOjgwODAvYXV0aC9yZWFsbXMvZHQvcHJvdG9jb2wvc2FtbCIvPjxtZDpTaW5nbGVTaWduT25TZXJ2aWNlIEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVJlZGlyZWN0IiBMb2NhdGlvbj0iaHR0cDovLzE5Mi4xNjguMTguNTM6ODA4MC9hdXRoL3JlYWxtcy9kdC9wcm90b2NvbC9zYW1sIi8+PG1kOlNpbmdsZVNpZ25PblNlcnZpY2UgQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOlNPQVAiIExvY2F0aW9uPSJodHRwOi8vMTkyLjE2OC4xOC41Mzo4MDgwL2F1dGgvcmVhbG1zL2R0L3Byb3RvY29sL3NhbWwiLz48bWQ6U2luZ2xlU2lnbk9uU2VydmljZSBCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1BcnRpZmFjdCIgTG9jYXRpb249Imh0dHA6Ly8xOTIuMTY4LjE4LjUzOjgwODAvYXV0aC9yZWFsbXMvZHQvcHJvdG9jb2wvc2FtbCIvPjwvbWQ6SURQU1NPRGVzY3JpcHRvcj48L21kOkVudGl0eURlc2NyaXB0b3I+";
}
