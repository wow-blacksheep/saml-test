package com.feng.samltest;

import com.feng.samltest.constant.SamlBindingEnum;
import com.feng.samltest.dto.SamlResponse;
import com.feng.samltest.exception.SamlException;
import com.feng.samltest.service.SamlClient;
import com.feng.samltest.sp.SettingsBuilder;
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
import static com.feng.samltest.constant.SamlBindingEnum.HTTP_POST;
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
                getXml("federation_metadata_new.xml"),
                HTTP_POST,
                null);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());
        String samlRequest = client.getSamlRequest(UN_SPECIFIED);
        System.out.println(samlRequest);
        //todo MyController.login

        //万华  jycong  密码1
    }

    @Test
    public void decodeAutheResponse() throws SamlException {
        //todo MyController.authorizeByPost
        //todo MyController.authorizeByGet

        String s = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgRGVzdGluYXRpb249Imh0dHA6Ly8xOTIuMTY4LjE4LjEyOTo4MDgwL2ludGVyLWFwaS9hdXRoL3YxL3RoaXJkL2F1dGhvcml6ZSIgSUQ9IkZJTVJTUF9iNzQ4MDZkNS0wMTgwLTE2YjgtYTcyYi1iMGVmMTUyMzExYTciIEluUmVzcG9uc2VUbz0ic3Vwb3NfNzIwOTJjNmItYWI3YS00ZDk5LWFjZjgtOGZiNDVjYzNkYzI5IiBJc3N1ZUluc3RhbnQ9IjIwMjItMDUtMTJUMDc6NTk6NTJaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly9zYW1xYXMud2hjaGVtLmNvbS9pc2FtbW1wcy9zcHMvc2FtbG1tcHMvc2FtbDIwPC9zYW1sOklzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiPjwvc2FtbHA6U3RhdHVzQ29kZT48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24gSUQ9IkFzc2VydGlvbi11dWlkYjc0ODA2YzQtMDE4MC0xNmQ3LWEwZWQtYjBlZjE1MjMxMWE3IiBJc3N1ZUluc3RhbnQ9IjIwMjItMDUtMTJUMDc6NTk6NTJaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly9zYW1xYXMud2hjaGVtLmNvbS9pc2FtbW1wcy9zcHMvc2FtbG1tcHMvc2FtbDIwPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBJZD0idXVpZGI3NDgwNmM5LTAxODAtMWMzNi1hNjViLWIwZWYxNTIzMTFhNyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjwvZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZD48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiI+PC9kczpTaWduYXR1cmVNZXRob2Q+PGRzOlJlZmVyZW5jZSBVUkk9IiNBc3NlcnRpb24tdXVpZGI3NDgwNmM0LTAxODAtMTZkNy1hMGVkLWIwZWYxNTIzMTFhNyI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOlRyYW5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48eGMxNG46SW5jbHVzaXZlTmFtZXNwYWNlcyB4bWxuczp4YzE0bj0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIiBQcmVmaXhMaXN0PSJzYW1sIHhzIHhzaSI+PC94YzE0bjpJbmNsdXNpdmVOYW1lc3BhY2VzPjwvZHM6VHJhbnNmb3JtPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ij48L2RzOkRpZ2VzdE1ldGhvZD48ZHM6RGlnZXN0VmFsdWU+U3I5VUd0QURzd1RTMXJZbHVoRmJmTEFhczd0K2lwL2ZMT2F4d1I2VU5mRT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+T3cxcnNPTU9MOU80S04wbUFxSnJaWFlWY2dzSUZ4Qml0cVAvemF1ZEtGR1c0SEN4b2E5dm5ZbDdNejBPSnRLamc1VUVnY01HLzJjQkx1dkxDeVJnWEFsekk3ZXp3ZmxaZ0l4VC82YzBXT1VaVlQ4bDBWcHNWZk92UmJOQm5JdE9rTGlwbVB1WUt6a0ZYUHhHMk1VWG5TcWQ5bDR1UjBmVXVQRlVzK3Z4bFZrPTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJQjVUQ0NBVTZnQXdJQkFnSUlSNXUydVdoMWhLWXdEUVlKS29aSWh2Y05BUUVMQlFBd0V6RVJNQThHQTFVRUF4TUlWVUZRVVVGVE1ERXdIaGNOTVRneE1EQTVNRE15TlRJeVdoY05Nemd4TURJMU1ETXlOVEl5V2pBVE1SRXdEd1lEVlFRREV3aFZRVkJSUVZNd01UQ0JuekFOQmdrcWhraUc5dzBCQVFFRkFBT0JqUUF3Z1lrQ2dZRUF3Y3VzTWZzdUJCeVdaSFl2RHpvVy9rL2JHWWtEWjg4TDI5T1FyYzJOMGxoTXc2bncveERaL050Q2FtK3dWRG9hWEQzWG10SklWWVZJVmFjVlgrY041STBpNDJJZFRDRU1hRStCZE5MNVVuSEMyckxBMllaalRhRk4xUVFrVHlKVEpILzdySDRMV0F4NFVIbGVCcnRjZzB1eWNQcFk4OXdLcmxiQ2M3QTdlV2NDQXdFQUFhTkNNRUF3SFFZRFZSME9CQllFRlBuMEhSYkJid05ZZEZ3Smo3UURUd3N5NCt3NE1COEdBMVVkSXdRWU1CYUFGUG4wSFJiQmJ3TllkRndKajdRRFR3c3k0K3c0TUEwR0NTcUdTSWIzRFFFQkN3VUFBNEdCQUNoWCtUbkxVUVN3ekZuaWZMb3lobnRxNnptazZJUFF2QTlQRFFCMkVXVmhiVFZoOHpRUFVsR2FSVkpGemREQUtUWnExT2k0WUo0QlFXdktvamVHdGFHd2doaTdOVlhaa1BCMFlCc0VqeGltOHRUekJMbEc3dFd4dTZhTC8rYTZFVFV5Nmt4TW85b0U3SUkyeFhQdDB6cnVMMmwyWXR2akY4enZFeUdudTRYNTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+anljb25nPC9zYW1sOk5hbWVJRD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJzdXBvc183MjA5MmM2Yi1hYjdhLTRkOTktYWNmOC04ZmI0NWNjM2RjMjkiIE5vdE9uT3JBZnRlcj0iMjAyMi0wNS0xMlQwODowNDo1MloiIFJlY2lwaWVudD0iaHR0cDovLzE5Mi4xNjguMTguMTI5OjgwODAvaW50ZXItYXBpL2F1dGgvdjEvdGhpcmQvYXV0aG9yaXplIj48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGE+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjItMDUtMTJUMDc6NTQ6NTJaIiBOb3RPbk9yQWZ0ZXI9IjIwMjItMDUtMTJUMDg6MDQ6NTJaIj48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPmh0dHA6Ly8xOTIuMTY4LjE4LjEyOTo4MDgwL3h4eDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjItMDUtMTJUMDc6NTk6NTJaIiBTZXNzaW9uSW5kZXg9InV1aWRiNzQ2MGNhNy0wMTgwLTFhZWYtYTNjZC1iMGVmMTUyMzExYTciIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMjItMDUtMTJUMDg6NTk6NTJaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJlbWFpbEFkZHJlc3MiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmp5Y29uZ0B3aGNoZW0uY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0FVVEhfTUVUSE9EIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5wYXNzd29yZDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ0YWd2YWx1ZV91c2VyX3Nlc3Npb25faWQiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPlZVRlFVVUZUTURFdGQyVmljMlZoYkRFQV9ZbnkrZUFBQUFBSUFBQUEwZUw1OFltaktKVGlmZndBQVREQnNNakl6WkN0bFowbERWV1l3YkU5NVlVVXpRekp5TDFKYWJXSk9ValYyTTNWMGFqQjRkVlZaT1dOMlNWZFBZWEZKUFE9PTpkZWZhdWx0PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX1BSSU5DSVBBTF9VVUlEIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4wMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDA8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfUU9QX0lORk8iIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPlNTSzogVExTVjEyOiA5Qzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9QUklOQ0lQQUxfRE9NQUlOIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5EZWZhdWx0PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFVVEhFTlRJQ0FUSU9OX0xFVkVMIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4xPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX1JFR0lTVFJZX0lEIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj51aWQ9anljb25nLGNuPXVzZXJzLGRjPXdhbmh1YSxkYz1jb208L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfTkVUV09SS19BRERSRVNTX1NUUiIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+MTAuMTAuMjI5LjEyNTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJtb2JpbGVOdW1iZXIiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjE4MTUzNTE5NzE3PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0FVVEhOTUVDSF9JTkZPIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5MREFQIFJlZ2lzdHJ5PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX1BSSU5DSVBBTF9OQU1FIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5qeWNvbmc8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfSVBfRkFNSUxZIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5BRl9JTkVUPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InRhZ3ZhbHVlX3Nlc3Npb25faW5kZXgiIE5hbWVGb3JtYXQ9InVybjppYm06bmFtZXM6SVRGSU06NS4xOmFjY2Vzc21hbmFnZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjMzY2MwOGQyLWQxYzktMTFlYy1iZDNlLTAwNTA1NjkxM2NmOTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9ORVRXT1JLX0FERFJFU1NfQklOIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4weDBhMGFlNTdkPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0JST1dTRVJfSU5GTyIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMS4wLjQ5NTEuNTQgU2FmYXJpLzUzNy4zNjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJBWk5fQ1JFRF9WRVJTSU9OIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4weDAwMDAwOTA1PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlNNU19TRVNTSU9OX1JFQUxNIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5JU0FNLURpc3RyaWJ1dGVkLVNlc3Npb24tQ2FjaGU8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iQVpOX0NSRURfTUVDSF9JRCIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+SVZfTERBUF9WMy4wPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkFaTl9DUkVEX0FVVEhaTl9JRCIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dWlkPWp5Y29uZyxjbj11c2VycyxkYz13YW5odWEsZGM9Y29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InRhZ3ZhbHVlX21heF9jb25jdXJyZW50X3dlYl9zZXNzaW9ucyIgTmFtZUZvcm1hdD0idXJuOmlibTpuYW1lczpJVEZJTTo1LjE6YWNjZXNzbWFuYWdlciI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dW5zZXQ8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idGFndmFsdWVfbG9naW5fdXNlcl9uYW1lIiBOYW1lRm9ybWF0PSJ1cm46aWJtOm5hbWVzOklURklNOjUuMTphY2Nlc3NtYW5hZ2VyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5qeWNvbmc8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L3NhbWw6QXR0cmlidXRlU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=";
        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx", "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize", getXml("federation_metadata_new.xml"), HTTP_POST);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());
        SamlResponse post = client.decodeAndValidateSamlResponse(s, "POST");
        String nameID = post.getNameID();
        System.out.println(nameID);
    }

    @Test
    public void logoutRequest() throws SamlException {
        // 万华 注销地址：https://samuat.whchem.com/logout.html


        SamlClient client = SamlClient.fromMetadata(
                "http://192.168.18.129:8080/xxx", "http://192.168.18.129:8080/inter-api/auth/logout", getXml("federation_metadata_new.xml"), HTTP_POST);
        client.setSPKeys(
                this.getClass().getResource("/saml-public-key-supos.crt").getFile(),
                this.getClass().getResource("/saml-private-key-supos.pk8").getFile());
        String samlRequest = client.getLogoutRequest("jycong");
        System.out.println(samlRequest);
    }


    @Test
    public void generateMetaData() throws Exception {
        Map<String, Object> samlData = new LinkedHashMap<>();
        samlData.put(SP_ENTITYID_PROPERTY_KEY, "http://192.168.18.129:8080/xxx");
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, "http://192.168.18.129:8080/inter-api/auth/v1/third/authorize");
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, "http://192.168.18.129:8080/inter-api/auth/logout");
        samlData.put(SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY, HTTP_POST.getFormat());
        samlData.put(SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, HTTP_POST.getFormat());
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

        String spMetadata = new SettingsBuilder()
                .setSamlData(samlData)
                .build()
                .getSPMetadata();
        System.out.println(spMetadata);
    }
}
