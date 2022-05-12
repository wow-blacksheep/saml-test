package com.feng.samltest.browser;

import org.apache.commons.lang.StringEscapeUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.Map;

public class BrowserUtils {
    /**
     * 呈现一个 HTTP 响应，该响应将导致浏览器将指定的值 POST 到一个 url。
     *
     * @param url    执行 POST 的 url.
     * @param values 要包含在 POST 中的值.
     */
    public static void postUsingBrowser(String url, HttpServletResponse response, Map<String, String> values) throws IOException {

        response.setContentType("text/html");
        @SuppressWarnings("resource")
        Writer writer = response.getWriter();
        writer.write(
                "<html><head></head><body><form id='TheForm' action='"
                        + StringEscapeUtils.escapeHtml(url)
                        + "' method='POST'>");

        for (String key : values.keySet()) {
            String encodedKey = StringEscapeUtils.escapeHtml(key);
            String encodedValue = StringEscapeUtils.escapeHtml(values.get(key));
            writer.write(
                    "<input type='hidden' id='"
                            + encodedKey
                            + "' name='"
                            + encodedKey
                            + "' value='"
                            + encodedValue
                            + "'/>");
        }

        writer.write(
                "</form><script type='text/javascript'>document.getElementById('TheForm').submit();</script></body></html>");
        writer.flush();

        response.setHeader("Cache-Control", "no-cache, no-store");
        response.setHeader("Pragma", "no-cache");
    }
}
