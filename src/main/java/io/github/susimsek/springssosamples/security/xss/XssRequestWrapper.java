package io.github.susimsek.springssosamples.security.xss;

import io.github.susimsek.springssosamples.utils.SanitizationUtil;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpMethod;
import org.springframework.util.FastByteArrayOutputStream;
import org.springframework.web.util.ContentCachingRequestWrapper;

public class XssRequestWrapper extends ContentCachingRequestWrapper {

    private final FastByteArrayOutputStream cachedContent;

    private final List<String> nonSanitizedHeaders;

    public XssRequestWrapper(HttpServletRequest request,
                             List<String> nonSanitizedHeaders) {
        super(request);
        this.nonSanitizedHeaders = nonSanitizedHeaders;
        int contentLength = request.getContentLength();
        this.cachedContent = contentLength > 0 ? new FastByteArrayOutputStream(contentLength) : new FastByteArrayOutputStream();
    }

    @Override
    public String getParameter(String name) {
        if (this.cachedContent.size() == 0 && this.isFormPost()) {
            this.writeRequestParametersToCachedContent();
        }
        return super.getParameter(name);
    }

    @Override
    public String[] getParameterValues(String name) {
        if (this.cachedContent.size() == 0 && this.isFormPost()) {
            this.writeRequestParametersToCachedContent();
        }

        return super.getParameterValues(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        if (this.cachedContent.size() == 0 && this.isFormPost()) {
            this.writeRequestParametersToCachedContent();
        }

        return super.getParameterMap();
    }

    @Override
    public byte[] getContentAsByteArray() {
        var content = this.cachedContent.toString(Charset.forName(this.getCharacterEncoding()));
        String sanitizedBodyString = SanitizationUtil.sanitizeJsonString(content);
       return sanitizedBodyString.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String getContentAsString() {
        var content = this.cachedContent.toString(Charset.forName(this.getCharacterEncoding()));
       return SanitizationUtil.sanitizeJsonString(content);
    }

    @Override
    public String getHeader(String name) {
        if (isNonSanitized(name)) {
            return super.getHeader(name);
        }
        String value = super.getHeader(name);
        return value != null ? SanitizationUtil.sanitizeInput(value) : null;
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (isNonSanitized(name)) {
            return super.getHeaders(name);
        }
        return Collections.enumeration(
            Collections.list(super.getHeaders(name)).stream()
                .map(SanitizationUtil::sanitizeInput)
                .toList()
        );
    }

    @Override
    public String getQueryString() {
        String queryString = super.getQueryString();
        return queryString != null ? SanitizationUtil.sanitizeInput(queryString) : null;
    }

    @Override
    public String getRequestURI() {
        String uri = super.getRequestURI();
        return uri != null ? SanitizationUtil.sanitizeInput(uri) : null;
    }

    @Override
    public StringBuffer getRequestURL() {
        StringBuffer requestURL = super.getRequestURL();
        return requestURL != null ? new StringBuffer(SanitizationUtil.sanitizeInput(requestURL.toString())) : null;
    }

    @Override
    public String getServletPath() {
        String servletPath = super.getServletPath();
        return servletPath != null ? SanitizationUtil.sanitizeInput(servletPath) : null;
    }

    @Override
    public String getPathInfo() {
        String pathInfo = super.getPathInfo();
        return pathInfo != null ? SanitizationUtil.sanitizeInput(pathInfo) : null;
    }

    private boolean isNonSanitized(String headerName) {
        return nonSanitizedHeaders.stream()
            .anyMatch(item -> item.equalsIgnoreCase(headerName));
    }

    private boolean isFormPost() {
        String contentType = this.getContentType();
        return contentType != null && contentType.contains("application/x-www-form-urlencoded") && HttpMethod.POST.matches(this.getMethod());
    }

    private void writeRequestParametersToCachedContent() {
        try {
            if (this.cachedContent.size() == 0) {
                String requestEncoding = this.getCharacterEncoding();
                Map<String, String[]> form = super.getParameterMap();
                Iterator<String> nameIterator = form.keySet().iterator();

                while(nameIterator.hasNext()) {
                    String name = nameIterator.next();
                    List<String> values = Arrays.asList(form.get(name));
                    Iterator<String> valueIterator = values.iterator();

                    while(valueIterator.hasNext()) {
                        String value = valueIterator.next();
                        this.cachedContent.write(URLEncoder.encode(name, requestEncoding).getBytes());
                        if (value != null) {
                            value = SanitizationUtil.sanitizeInput(value);
                            this.cachedContent.write(61);
                            this.cachedContent.write(URLEncoder.encode(value, requestEncoding).getBytes());
                            if (valueIterator.hasNext()) {
                                this.cachedContent.write(38);
                            }
                        }
                    }

                    if (nameIterator.hasNext()) {
                        this.cachedContent.write(38);
                    }
                }
            }

        } catch (IOException var8) {
            throw new IllegalStateException("Failed to write request parameters to cached content", var8);
        }
    }


}
