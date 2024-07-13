package io.github.susimsek.springssosamples.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
public class RequestMatcherConfig {

    private final MvcRequestMatcher.Builder mvc;

    public RequestMatcher[] staticResources() {
        return new MvcRequestMatcher[] {
            mvc.pattern("/index.html"),
            mvc.pattern("/webjars/**"),
            mvc.pattern("/*.js"),
            mvc.pattern("/*.css"),
            mvc.pattern("/*.ico"),
            mvc.pattern("/*.png"),
            mvc.pattern("/*.svg"),
            mvc.pattern("/*.webapp")
        };
    }

    public String[] staticResourcePaths() {
        return new String[] {
            "/webjars/**",
            "/*.js",
            "/*.css",
            "/*.ico",
            "/*.png",
            "/*.svg",
            "/*.webapp"
        };
    }

    public RequestMatcher[] swaggerPaths() {
        return new MvcRequestMatcher[] {
            mvc.pattern("/swagger-ui.html"),
            mvc.pattern("/swagger-ui/**"),
            mvc.pattern("/v3/api-docs/**")
        };
    }

    public String[] swaggerResourcePaths() {
        return new String[] {
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/v3/api-docs/**"
        };
    }

    public String[] actuatorEndpoints() {
        return new String[] {
            "/actuator/**"
        };
    }

    public RequestMatcher[] actuatorPaths() {
        return new MvcRequestMatcher[] {
            mvc.pattern("/actuator/**")
        };
    }
}