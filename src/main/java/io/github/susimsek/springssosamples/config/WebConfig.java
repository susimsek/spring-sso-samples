package io.github.susimsek.springssosamples.config;

import static io.github.susimsek.springssosamples.constant.Constants.SPRING_PROFILE_DEVELOPMENT;

import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import java.lang.reflect.InvocationTargetException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
@Slf4j
public class WebConfig implements ServletContextInitializer, WebMvcConfigurer {

    private final LocaleChangeInterceptor localeChangeInterceptor;
    private final Environment env;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor);
    }

    @Override
    public void onStartup(ServletContext servletContext) {
        if (env.getActiveProfiles().length != 0) {
            log.info("Web application configuration, using profiles: {}", (Object[]) env.getActiveProfiles());
        }

        if (env.acceptsProfiles(Profiles.of(SPRING_PROFILE_DEVELOPMENT))) {
            initH2Console(servletContext);
        }
        log.info("Web application fully configured");
    }


    public void initH2Console(ServletContext servletContext) {
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            Class<?> servletClass = Class.forName("org.h2.server.web.JakartaWebServlet", true, loader);
            Servlet servlet = (Servlet) servletClass.getDeclaredConstructor().newInstance();
            ServletRegistration.Dynamic registration = servletContext.addServlet("h2-console", servlet);
            registration.addMapping("/h2-console/*");
            registration.setInitParameter("webAllowOthers", "true");
            registration.setInitParameter("webPort", "8092");
            registration.setInitParameter("webSSL", "false");
            registration.setLoadOnStartup(1);
        } catch (ClassNotFoundException | LinkageError | NoSuchMethodException
                 | IllegalAccessException | InstantiationException |
                 InvocationTargetException e) {
            log.error("Failed to initialize H2 console", e);
            throw new IllegalStateException("Failed to initialize H2 console", e);
        }
    }
}
