package io.github.susimsek.springauthorizationserver.config;

import io.github.susimsek.springauthorizationserver.i18n.DomainMessageSource;
import io.github.susimsek.springauthorizationserver.i18n.ParameterMessageSource;
import io.github.susimsek.springauthorizationserver.service.MessageService;
import jakarta.validation.MessageInterpolator;
import jakarta.validation.Validator;
import java.time.Duration;
import java.util.Locale;
import org.hibernate.validator.messageinterpolation.ResourceBundleMessageInterpolator;
import org.springframework.boot.autoconfigure.context.MessageSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.context.MessageSourceProperties;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.util.StringUtils;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

@Configuration(proxyBeanMethods = false)
@Import(MessageSourceAutoConfiguration.class)
public class LocaleConfig {

    public static final Locale TR = Locale.of("tr", "TR");
    public static final Locale EN = Locale.ENGLISH;
    public static final String COOKIE_NAME = "lang";
    public static final String PARAM_NAME = "lang";

    @Bean
    public LocaleResolver localeResolver(WebProperties webProperties) {
        CookieLocaleResolver cookieLocaleResolver = new CookieLocaleResolver(COOKIE_NAME);
        cookieLocaleResolver.setDefaultLocale(webProperties.getLocale());
        cookieLocaleResolver.setCookieMaxAge(Duration.ofDays(365));
        return cookieLocaleResolver;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
        localeChangeInterceptor.setParamName(PARAM_NAME);
        return localeChangeInterceptor;
    }

    @Bean
    public MessageInterpolator messageInterpolator(Validator validator) {
        if (validator instanceof LocalValidatorFactoryBean localValidatorFactoryBean) {
            return localValidatorFactoryBean.getMessageInterpolator();
        }
        return new ResourceBundleMessageInterpolator();
    }

    @Bean
    public ParameterMessageSource messageSource(MessageSourceProperties properties,
                                                MessageService messageService) {
        DomainMessageSource messageSource = new DomainMessageSource(messageService);
        if (StringUtils.hasText(properties.getBasename())) {
            messageSource.setBasenames(StringUtils
                .commaDelimitedListToStringArray(StringUtils.trimAllWhitespace(properties.getBasename())));
        }
        if (properties.getEncoding() != null) {
            messageSource.setDefaultEncoding(properties.getEncoding().name());
        }
        messageSource.setFallbackToSystemLocale(properties.isFallbackToSystemLocale());
        Duration cacheDuration = properties.getCacheDuration();
        if (cacheDuration != null) {
            messageSource.setCacheMillis(cacheDuration.toMillis());
        }
        messageSource.setAlwaysUseMessageFormat(properties.isAlwaysUseMessageFormat());
        messageSource.setUseCodeAsDefaultMessage(properties.isUseCodeAsDefaultMessage());
        return messageSource;
    }
}
