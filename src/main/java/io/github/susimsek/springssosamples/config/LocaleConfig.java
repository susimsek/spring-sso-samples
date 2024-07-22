package io.github.susimsek.springssosamples.config;

import io.github.susimsek.springssosamples.i18n.SimpleParameterMessageSource;
import io.github.susimsek.springssosamples.i18n.ParameterMessageSource;
import io.github.susimsek.springssosamples.service.MessageService;
import jakarta.validation.MessageInterpolator;
import jakarta.validation.Validator;
import org.hibernate.validator.messageinterpolation.ResourceBundleMessageInterpolator;
import org.springframework.boot.autoconfigure.context.MessageSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.context.MessageSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.util.StringUtils;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import java.time.Duration;
import java.util.Locale;

@Configuration(proxyBeanMethods = false)
@Import(MessageSourceAutoConfiguration.class)
public class LocaleConfig {

    @Bean
    public LocaleResolver localeResolver() {
        CookieLocaleResolver cookieLocaleResolver = new CookieLocaleResolver();
        cookieLocaleResolver.setDefaultLocale(Locale.ENGLISH);
        cookieLocaleResolver.setCookieMaxAge(Duration.ofDays(365));
        return cookieLocaleResolver;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
        localeChangeInterceptor.setParamName("lang");
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
        SimpleParameterMessageSource messageSource = new SimpleParameterMessageSource(messageService);
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
