package io.github.susimsek.springauthorizationserver.aot;


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import io.github.susimsek.springauthorizationserver.dto.LoginForm;
import io.github.susimsek.springauthorizationserver.exception.Violation;
import io.github.susimsek.springauthorizationserver.logging.annotation.Loggable;
import jakarta.servlet.http.Cookie;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import liquibase.change.core.LoadDataColumnConfig;
import liquibase.changelog.ChangeLogHistoryServiceFactory;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.cache.jcache.internal.JCacheRegionFactory;
import org.springframework.aot.hint.ExecutableMode;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeHint;
import org.springframework.aot.hint.TypeReference;
import org.springframework.boot.autoconfigure.h2.H2ConsoleProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;

@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(HintsRegistrar.class)
@Slf4j
public class HintsRegistrar implements RuntimeHintsRegistrar {
    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        hints.reflection().registerType(Violation.class, TypeHint.Builder::withMembers);
        hints.reflection().registerType(TypeReference.of(LoginForm.class),
            hint -> hint.withMembers(MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS,
                MemberCategory.INVOKE_PUBLIC_METHODS));
        hints.resources().registerPattern("org/aspectj/weaver/weaver-messages.properties");
        hints.reflection().registerType(Loggable.class, TypeHint.Builder::withMembers);
        hints.resources().registerPattern("config/liquibase/master.xml");
        hints.resources().registerPattern("config/liquibase/changelog/*.xml");
        hints.resources().registerPattern("config/liquibase/data/*.csv");
        hints.reflection().registerType(LoadDataColumnConfig.class, type ->
            type.withConstructor(Collections.emptyList(), ExecutableMode.INVOKE));
        hints.reflection().registerType(ChangeLogHistoryServiceFactory.class, type ->
            type.withConstructor(Collections.emptyList(), ExecutableMode.INVOKE));
        hints.reflection().registerType(JCacheRegionFactory.class, type ->
            type.withConstructor(Collections.emptyList(), ExecutableMode.INVOKE));
        hints.reflection().registerType(TypeReference.of("org.h2.tools.Server"), hint ->
            hint.withMethod("createTcpServer",
                    Collections.singletonList(TypeReference.of(String[].class)),
                    ExecutableMode.INVOKE)
                .withMethod("start", Collections.emptyList(), ExecutableMode.INVOKE)
                .withMethod("stop", Collections.emptyList(), ExecutableMode.INVOKE));
        hints.reflection().registerType(
            TypeReference.of("org.h2.server.web.JakartaWebServlet"),
            type -> type.withConstructor(Collections.emptyList(), ExecutableMode.INVOKE));
        hints.reflection().registerType(H2ConsoleProperties.class, TypeHint.Builder::withMembers);
        hints.resources().registerPattern("i18n/messages.properties")
            .registerPattern("i18n/messages_*.properties");
        hints.reflection()
            .registerType(TypeReference.of("com.github.benmanes.caffeine.cache.SSSMSW"),
                builder -> builder.withConstructor(
                    List.of(TypeReference.of("com.github.benmanes.caffeine.cache.Caffeine"),
                        TypeReference.of("com.github.benmanes.caffeine.cache.AsyncCacheLoader"),
                        TypeReference.of("boolean")), ExecutableMode.INVOKE));
        var securityClasses = Set.of(EncryptionMethod.class, JWEAlgorithm.class);
        var servletClasses = Set.of(Cookie.class);
        var classes = new ArrayList<Class<?>>();
        classes.addAll(securityClasses);
        classes.addAll(servletClasses);

        classes.forEach(type -> {
            var typeReference = TypeReference.of(type);
            hints.reflection().registerType(typeReference, TypeHint.Builder::withMembers);
            if (Serializable.class.isAssignableFrom(type)) {
                hints.serialization().registerType(typeReference);
            }
        });
    }
}
