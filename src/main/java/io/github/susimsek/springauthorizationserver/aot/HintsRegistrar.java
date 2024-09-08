package io.github.susimsek.springauthorizationserver.aot;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.AbstractTypeResolver;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.cfg.MutableConfigOverride;
import com.fasterxml.jackson.databind.deser.BeanDeserializerModifier;
import com.fasterxml.jackson.databind.deser.DeserializationProblemHandler;
import com.fasterxml.jackson.databind.deser.Deserializers;
import com.fasterxml.jackson.databind.deser.KeyDeserializers;
import com.fasterxml.jackson.databind.deser.ValueInstantiators;
import com.fasterxml.jackson.databind.introspect.ClassIntrospector;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;
import com.fasterxml.jackson.databind.ser.Serializers;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.type.TypeModifier;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import io.github.susimsek.springauthorizationserver.dto.LoginForm;
import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationConsentId;
import io.github.susimsek.springauthorizationserver.entity.UserRoleMappingId;
import io.github.susimsek.springauthorizationserver.entity.UserSessionAttributeId;
import io.github.susimsek.springauthorizationserver.exception.Violation;
import io.github.susimsek.springauthorizationserver.logging.annotation.Loggable;
import jakarta.servlet.http.Cookie;
import java.io.Serializable;
import java.net.URL;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedCookie;

@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(HintsRegistrar.class)
@Slf4j
public class HintsRegistrar implements RuntimeHintsRegistrar {

    private Set<TypeReference> subs(Class<?>... classesToFind) {
        var all = new HashSet<TypeReference>();
        for (var individualClass : classesToFind) {
            var provider = new ClassPathScanningCandidateComponentProvider(false);
            provider.addIncludeFilter(new AssignableTypeFilter(individualClass));

            var subTypesOf = provider.findCandidateComponents("").stream()
                .map(beanDefinition -> TypeReference.of(beanDefinition.getBeanClassName()))
                .collect(Collectors.toSet());

            all.addAll(subTypesOf);
        }
        return all;
    }


    private Set<TypeReference> resolveJacksonTypes() {
        var all = new HashSet<TypeReference>();

        for (var pkg : Set.of("com.fasterxml", "org.springframework", "io.github.susimsek")) {
            var provider = new ClassPathScanningCandidateComponentProvider(false);

            // Find subtypes of JsonDeserializer, JsonSerializer, and Module
            all.addAll(subs(JsonDeserializer.class, JsonSerializer.class, Module.class));

            // Find types annotated with JsonTypeInfo
            provider.addIncludeFilter(new AnnotationTypeFilter(JsonTypeInfo.class));
            all.addAll(provider.findCandidateComponents(pkg).stream()
                .map(beanDefinition -> TypeReference.of(beanDefinition.getBeanClassName()))
                .collect(Collectors.toSet()));

            // Find types annotated with JsonAutoDetect
            provider.addIncludeFilter(new AnnotationTypeFilter(JsonAutoDetect.class));
            all.addAll(provider.findCandidateComponents(pkg).stream()
                .map(beanDefinition -> TypeReference.of(beanDefinition.getBeanClassName()))
                .collect(Collectors.toSet()));
        }

        // Register Jackson Module dependencies
        all.addAll(registerJacksonModuleDeps(all.stream()
            .filter(typeReference -> {
                try {
                    return Module.class.isAssignableFrom(Class.forName(typeReference.getName()));
                } catch (ClassNotFoundException e) {
                    throw new RuntimeException(e);
                }
            })
            .collect(Collectors.toSet())));

        return all;
    }

    private static Collection<TypeReference> registerJacksonModuleDeps(Set<TypeReference> moduleClasses) {
        var set = new HashSet<TypeReference>();
        var classLoader = HintsRegistrar.class.getClassLoader();
        var securityModules = new ArrayList<Module>();
        securityModules.addAll(SecurityJackson2Modules.getModules(classLoader));

        securityModules.addAll(moduleClasses.stream()
            .map(tr -> {
                try {
                    Class<?> cn = Class.forName(tr.getName());
                    for (var ctor : cn.getConstructors()) {
                        if (ctor.getParameterCount() == 0) {
                            return (Module) ctor.newInstance();
                        }
                    }
                } catch (Exception t) {
                    log.error("Couldn't construct and inspect module {}", tr.getName());
                }
                return null;
            })
            .collect(Collectors.toSet())
        );

        var om = new ObjectMapper();
        var sc = new AccumulatingSetupContext(om, set);

        for (var module : securityModules) {
            if (module != null) {
                set.add(TypeReference.of(module.getClass().getName()));
                module.setupModule(sc);
                module.getDependencies().forEach(m -> set.add(TypeReference.of(m.getClass().getName())));
            }
        }

        return set;
    }

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

        var oauth2CoreClasses =
            Set.of(TypeReference.of(SignatureAlgorithm.class), TypeReference.of(OAuth2AuthorizationResponseType.class),
                TypeReference.of(OAuth2AuthorizationRequest.class), TypeReference.of(AuthorizationGrantType.class),
                TypeReference.of(OAuth2TokenFormat.class), TypeReference.of(OAuth2Authorization.class),
                TypeReference.of(SecurityContextImpl.class), TypeReference.of(EncryptionMethod.class),
                TypeReference.of(JWEAlgorithm.class));

        var securityClasses = Set.of(TypeReference.of(User.class), TypeReference.of(WebAuthenticationDetails.class),
            TypeReference.of(GrantedAuthority.class), TypeReference.of(Principal.class),
            TypeReference.of(SimpleGrantedAuthority.class),
            TypeReference.of(UsernamePasswordAuthenticationToken.class));
        var servletClasses = Set.of(TypeReference.of(Cookie.class));
        var idClasses = Set.of(TypeReference.of(OAuth2AuthorizationConsentId.class),
            TypeReference.of(UserRoleMappingId.class), TypeReference.of(UserSessionAttributeId.class));
        var stringClasses = Map.of(
            "java.util.", Set.of("Arrays$ArrayList"),
            "java.util.Collections$",
            Set.of("UnmodifiableRandomAccessList", "EmptyList", "UnmodifiableMap", "EmptyMap", "SingletonList",
                "UnmodifiableSet")
        );//
        var javaClasses =
            Set.of(TypeReference.of(ArrayList.class), TypeReference.of(Date.class), TypeReference.of(Duration.class),
                TypeReference.of(Instant.class), TypeReference.of(URL.class),
                TypeReference.of(TreeMap.class), TypeReference.of(HashMap.class),
                TypeReference.of(LinkedHashMap.class), TypeReference.of(List.class));
        var savedRequestClasses =
            Set.of(TypeReference.of(DefaultSavedRequest.class), TypeReference.of(SavedCookie.class),
                TypeReference.of(DefaultSavedRequest.Builder.class));
        var jacksonTypes = resolveJacksonTypes();
        jacksonTypes.add(TypeReference.of(SecurityJackson2Modules.class));
        var classes = new ArrayList<TypeReference>();
        classes.addAll(jacksonTypes);
        classes.addAll(servletClasses);
        classes.addAll(oauth2CoreClasses);
        classes.addAll(savedRequestClasses);
        classes.addAll(javaClasses);
        classes.addAll(idClasses);
        classes.addAll(securityClasses);

        stringClasses.forEach(
            (root, setOfClasses) -> setOfClasses.forEach(cn -> classes.add(TypeReference.of(root + cn))));

        classes.forEach(typeReference -> {
            hints.reflection().registerType(typeReference, builder -> builder.withMembers(
                MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                MemberCategory.INVOKE_DECLARED_METHODS,
                MemberCategory.DECLARED_FIELDS
            ));
            try {
                var cls = Class.forName(typeReference.getName());
                if (Serializable.class.isAssignableFrom(cls)) {
                    hints.serialization().registerType(typeReference);
                }
            } catch (ClassNotFoundException exception) {
                log.error("couldn't register serialization hint for {}:{}",
                    typeReference.getName(), exception.getMessage());
            }
        });
    }

    static class AccumulatingSetupContext implements Module.SetupContext {

        private final Collection<TypeReference> classesToRegister;
        private final ObjectMapper objectMapper;

        AccumulatingSetupContext(ObjectMapper objectMapper, Collection<TypeReference> classes) {
            this.objectMapper = objectMapper;
            this.classesToRegister = classes;
        }

        @Override
        public Version getMapperVersion() {
            return null;
        }

        @Override
        public <C extends ObjectCodec> C getOwner() {
            return (C) this.objectMapper;
        }

        @Override
        public TypeFactory getTypeFactory() {
            return null;
        }

        @Override
        public boolean isEnabled(MapperFeature f) {
            return false;
        }

        @Override
        public boolean isEnabled(DeserializationFeature f) {
            return false;
        }

        @Override
        public boolean isEnabled(SerializationFeature f) {
            return false;
        }

        @Override
        public boolean isEnabled(JsonFactory.Feature f) {
            return false;
        }

        @Override
        public boolean isEnabled(JsonParser.Feature f) {
            return false;
        }

        @Override
        public boolean isEnabled(JsonGenerator.Feature f) {
            return false;
        }

        @Override
        public MutableConfigOverride configOverride(Class<?> type) {
            this.classesToRegister.add(TypeReference.of(type.getName()));
            return null;
        }

        @Override
        public void addDeserializers(Deserializers d) {

        }

        @Override
        public void addKeyDeserializers(KeyDeserializers s) {

        }

        @Override
        public void addSerializers(Serializers s) {

        }

        @Override
        public void addKeySerializers(Serializers s) {

        }

        @Override
        public void addBeanDeserializerModifier(BeanDeserializerModifier mod) {

        }

        @Override
        public void addBeanSerializerModifier(BeanSerializerModifier mod) {

        }

        @Override
        public void addAbstractTypeResolver(AbstractTypeResolver resolver) {

        }

        @Override
        public void addTypeModifier(TypeModifier modifier) {

        }

        @Override
        public void addValueInstantiators(ValueInstantiators instantiators) {

        }

        @Override
        public void setClassIntrospector(ClassIntrospector ci) {

        }

        @Override
        public void insertAnnotationIntrospector(AnnotationIntrospector ai) {

        }

        @Override
        public void appendAnnotationIntrospector(AnnotationIntrospector ai) {

        }

        @Override
        public void registerSubtypes(Class<?>... subtypes) {
            this.classesToRegister.addAll(Stream.of(subtypes)
                .map(cls -> TypeReference.of(cls.getName()))
                .collect(Collectors.toSet()));
        }

        @Override
        public void registerSubtypes(NamedType... subtypes) {
            this.classesToRegister.addAll(Stream.of(subtypes)
                .map(nt -> TypeReference.of(nt.getType().getName()))
                .collect(Collectors.toSet()));
        }

        @Override
        public void registerSubtypes(Collection<Class<?>> subtypes) {
            this.classesToRegister.addAll(subtypes.stream()
                .map(cls -> TypeReference.of(cls.getName()))
                .collect(Collectors.toSet()));
        }

        @Override
        public void setMixInAnnotations(Class<?> target, Class<?> mixinSource) {
            this.classesToRegister.add(TypeReference.of(target.getName()));
            this.classesToRegister.add(TypeReference.of(mixinSource.getName()));
        }

        @Override
        public void addDeserializationProblemHandler(DeserializationProblemHandler handler) {

        }

        @Override
        public void setNamingStrategy(PropertyNamingStrategy naming) {

        }
    }
}
