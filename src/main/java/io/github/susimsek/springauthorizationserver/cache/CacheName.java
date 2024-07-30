package io.github.susimsek.springauthorizationserver.cache;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CacheName {
    public static final String DEFAULT_UPDATE_TIMESTAMPS_REGION = "default-update-timestamps-region";
    public static final String DEFAULT_QUERY_RESULTS_REGION = "default-query-results-region";
    public static final String OAUTH2_AUTHORIZATION_ENTITY_CACHE = "oauth2AuthorizationEntity";
    public static final String OAUTH2_AUTHORIZATION_ENTITY_BY_SPECIFICATION_CACHE = "oauth2AuthorizationEntityBySpecification";
    public static final String OAUTH2_AUTHORIZATION_CONSENT_ENTITY_CACHE = "oauth2AuthorizationConsentEntity";
    public static final String OAUTH2_CLIENT_ENTITY_CACHE = "oauth2ClientEntity";
    public static final String OAUTH2_CLIENT_ENTITY_BY_CLIENT_ID_CACHE = "oauth2ClientEntityByClientId";
    public static final String OAUTH2_CLIENT_ENTITY_COUNT_BY_CLIENT_ID_CACHE = "oauth2ClientEntityCountByClientId";
    public static final String OAUTH2_CLIENT_ENTITY_COUNT_BY_CLIENT_SECRET_CACHE = "oauth2ClientEntityCountByClientSecret";
    public static final String OAUTH2_SCOPE_ENTITY_CACHE = "oauth2ScopeEntity";
    public static final String OAUTH2_CLIENT_SCOPE_MAPPING_ENTITY_CACHE = "oauth2ClientScopeMappingEntity";
    public static final String OAUTH2_KEY_ENTITY_CACHE = "oauth2KeyEntity";
    public static final String OAUTH2_KEY_ENTITY_BY_KID_CACHE = "oauth2KeyEntityByKid";
    public static final String OAUTH2_KEY_ENTITY_BY_USE_CACHE = "oauth2KeyEntityByUse";
    public static final String ROLE_ENTITY_CACHE = "roleEntity";
    public static final String USER_ENTITY_CACHE = "userEntity";
    public static final String MESSAGE_ENTITY_CACHE = "messageEntity";
    public static final String MESSAGES_CACHE = "messagesCache";
    public static final String USER_ROLE_MAPPING_ENTITY_CACHE = "userRoleMappingEntity";
    public static final String ROLE_ENTITY_BY_NAME_CACHE = "roleEntityByName";
    public static final String USER_ENTITY_BY_USERNAME_CACHE = "userEntityByUsername";
    public static final String USER_ENTITY_BY_EMAIL_CACHE = "userEntityByEmail";
    public static final String USER_SESSION_ENTITY_CACHE = "userSessionEntity";
    public static final String USER_SESSION_ATTRIBUTE_ENTITY_CACHE = "userSessionAttributeEntity";
    public static final String USER_SESSION_ENTITY_BY_SESSION_ID_CACHE = "userSessionEntityBySessionId";
    public static final String USER_SESSION_ENTITY_BY_PRINCIPAL_NAME_CACHE = "userSessionEntityByPrincipalName";
}
