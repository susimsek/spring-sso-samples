package io.github.susimsek.springssosamples.cache;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CacheName {
    public static final String DEFAULT_UPDATE_TIMESTAMPS_REGION = "default-update-timestamps-region";
    public static final String DEFAULT_QUERY_RESULTS_REGION = "default-query-results-region";
    public static final String OAUTH2_AUTHORIZATION_ENTITY_CACHE = "oauth2AuthorizationEntityCache";
    public static final String OAUTH2_AUTHORIZATION_CONSENT_ENTITY_CACHE = "oauth2AuthorizationConsentEntityCache";
    public static final String OAUTH2_CLIENT_ENTITY_CACHE = "oauth2ClientEntityCache";
    public static final String OAUTH2_SCOPE_ENTITY_CACHE = "oauth2ScopeEntityCache";
    public static final String OAUTH2_CLIENT_SCOPE_MAPPING_ENTITY_CACHE = "oauth2ClientScopeMappingEntityCache";
    public static final String ROLE_ENTITY_CACHE = "roleEntityCache";
    public static final String USER_ENTITY_CACHE = "userEntityCache";
    public static final String USER_ROLE_MAPPING_ENTITY_CACHE = "userRoleMappingEntityCache";
}
