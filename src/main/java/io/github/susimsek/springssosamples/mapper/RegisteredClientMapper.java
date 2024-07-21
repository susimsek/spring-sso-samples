package io.github.susimsek.springssosamples.mapper;

import io.github.susimsek.springssosamples.entity.OAuth2ClientScopeMappingEntity;
import io.github.susimsek.springssosamples.entity.OAuth2RegisteredClientEntity;
import io.github.susimsek.springssosamples.entity.OAuth2ScopeEntity;
import io.github.susimsek.springssosamples.security.oauth2.json.OAuth2JsonUtils;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Setter;
import org.mapstruct.Mapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

@Mapper(componentModel = "spring")
public abstract class RegisteredClientMapper {

    @Setter(onMethod_={@Autowired})
    private OAuth2JsonUtils oAuth2JsonUtils;

    public OAuth2RegisteredClientEntity toEntity(RegisteredClient registeredClient) {
        OAuth2RegisteredClientEntity client = new OAuth2RegisteredClientEntity();
        client.setId(registeredClient.getId());
        client.setClientId(registeredClient.getClientId());
        client.setClientIdIssuedAt(Optional.ofNullable(registeredClient.getClientIdIssuedAt())
            .orElse(Instant.now()));
        client.setClientSecret(registeredClient.getClientSecret());
        client.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        client.setClientName(registeredClient.getClientName());
        client.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(
            registeredClient.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue)
                .collect(Collectors.toSet())
        ));
        client.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(
            registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toSet())
        ));
        client.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        client.setPostLogoutRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        client.setClientSettings(oAuth2JsonUtils.writeMap(registeredClient.getClientSettings().getSettings()));
        client.setTokenSettings(oAuth2JsonUtils.writeMap(registeredClient.getTokenSettings().getSettings()));

        // Scope mapping
        Set<OAuth2ClientScopeMappingEntity> clientScopeMappings = registeredClient.getScopes().stream()
            .map(scope -> {
                OAuth2ScopeEntity scopeEntity = new OAuth2ScopeEntity();
                scopeEntity.setScope(scope);
                OAuth2ClientScopeMappingEntity clientScopeMapping = new OAuth2ClientScopeMappingEntity();
                clientScopeMapping.setClient(client);
                clientScopeMapping.setScope(scopeEntity);
                return clientScopeMapping;
            }).collect(Collectors.toSet());
        client.setClientScopes(clientScopeMappings);

        return client;
    }

    public RegisteredClient toDto(OAuth2RegisteredClientEntity client) {
        Map<String, Object> clientSettingsMap = oAuth2JsonUtils.parseMap(client.getClientSettings());
        ClientSettings clientSettings = ClientSettings.withSettings(clientSettingsMap).build();

        Map<String, Object> tokenSettingsMap = oAuth2JsonUtils.parseMap(client.getTokenSettings());
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.withSettings(tokenSettingsMap);
        if (!tokenSettingsMap.containsKey(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT)) {
            tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
        }
        TokenSettings tokenSettings = tokenSettingsBuilder.build();

        Set<String> scopes = client.getClientScopes().stream()
            .map(mapping -> mapping.getScope().getScope())
            .collect(Collectors.toSet());

        return RegisteredClient.withId(client.getId())
            .clientId(client.getClientId())
            .clientIdIssuedAt(client.getClientIdIssuedAt())
            .clientSecret(client.getClientSecret())
            .clientSecretExpiresAt(client.getClientSecretExpiresAt())
            .clientName(client.getClientName())
            .clientAuthenticationMethods(authenticationMethods -> authenticationMethods.addAll(resolveClientAuthenticationMethods(client.getClientAuthenticationMethods())))
            .authorizationGrantTypes(grantTypes -> grantTypes.addAll(resolveAuthorizationGrantTypes(client.getAuthorizationGrantTypes())))
            .redirectUris(uris -> uris.addAll(StringUtils.commaDelimitedListToSet(client.getRedirectUris())))
            .postLogoutRedirectUris(uris -> uris.addAll(StringUtils.commaDelimitedListToSet(client.getPostLogoutRedirectUris())))
            .scopes(sc -> sc.addAll(scopes))
            .clientSettings(clientSettings)
            .tokenSettings(tokenSettings)
            .build();
    }

    private Set<ClientAuthenticationMethod> resolveClientAuthenticationMethods(String clientAuthenticationMethods) {
        return StringUtils.commaDelimitedListToSet(clientAuthenticationMethods).stream()
            .map(RegisteredClientMapper::resolveClientAuthenticationMethod)
            .collect(Collectors.toSet());
    }

    private Set<AuthorizationGrantType> resolveAuthorizationGrantTypes(String authorizationGrantTypes) {
        return StringUtils.commaDelimitedListToSet(authorizationGrantTypes).stream()
            .map(RegisteredClientMapper::resolveAuthorizationGrantType)
            .collect(Collectors.toSet());
    }

    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }

    private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }
}
