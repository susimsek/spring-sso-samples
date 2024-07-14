package io.github.susimsek.springssosamples.mapper;

import io.github.susimsek.springssosamples.entity.OAuth2AuthorizationEntity;
import io.github.susimsek.springssosamples.security.oauth2.OAuth2JsonUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class OAuth2AuthorizationMapper {

    private final OAuth2JsonUtils jsonUtils;

    public OAuth2AuthorizationEntity toEntity(OAuth2Authorization model) {
        if (model == null) {
            return null;
        }

        OAuth2AuthorizationEntity entity = new OAuth2AuthorizationEntity();
        entity.setId(model.getId());
        entity.setRegisteredClientId(model.getRegisteredClientId());
        entity.setPrincipalName(model.getPrincipalName());
        entity.setAuthorizationGrantType(model.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(String.join(",", model.getAuthorizedScopes()));
        entity.setAttributes(jsonUtils.writeMap(model.getAttributes()));
        entity.setState(model.getAttribute(OAuth2ParameterNames.STATE));

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = model.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            entity.setAuthorizationCodeValue(authorizationCode.getToken().getTokenValue());
            entity.setAuthorizationCodeIssuedAt(authorizationCode.getToken().getIssuedAt());
            entity.setAuthorizationCodeExpiresAt(authorizationCode.getToken().getExpiresAt());
            entity.setAuthorizationCodeMetadata(jsonUtils.writeMap(authorizationCode.getMetadata()));
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = model.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            entity.setAccessTokenValue(accessToken.getToken().getTokenValue());
            entity.setAccessTokenIssuedAt(accessToken.getToken().getIssuedAt());
            entity.setAccessTokenExpiresAt(accessToken.getToken().getExpiresAt());
            entity.setAccessTokenMetadata(jsonUtils.writeMap(accessToken.getMetadata()));
            entity.setAccessTokenType(accessToken.getToken().getTokenType().getValue());
            entity.setAccessTokenScopes(String.join(",", accessToken.getToken().getScopes()));
        }

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = model.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            entity.setOidcIdTokenValue(oidcIdToken.getToken().getTokenValue());
            entity.setOidcIdTokenIssuedAt(oidcIdToken.getToken().getIssuedAt());
            entity.setOidcIdTokenExpiresAt(oidcIdToken.getToken().getExpiresAt());
            entity.setOidcIdTokenMetadata(jsonUtils.writeMap(oidcIdToken.getMetadata()));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = model.getRefreshToken();
        if (refreshToken != null) {
            entity.setRefreshTokenValue(refreshToken.getToken().getTokenValue());
            entity.setRefreshTokenIssuedAt(refreshToken.getToken().getIssuedAt());
            entity.setRefreshTokenExpiresAt(refreshToken.getToken().getExpiresAt());
            entity.setRefreshTokenMetadata(jsonUtils.writeMap(refreshToken.getMetadata()));
        }

        OAuth2Authorization.Token<OAuth2UserCode> userCode = model.getToken(OAuth2UserCode.class);
        if (userCode != null) {
            entity.setUserCodeValue(userCode.getToken().getTokenValue());
            entity.setUserCodeIssuedAt(userCode.getToken().getIssuedAt());
            entity.setUserCodeExpiresAt(userCode.getToken().getExpiresAt());
            entity.setUserCodeMetadata(jsonUtils.writeMap(userCode.getMetadata()));
        }

        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = model.getToken(OAuth2DeviceCode.class);
        if (deviceCode != null) {
            entity.setDeviceCodeValue(deviceCode.getToken().getTokenValue());
            entity.setDeviceCodeIssuedAt(deviceCode.getToken().getIssuedAt());
            entity.setDeviceCodeExpiresAt(deviceCode.getToken().getExpiresAt());
            entity.setDeviceCodeMetadata(jsonUtils.writeMap(deviceCode.getMetadata()));
        }

        return entity;
    }

    public OAuth2Authorization toModel(OAuth2AuthorizationEntity entity, RegisteredClient registeredClient) {
        if (entity == null) {
            return null;
        }

        Set<String> scopes = StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes());
        Map<String, Object> attributes = jsonUtils.parseMap(entity.getAttributes());

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(String.valueOf(entity.getId()))
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(scopes)
                .attributes(attrs -> attrs.putAll(attributes));

        if (StringUtils.hasText(entity.getState())) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }

        if (StringUtils.hasText(entity.getAuthorizationCodeValue())) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    entity.getAuthorizationCodeIssuedAt(),
                    entity.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(jsonUtils.parseMap(entity.getAuthorizationCodeMetadata())));
        }

        if (StringUtils.hasText(entity.getAccessTokenValue())) {
            OAuth2AccessToken.TokenType tokenType = OAuth2AccessToken.TokenType.BEARER;
            if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(entity.getAccessTokenType())) {
                tokenType = OAuth2AccessToken.TokenType.BEARER;
            }
            Set<String> accessTokenScopes = StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes());
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    tokenType,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    accessTokenScopes);
            builder.token(accessToken, metadata -> metadata.putAll(jsonUtils.parseMap(entity.getAccessTokenMetadata())));
        }

        if (StringUtils.hasText(entity.getOidcIdTokenValue())) {
            OidcIdToken oidcIdToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    entity.getOidcIdTokenIssuedAt(),
                    entity.getOidcIdTokenExpiresAt(),
                    jsonUtils.parseMap(entity.getOidcIdTokenMetadata()));
            builder.token(oidcIdToken, metadata -> metadata.putAll(jsonUtils.parseMap(entity.getOidcIdTokenMetadata())));
        }

        if (StringUtils.hasText(entity.getRefreshTokenValue())) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(jsonUtils.parseMap(entity.getRefreshTokenMetadata())));
        }

        if (StringUtils.hasText(entity.getUserCodeValue())) {
            OAuth2UserCode userCode = new OAuth2UserCode(
                    entity.getUserCodeValue(),
                    entity.getUserCodeIssuedAt(),
                    entity.getUserCodeExpiresAt());
            builder.token(userCode, metadata -> metadata.putAll(jsonUtils.parseMap(entity.getUserCodeMetadata())));
        }

        if (StringUtils.hasText(entity.getDeviceCodeValue())) {
            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                    entity.getDeviceCodeValue(),
                    entity.getDeviceCodeIssuedAt(),
                    entity.getDeviceCodeExpiresAt());
            builder.token(deviceCode, metadata -> metadata.putAll(jsonUtils.parseMap(entity.getDeviceCodeMetadata())));
        }

        return builder.build();
    }
}
