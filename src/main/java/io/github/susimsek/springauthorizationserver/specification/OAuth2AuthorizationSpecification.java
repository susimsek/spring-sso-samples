package io.github.susimsek.springauthorizationserver.specification;

import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationEntity;
import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationEntity_;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2AuthorizationSpecification {

    public static Specification<OAuth2AuthorizationEntity> hasToken(String token, String tokenType) {
        return (root, query, criteriaBuilder) -> {
            if (tokenType == null) {
                return criteriaBuilder.or(
                        criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.STATE), token),
                        criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.AUTHORIZATION_CODE_VALUE), token),
                        criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.ACCESS_TOKEN_VALUE), token),
                        criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.OIDC_ID_TOKEN_VALUE), token),
                        criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.REFRESH_TOKEN_VALUE), token),
                        criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.USER_CODE_VALUE), token),
                        criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.DEVICE_CODE_VALUE), token)
                );
            } else if (OAuth2ParameterNames.STATE.equals(tokenType)) {
                return criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.STATE), token);
            } else if (OAuth2ParameterNames.CODE.equals(tokenType)) {
                return criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.AUTHORIZATION_CODE_VALUE), token);
            } else if (OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType)) {
                return criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.ACCESS_TOKEN_VALUE), token);
            } else if (OidcParameterNames.ID_TOKEN.equals(tokenType)) {
                return criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.OIDC_ID_TOKEN_VALUE), token);
            } else if (OAuth2TokenType.REFRESH_TOKEN.getValue().equals(tokenType)) {
                return criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.REFRESH_TOKEN_VALUE), token);
            } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType)) {
                return criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.USER_CODE_VALUE), token);
            } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType)) {
                return criteriaBuilder.equal(root.get(OAuth2AuthorizationEntity_.DEVICE_CODE_VALUE), token);
            }
            return null;
        };
    }
}
