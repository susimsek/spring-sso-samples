package io.github.susimsek.springauthorizationserver.security.oauth2;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import io.github.susimsek.springauthorizationserver.security.JweToken;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

@RequiredArgsConstructor
public final class TokenGenerator implements OAuth2TokenGenerator<Jwt> {
    private final TokenEncoder tokenEncoder;
    private final OAuth2KeyService oAuth2KeyService;
    private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    @Nullable
    public Jwt generate(OAuth2TokenContext context) {
        if (context.getTokenType() != null && (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) ||
            "id_token".equals(context.getTokenType().getValue()))) {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) && !OAuth2TokenFormat.SELF_CONTAINED.equals(
                context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
                return null;
            } else {
                String issuer = null;
                if (context.getAuthorizationServerContext() != null) {
                    issuer = context.getAuthorizationServerContext().getIssuer();
                }

                RegisteredClient registeredClient = context.getRegisteredClient();
                Instant issuedAt = Instant.now();
                JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;
                JWEAlgorithm jweAlgorithm = JWEAlgorithm.RSA_OAEP_256;
                EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;
                var tokenSettings = context.getRegisteredClient().getTokenSettings();
                Instant expiresAt;
                if ("id_token".equals(context.getTokenType().getValue())) {
                    expiresAt = issuedAt.plus(30L, ChronoUnit.MINUTES);
                    if (tokenSettings.getIdTokenSignatureAlgorithm() != null) {
                        jwsAlgorithm = tokenSettings.getIdTokenSignatureAlgorithm();
                    }
                    if (tokenSettings.getSetting(JweToken.ALGORITHM) != null) {
                        jweAlgorithm = tokenSettings.getSetting(JweToken.ALGORITHM);
                    }
                    if (tokenSettings.getSetting(JweToken.ENCRYPTION_METHOD) != null) {
                        encryptionMethod = tokenSettings.getSetting(JweToken.ENCRYPTION_METHOD);
                    }
                } else {
                    expiresAt = issuedAt.plus(tokenSettings.getAccessTokenTimeToLive());
                }

                String jweKeyId = null;
                if (StringUtils.hasText(tokenSettings.getSetting(JweToken.KEY_ID))) {
                    jweKeyId = tokenSettings.getSetting(JweToken.KEY_ID);
                }


                JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
                if (StringUtils.hasText(issuer)) {
                    claimsBuilder.issuer(issuer);
                }

                claimsBuilder.subject(context.getPrincipal().getName())
                    .audience(Collections.singletonList(registeredClient.getClientId())).issuedAt(issuedAt)
                    .expiresAt(expiresAt).id(UUID.randomUUID().toString());
                SessionInformation sessionInformation;
                if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                    claimsBuilder.notBefore(issuedAt);
                    if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
                        claimsBuilder.claim("scope", context.getAuthorizedScopes());
                    }
                } else if ("id_token".equals(context.getTokenType().getValue())) {
                    claimsBuilder.claim("azp", registeredClient.getClientId());
                    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
                        OAuth2AuthorizationRequest authorizationRequest =
                            context.getAuthorization().getAttribute(OAuth2AuthorizationRequest.class.getName());
                        String nonce = (String) authorizationRequest.getAdditionalParameters().get("nonce");
                        if (StringUtils.hasText(nonce)) {
                            claimsBuilder.claim("nonce", nonce);
                        }

                        sessionInformation = context.get(SessionInformation.class);
                        if (sessionInformation != null) {
                            claimsBuilder.claim("sid", sessionInformation.getSessionId());
                            claimsBuilder.claim("auth_time", sessionInformation.getLastRequest());
                        }
                    } else if (AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType())) {
                        OidcIdToken currentIdToken = context.getAuthorization().getToken(OidcIdToken.class).getToken();
                        if (currentIdToken.hasClaim("sid")) {
                            claimsBuilder.claim("sid", currentIdToken.getClaim("sid"));
                        }

                        if (currentIdToken.hasClaim("auth_time")) {
                            claimsBuilder.claim("auth_time", currentIdToken.getClaim("auth_time"));
                        }
                    }
                }

                JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);
                if (this.jwtCustomizer != null) {
                    JwtEncodingContext.Builder jwtContextBuilder =
                        JwtEncodingContext.with(
                            jwsHeaderBuilder, claimsBuilder).registeredClient(context.getRegisteredClient()).principal(
                            context.getPrincipal()).authorizationServerContext(
                            context.getAuthorizationServerContext()).authorizedScopes(
                            context.getAuthorizedScopes()).tokenType(context.getTokenType()).authorizationGrantType(
                            context.getAuthorizationGrantType());
                    if (context.getAuthorization() != null) {
                        jwtContextBuilder.authorization(context.getAuthorization());
                    }

                    if (context.getAuthorizationGrant() != null) {
                        jwtContextBuilder.authorizationGrant(context.getAuthorizationGrant());
                    }

                    if ("id_token".equals(context.getTokenType().getValue())) {
                        sessionInformation = context.get(SessionInformation.class);
                        if (sessionInformation != null) {
                            jwtContextBuilder.put(SessionInformation.class, sessionInformation);
                        }
                    }

                    JwtEncodingContext jwtContext = jwtContextBuilder.build();
                    this.jwtCustomizer.customize(jwtContext);
                }

                JwsHeader jwsHeader = jwsHeaderBuilder.build();
                JWEHeader.Builder jweHeaderBuilder = new JWEHeader.Builder(jweAlgorithm, encryptionMethod)
                    .contentType("JWT");
                if (jweKeyId != null) {
                    jweHeaderBuilder.keyID(jweKeyId);
                }
                JwtClaimsSet claims = claimsBuilder.build();
                Boolean jweEnabled = tokenSettings
                    .getSetting(JweToken.ENABLED);
                if (Boolean.FALSE.equals(jweEnabled)) {
                    return tokenEncoder.encode(TokenEncoderParameters.from(jwsHeader, null, claims),
                        null);
                }
                OAuth2Key oAuth2Key = oAuth2KeyService.findByKidOrThrow(jweKeyId);
                return tokenEncoder.encode(
                    TokenEncoderParameters.from(jwsHeader, jweHeaderBuilder.build(), claims),
                    oAuth2Key.toRSAKey());
            }
        } else {
            return null;
        }
    }

    public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
        this.jwtCustomizer = jwtCustomizer;
    }
}
