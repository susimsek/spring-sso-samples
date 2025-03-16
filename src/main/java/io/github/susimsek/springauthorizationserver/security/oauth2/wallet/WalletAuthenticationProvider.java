package io.github.susimsek.springauthorizationserver.security.oauth2.wallet;

import io.github.susimsek.springauthorizationserver.security.oauth2.ExtendedAuthorizationGrantType;
import io.github.susimsek.springauthorizationserver.security.oauth2.OAuth2AuthenticationProviderUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class WalletAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    // Token tipleri
    private static final OAuth2TokenType ACCESS_TOKEN_TOKEN_TYPE =
        new OAuth2TokenType("access_token");
    private static final OAuth2TokenType REFRESH_TOKEN_TOKEN_TYPE =
        new OAuth2TokenType("refresh_token");

    private final Log logger = LogFactory.getLog(this.getClass());
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final WalletSignatureVerifier walletSignatureVerifier;
    private SessionRegistry sessionRegistry;

    public WalletAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                        WalletSignatureVerifier walletSignatureVerifier) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        Assert.notNull(walletSignatureVerifier, "walletSignatureVerifier cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.walletSignatureVerifier = walletSignatureVerifier;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Cast işlemi: WalletAuthenticationToken
        WalletAuthenticationToken walletAuthentication = (WalletAuthenticationToken) authentication;

        // 2. Client'ı al (burada OAuth2AuthenticationProviderUtils benzeri bir utility metodu kullanıyoruz)
        // Bu metot, client authentication bilgisini alıp geçerli değilse exception fırlatır.
        OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
            .getAuthenticatedClientElseThrowInvalidClient(walletAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        // 1. Wallet imza doğrulaması
        boolean valid = walletSignatureVerifier.verify(
            walletAuthentication.getMessage(),
            walletAuthentication.getSignature(),
            walletAuthentication.getWalletAddress()
        );
        if (!valid) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_grant", "Invalid wallet signature", ERROR_URI));
        }

        Set<String> authorizedScopes = new HashSet<>();
        authorizedScopes.add("wallet");
        var principal =  new UsernamePasswordAuthenticationToken(
            walletAuthentication.getWalletAddress(),
            walletAuthentication.getSignature(),
            Collections.singleton(new SimpleGrantedAuthority("ROLE_WALLET"))
        );

        Wallet wallet = new Wallet(
            walletAuthentication.getWalletAddress(),
            walletAuthentication.getSignature(),
            walletAuthentication.getMessage()
        );

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName("wallet")
            .authorizationGrantType(ExtendedAuthorizationGrantType.WALLET)
            .authorizedScopes(authorizedScopes)
            .attribute(Principal.class.getName(), principal)
            .attribute("wallet", wallet);


        DefaultOAuth2TokenContext.Builder tokenContextBuilder = (DefaultOAuth2TokenContext.Builder)((DefaultOAuth2TokenContext.Builder)((DefaultOAuth2TokenContext.Builder)((DefaultOAuth2TokenContext.Builder)((DefaultOAuth2TokenContext.Builder)((DefaultOAuth2TokenContext.Builder)((DefaultOAuth2TokenContext.Builder)DefaultOAuth2TokenContext.builder().registeredClient(registeredClient)).principal(principal)).authorizationServerContext(AuthorizationServerContextHolder.getContext())).authorization(authorizationBuilder.build())).authorizedScopes(authorizedScopes)).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)).authorizationGrant(walletAuthentication);


        // 5. Erişim token'ı (access token) üretimi
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(ACCESS_TOKEN_TOKEN_TYPE).build();
        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }
        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }
        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(authorizationBuilder, generatedAccessToken, tokenContext);


        // 6. Refresh token üretimi (varsa)
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder.tokenType(REFRESH_TOKEN_TOKEN_TYPE).build();
            OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
            if (generatedRefreshToken != null) {
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                    OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate a valid refresh token.", ERROR_URI);
                    throw new OAuth2AuthenticationException(error);
                }
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Generated refresh token");
                }
                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                authorizationBuilder.refreshToken(refreshToken);
            }
        }

        // 8. Authorization kaydını oluştur ve kaydet
        OAuth2Authorization authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);
        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        Map<String, Object> additionalParameters = Collections.emptyMap();
        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated wallet token request");
        }

        // 9. Sonuç olarak, erişim token'ı (ve varsa refresh token) içeren OAuth2AccessTokenAuthenticationToken döndürülür.
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal,
            accessToken, refreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return WalletAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
