package io.github.susimsek.springauthorizationserver.security.oauth2.wallet;

import io.github.susimsek.springauthorizationserver.security.oauth2.ExtendedAuthorizationGrantType;
import io.github.susimsek.springauthorizationserver.security.oauth2.OAuth2EndpointUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public final class WalletAuthenticationConverter implements AuthenticationConverter {

    public WalletAuthenticationConverter() {
    }

    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);
        String grantType = parameters.getFirst("grant_type");
        if (!ExtendedAuthorizationGrantType.WALLET.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        String walletAddress = parameters.getFirst("wallet_address");
        if (!StringUtils.hasText(walletAddress) || parameters.get("wallet_address").size() != 1) {
            OAuth2EndpointUtils.throwError("invalid_request",
                "wallet_address", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
        }

        String signature = parameters.getFirst("signature");
        if (!StringUtils.hasText(signature) || parameters.get("signature").size() != 1) {
            OAuth2EndpointUtils.throwError("invalid_request",
                "signature", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
        }

        String message = parameters.getFirst("message");
        if (!StringUtils.hasText(message) || parameters.get("message").size() != 1) {
            OAuth2EndpointUtils.throwError("invalid_request",
                "message", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!"grant_type".equals(key)
                && !"client_id".equals(key)
                && !"wallet_address".equals(key)
                && !"signature".equals(key)
                && !"message".equals(key)) {
                additionalParameters.put(key, value.size() == 1 ? value.getFirst() : value.toArray(new String[0]));
            }
        });

        return new WalletAuthenticationToken(walletAddress, signature, message,
            clientPrincipal, additionalParameters);
    }
}
