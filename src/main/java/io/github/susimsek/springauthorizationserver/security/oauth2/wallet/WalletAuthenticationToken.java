package io.github.susimsek.springauthorizationserver.security.oauth2.wallet;

import io.github.susimsek.springauthorizationserver.security.oauth2.ExtendedAuthorizationGrantType;
import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Map;


@Getter
public class WalletAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String walletAddress;
    private final String signature;
    private final String message;

    /**
     * Constructs a WalletAuthenticationToken with additional parameters.
     *
     * @param walletAddress the user's wallet address; must not be empty.
     * @param clientPrincipal the authenticated client principal; must not be null.
     * @param signature the wallet signature; must not be empty.
     * @param message the signed message; must not be empty.
     * @param additionalParameters additional parameters; must not be null.
     */
    public WalletAuthenticationToken(String walletAddress,
                                     String signature,
                                     String message,
                                       Authentication clientPrincipal,
                                       @Nullable Map<String, Object> additionalParameters) {
        super(ExtendedAuthorizationGrantType.WALLET, clientPrincipal, additionalParameters);
        Assert.hasText(walletAddress, "walletAddress cannot be empty");
        Assert.hasText(signature, "signature cannot be empty");
        Assert.hasText(message, "message cannot be empty");
        this.walletAddress = walletAddress;
        this.signature = signature;
        this.message = message;
    }
}
