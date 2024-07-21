package io.github.susimsek.springssosamples.security;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JweToken {
    private static final String TOKEN_SETTINGS_NAMESPACE = "settings.".concat("token.jwe-");
    public static final String ENABLED;
    public static final String ALGORITHM;
    public static final String ENCRYPTION_METHOD;


    static {
        ENABLED = TOKEN_SETTINGS_NAMESPACE.concat("enabled");
        ALGORITHM = TOKEN_SETTINGS_NAMESPACE.concat("algorithm");
        ENCRYPTION_METHOD = TOKEN_SETTINGS_NAMESPACE.concat("encryption-method");
    }
}
