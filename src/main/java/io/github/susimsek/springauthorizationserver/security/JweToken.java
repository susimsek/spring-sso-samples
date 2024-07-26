package io.github.susimsek.springauthorizationserver.security;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JweToken {
    private static final String TOKEN_SETTINGS_NAMESPACE = "settings.".concat("token.jwe-");
    public static final String ENABLED;
    public static final String ALGORITHM;
    public static final String ENCRYPTION_METHOD;
    public static final String KEY_ID;


    static {
        ENABLED = TOKEN_SETTINGS_NAMESPACE.concat("enabled");
        ALGORITHM = TOKEN_SETTINGS_NAMESPACE.concat("algorithm");
        ENCRYPTION_METHOD = TOKEN_SETTINGS_NAMESPACE.concat("encryption-method");
        KEY_ID = TOKEN_SETTINGS_NAMESPACE.concat("key-id");
    }
}
