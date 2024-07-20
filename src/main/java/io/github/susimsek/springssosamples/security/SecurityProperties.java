package io.github.susimsek.springssosamples.security;

import static io.github.susimsek.springssosamples.security.EncryptionConstants.PRIVATE_KEY_FOOTER;
import static io.github.susimsek.springssosamples.security.EncryptionConstants.PRIVATE_KEY_HEADER;
import static io.github.susimsek.springssosamples.security.EncryptionConstants.PUBLIC_KEY_FOOTER;
import static io.github.susimsek.springssosamples.security.EncryptionConstants.PUBLIC_KEY_HEADER;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    @Valid
    private JwtProperties jwt;

    @Valid
    private JweProperties jwe;

    @NotBlank(message = "{validation.field.notBlank}")
    private String contentSecurityPolicy;

    @Getter
    @Setter
    public static class JwtProperties {

        @NotBlank(message = "{validation.field.notBlank}")
        private String publicKey;

        @NotBlank(message = "{validation.field.notBlank}")
        private String privateKey;

        public String getFormattedPublicKey() {
            return PUBLIC_KEY_HEADER + publicKey + PUBLIC_KEY_FOOTER;
        }

        public String getFormattedPrivateKey() {
            return PRIVATE_KEY_HEADER + privateKey + PRIVATE_KEY_FOOTER;
        }
    }

    @Getter
    @Setter
    public static class JweProperties {
        @NotNull(message = "{validation.field.notNull}")
        private Boolean enabled = false;

        @NotBlank(message = "{validation.field.notBlank}")
        private String publicKey;

        @NotBlank(message = "{validation.field.notBlank}")
        private String privateKey;

        public String getFormattedPublicKey() {
            return PUBLIC_KEY_HEADER + publicKey + PUBLIC_KEY_FOOTER;
        }

        public String getFormattedPrivateKey() {
            return PRIVATE_KEY_HEADER + privateKey + PRIVATE_KEY_FOOTER;
        }
    }
}
