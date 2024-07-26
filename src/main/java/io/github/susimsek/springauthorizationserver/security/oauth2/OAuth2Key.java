package io.github.susimsek.springauthorizationserver.security.oauth2;

import static io.github.susimsek.springauthorizationserver.security.EncryptionConstants.PRIVATE_KEY_FOOTER;
import static io.github.susimsek.springauthorizationserver.security.EncryptionConstants.PRIVATE_KEY_HEADER;
import static io.github.susimsek.springauthorizationserver.security.EncryptionConstants.PUBLIC_KEY_FOOTER;
import static io.github.susimsek.springauthorizationserver.security.EncryptionConstants.PUBLIC_KEY_HEADER;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.converter.RsaKeyConverters;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class OAuth2Key implements Serializable {

    private String id;

    private String type;

    private Algorithm algorithm;

    private PublicKey publicKey;

    private PrivateKey privateKey;

    private boolean active;

    private String kid;

    private KeyUse use;

    private OAuth2Key(Builder builder) {
        this.id = builder.id;
        this.type = builder.type;
        this.algorithm = builder.algorithm;
        this.publicKey = builder.publicKey;
        this.privateKey = builder.privateKey;
        this.active = builder.active;
        this.kid = builder.kid;
        this.use = builder.use;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String id;
        private String type;
        private Algorithm algorithm;
        private PublicKey publicKey;
        private PrivateKey privateKey;
        private boolean active;
        private String kid;
        private KeyUse use;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder type(String type) {
            this.type = type;
            return this;
        }

        public Builder algorithm(String algorithm) {
            this.algorithm = new Algorithm(algorithm, Requirement.OPTIONAL);
            return this;
        }

        public Builder publicKey(String publicKey) {
            String formattedPublicKey = PUBLIC_KEY_HEADER + publicKey + PUBLIC_KEY_FOOTER;
            this.publicKey = RsaKeyConverters.x509().convert(new ByteArrayInputStream(
                formattedPublicKey.getBytes(StandardCharsets.UTF_8)));
            return this;
        }

        public Builder privateKey(String privateKey) {
            String formattedPrivateKey = PRIVATE_KEY_HEADER + privateKey + PRIVATE_KEY_FOOTER;
            this.privateKey = RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(
                formattedPrivateKey.getBytes(StandardCharsets.UTF_8)));
            return this;
        }

        public Builder active(boolean active) {
            this.active = active;
            return this;
        }

        public Builder kid(String kid) {
            this.kid = kid;
            return this;
        }

        public Builder use(String use) {
            this.use = new KeyUse(use);
            return this;
        }

        public OAuth2Key build() {
            return new OAuth2Key(this);
        }
    }

    public RSAKey toRSAKey() {
        return new RSAKey.Builder((RSAPublicKey) publicKey)
            .privateKey(privateKey)
            .keyUse(use)
            .algorithm(algorithm)
            .keyID(kid)
            .build();
    }
}
