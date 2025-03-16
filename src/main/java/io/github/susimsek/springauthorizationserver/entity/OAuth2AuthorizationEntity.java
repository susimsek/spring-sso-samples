package io.github.susimsek.springauthorizationserver.entity;

import io.github.susimsek.springauthorizationserver.cache.CacheName;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.proxy.HibernateProxy;

import java.time.Instant;
import java.util.Objects;

@Entity
@Table(name = "oauth2_authorization")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE, region = CacheName.OAUTH2_AUTHORIZATION_ENTITY_CACHE)
public class OAuth2AuthorizationEntity {

    @Id
    @Column(length = 36, nullable = false)
    private String id;

    @Column(name = "registered_client_id", length = 36, nullable = false)
    private String registeredClientId;

    @Column(name = "principal_name", length = 255, nullable = false)
    private String principalName;

    @Column(name = "authorization_grant_type", length = 255, nullable = false)
    private String authorizationGrantType;

    @Column(name = "authorized_scopes", length = 2048)
    private String authorizedScopes;

    @Column(name = "attributes", length = 4000)
    private String attributes;

    @Column(name = "state", length = 255)
    private String state;

    @Column(name = "authorization_code_value", length = 4000)
    private String authorizationCodeValue;

    @Column(name = "authorization_code_issued_at")
    private Instant authorizationCodeIssuedAt;

    @Column(name = "authorization_code_expires_at")
    private Instant authorizationCodeExpiresAt;

    @Column(name = "authorization_code_metadata", length = 4000)
    private String authorizationCodeMetadata;

    @Column(name = "access_token_value", length = 4000)
    private String accessTokenValue;

    @Column(name = "access_token_issued_at")
    private Instant accessTokenIssuedAt;

    @Column(name = "access_token_expires_at")
    private Instant accessTokenExpiresAt;

    @Column(name = "access_token_metadata", length = 4000)
    private String accessTokenMetadata;

    @Column(name = "access_token_type", length = 255)
    private String accessTokenType;

    @Column(name = "access_token_scopes", length = 2048)
    private String accessTokenScopes;

    @Column(name = "oidc_id_token_value", length = 4000)
    private String oidcIdTokenValue;

    @Column(name = "oidc_id_token_issued_at")
    private Instant oidcIdTokenIssuedAt;

    @Column(name = "oidc_id_token_expires_at")
    private Instant oidcIdTokenExpiresAt;

    @Column(name = "oidc_id_token_metadata", length = 4000)
    private String oidcIdTokenMetadata;

    @Column(name = "refresh_token_value", length = 4000)
    private String refreshTokenValue;

    @Column(name = "refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;

    @Column(name = "refresh_token_expires_at")
    private Instant refreshTokenExpiresAt;

    @Column(name = "refresh_token_metadata", length = 4000)
    private String refreshTokenMetadata;

    @Column(name = "user_code_value", length = 4000)
    private String userCodeValue;

    @Column(name = "user_code_issued_at")
    private Instant userCodeIssuedAt;

    @Column(name = "user_code_expires_at")
    private Instant userCodeExpiresAt;

    @Column(name = "user_code_metadata", length = 4000)
    private String userCodeMetadata;

    @Column(name = "device_code_value", length = 4000)
    private String deviceCodeValue;

    @Column(name = "device_code_issued_at")
    private Instant deviceCodeIssuedAt;

    @Column(name = "device_code_expires_at")
    private Instant deviceCodeExpiresAt;

    @Column(name = "device_code_metadata", length = 4000)
    private String deviceCodeMetadata;

    @Column(name = "wallet_address", length = 50)
    private String walletAddress;

    @Column(name = "wallet_signature", length = 150)
    private String walletSignature;

    @Column(name = "wallet_message", length = 1024)
    private String walletMessage;

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof OAuth2AuthorizationEntity otherAuthorization)) {
            return false;
        }
        Class<?> objEffectiveClass = obj instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass()
            : obj.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass()
            : this.getClass();
        if (!thisEffectiveClass.equals(objEffectiveClass)) {
            return false;
        }
        return id != null && Objects.equals(id, otherAuthorization.id);
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
            : getClass().hashCode();
    }
}
