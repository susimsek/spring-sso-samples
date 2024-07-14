package io.github.susimsek.springssosamples.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.hibernate.proxy.HibernateProxy;

@Entity
@Table(name = "oauth2_client")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class OAuth2RegisteredClientEntity extends BaseEntity {

    @Id
    @Column(length = 36, nullable = false)
    private String id;

    @Column(name = "client_id", length = 255, nullable = false)
    private String clientId;

    @Column(name = "client_id_issued_at", nullable = false)
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret", length = 255)
    private String clientSecret;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    @Column(name = "client_name", length = 255, nullable = false)
    private String clientName;

    @Column(name = "client_authentication_methods", length = 255, nullable = false)
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types", length = 255, nullable = false)
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris", length = 255)
    private String redirectUris;

    @Column(name = "post_logout_redirect_uris", length = 255)
    private String postLogoutRedirectUris;

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<OAuth2ClientScopeMappingEntity> clientScopes = new HashSet<>();

    @Column(name = "client_settings", length = 4000, nullable = false)
    private String clientSettings;

    @Column(name = "token_settings", length = 4000, nullable = false)
    private String tokenSettings;

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof OAuth2RegisteredClientEntity otherClient)) {
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
        return id != null && Objects.equals(id, otherClient.id);
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
            : getClass().hashCode();
    }
}
