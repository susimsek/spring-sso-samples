package io.github.susimsek.springssosamples.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.hibernate.proxy.HibernateProxy;

@Entity
@Table(name = "oauth2_authorization_consent")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@IdClass(OAuth2AuthorizationConsentId.class)
public class OAuth2AuthorizationConsentEntity extends BaseEntity implements Serializable {

    @Id
    @Column(name = "registered_client_id", length = 100, nullable = false)
    private String registeredClientId;

    @Id
    @Column(name = "principal_name", length = 200, nullable = false)
    private String principalName;

    @Column(name = "authorities", length = 1000, nullable = false)
    private String authorities;

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof OAuth2AuthorizationConsentEntity other)) {
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
        return Objects.equals(registeredClientId, other.registeredClientId) &&
               Objects.equals(principalName, other.principalName);
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
            : Objects.hash(registeredClientId, principalName);
    }
}