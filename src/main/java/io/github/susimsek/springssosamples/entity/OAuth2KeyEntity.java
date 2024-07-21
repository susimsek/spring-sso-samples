package io.github.susimsek.springssosamples.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import io.github.susimsek.springssosamples.cache.CacheName;
import org.hibernate.proxy.HibernateProxy;

@Entity
@Table(name = "oauth2_key")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE, region = CacheName.OAUTH2_KEY_ENTITY_CACHE)
public class OAuth2KeyEntity extends BaseEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "type", length = 255, nullable = false)
    private String type;

    @Column(name = "algorithm", length = 255, nullable = false)
    private String algorithm;

    @Column(name = "public_key", length = 2048)
    private String publicKey;

    @Column(name = "private_key", length = 2048)
    private String privateKey;

    @Column(name = "active", nullable = false)
    private boolean active;

    @Column(name = "kid", length = 255, nullable = false)
    private String kid;

    @Column(name = "use", length = 255)
    private String use;

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof OAuth2KeyEntity other)) {
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
        return Objects.equals(id, other.id);
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
            : Objects.hash(id);
    }
}
