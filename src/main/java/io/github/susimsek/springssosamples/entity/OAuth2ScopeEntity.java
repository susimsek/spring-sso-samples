package io.github.susimsek.springssosamples.entity;

import io.github.susimsek.springssosamples.cache.CacheName;
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
import org.hibernate.proxy.HibernateProxy;

@Entity
@Table(name = "oauth2_scope")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE, region = CacheName.OAUTH2_SCOPE_ENTITY_CACHE)
public class OAuth2ScopeEntity extends BaseEntity {

    @Id
    @Column(length = 36, nullable = false)
    private String id;

    @Column(name = "scope", length = 255, nullable = false)
    private String scope;

    @Column(length = 255)
    private String description;

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof OAuth2ScopeEntity otherScope)) {
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
        return id != null && Objects.equals(id, otherScope.id);
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
            : getClass().hashCode();
    }
}
