package io.github.susimsek.springssosamples.entity;
import io.github.susimsek.springssosamples.cache.CacheName;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import java.util.Objects;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.proxy.HibernateProxy;

@Entity
@Table(name = "oauth2_client_scope_mapping")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE, region = CacheName.OAUTH2_CLIENT_SCOPE_MAPPING_ENTITY_CACHE)
public class OAuth2ClientScopeMappingEntity extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sequenceGenerator")
    @SequenceGenerator(name = "sequenceGenerator", sequenceName = "seq_oauth2_client_scope_mapping", allocationSize = 1)
    @Column(name = "id", nullable = false, updatable = false)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2RegisteredClientEntity client;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scope_id", nullable = false)
    private OAuth2ScopeEntity scope;

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof OAuth2ClientScopeMappingEntity otherMapping)) {
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
        return id != null && Objects.equals(id, otherMapping.id);
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
            : getClass().hashCode();
    }
}
