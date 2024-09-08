package io.github.susimsek.springauthorizationserver.entity;


import io.github.susimsek.springauthorizationserver.cache.CacheName;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
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
@Table(name = "user_role_mapping")
@IdClass(UserRoleMappingId.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE, region = CacheName.USER_ROLE_MAPPING_ENTITY_CACHE)
public class UserRoleMappingEntity extends BaseEntity {

    @Id
    @Column(name = "user_id", length = 36, nullable = false)
    private String userId;

    @Id
    @Column(name = "role_id", length = 36, nullable = false)
    private String roleId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private UserEntity user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", insertable = false, updatable = false)
    private RoleEntity role;

    @Override
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UserRoleMappingEntity other)) {
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
        return userId != null && Objects.equals(userId, other.userId) &&
            roleId != null && Objects.equals(roleId, other.roleId);
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
            ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
            : Objects.hash(userId, roleId);
    }
}
