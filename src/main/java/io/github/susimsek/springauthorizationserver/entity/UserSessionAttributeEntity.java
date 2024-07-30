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
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.CacheConcurrencyStrategy;

@Entity
@Table(name = "user_session_attributes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@IdClass(UserSessionAttributeId.class)
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE, region = CacheName.USER_SESSION_ATTRIBUTE_ENTITY_CACHE)
public class UserSessionAttributeEntity extends DateAuditingEntity {

    @Id
    @Column(name = "session_id", length = 36)
    private String sessionId;

    @Id
    @Column(name = "attribute_name", length = 200)
    private String attributeName;

    @Column(name = "attribute_bytes", nullable = false)
    private byte[] attributeBytes;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", insertable = false, updatable = false)
    private UserSessionEntity session;
}
