package io.github.susimsek.springauthorizationserver.entity;

import io.github.susimsek.springauthorizationserver.cache.CacheName;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.Instant;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

@Entity
@Table(name = "user_session")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE, region = CacheName.USER_SESSION_ENTITY_CACHE)
public class UserSessionEntity implements Serializable {

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @Column(name = "session_id", length = 36, nullable = false, unique = true)
    private String sessionId;

    @Column(name = "creation_time", nullable = false)
    private Instant creationTime;

    @Column(name = "last_access_time", nullable = false)
    private Instant lastAccessTime;

    @Column(name = "max_inactive_interval", nullable = false)
    private int maxInactiveInterval;

    @Column(name = "expiry_time", nullable = false)
    private Instant expiryTime;

    @Column(name = "principal_name", length = 200)
    private String principalName;

    @OneToMany(mappedBy = "session", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @Cache(usage = CacheConcurrencyStrategy.READ_WRITE,
        region = CacheName.USER_SESSION_ENTITY_CACHE + ".attributes")
    private Set<UserSessionAttributeEntity> attributes;
}
