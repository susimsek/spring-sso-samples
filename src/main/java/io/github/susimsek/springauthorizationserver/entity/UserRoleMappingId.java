package io.github.susimsek.springauthorizationserver.entity;

import jakarta.persistence.Column;
import java.io.Serializable;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserRoleMappingId implements Serializable {

    @Column(name = "user_id", length = 36, nullable = false)
    private String userId;

    @Column(name = "role_id", length = 36, nullable = false)
    private String roleId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserRoleMappingId that = (UserRoleMappingId) o;
        return Objects.equals(userId, that.userId) &&
               Objects.equals(roleId, that.roleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, roleId);
    }
}
