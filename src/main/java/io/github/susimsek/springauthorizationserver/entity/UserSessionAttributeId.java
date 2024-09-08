package io.github.susimsek.springauthorizationserver.entity;

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
public class UserSessionAttributeId implements Serializable {
    private String sessionId;
    private String attributeName;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UserSessionAttributeId that = (UserSessionAttributeId) o;
        return Objects.equals(sessionId, that.sessionId) &&
            Objects.equals(attributeName, that.attributeName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId, attributeName);
    }
}
