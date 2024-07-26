package io.github.susimsek.springauthorizationserver.exception;

import org.springframework.http.HttpStatus;

public class ResourceConflictException extends ResourceException {
    public ResourceConflictException(String resourceName, String searchCriteria, Object searchValue) {
        super("resource_conflict", "error.oauth2.resource_conflict",
            HttpStatus.CONFLICT, resourceName, searchCriteria, searchValue);
    }
}
