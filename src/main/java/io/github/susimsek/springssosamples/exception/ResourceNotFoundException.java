package io.github.susimsek.springssosamples.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends ResourceException {

    public ResourceNotFoundException(String resourceName, String searchCriteria, Object searchValue) {
        super("resource_not_found", "error.oauth2.resource_not_found",
            HttpStatus.NOT_FOUND, resourceName, searchCriteria, searchValue);
    }

}
