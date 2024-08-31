# Spring Authorization Server Samples

![Introduction](https://github.com/susimsek/spring-sso-samples/blob/main/images/introduction.png)

## Overview

Spring Authorization Server is a framework that provides implementations of the OAuth 2.1 and OpenID Connect 1.0 specifications and other related specifications. It is built on top of Spring Security to provide a secure, light-weight, and customizable foundation for building OpenID Connect 1.0 Identity Providers and OAuth2 Authorization Server products.

## Registered Clients

This server comes with predefined registered OAuth2/OIDC clients:

| Client ID          | Client-Secret | Access Token Format |
|--------------------|---------------|---------------------|
| oidc-client        | secret        | JWE                 |
| oidc-client-opaque | secret        | Opaque              |

ll clients have configured the following redirect URI

* http://127.0.0.1:8080/login/oauth2/code/oidc-client

## Login

This server already has preconfigured users.
Therefore, to login please use one of these predefined credentials:

| Username | Email                    | Password | Roles  |
|----------|--------------------------|----------|--------|
| user     | user@example.com         | password | USER   |
| admin    | admin@example.com        | password | ADMIN  |

## Prerequisites

- Java 17
- Maven 3.x

## Build

To install dependencies and build the project, run the following command:

```sh
mvn clean install
```

## Testing

To run the application's tests, use the following command:

```sh
mvn verify
```

## Code Quality

To assess code quality locally using SonarQube, execute:

```sh
mvn -Psonar compile initialize sonar:sonar
```

## Checkstyle

To check the code style using Checkstyle, execute:

```sh
mvn checkstyle:check
```

## Docker

The sample applications can also be fully dockerized. To achieve this, first build a Docker image of your app:

```sh
mvn verify jib:dockerBuild
```

## Kubernetes

To deploy the application on a Kubernetes cluster using Helm, follow these steps:

Install PostgreSQL using Helm:

```sh
helm install postgresql bitnami/postgresql --values deploy/helm/postgresql/values.yaml --version 12.11.1
```

Install Spring Authorization Server using Helm:

```sh
helm install spring-authorization-server deploy/helm/spring-authorization-server
```

To uninstall and delete the deployments, use the following commands:

Uninstall PostgreSQL:

```sh
helm uninstall postgresql
```

Uninstall Spring Authorization Server:

```sh
helm uninstall spring-authorization-server
```

## Documentation

For API documentation, please refer to the Swagger UI:

http://localhost:7080/swagger-ui.html

## ER Diagram

Below is the ER Diagram used for the project:

![ER Diagram](https://github.com/susimsek/spring-sso-samples/blob/main/images/er-diagram.png)

## Used Technologies

- Java 17
- Checkstyle
- SonarQube
- Docker
- Kubernetes
- Helm
- Sonarqube
- GitHub Actions
- Spring Boot 3.x
- Spring Boot Starter Web
- Spring Boot Starter Validation
- Spring Boot Starter Data JPA
- Spring Boot Starter OAuth2 Authorization Server
- Spring Boot Starter Security
- Spring Security OAuth2 Jose
- Spring Boot Starter AOP
- Spring Boot Starter Cache
- Spring Boot Starter Thymeleaf
- Spring Boot Actuator
- Spring Boot Configuration Processor
- Spring Session JDBC
- SpringDoc OpenAPI Starter WebMVC UI
- Liquibase
- PostgreSQL
- H2
- Spring Boot DevTools
- Caffeine Cache
- Hibernate Jpamodelgen
- Hibernate JCache
- Lombok
- Mapstruct
- Micrometer Tracing
- Micrometer Tracing Bridge OTel
- Logback Appender For Loki
- Bootstrap
- Font Awesome
