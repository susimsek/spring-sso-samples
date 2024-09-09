# Spring Authorization Server Sample

![Spring Authorization Server](https://github.com/susimsek/spring-sso-samples/blob/main/images/introduction.png)

## Overview
Spring Authorization Server provides a secure and customizable foundation for building OAuth2 Authorization Servers and OpenID Connect Identity Providers. It’s built on top of Spring Security, supporting OAuth 2.1 and OpenID Connect 1.0 specifications.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Java 22**
- **Maven 3.x**
- **Docker** (for running dependencies like PostgreSQL etc.)
- **Kubernetes** (if deploying to a Kubernetes cluster)

## Usage

### Registered Clients

This server comes with predefined registered OAuth2/OIDC clients:

| Client ID               | Client-Secret | Access Token Format |
|-------------------------|---------------|---------------------|
| oidc-client             | secret        | JWE                 |
| oidc-client-pkce        | secret        | JWE                 |
| oidc-client-jwt         | secret        | JWT                 |
| oidc-client-pkce-jwt    | secret        | JWT                 |
| oidc-client-opaque      | secret        | Opaque              |
| oidc-client-pkce-opaque | secret        | Opaque              |

All clients use the following redirect URI for OAuth2 callbacks:

* http://127.0.0.1:8080/login/oauth2/code/oidc-client

### Login

This server already has preconfigured users.
Therefore, to login please use one of these predefined credentials:

| Username | Email                    | Password | Roles  |
|----------|--------------------------|----------|--------|
| user     | user@example.com         | password | USER   |
| admin    | admin@example.com        | password | ADMIN  |

### OAuth2 Endpoints

The following OAuth2 Authorization Server endpoints are available:

| Method | Endpoint                          | Description              |
|--------|-----------------------------------|--------------------------|
| GET    | /oauth2/authorize                 | Authorize                |
| GET    | /oauth2/jwks                      | JWKS                     |
| GET    | /.well-known/openid-configuration | OpenID Connect Discovery |
| GET    | /userinfo                         | User Info                |
| POST   | /oauth2/token                     | Token                    |
| POST   | /oauth2/revoke                    | Revoke Token             |
| POST   | /oauth2/introspect                | Introspect Token         |

## Build

To install dependencies and build the project, run the following command:

```sh
mvn clean install
```

## Run the Application

To run the application locally with an in-memory H2 database, run the following command:

```sh
mvn spring-boot:run
```

Access H2 Console:
You can access the H2 console at:

http://localhost:7080/h2-console

Use the following credentials to log in:

| Field    | Value                                                                      |
|----------|----------------------------------------------------------------------------|
| JDBC URL | `jdbc:h2:mem:sso;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE` |
| Username | `admin`                                                                    |
| Password | `password`                                                                 |

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

## Deployment

### Docker Deployment

The application can also be fully dockerized. To achieve this, first build a Docker image of your app:

```sh
mvn verify jib:dockerBuild
```

To deploy the application and dependencies (PostgreSQL) using Docker Compose for a production environment, follow these steps:

From the root directory of the project, use Docker Compose to deploy the application:

```sh
docker-compose -f deploy/docker-compose/prod/docker-compose.yml up -d
```

After the containers are up and running, check the logs to ensure everything is working as expected:

```sh
docker-compose -f deploy/docker-compose/prod/docker-compose.yml logs -f
```

To stop the containers, run the following command:

```sh
docker-compose -f deploy/docker-compose/prod/docker-compose.yml down
```

### Kubernetes Deployment

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

- Java 22
- Spring Boot 3.x
- Docker
- Kubernetes
- Checkstyle
- SonarQube
- Helm
- Sonarqube
- GitHub Actions
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
