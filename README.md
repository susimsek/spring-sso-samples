# Spring Authorization Server Samples

## Overview

Spring Authorization Server is a framework that provides implementations of the OAuth 2.1 and OpenID Connect 1.0 specifications and other related specifications. It is built on top of Spring Security to provide a secure, light-weight, and customizable foundation for building OpenID Connect 1.0 Identity Providers and OAuth2 Authorization Server products.

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

## Docker

The sample applications can also be fully dockerized. To achieve this, first build a Docker image of your app:

```sh
mvn verify jib:dockerBuild
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
