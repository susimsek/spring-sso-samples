# Spring SSO Samples

## Overview

Spring Authorization Server is a framework that provides implementations of the OAuth 2.1 and OpenID Connect 1.0 specifications and other related specifications. It is built on top of Spring Security to provide a secure, light-weight, and customizable foundation for building OpenID Connect 1.0 Identity Providers and OAuth2 Authorization Server products.

## Prerequisites

- Java 17
- Kotlin
- Maven 3.x
- Open AI

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

## Used Technologies

- Java 17
- Docker
- Sonarqube
- Spring Boot 3.x
- Spring Boot Web
- Spring Boot Validation
- Spring Boot Jpa
- Spring Boot OAuth2 Authorization Server
- Spring Boot Security
- Liquibase
- Hibernate Jpamodelgen
- Spring Boot Actuator
- Lombok
- Mapstruct
- Springdoc