# Auth Service

A robust, secure, and scalable Authentication Service built with Spring Boot. This service handles user authentication, authorization, role-based access control (RBAC), and session management for the application ecosystem.

## 🚀 Features

- **JWT Authentication** - Secure token-based authentication using RS256 asymmetric keys (Access & Refresh tokens).
- **Role-Based Access Control (RBAC)** - Comprehensive hierarchical roles including `SUPER_ADMIN`, `ADMIN`, `MANAGER`, `STAFF`, and `ENGINEER`.
- **Backend-for-Frontend (BFF) Ready** - Built to integrate seamlessly with a BFF gateway proxy.
- **Device Fingerprinting** - Advanced security to prevent token theft and replay attacks.
- **Login Attempt Tracking** - Automatic account lockouts to prevent brute-force attacks.
- **Cloud Database Ready** - Configured for Neon PostgreSQL serverless databases with optimized connection pooling.

## 🛠️ Technology Stack

- **Java 21**
- **Spring Boot 3.3.5**
  - Spring Security
  - Spring Data JPA
  - Spring Web
- **Database**: PostgreSQL (Cloud-hosted via Neon)
- **Database Migrations**: Hibernate DDL Auto
- **Build Tool**: Maven

## 📦 Getting Started

### Prerequisites
- JDK 21
- Maven
- PostgreSQL Database (Local or Neon Cloud)

### Environment Variables
Before running the application, set the following environment variables or add them to your `config/application.properties`:

```properties
spring.datasource.url=jdbc:postgresql://<your-db-url>?sslmode=require&connectTimeout=60&socketTimeout=60
spring.datasource.username=<your_db_username>
spring.datasource.password=<your_db_password>
```

### Running the Service

```bash
# Compile and build the project
./mvnw clean install

# Run the Spring Boot application
./mvnw spring-boot:run
```
The service will start on `http://localhost:8080`.

## 🔐 Key API Endpoints

### Public Endpoints
- `POST /auth/login` - Authenticate user and issue JWT tokens.
- `POST /auth/setup-password` - Set up a password using a setup token.
- `POST /auth/refresh-token` - Issue a new access token using a valid refresh token.
- `POST /auth/logout` - Revoke tokens and log out the user.

### Admin/Internal Endpoints
*(Requires `SUPER_ADMIN`, `ADMIN`, or `MANAGER` role)*
- `POST /admin/api/users/internal` - Create an internal staff/engineer user.
- `PUT /admin/api/users/{id}/approve` - Approve a user account.

## 🏗️ Architecture Note
This service is designed to sit behind a **BFF (Backend-for-Frontend)** Gateway. Direct client communication should generally route through the BFF, which handles cookie management and token injection.

## 📄 License
This project is part of the Professional Portfolio Module.
