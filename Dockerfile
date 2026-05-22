# Build stage
FROM maven:3.9.6-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
# Build the application, skipping tests for faster deployment
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
# Copy the built jar from the build stage
COPY --from=build /app/target/*.jar app.jar

# Expose the default Auth Service port
EXPOSE 8080

# Run the jar file
ENTRYPOINT ["java", "-jar", "app.jar"]
