# ---- Build Stage ----
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build the JAR
COPY src src
RUN mvn clean package -DskipTests

# ---- Run Stage ----
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

# Copy the built JAR from the build stage
COPY --from=build /app/target/*.jar app.jar

# Download the PostgreSQL JDBC driver JAR directly
ADD https://jdbc.postgresql.org/download/postgresql-42.7.4.jar /app/postgresql.jar

# Run the application with both JARs in the classpath
ENTRYPOINT ["java", "-cp", "app.jar:postgresql.jar", "org.springframework.boot.loader.JarLauncher"]