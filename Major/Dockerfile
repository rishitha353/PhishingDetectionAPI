FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src src
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

# Copy the built jar
COPY --from=build /app/target/*.jar app.jar

# Download PostgreSQL driver explicitly (fallback)
ADD https://jdbc.postgresql.org/download/postgresql-42.7.4.jar /app/postgresql.jar

# Run with both jars
EXPOSE 8080
ENTRYPOINT ["java", "-cp", "app.jar:postgresql.jar", "org.springframework.boot.loader.JarLauncher"]