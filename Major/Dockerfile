FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build the jar
COPY src src
RUN mvn clean package -DskipTests

# Use a slim Java image to run the app
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

# Copy the built jar from the build stage
COPY --from=build /app/target/*.jar app.jar

# List the contents of the jar to verify PostgreSQL driver is included
RUN jar tf app.jar | grep postgresql

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]