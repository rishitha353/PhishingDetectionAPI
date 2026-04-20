# Use a Maven image to build the application
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copy the Maven project file and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy the source code and build the JAR
COPY src src
RUN mvn clean package -DskipTests

# Use a slim Java runtime to run the app
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

# Copy the built JAR from the previous stage
COPY --from=build /app/target/*.jar app.jar

# This line explicitly adds the PostgreSQL driver JAR to the image
ADD https://jdbc.postgresql.org/download/postgresql-42.7.4.jar /app/postgresql.jar

# Run the application with both the app JAR and the PostgreSQL driver in the classpath
ENTRYPOINT ["java", "-cp", "app.jar:postgresql.jar", "org.springframework.boot.loader.JarLauncher"]