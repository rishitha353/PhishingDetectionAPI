# ---- Build Stage ----
# Use an official Maven image to build the application
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copy the Maven project file and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy the source code and build the executable JAR file
COPY src src
RUN mvn clean package -DskipTests

# ---- Run Stage ----
# Use a slim Java runtime image to run the application
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

# Copy the built JAR file from the previous stage
COPY --from=build /app/target/*.jar app.jar

# Expose the port your application runs on
EXPOSE 8080

# Run the JAR file. The 'exec' form is used for proper signal handling.
ENTRYPOINT ["java", "-jar", "app.jar"]