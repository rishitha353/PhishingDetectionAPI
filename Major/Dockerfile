FROM eclipse-temurin:17-jdk-focal

WORKDIR /app

# Copy Maven files
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Download dependencies
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src src

# Build the JAR file
RUN ./mvnw package -DskipTests

# Run the application
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "target/*.jar"]