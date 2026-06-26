# syntax=docker/dockerfile:1.4

# Stage 1 – clone & install totp library from GitHub
FROM maven:3.9-eclipse-temurin-21 AS totp-builder
WORKDIR /build
RUN git clone --depth=1 https://github.com/svinstvo-og/totp-starter.git .
RUN --mount=type=cache,target=/root/.m2 \
    mvn install -DskipTests -B --no-transfer-progress

# Stage 2 – build auth-portal (totp SNAPSHOT is in the shared cache mount)
FROM maven:3.9-eclipse-temurin-21 AS app-builder
WORKDIR /build
COPY pom.xml .
COPY src src
RUN --mount=type=cache,target=/root/.m2 \
    mvn package -DskipTests -B --no-transfer-progress

# Stage 3 – slim runtime image
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=app-builder /build/target/auth-portal-1.0.0-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
