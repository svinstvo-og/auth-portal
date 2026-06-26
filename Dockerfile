# syntax=docker/dockerfile:1.4

# Build stage – install totp library, then build auth-portal (sequential, same stage)
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build/totp
RUN git clone --depth=1 https://github.com/svinstvo-og/totp-starter.git .
RUN --mount=type=cache,target=/root/.m2 \
    mvn install -DskipTests -B --no-transfer-progress

WORKDIR /build/app
COPY pom.xml .
COPY src src
RUN --mount=type=cache,target=/root/.m2 \
    mvn package -DskipTests -B --no-transfer-progress

# Runtime stage – slim JRE only
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=builder /build/app/target/auth-portal-1.0.0-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
