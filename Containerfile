FROM registry.access.redhat.com/ubi9/openjdk-17:1.20 AS builder
USER 0
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -B clean package -DskipTests

FROM registry.access.redhat.com/ubi9/openjdk-17-runtime:1.20
COPY --from=builder /build/target/help-im-vulnerable-*.jar /deployments/app.jar
COPY --from=builder /build/target/bom.json /deployments/maven-sbom.json
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/deployments/app.jar"]
