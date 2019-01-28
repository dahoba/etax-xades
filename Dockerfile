# STAGE 1: Builder
FROM maven:3.5.2-alpine as builder
LABEL maintainer siritas<siritas@gmail.com>

ENV JAVA_OPTS=""
ENV MAVEN_OPTS="-XX:+TieredCompilation -XX:TieredStopAtLevel=1"

RUN mkdir -p /usr/src/etax-xades
WORKDIR /usr/src/etax-xades

COPY pom.xml .
RUN mvn -B --fail-never verify clean

COPY src src

RUN mvn -B -Dmaven.test.skip=true verify

### STAGE 2: Running
FROM openjdk:8-jre-alpine
RUN mkdir -p /usr/app/etax-xades
COPY --from=builder /usr/src/etax-xades/target/signxml-1.0.0.jar /usr/app/etax-xades/

EXPOSE 8080
ENV JAVA_OPTS=" -noverify -server -Xms128m"
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom", "-jar" ,"/usr/app/etax-xades/signxml-1.0.0.jar"]
