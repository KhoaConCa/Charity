FROM maven:3.9.8-amazoncorretto-21 AS build

WORKDIR /app
COPY pom.xml /app/gateway/
COPY src /app/gateway/src

WORKDIR /app/gateway
RUN mvn clean package -DskipTests

FROM amazoncorretto:21.0.4

WORKDIR /app
COPY --from=build /app/gateway/target/*.jar /app/gateway/app.jar

EXPOSE 8888

ENTRYPOINT ["java", "-jar", "/app/gateway/app.jar"]