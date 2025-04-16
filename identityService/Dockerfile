FROM maven:3.9.8-amazoncorretto-21 AS build

WORKDIR /app
COPY pom.xml /app/identity/
COPY src /app/identity/src

WORKDIR /app/identity
RUN mvn clean package -DskipTests

FROM amazoncorretto:21.0.4

WORKDIR /app
COPY --from=build /app/identity/target/*.jar /app/identity/app.jar

COPY .env /app/identity/.env

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/identity/app.jar"]