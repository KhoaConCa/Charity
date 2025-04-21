FROM maven:3.9.8-amazoncorretto-21 AS build

WORKDIR /app
COPY pom.xml /app/donation/
COPY src /app/donation/src

WORKDIR /app/donation
RUN mvn clean package -DskipTests

FROM amazoncorretto:21.0.4

WORKDIR /app
COPY --from=build /app/donation/target/*.jar /app/donation/app.jar

COPY .env /app/donation/.env

EXPOSE 8084

ENTRYPOINT ["java", "-jar", "/app/donation/app.jar"]