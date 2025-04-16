FROM maven:3.9.8-amazoncorretto-21 AS build

WORKDIR /app
COPY pom.xml /app/file/
COPY src /app/file/src

WORKDIR /app/file
RUN mvn clean package -DskipTests

FROM amazoncorretto:21.0.4

WORKDIR /app
COPY --from=build /app/file/target/*.jar /app/file/app.jar

COPY .env /app/file/.env

EXPOSE 8084

ENTRYPOINT ["java", "-jar", "/app/file/app.jar"]