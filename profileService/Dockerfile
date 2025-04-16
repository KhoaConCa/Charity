FROM maven:3.9.8-amazoncorretto-21 AS build

WORKDIR /app
COPY pom.xml /app/profile/
COPY src /app/profile/src

WORKDIR /app/profile
RUN mvn clean package -DskipTests

FROM amazoncorretto:21.0.4

WORKDIR /app
COPY --from=build /app/profile/target/*.jar /app/profile/app.jar

COPY .env /app/profile/.env

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "/app/profile/app.jar"]