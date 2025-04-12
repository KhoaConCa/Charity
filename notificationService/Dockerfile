FROM maven:3.9.8-amazoncorretto-21 AS build

WORKDIR /app
COPY pom.xml /app/notification/
COPY src /app/notification/src

WORKDIR /app/notification
RUN mvn clean package -DskipTests

FROM amazoncorretto:21.0.4

WORKDIR /app
COPY --from=build /app/notification/target/*.jar /app/notification/app.jar

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "/app/notification/app.jar"]