FROM maven:3.9.8-amazoncorretto-21 AS build

WORKDIR /app
COPY pom.xml /app/post/
COPY src /app/post/src

WORKDIR /app/post
RUN mvn clean package -DskipTests

FROM amazoncorretto:21.0.4

WORKDIR /app
COPY --from=build /app/post/target/*.jar /app/post/app.jar

COPY .env /app/post/.env

EXPOSE 8083

ENTRYPOINT ["java", "-jar", "/app/post/app.jar"]