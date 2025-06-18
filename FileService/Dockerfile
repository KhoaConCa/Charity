# Sử dụng image nhẹ để chạy Java
FROM eclipse-temurin:17-jdk-alpine

# Thư mục chứa app trong container
WORKDIR /app

# Copy file JAR đã đóng gói từ host vào container
COPY target/FileService-0.0.1-SNAPSHOT.jar app.jar

# Cấu hình lệnh để chạy ứng dụng Spring Boot
ENTRYPOINT ["java", "-jar", "app.jar"]
