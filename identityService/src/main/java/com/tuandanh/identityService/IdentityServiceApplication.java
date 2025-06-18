package com.tuandanh.identityService;

import io.github.cdimascio.dotenv.Dotenv;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

import java.util.Objects;

@Slf4j
@SpringBootApplication
@EnableFeignClients
public class IdentityServiceApplication {

	public static void main(String[] args) {
		// Load .env file
		Dotenv dotenv = Dotenv.configure()
				.directory("identityService") // Chỉ định thư mục chứa .env
				.filename(".env") // Đảm bảo tên file đúng
				.load();

		if(Objects.isNull(dotenv)){
			log.error("Failed to load env");
		}
		dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), entry.getValue()));

		SpringApplication.run(IdentityServiceApplication.class, args);
	}

}
