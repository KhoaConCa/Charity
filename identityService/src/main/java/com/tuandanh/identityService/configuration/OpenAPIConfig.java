package com.tuandanh.identityService.configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenAPIConfig {

    @Value("${openapi.title}")
    private String title;

    @Value("${openapi.description}")
    private String description;

    @Value("${openapi.version}")
    private String version;

    @Value("${openapi.license.name}")
    private String licenseName;

    @Value("${openapi.license.url}")
    private String licenseUrl;

    @Value("${openapi.server.url}")
    private String serverUrl;

    @Value("${openapi.server.description}")
    private String serverDescription;


    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title(title)
                        .version(version)
                        .description(description)
                        .license(new License()
                                .name(licenseName)
                                .url(licenseUrl)
                        )
                )
                .servers(List.of(new Server()
                        .url(serverUrl)
                        .description(serverDescription)
                ))
                .components(
                        new Components()
                                .addSecuritySchemes(
                                        "bearerAuth",
                                        new SecurityScheme()
                                                .type(SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .bearerFormat("JWT")
                                )
                ).security(List.of(new SecurityRequirement().addList("bearerAuth")));
    }

    @Bean
    public GroupedOpenApi groupedOpenApi() {
        return GroupedOpenApi.builder()
                .group("identity-service")
                .packagesToScan("com.tuandanh.identityService")
                .build();
    }
}
