package com.tuandanh.Apigateway.configuration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tuandanh.Apigateway.dto.ApiResponse;
import com.tuandanh.Apigateway.service.IdentityService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

@Component
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${app.api-prefix}")
    @NonFinal
    String API_PREFIX;

    IdentityService identityService;
    ObjectMapper mapper = new ObjectMapper();
    private static final Set<String> PUBLIC_ENDPOINTS1 = Set.of(
            "/users",
            "/auth/token",
            "/auth/introspect",
            "/auth/forgot-password",
            "/auth/reset-password",
            "/auth/send-otp",
            "/auth/verify-otp",
            "/oauth2/authorization/google",
            "/oauth2/authorization/facebook",
            "/auth/send-verify-email",
            "/users/registration",
            "/confirm-verify-email",

            // Swagger URLs
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/api/v1.0.0/identity/v3/api-docs",
            "/api/v1.0.0/profile/v3/api-docs"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (isPublicEndpoint(path)) {
            return chain.filter(exchange);
        }
        List<String> authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);

        // Check if Authorization header is missing
        if (CollectionUtils.isEmpty(authHeader) || authHeader.getFirst().isBlank()) {
            log.warn("Missing Authorization header");

            return unauthenticated(exchange.getResponse());
        }

        String token = authHeader.getFirst().replace("Bearer", "");

        return identityService.introspect(token).flatMap(introspectResponseApiResponse -> {
            if(introspectResponseApiResponse.getResult().isValid())
                return chain.filter(exchange);
            else
                return unauthenticated(exchange.getResponse());
        });
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private boolean isPublicEndpoint(String path) {
        return PUBLIC_ENDPOINTS1.stream()
                .anyMatch(publicPath -> path.startsWith(API_PREFIX) && path.contains(publicPath));
    }

    private Mono<Void> unauthenticated(ServerHttpResponse response){
        ApiResponse<?> apiResponse = ApiResponse.builder()
                .code(1401)
                .message("Unauthenticated")
                .build();

        String body = null;
        try {
            body = mapper.writeValueAsString(apiResponse);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }
}
