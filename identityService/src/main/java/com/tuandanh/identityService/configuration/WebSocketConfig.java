package com.tuandanh.identityService.configuration;

import com.tuandanh.identityService.interceptor.JwtHandshakeInterceptor;
import com.tuandanh.identityService.websocket.UserWebSocketHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final UserWebSocketHandler userWebSocketHandler;
    private final JwtHandshakeInterceptor jwtHandshakeInterceptor;

    public WebSocketConfig(UserWebSocketHandler userWebSocketHandler, JwtHandshakeInterceptor jwtHandshakeInterceptor) {
        this.userWebSocketHandler = userWebSocketHandler;
        this.jwtHandshakeInterceptor = jwtHandshakeInterceptor;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(userWebSocketHandler, "/ws")
                .setAllowedOrigins("*")
                .addInterceptors(jwtHandshakeInterceptor);
    }
}

