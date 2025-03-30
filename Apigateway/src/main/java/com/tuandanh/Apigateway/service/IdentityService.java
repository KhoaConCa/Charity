package com.tuandanh.Apigateway.service;

import com.tuandanh.Apigateway.dto.ApiResponse;
import com.tuandanh.Apigateway.dto.request.IntrospectRequest;
import com.tuandanh.Apigateway.dto.response.IntrospectResponse;
import com.tuandanh.Apigateway.repository.IdentityClient;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class IdentityService {
    IdentityClient identityClient;

    public Mono<ApiResponse<IntrospectResponse>> introspect(String token){
        IntrospectRequest request = IntrospectRequest.builder()
                .token(token)
                .build();

        return identityClient.introspect(request);
    }
}
