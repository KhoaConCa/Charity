package com.tuandanh.identityService.repository.httpclient;

import com.tuandanh.identityService.configuration.AuthenticationRequestInterceptor;
import com.tuandanh.identityService.dto.request.ProfileCreationRequest;
import com.tuandanh.identityService.dto.response.ProfileResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "profile-service", url = "${app.service.profile}",
        configuration = {AuthenticationRequestInterceptor.class})
public interface ProfileClient {
    @PostMapping(value = "/internal/userProfiles", consumes = MediaType.APPLICATION_JSON_VALUE)
    ProfileResponse createProfile(
            @RequestHeader String token,
            @RequestBody ProfileCreationRequest profileCreationRequest);
}
