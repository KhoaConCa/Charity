package com.tuandanh.notificationService.repository.httpClient;

import com.tuandanh.notificationService.configuration.AuthenticationRequestInterceptor;
import com.tuandanh.notificationService.configuration.FeignConfig;
import com.tuandanh.notificationService.dto.ApiResponse;
import com.tuandanh.notificationService.dto.response.ProfileResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "profile-service", contextId = "profileServiceClientForPost", url = "${app.service.profile}",
        configuration = {FeignConfig.class, AuthenticationRequestInterceptor.class})
public interface UserProfileClient {

    @GetMapping(value = "/internal/userProfiles/{profileId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    ApiResponse<ProfileResponse> getProfile(@PathVariable String profileId);

}
