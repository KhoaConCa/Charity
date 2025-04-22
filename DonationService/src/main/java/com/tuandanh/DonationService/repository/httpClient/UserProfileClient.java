package com.tuandanh.DonationService.repository.httpClient;

import com.tuandanh.DonationService.configuration.AuthenticationRequestInterceptor;
import com.tuandanh.DonationService.configuration.FeignConfig;
import com.tuandanh.DonationService.dto.ApiResponse;
import com.tuandanh.DonationService.dto.response.ProfileResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "profile-service", contextId = "profileServiceClientForDonation",
        url = "${app.service.profile}",
        configuration = {FeignConfig.class, AuthenticationRequestInterceptor.class})
public interface UserProfileClient {
    @GetMapping(value = "/internal/userProfiles/{profileId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    ApiResponse<ProfileResponse> getProfile(@PathVariable String profileId);
}
