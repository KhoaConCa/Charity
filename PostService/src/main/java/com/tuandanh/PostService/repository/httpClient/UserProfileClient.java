package com.tuandanh.PostService.repository.httpClient;

import com.tuandanh.PostService.configuration.AuthenticationRequestInterceptor;
import com.tuandanh.PostService.configuration.FeignConfig;
import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.response.FriendshipResponse;
import com.tuandanh.PostService.dto.response.ProfileResponse;
import io.swagger.v3.oas.annotations.Parameter;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.List;

@FeignClient(name = "profile-service", url = "${app.service.profile}",
        configuration = {FeignConfig.class, AuthenticationRequestInterceptor.class})
public interface UserProfileClient {
    @GetMapping(value = "/friends", consumes = MediaType.APPLICATION_JSON_VALUE)
    ApiResponse<List<FriendshipResponse>> getFriends(
            @RequestHeader("Authorization") String authorization);

    @GetMapping(value = "/{profileId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    ApiResponse<ProfileResponse> getProfile(@PathVariable String profileId);

    @GetMapping("/userProfiles/get-active-profile/{userId}")
    ApiResponse<String> getActiveProfile(
            @PathVariable String userId);
}
