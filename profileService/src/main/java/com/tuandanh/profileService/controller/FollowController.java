package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.FollowRequest;
import com.tuandanh.profileService.dto.response.FollowResponse;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.service.FollowService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/follow")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FollowController {
    FollowService followService;

    @GetMapping("/{profileId}")
    public ApiResponse<List<UserProfile>> getFollowingProfiles(
            @PathVariable String profileId, Authentication authentication) {
        List<UserProfile> followingProfiles = followService.getFollowingProfiles(profileId, authentication);

        return ApiResponse.<List<UserProfile>>builder()
                .result(followingProfiles)
                .build();
    }

    @PostMapping
    public ApiResponse<FollowResponse> followProfile(
            @RequestBody FollowRequest followRequest, Authentication authentication){
        FollowResponse followResponse = followService.followProfile(followRequest, authentication);

        return ApiResponse.<FollowResponse>builder()
                .result(followResponse)
                .build();
    }

    @DeleteMapping("/{followingId}/unfollow")
    public ApiResponse<String> unfollowProfile(
            @PathVariable String followingId, Authentication authentication){
        followService.unfollowProfile(followingId, authentication);

        return ApiResponse.<String>builder()
                .result("Unfollowed successfully")
                .build();
    }

    @GetMapping("/followers/{profileId}")
    public ApiResponse<List<UserProfile>> getFollowers(
            @PathVariable String profileId, Authentication authentication){
        List<UserProfile> followers = followService.getFollowers(profileId, authentication);

        return ApiResponse.<List<UserProfile>>builder()
                .result(followers)
                .build();
    }
}
