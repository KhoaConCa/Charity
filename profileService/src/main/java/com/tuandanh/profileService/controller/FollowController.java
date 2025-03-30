package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.FollowRequest;
import com.tuandanh.profileService.dto.response.FollowResponse;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.service.FollowService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Follow Controller", description = "Quản lý theo dõi người dùng")
public class FollowController {
    FollowService followService;

    @Operation(summary = "Lấy danh sách người dùng đang theo dõi", description = "API trả về danh sách hồ sơ mà người dùng hiện tại đang theo dõi.")
    @GetMapping("/{profileId}")
    public ApiResponse<List<UserProfile>> getFollowingProfiles(
            @PathVariable String profileId,
            @Parameter(hidden = true) Authentication authentication) {
        List<UserProfile> followingProfiles = followService.getFollowingProfiles(profileId, authentication);
        return ApiResponse.<List<UserProfile>>builder().result(followingProfiles).build();
    }

    @Operation(summary = "Theo dõi người dùng", description = "API cho phép người dùng theo dõi một hồ sơ khác.")
    @PostMapping
    public ApiResponse<FollowResponse> followProfile(
            @RequestBody FollowRequest followRequest,
            @Parameter(hidden = true) Authentication authentication) {
        FollowResponse followResponse = followService.followProfile(followRequest, authentication);
        return ApiResponse.<FollowResponse>builder().result(followResponse).build();
    }

    @Operation(summary = "Bỏ theo dõi", description = "API cho phép người dùng hủy theo dõi một hồ sơ nhất định.")
    @DeleteMapping("/{followingId}/unfollow")
    public ApiResponse<String> unfollowProfile(
            @PathVariable String followingId,
            @Parameter(hidden = true) Authentication authentication) {
        followService.unfollowProfile(followingId, authentication);
        return ApiResponse.<String>builder().result("Unfollowed successfully").build();
    }

    @Operation(summary = "Lấy danh sách người theo dõi", description = "API trả về danh sách những người đang theo dõi một hồ sơ nhất định.")
    @GetMapping("/followers/{profileId}")
    public ApiResponse<List<UserProfile>> getFollowers(
            @PathVariable String profileId,
            @Parameter(hidden = true) Authentication authentication) {
        List<UserProfile> followers = followService.getFollowers(profileId, authentication);
        return ApiResponse.<List<UserProfile>>builder().result(followers).build();
    }
}

