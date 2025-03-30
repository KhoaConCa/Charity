package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.service.BlockService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/block")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class BlockController {
    BlockService blockService;

    @GetMapping("/can-access/{targetProfileId}")
    public ApiResponse<Boolean> canAccess(@PathVariable String targetProfileId, Authentication authentication) {
        boolean canAccess = blockService.canAccessProfile(targetProfileId, authentication);

        return ApiResponse.<Boolean>builder()
                .result(canAccess)
                .build();
    }

    @GetMapping("/blocked-list")
    public ApiResponse<List<ProfileResponse>> getBlockedProfiles(Authentication authentication) {
        List<ProfileResponse> profiles = blockService.getBlockedProfiles(authentication);

        return ApiResponse.<List<ProfileResponse>>builder()
                .result(profiles)
                .build();
    }

    @GetMapping("/block-status/{targetProfileId}")
    public ApiResponse<Boolean> getBlockStatus(@PathVariable String targetProfileId, Authentication authentication) {
        boolean isBlocked = blockService.isBlocked(targetProfileId, authentication);

        return ApiResponse.<Boolean>builder()
                .result(isBlocked)
                .build();
    }

    @DeleteMapping("/unblock/{blockedId}")
    public ApiResponse<String> unblockProfile(@PathVariable String blockedId, Authentication authentication) {
        blockService.unblockProfile(blockedId, authentication);

        return ApiResponse.<String>builder()
                .result("unblock success")
                .build();
    }

    @PostMapping("/{blockingId}")
    public ApiResponse<String> blockProfile(@PathVariable String blockingId, Authentication authentication) {
        blockService.blockProfile(blockingId, authentication);

        return ApiResponse.<String>builder()
                .result("block success")
                .build();
    }


}
