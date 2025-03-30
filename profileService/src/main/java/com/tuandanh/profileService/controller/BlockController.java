package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.service.BlockService;
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
@RequestMapping("/block")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Block Controller", description = "Quản lý chặn người dùng")
public class BlockController {
    BlockService blockService;

    @Operation(summary = "Kiểm tra quyền truy cập hồ sơ", description = "Kiểm tra xem người dùng hiện tại có thể truy cập hồ sơ của một người dùng khác hay không.")
    @GetMapping("/can-access/{targetProfileId}")
    public ApiResponse<Boolean> canAccess(
            @PathVariable String targetProfileId,
            @Parameter(hidden = true) Authentication authentication) {
        boolean canAccess = blockService.canAccessProfile(targetProfileId, authentication);
        return ApiResponse.<Boolean>builder().result(canAccess).build();
    }

    @Operation(summary = "Danh sách người dùng bị chặn", description = "Lấy danh sách hồ sơ mà người dùng hiện tại đã chặn.")
    @GetMapping("/blocked-list")
    public ApiResponse<List<ProfileResponse>> getBlockedProfiles(
            @Parameter(hidden = true) Authentication authentication) {
        List<ProfileResponse> profiles = blockService.getBlockedProfiles(authentication);
        return ApiResponse.<List<ProfileResponse>>builder().result(profiles).build();
    }

    @Operation(summary = "Trạng thái chặn", description = "Kiểm tra xem người dùng hiện tại đã chặn một hồ sơ cụ thể chưa.")
    @GetMapping("/block-status/{targetProfileId}")
    public ApiResponse<Boolean> getBlockStatus(
            @PathVariable String targetProfileId,
            @Parameter(hidden = true) Authentication authentication) {
        boolean isBlocked = blockService.isBlocked(targetProfileId, authentication);
        return ApiResponse.<Boolean>builder().result(isBlocked).build();
    }

    @Operation(summary = "Bỏ chặn người dùng", description = "API cho phép người dùng bỏ chặn một hồ sơ cụ thể.")
    @DeleteMapping("/unblock/{blockedId}")
    public ApiResponse<String> unblockProfile(
            @PathVariable String blockedId,
            @Parameter(hidden = true) Authentication authentication) {
        blockService.unblockProfile(blockedId, authentication);
        return ApiResponse.<String>builder().result("Unblock success").build();
    }

    @Operation(summary = "Chặn người dùng", description = "API cho phép người dùng chặn một hồ sơ cụ thể.")
    @PostMapping("/{blockingId}")
    public ApiResponse<String> blockProfile(
            @PathVariable String blockingId,
            @Parameter(hidden = true) Authentication authentication) {
        blockService.blockProfile(blockingId, authentication);
        return ApiResponse.<String>builder().result("Block success").build();
    }
}

