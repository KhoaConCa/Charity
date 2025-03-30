package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.service.UserProfileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/userProfiles")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Internal User Profile Controller", description = "Quản lý hồ sơ người dùng nội bộ,Không được phép gọi API này")
public class InternalUserProfileController {
    UserProfileService userProfileService;

    @Operation(summary = "Tạo hồ sơ (JSON)", description = "API tạo một hồ sơ mới từ JSON request body")
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ApiResponse<ProfileResponse> createProfileJSON(
            @RequestBody @Valid ProfileCreationRequest profileCreationRequest) {

        ProfileResponse profileResponse = userProfileService.createProfileJson(profileCreationRequest);
        return ApiResponse.<ProfileResponse>builder().result(profileResponse).build();
    }
}
