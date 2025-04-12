package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.request.ProfileUpdateRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.service.UserProfileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/userProfiles")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "User Profile Controller", description = "Quản lý hồ sơ người dùng")
public class UserProfileController {
    UserProfileService userProfileService;

    @Operation(summary = "Lấy  hồ sơ hoạt động", description = "API lấy  hồ sơ đang hoạt động của người dùng")
    @GetMapping("/get-active-profile/{userId}")
    public ApiResponse<String> getActiveProfile(
            @PathVariable String userId) {
        String activeProfileId = userProfileService.getActiveProfile(userId);
        return ApiResponse.<String>builder().result(activeProfileId).build();
    }

    @Operation(summary = "Đặt hồ sơ hoạt động", description = "API đặt một hồ sơ làm hồ sơ hoạt động của người dùng")
    @PostMapping("/set-active-profile")
    public ApiResponse<String> setActiveProfile(
            @RequestParam String profileId,
            @Parameter(hidden = true) Authentication authentication) {
        userProfileService.setActiveProfile(profileId, authentication);
        return ApiResponse.<String>builder().result("setActiveProfile successful").build();
    }

    @Operation(summary = "Tạo hồ sơ mới", description = "API tạo một hồ sơ mới với thông tin và ảnh đại diện")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<ProfileResponse> createProfile(
            @RequestPart("profile") @Valid ProfileCreationRequest profileCreationRequest,
            @RequestPart("avatar") MultipartFile avatarFile) throws IOException {

        ProfileResponse profileResponse = userProfileService.createProfile(profileCreationRequest, avatarFile);
        return ApiResponse.<ProfileResponse>builder().result(profileResponse).build();
    }

    @Operation(summary = "Cập nhật hồ sơ", description = "API cập nhật thông tin của hồ sơ hiện tại")
    @PutMapping(value = "/{profileId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<ProfileResponse> updateProfile(
            @PathVariable String profileId,
            @RequestPart("profile") @Valid ProfileUpdateRequest profileUpdateRequest,
            @RequestPart(value = "avatar", required = false) MultipartFile avatarFile) throws IOException {

        ProfileResponse profileResponse = userProfileService.updateProfile(profileId, profileUpdateRequest, avatarFile);
        return ApiResponse.<ProfileResponse>builder().result(profileResponse).build();
    }

    @Operation(summary = "Cập nhật ảnh đại diện", description = "API cập nhật ảnh đại diện của hồ sơ")
    @PutMapping(value = "/{profileId}/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<String> updateAvatar(
            @PathVariable String profileId,
            @RequestPart("avatar") MultipartFile avatarFile) throws IOException {

        String newAvatarUrl = userProfileService.updateAvatar(profileId, avatarFile);
        return ApiResponse.<String>builder().result(newAvatarUrl).build();
    }

    @Operation(summary = "Lấy thông tin hồ sơ", description = "API lấy thông tin chi tiết của một hồ sơ")
    @GetMapping("/{profileId}")
    public ApiResponse<ProfileResponse> getProfile(@PathVariable String profileId){
        ProfileResponse profileResponse = userProfileService.getProfileByProfileId(profileId);
        return ApiResponse.<ProfileResponse>builder().result(profileResponse).build();
    }

    @Operation(summary = "Xóa hồ sơ", description = "API xóa một hồ sơ theo ID")
    @DeleteMapping("/{profileId}")
    public ApiResponse<String> deleteProfile(@PathVariable String profileId){
        userProfileService.deleteProfile(profileId);
        return ApiResponse.<String>builder().result("profile deleted").build();
    }

    @Operation(summary = "Lấy danh sách hồ sơ của tôi", description = "API lấy danh sách hồ sơ của người dùng hiện tại")
    @GetMapping("/myProfiles")
    public ApiResponse<List<ProfileResponse>> getMyProfiles(@Parameter(hidden = true) Authentication authentication){
        List<ProfileResponse> profileResponses = userProfileService.getMyProfiles(authentication);
        return ApiResponse.<List<ProfileResponse>>builder().result(profileResponses).build();
    }

    @Operation(summary = "Lấy danh sách tất cả hồ sơ", description = "API lấy danh sách tất cả hồ sơ trong hệ thống")
    @GetMapping
    public ApiResponse<List<ProfileResponse>> getAllProfiles(){
        List<ProfileResponse> profileResponses = userProfileService.getAllProfiles();
        return ApiResponse.<List<ProfileResponse>>builder().result(profileResponses).build();
    }
}
