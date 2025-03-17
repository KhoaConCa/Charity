package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.request.ProfileUpdateRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.service.UserProfileService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/userProfiles")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserProfileController {
    UserProfileService userProfileService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<ProfileResponse> createProfile(
            @RequestPart("profile") @Valid ProfileCreationRequest profileCreationRequest,
            @RequestPart("avatar") MultipartFile avatarFile) throws IOException {

        ProfileResponse profileResponse = userProfileService.createProfile(profileCreationRequest, avatarFile);

        return ApiResponse.<ProfileResponse>builder()
                .result(profileResponse)
                .build();
    }

    @PutMapping("/{profileId}")
    public ApiResponse<ProfileResponse> updateProfile(@PathVariable String profileId
            ,@RequestBody @Valid ProfileUpdateRequest profileUpdateRequest){
        ProfileResponse profileResponse = userProfileService.updateProfile(profileId, profileUpdateRequest);

        return ApiResponse.<ProfileResponse>builder()
                .result(profileResponse)
                .build();
    }

    @GetMapping("/{profileId}")
    public ApiResponse<ProfileResponse> getProfile(@PathVariable String profileId){
        ProfileResponse profileResponse = userProfileService.getProfileByProfileId(profileId);

        return ApiResponse.<ProfileResponse>builder()
                .result(profileResponse)
                .build();
    }

    @DeleteMapping("/{profileId}")
    public ApiResponse<String> deleteProfile(@PathVariable String profileId){
        userProfileService.deleteProfile(profileId);

        return ApiResponse.<String>builder()
                .result("profile deleted")
                .build();
    }
}
