package com.tuandanh.profileService.service;

import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.request.ProfileUpdateRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.exception.AppException;
import com.tuandanh.profileService.exception.ErrorCode;
import com.tuandanh.profileService.mapper.UserProfileMapper;
import com.tuandanh.profileService.repository.UserProfileRepository;
import com.tuandanh.profileService.service.aws3.S3Service;
import com.tuandanh.profileService.service.redis.RedisService;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserProfileService {
    UserProfileRepository userProfileRepository;
    UserProfileMapper userProfileMapper;
    S3Service s3Service;
    RedisService redisService;
    private String USER_ID = "userId";



    public void setActiveProfile(String profileId, Authentication authentication){
        String userId = getUserId(authentication);

        // Kiểm tra profileId có tồn tại không
        boolean exists = userProfileRepository.existsById(profileId);
        if (!exists) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        redisService.setActiveProfile(userId, profileId);
    }

    public String getUserId(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        return jwt.getClaim(USER_ID);
    }


    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
    public String updateAvatar(String profileId, MultipartFile avatarFile) throws IOException {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

        // Xóa avatar cũ nếu có
        if (userProfile.getAvatarUrl() != null) {
            s3Service.deleteAvatar(userProfile.getAvatarUrl());
        }

        // Upload avatar mới
        String newAvatarUrl = s3Service.uploadAvatar(avatarFile);
        userProfile.setAvatarUrl(newAvatarUrl);
        userProfileRepository.save(userProfile);

        return newAvatarUrl;
    }

    public ProfileResponse createProfileJson(ProfileCreationRequest profileCreationRequest) {
        UserProfile userProfile = userProfileMapper.toUserProfile(profileCreationRequest);

        return userProfileMapper.toProfileResponse(userProfileRepository.save(userProfile));
    }

    public ProfileResponse createProfile(ProfileCreationRequest profileCreationRequest, MultipartFile avatarFile)
            throws IOException {
        String avatarUrl = s3Service.uploadAvatar(avatarFile);
        UserProfile userProfile = userProfileMapper.toUserProfile(profileCreationRequest);
        userProfile.setAvatarUrl(avatarUrl);
        userProfile = userProfileRepository.save(userProfile);

        return userProfileMapper.toProfileResponse(userProfile);
    }

    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
public ProfileResponse updateProfile(String profileId, ProfileUpdateRequest request, MultipartFile avatarFile)
        throws IOException {

    UserProfile userProfile = userProfileRepository.findById(profileId)
            .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

    // Nếu có avatar mới, xóa ảnh cũ và upload ảnh mới lên S3
    if (avatarFile != null && !avatarFile.isEmpty()) {
        // Xóa avatar cũ nếu có
        if (userProfile.getAvatarUrl() != null) {
            s3Service.deleteAvatar(userProfile.getAvatarUrl());
        }

        // Upload avatar mới
        String newAvatarUrl = s3Service.uploadAvatar(avatarFile);
        userProfile.setAvatarUrl(newAvatarUrl);
    }

    // Cập nhật các thông tin khác từ request
    userProfileMapper.updateUserProfile(userProfile, request);
    userProfile = userProfileRepository.save(userProfile);

    return userProfileMapper.toProfileResponse(userProfile);
}

    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
    public void deleteProfile(String profileId) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));
        userProfileRepository.delete(userProfile);
    }


    public ProfileResponse getProfileByProfileId(String profileId) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));
        return userProfileMapper.toProfileResponse(userProfile);
    }

    public List<ProfileResponse> getMyProfiles(Authentication authentication) {
        String userId = getUserId(authentication);

        List<UserProfile> userProfiles = userProfileRepository.findByUserId(userId);

        if (userProfiles.isEmpty()) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        return userProfiles.stream()
                .map(userProfileMapper::toProfileResponse)
                .collect(Collectors.toList());
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<ProfileResponse> getAllProfiles() {
        List<UserProfile> userProfiles = userProfileRepository.findAll();

        if (userProfiles.isEmpty()) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        return userProfiles.stream()
                .map(userProfileMapper::toProfileResponse)
                .collect(Collectors.toList());
    }



    public boolean isProfileOwner(String profileId, Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String userId = jwt.getClaim("userId");

        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));



        boolean result = userProfile.getUserId().equals(userId);

        return result;
    }



}
