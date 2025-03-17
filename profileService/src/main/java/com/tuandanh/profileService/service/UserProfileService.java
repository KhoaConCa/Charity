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
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserProfileService {
    UserProfileRepository userProfileRepository;
    UserProfileMapper userProfileMapper;
    S3Service s3Service;

    public ProfileResponse createProfile(ProfileCreationRequest profileCreationRequest, MultipartFile avatarFile)
            throws IOException {
        String avatarUrl = s3Service.uploadAvatar(avatarFile);
        UserProfile userProfile = userProfileMapper.toUserProfile(profileCreationRequest);
        userProfile.setAvatarUrl(avatarUrl);
        userProfile = userProfileRepository.save(userProfile);

        return userProfileMapper.toProfileResponse(userProfile);
    }

//    @PreAuthorize("returnObject.userId == authentication.name or hasRole('ADMIN')")
    public ProfileResponse updateProfile(String profileId, ProfileUpdateRequest request) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                        .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

        userProfileMapper.updateUserProfile(userProfile, request);
        userProfile = userProfileRepository.save(userProfile);

        return userProfileMapper.toProfileResponse(userProfile);
    }

//    @PreAuthorize("hasRole('ADMIN') or @securityService.isOwner(#userId)")
    public void deleteProfile(String profileId) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));
        userProfileRepository.delete(userProfile);
    }

//    @PostAuthorize("returnObject.userId == authentication.name or hasRole('ADMIN')")
    public ProfileResponse getProfileByProfileId(String profileId) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException(""));
        return userProfileMapper.toProfileResponse(userProfile);
    }

//    // GET MY PROFILE (AUTHENTICATED USER)
//    public ProfileResponse getMyProfile() {
//        String userId = SecurityContextHolder.getContext().getAuthentication().getName();
//        UserProfile userProfile = userProfileRepository.findByUserId(userId)
//                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));
//        return userProfileMapper.toProfileResponse(userProfile);
//    }
}
