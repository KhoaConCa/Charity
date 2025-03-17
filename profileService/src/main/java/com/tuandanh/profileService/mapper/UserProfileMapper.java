package com.tuandanh.profileService.mapper;

import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.request.ProfileUpdateRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.entity.UserProfile;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface UserProfileMapper {
    UserProfile toUserProfile(ProfileCreationRequest profileCreationRequest);
    ProfileResponse toProfileResponse(UserProfile userProfile);
    void updateUserProfile(@MappingTarget UserProfile userProfile, ProfileUpdateRequest profileUpdateRequest);
}
