package com.tuandanh.profileService.mapper;

import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.request.ProfileUpdateRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.entity.UserProfile;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 22.0.2 (Oracle Corporation)"
)
@Component
public class UserProfileMapperImpl implements UserProfileMapper {

    @Override
    public UserProfile toUserProfile(ProfileCreationRequest profileCreationRequest) {
        if ( profileCreationRequest == null ) {
            return null;
        }

        UserProfile.UserProfileBuilder userProfile = UserProfile.builder();

        userProfile.username( profileCreationRequest.getUsername() );
        userProfile.firstName( profileCreationRequest.getFirstName() );
        userProfile.lastName( profileCreationRequest.getLastName() );
        userProfile.location( profileCreationRequest.getLocation() );

        return userProfile.build();
    }

    @Override
    public ProfileResponse toProfileResponse(UserProfile userProfile) {
        if ( userProfile == null ) {
            return null;
        }

        ProfileResponse.ProfileResponseBuilder profileResponse = ProfileResponse.builder();

        profileResponse.profileId( userProfile.getProfileId() );
        profileResponse.userId( userProfile.getUserId() );
        profileResponse.username( userProfile.getUsername() );
        profileResponse.firstName( userProfile.getFirstName() );
        profileResponse.lastName( userProfile.getLastName() );
        profileResponse.avatarUrl( userProfile.getAvatarUrl() );
        profileResponse.location( userProfile.getLocation() );
        profileResponse.createdAt( userProfile.getCreatedAt() );
        profileResponse.updatedAt( userProfile.getUpdatedAt() );

        return profileResponse.build();
    }

    @Override
    public void updateUserProfile(UserProfile userProfile, ProfileUpdateRequest profileUpdateRequest) {
        if ( profileUpdateRequest == null ) {
            return;
        }

        userProfile.setUsername( profileUpdateRequest.getUsername() );
        userProfile.setFirstName( profileUpdateRequest.getFirstName() );
        userProfile.setLastName( profileUpdateRequest.getLastName() );
        userProfile.setLocation( profileUpdateRequest.getLocation() );
    }
}
