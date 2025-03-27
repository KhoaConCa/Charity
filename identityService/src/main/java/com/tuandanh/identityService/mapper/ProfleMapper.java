package com.tuandanh.identityService.mapper;

import com.tuandanh.identityService.dto.request.ProfileCreationRequest;
import com.tuandanh.identityService.dto.request.UserCreationRequest;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface ProfleMapper {
    ProfileCreationRequest toProfileCreationRequest(UserCreationRequest userCreationRequest);
}
