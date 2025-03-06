package com.tuandanh.identityService.mapper;

import com.tuandanh.identityService.dto.request.UserCreationRequest;
import com.tuandanh.identityService.dto.request.UserUpdateRequest;
import com.tuandanh.identityService.dto.response.UserResponse;
import com.tuandanh.identityService.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface UserMapper {
    User toUser(UserCreationRequest request);

    UserResponse toUserResponse(User user);

    void updateUser(@MappingTarget User user, UserUpdateRequest request);
}
