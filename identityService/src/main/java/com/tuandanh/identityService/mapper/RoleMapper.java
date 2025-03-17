package com.tuandanh.identityService.mapper;

import com.tuandanh.identityService.dto.request.RoleRequest;
import com.tuandanh.identityService.dto.response.RoleResponse;
import com.tuandanh.identityService.entity.Role;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface RoleMapper {
    @Mapping(target = "permissions", ignore = true)
    Role toRole(RoleRequest request);

    RoleResponse toRoleResponse(Role role);
}
