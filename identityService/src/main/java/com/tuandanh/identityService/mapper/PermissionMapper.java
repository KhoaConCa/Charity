package com.tuandanh.identityService.mapper;

import com.tuandanh.identityService.dto.request.PermissionRequest;
import com.tuandanh.identityService.dto.response.PermissionResponse;
import com.tuandanh.identityService.entity.Permission;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface PermissionMapper {
    Permission toPermission(PermissionRequest request);

    PermissionResponse toPermissionResponse(Permission permission);
}
