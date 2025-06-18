package com.tuandanh.identityService.dto;

import java.util.List;

public record RoleDTO(
        String name,
        String description,
        List<String> permissions
) {}
