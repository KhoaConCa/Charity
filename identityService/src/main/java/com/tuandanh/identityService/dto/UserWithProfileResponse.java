package com.tuandanh.identityService.dto;

import java.util.List;

// DTO tổng hợp User + List<Profile>
public record UserWithProfileResponse(
        String userId,
        String username,
        String email,
        List<com.tuandanh.identityService.dto.response.ProfileResponse> profiles
) {}
