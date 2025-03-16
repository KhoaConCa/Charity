package com.tuandanh.identityService.controller;

import com.tuandanh.identityService.dto.ApiResponse;
import com.tuandanh.identityService.dto.request.RoleRequest;
import com.tuandanh.identityService.dto.response.RoleResponse;
import com.tuandanh.identityService.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Tag(name = "Role Controller", description = "Quản lý vai trò, bao gồm tạo, lấy danh sách và xoá vai trò")
public class RoleController {
    RoleService roleService;

    @Operation(
            summary = "Tạo vai trò mới",
            description = "API dùng để tạo một vai trò mới với thông tin được cung cấp trong request body"
    )
    @PostMapping
    ApiResponse<RoleResponse> create(@RequestBody RoleRequest request) {
        return ApiResponse.<RoleResponse>builder()
                .result(roleService.create(request))
                .build();
    }

    @Operation(
            summary = "Lấy danh sách vai trò",
            description = "API trả về danh sách tất cả các vai trò hiện có trong hệ thống"
    )
    @GetMapping
    ApiResponse<List<RoleResponse>> getAll() {
        return ApiResponse.<List<RoleResponse>>builder()
                .result(roleService.getAll())
                .build();
    }

    @Operation(
            summary = "Xoá vai trò",
            description = "API dùng để xoá vai trò theo tên vai trò cung cấp"
    )
    @DeleteMapping("/{role}")
    ApiResponse<Void> delete(@PathVariable String role) {
        roleService.delete(role);
        return ApiResponse.<Void>builder().build();
    }
}
