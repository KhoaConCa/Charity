package com.tuandanh.identityService.controller;

import com.tuandanh.identityService.dto.ApiResponse;
import com.tuandanh.identityService.dto.request.PermissionRequest;
import com.tuandanh.identityService.dto.response.PermissionResponse;
import com.tuandanh.identityService.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/permissions")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Tag(name = "Permission Controller", description = "Quản lý phân quyền, bao gồm tạo, lấy danh sách và xoá quyền")
public class PermissionController {
    PermissionService permissionService;

    @Operation(
            summary = "Tạo quyền mới",
            description = "API dùng để tạo một quyền mới với thông tin được cung cấp trong request body"
    )
    @PostMapping
    ApiResponse<PermissionResponse> create(@RequestBody PermissionRequest request) {
        return ApiResponse.<PermissionResponse>builder()
                .result(permissionService.create(request))
                .build();
    }

    @Operation(
            summary = "Lấy danh sách quyền",
            description = "API trả về danh sách tất cả các quyền hiện có trong hệ thống"
    )
    @GetMapping
    ApiResponse<List<PermissionResponse>> getAll() {
        return ApiResponse.<List<PermissionResponse>>builder()
                .result(permissionService.getAll())
                .build();
    }

    @Operation(
            summary = "Xoá quyền",
            description = "API dùng để xoá quyền theo tên quyền cung cấp"
    )
    @DeleteMapping("/{permission}")
    ApiResponse<Void> delete(@PathVariable String permission) {
        permissionService.delete(permission);
        return ApiResponse.<Void>builder().build();
    }
}