package com.tuandanh.notificationService.controller;

import com.tuandanh.notificationService.dto.ApiResponse;
import com.tuandanh.notificationService.entity.FakeNotificationLog;
import com.tuandanh.notificationService.service.PushNotificationService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/polling")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class NotificationController {
    PushNotificationService pushNotificationService;

    @GetMapping("/{userId}")
    public ApiResponse<List<FakeNotificationLog>> getListNotificationByUser(@PathVariable String userId) {
        List<FakeNotificationLog> list = pushNotificationService.getListNotificationByUsers(userId);

        return ApiResponse.<List<FakeNotificationLog>>builder()
                .result(list)
                .build();
    }

    @GetMapping("/unread/{userId}")
    public ApiResponse<List<FakeNotificationLog>> getUnreadListNotificationByUser(@PathVariable String userId) {
        var list = pushNotificationService.getUnreadNotificationLogs(userId);

        return ApiResponse.<List<FakeNotificationLog>>builder()
                .result(list)
                .build();
    }

    @PostMapping("/markAsRead/{notificationId}")
    public ApiResponse<FakeNotificationLog> markNotificationAsRead(@PathVariable String notificationId) {
        var notification = pushNotificationService.markAsRead(notificationId);

        return ApiResponse.<FakeNotificationLog>builder()
                .result(notification)
                .build();
    }

    @PostMapping("/marAllAsRead/{userId}")
    public ApiResponse<List<FakeNotificationLog>> markAllAsRead(@PathVariable String userId) {
        List<FakeNotificationLog> list = pushNotificationService.markAllAsRead(userId);

        return ApiResponse.<List<FakeNotificationLog>>builder()
                .result(list)
                .build();
    }
}
