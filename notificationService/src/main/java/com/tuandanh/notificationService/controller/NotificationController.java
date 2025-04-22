package com.tuandanh.notificationService.controller;

import com.tuandanh.notificationService.dto.ApiResponse;
import com.tuandanh.notificationService.entity.FakeNotificationLog;
import com.tuandanh.notificationService.service.PushNotificationService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
