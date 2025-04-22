package com.tuandanh.notificationService.controller;

import com.tuandanh.event.dto.NotificationEvent;
import com.tuandanh.notificationService.dto.ApiResponse;
import com.tuandanh.notificationService.service.PushNotificationService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PushNotificationController {
    PushNotificationService pushNotificationService;
    private static final String NEW_FOLLOW_REQUEST = "user-new-follow";
    private static final String NEW_FRIEND_REQUEST = "user-new-friend";
    private static final String NEW_TAGS_REQUEST = "tag-notification-topic";
    private static final String NEW_DONATION_REQUEST = "new-donation";

    @KafkaListener(topics = NEW_DONATION_REQUEST)
    public ApiResponse<String> mockSendNotification(@RequestBody NotificationEvent notificationEvent) {
        pushNotificationService.mockNotification(notificationEvent);

        return ApiResponse.<String>builder()
                .result("send notification successfully")
                .build();
    }

    @KafkaListener(topics = NEW_FOLLOW_REQUEST)
    public ApiResponse<String> sendNewFollowNotification(@RequestBody NotificationEvent notificationEvent) {
        // Gọi service để xử lý gửi thông báo
        pushNotificationService.sendNotificationToUser(notificationEvent, true);

        return ApiResponse.<String>builder()
                .result("send notification success")
                .build();
    }

    @KafkaListener(topics = NEW_FRIEND_REQUEST)
    public ApiResponse<String> sendNewFriendNotification(@RequestBody NotificationEvent notificationEvent) {
        // Gọi service để xử lý gửi thông báo
        pushNotificationService.sendNotificationToUser(notificationEvent, true);

        return ApiResponse.<String>builder()
                .result("send notification success")
                .build();
    }

    @KafkaListener(topics = NEW_TAGS_REQUEST)
    public ApiResponse<String> sendNewTagsNotification(@RequestBody NotificationEvent notificationEvent) {
        pushNotificationService.sendNotificationToUser(notificationEvent, true);

        return ApiResponse.<String>builder()
                .result("send tags notification success")
                .build();
    }
}

