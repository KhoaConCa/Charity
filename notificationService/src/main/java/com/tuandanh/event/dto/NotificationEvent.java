package com.tuandanh.event.dto;

import com.tuandanh.notificationService.enums.CHANEL;
import com.tuandanh.notificationService.enums.NotificationType;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class NotificationEvent {
    CHANEL chanel;
    String recipient;
    String templateCode;
    Map<String, Object> param;
    String subject;
    String body;
    NotificationType notificationType;
    LocalDateTime sentAt;
}
