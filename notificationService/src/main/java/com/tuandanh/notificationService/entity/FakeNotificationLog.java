package com.tuandanh.notificationService.entity;

import com.tuandanh.notificationService.enums.CHANEL;
import com.tuandanh.notificationService.enums.NotificationType;
import com.tuandanh.notificationService.enums.Status;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.MongoId;

import java.time.LocalDateTime;
import java.util.Map;

@Document(collection = "fake_notification_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class FakeNotificationLog {
    @MongoId
    String id;
    String userId;   // ID người dùng nhận thông báo
    String senderId;
    String avatarUrlOfSender;
    String firstNameOfSender;
    String lastNameOfSender;
    LocalDateTime createdAt;// Thời gian gửi thông báo
    String content;
    boolean isRead;
    LocalDateTime readAt;
}
