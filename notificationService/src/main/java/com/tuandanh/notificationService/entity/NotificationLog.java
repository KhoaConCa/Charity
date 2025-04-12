package com.tuandanh.notificationService.entity;

import com.tuandanh.notificationService.enums.CHANEL;
import com.tuandanh.notificationService.enums.NotificationType;
import com.tuandanh.notificationService.enums.Status;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.MongoId;

import java.time.LocalDateTime;
import java.util.Map;

@Document(collection = "notification_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class NotificationLog {
    @MongoId
    String id;
    String userId;   // ID người dùng nhận thông báo
    String senderId;
    NotificationType notificationType;
    Status status;
    String title;     // Tiêu đề thông báo
    String body;      // Nội dung thông báo
    LocalDateTime createdAt;
    LocalDateTime readAt;
    CHANEL chanel;
    Map<String, Object> metaData;
    LocalDateTime sentAt;      // Thời gian gửi thông báo
    String topic;

}

