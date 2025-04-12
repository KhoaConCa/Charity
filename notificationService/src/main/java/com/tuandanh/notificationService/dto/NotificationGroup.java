package com.tuandanh.notificationService.dto;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class NotificationGroup {
    private String postId;         // ID bài viết hoặc đối tượng liên quan
    private String actionType;     // "like", "comment", etc.
    private List<String> userIds;  // Danh sách người dùng thực hiện hành động
    private Date lastActionAt;     // Thời gian hành động cuối cùng
}

