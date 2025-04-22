package com.tuandanh.notificationService.service;

import com.google.firebase.messaging.*;
import com.tuandanh.event.dto.NotificationEvent;
import com.tuandanh.notificationService.dto.NotificationGroup;
import com.tuandanh.notificationService.entity.FakeNotificationLog;
import com.tuandanh.notificationService.entity.FcmToken;
import com.tuandanh.notificationService.entity.NotificationLog;
import com.tuandanh.notificationService.enums.NotificationType;
import com.tuandanh.notificationService.enums.Status;
import com.tuandanh.notificationService.exception.AppException;
import com.tuandanh.notificationService.exception.ErrorCode;
import com.tuandanh.notificationService.repository.FakeNotificationLogRepository;
import com.tuandanh.notificationService.repository.FcmTokenRepository;
import com.tuandanh.notificationService.repository.NotificationLogRepository;
import com.tuandanh.notificationService.repository.httpClient.UserProfileClient;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PushNotificationService {

    FcmTokenRepository fcmTokenRepository;
    NotificationLogRepository notificationLogRepository;
    FakeNotificationLogRepository fakeNotificationLogRepository;
    UserProfileClient userProfileClient;
    private static final String TOPIC = "topic";

    public List<FakeNotificationLog> getUnreadNotificationLogs(String userId) {
        return fakeNotificationLogRepository.findByUserIdAndIsReadFalseOrderByCreatedAtDesc(userId);
    }

    public FakeNotificationLog markAsRead(String id) {
        var notification = fakeNotificationLogRepository.findById(id)
                .orElseThrow(
                        () -> new AppException(ErrorCode.NOTIFICATION_NOT_FOUND)
                );

        notification.setRead(true);
        notification.setReadAt(LocalDateTime.now());

        return fakeNotificationLogRepository.save(notification);
    }

    public List<FakeNotificationLog> markAllAsRead(String userId){
        var list = getUnreadNotificationLogs(userId);

        list.forEach(
                notification -> {
                    notification.setRead(true);
                    notification.setReadAt(LocalDateTime.now());
                }
        );

        return fakeNotificationLogRepository.saveAll(list);
    }

    public List<FakeNotificationLog> getListNotificationByUsers(String userId){
        return fakeNotificationLogRepository.findByUserId(userId);
    }

    public void mockNotification(NotificationEvent notificationEvent){
        Map<String, Object> param = notificationEvent.getParam();

        var senderProfile = userProfileClient.getProfile(param.get("senderId").toString()).getResult();

        FakeNotificationLog fakeNotificationLog = FakeNotificationLog.builder()
                .senderId(param.get("senderId").toString())
                .userId(param.get("userId").toString())  // bạn đã để userId là người nhận rồi
                .avatarUrlOfSender(senderProfile.getAvatarUrl())
                .firstNameOfSender(senderProfile.getFirstName())
                .lastNameOfSender(senderProfile.getLastName())
                .content(notificationEvent.getBody())
                .isRead(false)
                .createdAt(LocalDateTime.now())
                .build();

        fakeNotificationLogRepository.save(fakeNotificationLog);
    }

    // Gửi thông báo cho một user từ NotificationEvent
    public void sendNotificationToUser(NotificationEvent notificationEvent, boolean isHighPriority) {
        List<FcmToken> tokens = fcmTokenRepository.findByUserId(notificationEvent.getRecipient());

        List<Message> messages = tokens.stream()
                .map(token -> buildMessage(token.getToken(), notificationEvent, isHighPriority))
                .collect(Collectors.toList());

        saveGroupedNotification(notificationEvent);

        sendBatchNotifications(messages);
    }

    // Gửi thông báo cho topic từ NotificationEvent
    public String sendNotificationToTopic(NotificationEvent notificationEvent, boolean isHighPriority) {
        Message message = buildMessage(null, notificationEvent, isHighPriority);

        saveGroupedNotification(notificationEvent);

        return sendNotification(message);
    }

    // Gộp thông báo và gửi thông báo cho nhóm người dùng
    public String createGroupedNotification(NotificationGroup group, boolean isHighPriority) {
        int count = group.getUserIds().size();

        // Lấy user cuối cùng tương tác bài viết
        String lastUser = group.getUserIds().get(group.getUserIds().size() - 1);

        // Tạo title và body của thông báo
        String title = "Có " + count + " người đã " + group.getActionType() + " bài viết của bạn";
        String body = lastUser + " và " + (count - 1) + " người khác đã " + group.getActionType() + " bài viết của bạn.";

        // Lưu thông báo vào database
//        saveGroupedNotification(n);

//        // Gửi thông báo đến các user
//        group.getUserIds().forEach(userId -> {
//            NotificationEvent notificationEvent = new NotificationEvent("groupNotification", userId, title, body, group.getActionType());
//            sendNotificationToUser(notificationEvent, isHighPriority);
//        });

        return "Grouped Notification Sent!";
    }

    // Lưu thông báo vào database
    private void saveGroupedNotification(NotificationEvent notificationEvent) {
        if (notificationEvent == null || notificationEvent.getParam() == null) {
            return;
        }

        Map<String, Object> params = notificationEvent.getParam();

        String userId = getStringParam(params, "userId");
        String senderId = getStringParam(params, "senderId");
        String topic = getStringParam(params, TOPIC);

        NotificationType notificationType = getNotificationTypeParam(params, "notificationType");

        Map<String, Object> metaData = new HashMap<>(params);
        metaData.remove("userId");
        metaData.remove("senderId");
        metaData.remove(TOPIC);
        metaData.remove("notificationType");

        NotificationLog notificationLog = NotificationLog.builder()
                .senderId(senderId.isEmpty() ? null : senderId)
                .userId(userId.isEmpty() ? null : userId)
                .notificationType(notificationType)
                .status(Status.SENT)
                .body(notificationEvent.getBody())
                .title(notificationEvent.getSubject())
                .createdAt(LocalDateTime.now())
                .chanel(notificationEvent.getChanel())
                .sentAt(notificationEvent.getSentAt() != null ? notificationEvent.getSentAt() : LocalDateTime.now())
                .topic(topic.isEmpty() ? null : topic)
                .metaData(metaData)
                .build();

        notificationLogRepository.save(notificationLog);
    }

    private String getStringParam(Map<String, Object> params, String key) {
        Object value = params.get(key);
        return value instanceof String ? (String) value : "";
    }

    private NotificationType getNotificationTypeParam(Map<String, Object> params, String key) {
        Object value = params.get(key);
        return value instanceof NotificationType ? (NotificationType) value : null;
    }



    // Xây dựng Message từ NotificationEvent
    private Message buildMessage(String token, NotificationEvent notificationEvent, boolean isHighPriority) {

        Message.Builder builder = Message.builder()
                .setNotification(Notification.builder()
                        .setTitle(notificationEvent.getSubject())
                        .setBody(notificationEvent.getBody())
                        .setImage(notificationEvent.getParam().get("avatarUrl") != null ?
                                notificationEvent.getParam().get("avatarUrl").toString() : null)  // Thêm hình ảnh nếu có
                        .build());

        // Cấu hình mức độ ưu tiên
        AndroidConfig.Priority priority = isHighPriority
                ? AndroidConfig.Priority.HIGH
                : AndroidConfig.Priority.NORMAL;

        builder.setAndroidConfig(AndroidConfig.builder().setPriority(priority).build());

        Map<String, Object> params = notificationEvent.getParam();
        String topic = getStringParam(params, TOPIC);

        // Kiểm tra xem có phải là thông báo cho topic không
        if (!topic.isEmpty()) {
            builder.setTopic(topic);
        } else if (token != null) {
            builder.setToken(token);
        }

        return builder.build();
    }

    // Gửi một thông báo đơn
    private String sendNotification(Message message) {
        try {
            return FirebaseMessaging.getInstance().send(message);
        } catch (FirebaseMessagingException e) {
            log.error("Error sending notification", e);
            return "Error: " + e.getMessage();
        }
    }

    // Gửi một loạt thông báo
    private String sendBatchNotifications(List<Message> messages) {
        try {
            BatchResponse response = FirebaseMessaging.getInstance().sendAll(messages);
            log.info("Successfully sent {} notifications", response.getSuccessCount());
            return "Successfully sent batch notifications";
        } catch (FirebaseMessagingException e) {
            log.error("Error sending batch notification", e);
            return "Error: " + e.getMessage();
        }
    }

    // Lấy thông báo của người dùng
    public List<NotificationLog> getUserNotifications(String userId) {
        return notificationLogRepository.findByUserId(userId);
    }
}







