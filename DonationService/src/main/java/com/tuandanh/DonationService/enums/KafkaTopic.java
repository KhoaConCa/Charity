package com.tuandanh.DonationService.enums;

public enum KafkaTopic {
    USER_LOGIN_EVENTS("user-login-events", "record login-logout events", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    USER_PROFILE_UPDATED("user-profile-updated", "record profile-updated events", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    USER_NEW_FOLLOW("user-new-follow", "record new-follow events", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    USER_STATUS_UPDATED("user-status-updated", "record status updated events", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    USER_ACTIVITY_TRACKING("user-activity-tracking", "record activity-tracking events", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    CHAT_MESSAGE_SENT("user-chat-message-sent", "record chat-message sent events", KafkaGroupTopic.MESSAGING_AND_CHAT_EVENTS),
    CHAT_MESSAGE_RECEIVED("user-chat-message-received", "record chat-message received", KafkaGroupTopic.MESSAGING_AND_CHAT_EVENTS),
    CHAT_MESSAGE_READ("user-chat-message-received", "record chat-message received", KafkaGroupTopic.MESSAGING_AND_CHAT_EVENTS),
    CHAT_TYPING_STATUS("user-chat-typing-status", "record chat-typing status" , KafkaGroupTopic.MESSAGING_AND_CHAT_EVENTS),
    NOTIFICATION_NEW_COMMENT("user-notification-new-comment", "record notification-new-comment events", KafkaGroupTopic.NOTIFICATION_AND_ALERT_EVENTS),
    NOTIFICATION_NEW_LIKE("user-notification-new-like", "record notification-new-like events", KafkaGroupTopic.NOTIFICATION_AND_ALERT_EVENTS),
    NOTIFICATION_NEW_MENTION("user-notification-new-mention", "record notification-new-mention events", KafkaGroupTopic.NOTIFICATION_AND_ALERT_EVENTS),
    NOTIFICATION_GROUP_INVITED("user-notification-group-invited", "record notification-group-invited", KafkaGroupTopic.NOTIFICATION_AND_ALERT_EVENTS),
    NOTIFICATION_POST_APPROVED("notification-post-approved", "record notification-post-approved events", KafkaGroupTopic.NOTIFICATION_AND_ALERT_EVENTS),
    POST_CREATED("user-post-created", "record post-created events", KafkaGroupTopic.CONTENT_AND_MEDIA_PROCESSING_EVENTS),
    POST_DELETED("user-post-deleted", "record post-deleted events", KafkaGroupTopic.CONTENT_AND_MEDIA_PROCESSING_EVENTS),
    POST_FLAGGED("user-post-flagged", "record post-flagged events", KafkaGroupTopic.CONTENT_AND_MEDIA_PROCESSING_EVENTS),
    MEDIA_UPLOADED("user-media-uploaded", "record media-uploaded events", KafkaGroupTopic.CONTENT_AND_MEDIA_PROCESSING_EVENTS),
    MEDIA_PROCESSING("user-media-processing", "record media-processing events", KafkaGroupTopic.CONTENT_AND_MEDIA_PROCESSING_EVENTS),
    SUSPICIOUS_LOGIN_ATTEMPT("user-new-device-alerts", "record user-new-device-alerts", KafkaGroupTopic.SECURITY_AND_FRAUD_DETECTION),
    ACCOUNT_BANNED("user-account-banned", "record account banned", KafkaGroupTopic.SECURITY_AND_FRAUD_DETECTION),
    FRAUD_DETECTION_ALERT("fraud-detection-alert", "record fraud detection alert ", KafkaGroupTopic.SECURITY_AND_FRAUD_DETECTION),
    USER_PASSWORD_RESET("user-password-reset", "record user-password-reset", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    USER_VERIFY_EMAIL("user-verify-email", "record user-verify-email", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    USER_TWO_FACTOR_AUTH("user-two-factor-auth", "record user-two-factor-auth", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    USER_NEW_FRIEND("user-new-friend", "record user-new-friend", KafkaGroupTopic.USER_ACTIVITY_EVENTS),
    NEW_DONATION("new-donation", "new notification about donation", KafkaGroupTopic.NOTIFICATION_AND_ALERT_EVENTS)
    ;

    public String getTopic() {
        return topic;
    }

    public String getDes() {
        return des;
    }

    public KafkaGroupTopic getKafkaGroupTopic() {
        return kafkaGroupTopic;
    }

    KafkaTopic(String topic, String des, KafkaGroupTopic kafkaGroupTopic) {
        this.topic = topic;
        this.des = des;
        this.kafkaGroupTopic = kafkaGroupTopic;
    }

    private final String topic;
    private final String des;
    private final KafkaGroupTopic kafkaGroupTopic;
}
