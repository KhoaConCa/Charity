package com.tuandanh.profileService.enums;

public enum KafkaGroupTopic {
    USER_ACTIVITY_EVENTS("User activity events"),
    MESSAGING_AND_CHAT_EVENTS("Message and chat events"),
    NOTIFICATION_AND_ALERT_EVENTS("Notification and alert events"),
    CONTENT_AND_MEDIA_PROCESSING_EVENTS("Content and media processing events"),
    SECURITY_AND_FRAUD_DETECTION("Security and frudetech events"),
    ;
    private final String groupTopic;

    KafkaGroupTopic(String groupTopic) {
        this.groupTopic = groupTopic;

    }

    public String getGroupTopic() {
        return groupTopic;
    }


}
