package com.tuandanh.notificationService.controller;

import com.tuandanh.event.dto.NotificationEvent;
import com.tuandanh.notificationService.dto.request.Recipient;
import com.tuandanh.notificationService.dto.request.SendEmailRequest;
import com.tuandanh.notificationService.service.EmailService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class EmailNotificationController {

    EmailService emailService;

    private static final String LOGIN_TOPIC = "user-login-events";
    private static final String NEW_DEVICE_TOPIC = "user-new-device-alerts";
    private static final String PASSWORD_RESET_TOPIC = "user-password-reset";
    private static final String VERIFY_EMAIL_TOPIC = "user-verify-email";
    private static final String TWO_FACTOR_AUTH_TOPIC = "user-two-factor-auth";

    @KafkaListener(topics = LOGIN_TOPIC)
    public void handleUserLogin(NotificationEvent message) {
        try {
            log.info("User login event received: {}", message);

            SendEmailRequest emailRequest = SendEmailRequest.builder()
                    .to(Recipient.builder().email(message.getRecipient()).build())
                    .subject(message.getSubject())
                    .templateName(message.getTemplateCode())
                    .param(message.getParam())
                    .build();

            emailService.sendTemplateEmail(emailRequest);
        } catch (Exception e) {
            log.error("Error processing user login event", e);
            // Không commit offset nếu có lỗi, Kafka sẽ retry
        }
    }

    @KafkaListener(topics = NEW_DEVICE_TOPIC)
    public void handleNewDeviceAlert(NotificationEvent message) {
        log.info("New device alert received: {}", message);

        SendEmailRequest emailRequest = SendEmailRequest.builder()
                .to(Recipient.builder().email(message.getRecipient()).build())
                .subject(message.getSubject())
                .templateName(message.getTemplateCode())
                .param(message.getParam())
                .build();

        emailService.sendTemplateEmail(emailRequest);
    }

    @KafkaListener(topics = PASSWORD_RESET_TOPIC)
    public void handlePasswordReset(NotificationEvent message) {
        log.info("Password reset request received: {}", message);

        SendEmailRequest emailRequest = SendEmailRequest.builder()
                .to(Recipient.builder().email(message.getRecipient()).build())
                .subject(message.getSubject())
                .templateName(message.getTemplateCode())
                .param(message.getParam())
                .build();

        emailService.sendTemplateEmail(emailRequest);
    }

    @KafkaListener(topics = VERIFY_EMAIL_TOPIC)
    public void handleEmailVerification(NotificationEvent message) {
        log.info("Email verification request received: {}", message);

        SendEmailRequest emailRequest = SendEmailRequest.builder()
                .to(Recipient.builder().email(message.getRecipient()).build())
                .subject(message.getSubject())
                .templateName(message.getTemplateCode())
                .param(message.getParam())
                .build();

        emailService.sendTemplateEmail(emailRequest);
    }

    @KafkaListener(topics = TWO_FACTOR_AUTH_TOPIC)
    public void handleTwoFactorAuthentication(NotificationEvent message) {
        log.info("Two-factor authentication request received: {}", message);

        SendEmailRequest emailRequest = SendEmailRequest.builder()
                .to(Recipient.builder().email(message.getRecipient()).build())
                .subject(message.getSubject())
                .templateName(message.getTemplateCode())
                .param(message.getParam())
                .build();

        emailService.sendTemplateEmail(emailRequest);
    }
}

