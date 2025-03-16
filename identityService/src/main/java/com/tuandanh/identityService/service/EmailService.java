package com.tuandanh.identityService.service;

import com.tuandanh.identityService.exception.AppException;
import com.tuandanh.identityService.exception.ErrorCode;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class EmailService {

    public static final String SUBJECT_PASSWORD_RESET = "Password Reset Request";
    public static final String SUBJECT_VERIFY_EMAIL = "Verify Your Email";
    public static final String SUBJECT_TWO_FACTOR_CODE = "Your Two-Factor Authentication Code";
    public static final String SUBJECT_NEW_DEVICE = "New Device Login Detected";
    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    JavaMailSender mailSender;
    SpringTemplateEngine templateEngine;

    public void sendNewDeviceAlert(String to, String deviceInfo) {
        sendTemplateEmail(to, SUBJECT_NEW_DEVICE,
                "email/new-device-alert.html", "device_info", deviceInfo);
    }

    public void sendPasswordResetEmail(String to, String resetLink) {
        sendTemplateEmail(to, SUBJECT_PASSWORD_RESET, "email/reset-password.html", "reset_link", resetLink);
    }

    public void sendVerifyEmail(String to, String verifyLink) {
        sendTemplateEmail(to, SUBJECT_VERIFY_EMAIL, "email/verify-email.html", "verify_link", verifyLink);
    }

    public void sendTwoFactorCode(String to, String code) {
        sendTemplateEmail(to, SUBJECT_TWO_FACTOR_CODE, "email/two-factor-code.html", "otp_code", code);
    }

    private void sendTemplateEmail(String to, String subject, String templateName, String variableName, String variableValue) {
        Context context = new Context();
        context.setVariable(variableName, variableValue);
        String htmlContent = templateEngine.process(templateName, context);
        log.error(htmlContent);
        sendHtmlEmail(to, subject, htmlContent);
    }

    private void sendHtmlEmail(String to, String subject, String htmlContent) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);
            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new AppException(ErrorCode.MESSAGING_FAIL);
        }
    }
}

