package com.tuandanh.notificationService.service;

import com.tuandanh.notificationService.dto.request.EmailRequest;
import com.tuandanh.notificationService.dto.request.SendEmailRequest;
import com.tuandanh.notificationService.dto.request.Sender;
import com.tuandanh.notificationService.dto.response.EmailResponse;
import com.tuandanh.notificationService.exception.AppException;
import com.tuandanh.notificationService.exception.ErrorCode;
import com.tuandanh.notificationService.repository.httpClient.EmailClient;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {
    @Value("${email.apiKey}")
    private static  String API_KEY;

    private final EmailClient emailClient;
    private final SpringTemplateEngine templateEngine;



    private void validateRequest(SendEmailRequest request) {
        if (request == null || request.getTo() == null) {
            throw new IllegalArgumentException("SendEmailRequest or recipient must not be null");
        }
    }
    public void sendTemplateEmail(SendEmailRequest request) {
        Context context = new Context();
        Map<String, Object> variables = request.getParam();
        if (variables != null) {
            variables.forEach(context::setVariable);
        }
        String templateName = request.getTemplateName();
        String htmlContent = templateEngine.process(templateName, context);

        log.info("Generated Email HTML for {}: {}", templateName, htmlContent);

        EmailRequest emailRequest = EmailRequest.builder()
                .sender(new Sender("Tuan Danh", "tuandanhn07@gmail.com"))
                .to(List.of(request.getTo()))
                .subject(request.getSubject())
                .htmlContent(htmlContent)
                .build();

        sendEmail(emailRequest);
    }

    public EmailResponse sendEmail(EmailRequest emailRequest) {
        try {
            return emailClient.sendEmail(API_KEY, emailRequest);
        } catch (FeignException e) {
            log.error("Failed to send email: {}", e.getMessage());
            throw new AppException(ErrorCode.CANNOT_SEND_EMAIL);
        }
    }
}
