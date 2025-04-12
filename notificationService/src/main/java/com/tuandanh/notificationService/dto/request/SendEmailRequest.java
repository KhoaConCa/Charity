package com.tuandanh.notificationService.dto.request;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Map;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SendEmailRequest {
    Recipient to;
    String subject;
    String templateName;
    Map<String,Object> param;
}
