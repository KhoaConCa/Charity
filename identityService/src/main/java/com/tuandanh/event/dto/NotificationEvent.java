package com.tuandanh.event.dto;

import com.tuandanh.identityService.enums.CHANEL;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class NotificationEvent {
    CHANEL chanel;
    String recipient;
    String templateCode;
    Map<String, Object> param;
    String subject;
    String body;
}
