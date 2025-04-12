package com.tuandanh.notificationService.dto.response;

import com.tuandanh.notificationService.dto.request.Recipient;
import com.tuandanh.notificationService.dto.request.Sender;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class EmailResponse {
    String messageId;
}
