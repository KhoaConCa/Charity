package com.tuandanh.DonationService.dto.response;


import com.tuandanh.DonationService.enums.Privacy;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.geo.Point;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class PostResponse {
    String id;
    String profileId;
    String content;
    List<String> fileIds;
    List<String> tags;
    Privacy privacy;
    Point point;
    LocalDateTime donationStartTime;
    LocalDateTime donationEndTime;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
