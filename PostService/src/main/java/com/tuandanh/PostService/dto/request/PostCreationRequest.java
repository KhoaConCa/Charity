package com.tuandanh.PostService.dto.request;

import com.tuandanh.PostService.enums.Privacy;
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
public class PostCreationRequest {
    String profileId;
    String content;
    List<String> fileIds;
    List<String> tags;
    Privacy privacy;
    Point point;
    LocalDateTime donationStartTime;
    LocalDateTime donationEndTime;
}
