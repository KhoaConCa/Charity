package com.tuandanh.PostService.dto;

import com.tuandanh.PostService.enums.ReactionType;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Reaction {
    ReactionType reactionType;
    String profileId;
}
