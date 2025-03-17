package com.tuandanh.identityService.dto.request;

import com.tuandanh.identityService.validator.PasswordConstraint;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ChangePasswordRequest {
    @NotBlank(message = "INVALID_PASSWORD")
    String oldPassword;

    @NotBlank(message = "INVALID_PASSWORD")
    @Size(min = 8, max = 50, message = "INVALID_PASSWORD")
    @PasswordConstraint(message = "INVALID_PASSWORD")
    String newPassword;
}
