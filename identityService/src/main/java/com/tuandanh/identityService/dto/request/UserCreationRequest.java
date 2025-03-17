package com.tuandanh.identityService.dto.request;

import com.tuandanh.identityService.validator.DobConstraint;
import com.tuandanh.identityService.validator.PasswordConstraint;
import jakarta.validation.constraints.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserCreationRequest {
    @NotBlank(message = "USERNAME_INVALID")
    @Size(min = 3, max = 20, message = "USERNAME_INVALID")
    String username;

    @NotBlank(message = "INVALID_PASSWORD")
    @Size(min = 8, max = 50, message = "INVALID_PASSWORD")
    @PasswordConstraint(message = "INVALID_PASSWORD")
    String password;

    @NotBlank(message = "FIRSTNAME_INVALID")
    @Size(max = 30, message = "FIRSTNAME_INVALID")
    String firstName;

    @NotBlank(message = "LASTNAME_INVALID")
    @Size(max = 30, message = "LASTNAME_INVALID")
    String lastName;

    @DobConstraint(min = 18, message = "DOB_INVALID")
    LocalDate dob;

    @NotBlank(message = "EMAIL_INVALID")
    @Email(message = "EMAIL_INVALID")
    String email;
}
