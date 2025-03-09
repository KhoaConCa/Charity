package com.tuandanh.identityService.dto.request;

import com.tuandanh.identityService.validator.DobConstraint;
import com.tuandanh.identityService.validator.PasswordConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserUpdateRequest {
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

    List<String> roles;
}
