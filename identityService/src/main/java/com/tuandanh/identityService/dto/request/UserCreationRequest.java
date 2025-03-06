package com.tuandanh.identityService.dto.request;

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
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,50}$",
            message = "INVALID_PASSWORD"
    )
    String password;

    @NotBlank(message = "FIRSTNAME_INVALID")
    @Size(max = 30, message = "FIRSTNAME_INVALID")
    String firstName;

    @NotBlank(message = "LASTNAME_INVALID")
    @Size(max = 30, message = "LASTNAME_INVALID")
    String lastName;

    @Past(message = "Date of birth must be in the past")// fix later
    LocalDate dob;

    @NotBlank(message = "EMAIL_INVALID")
    @Email(message = "EMAIL_INVALID")
    String email;
}
