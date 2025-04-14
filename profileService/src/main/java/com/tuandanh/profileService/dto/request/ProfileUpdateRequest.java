package com.tuandanh.profileService.dto.request;

import com.tuandanh.profileService.validator.DobConstraint;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.hibernate.validator.constraints.URL;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ProfileUpdateRequest {
    @NotBlank(message = "USERNAME_INVALID")
    @Size(min = 3, max = 20, message = "USERNAME_INVALID")
    String username;

    @NotBlank(message = "FIRSTNAME_INVALID")
    @Size(max = 30, message = "FIRSTNAME_INVALID")
    String firstName;

    @NotBlank(message = "LASTNAME_INVALID")
    @Size(max = 30, message = "LASTNAME_INVALID")
    String lastName;

    @Size(max = 300, message = "BIO_INVALID")
    String bio;

    @DobConstraint(min = 18, message = "DOB_INVALID")
    LocalDate dob;


    @Size(max = 100, message = "LOCATION_INVALID")
    String location;
}
