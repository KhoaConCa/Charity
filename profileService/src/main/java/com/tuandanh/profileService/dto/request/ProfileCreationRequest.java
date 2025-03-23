package com.tuandanh.profileService.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.hibernate.validator.constraints.URL;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ProfileCreationRequest {
    @NotBlank(message = "USERNAME_INVALID")
    @Size(min = 3, max = 20, message = "USERNAME_INVALID")
    String username;

    @NotBlank(message = "FIRSTNAME_INVALID")
    @Size(max = 30, message = "FIRSTNAME_INVALID")
    String firstName;

    @NotBlank(message = "LASTNAME_INVALID")
    @Size(max = 30, message = "LASTNAME_INVALID")
    String lastName;

    @Size(max = 100, message = "LOCATION_INVALID")
    String location;
}
