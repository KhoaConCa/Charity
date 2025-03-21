package com.tuandanh.profileService.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    PROFILE_NOT_EXISTED(1003,"profile not existed", HttpStatus.NOT_FOUND),
    PROFILE_EXISTED(1002, "Profile Existed", HttpStatus.CONFLICT),
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error", HttpStatus.INTERNAL_SERVER_ERROR),

    INVALID_KEY(1001, "Invalid key provided", HttpStatus.BAD_REQUEST),
    UNAUTHENTICATED(1004, "User is unauthenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1015, "Unauthorized", HttpStatus.FORBIDDEN),
    USERNAME_INVALID(1006, "Username must be at least 3 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    FIRSTNAME_INVALID(1007, "First name cannot exceed 30 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    LASTNAME_INVALID(1008, "Last name cannot exceed 30 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    URL_AVATAR_INVALID(1009, "Avatar invalid, please choose another avatar", HttpStatus.BAD_REQUEST),
    LOCATION_INVALID(1010, "Location invalid, please change the location", HttpStatus.BAD_REQUEST)
    ;
    private final int code;
    private final String message;
    private final HttpStatus httpStatus;

    ErrorCode(int code, String message, HttpStatus httpStatus) {
        this.code = code;
        this.message = message;
        this.httpStatus = httpStatus;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
