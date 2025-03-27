package com.tuandanh.identityService.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error", HttpStatus.INTERNAL_SERVER_ERROR),

    INVALID_KEY(1001, "Invalid key provided", HttpStatus.BAD_REQUEST),

    USER_EXISTED(1002, "User already exists", HttpStatus.CONFLICT),
    USER_NOT_EXISTED(1003, "User does not exist", HttpStatus.NOT_FOUND),

    USERNAME_INVALID(1004, "Username must be at least 3 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    INVALID_PASSWORD(1005, "Invalid Password", HttpStatus.BAD_REQUEST),

    FIRSTNAME_INVALID(1006, "First name cannot exceed 30 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    LASTNAME_INVALID(1007, "Last name cannot exceed 30 characters and cannot be blank", HttpStatus.BAD_REQUEST),

    EMAIL_INVALID(1008, "Invalid email format and cannot be blank", HttpStatus.BAD_REQUEST),
    DOB_INVALID(1009, "Date of birth is invalid", HttpStatus.BAD_REQUEST),

    USER_ALREADY_BLOCKED(1010, "User is already blocked", HttpStatus.CONFLICT),
    USER_ALREADY_UNBLOCKED(1011, "User is already unblocked", HttpStatus.CONFLICT),

    UNAUTHENTICATED(1012, "User is unauthenticated", HttpStatus.UNAUTHORIZED),
    JWT_TOKEN_ERROR(1013, "Invalid or expired JWT token", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1014, "Unauthorized", HttpStatus.FORBIDDEN),
    INVALID_OLD_PASSWORD(1015, "Old password is invalid", HttpStatus.BAD_REQUEST),
    EMAIL_NOT_EXISTED(1016, "Email already exists", HttpStatus.NOT_FOUND),
    MESSAGING_FAIL(1017, "Messaging failed", HttpStatus.INTERNAL_SERVER_ERROR),
    AUTHORIZED_HEADER_ERROR(1018, "Authorized Header error", HttpStatus.INTERNAL_SERVER_ERROR),
    OTP_EXPIRED_OR_NOT_FOUND(1019, "OTP expired or not found", HttpStatus.BAD_REQUEST),
    OTP_INVALID(1020, "OTP is invalid", HttpStatus.BAD_REQUEST),
    OTP_ATTEMPT_LIMIT_EXCEEDED(1021, "OTP attempt limit exceeded", HttpStatus.BAD_REQUEST),
    OTP_EXPIRED(1022, "OTP expired", HttpStatus.BAD_REQUEST),
    DISABLED_2FA(1023, "2FA is Disabled", HttpStatus.BAD_REQUEST),
    OTP_REQUEST_LIMIT_EXCEEDED(1024, "OTP request limit exceeded", HttpStatus.BAD_REQUEST),
    OTP_REQUEST_TOO_FREQUENT(1025, "OTP request too frequent", HttpStatus.BAD_REQUEST),
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
