package com.tuandanh.identityService.exception;

public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error"),
    INVALID_KEY(1001, "Uncategorized error"),
    USER_EXISTED(1002, "User existed"),
    USERNAME_INVALID(1003, "Username must be at least 3 characters and cannot be blank"),
    INVALID_PASSWORD(1004, "Password must be at least 8 characters and cannot be blank"),
    USER_NOT_EXISTED(1005, "User not existed"),
    FIRSTNAME_INVALID(1006, "First name cannot exceed 30 characters and cannot be blank"),
    LASTNAME_INVALID(1007, "Last name cannot exceed 30 characters and cannot be blank"),
    EMAIL_INVALID(1008, "Invalid email format and cannot be blank"),
    DOB_INVALID(1009, "First name cannot exceed 30 characters and cannot be blank"),// fix later
    USER_ALREADY_BLOCKED(1009, "User is blocked"),
    USER_ALREADY_UNBLOCKED(1009, "User is blocked"),
    ;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

    private int code;
    private String message;

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
