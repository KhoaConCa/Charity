package com.tuandanh.identityService.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.tuandanh.identityService.dto.request.*;
import com.tuandanh.identityService.dto.response.*;
import com.tuandanh.identityService.entity.Device;
import com.tuandanh.identityService.entity.InvalidatedToken;
import com.tuandanh.identityService.entity.User;
import com.tuandanh.identityService.enums.TokenType;
import com.tuandanh.identityService.exception.AppException;
import com.tuandanh.identityService.exception.ErrorCode;
import com.tuandanh.identityService.repository.DeviceRepository;
import com.tuandanh.identityService.repository.InvalidatedTokenRepository;
import com.tuandanh.identityService.repository.UserRepository;
import com.tuandanh.identityService.service.redis.RedisService;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    UserRepository userRepository;
    InvalidatedTokenRepository invalidatedTokenRepository;
    RedisService redisService;
    EmailService emailService;
    PasswordEncoder passwordEncoder;
    DeviceRepository deviceRepository;

    HttpServletRequest httpServletRequest;

    private static final Duration OTP_EXPIRATION = Duration.ofMinutes(5); // 5 minutes TTL

    @NonFinal
    @Value("${jwt.signerKey}")
    protected String SIGNER_KEY;

    @NonFinal
    @Value("${jwt.valid-duration}")
    protected long VALID_DURATION;

    @NonFinal
    @Value("${jwt.refreshable-duration}")
    protected long REFRESHABLE_DURATION;

    public TwoFAResponse enable2FA(){
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        return TwoFAResponse.builder()
                .result("2FA enabled successfully")
                .build();
    }

    public TwoFAResponse disable2FA(VerifyOtpRequest verifyOtpRequest){
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Kiểm tra nếu 2FA chưa bật thì không cần disable
        if (!user.isTwoFactorEnabled()) {
            throw new AppException(ErrorCode.DISABLED_2FA);
        }

        // Optional: Verify OTP if required
        if (verifyOtp(verifyOtpRequest) == null) {
            throw new AppException(ErrorCode.OTP_INVALID);
        }

        user.setTwoFactorEnabled(false);
        userRepository.save(user);

        return TwoFAResponse.builder()
                .result("2FA disabled successfully")
                .build();
    }

    public SendOtpResponse sendOtp(@Nullable String username) throws AppException {
        User user;

        if (username != null) {
            // Trường hợp chưa đăng nhập, tìm user theo username được truyền vào
            user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        } else {
            // Trường hợp đã đăng nhập, lấy username từ SecurityContext
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated() ||
                    authentication.getPrincipal().equals("anonymousUser")) {
                throw new AppException(ErrorCode.UNAUTHENTICATED);
            }

            String currentUsername = authentication.getName();
            user = userRepository.findByUsername(currentUsername)
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        }

        SendEmailRequest verifyEmailRequest = new SendEmailRequest(user.getEmail());

        String otp = generateOtp();
        // Lưu vào Redis với TTL
        redisService.storeToken(verifyEmailRequest.getEmail(), otp,TokenType.TWO_FACTOR);
        // Gửi email
        emailService.sendTwoFactorCode(verifyEmailRequest.getEmail(), otp);

        return SendOtpResponse.builder()
                .result("Otp sent to email")
                .build();
    }

    private String generateOtp() {
        int otp = (int) (Math.random() * 900_000) + 100_000; // 6-digit
        return String.valueOf(otp);
    }

    public AuthenticationResponse verifyOtp(VerifyOtpRequest verifyOtpRequest)
            throws AppException {
        String currentUsername = verifyOtpRequest.getUsername();
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        String email = user.getEmail();

        // 2. Kiểm tra giới hạn số lần nhập sai
        if (redisService.isOtpAttemptExceeded(email)) {
            throw new AppException(ErrorCode.OTP_ATTEMPT_LIMIT_EXCEEDED); // Custom error code
        }

        // 3. Lấy OTP từ Redis
        String storedOtp = redisService.getValueByToken(email, TokenType.TWO_FACTOR);

        if (storedOtp == null) {
            throw new AppException(ErrorCode.OTP_EXPIRED);
        }

        // 4. So sánh OTP
        if (!storedOtp.equals(verifyOtpRequest.getOtp())) {
            // Tăng số lần nhập sai
            redisService.increaseOtpAttempt(email);
            throw new AppException(ErrorCode.OTP_INVALID);
        }

        // 5. Nếu đúng thì reset số lần sai và xóa OTP
        redisService.resetOtpAttempts(email);
        redisService.deleteToken(email, TokenType.TWO_FACTOR);

        var token = generateToken(user);

        return AuthenticationResponse.builder()
                .authenticated(true)
                .token(token)
                .build();
    }


    public VerifyEmailResponse sendVerifyEmail(SendEmailRequest request) {
        String email = request.getEmail();
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        }

        String token = UUID.randomUUID().toString();
        redisService.storeToken(token, email, TokenType.VERIFY_EMAIL); // Lưu token xác nhận email

        String verifyLink = "http://localhost:8080/api/auth/verify-email?token=" + token;
        emailService.sendVerifyEmail(email, verifyLink);

        return VerifyEmailResponse.builder()
                .result("Verification email sent")
                .build();
    }

    public VerifyEmailResponse sendVerifyEmailLogIn(){
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        String email = user.getEmail();

        SendEmailRequest verifyEmailRequest = new SendEmailRequest(email);

        return sendVerifyEmail(verifyEmailRequest);
    }


    public VerifyEmailConfirmResponse confirmVerifyEmail(VerifyEmailConfirmRequest request) {
        String token = request.getToken();

        String email = redisService.getValueByToken(token, TokenType.VERIFY_EMAIL);
        if (email == null) {
            throw new AppException(ErrorCode.JWT_TOKEN_ERROR);
        }

        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        }

        User user = optionalUser.get();
        user.setEmailVerified(true); // Đánh dấu đã xác nhận
        userRepository.save(user);

        redisService.deleteToken(token, TokenType.VERIFY_EMAIL); // Xóa token

        return VerifyEmailConfirmResponse.builder()
                .result("Email verified successfully")
                .build();
    }



    public ForgotPasswordResponse processForgotPassword(ForgotPasswordRequest forgotPasswordRequest) {
        String email = forgotPasswordRequest.getEmail();
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            // Security: Do not reveal whether email exists
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        }

        String token = UUID.randomUUID().toString();
        redisService.storeToken(token, email, TokenType.RESET_PASSWORD); // Store token in Redis

        String resetLink = "http://localhost:8080/api/auth/reset-password?token=" + token;
        emailService.sendPasswordResetEmail(email, resetLink);

        return ForgotPasswordResponse.builder()
                .result("User existed, go to reset password")
                .build();
    }

    public ResetPasswordResponse resetPassword(ResetPasswordRequest resetPasswordRequest) {
        String token = resetPasswordRequest.getToken();
        String newPassword = resetPasswordRequest.getNewPassword();

        String email = redisService.getValueByToken(token, TokenType.RESET_PASSWORD);
        if (email == null) {
            throw new IllegalArgumentException("Invalid or expired token.");
        }

        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            throw new IllegalArgumentException("User not found.");
        }

        User user = optionalUser.get();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        redisService.deleteToken(token, TokenType.RESET_PASSWORD); // Invalidate token after use

        return ResetPasswordResponse.builder()
                .result("Password changed")
                .build();
    }

    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {
        var token = request.getToken();
        boolean isValid = true;

        try {
            verifyToken(token, false);
        } catch (AppException e) {
            isValid = false;
        }

        return IntrospectResponse.builder().valid(isValid).build();
    }

    public void logout(LogoutRequest request) throws ParseException, JOSEException {
        try {
            var signToken = verifyToken(request.getToken(), true);

            String jit = signToken.getJWTClaimsSet().getJWTID();
            Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken =
                    InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

            invalidatedTokenRepository.save(invalidatedToken);
        } catch (AppException exception){
            log.info("Token already expired");
        }
    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws JOSEException, ParseException {
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        SignedJWT signedJWT = SignedJWT.parse(token);

        Date expiryTime = (isRefresh)
                ? new Date(signedJWT.getJWTClaimsSet().getIssueTime()
                .toInstant().plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS).toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        var verified = signedJWT.verify(verifier);

        if (!(verified && expiryTime.after(new Date()))) throw new AppException(ErrorCode.UNAUTHENTICATED);

        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        return signedJWT;
    }

    public AuthenticationResponse refreshToken(RefreshRequest request) throws ParseException, JOSEException {
        var signedJWT = verifyToken(request.getToken(), true);

        var jit = signedJWT.getJWTClaimsSet().getJWTID();
        var expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        InvalidatedToken invalidatedToken =
                InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

        invalidatedTokenRepository.save(invalidatedToken);

        var username = signedJWT.getJWTClaimsSet().getSubject();

        var user =
                userRepository.findByUsername(username).orElseThrow(() -> new AppException(ErrorCode.UNAUTHENTICATED));

        var token = generateToken(user);

        return AuthenticationResponse.builder().token(token).authenticated(true).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request){
        // 1. Kiểm tra user tồn tại
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // 2. Kiểm tra password
        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());
        if (!authenticated) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        // 3. Kiểm tra device
        String deviceInfo = getDeviceInfo(httpServletRequest);

        boolean deviceExists = deviceRepository.existsByUserAndDeviceInfo(user, deviceInfo);

        // Gắn cờ yêu cầu OTP nếu cần
        boolean otpRequired = false;

        if (!deviceExists) {
            // 3.1 Gửi email cảnh báo
            emailService.sendNewDeviceAlert(user.getEmail(), deviceInfo);

            // 3.2 Lưu thiết bị mới vào DB (chưa xác nhận OTP)
            Device newDevice = Device.builder()
                    .user(user)
                    .deviceInfo(deviceInfo)
                    .createdAt(LocalDateTime.now())
                    .lastUsedAt(LocalDateTime.now())
                    .build();
            deviceRepository.save(newDevice);

            // 3.3 Nếu user không bật 2FA thì thiết bị lạ vẫn yêu cầu OTP
            otpRequired = true;
        } else {
            // Nếu thiết bị đã có, cập nhật lastUsedAt
            Device existingDevice = deviceRepository.findByUserAndDeviceInfo(user, deviceInfo);
            existingDevice.setLastUsedAt(LocalDateTime.now());
            deviceRepository.save(existingDevice);
        }

        // 4. Nếu user bật 2FA thì luôn yêu cầu OTP
        if (user.isTwoFactorEnabled()) {
            otpRequired = true;
        }

        // 5. Nếu cần OTP => gửi OTP & trả về thông báo
        if (otpRequired) {
            SendOtpResponse sendOtpResponse = sendOtp(user.getUsername());
            return AuthenticationResponse.builder()
                    .authenticated(false) // Chưa hoàn tất, cần xác thực OTP
                    .otpRequired(true)    // Cần nhập OTP
                    .message(sendOtpResponse.getResult()) // Thông báo cho client
                    .build();
        }

        // 6. Nếu không cần OTP => sinh token và hoàn tất
        String token = generateToken(user);

        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)
                .build();
    }

    private String getDeviceInfo(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String ip = request.getRemoteAddr();
        return userAgent + " | " + ip; // Kết hợp để tạo định danh thiết bị
    }


    public String generateToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer("tuandanh.com")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli()
                ))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new AppException(ErrorCode.JWT_TOKEN_ERROR);
        }
    }

    private String buildScope(User user) {
        StringJoiner stringJoiner = new StringJoiner(" ");

        if (!CollectionUtils.isEmpty(user.getRoles()))
            user.getRoles().forEach(role -> {
                stringJoiner.add("ROLE_" + role.getName());
                if (!CollectionUtils.isEmpty(role.getPermissions()))
                    role.getPermissions().forEach(permission -> stringJoiner.add(permission.getName()));
            });

        return stringJoiner.toString();
    }

    public String noticeWhenOauth2Failure(){
        return "OAuth2 Login Failed. Please try again.";
    }
}
