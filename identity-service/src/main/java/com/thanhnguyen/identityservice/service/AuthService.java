package com.thanhnguyen.identityservice.service;

import com.thanhnguyen.identityservice.dto.request.LoginRequest;
import com.thanhnguyen.identityservice.dto.response.LoginResponse;
import com.thanhnguyen.identityservice.entity.RefreshToken;
import com.thanhnguyen.identityservice.entity.User;
import com.thanhnguyen.identityservice.exception.InvalidCredentialsException;
import com.thanhnguyen.identityservice.repository.RefreshTokenRepository;
import com.thanhnguyen.identityservice.repository.UserRepository;
import com.thanhnguyen.identityservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    @Value("${app.jwt.refresh-token-expiration}") private long refreshTokenExpiration;

    public LoginResponse login(LoginRequest request)
    {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(InvalidCredentialsException::new);
        if(!passwordEncoder.matches(request.getPassword(), user.getHashedPassword()))
        {
            throw new InvalidCredentialsException();
        }
        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpiration));
        refreshTokenRepository.save(refreshToken);
        return new LoginResponse(accessToken, refreshToken.getToken());
    }
}
