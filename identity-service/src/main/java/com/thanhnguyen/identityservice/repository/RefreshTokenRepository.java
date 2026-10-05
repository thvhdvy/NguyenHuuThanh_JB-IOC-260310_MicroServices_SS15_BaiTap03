package com.thanhnguyen.identityservice.repository;

import com.thanhnguyen.identityservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
}
