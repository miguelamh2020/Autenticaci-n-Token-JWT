package com.authentication.jwttokenauthentication.repository;

import com.authentication.jwttokenauthentication.model.UserToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepository extends JpaRepository<UserToken, Long> {
    UserToken findByUserId(Long userId);
}
