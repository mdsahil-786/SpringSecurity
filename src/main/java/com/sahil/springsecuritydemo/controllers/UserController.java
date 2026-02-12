package com.sahil.springsecuritydemo.controllers;

import com.sahil.springsecuritydemo.entity.User;
import com.sahil.springsecuritydemo.service.RegisterUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final RegisterUserService registerUserService;

    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<?> getUserProfile() {
        log.info("Fetching user profile");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String email = authentication.getName();

        log.info("Fetching user profile for user: {}", email);

        User user = registerUserService.findByEmail(email);
        log.info("User profile fetched successfully for user: {}", user.getEmail());
        return ResponseEntity.ok(user);
    }



}