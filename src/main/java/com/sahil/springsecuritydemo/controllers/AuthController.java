package com.sahil.springsecuritydemo.controllers;


import com.sahil.springsecuritydemo.configs.security.JwtUtil;
import com.sahil.springsecuritydemo.dto.LoginUserDTO;
import com.sahil.springsecuritydemo.dto.RegisterUserDTO;
import com.sahil.springsecuritydemo.entity.User;
import com.sahil.springsecuritydemo.enums.Role;
import com.sahil.springsecuritydemo.service.RegisterUserService;
import com.sahil.springsecuritydemo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final RegisterUserService registerUserService;

    private final JwtUtil jwtUtil;

    private final AuthenticationManager authenticationManager;


    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterUserDTO registerUserDTO) {
        User user = registerUserService.registerUser(registerUserDTO.getEmail(), registerUserDTO.getPassword());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUserDTO loginUserDTO) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginUserDTO.getEmail(), loginUserDTO.getPassword())
        );

        UserDetails userDetails = userService.loadUserByUsername(loginUserDTO.getEmail());

        Set<Role> roles = userDetails.getAuthorities().stream().map(auth -> Role.valueOf(auth.getAuthority())).collect(Collectors.toSet());

        String token = jwtUtil.generateToken(
                userDetails.getUsername(),
                roles);

        return ResponseEntity.ok(token);

    }
}