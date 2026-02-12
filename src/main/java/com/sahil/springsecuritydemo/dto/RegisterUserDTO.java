package com.sahil.springsecuritydemo.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.Set;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterUserDTO
{
    @NotBlank(message="Username is required")
    @Size(min=3,max=20,message="Username must be between 3 and 20 characters")
    private String username;


    private String email;
    private String password;
}
