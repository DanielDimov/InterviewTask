package com.danieldimov.interviewtask.controller;

import com.danieldimov.interviewtask.model.entity.UserEntity;
import com.danieldimov.interviewtask.model.dto.UserDTO;
import com.danieldimov.interviewtask.service.UserService;
import jakarta.validation.constraints.Email;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RequestMapping("/api/auth")
@RestController
@Validated
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public Map<String, Boolean> register(@RequestParam @Email String email, @RequestParam String password) {
        UserEntity registeredUser = userService.register(email, password);

        return Map.of("registered", registeredUser != null && registeredUser.getId() > 0);
    }

    @PostMapping("/login")
    public Map<String, String> authenticate(@RequestParam @Email String email, @RequestParam String password) {
        UserEntity authenticatedUser = userService.authenticate(email, password);

        String token = userService.generateToken(authenticatedUser);

        return Map.of("token", token);
    }

    @GetMapping("/roles")
    public List<String> getRoles() {
        return List.of("ADMIN", "MERCHANT", "OTHER");
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserDTO> getUsers() {
        return userService.getAllUsers().stream()
                .map(UserDTO::new)
                .toList();
    }

    @GetMapping("/my-user")
    @PreAuthorize("hasAnyRole('ADMIN', 'MERCHANT')")
    public UserDTO getMyUser(Authentication auth) {
        var currentUser = userService.getAuthenticationUser(auth);

        return new UserDTO(currentUser);
    }
}