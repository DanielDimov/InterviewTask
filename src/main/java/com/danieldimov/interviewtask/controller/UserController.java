package com.danieldimov.interviewtask.controller;

import com.danieldimov.interviewtask.model.entity.UserEntity;
import com.danieldimov.interviewtask.model.dto.UserDTO;
import com.danieldimov.interviewtask.service.UserService;
import jakarta.validation.constraints.Email;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RequestMapping("/api/auth")
@RestController
@Transactional
@Validated
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public Map<String, Boolean> register(@RequestParam @Email String email, @RequestParam String password) {
        var registeredUser = userService.register(email, password);

        return Map.of("registered", registeredUser != null && registeredUser.getId() > 0);
    }

    @PostMapping("/login")
    public Map<String, String> authenticate(@RequestParam @Email String email, @RequestParam String password) {
        var authenticatedUser = userService.authenticate(email, password);

        var accessToken = userService.generateAccessToken(authenticatedUser);
        var refreshToken = userService.generateRefreshToken(authenticatedUser);

        return Map.of("access-token", accessToken, "refresh-token", refreshToken);
    }

    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestParam String token) {
        var authenticatedUser = userService.authenticate(token);

        var accessToken = userService.generateAccessToken(authenticatedUser);
        var refreshToken = userService.generateRefreshToken(authenticatedUser);

        return Map.of("access-token", accessToken, "refresh-token", refreshToken);
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('ADMIN')")
    public List<String> getRoles() {
        return userService.getRoles();
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('ADMIN')")
    public List<UserDTO> getUsers() {
        return userService.getAllUsers().stream()
                .map(UserDTO::new)
                .toList();
    }

    @GetMapping("/my-user")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'MERCHANT')")
    public UserDTO getMyUser(Authentication auth) {
        var currentUser = userService.getAuthenticationUser(auth);

        return new UserDTO(currentUser);
    }

    @PostMapping("/activate/{userId}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public Map<String, Boolean> activateUser(@PathVariable Long userId, Authentication auth) {
        var authUser = userService.getAuthenticationUser(auth);

        var success = userService.activate(userId, authUser);
        return Map.of("activated", success);
    }

    @PostMapping("/deactivate/{userId}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public Map<String, Boolean> deactivateUser(@PathVariable Long userId, Authentication auth) {
        var authUser = userService.getAuthenticationUser(auth);

        var success = userService.deactivate(userId, authUser);
        return Map.of("deactivated", success);
    }

    @PostMapping("/role/{userId}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public Map<String, Boolean> setUserRole(@PathVariable Long userId, @RequestParam String role, Authentication auth) {
        var authUser = userService.getAuthenticationUser(auth);

        var success = userService.setRole(userId, role, authUser);
        return Map.of("changed", success);
    }

}