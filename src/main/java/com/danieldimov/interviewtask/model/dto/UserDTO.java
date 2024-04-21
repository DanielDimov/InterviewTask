package com.danieldimov.interviewtask.model.dto;

import com.danieldimov.interviewtask.model.entity.UserEntity;

public record UserDTO(Long id, String email, String role, boolean active) {

    public UserDTO(UserEntity user) {
        this(user.getId(), user.getEmail(), user.getRole(), user.isActive());
    }
}