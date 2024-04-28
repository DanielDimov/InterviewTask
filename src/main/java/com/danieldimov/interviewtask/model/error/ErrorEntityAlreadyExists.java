package com.danieldimov.interviewtask.model.error;

import io.github.wimdeblauwe.errorhandlingspringbootstarter.ResponseErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
@ResponseErrorCode("ENTITY_ALREADY_EXISTS")
public class ErrorEntityAlreadyExists extends RuntimeException {
    public ErrorEntityAlreadyExists(String msg) {
        super(msg);
    }
}
