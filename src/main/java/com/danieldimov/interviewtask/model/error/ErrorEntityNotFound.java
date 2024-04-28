package com.danieldimov.interviewtask.model.error;

import io.github.wimdeblauwe.errorhandlingspringbootstarter.ResponseErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
@ResponseErrorCode("ENTITY_NOT_FOUND")
public class ErrorEntityNotFound extends RuntimeException {
    public ErrorEntityNotFound(String msg) {
        super(msg);
    }
}
