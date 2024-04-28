package com.danieldimov.interviewtask.model.error;

import io.github.wimdeblauwe.errorhandlingspringbootstarter.ResponseErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
@ResponseErrorCode("ENTITY_NOT_ACTIVE")
public class ErrorEntityNotActive extends RuntimeException {
    public ErrorEntityNotActive(String msg) {
        super(msg);
    }
}
