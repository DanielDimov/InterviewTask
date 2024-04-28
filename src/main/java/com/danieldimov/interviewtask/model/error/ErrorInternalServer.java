package com.danieldimov.interviewtask.model.error;

import io.github.wimdeblauwe.errorhandlingspringbootstarter.ResponseErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
@ResponseErrorCode("INTERNAL_SERVER_ERROR")
public class ErrorInternalServer extends RuntimeException {
    public ErrorInternalServer() {
        super("Something is broken at the server - sorry!");
    }
}
