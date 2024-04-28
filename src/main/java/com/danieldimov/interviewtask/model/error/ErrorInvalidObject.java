package com.danieldimov.interviewtask.model.error;

import io.github.wimdeblauwe.errorhandlingspringbootstarter.ResponseErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
@ResponseErrorCode("OBJECT_IS_INVALID")
public class ErrorInvalidObject extends RuntimeException {
    public ErrorInvalidObject(String msg) {
        super(msg);
    }
}
