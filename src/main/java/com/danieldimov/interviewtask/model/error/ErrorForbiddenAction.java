package com.danieldimov.interviewtask.model.error;

import io.github.wimdeblauwe.errorhandlingspringbootstarter.ResponseErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
@ResponseErrorCode("NOT_ACCEPTABLE_ACTION")
public class ErrorForbiddenAction extends RuntimeException {
    public ErrorForbiddenAction(String msg) {
        super(msg);
    }
}
