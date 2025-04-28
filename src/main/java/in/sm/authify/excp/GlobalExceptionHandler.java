package in.sm.authify.excp;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public void handleGlobalException(Exception e) {
        System.out.println(e.getMessage());
    }
}
