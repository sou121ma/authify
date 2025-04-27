package in.sm.authify.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
//@RestController
public class Welcome {
    @GetMapping("/")
    public String redirectToSwagger(){
        return "redirect:/swagger-ui.html";
    }
}

