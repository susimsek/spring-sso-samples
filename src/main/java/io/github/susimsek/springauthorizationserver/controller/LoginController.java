package io.github.susimsek.springauthorizationserver.controller;

import io.github.susimsek.springauthorizationserver.dto.LoginForm;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String showLoginForm(Model model) {
        model.addAttribute("loginForm", new LoginForm(null, null));
        return "login";
    }
}
