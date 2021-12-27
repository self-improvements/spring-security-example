package io.github.imsejin.example.googleotp.view.login;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/view")
class LoginController {

    @GetMapping("login/1")
    Object firstLogin(Model model) {
        return "first-login";
    }

    @GetMapping("login/2")
    Object secondLogin(Model model) {
        return "first-login";
    }

}

