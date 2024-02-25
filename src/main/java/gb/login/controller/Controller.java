package gb.login.controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@org.springframework.stereotype.Controller
public class Controller {
    @GetMapping("/login")
    public String hello() {
        return "login";
    }

    @GetMapping("/public-data")
    public String publicData(Model model) {
        model.addAttribute("message", "Public data.");
        return "public-data";
    }

    @GetMapping("/private-data")
    public String privateData(Model model) {
        model.addAttribute("message", "Private data.");
        return "private-data";
    }

}
