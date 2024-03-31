package com.example.springjwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
class AdminController {

    @GetMapping("/admin")
    public String adminPage(){
        return "Admin Controller";
    }
}
