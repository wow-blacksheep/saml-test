package com.feng.samltest.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MyController {

    @RequestMapping("login")
    public String login() {
        return "login.html";
    }

    @RequestMapping("logout")
    public String logout() {
        return "logout.html";
    }

    @GetMapping("third/authorize")
    @ResponseBody
    public String authorizeByGet() {
        return "authorizeByGet 方式被回调";
    }

    @PostMapping("third/authorize")
    @ResponseBody
    public String authorizeByPost() {
        return "authorizeByPost 方式被回调";
    }
}
