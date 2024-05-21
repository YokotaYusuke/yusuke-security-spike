package com.example.yusukesecurityspike

import org.springframework.web.bind.annotation.RequestMapping

class HomeController {
    @RequestMapping("/")
    fun index(): String {
        return "index.html"
    }
}