package org.example.tokenexchanger.controller

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class CommonController {

    @RequestMapping("/", "/health-check")
    fun healthCheck(): String {
        return "ok"
    }
}