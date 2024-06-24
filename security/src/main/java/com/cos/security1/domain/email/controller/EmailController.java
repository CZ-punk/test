package com.cos.security1.domain.email.controller;

import com.cos.security1.domain.email.dto.EmailAddDto;
import com.cos.security1.domain.email.service.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class EmailController {

    private final EmailService emailService;

//    @PostMapping("/addEmail")
//    public addEmail(@ResponseBody EmailAddDto emailAddDto) {
//        emailService.addEmail();
//        return "email add success";
//    }


}
