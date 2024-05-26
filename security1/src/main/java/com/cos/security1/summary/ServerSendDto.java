package com.cos.security1.summary;


import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class ServerSendDto {
    private String speech;
    private String contents;
    private String subject;
    private int length;

}
