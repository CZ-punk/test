package com.cos.security1.summary;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@ToString
public class ServerReceiveDto {

    private String summary;
    // 원준님이 주실 Json 형태를 파싱할 DTO



    public ServerReceiveDto(String summary) {
        this.summary = summary;
    }
}
