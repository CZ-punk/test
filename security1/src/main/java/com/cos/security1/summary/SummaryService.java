package com.cos.security1.summary;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class SummaryService {

    public ServerReceiveDto getSummaryFromAiServer(ServerSendDto serverSendDto) {

        WebClient webClient = WebClient.create();

        return webClient.post()
                .uri("http://43.200.188.238:8080/summary")
                .bodyValue(serverSendDto)
                .retrieve()
                .bodyToMono(ServerReceiveDto.class)
                .block();

        /**
         * {"speech": str, // 어투
         * "contents": str, // 내용
         * "subject": str, // 제목
         * "length": int} // 요약하고싶은 길이
         */
    }
}
