package com.cos.security1.summary;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class SummaryService {

    public ServerReceiveDto getSummaryFromAiServer(ServerSendDto serverSendDto) {

        WebClient webClient = WebClient.create();

        return webClient.post()
                .uri("http://요약서버의URL")
                .bodyValue(serverSendDto)
                .retrieve()
                .bodyToMono(ServerReceiveDto.class)
                .block();
    }

}
