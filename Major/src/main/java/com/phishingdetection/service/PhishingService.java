package com.phishingdetection.service;

import com.phishingdetection.model.PredictionResponse;
import com.phishingdetection.model.UrlCheck;
import com.phishingdetection.model.UrlRequest;
import com.phishingdetection.repository.UrlCheckRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

@Service
public class PhishingService {

    private final WebClient client;
    private final UrlCheckRepository repository;

    public PhishingService(UrlCheckRepository repository) {
        this.repository = repository;
        this.client = WebClient.builder()
                .baseUrl("http://localhost:5000")
                .build();
    }

    public PredictionResponse predict(UrlRequest request) {
        Map<String, String> body = Map.of(
                "url", request.getUrl(),
                "model", request.getModelType()
        );

        Mono<PredictionResponse> mono = client.post()
                .uri("/predict")
                .bodyValue(body)
                .retrieve()
                .bodyToMono(PredictionResponse.class);

        PredictionResponse resp = mono.block();

        UrlCheck log = new UrlCheck();
        log.setUrl(request.getUrl());
        log.setModelType(request.getModelType());
        log.setPhishing(resp.isIs_phishing());
        log.setConfidence(resp.getConfidence());
        log.setModelUsed(resp.getModel_used());
        log.setCheckedAt(LocalDateTime.now());

        repository.save(log);

        return resp;
    }
}