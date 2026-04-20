package com.phishingdetection.service;

import com.phishingdetection.model.PredictionResponse;
import com.phishingdetection.model.UrlCheck;
import com.phishingdetection.model.UrlRequest;
import com.phishingdetection.repository.UrlCheckRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class PhishingService {

    private final WebClient webClient;
    private final UrlCheckRepository repository;

    public PhishingService(UrlCheckRepository repository) {
        this.repository = repository;

        // Hardcoded Python API URL for Render cloud deployment
        String pythonApiUrl = "https://phishing-python-api.onrender.com";

        this.webClient = WebClient.builder()
                .baseUrl(pythonApiUrl)
                .build();
        System.out.println("Python API URL: " + pythonApiUrl);
    }

    public PredictionResponse predict(UrlRequest request) {
        String modelType = (request.getModelType() != null && !request.getModelType().isEmpty())
                ? request.getModelType()
                : "rf";

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("url", request.getUrl());
        requestBody.put("model_type", modelType);

        System.out.println("Calling Python API for URL: " + request.getUrl());

        PredictionResponse response = webClient.post()
                .uri("/predict")
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(PredictionResponse.class)
                .block();

        if (response == null) {
            throw new RuntimeException("Received null response from Python API");
        }

        UrlCheck log = new UrlCheck();
        log.setUrl(request.getUrl());
        log.setModelType(modelType);
        log.setPhishing(response.isIs_phishing());
        log.setConfidence(response.getConfidence());
        log.setModelUsed(response.getModel_used());
        log.setCheckedAt(LocalDateTime.now());

        repository.save(log);

        return response;
    }
}