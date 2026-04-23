package com.phishingdetection.service;

import com.phishingdetection.model.PredictionResponse;
import com.phishingdetection.model.UrlRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.HashMap;
import java.util.Map;

@Service
public class PhishingService {

    private final WebClient webClient;

    public PhishingService() {
        String pythonApiUrl = "https://phishing-python-api.onrender.com";
        this.webClient = WebClient.builder()
                .baseUrl(pythonApiUrl)
                .build();
        System.out.println("Python API URL: " + pythonApiUrl);
    }

    public PredictionResponse predict(UrlRequest request) {
        String modelType = (request.getModelType() != null && !request.getModelType().isEmpty())
                ? request.getModelType()
                : "ensemble";

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

        return response;
    }
}