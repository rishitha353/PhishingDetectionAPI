package com.phishingdetection.controller;

import com.phishingdetection.model.PredictionResponse;
import com.phishingdetection.model.UrlCheck;
import com.phishingdetection.model.UrlRequest;
import com.phishingdetection.repository.UrlCheckRepository;
import com.phishingdetection.service.PhishingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/phishing")
public class PhishingController {

    private final PhishingService service;
    private final UrlCheckRepository repository;

    public PhishingController(PhishingService service, UrlCheckRepository repository) {
        this.service = service;
        this.repository = repository;
    }

    @PostMapping("/predict")
    public ResponseEntity<PredictionResponse> predict(@RequestBody UrlRequest request) {
        PredictionResponse response = service.predict(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/history")
    public ResponseEntity<List<UrlCheck>> getHistory() {
        return ResponseEntity.ok(repository.findAll());
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Java API is running!");
    }
}