// src/main/java/com/phishingdetection/model/PredictionResponse.java
package com.phishingdetection.model;

public class PredictionResponse {

    private boolean is_phishing;
    private double confidence;
    private String model_used;

    public boolean isIs_phishing() {
        return is_phishing;
    }

    public void setIs_phishing(boolean is_phishing) {
        this.is_phishing = is_phishing;
    }

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }

    public String getModel_used() {
        return model_used;
    }

    public void setModel_used(String model_used) {
        this.model_used = model_used;
    }
}
