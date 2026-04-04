package com.phishingdetection.model;

public class UrlRequest {

    private String url;
    // rf, svm, xgb, cnn, ensemble
    private String modelType;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getModelType() {
        return modelType;
    }

    public void setModelType(String modelType) {
        this.modelType = modelType;
    }
}
