````markdown id="finalreadme01"
# 🛡️ Real-Time Phishing Detection System

A microservice-based system that detects phishing URLs in real-time using **Spring Boot APIs** and **Python ML/DL models**.

---

## 🚀 Features
- Real-time phishing URL detection via REST API  
- Multiple ML/DL models: Random Forest, SVM, XGBoost, 1D CNN  
- FastAPI-based ML service for predictions  
- Spring Boot backend for API handling  
- Dockerized services for easy deployment  
- Cloud deployment (ongoing)  
- Simple UI for interacting with the system  

---

## 🏗️ Architecture
Client → Spring Boot (REST API) → FastAPI (ML Models) → MySQL

---

## 🛠️ Tech Stack
- **Backend:** Java, Spring Boot  
- **ML Service:** Python, FastAPI  
- **Models:** Scikit-learn, TensorFlow  
- **Database:** MySQL  
- **Tools:** Docker, Postman  

---

## ⚙️ Setup

### Docker
```bash
docker-compose down -v
docker-compose up --build
````

### Manual Run

**Start ML Service**

```bash
cd python-api
uvicorn main:app --port 5000
```

**Start Backend**

```bash id="n7ccnk"
cd java-backend
mvn spring-boot:run
```

---

## 📡 API

**POST /check-url**

**Request**

```json id="k51nnt"
{
  "url": "http://example.com"
}
```

**Response**

```json id="2pqddp"
{
  "url": "http://example.com",
  "result": "Phishing"
}
```
