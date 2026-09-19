# 📊 AI Agent Webhook Auditor

A secure, high-performance system built from scratch to catch incoming code deployment webhooks, parse payloads asynchronously, run security rule validation, and track histories inside an isolated environment.

## 🛠️ Tech Stack & Features
- **FastAPI**: Asynchronous web engine for 24/7 webhook capturing.
- **PostgreSQL 16**: Isolated transactional database container for immutable logging.
- **SQLAlchemy & Asyncpg**: Async database operations to prevent blocking lags.
- **AI Shield Simulation**: Automated checks that instantly isolate injection threats.
- **Docker Compose**: Single-command containerization for easy deployment.
- **Live HTML Dashboard**: Visual breakdown table tracking all runtime logs directly from the database.

## 🚀 How to Run the Project

### 1. Boot up the Containers
Ensure you have **Docker Desktop** running, open your terminal inside the project directory, and execute:
```bash
docker compose up
```

### 2. Access the Interactive API Docs
Open your browser and navigate to:
[http://localhost:8000/docs](http://localhost:8000/docs)
Here you can use the built-in Swagger interface to send webhook test requests using both safe and dangerous code payloads.

### 3. Check the Live Dashboard
To view your database tables visually inside a clean user interface table format, navigate to:
[http://localhost:8000/dashboard](http://localhost:8000/dashboard)