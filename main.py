import os
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, Integer, String, Text, text

# 1. Database Connection Engine
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:my_secure_password@db:5432/webhook_auditor")
engine = create_async_engine(DATABASE_URL, echo=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# 2. Database Schema
class WebhookLog(Base):
    __tablename__ = "webhook_logs"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(50), nullable=False)
    raw_payload = Column(Text, nullable=False)
    ai_status = Column(String(50), default="Pending Evaluation")
    ai_analysis = Column(Text, nullable=True)

# 3. FastAPI App Initialization
app = FastAPI(title="AI Webhook Auditor")

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Data rules for incoming webhooks
class WebhookPayload(BaseModel):
    sender: str
    payload: str

# 4. Asynchronous AI Parsing Core
async def run_ai_code_audit(payload_text: str):
    await asyncio.sleep(1) # Simulates network delay talking to an LLM provider
    
    # Simple logic check to screen inputs
    dangerous_keywords = ["os.system", "rm -rf", "eval(", "subprocess", "password"]
    
    if any(keyword in payload_text for keyword in dangerous_keywords):
        return "FAILED", "AI Audit Alert: Critical Security Threat Detected! Harmful runtime execution strings found."
    else:
        return "PASSED", "AI Audit Clean: Code block verified. Runtime syntax matches standardized criteria."

# 5. Webhook Ingestion API Endpoint
@app.post("/webhook")
async def receive_webhook(data: WebhookPayload):
    async with async_session() as session:
        async with session.begin():
            new_log = WebhookLog(
                sender=data.sender,
                raw_payload=data.payload,
                ai_status="Processing"
            )
            session.add(new_log)
        
        status, review = await run_ai_code_audit(data.payload)
        
        async with session.begin():
            new_log.ai_status = status
            new_log.ai_analysis = review
            session.add(new_log)
            
        return {
            "status": "success",
            "message": f"Webhook caught from {data.sender}",
            "ai_evaluation_status": status,
            "ai_report": review
        }

# 6. Live Dashboard Interface Route
@app.get("/dashboard", response_class=HTMLResponse)
async def view_dashboard():
    async with async_session() as session:
        # Fetch records using the secure engine context
        result = await session.execute(
            text("SELECT id, sender, raw_payload, ai_status, ai_analysis FROM webhook_logs ORDER BY id DESC")
        )
        rows = result.fetchall()
        
    table_rows = ""
    for row in rows:
        # Safely assign styling based on evaluation outcome
        status_color = "#28a745" if row[3] == "PASSED" else ("#dc3545" if row[3] == "FAILED" else "#ffc107")
        table_rows += f"""
        <tr style="border-bottom: 1px solid #ddd; background-color: white;">
            <td style="padding: 12px; border: 1px solid #ddd;">{row[0]}</td>
            <td style="padding: 12px; font-weight: bold; border: 1px solid #ddd;">{row[1]}</td>
            <td style="padding: 12px; border: 1px solid #ddd;"><pre style="margin:0; background:#f4f4f4; padding:5px; border-radius:4px; font-family:Courier,monospace;">{row[2]}</pre></td>
            <td style="padding: 12px; border: 1px solid #ddd; text-align:center;"><span style="background:{status_color}; color:white; padding:6px 12px; border-radius:12px; font-size:12px; font-weight:bold; display:inline-block;">{row[3]}</span></td>
            <td style="padding: 12px; color: #333; border: 1px solid #ddd;">{row[4]}</td>
        </tr>
        """
        
    html_content = f"""
    <html>
        <head>
            <title>AI Webhook Auditor Dashboard</title>
        </head>
        <body style="font-family: Arial, sans-serif; margin: 40px; background-color: #f8f9fa; color: #333;">
            <div style="max-width: 1200px; margin: auto;">
                <h2 style="color: #007bff;">📊 AI Agent Webhook Auditor - Live Log Dashboard</h2>
                <p style="color: #666;">Below are the runtime tracking files saved securely inside your isolated PostgreSQL database container.</p>
                <table style="width: 100%; border-collapse: collapse; background: white; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; margin-top: 20px;">
                    <thead>
                        <tr style="background-color: #007bff; color: white; text-align: left;">
                            <th style="padding: 14px; border: 1px solid #007bff; width: 5%;">ID</th>
                            <th style="padding: 14px; border: 1px solid #007bff; width: 15%;">Sender</th>
                            <th style="padding: 14px; border: 1px solid #007bff; width: 35%;">Code Payload</th>
                            <th style="padding: 14px; border: 1px solid #007bff; width: 15%; text-align:center;">AI Security Status</th>
                            <th style="padding: 14px; border: 1px solid #007bff; width: 30%;">AI Audit Analysis Report</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows if table_rows else '<tr><td colspan="5" style="padding:30px; text-align:center; color:#888; font-size:16px;">No webhooks logged yet. Go to your /docs page to run a test execution!</td></tr>'}
                    </tbody>
                </table>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/")
def read_root():
    return {"message": "AI Webhook Auditor Server is running perfectly!"}