"""
OwlEyeEngine - Vercel Serverless entrypoint.

This module re-exports the FastAPI `app` so Vercel can detect and serve it
as a single serverless function. For portfolio/demo purposes, run in DEMO_MODE
(simulated data), which requires no persistent processes.
"""
import os

# Force demo mode on serverless (Vercel has no persistent process / WebSockets)
os.environ.setdefault("OWLEYE_DEMO_MODE", "true")

from web_dashboard import app, DEMO_MODE  # noqa: E402

# Vercel's ASGI contract
handler = app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
