"""Vercel serverless entry point.

Vercel's Python runtime serves the `app` object from this file.
No code changes needed here — all serverless adaptations (RapidOCR
fallback, IFC_DATA_DIR, stateless review tokens) live in fraudcheck/.
"""
from fraudcheck.web import app  # noqa: F401
