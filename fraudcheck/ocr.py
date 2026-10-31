"""OCR wrapper — image -> text.

Primary: Tesseract binary (install: apt tesseract-ocr / UB Mannheim build
on Windows / brew on macOS). Fallback: RapidOCR (pip rapidocr_onnxruntime,
pure-Python ONNX) when tesseract is absent — used for CI/verification.
"""
from __future__ import annotations

import shutil
import subprocess

_rapid = None


def tesseract_available() -> bool:
    return shutil.which("tesseract") is not None


def rapidocr_available() -> bool:
    try:
        import rapidocr_onnxruntime  # noqa: F401
        return True
    except ImportError:
        return False


def _ocr_tesseract(path: str, timeout: int) -> str:
    proc = subprocess.run(
        ["tesseract", path, "stdout", "-l", "eng+nep", "--psm", "6"],
        capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        # retry with English only (nep traineddata may be absent)
        proc = subprocess.run(
            ["tesseract", path, "stdout", "-l", "eng", "--psm", "6"],
            capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError(f"tesseract failed: {proc.stderr[:200]}")
    return proc.stdout


def _ocr_rapid(path: str) -> str:
    global _rapid
    if _rapid is None:
        from rapidocr_onnxruntime import RapidOCR
        _rapid = RapidOCR()  # downloads ONNX models on first use
    result, _ = _rapid(path)
    if not result:
        return ""
    return "\n".join(r[1] for r in result)


def ocr_image(path: str, timeout: int = 120) -> str:
    """Return OCR text for an image file.

    Raises FileNotFoundError for a missing image, RuntimeError when no
    OCR backend is installed.
    """
    import os
    if not os.path.exists(path):
        raise FileNotFoundError(f"image not found: {path}")
    if tesseract_available():
        return _ocr_tesseract(path, timeout)
    if rapidocr_available():
        return _ocr_rapid(path)
    raise RuntimeError(
        "no OCR backend found — install tesseract (apt: tesseract-ocr, "
        "Windows: UB Mannheim build) or: pip install rapidocr_onnxruntime")


def pipeline(image_path: str) -> dict:
    """Full v1 pipeline: image -> invoice dict (lazy imports)."""
    from .extract import extract_fields
    return extract_fields(ocr_image(image_path))
