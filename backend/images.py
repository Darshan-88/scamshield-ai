"""Local, bounded screenshot extraction. No image persistence or provider calls."""
import io
import os
import shutil
import subprocess
from threading import BoundedSemaphore

import cv2
import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_BYTES = 8 * 1024 * 1024
MAX_PIXELS = 12_000_000
MAX_SIDE = 6000
MAX_TEXT = 8000
MAX_QR = 5
MAX_QR_LENGTH = 3000
MIME_FORMAT = {'image/png': 'PNG', 'image/jpeg': 'JPEG', 'image/webp': 'WEBP'}
SLOTS = BoundedSemaphore(2)

class ImageInputError(ValueError):
    pass


def ocr_command():
    configured = os.getenv('TESSERACT_CMD', '').strip()
    return shutil.which(configured or 'tesseract')


def capabilities():
    return {'ocr_available': bool(ocr_command()), 'ocr_language': 'eng',
            'qr_available': True, 'max_bytes': MAX_BYTES, 'max_pixels': MAX_PIXELS,
            'formats': list(MIME_FORMAT), 'cloud_image_upload': False}


def decode_image(raw, mime):
    if mime not in MIME_FORMAT:
        raise ImageInputError('Use a PNG, JPEG or WebP image.')
    try:
        with Image.open(io.BytesIO(raw)) as original:
            if original.format != MIME_FORMAT[mime]:
                raise ImageInputError('Image content does not match its declared format.')
            w, h = original.size
            if w * h > MAX_PIXELS or max(w, h) > MAX_SIDE:
                raise ImageInputError('Image exceeds the 12 megapixel or 6000-pixel side limit.')
            if getattr(original, 'n_frames', 1) != 1:
                raise ImageInputError('Animated images are not supported.')
            original.load()
            rgb = ImageOps.exif_transpose(original).convert('RGBA')
            # Flatten transparency onto white, and discard original metadata.
            clean = Image.new('RGB', rgb.size, 'white')
            clean.paste(rgb, mask=rgb.getchannel('A'))
            return clean
    except ImageInputError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError, SyntaxError, OverflowError):
        raise ImageInputError('Invalid or damaged image.') from None


def extract_text(image):
    cmd = ocr_command()
    if not cmd:
        return '', 'not_installed', False
    # No pytesseract temporary files: pass normalized image over stdin.
    gray = ImageOps.autocontrast(ImageOps.grayscale(image))
    gray.thumbnail((3000, 3000))
    stream = io.BytesIO()
    gray.save(stream, format='PNG')
    try:
        result = subprocess.run([cmd, 'stdin', 'stdout', '-l', 'eng', '--psm', '11'],
                                input=stream.getvalue(), capture_output=True, timeout=15,
                                check=False, env={**os.environ, 'OMP_THREAD_LIMIT': '2'})
        if result.returncode:
            return '', 'unavailable', False
        text = result.stdout.decode('utf-8', errors='replace').strip()
        return text[:MAX_TEXT], 'extracted' if text else 'no_text', len(text) > MAX_TEXT
    except subprocess.TimeoutExpired:
        return '', 'timeout', False
    except OSError:
        return '', 'unavailable', False


def qr_kind(value):
    lower = value.lower()
    if lower.startswith(('https://', 'http://')):
        return 'web_url'
    if lower.startswith('upi://'):
        return 'upi_payment'
    return 'other'


def extract_qr(image):
    resized = image.copy()
    resized.thumbnail((2200, 2200))
    gray = cv2.cvtColor(np.asarray(resized), cv2.COLOR_RGB2GRAY)
    detector = cv2.QRCodeDetector()
    values = []
    detected = False
    try:
        ok, decoded, points, _ = detector.detectAndDecodeMulti(gray)
        detected = points is not None and len(points) > 0
        if ok:
            values.extend(v for v in decoded if v)
        if not values:
            value, points, _ = detector.detectAndDecode(gray)
            detected = detected or points is not None
            if value:
                values.append(value)
    except (cv2.error, UnicodeError, ValueError):
        return [], 'unavailable', False
    unique = list(dict.fromkeys(values))
    truncated = len(unique) > MAX_QR or any(len(v) > MAX_QR_LENGTH for v in unique)
    # Skip oversized payloads, never silently alter a link or payment request.
    items = [{'kind': qr_kind(v), 'value': v} for v in unique[:MAX_QR] if len(v) <= MAX_QR_LENGTH]
    return items, 'decoded' if items else 'undecoded' if detected else 'not_detected', truncated


def extract_image(raw, mime):
    image = decode_image(raw, mime)
    text, ocr_status, text_truncated = extract_text(image)
    qr, qr_status, qr_truncated = extract_qr(image)
    return {'text': text, 'ocr_status': ocr_status, 'qr_codes': qr, 'qr_status': qr_status,
            'text_truncated': text_truncated, 'qr_truncated': qr_truncated,
            'width': image.width, 'height': image.height,
            'notice': 'Review extracted content before scanning. OCR and QR recognition may miss information. Never open decoded links or approve payment requests.'}
