import cv2
import hashlib
import numpy as np
from typing import List, Optional

from epicurean.auditing.logger import get_logger

logger = get_logger(__name__)

def list_available_cameras() -> List[int]:
    """
    Detects and lists available camera devices.

    Returns:
        A list of integer indices for available cameras.
    """
    logger.info("Detecting available video cameras.")
    available_indices = []
    index = 0
    # Check for up to 10 camera indices.
    while index < 10:
        cap = cv2.VideoCapture(index)
        if cap.isOpened():
            available_indices.append(index)
            cap.release()
        index += 1
    
    if not available_indices:
        logger.warning("No video cameras detected.")
    else:
        logger.info(f"Found cameras at indices: {available_indices}")
        
    return available_indices

def capture_snapshot(camera_index: int) -> Optional[np.ndarray]:
    """
    Captures a single frame from a specified camera.

    Args:
        camera_index: The index of the camera to use.

    Returns:
        A NumPy array representing the captured image, or None if capture fails.
    """
    logger.info(f"Attempting to capture snapshot from camera {camera_index}.")
    cap = cv2.VideoCapture(camera_index)
    
    if not cap.isOpened():
        logger.error(f"Cannot open camera at index {camera_index}.")
        cap.release()
        return None
        
    ret, frame = cap.read()
    cap.release()
    
    if not ret:
        logger.error(f"Failed to read frame from camera {camera_index}.")
        return None
        
    logger.info(f"Successfully captured snapshot from camera {camera_index}.")
    return frame

def get_entropy_from_image(image: np.ndarray) -> str:
    """
    Generates a SHA-256 hash from the raw image data for use as an entropy seed.

    Args:
        image: A NumPy array representing the image.

    Returns:
        A hexadecimal string of the SHA-256 hash.
    """
    logger.debug("Generating entropy seed from image data.")
    image_bytes = image.tobytes()
    
    hasher = hashlib.sha256()
    hasher.update(image_bytes)
    hex_digest = hasher.hexdigest()
    
    logger.info(f"Generated entropy seed: {hex_digest[:16]}...")
    return hex_digest
