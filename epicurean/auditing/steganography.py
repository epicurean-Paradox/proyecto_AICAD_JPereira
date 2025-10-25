from stegano import lsb
from epicurean.auditing.logger import get_logger

logger = get_logger(__name__)

def hide_log_in_image(input_image_path: str, output_image_path: str, log_data: str) -> bool:
    """
    Hides log data within an image file using steganography.

    Args:
        input_image_path: Path to the original image.
        output_image_path: Path to save the image with hidden data.
        log_data: The string data to hide in the image.

    Returns:
        True if hiding the data was successful, False otherwise.
    """
    logger.debug(f"Hiding log data in '{input_image_path}'.")
    try:
        # Hide the secret message (log_data) in the image
        secret_image = lsb.hide(input_image_path, log_data)
        
        # Save the output image
        secret_image.save(output_image_path)
        
        logger.info(f"Successfully hid logs in '{output_image_path}'.")
        return True
    except FileNotFoundError:
        logger.error(f"Input image for steganography not found at: {input_image_path}")
        return False
    except Exception as e:
        logger.error(f"An error occurred during steganography: {e}")
        return False
