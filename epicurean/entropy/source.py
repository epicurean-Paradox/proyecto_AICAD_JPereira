import subprocess
import hashlib
from typing import List, Tuple, Optional

def _run_command(command: List[str]) -> Tuple[bool, str]:
    """
    Executes a shell command and captures its output.

    Args:
        command: The command to execute as a list of strings.

    Returns:
        A tuple containing a success boolean and the command's stdout or stderr.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return True, result.stdout.strip()
    except FileNotFoundError:
        return False, f"Error: The command '{command[0]}' was not found. Please ensure it is installed and in your PATH."
    except subprocess.CalledProcessError as e:
        return False, f"Error executing command: {e}\n{e.stderr.strip()}"

def list_available_cameras() -> List[str]:
    """
    Lists all video devices available to imagesnap.

    Returns:
        A list of available camera names.
        Returns an empty list if imagesnap is not found or fails.
    """
    success, output = _run_command(["imagesnap", "-l"])
    if not success:
        # In a CLI app, printing to stderr is better, but for now, this is fine.
        print(output)
        return []
    
    lines = output.split('\n')
    # The first line can be "Video Devices:", we clean it up.
    # Also handle the case where a device name might have leading/trailing spaces.
    camera_lines = lines[1:] if lines and "Video Devices:" in lines[0] else lines
    return [line.strip() for line in camera_lines if line.strip()]

def capture_frame(camera_name: str, output_path: str = "snapshot.jpg") -> Optional[str]:
    """
    Captures a single frame from the specified camera.

    Args:
        camera_name: The name of the camera to use.
        output_path: The path to save the captured image file.

    Returns:
        The path to the captured image if successful, otherwise None.
    """
    print(f"Attempting to capture a frame from '{camera_name}'...")
    print("Your OS may request permission to access the camera.")
    
    success, output = _run_command(["imagesnap", "-d", camera_name, output_path])
    
    if success:
        print(f"Successfully saved frame to '{output_path}'")
        return output_path
    else:
        print(output)
        return None

def generate_seed_from_image(image_path: str) -> Optional[str]:
    """
    Generates a SHA-256 hash from an image file.

    Args:
        image_path: The path to the image file.

    Returns:
        The hex digest of the SHA-256 hash, or None if the file cannot be read.
    """
    try:
        with open(image_path, "rb") as f:
            image_bytes = f.read()
            sha256_hash = hashlib.sha256(image_bytes).hexdigest()
            return sha256_hash
    except IOError as e:
        print(f"Error reading image file '{image_path}': {e}")
        return None