import pefile
from proyecto_aicad_jpereira.auditing.logger import get_logger

logger = get_logger(__name__)

def is_still_valid(pe: pefile.PE) -> bool:
    """
    Performs a sanity check by re-parsing the PE file from its in-memory representation.

    Args:
        pe: The loaded pefile object after mutation.

    Returns:
        True if the PE can be successfully re-parsed, False otherwise.
    """
    logger.debug("Performing validity check on mutated PE by re-parsing.")
    try:
        # Write the PE object to an in-memory byte array and attempt to re-parse it.
        repacked_data = pe.write()
        new_pe = pefile.PE(data=repacked_data)
        # If it gets here without an exception, the structure is likely valid.
        logger.debug("PE re-parsing successful, structure is valid.")
        return True
    except pefile.PEFormatError as e:
        logger.warning(f"PE re-parsing failed. The structure is likely corrupt: {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected exception occurred during PE re-validation: {e}")
        return False

def is_detected(pe: pefile.PE, suspicious_names: list[str] = None) -> bool:
    """
    Simulates a basic signature-based antivirus by checking for suspicious section names.

    Args:
        pe: The loaded pefile object after mutation.
        suspicious_names: A list of section names to consider suspicious.

    Returns:
        True if a suspicious signature is found, False otherwise.
    """
    if suspicious_names is None:
        suspicious_names = [".gemini", ".evil", ".bad"]

    logger.debug(f"Scanning for suspicious section names: {suspicious_names}")
    for section in pe.sections:
        section_name = section.Name.decode().strip('\x00')
        if section_name in suspicious_names:
            logger.warning(f"Detection triggered: Found suspicious section name '{section_name}'.")
            return True
            
    logger.info("No suspicious section names found.")
    return False
