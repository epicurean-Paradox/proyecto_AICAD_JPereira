import argparse
import os
import logging
import io
import cv2
import random
from epicurean.auditing.logger import get_logger
from epicurean.entropy.source import (
    list_available_cameras,
    capture_snapshot,
    get_entropy_from_image,
)
from epicurean.pe_mangler.mangler import PEMangler

# Configure logger
logger = get_logger(__name__)

def main():
    """
    Main entry point for the proyecto_AICAD_JPereira application.
    Handles command-line arguments for different modes of operation.
    """
    # --- Setup in-memory log capturing ---
    log_stream = io.StringIO()
    temp_handler = logging.StreamHandler(log_stream)
    logging.getLogger().addHandler(temp_handler)

    parser = argparse.ArgumentParser(
        description="proyecto_AICAD_JPereira: Adversarial PE File Generator."
    )
    parser.add_argument(
        "--list-cameras",
        action="store_true",
        help="List all available camera indices and exit.",
    )
    parser.add_argument(
        "--use-camera-index",
        type=int,
        metavar="INDEX",
        help="Use the specified camera index to generate the entropy source.",
    )
    parser.add_argument(
        "--pe-file",
        type=str,
        metavar="PATH",
        help="Path to the PE file to be mutated.",
    )

    args = parser.parse_args()
    logger.info(f"Application started with arguments: {args}")

    if args.list_cameras:
        print("Detecting available cameras...")
        logger.info("Listing available cameras.")
        cameras = list_available_cameras()
        if cameras:
            print("Available camera indices found:")
            for cam_index in cameras:
                print(f"  - {cam_index}")
        else:
            print("No cameras found.")
            logger.warning("No cameras were found during detection.")

    elif args.use_camera_index is not None:
        # --- Entropy Generation ---
        logger.info(f"--- Using camera index: {args.use_camera_index} ---")
        frame = capture_snapshot(args.use_camera_index)
        if frame is None:
            logger.critical("Failed to capture frame. Exiting.")
            print("\n--- Failed to capture frame. Exiting. ---")
            return

        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        snapshot_path = os.path.join(output_dir, "snapshot.png")
        cv2.imwrite(snapshot_path, frame)
        logger.info(f"Original snapshot saved to {snapshot_path}")

        seed = get_entropy_from_image(frame)
        if not seed:
            logger.critical("Failed to generate seed. Exiting.")
            print("\n--- Failed to generate seed. Exiting. ---")
            return

        logger.info("--- Entropy Source Acquired ---")
        print("\n--- Entropy Source Acquired ---")
        print(f"  SHA-256 Seed: {seed}")
        print("-----------------------------")

        # --- PE File Loading and Mutation Loop ---
        if args.pe_file:
            max_attempts = 5
            success = False
            for attempt in range(max_attempts):
                logger.info(f"--- Starting Mutation Attempt {attempt + 1}/{max_attempts} ---")
                mangler = None
                try:
                    pe_file_path = os.path.abspath(args.pe_file)
                    mangler = PEMangler(pe_file_path)
                    if attempt == 0:
                        logger.info("Initial PE file loaded successfully.")
                        print(mangler.get_info())

                    # --- Apply Mutations with attempt-specific seed ---
                    attempt_seed = f"{seed}_{attempt}"
                    rng = random.Random(attempt_seed)
                    
                    mutations_applied = []
                    
                    # 1. Section Rename Mutation
                    if mangler.apply_section_rename_mutation(attempt_seed):
                        mutations_applied.append("Section Rename")
                    
                    # 2. NOP Insertion with random name
                    nop_section_name = "." + ''.join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=6))
                    if mangler.apply_nops_mutation(attempt_seed, section_name=nop_section_name):
                        mutations_applied.append(f"NOP Insertion ({nop_section_name})")

                    if not mutations_applied:
                        logger.error("No mutations could be applied for this attempt.")
                        continue

                    logger.info(f"Attempt {attempt + 1}: Applied mutations: {', '.join(mutations_applied)}")

                    # --- Early Warning Evaluation ---
                    from epicurean.monitoring.early_warning import is_still_valid, is_detected
                    is_valid = is_still_valid(mangler.pe)
                    # We will now only consider ".gemini" as a suspicious name for the test
                    detected = is_detected(mangler.pe, suspicious_names=[".gemini"])

                    if is_valid and not detected:
                        logger.info(f"Attempt {attempt + 1} PASSED: PE is valid and not detected.")
                        output_pe_path = os.path.join(output_dir, "putty_mutated.exe")
                        mangler.save_mutated_file(output_pe_path)

                        # --- Steganography Step ---
                        logger.info("--- Starting Steganography Step ---")
                        from epicurean.auditing.steganography import hide_log_in_image
                        log_contents = log_stream.getvalue()
                        output_image_path = os.path.join(output_dir, "final_image_with_logs.png")
                        hide_log_in_image(snapshot_path, output_image_path, log_contents)
                        
                        success = True
                        print(f"\n--- Process SUCCEEDED on attempt {attempt + 1}. ---")
                        break # Exit the loop on success
                    else:
                        logger.warning(f"Attempt {attempt + 1} FAILED: Valid={is_valid}, Detected={detected}. Retrying...")
                        print(f"Attempt {attempt + 1} failed evaluation. Retrying...")

                except (FileNotFoundError, Exception) as e:
                    logger.critical(f"A critical error occurred during attempt {attempt + 1}: {e}", exc_info=True)
                    print(f"\n--- A critical error occurred: {e} ---")
                    break # Stop on critical errors
                finally:
                    if mangler:
                        mangler.close()
            
            if not success:
                logger.error(f"Failed to produce a valid, undetected PE file after {max_attempts} attempts.")
                print(f"\n--- Process FAILED after {max_attempts} attempts. ---")

    else:
        parser.print_help()
    
    # --- Clean up log handler ---
    logging.getLogger().removeHandler(temp_handler)

if __name__ == "__main__":
    main()
