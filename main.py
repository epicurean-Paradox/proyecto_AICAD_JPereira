import argparse
import os
from epicurean.entropy.source import (
    list_available_cameras,
    capture_frame,
    generate_seed_from_image
)
from epicurean.pe_mangler.mangler import PEMangler

def main():
    """
    Main entry point for the Epicurean Paradox application.
    Handles command-line arguments for different modes of operation.
    """
    parser = argparse.ArgumentParser(
        description="Epicurean Paradox: Adversarial PE File Generator."
    )
    parser.add_argument(
        "--list-cameras",
        action="store_true",
        help="List all available cameras and exit."
    )
    parser.add_argument(
        "--use-camera",
        type=str,
        metavar='"Camera Name"',
        help="Use the specified camera to generate the entropy source."
    )
    parser.add_argument(
        "--pe-file",
        type=str,
        metavar='PATH',
        help="Path to the PE file to be mutated."
    )

    args = parser.parse_args()

    if args.list_cameras:
        print("Detecting available cameras...")
        cameras = list_available_cameras()
        if cameras:
            print("Available cameras found:")
            for cam in cameras:
                print(f"  - {cam}")
        else:
            print("No cameras found or 'imagesnap' command failed.")

    elif args.use_camera:
        # --- Entropy Generation ---
        print(f"--- Using camera: '{args.use_camera}' ---")
        image_path = capture_frame(args.use_camera)
        if not image_path:
            print("\n--- Failed to capture frame. Exiting. ---")
            return

        seed = generate_seed_from_image(image_path)
        if not seed:
            print("\n--- Failed to generate seed. Exiting. ---")
            return

        print("\n--- Entropy Source Acquired ---")
        print(f"  Image Path: {image_path}")
        print(f"  SHA-256 Seed: {seed}")
        print("-----------------------------")

        # --- PE File Loading and Mutation ---
        if args.pe_file:
            mangler = None
            try:
                # Ensure we use an absolute path
                pe_file_path = os.path.abspath(args.pe_file)
                mangler = PEMangler(pe_file_path)
                print(mangler.get_info())

                # Apply mutation
                if mangler.apply_nops_mutation(seed):
                    # Save the mutated file
                    output_path = os.path.join(os.path.dirname(pe_file_path), "putty_mutated.exe")
                    mangler.save_mutated_file(output_path)
                else:
                    print("\n--- Mutation failed. File will not be saved. ---")

            except (FileNotFoundError, Exception) as e:
                print(f"Could not process PE file: {e}")
            finally:
                if mangler:
                    mangler.close()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
