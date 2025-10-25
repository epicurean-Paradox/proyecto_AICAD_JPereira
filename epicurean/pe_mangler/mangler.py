
import pefile
from typing import Optional

class PEMangler:
    """
    A class to load, analyze, and prepare a PE file for adversarial mutations.
    """

    def __init__(self, file_path: str):
        """
        Initializes the PEMangler by loading a PE file.

        Args:
            file_path: The absolute path to the PE file.

        Raises:
            FileNotFoundError: If the file does not exist.
            pefile.PEFormatError: If the file is not a valid PE file.
        """
        self.file_path = file_path
        self.pe: Optional[pefile.PE] = None

        try:
            print(f"Loading PE file: {self.file_path}")
            self.pe = pefile.PE(self.file_path)
            print("PE file loaded successfully.")
        except FileNotFoundError:
            print(f"Error: File not found at '{self.file_path}'")
            raise
        except pefile.PEFormatError as e:
            print(f"Error: '{self.file_path}' is not a valid PE file. {e}")
            raise

    def get_info(self) -> str:
        """
        Returns a string with basic information about the loaded PE file.
        """
        if not self.pe:
            return "No PE file loaded."

        info = []
        info.append(f"--- PE File Info: {self.file_path} ---")
        info.append(f"  Entry Point: {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        info.append(f"  Number of Sections: {len(self.pe.sections)}")
        
        for section in self.pe.sections:
            section_name = section.Name.decode().strip('\x00')
            info.append(f"    - Section: {section_name}, Size: {section.SizeOfRawData} bytes")
            
        info.append("--------------------------------------")
        return "\n".join(info)

    def apply_nops_mutation(self, seed: str, section_name: str = ".gemini") -> bool:
        """
        Applies the NOP insertion mutation to the loaded PE file.

        Args:
            seed: The seed for deterministic random operations.
            section_name: The name for the new section.

        Returns:
            True if mutation was successful, False otherwise.
        """
        if not self.pe:
            print("Error: Cannot apply mutation, no PE file loaded.")
            return False
        
        print(f"\n--- Applying NOP Insertion Mutation (section: {section_name}) ---")
        from .mutations import add_nop_section
        return add_nop_section(self.pe, seed, section_name=section_name)

    def apply_section_rename_mutation(self, seed: str) -> bool:
        """
        Applies the section rename mutation to the loaded PE file.

        Args:
            seed: The seed for deterministic random operations.

        Returns:
            True if mutation was successful, False otherwise.
        """
        if not self.pe:
            print("Error: Cannot apply mutation, no PE file loaded.")
            return False

        print("\n--- Applying Section Rename Mutation ---")
        from .mutations import rename_random_section
        return rename_random_section(self.pe, seed)

    def save_mutated_file(self, output_path: str) -> bool:
        """
        Saves the modified PE object to a new file.

        Args:
            output_path: The path to save the new PE file.

        Returns:
            True if saving was successful, False otherwise.
        """
        if not self.pe:
            print("Error: Cannot save, no PE file loaded.")
            return False
        
        print(f"\n--- Saving mutated file to: {output_path} ---")
        try:
            self.pe.write(output_path)
            print("File saved successfully.")
            return True
        except Exception as e:
            print(f"Error saving file: {e}")
            return False

    def close(self):
        """
        Closes the PE file handle.
        """
        if self.pe:
            self.pe.close()
