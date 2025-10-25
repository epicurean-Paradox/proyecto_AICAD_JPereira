import pefile
import random

def align(val_to_align, alignment):
    """Helper function to align a value to a given alignment.
    """
    return ((val_to_align + alignment - 1) // alignment) * alignment

def add_nop_section(pe: pefile.PE, seed: str, section_name: str = ".gemini") -> bool:
    """
    Adds a new executable section to the PE file filled with NOPs.

    Args:
        pe: The loaded pefile object.
        seed: The seed for deterministic random operations (currently unused but kept for API consistency).
        section_name: The name for the new section.

    Returns:
        True if the mutation was successful, False otherwise.
    """
    # Section characteristics: executable code
    characteristics = (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] |
                       pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE'])

    # Use a fixed size for the new section for simplicity
    section_size = 512
    nop_sled = b'\x90' * section_size

    # Create the new section header
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    new_section.Name = section_name.encode('utf-8')
    new_section.Misc_VirtualSize = len(nop_sled)
    
    # Align the virtual address
    last_section = pe.sections[-1]
    new_section.VirtualAddress = align(
        last_section.VirtualAddress + last_section.Misc_VirtualSize,
        pe.OPTIONAL_HEADER.SectionAlignment
    )

    # Align the raw data pointer
    new_section.PointerToRawData = align(
        last_section.PointerToRawData + last_section.SizeOfRawData,
        pe.OPTIONAL_HEADER.FileAlignment
    )

    new_section.SizeOfRawData = align(len(nop_sled), pe.OPTIONAL_HEADER.FileAlignment)
    new_section.Characteristics = characteristics

    # Add the new section header to the list of sections
    pe.sections.append(new_section)

    # Add the actual section data to the end of the file
    # This is a simplified approach; pefile's pack() will handle the final structure
    pe.__data__ = pe.__data__[:new_section.PointerToRawData] + nop_sled

    # Update PE headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = align(
        new_section.VirtualAddress + new_section.Misc_VirtualSize,
        pe.OPTIONAL_HEADER.SectionAlignment
    )

    print(f"Successfully prepared new section '{section_name}' for injection.")
    return True

def rename_random_section(pe: pefile.PE, seed: str) -> bool:
    """
    Renames a randomly chosen, non-critical PE section.

    Args:
        pe: The loaded pefile object.
        seed: The seed for deterministic random operations.

    Returns:
        True if the mutation was successful, False otherwise.
    """
    rng = random.Random(seed)
    
    # Avoid renaming critical sections to reduce chance of corruption
    critical_sections = [".text", ".rdata", ".data", ".rsrc", ".reloc"]
    
    eligible_sections = [
        s for s in pe.sections 
        if s.Name.decode().strip('\x00') not in critical_sections
    ]
    
    if not eligible_sections:
        print("No eligible sections found for renaming.")
        return False

    section_to_rename = rng.choice(eligible_sections)
    original_name = section_to_rename.Name.decode().strip('\x00')

    # Generate a new random name (7 chars, uppercase letters)
    new_name = "." + ''.join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=7))
    
    section_to_rename.Name = new_name.encode('utf-8').ljust(8, b'\x00')
    
    print(f"Successfully renamed section '{original_name}' to '{new_name}'.")
    return True