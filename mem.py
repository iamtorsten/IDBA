def classify_arm64_instruction(instruction):
    """
    Klassifiziert eine ARM64-Anweisung in Memory Read, Write oder Access.

    :param instruction: Der Assembly-Befehl als String.
    :return: Kategorie der Anweisung (Read, Write, Access oder Unbekannt).
    """

    # Memory Read Anweisungen
    memory_read_instructions = [
        "LDR", "LDUR", "LDP", "LDXR", "LDAR", "LDRB", "LDRH", "LDRSW",
        "LDRD", "LDNP", "PRFM", "LDRQ", "LDRSH", "LDRSB", "LDTR", "LDURB",
        "LDURH", "LDURSW", "LDTRB", "LDTRH", "LDTRSW"
    ]

    # Memory Write Anweisungen
    memory_write_instructions = [
        "STR", "STUR", "STP", "STXR", "STLR", "STRB", "STRH", "STRD",
        "STNP", "STTR", "STURB", "STURH", "STURW", "STTRB", "STTRH"
    ]

    # Memory Access Anweisungen
    memory_access_instructions = [
        "ADD", "SUB", "MOV", "MOVK", "ADR", "ADRP", "CMP", "CMN", "TST",
        "TEQ", "LSL", "LSR", "ASR", "ROR", "BIC", "ORR", "AND", "EOR",
        "SXTW", "UXTW", "SXTH", "UXTH", "SXTB", "UXTB"
    ]

    operation = instruction.__str__().upper()

    # Kategorie bestimmen
    if operation in memory_read_instructions:
        return f"Lesen"
    elif operation in memory_write_instructions:
        return f"Schreiben"
    elif operation in memory_access_instructions:
        return f"Zugriff"
    else:
        return f"Unklassifiziert"