def convert_register_value(hex_value):
    # Überprüfe, ob der Wert 'N/A' ist
    if hex_value == 'N/A':
        return 'N/A', 'N/A', 'N/A'

    # Überprüfen, ob hex_value ein ArrayBuffer oder ähnliches Objekt ist
    if isinstance(hex_value, (bytes, bytearray, memoryview)):
        # Konvertiere jeden Byte-Wert in einen zweistelligen Hexadezimalwert und füge sie zu einem vollständigen String zusammen
        hex_value = ''.join(format(b, '02x') for b in hex_value)
    elif hasattr(hex_value, 'byteLength'):  # Prüfen, ob es sich um Frida ArrayBuffer handelt
        # ArrayBuffer in ein Bytearray umwandeln und Hex-String erstellen
        hex_value = ''.join(format(b, '02x') for b in bytearray(hex_value))
    elif isinstance(hex_value, str) and hex_value.startswith('0x'):
        # Falls hex_value ein regulärer Hex-String ist, '0x' entfernen
        hex_value = hex_value[2:]

    # Konvertiere von hex zu int
    try:
        int_value = int(hex_value, 16)
    except ValueError:
        int_value = '<nicht darstellbar>'

    # Konvertiere zu Bytes
    try:
        byte_value = bytes.fromhex(hex_value)  # Hex-String zu Bytes konvertieren
    except ValueError:
        byte_value = b'<nicht darstellbar>'

    # Versuche, eine String-Darstellung zu erhalten
    try:
        str_value = byte_value.decode('utf-8') if byte_value != b'<nicht darstellbar>' else '<nicht darstellbar>'
    except UnicodeDecodeError:
        str_value = '<nicht darstellbar>'  # Wenn Dekodierung fehlschlägt

    return int_value, str_value, byte_value
