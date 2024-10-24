# Funktion zur Umwandlung von hexadezimalen Werten
def convert_register_value(hex_value):
    if hex_value == 'N/A':
        return 'N/A', 'N/A', 'N/A'
    # Konvertiere von hex zu int
    try:
        int_value = int(hex_value, 16)
    except:
        int_value = '<nicht darstellbar>'
    # Konvertiere zu Bytes
    try:
        byte_value = bytes.fromhex(hex_value[2:])  # Entferne '0x' für die Bytes-Konvertierung
    except:
        byte_value = '<nicht darstellbar>'
    # Versuche, eine String-Darstellung zu erhalten
    try:
        if byte_value != '<nicht darstellbar>':
            str_value = byte_value.decode('utf-8')  # Dekodiere zu String
        else:
            str_value = '<nicht darstellbar>'
    except UnicodeDecodeError:
        str_value = '<nicht darstellbar>'  # Wenn Dekodierung fehlschlägt
    return int_value, str_value, byte_value