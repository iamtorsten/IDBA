# Farben definieren
gruen = "\033[32m"
rot = "\033[91m"
gelb = "\033[93m"
blau = "\033[94m"
reset = "\033[0m"
leuchtgruen = "\033[1;32m"
# Zielanwendung
target = ""
# Zielbibliothek
target_library = ""
# Hooked Funktionen
functions = [
    {"offset": 0xab5b0, "name": "pattern_701872"},
]
# Dateiname-/Pfad
file_path_log = f'IDBA-log.txt'
file_path_vm_log = f'IDBA-vm-log.txt'
# Ausgabe Registeränderungen
write_register_changes = True
# Unbegrenzung von Instruktionen
infinity_instructions = True
# Maximale Instruktionen
max_instructions = 1000  # Passen Sie es nach Bedarf an
# Datei Header
header_set = False
# Aktiviere Binary Log
write_bin = True