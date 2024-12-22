# Farben definieren
gruen = "\033[32m"
rot = "\033[91m"
gelb = "\033[93m"
blau = "\033[94m"
reset = "\033[0m"
violet = "\033[35m"
leuchtgruen = "\033[1;32m"
# Zielanwendung
target = ""
# Zielbibliothek
target_library = ""
# Hooked Funktionen
functions = [
]
with open('symbols.txt', "r") as file:
    for line in file:
        line = line.strip()  # Entferne Leerzeichen und Zeilenumbrüche
        if line:  # Nur nicht-leere Zeilen verarbeiten
            # Zeile in ein Python-Objekt umwandeln
            function = eval(line)  # Vorsicht: Verwenden Sie eval nur mit vertrauenswürdigen Dateien!
            functions.append(function)
# Dateiname-/Pfad
file_path_log = f'IDBA-log.txt'
# Unbegrenzung von Instruktionen
infinity_instructions = True
# Maximale Instruktionen
max_instructions = 1000  # Passen Sie es nach Bedarf an
# Datei Header
header_set = False
# Ignorierte Offsets
ignored_offsets = [
    0x22080
]