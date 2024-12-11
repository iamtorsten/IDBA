from agent import target_library, file_path_log

log_file = file_path_log


def monitor_text_access(chunk_size=0x2000):
    """
    Überwacht Lese- und Schreibzugriffe auf den .text-Bereich eines angegebenen Moduls.
    Die Bereiche werden in kleinere Chunks (standardmäßig 8 KB) aufgeteilt.
    """

    script = f"""
           function splitRange(basePointer, size, chunkSize) {{
               var ranges = [];
               for (var offset = 0; offset < size; offset += chunkSize) {{
                   var chunkBase = basePointer.add(offset);
                   var chunkSize = Math.min(chunkSize, size - offset);
                   ranges.push({{ base: chunkBase, size: chunkSize }});
               }}
               return ranges;
           }}

           function monitorLibrary(targetLibrary) {{
               try {{
                   console.log("[DEBUG] Suche nach Modul: " + targetLibrary);

                   const module = Process.getModuleByName(targetLibrary);
                   if (!module) {{
                       console.error("[FEHLER] Modul " + targetLibrary + " nicht gefunden!");
                       return;
                   }}
                   console.log("[INFO] Modul gefunden: " + module.name + " bei Adresse: " + module.base);

                   var ranges = module.enumerateRanges('r--x');
                   if (ranges.length === 0) {{
                       console.log("[WARNUNG] Keine Bereiche mit 'r--x' gefunden.");
                       return;
                   }}

                   ranges.forEach(function(range) {{
                       if (range.protection !== "r-x") {{
                           console.warn("[INFO] Bereich übersprungen: " + JSON.stringify(range));
                           return;
                       }}

                       var basePointer = ptr(range.base);
                       var size = range.size;

                       var splitRanges = splitRange(basePointer, size, {chunk_size}); // Dynamische Chunk-Größe
                       splitRanges.forEach(function(splitRange) {{
                           try {{
                               console.log("[INFO] Überwache Chunk: Start = " + splitRange.base + ", Size = " + splitRange.size);

                               MemoryAccessMonitor.enable(splitRange.base, splitRange.size, {{
                                   onAccess: function(details) {{
                                       var addr = ptr(details.address);
                                       var type = details.operation;
                                       var value = "";

                                       try {{
                                           var data = Memory.readByteArray(addr, 16);
                                           var hex = Array.from(new Uint8Array(data))
                                                           .map(byte => ("0" + byte.toString(16)).slice(-2))
                                                           .join(" ");
                                           value = hex;
                                       }} catch (e) {{
                                           value = "[NICHT LESBAR]";
                                       }}

                                       var log = "Adresse: " + addr.toString(16) + " Zugriff: " + type + " Daten: " + value;
                                       console.log(log);
                                       send(log);
                                   }}
                               }});
                           }} catch (e) {{
                               console.error("[FEHLER] Fehler bei MemoryAccessMonitor.enable: " + e.message + " für Teilbereich: " + JSON.stringify(splitRange));
                           }}
                       }}); // Ende der Teilbereich-Überwachung
                   }}); // Ende der Bereichsüberwachung
               }} catch (e) {{
                   console.error("[FEHLER] Fehler beim Initialisieren der Überwachung: " + e.message);
               }}
           }}

           // Start der Überwachung
           monitorLibrary("{target_library}");
       """
    return script


def on_txt_message(message, data):
    if message["type"] == "send":
        print(f'[.TEXT SEGMENT] {message["payload"]}')
        log_file.write(".Text\n" + message["payload"] + "\n")
    elif message["type"] == "error":
        print("[FEHLER]", message["stack"])
    else:
        print("[INFO] Unerwartete Nachricht:", message)