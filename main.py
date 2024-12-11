# IDBA - Intelligent Dynamic Binary Analysis
# (c) 2024 Torsten Klement


import frida
import sys

from hook       import hook
from inject     import Inject
from agent      import *
from monitor    import on_message
from segment    import monitor_text_access, on_txt_message

banner = """
██╗██████╗ ██████╗  █████╗ 
██║██╔══██╗██╔══██╗██╔══██╗
██║██║  ██║██████╔╝███████║
██║██║  ██║██╔══██╗██╔══██║
██║██████╔╝██████╔╝██║  ██║
╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝ \n\nIntelligent Dynamic Binary Analysis\n(c) Torsten Klement, Telegram: https://t.me/iamtorsten
"""

print(f"{leuchtgruen}{banner}{reset}")


def main():
    try:
        # Hook
        if infinity_instructions:
            script_code = hook(target_library=target_library, functions=functions, ignore_offsets=ignored_offsets)
        else:
            script_code = hook(target_library=target_library, max_instructions=max_instructions, functions=functions, ignore_offsets=ignored_offsets)

        # Gerät, Sitzung und Quelle einrichten
        IDBA = Inject(target=target)
        device, session = IDBA.attach()
        script = IDBA.source(session, script_code)

        # on_message-Rückruf hinzufügen
        script.on('message', on_message)
        script.load()

        # .text Bereich Überwachung
        script = IDBA.source(session, monitor_text_access())
        script.on('message', on_txt_message)
        script.load()

        # Skript weiterlaufen lassen
        print(f"[*] IDBA [ -> {target} -> {target_library} -> {functions} ]: Überwachung gestartet. Drücken Sie Strg+C, um zu stoppen.")
        print(f"module_name={target_library}")
        sys.stdin.read()
    except frida.ServerNotRunningError:
        print("Der Server läuft nicht. Bitte starten Sie den Server auf Ihrem Gerät.")
    except frida.ProcessNotFoundError:
        print(f"Prozess '{target}' nicht gefunden. Stellen Sie sicher, dass die App ausgeführt wird.")
    except Exception as e:
        print(f"[FEHLER] {str(e)}")


if __name__ == "__main__":
    main()
