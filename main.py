# IDBA - Intelligent Dynamic Binary Analysis
# (c) 2024 Torsten Klement


import frida
import sys

from hook       import hook
from inject     import Inject
from agent      import *
from monitor    import on_message

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
            script_code = hook(target_library, functions)
        else:
            script_code = hook(target_library, functions, max_instructions)

        # Gerät, Sitzung und Quelle einrichten
        IDBA = Inject(target=target)
        device, session = IDBA.attach()
        script = IDBA.source(session, script_code)

        # on_message-Rückruf hinzufügen
        script.on('message', on_message)
        script.load()

        # Skript weiterlaufen lassen
        print(
            f"[*] IDBA [ -> {target} -> {target_library} -> {functions} ]: Überwachung gestartet. Drücken Sie Strg+C, um zu stoppen.")
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
