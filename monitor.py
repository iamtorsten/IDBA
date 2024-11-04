import codecs
import re
import agent

from utils import convert_register_value
from agent import *


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict):
            function_offset = payload.get("function_offset", "unknown")
            registers = payload.get("registers", {})
            instruction_address = payload.get("address", "N/A")
            base_address = payload.get("base_address", "N/A")
            target_offset = payload.get("target_offset", "N/A")

            try:
                real_instruction_address = hex(int(instruction_address, 16) - int(base_address, 16))
            except:
                real_instruction_address = "N/A"
            mnemonic = payload.get("mnemonic", "N/A")
            opStr = payload.get("opStr", "N/A")
            return_value = payload.get("retval")
            size = payload.get("size", "N/A")

            if not agent.header_set:
                try:
                    with codecs.open(file_path_log, "a", "utf-8") as f:
                        f.write(f"target={target}=>module_name={target_library} base={base_address} size={size}\n")
                        agent.header_set = True
                except Exception as e:
                    print(f"{rot}[FEHLER] Schreiben in die Protokolldatei fehlgeschlagen: {e}{reset}")
                    agent.header_set = True

            # Protokollfunktionseintrag
            if payload.get('event') == 'onEnter':
                register_values = []
                for reg in registers:
                    hex_value = registers[reg]['hex']
                    int_value, str_value, byte_value = convert_register_value(hex_value)
                    register_values.append(
                        f"{reg}=>{hex_value} (int: {int_value}, str: '{str_value}', bytes: {byte_value})")

                print(f"{gelb}Register=>[{target_library}!{function_offset}] " + ' '.join(register_values) + f"{reset}")

                try:
                    with codecs.open(file_path_log, "a", "utf-8") as f:
                        f.write(f"Register=>[{target_library}!{function_offset}] " + ' '.join(register_values))
                        f.write('\n')
                except Exception as e:
                    print(f"{rot}[FEHLER] Schreiben in die Protokolldatei fehlgeschlagen: {e}{reset}")

            # Anweisungen zur Protokollmontage mit Registerwerten
            if payload.get('event') == "instruction":
                # Finde alle Register in der Assembly-Anweisung
                # Beispiel für mögliche Register
                possible_registers = [
                    'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                    'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14',
                    'x15', 'x16', 'x17', 'x18', 'x19', 'x20', 'x21',
                    'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28',
                    'x29', 'x30', 'sp', 'pc',
                    'w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7',
                    'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14',
                    'w15', 'w16', 'w17', 'w18', 'w19', 'w20', 'w21',
                    'w22', 'w23', 'w24', 'w25', 'w26', 'w27', 'w28',
                    'w29', 'w30', 'wsp', 'wpc',
                    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
                    "q8", "q9", "q10", "q11", "q12", "q13", "q14",
                    "q15", "q16", "q17", "q18", "q19", "q20", "q21",
                    "q22", "q23", "q24", "q25", "q26", "q27", "q28",
                    "q29", "q30", "q31"
                ]

                # Erstelle einen regulären Ausdruck basierend auf den möglichen Registern
                register_pattern = r'\b(' + '|'.join(possible_registers) + r')\b'

                # Finde alle Register in der Assembly-Anweisung
                found_registers = re.findall(register_pattern, opStr)

                # Erstelle die register_values nur für gefundene Register
                register_values = ' '.join(
                    [f"{reg}=>{registers[reg]['hex']}" for reg in found_registers if reg in registers])

                register_values = []
                for reg in found_registers:
                    if reg in registers:
                        hex_value = registers[reg]['hex']
                        int_value, str_value, byte_value = convert_register_value(hex_value)
                        register_values.append(
                            f"{reg}=>{hex_value} (int: {int_value}, str: '{str_value}', bytes: {byte_value})")

                # Formatiere die Ausgabe
                formatted_output = (
                        f"{instruction_address}=>{real_instruction_address} [{target_library}!{function_offset}] \"{mnemonic} {opStr.strip()}\" " +
                        ' '.join(register_values)
                )
                print(f"{gruen}Anweisung: {formatted_output}{reset}")

                # In Logdatei schreiben
                try:
                    with codecs.open(file_path_log, "a", "utf-8") as f:
                        f.write(f"{formatted_output}\n")
                except Exception as e:
                    print(f"{rot}[FEHLER] Schreiben in die Protokolldatei fehlgeschlagen: {e}{reset}")

                # VM Log schreiben
                if write_bin:
                    try:
                        with codecs.open(file_path_vm_log, "a", "utf-8") as f:
                            f.write(f"{formatted_output}\n")
                    except Exception as e:
                        print(f"{rot}[FEHLER] Schreiben in die Protokolldatei fehlgeschlagen: {e}{reset}")

                current_registers = payload.get("registers", {})
                current_register_values = []
                for reg in current_registers:
                    hex_value = current_registers[reg]['hex']
                    int_value, str_value, byte_value = convert_register_value(hex_value)
                    current_register_values.append(
                        f"{reg}=>{hex_value} (int: {int_value}, str: '{str_value}', bytes: {byte_value})")

                if write_register_changes:
                    # Protokolliere die Registeränderungen
                    print(f"{gelb}Registeränderungen bei '{mnemonic} {opStr.strip()}': " + ' '.join(current_register_values) + f"{reset}")
                    try:
                        with codecs.open(file_path_log, "a", "utf-8") as f:
                            f.write(f"Registeränderungen bei '{mnemonic} {opStr.strip()}': " + ' '.join(
                                current_register_values) + '\n')
                    except Exception as e:
                        print(f"{rot}[FEHLER] Schreiben in die Protokolldatei fehlgeschlagen: {e}{reset}")

            # Log-Rückgabewert
            if return_value is not None:
                print(f"{blau}Rückgabewert=>{return_value}{reset}")
                try:
                    with codecs.open(file_path_log, "a", "utf-8") as f:
                        f.write(f"Rückgabewert=>{return_value}\n")
                except Exception as e:
                    print(
                        f"{rot}[FEHLER] Der Rückgabewert konnte nicht in die Protokolldatei geschrieben werden.: {e}{reset}")

            # OnLeave-Ereignissen
            if payload.get('event') == 'onLeave':
                try:
                    register_values = []
                    for reg in registers:
                        hex_value = registers[reg]['hex']
                        int_value, str_value, byte_value = convert_register_value(hex_value)
                        register_values.append(
                            f"{reg}=>{hex_value} (int: {int_value}, str: '{str_value}', bytes: {byte_value})")

                    print(f"{gelb}Register=>[{target_library}!{function_offset}] " + ' '.join(register_values) + f"{reset}")

                    with codecs.open(file_path_log, "a", "utf-8") as f:
                        f.write(f"Register=>[{target_library}!{function_offset}] " + ' '.join(register_values))
                        f.write('\n')
                except Exception as e:
                    print(
                        f"{rot}[FEHLER] Das Schreiben der Exit-Register in die Protokolldatei ist fehlgeschlagen.: {e}{reset}")

            # Protokollieren der Anweisungsdetails und registrieren der Werte bei Fehlern
            if payload.get('event') == 'error':
                error_msg = payload.get('message', 'Unknown error occurred.')
                print(f"{rot}[FEHLER] {error_msg}{reset}")
                try:
                    with codecs.open(file_path_log, "a", "utf-8") as f:
                        f.write(f"[ERROR] {error_msg}\n")
                except Exception as e:
                    print(f"{rot}[FEHLER] Fehler konnte nicht in die Protokolldatei geschrieben werden: {e}{reset}")

            # Protokollieren der Anwendungsverfolgung
            if payload.get("hook") == True and write_function_trace:
                sequence = f"{instruction_address}=>{real_instruction_address} [{target_library}!{function_offset}] => {target_offset}"
                print(f"{violet}[SPRUNG] {sequence}{reset}")
                try:
                    with codecs.open(file_path_call_stack, "a", "utf-8") as f:
                        f.write(f"[SPRUNG] {sequence}\n")
                except Exception as e:
                    print(f"{rot}[FEHLER] Fehler konnte nicht in die Protokolldatei geschrieben werden: {e}{reset}")
