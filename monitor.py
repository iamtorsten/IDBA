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
                possible_registers = [
                    # **x86-64 General-Purpose Registers**
                    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",

                    # **x86-64 32-bit General-Purpose Registers**
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",

                    # **x86-64 16-bit General-Purpose Registers**
                    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",

                    # **x86-64 8-bit General-Purpose Registers**
                    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
                    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",

                    # **ARM64 General-Purpose Registers (64-bit Integer)**
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp", "pc",

                    # **ARM64 General-Purpose Registers (32-bit Integer)**
                    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
                    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
                    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
                    "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wsp",

                    # **ARM64 Floating-Point Registers (64-bit Double-Precision)**
                    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
                    "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
                    "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
                    "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",

                    # **ARM64 Floating-Point Registers (32-bit Single-Precision)**
                    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                    "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
                    "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
                    "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",

                    # **ARM64 Floating-Point Registers (16-bit Half-Precision)**
                    "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7",
                    "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15",
                    "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
                    "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31",

                    # **ARM64 Vector Registers (128-bit SIMD)**
                    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
                    "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
                    "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
                    "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31",

                    # **Punktnotation für `vN` Vector Registers**
                    # Byte-Level
                    "v0.16b", "v1.16b", "v2.16b", "v3.16b", "v4.16b", "v5.16b", "v6.16b", "v7.16b",
                    "v8.16b", "v9.16b", "v10.16b", "v11.16b", "v12.16b", "v13.16b", "v14.16b", "v15.16b",
                    "v16.16b", "v17.16b", "v18.16b", "v19.16b", "v20.16b", "v21.16b", "v22.16b", "v23.16b",
                    "v24.16b", "v25.16b", "v26.16b", "v27.16b", "v28.16b", "v29.16b", "v30.16b", "v31.16b",

                    # Halfword-Level
                    "v0.8h", "v1.8h", "v2.8h", "v3.8h", "v4.8h", "v5.8h", "v6.8h", "v7.8h",
                    "v8.8h", "v9.8h", "v10.8h", "v11.8h", "v12.8h", "v13.8h", "v14.8h", "v15.8h",
                    "v16.8h", "v17.8h", "v18.8h", "v19.8h", "v20.8h", "v21.8h", "v22.8h", "v23.8h",
                    "v24.8h", "v25.8h", "v26.8h", "v27.8h", "v28.8h", "v29.8h", "v30.8h", "v31.8h",

                    # Singleword-Level
                    "v0.4s", "v1.4s", "v2.4s", "v3.4s", "v4.4s", "v5.4s", "v6.4s", "v7.4s",
                    "v8.4s", "v9.4s", "v10.4s", "v11.4s", "v12.4s", "v13.4s", "v14.4s", "v15.4s",
                    "v16.4s", "v17.4s", "v18.4s", "v19.4s", "v20.4s", "v21.4s", "v22.4s", "v23.4s",
                    "v24.4s", "v25.4s", "v26.4s", "v27.4s", "v28.4s", "v29.4s", "v30.4s", "v31.4s",

                    # Doubleword-Level
                    "v0.2d", "v1.2d", "v2.2d", "v3.2d", "v4.2d", "v5.2d", "v6.2d", "v7.2d",
                    "v8.2d", "v9.2d", "v10.2d", "v11.2d", "v12.2d", "v13.2d", "v14.2d", "v15.2d",
                    "v16.2d", "v17.2d", "v18.2d", "v19.2d", "v20.2d", "v21.2d", "v22.2d", "v23.2d",
                    "v24.2d", "v25.2d", "v26.2d", "v27.2d", "v28.2d", "v29.2d", "v30.2d", "v31.2d",

                    # **Punktnotation für `sN` Floating-Point Registers**
                    "s0.0", "s0.1", "s0.2", "s0.3", "s1.0", "s1.1", "s1.2", "s1.3",
                    "s2.0", "s2.1", "s2.2", "s2.3", "s3.0", "s3.1", "s3.2", "s3.3",
                    "s4.0", "s4.1", "s4.2", "s4.3", "s5.0", "s5.1", "s5.2", "s5.3",
                    "s6.0", "s6.1", "s6.2", "s6.3", "s7.0", "s7.1", "s7.2", "s7.3",
                    "s8.0", "s8.1", "s8.2", "s8.3", "s9.0", "s9.1", "s9.2", "s9.3",
                    "s10.0", "s10.1", "s10.2", "s10.3", "s11.0", "s11.1", "s11.2", "s11.3",
                    "s12.0", "s12.1", "s12.2", "s12.3", "s13.0", "s13.1", "s13.2", "s13.3",
                    "s14.0", "s14.1", "s14.2", "s14.3", "s15.0", "s15.1", "s15.2", "s15.3",
                    "s16.0", "s16.1", "s16.2", "s16.3", "s17.0", "s17.1", "s17.2", "s17.3",
                    "s18.0", "s18.1", "s18.2", "s18.3", "s19.0", "s19.1", "s19.2", "s19.3",
                    "s20.0", "s20.1", "s20.2", "s20.3", "s21.0", "s21.1", "s21.2", "s21.3",
                    "s22.0", "s22.1", "s22.2", "s22.3", "s23.0", "s23.1", "s23.2", "s23.3",
                    "s24.0", "s24.1", "s24.2", "s24.3", "s25.0", "s25.1", "s25.2", "s25.3",
                    "s26.0", "s26.1", "s26.2", "s26.3", "s27.0", "s27.1", "s27.2", "s27.3",
                    "s28.0", "s28.1", "s28.2", "s28.3", "s29.0", "s29.1", "s29.2", "s29.3",
                    "s30.0", "s30.1", "s30.2", "s30.3", "s31.0", "s31.1", "s31.2", "s31.3",

                    # **Punktnotation für `hN` Floating-Point Registers**
                    "h0.0", "h0.1", "h0.2", "h0.3", "h1.0", "h1.1", "h1.2", "h1.3",
                    "h2.0", "h2.1", "h2.2", "h2.3", "h3.0", "h3.1", "h3.2", "h3.3",
                    "h4.0", "h4.1", "h4.2", "h4.3", "h5.0", "h5.1", "h5.2", "h5.3",
                    "h6.0", "h6.1", "h6.2", "h6.3", "h7.0", "h7.1", "h7.2", "h7.3",
                    "h8.0", "h8.1", "h8.2", "h8.3", "h9.0", "h9.1", "h9.2", "h9.3",
                    "h10.0", "h10.1", "h10.2", "h10.3", "h11.0", "h11.1", "h11.2", "h11.3",
                    "h12.0", "h12.1", "h12.2", "h12.3", "h13.0", "h13.1", "h13.2", "h13.3",
                    "h14.0", "h14.1", "h14.2", "h14.3", "h15.0", "h15.1", "h15.2", "h15.3",
                    "h16.0", "h16.1", "h16.2", "h16.3", "h17.0", "h17.1", "h17.2", "h17.3",
                    "h18.0", "h18.1", "h18.2", "h18.3", "h19.0", "h19.1", "h19.2", "h19.3",
                    "h20.0", "h20.1", "h20.2", "h20.3", "h21.0", "h21.1", "h21.2", "h21.3",
                    "h22.0", "h22.1", "h22.2", "h22.3", "h23.0", "h23.1", "h23.2", "h23.3",
                    "h24.0", "h24.1", "h24.2", "h24.3", "h25.0", "h25.1", "h25.2", "h25.3",
                    "h26.0", "h26.1", "h26.2", "h26.3", "h27.0", "h27.1", "h27.2", "h27.3",
                    "h28.0", "h28.1", "h28.2", "h28.3", "h29.0", "h29.1", "h29.2", "h29.3",
                    "h30.0", "h30.1", "h30.2", "h30.3", "h31.0", "h31.1", "h31.2", "h31.3",

                    # **ARM64 Vector Registers (128-bit SIMD/FP)**
                    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
                    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
                    "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
                    "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
                ]

                # Erstelle einen regulären Ausdruck basierend auf den möglichen Registern
                register_pattern = r'(?<!\w)(' + '|'.join(possible_registers).replace('.', r'\.') + r')(?!\w)'

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
