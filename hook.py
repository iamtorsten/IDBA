def hook(target_library, functions, max_instructions=None, ignore_offsets=None):
    hooks = []
    js_ignore_offsets = ', '.join([f'"0x{offset:x}"' for offset in ignore_offsets]) if ignore_offsets else ""
    for function in functions:
        offset = function["offset"]
        name = function["name"]
        hook_code = f"""
        {{
            const targetLibrary = "{target_library}";
            const targetFunctionOffset = {offset};
            var maxInstructions = {max_instructions if max_instructions is not None else 'Infinity'};
            var hookedOffsets = new Set();  // Set für verfolgte Offsets
            var invalidOffsets = new Set(); // Set für einmalige Warnungen bei ungültigen Offsets
            var ignoreOffsets = new Set([{js_ignore_offsets}]); // Zu ignorierende Offsets
            var allHookedOffsets = new Set(); // Set auf globaler Ebene für alle gehookten Offsets


            function isRegister(opStr) {{
                const registerNames = [
                    "h0", "h0.0", "h0.1", "h1", "h1.0", "h1.1", "h2", "h2.0", "h2.1", "h3", "h3.0", "h3.1", "h4", "h4.0", "h4.1", "h5", "h5.0", "h5.1", "h6", "h6.0", "h6.1",
                    "h7", "h7.0", "h7.1", "h8", "h8.0", "h8.1", "h9", "h9.0", "h9.1", "h10", "h10.0", "h10.1", "h11", "h11.0", "h11.1", "h12", "h12.0", "h12.1", "h13", "h13.0", "h13.1",
                    "h14", "h14.0", "h14.1", "h15", "h15.0", "h15.1", "h16", "h16.0", "h16.1", "h17", "h17.0", "h17.1", "h18", "h18.0", "h18.1", "h19", "h19.0", "h19.1", "h20", "h20.0", "h20.1",
                    "h21", "h21.0", "h21.1", "h22", "h22.0", "h22.1", "h23", "h23.0", "h23.1", "h24", "h24.0", "h24.1", "h25", "h25.0", "h25.1", "h26", "h26.0", "h26.1", "h27", "h27.0", "h27.1",
                    "h28", "h28.0", "h28.1", "h29", "h29.0", "h29.1", "h30", "h30.0", "h30.1", "h31", "h31.0", "h31.1",
                    "s0", "s0.0", "s0.1", "s0.2", "s0.3", "s1", "s1.0", "s1.1", "s1.2", "s1.3", "s2", "s2.0", "s2.1", "s2.2", "s2.3",
                    "s3", "s3.0", "s3.1", "s3.2", "s3.3", "s4", "s4.0", "s4.1", "s4.2", "s4.3", "s5", "s5.0", "s5.1", "s5.2", "s5.3",
                    "s6", "s6.0", "s6.1", "s6.2", "s6.3", "s7", "s7.0", "s7.1", "s7.2", "s7.3", "s8", "s8.0", "s8.1", "s8.2", "s8.3",
                    "s9", "s9.0", "s9.1", "s9.2", "s9.3", "s10", "s10.0", "s10.1", "s10.2", "s10.3", "s11", "s11.0", "s11.1", "s11.2", "s11.3",
                    "s12", "s12.0", "s12.1", "s12.2", "s12.3", "s13", "s13.0", "s13.1", "s13.2", "s13.3", "s14", "s14.0", "s14.1", "s14.2", "s14.3",
                    "s15", "s15.0", "s15.1", "s15.2", "s15.3", "s16", "s16.0", "s16.1", "s16.2", "s16.3", "s17", "s17.0", "s17.1", "s17.2", "s17.3",
                    "s18", "s18.0", "s18.1", "s18.2", "s18.3", "s19", "s19.0", "s19.1", "s19.2", "s19.3", "s20", "s20.0", "s20.1", "s20.2", "s20.3",
                    "s21", "s21.0", "s21.1", "s21.2", "s21.3", "s22", "s22.0", "s22.1", "s22.2", "s22.3", "s23", "s23.0", "s23.1", "s23.2", "s23.3",
                    "s24", "s24.0", "s24.1", "s24.2", "s24.3", "s25", "s25.0", "s25.1", "s25.2", "s25.3", "s26", "s26.0", "s26.1", "s26.2", "s26.3",
                    "s27", "s27.0", "s27.1", "s27.2", "s27.3", "s28", "s28.0", "s28.1", "s28.2", "s28.3", "s29", "s29.0", "s29.1", "s29.2", "s29.3",
                    "s30", "s30.0", "s30.1", "s30.2", "s30.3", "s31", "s31.0", "s31.1", "s31.2", "s31.3",
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp", "pc",
                    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15", "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
                    "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31",
                    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
                    "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
                    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
                    "w8", "w9", "w10", "w11", "w12", "w13", "w14",
                    "w15", "w16", "w17", "w18", "w19", "w20", "w21",
                    "w22", "w23", "w24", "w25", "w26", "w27", "w28",
                    "w29", "w30", "wsp", "wpc",
                    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"
                ];
                return registerNames.includes(opStr);
            }}

            function getRegisterInfo(context) {{
                var registerNames = [
                    "h0", "h0.0", "h0.1", "h1", "h1.0", "h1.1", "h2", "h2.0", "h2.1", "h3", "h3.0", "h3.1", "h4", "h4.0", "h4.1", "h5", "h5.0", "h5.1", "h6", "h6.0", "h6.1",
                    "h7", "h7.0", "h7.1", "h8", "h8.0", "h8.1", "h9", "h9.0", "h9.1", "h10", "h10.0", "h10.1", "h11", "h11.0", "h11.1", "h12", "h12.0", "h12.1", "h13", "h13.0", "h13.1",
                    "h14", "h14.0", "h14.1", "h15", "h15.0", "h15.1", "h16", "h16.0", "h16.1", "h17", "h17.0", "h17.1", "h18", "h18.0", "h18.1", "h19", "h19.0", "h19.1", "h20", "h20.0", "h20.1",
                    "h21", "h21.0", "h21.1", "h22", "h22.0", "h22.1", "h23", "h23.0", "h23.1", "h24", "h24.0", "h24.1", "h25", "h25.0", "h25.1", "h26", "h26.0", "h26.1", "h27", "h27.0", "h27.1",
                    "h28", "h28.0", "h28.1", "h29", "h29.0", "h29.1", "h30", "h30.0", "h30.1", "h31", "h31.0", "h31.1",
                    "s0", "s0.0", "s0.1", "s0.2", "s0.3", "s1", "s1.0", "s1.1", "s1.2", "s1.3", "s2", "s2.0", "s2.1", "s2.2", "s2.3",
                    "s3", "s3.0", "s3.1", "s3.2", "s3.3", "s4", "s4.0", "s4.1", "s4.2", "s4.3", "s5", "s5.0", "s5.1", "s5.2", "s5.3",
                    "s6", "s6.0", "s6.1", "s6.2", "s6.3", "s7", "s7.0", "s7.1", "s7.2", "s7.3", "s8", "s8.0", "s8.1", "s8.2", "s8.3",
                    "s9", "s9.0", "s9.1", "s9.2", "s9.3", "s10", "s10.0", "s10.1", "s10.2", "s10.3", "s11", "s11.0", "s11.1", "s11.2", "s11.3",
                    "s12", "s12.0", "s12.1", "s12.2", "s12.3", "s13", "s13.0", "s13.1", "s13.2", "s13.3", "s14", "s14.0", "s14.1", "s14.2", "s14.3",
                    "s15", "s15.0", "s15.1", "s15.2", "s15.3", "s16", "s16.0", "s16.1", "s16.2", "s16.3", "s17", "s17.0", "s17.1", "s17.2", "s17.3",
                    "s18", "s18.0", "s18.1", "s18.2", "s18.3", "s19", "s19.0", "s19.1", "s19.2", "s19.3", "s20", "s20.0", "s20.1", "s20.2", "s20.3",
                    "s21", "s21.0", "s21.1", "s21.2", "s21.3", "s22", "s22.0", "s22.1", "s22.2", "s22.3", "s23", "s23.0", "s23.1", "s23.2", "s23.3",
                    "s24", "s24.0", "s24.1", "s24.2", "s24.3", "s25", "s25.0", "s25.1", "s25.2", "s25.3", "s26", "s26.0", "s26.1", "s26.2", "s26.3",
                    "s27", "s27.0", "s27.1", "s27.2", "s27.3", "s28", "s28.0", "s28.1", "s28.2", "s28.3", "s29", "s29.0", "s29.1", "s29.2", "s29.3",
                    "s30", "s30.0", "s30.1", "s30.2", "s30.3", "s31", "s31.0", "s31.1", "s31.2", "s31.3",
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp", "pc",
                    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15", "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
                    "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31",
                    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
                    "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
                    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
                    "w8", "w9", "w10", "w11", "w12", "w13", "w14",
                    "w15", "w16", "w17", "w18", "w19", "w20", "w21",
                    "w22", "w23", "w24", "w25", "w26", "w27", "w28",
                    "w29", "w30", "wsp", "wpc",
                    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"
                ];

                var registers = {{}};

                registerNames.forEach(function (name) {{
                    // Punktnotation in Register-Namen wird hier berücksichtigt
                    if (context[name] !== undefined) {{
                        if ((name.startsWith("q") || name.startsWith("d")) && context[name] instanceof ArrayBuffer) {{
                            // Verarbeitung von q- und d-Registern mit ArrayBuffer
                            var byteArray = new Uint8Array(context[name]);
                            var hexString = Array.from(byteArray, byte => ('0' + byte.toString(16)).slice(-2)).join('');
                            registers[name] = {{ "hex": "0x" + hexString }};
                        }} else {{
                            // Normaler Registerwert
                            try {{
                                var value = context[name].toString(16); // Wert in Hexadezimal
                                registers[name] = {{ "hex": "0x" + value }};
            
                                // Falls ein x-Register vorhanden ist, w-Register ableiten
                                if (name.startsWith("x") && name.length > 1) {{
                                    var wName = "w" + name.slice(1);
                                    registers[wName] = {{
                                        "hex": "0x" + (parseInt(value, 16) & 0xFFFFFFFF).toString(16)
                                    }};
                                }}
                            }} catch (error) {{
                                console.error(`Fehler beim Verarbeiten von Register: ${name}`, error);
                            }}
                        }}
                    }} else if (name.includes(".")) {{
                        // Falls das Register mit Punktnotation nicht direkt in context verfügbar ist
                        var baseRegister = name.split(".")[0]; // Basisregister wie "h0" extrahieren
                        if (context[baseRegister] !== undefined) {{
                            try {{
                                var baseValue = context[baseRegister];
                                var partIndex = parseInt(name.split(".")[1], 10); // Teilindex (z. B. 0 oder 1)
                                var shiftedValue = (baseValue >> (partIndex * 8)) & 0xFF; // Teilwert extrahieren
                                registers[name] = {{ "hex": "0x" + shiftedValue.toString(16) }};
                            }} catch (error) {{
                                console.error(`Fehler beim Verarbeiten von Punktnotation: ${name}`, error);
                            }}
                        }}
                    }}
                }});
                
                return registers;
            }}

            function hookFunction(libraryName, offset, functionName) {{
                var module = Process.getModuleByName(libraryName);
                var functionAddress = module.base.add(offset);
                
                console.log("[INFO] Hooking-Funktion an Adresse: " + functionAddress);

                // Prüfen, ob Offset ignoriert oder bereits gehookt ist
                if (ignoreOffsets.has(functionAddress) || hookedOffsets.has(functionAddress)) {{
                    console.log("[WARNUNG] Offset in ignoreOffsets oder bereits gehookt: " + functionAddress);
                    return;
                }}

                Interceptor.attach(functionAddress, {{
                    onEnter: function(args) {{
                        var baseAddress = module.base;
                        
                        console.log("[INFO] Basisadresse des Moduls: " + baseAddress);
                        console.log("[INFO] Funktionseinstiegspunkt: " + functionAddress);
                        console.log("[INFO] Modulgröße: " + module.size);

                        var registers = getRegisterInfo(this.context);
                        var registerOutput = {{
                            "event": "onEnter",
                            "registers": registers,
                            "function_name": functionName,
                            "function_offset": "{hex(offset)}",
                            "base_address": baseAddress.toString(),
                            "size": module.size
                        }};
                        send(registerOutput);

                        var currentAddress = this.context.pc;
                        for (var i = 0; i < maxInstructions; i++) {{
                            var instruction = Instruction.parse(currentAddress);
                            if (!instruction) break;
                            
                            console.log("[INFO] Verarbeitungsanweisung: " + instruction.mnemonic + " " + instruction.opStr);

                            if (
                                instruction.mnemonic === "b" || 
                                instruction.mnemonic === "bl" || 
                                instruction.mnemonic === "br" || 
                                instruction.mnemonic === "blr" || 
                                instruction.mnemonic.startsWith("b.") ||
                                instruction.mnemonic === "ret"
                            ) 
                            {{
                                if (!isRegister(instruction.opStr)) {{
                                    var targetOffset;

                                    if (instruction.mnemonic === "cbz" || instruction.mnemonic === "cbnz") {{
                                        // CBZ / CBNZ: Register + Target Address (e.g., cbz w8, #0x77120bc75c)
                                        let parts = instruction.opStr.split(",");
                                        if (parts.length > 1) {{
                                            let targetAddrStr = parts[1].trim().replace("#", "");  // Zieladresse im zweiten Argument
                                            let targetAddr = ptr(targetAddrStr);
                                            targetOffset = targetAddr.sub(module.base);
                                        }} else {{
                                            console.log("[FEHLER] Ungültiges Format für CBZ/CBNZ: " + instruction.opStr);
                                        }}
                                    }} else if (instruction.mnemonic === "tbz" || instruction.mnemonic === "tbnz") {{
                                        // TBZ / TBNZ: Register, Bit, Target Address (e.g., tbz w8, #0, #0x77120bc75c)
                                        let parts = instruction.opStr.split(",");
                                        if (parts.length > 2) {{
                                            let targetAddrStr = parts[2].trim().replace("#", "");  // Zieladresse im dritten Argument
                                            let targetAddr = ptr(targetAddrStr);
                                            targetOffset = targetAddr.sub(module.base);
                                        }} else {{
                                            console.log("[FEHLER] Ungültiges Format für TBZ/TBNZ: " + instruction.opStr);
                                        }}
                                    }} else if (instruction.opStr.includes("#")) {{
                                        // Standard branch instructions like "b <target>" or "bl <target>"
                                        let targetAddrStr = instruction.opStr.split("#")[1];
                                        let targetAddr = ptr(targetAddrStr);
                                        targetOffset = targetAddr.sub(module.base);
                                    }} else {{
                                        // Branch instructions with a register as the target
                                        if (instruction.opStr) {{
                                            let targetRegister = instruction.opStr.trim();
                                            if (this.context[targetRegister] !== undefined) {{
                                                targetOffset = this.context[targetRegister].sub(module.base);
                                            }} else {{
                                                console.log("[FEHLER] Unbekanntes Register für Branch: " + targetRegister);
                                            }}
                                        }} else {{
                                            console.log("[FEHLER] Kein Ziel gefunden für Branch: " + instruction.opStr);
                                        }}
                                    }}

                                    if (ignoreOffsets.has(targetOffset) || targetOffset.compare(0) < 0 || targetOffset.compare(module.size) >= 0) {{
                                        if (!invalidOffsets.has(targetOffset)) {{
                                            invalidOffsets.add(targetOffset);
                                            console.log("[WARNUNG] Zieladresse außerhalb des Modulbereichs: " + targetOffset);
                                        }}
                                    }}

                                    if (!ignoreOffsets.has(targetOffset.toString())) {{
                                        if (targetOffset && targetOffset.compare(0) >= 0 && targetOffset.compare(module.size) < 0) {{
                                            if (!hookedOffsets.has(targetOffset)) {{
                                                console.log("[INFO] Berechnetes Offset im Modul: " + targetOffset);
                                                if (!allHookedOffsets.has(targetOffset)) {{  // Überprüfen auf globale Ebene
                                                    allHookedOffsets.add(targetOffset); // Einmaliges Hinzufügen des Offsets
                                                    console.log("[INFO] Entering branch target at offset: " + targetOffset);
                                                    var branchRegisters = getRegisterInfo(this.context);
                                                    send({{
                                                        "event": "instruction",
                                                        "address": currentAddress.toString(),
                                                        "base_address": baseAddress.toString(),
                                                        "mnemonic": instruction.mnemonic,
                                                        "opStr": instruction.opStr,
                                                        "function_name": functionName,
                                                        "function_offset": "{hex(offset)}",
                                                        "registers": getRegisterInfo(this.context),
                                                        "target_offset": targetOffset.toString(),
                                                        "hook": true
                                                    }});
                                                }}
                                                hookedOffsets.add(targetOffset);
                                                console.log("[INFO] Hook erfolgreich erkannt an Offset: " + targetOffset);
                                            }} else {{
                                                console.log("[INFO] Offset bereits gehookt: " + targetOffset);
                                            }}
                                        }}
                                    }} else {{
                                        console.log("[WARNUNG] Zieladresse außerhalb des Modulbereichs oder in ignoreOffsets: " + targetOffset);
                                    }}
                                }} else {{
                                    console.log("[INFO] Anweisung ohne Zielregister oder Operand: " + instruction.mnemonic);
                                }}
                            }} else {{
                                send({{
                                    "event": "instruction",
                                    "address": currentAddress.toString(),
                                    "base_address": baseAddress.toString(),
                                    "mnemonic": instruction.mnemonic,
                                    "opStr": instruction.opStr,
                                    "function_name": functionName,
                                    "function_offset": "{hex(offset)}",
                                    "registers": getRegisterInfo(this.context)
                                }});
                            }}

                            currentAddress = currentAddress.add(instruction.size);
                        }}
                    }},
                    onLeave: function(retval) {{
                        var registers = getRegisterInfo(this.context);
                        var registerOutput = {{
                            "event": "onLeave",
                            "registers": registers,
                            "retval": retval.toInt32(),
                            "function_name": functionName,
                            "function_offset": "{hex(offset)}"
                        }};
                        send(registerOutput);
                        console.log("[INFO] Verlasse Funktionsaufruf bei: " + functionAddress);
                        console.log("[INFO] Rückgabewert: " + retval.toInt32());
                    }}
                }});
            }}

            hookFunction(targetLibrary, targetFunctionOffset, "{name}");
        }}
        """
        hooks.append(hook_code)

    return "\n".join(hooks)
