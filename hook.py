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
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                    "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                    "x15", "x16", "x17", "x18", "x19", "x20", "x21",
                    "x22", "x23", "x24", "x25", "x26", "x27", "x28",
                    "x29", "x30", "sp", "pc",
                    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
                    "q8", "q9", "q10", "q11", "q12", "q13", "q14",
                    "q15", "q16", "q17", "q18", "q19", "q20", "q21",
                    "q22", "q23", "q24", "q25", "q26", "q27", "q28",
                    "q29", "q30", "q31"
                ];
                return registerNames.includes(opStr);
            }}

            function getRegisterInfo(context) {{
                var registerNames = [
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                    "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                    "x15", "x16", "x17", "x18", "x19", "x20", "x21",
                    "x22", "x23", "x24", "x25", "x26", "x27", "x28",
                    "x29", "x30", "sp", "pc",
                    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
                    "q8", "q9", "q10", "q11", "q12", "q13", "q14",
                    "q15", "q16", "q17", "q18", "q19", "q20", "q21",
                    "q22", "q23", "q24", "q25", "q26", "q27", "q28",
                    "q29", "q30", "q31"
                ];

                var registers = {{}};

                registerNames.forEach(function(name) {{
                    if (context[name] !== undefined) {{
                        if (name.startsWith("q") && context[name] instanceof ArrayBuffer) {{
                            var byteArray = new Uint8Array(context[name]);
                            var hexString = Array.from(byteArray, byte => ('0' + byte.toString(16)).slice(-2)).join('');
                            registers[name] = {{ "hex": "0x" + hexString }};
                        }} else {{
                            var value = context[name].toString(16);
                            registers[name] = {{
                                "hex": "0x" + value
                            }};
                            if (name.startsWith("x") && name.length > 1) {{
                                var wName = "w" + name.slice(1);
                                registers[wName] = {{
                                    "hex": "0x" + (parseInt(value, 16) & 0xFFFFFFFF).toString(16)
                                }};
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
