def hook(target_library, functions, max_instructions=None):
    hooks = []
    for function in functions:
        offset = function["offset"]
        name = function["name"]
        hook_code = f"""
        {{
            const targetLibrary = "{target_library}";
            const targetFunctionOffset = {offset};
            var maxInstructions = {max_instructions if max_instructions is not None else 'Infinity'};  // Standardwert auf Infinity, wenn nicht angegeben

            function getRegisterInfo(context) {{
                var registerNames = [
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                    "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                    "x15", "x16", "x17", "x18", "x19", "x20", "x21",
                    "x22", "x23", "x24", "x25", "x26", "x27", "x28",
                    "x29", "x30", "sp", "pc",
                    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
                    "w8", "w9", "w10", "w11", "w12", "w13", "w14",
                    "w15", "w16", "w17", "w18", "w19", "w20", "w21",
                    "w22", "w23", "w24", "w25", "w26", "w27", "w28",
                    "w29", "w30", "wsp", "wpc",
                    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"
                ];

                var registers = {{}};  // Register initialisieren

                registerNames.forEach(function(name) {{
                    if (context[name] !== undefined) {{
                        var value = context[name].toString(16);
                        registers[name] = {{
                            "hex": "0x" + value
                        }};
                    }} else {{
                        registers[name] = {{
                            "hex": "N/A"
                        }};
                    }}
                }});

                return registers;
            }}

            function hookFunction(libraryName, offset, functionName) {{
                var module = Process.getModuleByName(libraryName);
                var functionAddress = module.base.add(offset);

                console.log("[INFO] Hooking-Funktion an Adresse: " + functionAddress);

                Interceptor.attach(functionAddress, {{
                    onEnter: function(args) {{
                        var baseAddress = Module.findBaseAddress("{target_library}");

                        console.log("[INFO] Basisadresse: " + baseAddress);
                        console.log("[INFO] An der Adresse eingegebene Funktion: " + functionAddress);
                        console.log("[INFO] Größe: " + module.size);

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

                        // Anweisungen zur Ablaufverfolgung
                        var currentAddress = this.context.pc;
                        for (var i = 0; i < maxInstructions; i++) {{
                            var instruction = Instruction.parse(currentAddress);
                            if (!instruction) break;

                            console.log("[INFO] Verarbeitungsanweisung: " + instruction.mnemonic + " " + instruction.opStr);

                            // Anweisungsdetails mit Registerinformationen senden
                            send({{
                                "event": "instruction",
                                "address": currentAddress.toString(),
                                "base_address": baseAddress.toString(),
                                "mnemonic": instruction.mnemonic,
                                "opStr": instruction.opStr,
                                "function_name": functionName,
                                "function_offset": "{hex(offset)}",
                                "registers": getRegisterInfo(this.context)  // Registrierungsinformationen mit Anweisungen senden
                            }});

                            currentAddress = currentAddress.add(instruction.size);
                        }}

                        // Überwache Funktionsaufrufe innerhalb dieser Funktion
                        monitorFunctionCalls(functionAddress);
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
                        send(registerOutput);  // Rückgabewert und Registerinformationen senden

                        // Protokollierung, nachdem die Funktion verlassen wurde
                        console.log("[INFO] Verlasse Funktionsaufruf bei: " + functionAddress);
                        console.log("[INFO] Rückgabewert: " + retval.toInt32());
                    }}
                }});
            }}

            function monitorFunctionCalls(functionAddress) {{
                Interceptor.attach(functionAddress, {{
                    onEnter: function(args) {{
                        console.log("[INFO] Betrete Funktionsaufruf bei: " + functionAddress);

                        // Protokollierung der Argumente
                        for (var i = 0; i < args.length; i++) {{
                            console.log("[INFO] Argument " + i + ": " + args[i].toString());
                            console.log("[INFO] Typ von Argument " + i + ": " + typeof args[i]); // Typ des Arguments loggen
                            console.log("[INFO] Adresse von Argument " + i + ": " + args[i].toString()); // Adresse des Arguments loggen
                        }}

                        // Anzahl der Argumente loggen
                        console.log("[INFO] Anzahl der Argumente: " + args.length);

                        // Dynamisches Hooking der aufgerufenen Funktion
                        // Überprüfe, ob ein Argument möglicherweise eine Funktion ist
                        for (var i = 0; i < args.length; i++) {{
                            var address = args[i].toInt32(); // Konvertiere das Argument in eine Ganzzahl
                            if (address !== 0 && Process.isExecutable(address)) {{
                                console.log("[INFO] Hooking nächste Funktion bei Adresse: " + args[i].toString());
                                hookFunction(targetLibrary, address, address); // Setze den Funktionsnamen entsprechend
                            }}
                        }}
                    }},
                    onLeave: function(retval) {{
                        // Protokollierung, nachdem die Funktion verlassen wurde
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