# Intelligent Dynamic Binary Analysis (IDBA)

## Übersicht: Overview: 概述:

Intelligent Dynamic Binary Analysis (IDBA) ist ein leistungsstarkes Tool, das für die dynamische Analyse von Binäranwendungen entwickelt wurde. Dieses Projekt nutzt das leistungsstarke Instrumentierungs-Framework von Frida, um in native Bibliotheken einzuhaken und verschiedene Laufzeitanalysen durchzuführen, wie z.B. Funktionsaufrufe, Speicherzugriffe und Registerwerte.

Intelligent Dynamic Binary Analysis (IDBA) is a powerful tool designed for dynamic analysis of binary applications. This project leverages Frida's powerful instrumentation framework to hook into native libraries and perform various runtime analysis such as function calls, memory accesses, and register values.

智能动态二进制分析 (IDBA) 是一款功能强大的工具，专为二进制应用程序的动态分析而设计。该项目利用 Frida 强大的检测框架来挂接本机库并执行各种运行时分析，例如函数调用、内存访问和寄存器值。

## Funktionen: Functions: 特征:

- **Dynamisches Hooking von Funktionen**: Abfangen von Funktionsaufrufen in nativen Bibliotheken und Durchführung von Echtzeitanalysen.
- **Überwachung des Speicherzugriffs**: Verfolgen und Protokollieren von Lese- und Schreiboperationen im Speicher.
- **Überwachung von Registern**: Erfassen und Protokollieren des Zustands der CPU-Register während der Funktionsausführung.
- **Anweisungsnachverfolgung**: Nachverfolgen von Anweisungen, die von den gehookten Funktionen ausgeführt werden, um Einblicke in das Verhalten der Anwendung zu erhalten.
- **Detailliertes Protokollieren**: Umfassendes Protokollieren von Ereignissen, einschließlich Funktionsaufrufen, -ausgängen und Speicherzugriffen, was bei der Fehlersuche und Analyse von großem Wert sein kann.<br><br>
- **Dynamic function hooking**: Intercept function calls in native libraries and perform real-time analysis.
- **Memory access monitoring**: Track and log memory read and write operations.
- **Register monitoring**: Capture and log the state of CPU registers during function execution.
- **Instruction tracing**: Track instructions executed by the hooked functions to gain insight into application behavior.
- **Detailed logging**: Comprehensive logging of events including function calls, exits, and memory accesses, which can be of great value in debugging and analysis. <br><br>
- **函数的动态hook**：拦截原生库中的函数调用并进行实时分析。
- **内存访问监控**：跟踪并记录内存读写操作。
- **寄存器监控**：捕获并记录函数执行期间CPU寄存器的状态。
- **语句跟踪**：跟踪挂钩函数执行的语句以深入了解应用程序的行为。
- **详细日志记录**：全面记录事件，包括函数调用、退出和内存访问，这对于故障排除和分析非常有价值。

## Anforderungen: Requirements: 要求:

- Python 3.x
- Frida 16.5.6

## Installation

1. **Repository klonen**: **Clone repository**: **克隆存储库**：
   ```bash
   git clone https://github.com/iamtorsten/idba.git
   cd idba

2. **Android Server pushen**: **Push Android Server**: **推送 Android 服务器**：
   ```bash
   cd idba
   adb devices
   adb push IDBA /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/IDBA"

## Bearbeitung: Editing: 编辑:

Passen Sie die Datei ``agent.py`` entsprechend Ihren Bedürfnissen an.

Customize the ``agent.py`` file according to your needs.

根据您的需要自定义“agent.py”文件。

## Ausführung: Execution: 执行:

1. **Android Server starten**: **Start Android Server**: **启动Android服务器**：
   ```bash
   cd idba
   adb devices
   adb shell
   su
   cd "/data/local/tmp"
   ./IDBA

2. **IDBA starten**: **Start IDBA**: **启动 IDBA**：
   ```bash
   python main.py

## Kontakt: Contact: 接触:

Für Fragen kontaktieren Sie mich bitte über den Messenger-Dienst Telegram. Mein Nutzername lautet [iamtorsten](https://t.me/iamtorsten).

If you have any questions, please contact me via the messenger service Telegram. My username is [iamtorsten](https://t.me/iamtorsten).

如果您有任何疑问，请通过 Telegram Messenger 服务与我联系。我的用户名是 [iamtorsten](https://t.me/iamtorsten)。

## Rechtliches: Legal: 合法的:

Dieses Projekt dient ausschließlich persönlichen Bildungszwecken. Sie können es für Ihren persönlichen Gebrauch ändern. Ich übernehme jedoch keine Verantwortung für Probleme, die durch Änderungen an diesem Projekt entstehen. Alle im Projekt dargestellten Prozesse dienen nur als Beispiele.

Die Verwendung dieses Codes muss den geltenden Gesetzen ihres Landes entsprechen.

This project is for personal educational purposes only. You can modify it for your personal use, but I am not responsible for any problems caused by modifications to this project. All processes presented in the project are for example purposes only.

The use of this code must comply with the applicable laws of your country.

该项目仅用于个人教育目的。您可以对其进行修改以供个人使用。但是，我对因更改此项目而引起的任何问题不承担任何责任。项目中提出的所有流程仅作为示例。

本代码的使用必须遵守您所在国家/地区的适用法律。
