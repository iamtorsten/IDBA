# Intelligent Dynamic Binary Analysis (IDBA)

## Übersicht

Intelligent Dynamic Binary Analysis (IDBA) ist ein leistungsstarkes Tool, das für die dynamische Analyse von Binäranwendungen entwickelt wurde. Dieses Projekt nutzt das leistungsstarke Instrumentierungs-Framework von Frida, um in native Bibliotheken einzuhaken und verschiedene Laufzeitanalysen durchzuführen, wie z.B. Funktionsaufrufe, Speicherzugriffe und Registerwerte.

## Funktionen

- **Dynamisches Hooking von Funktionen**: Abfangen von Funktionsaufrufen in nativen Bibliotheken und Durchführung von Echtzeitanalysen.
- **Überwachung des Speicherzugriffs**: Verfolgen und Protokollieren von Lese- und Schreiboperationen im Speicher.
- **Überwachung von Registern**: Erfassen und Protokollieren des Zustands der CPU-Register während der Funktionsausführung.
- **Anweisungsnachverfolgung**: Nachverfolgen von Anweisungen, die von den gehookten Funktionen ausgeführt werden, um Einblicke in das Verhalten der Anwendung zu erhalten.
- **Detailliertes Protokollieren**: Umfassendes Protokollieren von Ereignissen, einschließlich Funktionsaufrufen, -ausgängen und Speicherzugriffen, was bei der Fehlersuche und Analyse von großem Wert sein kann.

## Anforderungen

- Python 3.x
- Frida 16.5.6

## Installation

1. **Repository klonen**:
   ```bash
   git clone https://github.com/iamtorsten/idba.git
   cd idba

2. **Android Server pushen**:
   ```bash
   cd idba
   adb devices
   adb push IDBA /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/IDBA"

## Bearbeitung

Passen Sie die Datei ``agent.py`` entsprechend Ihren Bedürfnissen an.

## Ausführung

1. **Android Server starten**:
   ```bash
   cd idba
   adb devices
   adb shell
   su
   cd "/data/local/tmp"
   ./IDBA

2. **IDBA starten**:
   ```bash
   python main.py

## Kontakt

Für Fragen kontaktieren Sie mich bitte über den Messenger-Dienst Telegram. Mein Nutzername lautet [iamtorsten](https://t.me/iamtorsten).
