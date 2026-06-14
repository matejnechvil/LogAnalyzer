# Log Analyzer

Autor: Matěj Nechvíl

---

## 1. Zadání projektu

Konzolová aplikace psaná v jazyce C# pro načítání a analýzu systémových logů. Program detekuje podezřelé aktivity v logu a generuje přehledný report. Jsou použity vlastní testovací logy.

---

## 2. Funkce programu

### Práce se soubory

- Načtení logů ze souboru ve vlastním textovém formátu (`.log` / `.txt`, pole oddělená znakem `|`)
- Načtení seznamu důvěryhodných IP adres ze souboru (`.txt`, jedna IP na řádek)
- Export výsledků analýzy do souboru `report.txt`

### Detekce podezřelého chování

- **Brute force útok** – stejná IP provede více jak 5 neúspěšných přihlášení, přičemž mezi každými dvěma po sobě jdoucími pokusy uplyne méně než 20 sekund
- **Zablokovaný účet** – výskyt události `ACCOUNT_LOCKED`
- **Neznámá IP adresa** – IP adresa záznamu není v načteném seznamu důvěryhodných IP
- **Opakující se chyba** – stejný typ chybové události se vyskytne více než 2× v celém logu
- **Přihlášení v neobvyklou dobu** – přihlášení nebo neúspěšný pokus mezi 22:00 a 05:00

---

## 3. Třídy

| Třída | Atributy | Metody | Popis |
|---|---|---|---|
| `LogLoader` | `List<LogEntry> Entries`<br>`List<string> KnownIPs`<br>`event Action<int> OnProgress` | `LoadEntries()`<br>`LoadKnownIPs()`<br>`LoadFile()` (privátní)<br>`ParseEntry()` (privátní) | Načte soubor s logy nebo soubor s důvěryhodnými IP adresami; výsledky uloží do vlastností `Entries` / `KnownIPs`. Při načítání vyvolává událost `OnProgress` s počtem zpracovaných řádků. |
| `LogEntry` | `DateTime DateAndTime`<br>`string Severity`<br>`string Host`<br>`string User`<br>`string Event`<br>`string IP`<br>`int Port`<br>`string Service` | — | Datová třída reprezentující jeden řádek logu. |
| `Alert` | `string Title`<br>`string Severity`<br>`string Description`<br>`string AffectedUser`<br>`string IP`<br>`DateTime DateAndTime` | — | Datová třída reprezentující jedno detekované upozornění. |
| `LogAnalyzer` | `List<LogEntry> Entries` (privátní)<br>`List<string> KnownIPs` (privátní)<br>`List<Alert> Alerts`<br>`Dictionary<string,int> ErrorDict` (privátní)<br>`Dictionary<string,List<DateTime>> BruteForceDict` (privátní)<br>`Dictionary<string,string> bruteForceUsers` (privátní) | `Analyze()`<br>`DetectBruteForce()` (privátní)<br>`DetectLockedAccount()` (privátní)<br>`DetectUnknownIPs()` (privátní)<br>`DetectErrorRepetition()` (privátní)<br>`DetectNightLogin()` (privátní)<br>`CountAlertsByTitle()` (privátní)<br>`GetStatistics()` | Provede analýzu načtených záznamů a naplní seznam `Alerts`. Metoda `GetStatistics()` vrátí textový přehled počtů alertů dle kategorie. |
| `LogExporter` | — | `ExportToTxt()` | Vytvoří soubor `report.txt` ve vybrané složce obsahující statistiky a seznam všech alertů. |

---

## 4. Vazby mezi třídami

```
                    ┌─────────────┐
                    │   Program   │
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  LogLoader  │ │ LogAnalyzer │ │ LogExporter │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  LogEntry   │ │    Alert    │ │ report.txt  │
    └─────────────┘ └─────────────┘ └─────────────┘
    (datová třída)   (datová třída)    (výstup)
```

| Vazba | Popis |
|---|---|
| `Program → LogLoader` | Program vytvoří instanci `LogLoader` a zavolá `LoadEntries()` / `LoadKnownIPs()` |
| `LogLoader → LogEntry` | `LoadEntries()` vytváří instance `LogEntry` voláním `ParseEntry()` pro každý řádek |
| `Program → LogAnalyzer` | Program vytvoří instanci `LogAnalyzer` s daty z `LogLoader` a zavolá `Analyze()` |
| `LogAnalyzer → Alert` | Detekční metody vytvářejí instance `Alert` a přidávají je do `Alerts` |
| `Program → LogExporter` | Program vytvoří `LogExporter` a předá mu `Alerts` a výstup `GetStatistics()` pro export |

---

## 5. Popis práce se soubory

### Vstup – logy

Soubor je načten řádek po řádku pomocí `StreamReader`. Každý řádek je zpracován metodou `ParseEntry()`, která ho rozdělí podle oddělovače `|`. První pole (datum a čas) je převzato celé, ostatní pole jsou ve formátu `klíč:hodnota` – parser vezme vždy část za první dvojtečkou.

Formát řádku:
```
2025-05-12 08:30:49 | WARNING | host:PC-NOVAK | user:admin | EVENT:LOGIN_FAIL | IP:185.220.101.45 | port:4139 | service:sshd
```

Pořadí polí: datum a čas, závažnost, hostname, uživatel, událost, IP adresa, port, služba.

### Vstup – důvěryhodné IP adresy

Soubor obsahuje jednu IP adresu na každém řádku. Načítá se metodou `LoadKnownIPs()` do `List<string> KnownIPs`.

### Výstup – report.txt

Soubor je vytvořen pomocí `StreamWriter` do složky zvolené uživatelem. Obsahuje sekci statistik a sekci s výpisem všech alertů.

---

## 6. Ovládání

Aplikace běží v konzoli a ovládá se výběrem číselné volby (1–5) a klávesou Enter. Pro výběr souboru nebo cílové složky se otevře systémové dialogové okno (`OpenFileDialog` / `FolderBrowserDialog`).

| Volba | Akce |
|---|---|
| 1 | Načíst soubor s logy |
| 2 | Načíst soubor s důvěryhodnými IP adresami |
| 3 | Spustit analýzu a zobrazit výsledky |
| 4 | Exportovat výsledky do `report.txt` |
| 5 | Ukončit program |

Po analýze (volba 3) lze zobrazit buď souhrnné statistiky, nebo kompletní seznam alertů.
