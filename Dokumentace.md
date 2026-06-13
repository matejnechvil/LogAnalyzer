# Log Analyzer

Autor: Matěj Nechvíl

## 1. Zadání projektu

Konzolová aplikace psaná v jazyce C# pro načítání a analýzu systémových logů. Program detekuje podezřelé aktivity (brute force útoky, neznámé IP adresy…). Výstupem programu je přehledný report z analyzovaných logů. Jsou použity vlastní testovací logy.

## 2. Funkce programu

### 2.1 Práce se soubory

- Načtení dat ze souboru ve vlastním textovém formátu (`.log` / `.txt`, pole oddělená znakem `|`)
- Generace reportu a export do souboru (`.txt`)

### 2.2 Detekce podezřelého chování

- Brute force útok (stejná IP, X neúspěšných přihlášení za krátký časový úsek) — *plánováno, bude doplněno*
- Zablokovaný účet
- Detekce neznámé IP adresy (pomocí whitelistového souboru)
- Opakované chyby stejného typu
- Přihlášení v neobvyklou dobu (22:00 – 05:00)

## 3. Třídy

| Třída | Atributy | Metody | Popis |
|---|---|---|---|
| `LogLoader` | `List<LogEntry> Entries`<br>`List<string> KnownIps`<br>`event Action<int> OnProgress` | `LoadEntries()`<br>`ParseEntry()`<br>`LoadKnownIps()` | Načte soubor s logy (`LoadEntries`) nebo soubor s důvěryhodnými IP adresami (`LoadKnownIps`); výsledky uloží do vlastností `Entries` / `KnownIps` |
| `LogEntry` | `DateTime DateAndTime`<br>`string Severity`<br>`string Host`<br>`string User`<br>`string Event`<br>`string Ip`<br>`int Port`<br>`string Service` | — | Datová třída – jeden řádek záznamu |
| `Alert` | `string Title`<br>`string Severity`<br>`string Description`<br>`string AffectedUser`<br>`string Ip`<br>`DateTime DateAndTime` | — | Datová třída – jedno upozornění |
| `LogAnalyzer` | `List<LogEntry> Entries`<br>`List<string> KnownIps`<br>`List<Alert> Alerts` | `DetectBruteForce()`<br>`DetectLockedAccount()`<br>`DetectUnknownIPs()`<br>`DetectErrorRepetition()`<br>`DetectNightLogin()`<br>`CountAlertsByTitle()` (privátní)<br>`GetStatistics()` | Detekce hrozeb a výpočet statistik |
| `LogExporter` | — | `ExportToTxt()` | Vytvoří soubor `report.txt` s přehledem statistik a všech alertů ve vybrané složce |

## 4. Vazby mezi třídami

Diagram znázorňuje závislosti a tok dat mezi třídami aplikace:

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
    (datová třída)   (datová třída)   (výstup)
```

### Legenda vazeb

| Vazba | Popis |
|---|---|
| `LogLoader → LogEntry` | LogLoader vytváří instance `LogEntry` při parsování každého řádku logu |
| `LogLoader → LogAnalyzer` | LogLoader poskytuje `List<LogEntry>` a `List<string> KnownIps`, ze kterých Program vytvoří LogAnalyzer |
| `LogAnalyzer → Alert` | LogAnalyzer vytváří instance `Alert` při detekci podezřelé aktivity |
| `Program → LogAnalyzer` | Program vytvoří instanci LogAnalyzer s daty z LogLoaderu a zavolá `Analyze()` |
| `Program → LogExporter` | Program vytvoří LogExporter a předá mu `Alerts` a statistiky z LogAnalyzeru pro export do `report.txt` |
| `Program → vše` | Program řídí tok aplikace – volá metody všech tříd skrze menu |

## 5. Ovládání

Veškeré ovládání probíhá skrze konzoli výběrem číselné volby (1 – 5) a klávesou Enter pro potvrzení. Pro výběr souboru s logy, souboru s důvěryhodnými IP adresami a cílové složky pro export se otevře systémové okno (`OpenFileDialog` / `FolderBrowserDialog`).

## 6. Formát testovacích logů

Testovací logy jsou ve vlastním formátu, kde jsou pole oddělena znakem `|`:

```
2024-03-01 07:12:34 | INFO | host:PC-NOVAK | user:admin | EVENT:LOGIN_SUCCESS | IP:192.168.1.1 | port:49721 | service:winlogon
```

Pole záznamu:

1. datum a čas
2. závažnost (`INFO` / `WARNING` / `ERROR`)
3. hostname
4. uživatel
5. typ události (`LOGIN_SUCCESS`, `LOGIN_FAIL`, `ACCOUNT_LOCKED`...)
6. IP adresa
7. port
8. služba (`winlogon`, `sshd`, `ntfs`, `security`)
