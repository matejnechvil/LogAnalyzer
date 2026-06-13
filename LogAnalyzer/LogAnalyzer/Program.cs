namespace LogAnalyzer
{
    internal class Program
    {
        static LogAnalyzer logAnalyzer;
        static LogLoader logLoader = new LogLoader();
        [STAThread]
        static void Main(string[] args)
        {
            logLoader.OnProgress += count =>
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"\r  Loading... {count} lines");
                Console.ResetColor();
            };

            bool running = true;
            while (running)
            {
                Console.Clear();
                PrintLogo("Ready", ConsoleColor.Green);
                PrintMenu();

                int choice = 0;

                while (!(int.TryParse(Console.ReadLine(), out choice)))
                {
                    PrintColored("  [✗] No action selected.\n", ConsoleColor.Red);
                    Thread.Sleep(1000);
                    Console.Clear();
                    PrintLogo("Ready", ConsoleColor.Green);
                    PrintMenu();
                }

                switch (choice)
                {
                    case 1:
                        Choice1And2(1);
                        break;
                    case 2:
                        Choice1And2(2);
                        break;
                    case 3:
                        Choice3();
                        break;
                    case 4:
                        Choice4();
                        break;
                    case 5:
                        PrintColored("Exiting...", ConsoleColor.Red);
                        Thread.Sleep(1000);
                        running = false;
                        break;
                    default:
                        break;
                }

            }
        }

        static void Choice1And2(int choice)
        {
            Console.Clear();
            PrintLogo("Loading file", ConsoleColor.Yellow);
            PrintColored((choice == 1 ? "Select log file path..." : "Select trusted IPs file path..."), ConsoleColor.DarkYellow);

            string? path = GetPathDialog("file");
            Console.Clear();
            PrintLogo("Loading file", ConsoleColor.Yellow);

            if (path == null)
            {
                PrintColored("  [✗] No file selected.\n", ConsoleColor.Red);
                PrintColored("  Press Enter to continue...", ConsoleColor.DarkGray);
                Console.Write("  >> ");
                Console.ReadLine();
                return;
            }

            try
            {
                if (choice == 1)
                {
                    logLoader.LoadEntries(path);
                }
                else
                {
                    logLoader.LoadKnownIPs(path);
                }
            }
            catch (Exception)
            {
                Console.Clear();
                PrintLogo("ERROR", ConsoleColor.Red);
                PrintColored("  [✗] Invalid data format.\n", ConsoleColor.Red);
                PrintColored("  Press Enter to continue...", ConsoleColor.DarkGray);
                Console.Write("  >> ");
                Console.ReadLine();
                return;
            }

            Console.Clear();
            PrintLogo("Loading file", ConsoleColor.Yellow);

            if (choice == 1 ? logLoader.Entries.Count > 0 : logLoader.KnownIPs.Count > 0)
            {
                PrintColored("  ┌─ LOAD SUCCESSFUL ──────────────────────────┐", ConsoleColor.Green);
                PrintColored($"  │  Lines loaded : {(choice == 1 ? logLoader.Entries.Count : logLoader.KnownIPs.Count),-28}│", ConsoleColor.Green); PrintColored($"  │  File         : {Path.GetFileName(path),-28}│", ConsoleColor.Green);
                PrintColored("  └─────────────────────────────────────────────┘", ConsoleColor.Green);
            }
            else
            {
                PrintColored("  ┌─ WARNING ───────────────────────────────────┐", ConsoleColor.Yellow);
                PrintColored("  │  File loaded but contains no entries.       │", ConsoleColor.Yellow);
                PrintColored($"  │  File : {Path.GetFileName(path),-36}│", ConsoleColor.Yellow);
                PrintColored("  └─────────────────────────────────────────────┘", ConsoleColor.Yellow);
            }

            Console.WriteLine();
            PrintColored("  Press Enter to continue...", ConsoleColor.DarkGray);
            Console.Write("  >> ");
            Console.ReadLine();
        }

        static void Choice3()
        {
            Console.Clear();
            PrintLogo("Scan for threads", ConsoleColor.Yellow);

            if (logLoader.Entries.Count == 0)
            {
                PrintColored("  [✗] No entries loaded.\n", ConsoleColor.Red);
                PrintColored("  Do you want to load them? (Y/N)", ConsoleColor.DarkGray);
                Console.Write("  >> ");

                if (Console.ReadLine().ToUpper() == "Y")
                {
                    Choice1And2(1);
                }
                else
                {
                    return;
                }
            }

            logAnalyzer = new LogAnalyzer(logLoader.Entries, logLoader.KnownIPs);
            logAnalyzer.Analyze();

            Console.Clear();
            PrintLogo("Analysis complete", ConsoleColor.Green);

            PrintColored("  ┌─ ANALYSIS SUCCESSFUL ─────────────────────┐", ConsoleColor.Green);
            PrintColored($"  │  Entries processed : {logLoader.Entries.Count,-22}│", ConsoleColor.Green);
            PrintColored($"  │  Alerts generated  : {logAnalyzer.Alerts.Count,-22}│", ConsoleColor.Green);
            PrintColored("  └────────────────────────────────────────────┘", ConsoleColor.Green);

            Console.WriteLine();
            PrintColored("  What do you want to display?", ConsoleColor.DarkGray);
            Console.WriteLine("  1 - Statistics");
            Console.WriteLine("  2 - All alerts");
            Console.Write("  >> ");

            string choice = Console.ReadLine();

            Console.Clear();

            if (choice == "1")
            {
                Console.WriteLine(logAnalyzer.GetStatistics());
            }
            else if (choice == "2")
            {
                foreach (var alert in logAnalyzer.Alerts)
                {
                    Console.WriteLine("==================================");
                    Console.WriteLine($"Title: {alert.Title}");
                    Console.WriteLine($"Severity: {alert.Severity}");
                    Console.WriteLine($"Date: {alert.DateAndTime}");
                    Console.WriteLine($"DescrIPtion: {alert.DescrIPtion}");
                    Console.WriteLine($"Affected user: {alert.AffectedUser}");
                    Console.WriteLine($"IP: {alert.IP}");
                }

                Console.WriteLine("==================================");
            }
            else
            {
                Console.WriteLine("Invalid choice.");
            }

            Console.WriteLine("\nPress Enter to continue...");
            Console.ReadLine();
        }
        static void Choice4()
        {
            Console.Clear();
            PrintLogo("Export", ConsoleColor.Yellow);

            if (logAnalyzer == null || logAnalyzer.Alerts.Count == 0)
            {
                PrintColored("  [!] No alerts to export.\n", ConsoleColor.Red);
                PrintColored("  Press Enter to continue...", ConsoleColor.DarkGray);
                Console.Write("  >> ");
                Console.ReadLine();
                return;
            }

            string path = GetPathDialog("folder");

            if (path == null)
            {
                PrintColored("  [✗] No export location selected.\n", ConsoleColor.Red);
                PrintColored("  Press Enter to continue...", ConsoleColor.DarkGray);
                Console.Write("  >> ");
                Console.ReadLine();
                return;
            }

            try
            {
                LogExporter exporter = new LogExporter();
                exporter.ExportToTxt(
                    logAnalyzer.Alerts,
                    logAnalyzer.GetStatistics(),
                    path
                );

                Console.Clear();
                PrintLogo("Export", ConsoleColor.Green);

                PrintColored("  ┌─ EXPORT SUCCESSFUL ───────────────────────┐", ConsoleColor.Green);
                PrintColored($"  │  File saved to : {Path.GetFileName(path),-26}│", ConsoleColor.Green);
                PrintColored("  └───────────────────────────────────────────┘", ConsoleColor.Green);
            }
            catch
            {
                PrintColored("  [✗] Export failed.", ConsoleColor.Red);
            }

            Console.WriteLine();
            PrintColored("  Press Enter to continue...", ConsoleColor.DarkGray);
            Console.Write("  >> ");
            Console.ReadLine();
        }

        static string GetPathDialog(string mode)
        {
            Application.EnableVisualStyles();

            if (mode.ToLower() == "file")
            {
                using (OpenFileDialog dialog = new OpenFileDialog())
                {
                    dialog.Filter = "Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*";
                    dialog.Title = "Select File";

                    if (dialog.ShowDialog() == DialogResult.OK)
                        return dialog.FileName;
                }
            }
            else if (mode.ToLower() == "folder")
            {
                using (FolderBrowserDialog dialog = new FolderBrowserDialog())
                {
                    dialog.DescrIPtion = "Select Folder";
                    dialog.ShowNewFolderButton = true;

                    if (dialog.ShowDialog() == DialogResult.OK)
                        return dialog.SelectedPath;
                }
            }

            return null;
        }

        static void PrintLogo(string status, ConsoleColor statusColor)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(@"   =========================================");
            Console.WriteLine(@"  |   .---.                                 |");
            Console.WriteLine(@"  |  /     \   LOG ANALYZER                 |");
            Console.Write(@"  |  |  o  |   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(@"============================");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(@" |");
            Console.WriteLine(@"  |  \     /   version  :  1.0              |");
            Console.WriteLine(@"  |   `---'                                 |");
            Console.Write(@"  |      \     status   :  ");
            Console.ForegroundColor = statusColor;
            Console.Write($"{status,-17}");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(@"|");
            Console.WriteLine(@"  |       \                                 |");
            Console.WriteLine(@"   =========================================");
            Console.ResetColor();
        }

        static void PrintMenu()
        {
            Console.WriteLine(@"   ========================================= ");
            Console.WriteLine(@"  |   1  >>  Load log file                  |");
            Console.WriteLine(@"  |   2  >>  Load Trusted IPs               |");
            Console.WriteLine(@"  |   3  >>  Scan for Threats               |");
            Console.WriteLine(@"  |   4  >>  Export results                 |");
            Console.WriteLine(@"  |   5  >>  Exit                           |");
            Console.WriteLine(@"   =========================================");
            Console.WriteLine();
            Console.Write("  >> ");
        }
        static void PrintColored(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }
    }
}
