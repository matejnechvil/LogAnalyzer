using System.Windows.Forms;

namespace LogAnalyzer
{
    internal class Program
    {
        [STAThread]

        static void Main(string[] args)
        {
            LogLoader requiredFiles = new LogLoader();
            requiredFiles.OnProgress += count =>
            {
                Console.Write($"\rLoaded {count} lines...");
            };

            PrintLogo();
            Console.Write("  enter log file path > ");

            // File dialog for selecting log file //
            Application.EnableVisualStyles();
            OpenFileDialog SelectFileDialog = new OpenFileDialog();
            SelectFileDialog.Filter = "Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*";
            SelectFileDialog.Title = "Select Log File";

            if (SelectFileDialog.ShowDialog() == DialogResult.OK)
            {
                string path = SelectFileDialog.FileName;
                Console.WriteLine(path);
            }
            else
            {
                Console.WriteLine("No file selected. Exiting...");
                return;
            }

            bool running = true;
            while (running)
            {
                Console.Clear();
                PrintLogo();
                PrintMenu();

                int choice = 0;
                Console.ReadLine();
                do
                {
                    Console.WriteLine("ERR: Enter valid choice!");
                    Console.Write("  >> ");
                } while (!(int.TryParse(Console.ReadLine(), out choice)));


                switch (choice)
                {
                    case 1:
                        Console.WriteLine("choice 1");
                        break;
                    case 2:
                        Console.WriteLine("choice 2");
                        break;
                    case 3:
                        Console.WriteLine("choice 3");
                        break;
                    case 4:
                        Console.WriteLine("choice 4");
                        break;
                    case 5:
                        Console.WriteLine("Exiting...");
                        running = false;
                        break;
                    default:
                        break;
                }

            }
        }

        static void PrintLogo()
        {
            Console.WriteLine();
            Console.WriteLine(@"  ===========================================");
            Console.WriteLine(@"  |   .---.                                 |");
            Console.WriteLine(@"  |  /     \   LOG ANALYZER                 |");
            Console.WriteLine(@"  |  |  o  |   ============================ |");
            Console.WriteLine(@"  |  \     /   version  :  1.0              |");
            Console.WriteLine(@"  |   `---'                                 |");
            Console.WriteLine(@"  |      \     status   :  ready            |");
            Console.WriteLine(@"  |       \                                 |");
            Console.WriteLine(@"  ===========================================");
        }

        static void PrintMenu()
        {
            Console.WriteLine(@"  ===========================================");
            Console.WriteLine(@"  |   1  >>  Load log file                  |");
            Console.WriteLine(@"  |   2  >>  Search entries                 |");
            Console.WriteLine(@"  |   3  >>  Filter by IP                   |");
            Console.WriteLine(@"  |   4  >>  Export results                 |");
            Console.WriteLine(@"  |   5  >>  Exit                           |");
            Console.WriteLine(@"  ===========================================");
            Console.WriteLine();
            Console.Write("  >> ");
        }
    }
}
