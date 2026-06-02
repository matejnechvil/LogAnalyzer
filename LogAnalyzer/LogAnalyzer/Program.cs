namespace LogAnalyzer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            LogLoader requiredFiles = new LogLoader();
            requiredFiles.OnProgress += count =>
            {
                Console.Write($"\rLoaded {count} lines...");
            };

            Console.WriteLine(@"
   .-.   
  (   )   L O G   A N A L Y Z E R
   `-'    =======================
     \    v 1.0
      '
                ");

            bool running = true;
            while (running)
            {
                Console.Clear();
            }
        }
    }
}
