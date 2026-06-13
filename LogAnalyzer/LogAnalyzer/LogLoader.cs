using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogAnalyzer
{
    internal class LogLoader
    {
        public List<LogEntry> Entries { get; private set; }
        public List<string> KnownIps{ get; private set; }
        public event Action<int> OnProgress;

        public LogLoader()
        {
            this.Entries = new List<LogEntry>();
            this.KnownIps = new List<string>();
        }

        public void LoadEntries(string filePath)
        {
            Entries.Clear();
            foreach (var item in LoadFile(filePath))
            {
                Entries.Add(ParseEntry(item));
            }
        }

        public void LoadKnownIps(string filePath)
        {
            KnownIps.Clear();
            foreach (var item in LoadFile(filePath))
            {
                KnownIps.Add(item);
            }
        }

        private List<string> LoadFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File path {filePath} does not exist.");
            }

            List<string> lines = new List<string>();

            using (StreamReader sr = new StreamReader(filePath))
            {
                string ?line;
                int processedLines = 0;
                while ((line = sr.ReadLine()) != null)
                {
                    processedLines++;
                    OnProgress?.Invoke(processedLines);
                    lines.Add(line);
                }
            }
            return lines;
        }

        private LogEntry ParseEntry(string line) {

            List<string> result = new List<string>();

            string[] parts = line.Split('|');
            bool skipDate = true;

            foreach (string part in parts)
            {
                if (skipDate)
                {
                    result.Add(part);
                    skipDate = false;
                    continue;
                }
                string[] subParts = part.Split(':');
                if (subParts.Length > 1)
                {
                    result.Add(subParts[1]);
                }
                else
                {
                    result.Add(part);
                }
            }

            LogEntry entry = new LogEntry
            {
                DateAndTime = DateTime.Parse(result[0]),
                Severity = result[1].Trim(),
                Host = result[2].Trim(),
                User = result[3].Trim(),
                Event = result[4].Trim(),
                Ip = result[5].Trim(),
                port = int.Parse(result[6]),
                Service = result[7].Trim()
            };
            return entry;
        }
    }
}
