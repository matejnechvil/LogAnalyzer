using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogAnalyzer
{
    internal class LogExporter
    {
        public void ExportToTxt(List<Alert> alerts, string statistics, string outputPath)
        {
            string filePath = Path.Combine(outputPath, "report.txt");

            using (StreamWriter writer = new StreamWriter(filePath, false))
            {
                writer.WriteLine("===== LOG REPORT =====");
                writer.WriteLine();
                writer.WriteLine("=== STATISTICS ===");
                writer.WriteLine(statistics);

                writer.WriteLine();
                writer.WriteLine("=== ALERTS ===");

                foreach (var alert in alerts)
                {
                    writer.WriteLine("==================================");
                    writer.WriteLine($"Title: {alert.Title}");
                    writer.WriteLine($"Severity: {alert.Severity}");
                    writer.WriteLine($"Date: {alert.DateAndTime}");
                    writer.WriteLine($"DescrIPtion: {alert.DescrIPtion}");
                    writer.WriteLine($"Affected user: {alert.AffectedUser}");
                    writer.WriteLine($"IP: {alert.IP}");
                }

                writer.WriteLine("==================================");
            }
        }
    }
}
