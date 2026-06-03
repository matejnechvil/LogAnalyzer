using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogAnalyzer
{
    internal class LogAnalyzer
    {
        private List<LogEntry> Entries;
        private List<string> KnownIps;
        public List<Alert> Alerts { get; set; }

        public LogAnalyzer(List<LogEntry> Entries, List<string> KnownIps)
        {
            this.Entries = Entries;
            this.KnownIps = KnownIps;
            Alerts = new List<Alert>();
        }

        public void Analyze()
        {
            for (int i = 0; i < Entries.Count; i++)
            {
                DetectLockedAccount(Entries[i]);
            }
        }

        private void DetectLockedAccount(LogEntry oneEntry)
        {
            if (oneEntry.Event == "ACCOUNT_LOCKED")
            {
                Alert alert = new Alert
                {
                    Title = "ACCOUNT LOCKED",
                    AffectedUser = oneEntry.User,
                    Severity = oneEntry.Severity,
                    Decription = $"Account {oneEntry.User} on IP {oneEntry.Ip} was locked out on {oneEntry.DateAndTime:yyyy.dd.MM} at {oneEntry.DateAndTime:HH:mm:ss}",
                    DateAndTime = oneEntry.DateAndTime,
                    Ip = oneEntry.Ip
                };

                Alerts.Add(alert);
            }
        }


    }
}
