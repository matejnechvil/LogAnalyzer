using Microsoft.VisualBasic.Logging;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
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
                DetectNightLogin(Entries[i]);
                DetectUnknownIPs(Entries[i]);
                DetectErrorRepetition(Entries[i], i);
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
                    Description = $"Account {oneEntry.User} on IP {oneEntry.Ip} was locked out on {oneEntry.DateAndTime:yyyy.dd.MM} at {oneEntry.DateAndTime:HH:mm:ss}",
                    DateAndTime = oneEntry.DateAndTime,
                    Ip = oneEntry.Ip
                };

                Alerts.Add(alert);
            }
        }
        private void DetectNightLogin(LogEntry oneEntry)
        {
            int login;
            if (oneEntry.Event == "LOGIN_SUCCESS")
            {
                login = 1;
            }
            else if (oneEntry.Event == "LOGIN_FAIL")
            {
                login = 2;
            }
            else
            {
                login = 0;
            }

            if (login == 1 || login == 2)
            {
                if (oneEntry.DateAndTime.Hour > 21 || oneEntry.DateAndTime.Hour < 5)
                {
                    Alert alert = new Alert
                    {
                        Title = "NIGHT LOGIN",
                        AffectedUser = oneEntry.User,
                        Severity = oneEntry.Severity,
                        Description = $"Account {oneEntry.User} on IP {oneEntry.Ip} {(login == 1 ? "logged in" : "tried to log in")} outside of standard hours on {oneEntry.DateAndTime:yyyy.dd.MM} at {oneEntry.DateAndTime:HH:mm:ss}",
                        DateAndTime = oneEntry.DateAndTime,
                        Ip = oneEntry.Ip
                    };

                    Alerts.Add(alert);
                }
            }
        }

        public void DetectUnknownIPs(LogEntry oneEntry)
        {
            if (!KnownIps.Contains(oneEntry.Ip))
            {
                Alert alert = new Alert
                {
                    Title = "UNKNOWN IP ADRESS",
                    AffectedUser = oneEntry.User,
                    Severity = oneEntry.Severity,
                    Description = $"Account {oneEntry.User} on IP {oneEntry.Ip} is not in the list of trusted Ip adresses",
                    DateAndTime = oneEntry.DateAndTime,
                    Ip = oneEntry.Ip
                };

                Alerts.Add(alert);
            }
        }

        Dictionary<string, int> errorDict = new Dictionary<string, int>();
        public void DetectErrorRepetition(LogEntry oneEntry, int iteration)
        {
            if (oneEntry.Severity == "ERROR")
            {
                if (errorDict.ContainsKey(oneEntry.Event))
                {
                    errorDict[oneEntry.Event]++;
                }
                else
                {
                    errorDict.Add(oneEntry.Event, 1);
                }
            }

            if (iteration != Entries.Count - 1)
            {
                return;
            }

            foreach (var (errorName, count) in errorDict)
            {
                if (count > 2)
                {
                    Alert alert = new Alert
                    {
                        Title = "ERROR REPETITION",
                        AffectedUser = "NONE",
                        Severity = "ERROR",
                        Description = $"Error {errorName} has repeated {count} times in the log",
                        DateAndTime = DateTime.MinValue,
                        Ip = "NONE"
                    };

                    Alerts.Add(alert);
                }
            }
        }


    }
}
