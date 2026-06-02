using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogAnalyzer
{
    internal class LogEntry
    {
        public required DateTime DateAndTime { get; set; }
        public required string Severity { get; set; }
        public required string Host { get; set; }
        public required string User { get; set; }
        public required string Event { get; set; }
        public required string Ip { get; set; }
        public required int port { get; set; }
        public required string Service { get; set; }
    }
}
