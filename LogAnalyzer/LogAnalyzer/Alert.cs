using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogAnalyzer
{
    internal class Alert
    {
        public required string Title { get; set; }
        public required string Severity { get; set; }
        public required DateTime DateAndTime { get; set; }
        public required string Description { get; set; }
        public required string AffectedUser { get; set; }
        public required string Ip { get; set; }
    }
}
