using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace winrmcp_example
{
    class Program
    {
        static void Main(string[] args)
        {
            var winrm = new winrmcp.controller(
                "test.cloudapp.net",
                "Administrator",
                "wrong-password",
                winrmTcpPort: 5986,
                checkCertificateAsPublic: true);

            var output = winrm.RunScript("echo $env:computername");
            Console.WriteLine(output.StdOut);

            winrm.CopyFile(@"c:\share\installer.msi", @"c:\installer.msi");
        }
    }
}
