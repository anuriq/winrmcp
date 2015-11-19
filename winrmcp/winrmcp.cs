namespace winrmcp
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Management.Automation;
    using System.Management.Automation.Runspaces;
    using System.Security;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Initiate instance of controller to work with one remote host.
    /// Powershell sessions recreated on each method call.
    /// </summary>
    public class controller
    {
        #region Private fields
        private string hostAddress;
        private string username;
        private SecureString password;
        private int winrmPort;
        private string certificateThumbprint;
        private bool checkCertificateAsPublic;
        private bool checkCertificateByThumbprint;
        private long scriptsOverheadBytes = 819200;  // 800 kb found during testing
        #endregion

        #region Public fields and constants
        /// <summary>
        /// 50 MB default. See https://technet.microsoft.com/en-us/library/hh847850.aspx topic.
        /// </summary>
        public long MaxPowershellSendDataBytes = 52428800;

        /// <summary>
        /// Command line maximum char length. For cmd.exe equals to 8192, for
        /// PowerShell the limit is 32767 characters.
        /// This limitation comes from the UNICODE_STRING type
        /// and is same for CreateProcess call in Windows.
        /// </summary>
        public int CommandCharacterLimit = 32700;

        public const int TinyFileMaxBytes = 307200;
        public const string ShellSchema = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell";
        #endregion

        /// <summary>
        /// Populates internal fields to use for methods call.
        /// Create for specific remote host and keep for future use.
        /// </summary>
        /// <param name="hostAddress">IP or DNS name of remote host.</param>
        /// <param name="userName">Remote user.</param>
        /// <param name="userPassword">Remote user password.</param>
        /// <param name="winrmTcpPort">Default HTTP port is 5985. For default HTTPS port use 5986.</param>
        /// <param name="checkCertificateAsPublic">Check certificate as if it were a public HTTPS certificate.</param>
        /// <param name="checkCertificateByThumbprint">Check certificate by manually providing SHA1 thumbprint.</param>
        /// <param name="remoteCertificateThumbprint">Remote certificate SHA1 thumbprint.</param>
        public controller(
            string hostAddress,
            string userName,
            string userPassword,
            int winrmTcpPort = 5985,
            bool checkCertificateAsPublic = false,
            bool checkCertificateByThumbprint = false,
            string remoteCertificateThumbprint = ""
            )
        {
            #region Input validation
            if (string.IsNullOrWhiteSpace(hostAddress) ||
                string.IsNullOrWhiteSpace(userName) ||
                string.IsNullOrWhiteSpace(userPassword))
            {
                throw new WinRMException("Host address, username or password were not provided.");
            }

            if (checkCertificateByThumbprint && remoteCertificateThumbprint == "")
            {
                throw new WinRMException("Provide certificate thumbprint to check against.");
            }
            #endregion

            this.hostAddress = hostAddress;
            this.username = userName;
            SecureString tmp = new SecureString();
            userPassword.ToCharArray().ToList().ForEach(p => tmp.AppendChar(p));
            this.password = tmp;
            this.winrmPort = winrmTcpPort;
            this.checkCertificateAsPublic = checkCertificateAsPublic;
            this.certificateThumbprint = remoteCertificateThumbprint;
            this.checkCertificateByThumbprint = checkCertificateAsPublic ? false : checkCertificateByThumbprint;
        }

        public void CopyTinyFile(string sourceFilePath, string destinationFilePath)
        {
            var finfo = new FileInfo(sourceFilePath);
            if (finfo.Length > TinyFileMaxBytes)
                throw new WinRMException("Source file is too large. Use CopyFile method.");

            saveBytesToRemoteFile(File.ReadAllBytes(sourceFilePath), destinationFilePath);
        }

        public void SaveTinyFile(string content, string destinationFilePath)
        {
            var srcBytes = (new UTF8Encoding(true, true)).GetBytes(content);
            if (srcBytes.Length > TinyFileMaxBytes)
                throw new WinRMException("Source string is too large. Use CopyFile method.");

            saveBytesToRemoteFile(srcBytes, destinationFilePath);
        }

        public void CopyFile(string sourceFilePath, string destinationFilePath, bool checkHashes = true)
        {
            uploadFile(sourceFilePath, destinationFilePath);

            if (checkHashes)
            {
                bool copySuccessful = compareHashes(sourceFilePath, destinationFilePath);
                if (!copySuccessful)
                {
                    throw new WinRMException("Copy failed or hashes did not match.");
                }
            }
        }

        public RunScriptOutput RunScript(string scriptBlock)
        {
            var o = new RunScriptOutput();

            using (PowerShell powershell = PowerShell.Create())
            {
                powershell.Runspace = OpenRunspace();
                powershell.AddScript(scriptBlock);
                var results = powershell.BeginInvoke();
                foreach (PSObject obj in powershell.EndInvoke(results))
                {
                    o.AppendStdOut(obj);
                }
                powershell.Runspace.Close();
                if (powershell.HadErrors)
                {
                    o.HadErrors = true;
                    foreach (var errorRecord in powershell.Streams.Error)
                    {
                        o.AppendStdErr(errorRecord);
                    }
                }
            }

            return o;
        }

        #region Internal Methods

        private void saveBytesToRemoteFile(byte[] bytes, string destinationFile)
        {
            string srcBase64Encoded = Convert.ToBase64String(bytes);
            string remoteScript = string.Concat(
                string.Format("$targetPath=\"{0}\";\r\n", destinationFile),
                string.Format("$b64=\"{0}\";\r\n", srcBase64Encoded),
                "$fileBytes = ([Convert]::FromBase64String($b64));\r\n",
                "[IO.File]::WriteAllBytes($targetPath, $fileBytes);\r\n"
                );

            var results = RunScript(remoteScript);
            if (results.HadErrors)
            {
                throw new WinRMException(results.StdErr.Substring(0, 2000));
            }
        }

        private void uploadFile(string sourceFilePath, string destinationFilePath)
        {
            string initializeFile = string.Format("[IO.File]::Create('{0}').Dispose();\r\n", destinationFilePath);
            var output = RunScript(initializeFile);
            if (output.HadErrors)
            {
                Console.WriteLine(output.StdErr);
                throw new WinRMException("Failed to initialize file.");
            }

            foreach (var portion in getPortions(sourceFilePath, CommandCharacterLimit, MaxPowershellSendDataBytes))
            {
                PowerShell powershell = null;
                for (int i = 0; i < 5; i++)
                {
                    try
                    {
                        powershell = getShellToAppendFile(destinationFilePath);
                        var results = powershell.Invoke(portion);
                        if (powershell.HadErrors)
                        {
                            var stdErr = new StringBuilder();
                            foreach (var errorRecord in powershell.Streams.Error)
                            {
                                stdErr.AppendLine(errorRecord.ToString());
                            }
                            Console.WriteLine(stdErr);
                            throw new WinRMException(stdErr.ToString().Substring(0, 2000));
                        }
                        break;
                    }
                    catch (Exception e)
                    {
                        if (e.Message.Contains("because it is being used by another process."))
                        {
                            Console.WriteLine("{0}\r\nCopy failed because of process overlap. Retrying.", e.Message);
                            Thread.Sleep(500);
                        }
                        else
                        {
                            throw new WinRMException("Exception during uploading portion of file.", e);
                        }
                    }
                    finally
                    {
                        if (powershell.Runspace != null)
                        {
                            powershell.Runspace.Close();
                        }
                        powershell.Dispose();
                        Thread.Sleep(1000);  // to increase probability of previous powershell exit
                    }
                }
            }
        }

        private PowerShell getShellToAppendFile(string destinationFile, bool overwriteFile = false)
        {
            var runspace = OpenRunspace(false);
            runspace.ThreadOptions = PSThreadOptions.ReuseThread;
            runspace.ApartmentState = ApartmentState.STA;
            runspace.Open();
            var ps = PowerShell.Create();
            ps.Runspace = runspace;

            if (overwriteFile)
            {
                ps.AddScript(string.Format("[IO.File]::Create('{0}').Dispose();\r\n", destinationFile));
            }

            string remoteScript0 = @"
$ErrorActionPreference='Stop';

function waitfile {
param(
[Parameter(Mandatory=$True)]
[string]$dstfile
)
$fileInfo = New-Object System.IO.FileInfo $dstfile;
while ($true) {
    try {
        $stream = $fileInfo.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read);
        $stream.Close();
        break;
    }
    catch {	sleep 1; }
}
}

function writechunks {
    param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
    [string[]]$chunks,
    [Parameter(Mandatory=$True)]
    [string]$dstfile
    )
    begin {
        waitfile $dstfile;
        $fs=[IO.File]::Open($dstfile, [IO.FileMode]::Append, [IO.FileAccess]::Write);
    }
    process {
        $bytes=[Convert]::FromBase64String($_);
        $fs.Write($bytes, 0, $bytes.Length);
    }
    end {
        $fs.Flush(); $fs.Dispose();
    }
}";
            ps.AddScript(remoteScript0, useLocalScope: false);
            ps.Invoke();

            ps.Commands.Clear();
            ps.AddCommand("writechunks").AddParameter("dstfile", destinationFile);

            return ps;
        }

        private IEnumerable<IEnumerable<string>> getPortions(string sourceFilePath, int cmdCharLimit, long maxSendDataBytes)
        {
            // Upload the file in chunks to get around the Windows command line size limit.
            // Base64 encodes each set of three bytes into four bytes. In addition the output
            // is padded to always be a multiple of four.
            //
            //   ceil(n / 3) * 4 = m1 - m2
            //
            //   where:
            //     n  = bytes
            //     m1 = max (8192 character command limit.)
            //     m2 = len(filePath)
            int chunkSize = (cmdCharLimit / 4) * 3;

            // we calculate a number of chunks that will fit max send data size.
            // according to this we determine the actual send data size and
            // number of such data pieces.
            long numberOfChunksInPortion = (maxSendDataBytes - scriptsOverheadBytes) / cmdCharLimit;

            var finfo = new FileInfo(sourceFilePath);
            long numberOfPortions = (finfo.Length / chunkSize / numberOfChunksInPortion) + 1;

            for (int i = 0; i < numberOfPortions; i++)
            {
                long offset = i * numberOfChunksInPortion * chunkSize;
                yield return getChunks(sourceFilePath, chunkSize, numberOfChunksInPortion, offset);
            }
        }

        private IEnumerable<string> getChunks(string filePath, int chunkSize, long numberOfChunksInPortion, long offset)
        {
            byte[] chunk = new byte[chunkSize];

            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read))
            {
                fs.Seek(offset, SeekOrigin.Begin);

                for (int i = 0; i < numberOfChunksInPortion; i++)
                {
                    int bytesRead = fs.Read(chunk, 0, chunkSize);
                    if (bytesRead != 0)
                    {
                        string content = Convert.ToBase64String(chunk.Take(bytesRead).ToArray());
                        if (!string.IsNullOrEmpty(content))
                            yield return content;
                    }
                }
            }
        }

        private bool compareHashes(string srcFile, string dstFile)
        {
            string remoteScript = @"
$stream=([IO.StreamReader]'" + dstFile + @"').BaseStream;
try {
    $hash=[Security.Cryptography.HashAlgorithm]::Create('SHA1');
    $bytes=$hash.ComputeHash($stream);
    [BitConverter]::ToString($bytes);
}
finally {$stream.Close();}";
            var results = RunScript(remoteScript);
            if (results.HadErrors)
            {
                Console.WriteLine(results.StdErr);
                return false;
            }
            string remoteSha1Hash = results.StdOut;

            string localSha1Hash;
            var ha = HashAlgorithm.Create("SHA1");
            using (var stream = (new StreamReader(srcFile)).BaseStream)
            {
                localSha1Hash = BitConverter.ToString(ha.ComputeHash(stream));
            }
            return localSha1Hash.Equals(remoteSha1Hash, StringComparison.InvariantCultureIgnoreCase);
        }

        private Runspace OpenRunspace(bool openRunspace = true)
        {
            if (checkCertificateByThumbprint)
            {
                var webRequest = System.Net.WebRequest.CreateHttp(
                    string.Format(
                        "https://{0}:{1}/wsman", hostAddress, winrmPort
                    ));
                try { webRequest.GetResponse(); }
                catch { }
                if (webRequest.ServicePoint.Certificate != null)
                {
                    var winRMEndpointCertificate = new X509Certificate2(webRequest.ServicePoint.Certificate);
                    if (!winRMEndpointCertificate.Thumbprint.Equals(certificateThumbprint, StringComparison.InvariantCultureIgnoreCase))
                    {
                        throw new WinRMCertificateException(
                            "WinRM HTTPS endpoint is using an unexpected certificate. Maybe remote machine is compromised.");
                    }
                }
                else
                {
                    throw new WinRMCertificateException(
                        "Could not obtain WinRM endpoint certificate. Maybe OS configuration is wrong or WinRM HTTPS endpoint is not enabled.");
                }
            }

            Runspace remoteRunspace = null;
            getRunspace(
                string.Format("https://{0}/wsman", hostAddress),
                winrmPort,
                ShellSchema,
                username,
                password,
                ref remoteRunspace
             );
            if (openRunspace)
                remoteRunspace.Open();

            return remoteRunspace;
        }

        private void getRunspace(string uri, int port, string schema, string username, SecureString password, ref Runspace remoteRunspace)
        {
            PSCredential psc = new PSCredential(username, password);
            WSManConnectionInfo rri = new WSManConnectionInfo(new Uri(uri), schema, psc);
            rri.AuthenticationMechanism = AuthenticationMechanism.Basic;
            rri.Port = port;
            rri.ProxyAuthentication = AuthenticationMechanism.Negotiate;
            if (!checkCertificateAsPublic)
            {
                rri.SkipCACheck = true;
                rri.SkipCNCheck = true;
                rri.SkipRevocationCheck = true;
            }
            remoteRunspace = RunspaceFactory.CreateRunspace(rri);
        }

        #endregion
    }

    /// <summary>
    /// Object contains results of running PowerShell script on remote machine.
    /// </summary>
    public class RunScriptOutput
    {
        public bool HadErrors { get; set; }
        public string StdOut { get { return stdOut.ToString().Trim(); } }
        public string StdErr { get { return stdErr.ToString().Trim(); } }

        private StringBuilder stdOut;
        private StringBuilder stdErr;

        public RunScriptOutput()
        {
            HadErrors = false;
            stdErr = new StringBuilder();
            stdOut = new StringBuilder();
        }

        public void AppendStdOut(object message)
        {
            stdOut.AppendLine(message.ToString());
        }

        public void AppendStdErr(object message)
        {
            stdErr.AppendLine(message.ToString());
        }
    }

    public class WinRMException : ApplicationException
    {
        public WinRMException(string message)
            : base(message)
        { }

        public WinRMException(string message, Exception innerException)
            : base(message, innerException)
        { }
    }

    public class WinRMProcessOverlapException : WinRMException
    {
        public WinRMProcessOverlapException(string message)
            : base(message)
        { }

        public WinRMProcessOverlapException(string message, Exception innerException)
            : base(message, innerException)
        { }
    }

    public class WinRMCertificateException : WinRMException
    {
        public WinRMCertificateException(string message)
            : base(message)
        { }
    }
}
