using System;
using System.IO;
using ClamAVScannerClient.ImplementationFactory;

namespace ClamAVScannerClient
{
	class Program
	{
		static void Main(string[] args)
		{
			var sampleVirus = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
			var scanner = VirusScannerFactory.GetVirusScannerInstance();
			MemoryStream ms = new MemoryStream();
			var writer = new StreamWriter(ms);
			writer.Write(sampleVirus);
			writer.Flush();
			ms.Position = 0;

			var result = scanner.ScanStream(ms);
			Console.WriteLine(result);
			Console.ReadKey();
		}
	}
}
