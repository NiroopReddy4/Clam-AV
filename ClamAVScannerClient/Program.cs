using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using ClamAVScannerClient.ImplementationFactory;

namespace ClamAVScannerClient
{
	class Program
	{
		static async Task Main(string[] args)
		{
			
			var timeStart = DateTime.Now;
			Console.WriteLine("Started scanning @ {0}", timeStart);
			var sampleVirus = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
			var scanner = VirusScannerFactory.GetVirusScannerInstance();
			//MemoryStream ms = new MemoryStream();
			//var writer = new StreamWriter(ms);
			//writer.Write(sampleVirus);
			//writer.Flush();
			//ms.Position = 0;

			var bytesArr = Encoding.ASCII.GetBytes(sampleVirus);

			var result = await scanner.ScanBytes(bytesArr);
			var timeEnd = DateTime.Now;
			Console.WriteLine("Ended scanning @ {0}", timeEnd);
			Console.WriteLine("Time Taken to scan {0}",timeEnd - timeStart);
			Console.WriteLine();
			Console.WriteLine("Results:");
			Console.WriteLine("Threat-Detected : {0}", !result.IsVirusFree);
			Console.WriteLine("Message : {0}", result.Message);
			Console.ReadKey();
		}
	}
}
