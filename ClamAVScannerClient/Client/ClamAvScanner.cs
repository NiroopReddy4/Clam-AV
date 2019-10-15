using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using ClamAVScannerClient.Classes;
using ClamAVScannerClient.Interfaces;
using nClam;

namespace ClamAVScannerClient.Client
{
	public class ClamAvScanner : IScanViruses
	{
		private ClamClient _clamAvClient;
		private static readonly object lockObject = new object();
		public ClamClient ClamAvClient
		{
			get
			{
				if (_clamAvClient == null)
				{
					lock (lockObject)
					{
						//Telnet Start
						string error = string.Empty;
						try
						{
							//return _clamAvClient ?? (_clamAvClient = new ClamClient(server: "127.0.0.1", port:3310));
							return _clamAvClient ?? (_clamAvClient = new ClamClient(server: "192.168.99.100", port: 3310));
						}
						catch (Exception ex)
						{
							error = ex.ToString();
						}

					}
				}

				return _clamAvClient;
			}
		}

		//public static void Connect3(string host, int port)
		//{
		//	try
		//	{
		//		Socket s = new Socket(AddressFamily.InterNetwork,
		//			SocketType.Stream,
		//			ProtocolType.Tcp);

		//		Console.WriteLine("Establishing Connection to {0}",
		//			host);
		//		s.Connect(host, port);
		//		Console.WriteLine("Connection established");
		//	}
		//	catch (Exception ex)
		//	{
		//		Console.WriteLine(ex.ToString());
		//	}
		//}
		public async Task<ScanResult> ScanBytes(byte[] bytes)
		{
			//Connect3("http://192.168.99.100", 3310);
			var scanResult = await ClamAvClient.SendAndScanFileAsync(bytes);
			var result = MapScanResult(scanResult);
			return result;
		}

		public async Task<ScanResult> ScanFile(string filePath)
		{
			return MapScanResult(await ClamAvClient.ScanFileOnServerAsync(filePath));
		}

		public async Task<ScanResult> ScanStream(Stream stream)
		{
			return MapScanResult(await ClamAvClient.SendAndScanFileAsync(stream));
		}

		private ScanResult MapScanResult(ClamScanResult clamAvScanResult)
		{
			var status = clamAvScanResult.Result;
			var result = new ScanResult();
			switch (clamAvScanResult.Result)
			{
				case ClamScanResults.Unknown:
					result.Message = "Could Not Scan File";
					result.IsVirusFree = false;
					break;
				case ClamScanResults.Clean:
					result.Message = "No Virus File";
					result.IsVirusFree = true;
					break;
				case ClamScanResults.VirusDetected:
					result.Message = "Virus Found " + clamAvScanResult.InfectedFiles.FirstOrDefault().VirusName;
					result.IsVirusFree = false;
					break;
				case ClamScanResults.Error:
					result.Message = string.Format("Virus Scan Error! {0}", clamAvScanResult.RawResult);
					result.IsVirusFree = false;
					break;
				default:
					break;
			}

			return result;
		}
	}
}
