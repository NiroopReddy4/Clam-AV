using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
					lock(lockObject)
						return _clamAvClient ?? (_clamAvClient = new ClamClient(server:"http://192.168.99.100"));
				}

				return _clamAvClient;
			}
		}
		
		public ScanResult ScanBytes(byte[] bytes)
		{
			return MapScanResult(ClamAvClient.SendAndScanFileAsync(bytes));
		}

		public ScanResult ScanFile(string filePath)
		{
			return MapScanResult(ClamAvClient.ScanFileOnServerAsync(filePath));
		}

		public ScanResult ScanStream(Stream stream)
		{
			return MapScanResult(ClamAvClient.SendAndScanFileAsync(stream));
		}

		private ScanResult MapScanResult(Task<ClamScanResult> clamAvScanResult)
		{
			var result = new ScanResult();
			switch (clamAvScanResult.Result.Result)
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
					result.Message = "Virus Found " + clamAvScanResult.Result.InfectedFiles.FirstOrDefault().VirusName;
					result.IsVirusFree = false;
					break;
				case ClamScanResults.Error:
					result.Message = string.Format("Virus Scan Error! {0}", clamAvScanResult.Result.RawResult);
					result.IsVirusFree = false;
					break;
				default:
					break;
			}

			return result;
		}
	}
}
