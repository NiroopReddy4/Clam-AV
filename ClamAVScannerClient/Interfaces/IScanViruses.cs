using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using ClamAVScannerClient.Classes;

namespace ClamAVScannerClient.Interfaces
{
	public interface IScanViruses
	{
		Task<ScanResult> ScanFile(string filePath);
		Task<ScanResult> ScanBytes(byte[] bytes);
		Task<ScanResult> ScanStream(Stream stream);
	}
}
