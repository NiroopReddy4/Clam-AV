using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ClamAVScannerClient.Classes;

namespace ClamAVScannerClient.Interfaces
{
	public interface IScanViruses
	{
		ScanResult ScanFile(string filePath);
		ScanResult ScanBytes(byte[] bytes);
		ScanResult ScanStream(Stream stream);
	}
}
