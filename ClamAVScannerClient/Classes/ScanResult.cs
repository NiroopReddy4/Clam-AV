using System;
using System.Collections.Generic;
using System.Text;

namespace ClamAVScannerClient.Classes
{
	public class ScanResult
	{
		public string Message { get; set; }
		public bool IsVirusFree { get; set; }
	}
}
