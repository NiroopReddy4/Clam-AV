using System;
using System.Collections.Generic;
using System.Text;
using ClamAVScannerClient.Client;
using ClamAVScannerClient.Interfaces;

namespace ClamAVScannerClient.ImplementationFactory
{
	public class VirusScannerFactory
	{
		public static IScanViruses GetVirusScannerInstance()
		{
			return new ClamAvScanner();
		}
	}
}
