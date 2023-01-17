
// C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.Configuration.Install\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Configuration.Install.dll
// System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v4.0.30319
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Xml;
using Microsoft.Win32;

[assembly: CompilationRelaxations(8)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: ComVisible(false)]
[assembly: CLSCompliant(true)]
[assembly: AssemblyTitle("System.Configuration.Install.dll")]
[assembly: AssemblyDescription("System.Configuration.Install.dll")]
[assembly: AssemblyDefaultAlias("System.Configuration.Install.dll")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyFileVersion("4.8.9037.0")]
[assembly: AssemblyInformationalVersion("4.8.9037.0")]
[assembly: SatelliteContractVersion("4.0.0.0")]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyKeyFile("f:\\dd\\tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblySignatureKey("002400000c800000140100000602000000240000525341310008000001000100613399aff18ef1a2c2514a273a42d9042b72321f1757102df9ebada69923e2738406c21e5b801552ab8d200a65a235e001ac9adc25f2d811eb09496a4c6a59d4619589c69f5baf0c4179a47311d92555cd006acc8b5959f2bd6e10e360c34537a1d266da8085856583c85d81da7f3ec01ed9564c58d93d713cd0172c8e23a10f0239b80c96b07736f5d8b022542a4e74251a5f432824318b3539a5a087f8e53d2f135f9ca47f3bb2e10aff0af0849504fb7cea3ff192dc8de0edad64c68efde34c56d302ad55fd6e80f302d5efcdeae953658d3452561b5f36c542efdbdd9f888538d374cef106acf7d93a4445c3c73cd911f0571aaf3d54da12b11ddec375b3", "a5a866e1ee186f807668209f3b11236ace5e21f117803a3143abb126dd035d7d2f876b6938aaf2ee3414d5420d753621400db44a49c486ce134300a2106adb6bdb433590fef8ad5c43cba82290dc49530effd86523d9483c00f458af46890036b0e2c61d077d7fbac467a506eba29e467a87198b053c749aa2a4d2840c784e6d")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32 | DllImportSearchPath.AssemblyDirectory)]
[assembly: AssemblyVersion("4.0.0.0")]
internal static class FXAssembly
{
	internal const string Version = "4.0.0.0";
}
internal static class ThisAssembly
{
	internal const string Title = "System.Configuration.Install.dll";

	internal const string Description = "System.Configuration.Install.dll";

	internal const string DefaultAlias = "System.Configuration.Install.dll";

	internal const string Copyright = "© Microsoft Corporation.  All rights reserved.";

	internal const string Version = "4.0.0.0";

	internal const string InformationalVersion = "4.8.9037.0";

	internal const string DailyBuildNumberStr = "30319";

	internal const string BuildRevisionStr = "0";

	internal const int DailyBuildNumber = 30319;
}
internal static class AssemblyRef
{
	internal const string EcmaPublicKey = "b77a5c561934e089";

	internal const string EcmaPublicKeyToken = "b77a5c561934e089";

	internal const string EcmaPublicKeyFull = "00000000000000000400000000000000";

	internal const string SilverlightPublicKey = "31bf3856ad364e35";

	internal const string SilverlightPublicKeyToken = "31bf3856ad364e35";

	internal const string SilverlightPublicKeyFull = "0024000004800000940000000602000000240000525341310004000001000100B5FC90E7027F67871E773A8FDE8938C81DD402BA65B9201D60593E96C492651E889CC13F1415EBB53FAC1131AE0BD333C5EE6021672D9718EA31A8AEBD0DA0072F25D87DBA6FC90FFD598ED4DA35E44C398C454307E8E33B8426143DAEC9F596836F97C8F74750E5975C64E2189F45DEF46B2A2B1247ADC3652BF5C308055DA9";

	internal const string SilverlightPlatformPublicKey = "7cec85d7bea7798e";

	internal const string SilverlightPlatformPublicKeyToken = "7cec85d7bea7798e";

	internal const string SilverlightPlatformPublicKeyFull = "00240000048000009400000006020000002400005253413100040000010001008D56C76F9E8649383049F383C44BE0EC204181822A6C31CF5EB7EF486944D032188EA1D3920763712CCB12D75FB77E9811149E6148E5D32FBAAB37611C1878DDC19E20EF135D0CB2CFF2BFEC3D115810C3D9069638FE4BE215DBF795861920E5AB6F7DB2E2CEEF136AC23D5DD2BF031700AEC232F6C6B1C785B4305C123B37AB";

	internal const string PlatformPublicKey = "b77a5c561934e089";

	internal const string PlatformPublicKeyToken = "b77a5c561934e089";

	internal const string PlatformPublicKeyFull = "00000000000000000400000000000000";

	internal const string Mscorlib = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemData = "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemDataOracleClient = "System.Data.OracleClient, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string System = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemCore = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemNumerics = "System.Numerics, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemRuntimeRemoting = "System.Runtime.Remoting, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemThreadingTasksDataflow = "System.Threading.Tasks.Dataflow, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemWindowsForms = "System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemXml = "System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string MicrosoftPublicKey = "b03f5f7f11d50a3a";

	internal const string MicrosoftPublicKeyToken = "b03f5f7f11d50a3a";

	internal const string MicrosoftPublicKeyFull = "002400000480000094000000060200000024000052534131000400000100010007D1FA57C4AED9F0A32E84AA0FAEFD0DE9E8FD6AEC8F87FB03766C834C99921EB23BE79AD9D5DCC1DD9AD236132102900B723CF980957FC4E177108FC607774F29E8320E92EA05ECE4E821C0A5EFE8F1645C4C0C93C1AB99285D622CAA652C1DFAD63D745D6F2DE5F17E5EAF0FC4963D261C8A12436518206DC093344D5AD293";

	internal const string SharedLibPublicKey = "31bf3856ad364e35";

	internal const string SharedLibPublicKeyToken = "31bf3856ad364e35";

	internal const string SharedLibPublicKeyFull = "0024000004800000940000000602000000240000525341310004000001000100B5FC90E7027F67871E773A8FDE8938C81DD402BA65B9201D60593E96C492651E889CC13F1415EBB53FAC1131AE0BD333C5EE6021672D9718EA31A8AEBD0DA0072F25D87DBA6FC90FFD598ED4DA35E44C398C454307E8E33B8426143DAEC9F596836F97C8F74750E5975C64E2189F45DEF46B2A2B1247ADC3652BF5C308055DA9";

	internal const string SystemComponentModelDataAnnotations = "System.ComponentModel.DataAnnotations, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemConfiguration = "System.Configuration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemConfigurationInstall = "System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDeployment = "System.Deployment, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDesign = "System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDirectoryServices = "System.DirectoryServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDrawingDesign = "System.Drawing.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDrawing = "System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemEnterpriseServices = "System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemManagement = "System.Management, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemMessaging = "System.Messaging, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemNetHttp = "System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemNetHttpWebRequest = "System.Net.Http.WebRequest, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemRuntimeSerializationFormattersSoap = "System.Runtime.Serialization.Formatters.Soap, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemRuntimeWindowsRuntime = "System.Runtime.WindowsRuntime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemRuntimeWindowsRuntimeUIXaml = "System.Runtime.WindowsRuntimeUIXaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemSecurity = "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemServiceModelWeb = "System.ServiceModel.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemServiceProcess = "System.ServiceProcess, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWeb = "System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWebAbstractions = "System.Web.Abstractions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemWebDynamicData = "System.Web.DynamicData, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemWebDynamicDataDesign = "System.Web.DynamicData.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemWebEntityDesign = "System.Web.Entity.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemWebExtensions = "System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemWebExtensionsDesign = "System.Web.Extensions.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemWebMobile = "System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWebRegularExpressions = "System.Web.RegularExpressions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWebRouting = "System.Web.Routing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string SystemWebServices = "System.Web.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string WindowsBase = "WindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

	internal const string MicrosoftVisualStudio = "Microsoft.VisualStudio, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftVisualStudioWindowsForms = "Microsoft.VisualStudio.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string VJSharpCodeProvider = "VJSharpCodeProvider, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string ASPBrowserCapsPublicKey = "b7bd7678b977bd8f";

	internal const string ASPBrowserCapsFactory = "ASP.BrowserCapsFactory, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b7bd7678b977bd8f";

	internal const string MicrosoftVSDesigner = "Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftVisualStudioWeb = "Microsoft.VisualStudio.Web, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftWebDesign = "Microsoft.Web.Design.Client, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftVSDesignerMobile = "Microsoft.VSDesigner.Mobile, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftJScript = "Microsoft.JScript, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
}
namespace System
{
	internal static class ExternDll
	{
		public const string Activeds = "activeds.dll";

		public const string Advapi32 = "advapi32.dll";

		public const string Comctl32 = "comctl32.dll";

		public const string Comdlg32 = "comdlg32.dll";

		public const string Gdi32 = "gdi32.dll";

		public const string Gdiplus = "gdiplus.dll";

		public const string Hhctrl = "hhctrl.ocx";

		public const string Imm32 = "imm32.dll";

		public const string Kernel32 = "kernel32.dll";

		public const string Loadperf = "Loadperf.dll";

		public const string Mscoree = "mscoree.dll";

		public const string Clr = "clr.dll";

		public const string Msi = "msi.dll";

		public const string Mqrt = "mqrt.dll";

		public const string Ntdll = "ntdll.dll";

		public const string Ole32 = "ole32.dll";

		public const string Oleacc = "oleacc.dll";

		public const string Oleaut32 = "oleaut32.dll";

		public const string Olepro32 = "olepro32.dll";

		public const string PerfCounter = "perfcounter.dll";

		public const string Powrprof = "Powrprof.dll";

		public const string Psapi = "psapi.dll";

		public const string Shell32 = "shell32.dll";

		public const string User32 = "user32.dll";

		public const string Uxtheme = "uxtheme.dll";

		public const string WinMM = "winmm.dll";

		public const string Winspool = "winspool.drv";

		public const string Wtsapi32 = "wtsapi32.dll";

		public const string Version = "version.dll";

		public const string Vsassert = "vsassert.dll";

		public const string Fxassert = "Fxassert.dll";

		public const string Shlwapi = "shlwapi.dll";

		public const string Crypt32 = "crypt32.dll";

		public const string ShCore = "SHCore.dll";

		public const string Wldp = "wldp.dll";

		internal const string Odbc32 = "odbc32.dll";

		internal const string SNI = "System.Data.dll";

		internal const string OciDll = "oci.dll";

		internal const string OraMtsDll = "oramts.dll";

		internal const string UiaCore = "UIAutomationCore.dll";
	}
	internal static class HResults
	{
		internal const int Configuration = -2146232062;

		internal const int Xml = -2146232000;

		internal const int XmlSchema = -2146231999;

		internal const int XmlXslt = -2146231998;

		internal const int XmlXPath = -2146231997;

		internal const int Data = -2146232032;

		internal const int DataDeletedRowInaccessible = -2146232031;

		internal const int DataDuplicateName = -2146232030;

		internal const int DataInRowChangingEvent = -2146232029;

		internal const int DataInvalidConstraint = -2146232028;

		internal const int DataMissingPrimaryKey = -2146232027;

		internal const int DataNoNullAllowed = -2146232026;

		internal const int DataReadOnly = -2146232025;

		internal const int DataRowNotInTable = -2146232024;

		internal const int DataVersionNotFound = -2146232023;

		internal const int DataConstraint = -2146232022;

		internal const int StrongTyping = -2146232021;

		internal const int SqlType = -2146232016;

		internal const int SqlNullValue = -2146232015;

		internal const int SqlTruncate = -2146232014;

		internal const int AdapterMapping = -2146232013;

		internal const int DataAdapter = -2146232012;

		internal const int DBConcurrency = -2146232011;

		internal const int OperationAborted = -2146232010;

		internal const int InvalidUdt = -2146232009;

		internal const int Metadata = -2146232007;

		internal const int InvalidQuery = -2146232006;

		internal const int CommandCompilation = -2146232005;

		internal const int CommandExecution = -2146232004;

		internal const int SqlException = -2146232060;

		internal const int OdbcException = -2146232009;

		internal const int OracleException = -2146232008;

		internal const int ConnectionPlanException = -2146232003;

		internal const int NteBadKeySet = -2146893802;

		internal const int Win32AccessDenied = -2147024891;

		internal const int Win32InvalidHandle = -2147024890;

		internal const int License = -2146232063;

		internal const int InternalBufferOverflow = -2146232059;

		internal const int ServiceControllerTimeout = -2146232058;

		internal const int Install = -2146232057;

		internal const int EFail = -2147467259;
	}
}
namespace System.Diagnostics
{
	/// <summary>Allows you to install and configure an event log that your application reads from or writes to when running.</summary>
	public class EventLogInstaller : ComponentInstaller
	{
		private EventSourceCreationData sourceData = new EventSourceCreationData(null, null);

		private UninstallAction uninstallAction;

		/// <summary>Gets or sets the path of the resource file that contains category strings for the source.</summary>
		/// <returns>The path of the category resource file. The default is an empty string ("").</returns>
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[Editor("System.Windows.Forms.Design.FileNameEditor, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ComVisible(false)]
		[ResDescription("Desc_CategoryResourceFile")]
		public string CategoryResourceFile
		{
			get
			{
				return sourceData.CategoryResourceFile;
			}
			set
			{
				sourceData.CategoryResourceFile = value;
			}
		}

		/// <summary>Gets or sets the number of categories in the category resource file.</summary>
		/// <returns>The number of categories in the category resource file. The default value is zero.</returns>
		[ComVisible(false)]
		[ResDescription("Desc_CategoryCount")]
		public int CategoryCount
		{
			get
			{
				return sourceData.CategoryCount;
			}
			set
			{
				sourceData.CategoryCount = value;
			}
		}

		/// <summary>Gets or sets the name of the log to set the source to.</summary>
		/// <returns>The name of the log. This can be Application, System, or a custom log name. The default is an empty string ("").</returns>
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ResDescription("Desc_Log")]
		public string Log
		{
			get
			{
				if (sourceData.LogName == null && sourceData.Source != null)
				{
					sourceData.LogName = EventLog.LogNameFromSourceName(sourceData.Source, ".");
				}
				return sourceData.LogName;
			}
			set
			{
				sourceData.LogName = value;
			}
		}

		/// <summary>Gets or sets the path of the resource file that contains message formatting strings for the source.</summary>
		/// <returns>The path of the message resource file. The default is an empty string ("").</returns>
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[Editor("System.Windows.Forms.Design.FileNameEditor, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ComVisible(false)]
		[ResDescription("Desc_MessageResourceFile")]
		public string MessageResourceFile
		{
			get
			{
				return sourceData.MessageResourceFile;
			}
			set
			{
				sourceData.MessageResourceFile = value;
			}
		}

		/// <summary>Gets or sets the path of the resource file that contains message parameter strings for the source.</summary>
		/// <returns>The path of the message parameter resource file. The default is an empty string ("").</returns>
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[Editor("System.Windows.Forms.Design.FileNameEditor, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ComVisible(false)]
		[ResDescription("Desc_ParameterResourceFile")]
		public string ParameterResourceFile
		{
			get
			{
				return sourceData.ParameterResourceFile;
			}
			set
			{
				sourceData.ParameterResourceFile = value;
			}
		}

		/// <summary>Gets or sets the source name to register with the log.</summary>
		/// <returns>The name to register with the event log as a source of entries. The default is an empty string ("").</returns>
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ResDescription("Desc_Source")]
		public string Source
		{
			get
			{
				return sourceData.Source;
			}
			set
			{
				sourceData.Source = value;
			}
		}

		/// <summary>Gets or sets a value that indicates whether the Installutil.exe (Installer Tool) should remove the event log or leave it in its installed state at uninstall time.</summary>
		/// <returns>One of the <see cref="T:System.Configuration.Install.UninstallAction" /> values that indicates what state to leave the event log in when the <see cref="T:System.Diagnostics.EventLog" /> is uninstalled. The default is <see langword="Remove" />.</returns>
		/// <exception cref="T:System.ComponentModel.InvalidEnumArgumentException">
		///   <see cref="P:System.Diagnostics.EventLogInstaller.UninstallAction" /> contains an invalid value. The only valid values for this property are <see langword="Remove" /> and <see langword="NoAction" />.</exception>
		[DefaultValue(UninstallAction.Remove)]
		[ResDescription("Desc_UninstallAction")]
		public UninstallAction UninstallAction
		{
			get
			{
				return uninstallAction;
			}
			set
			{
				if (!Enum.IsDefined(typeof(UninstallAction), value))
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(UninstallAction));
				}
				uninstallAction = value;
			}
		}

		/// <summary>Copies the property values of an <see cref="T:System.Diagnostics.EventLog" /> component that are required at installation time for an event log.</summary>
		/// <param name="component">An <see cref="T:System.ComponentModel.IComponent" /> to use as a template for the <see cref="T:System.Diagnostics.EventLogInstaller" />.</param>
		/// <exception cref="T:System.ArgumentException">The specified component is not an <see cref="T:System.Diagnostics.EventLog" />.  
		///  -or-  
		///  The <see cref="P:System.Diagnostics.EventLog.Log" /> or <see cref="P:System.Diagnostics.EventLog.Source" /> property of the specified component is either <see langword="null" /> or empty.</exception>
		public override void CopyFromComponent(IComponent component)
		{
			if (!(component is EventLog eventLog))
			{
				throw new ArgumentException(Res.GetString("NotAnEventLog"));
			}
			if (eventLog.Log == null || eventLog.Log == string.Empty || eventLog.Source == null || eventLog.Source == string.Empty)
			{
				throw new ArgumentException(Res.GetString("IncompleteEventLog"));
			}
			Log = eventLog.Log;
			Source = eventLog.Source;
		}

		/// <summary>Performs the installation and writes event log information to the registry.</summary>
		/// <param name="stateSaver">An <see cref="T:System.Collections.IDictionary" /> used to save information needed to perform a rollback or uninstall operation.</param>
		/// <exception cref="T:System.PlatformNotSupportedException">The platform the installer is trying to use is not Windows NT 4.0 or later.</exception>
		/// <exception cref="T:System.ArgumentException">The name specified in the <see cref="P:System.Diagnostics.EventLogInstaller.Source" /> property is already registered for a different event log.</exception>
		public override void Install(IDictionary stateSaver)
		{
			base.Install(stateSaver);
			base.Context.LogMessage(Res.GetString("CreatingEventLog", Source, Log));
			if (Environment.OSVersion.Platform != PlatformID.Win32NT)
			{
				throw new PlatformNotSupportedException(Res.GetString("WinNTRequired"));
			}
			stateSaver["baseInstalledAndPlatformOK"] = true;
			bool flag = EventLog.Exists(Log, ".");
			stateSaver["logExists"] = flag;
			bool flag2 = EventLog.SourceExists(Source, ".");
			stateSaver["alreadyRegistered"] = flag2;
			if (flag2)
			{
				string text = EventLog.LogNameFromSourceName(Source, ".");
				if (text == Log)
				{
					return;
				}
			}
			EventLog.CreateEventSource(sourceData);
		}

		/// <summary>Determines whether an installer and another specified installer refer to the same source.</summary>
		/// <param name="otherInstaller">The installer to compare.</param>
		/// <returns>
		///   <see langword="true" /> if this installer and the installer specified by the <paramref name="otherInstaller" /> parameter would install or uninstall the same source; otherwise, <see langword="false" />.</returns>
		public override bool IsEquivalentInstaller(ComponentInstaller otherInstaller)
		{
			if (!(otherInstaller is EventLogInstaller eventLogInstaller))
			{
				return false;
			}
			return eventLogInstaller.Source == Source;
		}

		/// <summary>Restores the computer to the state it was in before the installation by rolling back the event log information that the installation procedure wrote to the registry.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the pre-installation state of the computer.</param>
		public override void Rollback(IDictionary savedState)
		{
			base.Rollback(savedState);
			base.Context.LogMessage(Res.GetString("RestoringEventLog", Source));
			if (savedState["baseInstalledAndPlatformOK"] == null)
			{
				return;
			}
			if (!(bool)savedState["logExists"])
			{
				EventLog.Delete(Log, ".");
				return;
			}
			object obj = savedState["alreadyRegistered"];
			bool flag = obj != null && (bool)obj;
			if (!flag && EventLog.SourceExists(Source, "."))
			{
				EventLog.DeleteEventSource(Source, ".");
			}
		}

		/// <summary>Removes an installation by removing event log information from the registry.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the pre-installation state of the computer.</param>
		public override void Uninstall(IDictionary savedState)
		{
			base.Uninstall(savedState);
			if (UninstallAction != 0)
			{
				return;
			}
			base.Context.LogMessage(Res.GetString("RemovingEventLog", Source));
			if (EventLog.SourceExists(Source, "."))
			{
				if (string.Compare(Log, Source, StringComparison.OrdinalIgnoreCase) != 0)
				{
					EventLog.DeleteEventSource(Source, ".");
				}
			}
			else
			{
				base.Context.LogMessage(Res.GetString("LocalSourceNotRegisteredWarning", Source));
			}
			RegistryKey registryKey = Registry.LocalMachine;
			RegistryKey registryKey2 = null;
			try
			{
				registryKey = registryKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\EventLog", writable: false);
				if (registryKey != null)
				{
					registryKey2 = registryKey.OpenSubKey(Log, writable: false);
				}
				if (registryKey2 != null)
				{
					string[] subKeyNames = registryKey2.GetSubKeyNames();
					if (subKeyNames == null || subKeyNames.Length == 0 || (subKeyNames.Length == 1 && string.Compare(subKeyNames[0], Log, StringComparison.OrdinalIgnoreCase) == 0))
					{
						base.Context.LogMessage(Res.GetString("DeletingEventLog", Log));
						EventLog.Delete(Log, ".");
					}
				}
			}
			finally
			{
				registryKey?.Close();
				registryKey2?.Close();
			}
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Diagnostics.EventLogInstaller" /> class.</summary>
		public EventLogInstaller()
		{
		}
	}
	/// <summary>Specifies an installer for the <see cref="T:System.Diagnostics.PerformanceCounter" /> component.</summary>
	public class PerformanceCounterInstaller : ComponentInstaller
	{
		private const string ServicePath = "SYSTEM\\CurrentControlSet\\Services";

		private const string PerfShimName = "netfxperf.dll";

		private const string PerfShimFullNameSuffix = "\\netfxperf.dll";

		private string categoryName = string.Empty;

		private CounterCreationDataCollection counters = new CounterCreationDataCollection();

		private string categoryHelp = string.Empty;

		private UninstallAction uninstallAction;

		private PerformanceCounterCategoryType categoryType = PerformanceCounterCategoryType.Unknown;

		/// <summary>Gets or sets the performance category name for the performance counter.</summary>
		/// <returns>The performance category name for the performance counter.</returns>
		/// <exception cref="T:System.ArgumentNullException">The value is set to <see langword="null" />.</exception>
		/// <exception cref="T:System.ArgumentException">The value is not a valid category name.</exception>
		[DefaultValue("")]
		[ResDescription("PCCategoryName")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public string CategoryName
		{
			get
			{
				return categoryName;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				CheckValidCategory(value);
				categoryName = value;
			}
		}

		/// <summary>Gets or sets the descriptive message for the performance counter.</summary>
		/// <returns>The descriptive message for the performance counter.</returns>
		/// <exception cref="T:System.ArgumentNullException">The value is set to <see langword="null" />.</exception>
		[DefaultValue("")]
		[ResDescription("PCI_CategoryHelp")]
		public string CategoryHelp
		{
			get
			{
				return categoryHelp;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				categoryHelp = value;
			}
		}

		/// <summary>Gets or sets the performance counter category type.</summary>
		/// <returns>One of the <see cref="T:System.Diagnostics.PerformanceCounterCategoryType" /> values.</returns>
		/// <exception cref="T:System.ComponentModel.InvalidEnumArgumentException">The value is not a <see cref="T:System.Diagnostics.PerformanceCounterCategoryType" />.</exception>
		[DefaultValue(PerformanceCounterCategoryType.Unknown)]
		[ResDescription("PCI_IsMultiInstance")]
		[ComVisible(false)]
		public PerformanceCounterCategoryType CategoryType
		{
			get
			{
				return categoryType;
			}
			set
			{
				if (value < PerformanceCounterCategoryType.Unknown || value > PerformanceCounterCategoryType.MultiInstance)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(PerformanceCounterCategoryType));
				}
				categoryType = value;
			}
		}

		/// <summary>Gets a collection of data that pertains to the counters to install.</summary>
		/// <returns>A <see cref="T:System.Diagnostics.CounterCreationDataCollection" /> that contains the names, help messages, and types of the counters to install.</returns>
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Content)]
		[ResDescription("PCI_Counters")]
		public CounterCreationDataCollection Counters => counters;

		/// <summary>Gets a value that indicates whether the performance counter should be removed at uninstall time.</summary>
		/// <returns>One of the <see cref="T:System.Configuration.Install.UninstallAction" /> values. The default is <see langword="Remove" />.</returns>
		/// <exception cref="T:System.ComponentModel.InvalidEnumArgumentException">The value is not an <see cref="T:System.Configuration.Install.UninstallAction" />.</exception>
		[DefaultValue(UninstallAction.Remove)]
		[ResDescription("PCI_UninstallAction")]
		public UninstallAction UninstallAction
		{
			get
			{
				return uninstallAction;
			}
			set
			{
				if (!Enum.IsDefined(typeof(UninstallAction), value))
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(UninstallAction));
				}
				uninstallAction = value;
			}
		}

		/// <summary>Copies all the properties from the specified component that are required at install time for a performance counter.</summary>
		/// <param name="component">The component to copy from.</param>
		/// <exception cref="T:System.ArgumentException">The specified component is not a <see cref="T:System.Diagnostics.PerformanceCounter" />.  
		///  -or-  
		///  The specified <see cref="T:System.Diagnostics.PerformanceCounter" /> is incomplete.  
		///  -or-  
		///  Multiple counters in different categories are trying to be installed.</exception>
		public override void CopyFromComponent(IComponent component)
		{
			if (!(component is PerformanceCounter))
			{
				throw new ArgumentException(Res.GetString("NotAPerformanceCounter"));
			}
			PerformanceCounter performanceCounter = (PerformanceCounter)component;
			if (performanceCounter.CategoryName == null || performanceCounter.CategoryName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("IncompletePerformanceCounter"));
			}
			if (!CategoryName.Equals(performanceCounter.CategoryName) && !string.IsNullOrEmpty(CategoryName))
			{
				throw new ArgumentException(Res.GetString("NewCategory"));
			}
			PerformanceCounterType counterType = PerformanceCounterType.NumberOfItems32;
			string counterHelp = string.Empty;
			if (string.IsNullOrEmpty(CategoryName))
			{
				CategoryName = performanceCounter.CategoryName;
			}
			if (Environment.OSVersion.Platform == PlatformID.Win32NT)
			{
				string machineName = performanceCounter.MachineName;
				if (PerformanceCounterCategory.Exists(CategoryName, machineName))
				{
					string name = "SYSTEM\\CurrentControlSet\\Services\\" + CategoryName + "\\Performance";
					RegistryKey registryKey = null;
					try
					{
						if (machineName == "." || string.Compare(machineName, SystemInformation.ComputerName, StringComparison.OrdinalIgnoreCase) == 0)
						{
							registryKey = Registry.LocalMachine.OpenSubKey(name);
						}
						else
						{
							RegistryKey registryKey2 = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, "\\\\" + machineName);
							registryKey = registryKey2.OpenSubKey(name);
						}
						if (registryKey == null)
						{
							throw new ArgumentException(Res.GetString("NotCustomPerformanceCategory"));
						}
						object value = registryKey.GetValue("Library", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
						if (value == null || !(value is string) || (string.Compare((string)value, "netfxperf.dll", StringComparison.OrdinalIgnoreCase) != 0 && !((string)value).EndsWith("\\netfxperf.dll", StringComparison.OrdinalIgnoreCase)))
						{
							throw new ArgumentException(Res.GetString("NotCustomPerformanceCategory"));
						}
						PerformanceCounterCategory performanceCounterCategory = new PerformanceCounterCategory(CategoryName, machineName);
						CategoryHelp = performanceCounterCategory.CategoryHelp;
						if (performanceCounterCategory.CounterExists(performanceCounter.CounterName))
						{
							counterType = performanceCounter.CounterType;
							counterHelp = performanceCounter.CounterHelp;
						}
						CategoryType = performanceCounterCategory.CategoryType;
					}
					finally
					{
						registryKey?.Close();
					}
				}
			}
			CounterCreationData value2 = new CounterCreationData(performanceCounter.CounterName, counterHelp, counterType);
			Counters.Add(value2);
		}

		private void DoRollback(IDictionary state)
		{
			base.Context.LogMessage(Res.GetString("RestoringPerformanceCounter", CategoryName));
			using RegistryKey registryKey2 = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services", writable: true);
			RegistryKey registryKey = null;
			if ((bool)state["categoryKeyExisted"])
			{
				registryKey = registryKey2.OpenSubKey(CategoryName, writable: true);
				if (registryKey == null)
				{
					registryKey = registryKey2.CreateSubKey(CategoryName);
				}
				registryKey.DeleteSubKeyTree("Performance");
				SerializableRegistryKey serializableRegistryKey = (SerializableRegistryKey)state["performanceKeyData"];
				if (serializableRegistryKey != null)
				{
					RegistryKey registryKey3 = registryKey.CreateSubKey("Performance");
					serializableRegistryKey.CopyToRegistry(registryKey3);
					registryKey3.Close();
				}
				registryKey.DeleteSubKeyTree("Linkage");
				SerializableRegistryKey serializableRegistryKey2 = (SerializableRegistryKey)state["linkageKeyData"];
				if (serializableRegistryKey2 != null)
				{
					RegistryKey registryKey4 = registryKey.CreateSubKey("Linkage");
					serializableRegistryKey2.CopyToRegistry(registryKey4);
					registryKey4.Close();
				}
			}
			else
			{
				registryKey = registryKey2.OpenSubKey(CategoryName);
				if (registryKey != null)
				{
					registryKey.Close();
					registryKey = null;
					registryKey2.DeleteSubKeyTree(CategoryName);
				}
			}
			registryKey?.Close();
		}

		/// <summary>Performs the installation.</summary>
		/// <param name="stateSaver">An <see cref="T:System.Collections.IDictionary" /> that is used to save the information needed to perform a commit, rollback, or uninstall operation.</param>
		public override void Install(IDictionary stateSaver)
		{
			base.Install(stateSaver);
			base.Context.LogMessage(Res.GetString("CreatingPerformanceCounter", CategoryName));
			RegistryKey registryKey = null;
			RegistryKey registryKey2 = null;
			RegistryKey registryKey3 = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services", writable: true);
			stateSaver["categoryKeyExisted"] = false;
			try
			{
				if (registryKey3 != null)
				{
					registryKey = registryKey3.OpenSubKey(CategoryName, writable: true);
					if (registryKey != null)
					{
						stateSaver["categoryKeyExisted"] = true;
						registryKey2 = registryKey.OpenSubKey("Performance");
						if (registryKey2 != null)
						{
							stateSaver["performanceKeyData"] = new SerializableRegistryKey(registryKey2);
							registryKey2.Close();
							registryKey.DeleteSubKeyTree("Performance");
						}
						registryKey2 = registryKey.OpenSubKey("Linkage");
						if (registryKey2 != null)
						{
							stateSaver["linkageKeyData"] = new SerializableRegistryKey(registryKey2);
							registryKey2.Close();
							registryKey.DeleteSubKeyTree("Linkage");
						}
					}
				}
			}
			finally
			{
				registryKey?.Close();
				registryKey3?.Close();
			}
			if (PerformanceCounterCategory.Exists(CategoryName))
			{
				PerformanceCounterCategory.Delete(CategoryName);
			}
			PerformanceCounterCategory.Create(CategoryName, CategoryHelp, categoryType, Counters);
		}

		/// <summary>Restores the computer to the state it was in before the installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the pre-installation state of the computer.</param>
		public override void Rollback(IDictionary savedState)
		{
			base.Rollback(savedState);
			DoRollback(savedState);
		}

		/// <summary>Removes an installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the post-installation state of the computer.</param>
		public override void Uninstall(IDictionary savedState)
		{
			base.Uninstall(savedState);
			if (UninstallAction == UninstallAction.Remove)
			{
				base.Context.LogMessage(Res.GetString("RemovingPerformanceCounter", CategoryName));
				PerformanceCounterCategory.Delete(CategoryName);
			}
		}

		internal static void CheckValidCategory(string categoryName)
		{
			if (categoryName == null)
			{
				throw new ArgumentNullException("categoryName");
			}
			if (!CheckValidId(categoryName))
			{
				throw new ArgumentException(Res.GetString("PerfInvalidCategoryName", 1, 253));
			}
		}

		internal static bool CheckValidId(string id)
		{
			if (id.Length == 0 || id.Length > 253)
			{
				return false;
			}
			for (int i = 0; i < id.Length; i++)
			{
				char c = id[i];
				if ((i == 0 || i == id.Length - 1) && c == ' ')
				{
					return false;
				}
				if (c == '"')
				{
					return false;
				}
				if (char.IsControl(c))
				{
					return false;
				}
			}
			return true;
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Diagnostics.PerformanceCounterInstaller" /> class.</summary>
		public PerformanceCounterInstaller()
		{
		}
	}
	[Serializable]
	internal class SerializableRegistryKey
	{
		public string[] ValueNames;

		public object[] Values;

		[OptionalField(VersionAdded = 2)]
		public RegistryValueKind[] ValueKinds;

		public string[] KeyNames;

		public SerializableRegistryKey[] Keys;

		public SerializableRegistryKey(RegistryKey keyToSave)
		{
			CopyFromRegistry(keyToSave);
		}

		public void CopyFromRegistry(RegistryKey keyToSave)
		{
			if (keyToSave == null)
			{
				throw new ArgumentNullException("keyToSave");
			}
			ValueNames = keyToSave.GetValueNames();
			if (ValueNames == null)
			{
				ValueNames = new string[0];
			}
			Values = new object[ValueNames.Length];
			ValueKinds = new RegistryValueKind[ValueNames.Length];
			for (int i = 0; i < ValueNames.Length; i++)
			{
				Values[i] = keyToSave.GetValue(ValueNames[i], null, RegistryValueOptions.DoNotExpandEnvironmentNames);
				ValueKinds[i] = keyToSave.GetValueKind(ValueNames[i]);
			}
			KeyNames = keyToSave.GetSubKeyNames();
			if (KeyNames == null)
			{
				KeyNames = new string[0];
			}
			Keys = new SerializableRegistryKey[KeyNames.Length];
			for (int j = 0; j < KeyNames.Length; j++)
			{
				Keys[j] = new SerializableRegistryKey(keyToSave.OpenSubKey(KeyNames[j]));
			}
		}

		public void CopyToRegistry(RegistryKey baseKey)
		{
			if (baseKey == null)
			{
				throw new ArgumentNullException("baseKey");
			}
			if (Values != null)
			{
				for (int i = 0; i < Values.Length; i++)
				{
					if (ValueKinds != null)
					{
						baseKey.SetValue(ValueNames[i], Values[i], ValueKinds[i]);
					}
					else
					{
						baseKey.SetValue(ValueNames[i], Values[i]);
					}
				}
			}
			if (Keys != null)
			{
				for (int j = 0; j < Keys.Length; j++)
				{
					RegistryKey baseKey2 = baseKey.CreateSubKey(KeyNames[j]);
					Keys[j].CopyToRegistry(baseKey2);
				}
			}
		}
	}
}
namespace System.Configuration.Install
{
	/// <summary>Loads an assembly, and runs all the installers in it.</summary>
	public class AssemblyInstaller : Installer
	{
		private Assembly assembly;

		private string[] commandLine;

		private bool useNewContext;

		private static bool helpPrinted;

		private bool initialized;

		/// <summary>Gets or sets the assembly to install.</summary>
		/// <returns>An <see cref="T:System.Reflection.Assembly" /> that defines the assembly to install.</returns>
		/// <exception cref="T:System.ArgumentNullException">The property value is <see langword="null" />.</exception>
		[ResDescription("Desc_AssemblyInstaller_Assembly")]
		public Assembly Assembly
		{
			get
			{
				return assembly;
			}
			set
			{
				assembly = value;
			}
		}

		/// <summary>Gets or sets the command line to use when creating a new <see cref="T:System.Configuration.Install.InstallContext" /> object for the assembly's installation.</summary>
		/// <returns>An array of type <see cref="T:System.String" /> that represents the command line to use when creating a new <see cref="T:System.Configuration.Install.InstallContext" /> object for the assembly's installation.</returns>
		[ResDescription("Desc_AssemblyInstaller_CommandLine")]
		public string[] CommandLine
		{
			get
			{
				return commandLine;
			}
			set
			{
				commandLine = value;
			}
		}

		/// <summary>Gets the help text for all the installers in the installer collection.</summary>
		/// <returns>The help text for all the installers in the installer collection, including the description of what each installer does and the command-line options (for the installation program) that can be passed to and understood by each installer.</returns>
		public override string HelpText
		{
			get
			{
				if (Path != null && Path.Length > 0)
				{
					base.Context = new InstallContext(null, new string[0]);
					if (!initialized)
					{
						InitializeFromAssembly();
					}
				}
				if (helpPrinted)
				{
					return base.HelpText;
				}
				helpPrinted = true;
				return Res.GetString("InstallAssemblyHelp") + "\r\n" + base.HelpText;
			}
		}

		/// <summary>Gets or sets the path of the assembly to install.</summary>
		/// <returns>The path of the assembly to install.</returns>
		[ResDescription("Desc_AssemblyInstaller_Path")]
		public string Path
		{
			get
			{
				if (assembly == null)
				{
					return null;
				}
				return assembly.Location;
			}
			set
			{
				if (value == null)
				{
					assembly = null;
				}
				assembly = Assembly.LoadFrom(value);
			}
		}

		/// <summary>Gets or sets a value indicating whether to create a new <see cref="T:System.Configuration.Install.InstallContext" /> object for the assembly's installation.</summary>
		/// <returns>
		///   <see langword="true" /> if a new <see cref="T:System.Configuration.Install.InstallContext" /> object should be created for the assembly's installation; otherwise, <see langword="false" />. The default is <see langword="true" />.</returns>
		[ResDescription("Desc_AssemblyInstaller_UseNewContext")]
		public bool UseNewContext
		{
			get
			{
				return useNewContext;
			}
			set
			{
				useNewContext = value;
			}
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.AssemblyInstaller" /> class.</summary>
		public AssemblyInstaller()
		{
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.AssemblyInstaller" /> class, and specifies both the file name of the assembly to install and the command line to use when creating a new <see cref="T:System.Configuration.Install.InstallContext" /> object for the assembly's installation.</summary>
		/// <param name="fileName">The file name of the assembly to install.</param>
		/// <param name="commandLine">The command line to use when creating a new <see cref="T:System.Configuration.Install.InstallContext" /> object for the assembly's installation. Can be a null value.</param>
		public AssemblyInstaller(string fileName, string[] commandLine)
		{
			Path = System.IO.Path.GetFullPath(fileName);
			this.commandLine = commandLine;
			useNewContext = true;
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.AssemblyInstaller" /> class, and specifies both the assembly to install and the command line to use when creating a new <see cref="T:System.Configuration.Install.InstallContext" /> object.</summary>
		/// <param name="assembly">The <see cref="T:System.Reflection.Assembly" /> to install.</param>
		/// <param name="commandLine">The command line to use when creating a new <see cref="T:System.Configuration.Install.InstallContext" /> object for the assembly's installation. Can be a null value.</param>
		public AssemblyInstaller(Assembly assembly, string[] commandLine)
		{
			Assembly = assembly;
			this.commandLine = commandLine;
			useNewContext = true;
		}

		/// <summary>Checks to see if the specified assembly can be installed.</summary>
		/// <param name="assemblyName">The assembly in which to search for installers.</param>
		/// <exception cref="T:System.Exception">The specified assembly cannot be installed.</exception>
		public static void CheckIfInstallable(string assemblyName)
		{
			AssemblyInstaller assemblyInstaller = new AssemblyInstaller();
			assemblyInstaller.UseNewContext = false;
			assemblyInstaller.Path = assemblyName;
			assemblyInstaller.CommandLine = new string[0];
			assemblyInstaller.Context = new InstallContext(null, new string[0]);
			assemblyInstaller.InitializeFromAssembly();
			if (assemblyInstaller.Installers.Count == 0)
			{
				throw new InvalidOperationException(Res.GetString("InstallNoPublicInstallers", assemblyName));
			}
		}

		private InstallContext CreateAssemblyContext()
		{
			InstallContext installContext = new InstallContext(System.IO.Path.ChangeExtension(Path, ".InstallLog"), CommandLine);
			if (base.Context != null)
			{
				installContext.Parameters["logtoconsole"] = base.Context.Parameters["logtoconsole"];
			}
			installContext.Parameters["assemblypath"] = Path;
			return installContext;
		}

		private void InitializeFromAssembly()
		{
			Type[] array = null;
			try
			{
				array = GetInstallerTypes(assembly);
			}
			catch (Exception ex)
			{
				base.Context.LogMessage(Res.GetString("InstallException", Path));
				Installer.LogException(ex, base.Context);
				base.Context.LogMessage(Res.GetString("InstallAbort", Path));
				throw new InvalidOperationException(Res.GetString("InstallNoInstallerTypes", Path), ex);
			}
			if (array == null || array.Length == 0)
			{
				base.Context.LogMessage(Res.GetString("InstallNoPublicInstallers", Path));
				return;
			}
			for (int i = 0; i < array.Length; i++)
			{
				try
				{
					Installer value = (Installer)Activator.CreateInstance(array[i], BindingFlags.Instance | BindingFlags.Public | BindingFlags.CreateInstance, null, new object[0], null);
					base.Installers.Add(value);
				}
				catch (Exception ex2)
				{
					base.Context.LogMessage(Res.GetString("InstallCannotCreateInstance", array[i].FullName));
					Installer.LogException(ex2, base.Context);
					throw new InvalidOperationException(Res.GetString("InstallCannotCreateInstance", array[i].FullName), ex2);
				}
			}
			initialized = true;
		}

		private string GetInstallStatePath(string assemblyPath)
		{
			string text = base.Context.Parameters["InstallStateDir"];
			assemblyPath = System.IO.Path.ChangeExtension(assemblyPath, ".InstallState");
			if (!string.IsNullOrEmpty(text))
			{
				return System.IO.Path.Combine(text, System.IO.Path.GetFileName(assemblyPath));
			}
			return assemblyPath;
		}

		/// <summary>Completes the installation transaction.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after all the installers in the installer collection have run.</param>
		/// <exception cref="T:System.ArgumentException">The <paramref name="savedState" /> parameter is <see langword="null" />.  
		///  -or-  
		///  The saved-state <see cref="T:System.Collections.IDictionary" /> might have been corrupted.  
		///  -or-  
		///  A file could not be found.</exception>
		/// <exception cref="T:System.Exception">An error occurred in the <see cref="E:System.Configuration.Install.Installer.Committing" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An error occurred in the <see cref="E:System.Configuration.Install.Installer.Committed" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An exception occurred during the <see cref="M:System.Configuration.Install.AssemblyInstaller.Commit(System.Collections.IDictionary)" /> phase of the installation. The exception is ignored and the installation continues. However, the application might not function correctly after installation completes.  
		///  -or-  
		///  Installer types were not found in one of the assemblies.  
		///  -or-  
		///  An instance of one of the installer types could not be created.</exception>
		/// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred during the <see cref="M:System.Configuration.Install.AssemblyInstaller.Commit(System.Collections.IDictionary)" /> phase of the installation. The exception is ignored and the installation continues. However, the application might not function correctly after installation completes.</exception>
		public override void Commit(IDictionary savedState)
		{
			PrintStartText(Res.GetString("InstallActivityCommitting"));
			if (!initialized)
			{
				InitializeFromAssembly();
			}
			string installStatePath = GetInstallStatePath(Path);
			FileStream fileStream = new FileStream(installStatePath, FileMode.Open, FileAccess.Read);
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			xmlReaderSettings.CheckCharacters = false;
			xmlReaderSettings.CloseInput = false;
			XmlReader xmlReader = null;
			if (fileStream != null)
			{
				xmlReader = XmlReader.Create(fileStream, xmlReaderSettings);
			}
			try
			{
				if (xmlReader != null)
				{
					NetDataContractSerializer netDataContractSerializer = new NetDataContractSerializer();
					savedState = (Hashtable)netDataContractSerializer.ReadObject(xmlReader);
				}
			}
			finally
			{
				xmlReader?.Close();
				fileStream?.Close();
				if (base.Installers.Count == 0)
				{
					base.Context.LogMessage(Res.GetString("RemovingInstallState"));
					File.Delete(installStatePath);
				}
			}
			base.Commit(savedState);
		}

		private static Type[] GetInstallerTypes(Assembly assem)
		{
			ArrayList arrayList = new ArrayList();
			Module[] modules = assem.GetModules();
			for (int i = 0; i < modules.Length; i++)
			{
				Type[] types = modules[i].GetTypes();
				for (int j = 0; j < types.Length; j++)
				{
					if (typeof(Installer).IsAssignableFrom(types[j]) && !types[j].IsAbstract && types[j].IsPublic && ((RunInstallerAttribute)TypeDescriptor.GetAttributes(types[j])[typeof(RunInstallerAttribute)]).RunInstaller)
					{
						arrayList.Add(types[j]);
					}
				}
			}
			return (Type[])arrayList.ToArray(typeof(Type));
		}

		/// <summary>Performs the installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> used to save information needed to perform a commit, rollback, or uninstall operation.</param>
		/// <exception cref="T:System.ArgumentException">The <paramref name="savedState" /> parameter is <see langword="null" />.  
		///  -or-  
		///  A file could not be found.</exception>
		/// <exception cref="T:System.Exception">An exception occurred in the <see cref="E:System.Configuration.Install.Installer.BeforeInstall" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An exception occurred in the <see cref="E:System.Configuration.Install.Installer.AfterInstall" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  Installer types were not found in one of the assemblies.  
		///  -or-  
		///  An instance of one of the installer types could not be created.</exception>
		public override void Install(IDictionary savedState)
		{
			PrintStartText(Res.GetString("InstallActivityInstalling"));
			if (!initialized)
			{
				InitializeFromAssembly();
			}
			Hashtable hashtable = new Hashtable();
			savedState = hashtable;
			try
			{
				base.Install(savedState);
			}
			finally
			{
				FileStream fileStream = new FileStream(GetInstallStatePath(Path), FileMode.Create);
				XmlWriterSettings xmlWriterSettings = new XmlWriterSettings();
				xmlWriterSettings.Encoding = Encoding.UTF8;
				xmlWriterSettings.CheckCharacters = false;
				xmlWriterSettings.CloseOutput = false;
				XmlWriter xmlWriter = XmlWriter.Create(fileStream, xmlWriterSettings);
				try
				{
					NetDataContractSerializer netDataContractSerializer = new NetDataContractSerializer();
					netDataContractSerializer.WriteObject(xmlWriter, savedState);
				}
				finally
				{
					xmlWriter.Close();
					fileStream.Close();
				}
			}
		}

		private void PrintStartText(string activity)
		{
			if (UseNewContext)
			{
				InstallContext installContext = CreateAssemblyContext();
				if (base.Context != null)
				{
					base.Context.LogMessage(Res.GetString("InstallLogContent", Path));
					base.Context.LogMessage(Res.GetString("InstallFileLocation", installContext.Parameters["logfile"]));
				}
				base.Context = installContext;
			}
			base.Context.LogMessage(string.Format(CultureInfo.InvariantCulture, activity, new object[1] { Path }));
			base.Context.LogMessage(Res.GetString("InstallLogParameters"));
			if (base.Context.Parameters.Count == 0)
			{
				base.Context.LogMessage("   " + Res.GetString("InstallLogNone"));
			}
			IDictionaryEnumerator dictionaryEnumerator = (IDictionaryEnumerator)base.Context.Parameters.GetEnumerator();
			while (dictionaryEnumerator.MoveNext())
			{
				string text = (string)dictionaryEnumerator.Key;
				string text2 = (string)dictionaryEnumerator.Value;
				if (text.Equals("password", StringComparison.InvariantCultureIgnoreCase))
				{
					text2 = "********";
				}
				base.Context.LogMessage("   " + text + " = " + text2);
			}
		}

		/// <summary>Restores the computer to the state it was in before the installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the pre-installation state of the computer.</param>
		/// <exception cref="T:System.ArgumentException">The <paramref name="savedState" /> parameter is <see langword="null" />.  
		///  -or-  
		///  The saved-state <see cref="T:System.Collections.IDictionary" /> might have been corrupted.  
		///  -or-  
		///  A file could not be found.</exception>
		/// <exception cref="T:System.Exception">An exception occurred in the <see cref="E:System.Configuration.Install.Installer.BeforeRollback" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An exception occurred in the <see cref="E:System.Configuration.Install.Installer.AfterRollback" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An exception occurred during the <see cref="M:System.Configuration.Install.AssemblyInstaller.Rollback(System.Collections.IDictionary)" /> phase of the installation. The exception is ignored and the rollback continues. However, the computer might not be fully reverted to its initial state after the rollback completes.  
		///  -or-  
		///  Installer types were not found in one of the assemblies.  
		///  -or-  
		///  An instance of one of the installer types could not be created.</exception>
		/// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred during the <see cref="M:System.Configuration.Install.AssemblyInstaller.Rollback(System.Collections.IDictionary)" /> phase of the installation. The exception is ignored and the rollback continues. However, the computer might not be fully reverted to its initial state after the rollback completes.</exception>
		public override void Rollback(IDictionary savedState)
		{
			PrintStartText(Res.GetString("InstallActivityRollingBack"));
			if (!initialized)
			{
				InitializeFromAssembly();
			}
			string installStatePath = GetInstallStatePath(Path);
			FileStream fileStream = new FileStream(installStatePath, FileMode.Open, FileAccess.Read);
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			xmlReaderSettings.CheckCharacters = false;
			xmlReaderSettings.CloseInput = false;
			XmlReader xmlReader = null;
			if (fileStream != null)
			{
				xmlReader = XmlReader.Create(fileStream, xmlReaderSettings);
			}
			try
			{
				if (xmlReader != null)
				{
					NetDataContractSerializer netDataContractSerializer = new NetDataContractSerializer();
					savedState = (Hashtable)netDataContractSerializer.ReadObject(xmlReader);
				}
			}
			finally
			{
				xmlReader?.Close();
				fileStream?.Close();
			}
			try
			{
				base.Rollback(savedState);
			}
			finally
			{
				File.Delete(installStatePath);
			}
		}

		/// <summary>Removes an installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the post-installation state of the computer.</param>
		/// <exception cref="T:System.ArgumentException">The saved-state <see cref="T:System.Collections.IDictionary" /> might have been corrupted.  
		///  -or-  
		///  A file could not be found.</exception>
		/// <exception cref="T:System.Exception">An error occurred in the <see cref="E:System.Configuration.Install.Installer.BeforeUninstall" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An error occurred in the <see cref="E:System.Configuration.Install.Installer.AfterUninstall" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An exception occurred while uninstalling. The exception is ignored and the uninstall continues. However, the application might not be fully uninstalled after the uninstall completes.  
		///  -or-  
		///  Installer types were not found in one of the assemblies.  
		///  -or-  
		///  An instance of one of the installer types could not be created.  
		///  -or-  
		///  A file could not be deleted.</exception>
		/// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred while uninstalling. The exception is ignored and the uninstall continues. However, the application might not be fully uninstalled after the uninstall completes.</exception>
		public override void Uninstall(IDictionary savedState)
		{
			PrintStartText(Res.GetString("InstallActivityUninstalling"));
			if (!initialized)
			{
				InitializeFromAssembly();
			}
			string installStatePath = GetInstallStatePath(Path);
			if (installStatePath != null && File.Exists(installStatePath))
			{
				FileStream fileStream = new FileStream(installStatePath, FileMode.Open, FileAccess.Read);
				XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
				xmlReaderSettings.CheckCharacters = false;
				xmlReaderSettings.CloseInput = false;
				XmlReader xmlReader = null;
				if (fileStream != null)
				{
					xmlReader = XmlReader.Create(fileStream, xmlReaderSettings);
				}
				try
				{
					if (xmlReader != null)
					{
						NetDataContractSerializer netDataContractSerializer = new NetDataContractSerializer();
						savedState = (Hashtable)netDataContractSerializer.ReadObject(xmlReader);
					}
				}
				catch
				{
					base.Context.LogMessage(Res.GetString("InstallSavedStateFileCorruptedWarning", Path, installStatePath));
					savedState = null;
				}
				finally
				{
					xmlReader?.Close();
					fileStream?.Close();
				}
			}
			else
			{
				savedState = null;
			}
			base.Uninstall(savedState);
			if (installStatePath != null && installStatePath.Length != 0)
			{
				try
				{
					File.Delete(installStatePath);
				}
				catch
				{
					throw new InvalidOperationException(Res.GetString("InstallUnableDeleteFile", installStatePath));
				}
			}
		}
	}
	/// <summary>Specifies an installer that copies properties from a component to use at install time.</summary>
	public abstract class ComponentInstaller : Installer
	{
		/// <summary>When overridden in a derived class, copies all the properties that are required at install time from the specified component.</summary>
		/// <param name="component">The component to copy from.</param>
		public abstract void CopyFromComponent(IComponent component);

		/// <summary>Determines if the specified installer installs the same object as this installer.</summary>
		/// <param name="otherInstaller">The installer to compare.</param>
		/// <returns>
		///   <see langword="true" /> if this installer and the installer specified by the <paramref name="otherInstaller" /> parameter install the same object; otherwise, <see langword="false" />.</returns>
		public virtual bool IsEquivalentInstaller(ComponentInstaller otherInstaller)
		{
			return false;
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.ComponentInstaller" /> class.</summary>
		protected ComponentInstaller()
		{
		}
	}
	/// <summary>Provides an interface for a managed installer.</summary>
	[ComImport]
	[Guid("1E233FE7-C16D-4512-8C3B-2E9988F08D38")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IManagedInstaller
	{
		/// <summary>Executes a managed installation.</summary>
		/// <param name="commandLine">The command line that specifies the installation.</param>
		/// <param name="hInstall">The handle to the installation.</param>
		/// <returns>The return code for installutil.exe. A successful installation returns 0. Other values indicate failure.</returns>
		[return: MarshalAs(UnmanagedType.I4)]
		int ManagedInstall([In][MarshalAs(UnmanagedType.BStr)] string commandLine, [In][MarshalAs(UnmanagedType.I4)] int hInstall);
	}
	/// <summary>Contains information about the current installation.</summary>
	public class InstallContext
	{
		private StringDictionary parameters;

		/// <summary>Gets the command-line parameters that were entered when InstallUtil.exe was run.</summary>
		/// <returns>A <see cref="T:System.Collections.Specialized.StringDictionary" /> that represents the command-line parameters that were entered when the installation executable was run.</returns>
		public StringDictionary Parameters => parameters;

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallContext" /> class.</summary>
		public InstallContext()
			: this(null, null)
		{
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallContext" /> class, and creates a log file for the installation.</summary>
		/// <param name="logFilePath">The path to the log file for this installation, or <see langword="null" /> if no log file should be created.</param>
		/// <param name="commandLine">The command-line parameters entered when running the installation program, or <see langword="null" /> if none were entered.</param>
		public InstallContext(string logFilePath, string[] commandLine)
		{
			parameters = ParseCommandLine(commandLine);
			if (Parameters["logfile"] == null && logFilePath != null)
			{
				Parameters["logfile"] = logFilePath;
			}
		}

		/// <summary>Determines whether the specified command-line parameter is <see langword="true" />.</summary>
		/// <param name="paramName">The name of the command-line parameter to check.</param>
		/// <returns>
		///   <see langword="true" /> if the specified parameter is set to "yes", "true", "1", or an empty string (""); otherwise, <see langword="false" />.</returns>
		public bool IsParameterTrue(string paramName)
		{
			string text = Parameters[paramName.ToLower(CultureInfo.InvariantCulture)];
			if (text == null)
			{
				return false;
			}
			if (string.Compare(text, "true", StringComparison.OrdinalIgnoreCase) != 0 && string.Compare(text, "yes", StringComparison.OrdinalIgnoreCase) != 0 && string.Compare(text, "1", StringComparison.OrdinalIgnoreCase) != 0)
			{
				return "".Equals(text);
			}
			return true;
		}

		internal void LogMessageHelper(string message)
		{
			StreamWriter streamWriter = null;
			try
			{
				if (!string.IsNullOrEmpty(Parameters["logfile"]))
				{
					streamWriter = new StreamWriter(Parameters["logfile"], append: true, Encoding.UTF8);
					streamWriter.WriteLine(message);
				}
			}
			finally
			{
				streamWriter?.Close();
			}
		}

		/// <summary>Writes a message to the console and to the log file for the installation.</summary>
		/// <param name="message">The message to write.</param>
		public void LogMessage(string message)
		{
			try
			{
				LogMessageHelper(message);
			}
			catch (Exception)
			{
				try
				{
					Parameters["logfile"] = Path.Combine(Path.GetTempPath(), Path.GetFileName(Parameters["logfile"]));
					LogMessageHelper(message);
				}
				catch (Exception)
				{
					Parameters["logfile"] = null;
				}
			}
			if (IsParameterTrue("LogToConsole") || Parameters["logtoconsole"] == null)
			{
				Console.WriteLine(message);
			}
		}

		/// <summary>Parses the command-line parameters into a string dictionary.</summary>
		/// <param name="args">An array containing the command-line parameters.</param>
		/// <returns>A <see cref="T:System.Collections.Specialized.StringDictionary" /> containing the parsed command-line parameters.</returns>
		protected static StringDictionary ParseCommandLine(string[] args)
		{
			StringDictionary stringDictionary = new StringDictionary();
			if (args == null)
			{
				return stringDictionary;
			}
			for (int i = 0; i < args.Length; i++)
			{
				if (args[i].StartsWith("/", StringComparison.Ordinal) || args[i].StartsWith("-", StringComparison.Ordinal))
				{
					args[i] = args[i].Substring(1);
				}
				int num = args[i].IndexOf('=');
				if (num < 0)
				{
					stringDictionary[args[i].ToLower(CultureInfo.InvariantCulture)] = "";
				}
				else
				{
					stringDictionary[args[i].Substring(0, num).ToLower(CultureInfo.InvariantCulture)] = args[i].Substring(num + 1);
				}
			}
			return stringDictionary;
		}
	}
	/// <summary>Provides the foundation for custom installations.</summary>
	[DefaultEvent("AfterInstall")]
	public class Installer : Component
	{
		private InstallerCollection installers;

		private InstallContext context;

		internal Installer parent;

		private InstallEventHandler afterCommitHandler;

		private InstallEventHandler afterInstallHandler;

		private InstallEventHandler afterRollbackHandler;

		private InstallEventHandler afterUninstallHandler;

		private InstallEventHandler beforeCommitHandler;

		private InstallEventHandler beforeInstallHandler;

		private InstallEventHandler beforeRollbackHandler;

		private InstallEventHandler beforeUninstallHandler;

		private const string wrappedExceptionSource = "WrappedExceptionSource";

		/// <summary>Gets or sets information about the current installation.</summary>
		/// <returns>An <see cref="T:System.Configuration.Install.InstallContext" /> that contains information about the current installation.</returns>
		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public InstallContext Context
		{
			get
			{
				return context;
			}
			set
			{
				context = value;
			}
		}

		/// <summary>Gets the help text for all the installers in the installer collection.</summary>
		/// <returns>The help text for all the installers in the installer collection, including the description of what the installer does and the command line options for the installation executable, such as the InstallUtil.exe utility, that can be passed to and understood by this installer.</returns>
		/// <exception cref="T:System.NullReferenceException">One of the installers in the installer collection specifies a null reference instead of help text. A likely cause for this exception is that a field to contain the help text is defined but not initialized.</exception>
		[ResDescription("Desc_Installer_HelpText")]
		public virtual string HelpText
		{
			get
			{
				StringBuilder stringBuilder = new StringBuilder();
				for (int i = 0; i < Installers.Count; i++)
				{
					string helpText = Installers[i].HelpText;
					if (helpText.Length > 0)
					{
						stringBuilder.Append("\r\n");
						stringBuilder.Append(helpText);
					}
				}
				return stringBuilder.ToString();
			}
		}

		/// <summary>Gets the collection of installers that this installer contains.</summary>
		/// <returns>An <see cref="T:System.Configuration.Install.InstallerCollection" /> containing the collection of installers associated with this installer.</returns>
		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Content)]
		public InstallerCollection Installers
		{
			get
			{
				if (installers == null)
				{
					installers = new InstallerCollection(this);
				}
				return installers;
			}
		}

		/// <summary>Gets or sets the installer containing the collection that this installer belongs to.</summary>
		/// <returns>An <see cref="T:System.Configuration.Install.Installer" /> containing the collection that this instance belongs to, or <see langword="null" /> if this instance does not belong to a collection.</returns>
		[Browsable(true)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[TypeConverter(typeof(InstallerParentConverter))]
		[ResDescription("Desc_Installer_Parent")]
		public Installer Parent
		{
			get
			{
				return parent;
			}
			set
			{
				if (value == this)
				{
					throw new InvalidOperationException(Res.GetString("InstallBadParent"));
				}
				if (value == parent)
				{
					return;
				}
				if (value != null && InstallerTreeContains(value))
				{
					throw new InvalidOperationException(Res.GetString("InstallRecursiveParent"));
				}
				if (parent != null)
				{
					int num = parent.Installers.IndexOf(this);
					if (num != -1)
					{
						parent.Installers.RemoveAt(num);
					}
				}
				parent = value;
				if (parent != null && !parent.Installers.Contains(this))
				{
					parent.Installers.Add(this);
				}
			}
		}

		/// <summary>Occurs after all the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property have committed their installations.</summary>
		public event InstallEventHandler Committed
		{
			add
			{
				afterCommitHandler = (InstallEventHandler)Delegate.Combine(afterCommitHandler, value);
			}
			remove
			{
				afterCommitHandler = (InstallEventHandler)Delegate.Remove(afterCommitHandler, value);
			}
		}

		/// <summary>Occurs after the <see cref="M:System.Configuration.Install.Installer.Install(System.Collections.IDictionary)" /> methods of all the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property have run.</summary>
		public event InstallEventHandler AfterInstall
		{
			add
			{
				afterInstallHandler = (InstallEventHandler)Delegate.Combine(afterInstallHandler, value);
			}
			remove
			{
				afterInstallHandler = (InstallEventHandler)Delegate.Remove(afterInstallHandler, value);
			}
		}

		/// <summary>Occurs after the installations of all the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property are rolled back.</summary>
		public event InstallEventHandler AfterRollback
		{
			add
			{
				afterRollbackHandler = (InstallEventHandler)Delegate.Combine(afterRollbackHandler, value);
			}
			remove
			{
				afterRollbackHandler = (InstallEventHandler)Delegate.Remove(afterRollbackHandler, value);
			}
		}

		/// <summary>Occurs after all the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property perform their uninstallation operations.</summary>
		public event InstallEventHandler AfterUninstall
		{
			add
			{
				afterUninstallHandler = (InstallEventHandler)Delegate.Combine(afterUninstallHandler, value);
			}
			remove
			{
				afterUninstallHandler = (InstallEventHandler)Delegate.Remove(afterUninstallHandler, value);
			}
		}

		/// <summary>Occurs before the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property committ their installations.</summary>
		public event InstallEventHandler Committing
		{
			add
			{
				beforeCommitHandler = (InstallEventHandler)Delegate.Combine(beforeCommitHandler, value);
			}
			remove
			{
				beforeCommitHandler = (InstallEventHandler)Delegate.Remove(beforeCommitHandler, value);
			}
		}

		/// <summary>Occurs before the <see cref="M:System.Configuration.Install.Installer.Install(System.Collections.IDictionary)" /> method of each installer in the installer collection has run.</summary>
		public event InstallEventHandler BeforeInstall
		{
			add
			{
				beforeInstallHandler = (InstallEventHandler)Delegate.Combine(beforeInstallHandler, value);
			}
			remove
			{
				beforeInstallHandler = (InstallEventHandler)Delegate.Remove(beforeInstallHandler, value);
			}
		}

		/// <summary>Occurs before the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property are rolled back.</summary>
		public event InstallEventHandler BeforeRollback
		{
			add
			{
				beforeRollbackHandler = (InstallEventHandler)Delegate.Combine(beforeRollbackHandler, value);
			}
			remove
			{
				beforeRollbackHandler = (InstallEventHandler)Delegate.Remove(beforeRollbackHandler, value);
			}
		}

		/// <summary>Occurs before the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property perform their uninstall operations.</summary>
		public event InstallEventHandler BeforeUninstall
		{
			add
			{
				beforeUninstallHandler = (InstallEventHandler)Delegate.Combine(beforeUninstallHandler, value);
			}
			remove
			{
				beforeUninstallHandler = (InstallEventHandler)Delegate.Remove(beforeUninstallHandler, value);
			}
		}

		internal bool InstallerTreeContains(Installer target)
		{
			if (Installers.Contains(target))
			{
				return true;
			}
			foreach (Installer installer in Installers)
			{
				if (installer.InstallerTreeContains(target))
				{
					return true;
				}
			}
			return false;
		}

		/// <summary>When overridden in a derived class, completes the install transaction.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after all the installers in the collection have run.</param>
		/// <exception cref="T:System.ArgumentException">The <paramref name="savedState" /> parameter is <see langword="null" />.  
		///  -or-  
		///  The saved-state <see cref="T:System.Collections.IDictionary" /> might have been corrupted.</exception>
		/// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred during the <see cref="M:System.Configuration.Install.Installer.Commit(System.Collections.IDictionary)" /> phase of the installation. This exception is ignored and the installation continues. However, the application might not function correctly after the installation is complete.</exception>
		public virtual void Commit(IDictionary savedState)
		{
			if (savedState == null)
			{
				throw new ArgumentException(Res.GetString("InstallNullParameter", "savedState"));
			}
			if (savedState["_reserved_lastInstallerAttempted"] == null || savedState["_reserved_nestedSavedStates"] == null)
			{
				throw new ArgumentException(Res.GetString("InstallDictionaryMissingValues", "savedState"));
			}
			Exception ex = null;
			try
			{
				OnCommitting(savedState);
			}
			catch (Exception ex2)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityWarning"), "OnCommitting", ex2);
				Context.LogMessage(Res.GetString("InstallCommitException"));
				ex = ex2;
			}
			int num = (int)savedState["_reserved_lastInstallerAttempted"];
			IDictionary[] array = (IDictionary[])savedState["_reserved_nestedSavedStates"];
			if (num + 1 != array.Length || num >= Installers.Count)
			{
				throw new ArgumentException(Res.GetString("InstallDictionaryCorrupted", "savedState"));
			}
			for (int i = 0; i < Installers.Count; i++)
			{
				Installers[i].Context = Context;
			}
			for (int j = 0; j <= num; j++)
			{
				try
				{
					Installers[j].Commit(array[j]);
				}
				catch (Exception ex3)
				{
					if (!IsWrappedException(ex3))
					{
						Context.LogMessage(Res.GetString("InstallLogCommitException", Installers[j].ToString()));
						LogException(ex3, Context);
						Context.LogMessage(Res.GetString("InstallCommitException"));
					}
					ex = ex3;
				}
			}
			savedState["_reserved_nestedSavedStates"] = array;
			savedState.Remove("_reserved_lastInstallerAttempted");
			try
			{
				OnCommitted(savedState);
			}
			catch (Exception ex4)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityWarning"), "OnCommitted", ex4);
				Context.LogMessage(Res.GetString("InstallCommitException"));
				ex = ex4;
			}
			if (ex != null)
			{
				Exception ex5 = ex;
				if (!IsWrappedException(ex))
				{
					ex5 = new InstallException(Res.GetString("InstallCommitException"), ex);
					ex5.Source = "WrappedExceptionSource";
				}
				throw ex5;
			}
		}

		/// <summary>When overridden in a derived class, performs the installation.</summary>
		/// <param name="stateSaver">An <see cref="T:System.Collections.IDictionary" /> used to save information needed to perform a commit, rollback, or uninstall operation.</param>
		/// <exception cref="T:System.ArgumentException">The <paramref name="stateSaver" /> parameter is <see langword="null" />.</exception>
		/// <exception cref="T:System.Exception">An exception occurred in the <see cref="E:System.Configuration.Install.Installer.BeforeInstall" /> event handler of one of the installers in the collection.  
		///  -or-  
		///  An exception occurred in the <see cref="E:System.Configuration.Install.Installer.AfterInstall" /> event handler of one of the installers in the collection.</exception>
		public virtual void Install(IDictionary stateSaver)
		{
			if (stateSaver == null)
			{
				throw new ArgumentException(Res.GetString("InstallNullParameter", "stateSaver"));
			}
			try
			{
				OnBeforeInstall(stateSaver);
			}
			catch (Exception ex)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityError"), "OnBeforeInstall", ex);
				throw new InvalidOperationException(Res.GetString("InstallEventException", "OnBeforeInstall", GetType().FullName), ex);
			}
			int num = -1;
			ArrayList arrayList = new ArrayList();
			try
			{
				for (int i = 0; i < Installers.Count; i++)
				{
					Installers[i].Context = Context;
				}
				for (int j = 0; j < Installers.Count; j++)
				{
					Installer installer = Installers[j];
					IDictionary dictionary = new Hashtable();
					try
					{
						num = j;
						installer.Install(dictionary);
					}
					finally
					{
						arrayList.Add(dictionary);
					}
				}
			}
			finally
			{
				stateSaver.Add("_reserved_lastInstallerAttempted", num);
				stateSaver.Add("_reserved_nestedSavedStates", arrayList.ToArray(typeof(IDictionary)));
			}
			try
			{
				OnAfterInstall(stateSaver);
			}
			catch (Exception ex2)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityError"), "OnAfterInstall", ex2);
				throw new InvalidOperationException(Res.GetString("InstallEventException", "OnAfterInstall", GetType().FullName), ex2);
			}
		}

		internal static void LogException(Exception e, InstallContext context)
		{
			bool flag = true;
			while (e != null)
			{
				if (flag)
				{
					context.LogMessage(e.GetType().FullName + ": " + e.Message);
					flag = false;
				}
				else
				{
					context.LogMessage(Res.GetString("InstallLogInner", e.GetType().FullName, e.Message));
				}
				if (context.IsParameterTrue("showcallstack"))
				{
					context.LogMessage(e.StackTrace);
				}
				e = e.InnerException;
			}
		}

		private bool IsWrappedException(Exception e)
		{
			if (e is InstallException && e.Source == "WrappedExceptionSource")
			{
				return e.TargetSite.ReflectedType == typeof(Installer);
			}
			return false;
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.Committed" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after all the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property run.</param>
		protected virtual void OnCommitted(IDictionary savedState)
		{
			if (afterCommitHandler != null)
			{
				afterCommitHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.AfterInstall" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after all the installers contained in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property have completed their installations.</param>
		protected virtual void OnAfterInstall(IDictionary savedState)
		{
			if (afterInstallHandler != null)
			{
				afterInstallHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.AfterRollback" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after the installers contained in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property are rolled back.</param>
		protected virtual void OnAfterRollback(IDictionary savedState)
		{
			if (afterRollbackHandler != null)
			{
				afterRollbackHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.AfterUninstall" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after all the installers contained in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property are uninstalled.</param>
		protected virtual void OnAfterUninstall(IDictionary savedState)
		{
			if (afterUninstallHandler != null)
			{
				afterUninstallHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.Committing" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer before the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property are committed.</param>
		protected virtual void OnCommitting(IDictionary savedState)
		{
			if (beforeCommitHandler != null)
			{
				beforeCommitHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.BeforeInstall" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer before the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property are installed. This <see cref="T:System.Collections.IDictionary" /> object should be empty at this point.</param>
		protected virtual void OnBeforeInstall(IDictionary savedState)
		{
			if (beforeInstallHandler != null)
			{
				beforeInstallHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.BeforeRollback" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer before the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property are rolled back.</param>
		protected virtual void OnBeforeRollback(IDictionary savedState)
		{
			if (beforeRollbackHandler != null)
			{
				beforeRollbackHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>Raises the <see cref="E:System.Configuration.Install.Installer.BeforeUninstall" /> event.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer before the installers in the <see cref="P:System.Configuration.Install.Installer.Installers" /> property uninstall their installations.</param>
		protected virtual void OnBeforeUninstall(IDictionary savedState)
		{
			if (beforeUninstallHandler != null)
			{
				beforeUninstallHandler(this, new InstallEventArgs(savedState));
			}
		}

		/// <summary>When overridden in a derived class, restores the pre-installation state of the computer.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the pre-installation state of the computer.</param>
		/// <exception cref="T:System.ArgumentException">The <paramref name="savedState" /> parameter is <see langword="null" />.  
		///  -or-  
		///  The saved-state <see cref="T:System.Collections.IDictionary" /> might have been corrupted.</exception>
		/// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred during the <see cref="M:System.Configuration.Install.Installer.Rollback(System.Collections.IDictionary)" /> phase of the installation. This exception is ignored and the rollback continues. However, the computer might not be fully reverted to its initial state after the rollback completes.</exception>
		public virtual void Rollback(IDictionary savedState)
		{
			if (savedState == null)
			{
				throw new ArgumentException(Res.GetString("InstallNullParameter", "savedState"));
			}
			if (savedState["_reserved_lastInstallerAttempted"] == null || savedState["_reserved_nestedSavedStates"] == null)
			{
				throw new ArgumentException(Res.GetString("InstallDictionaryMissingValues", "savedState"));
			}
			Exception ex = null;
			try
			{
				OnBeforeRollback(savedState);
			}
			catch (Exception ex2)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityWarning"), "OnBeforeRollback", ex2);
				Context.LogMessage(Res.GetString("InstallRollbackException"));
				ex = ex2;
			}
			int num = (int)savedState["_reserved_lastInstallerAttempted"];
			IDictionary[] array = (IDictionary[])savedState["_reserved_nestedSavedStates"];
			if (num + 1 != array.Length || num >= Installers.Count)
			{
				throw new ArgumentException(Res.GetString("InstallDictionaryCorrupted", "savedState"));
			}
			for (int num2 = Installers.Count - 1; num2 >= 0; num2--)
			{
				Installers[num2].Context = Context;
			}
			for (int num3 = num; num3 >= 0; num3--)
			{
				try
				{
					Installers[num3].Rollback(array[num3]);
				}
				catch (Exception ex3)
				{
					if (!IsWrappedException(ex3))
					{
						Context.LogMessage(Res.GetString("InstallLogRollbackException", Installers[num3].ToString()));
						LogException(ex3, Context);
						Context.LogMessage(Res.GetString("InstallRollbackException"));
					}
					ex = ex3;
				}
			}
			try
			{
				OnAfterRollback(savedState);
			}
			catch (Exception ex4)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityWarning"), "OnAfterRollback", ex4);
				Context.LogMessage(Res.GetString("InstallRollbackException"));
				ex = ex4;
			}
			if (ex != null)
			{
				Exception ex5 = ex;
				if (!IsWrappedException(ex))
				{
					ex5 = new InstallException(Res.GetString("InstallRollbackException"), ex);
					ex5.Source = "WrappedExceptionSource";
				}
				throw ex5;
			}
		}

		/// <summary>When overridden in a derived class, removes an installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after the installation was complete.</param>
		/// <exception cref="T:System.ArgumentException">The saved-state <see cref="T:System.Collections.IDictionary" /> might have been corrupted.</exception>
		/// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred while uninstalling. This exception is ignored and the uninstall continues. However, the application might not be fully uninstalled after the uninstallation completes.</exception>
		public virtual void Uninstall(IDictionary savedState)
		{
			Exception ex = null;
			try
			{
				OnBeforeUninstall(savedState);
			}
			catch (Exception ex2)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityWarning"), "OnBeforeUninstall", ex2);
				Context.LogMessage(Res.GetString("InstallUninstallException"));
				ex = ex2;
			}
			IDictionary[] array;
			if (savedState != null)
			{
				array = (IDictionary[])savedState["_reserved_nestedSavedStates"];
				if (array == null || array.Length != Installers.Count)
				{
					throw new ArgumentException(Res.GetString("InstallDictionaryCorrupted", "savedState"));
				}
			}
			else
			{
				array = new IDictionary[Installers.Count];
			}
			for (int num = Installers.Count - 1; num >= 0; num--)
			{
				Installers[num].Context = Context;
			}
			for (int num2 = Installers.Count - 1; num2 >= 0; num2--)
			{
				try
				{
					Installers[num2].Uninstall(array[num2]);
				}
				catch (Exception ex3)
				{
					if (!IsWrappedException(ex3))
					{
						Context.LogMessage(Res.GetString("InstallLogUninstallException", Installers[num2].ToString()));
						LogException(ex3, Context);
						Context.LogMessage(Res.GetString("InstallUninstallException"));
					}
					ex = ex3;
				}
			}
			try
			{
				OnAfterUninstall(savedState);
			}
			catch (Exception ex4)
			{
				WriteEventHandlerError(Res.GetString("InstallSeverityWarning"), "OnAfterUninstall", ex4);
				Context.LogMessage(Res.GetString("InstallUninstallException"));
				ex = ex4;
			}
			if (ex != null)
			{
				Exception ex5 = ex;
				if (!IsWrappedException(ex))
				{
					ex5 = new InstallException(Res.GetString("InstallUninstallException"), ex);
					ex5.Source = "WrappedExceptionSource";
				}
				throw ex5;
			}
		}

		private void WriteEventHandlerError(string severity, string eventName, Exception e)
		{
			Context.LogMessage(Res.GetString("InstallLogError", severity, eventName, GetType().FullName));
			LogException(e, Context);
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.Installer" /> class.</summary>
		public Installer()
		{
		}
	}
	internal class InstallerParentConverter : ReferenceConverter
	{
		public InstallerParentConverter(Type type)
			: base(type)
		{
		}

		public override StandardValuesCollection GetStandardValues(ITypeDescriptorContext context)
		{
			StandardValuesCollection standardValues = base.GetStandardValues(context);
			object instance = context.Instance;
			int i = 0;
			int num = 0;
			object[] array = new object[standardValues.Count - 1];
			for (; i < standardValues.Count; i++)
			{
				if (standardValues[i] != instance)
				{
					array[num] = standardValues[i];
					num++;
				}
			}
			return new StandardValuesCollection(array);
		}
	}
	/// <summary>Contains a collection of installers to be run during an installation.</summary>
	public class InstallerCollection : CollectionBase
	{
		private Installer owner;

		/// <summary>Gets or sets an installer at the specified index.</summary>
		/// <param name="index">The zero-based index of the installer to get or set.</param>
		/// <returns>An <see cref="T:System.Configuration.Install.Installer" /> that represents the installer at the specified index.</returns>
		public Installer this[int index]
		{
			get
			{
				return (Installer)base.List[index];
			}
			set
			{
				base.List[index] = value;
			}
		}

		internal InstallerCollection(Installer owner)
		{
			this.owner = owner;
		}

		/// <summary>Adds the specified installer to this collection of installers.</summary>
		/// <param name="value">An <see cref="T:System.Configuration.Install.Installer" /> that represents the installer to add to the collection.</param>
		/// <returns>The zero-based index of the added installer.</returns>
		public int Add(Installer value)
		{
			return base.List.Add(value);
		}

		/// <summary>Adds the specified collection of installers to this collection.</summary>
		/// <param name="value">An <see cref="T:System.Configuration.Install.InstallerCollection" /> that represents the installers to add to this collection.</param>
		public void AddRange(InstallerCollection value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			int count = value.Count;
			for (int i = 0; i < count; i++)
			{
				Add(value[i]);
			}
		}

		/// <summary>Adds the specified array of installers to this collection.</summary>
		/// <param name="value">An array of type <see cref="T:System.Configuration.Install.Installer" /> that represents the installers to add to this collection.</param>
		public void AddRange(Installer[] value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			for (int i = 0; i < value.Length; i++)
			{
				Add(value[i]);
			}
		}

		/// <summary>Determines whether the specified installer is included in collection.</summary>
		/// <param name="value">An <see cref="T:System.Configuration.Install.Installer" /> that represents the installer to look for.</param>
		/// <returns>
		///   <see langword="true" /> if the specified installer is in this collection; otherwise, <see langword="false" />.</returns>
		public bool Contains(Installer value)
		{
			return base.List.Contains(value);
		}

		/// <summary>Copies the items from the collection to an array, begining at the specified index.</summary>
		/// <param name="array">The array to copy to.</param>
		/// <param name="index">The index of the array at which to paste the collection.</param>
		public void CopyTo(Installer[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		/// <summary>Determines the index of a specified installer in the collection.</summary>
		/// <param name="value">The <see cref="T:System.Configuration.Install.Installer" /> to locate in the collection.</param>
		/// <returns>The zero-based index of the installer in the collection.</returns>
		public int IndexOf(Installer value)
		{
			return base.List.IndexOf(value);
		}

		/// <summary>Inserts the specified installer into the collection at the specified index.</summary>
		/// <param name="index">The zero-based index at which to insert the installer.</param>
		/// <param name="value">The <see cref="T:System.Configuration.Install.Installer" /> to insert.</param>
		public void Insert(int index, Installer value)
		{
			base.List.Insert(index, value);
		}

		/// <summary>Removes the specified <see cref="T:System.Configuration.Install.Installer" /> from the collection.</summary>
		/// <param name="value">An <see cref="T:System.Configuration.Install.Installer" /> that represents the installer to remove.</param>
		public void Remove(Installer value)
		{
			base.List.Remove(value);
		}

		/// <summary>Performs additional custom processes before a new installer is inserted into the collection.</summary>
		/// <param name="index">The zero-based index at which to insert <paramref name="value" />.</param>
		/// <param name="value">The new value of the installer at <paramref name="index" />.</param>
		protected override void OnInsert(int index, object value)
		{
			if (value == owner)
			{
				throw new ArgumentException(Res.GetString("CantAddSelf"));
			}
			_ = System.ComponentModel.CompModSwitches.InstallerDesign.TraceVerbose;
			((Installer)value).parent = owner;
		}

		/// <summary>Performs additional custom processes before an installer is removed from the collection.</summary>
		/// <param name="index">The zero-based index at which <paramref name="value" /> can be found.</param>
		/// <param name="value">The installer to be removed from <paramref name="index" />.</param>
		protected override void OnRemove(int index, object value)
		{
			_ = System.ComponentModel.CompModSwitches.InstallerDesign.TraceVerbose;
			((Installer)value).parent = null;
		}

		/// <summary>Performs additional custom processes before an existing installer is set to a new value.</summary>
		/// <param name="index">The zero-based index at which to replace <paramref name="oldValue" />.</param>
		/// <param name="oldValue">The value to replace with <paramref name="newValue" />.</param>
		/// <param name="newValue">The new value of the installer at <paramref name="index" />.</param>
		protected override void OnSet(int index, object oldValue, object newValue)
		{
			if (newValue == owner)
			{
				throw new ArgumentException(Res.GetString("CantAddSelf"));
			}
			_ = System.ComponentModel.CompModSwitches.InstallerDesign.TraceVerbose;
			((Installer)oldValue).parent = null;
			((Installer)newValue).parent = owner;
		}
	}
	/// <summary>Provides data for the events: <see cref="E:System.Configuration.Install.Installer.BeforeInstall" />, <see cref="E:System.Configuration.Install.Installer.AfterInstall" />, <see cref="E:System.Configuration.Install.Installer.Committing" />, <see cref="E:System.Configuration.Install.Installer.Committed" />, <see cref="E:System.Configuration.Install.Installer.BeforeRollback" />, <see cref="E:System.Configuration.Install.Installer.AfterRollback" />, <see cref="E:System.Configuration.Install.Installer.BeforeUninstall" />, <see cref="E:System.Configuration.Install.Installer.AfterUninstall" />.</summary>
	public class InstallEventArgs : EventArgs
	{
		private IDictionary savedState;

		/// <summary>Gets an <see cref="T:System.Collections.IDictionary" /> that represents the current state of the installation.</summary>
		/// <returns>An <see cref="T:System.Collections.IDictionary" /> that represents the current state of the installation.</returns>
		public IDictionary SavedState => savedState;

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallEventArgs" /> class, and leaves the <see cref="P:System.Configuration.Install.InstallEventArgs.SavedState" /> property empty.</summary>
		public InstallEventArgs()
		{
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallEventArgs" /> class, and specifies the value for the <see cref="P:System.Configuration.Install.InstallEventArgs.SavedState" /> property.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that represents the current state of the installation.</param>
		public InstallEventArgs(IDictionary savedState)
		{
			this.savedState = savedState;
		}
	}
	/// <summary>Represents the method that will handle the <see cref="E:System.Configuration.Install.Installer.BeforeInstall" />, <see cref="E:System.Configuration.Install.Installer.AfterInstall" />, <see cref="E:System.Configuration.Install.Installer.Committing" />, <see cref="E:System.Configuration.Install.Installer.Committed" />, <see cref="E:System.Configuration.Install.Installer.BeforeRollback" />, <see cref="E:System.Configuration.Install.Installer.AfterRollback" />, <see cref="E:System.Configuration.Install.Installer.BeforeUninstall" />, or <see cref="E:System.Configuration.Install.Installer.AfterUninstall" /> event of an <see cref="T:System.Configuration.Install.Installer" />.</summary>
	/// <param name="sender">The source of the event.</param>
	/// <param name="e">An <see cref="T:System.Configuration.Install.InstallEventArgs" /> that contains the event data.</param>
	public delegate void InstallEventHandler(object sender, InstallEventArgs e);
	/// <summary>The exception that is thrown when an error occurs during the commit, rollback, or uninstall phase of an installation.</summary>
	[Serializable]
	public class InstallException : SystemException
	{
		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallException" /> class.</summary>
		public InstallException()
		{
			base.HResult = -2146232057;
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallException" /> class, and specifies the message to display to the user.</summary>
		/// <param name="message">The message to display to the user.</param>
		public InstallException(string message)
			: base(message)
		{
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallException" /> class, and specifies the message to display to the user, and a reference to the inner exception that is the cause of this exception.</summary>
		/// <param name="message">The message to display to the user.</param>
		/// <param name="innerException">The exception that is the cause of the current exception. If the <paramref name="innerException" /> parameter is not <see langword="null" />, the current exception is raised in a <see langword="catch" /> block that handles the inner exception.</param>
		public InstallException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.InstallException" /> class with serialized data.</summary>
		/// <param name="info">The <see cref="T:System.Runtime.Serialization.SerializationInfo" /> that holds the serialized object data about the exception being thrown.</param>
		/// <param name="context">The <see cref="T:System.Runtime.Serialization.StreamingContext" /> that contains contextual information about the source or destination.</param>
		protected InstallException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	/// <summary>Represents a managed install.</summary>
	[ComVisible(true)]
	[Guid("42EB0342-0393-448f-84AA-D4BEB0283595")]
	public class ManagedInstallerClass : IManagedInstaller
	{
		/// <summary>For a description of this member, see <see cref="M:System.Configuration.Install.IManagedInstaller.ManagedInstall(System.String,System.Int32)" />.</summary>
		/// <param name="argString">The command line to install.</param>
		/// <param name="hInstall">The handle to the installation.</param>
		/// <returns>The return code for installutil.exe. A successful installation returns 0. Other values indicate failure.</returns>
		int IManagedInstaller.ManagedInstall(string argString, int hInstall)
		{
			try
			{
				string[] args = StringToArgs(argString);
				InstallHelper(args);
			}
			catch (Exception ex)
			{
				Exception ex2 = ex;
				StringBuilder stringBuilder = new StringBuilder();
				while (ex2 != null)
				{
					stringBuilder.Append(ex2.Message);
					ex2 = ex2.InnerException;
					if (ex2 != null)
					{
						stringBuilder.Append(" --> ");
					}
				}
				int num = NativeMethods.MsiCreateRecord(2);
				if (num != 0 && NativeMethods.MsiRecordSetInteger(num, 1, 1001) == 0 && NativeMethods.MsiRecordSetStringW(num, 2, stringBuilder.ToString()) == 0)
				{
					NativeMethods.MsiProcessMessage(hInstall, 16777216, num);
				}
				return -1;
			}
			return 0;
		}

		/// <summary>Handles the functionality of the Installutil.exe (Installer Tool).</summary>
		/// <param name="args">The arguments passed to the Installer Tool.</param>
		public static void InstallHelper(string[] args)
		{
			bool flag = false;
			bool flag2 = false;
			TransactedInstaller transactedInstaller = new TransactedInstaller();
			bool flag3 = false;
			try
			{
				ArrayList arrayList = new ArrayList();
				for (int i = 0; i < args.Length; i++)
				{
					if (args[i].StartsWith("/", StringComparison.Ordinal) || args[i].StartsWith("-", StringComparison.Ordinal))
					{
						string strA = args[i].Substring(1);
						if (string.Compare(strA, "u", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(strA, "uninstall", StringComparison.OrdinalIgnoreCase) == 0)
						{
							flag = true;
						}
						else if (string.Compare(strA, "?", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(strA, "help", StringComparison.OrdinalIgnoreCase) == 0)
						{
							flag3 = true;
						}
						else if (string.Compare(strA, "AssemblyName", StringComparison.OrdinalIgnoreCase) == 0)
						{
							flag2 = true;
						}
						else
						{
							arrayList.Add(args[i]);
						}
						continue;
					}
					Assembly assembly = null;
					try
					{
						assembly = ((!flag2) ? Assembly.LoadFrom(args[i]) : Assembly.Load(args[i]));
					}
					catch (Exception innerException)
					{
						if (args[i].IndexOf('=') != -1)
						{
							throw new ArgumentException(Res.GetString("InstallFileDoesntExistCommandLine", args[i]), innerException);
						}
						throw;
					}
					AssemblyInstaller value = new AssemblyInstaller(assembly, (string[])arrayList.ToArray(typeof(string)));
					transactedInstaller.Installers.Add(value);
				}
				if (flag3 || transactedInstaller.Installers.Count == 0)
				{
					flag3 = true;
					transactedInstaller.Installers.Add(new AssemblyInstaller());
					throw new InvalidOperationException(GetHelp(transactedInstaller));
				}
				transactedInstaller.Context = new InstallContext("InstallUtil.InstallLog", (string[])arrayList.ToArray(typeof(string)));
			}
			catch (Exception ex)
			{
				if (flag3)
				{
					throw ex;
				}
				throw new InvalidOperationException(Res.GetString("InstallInitializeException", ex.GetType().FullName, ex.Message));
			}
			try
			{
				string text = transactedInstaller.Context.Parameters["installtype"];
				if (text != null && string.Compare(text, "notransaction", StringComparison.OrdinalIgnoreCase) == 0)
				{
					string text2 = transactedInstaller.Context.Parameters["action"];
					if (text2 != null && string.Compare(text2, "rollback", StringComparison.OrdinalIgnoreCase) == 0)
					{
						transactedInstaller.Context.LogMessage(Res.GetString("InstallRollbackNtRun"));
						for (int j = 0; j < transactedInstaller.Installers.Count; j++)
						{
							transactedInstaller.Installers[j].Rollback(null);
						}
					}
					else if (text2 != null && string.Compare(text2, "commit", StringComparison.OrdinalIgnoreCase) == 0)
					{
						transactedInstaller.Context.LogMessage(Res.GetString("InstallCommitNtRun"));
						for (int k = 0; k < transactedInstaller.Installers.Count; k++)
						{
							transactedInstaller.Installers[k].Commit(null);
						}
					}
					else if (text2 != null && string.Compare(text2, "uninstall", StringComparison.OrdinalIgnoreCase) == 0)
					{
						transactedInstaller.Context.LogMessage(Res.GetString("InstallUninstallNtRun"));
						for (int l = 0; l < transactedInstaller.Installers.Count; l++)
						{
							transactedInstaller.Installers[l].Uninstall(null);
						}
					}
					else
					{
						transactedInstaller.Context.LogMessage(Res.GetString("InstallInstallNtRun"));
						for (int m = 0; m < transactedInstaller.Installers.Count; m++)
						{
							transactedInstaller.Installers[m].Install(null);
						}
					}
				}
				else if (!flag)
				{
					IDictionary stateSaver = new Hashtable();
					transactedInstaller.Install(stateSaver);
				}
				else
				{
					transactedInstaller.Uninstall(null);
				}
			}
			catch (Exception ex2)
			{
				throw ex2;
			}
		}

		private static string GetHelp(Installer installerWithHelp)
		{
			return Res.GetString("InstallHelpMessageStart") + Environment.NewLine + installerWithHelp.HelpText + Environment.NewLine + Res.GetString("InstallHelpMessageEnd") + Environment.NewLine;
		}

		private static string[] StringToArgs(string cmdLine)
		{
			ArrayList arrayList = new ArrayList();
			StringBuilder stringBuilder = null;
			bool flag = false;
			bool flag2 = false;
			foreach (char c in cmdLine)
			{
				if (stringBuilder == null)
				{
					if (char.IsWhiteSpace(c))
					{
						continue;
					}
					stringBuilder = new StringBuilder();
				}
				if (flag)
				{
					if (flag2)
					{
						if (c != '\\' && c != '"')
						{
							stringBuilder.Append('\\');
						}
						flag2 = false;
						stringBuilder.Append(c);
						continue;
					}
					switch (c)
					{
					case '"':
						flag = false;
						break;
					case '\\':
						flag2 = true;
						break;
					default:
						stringBuilder.Append(c);
						break;
					}
				}
				else if (char.IsWhiteSpace(c))
				{
					arrayList.Add(stringBuilder.ToString());
					stringBuilder = null;
					flag2 = false;
				}
				else if (flag2)
				{
					stringBuilder.Append(c);
					flag2 = false;
				}
				else
				{
					switch (c)
					{
					case '^':
						flag2 = true;
						break;
					case '"':
						flag = true;
						break;
					default:
						stringBuilder.Append(c);
						break;
					}
				}
			}
			if (stringBuilder != null)
			{
				arrayList.Add(stringBuilder.ToString());
			}
			string[] array = new string[arrayList.Count];
			arrayList.CopyTo(array);
			return array;
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.ManagedInstallerClass" /> class.</summary>
		public ManagedInstallerClass()
		{
		}
	}
	internal static class NativeMethods
	{
		public const int INSTALLMESSAGE_ERROR = 16777216;

		[DllImport("msi.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern int MsiCreateRecord(int cParams);

		[DllImport("msi.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern int MsiRecordSetInteger(int hRecord, int iField, int iValue);

		[DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern int MsiRecordSetStringW(int hRecord, int iField, string szValue);

		[DllImport("msi.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern int MsiProcessMessage(int hInstall, int messageType, int hRecord);
	}
	/// <summary>Defines an installer that either succeeds completely or fails and leaves the computer in its initial state.</summary>
	public class TransactedInstaller : Installer
	{
		/// <summary>Performs the installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> in which this method saves information needed to perform a commit, rollback, or uninstall operation.</param>
		/// <exception cref="T:System.ArgumentException">The <paramref name="savedState" /> parameter is <see langword="null" />.</exception>
		/// <exception cref="T:System.Exception">The installation failed, and is being rolled back.</exception>
		public override void Install(IDictionary savedState)
		{
			if (base.Context == null)
			{
				base.Context = new InstallContext();
			}
			base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoTransacted"));
			try
			{
				bool flag = true;
				try
				{
					base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoBeginInstall"));
					base.Install(savedState);
				}
				catch (Exception ex)
				{
					flag = false;
					base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoException"));
					Installer.LogException(ex, base.Context);
					base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoBeginRollback"));
					try
					{
						Rollback(savedState);
					}
					catch (Exception)
					{
					}
					base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoRollbackDone"));
					throw new InvalidOperationException(Res.GetString("InstallRollback"), ex);
				}
				if (flag)
				{
					base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoBeginCommit"));
					try
					{
						Commit(savedState);
						return;
					}
					finally
					{
						base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoCommitDone"));
					}
				}
			}
			finally
			{
				base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoTransactedDone"));
			}
		}

		/// <summary>Removes an installation.</summary>
		/// <param name="savedState">An <see cref="T:System.Collections.IDictionary" /> that contains the state of the computer after the installation completed.</param>
		public override void Uninstall(IDictionary savedState)
		{
			if (base.Context == null)
			{
				base.Context = new InstallContext();
			}
			base.Context.LogMessage(Environment.NewLine + Environment.NewLine + Res.GetString("InstallInfoBeginUninstall"));
			try
			{
				base.Uninstall(savedState);
			}
			finally
			{
				base.Context.LogMessage(Environment.NewLine + Res.GetString("InstallInfoUninstallDone"));
			}
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Configuration.Install.TransactedInstaller" /> class.</summary>
		public TransactedInstaller()
		{
		}
	}
	/// <summary>Specifies what an installer should do during an uninstallation.</summary>
	public enum UninstallAction
	{
		/// <summary>Removes the resource the installer created.</summary>
		Remove,
		/// <summary>Leaves the resource created by the installer as is.</summary>
		NoAction
	}
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class ResDescriptionAttribute : DescriptionAttribute
	{
		private bool replaced;

		public override string Description
		{
			get
			{
				if (!replaced)
				{
					replaced = true;
					base.DescriptionValue = Res.GetString(base.Description);
				}
				return base.Description;
			}
		}

		public ResDescriptionAttribute(string description)
			: base(description)
		{
		}
	}
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class ResCategoryAttribute : CategoryAttribute
	{
		public ResCategoryAttribute(string category)
			: base(category)
		{
		}

		protected override string GetLocalizedString(string value)
		{
			return Res.GetString(value);
		}
	}
	internal sealed class Res
	{
		internal const string InstallAbort = "InstallAbort";

		internal const string InstallException = "InstallException";

		internal const string InstallLogContent = "InstallLogContent";

		internal const string InstallFileLocation = "InstallFileLocation";

		internal const string InstallLogParameters = "InstallLogParameters";

		internal const string InstallLogNone = "InstallLogNone";

		internal const string InstallNoPublicInstallers = "InstallNoPublicInstallers";

		internal const string InstallFileNotFound = "InstallFileNotFound";

		internal const string InstallNoInstallerTypes = "InstallNoInstallerTypes";

		internal const string InstallCannotCreateInstance = "InstallCannotCreateInstance";

		internal const string InstallBadParent = "InstallBadParent";

		internal const string InstallRecursiveParent = "InstallRecursiveParent";

		internal const string InstallNullParameter = "InstallNullParameter";

		internal const string InstallDictionaryMissingValues = "InstallDictionaryMissingValues";

		internal const string InstallDictionaryCorrupted = "InstallDictionaryCorrupted";

		internal const string InstallCommitException = "InstallCommitException";

		internal const string InstallRollbackException = "InstallRollbackException";

		internal const string InstallUninstallException = "InstallUninstallException";

		internal const string InstallEventException = "InstallEventException";

		internal const string InstallInstallerNotFound = "InstallInstallerNotFound";

		internal const string InstallSeverityError = "InstallSeverityError";

		internal const string InstallSeverityWarning = "InstallSeverityWarning";

		internal const string InstallLogInner = "InstallLogInner";

		internal const string InstallLogError = "InstallLogError";

		internal const string InstallLogCommitException = "InstallLogCommitException";

		internal const string InstallLogRollbackException = "InstallLogRollbackException";

		internal const string InstallLogUninstallException = "InstallLogUninstallException";

		internal const string InstallRollback = "InstallRollback";

		internal const string InstallAssemblyHelp = "InstallAssemblyHelp";

		internal const string InstallActivityRollingBack = "InstallActivityRollingBack";

		internal const string InstallActivityUninstalling = "InstallActivityUninstalling";

		internal const string InstallActivityCommitting = "InstallActivityCommitting";

		internal const string InstallActivityInstalling = "InstallActivityInstalling";

		internal const string InstallInfoTransacted = "InstallInfoTransacted";

		internal const string InstallInfoBeginInstall = "InstallInfoBeginInstall";

		internal const string InstallInfoException = "InstallInfoException";

		internal const string InstallInfoBeginRollback = "InstallInfoBeginRollback";

		internal const string InstallInfoRollbackDone = "InstallInfoRollbackDone";

		internal const string InstallInfoBeginCommit = "InstallInfoBeginCommit";

		internal const string InstallInfoCommitDone = "InstallInfoCommitDone";

		internal const string InstallInfoTransactedDone = "InstallInfoTransactedDone";

		internal const string InstallInfoBeginUninstall = "InstallInfoBeginUninstall";

		internal const string InstallInfoUninstallDone = "InstallInfoUninstallDone";

		internal const string InstallSavedStateFileCorruptedWarning = "InstallSavedStateFileCorruptedWarning";

		internal const string IncompleteEventLog = "IncompleteEventLog";

		internal const string IncompletePerformanceCounter = "IncompletePerformanceCounter";

		internal const string PerfInvalidCategoryName = "PerfInvalidCategoryName";

		internal const string NotCustomPerformanceCategory = "NotCustomPerformanceCategory";

		internal const string RemovingInstallState = "RemovingInstallState";

		internal const string InstallUnableDeleteFile = "InstallUnableDeleteFile";

		internal const string InstallInitializeException = "InstallInitializeException";

		internal const string InstallFileDoesntExist = "InstallFileDoesntExist";

		internal const string InstallFileDoesntExistCommandLine = "InstallFileDoesntExistCommandLine";

		internal const string WinNTRequired = "WinNTRequired";

		internal const string WrappedExceptionSource = "WrappedExceptionSource";

		internal const string InvalidProperty = "InvalidProperty";

		internal const string InstallRollbackNtRun = "InstallRollbackNtRun";

		internal const string InstallCommitNtRun = "InstallCommitNtRun";

		internal const string InstallUninstallNtRun = "InstallUninstallNtRun";

		internal const string InstallInstallNtRun = "InstallInstallNtRun";

		internal const string InstallHelpMessageStart = "InstallHelpMessageStart";

		internal const string InstallHelpMessageEnd = "InstallHelpMessageEnd";

		internal const string CantAddSelf = "CantAddSelf";

		internal const string Desc_Installer_HelpText = "Desc_Installer_HelpText";

		internal const string Desc_Installer_Parent = "Desc_Installer_Parent";

		internal const string Desc_AssemblyInstaller_Assembly = "Desc_AssemblyInstaller_Assembly";

		internal const string Desc_AssemblyInstaller_CommandLine = "Desc_AssemblyInstaller_CommandLine";

		internal const string Desc_AssemblyInstaller_Path = "Desc_AssemblyInstaller_Path";

		internal const string Desc_AssemblyInstaller_UseNewContext = "Desc_AssemblyInstaller_UseNewContext";

		internal const string NotAnEventLog = "NotAnEventLog";

		internal const string CreatingEventLog = "CreatingEventLog";

		internal const string RestoringEventLog = "RestoringEventLog";

		internal const string RemovingEventLog = "RemovingEventLog";

		internal const string DeletingEventLog = "DeletingEventLog";

		internal const string LocalSourceNotRegisteredWarning = "LocalSourceNotRegisteredWarning";

		internal const string Desc_CategoryResourceFile = "Desc_CategoryResourceFile";

		internal const string Desc_CategoryCount = "Desc_CategoryCount";

		internal const string Desc_Log = "Desc_Log";

		internal const string Desc_MessageResourceFile = "Desc_MessageResourceFile";

		internal const string Desc_ParameterResourceFile = "Desc_ParameterResourceFile";

		internal const string Desc_Source = "Desc_Source";

		internal const string Desc_UninstallAction = "Desc_UninstallAction";

		internal const string NotAPerformanceCounter = "NotAPerformanceCounter";

		internal const string NewCategory = "NewCategory";

		internal const string RestoringPerformanceCounter = "RestoringPerformanceCounter";

		internal const string CreatingPerformanceCounter = "CreatingPerformanceCounter";

		internal const string RemovingPerformanceCounter = "RemovingPerformanceCounter";

		internal const string PCCategoryName = "PCCategoryName";

		internal const string PCCounterName = "PCCounterName";

		internal const string PCInstanceName = "PCInstanceName";

		internal const string PCMachineName = "PCMachineName";

		internal const string PCI_CategoryHelp = "PCI_CategoryHelp";

		internal const string PCI_Counters = "PCI_Counters";

		internal const string PCI_IsMultiInstance = "PCI_IsMultiInstance";

		internal const string PCI_UninstallAction = "PCI_UninstallAction";

		private static Res loader;

		private ResourceManager resources;

		private static CultureInfo Culture => null;

		public static ResourceManager Resources => GetLoader().resources;

		internal Res()
		{
			resources = new ResourceManager("System.Configuration.Install", GetType().Assembly);
		}

		private static Res GetLoader()
		{
			if (loader == null)
			{
				Res value = new Res();
				Interlocked.CompareExchange(ref loader, value, null);
			}
			return loader;
		}

		public static string GetString(string name, params object[] args)
		{
			Res res = GetLoader();
			if (res == null)
			{
				return null;
			}
			string @string = res.resources.GetString(name, Culture);
			if (args != null && args.Length != 0)
			{
				for (int i = 0; i < args.Length; i++)
				{
					if (args[i] is string text && text.Length > 1024)
					{
						args[i] = text.Substring(0, 1021) + "...";
					}
				}
				return string.Format(CultureInfo.CurrentCulture, @string, args);
			}
			return @string;
		}

		public static string GetString(string name)
		{
			return GetLoader()?.resources.GetString(name, Culture);
		}

		public static string GetString(string name, out bool usedFallback)
		{
			usedFallback = false;
			return GetString(name);
		}

		public static object GetObject(string name)
		{
			return GetLoader()?.resources.GetObject(name, Culture);
		}
	}
}
namespace System.ComponentModel
{
	internal static class CompModSwitches
	{
		private static TraceSwitch installerDesign;

		public static TraceSwitch InstallerDesign
		{
			get
			{
				if (installerDesign == null)
				{
					installerDesign = new TraceSwitch("InstallerDesign", "Enable tracing for design-time code for installers");
				}
				return installerDesign;
			}
		}
	}
}
