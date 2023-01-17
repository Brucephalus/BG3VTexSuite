
// C:\WINDOWS\assembly\GAC_MSIL\System.ServiceProcess\2.0.0.0__b03f5f7f11d50a3a\System.ServiceProcess.dll
// System.ServiceProcess, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Permissions;
using System.ServiceProcess;
using System.ServiceProcess.Design;
using System.ServiceProcess.Telemetry;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

[assembly: CLSCompliant(true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: CompilationRelaxations(8)]
[assembly: AssemblyDescription("System.ServiceProcess.dll")]
[assembly: ComVisible(false)]
[assembly: AssemblyTitle("System.ServiceProcess.dll")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDefaultAlias("System.ServiceProcess.dll")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
internal static class FXAssembly
{
	internal const string Version = "2.0.0.0";
}
internal static class ThisAssembly
{
	internal const string Title = "System.ServiceProcess.dll";

	internal const string Description = "System.ServiceProcess.dll";

	internal const string DefaultAlias = "System.ServiceProcess.dll";

	internal const string Copyright = "© Microsoft Corporation.  All rights reserved.";

	internal const string Version = "2.0.0.0";

	internal const string InformationalVersion = "2.0.50727.9149";

	internal const int DailyBuildNumber = 50727;
}
internal static class AssemblyRef
{
	internal const string EcmaPublicKey = "b77a5c561934e089";

	internal const string EcmaPublicKeyToken = "b77a5c561934e089";

	internal const string EcmaPublicKeyFull = "00000000000000000400000000000000";

	internal const string Mscorlib = "mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemData = "System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemDataOracleClient = "System.Data.OracleClient, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string System = "System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemRuntimeRemoting = "System.Runtime.Remoting, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemWindowsForms = "System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string SystemXml = "System.Xml, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

	internal const string MicrosoftPublicKey = "b03f5f7f11d50a3a";

	internal const string MicrosoftPublicKeyToken = "b03f5f7f11d50a3a";

	internal const string MicrosoftPublicKeyFull = "002400000480000094000000060200000024000052534131000400000100010007D1FA57C4AED9F0A32E84AA0FAEFD0DE9E8FD6AEC8F87FB03766C834C99921EB23BE79AD9D5DCC1DD9AD236132102900B723CF980957FC4E177108FC607774F29E8320E92EA05ECE4E821C0A5EFE8F1645C4C0C93C1AB99285D622CAA652C1DFAD63D745D6F2DE5F17E5EAF0FC4963D261C8A12436518206DC093344D5AD293";

	internal const string SystemConfiguration = "System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemConfigurationInstall = "System.Configuration.Install, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDeployment = "System.Deployment, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDesign = "System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDirectoryServices = "System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDrawingDesign = "System.Drawing.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemDrawing = "System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemEnterpriseServices = "System.EnterpriseServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemManagement = "System.Management, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemMessaging = "System.Messaging, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemRuntimeSerializationFormattersSoap = "System.Runtime.Serialization.Formatters.Soap, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemSecurity = "System.Security, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemServiceProcess = "System.ServiceProcess, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWeb = "System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWebMobile = "System.Web.Mobile, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWebRegularExpressions = "System.Web.RegularExpressions, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string SystemWebServices = "System.Web.Services, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftVisualStudio = "Microsoft.VisualStudio, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftVisualStudioWindowsForms = "Microsoft.VisualStudio.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string VJSharpCodeProvider = "VJSharpCodeProvider, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string ASPBrowserCapsPublicKey = "b7bd7678b977bd8f";

	internal const string ASPBrowserCapsFactory = "ASP.BrowserCapsFactory, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b7bd7678b977bd8f";

	internal const string MicrosoftVSDesigner = "Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftVisualStudioWeb = "Microsoft.VisualStudio.Web, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftVSDesignerMobile = "Microsoft.VSDesigner.Mobile, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

	internal const string MicrosoftJScript = "Microsoft.JScript, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
}
namespace System.ServiceProcess
{
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
		internal const string RTL = "RTL";

		internal const string FileName = "FileName";

		internal const string ServiceStartedIncorrectly = "ServiceStartedIncorrectly";

		internal const string CallbackHandler = "CallbackHandler";

		internal const string OpenService = "OpenService";

		internal const string StartService = "StartService";

		internal const string StopService = "StopService";

		internal const string PauseService = "PauseService";

		internal const string ResumeService = "ResumeService";

		internal const string ControlService = "ControlService";

		internal const string ServiceName = "ServiceName";

		internal const string ServiceStartType = "ServiceStartType";

		internal const string ServiceDependency = "ServiceDependency";

		internal const string InstallService = "InstallService";

		internal const string InstallError = "InstallError";

		internal const string UserName = "UserName";

		internal const string UserPassword = "UserPassword";

		internal const string ButtonOK = "ButtonOK";

		internal const string ServiceUsage = "ServiceUsage";

		internal const string ServiceNameTooLongForNt4 = "ServiceNameTooLongForNt4";

		internal const string DisplayNameTooLong = "DisplayNameTooLong";

		internal const string NoService = "NoService";

		internal const string NoDisplayName = "NoDisplayName";

		internal const string OpenSC = "OpenSC";

		internal const string Timeout = "Timeout";

		internal const string CannotChangeProperties = "CannotChangeProperties";

		internal const string CannotChangeName = "CannotChangeName";

		internal const string NoServices = "NoServices";

		internal const string NoMachineName = "NoMachineName";

		internal const string BadMachineName = "BadMachineName";

		internal const string NoGivenName = "NoGivenName";

		internal const string CannotStart = "CannotStart";

		internal const string NotAService = "NotAService";

		internal const string NoInstaller = "NoInstaller";

		internal const string UserCanceledInstall = "UserCanceledInstall";

		internal const string UnattendedCannotPrompt = "UnattendedCannotPrompt";

		internal const string InvalidParameter = "InvalidParameter";

		internal const string FailedToUnloadAppDomain = "FailedToUnloadAppDomain";

		internal const string NotInPendingState = "NotInPendingState";

		internal const string ArgsCantBeNull = "ArgsCantBeNull";

		internal const string StartSuccessful = "StartSuccessful";

		internal const string StopSuccessful = "StopSuccessful";

		internal const string PauseSuccessful = "PauseSuccessful";

		internal const string ContinueSuccessful = "ContinueSuccessful";

		internal const string InstallSuccessful = "InstallSuccessful";

		internal const string UninstallSuccessful = "UninstallSuccessful";

		internal const string CommandSuccessful = "CommandSuccessful";

		internal const string StartFailed = "StartFailed";

		internal const string StopFailed = "StopFailed";

		internal const string PauseFailed = "PauseFailed";

		internal const string ContinueFailed = "ContinueFailed";

		internal const string SessionChangeFailed = "SessionChangeFailed";

		internal const string InstallFailed = "InstallFailed";

		internal const string UninstallFailed = "UninstallFailed";

		internal const string CommandFailed = "CommandFailed";

		internal const string ErrorNumber = "ErrorNumber";

		internal const string ShutdownOK = "ShutdownOK";

		internal const string ShutdownFailed = "ShutdownFailed";

		internal const string PowerEventOK = "PowerEventOK";

		internal const string PowerEventFailed = "PowerEventFailed";

		internal const string InstallOK = "InstallOK";

		internal const string TryToStop = "TryToStop";

		internal const string ServiceRemoving = "ServiceRemoving";

		internal const string ServiceRemoved = "ServiceRemoved";

		internal const string HelpText = "HelpText";

		internal const string CantStartFromCommandLine = "CantStartFromCommandLine";

		internal const string CantStartFromCommandLineTitle = "CantStartFromCommandLineTitle";

		internal const string CantRunOnWin9x = "CantRunOnWin9x";

		internal const string CantRunOnWin9xTitle = "CantRunOnWin9xTitle";

		internal const string CantControlOnWin9x = "CantControlOnWin9x";

		internal const string CantInstallOnWin9x = "CantInstallOnWin9x";

		internal const string InstallingService = "InstallingService";

		internal const string StartingService = "StartingService";

		internal const string SBAutoLog = "SBAutoLog";

		internal const string SBServiceName = "SBServiceName";

		internal const string SBServiceDescription = "SBServiceDescription";

		internal const string ServiceControllerDesc = "ServiceControllerDesc";

		internal const string SPCanPauseAndContinue = "SPCanPauseAndContinue";

		internal const string SPCanShutdown = "SPCanShutdown";

		internal const string SPCanStop = "SPCanStop";

		internal const string SPDisplayName = "SPDisplayName";

		internal const string SPDependentServices = "SPDependentServices";

		internal const string SPMachineName = "SPMachineName";

		internal const string SPServiceName = "SPServiceName";

		internal const string SPServicesDependedOn = "SPServicesDependedOn";

		internal const string SPStatus = "SPStatus";

		internal const string SPServiceType = "SPServiceType";

		internal const string ServiceProcessInstallerAccount = "ServiceProcessInstallerAccount";

		internal const string ServiceInstallerDescription = "ServiceInstallerDescription";

		internal const string ServiceInstallerServicesDependedOn = "ServiceInstallerServicesDependedOn";

		internal const string ServiceInstallerServiceName = "ServiceInstallerServiceName";

		internal const string ServiceInstallerStartType = "ServiceInstallerStartType";

		internal const string ServiceInstallerDisplayName = "ServiceInstallerDisplayName";

		internal const string Label_SetServiceLogin = "Label_SetServiceLogin";

		internal const string Label_MissmatchedPasswords = "Label_MissmatchedPasswords";

		private static Res loader;

		private ResourceManager resources;

		private static object s_InternalSyncObject;

		private static object InternalSyncObject
		{
			get
			{
				if (s_InternalSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref s_InternalSyncObject, value, null);
				}
				return s_InternalSyncObject;
			}
		}

		private static CultureInfo Culture => null;

		public static ResourceManager Resources => GetLoader().resources;

		internal Res()
		{
			resources = new ResourceManager("System.ServiceProcess", GetType().Assembly);
		}

		private static Res GetLoader()
		{
			if (loader == null)
			{
				lock (InternalSyncObject)
				{
					if (loader == null)
					{
						loader = new Res();
					}
				}
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
			if (args != null && args.Length > 0)
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

		public static object GetObject(string name)
		{
			return GetLoader()?.resources.GetObject(name, Culture);
		}
	}
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

		public const string Mscorwks = "mscorwks.dll";

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

		public const string Shfolder = "shfolder.dll";

		public const string User32 = "user32.dll";

		public const string Uxtheme = "uxtheme.dll";

		public const string WinMM = "winmm.dll";

		public const string Winspool = "winspool.drv";

		public const string Wtsapi32 = "wtsapi32.dll";

		public const string Version = "version.dll";

		public const string Vsassert = "vsassert.dll";

		public const string Shlwapi = "shlwapi.dll";

		public const string Crypt32 = "crypt32.dll";

		internal const string Odbc32 = "odbc32.dll";

		internal const string SNI = "System.Data.dll";

		internal const string OciDll = "oci.dll";

		internal const string OraMtsDll = "oramts.dll";
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

		internal const int SqlException = -2146232060;

		internal const int OdbcException = -2146232009;

		internal const int OracleException = -2146232008;

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
namespace System.ServiceProcess
{
	internal static class NativeMethods
	{
		internal static class LoadLibraryHelper
		{
			[SecurityCritical]
			[SecurityTreatAsSafe]
			private static bool IsKnowledgeBase2533623OrGreater()
			{
				bool result = false;
				IntPtr hModule = IntPtr.Zero;
				if (GetModuleHandleEx(GetModuleHandleFlags.None, "kernel32.dll", out hModule) && hModule != IntPtr.Zero)
				{
					try
					{
						return GetProcAddress(hModule, "AddDllDirectory") != IntPtr.Zero;
					}
					finally
					{
						FreeLibrary(hModule);
					}
				}
				return result;
			}

			[SecurityCritical]
			internal static IntPtr SecureLoadLibraryEx(string lpFileName, IntPtr hFile, LoadLibraryFlags dwFlags)
			{
				if (!IsKnowledgeBase2533623OrGreater() && (dwFlags & LoadLibraryFlags.LOAD_LIBRARY_SEARCH_APPLICATION_DIR & LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS & LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR & LoadLibraryFlags.LOAD_LIBRARY_SEARCH_SYSTEM32 & LoadLibraryFlags.LOAD_LIBRARY_SEARCH_USER_DIRS) != 0)
				{
					dwFlags &= ~(LoadLibraryFlags.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LoadLibraryFlags.LOAD_LIBRARY_SEARCH_SYSTEM32 | LoadLibraryFlags.LOAD_LIBRARY_SEARCH_USER_DIRS);
				}
				return LoadLibraryEx(lpFileName, hFile, dwFlags);
			}
		}

		[ComVisible(false)]
		public enum StructFormat
		{
			Ansi = 1,
			Unicode,
			Auto
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public class ENUM_SERVICE_STATUS
		{
			public string serviceName;

			public string displayName;

			public int serviceType;

			public int currentState;

			public int controlsAccepted;

			public int win32ExitCode;

			public int serviceSpecificExitCode;

			public int checkPoint;

			public int waitHint;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public class ENUM_SERVICE_STATUS_PROCESS
		{
			public string serviceName;

			public string displayName;

			public int serviceType;

			public int currentState;

			public int controlsAccepted;

			public int win32ExitCode;

			public int serviceSpecificExitCode;

			public int checkPoint;

			public int waitHint;

			public int processID;

			public int serviceFlags;
		}

		[Flags]
		public enum LoadLibraryFlags : uint
		{
			None = 0u,
			DONT_RESOLVE_DLL_REFERENCES = 1u,
			LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x10u,
			LOAD_LIBRARY_AS_DATAFILE = 2u,
			LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x40u,
			LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20u,
			LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x200u,
			LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x1000u,
			LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x100u,
			LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800u,
			LOAD_LIBRARY_SEARCH_USER_DIRS = 0x400u,
			LOAD_WITH_ALTERED_SEARCH_PATH = 8u
		}

		[Flags]
		public enum GetModuleHandleFlags : uint
		{
			None = 0u,
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 4u,
			GET_MODULE_HANDLE_EX_FLAG_PIN = 1u,
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 2u
		}

		public struct SERVICE_STATUS
		{
			public int serviceType;

			public int currentState;

			public int controlsAccepted;

			public int win32ExitCode;

			public int serviceSpecificExitCode;

			public int checkPoint;

			public int waitHint;
		}

		[StructLayout(LayoutKind.Sequential)]
		public class QUERY_SERVICE_CONFIG
		{
			public int dwServiceType;

			public int dwStartType;

			public int dwErrorControl;

			public unsafe char* lpBinaryPathName;

			public unsafe char* lpLoadOrderGroup;

			public int dwTagId;

			public unsafe char* lpDependencies;

			public unsafe char* lpServiceStartName;

			public unsafe char* lpDisplayName;
		}

		[StructLayout(LayoutKind.Sequential)]
		public class SERVICE_TABLE_ENTRY
		{
			public IntPtr name;

			public Delegate callback;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public class LSA_UNICODE_STRING
		{
			public short length;

			public short maximumLength;

			public string buffer;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public class LSA_UNICODE_STRING_withPointer
		{
			public short length;

			public short maximumLength;

			public IntPtr pwstr = (IntPtr)0;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public class LSA_OBJECT_ATTRIBUTES
		{
			public int length;

			public IntPtr rootDirectory = (IntPtr)0;

			public IntPtr pointerLsaString = (IntPtr)0;

			public int attributes;

			public IntPtr pointerSecurityDescriptor = (IntPtr)0;

			public IntPtr pointerSecurityQualityOfService = (IntPtr)0;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct SERVICE_DESCRIPTION
		{
			public IntPtr description;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct SERVICE_FAILURE_ACTIONS
		{
			public uint dwResetPeriod;

			public IntPtr rebootMsg;

			public IntPtr command;

			public uint numActions;

			public unsafe SC_ACTION* actions;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct SC_ACTION
		{
			public int type;

			public uint delay;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public class WTSSESSION_NOTIFICATION
		{
			public int size;

			public int sessionId;
		}

		public delegate void ServiceMainCallback(int argCount, IntPtr argPointer);

		public delegate void ServiceControlCallback(int control);

		public delegate int ServiceControlCallbackEx(int control, int eventType, IntPtr eventData, IntPtr eventContext);

		public const int MAX_COMPUTERNAME_LENGTH = 31;

		public const int WM_POWERBROADCAST = 536;

		public const int NO_ERROR = 0;

		public const int BROADCAST_QUERY_DENY = 1112363332;

		public const int PBT_APMBATTERYLOW = 9;

		public const int PBT_APMOEMEVENT = 11;

		public const int PBT_APMPOWERSTATUSCHANGE = 10;

		public const int PBT_APMQUERYSUSPEND = 0;

		public const int PBT_APMQUERYSUSPENDFAILED = 2;

		public const int PBT_APMRESUMEAUTOMATIC = 18;

		public const int PBT_APMRESUMECRITICAL = 6;

		public const int PBT_APMRESUMESUSPEND = 7;

		public const int PBT_APMSUSPEND = 4;

		public const int ERROR_MORE_DATA = 234;

		public const int ERROR_INSUFFICIENT_BUFFER = 122;

		public const int MB_OK = 0;

		public const int MB_OKCANCEL = 1;

		public const int MB_ABORTRETRYIGNORE = 2;

		public const int MB_YESNOCANCEL = 3;

		public const int MB_YESNO = 4;

		public const int MB_RETRYCANCEL = 5;

		public const int MB_ICONHAND = 16;

		public const int MB_ICONQUESTION = 32;

		public const int MB_ICONEXCLAMATION = 48;

		public const int MB_ICONASTERISK = 64;

		public const int MB_USERICON = 128;

		public const int MB_ICONWARNING = 48;

		public const int MB_ICONERROR = 16;

		public const int MB_ICONINFORMATION = 64;

		public const int MB_DEFBUTTON1 = 0;

		public const int MB_DEFBUTTON2 = 256;

		public const int MB_DEFBUTTON3 = 512;

		public const int MB_DEFBUTTON4 = 768;

		public const int MB_APPLMODAL = 0;

		public const int MB_SYSTEMMODAL = 4096;

		public const int MB_TASKMODAL = 8192;

		public const int MB_HELP = 16384;

		public const int MB_NOFOCUS = 32768;

		public const int MB_SETFOREGROUND = 65536;

		public const int MB_DEFAULT_DESKTOP_ONLY = 131072;

		public const int MB_TOPMOST = 262144;

		public const int MB_RIGHT = 524288;

		public const int MB_RTLREADING = 1048576;

		public const int MB_SERVICE_NOTIFICATION = 2097152;

		public const int MB_SERVICE_NOTIFICATION_NT3X = 262144;

		public const int MB_TYPEMASK = 15;

		public const int MB_ICONMASK = 240;

		public const int MB_DEFMASK = 3840;

		public const int MB_MODEMASK = 12288;

		public const int MB_MISCMASK = 49152;

		public const int STANDARD_RIGHTS_DELETE = 65536;

		public const int STANDARD_RIGHTS_REQUIRED = 983040;

		public const int SERVICE_NO_CHANGE = -1;

		public const int ACCESS_TYPE_CHANGE_CONFIG = 2;

		public const int ACCESS_TYPE_ENUMERATE_DEPENDENTS = 8;

		public const int ACCESS_TYPE_INTERROGATE = 128;

		public const int ACCESS_TYPE_PAUSE_CONTINUE = 64;

		public const int ACCESS_TYPE_QUERY_CONFIG = 1;

		public const int ACCESS_TYPE_QUERY_STATUS = 4;

		public const int ACCESS_TYPE_START = 16;

		public const int ACCESS_TYPE_STOP = 32;

		public const int ACCESS_TYPE_USER_DEFINED_CONTROL = 256;

		public const int ACCESS_TYPE_ALL = 983551;

		public const int ACCEPT_NETBINDCHANGE = 16;

		public const int ACCEPT_PAUSE_CONTINUE = 2;

		public const int ACCEPT_PARAMCHANGE = 8;

		public const int ACCEPT_POWEREVENT = 64;

		public const int ACCEPT_SHUTDOWN = 4;

		public const int ACCEPT_STOP = 1;

		public const int ACCEPT_SESSIONCHANGE = 128;

		public const int CONTROL_CONTINUE = 3;

		public const int CONTROL_INTERROGATE = 4;

		public const int CONTROL_NETBINDADD = 7;

		public const int CONTROL_NETBINDDISABLE = 10;

		public const int CONTROL_NETBINDENABLE = 9;

		public const int CONTROL_NETBINDREMOVE = 8;

		public const int CONTROL_PARAMCHANGE = 6;

		public const int CONTROL_PAUSE = 2;

		public const int CONTROL_POWEREVENT = 13;

		public const int CONTROL_SHUTDOWN = 5;

		public const int CONTROL_STOP = 1;

		public const int CONTROL_DEVICEEVENT = 11;

		public const int CONTROL_SESSIONCHANGE = 14;

		public const int SERVICE_CONFIG_DESCRIPTION = 1;

		public const int SERVICE_CONFIG_FAILURE_ACTIONS = 2;

		public const int ERROR_CONTROL_CRITICAL = 3;

		public const int ERROR_CONTROL_IGNORE = 0;

		public const int ERROR_CONTROL_NORMAL = 1;

		public const int ERROR_CONTROL_SEVERE = 2;

		public const int SC_MANAGER_CONNECT = 1;

		public const int SC_MANAGER_CREATE_SERVICE = 2;

		public const int SC_MANAGER_ENUMERATE_SERVICE = 4;

		public const int SC_MANAGER_LOCK = 8;

		public const int SC_MANAGER_MODIFY_BOOT_CONFIG = 32;

		public const int SC_MANAGER_QUERY_LOCK_STATUS = 16;

		public const int SC_MANAGER_ALL = 983103;

		public const int SC_ENUM_PROCESS_INFO = 0;

		public const int SERVICE_QUERY_CONFIG = 1;

		public const int SERVICE_CHANGE_CONFIG = 2;

		public const int SERVICE_QUERY_STATUS = 4;

		public const int SERVICE_ENUMERATE_DEPENDENTS = 8;

		public const int SERVICE_START = 16;

		public const int SERVICE_STOP = 32;

		public const int SERVICE_PAUSE_CONTINUE = 64;

		public const int SERVICE_INTERROGATE = 128;

		public const int SERVICE_USER_DEFINED_CONTROL = 256;

		public const int SERVICE_ALL_ACCESS = 983551;

		public const int SERVICE_TYPE_ADAPTER = 4;

		public const int SERVICE_TYPE_FILE_SYSTEM_DRIVER = 2;

		public const int SERVICE_TYPE_INTERACTIVE_PROCESS = 256;

		public const int SERVICE_TYPE_KERNEL_DRIVER = 1;

		public const int SERVICE_TYPE_RECOGNIZER_DRIVER = 8;

		public const int SERVICE_TYPE_WIN32_OWN_PROCESS = 16;

		public const int SERVICE_TYPE_WIN32_SHARE_PROCESS = 32;

		public const int SERVICE_TYPE_WIN32 = 48;

		public const int SERVICE_TYPE_DRIVER = 11;

		public const int SERVICE_TYPE_ALL = 319;

		public const int START_TYPE_AUTO = 2;

		public const int START_TYPE_BOOT = 0;

		public const int START_TYPE_DEMAND = 3;

		public const int START_TYPE_DISABLED = 4;

		public const int START_TYPE_SYSTEM = 1;

		public const int SERVICE_ACTIVE = 1;

		public const int SERVICE_INACTIVE = 2;

		public const int SERVICE_STATE_ALL = 3;

		public const int STATE_CONTINUE_PENDING = 5;

		public const int STATE_PAUSED = 7;

		public const int STATE_PAUSE_PENDING = 6;

		public const int STATE_RUNNING = 4;

		public const int STATE_START_PENDING = 2;

		public const int STATE_STOPPED = 1;

		public const int STATE_STOP_PENDING = 3;

		public const int STATUS_ACTIVE = 1;

		public const int STATUS_INACTIVE = 2;

		public const int STATUS_ALL = 3;

		public const int POLICY_VIEW_LOCAL_INFORMATION = 1;

		public const int POLICY_VIEW_AUDIT_INFORMATION = 2;

		public const int POLICY_GET_PRIVATE_INFORMATION = 4;

		public const int POLICY_TRUST_ADMIN = 8;

		public const int POLICY_CREATE_ACCOUNT = 16;

		public const int POLICY_CREATE_SECRET = 32;

		public const int POLICY_CREATE_PRIVILEGE = 64;

		public const int POLICY_SET_DEFAULT_QUOTA_LIMITS = 128;

		public const int POLICY_SET_AUDIT_REQUIREMENTS = 256;

		public const int POLICY_AUDIT_LOG_ADMIN = 512;

		public const int POLICY_SERVER_ADMIN = 1024;

		public const int POLICY_LOOKUP_NAMES = 2048;

		public const int POLICY_ALL_ACCESS = 985087;

		public const int STATUS_OBJECT_NAME_NOT_FOUND = -1073741772;

		public const int WTS_CONSOLE_CONNECT = 1;

		public const int WTS_CONSOLE_DISCONNECT = 2;

		public const int WTS_REMOTE_CONNECT = 3;

		public const int WTS_REMOTE_DISCONNECT = 4;

		public const int WTS_SESSION_LOGON = 5;

		public const int WTS_SESSION_LOGOFF = 6;

		public const int WTS_SESSION_LOCK = 7;

		public const int WTS_SESSION_UNLOCK = 8;

		public const int WTS_SESSION_REMOTE_CONTROL = 9;

		public static readonly string DATABASE_ACTIVE = "ServicesActive";

		public static readonly string DATABASE_FAILED = "ServicesFailed";

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr OpenService(IntPtr databaseHandle, string serviceName, int access);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr RegisterServiceCtrlHandler(string serviceName, Delegate callback);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, Delegate callback, IntPtr userData);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public unsafe static extern bool SetServiceStatus(IntPtr serviceStatusHandle, SERVICE_STATUS* status);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool StartServiceCtrlDispatcher(IntPtr entry);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr CreateService(IntPtr databaseHandle, string serviceName, string displayName, int access, int serviceType, int startType, int errorControl, string binaryPath, string loadOrderGroup, IntPtr pTagId, string dependencies, string servicesStartName, string password);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool DeleteService(IntPtr serviceHandle);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int LsaOpenPolicy(LSA_UNICODE_STRING systemName, IntPtr pointerObjectAttributes, int desiredAccess, out IntPtr pointerPolicyHandle);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int LsaAddAccountRights(IntPtr policyHandle, byte[] accountSid, LSA_UNICODE_STRING userRights, int countOfRights);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int LsaRemoveAccountRights(IntPtr policyHandle, byte[] accountSid, bool allRights, LSA_UNICODE_STRING userRights, int countOfRights);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int LsaEnumerateAccountRights(IntPtr policyHandle, byte[] accountSid, out IntPtr pLsaUnicodeStringUserRights, out int RightsCount);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool LookupAccountName(string systemName, string accountName, byte[] sid, int[] sidLen, char[] refDomainName, int[] domNameLen, [In][Out] int[] sidNameUse);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool GetComputerName(StringBuilder lpBuffer, ref int nSize);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool ChangeServiceConfig2(IntPtr serviceHandle, uint infoLevel, ref SERVICE_DESCRIPTION serviceDesc);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		[SecurityCritical]
		[Obsolete("Use LoadLibraryHelper.SafeLoadLibraryEx instead")]
		internal static extern IntPtr LoadLibraryEx([In][MarshalAs(UnmanagedType.LPTStr)] string lpFileName, IntPtr hFile, [In] LoadLibraryFlags dwFlags);

		[DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr GetProcAddress([In] IntPtr hModule, [In][MarshalAs(UnmanagedType.LPStr)] string lpProcName);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		[SecurityCritical]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool GetModuleHandleEx([In] GetModuleHandleFlags dwFlags, [Optional][In][MarshalAs(UnmanagedType.LPTStr)] string lpModuleName, out IntPtr hModule);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool FreeLibrary([In] IntPtr hModule);
	}
	public enum PowerBroadcastStatus
	{
		BatteryLow = 9,
		OemEvent = 11,
		PowerStatusChange = 10,
		QuerySuspend = 0,
		QuerySuspendFailed = 2,
		ResumeAutomatic = 18,
		ResumeCritical = 6,
		ResumeSuspend = 7,
		Suspend = 4
	}
	[SuppressUnmanagedCodeSecurity]
	[ComVisible(false)]
	internal static class SafeNativeMethods
	{
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr OpenSCManager(string machineName, string databaseName, int access);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		public static extern bool CloseServiceHandle(IntPtr handle);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int LsaClose(IntPtr objectHandle);

		[DllImport("advapi32.dll")]
		public static extern int LsaFreeMemory(IntPtr ptr);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int LsaNtStatusToWinError(int ntStatus);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool GetServiceKeyName(IntPtr SCMHandle, string displayName, StringBuilder shortName, ref int shortNameLength);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool GetServiceDisplayName(IntPtr SCMHandle, string shortName, StringBuilder displayName, ref int displayNameLength);
	}
}
internal class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
	internal SafeServiceHandle(IntPtr handle, bool ownsHandle)
		: base(ownsHandle)
	{
		SetHandle(handle);
	}

	protected override bool ReleaseHandle()
	{
		return SafeNativeMethods.CloseServiceHandle(handle);
	}
}
namespace System.ServiceProcess
{
	public enum ServiceAccount
	{
		LocalService,
		NetworkService,
		LocalSystem,
		User
	}
	[InstallerType(typeof(ServiceProcessInstaller))]
	public class ServiceBase : Component
	{
		private delegate void DeferredHandlerDelegate();

		private delegate void DeferredHandlerDelegateCommand(int command);

		private delegate void DeferredHandlerDelegateAdvanced(int eventType, IntPtr eventData);

		private delegate void DeferredHandlerDelegateAdvancedSession(int eventType, int sessionId);

		public const int MaxNameLength = 80;

		private NativeMethods.SERVICE_STATUS status = default(NativeMethods.SERVICE_STATUS);

		private IntPtr statusHandle;

		private NativeMethods.ServiceControlCallback commandCallback;

		private NativeMethods.ServiceControlCallbackEx commandCallbackEx;

		private NativeMethods.ServiceMainCallback mainCallback;

		private IntPtr handleName;

		private ManualResetEvent startCompletedSignal;

		private int acceptedCommands;

		private bool autoLog;

		private string serviceName;

		private EventLog eventLog;

		private bool nameFrozen;

		private bool commandPropsFrozen;

		private bool disposed;

		private bool initialized;

		private bool isServiceHosted;

		[ServiceProcessDescription("SBAutoLog")]
		[DefaultValue(true)]
		public bool AutoLog
		{
			get
			{
				return autoLog;
			}
			set
			{
				autoLog = value;
			}
		}

		[ComVisible(false)]
		public int ExitCode
		{
			get
			{
				return status.win32ExitCode;
			}
			set
			{
				status.win32ExitCode = value;
			}
		}

		[DefaultValue(false)]
		public bool CanHandlePowerEvent
		{
			get
			{
				return (acceptedCommands & 0x40) != 0;
			}
			set
			{
				if (commandPropsFrozen)
				{
					throw new InvalidOperationException(Res.GetString("CannotChangeProperties"));
				}
				if (value)
				{
					acceptedCommands |= 64;
				}
				else
				{
					acceptedCommands &= -65;
				}
			}
		}

		[ComVisible(false)]
		[DefaultValue(false)]
		public bool CanHandleSessionChangeEvent
		{
			get
			{
				return (acceptedCommands & 0x80) != 0;
			}
			set
			{
				if (commandPropsFrozen)
				{
					throw new InvalidOperationException(Res.GetString("CannotChangeProperties"));
				}
				if (value)
				{
					acceptedCommands |= 128;
				}
				else
				{
					acceptedCommands &= -129;
				}
			}
		}

		[DefaultValue(false)]
		public bool CanPauseAndContinue
		{
			get
			{
				return (acceptedCommands & 2) != 0;
			}
			set
			{
				if (commandPropsFrozen)
				{
					throw new InvalidOperationException(Res.GetString("CannotChangeProperties"));
				}
				if (value)
				{
					acceptedCommands |= 2;
				}
				else
				{
					acceptedCommands &= -3;
				}
			}
		}

		[DefaultValue(false)]
		public bool CanShutdown
		{
			get
			{
				return (acceptedCommands & 4) != 0;
			}
			set
			{
				if (commandPropsFrozen)
				{
					throw new InvalidOperationException(Res.GetString("CannotChangeProperties"));
				}
				if (value)
				{
					acceptedCommands |= 4;
				}
				else
				{
					acceptedCommands &= -5;
				}
			}
		}

		[DefaultValue(true)]
		public bool CanStop
		{
			get
			{
				return (acceptedCommands & 1) != 0;
			}
			set
			{
				if (commandPropsFrozen)
				{
					throw new InvalidOperationException(Res.GetString("CannotChangeProperties"));
				}
				if (value)
				{
					acceptedCommands |= 1;
				}
				else
				{
					acceptedCommands &= -2;
				}
			}
		}

		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public virtual EventLog EventLog
		{
			get
			{
				if (eventLog == null)
				{
					eventLog = new EventLog();
					eventLog.Source = ServiceName;
					eventLog.Log = "Application";
				}
				return eventLog;
			}
		}

		[EditorBrowsable(EditorBrowsableState.Advanced)]
		protected IntPtr ServiceHandle
		{
			get
			{
				new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Demand();
				return statusHandle;
			}
		}

		[ServiceProcessDescription("SBServiceName")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public string ServiceName
		{
			get
			{
				return serviceName;
			}
			set
			{
				if (nameFrozen)
				{
					throw new InvalidOperationException(Res.GetString("CannotChangeName"));
				}
				if (value != "" && !ServiceController.ValidServiceName(value))
				{
					throw new ArgumentException(Res.GetString("ServiceName", value, 80.ToString(CultureInfo.CurrentCulture)));
				}
				serviceName = value;
			}
		}

		private static bool IsRTLResources => Res.GetString("RTL") != "RTL_False";

		public ServiceBase()
		{
			acceptedCommands = 1;
			AutoLog = true;
			ServiceName = "";
			SendServiceStartTelemetry();
		}

		[ComVisible(false)]
		public unsafe void RequestAdditionalTime(int milliseconds)
		{
			fixed (NativeMethods.SERVICE_STATUS* ptr = &status)
			{
				if (status.currentState != 5 && status.currentState != 2 && status.currentState != 3 && status.currentState != 6)
				{
					throw new InvalidOperationException(Res.GetString("NotInPendingState"));
				}
				status.waitHint = milliseconds;
				status.checkPoint++;
				NativeMethods.SetServiceStatus(statusHandle, ptr);
			}
		}

		protected override void Dispose(bool disposing)
		{
			if (handleName != (IntPtr)0)
			{
				Marshal.FreeHGlobal(handleName);
				handleName = (IntPtr)0;
			}
			nameFrozen = false;
			commandPropsFrozen = false;
			disposed = true;
			base.Dispose(disposing);
		}

		protected virtual void OnContinue()
		{
		}

		protected virtual void OnPause()
		{
		}

		protected virtual bool OnPowerEvent(PowerBroadcastStatus powerStatus)
		{
			return true;
		}

		protected virtual void OnSessionChange(SessionChangeDescription changeDescription)
		{
		}

		protected virtual void OnShutdown()
		{
		}

		protected virtual void OnStart(string[] args)
		{
		}

		protected virtual void OnStop()
		{
		}

		private unsafe void DeferredContinue()
		{
			fixed (NativeMethods.SERVICE_STATUS* ptr = &status)
			{
				try
				{
					OnContinue();
					WriteEventLogEntry(Res.GetString("ContinueSuccessful"));
					status.currentState = 4;
				}
				catch (Exception ex)
				{
					status.currentState = 7;
					WriteEventLogEntry(Res.GetString("ContinueFailed", ex.ToString()), EventLogEntryType.Error);
					throw;
				}
				catch
				{
					status.currentState = 7;
					WriteEventLogEntry(Res.GetString("ContinueFailed", string.Empty), EventLogEntryType.Error);
					throw;
				}
				finally
				{
					NativeMethods.SetServiceStatus(statusHandle, ptr);
				}
			}
		}

		private void DeferredCustomCommand(int command)
		{
			try
			{
				OnCustomCommand(command);
				WriteEventLogEntry(Res.GetString("CommandSuccessful"));
			}
			catch (Exception ex)
			{
				WriteEventLogEntry(Res.GetString("CommandFailed", ex.ToString()), EventLogEntryType.Error);
				throw;
			}
			catch
			{
				WriteEventLogEntry(Res.GetString("CommandFailed", string.Empty), EventLogEntryType.Error);
				throw;
			}
		}

		private unsafe void DeferredPause()
		{
			fixed (NativeMethods.SERVICE_STATUS* ptr = &status)
			{
				try
				{
					OnPause();
					WriteEventLogEntry(Res.GetString("PauseSuccessful"));
					status.currentState = 7;
				}
				catch (Exception ex)
				{
					status.currentState = 4;
					WriteEventLogEntry(Res.GetString("PauseFailed", ex.ToString()), EventLogEntryType.Error);
					throw;
				}
				catch
				{
					status.currentState = 4;
					WriteEventLogEntry(Res.GetString("PauseFailed", string.Empty), EventLogEntryType.Error);
					throw;
				}
				finally
				{
					NativeMethods.SetServiceStatus(statusHandle, ptr);
				}
			}
		}

		private void DeferredPowerEvent(int eventType, IntPtr eventData)
		{
			try
			{
				OnPowerEvent((PowerBroadcastStatus)eventType);
				WriteEventLogEntry(Res.GetString("PowerEventOK"));
			}
			catch (Exception ex)
			{
				WriteEventLogEntry(Res.GetString("PowerEventFailed", ex.ToString()), EventLogEntryType.Error);
				throw;
			}
			catch
			{
				WriteEventLogEntry(Res.GetString("PowerEventFailed", string.Empty), EventLogEntryType.Error);
				throw;
			}
		}

		private void DeferredSessionChange(int eventType, int sessionId)
		{
			try
			{
				OnSessionChange(new SessionChangeDescription((SessionChangeReason)eventType, sessionId));
			}
			catch (Exception ex)
			{
				WriteEventLogEntry(Res.GetString("SessionChangeFailed", ex.ToString()), EventLogEntryType.Error);
				throw;
			}
			catch
			{
				WriteEventLogEntry(Res.GetString("SessionChangeFailed", string.Empty), EventLogEntryType.Error);
				throw;
			}
		}

		private unsafe void DeferredStop()
		{
			fixed (NativeMethods.SERVICE_STATUS* ptr = &status)
			{
				int currentState = status.currentState;
				status.checkPoint = 0;
				status.waitHint = 0;
				status.currentState = 3;
				NativeMethods.SetServiceStatus(statusHandle, ptr);
				try
				{
					OnStop();
					WriteEventLogEntry(Res.GetString("StopSuccessful"));
					status.currentState = 1;
					NativeMethods.SetServiceStatus(statusHandle, ptr);
					if (isServiceHosted)
					{
						try
						{
							AppDomain.Unload(AppDomain.CurrentDomain);
						}
						catch (CannotUnloadAppDomainException ex)
						{
							WriteEventLogEntry(Res.GetString("FailedToUnloadAppDomain", AppDomain.CurrentDomain.FriendlyName, ex.Message), EventLogEntryType.Error);
						}
					}
				}
				catch (Exception ex2)
				{
					status.currentState = currentState;
					NativeMethods.SetServiceStatus(statusHandle, ptr);
					WriteEventLogEntry(Res.GetString("StopFailed", ex2.ToString()), EventLogEntryType.Error);
					throw;
				}
				catch
				{
					status.currentState = currentState;
					NativeMethods.SetServiceStatus(statusHandle, ptr);
					WriteEventLogEntry(Res.GetString("StopFailed", string.Empty), EventLogEntryType.Error);
					throw;
				}
			}
		}

		private unsafe void DeferredShutdown()
		{
			try
			{
				OnShutdown();
				WriteEventLogEntry(Res.GetString("ShutdownOK"));
				if (status.currentState != 7 && status.currentState != 4)
				{
					return;
				}
				fixed (NativeMethods.SERVICE_STATUS* ptr = &status)
				{
					status.checkPoint = 0;
					status.waitHint = 0;
					status.currentState = 1;
					NativeMethods.SetServiceStatus(statusHandle, ptr);
					if (isServiceHosted)
					{
						try
						{
							AppDomain.Unload(AppDomain.CurrentDomain);
							return;
						}
						catch (CannotUnloadAppDomainException ex)
						{
							WriteEventLogEntry(Res.GetString("FailedToUnloadAppDomain", AppDomain.CurrentDomain.FriendlyName, ex.Message), EventLogEntryType.Error);
							return;
						}
					}
				}
			}
			catch (Exception ex2)
			{
				WriteEventLogEntry(Res.GetString("ShutdownFailed", ex2.ToString()), EventLogEntryType.Error);
				throw;
			}
			catch
			{
				WriteEventLogEntry(Res.GetString("ShutdownFailed", string.Empty), EventLogEntryType.Error);
				throw;
			}
		}

		protected virtual void OnCustomCommand(int command)
		{
		}

		public static void Run(ServiceBase[] services)
		{
			if (services == null || services.Length == 0)
			{
				throw new ArgumentException(Res.GetString("NoServices"));
			}
			if (Environment.OSVersion.Platform != PlatformID.Win32NT)
			{
				string @string = Res.GetString("CantRunOnWin9x");
				string string2 = Res.GetString("CantRunOnWin9xTitle");
				LateBoundMessageBoxShow(@string, string2);
				return;
			}
			IntPtr intPtr = Marshal.AllocHGlobal((IntPtr)((services.Length + 1) * Marshal.SizeOf(typeof(NativeMethods.SERVICE_TABLE_ENTRY))));
			NativeMethods.SERVICE_TABLE_ENTRY[] array = new NativeMethods.SERVICE_TABLE_ENTRY[services.Length];
			bool multipleServices = services.Length > 1;
			IntPtr intPtr2 = (IntPtr)0;
			for (int i = 0; i < services.Length; i++)
			{
				services[i].Initialize(multipleServices);
				array[i] = services[i].GetEntry();
				intPtr2 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(NativeMethods.SERVICE_TABLE_ENTRY)) * i);
				Marshal.StructureToPtr(array[i], intPtr2, fDeleteOld: true);
			}
			NativeMethods.SERVICE_TABLE_ENTRY sERVICE_TABLE_ENTRY = new NativeMethods.SERVICE_TABLE_ENTRY();
			sERVICE_TABLE_ENTRY.callback = null;
			sERVICE_TABLE_ENTRY.name = (IntPtr)0;
			intPtr2 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(NativeMethods.SERVICE_TABLE_ENTRY)) * services.Length);
			Marshal.StructureToPtr(sERVICE_TABLE_ENTRY, intPtr2, fDeleteOld: true);
			bool flag = NativeMethods.StartServiceCtrlDispatcher(intPtr);
			string text = "";
			if (!flag)
			{
				text = new Win32Exception().Message;
				string string3 = Res.GetString("CantStartFromCommandLine");
				if (Environment.UserInteractive)
				{
					string string4 = Res.GetString("CantStartFromCommandLineTitle");
					LateBoundMessageBoxShow(string3, string4);
				}
				else
				{
					Console.WriteLine(string3);
				}
			}
			foreach (ServiceBase serviceBase in services)
			{
				serviceBase.Dispose();
				if (!flag && serviceBase.EventLog.Source.Length != 0)
				{
					serviceBase.WriteEventLogEntry(Res.GetString("StartFailed", text), EventLogEntryType.Error);
				}
			}
		}

		public static void Run(ServiceBase service)
		{
			if (service == null)
			{
				throw new ArgumentException(Res.GetString("NoServices"));
			}
			Run(new ServiceBase[1] { service });
		}

		public void Stop()
		{
			DeferredStop();
		}

		private void Initialize(bool multipleServices)
		{
			if (!initialized)
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (!multipleServices)
				{
					status.serviceType = 16;
				}
				else
				{
					status.serviceType = 32;
				}
				status.currentState = 2;
				status.controlsAccepted = 0;
				status.win32ExitCode = 0;
				status.serviceSpecificExitCode = 0;
				status.checkPoint = 0;
				status.waitHint = 0;
				mainCallback = ServiceMainCallback;
				commandCallback = ServiceCommandCallback;
				commandCallbackEx = ServiceCommandCallbackEx;
				handleName = Marshal.StringToHGlobalUni(ServiceName);
				initialized = true;
			}
		}

		private NativeMethods.SERVICE_TABLE_ENTRY GetEntry()
		{
			NativeMethods.SERVICE_TABLE_ENTRY sERVICE_TABLE_ENTRY = new NativeMethods.SERVICE_TABLE_ENTRY();
			nameFrozen = true;
			sERVICE_TABLE_ENTRY.callback = mainCallback;
			sERVICE_TABLE_ENTRY.name = handleName;
			return sERVICE_TABLE_ENTRY;
		}

		private static void LateBoundMessageBoxShow(string message, string title)
		{
			int num = 0;
			if (IsRTLResources)
			{
				num |= 0x180000;
			}
			Type type = Type.GetType("System.Windows.Forms.MessageBox, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
			Type type2 = Type.GetType("System.Windows.Forms.MessageBoxButtons, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
			Type type3 = Type.GetType("System.Windows.Forms.MessageBoxIcon, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
			Type type4 = Type.GetType("System.Windows.Forms.MessageBoxDefaultButton, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
			Type type5 = Type.GetType("System.Windows.Forms.MessageBoxOptions, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
			type.InvokeMember("Show", BindingFlags.Static | BindingFlags.Public | BindingFlags.InvokeMethod, null, null, new object[6]
			{
				message,
				title,
				Enum.ToObject(type2, 0),
				Enum.ToObject(type3, 0),
				Enum.ToObject(type4, 0),
				Enum.ToObject(type5, num)
			}, CultureInfo.InvariantCulture);
		}

		private int ServiceCommandCallbackEx(int command, int eventType, IntPtr eventData, IntPtr eventContext)
		{
			int result = 0;
			switch (command)
			{
			case 13:
			{
				DeferredHandlerDelegateAdvanced deferredHandlerDelegateAdvanced = DeferredPowerEvent;
				deferredHandlerDelegateAdvanced.BeginInvoke(eventType, eventData, null, null);
				break;
			}
			case 14:
			{
				DeferredHandlerDelegateAdvancedSession deferredHandlerDelegateAdvancedSession = DeferredSessionChange;
				NativeMethods.WTSSESSION_NOTIFICATION wTSSESSION_NOTIFICATION = new NativeMethods.WTSSESSION_NOTIFICATION();
				Marshal.PtrToStructure(eventData, wTSSESSION_NOTIFICATION);
				deferredHandlerDelegateAdvancedSession.BeginInvoke(eventType, wTSSESSION_NOTIFICATION.sessionId, null, null);
				break;
			}
			default:
				ServiceCommandCallback(command);
				break;
			}
			return result;
		}

		private unsafe void ServiceCommandCallback(int command)
		{
			fixed (NativeMethods.SERVICE_STATUS* ptr = &status)
			{
				if (command == 4)
				{
					NativeMethods.SetServiceStatus(statusHandle, ptr);
				}
				else
				{
					if (status.currentState == 5 || status.currentState == 2 || status.currentState == 3 || status.currentState == 6)
					{
						return;
					}
					switch (command)
					{
					case 3:
						if (status.currentState == 7)
						{
							status.currentState = 5;
							NativeMethods.SetServiceStatus(statusHandle, ptr);
							DeferredHandlerDelegate deferredHandlerDelegate3 = DeferredContinue;
							deferredHandlerDelegate3.BeginInvoke(null, null);
						}
						break;
					case 2:
						if (status.currentState == 4)
						{
							status.currentState = 6;
							NativeMethods.SetServiceStatus(statusHandle, ptr);
							DeferredHandlerDelegate deferredHandlerDelegate4 = DeferredPause;
							deferredHandlerDelegate4.BeginInvoke(null, null);
						}
						break;
					case 1:
					{
						int currentState = status.currentState;
						if (status.currentState == 7 || status.currentState == 4)
						{
							status.currentState = 3;
							NativeMethods.SetServiceStatus(statusHandle, ptr);
							status.currentState = currentState;
							DeferredHandlerDelegate deferredHandlerDelegate2 = DeferredStop;
							deferredHandlerDelegate2.BeginInvoke(null, null);
						}
						break;
					}
					case 5:
					{
						DeferredHandlerDelegate deferredHandlerDelegate = DeferredShutdown;
						deferredHandlerDelegate.BeginInvoke(null, null);
						break;
					}
					default:
					{
						DeferredHandlerDelegateCommand deferredHandlerDelegateCommand = DeferredCustomCommand;
						deferredHandlerDelegateCommand.BeginInvoke(command, null, null);
						break;
					}
					}
					return;
				}
			}
		}

		private void ServiceQueuedMainCallback(object state)
		{
			string[] args = (string[])state;
			try
			{
				OnStart(args);
				WriteEventLogEntry(Res.GetString("StartSuccessful"));
				status.checkPoint = 0;
				status.waitHint = 0;
				status.currentState = 4;
			}
			catch (Exception ex)
			{
				WriteEventLogEntry(Res.GetString("StartFailed", ex.ToString()), EventLogEntryType.Error);
				status.currentState = 1;
			}
			catch
			{
				WriteEventLogEntry(Res.GetString("StartFailed", string.Empty), EventLogEntryType.Error);
				status.currentState = 1;
			}
			startCompletedSignal.Set();
		}

		[ComVisible(false)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		public unsafe void ServiceMainCallback(int argCount, IntPtr argPointer)
		{
			fixed (NativeMethods.SERVICE_STATUS* ptr2 = &status)
			{
				string[] array = null;
				if (argCount > 0)
				{
					char** ptr = (char**)argPointer.ToPointer();
					array = new string[argCount - 1];
					for (int i = 0; i < array.Length; i++)
					{
						ptr++;
						array[i] = Marshal.PtrToStringUni((IntPtr)(*ptr));
					}
				}
				if (!initialized)
				{
					isServiceHosted = true;
					Initialize(multipleServices: true);
				}
				if (Environment.OSVersion.Version.Major >= 5)
				{
					statusHandle = NativeMethods.RegisterServiceCtrlHandlerEx(ServiceName, commandCallbackEx, (IntPtr)0);
				}
				else
				{
					statusHandle = NativeMethods.RegisterServiceCtrlHandler(ServiceName, commandCallback);
				}
				nameFrozen = true;
				if (statusHandle == (IntPtr)0)
				{
					string message = new Win32Exception().Message;
					WriteEventLogEntry(Res.GetString("StartFailed", message), EventLogEntryType.Error);
				}
				status.controlsAccepted = acceptedCommands;
				commandPropsFrozen = true;
				if (((uint)status.controlsAccepted & (true ? 1u : 0u)) != 0)
				{
					status.controlsAccepted |= 4;
				}
				if (Environment.OSVersion.Version.Major < 5)
				{
					status.controlsAccepted &= -65;
				}
				status.currentState = 2;
				if (!NativeMethods.SetServiceStatus(statusHandle, ptr2))
				{
					return;
				}
				startCompletedSignal = new ManualResetEvent(initialState: false);
				ThreadPool.QueueUserWorkItem(ServiceQueuedMainCallback, array);
				startCompletedSignal.WaitOne();
				if (!NativeMethods.SetServiceStatus(statusHandle, ptr2))
				{
					WriteEventLogEntry(Res.GetString("StartFailed", new Win32Exception().Message), EventLogEntryType.Error);
					status.currentState = 1;
					NativeMethods.SetServiceStatus(statusHandle, ptr2);
				}
			}
		}

		private void WriteEventLogEntry(string message)
		{
			try
			{
				if (AutoLog)
				{
					EventLog.WriteEntry(message);
				}
			}
			catch (StackOverflowException)
			{
				throw;
			}
			catch (OutOfMemoryException)
			{
				throw;
			}
			catch (ThreadAbortException)
			{
				throw;
			}
			catch
			{
			}
		}

		private void WriteEventLogEntry(string message, EventLogEntryType errorType)
		{
			try
			{
				if (AutoLog)
				{
					EventLog.WriteEntry(message, errorType);
				}
			}
			catch (StackOverflowException)
			{
				throw;
			}
			catch (OutOfMemoryException)
			{
				throw;
			}
			catch (ThreadAbortException)
			{
				throw;
			}
			catch
			{
			}
		}

		private void SendServiceStartTelemetry()
		{
			ServiceProcessTraceLogger.TraceServiceProcessStart();
		}
	}
	[ServiceProcessDescription("ServiceControllerDesc")]
	[Designer("System.ServiceProcess.Design.ServiceControllerDesigner, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
	public class ServiceController : Component
	{
		private const int DISPLAYNAMEBUFFERSIZE = 256;

		private string machineName = ".";

		private string name = "";

		private string displayName = "";

		private string eitherName = "";

		private int commandsAccepted;

		private ServiceControllerStatus status;

		private IntPtr serviceManagerHandle;

		private bool statusGenerated;

		private bool controlGranted;

		private bool browseGranted;

		private ServiceController[] dependentServices;

		private ServiceController[] servicesDependedOn;

		private int type;

		private bool disposed;

		private static readonly int UnknownEnvironment = 0;

		private static readonly int NtEnvironment = 1;

		private static readonly int NonNtEnvironment = 2;

		private static int environment = UnknownEnvironment;

		private static object s_InternalSyncObject;

		private static object InternalSyncObject
		{
			get
			{
				if (s_InternalSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref s_InternalSyncObject, value, null);
				}
				return s_InternalSyncObject;
			}
		}

		[ServiceProcessDescription("SPCanPauseAndContinue")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public bool CanPauseAndContinue
		{
			get
			{
				GenerateStatus();
				return (commandsAccepted & 2) != 0;
			}
		}

		[ServiceProcessDescription("SPCanShutdown")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public bool CanShutdown
		{
			get
			{
				GenerateStatus();
				return (commandsAccepted & 4) != 0;
			}
		}

		[ServiceProcessDescription("SPCanStop")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public bool CanStop
		{
			get
			{
				GenerateStatus();
				return (commandsAccepted & 1) != 0;
			}
		}

		[ReadOnly(true)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[ServiceProcessDescription("SPDisplayName")]
		public string DisplayName
		{
			get
			{
				if (displayName.Length == 0 && (eitherName.Length > 0 || name.Length > 0))
				{
					GenerateNames();
				}
				return displayName;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (string.Compare(value, displayName, StringComparison.OrdinalIgnoreCase) == 0)
				{
					displayName = value;
					return;
				}
				Close();
				displayName = value;
				name = "";
			}
		}

		[ServiceProcessDescription("SPDependentServices")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public ServiceController[] DependentServices
		{
			get
			{
				if (!browseGranted)
				{
					ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Browse, machineName, ServiceName);
					serviceControllerPermission.Demand();
					browseGranted = true;
				}
				if (dependentServices == null)
				{
					IntPtr serviceHandle = GetServiceHandle(8);
					try
					{
						int bytesNeeded = 0;
						int numEnumerated = 0;
						if (UnsafeNativeMethods.EnumDependentServices(serviceHandle, 3, (IntPtr)0, 0, ref bytesNeeded, ref numEnumerated))
						{
							dependentServices = new ServiceController[0];
							return dependentServices;
						}
						if (Marshal.GetLastWin32Error() != 234)
						{
							throw CreateSafeWin32Exception();
						}
						IntPtr intPtr = Marshal.AllocHGlobal((IntPtr)bytesNeeded);
						try
						{
							if (!UnsafeNativeMethods.EnumDependentServices(serviceHandle, 3, intPtr, bytesNeeded, ref bytesNeeded, ref numEnumerated))
							{
								throw CreateSafeWin32Exception();
							}
							dependentServices = new ServiceController[numEnumerated];
							for (int i = 0; i < numEnumerated; i++)
							{
								NativeMethods.ENUM_SERVICE_STATUS structure = new NativeMethods.ENUM_SERVICE_STATUS();
								IntPtr ptr = (IntPtr)((long)intPtr + i * Marshal.SizeOf(typeof(NativeMethods.ENUM_SERVICE_STATUS)));
								Marshal.PtrToStructure(ptr, structure);
								dependentServices[i] = new ServiceController(MachineName, structure);
							}
						}
						finally
						{
							Marshal.FreeHGlobal(intPtr);
						}
					}
					finally
					{
						SafeNativeMethods.CloseServiceHandle(serviceHandle);
					}
				}
				return dependentServices;
			}
		}

		[ServiceProcessDescription("SPMachineName")]
		[RecommendedAsConfigurable(true)]
		[Browsable(false)]
		[DefaultValue(".")]
		public string MachineName
		{
			get
			{
				return machineName;
			}
			set
			{
				if (!SyntaxCheck.CheckMachineName(value))
				{
					throw new ArgumentException(Res.GetString("BadMachineName", value));
				}
				if (string.Compare(machineName, value, StringComparison.OrdinalIgnoreCase) == 0)
				{
					machineName = value;
					return;
				}
				Close();
				machineName = value;
			}
		}

		[DefaultValue("")]
		[RecommendedAsConfigurable(true)]
		[TypeConverter(typeof(ServiceNameConverter))]
		[ReadOnly(true)]
		[ServiceProcessDescription("SPServiceName")]
		public string ServiceName
		{
			get
			{
				if (name.Length == 0 && (eitherName.Length > 0 || displayName.Length > 0))
				{
					GenerateNames();
				}
				return name;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (string.Compare(value, name, StringComparison.OrdinalIgnoreCase) == 0)
				{
					name = value;
					return;
				}
				if (!ValidServiceName(value))
				{
					throw new ArgumentException(Res.GetString("ServiceName", value, 80.ToString(CultureInfo.CurrentCulture)));
				}
				Close();
				name = value;
				displayName = "";
			}
		}

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[ServiceProcessDescription("SPServicesDependedOn")]
		public unsafe ServiceController[] ServicesDependedOn
		{
			get
			{
				if (!browseGranted)
				{
					ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Browse, machineName, ServiceName);
					serviceControllerPermission.Demand();
					browseGranted = true;
				}
				if (servicesDependedOn != null)
				{
					return servicesDependedOn;
				}
				IntPtr serviceHandle = GetServiceHandle(1);
				try
				{
					int bytesNeeded = 0;
					if (UnsafeNativeMethods.QueryServiceConfig(serviceHandle, (IntPtr)0, 0, out bytesNeeded))
					{
						servicesDependedOn = new ServiceController[0];
						return servicesDependedOn;
					}
					if (Marshal.GetLastWin32Error() != 122)
					{
						throw CreateSafeWin32Exception();
					}
					IntPtr intPtr = Marshal.AllocHGlobal((IntPtr)bytesNeeded);
					try
					{
						if (!UnsafeNativeMethods.QueryServiceConfig(serviceHandle, intPtr, bytesNeeded, out bytesNeeded))
						{
							throw CreateSafeWin32Exception();
						}
						NativeMethods.QUERY_SERVICE_CONFIG qUERY_SERVICE_CONFIG = new NativeMethods.QUERY_SERVICE_CONFIG();
						Marshal.PtrToStructure(intPtr, qUERY_SERVICE_CONFIG);
						char* ptr = qUERY_SERVICE_CONFIG.lpDependencies;
						Hashtable hashtable = new Hashtable();
						if (ptr != null)
						{
							StringBuilder stringBuilder = new StringBuilder();
							while (*ptr != 0)
							{
								stringBuilder.Append(*ptr);
								ptr++;
								if (*ptr != 0)
								{
									continue;
								}
								string text = stringBuilder.ToString();
								stringBuilder = new StringBuilder();
								ptr++;
								if (text.StartsWith("+", StringComparison.Ordinal))
								{
									NativeMethods.ENUM_SERVICE_STATUS_PROCESS[] servicesInGroup = GetServicesInGroup(machineName, text.Substring(1));
									NativeMethods.ENUM_SERVICE_STATUS_PROCESS[] array = servicesInGroup;
									foreach (NativeMethods.ENUM_SERVICE_STATUS_PROCESS eNUM_SERVICE_STATUS_PROCESS in array)
									{
										if (!hashtable.Contains(eNUM_SERVICE_STATUS_PROCESS.serviceName))
										{
											hashtable.Add(eNUM_SERVICE_STATUS_PROCESS.serviceName, new ServiceController(MachineName, eNUM_SERVICE_STATUS_PROCESS));
										}
									}
								}
								else if (!hashtable.Contains(text))
								{
									hashtable.Add(text, new ServiceController(text, MachineName));
								}
							}
						}
						servicesDependedOn = new ServiceController[hashtable.Count];
						hashtable.Values.CopyTo(servicesDependedOn, 0);
						return servicesDependedOn;
					}
					finally
					{
						Marshal.FreeHGlobal(intPtr);
					}
				}
				finally
				{
					SafeNativeMethods.CloseServiceHandle(serviceHandle);
				}
			}
		}

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false)]
		public SafeHandle ServiceHandle
		{
			get
			{
				new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Demand();
				return new SafeServiceHandle(GetServiceHandle(983551), ownsHandle: true);
			}
		}

		[ServiceProcessDescription("SPStatus")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public ServiceControllerStatus Status
		{
			get
			{
				GenerateStatus();
				return status;
			}
		}

		[ServiceProcessDescription("SPServiceType")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public ServiceType ServiceType
		{
			get
			{
				GenerateStatus();
				return (ServiceType)type;
			}
		}

		public ServiceController()
		{
			type = 319;
		}

		public ServiceController(string name)
			: this(name, ".")
		{
		}

		public ServiceController(string name, string machineName)
		{
			if (!SyntaxCheck.CheckMachineName(machineName))
			{
				throw new ArgumentException(Res.GetString("BadMachineName", machineName));
			}
			if (name == null || name.Length == 0)
			{
				throw new ArgumentException(Res.GetString("InvalidParameter", "name", name));
			}
			this.machineName = machineName;
			eitherName = name;
			type = 319;
		}

		internal ServiceController(string machineName, NativeMethods.ENUM_SERVICE_STATUS status)
		{
			if (!SyntaxCheck.CheckMachineName(machineName))
			{
				throw new ArgumentException(Res.GetString("BadMachineName", machineName));
			}
			this.machineName = machineName;
			name = status.serviceName;
			displayName = status.displayName;
			commandsAccepted = status.controlsAccepted;
			this.status = (ServiceControllerStatus)status.currentState;
			type = status.serviceType;
			statusGenerated = true;
		}

		internal ServiceController(string machineName, NativeMethods.ENUM_SERVICE_STATUS_PROCESS status)
		{
			if (!SyntaxCheck.CheckMachineName(machineName))
			{
				throw new ArgumentException(Res.GetString("BadMachineName", machineName));
			}
			this.machineName = machineName;
			name = status.serviceName;
			displayName = status.displayName;
			commandsAccepted = status.controlsAccepted;
			this.status = (ServiceControllerStatus)status.currentState;
			type = status.serviceType;
			statusGenerated = true;
		}

		private static void CheckEnvironment()
		{
			if (environment == UnknownEnvironment)
			{
				lock (InternalSyncObject)
				{
					if (environment == UnknownEnvironment)
					{
						if (Environment.OSVersion.Platform == PlatformID.Win32NT)
						{
							environment = NtEnvironment;
						}
						else
						{
							environment = NonNtEnvironment;
						}
					}
				}
			}
			if (environment == NonNtEnvironment)
			{
				throw new PlatformNotSupportedException(Res.GetString("CantControlOnWin9x"));
			}
		}

		public void Close()
		{
			if (serviceManagerHandle != (IntPtr)0)
			{
				SafeNativeMethods.CloseServiceHandle(serviceManagerHandle);
			}
			serviceManagerHandle = (IntPtr)0;
			statusGenerated = false;
			type = 319;
			browseGranted = false;
			controlGranted = false;
		}

		private static Win32Exception CreateSafeWin32Exception()
		{
			Win32Exception ex = null;
			SecurityPermission securityPermission = new SecurityPermission(PermissionState.Unrestricted);
			securityPermission.Assert();
			try
			{
				return new Win32Exception();
			}
			finally
			{
				CodeAccessPermission.RevertAssert();
			}
		}

		protected override void Dispose(bool disposing)
		{
			Close();
			disposed = true;
			base.Dispose(disposing);
		}

		private unsafe void GenerateStatus()
		{
			if (statusGenerated)
			{
				return;
			}
			if (!browseGranted)
			{
				ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Browse, machineName, ServiceName);
				serviceControllerPermission.Demand();
				browseGranted = true;
			}
			IntPtr serviceHandle = GetServiceHandle(4);
			try
			{
				NativeMethods.SERVICE_STATUS sERVICE_STATUS = default(NativeMethods.SERVICE_STATUS);
				if (!UnsafeNativeMethods.QueryServiceStatus(serviceHandle, &sERVICE_STATUS))
				{
					throw CreateSafeWin32Exception();
				}
				commandsAccepted = sERVICE_STATUS.controlsAccepted;
				status = (ServiceControllerStatus)sERVICE_STATUS.currentState;
				type = sERVICE_STATUS.serviceType;
				statusGenerated = true;
			}
			finally
			{
				SafeNativeMethods.CloseServiceHandle(serviceHandle);
			}
		}

		private void GenerateNames()
		{
			if (machineName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("NoMachineName"));
			}
			GetDataBaseHandleWithConnectAccess();
			if (name.Length == 0)
			{
				string text = eitherName;
				if (text.Length == 0)
				{
					text = displayName;
				}
				if (text.Length == 0)
				{
					throw new InvalidOperationException(Res.GetString("NoGivenName"));
				}
				int shortNameLength = 256;
				StringBuilder stringBuilder = new StringBuilder(shortNameLength);
				if (SafeNativeMethods.GetServiceKeyName(serviceManagerHandle, text, stringBuilder, ref shortNameLength))
				{
					name = stringBuilder.ToString();
					displayName = text;
					eitherName = "";
				}
				else
				{
					bool serviceDisplayName = SafeNativeMethods.GetServiceDisplayName(serviceManagerHandle, text, stringBuilder, ref shortNameLength);
					if (!serviceDisplayName && shortNameLength >= 256)
					{
						stringBuilder = new StringBuilder(++shortNameLength);
						serviceDisplayName = SafeNativeMethods.GetServiceDisplayName(serviceManagerHandle, text, stringBuilder, ref shortNameLength);
					}
					if (!serviceDisplayName)
					{
						Exception innerException = CreateSafeWin32Exception();
						throw new InvalidOperationException(Res.GetString("NoService", text, machineName), innerException);
					}
					name = text;
					displayName = stringBuilder.ToString();
					eitherName = "";
				}
			}
			if (displayName.Length == 0)
			{
				int displayNameLength = 256;
				StringBuilder stringBuilder2 = new StringBuilder(displayNameLength);
				bool serviceDisplayName2 = SafeNativeMethods.GetServiceDisplayName(serviceManagerHandle, name, stringBuilder2, ref displayNameLength);
				if (!serviceDisplayName2 && displayNameLength >= 256)
				{
					stringBuilder2 = new StringBuilder(++displayNameLength);
					serviceDisplayName2 = SafeNativeMethods.GetServiceDisplayName(serviceManagerHandle, name, stringBuilder2, ref displayNameLength);
				}
				if (!serviceDisplayName2)
				{
					Exception innerException2 = CreateSafeWin32Exception();
					throw new InvalidOperationException(Res.GetString("NoDisplayName", name, machineName), innerException2);
				}
				displayName = stringBuilder2.ToString();
			}
		}

		private static IntPtr GetDataBaseHandleWithAccess(string machineName, int serviceControlManaqerAccess)
		{
			CheckEnvironment();
			IntPtr zero = IntPtr.Zero;
			zero = ((!machineName.Equals(".") && machineName.Length != 0) ? SafeNativeMethods.OpenSCManager(machineName, null, serviceControlManaqerAccess) : SafeNativeMethods.OpenSCManager(null, null, serviceControlManaqerAccess));
			if (zero == (IntPtr)0)
			{
				Exception innerException = CreateSafeWin32Exception();
				throw new InvalidOperationException(Res.GetString("OpenSC", machineName), innerException);
			}
			return zero;
		}

		private void GetDataBaseHandleWithConnectAccess()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (serviceManagerHandle == (IntPtr)0)
			{
				serviceManagerHandle = GetDataBaseHandleWithAccess(MachineName, 1);
			}
		}

		private static IntPtr GetDataBaseHandleWithEnumerateAccess(string machineName)
		{
			return GetDataBaseHandleWithAccess(machineName, 4);
		}

		public static ServiceController[] GetDevices()
		{
			return GetDevices(".");
		}

		public static ServiceController[] GetDevices(string machineName)
		{
			return GetServicesOfType(machineName, 11);
		}

		private IntPtr GetServiceHandle(int desiredAccess)
		{
			GetDataBaseHandleWithConnectAccess();
			IntPtr intPtr = UnsafeNativeMethods.OpenService(serviceManagerHandle, ServiceName, desiredAccess);
			if (intPtr == (IntPtr)0)
			{
				Exception innerException = CreateSafeWin32Exception();
				throw new InvalidOperationException(Res.GetString("OpenService", ServiceName, MachineName), innerException);
			}
			return intPtr;
		}

		public static ServiceController[] GetServices()
		{
			return GetServices(".");
		}

		public static ServiceController[] GetServices(string machineName)
		{
			return GetServicesOfType(machineName, 48);
		}

		private static NativeMethods.ENUM_SERVICE_STATUS_PROCESS[] GetServicesInGroup(string machineName, string group)
		{
			IntPtr intPtr = (IntPtr)0;
			IntPtr intPtr2 = (IntPtr)0;
			int resumeHandle = 0;
			try
			{
				intPtr = GetDataBaseHandleWithEnumerateAccess(machineName);
				UnsafeNativeMethods.EnumServicesStatusEx(intPtr, 0, 48, 3, (IntPtr)0, 0, out var bytesNeeded, out var servicesReturned, ref resumeHandle, group);
				intPtr2 = Marshal.AllocHGlobal((IntPtr)bytesNeeded);
				UnsafeNativeMethods.EnumServicesStatusEx(intPtr, 0, 48, 3, intPtr2, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle, group);
				int num = servicesReturned;
				NativeMethods.ENUM_SERVICE_STATUS_PROCESS[] array = new NativeMethods.ENUM_SERVICE_STATUS_PROCESS[num];
				for (int i = 0; i < num; i++)
				{
					IntPtr ptr = (IntPtr)((long)intPtr2 + i * Marshal.SizeOf(typeof(NativeMethods.ENUM_SERVICE_STATUS_PROCESS)));
					NativeMethods.ENUM_SERVICE_STATUS_PROCESS eNUM_SERVICE_STATUS_PROCESS = new NativeMethods.ENUM_SERVICE_STATUS_PROCESS();
					Marshal.PtrToStructure(ptr, eNUM_SERVICE_STATUS_PROCESS);
					array[i] = eNUM_SERVICE_STATUS_PROCESS;
				}
				return array;
			}
			finally
			{
				Marshal.FreeHGlobal(intPtr2);
				if (intPtr != (IntPtr)0)
				{
					SafeNativeMethods.CloseServiceHandle(intPtr);
				}
			}
		}

		private static ServiceController[] GetServicesOfType(string machineName, int serviceType)
		{
			if (!SyntaxCheck.CheckMachineName(machineName))
			{
				throw new ArgumentException(Res.GetString("BadMachineName", machineName));
			}
			ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Browse, machineName, "*");
			serviceControllerPermission.Demand();
			CheckEnvironment();
			IntPtr intPtr = (IntPtr)0;
			IntPtr intPtr2 = (IntPtr)0;
			int resumeHandle = 0;
			try
			{
				intPtr = GetDataBaseHandleWithEnumerateAccess(machineName);
				UnsafeNativeMethods.EnumServicesStatus(intPtr, serviceType, 3, (IntPtr)0, 0, out var bytesNeeded, out var servicesReturned, ref resumeHandle);
				intPtr2 = Marshal.AllocHGlobal((IntPtr)bytesNeeded);
				UnsafeNativeMethods.EnumServicesStatus(intPtr, serviceType, 3, intPtr2, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle);
				int num = servicesReturned;
				ServiceController[] array = new ServiceController[num];
				for (int i = 0; i < num; i++)
				{
					IntPtr ptr = (IntPtr)((long)intPtr2 + i * Marshal.SizeOf(typeof(NativeMethods.ENUM_SERVICE_STATUS)));
					NativeMethods.ENUM_SERVICE_STATUS structure = new NativeMethods.ENUM_SERVICE_STATUS();
					Marshal.PtrToStructure(ptr, structure);
					array[i] = new ServiceController(machineName, structure);
				}
				return array;
			}
			finally
			{
				Marshal.FreeHGlobal(intPtr2);
				if (intPtr != (IntPtr)0)
				{
					SafeNativeMethods.CloseServiceHandle(intPtr);
				}
			}
		}

		public unsafe void Pause()
		{
			if (!controlGranted)
			{
				ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Control, machineName, ServiceName);
				serviceControllerPermission.Demand();
				controlGranted = true;
			}
			IntPtr serviceHandle = GetServiceHandle(64);
			try
			{
				NativeMethods.SERVICE_STATUS sERVICE_STATUS = default(NativeMethods.SERVICE_STATUS);
				if (!UnsafeNativeMethods.ControlService(serviceHandle, 2, &sERVICE_STATUS))
				{
					Exception innerException = CreateSafeWin32Exception();
					throw new InvalidOperationException(Res.GetString("PauseService", ServiceName, MachineName), innerException);
				}
			}
			finally
			{
				SafeNativeMethods.CloseServiceHandle(serviceHandle);
			}
		}

		public unsafe void Continue()
		{
			if (!controlGranted)
			{
				ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Control, machineName, ServiceName);
				serviceControllerPermission.Demand();
				controlGranted = true;
			}
			IntPtr serviceHandle = GetServiceHandle(64);
			try
			{
				NativeMethods.SERVICE_STATUS sERVICE_STATUS = default(NativeMethods.SERVICE_STATUS);
				if (!UnsafeNativeMethods.ControlService(serviceHandle, 3, &sERVICE_STATUS))
				{
					Exception innerException = CreateSafeWin32Exception();
					throw new InvalidOperationException(Res.GetString("ResumeService", ServiceName, MachineName), innerException);
				}
			}
			finally
			{
				SafeNativeMethods.CloseServiceHandle(serviceHandle);
			}
		}

		public unsafe void ExecuteCommand(int command)
		{
			if (!controlGranted)
			{
				ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Control, machineName, ServiceName);
				serviceControllerPermission.Demand();
				controlGranted = true;
			}
			IntPtr serviceHandle = GetServiceHandle(256);
			try
			{
				NativeMethods.SERVICE_STATUS sERVICE_STATUS = default(NativeMethods.SERVICE_STATUS);
				if (!UnsafeNativeMethods.ControlService(serviceHandle, command, &sERVICE_STATUS))
				{
					Exception innerException = CreateSafeWin32Exception();
					throw new InvalidOperationException(Res.GetString("ControlService", ServiceName, MachineName), innerException);
				}
			}
			finally
			{
				SafeNativeMethods.CloseServiceHandle(serviceHandle);
			}
		}

		public void Refresh()
		{
			statusGenerated = false;
			dependentServices = null;
			servicesDependedOn = null;
		}

		public void Start()
		{
			Start(new string[0]);
		}

		public void Start(string[] args)
		{
			if (args == null)
			{
				throw new ArgumentNullException("args");
			}
			if (!controlGranted)
			{
				ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Control, machineName, ServiceName);
				serviceControllerPermission.Demand();
				controlGranted = true;
			}
			IntPtr serviceHandle = GetServiceHandle(16);
			try
			{
				IntPtr[] array = new IntPtr[args.Length];
				int i = 0;
				try
				{
					for (i = 0; i < args.Length; i++)
					{
						if (args[i] == null)
						{
							throw new ArgumentNullException(Res.GetString("ArgsCantBeNull"), "args");
						}
						ref IntPtr reference = ref array[i];
						reference = Marshal.StringToHGlobalUni(args[i]);
					}
				}
				catch
				{
					for (int j = 0; j < i; j++)
					{
						Marshal.FreeHGlobal(array[i]);
					}
					throw;
				}
				GCHandle gCHandle = default(GCHandle);
				try
				{
					gCHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
					if (!UnsafeNativeMethods.StartService(serviceHandle, args.Length, gCHandle.AddrOfPinnedObject()))
					{
						Exception innerException = CreateSafeWin32Exception();
						throw new InvalidOperationException(Res.GetString("CannotStart", ServiceName, MachineName), innerException);
					}
				}
				finally
				{
					for (i = 0; i < args.Length; i++)
					{
						Marshal.FreeHGlobal(array[i]);
					}
					if (gCHandle.IsAllocated)
					{
						gCHandle.Free();
					}
				}
			}
			finally
			{
				SafeNativeMethods.CloseServiceHandle(serviceHandle);
			}
		}

		public unsafe void Stop()
		{
			if (!controlGranted)
			{
				ServiceControllerPermission serviceControllerPermission = new ServiceControllerPermission(ServiceControllerPermissionAccess.Control, machineName, ServiceName);
				serviceControllerPermission.Demand();
				controlGranted = true;
			}
			IntPtr serviceHandle = GetServiceHandle(32);
			try
			{
				for (int i = 0; i < DependentServices.Length; i++)
				{
					ServiceController serviceController = DependentServices[i];
					serviceController.Refresh();
					if (serviceController.Status != ServiceControllerStatus.Stopped)
					{
						serviceController.Stop();
						serviceController.WaitForStatus(ServiceControllerStatus.Stopped, new TimeSpan(0, 0, 30));
					}
				}
				NativeMethods.SERVICE_STATUS sERVICE_STATUS = default(NativeMethods.SERVICE_STATUS);
				if (!UnsafeNativeMethods.ControlService(serviceHandle, 1, &sERVICE_STATUS))
				{
					Exception innerException = CreateSafeWin32Exception();
					throw new InvalidOperationException(Res.GetString("StopService", ServiceName, MachineName), innerException);
				}
			}
			finally
			{
				SafeNativeMethods.CloseServiceHandle(serviceHandle);
			}
		}

		internal static bool ValidServiceName(string serviceName)
		{
			if (serviceName == null)
			{
				return false;
			}
			if (serviceName.Length > 80 || serviceName.Length == 0)
			{
				return false;
			}
			char[] array = serviceName.ToCharArray();
			foreach (char c in array)
			{
				if (c == '\\' || c == '/')
				{
					return false;
				}
			}
			return true;
		}

		public void WaitForStatus(ServiceControllerStatus desiredStatus)
		{
			WaitForStatus(desiredStatus, TimeSpan.MaxValue);
		}

		public void WaitForStatus(ServiceControllerStatus desiredStatus, TimeSpan timeout)
		{
			if (!Enum.IsDefined(typeof(ServiceControllerStatus), desiredStatus))
			{
				throw new InvalidEnumArgumentException("desiredStatus", (int)desiredStatus, typeof(ServiceControllerStatus));
			}
			DateTime utcNow = DateTime.UtcNow;
			Refresh();
			while (Status != desiredStatus)
			{
				if (DateTime.UtcNow - utcNow > timeout)
				{
					throw new TimeoutException(Res.GetString("Timeout"));
				}
				Thread.Sleep(250);
				Refresh();
			}
		}
	}
	[Serializable]
	public sealed class ServiceControllerPermission : ResourcePermissionBase
	{
		private ServiceControllerPermissionEntryCollection innerCollection;

		public ServiceControllerPermissionEntryCollection PermissionEntries
		{
			get
			{
				if (innerCollection == null)
				{
					innerCollection = new ServiceControllerPermissionEntryCollection(this, GetPermissionEntries());
				}
				return innerCollection;
			}
		}

		public ServiceControllerPermission()
		{
			SetNames();
		}

		public ServiceControllerPermission(PermissionState state)
			: base(state)
		{
			SetNames();
		}

		public ServiceControllerPermission(ServiceControllerPermissionAccess permissionAccess, string machineName, string serviceName)
		{
			SetNames();
			AddPermissionAccess(new ServiceControllerPermissionEntry(permissionAccess, machineName, serviceName));
		}

		public ServiceControllerPermission(ServiceControllerPermissionEntry[] permissionAccessEntries)
		{
			if (permissionAccessEntries == null)
			{
				throw new ArgumentNullException("permissionAccessEntries");
			}
			SetNames();
			for (int i = 0; i < permissionAccessEntries.Length; i++)
			{
				AddPermissionAccess(permissionAccessEntries[i]);
			}
		}

		internal void AddPermissionAccess(ServiceControllerPermissionEntry entry)
		{
			AddPermissionAccess(entry.GetBaseEntry());
		}

		internal new void Clear()
		{
			base.Clear();
		}

		internal void RemovePermissionAccess(ServiceControllerPermissionEntry entry)
		{
			RemovePermissionAccess(entry.GetBaseEntry());
		}

		private void SetNames()
		{
			base.PermissionAccessType = typeof(ServiceControllerPermissionAccess);
			base.TagNames = new string[2] { "Machine", "Service" };
		}
	}
	[Flags]
	public enum ServiceControllerPermissionAccess
	{
		None = 0,
		Browse = 2,
		Control = 6
	}
	[Serializable]
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Constructor | AttributeTargets.Method | AttributeTargets.Event, AllowMultiple = true, Inherited = false)]
	public class ServiceControllerPermissionAttribute : CodeAccessSecurityAttribute
	{
		private string machineName;

		private string serviceName;

		private ServiceControllerPermissionAccess permissionAccess;

		public string MachineName
		{
			get
			{
				return machineName;
			}
			set
			{
				if (!SyntaxCheck.CheckMachineName(value))
				{
					throw new ArgumentException(Res.GetString("BadMachineName", value));
				}
				machineName = value;
			}
		}

		public ServiceControllerPermissionAccess PermissionAccess
		{
			get
			{
				return permissionAccess;
			}
			set
			{
				permissionAccess = value;
			}
		}

		public string ServiceName
		{
			get
			{
				return serviceName;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!ServiceController.ValidServiceName(value))
				{
					throw new ArgumentException(Res.GetString("ServiceName", value, 80.ToString(CultureInfo.CurrentCulture)));
				}
				serviceName = value;
			}
		}

		public ServiceControllerPermissionAttribute(SecurityAction action)
			: base(action)
		{
			machineName = ".";
			serviceName = "*";
			permissionAccess = ServiceControllerPermissionAccess.Browse;
		}

		public override IPermission CreatePermission()
		{
			if (base.Unrestricted)
			{
				return new ServiceControllerPermission(PermissionState.Unrestricted);
			}
			return new ServiceControllerPermission(PermissionAccess, MachineName, ServiceName);
		}
	}
	[Serializable]
	public class ServiceControllerPermissionEntry
	{
		private string machineName;

		private string serviceName;

		private ServiceControllerPermissionAccess permissionAccess;

		public string MachineName => machineName;

		public ServiceControllerPermissionAccess PermissionAccess => permissionAccess;

		public string ServiceName => serviceName;

		public ServiceControllerPermissionEntry()
		{
			machineName = ".";
			serviceName = "*";
			permissionAccess = ServiceControllerPermissionAccess.Browse;
		}

		public ServiceControllerPermissionEntry(ServiceControllerPermissionAccess permissionAccess, string machineName, string serviceName)
		{
			if (serviceName == null)
			{
				throw new ArgumentNullException("serviceName");
			}
			if (!ServiceController.ValidServiceName(serviceName))
			{
				throw new ArgumentException(Res.GetString("ServiceName", serviceName, 80.ToString(CultureInfo.CurrentCulture)));
			}
			if (!SyntaxCheck.CheckMachineName(machineName))
			{
				throw new ArgumentException(Res.GetString("BadMachineName", machineName));
			}
			this.permissionAccess = permissionAccess;
			this.machineName = machineName;
			this.serviceName = serviceName;
		}

		internal ServiceControllerPermissionEntry(ResourcePermissionBaseEntry baseEntry)
		{
			permissionAccess = (ServiceControllerPermissionAccess)baseEntry.PermissionAccess;
			machineName = baseEntry.PermissionAccessPath[0];
			serviceName = baseEntry.PermissionAccessPath[1];
		}

		internal ResourcePermissionBaseEntry GetBaseEntry()
		{
			return new ResourcePermissionBaseEntry((int)PermissionAccess, new string[2] { MachineName, ServiceName });
		}
	}
	[Serializable]
	public class ServiceControllerPermissionEntryCollection : CollectionBase
	{
		private ServiceControllerPermission owner;

		public ServiceControllerPermissionEntry this[int index]
		{
			get
			{
				return (ServiceControllerPermissionEntry)base.List[index];
			}
			set
			{
				base.List[index] = value;
			}
		}

		internal ServiceControllerPermissionEntryCollection(ServiceControllerPermission owner, ResourcePermissionBaseEntry[] entries)
		{
			this.owner = owner;
			for (int i = 0; i < entries.Length; i++)
			{
				base.InnerList.Add(new ServiceControllerPermissionEntry(entries[i]));
			}
		}

		public int Add(ServiceControllerPermissionEntry value)
		{
			return base.List.Add(value);
		}

		public void AddRange(ServiceControllerPermissionEntry[] value)
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

		public void AddRange(ServiceControllerPermissionEntryCollection value)
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

		public bool Contains(ServiceControllerPermissionEntry value)
		{
			return base.List.Contains(value);
		}

		public void CopyTo(ServiceControllerPermissionEntry[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(ServiceControllerPermissionEntry value)
		{
			return base.List.IndexOf(value);
		}

		public void Insert(int index, ServiceControllerPermissionEntry value)
		{
			base.List.Insert(index, value);
		}

		public void Remove(ServiceControllerPermissionEntry value)
		{
			base.List.Remove(value);
		}

		protected override void OnClear()
		{
			owner.Clear();
		}

		protected override void OnInsert(int index, object value)
		{
			owner.AddPermissionAccess((ServiceControllerPermissionEntry)value);
		}

		protected override void OnRemove(int index, object value)
		{
			owner.RemovePermissionAccess((ServiceControllerPermissionEntry)value);
		}

		protected override void OnSet(int index, object oldValue, object newValue)
		{
			owner.RemovePermissionAccess((ServiceControllerPermissionEntry)oldValue);
			owner.AddPermissionAccess((ServiceControllerPermissionEntry)newValue);
		}
	}
	public enum ServiceControllerStatus
	{
		ContinuePending = 5,
		Paused = 7,
		PausePending = 6,
		Running = 4,
		StartPending = 2,
		Stopped = 1,
		StopPending = 3
	}
	public class ServiceInstaller : ComponentInstaller
	{
		private const string NetworkServiceName = "NT AUTHORITY\\NetworkService";

		private const string LocalServiceName = "NT AUTHORITY\\LocalService";

		private EventLogInstaller eventLogInstaller;

		private string serviceName = "";

		private string displayName = "";

		private string description = "";

		private string[] servicesDependedOn = new string[0];

		private ServiceStartMode startType = ServiceStartMode.Manual;

		private static bool environmentChecked;

		private static bool isWin9x;

		[DefaultValue("")]
		[ServiceProcessDescription("ServiceInstallerDisplayName")]
		public string DisplayName
		{
			get
			{
				return displayName;
			}
			set
			{
				if (value == null)
				{
					value = "";
				}
				displayName = value;
			}
		}

		[ComVisible(false)]
		[ServiceProcessDescription("ServiceInstallerDescription")]
		[DefaultValue("")]
		public string Description
		{
			get
			{
				return description;
			}
			set
			{
				if (value == null)
				{
					value = "";
				}
				description = value;
			}
		}

		[ServiceProcessDescription("ServiceInstallerServicesDependedOn")]
		public string[] ServicesDependedOn
		{
			get
			{
				return servicesDependedOn;
			}
			set
			{
				if (value == null)
				{
					value = new string[0];
				}
				servicesDependedOn = value;
			}
		}

		[DefaultValue("")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ServiceProcessDescription("ServiceInstallerServiceName")]
		public string ServiceName
		{
			get
			{
				return serviceName;
			}
			set
			{
				if (value == null)
				{
					value = "";
				}
				if (!ServiceController.ValidServiceName(value))
				{
					throw new ArgumentException(Res.GetString("ServiceName", value, 80.ToString(CultureInfo.CurrentCulture)));
				}
				serviceName = value;
				eventLogInstaller.Source = value;
			}
		}

		[DefaultValue(ServiceStartMode.Manual)]
		[ServiceProcessDescription("ServiceInstallerStartType")]
		public ServiceStartMode StartType
		{
			get
			{
				return startType;
			}
			set
			{
				if (!Enum.IsDefined(typeof(ServiceStartMode), value))
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ServiceStartMode));
				}
				startType = value;
			}
		}

		public ServiceInstaller()
		{
			eventLogInstaller = new EventLogInstaller();
			eventLogInstaller.Log = "Application";
			eventLogInstaller.Source = "";
			eventLogInstaller.UninstallAction = UninstallAction.Remove;
			base.Installers.Add(eventLogInstaller);
		}

		internal static void CheckEnvironment()
		{
			if (environmentChecked)
			{
				if (isWin9x)
				{
					throw new PlatformNotSupportedException(Res.GetString("CantControlOnWin9x"));
				}
				return;
			}
			isWin9x = Environment.OSVersion.Platform != PlatformID.Win32NT;
			environmentChecked = true;
			if (!isWin9x)
			{
				return;
			}
			throw new PlatformNotSupportedException(Res.GetString("CantInstallOnWin9x"));
		}

		public override void CopyFromComponent(IComponent component)
		{
			if (!(component is ServiceBase))
			{
				throw new ArgumentException(Res.GetString("NotAService"));
			}
			ServiceBase serviceBase = (ServiceBase)component;
			ServiceName = serviceBase.ServiceName;
		}

		public override void Install(IDictionary stateSaver)
		{
			base.Context.LogMessage(Res.GetString("InstallingService", ServiceName));
			try
			{
				CheckEnvironment();
				string servicesStartName = null;
				string password = null;
				ServiceProcessInstaller serviceProcessInstaller = null;
				if (base.Parent is ServiceProcessInstaller)
				{
					serviceProcessInstaller = (ServiceProcessInstaller)base.Parent;
				}
				else
				{
					for (int i = 0; i < base.Parent.Installers.Count; i++)
					{
						if (base.Parent.Installers[i] is ServiceProcessInstaller)
						{
							serviceProcessInstaller = (ServiceProcessInstaller)base.Parent.Installers[i];
							break;
						}
					}
				}
				if (serviceProcessInstaller == null)
				{
					throw new InvalidOperationException(Res.GetString("NoInstaller"));
				}
				switch (serviceProcessInstaller.Account)
				{
				case ServiceAccount.LocalService:
					servicesStartName = "NT AUTHORITY\\LocalService";
					break;
				case ServiceAccount.NetworkService:
					servicesStartName = "NT AUTHORITY\\NetworkService";
					break;
				case ServiceAccount.User:
					servicesStartName = serviceProcessInstaller.Username;
					password = serviceProcessInstaller.Password;
					break;
				}
				string text = base.Context.Parameters["assemblypath"];
				if (text == null || text.Length == 0)
				{
					throw new InvalidOperationException(Res.GetString("FileName"));
				}
				text = "\"" + text + "\"";
				if (!ValidateServiceName(ServiceName))
				{
					throw new InvalidOperationException(Res.GetString("ServiceName", ServiceName, 80.ToString(CultureInfo.CurrentCulture)));
				}
				if (DisplayName.Length > 255)
				{
					throw new ArgumentException(Res.GetString("DisplayNameTooLong", DisplayName));
				}
				string dependencies = null;
				if (ServicesDependedOn.Length > 0)
				{
					StringBuilder stringBuilder = new StringBuilder();
					for (int j = 0; j < ServicesDependedOn.Length; j++)
					{
						string text2 = ServicesDependedOn[j];
						try
						{
							ServiceController serviceController = new ServiceController(text2, ".");
							text2 = serviceController.ServiceName;
						}
						catch
						{
						}
						stringBuilder.Append(text2);
						stringBuilder.Append('\0');
					}
					stringBuilder.Append('\0');
					dependencies = stringBuilder.ToString();
				}
				IntPtr intPtr = SafeNativeMethods.OpenSCManager(null, null, 983103);
				IntPtr intPtr2 = IntPtr.Zero;
				if (intPtr == IntPtr.Zero)
				{
					throw new InvalidOperationException(Res.GetString("OpenSC", "."), new Win32Exception());
				}
				int serviceType = 16;
				int num = 0;
				for (int k = 0; k < base.Parent.Installers.Count; k++)
				{
					if (base.Parent.Installers[k] is ServiceInstaller)
					{
						num++;
						if (num > 1)
						{
							break;
						}
					}
				}
				if (num > 1)
				{
					serviceType = 32;
				}
				try
				{
					intPtr2 = NativeMethods.CreateService(intPtr, ServiceName, DisplayName, 983551, serviceType, (int)StartType, 1, text, null, IntPtr.Zero, dependencies, servicesStartName, password);
					if (intPtr2 == IntPtr.Zero)
					{
						throw new Win32Exception();
					}
					if (Description.Length != 0)
					{
						NativeMethods.SERVICE_DESCRIPTION serviceDesc = default(NativeMethods.SERVICE_DESCRIPTION);
						serviceDesc.description = Marshal.StringToHGlobalUni(Description);
						bool flag = NativeMethods.ChangeServiceConfig2(intPtr2, 1u, ref serviceDesc);
						Marshal.FreeHGlobal(serviceDesc.description);
						if (!flag)
						{
							throw new Win32Exception();
						}
					}
					stateSaver["installed"] = true;
				}
				finally
				{
					if (intPtr2 != IntPtr.Zero)
					{
						SafeNativeMethods.CloseServiceHandle(intPtr2);
					}
					SafeNativeMethods.CloseServiceHandle(intPtr);
				}
				base.Context.LogMessage(Res.GetString("InstallOK", ServiceName));
			}
			finally
			{
				base.Install(stateSaver);
			}
		}

		public override bool IsEquivalentInstaller(ComponentInstaller otherInstaller)
		{
			if (!(otherInstaller is ServiceInstaller serviceInstaller))
			{
				return false;
			}
			return serviceInstaller.ServiceName == ServiceName;
		}

		private void RemoveService()
		{
			base.Context.LogMessage(Res.GetString("ServiceRemoving", ServiceName));
			IntPtr intPtr = SafeNativeMethods.OpenSCManager(null, null, 983103);
			if (intPtr == IntPtr.Zero)
			{
				throw new Win32Exception();
			}
			IntPtr intPtr2 = IntPtr.Zero;
			try
			{
				intPtr2 = NativeMethods.OpenService(intPtr, ServiceName, 65536);
				if (intPtr2 == IntPtr.Zero)
				{
					throw new Win32Exception();
				}
				NativeMethods.DeleteService(intPtr2);
			}
			finally
			{
				if (intPtr2 != IntPtr.Zero)
				{
					SafeNativeMethods.CloseServiceHandle(intPtr2);
				}
				SafeNativeMethods.CloseServiceHandle(intPtr);
			}
			base.Context.LogMessage(Res.GetString("ServiceRemoved", ServiceName));
			try
			{
				using ServiceController serviceController = new ServiceController(ServiceName);
				if (serviceController.Status != ServiceControllerStatus.Stopped)
				{
					base.Context.LogMessage(Res.GetString("TryToStop", ServiceName));
					serviceController.Stop();
					int num = 10;
					serviceController.Refresh();
					while (serviceController.Status != ServiceControllerStatus.Stopped && num > 0)
					{
						Thread.Sleep(1000);
						serviceController.Refresh();
						num--;
					}
				}
			}
			catch
			{
			}
			Thread.Sleep(5000);
		}

		public override void Rollback(IDictionary savedState)
		{
			base.Rollback(savedState);
			object obj = savedState["installed"];
			if (obj != null && (bool)obj)
			{
				RemoveService();
			}
		}

		private bool ShouldSerializeServicesDependedOn()
		{
			if (servicesDependedOn != null && servicesDependedOn.Length > 0)
			{
				return true;
			}
			return false;
		}

		public override void Uninstall(IDictionary savedState)
		{
			base.Uninstall(savedState);
			RemoveService();
		}

		private static bool ValidateServiceName(string name)
		{
			if (name == null || name.Length == 0 || name.Length > 80)
			{
				return false;
			}
			char[] array = name.ToCharArray();
			for (int i = 0; i < array.Length; i++)
			{
				if (array[i] < ' ' || array[i] == '/' || array[i] == '\\')
				{
					return false;
				}
			}
			return true;
		}
	}
	[AttributeUsage(AttributeTargets.All)]
	public class ServiceProcessDescriptionAttribute : DescriptionAttribute
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

		public ServiceProcessDescriptionAttribute(string description)
			: base(description)
		{
		}
	}
	public class ServiceProcessInstaller : ComponentInstaller
	{
		private ServiceAccount serviceAccount = ServiceAccount.User;

		private bool haveLoginInfo;

		private string password;

		private string username;

		private static bool helpPrinted;

		public override string HelpText
		{
			get
			{
				if (helpPrinted)
				{
					return base.HelpText;
				}
				helpPrinted = true;
				return Res.GetString("HelpText") + "\r\n" + base.HelpText;
			}
		}

		[Browsable(false)]
		public string Password
		{
			get
			{
				if (!haveLoginInfo)
				{
					GetLoginInfo();
				}
				return password;
			}
			set
			{
				haveLoginInfo = false;
				password = value;
			}
		}

		[DefaultValue(ServiceAccount.User)]
		[ServiceProcessDescription("ServiceProcessInstallerAccount")]
		public ServiceAccount Account
		{
			get
			{
				if (!haveLoginInfo)
				{
					GetLoginInfo();
				}
				return serviceAccount;
			}
			set
			{
				haveLoginInfo = false;
				serviceAccount = value;
			}
		}

		[Browsable(false)]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public string Username
		{
			get
			{
				if (!haveLoginInfo)
				{
					GetLoginInfo();
				}
				return username;
			}
			set
			{
				haveLoginInfo = false;
				username = value;
			}
		}

		private static bool AccountHasRight(IntPtr policyHandle, byte[] accountSid, string rightName)
		{
			IntPtr pLsaUnicodeStringUserRights = (IntPtr)0;
			int RightsCount = 0;
			int num = NativeMethods.LsaEnumerateAccountRights(policyHandle, accountSid, out pLsaUnicodeStringUserRights, out RightsCount);
			switch (num)
			{
			case -1073741772:
				return false;
			default:
				throw new Win32Exception(SafeNativeMethods.LsaNtStatusToWinError(num));
			case 0:
			{
				bool result = false;
				try
				{
					IntPtr intPtr = pLsaUnicodeStringUserRights;
					for (int i = 0; i < RightsCount; i++)
					{
						NativeMethods.LSA_UNICODE_STRING_withPointer lSA_UNICODE_STRING_withPointer = new NativeMethods.LSA_UNICODE_STRING_withPointer();
						Marshal.PtrToStructure(intPtr, lSA_UNICODE_STRING_withPointer);
						char[] array = new char[lSA_UNICODE_STRING_withPointer.length];
						Marshal.Copy(lSA_UNICODE_STRING_withPointer.pwstr, array, 0, array.Length);
						string strA = new string(array, 0, array.Length);
						if (string.Compare(strA, rightName, StringComparison.Ordinal) == 0)
						{
							return true;
						}
						intPtr = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(NativeMethods.LSA_UNICODE_STRING)));
					}
					return result;
				}
				finally
				{
					SafeNativeMethods.LsaFreeMemory(pLsaUnicodeStringUserRights);
				}
			}
			}
		}

		public override void CopyFromComponent(IComponent comp)
		{
		}

		private byte[] GetAccountSid(string accountName)
		{
			byte[] array = new byte[256];
			int[] array2 = new int[1] { array.Length };
			char[] array3 = new char[1024];
			int[] domNameLen = new int[1] { array3.Length };
			int[] sidNameUse = new int[1];
			if (accountName.Substring(0, 2) == ".\\")
			{
				StringBuilder stringBuilder = new StringBuilder(32);
				int nSize = 32;
				if (!NativeMethods.GetComputerName(stringBuilder, ref nSize))
				{
					throw new Win32Exception();
				}
				accountName = string.Concat(stringBuilder, accountName.Substring(1));
			}
			if (!NativeMethods.LookupAccountName(null, accountName, array, array2, array3, domNameLen, sidNameUse))
			{
				throw new Win32Exception();
			}
			byte[] array4 = new byte[array2[0]];
			Array.Copy(array, 0, array4, 0, array2[0]);
			return array4;
		}

		private void GetLoginInfo()
		{
			if (base.Context == null || base.DesignMode || haveLoginInfo)
			{
				return;
			}
			haveLoginInfo = true;
			if (serviceAccount != ServiceAccount.User)
			{
				return;
			}
			if (base.Context.Parameters.ContainsKey("username"))
			{
				username = base.Context.Parameters["username"];
			}
			if (base.Context.Parameters.ContainsKey("password"))
			{
				password = base.Context.Parameters["password"];
			}
			if (username != null && username.Length != 0 && password != null)
			{
				return;
			}
			if (!base.Context.Parameters.ContainsKey("unattended"))
			{
				using (ServiceInstallerDialog serviceInstallerDialog = new ServiceInstallerDialog())
				{
					if (username != null)
					{
						serviceInstallerDialog.Username = username;
					}
					serviceInstallerDialog.ShowDialog();
					switch (serviceInstallerDialog.Result)
					{
					case ServiceInstallerDialogResult.Canceled:
						throw new InvalidOperationException(Res.GetString("UserCanceledInstall", base.Context.Parameters["assemblypath"]));
					case ServiceInstallerDialogResult.UseSystem:
						username = null;
						password = null;
						serviceAccount = ServiceAccount.LocalSystem;
						break;
					case ServiceInstallerDialogResult.OK:
						username = serviceInstallerDialog.Username;
						password = serviceInstallerDialog.Password;
						break;
					}
					return;
				}
			}
			throw new InvalidOperationException(Res.GetString("UnattendedCannotPrompt", base.Context.Parameters["assemblypath"]));
		}

		private static void GrantAccountRight(IntPtr policyHandle, byte[] accountSid, string rightName)
		{
			NativeMethods.LSA_UNICODE_STRING lSA_UNICODE_STRING = new NativeMethods.LSA_UNICODE_STRING();
			lSA_UNICODE_STRING.buffer = rightName;
			lSA_UNICODE_STRING.length = (short)(lSA_UNICODE_STRING.buffer.Length * 2);
			lSA_UNICODE_STRING.maximumLength = (short)(lSA_UNICODE_STRING.buffer.Length * 2);
			int num = NativeMethods.LsaAddAccountRights(policyHandle, accountSid, lSA_UNICODE_STRING, 1);
			if (num != 0)
			{
				throw new Win32Exception(SafeNativeMethods.LsaNtStatusToWinError(num));
			}
		}

		public override void Install(IDictionary stateSaver)
		{
			try
			{
				ServiceInstaller.CheckEnvironment();
				try
				{
					if (!haveLoginInfo)
					{
						try
						{
							GetLoginInfo();
						}
						catch
						{
							stateSaver["hadServiceLogonRight"] = true;
							throw;
						}
					}
				}
				finally
				{
					stateSaver["Account"] = Account;
					if (Account == ServiceAccount.User)
					{
						stateSaver["Username"] = Username;
					}
				}
				if (Account != ServiceAccount.User)
				{
					return;
				}
				IntPtr intPtr = OpenSecurityPolicy();
				bool flag = true;
				try
				{
					byte[] accountSid = GetAccountSid(Username);
					flag = AccountHasRight(intPtr, accountSid, "SeServiceLogonRight");
					if (!flag)
					{
						GrantAccountRight(intPtr, accountSid, "SeServiceLogonRight");
					}
				}
				finally
				{
					stateSaver["hadServiceLogonRight"] = flag;
					SafeNativeMethods.LsaClose(intPtr);
				}
			}
			finally
			{
				base.Install(stateSaver);
			}
		}

		private IntPtr OpenSecurityPolicy()
		{
			NativeMethods.LSA_OBJECT_ATTRIBUTES value = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
			GCHandle gCHandle = GCHandle.Alloc(value, GCHandleType.Pinned);
			try
			{
				int num = 0;
				IntPtr pointerObjectAttributes = gCHandle.AddrOfPinnedObject();
				num = NativeMethods.LsaOpenPolicy(null, pointerObjectAttributes, 2064, out var pointerPolicyHandle);
				if (num != 0)
				{
					throw new Win32Exception(SafeNativeMethods.LsaNtStatusToWinError(num));
				}
				return pointerPolicyHandle;
			}
			finally
			{
				gCHandle.Free();
			}
		}

		private static void RemoveAccountRight(IntPtr policyHandle, byte[] accountSid, string rightName)
		{
			NativeMethods.LSA_UNICODE_STRING lSA_UNICODE_STRING = new NativeMethods.LSA_UNICODE_STRING();
			lSA_UNICODE_STRING.buffer = rightName;
			lSA_UNICODE_STRING.length = (short)(lSA_UNICODE_STRING.buffer.Length * 2);
			lSA_UNICODE_STRING.maximumLength = lSA_UNICODE_STRING.length;
			int num = NativeMethods.LsaRemoveAccountRights(policyHandle, accountSid, allRights: false, lSA_UNICODE_STRING, 1);
			if (num != 0)
			{
				throw new Win32Exception(SafeNativeMethods.LsaNtStatusToWinError(num));
			}
		}

		public override void Rollback(IDictionary savedState)
		{
			try
			{
				if ((ServiceAccount)savedState["Account"] == ServiceAccount.User && !(bool)savedState["hadServiceLogonRight"])
				{
					string accountName = (string)savedState["Username"];
					IntPtr intPtr = OpenSecurityPolicy();
					try
					{
						byte[] accountSid = GetAccountSid(accountName);
						RemoveAccountRight(intPtr, accountSid, "SeServiceLogonRight");
						return;
					}
					finally
					{
						SafeNativeMethods.LsaClose(intPtr);
					}
				}
			}
			finally
			{
				base.Rollback(savedState);
			}
		}
	}
}
namespace System.ServiceProcess.Telemetry
{
	internal static class ServiceProcessTraceLogger
	{
		[SuppressUnmanagedCodeSecurity]
		[SecurityCritical]
		[UnmanagedFunctionPointer(CallingConvention.Winapi)]
		internal delegate void TraceServiceStartMethod();

		private const string TraceServiceStartMethodName = "TraceServiceStart";

		private const string TraceServiceStartSourceModule = "netfxperf.dll";

		[SecurityCritical]
		[SecurityTreatAsSafe]
		internal static void TraceServiceProcessStart()
		{
			TraceServiceStartMethod traceServiceStartMethod = null;
			try
			{
				try
				{
					traceServiceStartMethod = GetMethod<TraceServiceStartMethod>("netfxperf.dll", "TraceServiceStart");
				}
				catch (EntryPointNotFoundException)
				{
				}
				try
				{
					traceServiceStartMethod?.Invoke();
				}
				catch (TargetInvocationException)
				{
				}
			}
			catch
			{
			}
		}

		[SecurityCritical]
		private static TDelegate GetMethod<TDelegate>(string system32Module, string entryPoint) where TDelegate : class
		{
			try
			{
				ValidateGetMethodArgs<TDelegate>(ref system32Module, ref entryPoint);
			}
			catch (ArgumentException inner)
			{
				throw new EntryPointNotFoundException(string.Empty, inner);
			}
			catch (NotSupportedException inner2)
			{
				throw new EntryPointNotFoundException(string.Empty, inner2);
			}
			Type typeFromHandle = typeof(TDelegate);
			IntPtr intPtr = NativeMethods.LoadLibraryHelper.SecureLoadLibraryEx(system32Module, IntPtr.Zero, NativeMethods.LoadLibraryFlags.LOAD_LIBRARY_SEARCH_SYSTEM32);
			if (intPtr == IntPtr.Zero)
			{
				throw new EntryPointNotFoundException("Failed to load " + system32Module, new Win32Exception());
			}
			IntPtr procAddress = NativeMethods.GetProcAddress(intPtr, entryPoint);
			if (procAddress == IntPtr.Zero)
			{
				throw new EntryPointNotFoundException("Failed to get entrypoint " + entryPoint + " from " + system32Module, new Win32Exception());
			}
			Delegate delegateForFunctionPointer = Marshal.GetDelegateForFunctionPointer(procAddress, typeFromHandle);
			if ((object)delegateForFunctionPointer == null)
			{
				throw new EntryPointNotFoundException("Failed to get managed delegate (" + typeFromHandle.Name + ") for function pointer " + entryPoint);
			}
			if (!(delegateForFunctionPointer is TDelegate result))
			{
				string text = $"{system32Module}!{entryPoint}";
				throw new EntryPointNotFoundException("Delegate for " + text + " is not of type " + typeFromHandle.Name);
			}
			return result;
		}

		private static void ValidateGetMethodArgs<TDelegate>(ref string system32Module, ref string entryPoint)
		{
			if (system32Module == null)
			{
				throw new ArgumentNullException("system32Module");
			}
			if (entryPoint == null)
			{
				throw new ArgumentNullException("entryPoint");
			}
			system32Module = system32Module.Trim();
			entryPoint = entryPoint.Trim();
			if (system32Module.Length == 0)
			{
				throw new ArgumentException("system32Module");
			}
			if (entryPoint.Length == 0)
			{
				throw new ArgumentException("entryPoint");
			}
			Type typeFromHandle = typeof(TDelegate);
			if (!typeof(Delegate).IsAssignableFrom(typeFromHandle))
			{
				throw new NotSupportedException(typeFromHandle.Name + " is not a Delegate");
			}
		}
	}
}
namespace System.ServiceProcess
{
	public enum ServiceStartMode
	{
		Manual = 3,
		Automatic = 2,
		Disabled = 4
	}
	[Flags]
	public enum ServiceType
	{
		Adapter = 4,
		FileSystemDriver = 2,
		InteractiveProcess = 0x100,
		KernelDriver = 1,
		RecognizerDriver = 8,
		Win32OwnProcess = 0x10,
		Win32ShareProcess = 0x20
	}
	public enum SessionChangeReason
	{
		ConsoleConnect = 1,
		ConsoleDisconnect,
		RemoteConnect,
		RemoteDisconnect,
		SessionLogon,
		SessionLogoff,
		SessionLock,
		SessionUnlock,
		SessionRemoteControl
	}
	public struct SessionChangeDescription
	{
		private SessionChangeReason _reason;

		private int _id;

		public SessionChangeReason Reason => _reason;

		public int SessionId => _id;

		internal SessionChangeDescription(SessionChangeReason reason, int id)
		{
			_reason = reason;
			_id = id;
		}

		public override bool Equals(object obj)
		{
			if (obj == null || !(obj is SessionChangeDescription))
			{
				return false;
			}
			return Equals((SessionChangeDescription)obj);
		}

		public override int GetHashCode()
		{
			return (int)_reason ^ _id;
		}

		public bool Equals(SessionChangeDescription changeDescription)
		{
			if (_reason == changeDescription._reason)
			{
				return _id == changeDescription._id;
			}
			return false;
		}

		public static bool operator ==(SessionChangeDescription a, SessionChangeDescription b)
		{
			return a.Equals(b);
		}

		public static bool operator !=(SessionChangeDescription a, SessionChangeDescription b)
		{
			return !a.Equals(b);
		}
	}
	[Serializable]
	public class TimeoutException : SystemException
	{
		public TimeoutException()
		{
			base.HResult = -2146232058;
		}

		public TimeoutException(string message)
			: base(message)
		{
			base.HResult = -2146232058;
		}

		public TimeoutException(string message, Exception innerException)
			: base(message, innerException)
		{
			base.HResult = -2146232058;
		}

		protected TimeoutException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[ComVisible(false)]
	[SuppressUnmanagedCodeSecurity]
	internal static class UnsafeNativeMethods
	{
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public unsafe static extern bool ControlService(IntPtr serviceHandle, int control, NativeMethods.SERVICE_STATUS* pStatus);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public unsafe static extern bool QueryServiceStatus(IntPtr serviceHandle, NativeMethods.SERVICE_STATUS* pStatus);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool EnumServicesStatus(IntPtr databaseHandle, int serviceType, int serviceState, IntPtr status, int size, out int bytesNeeded, out int servicesReturned, ref int resumeHandle);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool EnumServicesStatusEx(IntPtr databaseHandle, int infolevel, int serviceType, int serviceState, IntPtr status, int size, out int bytesNeeded, out int servicesReturned, ref int resumeHandle, string group);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr OpenService(IntPtr databaseHandle, string serviceName, int access);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool StartService(IntPtr serviceHandle, int argNum, IntPtr argPtrs);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool EnumDependentServices(IntPtr serviceHandle, int serviceState, IntPtr bufferOfENUM_SERVICE_STATUS, int bufSize, ref int bytesNeeded, ref int numEnumerated);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern bool QueryServiceConfig(IntPtr serviceHandle, IntPtr query_service_config_ptr, int bufferSize, out int bytesNeeded);
	}
}
namespace System.ServiceProcess.Design
{
	public enum ServiceInstallerDialogResult
	{
		OK,
		UseSystem,
		Canceled
	}
	public class ServiceInstallerDialog : Form
	{
		private Button okButton;

		private TextBox passwordEdit;

		private Button cancelButton;

		private TextBox confirmPassword;

		private TextBox usernameEdit;

		private Label label1;

		private Label label2;

		private Label label3;

		private TableLayoutPanel okCancelTableLayoutPanel;

		private TableLayoutPanel overarchingTableLayoutPanel;

		private ServiceInstallerDialogResult result;

		public string Password
		{
			get
			{
				return passwordEdit.Text;
			}
			set
			{
				passwordEdit.Text = value;
			}
		}

		public ServiceInstallerDialogResult Result => result;

		public string Username
		{
			get
			{
				return usernameEdit.Text;
			}
			set
			{
				usernameEdit.Text = value;
			}
		}

		public ServiceInstallerDialog()
		{
			InitializeComponent();
		}

		[STAThread]
		public static void Main()
		{
			Application.Run(new ServiceInstallerDialog());
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.ServiceProcess.Design.ServiceInstallerDialog));
			this.okButton = new System.Windows.Forms.Button();
			this.passwordEdit = new System.Windows.Forms.TextBox();
			this.cancelButton = new System.Windows.Forms.Button();
			this.confirmPassword = new System.Windows.Forms.TextBox();
			this.usernameEdit = new System.Windows.Forms.TextBox();
			this.label1 = new System.Windows.Forms.Label();
			this.label2 = new System.Windows.Forms.Label();
			this.label3 = new System.Windows.Forms.Label();
			this.okCancelTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.overarchingTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.okCancelTableLayoutPanel.SuspendLayout();
			this.overarchingTableLayoutPanel.SuspendLayout();
			base.SuspendLayout();
			resources.ApplyResources(this.okButton, "okButton");
			this.okButton.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.okButton.DialogResult = System.Windows.Forms.DialogResult.OK;
			this.okButton.Margin = new System.Windows.Forms.Padding(0, 0, 3, 0);
			this.okButton.MinimumSize = new System.Drawing.Size(75, 23);
			this.okButton.Name = "okButton";
			this.okButton.Padding = new System.Windows.Forms.Padding(10, 0, 10, 0);
			this.okButton.Click += new System.EventHandler(okButton_Click);
			resources.ApplyResources(this.passwordEdit, "passwordEdit");
			this.passwordEdit.Margin = new System.Windows.Forms.Padding(3, 3, 0, 3);
			this.passwordEdit.Name = "passwordEdit";
			resources.ApplyResources(this.cancelButton, "cancelButton");
			this.cancelButton.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.cancelButton.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.cancelButton.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
			this.cancelButton.MinimumSize = new System.Drawing.Size(75, 23);
			this.cancelButton.Name = "cancelButton";
			this.cancelButton.Padding = new System.Windows.Forms.Padding(10, 0, 10, 0);
			this.cancelButton.Click += new System.EventHandler(cancelButton_Click);
			resources.ApplyResources(this.confirmPassword, "confirmPassword");
			this.confirmPassword.Margin = new System.Windows.Forms.Padding(3, 3, 0, 3);
			this.confirmPassword.Name = "confirmPassword";
			resources.ApplyResources(this.usernameEdit, "usernameEdit");
			this.usernameEdit.Margin = new System.Windows.Forms.Padding(3, 0, 0, 3);
			this.usernameEdit.Name = "usernameEdit";
			resources.ApplyResources(this.label1, "label1");
			this.label1.Margin = new System.Windows.Forms.Padding(0, 0, 3, 3);
			this.label1.Name = "label1";
			resources.ApplyResources(this.label2, "label2");
			this.label2.Margin = new System.Windows.Forms.Padding(0, 3, 3, 3);
			this.label2.Name = "label2";
			resources.ApplyResources(this.label3, "label3");
			this.label3.Margin = new System.Windows.Forms.Padding(0, 3, 3, 3);
			this.label3.Name = "label3";
			resources.ApplyResources(this.okCancelTableLayoutPanel, "okCancelTableLayoutPanel");
			this.okCancelTableLayoutPanel.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.overarchingTableLayoutPanel.SetColumnSpan(this.okCancelTableLayoutPanel, 2);
			this.okCancelTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50f));
			this.okCancelTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50f));
			this.okCancelTableLayoutPanel.Controls.Add(this.okButton, 0, 0);
			this.okCancelTableLayoutPanel.Controls.Add(this.cancelButton, 1, 0);
			this.okCancelTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0, 6, 0, 0);
			this.okCancelTableLayoutPanel.Name = "okCancelTableLayoutPanel";
			this.okCancelTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50f));
			resources.ApplyResources(this.overarchingTableLayoutPanel, "overarchingTableLayoutPanel");
			this.overarchingTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.overarchingTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50f));
			this.overarchingTableLayoutPanel.Controls.Add(this.label1, 0, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.okCancelTableLayoutPanel, 0, 3);
			this.overarchingTableLayoutPanel.Controls.Add(this.label2, 0, 1);
			this.overarchingTableLayoutPanel.Controls.Add(this.confirmPassword, 1, 2);
			this.overarchingTableLayoutPanel.Controls.Add(this.label3, 0, 2);
			this.overarchingTableLayoutPanel.Controls.Add(this.passwordEdit, 1, 1);
			this.overarchingTableLayoutPanel.Controls.Add(this.usernameEdit, 1, 0);
			this.overarchingTableLayoutPanel.Name = "overarchingTableLayoutPanel";
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			base.AcceptButton = this.okButton;
			resources.ApplyResources(this, "$this");
			base.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			base.AutoScaleDimensions = new System.Drawing.SizeF(6f, 13f);
			base.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			base.CancelButton = this.cancelButton;
			base.Controls.Add(this.overarchingTableLayoutPanel);
			base.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			base.HelpButton = true;
			base.MaximizeBox = false;
			base.MinimizeBox = false;
			base.Name = "ServiceInstallerDialog";
			base.ShowIcon = false;
			base.ShowInTaskbar = false;
			base.HelpButtonClicked += new System.ComponentModel.CancelEventHandler(ServiceInstallerDialog_HelpButtonClicked);
			this.okCancelTableLayoutPanel.ResumeLayout(false);
			this.okCancelTableLayoutPanel.PerformLayout();
			this.overarchingTableLayoutPanel.ResumeLayout(false);
			this.overarchingTableLayoutPanel.PerformLayout();
			base.ResumeLayout(false);
		}

		private void cancelButton_Click(object sender, EventArgs e)
		{
			result = ServiceInstallerDialogResult.Canceled;
			base.DialogResult = DialogResult.Cancel;
		}

		private void okButton_Click(object sender, EventArgs e)
		{
			result = ServiceInstallerDialogResult.OK;
			if (passwordEdit.Text == confirmPassword.Text)
			{
				base.DialogResult = DialogResult.OK;
				return;
			}
			MessageBoxOptions options = (MessageBoxOptions)0;
			Control control = this;
			while (control.RightToLeft == RightToLeft.Inherit)
			{
				control = control.Parent;
			}
			if (control.RightToLeft == RightToLeft.Yes)
			{
				options = MessageBoxOptions.RightAlign | MessageBoxOptions.RtlReading;
			}
			base.DialogResult = DialogResult.None;
			MessageBox.Show(Res.GetString("Label_MissmatchedPasswords"), Res.GetString("Label_SetServiceLogin"), MessageBoxButtons.OK, MessageBoxIcon.Exclamation, MessageBoxDefaultButton.Button1, options);
			passwordEdit.Text = string.Empty;
			confirmPassword.Text = string.Empty;
			passwordEdit.Focus();
		}

		private void ServiceInstallerDialog_HelpButtonClicked(object sender, CancelEventArgs e)
		{
			e.Cancel = true;
		}
	}
	internal class ServiceNameConverter : TypeConverter
	{
		private StandardValuesCollection values;

		private string previousMachineName;

		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
		{
			if (sourceType == typeof(string))
			{
				return true;
			}
			return base.CanConvertFrom(context, sourceType);
		}

		public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
		{
			if (value is string)
			{
				return ((string)value).Trim();
			}
			return base.ConvertFrom(context, culture, value);
		}

		public override StandardValuesCollection GetStandardValues(ITypeDescriptorContext context)
		{
			ServiceController serviceController = ((context == null) ? null : (context.Instance as ServiceController));
			string text = ".";
			if (serviceController != null)
			{
				text = serviceController.MachineName;
			}
			if (values == null || text != previousMachineName)
			{
				try
				{
					ServiceController[] services = ServiceController.GetServices(text);
					string[] array = new string[services.Length];
					for (int i = 0; i < services.Length; i++)
					{
						array[i] = services[i].ServiceName;
					}
					values = new StandardValuesCollection(array);
					previousMachineName = text;
				}
				catch
				{
				}
			}
			return values;
		}

		public override bool GetStandardValuesExclusive(ITypeDescriptorContext context)
		{
			return false;
		}

		public override bool GetStandardValuesSupported(ITypeDescriptorContext context)
		{
			return true;
		}
	}
}
