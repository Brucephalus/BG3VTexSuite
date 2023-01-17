
// C:\WINDOWS\assembly\GAC_MSIL\System.Configuration.Install\2.0.0.0__b03f5f7f11d50a3a\System.Configuration.Install.dll
// System.Configuration.Install, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
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
using System.Runtime.Serialization.Formatters.Soap;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: CLSCompliant(true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: CompilationRelaxations(8)]
[assembly: AssemblyTitle("System.Configuration.Install.dll")]
[assembly: ComVisible(false)]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDescription("System.Configuration.Install.dll")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyDefaultAlias("System.Configuration.Install.dll")]
[assembly: AssemblyVersion("2.0.0.0")]
internal static class FXAssembly
{
	internal const string Version = "2.0.0.0";
}
internal static class ThisAssembly
{
	internal const string Title = "System.Configuration.Install.dll";

	internal const string Description = "System.Configuration.Install.dll";

	internal const string DefaultAlias = "System.Configuration.Install.dll";

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
namespace System.Configuration.Install
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
			resources = new ResourceManager("System.Configuration.Install", GetType().Assembly);
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
namespace System.Configuration.Install
{
	[DefaultEvent("AfterInstall")]
	public class Installer : Component
	{
		private const string wrappedExceptionSource = "WrappedExceptionSource";

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

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false)]
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

		[TypeConverter(typeof(InstallerParentConverter))]
		[Browsable(true)]
		[ResDescription("Desc_Installer_Parent")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
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

		protected virtual void OnCommitted(IDictionary savedState)
		{
			if (afterCommitHandler != null)
			{
				afterCommitHandler(this, new InstallEventArgs(savedState));
			}
		}

		protected virtual void OnAfterInstall(IDictionary savedState)
		{
			if (afterInstallHandler != null)
			{
				afterInstallHandler(this, new InstallEventArgs(savedState));
			}
		}

		protected virtual void OnAfterRollback(IDictionary savedState)
		{
			if (afterRollbackHandler != null)
			{
				afterRollbackHandler(this, new InstallEventArgs(savedState));
			}
		}

		protected virtual void OnAfterUninstall(IDictionary savedState)
		{
			if (afterUninstallHandler != null)
			{
				afterUninstallHandler(this, new InstallEventArgs(savedState));
			}
		}

		protected virtual void OnCommitting(IDictionary savedState)
		{
			if (beforeCommitHandler != null)
			{
				beforeCommitHandler(this, new InstallEventArgs(savedState));
			}
		}

		protected virtual void OnBeforeInstall(IDictionary savedState)
		{
			if (beforeInstallHandler != null)
			{
				beforeInstallHandler(this, new InstallEventArgs(savedState));
			}
		}

		protected virtual void OnBeforeRollback(IDictionary savedState)
		{
			if (beforeRollbackHandler != null)
			{
				beforeRollbackHandler(this, new InstallEventArgs(savedState));
			}
		}

		protected virtual void OnBeforeUninstall(IDictionary savedState)
		{
			if (beforeUninstallHandler != null)
			{
				beforeUninstallHandler(this, new InstallEventArgs(savedState));
			}
		}

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
				if (array.Length != Installers.Count)
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
	}
	public class AssemblyInstaller : Installer
	{
		private Assembly assembly;

		private string[] commandLine;

		private bool useNewContext;

		private static bool helpPrinted;

		private bool initialized;

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

		public AssemblyInstaller()
		{
		}

		public AssemblyInstaller(string fileName, string[] commandLine)
		{
			Path = System.IO.Path.GetFullPath(fileName);
			this.commandLine = commandLine;
			useNewContext = true;
		}

		public AssemblyInstaller(Assembly assembly, string[] commandLine)
		{
			Assembly = assembly;
			this.commandLine = commandLine;
			useNewContext = true;
		}

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

		public override void Commit(IDictionary savedState)
		{
			PrintStartText(Res.GetString("InstallActivityCommitting"));
			if (!initialized)
			{
				InitializeFromAssembly();
			}
			string installStatePath = GetInstallStatePath(Path);
			FileStream fileStream = new FileStream(installStatePath, FileMode.Open, FileAccess.Read);
			try
			{
				SoapFormatter soapFormatter = new SoapFormatter();
				savedState = (IDictionary)soapFormatter.Deserialize(fileStream);
			}
			finally
			{
				fileStream.Close();
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

		public override void Install(IDictionary savedState)
		{
			PrintStartText(Res.GetString("InstallActivityInstalling"));
			if (!initialized)
			{
				InitializeFromAssembly();
			}
			savedState = new Hashtable();
			try
			{
				base.Install(savedState);
			}
			finally
			{
				FileStream fileStream = new FileStream(GetInstallStatePath(Path), FileMode.Create);
				try
				{
					SoapFormatter soapFormatter = new SoapFormatter();
					soapFormatter.Serialize(fileStream, savedState);
				}
				finally
				{
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
			base.Context.LogMessage(string.Format(CultureInfo.InvariantCulture, activity, Path));
			base.Context.LogMessage(Res.GetString("InstallLogParameters"));
			if (base.Context.Parameters.Count == 0)
			{
				base.Context.LogMessage("   " + Res.GetString("InstallLogNone"));
			}
			IDictionaryEnumerator dictionaryEnumerator = (IDictionaryEnumerator)base.Context.Parameters.GetEnumerator();
			while (dictionaryEnumerator.MoveNext())
			{
				base.Context.LogMessage("   " + (string)dictionaryEnumerator.Key + " = " + (string)dictionaryEnumerator.Value);
			}
		}

		public override void Rollback(IDictionary savedState)
		{
			PrintStartText(Res.GetString("InstallActivityRollingBack"));
			if (!initialized)
			{
				InitializeFromAssembly();
			}
			string installStatePath = GetInstallStatePath(Path);
			FileStream fileStream = new FileStream(installStatePath, FileMode.Open, FileAccess.Read);
			try
			{
				SoapFormatter soapFormatter = new SoapFormatter();
				savedState = (IDictionary)soapFormatter.Deserialize(fileStream);
			}
			finally
			{
				fileStream.Close();
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
				try
				{
					SoapFormatter soapFormatter = new SoapFormatter();
					savedState = (IDictionary)soapFormatter.Deserialize(fileStream);
				}
				catch
				{
					base.Context.LogMessage(Res.GetString("InstallSavedStateFileCorruptedWarning", Path, installStatePath));
					savedState = null;
				}
				finally
				{
					fileStream.Close();
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
	public abstract class ComponentInstaller : Installer
	{
		public abstract void CopyFromComponent(IComponent component);

		public virtual bool IsEquivalentInstaller(ComponentInstaller otherInstaller)
		{
			return false;
		}
	}
}
namespace System.Diagnostics
{
	public class EventLogInstaller : ComponentInstaller
	{
		private EventSourceCreationData sourceData = new EventSourceCreationData(null, null);

		private UninstallAction uninstallAction;

		[ResDescription("Desc_CategoryResourceFile")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[Editor("System.Windows.Forms.Design.FileNameEditor, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ComVisible(false)]
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

		[ResDescription("Desc_CategoryCount")]
		[ComVisible(false)]
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

		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
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

		[ComVisible(false)]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ResDescription("Desc_MessageResourceFile")]
		[Editor("System.Windows.Forms.Design.FileNameEditor, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
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

		[ResDescription("Desc_ParameterResourceFile")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ComVisible(false)]
		[Editor("System.Windows.Forms.Design.FileNameEditor, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
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

		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
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

		public override bool IsEquivalentInstaller(ComponentInstaller otherInstaller)
		{
			if (!(otherInstaller is EventLogInstaller eventLogInstaller))
			{
				return false;
			}
			return eventLogInstaller.Source == Source;
		}

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
	}
}
namespace System.Configuration.Install
{
	[ComImport]
	[Guid("1E233FE7-C16D-4512-8C3B-2E9988F08D38")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IManagedInstaller
	{
		[return: MarshalAs(UnmanagedType.I4)]
		int ManagedInstall([In][MarshalAs(UnmanagedType.BStr)] string commandLine, [In][MarshalAs(UnmanagedType.I4)] int hInstall);
	}
	public class InstallContext
	{
		private string logFilePath;

		private StringDictionary parameters;

		public StringDictionary Parameters => parameters;

		public InstallContext()
			: this(null, null)
		{
		}

		public InstallContext(string logFilePath, string[] commandLine)
		{
			parameters = ParseCommandLine(commandLine);
			if (Parameters["logfile"] != null)
			{
				this.logFilePath = Parameters["logfile"];
			}
			else if (logFilePath != null)
			{
				this.logFilePath = logFilePath;
				Parameters["logfile"] = logFilePath;
			}
		}

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

		public void LogMessage(string message)
		{
			logFilePath = Parameters["logfile"];
			if (logFilePath != null && !"".Equals(logFilePath))
			{
				StreamWriter streamWriter = null;
				try
				{
					streamWriter = new StreamWriter(logFilePath, append: true, Encoding.UTF8);
					streamWriter.WriteLine(message);
				}
				finally
				{
					streamWriter?.Close();
				}
			}
			if (IsParameterTrue("LogToConsole") || Parameters["logtoconsole"] == null)
			{
				Console.WriteLine(message);
			}
		}

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
	public class InstallerCollection : CollectionBase
	{
		private Installer owner;

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

		public int Add(Installer value)
		{
			return base.List.Add(value);
		}

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

		public bool Contains(Installer value)
		{
			return base.List.Contains(value);
		}

		public void CopyTo(Installer[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(Installer value)
		{
			return base.List.IndexOf(value);
		}

		public void Insert(int index, Installer value)
		{
			base.List.Insert(index, value);
		}

		public void Remove(Installer value)
		{
			base.List.Remove(value);
		}

		protected override void OnInsert(int index, object value)
		{
			if (value == owner)
			{
				throw new ArgumentException(Res.GetString("CantAddSelf"));
			}
			_ = System.ComponentModel.CompModSwitches.InstallerDesign.TraceVerbose;
			((Installer)value).parent = owner;
		}

		protected override void OnRemove(int index, object value)
		{
			_ = System.ComponentModel.CompModSwitches.InstallerDesign.TraceVerbose;
			((Installer)value).parent = null;
		}

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
	public class InstallEventArgs : EventArgs
	{
		private IDictionary savedState;

		public IDictionary SavedState => savedState;

		public InstallEventArgs()
		{
		}

		public InstallEventArgs(IDictionary savedState)
		{
			this.savedState = savedState;
		}
	}
	public delegate void InstallEventHandler(object sender, InstallEventArgs e);
	[Serializable]
	public class InstallException : SystemException
	{
		public InstallException()
		{
			base.HResult = -2146232057;
		}

		public InstallException(string message)
			: base(message)
		{
		}

		public InstallException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected InstallException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[ComVisible(true)]
	[Guid("42EB0342-0393-448f-84AA-D4BEB0283595")]
	public class ManagedInstallerClass : IManagedInstaller
	{
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
}
namespace System.Diagnostics
{
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

		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[DefaultValue("")]
		[ResDescription("PCCategoryName")]
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

		[ComVisible(false)]
		[DefaultValue(PerformanceCounterCategoryType.Unknown)]
		[ResDescription("PCI_IsMultiInstance")]
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

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Content)]
		[ResDescription("PCI_Counters")]
		public CounterCreationDataCollection Counters => counters;

		[ResDescription("PCI_UninstallAction")]
		[DefaultValue(UninstallAction.Remove)]
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
			PerformanceCounterCategory.Create(CategoryName, CategoryHelp, categoryType, Counters);
		}

		public override void Rollback(IDictionary savedState)
		{
			base.Rollback(savedState);
			DoRollback(savedState);
		}

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
				throw new ArgumentException(Res.GetString("PerfInvalidCategoryName", 1, 80));
			}
		}

		internal static bool CheckValidId(string id)
		{
			if (id.Length == 0 || id.Length > 80)
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
	}
	[Serializable]
	internal class SerializableRegistryKey
	{
		public string[] ValueNames;

		public object[] Values;

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
			for (int i = 0; i < ValueNames.Length; i++)
			{
				Values[i] = keyToSave.GetValue(ValueNames[i]);
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
					baseKey.SetValue(ValueNames[i], Values[i]);
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
	public class TransactedInstaller : Installer
	{
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
	}
	public enum UninstallAction
	{
		Remove,
		NoAction
	}
}
