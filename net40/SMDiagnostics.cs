
// C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\SMDiagnostics\v4.0_4.0.0.0__b77a5c561934e089\SMDiagnostics.dll
// SMDiagnostics, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v4.0.30319
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 00000000000000000400000000000000

#define TRACE
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.ServiceModel.Configuration;
using System.Text;
using System.Threading;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Win32.SafeHandles;

[assembly: CompilationRelaxations(8)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: InternalsVisibleTo("infocard, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("IndigoUdpTransport, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("Microsoft.Transactions.Bridge, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("Microsoft.Transactions.Bridge.Dtc, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("System.IdentityModel.Selectors, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.IO.Log, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("System.Runtime.Serialization, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.ServiceModel, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.ServiceModel.Activation, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.Friend, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("System.ServiceModel.WasHosting, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.IdentityModel, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.IdentityModel.Services, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("SMSvcHost, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("ChannelFx, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("System.WorkflowServices, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.Web, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("Microsoft.ServiceModel.Web.Test, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: ComVisible(false)]
[assembly: CLSCompliant(true)]
[assembly: AllowPartiallyTrustedCallers]
[assembly: SecurityCritical]
[assembly: SecurityRules(SecurityRuleSet.Level1, SkipVerificationInFullTrust = true)]
[assembly: AssemblyTitle("SMDiagnostics.dll")]
[assembly: AssemblyDescription("SMDiagnostics.dll")]
[assembly: AssemblyDefaultAlias("SMDiagnostics.dll")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyFileVersion("4.8.9037.0")]
[assembly: AssemblyInformationalVersion("4.8.9037.0")]
[assembly: SatelliteContractVersion("4.0.0.0")]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyKeyFile("f:\\dd\\tools\\devdiv\\EcmaPublicKey.snk")]
[assembly: AssemblySignatureKey("002400000c800000140100000602000000240000525341310008000001000100613399aff18ef1a2c2514a273a42d9042b72321f1757102df9ebada69923e2738406c21e5b801552ab8d200a65a235e001ac9adc25f2d811eb09496a4c6a59d4619589c69f5baf0c4179a47311d92555cd006acc8b5959f2bd6e10e360c34537a1d266da8085856583c85d81da7f3ec01ed9564c58d93d713cd0172c8e23a10f0239b80c96b07736f5d8b022542a4e74251a5f432824318b3539a5a087f8e53d2f135f9ca47f3bb2e10aff0af0849504fb7cea3ff192dc8de0edad64c68efde34c56d302ad55fd6e80f302d5efcdeae953658d3452561b5f36c542efdbdd9f888538d374cef106acf7d93a4445c3c73cd911f0571aaf3d54da12b11ddec375b3", "a5a866e1ee186f807668209f3b11236ace5e21f117803a3143abb126dd035d7d2f876b6938aaf2ee3414d5420d753621400db44a49c486ce134300a2106adb6bdb433590fef8ad5c43cba82290dc49530effd86523d9483c00f458af46890036b0e2c61d077d7fbac467a506eba29e467a87198b053c749aa2a4d2840c784e6d")]
[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32 | DllImportSearchPath.AssemblyDirectory)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("4.0.0.0")]
[module: UnverifiableCode]
namespace System.ServiceModel.Configuration
{
	internal class MachineSettingsSection : ConfigurationSection
	{
		private static bool enableLoggingKnownPii;

		private static bool hasInitialized = false;

		private static object syncRoot = new object();

		private const string enableLoggingKnownPiiKey = "enableLoggingKnownPii";

		private ConfigurationPropertyCollection properties;

		protected internal override ConfigurationPropertyCollection Properties
		{
			protected get
			{
				if (properties == null)
				{
					ConfigurationPropertyCollection configurationPropertyCollection = new ConfigurationPropertyCollection();
					configurationPropertyCollection.Add(new ConfigurationProperty("enableLoggingKnownPii", typeof(bool), false, null, null, ConfigurationPropertyOptions.None));
					properties = configurationPropertyCollection;
				}
				return properties;
			}
		}

		public static bool EnableLoggingKnownPii
		{
			get
			{
				if (!hasInitialized)
				{
					lock (syncRoot)
					{
						if (!hasInitialized)
						{
							MachineSettingsSection machineSettingsSection = (MachineSettingsSection)ConfigurationManager.GetSection("system.serviceModel/machineSettings");
							enableLoggingKnownPii = (bool)machineSettingsSection["enableLoggingKnownPii"];
							hasInitialized = true;
						}
					}
				}
				return enableLoggingKnownPii;
			}
		}
	}
}
namespace System.ServiceModel.Diagnostics
{
	internal class Activity : IDisposable
	{
		protected Guid parentId;

		private Guid currentId;

		private bool mustDispose;

		protected Guid Id => currentId;

		protected Activity(Guid activityId, Guid parentId)
		{
			currentId = activityId;
			this.parentId = parentId;
			mustDispose = true;
			DiagnosticTraceBase.ActivityId = currentId;
		}

		internal static Activity CreateActivity(Guid activityId)
		{
			Activity result = null;
			if (activityId != Guid.Empty)
			{
				Guid activityId2 = DiagnosticTraceBase.ActivityId;
				if (activityId != activityId2)
				{
					result = new Activity(activityId, activityId2);
				}
			}
			return result;
		}

		public virtual void Dispose()
		{
			if (mustDispose)
			{
				mustDispose = false;
				DiagnosticTraceBase.ActivityId = parentId;
			}
			GC.SuppressFinalize(this);
		}
	}
	internal class DiagnosticTraceSource : PiiTraceSource
	{
		private const string PropagateActivityValue = "propagateActivity";

		internal bool PropagateActivity
		{
			get
			{
				bool result = false;
				string value = base.Attributes["propagateActivity"];
				if (!string.IsNullOrEmpty(value) && !bool.TryParse(value, out result))
				{
					result = false;
				}
				return result;
			}
			set
			{
				base.Attributes["propagateActivity"] = value.ToString();
			}
		}

		internal DiagnosticTraceSource(string name, string eventSourceName)
			: base(name, eventSourceName)
		{
		}

		internal DiagnosticTraceSource(string name, string eventSourceName, SourceLevels level)
			: base(name, eventSourceName, level)
		{
		}

		protected override string[] GetSupportedAttributes()
		{
			string[] supportedAttributes = base.GetSupportedAttributes();
			string[] array = new string[supportedAttributes.Length + 1];
			for (int i = 0; i < supportedAttributes.Length; i++)
			{
				array[i] = supportedAttributes[i];
			}
			array[supportedAttributes.Length] = "propagateActivity";
			return array;
		}
	}
	internal static class DiagnosticStrings
	{
		internal const string DiagnosticsNamespace = "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics";

		internal const string ActivityIdName = "E2ETrace.ActivityID";

		internal const string ActivityId = "ActivityId";

		internal const string AppDomain = "AppDomain";

		internal const string DataTag = "Data";

		internal const string DataItemsTag = "DataItems";

		internal const string DeflateCookieAfterDeflatingTag = "AfterDeflating";

		internal const string DeflateCookieOriginalSizeTag = "OriginalSize";

		internal const string DescriptionTag = "Description";

		internal const string EventLogTag = "EventLog";

		internal const string ExceptionTag = "Exception";

		internal const string ExceptionTypeTag = "ExceptionType";

		internal const string ExceptionStringTag = "ExceptionString";

		internal const string ExtendedDataTag = "ExtendedData";

		internal const string HeaderTag = "Header";

		internal const string InnerExceptionTag = "InnerException";

		internal const string KeyTag = "Key";

		internal const string MessageTag = "Message";

		internal const string NameTag = "Name";

		internal const string NamespaceTag = "xmlns";

		internal const string NativeErrorCodeTag = "NativeErrorCode";

		internal const string ProcessId = "ProcessId";

		internal const string ProcessName = "ProcessName";

		internal const string RoleTag = "Role";

		internal const string SeverityTag = "Severity";

		internal const string SourceTag = "Source";

		internal const string StackTraceTag = "StackTrace";

		internal const string TraceCodeTag = "TraceIdentifier";

		internal const string TraceRecordTag = "TraceRecord";

		internal const string ValueTag = "Value";

		internal static string[][] HeadersPaths = new string[2][]
		{
			new string[4] { "TraceRecord", "ExtendedData", "MessageHeaders", "Security" },
			new string[4] { "TraceRecord", "ExtendedData", "MessageHeaders", "IssuedTokens" }
		};

		internal static string[] PiiList = new string[9] { "BinarySecret", "Entropy", "Password", "Nonce", "Username", "BinarySecurityToken", "NameIdentifier", "SubjectLocality", "AttributeValue" };
	}
	[Obsolete("This has been replaced by System.Runtime.Diagnostics.EventLogCategory")]
	internal enum EventLogCategory : ushort
	{
		ServiceAuthorization = 1,
		MessageAuthentication,
		ObjectAccess,
		Tracing,
		WebHost,
		FailFast,
		MessageLogging,
		PerformanceCounter,
		Wmi,
		ComPlus,
		StateMachine,
		Wsat,
		SharingService,
		ListenerAdapter
	}
	[Obsolete("This has been replaced by System.Runtime.Diagnostics.EventLogEventId")]
	internal enum EventLogEventId : uint
	{
		FailedToSetupTracing = 3221291108u,
		FailedToInitializeTraceSource = 3221291109u,
		FailFast = 3221291110u,
		FailFastException = 3221291111u,
		FailedToTraceEvent = 3221291112u,
		FailedToTraceEventWithException = 3221291113u,
		InvariantAssertionFailed = 3221291114u,
		PiiLoggingOn = 3221291115u,
		PiiLoggingNotAllowed = 3221291116u,
		WebHostUnhandledException = 3221356545u,
		WebHostHttpError = 3221356546u,
		WebHostFailedToProcessRequest = 3221356547u,
		WebHostFailedToListen = 3221356548u,
		FailedToLogMessage = 3221356549u,
		RemovedBadFilter = 3221356550u,
		FailedToCreateMessageLoggingTraceSource = 3221356551u,
		MessageLoggingOn = 3221356552u,
		MessageLoggingOff = 3221356553u,
		FailedToLoadPerformanceCounter = 3221356554u,
		FailedToRemovePerformanceCounter = 3221356555u,
		WmiGetObjectFailed = 3221356556u,
		WmiPutInstanceFailed = 3221356557u,
		WmiDeleteInstanceFailed = 3221356558u,
		WmiCreateInstanceFailed = 3221356559u,
		WmiExecQueryFailed = 3221356560u,
		WmiExecMethodFailed = 3221356561u,
		WmiRegistrationFailed = 3221356562u,
		WmiUnregistrationFailed = 3221356563u,
		WmiAdminTypeMismatch = 3221356564u,
		WmiPropertyMissing = 3221356565u,
		ComPlusServiceHostStartingServiceError = 3221356566u,
		ComPlusDllHostInitializerStartingError = 3221356567u,
		ComPlusTLBImportError = 3221356568u,
		ComPlusInvokingMethodFailed = 3221356569u,
		ComPlusInstanceCreationError = 3221356570u,
		ComPlusInvokingMethodFailedMismatchedTransactions = 3221356571u,
		UnhandledStateMachineExceptionRecordDescription = 3221422081u,
		FatalUnexpectedStateMachineEvent = 3221422082u,
		ParticipantRecoveryLogEntryCorrupt = 3221422083u,
		CoordinatorRecoveryLogEntryCorrupt = 3221422084u,
		CoordinatorRecoveryLogEntryCreationFailure = 3221422085u,
		ParticipantRecoveryLogEntryCreationFailure = 3221422086u,
		ProtocolInitializationFailure = 3221422087u,
		ProtocolStartFailure = 3221422088u,
		ProtocolRecoveryBeginningFailure = 3221422089u,
		ProtocolRecoveryCompleteFailure = 3221422090u,
		TransactionBridgeRecoveryFailure = 3221422091u,
		ProtocolStopFailure = 3221422092u,
		NonFatalUnexpectedStateMachineEvent = 3221422093u,
		PerformanceCounterInitializationFailure = 3221422094u,
		ProtocolRecoveryComplete = 3221422095u,
		ProtocolStopped = 3221422096u,
		ThumbPrintNotFound = 3221422097u,
		ThumbPrintNotValidated = 3221422098u,
		SslNoPrivateKey = 3221422099u,
		SslNoAccessiblePrivateKey = 3221422100u,
		MissingNecessaryKeyUsage = 3221422101u,
		MissingNecessaryEnhancedKeyUsage = 3221422102u,
		StartErrorPublish = 3221487617u,
		BindingError = 3221487618u,
		LAFailedToListenForApp = 3221487619u,
		UnknownListenerAdapterError = 3221487620u,
		WasDisconnected = 3221487621u,
		WasConnectionTimedout = 3221487622u,
		ServiceStartFailed = 3221487623u,
		MessageQueueDuplicatedSocketLeak = 3221487624u,
		MessageQueueDuplicatedPipeLeak = 3221487625u,
		SharingUnhandledException = 3221487626u,
		ServiceAuthorizationSuccess = 1074135041u,
		ServiceAuthorizationFailure = 3221618690u,
		MessageAuthenticationSuccess = 1074135043u,
		MessageAuthenticationFailure = 3221618692u,
		SecurityNegotiationSuccess = 1074135045u,
		SecurityNegotiationFailure = 3221618694u,
		TransportAuthenticationSuccess = 1074135047u,
		TransportAuthenticationFailure = 3221618696u,
		ImpersonationSuccess = 1074135049u,
		ImpersonationFailure = 3221618698u
	}
	[Obsolete("This has been replaced by System.Runtime.Diagnostics.EventLogger")]
	internal class EventLogger
	{
		private System.Runtime.Diagnostics.EventLogger innerEventLogger;

		private EventLogger()
		{
		}

		[Obsolete("For SMDiagnostics.dll use only. Call DiagnosticUtility.EventLog instead")]
		internal EventLogger(string eventLogSourceName, object diagnosticTrace)
		{
			innerEventLogger = new System.Runtime.Diagnostics.EventLogger(eventLogSourceName, (DiagnosticTraceBase)diagnosticTrace);
		}

		[SecurityCritical]
		internal static EventLogger UnsafeCreateEventLogger(string eventLogSourceName, object diagnosticTrace)
		{
			EventLogger eventLogger = new EventLogger();
			eventLogger.innerEventLogger = System.Runtime.Diagnostics.EventLogger.UnsafeCreateEventLogger(eventLogSourceName, (DiagnosticTraceBase)diagnosticTrace);
			return eventLogger;
		}

		internal void LogEvent(TraceEventType type, EventLogCategory category, EventLogEventId eventId, bool shouldTrace, params string[] values)
		{
			innerEventLogger.LogEvent(type, (ushort)category, (uint)eventId, shouldTrace, values);
		}

		[SecurityCritical]
		internal void UnsafeLogEvent(TraceEventType type, EventLogCategory category, EventLogEventId eventId, bool shouldTrace, params string[] values)
		{
			innerEventLogger.UnsafeLogEvent(type, (ushort)category, (uint)eventId, shouldTrace, values);
		}

		internal void LogEvent(TraceEventType type, EventLogCategory category, EventLogEventId eventId, params string[] values)
		{
			innerEventLogger.LogEvent(type, (ushort)category, (uint)eventId, values);
		}

		internal static string NormalizeEventLogParameter(string param)
		{
			return System.Runtime.Diagnostics.EventLogger.NormalizeEventLogParameter(param);
		}
	}
	internal class ExceptionUtility
	{
		private const string ExceptionStackAsStringKey = "System.ServiceModel.Diagnostics.ExceptionUtility.ExceptionStackAsString";

		internal static ExceptionUtility mainInstance;

		private LegacyDiagnosticTrace diagnosticTrace;

		private ExceptionTrace exceptionTrace;

		private string name;

		private string eventSourceName;

		[ThreadStatic]
		private static Guid activityId;

		[ThreadStatic]
		private static bool useStaticActivityId;

		[Obsolete("For SMDiagnostics.dll use only. Call DiagnosticUtility.ExceptionUtility instead")]
		internal ExceptionUtility(string name, string eventSourceName, object diagnosticTrace, object exceptionTrace)
		{
			this.diagnosticTrace = (LegacyDiagnosticTrace)diagnosticTrace;
			this.exceptionTrace = (ExceptionTrace)exceptionTrace;
			this.name = name;
			this.eventSourceName = eventSourceName;
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[Obsolete("For SMDiagnostics.dll use only. Call DiagnosticUtility.ExceptionUtility instead")]
		internal void TraceFailFast(string message)
		{
			System.Runtime.Diagnostics.EventLogger logger = null;
			try
			{
				logger = new System.Runtime.Diagnostics.EventLogger(eventSourceName, diagnosticTrace);
			}
			finally
			{
				TraceFailFast(message, logger);
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[Obsolete("For SMDiagnostics.dll use only. Call DiagnosticUtility.ExceptionUtility instead")]
		internal static void TraceFailFast(string message, System.Runtime.Diagnostics.EventLogger logger)
		{
			try
			{
				if (logger == null)
				{
					return;
				}
				string text = null;
				try
				{
					text = new StackTrace().ToString();
				}
				catch (Exception ex)
				{
					text = ex.Message;
				}
				finally
				{
					logger.LogEvent(TraceEventType.Critical, 6, 3221291110u, message, text);
				}
			}
			catch (Exception ex2)
			{
				logger?.LogEvent(TraceEventType.Critical, 6, 3221291111u, ex2.ToString());
				throw;
			}
		}

		[Obsolete("For SMDiagnostics.dll use only. Call DiagnosticUtility.ExceptionUtility instead")]
		internal void TraceFailFastException(Exception exception)
		{
			TraceFailFast(exception?.ToString());
		}

		internal Exception ThrowHelper(Exception exception, TraceEventType eventType, TraceRecord extendedData)
		{
			if (diagnosticTrace != null && diagnosticTrace.ShouldTrace(eventType))
			{
				using (useStaticActivityId ? Activity.CreateActivity(activityId) : null)
				{
					diagnosticTrace.TraceEvent(eventType, 131075, LegacyDiagnosticTrace.GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "ThrowingException"), TraceSR.GetString("ThrowingException"), extendedData, exception, null);
				}
				IDictionary data = exception.Data;
				if (data != null && !data.IsReadOnly && !data.IsFixedSize)
				{
					object obj = data["System.ServiceModel.Diagnostics.ExceptionUtility.ExceptionStackAsString"];
					string text = ((obj == null) ? "" : (obj as string));
					if (text != null)
					{
						string stackTrace = exception.StackTrace;
						if (!string.IsNullOrEmpty(stackTrace))
						{
							text = (string)(data["System.ServiceModel.Diagnostics.ExceptionUtility.ExceptionStackAsString"] = text + ((text.Length == 0) ? "" : Environment.NewLine) + "throw" + Environment.NewLine + stackTrace + Environment.NewLine + "catch" + Environment.NewLine);
						}
					}
				}
			}
			exceptionTrace.TraceEtwException(exception, eventType);
			return exception;
		}

		internal Exception ThrowHelper(Exception exception, TraceEventType eventType)
		{
			return ThrowHelper(exception, eventType, null);
		}

		internal ArgumentException ThrowHelperArgument(string message)
		{
			return (ArgumentException)ThrowHelperError(new ArgumentException(message));
		}

		internal ArgumentException ThrowHelperArgument(string paramName, string message)
		{
			return (ArgumentException)ThrowHelperError(new ArgumentException(message, paramName));
		}

		internal ArgumentNullException ThrowHelperArgumentNull(string paramName)
		{
			return (ArgumentNullException)ThrowHelperError(new ArgumentNullException(paramName));
		}

		internal ArgumentNullException ThrowHelperArgumentNull(string paramName, string message)
		{
			return (ArgumentNullException)ThrowHelperError(new ArgumentNullException(paramName, message));
		}

		internal ArgumentException ThrowHelperArgumentNullOrEmptyString(string arg)
		{
			return (ArgumentException)ThrowHelperError(new ArgumentException(TraceSR.GetString("StringNullOrEmpty"), arg));
		}

		internal Exception ThrowHelperFatal(string message, Exception innerException)
		{
			return ThrowHelperError(new FatalException(message, innerException));
		}

		internal Exception ThrowHelperInternal(bool fatal)
		{
			if (!fatal)
			{
				return Fx.AssertAndThrow("InternalException should never be thrown.");
			}
			return Fx.AssertAndThrowFatal("Fatal InternalException should never be thrown.");
		}

		internal Exception ThrowHelperInvalidOperation(string message)
		{
			return ThrowHelperError(new InvalidOperationException(message));
		}

		internal Exception ThrowHelperCallback(string message, Exception innerException)
		{
			return ThrowHelperCritical(new CallbackException(message, innerException));
		}

		internal Exception ThrowHelperCallback(Exception innerException)
		{
			return ThrowHelperCallback(TraceSR.GetString("GenericCallbackException"), innerException);
		}

		internal Exception ThrowHelperCritical(Exception exception)
		{
			return ThrowHelper(exception, TraceEventType.Critical);
		}

		internal Exception ThrowHelperError(Exception exception)
		{
			return ThrowHelper(exception, TraceEventType.Error);
		}

		internal Exception ThrowHelperWarning(Exception exception)
		{
			return ThrowHelper(exception, TraceEventType.Warning);
		}

		internal Exception ThrowHelperXml(XmlReader reader, string message)
		{
			return ThrowHelperXml(reader, message, null);
		}

		internal Exception ThrowHelperXml(XmlReader reader, string message, Exception inner)
		{
			IXmlLineInfo xmlLineInfo = reader as IXmlLineInfo;
			return ThrowHelperError(new XmlException(message, inner, xmlLineInfo?.LineNumber ?? 0, xmlLineInfo?.LinePosition ?? 0));
		}

		internal void DiagnosticTraceHandledException(Exception exception, TraceEventType eventType)
		{
			if (diagnosticTrace != null && diagnosticTrace.ShouldTrace(eventType))
			{
				using (useStaticActivityId ? Activity.CreateActivity(activityId) : null)
				{
					diagnosticTrace.TraceEvent(eventType, 131076, LegacyDiagnosticTrace.GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "TraceHandledException"), TraceSR.GetString("TraceHandledException"), null, exception, null);
				}
			}
		}

		internal static void UseActivityId(Guid activityId)
		{
			ExceptionUtility.activityId = activityId;
			useStaticActivityId = true;
		}

		internal static void ClearActivityId()
		{
			useStaticActivityId = false;
			activityId = Guid.Empty;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static bool IsInfrastructureException(Exception exception)
		{
			if (exception != null)
			{
				if (!(exception is ThreadAbortException))
				{
					return exception is AppDomainUnloadedException;
				}
				return true;
			}
			return false;
		}
	}
	internal class LegacyDiagnosticTrace : DiagnosticTraceBase
	{
		private const int MaxTraceSize = 65535;

		private bool shouldUseActivity;

		private TraceSourceKind traceSourceType = TraceSourceKind.PiiTraceSource;

		private const string subType = "";

		private const string version = "1";

		private const int traceFailureLogThreshold = 1;

		private const SourceLevels DefaultLevel = SourceLevels.Off;

		private static object classLockObject = new object();

		[Obsolete("For SMDiagnostics.dll use only. Call DiagnosticUtility.ShouldUseActivity instead")]
		internal bool ShouldUseActivity => shouldUseActivity;

		public bool ShouldLogPii
		{
			get
			{
				if (base.TraceSource is PiiTraceSource piiTraceSource)
				{
					return piiTraceSource.ShouldLogPii;
				}
				return false;
			}
			set
			{
				if (base.TraceSource is PiiTraceSource piiTraceSource)
				{
					piiTraceSource.ShouldLogPii = value;
				}
			}
		}

		protected override void OnSetLevel(SourceLevels level)
		{
			if (base.TraceSource != null)
			{
				if (base.TraceSource.Switch.Level != 0 && level == SourceLevels.Off)
				{
					TraceSource traceSource = base.TraceSource;
					CreateTraceSource();
					traceSource.Close();
				}
				shouldUseActivity = (level & SourceLevels.ActivityTracing) != 0;
			}
		}

		[Obsolete("For SMDiagnostics.dll use only. Never 'new' this type up unless you are DiagnosticUtility.")]
		[SecurityCritical]
		internal LegacyDiagnosticTrace(TraceSourceKind sourceType, string traceSourceName, string eventSourceName)
			: base(traceSourceName)
		{
			traceSourceType = sourceType;
			base.EventSourceName = eventSourceName;
			try
			{
				CreateTraceSource();
				AddDomainEventHandlersForCleanup();
			}
			catch (ConfigurationErrorsException)
			{
				throw;
			}
			catch (Exception ex2)
			{
				if (Fx.IsFatal(ex2))
				{
					throw;
				}
				System.Runtime.Diagnostics.EventLogger eventLogger = new System.Runtime.Diagnostics.EventLogger(base.EventSourceName, null);
				eventLogger.LogEvent(TraceEventType.Error, 4, 3221291108u, false, ex2.ToString());
			}
		}

		[SecuritySafeCritical]
		private void CreateTraceSource()
		{
			PiiTraceSource piiTraceSource = null;
			piiTraceSource = ((traceSourceType != TraceSourceKind.PiiTraceSource) ? new DiagnosticTraceSource(TraceSourceName, base.EventSourceName, SourceLevels.Off) : new PiiTraceSource(TraceSourceName, base.EventSourceName, SourceLevels.Off));
			SetTraceSource(piiTraceSource);
		}

		internal void TraceEvent(TraceEventType type, int code, string msdnTraceCode, string description, TraceRecord trace, Exception exception, object source)
		{
			TraceXPathNavigator navigator = null;
			try
			{
				if (base.TraceSource != null && base.HaveListeners)
				{
					try
					{
						BuildTrace(type, msdnTraceCode, description, trace, exception, source, out navigator);
					}
					catch (PlainXmlWriter.MaxSizeExceededException)
					{
						StringTraceRecord trace2 = new StringTraceRecord("TruncatedTraceId", msdnTraceCode);
						TraceEvent(type, 131084, GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "TraceTruncatedQuotaExceeded"), TraceSR.GetString("TraceCodeTraceTruncatedQuotaExceeded"), trace2, null, null);
					}
					base.TraceSource.TraceData(type, code, navigator);
					if (base.CalledShutdown)
					{
						base.TraceSource.Flush();
					}
					base.LastFailure = DateTime.MinValue;
				}
			}
			catch (Exception exception2)
			{
				if (Fx.IsFatal(exception2))
				{
					throw;
				}
				LogTraceFailure((navigator == null) ? string.Empty : navigator.ToString(), exception2);
			}
		}

		internal void TraceEvent(TraceEventType type, int code, string msdnTraceCode, string description, TraceRecord trace, Exception exception, Guid activityId, object source)
		{
			using ((ShouldUseActivity && Guid.Empty != activityId) ? Activity.CreateActivity(activityId) : null)
			{
				TraceEvent(type, code, msdnTraceCode, description, trace, exception, source);
			}
		}

		internal static string GenerateMsdnTraceCode(string traceSource, string traceCodeString)
		{
			return string.Format(CultureInfo.InvariantCulture, "https://docs.microsoft.com/dotnet/framework/wcf/diagnostics/tracing/{0}-{1}", new object[2]
			{
				traceSource.Replace('.', '-'),
				traceCodeString
			});
		}

		internal void TraceTransfer(Guid newId)
		{
			if (!ShouldUseActivity)
			{
				return;
			}
			Guid activityId = DiagnosticTraceBase.ActivityId;
			if (!(newId != activityId) || !base.HaveListeners)
			{
				return;
			}
			try
			{
				base.TraceSource.TraceTransfer(0, null, newId);
			}
			catch (Exception exception)
			{
				if (Fx.IsFatal(exception))
				{
					throw;
				}
				LogTraceFailure(null, exception);
			}
		}

		protected override void OnShutdownTracing()
		{
			if (base.TraceSource != null && base.Level != 0)
			{
				if (ShouldTrace(TraceEventType.Information))
				{
					Dictionary<string, string> dictionary = new Dictionary<string, string>(3);
					dictionary["AppDomain.FriendlyName"] = AppDomain.CurrentDomain.FriendlyName;
					dictionary["ProcessName"] = DiagnosticTraceBase.ProcessName;
					dictionary["ProcessId"] = DiagnosticTraceBase.ProcessId.ToString(CultureInfo.CurrentCulture);
					TraceEvent(TraceEventType.Information, 131073, GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "AppDomainUnload"), TraceSR.GetString("TraceCodeAppDomainUnload"), new DictionaryTraceRecord(dictionary), null, null);
				}
				base.TraceSource.Flush();
			}
		}

		protected override void OnUnhandledException(Exception exception)
		{
			TraceEvent(TraceEventType.Critical, 131077, "UnhandledException", TraceSR.GetString("UnhandledException"), null, exception, null);
		}

		private void BuildTrace(TraceEventType type, string msdnTraceCode, string description, TraceRecord trace, Exception exception, object source, out TraceXPathNavigator navigator)
		{
			PlainXmlWriter plainXmlWriter = new PlainXmlWriter(65535);
			navigator = plainXmlWriter.Navigator;
			BuildTrace(plainXmlWriter, type, msdnTraceCode, description, trace, exception, source);
			if (!ShouldLogPii)
			{
				navigator.RemovePii(DiagnosticStrings.HeadersPaths);
			}
		}

		private void BuildTrace(PlainXmlWriter xml, TraceEventType type, string msdnTraceCode, string description, TraceRecord trace, Exception exception, object source)
		{
			xml.WriteStartElement("TraceRecord");
			xml.WriteAttributeString("xmlns", "http://schemas.microsoft.com/2004/10/E2ETraceEvent/TraceRecord");
			xml.WriteAttributeString("Severity", DiagnosticTraceBase.LookupSeverity(type));
			xml.WriteElementString("TraceIdentifier", msdnTraceCode);
			xml.WriteElementString("Description", description);
			xml.WriteElementString("AppDomain", DiagnosticTraceBase.AppDomainFriendlyName);
			if (source != null)
			{
				xml.WriteElementString("Source", DiagnosticTraceBase.CreateSourceString(source));
			}
			if (trace != null)
			{
				xml.WriteStartElement("ExtendedData");
				xml.WriteAttributeString("xmlns", trace.EventId);
				trace.WriteTo(xml);
				xml.WriteEndElement();
			}
			if (exception != null)
			{
				xml.WriteStartElement("Exception");
				DiagnosticTraceBase.AddExceptionToTraceString(xml, exception);
				xml.WriteEndElement();
			}
			xml.WriteEndElement();
		}

		public override bool IsEnabled()
		{
			return true;
		}

		public override void TraceEventLogEvent(TraceEventType type, TraceRecord traceRecord)
		{
			TraceEvent(type, 131074, GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "EventLog"), TraceSR.GetString("TraceCodeEventLog"), traceRecord, null, null);
		}
	}
	internal static class NativeMethods
	{
		private const string ADVAPI32 = "advapi32.dll";

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[SecurityCritical]
		internal static extern SafeEventLogWriteHandle RegisterEventSource(string uncServerName, string sourceName);
	}
	internal class PiiTraceSource : TraceSource
	{
		private string eventSourceName = string.Empty;

		internal const string LogPii = "logKnownPii";

		private bool shouldLogPii;

		private bool initialized;

		private object localSyncObject = new object();

		internal bool ShouldLogPii
		{
			get
			{
				if (!initialized)
				{
					Initialize();
				}
				return shouldLogPii;
			}
			set
			{
				initialized = true;
				shouldLogPii = value;
			}
		}

		internal PiiTraceSource(string name, string eventSourceName)
			: base(name)
		{
			this.eventSourceName = eventSourceName;
		}

		internal PiiTraceSource(string name, string eventSourceName, SourceLevels levels)
			: base(name, levels)
		{
			this.eventSourceName = eventSourceName;
		}

		private void Initialize()
		{
			if (initialized)
			{
				return;
			}
			lock (localSyncObject)
			{
				if (initialized)
				{
					return;
				}
				string value = base.Attributes["logKnownPii"];
				bool result = false;
				if (!string.IsNullOrEmpty(value) && !bool.TryParse(value, out result))
				{
					result = false;
				}
				if (result)
				{
					System.Runtime.Diagnostics.EventLogger eventLogger = new System.Runtime.Diagnostics.EventLogger(eventSourceName, null);
					if (MachineSettingsSection.EnableLoggingKnownPii)
					{
						eventLogger.LogEvent(TraceEventType.Information, 7, 3221291115u, false);
						shouldLogPii = true;
					}
					else
					{
						eventLogger.LogEvent(TraceEventType.Error, 7, 3221291116u, false);
					}
				}
				initialized = true;
			}
		}

		protected override string[] GetSupportedAttributes()
		{
			return new string[1] { "logKnownPii" };
		}
	}
	internal class PlainXmlWriter : XmlWriter
	{
		internal class MaxSizeExceededException : Exception
		{
		}

		private TraceXPathNavigator navigator;

		private bool writingAttribute;

		private string currentAttributeName;

		private string currentAttributePrefix;

		private string currentAttributeNs;

		private string currentAttributeText = string.Empty;

		public TraceXPathNavigator Navigator => navigator;

		public override WriteState WriteState => navigator.WriteState;

		public override XmlSpace XmlSpace => XmlSpace.Default;

		public override string XmlLang => string.Empty;

		public PlainXmlWriter()
			: this(-1)
		{
		}

		public PlainXmlWriter(int maxSize)
		{
			navigator = new TraceXPathNavigator(maxSize);
		}

		public override void WriteStartDocument()
		{
		}

		public override void WriteStartDocument(bool standalone)
		{
		}

		public override void WriteDocType(string name, string pubid, string sysid, string subset)
		{
		}

		public override void WriteEndDocument()
		{
		}

		public override string LookupPrefix(string ns)
		{
			return navigator.LookupPrefix(ns);
		}

		public override void WriteValue(object value)
		{
			navigator.AddText(value.ToString());
		}

		public override void WriteValue(string value)
		{
			navigator.AddText(value);
		}

		public override void WriteBase64(byte[] buffer, int offset, int count)
		{
		}

		public override void WriteStartElement(string prefix, string localName, string ns)
		{
			if (string.IsNullOrEmpty(localName))
			{
				throw new ArgumentNullException("localName");
			}
			navigator.AddElement(prefix, localName, ns);
		}

		public override void WriteFullEndElement()
		{
			WriteEndElement();
		}

		public override void WriteEndElement()
		{
			navigator.CloseElement();
		}

		public override void WriteStartAttribute(string prefix, string localName, string ns)
		{
			if (writingAttribute)
			{
				throw new InvalidOperationException();
			}
			currentAttributeName = localName;
			currentAttributePrefix = prefix;
			currentAttributeNs = ns;
			currentAttributeText = string.Empty;
			writingAttribute = true;
		}

		public override void WriteEndAttribute()
		{
			if (!writingAttribute)
			{
				throw new InvalidOperationException();
			}
			navigator.AddAttribute(currentAttributeName, currentAttributeText, currentAttributeNs, currentAttributePrefix);
			writingAttribute = false;
		}

		public override void WriteCData(string text)
		{
			WriteRaw("<![CDATA[" + text + "]]>");
		}

		public override void WriteComment(string text)
		{
			navigator.AddComment(text);
		}

		public override void WriteProcessingInstruction(string name, string text)
		{
			navigator.AddProcessingInstruction(name, text);
		}

		public override void WriteEntityRef(string name)
		{
		}

		public override void WriteCharEntity(char ch)
		{
		}

		public override void WriteSurrogateCharEntity(char lowChar, char highChar)
		{
		}

		public override void WriteWhitespace(string ws)
		{
		}

		public override void WriteString(string text)
		{
			if (writingAttribute)
			{
				currentAttributeText += text;
			}
			else
			{
				WriteValue(text);
			}
		}

		public override void WriteChars(char[] buffer, int index, int count)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer");
			}
			if (index < 0)
			{
				throw new ArgumentOutOfRangeException("index");
			}
			if (count < 0)
			{
				throw new ArgumentOutOfRangeException("count");
			}
			if (buffer.Length - index < count)
			{
				throw new ArgumentException(TraceSR.GetString("WriteCharsInvalidContent"));
			}
			WriteString(new string(buffer, index, count));
		}

		public override void WriteRaw(string data)
		{
			WriteString(data);
		}

		public override void WriteRaw(char[] buffer, int index, int count)
		{
			WriteChars(buffer, index, count);
		}

		public override void Close()
		{
		}

		public override void Flush()
		{
		}
	}
	[SecurityCritical]
	internal sealed class SafeEventLogWriteHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		[SecurityCritical]
		private SafeEventLogWriteHandle()
			: base(ownsHandle: true)
		{
		}

		[SecurityCritical]
		internal static SafeEventLogWriteHandle RegisterEventSource(string uncServerName, string sourceName)
		{
			SafeEventLogWriteHandle safeEventLogWriteHandle = NativeMethods.RegisterEventSource(uncServerName, sourceName);
			int lastWin32Error = Marshal.GetLastWin32Error();
			_ = safeEventLogWriteHandle.IsInvalid;
			return safeEventLogWriteHandle;
		}

		[DllImport("advapi32", SetLastError = true)]
		private static extern bool DeregisterEventSource(IntPtr hEventLog);

		[SecurityCritical]
		protected override bool ReleaseHandle()
		{
			return DeregisterEventSource(handle);
		}
	}
	internal static class DiagnosticsTraceCode
	{
		public const int Diagnostics = 131072;

		public const int AppDomainUnload = 131073;

		public const int EventLog = 131074;

		public const int ThrowingException = 131075;

		public const int TraceHandledException = 131076;

		public const int UnhandledException = 131077;

		public const int TraceTruncatedQuotaExceeded = 131084;
	}
	internal enum TraceSourceKind
	{
		DiagnosticTraceSource,
		PiiTraceSource
	}
	[DebuggerDisplay("")]
	internal class TraceXPathNavigator : XPathNavigator
	{
		private interface IMeasurable
		{
			int Size { get; }
		}

		private class TraceNode
		{
			private XPathNodeType nodeType;

			internal ElementNode parent;

			internal XPathNodeType NodeType => nodeType;

			protected TraceNode(XPathNodeType nodeType, ElementNode parent)
			{
				this.nodeType = nodeType;
				this.parent = parent;
			}
		}

		private class CommentNode : TraceNode, IMeasurable
		{
			internal string nodeValue;

			public int Size => nodeValue.Length + 8;

			internal CommentNode(string text, ElementNode parent)
				: base(XPathNodeType.Comment, parent)
			{
				nodeValue = text;
			}
		}

		private class ElementNode : TraceNode, IMeasurable
		{
			private int attributeIndex;

			private int elementIndex;

			internal string name;

			internal string prefix;

			internal string xmlns;

			internal List<TraceNode> childNodes = new List<TraceNode>();

			internal List<AttributeNode> attributes = new List<AttributeNode>();

			internal TextNode text;

			internal bool movedToText;

			internal AttributeNode CurrentAttribute => attributes[attributeIndex];

			public int Size
			{
				get
				{
					int num = 2 * name.Length + 6;
					if (!string.IsNullOrEmpty(prefix))
					{
						num += prefix.Length + 1;
					}
					if (!string.IsNullOrEmpty(xmlns))
					{
						num += xmlns.Length + 9;
					}
					return num;
				}
			}

			internal ElementNode(string name, string prefix, ElementNode parent, string xmlns)
				: base(XPathNodeType.Element, parent)
			{
				this.name = name;
				this.prefix = prefix;
				this.xmlns = xmlns;
			}

			internal void Add(TraceNode node)
			{
				childNodes.Add(node);
			}

			internal IEnumerable<ElementNode> FindSubnodes(string[] headersPath)
			{
				if (headersPath == null)
				{
					throw new ArgumentNullException("headersPath");
				}
				ElementNode elementNode = this;
				if (string.CompareOrdinal(elementNode.name, headersPath[0]) != 0)
				{
					elementNode = null;
				}
				int i = 0;
				while (elementNode != null)
				{
					int num = i + 1;
					i = num;
					if (num >= headersPath.Length)
					{
						break;
					}
					ElementNode subNode = null;
					if (elementNode.childNodes != null)
					{
						foreach (TraceNode childNode in elementNode.childNodes)
						{
							if (childNode.NodeType == XPathNodeType.Element && childNode is ElementNode elementNode2 && string.CompareOrdinal(elementNode2.name, headersPath[i]) == 0)
							{
								if (headersPath.Length != i + 1)
								{
									subNode = elementNode2;
									break;
								}
								yield return elementNode2;
							}
						}
					}
					elementNode = subNode;
				}
			}

			internal TraceNode MoveToNext()
			{
				TraceNode result = null;
				if (elementIndex + 1 < childNodes.Count)
				{
					elementIndex++;
					result = childNodes[elementIndex];
				}
				return result;
			}

			internal bool MoveToFirstAttribute()
			{
				attributeIndex = 0;
				if (attributes != null)
				{
					return attributes.Count > 0;
				}
				return false;
			}

			internal bool MoveToNextAttribute()
			{
				bool result = false;
				if (attributeIndex + 1 < attributes.Count)
				{
					attributeIndex++;
					result = true;
				}
				return result;
			}

			internal void Reset()
			{
				attributeIndex = 0;
				elementIndex = 0;
				movedToText = false;
				if (childNodes == null)
				{
					return;
				}
				foreach (TraceNode childNode in childNodes)
				{
					if (childNode.NodeType == XPathNodeType.Element && childNode is ElementNode elementNode)
					{
						elementNode.Reset();
					}
				}
			}
		}

		private class AttributeNode : IMeasurable
		{
			internal string name;

			internal string nodeValue;

			internal string prefix;

			internal string xmlns;

			public int Size
			{
				get
				{
					int num = name.Length + nodeValue.Length + 5;
					if (!string.IsNullOrEmpty(prefix))
					{
						num += prefix.Length + 1;
					}
					if (!string.IsNullOrEmpty(xmlns))
					{
						num += xmlns.Length + 9;
					}
					return num;
				}
			}

			internal AttributeNode(string name, string prefix, string value, string xmlns)
			{
				this.name = name;
				this.prefix = prefix;
				nodeValue = value;
				this.xmlns = xmlns;
			}
		}

		private class ProcessingInstructionNode : TraceNode, IMeasurable
		{
			internal string name;

			internal string text;

			public int Size => name.Length + text.Length + 12;

			internal ProcessingInstructionNode(string name, string text, ElementNode parent)
				: base(XPathNodeType.ProcessingInstruction, parent)
			{
				this.name = name;
				this.text = text;
			}
		}

		private class TextNode : IMeasurable
		{
			internal string nodeValue;

			public int Size => nodeValue.Length;

			internal TextNode(string value)
			{
				nodeValue = value;
			}
		}

		private const int UnlimitedSize = -1;

		private ElementNode root;

		private TraceNode current;

		private bool closed;

		private XPathNodeType state = XPathNodeType.Element;

		private int maxSize;

		private long currentSize;

		public override string BaseURI => string.Empty;

		public override bool IsEmptyElement
		{
			get
			{
				bool result = true;
				if (current != null)
				{
					result = CurrentElement.text != null || CurrentElement.childNodes.Count > 0;
				}
				return result;
			}
		}

		[DebuggerDisplay("")]
		public override string LocalName => Name;

		[DebuggerDisplay("")]
		public override string Name
		{
			get
			{
				string result = string.Empty;
				if (current != null)
				{
					switch (state)
					{
					case XPathNodeType.Attribute:
						result = CurrentElement.CurrentAttribute.name;
						break;
					case XPathNodeType.Element:
						result = CurrentElement.name;
						break;
					case XPathNodeType.ProcessingInstruction:
						result = CurrentProcessingInstruction.name;
						break;
					}
				}
				return result;
			}
		}

		public override XmlNameTable NameTable => null;

		[DebuggerDisplay("")]
		public override string NamespaceURI
		{
			get
			{
				string result = string.Empty;
				if (current != null)
				{
					switch (state)
					{
					case XPathNodeType.Element:
						result = CurrentElement.xmlns;
						break;
					case XPathNodeType.Attribute:
						result = CurrentElement.CurrentAttribute.xmlns;
						break;
					case XPathNodeType.Namespace:
						result = null;
						break;
					}
				}
				return result;
			}
		}

		[DebuggerDisplay("")]
		public override XPathNodeType NodeType => state;

		[DebuggerDisplay("")]
		public override string Prefix
		{
			get
			{
				string result = string.Empty;
				if (current != null)
				{
					switch (state)
					{
					case XPathNodeType.Element:
						result = CurrentElement.prefix;
						break;
					case XPathNodeType.Attribute:
						result = CurrentElement.CurrentAttribute.prefix;
						break;
					case XPathNodeType.Namespace:
						result = null;
						break;
					}
				}
				return result;
			}
		}

		private CommentNode CurrentComment => current as CommentNode;

		private ElementNode CurrentElement => current as ElementNode;

		private ProcessingInstructionNode CurrentProcessingInstruction => current as ProcessingInstructionNode;

		[DebuggerDisplay("")]
		public override string Value
		{
			get
			{
				string result = string.Empty;
				if (current != null)
				{
					switch (state)
					{
					case XPathNodeType.Text:
						result = CurrentElement.text.nodeValue;
						break;
					case XPathNodeType.Attribute:
						result = CurrentElement.CurrentAttribute.nodeValue;
						break;
					case XPathNodeType.Comment:
						result = CurrentComment.nodeValue;
						break;
					case XPathNodeType.ProcessingInstruction:
						result = CurrentProcessingInstruction.text;
						break;
					}
				}
				return result;
			}
		}

		internal WriteState WriteState
		{
			get
			{
				WriteState result = WriteState.Error;
				if (current == null)
				{
					result = WriteState.Start;
				}
				else if (closed)
				{
					result = WriteState.Closed;
				}
				else
				{
					switch (state)
					{
					case XPathNodeType.Attribute:
						result = WriteState.Attribute;
						break;
					case XPathNodeType.Element:
						result = WriteState.Element;
						break;
					case XPathNodeType.Text:
						result = WriteState.Content;
						break;
					case XPathNodeType.Comment:
						result = WriteState.Content;
						break;
					}
				}
				return result;
			}
		}

		public TraceXPathNavigator(int maxSize)
		{
			this.maxSize = maxSize;
			currentSize = 0L;
		}

		internal void AddElement(string prefix, string name, string xmlns)
		{
			if (closed)
			{
				throw new InvalidOperationException();
			}
			ElementNode node = new ElementNode(name, prefix, CurrentElement, xmlns);
			if (current == null)
			{
				VerifySize(node);
				root = node;
				current = root;
			}
			else if (!closed)
			{
				VerifySize(node);
				CurrentElement.Add(node);
				current = node;
			}
		}

		internal void AddProcessingInstruction(string name, string text)
		{
			if (current != null)
			{
				ProcessingInstructionNode node = new ProcessingInstructionNode(name, text, CurrentElement);
				VerifySize(node);
				CurrentElement.Add(node);
			}
		}

		internal void AddText(string value)
		{
			if (closed)
			{
				throw new InvalidOperationException();
			}
			if (current != null)
			{
				if (CurrentElement.text == null)
				{
					TextNode textNode = new TextNode(value);
					VerifySize(textNode);
					CurrentElement.text = textNode;
				}
				else if (!string.IsNullOrEmpty(value))
				{
					VerifySize(value);
					CurrentElement.text.nodeValue += value;
				}
			}
		}

		internal void AddAttribute(string name, string value, string xmlns, string prefix)
		{
			if (closed)
			{
				throw new InvalidOperationException();
			}
			if (current == null)
			{
				throw new InvalidOperationException();
			}
			AttributeNode attributeNode = new AttributeNode(name, prefix, value, xmlns);
			VerifySize(attributeNode);
			CurrentElement.attributes.Add(attributeNode);
		}

		internal void AddComment(string text)
		{
			if (closed)
			{
				throw new InvalidOperationException();
			}
			if (current == null)
			{
				throw new InvalidOperationException();
			}
			CommentNode node = new CommentNode(text, CurrentElement);
			VerifySize(node);
			CurrentElement.Add(node);
		}

		internal void CloseElement()
		{
			if (closed)
			{
				throw new InvalidOperationException();
			}
			current = CurrentElement.parent;
			if (current == null)
			{
				closed = true;
			}
		}

		public override XPathNavigator Clone()
		{
			return this;
		}

		public override bool IsSamePosition(XPathNavigator other)
		{
			return false;
		}

		public override string LookupPrefix(string ns)
		{
			return LookupPrefix(ns, CurrentElement);
		}

		private string LookupPrefix(string ns, ElementNode node)
		{
			string text = null;
			if (string.Compare(ns, node.xmlns, StringComparison.Ordinal) == 0)
			{
				text = node.prefix;
			}
			else
			{
				foreach (AttributeNode attribute in node.attributes)
				{
					if (string.Compare("xmlns", attribute.prefix, StringComparison.Ordinal) == 0 && string.Compare(ns, attribute.nodeValue, StringComparison.Ordinal) == 0)
					{
						text = attribute.name;
						break;
					}
				}
			}
			if (text == null && node.parent != null)
			{
				text = LookupPrefix(ns, node.parent);
			}
			return text;
		}

		public override bool MoveTo(XPathNavigator other)
		{
			return false;
		}

		public override bool MoveToFirstAttribute()
		{
			if (current == null)
			{
				throw new InvalidOperationException();
			}
			bool flag = CurrentElement.MoveToFirstAttribute();
			if (flag)
			{
				state = XPathNodeType.Attribute;
			}
			return flag;
		}

		public override bool MoveToFirstChild()
		{
			if (current == null)
			{
				throw new InvalidOperationException();
			}
			bool result = false;
			if (CurrentElement.childNodes != null && CurrentElement.childNodes.Count > 0)
			{
				current = CurrentElement.childNodes[0];
				state = current.NodeType;
				result = true;
			}
			else if ((CurrentElement.childNodes == null || CurrentElement.childNodes.Count == 0) && CurrentElement.text != null)
			{
				state = XPathNodeType.Text;
				CurrentElement.movedToText = true;
				result = true;
			}
			return result;
		}

		public override bool MoveToFirstNamespace(XPathNamespaceScope namespaceScope)
		{
			return false;
		}

		public override bool MoveToId(string id)
		{
			return false;
		}

		public override bool MoveToNext()
		{
			if (current == null)
			{
				throw new InvalidOperationException();
			}
			bool result = false;
			if (state != XPathNodeType.Text)
			{
				ElementNode parent = current.parent;
				if (parent != null)
				{
					TraceNode traceNode = parent.MoveToNext();
					if (traceNode == null && parent.text != null && !parent.movedToText)
					{
						state = XPathNodeType.Text;
						parent.movedToText = true;
						current = parent;
						result = true;
					}
					else if (traceNode != null)
					{
						state = traceNode.NodeType;
						result = true;
						current = traceNode;
					}
				}
			}
			return result;
		}

		public override bool MoveToNextAttribute()
		{
			if (current == null)
			{
				throw new InvalidOperationException();
			}
			bool flag = CurrentElement.MoveToNextAttribute();
			if (flag)
			{
				state = XPathNodeType.Attribute;
			}
			return flag;
		}

		public override bool MoveToNextNamespace(XPathNamespaceScope namespaceScope)
		{
			return false;
		}

		public override bool MoveToParent()
		{
			if (current == null)
			{
				throw new InvalidOperationException();
			}
			bool result = false;
			switch (state)
			{
			case XPathNodeType.Element:
			case XPathNodeType.ProcessingInstruction:
			case XPathNodeType.Comment:
				if (current.parent != null)
				{
					current = current.parent;
					state = current.NodeType;
					result = true;
				}
				break;
			case XPathNodeType.Attribute:
				state = XPathNodeType.Element;
				result = true;
				break;
			case XPathNodeType.Text:
				state = XPathNodeType.Element;
				result = true;
				break;
			case XPathNodeType.Namespace:
				state = XPathNodeType.Element;
				result = true;
				break;
			}
			return result;
		}

		public override bool MoveToPrevious()
		{
			return false;
		}

		public override void MoveToRoot()
		{
			current = root;
			state = XPathNodeType.Element;
			root.Reset();
		}

		public override string ToString()
		{
			MoveToRoot();
			StringBuilder stringBuilder = new StringBuilder();
			EncodingFallbackAwareXmlTextWriter encodingFallbackAwareXmlTextWriter = new EncodingFallbackAwareXmlTextWriter(new StringWriter(stringBuilder, CultureInfo.CurrentCulture));
			encodingFallbackAwareXmlTextWriter.WriteNode(this, defattr: false);
			return stringBuilder.ToString();
		}

		private void VerifySize(IMeasurable node)
		{
			VerifySize(node.Size);
		}

		private void VerifySize(string node)
		{
			VerifySize(node.Length);
		}

		private void VerifySize(int nodeSize)
		{
			if (maxSize != -1 && currentSize + nodeSize > maxSize)
			{
				throw new PlainXmlWriter.MaxSizeExceededException();
			}
			currentSize += nodeSize;
		}

		public void RemovePii(string[][] paths)
		{
			if (paths == null)
			{
				throw new ArgumentNullException("paths");
			}
			foreach (string[] path in paths)
			{
				RemovePii(path);
			}
		}

		public void RemovePii(string[] path)
		{
			RemovePii(path, DiagnosticStrings.PiiList);
		}

		public void RemovePii(string[] headersPath, string[] piiList)
		{
			if (root == null)
			{
				throw new InvalidOperationException();
			}
			foreach (ElementNode item in root.FindSubnodes(headersPath))
			{
				MaskSubnodes(item, piiList);
			}
		}

		private static void MaskElement(ElementNode element)
		{
			if (element != null)
			{
				element.childNodes.Clear();
				element.Add(new CommentNode("Removed", element));
				element.text = null;
				element.attributes = null;
			}
		}

		private static void MaskSubnodes(ElementNode element, string[] elementNames)
		{
			MaskSubnodes(element, elementNames, processNodeItself: false);
		}

		private static void MaskSubnodes(ElementNode element, string[] elementNames, bool processNodeItself)
		{
			if (elementNames == null)
			{
				throw new ArgumentNullException("elementNames");
			}
			if (element == null)
			{
				return;
			}
			bool flag = true;
			if (processNodeItself)
			{
				foreach (string strA in elementNames)
				{
					if (string.CompareOrdinal(strA, element.name) == 0)
					{
						MaskElement(element);
						flag = false;
						break;
					}
				}
			}
			if (!flag || element.childNodes == null)
			{
				return;
			}
			foreach (ElementNode childNode in element.childNodes)
			{
				MaskSubnodes(childNode, elementNames, processNodeItself: true);
			}
		}
	}
	internal class EncodingFallbackAwareXmlTextWriter : XmlTextWriter
	{
		private Encoding encoding;

		internal EncodingFallbackAwareXmlTextWriter(TextWriter writer)
			: base(writer)
		{
			encoding = writer.Encoding;
		}

		public override void WriteString(string value)
		{
			if (!string.IsNullOrEmpty(value) && ContainsInvalidXmlChar(value))
			{
				byte[] bytes = encoding.GetBytes(value);
				value = encoding.GetString(bytes);
			}
			base.WriteString(value);
		}

		private bool ContainsInvalidXmlChar(string value)
		{
			if (string.IsNullOrEmpty(value))
			{
				return false;
			}
			int num = 0;
			int length = value.Length;
			while (num < length)
			{
				if (XmlConvert.IsXmlChar(value[num]))
				{
					num++;
					continue;
				}
				if (num + 1 < length && XmlConvert.IsXmlSurrogatePair(value[num + 1], value[num]))
				{
					num += 2;
					continue;
				}
				return true;
			}
			return false;
		}
	}
	internal class Utility
	{
		private ExceptionUtility exceptionUtility;

		[Obsolete("For SMDiagnostics.dll use only. Call DiagnosticUtility.Utility instead")]
		internal Utility(ExceptionUtility exceptionUtility)
		{
			this.exceptionUtility = exceptionUtility;
		}

		internal static void CloseInvalidOutSafeHandle(SafeHandle handle)
		{
			handle?.SetHandleAsInvalid();
		}

		internal static void CloseInvalidOutCriticalHandle(CriticalHandle handle)
		{
			handle?.SetHandleAsInvalid();
		}

		internal Guid CreateGuid(string guidString)
		{
			return Fx.CreateGuid(guidString);
		}

		internal bool TryCreateGuid(string guidString, out Guid result)
		{
			return Fx.TryCreateGuid(guidString, out result);
		}

		internal byte[] AllocateByteArray(int size)
		{
			return Fx.AllocateByteArray(size);
		}

		internal char[] AllocateCharArray(int size)
		{
			return Fx.AllocateCharArray(size);
		}
	}
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class TraceSRDescriptionAttribute : DescriptionAttribute
	{
		private bool replaced;

		public override string Description
		{
			get
			{
				if (!replaced)
				{
					replaced = true;
					base.DescriptionValue = TraceSR.GetString(base.Description);
				}
				return base.Description;
			}
		}

		public TraceSRDescriptionAttribute(string description)
			: base(description)
		{
		}
	}
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class TraceSRCategoryAttribute : CategoryAttribute
	{
		public TraceSRCategoryAttribute(string category)
			: base(category)
		{
		}

		protected override string GetLocalizedString(string value)
		{
			return TraceSR.GetString(value);
		}
	}
	internal sealed class TraceSR
	{
		internal const string ActivityBoundary = "ActivityBoundary";

		internal const string ThrowingException = "ThrowingException";

		internal const string TraceHandledException = "TraceHandledException";

		internal const string TraceCodeAppDomainUnload = "TraceCodeAppDomainUnload";

		internal const string TraceCodeEventLog = "TraceCodeEventLog";

		internal const string TraceCodeTraceTruncatedQuotaExceeded = "TraceCodeTraceTruncatedQuotaExceeded";

		internal const string UnhandledException = "UnhandledException";

		internal const string WriteCharsInvalidContent = "WriteCharsInvalidContent";

		internal const string GenericCallbackException = "GenericCallbackException";

		internal const string StringNullOrEmpty = "StringNullOrEmpty";

		private static TraceSR loader;

		private ResourceManager resources;

		private static CultureInfo Culture => null;

		public static ResourceManager Resources => GetLoader().resources;

		internal TraceSR()
		{
			resources = new ResourceManager("SMDiagnostics", GetType().Assembly);
		}

		private static TraceSR GetLoader()
		{
			if (loader == null)
			{
				TraceSR value = new TraceSR();
				Interlocked.CompareExchange(ref loader, value, null);
			}
			return loader;
		}

		public static string GetString(string name, params object[] args)
		{
			TraceSR traceSR = GetLoader();
			if (traceSR == null)
			{
				return null;
			}
			string @string = traceSR.resources.GetString(name, Culture);
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
