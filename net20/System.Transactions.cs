
// C:\WINDOWS\assembly\GAC_32\System.Transactions\2.0.0.0__b77a5c561934e089\System.Transactions.dll
// System.Transactions, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
// Global type: <Module>
// Architecture: x86
// This assembly contains unmanaged code.
// Runtime: v2.0.50727
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
using System.EnterpriseServices;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Transactions.Configuration;
using System.Transactions.Diagnostics;
using System.Transactions.Oletx;
using System.Xml;
using System.Xml.XPath;

[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\EcmaPublicKey.snk")]
[assembly: BestFitMapping(false)]
[assembly: ComVisible(false)]
[assembly: CLSCompliant(true)]
[assembly: AllowPartiallyTrustedCallers]
[assembly: AssemblyTitle("System.Transactions.dll")]
[assembly: AssemblyDescription("System.Transactions.dll")]
[assembly: AssemblyDefaultAlias("System.Transactions.dll")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyDelaySign(true)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum)]
[assembly: AssemblyVersion("2.0.0.0")]
namespace System.Transactions
{
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class SRDescriptionAttribute : System.ComponentModel.DescriptionAttribute
	{
		private bool replaced;

		public override string Description
		{
			get
			{
				if (!replaced)
				{
					replaced = true;
					base.DescriptionValue = SR.GetString(base.Description);
				}
				return base.Description;
			}
		}

		public SRDescriptionAttribute(string description)
			: base(description)
		{
		}
	}
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class SRCategoryAttribute : CategoryAttribute
	{
		public SRCategoryAttribute(string category)
			: base(category)
		{
		}

		protected override string GetLocalizedString(string value)
		{
			return SR.GetString(value);
		}
	}
	internal sealed class SR
	{
		internal const string ArgumentWrongType = "ArgumentWrongType";

		internal const string BadAsyncResult = "BadAsyncResult";

		internal const string BadResourceManagerId = "BadResourceManagerId";

		internal const string CannotGetPrepareInfo = "CannotGetPrepareInfo";

		internal const string CannotGetTransactionIdentifier = "CannotGetTransactionIdentifier";

		internal const string CannotPromoteSnapshot = "CannotPromoteSnapshot";

		internal const string CannotSetCurrent = "CannotSetCurrent";

		internal const string CannotSupportNodeNameSpecification = "CannotSupportNodeNameSpecification";

		internal const string ConfigInvalidConfigurationValue = "ConfigInvalidConfigurationValue";

		internal const string ConfigNull = "ConfigNull";

		internal const string ConfigDistributedTransactionManagerName = "ConfigDistributedTransactionManagerName";

		internal const string ConfigInvalidTimeSpanValue = "ConfigInvalidTimeSpanValue";

		internal const string ConfigurationSectionNotFound = "ConfigurationSectionNotFound";

		internal const string CurrentDelegateSet = "CurrentDelegateSet";

		internal const string DistributedTransactionManager = "DistributedTransactionManager";

		internal const string DisposeScope = "DisposeScope";

		internal const string DtcTransactionManagerUnavailable = "DtcTransactionManagerUnavailable";

		internal const string DuplicateRecoveryComplete = "DuplicateRecoveryComplete";

		internal const string EnlistmentStateException = "EnlistmentStateException";

		internal const string EsNotSupported = "EsNotSupported";

		internal const string FailedToCreateTraceSource = "FailedToCreateTraceSource";

		internal const string FailedToInitializeTraceSource = "FailedToInitializeTraceSource";

		internal const string FailedToTraceEvent = "FailedToTraceEvent";

		internal const string InternalError = "InternalError";

		internal const string InvalidArgument = "InvalidArgument";

		internal const string InvalidRecoveryInformation = "InvalidRecoveryInformation";

		internal const string InvalidScopeThread = "InvalidScopeThread";

		internal const string NetworkTransactionsDisabled = "NetworkTransactionsDisabled";

		internal const string OletxEnlistmentUnexpectedTransactionStatus = "OletxEnlistmentUnexpectedTransactionStatus";

		internal const string OletxTooManyEnlistments = "OletxTooManyEnlistments";

		internal const string OnlySupportedOnWinNT = "OnlySupportedOnWinNT";

		internal const string PrepareInfo = "PrepareInfo";

		internal const string PromotionFailed = "PromotionFailed";

		internal const string PromotedReturnedInvalidValue = "PromotedReturnedInvalidValue";

		internal const string PromotedTransactionExists = "PromotedTransactionExists";

		internal const string ProxyCannotSupportMultipleNodeNames = "ProxyCannotSupportMultipleNodeNames";

		internal const string ReenlistAfterRecoveryComplete = "ReenlistAfterRecoveryComplete";

		internal const string ResourceManagerIdDoesNotMatchRecoveryInformation = "ResourceManagerIdDoesNotMatchRecoveryInformation";

		internal const string TooLate = "TooLate";

		internal const string TraceActivityIdSet = "TraceActivityIdSet";

		internal const string TraceCloneCreated = "TraceCloneCreated";

		internal const string TraceConfiguredDefaultTimeoutAdjusted = "TraceConfiguredDefaultTimeoutAdjusted";

		internal const string TraceDependentCloneComplete = "TraceDependentCloneComplete";

		internal const string TraceDependentCloneCreated = "TraceDependentCloneCreated";

		internal const string TraceEnlistment = "TraceEnlistment";

		internal const string TraceEnlistmentCallbackNegative = "TraceEnlistmentCallbackNegative";

		internal const string TraceEnlistmentCallbackPositive = "TraceEnlistmentCallbackPositive";

		internal const string TraceEnlistmentNotificationCall = "TraceEnlistmentNotificationCall";

		internal const string TraceExceptionConsumed = "TraceExceptionConsumed";

		internal const string TraceInternalError = "TraceInternalError";

		internal const string TraceInvalidOperationException = "TraceInvalidOperationException";

		internal const string TraceMethodEntered = "TraceMethodEntered";

		internal const string TraceMethodExited = "TraceMethodExited";

		internal const string TraceNewActivityIdIssued = "TraceNewActivityIdIssued";

		internal const string TraceRecoveryComplete = "TraceRecoveryComplete";

		internal const string TraceReenlist = "TraceReenlist";

		internal const string TraceSourceBase = "TraceSourceBase";

		internal const string TraceSourceLtm = "TraceSourceLtm";

		internal const string TraceSourceOletx = "TraceSourceOletx";

		internal const string TraceTransactionAborted = "TraceTransactionAborted";

		internal const string TraceTransactionCommitCalled = "TraceTransactionCommitCalled";

		internal const string TraceTransactionCommitted = "TraceTransactionCommitted";

		internal const string TraceTransactionCreated = "TraceTransactionCreated";

		internal const string TraceTransactionDeserialized = "TraceTransactionDeserialized";

		internal const string TraceTransactionException = "TraceTransactionException";

		internal const string TraceTransactionInDoubt = "TraceTransactionInDoubt";

		internal const string TraceTransactionManagerCreated = "TraceTransactionManagerCreated";

		internal const string TraceTransactionPromoted = "TraceTransactionPromoted";

		internal const string TraceTransactionRollbackCalled = "TraceTransactionRollbackCalled";

		internal const string TraceTransactionScopeCreated = "TraceTransactionScopeCreated";

		internal const string TraceTransactionScopeCurrentTransactionChanged = "TraceTransactionScopeCurrentTransactionChanged";

		internal const string TraceTransactionScopeDisposed = "TraceTransactionScopeDisposed";

		internal const string TraceTransactionScopeIncomplete = "TraceTransactionScopeIncomplete";

		internal const string TraceTransactionScopeNestedIncorrectly = "TraceTransactionScopeNestedIncorrectly";

		internal const string TraceTransactionScopeTimeout = "TraceTransactionScopeTimeout";

		internal const string TraceTransactionSerialized = "TraceTransactionSerialized";

		internal const string TraceTransactionTimeout = "TraceTransactionTimeout";

		internal const string TraceUnhandledException = "TraceUnhandledException";

		internal const string TransactionAborted = "TransactionAborted";

		internal const string TransactionAlreadyCompleted = "TransactionAlreadyCompleted";

		internal const string TransactionAlreadyOver = "TransactionAlreadyOver";

		internal const string TransactionIndoubt = "TransactionIndoubt";

		internal const string TransactionManagerCommunicationException = "TransactionManagerCommunicationException";

		internal const string TransactionScopeComplete = "TransactionScopeComplete";

		internal const string TransactionScopeIncorrectCurrent = "TransactionScopeIncorrectCurrent";

		internal const string TransactionScopeInvalidNesting = "TransactionScopeInvalidNesting";

		internal const string TransactionScopeIsolationLevelDifferentFromTransaction = "TransactionScopeIsolationLevelDifferentFromTransaction";

		internal const string TransactionScopeTimerObjectInvalid = "TransactionScopeTimerObjectInvalid";

		internal const string TransactionStateException = "TransactionStateException";

		internal const string UnableToDeserializeTransaction = "UnableToDeserializeTransaction";

		internal const string UnableToDeserializeTransactionInternalError = "UnableToDeserializeTransactionInternalError";

		internal const string UnableToGetNotificationShimFactory = "UnableToGetNotificationShimFactory";

		internal const string UnexpectedTransactionManagerConfigurationValue = "UnexpectedTransactionManagerConfigurationValue";

		internal const string UnexpectedFailureOfThreadPool = "UnexpectedFailureOfThreadPool";

		internal const string UnexpectedTimerFailure = "UnexpectedTimerFailure";

		internal const string UnrecognizedRecoveryInformation = "UnrecognizedRecoveryInformation";

		internal const string VolEnlistNoRecoveryInfo = "VolEnlistNoRecoveryInfo";

		internal const string CannotAddToClosedDocument = "CannotAddToClosedDocument";

		internal const string DocumentAlreadyClosed = "DocumentAlreadyClosed";

		internal const string EventLogValue = "EventLogValue";

		internal const string EventLogEventIdValue = "EventLogEventIdValue";

		internal const string EventLogExceptionValue = "EventLogExceptionValue";

		internal const string EventLogSourceValue = "EventLogSourceValue";

		internal const string EventLogTraceValue = "EventLogTraceValue";

		internal const string NamedActivity = "NamedActivity";

		internal const string OperationInvalidOnAnEmptyDocument = "OperationInvalidOnAnEmptyDocument";

		internal const string TextNodeAlreadyPopulated = "TextNodeAlreadyPopulated";

		internal const string ThrowingException = "ThrowingException";

		internal const string TracingException = "TracingException";

		internal const string TraceCodeAppDomainUnloading = "TraceCodeAppDomainUnloading";

		internal const string TraceFailure = "TraceFailure";

		internal const string UnhandledException = "UnhandledException";

		private static SR loader;

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

		internal SR()
		{
			resources = new ResourceManager("Resources", GetType().Assembly);
		}

		private static SR GetLoader()
		{
			if (loader == null)
			{
				lock (InternalSyncObject)
				{
					if (loader == null)
					{
						loader = new SR();
					}
				}
			}
			return loader;
		}

		public static string GetString(string name, params object[] args)
		{
			SR sR = GetLoader();
			if (sR == null)
			{
				return null;
			}
			string @string = sR.resources.GetString(name, Culture);
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
	internal enum EnterpriseServicesState
	{
		Unknown = 0,
		Available = -1,
		Unavailable = 1
	}
	public class TransactionEventArgs : EventArgs
	{
		internal Transaction transaction;

		public Transaction Transaction => transaction;
	}
	public delegate void TransactionCompletedEventHandler(object sender, TransactionEventArgs e);
	public enum IsolationLevel
	{
		Serializable,
		RepeatableRead,
		ReadCommitted,
		ReadUncommitted,
		Snapshot,
		Chaos,
		Unspecified
	}
	public enum TransactionStatus
	{
		Active,
		Committed,
		Aborted,
		InDoubt
	}
	public enum DependentCloneOption
	{
		BlockCommitUntilComplete,
		RollbackIfNotComplete
	}
	[Flags]
	public enum EnlistmentOptions
	{
		None = 0,
		EnlistDuringPrepareRequired = 1
	}
	[Serializable]
	public class Transaction : IDisposable, ISerializable
	{
		internal const int disposedTrueValue = 1;

		private static EnterpriseServicesState _enterpriseServicesOk = EnterpriseServicesState.Unknown;

		private static Guid IID_IObjContext = new Guid("000001c6-0000-0000-C000-000000000046");

		internal IsolationLevel isoLevel;

		internal bool complete;

		internal int cloneId;

		internal int disposed;

		internal InternalTransaction internalTransaction;

		internal TransactionTraceIdentifier traceIdentifier;

		internal static bool EnterpriseServicesOk
		{
			get
			{
				if (_enterpriseServicesOk == EnterpriseServicesState.Unknown)
				{
					if (Type.GetType("System.EnterpriseServices.ContextUtil, System.EnterpriseServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", throwOnError: false) != null)
					{
						_enterpriseServicesOk = EnterpriseServicesState.Available;
					}
					else
					{
						_enterpriseServicesOk = EnterpriseServicesState.Unavailable;
					}
				}
				return _enterpriseServicesOk == EnterpriseServicesState.Available;
			}
		}

		public static Transaction Current
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "Transaction.get_Current");
				}
				Transaction current = null;
				TransactionScope currentScope = null;
				ContextData contextData = null;
				Transaction contextTransaction = null;
				GetCurrentTransactionAndScope(out current, out currentScope, out contextData, out contextTransaction);
				if (currentScope != null && currentScope.ScopeComplete)
				{
					throw new InvalidOperationException(SR.GetString("TransactionScopeComplete"));
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "Transaction.get_Current");
				}
				return current;
			}
			set
			{
				if (!TransactionManager._platformValidated)
				{
					TransactionManager.ValidatePlatform();
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "Transaction.set_Current");
				}
				if (InteropMode(ContextData.CurrentData.CurrentScope) != 0)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
					{
						System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceBase"), SR.GetString("CannotSetCurrent"));
					}
					throw new InvalidOperationException(SR.GetString("CannotSetCurrent"));
				}
				ContextData.CurrentData.CurrentTransaction = value;
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "Transaction.set_Current");
				}
			}
		}

		internal bool Disposed => disposed == 1;

		public TransactionInformation TransactionInformation
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.get_TransactionInformation");
				}
				if (Disposed)
				{
					throw new ObjectDisposedException("Transaction");
				}
				TransactionInformation transactionInformation = internalTransaction.transactionInformation;
				if (transactionInformation == null)
				{
					transactionInformation = new TransactionInformation(internalTransaction);
					internalTransaction.transactionInformation = transactionInformation;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.get_TransactionInformation");
				}
				return transactionInformation;
			}
		}

		public IsolationLevel IsolationLevel
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.get_IsolationLevel");
				}
				if (Disposed)
				{
					throw new ObjectDisposedException("Transaction");
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.get_IsolationLevel");
				}
				return isoLevel;
			}
		}

		internal TransactionTraceIdentifier TransactionTraceId
		{
			get
			{
				if (traceIdentifier == TransactionTraceIdentifier.Empty)
				{
					lock (internalTransaction)
					{
						if (traceIdentifier == TransactionTraceIdentifier.Empty)
						{
							TransactionTraceIdentifier transactionTraceIdentifier = new TransactionTraceIdentifier(internalTransaction.TransactionTraceId.TransactionIdentifier, cloneId);
							Thread.MemoryBarrier();
							traceIdentifier = transactionTraceIdentifier;
						}
					}
				}
				return traceIdentifier;
			}
		}

		public event TransactionCompletedEventHandler TransactionCompleted
		{
			add
			{
				if (Disposed)
				{
					throw new ObjectDisposedException("Transaction");
				}
				lock (internalTransaction)
				{
					internalTransaction.State.AddOutcomeRegistrant(internalTransaction, value);
				}
			}
			remove
			{
				lock (internalTransaction)
				{
					internalTransaction.transactionCompletedDelegate = (TransactionCompletedEventHandler)Delegate.Remove(internalTransaction.transactionCompletedDelegate, value);
				}
			}
		}

		internal static void VerifyEnterpriseServicesOk()
		{
			if (!EnterpriseServicesOk)
			{
				throw new NotSupportedException(SR.GetString("EsNotSupported"));
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		private static Transaction JitSafeGetContextTransaction(ContextData contextData)
		{
			SafeIUnknown safeUnknown = null;
			if (contextData.WeakDefaultComContext != null)
			{
				safeUnknown = (SafeIUnknown)contextData.WeakDefaultComContext.Target;
			}
			if (contextData.DefaultComContextState == DefaultComContextState.Unknown || (contextData.DefaultComContextState == DefaultComContextState.Available && safeUnknown == null))
			{
				try
				{
					NativeMethods.CoGetDefaultContext(-1, ref IID_IObjContext, out safeUnknown);
					contextData.WeakDefaultComContext = new WeakReference(safeUnknown);
					contextData.DefaultComContextState = DefaultComContextState.Available;
				}
				catch (EntryPointNotFoundException exception)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceBase"), exception);
					}
					contextData.DefaultComContextState = DefaultComContextState.Unavailable;
				}
			}
			if (contextData.DefaultComContextState == DefaultComContextState.Available)
			{
				IntPtr contextToken = IntPtr.Zero;
				NativeMethods.CoGetContextToken(out contextToken);
				if (safeUnknown.DangerousGetHandle() == contextToken)
				{
					return null;
				}
			}
			if (!ContextUtil.IsInTransaction)
			{
				return null;
			}
			return ContextUtil.SystemTransaction;
		}

		internal static Transaction GetContextTransaction(ContextData contextData)
		{
			if (EnterpriseServicesOk)
			{
				return JitSafeGetContextTransaction(contextData);
			}
			return null;
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		internal static bool UseServiceDomainForCurrent()
		{
			return !ContextUtil.IsDefaultContext();
		}

		internal static EnterpriseServicesInteropOption InteropMode(TransactionScope currentScope)
		{
			return currentScope?.InteropMode ?? EnterpriseServicesInteropOption.None;
		}

		internal static Transaction FastGetTransaction(TransactionScope currentScope, ContextData contextData, out Transaction contextTransaction)
		{
			Transaction transaction = null;
			contextTransaction = null;
			contextTransaction = contextData.CurrentTransaction;
			switch (InteropMode(currentScope))
			{
			case EnterpriseServicesInteropOption.None:
				transaction = contextTransaction;
				if (transaction == null && currentScope == null)
				{
					transaction = ((!TransactionManager.currentDelegateSet) ? GetContextTransaction(contextData) : TransactionManager.currentDelegate());
				}
				break;
			case EnterpriseServicesInteropOption.Full:
				transaction = GetContextTransaction(contextData);
				break;
			case EnterpriseServicesInteropOption.Automatic:
				transaction = ((!UseServiceDomainForCurrent()) ? contextData.CurrentTransaction : GetContextTransaction(contextData));
				break;
			}
			return transaction;
		}

		internal static void GetCurrentTransactionAndScope(out Transaction current, out TransactionScope currentScope, out ContextData contextData, out Transaction contextTransaction)
		{
			contextData = ContextData.CurrentData;
			currentScope = contextData.CurrentScope;
			current = FastGetTransaction(currentScope, contextData, out contextTransaction);
		}

		private Transaction()
		{
		}

		internal Transaction(IsolationLevel isoLevel, InternalTransaction internalTransaction)
		{
			TransactionManager.ValidateIsolationLevel(isoLevel);
			this.isoLevel = isoLevel;
			if (IsolationLevel.Unspecified == this.isoLevel)
			{
				this.isoLevel = TransactionManager.DefaultIsolationLevel;
			}
			if (internalTransaction != null)
			{
				this.internalTransaction = internalTransaction;
				cloneId = Interlocked.Increment(ref this.internalTransaction.cloneCount);
			}
		}

		internal Transaction(System.Transactions.Oletx.OletxTransaction oleTransaction)
		{
			isoLevel = oleTransaction.IsolationLevel;
			internalTransaction = new InternalTransaction(this, oleTransaction);
			cloneId = Interlocked.Increment(ref internalTransaction.cloneCount);
		}

		internal Transaction(IsolationLevel isoLevel, ISimpleTransactionSuperior superior)
		{
			TransactionManager.ValidateIsolationLevel(isoLevel);
			if (superior == null)
			{
				throw new ArgumentNullException("superior");
			}
			this.isoLevel = isoLevel;
			if (IsolationLevel.Unspecified == this.isoLevel)
			{
				this.isoLevel = TransactionManager.DefaultIsolationLevel;
			}
			internalTransaction = new InternalTransaction(this, superior);
			cloneId = 1;
		}

		public override int GetHashCode()
		{
			return internalTransaction.TransactionHash;
		}

		public override bool Equals(object obj)
		{
			Transaction transaction = obj as Transaction;
			if (null == transaction)
			{
				return false;
			}
			return internalTransaction.TransactionHash == transaction.internalTransaction.TransactionHash;
		}

		public static bool operator ==(Transaction x, Transaction y)
		{
			return x?.Equals(y) ?? ((object)y == null);
		}

		public static bool operator !=(Transaction x, Transaction y)
		{
			if ((object)x != null)
			{
				return !x.Equals(y);
			}
			return (object)y != null;
		}

		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public Enlistment EnlistDurable(Guid resourceManagerIdentifier, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistDurable( IEnlistmentNotification )");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (resourceManagerIdentifier == Guid.Empty)
			{
				throw new ArgumentException(SR.GetString("BadResourceManagerId"), "resourceManagerIdentifier");
			}
			if (enlistmentNotification == null)
			{
				throw new ArgumentNullException("enlistmentNotification");
			}
			if (enlistmentOptions != 0 && enlistmentOptions != EnlistmentOptions.EnlistDuringPrepareRequired)
			{
				throw new ArgumentOutOfRangeException("enlistmentOptions");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			lock (internalTransaction)
			{
				Enlistment result = internalTransaction.State.EnlistDurable(internalTransaction, resourceManagerIdentifier, enlistmentNotification, enlistmentOptions, this);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistDurable( IEnlistmentNotification )");
				}
				return result;
			}
		}

		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public Enlistment EnlistDurable(Guid resourceManagerIdentifier, ISinglePhaseNotification singlePhaseNotification, EnlistmentOptions enlistmentOptions)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistDurable( ISinglePhaseNotification )");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (resourceManagerIdentifier == Guid.Empty)
			{
				throw new ArgumentException(SR.GetString("BadResourceManagerId"), "resourceManagerIdentifier");
			}
			if (singlePhaseNotification == null)
			{
				throw new ArgumentNullException("singlePhaseNotification");
			}
			if (enlistmentOptions != 0 && enlistmentOptions != EnlistmentOptions.EnlistDuringPrepareRequired)
			{
				throw new ArgumentOutOfRangeException("enlistmentOptions");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			lock (internalTransaction)
			{
				Enlistment result = internalTransaction.State.EnlistDurable(internalTransaction, resourceManagerIdentifier, singlePhaseNotification, enlistmentOptions, this);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistDurable( ISinglePhaseNotification )");
				}
				return result;
			}
		}

		public void Rollback()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.Rollback");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionRollbackCalledTraceRecord.Trace(SR.GetString("TraceSourceLtm"), TransactionTraceId);
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			lock (internalTransaction)
			{
				internalTransaction.State.Rollback(internalTransaction, null);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.Rollback");
			}
		}

		public void Rollback(Exception e)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.Rollback");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionRollbackCalledTraceRecord.Trace(SR.GetString("TraceSourceLtm"), TransactionTraceId);
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			lock (internalTransaction)
			{
				internalTransaction.State.Rollback(internalTransaction, e);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.Rollback");
			}
		}

		public Enlistment EnlistVolatile(IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistVolatile( IEnlistmentNotification )");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (enlistmentNotification == null)
			{
				throw new ArgumentNullException("enlistmentNotification");
			}
			if (enlistmentOptions != 0 && enlistmentOptions != EnlistmentOptions.EnlistDuringPrepareRequired)
			{
				throw new ArgumentOutOfRangeException("enlistmentOptions");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			lock (internalTransaction)
			{
				Enlistment result = internalTransaction.State.EnlistVolatile(internalTransaction, enlistmentNotification, enlistmentOptions, this);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistVolatile( IEnlistmentNotification )");
				}
				return result;
			}
		}

		public Enlistment EnlistVolatile(ISinglePhaseNotification singlePhaseNotification, EnlistmentOptions enlistmentOptions)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistVolatile( ISinglePhaseNotification )");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (singlePhaseNotification == null)
			{
				throw new ArgumentNullException("singlePhaseNotification");
			}
			if (enlistmentOptions != 0 && enlistmentOptions != EnlistmentOptions.EnlistDuringPrepareRequired)
			{
				throw new ArgumentOutOfRangeException("enlistmentOptions");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			lock (internalTransaction)
			{
				Enlistment result = internalTransaction.State.EnlistVolatile(internalTransaction, singlePhaseNotification, enlistmentOptions, this);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistVolatile( ISinglePhaseNotification )");
				}
				return result;
			}
		}

		public Transaction Clone()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.Clone");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			Transaction result = InternalClone();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.Clone");
			}
			return result;
		}

		internal Transaction InternalClone()
		{
			Transaction transaction = new Transaction(isoLevel, internalTransaction);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.CloneCreatedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), transaction.TransactionTraceId);
			}
			return transaction;
		}

		public DependentTransaction DependentClone(DependentCloneOption cloneOption)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.DependentClone");
			}
			if (cloneOption != 0 && cloneOption != DependentCloneOption.RollbackIfNotComplete)
			{
				throw new ArgumentOutOfRangeException("cloneOption");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			DependentTransaction dependentTransaction = new DependentTransaction(isoLevel, internalTransaction, cloneOption == DependentCloneOption.BlockCommitUntilComplete);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.DependentCloneCreatedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), dependentTransaction.TransactionTraceId, cloneOption);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.DependentClone");
			}
			return dependentTransaction;
		}

		public void Dispose()
		{
			InternalDispose();
		}

		internal virtual void InternalDispose()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "IDisposable.Dispose");
			}
			if (Interlocked.Exchange(ref disposed, 1) != 1)
			{
				long num = Interlocked.Decrement(ref internalTransaction.cloneCount);
				if (num == 0)
				{
					internalTransaction.Dispose();
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "IDisposable.Dispose");
				}
			}
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		void ISerializable.GetObjectData(SerializationInfo serializationInfo, StreamingContext context)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "ISerializable.GetObjectData");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (serializationInfo == null)
			{
				throw new ArgumentNullException("serializationInfo");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			lock (internalTransaction)
			{
				internalTransaction.State.GetObjectData(internalTransaction, serializationInfo, context);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.TransactionSerializedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), TransactionTraceId);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "ISerializable.GetObjectData");
			}
		}

		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public bool EnlistPromotableSinglePhase(IPromotableSinglePhaseNotification promotableSinglePhaseNotification)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistPromotableSinglePhase");
			}
			if (Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (promotableSinglePhaseNotification == null)
			{
				throw new ArgumentNullException("promotableSinglePhaseNotification");
			}
			if (complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			bool result = false;
			lock (internalTransaction)
			{
				result = internalTransaction.State.EnlistPromotableSinglePhase(internalTransaction, promotableSinglePhaseNotification, this);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Transaction.EnlistPromotableSinglePhase");
			}
			return result;
		}

		internal System.Transactions.Oletx.OletxTransaction Promote()
		{
			lock (internalTransaction)
			{
				internalTransaction.State.Promote(internalTransaction);
				return internalTransaction.PromotedTransaction;
			}
		}
	}
	internal enum DefaultComContextState
	{
		Unknown = 0,
		Unavailable = -1,
		Available = 1
	}
	[SuppressUnmanagedCodeSecurity]
	internal static class NativeMethods
	{
		[DllImport("Ole32")]
		[SuppressUnmanagedCodeSecurity]
		internal static extern void CoGetContextToken(out IntPtr contextToken);

		[DllImport("Ole32")]
		[SuppressUnmanagedCodeSecurity]
		internal static extern void CoGetDefaultContext(int aptType, ref Guid contextInterface, out SafeIUnknown safeUnknown);
	}
	internal class ContextData
	{
		internal TransactionScope CurrentScope;

		internal Transaction CurrentTransaction;

		internal DefaultComContextState DefaultComContextState;

		internal WeakReference WeakDefaultComContext;

		[ThreadStatic]
		private static ContextData staticData;

		internal static ContextData CurrentData
		{
			get
			{
				ContextData contextData = staticData;
				if (contextData == null)
				{
					contextData = (staticData = new ContextData());
				}
				return contextData;
			}
		}
	}
	public class TransactionInformation
	{
		private InternalTransaction internalTransaction;

		public string LocalIdentifier
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "TransactionInformation.get_LocalIdentifier");
				}
				try
				{
					return internalTransaction.TransactionTraceId.TransactionIdentifier;
				}
				finally
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "TransactionInformation.get_LocalIdentifier");
					}
				}
			}
		}

		public Guid DistributedIdentifier
		{
			get
			{
				//Discarded unreachable code: IL_0049
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "TransactionInformation.get_DistributedIdentifier");
				}
				try
				{
					lock (internalTransaction)
					{
						return internalTransaction.State.get_Identifier(internalTransaction);
					}
				}
				finally
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "TransactionInformation.get_DistributedIdentifier");
					}
				}
			}
		}

		public DateTime CreationTime => new DateTime(internalTransaction.CreationTime);

		public TransactionStatus Status
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "TransactionInformation.get_Status");
				}
				try
				{
					return internalTransaction.State.get_Status(internalTransaction);
				}
				finally
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "TransactionInformation.get_Status");
					}
				}
			}
		}

		internal TransactionInformation(InternalTransaction internalTransaction)
		{
			this.internalTransaction = internalTransaction;
		}
	}
	[Serializable]
	public sealed class DependentTransaction : Transaction
	{
		private bool blocking;

		internal DependentTransaction(IsolationLevel isoLevel, InternalTransaction internalTransaction, bool blocking)
			: base(isoLevel, internalTransaction)
		{
			this.blocking = blocking;
			lock (base.internalTransaction)
			{
				if (blocking)
				{
					base.internalTransaction.State.CreateBlockingClone(base.internalTransaction);
				}
				else
				{
					base.internalTransaction.State.CreateAbortingClone(base.internalTransaction);
				}
			}
		}

		public void Complete()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "DependentTransaction.Complete");
			}
			lock (internalTransaction)
			{
				if (base.Disposed)
				{
					throw new ObjectDisposedException("Transaction");
				}
				if (complete)
				{
					throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
				}
				complete = true;
				if (blocking)
				{
					internalTransaction.State.CompleteBlockingClone(internalTransaction);
				}
				else
				{
					internalTransaction.State.CompleteAbortingClone(internalTransaction);
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.DependentCloneCompleteTraceRecord.Trace(SR.GetString("TraceSourceLtm"), base.TransactionTraceId);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "DependentTransaction.Complete");
			}
		}
	}
	[Serializable]
	public sealed class CommittableTransaction : Transaction, IAsyncResult
	{
		internal bool completedSynchronously;

		object IAsyncResult.AsyncState => internalTransaction.asyncState;

		bool IAsyncResult.CompletedSynchronously => completedSynchronously;

		WaitHandle IAsyncResult.AsyncWaitHandle
		{
			get
			{
				if (internalTransaction.asyncResultEvent == null)
				{
					lock (internalTransaction)
					{
						if (internalTransaction.asyncResultEvent == null)
						{
							ManualResetEvent asyncResultEvent = new ManualResetEvent(internalTransaction.State.get_Status(internalTransaction) != TransactionStatus.Active);
							Thread.MemoryBarrier();
							internalTransaction.asyncResultEvent = asyncResultEvent;
						}
					}
				}
				return internalTransaction.asyncResultEvent;
			}
		}

		bool IAsyncResult.IsCompleted
		{
			get
			{
				lock (internalTransaction)
				{
					return internalTransaction.State.get_Status(internalTransaction) != TransactionStatus.Active;
				}
			}
		}

		public CommittableTransaction()
			: this(TransactionManager.DefaultIsolationLevel, TransactionManager.DefaultTimeout)
		{
		}

		public CommittableTransaction(TimeSpan timeout)
			: this(TransactionManager.DefaultIsolationLevel, timeout)
		{
		}

		public CommittableTransaction(TransactionOptions options)
			: this(options.IsolationLevel, options.Timeout)
		{
		}

		internal CommittableTransaction(IsolationLevel isoLevel, TimeSpan timeout)
			: base(isoLevel, (InternalTransaction)null)
		{
			internalTransaction = new InternalTransaction(timeout, this);
			internalTransaction.cloneCount = 1;
			cloneId = 1;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.TransactionCreatedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), base.TransactionTraceId);
			}
		}

		public IAsyncResult BeginCommit(AsyncCallback asyncCallback, object asyncState)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "CommittableTransaction.BeginCommit");
				System.Transactions.Diagnostics.TransactionCommitCalledTraceRecord.Trace(SR.GetString("TraceSourceLtm"), base.TransactionTraceId);
			}
			if (base.Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			lock (internalTransaction)
			{
				if (complete)
				{
					throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
				}
				internalTransaction.State.BeginCommit(internalTransaction, asyncCommit: true, asyncCallback, asyncState);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "CommittableTransaction.BeginCommit");
			}
			return this;
		}

		public void Commit()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "CommittableTransaction.Commit");
				System.Transactions.Diagnostics.TransactionCommitCalledTraceRecord.Trace(SR.GetString("TraceSourceLtm"), base.TransactionTraceId);
			}
			if (base.Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			lock (internalTransaction)
			{
				if (complete)
				{
					throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
				}
				internalTransaction.State.BeginCommit(internalTransaction, asyncCommit: false, null, null);
				while (!internalTransaction.State.IsCompleted(internalTransaction) && Monitor.Wait(internalTransaction))
				{
				}
				internalTransaction.State.EndCommit(internalTransaction);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "CommittableTransaction.Commit");
			}
		}

		internal override void InternalDispose()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "IDisposable.Dispose");
			}
			if (Interlocked.Exchange(ref disposed, 1) == 1)
			{
				return;
			}
			if (internalTransaction.State.get_Status(internalTransaction) == TransactionStatus.Active)
			{
				lock (internalTransaction)
				{
					internalTransaction.State.DisposeRoot(internalTransaction);
				}
			}
			long num = Interlocked.Decrement(ref internalTransaction.cloneCount);
			if (num == 0)
			{
				internalTransaction.Dispose();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "IDisposable.Dispose");
			}
		}

		public void EndCommit(IAsyncResult asyncResult)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "CommittableTransaction.EndCommit");
			}
			if (asyncResult != this)
			{
				throw new ArgumentException(SR.GetString("BadAsyncResult"), "asyncResult");
			}
			lock (internalTransaction)
			{
				while (!internalTransaction.State.IsCompleted(internalTransaction) && Monitor.Wait(internalTransaction))
				{
				}
				internalTransaction.State.EndCommit(internalTransaction);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "CommittableTransaction.EndCommit");
			}
		}
	}
	internal class InternalTransaction : IDisposable
	{
		internal const int volatileArrayIncrement = 8;

		protected TransactionState transactionState;

		internal TransactionState promoteState;

		internal FinalizedObject finalizedObject;

		internal int transactionHash;

		internal static int nextHash;

		private long absoluteTimeout;

		private long creationTime;

		internal InternalEnlistment durableEnlistment;

		internal VolatileEnlistmentSet phase0Volatiles;

		internal VolatileEnlistmentSet phase1Volatiles;

		internal int phase0VolatileWaveCount;

		internal System.Transactions.Oletx.OletxDependentTransaction phase0WaveDependentClone;

		internal int phase0WaveDependentCloneCount;

		internal System.Transactions.Oletx.OletxDependentTransaction abortingDependentClone;

		internal int abortingDependentCloneCount;

		internal Bucket tableBucket;

		internal int bucketIndex;

		internal TransactionCompletedEventHandler transactionCompletedDelegate;

		private System.Transactions.Oletx.OletxTransaction promotedTransaction;

		internal Exception innerException;

		internal int cloneCount;

		internal int enlistmentCount;

		internal ManualResetEvent asyncResultEvent;

		internal bool asyncCommit;

		internal AsyncCallback asyncCallback;

		internal object asyncState;

		internal bool needPulse;

		internal TransactionInformation transactionInformation;

		internal CommittableTransaction committableTransaction;

		internal Transaction outcomeSource;

		private static object classSyncObject;

		private static string instanceIdentifier;

		private TransactionTraceIdentifier traceIdentifier;

		internal ITransactionPromoter promoter;

		internal TransactionState State
		{
			get
			{
				return transactionState;
			}
			set
			{
				transactionState = value;
			}
		}

		internal int TransactionHash => transactionHash;

		internal long AbsoluteTimeout => absoluteTimeout;

		internal long CreationTime
		{
			get
			{
				return creationTime;
			}
			set
			{
				creationTime = value;
			}
		}

		internal System.Transactions.Oletx.OletxTransaction PromotedTransaction
		{
			get
			{
				return promotedTransaction;
			}
			set
			{
				promotedTransaction = value;
			}
		}

		internal static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}

		internal static string InstanceIdentifier
		{
			get
			{
				if (instanceIdentifier == null)
				{
					lock (ClassSyncObject)
					{
						if (instanceIdentifier == null)
						{
							string text = Guid.NewGuid().ToString() + ":";
							Thread.MemoryBarrier();
							instanceIdentifier = text;
						}
					}
				}
				return instanceIdentifier;
			}
		}

		internal TransactionTraceIdentifier TransactionTraceId
		{
			get
			{
				if (traceIdentifier == TransactionTraceIdentifier.Empty)
				{
					lock (this)
					{
						if (traceIdentifier == TransactionTraceIdentifier.Empty)
						{
							TransactionTraceIdentifier transactionTraceIdentifier = new TransactionTraceIdentifier(InstanceIdentifier + Convert.ToString(transactionHash, CultureInfo.InvariantCulture), 0);
							Thread.MemoryBarrier();
							traceIdentifier = transactionTraceIdentifier;
						}
					}
				}
				return traceIdentifier;
			}
		}

		internal InternalTransaction(TimeSpan timeout, CommittableTransaction committableTransaction)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			absoluteTimeout = TransactionManager.TransactionTable.TimeoutTicks(timeout);
			TransactionState._TransactionStateActive.EnterState(this);
			promoteState = TransactionState._TransactionStatePromoted;
			this.committableTransaction = committableTransaction;
			outcomeSource = committableTransaction;
			transactionHash = TransactionManager.TransactionTable.Add(this);
		}

		internal InternalTransaction(Transaction outcomeSource, System.Transactions.Oletx.OletxTransaction distributedTx)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			promotedTransaction = distributedTx;
			absoluteTimeout = long.MaxValue;
			this.outcomeSource = outcomeSource;
			transactionHash = TransactionManager.TransactionTable.Add(this);
			TransactionState._TransactionStateNonCommittablePromoted.EnterState(this);
			promoteState = TransactionState._TransactionStateNonCommittablePromoted;
		}

		internal InternalTransaction(Transaction outcomeSource, ITransactionPromoter promoter)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			absoluteTimeout = long.MaxValue;
			this.outcomeSource = outcomeSource;
			transactionHash = TransactionManager.TransactionTable.Add(this);
			this.promoter = promoter;
			TransactionState._TransactionStateSubordinateActive.EnterState(this);
			promoteState = TransactionState._TransactionStateDelegatedSubordinate;
		}

		internal static void DistributedTransactionOutcome(InternalTransaction tx, TransactionStatus status)
		{
			FinalizedObject finalizedObject = null;
			lock (tx)
			{
				if (tx.innerException == null)
				{
					tx.innerException = tx.PromotedTransaction.InnerException;
				}
				switch (status)
				{
				case TransactionStatus.Committed:
					tx.State.ChangeStatePromotedCommitted(tx);
					break;
				case TransactionStatus.Aborted:
					tx.State.ChangeStatePromotedAborted(tx);
					break;
				case TransactionStatus.InDoubt:
					tx.State.InDoubtFromDtc(tx);
					break;
				default:
					TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), "", null);
					break;
				}
				finalizedObject = tx.finalizedObject;
			}
			finalizedObject?.Dispose();
		}

		internal void SignalAsyncCompletion()
		{
			if (asyncResultEvent != null)
			{
				asyncResultEvent.Set();
			}
			if (asyncCallback != null)
			{
				Monitor.Exit(this);
				try
				{
					asyncCallback(committableTransaction);
				}
				finally
				{
					Monitor.Enter(this);
				}
			}
		}

		internal void FireCompletion()
		{
			TransactionCompletedEventHandler transactionCompletedEventHandler = transactionCompletedDelegate;
			if (transactionCompletedEventHandler != null)
			{
				TransactionEventArgs transactionEventArgs = new TransactionEventArgs();
				transactionEventArgs.transaction = outcomeSource.InternalClone();
				transactionCompletedEventHandler(transactionEventArgs.transaction, transactionEventArgs);
			}
		}

		public void Dispose()
		{
			if (promotedTransaction != null)
			{
				promotedTransaction.Dispose();
			}
		}
	}
	internal sealed class FinalizedObject : IDisposable
	{
		private Guid identifier;

		private InternalTransaction internalTransaction;

		internal FinalizedObject(InternalTransaction internalTransaction, Guid identifier)
		{
			this.internalTransaction = internalTransaction;
			this.identifier = identifier;
		}

		private void Dispose(bool disposing)
		{
			if (disposing)
			{
				GC.SuppressFinalize(this);
			}
			Hashtable promotedTransactionTable = TransactionManager.PromotedTransactionTable;
			lock (promotedTransactionTable)
			{
				WeakReference weakReference = (WeakReference)promotedTransactionTable[identifier];
				if (weakReference != null && weakReference.Target != null)
				{
					weakReference.Target = null;
				}
				promotedTransactionTable.Remove(identifier);
			}
		}

		public void Dispose()
		{
			Dispose(disposing: true);
		}

		~FinalizedObject()
		{
			Dispose(disposing: false);
		}
	}
	internal abstract class TransactionState
	{
		private static TransactionStateActive _transactionStateActive;

		private static TransactionStateSubordinateActive _transactionStateSubordinateActive;

		private static TransactionStatePhase0 _transactionStatePhase0;

		private static TransactionStateVolatilePhase1 _transactionStateVolatilePhase1;

		private static TransactionStateVolatileSPC _transactionStateVolatileSPC;

		private static TransactionStateSPC _transactionStateSPC;

		private static TransactionStateAborted _transactionStateAborted;

		private static TransactionStateCommitted _transactionStateCommitted;

		private static TransactionStateInDoubt _transactionStateInDoubt;

		private static TransactionStatePromoted _transactionStatePromoted;

		private static TransactionStateNonCommittablePromoted _transactionStateNonCommittablePromoted;

		private static TransactionStatePromotedP0Wave _transactionStatePromotedP0Wave;

		private static TransactionStatePromotedCommitting _transactionStatePromotedCommitting;

		private static TransactionStatePromotedPhase0 _transactionStatePromotedPhase0;

		private static TransactionStatePromotedPhase1 _transactionStatePromotedPhase1;

		private static TransactionStatePromotedP0Aborting _transactionStatePromotedP0Aborting;

		private static TransactionStatePromotedP1Aborting _transactionStatePromotedP1Aborting;

		private static TransactionStatePromotedAborted _transactionStatePromotedAborted;

		private static TransactionStatePromotedCommitted _transactionStatePromotedCommitted;

		private static TransactionStatePromotedIndoubt _transactionStatePromotedIndoubt;

		private static TransactionStateDelegated _transactionStateDelegated;

		private static TransactionStateDelegatedSubordinate _transactionStateDelegatedSubordinate;

		private static TransactionStateDelegatedP0Wave _transactionStateDelegatedP0Wave;

		private static TransactionStateDelegatedCommitting _transactionStateDelegatedCommitting;

		private static TransactionStateDelegatedAborting _transactionStateDelegatedAborting;

		private static TransactionStatePSPEOperation _transactionStatePSPEOperation;

		private static object classSyncObject;

		internal static TransactionStateActive _TransactionStateActive
		{
			get
			{
				if (_transactionStateActive == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateActive == null)
						{
							TransactionStateActive transactionStateActive = new TransactionStateActive();
							Thread.MemoryBarrier();
							_transactionStateActive = transactionStateActive;
						}
					}
				}
				return _transactionStateActive;
			}
		}

		internal static TransactionStateSubordinateActive _TransactionStateSubordinateActive
		{
			get
			{
				if (_transactionStateSubordinateActive == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateSubordinateActive == null)
						{
							TransactionStateSubordinateActive transactionStateSubordinateActive = new TransactionStateSubordinateActive();
							Thread.MemoryBarrier();
							_transactionStateSubordinateActive = transactionStateSubordinateActive;
						}
					}
				}
				return _transactionStateSubordinateActive;
			}
		}

		internal static TransactionStatePSPEOperation _TransactionStatePSPEOperation
		{
			get
			{
				if (_transactionStatePSPEOperation == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePSPEOperation == null)
						{
							TransactionStatePSPEOperation transactionStatePSPEOperation = new TransactionStatePSPEOperation();
							Thread.MemoryBarrier();
							_transactionStatePSPEOperation = transactionStatePSPEOperation;
						}
					}
				}
				return _transactionStatePSPEOperation;
			}
		}

		protected static TransactionStatePhase0 _TransactionStatePhase0
		{
			get
			{
				if (_transactionStatePhase0 == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePhase0 == null)
						{
							TransactionStatePhase0 transactionStatePhase = new TransactionStatePhase0();
							Thread.MemoryBarrier();
							_transactionStatePhase0 = transactionStatePhase;
						}
					}
				}
				return _transactionStatePhase0;
			}
		}

		protected static TransactionStateVolatilePhase1 _TransactionStateVolatilePhase1
		{
			get
			{
				if (_transactionStateVolatilePhase1 == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateVolatilePhase1 == null)
						{
							TransactionStateVolatilePhase1 transactionStateVolatilePhase = new TransactionStateVolatilePhase1();
							Thread.MemoryBarrier();
							_transactionStateVolatilePhase1 = transactionStateVolatilePhase;
						}
					}
				}
				return _transactionStateVolatilePhase1;
			}
		}

		protected static TransactionStateVolatileSPC _TransactionStateVolatileSPC
		{
			get
			{
				if (_transactionStateVolatileSPC == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateVolatileSPC == null)
						{
							TransactionStateVolatileSPC transactionStateVolatileSPC = new TransactionStateVolatileSPC();
							Thread.MemoryBarrier();
							_transactionStateVolatileSPC = transactionStateVolatileSPC;
						}
					}
				}
				return _transactionStateVolatileSPC;
			}
		}

		protected static TransactionStateSPC _TransactionStateSPC
		{
			get
			{
				if (_transactionStateSPC == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateSPC == null)
						{
							TransactionStateSPC transactionStateSPC = new TransactionStateSPC();
							Thread.MemoryBarrier();
							_transactionStateSPC = transactionStateSPC;
						}
					}
				}
				return _transactionStateSPC;
			}
		}

		protected static TransactionStateAborted _TransactionStateAborted
		{
			get
			{
				if (_transactionStateAborted == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateAborted == null)
						{
							TransactionStateAborted transactionStateAborted = new TransactionStateAborted();
							Thread.MemoryBarrier();
							_transactionStateAborted = transactionStateAborted;
						}
					}
				}
				return _transactionStateAborted;
			}
		}

		protected static TransactionStateCommitted _TransactionStateCommitted
		{
			get
			{
				if (_transactionStateCommitted == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateCommitted == null)
						{
							TransactionStateCommitted transactionStateCommitted = new TransactionStateCommitted();
							Thread.MemoryBarrier();
							_transactionStateCommitted = transactionStateCommitted;
						}
					}
				}
				return _transactionStateCommitted;
			}
		}

		protected static TransactionStateInDoubt _TransactionStateInDoubt
		{
			get
			{
				if (_transactionStateInDoubt == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateInDoubt == null)
						{
							TransactionStateInDoubt transactionStateInDoubt = new TransactionStateInDoubt();
							Thread.MemoryBarrier();
							_transactionStateInDoubt = transactionStateInDoubt;
						}
					}
				}
				return _transactionStateInDoubt;
			}
		}

		internal static TransactionStatePromoted _TransactionStatePromoted
		{
			get
			{
				if (_transactionStatePromoted == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromoted == null)
						{
							TransactionStatePromoted transactionStatePromoted = new TransactionStatePromoted();
							Thread.MemoryBarrier();
							_transactionStatePromoted = transactionStatePromoted;
						}
					}
				}
				return _transactionStatePromoted;
			}
		}

		internal static TransactionStateNonCommittablePromoted _TransactionStateNonCommittablePromoted
		{
			get
			{
				if (_transactionStateNonCommittablePromoted == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateNonCommittablePromoted == null)
						{
							TransactionStateNonCommittablePromoted transactionStateNonCommittablePromoted = new TransactionStateNonCommittablePromoted();
							Thread.MemoryBarrier();
							_transactionStateNonCommittablePromoted = transactionStateNonCommittablePromoted;
						}
					}
				}
				return _transactionStateNonCommittablePromoted;
			}
		}

		protected static TransactionStatePromotedP0Wave _TransactionStatePromotedP0Wave
		{
			get
			{
				if (_transactionStatePromotedP0Wave == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedP0Wave == null)
						{
							TransactionStatePromotedP0Wave transactionStatePromotedP0Wave = new TransactionStatePromotedP0Wave();
							Thread.MemoryBarrier();
							_transactionStatePromotedP0Wave = transactionStatePromotedP0Wave;
						}
					}
				}
				return _transactionStatePromotedP0Wave;
			}
		}

		protected static TransactionStatePromotedCommitting _TransactionStatePromotedCommitting
		{
			get
			{
				if (_transactionStatePromotedCommitting == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedCommitting == null)
						{
							TransactionStatePromotedCommitting transactionStatePromotedCommitting = new TransactionStatePromotedCommitting();
							Thread.MemoryBarrier();
							_transactionStatePromotedCommitting = transactionStatePromotedCommitting;
						}
					}
				}
				return _transactionStatePromotedCommitting;
			}
		}

		protected static TransactionStatePromotedPhase0 _TransactionStatePromotedPhase0
		{
			get
			{
				if (_transactionStatePromotedPhase0 == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedPhase0 == null)
						{
							TransactionStatePromotedPhase0 transactionStatePromotedPhase = new TransactionStatePromotedPhase0();
							Thread.MemoryBarrier();
							_transactionStatePromotedPhase0 = transactionStatePromotedPhase;
						}
					}
				}
				return _transactionStatePromotedPhase0;
			}
		}

		protected static TransactionStatePromotedPhase1 _TransactionStatePromotedPhase1
		{
			get
			{
				if (_transactionStatePromotedPhase1 == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedPhase1 == null)
						{
							TransactionStatePromotedPhase1 transactionStatePromotedPhase = new TransactionStatePromotedPhase1();
							Thread.MemoryBarrier();
							_transactionStatePromotedPhase1 = transactionStatePromotedPhase;
						}
					}
				}
				return _transactionStatePromotedPhase1;
			}
		}

		protected static TransactionStatePromotedP0Aborting _TransactionStatePromotedP0Aborting
		{
			get
			{
				if (_transactionStatePromotedP0Aborting == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedP0Aborting == null)
						{
							TransactionStatePromotedP0Aborting transactionStatePromotedP0Aborting = new TransactionStatePromotedP0Aborting();
							Thread.MemoryBarrier();
							_transactionStatePromotedP0Aborting = transactionStatePromotedP0Aborting;
						}
					}
				}
				return _transactionStatePromotedP0Aborting;
			}
		}

		protected static TransactionStatePromotedP1Aborting _TransactionStatePromotedP1Aborting
		{
			get
			{
				if (_transactionStatePromotedP1Aborting == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedP1Aborting == null)
						{
							TransactionStatePromotedP1Aborting transactionStatePromotedP1Aborting = new TransactionStatePromotedP1Aborting();
							Thread.MemoryBarrier();
							_transactionStatePromotedP1Aborting = transactionStatePromotedP1Aborting;
						}
					}
				}
				return _transactionStatePromotedP1Aborting;
			}
		}

		protected static TransactionStatePromotedAborted _TransactionStatePromotedAborted
		{
			get
			{
				if (_transactionStatePromotedAborted == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedAborted == null)
						{
							TransactionStatePromotedAborted transactionStatePromotedAborted = new TransactionStatePromotedAborted();
							Thread.MemoryBarrier();
							_transactionStatePromotedAborted = transactionStatePromotedAborted;
						}
					}
				}
				return _transactionStatePromotedAborted;
			}
		}

		protected static TransactionStatePromotedCommitted _TransactionStatePromotedCommitted
		{
			get
			{
				if (_transactionStatePromotedCommitted == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedCommitted == null)
						{
							TransactionStatePromotedCommitted transactionStatePromotedCommitted = new TransactionStatePromotedCommitted();
							Thread.MemoryBarrier();
							_transactionStatePromotedCommitted = transactionStatePromotedCommitted;
						}
					}
				}
				return _transactionStatePromotedCommitted;
			}
		}

		protected static TransactionStatePromotedIndoubt _TransactionStatePromotedIndoubt
		{
			get
			{
				if (_transactionStatePromotedIndoubt == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStatePromotedIndoubt == null)
						{
							TransactionStatePromotedIndoubt transactionStatePromotedIndoubt = new TransactionStatePromotedIndoubt();
							Thread.MemoryBarrier();
							_transactionStatePromotedIndoubt = transactionStatePromotedIndoubt;
						}
					}
				}
				return _transactionStatePromotedIndoubt;
			}
		}

		protected static TransactionStateDelegated _TransactionStateDelegated
		{
			get
			{
				if (_transactionStateDelegated == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateDelegated == null)
						{
							TransactionStateDelegated transactionStateDelegated = new TransactionStateDelegated();
							Thread.MemoryBarrier();
							_transactionStateDelegated = transactionStateDelegated;
						}
					}
				}
				return _transactionStateDelegated;
			}
		}

		internal static TransactionStateDelegatedSubordinate _TransactionStateDelegatedSubordinate
		{
			get
			{
				if (_transactionStateDelegatedSubordinate == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateDelegatedSubordinate == null)
						{
							TransactionStateDelegatedSubordinate transactionStateDelegatedSubordinate = new TransactionStateDelegatedSubordinate();
							Thread.MemoryBarrier();
							_transactionStateDelegatedSubordinate = transactionStateDelegatedSubordinate;
						}
					}
				}
				return _transactionStateDelegatedSubordinate;
			}
		}

		protected static TransactionStateDelegatedP0Wave _TransactionStateDelegatedP0Wave
		{
			get
			{
				if (_transactionStateDelegatedP0Wave == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateDelegatedP0Wave == null)
						{
							TransactionStateDelegatedP0Wave transactionStateDelegatedP0Wave = new TransactionStateDelegatedP0Wave();
							Thread.MemoryBarrier();
							_transactionStateDelegatedP0Wave = transactionStateDelegatedP0Wave;
						}
					}
				}
				return _transactionStateDelegatedP0Wave;
			}
		}

		protected static TransactionStateDelegatedCommitting _TransactionStateDelegatedCommitting
		{
			get
			{
				if (_transactionStateDelegatedCommitting == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateDelegatedCommitting == null)
						{
							TransactionStateDelegatedCommitting transactionStateDelegatedCommitting = new TransactionStateDelegatedCommitting();
							Thread.MemoryBarrier();
							_transactionStateDelegatedCommitting = transactionStateDelegatedCommitting;
						}
					}
				}
				return _transactionStateDelegatedCommitting;
			}
		}

		protected static TransactionStateDelegatedAborting _TransactionStateDelegatedAborting
		{
			get
			{
				if (_transactionStateDelegatedAborting == null)
				{
					lock (ClassSyncObject)
					{
						if (_transactionStateDelegatedAborting == null)
						{
							TransactionStateDelegatedAborting transactionStateDelegatedAborting = new TransactionStateDelegatedAborting();
							Thread.MemoryBarrier();
							_transactionStateDelegatedAborting = transactionStateDelegatedAborting;
						}
					}
				}
				return _transactionStateDelegatedAborting;
			}
		}

		internal static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}

		internal void CommonEnterState(InternalTransaction tx)
		{
			tx.State = this;
		}

		internal abstract void EnterState(InternalTransaction tx);

		internal virtual void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void EndCommit(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void Rollback(InternalTransaction tx, Exception e)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual Enlistment EnlistVolatile(InternalTransaction tx, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual Enlistment EnlistVolatile(InternalTransaction tx, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void CheckForFinishedTransaction(InternalTransaction tx)
		{
		}

		internal virtual Guid get_Identifier(InternalTransaction tx)
		{
			return Guid.Empty;
		}

		internal abstract TransactionStatus get_Status(InternalTransaction tx);

		internal virtual void AddOutcomeRegistrant(InternalTransaction tx, TransactionCompletedEventHandler transactionCompletedDelegate)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual bool EnlistPromotableSinglePhase(InternalTransaction tx, IPromotableSinglePhaseNotification promotableSinglePhaseNotification, Transaction atomicTransaction)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void CompleteBlockingClone(InternalTransaction tx)
		{
		}

		internal virtual void CompleteAbortingClone(InternalTransaction tx)
		{
		}

		internal virtual void CreateBlockingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void CreateAbortingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void ChangeStateTransactionCommitted(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void InDoubtFromEnlistment(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void ChangeStatePromotedAborted(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void ChangeStatePromotedCommitted(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void InDoubtFromDtc(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void ChangeStatePromotedPhase0(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void ChangeStatePromotedPhase1(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void ChangeStateAbortedDuringPromotion(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual void Timeout(InternalTransaction tx)
		{
		}

		internal virtual void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void RestartCommitIfNeeded(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "");
			}
			throw new InvalidOperationException();
		}

		internal virtual bool ContinuePhase0Prepares()
		{
			return false;
		}

		internal virtual bool ContinuePhase1Prepares()
		{
			return false;
		}

		internal virtual void Promote(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal virtual void DisposeRoot(InternalTransaction tx)
		{
		}

		internal virtual bool IsCompleted(InternalTransaction tx)
		{
			tx.needPulse = true;
			return false;
		}

		protected void AddVolatileEnlistment(ref VolatileEnlistmentSet enlistments, Enlistment enlistment)
		{
			if (enlistments.volatileEnlistmentCount == enlistments.volatileEnlistmentSize)
			{
				InternalEnlistment[] array = new InternalEnlistment[enlistments.volatileEnlistmentSize + 8];
				if (enlistments.volatileEnlistmentSize > 0)
				{
					Array.Copy(enlistments.volatileEnlistments, array, enlistments.volatileEnlistmentSize);
				}
				enlistments.volatileEnlistmentSize += 8;
				enlistments.volatileEnlistments = array;
			}
			enlistments.volatileEnlistments[enlistments.volatileEnlistmentCount] = enlistment.InternalEnlistment;
			enlistments.volatileEnlistmentCount++;
			VolatileEnlistmentState._VolatileEnlistmentActive.EnterState(enlistments.volatileEnlistments[enlistments.volatileEnlistmentCount - 1]);
		}
	}
	internal abstract class ActiveStates : TransactionState
	{
		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.Active;
		}

		internal override void AddOutcomeRegistrant(InternalTransaction tx, TransactionCompletedEventHandler transactionCompletedDelegate)
		{
			tx.transactionCompletedDelegate = (TransactionCompletedEventHandler)Delegate.Combine(tx.transactionCompletedDelegate, transactionCompletedDelegate);
		}
	}
	internal abstract class EnlistableStates : ActiveStates
	{
		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			tx.promoteState.EnterState(tx);
			return tx.State.EnlistDurable(tx, resourceManagerIdentifier, enlistmentNotification, enlistmentOptions, atomicTransaction);
		}

		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			if (tx.durableEnlistment != null || (enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
			{
				tx.promoteState.EnterState(tx);
				return tx.State.EnlistDurable(tx, resourceManagerIdentifier, enlistmentNotification, enlistmentOptions, atomicTransaction);
			}
			Enlistment enlistment = new Enlistment(resourceManagerIdentifier, tx, enlistmentNotification, enlistmentNotification, atomicTransaction);
			tx.durableEnlistment = enlistment.InternalEnlistment;
			DurableEnlistmentState._DurableEnlistmentActive.EnterState(tx.durableEnlistment);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.durableEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentType.Durable, EnlistmentOptions.None);
			}
			return enlistment;
		}

		internal override void Timeout(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionTimeoutTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
			TimeoutException e = new TimeoutException(SR.GetString("TraceTransactionTimeout"));
			Rollback(tx, e);
		}

		internal override void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			tx.promoteState.EnterState(tx);
			tx.State.GetObjectData(tx, serializationInfo, context);
		}

		internal override void CompleteBlockingClone(InternalTransaction tx)
		{
			tx.phase0Volatiles.dependentClones--;
			if (tx.phase0Volatiles.preparedVolatileEnlistments == tx.phase0VolatileWaveCount + tx.phase0Volatiles.dependentClones)
			{
				tx.State.Phase0VolatilePrepareDone(tx);
			}
		}

		internal override void CompleteAbortingClone(InternalTransaction tx)
		{
			tx.phase1Volatiles.dependentClones--;
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			tx.phase0Volatiles.dependentClones++;
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			tx.phase1Volatiles.dependentClones++;
		}

		internal override void Promote(InternalTransaction tx)
		{
			tx.promoteState.EnterState(tx);
			tx.State.CheckForFinishedTransaction(tx);
		}
	}
	internal class TransactionStateActive : EnlistableStates
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			tx.asyncCommit = asyncCommit;
			tx.asyncCallback = asyncCallback;
			tx.asyncState = asyncState;
			TransactionState._TransactionStatePhase0.EnterState(tx);
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStateAborted.EnterState(tx);
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Enlistment enlistment = new Enlistment(tx, enlistmentNotification, null, atomicTransaction, enlistmentOptions);
			if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
			{
				AddVolatileEnlistment(ref tx.phase0Volatiles, enlistment);
			}
			else
			{
				AddVolatileEnlistment(ref tx.phase1Volatiles, enlistment);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.InternalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentType.Volatile, enlistmentOptions);
			}
			return enlistment;
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Enlistment enlistment = new Enlistment(tx, enlistmentNotification, enlistmentNotification, atomicTransaction, enlistmentOptions);
			if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
			{
				AddVolatileEnlistment(ref tx.phase0Volatiles, enlistment);
			}
			else
			{
				AddVolatileEnlistment(ref tx.phase1Volatiles, enlistment);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.InternalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentType.Volatile, enlistmentOptions);
			}
			return enlistment;
		}

		internal override bool EnlistPromotableSinglePhase(InternalTransaction tx, IPromotableSinglePhaseNotification promotableSinglePhaseNotification, Transaction atomicTransaction)
		{
			if (tx.durableEnlistment != null)
			{
				return false;
			}
			TransactionState._TransactionStatePSPEOperation.PSPEInitialize(tx, promotableSinglePhaseNotification);
			Enlistment enlistment = new Enlistment(tx, promotableSinglePhaseNotification, atomicTransaction);
			tx.durableEnlistment = enlistment.InternalEnlistment;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.durableEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentType.PromotableSinglePhase, EnlistmentOptions.None);
			}
			tx.promoter = promotableSinglePhaseNotification;
			tx.promoteState = TransactionState._TransactionStateDelegated;
			DurableEnlistmentState._DurableEnlistmentActive.EnterState(tx.durableEnlistment);
			return true;
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void DisposeRoot(InternalTransaction tx)
		{
			tx.State.Rollback(tx, null);
		}
	}
	internal class TransactionStateSubordinateActive : TransactionStateActive
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			((ISimpleTransactionSuperior)tx.promoter).Rollback();
			TransactionState._TransactionStateAborted.EnterState(tx);
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			tx.promoteState.EnterState(tx);
			return tx.State.EnlistVolatile(tx, enlistmentNotification, enlistmentOptions, atomicTransaction);
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			tx.promoteState.EnterState(tx);
			return tx.State.EnlistVolatile(tx, enlistmentNotification, enlistmentOptions, atomicTransaction);
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			tx.promoteState.EnterState(tx);
			return tx.State.get_Status(tx);
		}

		internal override void AddOutcomeRegistrant(InternalTransaction tx, TransactionCompletedEventHandler transactionCompletedDelegate)
		{
			tx.promoteState.EnterState(tx);
			tx.State.AddOutcomeRegistrant(tx, transactionCompletedDelegate);
		}

		internal override bool EnlistPromotableSinglePhase(InternalTransaction tx, IPromotableSinglePhaseNotification promotableSinglePhaseNotification, Transaction atomicTransaction)
		{
			return false;
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			tx.promoteState.EnterState(tx);
			tx.State.CreateBlockingClone(tx);
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			tx.promoteState.EnterState(tx);
			tx.State.CreateAbortingClone(tx);
		}
	}
	internal class TransactionStatePhase0 : EnlistableStates
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			int volatileEnlistmentCount = tx.phase0Volatiles.volatileEnlistmentCount;
			int dependentClones = tx.phase0Volatiles.dependentClones;
			tx.phase0VolatileWaveCount = volatileEnlistmentCount;
			if (tx.phase0Volatiles.preparedVolatileEnlistments < volatileEnlistmentCount + dependentClones)
			{
				for (int i = 0; i < volatileEnlistmentCount; i++)
				{
					tx.phase0Volatiles.volatileEnlistments[i].twoPhaseState.ChangeStatePreparing(tx.phase0Volatiles.volatileEnlistments[i]);
					if (!tx.State.ContinuePhase0Prepares())
					{
						break;
					}
				}
			}
			else
			{
				TransactionState._TransactionStateVolatilePhase1.EnterState(tx);
			}
		}

		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Enlistment result = base.EnlistDurable(tx, resourceManagerIdentifier, enlistmentNotification, enlistmentOptions, atomicTransaction);
			tx.State.RestartCommitIfNeeded(tx);
			return result;
		}

		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Enlistment result = base.EnlistDurable(tx, resourceManagerIdentifier, enlistmentNotification, enlistmentOptions, atomicTransaction);
			tx.State.RestartCommitIfNeeded(tx);
			return result;
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Enlistment enlistment = new Enlistment(tx, enlistmentNotification, null, atomicTransaction, enlistmentOptions);
			if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
			{
				AddVolatileEnlistment(ref tx.phase0Volatiles, enlistment);
			}
			else
			{
				AddVolatileEnlistment(ref tx.phase1Volatiles, enlistment);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.InternalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentType.Volatile, enlistmentOptions);
			}
			return enlistment;
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Enlistment enlistment = new Enlistment(tx, enlistmentNotification, enlistmentNotification, atomicTransaction, enlistmentOptions);
			if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
			{
				AddVolatileEnlistment(ref tx.phase0Volatiles, enlistment);
			}
			else
			{
				AddVolatileEnlistment(ref tx.phase1Volatiles, enlistment);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.InternalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentType.Volatile, enlistmentOptions);
			}
			return enlistment;
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			ChangeStateTransactionAborted(tx, e);
		}

		internal override bool EnlistPromotableSinglePhase(InternalTransaction tx, IPromotableSinglePhaseNotification promotableSinglePhaseNotification, Transaction atomicTransaction)
		{
			if (tx.durableEnlistment != null)
			{
				return false;
			}
			TransactionState._TransactionStatePSPEOperation.Phase0PSPEInitialize(tx, promotableSinglePhaseNotification);
			Enlistment enlistment = new Enlistment(tx, promotableSinglePhaseNotification, atomicTransaction);
			tx.durableEnlistment = enlistment.InternalEnlistment;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.durableEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentType.PromotableSinglePhase, EnlistmentOptions.None);
			}
			tx.promoter = promotableSinglePhaseNotification;
			tx.promoteState = TransactionState._TransactionStateDelegated;
			DurableEnlistmentState._DurableEnlistmentActive.EnterState(tx.durableEnlistment);
			return true;
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
			int volatileEnlistmentCount = tx.phase0Volatiles.volatileEnlistmentCount;
			int dependentClones = tx.phase0Volatiles.dependentClones;
			tx.phase0VolatileWaveCount = volatileEnlistmentCount;
			if (tx.phase0Volatiles.preparedVolatileEnlistments < volatileEnlistmentCount + dependentClones)
			{
				for (int i = 0; i < volatileEnlistmentCount; i++)
				{
					tx.phase0Volatiles.volatileEnlistments[i].twoPhaseState.ChangeStatePreparing(tx.phase0Volatiles.volatileEnlistments[i]);
					if (!tx.State.ContinuePhase0Prepares())
					{
						break;
					}
				}
			}
			else
			{
				TransactionState._TransactionStateVolatilePhase1.EnterState(tx);
			}
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void RestartCommitIfNeeded(InternalTransaction tx)
		{
		}

		internal override bool ContinuePhase0Prepares()
		{
			return true;
		}

		internal override void Promote(InternalTransaction tx)
		{
			tx.promoteState.EnterState(tx);
			tx.State.CheckForFinishedTransaction(tx);
			tx.State.RestartCommitIfNeeded(tx);
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStateAborted.EnterState(tx);
		}

		internal override void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			tx.promoteState.EnterState(tx);
			tx.State.GetObjectData(tx, serializationInfo, context);
			tx.State.RestartCommitIfNeeded(tx);
		}
	}
	internal class TransactionStateVolatilePhase1 : ActiveStates
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			tx.committableTransaction.complete = true;
			if (tx.phase1Volatiles.dependentClones != 0)
			{
				TransactionState._TransactionStateAborted.EnterState(tx);
			}
			else if (tx.phase1Volatiles.volatileEnlistmentCount == 1 && tx.durableEnlistment == null && tx.phase1Volatiles.volatileEnlistments[0].SinglePhaseNotification != null)
			{
				TransactionState._TransactionStateVolatileSPC.EnterState(tx);
			}
			else if (tx.phase1Volatiles.volatileEnlistmentCount > 0)
			{
				for (int i = 0; i < tx.phase1Volatiles.volatileEnlistmentCount; i++)
				{
					tx.phase1Volatiles.volatileEnlistments[i].twoPhaseState.ChangeStatePreparing(tx.phase1Volatiles.volatileEnlistments[i]);
					if (!tx.State.ContinuePhase1Prepares())
					{
						break;
					}
				}
			}
			else
			{
				TransactionState._TransactionStateSPC.EnterState(tx);
			}
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			ChangeStateTransactionAborted(tx, e);
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStateAborted.EnterState(tx);
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
			TransactionState._TransactionStateSPC.EnterState(tx);
		}

		internal override bool ContinuePhase1Prepares()
		{
			return true;
		}

		internal override void Timeout(InternalTransaction tx)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionTimeoutTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
			TimeoutException e = new TimeoutException(SR.GetString("TraceTransactionTimeout"));
			Rollback(tx, e);
		}
	}
	internal class TransactionStateVolatileSPC : ActiveStates
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			tx.phase1Volatiles.volatileEnlistments[0].twoPhaseState.ChangeStateSinglePhaseCommit(tx.phase1Volatiles.volatileEnlistments[0]);
		}

		internal override void ChangeStateTransactionCommitted(InternalTransaction tx)
		{
			TransactionState._TransactionStateCommitted.EnterState(tx);
		}

		internal override void InDoubtFromEnlistment(InternalTransaction tx)
		{
			TransactionState._TransactionStateInDoubt.EnterState(tx);
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStateAborted.EnterState(tx);
		}
	}
	internal class TransactionStateSPC : ActiveStates
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			if (tx.durableEnlistment != null)
			{
				tx.durableEnlistment.State.ChangeStateCommitting(tx.durableEnlistment);
			}
			else
			{
				TransactionState._TransactionStateCommitted.EnterState(tx);
			}
		}

		internal override void ChangeStateTransactionCommitted(InternalTransaction tx)
		{
			TransactionState._TransactionStateCommitted.EnterState(tx);
		}

		internal override void InDoubtFromEnlistment(InternalTransaction tx)
		{
			TransactionState._TransactionStateInDoubt.EnterState(tx);
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStateAborted.EnterState(tx);
		}
	}
	internal abstract class TransactionStateEnded : TransactionState
	{
		internal override void EnterState(InternalTransaction tx)
		{
			if (tx.needPulse)
			{
				Monitor.Pulse(tx);
			}
		}

		internal override void AddOutcomeRegistrant(InternalTransaction tx, TransactionCompletedEventHandler transactionCompletedDelegate)
		{
			if (transactionCompletedDelegate != null)
			{
				TransactionEventArgs transactionEventArgs = new TransactionEventArgs();
				transactionEventArgs.transaction = tx.outcomeSource.InternalClone();
				transactionCompletedDelegate(transactionEventArgs.transaction, transactionEventArgs);
			}
		}

		internal override bool IsCompleted(InternalTransaction tx)
		{
			return true;
		}
	}
	internal class TransactionStateAborted : TransactionStateEnded
	{
		internal override void EnterState(InternalTransaction tx)
		{
			base.EnterState(tx);
			CommonEnterState(tx);
			for (int i = 0; i < tx.phase0Volatiles.volatileEnlistmentCount; i++)
			{
				tx.phase0Volatiles.volatileEnlistments[i].twoPhaseState.InternalAborted(tx.phase0Volatiles.volatileEnlistments[i]);
			}
			for (int j = 0; j < tx.phase1Volatiles.volatileEnlistmentCount; j++)
			{
				tx.phase1Volatiles.volatileEnlistments[j].twoPhaseState.InternalAborted(tx.phase1Volatiles.volatileEnlistments[j]);
			}
			if (tx.durableEnlistment != null)
			{
				tx.durableEnlistment.State.InternalAborted(tx.durableEnlistment);
			}
			TransactionManager.TransactionTable.Remove(tx);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionAbortedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
			tx.FireCompletion();
			if (tx.asyncCommit)
			{
				tx.SignalAsyncCompletion();
			}
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.Aborted;
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			throw CreateTransactionAbortedException(tx);
		}

		internal override void EndCommit(InternalTransaction tx)
		{
			throw CreateTransactionAbortedException(tx);
		}

		internal override void RestartCommitIfNeeded(InternalTransaction tx)
		{
		}

		internal override void Timeout(InternalTransaction tx)
		{
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
		}

		internal override void ChangeStatePromotedAborted(InternalTransaction tx)
		{
		}

		internal override void ChangeStateAbortedDuringPromotion(InternalTransaction tx)
		{
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			throw CreateTransactionAbortedException(tx);
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			throw CreateTransactionAbortedException(tx);
		}

		internal override void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			throw CreateTransactionAbortedException(tx);
		}

		internal override void CheckForFinishedTransaction(InternalTransaction tx)
		{
			throw CreateTransactionAbortedException(tx);
		}

		private TransactionException CreateTransactionAbortedException(InternalTransaction tx)
		{
			return TransactionAbortedException.Create(SR.GetString("TraceSourceLtm"), SR.GetString("TransactionAborted"), tx.innerException);
		}
	}
	internal class TransactionStateCommitted : TransactionStateEnded
	{
		internal override void EnterState(InternalTransaction tx)
		{
			base.EnterState(tx);
			CommonEnterState(tx);
			for (int i = 0; i < tx.phase0Volatiles.volatileEnlistmentCount; i++)
			{
				tx.phase0Volatiles.volatileEnlistments[i].twoPhaseState.InternalCommitted(tx.phase0Volatiles.volatileEnlistments[i]);
			}
			for (int j = 0; j < tx.phase1Volatiles.volatileEnlistmentCount; j++)
			{
				tx.phase1Volatiles.volatileEnlistments[j].twoPhaseState.InternalCommitted(tx.phase1Volatiles.volatileEnlistments[j]);
			}
			TransactionManager.TransactionTable.Remove(tx);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.TransactionCommittedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
			tx.FireCompletion();
			if (tx.asyncCommit)
			{
				tx.SignalAsyncCompletion();
			}
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.Committed;
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void EndCommit(InternalTransaction tx)
		{
		}
	}
	internal class TransactionStateInDoubt : TransactionStateEnded
	{
		internal override void EnterState(InternalTransaction tx)
		{
			base.EnterState(tx);
			CommonEnterState(tx);
			for (int i = 0; i < tx.phase0Volatiles.volatileEnlistmentCount; i++)
			{
				tx.phase0Volatiles.volatileEnlistments[i].twoPhaseState.InternalIndoubt(tx.phase0Volatiles.volatileEnlistments[i]);
			}
			for (int j = 0; j < tx.phase1Volatiles.volatileEnlistmentCount; j++)
			{
				tx.phase1Volatiles.volatileEnlistments[j].twoPhaseState.InternalIndoubt(tx.phase1Volatiles.volatileEnlistments[j]);
			}
			TransactionManager.TransactionTable.Remove(tx);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionInDoubtTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
			tx.FireCompletion();
			if (tx.asyncCommit)
			{
				tx.SignalAsyncCompletion();
			}
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.InDoubt;
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void EndCommit(InternalTransaction tx)
		{
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}

		internal override void CheckForFinishedTransaction(InternalTransaction tx)
		{
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}

		internal override void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}
	}
	internal abstract class TransactionStatePromotedBase : TransactionState
	{
		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.Active;
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Monitor.Exit(tx);
			try
			{
				Enlistment enlistment = new Enlistment(enlistmentNotification, tx, atomicTransaction);
				EnlistmentState._EnlistmentStatePromoted.EnterState(enlistment.InternalEnlistment);
				enlistment.InternalEnlistment.PromotedEnlistment = tx.PromotedTransaction.EnlistVolatile(enlistment.InternalEnlistment, enlistmentOptions);
				return enlistment;
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Monitor.Exit(tx);
			try
			{
				Enlistment enlistment = new Enlistment(enlistmentNotification, tx, atomicTransaction);
				EnlistmentState._EnlistmentStatePromoted.EnterState(enlistment.InternalEnlistment);
				enlistment.InternalEnlistment.PromotedEnlistment = tx.PromotedTransaction.EnlistVolatile(enlistment.InternalEnlistment, enlistmentOptions);
				return enlistment;
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Monitor.Exit(tx);
			try
			{
				Enlistment enlistment = new Enlistment(resourceManagerIdentifier, tx, enlistmentNotification, null, atomicTransaction);
				EnlistmentState._EnlistmentStatePromoted.EnterState(enlistment.InternalEnlistment);
				enlistment.InternalEnlistment.PromotedEnlistment = tx.PromotedTransaction.EnlistDurable(resourceManagerIdentifier, (DurableInternalEnlistment)enlistment.InternalEnlistment, canDoSinglePhase: false, enlistmentOptions);
				return enlistment;
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			Monitor.Exit(tx);
			try
			{
				Enlistment enlistment = new Enlistment(resourceManagerIdentifier, tx, enlistmentNotification, enlistmentNotification, atomicTransaction);
				EnlistmentState._EnlistmentStatePromoted.EnterState(enlistment.InternalEnlistment);
				enlistment.InternalEnlistment.PromotedEnlistment = tx.PromotedTransaction.EnlistDurable(resourceManagerIdentifier, (DurableInternalEnlistment)enlistment.InternalEnlistment, canDoSinglePhase: true, enlistmentOptions);
				return enlistment;
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			Monitor.Exit(tx);
			try
			{
				tx.PromotedTransaction.Rollback();
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override Guid get_Identifier(InternalTransaction tx)
		{
			return tx.PromotedTransaction.Identifier;
		}

		internal override void AddOutcomeRegistrant(InternalTransaction tx, TransactionCompletedEventHandler transactionCompletedDelegate)
		{
			tx.transactionCompletedDelegate = (TransactionCompletedEventHandler)Delegate.Combine(tx.transactionCompletedDelegate, transactionCompletedDelegate);
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			tx.asyncCommit = asyncCommit;
			tx.asyncCallback = asyncCallback;
			tx.asyncState = asyncState;
			TransactionState._TransactionStatePromotedCommitting.EnterState(tx);
		}

		internal override void RestartCommitIfNeeded(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedP0Wave.EnterState(tx);
		}

		internal override bool EnlistPromotableSinglePhase(InternalTransaction tx, IPromotableSinglePhaseNotification promotableSinglePhaseNotification, Transaction atomicTransaction)
		{
			return false;
		}

		internal override void CompleteBlockingClone(InternalTransaction tx)
		{
			if (tx.phase0Volatiles.dependentClones > 0)
			{
				tx.phase0Volatiles.dependentClones--;
				if (tx.phase0Volatiles.preparedVolatileEnlistments == tx.phase0VolatileWaveCount + tx.phase0Volatiles.dependentClones)
				{
					tx.State.Phase0VolatilePrepareDone(tx);
				}
				return;
			}
			tx.phase0WaveDependentCloneCount--;
			if (tx.phase0WaveDependentCloneCount != 0)
			{
				return;
			}
			System.Transactions.Oletx.OletxDependentTransaction phase0WaveDependentClone = tx.phase0WaveDependentClone;
			tx.phase0WaveDependentClone = null;
			Monitor.Exit(tx);
			try
			{
				try
				{
					phase0WaveDependentClone.Complete();
				}
				finally
				{
					phase0WaveDependentClone.Dispose();
				}
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override void CompleteAbortingClone(InternalTransaction tx)
		{
			if (tx.phase1Volatiles.VolatileDemux != null)
			{
				tx.phase1Volatiles.dependentClones--;
				return;
			}
			tx.abortingDependentCloneCount--;
			if (tx.abortingDependentCloneCount != 0)
			{
				return;
			}
			System.Transactions.Oletx.OletxDependentTransaction abortingDependentClone = tx.abortingDependentClone;
			tx.abortingDependentClone = null;
			Monitor.Exit(tx);
			try
			{
				try
				{
					abortingDependentClone.Complete();
				}
				finally
				{
					abortingDependentClone.Dispose();
				}
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			if (tx.phase0WaveDependentClone == null)
			{
				tx.phase0WaveDependentClone = tx.PromotedTransaction.DependentClone(delayCommit: true);
			}
			tx.phase0WaveDependentCloneCount++;
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			if (tx.phase1Volatiles.VolatileDemux != null)
			{
				tx.phase1Volatiles.dependentClones++;
				return;
			}
			if (tx.abortingDependentClone == null)
			{
				tx.abortingDependentClone = tx.PromotedTransaction.DependentClone(delayCommit: false);
			}
			tx.abortingDependentCloneCount++;
		}

		internal override bool ContinuePhase0Prepares()
		{
			return true;
		}

		internal override void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			ISerializable promotedTransaction = tx.PromotedTransaction;
			if (promotedTransaction == null)
			{
				throw new NotSupportedException();
			}
			serializationInfo.FullTypeName = tx.PromotedTransaction.GetType().FullName;
			promotedTransaction.GetObjectData(serializationInfo, context);
		}

		internal override void ChangeStatePromotedAborted(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedAborted.EnterState(tx);
		}

		internal override void ChangeStatePromotedCommitted(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedCommitted.EnterState(tx);
		}

		internal override void InDoubtFromDtc(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedIndoubt.EnterState(tx);
		}

		internal override void InDoubtFromEnlistment(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedIndoubt.EnterState(tx);
		}

		internal override void ChangeStateAbortedDuringPromotion(InternalTransaction tx)
		{
			TransactionState._TransactionStateAborted.EnterState(tx);
		}

		internal override void Timeout(InternalTransaction tx)
		{
			try
			{
				if (tx.innerException == null)
				{
					tx.innerException = new TimeoutException(SR.GetString("TraceTransactionTimeout"));
				}
				tx.PromotedTransaction.Rollback();
				if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
				{
					System.Transactions.Diagnostics.TransactionTimeoutTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
				}
			}
			catch (TransactionException exception)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception);
				}
			}
		}

		internal override void Promote(InternalTransaction tx)
		{
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
		}
	}
	internal class TransactionStateNonCommittablePromoted : TransactionStatePromotedBase
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			tx.PromotedTransaction.realOletxTransaction.InternalTransaction = tx;
		}
	}
	internal class TransactionStatePromoted : TransactionStatePromotedBase
	{
		internal override void EnterState(InternalTransaction tx)
		{
			if (tx.outcomeSource.isoLevel == IsolationLevel.Snapshot)
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("CannotPromoteSnapshot"), null);
			}
			CommonEnterState(tx);
			System.Transactions.Oletx.OletxCommittableTransaction oletxCommittableTransaction = null;
			try
			{
				TimeSpan timeSpan;
				if (tx.AbsoluteTimeout == long.MaxValue)
				{
					timeSpan = TimeSpan.Zero;
				}
				else
				{
					timeSpan = TransactionManager.TransactionTable.RecalcTimeout(tx);
					if (timeSpan <= TimeSpan.Zero)
					{
						return;
					}
				}
				TransactionOptions properties = default(TransactionOptions);
				properties.IsolationLevel = tx.outcomeSource.isoLevel;
				properties.Timeout = timeSpan;
				oletxCommittableTransaction = TransactionManager.DistributedTransactionManager.CreateTransaction(properties);
				oletxCommittableTransaction.savedLtmPromotedTransaction = tx.outcomeSource;
				if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
				{
					System.Transactions.Diagnostics.TransactionPromotedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId, oletxCommittableTransaction.TransactionTraceId);
				}
			}
			catch (TransactionException innerException)
			{
				TransactionException exception = (TransactionException)(tx.innerException = innerException);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception);
				}
				return;
			}
			finally
			{
				if (oletxCommittableTransaction == null)
				{
					tx.State.ChangeStateAbortedDuringPromotion(tx);
				}
			}
			tx.PromotedTransaction = oletxCommittableTransaction;
			Hashtable promotedTransactionTable = TransactionManager.PromotedTransactionTable;
			lock (promotedTransactionTable)
			{
				tx.finalizedObject = new FinalizedObject(tx, oletxCommittableTransaction.Identifier);
				WeakReference value = new WeakReference(tx.outcomeSource, trackResurrection: false);
				promotedTransactionTable[oletxCommittableTransaction.Identifier] = value;
			}
			TransactionManager.FireDistributedTransactionStarted(tx.outcomeSource);
			PromoteEnlistmentsAndOutcome(tx);
		}

		protected bool PromotePhaseVolatiles(InternalTransaction tx, ref VolatileEnlistmentSet volatiles, bool phase0)
		{
			if (volatiles.volatileEnlistmentCount + volatiles.dependentClones > 0)
			{
				if (phase0)
				{
					volatiles.VolatileDemux = new Phase0VolatileDemultiplexer(tx);
				}
				else
				{
					volatiles.VolatileDemux = new Phase1VolatileDemultiplexer(tx);
				}
				volatiles.VolatileDemux.oletxEnlistment = tx.PromotedTransaction.EnlistVolatile(volatiles.VolatileDemux, phase0 ? EnlistmentOptions.EnlistDuringPrepareRequired : EnlistmentOptions.None);
			}
			return true;
		}

		internal virtual bool PromoteDurable(InternalTransaction tx)
		{
			if (tx.durableEnlistment != null)
			{
				InternalEnlistment durableEnlistment = tx.durableEnlistment;
				IPromotedEnlistment promotedEnlistment = tx.PromotedTransaction.EnlistDurable(durableEnlistment.ResourceManagerIdentifier, (DurableInternalEnlistment)durableEnlistment, durableEnlistment.SinglePhaseNotification != null, EnlistmentOptions.None);
				tx.durableEnlistment.State.ChangeStatePromoted(tx.durableEnlistment, promotedEnlistment);
			}
			return true;
		}

		internal virtual void PromoteEnlistmentsAndOutcome(InternalTransaction tx)
		{
			bool flag = false;
			tx.PromotedTransaction.RealTransaction.InternalTransaction = tx;
			try
			{
				flag = PromotePhaseVolatiles(tx, ref tx.phase0Volatiles, phase0: true);
			}
			catch (TransactionException innerException)
			{
				TransactionException exception = (TransactionException)(tx.innerException = innerException);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception);
				}
				return;
			}
			finally
			{
				if (!flag)
				{
					tx.PromotedTransaction.Rollback();
					tx.State.ChangeStateAbortedDuringPromotion(tx);
				}
			}
			flag = false;
			try
			{
				flag = PromotePhaseVolatiles(tx, ref tx.phase1Volatiles, phase0: false);
			}
			catch (TransactionException innerException2)
			{
				TransactionException exception2 = (TransactionException)(tx.innerException = innerException2);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception2);
				}
				return;
			}
			finally
			{
				if (!flag)
				{
					tx.PromotedTransaction.Rollback();
					tx.State.ChangeStateAbortedDuringPromotion(tx);
				}
			}
			flag = false;
			try
			{
				flag = PromoteDurable(tx);
			}
			catch (TransactionException innerException3)
			{
				TransactionException exception3 = (TransactionException)(tx.innerException = innerException3);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception3);
				}
			}
			finally
			{
				if (!flag)
				{
					tx.PromotedTransaction.Rollback();
					tx.State.ChangeStateAbortedDuringPromotion(tx);
				}
			}
		}

		internal override void DisposeRoot(InternalTransaction tx)
		{
			tx.State.Rollback(tx, null);
		}
	}
	internal class TransactionStatePromotedP0Wave : TransactionStatePromotedBase
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
			try
			{
				TransactionState._TransactionStatePromotedCommitting.EnterState(tx);
			}
			catch (TransactionException ex)
			{
				if (tx.innerException == null)
				{
					tx.innerException = ex;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), ex);
				}
			}
		}

		internal override bool ContinuePhase0Prepares()
		{
			return true;
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStatePromotedP0Aborting.EnterState(tx);
		}
	}
	internal class TransactionStatePromotedCommitting : TransactionStatePromotedBase
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			System.Transactions.Oletx.OletxCommittableTransaction oletxCommittableTransaction = (System.Transactions.Oletx.OletxCommittableTransaction)tx.PromotedTransaction;
			oletxCommittableTransaction.BeginCommit(tx);
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void ChangeStatePromotedPhase0(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedPhase0.EnterState(tx);
		}

		internal override void ChangeStatePromotedPhase1(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedPhase1.EnterState(tx);
		}
	}
	internal class TransactionStatePromotedPhase0 : TransactionStatePromotedCommitting
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			int volatileEnlistmentCount = tx.phase0Volatiles.volatileEnlistmentCount;
			int dependentClones = tx.phase0Volatiles.dependentClones;
			tx.phase0VolatileWaveCount = volatileEnlistmentCount;
			if (tx.phase0Volatiles.preparedVolatileEnlistments < volatileEnlistmentCount + dependentClones)
			{
				for (int i = 0; i < volatileEnlistmentCount; i++)
				{
					tx.phase0Volatiles.volatileEnlistments[i].twoPhaseState.ChangeStatePreparing(tx.phase0Volatiles.volatileEnlistments[i]);
					if (!tx.State.ContinuePhase0Prepares())
					{
						break;
					}
				}
			}
			else
			{
				Phase0VolatilePrepareDone(tx);
			}
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
			Monitor.Exit(tx);
			try
			{
				tx.phase0Volatiles.VolatileDemux.oletxEnlistment.Prepared();
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override bool ContinuePhase0Prepares()
		{
			return true;
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStatePromotedP0Aborting.EnterState(tx);
		}
	}
	internal class TransactionStatePromotedPhase1 : TransactionStatePromotedCommitting
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			if (tx.committableTransaction != null)
			{
				tx.committableTransaction.complete = true;
			}
			if (tx.phase1Volatiles.dependentClones != 0)
			{
				tx.State.ChangeStateTransactionAborted(tx, null);
				return;
			}
			int volatileEnlistmentCount = tx.phase1Volatiles.volatileEnlistmentCount;
			if (tx.phase1Volatiles.preparedVolatileEnlistments < volatileEnlistmentCount)
			{
				for (int i = 0; i < volatileEnlistmentCount; i++)
				{
					tx.phase1Volatiles.volatileEnlistments[i].twoPhaseState.ChangeStatePreparing(tx.phase1Volatiles.volatileEnlistments[i]);
					if (!tx.State.ContinuePhase1Prepares())
					{
						break;
					}
				}
			}
			else
			{
				Phase1VolatilePrepareDone(tx);
			}
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStatePromotedP1Aborting.EnterState(tx);
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
			Monitor.Exit(tx);
			try
			{
				tx.phase1Volatiles.VolatileDemux.oletxEnlistment.Prepared();
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override bool ContinuePhase1Prepares()
		{
			return true;
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw new TransactionException(SR.GetString("TooLate"));
		}

		internal override Enlistment EnlistVolatile(InternalTransaction tx, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw new TransactionException(SR.GetString("TooLate"));
		}

		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, IEnlistmentNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw new TransactionException(SR.GetString("TooLate"));
		}

		internal override Enlistment EnlistDurable(InternalTransaction tx, Guid resourceManagerIdentifier, ISinglePhaseNotification enlistmentNotification, EnlistmentOptions enlistmentOptions, Transaction atomicTransaction)
		{
			throw new TransactionException(SR.GetString("TooLate"));
		}
	}
	internal abstract class TransactionStatePromotedAborting : TransactionStatePromotedBase
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.Aborted;
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void ChangeStatePromotedAborted(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedAborted.EnterState(tx);
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
		}

		internal override void RestartCommitIfNeeded(InternalTransaction tx)
		{
		}
	}
	internal class TransactionStatePromotedP0Aborting : TransactionStatePromotedAborting
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			ChangeStatePromotedAborted(tx);
			if (tx.phase0Volatiles.VolatileDemux.preparingEnlistment != null)
			{
				Monitor.Exit(tx);
				try
				{
					tx.phase0Volatiles.VolatileDemux.oletxEnlistment.ForceRollback();
					return;
				}
				finally
				{
					Monitor.Enter(tx);
				}
			}
			tx.PromotedTransaction.Rollback();
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
		}
	}
	internal class TransactionStatePromotedP1Aborting : TransactionStatePromotedAborting
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			ChangeStatePromotedAborted(tx);
			Monitor.Exit(tx);
			try
			{
				tx.phase1Volatiles.VolatileDemux.oletxEnlistment.ForceRollback();
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
		}
	}
	internal abstract class TransactionStatePromotedEnded : TransactionStateEnded
	{
		private static WaitCallback signalMethod;

		private static WaitCallback SignalMethod
		{
			get
			{
				if (signalMethod == null)
				{
					lock (TransactionState.ClassSyncObject)
					{
						if (signalMethod == null)
						{
							signalMethod = SignalCallback;
						}
					}
				}
				return signalMethod;
			}
		}

		internal override void EnterState(InternalTransaction tx)
		{
			base.EnterState(tx);
			CommonEnterState(tx);
			if (!ThreadPool.QueueUserWorkItem(SignalMethod, tx))
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedFailureOfThreadPool"), null);
			}
		}

		internal override void AddOutcomeRegistrant(InternalTransaction tx, TransactionCompletedEventHandler transactionCompletedDelegate)
		{
			if (transactionCompletedDelegate != null)
			{
				TransactionEventArgs transactionEventArgs = new TransactionEventArgs();
				transactionEventArgs.transaction = tx.outcomeSource.InternalClone();
				transactionCompletedDelegate(transactionEventArgs.transaction, transactionEventArgs);
			}
		}

		internal override void EndCommit(InternalTransaction tx)
		{
			PromotedTransactionOutcome(tx);
		}

		internal override void CompleteBlockingClone(InternalTransaction tx)
		{
		}

		internal override void CompleteAbortingClone(InternalTransaction tx)
		{
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override Guid get_Identifier(InternalTransaction tx)
		{
			return tx.PromotedTransaction.Identifier;
		}

		internal override void Promote(InternalTransaction tx)
		{
		}

		protected abstract void PromotedTransactionOutcome(InternalTransaction tx);

		private static void SignalCallback(object state)
		{
			InternalTransaction internalTransaction = (InternalTransaction)state;
			lock (internalTransaction)
			{
				internalTransaction.SignalAsyncCompletion();
				TransactionManager.TransactionTable.Remove(internalTransaction);
			}
		}
	}
	internal class TransactionStatePromotedAborted : TransactionStatePromotedEnded
	{
		internal override void EnterState(InternalTransaction tx)
		{
			base.EnterState(tx);
			if (tx.phase1Volatiles.VolatileDemux != null)
			{
				tx.phase1Volatiles.VolatileDemux.BroadcastRollback(ref tx.phase1Volatiles);
			}
			if (tx.phase0Volatiles.VolatileDemux != null)
			{
				tx.phase0Volatiles.VolatileDemux.BroadcastRollback(ref tx.phase0Volatiles);
			}
			tx.FireCompletion();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionAbortedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.Aborted;
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			throw TransactionAbortedException.Create(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void CreateBlockingClone(InternalTransaction tx)
		{
			throw TransactionAbortedException.Create(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void CreateAbortingClone(InternalTransaction tx)
		{
			throw TransactionAbortedException.Create(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void RestartCommitIfNeeded(InternalTransaction tx)
		{
		}

		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void Phase1VolatilePrepareDone(InternalTransaction tx)
		{
		}

		internal override void ChangeStatePromotedPhase0(InternalTransaction tx)
		{
			throw new TransactionAbortedException(tx.innerException);
		}

		internal override void ChangeStatePromotedPhase1(InternalTransaction tx)
		{
			throw new TransactionAbortedException(tx.innerException);
		}

		internal override void ChangeStatePromotedAborted(InternalTransaction tx)
		{
		}

		internal override void ChangeStateTransactionAborted(InternalTransaction tx, Exception e)
		{
		}

		protected override void PromotedTransactionOutcome(InternalTransaction tx)
		{
			if (tx.innerException == null && tx.PromotedTransaction != null)
			{
				tx.innerException = tx.PromotedTransaction.InnerException;
			}
			throw TransactionAbortedException.Create(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void CheckForFinishedTransaction(InternalTransaction tx)
		{
			throw new TransactionAbortedException(tx.innerException);
		}

		internal override void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			throw TransactionAbortedException.Create(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void InDoubtFromDtc(InternalTransaction tx)
		{
		}

		internal override void InDoubtFromEnlistment(InternalTransaction tx)
		{
		}
	}
	internal class TransactionStatePromotedCommitted : TransactionStatePromotedEnded
	{
		internal override void EnterState(InternalTransaction tx)
		{
			base.EnterState(tx);
			if (tx.phase1Volatiles.VolatileDemux != null)
			{
				tx.phase1Volatiles.VolatileDemux.BroadcastCommitted(ref tx.phase1Volatiles);
			}
			if (tx.phase0Volatiles.VolatileDemux != null)
			{
				tx.phase0Volatiles.VolatileDemux.BroadcastCommitted(ref tx.phase0Volatiles);
			}
			tx.FireCompletion();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.TransactionCommittedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.Committed;
		}

		internal override void ChangeStatePromotedCommitted(InternalTransaction tx)
		{
		}

		protected override void PromotedTransactionOutcome(InternalTransaction tx)
		{
		}

		internal override void InDoubtFromDtc(InternalTransaction tx)
		{
		}

		internal override void InDoubtFromEnlistment(InternalTransaction tx)
		{
		}
	}
	internal class TransactionStatePromotedIndoubt : TransactionStatePromotedEnded
	{
		internal override void EnterState(InternalTransaction tx)
		{
			base.EnterState(tx);
			if (tx.phase1Volatiles.VolatileDemux != null)
			{
				tx.phase1Volatiles.VolatileDemux.BroadcastInDoubt(ref tx.phase1Volatiles);
			}
			if (tx.phase0Volatiles.VolatileDemux != null)
			{
				tx.phase0Volatiles.VolatileDemux.BroadcastInDoubt(ref tx.phase0Volatiles);
			}
			tx.FireCompletion();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionInDoubtTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId);
			}
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			return TransactionStatus.InDoubt;
		}

		internal override void RestartCommitIfNeeded(InternalTransaction tx)
		{
		}

		internal override void ChangeStatePromotedPhase0(InternalTransaction tx)
		{
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}

		internal override void ChangeStatePromotedPhase1(InternalTransaction tx)
		{
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}

		internal override void InDoubtFromDtc(InternalTransaction tx)
		{
		}

		internal override void InDoubtFromEnlistment(InternalTransaction tx)
		{
		}

		protected override void PromotedTransactionOutcome(InternalTransaction tx)
		{
			if (tx.innerException == null && tx.PromotedTransaction != null)
			{
				tx.innerException = tx.PromotedTransaction.InnerException;
			}
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}

		internal override void CheckForFinishedTransaction(InternalTransaction tx)
		{
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}

		internal override void GetObjectData(InternalTransaction tx, SerializationInfo serializationInfo, StreamingContext context)
		{
			throw TransactionInDoubtException.Create(SR.GetString("TraceSourceBase"), tx.innerException);
		}

		internal override void ChangeStatePromotedAborted(InternalTransaction tx)
		{
		}

		internal override void ChangeStatePromotedCommitted(InternalTransaction tx)
		{
		}
	}
	internal abstract class TransactionStateDelegatedBase : TransactionStatePromoted
	{
		internal override void EnterState(InternalTransaction tx)
		{
			if (tx.outcomeSource.isoLevel == IsolationLevel.Snapshot)
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("CannotPromoteSnapshot"), null);
			}
			CommonEnterState(tx);
			System.Transactions.Oletx.OletxTransaction oletxTransaction = null;
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose && tx.durableEnlistment != null)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.durableEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Promote);
				}
				oletxTransaction = TransactionState._TransactionStatePSPEOperation.PSPEPromote(tx);
			}
			catch (TransactionPromotionException innerException)
			{
				TransactionPromotionException exception = (TransactionPromotionException)(tx.innerException = innerException);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception);
				}
			}
			finally
			{
				if (oletxTransaction == null)
				{
					tx.State.ChangeStateAbortedDuringPromotion(tx);
				}
			}
			if (oletxTransaction != null)
			{
				tx.PromotedTransaction = oletxTransaction;
				Hashtable promotedTransactionTable = TransactionManager.PromotedTransactionTable;
				lock (promotedTransactionTable)
				{
					tx.finalizedObject = new FinalizedObject(tx, tx.PromotedTransaction.Identifier);
					WeakReference value = new WeakReference(tx.outcomeSource, trackResurrection: false);
					promotedTransactionTable[tx.PromotedTransaction.Identifier] = value;
				}
				TransactionManager.FireDistributedTransactionStarted(tx.outcomeSource);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
				{
					System.Transactions.Diagnostics.TransactionPromotedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.TransactionTraceId, oletxTransaction.TransactionTraceId);
				}
				PromoteEnlistmentsAndOutcome(tx);
			}
		}
	}
	internal class TransactionStateDelegated : TransactionStateDelegatedBase
	{
		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			tx.asyncCommit = asyncCommit;
			tx.asyncCallback = asyncCallback;
			tx.asyncState = asyncState;
			TransactionState._TransactionStateDelegatedCommitting.EnterState(tx);
		}

		internal override bool PromoteDurable(InternalTransaction tx)
		{
			tx.durableEnlistment.State.ChangeStateDelegated(tx.durableEnlistment);
			return true;
		}

		internal override void RestartCommitIfNeeded(InternalTransaction tx)
		{
			TransactionState._TransactionStateDelegatedP0Wave.EnterState(tx);
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			TransactionState._TransactionStateDelegatedAborting.EnterState(tx);
		}
	}
	internal class TransactionStateDelegatedSubordinate : TransactionStateDelegatedBase
	{
		internal override bool PromoteDurable(InternalTransaction tx)
		{
			return true;
		}

		internal override void Rollback(InternalTransaction tx, Exception e)
		{
			if (tx.innerException == null)
			{
				tx.innerException = e;
			}
			tx.PromotedTransaction.Rollback();
			TransactionState._TransactionStatePromotedAborted.EnterState(tx);
		}

		internal override void ChangeStatePromotedPhase0(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedPhase0.EnterState(tx);
		}

		internal override void ChangeStatePromotedPhase1(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedPhase1.EnterState(tx);
		}
	}
	internal class TransactionStatePSPEOperation : TransactionState
	{
		internal override void EnterState(InternalTransaction tx)
		{
			throw new InvalidOperationException();
		}

		internal override TransactionStatus get_Status(InternalTransaction tx)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal void PSPEInitialize(InternalTransaction tx, IPromotableSinglePhaseNotification promotableSinglePhaseNotification)
		{
			CommonEnterState(tx);
			try
			{
				promotableSinglePhaseNotification.Initialize();
			}
			finally
			{
				TransactionState._TransactionStateActive.CommonEnterState(tx);
			}
		}

		internal void Phase0PSPEInitialize(InternalTransaction tx, IPromotableSinglePhaseNotification promotableSinglePhaseNotification)
		{
			CommonEnterState(tx);
			try
			{
				promotableSinglePhaseNotification.Initialize();
			}
			finally
			{
				TransactionState._TransactionStatePhase0.CommonEnterState(tx);
			}
		}

		internal System.Transactions.Oletx.OletxTransaction PSPEPromote(InternalTransaction tx)
		{
			//Discarded unreachable code: IL_0060
			TransactionState state = tx.State;
			CommonEnterState(tx);
			System.Transactions.Oletx.OletxTransaction oletxTransaction = null;
			try
			{
				byte[] array = tx.promoter.Promote();
				if (array == null)
				{
					throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("PromotedReturnedInvalidValue"), null);
				}
				try
				{
					oletxTransaction = TransactionInterop.GetOletxTransactionFromTransmitterPropigationToken(array);
				}
				catch (ArgumentException innerException)
				{
					throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("PromotedReturnedInvalidValue"), innerException);
				}
				if (TransactionManager.FindPromotedTransaction(oletxTransaction.Identifier) != null)
				{
					oletxTransaction.Dispose();
					throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("PromotedTransactionExists"), null);
				}
				return oletxTransaction;
			}
			finally
			{
				state.CommonEnterState(tx);
			}
		}
	}
	internal class TransactionStateDelegatedP0Wave : TransactionStatePromotedP0Wave
	{
		internal override void Phase0VolatilePrepareDone(InternalTransaction tx)
		{
			TransactionState._TransactionStateDelegatedCommitting.EnterState(tx);
		}
	}
	internal class TransactionStateDelegatedCommitting : TransactionStatePromotedCommitting
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			Monitor.Exit(tx);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.durableEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.SinglePhaseCommit);
			}
			try
			{
				tx.durableEnlistment.PromotableSinglePhaseNotification.SinglePhaseCommit(tx.durableEnlistment.SinglePhaseEnlistment);
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}
	}
	internal class TransactionStateDelegatedAborting : TransactionStatePromotedAborted
	{
		internal override void EnterState(InternalTransaction tx)
		{
			CommonEnterState(tx);
			Monitor.Exit(tx);
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), tx.durableEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Rollback);
				}
				tx.durableEnlistment.PromotableSinglePhaseNotification.Rollback(tx.durableEnlistment.SinglePhaseEnlistment);
			}
			finally
			{
				Monitor.Enter(tx);
			}
		}

		internal override void BeginCommit(InternalTransaction tx, bool asyncCommit, AsyncCallback asyncCallback, object asyncState)
		{
			throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceLtm"), tx.innerException);
		}

		internal override void ChangeStatePromotedAborted(InternalTransaction tx)
		{
			TransactionState._TransactionStatePromotedAborted.EnterState(tx);
		}
	}
	internal interface IPromotedEnlistment
	{
		InternalEnlistment InternalEnlistment { get; set; }

		void EnlistmentDone();

		void Prepared();

		void ForceRollback();

		void ForceRollback(Exception e);

		void Committed();

		void Aborted();

		void Aborted(Exception e);

		void InDoubt();

		void InDoubt(Exception e);

		byte[] GetRecoveryInformation();
	}
	internal interface IEnlistmentNotificationInternal
	{
		void Prepare(IPromotedEnlistment preparingEnlistment);

		void Commit(IPromotedEnlistment enlistment);

		void Rollback(IPromotedEnlistment enlistment);

		void InDoubt(IPromotedEnlistment enlistment);
	}
	internal interface ISinglePhaseNotificationInternal : IEnlistmentNotificationInternal
	{
		void SinglePhaseCommit(IPromotedEnlistment singlePhaseEnlistment);
	}
	internal class InternalEnlistment : ISinglePhaseNotificationInternal, IEnlistmentNotificationInternal
	{
		internal EnlistmentState twoPhaseState;

		protected IEnlistmentNotification twoPhaseNotifications;

		protected ISinglePhaseNotification singlePhaseNotifications;

		protected InternalTransaction transaction;

		private Transaction atomicTransaction;

		private EnlistmentTraceIdentifier traceIdentifier;

		private int enlistmentId;

		private Enlistment enlistment;

		private PreparingEnlistment preparingEnlistment;

		private SinglePhaseEnlistment singlePhaseEnlistment;

		private IPromotedEnlistment promotedEnlistment;

		internal EnlistmentState State
		{
			get
			{
				return twoPhaseState;
			}
			set
			{
				twoPhaseState = value;
			}
		}

		internal Enlistment Enlistment => enlistment;

		internal PreparingEnlistment PreparingEnlistment
		{
			get
			{
				if (preparingEnlistment == null)
				{
					preparingEnlistment = new PreparingEnlistment(this);
				}
				return preparingEnlistment;
			}
		}

		internal SinglePhaseEnlistment SinglePhaseEnlistment
		{
			get
			{
				if (singlePhaseEnlistment == null)
				{
					singlePhaseEnlistment = new SinglePhaseEnlistment(this);
				}
				return singlePhaseEnlistment;
			}
		}

		internal InternalTransaction Transaction => transaction;

		internal virtual object SyncRoot => transaction;

		internal IEnlistmentNotification EnlistmentNotification => twoPhaseNotifications;

		internal ISinglePhaseNotification SinglePhaseNotification => singlePhaseNotifications;

		internal virtual IPromotableSinglePhaseNotification PromotableSinglePhaseNotification
		{
			get
			{
				throw new NotImplementedException();
			}
		}

		internal IPromotedEnlistment PromotedEnlistment
		{
			get
			{
				return promotedEnlistment;
			}
			set
			{
				promotedEnlistment = value;
			}
		}

		internal EnlistmentTraceIdentifier EnlistmentTraceId
		{
			get
			{
				if (traceIdentifier == EnlistmentTraceIdentifier.Empty)
				{
					lock (SyncRoot)
					{
						if (traceIdentifier == EnlistmentTraceIdentifier.Empty)
						{
							EnlistmentTraceIdentifier enlistmentTraceIdentifier = ((!(null != atomicTransaction)) ? new EnlistmentTraceIdentifier(Guid.Empty, new TransactionTraceIdentifier(InternalTransaction.InstanceIdentifier + Convert.ToString(Interlocked.Increment(ref InternalTransaction.nextHash), CultureInfo.InvariantCulture), 0), enlistmentId) : new EnlistmentTraceIdentifier(Guid.Empty, atomicTransaction.TransactionTraceId, enlistmentId));
							Thread.MemoryBarrier();
							traceIdentifier = enlistmentTraceIdentifier;
						}
					}
				}
				return traceIdentifier;
			}
		}

		internal virtual Guid ResourceManagerIdentifier
		{
			get
			{
				throw new NotImplementedException();
			}
		}

		protected InternalEnlistment(Enlistment enlistment, IEnlistmentNotification twoPhaseNotifications)
		{
			this.enlistment = enlistment;
			this.twoPhaseNotifications = twoPhaseNotifications;
			enlistmentId = 1;
			traceIdentifier = EnlistmentTraceIdentifier.Empty;
		}

		protected InternalEnlistment(Enlistment enlistment, InternalTransaction transaction, Transaction atomicTransaction)
		{
			this.enlistment = enlistment;
			this.transaction = transaction;
			this.atomicTransaction = atomicTransaction;
			enlistmentId = transaction.enlistmentCount++;
			traceIdentifier = EnlistmentTraceIdentifier.Empty;
		}

		internal InternalEnlistment(Enlistment enlistment, InternalTransaction transaction, IEnlistmentNotification twoPhaseNotifications, ISinglePhaseNotification singlePhaseNotifications, Transaction atomicTransaction)
		{
			this.enlistment = enlistment;
			this.transaction = transaction;
			this.twoPhaseNotifications = twoPhaseNotifications;
			this.singlePhaseNotifications = singlePhaseNotifications;
			this.atomicTransaction = atomicTransaction;
			enlistmentId = transaction.enlistmentCount++;
			traceIdentifier = EnlistmentTraceIdentifier.Empty;
		}

		internal InternalEnlistment(Enlistment enlistment, IEnlistmentNotification twoPhaseNotifications, InternalTransaction transaction, Transaction atomicTransaction)
		{
			this.enlistment = enlistment;
			this.twoPhaseNotifications = twoPhaseNotifications;
			this.transaction = transaction;
			this.atomicTransaction = atomicTransaction;
		}

		internal virtual void FinishEnlistment()
		{
			Transaction.phase0Volatiles.preparedVolatileEnlistments++;
			CheckComplete();
		}

		internal virtual void CheckComplete()
		{
			if (Transaction.phase0Volatiles.preparedVolatileEnlistments == Transaction.phase0VolatileWaveCount + Transaction.phase0Volatiles.dependentClones)
			{
				Transaction.State.Phase0VolatilePrepareDone(Transaction);
			}
		}

		void ISinglePhaseNotificationInternal.SinglePhaseCommit(IPromotedEnlistment singlePhaseEnlistment)
		{
			bool flag = false;
			promotedEnlistment = singlePhaseEnlistment;
			try
			{
				singlePhaseNotifications.SinglePhaseCommit(SinglePhaseEnlistment);
				flag = true;
			}
			finally
			{
				if (!flag)
				{
					SinglePhaseEnlistment.InDoubt();
				}
			}
		}

		void IEnlistmentNotificationInternal.Prepare(IPromotedEnlistment preparingEnlistment)
		{
			promotedEnlistment = preparingEnlistment;
			twoPhaseNotifications.Prepare(PreparingEnlistment);
		}

		void IEnlistmentNotificationInternal.Commit(IPromotedEnlistment enlistment)
		{
			promotedEnlistment = enlistment;
			twoPhaseNotifications.Commit(Enlistment);
		}

		void IEnlistmentNotificationInternal.Rollback(IPromotedEnlistment enlistment)
		{
			promotedEnlistment = enlistment;
			twoPhaseNotifications.Rollback(Enlistment);
		}

		void IEnlistmentNotificationInternal.InDoubt(IPromotedEnlistment enlistment)
		{
			promotedEnlistment = enlistment;
			twoPhaseNotifications.InDoubt(Enlistment);
		}
	}
	internal class DurableInternalEnlistment : InternalEnlistment
	{
		internal Guid resourceManagerIdentifier;

		internal override Guid ResourceManagerIdentifier => resourceManagerIdentifier;

		internal DurableInternalEnlistment(Enlistment enlistment, Guid resourceManagerIdentifier, InternalTransaction transaction, IEnlistmentNotification twoPhaseNotifications, ISinglePhaseNotification singlePhaseNotifications, Transaction atomicTransaction)
			: base(enlistment, transaction, twoPhaseNotifications, singlePhaseNotifications, atomicTransaction)
		{
			this.resourceManagerIdentifier = resourceManagerIdentifier;
		}

		protected DurableInternalEnlistment(Enlistment enlistment, IEnlistmentNotification twoPhaseNotifications)
			: base(enlistment, twoPhaseNotifications)
		{
		}
	}
	internal class RecoveringInternalEnlistment : DurableInternalEnlistment
	{
		private object syncRoot;

		internal override object SyncRoot => syncRoot;

		internal RecoveringInternalEnlistment(Enlistment enlistment, IEnlistmentNotification twoPhaseNotifications, object syncRoot)
			: base(enlistment, twoPhaseNotifications)
		{
			this.syncRoot = syncRoot;
		}
	}
	internal class PromotableInternalEnlistment : InternalEnlistment
	{
		private IPromotableSinglePhaseNotification promotableNotificationInterface;

		internal override IPromotableSinglePhaseNotification PromotableSinglePhaseNotification => promotableNotificationInterface;

		internal PromotableInternalEnlistment(Enlistment enlistment, InternalTransaction transaction, IPromotableSinglePhaseNotification promotableSinglePhaseNotification, Transaction atomicTransaction)
			: base(enlistment, transaction, atomicTransaction)
		{
			promotableNotificationInterface = promotableSinglePhaseNotification;
		}
	}
	internal class Phase1VolatileEnlistment : InternalEnlistment
	{
		public Phase1VolatileEnlistment(Enlistment enlistment, InternalTransaction transaction, IEnlistmentNotification twoPhaseNotifications, ISinglePhaseNotification singlePhaseNotifications, Transaction atomicTransaction)
			: base(enlistment, transaction, twoPhaseNotifications, singlePhaseNotifications, atomicTransaction)
		{
		}

		internal override void FinishEnlistment()
		{
			transaction.phase1Volatiles.preparedVolatileEnlistments++;
			CheckComplete();
		}

		internal override void CheckComplete()
		{
			if (transaction.phase1Volatiles.preparedVolatileEnlistments == transaction.phase1Volatiles.volatileEnlistmentCount + transaction.phase1Volatiles.dependentClones)
			{
				transaction.State.Phase1VolatilePrepareDone(transaction);
			}
		}
	}
	public class Enlistment
	{
		internal InternalEnlistment internalEnlistment;

		internal InternalEnlistment InternalEnlistment => internalEnlistment;

		internal Enlistment(InternalEnlistment internalEnlistment)
		{
			this.internalEnlistment = internalEnlistment;
		}

		internal Enlistment(Guid resourceManagerIdentifier, InternalTransaction transaction, IEnlistmentNotification twoPhaseNotifications, ISinglePhaseNotification singlePhaseNotifications, Transaction atomicTransaction)
		{
			internalEnlistment = new DurableInternalEnlistment(this, resourceManagerIdentifier, transaction, twoPhaseNotifications, singlePhaseNotifications, atomicTransaction);
		}

		internal Enlistment(InternalTransaction transaction, IEnlistmentNotification twoPhaseNotifications, ISinglePhaseNotification singlePhaseNotifications, Transaction atomicTransaction, EnlistmentOptions enlistmentOptions)
		{
			if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
			{
				internalEnlistment = new InternalEnlistment(this, transaction, twoPhaseNotifications, singlePhaseNotifications, atomicTransaction);
			}
			else
			{
				internalEnlistment = new Phase1VolatileEnlistment(this, transaction, twoPhaseNotifications, singlePhaseNotifications, atomicTransaction);
			}
		}

		internal Enlistment(InternalTransaction transaction, IPromotableSinglePhaseNotification promotableSinglePhaseNotification, Transaction atomicTransaction)
		{
			internalEnlistment = new PromotableInternalEnlistment(this, transaction, promotableSinglePhaseNotification, atomicTransaction);
		}

		internal Enlistment(IEnlistmentNotification twoPhaseNotifications, InternalTransaction transaction, Transaction atomicTransaction)
		{
			internalEnlistment = new InternalEnlistment(this, twoPhaseNotifications, transaction, atomicTransaction);
		}

		internal Enlistment(IEnlistmentNotification twoPhaseNotifications, object syncRoot)
		{
			internalEnlistment = new RecoveringInternalEnlistment(this, twoPhaseNotifications, syncRoot);
		}

		public void Done()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Enlistment.Done");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.Done);
			}
			lock (internalEnlistment.SyncRoot)
			{
				internalEnlistment.State.EnlistmentDone(internalEnlistment);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "Enlistment.Done");
			}
		}
	}
	public class PreparingEnlistment : Enlistment
	{
		internal PreparingEnlistment(InternalEnlistment enlistment)
			: base(enlistment)
		{
		}

		public void Prepared()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.Prepared");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.Prepared);
			}
			lock (internalEnlistment.SyncRoot)
			{
				internalEnlistment.State.Prepared(internalEnlistment);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.Prepared");
			}
		}

		public void ForceRollback()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.ForceRollback");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.ForceRollback);
			}
			lock (internalEnlistment.SyncRoot)
			{
				internalEnlistment.State.ForceRollback(internalEnlistment, null);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.ForceRollback");
			}
		}

		public void ForceRollback(Exception e)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.ForceRollback");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.ForceRollback);
			}
			lock (internalEnlistment.SyncRoot)
			{
				internalEnlistment.State.ForceRollback(internalEnlistment, e);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.ForceRollback");
			}
		}

		public byte[] RecoveryInformation()
		{
			//Discarded unreachable code: IL_004e
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.RecoveryInformation");
			}
			try
			{
				lock (internalEnlistment.SyncRoot)
				{
					return internalEnlistment.State.RecoveryInformation(internalEnlistment);
				}
			}
			finally
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "PreparingEnlistment.RecoveryInformation");
				}
			}
		}
	}
	public class SinglePhaseEnlistment : Enlistment
	{
		internal SinglePhaseEnlistment(InternalEnlistment enlistment)
			: base(enlistment)
		{
		}

		public void Aborted()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.Aborted");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.Aborted);
			}
			lock (internalEnlistment.SyncRoot)
			{
				internalEnlistment.State.Aborted(internalEnlistment, null);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.Aborted");
			}
		}

		public void Aborted(Exception e)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.Aborted");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.Aborted);
			}
			lock (internalEnlistment.SyncRoot)
			{
				internalEnlistment.State.Aborted(internalEnlistment, e);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.Aborted");
			}
		}

		public void Committed()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.Committed");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.Committed);
			}
			lock (internalEnlistment.SyncRoot)
			{
				internalEnlistment.State.Committed(internalEnlistment);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.Committed");
			}
		}

		public void InDoubt()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.InDoubt");
			}
			lock (internalEnlistment.SyncRoot)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
				{
					System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.InDoubt);
				}
				internalEnlistment.State.InDoubt(internalEnlistment, null);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.InDoubt");
			}
		}

		public void InDoubt(Exception e)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.InDoubt");
			}
			lock (internalEnlistment.SyncRoot)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
				{
					System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceLtm"), internalEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.EnlistmentCallback.InDoubt);
				}
				internalEnlistment.State.InDoubt(internalEnlistment, e);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), "SinglePhaseEnlistment.InDoubt");
			}
		}
	}
	internal struct EnlistmentTraceIdentifier
	{
		public static readonly EnlistmentTraceIdentifier Empty = default(EnlistmentTraceIdentifier);

		private Guid resourceManagerIdentifier;

		private TransactionTraceIdentifier transactionTraceIdentifier;

		private int enlistmentIdentifier;

		public Guid ResourceManagerIdentifier => resourceManagerIdentifier;

		public TransactionTraceIdentifier TransactionTraceId => transactionTraceIdentifier;

		public int EnlistmentIdentifier => enlistmentIdentifier;

		public EnlistmentTraceIdentifier(Guid resourceManagerIdentifier, TransactionTraceIdentifier transactionTraceId, int enlistmentIdentifier)
		{
			this.resourceManagerIdentifier = resourceManagerIdentifier;
			transactionTraceIdentifier = transactionTraceId;
			this.enlistmentIdentifier = enlistmentIdentifier;
		}

		public override int GetHashCode()
		{
			return base.GetHashCode();
		}

		public override bool Equals(object objectToCompare)
		{
			if (!(objectToCompare is EnlistmentTraceIdentifier enlistmentTraceIdentifier))
			{
				return false;
			}
			if (enlistmentTraceIdentifier.ResourceManagerIdentifier != ResourceManagerIdentifier || enlistmentTraceIdentifier.TransactionTraceId != TransactionTraceId || enlistmentTraceIdentifier.EnlistmentIdentifier != EnlistmentIdentifier)
			{
				return false;
			}
			return true;
		}

		public static bool operator ==(EnlistmentTraceIdentifier id1, EnlistmentTraceIdentifier id2)
		{
			return id1.Equals(id2);
		}

		public static bool operator !=(EnlistmentTraceIdentifier id1, EnlistmentTraceIdentifier id2)
		{
			return !id1.Equals(id2);
		}
	}
	internal abstract class EnlistmentState
	{
		internal static EnlistmentStatePromoted _enlistmentStatePromoted;

		private static object classSyncObject;

		private static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}

		internal static EnlistmentStatePromoted _EnlistmentStatePromoted
		{
			get
			{
				if (_enlistmentStatePromoted == null)
				{
					lock (ClassSyncObject)
					{
						if (_enlistmentStatePromoted == null)
						{
							EnlistmentStatePromoted enlistmentStatePromoted = new EnlistmentStatePromoted();
							Thread.MemoryBarrier();
							_enlistmentStatePromoted = enlistmentStatePromoted;
						}
					}
				}
				return _enlistmentStatePromoted;
			}
		}

		internal abstract void EnterState(InternalEnlistment enlistment);

		internal virtual void EnlistmentDone(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void Prepared(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void ForceRollback(InternalEnlistment enlistment, Exception e)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void Committed(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void Aborted(InternalEnlistment enlistment, Exception e)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void InDoubt(InternalEnlistment enlistment, Exception e)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual byte[] RecoveryInformation(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void InternalAborted(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void InternalCommitted(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void InternalIndoubt(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void ChangeStateCommitting(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void ChangeStatePromoted(InternalEnlistment enlistment, IPromotedEnlistment promotedEnlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void ChangeStateDelegated(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void ChangeStatePreparing(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}

		internal virtual void ChangeStateSinglePhaseCommit(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceLtm"), null);
		}
	}
	internal class EnlistmentStatePromoted : EnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			Monitor.Exit(enlistment.SyncRoot);
			try
			{
				enlistment.PromotedEnlistment.EnlistmentDone();
			}
			finally
			{
				Monitor.Enter(enlistment.SyncRoot);
			}
		}

		internal override void Prepared(InternalEnlistment enlistment)
		{
			Monitor.Exit(enlistment.SyncRoot);
			try
			{
				enlistment.PromotedEnlistment.Prepared();
			}
			finally
			{
				Monitor.Enter(enlistment.SyncRoot);
			}
		}

		internal override void ForceRollback(InternalEnlistment enlistment, Exception e)
		{
			Monitor.Exit(enlistment.SyncRoot);
			try
			{
				enlistment.PromotedEnlistment.ForceRollback(e);
			}
			finally
			{
				Monitor.Enter(enlistment.SyncRoot);
			}
		}

		internal override void Committed(InternalEnlistment enlistment)
		{
			Monitor.Exit(enlistment.SyncRoot);
			try
			{
				enlistment.PromotedEnlistment.Committed();
			}
			finally
			{
				Monitor.Enter(enlistment.SyncRoot);
			}
		}

		internal override void Aborted(InternalEnlistment enlistment, Exception e)
		{
			Monitor.Exit(enlistment.SyncRoot);
			try
			{
				enlistment.PromotedEnlistment.Aborted(e);
			}
			finally
			{
				Monitor.Enter(enlistment.SyncRoot);
			}
		}

		internal override void InDoubt(InternalEnlistment enlistment, Exception e)
		{
			Monitor.Exit(enlistment.SyncRoot);
			try
			{
				enlistment.PromotedEnlistment.InDoubt(e);
			}
			finally
			{
				Monitor.Enter(enlistment.SyncRoot);
			}
		}

		internal override byte[] RecoveryInformation(InternalEnlistment enlistment)
		{
			Monitor.Exit(enlistment.SyncRoot);
			try
			{
				return enlistment.PromotedEnlistment.GetRecoveryInformation();
			}
			finally
			{
				Monitor.Enter(enlistment.SyncRoot);
			}
		}
	}
	internal abstract class DurableEnlistmentState : EnlistmentState
	{
		private static DurableEnlistmentActive _durableEnlistmentActive;

		private static DurableEnlistmentAborting _durableEnlistmentAborting;

		private static DurableEnlistmentCommitting _durableEnlistmentCommitting;

		private static DurableEnlistmentDelegated _durableEnlistmentDelegated;

		private static DurableEnlistmentEnded _durableEnlistmentEnded;

		private static object classSyncObject;

		internal static DurableEnlistmentActive _DurableEnlistmentActive
		{
			get
			{
				if (_durableEnlistmentActive == null)
				{
					lock (ClassSyncObject)
					{
						if (_durableEnlistmentActive == null)
						{
							DurableEnlistmentActive durableEnlistmentActive = new DurableEnlistmentActive();
							Thread.MemoryBarrier();
							_durableEnlistmentActive = durableEnlistmentActive;
						}
					}
				}
				return _durableEnlistmentActive;
			}
		}

		protected static DurableEnlistmentAborting _DurableEnlistmentAborting
		{
			get
			{
				if (_durableEnlistmentAborting == null)
				{
					lock (ClassSyncObject)
					{
						if (_durableEnlistmentAborting == null)
						{
							DurableEnlistmentAborting durableEnlistmentAborting = new DurableEnlistmentAborting();
							Thread.MemoryBarrier();
							_durableEnlistmentAborting = durableEnlistmentAborting;
						}
					}
				}
				return _durableEnlistmentAborting;
			}
		}

		protected static DurableEnlistmentCommitting _DurableEnlistmentCommitting
		{
			get
			{
				if (_durableEnlistmentCommitting == null)
				{
					lock (ClassSyncObject)
					{
						if (_durableEnlistmentCommitting == null)
						{
							DurableEnlistmentCommitting durableEnlistmentCommitting = new DurableEnlistmentCommitting();
							Thread.MemoryBarrier();
							_durableEnlistmentCommitting = durableEnlistmentCommitting;
						}
					}
				}
				return _durableEnlistmentCommitting;
			}
		}

		protected static DurableEnlistmentDelegated _DurableEnlistmentDelegated
		{
			get
			{
				if (_durableEnlistmentDelegated == null)
				{
					lock (ClassSyncObject)
					{
						if (_durableEnlistmentDelegated == null)
						{
							DurableEnlistmentDelegated durableEnlistmentDelegated = new DurableEnlistmentDelegated();
							Thread.MemoryBarrier();
							_durableEnlistmentDelegated = durableEnlistmentDelegated;
						}
					}
				}
				return _durableEnlistmentDelegated;
			}
		}

		protected static DurableEnlistmentEnded _DurableEnlistmentEnded
		{
			get
			{
				if (_durableEnlistmentEnded == null)
				{
					lock (ClassSyncObject)
					{
						if (_durableEnlistmentEnded == null)
						{
							DurableEnlistmentEnded durableEnlistmentEnded = new DurableEnlistmentEnded();
							Thread.MemoryBarrier();
							_durableEnlistmentEnded = durableEnlistmentEnded;
						}
					}
				}
				return _durableEnlistmentEnded;
			}
		}

		private static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}
	}
	internal class DurableEnlistmentActive : DurableEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentAborting.EnterState(enlistment);
		}

		internal override void ChangeStateCommitting(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentCommitting.EnterState(enlistment);
		}

		internal override void ChangeStatePromoted(InternalEnlistment enlistment, IPromotedEnlistment promotedEnlistment)
		{
			enlistment.PromotedEnlistment = promotedEnlistment;
			EnlistmentState._EnlistmentStatePromoted.EnterState(enlistment);
		}

		internal override void ChangeStateDelegated(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentDelegated.EnterState(enlistment);
		}
	}
	internal class DurableEnlistmentAborting : DurableEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
			Monitor.Exit(enlistment.Transaction);
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Rollback);
				}
				if (enlistment.SinglePhaseNotification != null)
				{
					enlistment.SinglePhaseNotification.Rollback(enlistment.SinglePhaseEnlistment);
				}
				else
				{
					enlistment.PromotableSinglePhaseNotification.Rollback(enlistment.SinglePhaseEnlistment);
				}
			}
			finally
			{
				Monitor.Enter(enlistment.Transaction);
			}
		}

		internal override void Aborted(InternalEnlistment enlistment, Exception e)
		{
			if (enlistment.Transaction.innerException == null)
			{
				enlistment.Transaction.innerException = e;
			}
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
		}
	}
	internal class DurableEnlistmentCommitting : DurableEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			bool flag = false;
			enlistment.State = this;
			Monitor.Exit(enlistment.Transaction);
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.SinglePhaseCommit);
				}
				if (enlistment.SinglePhaseNotification != null)
				{
					enlistment.SinglePhaseNotification.SinglePhaseCommit(enlistment.SinglePhaseEnlistment);
				}
				else
				{
					enlistment.PromotableSinglePhaseNotification.SinglePhaseCommit(enlistment.SinglePhaseEnlistment);
				}
				flag = true;
			}
			finally
			{
				if (!flag)
				{
					enlistment.SinglePhaseEnlistment.InDoubt();
				}
				Monitor.Enter(enlistment.Transaction);
			}
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStateTransactionCommitted(enlistment.Transaction);
		}

		internal override void Committed(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStateTransactionCommitted(enlistment.Transaction);
		}

		internal override void Aborted(InternalEnlistment enlistment, Exception e)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStateTransactionAborted(enlistment.Transaction, e);
		}

		internal override void InDoubt(InternalEnlistment enlistment, Exception e)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
			if (enlistment.Transaction.innerException == null)
			{
				enlistment.Transaction.innerException = e;
			}
			enlistment.Transaction.State.InDoubtFromEnlistment(enlistment.Transaction);
		}
	}
	internal class DurableEnlistmentDelegated : DurableEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void Committed(InternalEnlistment enlistment)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStatePromotedCommitted(enlistment.Transaction);
		}

		internal override void Aborted(InternalEnlistment enlistment, Exception e)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
			if (enlistment.Transaction.innerException == null)
			{
				enlistment.Transaction.innerException = e;
			}
			enlistment.Transaction.State.ChangeStatePromotedAborted(enlistment.Transaction);
		}

		internal override void InDoubt(InternalEnlistment enlistment, Exception e)
		{
			DurableEnlistmentState._DurableEnlistmentEnded.EnterState(enlistment);
			if (enlistment.Transaction.innerException == null)
			{
				enlistment.Transaction.innerException = e;
			}
			enlistment.Transaction.State.InDoubtFromEnlistment(enlistment.Transaction);
		}
	}
	internal class DurableEnlistmentEnded : DurableEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
		}

		internal override void InDoubt(InternalEnlistment enlistment, Exception e)
		{
		}
	}
	internal abstract class VolatileEnlistmentState : EnlistmentState
	{
		private static VolatileEnlistmentActive _volatileEnlistmentActive;

		private static VolatileEnlistmentPreparing _volatileEnlistmentPreparing;

		private static VolatileEnlistmentPrepared _volatileEnlistmentPrepared;

		private static VolatileEnlistmentSPC _volatileEnlistmentSPC;

		private static VolatileEnlistmentPreparingAborting _volatileEnlistmentPreparingAborting;

		private static VolatileEnlistmentAborting _volatileEnlistmentAborting;

		private static VolatileEnlistmentCommitting _volatileEnlistmentCommitting;

		private static VolatileEnlistmentInDoubt _volatileEnlistmentInDoubt;

		private static VolatileEnlistmentEnded _volatileEnlistmentEnded;

		private static VolatileEnlistmentDone _volatileEnlistmentDone;

		private static object classSyncObject;

		internal static VolatileEnlistmentActive _VolatileEnlistmentActive
		{
			get
			{
				if (_volatileEnlistmentActive == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentActive == null)
						{
							VolatileEnlistmentActive volatileEnlistmentActive = new VolatileEnlistmentActive();
							Thread.MemoryBarrier();
							_volatileEnlistmentActive = volatileEnlistmentActive;
						}
					}
				}
				return _volatileEnlistmentActive;
			}
		}

		protected static VolatileEnlistmentPreparing _VolatileEnlistmentPreparing
		{
			get
			{
				if (_volatileEnlistmentPreparing == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentPreparing == null)
						{
							VolatileEnlistmentPreparing volatileEnlistmentPreparing = new VolatileEnlistmentPreparing();
							Thread.MemoryBarrier();
							_volatileEnlistmentPreparing = volatileEnlistmentPreparing;
						}
					}
				}
				return _volatileEnlistmentPreparing;
			}
		}

		protected static VolatileEnlistmentPrepared _VolatileEnlistmentPrepared
		{
			get
			{
				if (_volatileEnlistmentPrepared == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentPrepared == null)
						{
							VolatileEnlistmentPrepared volatileEnlistmentPrepared = new VolatileEnlistmentPrepared();
							Thread.MemoryBarrier();
							_volatileEnlistmentPrepared = volatileEnlistmentPrepared;
						}
					}
				}
				return _volatileEnlistmentPrepared;
			}
		}

		protected static VolatileEnlistmentSPC _VolatileEnlistmentSPC
		{
			get
			{
				if (_volatileEnlistmentSPC == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentSPC == null)
						{
							VolatileEnlistmentSPC volatileEnlistmentSPC = new VolatileEnlistmentSPC();
							Thread.MemoryBarrier();
							_volatileEnlistmentSPC = volatileEnlistmentSPC;
						}
					}
				}
				return _volatileEnlistmentSPC;
			}
		}

		protected static VolatileEnlistmentPreparingAborting _VolatileEnlistmentPreparingAborting
		{
			get
			{
				if (_volatileEnlistmentPreparingAborting == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentPreparingAborting == null)
						{
							VolatileEnlistmentPreparingAborting volatileEnlistmentPreparingAborting = new VolatileEnlistmentPreparingAborting();
							Thread.MemoryBarrier();
							_volatileEnlistmentPreparingAborting = volatileEnlistmentPreparingAborting;
						}
					}
				}
				return _volatileEnlistmentPreparingAborting;
			}
		}

		protected static VolatileEnlistmentAborting _VolatileEnlistmentAborting
		{
			get
			{
				if (_volatileEnlistmentAborting == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentAborting == null)
						{
							VolatileEnlistmentAborting volatileEnlistmentAborting = new VolatileEnlistmentAborting();
							Thread.MemoryBarrier();
							_volatileEnlistmentAborting = volatileEnlistmentAborting;
						}
					}
				}
				return _volatileEnlistmentAborting;
			}
		}

		protected static VolatileEnlistmentCommitting _VolatileEnlistmentCommitting
		{
			get
			{
				if (_volatileEnlistmentCommitting == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentCommitting == null)
						{
							VolatileEnlistmentCommitting volatileEnlistmentCommitting = new VolatileEnlistmentCommitting();
							Thread.MemoryBarrier();
							_volatileEnlistmentCommitting = volatileEnlistmentCommitting;
						}
					}
				}
				return _volatileEnlistmentCommitting;
			}
		}

		protected static VolatileEnlistmentInDoubt _VolatileEnlistmentInDoubt
		{
			get
			{
				if (_volatileEnlistmentInDoubt == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentInDoubt == null)
						{
							VolatileEnlistmentInDoubt volatileEnlistmentInDoubt = new VolatileEnlistmentInDoubt();
							Thread.MemoryBarrier();
							_volatileEnlistmentInDoubt = volatileEnlistmentInDoubt;
						}
					}
				}
				return _volatileEnlistmentInDoubt;
			}
		}

		protected static VolatileEnlistmentEnded _VolatileEnlistmentEnded
		{
			get
			{
				if (_volatileEnlistmentEnded == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentEnded == null)
						{
							VolatileEnlistmentEnded volatileEnlistmentEnded = new VolatileEnlistmentEnded();
							Thread.MemoryBarrier();
							_volatileEnlistmentEnded = volatileEnlistmentEnded;
						}
					}
				}
				return _volatileEnlistmentEnded;
			}
		}

		protected static VolatileEnlistmentDone _VolatileEnlistmentDone
		{
			get
			{
				if (_volatileEnlistmentDone == null)
				{
					lock (ClassSyncObject)
					{
						if (_volatileEnlistmentDone == null)
						{
							VolatileEnlistmentDone volatileEnlistmentDone = new VolatileEnlistmentDone();
							Thread.MemoryBarrier();
							_volatileEnlistmentDone = volatileEnlistmentDone;
						}
					}
				}
				return _volatileEnlistmentDone;
			}
		}

		private static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}

		internal override byte[] RecoveryInformation(InternalEnlistment enlistment)
		{
			throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("VolEnlistNoRecoveryInfo"), null);
		}
	}
	internal class VolatileEnlistmentActive : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentDone.EnterState(enlistment);
			enlistment.FinishEnlistment();
		}

		internal override void ChangeStatePreparing(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentPreparing.EnterState(enlistment);
		}

		internal override void ChangeStateSinglePhaseCommit(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentSPC.EnterState(enlistment);
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentAborting.EnterState(enlistment);
		}
	}
	internal class VolatileEnlistmentPreparing : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
			Monitor.Exit(enlistment.Transaction);
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Prepare);
				}
				enlistment.EnlistmentNotification.Prepare(enlistment.PreparingEnlistment);
			}
			finally
			{
				Monitor.Enter(enlistment.Transaction);
			}
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentDone.EnterState(enlistment);
			enlistment.FinishEnlistment();
		}

		internal override void Prepared(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentPrepared.EnterState(enlistment);
			enlistment.FinishEnlistment();
		}

		internal override void ForceRollback(InternalEnlistment enlistment, Exception e)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStateTransactionAborted(enlistment.Transaction, e);
			enlistment.FinishEnlistment();
		}

		internal override void ChangeStatePreparing(InternalEnlistment enlistment)
		{
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentPreparingAborting.EnterState(enlistment);
		}
	}
	internal class VolatileEnlistmentSPC : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			bool flag = false;
			enlistment.State = this;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.SinglePhaseCommit);
			}
			Monitor.Exit(enlistment.Transaction);
			try
			{
				enlistment.SinglePhaseNotification.SinglePhaseCommit(enlistment.SinglePhaseEnlistment);
				flag = true;
			}
			finally
			{
				if (!flag)
				{
					enlistment.SinglePhaseEnlistment.InDoubt();
				}
				Monitor.Enter(enlistment.Transaction);
			}
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStateTransactionCommitted(enlistment.Transaction);
		}

		internal override void Committed(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStateTransactionCommitted(enlistment.Transaction);
		}

		internal override void Aborted(InternalEnlistment enlistment, Exception e)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
			enlistment.Transaction.State.ChangeStateTransactionAborted(enlistment.Transaction, e);
		}

		internal override void InDoubt(InternalEnlistment enlistment, Exception e)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
			if (enlistment.Transaction.innerException == null)
			{
				enlistment.Transaction.innerException = e;
			}
			enlistment.Transaction.State.InDoubtFromEnlistment(enlistment.Transaction);
		}
	}
	internal class VolatileEnlistmentPrepared : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentAborting.EnterState(enlistment);
		}

		internal override void InternalCommitted(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentCommitting.EnterState(enlistment);
		}

		internal override void InternalIndoubt(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentInDoubt.EnterState(enlistment);
		}

		internal override void ChangeStatePreparing(InternalEnlistment enlistment)
		{
		}
	}
	internal class VolatileEnlistmentPreparingAborting : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
		}

		internal override void Prepared(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentAborting.EnterState(enlistment);
			enlistment.FinishEnlistment();
		}

		internal override void ForceRollback(InternalEnlistment enlistment, Exception e)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
			if (enlistment.Transaction.innerException == null)
			{
				enlistment.Transaction.innerException = e;
			}
			enlistment.FinishEnlistment();
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
		}
	}
	internal class VolatileEnlistmentAborting : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
			Monitor.Exit(enlistment.Transaction);
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Rollback);
				}
				enlistment.EnlistmentNotification.Rollback(enlistment.SinglePhaseEnlistment);
			}
			finally
			{
				Monitor.Enter(enlistment.Transaction);
			}
		}

		internal override void ChangeStatePreparing(InternalEnlistment enlistment)
		{
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
		}
	}
	internal class VolatileEnlistmentCommitting : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
			Monitor.Exit(enlistment.Transaction);
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Commit);
				}
				enlistment.EnlistmentNotification.Commit(enlistment.Enlistment);
			}
			finally
			{
				Monitor.Enter(enlistment.Transaction);
			}
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
		}
	}
	internal class VolatileEnlistmentInDoubt : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
			Monitor.Exit(enlistment.Transaction);
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceLtm"), enlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.InDoubt);
				}
				enlistment.EnlistmentNotification.InDoubt(enlistment.PreparingEnlistment);
			}
			finally
			{
				Monitor.Enter(enlistment.Transaction);
			}
		}

		internal override void EnlistmentDone(InternalEnlistment enlistment)
		{
			VolatileEnlistmentState._VolatileEnlistmentEnded.EnterState(enlistment);
		}
	}
	internal class VolatileEnlistmentEnded : VolatileEnlistmentState
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void ChangeStatePreparing(InternalEnlistment enlistment)
		{
		}

		internal override void InternalAborted(InternalEnlistment enlistment)
		{
		}

		internal override void InternalCommitted(InternalEnlistment enlistment)
		{
		}

		internal override void InternalIndoubt(InternalEnlistment enlistment)
		{
		}

		internal override void InDoubt(InternalEnlistment enlistment, Exception e)
		{
		}
	}
	internal class VolatileEnlistmentDone : VolatileEnlistmentEnded
	{
		internal override void EnterState(InternalEnlistment enlistment)
		{
			enlistment.State = this;
		}

		internal override void ChangeStatePreparing(InternalEnlistment enlistment)
		{
			enlistment.CheckComplete();
		}
	}
	internal abstract class VolatileDemultiplexer : IEnlistmentNotificationInternal
	{
		protected InternalTransaction transaction;

		internal IPromotedEnlistment oletxEnlistment;

		internal IPromotedEnlistment preparingEnlistment;

		private static object classSyncObject;

		private static WaitCallback prepareCallback;

		private static WaitCallback commitCallback;

		private static WaitCallback rollbackCallback;

		private static WaitCallback inDoubtCallback;

		internal static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}

		private static WaitCallback PrepareCallback
		{
			get
			{
				if (prepareCallback == null)
				{
					lock (ClassSyncObject)
					{
						if (prepareCallback == null)
						{
							WaitCallback waitCallback = PoolablePrepare;
							Thread.MemoryBarrier();
							prepareCallback = waitCallback;
						}
					}
				}
				return prepareCallback;
			}
		}

		private static WaitCallback CommitCallback
		{
			get
			{
				if (commitCallback == null)
				{
					lock (ClassSyncObject)
					{
						if (commitCallback == null)
						{
							WaitCallback waitCallback = PoolableCommit;
							Thread.MemoryBarrier();
							commitCallback = waitCallback;
						}
					}
				}
				return commitCallback;
			}
		}

		private static WaitCallback RollbackCallback
		{
			get
			{
				if (rollbackCallback == null)
				{
					lock (ClassSyncObject)
					{
						if (rollbackCallback == null)
						{
							WaitCallback waitCallback = PoolableRollback;
							Thread.MemoryBarrier();
							rollbackCallback = waitCallback;
						}
					}
				}
				return rollbackCallback;
			}
		}

		private static WaitCallback InDoubtCallback
		{
			get
			{
				if (inDoubtCallback == null)
				{
					lock (ClassSyncObject)
					{
						if (inDoubtCallback == null)
						{
							WaitCallback waitCallback = PoolableInDoubt;
							Thread.MemoryBarrier();
							inDoubtCallback = waitCallback;
						}
					}
				}
				return inDoubtCallback;
			}
		}

		public VolatileDemultiplexer(InternalTransaction transaction)
		{
			this.transaction = transaction;
		}

		internal void BroadcastCommitted(ref VolatileEnlistmentSet volatiles)
		{
			for (int i = 0; i < volatiles.volatileEnlistmentCount; i++)
			{
				volatiles.volatileEnlistments[i].twoPhaseState.InternalCommitted(volatiles.volatileEnlistments[i]);
			}
		}

		internal void BroadcastRollback(ref VolatileEnlistmentSet volatiles)
		{
			for (int i = 0; i < volatiles.volatileEnlistmentCount; i++)
			{
				volatiles.volatileEnlistments[i].twoPhaseState.InternalAborted(volatiles.volatileEnlistments[i]);
			}
		}

		internal void BroadcastInDoubt(ref VolatileEnlistmentSet volatiles)
		{
			for (int i = 0; i < volatiles.volatileEnlistmentCount; i++)
			{
				volatiles.volatileEnlistments[i].twoPhaseState.InternalIndoubt(volatiles.volatileEnlistments[i]);
			}
		}

		protected static void PoolablePrepare(object state)
		{
			VolatileDemultiplexer volatileDemultiplexer = (VolatileDemultiplexer)state;
			if (Monitor.TryEnter(volatileDemultiplexer.transaction, 250))
			{
				try
				{
					volatileDemultiplexer.InternalPrepare();
					return;
				}
				finally
				{
					Monitor.Exit(volatileDemultiplexer.transaction);
				}
			}
			if (!ThreadPool.QueueUserWorkItem(PrepareCallback, volatileDemultiplexer))
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedFailureOfThreadPool"), null);
			}
		}

		protected static void PoolableCommit(object state)
		{
			VolatileDemultiplexer volatileDemultiplexer = (VolatileDemultiplexer)state;
			if (Monitor.TryEnter(volatileDemultiplexer.transaction, 250))
			{
				try
				{
					volatileDemultiplexer.InternalCommit();
					return;
				}
				finally
				{
					Monitor.Exit(volatileDemultiplexer.transaction);
				}
			}
			if (!ThreadPool.QueueUserWorkItem(CommitCallback, volatileDemultiplexer))
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedFailureOfThreadPool"), null);
			}
		}

		protected static void PoolableRollback(object state)
		{
			VolatileDemultiplexer volatileDemultiplexer = (VolatileDemultiplexer)state;
			if (Monitor.TryEnter(volatileDemultiplexer.transaction, 250))
			{
				try
				{
					volatileDemultiplexer.InternalRollback();
					return;
				}
				finally
				{
					Monitor.Exit(volatileDemultiplexer.transaction);
				}
			}
			if (!ThreadPool.QueueUserWorkItem(RollbackCallback, volatileDemultiplexer))
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedFailureOfThreadPool"), null);
			}
		}

		protected static void PoolableInDoubt(object state)
		{
			VolatileDemultiplexer volatileDemultiplexer = (VolatileDemultiplexer)state;
			if (Monitor.TryEnter(volatileDemultiplexer.transaction, 250))
			{
				try
				{
					volatileDemultiplexer.InternalInDoubt();
					return;
				}
				finally
				{
					Monitor.Exit(volatileDemultiplexer.transaction);
				}
			}
			if (!ThreadPool.QueueUserWorkItem(InDoubtCallback, volatileDemultiplexer))
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedFailureOfThreadPool"), null);
			}
		}

		protected abstract void InternalPrepare();

		protected abstract void InternalCommit();

		protected abstract void InternalRollback();

		protected abstract void InternalInDoubt();

		public abstract void Prepare(IPromotedEnlistment en);

		public abstract void Commit(IPromotedEnlistment en);

		public abstract void Rollback(IPromotedEnlistment en);

		public abstract void InDoubt(IPromotedEnlistment en);
	}
	internal class Phase0VolatileDemultiplexer : VolatileDemultiplexer
	{
		public Phase0VolatileDemultiplexer(InternalTransaction transaction)
			: base(transaction)
		{
		}

		protected override void InternalPrepare()
		{
			try
			{
				transaction.State.ChangeStatePromotedPhase0(transaction);
			}
			catch (TransactionAbortedException ex)
			{
				oletxEnlistment.ForceRollback(ex);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), ex);
				}
			}
			catch (TransactionInDoubtException exception)
			{
				oletxEnlistment.EnlistmentDone();
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception);
				}
			}
		}

		protected override void InternalCommit()
		{
			oletxEnlistment.EnlistmentDone();
			transaction.State.ChangeStatePromotedCommitted(transaction);
		}

		protected override void InternalRollback()
		{
			oletxEnlistment.EnlistmentDone();
			transaction.State.ChangeStatePromotedAborted(transaction);
		}

		protected override void InternalInDoubt()
		{
			transaction.State.InDoubtFromDtc(transaction);
		}

		public override void Prepare(IPromotedEnlistment en)
		{
			preparingEnlistment = en;
			VolatileDemultiplexer.PoolablePrepare(this);
		}

		public override void Commit(IPromotedEnlistment en)
		{
			oletxEnlistment = en;
			VolatileDemultiplexer.PoolableCommit(this);
		}

		public override void Rollback(IPromotedEnlistment en)
		{
			oletxEnlistment = en;
			VolatileDemultiplexer.PoolableRollback(this);
		}

		public override void InDoubt(IPromotedEnlistment en)
		{
			oletxEnlistment = en;
			VolatileDemultiplexer.PoolableInDoubt(this);
		}
	}
	internal class Phase1VolatileDemultiplexer : VolatileDemultiplexer
	{
		public Phase1VolatileDemultiplexer(InternalTransaction transaction)
			: base(transaction)
		{
		}

		protected override void InternalPrepare()
		{
			try
			{
				transaction.State.ChangeStatePromotedPhase1(transaction);
			}
			catch (TransactionAbortedException ex)
			{
				oletxEnlistment.ForceRollback(ex);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), ex);
				}
			}
			catch (TransactionInDoubtException exception)
			{
				oletxEnlistment.EnlistmentDone();
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceLtm"), exception);
				}
			}
		}

		protected override void InternalCommit()
		{
			oletxEnlistment.EnlistmentDone();
			transaction.State.ChangeStatePromotedCommitted(transaction);
		}

		protected override void InternalRollback()
		{
			oletxEnlistment.EnlistmentDone();
			transaction.State.ChangeStatePromotedAborted(transaction);
		}

		protected override void InternalInDoubt()
		{
			transaction.State.InDoubtFromDtc(transaction);
		}

		public override void Prepare(IPromotedEnlistment en)
		{
			preparingEnlistment = en;
			VolatileDemultiplexer.PoolablePrepare(this);
		}

		public override void Commit(IPromotedEnlistment en)
		{
			oletxEnlistment = en;
			VolatileDemultiplexer.PoolableCommit(this);
		}

		public override void Rollback(IPromotedEnlistment en)
		{
			oletxEnlistment = en;
			VolatileDemultiplexer.PoolableRollback(this);
		}

		public override void InDoubt(IPromotedEnlistment en)
		{
			oletxEnlistment = en;
			VolatileDemultiplexer.PoolableInDoubt(this);
		}
	}
	internal struct VolatileEnlistmentSet
	{
		internal InternalEnlistment[] volatileEnlistments;

		internal int volatileEnlistmentCount;

		internal int volatileEnlistmentSize;

		internal int dependentClones;

		internal int preparedVolatileEnlistments;

		private VolatileDemultiplexer volatileDemux;

		internal VolatileDemultiplexer VolatileDemux
		{
			get
			{
				return volatileDemux;
			}
			set
			{
				volatileDemux = value;
			}
		}
	}
	public interface IEnlistmentNotification
	{
		void Prepare(PreparingEnlistment preparingEnlistment);

		void Commit(Enlistment enlistment);

		void Rollback(Enlistment enlistment);

		void InDoubt(Enlistment enlistment);
	}
	public interface ITransactionPromoter
	{
		byte[] Promote();
	}
	public interface IPromotableSinglePhaseNotification : ITransactionPromoter
	{
		void Initialize();

		void SinglePhaseCommit(SinglePhaseEnlistment singlePhaseEnlistment);

		void Rollback(SinglePhaseEnlistment singlePhaseEnlistment);
	}
	public interface ISimpleTransactionSuperior : ITransactionPromoter
	{
		void Rollback();
	}
	[Serializable]
	public sealed class SubordinateTransaction : Transaction
	{
		public SubordinateTransaction(IsolationLevel isoLevel, ISimpleTransactionSuperior superior)
			: base(isoLevel, superior)
		{
		}
	}
	public interface ISinglePhaseNotification : IEnlistmentNotification
	{
		void SinglePhaseCommit(SinglePhaseEnlistment singlePhaseEnlistment);
	}
	[Serializable]
	public class TransactionException : SystemException
	{
		internal static TransactionException Create(string traceSource, string message, Exception innerException)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.TransactionExceptionTraceRecord.Trace(traceSource, message);
			}
			return new TransactionException(message, innerException);
		}

		internal static TransactionException CreateTransactionStateException(string traceSource, Exception innerException)
		{
			return Create(traceSource, SR.GetString("TransactionStateException"), innerException);
		}

		internal static Exception CreateEnlistmentStateException(string traceSource, Exception innerException)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(traceSource, SR.GetString("EnlistmentStateException"));
			}
			return new InvalidOperationException(SR.GetString("EnlistmentStateException"), innerException);
		}

		internal static Exception CreateTransactionCompletedException(string traceSource)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(traceSource, SR.GetString("TransactionAlreadyCompleted"));
			}
			return new InvalidOperationException(SR.GetString("TransactionAlreadyCompleted"));
		}

		internal static Exception CreateInvalidOperationException(string traceSource, string message, Exception innerException)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(traceSource, message);
			}
			return new InvalidOperationException(message, innerException);
		}

		public TransactionException()
		{
		}

		public TransactionException(string message)
			: base(message)
		{
		}

		public TransactionException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected TransactionException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[Serializable]
	public class TransactionAbortedException : TransactionException
	{
		internal new static TransactionAbortedException Create(string traceSource, string message, Exception innerException)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.TransactionExceptionTraceRecord.Trace(traceSource, message);
			}
			return new TransactionAbortedException(message, innerException);
		}

		internal static TransactionAbortedException Create(string traceSource, Exception innerException)
		{
			return Create(traceSource, SR.GetString("TransactionAborted"), innerException);
		}

		public TransactionAbortedException()
			: base(SR.GetString("TransactionAborted"))
		{
		}

		public TransactionAbortedException(string message)
			: base(message)
		{
		}

		public TransactionAbortedException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		internal TransactionAbortedException(Exception innerException)
			: base(SR.GetString("TransactionAborted"), innerException)
		{
		}

		protected TransactionAbortedException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[Serializable]
	public class TransactionInDoubtException : TransactionException
	{
		internal new static TransactionInDoubtException Create(string traceSource, string message, Exception innerException)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.TransactionExceptionTraceRecord.Trace(traceSource, message);
			}
			return new TransactionInDoubtException(message, innerException);
		}

		internal static TransactionInDoubtException Create(string traceSource, Exception innerException)
		{
			return Create(traceSource, SR.GetString("TransactionIndoubt"), innerException);
		}

		public TransactionInDoubtException()
			: base(SR.GetString("TransactionIndoubt"))
		{
		}

		public TransactionInDoubtException(string message)
			: base(message)
		{
		}

		public TransactionInDoubtException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected TransactionInDoubtException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[Serializable]
	public class TransactionManagerCommunicationException : TransactionException
	{
		internal new static TransactionManagerCommunicationException Create(string traceSource, string message, Exception innerException)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
			{
				System.Transactions.Diagnostics.TransactionExceptionTraceRecord.Trace(traceSource, message);
			}
			return new TransactionManagerCommunicationException(message, innerException);
		}

		internal static TransactionManagerCommunicationException Create(string traceSource, Exception innerException)
		{
			return Create(traceSource, SR.GetString("TransactionManagerCommunicationException"), innerException);
		}

		public TransactionManagerCommunicationException()
			: base(SR.GetString("TransactionManagerCommunicationException"))
		{
		}

		public TransactionManagerCommunicationException(string message)
			: base(message)
		{
		}

		public TransactionManagerCommunicationException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected TransactionManagerCommunicationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[Serializable]
	public class TransactionPromotionException : TransactionException
	{
		public TransactionPromotionException()
			: this(SR.GetString("PromotionFailed"))
		{
		}

		public TransactionPromotionException(string message)
			: base(message)
		{
		}

		public TransactionPromotionException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected TransactionPromotionException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[ComImport]
	[Guid("0fb15084-af41-11ce-bd2b-204c4f4f5020")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IDtcTransaction
	{
		void Commit(int retaining, [MarshalAs(UnmanagedType.I4)] int commitType, int reserved);

		void Abort(IntPtr reason, int retaining, int async);

		void GetTransactionInfo(IntPtr transactionInformation);
	}
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	public static class TransactionInterop
	{
		internal static System.Transactions.Oletx.OletxTransaction ConvertToOletxTransaction(Transaction transaction)
		{
			if (null == transaction)
			{
				throw new ArgumentNullException("transaction");
			}
			if (transaction.Disposed)
			{
				throw new ObjectDisposedException("Transaction");
			}
			if (transaction.complete)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceLtm"));
			}
			return transaction.Promote();
		}

		public static byte[] GetExportCookie(Transaction transaction, byte[] whereabouts)
		{
			//Discarded unreachable code: IL_00c8
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			byte[] array = null;
			if (null == transaction)
			{
				throw new ArgumentNullException("transaction");
			}
			if (whereabouts == null)
			{
				throw new ArgumentNullException("whereabouts");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetExportCookie");
			}
			byte[] array2 = new byte[whereabouts.Length];
			Array.Copy(whereabouts, array2, whereabouts.Length);
			whereabouts = array2;
			int cookieIndex = 0;
			uint cookieSize = 0u;
			System.Transactions.Oletx.CoTaskMemHandle cookieBuffer = null;
			System.Transactions.Oletx.OletxTransaction oletxTransaction = ConvertToOletxTransaction(transaction);
			try
			{
				oletxTransaction.realOletxTransaction.TransactionShim.Export(Convert.ToUInt32(whereabouts.Length), whereabouts, out cookieIndex, out cookieSize, out cookieBuffer);
				array = new byte[cookieSize];
				Marshal.Copy(cookieBuffer.DangerousGetHandle(), array, 0, Convert.ToInt32(cookieSize));
			}
			catch (COMException ex)
			{
				System.Transactions.Oletx.OletxTransactionManager.ProxyException(ex);
				throw TransactionManagerCommunicationException.Create(SR.GetString("TraceSourceOletx"), ex);
			}
			finally
			{
				cookieBuffer?.Close();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetExportCookie");
			}
			return array;
		}

		public static Transaction GetTransactionFromExportCookie(byte[] cookie)
		{
			//Discarded unreachable code: IL_0163
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (cookie == null)
			{
				throw new ArgumentNullException("cookie");
			}
			if (cookie.Length < 32)
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "cookie");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromExportCookie");
			}
			byte[] array = new byte[cookie.Length];
			Array.Copy(cookie, array, cookie.Length);
			cookie = array;
			Transaction transaction = null;
			System.Transactions.Oletx.ITransactionShim transactionShim = null;
			Guid transactionIdentifier = Guid.Empty;
			System.Transactions.Oletx.OletxTransactionIsolationLevel isolationLevel = System.Transactions.Oletx.OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE;
			System.Transactions.Oletx.OutcomeEnlistment outcomeEnlistment = null;
			System.Transactions.Oletx.OletxTransaction oletxTransaction = null;
			byte[] array2 = new byte[16];
			for (int i = 0; i < array2.Length; i++)
			{
				array2[i] = cookie[i + 16];
			}
			Guid transactionIdentifier2 = new Guid(array2);
			transaction = TransactionManager.FindPromotedTransaction(transactionIdentifier2);
			if (null != transaction)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromExportCookie");
				}
				return transaction;
			}
			System.Transactions.Oletx.RealOletxTransaction realOletxTransaction = null;
			System.Transactions.Oletx.OletxTransactionManager distributedTransactionManager = TransactionManager.DistributedTransactionManager;
			distributedTransactionManager.dtcTransactionManagerLock.AcquireReaderLock(-1);
			try
			{
				outcomeEnlistment = new System.Transactions.Oletx.OutcomeEnlistment();
				IntPtr intPtr = IntPtr.Zero;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					intPtr = System.Transactions.Oletx.HandleTable.AllocHandle(outcomeEnlistment);
					distributedTransactionManager.DtcTransactionManager.ProxyShimFactory.Import(Convert.ToUInt32(cookie.Length), cookie, intPtr, out transactionIdentifier, out isolationLevel, out transactionShim);
				}
				finally
				{
					if (transactionShim == null && intPtr != IntPtr.Zero)
					{
						System.Transactions.Oletx.HandleTable.FreeHandle(intPtr);
					}
				}
			}
			catch (COMException ex)
			{
				System.Transactions.Oletx.OletxTransactionManager.ProxyException(ex);
				throw TransactionManagerCommunicationException.Create(SR.GetString("TraceSourceOletx"), ex);
			}
			finally
			{
				distributedTransactionManager.dtcTransactionManagerLock.ReleaseReaderLock();
			}
			realOletxTransaction = new System.Transactions.Oletx.RealOletxTransaction(distributedTransactionManager, transactionShim, outcomeEnlistment, transactionIdentifier, isolationLevel, isRoot: false);
			oletxTransaction = new System.Transactions.Oletx.OletxTransaction(realOletxTransaction);
			transaction = TransactionManager.FindOrCreatePromotedTransaction(transactionIdentifier2, oletxTransaction);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromExportCookie");
			}
			return transaction;
		}

		public static byte[] GetTransmitterPropagationToken(Transaction transaction)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (null == transaction)
			{
				throw new ArgumentNullException("transaction");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransmitterPropagationToken");
			}
			System.Transactions.Oletx.OletxTransaction oletxTx = ConvertToOletxTransaction(transaction);
			byte[] transmitterPropagationToken = GetTransmitterPropagationToken(oletxTx);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransmitterPropagationToken");
			}
			return transmitterPropagationToken;
		}

		internal static byte[] GetTransmitterPropagationToken(System.Transactions.Oletx.OletxTransaction oletxTx)
		{
			//Discarded unreachable code: IL_0040
			byte[] array = null;
			System.Transactions.Oletx.CoTaskMemHandle propgationToken = null;
			uint propagationTokeSize = 0u;
			try
			{
				oletxTx.realOletxTransaction.TransactionShim.GetPropagationToken(out propagationTokeSize, out propgationToken);
				array = new byte[propagationTokeSize];
				Marshal.Copy(propgationToken.DangerousGetHandle(), array, 0, Convert.ToInt32(propagationTokeSize));
				return array;
			}
			catch (COMException comException)
			{
				System.Transactions.Oletx.OletxTransactionManager.ProxyException(comException);
				throw;
			}
			finally
			{
				propgationToken?.Close();
			}
		}

		public static Transaction GetTransactionFromTransmitterPropagationToken(byte[] propagationToken)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			Transaction transaction = null;
			if (propagationToken == null)
			{
				throw new ArgumentNullException("propagationToken");
			}
			if (propagationToken.Length < 24)
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "propagationToken");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromTransmitterPropagationToken");
			}
			byte[] array = new byte[16];
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = propagationToken[i + 8];
			}
			Guid transactionIdentifier = new Guid(array);
			Transaction transaction2 = TransactionManager.FindPromotedTransaction(transactionIdentifier);
			if (null != transaction2)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromTransmitterPropagationToken");
				}
				return transaction2;
			}
			System.Transactions.Oletx.OletxTransaction oletxTransactionFromTransmitterPropigationToken = GetOletxTransactionFromTransmitterPropigationToken(propagationToken);
			transaction = TransactionManager.FindOrCreatePromotedTransaction(transactionIdentifier, oletxTransactionFromTransmitterPropigationToken);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromTransmitterPropagationToken");
			}
			return transaction;
		}

		internal static System.Transactions.Oletx.OletxTransaction GetOletxTransactionFromTransmitterPropigationToken(byte[] propagationToken)
		{
			//Discarded unreachable code: IL_00c7
			System.Transactions.Oletx.ITransactionShim transactionShim = null;
			if (propagationToken == null)
			{
				throw new ArgumentNullException("propagationToken");
			}
			if (propagationToken.Length < 24)
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "propagationToken");
			}
			byte[] array = new byte[propagationToken.Length];
			Array.Copy(propagationToken, array, propagationToken.Length);
			propagationToken = array;
			System.Transactions.Oletx.OletxTransactionManager distributedTransactionManager = TransactionManager.DistributedTransactionManager;
			distributedTransactionManager.dtcTransactionManagerLock.AcquireReaderLock(-1);
			System.Transactions.Oletx.OutcomeEnlistment outcomeEnlistment;
			Guid transactionIdentifier;
			System.Transactions.Oletx.OletxTransactionIsolationLevel isolationLevel;
			try
			{
				outcomeEnlistment = new System.Transactions.Oletx.OutcomeEnlistment();
				IntPtr intPtr = IntPtr.Zero;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					intPtr = System.Transactions.Oletx.HandleTable.AllocHandle(outcomeEnlistment);
					distributedTransactionManager.DtcTransactionManager.ProxyShimFactory.ReceiveTransaction(Convert.ToUInt32(propagationToken.Length), propagationToken, intPtr, out transactionIdentifier, out isolationLevel, out transactionShim);
				}
				finally
				{
					if (transactionShim == null && intPtr != IntPtr.Zero)
					{
						System.Transactions.Oletx.HandleTable.FreeHandle(intPtr);
					}
				}
			}
			catch (COMException ex)
			{
				System.Transactions.Oletx.OletxTransactionManager.ProxyException(ex);
				throw TransactionManagerCommunicationException.Create(SR.GetString("TraceSourceOletx"), ex);
			}
			finally
			{
				distributedTransactionManager.dtcTransactionManagerLock.ReleaseReaderLock();
			}
			System.Transactions.Oletx.RealOletxTransaction realOletxTransaction = null;
			realOletxTransaction = new System.Transactions.Oletx.RealOletxTransaction(distributedTransactionManager, transactionShim, outcomeEnlistment, transactionIdentifier, isolationLevel, isRoot: false);
			return new System.Transactions.Oletx.OletxTransaction(realOletxTransaction);
		}

		public static IDtcTransaction GetDtcTransaction(Transaction transaction)
		{
			//Discarded unreachable code: IL_0061
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (null == transaction)
			{
				throw new ArgumentNullException("transaction");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetDtcTransaction");
			}
			IDtcTransaction transactionNative = null;
			System.Transactions.Oletx.OletxTransaction oletxTransaction = ConvertToOletxTransaction(transaction);
			try
			{
				oletxTransaction.realOletxTransaction.TransactionShim.GetITransactionNative(out transactionNative);
			}
			catch (COMException comException)
			{
				System.Transactions.Oletx.OletxTransactionManager.ProxyException(comException);
				throw;
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetDtcTransaction");
			}
			return transactionNative;
		}

		public static Transaction GetTransactionFromDtcTransaction(IDtcTransaction transactionNative)
		{
			//Discarded unreachable code: IL_0149
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			bool flag = false;
			System.Transactions.Oletx.ITransactionShim transactionShim = null;
			Guid transactionIdentifier = Guid.Empty;
			System.Transactions.Oletx.OletxTransactionIsolationLevel isolationLevel = System.Transactions.Oletx.OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE;
			System.Transactions.Oletx.OutcomeEnlistment outcomeEnlistment = null;
			System.Transactions.Oletx.RealOletxTransaction realOletxTransaction = null;
			System.Transactions.Oletx.OletxTransaction oletxTransaction = null;
			if (transactionNative == null)
			{
				throw new ArgumentNullException("transactionNative");
			}
			Transaction transaction = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromDtc");
			}
			if (!(transactionNative is System.Transactions.Oletx.ITransactionNativeInternal transactionNativeInternal))
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "transactionNative");
			}
			System.Transactions.Oletx.OletxXactTransInfo xactInfo = default(System.Transactions.Oletx.OletxXactTransInfo);
			try
			{
				transactionNativeInternal.GetTransactionInfo(out xactInfo);
			}
			catch (COMException ex)
			{
				if (System.Transactions.Oletx.NativeMethods.XACT_E_NOTRANSACTION != ex.ErrorCode)
				{
					throw;
				}
				flag = true;
				xactInfo.uow = Guid.Empty;
			}
			System.Transactions.Oletx.OletxTransactionManager distributedTransactionManager = TransactionManager.DistributedTransactionManager;
			if (!flag)
			{
				transaction = TransactionManager.FindPromotedTransaction(xactInfo.uow);
				if (null != transaction)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromDtcTransaction");
					}
					return transaction;
				}
				distributedTransactionManager.dtcTransactionManagerLock.AcquireReaderLock(-1);
				try
				{
					outcomeEnlistment = new System.Transactions.Oletx.OutcomeEnlistment();
					IntPtr intPtr = IntPtr.Zero;
					RuntimeHelpers.PrepareConstrainedRegions();
					try
					{
						intPtr = System.Transactions.Oletx.HandleTable.AllocHandle(outcomeEnlistment);
						distributedTransactionManager.DtcTransactionManager.ProxyShimFactory.CreateTransactionShim(transactionNative, intPtr, out transactionIdentifier, out isolationLevel, out transactionShim);
					}
					finally
					{
						if (transactionShim == null && intPtr != IntPtr.Zero)
						{
							System.Transactions.Oletx.HandleTable.FreeHandle(intPtr);
						}
					}
				}
				catch (COMException comException)
				{
					System.Transactions.Oletx.OletxTransactionManager.ProxyException(comException);
					throw;
				}
				finally
				{
					distributedTransactionManager.dtcTransactionManagerLock.ReleaseReaderLock();
				}
				realOletxTransaction = new System.Transactions.Oletx.RealOletxTransaction(distributedTransactionManager, transactionShim, outcomeEnlistment, transactionIdentifier, isolationLevel, isRoot: false);
				oletxTransaction = new System.Transactions.Oletx.OletxTransaction(realOletxTransaction);
				transaction = TransactionManager.FindOrCreatePromotedTransaction(xactInfo.uow, oletxTransaction);
			}
			else
			{
				realOletxTransaction = new System.Transactions.Oletx.RealOletxTransaction(distributedTransactionManager, null, null, transactionIdentifier, System.Transactions.Oletx.OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE, isRoot: false);
				oletxTransaction = new System.Transactions.Oletx.OletxTransaction(realOletxTransaction);
				transaction = new Transaction(oletxTransaction);
				TransactionManager.FireDistributedTransactionStarted(transaction);
				oletxTransaction.savedLtmPromotedTransaction = transaction;
				InternalTransaction.DistributedTransactionOutcome(transaction.internalTransaction, TransactionStatus.InDoubt);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetTransactionFromDtc");
			}
			return transaction;
		}

		public static byte[] GetWhereabouts()
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			byte[] result = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetWhereabouts");
			}
			System.Transactions.Oletx.OletxTransactionManager distributedTransactionManager = TransactionManager.DistributedTransactionManager;
			if (distributedTransactionManager == null)
			{
				throw new ArgumentException(SR.GetString("ArgumentWrongType"), "transactionManager");
			}
			distributedTransactionManager.dtcTransactionManagerLock.AcquireReaderLock(-1);
			try
			{
				result = distributedTransactionManager.DtcTransactionManager.Whereabouts;
			}
			finally
			{
				distributedTransactionManager.dtcTransactionManagerLock.ReleaseReaderLock();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "TransactionInterop.GetWhereabouts");
			}
			return result;
		}
	}
	public delegate Transaction HostCurrentTransactionCallback();
	public delegate void TransactionStartedEventHandler(object sender, TransactionEventArgs e);
	public static class TransactionManager
	{
		private const int recoveryInformationVersion1 = 1;

		private const int currentRecoveryVersion = 1;

		internal static bool _platformValidated;

		private static Hashtable promotedTransactionTable;

		private static TransactionTable transactionTable;

		private static TransactionStartedEventHandler distributedTransactionStartedDelegate;

		internal static HostCurrentTransactionCallback currentDelegate;

		internal static bool currentDelegateSet;

		private static object classSyncObject;

		private static DefaultSettingsSection defaultSettings;

		private static MachineSettingsSection machineSettings;

		private static bool _defaultTimeoutValidated;

		private static TimeSpan _defaultTimeout;

		private static bool _cachedMaxTimeout;

		private static TimeSpan _maximumTimeout;

		internal static System.Transactions.Oletx.OletxTransactionManager distributedTransactionManager;

		public static HostCurrentTransactionCallback HostCurrentCallback
		{
			[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
			get
			{
				if (!_platformValidated)
				{
					ValidatePlatform();
				}
				return currentDelegate;
			}
			[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
			set
			{
				if (!_platformValidated)
				{
					ValidatePlatform();
				}
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				lock (ClassSyncObject)
				{
					if (currentDelegateSet)
					{
						throw new InvalidOperationException(SR.GetString("CurrentDelegateSet"));
					}
					currentDelegateSet = true;
				}
				currentDelegate = value;
			}
		}

		private static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}

		internal static IsolationLevel DefaultIsolationLevel
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.get_DefaultIsolationLevel");
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.get_DefaultIsolationLevel");
				}
				return IsolationLevel.Serializable;
			}
		}

		private static DefaultSettingsSection DefaultSettings
		{
			get
			{
				if (defaultSettings == null)
				{
					defaultSettings = DefaultSettingsSection.GetSection();
				}
				return defaultSettings;
			}
		}

		private static MachineSettingsSection MachineSettings
		{
			get
			{
				if (machineSettings == null)
				{
					machineSettings = MachineSettingsSection.GetSection();
				}
				return machineSettings;
			}
		}

		public static TimeSpan DefaultTimeout
		{
			get
			{
				if (!_platformValidated)
				{
					ValidatePlatform();
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.get_DefaultTimeout");
				}
				if (!_defaultTimeoutValidated)
				{
					_defaultTimeout = ValidateTimeout(DefaultSettings.Timeout);
					if (_defaultTimeout != DefaultSettings.Timeout && System.Transactions.Diagnostics.DiagnosticTrace.Warning)
					{
						System.Transactions.Diagnostics.ConfiguredDefaultTimeoutAdjustedTraceRecord.Trace(SR.GetString("TraceSourceBase"));
					}
					_defaultTimeoutValidated = true;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.get_DefaultTimeout");
				}
				return _defaultTimeout;
			}
		}

		public static TimeSpan MaximumTimeout
		{
			get
			{
				if (!_platformValidated)
				{
					ValidatePlatform();
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.get_DefaultMaximumTimeout");
				}
				if (!_cachedMaxTimeout)
				{
					lock (ClassSyncObject)
					{
						if (!_cachedMaxTimeout)
						{
							TimeSpan maxTimeout = MachineSettings.MaxTimeout;
							Thread.MemoryBarrier();
							_maximumTimeout = maxTimeout;
							_cachedMaxTimeout = true;
						}
					}
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.get_DefaultMaximumTimeout");
				}
				return _maximumTimeout;
			}
		}

		internal static Hashtable PromotedTransactionTable
		{
			get
			{
				if (promotedTransactionTable == null)
				{
					lock (ClassSyncObject)
					{
						if (promotedTransactionTable == null)
						{
							Hashtable hashtable = new Hashtable(100);
							Thread.MemoryBarrier();
							promotedTransactionTable = hashtable;
						}
					}
				}
				return promotedTransactionTable;
			}
		}

		internal static TransactionTable TransactionTable
		{
			get
			{
				if (TransactionManager.transactionTable == null)
				{
					lock (ClassSyncObject)
					{
						if (TransactionManager.transactionTable == null)
						{
							TransactionTable transactionTable = new TransactionTable();
							Thread.MemoryBarrier();
							TransactionManager.transactionTable = transactionTable;
						}
					}
				}
				return TransactionManager.transactionTable;
			}
		}

		internal static System.Transactions.Oletx.OletxTransactionManager DistributedTransactionManager
		{
			get
			{
				if (distributedTransactionManager == null)
				{
					lock (ClassSyncObject)
					{
						if (distributedTransactionManager == null)
						{
							System.Transactions.Oletx.OletxTransactionManager oletxTransactionManager = new System.Transactions.Oletx.OletxTransactionManager(DefaultSettings.DistributedTransactionManagerName);
							Thread.MemoryBarrier();
							distributedTransactionManager = oletxTransactionManager;
						}
					}
				}
				return distributedTransactionManager;
			}
		}

		public static event TransactionStartedEventHandler DistributedTransactionStarted
		{
			[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
			add
			{
				if (!_platformValidated)
				{
					ValidatePlatform();
				}
				lock (ClassSyncObject)
				{
					distributedTransactionStartedDelegate = (TransactionStartedEventHandler)Delegate.Combine(distributedTransactionStartedDelegate, value);
					if (value != null)
					{
						ProcessExistingTransactions(value);
					}
				}
			}
			[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
			remove
			{
				if (!_platformValidated)
				{
					ValidatePlatform();
				}
				lock (ClassSyncObject)
				{
					distributedTransactionStartedDelegate = (TransactionStartedEventHandler)Delegate.Remove(distributedTransactionStartedDelegate, value);
				}
			}
		}

		internal static void ProcessExistingTransactions(TransactionStartedEventHandler eventHandler)
		{
			lock (PromotedTransactionTable)
			{
				foreach (DictionaryEntry item in PromotedTransactionTable)
				{
					WeakReference weakReference = (WeakReference)item.Value;
					Transaction transaction = (Transaction)weakReference.Target;
					if (transaction != null)
					{
						TransactionEventArgs transactionEventArgs = new TransactionEventArgs();
						transactionEventArgs.transaction = transaction.InternalClone();
						eventHandler(transactionEventArgs.transaction, transactionEventArgs);
					}
				}
			}
		}

		internal static void FireDistributedTransactionStarted(Transaction transaction)
		{
			TransactionStartedEventHandler transactionStartedEventHandler = null;
			lock (ClassSyncObject)
			{
				transactionStartedEventHandler = distributedTransactionStartedDelegate;
			}
			if (transactionStartedEventHandler != null)
			{
				TransactionEventArgs transactionEventArgs = new TransactionEventArgs();
				transactionEventArgs.transaction = transaction.InternalClone();
				transactionStartedEventHandler(transactionEventArgs.transaction, transactionEventArgs);
			}
		}

		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public static Enlistment Reenlist(Guid resourceManagerIdentifier, byte[] recoveryInformation, IEnlistmentNotification enlistmentNotification)
		{
			//Discarded unreachable code: IL_012e, IL_0169
			if (resourceManagerIdentifier == Guid.Empty)
			{
				throw new ArgumentException(SR.GetString("BadResourceManagerId"), "resourceManagerIdentifier");
			}
			if (recoveryInformation == null)
			{
				throw new ArgumentNullException("recoveryInformation");
			}
			if (enlistmentNotification == null)
			{
				throw new ArgumentNullException("enlistmentNotification");
			}
			if (!_platformValidated)
			{
				ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.Reenlist");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.ReenlistTraceRecord.Trace(SR.GetString("TraceSourceBase"), resourceManagerIdentifier);
			}
			MemoryStream memoryStream = new MemoryStream(recoveryInformation);
			int num = 0;
			string nodeName = null;
			byte[] recoveryInformation2 = null;
			try
			{
				BinaryReader binaryReader = new BinaryReader(memoryStream);
				num = binaryReader.ReadInt32();
				if (num != 1)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
					{
						System.Transactions.Diagnostics.TransactionExceptionTraceRecord.Trace(SR.GetString("TraceSourceBase"), SR.GetString("UnrecognizedRecoveryInformation"));
					}
					throw new ArgumentException(SR.GetString("UnrecognizedRecoveryInformation"), "recoveryInformation");
				}
				nodeName = binaryReader.ReadString();
				recoveryInformation2 = binaryReader.ReadBytes(recoveryInformation.Length - checked((int)memoryStream.Position));
			}
			catch (EndOfStreamException innerException)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
				{
					System.Transactions.Diagnostics.TransactionExceptionTraceRecord.Trace(SR.GetString("TraceSourceBase"), SR.GetString("UnrecognizedRecoveryInformation"));
				}
				throw new ArgumentException(SR.GetString("UnrecognizedRecoveryInformation"), "recoveryInformation", innerException);
			}
			catch (FormatException innerException2)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
				{
					System.Transactions.Diagnostics.TransactionExceptionTraceRecord.Trace(SR.GetString("TraceSourceBase"), SR.GetString("UnrecognizedRecoveryInformation"));
				}
				throw new ArgumentException(SR.GetString("UnrecognizedRecoveryInformation"), "recoveryInformation", innerException2);
			}
			finally
			{
				memoryStream.Close();
			}
			System.Transactions.Oletx.OletxTransactionManager oletxTransactionManager = CheckTransactionManager(nodeName);
			object syncRoot = new object();
			Enlistment enlistment = new Enlistment(enlistmentNotification, syncRoot);
			EnlistmentState._EnlistmentStatePromoted.EnterState(enlistment.InternalEnlistment);
			enlistment.InternalEnlistment.PromotedEnlistment = oletxTransactionManager.ReenlistTransaction(resourceManagerIdentifier, recoveryInformation2, (RecoveringInternalEnlistment)enlistment.InternalEnlistment);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.Reenlist");
			}
			return enlistment;
		}

		private static System.Transactions.Oletx.OletxTransactionManager CheckTransactionManager(string nodeName)
		{
			System.Transactions.Oletx.OletxTransactionManager oletxTransactionManager = DistributedTransactionManager;
			if ((oletxTransactionManager.NodeName != null || (nodeName != null && nodeName.Length != 0)) && (oletxTransactionManager.NodeName == null || !oletxTransactionManager.NodeName.Equals(nodeName)))
			{
				throw new ArgumentException(SR.GetString("InvalidRecoveryInformation"), "recoveryInformation");
			}
			return oletxTransactionManager;
		}

		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public static void RecoveryComplete(Guid resourceManagerIdentifier)
		{
			if (resourceManagerIdentifier == Guid.Empty)
			{
				throw new ArgumentException(SR.GetString("BadResourceManagerId"), "resourceManagerIdentifier");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.RecoveryComplete");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.RecoveryCompleteTraceRecord.Trace(SR.GetString("TraceSourceBase"), resourceManagerIdentifier);
			}
			DistributedTransactionManager.ResourceManagerRecoveryComplete(resourceManagerIdentifier);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.RecoveryComplete");
			}
		}

		internal static byte[] GetRecoveryInformation(string startupInfo, byte[] resourceManagerRecoveryInformation)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.GetRecoveryInformation");
			}
			MemoryStream memoryStream = new MemoryStream();
			byte[] result = null;
			try
			{
				BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
				binaryWriter.Write(1);
				if (startupInfo != null)
				{
					binaryWriter.Write(startupInfo);
				}
				else
				{
					binaryWriter.Write("");
				}
				binaryWriter.Write(resourceManagerRecoveryInformation);
				binaryWriter.Flush();
				result = memoryStream.ToArray();
			}
			finally
			{
				memoryStream.Close();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionManager.GetRecoveryInformation");
			}
			return result;
		}

		internal static byte[] ConvertToByteArray(object thingToConvert)
		{
			MemoryStream memoryStream = new MemoryStream();
			byte[] array = null;
			try
			{
				IFormatter formatter = new BinaryFormatter();
				formatter.Serialize(memoryStream, thingToConvert);
				array = new byte[memoryStream.Length];
				memoryStream.Position = 0L;
				memoryStream.Read(array, 0, Convert.ToInt32(memoryStream.Length, CultureInfo.InvariantCulture));
				return array;
			}
			finally
			{
				memoryStream.Close();
			}
		}

		internal static void ValidateIsolationLevel(IsolationLevel transactionIsolationLevel)
		{
			switch (transactionIsolationLevel)
			{
			case IsolationLevel.Serializable:
			case IsolationLevel.RepeatableRead:
			case IsolationLevel.ReadCommitted:
			case IsolationLevel.ReadUncommitted:
			case IsolationLevel.Snapshot:
			case IsolationLevel.Chaos:
			case IsolationLevel.Unspecified:
				return;
			}
			throw new ArgumentOutOfRangeException("transactionIsolationLevel");
		}

		internal static TimeSpan ValidateTimeout(TimeSpan transactionTimeout)
		{
			if (transactionTimeout < TimeSpan.Zero)
			{
				throw new ArgumentOutOfRangeException("transactionTimeout");
			}
			if (MaximumTimeout != TimeSpan.Zero && (transactionTimeout > MaximumTimeout || transactionTimeout == TimeSpan.Zero))
			{
				return MaximumTimeout;
			}
			return transactionTimeout;
		}

		internal static Transaction FindPromotedTransaction(Guid transactionIdentifier)
		{
			Hashtable hashtable = PromotedTransactionTable;
			WeakReference weakReference = (WeakReference)hashtable[transactionIdentifier];
			if (weakReference != null)
			{
				Transaction transaction = weakReference.Target as Transaction;
				if (null != transaction)
				{
					return transaction.InternalClone();
				}
				lock (hashtable)
				{
					hashtable.Remove(transactionIdentifier);
				}
			}
			return null;
		}

		internal static Transaction FindOrCreatePromotedTransaction(Guid transactionIdentifier, System.Transactions.Oletx.OletxTransaction oletx)
		{
			Transaction transaction = null;
			Hashtable hashtable = PromotedTransactionTable;
			lock (hashtable)
			{
				WeakReference weakReference = (WeakReference)hashtable[transactionIdentifier];
				if (weakReference != null)
				{
					transaction = weakReference.Target as Transaction;
					if (null != transaction)
					{
						oletx.Dispose();
						return transaction.InternalClone();
					}
					lock (hashtable)
					{
						hashtable.Remove(transactionIdentifier);
					}
				}
				transaction = new Transaction(oletx);
				transaction.internalTransaction.finalizedObject = new FinalizedObject(transaction.internalTransaction, oletx.Identifier);
				weakReference = new WeakReference(transaction, trackResurrection: false);
				hashtable[oletx.Identifier] = weakReference;
			}
			oletx.savedLtmPromotedTransaction = transaction;
			FireDistributedTransactionStarted(transaction);
			return transaction;
		}

		internal static void ValidatePlatform()
		{
			if (PlatformID.Win32NT != Environment.OSVersion.Platform)
			{
				throw new PlatformNotSupportedException(SR.GetString("OnlySupportedOnWinNT"));
			}
			_platformValidated = true;
		}
	}
	internal class CheapUnfairReaderWriterLock
	{
		private const int MAX_SPIN_COUNT = 100;

		private const int SLEEP_TIME = 500;

		private object writerFinishedEvent;

		private int readersIn;

		private int readersOut;

		private bool writerPresent;

		private object syncRoot;

		private object SyncRoot
		{
			get
			{
				if (syncRoot == null)
				{
					Interlocked.CompareExchange(ref syncRoot, new object(), null);
				}
				return syncRoot;
			}
		}

		private bool ReadersPresent => readersIn != readersOut;

		private ManualResetEvent WriterFinishedEvent
		{
			get
			{
				if (writerFinishedEvent == null)
				{
					Interlocked.CompareExchange(ref writerFinishedEvent, new ManualResetEvent(initialState: true), null);
				}
				return (ManualResetEvent)writerFinishedEvent;
			}
		}

		public int AcquireReaderLock()
		{
			int num = 0;
			while (true)
			{
				if (writerPresent)
				{
					WriterFinishedEvent.WaitOne();
				}
				num = Interlocked.Increment(ref readersIn);
				if (!writerPresent)
				{
					break;
				}
				Interlocked.Decrement(ref readersIn);
			}
			return num;
		}

		public void AcquireWriterLock()
		{
			Monitor.Enter(SyncRoot);
			writerPresent = true;
			WriterFinishedEvent.Reset();
			do
			{
				int num = 0;
				while (ReadersPresent && num < 100)
				{
					Thread.Sleep(0);
					num++;
				}
				if (ReadersPresent)
				{
					Thread.Sleep(500);
				}
			}
			while (ReadersPresent);
		}

		public void ReleaseReaderLock()
		{
			Interlocked.Increment(ref readersOut);
		}

		public void ReleaseWriterLock()
		{
			try
			{
				writerPresent = false;
				WriterFinishedEvent.Set();
			}
			finally
			{
				Monitor.Exit(SyncRoot);
			}
		}
	}
	internal class TransactionTable
	{
		private const int timerInternalExponent = 9;

		private const long TicksPerMillisecond = 10000L;

		private Timer timer;

		private bool timerEnabled;

		private int timerInterval;

		private long ticks;

		private long lastTimerTime;

		private BucketSet headBucketSet;

		private CheapUnfairReaderWriterLock rwLock;

		private long CurrentTime
		{
			get
			{
				if (timerEnabled)
				{
					return lastTimerTime;
				}
				return DateTime.UtcNow.Ticks;
			}
		}

		internal TransactionTable()
		{
			timer = new Timer(ThreadTimer, null, -1, timerInterval);
			timerEnabled = false;
			timerInterval = 512;
			ticks = 0L;
			headBucketSet = new BucketSet(this, long.MaxValue);
			rwLock = new CheapUnfairReaderWriterLock();
		}

		internal long TimeoutTicks(TimeSpan timeout)
		{
			if (timeout != TimeSpan.Zero)
			{
				return (timeout.Ticks / 10000 >> 9) + ticks;
			}
			return long.MaxValue;
		}

		internal TimeSpan RecalcTimeout(InternalTransaction tx)
		{
			return TimeSpan.FromMilliseconds((tx.AbsoluteTimeout - ticks) * timerInterval);
		}

		internal int Add(InternalTransaction txNew)
		{
			Thread.BeginCriticalRegion();
			int num = 0;
			try
			{
				num = rwLock.AcquireReaderLock();
				try
				{
					if (txNew.AbsoluteTimeout != long.MaxValue && !timerEnabled)
					{
						if (!timer.Change(timerInterval, timerInterval))
						{
							throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedTimerFailure"), null);
						}
						lastTimerTime = DateTime.UtcNow.Ticks;
						timerEnabled = true;
					}
					txNew.CreationTime = CurrentTime;
					AddIter(txNew);
					return num;
				}
				finally
				{
					rwLock.ReleaseReaderLock();
				}
			}
			finally
			{
				Thread.EndCriticalRegion();
			}
		}

		private void AddIter(InternalTransaction txNew)
		{
			BucketSet bucketSet = headBucketSet;
			while (bucketSet.AbsoluteTimeout != txNew.AbsoluteTimeout)
			{
				BucketSet bucketSet2 = null;
				do
				{
					WeakReference weakReference = (WeakReference)bucketSet.nextSetWeak;
					BucketSet bucketSet3 = null;
					if (weakReference != null)
					{
						bucketSet3 = (BucketSet)weakReference.Target;
					}
					if (bucketSet3 == null)
					{
						BucketSet bucketSet4 = new BucketSet(this, txNew.AbsoluteTimeout);
						WeakReference value = new WeakReference(bucketSet4);
						WeakReference weakReference2 = (WeakReference)Interlocked.CompareExchange(ref bucketSet.nextSetWeak, value, weakReference);
						if (weakReference2 == weakReference)
						{
							bucketSet4.prevSet = bucketSet;
						}
					}
					else
					{
						bucketSet2 = bucketSet;
						bucketSet = bucketSet3;
					}
				}
				while (bucketSet.AbsoluteTimeout > txNew.AbsoluteTimeout);
				if (bucketSet.AbsoluteTimeout == txNew.AbsoluteTimeout)
				{
					continue;
				}
				BucketSet bucketSet5 = new BucketSet(this, txNew.AbsoluteTimeout);
				WeakReference value2 = new WeakReference(bucketSet5);
				bucketSet5.nextSetWeak = bucketSet2.nextSetWeak;
				WeakReference weakReference3 = (WeakReference)Interlocked.CompareExchange(ref bucketSet2.nextSetWeak, value2, bucketSet5.nextSetWeak);
				if (weakReference3 == bucketSet5.nextSetWeak)
				{
					if (weakReference3 != null)
					{
						BucketSet bucketSet6 = (BucketSet)weakReference3.Target;
						if (bucketSet6 != null)
						{
							bucketSet6.prevSet = bucketSet5;
						}
					}
					bucketSet5.prevSet = bucketSet;
				}
				bucketSet = bucketSet2;
				bucketSet2 = null;
			}
			bucketSet.Add(txNew);
		}

		internal void Remove(InternalTransaction tx)
		{
			tx.tableBucket.Remove(tx);
			tx.tableBucket = null;
		}

		private void ThreadTimer(object state)
		{
			if (!timerEnabled)
			{
				return;
			}
			ticks++;
			lastTimerTime = DateTime.UtcNow.Ticks;
			BucketSet bucketSet = null;
			BucketSet bucketSet2 = headBucketSet;
			WeakReference weakReference = (WeakReference)bucketSet2.nextSetWeak;
			BucketSet bucketSet3 = null;
			if (weakReference != null)
			{
				bucketSet3 = (BucketSet)weakReference.Target;
			}
			if (bucketSet3 == null)
			{
				rwLock.AcquireWriterLock();
				try
				{
					if (!timer.Change(-1, -1))
					{
						throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedTimerFailure"), null);
					}
					timerEnabled = false;
					return;
				}
				finally
				{
					rwLock.ReleaseWriterLock();
				}
			}
			while (true)
			{
				weakReference = (WeakReference)bucketSet2.nextSetWeak;
				if (weakReference == null)
				{
					break;
				}
				bucketSet3 = (BucketSet)weakReference.Target;
				if (bucketSet3 == null)
				{
					break;
				}
				bucketSet = bucketSet2;
				bucketSet2 = bucketSet3;
				if (bucketSet2.AbsoluteTimeout > ticks)
				{
					continue;
				}
				Thread.BeginCriticalRegion();
				try
				{
					WeakReference weakReference2 = (WeakReference)Interlocked.CompareExchange(ref bucketSet.nextSetWeak, null, weakReference);
					if (weakReference2 == weakReference)
					{
						BucketSet bucketSet4 = null;
						do
						{
							bucketSet4 = ((weakReference2 == null) ? null : ((BucketSet)weakReference2.Target));
							if (bucketSet4 != null)
							{
								bucketSet4.TimeoutTransactions();
								weakReference2 = (WeakReference)bucketSet4.nextSetWeak;
							}
						}
						while (bucketSet4 != null);
						break;
					}
				}
				finally
				{
					Thread.EndCriticalRegion();
				}
				bucketSet2 = bucketSet;
			}
		}
	}
	internal class BucketSet
	{
		internal object nextSetWeak;

		internal BucketSet prevSet;

		private TransactionTable table;

		private long absoluteTimeout;

		internal Bucket headBucket;

		internal long AbsoluteTimeout => absoluteTimeout;

		internal BucketSet(TransactionTable table, long absoluteTimeout)
		{
			headBucket = new Bucket(this);
			this.table = table;
			this.absoluteTimeout = absoluteTimeout;
		}

		internal void Add(InternalTransaction newTx)
		{
			while (!headBucket.Add(newTx))
			{
			}
		}

		internal void TimeoutTransactions()
		{
			Bucket bucket = headBucket;
			do
			{
				bucket.TimeoutTransactions();
				WeakReference nextBucketWeak = bucket.nextBucketWeak;
				bucket = ((nextBucketWeak == null) ? null : ((Bucket)nextBucketWeak.Target));
			}
			while (bucket != null);
		}
	}
	internal class Bucket
	{
		private bool timedOut;

		private int index;

		private int size;

		private InternalTransaction[] transactions;

		internal WeakReference nextBucketWeak;

		private Bucket previous;

		private BucketSet owningSet;

		internal Bucket(BucketSet owningSet)
		{
			timedOut = false;
			index = -1;
			size = 1024;
			transactions = new InternalTransaction[size];
			this.owningSet = owningSet;
		}

		internal bool Add(InternalTransaction tx)
		{
			int num = Interlocked.Increment(ref index);
			if (num < size)
			{
				tx.tableBucket = this;
				tx.bucketIndex = num;
				Thread.MemoryBarrier();
				transactions[num] = tx;
				if (timedOut)
				{
					lock (tx)
					{
						tx.State.Timeout(tx);
					}
				}
				return true;
			}
			Bucket bucket = new Bucket(owningSet);
			bucket.nextBucketWeak = new WeakReference(this);
			Bucket bucket2 = Interlocked.CompareExchange(ref owningSet.headBucket, bucket, this);
			if (bucket2 == this)
			{
				previous = bucket;
			}
			return false;
		}

		internal void Remove(InternalTransaction tx)
		{
			transactions[tx.bucketIndex] = null;
		}

		internal void TimeoutTransactions()
		{
			int num = index;
			timedOut = true;
			Thread.MemoryBarrier();
			for (int i = 0; i <= num && i < size; i++)
			{
				InternalTransaction internalTransaction = transactions[i];
				if (internalTransaction != null)
				{
					lock (internalTransaction)
					{
						internalTransaction.State.Timeout(internalTransaction);
					}
				}
			}
		}
	}
	public struct TransactionOptions
	{
		private TimeSpan timeout;

		private IsolationLevel isolationLevel;

		public TimeSpan Timeout
		{
			get
			{
				return timeout;
			}
			set
			{
				timeout = value;
			}
		}

		public IsolationLevel IsolationLevel
		{
			get
			{
				return isolationLevel;
			}
			set
			{
				isolationLevel = value;
			}
		}

		public override int GetHashCode()
		{
			return base.GetHashCode();
		}

		public override bool Equals(object obj)
		{
			if (!(obj is TransactionOptions transactionOptions))
			{
				return false;
			}
			if (transactionOptions.timeout == timeout)
			{
				return transactionOptions.isolationLevel == isolationLevel;
			}
			return false;
		}

		public static bool operator ==(TransactionOptions x, TransactionOptions y)
		{
			return x.Equals(y);
		}

		public static bool operator !=(TransactionOptions x, TransactionOptions y)
		{
			return !x.Equals(y);
		}
	}
	[Serializable]
	public sealed class DistributedTransactionPermission : CodeAccessPermission, IUnrestrictedPermission
	{
		private bool unrestricted;

		public DistributedTransactionPermission(PermissionState state)
		{
			if (state == PermissionState.Unrestricted)
			{
				unrestricted = true;
			}
			else
			{
				unrestricted = false;
			}
		}

		public bool IsUnrestricted()
		{
			return unrestricted;
		}

		public override IPermission Copy()
		{
			DistributedTransactionPermission distributedTransactionPermission = new DistributedTransactionPermission(PermissionState.None);
			if (IsUnrestricted())
			{
				distributedTransactionPermission.unrestricted = true;
			}
			else
			{
				distributedTransactionPermission.unrestricted = false;
			}
			return distributedTransactionPermission;
		}

		public override IPermission Intersect(IPermission target)
		{
			//Discarded unreachable code: IL_0039
			try
			{
				if (target == null)
				{
					return null;
				}
				DistributedTransactionPermission distributedTransactionPermission = (DistributedTransactionPermission)target;
				if (!distributedTransactionPermission.IsUnrestricted())
				{
					return distributedTransactionPermission;
				}
				return Copy();
			}
			catch (InvalidCastException)
			{
				throw new ArgumentException(SR.GetString("ArgumentWrongType"), "target");
			}
		}

		public override IPermission Union(IPermission target)
		{
			//Discarded unreachable code: IL_003e
			try
			{
				if (target == null)
				{
					return Copy();
				}
				DistributedTransactionPermission distributedTransactionPermission = (DistributedTransactionPermission)target;
				if (distributedTransactionPermission.IsUnrestricted())
				{
					return distributedTransactionPermission;
				}
				return Copy();
			}
			catch (InvalidCastException)
			{
				throw new ArgumentException(SR.GetString("ArgumentWrongType"), "target");
			}
		}

		public override bool IsSubsetOf(IPermission target)
		{
			//Discarded unreachable code: IL_0047
			if (target == null)
			{
				return !unrestricted;
			}
			try
			{
				DistributedTransactionPermission distributedTransactionPermission = (DistributedTransactionPermission)target;
				if (!unrestricted)
				{
					return true;
				}
				if (distributedTransactionPermission.unrestricted)
				{
					return true;
				}
				return false;
			}
			catch (InvalidCastException)
			{
				throw new ArgumentException(SR.GetString("ArgumentWrongType"), "target");
			}
		}

		public override SecurityElement ToXml()
		{
			SecurityElement securityElement = new SecurityElement("IPermission");
			Type type = GetType();
			StringBuilder stringBuilder = new StringBuilder(type.Assembly.ToString());
			stringBuilder.Replace('"', '\'');
			securityElement.AddAttribute("class", type.FullName + ", " + stringBuilder);
			securityElement.AddAttribute("version", "1");
			securityElement.AddAttribute("Unrestricted", unrestricted.ToString());
			return securityElement;
		}

		public override void FromXml(SecurityElement securityElement)
		{
			if (securityElement == null)
			{
				throw new ArgumentNullException("securityElement");
			}
			if (!securityElement.Tag.Equals("IPermission"))
			{
				throw new ArgumentException(SR.GetString("ArgumentWrongType"), "securityElement");
			}
			string text = securityElement.Attribute("Unrestricted");
			if (text != null)
			{
				unrestricted = Convert.ToBoolean(text, CultureInfo.InvariantCulture);
			}
			else
			{
				unrestricted = false;
			}
		}
	}
	[AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
	public sealed class DistributedTransactionPermissionAttribute : CodeAccessSecurityAttribute
	{
		private bool unrestricted;

		public new bool Unrestricted
		{
			get
			{
				return unrestricted;
			}
			set
			{
				unrestricted = value;
			}
		}

		public DistributedTransactionPermissionAttribute(SecurityAction action)
			: base(action)
		{
		}

		public override IPermission CreatePermission()
		{
			if (Unrestricted)
			{
				return new DistributedTransactionPermission(PermissionState.Unrestricted);
			}
			return new DistributedTransactionPermission(PermissionState.None);
		}
	}
	public enum TransactionScopeOption
	{
		Required,
		RequiresNew,
		Suppress
	}
	public enum EnterpriseServicesInteropOption
	{
		None,
		Automatic,
		Full
	}
	public sealed class TransactionScope : IDisposable
	{
		private bool complete;

		private Transaction savedCurrent;

		private Transaction contextTransaction;

		private TransactionScope savedCurrentScope;

		private ContextData threadContextData;

		private Transaction expectedCurrent;

		private CommittableTransaction committableTransaction;

		private DependentTransaction dependentTransaction;

		private bool disposed;

		private Timer scopeTimer;

		private Thread scopeThread;

		private bool createdServiceDomain;

		private bool createdDoubleServiceDomain;

		private bool interopModeSpecified;

		private EnterpriseServicesInteropOption interopOption;

		internal bool ScopeComplete => complete;

		internal EnterpriseServicesInteropOption InteropMode => interopOption;

		public TransactionScope()
			: this(TransactionScopeOption.Required)
		{
		}

		public TransactionScope(TransactionScopeOption scopeOption)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption )");
			}
			if (NeedToCreateTransaction(scopeOption))
			{
				committableTransaction = new CommittableTransaction();
				expectedCurrent = committableTransaction.Clone();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				if (!(null == expectedCurrent))
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(txScopeResult: (null == committableTransaction) ? System.Transactions.Diagnostics.TransactionScopeResult.UsingExistingCurrent : System.Transactions.Diagnostics.TransactionScopeResult.CreatedTransaction, traceSource: SR.GetString("TraceSourceBase"), txTraceId: expectedCurrent.TransactionTraceId);
				}
				else
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(SR.GetString("TraceSourceBase"), TransactionTraceIdentifier.Empty, System.Transactions.Diagnostics.TransactionScopeResult.NoTransaction);
				}
			}
			PushScope();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption )");
			}
		}

		public TransactionScope(TransactionScopeOption scopeOption, TimeSpan scopeTimeout)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption, TimeSpan )");
			}
			ValidateScopeTimeout("scopeTimeout", scopeTimeout);
			TimeSpan timeout = TransactionManager.ValidateTimeout(scopeTimeout);
			if (NeedToCreateTransaction(scopeOption))
			{
				committableTransaction = new CommittableTransaction(timeout);
				expectedCurrent = committableTransaction.Clone();
			}
			if (null != expectedCurrent && null == committableTransaction && TimeSpan.Zero != scopeTimeout)
			{
				scopeTimer = new Timer(TimerCallback, this, scopeTimeout, TimeSpan.Zero);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				if (!(null == expectedCurrent))
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(txScopeResult: (null == committableTransaction) ? System.Transactions.Diagnostics.TransactionScopeResult.UsingExistingCurrent : System.Transactions.Diagnostics.TransactionScopeResult.CreatedTransaction, traceSource: SR.GetString("TraceSourceBase"), txTraceId: expectedCurrent.TransactionTraceId);
				}
				else
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(SR.GetString("TraceSourceBase"), TransactionTraceIdentifier.Empty, System.Transactions.Diagnostics.TransactionScopeResult.NoTransaction);
				}
			}
			PushScope();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption, TimeSpan )");
			}
		}

		public TransactionScope(TransactionScopeOption scopeOption, TransactionOptions transactionOptions)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption, TransactionOptions )");
			}
			ValidateScopeTimeout("transactionOptions.Timeout", transactionOptions.Timeout);
			TimeSpan timeout = transactionOptions.Timeout;
			transactionOptions.Timeout = TransactionManager.ValidateTimeout(transactionOptions.Timeout);
			TransactionManager.ValidateIsolationLevel(transactionOptions.IsolationLevel);
			if (NeedToCreateTransaction(scopeOption))
			{
				committableTransaction = new CommittableTransaction(transactionOptions);
				expectedCurrent = committableTransaction.Clone();
			}
			else if (null != expectedCurrent && IsolationLevel.Unspecified != transactionOptions.IsolationLevel && expectedCurrent.IsolationLevel != transactionOptions.IsolationLevel)
			{
				throw new ArgumentException(SR.GetString("TransactionScopeIsolationLevelDifferentFromTransaction"), "transactionOptions.IsolationLevel");
			}
			if (null != expectedCurrent && null == committableTransaction && TimeSpan.Zero != timeout)
			{
				scopeTimer = new Timer(TimerCallback, this, timeout, TimeSpan.Zero);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				if (!(null == expectedCurrent))
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(txScopeResult: (null == committableTransaction) ? System.Transactions.Diagnostics.TransactionScopeResult.UsingExistingCurrent : System.Transactions.Diagnostics.TransactionScopeResult.CreatedTransaction, traceSource: SR.GetString("TraceSourceBase"), txTraceId: expectedCurrent.TransactionTraceId);
				}
				else
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(SR.GetString("TraceSourceBase"), TransactionTraceIdentifier.Empty, System.Transactions.Diagnostics.TransactionScopeResult.NoTransaction);
				}
			}
			PushScope();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption, TransactionOptions )");
			}
		}

		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public TransactionScope(TransactionScopeOption scopeOption, TransactionOptions transactionOptions, EnterpriseServicesInteropOption interopOption)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption, TransactionOptions, EnterpriseServicesInteropOption )");
			}
			ValidateScopeTimeout("transactionOptions.Timeout", transactionOptions.Timeout);
			TimeSpan timeout = transactionOptions.Timeout;
			transactionOptions.Timeout = TransactionManager.ValidateTimeout(transactionOptions.Timeout);
			TransactionManager.ValidateIsolationLevel(transactionOptions.IsolationLevel);
			ValidateInteropOption(interopOption);
			interopModeSpecified = true;
			this.interopOption = interopOption;
			if (NeedToCreateTransaction(scopeOption))
			{
				committableTransaction = new CommittableTransaction(transactionOptions);
				expectedCurrent = committableTransaction.Clone();
			}
			else if (null != expectedCurrent && IsolationLevel.Unspecified != transactionOptions.IsolationLevel && expectedCurrent.IsolationLevel != transactionOptions.IsolationLevel)
			{
				throw new ArgumentException(SR.GetString("TransactionScopeIsolationLevelDifferentFromTransaction"), "transactionOptions.IsolationLevel");
			}
			if (null != expectedCurrent && null == committableTransaction && TimeSpan.Zero != timeout)
			{
				scopeTimer = new Timer(TimerCallback, this, timeout, TimeSpan.Zero);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				if (!(null == expectedCurrent))
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(txScopeResult: (null == committableTransaction) ? System.Transactions.Diagnostics.TransactionScopeResult.UsingExistingCurrent : System.Transactions.Diagnostics.TransactionScopeResult.CreatedTransaction, traceSource: SR.GetString("TraceSourceBase"), txTraceId: expectedCurrent.TransactionTraceId);
				}
				else
				{
					System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(SR.GetString("TraceSourceBase"), TransactionTraceIdentifier.Empty, System.Transactions.Diagnostics.TransactionScopeResult.NoTransaction);
				}
			}
			PushScope();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( TransactionScopeOption, TransactionOptions, EnterpriseServicesInteropOption )");
			}
		}

		public TransactionScope(Transaction transactionToUse)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( Transaction )");
			}
			Initialize(transactionToUse, TimeSpan.Zero, interopModeSpecified: false);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( Transaction )");
			}
		}

		public TransactionScope(Transaction transactionToUse, TimeSpan scopeTimeout)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( Transaction, TimeSpan )");
			}
			Initialize(transactionToUse, scopeTimeout, interopModeSpecified: false);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( Transaction, TimeSpan )");
			}
		}

		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public TransactionScope(Transaction transactionToUse, TimeSpan scopeTimeout, EnterpriseServicesInteropOption interopOption)
		{
			if (!TransactionManager._platformValidated)
			{
				TransactionManager.ValidatePlatform();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( Transaction, TimeSpan, EnterpriseServicesInteropOption )");
			}
			ValidateInteropOption(interopOption);
			this.interopOption = interopOption;
			Initialize(transactionToUse, scopeTimeout, interopModeSpecified: true);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.ctor( Transaction, TimeSpan, EnterpriseServicesInteropOption )");
			}
		}

		private bool NeedToCreateTransaction(TransactionScopeOption scopeOption)
		{
			bool result = false;
			CommonInitialize();
			switch (scopeOption)
			{
			case TransactionScopeOption.Suppress:
				expectedCurrent = null;
				result = false;
				break;
			case TransactionScopeOption.Required:
				expectedCurrent = savedCurrent;
				if (null == expectedCurrent)
				{
					result = true;
				}
				break;
			case TransactionScopeOption.RequiresNew:
				result = true;
				break;
			default:
				throw new ArgumentOutOfRangeException("scopeOption");
			}
			return result;
		}

		private void Initialize(Transaction transactionToUse, TimeSpan scopeTimeout, bool interopModeSpecified)
		{
			if (null == transactionToUse)
			{
				throw new ArgumentNullException("transactionToUse");
			}
			ValidateScopeTimeout("scopeTimeout", scopeTimeout);
			CommonInitialize();
			if (TimeSpan.Zero != scopeTimeout)
			{
				scopeTimer = new Timer(TimerCallback, this, scopeTimeout, TimeSpan.Zero);
			}
			expectedCurrent = transactionToUse;
			this.interopModeSpecified = interopModeSpecified;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.TransactionScopeCreatedTraceRecord.Trace(SR.GetString("TraceSourceBase"), expectedCurrent.TransactionTraceId, System.Transactions.Diagnostics.TransactionScopeResult.TransactionPassed);
			}
			PushScope();
		}

		public void Dispose()
		{
			bool flag = false;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.Dispose");
			}
			if (disposed)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.Dispose");
				}
				return;
			}
			if (scopeThread != Thread.CurrentThread)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Error)
				{
					System.Transactions.Diagnostics.InvalidOperationExceptionTraceRecord.Trace(SR.GetString("TraceSourceBase"), SR.GetString("InvalidScopeThread"));
				}
				throw new InvalidOperationException(SR.GetString("InvalidScopeThread"));
			}
			Exception ex = null;
			try
			{
				disposed = true;
				TransactionScope currentScope = threadContextData.CurrentScope;
				Transaction transaction = null;
				Transaction transaction2 = Transaction.FastGetTransaction(currentScope, threadContextData, out transaction);
				if (!Equals(currentScope))
				{
					if (currentScope == null)
					{
						Transaction transaction3 = committableTransaction;
						if (transaction3 == null)
						{
							transaction3 = dependentTransaction;
						}
						transaction3.Rollback();
						flag = true;
						throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceBase"), SR.GetString("TransactionScopeInvalidNesting"), null);
					}
					if (currentScope.interopOption == EnterpriseServicesInteropOption.None && ((null != currentScope.expectedCurrent && !currentScope.expectedCurrent.Equals(transaction2)) || (null != transaction2 && null == currentScope.expectedCurrent)))
					{
						if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
						{
							System.Transactions.Diagnostics.TransactionScopeCurrentChangedTraceRecord.Trace(currentTxTraceId: (!(null == transaction2)) ? transaction2.TransactionTraceId : TransactionTraceIdentifier.Empty, scopeTxTraceId: (!(null == expectedCurrent)) ? expectedCurrent.TransactionTraceId : TransactionTraceIdentifier.Empty, traceSource: SR.GetString("TraceSourceBase"));
						}
						ex = TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceBase"), SR.GetString("TransactionScopeIncorrectCurrent"), null);
						if (null != transaction2)
						{
							try
							{
								transaction2.Rollback();
							}
							catch (TransactionException)
							{
							}
							catch (ObjectDisposedException)
							{
							}
						}
					}
					while (!Equals(currentScope))
					{
						if (ex == null)
						{
							ex = TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceBase"), SR.GetString("TransactionScopeInvalidNesting"), null);
						}
						if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
						{
							if (null == currentScope.expectedCurrent)
							{
								System.Transactions.Diagnostics.TransactionScopeNestedIncorrectlyTraceRecord.Trace(SR.GetString("TraceSourceBase"), TransactionTraceIdentifier.Empty);
							}
							else
							{
								System.Transactions.Diagnostics.TransactionScopeNestedIncorrectlyTraceRecord.Trace(SR.GetString("TraceSourceBase"), currentScope.expectedCurrent.TransactionTraceId);
							}
						}
						currentScope.complete = false;
						try
						{
							currentScope.InternalDispose();
						}
						catch (TransactionException)
						{
						}
						currentScope = threadContextData.CurrentScope;
						complete = false;
					}
				}
				else if (interopOption == EnterpriseServicesInteropOption.None && ((null != expectedCurrent && !expectedCurrent.Equals(transaction2)) || (null != transaction2 && null == expectedCurrent)))
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
					{
						System.Transactions.Diagnostics.TransactionScopeCurrentChangedTraceRecord.Trace(currentTxTraceId: (!(null == transaction2)) ? transaction2.TransactionTraceId : TransactionTraceIdentifier.Empty, scopeTxTraceId: (!(null == expectedCurrent)) ? expectedCurrent.TransactionTraceId : TransactionTraceIdentifier.Empty, traceSource: SR.GetString("TraceSourceBase"));
					}
					if (ex == null)
					{
						ex = TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceBase"), SR.GetString("TransactionScopeIncorrectCurrent"), null);
					}
					if (null != transaction2)
					{
						try
						{
							transaction2.Rollback();
						}
						catch (TransactionException)
						{
						}
						catch (ObjectDisposedException)
						{
						}
					}
					complete = false;
				}
				flag = true;
			}
			finally
			{
				if (!flag)
				{
					PopScope();
				}
			}
			InternalDispose();
			if (ex != null)
			{
				throw ex;
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.Dispose");
			}
		}

		private void InternalDispose()
		{
			disposed = true;
			try
			{
				PopScope();
				if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
				{
					if (null == expectedCurrent)
					{
						System.Transactions.Diagnostics.TransactionScopeDisposedTraceRecord.Trace(SR.GetString("TraceSourceBase"), TransactionTraceIdentifier.Empty);
					}
					else
					{
						System.Transactions.Diagnostics.TransactionScopeDisposedTraceRecord.Trace(SR.GetString("TraceSourceBase"), expectedCurrent.TransactionTraceId);
					}
				}
				if (!(null != expectedCurrent))
				{
					return;
				}
				if (!complete)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
					{
						System.Transactions.Diagnostics.TransactionScopeIncompleteTraceRecord.Trace(SR.GetString("TraceSourceBase"), expectedCurrent.TransactionTraceId);
					}
					Transaction transaction = committableTransaction;
					if (transaction == null)
					{
						transaction = dependentTransaction;
					}
					transaction.Rollback();
				}
				else if (null != committableTransaction)
				{
					committableTransaction.Commit();
				}
				else
				{
					dependentTransaction.Complete();
				}
			}
			finally
			{
				if (scopeTimer != null)
				{
					scopeTimer.Dispose();
				}
				if (null != committableTransaction)
				{
					committableTransaction.Dispose();
					expectedCurrent.Dispose();
				}
				if (null != dependentTransaction)
				{
					dependentTransaction.Dispose();
				}
			}
		}

		public void Complete()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.Complete");
			}
			if (disposed)
			{
				throw new ObjectDisposedException("TransactionScope");
			}
			if (complete)
			{
				throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceBase"), SR.GetString("DisposeScope"), null);
			}
			complete = true;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceBase"), "TransactionScope.Complete");
			}
		}

		private static void TimerCallback(object state)
		{
			if (!(state is TransactionScope transactionScope))
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceBase"), SR.GetString("TransactionScopeTimerObjectInvalid"));
				}
				throw TransactionException.Create(SR.GetString("TraceSourceBase"), SR.GetString("InternalError") + SR.GetString("TransactionScopeTimerObjectInvalid"), null);
			}
			transactionScope.Timeout();
		}

		private void Timeout()
		{
			if (complete || !(null != expectedCurrent))
			{
				return;
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionScopeTimeoutTraceRecord.Trace(SR.GetString("TraceSourceBase"), expectedCurrent.TransactionTraceId);
			}
			try
			{
				expectedCurrent.Rollback();
			}
			catch (ObjectDisposedException exception)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceBase"), exception);
				}
			}
			catch (TransactionException exception2)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceBase"), exception2);
				}
			}
		}

		private void CommonInitialize()
		{
			complete = false;
			dependentTransaction = null;
			disposed = false;
			committableTransaction = null;
			expectedCurrent = null;
			scopeTimer = null;
			scopeThread = Thread.CurrentThread;
			Transaction.GetCurrentTransactionAndScope(out savedCurrent, out savedCurrentScope, out threadContextData, out contextTransaction);
		}

		private void PushScope()
		{
			if (!interopModeSpecified)
			{
				interopOption = Transaction.InteropMode(savedCurrentScope);
			}
			SetCurrent(expectedCurrent);
			threadContextData.CurrentScope = this;
		}

		private void PopScope()
		{
			threadContextData.CurrentScope = savedCurrentScope;
			RestoreCurrent();
		}

		private void SetCurrent(Transaction newCurrent)
		{
			if (dependentTransaction == null && committableTransaction == null && newCurrent != null)
			{
				dependentTransaction = newCurrent.DependentClone(DependentCloneOption.RollbackIfNotComplete);
			}
			switch (interopOption)
			{
			case EnterpriseServicesInteropOption.None:
				threadContextData.CurrentTransaction = newCurrent;
				break;
			case EnterpriseServicesInteropOption.Automatic:
				Transaction.VerifyEnterpriseServicesOk();
				if (Transaction.UseServiceDomainForCurrent())
				{
					PushServiceDomain(newCurrent);
				}
				else
				{
					threadContextData.CurrentTransaction = newCurrent;
				}
				break;
			case EnterpriseServicesInteropOption.Full:
				Transaction.VerifyEnterpriseServicesOk();
				PushServiceDomain(newCurrent);
				break;
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void PushServiceDomain(Transaction newCurrent)
		{
			//Discarded unreachable code: IL_00ad
			if ((newCurrent != null && newCurrent.Equals(ContextUtil.SystemTransaction)) || (newCurrent == null && ContextUtil.SystemTransaction == null))
			{
				return;
			}
			ServiceConfig serviceConfig = new ServiceConfig();
			try
			{
				if (newCurrent != null)
				{
					serviceConfig.Synchronization = SynchronizationOption.RequiresNew;
					ServiceDomain.Enter(serviceConfig);
					createdDoubleServiceDomain = true;
					serviceConfig.Synchronization = SynchronizationOption.Required;
					serviceConfig.BringYourOwnSystemTransaction = newCurrent;
				}
				ServiceDomain.Enter(serviceConfig);
				createdServiceDomain = true;
			}
			catch (COMException ex)
			{
				if (System.Transactions.Oletx.NativeMethods.XACT_E_NOTRANSACTION == ex.ErrorCode)
				{
					throw TransactionException.Create(SR.GetString("TraceSourceBase"), SR.GetString("TransactionAlreadyOver"), ex);
				}
				throw TransactionException.Create(SR.GetString("TraceSourceBase"), ex.Message, ex);
			}
			finally
			{
				if (!createdServiceDomain && createdDoubleServiceDomain)
				{
					ServiceDomain.Leave();
				}
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void JitSafeLeaveServiceDomain()
		{
			if (createdDoubleServiceDomain)
			{
				ServiceDomain.Leave();
			}
			ServiceDomain.Leave();
		}

		private void RestoreCurrent()
		{
			if (createdServiceDomain)
			{
				JitSafeLeaveServiceDomain();
			}
			threadContextData.CurrentTransaction = contextTransaction;
		}

		private void ValidateInteropOption(EnterpriseServicesInteropOption interopOption)
		{
			if (interopOption < EnterpriseServicesInteropOption.None || interopOption > EnterpriseServicesInteropOption.Full)
			{
				throw new ArgumentOutOfRangeException("interopOption");
			}
		}

		private void ValidateScopeTimeout(string paramName, TimeSpan scopeTimeout)
		{
			if (scopeTimeout < TimeSpan.Zero)
			{
				throw new ArgumentOutOfRangeException(paramName);
			}
		}
	}
	internal struct TransactionTraceIdentifier
	{
		public static readonly TransactionTraceIdentifier Empty = default(TransactionTraceIdentifier);

		private string transactionIdentifier;

		private int cloneIdentifier;

		public string TransactionIdentifier => transactionIdentifier;

		public int CloneIdentifier => cloneIdentifier;

		public TransactionTraceIdentifier(string transactionIdentifier, int cloneIdentifier)
		{
			this.transactionIdentifier = transactionIdentifier;
			this.cloneIdentifier = cloneIdentifier;
		}

		public override int GetHashCode()
		{
			return base.GetHashCode();
		}

		public override bool Equals(object objectToCompare)
		{
			if (!(objectToCompare is TransactionTraceIdentifier transactionTraceIdentifier))
			{
				return false;
			}
			if (transactionTraceIdentifier.TransactionIdentifier != TransactionIdentifier || transactionTraceIdentifier.CloneIdentifier != CloneIdentifier)
			{
				return false;
			}
			return true;
		}

		public static bool operator ==(TransactionTraceIdentifier id1, TransactionTraceIdentifier id2)
		{
			return id1.Equals(id2);
		}

		public static bool operator !=(TransactionTraceIdentifier id1, TransactionTraceIdentifier id2)
		{
			return !id1.Equals(id2);
		}
	}
	internal sealed class SafeIUnknown : SafeHandle
	{
		public override bool IsInvalid
		{
			get
			{
				if (!base.IsClosed)
				{
					return IntPtr.Zero == handle;
				}
				return true;
			}
		}

		internal SafeIUnknown()
			: base(IntPtr.Zero, ownsHandle: true)
		{
		}

		internal SafeIUnknown(IntPtr unknown)
			: base(IntPtr.Zero, ownsHandle: true)
		{
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
			}
			finally
			{
				handle = unknown;
			}
		}

		protected override bool ReleaseHandle()
		{
			IntPtr intPtr = handle;
			handle = IntPtr.Zero;
			if (IntPtr.Zero != intPtr)
			{
				Marshal.Release(intPtr);
			}
			return true;
		}
	}
}
namespace System.Transactions.Oletx
{
	internal sealed class CoTaskMemHandle : SafeHandle
	{
		public override bool IsInvalid
		{
			get
			{
				if (!base.IsClosed)
				{
					return handle == IntPtr.Zero;
				}
				return true;
			}
		}

		public CoTaskMemHandle()
			: base(IntPtr.Zero, ownsHandle: true)
		{
		}

		[DllImport("ole32.dll")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SuppressUnmanagedCodeSecurity]
		private static extern void CoTaskMemFree(IntPtr ptr);

		protected override bool ReleaseHandle()
		{
			CoTaskMemFree(handle);
			return true;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal static class NativeMethods
	{
		internal static int S_OK = 0;

		internal static int E_FAIL = -2147467259;

		internal static int XACT_S_READONLY = 315394;

		internal static int XACT_S_SINGLEPHASE = 315401;

		internal static int XACT_E_ABORTED = -2147168231;

		internal static int XACT_E_NOTRANSACTION = -2147168242;

		internal static int XACT_E_CONNECTION_DOWN = -2147168228;

		internal static int XACT_E_REENLISTTIMEOUT = -2147168226;

		internal static int XACT_E_RECOVERYALREADYDONE = -2147167996;

		internal static int XACT_E_TMNOTAVAILABLE = -2147168229;

		internal static int XACT_E_INDOUBT = -2147168234;

		internal static int XACT_E_ALREADYINPROGRESS = -2147168232;

		internal static int XACT_E_TOOMANY_ENLISTMENTS = -2147167999;

		internal static int XACT_E_PROTOCOL = -2147167995;

		internal static int XACT_E_FIRST = -2147168256;

		internal static int XACT_E_LAST = -2147168215;

		internal static int XACT_E_NOTSUPPORTED = -2147168241;

		internal static int XACT_E_NETWORK_TX_DISABLED = -2147168220;

		[DllImport("System.Transactions.Dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
		internal static extern int GetNotificationFactory(SafeHandle notificationEventHandle, [MarshalAs(UnmanagedType.Interface)] out IDtcProxyShimFactory ppProxyShimFactory);
	}
	internal enum ShimNotificationType
	{
		None,
		Phase0RequestNotify,
		VoteRequestNotify,
		PrepareRequestNotify,
		CommitRequestNotify,
		AbortRequestNotify,
		CommittedNotify,
		AbortedNotify,
		InDoubtNotify,
		EnlistmentTmDownNotify,
		ResourceManagerTmDownNotify
	}
	internal enum OletxPrepareVoteType
	{
		ReadOnly,
		SinglePhase,
		Prepared,
		Failed,
		InDoubt
	}
	internal enum OletxTransactionOutcome
	{
		NotKnownYet,
		Committed,
		Aborted
	}
	internal enum OletxTransactionIsolationLevel
	{
		ISOLATIONLEVEL_UNSPECIFIED = -1,
		ISOLATIONLEVEL_CHAOS = 16,
		ISOLATIONLEVEL_READUNCOMMITTED = 256,
		ISOLATIONLEVEL_BROWSE = 256,
		ISOLATIONLEVEL_CURSORSTABILITY = 4096,
		ISOLATIONLEVEL_READCOMMITTED = 4096,
		ISOLATIONLEVEL_REPEATABLEREAD = 65536,
		ISOLATIONLEVEL_SERIALIZABLE = 1048576,
		ISOLATIONLEVEL_ISOLATED = 1048576
	}
	[Flags]
	internal enum OletxTransactionIsoFlags
	{
		ISOFLAG_NONE = 0,
		ISOFLAG_RETAIN_COMMIT_DC = 1,
		ISOFLAG_RETAIN_COMMIT = 2,
		ISOFLAG_RETAIN_COMMIT_NO = 3,
		ISOFLAG_RETAIN_ABORT_DC = 4,
		ISOFLAG_RETAIN_ABORT = 8,
		ISOFLAG_RETAIN_ABORT_NO = 0xC,
		ISOFLAG_RETAIN_DONTCARE = 5,
		ISOFLAG_RETAIN_BOTH = 0xA,
		ISOFLAG_RETAIN_NONE = 0xF,
		ISOFLAG_OPTIMISTIC = 0x10,
		ISOFLAG_READONLY = 0x20
	}
	[Flags]
	internal enum OletxXacttc
	{
		XACTTC_NONE = 0,
		XACTTC_SYNC_PHASEONE = 1,
		XACTTC_SYNC_PHASETWO = 2,
		XACTTC_SYNC = 2,
		XACTTC_ASYNC_PHASEONE = 4,
		XACTTC_ASYNC = 4
	}
	internal enum OletxTransactionStatus
	{
		OLETX_TRANSACTION_STATUS_NONE = 0,
		OLETX_TRANSACTION_STATUS_OPENNORMAL = 1,
		OLETX_TRANSACTION_STATUS_OPENREFUSED = 2,
		OLETX_TRANSACTION_STATUS_PREPARING = 4,
		OLETX_TRANSACTION_STATUS_PREPARED = 8,
		OLETX_TRANSACTION_STATUS_PREPARERETAINING = 16,
		OLETX_TRANSACTION_STATUS_PREPARERETAINED = 32,
		OLETX_TRANSACTION_STATUS_COMMITTING = 64,
		OLETX_TRANSACTION_STATUS_COMMITRETAINING = 128,
		OLETX_TRANSACTION_STATUS_ABORTING = 256,
		OLETX_TRANSACTION_STATUS_ABORTED = 512,
		OLETX_TRANSACTION_STATUS_COMMITTED = 1024,
		OLETX_TRANSACTION_STATUS_HEURISTIC_ABORT = 2048,
		OLETX_TRANSACTION_STATUS_HEURISTIC_COMMIT = 4096,
		OLETX_TRANSACTION_STATUS_HEURISTIC_DAMAGE = 8192,
		OLETX_TRANSACTION_STATUS_HEURISTIC_DANGER = 16384,
		OLETX_TRANSACTION_STATUS_FORCED_ABORT = 32768,
		OLETX_TRANSACTION_STATUS_FORCED_COMMIT = 65536,
		OLETX_TRANSACTION_STATUS_INDOUBT = 131072,
		OLETX_TRANSACTION_STATUS_CLOSED = 262144,
		OLETX_TRANSACTION_STATUS_OPEN = 3,
		OLETX_TRANSACTION_STATUS_NOTPREPARED = 524227,
		OLETX_TRANSACTION_STATUS_ALL = 524287
	}
	[ComVisible(false)]
	internal struct OletxXactTransInfo
	{
		internal Guid uow;

		internal OletxTransactionIsolationLevel isoLevel;

		internal OletxTransactionIsoFlags isoFlags;

		internal int grfTCSupported;

		internal int grfRMSupported;

		internal int grfTCSupportedRetaining;

		internal int grfRMSupportedRetaining;

		internal OletxXactTransInfo(Guid guid, OletxTransactionIsolationLevel isoLevel)
		{
			uow = guid;
			this.isoLevel = isoLevel;
			isoFlags = OletxTransactionIsoFlags.ISOFLAG_NONE;
			grfTCSupported = 0;
			grfRMSupported = 0;
			grfTCSupportedRetaining = 0;
			grfRMSupportedRetaining = 0;
		}
	}
	[ComImport]
	[Guid("A5FAB903-21CB-49eb-93AE-EF72CD45169E")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[SuppressUnmanagedCodeSecurity]
	internal interface IVoterBallotShim
	{
		void Vote([MarshalAs(UnmanagedType.Bool)] bool voteYes);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("55FF6514-948A-4307-A692-73B84E2AF53E")]
	[SuppressUnmanagedCodeSecurity]
	internal interface IPhase0EnlistmentShim
	{
		void Unenlist();

		void Phase0Done([MarshalAs(UnmanagedType.Bool)] bool voteYes);
	}
	[ComImport]
	[SuppressUnmanagedCodeSecurity]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("5EC35E09-B285-422c-83F5-1372384A42CC")]
	internal interface IEnlistmentShim
	{
		void PrepareRequestDone(OletxPrepareVoteType voteType);

		void CommitRequestDone();

		void AbortRequestDone();
	}
	[ComImport]
	[Guid("279031AF-B00E-42e6-A617-79747E22DD22")]
	[SuppressUnmanagedCodeSecurity]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ITransactionShim
	{
		void Commit();

		void Abort();

		void GetITransactionNative([MarshalAs(UnmanagedType.Interface)] out IDtcTransaction transactionNative);

		void Export([MarshalAs(UnmanagedType.U4)] uint whereaboutsSize, [MarshalAs(UnmanagedType.LPArray)] byte[] whereabouts, [MarshalAs(UnmanagedType.I4)] out int cookieIndex, [MarshalAs(UnmanagedType.U4)] out uint cookieSize, out CoTaskMemHandle cookieBuffer);

		void CreateVoter(IntPtr managedIdentifier, [MarshalAs(UnmanagedType.Interface)] out IVoterBallotShim voterBallotShim);

		void GetPropagationToken([MarshalAs(UnmanagedType.U4)] out uint propagationTokeSize, out CoTaskMemHandle propgationToken);

		void Phase0Enlist(IntPtr managedIdentifier, [MarshalAs(UnmanagedType.Interface)] out IPhase0EnlistmentShim phase0EnlistmentShim);

		void GetTransactionDoNotUse(out IntPtr transaction);
	}
	[ComImport]
	[SuppressUnmanagedCodeSecurity]
	[Guid("27C73B91-99F5-46d5-A247-732A1A16529E")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IResourceManagerShim
	{
		void Enlist([MarshalAs(UnmanagedType.Interface)] ITransactionShim transactionShim, IntPtr managedIdentifier, [MarshalAs(UnmanagedType.Interface)] out IEnlistmentShim enlistmentShim);

		void Reenlist([MarshalAs(UnmanagedType.U4)] uint prepareInfoSize, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] prepareInfo, out OletxTransactionOutcome outcome);

		void ReenlistComplete();
	}
	[ComImport]
	[Guid("467C8BCB-BDDE-4885-B143-317107468275")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[SuppressUnmanagedCodeSecurity]
	internal interface IDtcProxyShimFactory
	{
		void ConnectToProxy([MarshalAs(UnmanagedType.LPWStr)] string nodeName, Guid resourceManagerIdentifier, IntPtr managedIdentifier, [MarshalAs(UnmanagedType.Bool)] out bool nodeNameMatches, [MarshalAs(UnmanagedType.U4)] out uint whereaboutsSize, out CoTaskMemHandle whereaboutsBuffer, [MarshalAs(UnmanagedType.Interface)] out IResourceManagerShim resourceManagerShim);

		void GetNotification(out IntPtr managedIdentifier, [MarshalAs(UnmanagedType.I4)] out ShimNotificationType shimNotificationType, [MarshalAs(UnmanagedType.Bool)] out bool isSinglePhase, [MarshalAs(UnmanagedType.Bool)] out bool abortingHint, [MarshalAs(UnmanagedType.Bool)] out bool releaseRequired, [MarshalAs(UnmanagedType.U4)] out uint prepareInfoSize, out CoTaskMemHandle prepareInfo);

		void ReleaseNotificationLock();

		void BeginTransaction([MarshalAs(UnmanagedType.U4)] uint timeout, OletxTransactionIsolationLevel isolationLevel, IntPtr managedIdentifier, out Guid transactionIdentifier, [MarshalAs(UnmanagedType.Interface)] out ITransactionShim transactionShim);

		void CreateResourceManager(Guid resourceManagerIdentifier, IntPtr managedIdentifier, [MarshalAs(UnmanagedType.Interface)] out IResourceManagerShim resourceManagerShim);

		void Import([MarshalAs(UnmanagedType.U4)] uint cookieSize, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] byte[] cookie, IntPtr managedIdentifier, out Guid transactionIdentifier, out OletxTransactionIsolationLevel isolationLevel, [MarshalAs(UnmanagedType.Interface)] out ITransactionShim transactionShim);

		void ReceiveTransaction([MarshalAs(UnmanagedType.U4)] uint propgationTokenSize, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] byte[] propgationToken, IntPtr managedIdentifier, out Guid transactionIdentifier, out OletxTransactionIsolationLevel isolationLevel, [MarshalAs(UnmanagedType.Interface)] out ITransactionShim transactionShim);

		void CreateTransactionShim([MarshalAs(UnmanagedType.Interface)] IDtcTransaction transactionNative, IntPtr managedIdentifier, out Guid transactionIdentifier, out OletxTransactionIsolationLevel isolationLevel, [MarshalAs(UnmanagedType.Interface)] out ITransactionShim transactionShim);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("0fb15084-af41-11ce-bd2b-204c4f4f5020")]
	[SuppressUnmanagedCodeSecurity]
	internal interface ITransactionNativeInternal
	{
		void Commit(int retaining, [MarshalAs(UnmanagedType.I4)] OletxXacttc commitType, int reserved);

		void Abort(IntPtr reason, int retaining, int async);

		void GetTransactionInfo(out OletxXactTransInfo xactInfo);
	}
	internal class DtcTransactionManager
	{
		private string nodeName;

		private OletxTransactionManager oletxTm;

		private IDtcProxyShimFactory proxyShimFactory;

		private uint whereaboutsSize;

		private byte[] whereabouts;

		private bool initialized;

		internal IDtcProxyShimFactory ProxyShimFactory
		{
			get
			{
				if (!initialized)
				{
					lock (this)
					{
						Initialize();
					}
				}
				return proxyShimFactory;
			}
		}

		internal byte[] Whereabouts
		{
			get
			{
				if (!initialized)
				{
					lock (this)
					{
						Initialize();
					}
				}
				return whereabouts;
			}
		}

		internal DtcTransactionManager(string nodeName, OletxTransactionManager oletxTm)
		{
			this.nodeName = nodeName;
			this.oletxTm = oletxTm;
			initialized = false;
			proxyShimFactory = OletxTransactionManager.proxyShimFactory;
		}

		private void Initialize()
		{
			//Discarded unreachable code: IL_00f7
			if (initialized)
			{
				return;
			}
			OletxInternalResourceManager internalResourceManager = oletxTm.internalResourceManager;
			IntPtr intPtr = IntPtr.Zero;
			IResourceManagerShim resourceManagerShim = null;
			bool nodeNameMatches = false;
			CoTaskMemHandle whereaboutsBuffer = null;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				intPtr = HandleTable.AllocHandle(internalResourceManager);
				proxyShimFactory.ConnectToProxy(nodeName, internalResourceManager.Identifier, intPtr, out nodeNameMatches, out whereaboutsSize, out whereaboutsBuffer, out resourceManagerShim);
				if (!nodeNameMatches)
				{
					throw new NotSupportedException(SR.GetString("ProxyCannotSupportMultipleNodeNames"));
				}
				if (whereaboutsBuffer != null && whereaboutsSize != 0)
				{
					whereabouts = new byte[whereaboutsSize];
					Marshal.Copy(whereaboutsBuffer.DangerousGetHandle(), whereabouts, 0, Convert.ToInt32(whereaboutsSize));
				}
				internalResourceManager.resourceManagerShim = resourceManagerShim;
				internalResourceManager.CallReenlistComplete();
				initialized = true;
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_NOTSUPPORTED == ex.ErrorCode)
				{
					throw new NotSupportedException(SR.GetString("CannotSupportNodeNameSpecification"));
				}
				OletxTransactionManager.ProxyException(ex);
				throw TransactionManagerCommunicationException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionManagerCommunicationException"), ex);
			}
			finally
			{
				whereaboutsBuffer?.Close();
				if (!initialized)
				{
					if (intPtr != IntPtr.Zero && resourceManagerShim == null)
					{
						HandleTable.FreeHandle(intPtr);
					}
					if (whereabouts != null)
					{
						whereabouts = null;
						whereaboutsSize = 0u;
					}
				}
			}
		}

		internal void ReleaseProxy()
		{
			lock (this)
			{
				whereabouts = null;
				whereaboutsSize = 0u;
				initialized = false;
			}
		}

		internal static uint AdjustTimeout(TimeSpan timeout)
		{
			uint num = 0u;
			try
			{
				return Convert.ToUInt32(timeout.TotalMilliseconds, CultureInfo.CurrentCulture);
			}
			catch (OverflowException exception)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), exception);
				}
				return uint.MaxValue;
			}
		}
	}
	internal static class HandleTable
	{
		private static Dictionary<int, object> handleTable = new Dictionary<int, object>(256);

		private static object syncRoot = new object();

		private static int currentHandle;

		public static IntPtr AllocHandle(object target)
		{
			lock (syncRoot)
			{
				int num = FindAvailableHandle();
				handleTable.Add(num, target);
				return new IntPtr(num);
			}
		}

		public static bool FreeHandle(IntPtr handle)
		{
			lock (syncRoot)
			{
				return handleTable.Remove(handle.ToInt32());
			}
		}

		public static object FindHandle(IntPtr handle)
		{
			lock (syncRoot)
			{
				if (!handleTable.TryGetValue(handle.ToInt32(), out var value))
				{
					return null;
				}
				return value;
			}
		}

		private static int FindAvailableHandle()
		{
			int num = 0;
			do
			{
				num = ((++currentHandle != 0) ? currentHandle : (++currentHandle));
			}
			while (handleTable.ContainsKey(num));
			return num;
		}
	}
	[Serializable]
	internal class OletxTransaction : ISerializable, IObjectReference
	{
		protected const string propagationTokenString = "OletxTransactionPropagationToken";

		internal RealOletxTransaction realOletxTransaction;

		private byte[] propagationTokenForDeserialize;

		protected int disposed;

		internal Transaction savedLtmPromotedTransaction;

		private TransactionTraceIdentifier traceIdentifier = TransactionTraceIdentifier.Empty;

		internal RealOletxTransaction RealTransaction => realOletxTransaction;

		internal Guid Identifier
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.get_Identifier");
				}
				Guid identifier = realOletxTransaction.Identifier;
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.get_Identifier");
				}
				return identifier;
			}
		}

		internal TransactionStatus Status
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.get_Status");
				}
				TransactionStatus status = realOletxTransaction.Status;
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.get_Status");
				}
				return status;
			}
		}

		internal Exception InnerException => realOletxTransaction.innerException;

		internal TransactionTraceIdentifier TransactionTraceId
		{
			get
			{
				if (TransactionTraceIdentifier.Empty == traceIdentifier)
				{
					lock (realOletxTransaction)
					{
						if (TransactionTraceIdentifier.Empty == traceIdentifier)
						{
							try
							{
								TransactionTraceIdentifier transactionTraceIdentifier = new TransactionTraceIdentifier(realOletxTransaction.Identifier.ToString(), 0);
								Thread.MemoryBarrier();
								traceIdentifier = transactionTraceIdentifier;
							}
							catch (TransactionException exception)
							{
								if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
								{
									System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), exception);
								}
							}
						}
					}
				}
				return traceIdentifier;
			}
		}

		public virtual IsolationLevel IsolationLevel => realOletxTransaction.TransactionIsolationLevel;

		internal OletxTransaction(RealOletxTransaction realOletxTransaction)
		{
			this.realOletxTransaction = realOletxTransaction;
			this.realOletxTransaction.OletxTransactionCreated();
		}

		protected OletxTransaction(SerializationInfo serializationInfo, StreamingContext context)
		{
			if (serializationInfo == null)
			{
				throw new ArgumentNullException("serializationInfo");
			}
			propagationTokenForDeserialize = (byte[])serializationInfo.GetValue("OletxTransactionPropagationToken", typeof(byte[]));
			if (propagationTokenForDeserialize.Length < 24)
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "serializationInfo");
			}
		}

		public object GetRealObject(StreamingContext context)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "IObjectReference.GetRealObject");
			}
			if (propagationTokenForDeserialize == null)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), SR.GetString("UnableToDeserializeTransaction"));
				}
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("UnableToDeserializeTransactionInternalError"), null);
			}
			if (null != savedLtmPromotedTransaction)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "IObjectReference.GetRealObject");
				}
				return savedLtmPromotedTransaction;
			}
			Transaction transaction = (savedLtmPromotedTransaction = TransactionInterop.GetTransactionFromTransmitterPropagationToken(propagationTokenForDeserialize));
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.TransactionDeserializedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), transaction.internalTransaction.PromotedTransaction.TransactionTraceId);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "IObjectReference.GetRealObject");
			}
			return transaction;
		}

		internal void Dispose()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "IDisposable.Dispose");
			}
			if (Interlocked.CompareExchange(ref disposed, 1, 0) == 0)
			{
				realOletxTransaction.OletxTransactionDisposed();
			}
			GC.SuppressFinalize(this);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "IDisposable.Dispose");
			}
		}

		internal void Rollback()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.Rollback");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.TransactionRollbackCalledTraceRecord.Trace(SR.GetString("TraceSourceOletx"), TransactionTraceId);
			}
			realOletxTransaction.Rollback();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.Rollback");
			}
		}

		internal IPromotedEnlistment EnlistVolatile(ISinglePhaseNotificationInternal singlePhaseNotification, EnlistmentOptions enlistmentOptions)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.EnlistVolatile( ISinglePhaseNotificationInternal )");
			}
			if (realOletxTransaction == null || realOletxTransaction.TooLateForEnlistments)
			{
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TooLate"), null);
			}
			IPromotedEnlistment result = realOletxTransaction.EnlistVolatile(singlePhaseNotification, enlistmentOptions, this);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.EnlistVolatile( ISinglePhaseNotificationInternal )");
			}
			return result;
		}

		internal IPromotedEnlistment EnlistVolatile(IEnlistmentNotificationInternal enlistmentNotification, EnlistmentOptions enlistmentOptions)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.EnlistVolatile( IEnlistmentNotificationInternal )");
			}
			if (realOletxTransaction == null || realOletxTransaction.TooLateForEnlistments)
			{
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TooLate"), null);
			}
			IPromotedEnlistment result = realOletxTransaction.EnlistVolatile(enlistmentNotification, enlistmentOptions, this);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.EnlistVolatile( IEnlistmentNotificationInternal )");
			}
			return result;
		}

		internal IPromotedEnlistment EnlistDurable(Guid resourceManagerIdentifier, ISinglePhaseNotificationInternal singlePhaseNotification, bool canDoSinglePhase, EnlistmentOptions enlistmentOptions)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.EnlistDurable( ISinglePhaseNotificationInternal )");
			}
			if (realOletxTransaction == null || realOletxTransaction.TooLateForEnlistments)
			{
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TooLate"), null);
			}
			OletxTransactionManager oletxTransactionManagerInstance = realOletxTransaction.OletxTransactionManagerInstance;
			OletxResourceManager oletxResourceManager = oletxTransactionManagerInstance.FindOrRegisterResourceManager(resourceManagerIdentifier);
			OletxEnlistment result = oletxResourceManager.EnlistDurable(this, canDoSinglePhase, singlePhaseNotification, enlistmentOptions);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.EnlistDurable( ISinglePhaseNotificationInternal )");
			}
			return result;
		}

		internal OletxDependentTransaction DependentClone(bool delayCommit)
		{
			OletxDependentTransaction oletxDependentTransaction = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.DependentClone");
			}
			if (TransactionStatus.Aborted == Status)
			{
				throw TransactionAbortedException.Create(SR.GetString("TraceSourceOletx"), realOletxTransaction.innerException);
			}
			if (TransactionStatus.InDoubt == Status)
			{
				throw TransactionInDoubtException.Create(SR.GetString("TraceSourceOletx"), realOletxTransaction.innerException);
			}
			if (Status != 0)
			{
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionAlreadyOver"), null);
			}
			oletxDependentTransaction = new OletxDependentTransaction(realOletxTransaction, delayCommit);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.DependentClone");
			}
			return oletxDependentTransaction;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
		public void GetObjectData(SerializationInfo serializationInfo, StreamingContext context)
		{
			if (serializationInfo == null)
			{
				throw new ArgumentNullException("serializationInfo");
			}
			byte[] array = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.GetObjectData");
			}
			array = TransactionInterop.GetTransmitterPropagationToken(this);
			serializationInfo.SetType(typeof(OletxTransaction));
			serializationInfo.AddValue("OletxTransactionPropagationToken", array);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.TransactionSerializedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), TransactionTraceId);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransaction.GetObjectData");
			}
		}
	}
	[Serializable]
	internal class OletxCommittableTransaction : OletxTransaction
	{
		private bool commitCalled;

		internal bool CommitCalled => commitCalled;

		internal OletxCommittableTransaction(RealOletxTransaction realOletxTransaction)
			: base(realOletxTransaction)
		{
			realOletxTransaction.committableTransaction = this;
		}

		internal void BeginCommit(InternalTransaction internalTransaction)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "CommittableTransaction.BeginCommit");
				System.Transactions.Diagnostics.TransactionCommitCalledTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.TransactionTraceId);
			}
			realOletxTransaction.InternalTransaction = internalTransaction;
			commitCalled = true;
			realOletxTransaction.Commit();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "CommittableTransaction.BeginCommit");
			}
		}
	}
	[Serializable]
	internal class OletxDependentTransaction : OletxTransaction
	{
		private OletxVolatileEnlistmentContainer volatileEnlistmentContainer;

		private int completed;

		internal OletxDependentTransaction(RealOletxTransaction realTransaction, bool delayCommit)
			: base(realTransaction)
		{
			if (realTransaction == null)
			{
				throw new ArgumentNullException("realTransaction");
			}
			volatileEnlistmentContainer = realOletxTransaction.AddDependentClone(delayCommit);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.DependentCloneCreatedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.TransactionTraceId, (!delayCommit) ? DependentCloneOption.RollbackIfNotComplete : DependentCloneOption.BlockCommitUntilComplete);
			}
		}

		public void Complete()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "DependentTransaction.Complete");
			}
			int num = Interlocked.CompareExchange(ref completed, 1, 0);
			if (1 == num)
			{
				throw TransactionException.CreateTransactionCompletedException(SR.GetString("TraceSourceOletx"));
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.DependentCloneCompleteTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.TransactionTraceId);
			}
			volatileEnlistmentContainer.DependentCloneCompleted();
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "DependentTransaction.Complete");
			}
		}
	}
	[Serializable]
	internal class OletxRecoveryInformation
	{
		internal byte[] proxyRecoveryInformation;

		internal OletxRecoveryInformation(byte[] proxyRecoveryInformation)
		{
			this.proxyRecoveryInformation = proxyRecoveryInformation;
		}
	}
	internal abstract class OletxBaseEnlistment
	{
		protected Guid enlistmentGuid;

		protected OletxResourceManager oletxResourceManager;

		protected OletxTransaction oletxTransaction;

		protected string transactionGuidString;

		protected int enlistmentId;

		internal EnlistmentTraceIdentifier traceIdentifier;

		protected InternalEnlistment internalEnlistment;

		protected EnlistmentTraceIdentifier InternalTraceIdentifier
		{
			get
			{
				if (EnlistmentTraceIdentifier.Empty == traceIdentifier)
				{
					lock (this)
					{
						if (EnlistmentTraceIdentifier.Empty == traceIdentifier)
						{
							Guid resourceManagerIdentifier = Guid.Empty;
							if (oletxResourceManager != null)
							{
								resourceManagerIdentifier = oletxResourceManager.resourceManagerIdentifier;
							}
							EnlistmentTraceIdentifier enlistmentTraceIdentifier;
							if (oletxTransaction != null)
							{
								enlistmentTraceIdentifier = new EnlistmentTraceIdentifier(resourceManagerIdentifier, oletxTransaction.TransactionTraceId, enlistmentId);
							}
							else
							{
								TransactionTraceIdentifier transactionTraceId = new TransactionTraceIdentifier(transactionGuidString, 0);
								enlistmentTraceIdentifier = new EnlistmentTraceIdentifier(resourceManagerIdentifier, transactionTraceId, enlistmentId);
							}
							Thread.MemoryBarrier();
							traceIdentifier = enlistmentTraceIdentifier;
						}
					}
				}
				return traceIdentifier;
			}
		}

		public OletxBaseEnlistment(OletxResourceManager oletxResourceManager, OletxTransaction oletxTransaction)
		{
			_ = Guid.Empty;
			enlistmentGuid = Guid.NewGuid();
			this.oletxResourceManager = oletxResourceManager;
			this.oletxTransaction = oletxTransaction;
			if (oletxTransaction != null)
			{
				enlistmentId = oletxTransaction.realOletxTransaction.enlistmentCount++;
				transactionGuidString = oletxTransaction.realOletxTransaction.TxGuid.ToString();
			}
			else
			{
				Guid empty = Guid.Empty;
				transactionGuidString = empty.ToString();
			}
			traceIdentifier = EnlistmentTraceIdentifier.Empty;
		}

		protected void AddToEnlistmentTable()
		{
			lock (oletxResourceManager.enlistmentHashtable.SyncRoot)
			{
				oletxResourceManager.enlistmentHashtable.Add(enlistmentGuid, this);
			}
		}

		protected void RemoveFromEnlistmentTable()
		{
			lock (oletxResourceManager.enlistmentHashtable.SyncRoot)
			{
				oletxResourceManager.enlistmentHashtable.Remove(enlistmentGuid);
			}
		}
	}
	internal class OletxEnlistment : OletxBaseEnlistment, IPromotedEnlistment
	{
		internal enum OletxEnlistmentState
		{
			Active,
			Phase0Preparing,
			Preparing,
			SinglePhaseCommitting,
			Prepared,
			Committing,
			Committed,
			Aborting,
			Aborted,
			InDoubt,
			Done
		}

		private IEnlistmentShim enlistmentShim;

		private IPhase0EnlistmentShim phase0Shim;

		private bool canDoSinglePhase;

		private IEnlistmentNotificationInternal iEnlistmentNotification;

		private byte[] proxyPrepareInfoByteArray;

		private OletxEnlistmentState state;

		private bool isSinglePhase;

		private Guid transactionGuid = Guid.Empty;

		internal IntPtr phase1Handle = IntPtr.Zero;

		private bool fabricateRollback;

		private bool tmWentDown;

		private bool aborting;

		private byte[] prepareInfoByteArray;

		internal Guid TransactionIdentifier => transactionGuid;

		internal IEnlistmentNotificationInternal EnlistmentNotification => iEnlistmentNotification;

		internal IEnlistmentShim EnlistmentShim
		{
			get
			{
				return enlistmentShim;
			}
			set
			{
				enlistmentShim = value;
			}
		}

		internal IPhase0EnlistmentShim Phase0EnlistmentShim
		{
			get
			{
				return phase0Shim;
			}
			set
			{
				lock (this)
				{
					if (value != null && (aborting || tmWentDown))
					{
						value.Phase0Done(voteYes: false);
					}
					phase0Shim = value;
				}
			}
		}

		internal OletxEnlistmentState State
		{
			get
			{
				return state;
			}
			set
			{
				state = value;
			}
		}

		internal byte[] ProxyPrepareInfoByteArray => proxyPrepareInfoByteArray;

		public EnlistmentTraceIdentifier EnlistmentTraceId
		{
			get
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.get_TraceIdentifier");
					System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.get_TraceIdentifier");
				}
				return base.InternalTraceIdentifier;
			}
		}

		public InternalEnlistment InternalEnlistment
		{
			get
			{
				return internalEnlistment;
			}
			set
			{
				internalEnlistment = value;
			}
		}

		internal OletxEnlistment(bool canDoSinglePhase, IEnlistmentNotificationInternal enlistmentNotification, Guid transactionGuid, EnlistmentOptions enlistmentOptions, OletxResourceManager oletxResourceManager, OletxTransaction oletxTransaction)
			: base(oletxResourceManager, oletxTransaction)
		{
			_ = Guid.Empty;
			enlistmentShim = null;
			phase0Shim = null;
			this.canDoSinglePhase = canDoSinglePhase;
			iEnlistmentNotification = enlistmentNotification;
			state = OletxEnlistmentState.Active;
			this.transactionGuid = transactionGuid;
			proxyPrepareInfoByteArray = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentType.Durable, enlistmentOptions);
			}
			AddToEnlistmentTable();
		}

		internal OletxEnlistment(IEnlistmentNotificationInternal enlistmentNotification, OletxTransactionStatus xactStatus, byte[] prepareInfoByteArray, OletxResourceManager oletxResourceManager)
			: base(oletxResourceManager, null)
		{
			_ = Guid.Empty;
			enlistmentShim = null;
			phase0Shim = null;
			canDoSinglePhase = false;
			iEnlistmentNotification = enlistmentNotification;
			state = OletxEnlistmentState.Active;
			int num = prepareInfoByteArray.Length;
			proxyPrepareInfoByteArray = new byte[num];
			Array.Copy(prepareInfoByteArray, proxyPrepareInfoByteArray, num);
			byte[] array = new byte[16];
			Array.Copy(proxyPrepareInfoByteArray, array, 16);
			transactionGuid = new Guid(array);
			transactionGuidString = transactionGuid.ToString();
			switch (xactStatus)
			{
			case OletxTransactionStatus.OLETX_TRANSACTION_STATUS_ABORTED:
				state = OletxEnlistmentState.Aborting;
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Rollback);
				}
				iEnlistmentNotification.Rollback(this);
				break;
			case OletxTransactionStatus.OLETX_TRANSACTION_STATUS_COMMITTED:
				state = OletxEnlistmentState.Committing;
				lock (oletxResourceManager.reenlistList)
				{
					oletxResourceManager.reenlistPendingList.Add(this);
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Commit);
				}
				iEnlistmentNotification.Commit(this);
				break;
			case OletxTransactionStatus.OLETX_TRANSACTION_STATUS_PREPARED:
				state = OletxEnlistmentState.Prepared;
				lock (oletxResourceManager.reenlistList)
				{
					oletxResourceManager.reenlistList.Add(this);
					oletxResourceManager.StartReenlistThread();
				}
				break;
			default:
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), SR.GetString("OletxEnlistmentUnexpectedTransactionStatus"));
				}
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("OletxEnlistmentUnexpectedTransactionStatus"), null);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentType.Durable, EnlistmentOptions.None);
			}
			AddToEnlistmentTable();
		}

		internal void FinishEnlistment()
		{
			lock (this)
			{
				if (enlistmentShim == null)
				{
					oletxResourceManager.RemoveFromReenlistPending(this);
				}
				iEnlistmentNotification = null;
				RemoveFromEnlistmentTable();
			}
		}

		internal void TMDownFromInternalRM(OletxTransactionManager oletxTm)
		{
			lock (this)
			{
				if (oletxTransaction == null || oletxTm == oletxTransaction.realOletxTransaction.OletxTransactionManagerInstance)
				{
					tmWentDown = true;
				}
			}
		}

		public bool PrepareRequest(bool singlePhase, byte[] prepareInfo)
		{
			//Discarded unreachable code: IL_014b, IL_0171
			IEnlistmentShim enlistmentShim = null;
			OletxEnlistmentState oletxEnlistmentState = OletxEnlistmentState.Active;
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			OletxRecoveryInformation oletxRecoveryInformation = null;
			lock (this)
			{
				oletxEnlistmentState = ((state != 0) ? state : (state = OletxEnlistmentState.Preparing));
				enlistmentNotificationInternal = iEnlistmentNotification;
				enlistmentShim = EnlistmentShim;
				oletxTransaction.realOletxTransaction.TooLateForEnlistments = true;
			}
			if (OletxEnlistmentState.Preparing == oletxEnlistmentState)
			{
				oletxRecoveryInformation = new OletxRecoveryInformation(prepareInfo);
				isSinglePhase = singlePhase;
				long num = prepareInfo.Length;
				proxyPrepareInfoByteArray = new byte[num];
				Array.Copy(prepareInfo, proxyPrepareInfoByteArray, num);
				if (isSinglePhase && canDoSinglePhase)
				{
					ISinglePhaseNotificationInternal singlePhaseNotificationInternal = (ISinglePhaseNotificationInternal)enlistmentNotificationInternal;
					state = OletxEnlistmentState.SinglePhaseCommitting;
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.SinglePhaseCommit);
					}
					singlePhaseNotificationInternal.SinglePhaseCommit(this);
					return true;
				}
				byte[] resourceManagerRecoveryInformation = TransactionManager.ConvertToByteArray(oletxRecoveryInformation);
				state = OletxEnlistmentState.Preparing;
				prepareInfoByteArray = TransactionManager.GetRecoveryInformation(oletxResourceManager.oletxTransactionManager.CreationNodeName, resourceManagerRecoveryInformation);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Prepare);
				}
				enlistmentNotificationInternal.Prepare(this);
				return false;
			}
			if (OletxEnlistmentState.Prepared == oletxEnlistmentState)
			{
				try
				{
					enlistmentShim.PrepareRequestDone(OletxPrepareVoteType.Prepared);
					return false;
				}
				catch (COMException comException)
				{
					OletxTransactionManager.ProxyException(comException);
					throw;
				}
			}
			if (OletxEnlistmentState.Done == oletxEnlistmentState)
			{
				try
				{
					try
					{
						enlistmentShim.PrepareRequestDone(OletxPrepareVoteType.ReadOnly);
						return true;
					}
					finally
					{
						FinishEnlistment();
					}
				}
				catch (COMException comException2)
				{
					OletxTransactionManager.ProxyException(comException2);
					throw;
				}
			}
			try
			{
				enlistmentShim.PrepareRequestDone(OletxPrepareVoteType.Failed);
			}
			catch (COMException exception)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), exception);
				}
			}
			return true;
		}

		public void CommitRequest()
		{
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			IEnlistmentShim enlistmentShim = null;
			bool flag = false;
			lock (this)
			{
				if (OletxEnlistmentState.Prepared == state)
				{
					state = OletxEnlistmentState.Committing;
					enlistmentNotificationInternal = iEnlistmentNotification;
				}
				else
				{
					enlistmentShim = EnlistmentShim;
					flag = true;
				}
			}
			if (enlistmentNotificationInternal != null)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Commit);
				}
				enlistmentNotificationInternal.Commit(this);
			}
			else
			{
				if (enlistmentShim == null)
				{
					return;
				}
				try
				{
					enlistmentShim.CommitRequestDone();
				}
				catch (COMException ex)
				{
					if (NativeMethods.XACT_E_CONNECTION_DOWN == ex.ErrorCode || NativeMethods.XACT_E_TMNOTAVAILABLE == ex.ErrorCode)
					{
						flag = true;
						if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
						{
							System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
						}
						return;
					}
					throw;
				}
				finally
				{
					if (flag)
					{
						FinishEnlistment();
					}
				}
			}
		}

		public void AbortRequest()
		{
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			IEnlistmentShim enlistmentShim = null;
			bool flag = false;
			lock (this)
			{
				if (state == OletxEnlistmentState.Active || OletxEnlistmentState.Prepared == state)
				{
					state = OletxEnlistmentState.Aborting;
					enlistmentNotificationInternal = iEnlistmentNotification;
				}
				else
				{
					if (OletxEnlistmentState.Phase0Preparing == state)
					{
						fabricateRollback = true;
					}
					else
					{
						flag = true;
					}
					enlistmentShim = EnlistmentShim;
				}
			}
			if (enlistmentNotificationInternal != null)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Rollback);
				}
				enlistmentNotificationInternal.Rollback(this);
			}
			else
			{
				if (enlistmentShim == null)
				{
					return;
				}
				try
				{
					enlistmentShim.AbortRequestDone();
				}
				catch (COMException ex)
				{
					if (NativeMethods.XACT_E_CONNECTION_DOWN == ex.ErrorCode || NativeMethods.XACT_E_TMNOTAVAILABLE == ex.ErrorCode)
					{
						flag = true;
						if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
						{
							System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
						}
						return;
					}
					throw;
				}
				finally
				{
					if (flag)
					{
						FinishEnlistment();
					}
				}
			}
		}

		public void TMDown()
		{
			lock (oletxResourceManager.reenlistList)
			{
				lock (this)
				{
					tmWentDown = true;
					if (OletxEnlistmentState.Prepared == state || OletxEnlistmentState.Committing == state)
					{
						oletxResourceManager.reenlistList.Add(this);
					}
				}
			}
		}

		public void Phase0Request(bool abortingHint)
		{
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			OletxEnlistmentState oletxEnlistmentState = OletxEnlistmentState.Active;
			OletxCommittableTransaction oletxCommittableTransaction = null;
			bool flag = false;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.Phase0Request");
			}
			oletxCommittableTransaction = oletxTransaction.realOletxTransaction.committableTransaction;
			if (oletxCommittableTransaction != null && !oletxCommittableTransaction.CommitCalled)
			{
				flag = true;
			}
			lock (this)
			{
				aborting = abortingHint;
				if (state == OletxEnlistmentState.Active)
				{
					if (aborting || flag || tmWentDown)
					{
						if (phase0Shim != null)
						{
							try
							{
								phase0Shim.Phase0Done(voteYes: false);
							}
							catch (COMException exception)
							{
								if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
								{
									System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), exception);
								}
							}
						}
					}
					else
					{
						oletxEnlistmentState = (state = OletxEnlistmentState.Phase0Preparing);
						enlistmentNotificationInternal = iEnlistmentNotification;
					}
				}
			}
			if (enlistmentNotificationInternal != null)
			{
				if (OletxEnlistmentState.Phase0Preparing != oletxEnlistmentState)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.Phase0Request");
					}
					return;
				}
				byte[] array = transactionGuid.ToByteArray();
				byte[] array2 = oletxResourceManager.resourceManagerIdentifier.ToByteArray();
				byte[] array3 = new byte[array.Length + array2.Length];
				Thread.MemoryBarrier();
				proxyPrepareInfoByteArray = array3;
				int num = 0;
				for (num = 0; num < array.Length; num++)
				{
					proxyPrepareInfoByteArray[num] = array[num];
				}
				for (num = 0; num < array2.Length; num++)
				{
					proxyPrepareInfoByteArray[array.Length + num] = array2[num];
				}
				OletxRecoveryInformation thingToConvert = new OletxRecoveryInformation(proxyPrepareInfoByteArray);
				byte[] resourceManagerRecoveryInformation = TransactionManager.ConvertToByteArray(thingToConvert);
				prepareInfoByteArray = TransactionManager.GetRecoveryInformation(oletxResourceManager.oletxTransactionManager.CreationNodeName, resourceManagerRecoveryInformation);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Prepare);
				}
				enlistmentNotificationInternal.Prepare(this);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.Phase0Request");
			}
		}

		public void EnlistmentDone()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.EnlistmentDone");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.Done);
			}
			IEnlistmentShim enlistmentShim = null;
			IPhase0EnlistmentShim phase0EnlistmentShim = null;
			OletxEnlistmentState oletxEnlistmentState = OletxEnlistmentState.Active;
			bool flag = false;
			bool flag2;
			lock (this)
			{
				oletxEnlistmentState = state;
				if (state == OletxEnlistmentState.Active)
				{
					phase0EnlistmentShim = Phase0EnlistmentShim;
					if (phase0EnlistmentShim != null)
					{
						oletxTransaction.realOletxTransaction.DecrementUndecidedEnlistments();
					}
					flag2 = false;
				}
				else if (OletxEnlistmentState.Preparing == state)
				{
					enlistmentShim = EnlistmentShim;
					flag2 = true;
				}
				else if (OletxEnlistmentState.Phase0Preparing == state)
				{
					phase0EnlistmentShim = Phase0EnlistmentShim;
					oletxTransaction.realOletxTransaction.DecrementUndecidedEnlistments();
					flag2 = (fabricateRollback ? true : false);
				}
				else
				{
					if (OletxEnlistmentState.Committing != state && OletxEnlistmentState.Aborting != state && OletxEnlistmentState.SinglePhaseCommitting != state)
					{
						throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
					}
					enlistmentShim = EnlistmentShim;
					flag2 = true;
				}
				flag = fabricateRollback;
				state = OletxEnlistmentState.Done;
			}
			try
			{
				if (enlistmentShim != null)
				{
					if (OletxEnlistmentState.Preparing == oletxEnlistmentState)
					{
						try
						{
							enlistmentShim.PrepareRequestDone(OletxPrepareVoteType.ReadOnly);
						}
						finally
						{
							HandleTable.FreeHandle(phase1Handle);
						}
					}
					else if (OletxEnlistmentState.Committing == oletxEnlistmentState)
					{
						enlistmentShim.CommitRequestDone();
					}
					else if (OletxEnlistmentState.Aborting == oletxEnlistmentState)
					{
						if (!flag)
						{
							enlistmentShim.AbortRequestDone();
						}
					}
					else
					{
						if (OletxEnlistmentState.SinglePhaseCommitting != oletxEnlistmentState)
						{
							throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
						}
						enlistmentShim.PrepareRequestDone(OletxPrepareVoteType.SinglePhase);
					}
				}
				else if (phase0EnlistmentShim != null)
				{
					if (oletxEnlistmentState == OletxEnlistmentState.Active)
					{
						phase0EnlistmentShim.Unenlist();
					}
					else
					{
						if (OletxEnlistmentState.Phase0Preparing != oletxEnlistmentState)
						{
							throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
						}
						phase0EnlistmentShim.Phase0Done(voteYes: true);
					}
				}
			}
			catch (COMException exception)
			{
				flag2 = true;
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), exception);
				}
			}
			finally
			{
				if (flag2)
				{
					FinishEnlistment();
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.EnlistmentDone");
			}
		}

		public void Prepared()
		{
			_ = NativeMethods.S_OK;
			IEnlistmentShim enlistmentShim = null;
			IPhase0EnlistmentShim phase0EnlistmentShim = null;
			bool flag = false;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.Prepared");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.Prepared);
			}
			lock (this)
			{
				if (OletxEnlistmentState.Preparing == state)
				{
					enlistmentShim = EnlistmentShim;
				}
				else
				{
					if (OletxEnlistmentState.Phase0Preparing != state)
					{
						throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
					}
					phase0EnlistmentShim = Phase0EnlistmentShim;
					if (oletxTransaction.realOletxTransaction.Doomed || fabricateRollback)
					{
						fabricateRollback = true;
						flag = fabricateRollback;
					}
				}
				state = OletxEnlistmentState.Prepared;
			}
			try
			{
				if (enlistmentShim != null)
				{
					enlistmentShim.PrepareRequestDone(OletxPrepareVoteType.Prepared);
				}
				else if (phase0EnlistmentShim != null)
				{
					oletxTransaction.realOletxTransaction.DecrementUndecidedEnlistments();
					phase0EnlistmentShim.Phase0Done(!flag);
				}
				else
				{
					flag = true;
				}
				if (flag)
				{
					AbortRequest();
				}
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN == ex.ErrorCode || NativeMethods.XACT_E_TMNOTAVAILABLE == ex.ErrorCode)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
					}
				}
				else
				{
					if (NativeMethods.XACT_E_PROTOCOL != ex.ErrorCode)
					{
						throw;
					}
					Phase0EnlistmentShim = null;
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
					}
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.Prepared");
			}
		}

		public void ForceRollback()
		{
			ForceRollback(null);
		}

		public void ForceRollback(Exception e)
		{
			IEnlistmentShim enlistmentShim = null;
			IPhase0EnlistmentShim phase0EnlistmentShim = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.ForceRollback");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.ForceRollback);
			}
			lock (this)
			{
				if (OletxEnlistmentState.Preparing == state)
				{
					enlistmentShim = EnlistmentShim;
				}
				else
				{
					if (OletxEnlistmentState.Phase0Preparing != state)
					{
						throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
					}
					phase0EnlistmentShim = Phase0EnlistmentShim;
					if (phase0EnlistmentShim != null)
					{
						oletxTransaction.realOletxTransaction.DecrementUndecidedEnlistments();
					}
				}
				state = OletxEnlistmentState.Aborted;
			}
			Interlocked.CompareExchange(ref oletxTransaction.realOletxTransaction.innerException, e, null);
			try
			{
				if (enlistmentShim != null)
				{
					try
					{
						enlistmentShim.PrepareRequestDone(OletxPrepareVoteType.Failed);
					}
					finally
					{
						HandleTable.FreeHandle(phase1Handle);
					}
				}
				phase0EnlistmentShim?.Phase0Done(voteYes: false);
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex.ErrorCode)
				{
					throw;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
				}
			}
			finally
			{
				FinishEnlistment();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.ForceRollback");
			}
		}

		public void Committed()
		{
			IEnlistmentShim enlistmentShim = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxSinglePhaseEnlistment.Committed");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.Committed);
			}
			lock (this)
			{
				if (!isSinglePhase || OletxEnlistmentState.SinglePhaseCommitting != state)
				{
					throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
				}
				state = OletxEnlistmentState.Committed;
				enlistmentShim = EnlistmentShim;
			}
			try
			{
				enlistmentShim?.PrepareRequestDone(OletxPrepareVoteType.SinglePhase);
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex.ErrorCode)
				{
					throw;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
				}
			}
			finally
			{
				FinishEnlistment();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxSinglePhaseEnlistment.Committed");
			}
		}

		public void Aborted()
		{
			Aborted(null);
		}

		public void Aborted(Exception e)
		{
			IEnlistmentShim enlistmentShim = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxSinglePhaseEnlistment.Aborted");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.Aborted);
			}
			lock (this)
			{
				if (!isSinglePhase || OletxEnlistmentState.SinglePhaseCommitting != state)
				{
					throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
				}
				state = OletxEnlistmentState.Aborted;
				enlistmentShim = EnlistmentShim;
			}
			Interlocked.CompareExchange(ref oletxTransaction.realOletxTransaction.innerException, e, null);
			try
			{
				enlistmentShim?.PrepareRequestDone(OletxPrepareVoteType.Failed);
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex.ErrorCode)
				{
					throw;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
				}
			}
			finally
			{
				FinishEnlistment();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxSinglePhaseEnlistment.Aborted");
			}
		}

		public void InDoubt()
		{
			InDoubt(null);
		}

		public void InDoubt(Exception e)
		{
			IEnlistmentShim enlistmentShim = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxSinglePhaseEnlistment.InDoubt");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.InDoubt);
			}
			lock (this)
			{
				if (!isSinglePhase || OletxEnlistmentState.SinglePhaseCommitting != state)
				{
					throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
				}
				state = OletxEnlistmentState.InDoubt;
				enlistmentShim = EnlistmentShim;
			}
			lock (oletxTransaction.realOletxTransaction)
			{
				if (oletxTransaction.realOletxTransaction.innerException == null)
				{
					oletxTransaction.realOletxTransaction.innerException = e;
				}
			}
			try
			{
				enlistmentShim?.PrepareRequestDone(OletxPrepareVoteType.InDoubt);
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex.ErrorCode)
				{
					throw;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
				}
			}
			finally
			{
				FinishEnlistment();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxSinglePhaseEnlistment.InDoubt");
			}
		}

		public byte[] GetRecoveryInformation()
		{
			if (prepareInfoByteArray == null)
			{
				throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
			}
			return prepareInfoByteArray;
		}
	}
	internal sealed class OletxResourceManager
	{
		internal Guid resourceManagerIdentifier;

		internal IResourceManagerShim resourceManagerShim;

		internal Hashtable enlistmentHashtable;

		internal static Hashtable volatileEnlistmentHashtable = new Hashtable();

		internal OletxTransactionManager oletxTransactionManager;

		internal ArrayList reenlistList;

		internal ArrayList reenlistPendingList;

		internal Timer reenlistThreadTimer;

		internal Thread reenlistThread;

		private bool recoveryCompleteCalledByApplication;

		internal IResourceManagerShim ResourceManagerShim
		{
			get
			{
				IResourceManagerShim resourceManagerShim = null;
				if (this.resourceManagerShim == null)
				{
					lock (this)
					{
						if (this.resourceManagerShim == null)
						{
							oletxTransactionManager.dtcTransactionManagerLock.AcquireReaderLock(-1);
							try
							{
								Guid guid = resourceManagerIdentifier;
								IntPtr intPtr = IntPtr.Zero;
								RuntimeHelpers.PrepareConstrainedRegions();
								try
								{
									intPtr = HandleTable.AllocHandle(this);
									oletxTransactionManager.DtcTransactionManager.ProxyShimFactory.CreateResourceManager(guid, intPtr, out resourceManagerShim);
								}
								finally
								{
									if (resourceManagerShim == null && intPtr != IntPtr.Zero)
									{
										HandleTable.FreeHandle(intPtr);
									}
								}
							}
							catch (COMException ex)
							{
								if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex.ErrorCode)
								{
									throw;
								}
								resourceManagerShim = null;
								if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
								{
									System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
								}
							}
							catch (TransactionException ex2)
							{
								if (!(ex2.InnerException is COMException ex3))
								{
									throw;
								}
								if (NativeMethods.XACT_E_CONNECTION_DOWN != ex3.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex3.ErrorCode)
								{
									throw;
								}
								resourceManagerShim = null;
								if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
								{
									System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex2);
								}
							}
							finally
							{
								oletxTransactionManager.dtcTransactionManagerLock.ReleaseReaderLock();
							}
							Thread.MemoryBarrier();
							this.resourceManagerShim = resourceManagerShim;
						}
					}
				}
				return this.resourceManagerShim;
			}
			set
			{
				resourceManagerShim = value;
			}
		}

		internal bool RecoveryCompleteCalledByApplication
		{
			get
			{
				return recoveryCompleteCalledByApplication;
			}
			set
			{
				recoveryCompleteCalledByApplication = value;
			}
		}

		internal OletxResourceManager(OletxTransactionManager transactionManager, Guid resourceManagerIdentifier)
		{
			resourceManagerShim = null;
			oletxTransactionManager = transactionManager;
			this.resourceManagerIdentifier = resourceManagerIdentifier;
			enlistmentHashtable = new Hashtable();
			reenlistList = new ArrayList();
			reenlistPendingList = new ArrayList();
			reenlistThreadTimer = null;
			reenlistThread = null;
			recoveryCompleteCalledByApplication = false;
		}

		internal bool CallProxyReenlistComplete()
		{
			bool result = false;
			if (RecoveryCompleteCalledByApplication)
			{
				IResourceManagerShim resourceManagerShim = null;
				try
				{
					resourceManagerShim = ResourceManagerShim;
					if (resourceManagerShim != null)
					{
						resourceManagerShim.ReenlistComplete();
						return true;
					}
					return result;
				}
				catch (COMException ex)
				{
					if (NativeMethods.XACT_E_CONNECTION_DOWN == ex.ErrorCode || NativeMethods.XACT_E_TMNOTAVAILABLE == ex.ErrorCode)
					{
						result = false;
						if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
						{
							System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
							return result;
						}
						return result;
					}
					if (NativeMethods.XACT_E_RECOVERYALREADYDONE != ex.ErrorCode)
					{
						OletxTransactionManager.ProxyException(ex);
						throw;
					}
					return true;
				}
				finally
				{
					resourceManagerShim = null;
				}
			}
			return true;
		}

		internal void TMDownFromInternalRM(OletxTransactionManager oletxTM)
		{
			Hashtable hashtable = null;
			IDictionaryEnumerator dictionaryEnumerator = null;
			OletxEnlistment oletxEnlistment = null;
			ResourceManagerShim = null;
			lock (enlistmentHashtable.SyncRoot)
			{
				hashtable = (Hashtable)enlistmentHashtable.Clone();
			}
			dictionaryEnumerator = hashtable.GetEnumerator();
			while (dictionaryEnumerator.MoveNext())
			{
				if (dictionaryEnumerator.Value is OletxEnlistment oletxEnlistment2)
				{
					oletxEnlistment2.TMDownFromInternalRM(oletxTM);
				}
			}
		}

		public void TMDown()
		{
			StartReenlistThread();
		}

		internal OletxEnlistment EnlistDurable(OletxTransaction oletxTransaction, bool canDoSinglePhase, IEnlistmentNotificationInternal enlistmentNotification, EnlistmentOptions enlistmentOptions)
		{
			//Discarded unreachable code: IL_0111
			IResourceManagerShim resourceManagerShim = null;
			IEnlistmentShim enlistmentShim = null;
			IPhase0EnlistmentShim phase0EnlistmentShim = null;
			_ = Guid.Empty;
			IntPtr intPtr = IntPtr.Zero;
			bool flag = false;
			bool flag2 = false;
			OletxEnlistment oletxEnlistment = new OletxEnlistment(canDoSinglePhase, enlistmentNotification, oletxTransaction.RealTransaction.TxGuid, enlistmentOptions, this, oletxTransaction);
			bool flag3 = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
				{
					RuntimeHelpers.PrepareConstrainedRegions();
					try
					{
					}
					finally
					{
						oletxTransaction.RealTransaction.IncrementUndecidedEnlistments();
						flag2 = true;
					}
				}
				lock (oletxEnlistment)
				{
					RuntimeHelpers.PrepareConstrainedRegions();
					try
					{
						resourceManagerShim = ResourceManagerShim;
						if (resourceManagerShim == null)
						{
							throw TransactionManagerCommunicationException.Create(SR.GetString("TraceSourceOletx"), null);
						}
						if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
						{
							intPtr = HandleTable.AllocHandle(oletxEnlistment);
							RuntimeHelpers.PrepareConstrainedRegions();
							try
							{
							}
							finally
							{
								oletxTransaction.RealTransaction.TransactionShim.Phase0Enlist(intPtr, out phase0EnlistmentShim);
								flag = true;
							}
							oletxEnlistment.Phase0EnlistmentShim = phase0EnlistmentShim;
						}
						oletxEnlistment.phase1Handle = HandleTable.AllocHandle(oletxEnlistment);
						resourceManagerShim.Enlist(oletxTransaction.RealTransaction.TransactionShim, oletxEnlistment.phase1Handle, out enlistmentShim);
						oletxEnlistment.EnlistmentShim = enlistmentShim;
					}
					catch (COMException ex)
					{
						if (NativeMethods.XACT_E_TOOMANY_ENLISTMENTS == ex.ErrorCode)
						{
							throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("OletxTooManyEnlistments"), ex);
						}
						OletxTransactionManager.ProxyException(ex);
						throw;
					}
					finally
					{
						if (oletxEnlistment.EnlistmentShim == null)
						{
							if (intPtr != IntPtr.Zero && !flag)
							{
								HandleTable.FreeHandle(intPtr);
							}
							if (oletxEnlistment.phase1Handle != IntPtr.Zero)
							{
								HandleTable.FreeHandle(oletxEnlistment.phase1Handle);
							}
						}
					}
				}
				flag3 = true;
				return oletxEnlistment;
			}
			finally
			{
				if (!flag3 && (enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0 && flag2)
				{
					oletxTransaction.RealTransaction.DecrementUndecidedEnlistments();
				}
			}
		}

		internal OletxEnlistment Reenlist(int prepareInfoLength, byte[] prepareInfo, IEnlistmentNotificationInternal enlistmentNotification)
		{
			//Discarded unreachable code: IL_003e
			OletxTransactionOutcome outcome = OletxTransactionOutcome.NotKnownYet;
			OletxTransactionStatus xactStatus = OletxTransactionStatus.OLETX_TRANSACTION_STATUS_NONE;
			MemoryStream serializationStream = new MemoryStream(prepareInfo);
			IFormatter formatter = new BinaryFormatter();
			OletxRecoveryInformation oletxRecoveryInformation;
			try
			{
				oletxRecoveryInformation = formatter.Deserialize(serializationStream) as OletxRecoveryInformation;
			}
			catch (SerializationException innerException)
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "prepareInfo", innerException);
			}
			if (oletxRecoveryInformation == null)
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "prepareInfo");
			}
			byte[] array = new byte[16];
			for (int i = 0; i < 16; i++)
			{
				array[i] = oletxRecoveryInformation.proxyRecoveryInformation[i + 16];
			}
			Guid guid = new Guid(array);
			if (guid != resourceManagerIdentifier)
			{
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("ResourceManagerIdDoesNotMatchRecoveryInformation"), null);
			}
			IResourceManagerShim resourceManagerShim = null;
			try
			{
				resourceManagerShim = ResourceManagerShim;
				if (resourceManagerShim == null)
				{
					throw new COMException(SR.GetString("DtcTransactionManagerUnavailable"), NativeMethods.XACT_E_CONNECTION_DOWN);
				}
				resourceManagerShim.Reenlist(Convert.ToUInt32(oletxRecoveryInformation.proxyRecoveryInformation.Length, CultureInfo.InvariantCulture), oletxRecoveryInformation.proxyRecoveryInformation, out outcome);
				if (OletxTransactionOutcome.Committed == outcome)
				{
					xactStatus = OletxTransactionStatus.OLETX_TRANSACTION_STATUS_COMMITTED;
				}
				else if (OletxTransactionOutcome.Aborted == outcome)
				{
					xactStatus = OletxTransactionStatus.OLETX_TRANSACTION_STATUS_ABORTED;
				}
				else
				{
					xactStatus = OletxTransactionStatus.OLETX_TRANSACTION_STATUS_PREPARED;
					StartReenlistThread();
				}
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode)
				{
					throw;
				}
				xactStatus = OletxTransactionStatus.OLETX_TRANSACTION_STATUS_PREPARED;
				ResourceManagerShim = null;
				StartReenlistThread();
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
				}
			}
			finally
			{
				resourceManagerShim = null;
			}
			return new OletxEnlistment(enlistmentNotification, xactStatus, oletxRecoveryInformation.proxyRecoveryInformation, this);
		}

		internal void RecoveryComplete()
		{
			Timer timer = null;
			RecoveryCompleteCalledByApplication = true;
			try
			{
				lock (reenlistList)
				{
					lock (this)
					{
						if (reenlistList.Count == 0 && reenlistPendingList.Count == 0)
						{
							if (reenlistThreadTimer != null)
							{
								timer = reenlistThreadTimer;
								reenlistThreadTimer = null;
							}
							if (!CallProxyReenlistComplete())
							{
								StartReenlistThread();
							}
						}
						else
						{
							StartReenlistThread();
						}
					}
				}
			}
			finally
			{
				timer?.Dispose();
			}
		}

		internal void StartReenlistThread()
		{
			lock (this)
			{
				if (reenlistThreadTimer == null && reenlistThread == null)
				{
					reenlistThreadTimer = new Timer(ReenlistThread, this, 10, -1);
				}
			}
		}

		internal void RemoveFromReenlistPending(OletxEnlistment enlistment)
		{
			lock (reenlistList)
			{
				reenlistPendingList.Remove(enlistment);
				lock (this)
				{
					if (reenlistThreadTimer != null && reenlistList.Count == 0 && reenlistPendingList.Count == 0 && !reenlistThreadTimer.Change(0, -1))
					{
						throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedTimerFailure"), null);
					}
				}
			}
		}

		internal void ReenlistThread(object state)
		{
			//Discarded unreachable code: IL_0442
			int num = 0;
			bool flag = false;
			OletxEnlistment oletxEnlistment = null;
			IResourceManagerShim resourceManagerShim = null;
			bool flag2 = false;
			Timer timer = null;
			bool flag3 = false;
			OletxResourceManager oletxResourceManager = (OletxResourceManager)state;
			try
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
				{
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxResourceManager.ReenlistThread");
				}
				lock (oletxResourceManager)
				{
					resourceManagerShim = oletxResourceManager.ResourceManagerShim;
					timer = oletxResourceManager.reenlistThreadTimer;
					oletxResourceManager.reenlistThreadTimer = null;
					oletxResourceManager.reenlistThread = Thread.CurrentThread;
				}
				if (resourceManagerShim != null)
				{
					lock (oletxResourceManager.reenlistList)
					{
						num = oletxResourceManager.reenlistList.Count;
					}
					flag = false;
					while (!flag && num > 0 && resourceManagerShim != null)
					{
						lock (oletxResourceManager.reenlistList)
						{
							oletxEnlistment = null;
							num--;
							if (oletxResourceManager.reenlistList.Count == 0)
							{
								flag = true;
							}
							else
							{
								oletxEnlistment = oletxResourceManager.reenlistList[0] as OletxEnlistment;
								if (oletxEnlistment == null)
								{
									if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
									{
										System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
									}
									throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("InternalError"), null);
								}
								oletxResourceManager.reenlistList.RemoveAt(0);
								object obj = oletxEnlistment;
								lock (obj)
								{
									if (OletxEnlistment.OletxEnlistmentState.Done == oletxEnlistment.State)
									{
										oletxEnlistment = null;
									}
									else if (OletxEnlistment.OletxEnlistmentState.Prepared != oletxEnlistment.State)
									{
										oletxResourceManager.reenlistList.Add(oletxEnlistment);
										oletxEnlistment = null;
									}
								}
							}
						}
						if (oletxEnlistment == null)
						{
							continue;
						}
						OletxTransactionOutcome outcome = OletxTransactionOutcome.NotKnownYet;
						try
						{
							if (oletxEnlistment.ProxyPrepareInfoByteArray == null)
							{
								if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
								{
									System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
								}
								throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("InternalError"), null);
							}
							resourceManagerShim.Reenlist((uint)oletxEnlistment.ProxyPrepareInfoByteArray.Length, oletxEnlistment.ProxyPrepareInfoByteArray, out outcome);
							if (outcome == OletxTransactionOutcome.NotKnownYet)
							{
								object obj2 = oletxEnlistment;
								lock (obj2)
								{
									if (OletxEnlistment.OletxEnlistmentState.Done == oletxEnlistment.State)
									{
										oletxEnlistment = null;
									}
									else
									{
										lock (oletxResourceManager.reenlistList)
										{
											oletxResourceManager.reenlistList.Add(oletxEnlistment);
											oletxEnlistment = null;
										}
									}
								}
							}
						}
						catch (COMException ex)
						{
							if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode)
							{
								throw;
							}
							if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
							{
								System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
							}
							if (NativeMethods.XACT_E_CONNECTION_DOWN == ex.ErrorCode)
							{
								oletxResourceManager.ResourceManagerShim = null;
								resourceManagerShim = oletxResourceManager.ResourceManagerShim;
							}
						}
						if (oletxEnlistment == null)
						{
							continue;
						}
						object obj3 = oletxEnlistment;
						lock (obj3)
						{
							if (OletxEnlistment.OletxEnlistmentState.Done == oletxEnlistment.State)
							{
								oletxEnlistment = null;
								continue;
							}
							lock (oletxResourceManager.reenlistList)
							{
								oletxResourceManager.reenlistPendingList.Add(oletxEnlistment);
							}
							if (OletxTransactionOutcome.Committed == outcome)
							{
								oletxEnlistment.State = OletxEnlistment.OletxEnlistmentState.Committing;
								if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
								{
									System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), oletxEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Commit);
								}
								oletxEnlistment.EnlistmentNotification.Commit(oletxEnlistment);
								continue;
							}
							if (OletxTransactionOutcome.Aborted == outcome)
							{
								oletxEnlistment.State = OletxEnlistment.OletxEnlistmentState.Aborting;
								if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
								{
									System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), oletxEnlistment.EnlistmentTraceId, System.Transactions.Diagnostics.NotificationCall.Rollback);
								}
								oletxEnlistment.EnlistmentNotification.Rollback(oletxEnlistment);
								continue;
							}
							if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
							{
								System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
							}
							throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("InternalError"), null);
						}
					}
				}
				resourceManagerShim = null;
				lock (oletxResourceManager.reenlistList)
				{
					lock (oletxResourceManager)
					{
						num = oletxResourceManager.reenlistList.Count;
						if (0 >= num && 0 >= oletxResourceManager.reenlistPendingList.Count)
						{
							if (oletxResourceManager.CallProxyReenlistComplete())
							{
								flag3 = true;
							}
							else
							{
								oletxResourceManager.reenlistThreadTimer = timer;
								if (!timer.Change(10000, -1))
								{
									throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedTimerFailure"), null);
								}
							}
						}
						else
						{
							oletxResourceManager.reenlistThreadTimer = timer;
							if (!timer.Change(10000, -1))
							{
								throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceLtm"), SR.GetString("UnexpectedTimerFailure"), null);
							}
						}
						oletxResourceManager.reenlistThread = null;
					}
					if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
					{
						System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxResourceManager.ReenlistThread");
					}
				}
			}
			finally
			{
				resourceManagerShim = null;
				if (flag3)
				{
					timer?.Dispose();
				}
			}
		}
	}
	internal class RealOletxTransaction
	{
		private OletxTransactionManager oletxTransactionManager;

		private ITransactionShim transactionShim;

		private Guid txGuid;

		private IsolationLevel isolationLevel;

		internal Exception innerException;

		private TransactionStatus status;

		private int undisposedOletxTransactionCount;

		internal ArrayList phase0EnlistVolatilementContainerList;

		internal OletxPhase1VolatileEnlistmentContainer phase1EnlistVolatilementContainer;

		private OutcomeEnlistment outcomeEnlistment;

		private int undecidedEnlistmentCount;

		private bool doomed;

		internal int enlistmentCount;

		private DateTime creationTime;

		private DateTime lastStateChangeTime;

		private TransactionTraceIdentifier traceIdentifier = TransactionTraceIdentifier.Empty;

		internal OletxCommittableTransaction committableTransaction;

		internal OletxTransaction internalClone;

		private bool tooLateForEnlistments;

		private InternalTransaction internalTransaction;

		internal InternalTransaction InternalTransaction
		{
			get
			{
				return internalTransaction;
			}
			set
			{
				internalTransaction = value;
			}
		}

		internal OletxTransactionManager OletxTransactionManagerInstance => oletxTransactionManager;

		internal Guid Identifier
		{
			get
			{
				if (txGuid.Equals(Guid.Empty))
				{
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("CannotGetTransactionIdentifier"), null);
				}
				return txGuid;
			}
		}

		internal IsolationLevel TransactionIsolationLevel => isolationLevel;

		internal TransactionStatus Status => status;

		internal Guid TxGuid => txGuid;

		internal int UndecidedEnlistments => undecidedEnlistmentCount;

		internal bool Doomed => doomed;

		internal ITransactionShim TransactionShim
		{
			get
			{
				ITransactionShim transactionShim = this.transactionShim;
				if (transactionShim == null)
				{
					throw TransactionInDoubtException.Create(SR.GetString("TraceSourceOletx"), null);
				}
				return transactionShim;
			}
		}

		internal bool TooLateForEnlistments
		{
			get
			{
				return tooLateForEnlistments;
			}
			set
			{
				tooLateForEnlistments = value;
			}
		}

		internal TransactionTraceIdentifier TransactionTraceId
		{
			get
			{
				if (TransactionTraceIdentifier.Empty == traceIdentifier)
				{
					lock (this)
					{
						if (TransactionTraceIdentifier.Empty == traceIdentifier && Guid.Empty != txGuid)
						{
							TransactionTraceIdentifier transactionTraceIdentifier = new TransactionTraceIdentifier(txGuid.ToString(), 0);
							Thread.MemoryBarrier();
							traceIdentifier = transactionTraceIdentifier;
						}
					}
				}
				return traceIdentifier;
			}
		}

		internal void IncrementUndecidedEnlistments()
		{
			Interlocked.Increment(ref undecidedEnlistmentCount);
		}

		internal void DecrementUndecidedEnlistments()
		{
			Interlocked.Decrement(ref undecidedEnlistmentCount);
		}

		internal RealOletxTransaction(OletxTransactionManager transactionManager, ITransactionShim transactionShim, OutcomeEnlistment outcomeEnlistment, Guid identifier, OletxTransactionIsolationLevel oletxIsoLevel, bool isRoot)
		{
			bool flag = false;
			try
			{
				oletxTransactionManager = transactionManager;
				this.transactionShim = transactionShim;
				this.outcomeEnlistment = outcomeEnlistment;
				txGuid = identifier;
				isolationLevel = OletxTransactionManager.ConvertIsolationLevelFromProxyValue(oletxIsoLevel);
				status = TransactionStatus.Active;
				undisposedOletxTransactionCount = 0;
				phase0EnlistVolatilementContainerList = null;
				phase1EnlistVolatilementContainer = null;
				tooLateForEnlistments = false;
				internalTransaction = null;
				creationTime = DateTime.UtcNow;
				lastStateChangeTime = creationTime;
				internalClone = new OletxTransaction(this);
				if (this.outcomeEnlistment != null)
				{
					this.outcomeEnlistment.SetRealTransaction(this);
				}
				else
				{
					status = TransactionStatus.InDoubt;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.HaveListeners)
				{
					System.Transactions.Diagnostics.DiagnosticTrace.TraceTransfer(txGuid);
				}
				flag = true;
			}
			finally
			{
				if (!flag && this.outcomeEnlistment != null)
				{
					this.outcomeEnlistment.UnregisterOutcomeCallback();
					this.outcomeEnlistment = null;
				}
			}
		}

		internal OletxVolatileEnlistmentContainer AddDependentClone(bool delayCommit)
		{
			//Discarded unreachable code: IL_0171
			IPhase0EnlistmentShim phase0EnlistmentShim = null;
			IVoterBallotShim voterBallotShim = null;
			bool flag = false;
			bool flag2 = false;
			OletxVolatileEnlistmentContainer oletxVolatileEnlistmentContainer = null;
			OletxPhase0VolatileEnlistmentContainer oletxPhase0VolatileEnlistmentContainer = null;
			OletxPhase1VolatileEnlistmentContainer oletxPhase1VolatileEnlistmentContainer = null;
			bool flag3 = false;
			IntPtr intPtr = IntPtr.Zero;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				lock (this)
				{
					if (delayCommit)
					{
						if (phase0EnlistVolatilementContainerList == null)
						{
							phase0EnlistVolatilementContainerList = new ArrayList(1);
						}
						if (phase0EnlistVolatilementContainerList.Count == 0)
						{
							oletxPhase0VolatileEnlistmentContainer = new OletxPhase0VolatileEnlistmentContainer(this);
							flag2 = true;
						}
						else
						{
							oletxPhase0VolatileEnlistmentContainer = phase0EnlistVolatilementContainerList[phase0EnlistVolatilementContainerList.Count - 1] as OletxPhase0VolatileEnlistmentContainer;
							if (!oletxPhase0VolatileEnlistmentContainer.NewEnlistmentsAllowed)
							{
								oletxPhase0VolatileEnlistmentContainer = new OletxPhase0VolatileEnlistmentContainer(this);
								flag2 = true;
							}
							else
							{
								flag2 = false;
							}
						}
						if (flag2)
						{
							intPtr = HandleTable.AllocHandle(oletxPhase0VolatileEnlistmentContainer);
						}
					}
					else if (phase1EnlistVolatilementContainer == null)
					{
						oletxPhase1VolatileEnlistmentContainer = new OletxPhase1VolatileEnlistmentContainer(this);
						flag = true;
						oletxPhase1VolatileEnlistmentContainer.voterHandle = HandleTable.AllocHandle(oletxPhase1VolatileEnlistmentContainer);
					}
					else
					{
						flag = false;
						oletxPhase1VolatileEnlistmentContainer = phase1EnlistVolatilementContainer;
					}
					try
					{
						if (flag2)
						{
							lock (oletxPhase0VolatileEnlistmentContainer)
							{
								transactionShim.Phase0Enlist(intPtr, out phase0EnlistmentShim);
								oletxPhase0VolatileEnlistmentContainer.Phase0EnlistmentShim = phase0EnlistmentShim;
							}
						}
						if (flag)
						{
							OletxTransactionManagerInstance.dtcTransactionManagerLock.AcquireReaderLock(-1);
							try
							{
								transactionShim.CreateVoter(oletxPhase1VolatileEnlistmentContainer.voterHandle, out voterBallotShim);
								flag3 = true;
							}
							finally
							{
								OletxTransactionManagerInstance.dtcTransactionManagerLock.ReleaseReaderLock();
							}
							oletxPhase1VolatileEnlistmentContainer.VoterBallotShim = voterBallotShim;
						}
						if (delayCommit)
						{
							if (flag2)
							{
								phase0EnlistVolatilementContainerList.Add(oletxPhase0VolatileEnlistmentContainer);
							}
							oletxPhase0VolatileEnlistmentContainer.AddDependentClone();
							return oletxPhase0VolatileEnlistmentContainer;
						}
						if (flag)
						{
							phase1EnlistVolatilementContainer = oletxPhase1VolatileEnlistmentContainer;
						}
						oletxPhase1VolatileEnlistmentContainer.AddDependentClone();
						return oletxPhase1VolatileEnlistmentContainer;
					}
					catch (COMException comException)
					{
						OletxTransactionManager.ProxyException(comException);
						throw;
					}
				}
			}
			finally
			{
				if (intPtr != IntPtr.Zero && oletxPhase0VolatileEnlistmentContainer.Phase0EnlistmentShim == null)
				{
					HandleTable.FreeHandle(intPtr);
				}
				if (!flag3 && oletxPhase1VolatileEnlistmentContainer != null && oletxPhase1VolatileEnlistmentContainer.voterHandle != IntPtr.Zero && flag)
				{
					HandleTable.FreeHandle(oletxPhase1VolatileEnlistmentContainer.voterHandle);
				}
			}
		}

		internal IPromotedEnlistment CommonEnlistVolatile(IEnlistmentNotificationInternal enlistmentNotification, EnlistmentOptions enlistmentOptions, OletxTransaction oletxTransaction)
		{
			//Discarded unreachable code: IL_0159
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			bool flag = false;
			bool flag2 = false;
			OletxPhase0VolatileEnlistmentContainer oletxPhase0VolatileEnlistmentContainer = null;
			OletxPhase1VolatileEnlistmentContainer oletxPhase1VolatileEnlistmentContainer = null;
			IntPtr intPtr = IntPtr.Zero;
			IVoterBallotShim voterBallotShim = null;
			IPhase0EnlistmentShim phase0EnlistmentShim = null;
			bool flag3 = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				lock (this)
				{
					oletxVolatileEnlistment = new OletxVolatileEnlistment(enlistmentNotification, enlistmentOptions, oletxTransaction);
					if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
					{
						if (phase0EnlistVolatilementContainerList == null)
						{
							phase0EnlistVolatilementContainerList = new ArrayList(1);
						}
						if (phase0EnlistVolatilementContainerList.Count == 0)
						{
							oletxPhase0VolatileEnlistmentContainer = new OletxPhase0VolatileEnlistmentContainer(this);
							flag2 = true;
						}
						else
						{
							oletxPhase0VolatileEnlistmentContainer = phase0EnlistVolatilementContainerList[phase0EnlistVolatilementContainerList.Count - 1] as OletxPhase0VolatileEnlistmentContainer;
							if (!oletxPhase0VolatileEnlistmentContainer.NewEnlistmentsAllowed)
							{
								oletxPhase0VolatileEnlistmentContainer = new OletxPhase0VolatileEnlistmentContainer(this);
								flag2 = true;
							}
							else
							{
								flag2 = false;
							}
						}
						if (flag2)
						{
							intPtr = HandleTable.AllocHandle(oletxPhase0VolatileEnlistmentContainer);
						}
					}
					else if (phase1EnlistVolatilementContainer == null)
					{
						flag = true;
						oletxPhase1VolatileEnlistmentContainer = new OletxPhase1VolatileEnlistmentContainer(this);
						oletxPhase1VolatileEnlistmentContainer.voterHandle = HandleTable.AllocHandle(oletxPhase1VolatileEnlistmentContainer);
					}
					else
					{
						flag = false;
						oletxPhase1VolatileEnlistmentContainer = phase1EnlistVolatilementContainer;
					}
					try
					{
						if (flag2)
						{
							lock (oletxPhase0VolatileEnlistmentContainer)
							{
								transactionShim.Phase0Enlist(intPtr, out phase0EnlistmentShim);
								oletxPhase0VolatileEnlistmentContainer.Phase0EnlistmentShim = phase0EnlistmentShim;
							}
						}
						if (flag)
						{
							transactionShim.CreateVoter(oletxPhase1VolatileEnlistmentContainer.voterHandle, out voterBallotShim);
							flag3 = true;
							oletxPhase1VolatileEnlistmentContainer.VoterBallotShim = voterBallotShim;
						}
						if ((enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0)
						{
							oletxPhase0VolatileEnlistmentContainer.AddEnlistment(oletxVolatileEnlistment);
							if (flag2)
							{
								phase0EnlistVolatilementContainerList.Add(oletxPhase0VolatileEnlistmentContainer);
								return oletxVolatileEnlistment;
							}
							return oletxVolatileEnlistment;
						}
						oletxPhase1VolatileEnlistmentContainer.AddEnlistment(oletxVolatileEnlistment);
						if (flag)
						{
							phase1EnlistVolatilementContainer = oletxPhase1VolatileEnlistmentContainer;
							return oletxVolatileEnlistment;
						}
						return oletxVolatileEnlistment;
					}
					catch (COMException comException)
					{
						OletxTransactionManager.ProxyException(comException);
						throw;
					}
				}
			}
			finally
			{
				if (intPtr != IntPtr.Zero && oletxPhase0VolatileEnlistmentContainer.Phase0EnlistmentShim == null)
				{
					HandleTable.FreeHandle(intPtr);
				}
				if (!flag3 && oletxPhase1VolatileEnlistmentContainer != null && oletxPhase1VolatileEnlistmentContainer.voterHandle != IntPtr.Zero && flag)
				{
					HandleTable.FreeHandle(oletxPhase1VolatileEnlistmentContainer.voterHandle);
				}
			}
		}

		internal IPromotedEnlistment EnlistVolatile(ISinglePhaseNotificationInternal enlistmentNotification, EnlistmentOptions enlistmentOptions, OletxTransaction oletxTransaction)
		{
			return CommonEnlistVolatile(enlistmentNotification, enlistmentOptions, oletxTransaction);
		}

		internal IPromotedEnlistment EnlistVolatile(IEnlistmentNotificationInternal enlistmentNotification, EnlistmentOptions enlistmentOptions, OletxTransaction oletxTransaction)
		{
			return CommonEnlistVolatile(enlistmentNotification, enlistmentOptions, oletxTransaction);
		}

		internal void Commit()
		{
			try
			{
				transactionShim.Commit();
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_ABORTED == ex.ErrorCode || NativeMethods.XACT_E_INDOUBT == ex.ErrorCode)
				{
					Interlocked.CompareExchange(ref innerException, ex, null);
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
					}
					return;
				}
				if (NativeMethods.XACT_E_ALREADYINPROGRESS == ex.ErrorCode)
				{
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionAlreadyOver"), ex);
				}
				OletxTransactionManager.ProxyException(ex);
				throw;
			}
		}

		internal void Rollback()
		{
			_ = Guid.Empty;
			lock (this)
			{
				if (TransactionStatus.Aborted != status && status != 0)
				{
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionAlreadyOver"), null);
				}
				if (TransactionStatus.Aborted == status)
				{
					return;
				}
				if (0 < undecidedEnlistmentCount)
				{
					doomed = true;
				}
				else if (tooLateForEnlistments)
				{
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionAlreadyOver"), null);
				}
				if (phase0EnlistVolatilementContainerList != null)
				{
					foreach (OletxPhase0VolatileEnlistmentContainer phase0EnlistVolatilementContainer in phase0EnlistVolatilementContainerList)
					{
						phase0EnlistVolatilementContainer.RollbackFromTransaction();
					}
				}
				if (phase1EnlistVolatilementContainer != null)
				{
					phase1EnlistVolatilementContainer.RollbackFromTransaction();
				}
			}
			try
			{
				transactionShim.Abort();
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_ALREADYINPROGRESS == ex.ErrorCode)
				{
					if (doomed)
					{
						if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
						{
							System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
						}
						return;
					}
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionAlreadyOver"), ex);
				}
				OletxTransactionManager.ProxyException(ex);
				throw;
			}
		}

		internal void OletxTransactionCreated()
		{
			Interlocked.Increment(ref undisposedOletxTransactionCount);
		}

		internal void OletxTransactionDisposed()
		{
			Interlocked.Decrement(ref undisposedOletxTransactionCount);
		}

		internal void FireOutcome(TransactionStatus statusArg)
		{
			lock (this)
			{
				switch (statusArg)
				{
				case TransactionStatus.Committed:
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.TransactionCommittedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), TransactionTraceId);
					}
					status = TransactionStatus.Committed;
					break;
				case TransactionStatus.Aborted:
					if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
					{
						System.Transactions.Diagnostics.TransactionAbortedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), TransactionTraceId);
					}
					status = TransactionStatus.Aborted;
					break;
				default:
					if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
					{
						System.Transactions.Diagnostics.TransactionInDoubtTraceRecord.Trace(SR.GetString("TraceSourceOletx"), TransactionTraceId);
					}
					status = TransactionStatus.InDoubt;
					break;
				}
			}
			if (InternalTransaction != null)
			{
				InternalTransaction.DistributedTransactionOutcome(InternalTransaction, status);
			}
		}

		internal void TMDown()
		{
			lock (this)
			{
				if (phase0EnlistVolatilementContainerList != null)
				{
					foreach (OletxPhase0VolatileEnlistmentContainer phase0EnlistVolatilementContainer in phase0EnlistVolatilementContainerList)
					{
						phase0EnlistVolatilementContainer.TMDown();
					}
				}
			}
			outcomeEnlistment.TMDown();
		}
	}
	internal sealed class OutcomeEnlistment
	{
		private WeakReference weakRealTransaction;

		private Guid txGuid;

		private bool haveIssuedOutcome;

		private TransactionStatus savedStatus;

		internal Guid TransactionIdentifier => txGuid;

		internal OutcomeEnlistment()
		{
			haveIssuedOutcome = false;
			savedStatus = TransactionStatus.InDoubt;
		}

		internal void SetRealTransaction(RealOletxTransaction realTx)
		{
			bool flag = false;
			TransactionStatus transactionStatus = TransactionStatus.InDoubt;
			lock (this)
			{
				flag = haveIssuedOutcome;
				transactionStatus = savedStatus;
				if (!flag)
				{
					weakRealTransaction = new WeakReference(realTx);
					txGuid = realTx.TxGuid;
				}
			}
			if (flag)
			{
				realTx.FireOutcome(transactionStatus);
				if ((TransactionStatus.Aborted == transactionStatus || TransactionStatus.InDoubt == transactionStatus) && realTx.phase1EnlistVolatilementContainer != null)
				{
					realTx.phase1EnlistVolatilementContainer.OutcomeFromTransaction(transactionStatus);
				}
			}
		}

		internal void UnregisterOutcomeCallback()
		{
			weakRealTransaction = null;
		}

		private void InvokeOutcomeFunction(TransactionStatus status)
		{
			WeakReference weakReference = null;
			lock (this)
			{
				if (haveIssuedOutcome)
				{
					return;
				}
				haveIssuedOutcome = true;
				savedStatus = status;
				weakReference = weakRealTransaction;
			}
			if (weakReference == null)
			{
				return;
			}
			if (weakReference.Target is RealOletxTransaction realOletxTransaction)
			{
				realOletxTransaction.FireOutcome(status);
				if (realOletxTransaction.phase0EnlistVolatilementContainerList != null)
				{
					foreach (OletxPhase0VolatileEnlistmentContainer phase0EnlistVolatilementContainer in realOletxTransaction.phase0EnlistVolatilementContainerList)
					{
						phase0EnlistVolatilementContainer.OutcomeFromTransaction(status);
					}
				}
				if ((TransactionStatus.Aborted == status || TransactionStatus.InDoubt == status) && realOletxTransaction.phase1EnlistVolatilementContainer != null)
				{
					realOletxTransaction.phase1EnlistVolatilementContainer.OutcomeFromTransaction(status);
				}
			}
			weakReference.Target = null;
		}

		internal bool TransactionIsInDoubt(RealOletxTransaction realTx)
		{
			if (realTx.committableTransaction != null && !realTx.committableTransaction.CommitCalled)
			{
				return false;
			}
			return realTx.UndecidedEnlistments == 0;
		}

		internal void TMDown()
		{
			bool flag = true;
			RealOletxTransaction realOletxTransaction = null;
			lock (this)
			{
				if (weakRealTransaction != null)
				{
					realOletxTransaction = weakRealTransaction.Target as RealOletxTransaction;
				}
			}
			if (realOletxTransaction != null)
			{
				lock (realOletxTransaction)
				{
					flag = TransactionIsInDoubt(realOletxTransaction);
				}
			}
			if (flag)
			{
				InDoubt();
			}
			else
			{
				Aborted();
			}
		}

		public void Committed()
		{
			InvokeOutcomeFunction(TransactionStatus.Committed);
		}

		public void Aborted()
		{
			InvokeOutcomeFunction(TransactionStatus.Aborted);
		}

		public void InDoubt()
		{
			InvokeOutcomeFunction(TransactionStatus.InDoubt);
		}
	}
	internal class OletxTransactionManager
	{
		private IsolationLevel isolationLevelProperty;

		private TimeSpan timeoutProperty;

		private TransactionOptions configuredTransactionOptions = default(TransactionOptions);

		private static object classSyncObject;

		internal static Hashtable resourceManagerHashTable;

		internal static ReaderWriterLock resourceManagerHashTableLock;

		internal static volatile bool processingTmDown;

		internal ReaderWriterLock dtcTransactionManagerLock;

		private DtcTransactionManager dtcTransactionManager;

		internal OletxInternalResourceManager internalResourceManager;

		internal static IDtcProxyShimFactory proxyShimFactory;

		internal static EventWaitHandle shimWaitHandle;

		private string nodeNameField;

		internal static EventWaitHandle ShimWaitHandle
		{
			get
			{
				if (shimWaitHandle == null)
				{
					lock (ClassSyncObject)
					{
						if (shimWaitHandle == null)
						{
							shimWaitHandle = new EventWaitHandle(initialState: false, EventResetMode.AutoReset);
						}
					}
				}
				return shimWaitHandle;
			}
		}

		internal string CreationNodeName => nodeNameField;

		internal DtcTransactionManager DtcTransactionManager
		{
			get
			{
				if (dtcTransactionManagerLock.IsReaderLockHeld || dtcTransactionManagerLock.IsWriterLockHeld)
				{
					if (dtcTransactionManager == null)
					{
						throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("DtcTransactionManagerUnavailable"), null);
					}
					return dtcTransactionManager;
				}
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("InternalError"), null);
			}
		}

		internal string NodeName => nodeNameField;

		internal static object ClassSyncObject
		{
			get
			{
				if (classSyncObject == null)
				{
					object value = new object();
					Interlocked.CompareExchange(ref classSyncObject, value, null);
				}
				return classSyncObject;
			}
		}

		internal static void ShimNotificationCallback(object state, bool timeout)
		{
			IntPtr managedIdentifier = IntPtr.Zero;
			ShimNotificationType shimNotificationType = ShimNotificationType.None;
			bool isSinglePhase = false;
			bool abortingHint = false;
			uint prepareInfoSize = 0u;
			CoTaskMemHandle prepareInfo = null;
			bool releaseRequired = false;
			bool flag = false;
			IDtcProxyShimFactory dtcProxyShimFactory = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransactionManager.ShimNotificationCallback");
			}
			Thread.BeginCriticalRegion();
			try
			{
				do
				{
					dtcProxyShimFactory = proxyShimFactory;
					try
					{
						Thread.BeginThreadAffinity();
						RuntimeHelpers.PrepareConstrainedRegions();
						try
						{
							dtcProxyShimFactory.GetNotification(out managedIdentifier, out shimNotificationType, out isSinglePhase, out abortingHint, out releaseRequired, out prepareInfoSize, out prepareInfo);
						}
						finally
						{
							if (releaseRequired)
							{
								if (HandleTable.FindHandle(managedIdentifier) is OletxInternalResourceManager)
								{
									processingTmDown = true;
									Monitor.Enter(proxyShimFactory);
								}
								else
								{
									releaseRequired = false;
								}
								dtcProxyShimFactory.ReleaseNotificationLock();
							}
							Thread.EndThreadAffinity();
						}
						if (processingTmDown)
						{
							lock (proxyShimFactory)
							{
							}
						}
						if (shimNotificationType == ShimNotificationType.None)
						{
							continue;
						}
						object obj = HandleTable.FindHandle(managedIdentifier);
						switch (shimNotificationType)
						{
						case ShimNotificationType.Phase0RequestNotify:
							try
							{
								if (obj is OletxPhase0VolatileEnlistmentContainer oletxPhase0VolatileEnlistmentContainer)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxPhase0VolatileEnlistmentContainer.TransactionIdentifier);
									oletxPhase0VolatileEnlistmentContainer.Phase0Request(abortingHint);
								}
								else if (obj is OletxEnlistment oletxEnlistment5)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxEnlistment5.TransactionIdentifier);
									oletxEnlistment5.Phase0Request(abortingHint);
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						case ShimNotificationType.VoteRequestNotify:
							if (obj is OletxPhase1VolatileEnlistmentContainer oletxPhase1VolatileEnlistmentContainer4)
							{
								System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxPhase1VolatileEnlistmentContainer4.TransactionIdentifier);
								oletxPhase1VolatileEnlistmentContainer4.VoteRequest();
							}
							else
							{
								Environment.FailFast(SR.GetString("InternalError"));
							}
							break;
						case ShimNotificationType.CommittedNotify:
							try
							{
								if (obj is OutcomeEnlistment outcomeEnlistment3)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(outcomeEnlistment3.TransactionIdentifier);
									outcomeEnlistment3.Committed();
								}
								else if (obj is OletxPhase1VolatileEnlistmentContainer oletxPhase1VolatileEnlistmentContainer3)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxPhase1VolatileEnlistmentContainer3.TransactionIdentifier);
									oletxPhase1VolatileEnlistmentContainer3.Committed();
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						case ShimNotificationType.AbortedNotify:
							try
							{
								if (obj is OutcomeEnlistment outcomeEnlistment2)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(outcomeEnlistment2.TransactionIdentifier);
									outcomeEnlistment2.Aborted();
								}
								else if (obj is OletxPhase1VolatileEnlistmentContainer oletxPhase1VolatileEnlistmentContainer2)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxPhase1VolatileEnlistmentContainer2.TransactionIdentifier);
									oletxPhase1VolatileEnlistmentContainer2.Aborted();
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						case ShimNotificationType.InDoubtNotify:
							try
							{
								if (obj is OutcomeEnlistment outcomeEnlistment)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(outcomeEnlistment.TransactionIdentifier);
									outcomeEnlistment.InDoubt();
								}
								else if (obj is OletxPhase1VolatileEnlistmentContainer oletxPhase1VolatileEnlistmentContainer)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxPhase1VolatileEnlistmentContainer.TransactionIdentifier);
									oletxPhase1VolatileEnlistmentContainer.InDoubt();
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						case ShimNotificationType.PrepareRequestNotify:
						{
							byte[] array = new byte[prepareInfoSize];
							Marshal.Copy(prepareInfo.DangerousGetHandle(), array, 0, Convert.ToInt32(prepareInfoSize));
							bool flag2 = true;
							try
							{
								if (obj is OletxEnlistment oletxEnlistment4)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxEnlistment4.TransactionIdentifier);
									flag2 = oletxEnlistment4.PrepareRequest(isSinglePhase, array);
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								if (flag2)
								{
									HandleTable.FreeHandle(managedIdentifier);
								}
							}
							break;
						}
						case ShimNotificationType.CommitRequestNotify:
							try
							{
								if (obj is OletxEnlistment oletxEnlistment3)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxEnlistment3.TransactionIdentifier);
									oletxEnlistment3.CommitRequest();
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						case ShimNotificationType.AbortRequestNotify:
							try
							{
								if (obj is OletxEnlistment oletxEnlistment2)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxEnlistment2.TransactionIdentifier);
									oletxEnlistment2.AbortRequest();
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						case ShimNotificationType.EnlistmentTmDownNotify:
							try
							{
								if (obj is OletxEnlistment oletxEnlistment)
								{
									System.Transactions.Diagnostics.DiagnosticTrace.SetActivityId(oletxEnlistment.TransactionIdentifier);
									oletxEnlistment.TMDown();
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						case ShimNotificationType.ResourceManagerTmDownNotify:
						{
							OletxResourceManager oletxResourceManager = obj as OletxResourceManager;
							try
							{
								if (oletxResourceManager != null)
								{
									oletxResourceManager.TMDown();
								}
								else if (obj is OletxInternalResourceManager oletxInternalResourceManager)
								{
									oletxInternalResourceManager.TMDown();
								}
								else
								{
									Environment.FailFast(SR.GetString("InternalError"));
								}
							}
							finally
							{
								HandleTable.FreeHandle(managedIdentifier);
							}
							break;
						}
						default:
							Environment.FailFast(SR.GetString("InternalError"));
							break;
						}
					}
					finally
					{
						prepareInfo?.Close();
						if (releaseRequired)
						{
							releaseRequired = false;
							processingTmDown = false;
							Monitor.Exit(proxyShimFactory);
						}
					}
				}
				while (shimNotificationType != 0);
				flag = true;
			}
			finally
			{
				if (releaseRequired)
				{
					releaseRequired = false;
					processingTmDown = false;
					Monitor.Exit(proxyShimFactory);
				}
				if (!flag && managedIdentifier != IntPtr.Zero)
				{
					HandleTable.FreeHandle(managedIdentifier);
				}
				Thread.EndCriticalRegion();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxTransactionManager.ShimNotificationCallback");
			}
		}

		internal OletxTransactionManager(string nodeName)
		{
			lock (ClassSyncObject)
			{
				if (proxyShimFactory == null)
				{
					if (NativeMethods.GetNotificationFactory(ShimWaitHandle.SafeWaitHandle, out proxyShimFactory) != 0)
					{
						throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("UnableToGetNotificationShimFactory"), null);
					}
					ThreadPool.UnsafeRegisterWaitForSingleObject(ShimWaitHandle, ShimNotificationCallback, null, -1, executeOnlyOnce: false);
				}
			}
			dtcTransactionManagerLock = new ReaderWriterLock();
			nodeNameField = nodeName;
			if (nodeNameField != null && nodeNameField.Length == 0)
			{
				nodeNameField = null;
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.DistributedTransactionManagerCreatedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), GetType(), nodeNameField);
			}
			configuredTransactionOptions.IsolationLevel = (isolationLevelProperty = TransactionManager.DefaultIsolationLevel);
			configuredTransactionOptions.Timeout = (timeoutProperty = TransactionManager.DefaultTimeout);
			internalResourceManager = new OletxInternalResourceManager(this);
			dtcTransactionManagerLock.AcquireWriterLock(-1);
			try
			{
				dtcTransactionManager = new DtcTransactionManager(nodeNameField, this);
			}
			finally
			{
				dtcTransactionManagerLock.ReleaseWriterLock();
			}
			if (resourceManagerHashTable == null)
			{
				resourceManagerHashTable = new Hashtable(2);
				resourceManagerHashTableLock = new ReaderWriterLock();
			}
		}

		internal OletxCommittableTransaction CreateTransaction(TransactionOptions properties)
		{
			//Discarded unreachable code: IL_00bf
			OletxCommittableTransaction oletxCommittableTransaction = null;
			RealOletxTransaction realOletxTransaction = null;
			ITransactionShim transactionShim = null;
			Guid transactionIdentifier = Guid.Empty;
			OutcomeEnlistment outcomeEnlistment = null;
			DistributedTransactionPermission distributedTransactionPermission = new DistributedTransactionPermission(PermissionState.Unrestricted);
			distributedTransactionPermission.Demand();
			TransactionManager.ValidateIsolationLevel(properties.IsolationLevel);
			if (IsolationLevel.Unspecified == properties.IsolationLevel)
			{
				properties.IsolationLevel = configuredTransactionOptions.IsolationLevel;
			}
			properties.Timeout = TransactionManager.ValidateTimeout(properties.Timeout);
			dtcTransactionManagerLock.AcquireReaderLock(-1);
			try
			{
				OletxTransactionIsolationLevel oletxTransactionIsolationLevel = ConvertIsolationLevel(properties.IsolationLevel);
				uint timeout = DtcTransactionManager.AdjustTimeout(properties.Timeout);
				outcomeEnlistment = new OutcomeEnlistment();
				IntPtr intPtr = IntPtr.Zero;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					intPtr = HandleTable.AllocHandle(outcomeEnlistment);
					dtcTransactionManager.ProxyShimFactory.BeginTransaction(timeout, oletxTransactionIsolationLevel, intPtr, out transactionIdentifier, out transactionShim);
				}
				catch (COMException comException)
				{
					ProxyException(comException);
					throw;
				}
				finally
				{
					if (transactionShim == null && intPtr != IntPtr.Zero)
					{
						HandleTable.FreeHandle(intPtr);
					}
				}
				realOletxTransaction = new RealOletxTransaction(this, transactionShim, outcomeEnlistment, transactionIdentifier, oletxTransactionIsolationLevel, isRoot: true);
				oletxCommittableTransaction = new OletxCommittableTransaction(realOletxTransaction);
				if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
				{
					System.Transactions.Diagnostics.TransactionCreatedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), oletxCommittableTransaction.TransactionTraceId);
					return oletxCommittableTransaction;
				}
				return oletxCommittableTransaction;
			}
			finally
			{
				dtcTransactionManagerLock.ReleaseReaderLock();
			}
		}

		internal OletxEnlistment ReenlistTransaction(Guid resourceManagerIdentifier, byte[] recoveryInformation, IEnlistmentNotificationInternal enlistmentNotification)
		{
			if (recoveryInformation == null)
			{
				throw new ArgumentNullException("recoveryInformation");
			}
			if (enlistmentNotification == null)
			{
				throw new ArgumentNullException("enlistmentNotification");
			}
			OletxResourceManager oletxResourceManager = RegisterResourceManager(resourceManagerIdentifier);
			if (oletxResourceManager == null)
			{
				throw new ArgumentException(SR.GetString("InvalidArgument"), "resourceManagerIdentifier");
			}
			if (oletxResourceManager.RecoveryCompleteCalledByApplication)
			{
				throw new InvalidOperationException(SR.GetString("ReenlistAfterRecoveryComplete"));
			}
			return oletxResourceManager.Reenlist(recoveryInformation.Length, recoveryInformation, enlistmentNotification);
		}

		internal void ResourceManagerRecoveryComplete(Guid resourceManagerIdentifier)
		{
			OletxResourceManager oletxResourceManager = RegisterResourceManager(resourceManagerIdentifier);
			if (oletxResourceManager.RecoveryCompleteCalledByApplication)
			{
				throw new InvalidOperationException(SR.GetString("DuplicateRecoveryComplete"));
			}
			oletxResourceManager.RecoveryComplete();
		}

		internal OletxResourceManager RegisterResourceManager(Guid resourceManagerIdentifier)
		{
			OletxResourceManager oletxResourceManager = null;
			resourceManagerHashTableLock.AcquireWriterLock(-1);
			try
			{
				if (resourceManagerHashTable[resourceManagerIdentifier] is OletxResourceManager result)
				{
					return result;
				}
				oletxResourceManager = new OletxResourceManager(this, resourceManagerIdentifier);
				resourceManagerHashTable.Add(resourceManagerIdentifier, oletxResourceManager);
				return oletxResourceManager;
			}
			finally
			{
				resourceManagerHashTableLock.ReleaseWriterLock();
			}
		}

		internal OletxResourceManager FindOrRegisterResourceManager(Guid resourceManagerIdentifier)
		{
			if (resourceManagerIdentifier == Guid.Empty)
			{
				throw new ArgumentException(SR.GetString("BadResourceManagerId"), "resourceManagerIdentifier");
			}
			OletxResourceManager oletxResourceManager = null;
			resourceManagerHashTableLock.AcquireReaderLock(-1);
			try
			{
				oletxResourceManager = resourceManagerHashTable[resourceManagerIdentifier] as OletxResourceManager;
			}
			finally
			{
				resourceManagerHashTableLock.ReleaseReaderLock();
			}
			if (oletxResourceManager == null)
			{
				return RegisterResourceManager(resourceManagerIdentifier);
			}
			return oletxResourceManager;
		}

		internal static void ProxyException(COMException comException)
		{
			if (NativeMethods.XACT_E_CONNECTION_DOWN == comException.ErrorCode || NativeMethods.XACT_E_TMNOTAVAILABLE == comException.ErrorCode)
			{
				throw TransactionManagerCommunicationException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionManagerCommunicationException"), comException);
			}
			if (NativeMethods.XACT_E_NETWORK_TX_DISABLED == comException.ErrorCode)
			{
				throw TransactionManagerCommunicationException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("NetworkTransactionsDisabled"), comException);
			}
			if (NativeMethods.XACT_E_FIRST <= comException.ErrorCode && NativeMethods.XACT_E_LAST >= comException.ErrorCode)
			{
				if (NativeMethods.XACT_E_NOTRANSACTION == comException.ErrorCode)
				{
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TransactionAlreadyOver"), comException);
				}
				throw TransactionException.Create(SR.GetString("TraceSourceOletx"), comException.Message, comException);
			}
		}

		internal void ReinitializeProxy()
		{
			dtcTransactionManagerLock.AcquireWriterLock(-1);
			try
			{
				if (dtcTransactionManager != null)
				{
					dtcTransactionManager.ReleaseProxy();
				}
			}
			finally
			{
				dtcTransactionManagerLock.ReleaseWriterLock();
			}
		}

		internal static OletxTransactionIsolationLevel ConvertIsolationLevel(IsolationLevel isolationLevel)
		{
			return isolationLevel switch
			{
				IsolationLevel.Serializable => OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE, 
				IsolationLevel.RepeatableRead => OletxTransactionIsolationLevel.ISOLATIONLEVEL_REPEATABLEREAD, 
				IsolationLevel.ReadCommitted => OletxTransactionIsolationLevel.ISOLATIONLEVEL_CURSORSTABILITY, 
				IsolationLevel.ReadUncommitted => OletxTransactionIsolationLevel.ISOLATIONLEVEL_READUNCOMMITTED, 
				IsolationLevel.Chaos => OletxTransactionIsolationLevel.ISOLATIONLEVEL_CHAOS, 
				IsolationLevel.Unspecified => OletxTransactionIsolationLevel.ISOLATIONLEVEL_UNSPECIFIED, 
				_ => OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE, 
			};
		}

		internal static IsolationLevel ConvertIsolationLevelFromProxyValue(OletxTransactionIsolationLevel proxyIsolationLevel)
		{
			return proxyIsolationLevel switch
			{
				OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE => IsolationLevel.Serializable, 
				OletxTransactionIsolationLevel.ISOLATIONLEVEL_REPEATABLEREAD => IsolationLevel.RepeatableRead, 
				OletxTransactionIsolationLevel.ISOLATIONLEVEL_CURSORSTABILITY => IsolationLevel.ReadCommitted, 
				OletxTransactionIsolationLevel.ISOLATIONLEVEL_READUNCOMMITTED => IsolationLevel.ReadUncommitted, 
				OletxTransactionIsolationLevel.ISOLATIONLEVEL_UNSPECIFIED => IsolationLevel.Unspecified, 
				OletxTransactionIsolationLevel.ISOLATIONLEVEL_CHAOS => IsolationLevel.Chaos, 
				_ => IsolationLevel.Serializable, 
			};
		}
	}
	internal class OletxInternalResourceManager
	{
		private OletxTransactionManager oletxTm;

		private Guid myGuid;

		internal IResourceManagerShim resourceManagerShim;

		internal Guid Identifier => myGuid;

		internal OletxInternalResourceManager(OletxTransactionManager oletxTm)
		{
			this.oletxTm = oletxTm;
			myGuid = Guid.NewGuid();
		}

		public void TMDown()
		{
			resourceManagerShim = null;
			Transaction transaction = null;
			RealOletxTransaction realOletxTransaction = null;
			IDictionaryEnumerator dictionaryEnumerator = null;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxInternalResourceManager.TMDown");
			}
			Hashtable hashtable = null;
			lock (TransactionManager.PromotedTransactionTable.SyncRoot)
			{
				hashtable = (Hashtable)TransactionManager.PromotedTransactionTable.Clone();
			}
			dictionaryEnumerator = hashtable.GetEnumerator();
			while (dictionaryEnumerator.MoveNext())
			{
				WeakReference weakReference = (WeakReference)dictionaryEnumerator.Value;
				if (weakReference == null)
				{
					continue;
				}
				transaction = (Transaction)weakReference.Target;
				if (null != transaction)
				{
					realOletxTransaction = transaction.internalTransaction.PromotedTransaction.realOletxTransaction;
					if (realOletxTransaction.OletxTransactionManagerInstance == oletxTm)
					{
						realOletxTransaction.TMDown();
					}
				}
			}
			Hashtable hashtable2 = null;
			if (OletxTransactionManager.resourceManagerHashTable != null)
			{
				OletxTransactionManager.resourceManagerHashTableLock.AcquireReaderLock(-1);
				try
				{
					hashtable2 = (Hashtable)OletxTransactionManager.resourceManagerHashTable.Clone();
				}
				finally
				{
					OletxTransactionManager.resourceManagerHashTableLock.ReleaseReaderLock();
				}
			}
			if (hashtable2 != null)
			{
				dictionaryEnumerator = hashtable2.GetEnumerator();
				while (dictionaryEnumerator.MoveNext())
				{
					((OletxResourceManager)dictionaryEnumerator.Value)?.TMDownFromInternalRM(oletxTm);
				}
			}
			oletxTm.dtcTransactionManagerLock.AcquireWriterLock(-1);
			try
			{
				oletxTm.ReinitializeProxy();
			}
			finally
			{
				oletxTm.dtcTransactionManagerLock.ReleaseWriterLock();
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxInternalResourceManager.TMDown");
			}
		}

		internal void CallReenlistComplete()
		{
			resourceManagerShim.ReenlistComplete();
		}
	}
	internal abstract class OletxVolatileEnlistmentContainer
	{
		protected RealOletxTransaction realOletxTransaction;

		protected ArrayList enlistmentList;

		protected int phase;

		protected int outstandingNotifications;

		protected bool collectedVoteYes;

		protected int incompleteDependentClones;

		protected bool alreadyVoted;

		internal Guid TransactionIdentifier => realOletxTransaction.Identifier;

		internal abstract void DecrementOutstandingNotifications(bool voteYes);

		internal abstract void AddDependentClone();

		internal abstract void DependentCloneCompleted();

		internal abstract void RollbackFromTransaction();

		internal abstract void OutcomeFromTransaction(TransactionStatus outcome);

		internal abstract void Committed();

		internal abstract void Aborted();

		internal abstract void InDoubt();
	}
	internal class OletxPhase0VolatileEnlistmentContainer : OletxVolatileEnlistmentContainer
	{
		private IPhase0EnlistmentShim phase0EnlistmentShim;

		private bool aborting;

		private bool tmWentDown;

		internal bool NewEnlistmentsAllowed => -1 == phase;

		internal IPhase0EnlistmentShim Phase0EnlistmentShim
		{
			get
			{
				IPhase0EnlistmentShim phase0EnlistmentShim = null;
				lock (this)
				{
					return this.phase0EnlistmentShim;
				}
			}
			set
			{
				lock (this)
				{
					if (aborting || tmWentDown)
					{
						value.Phase0Done(voteYes: false);
					}
					phase0EnlistmentShim = value;
				}
			}
		}

		internal OletxPhase0VolatileEnlistmentContainer(RealOletxTransaction realOletxTransaction)
		{
			phase0EnlistmentShim = null;
			base.realOletxTransaction = realOletxTransaction;
			phase = -1;
			aborting = false;
			tmWentDown = false;
			outstandingNotifications = 0;
			incompleteDependentClones = 0;
			alreadyVoted = false;
			collectedVoteYes = true;
			enlistmentList = new ArrayList();
			realOletxTransaction.IncrementUndecidedEnlistments();
		}

		internal void TMDown()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPhase0VolatileEnlistmentContainer.TMDown");
			}
			tmWentDown = true;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPhase0VolatileEnlistmentContainer.TMDown");
			}
		}

		internal void AddEnlistment(OletxVolatileEnlistment enlistment)
		{
			lock (this)
			{
				if (-1 != phase)
				{
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TooLate"), null);
				}
				enlistmentList.Add(enlistment);
			}
		}

		internal override void AddDependentClone()
		{
			lock (this)
			{
				if (-1 != phase)
				{
					throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceOletx"), null);
				}
				incompleteDependentClones++;
			}
		}

		internal override void DependentCloneCompleted()
		{
			bool flag = false;
			lock (this)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					string methodName = "OletxPhase0VolatileEnlistmentContainer.DependentCloneCompleted, outstandingNotifications = " + outstandingNotifications.ToString(CultureInfo.CurrentCulture) + ", incompleteDependentClones = " + incompleteDependentClones.ToString(CultureInfo.CurrentCulture) + ", phase = " + phase.ToString(CultureInfo.CurrentCulture);
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
				}
				incompleteDependentClones--;
				if (incompleteDependentClones == 0 && phase == 0)
				{
					outstandingNotifications++;
					flag = true;
				}
			}
			if (flag)
			{
				DecrementOutstandingNotifications(voteYes: true);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase0VolatileEnlistmentContainer.DependentCloneCompleted";
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}

		internal override void RollbackFromTransaction()
		{
			lock (this)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					string methodName = "OletxPhase0VolatileEnlistmentContainer.RollbackFromTransaction, outstandingNotifications = " + outstandingNotifications.ToString(CultureInfo.CurrentCulture) + ", incompleteDependentClones = " + incompleteDependentClones.ToString(CultureInfo.CurrentCulture);
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
				}
				if (phase == 0 && (0 < outstandingNotifications || 0 < incompleteDependentClones))
				{
					alreadyVoted = true;
					if (Phase0EnlistmentShim != null)
					{
						Phase0EnlistmentShim.Phase0Done(voteYes: false);
					}
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase0VolatileEnlistmentContainer.RollbackFromTransaction";
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}

		internal override void DecrementOutstandingNotifications(bool voteYes)
		{
			bool flag = false;
			IPhase0EnlistmentShim phase0EnlistmentShim = null;
			lock (this)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					string methodName = "OletxPhase0VolatileEnlistmentContainer.DecrementOutstandingNotifications, outstandingNotifications = " + outstandingNotifications.ToString(CultureInfo.CurrentCulture) + ", incompleteDependentClones = " + incompleteDependentClones.ToString(CultureInfo.CurrentCulture);
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
				}
				outstandingNotifications--;
				collectedVoteYes = collectedVoteYes && voteYes;
				if (outstandingNotifications == 0 && incompleteDependentClones == 0)
				{
					if (phase == 0 && !alreadyVoted)
					{
						flag = true;
						alreadyVoted = true;
						phase0EnlistmentShim = this.phase0EnlistmentShim;
					}
					realOletxTransaction.DecrementUndecidedEnlistments();
				}
			}
			try
			{
				if (flag)
				{
					phase0EnlistmentShim?.Phase0Done(collectedVoteYes && !realOletxTransaction.Doomed);
				}
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN == ex.ErrorCode || NativeMethods.XACT_E_TMNOTAVAILABLE == ex.ErrorCode)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
					}
				}
				else
				{
					if (NativeMethods.XACT_E_PROTOCOL != ex.ErrorCode)
					{
						throw;
					}
					this.phase0EnlistmentShim = null;
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
					}
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase0VolatileEnlistmentContainer.DecrementOutstandingNotifications";
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}

		internal override void OutcomeFromTransaction(TransactionStatus outcome)
		{
			if (TransactionStatus.Committed == outcome)
			{
				Committed();
			}
			else if (TransactionStatus.Aborted == outcome)
			{
				Aborted();
			}
			else if (TransactionStatus.InDoubt == outcome)
			{
				InDoubt();
			}
		}

		internal override void Committed()
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			lock (this)
			{
				phase = 2;
				num = enlistmentList.Count;
			}
			for (int i = 0; i < num; i++)
			{
				if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistment2.Commit();
			}
		}

		internal override void Aborted()
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			lock (this)
			{
				phase = 2;
				num = enlistmentList.Count;
			}
			for (int i = 0; i < num; i++)
			{
				if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistment2.Rollback();
			}
		}

		internal override void InDoubt()
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			lock (this)
			{
				phase = 2;
				num = enlistmentList.Count;
			}
			for (int i = 0; i < num; i++)
			{
				if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistment2.InDoubt();
			}
		}

		internal void Phase0Request(bool abortHint)
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			OletxCommittableTransaction oletxCommittableTransaction = null;
			bool flag = false;
			lock (this)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					string methodName = "OletxPhase0VolatileEnlistmentContainer.Phase0Request, abortHint = " + abortHint.ToString(CultureInfo.CurrentCulture) + ", phase = " + phase.ToString(CultureInfo.CurrentCulture);
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
				}
				aborting = abortHint;
				oletxCommittableTransaction = realOletxTransaction.committableTransaction;
				if (oletxCommittableTransaction != null && !oletxCommittableTransaction.CommitCalled)
				{
					flag = true;
					aborting = true;
				}
				if (2 != phase && -1 != phase)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPhase0VolatileEnlistmentContainer.Phase0Request, phase != -1");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				if (-1 == phase)
				{
					phase = 0;
				}
				if (aborting || tmWentDown || flag || 2 == phase)
				{
					if (phase0EnlistmentShim == null)
					{
						return;
					}
					try
					{
						phase0EnlistmentShim.Phase0Done(voteYes: false);
						return;
					}
					catch (COMException exception)
					{
						if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
						{
							System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), exception);
						}
						return;
					}
				}
				outstandingNotifications = enlistmentList.Count;
				num = enlistmentList.Count;
				if (num == 0)
				{
					outstandingNotifications = 1;
				}
			}
			if (num == 0)
			{
				DecrementOutstandingNotifications(voteYes: true);
			}
			else
			{
				for (int i = 0; i < num; i++)
				{
					if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
					{
						if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
						{
							System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
						}
						throw new InvalidOperationException(SR.GetString("InternalError"));
					}
					oletxVolatileEnlistment2.Prepare(this);
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase0VolatileEnlistmentContainer.Phase0Request, abortHint = " + abortHint.ToString(CultureInfo.CurrentCulture);
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}
	}
	internal class OletxPhase1VolatileEnlistmentContainer : OletxVolatileEnlistmentContainer
	{
		private IVoterBallotShim voterBallotShim;

		internal IntPtr voterHandle = IntPtr.Zero;

		internal IVoterBallotShim VoterBallotShim
		{
			get
			{
				IVoterBallotShim voterBallotShim = null;
				lock (this)
				{
					return this.voterBallotShim;
				}
			}
			set
			{
				lock (this)
				{
					voterBallotShim = value;
				}
			}
		}

		internal OletxPhase1VolatileEnlistmentContainer(RealOletxTransaction realOletxTransaction)
		{
			voterBallotShim = null;
			base.realOletxTransaction = realOletxTransaction;
			phase = -1;
			outstandingNotifications = 0;
			incompleteDependentClones = 0;
			alreadyVoted = false;
			collectedVoteYes = true;
			enlistmentList = new ArrayList();
			realOletxTransaction.IncrementUndecidedEnlistments();
		}

		internal void AddEnlistment(OletxVolatileEnlistment enlistment)
		{
			lock (this)
			{
				if (-1 != phase)
				{
					throw TransactionException.Create(SR.GetString("TraceSourceOletx"), SR.GetString("TooLate"), null);
				}
				enlistmentList.Add(enlistment);
			}
		}

		internal override void AddDependentClone()
		{
			lock (this)
			{
				if (-1 != phase)
				{
					throw TransactionException.CreateTransactionStateException(SR.GetString("TraceSourceOletx"), null);
				}
				incompleteDependentClones++;
			}
		}

		internal override void DependentCloneCompleted()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName = "OletxPhase1VolatileEnlistmentContainer.DependentCloneCompleted, outstandingNotifications = " + outstandingNotifications.ToString(CultureInfo.CurrentCulture) + ", incompleteDependentClones = " + incompleteDependentClones.ToString(CultureInfo.CurrentCulture) + ", phase = " + phase.ToString(CultureInfo.CurrentCulture);
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
			}
			incompleteDependentClones--;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase1VolatileEnlistmentContainer.DependentCloneCompleted";
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}

		internal override void RollbackFromTransaction()
		{
			bool flag = false;
			IVoterBallotShim voterBallotShim = null;
			lock (this)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					string methodName = "OletxPhase1VolatileEnlistmentContainer.RollbackFromTransaction, outstandingNotifications = " + outstandingNotifications.ToString(CultureInfo.CurrentCulture) + ", incompleteDependentClones = " + incompleteDependentClones.ToString(CultureInfo.CurrentCulture);
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
				}
				if (1 == phase && 0 < outstandingNotifications)
				{
					alreadyVoted = true;
					flag = true;
					voterBallotShim = this.voterBallotShim;
				}
			}
			if (flag)
			{
				try
				{
					voterBallotShim?.Vote(voteYes: false);
					Aborted();
				}
				catch (COMException ex)
				{
					if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex.ErrorCode)
					{
						throw;
					}
					lock (this)
					{
						if (1 == phase)
						{
							InDoubt();
						}
					}
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
					}
				}
				finally
				{
					HandleTable.FreeHandle(voterHandle);
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase1VolatileEnlistmentContainer.RollbackFromTransaction";
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}

		internal override void DecrementOutstandingNotifications(bool voteYes)
		{
			bool flag = false;
			IVoterBallotShim voterBallotShim = null;
			lock (this)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					string methodName = "OletxPhase1VolatileEnlistmentContainer.DecrementOutstandingNotifications, outstandingNotifications = " + outstandingNotifications.ToString(CultureInfo.CurrentCulture) + ", incompleteDependentClones = " + incompleteDependentClones.ToString(CultureInfo.CurrentCulture);
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
				}
				outstandingNotifications--;
				collectedVoteYes = collectedVoteYes && voteYes;
				if (outstandingNotifications == 0)
				{
					if (1 == phase && !alreadyVoted)
					{
						flag = true;
						alreadyVoted = true;
						voterBallotShim = VoterBallotShim;
					}
					realOletxTransaction.DecrementUndecidedEnlistments();
				}
			}
			try
			{
				if (flag)
				{
					if (collectedVoteYes && !realOletxTransaction.Doomed)
					{
						voterBallotShim?.Vote(voteYes: true);
					}
					else
					{
						try
						{
							voterBallotShim?.Vote(voteYes: false);
							Aborted();
						}
						finally
						{
							HandleTable.FreeHandle(voterHandle);
						}
					}
				}
			}
			catch (COMException ex)
			{
				if (NativeMethods.XACT_E_CONNECTION_DOWN != ex.ErrorCode && NativeMethods.XACT_E_TMNOTAVAILABLE != ex.ErrorCode)
				{
					throw;
				}
				lock (this)
				{
					if (1 == phase)
					{
						InDoubt();
					}
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.ExceptionConsumedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), ex);
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase1VolatileEnlistmentContainer.DecrementOutstandingNotifications";
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}

		internal override void OutcomeFromTransaction(TransactionStatus outcome)
		{
			bool flag = false;
			bool flag2 = false;
			lock (this)
			{
				if (1 == phase && 0 < outstandingNotifications)
				{
					if (TransactionStatus.Aborted == outcome)
					{
						flag = true;
					}
					else if (TransactionStatus.InDoubt == outcome)
					{
						flag2 = true;
					}
				}
			}
			if (flag)
			{
				Aborted();
			}
			if (flag2)
			{
				InDoubt();
			}
		}

		internal override void Committed()
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			lock (this)
			{
				phase = 2;
				num = enlistmentList.Count;
			}
			for (int i = 0; i < num; i++)
			{
				if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistment2.Commit();
			}
		}

		internal override void Aborted()
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			lock (this)
			{
				phase = 2;
				num = enlistmentList.Count;
			}
			for (int i = 0; i < num; i++)
			{
				if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistment2.Rollback();
			}
		}

		internal override void InDoubt()
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			lock (this)
			{
				phase = 2;
				num = enlistmentList.Count;
			}
			for (int i = 0; i < num; i++)
			{
				if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistment2.InDoubt();
			}
		}

		internal void VoteRequest()
		{
			OletxVolatileEnlistment oletxVolatileEnlistment = null;
			int num = 0;
			bool flag = false;
			lock (this)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					string methodName = "OletxPhase1VolatileEnlistmentContainer.VoteRequest";
					System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName);
				}
				phase = 1;
				if (0 < incompleteDependentClones)
				{
					flag = true;
					outstandingNotifications = 1;
				}
				else
				{
					outstandingNotifications = enlistmentList.Count;
					num = enlistmentList.Count;
					if (num == 0)
					{
						outstandingNotifications = 1;
					}
				}
				realOletxTransaction.TooLateForEnlistments = true;
			}
			if (flag)
			{
				DecrementOutstandingNotifications(voteYes: false);
			}
			else if (num == 0)
			{
				DecrementOutstandingNotifications(voteYes: true);
			}
			else
			{
				for (int i = 0; i < num; i++)
				{
					if (!(enlistmentList[i] is OletxVolatileEnlistment oletxVolatileEnlistment2))
					{
						if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
						{
							System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
						}
						throw new InvalidOperationException(SR.GetString("InternalError"));
					}
					oletxVolatileEnlistment2.Prepare(this);
				}
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				string methodName2 = "OletxPhase1VolatileEnlistmentContainer.VoteRequest";
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), methodName2);
			}
		}
	}
	internal class OletxVolatileEnlistment : OletxBaseEnlistment, IPromotedEnlistment
	{
		private enum OletxVolatileEnlistmentState
		{
			Active,
			Preparing,
			Committing,
			Aborting,
			Prepared,
			Aborted,
			InDoubt,
			Done
		}

		private IEnlistmentNotificationInternal iEnlistmentNotification;

		private OletxVolatileEnlistmentState state;

		private OletxVolatileEnlistmentContainer container;

		internal bool enlistDuringPrepareRequired;

		private TransactionStatus pendingOutcome;

		InternalEnlistment IPromotedEnlistment.InternalEnlistment
		{
			get
			{
				return internalEnlistment;
			}
			set
			{
				internalEnlistment = value;
			}
		}

		internal OletxVolatileEnlistment(IEnlistmentNotificationInternal enlistmentNotification, EnlistmentOptions enlistmentOptions, OletxTransaction oletxTransaction)
			: base(null, oletxTransaction)
		{
			iEnlistmentNotification = enlistmentNotification;
			enlistDuringPrepareRequired = (enlistmentOptions & EnlistmentOptions.EnlistDuringPrepareRequired) != 0;
			container = null;
			pendingOutcome = TransactionStatus.Active;
			if (System.Transactions.Diagnostics.DiagnosticTrace.Information)
			{
				System.Transactions.Diagnostics.EnlistmentTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentType.Volatile, enlistmentOptions);
			}
		}

		internal void Prepare(OletxVolatileEnlistmentContainer container)
		{
			OletxVolatileEnlistmentState oletxVolatileEnlistmentState = OletxVolatileEnlistmentState.Active;
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			lock (this)
			{
				enlistmentNotificationInternal = iEnlistmentNotification;
				oletxVolatileEnlistmentState = ((state != 0) ? state : (state = OletxVolatileEnlistmentState.Preparing));
				this.container = container;
			}
			if (OletxVolatileEnlistmentState.Preparing == oletxVolatileEnlistmentState)
			{
				if (enlistmentNotificationInternal != null)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Prepare);
					}
					enlistmentNotificationInternal.Prepare(this);
					return;
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
				}
				throw new InvalidOperationException(SR.GetString("InternalError"));
			}
			if (OletxVolatileEnlistmentState.Done == oletxVolatileEnlistmentState)
			{
				container.DecrementOutstandingNotifications(voteYes: true);
				return;
			}
			if (OletxVolatileEnlistmentState.Prepared == oletxVolatileEnlistmentState && enlistDuringPrepareRequired)
			{
				container.DecrementOutstandingNotifications(voteYes: true);
				return;
			}
			if (OletxVolatileEnlistmentState.Aborting == oletxVolatileEnlistmentState || OletxVolatileEnlistmentState.Aborted == oletxVolatileEnlistmentState)
			{
				container.DecrementOutstandingNotifications(voteYes: false);
				return;
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
			{
				System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
			}
			throw new InvalidOperationException(SR.GetString("InternalError"));
		}

		internal void Commit()
		{
			OletxVolatileEnlistmentState oletxVolatileEnlistmentState = OletxVolatileEnlistmentState.Active;
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			lock (this)
			{
				if (OletxVolatileEnlistmentState.Prepared == state)
				{
					oletxVolatileEnlistmentState = (state = OletxVolatileEnlistmentState.Committing);
					enlistmentNotificationInternal = iEnlistmentNotification;
				}
				else
				{
					oletxVolatileEnlistmentState = state;
				}
			}
			if (OletxVolatileEnlistmentState.Committing == oletxVolatileEnlistmentState)
			{
				if (enlistmentNotificationInternal == null)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Commit);
				}
				enlistmentNotificationInternal.Commit(this);
			}
			else if (OletxVolatileEnlistmentState.Done != oletxVolatileEnlistmentState)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
				}
				throw new InvalidOperationException(SR.GetString("InternalError"));
			}
		}

		internal void Rollback()
		{
			OletxVolatileEnlistmentState oletxVolatileEnlistmentState = OletxVolatileEnlistmentState.Active;
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			lock (this)
			{
				if (OletxVolatileEnlistmentState.Prepared == state || state == OletxVolatileEnlistmentState.Active)
				{
					oletxVolatileEnlistmentState = (state = OletxVolatileEnlistmentState.Aborting);
					enlistmentNotificationInternal = iEnlistmentNotification;
				}
				else
				{
					if (OletxVolatileEnlistmentState.Preparing == state)
					{
						pendingOutcome = TransactionStatus.Aborted;
					}
					oletxVolatileEnlistmentState = state;
				}
			}
			if (OletxVolatileEnlistmentState.Aborting == oletxVolatileEnlistmentState)
			{
				if (enlistmentNotificationInternal != null)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
					{
						System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.Rollback);
					}
					enlistmentNotificationInternal.Rollback(this);
				}
			}
			else if (OletxVolatileEnlistmentState.Preparing != oletxVolatileEnlistmentState && OletxVolatileEnlistmentState.Done != oletxVolatileEnlistmentState)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
				}
				throw new InvalidOperationException(SR.GetString("InternalError"));
			}
		}

		internal void InDoubt()
		{
			OletxVolatileEnlistmentState oletxVolatileEnlistmentState = OletxVolatileEnlistmentState.Active;
			IEnlistmentNotificationInternal enlistmentNotificationInternal = null;
			lock (this)
			{
				if (OletxVolatileEnlistmentState.Prepared == state)
				{
					oletxVolatileEnlistmentState = (state = OletxVolatileEnlistmentState.InDoubt);
					enlistmentNotificationInternal = iEnlistmentNotification;
				}
				else
				{
					if (OletxVolatileEnlistmentState.Preparing == state)
					{
						pendingOutcome = TransactionStatus.InDoubt;
					}
					oletxVolatileEnlistmentState = state;
				}
			}
			if (OletxVolatileEnlistmentState.InDoubt == oletxVolatileEnlistmentState)
			{
				if (enlistmentNotificationInternal == null)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
				{
					System.Transactions.Diagnostics.EnlistmentNotificationCallTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.NotificationCall.InDoubt);
				}
				enlistmentNotificationInternal.InDoubt(this);
			}
			else if (OletxVolatileEnlistmentState.Preparing != oletxVolatileEnlistmentState && OletxVolatileEnlistmentState.Done != oletxVolatileEnlistmentState)
			{
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
				}
				throw new InvalidOperationException(SR.GetString("InternalError"));
			}
		}

		void IPromotedEnlistment.EnlistmentDone()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.EnlistmentDone");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.Done);
			}
			OletxVolatileEnlistmentState oletxVolatileEnlistmentState = OletxVolatileEnlistmentState.Active;
			OletxVolatileEnlistmentContainer oletxVolatileEnlistmentContainer = null;
			lock (this)
			{
				oletxVolatileEnlistmentState = state;
				oletxVolatileEnlistmentContainer = container;
				if (state != 0 && OletxVolatileEnlistmentState.Preparing != state && OletxVolatileEnlistmentState.Aborting != state && OletxVolatileEnlistmentState.Committing != state && OletxVolatileEnlistmentState.InDoubt != state)
				{
					throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
				}
				state = OletxVolatileEnlistmentState.Done;
			}
			if (OletxVolatileEnlistmentState.Preparing == oletxVolatileEnlistmentState)
			{
				oletxVolatileEnlistmentContainer?.DecrementOutstandingNotifications(voteYes: true);
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxEnlistment.EnlistmentDone");
			}
		}

		void IPromotedEnlistment.Prepared()
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.Prepared");
				System.Transactions.Diagnostics.EnlistmentCallbackPositiveTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.Prepared);
			}
			OletxVolatileEnlistmentContainer oletxVolatileEnlistmentContainer = null;
			TransactionStatus transactionStatus = TransactionStatus.Active;
			lock (this)
			{
				if (OletxVolatileEnlistmentState.Preparing != state)
				{
					throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
				}
				state = OletxVolatileEnlistmentState.Prepared;
				transactionStatus = pendingOutcome;
				if (container == null)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistmentContainer = container;
			}
			oletxVolatileEnlistmentContainer.DecrementOutstandingNotifications(voteYes: true);
			switch (transactionStatus)
			{
			case TransactionStatus.Aborted:
				Rollback();
				break;
			case TransactionStatus.InDoubt:
				InDoubt();
				break;
			default:
				if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
				{
					System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
				}
				throw new InvalidOperationException(SR.GetString("InternalError"));
			case TransactionStatus.Active:
				break;
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.Prepared");
			}
		}

		void IPromotedEnlistment.ForceRollback()
		{
			((IPromotedEnlistment)this).ForceRollback((Exception)null);
		}

		void IPromotedEnlistment.ForceRollback(Exception e)
		{
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodEnteredTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.ForceRollback");
			}
			if (System.Transactions.Diagnostics.DiagnosticTrace.Warning)
			{
				System.Transactions.Diagnostics.EnlistmentCallbackNegativeTraceRecord.Trace(SR.GetString("TraceSourceOletx"), base.InternalTraceIdentifier, System.Transactions.Diagnostics.EnlistmentCallback.ForceRollback);
			}
			OletxVolatileEnlistmentContainer oletxVolatileEnlistmentContainer = null;
			lock (this)
			{
				if (OletxVolatileEnlistmentState.Preparing != state)
				{
					throw TransactionException.CreateEnlistmentStateException(SR.GetString("TraceSourceOletx"), null);
				}
				state = OletxVolatileEnlistmentState.Done;
				if (container == null)
				{
					if (System.Transactions.Diagnostics.DiagnosticTrace.Critical)
					{
						System.Transactions.Diagnostics.InternalErrorTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "");
					}
					throw new InvalidOperationException(SR.GetString("InternalError"));
				}
				oletxVolatileEnlistmentContainer = container;
			}
			Interlocked.CompareExchange(ref oletxTransaction.realOletxTransaction.innerException, e, null);
			oletxVolatileEnlistmentContainer.DecrementOutstandingNotifications(voteYes: false);
			if (System.Transactions.Diagnostics.DiagnosticTrace.Verbose)
			{
				System.Transactions.Diagnostics.MethodExitedTraceRecord.Trace(SR.GetString("TraceSourceOletx"), "OletxPreparingEnlistment.ForceRollback");
			}
		}

		void IPromotedEnlistment.Committed()
		{
			throw new InvalidOperationException();
		}

		void IPromotedEnlistment.Aborted()
		{
			throw new InvalidOperationException();
		}

		void IPromotedEnlistment.Aborted(Exception e)
		{
			throw new InvalidOperationException();
		}

		void IPromotedEnlistment.InDoubt()
		{
			throw new InvalidOperationException();
		}

		void IPromotedEnlistment.InDoubt(Exception e)
		{
			throw new InvalidOperationException();
		}

		byte[] IPromotedEnlistment.GetRecoveryInformation()
		{
			throw TransactionException.CreateInvalidOperationException(SR.GetString("TraceSourceOletx"), SR.GetString("VolEnlistNoRecoveryInfo"), null);
		}
	}
}
namespace System.Transactions.Configuration
{
	internal static class ConfigurationStrings
	{
		internal const string DefaultDistributedTransactionManagerName = "";

		internal const string DefaultMaxTimeout = "00:10:00";

		internal const string DefaultTimeout = "00:01:00";

		internal const string TimeSpanZero = "00:00:00";

		internal const string DefaultSettingsSectionName = "defaultSettings";

		internal const string DistributedTransactionManagerName = "distributedTransactionManagerName";

		internal const string MaxTimeout = "maxTimeout";

		internal const string MachineSettingsSectionName = "machineSettings";

		internal const string SectionGroupName = "system.transactions";

		internal const string Timeout = "timeout";

		internal static string DefaultSettingsSectionPath => GetSectionPath("defaultSettings");

		internal static string MachineSettingsSectionPath => GetSectionPath("machineSettings");

		internal static string GetSectionPath(string sectionName)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0}/{1}", "system.transactions", sectionName);
		}

		internal static bool IsValidTimeSpan(TimeSpan span)
		{
			return span >= TimeSpan.Zero;
		}
	}
	public sealed class DefaultSettingsSection : ConfigurationSection
	{
		[ConfigurationProperty("distributedTransactionManagerName", DefaultValue = "")]
		public string DistributedTransactionManagerName
		{
			get
			{
				return (string)base["distributedTransactionManagerName"];
			}
			set
			{
				base["distributedTransactionManagerName"] = value;
			}
		}

		[ConfigurationProperty("timeout", DefaultValue = "00:01:00")]
		[TimeSpanValidator(MinValueString = "00:00:00", MaxValueString = "10675199.02:48:05.4775807")]
		public TimeSpan Timeout
		{
			get
			{
				return (TimeSpan)base["timeout"];
			}
			set
			{
				if (!ConfigurationStrings.IsValidTimeSpan(value))
				{
					throw new ArgumentOutOfRangeException("Timeout", SR.GetString("ConfigInvalidTimeSpanValue"));
				}
				base["timeout"] = value;
			}
		}

		protected internal override ConfigurationPropertyCollection Properties
		{
			protected get
			{
				ConfigurationPropertyCollection configurationPropertyCollection = new ConfigurationPropertyCollection();
				configurationPropertyCollection.Add(new ConfigurationProperty("distributedTransactionManagerName", typeof(string), "", ConfigurationPropertyOptions.None));
				configurationPropertyCollection.Add(new ConfigurationProperty("timeout", typeof(TimeSpan), "00:01:00", null, new TimeSpanValidator(TimeSpan.Zero, TimeSpan.MaxValue), ConfigurationPropertyOptions.None));
				return configurationPropertyCollection;
			}
		}

		internal static DefaultSettingsSection GetSection()
		{
			DefaultSettingsSection defaultSettingsSection = (DefaultSettingsSection)System.Configuration.PrivilegedConfigurationManager.GetSection(ConfigurationStrings.DefaultSettingsSectionPath);
			if (defaultSettingsSection == null)
			{
				throw new ConfigurationErrorsException(string.Format(CultureInfo.CurrentCulture, SR.GetString("ConfigurationSectionNotFound"), ConfigurationStrings.DefaultSettingsSectionPath));
			}
			return defaultSettingsSection;
		}
	}
	public sealed class MachineSettingsSection : ConfigurationSection
	{
		[ConfigurationProperty("maxTimeout", DefaultValue = "00:10:00")]
		[TimeSpanValidator(MinValueString = "00:00:00", MaxValueString = "10675199.02:48:05.4775807")]
		public TimeSpan MaxTimeout
		{
			get
			{
				return (TimeSpan)base["maxTimeout"];
			}
			set
			{
				if (!ConfigurationStrings.IsValidTimeSpan(value))
				{
					throw new ArgumentOutOfRangeException("MaxTimeout", SR.GetString("ConfigInvalidTimeSpanValue"));
				}
				base["maxTimeout"] = value;
			}
		}

		protected internal override ConfigurationPropertyCollection Properties
		{
			protected get
			{
				ConfigurationPropertyCollection configurationPropertyCollection = new ConfigurationPropertyCollection();
				configurationPropertyCollection.Add(new ConfigurationProperty("maxTimeout", typeof(TimeSpan), "00:10:00", null, new TimeSpanValidator(TimeSpan.Zero, TimeSpan.MaxValue), ConfigurationPropertyOptions.None));
				return configurationPropertyCollection;
			}
		}

		internal static MachineSettingsSection GetSection()
		{
			MachineSettingsSection machineSettingsSection = (MachineSettingsSection)System.Configuration.PrivilegedConfigurationManager.GetSection(ConfigurationStrings.MachineSettingsSectionPath);
			if (machineSettingsSection == null)
			{
				throw new ConfigurationErrorsException(string.Format(CultureInfo.CurrentCulture, SR.GetString("ConfigurationSectionNotFound"), ConfigurationStrings.MachineSettingsSectionPath));
			}
			return machineSettingsSection;
		}
	}
	public sealed class TransactionsSectionGroup : ConfigurationSectionGroup
	{
		[ConfigurationProperty("defaultSettings")]
		public DefaultSettingsSection DefaultSettings => (DefaultSettingsSection)base.Sections["defaultSettings"];

		[ConfigurationProperty("machineSettings")]
		public MachineSettingsSection MachineSettings => (MachineSettingsSection)base.Sections["machineSettings"];

		public static TransactionsSectionGroup GetSectionGroup(System.Configuration.Configuration config)
		{
			if (config == null)
			{
				throw new ArgumentNullException("config");
			}
			return (TransactionsSectionGroup)config.GetSectionGroup("system.transactions");
		}
	}
}
namespace System.Transactions.Diagnostics
{
	internal class Activity : IDisposable
	{
		private Guid oldGuid;

		private Guid newGuid;

		private bool emitTransfer;

		private bool mustDispose;

		private Activity(ref Guid newGuid, bool emitTransfer)
		{
			this.emitTransfer = emitTransfer;
			if (!DiagnosticTrace.ShouldCorrelate || !(newGuid != Guid.Empty))
			{
				return;
			}
			this.newGuid = newGuid;
			oldGuid = DiagnosticTrace.GetActivityId();
			if (oldGuid != newGuid)
			{
				mustDispose = true;
				if (this.emitTransfer)
				{
					DiagnosticTrace.TraceTransfer(newGuid);
				}
				DiagnosticTrace.SetActivityId(newGuid);
			}
		}

		internal static Activity CreateActivity(Guid newGuid, bool emitTransfer)
		{
			Activity result = null;
			if (DiagnosticTrace.ShouldCorrelate && newGuid != Guid.Empty && newGuid != DiagnosticTrace.GetActivityId())
			{
				result = new Activity(ref newGuid, emitTransfer);
			}
			return result;
		}

		public void Dispose()
		{
			if (mustDispose)
			{
				mustDispose = false;
				if (emitTransfer)
				{
					DiagnosticTrace.TraceTransfer(oldGuid);
				}
				DiagnosticTrace.SetActivityId(oldGuid);
			}
		}
	}
	internal static class DiagnosticTrace
	{
		internal const string DefaultTraceListenerName = "Default";

		private const string subType = "";

		private const string version = "1";

		private const int traceFailureLogThreshold = 10;

		private const string EventLogSourceName = ".NET Runtime";

		private const string TraceSourceName = "System.Transactions";

		private const string TraceRecordVersion = "http://schemas.microsoft.com/2004/10/E2ETraceEvent/TraceRecord";

		private static TraceSource traceSource;

		private static bool tracingEnabled;

		private static bool haveListeners;

		private static Dictionary<int, string> traceEventTypeNames;

		private static object localSyncObject;

		private static int traceFailureCount;

		private static int traceFailureThreshold;

		private static SourceLevels level;

		private static bool calledShutdown;

		private static bool shouldCorrelate;

		private static bool shouldTraceVerbose;

		private static bool shouldTraceInformation;

		private static bool shouldTraceWarning;

		private static bool shouldTraceError;

		private static bool shouldTraceCritical;

		internal static Guid EmptyGuid;

		private static string AppDomainFriendlyName;

		private static string ProcessName
		{
			get
			{
				string text = null;
				using Process process = Process.GetCurrentProcess();
				return process.ProcessName;
			}
		}

		private static int ProcessId
		{
			get
			{
				int num = -1;
				using Process process = Process.GetCurrentProcess();
				return process.Id;
			}
		}

		private static TraceSource TraceSource
		{
			get
			{
				return traceSource;
			}
			set
			{
				traceSource = value;
			}
		}

		private static Dictionary<int, string> TraceEventTypeNames => traceEventTypeNames;

		internal static SourceLevels Level
		{
			get
			{
				if (TraceSource != null && TraceSource.Switch.Level != level)
				{
					level = TraceSource.Switch.Level;
				}
				return level;
			}
			set
			{
				SetLevelThreadSafe(value);
			}
		}

		internal static bool HaveListeners => haveListeners;

		internal static bool TracingEnabled
		{
			get
			{
				if (tracingEnabled)
				{
					return traceSource != null;
				}
				return false;
			}
		}

		internal static bool ShouldCorrelate => shouldCorrelate;

		internal static bool Critical => shouldTraceCritical;

		internal static bool Error => shouldTraceError;

		internal static bool Warning => shouldTraceWarning;

		internal static bool Information => shouldTraceInformation;

		internal static bool Verbose => shouldTraceVerbose;

		private static int TraceFailureCount
		{
			get
			{
				return traceFailureCount;
			}
			set
			{
				traceFailureCount = value;
			}
		}

		private static int TraceFailureThreshold
		{
			get
			{
				return traceFailureThreshold;
			}
			set
			{
				traceFailureThreshold = value;
			}
		}

		private static SourceLevels FixLevel(SourceLevels level)
		{
			if (((uint)level & 0xFFFFFFF0u & 0x1Fu) != 0)
			{
				level |= SourceLevels.Verbose;
			}
			else if (((uint)level & 0xFFFFFFF8u & 0xFu) != 0)
			{
				level |= SourceLevels.Information;
			}
			else if (((uint)level & 0xFFFFFFFCu & 7u) != 0)
			{
				level |= SourceLevels.Warning;
			}
			if (((uint)level & 0xFFFFFFFEu & 3u) != 0)
			{
				level |= SourceLevels.Error;
			}
			if ((level & SourceLevels.Critical) != 0)
			{
				level |= SourceLevels.Critical;
			}
			if ((level & ~SourceLevels.Warning) == 0)
			{
				return level;
			}
			return level | SourceLevels.ActivityTracing;
		}

		private static void SetLevel(SourceLevels level)
		{
			SourceLevels sourceLevels = (DiagnosticTrace.level = FixLevel(level));
			if (TraceSource != null)
			{
				TraceSource.Switch.Level = sourceLevels;
				shouldCorrelate = ShouldTrace(TraceEventType.Transfer);
				shouldTraceVerbose = ShouldTrace(TraceEventType.Verbose);
				shouldTraceInformation = ShouldTrace(TraceEventType.Information);
				shouldTraceWarning = ShouldTrace(TraceEventType.Warning);
				shouldTraceError = ShouldTrace(TraceEventType.Error);
				shouldTraceCritical = ShouldTrace(TraceEventType.Critical);
			}
		}

		private static void SetLevelThreadSafe(SourceLevels level)
		{
			if (TracingEnabled && level != Level)
			{
				lock (localSyncObject)
				{
					SetLevel(level);
				}
			}
		}

		static DiagnosticTrace()
		{
			//Discarded unreachable code: IL_01d4, IL_01dc, IL_01e1, IL_01e6, IL_024b
			traceSource = null;
			tracingEnabled = true;
			haveListeners = false;
			localSyncObject = new object();
			traceFailureCount = 0;
			traceFailureThreshold = 0;
			calledShutdown = false;
			shouldCorrelate = false;
			shouldTraceVerbose = false;
			shouldTraceInformation = false;
			shouldTraceWarning = false;
			shouldTraceError = false;
			shouldTraceCritical = false;
			EmptyGuid = Guid.Empty;
			AppDomainFriendlyName = null;
			AppDomainFriendlyName = AppDomain.CurrentDomain.FriendlyName;
			traceEventTypeNames = new Dictionary<int, string>();
			traceEventTypeNames[1] = "Critical";
			traceEventTypeNames[2] = "Error";
			traceEventTypeNames[4] = "Warning";
			traceEventTypeNames[8] = "Information";
			traceEventTypeNames[16] = "Verbose";
			traceEventTypeNames[2048] = "Resume";
			traceEventTypeNames[256] = "Start";
			traceEventTypeNames[512] = "Stop";
			traceEventTypeNames[1024] = "Suspend";
			traceEventTypeNames[4096] = "Transfer";
			TraceFailureThreshold = 10;
			TraceFailureCount = TraceFailureThreshold + 1;
			try
			{
				traceSource = new TraceSource("System.Transactions", SourceLevels.Critical);
				AppDomain currentDomain = AppDomain.CurrentDomain;
				if (TraceSource.Switch.ShouldTrace(TraceEventType.Critical))
				{
					currentDomain.UnhandledException += UnhandledExceptionHandler;
				}
				currentDomain.DomainUnload += ExitOrUnloadEventHandler;
				currentDomain.ProcessExit += ExitOrUnloadEventHandler;
				haveListeners = TraceSource.Listeners.Count > 0;
				SetLevel(TraceSource.Switch.Level);
			}
			catch (ConfigurationErrorsException)
			{
				throw;
			}
			catch (OutOfMemoryException)
			{
				throw;
			}
			catch (StackOverflowException)
			{
				throw;
			}
			catch (ThreadAbortException)
			{
				throw;
			}
			catch (Exception ex5)
			{
				if (TraceSource == null)
				{
					LogEvent(TraceEventType.Error, string.Format(CultureInfo.CurrentCulture, SR.GetString("FailedToCreateTraceSource"), ex5), addProcessInfo: true);
				}
				else
				{
					TraceSource = null;
					LogEvent(TraceEventType.Error, string.Format(CultureInfo.CurrentCulture, SR.GetString("FailedToInitializeTraceSource"), ex5), addProcessInfo: true);
				}
			}
			catch
			{
				throw;
			}
		}

		internal static bool ShouldTrace(TraceEventType type)
		{
			if (((uint)type & (uint)Level) != 0 && TraceSource != null)
			{
				return HaveListeners;
			}
			return false;
		}

		internal static void TraceEvent(TraceEventType type, string code, string description)
		{
			TraceEvent(type, code, description, null, null, ref EmptyGuid, emitTransfer: false, null);
		}

		internal static void TraceEvent(TraceEventType type, string code, string description, TraceRecord trace)
		{
			TraceEvent(type, code, description, trace, null, ref EmptyGuid, emitTransfer: false, null);
		}

		internal static void TraceEvent(TraceEventType type, string code, string description, TraceRecord trace, Exception exception)
		{
			TraceEvent(type, code, description, trace, exception, ref EmptyGuid, emitTransfer: false, null);
		}

		internal static void TraceEvent(TraceEventType type, string code, string description, TraceRecord trace, Exception exception, ref Guid activityId, bool emitTransfer, object source)
		{
			//Discarded unreachable code: IL_004d, IL_0052, IL_0057, IL_00a4
			if (!ShouldTrace(type))
			{
				return;
			}
			using (Activity.CreateActivity(activityId, emitTransfer))
			{
				XPathNavigator data = BuildTraceString(type, code, description, trace, exception, source);
				try
				{
					TraceSource.TraceData(type, 0, data);
					if (calledShutdown)
					{
						TraceSource.Flush();
					}
				}
				catch (OutOfMemoryException)
				{
					throw;
				}
				catch (StackOverflowException)
				{
					throw;
				}
				catch (ThreadAbortException)
				{
					throw;
				}
				catch (Exception e)
				{
					string @string = SR.GetString("TraceFailure", type.ToString(), code, description, (source == null) ? string.Empty : CreateSourceString(source));
					LogTraceFailure(@string, e);
				}
				catch
				{
					throw;
				}
			}
		}

		internal static void TraceAndLogEvent(TraceEventType type, string code, string description, TraceRecord trace, Exception exception, ref Guid activityId, object source)
		{
			//Discarded unreachable code: IL_002e, IL_0033, IL_0038, IL_0047
			bool flag = ShouldTrace(type);
			string traceString = null;
			try
			{
				LogEvent(type, code, description, trace, exception, source);
				if (flag)
				{
					TraceEvent(type, code, description, trace, exception, ref activityId, emitTransfer: false, source);
				}
			}
			catch (OutOfMemoryException)
			{
				throw;
			}
			catch (StackOverflowException)
			{
				throw;
			}
			catch (ThreadAbortException)
			{
				throw;
			}
			catch (Exception e)
			{
				LogTraceFailure(traceString, e);
			}
			catch
			{
				throw;
			}
		}

		internal static void TraceTransfer(Guid newId)
		{
			//Discarded unreachable code: IL_0038, IL_003d, IL_0042, IL_0051
			Guid activityId = GetActivityId();
			if (!ShouldCorrelate || !(newId != activityId) || !HaveListeners)
			{
				return;
			}
			try
			{
				if (newId != activityId)
				{
					TraceSource.TraceTransfer(0, null, newId);
				}
			}
			catch (OutOfMemoryException)
			{
				throw;
			}
			catch (StackOverflowException)
			{
				throw;
			}
			catch (ThreadAbortException)
			{
				throw;
			}
			catch (Exception e)
			{
				LogTraceFailure(null, e);
			}
			catch
			{
				throw;
			}
		}

		internal static Guid GetActivityId()
		{
			object obj = Trace.CorrelationManager.ActivityId;
			if (obj != null)
			{
				return (Guid)obj;
			}
			return Guid.Empty;
		}

		internal static void GetActivityId(ref Guid guid)
		{
			if (ShouldCorrelate)
			{
				guid = GetActivityId();
			}
		}

		internal static void SetActivityId(Guid id)
		{
			Trace.CorrelationManager.ActivityId = id;
		}

		private static string CreateSourceString(object source)
		{
			return source.GetType().ToString() + "/" + source.GetHashCode().ToString(CultureInfo.CurrentCulture);
		}

		private static void LogEvent(TraceEventType type, string code, string description, TraceRecord trace, Exception exception, object source)
		{
			StringBuilder stringBuilder = new StringBuilder(SR.GetString("EventLogValue", ProcessName, ProcessId.ToString(CultureInfo.CurrentCulture), code, description));
			if (source != null)
			{
				stringBuilder.AppendLine(SR.GetString("EventLogSourceValue", CreateSourceString(source)));
			}
			if (exception != null)
			{
				stringBuilder.AppendLine(SR.GetString("EventLogExceptionValue", exception.ToString()));
			}
			if (trace != null)
			{
				stringBuilder.AppendLine(SR.GetString("EventLogEventIdValue", trace.EventId));
				stringBuilder.AppendLine(SR.GetString("EventLogTraceValue", trace.ToString()));
			}
			LogEvent(type, stringBuilder.ToString(), addProcessInfo: false);
		}

		internal static void LogEvent(TraceEventType type, string message, bool addProcessInfo)
		{
			if (addProcessInfo)
			{
				message = string.Format(CultureInfo.CurrentCulture, "{0}: {1}\n{2}: {3}\n{4}", "ProcessName", ProcessName, "ProcessId", ProcessId, message);
			}
			LogEvent(type, message);
		}

		internal static void LogEvent(TraceEventType type, string message)
		{
			//Discarded unreachable code: IL_0039, IL_003e, IL_0043
			try
			{
				if (!string.IsNullOrEmpty(message) && message.Length >= 8192)
				{
					message = message.Substring(0, 8191);
				}
				EventLog.WriteEntry(".NET Runtime", message, EventLogEntryTypeFromEventType(type));
			}
			catch (OutOfMemoryException)
			{
				throw;
			}
			catch (StackOverflowException)
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

		private static string LookupSeverity(TraceEventType type)
		{
			int num = (int)(type & (TraceEventType)31);
			if ((type & (TraceEventType)768) != 0)
			{
				num = (int)type;
			}
			else if (num == 0)
			{
				num = 16;
			}
			return TraceEventTypeNames[num];
		}

		private static void LogTraceFailure(string traceString, Exception e)
		{
			if (e != null)
			{
				traceString = string.Format(CultureInfo.CurrentCulture, SR.GetString("FailedToTraceEvent"), e, (traceString != null) ? traceString : "");
			}
			lock (localSyncObject)
			{
				if (TraceFailureCount > TraceFailureThreshold)
				{
					TraceFailureCount = 1;
					TraceFailureThreshold *= 2;
					LogEvent(TraceEventType.Error, traceString, addProcessInfo: true);
				}
				else
				{
					TraceFailureCount++;
				}
			}
		}

		private static void ShutdownTracing()
		{
			//Discarded unreachable code: IL_009c, IL_00a1, IL_00a6, IL_00b5
			if (TraceSource == null)
			{
				return;
			}
			try
			{
				if (Level != 0)
				{
					if (Information)
					{
						Dictionary<string, string> dictionary = new Dictionary<string, string>(3);
						dictionary["AppDomain.FriendlyName"] = AppDomain.CurrentDomain.FriendlyName;
						dictionary["ProcessName"] = ProcessName;
						dictionary["ProcessId"] = ProcessId.ToString(CultureInfo.CurrentCulture);
						TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/TraceCodes/System/ActivityTracing/2004/07/Diagnostics/AppDomainUnload", SR.GetString("TraceCodeAppDomainUnloading"), new DictionaryTraceRecord(dictionary), null, ref EmptyGuid, emitTransfer: false, null);
					}
					calledShutdown = true;
					TraceSource.Flush();
				}
			}
			catch (OutOfMemoryException)
			{
				throw;
			}
			catch (StackOverflowException)
			{
				throw;
			}
			catch (ThreadAbortException)
			{
				throw;
			}
			catch (Exception e)
			{
				LogTraceFailure(null, e);
			}
			catch
			{
				throw;
			}
		}

		private static void ExitOrUnloadEventHandler(object sender, EventArgs e)
		{
			ShutdownTracing();
		}

		private static void UnhandledExceptionHandler(object sender, UnhandledExceptionEventArgs args)
		{
			Exception exception = (Exception)args.ExceptionObject;
			TraceEvent(TraceEventType.Critical, "http://msdn.microsoft.com/TraceCodes/System/ActivityTracing/2004/07/Reliability/Exception/Unhandled", SR.GetString("UnhandledException"), null, exception, ref EmptyGuid, emitTransfer: false, null);
			ShutdownTracing();
		}

		private static XPathNavigator BuildTraceString(TraceEventType type, string code, string description, TraceRecord trace, Exception exception, object source)
		{
			return BuildTraceString(new PlainXmlWriter(), type, code, description, trace, exception, source);
		}

		private static XPathNavigator BuildTraceString(PlainXmlWriter xml, TraceEventType type, string code, string description, TraceRecord trace, Exception exception, object source)
		{
			xml.WriteStartElement("TraceRecord");
			xml.WriteAttributeString("xmlns", "http://schemas.microsoft.com/2004/10/E2ETraceEvent/TraceRecord");
			xml.WriteAttributeString("Severity", LookupSeverity(type));
			xml.WriteElementString("TraceIdentifier", code);
			xml.WriteElementString("Description", description);
			xml.WriteElementString("AppDomain", AppDomainFriendlyName);
			if (source != null)
			{
				xml.WriteElementString("Source", CreateSourceString(source));
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
				AddExceptionToTraceString(xml, exception);
				xml.WriteEndElement();
			}
			xml.WriteEndElement();
			return xml.ToNavigator();
		}

		private static void AddExceptionToTraceString(XmlWriter xml, Exception exception)
		{
			xml.WriteElementString("ExceptionType", XmlEncode(exception.GetType().AssemblyQualifiedName));
			xml.WriteElementString("Message", XmlEncode(exception.Message));
			xml.WriteElementString("StackTrace", XmlEncode(StackTraceString(exception)));
			xml.WriteElementString("ExceptionString", XmlEncode(exception.ToString()));
			if (exception is Win32Exception ex)
			{
				xml.WriteElementString("NativeErrorCode", ex.NativeErrorCode.ToString("X", CultureInfo.InvariantCulture));
			}
			if (exception.Data != null && exception.Data.Count > 0)
			{
				xml.WriteStartElement("DataItems");
				foreach (object key in exception.Data.Keys)
				{
					xml.WriteStartElement("Data");
					xml.WriteElementString("Key", XmlEncode(key.ToString()));
					xml.WriteElementString("Value", XmlEncode(exception.Data[key].ToString()));
					xml.WriteEndElement();
				}
				xml.WriteEndElement();
			}
			if (exception.InnerException != null)
			{
				xml.WriteStartElement("InnerException");
				AddExceptionToTraceString(xml, exception.InnerException);
				xml.WriteEndElement();
			}
		}

		private static string StackTraceString(Exception exception)
		{
			string text = exception.StackTrace;
			if (string.IsNullOrEmpty(text))
			{
				StackTrace stackTrace = new StackTrace(fNeedFileInfo: true);
				StackFrame[] frames = stackTrace.GetFrames();
				int num = 0;
				StackFrame[] array = frames;
				foreach (StackFrame stackFrame in array)
				{
					Type declaringType = stackFrame.GetMethod().DeclaringType;
					if (declaringType != typeof(DiagnosticTrace))
					{
						break;
					}
					num++;
				}
				stackTrace = new StackTrace(num);
				text = stackTrace.ToString();
			}
			return text;
		}

		internal static string XmlEncode(string text)
		{
			if (text == null)
			{
				return null;
			}
			int length = text.Length;
			StringBuilder stringBuilder = new StringBuilder(length + 8);
			for (int i = 0; i < length; i++)
			{
				char c = text[i];
				switch (c)
				{
				case '<':
					stringBuilder.Append("&lt;");
					break;
				case '>':
					stringBuilder.Append("&gt;");
					break;
				case '&':
					stringBuilder.Append("&amp;");
					break;
				default:
					stringBuilder.Append(c);
					break;
				}
			}
			return stringBuilder.ToString();
		}

		private static EventLogEntryType EventLogEntryTypeFromEventType(TraceEventType type)
		{
			EventLogEntryType result = EventLogEntryType.Information;
			switch (type)
			{
			case TraceEventType.Critical:
			case TraceEventType.Error:
				result = EventLogEntryType.Error;
				break;
			case TraceEventType.Warning:
				result = EventLogEntryType.Warning;
				break;
			}
			return result;
		}
	}
	internal class PlainXmlWriter : XmlWriter
	{
		private TraceXPathNavigator navigator;

		private Stack<string> stack;

		private bool writingAttribute;

		private string currentAttributeName;

		private string currentAttributePrefix;

		private string currentAttributeNs;

		private bool format;

		public override WriteState WriteState
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override XmlSpace XmlSpace
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override string XmlLang
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public PlainXmlWriter(bool format)
		{
			navigator = new TraceXPathNavigator();
			stack = new Stack<string>();
			this.format = format;
		}

		public PlainXmlWriter()
			: this(format: false)
		{
		}

		public XPathNavigator ToNavigator()
		{
			return navigator;
		}

		public override void WriteStartDocument()
		{
		}

		public override void WriteDocType(string name, string pubid, string sysid, string subset)
		{
		}

		public override void WriteStartDocument(bool standalone)
		{
			throw new NotSupportedException();
		}

		public override void WriteEndDocument()
		{
			throw new NotSupportedException();
		}

		public override string LookupPrefix(string ns)
		{
			throw new NotSupportedException();
		}

		public override void WriteNmToken(string name)
		{
			throw new NotSupportedException();
		}

		public override void WriteName(string name)
		{
			throw new NotSupportedException();
		}

		public override void WriteQualifiedName(string localName, string ns)
		{
			throw new NotSupportedException();
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
			currentAttributeName = localName;
			currentAttributePrefix = prefix;
			currentAttributeNs = ns;
			writingAttribute = true;
		}

		public override void WriteEndAttribute()
		{
			writingAttribute = false;
		}

		public override void WriteCData(string text)
		{
			throw new NotSupportedException();
		}

		public override void WriteComment(string text)
		{
			throw new NotSupportedException();
		}

		public override void WriteProcessingInstruction(string name, string text)
		{
			throw new NotSupportedException();
		}

		public override void WriteEntityRef(string name)
		{
			throw new NotSupportedException();
		}

		public override void WriteCharEntity(char ch)
		{
			throw new NotSupportedException();
		}

		public override void WriteSurrogateCharEntity(char lowChar, char highChar)
		{
			throw new NotSupportedException();
		}

		public override void WriteWhitespace(string ws)
		{
			throw new NotSupportedException();
		}

		public override void WriteString(string text)
		{
			if (writingAttribute)
			{
				navigator.AddAttribute(currentAttributeName, text, currentAttributeNs, currentAttributePrefix);
			}
			else
			{
				WriteValue(text);
			}
		}

		public override void WriteChars(char[] buffer, int index, int count)
		{
			throw new NotSupportedException();
		}

		public override void WriteRaw(string data)
		{
			throw new NotSupportedException();
		}

		public override void WriteRaw(char[] buffer, int index, int count)
		{
			throw new NotSupportedException();
		}

		public override void WriteBinHex(byte[] buffer, int index, int count)
		{
			throw new NotSupportedException();
		}

		public override void Close()
		{
		}

		public override void Flush()
		{
		}
	}
	internal abstract class TraceRecord
	{
		protected internal const string EventIdBase = "http://schemas.microsoft.com/2004/03/Transactions/";

		protected internal const string NamespaceSuffix = "TraceRecord";

		internal virtual string EventId => "http://schemas.microsoft.com/2004/03/Transactions/EmptyTraceRecord";

		public override string ToString()
		{
			PlainXmlWriter plainXmlWriter = new PlainXmlWriter();
			WriteTo(plainXmlWriter);
			return plainXmlWriter.ToString();
		}

		internal abstract void WriteTo(XmlWriter xml);
	}
	internal enum EnlistmentType
	{
		Volatile,
		Durable,
		PromotableSinglePhase
	}
	internal enum NotificationCall
	{
		Prepare,
		Commit,
		Rollback,
		InDoubt,
		SinglePhaseCommit,
		Promote
	}
	internal enum EnlistmentCallback
	{
		Done,
		Prepared,
		ForceRollback,
		Committed,
		Aborted,
		InDoubt
	}
	internal enum TransactionScopeResult
	{
		CreatedTransaction,
		UsingExistingCurrent,
		TransactionPassed,
		DependentTransactionPassed,
		NoTransaction
	}
	internal static class TraceHelper
	{
		internal static void WriteTxId(XmlWriter writer, TransactionTraceIdentifier txTraceId)
		{
			writer.WriteStartElement("TransactionTraceIdentifier");
			if (txTraceId.TransactionIdentifier != null)
			{
				writer.WriteElementString("TransactionIdentifier", txTraceId.TransactionIdentifier);
			}
			else
			{
				writer.WriteElementString("TransactionIdentifier", "");
			}
			int cloneIdentifier = txTraceId.CloneIdentifier;
			if (cloneIdentifier != 0)
			{
				writer.WriteElementString("CloneIdentifier", cloneIdentifier.ToString(CultureInfo.CurrentCulture));
			}
			writer.WriteEndElement();
		}

		internal static void WriteEnId(XmlWriter writer, EnlistmentTraceIdentifier enId)
		{
			writer.WriteStartElement("EnlistmentTraceIdentifier");
			writer.WriteElementString("ResourceManagerId", enId.ResourceManagerIdentifier.ToString());
			WriteTxId(writer, enId.TransactionTraceId);
			writer.WriteElementString("EnlistmentIdentifier", enId.EnlistmentIdentifier.ToString(CultureInfo.CurrentCulture));
			writer.WriteEndElement();
		}

		internal static void WriteTraceSource(XmlWriter writer, string traceSource)
		{
			writer.WriteElementString("TraceSource", traceSource);
		}
	}
	internal class TransactionCreatedTraceRecord : TraceRecord
	{
		private static TransactionCreatedTraceRecord record = new TransactionCreatedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionCreatedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionCreated", SR.GetString("TraceTransactionCreated"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionPromotedTraceRecord : TraceRecord
	{
		private static TransactionPromotedTraceRecord record = new TransactionPromotedTraceRecord();

		private TransactionTraceIdentifier localTxTraceId;

		private TransactionTraceIdentifier distTxTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionPromotedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier localTxTraceId, TransactionTraceIdentifier distTxTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.localTxTraceId = localTxTraceId;
				record.distTxTraceId = distTxTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionPromoted", SR.GetString("TraceTransactionPromoted"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteStartElement("LightweightTransaction");
			TraceHelper.WriteTxId(xml, localTxTraceId);
			xml.WriteEndElement();
			xml.WriteStartElement("PromotedTransaction");
			TraceHelper.WriteTxId(xml, distTxTraceId);
			xml.WriteEndElement();
		}
	}
	internal class EnlistmentTraceRecord : TraceRecord
	{
		private static EnlistmentTraceRecord record = new EnlistmentTraceRecord();

		private EnlistmentTraceIdentifier enTraceId;

		private EnlistmentType enType;

		private EnlistmentOptions enOptions;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/EnlistmentTraceRecord";

		internal static void Trace(string traceSource, EnlistmentTraceIdentifier enTraceId, EnlistmentType enType, EnlistmentOptions enOptions)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.enTraceId = enTraceId;
				record.enType = enType;
				record.enOptions = enOptions;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/Enlistment", SR.GetString("TraceEnlistment"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteEnId(xml, enTraceId);
			xml.WriteElementString("EnlistmentType", enType.ToString());
			xml.WriteElementString("EnlistmentOptions", enOptions.ToString());
		}
	}
	internal class EnlistmentNotificationCallTraceRecord : TraceRecord
	{
		private static EnlistmentNotificationCallTraceRecord record = new EnlistmentNotificationCallTraceRecord();

		private EnlistmentTraceIdentifier enTraceId;

		private NotificationCall notCall;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/EnlistmentNotificationCallTraceRecord";

		internal static void Trace(string traceSource, EnlistmentTraceIdentifier enTraceId, NotificationCall notCall)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.enTraceId = enTraceId;
				record.notCall = notCall;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/EnlistmentNotificationCall", SR.GetString("TraceEnlistmentNotificationCall"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteEnId(xml, enTraceId);
			xml.WriteElementString("NotificationCall", notCall.ToString());
		}
	}
	internal class EnlistmentCallbackPositiveTraceRecord : TraceRecord
	{
		private static EnlistmentCallbackPositiveTraceRecord record = new EnlistmentCallbackPositiveTraceRecord();

		private EnlistmentTraceIdentifier enTraceId;

		private EnlistmentCallback callback;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/EnlistmentCallbackPositiveTraceRecord";

		internal static void Trace(string traceSource, EnlistmentTraceIdentifier enTraceId, EnlistmentCallback callback)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.enTraceId = enTraceId;
				record.callback = callback;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/EnlistmentCallbackPositive", SR.GetString("TraceEnlistmentCallbackPositive"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteEnId(xml, enTraceId);
			xml.WriteElementString("EnlistmentCallback", callback.ToString());
		}
	}
	internal class EnlistmentCallbackNegativeTraceRecord : TraceRecord
	{
		private static EnlistmentCallbackNegativeTraceRecord record = new EnlistmentCallbackNegativeTraceRecord();

		private EnlistmentTraceIdentifier enTraceId;

		private EnlistmentCallback callback;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/EnlistmentCallbackNegativeTraceRecord";

		internal static void Trace(string traceSource, EnlistmentTraceIdentifier enTraceId, EnlistmentCallback callback)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.enTraceId = enTraceId;
				record.callback = callback;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/EnlistmentCallbackNegative", SR.GetString("TraceEnlistmentCallbackNegative"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteEnId(xml, enTraceId);
			xml.WriteElementString("EnlistmentCallback", callback.ToString());
		}
	}
	internal class TransactionCommitCalledTraceRecord : TraceRecord
	{
		private static TransactionCommitCalledTraceRecord record = new TransactionCommitCalledTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionCommitCalledTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionCommitCalled", SR.GetString("TraceTransactionCommitCalled"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionRollbackCalledTraceRecord : TraceRecord
	{
		private static TransactionRollbackCalledTraceRecord record = new TransactionRollbackCalledTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionRollbackCalledTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionRollbackCalled", SR.GetString("TraceTransactionRollbackCalled"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionCommittedTraceRecord : TraceRecord
	{
		private static TransactionCommittedTraceRecord record = new TransactionCommittedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionCommittedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionCommitted", SR.GetString("TraceTransactionCommitted"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionAbortedTraceRecord : TraceRecord
	{
		private static TransactionAbortedTraceRecord record = new TransactionAbortedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionAbortedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionAborted", SR.GetString("TraceTransactionAborted"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionInDoubtTraceRecord : TraceRecord
	{
		private static TransactionInDoubtTraceRecord record = new TransactionInDoubtTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionInDoubtTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionInDoubt", SR.GetString("TraceTransactionInDoubt"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionScopeCreatedTraceRecord : TraceRecord
	{
		private static TransactionScopeCreatedTraceRecord record = new TransactionScopeCreatedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private TransactionScopeResult txScopeResult;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionScopeCreatedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId, TransactionScopeResult txScopeResult)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				record.txScopeResult = txScopeResult;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionScopeCreated", SR.GetString("TraceTransactionScopeCreated"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
			xml.WriteElementString("TransactionScopeResult", txScopeResult.ToString());
		}
	}
	internal class TransactionScopeDisposedTraceRecord : TraceRecord
	{
		private static TransactionScopeDisposedTraceRecord record = new TransactionScopeDisposedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionScopeDisposedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionScopeDisposed", SR.GetString("TraceTransactionScopeDisposed"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionScopeIncompleteTraceRecord : TraceRecord
	{
		private static TransactionScopeIncompleteTraceRecord record = new TransactionScopeIncompleteTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionScopeIncompleteTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionScopeIncomplete", SR.GetString("TraceTransactionScopeIncomplete"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionScopeNestedIncorrectlyTraceRecord : TraceRecord
	{
		private static TransactionScopeNestedIncorrectlyTraceRecord record = new TransactionScopeNestedIncorrectlyTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionScopeNestedIncorrectlyTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionScopeNestedIncorrectly", SR.GetString("TraceTransactionScopeNestedIncorrectly"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionScopeCurrentChangedTraceRecord : TraceRecord
	{
		private static TransactionScopeCurrentChangedTraceRecord record = new TransactionScopeCurrentChangedTraceRecord();

		private TransactionTraceIdentifier scopeTxTraceId;

		private TransactionTraceIdentifier currentTxTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionScopeCurrentChangedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier scopeTxTraceId, TransactionTraceIdentifier currentTxTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.scopeTxTraceId = scopeTxTraceId;
				record.currentTxTraceId = currentTxTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionScopeCurrentTransactionChanged", SR.GetString("TraceTransactionScopeCurrentTransactionChanged"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, scopeTxTraceId);
			TraceHelper.WriteTxId(xml, currentTxTraceId);
		}
	}
	internal class TransactionScopeTimeoutTraceRecord : TraceRecord
	{
		private static TransactionScopeTimeoutTraceRecord record = new TransactionScopeTimeoutTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionScopeTimeoutTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionScopeTimeout", SR.GetString("TraceTransactionScopeTimeout"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionTimeoutTraceRecord : TraceRecord
	{
		private static TransactionTimeoutTraceRecord record = new TransactionTimeoutTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionTimeoutTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionTimeout", SR.GetString("TraceTransactionTimeout"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class DependentCloneCreatedTraceRecord : TraceRecord
	{
		private static DependentCloneCreatedTraceRecord record = new DependentCloneCreatedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private DependentCloneOption option;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/DependentCloneCreatedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId, DependentCloneOption option)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				record.option = option;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/DependentCloneCreated", SR.GetString("TraceDependentCloneCreated"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
			xml.WriteElementString("DependentCloneOption", option.ToString());
		}
	}
	internal class DependentCloneCompleteTraceRecord : TraceRecord
	{
		private static DependentCloneCompleteTraceRecord record = new DependentCloneCompleteTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/DependentCloneCompleteTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/DependentCloneComplete", SR.GetString("TraceDependentCloneComplete"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class CloneCreatedTraceRecord : TraceRecord
	{
		private static CloneCreatedTraceRecord record = new CloneCreatedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/CloneCreatedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/CloneCreated", SR.GetString("TraceCloneCreated"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class RecoveryCompleteTraceRecord : TraceRecord
	{
		private static RecoveryCompleteTraceRecord record = new RecoveryCompleteTraceRecord();

		private Guid rmId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/RecoveryCompleteTraceRecord";

		internal static void Trace(string traceSource, Guid rmId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.rmId = rmId;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/RecoveryComplete", SR.GetString("TraceRecoveryComplete"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("ResourceManagerId", rmId.ToString());
		}
	}
	internal class ReenlistTraceRecord : TraceRecord
	{
		private static ReenlistTraceRecord record = new ReenlistTraceRecord();

		private Guid rmId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/ReenlistTraceRecord";

		internal static void Trace(string traceSource, Guid rmId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.rmId = rmId;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/Reenlist", SR.GetString("TraceReenlist"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("ResourceManagerId", rmId.ToString());
		}
	}
	internal class DistributedTransactionManagerCreatedTraceRecord : TraceRecord
	{
		private static DistributedTransactionManagerCreatedTraceRecord record = new DistributedTransactionManagerCreatedTraceRecord();

		private Type tmType;

		private string nodeName;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionManagerCreatedTraceRecord";

		internal static void Trace(string traceSource, Type tmType, string nodeName)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.tmType = tmType;
				record.nodeName = nodeName;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionManagerCreated", SR.GetString("TraceTransactionManagerCreated"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("TransactionManagerType", tmType.ToString());
			xml.WriteStartElement("TransactionManagerProperties");
			xml.WriteElementString("DistributedTransactionManagerName", nodeName);
			xml.WriteEndElement();
		}
	}
	internal class TransactionSerializedTraceRecord : TraceRecord
	{
		private static TransactionSerializedTraceRecord record = new TransactionSerializedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionSerializedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Information, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionSerialized", SR.GetString("TraceTransactionSerialized"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionDeserializedTraceRecord : TraceRecord
	{
		private static TransactionDeserializedTraceRecord record = new TransactionDeserializedTraceRecord();

		private TransactionTraceIdentifier txTraceId;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionDeserializedTraceRecord";

		internal static void Trace(string traceSource, TransactionTraceIdentifier txTraceId)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.txTraceId = txTraceId;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionDeserialized", SR.GetString("TraceTransactionDeserialized"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			TraceHelper.WriteTxId(xml, txTraceId);
		}
	}
	internal class TransactionExceptionTraceRecord : TraceRecord
	{
		private static TransactionExceptionTraceRecord record = new TransactionExceptionTraceRecord();

		private string exceptionMessage;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/TransactionExceptionTraceRecord";

		internal static void Trace(string traceSource, string exceptionMessage)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.exceptionMessage = exceptionMessage;
				DiagnosticTrace.TraceEvent(TraceEventType.Error, "http://msdn.microsoft.com/2004/06/System/Transactions/TransactionException", SR.GetString("TraceTransactionException"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("ExceptionMessage", exceptionMessage);
		}
	}
	internal class DictionaryTraceRecord : TraceRecord
	{
		private IDictionary dictionary;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/DictionaryTraceRecord";

		internal DictionaryTraceRecord(IDictionary dictionary)
		{
			this.dictionary = dictionary;
		}

		internal override void WriteTo(XmlWriter xml)
		{
			if (dictionary == null)
			{
				return;
			}
			foreach (object key in dictionary.Keys)
			{
				xml.WriteElementString(key.ToString(), dictionary[key].ToString());
			}
		}

		public override string ToString()
		{
			string result = null;
			if (dictionary != null)
			{
				StringBuilder stringBuilder = new StringBuilder();
				{
					foreach (object key in dictionary.Keys)
					{
						stringBuilder.AppendLine(string.Format(CultureInfo.InvariantCulture, "{0}: {1}", key, dictionary[key].ToString()));
					}
					return result;
				}
			}
			return result;
		}
	}
	internal class ExceptionConsumedTraceRecord : TraceRecord
	{
		private static ExceptionConsumedTraceRecord record = new ExceptionConsumedTraceRecord();

		private Exception exception;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/ExceptionConsumedTraceRecord";

		internal static void Trace(string traceSource, Exception exception)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.exception = exception;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/ExceptionConsumed", SR.GetString("TraceExceptionConsumed"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("ExceptionMessage", exception.Message);
			xml.WriteElementString("ExceptionStack", exception.StackTrace);
		}
	}
	internal class InvalidOperationExceptionTraceRecord : TraceRecord
	{
		private static InvalidOperationExceptionTraceRecord record = new InvalidOperationExceptionTraceRecord();

		private string exceptionMessage;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/InvalidOperationExceptionTraceRecord";

		internal static void Trace(string traceSource, string exceptionMessage)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.exceptionMessage = exceptionMessage;
				DiagnosticTrace.TraceEvent(TraceEventType.Error, "http://msdn.microsoft.com/2004/06/System/Transactions/InvalidOperationException", SR.GetString("TraceInvalidOperationException"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("ExceptionMessage", exceptionMessage);
		}
	}
	internal class InternalErrorTraceRecord : TraceRecord
	{
		private static InternalErrorTraceRecord record = new InternalErrorTraceRecord();

		private string exceptionMessage;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/InternalErrorTraceRecord";

		internal static void Trace(string traceSource, string exceptionMessage)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.exceptionMessage = exceptionMessage;
				DiagnosticTrace.TraceEvent(TraceEventType.Critical, "http://msdn.microsoft.com/2004/06/System/Transactions/InternalError", SR.GetString("TraceInternalError"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("ExceptionMessage", exceptionMessage);
		}
	}
	internal class MethodEnteredTraceRecord : TraceRecord
	{
		private static MethodEnteredTraceRecord record = new MethodEnteredTraceRecord();

		private string methodName;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/MethodEnteredTraceRecord";

		internal static void Trace(string traceSource, string methodName)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.methodName = methodName;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/MethodEntered", SR.GetString("TraceMethodEntered"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("MethodName", methodName);
		}
	}
	internal class MethodExitedTraceRecord : TraceRecord
	{
		private static MethodExitedTraceRecord record = new MethodExitedTraceRecord();

		private string methodName;

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/MethodExitedTraceRecord";

		internal static void Trace(string traceSource, string methodName)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				record.methodName = methodName;
				DiagnosticTrace.TraceEvent(TraceEventType.Verbose, "http://msdn.microsoft.com/2004/06/System/Transactions/MethodExited", SR.GetString("TraceMethodExited"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
			xml.WriteElementString("MethodName", methodName);
		}
	}
	internal class ConfiguredDefaultTimeoutAdjustedTraceRecord : TraceRecord
	{
		private static ConfiguredDefaultTimeoutAdjustedTraceRecord record = new ConfiguredDefaultTimeoutAdjustedTraceRecord();

		private string traceSource;

		internal override string EventId => "http://schemas.microsoft.com/2004/03/Transactions/ConfiguredDefaultTimeoutAdjustedTraceRecord";

		internal static void Trace(string traceSource)
		{
			lock (record)
			{
				record.traceSource = traceSource;
				DiagnosticTrace.TraceEvent(TraceEventType.Warning, "http://msdn.microsoft.com/2004/06/System/Transactions/ConfiguredDefaultTimeoutAdjusted", SR.GetString("TraceConfiguredDefaultTimeoutAdjusted"), record);
			}
		}

		internal override void WriteTo(XmlWriter xml)
		{
			TraceHelper.WriteTraceSource(xml, traceSource);
		}
	}
	internal class TraceXPathNavigator : XPathNavigator
	{
		private class ElementNode
		{
			internal string name;

			internal string xmlns;

			internal string prefix;

			internal List<ElementNode> childNodes = new List<ElementNode>();

			internal ElementNode parent;

			internal List<AttributeNode> attributes = new List<AttributeNode>();

			internal TextNode text;

			internal bool movedToText;

			private int attributeIndex;

			private int elementIndex;

			internal AttributeNode CurrentAttribute => attributes[attributeIndex];

			internal ElementNode(string name, string prefix, string xmlns, ElementNode parent)
			{
				this.name = name;
				this.prefix = prefix;
				this.xmlns = xmlns;
				this.parent = parent;
			}

			internal ElementNode MoveToNext()
			{
				ElementNode result = null;
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
				return attributes.Count > 0;
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
				foreach (ElementNode childNode in childNodes)
				{
					childNode.Reset();
				}
			}
		}

		private class AttributeNode
		{
			internal string name;

			internal string xmlns;

			internal string prefix;

			internal string nodeValue;

			internal AttributeNode(string name, string prefix, string xmlns, string value)
			{
				this.name = name;
				this.prefix = prefix;
				this.xmlns = xmlns;
				nodeValue = value;
			}
		}

		private class TextNode
		{
			internal string nodeValue;

			internal TextNode(string value)
			{
				nodeValue = value;
			}
		}

		private ElementNode root;

		private ElementNode current;

		private bool closed;

		private XPathNodeType state = XPathNodeType.Element;

		public override string BaseURI => null;

		public override bool IsEmptyElement
		{
			get
			{
				bool result = true;
				if (current != null)
				{
					result = current.text != null || current.childNodes.Count > 0;
				}
				return result;
			}
		}

		public override string LocalName => Name;

		public override string Name
		{
			get
			{
				if (current == null)
				{
					throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
				}
				string result = null;
				switch (state)
				{
				case XPathNodeType.Element:
					result = current.name;
					break;
				case XPathNodeType.Attribute:
					result = current.CurrentAttribute.name;
					break;
				}
				return result;
			}
		}

		public override XmlNameTable NameTable => null;

		public override string NamespaceURI => null;

		public override XPathNodeType NodeType => state;

		public override string Prefix
		{
			get
			{
				if (current == null)
				{
					throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
				}
				string result = null;
				switch (state)
				{
				case XPathNodeType.Element:
					result = current.prefix;
					break;
				case XPathNodeType.Attribute:
					result = current.CurrentAttribute.prefix;
					break;
				case XPathNodeType.Namespace:
					result = current.prefix;
					break;
				}
				return result;
			}
		}

		public override string Value
		{
			get
			{
				if (current == null)
				{
					throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
				}
				string result = null;
				switch (state)
				{
				case XPathNodeType.Text:
					result = current.text.nodeValue;
					break;
				case XPathNodeType.Attribute:
					result = current.CurrentAttribute.nodeValue;
					break;
				case XPathNodeType.Namespace:
					result = current.xmlns;
					break;
				}
				return result;
			}
		}

		internal void AddElement(string prefix, string name, string xmlns)
		{
			ElementNode item = new ElementNode(name, prefix, xmlns, current);
			if (closed)
			{
				throw new InvalidOperationException(SR.GetString("CannotAddToClosedDocument"));
			}
			if (current == null)
			{
				root = item;
				current = root;
			}
			else if (!closed)
			{
				current.childNodes.Add(item);
				current = item;
			}
		}

		internal void AddText(string value)
		{
			if (closed)
			{
				throw new InvalidOperationException(SR.GetString("CannotAddToClosedDocument"));
			}
			if (current == null)
			{
				throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
			}
			if (current.text != null)
			{
				throw new InvalidOperationException(SR.GetString("TextNodeAlreadyPopulated"));
			}
			current.text = new TextNode(value);
		}

		internal void AddAttribute(string name, string value, string xmlns, string prefix)
		{
			if (closed)
			{
				throw new InvalidOperationException(SR.GetString("CannotAddToClosedDocument"));
			}
			if (current == null)
			{
				throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
			}
			AttributeNode item = new AttributeNode(name, prefix, xmlns, value);
			current.attributes.Add(item);
		}

		internal void CloseElement()
		{
			if (closed)
			{
				throw new InvalidOperationException(SR.GetString("DocumentAlreadyClosed"));
			}
			current = current.parent;
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
			throw new NotSupportedException();
		}

		public override bool MoveTo(XPathNavigator other)
		{
			throw new NotSupportedException();
		}

		public override bool MoveToFirstAttribute()
		{
			if (current == null)
			{
				throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
			}
			bool flag = current.MoveToFirstAttribute();
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
				throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
			}
			bool result = false;
			if (current.childNodes.Count > 0)
			{
				current = current.childNodes[0];
				state = XPathNodeType.Element;
				result = true;
			}
			else if (current.childNodes.Count == 0 && current.text != null)
			{
				state = XPathNodeType.Text;
				current.movedToText = true;
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
			throw new NotSupportedException();
		}

		public override bool MoveToNext()
		{
			if (current == null)
			{
				throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
			}
			bool result = false;
			if (state != XPathNodeType.Text)
			{
				ElementNode parent = current.parent;
				if (parent != null)
				{
					ElementNode elementNode = parent.MoveToNext();
					if (elementNode == null && parent.text != null && !parent.movedToText)
					{
						state = XPathNodeType.Text;
						parent.movedToText = true;
						result = true;
					}
					else if (elementNode != null)
					{
						state = XPathNodeType.Element;
						result = true;
						current = elementNode;
					}
				}
			}
			return result;
		}

		public override bool MoveToNextAttribute()
		{
			if (current == null)
			{
				throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
			}
			bool flag = current.MoveToNextAttribute();
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
				throw new InvalidOperationException(SR.GetString("OperationInvalidOnAnEmptyDocument"));
			}
			bool result = false;
			switch (state)
			{
			case XPathNodeType.Element:
				if (current.parent != null)
				{
					current = current.parent;
					state = XPathNodeType.Element;
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
			throw new NotSupportedException();
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
			XmlTextWriter xmlTextWriter = new XmlTextWriter(new StringWriter(stringBuilder, CultureInfo.CurrentCulture));
			xmlTextWriter.WriteNode(this, defattr: false);
			return stringBuilder.ToString();
		}
	}
}
namespace System.Configuration
{
	[ConfigurationPermission(SecurityAction.Assert, Unrestricted = true)]
	internal static class PrivilegedConfigurationManager
	{
		internal static ConnectionStringSettingsCollection ConnectionStrings => ConfigurationManager.ConnectionStrings;

		internal static object GetSection(string sectionName)
		{
			return ConfigurationManager.GetSection(sectionName);
		}
	}
}
