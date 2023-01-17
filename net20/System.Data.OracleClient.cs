
// C:\WINDOWS\assembly\GAC_32\System.Data.OracleClient\2.0.0.0__b77a5c561934e089\System.Data.OracleClient.dll
// System.Data.OracleClient, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
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
using System.Collections.Specialized;
using System.ComponentModel;
using System.ComponentModel.Design.Serialization;
using System.Configuration;
using System.Data.Common;
using System.Data.OracleClient;
using System.Data.ProviderBase;
using System.Data.SqlClient;
using System.Data.SqlTypes;
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
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Transactions;

[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyDelaySign(true)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: Dependency("System.Data,", LoadHint.Always)]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: CLSCompliant(true)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\EcmaPublicKey.snk")]
[assembly: ComVisible(false)]
[assembly: AssemblyTitle("System.Data.OracleClient.dll")]
[assembly: AssemblyDescription("System.Data.OracleClient.dll")]
[assembly: AssemblyDefaultAlias("System.Data.OracleClient.dll")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: BidMetaText("<CountHint> Trace=600; Scope=30;")]
[module: UnverifiableCode]
[module: BidMetaText("<Alias> ora = System.Data.OracleClient;")]
[module: BidMetaText(":FormatControl: InstanceID='' ")]
[module: BidIdentity("System.Data.OracleClient.1")]
namespace System.Data.OracleClient
{
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class ResDescriptionAttribute : System.ComponentModel.DescriptionAttribute
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
		internal const string ADP_CollectionIndexInt32 = "ADP_CollectionIndexInt32";

		internal const string ADP_CollectionIndexString = "ADP_CollectionIndexString";

		internal const string ADP_CollectionInvalidType = "ADP_CollectionInvalidType";

		internal const string ADP_CollectionIsNotParent = "ADP_CollectionIsNotParent";

		internal const string ADP_CollectionIsParent = "ADP_CollectionIsParent";

		internal const string ADP_CollectionNullValue = "ADP_CollectionNullValue";

		internal const string ADP_CollectionRemoveInvalidObject = "ADP_CollectionRemoveInvalidObject";

		internal const string ADP_ConnectionAlreadyOpen = "ADP_ConnectionAlreadyOpen";

		internal const string ADP_ConnectionStateMsg_Closed = "ADP_ConnectionStateMsg_Closed";

		internal const string ADP_ConnectionStateMsg_Connecting = "ADP_ConnectionStateMsg_Connecting";

		internal const string ADP_ConnectionStateMsg_Open = "ADP_ConnectionStateMsg_Open";

		internal const string ADP_ConnectionStateMsg_OpenExecuting = "ADP_ConnectionStateMsg_OpenExecuting";

		internal const string ADP_ConnectionStateMsg_OpenFetching = "ADP_ConnectionStateMsg_OpenFetching";

		internal const string ADP_ConnectionStateMsg = "ADP_ConnectionStateMsg";

		internal const string ADP_ConnectionStringSyntax = "ADP_ConnectionStringSyntax";

		internal const string ADP_DataReaderClosed = "ADP_DataReaderClosed";

		internal const string ADP_EmptyString = "ADP_EmptyString";

		internal const string ADP_InternalConnectionError = "ADP_InternalConnectionError";

		internal const string ADP_InvalidDataDirectory = "ADP_InvalidDataDirectory";

		internal const string ADP_InvalidEnumerationValue = "ADP_InvalidEnumerationValue";

		internal const string ADP_InvalidKey = "ADP_InvalidKey";

		internal const string ADP_InvalidOffsetValue = "ADP_InvalidOffsetValue";

		internal const string ADP_InvalidValue = "ADP_InvalidValue";

		internal const string ADP_InvalidXMLBadVersion = "ADP_InvalidXMLBadVersion";

		internal const string ADP_NoConnectionString = "ADP_NoConnectionString";

		internal const string ADP_NotAPermissionElement = "ADP_NotAPermissionElement";

		internal const string ADP_OpenConnectionPropertySet = "ADP_OpenConnectionPropertySet";

		internal const string ADP_PermissionTypeMismatch = "ADP_PermissionTypeMismatch";

		internal const string ADP_PooledOpenTimeout = "ADP_PooledOpenTimeout";

		internal const string DataCategory_Data = "DataCategory_Data";

		internal const string DataCategory_StateChange = "DataCategory_StateChange";

		internal const string DataCategory_Update = "DataCategory_Update";

		internal const string DbCommand_CommandTimeout = "DbCommand_CommandTimeout";

		internal const string DbConnection_State = "DbConnection_State";

		internal const string DbConnection_StateChange = "DbConnection_StateChange";

		internal const string DbParameter_DbType = "DbParameter_DbType";

		internal const string DbParameter_Direction = "DbParameter_Direction";

		internal const string DbParameter_IsNullable = "DbParameter_IsNullable";

		internal const string DbParameter_Offset = "DbParameter_Offset";

		internal const string DbParameter_ParameterName = "DbParameter_ParameterName";

		internal const string DbParameter_Size = "DbParameter_Size";

		internal const string DbParameter_SourceColumn = "DbParameter_SourceColumn";

		internal const string DbParameter_SourceVersion = "DbParameter_SourceVersion";

		internal const string DbParameter_SourceColumnNullMapping = "DbParameter_SourceColumnNullMapping";

		internal const string DbParameter_Value = "DbParameter_Value";

		internal const string MDF_QueryFailed = "MDF_QueryFailed";

		internal const string MDF_TooManyRestrictions = "MDF_TooManyRestrictions";

		internal const string MDF_InvalidRestrictionValue = "MDF_InvalidRestrictionValue";

		internal const string MDF_UndefinedCollection = "MDF_UndefinedCollection";

		internal const string MDF_UndefinedPopulationMechanism = "MDF_UndefinedPopulationMechanism";

		internal const string MDF_UnsupportedVersion = "MDF_UnsupportedVersion";

		internal const string MDF_MissingDataSourceInformationColumn = "MDF_MissingDataSourceInformationColumn";

		internal const string MDF_IncorrectNumberOfDataSourceInformationRows = "MDF_IncorrectNumberOfDataSourceInformationRows";

		internal const string MDF_MissingRestrictionColumn = "MDF_MissingRestrictionColumn";

		internal const string MDF_MissingRestrictionRow = "MDF_MissingRestrictionRow";

		internal const string MDF_NoColumns = "MDF_NoColumns";

		internal const string MDF_UnableToBuildCollection = "MDF_UnableToBuildCollection";

		internal const string MDF_AmbigousCollectionName = "MDF_AmbigousCollectionName";

		internal const string MDF_CollectionNameISNotUnique = "MDF_CollectionNameISNotUnique";

		internal const string MDF_DataTableDoesNotExist = "MDF_DataTableDoesNotExist";

		internal const string MDF_InvalidXml = "MDF_InvalidXml";

		internal const string MDF_InvalidXmlMissingColumn = "MDF_InvalidXmlMissingColumn";

		internal const string MDF_InvalidXmlInvalidValue = "MDF_InvalidXmlInvalidValue";

		internal const string ADP_InternalError = "ADP_InternalError";

		internal const string ADP_NoMessageAvailable = "ADP_NoMessageAvailable";

		internal const string ADP_BadBindValueType = "ADP_BadBindValueType";

		internal const string ADP_BadOracleClientImageFormat = "ADP_BadOracleClientImageFormat";

		internal const string ADP_BadOracleClientVersion = "ADP_BadOracleClientVersion";

		internal const string ADP_BufferExceeded = "ADP_BufferExceeded";

		internal const string ADP_CannotDeriveOverloaded = "ADP_CannotDeriveOverloaded";

		internal const string ADP_CannotOpenLobWithDifferentMode = "ADP_CannotOpenLobWithDifferentMode";

		internal const string ADP_ChangeDatabaseNotSupported = "ADP_ChangeDatabaseNotSupported";

		internal const string ADP_ClosedConnectionError = "ADP_ClosedConnectionError";

		internal const string ADP_ClosedDataReaderError = "ADP_ClosedDataReaderError";

		internal const string ADP_CommandTextRequired = "ADP_CommandTextRequired";

		internal const string ADP_ConfigWrongNumberOfValues = "ADP_ConfigWrongNumberOfValues";

		internal const string ADP_ConfigUnableToLoadXmlMetaDataFile = "ADP_ConfigUnableToLoadXmlMetaDataFile";

		internal const string ADP_ConnectionRequired = "ADP_ConnectionRequired";

		internal const string ADP_CouldNotCreateEnvironment = "ADP_CouldNotCreateEnvironment";

		internal const string ADP_ConvertFailed = "ADP_ConvertFailed";

		internal const string ADP_DataIsNull = "ADP_DataIsNull";

		internal const string ADP_DataReaderNoData = "ADP_DataReaderNoData";

		internal const string ADP_DeriveParametersNotSupported = "ADP_DeriveParametersNotSupported";

		internal const string ADP_DistribTxRequiresOracle9i = "ADP_DistribTxRequiresOracle9i";

		internal const string ADP_DistribTxRequiresOracleServicesForMTS = "ADP_DistribTxRequiresOracleServicesForMTS";

		internal const string ADP_IdentifierIsNotQuoted = "ADP_IdentifierIsNotQuoted";

		internal const string ADP_InputRefCursorNotSupported = "ADP_InputRefCursorNotSupported";

		internal const string ADP_InternalProviderError = "ADP_InternalProviderError";

		internal const string ADP_InvalidCommandType = "ADP_InvalidCommandType";

		internal const string ADP_InvalidConnectionOptionLength = "ADP_InvalidConnectionOptionLength";

		internal const string ADP_InvalidConnectionOptionValue = "ADP_InvalidConnectionOptionValue";

		internal const string ADP_InvalidDataLength = "ADP_InvalidDataLength";

		internal const string ADP_InvalidDataType = "ADP_InvalidDataType";

		internal const string ADP_InvalidDataTypeForValue = "ADP_InvalidDataTypeForValue";

		internal const string ADP_InvalidDbType = "ADP_InvalidDbType";

		internal const string ADP_InvalidDestinationBufferIndex = "ADP_InvalidDestinationBufferIndex";

		internal const string ADP_InvalidLobType = "ADP_InvalidLobType";

		internal const string ADP_InvalidMinMaxPoolSizeValues = "ADP_InvalidMinMaxPoolSizeValues";

		internal const string ADP_InvalidOracleType = "ADP_InvalidOracleType";

		internal const string ADP_InvalidSeekOrigin = "ADP_InvalidSeekOrigin";

		internal const string ADP_InvalidSizeValue = "ADP_InvalidSizeValue";

		internal const string ADP_InvalidSourceBufferIndex = "ADP_InvalidSourceBufferIndex";

		internal const string ADP_InvalidSourceOffset = "ADP_InvalidSourceOffset";

		internal const string ADP_KeywordNotSupported = "ADP_KeywordNotSupported";

		internal const string ADP_LobAmountExceeded = "ADP_LobAmountExceeded";

		internal const string ADP_LobAmountMustBeEven = "ADP_LobAmountMustBeEven";

		internal const string ADP_LobPositionMustBeEven = "ADP_LobPositionMustBeEven";

		internal const string ADP_LobWriteInvalidOnNull = "ADP_LobWriteInvalidOnNull";

		internal const string ADP_LobWriteRequiresTransaction = "ADP_LobWriteRequiresTransaction";

		internal const string ADP_MonthOutOfRange = "ADP_MonthOutOfRange";

		internal const string ADP_MustBePositive = "ADP_MustBePositive";

		internal const string ADP_NoCommandText = "ADP_NoCommandText";

		internal const string ADP_NoData = "ADP_NoData";

		internal const string ADP_NoLocalTransactionInDistributedContext = "ADP_NoLocalTransactionInDistributedContext";

		internal const string ADP_NoOptimizedDirectTableAccess = "ADP_NoOptimizedDirectTableAccess";

		internal const string ADP_NoParallelTransactions = "ADP_NoParallelTransactions";

		internal const string ADP_OpenConnectionRequired = "ADP_OpenConnectionRequired";

		internal const string ADP_OperationFailed = "ADP_OperationFailed";

		internal const string ADP_OperationResultedInOverflow = "ADP_OperationResultedInOverflow";

		internal const string ADP_ParameterConversionFailed = "ADP_ParameterConversionFailed";

		internal const string ADP_ParameterSizeIsMissing = "ADP_ParameterSizeIsMissing";

		internal const string ADP_ParameterSizeIsTooLarge = "ADP_ParameterSizeIsTooLarge";

		internal const string ADP_PleaseUninstallTheBeta = "ADP_PleaseUninstallTheBeta";

		internal const string ADP_ReadOnlyLob = "ADP_ReadOnlyLob";

		internal const string ADP_SeekBeyondEnd = "ADP_SeekBeyondEnd";

		internal const string ADP_SQLParserInternalError = "ADP_SQLParserInternalError";

		internal const string ADP_SyntaxErrorExpectedCommaAfterColumn = "ADP_SyntaxErrorExpectedCommaAfterColumn";

		internal const string ADP_SyntaxErrorExpectedCommaAfterTable = "ADP_SyntaxErrorExpectedCommaAfterTable";

		internal const string ADP_SyntaxErrorExpectedIdentifier = "ADP_SyntaxErrorExpectedIdentifier";

		internal const string ADP_SyntaxErrorExpectedNextPart = "ADP_SyntaxErrorExpectedNextPart";

		internal const string ADP_SyntaxErrorMissingParenthesis = "ADP_SyntaxErrorMissingParenthesis";

		internal const string ADP_SyntaxErrorTooManyNameParts = "ADP_SyntaxErrorTooManyNameParts";

		internal const string ADP_TransactionCompleted = "ADP_TransactionCompleted";

		internal const string ADP_TransactionConnectionMismatch = "ADP_TransactionConnectionMismatch";

		internal const string ADP_TransactionPresent = "ADP_TransactionPresent";

		internal const string ADP_TransactionRequired_Execute = "ADP_TransactionRequired_Execute";

		internal const string ADP_TypeNotSupported = "ADP_TypeNotSupported";

		internal const string ADP_UnexpectedReturnCode = "ADP_UnexpectedReturnCode";

		internal const string ADP_UnknownDataTypeCode = "ADP_UnknownDataTypeCode";

		internal const string ADP_UnsupportedIsolationLevel = "ADP_UnsupportedIsolationLevel";

		internal const string ADP_WriteByteForBinaryLobsOnly = "ADP_WriteByteForBinaryLobsOnly";

		internal const string ADP_WrongType = "ADP_WrongType";

		internal const string DataCategory_Advanced = "DataCategory_Advanced";

		internal const string DataCategory_Initialization = "DataCategory_Initialization";

		internal const string DataCategory_Pooling = "DataCategory_Pooling";

		internal const string DataCategory_Security = "DataCategory_Security";

		internal const string DataCategory_Source = "DataCategory_Source";

		internal const string OracleCategory_Behavior = "OracleCategory_Behavior";

		internal const string OracleCategory_Data = "OracleCategory_Data";

		internal const string OracleCategory_Fill = "OracleCategory_Fill";

		internal const string OracleCategory_InfoMessage = "OracleCategory_InfoMessage";

		internal const string OracleCategory_StateChange = "OracleCategory_StateChange";

		internal const string OracleCategory_Update = "OracleCategory_Update";

		internal const string DbCommand_CommandText = "DbCommand_CommandText";

		internal const string DbCommand_CommandType = "DbCommand_CommandType";

		internal const string DbCommand_Connection = "DbCommand_Connection";

		internal const string DbCommand_Transaction = "DbCommand_Transaction";

		internal const string DbCommand_UpdatedRowSource = "DbCommand_UpdatedRowSource";

		internal const string DbCommand_Parameters = "DbCommand_Parameters";

		internal const string OracleCommandBuilder_DataAdapter = "OracleCommandBuilder_DataAdapter";

		internal const string OracleCommandBuilder_QuotePrefix = "OracleCommandBuilder_QuotePrefix";

		internal const string OracleCommandBuilder_QuoteSuffix = "OracleCommandBuilder_QuoteSuffix";

		internal const string OracleConnection_ConnectionString = "OracleConnection_ConnectionString";

		internal const string OracleConnection_DataSource = "OracleConnection_DataSource";

		internal const string OracleConnection_InfoMessage = "OracleConnection_InfoMessage";

		internal const string OracleConnection_StateChange = "OracleConnection_StateChange";

		internal const string OracleConnection_State = "OracleConnection_State";

		internal const string OracleConnection_ServerVersion = "OracleConnection_ServerVersion";

		internal const string DbConnectionString_ConnectionString = "DbConnectionString_ConnectionString";

		internal const string DbConnectionString_DataSource = "DbConnectionString_DataSource";

		internal const string DbConnectionString_Enlist = "DbConnectionString_Enlist";

		internal const string DbConnectionString_IntegratedSecurity = "DbConnectionString_IntegratedSecurity";

		internal const string DbConnectionString_LoadBalanceTimeout = "DbConnectionString_LoadBalanceTimeout";

		internal const string DbConnectionString_MaxPoolSize = "DbConnectionString_MaxPoolSize";

		internal const string DbConnectionString_MinPoolSize = "DbConnectionString_MinPoolSize";

		internal const string DbConnectionString_OmitOracleConnectionName = "DbConnectionString_OmitOracleConnectionName";

		internal const string DbConnectionString_Password = "DbConnectionString_Password";

		internal const string DbConnectionString_PersistSecurityInfo = "DbConnectionString_PersistSecurityInfo";

		internal const string DbConnectionString_Pooling = "DbConnectionString_Pooling";

		internal const string DbConnectionString_Unicode = "DbConnectionString_Unicode";

		internal const string DbConnectionString_UserID = "DbConnectionString_UserID";

		internal const string DbDataAdapter_DeleteCommand = "DbDataAdapter_DeleteCommand";

		internal const string DbDataAdapter_InsertCommand = "DbDataAdapter_InsertCommand";

		internal const string DbDataAdapter_RowUpdated = "DbDataAdapter_RowUpdated";

		internal const string DbDataAdapter_RowUpdating = "DbDataAdapter_RowUpdating";

		internal const string DbDataAdapter_SelectCommand = "DbDataAdapter_SelectCommand";

		internal const string DbDataAdapter_UpdateCommand = "DbDataAdapter_UpdateCommand";

		internal const string DbTable_Connection = "DbTable_Connection";

		internal const string DbTable_DeleteCommand = "DbTable_DeleteCommand";

		internal const string DbTable_InsertCommand = "DbTable_InsertCommand";

		internal const string DbTable_SelectCommand = "DbTable_SelectCommand";

		internal const string DbTable_UpdateCommand = "DbTable_UpdateCommand";

		internal const string OracleParameter_OracleType = "OracleParameter_OracleType";

		internal const string OracleMetaDataFactory_XML = "OracleMetaDataFactory_XML";

		internal const string SqlMisc_NullString = "SqlMisc_NullString";

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
			resources = new ResourceManager("System.Data.OracleClient", GetType().Assembly);
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
[ComVisible(false)]
internal static class Bid
{
	internal enum ApiGroup : uint
	{
		Off = 0u,
		Default = 1u,
		Trace = 2u,
		Scope = 4u,
		Perf = 8u,
		Resource = 16u,
		Memory = 32u,
		StatusOk = 64u,
		Advanced = 128u,
		MaskBid = 4095u,
		MaskUser = 4294963200u,
		MaskAll = uint.MaxValue
	}

	private delegate ApiGroup CtrlCB(ApiGroup mask, ApiGroup bits);

	[StructLayout(LayoutKind.Sequential)]
	private class BindingCookie
	{
		internal IntPtr _data;

		internal BindingCookie()
		{
			_data = (IntPtr)(-1);
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal void Invalidate()
		{
			_data = (IntPtr)(-1);
		}
	}

	private enum CtlCmd : uint
	{
		Reverse = 1u,
		Unicode = 2u,
		DcsBase = 1073741824u,
		DcsMax = 1610612732u,
		CplBase = 1610612736u,
		CplMax = 2147483644u,
		CmdSpaceCount = 1073741824u,
		CmdSpaceEnum = 1073741828u,
		CmdSpaceQuery = 1073741832u,
		GetEventID = 1073741846u,
		ParseString = 1073741850u,
		AddExtension = 1073741854u,
		AddMetaText = 1073741858u,
		AddResHandle = 1073741862u,
		Shutdown = 1073741866u,
		LastItem = 1073741867u
	}

	private struct BIDEXTINFO
	{
		private IntPtr hModule;

		[MarshalAs(UnmanagedType.LPWStr)]
		private string DomainName;

		private int Reserved2;

		private int Reserved;

		[MarshalAs(UnmanagedType.LPWStr)]
		private string ModulePath;

		private IntPtr ModulePathA;

		private IntPtr pBindCookie;

		internal BIDEXTINFO(IntPtr hMod, string modPath, string friendlyName, IntPtr cookiePtr)
		{
			hModule = hMod;
			DomainName = friendlyName;
			Reserved2 = 0;
			Reserved = 0;
			ModulePath = modPath;
			ModulePathA = IntPtr.Zero;
			pBindCookie = cookiePtr;
		}
	}

	private sealed class AutoInit : SafeHandle
	{
		private bool _bInitialized;

		public override bool IsInvalid => !_bInitialized;

		internal AutoInit()
			: base(IntPtr.Zero, ownsHandle: true)
		{
			initEntryPoint();
			_bInitialized = true;
		}

		protected override bool ReleaseHandle()
		{
			_bInitialized = false;
			doneEntryPoint();
			return true;
		}
	}

	[SuppressUnmanagedCodeSecurity]
	[ComVisible(false)]
	private static class NativeMethods
	{
		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "DllBidPutStrW")]
		internal static extern void PutStr(IntPtr hID, UIntPtr src, UIntPtr info, string str);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string strConst);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, string a1);

		[DllImport("System.Data.OracleClient.dll", EntryPoint = "DllBidScopeLeave")]
		internal static extern void ScopeLeave(IntPtr hID, UIntPtr src, UIntPtr info, ref IntPtr hScp);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidScopeEnterCW")]
		internal static extern void ScopeEnter(IntPtr hID, UIntPtr src, UIntPtr info, out IntPtr hScp, string strConst);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidScopeEnterCW")]
		internal static extern void ScopeEnter(IntPtr hID, UIntPtr src, UIntPtr info, out IntPtr hScp, string fmtPrintfW, int a1);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidScopeEnterCW")]
		internal static extern void ScopeEnter(IntPtr hID, UIntPtr src, UIntPtr info, out IntPtr hScp, string fmtPrintfW, int a1, int a2);

		[DllImport("System.Data.OracleClient.dll", CharSet = CharSet.Unicode, EntryPoint = "DllBidCtlProc")]
		internal static extern void AddMetaText(IntPtr hID, IntPtr cmdSpace, CtlCmd cmd, IntPtr nop1, string txtID, IntPtr nop2);

		[DllImport("System.Data.OracleClient.dll", BestFitMapping = false, CharSet = CharSet.Ansi)]
		internal static extern void DllBidEntryPoint(ref IntPtr hID, int bInitAndVer, string sIdentity, uint propBits, ref ApiGroup pGblFlags, CtrlCB fAddr, ref BIDEXTINFO pExtInfo, IntPtr pHooks, IntPtr pHdr);

		[DllImport("System.Data.OracleClient.dll")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void DllBidEntryPoint(ref IntPtr hID, int bInitAndVer, IntPtr unused1, uint propBits, ref ApiGroup pGblFlags, IntPtr unused2, IntPtr unused3, IntPtr unused4, IntPtr unused5);

		[DllImport("System.Data.OracleClient.dll")]
		internal static extern void DllBidInitialize();

		[DllImport("System.Data.OracleClient.dll")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void DllBidFinalize();

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidScopeEnterCW")]
		internal static extern void ScopeEnter(IntPtr hID, UIntPtr src, UIntPtr info, out IntPtr hScp, string fmtPrintfW, int a1, string a2);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, uint a1, int a2);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, int a2);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, string a1, int a2);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, string a2);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, IntPtr a2, int a3);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, string a2, int a3);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, int a2, int a3);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, int a2, string a3);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, uint a4);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, int a3, IntPtr a4);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, int a5);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, uint a4, uint a5);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, string a2, int a3, string a4, int a5);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, string a3, int a4, int a5);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, int a3, int a4, int a5);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, uint a3, uint a4, uint a5, uint a6);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, int a2, IntPtr a3, IntPtr a4, int a5, int a6);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, uint a5, uint a6, uint a7);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, string a4, int a5, string a6, int a7);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, int a5, int a6, int a7, int a8);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, int a5, IntPtr a6, IntPtr a7, int a8);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, int a3, IntPtr a4, IntPtr a5, IntPtr a6, IntPtr a7, IntPtr a8);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, uint a5, IntPtr a6, int a7, IntPtr a8, IntPtr a9, int a10, int a11);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, uint a5, IntPtr a6, int a7, int a8, IntPtr a9, IntPtr a10, int a11, int a12);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, string a3, int a4, IntPtr a5, int a6, int a7, IntPtr a8, int a9, IntPtr a10, int a11, IntPtr a12, uint a13, IntPtr a14, int a15);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, int a2);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, int a3);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5, int a6, IntPtr a7);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, int a2, int a3, IntPtr a4, IntPtr a5, int a6);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, int a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5, int a6, IntPtr a7, int a8, int a9);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, string a2, string a3, IntPtr a4, string a5, uint a6, int a7);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, string a2, string a3, IntPtr a4, IntPtr a5, uint a6, int a7);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, string a2, string a3, IntPtr a4, int a5, uint a6, int a7);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, string a2, IntPtr a3, int a4, IntPtr a5, int a6);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, string a2, int a3, uint a4, string a5, IntPtr a6);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, string a2, IntPtr a3, uint a4, string a5, IntPtr a6);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, uint a3, IntPtr a4, int a5, int a6, string a7, IntPtr a8, IntPtr a9, IntPtr a10, int a11, IntPtr a12, int a13);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, string a2, string a3, uint a4, string a5, IntPtr a6);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, string a4, int a5);

		[DllImport("System.Data.OracleClient.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "DllBidTraceCW")]
		internal static extern void Trace(IntPtr hID, UIntPtr src, UIntPtr info, string fmtPrintfW, IntPtr a1, IntPtr a2, int a3, int a4, int a5, string a6);
	}

	private const int BidVer = 9210;

	private const uint configFlags = 3489660928u;

	private const string dllName = "System.Data.OracleClient.dll";

	private static IntPtr __noData;

	private static object _setBitsLock = new object();

	private static IntPtr modID = internalInitialize();

	private static ApiGroup modFlags;

	private static string modIdentity;

	private static CtrlCB ctrlCallback;

	private static BindingCookie cookieObject;

	private static GCHandle hCookie;

	private static IntPtr __defaultCmdSpace;

	private static AutoInit ai;

	internal static bool TraceOn => (modFlags & ApiGroup.Trace) != 0;

	internal static bool AdvancedOn => (modFlags & ApiGroup.Advanced) != 0;

	internal static IntPtr NoData => __noData;

	internal static IntPtr DefaultCmdSpace => __defaultCmdSpace;

	internal static bool IsOn(ApiGroup flag)
	{
		return (modFlags & flag) != 0;
	}

	internal static void PutStr(string str)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.PutStr(modID, UIntPtr.Zero, (UIntPtr)0u, str);
		}
	}

	internal static void Trace(string strConst)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, strConst);
		}
	}

	internal static void Trace(string fmtPrintfW, string a1)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1);
		}
	}

	internal static void ScopeLeave(ref IntPtr hScp)
	{
		if ((modFlags & ApiGroup.Scope) != 0 && modID != NoData)
		{
			if (hScp != NoData)
			{
				NativeMethods.ScopeLeave(modID, UIntPtr.Zero, UIntPtr.Zero, ref hScp);
			}
		}
		else
		{
			hScp = NoData;
		}
	}

	internal static void ScopeEnter(out IntPtr hScp, string strConst)
	{
		if ((modFlags & ApiGroup.Scope) != 0 && modID != NoData)
		{
			NativeMethods.ScopeEnter(modID, UIntPtr.Zero, UIntPtr.Zero, out hScp, strConst);
		}
		else
		{
			hScp = NoData;
		}
	}

	internal static void ScopeEnter(out IntPtr hScp, string fmtPrintfW, int a1)
	{
		if ((modFlags & ApiGroup.Scope) != 0 && modID != NoData)
		{
			NativeMethods.ScopeEnter(modID, UIntPtr.Zero, UIntPtr.Zero, out hScp, fmtPrintfW, a1);
		}
		else
		{
			hScp = NoData;
		}
	}

	internal static void ScopeEnter(out IntPtr hScp, string fmtPrintfW, int a1, int a2)
	{
		if ((modFlags & ApiGroup.Scope) != 0 && modID != NoData)
		{
			NativeMethods.ScopeEnter(modID, UIntPtr.Zero, UIntPtr.Zero, out hScp, fmtPrintfW, a1, a2);
		}
		else
		{
			hScp = NoData;
		}
	}

	internal static ApiGroup SetApiGroupBits(ApiGroup mask, ApiGroup bits)
	{
		lock (_setBitsLock)
		{
			ApiGroup apiGroup = modFlags;
			if (mask != 0)
			{
				modFlags ^= (bits ^ apiGroup) & mask;
			}
			return apiGroup;
		}
	}

	internal static bool AddMetaText(string metaStr)
	{
		if (modID != NoData)
		{
			NativeMethods.AddMetaText(modID, DefaultCmdSpace, CtlCmd.AddMetaText, IntPtr.Zero, metaStr, IntPtr.Zero);
		}
		return true;
	}

	[Conditional("DEBUG")]
	internal static void DTRACE(string strConst)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.PutStr(modID, UIntPtr.Zero, (UIntPtr)1u, strConst);
		}
	}

	[Conditional("DEBUG")]
	internal static void DTRACE(string clrFormatString, params object[] args)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.PutStr(modID, UIntPtr.Zero, (UIntPtr)1u, string.Format(CultureInfo.CurrentCulture, clrFormatString, args));
		}
	}

	[Conditional("DEBUG")]
	internal static void DASSERT(bool condition)
	{
		if (!condition)
		{
			System.Diagnostics.Trace.Assert(condition: false);
		}
	}

	private static void deterministicStaticInit()
	{
		__noData = (IntPtr)(-1);
		__defaultCmdSpace = (IntPtr)(-1);
		modFlags = ApiGroup.Off;
		modIdentity = string.Empty;
		ctrlCallback = SetApiGroupBits;
		cookieObject = new BindingCookie();
		hCookie = GCHandle.Alloc(cookieObject, GCHandleType.Pinned);
	}

	private static string getIdentity(Module mod)
	{
		object[] customAttributes = mod.GetCustomAttributes(typeof(BidIdentityAttribute), inherit: true);
		if (customAttributes.Length == 0)
		{
			return mod.Name;
		}
		return ((BidIdentityAttribute)customAttributes[0]).IdentityString;
	}

	private static string getAppDomainFriendlyName()
	{
		string text = AppDomain.CurrentDomain.FriendlyName;
		if (text == null || text.Length <= 0)
		{
			text = "AppDomain.H" + AppDomain.CurrentDomain.GetHashCode();
		}
		return text;
	}

	[FileIOPermission(SecurityAction.Assert, Unrestricted = true)]
	private static string getModulePath(Module mod)
	{
		return mod.FullyQualifiedName;
	}

	private static void initEntryPoint()
	{
		NativeMethods.DllBidInitialize();
		Module manifestModule = Assembly.GetExecutingAssembly().ManifestModule;
		modIdentity = getIdentity(manifestModule);
		modID = NoData;
		BIDEXTINFO pExtInfo = new BIDEXTINFO(Marshal.GetHINSTANCE(manifestModule), getModulePath(manifestModule), getAppDomainFriendlyName(), hCookie.AddrOfPinnedObject());
		NativeMethods.DllBidEntryPoint(ref modID, 9210, modIdentity, 3489660928u, ref modFlags, ctrlCallback, ref pExtInfo, IntPtr.Zero, IntPtr.Zero);
		if (modID != NoData)
		{
			object[] customAttributes = manifestModule.GetCustomAttributes(typeof(BidMetaTextAttribute), inherit: true);
			object[] array = customAttributes;
			foreach (object obj in array)
			{
				AddMetaText(((BidMetaTextAttribute)obj).MetaText);
			}
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	private static void doneEntryPoint()
	{
		if (modID == NoData)
		{
			modFlags = ApiGroup.Off;
			return;
		}
		try
		{
			NativeMethods.DllBidEntryPoint(ref modID, 0, IntPtr.Zero, 3489660928u, ref modFlags, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			NativeMethods.DllBidFinalize();
		}
		catch
		{
			modFlags = ApiGroup.Off;
		}
		finally
		{
			cookieObject.Invalidate();
			modID = NoData;
			modFlags = ApiGroup.Off;
		}
	}

	private static IntPtr internalInitialize()
	{
		deterministicStaticInit();
		ai = new AutoInit();
		return modID;
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void PoolerTrace(string fmtPrintfW, int a1)
	{
		if ((modFlags & (ApiGroup)4096u) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1);
		}
	}

	internal static void PoolerTrace(string fmtPrintfW, int a1, int a2)
	{
		if ((modFlags & (ApiGroup)4096u) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2);
		}
	}

	internal static void PoolerTrace(string fmtPrintfW, int a1, int a2, int a3)
	{
		if ((modFlags & (ApiGroup)4096u) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3);
		}
	}

	internal static void PoolerScopeEnter(out IntPtr hScp, string fmtPrintfW, int a1)
	{
		if ((modFlags & (ApiGroup)4096u) != 0 && modID != NoData)
		{
			NativeMethods.ScopeEnter(modID, UIntPtr.Zero, UIntPtr.Zero, out hScp, fmtPrintfW, a1);
		}
		else
		{
			hScp = NoData;
		}
	}

	internal static void ScopeEnter(out IntPtr hScp, string fmtPrintfW, int a1, string a2)
	{
		if ((modFlags & ApiGroup.Scope) != 0 && modID != NoData)
		{
			NativeMethods.ScopeEnter(modID, UIntPtr.Zero, UIntPtr.Zero, out hScp, fmtPrintfW, a1, a2);
		}
		else
		{
			hScp = NoData;
		}
	}

	internal static void Trace(string fmtPrintfW, uint a1, int a2)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2);
		}
	}

	internal static void Trace(string fmtPrintfW, int a1, int a2)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2);
		}
	}

	internal static void Trace(string fmtPrintfW, string a1, int a2)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2);
		}
	}

	internal static void Trace(string fmtPrintfW, int a1, string a2)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2);
		}
	}

	internal static void Trace(string fmtPrintfW, int a1, IntPtr a2, int a3)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3);
		}
	}

	internal static void Trace(string fmtPrintfW, int a1, string a2, int a3)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3);
		}
	}

	internal static void Trace(string fmtPrintfW, int a1, int a2, string a3)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, uint a4)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, int a3, IntPtr a4)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, int a5)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, uint a4, uint a5)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5);
		}
	}

	internal static void Trace(string fmtPrintfW, int a1, string a2, int a3, string a4, int a5)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, int a2, IntPtr a3, IntPtr a4, int a5, int a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, uint a5, uint a6, uint a7)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, string a4, int a5, string a6, int a7)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, int a5, int a6, int a7, int a8)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7, a8);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, int a3, IntPtr a4, IntPtr a5, IntPtr a6, IntPtr a7, IntPtr a8)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7, a8);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, uint a5, IntPtr a6, int a7, IntPtr a8, IntPtr a9, int a10, int a11)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, IntPtr a3, int a4, uint a5, IntPtr a6, int a7, int a8, IntPtr a9, IntPtr a10, int a11, int a12)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
		}
	}

	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, string a3, int a4, IntPtr a5, int a6, int a7, IntPtr a8, int a9, IntPtr a10, int a11, IntPtr a12, uint a13, IntPtr a14, int a15)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15);
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void Trace(string fmtPrintfW, int a1)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1);
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void Trace(string fmtPrintfW, IntPtr a1)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1);
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void Trace(string fmtPrintfW, IntPtr a1, int a2)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2);
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void Trace(string fmtPrintfW, IntPtr a1, IntPtr a2, int a3)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3);
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void Trace(string fmtPrintfW, OciHandle a1, int a2, int a3, IntPtr a4, IntPtr a5, int a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2, a3, a4, a5, a6);
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void Trace(string fmtPrintfW, int a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5, int a6, IntPtr a7)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7);
		}
	}

	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	internal static void Trace(string fmtPrintfW, int a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5, int a6, IntPtr a7, int a8, int a9)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, a1, a2, a3, a4, a5, a6, a7, a8, a9);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OCI.HTYPE a2, OCI.ATTR a3, OciHandle a4, string a5, uint a6, int a7)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2.ToString(), OciHandle.GetAttributeName(a1, a3), OciHandle.HandleValueToTrace(a4), a5, a6, a7);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OCI.HTYPE a2, OCI.ATTR a3, OciHandle a4, IntPtr a5, uint a6, int a7)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2.ToString(), OciHandle.GetAttributeName(a1, a3), OciHandle.HandleValueToTrace(a4), a5, a6, a7);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OCI.HTYPE a2, OCI.ATTR a3, OciHandle a4, int a5, uint a6, int a7)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2.ToString(), OciHandle.GetAttributeName(a1, a3), OciHandle.HandleValueToTrace(a4), a5, a6, a7);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OCI.HTYPE a2, OciHandle a3, int a4, IntPtr a5, int a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2.ToString(), OciHandle.HandleValueToTrace(a3), a4, a5, a6);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OCI.HTYPE a2, int a3, uint a4, OCI.ATTR a5, OciHandle a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2.ToString(), a3, a4, OciHandle.GetAttributeName(a1, a5), OciHandle.HandleValueToTrace(a6));
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OCI.HTYPE a2, OciHandle a3, uint a4, OCI.ATTR a5, OciHandle a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2.ToString(), OciHandle.HandleValueToTrace(a3), a4, OciHandle.GetAttributeName(a1, a5), OciHandle.HandleValueToTrace(a6));
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OciHandle a2, uint a3, IntPtr a4, int a5, int a6, OCI.DATATYPE a7, IntPtr a8, IntPtr a9, IntPtr a10, int a11, IntPtr a12, int a13)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), OciHandle.HandleValueToTrace(a2), a3, a4, a5, a6, a7.ToString(), a8, a9, a10, a11, a12, a13);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OciHandle a2, uint a3, uint a4, uint a5, uint a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), OciHandle.HandleValueToTrace(a2), a3, a4, a5, a6);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OCI.HTYPE a2, string a3, uint a4, OCI.ATTR a5, OciHandle a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), a2.ToString(), a3, a4, OciHandle.GetAttributeName(a1, a5), OciHandle.HandleValueToTrace(a6));
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OciHandle a2, string a3, int a4, int a5)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), OciHandle.HandleValueToTrace(a2), a3, a4, a5);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OciHandle a2, OciHandle a3, OCI.CRED a4, int a5)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), OciHandle.HandleValueToTrace(a2), OciHandle.HandleValueToTrace(a3), a4.ToString(), a5);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OciHandle a2, OciHandle a3, int a4, int a5, IntPtr a6, IntPtr a7, int a8)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), OciHandle.HandleValueToTrace(a2), OciHandle.HandleValueToTrace(a3), a4, a5, a6, a7, a8);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OciHandle a2, int a3, int a4, int a5)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), OciHandle.HandleValueToTrace(a2), a3, a4, a5);
		}
	}

	internal static void Trace(string fmtPrintfW, OciHandle a1, OciHandle a2, int a3, int a4, int a5, string a6)
	{
		if ((modFlags & ApiGroup.Trace) != 0 && modID != NoData)
		{
			NativeMethods.Trace(modID, UIntPtr.Zero, UIntPtr.Zero, fmtPrintfW, OciHandle.HandleValueToTrace(a1), OciHandle.HandleValueToTrace(a2), a3, a4, a5, a6);
		}
	}
}
[AttributeUsage(AttributeTargets.Module, AllowMultiple = false)]
internal sealed class BidIdentityAttribute : Attribute
{
	private string _identity;

	internal string IdentityString => _identity;

	internal BidIdentityAttribute(string idStr)
	{
		_identity = idStr;
	}
}
[AttributeUsage(AttributeTargets.Module, AllowMultiple = true)]
internal sealed class BidMetaTextAttribute : Attribute
{
	private string _metaText;

	internal string MetaText => _metaText;

	internal BidMetaTextAttribute(string str)
	{
		_metaText = str;
	}
}
namespace System.Data.OracleClient
{
	internal abstract class DbSqlParser
	{
		public enum TokenType
		{
			Null = 0,
			Identifier = 1,
			QuotedIdentifier = 2,
			String = 3,
			Other = 100,
			Other_Comma = 101,
			Other_Period = 102,
			Other_LeftParen = 103,
			Other_RightParen = 104,
			Other_Star = 105,
			Keyword = 200,
			Keyword_ALL = 201,
			Keyword_AS = 202,
			Keyword_COMPUTE = 203,
			Keyword_CROSS = 204,
			Keyword_DISTINCT = 205,
			Keyword_FOR = 206,
			Keyword_FROM = 207,
			Keyword_FULL = 208,
			Keyword_GROUP = 209,
			Keyword_HAVING = 210,
			Keyword_INNER = 211,
			Keyword_INTERSECT = 212,
			Keyword_INTO = 213,
			Keyword_JOIN = 214,
			Keyword_LEFT = 215,
			Keyword_MINUS = 216,
			Keyword_NATURAL = 217,
			Keyword_ON = 218,
			Keyword_ORDER = 219,
			Keyword_OUTER = 220,
			Keyword_RIGHT = 221,
			Keyword_SELECT = 222,
			Keyword_TOP = 223,
			Keyword_UNION = 224,
			Keyword_USING = 225,
			Keyword_WHERE = 226
		}

		internal struct Token
		{
			private TokenType _type;

			private string _value;

			internal static readonly Token Null = new Token(TokenType.Null, null);

			internal string Value => _value;

			internal TokenType Type => _type;

			internal Token(TokenType type, string value)
			{
				_type = type;
				_value = value;
			}
		}

		private enum PARSERSTATE
		{
			NOTHINGYET = 1,
			SELECT,
			COLUMN,
			COLUMNALIAS,
			TABLE,
			TABLEALIAS,
			FROM,
			EXPRESSION,
			JOIN,
			JOINCONDITION,
			DONE
		}

		private const string SqlTokenPattern_Part1 = "[\\s;]*((?<keyword>all|as|compute|cross|distinct|for|from|full|group|having|intersect|inner|join|left|minus|natural|order|outer|on|right|select|top|union|using|where)\\b|(?<identifier>";

		private const string SqlTokenPattern_Part2 = "*)|";

		private const string SqlTokenPattern_Part3 = "(?<quotedidentifier>";

		private const string SqlTokenPattern_Part4 = ")";

		private const string SqlTokenPattern_Part5 = "|(?<string>";

		private const string SqlTokenPattern_Part6 = ")|(?<other>.))[\\s;]*";

		private static Regex _sqlTokenParser;

		private static string _sqlTokenPattern;

		private static int _identifierGroup;

		private static int _quotedidentifierGroup;

		private static int _keywordGroup;

		private static int _stringGroup;

		private static int _otherGroup;

		private string _quotePrefixCharacter;

		private string _quoteSuffixCharacter;

		private DbSqlParserColumnCollection _columns;

		private DbSqlParserTableCollection _tables;

		internal DbSqlParserColumnCollection Columns
		{
			get
			{
				if (_columns == null)
				{
					_columns = new DbSqlParserColumnCollection();
				}
				return _columns;
			}
		}

		protected virtual string QuotePrefixCharacter => _quotePrefixCharacter;

		protected virtual string QuoteSuffixCharacter => _quoteSuffixCharacter;

		private static Regex SqlTokenParser
		{
			get
			{
				Regex sqlTokenParser = _sqlTokenParser;
				if (sqlTokenParser == null)
				{
					sqlTokenParser = GetSqlTokenParser();
				}
				return sqlTokenParser;
			}
		}

		internal DbSqlParserTableCollection Tables
		{
			get
			{
				if (_tables == null)
				{
					_tables = new DbSqlParserTableCollection();
				}
				return _tables;
			}
		}

		public DbSqlParser(string quotePrefixCharacter, string quoteSuffixCharacter, string regexPattern)
		{
			_quotePrefixCharacter = quotePrefixCharacter;
			_quoteSuffixCharacter = quoteSuffixCharacter;
			_sqlTokenPattern = regexPattern;
		}

		internal static string CreateRegexPattern(string validIdentifierFirstCharacters, string validIdendifierCharacters, string quotePrefixCharacter, string quotedIdentifierCharacters, string quoteSuffixCharacter, string stringPattern)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append("[\\s;]*((?<keyword>all|as|compute|cross|distinct|for|from|full|group|having|intersect|inner|join|left|minus|natural|order|outer|on|right|select|top|union|using|where)\\b|(?<identifier>");
			stringBuilder.Append(validIdentifierFirstCharacters);
			stringBuilder.Append(validIdendifierCharacters);
			stringBuilder.Append("*)|");
			stringBuilder.Append(quotePrefixCharacter);
			stringBuilder.Append("(?<quotedidentifier>");
			stringBuilder.Append(quotedIdentifierCharacters);
			stringBuilder.Append(")");
			stringBuilder.Append(quoteSuffixCharacter);
			stringBuilder.Append("|(?<string>");
			stringBuilder.Append(stringPattern);
			stringBuilder.Append(")|(?<other>.))[\\s;]*");
			return stringBuilder.ToString();
		}

		private void AddColumn(int maxPart, Token[] namePart, Token aliasName)
		{
			Columns.Add(GetPart(0, namePart, maxPart), GetPart(1, namePart, maxPart), GetPart(2, namePart, maxPart), GetPart(3, namePart, maxPart), GetTokenAsString(aliasName));
		}

		private void AddTable(int maxPart, Token[] namePart, Token correlationName)
		{
			Tables.Add(GetPart(1, namePart, maxPart), GetPart(2, namePart, maxPart), GetPart(3, namePart, maxPart), GetTokenAsString(correlationName));
		}

		private void CompleteSchemaInformation()
		{
			DbSqlParserColumnCollection columns = Columns;
			DbSqlParserTableCollection tables = Tables;
			int num = columns.Count;
			int count = tables.Count;
			for (int i = 0; i < count; i++)
			{
				DbSqlParserTable dbSqlParserTable = tables[i];
				DbSqlParserColumnCollection dbSqlParserColumnCollection2 = (dbSqlParserTable.Columns = GatherTableColumns(dbSqlParserTable));
			}
			for (int j = 0; j < num; j++)
			{
				DbSqlParserColumn dbSqlParserColumn = columns[j];
				DbSqlParserTable dbSqlParserTable2 = FindTableForColumn(dbSqlParserColumn);
				if (dbSqlParserColumn.IsExpression)
				{
					continue;
				}
				if ("*" == dbSqlParserColumn.ColumnName)
				{
					columns.RemoveAt(j);
					if (dbSqlParserColumn.TableName.Length != 0)
					{
						DbSqlParserColumnCollection columns2 = dbSqlParserTable2.Columns;
						int count2 = columns2.Count;
						for (int k = 0; k < count2; k++)
						{
							columns.Insert(j + k, columns2[k]);
						}
						num += count2 - 1;
						j += count2 - 1;
						continue;
					}
					for (int l = 0; l < count; l++)
					{
						dbSqlParserTable2 = tables[l];
						DbSqlParserColumnCollection columns3 = dbSqlParserTable2.Columns;
						int count3 = columns3.Count;
						for (int m = 0; m < count3; m++)
						{
							columns.Insert(j + m, columns3[m]);
						}
						num += count3 - 1;
						j += count3;
					}
				}
				else
				{
					DbSqlParserColumn dbSqlParserColumn2 = FindCompletedColumn(dbSqlParserTable2, dbSqlParserColumn);
					if (dbSqlParserColumn2 != null)
					{
						dbSqlParserColumn.CopySchemaInfoFrom(dbSqlParserColumn2);
					}
					else
					{
						dbSqlParserColumn.CopySchemaInfoFrom(dbSqlParserTable2);
					}
				}
			}
			for (int n = 0; n < count; n++)
			{
				DbSqlParserTable table = tables[n];
				GatherKeyColumns(table);
			}
		}

		protected DbSqlParserColumn FindCompletedColumn(DbSqlParserTable table, DbSqlParserColumn searchColumn)
		{
			DbSqlParserColumnCollection columns = table.Columns;
			int count = columns.Count;
			for (int i = 0; i < count; i++)
			{
				DbSqlParserColumn dbSqlParserColumn = columns[i];
				if (CatalogMatch(dbSqlParserColumn.ColumnName, searchColumn.ColumnName))
				{
					return dbSqlParserColumn;
				}
			}
			return null;
		}

		internal DbSqlParserTable FindTableForColumn(DbSqlParserColumn column)
		{
			DbSqlParserTableCollection tables = Tables;
			int count = tables.Count;
			for (int i = 0; i < count; i++)
			{
				DbSqlParserTable dbSqlParserTable = tables[i];
				if (System.Data.Common.ADP.IsEmpty(column.DatabaseName) && System.Data.Common.ADP.IsEmpty(column.SchemaName) && CatalogMatch(column.TableName, dbSqlParserTable.CorrelationName))
				{
					return dbSqlParserTable;
				}
				if ((System.Data.Common.ADP.IsEmpty(column.DatabaseName) || CatalogMatch(column.DatabaseName, dbSqlParserTable.DatabaseName)) && (System.Data.Common.ADP.IsEmpty(column.SchemaName) || CatalogMatch(column.SchemaName, dbSqlParserTable.SchemaName)) && (System.Data.Common.ADP.IsEmpty(column.TableName) || CatalogMatch(column.TableName, dbSqlParserTable.TableName)))
				{
					return dbSqlParserTable;
				}
			}
			return null;
		}

		private string GetPart(int part, Token[] namePart, int maxPart)
		{
			int num = maxPart - namePart.Length + part + 1;
			if (0 > num)
			{
				return null;
			}
			return GetTokenAsString(namePart[num]);
		}

		private static Regex GetSqlTokenParser()
		{
			Regex regex = _sqlTokenParser;
			if (regex == null)
			{
				regex = new Regex(_sqlTokenPattern, RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture);
				_identifierGroup = regex.GroupNumberFromName("identifier");
				_quotedidentifierGroup = regex.GroupNumberFromName("quotedidentifier");
				_keywordGroup = regex.GroupNumberFromName("keyword");
				_stringGroup = regex.GroupNumberFromName("string");
				_otherGroup = regex.GroupNumberFromName("other");
				_sqlTokenParser = regex;
			}
			return regex;
		}

		private string GetTokenAsString(Token token)
		{
			if (TokenType.QuotedIdentifier == token.Type)
			{
				return _quotePrefixCharacter + token.Value + _quoteSuffixCharacter;
			}
			return token.Value;
		}

		public void Parse(string statementText)
		{
			Parse2(statementText);
			CompleteSchemaInformation();
		}

		private void Parse2(string statementText)
		{
			PARSERSTATE pARSERSTATE = PARSERSTATE.NOTHINGYET;
			Token[] array = new Token[4];
			int num = 0;
			Token token = Token.Null;
			TokenType tokenType = TokenType.Null;
			int num2 = 0;
			_columns = null;
			_tables = null;
			Match match = SqlTokenParser.Match(statementText);
			Token token2 = TokenFromMatch(match);
			while (true)
			{
				bool flag = false;
				switch (pARSERSTATE)
				{
				case PARSERSTATE.DONE:
					return;
				case PARSERSTATE.NOTHINGYET:
				{
					TokenType type2 = token2.Type;
					if (type2 == TokenType.Keyword_SELECT)
					{
						pARSERSTATE = PARSERSTATE.SELECT;
						break;
					}
					throw System.Data.Common.ADP.InvalidOperation(Res.GetString("ADP_SQLParserInternalError"));
				}
				case PARSERSTATE.SELECT:
					switch (token2.Type)
					{
					case TokenType.Identifier:
					case TokenType.QuotedIdentifier:
						pARSERSTATE = PARSERSTATE.COLUMN;
						num = 0;
						array[0] = token2;
						break;
					case TokenType.Keyword_FROM:
						pARSERSTATE = PARSERSTATE.FROM;
						break;
					case TokenType.Other_Star:
						pARSERSTATE = PARSERSTATE.COLUMNALIAS;
						num = 0;
						array[0] = token2;
						break;
					case TokenType.Other_LeftParen:
						pARSERSTATE = PARSERSTATE.EXPRESSION;
						num2++;
						break;
					case TokenType.Other_RightParen:
						throw System.Data.Common.ADP.SyntaxErrorMissingParenthesis();
					default:
						pARSERSTATE = PARSERSTATE.EXPRESSION;
						break;
					case TokenType.Keyword_ALL:
					case TokenType.Keyword_DISTINCT:
						break;
					}
					break;
				case PARSERSTATE.COLUMN:
					switch (token2.Type)
					{
					case TokenType.Identifier:
					case TokenType.QuotedIdentifier:
						if (TokenType.Other_Period != tokenType)
						{
							pARSERSTATE = PARSERSTATE.COLUMNALIAS;
							token = token2;
						}
						else
						{
							array[++num] = token2;
						}
						break;
					case TokenType.Other_Period:
						if (num > 3)
						{
							throw System.Data.Common.ADP.SyntaxErrorTooManyNameParts();
						}
						break;
					case TokenType.Other_Star:
						pARSERSTATE = PARSERSTATE.COLUMNALIAS;
						array[++num] = token2;
						break;
					case TokenType.Other_Comma:
					case TokenType.Keyword_FROM:
						pARSERSTATE = ((token2.Type == TokenType.Keyword_FROM) ? PARSERSTATE.FROM : PARSERSTATE.SELECT);
						AddColumn(num, array, token);
						num = -1;
						token = Token.Null;
						break;
					case TokenType.Other_LeftParen:
						pARSERSTATE = PARSERSTATE.EXPRESSION;
						num2++;
						num = -1;
						break;
					case TokenType.Other_RightParen:
						throw System.Data.Common.ADP.SyntaxErrorMissingParenthesis();
					default:
						pARSERSTATE = PARSERSTATE.EXPRESSION;
						num = -1;
						break;
					case TokenType.Keyword_AS:
						break;
					}
					break;
				case PARSERSTATE.COLUMNALIAS:
				{
					TokenType type = token2.Type;
					if (type == TokenType.Other_Comma || type == TokenType.Keyword_FROM)
					{
						pARSERSTATE = ((token2.Type == TokenType.Keyword_FROM) ? PARSERSTATE.FROM : PARSERSTATE.SELECT);
						AddColumn(num, array, token);
						num = -1;
						token = Token.Null;
						break;
					}
					throw System.Data.Common.ADP.SyntaxErrorExpectedCommaAfterColumn();
				}
				case PARSERSTATE.EXPRESSION:
					switch (token2.Type)
					{
					case TokenType.Identifier:
					case TokenType.QuotedIdentifier:
						if (num2 == 0)
						{
							token = token2;
						}
						break;
					case TokenType.Other_Comma:
					case TokenType.Keyword_FROM:
						if (num2 == 0)
						{
							pARSERSTATE = ((token2.Type == TokenType.Keyword_FROM) ? PARSERSTATE.FROM : PARSERSTATE.SELECT);
							AddColumn(num, array, token);
							num = -1;
							token = Token.Null;
						}
						break;
					case TokenType.Other_LeftParen:
						num2++;
						break;
					case TokenType.Other_RightParen:
						num2--;
						break;
					}
					break;
				case PARSERSTATE.FROM:
					switch (token2.Type)
					{
					case TokenType.Identifier:
					case TokenType.QuotedIdentifier:
						break;
					default:
						throw System.Data.Common.ADP.SyntaxErrorExpectedIdentifier();
					}
					pARSERSTATE = PARSERSTATE.TABLE;
					num = 0;
					array[0] = token2;
					break;
				case PARSERSTATE.JOIN:
					switch (token2.Type)
					{
					case TokenType.Keyword_JOIN:
						pARSERSTATE = PARSERSTATE.FROM;
						break;
					default:
						throw System.Data.Common.ADP.SyntaxErrorExpectedNextPart();
					case TokenType.Keyword_INNER:
					case TokenType.Keyword_OUTER:
						break;
					}
					break;
				case PARSERSTATE.JOINCONDITION:
					switch (token2.Type)
					{
					case TokenType.Other_LeftParen:
						num2++;
						break;
					case TokenType.Other_RightParen:
						num2--;
						break;
					default:
						if (num2 == 0)
						{
							switch (token2.Type)
							{
							case TokenType.Null:
							case TokenType.Keyword_COMPUTE:
							case TokenType.Keyword_FOR:
							case TokenType.Keyword_GROUP:
							case TokenType.Keyword_HAVING:
							case TokenType.Keyword_INTERSECT:
							case TokenType.Keyword_MINUS:
							case TokenType.Keyword_ORDER:
							case TokenType.Keyword_UNION:
							case TokenType.Keyword_WHERE:
								pARSERSTATE = PARSERSTATE.DONE;
								break;
							case TokenType.Keyword_JOIN:
								pARSERSTATE = PARSERSTATE.FROM;
								break;
							case TokenType.Keyword_CROSS:
							case TokenType.Keyword_LEFT:
							case TokenType.Keyword_NATURAL:
							case TokenType.Keyword_RIGHT:
								pARSERSTATE = PARSERSTATE.JOIN;
								break;
							}
						}
						break;
					}
					break;
				case PARSERSTATE.TABLE:
					switch (token2.Type)
					{
					case TokenType.Identifier:
					case TokenType.QuotedIdentifier:
						if (TokenType.Other_Period != tokenType)
						{
							pARSERSTATE = PARSERSTATE.TABLEALIAS;
							token = token2;
						}
						else
						{
							array[++num] = token2;
						}
						break;
					case TokenType.Other_Period:
						if (num > 2)
						{
							throw System.Data.Common.ADP.SyntaxErrorTooManyNameParts();
						}
						break;
					case TokenType.Null:
					case TokenType.Keyword_COMPUTE:
					case TokenType.Keyword_FOR:
					case TokenType.Keyword_GROUP:
					case TokenType.Keyword_HAVING:
					case TokenType.Keyword_INTERSECT:
					case TokenType.Keyword_MINUS:
					case TokenType.Keyword_ORDER:
					case TokenType.Keyword_UNION:
					case TokenType.Keyword_WHERE:
						pARSERSTATE = PARSERSTATE.DONE;
						flag = true;
						break;
					case TokenType.Other_Comma:
					case TokenType.Keyword_JOIN:
						pARSERSTATE = PARSERSTATE.FROM;
						flag = true;
						break;
					case TokenType.Keyword_CROSS:
					case TokenType.Keyword_LEFT:
					case TokenType.Keyword_NATURAL:
					case TokenType.Keyword_RIGHT:
						pARSERSTATE = PARSERSTATE.JOIN;
						flag = true;
						break;
					case TokenType.Keyword_ON:
					case TokenType.Keyword_USING:
						pARSERSTATE = PARSERSTATE.JOINCONDITION;
						flag = true;
						break;
					default:
						throw System.Data.Common.ADP.SyntaxErrorExpectedNextPart();
					case TokenType.Keyword_AS:
						break;
					}
					break;
				case PARSERSTATE.TABLEALIAS:
					flag = true;
					switch (token2.Type)
					{
					case TokenType.Null:
					case TokenType.Keyword_COMPUTE:
					case TokenType.Keyword_FOR:
					case TokenType.Keyword_GROUP:
					case TokenType.Keyword_HAVING:
					case TokenType.Keyword_INTERSECT:
					case TokenType.Keyword_MINUS:
					case TokenType.Keyword_ORDER:
					case TokenType.Keyword_UNION:
					case TokenType.Keyword_WHERE:
						pARSERSTATE = PARSERSTATE.DONE;
						break;
					case TokenType.Other_Comma:
					case TokenType.Keyword_JOIN:
						pARSERSTATE = PARSERSTATE.FROM;
						break;
					case TokenType.Keyword_ON:
					case TokenType.Keyword_USING:
						pARSERSTATE = PARSERSTATE.JOINCONDITION;
						break;
					case TokenType.Keyword_CROSS:
					case TokenType.Keyword_LEFT:
					case TokenType.Keyword_NATURAL:
					case TokenType.Keyword_RIGHT:
						pARSERSTATE = PARSERSTATE.JOIN;
						break;
					default:
						throw System.Data.Common.ADP.SyntaxErrorExpectedCommaAfterTable();
					}
					break;
				default:
					throw System.Data.Common.ADP.InvalidOperation(Res.GetString("ADP_SQLParserInternalError"));
				}
				if (flag)
				{
					AddTable(num, array, token);
					num = -1;
					token = Token.Null;
					flag = false;
				}
				tokenType = token2.Type;
				match = match.NextMatch();
				token2 = TokenFromMatch(match);
			}
		}

		internal static Token TokenFromMatch(Match match)
		{
			if (match == null || Match.Empty == match || !match.Success)
			{
				return Token.Null;
			}
			if (match.Groups[_identifierGroup].Success)
			{
				return new Token(TokenType.Identifier, match.Groups[_identifierGroup].Value);
			}
			if (match.Groups[_quotedidentifierGroup].Success)
			{
				return new Token(TokenType.QuotedIdentifier, match.Groups[_quotedidentifierGroup].Value);
			}
			if (match.Groups[_stringGroup].Success)
			{
				return new Token(TokenType.String, match.Groups[_stringGroup].Value);
			}
			if (match.Groups[_otherGroup].Success)
			{
				string text = match.Groups[_otherGroup].Value.ToLower(CultureInfo.InvariantCulture);
				TokenType type = TokenType.Other;
				switch (text[0])
				{
				case ',':
					type = TokenType.Other_Comma;
					break;
				case '.':
					type = TokenType.Other_Period;
					break;
				case '(':
					type = TokenType.Other_LeftParen;
					break;
				case ')':
					type = TokenType.Other_RightParen;
					break;
				case '*':
					type = TokenType.Other_Star;
					break;
				}
				return new Token(type, match.Groups[_otherGroup].Value);
			}
			if (match.Groups[_keywordGroup].Success)
			{
				string text2 = match.Groups[_keywordGroup].Value.ToLower(CultureInfo.InvariantCulture);
				int length = text2.Length;
				TokenType tokenType = TokenType.Keyword;
				switch (length)
				{
				case 2:
					if ("as" == text2)
					{
						tokenType = TokenType.Keyword_AS;
					}
					else if ("on" == text2)
					{
						tokenType = TokenType.Keyword_ON;
					}
					break;
				case 3:
					if ("for" == text2)
					{
						tokenType = TokenType.Keyword_FOR;
					}
					else if ("all" == text2)
					{
						tokenType = TokenType.Keyword_ALL;
					}
					else if ("top" == text2)
					{
						tokenType = TokenType.Keyword_TOP;
					}
					break;
				case 4:
					if ("from" == text2)
					{
						tokenType = TokenType.Keyword_FROM;
					}
					else if ("into" == text2)
					{
						tokenType = TokenType.Keyword_INTO;
					}
					else if ("join" == text2)
					{
						tokenType = TokenType.Keyword_JOIN;
					}
					else if ("left" == text2)
					{
						tokenType = TokenType.Keyword_LEFT;
					}
					break;
				case 5:
					if ("where" == text2)
					{
						tokenType = TokenType.Keyword_WHERE;
					}
					else if ("group" == text2)
					{
						tokenType = TokenType.Keyword_GROUP;
					}
					else if ("order" == text2)
					{
						tokenType = TokenType.Keyword_ORDER;
					}
					else if ("right" == text2)
					{
						tokenType = TokenType.Keyword_RIGHT;
					}
					else if ("outer" == text2)
					{
						tokenType = TokenType.Keyword_OUTER;
					}
					else if ("using" == text2)
					{
						tokenType = TokenType.Keyword_USING;
					}
					else if ("cross" == text2)
					{
						tokenType = TokenType.Keyword_CROSS;
					}
					else if ("union" == text2)
					{
						tokenType = TokenType.Keyword_UNION;
					}
					else if ("minus" == text2)
					{
						tokenType = TokenType.Keyword_MINUS;
					}
					else if ("inner" == text2)
					{
						tokenType = TokenType.Keyword_INNER;
					}
					break;
				case 6:
					if ("select" == text2)
					{
						tokenType = TokenType.Keyword_SELECT;
					}
					else if ("having" == text2)
					{
						tokenType = TokenType.Keyword_HAVING;
					}
					break;
				case 7:
					if ("compute" == text2)
					{
						tokenType = TokenType.Keyword_COMPUTE;
					}
					else if ("natural" == text2)
					{
						tokenType = TokenType.Keyword_NATURAL;
					}
					break;
				case 8:
					if ("distinct" == text2)
					{
						tokenType = TokenType.Keyword_DISTINCT;
					}
					break;
				case 9:
					if ("intersect" == text2)
					{
						tokenType = TokenType.Keyword_INTERSECT;
					}
					break;
				}
				if (TokenType.Keyword != tokenType)
				{
					return new Token(tokenType, text2);
				}
			}
			return Token.Null;
		}

		protected abstract bool CatalogMatch(string valueA, string valueB);

		protected abstract void GatherKeyColumns(DbSqlParserTable table);

		protected abstract DbSqlParserColumnCollection GatherTableColumns(DbSqlParserTable table);
	}
	internal sealed class DbSqlParserColumn
	{
		internal enum ConstraintType
		{
			PrimaryKey = 1,
			UniqueKey,
			UniqueConstraint
		}

		private bool _isKey;

		private bool _isUnique;

		private string _databaseName;

		private string _schemaName;

		private string _tableName;

		private string _columnName;

		private string _alias;

		internal string ColumnName
		{
			get
			{
				if (_columnName != null)
				{
					return _columnName;
				}
				return string.Empty;
			}
		}

		internal string DatabaseName
		{
			get
			{
				if (_databaseName != null)
				{
					return _databaseName;
				}
				return string.Empty;
			}
		}

		internal bool IsAliased => _alias != null;

		internal bool IsExpression => _columnName == null;

		internal bool IsKey => _isKey;

		internal bool IsUnique => _isUnique;

		internal string SchemaName
		{
			get
			{
				if (_schemaName != null)
				{
					return _schemaName;
				}
				return string.Empty;
			}
		}

		internal string TableName
		{
			get
			{
				if (_tableName != null)
				{
					return _tableName;
				}
				return string.Empty;
			}
		}

		internal DbSqlParserColumn(string databaseName, string schemaName, string tableName, string columnName, string alias)
		{
			_databaseName = databaseName;
			_schemaName = schemaName;
			_tableName = tableName;
			_columnName = columnName;
			_alias = alias;
		}

		internal void CopySchemaInfoFrom(DbSqlParserColumn completedColumn)
		{
			_databaseName = completedColumn.DatabaseName;
			_schemaName = completedColumn.SchemaName;
			_tableName = completedColumn.TableName;
			_columnName = completedColumn.ColumnName;
			_isKey = completedColumn.IsKey;
			_isUnique = completedColumn.IsUnique;
		}

		internal void CopySchemaInfoFrom(DbSqlParserTable table)
		{
			_databaseName = table.DatabaseName;
			_schemaName = table.SchemaName;
			_tableName = table.TableName;
			_isKey = false;
			_isUnique = false;
		}

		internal void SetConstraint(ConstraintType constraintType)
		{
			switch (constraintType)
			{
			case ConstraintType.PrimaryKey:
				_isKey = true;
				break;
			case ConstraintType.UniqueKey:
			case ConstraintType.UniqueConstraint:
				_isUnique = (_isKey = true);
				break;
			}
		}
	}
	internal sealed class DbSqlParserColumnCollection : CollectionBase
	{
		private Type ItemType => typeof(DbSqlParserColumn);

		internal DbSqlParserColumn this[int i] => (DbSqlParserColumn)base.InnerList[i];

		internal DbSqlParserColumn Add(DbSqlParserColumn value)
		{
			OnValidate(value);
			base.InnerList.Add(value);
			return value;
		}

		internal DbSqlParserColumn Add(string databaseName, string schemaName, string tableName, string columnName, string alias)
		{
			DbSqlParserColumn value = new DbSqlParserColumn(databaseName, schemaName, tableName, columnName, alias);
			return Add(value);
		}

		internal void Insert(int index, DbSqlParserColumn value)
		{
			base.InnerList.Insert(index, value);
		}

		protected override void OnValidate(object value)
		{
		}
	}
	internal sealed class DbSqlParserTable
	{
		private string _databaseName;

		private string _schemaName;

		private string _tableName;

		private string _correlationName;

		private DbSqlParserColumnCollection _columns;

		internal DbSqlParserColumnCollection Columns
		{
			get
			{
				if (_columns == null)
				{
					_columns = new DbSqlParserColumnCollection();
				}
				return _columns;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!typeof(DbSqlParserColumnCollection).IsInstanceOfType(value))
				{
					throw new InvalidCastException("value");
				}
				_columns = value;
			}
		}

		internal string CorrelationName
		{
			get
			{
				if (_correlationName != null)
				{
					return _correlationName;
				}
				return string.Empty;
			}
		}

		internal string DatabaseName
		{
			get
			{
				if (_databaseName != null)
				{
					return _databaseName;
				}
				return string.Empty;
			}
		}

		internal string SchemaName
		{
			get
			{
				if (_schemaName != null)
				{
					return _schemaName;
				}
				return string.Empty;
			}
		}

		internal string TableName
		{
			get
			{
				if (_tableName != null)
				{
					return _tableName;
				}
				return string.Empty;
			}
		}

		internal DbSqlParserTable(string databaseName, string schemaName, string tableName, string correlationName)
		{
			_databaseName = databaseName;
			_schemaName = schemaName;
			_tableName = tableName;
			_correlationName = correlationName;
		}
	}
	internal sealed class DbSqlParserTableCollection : CollectionBase
	{
		private Type ItemType => typeof(DbSqlParserTable);

		internal DbSqlParserTable this[int i] => (DbSqlParserTable)base.InnerList[i];

		internal DbSqlParserTable Add(DbSqlParserTable value)
		{
			OnValidate(value);
			base.InnerList.Add(value);
			return value;
		}

		internal DbSqlParserTable Add(string databaseName, string schemaName, string tableName, string correlationName)
		{
			DbSqlParserTable value = new DbSqlParserTable(databaseName, schemaName, tableName, correlationName);
			return Add(value);
		}

		protected override void OnValidate(object value)
		{
		}
	}
}
namespace System.Data.Common
{
	internal sealed class ADP
	{
		internal enum ConnectionError
		{
			BeginGetConnectionReturnsNull,
			GetConnectionReturnsNull,
			ConnectionOptionsMissing,
			CouldNotSwitchToClosedPreviouslyOpenedState
		}

		internal enum InternalErrorCode
		{
			UnpooledObjectHasOwner = 0,
			UnpooledObjectHasWrongOwner = 1,
			PushingObjectSecondTime = 2,
			PooledObjectHasOwner = 3,
			PooledObjectInPoolMoreThanOnce = 4,
			CreateObjectReturnedNull = 5,
			NewObjectCannotBePooled = 6,
			NonPooledObjectUsedMoreThanOnce = 7,
			AttemptingToPoolOnRestrictedToken = 8,
			ConvertSidToStringSidWReturnedNull = 10,
			AttemptingToConstructReferenceCollectionOnStaticObject = 12,
			AttemptingToEnlistTwice = 13,
			CreateReferenceCollectionReturnedNull = 14,
			PooledObjectWithoutPool = 15,
			UnexpectedWaitAnyResult = 16,
			NameValuePairNext = 20,
			InvalidParserState1 = 21,
			InvalidParserState2 = 22,
			InvalidBuffer = 30,
			InvalidLongBuffer = 31,
			InvalidNumberOfRows = 32
		}

		internal const string Parameter = "Parameter";

		internal const string ParameterName = "ParameterName";

		internal const string ConnectionString = "ConnectionString";

		internal const CompareOptions compareOptions = CompareOptions.IgnoreCase | CompareOptions.IgnoreKanaType | CompareOptions.IgnoreWidth;

		internal static readonly bool IsWindowsNT = PlatformID.Win32NT == Environment.OSVersion.Platform;

		internal static readonly bool IsPlatformNT5 = IsWindowsNT && Environment.OSVersion.Version.Major >= 5;

		private static readonly Type StackOverflowType = typeof(StackOverflowException);

		private static readonly Type OutOfMemoryType = typeof(OutOfMemoryException);

		private static readonly Type ThreadAbortType = typeof(ThreadAbortException);

		private static readonly Type NullReferenceType = typeof(NullReferenceException);

		private static readonly Type AccessViolationType = typeof(AccessViolationException);

		private static readonly Type SecurityType = typeof(SecurityException);

		internal static readonly Type ArgumentNullExceptionType = typeof(ArgumentNullException);

		internal static readonly Type FormatExceptionType = typeof(FormatException);

		internal static readonly Type OverflowExceptionType = typeof(OverflowException);

		internal static readonly string NullString = System.Data.OracleClient.Res.GetString("SqlMisc_NullString");

		internal static readonly int CharSize = 2;

		internal static readonly byte[] EmptyByteArray = new byte[0];

		internal static readonly int PtrSize = IntPtr.Size;

		internal static readonly string StrEmpty = "";

		internal static readonly HandleRef NullHandleRef = new HandleRef(null, IntPtr.Zero);

		internal static int SrcCompare(string strA, string strB)
		{
			if (!(strA == strB))
			{
				return 1;
			}
			return 0;
		}

		internal static int DstCompare(string strA, string strB)
		{
			return CultureInfo.CurrentCulture.CompareInfo.Compare(strA, strB, CompareOptions.IgnoreCase | CompareOptions.IgnoreKanaType | CompareOptions.IgnoreWidth);
		}

		private static string ConnectionStateMsg(ConnectionState state)
		{
			switch (state)
			{
			case ConnectionState.Closed:
			case ConnectionState.Connecting | ConnectionState.Broken:
				return System.Data.OracleClient.Res.GetString("ADP_ConnectionStateMsg_Closed");
			case ConnectionState.Connecting:
				return System.Data.OracleClient.Res.GetString("ADP_ConnectionStateMsg_Connecting");
			case ConnectionState.Open:
				return System.Data.OracleClient.Res.GetString("ADP_ConnectionStateMsg_Open");
			case ConnectionState.Open | ConnectionState.Executing:
				return System.Data.OracleClient.Res.GetString("ADP_ConnectionStateMsg_OpenExecuting");
			case ConnectionState.Open | ConnectionState.Fetching:
				return System.Data.OracleClient.Res.GetString("ADP_ConnectionStateMsg_OpenFetching");
			default:
				return System.Data.OracleClient.Res.GetString("ADP_ConnectionStateMsg", state.ToString());
			}
		}

		internal static void CheckArgumentLength(string value, string parameterName)
		{
			CheckArgumentNull(value, parameterName);
			if (value.Length == 0)
			{
				throw Argument(System.Data.OracleClient.Res.GetString("ADP_EmptyString", parameterName));
			}
		}

		internal static bool CompareInsensitiveInvariant(string strvalue, string strconst)
		{
			return 0 == CultureInfo.InvariantCulture.CompareInfo.Compare(strvalue, strconst, CompareOptions.IgnoreCase);
		}

		internal static bool IsEmptyArray(string[] array)
		{
			if (array != null)
			{
				return 0 == array.Length;
			}
			return true;
		}

		internal static Exception CollectionNullValue(string parameter, Type collection, Type itemType)
		{
			return ArgumentNull(parameter, System.Data.OracleClient.Res.GetString("ADP_CollectionNullValue", collection.Name, itemType.Name));
		}

		internal static Exception CollectionIndexInt32(int index, Type collection, int count)
		{
			return IndexOutOfRange(System.Data.OracleClient.Res.GetString("ADP_CollectionIndexInt32", index.ToString(CultureInfo.InvariantCulture), collection.Name, count.ToString(CultureInfo.InvariantCulture)));
		}

		internal static Exception CollectionIndexString(Type itemType, string propertyName, string propertyValue, Type collection)
		{
			return IndexOutOfRange(System.Data.OracleClient.Res.GetString("ADP_CollectionIndexString", itemType.Name, propertyName, propertyValue, collection.Name));
		}

		internal static Exception CollectionInvalidType(Type collection, Type itemType, object invalidValue)
		{
			return InvalidCast(System.Data.OracleClient.Res.GetString("ADP_CollectionInvalidType", collection.Name, itemType.Name, invalidValue.GetType().Name));
		}

		internal static ArgumentException CollectionRemoveInvalidObject(Type itemType, ICollection collection)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_CollectionRemoveInvalidObject", itemType.Name, collection.GetType().Name));
		}

		internal static Exception ConnectionAlreadyOpen(ConnectionState state)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_ConnectionAlreadyOpen", ConnectionStateMsg(state)));
		}

		internal static ArgumentException ConnectionStringSyntax(int index)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_ConnectionStringSyntax", index));
		}

		internal static Exception InvalidDataDirectory()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_InvalidDataDirectory"));
		}

		internal static ArgumentException InvalidKeyname(string parameterName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidKey"), parameterName);
		}

		internal static ArgumentException InvalidValue(string parameterName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidValue"), parameterName);
		}

		internal static Exception DataReaderClosed(string method)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_DataReaderClosed", method));
		}

		internal static Exception InvalidXMLBadVersion()
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidXMLBadVersion"));
		}

		internal static Exception NotAPermissionElement()
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_NotAPermissionElement"));
		}

		internal static Exception PermissionTypeMismatch()
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_PermissionTypeMismatch"));
		}

		internal static Exception InternalConnectionError(ConnectionError internalError)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_InternalConnectionError", (int)internalError));
		}

		internal static Exception InternalError(InternalErrorCode internalError)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_InternalProviderError", (int)internalError));
		}

		internal static Exception InvalidConnectionOptionValue(string key, Exception inner)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidConnectionOptionValue", key), inner);
		}

		internal static Exception InvalidEnumerationValue(Type type, int value)
		{
			return ArgumentOutOfRange(System.Data.OracleClient.Res.GetString("ADP_InvalidEnumerationValue", type.Name, value.ToString(CultureInfo.InvariantCulture)), type.Name);
		}

		internal static Exception InvalidDataRowVersion(DataRowVersion value)
		{
			return InvalidEnumerationValue(typeof(DataRowVersion), (int)value);
		}

		internal static Exception InvalidKeyRestrictionBehavior(KeyRestrictionBehavior value)
		{
			return InvalidEnumerationValue(typeof(KeyRestrictionBehavior), (int)value);
		}

		internal static Exception InvalidOffsetValue(int value)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidOffsetValue", value.ToString(CultureInfo.InvariantCulture)));
		}

		internal static Exception InvalidParameterDirection(ParameterDirection value)
		{
			return InvalidEnumerationValue(typeof(ParameterDirection), (int)value);
		}

		internal static Exception InvalidParameterType(IDataParameterCollection collection, Type parameterType, object invalidValue)
		{
			return CollectionInvalidType(collection.GetType(), parameterType, invalidValue);
		}

		internal static Exception InvalidPermissionState(PermissionState value)
		{
			return InvalidEnumerationValue(typeof(PermissionState), (int)value);
		}

		internal static Exception InvalidUpdateRowSource(UpdateRowSource value)
		{
			return InvalidEnumerationValue(typeof(UpdateRowSource), (int)value);
		}

		internal static Exception MethodNotImplemented(string methodName)
		{
			NotImplementedException ex = new NotImplementedException(methodName);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static Exception NoConnectionString()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_NoConnectionString"));
		}

		internal static Exception ParameterNull(string parameter, IDataParameterCollection collection, Type parameterType)
		{
			return CollectionNullValue(parameter, collection.GetType(), parameterType);
		}

		internal static Exception ParametersIsNotParent(Type parameterType, IDataParameterCollection collection)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_CollectionIsNotParent", parameterType.Name, collection.GetType().Name));
		}

		internal static ArgumentException ParametersIsParent(Type parameterType, IDataParameterCollection collection)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_CollectionIsNotParent", parameterType.Name, collection.GetType().Name));
		}

		internal static Exception ParametersMappingIndex(int index, IDataParameterCollection collection)
		{
			return CollectionIndexInt32(index, collection.GetType(), collection.Count);
		}

		internal static Exception ParametersSourceIndex(string parameterName, IDataParameterCollection collection, Type parameterType)
		{
			return CollectionIndexString(parameterType, "ParameterName", parameterName, collection.GetType());
		}

		internal static Exception PooledOpenTimeout()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_PooledOpenTimeout"));
		}

		internal static Exception OpenConnectionPropertySet(string property, ConnectionState state)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_OpenConnectionPropertySet", property, ConnectionStateMsg(state)));
		}

		internal static Exception AmbigousCollectionName(string collectionName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_AmbigousCollectionName", collectionName));
		}

		internal static Exception CollectionNameIsNotUnique(string collectionName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_CollectionNameISNotUnique", collectionName));
		}

		internal static Exception DataTableDoesNotExist(string collectionName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_DataTableDoesNotExist", collectionName));
		}

		internal static Exception IncorrectNumberOfDataSourceInformationRows()
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_IncorrectNumberOfDataSourceInformationRows"));
		}

		internal static Exception InvalidXml()
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_InvalidXml"));
		}

		internal static Exception InvalidXmlMissingColumn(string collectionName, string columnName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_InvalidXmlMissingColumn", collectionName, columnName));
		}

		internal static Exception InvalidXmlInvalidValue(string collectionName, string columnName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_InvalidXmlInvalidValue", collectionName, columnName));
		}

		internal static Exception MissingDataSourceInformationColumn()
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_MissingDataSourceInformationColumn"));
		}

		internal static Exception MissingRestrictionColumn()
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_MissingRestrictionColumn"));
		}

		internal static Exception MissingRestrictionRow()
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_MissingRestrictionRow"));
		}

		internal static Exception NoColumns()
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_NoColumns"));
		}

		internal static Exception QueryFailed(string collectionName, Exception e)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("MDF_QueryFailed", collectionName), e);
		}

		internal static Exception TooManyRestrictions(string collectionName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_TooManyRestrictions", collectionName));
		}

		internal static Exception UndefinedCollection(string collectionName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_UndefinedCollection", collectionName));
		}

		internal static Exception UndefinedPopulationMechanism(string populationMechanism)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_UndefinedPopulationMechanism", populationMechanism));
		}

		internal static Exception UnsupportedVersion(string collectionName)
		{
			return Argument(System.Data.OracleClient.Res.GetString("MDF_UnsupportedVersion", collectionName));
		}

		private ADP()
		{
		}

		private static void TraceException(string trace, Exception e)
		{
			if (e != null)
			{
				Bid.Trace(trace, e.ToString());
			}
		}

		internal static Exception TraceException(Exception e)
		{
			TraceExceptionAsReturnValue(e);
			return e;
		}

		internal static void TraceExceptionAsReturnValue(Exception e)
		{
			TraceException("<oc|ERR|THROW> '%ls'\n", e);
		}

		internal static void TraceExceptionForCapture(Exception e)
		{
			TraceException("<comm.ADP.TraceException|ERR|CATCH> '%ls'\n", e);
		}

		internal static void TraceExceptionWithoutRethrow(Exception e)
		{
			TraceException("<oc|ERR|CATCH> '%ls'\n", e);
		}

		internal static ArgumentException Argument(string error)
		{
			ArgumentException ex = new ArgumentException(error);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static ArgumentException Argument(string error, string parameter)
		{
			ArgumentException ex = new ArgumentException(error, parameter);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static ArgumentException Argument(string error, Exception inner)
		{
			ArgumentException ex = new ArgumentException(error, inner);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static ArgumentNullException ArgumentNull(string parameter)
		{
			ArgumentNullException ex = new ArgumentNullException(parameter);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static ArgumentNullException ArgumentNull(string parameter, string error)
		{
			ArgumentNullException ex = new ArgumentNullException(parameter, error);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static ArgumentOutOfRangeException ArgumentOutOfRange(string argName, string message)
		{
			ArgumentOutOfRangeException ex = new ArgumentOutOfRangeException(argName, message);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static ConfigurationException Configuration(string message)
		{
			ConfigurationException ex = new ConfigurationErrorsException(message);
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static Exception ProviderException(string error)
		{
			return InvalidOperation(error);
		}

		internal static Exception IndexOutOfRange(string error)
		{
			return TraceException(new IndexOutOfRangeException(error));
		}

		internal static Exception InvalidCast()
		{
			return TraceException(new InvalidCastException());
		}

		internal static Exception InvalidCast(string error)
		{
			return TraceException(new InvalidCastException(error));
		}

		internal static Exception InvalidOperation(string error)
		{
			return TraceException(new InvalidOperationException(error));
		}

		internal static Exception InvalidOperation(string error, Exception inner)
		{
			return TraceException(new InvalidOperationException(error, inner));
		}

		internal static Exception NotSupported()
		{
			return TraceException(new NotSupportedException());
		}

		internal static Exception NotSupported(string message)
		{
			return TraceException(new NotSupportedException(message));
		}

		internal static Exception ObjectDisposed(string name)
		{
			return TraceException(new ObjectDisposedException(name));
		}

		internal static Exception OracleError(OciErrorHandle errorHandle, int rc)
		{
			return TraceException(OracleException.CreateException(errorHandle, rc));
		}

		internal static Exception OracleError(int rc, OracleInternalConnection internalConnection)
		{
			return TraceException(OracleException.CreateException(rc, internalConnection));
		}

		internal static Exception Overflow(string error)
		{
			return TraceException(new OverflowException(error));
		}

		internal static Exception Simple(string message)
		{
			return TraceException(new Exception(message));
		}

		internal static Exception BadBindValueType(Type valueType, OracleType oracleType)
		{
			return InvalidCast(System.Data.OracleClient.Res.GetString("ADP_BadBindValueType", valueType.ToString(), oracleType.ToString()));
		}

		internal static Exception UnsupportedOracleDateTimeBinding(OracleType dtType)
		{
			return ArgumentOutOfRange("", System.Data.OracleClient.Res.GetString("ADP_BadBindValueType", typeof(OracleDateTime).ToString(), dtType.ToString()));
		}

		internal static Exception BadOracleClientImageFormat(Exception e)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_BadOracleClientImageFormat"), e);
		}

		internal static Exception BadOracleClientVersion()
		{
			return Simple(System.Data.OracleClient.Res.GetString("ADP_BadOracleClientVersion"));
		}

		internal static Exception BufferExceeded(string argName)
		{
			return ArgumentOutOfRange(argName, System.Data.OracleClient.Res.GetString("ADP_BufferExceeded"));
		}

		internal static Exception CannotDeriveOverloaded()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_CannotDeriveOverloaded"));
		}

		internal static Exception CannotOpenLobWithDifferentMode(OracleLobOpenMode newmode, OracleLobOpenMode current)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_CannotOpenLobWithDifferentMode", newmode.ToString(), current.ToString()));
		}

		internal static Exception ChangeDatabaseNotSupported()
		{
			return NotSupported(System.Data.OracleClient.Res.GetString("ADP_ChangeDatabaseNotSupported"));
		}

		internal static Exception ClosedConnectionError()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_ClosedConnectionError"));
		}

		internal static Exception ClosedDataReaderError()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_ClosedDataReaderError"));
		}

		internal static Exception CommandTextRequired(string method)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_CommandTextRequired", method));
		}

		internal static ConfigurationException ConfigUnableToLoadXmlMetaDataFile(string settingName)
		{
			return Configuration(System.Data.OracleClient.Res.GetString("ADP_ConfigUnableToLoadXmlMetaDataFile", settingName));
		}

		internal static ConfigurationException ConfigWrongNumberOfValues(string settingName)
		{
			return Configuration(System.Data.OracleClient.Res.GetString("ADP_ConfigWrongNumberOfValues", settingName));
		}

		internal static Exception ConnectionRequired(string method)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_ConnectionRequired", method));
		}

		internal static Exception CouldNotCreateEnvironment(string methodname, int rc)
		{
			return Simple(System.Data.OracleClient.Res.GetString("ADP_CouldNotCreateEnvironment", methodname, rc.ToString(CultureInfo.CurrentCulture)));
		}

		internal static ArgumentException ConvertFailed(Type fromType, Type toType, Exception innerException)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_ConvertFailed", fromType.FullName, toType.FullName), innerException);
		}

		internal static Exception DataIsNull()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_DataIsNull"));
		}

		internal static Exception DataReaderNoData()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_DataReaderNoData"));
		}

		internal static Exception DeriveParametersNotSupported(IDbCommand value)
		{
			return ProviderException(System.Data.OracleClient.Res.GetString("ADP_DeriveParametersNotSupported", value.GetType().Name, value.CommandType.ToString()));
		}

		internal static Exception DistribTxRequiresOracle9i()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_DistribTxRequiresOracle9i"));
		}

		internal static Exception DistribTxRequiresOracleServicesForMTS(Exception inner)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_DistribTxRequiresOracleServicesForMTS"), inner);
		}

		internal static Exception IdentifierIsNotQuoted()
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_IdentifierIsNotQuoted"));
		}

		internal static Exception InputRefCursorNotSupported(string parameterName)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_InputRefCursorNotSupported", parameterName));
		}

		internal static Exception InvalidCommandType(CommandType cmdType)
		{
			object[] array = new object[1];
			int num = (int)cmdType;
			array[0] = num.ToString(CultureInfo.CurrentCulture);
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidCommandType", array));
		}

		internal static Exception InvalidConnectionOptionLength(string key, int maxLength)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidConnectionOptionLength", key, maxLength));
		}

		internal static Exception InvalidConnectionOptionValue(string key)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidConnectionOptionValue", key));
		}

		internal static Exception InvalidDataLength(long length)
		{
			return IndexOutOfRange(System.Data.OracleClient.Res.GetString("ADP_InvalidDataLength", length.ToString(CultureInfo.CurrentCulture)));
		}

		internal static Exception InvalidDataType(TypeCode tc)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidDataType", tc.ToString()));
		}

		internal static Exception InvalidDataTypeForValue(Type dataType, TypeCode tc)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidDataTypeForValue", dataType.ToString(), tc.ToString()));
		}

		internal static Exception InvalidDbType(DbType dbType)
		{
			return ArgumentOutOfRange("dbType", System.Data.OracleClient.Res.GetString("ADP_InvalidDbType", dbType.ToString()));
		}

		internal static Exception InvalidDestinationBufferIndex(int maxLen, int dstOffset, string parameterName)
		{
			return ArgumentOutOfRange(parameterName, System.Data.OracleClient.Res.GetString("ADP_InvalidDestinationBufferIndex", maxLen.ToString(CultureInfo.CurrentCulture), dstOffset.ToString(CultureInfo.CurrentCulture)));
		}

		internal static Exception InvalidLobType(OracleType oracleType)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_InvalidLobType", oracleType.ToString()));
		}

		internal static Exception InvalidMinMaxPoolSizeValues()
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidMinMaxPoolSizeValues"));
		}

		internal static Exception InvalidOracleType(OracleType oracleType)
		{
			return ArgumentOutOfRange("oracleType", System.Data.OracleClient.Res.GetString("ADP_InvalidOracleType", oracleType.ToString()));
		}

		internal static Exception InvalidSeekOrigin(SeekOrigin origin)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidSeekOrigin", origin.ToString()));
		}

		internal static Exception InvalidSizeValue(int value)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_InvalidSizeValue", value.ToString(CultureInfo.InvariantCulture)));
		}

		internal static ArgumentException KeywordNotSupported(string keyword)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_KeywordNotSupported", keyword));
		}

		internal static Exception InvalidSourceBufferIndex(int maxLen, long srcOffset, string parameterName)
		{
			return ArgumentOutOfRange(parameterName, System.Data.OracleClient.Res.GetString("ADP_InvalidSourceBufferIndex", maxLen.ToString(CultureInfo.CurrentCulture), srcOffset.ToString(CultureInfo.CurrentCulture)));
		}

		internal static Exception InvalidSourceOffset(string argName, long minValue, long maxValue)
		{
			return ArgumentOutOfRange(argName, System.Data.OracleClient.Res.GetString("ADP_InvalidSourceOffset", minValue.ToString(CultureInfo.CurrentCulture), maxValue.ToString(CultureInfo.CurrentCulture)));
		}

		internal static Exception LobAmountExceeded(string argName)
		{
			return ArgumentOutOfRange(argName, System.Data.OracleClient.Res.GetString("ADP_LobAmountExceeded"));
		}

		internal static Exception LobAmountMustBeEven(string argName)
		{
			return ArgumentOutOfRange(argName, System.Data.OracleClient.Res.GetString("ADP_LobAmountMustBeEven"));
		}

		internal static Exception LobPositionMustBeEven()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_LobPositionMustBeEven"));
		}

		internal static Exception LobWriteInvalidOnNull()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_LobWriteInvalidOnNull"));
		}

		internal static Exception LobWriteRequiresTransaction()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_LobWriteRequiresTransaction"));
		}

		internal static Exception MonthOutOfRange()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_MonthOutOfRange"));
		}

		internal static Exception MustBePositive(string argName)
		{
			return ArgumentOutOfRange(argName, System.Data.OracleClient.Res.GetString("ADP_MustBePositive"));
		}

		internal static Exception NoCommandText()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_NoCommandText"));
		}

		internal static Exception NoData()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_NoData"));
		}

		internal static Exception NoLocalTransactionInDistributedContext()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_NoLocalTransactionInDistributedContext"));
		}

		internal static Exception NoOptimizedDirectTableAccess()
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_NoOptimizedDirectTableAccess"));
		}

		internal static Exception NoParallelTransactions()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_NoParallelTransactions"));
		}

		internal static Exception OpenConnectionRequired(string method, ConnectionState state)
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_OpenConnectionRequired", method, "ConnectionState", state.ToString()));
		}

		internal static Exception OperationFailed(string method, int rc)
		{
			return Simple(System.Data.OracleClient.Res.GetString("ADP_OperationFailed", method, rc));
		}

		internal static Exception OperationResultedInOverflow()
		{
			return Overflow(System.Data.OracleClient.Res.GetString("ADP_OperationResultedInOverflow"));
		}

		internal static Exception ParameterConversionFailed(object value, Type destType, Exception inner)
		{
			string @string = System.Data.OracleClient.Res.GetString("ADP_ParameterConversionFailed", value.GetType().Name, destType.Name);
			Exception ex = ((inner is ArgumentException) ? new ArgumentException(@string, inner) : ((inner is FormatException) ? new FormatException(@string, inner) : ((inner is InvalidCastException) ? new InvalidCastException(@string, inner) : ((!(inner is OverflowException)) ? inner : new OverflowException(@string, inner)))));
			TraceExceptionAsReturnValue(ex);
			return ex;
		}

		internal static Exception ParameterSizeIsTooLarge(string parameterName)
		{
			return Simple(System.Data.OracleClient.Res.GetString("ADP_ParameterSizeIsTooLarge", parameterName));
		}

		internal static Exception ParameterSizeIsMissing(string parameterName, Type dataType)
		{
			return Simple(System.Data.OracleClient.Res.GetString("ADP_ParameterSizeIsMissing", parameterName, dataType.Name));
		}

		internal static Exception ReadOnlyLob()
		{
			return NotSupported(System.Data.OracleClient.Res.GetString("ADP_ReadOnlyLob"));
		}

		internal static Exception SeekBeyondEnd(string parameter)
		{
			return ArgumentOutOfRange(parameter, System.Data.OracleClient.Res.GetString("ADP_SeekBeyondEnd"));
		}

		internal static Exception SyntaxErrorExpectedCommaAfterColumn()
		{
			return TraceException(InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_SyntaxErrorExpectedCommaAfterColumn")));
		}

		internal static Exception SyntaxErrorExpectedCommaAfterTable()
		{
			return TraceException(InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_SyntaxErrorExpectedCommaAfterTable")));
		}

		internal static Exception SyntaxErrorExpectedIdentifier()
		{
			return TraceException(InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_SyntaxErrorExpectedIdentifier")));
		}

		internal static Exception SyntaxErrorExpectedNextPart()
		{
			return TraceException(InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_SyntaxErrorExpectedNextPart")));
		}

		internal static Exception SyntaxErrorMissingParenthesis()
		{
			return TraceException(InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_SyntaxErrorMissingParenthesis")));
		}

		internal static Exception SyntaxErrorTooManyNameParts()
		{
			return TraceException(InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_SyntaxErrorTooManyNameParts")));
		}

		internal static Exception TransactionCompleted()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_TransactionCompleted"));
		}

		internal static Exception TransactionConnectionMismatch()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_TransactionConnectionMismatch"));
		}

		internal static Exception TransactionPresent()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_TransactionPresent"));
		}

		internal static Exception TransactionRequired()
		{
			return InvalidOperation(System.Data.OracleClient.Res.GetString("ADP_TransactionRequired_Execute"));
		}

		internal static Exception TypeNotSupported(OCI.DATATYPE ociType)
		{
			return NotSupported(System.Data.OracleClient.Res.GetString("ADP_TypeNotSupported", ociType.ToString()));
		}

		internal static Exception UnknownDataTypeCode(Type dataType, TypeCode tc)
		{
			return Simple(System.Data.OracleClient.Res.GetString("ADP_UnknownDataTypeCode", dataType.ToString(), tc.ToString()));
		}

		internal static Exception UnsupportedIsolationLevel()
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_UnsupportedIsolationLevel"));
		}

		internal static Exception WriteByteForBinaryLobsOnly()
		{
			return NotSupported(System.Data.OracleClient.Res.GetString("ADP_WriteByteForBinaryLobsOnly"));
		}

		internal static Exception WrongType(Type got, Type expected)
		{
			return Argument(System.Data.OracleClient.Res.GetString("ADP_WrongType", got.ToString(), expected.ToString()));
		}

		public static void CheckArgumentNull(object value, string parameterName)
		{
			if (value == null)
			{
				throw ArgumentNull(parameterName);
			}
		}

		internal static bool IsCatchableExceptionType(Exception e)
		{
			Type type = e.GetType();
			if (type != StackOverflowType && type != OutOfMemoryType && type != ThreadAbortType && type != NullReferenceType && type != AccessViolationType)
			{
				return !SecurityType.IsAssignableFrom(type);
			}
			return false;
		}

		internal static Delegate FindBuilder(MulticastDelegate mcd)
		{
			if ((object)mcd != null)
			{
				Delegate[] invocationList = mcd.GetInvocationList();
				for (int i = 0; i < invocationList.Length; i++)
				{
					if (invocationList[i].Target is DbCommandBuilder)
					{
						return invocationList[i];
					}
				}
			}
			return null;
		}

		internal static IntPtr IntPtrOffset(IntPtr pbase, int offset)
		{
			if (4 == PtrSize)
			{
				return (IntPtr)(pbase.ToInt32() + offset);
			}
			return (IntPtr)(pbase.ToInt64() + offset);
		}

		internal static bool IsDirection(IDataParameter value, ParameterDirection condition)
		{
			return condition == (condition & value.Direction);
		}

		internal static bool IsDirection(ParameterDirection value, ParameterDirection condition)
		{
			return condition == (condition & value);
		}

		internal static bool IsEmpty(string str)
		{
			if (str != null)
			{
				return 0 == str.Length;
			}
			return true;
		}

		internal static bool IsNull(object value)
		{
			if (value == null || DBNull.Value == value)
			{
				return true;
			}
			if (value is INullable nullable)
			{
				return nullable.IsNull;
			}
			return false;
		}

		internal static Transaction GetCurrentTransaction()
		{
			return Transaction.Current;
		}

		internal static IDtcTransaction GetOletxTransaction(Transaction transaction)
		{
			IDtcTransaction result = null;
			if (null != transaction)
			{
				result = TransactionInterop.GetDtcTransaction(transaction);
			}
			return result;
		}

		[FileIOPermission(SecurityAction.Assert, AllFiles = FileIOPermissionAccess.PathDiscovery)]
		internal static string GetFullPath(string filename)
		{
			return Path.GetFullPath(filename);
		}

		internal static Stream GetFileStream(string filename)
		{
			new FileIOPermission(FileIOPermissionAccess.Read, filename).Assert();
			try
			{
				return new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
			}
			finally
			{
				CodeAccessPermission.RevertAssert();
			}
		}

		internal static Stream GetXmlStreamFromValues(string[] values, string errorString)
		{
			if (values.Length != 1)
			{
				throw ConfigWrongNumberOfValues(errorString);
			}
			return GetXmlStream(values[0], errorString);
		}

		internal static Stream GetXmlStream(string value, string errorString)
		{
			//Discarded unreachable code: IL_0083
			string runtimeDirectory = RuntimeEnvironment.GetRuntimeDirectory();
			if (runtimeDirectory == null)
			{
				throw ConfigUnableToLoadXmlMetaDataFile(errorString);
			}
			StringBuilder stringBuilder = new StringBuilder(runtimeDirectory.Length + "config\\".Length + value.Length);
			stringBuilder.Append(runtimeDirectory);
			stringBuilder.Append("config\\");
			stringBuilder.Append(value);
			string text = stringBuilder.ToString();
			if (GetFullPath(text) != text)
			{
				throw ConfigUnableToLoadXmlMetaDataFile(errorString);
			}
			try
			{
				return GetFileStream(text);
			}
			catch (Exception e)
			{
				if (!IsCatchableExceptionType(e))
				{
					throw;
				}
				throw ConfigUnableToLoadXmlMetaDataFile(errorString);
			}
		}
	}
}
namespace System.Data.OracleClient
{
	internal sealed class MetaType
	{
		internal const int LongMax = int.MaxValue;

		private const string N_BFILE = "BFILE";

		private const string N_BLOB = "BLOB";

		private const string N_CHAR = "CHAR";

		private const string N_CLOB = "CLOB";

		private const string N_DATE = "DATE";

		private const string N_FLOAT = "FLOAT";

		private const string N_INTEGER = "INTEGER";

		private const string N_INTERVALYM = "INTERVAL YEAR TO MONTH";

		private const string N_INTERVALDS = "INTERVAL DAY TO SECOND";

		private const string N_LONG = "LONG";

		private const string N_LONGRAW = "LONG RAW";

		private const string N_NCHAR = "NCHAR";

		private const string N_NCLOB = "NCLOB";

		private const string N_NUMBER = "NUMBER";

		private const string N_NVARCHAR2 = "NVARCHAR2";

		private const string N_RAW = "RAW";

		private const string N_REFCURSOR = "REF CURSOR";

		private const string N_ROWID = "ROWID";

		private const string N_TIMESTAMP = "TIMESTAMP";

		private const string N_TIMESTAMPLTZ = "TIMESTAMP WITH LOCAL TIME ZONE";

		private const string N_TIMESTAMPTZ = "TIMESTAMP WITH TIME ZONE";

		private const string N_UNSIGNEDINT = "UNSIGNED INTEGER";

		private const string N_VARCHAR2 = "VARCHAR2";

		private static readonly MetaType[] dbTypeMetaType;

		private static readonly MetaType[] oracleTypeMetaType;

		internal static readonly MetaType oracleTypeMetaType_LONGVARCHAR;

		internal static readonly MetaType oracleTypeMetaType_LONGVARRAW;

		internal static readonly MetaType oracleTypeMetaType_LONGNVARCHAR;

		private readonly DbType _dbType;

		private readonly OracleType _oracleType;

		private readonly OCI.DATATYPE _ociType;

		private readonly Type _convertToType;

		private readonly Type _noConvertType;

		private readonly int _bindSize;

		private readonly int _maxBindSize;

		private readonly string _dataTypeName;

		private readonly bool _isCharacterType;

		private readonly bool _isLob;

		private readonly bool _isLong;

		private readonly bool _usesNationalCharacterSet;

		internal Type BaseType => _convertToType;

		internal int BindSize => _bindSize;

		internal string DataTypeName => _dataTypeName;

		internal DbType DbType => _dbType;

		internal bool IsCharacterType => _isCharacterType;

		internal bool IsLob => _isLob;

		internal bool IsLong => _isLong;

		internal bool IsVariableLength
		{
			get
			{
				if (_bindSize != 0)
				{
					return int.MaxValue == _bindSize;
				}
				return true;
			}
		}

		internal int MaxBindSize => _maxBindSize;

		internal Type NoConvertType => _noConvertType;

		internal OCI.DATATYPE OciType => _ociType;

		internal OracleType OracleType => _oracleType;

		internal bool UsesNationalCharacterSet => _usesNationalCharacterSet;

		static MetaType()
		{
			dbTypeMetaType = new MetaType[24];
			dbTypeMetaType[0] = new MetaType(DbType.AnsiString, OracleType.VarChar, OCI.DATATYPE.VARCHAR2, "VARCHAR2", typeof(string), typeof(OracleString), 0, 4000, usesNationalCharacterSet: false);
			dbTypeMetaType[1] = new MetaType(DbType.Binary, OracleType.Raw, OCI.DATATYPE.RAW, "RAW", typeof(byte[]), typeof(OracleBinary), 0, 2000, usesNationalCharacterSet: false);
			dbTypeMetaType[2] = new MetaType(DbType.Byte, OracleType.Byte, OCI.DATATYPE.UNSIGNEDINT, "UNSIGNED INTEGER", typeof(byte), typeof(byte), 1, 1, usesNationalCharacterSet: false);
			dbTypeMetaType[3] = new MetaType(DbType.Boolean, OracleType.Byte, OCI.DATATYPE.UNSIGNEDINT, "UNSIGNED INTEGER", typeof(byte), typeof(byte), 1, 1, usesNationalCharacterSet: false);
			dbTypeMetaType[4] = new MetaType(DbType.Currency, OracleType.Number, OCI.DATATYPE.VARNUM, "NUMBER", typeof(decimal), typeof(OracleNumber), 22, 22, usesNationalCharacterSet: false);
			dbTypeMetaType[5] = new MetaType(DbType.Date, OracleType.DateTime, OCI.DATATYPE.DATE, "DATE", typeof(DateTime), typeof(OracleDateTime), 7, 7, usesNationalCharacterSet: false);
			dbTypeMetaType[6] = new MetaType(DbType.DateTime, OracleType.DateTime, OCI.DATATYPE.DATE, "DATE", typeof(DateTime), typeof(OracleDateTime), 7, 7, usesNationalCharacterSet: false);
			dbTypeMetaType[7] = new MetaType(DbType.Decimal, OracleType.Number, OCI.DATATYPE.VARNUM, "NUMBER", typeof(decimal), typeof(OracleNumber), 22, 22, usesNationalCharacterSet: false);
			dbTypeMetaType[8] = new MetaType(DbType.Double, OracleType.Double, OCI.DATATYPE.FLOAT, "FLOAT", typeof(double), typeof(double), 8, 8, usesNationalCharacterSet: false);
			dbTypeMetaType[9] = new MetaType(DbType.Guid, OracleType.Raw, OCI.DATATYPE.RAW, "RAW", typeof(byte[]), typeof(OracleBinary), 16, 16, usesNationalCharacterSet: false);
			dbTypeMetaType[10] = new MetaType(DbType.Int16, OracleType.Int16, OCI.DATATYPE.INTEGER, "INTEGER", typeof(short), typeof(short), 2, 2, usesNationalCharacterSet: false);
			dbTypeMetaType[11] = new MetaType(DbType.Int32, OracleType.Int32, OCI.DATATYPE.INTEGER, "INTEGER", typeof(int), typeof(int), 4, 4, usesNationalCharacterSet: false);
			dbTypeMetaType[12] = new MetaType(DbType.Int64, OracleType.Number, OCI.DATATYPE.VARNUM, "NUMBER", typeof(decimal), typeof(OracleNumber), 22, 22, usesNationalCharacterSet: false);
			dbTypeMetaType[13] = new MetaType(DbType.Object, OracleType.Blob, OCI.DATATYPE.BLOB, "BLOB", typeof(object), typeof(OracleLob), IntPtr.Size, IntPtr.Size, usesNationalCharacterSet: false);
			dbTypeMetaType[14] = new MetaType(DbType.SByte, OracleType.SByte, OCI.DATATYPE.INTEGER, "INTEGER", typeof(sbyte), typeof(sbyte), 1, 1, usesNationalCharacterSet: false);
			dbTypeMetaType[15] = new MetaType(DbType.Single, OracleType.Float, OCI.DATATYPE.FLOAT, "FLOAT", typeof(float), typeof(float), 4, 4, usesNationalCharacterSet: false);
			dbTypeMetaType[16] = new MetaType(DbType.String, OracleType.NVarChar, OCI.DATATYPE.VARCHAR2, "NVARCHAR2", typeof(string), typeof(OracleString), 0, 4000, usesNationalCharacterSet: true);
			dbTypeMetaType[17] = new MetaType(DbType.Time, OracleType.DateTime, OCI.DATATYPE.DATE, "DATE", typeof(DateTime), typeof(OracleDateTime), 7, 7, usesNationalCharacterSet: false);
			dbTypeMetaType[18] = new MetaType(DbType.UInt16, OracleType.UInt16, OCI.DATATYPE.UNSIGNEDINT, "UNSIGNED INTEGER", typeof(ushort), typeof(ushort), 2, 2, usesNationalCharacterSet: false);
			dbTypeMetaType[19] = new MetaType(DbType.UInt32, OracleType.UInt32, OCI.DATATYPE.UNSIGNEDINT, "UNSIGNED INTEGER", typeof(uint), typeof(uint), 4, 4, usesNationalCharacterSet: false);
			dbTypeMetaType[20] = new MetaType(DbType.UInt64, OracleType.Number, OCI.DATATYPE.VARNUM, "NUMBER", typeof(decimal), typeof(OracleNumber), 22, 22, usesNationalCharacterSet: false);
			dbTypeMetaType[21] = new MetaType(DbType.VarNumeric, OracleType.Number, OCI.DATATYPE.VARNUM, "NUMBER", typeof(decimal), typeof(OracleNumber), 22, 22, usesNationalCharacterSet: false);
			dbTypeMetaType[22] = new MetaType(DbType.AnsiStringFixedLength, OracleType.Char, OCI.DATATYPE.CHAR, "CHAR", typeof(string), typeof(OracleString), 0, 2000, usesNationalCharacterSet: false);
			dbTypeMetaType[23] = new MetaType(DbType.StringFixedLength, OracleType.NChar, OCI.DATATYPE.CHAR, "NCHAR", typeof(string), typeof(OracleString), 0, 2000, usesNationalCharacterSet: true);
			oracleTypeMetaType = new MetaType[31];
			oracleTypeMetaType[1] = new MetaType(DbType.Binary, OracleType.BFile, OCI.DATATYPE.BFILE, "BFILE", typeof(byte[]), typeof(OracleBFile), IntPtr.Size, IntPtr.Size, usesNationalCharacterSet: false);
			oracleTypeMetaType[2] = new MetaType(DbType.Binary, OracleType.Blob, OCI.DATATYPE.BLOB, "BLOB", typeof(byte[]), typeof(OracleLob), IntPtr.Size, IntPtr.Size, usesNationalCharacterSet: false);
			oracleTypeMetaType[3] = dbTypeMetaType[22];
			oracleTypeMetaType[4] = new MetaType(DbType.AnsiString, OracleType.Clob, OCI.DATATYPE.CLOB, "CLOB", typeof(string), typeof(OracleLob), IntPtr.Size, IntPtr.Size, usesNationalCharacterSet: false);
			oracleTypeMetaType[5] = new MetaType(DbType.Object, OracleType.Cursor, OCI.DATATYPE.RSET, "REF CURSOR", typeof(object), typeof(object), IntPtr.Size, IntPtr.Size, usesNationalCharacterSet: false);
			oracleTypeMetaType[6] = dbTypeMetaType[6];
			oracleTypeMetaType[8] = new MetaType(DbType.Int32, OracleType.IntervalYearToMonth, OCI.DATATYPE.INT_INTERVAL_YM, "INTERVAL YEAR TO MONTH", typeof(int), typeof(OracleMonthSpan), 5, 5, usesNationalCharacterSet: false);
			oracleTypeMetaType[7] = new MetaType(DbType.Object, OracleType.IntervalDayToSecond, OCI.DATATYPE.INT_INTERVAL_DS, "INTERVAL DAY TO SECOND", typeof(TimeSpan), typeof(OracleTimeSpan), 11, 11, usesNationalCharacterSet: false);
			oracleTypeMetaType[9] = new MetaType(DbType.Binary, OracleType.LongRaw, OCI.DATATYPE.LONGRAW, "LONG RAW", typeof(byte[]), typeof(OracleBinary), int.MaxValue, 32700, usesNationalCharacterSet: false);
			oracleTypeMetaType[10] = new MetaType(DbType.AnsiString, OracleType.LongVarChar, OCI.DATATYPE.LONG, "LONG", typeof(string), typeof(OracleString), int.MaxValue, 32700, usesNationalCharacterSet: false);
			oracleTypeMetaType[11] = dbTypeMetaType[23];
			oracleTypeMetaType[12] = new MetaType(DbType.String, OracleType.NClob, OCI.DATATYPE.CLOB, "NCLOB", typeof(string), typeof(OracleLob), IntPtr.Size, IntPtr.Size, usesNationalCharacterSet: true);
			oracleTypeMetaType[13] = dbTypeMetaType[21];
			oracleTypeMetaType[14] = dbTypeMetaType[16];
			oracleTypeMetaType[15] = dbTypeMetaType[1];
			oracleTypeMetaType[16] = new MetaType(DbType.AnsiString, OracleType.RowId, OCI.DATATYPE.VARCHAR2, "ROWID", typeof(string), typeof(OracleString), 3950, 3950, usesNationalCharacterSet: false);
			oracleTypeMetaType[18] = new MetaType(DbType.DateTime, OracleType.Timestamp, OCI.DATATYPE.INT_TIMESTAMP, "TIMESTAMP", typeof(DateTime), typeof(OracleDateTime), 11, 11, usesNationalCharacterSet: false);
			oracleTypeMetaType[19] = new MetaType(DbType.DateTime, OracleType.TimestampLocal, OCI.DATATYPE.INT_TIMESTAMP_LTZ, "TIMESTAMP WITH LOCAL TIME ZONE", typeof(DateTime), typeof(OracleDateTime), 11, 11, usesNationalCharacterSet: false);
			oracleTypeMetaType[20] = new MetaType(DbType.DateTime, OracleType.TimestampWithTZ, OCI.DATATYPE.INT_TIMESTAMP_TZ, "TIMESTAMP WITH TIME ZONE", typeof(DateTime), typeof(OracleDateTime), 13, 13, usesNationalCharacterSet: false);
			oracleTypeMetaType[22] = dbTypeMetaType[0];
			oracleTypeMetaType[23] = dbTypeMetaType[2];
			oracleTypeMetaType[24] = dbTypeMetaType[18];
			oracleTypeMetaType[25] = dbTypeMetaType[19];
			oracleTypeMetaType[26] = dbTypeMetaType[14];
			oracleTypeMetaType[27] = dbTypeMetaType[10];
			oracleTypeMetaType[28] = dbTypeMetaType[11];
			oracleTypeMetaType[29] = dbTypeMetaType[15];
			oracleTypeMetaType[30] = dbTypeMetaType[8];
			oracleTypeMetaType_LONGVARCHAR = new MetaType(DbType.AnsiString, OracleType.VarChar, OCI.DATATYPE.LONGVARCHAR, "VARCHAR2", typeof(string), typeof(OracleString), 0, int.MaxValue, usesNationalCharacterSet: false);
			oracleTypeMetaType_LONGVARRAW = new MetaType(DbType.Binary, OracleType.Raw, OCI.DATATYPE.LONGVARRAW, "RAW", typeof(byte[]), typeof(OracleBinary), 0, int.MaxValue, usesNationalCharacterSet: false);
			oracleTypeMetaType_LONGNVARCHAR = new MetaType(DbType.String, OracleType.NVarChar, OCI.DATATYPE.LONGVARCHAR, "NVARCHAR2", typeof(string), typeof(OracleString), 0, int.MaxValue, usesNationalCharacterSet: true);
		}

		public MetaType(DbType dbType, OracleType oracleType, OCI.DATATYPE ociType, string dataTypeName, Type convertToType, Type noConvertType, int bindSize, int maxBindSize, bool usesNationalCharacterSet)
		{
			_dbType = dbType;
			_oracleType = oracleType;
			_ociType = ociType;
			_convertToType = convertToType;
			_noConvertType = noConvertType;
			_bindSize = bindSize;
			_maxBindSize = maxBindSize;
			_dataTypeName = dataTypeName;
			_usesNationalCharacterSet = usesNationalCharacterSet;
			switch (oracleType)
			{
			case OracleType.Char:
			case OracleType.Clob:
			case OracleType.LongVarChar:
			case OracleType.NChar:
			case OracleType.NClob:
			case OracleType.NVarChar:
			case OracleType.VarChar:
				_isCharacterType = true;
				break;
			}
			switch (oracleType)
			{
			case OracleType.LongRaw:
			case OracleType.LongVarChar:
				_isLong = true;
				break;
			}
			switch (oracleType)
			{
			case OracleType.BFile:
			case OracleType.Blob:
			case OracleType.Clob:
			case OracleType.NClob:
				_isLob = true;
				break;
			}
		}

		internal static MetaType GetDefaultMetaType()
		{
			return dbTypeMetaType[0];
		}

		internal static MetaType GetMetaTypeForObject(object value)
		{
			Type type = ((!(value is Type)) ? value.GetType() : ((Type)value));
			switch (Type.GetTypeCode(type))
			{
			case TypeCode.Empty:
				throw System.Data.Common.ADP.InvalidDataType(TypeCode.Empty);
			case TypeCode.DBNull:
				throw System.Data.Common.ADP.InvalidDataType(TypeCode.DBNull);
			case TypeCode.Boolean:
				return dbTypeMetaType[3];
			case TypeCode.Char:
				return dbTypeMetaType[2];
			case TypeCode.SByte:
				return dbTypeMetaType[14];
			case TypeCode.Byte:
				return dbTypeMetaType[2];
			case TypeCode.Int16:
				return dbTypeMetaType[10];
			case TypeCode.UInt16:
				return dbTypeMetaType[18];
			case TypeCode.Int32:
				return dbTypeMetaType[11];
			case TypeCode.UInt32:
				return dbTypeMetaType[19];
			case TypeCode.Int64:
				return dbTypeMetaType[12];
			case TypeCode.UInt64:
				return dbTypeMetaType[20];
			case TypeCode.Single:
				return dbTypeMetaType[15];
			case TypeCode.Double:
				return dbTypeMetaType[8];
			case TypeCode.Decimal:
				return dbTypeMetaType[7];
			case TypeCode.DateTime:
				return dbTypeMetaType[6];
			case TypeCode.String:
				return dbTypeMetaType[0];
			case TypeCode.Object:
				if (type == typeof(byte[]))
				{
					return dbTypeMetaType[1];
				}
				if (type == typeof(Guid))
				{
					return dbTypeMetaType[9];
				}
				if (type == typeof(object))
				{
					throw System.Data.Common.ADP.InvalidDataTypeForValue(type, Type.GetTypeCode(type));
				}
				if (type == typeof(OracleBFile))
				{
					return oracleTypeMetaType[1];
				}
				if (type == typeof(OracleBinary))
				{
					return oracleTypeMetaType[15];
				}
				if (type == typeof(OracleDateTime))
				{
					return oracleTypeMetaType[6];
				}
				if (type == typeof(OracleNumber))
				{
					return oracleTypeMetaType[13];
				}
				if (type == typeof(OracleString))
				{
					return oracleTypeMetaType[22];
				}
				if (type == typeof(OracleLob))
				{
					OracleLob oracleLob = (OracleLob)value;
					switch (oracleLob.LobType)
					{
					case OracleType.Blob:
						return oracleTypeMetaType[2];
					case OracleType.Clob:
						return oracleTypeMetaType[4];
					case OracleType.NClob:
						return oracleTypeMetaType[12];
					}
				}
				throw System.Data.Common.ADP.UnknownDataTypeCode(type, Type.GetTypeCode(type));
			default:
				throw System.Data.Common.ADP.UnknownDataTypeCode(type, Type.GetTypeCode(type));
			}
		}

		internal static MetaType GetMetaTypeForType(DbType dbType)
		{
			if (dbType < DbType.AnsiString || dbType > DbType.StringFixedLength)
			{
				throw System.Data.Common.ADP.InvalidDbType(dbType);
			}
			return dbTypeMetaType[(int)dbType];
		}

		internal static MetaType GetMetaTypeForType(OracleType oracleType)
		{
			if (oracleType < OracleType.BFile || oracleType - 1 > OracleType.Double)
			{
				throw System.Data.Common.ADP.InvalidOracleType(oracleType);
			}
			return oracleTypeMetaType[(int)oracleType];
		}
	}
}
namespace System.Data.ProviderBase
{
	internal abstract class DbBuffer : SafeHandle
	{
		internal const int LMEM_FIXED = 0;

		internal const int LMEM_MOVEABLE = 2;

		internal const int LMEM_ZEROINIT = 64;

		private readonly int _bufferLength;

		private int _baseOffset;

		protected int BaseOffset
		{
			get
			{
				return _baseOffset;
			}
			set
			{
				_baseOffset = value;
			}
		}

		public override bool IsInvalid => IntPtr.Zero == handle;

		internal int Length => _bufferLength;

		protected DbBuffer(int initialSize, bool zeroBuffer)
			: base(IntPtr.Zero, ownsHandle: true)
		{
			if (0 < initialSize)
			{
				int flags = (zeroBuffer ? 64 : 0);
				_bufferLength = initialSize;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					handle = System.Data.Common.SafeNativeMethods.LocalAlloc(flags, (IntPtr)initialSize);
				}
				if (IntPtr.Zero == handle)
				{
					throw new OutOfMemoryException();
				}
			}
		}

		protected DbBuffer(int initialSize)
			: this(initialSize, zeroBuffer: true)
		{
		}

		internal string PtrToStringUni(int offset)
		{
			offset += BaseOffset;
			Validate(offset, 2);
			string text = null;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				int num = System.Data.Common.UnsafeNativeMethods.lstrlenW(ptr);
				Validate(offset, 2 * (num + 1));
				return Marshal.PtrToStringUni(ptr, num);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal string PtrToStringUni(int offset, int length)
		{
			offset += BaseOffset;
			Validate(offset, 2 * length);
			string text = null;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				return Marshal.PtrToStringUni(ptr, length);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal byte[] ReadBytes(int offset, int length)
		{
			byte[] destination = new byte[length];
			return ReadBytes(offset, destination, 0, length);
		}

		internal byte[] ReadBytes(int offset, byte[] destination, int startIndex, int length)
		{
			offset += BaseOffset;
			Validate(offset, length);
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr source = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				Marshal.Copy(source, destination, startIndex, length);
				return destination;
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal short ReadInt16(int offset)
		{
			offset += BaseOffset;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = DangerousGetHandle();
				return Marshal.ReadInt16(ptr, offset);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal int ReadInt32(int offset)
		{
			offset += BaseOffset;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = DangerousGetHandle();
				return Marshal.ReadInt32(ptr, offset);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal IntPtr ReadIntPtr(int offset)
		{
			offset += BaseOffset;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = DangerousGetHandle();
				return Marshal.ReadIntPtr(ptr, offset);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		protected override bool ReleaseHandle()
		{
			IntPtr intPtr = handle;
			handle = IntPtr.Zero;
			if (IntPtr.Zero != intPtr)
			{
				System.Data.Common.SafeNativeMethods.LocalFree(intPtr);
			}
			return true;
		}

		internal void StructureToPtr(int offset, object structure)
		{
			offset += BaseOffset;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				Marshal.StructureToPtr(structure, ptr, fDeleteOld: false);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal void WriteBytes(int offset, byte[] source, int startIndex, int length)
		{
			offset += BaseOffset;
			Validate(offset, length);
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr destination = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				Marshal.Copy(source, startIndex, destination, length);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal void WriteInt16(int offset, short value)
		{
			offset += BaseOffset;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = DangerousGetHandle();
				Marshal.WriteInt16(ptr, offset, value);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal void WriteInt32(int offset, int value)
		{
			offset += BaseOffset;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = DangerousGetHandle();
				Marshal.WriteInt32(ptr, offset, value);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal void WriteIntPtr(int offset, IntPtr value)
		{
			offset += BaseOffset;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = DangerousGetHandle();
				Marshal.WriteIntPtr(ptr, offset, value);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		[Conditional("DEBUG")]
		protected void ValidateCheck(int offset, int count)
		{
			Validate(offset, count);
		}

		protected void Validate(int offset, int count)
		{
			if (offset < 0 || count < 0 || Length < checked(offset + count))
			{
				throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidBuffer);
			}
		}
	}
}
namespace System.Data.OracleClient
{
	internal class NativeBuffer : System.Data.ProviderBase.DbBuffer
	{
		public NativeBuffer(int initialSize, bool zeroBuffer)
			: base(initialSize, zeroBuffer)
		{
		}

		public NativeBuffer(int initialSize)
			: base(initialSize, zeroBuffer: false)
		{
		}

		internal IntPtr DangerousGetDataPtr()
		{
			return DangerousGetHandle();
		}

		internal IntPtr DangerousGetDataPtr(int offset)
		{
			return System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
		}

		internal IntPtr DangerousGetDataPtrWithBaseOffset(int offset)
		{
			return System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset + base.BaseOffset);
		}

		internal static IntPtr HandleValueToTrace(NativeBuffer buffer)
		{
			return buffer.DangerousGetHandle();
		}

		internal string PtrToStringAnsi(int offset)
		{
			offset += base.BaseOffset;
			Validate(offset, 1);
			string text = null;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				int num = System.Data.Common.UnsafeNativeMethods.lstrlenA(ptr);
				text = Marshal.PtrToStringAnsi(ptr, num);
				Validate(offset, num + 1);
				return text;
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal string PtrToStringAnsi(int offset, int length)
		{
			offset += base.BaseOffset;
			Validate(offset, length);
			string text = null;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				return Marshal.PtrToStringAnsi(ptr, length);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal object PtrToStructure(int offset, Type oftype)
		{
			offset += base.BaseOffset;
			object obj = null;
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				IntPtr ptr = System.Data.Common.ADP.IntPtrOffset(DangerousGetHandle(), offset);
				return Marshal.PtrToStructure(ptr, oftype);
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}

		internal static void SafeDispose(ref NativeBuffer_LongColumnData handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}
	}
	internal sealed class NativeBuffer_Exception : NativeBuffer
	{
		internal NativeBuffer_Exception(int initialSize)
			: base(initialSize)
		{
		}
	}
	internal sealed class NativeBuffer_LongColumnData : NativeBuffer
	{
		private const int ChunkIsFree = -2;

		private const int ChunkToBeFilled = -1;

		private IntPtr _currentChunk = IntPtr.Zero;

		private int _chunkCount;

		private static readonly int AllocationSize = 8184;

		private static readonly int ReservedSize = 2 * IntPtr.Size;

		internal static readonly int MaxChunkSize = AllocationSize - ReservedSize;

		private static readonly int LengthOrIndicatorOffset = IntPtr.Size;

		private static readonly OutOfMemoryException OutOfMemory = new OutOfMemoryException();

		internal int TotalLengthInBytes
		{
			get
			{
				IntPtr intPtr = handle;
				int num = 0;
				for (int i = 0; i < _chunkCount; i++)
				{
					intPtr = Marshal.ReadIntPtr(intPtr);
					if (intPtr == IntPtr.Zero)
					{
						throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidLongBuffer);
					}
					int num2 = Marshal.ReadInt32(intPtr, LengthOrIndicatorOffset);
					if (num2 <= 0)
					{
						throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidLongBuffer);
					}
					if (num2 > MaxChunkSize)
					{
						throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidLongBuffer);
					}
					num = checked(num + num2);
				}
				return num;
			}
		}

		internal NativeBuffer_LongColumnData()
			: base(ReservedSize)
		{
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
			}
			finally
			{
				_currentChunk = handle;
				Marshal.WriteIntPtr(_currentChunk, 0, IntPtr.Zero);
				Marshal.WriteInt32(_currentChunk, LengthOrIndicatorOffset, -2);
			}
		}

		internal static void CopyOutOfLineBytes(IntPtr longBuffer, int cbSourceOffset, byte[] destinationBuffer, int cbDestinationOffset, int cbCount)
		{
			if (IntPtr.Zero == longBuffer)
			{
				throw System.Data.Common.ADP.ArgumentNull("longBuffer");
			}
			int num = 0;
			int num2 = cbCount;
			while (num2 > 0)
			{
				longBuffer = Marshal.ReadIntPtr(longBuffer);
				if (IntPtr.Zero == longBuffer)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidLongBuffer);
				}
				int num3 = Marshal.ReadInt32(longBuffer, LengthOrIndicatorOffset);
				if (num3 <= 0 || num3 > MaxChunkSize)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidLongBuffer);
				}
				int num4 = cbSourceOffset - num;
				if (num4 < num3)
				{
					int num5 = Math.Min(num2, num + num3 - cbSourceOffset);
					Marshal.Copy(System.Data.Common.ADP.IntPtrOffset(longBuffer, num4 + ReservedSize), destinationBuffer, cbDestinationOffset, num5);
					cbSourceOffset += num5;
					cbDestinationOffset += num5;
					num2 -= num5;
				}
				num += num3;
			}
		}

		internal static void CopyOutOfLineChars(IntPtr longBuffer, int cchSourceOffset, char[] destinationBuffer, int cchDestinationOffset, int cchCount)
		{
			if (IntPtr.Zero == longBuffer)
			{
				throw System.Data.Common.ADP.ArgumentNull("longBuffer");
			}
			int num = 0;
			int num2 = cchCount;
			while (num2 > 0)
			{
				longBuffer = Marshal.ReadIntPtr(longBuffer);
				if (IntPtr.Zero == longBuffer)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidLongBuffer);
				}
				int num3 = Marshal.ReadInt32(longBuffer, LengthOrIndicatorOffset);
				if (num3 <= 0 || num3 > MaxChunkSize)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidLongBuffer);
				}
				if (((uint)num3 & (true ? 1u : 0u)) != 0)
				{
					throw System.Data.Common.ADP.InvalidCast();
				}
				int num4 = num3 / 2;
				int num5 = cchSourceOffset - num;
				if (num5 < num4)
				{
					int num6 = Math.Min(num2, num + num4 - cchSourceOffset);
					Marshal.Copy(System.Data.Common.ADP.IntPtrOffset(longBuffer, num5 * System.Data.Common.ADP.CharSize + ReservedSize), destinationBuffer, cchDestinationOffset, num6);
					cchSourceOffset += num6;
					cchDestinationOffset += num6;
					num2 -= num6;
				}
				num += num4;
			}
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal IntPtr GetChunk(out IntPtr lengthPtr)
		{
			IntPtr intPtr = Marshal.ReadIntPtr(_currentChunk);
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
			}
			finally
			{
				if (IntPtr.Zero == intPtr)
				{
					intPtr = System.Data.Common.SafeNativeMethods.LocalAlloc(0, (IntPtr)AllocationSize);
					if (IntPtr.Zero != intPtr)
					{
						Marshal.WriteIntPtr(intPtr, IntPtr.Zero);
						Marshal.WriteIntPtr(_currentChunk, intPtr);
					}
				}
				if (IntPtr.Zero != intPtr)
				{
					Marshal.WriteInt32(intPtr, LengthOrIndicatorOffset, -1);
					_currentChunk = intPtr;
					_chunkCount++;
				}
			}
			if (IntPtr.Zero == intPtr)
			{
				throw new OutOfMemoryException();
			}
			lengthPtr = System.Data.Common.ADP.IntPtrOffset(intPtr, LengthOrIndicatorOffset);
			return System.Data.Common.ADP.IntPtrOffset(intPtr, ReservedSize);
		}

		protected override bool ReleaseHandle()
		{
			IntPtr intPtr = handle;
			while (IntPtr.Zero != intPtr)
			{
				IntPtr intPtr2 = Marshal.ReadIntPtr(intPtr);
				System.Data.Common.SafeNativeMethods.LocalFree(intPtr);
				intPtr = intPtr2;
			}
			return true;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal void Reset()
		{
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				DangerousAddRef(ref success);
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					IntPtr intPtr = (_currentChunk = handle);
					while (IntPtr.Zero != intPtr)
					{
						IntPtr intPtr2 = Marshal.ReadIntPtr(intPtr);
						Marshal.WriteInt32(intPtr, LengthOrIndicatorOffset, -2);
						intPtr = intPtr2;
					}
					_chunkCount = 0;
				}
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
		}
	}
	internal sealed class NativeBuffer_ParameterBuffer : NativeBuffer
	{
		internal NativeBuffer_ParameterBuffer(int initialSize)
			: base(initialSize, zeroBuffer: true)
		{
		}
	}
	internal sealed class NativeBuffer_RowBuffer : NativeBuffer
	{
		private int _numberOfRows;

		private int _rowLength;

		private bool _ready;

		internal bool CurrentPositionIsValid => base.BaseOffset >= 0 && base.BaseOffset < NumberOfRows * RowLength;

		internal int NumberOfRows
		{
			get
			{
				return _numberOfRows;
			}
			set
			{
				if (value < 0 || base.Length < value * RowLength)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.InvalidNumberOfRows);
				}
				_numberOfRows = value;
			}
		}

		internal int RowLength => _rowLength;

		internal NativeBuffer_RowBuffer(int initialSize, int numberOfRows)
			: base(initialSize * numberOfRows, zeroBuffer: false)
		{
			_rowLength = initialSize;
			_numberOfRows = numberOfRows;
		}

		internal void MoveFirst()
		{
			base.BaseOffset = 0;
			_ready = true;
		}

		internal bool MoveNext()
		{
			if (!_ready)
			{
				return false;
			}
			base.BaseOffset += RowLength;
			return CurrentPositionIsValid;
		}

		internal bool MovePrevious()
		{
			if (!_ready)
			{
				return false;
			}
			if (base.BaseOffset <= -RowLength)
			{
				return false;
			}
			base.BaseOffset -= RowLength;
			return true;
		}
	}
	internal sealed class NativeBuffer_ScratchBuffer : NativeBuffer
	{
		internal NativeBuffer_ScratchBuffer(int initialSize)
			: base(initialSize)
		{
		}
	}
	internal sealed class NativeBuffer_ServerVersion : NativeBuffer
	{
		internal NativeBuffer_ServerVersion(int initialSize)
			: base(initialSize)
		{
		}
	}
	internal sealed class OCI
	{
		internal enum PATTR
		{
			OCI_ATTR_DATA_SIZE = 1,
			OCI_ATTR_DATA_TYPE,
			OCI_ATTR_DISP_SIZE,
			OCI_ATTR_NAME,
			OCI_ATTR_PRECISION,
			OCI_ATTR_SCALE,
			OCI_ATTR_IS_NULL
		}

		internal enum ATTR
		{
			OCI_ATTR_FNCODE = 1,
			OCI_ATTR_OBJECT = 2,
			OCI_ATTR_NONBLOCKING_MODE = 3,
			OCI_ATTR_SQLCODE = 4,
			OCI_ATTR_ENV = 5,
			OCI_ATTR_SERVER = 6,
			OCI_ATTR_SESSION = 7,
			OCI_ATTR_TRANS = 8,
			OCI_ATTR_ROW_COUNT = 9,
			OCI_ATTR_SQLFNCODE = 10,
			OCI_ATTR_PREFETCH_ROWS = 11,
			OCI_ATTR_NESTED_PREFETCH_ROWS = 12,
			OCI_ATTR_PREFETCH_MEMORY = 13,
			OCI_ATTR_NESTED_PREFETCH_MEMORY = 14,
			OCI_ATTR_CHAR_COUNT = 15,
			OCI_ATTR_PDSCL = 16,
			OCI_ATTR_FSPRECISION = 16,
			OCI_ATTR_PDPRC = 17,
			OCI_ATTR_LFPRECISION = 17,
			OCI_ATTR_PARAM_COUNT = 18,
			OCI_ATTR_ROWID = 19,
			OCI_ATTR_CHARSET = 20,
			OCI_ATTR_NCHAR = 21,
			OCI_ATTR_USERNAME = 22,
			OCI_ATTR_PASSWORD = 23,
			OCI_ATTR_STMT_TYPE = 24,
			OCI_ATTR_INTERNAL_NAME = 25,
			OCI_ATTR_EXTERNAL_NAME = 26,
			OCI_ATTR_XID = 27,
			OCI_ATTR_TRANS_LOCK = 28,
			OCI_ATTR_TRANS_NAME = 29,
			OCI_ATTR_HEAPALLOC = 30,
			OCI_ATTR_CHARSET_ID = 31,
			OCI_ATTR_CHARSET_FORM = 32,
			OCI_ATTR_MAXDATA_SIZE = 33,
			OCI_ATTR_CACHE_OPT_SIZE = 34,
			OCI_ATTR_CACHE_MAX_SIZE = 35,
			OCI_ATTR_PINOPTION = 36,
			OCI_ATTR_ALLOC_DURATION = 37,
			OCI_ATTR_PIN_DURATION = 38,
			OCI_ATTR_FDO = 39,
			OCI_ATTR_POSTPROCESSING_CALLBACK = 40,
			OCI_ATTR_POSTPROCESSING_CONTEXT = 41,
			OCI_ATTR_ROWS_RETURNED = 42,
			OCI_ATTR_FOCBK = 43,
			OCI_ATTR_IN_V8_MODE = 44,
			OCI_ATTR_LOBEMPTY = 45,
			OCI_ATTR_SESSLANG = 46,
			OCI_ATTR_VISIBILITY = 47,
			OCI_ATTR_RELATIVE_MSGID = 48,
			OCI_ATTR_SEQUENCE_DEVIATION = 49,
			OCI_ATTR_CONSUMER_NAME = 50,
			OCI_ATTR_DEQ_MODE = 51,
			OCI_ATTR_NAVIGATION = 52,
			OCI_ATTR_WAIT = 53,
			OCI_ATTR_DEQ_MSGID = 54,
			OCI_ATTR_PRIORITY = 55,
			OCI_ATTR_DELAY = 56,
			OCI_ATTR_EXPIRATION = 57,
			OCI_ATTR_CORRELATION = 58,
			OCI_ATTR_ATTEMPTS = 59,
			OCI_ATTR_RECIPIENT_LIST = 60,
			OCI_ATTR_EXCEPTION_QUEUE = 61,
			OCI_ATTR_ENQ_TIME = 62,
			OCI_ATTR_MSG_STATE = 63,
			OCI_ATTR_AGENT_NAME = 64,
			OCI_ATTR_AGENT_ADDRESS = 65,
			OCI_ATTR_AGENT_PROTOCOL = 66,
			OCI_ATTR_SENDER_ID = 68,
			OCI_ATTR_ORIGINAL_MSGID = 69,
			OCI_ATTR_QUEUE_NAME = 70,
			OCI_ATTR_NFY_MSGID = 71,
			OCI_ATTR_MSG_PROP = 72,
			OCI_ATTR_NUM_DML_ERRORS = 73,
			OCI_ATTR_DML_ROW_OFFSET = 74,
			OCI_ATTR_DATEFORMAT = 75,
			OCI_ATTR_BUF_ADDR = 76,
			OCI_ATTR_BUF_SIZE = 77,
			OCI_ATTR_DIRPATH_MODE = 78,
			OCI_ATTR_DIRPATH_NOLOG = 79,
			OCI_ATTR_DIRPATH_PARALLEL = 80,
			OCI_ATTR_NUM_ROWS = 81,
			OCI_ATTR_COL_COUNT = 82,
			OCI_ATTR_STREAM_OFFSET = 83,
			OCI_ATTR_SHARED_HEAPALLOC = 84,
			OCI_ATTR_SERVER_GROUP = 85,
			OCI_ATTR_MIGSESSION = 86,
			OCI_ATTR_NOCACHE = 87,
			OCI_ATTR_MEMPOOL_SIZE = 88,
			OCI_ATTR_MEMPOOL_INSTNAME = 89,
			OCI_ATTR_MEMPOOL_APPNAME = 90,
			OCI_ATTR_MEMPOOL_HOMENAME = 91,
			OCI_ATTR_MEMPOOL_MODEL = 92,
			OCI_ATTR_MODES = 93,
			OCI_ATTR_SUBSCR_NAME = 94,
			OCI_ATTR_SUBSCR_CALLBACK = 95,
			OCI_ATTR_SUBSCR_CTX = 96,
			OCI_ATTR_SUBSCR_PAYLOAD = 97,
			OCI_ATTR_SUBSCR_NAMESPACE = 98,
			OCI_ATTR_PROXY_CREDENTIALS = 99,
			OCI_ATTR_INITIAL_CLIENT_ROLES = 100,
			OCI_ATTR_UNK = 101,
			OCI_ATTR_NUM_COLS = 102,
			OCI_ATTR_LIST_COLUMNS = 103,
			OCI_ATTR_RDBA = 104,
			OCI_ATTR_CLUSTERED = 105,
			OCI_ATTR_PARTITIONED = 106,
			OCI_ATTR_INDEX_ONLY = 107,
			OCI_ATTR_LIST_ARGUMENTS = 108,
			OCI_ATTR_LIST_SUBPROGRAMS = 109,
			OCI_ATTR_REF_TDO = 110,
			OCI_ATTR_LINK = 111,
			OCI_ATTR_MIN = 112,
			OCI_ATTR_MAX = 113,
			OCI_ATTR_INCR = 114,
			OCI_ATTR_CACHE = 115,
			OCI_ATTR_ORDER = 116,
			OCI_ATTR_HW_MARK = 117,
			OCI_ATTR_TYPE_SCHEMA = 118,
			OCI_ATTR_TIMESTAMP = 119,
			OCI_ATTR_NUM_ATTRS = 120,
			OCI_ATTR_NUM_PARAMS = 121,
			OCI_ATTR_OBJID = 122,
			OCI_ATTR_PTYPE = 123,
			OCI_ATTR_PARAM = 124,
			OCI_ATTR_OVERLOAD_ID = 125,
			OCI_ATTR_TABLESPACE = 126,
			OCI_ATTR_TDO = 127,
			OCI_ATTR_LTYPE = 128,
			OCI_ATTR_PARSE_ERROR_OFFSET = 129,
			OCI_ATTR_IS_TEMPORARY = 130,
			OCI_ATTR_IS_TYPED = 131,
			OCI_ATTR_DURATION = 132,
			OCI_ATTR_IS_INVOKER_RIGHTS = 133,
			OCI_ATTR_OBJ_NAME = 134,
			OCI_ATTR_OBJ_SCHEMA = 135,
			OCI_ATTR_OBJ_ID = 136,
			OCI_ATTR_DIRPATH_SORTED_INDEX = 137,
			OCI_ATTR_DIRPATH_INDEX_MAINT_METHOD = 138,
			OCI_ATTR_DIRPATH_FILE = 139,
			OCI_ATTR_DIRPATH_STORAGE_INITIAL = 140,
			OCI_ATTR_DIRPATH_STORAGE_NEXT = 141,
			OCI_ATTR_TRANS_TIMEOUT = 142,
			OCI_ATTR_SERVER_STATUS = 143,
			OCI_ATTR_STATEMENT = 144,
			OCI_ATTR_NO_CACHE = 145,
			OCI_ATTR_RESERVED_1 = 146,
			OCI_ATTR_SERVER_BUSY = 147,
			OCI_ATTR_MAXCHAR_SIZE = 163,
			OCI_ATTR_ENV_CHARSET_ID = 207,
			OCI_ATTR_ENV_NCHARSET_ID = 208,
			OCI_ATTR_ENV_UTF16 = 209,
			OCI_ATTR_CHAR_SIZE = 286,
			OCI_ATTR_DATA_SIZE = 1,
			OCI_ATTR_DATA_TYPE = 2,
			OCI_ATTR_DISP_SIZE = 3,
			OCI_ATTR_NAME = 4,
			OCI_ATTR_PRECISION = 5,
			OCI_ATTR_SCALE = 6,
			OCI_ATTR_IS_NULL = 7
		}

		internal enum CHARSETFORM : byte
		{
			SQLCS_IMPLICIT = 1,
			SQLCS_NCHAR,
			SQLCS_EXPLICIT,
			SQLCS_FLEXIBLE,
			SQLCS_LIT_NULL
		}

		internal enum CRED
		{
			OCI_CRED_RDBMS = 1,
			OCI_CRED_EXT,
			OCI_CRED_PROXY
		}

		internal enum DATATYPE : short
		{
			VARCHAR2 = 1,
			NUMBER = 2,
			INTEGER = 3,
			FLOAT = 4,
			STRING = 5,
			VARNUM = 6,
			LONG = 8,
			ROWID = 11,
			DATE = 12,
			VARRAW = 15,
			RAW = 23,
			LONGRAW = 24,
			UNSIGNEDINT = 68,
			LONGVARCHAR = 94,
			LONGVARRAW = 95,
			CHAR = 96,
			CHARZ = 97,
			CURSOR = 102,
			ROWID_DESC = 104,
			MLSLABEL = 105,
			USERDEFINED = 108,
			REF = 110,
			CLOB = 112,
			BLOB = 113,
			BFILE = 114,
			RSET = 116,
			OCIDATE = 156,
			INT_TIMESTAMP = 180,
			INT_TIMESTAMP_TZ = 181,
			INT_TIMESTAMP_LTZ = 231,
			INT_INTERVAL_YM = 182,
			INT_INTERVAL_DS = 183,
			ANSIDATE = 184,
			TIME = 185,
			TIME_TZ = 186,
			TIMESTAMP = 187,
			TIMESTAMP_TZ = 188,
			INTERVAL_YM = 189,
			INTERVAL_DS = 190,
			TIMESTAMP_LTZ = 232,
			UROWID = 208,
			PLSQLRECORD = 250,
			PLSQLTABLE = 251
		}

		internal enum DURATION : short
		{
			OCI_DURATION_BEGIN = 10,
			OCI_DURATION_NULL = 9,
			OCI_DURATION_DEFAULT = 8,
			OCI_DURATION_NEXT = 7,
			OCI_DURATION_SESSION = 10,
			OCI_DURATION_TRANS = 11,
			OCI_DURATION_CALL = 12,
			OCI_DURATION_STATEMENT = 13,
			OCI_DURATION_CALLOUT = 14,
			OCI_DURATION_LAST = 14
		}

		internal enum FETCH : short
		{
			OCI_FETCH_NEXT = 2,
			OCI_FETCH_FIRST = 4,
			OCI_FETCH_LAST = 8,
			OCI_FETCH_PRIOR = 0x10,
			OCI_FETCH_ABSOLUTE = 0x20,
			OCI_FETCH_RELATIVE = 0x40
		}

		internal enum HTYPE
		{
			OCI_HTYPE_ENV = 1,
			OCI_HTYPE_ERROR = 2,
			OCI_HTYPE_SVCCTX = 3,
			OCI_HTYPE_STMT = 4,
			OCI_HTYPE_BIND = 5,
			OCI_HTYPE_DEFINE = 6,
			OCI_HTYPE_DESCRIBE = 7,
			OCI_HTYPE_SERVER = 8,
			OCI_HTYPE_SESSION = 9,
			OCI_HTYPE_TRANS = 10,
			OCI_HTYPE_COMPLEXOBJECT = 11,
			OCI_HTYPE_SECURITY = 12,
			OCI_HTYPE_SUBSCRIPTION = 13,
			OCI_HTYPE_DIRPATH_CTX = 14,
			OCI_HTYPE_DIRPATH_COLUMN_ARRAY = 15,
			OCI_HTYPE_DIRPATH_STREAM = 16,
			OCI_HTYPE_PROC = 17,
			OCI_DTYPE_FIRST = 50,
			OCI_DTYPE_LOB = 50,
			OCI_DTYPE_SNAP = 51,
			OCI_DTYPE_RSET = 52,
			OCI_DTYPE_PARAM = 53,
			OCI_DTYPE_ROWID = 54,
			OCI_DTYPE_COMPLEXOBJECTCOMP = 55,
			OCI_DTYPE_FILE = 56,
			OCI_DTYPE_AQENQ_OPTIONS = 57,
			OCI_DTYPE_AQDEQ_OPTIONS = 58,
			OCI_DTYPE_AQMSG_PROPERTIES = 59,
			OCI_DTYPE_AQAGENT = 60,
			OCI_DTYPE_LOCATOR = 61,
			OCI_DTYPE_INTERVAL_YM = 62,
			OCI_DTYPE_INTERVAL_DS = 63,
			OCI_DTYPE_AQNFY_DESCRIPTOR = 64,
			OCI_DTYPE_DATE = 65,
			OCI_DTYPE_TIME = 66,
			OCI_DTYPE_TIME_TZ = 67,
			OCI_DTYPE_TIMESTAMP = 68,
			OCI_DTYPE_TIMESTAMP_TZ = 69,
			OCI_DTYPE_TIMESTAMP_LTZ = 70,
			OCI_DTYPE_UCB = 71,
			OCI_DTYPE_LAST = 71
		}

		internal enum INDICATOR
		{
			TOOBIG = -2,
			ISNULL,
			OK
		}

		internal enum LOB_TYPE : byte
		{
			OCI_TEMP_BLOB = 1,
			OCI_TEMP_CLOB
		}

		[Flags]
		internal enum MODE
		{
			OCI_DEFAULT = 0,
			OCI_THREADED = 1,
			OCI_OBJECT = 2,
			OCI_EVENTS = 4,
			OCI_SHARED = 0x10,
			OCI_NO_UCB = 0x40,
			OCI_NO_MUTEX = 0x80,
			OCI_SHARED_EXT = 0x100,
			OCI_CACHE = 0x200,
			OCI_NO_CACHE = 0x400,
			OCI_UTF16 = 0x4000,
			OCI_MIGRATE = 1,
			OCI_SYSDBA = 2,
			OCI_SYSOPER = 4,
			OCI_PRELIM_AUTH = 8,
			OCIP_ICACHE = 0x10,
			OCI_BATCH_MODE = 1,
			OCI_EXACT_FETCH = 2,
			OCI_KEEP_FETCH_STATE = 4,
			OCI_SCROLLABLE_CURSOR = 8,
			OCI_DESCRIBE_ONLY = 0x10,
			OCI_COMMIT_ON_SUCCESS = 0x20,
			OCI_NON_BLOCKING = 0x40,
			OCI_BATCH_ERRORS = 0x80,
			OCI_PARSE_ONLY = 0x100,
			OCI_SHOW_DML_WARNINGS = 0x400,
			OCI_SB2_IND_PTR = 1,
			OCI_DATA_AT_EXEC = 2,
			OCI_DYNAMIC_FETCH = 2,
			OCI_PIECEWISE = 4
		}

		internal enum RETURNCODE
		{
			OCI_CONTINUE = -24200,
			OCI_STILL_EXECUTING = -3123,
			OCI_INVALID_HANDLE = -2,
			OCI_ERROR = -1,
			OCI_SUCCESS = 0,
			OCI_SUCCESS_WITH_INFO = 1,
			OCI_NEED_DATA = 99,
			OCI_NO_DATA = 100,
			OCI_RESERVED_FOR_INT_USE = 200
		}

		internal enum SIGN
		{
			OCI_NUMBER_UNSIGNED = 0,
			OCI_NUMBER_SIGNED = 2
		}

		internal enum STMT
		{
			OCI_STMT_SELECT = 1,
			OCI_STMT_UPDATE,
			OCI_STMT_DELETE,
			OCI_STMT_INSERT,
			OCI_STMT_CREATE,
			OCI_STMT_DROP,
			OCI_STMT_ALTER,
			OCI_STMT_BEGIN,
			OCI_STMT_DECLARE
		}

		internal enum SYNTAX
		{
			OCI_NTV_SYNTAX = 1,
			OCI_V7_SYNTAX,
			OCI_V8_SYNTAX
		}

		internal static class Callback
		{
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			internal delegate int OCICallbackDefine(IntPtr octxp, IntPtr defnp, uint iter, IntPtr bufpp, IntPtr alenp, IntPtr piecep, IntPtr indp, IntPtr rcodep);
		}

		private static int _clientVersion;

		internal static bool ClientVersionAtLeastOracle9i => 90 <= _clientVersion;

		private OCI()
		{
		}

		internal static int DetermineClientVersion()
		{
			//Discarded unreachable code: IL_00c8
			if (_clientVersion != 0)
			{
				return _clientVersion;
			}
			int num = 0;
			MODE mODE = MODE.OCI_THREADED | MODE.OCI_OBJECT;
			try
			{
				System.Data.Common.UnsafeNativeMethods.OCILobCopy2(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0uL, 0uL, 0uL);
				num = 101;
			}
			catch (EntryPointNotFoundException e)
			{
				System.Data.Common.ADP.TraceException(e);
				try
				{
					OciHandle handle = new OciNlsEnvironmentHandle(mODE);
					if (!handle.IsInvalid)
					{
						num = 92;
						OciHandle.SafeDispose(ref handle);
					}
				}
				catch (EntryPointNotFoundException e2)
				{
					System.Data.Common.ADP.TraceException(e2);
					try
					{
						mODE |= MODE.OCI_UTF16;
						OciHandle handle2 = new OciEnvironmentHandle(mODE, unicode: true);
						num = 90;
						OciHandle.SafeDispose(ref handle2);
						goto end_IL_0060;
					}
					catch (EntryPointNotFoundException e3)
					{
						System.Data.Common.ADP.TraceException(e3);
						num = 80;
						goto end_IL_0060;
					}
					catch (Exception e4)
					{
						if (!System.Data.Common.ADP.IsCatchableExceptionType(e4))
						{
							throw;
						}
						System.Data.Common.ADP.TraceException(e4);
						num = 81;
						goto end_IL_0060;
					}
					end_IL_0060:;
				}
			}
			catch (DllNotFoundException e5)
			{
				System.Data.Common.ADP.TraceException(e5);
				num = 73;
			}
			catch (BadImageFormatException e6)
			{
				throw System.Data.Common.ADP.BadOracleClientImageFormat(e6);
			}
			if (81 > num)
			{
				throw System.Data.Common.ADP.BadOracleClientVersion();
			}
			_clientVersion = num;
			return _clientVersion;
		}
	}
	internal sealed class OciEnlistContext : SafeHandle
	{
		private OciServiceContextHandle _serviceContextHandle;

		public override bool IsInvalid => IntPtr.Zero == handle;

		internal OciEnlistContext(byte[] userName, byte[] password, byte[] serverName, OciServiceContextHandle serviceContextHandle, OciErrorHandle errorHandle)
			: base(IntPtr.Zero, ownsHandle: true)
		{
			//Discarded unreachable code: IL_003e
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
			}
			finally
			{
				_serviceContextHandle = serviceContextHandle;
				int num = 0;
				try
				{
					num = TracedNativeMethods.OraMTSEnlCtxGet(userName, password, serverName, _serviceContextHandle, errorHandle, out handle);
				}
				catch (DllNotFoundException inner)
				{
					throw System.Data.Common.ADP.DistribTxRequiresOracleServicesForMTS(inner);
				}
				if (num != 0)
				{
					OracleException.Check(errorHandle, num);
				}
				serviceContextHandle.AddRef();
			}
		}

		internal void Join(OracleInternalConnection internalConnection, Transaction indigoTransaction)
		{
			IDtcTransaction oletxTransaction = System.Data.Common.ADP.GetOletxTransaction(indigoTransaction);
			int num = TracedNativeMethods.OraMTSJoinTxn(this, oletxTransaction);
			if (num != 0)
			{
				OracleException.Check(num, internalConnection);
			}
		}

		protected override bool ReleaseHandle()
		{
			IntPtr intPtr = handle;
			handle = IntPtr.Zero;
			if (IntPtr.Zero != intPtr)
			{
				TracedNativeMethods.OraMTSEnlCtxRel(intPtr);
			}
			if (_serviceContextHandle != null)
			{
				_serviceContextHandle.Release();
				_serviceContextHandle = null;
			}
			return true;
		}

		internal static void SafeDispose(ref OciEnlistContext ociEnlistContext)
		{
			if (ociEnlistContext != null)
			{
				ociEnlistContext.Dispose();
			}
			ociEnlistContext = null;
		}

		internal static IntPtr HandleValueToTrace(OciEnlistContext handle)
		{
			return handle.DangerousGetHandle();
		}
	}
	internal abstract class OciHandle : SafeHandle
	{
		[Flags]
		protected enum HANDLEFLAG
		{
			DEFAULT = 0,
			UNICODE = 1,
			NLS = 2
		}

		private OCI.HTYPE _handleType;

		private int _refCount;

		private OciHandle _parentHandle;

		private bool _isUnicode;

		internal OciHandle EnvironmentHandle
		{
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			get
			{
				if (HandleType == OCI.HTYPE.OCI_HTYPE_ENV)
				{
					return this;
				}
				return ParentHandle.EnvironmentHandle;
			}
		}

		internal OCI.HTYPE HandleType => _handleType;

		public override bool IsInvalid => IntPtr.Zero == handle;

		internal bool IsUnicode
		{
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			get
			{
				return _isUnicode;
			}
		}

		internal OciHandle ParentHandle
		{
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			get
			{
				return _parentHandle;
			}
		}

		protected OciHandle()
			: base(IntPtr.Zero, ownsHandle: true)
		{
		}

		protected OciHandle(OCI.HTYPE handleType)
			: base(IntPtr.Zero, ownsHandle: false)
		{
			_handleType = handleType;
		}

		protected OciHandle(OciHandle parentHandle, OCI.HTYPE handleType)
			: this(parentHandle, handleType, OCI.MODE.OCI_DEFAULT, HANDLEFLAG.DEFAULT)
		{
		}

		protected OciHandle(OciHandle parentHandle, OCI.HTYPE handleType, OCI.MODE ocimode, HANDLEFLAG handleflags)
			: this()
		{
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
			}
			finally
			{
				_handleType = handleType;
				_parentHandle = parentHandle;
				_refCount = 1;
				switch (handleType)
				{
				case OCI.HTYPE.OCI_HTYPE_ENV:
					if ((handleflags & HANDLEFLAG.NLS) == HANDLEFLAG.NLS)
					{
						int num = TracedNativeMethods.OCIEnvNlsCreate(out handle, ocimode, 0, 0);
						if (num != 0 || IntPtr.Zero == handle)
						{
							throw System.Data.Common.ADP.OperationFailed("OCIEnvNlsCreate", num);
						}
					}
					else
					{
						int num = TracedNativeMethods.OCIEnvCreate(out handle, ocimode);
						if (num != 0 || IntPtr.Zero == handle)
						{
							throw System.Data.Common.ADP.OperationFailed("OCIEnvCreate", num);
						}
					}
					break;
				case OCI.HTYPE.OCI_HTYPE_ERROR:
				case OCI.HTYPE.OCI_HTYPE_SVCCTX:
				case OCI.HTYPE.OCI_HTYPE_STMT:
				case OCI.HTYPE.OCI_HTYPE_SERVER:
				case OCI.HTYPE.OCI_HTYPE_SESSION:
				{
					int num = TracedNativeMethods.OCIHandleAlloc(parentHandle.EnvironmentHandle, out handle, handleType);
					if (num != 0 || IntPtr.Zero == handle)
					{
						throw System.Data.Common.ADP.OperationFailed("OCIHandleAlloc", num);
					}
					break;
				}
				case OCI.HTYPE.OCI_DTYPE_FIRST:
				case OCI.HTYPE.OCI_DTYPE_ROWID:
				case OCI.HTYPE.OCI_DTYPE_FILE:
				case OCI.HTYPE.OCI_DTYPE_INTERVAL_DS:
				case OCI.HTYPE.OCI_DTYPE_TIMESTAMP:
				case OCI.HTYPE.OCI_DTYPE_TIMESTAMP_TZ:
				case OCI.HTYPE.OCI_DTYPE_TIMESTAMP_LTZ:
				{
					int num = TracedNativeMethods.OCIDescriptorAlloc(parentHandle.EnvironmentHandle, out handle, handleType);
					if (num != 0 || IntPtr.Zero == handle)
					{
						throw System.Data.Common.ADP.OperationFailed("OCIDescriptorAlloc", num);
					}
					break;
				}
				}
				if (parentHandle != null)
				{
					parentHandle.AddRef();
					_isUnicode = parentHandle.IsUnicode;
				}
				else
				{
					_isUnicode = (handleflags & HANDLEFLAG.UNICODE) == HANDLEFLAG.UNICODE;
				}
			}
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal int AddRef()
		{
			return Interlocked.Increment(ref _refCount);
		}

		internal void GetAttribute(OCI.ATTR attribute, out byte value, OciErrorHandle errorHandle)
		{
			uint sizep = 0u;
			int num = TracedNativeMethods.OCIAttrGet(this, out value, out sizep, attribute, (OciHandle)errorHandle);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		internal void GetAttribute(OCI.ATTR attribute, out short value, OciErrorHandle errorHandle)
		{
			uint sizep = 0u;
			int num = TracedNativeMethods.OCIAttrGet(this, out value, out sizep, attribute, (OciHandle)errorHandle);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		internal void GetAttribute(OCI.ATTR attribute, out int value, OciErrorHandle errorHandle)
		{
			uint sizep = 0u;
			int num = TracedNativeMethods.OCIAttrGet(this, out value, out sizep, attribute, (OciHandle)errorHandle);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		internal void GetAttribute(OCI.ATTR attribute, out string value, OciErrorHandle errorHandle, OracleConnection connection)
		{
			IntPtr attributep = IntPtr.Zero;
			uint sizep = 0u;
			int num = TracedNativeMethods.OCIAttrGet(this, ref attributep, ref sizep, attribute, errorHandle);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			byte[] array = new byte[sizep];
			Marshal.Copy(attributep, array, 0, checked((int)sizep));
			value = connection.GetString(array);
		}

		internal byte[] GetBytes(string value)
		{
			uint length = (uint)value.Length;
			byte[] array;
			if (IsUnicode)
			{
				array = new byte[length * System.Data.Common.ADP.CharSize];
				GetBytes(value.ToCharArray(), 0, length, array, 0);
			}
			else
			{
				byte[] array2 = new byte[length * 4];
				uint bytes = GetBytes(value.ToCharArray(), 0, length, array2, 0);
				array = new byte[bytes];
				Buffer.BlockCopy(array2, 0, array, 0, checked((int)bytes));
			}
			return array;
		}

		internal uint GetBytes(char[] chars, int charIndex, uint charCount, byte[] bytes, int byteIndex)
		{
			uint size;
			if (IsUnicode)
			{
				size = checked((uint)((long)charCount * System.Data.Common.ADP.CharSize));
				Buffer.BlockCopy(chars, charIndex * System.Data.Common.ADP.CharSize, bytes, byteIndex, checked((int)size));
			}
			else
			{
				OciHandle environmentHandle = EnvironmentHandle;
				GCHandle gCHandle = default(GCHandle);
				GCHandle gCHandle2 = default(GCHandle);
				int num;
				try
				{
					gCHandle = GCHandle.Alloc(chars, GCHandleType.Pinned);
					IntPtr src = new IntPtr((long)gCHandle.AddrOfPinnedObject() + charIndex);
					IntPtr dst;
					if (bytes == null)
					{
						dst = IntPtr.Zero;
						size = 0u;
					}
					else
					{
						gCHandle2 = GCHandle.Alloc(bytes, GCHandleType.Pinned);
						dst = new IntPtr((long)gCHandle2.AddrOfPinnedObject() + byteIndex);
						size = checked((uint)(bytes.Length - byteIndex));
					}
					num = System.Data.Common.UnsafeNativeMethods.OCIUnicodeToCharSet(environmentHandle, dst, size, src, charCount, out size);
				}
				finally
				{
					gCHandle.Free();
					if (gCHandle2.IsAllocated)
					{
						gCHandle2.Free();
					}
				}
				if (num != 0)
				{
					throw System.Data.Common.ADP.OperationFailed("OCIUnicodeToCharSet", num);
				}
			}
			return size;
		}

		internal uint GetChars(byte[] bytes, int byteIndex, uint byteCount, char[] chars, int charIndex)
		{
			uint size;
			if (IsUnicode)
			{
				checked
				{
					size = (uint)unchecked(checked((long)byteCount) / System.Data.Common.ADP.CharSize);
					Buffer.BlockCopy(bytes, byteIndex, chars, unchecked(charIndex * System.Data.Common.ADP.CharSize), (int)byteCount);
				}
			}
			else
			{
				OciHandle environmentHandle = EnvironmentHandle;
				GCHandle gCHandle = default(GCHandle);
				GCHandle gCHandle2 = default(GCHandle);
				int num;
				try
				{
					gCHandle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
					IntPtr src = new IntPtr((long)gCHandle.AddrOfPinnedObject() + byteIndex);
					IntPtr dst;
					if (chars == null)
					{
						dst = IntPtr.Zero;
						size = 0u;
					}
					else
					{
						gCHandle2 = GCHandle.Alloc(chars, GCHandleType.Pinned);
						dst = new IntPtr((long)gCHandle2.AddrOfPinnedObject() + charIndex);
						size = checked((uint)(chars.Length - charIndex));
					}
					num = System.Data.Common.UnsafeNativeMethods.OCICharSetToUnicode(environmentHandle, dst, size, src, byteCount, out size);
				}
				finally
				{
					gCHandle.Free();
					if (gCHandle2.IsAllocated)
					{
						gCHandle2.Free();
					}
				}
				if (num != 0)
				{
					throw System.Data.Common.ADP.OperationFailed("OCICharSetToUnicode", num);
				}
			}
			return size;
		}

		internal static string GetAttributeName(OciHandle handle, OCI.ATTR atype)
		{
			if (OCI.HTYPE.OCI_DTYPE_PARAM == handle.HandleType)
			{
				return ((OCI.PATTR)atype).ToString();
			}
			return atype.ToString();
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static IntPtr HandleValueToTrace(OciHandle handle)
		{
			return handle.DangerousGetHandle();
		}

		internal string PtrToString(NativeBuffer buf)
		{
			string text = null;
			if (IsUnicode)
			{
				return buf.PtrToStringUni(0);
			}
			return buf.PtrToStringAnsi(0);
		}

		internal string PtrToString(IntPtr buf, int len)
		{
			if (IsUnicode)
			{
				return Marshal.PtrToStringUni(buf, len);
			}
			return Marshal.PtrToStringAnsi(buf, len);
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal int Release()
		{
			RuntimeHelpers.PrepareConstrainedRegions();
			int num;
			try
			{
			}
			finally
			{
				num = Interlocked.Decrement(ref _refCount);
				if (num == 0)
				{
					IntPtr intPtr = Interlocked.CompareExchange(ref handle, IntPtr.Zero, handle);
					if (IntPtr.Zero != intPtr)
					{
						OCI.HTYPE handleType = HandleType;
						OciHandle parentHandle = ParentHandle;
						switch (handleType)
						{
						case OCI.HTYPE.OCI_HTYPE_ENV:
						{
							int num2 = TracedNativeMethods.OCIHandleFree(intPtr, handleType);
							if (num2 != 0)
							{
								throw System.Data.Common.ADP.OperationFailed("OCIHandleFree", num2);
							}
							break;
						}
						case OCI.HTYPE.OCI_HTYPE_SERVER:
							TracedNativeMethods.OCIServerDetach(intPtr, parentHandle.DangerousGetHandle(), OCI.MODE.OCI_DEFAULT);
							goto case OCI.HTYPE.OCI_HTYPE_ERROR;
						case OCI.HTYPE.OCI_HTYPE_SVCCTX:
						{
							OciHandle ociHandle = parentHandle;
							if (ociHandle != null)
							{
								OciHandle parentHandle2 = ociHandle.ParentHandle;
								if (parentHandle2 != null)
								{
									OciHandle parentHandle3 = parentHandle2.ParentHandle;
									if (parentHandle3 != null)
									{
										int num2 = TracedNativeMethods.OCISessionEnd(intPtr, parentHandle3.DangerousGetHandle(), ociHandle.DangerousGetHandle(), OCI.MODE.OCI_DEFAULT);
									}
								}
							}
							goto case OCI.HTYPE.OCI_HTYPE_ERROR;
						}
						case OCI.HTYPE.OCI_HTYPE_ERROR:
						case OCI.HTYPE.OCI_HTYPE_STMT:
						case OCI.HTYPE.OCI_HTYPE_SESSION:
						{
							int num2 = TracedNativeMethods.OCIHandleFree(intPtr, handleType);
							if (num2 != 0)
							{
								throw System.Data.Common.ADP.OperationFailed("OCIHandleFree", num2);
							}
							break;
						}
						case OCI.HTYPE.OCI_DTYPE_FIRST:
						case OCI.HTYPE.OCI_DTYPE_ROWID:
						case OCI.HTYPE.OCI_DTYPE_FILE:
						case OCI.HTYPE.OCI_DTYPE_INTERVAL_DS:
						case OCI.HTYPE.OCI_DTYPE_TIMESTAMP:
						case OCI.HTYPE.OCI_DTYPE_TIMESTAMP_TZ:
						case OCI.HTYPE.OCI_DTYPE_TIMESTAMP_LTZ:
						{
							int num2 = TracedNativeMethods.OCIDescriptorFree(intPtr, handleType);
							if (num2 != 0)
							{
								throw System.Data.Common.ADP.OperationFailed("OCIDescriptorFree", num2);
							}
							break;
						}
						}
						parentHandle?.Release();
					}
				}
			}
			return num;
		}

		protected override bool ReleaseHandle()
		{
			Release();
			return true;
		}

		internal static void SafeDispose(ref OciHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciEnvironmentHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciErrorHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciRowidDescriptor handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciStatementHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciSessionHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciServiceContextHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciServerHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciDefineHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciBindHandle handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciParameterDescriptor handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal static void SafeDispose(ref OciDateTimeDescriptor handle)
		{
			if (handle != null)
			{
				handle.Dispose();
			}
			handle = null;
		}

		internal void SetAttribute(OCI.ATTR attribute, int value, OciErrorHandle errorHandle)
		{
			int num = TracedNativeMethods.OCIAttrSet(this, ref value, 0u, attribute, errorHandle);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		internal void SetAttribute(OCI.ATTR attribute, OciHandle value, OciErrorHandle errorHandle)
		{
			int num = TracedNativeMethods.OCIAttrSet(this, value, 0u, attribute, errorHandle);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		internal void SetAttribute(OCI.ATTR attribute, string value, OciErrorHandle errorHandle)
		{
			uint length = (uint)value.Length;
			byte[] array = new byte[length * 4];
			uint bytes = GetBytes(value.ToCharArray(), 0, length, array, 0);
			int num = TracedNativeMethods.OCIAttrSet(this, array, bytes, attribute, errorHandle);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}
	}
	internal sealed class OciEnvironmentHandle : OciHandle
	{
		internal OciEnvironmentHandle(OCI.MODE environmentMode, bool unicode)
			: base(null, OCI.HTYPE.OCI_HTYPE_ENV, environmentMode, unicode ? HANDLEFLAG.UNICODE : HANDLEFLAG.DEFAULT)
		{
		}
	}
	internal sealed class OciErrorHandle : OciHandle
	{
		private bool _connectionIsBroken;

		internal bool ConnectionIsBroken
		{
			get
			{
				return _connectionIsBroken;
			}
			set
			{
				_connectionIsBroken = value;
			}
		}

		internal OciErrorHandle(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_HTYPE_ERROR)
		{
		}
	}
	internal sealed class OciDateTimeDescriptor : OciHandle
	{
		internal OciDateTimeDescriptor(OciHandle parent, OCI.HTYPE dateTimeType)
			: base(parent, AssertDateTimeType(dateTimeType))
		{
		}

		private static OCI.HTYPE AssertDateTimeType(OCI.HTYPE dateTimeType)
		{
			return dateTimeType;
		}
	}
	internal sealed class OciFileDescriptor : OciHandle
	{
		internal OciFileDescriptor(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_DTYPE_FILE)
		{
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal int OCILobFileSetNameWrapper(OciHandle envhp, OciHandle errhp, byte[] dirAlias, ushort dirAliasLength, byte[] fileName, ushort fileNameLength)
		{
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			int result;
			try
			{
				DangerousAddRef(ref success);
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					IntPtr filep = DangerousGetHandle();
					result = System.Data.Common.UnsafeNativeMethods.OCILobFileSetName(envhp, errhp, ref filep, dirAlias, dirAliasLength, fileName, fileNameLength);
					handle = filep;
				}
			}
			finally
			{
				if (success)
				{
					DangerousRelease();
				}
			}
			return result;
		}
	}
	internal sealed class OciIntervalDescriptor : OciHandle
	{
		internal OciIntervalDescriptor(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_DTYPE_INTERVAL_DS)
		{
		}
	}
	internal sealed class OciLobDescriptor : OciHandle
	{
		internal OciLobDescriptor(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_DTYPE_FIRST)
		{
		}
	}
	internal sealed class OciNlsEnvironmentHandle : OciHandle
	{
		internal OciNlsEnvironmentHandle(OCI.MODE environmentMode)
			: base(null, OCI.HTYPE.OCI_HTYPE_ENV, environmentMode, HANDLEFLAG.NLS)
		{
		}
	}
	internal sealed class OciRowidDescriptor : OciHandle
	{
		internal OciRowidDescriptor(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_DTYPE_ROWID)
		{
		}

		internal void GetRowid(OciStatementHandle statementHandle, OciErrorHandle errorHandle)
		{
			uint sizep = 0u;
			int num = TracedNativeMethods.OCIAttrGet(statementHandle, this, out sizep, OCI.ATTR.OCI_ATTR_ROWID, errorHandle);
			if (100 == num)
			{
				Dispose();
			}
			else if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}
	}
	internal sealed class OciServerHandle : OciHandle
	{
		internal OciServerHandle(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_HTYPE_SERVER, OCI.MODE.OCI_DEFAULT, HANDLEFLAG.DEFAULT)
		{
		}
	}
	internal sealed class OciServiceContextHandle : OciHandle
	{
		internal OciServiceContextHandle(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_HTYPE_SVCCTX, OCI.MODE.OCI_DEFAULT, HANDLEFLAG.DEFAULT)
		{
		}
	}
	internal sealed class OciSessionHandle : OciHandle
	{
		internal OciSessionHandle(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_HTYPE_SESSION, OCI.MODE.OCI_DEFAULT, HANDLEFLAG.DEFAULT)
		{
		}
	}
	internal sealed class OciStatementHandle : OciHandle
	{
		internal OciStatementHandle(OciHandle parent)
			: base(parent, OCI.HTYPE.OCI_HTYPE_STMT)
		{
		}

		internal OciParameterDescriptor GetDescriptor(int i, OciErrorHandle errorHandle)
		{
			IntPtr paramdpp;
			int num = TracedNativeMethods.OCIParamGet(this, base.HandleType, errorHandle, out paramdpp, i + 1);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return new OciParameterDescriptor(this, paramdpp);
		}

		internal OciRowidDescriptor GetRowid(OciHandle environmentHandle, OciErrorHandle errorHandle)
		{
			OciRowidDescriptor ociRowidDescriptor = new OciRowidDescriptor(environmentHandle);
			ociRowidDescriptor.GetRowid(this, errorHandle);
			return ociRowidDescriptor;
		}
	}
	internal abstract class OciSimpleHandle : OciHandle
	{
		public override bool IsInvalid => true;

		internal OciSimpleHandle(OciHandle parent, OCI.HTYPE handleType, IntPtr value)
			: base(handleType)
		{
			handle = value;
		}
	}
	internal sealed class OciBindHandle : OciSimpleHandle
	{
		internal OciBindHandle(OciHandle parent, IntPtr value)
			: base(parent, OCI.HTYPE.OCI_HTYPE_BIND, value)
		{
		}
	}
	internal sealed class OciDefineHandle : OciSimpleHandle
	{
		internal OciDefineHandle(OciHandle parent, IntPtr value)
			: base(parent, OCI.HTYPE.OCI_HTYPE_DEFINE, value)
		{
		}
	}
	internal sealed class OciParameterDescriptor : OciSimpleHandle
	{
		internal OciParameterDescriptor(OciHandle parent, IntPtr value)
			: base(parent, OCI.HTYPE.OCI_DTYPE_PARAM, value)
		{
		}
	}
	internal sealed class OciLobLocator
	{
		private OracleConnection _connection;

		private int _connectionCloseCount;

		private OracleType _lobType;

		private OciHandle _descriptor;

		private int _cloneCount;

		private int _openMode;

		internal OracleConnection Connection => _connection;

		internal bool ConnectionIsClosed
		{
			get
			{
				if (_connection != null)
				{
					return _connectionCloseCount != _connection.CloseCount;
				}
				return true;
			}
		}

		internal OciErrorHandle ErrorHandle => Connection.ErrorHandle;

		internal OciHandle Descriptor
		{
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			get
			{
				return _descriptor;
			}
		}

		public OracleType LobType => _lobType;

		internal OciServiceContextHandle ServiceContextHandle => Connection.ServiceContextHandle;

		internal OciLobLocator(OracleConnection connection, OracleType lobType)
		{
			_connection = connection;
			_connectionCloseCount = connection.CloseCount;
			_lobType = lobType;
			_cloneCount = 1;
			switch (lobType)
			{
			case OracleType.Blob:
			case OracleType.Clob:
			case OracleType.NClob:
				_descriptor = new OciLobDescriptor(connection.ServiceContextHandle);
				break;
			case OracleType.BFile:
				_descriptor = new OciFileDescriptor(connection.ServiceContextHandle);
				break;
			}
		}

		internal OciLobLocator Clone()
		{
			Interlocked.Increment(ref _cloneCount);
			return this;
		}

		internal void Dispose()
		{
			if (Interlocked.Decrement(ref _cloneCount) == 0)
			{
				if (_openMode != 0 && !ConnectionIsClosed)
				{
					ForceClose();
				}
				OciHandle.SafeDispose(ref _descriptor);
				GC.KeepAlive(this);
				_connection = null;
			}
		}

		internal void ForceClose()
		{
			if (_openMode != 0)
			{
				int num = TracedNativeMethods.OCILobClose(ServiceContextHandle, ErrorHandle, Descriptor);
				if (num != 0)
				{
					Connection.CheckError(ErrorHandle, num);
				}
				_openMode = 0;
			}
		}

		internal void ForceOpen()
		{
			if (_openMode != 0)
			{
				int num = TracedNativeMethods.OCILobOpen(ServiceContextHandle, ErrorHandle, Descriptor, (byte)_openMode);
				if (num != 0)
				{
					_openMode = 0;
					Connection.CheckError(ErrorHandle, num);
				}
			}
		}

		internal void Open(OracleLobOpenMode mode)
		{
			OracleLobOpenMode oracleLobOpenMode = (OracleLobOpenMode)Interlocked.CompareExchange(ref _openMode, (int)mode, 0);
			if (oracleLobOpenMode == (OracleLobOpenMode)0)
			{
				ForceOpen();
			}
			else if (mode != oracleLobOpenMode)
			{
				throw System.Data.Common.ADP.CannotOpenLobWithDifferentMode(mode, oracleLobOpenMode);
			}
		}

		internal static void SafeDispose(ref OciLobLocator locator)
		{
			if (locator != null)
			{
				locator.Dispose();
			}
			locator = null;
		}
	}
	public sealed class OracleBFile : Stream, ICloneable, INullable, IDisposable
	{
		private const short MaxDirectoryAliasChars = 30;

		private const short MaxFileAliasChars = 255;

		private OracleLob _lob;

		private string _fileName;

		private string _directoryAlias;

		public new static readonly OracleBFile Null = new OracleBFile();

		public override bool CanRead
		{
			get
			{
				if (IsNull)
				{
					return true;
				}
				return !IsDisposed;
			}
		}

		public override bool CanSeek
		{
			get
			{
				if (IsNull)
				{
					return true;
				}
				return !IsDisposed;
			}
		}

		public override bool CanWrite => false;

		public OracleConnection Connection
		{
			get
			{
				AssertInternalLobIsValid();
				return _lob.Connection;
			}
		}

		internal OciHandle Descriptor => LobLocator.Descriptor;

		public string DirectoryName
		{
			get
			{
				AssertInternalLobIsValid();
				if (IsNull)
				{
					return string.Empty;
				}
				if (_directoryAlias == null)
				{
					GetNames();
				}
				return _directoryAlias;
			}
		}

		public bool FileExists
		{
			get
			{
				AssertInternalLobIsValid();
				if (IsNull)
				{
					return false;
				}
				_lob.AssertConnectionIsOpen();
				int flag;
				int num = TracedNativeMethods.OCILobFileExists(ServiceContextHandle, ErrorHandle, Descriptor, out flag);
				if (num != 0)
				{
					Connection.CheckError(ErrorHandle, num);
				}
				return flag != 0;
			}
		}

		public string FileName
		{
			get
			{
				AssertInternalLobIsValid();
				if (IsNull)
				{
					return string.Empty;
				}
				if (_fileName == null)
				{
					GetNames();
				}
				return _fileName;
			}
		}

		internal OciErrorHandle ErrorHandle => _lob.ErrorHandle;

		private bool IsDisposed => null == _lob;

		public bool IsNull => OracleLob.Null == _lob;

		public override long Length
		{
			get
			{
				AssertInternalLobIsValid();
				if (IsNull)
				{
					return 0L;
				}
				return _lob.Length;
			}
		}

		internal OciLobLocator LobLocator => _lob.LobLocator;

		public override long Position
		{
			get
			{
				AssertInternalLobIsValid();
				if (IsNull)
				{
					return 0L;
				}
				return _lob.Position;
			}
			set
			{
				AssertInternalLobIsValid();
				if (!IsNull)
				{
					_lob.Position = value;
				}
			}
		}

		internal OciServiceContextHandle ServiceContextHandle => _lob.ServiceContextHandle;

		public object Value
		{
			get
			{
				AssertInternalLobIsValid();
				if (IsNull)
				{
					return DBNull.Value;
				}
				EnsureLobIsOpened();
				return _lob.Value;
			}
		}

		internal OracleBFile()
		{
			_lob = OracleLob.Null;
		}

		internal OracleBFile(OciLobLocator lobLocator)
		{
			_lob = new OracleLob(lobLocator);
		}

		internal OracleBFile(OracleBFile bfile)
		{
			_lob = (OracleLob)bfile._lob.Clone();
			_fileName = bfile._fileName;
			_directoryAlias = bfile._directoryAlias;
		}

		internal void AssertInternalLobIsValid()
		{
			if (IsDisposed)
			{
				throw System.Data.Common.ADP.ObjectDisposed("OracleBFile");
			}
		}

		public object Clone()
		{
			return new OracleBFile(this);
		}

		public long CopyTo(OracleLob destination)
		{
			return CopyTo(0L, destination, 0L, Length);
		}

		public long CopyTo(OracleLob destination, long destinationOffset)
		{
			return CopyTo(0L, destination, destinationOffset, Length);
		}

		public long CopyTo(long sourceOffset, OracleLob destination, long destinationOffset, long amount)
		{
			AssertInternalLobIsValid();
			if (destination == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("destination");
			}
			if (destination.IsNull)
			{
				throw System.Data.Common.ADP.LobWriteInvalidOnNull();
			}
			if (_lob.IsNull)
			{
				return 0L;
			}
			_lob.AssertConnectionIsOpen();
			_lob.AssertAmountIsValid(amount, "amount");
			_lob.AssertAmountIsValid(sourceOffset, "sourceOffset");
			_lob.AssertAmountIsValid(destinationOffset, "destinationOffset");
			_lob.AssertTransactionExists();
			long num = Math.Min(Length - sourceOffset, amount);
			long num2 = destinationOffset + 1;
			long num3 = sourceOffset + 1;
			if (0 >= num)
			{
				return 0L;
			}
			int num4 = TracedNativeMethods.OCILobLoadFromFile(ServiceContextHandle, ErrorHandle, destination.Descriptor, Descriptor, (uint)num, (uint)num2, (uint)num3);
			if (num4 != 0)
			{
				Connection.CheckError(ErrorHandle, num4);
			}
			return num;
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				_lob?.Close();
			}
			_lob = null;
			_fileName = null;
			_directoryAlias = null;
			base.Dispose(disposing);
		}

		private void EnsureLobIsOpened()
		{
			LobLocator.Open(OracleLobOpenMode.ReadOnly);
		}

		public override void Flush()
		{
		}

		internal void GetNames()
		{
			_lob.AssertConnectionIsOpen();
			short num = (short)((!Connection.EnvironmentHandle.IsUnicode) ? 1 : 2);
			ushort d_length;
			int offset;
			ushort f_length;
			checked
			{
				d_length = (ushort)(30 * num);
				offset = d_length;
				f_length = (ushort)(255 * num);
			}
			NativeBuffer scratchBuffer = Connection.GetScratchBuffer(d_length + f_length);
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				scratchBuffer.DangerousAddRef(ref success);
				int num2 = TracedNativeMethods.OCILobFileGetName(Connection.EnvironmentHandle, ErrorHandle, Descriptor, scratchBuffer.DangerousGetDataPtr(), ref d_length, scratchBuffer.DangerousGetDataPtr(offset), ref f_length);
				if (num2 != 0)
				{
					Connection.CheckError(ErrorHandle, num2);
				}
				_directoryAlias = Connection.GetString(scratchBuffer.ReadBytes(0, d_length));
				_fileName = Connection.GetString(scratchBuffer.ReadBytes(offset, f_length));
			}
			finally
			{
				if (success)
				{
					scratchBuffer.DangerousRelease();
				}
			}
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			AssertInternalLobIsValid();
			if (!IsNull)
			{
				EnsureLobIsOpened();
			}
			return _lob.Read(buffer, offset, count);
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			AssertInternalLobIsValid();
			return _lob.Seek(offset, origin);
		}

		public void SetFileName(string directory, string file)
		{
			AssertInternalLobIsValid();
			if (IsNull)
			{
				return;
			}
			_lob.AssertConnectionIsOpen();
			_lob.AssertTransactionExists();
			OciFileDescriptor ociFileDescriptor = (OciFileDescriptor)LobLocator.Descriptor;
			if (ociFileDescriptor == null)
			{
				return;
			}
			LobLocator.ForceClose();
			int num = TracedNativeMethods.OCILobFileSetName(Connection.EnvironmentHandle, ErrorHandle, ociFileDescriptor, directory, file);
			if (num != 0)
			{
				Connection.CheckError(ErrorHandle, num);
			}
			LobLocator.ForceOpen();
			_fileName = null;
			_directoryAlias = null;
			try
			{
				_lob.Position = 0L;
			}
			catch (Exception e)
			{
				if (!System.Data.Common.ADP.IsCatchableExceptionType(e))
				{
					throw;
				}
			}
		}

		public override void SetLength(long value)
		{
			AssertInternalLobIsValid();
			throw System.Data.Common.ADP.ReadOnlyLob();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			AssertInternalLobIsValid();
			throw System.Data.Common.ADP.ReadOnlyLob();
		}
	}
	public struct OracleBinary : IComparable, INullable
	{
		private byte[] _value;

		public static readonly OracleBinary Null = new OracleBinary(isNull: true);

		public bool IsNull => null == _value;

		public int Length
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return _value.Length;
			}
		}

		public byte[] Value
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return (byte[])_value.Clone();
			}
		}

		public byte this[int index]
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return _value[index];
			}
		}

		private OracleBinary(bool isNull)
		{
			_value = (isNull ? null : new byte[0]);
		}

		public OracleBinary(byte[] b)
		{
			_value = ((b == null) ? b : ((byte[])b.Clone()));
		}

		internal OracleBinary(NativeBuffer buffer, int valueOffset, int lengthOffset, MetaType metaType)
		{
			int length = GetLength(buffer, lengthOffset, metaType);
			_value = new byte[length];
			GetBytes(buffer, valueOffset, metaType, 0, _value, 0, length);
		}

		public int CompareTo(object obj)
		{
			if (obj.GetType() == typeof(OracleBinary))
			{
				OracleBinary oracleBinary = (OracleBinary)obj;
				if (IsNull)
				{
					if (!oracleBinary.IsNull)
					{
						return -1;
					}
					return 0;
				}
				if (oracleBinary.IsNull)
				{
					return 1;
				}
				return PerformCompareByte(_value, oracleBinary._value);
			}
			throw System.Data.Common.ADP.WrongType(obj.GetType(), typeof(OracleBinary));
		}

		public override bool Equals(object value)
		{
			if (value is OracleBinary)
			{
				return (this == (OracleBinary)value).Value;
			}
			return false;
		}

		internal static int GetBytes(NativeBuffer buffer, int valueOffset, MetaType metaType, int sourceOffset, byte[] destinationBuffer, int destinationOffset, int byteCount)
		{
			if (!metaType.IsLong)
			{
				buffer.ReadBytes(valueOffset + sourceOffset, destinationBuffer, destinationOffset, byteCount);
			}
			else
			{
				NativeBuffer_LongColumnData.CopyOutOfLineBytes(buffer.ReadIntPtr(valueOffset), sourceOffset, destinationBuffer, destinationOffset, byteCount);
			}
			return byteCount;
		}

		internal static int GetLength(NativeBuffer buffer, int lengthOffset, MetaType metaType)
		{
			if (metaType.IsLong)
			{
				return buffer.ReadInt32(lengthOffset);
			}
			return buffer.ReadInt16(lengthOffset);
		}

		public override int GetHashCode()
		{
			if (!IsNull)
			{
				return _value.GetHashCode();
			}
			return 0;
		}

		private static int PerformCompareByte(byte[] x, byte[] y)
		{
			int num = x.Length;
			int num2 = y.Length;
			bool flag = num < num2;
			int num3 = (flag ? num : num2);
			for (int i = 0; i < num3; i++)
			{
				if (x[i] != y[i])
				{
					if (x[i] < y[i])
					{
						return -1;
					}
					return 1;
				}
			}
			if (num == num2)
			{
				return 0;
			}
			byte b = 0;
			if (flag)
			{
				for (int i = num3; i < num2; i++)
				{
					if (y[i] != b)
					{
						return -1;
					}
				}
			}
			else
			{
				for (int i = num3; i < num; i++)
				{
					if (x[i] != b)
					{
						return 1;
					}
				}
			}
			return 0;
		}

		public static OracleBinary Concat(OracleBinary x, OracleBinary y)
		{
			return x + y;
		}

		public static OracleBoolean Equals(OracleBinary x, OracleBinary y)
		{
			return x == y;
		}

		public static OracleBoolean GreaterThan(OracleBinary x, OracleBinary y)
		{
			return x > y;
		}

		public static OracleBoolean GreaterThanOrEqual(OracleBinary x, OracleBinary y)
		{
			return x >= y;
		}

		public static OracleBoolean LessThan(OracleBinary x, OracleBinary y)
		{
			return x < y;
		}

		public static OracleBoolean LessThanOrEqual(OracleBinary x, OracleBinary y)
		{
			return x <= y;
		}

		public static OracleBoolean NotEquals(OracleBinary x, OracleBinary y)
		{
			return x != y;
		}

		public static implicit operator OracleBinary(byte[] b)
		{
			return new OracleBinary(b);
		}

		public static explicit operator byte[](OracleBinary x)
		{
			return x.Value;
		}

		public static OracleBinary operator +(OracleBinary x, OracleBinary y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			byte[] array = new byte[x._value.Length + y._value.Length];
			x._value.CopyTo(array, 0);
			y._value.CopyTo(array, x.Value.Length);
			return new OracleBinary(array);
		}

		public static OracleBoolean operator ==(OracleBinary x, OracleBinary y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) == 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >(OracleBinary x, OracleBinary y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) > 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >=(OracleBinary x, OracleBinary y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) >= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <(OracleBinary x, OracleBinary y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) < 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <=(OracleBinary x, OracleBinary y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) <= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator !=(OracleBinary x, OracleBinary y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) != 0);
			}
			return OracleBoolean.Null;
		}
	}
	public struct OracleBoolean : IComparable
	{
		private const byte x_Null = 0;

		private const byte x_True = 1;

		private const byte x_False = 2;

		private byte _value;

		public static readonly OracleBoolean False = new OracleBoolean(value: false);

		public static readonly OracleBoolean Null = new OracleBoolean(0, isNull: true);

		public static readonly OracleBoolean One = new OracleBoolean(1);

		public static readonly OracleBoolean True = new OracleBoolean(value: true);

		public static readonly OracleBoolean Zero = new OracleBoolean(0);

		private byte ByteValue => _value;

		public bool IsFalse => _value == 2;

		public bool IsNull => _value == 0;

		public bool IsTrue => _value == 1;

		public bool Value => _value switch
		{
			1 => true, 
			2 => false, 
			_ => throw System.Data.Common.ADP.DataIsNull(), 
		};

		public OracleBoolean(bool value)
		{
			_value = (byte)(value ? 1 : 2);
		}

		public OracleBoolean(int value)
			: this(value, isNull: false)
		{
		}

		private OracleBoolean(int value, bool isNull)
		{
			if (isNull)
			{
				_value = 0;
			}
			else
			{
				_value = (byte)((value != 0) ? 1 : 2);
			}
		}

		public int CompareTo(object obj)
		{
			if (obj is OracleBoolean oracleBoolean)
			{
				if (IsNull)
				{
					if (!oracleBoolean.IsNull)
					{
						return -1;
					}
					return 0;
				}
				if (oracleBoolean.IsNull)
				{
					return 1;
				}
				if (ByteValue < oracleBoolean.ByteValue)
				{
					return -1;
				}
				if (ByteValue > oracleBoolean.ByteValue)
				{
					return 1;
				}
				return 0;
			}
			throw System.Data.Common.ADP.WrongType(obj.GetType(), typeof(OracleBoolean));
		}

		public override bool Equals(object value)
		{
			if (value is OracleBoolean oracleBoolean)
			{
				if (oracleBoolean.IsNull || IsNull)
				{
					if (oracleBoolean.IsNull)
					{
						return IsNull;
					}
					return false;
				}
				return (this == oracleBoolean).Value;
			}
			return false;
		}

		public override int GetHashCode()
		{
			if (!IsNull)
			{
				return _value.GetHashCode();
			}
			return 0;
		}

		public static OracleBoolean Parse(string s)
		{
			try
			{
				return new OracleBoolean(int.Parse(s, CultureInfo.InvariantCulture));
			}
			catch (Exception ex)
			{
				Type type = ex.GetType();
				if (type == System.Data.Common.ADP.ArgumentNullExceptionType || type == System.Data.Common.ADP.FormatExceptionType || type == System.Data.Common.ADP.OverflowExceptionType)
				{
					return new OracleBoolean(bool.Parse(s));
				}
				throw ex;
			}
		}

		public override string ToString()
		{
			if (IsNull)
			{
				return System.Data.Common.ADP.NullString;
			}
			return Value.ToString(CultureInfo.CurrentCulture);
		}

		public static OracleBoolean And(OracleBoolean x, OracleBoolean y)
		{
			return x & y;
		}

		public static OracleBoolean Equals(OracleBoolean x, OracleBoolean y)
		{
			return x == y;
		}

		public static OracleBoolean NotEquals(OracleBoolean x, OracleBoolean y)
		{
			return x != y;
		}

		public static OracleBoolean OnesComplement(OracleBoolean x)
		{
			return ~x;
		}

		public static OracleBoolean Or(OracleBoolean x, OracleBoolean y)
		{
			return x | y;
		}

		public static OracleBoolean Xor(OracleBoolean x, OracleBoolean y)
		{
			return x ^ y;
		}

		public static implicit operator OracleBoolean(bool x)
		{
			return new OracleBoolean(x);
		}

		public static explicit operator OracleBoolean(string x)
		{
			return Parse(x);
		}

		public static explicit operator OracleBoolean(OracleNumber x)
		{
			if (!x.IsNull)
			{
				return new OracleBoolean(x.Value != 0m);
			}
			return Null;
		}

		public static explicit operator bool(OracleBoolean x)
		{
			return x.Value;
		}

		public static OracleBoolean operator !(OracleBoolean x)
		{
			return x._value switch
			{
				1 => False, 
				2 => True, 
				_ => Null, 
			};
		}

		public static OracleBoolean operator ~(OracleBoolean x)
		{
			return !x;
		}

		public static bool operator true(OracleBoolean x)
		{
			return x.IsTrue;
		}

		public static bool operator false(OracleBoolean x)
		{
			return x.IsFalse;
		}

		public static OracleBoolean operator &(OracleBoolean x, OracleBoolean y)
		{
			if (x._value == 2 || y._value == 2)
			{
				return False;
			}
			if (x._value == 1 && y._value == 1)
			{
				return True;
			}
			return Null;
		}

		public static OracleBoolean operator ==(OracleBoolean x, OracleBoolean y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x._value == y._value);
			}
			return Null;
		}

		public static OracleBoolean operator !=(OracleBoolean x, OracleBoolean y)
		{
			return !(x == y);
		}

		public static OracleBoolean operator |(OracleBoolean x, OracleBoolean y)
		{
			if (x._value == 1 || y._value == 1)
			{
				return True;
			}
			if (x._value == 2 && y._value == 2)
			{
				return False;
			}
			return Null;
		}

		public static OracleBoolean operator ^(OracleBoolean x, OracleBoolean y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x._value != y._value);
			}
			return Null;
		}
	}
	internal sealed class OracleColumn
	{
		private OciParameterDescriptor _describeHandle;

		private int _ordinal;

		private string _columnName;

		private MetaType _metaType;

		private byte _precision;

		private byte _scale;

		private int _byteSize;

		private bool _isNullable;

		private int _indicatorOffset;

		private int _lengthOffset;

		private int _valueOffset;

		private NativeBuffer_RowBuffer _rowBuffer;

		private NativeBuffer_LongColumnData _longBuffer;

		private int _longLength;

		private OCI.Callback.OCICallbackDefine _callback;

		private OciLobLocator _lobLocator;

		private OracleConnection _connection;

		private int _connectionCloseCount;

		private bool _bindAsUTF16;

		internal string ColumnName => _columnName;

		internal bool IsNullable => _isNullable;

		internal bool IsLob => _metaType.IsLob;

		internal bool IsLong => _metaType.IsLong;

		internal OracleType OracleType => _metaType.OracleType;

		internal int Ordinal => _ordinal;

		internal byte Precision => _precision;

		internal byte Scale => _scale;

		internal int SchemaTableSize
		{
			get
			{
				if (!_bindAsUTF16 || _metaType.IsLong)
				{
					return _byteSize;
				}
				return _byteSize / 2;
			}
		}

		internal OracleColumn(OciStatementHandle statementHandle, int ordinal, OciErrorHandle errorHandle, OracleConnection connection)
		{
			_ordinal = ordinal;
			_describeHandle = statementHandle.GetDescriptor(_ordinal, errorHandle);
			_connection = connection;
			_connectionCloseCount = connection.CloseCount;
		}

		private int _callback_GetColumnPiecewise(IntPtr octxp, IntPtr defnp, uint iter, IntPtr bufpp, IntPtr alenp, IntPtr piecep, IntPtr indpp, IntPtr rcodep)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc._callback_GetColumnPiecewise|ADV|OCI> octxp=0x%-07Ix defnp=0x%-07Ix iter=%-2d bufpp=0x%-07Ix alenp=0x%-07Ix piecep=0x%-07Ix indpp=0x%-07Ix rcodep=0x%-07Ix\n", octxp, defnp, (int)iter, bufpp, alenp, piecep, indpp, rcodep);
			}
			IntPtr val = ((-1 != _indicatorOffset) ? _rowBuffer.DangerousGetDataPtr(_indicatorOffset) : IntPtr.Zero);
			IntPtr lengthPtr;
			IntPtr chunk = _longBuffer.GetChunk(out lengthPtr);
			Marshal.WriteIntPtr(bufpp, chunk);
			Marshal.WriteIntPtr(indpp, val);
			Marshal.WriteIntPtr(alenp, lengthPtr);
			Marshal.WriteInt32(lengthPtr, NativeBuffer_LongColumnData.MaxChunkSize);
			GC.KeepAlive(this);
			return -24200;
		}

		internal void Bind(OciStatementHandle statementHandle, NativeBuffer_RowBuffer buffer, OciErrorHandle errorHandle, int rowBufferLength)
		{
			OciDefineHandle handle = null;
			OCI.MODE mode = OCI.MODE.OCI_DEFAULT;
			OCI.DATATYPE ociType = _metaType.OciType;
			_rowBuffer = buffer;
			int value_sz;
			if (_metaType.IsLong)
			{
				mode = OCI.MODE.OCI_OBJECT;
				value_sz = int.MaxValue;
			}
			else
			{
				value_sz = _byteSize;
			}
			IntPtr indp = IntPtr.Zero;
			IntPtr rlenp = IntPtr.Zero;
			IntPtr valuep = _rowBuffer.DangerousGetDataPtr(_valueOffset);
			if (-1 != _indicatorOffset)
			{
				indp = _rowBuffer.DangerousGetDataPtr(_indicatorOffset);
			}
			if (-1 != _lengthOffset && !_metaType.IsLong)
			{
				rlenp = _rowBuffer.DangerousGetDataPtr(_lengthOffset);
			}
			checked
			{
				try
				{
					int num = TracedNativeMethods.OCIDefineByPos(statementHandle, out var hndlpp, errorHandle, (uint)_ordinal + 1u, valuep, value_sz, ociType, indp, rlenp, IntPtr.Zero, mode);
					if (num != 0)
					{
						_connection.CheckError(errorHandle, num);
					}
					handle = new OciDefineHandle(statementHandle, hndlpp);
					if (rowBufferLength != 0)
					{
						uint num2 = (uint)rowBufferLength;
						uint indskip = ((-1 != _indicatorOffset) ? num2 : 0u);
						uint rlskip = ((-1 != _lengthOffset && !_metaType.IsLong) ? num2 : 0u);
						num = TracedNativeMethods.OCIDefineArrayOfStruct(handle, errorHandle, num2, indskip, rlskip, 0u);
						if (num != 0)
						{
							_connection.CheckError(errorHandle, num);
						}
					}
					if (_metaType.UsesNationalCharacterSet)
					{
						handle.SetAttribute(OCI.ATTR.OCI_ATTR_CHARSET_FORM, 2, errorHandle);
					}
					if (!_connection.UnicodeEnabled && _bindAsUTF16)
					{
						handle.SetAttribute(OCI.ATTR.OCI_ATTR_CHARSET_ID, 1000, errorHandle);
					}
					if (_metaType.IsLong)
					{
						_rowBuffer.WriteIntPtr(_valueOffset, IntPtr.Zero);
						_callback = _callback_GetColumnPiecewise;
						num = TracedNativeMethods.OCIDefineDynamic(handle, errorHandle, IntPtr.Zero, _callback);
						if (num != 0)
						{
							_connection.CheckError(errorHandle, num);
						}
					}
				}
				finally
				{
					NativeBuffer.SafeDispose(ref _longBuffer);
					OciHandle.SafeDispose(ref handle);
				}
			}
		}

		internal bool Describe(ref int offset, OracleConnection connection, OciErrorHandle errorHandle)
		{
			bool flag = false;
			bool result = false;
			_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_SQLCODE, out _columnName, errorHandle, _connection);
			_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_OBJECT, out short value, errorHandle);
			_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_SESSION, out byte value2, errorHandle);
			_isNullable = 0 != value2;
			OCI.DATATYPE dATATYPE = (OCI.DATATYPE)value;
			switch (dATATYPE)
			{
			case OCI.DATATYPE.VARCHAR2:
			case OCI.DATATYPE.CHAR:
			{
				_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_FNCODE, out _byteSize, errorHandle);
				_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_CHARSET_FORM, out value2, errorHandle);
				OCI.CHARSETFORM cHARSETFORM = (OCI.CHARSETFORM)value2;
				_bindAsUTF16 = connection.ServerVersionAtLeastOracle8;
				int num;
				if (connection.ServerVersionAtLeastOracle9i && OCI.ClientVersionAtLeastOracle9i)
				{
					_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_CHAR_SIZE, out value, errorHandle);
					num = value;
				}
				else
				{
					num = _byteSize;
				}
				if (cHARSETFORM == OCI.CHARSETFORM.SQLCS_NCHAR)
				{
					_metaType = MetaType.GetMetaTypeForType((OCI.DATATYPE.CHAR == dATATYPE) ? OracleType.NChar : OracleType.NVarChar);
				}
				else
				{
					_metaType = MetaType.GetMetaTypeForType((OCI.DATATYPE.CHAR == dATATYPE) ? OracleType.Char : OracleType.VarChar);
					if (_bindAsUTF16)
					{
						_byteSize *= System.Data.Common.ADP.CharSize;
					}
				}
				_byteSize = Math.Max(_byteSize, num * System.Data.Common.ADP.CharSize);
				flag = true;
				break;
			}
			case OCI.DATATYPE.DATE:
				_metaType = MetaType.GetMetaTypeForType(OracleType.DateTime);
				_byteSize = _metaType.BindSize;
				flag = true;
				break;
			case OCI.DATATYPE.TIMESTAMP:
				_metaType = MetaType.GetMetaTypeForType(OracleType.Timestamp);
				_byteSize = _metaType.BindSize;
				flag = true;
				break;
			case OCI.DATATYPE.TIMESTAMP_LTZ:
				_metaType = MetaType.GetMetaTypeForType(OracleType.TimestampLocal);
				_byteSize = _metaType.BindSize;
				flag = true;
				break;
			case OCI.DATATYPE.TIMESTAMP_TZ:
				_metaType = MetaType.GetMetaTypeForType(OracleType.TimestampWithTZ);
				_byteSize = _metaType.BindSize;
				flag = true;
				break;
			case OCI.DATATYPE.INTERVAL_YM:
				_metaType = MetaType.GetMetaTypeForType(OracleType.IntervalYearToMonth);
				_byteSize = _metaType.BindSize;
				break;
			case OCI.DATATYPE.INTERVAL_DS:
				_metaType = MetaType.GetMetaTypeForType(OracleType.IntervalDayToSecond);
				_byteSize = _metaType.BindSize;
				break;
			case OCI.DATATYPE.NUMBER:
				_metaType = MetaType.GetMetaTypeForType(OracleType.Number);
				_byteSize = _metaType.BindSize;
				_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_ENV, out _precision, errorHandle);
				_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_SERVER, out _scale, errorHandle);
				break;
			case OCI.DATATYPE.RAW:
				_metaType = MetaType.GetMetaTypeForType(OracleType.Raw);
				_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_FNCODE, out _byteSize, errorHandle);
				flag = true;
				break;
			case OCI.DATATYPE.ROWID:
			case OCI.DATATYPE.ROWID_DESC:
			case OCI.DATATYPE.UROWID:
				_metaType = MetaType.GetMetaTypeForType(OracleType.RowId);
				_byteSize = _metaType.BindSize;
				if (connection.UnicodeEnabled)
				{
					_bindAsUTF16 = true;
					_byteSize *= System.Data.Common.ADP.CharSize;
				}
				flag = true;
				break;
			case OCI.DATATYPE.BFILE:
				_metaType = MetaType.GetMetaTypeForType(OracleType.BFile);
				_byteSize = _metaType.BindSize;
				result = true;
				break;
			case OCI.DATATYPE.BLOB:
				_metaType = MetaType.GetMetaTypeForType(OracleType.Blob);
				_byteSize = _metaType.BindSize;
				result = true;
				break;
			case OCI.DATATYPE.CLOB:
				_describeHandle.GetAttribute(OCI.ATTR.OCI_ATTR_CHARSET_FORM, out value2, errorHandle);
				_metaType = MetaType.GetMetaTypeForType((2 == value2) ? OracleType.NClob : OracleType.Clob);
				_byteSize = _metaType.BindSize;
				result = true;
				break;
			case OCI.DATATYPE.LONG:
				_metaType = MetaType.GetMetaTypeForType(OracleType.LongVarChar);
				_byteSize = _metaType.BindSize;
				flag = true;
				result = true;
				_bindAsUTF16 = connection.ServerVersionAtLeastOracle8;
				break;
			case OCI.DATATYPE.LONGRAW:
				_metaType = MetaType.GetMetaTypeForType(OracleType.LongRaw);
				_byteSize = _metaType.BindSize;
				flag = true;
				result = true;
				break;
			default:
				throw System.Data.Common.ADP.TypeNotSupported(dATATYPE);
			}
			if (_isNullable)
			{
				_indicatorOffset = offset;
				offset += IntPtr.Size;
			}
			else
			{
				_indicatorOffset = -1;
			}
			if (flag)
			{
				_lengthOffset = offset;
				offset += IntPtr.Size;
			}
			else
			{
				_lengthOffset = -1;
			}
			_valueOffset = offset;
			if (OCI.DATATYPE.LONG == dATATYPE || OCI.DATATYPE.LONGRAW == dATATYPE)
			{
				offset += IntPtr.Size;
			}
			else
			{
				offset += _byteSize;
			}
			offset = (offset + (IntPtr.Size - 1)) & ~(IntPtr.Size - 1);
			OciHandle.SafeDispose(ref _describeHandle);
			return result;
		}

		internal void Dispose()
		{
			NativeBuffer.SafeDispose(ref _longBuffer);
			OciLobLocator.SafeDispose(ref _lobLocator);
			OciHandle.SafeDispose(ref _describeHandle);
			_columnName = null;
			_metaType = null;
			_callback = null;
			_connection = null;
		}

		internal void FixupLongValueLength(NativeBuffer buffer)
		{
			if (_longBuffer != null && -1 == _longLength)
			{
				_longLength = _longBuffer.TotalLengthInBytes;
				if (_bindAsUTF16)
				{
					_longLength /= 2;
				}
				buffer.WriteInt32(_lengthOffset, _longLength);
			}
		}

		internal string GetDataTypeName()
		{
			return _metaType.DataTypeName;
		}

		internal Type GetFieldType()
		{
			return _metaType.BaseType;
		}

		internal Type GetFieldOracleType()
		{
			return _metaType.NoConvertType;
		}

		internal object GetValue(NativeBuffer_RowBuffer buffer)
		{
			if (IsDBNull(buffer))
			{
				return DBNull.Value;
			}
			switch (_metaType.OciType)
			{
			case OCI.DATATYPE.BFILE:
			{
				using OracleBFile oracleBFile = GetOracleBFile(buffer);
				return oracleBFile.Value;
			}
			case OCI.DATATYPE.RAW:
			case OCI.DATATYPE.LONGRAW:
			{
				long bytes = GetBytes(buffer, 0L, null, 0, 0);
				byte[] array = new byte[bytes];
				GetBytes(buffer, 0L, array, 0, (int)bytes);
				return array;
			}
			case OCI.DATATYPE.DATE:
			case OCI.DATATYPE.INT_TIMESTAMP:
			case OCI.DATATYPE.INT_TIMESTAMP_TZ:
			case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
				return GetDateTime(buffer);
			case OCI.DATATYPE.CLOB:
			case OCI.DATATYPE.BLOB:
			{
				using OracleLob oracleLob = GetOracleLob(buffer);
				return oracleLob.Value;
			}
			case OCI.DATATYPE.INT_INTERVAL_YM:
				return GetInt32(buffer);
			case OCI.DATATYPE.VARNUM:
				return GetDecimal(buffer);
			case OCI.DATATYPE.VARCHAR2:
			case OCI.DATATYPE.LONG:
			case OCI.DATATYPE.CHAR:
				return GetString(buffer);
			case OCI.DATATYPE.INT_INTERVAL_DS:
				return GetTimeSpan(buffer);
			default:
				throw System.Data.Common.ADP.TypeNotSupported(_metaType.OciType);
			}
		}

		internal object GetOracleValue(NativeBuffer_RowBuffer buffer)
		{
			switch (_metaType.OciType)
			{
			case OCI.DATATYPE.BFILE:
				return GetOracleBFile(buffer);
			case OCI.DATATYPE.RAW:
			case OCI.DATATYPE.LONGRAW:
				return GetOracleBinary(buffer);
			case OCI.DATATYPE.DATE:
			case OCI.DATATYPE.INT_TIMESTAMP:
			case OCI.DATATYPE.INT_TIMESTAMP_TZ:
			case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
				return GetOracleDateTime(buffer);
			case OCI.DATATYPE.CLOB:
			case OCI.DATATYPE.BLOB:
				return GetOracleLob(buffer);
			case OCI.DATATYPE.INT_INTERVAL_YM:
				return GetOracleMonthSpan(buffer);
			case OCI.DATATYPE.VARNUM:
				return GetOracleNumber(buffer);
			case OCI.DATATYPE.VARCHAR2:
			case OCI.DATATYPE.LONG:
			case OCI.DATATYPE.CHAR:
				return GetOracleString(buffer);
			case OCI.DATATYPE.INT_INTERVAL_DS:
				return GetOracleTimeSpan(buffer);
			default:
				throw System.Data.Common.ADP.TypeNotSupported(_metaType.OciType);
			}
		}

		internal long GetBytes(NativeBuffer_RowBuffer buffer, long fieldOffset, byte[] destinationBuffer, int destinationOffset, int length)
		{
			if (length < 0)
			{
				throw System.Data.Common.ADP.InvalidDataLength(length);
			}
			if (destinationOffset < 0 || (destinationBuffer != null && destinationOffset >= destinationBuffer.Length))
			{
				throw System.Data.Common.ADP.InvalidDestinationBufferIndex(destinationBuffer.Length, destinationOffset, "bufferoffset");
			}
			if (0 > fieldOffset || uint.MaxValue < fieldOffset)
			{
				throw System.Data.Common.ADP.InvalidSourceOffset("fieldOffset", 0L, 4294967295L);
			}
			int num3;
			if (IsLob)
			{
				OracleType oracleType = _metaType.OracleType;
				if (OracleType.Blob != oracleType && OracleType.BFile != oracleType)
				{
					throw System.Data.Common.ADP.InvalidCast();
				}
				if (IsDBNull(buffer))
				{
					throw System.Data.Common.ADP.DataReaderNoData();
				}
				using OracleLob oracleLob = new OracleLob(_lobLocator);
				uint num = (uint)oracleLob.Length;
				uint num2 = (uint)fieldOffset;
				if (num2 > num)
				{
					throw System.Data.Common.ADP.InvalidSourceBufferIndex((int)num, (int)num2, "fieldOffset");
				}
				num3 = (int)(num - num2);
				if (destinationBuffer != null)
				{
					num3 = Math.Min(num3, length);
					if (0 < num3)
					{
						oracleLob.Seek(num2, SeekOrigin.Begin);
						oracleLob.Read(destinationBuffer, destinationOffset, num3);
					}
				}
			}
			else
			{
				if (OracleType.Raw != OracleType && OracleType.LongRaw != OracleType)
				{
					throw System.Data.Common.ADP.InvalidCast();
				}
				if (IsDBNull(buffer))
				{
					throw System.Data.Common.ADP.DataReaderNoData();
				}
				FixupLongValueLength(buffer);
				int length2 = OracleBinary.GetLength(buffer, _lengthOffset, _metaType);
				int num4 = (int)fieldOffset;
				num3 = length2 - num4;
				if (destinationBuffer != null)
				{
					num3 = Math.Min(num3, length);
					if (0 < num3)
					{
						OracleBinary.GetBytes(buffer, _valueOffset, _metaType, num4, destinationBuffer, destinationOffset, num3);
					}
				}
			}
			return Math.Max(0, num3);
		}

		internal long GetChars(NativeBuffer_RowBuffer buffer, long fieldOffset, char[] destinationBuffer, int destinationOffset, int length)
		{
			if (length < 0)
			{
				throw System.Data.Common.ADP.InvalidDataLength(length);
			}
			if (destinationOffset < 0 || (destinationBuffer != null && destinationOffset >= destinationBuffer.Length))
			{
				throw System.Data.Common.ADP.InvalidDestinationBufferIndex(destinationBuffer.Length, destinationOffset, "bufferoffset");
			}
			if (0 > fieldOffset || uint.MaxValue < fieldOffset)
			{
				throw System.Data.Common.ADP.InvalidSourceOffset("fieldOffset", 0L, 4294967295L);
			}
			int num2;
			if (IsLob)
			{
				OracleType oracleType = _metaType.OracleType;
				if (OracleType.Clob != oracleType && OracleType.NClob != oracleType && OracleType.BFile != oracleType)
				{
					throw System.Data.Common.ADP.InvalidCast();
				}
				if (IsDBNull(buffer))
				{
					throw System.Data.Common.ADP.DataReaderNoData();
				}
				using OracleLob oracleLob = new OracleLob(_lobLocator);
				string text = (string)oracleLob.Value;
				int length2 = text.Length;
				int num = (int)fieldOffset;
				if (num < 0)
				{
					throw System.Data.Common.ADP.InvalidSourceBufferIndex(length2, num, "fieldOffset");
				}
				num2 = length2 - num;
				if (destinationBuffer != null)
				{
					num2 = Math.Min(num2, length);
					if (0 < num2)
					{
						char[] src = text.ToCharArray(num, num2);
						Buffer.BlockCopy(src, 0, destinationBuffer, destinationOffset, num2);
					}
				}
			}
			else
			{
				if (OracleType.Char != OracleType && OracleType.VarChar != OracleType && OracleType.LongVarChar != OracleType && OracleType.NChar != OracleType && OracleType.NVarChar != OracleType)
				{
					throw System.Data.Common.ADP.InvalidCast();
				}
				if (IsDBNull(buffer))
				{
					throw System.Data.Common.ADP.DataReaderNoData();
				}
				FixupLongValueLength(buffer);
				int length3 = OracleString.GetLength(buffer, _lengthOffset, _metaType);
				int num3 = (int)fieldOffset;
				num2 = length3 - num3;
				if (destinationBuffer != null)
				{
					num2 = Math.Min(num2, length);
					if (0 < num2)
					{
						OracleString.GetChars(buffer, _valueOffset, _lengthOffset, _metaType, _connection, _bindAsUTF16, num3, destinationBuffer, destinationOffset, num2);
					}
				}
			}
			return Math.Max(0, num2);
		}

		internal DateTime GetDateTime(NativeBuffer_RowBuffer buffer)
		{
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			if (typeof(DateTime) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			return OracleDateTime.MarshalToDateTime(buffer, _valueOffset, _lengthOffset, _metaType, _connection);
		}

		internal decimal GetDecimal(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(decimal) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			return OracleNumber.MarshalToDecimal(buffer, _valueOffset, _connection);
		}

		internal double GetDouble(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(decimal) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			decimal num = OracleNumber.MarshalToDecimal(buffer, _valueOffset, _connection);
			return (double)num;
		}

		internal float GetFloat(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(decimal) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			decimal num = OracleNumber.MarshalToDecimal(buffer, _valueOffset, _connection);
			return (float)num;
		}

		internal int GetInt32(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(int) != _metaType.BaseType && typeof(decimal) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			if (typeof(int) == _metaType.BaseType)
			{
				return OracleMonthSpan.MarshalToInt32(buffer, _valueOffset);
			}
			return OracleNumber.MarshalToInt32(buffer, _valueOffset, _connection);
		}

		internal long GetInt64(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(decimal) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			return OracleNumber.MarshalToInt64(buffer, _valueOffset, _connection);
		}

		internal string GetString(NativeBuffer_RowBuffer buffer)
		{
			if (IsLob)
			{
				OracleType oracleType = _metaType.OracleType;
				if (OracleType.Clob != oracleType && OracleType.NClob != oracleType && OracleType.BFile != oracleType)
				{
					throw System.Data.Common.ADP.InvalidCast();
				}
				if (IsDBNull(buffer))
				{
					throw System.Data.Common.ADP.DataReaderNoData();
				}
				using OracleLob oracleLob = new OracleLob(_lobLocator);
				return (string)oracleLob.Value;
			}
			if (typeof(string) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			FixupLongValueLength(buffer);
			return OracleString.MarshalToString(buffer, _valueOffset, _lengthOffset, _metaType, _connection, _bindAsUTF16, outputParameterBinding: false);
		}

		internal TimeSpan GetTimeSpan(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(TimeSpan) != _metaType.BaseType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
			return OracleTimeSpan.MarshalToTimeSpan(buffer, _valueOffset);
		}

		internal OracleBFile GetOracleBFile(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleBFile) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				return OracleBFile.Null;
			}
			return new OracleBFile(_lobLocator);
		}

		internal OracleBinary GetOracleBinary(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleBinary) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			FixupLongValueLength(buffer);
			if (IsDBNull(buffer))
			{
				return OracleBinary.Null;
			}
			return new OracleBinary(buffer, _valueOffset, _lengthOffset, _metaType);
		}

		internal OracleDateTime GetOracleDateTime(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleDateTime) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				return OracleDateTime.Null;
			}
			return new OracleDateTime(buffer, _valueOffset, _lengthOffset, _metaType, _connection);
		}

		internal OracleLob GetOracleLob(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleLob) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				return OracleLob.Null;
			}
			return new OracleLob(_lobLocator);
		}

		internal OracleMonthSpan GetOracleMonthSpan(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleMonthSpan) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				return OracleMonthSpan.Null;
			}
			return new OracleMonthSpan(buffer, _valueOffset);
		}

		internal OracleNumber GetOracleNumber(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleNumber) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				return OracleNumber.Null;
			}
			return new OracleNumber(buffer, _valueOffset);
		}

		internal OracleString GetOracleString(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleString) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				return OracleString.Null;
			}
			FixupLongValueLength(buffer);
			return new OracleString(buffer, _valueOffset, _lengthOffset, _metaType, _connection, _bindAsUTF16, outputParameterBinding: false);
		}

		internal OracleTimeSpan GetOracleTimeSpan(NativeBuffer_RowBuffer buffer)
		{
			if (typeof(OracleTimeSpan) != _metaType.NoConvertType)
			{
				throw System.Data.Common.ADP.InvalidCast();
			}
			if (IsDBNull(buffer))
			{
				return OracleTimeSpan.Null;
			}
			return new OracleTimeSpan(buffer, _valueOffset);
		}

		internal bool IsDBNull(NativeBuffer_RowBuffer buffer)
		{
			if (_isNullable)
			{
				return buffer.ReadInt16(_indicatorOffset) == -1;
			}
			return false;
		}

		internal void Rebind(OracleConnection connection, ref bool mustRelease, ref SafeHandle handleToBind)
		{
			handleToBind = null;
			switch (_metaType.OciType)
			{
			case OCI.DATATYPE.LONG:
			case OCI.DATATYPE.LONGRAW:
				_rowBuffer.WriteInt32(_lengthOffset, 0);
				_longLength = -1;
				if (_longBuffer != null)
				{
					_longBuffer.Reset();
				}
				else
				{
					_longBuffer = new NativeBuffer_LongColumnData();
				}
				handleToBind = _longBuffer;
				break;
			case OCI.DATATYPE.CLOB:
			case OCI.DATATYPE.BLOB:
			case OCI.DATATYPE.BFILE:
				OciLobLocator.SafeDispose(ref _lobLocator);
				_lobLocator = new OciLobLocator(connection, _metaType.OracleType);
				handleToBind = _lobLocator.Descriptor;
				break;
			}
			if (handleToBind != null)
			{
				handleToBind.DangerousAddRef(ref mustRelease);
				_rowBuffer.WriteIntPtr(_valueOffset, handleToBind.DangerousGetHandle());
			}
		}
	}
	[ToolboxItem(true)]
	[Designer("Microsoft.VSDesigner.Data.VS.OracleCommandDesigner, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
	[DefaultEvent("RecordsAffected")]
	public sealed class OracleCommand : DbCommand, ICloneable
	{
		private static int _objectTypeCount;

		internal readonly int _objectID = Interlocked.Increment(ref _objectTypeCount);

		private string _commandText;

		private CommandType _commandType;

		private UpdateRowSource _updatedRowSource = UpdateRowSource.Both;

		private bool _designTimeInvisible;

		private OracleConnection _connection;

		private OciStatementHandle _preparedStatementHandle;

		private int _preparedAtCloseCount;

		private OracleParameterCollection _parameterCollection;

		private OCI.STMT _statementType;

		private OracleTransaction _transaction;

		[Editor("Microsoft.VSDesigner.Data.Oracle.Design.OracleCommandTextEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("OracleCategory_Data")]
		[DefaultValue("")]
		[ResDescription("DbCommand_CommandText")]
		public override string CommandText
		{
			get
			{
				string commandText = _commandText;
				if (commandText == null)
				{
					return System.Data.Common.ADP.StrEmpty;
				}
				return commandText;
			}
			set
			{
				if (Bid.TraceOn)
				{
					Bid.Trace("<ora.OracleCommand.set_CommandText|API> %d#, '", ObjectID);
					Bid.PutStr(value);
					Bid.Trace("'\n");
				}
				if (System.Data.Common.ADP.SrcCompare(_commandText, value) != 0)
				{
					PropertyChanging();
					_commandText = value;
				}
			}
		}

		[ResCategory("OracleCategory_Data")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		[ResDescription("DbCommand_CommandTimeout")]
		public override int CommandTimeout
		{
			get
			{
				return 0;
			}
			set
			{
			}
		}

		[RefreshProperties(RefreshProperties.All)]
		[DefaultValue(CommandType.Text)]
		[ResDescription("DbCommand_CommandType")]
		[ResCategory("OracleCategory_Data")]
		public override CommandType CommandType
		{
			get
			{
				CommandType commandType = _commandType;
				if (commandType == (CommandType)0)
				{
					return CommandType.Text;
				}
				return commandType;
			}
			set
			{
				if (_commandType != value)
				{
					switch (value)
					{
					case CommandType.Text:
					case CommandType.StoredProcedure:
						PropertyChanging();
						_commandType = value;
						break;
					case CommandType.TableDirect:
						throw System.Data.Common.ADP.NoOptimizedDirectTableAccess();
					default:
						throw System.Data.Common.ADP.InvalidCommandType(value);
					}
				}
			}
		}

		[ResCategory("OracleCategory_Behavior")]
		[ResDescription("DbCommand_Connection")]
		[DefaultValue(null)]
		[Editor("Microsoft.VSDesigner.Data.Design.DbConnectionEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public new OracleConnection Connection
		{
			get
			{
				return _connection;
			}
			set
			{
				if (_connection != value)
				{
					PropertyChanging();
					_connection = value;
				}
			}
		}

		private bool ConnectionIsClosed
		{
			get
			{
				OracleConnection connection = Connection;
				if (connection != null)
				{
					return ConnectionState.Closed == connection.State;
				}
				return true;
			}
		}

		protected override DbConnection DbConnection
		{
			get
			{
				return Connection;
			}
			set
			{
				Connection = (OracleConnection)value;
			}
		}

		protected override DbParameterCollection DbParameterCollection => Parameters;

		protected override DbTransaction DbTransaction
		{
			get
			{
				return Transaction;
			}
			set
			{
				Transaction = (OracleTransaction)value;
			}
		}

		[Browsable(false)]
		[DesignOnly(true)]
		[DefaultValue(true)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		public override bool DesignTimeVisible
		{
			get
			{
				return !_designTimeInvisible;
			}
			set
			{
				_designTimeInvisible = !value;
				TypeDescriptor.Refresh(this);
			}
		}

		private OciEnvironmentHandle EnvironmentHandle => _connection.EnvironmentHandle;

		private OciErrorHandle ErrorHandle => _connection.ErrorHandle;

		internal int ObjectID => _objectID;

		[ResCategory("OracleCategory_Data")]
		[ResDescription("DbCommand_Parameters")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Content)]
		public new OracleParameterCollection Parameters
		{
			get
			{
				if (_parameterCollection == null)
				{
					_parameterCollection = new OracleParameterCollection();
				}
				return _parameterCollection;
			}
		}

		internal string StatementText
		{
			get
			{
				string result = null;
				string commandText = CommandText;
				if (System.Data.Common.ADP.IsEmpty(commandText))
				{
					throw System.Data.Common.ADP.NoCommandText();
				}
				switch (CommandType)
				{
				case CommandType.StoredProcedure:
				{
					StringBuilder stringBuilder = new StringBuilder();
					stringBuilder.Append("begin ");
					int count = Parameters.Count;
					int num = 0;
					for (int i = 0; i < count; i++)
					{
						OracleParameter oracleParameter = Parameters[i];
						if (System.Data.Common.ADP.IsDirection(oracleParameter, ParameterDirection.ReturnValue))
						{
							stringBuilder.Append(":");
							stringBuilder.Append(oracleParameter.ParameterName);
							stringBuilder.Append(" := ");
						}
					}
					stringBuilder.Append(commandText);
					string value = "(";
					for (int j = 0; j < count; j++)
					{
						OracleParameter oracleParameter2 = Parameters[j];
						if (!System.Data.Common.ADP.IsDirection(oracleParameter2, ParameterDirection.ReturnValue) && (System.Data.Common.ADP.IsDirection(oracleParameter2, ParameterDirection.Output) || oracleParameter2.Value != null) && (oracleParameter2.Value != null || System.Data.Common.ADP.IsDirection(oracleParameter2, ParameterDirection.Output)))
						{
							stringBuilder.Append(value);
							value = ", ";
							num++;
							stringBuilder.Append(oracleParameter2.ParameterName);
							stringBuilder.Append("=>:");
							stringBuilder.Append(oracleParameter2.ParameterName);
						}
					}
					if (num != 0)
					{
						stringBuilder.Append("); end;");
					}
					else
					{
						stringBuilder.Append("; end;");
					}
					result = stringBuilder.ToString();
					break;
				}
				case CommandType.Text:
					result = commandText;
					break;
				}
				return result;
			}
		}

		private OciServiceContextHandle ServiceContextHandle => _connection.ServiceContextHandle;

		internal OCI.STMT StatementType => _statementType;

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[ResDescription("DbCommand_Transaction")]
		[Browsable(false)]
		public new OracleTransaction Transaction
		{
			get
			{
				if (_transaction != null && _transaction.Connection == null)
				{
					_transaction = null;
				}
				return _transaction;
			}
			set
			{
				_transaction = value;
			}
		}

		[DefaultValue(UpdateRowSource.Both)]
		[ResCategory("DataCategory_Update")]
		[ResDescription("DbCommand_UpdatedRowSource")]
		public override UpdateRowSource UpdatedRowSource
		{
			get
			{
				return _updatedRowSource;
			}
			set
			{
				switch (value)
				{
				case UpdateRowSource.None:
				case UpdateRowSource.OutputParameters:
				case UpdateRowSource.FirstReturnedRecord:
				case UpdateRowSource.Both:
					_updatedRowSource = value;
					break;
				default:
					throw System.Data.Common.ADP.InvalidUpdateRowSource(value);
				}
			}
		}

		public OracleCommand()
		{
			GC.SuppressFinalize(this);
		}

		public OracleCommand(string commandText)
			: this()
		{
			CommandText = commandText;
		}

		public OracleCommand(string commandText, OracleConnection connection)
			: this()
		{
			CommandText = commandText;
			Connection = connection;
		}

		public OracleCommand(string commandText, OracleConnection connection, OracleTransaction tx)
			: this()
		{
			CommandText = commandText;
			Connection = connection;
			Transaction = tx;
		}

		private OracleCommand(OracleCommand command)
			: this()
		{
			CommandText = command.CommandText;
			CommandType = command.CommandType;
			Connection = command.Connection;
			DesignTimeVisible = command.DesignTimeVisible;
			UpdatedRowSource = command.UpdatedRowSource;
			Transaction = command.Transaction;
			if (command._parameterCollection == null || 0 >= command._parameterCollection.Count)
			{
				return;
			}
			OracleParameterCollection parameters = Parameters;
			foreach (ICloneable parameter in command.Parameters)
			{
				parameters.Add(parameter.Clone());
			}
		}

		public void ResetCommandTimeout()
		{
		}

		private bool ShouldSerializeCommandTimeout()
		{
			return false;
		}

		public override void Cancel()
		{
			Bid.ScopeEnter(out var hScp, "<ora.OracleCommand.Cancel|API> %d#\n", ObjectID);
			try
			{
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		public object Clone()
		{
			OracleCommand oracleCommand = new OracleCommand(this);
			Bid.Trace("<ora.OracleCommand.Clone|API> %d#, clone=%d#\n", ObjectID, oracleCommand.ObjectID);
			return oracleCommand;
		}

		public new OracleParameter CreateParameter()
		{
			return new OracleParameter();
		}

		protected override DbParameter CreateDbParameter()
		{
			return CreateParameter();
		}

		internal string Execute(OciStatementHandle statementHandle, CommandBehavior behavior, out ArrayList resultParameterOrdinals)
		{
			OciRowidDescriptor rowidDescriptor;
			return Execute(statementHandle, behavior, needRowid: false, out rowidDescriptor, out resultParameterOrdinals);
		}

		internal string Execute(OciStatementHandle statementHandle, CommandBehavior behavior, bool needRowid, out OciRowidDescriptor rowidDescriptor, out ArrayList resultParameterOrdinals)
		{
			if (ConnectionIsClosed)
			{
				throw System.Data.Common.ADP.ClosedConnectionError();
			}
			if (_transaction == null && Connection.Transaction != null)
			{
				throw System.Data.Common.ADP.TransactionRequired();
			}
			if (_transaction != null && _transaction.Connection != null && Connection != _transaction.Connection)
			{
				throw System.Data.Common.ADP.TransactionConnectionMismatch();
			}
			rowidDescriptor = null;
			Connection.RollbackDeadTransaction();
			int num = 0;
			NativeBuffer nativeBuffer = null;
			bool success = false;
			bool[] array = null;
			SafeHandle[] array2 = null;
			OracleParameterBinding[] array3 = null;
			string text = null;
			resultParameterOrdinals = null;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				if (_preparedStatementHandle != statementHandle)
				{
					text = StatementText;
					num = TracedNativeMethods.OCIStmtPrepare(statementHandle, ErrorHandle, text, OCI.SYNTAX.OCI_NTV_SYNTAX, OCI.MODE.OCI_DEFAULT, Connection);
					if (num != 0)
					{
						Connection.CheckError(ErrorHandle, num);
					}
				}
				statementHandle.GetAttribute(OCI.ATTR.OCI_ATTR_STMT_TYPE, out short value, ErrorHandle);
				_statementType = (OCI.STMT)value;
				int num2;
				if (OCI.STMT.OCI_STMT_SELECT != _statementType)
				{
					num2 = 1;
				}
				else
				{
					num2 = 0;
					if (CommandBehavior.SingleRow != behavior)
					{
						statementHandle.SetAttribute(OCI.ATTR.OCI_ATTR_PREFETCH_ROWS, 0, ErrorHandle);
						statementHandle.SetAttribute(OCI.ATTR.OCI_ATTR_PREFETCH_MEMORY, 0, ErrorHandle);
					}
				}
				OCI.MODE mODE = OCI.MODE.OCI_DEFAULT;
				if (num2 == 0)
				{
					if (IsBehavior(behavior, CommandBehavior.SchemaOnly))
					{
						mODE |= OCI.MODE.OCI_SHARED;
					}
				}
				else if (_connection.TransactionState == TransactionState.AutoCommit)
				{
					mODE |= OCI.MODE.OCI_COMMIT_ON_SUCCESS;
				}
				else if (TransactionState.GlobalStarted != _connection.TransactionState)
				{
					_connection.TransactionState = TransactionState.LocalStarted;
				}
				if ((mODE & OCI.MODE.OCI_SHARED) == 0 && _parameterCollection != null && _parameterCollection.Count > 0)
				{
					int offset = 0;
					int count = _parameterCollection.Count;
					array = new bool[count];
					array2 = new SafeHandle[count];
					array3 = new OracleParameterBinding[count];
					for (int i = 0; i < count; i++)
					{
						array3[i] = new OracleParameterBinding(this, _parameterCollection[i]);
						array3[i].PrepareForBind(_connection, ref offset);
						if (OracleType.Cursor == _parameterCollection[i].OracleType || 0 < _parameterCollection[i].CommandSetResult)
						{
							if (resultParameterOrdinals == null)
							{
								resultParameterOrdinals = new ArrayList();
							}
							resultParameterOrdinals.Add(i);
						}
					}
					nativeBuffer = new NativeBuffer_ParameterBuffer(offset);
					nativeBuffer.DangerousAddRef(ref success);
					for (int j = 0; j < count; j++)
					{
						array3[j].Bind(statementHandle, nativeBuffer, _connection, ref array[j], ref array2[j]);
					}
				}
				num = TracedNativeMethods.OCIStmtExecute(ServiceContextHandle, statementHandle, ErrorHandle, num2, mODE);
				if (num != 0)
				{
					Connection.CheckError(ErrorHandle, num);
				}
				if (array3 != null)
				{
					int num3 = array3.Length;
					for (int k = 0; k < num3; k++)
					{
						array3[k].PostExecute(nativeBuffer, _connection);
						array3[k].Dispose();
						array3[k] = null;
					}
					array3 = null;
				}
				if (needRowid)
				{
					if ((mODE & OCI.MODE.OCI_SHARED) == 0)
					{
						switch (_statementType)
						{
						case OCI.STMT.OCI_STMT_UPDATE:
						case OCI.STMT.OCI_STMT_DELETE:
						case OCI.STMT.OCI_STMT_INSERT:
							rowidDescriptor = statementHandle.GetRowid(EnvironmentHandle, ErrorHandle);
							return text;
						default:
							rowidDescriptor = null;
							return text;
						}
					}
					return text;
				}
				return text;
			}
			finally
			{
				if (success)
				{
					nativeBuffer.DangerousRelease();
				}
				if (nativeBuffer != null)
				{
					nativeBuffer.Dispose();
					nativeBuffer = null;
				}
				if (array3 != null)
				{
					int num4 = array3.Length;
					for (int l = 0; l < num4; l++)
					{
						if (array3[l] != null)
						{
							array3[l].Dispose();
							array3[l] = null;
						}
					}
					array3 = null;
				}
				if (array != null && array2 != null)
				{
					int num5 = array.Length;
					for (int m = 0; m < num5; m++)
					{
						if (array[m])
						{
							array2[m].DangerousRelease();
						}
					}
				}
			}
		}

		protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
		{
			return ExecuteReader(behavior);
		}

		public override int ExecuteNonQuery()
		{
			OracleConnection.ExecutePermission.Demand();
			Bid.ScopeEnter(out var hScp, "<ora.OracleCommand.ExecuteNonQuery|API> %d#\n", ObjectID);
			try
			{
				OciRowidDescriptor rowidDescriptor = null;
				int result = ExecuteNonQueryInternal(needRowid: false, out rowidDescriptor);
				OciHandle.SafeDispose(ref rowidDescriptor);
				return result;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private int ExecuteNonQueryInternal(bool needRowid, out OciRowidDescriptor rowidDescriptor)
		{
			//Discarded unreachable code: IL_00aa
			OciStatementHandle ociStatementHandle = null;
			int value = -1;
			try
			{
				try
				{
					ArrayList resultParameterOrdinals = new ArrayList();
					ociStatementHandle = GetStatementHandle();
					Execute(ociStatementHandle, CommandBehavior.Default, needRowid, out rowidDescriptor, out resultParameterOrdinals);
					if (resultParameterOrdinals != null)
					{
						value = 0;
						{
							foreach (int item in resultParameterOrdinals)
							{
								OracleParameter oracleParameter = _parameterCollection[item];
								if (OracleType.Cursor != oracleParameter.OracleType)
								{
									value += (int)oracleParameter.Value;
								}
							}
							return value;
						}
					}
					if (OCI.STMT.OCI_STMT_SELECT != _statementType)
					{
						ociStatementHandle.GetAttribute(OCI.ATTR.OCI_ATTR_ROW_COUNT, out value, ErrorHandle);
						return value;
					}
					return value;
				}
				finally
				{
					if (ociStatementHandle != null)
					{
						ReleaseStatementHandle(ociStatementHandle);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		public int ExecuteOracleNonQuery(out OracleString rowid)
		{
			OracleConnection.ExecutePermission.Demand();
			Bid.ScopeEnter(out var hScp, "<ora.OracleCommand.ExecuteOracleNonQuery|API> %d#\n", ObjectID);
			try
			{
				OciRowidDescriptor rowidDescriptor = null;
				int result = ExecuteNonQueryInternal(needRowid: true, out rowidDescriptor);
				rowid = GetPersistedRowid(Connection, rowidDescriptor);
				OciHandle.SafeDispose(ref rowidDescriptor);
				return result;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		public object ExecuteOracleScalar()
		{
			OracleConnection.ExecutePermission.Demand();
			Bid.ScopeEnter(out var hScp, "<ora.OracleCommand.ExecuteOracleScalar|API> %d#", ObjectID);
			try
			{
				OciRowidDescriptor rowidDescriptor = null;
				object result = ExecuteScalarInternal(needCLStype: false, needRowid: false, out rowidDescriptor);
				OciHandle.SafeDispose(ref rowidDescriptor);
				return result;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		public new OracleDataReader ExecuteReader()
		{
			return ExecuteReader(CommandBehavior.Default);
		}

		public new OracleDataReader ExecuteReader(CommandBehavior behavior)
		{
			OracleConnection.ExecutePermission.Demand();
			Bid.ScopeEnter(out var hScp, "<ora.OracleCommand.ExecuteReader|API> %d#, behavior=%d{ds.CommandBehavior}\n", ObjectID, (int)behavior);
			try
			{
				OciStatementHandle ociStatementHandle = null;
				OracleDataReader oracleDataReader = null;
				ArrayList resultParameterOrdinals = null;
				try
				{
					ociStatementHandle = GetStatementHandle();
					string statementText = Execute(ociStatementHandle, behavior, out resultParameterOrdinals);
					if (ociStatementHandle == _preparedStatementHandle)
					{
						_preparedStatementHandle = null;
					}
					oracleDataReader = ((resultParameterOrdinals != null) ? new OracleDataReader(this, resultParameterOrdinals, statementText, behavior) : new OracleDataReader(this, ociStatementHandle, statementText, behavior));
				}
				finally
				{
					if (ociStatementHandle != null && (oracleDataReader == null || resultParameterOrdinals != null))
					{
						ReleaseStatementHandle(ociStatementHandle);
					}
				}
				return oracleDataReader;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		public override object ExecuteScalar()
		{
			OracleConnection.ExecutePermission.Demand();
			Bid.ScopeEnter(out var hScp, "<ora.OracleCommand.ExecuteScalar|API> %d#\n", ObjectID);
			try
			{
				OciRowidDescriptor rowidDescriptor;
				object result = ExecuteScalarInternal(needCLStype: true, needRowid: false, out rowidDescriptor);
				OciHandle.SafeDispose(ref rowidDescriptor);
				return result;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private object ExecuteScalarInternal(bool needCLStype, bool needRowid, out OciRowidDescriptor rowidDescriptor)
		{
			OciStatementHandle ociStatementHandle = null;
			object result = null;
			int num = 0;
			try
			{
				ociStatementHandle = GetStatementHandle();
				ArrayList resultParameterOrdinals = new ArrayList();
				Execute(ociStatementHandle, CommandBehavior.Default, needRowid, out rowidDescriptor, out resultParameterOrdinals);
				if (OCI.STMT.OCI_STMT_SELECT == _statementType)
				{
					OracleColumn oracleColumn = new OracleColumn(ociStatementHandle, 0, ErrorHandle, _connection);
					int offset = 0;
					bool success = false;
					bool mustRelease = false;
					SafeHandle handleToBind = null;
					oracleColumn.Describe(ref offset, _connection, ErrorHandle);
					NativeBuffer_RowBuffer nativeBuffer_RowBuffer = new NativeBuffer_RowBuffer(offset, 1);
					RuntimeHelpers.PrepareConstrainedRegions();
					try
					{
						nativeBuffer_RowBuffer.DangerousAddRef(ref success);
						oracleColumn.Bind(ociStatementHandle, nativeBuffer_RowBuffer, ErrorHandle, 0);
						oracleColumn.Rebind(_connection, ref mustRelease, ref handleToBind);
						num = TracedNativeMethods.OCIStmtFetch(ociStatementHandle, ErrorHandle, 1, OCI.FETCH.OCI_FETCH_NEXT, OCI.MODE.OCI_DEFAULT);
						if (100 != num)
						{
							if (num != 0)
							{
								Connection.CheckError(ErrorHandle, num);
							}
							result = ((!needCLStype) ? oracleColumn.GetOracleValue(nativeBuffer_RowBuffer) : oracleColumn.GetValue(nativeBuffer_RowBuffer));
						}
					}
					finally
					{
						if (mustRelease)
						{
							handleToBind.DangerousRelease();
						}
						if (success)
						{
							nativeBuffer_RowBuffer.DangerousRelease();
						}
					}
					GC.KeepAlive(oracleColumn);
					return result;
				}
				return result;
			}
			finally
			{
				if (ociStatementHandle != null)
				{
					ReleaseStatementHandle(ociStatementHandle);
				}
			}
		}

		internal static OracleString GetPersistedRowid(OracleConnection connection, OciRowidDescriptor rowidHandle)
		{
			OracleString @null = OracleString.Null;
			if (rowidHandle != null)
			{
				OciErrorHandle errorHandle = connection.ErrorHandle;
				NativeBuffer scratchBuffer = connection.GetScratchBuffer(3970);
				bool success = false;
				bool success2 = false;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					scratchBuffer.DangerousAddRef(ref success);
					if (OCI.ClientVersionAtLeastOracle9i)
					{
						int bufferLength = scratchBuffer.Length;
						int num = TracedNativeMethods.OCIRowidToChar(rowidHandle, scratchBuffer, ref bufferLength, errorHandle);
						if (num != 0)
						{
							connection.CheckError(errorHandle, num);
						}
						string s = scratchBuffer.PtrToStringAnsi(0, bufferLength);
						return new OracleString(s);
					}
					rowidHandle.DangerousAddRef(ref success2);
					OciServiceContextHandle serviceContextHandle = connection.ServiceContextHandle;
					OciStatementHandle handle = new OciStatementHandle(serviceContextHandle);
					string stmt = "begin :rowid := :rdesc; end;";
					int offset = 0;
					int offset2 = 4;
					int offset3 = 8;
					int offset4 = 12;
					int num2 = 16;
					int num3 = 20;
					try
					{
						int num = TracedNativeMethods.OCIStmtPrepare(handle, errorHandle, stmt, OCI.SYNTAX.OCI_NTV_SYNTAX, OCI.MODE.OCI_DEFAULT, connection);
						if (num != 0)
						{
							connection.CheckError(errorHandle, num);
						}
						scratchBuffer.WriteIntPtr(offset3, rowidHandle.DangerousGetHandle());
						scratchBuffer.WriteInt32(offset, 0);
						scratchBuffer.WriteInt32(offset2, 4);
						scratchBuffer.WriteInt32(offset4, 0);
						scratchBuffer.WriteInt32(num2, 3950);
						num = TracedNativeMethods.OCIBindByName(handle, out var _, errorHandle, "rowid", 5, scratchBuffer.DangerousGetDataPtr(num3), 3950, OCI.DATATYPE.VARCHAR2, scratchBuffer.DangerousGetDataPtr(offset4), scratchBuffer.DangerousGetDataPtr(num2), OCI.MODE.OCI_DEFAULT);
						if (num != 0)
						{
							connection.CheckError(errorHandle, num);
						}
						num = TracedNativeMethods.OCIBindByName(handle, out var _, errorHandle, "rdesc", 5, scratchBuffer.DangerousGetDataPtr(offset3), 4, OCI.DATATYPE.ROWID_DESC, scratchBuffer.DangerousGetDataPtr(offset), scratchBuffer.DangerousGetDataPtr(offset2), OCI.MODE.OCI_DEFAULT);
						if (num != 0)
						{
							connection.CheckError(errorHandle, num);
						}
						num = TracedNativeMethods.OCIStmtExecute(serviceContextHandle, handle, errorHandle, 1, OCI.MODE.OCI_DEFAULT);
						if (num != 0)
						{
							connection.CheckError(errorHandle, num);
						}
						if (scratchBuffer.ReadInt16(offset4) != -1)
						{
							@null = new OracleString(scratchBuffer, num3, num2, MetaType.GetMetaTypeForType(OracleType.RowId), connection, boundAsUCS2: false, outputParameterBinding: true);
							GC.KeepAlive(rowidHandle);
							return @null;
						}
						return @null;
					}
					finally
					{
						OciHandle.SafeDispose(ref handle);
					}
				}
				finally
				{
					if (success2)
					{
						rowidHandle.DangerousRelease();
					}
					if (success)
					{
						scratchBuffer.DangerousRelease();
					}
				}
			}
			return @null;
		}

		private OciStatementHandle GetStatementHandle()
		{
			if (ConnectionIsClosed)
			{
				throw System.Data.Common.ADP.ClosedConnectionError();
			}
			if (_preparedStatementHandle != null)
			{
				if (_connection.CloseCount == _preparedAtCloseCount)
				{
					return _preparedStatementHandle;
				}
				_preparedStatementHandle.Dispose();
				_preparedStatementHandle = null;
			}
			return new OciStatementHandle(ServiceContextHandle);
		}

		internal static bool IsBehavior(CommandBehavior value, CommandBehavior condition)
		{
			return condition == (condition & value);
		}

		public override void Prepare()
		{
			OracleConnection.ExecutePermission.Demand();
			Bid.ScopeEnter(out var hScp, "<ora.OracleCommand.Prepare|API> %d#\n", ObjectID);
			try
			{
				if (ConnectionIsClosed)
				{
					throw System.Data.Common.ADP.ClosedConnectionError();
				}
				if (CommandType.Text == CommandType)
				{
					OciStatementHandle statementHandle = GetStatementHandle();
					int closeCount = _connection.CloseCount;
					string statementText = StatementText;
					int num = TracedNativeMethods.OCIStmtPrepare(statementHandle, ErrorHandle, statementText, OCI.SYNTAX.OCI_NTV_SYNTAX, OCI.MODE.OCI_DEFAULT, Connection);
					if (num != 0)
					{
						Connection.CheckError(ErrorHandle, num);
					}
					statementHandle.GetAttribute(OCI.ATTR.OCI_ATTR_STMT_TYPE, out short value, ErrorHandle);
					_statementType = (OCI.STMT)value;
					if (OCI.STMT.OCI_STMT_SELECT == _statementType)
					{
						num = TracedNativeMethods.OCIStmtExecute(_connection.ServiceContextHandle, statementHandle, ErrorHandle, 0, OCI.MODE.OCI_SHARED);
						if (num != 0)
						{
							Connection.CheckError(ErrorHandle, num);
						}
					}
					if (statementHandle != _preparedStatementHandle)
					{
						OciHandle.SafeDispose(ref _preparedStatementHandle);
					}
					_preparedStatementHandle = statementHandle;
					_preparedAtCloseCount = closeCount;
				}
				else if (_preparedStatementHandle != null)
				{
					OciHandle.SafeDispose(ref _preparedStatementHandle);
				}
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private void PropertyChanging()
		{
			if (_preparedStatementHandle != null)
			{
				_preparedStatementHandle.Dispose();
				_preparedStatementHandle = null;
			}
		}

		private void ReleaseStatementHandle(OciStatementHandle statementHandle)
		{
			if (Connection.State != 0 && _preparedStatementHandle != statementHandle)
			{
				OciHandle.SafeDispose(ref statementHandle);
			}
		}
	}
	public sealed class OracleCommandBuilder : DbCommandBuilder
	{
		private const char _doubleQuoteChar = '"';

		private const string _doubleQuoteString = "\"";

		private const string _doubleQuoteEscapeString = "\"\"";

		private const char _singleQuoteChar = '\'';

		private const string _singleQuoteString = "'";

		private const string _singleQuoteEscapeString = "''";

		private const string ResolveNameCommand_Part1 = "begin dbms_utility.name_resolve(";

		private const string ResolveNameCommand_Part2 = ",1,:schema,:part1,:part2,:dblink,:part1type,:objectnum); end;";

		private const string DeriveParameterCommand_Part2 = " and package_name";

		private const string DeriveParameterCommand_Part3 = " and object_name = ";

		private const string DeriveParameterCommand_Part4 = "  order by overload, position";

		private static readonly string DeriveParameterCommand_Part1 = "select overload, decode(position,0,'RETURN_VALUE',nvl(argument_name,chr(0))) name, decode(in_out,'IN',1,'IN/OUT',3,'OUT',decode(argument_name,null,6,2),1) direction, decode(data_type, 'BFILE'," + 1.ToString(CultureInfo.CurrentCulture) + ", 'BLOB'," + 2.ToString(CultureInfo.CurrentCulture) + ", 'CHAR'," + 3.ToString(CultureInfo.CurrentCulture) + ", 'CLOB'," + 4.ToString(CultureInfo.CurrentCulture) + ", 'DATE'," + 6.ToString(CultureInfo.CurrentCulture) + ", 'FLOAT'," + 13.ToString(CultureInfo.CurrentCulture) + ", 'INTERVAL YEAR TO MONTH'," + 8.ToString(CultureInfo.CurrentCulture) + ", 'INTERVAL DAY TO SECOND'," + 7.ToString(CultureInfo.CurrentCulture) + ", 'LONG'," + 10.ToString(CultureInfo.CurrentCulture) + ", 'LONG RAW'," + 9.ToString(CultureInfo.CurrentCulture) + ", 'NCHAR'," + 11.ToString(CultureInfo.CurrentCulture) + ", 'NCLOB'," + 12.ToString(CultureInfo.CurrentCulture) + ", 'NUMBER'," + 13.ToString(CultureInfo.CurrentCulture) + ", 'NVARCHAR2'," + 14.ToString(CultureInfo.CurrentCulture) + ", 'RAW'," + 15.ToString(CultureInfo.CurrentCulture) + ", 'REF CURSOR'," + 5.ToString(CultureInfo.CurrentCulture) + ", 'ROWID'," + 16.ToString(CultureInfo.CurrentCulture) + ", 'TIMESTAMP'," + 18.ToString(CultureInfo.CurrentCulture) + ", 'TIMESTAMP WITH LOCAL TIME ZONE'," + 19.ToString(CultureInfo.CurrentCulture) + ", 'TIMESTAMP WITH TIME ZONE'," + 20.ToString(CultureInfo.CurrentCulture) + ", 'VARCHAR2'," + 22.ToString(CultureInfo.CurrentCulture) + "," + 22.ToString(CultureInfo.CurrentCulture) + ") oracletype, decode(data_type, 'CHAR'," + 2000 + ", 'LONG'," + int.MaxValue + ", 'LONG RAW'," + int.MaxValue + ", 'NCHAR'," + 4000 + ", 'NVARCHAR2'," + 4000 + ", 'RAW'," + 2000 + ", 'VARCHAR2'," + 2000 + ",0) length, nvl(data_precision, 255) precision, nvl(data_scale, 255) scale from all_arguments where data_level = 0 and data_type is not null and owner = ";

		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		public override CatalogLocation CatalogLocation
		{
			get
			{
				return CatalogLocation.End;
			}
			set
			{
				if (CatalogLocation.End != value)
				{
					throw System.Data.Common.ADP.NotSupported();
				}
			}
		}

		[Browsable(false)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public override string CatalogSeparator
		{
			get
			{
				return "@";
			}
			set
			{
				if ("@" != value)
				{
					throw System.Data.Common.ADP.NotSupported();
				}
			}
		}

		[ResDescription("OracleCommandBuilder_DataAdapter")]
		[DefaultValue(null)]
		[ResCategory("OracleCategory_Update")]
		public new OracleDataAdapter DataAdapter
		{
			get
			{
				return (OracleDataAdapter)base.DataAdapter;
			}
			set
			{
				base.DataAdapter = value;
			}
		}

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		[Browsable(false)]
		public override string SchemaSeparator
		{
			get
			{
				return ".";
			}
			set
			{
				if ("." != value)
				{
					throw System.Data.Common.ADP.NotSupported();
				}
			}
		}

		public OracleCommandBuilder()
		{
			GC.SuppressFinalize(this);
		}

		public OracleCommandBuilder(OracleDataAdapter adapter)
			: this()
		{
			DataAdapter = adapter;
		}

		protected override void ApplyParameterInfo(DbParameter parameter, DataRow datarow, StatementType statementType, bool whereClause)
		{
			OracleParameter oracleParameter = (OracleParameter)parameter;
			object obj = datarow["ProviderType", DataRowVersion.Default];
			OracleType oracleType = (OracleType)obj;
			OracleType oracleType2 = oracleType;
			if (oracleType2 == OracleType.LongVarChar)
			{
				oracleType = OracleType.VarChar;
			}
			oracleParameter.OracleType = oracleType;
			oracleParameter.Offset = 0;
		}

		public static void DeriveParameters(OracleCommand command)
		{
			OracleConnection.ExecutePermission.Demand();
			if (command == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("command");
			}
			switch (command.CommandType)
			{
			case CommandType.Text:
			case CommandType.TableDirect:
				throw System.Data.Common.ADP.DeriveParametersNotSupported(command);
			default:
				throw System.Data.Common.ADP.InvalidCommandType(command.CommandType);
			case CommandType.StoredProcedure:
			{
				if (System.Data.Common.ADP.IsEmpty(command.CommandText))
				{
					throw System.Data.Common.ADP.CommandTextRequired("DeriveParameters");
				}
				OracleConnection connection = command.Connection;
				if (connection == null)
				{
					throw System.Data.Common.ADP.ConnectionRequired("DeriveParameters");
				}
				ConnectionState state = connection.State;
				if (ConnectionState.Open != state)
				{
					throw System.Data.Common.ADP.OpenConnectionRequired("DeriveParameters", state);
				}
				ArrayList arrayList = DeriveParametersFromStoredProcedure(connection, command);
				OracleParameterCollection parameters = command.Parameters;
				parameters.Clear();
				int count = arrayList.Count;
				for (int i = 0; i < count; i++)
				{
					parameters.Add((OracleParameter)arrayList[i]);
				}
				break;
			}
			}
		}

		private static ArrayList DeriveParametersFromStoredProcedure(OracleConnection connection, OracleCommand command)
		{
			ArrayList arrayList = new ArrayList();
			OracleCommand oracleCommand = connection.CreateCommand();
			oracleCommand.Transaction = command.Transaction;
			if (ResolveName(oracleCommand, command.CommandText, out var schema, out var packageName, out var objectName, out var _) != 0)
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(DeriveParameterCommand_Part1);
				stringBuilder.Append(QuoteIdentifier(schema, "'", "''"));
				stringBuilder.Append(" and package_name");
				if (!System.Data.Common.ADP.IsNull(packageName))
				{
					stringBuilder.Append(" = ");
					stringBuilder.Append(QuoteIdentifier(packageName, "'", "''"));
				}
				else
				{
					stringBuilder.Append(" is null");
				}
				stringBuilder.Append(" and object_name = ");
				stringBuilder.Append(QuoteIdentifier(objectName, "'", "''"));
				stringBuilder.Append("  order by overload, position");
				oracleCommand.Parameters.Clear();
				oracleCommand.CommandText = stringBuilder.ToString();
				using OracleDataReader oracleDataReader = oracleCommand.ExecuteReader();
				while (oracleDataReader.Read())
				{
					if (!System.Data.Common.ADP.IsNull(oracleDataReader.GetValue(0)))
					{
						throw System.Data.Common.ADP.CannotDeriveOverloaded();
					}
					string @string = oracleDataReader.GetString(1);
					ParameterDirection direction = (ParameterDirection)(int)oracleDataReader.GetDecimal(2);
					OracleType oracleType = (OracleType)(int)oracleDataReader.GetDecimal(3);
					int size = (int)oracleDataReader.GetDecimal(4);
					byte precision = (byte)oracleDataReader.GetDecimal(5);
					int num = (int)oracleDataReader.GetDecimal(6);
					byte scale = (byte)((num >= 0) ? ((byte)num) : 0);
					OracleParameter value = new OracleParameter(@string, oracleType, size, direction, isNullable: true, precision, scale, "", DataRowVersion.Current, null);
					arrayList.Add(value);
				}
				return arrayList;
			}
			return arrayList;
		}

		public new OracleCommand GetInsertCommand()
		{
			return (OracleCommand)base.GetInsertCommand();
		}

		public new OracleCommand GetInsertCommand(bool useColumnsForParameterNames)
		{
			return (OracleCommand)base.GetInsertCommand(useColumnsForParameterNames);
		}

		public new OracleCommand GetUpdateCommand()
		{
			return (OracleCommand)base.GetUpdateCommand();
		}

		public new OracleCommand GetUpdateCommand(bool useColumnsForParameterNames)
		{
			return (OracleCommand)base.GetUpdateCommand(useColumnsForParameterNames);
		}

		public new OracleCommand GetDeleteCommand()
		{
			return (OracleCommand)base.GetDeleteCommand();
		}

		public new OracleCommand GetDeleteCommand(bool useColumnsForParameterNames)
		{
			return (OracleCommand)base.GetDeleteCommand(useColumnsForParameterNames);
		}

		protected override string GetParameterName(int parameterOrdinal)
		{
			return "p" + parameterOrdinal.ToString(CultureInfo.CurrentCulture);
		}

		protected override string GetParameterName(string parameterName)
		{
			return parameterName;
		}

		protected override string GetParameterPlaceholder(int parameterOrdinal)
		{
			return ":" + GetParameterName(parameterOrdinal);
		}

		public override string QuoteIdentifier(string unquotedIdentifier)
		{
			return QuoteIdentifier(unquotedIdentifier, "\"", "\"\"");
		}

		private static string QuoteIdentifier(string unquotedIdentifier, string quoteString, string quoteEscapeString)
		{
			System.Data.Common.ADP.CheckArgumentNull(unquotedIdentifier, "unquotedIdentifier");
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append(quoteString);
			stringBuilder.Append(unquotedIdentifier.Replace(quoteString, quoteEscapeString));
			stringBuilder.Append(quoteString);
			return stringBuilder.ToString();
		}

		private static uint ResolveName(OracleCommand command, string nameToResolve, out string schema, out string packageName, out string objectName, out string dblink)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append("begin dbms_utility.name_resolve(");
			stringBuilder.Append(QuoteIdentifier(nameToResolve, "'", "''"));
			stringBuilder.Append(",1,:schema,:part1,:part2,:dblink,:part1type,:objectnum); end;");
			command.CommandText = stringBuilder.ToString();
			command.Parameters.Add(new OracleParameter("schema", OracleType.VarChar, 30)).Direction = ParameterDirection.Output;
			command.Parameters.Add(new OracleParameter("part1", OracleType.VarChar, 30)).Direction = ParameterDirection.Output;
			command.Parameters.Add(new OracleParameter("part2", OracleType.VarChar, 30)).Direction = ParameterDirection.Output;
			command.Parameters.Add(new OracleParameter("dblink", OracleType.VarChar, 128)).Direction = ParameterDirection.Output;
			command.Parameters.Add(new OracleParameter("part1type", OracleType.UInt32)).Direction = ParameterDirection.Output;
			command.Parameters.Add(new OracleParameter("objectnum", OracleType.UInt32)).Direction = ParameterDirection.Output;
			command.ExecuteNonQuery();
			object value = command.Parameters["objectnum"].Value;
			if (System.Data.Common.ADP.IsNull(value))
			{
				schema = string.Empty;
				packageName = string.Empty;
				objectName = string.Empty;
				dblink = string.Empty;
				return 0u;
			}
			schema = (System.Data.Common.ADP.IsNull(command.Parameters["schema"].Value) ? null : ((string)command.Parameters["schema"].Value));
			packageName = (System.Data.Common.ADP.IsNull(command.Parameters["part1"].Value) ? null : ((string)command.Parameters["part1"].Value));
			objectName = (System.Data.Common.ADP.IsNull(command.Parameters["part2"].Value) ? null : ((string)command.Parameters["part2"].Value));
			dblink = (System.Data.Common.ADP.IsNull(command.Parameters["dblink"].Value) ? null : ((string)command.Parameters["dblink"].Value));
			return (uint)command.Parameters["part1type"].Value;
		}

		private void RowUpdatingHandler(object sender, OracleRowUpdatingEventArgs ruevent)
		{
			RowUpdatingHandler(ruevent);
		}

		protected override void SetRowUpdatingHandler(DbDataAdapter adapter)
		{
			if (adapter == base.DataAdapter)
			{
				((OracleDataAdapter)adapter).RowUpdating -= RowUpdatingHandler;
			}
			else
			{
				((OracleDataAdapter)adapter).RowUpdating += RowUpdatingHandler;
			}
		}

		public override string UnquoteIdentifier(string quotedIdentifier)
		{
			System.Data.Common.ADP.CheckArgumentNull(quotedIdentifier, "quotedIdentifier");
			if (quotedIdentifier.Length < 2 || quotedIdentifier[0] != '"' || quotedIdentifier[quotedIdentifier.Length - 1] != '"')
			{
				throw System.Data.Common.ADP.IdentifierIsNotQuoted();
			}
			return quotedIdentifier.Substring(1, quotedIdentifier.Length - 2).Replace("\"\"", "\"");
		}
	}
	internal sealed class OracleCommandSet : IDisposable
	{
		private sealed class LocalCommand
		{
			internal readonly bool IsQuery;

			internal readonly string CommandText;

			internal readonly DbParameter[] Parameters;

			internal readonly string[] ParameterNames;

			internal readonly LocalParameter[] ParameterInsertionPoints;

			internal OracleParameter ResultParameter;

			internal LocalCommand(string commandText, bool isQuery, DbParameter[] parameters, string[] parameterNames, LocalParameter[] parameterInsertionPoints)
			{
				CommandText = commandText;
				IsQuery = isQuery;
				Parameters = parameters;
				ParameterNames = parameterNames;
				ParameterInsertionPoints = parameterInsertionPoints;
			}
		}

		private struct LocalParameter
		{
			internal readonly int ParameterIndex;

			internal readonly int InsertionPoint;

			internal readonly int RemovalLength;

			internal LocalParameter(int parameterIndex, int insertionPoint, int removalLength)
			{
				ParameterIndex = parameterIndex;
				InsertionPoint = insertionPoint;
				RemovalLength = removalLength;
			}
		}

		private static readonly string _sqlTokenPattern = "[\\s]+|(?<string>'([^']|'')*')|(?<comment>(/\\*([^\\*]|\\*[^/])*\\*/)|(--.*))|(?<parametermarker>:[\\p{Lo}\\p{Lu}\\p{Ll}\\p{Lm}\\p{Nd}\\uff3f_#$]+)|(?<query>select)|(?<identifier>([\\p{Lo}\\p{Lu}\\p{Ll}\\p{Lm}\\p{Nd}\\uff3f_#$]+)|(\"([^\"]|\"\")*\"))|(?<other>.)";

		private static Regex _sqlTokenParser;

		private static int _commentGroup;

		private static int _identifierGroup;

		private static int _parameterMarkerGroup;

		private static int _queryGroup;

		private static int _stringGroup;

		private static int _otherGroup;

		private static readonly string Declarations_Prefix = "declare\ntype refcursortype is ref cursor;\n";

		private static readonly string Declarations_CursorType = " refcursortype;\n";

		private static readonly string Body_Prefix = "begin\n";

		private static readonly string Body_Suffix = "end;";

		private static readonly string Command_QueryPrefix_Part1 = "open ";

		private static readonly string Command_QueryPrefix_Part2 = " for ";

		private static readonly string Command_Suffix_Part1 = ";\n:";

		private static readonly string Command_NonQuerySuffix_Part2 = " := sql%rowcount;\n";

		private static readonly string Command_QuerySuffix_Part2 = " := ";

		private static readonly string Command_QuerySuffix_Part3 = ";\n";

		private Hashtable _usedParameterNames = new Hashtable(StringComparer.OrdinalIgnoreCase);

		private ArrayList _commandList = new ArrayList();

		private OracleCommand _batchCommand;

		private bool _dirty;

		private OracleCommand BatchCommand
		{
			get
			{
				OracleCommand batchCommand = _batchCommand;
				if (batchCommand == null)
				{
					throw System.Data.Common.ADP.ObjectDisposed(GetType().Name);
				}
				return batchCommand;
			}
		}

		public int CommandCount => CommandList.Count;

		private ArrayList CommandList
		{
			get
			{
				ArrayList commandList = _commandList;
				if (commandList == null)
				{
					throw System.Data.Common.ADP.ObjectDisposed(GetType().Name);
				}
				return commandList;
			}
		}

		public int CommandTimeout
		{
			set
			{
				BatchCommand.CommandTimeout = value;
			}
		}

		public OracleConnection Connection
		{
			set
			{
				BatchCommand.Connection = value;
			}
		}

		internal OracleTransaction Transaction
		{
			set
			{
				BatchCommand.Transaction = value;
			}
		}

		public OracleCommandSet()
			: this(null, null)
		{
		}

		public OracleCommandSet(OracleConnection connection, OracleTransaction transaction)
		{
			_batchCommand = new OracleCommand();
			Connection = connection;
			Transaction = transaction;
		}

		public void Append(OracleCommand command)
		{
			System.Data.Common.ADP.CheckArgumentNull(command, "command");
			if (System.Data.Common.ADP.IsEmpty(command.CommandText))
			{
				throw System.Data.Common.ADP.CommandTextRequired("Append");
			}
			ICollection parameters = command.Parameters;
			OracleParameter[] array = new OracleParameter[parameters.Count];
			parameters.CopyTo(array, 0);
			string[] array2 = new string[array.Length];
			if (0 < array.Length)
			{
				for (int i = 0; i < array.Length; i++)
				{
					array2[i] = array[i].ParameterName;
					OracleParameter oracleParameter = command.CreateParameter();
					array[i].CopyTo(oracleParameter);
					object value = oracleParameter.Value;
					if (value is byte[])
					{
						byte[] array3 = (byte[])value;
						int offset = oracleParameter.Offset;
						int size = oracleParameter.Size;
						int num = array3.Length - offset;
						if (size != 0 && size < num)
						{
							num = size;
						}
						byte[] array4 = new byte[Math.Max(num, 0)];
						Buffer.BlockCopy(array3, offset, array4, 0, array4.Length);
						oracleParameter.Offset = 0;
						oracleParameter.Value = array4;
					}
					else if (value is char[])
					{
						char[] array5 = (char[])value;
						int offset2 = oracleParameter.Offset;
						int size2 = oracleParameter.Size;
						int num2 = array5.Length - offset2;
						if (size2 != 0 && size2 < num2)
						{
							num2 = size2;
						}
						char[] array6 = new char[Math.Max(num2, 0)];
						Buffer.BlockCopy(array5, offset2, array6, 0, array6.Length * 2);
						oracleParameter.Offset = 0;
						oracleParameter.Value = array6;
					}
					else if (value is ICloneable)
					{
						oracleParameter.Value = ((ICloneable)value).Clone();
					}
					array[i] = oracleParameter;
				}
			}
			string statementText = command.StatementText;
			bool isQuery = false;
			LocalParameter[] parameterInsertionPoints = ParseText(command, statementText, out isQuery);
			LocalCommand value2 = new LocalCommand(statementText, isQuery, array, array2, parameterInsertionPoints);
			_dirty = true;
			CommandList.Add(value2);
		}

		public void Clear()
		{
			DbCommand batchCommand = BatchCommand;
			if (batchCommand != null)
			{
				batchCommand.Parameters.Clear();
				batchCommand.CommandText = null;
			}
			_commandList?.Clear();
			_usedParameterNames?.Clear();
		}

		public void Dispose()
		{
			DbCommand batchCommand = _batchCommand;
			_batchCommand = null;
			_commandList = null;
			_usedParameterNames = null;
			batchCommand?.Dispose();
		}

		public int ExecuteNonQuery()
		{
			GenerateBatchCommandText();
			return BatchCommand.ExecuteNonQuery();
		}

		private void GenerateBatchCommandText()
		{
			if (!_dirty)
			{
				return;
			}
			DbCommand batchCommand = BatchCommand;
			StringBuilder stringBuilder = new StringBuilder();
			StringBuilder stringBuilder2 = new StringBuilder();
			int num = 1;
			int num2 = 1;
			int num3 = 1;
			batchCommand.Parameters.Clear();
			stringBuilder.Append(Declarations_Prefix);
			stringBuilder2.Append(Body_Prefix);
			foreach (LocalCommand command in CommandList)
			{
				DbParameter[] parameters = command.Parameters;
				foreach (DbParameter dbParameter in parameters)
				{
					string text;
					do
					{
						text = "p" + num3.ToString(CultureInfo.InvariantCulture);
						num3++;
					}
					while (_usedParameterNames.ContainsKey(text));
					dbParameter.ParameterName = text;
					batchCommand.Parameters.Add(dbParameter);
				}
				string text2;
				do
				{
					text2 = "r" + num.ToString(CultureInfo.InvariantCulture) + "_" + num3.ToString(CultureInfo.InvariantCulture);
					num3++;
				}
				while (_usedParameterNames.ContainsKey(text2));
				OracleParameter oracleParameter = new OracleParameter();
				oracleParameter.CommandSetResult = num++;
				oracleParameter.Direction = ParameterDirection.Output;
				oracleParameter.ParameterName = text2;
				batchCommand.Parameters.Add(oracleParameter);
				int num4 = stringBuilder2.Length;
				if (command.IsQuery)
				{
					string value = "c" + num2.ToString(CultureInfo.InvariantCulture);
					num2++;
					stringBuilder.Append(value);
					stringBuilder.Append(Declarations_CursorType);
					stringBuilder2.Append(Command_QueryPrefix_Part1);
					stringBuilder2.Append(value);
					stringBuilder2.Append(Command_QueryPrefix_Part2);
					num4 = stringBuilder2.Length;
					stringBuilder2.Append(command.CommandText);
					stringBuilder2.Append(Command_Suffix_Part1);
					stringBuilder2.Append(text2);
					stringBuilder2.Append(Command_QuerySuffix_Part2);
					stringBuilder2.Append(value);
					stringBuilder2.Append(Command_QuerySuffix_Part3);
					oracleParameter.OracleType = OracleType.Cursor;
				}
				else
				{
					string commandText = command.CommandText;
					stringBuilder2.Append(commandText.TrimEnd(';'));
					stringBuilder2.Append(Command_Suffix_Part1);
					stringBuilder2.Append(text2);
					stringBuilder2.Append(Command_NonQuerySuffix_Part2);
					oracleParameter.OracleType = OracleType.Int32;
					command.ResultParameter = oracleParameter;
				}
				LocalParameter[] parameterInsertionPoints = command.ParameterInsertionPoints;
				for (int j = 0; j < parameterInsertionPoints.Length; j++)
				{
					LocalParameter localParameter = parameterInsertionPoints[j];
					DbParameter dbParameter2 = command.Parameters[localParameter.ParameterIndex];
					string text3 = ":" + dbParameter2.ParameterName;
					stringBuilder2.Remove(num4 + localParameter.InsertionPoint, localParameter.RemovalLength);
					stringBuilder2.Insert(num4 + localParameter.InsertionPoint, text3);
					num4 += text3.Length - localParameter.RemovalLength;
				}
			}
			stringBuilder2.Append(Body_Suffix);
			stringBuilder.Append(stringBuilder2);
			batchCommand.CommandText = stringBuilder.ToString();
			_dirty = false;
		}

		internal bool GetBatchedRecordsAffected(int commandIndex, out int recordsAffected)
		{
			OracleParameter resultParameter = ((LocalCommand)CommandList[commandIndex]).ResultParameter;
			if (resultParameter != null)
			{
				if (resultParameter.Value is int)
				{
					recordsAffected = (int)resultParameter.Value;
					return true;
				}
				recordsAffected = -1;
				return false;
			}
			recordsAffected = -1;
			return true;
		}

		internal DbParameter GetParameter(int commandIndex, int parameterIndex)
		{
			return ((LocalCommand)CommandList[commandIndex]).Parameters[parameterIndex];
		}

		public int GetParameterCount(int commandIndex)
		{
			return ((LocalCommand)CommandList[commandIndex]).Parameters.Length;
		}

		private static Regex GetSqlTokenParser()
		{
			Regex regex = _sqlTokenParser;
			if (regex == null)
			{
				regex = new Regex(_sqlTokenPattern, RegexOptions.ExplicitCapture);
				_commentGroup = regex.GroupNumberFromName("comment");
				_identifierGroup = regex.GroupNumberFromName("identifier");
				_parameterMarkerGroup = regex.GroupNumberFromName("parametermarker");
				_queryGroup = regex.GroupNumberFromName("query");
				_stringGroup = regex.GroupNumberFromName("string");
				_otherGroup = regex.GroupNumberFromName("other");
				_sqlTokenParser = regex;
			}
			return regex;
		}

		private LocalParameter[] ParseText(OracleCommand command, string commandText, out bool isQuery)
		{
			OracleParameterCollection parameters = command.Parameters;
			ArrayList arrayList = new ArrayList();
			Regex sqlTokenParser = GetSqlTokenParser();
			isQuery = false;
			bool flag = false;
			Match match = sqlTokenParser.Match(commandText);
			while (Match.Empty != match)
			{
				if (!match.Groups[_commentGroup].Success)
				{
					if (match.Groups[_identifierGroup].Success || match.Groups[_stringGroup].Success || match.Groups[_otherGroup].Success)
					{
						flag = true;
					}
					else if (match.Groups[_queryGroup].Success)
					{
						if (!flag)
						{
							isQuery = true;
						}
					}
					else if (match.Groups[_parameterMarkerGroup].Success)
					{
						string value = match.Groups[_parameterMarkerGroup].Value;
						string text = value.Substring(1);
						_usedParameterNames[text] = null;
						int num = parameters.IndexOf(text);
						if (0 > num)
						{
							string parameterName = ":" + text;
							num = parameters.IndexOf(parameterName);
						}
						if (0 <= num)
						{
							arrayList.Add(new LocalParameter(num, match.Index, match.Length));
						}
					}
				}
				match = match.NextMatch();
			}
			LocalParameter[] array = new LocalParameter[arrayList.Count];
			arrayList.CopyTo(array, 0);
			return array;
		}
	}
	internal enum TransactionState
	{
		AutoCommit,
		LocalStarted,
		GlobalStarted
	}
	[DefaultEvent("InfoMessage")]
	public sealed class OracleConnection : DbConnection, ICloneable
	{
		private static readonly object EventInfoMessage = new object();

		private static readonly System.Data.ProviderBase.DbConnectionFactory _connectionFactory = OracleConnectionFactory.SingletonInstance;

		internal static readonly CodeAccessPermission ExecutePermission = CreateExecutePermission();

		private System.Data.Common.DbConnectionOptions _userConnectionOptions;

		private System.Data.ProviderBase.DbConnectionPoolGroup _poolGroup;

		private System.Data.ProviderBase.DbConnectionInternal _innerConnection;

		private int _closeCount;

		private static int _objectTypeCount;

		internal readonly int ObjectID = Interlocked.Increment(ref _objectTypeCount);

		[RefreshProperties(RefreshProperties.All)]
		[Editor("Microsoft.VSDesigner.Data.Oracle.Design.OracleConnectionStringEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ResDescription("OracleConnection_ConnectionString")]
		[RecommendedAsConfigurable(true)]
		[ResCategory("OracleCategory_Data")]
		[DefaultValue("")]
		public override string ConnectionString
		{
			get
			{
				return ConnectionString_Get();
			}
			set
			{
				ConnectionString_Set(value);
			}
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		[Browsable(false)]
		public override int ConnectionTimeout => 0;

		[Browsable(false)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		public override string Database => string.Empty;

		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[ResDescription("OracleConnection_DataSource")]
		public override string DataSource
		{
			get
			{
				OracleConnectionString oracleConnectionString = (OracleConnectionString)ConnectionOptions;
				string result = string.Empty;
				if (oracleConnectionString != null)
				{
					result = oracleConnectionString.DataSource;
				}
				return result;
			}
		}

		internal OciEnvironmentHandle EnvironmentHandle => GetOpenInternalConnection().EnvironmentHandle;

		internal OciErrorHandle ErrorHandle => GetOpenInternalConnection().ErrorHandle;

		internal bool HasTransaction => GetOpenInternalConnection().HasTransaction;

		internal TimeSpan ServerTimeZoneAdjustmentToUTC => GetOpenInternalConnection().GetServerTimeZoneAdjustmentToUTC(this);

		[Browsable(false)]
		[ResDescription("OracleConnection_ServerVersion")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public override string ServerVersion => GetOpenInternalConnection().ServerVersion;

		internal bool ServerVersionAtLeastOracle8 => GetOpenInternalConnection().ServerVersionAtLeastOracle8;

		internal bool ServerVersionAtLeastOracle9i => GetOpenInternalConnection().ServerVersionAtLeastOracle9i;

		internal OciServiceContextHandle ServiceContextHandle => GetOpenInternalConnection().ServiceContextHandle;

		internal OracleTransaction Transaction => GetOpenInternalConnection().Transaction;

		internal TransactionState TransactionState
		{
			get
			{
				return GetOpenInternalConnection().TransactionState;
			}
			set
			{
				GetOpenInternalConnection().TransactionState = value;
			}
		}

		internal bool UnicodeEnabled => GetOpenInternalConnection().UnicodeEnabled;

		internal int CloseCount => _closeCount;

		internal System.Data.ProviderBase.DbConnectionFactory ConnectionFactory => _connectionFactory;

		internal System.Data.Common.DbConnectionOptions ConnectionOptions => PoolGroup?.ConnectionOptions;

		internal System.Data.ProviderBase.DbConnectionInternal InnerConnection => _innerConnection;

		internal System.Data.ProviderBase.DbConnectionPoolGroup PoolGroup
		{
			get
			{
				return _poolGroup;
			}
			set
			{
				_poolGroup = value;
			}
		}

		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[ResDescription("DbConnection_State")]
		public override ConnectionState State => InnerConnection.State;

		internal System.Data.Common.DbConnectionOptions UserConnectionOptions => _userConnectionOptions;

		[ResCategory("OracleCategory_InfoMessage")]
		[ResDescription("OracleConnection_InfoMessage")]
		public event OracleInfoMessageEventHandler InfoMessage
		{
			add
			{
				base.Events.AddHandler(EventInfoMessage, value);
			}
			remove
			{
				base.Events.RemoveHandler(EventInfoMessage, value);
			}
		}

		public OracleConnection(string connectionString)
			: this()
		{
			ConnectionString = connectionString;
		}

		internal OracleConnection(OracleConnection connection)
			: this()
		{
			CopyFrom(connection);
		}

		public new OracleTransaction BeginTransaction()
		{
			return BeginTransaction(IsolationLevel.Unspecified);
		}

		public new OracleTransaction BeginTransaction(IsolationLevel il)
		{
			return (OracleTransaction)base.BeginTransaction(il);
		}

		public override void ChangeDatabase(string value)
		{
			//Discarded unreachable code: IL_0019
			Bid.ScopeEnter(out var hScp, "<ora.OracleConnection.ChangeDatabase|API> %d#, value='%ls'\n", ObjectID, value);
			try
			{
				throw System.Data.Common.ADP.ChangeDatabaseNotSupported();
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		internal void CheckError(OciErrorHandle errorHandle, int rc)
		{
			switch (rc)
			{
			case -1:
			case 100:
			{
				Exception ex = System.Data.Common.ADP.OracleError(errorHandle, rc);
				if (errorHandle != null && errorHandle.ConnectionIsBroken)
				{
					GetOpenInternalConnection()?.ConnectionIsBroken();
				}
				throw ex;
			}
			case -2:
				throw System.Data.Common.ADP.InvalidOperation(Res.GetString("ADP_InternalError", rc));
			case 1:
			{
				OracleException exception = OracleException.CreateException(errorHandle, rc);
				OracleInfoMessageEventArgs infoMessageEvent = new OracleInfoMessageEventArgs(exception);
				OnInfoMessage(infoMessageEvent);
				break;
			}
			default:
				if (rc < 0 || rc == 99)
				{
					throw System.Data.Common.ADP.Simple(Res.GetString("ADP_UnexpectedReturnCode", rc.ToString(CultureInfo.CurrentCulture)));
				}
				break;
			}
		}

		public static void ClearAllPools()
		{
			new OraclePermission(PermissionState.Unrestricted).Demand();
			OracleConnectionFactory.SingletonInstance.ClearAllPools();
		}

		public static void ClearPool(OracleConnection connection)
		{
			System.Data.Common.ADP.CheckArgumentNull(connection, "connection");
			System.Data.Common.DbConnectionOptions userConnectionOptions = connection.UserConnectionOptions;
			if (userConnectionOptions != null)
			{
				userConnectionOptions.DemandPermission();
				OracleConnectionFactory.SingletonInstance.ClearPool(connection);
			}
		}

		object ICloneable.Clone()
		{
			OracleConnection oracleConnection = new OracleConnection(this);
			Bid.Trace("<ora.OracleConnection.Clone|API> %d#, clone=%d#\n", ObjectID, oracleConnection.ObjectID);
			return oracleConnection;
		}

		public override void Close()
		{
			InnerConnection.CloseConnection(this, ConnectionFactory);
		}

		internal void Commit()
		{
			GetOpenInternalConnection().Commit();
		}

		public new OracleCommand CreateCommand()
		{
			OracleCommand oracleCommand = new OracleCommand();
			oracleCommand.Connection = this;
			return oracleCommand;
		}

		private void DisposeMe(bool disposing)
		{
		}

		public void EnlistDistributedTransaction(ITransaction distributedTransaction)
		{
			EnlistDistributedTransactionHelper(distributedTransaction);
		}

		internal byte[] GetBytes(string value, bool useNationalCharacterSet)
		{
			return GetOpenInternalConnection().GetBytes(value, useNationalCharacterSet);
		}

		internal OracleInternalConnection GetOpenInternalConnection()
		{
			System.Data.ProviderBase.DbConnectionInternal innerConnection = InnerConnection;
			if (innerConnection is OracleInternalConnection)
			{
				return innerConnection as OracleInternalConnection;
			}
			throw System.Data.Common.ADP.ClosedConnectionError();
		}

		internal NativeBuffer GetScratchBuffer(int minSize)
		{
			return GetOpenInternalConnection().GetScratchBuffer(minSize);
		}

		internal string GetString(byte[] bytearray)
		{
			return GetOpenInternalConnection().GetString(bytearray);
		}

		internal string GetString(byte[] bytearray, bool useNationalCharacterSet)
		{
			return GetOpenInternalConnection().GetString(bytearray, useNationalCharacterSet);
		}

		public override void Open()
		{
			InnerConnection.OpenConnection(this, ConnectionFactory);
			if (InnerConnection is OracleInternalConnection oracleInternalConnection)
			{
				oracleInternalConnection.FireDeferredInfoMessageEvents(this);
			}
		}

		internal void Rollback()
		{
			if (InnerConnection is OracleInternalConnection oracleInternalConnection)
			{
				oracleInternalConnection.Rollback();
			}
		}

		internal void RollbackDeadTransaction()
		{
			GetOpenInternalConnection().RollbackDeadTransaction();
		}

		internal void OnInfoMessage(OracleInfoMessageEventArgs infoMessageEvent)
		{
			((OracleInfoMessageEventHandler)base.Events[EventInfoMessage])?.Invoke(this, infoMessageEvent);
		}

		public OracleConnection()
		{
			GC.SuppressFinalize(this);
			_innerConnection = System.Data.ProviderBase.DbConnectionClosedNeverOpened.SingletonInstance;
		}

		private void CopyFrom(OracleConnection connection)
		{
			System.Data.Common.ADP.CheckArgumentNull(connection, "connection");
			_userConnectionOptions = connection.UserConnectionOptions;
			_poolGroup = connection.PoolGroup;
			if (System.Data.ProviderBase.DbConnectionClosedNeverOpened.SingletonInstance == connection._innerConnection)
			{
				_innerConnection = System.Data.ProviderBase.DbConnectionClosedNeverOpened.SingletonInstance;
			}
			else
			{
				_innerConnection = System.Data.ProviderBase.DbConnectionClosedPreviouslyOpened.SingletonInstance;
			}
		}

		private string ConnectionString_Get()
		{
			Bid.Trace("<prov.DbConnectionHelper.ConnectionString_Get|API> %d#\n", ObjectID);
			bool shouldHidePassword = InnerConnection.ShouldHidePassword;
			System.Data.Common.DbConnectionOptions userConnectionOptions = UserConnectionOptions;
			if (userConnectionOptions == null)
			{
				return "";
			}
			return userConnectionOptions.UsersConnectionString(shouldHidePassword);
		}

		private void ConnectionString_Set(string value)
		{
			System.Data.Common.DbConnectionOptions userConnectionOptions = null;
			System.Data.ProviderBase.DbConnectionPoolGroup connectionPoolGroup = ConnectionFactory.GetConnectionPoolGroup(value, null, ref userConnectionOptions);
			System.Data.ProviderBase.DbConnectionInternal innerConnection = InnerConnection;
			bool flag = innerConnection.AllowSetConnectionString;
			if (flag)
			{
				flag = SetInnerConnectionFrom(System.Data.ProviderBase.DbConnectionClosedBusy.SingletonInstance, innerConnection);
				if (flag)
				{
					_userConnectionOptions = userConnectionOptions;
					_poolGroup = connectionPoolGroup;
					_innerConnection = System.Data.ProviderBase.DbConnectionClosedNeverOpened.SingletonInstance;
				}
			}
			if (!flag)
			{
				throw System.Data.Common.ADP.OpenConnectionPropertySet("ConnectionString", innerConnection.State);
			}
			if (Bid.TraceOn)
			{
				string a = ((userConnectionOptions != null) ? userConnectionOptions.UsersConnectionStringForTrace() : "");
				Bid.Trace("<prov.DbConnectionHelper.ConnectionString_Set|API> %d#, '%ls'\n", ObjectID, a);
			}
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal void Abort(Exception e)
		{
			System.Data.ProviderBase.DbConnectionInternal innerConnection = _innerConnection;
			if (ConnectionState.Open == innerConnection.State)
			{
				Interlocked.CompareExchange(ref _innerConnection, System.Data.ProviderBase.DbConnectionClosedPreviouslyOpened.SingletonInstance, innerConnection);
				innerConnection.DoomThisConnection();
			}
			if (e is OutOfMemoryException)
			{
				Bid.Trace("<prov.DbConnectionHelper.Abort|RES|INFO|CPOOL> %d#, Aborting operation due to asynchronous exception: %ls\n", ObjectID, "OutOfMemory");
			}
			else
			{
				Bid.Trace("<prov.DbConnectionHelper.Abort|RES|INFO|CPOOL> %d#, Aborting operation due to asynchronous exception: %ls\n", ObjectID, e.ToString());
			}
		}

		internal void AddWeakReference(object value, int tag)
		{
			InnerConnection.AddWeakReference(value, tag);
		}

		protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
		{
			Bid.ScopeEnter(out var hScp, "<prov.DbConnectionHelper.BeginDbTransaction|API> %d#, isolationLevel=%d{ds.IsolationLevel}", ObjectID, (int)isolationLevel);
			try
			{
				return InnerConnection.BeginTransaction(isolationLevel);
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		protected override DbCommand CreateDbCommand()
		{
			DbCommand dbCommand = null;
			Bid.ScopeEnter(out var hScp, "<prov.DbConnectionHelper.CreateDbCommand|API> %d#\n", ObjectID);
			try
			{
				DbProviderFactory providerFactory = ConnectionFactory.ProviderFactory;
				dbCommand = providerFactory.CreateCommand();
				dbCommand.Connection = this;
				return dbCommand;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private static CodeAccessPermission CreateExecutePermission()
		{
			OraclePermission oraclePermission = new OraclePermission(PermissionState.None);
			oraclePermission.Add(string.Empty, string.Empty, KeyRestrictionBehavior.AllowOnly);
			return oraclePermission;
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				_userConnectionOptions = null;
				_poolGroup = null;
				Close();
			}
			DisposeMe(disposing);
			base.Dispose(disposing);
		}

		private void EnlistDistributedTransactionHelper(ITransaction transaction)
		{
			PermissionSet permissionSet = new PermissionSet(PermissionState.None);
			permissionSet.AddPermission(ExecutePermission);
			permissionSet.AddPermission(new SecurityPermission(SecurityPermissionFlag.UnmanagedCode));
			permissionSet.Demand();
			Bid.Trace("<prov.DbConnectionHelper.EnlistDistributedTransactionHelper|RES|TRAN> %d#, Connection enlisting in a transaction.\n", ObjectID);
			Transaction transaction2 = null;
			if (transaction != null)
			{
				transaction2 = TransactionInterop.GetTransactionFromDtcTransaction((IDtcTransaction)transaction);
			}
			InnerConnection.EnlistTransaction(transaction2);
			GC.KeepAlive(this);
		}

		public override void EnlistTransaction(Transaction transaction)
		{
			ExecutePermission.Demand();
			Bid.Trace("<prov.DbConnectionHelper.EnlistTransaction|RES|TRAN> %d#, Connection enlisting in a transaction.\n", ObjectID);
			System.Data.ProviderBase.DbConnectionInternal innerConnection = InnerConnection;
			if (innerConnection.HasEnlistedTransaction)
			{
				if (!innerConnection.EnlistedTransaction.Equals(transaction))
				{
					throw System.Data.Common.ADP.TransactionPresent();
				}
			}
			else
			{
				innerConnection.EnlistTransaction(transaction);
				GC.KeepAlive(this);
			}
		}

		private System.Data.ProviderBase.DbMetaDataFactory GetMetaDataFactory(System.Data.ProviderBase.DbConnectionInternal internalConnection)
		{
			return ConnectionFactory.GetMetaDataFactory(_poolGroup, internalConnection);
		}

		internal System.Data.ProviderBase.DbMetaDataFactory GetMetaDataFactoryInternal(System.Data.ProviderBase.DbConnectionInternal internalConnection)
		{
			return GetMetaDataFactory(internalConnection);
		}

		public override DataTable GetSchema()
		{
			return GetSchema(DbMetaDataCollectionNames.MetaDataCollections, null);
		}

		public override DataTable GetSchema(string collectionName)
		{
			return GetSchema(collectionName, null);
		}

		public override DataTable GetSchema(string collectionName, string[] restrictionValues)
		{
			ExecutePermission.Demand();
			return InnerConnection.GetSchema(ConnectionFactory, PoolGroup, this, collectionName, restrictionValues);
		}

		internal void NotifyWeakReference(int message)
		{
			InnerConnection.NotifyWeakReference(message);
		}

		internal void PermissionDemand()
		{
			System.Data.Common.DbConnectionOptions dbConnectionOptions = PoolGroup?.ConnectionOptions;
			if (dbConnectionOptions == null || dbConnectionOptions.IsEmpty)
			{
				throw System.Data.Common.ADP.NoConnectionString();
			}
			System.Data.Common.DbConnectionOptions userConnectionOptions = UserConnectionOptions;
			userConnectionOptions.DemandPermission();
		}

		internal void RemoveWeakReference(object value)
		{
			InnerConnection.RemoveWeakReference(value);
		}

		internal void SetInnerConnectionEvent(System.Data.ProviderBase.DbConnectionInternal to)
		{
			ConnectionState connectionState = _innerConnection.State & ConnectionState.Open;
			ConnectionState connectionState2 = to.State & ConnectionState.Open;
			if (connectionState != connectionState2 && connectionState2 == ConnectionState.Closed)
			{
				_closeCount++;
			}
			_innerConnection = to;
			if (connectionState == ConnectionState.Closed && ConnectionState.Open == connectionState2)
			{
				OnStateChange(System.Data.ProviderBase.DbConnectionInternal.StateChangeOpen);
			}
			else if (ConnectionState.Open == connectionState && connectionState2 == ConnectionState.Closed)
			{
				OnStateChange(System.Data.ProviderBase.DbConnectionInternal.StateChangeClosed);
			}
			else if (connectionState != connectionState2)
			{
				OnStateChange(new StateChangeEventArgs(connectionState, connectionState2));
			}
		}

		internal bool SetInnerConnectionFrom(System.Data.ProviderBase.DbConnectionInternal to, System.Data.ProviderBase.DbConnectionInternal from)
		{
			return from == Interlocked.CompareExchange(ref _innerConnection, to, from);
		}

		internal void SetInnerConnectionTo(System.Data.ProviderBase.DbConnectionInternal to)
		{
			_innerConnection = to;
		}

		[Conditional("DEBUG")]
		internal static void VerifyExecutePermission()
		{
			//Discarded unreachable code: IL_000f
			try
			{
				ExecutePermission.Demand();
			}
			catch (SecurityException)
			{
				throw;
			}
		}
	}
}
namespace System.Data.ProviderBase
{
	internal abstract class DbConnectionFactory
	{
		private const int PruningDueTime = 240000;

		private const int PruningPeriod = 30000;

		private Dictionary<string, DbConnectionPoolGroup> _connectionPoolGroups;

		private readonly List<DbConnectionPool> _poolsToRelease;

		private readonly List<DbConnectionPoolGroup> _poolGroupsToRelease;

		private readonly DbConnectionPoolCounters _performanceCounters;

		private readonly Timer _pruningTimer;

		private static int _objectTypeCount;

		internal readonly int _objectID = Interlocked.Increment(ref _objectTypeCount);

		internal DbConnectionPoolCounters PerformanceCounters => _performanceCounters;

		public abstract DbProviderFactory ProviderFactory { get; }

		internal int ObjectID => _objectID;

		protected DbConnectionFactory()
			: this(DbConnectionPoolCountersNoCounters.SingletonInstance)
		{
		}

		protected DbConnectionFactory(DbConnectionPoolCounters performanceCounters)
		{
			_performanceCounters = performanceCounters;
			_connectionPoolGroups = new Dictionary<string, DbConnectionPoolGroup>();
			_poolsToRelease = new List<DbConnectionPool>();
			_poolGroupsToRelease = new List<DbConnectionPoolGroup>();
			_pruningTimer = CreatePruningTimer();
		}

		public void ClearAllPools()
		{
			Bid.ScopeEnter(out var hScp, "<prov.DbConnectionFactory.ClearAllPools|API> ");
			try
			{
				Dictionary<string, DbConnectionPoolGroup> connectionPoolGroups = _connectionPoolGroups;
				foreach (KeyValuePair<string, DbConnectionPoolGroup> item in connectionPoolGroups)
				{
					item.Value?.Clear();
				}
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		public void ClearPool(DbConnection connection)
		{
			System.Data.Common.ADP.CheckArgumentNull(connection, "connection");
			Bid.ScopeEnter(out var hScp, "<prov.DbConnectionFactory.ClearPool|API> %d#", GetObjectId(connection));
			try
			{
				GetConnectionPoolGroup(connection)?.Clear();
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		internal virtual DbConnectionPoolProviderInfo CreateConnectionPoolProviderInfo(System.Data.Common.DbConnectionOptions connectionOptions)
		{
			return null;
		}

		protected virtual DbMetaDataFactory CreateMetaDataFactory(DbConnectionInternal internalConnection, out bool cacheMetaDataFactory)
		{
			cacheMetaDataFactory = false;
			throw System.Data.Common.ADP.NotSupported();
		}

		internal DbConnectionInternal CreateNonPooledConnection(DbConnection owningConnection, DbConnectionPoolGroup poolGroup)
		{
			System.Data.Common.DbConnectionOptions connectionOptions = poolGroup.ConnectionOptions;
			DbConnectionPoolGroupProviderInfo providerInfo = poolGroup.ProviderInfo;
			DbConnectionInternal dbConnectionInternal = CreateConnection(connectionOptions, providerInfo, null, owningConnection);
			if (dbConnectionInternal != null)
			{
				PerformanceCounters.HardConnectsPerSecond.Increment();
				dbConnectionInternal.MakeNonPooledObject(owningConnection, PerformanceCounters);
			}
			Bid.Trace("<prov.DbConnectionFactory.CreateNonPooledConnection|RES|CPOOL> %d#, Non-pooled database connection created.\n", ObjectID);
			return dbConnectionInternal;
		}

		internal DbConnectionInternal CreatePooledConnection(DbConnection owningConnection, DbConnectionPool pool, System.Data.Common.DbConnectionOptions options)
		{
			DbConnectionPoolGroupProviderInfo providerInfo = pool.PoolGroup.ProviderInfo;
			DbConnectionInternal dbConnectionInternal = CreateConnection(options, providerInfo, pool, owningConnection);
			if (dbConnectionInternal != null)
			{
				PerformanceCounters.HardConnectsPerSecond.Increment();
				dbConnectionInternal.MakePooledConnection(pool);
			}
			Bid.Trace("<prov.DbConnectionFactory.CreatePooledConnection|RES|CPOOL> %d#, Pooled database connection created.\n", ObjectID);
			return dbConnectionInternal;
		}

		internal virtual DbConnectionPoolGroupProviderInfo CreateConnectionPoolGroupProviderInfo(System.Data.Common.DbConnectionOptions connectionOptions)
		{
			return null;
		}

		private Timer CreatePruningTimer()
		{
			TimerCallback callback = PruneConnectionPoolGroups;
			return new Timer(callback, null, 240000, 30000);
		}

		internal DbConnectionInternal GetConnection(DbConnection owningConnection)
		{
			int num = 5;
			DbConnectionInternal dbConnectionInternal;
			do
			{
				DbConnectionPoolGroup connectionPoolGroup = GetConnectionPoolGroup(owningConnection);
				DbConnectionPool connectionPool = GetConnectionPool(owningConnection, connectionPoolGroup);
				if (connectionPool == null)
				{
					connectionPoolGroup = GetConnectionPoolGroup(owningConnection);
					dbConnectionInternal = CreateNonPooledConnection(owningConnection, connectionPoolGroup);
					PerformanceCounters.NumberOfNonPooledConnections.Increment();
					continue;
				}
				dbConnectionInternal = connectionPool.GetConnection(owningConnection);
				if (dbConnectionInternal != null)
				{
					break;
				}
				if (connectionPool.IsRunning)
				{
					Bid.Trace("<prov.DbConnectionFactory.GetConnection|RES|CPOOL> %d#, GetConnection failed because a pool timeout occurred.\n", ObjectID);
					throw System.Data.Common.ADP.PooledOpenTimeout();
				}
				Thread.Sleep(1);
			}
			while (dbConnectionInternal == null && num-- > 0);
			if (dbConnectionInternal == null)
			{
				Bid.Trace("<prov.DbConnectionFactory.GetConnection|RES|CPOOL> %d#, GetConnection failed because a pool timeout occurred and all retries were exhausted.\n", ObjectID);
				throw System.Data.Common.ADP.PooledOpenTimeout();
			}
			return dbConnectionInternal;
		}

		private DbConnectionPool GetConnectionPool(DbConnection owningObject, DbConnectionPoolGroup connectionPoolGroup)
		{
			if (connectionPoolGroup.IsDisabled && connectionPoolGroup.PoolGroupOptions != null)
			{
				Bid.Trace("<prov.DbConnectionFactory.GetConnectionPool|RES|INFO|CPOOL> %d#, DisabledPoolGroup=%d#\n", ObjectID, connectionPoolGroup.ObjectID);
				DbConnectionPoolGroupOptions poolGroupOptions = connectionPoolGroup.PoolGroupOptions;
				System.Data.Common.DbConnectionOptions userConnectionOptions = connectionPoolGroup.ConnectionOptions;
				string connectionString = userConnectionOptions.UsersConnectionString(hidePassword: false);
				connectionPoolGroup = GetConnectionPoolGroup(connectionString, poolGroupOptions, ref userConnectionOptions);
				SetConnectionPoolGroup(owningObject, connectionPoolGroup);
			}
			return connectionPoolGroup.GetConnectionPool(this);
		}

		internal DbConnectionPoolGroup GetConnectionPoolGroup(string connectionString, DbConnectionPoolGroupOptions poolOptions, ref System.Data.Common.DbConnectionOptions userConnectionOptions)
		{
			if (System.Data.Common.ADP.IsEmpty(connectionString))
			{
				return null;
			}
			Dictionary<string, DbConnectionPoolGroup> connectionPoolGroups = _connectionPoolGroups;
			if (!connectionPoolGroups.TryGetValue(connectionString, out var value) || (value.IsDisabled && value.PoolGroupOptions != null))
			{
				System.Data.Common.DbConnectionOptions dbConnectionOptions = CreateConnectionOptions(connectionString, userConnectionOptions);
				if (dbConnectionOptions == null)
				{
					throw System.Data.Common.ADP.InternalConnectionError(System.Data.Common.ADP.ConnectionError.ConnectionOptionsMissing);
				}
				string text = connectionString;
				if (userConnectionOptions == null)
				{
					userConnectionOptions = dbConnectionOptions;
					text = dbConnectionOptions.Expand();
					if ((object)text != connectionString)
					{
						return GetConnectionPoolGroup(text, null, ref userConnectionOptions);
					}
				}
				if (poolOptions == null && System.Data.Common.ADP.IsWindowsNT)
				{
					poolOptions = ((value == null) ? CreateConnectionPoolGroupOptions(dbConnectionOptions) : value.PoolGroupOptions);
				}
				DbConnectionPoolGroup dbConnectionPoolGroup = new DbConnectionPoolGroup(dbConnectionOptions, poolOptions);
				dbConnectionPoolGroup.ProviderInfo = CreateConnectionPoolGroupProviderInfo(dbConnectionOptions);
				lock (this)
				{
					connectionPoolGroups = _connectionPoolGroups;
					if (!connectionPoolGroups.TryGetValue(text, out value))
					{
						Dictionary<string, DbConnectionPoolGroup> dictionary = new Dictionary<string, DbConnectionPoolGroup>(1 + connectionPoolGroups.Count);
						foreach (KeyValuePair<string, DbConnectionPoolGroup> item in connectionPoolGroups)
						{
							dictionary.Add(item.Key, item.Value);
						}
						dictionary.Add(text, dbConnectionPoolGroup);
						PerformanceCounters.NumberOfActiveConnectionPoolGroups.Increment();
						value = dbConnectionPoolGroup;
						_connectionPoolGroups = dictionary;
						return value;
					}
					return value;
				}
			}
			if (userConnectionOptions == null)
			{
				userConnectionOptions = value.ConnectionOptions;
			}
			return value;
		}

		internal DbMetaDataFactory GetMetaDataFactory(DbConnectionPoolGroup connectionPoolGroup, DbConnectionInternal internalConnection)
		{
			DbMetaDataFactory dbMetaDataFactory = connectionPoolGroup.MetaDataFactory;
			if (dbMetaDataFactory == null)
			{
				bool cacheMetaDataFactory = false;
				dbMetaDataFactory = CreateMetaDataFactory(internalConnection, out cacheMetaDataFactory);
				if (cacheMetaDataFactory)
				{
					connectionPoolGroup.MetaDataFactory = dbMetaDataFactory;
				}
			}
			return dbMetaDataFactory;
		}

		private void PruneConnectionPoolGroups(object state)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<prov.DbConnectionFactory.PruneConnectionPoolGroups|RES|INFO|CPOOL> %d#\n", ObjectID);
			}
			lock (_poolsToRelease)
			{
				if (_poolsToRelease.Count != 0)
				{
					DbConnectionPool[] array = _poolsToRelease.ToArray();
					DbConnectionPool[] array2 = array;
					foreach (DbConnectionPool dbConnectionPool in array2)
					{
						if (dbConnectionPool == null)
						{
							continue;
						}
						dbConnectionPool.Clear();
						if (dbConnectionPool.Count == 0)
						{
							_poolsToRelease.Remove(dbConnectionPool);
							if (Bid.AdvancedOn)
							{
								Bid.Trace("<prov.DbConnectionFactory.PruneConnectionPoolGroups|RES|INFO|CPOOL> %d#, ReleasePool=%d#\n", ObjectID, dbConnectionPool.ObjectID);
							}
							PerformanceCounters.NumberOfInactiveConnectionPools.Decrement();
						}
					}
				}
			}
			lock (_poolGroupsToRelease)
			{
				if (_poolGroupsToRelease.Count != 0)
				{
					DbConnectionPoolGroup[] array3 = _poolGroupsToRelease.ToArray();
					DbConnectionPoolGroup[] array4 = array3;
					foreach (DbConnectionPoolGroup dbConnectionPoolGroup in array4)
					{
						if (dbConnectionPoolGroup == null)
						{
							continue;
						}
						dbConnectionPoolGroup.Clear();
						if (dbConnectionPoolGroup.Count == 0)
						{
							_poolGroupsToRelease.Remove(dbConnectionPoolGroup);
							if (Bid.AdvancedOn)
							{
								Bid.Trace("<prov.DbConnectionFactory.PruneConnectionPoolGroups|RES|INFO|CPOOL> %d#, ReleasePoolGroup=%d#\n", ObjectID, dbConnectionPoolGroup.ObjectID);
							}
							PerformanceCounters.NumberOfInactiveConnectionPoolGroups.Decrement();
						}
					}
				}
			}
			lock (this)
			{
				Dictionary<string, DbConnectionPoolGroup> connectionPoolGroups = _connectionPoolGroups;
				Dictionary<string, DbConnectionPoolGroup> dictionary = new Dictionary<string, DbConnectionPoolGroup>(connectionPoolGroups.Count);
				foreach (KeyValuePair<string, DbConnectionPoolGroup> item in connectionPoolGroups)
				{
					if (item.Value != null)
					{
						if (item.Value.Prune())
						{
							PerformanceCounters.NumberOfActiveConnectionPoolGroups.Decrement();
							QueuePoolGroupForRelease(item.Value);
						}
						else
						{
							dictionary.Add(item.Key, item.Value);
						}
					}
				}
				_connectionPoolGroups = dictionary;
			}
		}

		internal void QueuePoolForRelease(DbConnectionPool pool, bool clearing)
		{
			pool.Shutdown();
			lock (_poolsToRelease)
			{
				if (clearing)
				{
					pool.Clear();
				}
				_poolsToRelease.Add(pool);
			}
			PerformanceCounters.NumberOfInactiveConnectionPools.Increment();
		}

		internal void QueuePoolGroupForRelease(DbConnectionPoolGroup poolGroup)
		{
			Bid.Trace("<prov.DbConnectionFactory.QueuePoolGroupForRelease|RES|INFO|CPOOL> %d#, poolGroup=%d#\n", ObjectID, poolGroup.ObjectID);
			lock (_poolGroupsToRelease)
			{
				_poolGroupsToRelease.Add(poolGroup);
			}
			PerformanceCounters.NumberOfInactiveConnectionPoolGroups.Increment();
		}

		protected abstract DbConnectionInternal CreateConnection(System.Data.Common.DbConnectionOptions options, object poolGroupProviderInfo, DbConnectionPool pool, DbConnection owningConnection);

		protected abstract System.Data.Common.DbConnectionOptions CreateConnectionOptions(string connectionString, System.Data.Common.DbConnectionOptions previous);

		protected abstract DbConnectionPoolGroupOptions CreateConnectionPoolGroupOptions(System.Data.Common.DbConnectionOptions options);

		internal abstract DbConnectionPoolGroup GetConnectionPoolGroup(DbConnection connection);

		internal abstract DbConnectionInternal GetInnerConnection(DbConnection connection);

		protected abstract int GetObjectId(DbConnection connection);

		internal abstract void PermissionDemand(DbConnection outerConnection);

		internal abstract void SetConnectionPoolGroup(DbConnection outerConnection, DbConnectionPoolGroup poolGroup);

		internal abstract void SetInnerConnectionEvent(DbConnection owningObject, DbConnectionInternal to);

		internal abstract bool SetInnerConnectionFrom(DbConnection owningObject, DbConnectionInternal to, DbConnectionInternal from);

		internal abstract void SetInnerConnectionTo(DbConnection owningObject, DbConnectionInternal to);
	}
}
namespace System.Data.OracleClient
{
	internal sealed class OracleConnectionFactory : System.Data.ProviderBase.DbConnectionFactory
	{
		public const string _metaDataXml = "MetaDataXml";

		public static readonly OracleConnectionFactory SingletonInstance = new OracleConnectionFactory();

		public override DbProviderFactory ProviderFactory => OracleClientFactory.Instance;

		private OracleConnectionFactory()
			: base(OraclePerformanceCounters.SingletonInstance)
		{
		}

		protected override System.Data.ProviderBase.DbConnectionInternal CreateConnection(System.Data.Common.DbConnectionOptions options, object poolGroupProviderInfo, System.Data.ProviderBase.DbConnectionPool pool, DbConnection owningObject)
		{
			return new OracleInternalConnection(options as OracleConnectionString);
		}

		protected override System.Data.Common.DbConnectionOptions CreateConnectionOptions(string connectionOptions, System.Data.Common.DbConnectionOptions previous)
		{
			return new OracleConnectionString(connectionOptions);
		}

		protected override System.Data.ProviderBase.DbConnectionPoolGroupOptions CreateConnectionPoolGroupOptions(System.Data.Common.DbConnectionOptions connectionOptions)
		{
			OracleConnectionString oracleConnectionString = (OracleConnectionString)connectionOptions;
			System.Data.ProviderBase.DbConnectionPoolGroupOptions result = null;
			if (oracleConnectionString.Pooling)
			{
				result = new System.Data.ProviderBase.DbConnectionPoolGroupOptions(oracleConnectionString.IntegratedSecurity, oracleConnectionString.MinPoolSize, oracleConnectionString.MaxPoolSize, 30000, oracleConnectionString.LoadBalanceTimeout, oracleConnectionString.Enlist, useDeactivateQueue: false);
			}
			return result;
		}

		protected override System.Data.ProviderBase.DbMetaDataFactory CreateMetaDataFactory(System.Data.ProviderBase.DbConnectionInternal internalConnection, out bool cacheMetaDataFactory)
		{
			cacheMetaDataFactory = false;
			NameValueCollection nameValueCollection = (NameValueCollection)System.Configuration.PrivilegedConfigurationManager.GetSection("system.data.oracleclient");
			Stream stream = null;
			if (nameValueCollection != null)
			{
				string[] values = nameValueCollection.GetValues("MetaDataXml");
				if (values != null)
				{
					stream = System.Data.Common.ADP.GetXmlStreamFromValues(values, "MetaDataXml");
				}
			}
			if (stream == null)
			{
				stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("System.Data.OracleClient.OracleMetaData.xml");
				cacheMetaDataFactory = true;
			}
			return new System.Data.ProviderBase.DbMetaDataFactory(stream, internalConnection.ServerVersion, internalConnection.ServerVersionNormalized);
		}

		internal override System.Data.ProviderBase.DbConnectionPoolGroup GetConnectionPoolGroup(DbConnection connection)
		{
			if (connection is OracleConnection oracleConnection)
			{
				return oracleConnection.PoolGroup;
			}
			return null;
		}

		internal override System.Data.ProviderBase.DbConnectionInternal GetInnerConnection(DbConnection connection)
		{
			if (connection is OracleConnection oracleConnection)
			{
				return oracleConnection.InnerConnection;
			}
			return null;
		}

		protected override int GetObjectId(DbConnection connection)
		{
			if (connection is OracleConnection oracleConnection)
			{
				return oracleConnection.ObjectID;
			}
			return 0;
		}

		internal override void PermissionDemand(DbConnection outerConnection)
		{
			if (outerConnection is OracleConnection oracleConnection)
			{
				oracleConnection.PermissionDemand();
			}
		}

		internal override void SetConnectionPoolGroup(DbConnection outerConnection, System.Data.ProviderBase.DbConnectionPoolGroup poolGroup)
		{
			if (outerConnection is OracleConnection oracleConnection)
			{
				oracleConnection.PoolGroup = poolGroup;
			}
		}

		internal override void SetInnerConnectionEvent(DbConnection owningObject, System.Data.ProviderBase.DbConnectionInternal to)
		{
			if (owningObject is OracleConnection oracleConnection)
			{
				oracleConnection.SetInnerConnectionEvent(to);
			}
		}

		internal override bool SetInnerConnectionFrom(DbConnection owningObject, System.Data.ProviderBase.DbConnectionInternal to, System.Data.ProviderBase.DbConnectionInternal from)
		{
			if (owningObject is OracleConnection oracleConnection)
			{
				return oracleConnection.SetInnerConnectionFrom(to, from);
			}
			return false;
		}

		internal override void SetInnerConnectionTo(DbConnection owningObject, System.Data.ProviderBase.DbConnectionInternal to)
		{
			if (owningObject is OracleConnection oracleConnection)
			{
				oracleConnection.SetInnerConnectionTo(to);
			}
		}
	}
}
namespace System.Data.ProviderBase
{
	internal abstract class DbConnectionPoolCounters
	{
		private static class CreationData
		{
			internal static readonly CounterCreationData HardConnectsPerSecond = new CounterCreationData("HardConnectsPerSecond", "The number of actual connections per second that are being made to servers", PerformanceCounterType.RateOfCountsPerSecond32);

			internal static readonly CounterCreationData HardDisconnectsPerSecond = new CounterCreationData("HardDisconnectsPerSecond", "The number of actual disconnects per second that are being made to servers", PerformanceCounterType.RateOfCountsPerSecond32);

			internal static readonly CounterCreationData SoftConnectsPerSecond = new CounterCreationData("SoftConnectsPerSecond", "The number of connections we get from the pool per second", PerformanceCounterType.RateOfCountsPerSecond32);

			internal static readonly CounterCreationData SoftDisconnectsPerSecond = new CounterCreationData("SoftDisconnectsPerSecond", "The number of connections we return to the pool per second", PerformanceCounterType.RateOfCountsPerSecond32);

			internal static readonly CounterCreationData NumberOfNonPooledConnections = new CounterCreationData("NumberOfNonPooledConnections", "The number of connections that are not using connection pooling", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfPooledConnections = new CounterCreationData("NumberOfPooledConnections", "The number of connections that are managed by the connection pooler", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfActiveConnectionPoolGroups = new CounterCreationData("NumberOfActiveConnectionPoolGroups", "The number of unique connection strings", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfInactiveConnectionPoolGroups = new CounterCreationData("NumberOfInactiveConnectionPoolGroups", "The number of unique connection strings waiting for pruning", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfActiveConnectionPools = new CounterCreationData("NumberOfActiveConnectionPools", "The number of connection pools", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfInactiveConnectionPools = new CounterCreationData("NumberOfInactiveConnectionPools", "The number of connection pools", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfActiveConnections = new CounterCreationData("NumberOfActiveConnections", "The number of connections currently in-use", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfFreeConnections = new CounterCreationData("NumberOfFreeConnections", "The number of connections currently available for use", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfStasisConnections = new CounterCreationData("NumberOfStasisConnections", "The number of connections currently waiting to be made ready for use", PerformanceCounterType.NumberOfItems32);

			internal static readonly CounterCreationData NumberOfReclaimedConnections = new CounterCreationData("NumberOfReclaimedConnections", "The number of connections we reclaim from GC'd external connections", PerformanceCounterType.NumberOfItems32);
		}

		internal sealed class Counter
		{
			private PerformanceCounter _instance;

			internal Counter(string categoryName, string instanceName, string counterName, PerformanceCounterType counterType)
			{
				if (!System.Data.Common.ADP.IsPlatformNT5)
				{
					return;
				}
				try
				{
					if (!System.Data.Common.ADP.IsEmpty(categoryName) && !System.Data.Common.ADP.IsEmpty(instanceName))
					{
						_instance = new PerformanceCounter
						{
							CategoryName = categoryName,
							CounterName = counterName,
							InstanceName = instanceName,
							InstanceLifetime = PerformanceCounterInstanceLifetime.Process,
							ReadOnly = false,
							RawValue = 0L
						};
					}
				}
				catch (InvalidOperationException e)
				{
					System.Data.Common.ADP.TraceExceptionWithoutRethrow(e);
				}
			}

			internal void Decrement()
			{
				_instance?.Decrement();
			}

			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
			internal void Dispose()
			{
				PerformanceCounter instance = _instance;
				_instance = null;
				instance?.RemoveInstance();
			}

			internal void Increment()
			{
				_instance?.Increment();
			}
		}

		internal readonly Counter HardConnectsPerSecond;

		internal readonly Counter HardDisconnectsPerSecond;

		internal readonly Counter SoftConnectsPerSecond;

		internal readonly Counter SoftDisconnectsPerSecond;

		internal readonly Counter NumberOfNonPooledConnections;

		internal readonly Counter NumberOfPooledConnections;

		internal readonly Counter NumberOfActiveConnectionPoolGroups;

		internal readonly Counter NumberOfInactiveConnectionPoolGroups;

		internal readonly Counter NumberOfActiveConnectionPools;

		internal readonly Counter NumberOfInactiveConnectionPools;

		internal readonly Counter NumberOfActiveConnections;

		internal readonly Counter NumberOfFreeConnections;

		internal readonly Counter NumberOfStasisConnections;

		internal readonly Counter NumberOfReclaimedConnections;

		protected DbConnectionPoolCounters()
			: this(null, null)
		{
		}

		protected DbConnectionPoolCounters(string categoryName, string categoryHelp)
		{
			AppDomain.CurrentDomain.DomainUnload += UnloadEventHandler;
			AppDomain.CurrentDomain.ProcessExit += ExitEventHandler;
			AppDomain.CurrentDomain.UnhandledException += ExceptionEventHandler;
			string instanceName = null;
			if (!System.Data.Common.ADP.IsEmpty(categoryName) && System.Data.Common.ADP.IsPlatformNT5)
			{
				instanceName = GetInstanceName();
			}
			HardConnectsPerSecond = new Counter(categoryName, instanceName, CreationData.HardConnectsPerSecond.CounterName, CreationData.HardConnectsPerSecond.CounterType);
			HardDisconnectsPerSecond = new Counter(categoryName, instanceName, CreationData.HardDisconnectsPerSecond.CounterName, CreationData.HardDisconnectsPerSecond.CounterType);
			NumberOfNonPooledConnections = new Counter(categoryName, instanceName, CreationData.NumberOfNonPooledConnections.CounterName, CreationData.NumberOfNonPooledConnections.CounterType);
			NumberOfPooledConnections = new Counter(categoryName, instanceName, CreationData.NumberOfPooledConnections.CounterName, CreationData.NumberOfPooledConnections.CounterType);
			NumberOfActiveConnectionPoolGroups = new Counter(categoryName, instanceName, CreationData.NumberOfActiveConnectionPoolGroups.CounterName, CreationData.NumberOfActiveConnectionPoolGroups.CounterType);
			NumberOfInactiveConnectionPoolGroups = new Counter(categoryName, instanceName, CreationData.NumberOfInactiveConnectionPoolGroups.CounterName, CreationData.NumberOfInactiveConnectionPoolGroups.CounterType);
			NumberOfActiveConnectionPools = new Counter(categoryName, instanceName, CreationData.NumberOfActiveConnectionPools.CounterName, CreationData.NumberOfActiveConnectionPools.CounterType);
			NumberOfInactiveConnectionPools = new Counter(categoryName, instanceName, CreationData.NumberOfInactiveConnectionPools.CounterName, CreationData.NumberOfInactiveConnectionPools.CounterType);
			NumberOfStasisConnections = new Counter(categoryName, instanceName, CreationData.NumberOfStasisConnections.CounterName, CreationData.NumberOfStasisConnections.CounterType);
			NumberOfReclaimedConnections = new Counter(categoryName, instanceName, CreationData.NumberOfReclaimedConnections.CounterName, CreationData.NumberOfReclaimedConnections.CounterType);
			string categoryName2 = null;
			if (!System.Data.Common.ADP.IsEmpty(categoryName))
			{
				TraceSwitch traceSwitch = new TraceSwitch("ConnectionPoolPerformanceCounterDetail", "level of detail to track with connection pool performance counters");
				if (TraceLevel.Verbose == traceSwitch.Level)
				{
					categoryName2 = categoryName;
				}
			}
			SoftConnectsPerSecond = new Counter(categoryName2, instanceName, CreationData.SoftConnectsPerSecond.CounterName, CreationData.SoftConnectsPerSecond.CounterType);
			SoftDisconnectsPerSecond = new Counter(categoryName2, instanceName, CreationData.SoftDisconnectsPerSecond.CounterName, CreationData.SoftDisconnectsPerSecond.CounterType);
			NumberOfActiveConnections = new Counter(categoryName2, instanceName, CreationData.NumberOfActiveConnections.CounterName, CreationData.NumberOfActiveConnections.CounterType);
			NumberOfFreeConnections = new Counter(categoryName2, instanceName, CreationData.NumberOfFreeConnections.CounterName, CreationData.NumberOfFreeConnections.CounterType);
		}

		[FileIOPermission(SecurityAction.Assert, Unrestricted = true)]
		private string GetAssemblyName()
		{
			string result = null;
			Assembly entryAssembly = Assembly.GetEntryAssembly();
			if (entryAssembly != null)
			{
				AssemblyName name = entryAssembly.GetName();
				if (name != null)
				{
					result = name.Name;
				}
			}
			return result;
		}

		private string GetInstanceName()
		{
			string text = null;
			string text2 = GetAssemblyName();
			if (System.Data.Common.ADP.IsEmpty(text2))
			{
				AppDomain currentDomain = AppDomain.CurrentDomain;
				if (currentDomain != null)
				{
					text2 = currentDomain.FriendlyName;
				}
			}
			int currentProcessId = System.Data.Common.SafeNativeMethods.GetCurrentProcessId();
			text = string.Format(null, "{0}[{1}]", text2, currentProcessId);
			return text.Replace('(', '[').Replace(')', ']').Replace('#', '_')
				.Replace('/', '_')
				.Replace('\\', '_');
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		public void Dispose()
		{
			SafeDispose(HardConnectsPerSecond);
			SafeDispose(HardDisconnectsPerSecond);
			SafeDispose(SoftConnectsPerSecond);
			SafeDispose(SoftDisconnectsPerSecond);
			SafeDispose(NumberOfNonPooledConnections);
			SafeDispose(NumberOfPooledConnections);
			SafeDispose(NumberOfActiveConnectionPoolGroups);
			SafeDispose(NumberOfInactiveConnectionPoolGroups);
			SafeDispose(NumberOfActiveConnectionPools);
			SafeDispose(NumberOfActiveConnections);
			SafeDispose(NumberOfFreeConnections);
			SafeDispose(NumberOfStasisConnections);
			SafeDispose(NumberOfReclaimedConnections);
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		private void SafeDispose(Counter counter)
		{
			counter?.Dispose();
		}

		[PrePrepareMethod]
		private void ExceptionEventHandler(object sender, UnhandledExceptionEventArgs e)
		{
			if (e != null && e.IsTerminating)
			{
				Dispose();
			}
		}

		[PrePrepareMethod]
		private void ExitEventHandler(object sender, EventArgs e)
		{
			Dispose();
		}

		[PrePrepareMethod]
		private void UnloadEventHandler(object sender, EventArgs e)
		{
			Dispose();
		}
	}
}
namespace System.Data.OracleClient
{
	internal sealed class OraclePerformanceCounters : System.Data.ProviderBase.DbConnectionPoolCounters
	{
		private const string CategoryName = ".NET Data Provider for Oracle";

		private const string CategoryHelp = "Counters for System.Data.OracleClient";

		public static readonly OraclePerformanceCounters SingletonInstance = new OraclePerformanceCounters();

		[PerformanceCounterPermission(SecurityAction.Assert, PermissionAccess = PerformanceCounterPermissionAccess.Write, MachineName = ".", CategoryName = ".NET Data Provider for Oracle")]
		private OraclePerformanceCounters()
			: base(".NET Data Provider for Oracle", "Counters for System.Data.OracleClient")
		{
		}
	}
}
namespace System.Data.Common
{
	internal class DbConnectionOptions
	{
		private enum ParserState
		{
			NothingYet = 1,
			Key,
			KeyEqual,
			KeyEnd,
			UnquotedValue,
			DoubleQuoteValue,
			DoubleQuoteValueQuote,
			SingleQuoteValue,
			SingleQuoteValueQuote,
			BraceQuoteValue,
			BraceQuoteValueQuote,
			QuotedValueEnd,
			NullTermination
		}

		private const string ConnectionStringValidKeyPattern = "^(?![;\\s])[^\\p{Cc}]+(?<!\\s)$";

		private const string ConnectionStringValidValuePattern = "^[^\0]*$";

		private const string ConnectionStringQuoteValuePattern = "^[^\"'=;\\s\\p{Cc}]*$";

		private const string ConnectionStringQuoteOdbcValuePattern = "^\\{([^\\}\0]|\\}\\})*\\}$";

		internal const string DataDirectory = "|datadirectory|";

		private readonly string _usersConnectionString;

		private readonly Hashtable _parsetable;

		internal readonly System.Data.OracleClient.NameValuePair KeyChain;

		internal readonly bool HasPasswordKeyword;

		internal readonly bool UseOdbcRules;

		private PermissionSet _permissionset;

		internal bool HasBlankPassword
		{
			get
			{
				if (!ConvertValueToIntegratedSecurity())
				{
					if (_parsetable.ContainsKey("password"))
					{
						return ADP.IsEmpty((string)_parsetable["password"]);
					}
					if (_parsetable.ContainsKey("pwd"))
					{
						return ADP.IsEmpty((string)_parsetable["pwd"]);
					}
					if (!_parsetable.ContainsKey("user id") || ADP.IsEmpty((string)_parsetable["user id"]))
					{
						if (_parsetable.ContainsKey("uid"))
						{
							return !ADP.IsEmpty((string)_parsetable["uid"]);
						}
						return false;
					}
					return true;
				}
				return false;
			}
		}

		internal bool HasPersistablePassword
		{
			get
			{
				if (HasPasswordKeyword)
				{
					return ConvertValueToBoolean("persist security info", defaultValue: false);
				}
				return true;
			}
		}

		public bool IsEmpty => null == KeyChain;

		internal Hashtable Parsetable => _parsetable;

		public DbConnectionOptions(string connectionString)
			: this(connectionString, null, useOdbcRules: false)
		{
		}

		public DbConnectionOptions(string connectionString, Hashtable synonyms, bool useOdbcRules)
		{
			UseOdbcRules = useOdbcRules;
			_parsetable = new Hashtable();
			_usersConnectionString = ((connectionString != null) ? connectionString : "");
			if (0 < _usersConnectionString.Length)
			{
				KeyChain = ParseInternal(_parsetable, _usersConnectionString, buildChain: true, synonyms, UseOdbcRules);
				HasPasswordKeyword = _parsetable.ContainsKey("password") || _parsetable.ContainsKey("pwd");
			}
		}

		public string UsersConnectionString(bool hidePassword)
		{
			return UsersConnectionString(hidePassword, forceHidePassword: false);
		}

		private string UsersConnectionString(bool hidePassword, bool forceHidePassword)
		{
			string constr = _usersConnectionString;
			if (HasPasswordKeyword && (forceHidePassword || (hidePassword && !HasPersistablePassword)))
			{
				ReplacePasswordPwd(out constr, fakePassword: false);
			}
			if (constr == null)
			{
				return "";
			}
			return constr;
		}

		internal string UsersConnectionStringForTrace()
		{
			return UsersConnectionString(hidePassword: true, forceHidePassword: true);
		}

		public bool ConvertValueToBoolean(string keyName, bool defaultValue)
		{
			object obj = _parsetable[keyName];
			if (obj == null)
			{
				return defaultValue;
			}
			return ConvertValueToBooleanInternal(keyName, (string)obj);
		}

		internal static bool ConvertValueToBooleanInternal(string keyName, string stringValue)
		{
			if (CompareInsensitiveInvariant(stringValue, "true") || CompareInsensitiveInvariant(stringValue, "yes"))
			{
				return true;
			}
			if (CompareInsensitiveInvariant(stringValue, "false") || CompareInsensitiveInvariant(stringValue, "no"))
			{
				return false;
			}
			string strvalue = stringValue.Trim();
			if (CompareInsensitiveInvariant(strvalue, "true") || CompareInsensitiveInvariant(strvalue, "yes"))
			{
				return true;
			}
			if (CompareInsensitiveInvariant(strvalue, "false") || CompareInsensitiveInvariant(strvalue, "no"))
			{
				return false;
			}
			throw ADP.InvalidConnectionOptionValue(keyName);
		}

		public bool ConvertValueToIntegratedSecurity()
		{
			object obj = _parsetable["integrated security"];
			if (obj == null)
			{
				return false;
			}
			return ConvertValueToIntegratedSecurityInternal((string)obj);
		}

		internal bool ConvertValueToIntegratedSecurityInternal(string stringValue)
		{
			if (CompareInsensitiveInvariant(stringValue, "sspi") || CompareInsensitiveInvariant(stringValue, "true") || CompareInsensitiveInvariant(stringValue, "yes"))
			{
				return true;
			}
			if (CompareInsensitiveInvariant(stringValue, "false") || CompareInsensitiveInvariant(stringValue, "no"))
			{
				return false;
			}
			string strvalue = stringValue.Trim();
			if (CompareInsensitiveInvariant(strvalue, "sspi") || CompareInsensitiveInvariant(strvalue, "true") || CompareInsensitiveInvariant(strvalue, "yes"))
			{
				return true;
			}
			if (CompareInsensitiveInvariant(strvalue, "false") || CompareInsensitiveInvariant(strvalue, "no"))
			{
				return false;
			}
			throw ADP.InvalidConnectionOptionValue("integrated security");
		}

		public int ConvertValueToInt32(string keyName, int defaultValue)
		{
			object obj = _parsetable[keyName];
			if (obj == null)
			{
				return defaultValue;
			}
			return ConvertToInt32Internal(keyName, (string)obj);
		}

		internal static int ConvertToInt32Internal(string keyname, string stringValue)
		{
			//Discarded unreachable code: IL_0018, IL_0023
			try
			{
				return int.Parse(stringValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
			}
			catch (FormatException inner)
			{
				throw ADP.InvalidConnectionOptionValue(keyname, inner);
			}
			catch (OverflowException inner2)
			{
				throw ADP.InvalidConnectionOptionValue(keyname, inner2);
			}
		}

		public string ConvertValueToString(string keyName, string defaultValue)
		{
			string text = (string)_parsetable[keyName];
			if (text == null)
			{
				return defaultValue;
			}
			return text;
		}

		private static bool CompareInsensitiveInvariant(string strvalue, string strconst)
		{
			return 0 == StringComparer.OrdinalIgnoreCase.Compare(strvalue, strconst);
		}

		protected internal virtual PermissionSet CreatePermissionSet()
		{
			return null;
		}

		internal void DemandPermission()
		{
			if (_permissionset == null)
			{
				_permissionset = CreatePermissionSet();
			}
			_permissionset.Demand();
		}

		protected internal virtual string Expand()
		{
			return _usersConnectionString;
		}

		private static string GetKeyName(StringBuilder buffer)
		{
			int num = buffer.Length;
			while (0 < num && char.IsWhiteSpace(buffer[num - 1]))
			{
				num--;
			}
			return buffer.ToString(0, num).ToLower(CultureInfo.InvariantCulture);
		}

		private static string GetKeyValue(StringBuilder buffer, bool trimWhitespace)
		{
			int num = buffer.Length;
			int i = 0;
			if (trimWhitespace)
			{
				for (; i < num && char.IsWhiteSpace(buffer[i]); i++)
				{
				}
				while (0 < num && char.IsWhiteSpace(buffer[num - 1]))
				{
					num--;
				}
			}
			return buffer.ToString(i, num - i);
		}

		internal static int GetKeyValuePair(string connectionString, int currentPosition, StringBuilder buffer, bool useOdbcRules, out string keyname, out string keyvalue)
		{
			int index = currentPosition;
			buffer.Length = 0;
			keyname = null;
			keyvalue = null;
			char c = '\0';
			ParserState parserState = ParserState.NothingYet;
			for (int length = connectionString.Length; currentPosition < length; currentPosition++)
			{
				c = connectionString[currentPosition];
				switch (parserState)
				{
				case ParserState.NothingYet:
					if (';' == c || char.IsWhiteSpace(c))
					{
						continue;
					}
					if (c == '\0')
					{
						parserState = ParserState.NullTermination;
						continue;
					}
					if (char.IsControl(c))
					{
						throw ADP.ConnectionStringSyntax(index);
					}
					index = currentPosition;
					if ('=' != c)
					{
						parserState = ParserState.Key;
						goto IL_024d;
					}
					parserState = ParserState.KeyEqual;
					continue;
				case ParserState.Key:
					if ('=' == c)
					{
						parserState = ParserState.KeyEqual;
						continue;
					}
					if (!char.IsWhiteSpace(c) && char.IsControl(c))
					{
						throw ADP.ConnectionStringSyntax(index);
					}
					goto IL_024d;
				case ParserState.KeyEqual:
					if (!useOdbcRules && '=' == c)
					{
						parserState = ParserState.Key;
						goto IL_024d;
					}
					keyname = GetKeyName(buffer);
					if (ADP.IsEmpty(keyname))
					{
						throw ADP.ConnectionStringSyntax(index);
					}
					buffer.Length = 0;
					parserState = ParserState.KeyEnd;
					goto case ParserState.KeyEnd;
				case ParserState.KeyEnd:
					if (char.IsWhiteSpace(c))
					{
						continue;
					}
					if (useOdbcRules)
					{
						if ('{' == c)
						{
							parserState = ParserState.BraceQuoteValue;
							goto IL_024d;
						}
					}
					else
					{
						if ('\'' == c)
						{
							parserState = ParserState.SingleQuoteValue;
							continue;
						}
						if ('"' == c)
						{
							parserState = ParserState.DoubleQuoteValue;
							continue;
						}
					}
					if (';' == c || c == '\0')
					{
						break;
					}
					if (char.IsControl(c))
					{
						throw ADP.ConnectionStringSyntax(index);
					}
					parserState = ParserState.UnquotedValue;
					goto IL_024d;
				case ParserState.UnquotedValue:
					if (!char.IsWhiteSpace(c) && (char.IsControl(c) || ';' == c))
					{
						break;
					}
					goto IL_024d;
				case ParserState.DoubleQuoteValue:
					if ('"' == c)
					{
						parserState = ParserState.DoubleQuoteValueQuote;
						continue;
					}
					if (c == '\0')
					{
						throw ADP.ConnectionStringSyntax(index);
					}
					goto IL_024d;
				case ParserState.DoubleQuoteValueQuote:
					if ('"' == c)
					{
						parserState = ParserState.DoubleQuoteValue;
						goto IL_024d;
					}
					keyvalue = GetKeyValue(buffer, trimWhitespace: false);
					parserState = ParserState.QuotedValueEnd;
					goto case ParserState.QuotedValueEnd;
				case ParserState.SingleQuoteValue:
					if ('\'' == c)
					{
						parserState = ParserState.SingleQuoteValueQuote;
						continue;
					}
					if (c == '\0')
					{
						throw ADP.ConnectionStringSyntax(index);
					}
					goto IL_024d;
				case ParserState.SingleQuoteValueQuote:
					if ('\'' == c)
					{
						parserState = ParserState.SingleQuoteValue;
						goto IL_024d;
					}
					keyvalue = GetKeyValue(buffer, trimWhitespace: false);
					parserState = ParserState.QuotedValueEnd;
					goto case ParserState.QuotedValueEnd;
				case ParserState.BraceQuoteValue:
					if ('}' == c)
					{
						parserState = ParserState.BraceQuoteValueQuote;
					}
					else if (c == '\0')
					{
						throw ADP.ConnectionStringSyntax(index);
					}
					goto IL_024d;
				case ParserState.BraceQuoteValueQuote:
					if ('}' == c)
					{
						parserState = ParserState.BraceQuoteValue;
						goto IL_024d;
					}
					keyvalue = GetKeyValue(buffer, trimWhitespace: false);
					parserState = ParserState.QuotedValueEnd;
					goto case ParserState.QuotedValueEnd;
				case ParserState.QuotedValueEnd:
					if (char.IsWhiteSpace(c))
					{
						continue;
					}
					if (';' != c)
					{
						if (c == '\0')
						{
							parserState = ParserState.NullTermination;
							continue;
						}
						throw ADP.ConnectionStringSyntax(index);
					}
					break;
				case ParserState.NullTermination:
					if (c == '\0' || char.IsWhiteSpace(c))
					{
						continue;
					}
					throw ADP.ConnectionStringSyntax(currentPosition);
				default:
					{
						throw ADP.InternalError(ADP.InternalErrorCode.InvalidParserState1);
					}
					IL_024d:
					buffer.Append(c);
					continue;
				}
				break;
			}
			switch (parserState)
			{
			case ParserState.Key:
			case ParserState.DoubleQuoteValue:
			case ParserState.SingleQuoteValue:
			case ParserState.BraceQuoteValue:
				throw ADP.ConnectionStringSyntax(index);
			case ParserState.KeyEqual:
				keyname = GetKeyName(buffer);
				if (ADP.IsEmpty(keyname))
				{
					throw ADP.ConnectionStringSyntax(index);
				}
				break;
			case ParserState.UnquotedValue:
			{
				keyvalue = GetKeyValue(buffer, trimWhitespace: true);
				char c2 = keyvalue[keyvalue.Length - 1];
				if (!useOdbcRules && ('\'' == c2 || '"' == c2))
				{
					throw ADP.ConnectionStringSyntax(index);
				}
				break;
			}
			case ParserState.DoubleQuoteValueQuote:
			case ParserState.SingleQuoteValueQuote:
			case ParserState.BraceQuoteValueQuote:
			case ParserState.QuotedValueEnd:
				keyvalue = GetKeyValue(buffer, trimWhitespace: false);
				break;
			default:
				throw ADP.InternalError(ADP.InternalErrorCode.InvalidParserState2);
			case ParserState.NothingYet:
			case ParserState.KeyEnd:
			case ParserState.NullTermination:
				break;
			}
			if (';' == c && currentPosition < connectionString.Length)
			{
				currentPosition++;
			}
			return currentPosition;
		}

		private static bool IsValueValidInternal(string keyvalue)
		{
			if (keyvalue != null)
			{
				return -1 == keyvalue.IndexOf('\0');
			}
			return true;
		}

		private static bool IsKeyNameValid(string keyname)
		{
			if (keyname != null)
			{
				if (0 < keyname.Length && ';' != keyname[0] && !char.IsWhiteSpace(keyname[0]))
				{
					return -1 == keyname.IndexOf('\0');
				}
				return false;
			}
			return false;
		}

		private static System.Data.OracleClient.NameValuePair ParseInternal(Hashtable parsetable, string connectionString, bool buildChain, Hashtable synonyms, bool firstKey)
		{
			StringBuilder buffer = new StringBuilder();
			System.Data.OracleClient.NameValuePair nameValuePair = null;
			System.Data.OracleClient.NameValuePair result = null;
			int num = 0;
			int length = connectionString.Length;
			while (num < length)
			{
				int num2 = num;
				num = GetKeyValuePair(connectionString, num2, buffer, firstKey, out var keyname, out var keyvalue);
				if (ADP.IsEmpty(keyname))
				{
					break;
				}
				string text = ((synonyms != null) ? ((string)synonyms[keyname]) : keyname);
				if (!IsKeyNameValid(text))
				{
					throw ADP.KeywordNotSupported(keyname);
				}
				if (!firstKey || !parsetable.Contains(text))
				{
					parsetable[text] = keyvalue;
				}
				if (nameValuePair != null)
				{
					System.Data.OracleClient.NameValuePair nameValuePair3 = (nameValuePair.Next = new System.Data.OracleClient.NameValuePair(text, keyvalue, num - num2));
					nameValuePair = nameValuePair3;
				}
				else if (buildChain)
				{
					result = (nameValuePair = new System.Data.OracleClient.NameValuePair(text, keyvalue, num - num2));
				}
			}
			return result;
		}

		internal System.Data.OracleClient.NameValuePair ReplacePasswordPwd(out string constr, bool fakePassword)
		{
			int num = 0;
			System.Data.OracleClient.NameValuePair result = null;
			System.Data.OracleClient.NameValuePair nameValuePair = null;
			System.Data.OracleClient.NameValuePair nameValuePair2 = null;
			StringBuilder stringBuilder = new StringBuilder(_usersConnectionString.Length);
			for (System.Data.OracleClient.NameValuePair nameValuePair3 = KeyChain; nameValuePair3 != null; nameValuePair3 = nameValuePair3.Next)
			{
				if ("password" != nameValuePair3.Name && "pwd" != nameValuePair3.Name)
				{
					stringBuilder.Append(_usersConnectionString, num, nameValuePair3.Length);
					if (fakePassword)
					{
						nameValuePair2 = new System.Data.OracleClient.NameValuePair(nameValuePair3.Name, nameValuePair3.Value, nameValuePair3.Length);
					}
				}
				else if (fakePassword)
				{
					stringBuilder.Append(nameValuePair3.Name).Append("=*;");
					nameValuePair2 = new System.Data.OracleClient.NameValuePair(nameValuePair3.Name, "*", nameValuePair3.Name.Length + "=*;".Length);
				}
				if (fakePassword)
				{
					if (nameValuePair != null)
					{
						System.Data.OracleClient.NameValuePair nameValuePair5 = (nameValuePair.Next = nameValuePair2);
						nameValuePair = nameValuePair5;
					}
					else
					{
						nameValuePair = (result = nameValuePair2);
					}
				}
				num += nameValuePair3.Length;
			}
			constr = stringBuilder.ToString();
			return result;
		}
	}
}
namespace System.Data.OracleClient
{
	internal sealed class OracleConnectionString : System.Data.Common.DbConnectionOptions
	{
		private static Hashtable _validKeyNamesAndSynonyms;

		private readonly bool _enlist;

		private readonly bool _integratedSecurity;

		private readonly bool _persistSecurityInfo;

		private readonly bool _pooling;

		private readonly bool _unicode;

		private readonly bool _omitOracleConnectionName;

		private readonly int _loadBalanceTimeout;

		private readonly int _maxPoolSize;

		private readonly int _minPoolSize;

		private readonly string _dataSource;

		private readonly string _password;

		private readonly string _userId;

		internal bool Enlist => _enlist;

		internal bool IntegratedSecurity => _integratedSecurity;

		internal bool Pooling => _pooling;

		internal bool Unicode => _unicode;

		internal bool OmitOracleConnectionName => _omitOracleConnectionName;

		internal int LoadBalanceTimeout => _loadBalanceTimeout;

		internal int MaxPoolSize => _maxPoolSize;

		internal int MinPoolSize => _minPoolSize;

		internal string DataSource => _dataSource;

		internal string UserId => _userId;

		internal string Password => _password;

		public OracleConnectionString(string connectionString)
			: base(connectionString, GetParseSynonyms(), useOdbcRules: false)
		{
			_integratedSecurity = ConvertValueToIntegratedSecurity();
			_enlist = ConvertValueToBoolean("enlist", System.Data.Common.ADP.IsWindowsNT);
			_persistSecurityInfo = ConvertValueToBoolean("persist security info", defaultValue: false);
			_pooling = ConvertValueToBoolean("pooling", defaultValue: true);
			_unicode = ConvertValueToBoolean("unicode", defaultValue: false);
			_omitOracleConnectionName = ConvertValueToBoolean("omit oracle connection name", defaultValue: false);
			_loadBalanceTimeout = ConvertValueToInt32("load balance timeout", 0);
			_maxPoolSize = ConvertValueToInt32("max pool size", 100);
			_minPoolSize = ConvertValueToInt32("min pool size", 0);
			_dataSource = ConvertValueToString("data source", "");
			_userId = ConvertValueToString("user id", "");
			_password = ConvertValueToString("password", "");
			if (_userId.Length > 30)
			{
				throw System.Data.Common.ADP.InvalidConnectionOptionLength("user id", 30);
			}
			if (_password.Length > 30)
			{
				throw System.Data.Common.ADP.InvalidConnectionOptionLength("password", 30);
			}
			if (_loadBalanceTimeout < 0)
			{
				throw System.Data.Common.ADP.InvalidConnectionOptionValue("load balance timeout");
			}
			if (_maxPoolSize < 1)
			{
				throw System.Data.Common.ADP.InvalidConnectionOptionValue("max pool size");
			}
			if (_minPoolSize < 0)
			{
				throw System.Data.Common.ADP.InvalidConnectionOptionValue("min pool size");
			}
			if (_maxPoolSize < _minPoolSize)
			{
				throw System.Data.Common.ADP.InvalidMinMaxPoolSizeValues();
			}
		}

		protected internal override PermissionSet CreatePermissionSet()
		{
			PermissionSet permissionSet = new PermissionSet(PermissionState.None);
			permissionSet.AddPermission(new OraclePermission(this));
			return permissionSet;
		}

		internal static Hashtable GetParseSynonyms()
		{
			Hashtable hashtable = _validKeyNamesAndSynonyms;
			if (hashtable == null)
			{
				hashtable = new Hashtable(19);
				hashtable.Add("data source", "data source");
				hashtable.Add("enlist", "enlist");
				hashtable.Add("integrated security", "integrated security");
				hashtable.Add("load balance timeout", "load balance timeout");
				hashtable.Add("max pool size", "max pool size");
				hashtable.Add("min pool size", "min pool size");
				hashtable.Add("omit oracle connection name", "omit oracle connection name");
				hashtable.Add("password", "password");
				hashtable.Add("persist security info", "persist security info");
				hashtable.Add("pooling", "pooling");
				hashtable.Add("unicode", "unicode");
				hashtable.Add("user id", "user id");
				hashtable.Add("server", "data source");
				hashtable.Add("pwd", "password");
				hashtable.Add("persistsecurityinfo", "persist security info");
				hashtable.Add("uid", "user id");
				hashtable.Add("user", "user id");
				hashtable.Add("connection lifetime", "load balance timeout");
				hashtable.Add("workaround oracle bug 914652", "omit oracle connection name");
				_validKeyNamesAndSynonyms = hashtable;
			}
			return hashtable;
		}
	}
	[DefaultProperty("DataSource")]
	[TypeConverter(typeof(OracleConnectionStringBuilderConverter))]
	public sealed class OracleConnectionStringBuilder : DbConnectionStringBuilder
	{
		private enum Keywords
		{
			DataSource,
			PersistSecurityInfo,
			IntegratedSecurity,
			UserID,
			Password,
			Enlist,
			Pooling,
			MinPoolSize,
			MaxPoolSize,
			Unicode,
			LoadBalanceTimeout,
			OmitOracleConnectionName
		}

		internal sealed class OracleConnectionStringBuilderConverter : ExpandableObjectConverter
		{
			public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
			{
				if (typeof(InstanceDescriptor) == destinationType)
				{
					return true;
				}
				return base.CanConvertTo(context, destinationType);
			}

			public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
			{
				if (destinationType == null)
				{
					throw System.Data.Common.ADP.ArgumentNull("destinationType");
				}
				if (typeof(InstanceDescriptor) == destinationType && value is OracleConnectionStringBuilder options)
				{
					return ConvertToInstanceDescriptor(options);
				}
				return base.ConvertTo(context, culture, value, destinationType);
			}

			private InstanceDescriptor ConvertToInstanceDescriptor(OracleConnectionStringBuilder options)
			{
				Type[] types = new Type[1] { typeof(string) };
				object[] arguments = new object[1] { options.ConnectionString };
				ConstructorInfo constructor = typeof(OracleConnectionStringBuilder).GetConstructor(types);
				return new InstanceDescriptor(constructor, arguments);
			}
		}

		private static readonly string[] _validKeywords;

		private static readonly Dictionary<string, Keywords> _keywords;

		private string _dataSource = "";

		private string _password = "";

		private string _userID = "";

		private int _loadBalanceTimeout;

		private int _maxPoolSize = 100;

		private int _minPoolSize;

		private bool _enlist = true;

		private bool _integratedSecurity;

		private bool _persistSecurityInfo;

		private bool _pooling = true;

		private bool _unicode;

		private bool _omitOracleConnectionName;

		public override object this[string keyword]
		{
			get
			{
				Keywords index = GetIndex(keyword);
				return GetAt(index);
			}
			set
			{
				Bid.Trace("<comm.OracleConnectionStringBuilder.set_Item|API> keyword='%ls'\n", keyword);
				if (value != null)
				{
					switch (GetIndex(keyword))
					{
					case Keywords.DataSource:
						DataSource = ConvertToString(value);
						break;
					case Keywords.Password:
						Password = ConvertToString(value);
						break;
					case Keywords.UserID:
						UserID = ConvertToString(value);
						break;
					case Keywords.LoadBalanceTimeout:
						LoadBalanceTimeout = ConvertToInt32(value);
						break;
					case Keywords.MaxPoolSize:
						MaxPoolSize = ConvertToInt32(value);
						break;
					case Keywords.MinPoolSize:
						MinPoolSize = ConvertToInt32(value);
						break;
					case Keywords.IntegratedSecurity:
						IntegratedSecurity = ConvertToIntegratedSecurity(value);
						break;
					case Keywords.Enlist:
						Enlist = ConvertToBoolean(value);
						break;
					case Keywords.PersistSecurityInfo:
						PersistSecurityInfo = ConvertToBoolean(value);
						break;
					case Keywords.Pooling:
						Pooling = ConvertToBoolean(value);
						break;
					case Keywords.Unicode:
						Unicode = ConvertToBoolean(value);
						break;
					case Keywords.OmitOracleConnectionName:
						OmitOracleConnectionName = ConvertToBoolean(value);
						break;
					default:
						throw System.Data.Common.ADP.KeywordNotSupported(keyword);
					}
				}
				else
				{
					Remove(keyword);
				}
			}
		}

		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("DataCategory_Source")]
		[ResDescription("DbConnectionString_DataSource")]
		[DisplayName("Data Source")]
		public string DataSource
		{
			get
			{
				return _dataSource;
			}
			set
			{
				if (value != null && 128 < value.Length)
				{
					throw System.Data.Common.ADP.InvalidConnectionOptionLength("Data Source", 128);
				}
				SetValue("Data Source", value);
				_dataSource = value;
			}
		}

		[ResCategory("DataCategory_Pooling")]
		[DisplayName("Enlist")]
		[RefreshProperties(RefreshProperties.All)]
		[ResDescription("DbConnectionString_Enlist")]
		public bool Enlist
		{
			get
			{
				return _enlist;
			}
			set
			{
				SetValue("Enlist", value);
				_enlist = value;
			}
		}

		[ResCategory("DataCategory_Security")]
		[ResDescription("DbConnectionString_IntegratedSecurity")]
		[RefreshProperties(RefreshProperties.All)]
		[DisplayName("Integrated Security")]
		public bool IntegratedSecurity
		{
			get
			{
				return _integratedSecurity;
			}
			set
			{
				SetValue("Integrated Security", value);
				_integratedSecurity = value;
			}
		}

		[DisplayName("Load Balance Timeout")]
		[ResDescription("DbConnectionString_LoadBalanceTimeout")]
		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("DataCategory_Pooling")]
		public int LoadBalanceTimeout
		{
			get
			{
				return _loadBalanceTimeout;
			}
			set
			{
				if (value < 0)
				{
					throw System.Data.Common.ADP.InvalidConnectionOptionValue("Load Balance Timeout");
				}
				SetValue("Load Balance Timeout", value);
				_loadBalanceTimeout = value;
			}
		}

		[DisplayName("Max Pool Size")]
		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("DataCategory_Pooling")]
		[ResDescription("DbConnectionString_MaxPoolSize")]
		public int MaxPoolSize
		{
			get
			{
				return _maxPoolSize;
			}
			set
			{
				if (value < 1)
				{
					throw System.Data.Common.ADP.InvalidConnectionOptionValue("Max Pool Size");
				}
				SetValue("Max Pool Size", value);
				_maxPoolSize = value;
			}
		}

		[DisplayName("Min Pool Size")]
		[ResCategory("DataCategory_Pooling")]
		[RefreshProperties(RefreshProperties.All)]
		[ResDescription("DbConnectionString_MinPoolSize")]
		public int MinPoolSize
		{
			get
			{
				return _minPoolSize;
			}
			set
			{
				if (value < 0)
				{
					throw System.Data.Common.ADP.InvalidConnectionOptionValue("Min Pool Size");
				}
				SetValue("Min Pool Size", value);
				_minPoolSize = value;
			}
		}

		[RefreshProperties(RefreshProperties.All)]
		[ResDescription("DbConnectionString_OmitOracleConnectionName")]
		[DisplayName("Omit Oracle Connection Name")]
		[ResCategory("DataCategory_Initialization")]
		public bool OmitOracleConnectionName
		{
			get
			{
				return _omitOracleConnectionName;
			}
			set
			{
				SetValue("Omit Oracle Connection Name", value);
				_omitOracleConnectionName = value;
			}
		}

		[PasswordPropertyText(true)]
		[DisplayName("Password")]
		[ResCategory("DataCategory_Security")]
		[ResDescription("DbConnectionString_Password")]
		[RefreshProperties(RefreshProperties.All)]
		public string Password
		{
			get
			{
				return _password;
			}
			set
			{
				if (value != null && 30 < value.Length)
				{
					throw System.Data.Common.ADP.InvalidConnectionOptionLength("Password", 30);
				}
				SetValue("Password", value);
				_password = value;
			}
		}

		[ResDescription("DbConnectionString_PersistSecurityInfo")]
		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("DataCategory_Security")]
		[DisplayName("Persist Security Info")]
		public bool PersistSecurityInfo
		{
			get
			{
				return _persistSecurityInfo;
			}
			set
			{
				SetValue("Persist Security Info", value);
				_persistSecurityInfo = value;
			}
		}

		[RefreshProperties(RefreshProperties.All)]
		[DisplayName("Pooling")]
		[ResCategory("DataCategory_Pooling")]
		[ResDescription("DbConnectionString_Pooling")]
		public bool Pooling
		{
			get
			{
				return _pooling;
			}
			set
			{
				SetValue("Pooling", value);
				_pooling = value;
			}
		}

		[DisplayName("Unicode")]
		[ResDescription("DbConnectionString_Unicode")]
		[ResCategory("DataCategory_Initialization")]
		[RefreshProperties(RefreshProperties.All)]
		public bool Unicode
		{
			get
			{
				return _unicode;
			}
			set
			{
				SetValue("Unicode", value);
				_unicode = value;
			}
		}

		[DisplayName("User ID")]
		[ResDescription("DbConnectionString_UserID")]
		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("DataCategory_Security")]
		public string UserID
		{
			get
			{
				return _userID;
			}
			set
			{
				if (value != null && 30 < value.Length)
				{
					throw System.Data.Common.ADP.InvalidConnectionOptionLength("User ID", 30);
				}
				SetValue("User ID", value);
				_userID = value;
			}
		}

		public override bool IsFixedSize => true;

		public override ICollection Keys => new System.Data.Common.ReadOnlyCollection<string>(_validKeywords);

		public override ICollection Values
		{
			get
			{
				object[] array = new object[_validKeywords.Length];
				for (int i = 0; i < _validKeywords.Length; i++)
				{
					array[i] = GetAt((Keywords)i);
				}
				return new System.Data.Common.ReadOnlyCollection<object>(array);
			}
		}

		static OracleConnectionStringBuilder()
		{
			string[] array = new string[12];
			array[0] = "Data Source";
			array[5] = "Enlist";
			array[2] = "Integrated Security";
			array[10] = "Load Balance Timeout";
			array[8] = "Max Pool Size";
			array[7] = "Min Pool Size";
			array[4] = "Password";
			array[1] = "Persist Security Info";
			array[6] = "Pooling";
			array[9] = "Unicode";
			array[3] = "User ID";
			array[11] = "Omit Oracle Connection Name";
			_validKeywords = array;
			_keywords = new Dictionary<string, Keywords>(19, StringComparer.OrdinalIgnoreCase)
			{
				{
					"Data Source",
					Keywords.DataSource
				},
				{
					"Enlist",
					Keywords.Enlist
				},
				{
					"Integrated Security",
					Keywords.IntegratedSecurity
				},
				{
					"Load Balance Timeout",
					Keywords.LoadBalanceTimeout
				},
				{
					"Max Pool Size",
					Keywords.MaxPoolSize
				},
				{
					"Min Pool Size",
					Keywords.MinPoolSize
				},
				{
					"Omit Oracle Connection Name",
					Keywords.OmitOracleConnectionName
				},
				{
					"Password",
					Keywords.Password
				},
				{
					"Persist Security Info",
					Keywords.PersistSecurityInfo
				},
				{
					"Pooling",
					Keywords.Pooling
				},
				{
					"Unicode",
					Keywords.Unicode
				},
				{
					"User ID",
					Keywords.UserID
				},
				{
					"server",
					Keywords.DataSource
				},
				{
					"connection lifetime",
					Keywords.LoadBalanceTimeout
				},
				{
					"pwd",
					Keywords.Password
				},
				{
					"persistsecurityinfo",
					Keywords.PersistSecurityInfo
				},
				{
					"uid",
					Keywords.UserID
				},
				{
					"user",
					Keywords.UserID
				},
				{
					"Workaround Oracle Bug 914652",
					Keywords.OmitOracleConnectionName
				}
			};
		}

		public OracleConnectionStringBuilder()
			: this(null)
		{
		}

		public OracleConnectionStringBuilder(string connectionString)
		{
			if (!System.Data.Common.ADP.IsEmpty(connectionString))
			{
				base.ConnectionString = connectionString;
			}
		}

		public override void Clear()
		{
			base.Clear();
			for (int i = 0; i < _validKeywords.Length; i++)
			{
				Reset((Keywords)i);
			}
		}

		internal new void ClearPropertyDescriptors()
		{
			base.ClearPropertyDescriptors();
		}

		public override bool ContainsKey(string keyword)
		{
			System.Data.Common.ADP.CheckArgumentNull(keyword, "keyword");
			return _keywords.ContainsKey(keyword);
		}

		private static bool ConvertToBoolean(object value)
		{
			return System.Data.Common.DbConnectionStringBuilderUtil.ConvertToBoolean(value);
		}

		private static int ConvertToInt32(object value)
		{
			return System.Data.Common.DbConnectionStringBuilderUtil.ConvertToInt32(value);
		}

		private static bool ConvertToIntegratedSecurity(object value)
		{
			return System.Data.Common.DbConnectionStringBuilderUtil.ConvertToIntegratedSecurity(value);
		}

		private static string ConvertToString(object value)
		{
			return System.Data.Common.DbConnectionStringBuilderUtil.ConvertToString(value);
		}

		private object GetAt(Keywords index)
		{
			return index switch
			{
				Keywords.DataSource => DataSource, 
				Keywords.Enlist => Enlist, 
				Keywords.IntegratedSecurity => IntegratedSecurity, 
				Keywords.LoadBalanceTimeout => LoadBalanceTimeout, 
				Keywords.MaxPoolSize => MaxPoolSize, 
				Keywords.MinPoolSize => MinPoolSize, 
				Keywords.OmitOracleConnectionName => OmitOracleConnectionName, 
				Keywords.Password => Password, 
				Keywords.PersistSecurityInfo => PersistSecurityInfo, 
				Keywords.Pooling => Pooling, 
				Keywords.Unicode => Unicode, 
				Keywords.UserID => UserID, 
				_ => throw System.Data.Common.ADP.KeywordNotSupported(_validKeywords[(int)index]), 
			};
		}

		private Keywords GetIndex(string keyword)
		{
			System.Data.Common.ADP.CheckArgumentNull(keyword, "keyword");
			if (_keywords.TryGetValue(keyword, out var value))
			{
				return value;
			}
			throw System.Data.Common.ADP.KeywordNotSupported(keyword);
		}

		private Attribute[] GetAttributesFromCollection(AttributeCollection collection)
		{
			Attribute[] array = new Attribute[collection.Count];
			collection.CopyTo(array, 0);
			return array;
		}

		protected override void GetProperties(Hashtable propertyDescriptors)
		{
			foreach (PropertyDescriptor property in TypeDescriptor.GetProperties(this, noCustomTypeDesc: true))
			{
				bool refreshOnChange = false;
				bool flag = false;
				string displayName = property.DisplayName;
				if ("Integrated Security" == displayName)
				{
					refreshOnChange = true;
					flag = property.IsReadOnly;
				}
				else
				{
					if (!("Password" == displayName) && !("User ID" == displayName))
					{
						continue;
					}
					flag = IntegratedSecurity;
				}
				Attribute[] attributesFromCollection = GetAttributesFromCollection(property.Attributes);
				System.Data.Common.DbConnectionStringBuilderDescriptor dbConnectionStringBuilderDescriptor = new System.Data.Common.DbConnectionStringBuilderDescriptor(property.Name, property.ComponentType, property.PropertyType, flag, attributesFromCollection);
				dbConnectionStringBuilderDescriptor.RefreshOnChange = refreshOnChange;
				propertyDescriptors[displayName] = dbConnectionStringBuilderDescriptor;
			}
			base.GetProperties(propertyDescriptors);
		}

		public override bool Remove(string keyword)
		{
			System.Data.Common.ADP.CheckArgumentNull(keyword, "keyword");
			if (_keywords.TryGetValue(keyword, out var value))
			{
				base.Remove(_validKeywords[(int)value]);
				Reset(value);
				return true;
			}
			return false;
		}

		private void Reset(Keywords index)
		{
			switch (index)
			{
			case Keywords.DataSource:
				_dataSource = "";
				break;
			case Keywords.Enlist:
				_enlist = true;
				break;
			case Keywords.IntegratedSecurity:
				_integratedSecurity = false;
				break;
			case Keywords.LoadBalanceTimeout:
				_loadBalanceTimeout = 0;
				break;
			case Keywords.MaxPoolSize:
				_maxPoolSize = 100;
				break;
			case Keywords.MinPoolSize:
				_minPoolSize = 0;
				break;
			case Keywords.OmitOracleConnectionName:
				_omitOracleConnectionName = false;
				break;
			case Keywords.Password:
				_password = "";
				break;
			case Keywords.PersistSecurityInfo:
				_persistSecurityInfo = false;
				break;
			case Keywords.Pooling:
				_pooling = true;
				break;
			case Keywords.Unicode:
				_unicode = false;
				break;
			case Keywords.UserID:
				_userID = "";
				break;
			default:
				throw System.Data.Common.ADP.KeywordNotSupported(_validKeywords[(int)index]);
			}
		}

		private void SetValue(string keyword, bool value)
		{
			base[keyword] = value.ToString(null);
		}

		private void SetValue(string keyword, int value)
		{
			base[keyword] = value.ToString((IFormatProvider)null);
		}

		private void SetValue(string keyword, string value)
		{
			System.Data.Common.ADP.CheckArgumentNull(value, keyword);
			base[keyword] = value;
		}

		public override bool ShouldSerialize(string keyword)
		{
			System.Data.Common.ADP.CheckArgumentNull(keyword, "keyword");
			if (_keywords.TryGetValue(keyword, out var value))
			{
				return base.ShouldSerialize(_validKeywords[(int)value]);
			}
			return false;
		}

		public override bool TryGetValue(string keyword, out object value)
		{
			if (_keywords.TryGetValue(keyword, out var value2))
			{
				value = GetAt(value2);
				return true;
			}
			value = null;
			return false;
		}
	}
	[DefaultEvent("RowUpdated")]
	[Designer("Microsoft.VSDesigner.Data.VS.OracleDataAdapterDesigner, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
	[ToolboxItem("Microsoft.VSDesigner.Data.VS.OracleDataAdapterToolboxItem, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
	public sealed class OracleDataAdapter : DbDataAdapter, IDbDataAdapter, IDataAdapter, ICloneable
	{
		internal static readonly object EventRowUpdated = new object();

		internal static readonly object EventRowUpdating = new object();

		private OracleCommand _deleteCommand;

		private OracleCommand _insertCommand;

		private OracleCommand _selectCommand;

		private OracleCommand _updateCommand;

		private OracleCommandSet _commandSet;

		private int _updateBatchSize = 1;

		[DefaultValue(null)]
		[ResCategory("OracleCategory_Update")]
		[ResDescription("DbDataAdapter_DeleteCommand")]
		[Editor("Microsoft.VSDesigner.Data.Design.DBCommandEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public new OracleCommand DeleteCommand
		{
			get
			{
				return _deleteCommand;
			}
			set
			{
				_deleteCommand = value;
			}
		}

		IDbCommand IDbDataAdapter.DeleteCommand
		{
			get
			{
				return _deleteCommand;
			}
			set
			{
				_deleteCommand = (OracleCommand)value;
			}
		}

		[DefaultValue(null)]
		[ResDescription("DbDataAdapter_InsertCommand")]
		[Editor("Microsoft.VSDesigner.Data.Design.DBCommandEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[ResCategory("OracleCategory_Update")]
		public new OracleCommand InsertCommand
		{
			get
			{
				return _insertCommand;
			}
			set
			{
				_insertCommand = value;
			}
		}

		IDbCommand IDbDataAdapter.InsertCommand
		{
			get
			{
				return _insertCommand;
			}
			set
			{
				_insertCommand = (OracleCommand)value;
			}
		}

		[DefaultValue(null)]
		[ResDescription("DbDataAdapter_SelectCommand")]
		[ResCategory("OracleCategory_Fill")]
		[Editor("Microsoft.VSDesigner.Data.Design.DBCommandEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public new OracleCommand SelectCommand
		{
			get
			{
				return _selectCommand;
			}
			set
			{
				_selectCommand = value;
			}
		}

		IDbCommand IDbDataAdapter.SelectCommand
		{
			get
			{
				return _selectCommand;
			}
			set
			{
				_selectCommand = (OracleCommand)value;
			}
		}

		public override int UpdateBatchSize
		{
			get
			{
				return _updateBatchSize;
			}
			set
			{
				if (0 > value)
				{
					throw System.Data.Common.ADP.MustBePositive("UpdateBatchSize");
				}
				_updateBatchSize = value;
			}
		}

		[Editor("Microsoft.VSDesigner.Data.Design.DBCommandEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[DefaultValue(null)]
		[ResDescription("DbDataAdapter_UpdateCommand")]
		[ResCategory("OracleCategory_Update")]
		public new OracleCommand UpdateCommand
		{
			get
			{
				return _updateCommand;
			}
			set
			{
				_updateCommand = value;
			}
		}

		IDbCommand IDbDataAdapter.UpdateCommand
		{
			get
			{
				return _updateCommand;
			}
			set
			{
				_updateCommand = (OracleCommand)value;
			}
		}

		[ResDescription("DbDataAdapter_RowUpdated")]
		[ResCategory("OracleCategory_Update")]
		public event OracleRowUpdatedEventHandler RowUpdated
		{
			add
			{
				base.Events.AddHandler(EventRowUpdated, value);
			}
			remove
			{
				base.Events.RemoveHandler(EventRowUpdated, value);
			}
		}

		[ResCategory("OracleCategory_Update")]
		[ResDescription("DbDataAdapter_RowUpdating")]
		public event OracleRowUpdatingEventHandler RowUpdating
		{
			add
			{
				OracleRowUpdatingEventHandler oracleRowUpdatingEventHandler = (OracleRowUpdatingEventHandler)base.Events[EventRowUpdating];
				if (oracleRowUpdatingEventHandler != null && value.Target is OracleCommandBuilder)
				{
					OracleRowUpdatingEventHandler oracleRowUpdatingEventHandler2 = (OracleRowUpdatingEventHandler)System.Data.Common.ADP.FindBuilder(oracleRowUpdatingEventHandler);
					if (oracleRowUpdatingEventHandler2 != null)
					{
						base.Events.RemoveHandler(EventRowUpdating, oracleRowUpdatingEventHandler2);
					}
				}
				base.Events.AddHandler(EventRowUpdating, value);
			}
			remove
			{
				base.Events.RemoveHandler(EventRowUpdating, value);
			}
		}

		public OracleDataAdapter()
		{
			GC.SuppressFinalize(this);
		}

		public OracleDataAdapter(OracleCommand selectCommand)
			: this()
		{
			SelectCommand = selectCommand;
		}

		public OracleDataAdapter(string selectCommandText, string selectConnectionString)
			: this()
		{
			OracleConnection connection = new OracleConnection(selectConnectionString);
			SelectCommand = new OracleCommand();
			SelectCommand.Connection = connection;
			SelectCommand.CommandText = selectCommandText;
		}

		public OracleDataAdapter(string selectCommandText, OracleConnection selectConnection)
			: this()
		{
			SelectCommand = new OracleCommand();
			SelectCommand.Connection = selectConnection;
			SelectCommand.CommandText = selectCommandText;
		}

		private OracleDataAdapter(OracleDataAdapter from)
			: base(from)
		{
			GC.SuppressFinalize(this);
		}

		protected override int AddToBatch(IDbCommand command)
		{
			int commandCount = _commandSet.CommandCount;
			_commandSet.Append((OracleCommand)command);
			return commandCount;
		}

		protected override void ClearBatch()
		{
			_commandSet.Clear();
		}

		object ICloneable.Clone()
		{
			return new OracleDataAdapter(this);
		}

		protected override RowUpdatedEventArgs CreateRowUpdatedEvent(DataRow dataRow, IDbCommand command, StatementType statementType, DataTableMapping tableMapping)
		{
			return new OracleRowUpdatedEventArgs(dataRow, command, statementType, tableMapping);
		}

		protected override RowUpdatingEventArgs CreateRowUpdatingEvent(DataRow dataRow, IDbCommand command, StatementType statementType, DataTableMapping tableMapping)
		{
			return new OracleRowUpdatingEventArgs(dataRow, command, statementType, tableMapping);
		}

		protected override int ExecuteBatch()
		{
			return _commandSet.ExecuteNonQuery();
		}

		protected override IDataParameter GetBatchedParameter(int commandIdentifier, int parameterIndex)
		{
			return _commandSet.GetParameter(commandIdentifier, parameterIndex);
		}

		protected override bool GetBatchedRecordsAffected(int commandIdentifier, out int recordsAffected, out Exception error)
		{
			error = null;
			return _commandSet.GetBatchedRecordsAffected(commandIdentifier, out recordsAffected);
		}

		protected override void InitializeBatching()
		{
			_commandSet = new OracleCommandSet();
			OracleCommand oracleCommand = SelectCommand;
			if (oracleCommand == null)
			{
				oracleCommand = InsertCommand;
				if (oracleCommand == null)
				{
					oracleCommand = UpdateCommand;
					if (oracleCommand == null)
					{
						oracleCommand = DeleteCommand;
					}
				}
			}
			if (oracleCommand != null)
			{
				_commandSet.Connection = oracleCommand.Connection;
				_commandSet.Transaction = oracleCommand.Transaction;
				_commandSet.CommandTimeout = oracleCommand.CommandTimeout;
			}
		}

		protected override void OnRowUpdated(RowUpdatedEventArgs value)
		{
			OracleRowUpdatedEventHandler oracleRowUpdatedEventHandler = (OracleRowUpdatedEventHandler)base.Events[EventRowUpdated];
			if (oracleRowUpdatedEventHandler != null && value is OracleRowUpdatedEventArgs)
			{
				oracleRowUpdatedEventHandler(this, (OracleRowUpdatedEventArgs)value);
			}
		}

		protected override void OnRowUpdating(RowUpdatingEventArgs value)
		{
			OracleRowUpdatingEventHandler oracleRowUpdatingEventHandler = (OracleRowUpdatingEventHandler)base.Events[EventRowUpdating];
			if (oracleRowUpdatingEventHandler != null && value is OracleRowUpdatingEventArgs)
			{
				oracleRowUpdatingEventHandler(this, (OracleRowUpdatingEventArgs)value);
			}
		}

		protected override void TerminateBatching()
		{
			if (_commandSet != null)
			{
				_commandSet.Dispose();
				_commandSet = null;
			}
		}
	}
	public sealed class OracleDataReader : DbDataReader
	{
		private const int _prefetchMemory = 65536;

		private const byte x_hasRows_Unknown = 0;

		private const byte x_hasRows_False = 1;

		private const byte x_hasRows_True = 2;

		private OracleConnection _connection;

		private int _connectionCloseCount;

		private OciStatementHandle _statementHandle;

		private string _statementText;

		private CommandBehavior _commandBehavior;

		private OracleColumn[] _columnInfo;

		private NativeBuffer_RowBuffer _buffer;

		private int _rowBufferLength;

		private int _rowsToPrefetch;

		private int _rowsTotal;

		private bool _isLastBuffer;

		private bool _endOfData;

		private bool _closeConnectionToo;

		private bool _keyInfoRequested;

		private byte _hasRows;

		private static int _objectTypeCount;

		internal readonly int ObjectID = Interlocked.Increment(ref _objectTypeCount);

		private System.Data.ProviderBase.FieldNameLookup _fieldNameLookup;

		private DataTable _schemaTable;

		private int _recordsAffected;

		private OracleDataReader[] _refCursorDataReaders;

		private int _nextRefCursor;

		public override int Depth
		{
			get
			{
				AssertReaderIsOpen("Depth");
				return 0;
			}
		}

		private OciErrorHandle ErrorHandle => _connection.ErrorHandle;

		public override int FieldCount
		{
			get
			{
				AssertReaderIsOpen();
				if (_columnInfo == null)
				{
					return 0;
				}
				return _columnInfo.Length;
			}
		}

		public override bool HasRows
		{
			get
			{
				AssertReaderIsOpen();
				bool flag = 2 == _hasRows;
				if (_hasRows == 0)
				{
					flag = ReadInternal();
					if (_buffer != null)
					{
						_buffer.MovePrevious();
					}
					_hasRows = (byte)((!flag) ? 1 : 2);
				}
				return flag;
			}
		}

		public override bool IsClosed
		{
			get
			{
				if (_statementHandle != null && _connection != null)
				{
					return _connectionCloseCount != _connection.CloseCount;
				}
				return true;
			}
		}

		private bool IsValidRow
		{
			get
			{
				if (!_endOfData && _buffer != null)
				{
					return _buffer.CurrentPositionIsValid;
				}
				return false;
			}
		}

		public override int RecordsAffected => _recordsAffected;

		public override object this[int i] => GetValue(i);

		public override object this[string name]
		{
			get
			{
				int ordinal = GetOrdinal(name);
				return GetValue(ordinal);
			}
		}

		internal OracleDataReader(OracleCommand command, OciStatementHandle statementHandle, string statementText, CommandBehavior commandBehavior)
		{
			_commandBehavior = commandBehavior;
			_statementHandle = statementHandle;
			_connection = command.Connection;
			_connectionCloseCount = _connection.CloseCount;
			_columnInfo = null;
			if (OCI.STMT.OCI_STMT_SELECT == command.StatementType)
			{
				FillColumnInfo();
				_recordsAffected = -1;
				if (IsCommandBehavior(CommandBehavior.SchemaOnly))
				{
					_endOfData = true;
				}
			}
			else
			{
				_statementHandle.GetAttribute(OCI.ATTR.OCI_ATTR_ROW_COUNT, out _recordsAffected, ErrorHandle);
				_endOfData = true;
				_hasRows = 1;
			}
			_statementText = statementText;
			_closeConnectionToo = IsCommandBehavior(CommandBehavior.CloseConnection);
			if (CommandType.Text == command.CommandType)
			{
				_keyInfoRequested = IsCommandBehavior(CommandBehavior.KeyInfo);
			}
		}

		internal OracleDataReader(OracleConnection connection, OciStatementHandle statementHandle)
		{
			_commandBehavior = CommandBehavior.Default;
			_statementHandle = statementHandle;
			_connection = connection;
			_connectionCloseCount = _connection.CloseCount;
			_recordsAffected = -1;
			FillColumnInfo();
		}

		internal OracleDataReader(OracleCommand command, ArrayList refCursorParameterOrdinals, string statementText, CommandBehavior commandBehavior)
		{
			_commandBehavior = commandBehavior;
			_statementText = statementText;
			_closeConnectionToo = IsCommandBehavior(CommandBehavior.CloseConnection);
			if (CommandType.Text == command.CommandType)
			{
				_keyInfoRequested = IsCommandBehavior(CommandBehavior.KeyInfo);
			}
			ArrayList arrayList = new ArrayList();
			int num = 0;
			OracleDataReader oracleDataReader = null;
			for (int i = 0; i < refCursorParameterOrdinals.Count; i++)
			{
				int index = (int)refCursorParameterOrdinals[i];
				OracleParameter oracleParameter = command.Parameters[index];
				if (OracleType.Cursor == oracleParameter.OracleType)
				{
					oracleDataReader = (OracleDataReader)oracleParameter.Value;
					oracleDataReader._recordsAffected = num;
					arrayList.Add(oracleDataReader);
					oracleParameter.Value = DBNull.Value;
				}
				else
				{
					num += (int)oracleParameter.Value;
				}
			}
			_refCursorDataReaders = new OracleDataReader[arrayList.Count];
			arrayList.CopyTo(_refCursorDataReaders);
			_nextRefCursor = 0;
			NextResultInternal();
		}

		private void AssertReaderHasColumns()
		{
			if (0 >= FieldCount)
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
		}

		private void AssertReaderHasData()
		{
			if (!IsValidRow)
			{
				throw System.Data.Common.ADP.DataReaderNoData();
			}
		}

		private void AssertReaderIsOpen(string methodName)
		{
			if (IsClosed)
			{
				throw System.Data.Common.ADP.DataReaderClosed(methodName);
			}
		}

		private void AssertReaderIsOpen()
		{
			if (_connection != null && _connectionCloseCount != _connection.CloseCount)
			{
				Close();
			}
			if (_statementHandle == null)
			{
				throw System.Data.Common.ADP.ClosedDataReaderError();
			}
			if (_connection == null || ConnectionState.Open != _connection.State)
			{
				throw System.Data.Common.ADP.ClosedConnectionError();
			}
		}

		private object SetSchemaValue(string value)
		{
			if (System.Data.Common.ADP.IsEmpty(value))
			{
				return DBNull.Value;
			}
			return value;
		}

		private void Cleanup()
		{
			if (_buffer != null)
			{
				_buffer.Dispose();
				_buffer = null;
			}
			if (_columnInfo == null)
			{
				return;
			}
			if (_refCursorDataReaders == null)
			{
				int num = _columnInfo.Length;
				while (--num >= 0)
				{
					if (_columnInfo[num] != null)
					{
						_columnInfo[num].Dispose();
						_columnInfo[num] = null;
					}
				}
			}
			_columnInfo = null;
		}

		public override void Close()
		{
			Bid.ScopeEnter(out var hScp, "<ora.OracleDataReader.Close|API> %d#\n", ObjectID);
			try
			{
				OciHandle.SafeDispose(ref _statementHandle);
				Cleanup();
				if (_refCursorDataReaders != null)
				{
					int num = _refCursorDataReaders.Length;
					while (--num >= 0)
					{
						OracleDataReader oracleDataReader = _refCursorDataReaders[num];
						_refCursorDataReaders[num] = null;
						oracleDataReader?.Dispose();
					}
					_refCursorDataReaders = null;
				}
				if (_closeConnectionToo && _connection != null)
				{
					_connection.Close();
				}
				_connection = null;
				_fieldNameLookup = null;
				_schemaTable = null;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private DataTable CreateSchemaTable(int columnCount)
		{
			DataTable dataTable = new DataTable("SchemaTable");
			dataTable.Locale = CultureInfo.InvariantCulture;
			dataTable.MinimumCapacity = columnCount;
			DataColumn column = new DataColumn(SchemaTableColumn.ColumnName, typeof(string));
			DataColumn dataColumn = new DataColumn(SchemaTableColumn.ColumnOrdinal, typeof(int));
			DataColumn column2 = new DataColumn(SchemaTableColumn.ColumnSize, typeof(int));
			DataColumn column3 = new DataColumn(SchemaTableColumn.NumericPrecision, typeof(short));
			DataColumn column4 = new DataColumn(SchemaTableColumn.NumericScale, typeof(short));
			DataColumn column5 = new DataColumn(SchemaTableColumn.DataType, typeof(Type));
			DataColumn column6 = new DataColumn(SchemaTableColumn.ProviderType, typeof(int));
			DataColumn dataColumn2 = new DataColumn(SchemaTableColumn.IsLong, typeof(bool));
			DataColumn column7 = new DataColumn(SchemaTableColumn.AllowDBNull, typeof(bool));
			DataColumn column8 = new DataColumn(SchemaTableColumn.IsAliased, typeof(bool));
			DataColumn column9 = new DataColumn(SchemaTableColumn.IsExpression, typeof(bool));
			DataColumn column10 = new DataColumn(SchemaTableColumn.IsKey, typeof(bool));
			DataColumn column11 = new DataColumn(SchemaTableColumn.IsUnique, typeof(bool));
			DataColumn column12 = new DataColumn(SchemaTableColumn.BaseSchemaName, typeof(string));
			DataColumn column13 = new DataColumn(SchemaTableColumn.BaseTableName, typeof(string));
			DataColumn column14 = new DataColumn(SchemaTableColumn.BaseColumnName, typeof(string));
			dataColumn.DefaultValue = 0;
			dataColumn2.DefaultValue = false;
			DataColumnCollection columns = dataTable.Columns;
			columns.Add(column);
			columns.Add(dataColumn);
			columns.Add(column2);
			columns.Add(column3);
			columns.Add(column4);
			columns.Add(column5);
			columns.Add(column6);
			columns.Add(dataColumn2);
			columns.Add(column7);
			columns.Add(column8);
			columns.Add(column9);
			columns.Add(column10);
			columns.Add(column11);
			columns.Add(column12);
			columns.Add(column13);
			columns.Add(column14);
			for (int i = 0; i < columns.Count; i++)
			{
				columns[i].ReadOnly = true;
			}
			return dataTable;
		}

		internal void FillColumnInfo()
		{
			bool flag = false;
			_statementHandle.GetAttribute(OCI.ATTR.OCI_ATTR_PARAM_COUNT, out int value, ErrorHandle);
			_columnInfo = new OracleColumn[value];
			_rowBufferLength = 0;
			for (int i = 0; i < value; i++)
			{
				_columnInfo[i] = new OracleColumn(_statementHandle, i, ErrorHandle, _connection);
				if (_columnInfo[i].Describe(ref _rowBufferLength, _connection, ErrorHandle))
				{
					flag = true;
				}
			}
			if (flag || _rowBufferLength == 0)
			{
				_rowsToPrefetch = 1;
			}
			else
			{
				_rowsToPrefetch = (65536 + _rowBufferLength - 1) / _rowBufferLength;
			}
		}

		private void FillSchemaTable(DataTable schemaTable)
		{
			DataColumn column = new DataColumn(SchemaTableOptionalColumn.ProviderSpecificDataType, typeof(Type));
			schemaTable.Columns.Add(column);
			int fieldCount = FieldCount;
			DbSqlParserColumnCollection dbSqlParserColumnCollection = null;
			int num = 0;
			if (_keyInfoRequested)
			{
				OracleSqlParser oracleSqlParser = new OracleSqlParser();
				oracleSqlParser.Parse(_statementText, _connection);
				dbSqlParserColumnCollection = oracleSqlParser.Columns;
				num = dbSqlParserColumnCollection.Count;
			}
			for (int i = 0; i < fieldCount; i++)
			{
				OracleColumn oracleColumn = _columnInfo[i];
				DataRow dataRow = schemaTable.NewRow();
				dataRow[SchemaTableColumn.ColumnName] = oracleColumn.ColumnName;
				dataRow[SchemaTableColumn.ColumnOrdinal] = oracleColumn.Ordinal;
				if (oracleColumn.IsLong | oracleColumn.IsLob)
				{
					dataRow[SchemaTableColumn.ColumnSize] = int.MaxValue;
				}
				else
				{
					dataRow[SchemaTableColumn.ColumnSize] = oracleColumn.SchemaTableSize;
				}
				dataRow[SchemaTableColumn.NumericPrecision] = oracleColumn.Precision;
				dataRow[SchemaTableColumn.NumericScale] = oracleColumn.Scale;
				dataRow[SchemaTableColumn.DataType] = oracleColumn.GetFieldType();
				dataRow[column] = oracleColumn.GetFieldOracleType();
				dataRow[SchemaTableColumn.ProviderType] = oracleColumn.OracleType;
				dataRow[SchemaTableColumn.IsLong] = oracleColumn.IsLong | oracleColumn.IsLob;
				dataRow[SchemaTableColumn.AllowDBNull] = oracleColumn.IsNullable;
				if (_keyInfoRequested && num == fieldCount)
				{
					DbSqlParserColumn dbSqlParserColumn = dbSqlParserColumnCollection[i];
					dataRow[SchemaTableColumn.IsAliased] = dbSqlParserColumn.IsAliased;
					dataRow[SchemaTableColumn.IsExpression] = dbSqlParserColumn.IsExpression;
					dataRow[SchemaTableColumn.IsKey] = dbSqlParserColumn.IsKey;
					dataRow[SchemaTableColumn.IsUnique] = dbSqlParserColumn.IsUnique;
					dataRow[SchemaTableColumn.BaseSchemaName] = SetSchemaValue(OracleSqlParser.CatalogCase(dbSqlParserColumn.SchemaName));
					dataRow[SchemaTableColumn.BaseTableName] = SetSchemaValue(OracleSqlParser.CatalogCase(dbSqlParserColumn.TableName));
					dataRow[SchemaTableColumn.BaseColumnName] = SetSchemaValue(OracleSqlParser.CatalogCase(dbSqlParserColumn.ColumnName));
				}
				else
				{
					dataRow[SchemaTableColumn.IsAliased] = DBNull.Value;
					dataRow[SchemaTableColumn.IsExpression] = DBNull.Value;
					dataRow[SchemaTableColumn.IsKey] = DBNull.Value;
					dataRow[SchemaTableColumn.IsUnique] = DBNull.Value;
					dataRow[SchemaTableColumn.BaseSchemaName] = DBNull.Value;
					dataRow[SchemaTableColumn.BaseTableName] = DBNull.Value;
					dataRow[SchemaTableColumn.BaseColumnName] = DBNull.Value;
				}
				schemaTable.Rows.Add(dataRow);
				dataRow.AcceptChanges();
			}
		}

		public override string GetDataTypeName(int i)
		{
			AssertReaderIsOpen();
			if (_columnInfo == null)
			{
				throw System.Data.Common.ADP.NoData();
			}
			return _columnInfo[i].GetDataTypeName();
		}

		public override Type GetProviderSpecificFieldType(int i)
		{
			if (_columnInfo == null)
			{
				AssertReaderIsOpen();
				throw System.Data.Common.ADP.NoData();
			}
			return _columnInfo[i].GetFieldOracleType();
		}

		public override IEnumerator GetEnumerator()
		{
			return new DbEnumerator(this, IsCommandBehavior(CommandBehavior.CloseConnection));
		}

		public override Type GetFieldType(int i)
		{
			if (_columnInfo == null)
			{
				AssertReaderIsOpen();
				throw System.Data.Common.ADP.NoData();
			}
			return _columnInfo[i].GetFieldType();
		}

		public override string GetName(int i)
		{
			if (_columnInfo == null)
			{
				AssertReaderIsOpen();
				throw System.Data.Common.ADP.NoData();
			}
			return _columnInfo[i].ColumnName;
		}

		public override int GetOrdinal(string name)
		{
			AssertReaderIsOpen("GetOrdinal");
			AssertReaderHasColumns();
			if (_fieldNameLookup == null)
			{
				_fieldNameLookup = new System.Data.ProviderBase.FieldNameLookup(this, -1);
			}
			return _fieldNameLookup.GetOrdinal(name);
		}

		public override DataTable GetSchemaTable()
		{
			DataTable dataTable = _schemaTable;
			if (dataTable == null)
			{
				AssertReaderIsOpen("GetSchemaTable");
				if (0 < FieldCount)
				{
					dataTable = CreateSchemaTable(FieldCount);
					FillSchemaTable(dataTable);
					_schemaTable = dataTable;
				}
				else if (0 > FieldCount)
				{
					throw System.Data.Common.ADP.DataReaderNoData();
				}
			}
			return dataTable;
		}

		public override object GetValue(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetValue(_buffer);
		}

		public override int GetValues(object[] values)
		{
			if (values == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("values");
			}
			AssertReaderIsOpen();
			AssertReaderHasData();
			int num = Math.Min(values.Length, FieldCount);
			for (int i = 0; i < num; i++)
			{
				values[i] = _columnInfo[i].GetValue(_buffer);
			}
			return num;
		}

		public override bool GetBoolean(int i)
		{
			throw System.Data.Common.ADP.NotSupported();
		}

		public override byte GetByte(int i)
		{
			throw System.Data.Common.ADP.NotSupported();
		}

		public override long GetBytes(int i, long fieldOffset, byte[] buffer2, int bufferoffset, int length)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetBytes(_buffer, fieldOffset, buffer2, bufferoffset, length);
		}

		public override char GetChar(int i)
		{
			throw System.Data.Common.ADP.NotSupported();
		}

		public override long GetChars(int i, long fieldOffset, char[] buffer2, int bufferoffset, int length)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetChars(_buffer, fieldOffset, buffer2, bufferoffset, length);
		}

		public override DateTime GetDateTime(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetDateTime(_buffer);
		}

		public override decimal GetDecimal(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetDecimal(_buffer);
		}

		public override double GetDouble(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetDouble(_buffer);
		}

		public override float GetFloat(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetFloat(_buffer);
		}

		public override Guid GetGuid(int i)
		{
			throw System.Data.Common.ADP.NotSupported();
		}

		public override short GetInt16(int i)
		{
			throw System.Data.Common.ADP.NotSupported();
		}

		public override int GetInt32(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetInt32(_buffer);
		}

		public override long GetInt64(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetInt64(_buffer);
		}

		public override object GetProviderSpecificValue(int i)
		{
			return GetOracleValue(i);
		}

		public override int GetProviderSpecificValues(object[] values)
		{
			return GetOracleValues(values);
		}

		public override string GetString(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetString(_buffer);
		}

		public TimeSpan GetTimeSpan(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetTimeSpan(_buffer);
		}

		public OracleBFile GetOracleBFile(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleBFile(_buffer);
		}

		public OracleBinary GetOracleBinary(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleBinary(_buffer);
		}

		public OracleDateTime GetOracleDateTime(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleDateTime(_buffer);
		}

		public OracleLob GetOracleLob(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleLob(_buffer);
		}

		public OracleMonthSpan GetOracleMonthSpan(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleMonthSpan(_buffer);
		}

		public OracleNumber GetOracleNumber(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleNumber(_buffer);
		}

		public OracleString GetOracleString(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleString(_buffer);
		}

		public OracleTimeSpan GetOracleTimeSpan(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleTimeSpan(_buffer);
		}

		public object GetOracleValue(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].GetOracleValue(_buffer);
		}

		public int GetOracleValues(object[] values)
		{
			if (values == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("values");
			}
			AssertReaderIsOpen();
			AssertReaderHasData();
			int num = Math.Min(values.Length, FieldCount);
			for (int i = 0; i < num; i++)
			{
				values[i] = GetOracleValue(i);
			}
			return num;
		}

		private bool IsCommandBehavior(CommandBehavior condition)
		{
			return condition == (condition & _commandBehavior);
		}

		public override bool IsDBNull(int i)
		{
			AssertReaderIsOpen();
			AssertReaderHasData();
			return _columnInfo[i].IsDBNull(_buffer);
		}

		public override bool NextResult()
		{
			Bid.ScopeEnter(out var hScp, "<ora.OracleDataReader.NextResult|API> %d#\n", ObjectID);
			try
			{
				AssertReaderIsOpen("NextResult");
				_fieldNameLookup = null;
				_schemaTable = null;
				return NextResultInternal();
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private bool NextResultInternal()
		{
			Cleanup();
			if (_refCursorDataReaders == null || _nextRefCursor >= _refCursorDataReaders.Length)
			{
				_endOfData = true;
				_hasRows = 1;
				return false;
			}
			if (_nextRefCursor > 0)
			{
				_refCursorDataReaders[_nextRefCursor - 1].Dispose();
				_refCursorDataReaders[_nextRefCursor - 1] = null;
			}
			OciStatementHandle handle = _statementHandle;
			_statementHandle = _refCursorDataReaders[_nextRefCursor]._statementHandle;
			OciHandle.SafeDispose(ref handle);
			_connection = _refCursorDataReaders[_nextRefCursor]._connection;
			_connectionCloseCount = _refCursorDataReaders[_nextRefCursor]._connectionCloseCount;
			_hasRows = _refCursorDataReaders[_nextRefCursor]._hasRows;
			_recordsAffected = _refCursorDataReaders[_nextRefCursor]._recordsAffected;
			_columnInfo = _refCursorDataReaders[_nextRefCursor]._columnInfo;
			_rowBufferLength = _refCursorDataReaders[_nextRefCursor]._rowBufferLength;
			_rowsToPrefetch = _refCursorDataReaders[_nextRefCursor]._rowsToPrefetch;
			_nextRefCursor++;
			_endOfData = false;
			_isLastBuffer = false;
			_rowsTotal = 0;
			return true;
		}

		public override bool Read()
		{
			Bid.ScopeEnter(out var hScp, "<ora.OracleDataReader.Read|API> %d#\n", ObjectID);
			try
			{
				AssertReaderIsOpen("Read");
				bool flag = ReadInternal();
				if (flag)
				{
					_hasRows = 2;
				}
				return flag;
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private bool ReadInternal()
		{
			if (_endOfData)
			{
				return false;
			}
			int num = _columnInfo.Length;
			NativeBuffer_RowBuffer nativeBuffer_RowBuffer = _buffer;
			bool success = false;
			bool[] array = new bool[num];
			SafeHandle[] array2 = new SafeHandle[num];
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				if (nativeBuffer_RowBuffer == null)
				{
					int rowBufferLength = ((_rowsToPrefetch > 1) ? _rowBufferLength : 0);
					nativeBuffer_RowBuffer = new NativeBuffer_RowBuffer(_rowBufferLength, _rowsToPrefetch);
					nativeBuffer_RowBuffer.DangerousAddRef(ref success);
					for (int i = 0; i < num; i++)
					{
						_columnInfo[i].Bind(_statementHandle, nativeBuffer_RowBuffer, ErrorHandle, rowBufferLength);
					}
					_buffer = nativeBuffer_RowBuffer;
				}
				else
				{
					nativeBuffer_RowBuffer.DangerousAddRef(ref success);
				}
				if (nativeBuffer_RowBuffer.MoveNext())
				{
					return true;
				}
				if (_isLastBuffer)
				{
					_endOfData = true;
					return false;
				}
				nativeBuffer_RowBuffer.MoveFirst();
				if (1 == _rowsToPrefetch)
				{
					for (int i = 0; i < num; i++)
					{
						_columnInfo[i].Rebind(_connection, ref array[i], ref array2[i]);
					}
				}
				int num2 = TracedNativeMethods.OCIStmtFetch(_statementHandle, ErrorHandle, _rowsToPrefetch, OCI.FETCH.OCI_FETCH_NEXT, OCI.MODE.OCI_DEFAULT);
				int rowsTotal = _rowsTotal;
				_statementHandle.GetAttribute(OCI.ATTR.OCI_ATTR_ROW_COUNT, out _rowsTotal, ErrorHandle);
				if (num2 == 0)
				{
					return true;
				}
				if (1 == num2)
				{
					_connection.CheckError(ErrorHandle, num2);
					return true;
				}
				if (100 == num2)
				{
					int num3 = _rowsTotal - rowsTotal;
					if (num3 == 0)
					{
						if (_rowsTotal == 0)
						{
							_hasRows = 1;
						}
						_endOfData = true;
						return false;
					}
					nativeBuffer_RowBuffer.NumberOfRows = num3;
					_isLastBuffer = true;
					return true;
				}
				_endOfData = true;
				_connection.CheckError(ErrorHandle, num2);
				return false;
			}
			finally
			{
				if (1 == _rowsToPrefetch)
				{
					for (int i = 0; i < num; i++)
					{
						if (array[i])
						{
							array2[i].DangerousRelease();
						}
					}
				}
				if (success)
				{
					nativeBuffer_RowBuffer.DangerousRelease();
				}
			}
		}
	}
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct OracleDateTime : IComparable, INullable
	{
		private const int MaxOracleFSecPrecision = 9;

		private const byte x_DATE_Length = 7;

		private const byte x_TIMESTAMP_Length = 11;

		private const byte x_TIMESTAMP_WITH_TIMEZONE_Length = 13;

		private const int FractionalSecondsPerTick = 100;

		private byte[] _value;

		public static readonly OracleDateTime MaxValue = new OracleDateTime(DateTime.MaxValue);

		public static readonly OracleDateTime MinValue = new OracleDateTime(DateTime.MinValue);

		public static readonly OracleDateTime Null = new OracleDateTime(isNull: true);

		public bool IsNull => null == _value;

		public DateTime Value
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return ToDateTime(_value);
			}
		}

		public int Year
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var year, out var _, out var _, out var _, out var _, out var _, out var _);
				return year;
			}
		}

		public int Month
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var month, out var _, out var _, out var _, out var _, out var _);
				return month;
			}
		}

		public int Day
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var day, out var _, out var _, out var _, out var _);
				return day;
			}
		}

		public int Hour
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var _, out var hour, out var _, out var _, out var _);
				return hour;
			}
		}

		public int Minute
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var _, out var _, out var minute, out var _, out var _);
				return minute;
			}
		}

		public int Second
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var _, out var _, out var _, out var second, out var _);
				return second;
			}
		}

		public int Millisecond
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var _, out var _, out var _, out var _, out var fsec);
				return (int)((long)(fsec / 100) / 10000L);
			}
		}

		internal bool HasTimeZoneInfo
		{
			get
			{
				if (_value != null)
				{
					return _value.Length >= 13;
				}
				return false;
			}
		}

		internal bool HasTimeInfo
		{
			get
			{
				if (_value != null)
				{
					return _value.Length >= 11;
				}
				return false;
			}
		}

		private OracleDateTime(bool isNull)
		{
			_value = null;
		}

		public OracleDateTime(DateTime dt)
		{
			_value = new byte[11];
			Pack(_value, dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second, (int)(dt.Ticks % 10000000) * 100);
		}

		public OracleDateTime(long ticks)
		{
			_value = new byte[11];
			DateTime dateTime = new DateTime(ticks);
			Pack(_value, dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, dateTime.Minute, dateTime.Second, (int)(dateTime.Ticks % 10000000) * 100);
		}

		public OracleDateTime(int year, int month, int day)
			: this(year, month, day, 0, 0, 0, 0)
		{
		}

		public OracleDateTime(int year, int month, int day, Calendar calendar)
			: this(year, month, day, 0, 0, 0, 0, calendar)
		{
		}

		public OracleDateTime(int year, int month, int day, int hour, int minute, int second)
			: this(year, month, day, hour, minute, second, 0)
		{
		}

		public OracleDateTime(int year, int month, int day, int hour, int minute, int second, Calendar calendar)
			: this(year, month, day, hour, minute, second, 0, calendar)
		{
		}

		public OracleDateTime(int year, int month, int day, int hour, int minute, int second, int millisecond)
		{
			_value = new byte[11];
			new DateTime((year >= 0) ? year : 0, month, (year < 0) ? 1 : day, hour, minute, second, millisecond);
			Pack(_value, year, month, day, hour, minute, second, (int)((long)millisecond * 10000L) * 100);
		}

		public OracleDateTime(int year, int month, int day, int hour, int minute, int second, int millisecond, Calendar calendar)
		{
			_value = new byte[11];
			DateTime dateTime = new DateTime(year, month, day, hour, minute, second, millisecond, calendar);
			Pack(_value, dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, dateTime.Minute, dateTime.Second, (int)(dateTime.Ticks % 10000000) * 100);
		}

		public OracleDateTime(OracleDateTime from)
		{
			_value = new byte[from._value.Length];
			from._value.CopyTo(_value, 0);
		}

		internal OracleDateTime(NativeBuffer buffer, int valueOffset, int lengthOffset, MetaType metaType, OracleConnection connection)
		{
			_value = GetBytesFromBuffer(buffer, valueOffset, lengthOffset, metaType, connection);
		}

		internal OracleDateTime(OciDateTimeDescriptor dateTimeDescriptor, MetaType metaType, OracleConnection connection)
		{
			_value = GetBytesFromDescriptor(dateTimeDescriptor, metaType, connection);
		}

		private static void Pack(byte[] dateval, int year, int month, int day, int hour, int minute, int second, int fsecs)
		{
			dateval[0] = (byte)(year / 100 + 100);
			dateval[1] = (byte)(year % 100 + 100);
			dateval[2] = (byte)month;
			dateval[3] = (byte)day;
			dateval[4] = (byte)(hour + 1);
			dateval[5] = (byte)(minute + 1);
			dateval[6] = (byte)(second + 1);
			dateval[7] = (byte)(fsecs >> 24);
			dateval[8] = (byte)((uint)(fsecs >> 16) & 0xFFu);
			dateval[9] = (byte)((uint)(fsecs >> 8) & 0xFFu);
			dateval[10] = (byte)((uint)fsecs & 0xFFu);
		}

		private static int Unpack(byte[] dateval, out int year, out int month, out int day, out int hour, out int minute, out int second, out int fsec)
		{
			year = (dateval[0] - 100) * 100 + (dateval[1] - 100);
			month = dateval[2];
			day = dateval[3];
			hour = dateval[4] - 1;
			minute = dateval[5] - 1;
			second = dateval[6] - 1;
			int hours;
			int minutes;
			if (7 == dateval.Length)
			{
				hours = (fsec = (minutes = 0));
			}
			else
			{
				fsec = (dateval[7] << 24) | (dateval[8] << 16) | (dateval[9] << 8) | dateval[10];
				if (11 == dateval.Length)
				{
					hours = (minutes = 0);
				}
				else
				{
					hours = dateval[11] - 20;
					minutes = dateval[12] - 60;
				}
			}
			if (13 == dateval.Length)
			{
				DateTime dateTime = new DateTime(year, month, day, hour, minute, second) + new TimeSpan(hours, minutes, 0);
				year = dateTime.Year;
				month = dateTime.Month;
				day = dateTime.Day;
				hour = dateTime.Hour;
				minute = dateTime.Minute;
			}
			return dateval.Length;
		}

		public int CompareTo(object obj)
		{
			if (obj.GetType() == typeof(OracleDateTime))
			{
				OracleDateTime oracleDateTime = (OracleDateTime)obj;
				if (IsNull)
				{
					if (!oracleDateTime.IsNull)
					{
						return -1;
					}
					return 0;
				}
				if (oracleDateTime.IsNull)
				{
					return 1;
				}
				Unpack(_value, out var year, out var month, out var day, out var hour, out var minute, out var second, out var fsec);
				Unpack(oracleDateTime._value, out var year2, out var month2, out var day2, out var hour2, out var minute2, out var second2, out var fsec2);
				int num = year - year2;
				if (num != 0)
				{
					return num;
				}
				num = month - month2;
				if (num != 0)
				{
					return num;
				}
				num = day - day2;
				if (num != 0)
				{
					return num;
				}
				num = hour - hour2;
				if (num != 0)
				{
					return num;
				}
				num = minute - minute2;
				if (num != 0)
				{
					return num;
				}
				num = second - second2;
				if (num != 0)
				{
					return num;
				}
				num = fsec - fsec2;
				if (num != 0)
				{
					return num;
				}
				return 0;
			}
			throw System.Data.Common.ADP.WrongType(obj.GetType(), typeof(OracleDateTime));
		}

		public override bool Equals(object value)
		{
			if (value is OracleDateTime)
			{
				return (this == (OracleDateTime)value).Value;
			}
			return false;
		}

		internal static byte[] GetBytesFromDescriptor(OciDateTimeDescriptor dateTimeDescriptor, MetaType metaType, OracleConnection connection)
		{
			OCI.DATATYPE ociType = metaType.OciType;
			uint num = ociType switch
			{
				OCI.DATATYPE.INT_TIMESTAMP => 11u, 
				OCI.DATATYPE.INT_TIMESTAMP_LTZ => 13u, 
				_ => 13u, 
			};
			byte[] array = new byte[num];
			uint len = num;
			OciIntervalDescriptor reftz = new OciIntervalDescriptor(connection.EnvironmentHandle);
			int num2 = System.Data.Common.UnsafeNativeMethods.OCIDateTimeToArray(connection.EnvironmentHandle, connection.ErrorHandle, dateTimeDescriptor, reftz, array, ref len, 9);
			if (num2 != 0)
			{
				connection.CheckError(connection.ErrorHandle, num2);
			}
			if (OCI.DATATYPE.INT_TIMESTAMP_LTZ == ociType)
			{
				TimeSpan serverTimeZoneAdjustmentToUTC = connection.ServerTimeZoneAdjustmentToUTC;
				array[11] = (byte)(serverTimeZoneAdjustmentToUTC.Hours + 20);
				array[12] = (byte)(serverTimeZoneAdjustmentToUTC.Minutes + 60);
			}
			else if (OCI.DATATYPE.INT_TIMESTAMP_TZ == ociType)
			{
				num2 = System.Data.Common.UnsafeNativeMethods.OCIDateTimeGetTimeZoneOffset(connection.EnvironmentHandle, connection.ErrorHandle, dateTimeDescriptor, out var hour, out var min);
				if (num2 != 0)
				{
					connection.CheckError(connection.ErrorHandle, num2);
				}
				array[11] = (byte)(hour + 20);
				array[12] = (byte)(min + 60);
			}
			return array;
		}

		internal static byte[] GetBytesFromBuffer(NativeBuffer buffer, int valueOffset, int lengthOffset, MetaType metaType, OracleConnection connection)
		{
			OCI.DATATYPE ociType = metaType.OciType;
			short length = buffer.ReadInt16(lengthOffset);
			uint num = ociType switch
			{
				OCI.DATATYPE.DATE => 7u, 
				OCI.DATATYPE.INT_TIMESTAMP => 11u, 
				OCI.DATATYPE.INT_TIMESTAMP_LTZ => 13u, 
				_ => 13u, 
			};
			byte[] array = new byte[num];
			buffer.ReadBytes(valueOffset, array, 0, length);
			if (OCI.DATATYPE.INT_TIMESTAMP_LTZ == ociType)
			{
				TimeSpan serverTimeZoneAdjustmentToUTC = connection.ServerTimeZoneAdjustmentToUTC;
				array[11] = (byte)(serverTimeZoneAdjustmentToUTC.Hours + 20);
				array[12] = (byte)(serverTimeZoneAdjustmentToUTC.Minutes + 60);
			}
			else if (OCI.DATATYPE.INT_TIMESTAMP_TZ == ociType && 128 < array[11])
			{
				OciIntervalDescriptor reftz = new OciIntervalDescriptor(connection.EnvironmentHandle);
				OciDateTimeDescriptor datetime = new OciDateTimeDescriptor(connection.EnvironmentHandle, OCI.HTYPE.OCI_DTYPE_TIMESTAMP_TZ);
				int num2 = System.Data.Common.UnsafeNativeMethods.OCIDateTimeFromArray(connection.EnvironmentHandle, connection.ErrorHandle, array, num, 188, datetime, reftz, 0);
				if (num2 != 0)
				{
					connection.CheckError(connection.ErrorHandle, num2);
				}
				num2 = System.Data.Common.UnsafeNativeMethods.OCIDateTimeGetTimeZoneOffset(connection.EnvironmentHandle, connection.ErrorHandle, datetime, out var hour, out var min);
				if (num2 != 0)
				{
					connection.CheckError(connection.ErrorHandle, num2);
				}
				array[11] = (byte)(hour + 20);
				array[12] = (byte)(min + 60);
			}
			return array;
		}

		public override int GetHashCode()
		{
			return (!IsNull) ? _value.GetHashCode() : 0;
		}

		internal static DateTime MarshalToDateTime(NativeBuffer buffer, int valueOffset, int lengthOffset, MetaType metaType, OracleConnection connection)
		{
			byte[] bytesFromBuffer = GetBytesFromBuffer(buffer, valueOffset, lengthOffset, metaType, connection);
			return ToDateTime(bytesFromBuffer);
		}

		internal static int MarshalDateToNative(object value, NativeBuffer buffer, int offset, OCI.DATATYPE ociType, OracleConnection connection)
		{
			byte[] array;
			if (value is OracleDateTime)
			{
				array = ((OracleDateTime)value)._value;
			}
			else
			{
				DateTime dateTime = (DateTime)value;
				array = new byte[11];
				Pack(array, dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, dateTime.Minute, dateTime.Second, 0);
			}
			int num = 7;
			buffer.WriteBytes(offset, array, 0, num);
			return num;
		}

		internal static DateTime MarshalTimestampToDateTime(OciDateTimeDescriptor dateTimeDescriptor, MetaType metaType, OracleConnection connection)
		{
			byte[] bytesFromDescriptor = GetBytesFromDescriptor(dateTimeDescriptor, metaType, connection);
			return ToDateTime(bytesFromDescriptor);
		}

		internal static OciDateTimeDescriptor CreateEmptyDescriptor(OCI.DATATYPE ociType, OracleConnection connection)
		{
			return new OciDateTimeDescriptor(connection.EnvironmentHandle, ociType switch
			{
				OCI.DATATYPE.INT_TIMESTAMP => OCI.HTYPE.OCI_DTYPE_TIMESTAMP, 
				OCI.DATATYPE.INT_TIMESTAMP_TZ => OCI.HTYPE.OCI_DTYPE_TIMESTAMP_TZ, 
				_ => OCI.HTYPE.OCI_DTYPE_TIMESTAMP_LTZ, 
			});
		}

		internal static OciDateTimeDescriptor CreateDescriptor(OCI.DATATYPE ociType, OracleConnection connection, object value)
		{
			byte[] array;
			if (value is OracleDateTime)
			{
				array = ((OracleDateTime)value)._value;
			}
			else
			{
				DateTime dt = (DateTime)value;
				array = new OracleDateTime(dt)._value;
			}
			OCI.DATATYPE dATATYPE;
			switch (ociType)
			{
			case OCI.DATATYPE.INT_TIMESTAMP:
				dATATYPE = OCI.DATATYPE.TIMESTAMP;
				break;
			case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
				dATATYPE = OCI.DATATYPE.TIMESTAMP_LTZ;
				break;
			default:
			{
				dATATYPE = OCI.DATATYPE.TIMESTAMP_TZ;
				TimeSpan serverTimeZoneAdjustmentToUTC = connection.ServerTimeZoneAdjustmentToUTC;
				if (array.Length < 13)
				{
					byte[] array2 = new byte[13];
					Buffer.BlockCopy(array, 0, array2, 0, array.Length);
					array = array2;
					array[11] = (byte)(20 + serverTimeZoneAdjustmentToUTC.Hours);
					array[12] = (byte)(60 + serverTimeZoneAdjustmentToUTC.Minutes);
				}
				break;
			}
			}
			OciDateTimeDescriptor ociDateTimeDescriptor = CreateEmptyDescriptor(ociType, connection);
			OciIntervalDescriptor reftz = new OciIntervalDescriptor(connection.EnvironmentHandle);
			int num = System.Data.Common.UnsafeNativeMethods.OCIDateTimeFromArray(connection.EnvironmentHandle, connection.ErrorHandle, array, (uint)array.Length, (byte)dATATYPE, ociDateTimeDescriptor, reftz, 9);
			if (num != 0)
			{
				connection.CheckError(connection.ErrorHandle, num);
			}
			return ociDateTimeDescriptor;
		}

		public static OracleDateTime Parse(string s)
		{
			DateTime dt = DateTime.Parse(s, null);
			return new OracleDateTime(dt);
		}

		private static DateTime ToDateTime(byte[] rawValue)
		{
			int year;
			int month;
			int day;
			int hour;
			int minute;
			int second;
			int fsec;
			int num = Unpack(rawValue, out year, out month, out day, out hour, out minute, out second, out fsec);
			DateTime result = new DateTime(year, month, day, hour, minute, second);
			if (num > 7 && fsec > 100)
			{
				return result.AddTicks((long)fsec / 100L);
			}
			return result;
		}

		public override string ToString()
		{
			if (IsNull)
			{
				return System.Data.Common.ADP.NullString;
			}
			return Value.ToString((IFormatProvider)null);
		}

		public static OracleBoolean Equals(OracleDateTime x, OracleDateTime y)
		{
			return x == y;
		}

		public static OracleBoolean GreaterThan(OracleDateTime x, OracleDateTime y)
		{
			return x > y;
		}

		public static OracleBoolean GreaterThanOrEqual(OracleDateTime x, OracleDateTime y)
		{
			return x >= y;
		}

		public static OracleBoolean LessThan(OracleDateTime x, OracleDateTime y)
		{
			return x < y;
		}

		public static OracleBoolean LessThanOrEqual(OracleDateTime x, OracleDateTime y)
		{
			return x <= y;
		}

		public static OracleBoolean NotEquals(OracleDateTime x, OracleDateTime y)
		{
			return x != y;
		}

		public static explicit operator DateTime(OracleDateTime x)
		{
			if (x.IsNull)
			{
				throw System.Data.Common.ADP.DataIsNull();
			}
			return x.Value;
		}

		public static explicit operator OracleDateTime(string x)
		{
			return Parse(x);
		}

		public static OracleBoolean operator ==(OracleDateTime x, OracleDateTime y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) == 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >(OracleDateTime x, OracleDateTime y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) > 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >=(OracleDateTime x, OracleDateTime y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) >= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <(OracleDateTime x, OracleDateTime y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) < 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <=(OracleDateTime x, OracleDateTime y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) <= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator !=(OracleDateTime x, OracleDateTime y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) != 0);
			}
			return OracleBoolean.Null;
		}
	}
	internal sealed class OracleEncoding : Encoding
	{
		private OracleInternalConnection _connection;

		internal OciHandle Handle
		{
			get
			{
				OciHandle ociHandle = _connection.SessionHandle;
				if (ociHandle == null || ociHandle.IsInvalid)
				{
					ociHandle = _connection.EnvironmentHandle;
				}
				return ociHandle;
			}
		}

		public OracleEncoding(OracleInternalConnection connection)
		{
			_connection = connection;
		}

		public override int GetByteCount(char[] chars, int index, int count)
		{
			return GetBytes(chars, index, count, null, 0);
		}

		public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
		{
			OciHandle handle = Handle;
			checked
			{
				return (int)handle.GetBytes(chars, charIndex, unchecked((uint)charCount), bytes, byteIndex);
			}
		}

		public override int GetCharCount(byte[] bytes, int index, int count)
		{
			return GetChars(bytes, index, count, null, 0);
		}

		public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
		{
			OciHandle handle = Handle;
			checked
			{
				return (int)handle.GetChars(bytes, byteIndex, unchecked((uint)byteCount), chars, charIndex);
			}
		}

		public override int GetMaxByteCount(int charCount)
		{
			return checked(charCount * 4);
		}

		public override int GetMaxCharCount(int byteCount)
		{
			return byteCount;
		}
	}
	[Serializable]
	public sealed class OracleException : DbException
	{
		private int _code;

		public int Code => _code;

		private OracleException(SerializationInfo si, StreamingContext sc)
			: base(si, sc)
		{
			_code = (int)si.GetValue("code", typeof(int));
			base.HResult = -2146232008;
		}

		private OracleException(string message, int code)
			: base(message)
		{
			_code = code;
			base.HResult = -2146232008;
		}

		private static bool ConnectionIsBroken(int code)
		{
			if (12500 <= code && code <= 12699)
			{
				return true;
			}
			switch (code)
			{
			case 18:
			case 19:
			case 24:
			case 28:
			case 436:
			case 1012:
			case 1033:
			case 1034:
			case 1075:
			case 2392:
			case 2399:
			case 3113:
			case 3114:
				return true;
			default:
				return false;
			}
		}

		internal static OracleException CreateException(OciErrorHandle errorHandle, int rc)
		{
			using NativeBuffer nativeBuffer = new NativeBuffer_Exception(1000);
			int errcodep;
			string text;
			if (errorHandle != null)
			{
				int recordno = 1;
				int num = TracedNativeMethods.OCIErrorGet(errorHandle, recordno, out errcodep, nativeBuffer);
				if (num == 0)
				{
					text = errorHandle.PtrToString(nativeBuffer);
					if (errcodep != 0 && text.StartsWith("ORA-00000", StringComparison.Ordinal) && TracedNativeMethods.oermsg((short)errcodep, nativeBuffer) == 0)
					{
						text = errorHandle.PtrToString(nativeBuffer);
					}
				}
				else
				{
					text = Res.GetString("ADP_NoMessageAvailable", rc, num);
					errcodep = 0;
				}
				if (ConnectionIsBroken(errcodep))
				{
					errorHandle.ConnectionIsBroken = true;
				}
			}
			else
			{
				text = Res.GetString("ADP_NoMessageAvailable", rc, -1);
				errcodep = 0;
			}
			return new OracleException(text, errcodep);
		}

		internal static OracleException CreateException(int rc, OracleInternalConnection internalConnection)
		{
			using NativeBuffer nativeBuffer = new NativeBuffer_Exception(1000);
			int lpdLen = nativeBuffer.Length;
			int dwErr = 0;
			int num = TracedNativeMethods.OraMTSOCIErrGet(ref dwErr, nativeBuffer, ref lpdLen);
			string message;
			if (1 == num)
			{
				message = nativeBuffer.PtrToStringAnsi(0, lpdLen);
			}
			else
			{
				message = Res.GetString("ADP_NoMessageAvailable", rc, num);
				dwErr = 0;
			}
			if (ConnectionIsBroken(dwErr))
			{
				internalConnection.DoomThisConnection();
			}
			return new OracleException(message, dwErr);
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static void Check(OciErrorHandle errorHandle, int rc)
		{
			switch (rc)
			{
			case -1:
			case 100:
				throw System.Data.Common.ADP.OracleError(errorHandle, rc);
			case -2:
				throw System.Data.Common.ADP.InvalidOperation(Res.GetString("ADP_InternalError", rc));
			}
			if (rc < 0 || rc == 99 || rc == 1)
			{
				throw System.Data.Common.ADP.Simple(Res.GetString("ADP_UnexpectedReturnCode", rc.ToString(CultureInfo.CurrentCulture)));
			}
		}

		internal static void Check(int rc, OracleInternalConnection internalConnection)
		{
			if (rc != 0)
			{
				throw System.Data.Common.ADP.OracleError(rc, internalConnection);
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
		public override void GetObjectData(SerializationInfo si, StreamingContext context)
		{
			if (si == null)
			{
				throw new ArgumentNullException("si");
			}
			si.AddValue("code", _code, typeof(int));
			base.GetObjectData(si, context);
		}
	}
	public sealed class OracleClientFactory : DbProviderFactory
	{
		public static readonly OracleClientFactory Instance = new OracleClientFactory();

		private OracleClientFactory()
		{
		}

		public override DbCommand CreateCommand()
		{
			return new OracleCommand();
		}

		public override DbCommandBuilder CreateCommandBuilder()
		{
			return new OracleCommandBuilder();
		}

		public override DbConnection CreateConnection()
		{
			return new OracleConnection();
		}

		public override DbConnectionStringBuilder CreateConnectionStringBuilder()
		{
			return new OracleConnectionStringBuilder();
		}

		public override DbDataAdapter CreateDataAdapter()
		{
			return new OracleDataAdapter();
		}

		public override DbParameter CreateParameter()
		{
			return new OracleParameter();
		}

		public override CodeAccessPermission CreatePermission(PermissionState state)
		{
			return new OraclePermission(state);
		}
	}
	public sealed class OracleInfoMessageEventArgs : EventArgs
	{
		private OracleException exception;

		public int Code => exception.Code;

		public string Message => exception.Message;

		public string Source => exception.Source;

		internal OracleInfoMessageEventArgs(OracleException exception)
		{
			this.exception = exception;
		}

		public override string ToString()
		{
			return Message;
		}
	}
	public delegate void OracleInfoMessageEventHandler(object sender, OracleInfoMessageEventArgs e);
}
namespace System.Data.ProviderBase
{
	internal abstract class DbConnectionInternal
	{
		private static int _objectTypeCount;

		internal readonly int _objectID = Interlocked.Increment(ref _objectTypeCount);

		internal static readonly StateChangeEventArgs StateChangeClosed = new StateChangeEventArgs(ConnectionState.Open, ConnectionState.Closed);

		internal static readonly StateChangeEventArgs StateChangeOpen = new StateChangeEventArgs(ConnectionState.Closed, ConnectionState.Open);

		private readonly bool _allowSetConnectionString;

		private readonly bool _hidePassword;

		private readonly ConnectionState _state;

		private readonly WeakReference _owningObject = new WeakReference(null, trackResurrection: false);

		private DbConnectionInternal _nextPooledObject;

		private DbConnectionPool _connectionPool;

		private DbConnectionPoolCounters _performanceCounters;

		private DbReferenceCollection _referenceCollection;

		private int _pooledCount;

		private bool _connectionIsDoomed;

		private bool _cannotBePooled;

		private bool _isInStasis;

		private DateTime _createTime;

		private Transaction _enlistedTransaction;

		internal DbConnectionInternal NextPooledObject
		{
			get
			{
				return _nextPooledObject;
			}
			set
			{
				_nextPooledObject = value;
			}
		}

		internal bool AllowSetConnectionString => _allowSetConnectionString;

		internal bool CanBePooled => !_connectionIsDoomed && !_cannotBePooled && !_owningObject.IsAlive;

		protected internal Transaction EnlistedTransaction
		{
			get
			{
				return _enlistedTransaction;
			}
			set
			{
				if ((!(null == _enlistedTransaction) || !(null != value)) && (!(null != _enlistedTransaction) || _enlistedTransaction.Equals(value)))
				{
					return;
				}
				Transaction transaction = null;
				Transaction transaction2 = null;
				try
				{
					if (null != value)
					{
						transaction = value.Clone();
					}
					lock (this)
					{
						transaction2 = _enlistedTransaction;
						_enlistedTransaction = transaction;
						value = transaction;
						transaction = null;
					}
				}
				finally
				{
					if (null != transaction2)
					{
						transaction2.Dispose();
					}
					if (null != transaction)
					{
						transaction.Dispose();
					}
				}
				if (null != value)
				{
					if (Bid.IsOn((Bid.ApiGroup)4096u))
					{
						int hashCode = value.GetHashCode();
						Bid.PoolerTrace("<prov.DbConnectionInternal.set_EnlistedTransaction|RES|CPOOL> %d#, Transaction %d#, Enlisting.\n", ObjectID, hashCode);
					}
					TransactionOutcomeEnlist(value);
				}
			}
		}

		internal bool IsTxRootWaitingForTxEnd => _isInStasis;

		internal virtual bool RequireExplicitTransactionUnbind => false;

		protected internal virtual bool IsNonPoolableTransactionRoot => false;

		internal virtual bool IsTransactionRoot => false;

		public bool HasEnlistedTransaction => null != EnlistedTransaction;

		protected internal bool IsConnectionDoomed => _connectionIsDoomed;

		internal bool IsEmancipated => !IsTxRootWaitingForTxEnd && _pooledCount < 1 && !_owningObject.IsAlive;

		internal int ObjectID => _objectID;

		protected internal object Owner => _owningObject.Target;

		internal DbConnectionPool Pool => _connectionPool;

		protected DbConnectionPoolCounters PerformanceCounters => _performanceCounters;

		protected virtual bool ReadyToPrepareTransaction => true;

		protected internal DbReferenceCollection ReferenceCollection => _referenceCollection;

		public abstract string ServerVersion { get; }

		public virtual string ServerVersionNormalized
		{
			get
			{
				throw System.Data.Common.ADP.NotSupported();
			}
		}

		public bool ShouldHidePassword => _hidePassword;

		public ConnectionState State => _state;

		protected DbConnectionInternal()
			: this(ConnectionState.Open, hidePassword: true, allowSetConnectionString: false)
		{
		}

		internal DbConnectionInternal(ConnectionState state, bool hidePassword, bool allowSetConnectionString)
		{
			_allowSetConnectionString = allowSetConnectionString;
			_hidePassword = hidePassword;
			_state = state;
		}

		protected abstract void Activate(Transaction transaction);

		internal void ActivateConnection(Transaction transaction)
		{
			Bid.PoolerTrace("<prov.DbConnectionInternal.ActivateConnection|RES|INFO|CPOOL> %d#, Activating\n", ObjectID);
			Activate(transaction);
			PerformanceCounters.NumberOfActiveConnections.Increment();
		}

		internal void AddWeakReference(object value, int tag)
		{
			if (_referenceCollection == null)
			{
				_referenceCollection = CreateReferenceCollection();
				if (_referenceCollection == null)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.CreateReferenceCollectionReturnedNull);
				}
			}
			_referenceCollection.Add(value, tag);
		}

		public abstract DbTransaction BeginTransaction(IsolationLevel il);

		public virtual void ChangeDatabase(string value)
		{
			throw System.Data.Common.ADP.MethodNotImplemented("ChangeDatabase");
		}

		internal virtual void CloseConnection(DbConnection owningObject, DbConnectionFactory connectionFactory)
		{
			Bid.PoolerTrace("<prov.DbConnectionInternal.CloseConnection|RES|CPOOL> %d# Closing.\n", ObjectID);
			if (!connectionFactory.SetInnerConnectionFrom(owningObject, DbConnectionOpenBusy.SingletonInstance, this))
			{
				return;
			}
			try
			{
				DbConnectionPool pool = Pool;
				Transaction enlistedTransaction = EnlistedTransaction;
				if (null != enlistedTransaction && enlistedTransaction.TransactionInformation.Status != 0)
				{
					DetachTransaction(enlistedTransaction);
				}
				if (pool != null)
				{
					pool.PutObject(this, owningObject);
					return;
				}
				Deactivate();
				PerformanceCounters.HardDisconnectsPerSecond.Increment();
				_owningObject.Target = null;
				if (IsTransactionRoot)
				{
					SetInStasis();
					return;
				}
				PerformanceCounters.NumberOfNonPooledConnections.Decrement();
				Dispose();
			}
			finally
			{
				connectionFactory.SetInnerConnectionEvent(owningObject, DbConnectionClosedPreviouslyOpened.SingletonInstance);
			}
		}

		protected virtual DbReferenceCollection CreateReferenceCollection()
		{
			throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.AttemptingToConstructReferenceCollectionOnStaticObject);
		}

		protected abstract void Deactivate();

		internal void DeactivateConnection()
		{
			Bid.PoolerTrace("<prov.DbConnectionInternal.DeactivateConnection|RES|INFO|CPOOL> %d#, Deactivating\n", ObjectID);
			PerformanceCounters.NumberOfActiveConnections.Decrement();
			if (!_connectionIsDoomed && Pool.UseLoadBalancing && DateTime.UtcNow.Ticks - _createTime.Ticks > Pool.LoadBalanceTimeout.Ticks)
			{
				DoNotPoolThisConnection();
			}
			Deactivate();
		}

		internal virtual void DelegatedTransactionEnded()
		{
			Bid.Trace("<prov.DbConnectionInternal.DelegatedTransactionEnded|RES|CPOOL> %d#, Delegated Transaction Completed.\n", ObjectID);
			if (1 == _pooledCount)
			{
				TerminateStasis(returningToPool: true);
				Deactivate();
				DbConnectionPool pool = Pool;
				if (pool == null)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.PooledObjectWithoutPool);
				}
				pool.PutObjectFromTransactedPool(this);
			}
			else if (-1 == _pooledCount && !_owningObject.IsAlive)
			{
				TerminateStasis(returningToPool: false);
				Deactivate();
				PerformanceCounters.NumberOfNonPooledConnections.Decrement();
				Dispose();
			}
		}

		public virtual void Dispose()
		{
			_connectionPool = null;
			_performanceCounters = null;
			_connectionIsDoomed = true;
			_enlistedTransaction = null;
		}

		protected internal void DoNotPoolThisConnection()
		{
			_cannotBePooled = true;
			Bid.PoolerTrace("<prov.DbConnectionInternal.DoNotPoolThisConnection|RES|INFO|CPOOL> %d#, Marking pooled object as non-poolable so it will be disposed\n", ObjectID);
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		protected internal void DoomThisConnection()
		{
			_connectionIsDoomed = true;
			Bid.PoolerTrace("<prov.DbConnectionInternal.DoomThisConnection|RES|INFO|CPOOL> %d#, Dooming\n", ObjectID);
		}

		public abstract void EnlistTransaction(Transaction transaction);

		protected internal virtual DataTable GetSchema(DbConnectionFactory factory, DbConnectionPoolGroup poolGroup, DbConnection outerConnection, string collectionName, string[] restrictions)
		{
			DbMetaDataFactory metaDataFactory = factory.GetMetaDataFactory(poolGroup, this);
			return metaDataFactory.GetSchema(outerConnection, collectionName, restrictions);
		}

		internal void MakeNonPooledObject(object owningObject, DbConnectionPoolCounters performanceCounters)
		{
			_connectionPool = null;
			_performanceCounters = performanceCounters;
			_owningObject.Target = owningObject;
			_pooledCount = -1;
		}

		internal void MakePooledConnection(DbConnectionPool connectionPool)
		{
			_createTime = DateTime.UtcNow;
			_connectionPool = connectionPool;
			_performanceCounters = connectionPool.PerformanceCounters;
		}

		internal void NotifyWeakReference(int message)
		{
			ReferenceCollection?.Notify(message);
		}

		internal virtual void OpenConnection(DbConnection outerConnection, DbConnectionFactory connectionFactory)
		{
			throw System.Data.Common.ADP.ConnectionAlreadyOpen(State);
		}

		internal void PrePush(object expectedOwner)
		{
			if (expectedOwner == null)
			{
				if (_owningObject.Target != null)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.UnpooledObjectHasOwner);
				}
			}
			else if (_owningObject.Target != expectedOwner)
			{
				throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.UnpooledObjectHasWrongOwner);
			}
			if (_pooledCount != 0)
			{
				throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.PushingObjectSecondTime);
			}
			if (Bid.IsOn((Bid.ApiGroup)4096u))
			{
				Bid.PoolerTrace("<prov.DbConnectionInternal.PrePush|RES|CPOOL> %d#, Preparing to push into pool, owning connection %d#, pooledCount=%d\n", ObjectID, 0, _pooledCount);
			}
			_pooledCount++;
			_owningObject.Target = null;
		}

		internal void PostPop(object newOwner)
		{
			if (_owningObject.Target != null)
			{
				throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.PooledObjectHasOwner);
			}
			_owningObject.Target = newOwner;
			_pooledCount--;
			if (Bid.IsOn((Bid.ApiGroup)4096u))
			{
				Bid.PoolerTrace("<prov.DbConnectionInternal.PostPop|RES|CPOOL> %d#, Preparing to pop from pool,  owning connection %d#, pooledCount=%d\n", ObjectID, 0, _pooledCount);
			}
			if (Pool != null)
			{
				if (_pooledCount != 0)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.PooledObjectInPoolMoreThanOnce);
				}
			}
			else if (-1 != _pooledCount)
			{
				throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.NonPooledObjectUsedMoreThanOnce);
			}
		}

		internal void RemoveWeakReference(object value)
		{
			ReferenceCollection?.Remove(value);
		}

		protected virtual void CleanupTransactionOnCompletion(Transaction transaction)
		{
		}

		internal void DetachTransaction(Transaction transaction)
		{
			Bid.Trace("<prov.DbConnectionInternal.DetachTransaction|RES|CPOOL> %d#, Transaction Completed. (pooledCount=%d)\n", ObjectID, _pooledCount);
			lock (this)
			{
				DbConnection dbConnection = (DbConnection)Owner;
				if ((!RequireExplicitTransactionUnbind || dbConnection == null) && _enlistedTransaction != null && transaction.Equals(_enlistedTransaction))
				{
					EnlistedTransaction = null;
					if (IsTxRootWaitingForTxEnd)
					{
						DelegatedTransactionEnded();
					}
				}
			}
		}

		internal void CleanupConnectionOnTransactionCompletion(Transaction transaction)
		{
			DetachTransaction(transaction);
			Pool?.TransactionEnded(transaction, this);
		}

		private void TransactionCompletedEvent(object sender, TransactionEventArgs e)
		{
			Transaction transaction = e.Transaction;
			Bid.Trace("<prov.DbConnectionInternal.TransactionCompletedEvent|RES|CPOOL> %d#, Transaction Completed. (pooledCount=%d)\n", ObjectID, _pooledCount);
			CleanupTransactionOnCompletion(transaction);
			CleanupConnectionOnTransactionCompletion(transaction);
		}

		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		private void TransactionOutcomeEnlist(Transaction transaction)
		{
			transaction.TransactionCompleted += TransactionCompletedEvent;
		}

		internal void SetInStasis()
		{
			_isInStasis = true;
			Bid.PoolerTrace("<prov.DbConnectionInternal.SetInStasis|RES|CPOOL> %d#, Non-Pooled Connection has Delegated Transaction, waiting to Dispose.\n", ObjectID);
			PerformanceCounters.NumberOfStasisConnections.Increment();
		}

		private void TerminateStasis(bool returningToPool)
		{
			if (returningToPool)
			{
				Bid.PoolerTrace("<prov.DbConnectionInternal.TerminateStasis|RES|CPOOL> %d#, Delegated Transaction has ended, connection is closed.  Returning to general pool.\n", ObjectID);
			}
			else
			{
				Bid.PoolerTrace("<prov.DbConnectionInternal.TerminateStasis|RES|CPOOL> %d#, Delegated Transaction has ended, connection is closed/leaked.  Disposing.\n", ObjectID);
			}
			PerformanceCounters.NumberOfStasisConnections.Decrement();
			_isInStasis = false;
		}
	}
}
namespace System.Data.OracleClient
{
	internal sealed class OracleInternalConnection : System.Data.ProviderBase.DbConnectionInternal
	{
		internal enum PARSERSTATE
		{
			NOTHINGYET = 1,
			PERIOD,
			DIGIT
		}

		private OracleConnectionString _connectionOptions;

		private OciEnvironmentHandle _environmentHandle;

		private OciErrorHandle _errorHandle;

		private OciServerHandle _serverHandle;

		private OciServiceContextHandle _serviceContextHandle;

		private OciSessionHandle _sessionHandle;

		private OciEnlistContext _enlistContext;

		private bool _connectionIsOpen;

		private WeakReference _transaction;

		private TransactionState _transactionState;

		private List<OracleInfoMessageEventArgs> _deferredInfoMessageCollection;

		private long _serverVersion;

		private string _serverVersionString;

		private string _serverVersionStringNormalized;

		private TimeSpan _serverTimeZoneAdjustment = TimeSpan.MinValue;

		private NativeBuffer _scratchBuffer;

		private Encoding _encodingDatabase;

		private Encoding _encodingNational;

		internal OciEnvironmentHandle EnvironmentHandle => _environmentHandle;

		internal OciErrorHandle ErrorHandle => _errorHandle;

		internal bool HasTransaction
		{
			get
			{
				TransactionState transactionState = TransactionState;
				return TransactionState.LocalStarted == transactionState || TransactionState.GlobalStarted == transactionState;
			}
		}

		public override string ServerVersion
		{
			get
			{
				if (_serverVersionString == null)
				{
					string text = "no version available";
					NativeBuffer nativeBuffer = null;
					try
					{
						nativeBuffer = new NativeBuffer_ServerVersion(500);
						int num = TracedNativeMethods.OCIServerVersion(ServiceContextHandle, ErrorHandle, nativeBuffer);
						if (num != 0)
						{
							throw System.Data.Common.ADP.OracleError(ErrorHandle, num);
						}
						if (num == 0)
						{
							text = ServiceContextHandle.PtrToString(nativeBuffer);
						}
						_serverVersion = ParseServerVersion(text);
						_serverVersionString = string.Format(null, "{0}.{1}.{2}.{3}.{4} {5}", (_serverVersion >> 32) & 0xFF, (_serverVersion >> 24) & 0xFF, (_serverVersion >> 16) & 0xFF, (_serverVersion >> 8) & 0xFF, _serverVersion & 0xFF, text);
						_serverVersionStringNormalized = string.Format(null, "{0:00}.{1:00}.{2:00}.{3:00}.{4:00} ", (_serverVersion >> 32) & 0xFF, (_serverVersion >> 24) & 0xFF, (_serverVersion >> 16) & 0xFF, (_serverVersion >> 8) & 0xFF, _serverVersion & 0xFF);
					}
					finally
					{
						if (nativeBuffer != null)
						{
							nativeBuffer.Dispose();
							nativeBuffer = null;
						}
					}
				}
				return _serverVersionString;
			}
		}

		public override string ServerVersionNormalized
		{
			get
			{
				if (_serverVersionStringNormalized == null)
				{
					_ = ServerVersion;
				}
				return _serverVersionStringNormalized;
			}
		}

		internal bool ServerVersionAtLeastOracle8 => ServerVersionNumber >= 34359738368L;

		internal bool ServerVersionAtLeastOracle8i => ServerVersionNumber >= 34376515584L;

		internal bool ServerVersionAtLeastOracle9i => ServerVersionNumber >= 38654705664L;

		internal long ServerVersionNumber
		{
			get
			{
				if (0 == _serverVersion)
				{
					_ = ServerVersion;
				}
				return _serverVersion;
			}
		}

		internal OciServiceContextHandle ServiceContextHandle => _serviceContextHandle;

		internal OciSessionHandle SessionHandle => _sessionHandle;

		internal OracleTransaction Transaction
		{
			get
			{
				if (_transaction != null && _transaction.IsAlive)
				{
					if (((OracleTransaction)_transaction.Target).Connection != null)
					{
						return (OracleTransaction)_transaction.Target;
					}
					_transaction.Target = null;
				}
				return null;
			}
			set
			{
				if (value == null)
				{
					_transaction = null;
				}
				else if (_transaction != null)
				{
					_transaction.Target = value;
				}
				else
				{
					_transaction = new WeakReference(value);
				}
			}
		}

		internal TransactionState TransactionState
		{
			get
			{
				return _transactionState;
			}
			set
			{
				_transactionState = value;
			}
		}

		internal bool UnicodeEnabled
		{
			get
			{
				if (OCI.ClientVersionAtLeastOracle9i)
				{
					if (EnvironmentHandle != null)
					{
						return EnvironmentHandle.IsUnicode;
					}
					return true;
				}
				return false;
			}
		}

		internal OracleInternalConnection(OracleConnectionString connectionOptions)
		{
			_connectionOptions = connectionOptions;
			string userId = connectionOptions.UserId;
			string password = connectionOptions.Password;
			string dataSource = connectionOptions.DataSource;
			bool integratedSecurity = connectionOptions.IntegratedSecurity;
			bool unicode = connectionOptions.Unicode;
			bool omitOracleConnectionName = _connectionOptions.OmitOracleConnectionName;
			_connectionIsOpen = OpenOnLocalTransaction(userId, password, dataSource, integratedSecurity, unicode, omitOracleConnectionName);
			if (UnicodeEnabled)
			{
				_encodingDatabase = Encoding.Unicode;
			}
			else if (ServerVersionAtLeastOracle8i)
			{
				_encodingDatabase = new OracleEncoding(this);
			}
			else
			{
				_encodingDatabase = Encoding.Default;
			}
			_encodingNational = Encoding.Unicode;
			if (connectionOptions.Enlist && !connectionOptions.Pooling)
			{
				Transaction currentTransaction = System.Data.Common.ADP.GetCurrentTransaction();
				if (null != currentTransaction)
				{
					Enlist(userId, password, dataSource, currentTransaction, manualEnlistment: false);
				}
			}
		}

		protected override void Activate(Transaction transaction)
		{
			bool flag = null != transaction;
			OracleConnectionString connectionOptions = _connectionOptions;
			if (flag && connectionOptions.Enlist)
			{
				if (!transaction.Equals(base.EnlistedTransaction))
				{
					Enlist(connectionOptions.UserId, connectionOptions.Password, connectionOptions.DataSource, transaction, manualEnlistment: false);
				}
			}
			else if (!flag && _enlistContext != null)
			{
				UnEnlist();
			}
		}

		public override DbTransaction BeginTransaction(IsolationLevel il)
		{
			return BeginOracleTransaction(il);
		}

		internal OracleTransaction BeginOracleTransaction(IsolationLevel il)
		{
			OracleConnection.ExecutePermission.Demand();
			if (TransactionState != 0)
			{
				throw System.Data.Common.ADP.NoParallelTransactions();
			}
			RollbackDeadTransaction();
			return Transaction = new OracleTransaction(ProxyConnection(), il);
		}

		private void CreateDeferredInfoMessage(OciErrorHandle errorHandle, int rc)
		{
			OracleException exception = OracleException.CreateException(errorHandle, rc);
			OracleInfoMessageEventArgs item = new OracleInfoMessageEventArgs(exception);
			List<OracleInfoMessageEventArgs> list = _deferredInfoMessageCollection;
			if (list == null)
			{
				list = (_deferredInfoMessageCollection = new List<OracleInfoMessageEventArgs>());
			}
			list.Add(item);
		}

		internal void ConnectionIsBroken()
		{
			DoomThisConnection();
			OracleConnection oracleConnection = (OracleConnection)base.Owner;
			if (oracleConnection != null)
			{
				oracleConnection.Close();
			}
			else
			{
				Dispose();
			}
		}

		internal void Commit()
		{
			int num = TracedNativeMethods.OCITransCommit(ServiceContextHandle, ErrorHandle, OCI.MODE.OCI_DEFAULT);
			if (num != 0)
			{
				OracleException.Check(ErrorHandle, num);
			}
			TransactionState = TransactionState.AutoCommit;
			Transaction = null;
		}

		protected override void Deactivate()
		{
			if (!base.IsConnectionDoomed && ErrorHandle != null && ErrorHandle.ConnectionIsBroken)
			{
				ConnectionIsBroken();
			}
			if (TransactionState.LocalStarted != TransactionState)
			{
				return;
			}
			try
			{
				Rollback();
			}
			catch (Exception e)
			{
				if (!System.Data.Common.ADP.IsCatchableExceptionType(e))
				{
					throw;
				}
				System.Data.Common.ADP.TraceException(e);
				DoomThisConnection();
			}
		}

		public override void Dispose()
		{
			Deactivate();
			OciEnlistContext.SafeDispose(ref _enlistContext);
			OciHandle.SafeDispose(ref _sessionHandle);
			OciHandle.SafeDispose(ref _serviceContextHandle);
			OciHandle.SafeDispose(ref _serverHandle);
			OciHandle.SafeDispose(ref _errorHandle);
			OciHandle.SafeDispose(ref _environmentHandle);
			if (_scratchBuffer != null)
			{
				_scratchBuffer.Dispose();
			}
			_scratchBuffer = null;
			_encodingDatabase = null;
			_encodingNational = null;
			_transaction = null;
			_serverVersionString = null;
			base.Dispose();
		}

		private void Enlist(string userName, string password, string serverName, Transaction transaction, bool manualEnlistment)
		{
			UnEnlist();
			if (!OCI.ClientVersionAtLeastOracle9i)
			{
				throw System.Data.Common.ADP.DistribTxRequiresOracle9i();
			}
			if (null != transaction)
			{
				if (HasTransaction)
				{
					throw System.Data.Common.ADP.TransactionPresent();
				}
				byte[] bytes = Encoding.Default.GetBytes(password);
				byte[] bytes2 = Encoding.Default.GetBytes(userName);
				byte[] bytes3 = Encoding.Default.GetBytes(serverName);
				_enlistContext = new OciEnlistContext(bytes2, bytes, bytes3, ServiceContextHandle, ErrorHandle);
				_enlistContext.Join(this, transaction);
				TransactionState = TransactionState.GlobalStarted;
			}
			else
			{
				TransactionState = TransactionState.AutoCommit;
			}
			base.EnlistedTransaction = transaction;
		}

		public override void EnlistTransaction(Transaction transaction)
		{
			OracleConnectionString connectionOptions = _connectionOptions;
			RollbackDeadTransaction();
			Enlist(connectionOptions.UserId, connectionOptions.Password, connectionOptions.DataSource, transaction, manualEnlistment: true);
		}

		internal void FireDeferredInfoMessageEvents(OracleConnection outerConnection)
		{
			List<OracleInfoMessageEventArgs> deferredInfoMessageCollection = _deferredInfoMessageCollection;
			_deferredInfoMessageCollection = null;
			if (deferredInfoMessageCollection == null)
			{
				return;
			}
			foreach (OracleInfoMessageEventArgs item in deferredInfoMessageCollection)
			{
				if (item != null)
				{
					outerConnection.OnInfoMessage(item);
				}
			}
		}

		internal byte[] GetBytes(string value, bool useNationalCharacterSet)
		{
			if (useNationalCharacterSet)
			{
				return _encodingNational.GetBytes(value);
			}
			return _encodingDatabase.GetBytes(value);
		}

		internal NativeBuffer GetScratchBuffer(int minSize)
		{
			NativeBuffer nativeBuffer = _scratchBuffer;
			if (nativeBuffer == null || nativeBuffer.Length < minSize)
			{
				nativeBuffer?.Dispose();
				nativeBuffer = (_scratchBuffer = new NativeBuffer_ScratchBuffer(minSize));
			}
			return nativeBuffer;
		}

		internal string GetString(byte[] bytearray)
		{
			return _encodingDatabase.GetString(bytearray);
		}

		internal string GetString(byte[] bytearray, bool useNationalCharacterSet)
		{
			if (useNationalCharacterSet)
			{
				return _encodingNational.GetString(bytearray);
			}
			return _encodingDatabase.GetString(bytearray);
		}

		internal TimeSpan GetServerTimeZoneAdjustmentToUTC(OracleConnection connection)
		{
			TimeSpan serverTimeZoneAdjustment = _serverTimeZoneAdjustment;
			if (TimeSpan.MinValue == serverTimeZoneAdjustment)
			{
				if (ServerVersionAtLeastOracle9i)
				{
					OracleCommand oracleCommand = new OracleCommand();
					oracleCommand.Connection = connection;
					oracleCommand.Transaction = Transaction;
					oracleCommand.CommandText = "select tz_offset(dbtimezone) from dual";
					string text = (string)oracleCommand.ExecuteScalar();
					int hours = int.Parse(text.Substring(0, 3), CultureInfo.InvariantCulture);
					int minutes = int.Parse(text.Substring(4, 2), CultureInfo.InvariantCulture);
					serverTimeZoneAdjustment = new TimeSpan(hours, minutes, 0);
				}
				else
				{
					serverTimeZoneAdjustment = TimeSpan.Zero;
				}
				_serverTimeZoneAdjustment = serverTimeZoneAdjustment;
			}
			return _serverTimeZoneAdjustment;
		}

		private bool OpenOnLocalTransaction(string userName, string password, string serverName, bool integratedSecurity, bool unicode, bool omitOracleConnectionName)
		{
			//Discarded unreachable code: IL_01f8
			int rc = 0;
			_ = IntPtr.Zero;
			OCI.MODE mODE = OCI.MODE.OCI_THREADED | OCI.MODE.OCI_OBJECT;
			OCI.DetermineClientVersion();
			if (unicode)
			{
				if (OCI.ClientVersionAtLeastOracle9i)
				{
					mODE |= OCI.MODE.OCI_UTF16;
				}
				else
				{
					unicode = false;
				}
			}
			_environmentHandle = new OciEnvironmentHandle(mODE, unicode);
			if (_environmentHandle.IsInvalid)
			{
				throw System.Data.Common.ADP.CouldNotCreateEnvironment("OCIEnvCreate", rc);
			}
			_errorHandle = new OciErrorHandle(_environmentHandle);
			_serverHandle = new OciServerHandle(_errorHandle);
			_sessionHandle = new OciSessionHandle(_serverHandle);
			_serviceContextHandle = new OciServiceContextHandle(_sessionHandle);
			try
			{
				rc = TracedNativeMethods.OCIServerAttach(_serverHandle, _errorHandle, serverName, serverName.Length, OCI.MODE.OCI_DEFAULT);
				if (rc != 0)
				{
					if (1 == rc)
					{
						CreateDeferredInfoMessage(ErrorHandle, rc);
					}
					else
					{
						OracleException.Check(ErrorHandle, rc);
					}
				}
				_serviceContextHandle.SetAttribute(OCI.ATTR.OCI_ATTR_SERVER, _serverHandle, _errorHandle);
				OCI.CRED credt;
				if (integratedSecurity)
				{
					credt = OCI.CRED.OCI_CRED_EXT;
				}
				else
				{
					credt = OCI.CRED.OCI_CRED_RDBMS;
					_sessionHandle.SetAttribute(OCI.ATTR.OCI_ATTR_USERNAME, userName, _errorHandle);
					if (password != null)
					{
						_sessionHandle.SetAttribute(OCI.ATTR.OCI_ATTR_PASSWORD, password, _errorHandle);
					}
				}
				if (!omitOracleConnectionName)
				{
					string text = _connectionOptions.DataSource;
					if (text.Length > 16)
					{
						text = text.Substring(0, 16);
					}
					_serverHandle.SetAttribute(OCI.ATTR.OCI_ATTR_EXTERNAL_NAME, text, _errorHandle);
					_serverHandle.SetAttribute(OCI.ATTR.OCI_ATTR_INTERNAL_NAME, text, _errorHandle);
				}
				rc = TracedNativeMethods.OCISessionBegin(_serviceContextHandle, _errorHandle, _sessionHandle, credt, OCI.MODE.OCI_DEFAULT);
				if (rc != 0)
				{
					if (1 == rc)
					{
						CreateDeferredInfoMessage(ErrorHandle, rc);
					}
					else
					{
						OracleException.Check(ErrorHandle, rc);
					}
				}
				_serviceContextHandle.SetAttribute(OCI.ATTR.OCI_ATTR_SESSION, _sessionHandle, _errorHandle);
			}
			catch (OracleException)
			{
				OciHandle.SafeDispose(ref _serviceContextHandle);
				OciHandle.SafeDispose(ref _sessionHandle);
				OciHandle.SafeDispose(ref _serverHandle);
				OciHandle.SafeDispose(ref _errorHandle);
				OciHandle.SafeDispose(ref _environmentHandle);
				throw;
			}
			return true;
		}

		internal static long ParseServerVersion(string versionString)
		{
			PARSERSTATE pARSERSTATE = PARSERSTATE.NOTHINGYET;
			int num = 0;
			int num2 = 0;
			long num3 = 0L;
			versionString += "0.0.0.0.0 ";
			for (int i = 0; i < versionString.Length; i++)
			{
				switch (pARSERSTATE)
				{
				case PARSERSTATE.NOTHINGYET:
					if (char.IsDigit(versionString, i))
					{
						pARSERSTATE = PARSERSTATE.DIGIT;
						num = i;
					}
					break;
				case PARSERSTATE.PERIOD:
					if (char.IsDigit(versionString, i))
					{
						pARSERSTATE = PARSERSTATE.DIGIT;
						num = i;
					}
					else
					{
						pARSERSTATE = PARSERSTATE.NOTHINGYET;
						num2 = 0;
						num3 = 0L;
					}
					break;
				case PARSERSTATE.DIGIT:
					if ("." == versionString.Substring(i, 1) || 4 == num2)
					{
						num2++;
						pARSERSTATE = PARSERSTATE.PERIOD;
						long num4 = int.Parse(versionString.Substring(num, i - num), CultureInfo.InvariantCulture);
						num3 = (num3 << 8) + num4;
						if (5 == num2)
						{
							return num3;
						}
					}
					else if (!char.IsDigit(versionString, i))
					{
						pARSERSTATE = PARSERSTATE.NOTHINGYET;
						num2 = 0;
						num3 = 0L;
					}
					break;
				}
			}
			return 0L;
		}

		private OracleConnection ProxyConnection()
		{
			OracleConnection oracleConnection = (OracleConnection)base.Owner;
			if (oracleConnection == null)
			{
				throw System.Data.Common.ADP.InvalidOperation("internal connection without a proxy?");
			}
			return oracleConnection;
		}

		internal void Rollback()
		{
			if (TransactionState.GlobalStarted != _transactionState)
			{
				int num = TracedNativeMethods.OCITransRollback(ServiceContextHandle, ErrorHandle, OCI.MODE.OCI_DEFAULT);
				if (num != 0)
				{
					OracleException.Check(ErrorHandle, num);
				}
				TransactionState = TransactionState.AutoCommit;
			}
			Transaction = null;
		}

		internal void RollbackDeadTransaction()
		{
			if (_transaction != null && !_transaction.IsAlive)
			{
				Rollback();
			}
		}

		private void UnEnlist()
		{
			if (_enlistContext != null)
			{
				TransactionState = TransactionState.AutoCommit;
				_enlistContext.Join(this, null);
				OciEnlistContext.SafeDispose(ref _enlistContext);
				Transaction = null;
			}
		}
	}
	public sealed class OracleLob : Stream, ICloneable, IDisposable, INullable
	{
		private const byte x_IsTemporaryUnknown = 0;

		private const byte x_IsTemporary = 1;

		private const byte x_IsNotTemporary = 2;

		private bool _isNull;

		private OciLobLocator _lobLocator;

		private OracleType _lobType;

		private OCI.CHARSETFORM _charsetForm;

		private long _currentPosition;

		private byte _isTemporaryState;

		public new static readonly OracleLob Null = new OracleLob();

		public override bool CanRead
		{
			get
			{
				if (IsNull)
				{
					return true;
				}
				return !IsDisposed;
			}
		}

		public override bool CanSeek
		{
			get
			{
				if (IsNull)
				{
					return true;
				}
				return !IsDisposed;
			}
		}

		public override bool CanWrite
		{
			get
			{
				bool result = OracleType.BFile != _lobType;
				if (!IsNull)
				{
					result = !IsDisposed;
				}
				return result;
			}
		}

		public int ChunkSize
		{
			get
			{
				AssertObjectNotDisposed();
				if (IsNull)
				{
					return 0;
				}
				AssertConnectionIsOpen();
				uint lenp = 0u;
				int num = TracedNativeMethods.OCILobGetChunkSize(ServiceContextHandle, ErrorHandle, Descriptor, out lenp);
				if (num != 0)
				{
					Connection.CheckError(ErrorHandle, num);
				}
				return (int)lenp;
			}
		}

		public OracleConnection Connection
		{
			get
			{
				AssertObjectNotDisposed();
				return LobLocator?.Connection;
			}
		}

		private bool ConnectionIsClosed
		{
			get
			{
				if (LobLocator != null)
				{
					return LobLocator.ConnectionIsClosed;
				}
				return true;
			}
		}

		private uint CurrentOraclePosition => (uint)((int)AdjustOffsetToOracle(_currentPosition) + 1);

		internal OciHandle Descriptor => LobLocator.Descriptor;

		internal OciErrorHandle ErrorHandle => LobLocator.ErrorHandle;

		public bool IsBatched
		{
			get
			{
				if (IsNull || IsDisposed || ConnectionIsClosed)
				{
					return false;
				}
				int flag;
				int num = TracedNativeMethods.OCILobIsOpen(ServiceContextHandle, ErrorHandle, Descriptor, out flag);
				if (num != 0)
				{
					Connection.CheckError(ErrorHandle, num);
				}
				return flag != 0;
			}
		}

		private bool IsCharacterLob
		{
			get
			{
				if (OracleType.Clob != _lobType)
				{
					return OracleType.NClob == _lobType;
				}
				return true;
			}
		}

		private bool IsDisposed
		{
			get
			{
				if (!_isNull)
				{
					return null == LobLocator;
				}
				return false;
			}
		}

		public bool IsNull => _isNull;

		public bool IsTemporary
		{
			get
			{
				AssertObjectNotDisposed();
				if (IsNull)
				{
					return false;
				}
				AssertConnectionIsOpen();
				if (_isTemporaryState == 0)
				{
					int flag;
					int num = TracedNativeMethods.OCILobIsTemporary(Connection.EnvironmentHandle, ErrorHandle, Descriptor, out flag);
					if (num != 0)
					{
						Connection.CheckError(ErrorHandle, num);
					}
					_isTemporaryState = (byte)((flag != 0) ? 1 : 2);
				}
				return 1 == _isTemporaryState;
			}
		}

		internal OciLobLocator LobLocator => _lobLocator;

		public OracleType LobType => _lobType;

		public override long Length
		{
			get
			{
				AssertObjectNotDisposed();
				if (IsNull)
				{
					return 0L;
				}
				AssertConnectionIsOpen();
				uint lenp;
				int num = TracedNativeMethods.OCILobGetLength(ServiceContextHandle, ErrorHandle, Descriptor, out lenp);
				if (num != 0)
				{
					Connection.CheckError(ErrorHandle, num);
				}
				return AdjustOracleToOffset(lenp);
			}
		}

		public override long Position
		{
			get
			{
				AssertObjectNotDisposed();
				if (IsNull)
				{
					return 0L;
				}
				AssertConnectionIsOpen();
				return _currentPosition;
			}
			set
			{
				if (!IsNull)
				{
					Seek(value, SeekOrigin.Begin);
				}
			}
		}

		internal OciServiceContextHandle ServiceContextHandle => LobLocator.ServiceContextHandle;

		public object Value
		{
			get
			{
				AssertObjectNotDisposed();
				if (IsNull)
				{
					return DBNull.Value;
				}
				long currentPosition = _currentPosition;
				int num = (int)Length;
				bool flag = OracleType.Blob == _lobType || OracleType.BFile == _lobType;
				if (num == 0)
				{
					if (flag)
					{
						return new byte[0];
					}
					return string.Empty;
				}
				try
				{
					Seek(0L, SeekOrigin.Begin);
					if (flag)
					{
						byte[] array = new byte[num];
						Read(array, 0, num);
						return array;
					}
					try
					{
						StreamReader streamReader = new StreamReader(this, Encoding.Unicode);
						return streamReader.ReadToEnd();
					}
					finally
					{
						StreamReader streamReader = null;
					}
				}
				finally
				{
					_currentPosition = currentPosition;
				}
			}
		}

		internal OracleLob()
		{
			_isNull = true;
			_lobType = OracleType.Blob;
		}

		internal OracleLob(OciLobLocator lobLocator)
		{
			_lobLocator = lobLocator.Clone();
			_lobType = _lobLocator.LobType;
			_charsetForm = ((OracleType.NClob != _lobType) ? OCI.CHARSETFORM.SQLCS_IMPLICIT : OCI.CHARSETFORM.SQLCS_NCHAR);
		}

		internal OracleLob(OracleLob lob)
		{
			_lobLocator = lob._lobLocator.Clone();
			_lobType = lob._lobLocator.LobType;
			_charsetForm = lob._charsetForm;
			_currentPosition = lob._currentPosition;
			_isTemporaryState = lob._isTemporaryState;
		}

		internal OracleLob(OracleConnection connection, OracleType oracleType)
		{
			_lobLocator = new OciLobLocator(connection, oracleType);
			_lobType = oracleType;
			_charsetForm = ((OracleType.NClob != _lobType) ? OCI.CHARSETFORM.SQLCS_IMPLICIT : OCI.CHARSETFORM.SQLCS_NCHAR);
			_isTemporaryState = 1;
			OCI.LOB_TYPE lobtype = ((OracleType.Blob == oracleType) ? OCI.LOB_TYPE.OCI_TEMP_BLOB : OCI.LOB_TYPE.OCI_TEMP_CLOB);
			int num = TracedNativeMethods.OCILobCreateTemporary(connection.ServiceContextHandle, connection.ErrorHandle, _lobLocator.Descriptor, 0, _charsetForm, lobtype, 0, OCI.DURATION.OCI_DURATION_BEGIN);
			if (num != 0)
			{
				connection.CheckError(ErrorHandle, num);
			}
		}

		internal int AdjustOffsetToOracle(int amount)
		{
			return IsCharacterLob ? (amount / 2) : amount;
		}

		internal long AdjustOffsetToOracle(long amount)
		{
			return IsCharacterLob ? (amount / 2) : amount;
		}

		internal int AdjustOracleToOffset(int amount)
		{
			return IsCharacterLob ? checked(amount * 2) : amount;
		}

		internal long AdjustOracleToOffset(long amount)
		{
			return IsCharacterLob ? checked(amount * 2) : amount;
		}

		internal void AssertAmountIsEven(long amount, string argName)
		{
			if (IsCharacterLob && 1 == (amount & 1))
			{
				throw System.Data.Common.ADP.LobAmountMustBeEven(argName);
			}
		}

		internal void AssertAmountIsValidOddOK(long amount, string argName)
		{
			if (amount < 0 || amount >= uint.MaxValue)
			{
				throw System.Data.Common.ADP.LobAmountExceeded(argName);
			}
		}

		internal void AssertAmountIsValid(long amount, string argName)
		{
			AssertAmountIsValidOddOK(amount, argName);
			AssertAmountIsEven(amount, argName);
		}

		internal void AssertConnectionIsOpen()
		{
			if (ConnectionIsClosed)
			{
				throw System.Data.Common.ADP.ClosedConnectionError();
			}
		}

		internal void AssertObjectNotDisposed()
		{
			if (IsDisposed)
			{
				throw System.Data.Common.ADP.ObjectDisposed("OracleLob");
			}
		}

		internal void AssertPositionIsValid()
		{
			if (IsCharacterLob && 1 == (_currentPosition & 1))
			{
				throw System.Data.Common.ADP.LobPositionMustBeEven();
			}
		}

		internal void AssertTransactionExists()
		{
			if (!Connection.HasTransaction)
			{
				throw System.Data.Common.ADP.LobWriteRequiresTransaction();
			}
		}

		public void Append(OracleLob source)
		{
			if (source == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("source");
			}
			AssertObjectNotDisposed();
			source.AssertObjectNotDisposed();
			if (IsNull)
			{
				throw System.Data.Common.ADP.LobWriteInvalidOnNull();
			}
			if (!source.IsNull)
			{
				AssertConnectionIsOpen();
				int num = TracedNativeMethods.OCILobAppend(ServiceContextHandle, ErrorHandle, Descriptor, source.Descriptor);
				if (num != 0)
				{
					Connection.CheckError(ErrorHandle, num);
				}
			}
		}

		public void BeginBatch()
		{
			BeginBatch(OracleLobOpenMode.ReadOnly);
		}

		public void BeginBatch(OracleLobOpenMode mode)
		{
			AssertObjectNotDisposed();
			if (!IsNull)
			{
				AssertConnectionIsOpen();
				LobLocator.Open(mode);
			}
		}

		public object Clone()
		{
			AssertObjectNotDisposed();
			if (IsNull)
			{
				return Null;
			}
			AssertConnectionIsOpen();
			return new OracleLob(this);
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing && !IsNull && !ConnectionIsClosed)
				{
					Flush();
					OciLobLocator.SafeDispose(ref _lobLocator);
					_lobLocator = null;
				}
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public long CopyTo(OracleLob destination)
		{
			return CopyTo(0L, destination, 0L, Length);
		}

		public long CopyTo(OracleLob destination, long destinationOffset)
		{
			return CopyTo(0L, destination, destinationOffset, Length);
		}

		public long CopyTo(long sourceOffset, OracleLob destination, long destinationOffset, long amount)
		{
			if (destination == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("destination");
			}
			AssertObjectNotDisposed();
			destination.AssertObjectNotDisposed();
			AssertAmountIsValid(amount, "amount");
			AssertAmountIsValid(sourceOffset, "sourceOffset");
			AssertAmountIsValid(destinationOffset, "destinationOffset");
			if (destination.IsNull)
			{
				throw System.Data.Common.ADP.LobWriteInvalidOnNull();
			}
			if (IsNull)
			{
				return 0L;
			}
			AssertConnectionIsOpen();
			AssertTransactionExists();
			long num = AdjustOffsetToOracle(Math.Min(Length - sourceOffset, amount));
			long num2 = AdjustOffsetToOracle(destinationOffset) + 1;
			long num3 = AdjustOffsetToOracle(sourceOffset) + 1;
			if (0 >= num)
			{
				return 0L;
			}
			int num4 = TracedNativeMethods.OCILobCopy(ServiceContextHandle, ErrorHandle, destination.Descriptor, Descriptor, (uint)num, (uint)num2, (uint)num3);
			if (num4 != 0)
			{
				Connection.CheckError(ErrorHandle, num4);
			}
			return AdjustOracleToOffset(num);
		}

		public void EndBatch()
		{
			AssertObjectNotDisposed();
			if (!IsNull)
			{
				AssertConnectionIsOpen();
				LobLocator.ForceClose();
			}
		}

		public long Erase()
		{
			return Erase(0L, Length);
		}

		public long Erase(long offset, long amount)
		{
			AssertObjectNotDisposed();
			if (IsNull)
			{
				throw System.Data.Common.ADP.LobWriteInvalidOnNull();
			}
			AssertAmountIsValid(amount, "amount");
			AssertAmountIsEven(offset, "offset");
			AssertPositionIsValid();
			AssertConnectionIsOpen();
			AssertTransactionExists();
			if (offset < 0 || offset >= uint.MaxValue)
			{
				return 0L;
			}
			uint amount2 = (uint)AdjustOffsetToOracle(amount);
			uint offset2 = (uint)((int)AdjustOffsetToOracle(offset) + 1);
			int num = TracedNativeMethods.OCILobErase(ServiceContextHandle, ErrorHandle, Descriptor, ref amount2, offset2);
			if (num != 0)
			{
				Connection.CheckError(ErrorHandle, num);
			}
			return AdjustOracleToOffset(amount2);
		}

		internal void Free()
		{
			int num = TracedNativeMethods.OCILobFreeTemporary(_lobLocator.ServiceContextHandle, _lobLocator.ErrorHandle, _lobLocator.Descriptor);
			if (num != 0)
			{
				_lobLocator.Connection.CheckError(ErrorHandle, num);
			}
		}

		public override void Flush()
		{
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			AssertObjectNotDisposed();
			if (count < 0)
			{
				throw System.Data.Common.ADP.MustBePositive("count");
			}
			if (offset < 0)
			{
				throw System.Data.Common.ADP.MustBePositive("offset");
			}
			if (buffer == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("buffer");
			}
			if (buffer.Length < (long)offset + (long)count)
			{
				throw System.Data.Common.ADP.BufferExceeded("count");
			}
			if (IsNull || count == 0)
			{
				return 0;
			}
			AssertConnectionIsOpen();
			AssertAmountIsValidOddOK(offset, "offset");
			AssertAmountIsValidOddOK(count, "count");
			uint num = (uint)_currentPosition;
			int num2 = 0;
			int num3 = 0;
			int num4 = 0;
			byte[] array = buffer;
			int num5 = offset;
			int num6 = count;
			if (IsCharacterLob)
			{
				num2 = (int)(num & 1);
				num3 = offset & 1;
				num4 = count & 1;
				num /= 2u;
				if (1 == num3 || 1 == num2 || 1 == num4)
				{
					num5 = 0;
					num6 = count + num4 + 2 * num2;
					array = new byte[num6];
				}
			}
			ushort csid = (ushort)(IsCharacterLob ? 1000 : 0);
			int num7 = 0;
			int amtp = AdjustOffsetToOracle(num6);
			GCHandle gCHandle = default(GCHandle);
			try
			{
				gCHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
				num7 = TracedNativeMethods.OCILobRead(bufp: new IntPtr((long)gCHandle.AddrOfPinnedObject() + num5), svchp: ServiceContextHandle, errhp: ErrorHandle, locp: Descriptor, amtp: ref amtp, offset: num + 1, bufl: checked((uint)num6), csid: csid, csfrm: _charsetForm);
			}
			finally
			{
				if (gCHandle.IsAllocated)
				{
					gCHandle.Free();
				}
			}
			if (99 == num7)
			{
				num7 = 0;
			}
			if (100 == num7)
			{
				return 0;
			}
			if (num7 != 0)
			{
				Connection.CheckError(ErrorHandle, num7);
			}
			amtp = AdjustOracleToOffset(amtp);
			if (array != buffer)
			{
				amtp = ((amtp < count) ? (amtp - num2) : count);
				Buffer.BlockCopy(array, num2, buffer, offset, amtp);
				array = null;
			}
			_currentPosition += amtp;
			return amtp;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			AssertObjectNotDisposed();
			if (IsNull)
			{
				return 0L;
			}
			long num = offset;
			long length = Length;
			num = origin switch
			{
				SeekOrigin.Begin => offset, 
				SeekOrigin.End => length + offset, 
				SeekOrigin.Current => _currentPosition + offset, 
				_ => throw System.Data.Common.ADP.InvalidSeekOrigin(origin), 
			};
			if (num < 0 || num > length)
			{
				throw System.Data.Common.ADP.SeekBeyondEnd("offset");
			}
			_currentPosition = num;
			return _currentPosition;
		}

		public override void SetLength(long value)
		{
			AssertObjectNotDisposed();
			if (IsNull)
			{
				throw System.Data.Common.ADP.LobWriteInvalidOnNull();
			}
			AssertConnectionIsOpen();
			AssertAmountIsValid(value, "value");
			AssertTransactionExists();
			uint newlen = (uint)AdjustOffsetToOracle(value);
			int num = TracedNativeMethods.OCILobTrim(ServiceContextHandle, ErrorHandle, Descriptor, newlen);
			if (num != 0)
			{
				Connection.CheckError(ErrorHandle, num);
			}
			_currentPosition = Math.Min(_currentPosition, value);
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			AssertObjectNotDisposed();
			AssertConnectionIsOpen();
			if (count < 0)
			{
				throw System.Data.Common.ADP.MustBePositive("count");
			}
			if (offset < 0)
			{
				throw System.Data.Common.ADP.MustBePositive("offset");
			}
			if (buffer == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("buffer");
			}
			if (buffer.Length < (long)offset + (long)count)
			{
				throw System.Data.Common.ADP.BufferExceeded("count");
			}
			AssertTransactionExists();
			if (IsNull)
			{
				throw System.Data.Common.ADP.LobWriteInvalidOnNull();
			}
			AssertAmountIsValid(offset, "offset");
			AssertAmountIsValid(count, "count");
			AssertPositionIsValid();
			OCI.CHARSETFORM charsetForm = _charsetForm;
			ushort csid = (ushort)(IsCharacterLob ? 1000 : 0);
			int amtp = AdjustOffsetToOracle(count);
			int num = 0;
			if (amtp == 0)
			{
				return;
			}
			GCHandle gCHandle = default(GCHandle);
			try
			{
				gCHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
				num = TracedNativeMethods.OCILobWrite(bufp: new IntPtr((long)gCHandle.AddrOfPinnedObject() + offset), svchp: ServiceContextHandle, errhp: ErrorHandle, locp: Descriptor, amtp: ref amtp, offset: CurrentOraclePosition, buflen: (uint)count, piece: 0, csid: csid, csfrm: charsetForm);
			}
			finally
			{
				if (gCHandle.IsAllocated)
				{
					gCHandle.Free();
				}
			}
			if (num != 0)
			{
				Connection.CheckError(ErrorHandle, num);
			}
			amtp = AdjustOracleToOffset(amtp);
			_currentPosition += amtp;
		}

		public override void WriteByte(byte value)
		{
			if (OracleType.Clob == _lobType || OracleType.NClob == _lobType)
			{
				throw System.Data.Common.ADP.WriteByteForBinaryLobsOnly();
			}
			base.WriteByte(value);
		}
	}
	public enum OracleLobOpenMode
	{
		ReadOnly = 1,
		ReadWrite
	}
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct OracleMonthSpan : IComparable, INullable
	{
		private const int MaxMonth = 176556;

		private const int MinMonth = -176556;

		private const int NullValue = int.MaxValue;

		private int _value;

		public static readonly OracleMonthSpan MaxValue = new OracleMonthSpan(176556);

		public static readonly OracleMonthSpan MinValue = new OracleMonthSpan(-176556);

		public static readonly OracleMonthSpan Null = new OracleMonthSpan(isNull: true);

		public bool IsNull => int.MaxValue == _value;

		public int Value
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return _value;
			}
		}

		internal OracleMonthSpan(bool isNull)
		{
			_value = int.MaxValue;
		}

		public OracleMonthSpan(int months)
		{
			_value = months;
			AssertValid(_value);
		}

		public OracleMonthSpan(int years, int months)
		{
			//Discarded unreachable code: IL_0015
			try
			{
				_value = checked(years * 12 + months);
			}
			catch (OverflowException)
			{
				throw System.Data.Common.ADP.MonthOutOfRange();
			}
			AssertValid(_value);
		}

		public OracleMonthSpan(OracleMonthSpan from)
		{
			_value = from._value;
		}

		internal OracleMonthSpan(NativeBuffer buffer, int valueOffset)
		{
			_value = MarshalToInt32(buffer, valueOffset);
		}

		private static void AssertValid(int monthSpan)
		{
			if (monthSpan < -176556 || monthSpan > 176556)
			{
				throw System.Data.Common.ADP.MonthOutOfRange();
			}
		}

		public int CompareTo(object obj)
		{
			if (obj.GetType() == typeof(OracleMonthSpan))
			{
				OracleMonthSpan oracleMonthSpan = (OracleMonthSpan)obj;
				if (IsNull)
				{
					if (!oracleMonthSpan.IsNull)
					{
						return -1;
					}
					return 0;
				}
				if (oracleMonthSpan.IsNull)
				{
					return 1;
				}
				return _value.CompareTo(oracleMonthSpan._value);
			}
			throw System.Data.Common.ADP.WrongType(obj.GetType(), typeof(OracleMonthSpan));
		}

		public override bool Equals(object value)
		{
			if (value is OracleMonthSpan)
			{
				return (this == (OracleMonthSpan)value).Value;
			}
			return false;
		}

		public override int GetHashCode()
		{
			if (!IsNull)
			{
				return _value.GetHashCode();
			}
			return 0;
		}

		internal static int MarshalToInt32(NativeBuffer buffer, int valueOffset)
		{
			byte[] array = buffer.ReadBytes(valueOffset, 5);
			int num = (int)(((array[0] << 24) | (array[1] << 16) | (array[2] << 8) | array[3]) - 2147483648u);
			int num2 = array[4] - 60;
			int num3 = num * 12 + num2;
			AssertValid(num3);
			return num3;
		}

		internal static int MarshalToNative(object value, NativeBuffer buffer, int offset)
		{
			int num = ((!(value is OracleMonthSpan)) ? ((int)value) : ((OracleMonthSpan)value)._value);
			byte[] array = new byte[5];
			int num2 = (int)(num / 12 + 2147483648u);
			int num3 = num % 12;
			array[0] = (byte)(num2 >> 24);
			array[1] = (byte)((uint)(num2 >> 16) & 0xFFu);
			array[2] = (byte)((uint)(num2 >> 8) & 0xFFu);
			array[3] = (byte)((uint)num2 & 0xFFu);
			array[4] = (byte)(num3 + 60);
			buffer.WriteBytes(offset, array, 0, 5);
			return 5;
		}

		public static OracleMonthSpan Parse(string s)
		{
			int months = int.Parse(s, CultureInfo.InvariantCulture);
			return new OracleMonthSpan(months);
		}

		public override string ToString()
		{
			if (IsNull)
			{
				return System.Data.Common.ADP.NullString;
			}
			return Value.ToString(CultureInfo.CurrentCulture);
		}

		public static OracleBoolean Equals(OracleMonthSpan x, OracleMonthSpan y)
		{
			return x == y;
		}

		public static OracleBoolean GreaterThan(OracleMonthSpan x, OracleMonthSpan y)
		{
			return x > y;
		}

		public static OracleBoolean GreaterThanOrEqual(OracleMonthSpan x, OracleMonthSpan y)
		{
			return x >= y;
		}

		public static OracleBoolean LessThan(OracleMonthSpan x, OracleMonthSpan y)
		{
			return x < y;
		}

		public static OracleBoolean LessThanOrEqual(OracleMonthSpan x, OracleMonthSpan y)
		{
			return x <= y;
		}

		public static OracleBoolean NotEquals(OracleMonthSpan x, OracleMonthSpan y)
		{
			return x != y;
		}

		public static explicit operator int(OracleMonthSpan x)
		{
			if (x.IsNull)
			{
				throw System.Data.Common.ADP.DataIsNull();
			}
			return x.Value;
		}

		public static explicit operator OracleMonthSpan(string x)
		{
			return Parse(x);
		}

		public static OracleBoolean operator ==(OracleMonthSpan x, OracleMonthSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) == 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >(OracleMonthSpan x, OracleMonthSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) > 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >=(OracleMonthSpan x, OracleMonthSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) >= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <(OracleMonthSpan x, OracleMonthSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) < 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <=(OracleMonthSpan x, OracleMonthSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) <= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator !=(OracleMonthSpan x, OracleMonthSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) != 0);
			}
			return OracleBoolean.Null;
		}
	}
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct OracleNumber : IComparable, INullable
	{
		private const string WholeDigitPattern = "999999999999999999999999999999999999999999999999999999999999999";

		private const int WholeDigitPattern_Length = 63;

		private static double doubleMinValue = -9.99999999999999E+125;

		private static double doubleMaxValue = 9.99999999999999E+125;

		private static readonly byte[] OciNumberValue_DecimalMaxValue = new byte[17]
		{
			16, 207, 8, 93, 29, 17, 26, 15, 27, 44,
			38, 59, 93, 49, 99, 31, 40
		};

		private static readonly byte[] OciNumberValue_DecimalMinValue = new byte[18]
		{
			17, 48, 94, 9, 73, 85, 76, 87, 75, 58,
			64, 43, 9, 53, 3, 71, 62, 102
		};

		private static readonly byte[] OciNumberValue_E = new byte[22]
		{
			21, 193, 3, 72, 83, 82, 83, 85, 60, 5,
			53, 36, 37, 3, 88, 48, 14, 53, 67, 25,
			98, 77
		};

		private static readonly byte[] OciNumberValue_MaxValue = new byte[21]
		{
			20, 255, 100, 100, 100, 100, 100, 100, 100, 100,
			100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
			100
		};

		private static readonly byte[] OciNumberValue_MinValue = new byte[22]
		{
			21, 0, 2, 2, 2, 2, 2, 2, 2, 2,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			2, 102
		};

		private static readonly byte[] OciNumberValue_MinusOne = new byte[4] { 3, 62, 100, 102 };

		private static readonly byte[] OciNumberValue_One = new byte[3] { 2, 193, 2 };

		private static readonly byte[] OciNumberValue_Pi = new byte[22]
		{
			21, 193, 4, 15, 16, 93, 66, 36, 90, 80,
			33, 39, 47, 27, 44, 39, 33, 80, 51, 29,
			85, 21
		};

		private static readonly byte[] OciNumberValue_TwoPow64 = new byte[12]
		{
			11, 202, 19, 45, 68, 45, 8, 38, 10, 56,
			17, 17
		};

		private static readonly byte[] OciNumberValue_Zero = new byte[2] { 1, 128 };

		private byte[] _value;

		public static readonly OracleNumber E = new OracleNumber(OciNumberValue_E);

		public static readonly int MaxPrecision = 38;

		public static readonly int MaxScale = 127;

		public static readonly int MinScale = -84;

		public static readonly OracleNumber MaxValue = new OracleNumber(OciNumberValue_MaxValue);

		public static readonly OracleNumber MinValue = new OracleNumber(OciNumberValue_MinValue);

		public static readonly OracleNumber MinusOne = new OracleNumber(OciNumberValue_MinusOne);

		public static readonly OracleNumber Null = new OracleNumber(isNull: true);

		public static readonly OracleNumber One = new OracleNumber(OciNumberValue_One);

		public static readonly OracleNumber PI = new OracleNumber(OciNumberValue_Pi);

		public static readonly OracleNumber Zero = new OracleNumber(OciNumberValue_Zero);

		public bool IsNull => null == _value;

		public decimal Value => (decimal)this;

		private OracleNumber(bool isNull)
		{
			_value = (isNull ? null : new byte[22]);
		}

		private OracleNumber(byte[] bits)
		{
			_value = bits;
		}

		public OracleNumber(decimal decValue)
			: this(isNull: false)
		{
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			FromDecimal(errorHandle, decValue, _value);
		}

		public OracleNumber(double dblValue)
			: this(isNull: false)
		{
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			FromDouble(errorHandle, dblValue, _value);
		}

		public OracleNumber(int intValue)
			: this(isNull: false)
		{
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			FromInt32(errorHandle, intValue, _value);
		}

		public OracleNumber(long longValue)
			: this(isNull: false)
		{
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			FromInt64(errorHandle, longValue, _value);
		}

		public OracleNumber(OracleNumber from)
		{
			byte[] value = from._value;
			if (value != null)
			{
				_value = (byte[])value.Clone();
			}
			else
			{
				_value = null;
			}
		}

		internal OracleNumber(string s)
			: this(isNull: false)
		{
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			FromString(errorHandle, s, _value);
		}

		internal OracleNumber(NativeBuffer buffer, int valueOffset)
			: this(isNull: false)
		{
			buffer.ReadBytes(valueOffset, _value, 0, 22);
		}

		public int CompareTo(object obj)
		{
			if (obj.GetType() == typeof(OracleNumber))
			{
				OracleNumber oracleNumber = (OracleNumber)obj;
				if (IsNull)
				{
					if (!oracleNumber.IsNull)
					{
						return -1;
					}
					return 0;
				}
				if (oracleNumber.IsNull)
				{
					return 1;
				}
				OracleConnection.ExecutePermission.Demand();
				OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
				return InternalCmp(errorHandle, _value, oracleNumber._value);
			}
			throw System.Data.Common.ADP.WrongType(obj.GetType(), typeof(OracleNumber));
		}

		public override bool Equals(object value)
		{
			if (value is OracleNumber)
			{
				return (this == (OracleNumber)value).Value;
			}
			return false;
		}

		public override int GetHashCode()
		{
			if (!IsNull)
			{
				return _value.GetHashCode();
			}
			return 0;
		}

		internal static decimal MarshalToDecimal(NativeBuffer buffer, int valueOffset, OracleConnection connection)
		{
			byte[] value = buffer.ReadBytes(valueOffset, 22);
			OciErrorHandle errorHandle = connection.ErrorHandle;
			return ToDecimal(errorHandle, value);
		}

		internal static int MarshalToInt32(NativeBuffer buffer, int valueOffset, OracleConnection connection)
		{
			byte[] value = buffer.ReadBytes(valueOffset, 22);
			OciErrorHandle errorHandle = connection.ErrorHandle;
			return ToInt32(errorHandle, value);
		}

		internal static long MarshalToInt64(NativeBuffer buffer, int valueOffset, OracleConnection connection)
		{
			byte[] value = buffer.ReadBytes(valueOffset, 22);
			OciErrorHandle errorHandle = connection.ErrorHandle;
			return ToInt64(errorHandle, value);
		}

		internal static int MarshalToNative(object value, NativeBuffer buffer, int offset, OracleConnection connection)
		{
			byte[] array;
			if (value is OracleNumber)
			{
				array = ((OracleNumber)value)._value;
			}
			else
			{
				OciErrorHandle errorHandle = connection.ErrorHandle;
				array = new byte[22];
				if (value is decimal)
				{
					FromDecimal(errorHandle, (decimal)value, array);
				}
				else if (value is int)
				{
					FromInt32(errorHandle, (int)value, array);
				}
				else if (value is long)
				{
					FromInt64(errorHandle, (long)value, array);
				}
				else
				{
					FromDouble(errorHandle, (double)value, array);
				}
			}
			buffer.WriteBytes(offset, array, 0, 22);
			return 22;
		}

		public static OracleNumber Parse(string s)
		{
			if (s == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("s");
			}
			return new OracleNumber(s);
		}

		private static void InternalAdd(OciErrorHandle errorHandle, byte[] x, byte[] y, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberAdd(errorHandle, x, y, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static int InternalCmp(OciErrorHandle errorHandle, byte[] value1, byte[] value2)
		{
			int result;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberCmp(errorHandle, value1, value2, out result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		private static void InternalDiv(OciErrorHandle errorHandle, byte[] x, byte[] y, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberDiv(errorHandle, x, y, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static bool InternalIsInt(OciErrorHandle errorHandle, byte[] n)
		{
			int result;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberIsInt(errorHandle, n, out result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return 0 != result;
		}

		private static void InternalMod(OciErrorHandle errorHandle, byte[] x, byte[] y, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberMod(errorHandle, x, y, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void InternalMul(OciErrorHandle errorHandle, byte[] x, byte[] y, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberMul(errorHandle, x, y, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void InternalNeg(OciErrorHandle errorHandle, byte[] x, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberNeg(errorHandle, x, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static int InternalSign(OciErrorHandle errorHandle, byte[] n)
		{
			int result;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberSign(errorHandle, n, out result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		private static void InternalShift(OciErrorHandle errorHandle, byte[] n, int digits, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberShift(errorHandle, n, digits, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void InternalSub(OciErrorHandle errorHandle, byte[] x, byte[] y, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberSub(errorHandle, x, y, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void InternalTrunc(OciErrorHandle errorHandle, byte[] n, int position, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberTrunc(errorHandle, n, position, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void FromDecimal(OciErrorHandle errorHandle, decimal decimalValue, byte[] result)
		{
			int[] bits = decimal.GetBits(decimalValue);
			ulong ulongValue = ((ulong)(uint)bits[1] << 32) | (uint)bits[0];
			uint num = (uint)bits[2];
			int num2 = bits[3] >> 31;
			int num3 = (bits[3] >> 16) & 0x7F;
			FromUInt64(errorHandle, ulongValue, result);
			if (num != 0)
			{
				byte[] array = new byte[22];
				FromUInt32(errorHandle, num, array);
				InternalMul(errorHandle, array, OciNumberValue_TwoPow64, array);
				InternalAdd(errorHandle, result, array, result);
			}
			if (num2 != 0)
			{
				InternalNeg(errorHandle, result, result);
			}
			if (num3 != 0)
			{
				InternalShift(errorHandle, result, -num3, result);
			}
		}

		private static void FromDouble(OciErrorHandle errorHandle, double dblValue, byte[] result)
		{
			if (dblValue < doubleMinValue || dblValue > doubleMaxValue)
			{
				throw System.Data.Common.ADP.OperationResultedInOverflow();
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberFromReal(errorHandle, ref dblValue, 8u, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void FromInt32(OciErrorHandle errorHandle, int intValue, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberFromInt(errorHandle, ref intValue, 4u, OCI.SIGN.OCI_NUMBER_SIGNED, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void FromUInt32(OciErrorHandle errorHandle, uint uintValue, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberFromInt(errorHandle, ref uintValue, 4u, OCI.SIGN.OCI_NUMBER_UNSIGNED, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void FromInt64(OciErrorHandle errorHandle, long longValue, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberFromInt(errorHandle, ref longValue, 8u, OCI.SIGN.OCI_NUMBER_SIGNED, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private static void FromUInt64(OciErrorHandle errorHandle, ulong ulongValue, byte[] result)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberFromInt(errorHandle, ref ulongValue, 8u, OCI.SIGN.OCI_NUMBER_UNSIGNED, result);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
		}

		private void FromStringOfDigits(OciErrorHandle errorHandle, string s, byte[] result)
		{
			if (s.Length <= 63)
			{
				int num = System.Data.Common.UnsafeNativeMethods.OCINumberFromText(errorHandle, s, (uint)s.Length, "999999999999999999999999999999999999999999999999999999999999999", 63u, IntPtr.Zero, 0u, result);
				if (num != 0)
				{
					OracleException.Check(errorHandle, num);
				}
			}
			else
			{
				byte[] array = new byte[22];
				string s2 = s.Substring(0, 63);
				string text = s.Substring(63);
				FromStringOfDigits(errorHandle, s2, array);
				FromStringOfDigits(errorHandle, text, result);
				InternalShift(errorHandle, array, text.Length, array);
				InternalAdd(errorHandle, result, array, result);
			}
		}

		private void FromString(OciErrorHandle errorHandle, string s, byte[] result)
		{
			byte[] array = new byte[22];
			int num = 0;
			s = s.Trim();
			int num2 = s.IndexOfAny("eE".ToCharArray());
			if (num2 > 0)
			{
				num = int.Parse(s.Substring(num2 + 1), CultureInfo.InvariantCulture);
				s = s.Substring(0, num2);
			}
			bool flag = false;
			if ('-' == s[0])
			{
				flag = true;
				s = s.Substring(1);
			}
			else if ('+' == s[0])
			{
				s = s.Substring(1);
			}
			int num3 = s.IndexOf('.');
			if (0 <= num3)
			{
				string text = s.Substring(num3 + 1);
				FromStringOfDigits(errorHandle, text, result);
				InternalShift(errorHandle, result, -text.Length, result);
				if (num3 != 0)
				{
					FromStringOfDigits(errorHandle, s.Substring(0, num3), array);
					InternalAdd(errorHandle, result, array, result);
				}
			}
			else
			{
				FromStringOfDigits(errorHandle, s, result);
			}
			if (num != 0)
			{
				InternalShift(errorHandle, result, num, result);
			}
			if (flag)
			{
				InternalNeg(errorHandle, result, result);
			}
			GC.KeepAlive(s);
		}

		private static decimal ToDecimal(OciErrorHandle errorHandle, byte[] value)
		{
			byte[] array = (byte[])value.Clone();
			byte[] array2 = new byte[22];
			byte b = 0;
			int num = InternalSign(errorHandle, array);
			if (num < 0)
			{
				InternalNeg(errorHandle, array, array);
			}
			if (!InternalIsInt(errorHandle, array))
			{
				int num2 = 2 * (array[0] - ((array[1] & 0x7F) - 64) - 1);
				InternalShift(errorHandle, array, num2, array);
				b = (byte)(b + (byte)num2);
				while (!InternalIsInt(errorHandle, array))
				{
					InternalShift(errorHandle, array, 1, array);
					b = (byte)(b + 1);
				}
			}
			InternalMod(errorHandle, array, OciNumberValue_TwoPow64, array2);
			ulong num3 = ToUInt64(errorHandle, array2);
			InternalDiv(errorHandle, array, OciNumberValue_TwoPow64, array2);
			InternalTrunc(errorHandle, array2, 0, array2);
			uint hi = ToUInt32(errorHandle, array2);
			return new decimal((int)(num3 & 0xFFFFFFFFu), (int)(num3 >> 32), (int)hi, num < 0, b);
		}

		private static int ToInt32(OciErrorHandle errorHandle, byte[] value)
		{
			int rsl;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberToInt((OciHandle)errorHandle, value, 4u, OCI.SIGN.OCI_NUMBER_SIGNED, out rsl);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return rsl;
		}

		private static uint ToUInt32(OciErrorHandle errorHandle, byte[] value)
		{
			uint rsl;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberToInt((OciHandle)errorHandle, value, 4u, OCI.SIGN.OCI_NUMBER_UNSIGNED, out rsl);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return rsl;
		}

		private static long ToInt64(OciErrorHandle errorHandle, byte[] value)
		{
			long rsl;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberToInt((OciHandle)errorHandle, value, 8u, OCI.SIGN.OCI_NUMBER_SIGNED, out rsl);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return rsl;
		}

		private static ulong ToUInt64(OciErrorHandle errorHandle, byte[] value)
		{
			ulong rsl;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberToInt((OciHandle)errorHandle, value, 8u, OCI.SIGN.OCI_NUMBER_UNSIGNED, out rsl);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return rsl;
		}

		private static string ToString(OciErrorHandle errorHandle, byte[] value)
		{
			byte[] array = new byte[64];
			uint buf_size = (uint)array.Length;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberToText(errorHandle, value, "TM9", 3, IntPtr.Zero, 0u, ref buf_size, array);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			int num2 = Array.IndexOf(array, (byte)58);
			num2 = ((num2 > 0) ? num2 : Array.LastIndexOf(array, 0));
			return Encoding.Default.GetString(array, 0, (num2 > 0) ? num2 : checked((int)buf_size));
		}

		public override string ToString()
		{
			if (IsNull)
			{
				return System.Data.Common.ADP.NullString;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			return ToString(errorHandle, _value);
		}

		public static OracleBoolean operator ==(OracleNumber x, OracleNumber y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) == 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >(OracleNumber x, OracleNumber y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) > 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >=(OracleNumber x, OracleNumber y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) >= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <(OracleNumber x, OracleNumber y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) < 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <=(OracleNumber x, OracleNumber y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) <= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator !=(OracleNumber x, OracleNumber y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) != 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleNumber operator -(OracleNumber x)
		{
			if (x.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalNeg(errorHandle, x._value, result._value);
			return result;
		}

		public static OracleNumber operator +(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalAdd(errorHandle, x._value, y._value, result._value);
			return result;
		}

		public static OracleNumber operator -(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalSub(errorHandle, x._value, y._value, result._value);
			return result;
		}

		public static OracleNumber operator *(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalMul(errorHandle, x._value, y._value, result._value);
			return result;
		}

		public static OracleNumber operator /(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalDiv(errorHandle, x._value, y._value, result._value);
			return result;
		}

		public static OracleNumber operator %(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalMod(errorHandle, x._value, y._value, result._value);
			return result;
		}

		public static explicit operator decimal(OracleNumber x)
		{
			if (x.IsNull)
			{
				throw System.Data.Common.ADP.DataIsNull();
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			return ToDecimal(errorHandle, x._value);
		}

		public static explicit operator double(OracleNumber x)
		{
			if (x.IsNull)
			{
				throw System.Data.Common.ADP.DataIsNull();
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			double rsl;
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberToReal(errorHandle, x._value, 8u, out rsl);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return rsl;
		}

		public static explicit operator int(OracleNumber x)
		{
			if (x.IsNull)
			{
				throw System.Data.Common.ADP.DataIsNull();
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			return ToInt32(errorHandle, x._value);
		}

		public static explicit operator long(OracleNumber x)
		{
			if (x.IsNull)
			{
				throw System.Data.Common.ADP.DataIsNull();
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			return ToInt64(errorHandle, x._value);
		}

		public static explicit operator OracleNumber(decimal x)
		{
			return new OracleNumber(x);
		}

		public static explicit operator OracleNumber(double x)
		{
			return new OracleNumber(x);
		}

		public static explicit operator OracleNumber(int x)
		{
			return new OracleNumber(x);
		}

		public static explicit operator OracleNumber(long x)
		{
			return new OracleNumber(x);
		}

		public static explicit operator OracleNumber(string x)
		{
			return new OracleNumber(x);
		}

		public static OracleNumber Abs(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberAbs(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Acos(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberArcCos(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Add(OracleNumber x, OracleNumber y)
		{
			return x + y;
		}

		public static OracleNumber Asin(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberArcSin(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Atan(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberArcTan(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Atan2(OracleNumber y, OracleNumber x)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberArcTan2(errorHandle, y._value, x._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Ceiling(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberCeil(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Cos(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberCos(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Cosh(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberHypCos(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Divide(OracleNumber x, OracleNumber y)
		{
			return x / y;
		}

		public static OracleBoolean Equals(OracleNumber x, OracleNumber y)
		{
			return x == y;
		}

		public static OracleNumber Exp(OracleNumber p)
		{
			if (p.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberExp(errorHandle, p._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Floor(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberFloor(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleBoolean GreaterThan(OracleNumber x, OracleNumber y)
		{
			return x > y;
		}

		public static OracleBoolean GreaterThanOrEqual(OracleNumber x, OracleNumber y)
		{
			return x >= y;
		}

		public static OracleBoolean LessThan(OracleNumber x, OracleNumber y)
		{
			return x < y;
		}

		public static OracleBoolean LessThanOrEqual(OracleNumber x, OracleNumber y)
		{
			return x <= y;
		}

		public static OracleNumber Log(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberLn(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Log(OracleNumber n, int newBase)
		{
			return Log(n, new OracleNumber(newBase));
		}

		public static OracleNumber Log(OracleNumber n, OracleNumber newBase)
		{
			if (n.IsNull || newBase.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberLog(errorHandle, newBase._value, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Log10(OracleNumber n)
		{
			return Log(n, new OracleNumber(10));
		}

		public static OracleNumber Max(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			if (!OracleBoolean.op_True(x > y))
			{
				return y;
			}
			return x;
		}

		public static OracleNumber Min(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			if (!OracleBoolean.op_True(x < y))
			{
				return y;
			}
			return x;
		}

		public static OracleNumber Modulo(OracleNumber x, OracleNumber y)
		{
			return x % y;
		}

		public static OracleNumber Multiply(OracleNumber x, OracleNumber y)
		{
			return x * y;
		}

		public static OracleNumber Negate(OracleNumber x)
		{
			return -x;
		}

		public static OracleBoolean NotEquals(OracleNumber x, OracleNumber y)
		{
			return x != y;
		}

		public static OracleNumber Pow(OracleNumber x, int y)
		{
			if (x.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberIntPower(errorHandle, x._value, y, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Pow(OracleNumber x, OracleNumber y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberPower(errorHandle, x._value, y._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Round(OracleNumber n, int position)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberRound(errorHandle, n._value, position, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Shift(OracleNumber n, int digits)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalShift(errorHandle, n._value, digits, result._value);
			return result;
		}

		public static OracleNumber Sign(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			int num = InternalSign(errorHandle, n._value);
			return (num > 0) ? One : MinusOne;
		}

		public static OracleNumber Sin(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberSin(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Sinh(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberHypSin(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Sqrt(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberSqrt(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Subtract(OracleNumber x, OracleNumber y)
		{
			return x - y;
		}

		public static OracleNumber Tan(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberTan(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Tanh(OracleNumber n)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			int num = System.Data.Common.UnsafeNativeMethods.OCINumberHypTan(errorHandle, n._value, result._value);
			if (num != 0)
			{
				OracleException.Check(errorHandle, num);
			}
			return result;
		}

		public static OracleNumber Truncate(OracleNumber n, int position)
		{
			if (n.IsNull)
			{
				return Null;
			}
			OracleConnection.ExecutePermission.Demand();
			OciErrorHandle errorHandle = TempEnvironment.GetErrorHandle();
			OracleNumber result = new OracleNumber(isNull: false);
			InternalTrunc(errorHandle, n._value, position, result._value);
			return result;
		}
	}
	[TypeConverter(typeof(OracleParameterConverter))]
	public sealed class OracleParameter : DbParameter, ICloneable, IDbDataParameter, IDataParameter
	{
		internal sealed class OracleParameterConverter : ExpandableObjectConverter
		{
			public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
			{
				if (destinationType == typeof(InstanceDescriptor))
				{
					return true;
				}
				return base.CanConvertTo(context, destinationType);
			}

			public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
			{
				if (destinationType == null)
				{
					throw System.Data.Common.ADP.ArgumentNull("destinationType");
				}
				if (destinationType == typeof(InstanceDescriptor) && value is OracleParameter)
				{
					return ConvertToInstanceDescriptor(value as OracleParameter);
				}
				return base.ConvertTo(context, culture, value, destinationType);
			}

			private InstanceDescriptor ConvertToInstanceDescriptor(OracleParameter p)
			{
				int num = 0;
				if (p.ShouldSerializeOracleType())
				{
					num |= 1;
				}
				if (p.ShouldSerializeSize())
				{
					num |= 2;
				}
				if (!System.Data.Common.ADP.IsEmpty(p.SourceColumn))
				{
					num |= 4;
				}
				if (p.Value != null)
				{
					num |= 8;
				}
				if (ParameterDirection.Input != p.Direction || p.IsNullable || p.ShouldSerializePrecision() || p.ShouldSerializeScale() || DataRowVersion.Current != p.SourceVersion)
				{
					num |= 0x10;
				}
				if (p.SourceColumnNullMapping)
				{
					num |= 0x20;
				}
				Type[] types;
				object[] arguments;
				switch (num)
				{
				case 0:
				case 1:
					types = new Type[2]
					{
						typeof(string),
						typeof(OracleType)
					};
					arguments = new object[2] { p.ParameterName, p.OracleType };
					break;
				case 2:
				case 3:
					types = new Type[3]
					{
						typeof(string),
						typeof(OracleType),
						typeof(int)
					};
					arguments = new object[3] { p.ParameterName, p.OracleType, p.Size };
					break;
				case 4:
				case 5:
				case 6:
				case 7:
					types = new Type[4]
					{
						typeof(string),
						typeof(OracleType),
						typeof(int),
						typeof(string)
					};
					arguments = new object[4] { p.ParameterName, p.OracleType, p.Size, p.SourceColumn };
					break;
				case 8:
					types = new Type[2]
					{
						typeof(string),
						typeof(object)
					};
					arguments = new object[2] { p.ParameterName, p.Value };
					break;
				default:
					if ((0x20 & num) == 0)
					{
						types = new Type[10]
						{
							typeof(string),
							typeof(OracleType),
							typeof(int),
							typeof(ParameterDirection),
							typeof(bool),
							typeof(byte),
							typeof(byte),
							typeof(string),
							typeof(DataRowVersion),
							typeof(object)
						};
						arguments = new object[10] { p.ParameterName, p.OracleType, p.Size, p.Direction, p.IsNullable, p.PrecisionInternal, p.ScaleInternal, p.SourceColumn, p.SourceVersion, p.Value };
					}
					else
					{
						types = new Type[8]
						{
							typeof(string),
							typeof(OracleType),
							typeof(int),
							typeof(ParameterDirection),
							typeof(string),
							typeof(DataRowVersion),
							typeof(bool),
							typeof(object)
						};
						arguments = new object[8] { p.ParameterName, p.OracleType, p.Size, p.Direction, p.SourceColumn, p.SourceVersion, p.SourceColumnNullMapping, p.Value };
					}
					break;
				}
				ConstructorInfo constructor = typeof(OracleParameter).GetConstructor(types);
				return new InstanceDescriptor(constructor, arguments);
			}
		}

		private MetaType _metaType;

		private int _commandSetResult;

		private MetaType _coercedMetaType;

		private string _parameterName;

		private byte _precision;

		private byte _scale;

		private bool _hasScale;

		private object _value;

		private object _parent;

		private ParameterDirection _direction;

		private int _size;

		private int _offset;

		private string _sourceColumn;

		private DataRowVersion _sourceVersion;

		private bool _sourceColumnNullMapping;

		private bool _isNullable;

		private object _coercedValue;

		internal int BindSize
		{
			get
			{
				int num = GetActualSize();
				if (32767 < num && ParameterDirection.Input == Direction)
				{
					num = ValueSize(GetCoercedValueInternal());
				}
				return num;
			}
		}

		internal int CommandSetResult
		{
			get
			{
				return _commandSetResult;
			}
			set
			{
				_commandSetResult = value;
			}
		}

		public override DbType DbType
		{
			get
			{
				return GetMetaType().DbType;
			}
			set
			{
				if (_metaType == null || _metaType.DbType != value)
				{
					PropertyTypeChanging();
					_metaType = MetaType.GetMetaTypeForType(value);
				}
			}
		}

		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("OracleCategory_Data")]
		[ResDescription("OracleParameter_OracleType")]
		[DbProviderSpecificTypeProperty(true)]
		[DefaultValue(OracleType.VarChar)]
		public OracleType OracleType
		{
			get
			{
				return GetMetaType().OracleType;
			}
			set
			{
				MetaType metaType = _metaType;
				if (metaType == null || metaType.OracleType != value)
				{
					PropertyTypeChanging();
					_metaType = MetaType.GetMetaTypeForType(value);
				}
			}
		}

		[ResCategory("DataCategory_Data")]
		[ResDescription("DbParameter_ParameterName")]
		public override string ParameterName
		{
			get
			{
				string parameterName = _parameterName;
				if (parameterName == null)
				{
					return System.Data.Common.ADP.StrEmpty;
				}
				return parameterName;
			}
			set
			{
				if (_parameterName != value)
				{
					_parameterName = value;
				}
			}
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		[Browsable(false)]
		[Obsolete("Precision has been deprecated.  Use the Math classes to explicitly set the precision of a decimal.  http://go.microsoft.com/fwlink/?linkid=14202")]
		public byte Precision
		{
			get
			{
				return PrecisionInternal;
			}
			set
			{
				PrecisionInternal = value;
			}
		}

		private byte PrecisionInternal
		{
			get
			{
				return _precision;
			}
			set
			{
				if (_precision != value)
				{
					_precision = value;
				}
			}
		}

		[Obsolete("Scale has been deprecated.  Use the Math classes to explicitly set the scale of a decimal.  http://go.microsoft.com/fwlink/?linkid=14202")]
		[Browsable(false)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		public byte Scale
		{
			get
			{
				return ScaleInternal;
			}
			set
			{
				ScaleInternal = value;
			}
		}

		private byte ScaleInternal
		{
			get
			{
				return _scale;
			}
			set
			{
				if (_scale != value || !_hasScale)
				{
					_scale = value;
					_hasScale = true;
				}
			}
		}

		[ResDescription("DbParameter_Value")]
		[ResCategory("DataCategory_Data")]
		[RefreshProperties(RefreshProperties.All)]
		[TypeConverter(typeof(StringConverter))]
		public override object Value
		{
			get
			{
				return _value;
			}
			set
			{
				_coercedValue = null;
				_value = value;
			}
		}

		private object CoercedValue
		{
			get
			{
				return _coercedValue;
			}
			set
			{
				_coercedValue = value;
			}
		}

		[ResDescription("DbParameter_Direction")]
		[RefreshProperties(RefreshProperties.All)]
		[ResCategory("DataCategory_Data")]
		public override ParameterDirection Direction
		{
			get
			{
				ParameterDirection direction = _direction;
				if (direction == (ParameterDirection)0)
				{
					return ParameterDirection.Input;
				}
				return direction;
			}
			set
			{
				if (_direction != value)
				{
					switch (value)
					{
					case ParameterDirection.Input:
					case ParameterDirection.Output:
					case ParameterDirection.InputOutput:
					case ParameterDirection.ReturnValue:
						PropertyChanging();
						_direction = value;
						break;
					default:
						throw System.Data.Common.ADP.InvalidParameterDirection(value);
					}
				}
			}
		}

		public override bool IsNullable
		{
			get
			{
				return _isNullable;
			}
			set
			{
				_isNullable = value;
			}
		}

		[Browsable(false)]
		[EditorBrowsable(EditorBrowsableState.Advanced)]
		[ResCategory("DataCategory_Data")]
		[ResDescription("DbParameter_Offset")]
		public int Offset
		{
			get
			{
				return _offset;
			}
			set
			{
				if (value < 0)
				{
					throw System.Data.Common.ADP.InvalidOffsetValue(value);
				}
				_offset = value;
			}
		}

		[ResCategory("DataCategory_Data")]
		[ResDescription("DbParameter_Size")]
		public override int Size
		{
			get
			{
				int num = _size;
				if (num == 0)
				{
					num = ValueSize(Value);
				}
				return num;
			}
			set
			{
				if (_size != value)
				{
					if (value < -1)
					{
						throw System.Data.Common.ADP.InvalidSizeValue(value);
					}
					PropertyChanging();
					_size = value;
				}
			}
		}

		[ResDescription("DbParameter_SourceColumn")]
		[ResCategory("DataCategory_Update")]
		public override string SourceColumn
		{
			get
			{
				string sourceColumn = _sourceColumn;
				if (sourceColumn == null)
				{
					return System.Data.Common.ADP.StrEmpty;
				}
				return sourceColumn;
			}
			set
			{
				_sourceColumn = value;
			}
		}

		public override bool SourceColumnNullMapping
		{
			get
			{
				return _sourceColumnNullMapping;
			}
			set
			{
				_sourceColumnNullMapping = value;
			}
		}

		[ResCategory("DataCategory_Update")]
		[ResDescription("DbParameter_SourceVersion")]
		public override DataRowVersion SourceVersion
		{
			get
			{
				DataRowVersion sourceVersion = _sourceVersion;
				if (sourceVersion == (DataRowVersion)0)
				{
					return DataRowVersion.Current;
				}
				return sourceVersion;
			}
			set
			{
				switch (value)
				{
				case DataRowVersion.Original:
				case DataRowVersion.Current:
				case DataRowVersion.Proposed:
				case DataRowVersion.Default:
					_sourceVersion = value;
					break;
				default:
					throw System.Data.Common.ADP.InvalidDataRowVersion(value);
				}
			}
		}

		public OracleParameter()
		{
		}

		public OracleParameter(string name, object value)
		{
			ParameterName = name;
			Value = value;
		}

		public OracleParameter(string name, OracleType oracleType)
			: this()
		{
			ParameterName = name;
			OracleType = oracleType;
		}

		public OracleParameter(string name, OracleType oracleType, int size)
			: this()
		{
			ParameterName = name;
			OracleType = oracleType;
			Size = size;
		}

		public OracleParameter(string name, OracleType oracleType, int size, string srcColumn)
			: this()
		{
			ParameterName = name;
			OracleType = oracleType;
			Size = size;
			SourceColumn = srcColumn;
		}

		public OracleParameter(string name, OracleType oracleType, int size, ParameterDirection direction, bool isNullable, byte precision, byte scale, string srcColumn, DataRowVersion srcVersion, object value)
			: this()
		{
			ParameterName = name;
			OracleType = oracleType;
			Size = size;
			Direction = direction;
			IsNullable = isNullable;
			PrecisionInternal = precision;
			ScaleInternal = scale;
			SourceColumn = srcColumn;
			SourceVersion = srcVersion;
			Value = value;
		}

		public OracleParameter(string name, OracleType oracleType, int size, ParameterDirection direction, string sourceColumn, DataRowVersion sourceVersion, bool sourceColumnNullMapping, object value)
			: this()
		{
			ParameterName = name;
			OracleType = oracleType;
			Size = size;
			Direction = direction;
			SourceColumn = sourceColumn;
			SourceVersion = sourceVersion;
			SourceColumnNullMapping = sourceColumnNullMapping;
			Value = value;
		}

		public override void ResetDbType()
		{
			ResetOracleType();
		}

		public void ResetOracleType()
		{
			if (_metaType != null)
			{
				PropertyTypeChanging();
				_metaType = null;
			}
		}

		private bool ShouldSerializePrecision()
		{
			return 0 != _precision;
		}

		private bool ShouldSerializeScale()
		{
			return _hasScale;
		}

		private static object CoerceValue(object value, MetaType destinationType)
		{
			//Discarded unreachable code: IL_00cd
			if (value != null && !Convert.IsDBNull(value) && typeof(object) != destinationType.BaseType)
			{
				Type type = value.GetType();
				if (type != destinationType.BaseType && type != destinationType.NoConvertType)
				{
					try
					{
						if (typeof(string) == destinationType.BaseType && typeof(char[]) == type)
						{
							value = new string((char[])value);
							return value;
						}
						if (DbType.Currency == destinationType.DbType && typeof(string) == type)
						{
							value = decimal.Parse((string)value, NumberStyles.Currency, null);
							return value;
						}
						value = Convert.ChangeType(value, destinationType.BaseType, null);
						return value;
					}
					catch (Exception ex)
					{
						if (!System.Data.Common.ADP.IsCatchableExceptionType(ex))
						{
							throw;
						}
						throw System.Data.Common.ADP.ParameterConversionFailed(value, destinationType.BaseType, ex);
					}
				}
			}
			return value;
		}

		object ICloneable.Clone()
		{
			return new OracleParameter(this);
		}

		private void CloneHelper(OracleParameter destination)
		{
			CloneHelperCore(destination);
			destination._metaType = _metaType;
			destination._parameterName = _parameterName;
			destination._precision = _precision;
			destination._scale = _scale;
			destination._hasScale = _hasScale;
		}

		internal int GetActualSize()
		{
			if (!ShouldSerializeSize())
			{
				return ValueSize(CoercedValue);
			}
			return Size;
		}

		private MetaType GetMetaType()
		{
			return GetMetaType(Value);
		}

		internal MetaType GetMetaType(object value)
		{
			MetaType metaType = _metaType;
			if (metaType == null)
			{
				metaType = (_metaType = ((value == null || Convert.IsDBNull(value)) ? MetaType.GetDefaultMetaType() : MetaType.GetMetaTypeForObject(value)));
			}
			return metaType;
		}

		internal object GetCoercedValueInternal()
		{
			object obj = CoercedValue;
			if (obj == null)
			{
				obj = (CoercedValue = CoerceValue(Value, _coercedMetaType));
			}
			return obj;
		}

		private void PropertyChanging()
		{
		}

		private void PropertyTypeChanging()
		{
			PropertyChanging();
			CoercedValue = null;
		}

		internal void SetCoercedValueInternal(object value, MetaType metaType)
		{
			_coercedMetaType = metaType;
			CoercedValue = CoerceValue(value, metaType);
		}

		private bool ShouldSerializeOracleType()
		{
			return null != _metaType;
		}

		private int ValueSize(object value)
		{
			if (value is OracleString oracleString)
			{
				return oracleString.Length;
			}
			if (value is string)
			{
				return ((string)value).Length;
			}
			if (value is char[])
			{
				return ((char[])value).Length;
			}
			if (value is OracleBinary oracleBinary)
			{
				return oracleBinary.Length;
			}
			return ValueSizeCore(value);
		}

		private OracleParameter(OracleParameter source)
			: this()
		{
			System.Data.Common.ADP.CheckArgumentNull(source, "source");
			source.CloneHelper(this);
			if (_value is ICloneable cloneable)
			{
				_value = cloneable.Clone();
			}
		}

		private void ResetSize()
		{
			if (_size != 0)
			{
				PropertyChanging();
				_size = 0;
			}
		}

		private bool ShouldSerializeSize()
		{
			return 0 != _size;
		}

		private void CloneHelperCore(OracleParameter destination)
		{
			destination._value = _value;
			destination._direction = _direction;
			destination._size = _size;
			destination._offset = _offset;
			destination._sourceColumn = _sourceColumn;
			destination._sourceVersion = _sourceVersion;
			destination._sourceColumnNullMapping = _sourceColumnNullMapping;
			destination._isNullable = _isNullable;
		}

		internal void CopyTo(DbParameter destination)
		{
			System.Data.Common.ADP.CheckArgumentNull(destination, "destination");
			CloneHelper((OracleParameter)destination);
		}

		internal object CompareExchangeParent(object value, object comparand)
		{
			object parent = _parent;
			if (comparand == parent)
			{
				_parent = value;
			}
			return parent;
		}

		internal void ResetParent()
		{
			_parent = null;
		}

		public override string ToString()
		{
			return ParameterName;
		}

		private byte ValuePrecisionCore(object value)
		{
			if (value is decimal)
			{
				return ((SqlDecimal)(decimal)value).Precision;
			}
			return 0;
		}

		private byte ValueScaleCore(object value)
		{
			if (value is decimal)
			{
				return (byte)((decimal.GetBits((decimal)value)[3] & 0xFF0000) >> 16);
			}
			return 0;
		}

		private int ValueSizeCore(object value)
		{
			if (!System.Data.Common.ADP.IsNull(value))
			{
				if (value is string text)
				{
					return text.Length;
				}
				if (value is byte[] array)
				{
					return array.Length;
				}
				if (value is char[] array2)
				{
					return array2.Length;
				}
				if (value is byte || value is char)
				{
					return 1;
				}
			}
			return 0;
		}
	}
	internal sealed class OracleParameterBinding
	{
		private OracleCommand _command;

		private OracleParameter _parameter;

		private object _coercedValue;

		private MetaType _bindingMetaType;

		private OciBindHandle _bindHandle;

		private int _bindSize;

		private int _bufferLength;

		private int _indicatorOffset;

		private int _lengthOffset;

		private int _valueOffset;

		private bool _bindAsUCS2;

		private bool _freeTemporaryLob;

		private OciStatementHandle _descriptor;

		private OciLobLocator _locator;

		private OciDateTimeDescriptor _dateTimeDescriptor;

		internal OracleParameter Parameter => _parameter;

		internal OracleParameterBinding(OracleCommand command, OracleParameter parameter)
		{
			_command = command;
			_parameter = parameter;
		}

		internal void Bind(OciStatementHandle statementHandle, NativeBuffer parameterBuffer, OracleConnection connection, ref bool mustRelease, ref SafeHandle handleToBind)
		{
			if (!IsDirection(Parameter, ParameterDirection.Output) && Parameter.Value == null)
			{
				return;
			}
			string parameterName = Parameter.ParameterName;
			OciErrorHandle errorHandle = connection.ErrorHandle;
			OciServiceContextHandle serviceContextHandle = connection.ServiceContextHandle;
			int num = 0;
			OCI.INDICATOR iNDICATOR = OCI.INDICATOR.OK;
			OCI.DATATYPE ociType = _bindingMetaType.OciType;
			IntPtr indp = parameterBuffer.DangerousGetDataPtr(_indicatorOffset);
			IntPtr alenp = parameterBuffer.DangerousGetDataPtr(_lengthOffset);
			IntPtr valuep = parameterBuffer.DangerousGetDataPtr(_valueOffset);
			OciHandle.SafeDispose(ref _dateTimeDescriptor);
			if (IsDirection(Parameter, ParameterDirection.Input))
			{
				if (System.Data.Common.ADP.IsNull(_coercedValue))
				{
					iNDICATOR = OCI.INDICATOR.ISNULL;
					switch (ociType)
					{
					case OCI.DATATYPE.INT_TIMESTAMP:
					case OCI.DATATYPE.INT_TIMESTAMP_TZ:
					case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
						_dateTimeDescriptor = OracleDateTime.CreateEmptyDescriptor(ociType, connection);
						handleToBind = _dateTimeDescriptor;
						break;
					}
				}
				else
				{
					num = PutOracleValue(_coercedValue, parameterBuffer, _valueOffset, _bindingMetaType, connection, ref handleToBind);
				}
			}
			else
			{
				num = ((!_bindingMetaType.IsVariableLength) ? _bufferLength : 0);
				OciLobLocator.SafeDispose(ref _locator);
				OciHandle.SafeDispose(ref _descriptor);
				switch (ociType)
				{
				case OCI.DATATYPE.CLOB:
				case OCI.DATATYPE.BLOB:
				case OCI.DATATYPE.BFILE:
					_locator = new OciLobLocator(connection, _bindingMetaType.OracleType);
					handleToBind = _locator.Descriptor;
					break;
				case OCI.DATATYPE.RSET:
					_descriptor = new OciStatementHandle(serviceContextHandle);
					handleToBind = _descriptor;
					break;
				case OCI.DATATYPE.INT_TIMESTAMP:
				case OCI.DATATYPE.INT_TIMESTAMP_TZ:
				case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
					_dateTimeDescriptor = OracleDateTime.CreateEmptyDescriptor(ociType, connection);
					handleToBind = _dateTimeDescriptor;
					break;
				}
			}
			if (handleToBind != null)
			{
				handleToBind.DangerousAddRef(ref mustRelease);
				parameterBuffer.WriteIntPtr(_valueOffset, handleToBind.DangerousGetHandle());
			}
			parameterBuffer.WriteInt16(_indicatorOffset, (short)iNDICATOR);
			if (OCI.DATATYPE.LONGVARCHAR == ociType || OCI.DATATYPE.LONGVARRAW == ociType)
			{
				alenp = IntPtr.Zero;
			}
			else if (_bindAsUCS2)
			{
				parameterBuffer.WriteInt32(_lengthOffset, num / System.Data.Common.ADP.CharSize);
			}
			else
			{
				parameterBuffer.WriteInt32(_lengthOffset, num);
			}
			int num2 = ((!IsDirection(Parameter, ParameterDirection.Output)) ? num : _bufferLength);
			OCI.DATATYPE dty = ociType;
			switch (ociType)
			{
			case OCI.DATATYPE.INT_TIMESTAMP:
				dty = OCI.DATATYPE.TIMESTAMP;
				break;
			case OCI.DATATYPE.INT_TIMESTAMP_TZ:
				dty = OCI.DATATYPE.TIMESTAMP_TZ;
				break;
			case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
				dty = OCI.DATATYPE.TIMESTAMP_LTZ;
				break;
			}
			IntPtr bindpp;
			int num3 = TracedNativeMethods.OCIBindByName(statementHandle, out bindpp, errorHandle, parameterName, parameterName.Length, valuep, num2, dty, indp, alenp, OCI.MODE.OCI_DEFAULT);
			if (num3 != 0)
			{
				_command.Connection.CheckError(errorHandle, num3);
			}
			_bindHandle = new OciBindHandle(statementHandle, bindpp);
			if (_bindingMetaType.IsCharacterType)
			{
				if (OCI.ClientVersionAtLeastOracle9i && IsDirection(Parameter, ParameterDirection.Output))
				{
					_bindHandle.SetAttribute(OCI.ATTR.OCI_ATTR_MAXCHAR_SIZE, _bindSize, errorHandle);
				}
				if (num2 > _bindingMetaType.MaxBindSize / System.Data.Common.ADP.CharSize || (!OCI.ClientVersionAtLeastOracle9i && _bindingMetaType.UsesNationalCharacterSet))
				{
					_bindHandle.SetAttribute(OCI.ATTR.OCI_ATTR_MAXDATA_SIZE, _bindingMetaType.MaxBindSize, errorHandle);
				}
				if (_bindingMetaType.UsesNationalCharacterSet)
				{
					_bindHandle.SetAttribute(OCI.ATTR.OCI_ATTR_CHARSET_FORM, 2, errorHandle);
				}
				if (_bindAsUCS2)
				{
					_bindHandle.SetAttribute(OCI.ATTR.OCI_ATTR_CHARSET_ID, 1000, errorHandle);
				}
			}
			GC.KeepAlive(parameterBuffer);
		}

		private OracleLob CreateTemporaryLobForValue(OracleConnection connection, OracleType oracleType, object value)
		{
			switch (oracleType)
			{
			case OracleType.BFile:
				oracleType = OracleType.Blob;
				break;
			default:
				throw System.Data.Common.ADP.InvalidLobType(oracleType);
			case OracleType.Blob:
			case OracleType.Clob:
			case OracleType.NClob:
				break;
			}
			OracleLob oracleLob = new OracleLob(connection, oracleType);
			if (value is byte[] array)
			{
				oracleLob.Write(array, 0, array.Length);
			}
			else
			{
				Encoding encoding = new UnicodeEncoding(bigEndian: false, byteOrderMark: false);
				oracleLob.Seek(0L, SeekOrigin.Begin);
				StreamWriter streamWriter = new StreamWriter(oracleLob, encoding);
				streamWriter.Write(value);
				streamWriter.Flush();
			}
			return oracleLob;
		}

		internal object GetOutputValue(NativeBuffer parameterBuffer, OracleConnection connection, bool needCLSType)
		{
			if (parameterBuffer.ReadInt16(_indicatorOffset) == -1)
			{
				return DBNull.Value;
			}
			switch (_bindingMetaType.OciType)
			{
			case OCI.DATATYPE.INTEGER:
			case OCI.DATATYPE.FLOAT:
			case OCI.DATATYPE.UNSIGNEDINT:
				return parameterBuffer.PtrToStructure(_valueOffset, _bindingMetaType.BaseType);
			case OCI.DATATYPE.BFILE:
				return new OracleBFile(_locator);
			case OCI.DATATYPE.RAW:
			case OCI.DATATYPE.LONGRAW:
			case OCI.DATATYPE.LONGVARRAW:
			{
				object obj = new OracleBinary(parameterBuffer, _valueOffset, _lengthOffset, _bindingMetaType);
				if (needCLSType)
				{
					object value2 = ((OracleBinary)obj).Value;
					obj = value2;
				}
				return obj;
			}
			case OCI.DATATYPE.RSET:
				return new OracleDataReader(connection, _descriptor);
			case OCI.DATATYPE.DATE:
			{
				object obj = new OracleDateTime(parameterBuffer, _valueOffset, _lengthOffset, _bindingMetaType, connection);
				if (needCLSType)
				{
					object obj3 = ((OracleDateTime)obj).Value;
					obj = obj3;
				}
				return obj;
			}
			case OCI.DATATYPE.INT_TIMESTAMP:
			case OCI.DATATYPE.INT_TIMESTAMP_TZ:
			case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
			{
				object obj = new OracleDateTime(_dateTimeDescriptor, _bindingMetaType, connection);
				if (needCLSType)
				{
					object obj5 = ((OracleDateTime)obj).Value;
					obj = obj5;
				}
				return obj;
			}
			case OCI.DATATYPE.CLOB:
			case OCI.DATATYPE.BLOB:
				return new OracleLob(_locator);
			case OCI.DATATYPE.INT_INTERVAL_YM:
			{
				object obj = new OracleMonthSpan(parameterBuffer, _valueOffset);
				if (needCLSType)
				{
					object obj6 = ((OracleMonthSpan)obj).Value;
					obj = obj6;
				}
				return obj;
			}
			case OCI.DATATYPE.VARNUM:
			{
				object obj = new OracleNumber(parameterBuffer, _valueOffset);
				if (needCLSType)
				{
					object obj4 = ((OracleNumber)obj).Value;
					obj = obj4;
				}
				return obj;
			}
			case OCI.DATATYPE.VARCHAR2:
			case OCI.DATATYPE.LONG:
			case OCI.DATATYPE.LONGVARCHAR:
			case OCI.DATATYPE.CHAR:
			{
				object obj = new OracleString(parameterBuffer, _valueOffset, _lengthOffset, _bindingMetaType, connection, _bindAsUCS2, outputParameterBinding: true);
				int size = _parameter.Size;
				if (size != 0 && size < ((OracleString)obj).Length)
				{
					string text = ((OracleString)obj).Value.Substring(0, size);
					obj = ((!needCLSType) ? ((object)new OracleString(text)) : text);
				}
				else if (needCLSType)
				{
					object value = ((OracleString)obj).Value;
					obj = value;
				}
				return obj;
			}
			case OCI.DATATYPE.INT_INTERVAL_DS:
			{
				object obj = new OracleTimeSpan(parameterBuffer, _valueOffset);
				if (needCLSType)
				{
					object obj2 = ((OracleTimeSpan)obj).Value;
					obj = obj2;
				}
				return obj;
			}
			default:
				throw System.Data.Common.ADP.TypeNotSupported(_bindingMetaType.OciType);
			}
		}

		internal void Dispose()
		{
			OciHandle.SafeDispose(ref _bindHandle);
			if (_freeTemporaryLob && _coercedValue is OracleLob oracleLob)
			{
				oracleLob.Free();
			}
		}

		internal static bool IsDirection(IDataParameter value, ParameterDirection condition)
		{
			return condition == (condition & value.Direction);
		}

		private bool IsEmpty(object value)
		{
			bool result = false;
			if (value is string)
			{
				result = 0 == ((string)value).Length;
			}
			if (value is OracleString)
			{
				result = 0 == ((OracleString)value).Length;
			}
			if (value is char[])
			{
				result = 0 == ((char[])value).Length;
			}
			if (value is byte[])
			{
				result = 0 == ((byte[])value).Length;
			}
			if (value is OracleBinary)
			{
				result = 0 == ((OracleBinary)value).Length;
			}
			return result;
		}

		internal void PostExecute(NativeBuffer parameterBuffer, OracleConnection connection)
		{
			OracleParameter parameter = Parameter;
			if (!IsDirection(parameter, ParameterDirection.Output) && !IsDirection(parameter, ParameterDirection.ReturnValue))
			{
				return;
			}
			bool needCLSType = true;
			if (IsDirection(parameter, ParameterDirection.Input))
			{
				object value = parameter.Value;
				if (value is INullable)
				{
					needCLSType = false;
				}
			}
			parameter.Value = GetOutputValue(parameterBuffer, connection, needCLSType);
		}

		internal void PrepareForBind(OracleConnection connection, ref int offset)
		{
			OracleParameter parameter = Parameter;
			bool flag = false;
			object value = parameter.Value;
			if (!IsDirection(parameter, ParameterDirection.Output) && value == null)
			{
				_bufferLength = 0;
				return;
			}
			_bindingMetaType = parameter.GetMetaType(value);
			if (OCI.DATATYPE.RSET == _bindingMetaType.OciType && System.Data.Common.ADP.IsDirection(parameter.Direction, ParameterDirection.Input))
			{
				throw System.Data.Common.ADP.InputRefCursorNotSupported(parameter.ParameterName);
			}
			parameter.SetCoercedValueInternal(value, _bindingMetaType);
			_coercedValue = parameter.GetCoercedValueInternal();
			switch (_bindingMetaType.OciType)
			{
			case OCI.DATATYPE.CLOB:
			case OCI.DATATYPE.BLOB:
			case OCI.DATATYPE.BFILE:
				if (!System.Data.Common.ADP.IsNull(_coercedValue) && !(_coercedValue is OracleLob) && !(_coercedValue is OracleBFile))
				{
					if (connection.HasTransaction)
					{
						_freeTemporaryLob = true;
						_coercedValue = CreateTemporaryLobForValue(connection, _bindingMetaType.OracleType, _coercedValue);
					}
					else
					{
						_bindingMetaType = MetaType.GetMetaTypeForType(_bindingMetaType.DbType);
						flag = true;
					}
				}
				break;
			}
			_bindSize = _bindingMetaType.BindSize;
			if ((IsDirection(parameter, ParameterDirection.Output) && _bindingMetaType.IsVariableLength) || (_bindSize == 0 && !System.Data.Common.ADP.IsNull(_coercedValue)) || _bindSize > 32767)
			{
				int bindSize = parameter.BindSize;
				if (bindSize != 0)
				{
					_bindSize = bindSize;
				}
				if ((_bindSize == 0 || int.MaxValue == _bindSize) && !IsEmpty(_coercedValue))
				{
					throw System.Data.Common.ADP.ParameterSizeIsMissing(parameter.ParameterName, _bindingMetaType.BaseType);
				}
			}
			_bufferLength = _bindSize;
			if (_bindingMetaType.IsCharacterType && connection.ServerVersionAtLeastOracle8)
			{
				_bindAsUCS2 = true;
				_bufferLength *= System.Data.Common.ADP.CharSize;
			}
			if (!System.Data.Common.ADP.IsNull(_coercedValue) && (_bindSize > _bindingMetaType.MaxBindSize || flag))
			{
				switch (_bindingMetaType.OciType)
				{
				case OCI.DATATYPE.VARCHAR2:
				case OCI.DATATYPE.LONG:
				case OCI.DATATYPE.CHAR:
					_bindingMetaType = (_bindingMetaType.UsesNationalCharacterSet ? MetaType.oracleTypeMetaType_LONGNVARCHAR : MetaType.oracleTypeMetaType_LONGVARCHAR);
					break;
				case OCI.DATATYPE.RAW:
				case OCI.DATATYPE.LONGRAW:
					_bindingMetaType = MetaType.oracleTypeMetaType_LONGVARRAW;
					break;
				}
				_bufferLength += 4;
			}
			if (0 > _bufferLength)
			{
				throw System.Data.Common.ADP.ParameterSizeIsTooLarge(parameter.ParameterName);
			}
			_indicatorOffset = offset;
			offset += IntPtr.Size;
			_lengthOffset = offset;
			offset += IntPtr.Size;
			_valueOffset = offset;
			offset += _bufferLength;
			offset = (offset + (IntPtr.Size - 1)) & ~(IntPtr.Size - 1);
		}

		internal int PutOracleValue(object value, NativeBuffer buffer, int bufferOffset, MetaType metaType, OracleConnection connection, ref SafeHandle handleToBind)
		{
			handleToBind = null;
			OCI.DATATYPE ociType = metaType.OciType;
			OracleParameter parameter = Parameter;
			int result;
			switch (ociType)
			{
			case OCI.DATATYPE.INTEGER:
			case OCI.DATATYPE.FLOAT:
			case OCI.DATATYPE.UNSIGNEDINT:
				buffer.StructureToPtr(bufferOffset, value);
				result = metaType.BindSize;
				break;
			case OCI.DATATYPE.RAW:
			case OCI.DATATYPE.LONGRAW:
			case OCI.DATATYPE.LONGVARRAW:
			{
				byte[] array = ((!(_coercedValue is OracleBinary)) ? ((byte[])_coercedValue) : ((OracleBinary)_coercedValue).Value);
				int num = array.Length - parameter.Offset;
				int actualSize = parameter.GetActualSize();
				if (actualSize != 0)
				{
					num = Math.Min(num, actualSize);
				}
				if (OCI.DATATYPE.LONGVARRAW == ociType)
				{
					buffer.WriteInt32(bufferOffset, num);
					bufferOffset = checked(bufferOffset + 4);
					result = num + 4;
				}
				else
				{
					result = num;
				}
				buffer.WriteBytes(bufferOffset, array, parameter.Offset, num);
				break;
			}
			case OCI.DATATYPE.DATE:
				result = OracleDateTime.MarshalDateToNative(value, buffer, bufferOffset, ociType, connection);
				break;
			case OCI.DATATYPE.INT_TIMESTAMP_TZ:
				if (value is OracleDateTime oracleDateTime && !oracleDateTime.HasTimeZoneInfo)
				{
					throw System.Data.Common.ADP.UnsupportedOracleDateTimeBinding(OracleType.TimestampWithTZ);
				}
				_dateTimeDescriptor = OracleDateTime.CreateDescriptor(ociType, connection, value);
				handleToBind = _dateTimeDescriptor;
				result = IntPtr.Size;
				break;
			case OCI.DATATYPE.INT_TIMESTAMP:
			case OCI.DATATYPE.INT_TIMESTAMP_LTZ:
				if (value is OracleDateTime oracleDateTime2 && !oracleDateTime2.HasTimeInfo)
				{
					throw System.Data.Common.ADP.UnsupportedOracleDateTimeBinding(metaType.OracleType);
				}
				_dateTimeDescriptor = OracleDateTime.CreateDescriptor(ociType, connection, value);
				handleToBind = _dateTimeDescriptor;
				result = IntPtr.Size;
				break;
			case OCI.DATATYPE.BFILE:
				if (!(value is OracleBFile))
				{
					throw System.Data.Common.ADP.BadBindValueType(value.GetType(), metaType.OracleType);
				}
				handleToBind = ((OracleBFile)value).Descriptor;
				result = IntPtr.Size;
				break;
			case OCI.DATATYPE.CLOB:
			case OCI.DATATYPE.BLOB:
				if (!(value is OracleLob))
				{
					throw System.Data.Common.ADP.BadBindValueType(value.GetType(), metaType.OracleType);
				}
				handleToBind = ((OracleLob)value).Descriptor;
				result = IntPtr.Size;
				break;
			case OCI.DATATYPE.INT_INTERVAL_YM:
				result = OracleMonthSpan.MarshalToNative(value, buffer, bufferOffset);
				break;
			case OCI.DATATYPE.VARNUM:
				result = OracleNumber.MarshalToNative(value, buffer, bufferOffset, connection);
				break;
			case OCI.DATATYPE.VARCHAR2:
			case OCI.DATATYPE.LONG:
			case OCI.DATATYPE.LONGVARCHAR:
			case OCI.DATATYPE.CHAR:
				result = OracleString.MarshalToNative(value, parameter.Offset, parameter.GetActualSize(), buffer, bufferOffset, ociType, _bindAsUCS2);
				break;
			case OCI.DATATYPE.INT_INTERVAL_DS:
				result = OracleTimeSpan.MarshalToNative(value, buffer, bufferOffset);
				break;
			default:
				throw System.Data.Common.ADP.TypeNotSupported(ociType);
			}
			return result;
		}
	}
	[Editor("Microsoft.VSDesigner.Data.Design.DBParametersEditor, Microsoft.VSDesigner, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
	[ListBindable(false)]
	public sealed class OracleParameterCollection : DbParameterCollection
	{
		private static Type ItemType = typeof(OracleParameter);

		private List<OracleParameter> _items;

		public new OracleParameter this[int index]
		{
			get
			{
				return (OracleParameter)GetParameter(index);
			}
			set
			{
				SetParameter(index, value);
			}
		}

		public new OracleParameter this[string parameterName]
		{
			get
			{
				int index = IndexOf(parameterName);
				return (OracleParameter)GetParameter(index);
			}
			set
			{
				int index = IndexOf(parameterName);
				SetParameter(index, value);
			}
		}

		public override int Count
		{
			get
			{
				if (_items == null)
				{
					return 0;
				}
				return _items.Count;
			}
		}

		private List<OracleParameter> InnerList
		{
			get
			{
				List<OracleParameter> list = _items;
				if (list == null)
				{
					list = (_items = new List<OracleParameter>());
				}
				return list;
			}
		}

		public override bool IsFixedSize => ((IList)InnerList).IsFixedSize;

		public override bool IsReadOnly => ((IList)InnerList).IsReadOnly;

		public override bool IsSynchronized => ((ICollection)InnerList).IsSynchronized;

		public override object SyncRoot => ((ICollection)InnerList).SyncRoot;

		public OracleParameter Add(OracleParameter value)
		{
			Add((object)value);
			return value;
		}

		[Obsolete("Add(String parameterName, Object value) has been deprecated.  Use AddWithValue(String parameterName, Object value).  http://go.microsoft.com/fwlink/?linkid=14202", false)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		public OracleParameter Add(string parameterName, object value)
		{
			OracleParameter value2 = new OracleParameter(parameterName, value);
			return Add(value2);
		}

		public OracleParameter Add(string parameterName, OracleType dataType)
		{
			OracleParameter value = new OracleParameter(parameterName, dataType);
			return Add(value);
		}

		public OracleParameter Add(string parameterName, OracleType dataType, int size)
		{
			OracleParameter value = new OracleParameter(parameterName, dataType, size);
			return Add(value);
		}

		public OracleParameter Add(string parameterName, OracleType dataType, int size, string srcColumn)
		{
			OracleParameter value = new OracleParameter(parameterName, dataType, size, srcColumn);
			return Add(value);
		}

		public void AddRange(OracleParameter[] values)
		{
			AddRange((Array)values);
		}

		public OracleParameter AddWithValue(string parameterName, object value)
		{
			OracleParameter value2 = new OracleParameter(parameterName, value);
			return Add(value2);
		}

		public override bool Contains(string parameterName)
		{
			return -1 != IndexOf(parameterName);
		}

		public bool Contains(OracleParameter value)
		{
			return -1 != IndexOf(value);
		}

		public void CopyTo(OracleParameter[] array, int index)
		{
			CopyTo((Array)array, index);
		}

		public int IndexOf(OracleParameter value)
		{
			return IndexOf((object)value);
		}

		public void Insert(int index, OracleParameter value)
		{
			Insert(index, (object)value);
		}

		private void OnChange()
		{
		}

		public void Remove(OracleParameter value)
		{
			Remove((object)value);
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public override int Add(object value)
		{
			OnChange();
			ValidateType(value);
			Validate(-1, value);
			InnerList.Add((OracleParameter)value);
			return Count - 1;
		}

		public override void AddRange(Array values)
		{
			OnChange();
			if (values == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("values");
			}
			foreach (object value in values)
			{
				ValidateType(value);
			}
			foreach (OracleParameter value2 in values)
			{
				Validate(-1, value2);
				InnerList.Add(value2);
			}
		}

		private int CheckName(string parameterName)
		{
			int num = IndexOf(parameterName);
			if (num < 0)
			{
				throw System.Data.Common.ADP.ParametersSourceIndex(parameterName, this, ItemType);
			}
			return num;
		}

		public override void Clear()
		{
			OnChange();
			List<OracleParameter> innerList = InnerList;
			if (innerList == null)
			{
				return;
			}
			foreach (OracleParameter item in innerList)
			{
				item.ResetParent();
			}
			innerList.Clear();
		}

		public override bool Contains(object value)
		{
			return -1 != IndexOf(value);
		}

		public override void CopyTo(Array array, int index)
		{
			((ICollection)InnerList).CopyTo(array, index);
		}

		public override IEnumerator GetEnumerator()
		{
			return ((IEnumerable)InnerList).GetEnumerator();
		}

		protected override DbParameter GetParameter(int index)
		{
			RangeCheck(index);
			return InnerList[index];
		}

		protected override DbParameter GetParameter(string parameterName)
		{
			int num = IndexOf(parameterName);
			if (num < 0)
			{
				throw System.Data.Common.ADP.ParametersSourceIndex(parameterName, this, ItemType);
			}
			return InnerList[num];
		}

		private static int IndexOf(IEnumerable items, string parameterName)
		{
			if (items != null)
			{
				int num = 0;
				foreach (OracleParameter item in items)
				{
					if (System.Data.Common.ADP.SrcCompare(parameterName, item.ParameterName) == 0)
					{
						return num;
					}
					num++;
				}
				num = 0;
				foreach (OracleParameter item2 in items)
				{
					if (System.Data.Common.ADP.DstCompare(parameterName, item2.ParameterName) == 0)
					{
						return num;
					}
					num++;
				}
			}
			return -1;
		}

		public override int IndexOf(string parameterName)
		{
			return IndexOf(InnerList, parameterName);
		}

		public override int IndexOf(object value)
		{
			if (value != null)
			{
				ValidateType(value);
				List<OracleParameter> innerList = InnerList;
				if (innerList != null)
				{
					int count = innerList.Count;
					for (int i = 0; i < count; i++)
					{
						if (value == innerList[i])
						{
							return i;
						}
					}
				}
			}
			return -1;
		}

		public override void Insert(int index, object value)
		{
			OnChange();
			ValidateType(value);
			Validate(-1, (OracleParameter)value);
			InnerList.Insert(index, (OracleParameter)value);
		}

		private void RangeCheck(int index)
		{
			if (index < 0 || Count <= index)
			{
				throw System.Data.Common.ADP.ParametersMappingIndex(index, this);
			}
		}

		public override void Remove(object value)
		{
			OnChange();
			ValidateType(value);
			int num = IndexOf(value);
			if (-1 != num)
			{
				RemoveIndex(num);
			}
			else if (this != ((OracleParameter)value).CompareExchangeParent(null, this))
			{
				throw System.Data.Common.ADP.CollectionRemoveInvalidObject(ItemType, this);
			}
		}

		public override void RemoveAt(int index)
		{
			OnChange();
			RangeCheck(index);
			RemoveIndex(index);
		}

		public override void RemoveAt(string parameterName)
		{
			OnChange();
			int index = CheckName(parameterName);
			RemoveIndex(index);
		}

		private void RemoveIndex(int index)
		{
			List<OracleParameter> innerList = InnerList;
			OracleParameter oracleParameter = innerList[index];
			innerList.RemoveAt(index);
			oracleParameter.ResetParent();
		}

		private void Replace(int index, object newValue)
		{
			List<OracleParameter> innerList = InnerList;
			ValidateType(newValue);
			Validate(index, newValue);
			OracleParameter oracleParameter = innerList[index];
			innerList[index] = (OracleParameter)newValue;
			oracleParameter.ResetParent();
		}

		protected override void SetParameter(int index, DbParameter value)
		{
			OnChange();
			RangeCheck(index);
			Replace(index, value);
		}

		protected override void SetParameter(string parameterName, DbParameter value)
		{
			OnChange();
			int num = IndexOf(parameterName);
			if (num < 0)
			{
				throw System.Data.Common.ADP.ParametersSourceIndex(parameterName, this, ItemType);
			}
			Replace(num, value);
		}

		private void Validate(int index, object value)
		{
			if (value == null)
			{
				throw System.Data.Common.ADP.ParameterNull("value", this, ItemType);
			}
			object obj = ((OracleParameter)value).CompareExchangeParent(this, null);
			if (obj != null)
			{
				if (this != obj)
				{
					throw System.Data.Common.ADP.ParametersIsNotParent(ItemType, this);
				}
				if (index != IndexOf(value))
				{
					throw System.Data.Common.ADP.ParametersIsParent(ItemType, this);
				}
			}
			string parameterName = ((OracleParameter)value).ParameterName;
			if (parameterName.Length == 0)
			{
				index = 1;
				do
				{
					parameterName = "Parameter" + index.ToString(CultureInfo.CurrentCulture);
					index++;
				}
				while (-1 != IndexOf(parameterName));
				((OracleParameter)value).ParameterName = parameterName;
			}
		}

		private void ValidateType(object value)
		{
			if (value == null)
			{
				throw System.Data.Common.ADP.ParameterNull("value", this, ItemType);
			}
			if (!ItemType.IsInstanceOfType(value))
			{
				throw System.Data.Common.ADP.InvalidParameterType(this, ItemType, value);
			}
		}
	}
	[Serializable]
	public sealed class OraclePermission : CodeAccessPermission, IUnrestrictedPermission
	{
		private bool _isUnrestricted;

		private bool _allowBlankPassword;

		private NameValuePermission _keyvaluetree = NameValuePermission.Default;

		private ArrayList _keyvalues;

		public bool AllowBlankPassword
		{
			get
			{
				return _allowBlankPassword;
			}
			set
			{
				_allowBlankPassword = value;
			}
		}

		public OraclePermission(PermissionState state)
		{
			switch (state)
			{
			case PermissionState.Unrestricted:
				_isUnrestricted = true;
				break;
			case PermissionState.None:
				_isUnrestricted = false;
				break;
			default:
				throw System.Data.Common.ADP.InvalidPermissionState(state);
			}
		}

		private OraclePermission(OraclePermission permission)
		{
			if (permission == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("permissionAttribute");
			}
			CopyFrom(permission);
		}

		internal OraclePermission(OraclePermissionAttribute permissionAttribute)
		{
			if (permissionAttribute == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("permissionAttribute");
			}
			_isUnrestricted = permissionAttribute.Unrestricted;
			if (!_isUnrestricted)
			{
				_allowBlankPassword = permissionAttribute.AllowBlankPassword;
				if (permissionAttribute.ShouldSerializeConnectionString() || permissionAttribute.ShouldSerializeKeyRestrictions())
				{
					Add(permissionAttribute.ConnectionString, permissionAttribute.KeyRestrictions, permissionAttribute.KeyRestrictionBehavior);
				}
			}
		}

		internal OraclePermission(OracleConnectionString connectionOptions)
		{
			if (connectionOptions != null)
			{
				_allowBlankPassword = connectionOptions.HasBlankPassword;
				AddPermissionEntry(new DBConnectionString(connectionOptions));
			}
		}

		public void Add(string connectionString, string restrictions, KeyRestrictionBehavior behavior)
		{
			DBConnectionString entry = new DBConnectionString(connectionString, restrictions, behavior, OracleConnectionString.GetParseSynonyms(), useOdbcRules: false);
			AddPermissionEntry(entry);
		}

		public override IPermission Copy()
		{
			return new OraclePermission(this);
		}

		internal void AddPermissionEntry(DBConnectionString entry)
		{
			if (_keyvaluetree == null)
			{
				_keyvaluetree = new NameValuePermission();
			}
			if (_keyvalues == null)
			{
				_keyvalues = new ArrayList();
			}
			NameValuePermission.AddEntry(_keyvaluetree, _keyvalues, entry);
			_isUnrestricted = false;
		}

		private void Clear()
		{
			_keyvaluetree = null;
			_keyvalues = null;
		}

		private void CopyFrom(OraclePermission permission)
		{
			_isUnrestricted = permission.IsUnrestricted();
			if (_isUnrestricted)
			{
				return;
			}
			_allowBlankPassword = permission.AllowBlankPassword;
			if (permission._keyvalues != null)
			{
				_keyvalues = (ArrayList)permission._keyvalues.Clone();
				if (permission._keyvaluetree != null)
				{
					_keyvaluetree = permission._keyvaluetree.CopyNameValue();
				}
			}
		}

		public override IPermission Intersect(IPermission target)
		{
			if (target == null)
			{
				return null;
			}
			if (target.GetType() != GetType())
			{
				throw System.Data.Common.ADP.PermissionTypeMismatch();
			}
			if (IsUnrestricted())
			{
				return target.Copy();
			}
			OraclePermission oraclePermission = (OraclePermission)target;
			if (oraclePermission.IsUnrestricted())
			{
				return Copy();
			}
			OraclePermission oraclePermission2 = (OraclePermission)oraclePermission.Copy();
			oraclePermission2._allowBlankPassword &= AllowBlankPassword;
			if (_keyvalues != null && oraclePermission2._keyvalues != null)
			{
				oraclePermission2._keyvalues.Clear();
				oraclePermission2._keyvaluetree.Intersect(oraclePermission2._keyvalues, _keyvaluetree);
			}
			else
			{
				oraclePermission2._keyvalues = null;
				oraclePermission2._keyvaluetree = null;
			}
			if (oraclePermission2.IsEmpty())
			{
				oraclePermission2 = null;
			}
			return oraclePermission2;
		}

		private bool IsEmpty()
		{
			ArrayList keyvalues = _keyvalues;
			return !IsUnrestricted() && !AllowBlankPassword && (keyvalues == null || 0 == keyvalues.Count);
		}

		public override bool IsSubsetOf(IPermission target)
		{
			if (target == null)
			{
				return IsEmpty();
			}
			if (target.GetType() != GetType())
			{
				throw System.Data.Common.ADP.PermissionTypeMismatch();
			}
			OraclePermission oraclePermission = target as OraclePermission;
			bool flag = oraclePermission.IsUnrestricted();
			if (!flag && !IsUnrestricted() && (!AllowBlankPassword || oraclePermission.AllowBlankPassword) && (_keyvalues == null || oraclePermission._keyvaluetree != null))
			{
				flag = true;
				if (_keyvalues != null)
				{
					foreach (DBConnectionString keyvalue in _keyvalues)
					{
						if (!oraclePermission._keyvaluetree.CheckValueForKeyPermit(keyvalue))
						{
							return false;
						}
					}
					return flag;
				}
			}
			return flag;
		}

		public bool IsUnrestricted()
		{
			return _isUnrestricted;
		}

		public override IPermission Union(IPermission target)
		{
			if (target == null)
			{
				return Copy();
			}
			if (target.GetType() != GetType())
			{
				throw System.Data.Common.ADP.PermissionTypeMismatch();
			}
			if (IsUnrestricted())
			{
				return Copy();
			}
			OraclePermission oraclePermission = (OraclePermission)target.Copy();
			if (!oraclePermission.IsUnrestricted())
			{
				oraclePermission._allowBlankPassword |= AllowBlankPassword;
				if (_keyvalues != null)
				{
					foreach (DBConnectionString keyvalue in _keyvalues)
					{
						oraclePermission.AddPermissionEntry(keyvalue);
					}
				}
			}
			if (!oraclePermission.IsEmpty())
			{
				return oraclePermission;
			}
			return null;
		}

		private string DecodeXmlValue(string value)
		{
			if (value != null && 0 < value.Length)
			{
				value = value.Replace("&quot;", "\"");
				value = value.Replace("&apos;", "'");
				value = value.Replace("&lt;", "<");
				value = value.Replace("&gt;", ">");
				value = value.Replace("&amp;", "&");
			}
			return value;
		}

		private string EncodeXmlValue(string value)
		{
			if (value != null && 0 < value.Length)
			{
				value = value.Replace('\0', ' ');
				value = value.Trim();
				value = value.Replace("&", "&amp;");
				value = value.Replace(">", "&gt;");
				value = value.Replace("<", "&lt;");
				value = value.Replace("'", "&apos;");
				value = value.Replace("\"", "&quot;");
			}
			return value;
		}

		public override void FromXml(SecurityElement securityElement)
		{
			if (securityElement == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("securityElement");
			}
			string tag = securityElement.Tag;
			if (!tag.Equals("Permission") && !tag.Equals("IPermission"))
			{
				throw System.Data.Common.ADP.NotAPermissionElement();
			}
			string text = securityElement.Attribute("version");
			if (text != null && !text.Equals("1"))
			{
				throw System.Data.Common.ADP.InvalidXMLBadVersion();
			}
			string text2 = securityElement.Attribute("Unrestricted");
			_isUnrestricted = text2 != null && bool.Parse(text2);
			Clear();
			if (!_isUnrestricted)
			{
				string text3 = securityElement.Attribute("AllowBlankPassword");
				_allowBlankPassword = text3 != null && bool.Parse(text3);
				ArrayList children = securityElement.Children;
				if (children == null)
				{
					return;
				}
				{
					foreach (SecurityElement item in children)
					{
						tag = item.Tag;
						if ("add" == tag || (tag != null && "add" == tag.ToLower(CultureInfo.InvariantCulture)))
						{
							string value = item.Attribute("ConnectionString");
							string value2 = item.Attribute("KeyRestrictions");
							string text4 = item.Attribute("KeyRestrictionBehavior");
							KeyRestrictionBehavior behavior = KeyRestrictionBehavior.AllowOnly;
							if (text4 != null)
							{
								behavior = (KeyRestrictionBehavior)Enum.Parse(typeof(KeyRestrictionBehavior), text4, ignoreCase: true);
							}
							value = DecodeXmlValue(value);
							value2 = DecodeXmlValue(value2);
							Add(value, value2, behavior);
						}
					}
					return;
				}
			}
			_allowBlankPassword = false;
		}

		public override SecurityElement ToXml()
		{
			Type type = GetType();
			SecurityElement securityElement = new SecurityElement("IPermission");
			securityElement.AddAttribute("class", type.AssemblyQualifiedName.Replace('"', '\''));
			securityElement.AddAttribute("version", "1");
			if (IsUnrestricted())
			{
				securityElement.AddAttribute("Unrestricted", "true");
			}
			else
			{
				securityElement.AddAttribute("AllowBlankPassword", _allowBlankPassword.ToString(CultureInfo.InvariantCulture));
				if (_keyvalues != null)
				{
					foreach (DBConnectionString keyvalue in _keyvalues)
					{
						SecurityElement securityElement2 = new SecurityElement("add");
						string connectionString = keyvalue.ConnectionString;
						connectionString = EncodeXmlValue(connectionString);
						if (!System.Data.Common.ADP.IsEmpty(connectionString))
						{
							securityElement2.AddAttribute("ConnectionString", connectionString);
						}
						connectionString = keyvalue.Restrictions;
						connectionString = EncodeXmlValue(connectionString);
						if (connectionString == null)
						{
							connectionString = System.Data.Common.ADP.StrEmpty;
						}
						securityElement2.AddAttribute("KeyRestrictions", connectionString);
						connectionString = keyvalue.Behavior.ToString();
						securityElement2.AddAttribute("KeyRestrictionBehavior", connectionString);
						securityElement.AddChild(securityElement2);
					}
					return securityElement;
				}
			}
			return securityElement;
		}
	}
	[Serializable]
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Constructor | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
	public sealed class OraclePermissionAttribute : CodeAccessSecurityAttribute
	{
		private bool _allowBlankPassword;

		private string _connectionString;

		private string _restrictions;

		private KeyRestrictionBehavior _behavior;

		public bool AllowBlankPassword
		{
			get
			{
				return _allowBlankPassword;
			}
			set
			{
				_allowBlankPassword = value;
			}
		}

		public string ConnectionString
		{
			get
			{
				string connectionString = _connectionString;
				if (connectionString == null)
				{
					return string.Empty;
				}
				return connectionString;
			}
			set
			{
				_connectionString = value;
			}
		}

		public KeyRestrictionBehavior KeyRestrictionBehavior
		{
			get
			{
				return _behavior;
			}
			set
			{
				switch (value)
				{
				case KeyRestrictionBehavior.AllowOnly:
				case KeyRestrictionBehavior.PreventUsage:
					_behavior = value;
					break;
				default:
					throw System.Data.Common.ADP.InvalidKeyRestrictionBehavior(value);
				}
			}
		}

		public string KeyRestrictions
		{
			get
			{
				string restrictions = _restrictions;
				if (restrictions == null)
				{
					return System.Data.Common.ADP.StrEmpty;
				}
				return restrictions;
			}
			set
			{
				_restrictions = value;
			}
		}

		public OraclePermissionAttribute(SecurityAction action)
			: base(action)
		{
		}

		public override IPermission CreatePermission()
		{
			return new OraclePermission(this);
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public bool ShouldSerializeConnectionString()
		{
			return null != _connectionString;
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public bool ShouldSerializeKeyRestrictions()
		{
			return null != _restrictions;
		}
	}
	public sealed class OracleRowUpdatedEventArgs : RowUpdatedEventArgs
	{
		public new OracleCommand Command => (OracleCommand)base.Command;

		public OracleRowUpdatedEventArgs(DataRow row, IDbCommand command, StatementType statementType, DataTableMapping tableMapping)
			: base(row, command, statementType, tableMapping)
		{
		}
	}
	public delegate void OracleRowUpdatedEventHandler(object sender, OracleRowUpdatedEventArgs e);
	public sealed class OracleRowUpdatingEventArgs : RowUpdatingEventArgs
	{
		public new OracleCommand Command
		{
			get
			{
				return base.Command as OracleCommand;
			}
			set
			{
				base.Command = value;
			}
		}

		protected override IDbCommand BaseCommand
		{
			get
			{
				return base.BaseCommand;
			}
			set
			{
				base.BaseCommand = value as OracleCommand;
			}
		}

		public OracleRowUpdatingEventArgs(DataRow row, IDbCommand command, StatementType statementType, DataTableMapping tableMapping)
			: base(row, command, statementType, tableMapping)
		{
		}
	}
	public delegate void OracleRowUpdatingEventHandler(object sender, OracleRowUpdatingEventArgs e);
	internal sealed class OracleSqlParser : DbSqlParser
	{
		private sealed class ConstraintColumn
		{
			internal string columnName;

			internal DbSqlParserColumn.ConstraintType constraintType;

			internal DbSqlParserColumn parsedColumn;
		}

		private const string SynonymQueryBegin = "select table_owner, table_name from all_synonyms where";

		private const string SynonymQueryNoSchema = " owner in ('PUBLIC', user)";

		private const string SynonymQuerySchema = " owner = '";

		private const string SynonymQueryTable = " and synonym_name = '";

		private const string SynonymQueryEnd = "' order by decode(owner, 'PUBLIC', 2, 1)";

		private static readonly string ConstraintOwnerParameterName = "OwnerName";

		private static readonly string ConstraintTableParameterName = "TableName";

		private static readonly string ConstraintQuery1a = "select ac.constraint_name key_name, acc.column_name key_col," + 1.ToString(CultureInfo.InvariantCulture) + " from all_cons_columns acc, all_constraints ac where acc.owner = ac.owner and acc.constraint_name = ac.constraint_name and acc.table_name = ac.table_name and ac.constraint_type = 'P'";

		private static readonly string ConstraintQuery1b_ownerDefault = " and ac.owner = user";

		private static readonly string ConstraintQuery1b_ownerIsKnown = " and ac.owner = :OwnerName";

		private static readonly string ConstraintQuery1c = " and ac.table_name = :TableName order by acc.constraint_name";

		private static readonly string ConstraintQuery2a = "select aic.index_name key_name, aic.column_name key_col," + 3.ToString(CultureInfo.InvariantCulture) + " from all_ind_columns aic, all_indexes ai where aic.table_owner = ai.table_owner and aic.table_name = ai.table_name and aic.index_name = ai.index_name and ai.uniqueness = 'UNIQUE'";

		private static readonly string ConstraintQuery2b_ownerDefault = " and ai.owner = user";

		private static readonly string ConstraintQuery2b_ownerIsKnown = " and ai.owner = :OwnerName";

		private static readonly string ConstraintQuery2c = " and ai.table_name = :TableName order by aic.index_name";

		private OracleConnection _connection;

		private static readonly string _quoteCharacter = "\"";

		private static readonly string _regexPattern = DbSqlParser.CreateRegexPattern("[\\p{Lo}\\p{Lu}\\p{Ll}\\p{Lm}\uff3f_#$]", "[\\p{Lo}\\p{Lu}\\p{Ll}\\p{Lm}\\p{Nd}\uff3f_#$]", _quoteCharacter, "([^\"]|\"\")*", _quoteCharacter, "('([^']|'')*')");

		internal OracleSqlParser()
			: base(_quoteCharacter, _quoteCharacter, _regexPattern)
		{
		}

		internal static string CatalogCase(string value)
		{
			if (System.Data.Common.ADP.IsEmpty(value))
			{
				return string.Empty;
			}
			if ('"' == value[0])
			{
				return value.Substring(1, value.Length - 2);
			}
			return value.ToUpper(CultureInfo.CurrentCulture);
		}

		protected override bool CatalogMatch(string valueA, string valueB)
		{
			if (System.Data.Common.ADP.IsEmpty(valueA) && System.Data.Common.ADP.IsEmpty(valueB))
			{
				return true;
			}
			if (System.Data.Common.ADP.IsEmpty(valueA) || System.Data.Common.ADP.IsEmpty(valueB))
			{
				return false;
			}
			bool flag = '"' == valueA[0];
			int num = 0;
			int num2 = valueA.Length;
			bool flag2 = '"' == valueB[0];
			int num3 = 0;
			int num4 = valueB.Length;
			if (flag)
			{
				num++;
				num2 -= 2;
			}
			if (flag2)
			{
				num3++;
				num4 -= 2;
			}
			CompareOptions compareOptions = CompareOptions.IgnoreKanaType | CompareOptions.IgnoreWidth;
			if (!flag || !flag2)
			{
				compareOptions |= CompareOptions.IgnoreCase;
			}
			int num5 = CultureInfo.CurrentCulture.CompareInfo.Compare(valueA, num, num2, valueB, num3, num4, compareOptions);
			return 0 == num5;
		}

		private DbSqlParserColumn FindConstraintColumn(string schemaName, string tableName, string columnName)
		{
			DbSqlParserColumnCollection columns = base.Columns;
			int count = columns.Count;
			for (int i = 0; i < count; i++)
			{
				DbSqlParserColumn dbSqlParserColumn = columns[i];
				if (CatalogMatch(dbSqlParserColumn.SchemaName, schemaName) && CatalogMatch(dbSqlParserColumn.TableName, tableName) && CatalogMatch(dbSqlParserColumn.ColumnName, columnName))
				{
					return dbSqlParserColumn;
				}
			}
			return null;
		}

		protected override void GatherKeyColumns(DbSqlParserTable table)
		{
			using OracleCommand oracleCommand = _connection.CreateCommand();
			oracleCommand.Transaction = _connection.Transaction;
			string text = CatalogCase(table.SchemaName);
			string text2 = CatalogCase(table.TableName);
			string text3 = text;
			string value = text2;
			oracleCommand.CommandText = GetSynonymQueryStatement(text, text2);
			using (OracleDataReader oracleDataReader = oracleCommand.ExecuteReader())
			{
				if (oracleDataReader.Read())
				{
					text3 = oracleDataReader.GetString(0);
					value = oracleDataReader.GetString(1);
				}
			}
			StringBuilder stringBuilder = new StringBuilder(ConstraintQuery1a);
			StringBuilder stringBuilder2 = new StringBuilder(ConstraintQuery2a);
			if (System.Data.Common.ADP.IsEmpty(text3))
			{
				stringBuilder.Append(ConstraintQuery1b_ownerDefault);
				stringBuilder2.Append(ConstraintQuery2b_ownerDefault);
			}
			else
			{
				oracleCommand.Parameters.Add(new OracleParameter(ConstraintOwnerParameterName, DbType.String)).Value = text3;
				stringBuilder.Append(ConstraintQuery1b_ownerIsKnown);
				stringBuilder2.Append(ConstraintQuery2b_ownerIsKnown);
			}
			oracleCommand.Parameters.Add(new OracleParameter(ConstraintTableParameterName, DbType.String)).Value = value;
			stringBuilder.Append(ConstraintQuery1c);
			stringBuilder2.Append(ConstraintQuery2c);
			string[] array = new string[2]
			{
				stringBuilder.ToString(),
				stringBuilder2.ToString()
			};
			string[] array2 = array;
			for (int i = 0; i < array2.Length; i++)
			{
				string text5 = (oracleCommand.CommandText = array2[i]);
				using OracleDataReader oracleDataReader2 = oracleCommand.ExecuteReader();
				ArrayList arrayList = new ArrayList();
				bool flag = oracleDataReader2.Read();
				bool flag2 = false;
				while (flag)
				{
					arrayList.Clear();
					string @string = oracleDataReader2.GetString(0);
					do
					{
						ConstraintColumn constraintColumn = new ConstraintColumn();
						constraintColumn.columnName = oracleDataReader2.GetString(1);
						constraintColumn.constraintType = (DbSqlParserColumn.ConstraintType)(int)oracleDataReader2.GetDecimal(2);
						constraintColumn.parsedColumn = null;
						arrayList.Add(constraintColumn);
						flag = oracleDataReader2.Read();
					}
					while (flag && @string == oracleDataReader2.GetString(0));
					flag2 = true;
					for (int j = 0; j < arrayList.Count; j++)
					{
						ConstraintColumn constraintColumn = (ConstraintColumn)arrayList[j];
						constraintColumn.parsedColumn = FindConstraintColumn(text, text2, constraintColumn.columnName);
						if (constraintColumn.parsedColumn == null)
						{
							flag2 = false;
							break;
						}
					}
					if (flag2)
					{
						for (int k = 0; k < arrayList.Count; k++)
						{
							ConstraintColumn constraintColumn = (ConstraintColumn)arrayList[k];
							constraintColumn.parsedColumn.SetConstraint(constraintColumn.constraintType);
						}
						break;
					}
				}
				if (flag2)
				{
					break;
				}
			}
		}

		protected override DbSqlParserColumnCollection GatherTableColumns(DbSqlParserTable table)
		{
			OciStatementHandle handle = new OciStatementHandle(_connection.ServiceContextHandle);
			OciErrorHandle errorHandle = _connection.ErrorHandle;
			StringBuilder stringBuilder = new StringBuilder();
			string schemaName = table.SchemaName;
			string tableName = table.TableName;
			DbSqlParserColumnCollection dbSqlParserColumnCollection = new DbSqlParserColumnCollection();
			stringBuilder.Append("select * from ");
			if (!System.Data.Common.ADP.IsEmpty(schemaName))
			{
				stringBuilder.Append(schemaName);
				stringBuilder.Append(".");
			}
			stringBuilder.Append(tableName);
			string stmt = stringBuilder.ToString();
			if (TracedNativeMethods.OCIStmtPrepare(handle, errorHandle, stmt, OCI.SYNTAX.OCI_NTV_SYNTAX, OCI.MODE.OCI_DEFAULT, _connection) == 0 && TracedNativeMethods.OCIStmtExecute(_connection.ServiceContextHandle, handle, errorHandle, 0, OCI.MODE.OCI_SHARED) == 0)
			{
				handle.GetAttribute(OCI.ATTR.OCI_ATTR_PARAM_COUNT, out int value, errorHandle);
				for (int i = 0; i < value; i++)
				{
					OciParameterDescriptor handle2 = handle.GetDescriptor(i, errorHandle);
					handle2.GetAttribute(OCI.ATTR.OCI_ATTR_SQLCODE, out var value2, errorHandle, _connection);
					OciHandle.SafeDispose(ref handle2);
					value2 = QuotePrefixCharacter + value2 + QuoteSuffixCharacter;
					dbSqlParserColumnCollection.Add(null, schemaName, tableName, value2, null);
				}
			}
			OciHandle.SafeDispose(ref handle);
			return dbSqlParserColumnCollection;
		}

		private string GetSynonymQueryStatement(string schemaName, string tableName)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append("select table_owner, table_name from all_synonyms where");
			if (System.Data.Common.ADP.IsEmpty(schemaName))
			{
				stringBuilder.Append(" owner in ('PUBLIC', user)");
			}
			else
			{
				stringBuilder.Append(" owner = '");
				stringBuilder.Append(schemaName);
				stringBuilder.Append("'");
			}
			stringBuilder.Append(" and synonym_name = '");
			stringBuilder.Append(tableName);
			stringBuilder.Append("' order by decode(owner, 'PUBLIC', 2, 1)");
			return stringBuilder.ToString();
		}

		internal void Parse(string statementText, OracleConnection connection)
		{
			_connection = connection;
			Parse(statementText);
		}
	}
	public struct OracleString : IComparable, INullable
	{
		private string _value;

		public static readonly OracleString Empty = new OracleString(isNull: false);

		public static readonly OracleString Null = new OracleString(isNull: true);

		public bool IsNull => null == _value;

		public int Length
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return _value.Length;
			}
		}

		public string Value
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return _value;
			}
		}

		public char this[int index]
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return _value[index];
			}
		}

		private OracleString(bool isNull)
		{
			_value = (isNull ? null : string.Empty);
		}

		public OracleString(string s)
		{
			_value = s;
		}

		internal OracleString(NativeBuffer buffer, int valueOffset, int lengthOffset, MetaType metaType, OracleConnection connection, bool boundAsUCS2, bool outputParameterBinding)
		{
			_value = MarshalToString(buffer, valueOffset, lengthOffset, metaType, connection, boundAsUCS2, outputParameterBinding);
		}

		public int CompareTo(object obj)
		{
			if (obj.GetType() == typeof(OracleString))
			{
				OracleString oracleString = (OracleString)obj;
				if (IsNull)
				{
					if (!oracleString.IsNull)
					{
						return -1;
					}
					return 0;
				}
				if (oracleString.IsNull)
				{
					return 1;
				}
				return CultureInfo.CurrentCulture.CompareInfo.Compare(_value, oracleString._value);
			}
			throw System.Data.Common.ADP.WrongType(obj.GetType(), typeof(OracleString));
		}

		public override bool Equals(object value)
		{
			if (value is OracleString)
			{
				return (this == (OracleString)value).Value;
			}
			return false;
		}

		internal static int GetChars(NativeBuffer buffer, int valueOffset, int lengthOffset, MetaType metaType, OracleConnection connection, bool boundAsUCS2, int sourceOffset, char[] destinationBuffer, int destinationOffset, int charCount)
		{
			bool success = false;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				buffer.DangerousAddRef(ref success);
				if (boundAsUCS2)
				{
					if (!metaType.IsLong)
					{
						Marshal.Copy(buffer.DangerousGetDataPtrWithBaseOffset(valueOffset + System.Data.Common.ADP.CharSize * sourceOffset), destinationBuffer, destinationOffset, charCount);
						return charCount;
					}
					NativeBuffer_LongColumnData.CopyOutOfLineChars(buffer.ReadIntPtr(valueOffset), sourceOffset, destinationBuffer, destinationOffset, charCount);
					return charCount;
				}
				string text = MarshalToString(buffer, valueOffset, lengthOffset, metaType, connection, boundAsUCS2, outputParameterBinding: false);
				int length = text.Length;
				int num = ((sourceOffset + charCount > length) ? (length - sourceOffset) : charCount);
				char[] src = text.ToCharArray(sourceOffset, num);
				Buffer.BlockCopy(src, 0, destinationBuffer, destinationOffset * System.Data.Common.ADP.CharSize, num * System.Data.Common.ADP.CharSize);
				charCount = num;
				return charCount;
			}
			finally
			{
				if (success)
				{
					buffer.DangerousRelease();
				}
			}
		}

		public override int GetHashCode()
		{
			if (!IsNull)
			{
				return _value.GetHashCode();
			}
			return 0;
		}

		internal static int GetLength(NativeBuffer buffer, int lengthOffset, MetaType metaType)
		{
			int result = ((!metaType.IsLong) ? buffer.ReadInt16(lengthOffset) : buffer.ReadInt32(lengthOffset));
			GC.KeepAlive(buffer);
			return result;
		}

		internal static string MarshalToString(NativeBuffer buffer, int valueOffset, int lengthOffset, MetaType metaType, OracleConnection connection, bool boundAsUCS2, bool outputParameterBinding)
		{
			int num = GetLength(buffer, lengthOffset, metaType);
			if (boundAsUCS2 && outputParameterBinding)
			{
				num /= 2;
			}
			bool flag = metaType.IsLong && !outputParameterBinding;
			_ = IntPtr.Zero;
			string result;
			if (boundAsUCS2)
			{
				if (flag)
				{
					byte[] array = new byte[num * System.Data.Common.ADP.CharSize];
					NativeBuffer_LongColumnData.CopyOutOfLineBytes(buffer.ReadIntPtr(valueOffset), 0, array, 0, num * System.Data.Common.ADP.CharSize);
					result = Encoding.Unicode.GetString(array);
				}
				else
				{
					result = buffer.PtrToStringUni(valueOffset, num);
				}
			}
			else
			{
				byte[] array2;
				if (flag)
				{
					array2 = new byte[num];
					NativeBuffer_LongColumnData.CopyOutOfLineBytes(buffer.ReadIntPtr(valueOffset), 0, array2, 0, num);
				}
				else
				{
					array2 = buffer.ReadBytes(valueOffset, num);
				}
				result = connection.GetString(array2, metaType.UsesNationalCharacterSet);
			}
			GC.KeepAlive(buffer);
			return result;
		}

		internal static int MarshalToNative(object value, int offset, int size, NativeBuffer buffer, int bufferOffset, OCI.DATATYPE ociType, bool bindAsUCS2)
		{
			Encoding encoding = (bindAsUCS2 ? Encoding.Unicode : Encoding.UTF8);
			string text = ((!(value is OracleString)) ? ((string)value) : ((OracleString)value)._value);
			string s = ((offset == 0 && size == 0) ? text : ((size != 0 && offset + size <= text.Length) ? text.Substring(offset, size) : text.Substring(offset)));
			byte[] bytes = encoding.GetBytes(s);
			int num = bytes.Length;
			int num2 = num;
			if (num != 0)
			{
				int num3 = num;
				if (bindAsUCS2)
				{
					num3 /= 2;
				}
				if (OCI.DATATYPE.LONGVARCHAR == ociType)
				{
					buffer.WriteInt32(bufferOffset, num3);
					bufferOffset = checked(bufferOffset + 4);
					num2 += 4;
				}
				buffer.WriteBytes(bufferOffset, bytes, 0, num);
			}
			return num2;
		}

		public override string ToString()
		{
			if (IsNull)
			{
				return System.Data.Common.ADP.NullString;
			}
			return _value;
		}

		public static OracleString Concat(OracleString x, OracleString y)
		{
			return x + y;
		}

		public static OracleBoolean Equals(OracleString x, OracleString y)
		{
			return x == y;
		}

		public static OracleBoolean GreaterThan(OracleString x, OracleString y)
		{
			return x > y;
		}

		public static OracleBoolean GreaterThanOrEqual(OracleString x, OracleString y)
		{
			return x >= y;
		}

		public static OracleBoolean LessThan(OracleString x, OracleString y)
		{
			return x < y;
		}

		public static OracleBoolean LessThanOrEqual(OracleString x, OracleString y)
		{
			return x <= y;
		}

		public static OracleBoolean NotEquals(OracleString x, OracleString y)
		{
			return x != y;
		}

		public static implicit operator OracleString(string s)
		{
			return new OracleString(s);
		}

		public static explicit operator string(OracleString x)
		{
			return x.Value;
		}

		public static OracleString operator +(OracleString x, OracleString y)
		{
			if (x.IsNull || y.IsNull)
			{
				return Null;
			}
			return new OracleString(x._value + y._value);
		}

		public static OracleBoolean operator ==(OracleString x, OracleString y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) == 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >(OracleString x, OracleString y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) > 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >=(OracleString x, OracleString y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) >= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <(OracleString x, OracleString y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) < 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <=(OracleString x, OracleString y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) <= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator !=(OracleString x, OracleString y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) != 0);
			}
			return OracleBoolean.Null;
		}
	}
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct OracleTimeSpan : IComparable, INullable
	{
		private const int FractionalSecondsPerTick = 100;

		private byte[] _value;

		public static readonly OracleTimeSpan MaxValue = new OracleTimeSpan(TimeSpan.MaxValue);

		public static readonly OracleTimeSpan MinValue = new OracleTimeSpan(TimeSpan.MinValue);

		public static readonly OracleTimeSpan Null = new OracleTimeSpan(isNull: true);

		public bool IsNull => null == _value;

		public TimeSpan Value
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				return ToTimeSpan(_value);
			}
		}

		public int Days
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var days, out var _, out var _, out var _, out var _);
				return days;
			}
		}

		public int Hours
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var hours, out var _, out var _, out var _);
				return hours;
			}
		}

		public int Minutes
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var minutes, out var _, out var _);
				return minutes;
			}
		}

		public int Seconds
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var _, out var seconds, out var _);
				return seconds;
			}
		}

		public int Milliseconds
		{
			get
			{
				if (IsNull)
				{
					throw System.Data.Common.ADP.DataIsNull();
				}
				Unpack(_value, out var _, out var _, out var _, out var _, out var fsecs);
				return (int)((long)(fsecs / 100) / 10000L);
			}
		}

		private OracleTimeSpan(bool isNull)
		{
			_value = null;
		}

		public OracleTimeSpan(TimeSpan ts)
		{
			_value = new byte[11];
			Pack(_value, ts.Days, ts.Hours, ts.Minutes, ts.Seconds, (int)(ts.Ticks % 10000000) * 100);
		}

		public OracleTimeSpan(long ticks)
		{
			_value = new byte[11];
			TimeSpan timeSpan = new TimeSpan(ticks);
			Pack(_value, timeSpan.Days, timeSpan.Hours, timeSpan.Minutes, timeSpan.Seconds, (int)(timeSpan.Ticks % 10000000) * 100);
		}

		public OracleTimeSpan(int hours, int minutes, int seconds)
			: this(0, hours, minutes, seconds, 0)
		{
		}

		public OracleTimeSpan(int days, int hours, int minutes, int seconds)
			: this(days, hours, minutes, seconds, 0)
		{
		}

		public OracleTimeSpan(int days, int hours, int minutes, int seconds, int milliseconds)
		{
			_value = new byte[11];
			Pack(_value, days, hours, minutes, seconds, (int)((long)milliseconds * 10000L) * 100);
		}

		public OracleTimeSpan(OracleTimeSpan from)
		{
			_value = new byte[from._value.Length];
			from._value.CopyTo(_value, 0);
		}

		internal OracleTimeSpan(NativeBuffer buffer, int valueOffset)
			: this(isNull: true)
		{
			_value = buffer.ReadBytes(valueOffset, 11);
		}

		private static void Pack(byte[] spanval, int days, int hours, int minutes, int seconds, int fsecs)
		{
			days = (int)(days + 2147483648u);
			fsecs = (int)(fsecs + 2147483648u);
			spanval[0] = (byte)(days >> 24);
			spanval[1] = (byte)((uint)(days >> 16) & 0xFFu);
			spanval[2] = (byte)((uint)(days >> 8) & 0xFFu);
			spanval[3] = (byte)((uint)days & 0xFFu);
			spanval[4] = (byte)(hours + 60);
			spanval[5] = (byte)(minutes + 60);
			spanval[6] = (byte)(seconds + 60);
			spanval[7] = (byte)(fsecs >> 24);
			spanval[8] = (byte)((uint)(fsecs >> 16) & 0xFFu);
			spanval[9] = (byte)((uint)(fsecs >> 8) & 0xFFu);
			spanval[10] = (byte)((uint)fsecs & 0xFFu);
		}

		private static void Unpack(byte[] spanval, out int days, out int hours, out int minutes, out int seconds, out int fsecs)
		{
			days = (int)(((spanval[0] << 24) | (spanval[1] << 16) | (spanval[2] << 8) | spanval[3]) - 2147483648u);
			hours = spanval[4] - 60;
			minutes = spanval[5] - 60;
			seconds = spanval[6] - 60;
			fsecs = (int)(((spanval[7] << 24) | (spanval[8] << 16) | (spanval[9] << 8) | spanval[10]) - 2147483648u);
		}

		public int CompareTo(object obj)
		{
			if (obj.GetType() == typeof(OracleTimeSpan))
			{
				OracleTimeSpan oracleTimeSpan = (OracleTimeSpan)obj;
				if (IsNull)
				{
					if (!oracleTimeSpan.IsNull)
					{
						return -1;
					}
					return 0;
				}
				if (oracleTimeSpan.IsNull)
				{
					return 1;
				}
				Unpack(_value, out var days, out var hours, out var minutes, out var seconds, out var fsecs);
				Unpack(oracleTimeSpan._value, out var days2, out var hours2, out var minutes2, out var seconds2, out var fsecs2);
				int num = days - days2;
				if (num != 0)
				{
					return num;
				}
				num = hours - hours2;
				if (num != 0)
				{
					return num;
				}
				num = minutes - minutes2;
				if (num != 0)
				{
					return num;
				}
				num = seconds - seconds2;
				if (num != 0)
				{
					return num;
				}
				num = fsecs - fsecs2;
				if (num != 0)
				{
					return num;
				}
				return 0;
			}
			throw System.Data.Common.ADP.WrongType(obj.GetType(), typeof(OracleTimeSpan));
		}

		public override bool Equals(object value)
		{
			if (value is OracleTimeSpan)
			{
				return (this == (OracleTimeSpan)value).Value;
			}
			return false;
		}

		public override int GetHashCode()
		{
			if (!IsNull)
			{
				return _value.GetHashCode();
			}
			return 0;
		}

		internal static TimeSpan MarshalToTimeSpan(NativeBuffer buffer, int valueOffset)
		{
			byte[] rawValue = buffer.ReadBytes(valueOffset, 11);
			return ToTimeSpan(rawValue);
		}

		internal static int MarshalToNative(object value, NativeBuffer buffer, int offset)
		{
			byte[] array;
			if (value is OracleTimeSpan)
			{
				array = ((OracleTimeSpan)value)._value;
			}
			else
			{
				TimeSpan timeSpan = (TimeSpan)value;
				array = new byte[11];
				Pack(array, timeSpan.Days, timeSpan.Hours, timeSpan.Minutes, timeSpan.Seconds, (int)(timeSpan.Ticks % 10000000) * 100);
			}
			buffer.WriteBytes(offset, array, 0, 11);
			return 11;
		}

		public static OracleTimeSpan Parse(string s)
		{
			TimeSpan ts = TimeSpan.Parse(s);
			return new OracleTimeSpan(ts);
		}

		public override string ToString()
		{
			if (IsNull)
			{
				return System.Data.Common.ADP.NullString;
			}
			return Value.ToString();
		}

		private static TimeSpan ToTimeSpan(byte[] rawValue)
		{
			Unpack(rawValue, out var days, out var hours, out var minutes, out var seconds, out var fsecs);
			long num = days * 864000000000L + hours * 36000000000L + (long)minutes * 600000000L + (long)seconds * 10000000L;
			if (fsecs < 100 || fsecs > 100)
			{
				num += (long)fsecs / 100L;
			}
			return new TimeSpan(num);
		}

		public static OracleBoolean Equals(OracleTimeSpan x, OracleTimeSpan y)
		{
			return x == y;
		}

		public static OracleBoolean GreaterThan(OracleTimeSpan x, OracleTimeSpan y)
		{
			return x > y;
		}

		public static OracleBoolean GreaterThanOrEqual(OracleTimeSpan x, OracleTimeSpan y)
		{
			return x >= y;
		}

		public static OracleBoolean LessThan(OracleTimeSpan x, OracleTimeSpan y)
		{
			return x < y;
		}

		public static OracleBoolean LessThanOrEqual(OracleTimeSpan x, OracleTimeSpan y)
		{
			return x <= y;
		}

		public static OracleBoolean NotEquals(OracleTimeSpan x, OracleTimeSpan y)
		{
			return x != y;
		}

		public static explicit operator TimeSpan(OracleTimeSpan x)
		{
			if (x.IsNull)
			{
				throw System.Data.Common.ADP.DataIsNull();
			}
			return x.Value;
		}

		public static explicit operator OracleTimeSpan(string x)
		{
			return Parse(x);
		}

		public static OracleBoolean operator ==(OracleTimeSpan x, OracleTimeSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) == 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >(OracleTimeSpan x, OracleTimeSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) > 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator >=(OracleTimeSpan x, OracleTimeSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) >= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <(OracleTimeSpan x, OracleTimeSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) < 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator <=(OracleTimeSpan x, OracleTimeSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) <= 0);
			}
			return OracleBoolean.Null;
		}

		public static OracleBoolean operator !=(OracleTimeSpan x, OracleTimeSpan y)
		{
			if (!x.IsNull && !y.IsNull)
			{
				return new OracleBoolean(x.CompareTo(y) != 0);
			}
			return OracleBoolean.Null;
		}
	}
	public sealed class OracleTransaction : DbTransaction
	{
		private OracleConnection _connection;

		private int _connectionCloseCount;

		private IsolationLevel _isolationLevel = IsolationLevel.ReadCommitted;

		private static int _objectTypeCount;

		internal readonly int _objectID = Interlocked.Increment(ref _objectTypeCount);

		public new OracleConnection Connection => _connection;

		protected override DbConnection DbConnection => Connection;

		public override IsolationLevel IsolationLevel
		{
			get
			{
				AssertNotCompleted();
				if (IsolationLevel.Unspecified == _isolationLevel)
				{
					using OracleCommand oracleCommand = Connection.CreateCommand();
					oracleCommand.Transaction = this;
					oracleCommand.CommandText = "select decode(value,'FALSE',0,1) from V$SYSTEM_PARAMETER where name = 'serializable'";
					decimal num = (decimal)oracleCommand.ExecuteScalar();
					if (0m == num)
					{
						_isolationLevel = IsolationLevel.ReadCommitted;
					}
					else
					{
						_isolationLevel = IsolationLevel.Serializable;
					}
				}
				return _isolationLevel;
			}
		}

		internal int ObjectID => _objectID;

		internal OracleTransaction(OracleConnection connection)
			: this(connection, IsolationLevel.Unspecified)
		{
		}

		internal OracleTransaction(OracleConnection connection, IsolationLevel isolationLevel)
		{
			//Discarded unreachable code: IL_00db
			TransactionState transactionState = connection.TransactionState;
			if (TransactionState.GlobalStarted == transactionState)
			{
				throw System.Data.Common.ADP.NoLocalTransactionInDistributedContext();
			}
			_connection = connection;
			_connectionCloseCount = connection.CloseCount;
			_isolationLevel = isolationLevel;
			_connection.TransactionState = TransactionState.LocalStarted;
			try
			{
				switch (isolationLevel)
				{
				case IsolationLevel.ReadCommitted:
				{
					using OracleCommand oracleCommand2 = Connection.CreateCommand();
					oracleCommand2.CommandText = "set transaction isolation level read committed";
					oracleCommand2.ExecuteNonQuery();
					break;
				}
				case IsolationLevel.Serializable:
				{
					using OracleCommand oracleCommand = Connection.CreateCommand();
					oracleCommand.CommandText = "set transaction isolation level serializable";
					oracleCommand.ExecuteNonQuery();
					break;
				}
				default:
					throw System.Data.Common.ADP.UnsupportedIsolationLevel();
				case IsolationLevel.Unspecified:
					break;
				}
			}
			catch
			{
				_connection.TransactionState = transactionState;
				throw;
			}
		}

		private void AssertNotCompleted()
		{
			if (Connection == null || _connectionCloseCount != Connection.CloseCount)
			{
				throw System.Data.Common.ADP.TransactionCompleted();
			}
		}

		public override void Commit()
		{
			OracleConnection.ExecutePermission.Demand();
			Bid.ScopeEnter(out var hScp, "<ora.OracleTransaction.Commit|API> %d#\n", ObjectID);
			try
			{
				AssertNotCompleted();
				Connection.Commit();
				Dispose(disposing: true);
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (Connection != null)
				{
					Connection.Rollback();
				}
				_connection = null;
			}
			base.Dispose(disposing);
		}

		public override void Rollback()
		{
			Bid.ScopeEnter(out var hScp, "<ora.OracleTransaction.Rollback|API> %d#\n", ObjectID);
			try
			{
				AssertNotCompleted();
				Dispose(disposing: true);
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}
	}
	public enum OracleType
	{
		BFile = 1,
		Blob = 2,
		Char = 3,
		Clob = 4,
		Cursor = 5,
		DateTime = 6,
		IntervalDayToSecond = 7,
		IntervalYearToMonth = 8,
		LongRaw = 9,
		LongVarChar = 10,
		NChar = 11,
		NClob = 12,
		Number = 13,
		NVarChar = 14,
		Raw = 15,
		RowId = 16,
		Timestamp = 18,
		TimestampLocal = 19,
		TimestampWithTZ = 20,
		VarChar = 22,
		Byte = 23,
		UInt16 = 24,
		UInt32 = 25,
		SByte = 26,
		Int16 = 27,
		Int32 = 28,
		Float = 29,
		Double = 30
	}
}
namespace System.Data.Common
{
	[SuppressUnmanagedCodeSecurity]
	internal sealed class SafeNativeMethods
	{
		private SafeNativeMethods()
		{
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		internal static extern int GetCurrentProcessId();

		[DllImport("kernel32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern int ReleaseSemaphore(IntPtr handle, int releaseCount, IntPtr previousCount);

		[DllImport("kernel32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern int WaitForMultipleObjectsEx(uint nCount, IntPtr lpHandles, bool bWaitAll, uint dwMilliseconds, bool bAlertable);

		[DllImport("kernel32.dll")]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern int WaitForSingleObjectEx(IntPtr lpHandles, uint dwMilliseconds, bool bAlertable);

		[DllImport("kernel32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern IntPtr LocalAlloc(int flags, IntPtr countOfBytes);

		[DllImport("kernel32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern IntPtr LocalFree(IntPtr handle);
	}
}
namespace System.Data.OracleClient
{
	internal sealed class TempEnvironment
	{
		private static OciEnvironmentHandle environmentHandle;

		private static OciErrorHandle availableErrorHandle;

		private static volatile bool isInitialized;

		private static object locked = new object();

		private TempEnvironment()
		{
		}

		private static void Initialize()
		{
			lock (locked)
			{
				if (!isInitialized)
				{
					bool unicode = false;
					OCI.MODE environmentMode = OCI.MODE.OCI_THREADED | OCI.MODE.OCI_OBJECT;
					OCI.DetermineClientVersion();
					environmentHandle = new OciEnvironmentHandle(environmentMode, unicode);
					availableErrorHandle = new OciErrorHandle(environmentHandle);
					isInitialized = true;
				}
			}
		}

		internal static OciErrorHandle GetErrorHandle()
		{
			if (!isInitialized)
			{
				Initialize();
			}
			return availableErrorHandle;
		}
	}
	internal static class TracedNativeMethods
	{
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static int OraMTSEnlCtxGet(byte[] userName, byte[] password, byte[] serverName, OciHandle pOCISvc, OciHandle pOCIErr, out IntPtr pCtxt)
		{
			RuntimeHelpers.PrepareConstrainedRegions();
			int num;
			try
			{
			}
			finally
			{
				if (Bid.AdvancedOn)
				{
					Bid.Trace("<oc.OraMTSEnlCtxGet|ADV|OCI> userName=..., password=..., serverName=..., pOCISvc=0x%-07Ix pOCIErr=0x%-07Ix dwFlags=0x%08X\n", OciHandle.HandleValueToTrace(pOCISvc), OciHandle.HandleValueToTrace(pOCIErr), 0);
				}
				num = System.Data.Common.UnsafeNativeMethods.OraMTSEnlCtxGet(userName, password, serverName, pOCISvc, pOCIErr, 0u, out pCtxt);
				if (Bid.AdvancedOn)
				{
					Bid.Trace("<oc.OraMTSEnlCtxGet|ADV|OCI|RET> pCtxt=0x%-07Ix rc=%d\n", pCtxt, num);
				}
			}
			return num;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static int OraMTSEnlCtxRel(IntPtr pCtxt)
		{
			RuntimeHelpers.PrepareConstrainedRegions();
			int num;
			try
			{
			}
			finally
			{
				if (Bid.AdvancedOn)
				{
					Bid.Trace("<oc.OraMTSEnlCtxRel|ADV|OCI> pCtxt=%Id\n", pCtxt);
				}
				num = System.Data.Common.UnsafeNativeMethods.OraMTSEnlCtxRel(pCtxt);
				if (Bid.AdvancedOn)
				{
					Bid.Trace("<oc.OraMTSEnlCtxRel|ADV|OCI|RET> rc=%d\n", num);
				}
			}
			return num;
		}

		internal static int OraMTSOCIErrGet(ref int dwErr, NativeBuffer lpcEMsg, ref int lpdLen)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OraMTSOCIErrGet|ADV|OCI> dwErr=%08X, lpcEMsg=0x%-07Ix lpdLen=%d\n", dwErr, NativeBuffer.HandleValueToTrace(lpcEMsg), lpdLen);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OraMTSOCIErrGet(ref dwErr, lpcEMsg, ref lpdLen);
			if (Bid.AdvancedOn)
			{
				if (num == 0)
				{
					Bid.Trace("<oc.OraMTSOCIErrGet|ADV|OCI|RET> rc=%d\n", num);
				}
				else
				{
					string a = lpcEMsg.PtrToStringAnsi(0, lpdLen);
					Bid.Trace("<oc.OraMTSOCIErrGet|ADV|OCI|RET> rd=%d message='%ls', lpdLen=%d\n", num, a, lpdLen);
				}
			}
			return num;
		}

		internal static int OraMTSJoinTxn(OciEnlistContext pCtxt, IDtcTransaction pTrans)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OraMTSJoinTxn|ADV|OCI> pCtxt=0x%-07Ix pTrans=...\n", OciEnlistContext.HandleValueToTrace(pCtxt));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OraMTSJoinTxn(pCtxt, pTrans);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OraMTSJoinTxn|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int oermsg(short rcode, NativeBuffer buf)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.oermsg|ADV|OCI> rcode=%d\n", rcode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.oermsg(rcode, buf);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.oermsg|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCIAttrGet(OciHandle trgthndlp, ref IntPtr attributep, ref uint sizep, OCI.ATTR attrtype, OciHandle errhp)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCIAttrGet(trgthndlp, trgthndlp.HandleType, ref attributep, ref sizep, attrtype, errhp);
			if (Bid.AdvancedOn)
			{
				if (OCI.ATTR.OCI_ATTR_SQLCODE == attrtype)
				{
					Bid.Trace("<oc.OCIAttrGet|ADV|OCI|RET>          trgthndlp=0x%-07Ix trghndltyp=%-18ls attrtype=%-22ls errhp=0x%-07Ix attributep=%-20ls sizep=%2d rc=%d\n", trgthndlp, trgthndlp.HandleType, attrtype, errhp, trgthndlp.PtrToString(attributep, checked((int)sizep)), sizep, num);
				}
				else
				{
					Bid.Trace("<oc.OCIAttrGet|ADV|OCI|RET>          trgthndlp=0x%-07Ix trghndltyp=%-18ls attrtype=%-22ls errhp=0x%-07Ix attributep=0x%-18Ix sizep=%2d rc=%d\n", trgthndlp, trgthndlp.HandleType, attrtype, errhp, attributep, sizep, num);
				}
			}
			return num;
		}

		internal static int OCIAttrGet(OciHandle trgthndlp, out byte attributep, out uint sizep, OCI.ATTR attrtype, OciHandle errhp)
		{
			int attributep2 = 0;
			int num = System.Data.Common.UnsafeNativeMethods.OCIAttrGet(trgthndlp, trgthndlp.HandleType, out attributep2, out sizep, attrtype, errhp);
			attributep = (byte)attributep2;
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIAttrGet|ADV|OCI|RET>          trgthndlp=0x%-07Ix trghndltyp=%-18ls attrtype=%-22ls errhp=0x%-07Ix attributep=%-20d sizep=%2d rc=%d\n", trgthndlp, trgthndlp.HandleType, attrtype, errhp, attributep, sizep, num);
			}
			return num;
		}

		internal static int OCIAttrGet(OciHandle trgthndlp, out short attributep, out uint sizep, OCI.ATTR attrtype, OciHandle errhp)
		{
			int attributep2 = 0;
			int num = System.Data.Common.UnsafeNativeMethods.OCIAttrGet(trgthndlp, trgthndlp.HandleType, out attributep2, out sizep, attrtype, errhp);
			attributep = (short)attributep2;
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIAttrGet|ADV|OCI|RET>          trgthndlp=0x%-07Ix trghndltyp=%-18ls attrtype=%-22ls errhp=0x%-07Ix attributep=%-20d sizep=%2d rc=%d\n", trgthndlp, trgthndlp.HandleType, attrtype, errhp, attributep, sizep, num);
			}
			return num;
		}

		internal static int OCIAttrGet(OciHandle trgthndlp, out int attributep, out uint sizep, OCI.ATTR attrtype, OciHandle errhp)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCIAttrGet(trgthndlp, trgthndlp.HandleType, out attributep, out sizep, attrtype, errhp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIAttrGet|ADV|OCI|RET>          trgthndlp=0x%-07Ix trghndltyp=%-18ls attrtype=%-22ls errhp=0x%-07Ix attributep=%-20d sizep=%2d rc=%d\n", trgthndlp, trgthndlp.HandleType, attrtype, errhp, attributep, sizep, num);
			}
			return num;
		}

		internal static int OCIAttrGet(OciHandle trgthndlp, OciHandle attributep, out uint sizep, OCI.ATTR attrtype, OciHandle errhp)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCIAttrGet(trgthndlp, trgthndlp.HandleType, attributep, out sizep, attrtype, errhp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIAttrGet|ADV|OCI|RET>          trgthndlp=0x%-07Ix trghndltyp=%-18ls attrtype=%-22ls errhp=0x%-07Ix attributep=0x%-18Ix sizep=%2d rc=%d\n", trgthndlp, trgthndlp.HandleType, attrtype, errhp, OciHandle.HandleValueToTrace(attributep), sizep, num);
			}
			return num;
		}

		internal static int OCIAttrSet(OciHandle trgthndlp, ref int attributep, uint size, OCI.ATTR attrtype, OciHandle errhp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIAttrSet|ADV|OCI>              trgthndlp=0x%-07Ix trghndltyp=%-18ls attributep=%-9d size=%-2d attrtype=%-22ls errhp=0x%-07Ix\n", trgthndlp, trgthndlp.HandleType, attributep, size, attrtype, errhp);
			}
			return System.Data.Common.UnsafeNativeMethods.OCIAttrSet(trgthndlp, trgthndlp.HandleType, ref attributep, size, attrtype, errhp);
		}

		internal static int OCIAttrSet(OciHandle trgthndlp, OciHandle attributep, uint size, OCI.ATTR attrtype, OciHandle errhp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIAttrSet|ADV|OCI>              trgthndlp=0x%-07Ix trghndltyp=%-18ls attributep=0x%-07Ix size=%d attrtype=%-22ls errhp=0x%-07Ix\n", trgthndlp, trgthndlp.HandleType, attributep, size, attrtype, errhp);
			}
			return System.Data.Common.UnsafeNativeMethods.OCIAttrSet(trgthndlp, trgthndlp.HandleType, attributep, size, attrtype, errhp);
		}

		internal static int OCIAttrSet(OciHandle trgthndlp, byte[] attributep, uint size, OCI.ATTR attrtype, OciHandle errhp)
		{
			if (Bid.AdvancedOn)
			{
				string a;
				if (OCI.ATTR.OCI_ATTR_EXTERNAL_NAME == attrtype || OCI.ATTR.OCI_ATTR_INTERNAL_NAME == attrtype)
				{
					char[] chars = Encoding.UTF8.GetChars(attributep, 0, checked((int)size));
					a = new string(chars);
				}
				else
				{
					a = attributep.ToString();
				}
				Bid.Trace("<oc.OCIAttrSet|ADV|OCI>              trgthndlp=0x%-07Ix trghndltyp=%-18ls attributep='%ls' size=%d attrtype=%-22ls errhp=0x%-07Ix\n", trgthndlp, trgthndlp.HandleType, a, size, attrtype, errhp);
			}
			return System.Data.Common.UnsafeNativeMethods.OCIAttrSet(trgthndlp, trgthndlp.HandleType, attributep, size, attrtype, errhp);
		}

		internal static int OCIBindByName(OciHandle stmtp, out IntPtr bindpp, OciHandle errhp, string placeholder, int placeh_len, IntPtr valuep, int value_sz, OCI.DATATYPE dty, IntPtr indp, IntPtr alenp, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIBindByName|ADV|OCI>           stmtp=0x%-07Ix errhp=0x%-07Ix placeholder=%-20ls placeh_len=%-2d valuep=0x%-07Ix value_sz=%-4d dty=%d{OCI.DATATYPE} indp=0x%-07Ix *indp=%-3d alenp=0x%-07Ix *alenp=%-4d rcodep=0x%-07Ix maxarr_len=%-4d curelap=0x%-07Ix mode=0x%x{OCI.MODE}\n", OciHandle.HandleValueToTrace(stmtp), OciHandle.HandleValueToTrace(errhp), placeholder, placeh_len, valuep, value_sz, (int)dty, indp, (!(IntPtr.Zero == indp)) ? Marshal.ReadInt16(indp) : 0, alenp, (!(IntPtr.Zero == alenp)) ? Marshal.ReadInt16(alenp) : 0, IntPtr.Zero, 0u, IntPtr.Zero, (int)mode);
			}
			byte[] bytes = stmtp.GetBytes(placeholder);
			int placeh_len2 = bytes.Length;
			int num = System.Data.Common.UnsafeNativeMethods.OCIBindByName(stmtp, out bindpp, errhp, bytes, placeh_len2, valuep, value_sz, dty, indp, alenp, IntPtr.Zero, 0u, IntPtr.Zero, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIBindByName|ADV|OCI|RET>       bindpp=0x%-07Ix rc=%d\n", bindpp, num);
			}
			return num;
		}

		internal static int OCIDefineByPos(OciHandle stmtp, out IntPtr hndlpp, OciHandle errhp, uint position, IntPtr valuep, int value_sz, OCI.DATATYPE dty, IntPtr indp, IntPtr rlenp, IntPtr rcodep, OCI.MODE mode)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCIDefineByPos(stmtp, out hndlpp, errhp, position, valuep, value_sz, dty, indp, rlenp, rcodep, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIDefineByPos|ADV|OCI|RET>      stmtp=0x%-07Ix errhp=0x%-07Ix position=%-2d valuep=0x%-07Ix value_sz=%-4d dty=%-3d %-14s indp=0x%-07Ix rlenp=0x%-07Ix rcodep=0x%-07Ix mode=0x%x{OCI.MODE} hndlpp=0x%-07Ix rc=%d\n", stmtp, errhp, position, valuep, value_sz, (int)dty, dty, indp, rlenp, rcodep, (int)mode, hndlpp, num);
			}
			return num;
		}

		internal static int OCIDefineArrayOfStruct(OciHandle defnp, OciHandle errhp, uint pvskip, uint indskip, uint rlskip, uint rcskip)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIDefineArrayOfStruct|ADV|OCI>  defnp=0x%-07Ix errhp=0x%-07Ix pvskip=%-4d indskip=%-4d rlskip=%-4d rcskip=%-4d\n", defnp, errhp, pvskip, indskip, rlskip, rcskip);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIDefineArrayOfStruct(defnp, errhp, pvskip, indskip, rlskip, rcskip);
			if (num != 0 && Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIDefineArrayOfStruct|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCIDefineDynamic(OciHandle defnp, OciHandle errhp, IntPtr octxp, OCI.Callback.OCICallbackDefine ocbfp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIDefineDynamic|ADV|OCI>        defnp=0x%-07Ix errhp=0x%-07Ix octxp=0x%-07Ix ocbfp=...\n", OciHandle.HandleValueToTrace(defnp), OciHandle.HandleValueToTrace(errhp), octxp);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIDefineDynamic(defnp, errhp, octxp, ocbfp);
			if (num != 0 && Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIDefineDynamic|ADV|OCI|RET>    rc=%d\n", num);
			}
			return num;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static int OCIDescriptorAlloc(OciHandle parenth, out IntPtr hndlpp, OCI.HTYPE type)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCIDescriptorAlloc(parenth, out hndlpp, type, 0u, IntPtr.Zero);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIDescriptorAlloc|ADV|OCI|RET>  parenth=0x%-07Ix type=%3d xtramemsz=%d usrmempp=0x%-07Ix hndlpp=0x%-07Ix rc=%d\n", parenth, (int)type, 0, IntPtr.Zero, hndlpp, num);
			}
			return num;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static int OCIDescriptorFree(IntPtr hndlp, OCI.HTYPE type)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIDescriptorFree|ADV|OCI>       hndlp=0x%Id type=%3d\n", hndlp, (int)type);
			}
			return System.Data.Common.UnsafeNativeMethods.OCIDescriptorFree(hndlp, type);
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static int OCIEnvCreate(out IntPtr envhpp, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIEnvCreate|ADV|OCI>  mode=0x%x{OCI.MODE} ctxp=0x%-07Ix malocfp=0x%-07Ix ralocfp=0x%-07Ix mfreefp=0x%-07Ix xtramemsz=%d usrmempp=0x%-07Ix", (int)mode, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIEnvCreate(out envhpp, mode, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0u, IntPtr.Zero);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIEnvCreate|ADV|OCI|RET>       envhpp=0x%-07Ix, rc=%d\n", envhpp, num);
			}
			return num;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static int OCIEnvNlsCreate(out IntPtr envhpp, OCI.MODE mode, ushort charset, ushort ncharset)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIEnvNlsCreate|ADV|OCI> mode=0x%x{OCI.MODE} ctxp=0x%-07Ix malocfp=0x%-07Ix ralocfp=0x%-07Ix mfreefp=0x%-07Ix xtramemsz=%d usrmempp=0x%-07Ix charset=%d ncharset=%d", (int)mode, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, charset, ncharset);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIEnvNlsCreate(out envhpp, mode, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0u, IntPtr.Zero, charset, ncharset);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIEnvNlsCreate|ADV|OCI|RET>    envhpp=0x%-07Ix rc=%d\n", envhpp, num);
			}
			return num;
		}

		internal static int OCIErrorGet(OciHandle hndlp, int recordno, out int errcodep, NativeBuffer bufp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIErrorGet|ADV|OCI>             hndlp=0x%-07Ix recordno=%d sqlstate=0x%-07Ix bufp=0x%-07Ix bufsiz=%d type=%d{OCI.HTYPE}\n", OciHandle.HandleValueToTrace(hndlp), recordno, IntPtr.Zero, NativeBuffer.HandleValueToTrace(bufp), bufp.Length, (int)hndlp.HandleType);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIErrorGet(hndlp, checked((uint)recordno), IntPtr.Zero, out errcodep, bufp, (uint)bufp.Length, hndlp.HandleType);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIErrorGet|ADV|OCI|RET>         errcodep=%d rc=%d\n\t%ls\n\n", errcodep, num, hndlp.PtrToString(bufp));
			}
			return num;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static int OCIHandleAlloc(OciHandle parenth, out IntPtr hndlpp, OCI.HTYPE type)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCIHandleAlloc(parenth, out hndlpp, type, 0u, IntPtr.Zero);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIHandleAlloc|ADV|OCI|RET>      parenth=0x%-07Ix type=%3d xtramemsz=%d usrmempp=0x%-07Ix hndlpp=0x%-07Ix rc=%d\n", parenth, (int)type, 0, IntPtr.Zero, hndlpp, num);
			}
			return num;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static int OCIHandleFree(IntPtr hndlp, OCI.HTYPE type)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIHandleFree|ADV|OCI>           hndlp=0x%-07Ix type=%3d\n", hndlp, (int)type);
			}
			return System.Data.Common.UnsafeNativeMethods.OCIHandleFree(hndlp, type);
		}

		internal static int OCILobAppend(OciHandle svchp, OciHandle errhp, OciHandle dst_locp, OciHandle src_locp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobAppend|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix dst_locp=0x%-07Ix src_locp=%Id\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(dst_locp), OciHandle.HandleValueToTrace(src_locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobAppend(svchp, errhp, dst_locp, src_locp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobAppend|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCILobClose(OciHandle svchp, OciHandle errhp, OciHandle locp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oci.OCILobClose|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=%Id\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobClose(svchp, errhp, locp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobClose|ADV|OCI|RET> %d\n", num);
			}
			return num;
		}

		internal static int OCILobCopy(OciHandle svchp, OciHandle errhp, OciHandle dst_locp, OciHandle src_locp, uint amount, uint dst_offset, uint src_offset)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobCopy|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix dst_locp=0x%-07Ix src_locp=0x%-07Ix amount=%u dst_offset=%u src_offset=%u\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(dst_locp), OciHandle.HandleValueToTrace(src_locp), amount, dst_offset, src_offset);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobCopy(svchp, errhp, dst_locp, src_locp, amount, dst_offset, src_offset);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobCopy|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCILobCreateTemporary(OciHandle svchp, OciHandle errhp, OciHandle locp, [In][MarshalAs(UnmanagedType.U2)] ushort csid, [In][MarshalAs(UnmanagedType.U1)] OCI.CHARSETFORM csfrm, [In][MarshalAs(UnmanagedType.U1)] OCI.LOB_TYPE lobtype, int cache, [In][MarshalAs(UnmanagedType.U2)] OCI.DURATION duration)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobCreateTemporary|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=0x%-07Ix csid=%d csfrm=%d{OCI.CHARSETFORM} lobtype=%d{OCI.LOB_TYPE} cache=%d duration=%d{OCI.DURATION}\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp), csid, (int)csfrm, (int)lobtype, cache, (int)duration);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobCreateTemporary(svchp, errhp, locp, csid, csfrm, lobtype, cache, duration);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobCreateTemporary|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCILobErase(OciHandle svchp, OciHandle errhp, OciHandle locp, ref uint amount, uint offset)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobErase|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=0x%-07Ix amount=%d, offset=%d\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp), amount, offset);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobErase(svchp, errhp, locp, ref amount, offset);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobErase|ADV|OCI|RET> amount=%u, rc=%d\n", amount, num);
			}
			return num;
		}

		internal static int OCILobFileExists(OciHandle svchp, OciHandle errhp, OciHandle locp, out int flag)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobFileExists|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=%Id\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobFileExists(svchp, errhp, locp, out flag);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobFileExists|ADV|OCI|RET> flag=%u, rc=%d\n", flag, num);
			}
			return num;
		}

		internal static int OCILobFileGetName(OciHandle envhp, OciHandle errhp, OciHandle filep, IntPtr dir_alias, ref ushort d_length, IntPtr filename, ref ushort f_length)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobFileGetName|ADV|OCI> envhp=0x%-07Ix errhp=0x%-07Ix filep=%Id\n", OciHandle.HandleValueToTrace(envhp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(filep));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobFileGetName(envhp, errhp, filep, dir_alias, ref d_length, filename, ref f_length);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobFileGetName|ADV|OCI|RET> rc=%d, dir_alias='%ls', d_lenght=%d, filename='%ls', f_length=%d\n", num, envhp.PtrToString(dir_alias, d_length), d_length, envhp.PtrToString(filename, f_length), f_length);
			}
			return num;
		}

		internal static int OCILobFileSetName(OciHandle envhp, OciHandle errhp, OciFileDescriptor filep, string dir_alias, string filename)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobFileSetName|ADV|OCI> envhp=0x%-07Ix errhp=0x%-07Ix filep=0x%-07Ix dir_alias='%ls', d_length=%d, filename='%ls', f_length=%d\n", OciHandle.HandleValueToTrace(envhp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(filep), dir_alias, dir_alias.Length, filename, filename.Length);
			}
			byte[] bytes = envhp.GetBytes(dir_alias);
			checked
			{
				ushort dirAliasLength = (ushort)bytes.Length;
				byte[] bytes2 = envhp.GetBytes(filename);
				ushort fileNameLength = (ushort)bytes2.Length;
				int num = filep.OCILobFileSetNameWrapper(envhp, errhp, bytes, dirAliasLength, bytes2, fileNameLength);
				if (Bid.AdvancedOn)
				{
					Bid.Trace("<oc.OCILobFileSetName|ADV|OCI|RET> rc=%d\n", num);
				}
				return num;
			}
		}

		internal static int OCILobFreeTemporary(OciHandle svchp, OciHandle errhp, OciHandle locp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobFreeTemporary|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=%Id\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobFreeTemporary(svchp, errhp, locp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobFreeTemporary|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCILobGetChunkSize(OciHandle svchp, OciHandle errhp, OciHandle locp, out uint lenp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobGetChunkSize|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=%Id\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobGetChunkSize(svchp, errhp, locp, out lenp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobGetChunkSize|ADV|OCI|RET> len=%u, rc=%d\n", lenp, num);
			}
			return num;
		}

		internal static int OCILobGetLength(OciHandle svchp, OciHandle errhp, OciHandle locp, out uint lenp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobGetLength|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=%Id\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobGetLength(svchp, errhp, locp, out lenp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobGetLength|ADV|OCI|RET> len=%u, rc=%d\n", lenp, num);
			}
			return num;
		}

		internal static int OCILobIsOpen(OciHandle svchp, OciHandle errhp, OciHandle locp, out int flag)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobIsOpen|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=%Id\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobIsOpen(svchp, errhp, locp, out flag);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobIsOpen|ADV|OCI|RET> flag=%d, rc=%d\n", flag, num);
			}
			return num;
		}

		internal static int OCILobIsTemporary(OciHandle envhp, OciHandle errhp, OciHandle locp, out int flag)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobIsTemporary|ADV|OCI> envhp=0x%-07Ix errhp=0x%-07Ix locp=%Id\n", OciHandle.HandleValueToTrace(envhp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobIsTemporary(envhp, errhp, locp, out flag);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobIsTemporary|ADV|OCI|RET> flag=%d, rc=%d\n", flag, num);
			}
			return num;
		}

		internal static int OCILobLoadFromFile(OciHandle svchp, OciHandle errhp, OciHandle dst_locp, OciHandle src_locp, uint amount, uint dst_offset, uint src_offset)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobLoadFromFile|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix dst_locp=0x%-07Ix src_locp=0x%-07Ix amount=%u dst_offset=%u src_offset=%u\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(dst_locp), OciHandle.HandleValueToTrace(src_locp), amount, dst_offset, src_offset);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobLoadFromFile(svchp, errhp, dst_locp, src_locp, amount, dst_offset, src_offset);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobLoadFromFile|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCILobOpen(OciHandle svchp, OciHandle errhp, OciHandle locp, byte mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobOpen|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=0x%-07Ix mode=%d\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp), mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobOpen(svchp, errhp, locp, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobOpen|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCILobRead(OciHandle svchp, OciHandle errhp, OciHandle locp, ref int amtp, uint offset, IntPtr bufp, uint bufl, ushort csid, OCI.CHARSETFORM csfrm)
		{
			uint amtp2 = checked((uint)amtp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobRead|ADV|OCI>              svchp=0x%-07Ix errhp=0x%-07Ix locp=0x%-07Ix amt=%-4d offset=%-6u bufp=0x%-07Ix bufl=%-4d ctxp=0x%-07Ix cbfp=0x%-07Ix csid=%-4d csfrm=%d{OCI.CHARSETFORM}\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp), amtp, offset, bufp, (int)bufl, IntPtr.Zero, IntPtr.Zero, csid, (int)csfrm);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobRead(svchp, errhp, locp, ref amtp2, offset, bufp, bufl, IntPtr.Zero, IntPtr.Zero, csid, csfrm);
			amtp = checked((int)amtp2);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobRead|ADV|OCI|RET>          amt=%-4d rc=%d\n", amtp, num);
			}
			return num;
		}

		internal static int OCILobTrim(OciHandle svchp, OciHandle errhp, OciHandle locp, uint newlen)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobTrim|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=0x%-07Ix newlen=%d\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp), newlen);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobTrim(svchp, errhp, locp, newlen);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobTrim|ADV|OCI|RET> rc=%d\n", num);
			}
			return num;
		}

		internal static int OCILobWrite(OciHandle svchp, OciHandle errhp, OciHandle locp, ref int amtp, uint offset, IntPtr bufp, uint buflen, byte piece, ushort csid, OCI.CHARSETFORM csfrm)
		{
			uint amtp2 = checked((uint)amtp);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobWrite|ADV|OCI> svchp=0x%-07Ix errhp=0x%-07Ix locp=0x%-07Ix amt=%d offset=%u bufp=0x%-07Ix buflen=%d piece=%d{Byte} ctxp=0x%-07Ix cbfp=0x%-07Ix csid=%d csfrm=%d{OCI.CHARSETFORM}\n", OciHandle.HandleValueToTrace(svchp), OciHandle.HandleValueToTrace(errhp), OciHandle.HandleValueToTrace(locp), amtp, offset, bufp, (int)buflen, piece, IntPtr.Zero, IntPtr.Zero, csid, (int)csfrm);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCILobWrite(svchp, errhp, locp, ref amtp2, offset, bufp, buflen, piece, IntPtr.Zero, IntPtr.Zero, csid, csfrm);
			amtp = checked((int)amtp2);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCILobWrite|ADV|OCI|RET> amt=%d, rc=%d\n", amtp, num);
			}
			return num;
		}

		internal static int OCIParamGet(OciHandle hndlp, OCI.HTYPE hType, OciHandle errhp, out IntPtr paramdpp, int pos)
		{
			int num = System.Data.Common.UnsafeNativeMethods.OCIParamGet(hndlp, hType, errhp, out paramdpp, checked((uint)pos));
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIParamGet|ADV|OCI|RET>         hndlp=0x%-07Ix htype=%-18ls errhp=0x%-07Ix pos=%d paramdpp=0x%-07Ix rc=%d\n", hndlp, hType, errhp, pos, paramdpp, num);
			}
			return num;
		}

		internal static int OCIRowidToChar(OciHandle rowidDesc, NativeBuffer outbfp, ref int bufferLength, OciHandle errhp)
		{
			ushort outbflp = checked((ushort)bufferLength);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIRowidToChar|ADV|OCI>          rowidDesc=0x%-07Ix outbfp=0x%-07Ix outbflp=%d, errhp=0x%-07Ix\n", OciHandle.HandleValueToTrace(rowidDesc), NativeBuffer.HandleValueToTrace(outbfp), outbfp.Length, OciHandle.HandleValueToTrace(errhp));
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIRowidToChar(rowidDesc, outbfp, ref outbflp, errhp);
			bufferLength = outbflp;
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIRowidToChar|ADV|OCI|RET>      outbfp='%ls' rc=%d\n", outbfp.PtrToStringAnsi(0, outbflp), num);
			}
			return num;
		}

		internal static int OCIServerAttach(OciHandle srvhp, OciHandle errhp, string dblink, int dblink_len, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIServerAttach|ADV|OCI>         srvhp=0x%-07Ix errhp=0x%-07Ix dblink='%ls' dblink_len=%d mode=0x%x{OCI.MODE}\n", srvhp, errhp, dblink, dblink_len, (int)mode);
			}
			byte[] bytes = srvhp.GetBytes(dblink);
			int dblink_len2 = bytes.Length;
			int num = System.Data.Common.UnsafeNativeMethods.OCIServerAttach(srvhp, errhp, bytes, dblink_len2, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIServerAttach|ADV|OCI|RET>     rc=%d\n", num);
			}
			return num;
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static int OCIServerDetach(IntPtr srvhp, IntPtr errhp, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIServerDetach|ADV|OCI>        srvhp=0x%-07Ix errhp=0x%-07Ix mode=0x%x{OCI.MODE}\n", srvhp, errhp, (int)mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIServerDetach(srvhp, errhp, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIServerDetach|ADV|OCI|RET>    rc=%d\n", num);
			}
			return num;
		}

		internal static int OCIServerVersion(OciHandle hndlp, OciHandle errhp, NativeBuffer bufp)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIServerVersion|ADV|OCI>        hndlp=0x%-07Ix errhp=0x%-07Ix bufp=0x%-07Ix bufsz=%d hndltype=%d{OCI.HTYPE}\n", OciHandle.HandleValueToTrace(hndlp), OciHandle.HandleValueToTrace(errhp), NativeBuffer.HandleValueToTrace(bufp), bufp.Length, (int)hndlp.HandleType);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIServerVersion(hndlp, errhp, bufp, (uint)bufp.Length, (byte)hndlp.HandleType);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIServerVersion|ADV|OCI|RET>    rc=%d\n%ls\n\n", num, hndlp.PtrToString(bufp));
			}
			return num;
		}

		internal static int OCISessionBegin(OciHandle svchp, OciHandle errhp, OciHandle usrhp, OCI.CRED credt, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCISessionBegin|ADV|OCI>         svchp=0x%-07Ix errhp=0x%-07Ix usrhp=0x%-07Ix credt=%s mode=0x%x{OCI.MODE}\n", svchp, errhp, usrhp, credt, (int)mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCISessionBegin(svchp, errhp, usrhp, credt, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCISessionBegin|ADV|OCI|RET>     rc=%d\n", num);
			}
			return num;
		}

		internal static int OCISessionEnd(IntPtr svchp, IntPtr errhp, IntPtr usrhp, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCISessionEnd|ADV|OCI>           svchp=0x%-07Ix errhp=0x%-07Ix usrhp=0x%-07Ix mode=0x%x{OCI.MODE}\n", svchp, errhp, usrhp, (int)mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCISessionEnd(svchp, errhp, usrhp, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCISessionEnd|ADV|OCI|RET>       rc=%d\n", num);
			}
			return num;
		}

		internal static int OCIStmtExecute(OciHandle svchp, OciHandle stmtp, OciHandle errhp, int iters, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIStmtExecute|ADV|OCI>          svchp=0x%-07Ix stmtp=0x%-07Ix errhp=0x%-07Ix iters=%d rowoff=%d snap_in=0x%-07Ix snap_out=0x%-07Ix mode=0x%x{OCI.MODE}\n", svchp, stmtp, errhp, iters, 0, IntPtr.Zero, IntPtr.Zero, (int)mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIStmtExecute(svchp, stmtp, errhp, checked((uint)iters), 0u, IntPtr.Zero, IntPtr.Zero, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIStmtExecute|ADV|OCI|RET>      rc=%d\n", num);
			}
			return num;
		}

		internal static int OCIStmtFetch(OciHandle stmtp, OciHandle errhp, int nrows, OCI.FETCH orientation, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIStmtFetch|ADV|OCI>            stmtp=0x%-07Ix errhp=0x%-07Ix nrows=%d orientation=%d{OCI.FETCH}, mode=0x%x{OCI.MODE}\n", stmtp, errhp, nrows, (int)orientation, (int)mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCIStmtFetch(stmtp, errhp, checked((uint)nrows), orientation, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIStmtFetch|ADV|OCI|RET>        rc=%d\n", num);
			}
			return num;
		}

		internal static int OCIStmtPrepare(OciHandle stmtp, OciHandle errhp, string stmt, OCI.SYNTAX language, OCI.MODE mode, OracleConnection connection)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIStmtPrepare|ADV|OCI>          stmtp=0x%-07Ix errhp=0x%-07Ix stmt_len=%d language=%d{OCI.SYNTAX} mode=0x%x{OCI.MODE}\n\t\t%ls\n\n", stmtp, errhp, stmt.Length, (int)language, (int)mode, stmt);
			}
			byte[] bytes = connection.GetBytes(stmt, useNationalCharacterSet: false);
			uint stmt_len = (uint)bytes.Length;
			int num = System.Data.Common.UnsafeNativeMethods.OCIStmtPrepare(stmtp, errhp, bytes, stmt_len, language, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCIStmtPrepare|ADV|OCI|RET>      rc=%d\n", num);
			}
			return num;
		}

		internal static int OCITransCommit(OciHandle srvhp, OciHandle errhp, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCITransCommit|ADV|OCI>          srvhp=0x%-07Ix errhp=0x%-07Ix mode=0x%x{OCI.MODE}\n", OciHandle.HandleValueToTrace(srvhp), OciHandle.HandleValueToTrace(errhp), (int)mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCITransCommit(srvhp, errhp, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCITransCommit|ADV|OCI|RET>      rc=%d\n", num);
			}
			return num;
		}

		internal static int OCITransRollback(OciHandle srvhp, OciHandle errhp, OCI.MODE mode)
		{
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCITransRollback|ADV|OCI>         srvhp=0x%-07Ix errhp=0x%-07Ix mode=0x%x{OCI.MODE}\n", OciHandle.HandleValueToTrace(srvhp), OciHandle.HandleValueToTrace(errhp), (int)mode);
			}
			int num = System.Data.Common.UnsafeNativeMethods.OCITransRollback(srvhp, errhp, mode);
			if (Bid.AdvancedOn)
			{
				Bid.Trace("<oc.OCITransRollback|ADV|OCI|RET>      rc=%d\n", num);
			}
			return num;
		}
	}
}
namespace System.Data.Common
{
	[SuppressUnmanagedCodeSecurity]
	internal sealed class UnsafeNativeMethods
	{
		private UnsafeNativeMethods()
		{
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool CheckTokenMembership(IntPtr tokenHandle, byte[] sidToCheck, out bool isMember);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern int CreateWellKnownSid(int sidType, byte[] domainSid, [Out] byte[] resultSid, ref uint resultSidLength);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool GetTokenInformation(IntPtr tokenHandle, uint token_class, IntPtr tokenStruct, uint tokenInformationLength, ref uint tokenString);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool IsTokenRestricted(IntPtr tokenHandle);

		[DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
		internal static extern int lstrlenA(IntPtr ptr);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		internal static extern int lstrlenW(IntPtr ptr);

		[DllImport("kernel32.dll")]
		internal static extern void SetLastError(int dwErrCode);

		[DllImport("oramts.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern int OraMTSEnlCtxGet([In][MarshalAs(UnmanagedType.LPArray)] byte[] lpUname, [In][MarshalAs(UnmanagedType.LPArray)] byte[] lpPsswd, [In][MarshalAs(UnmanagedType.LPArray)] byte[] lpDbnam, OciHandle pOCISvc, OciHandle pOCIErr, uint dwFlags, out IntPtr pCtxt);

		[DllImport("oramts.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern int OraMTSEnlCtxRel(IntPtr pCtxt);

		[DllImport("oramts.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OraMTSOCIErrGet(ref int dwErr, NativeBuffer lpcEMsg, ref int lpdLen);

		[DllImport("oramts.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OraMTSJoinTxn(OciEnlistContext pCtxt, IDtcTransaction pTrans);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int oermsg(short rcode, NativeBuffer buf);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIAttrGet(OciHandle trgthndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE trghndltyp, OciHandle attributep, out uint sizep, [In][MarshalAs(UnmanagedType.U4)] OCI.ATTR attrtype, OciHandle errhp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIAttrGet(OciHandle trgthndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE trghndltyp, out int attributep, out uint sizep, [In][MarshalAs(UnmanagedType.U4)] OCI.ATTR attrtype, OciHandle errhp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIAttrGet(OciHandle trgthndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE trghndltyp, ref IntPtr attributep, ref uint sizep, [In][MarshalAs(UnmanagedType.U4)] OCI.ATTR attrtype, OciHandle errhp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIAttrSet(OciHandle trgthndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE trghndltyp, OciHandle attributep, uint size, [In][MarshalAs(UnmanagedType.U4)] OCI.ATTR attrtype, OciHandle errhp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIAttrSet(OciHandle trgthndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE trghndltyp, ref int attributep, uint size, [In][MarshalAs(UnmanagedType.U4)] OCI.ATTR attrtype, OciHandle errhp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIAttrSet(OciHandle trgthndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE trghndltyp, [In][MarshalAs(UnmanagedType.LPArray)] byte[] attributep, uint size, [In][MarshalAs(UnmanagedType.U4)] OCI.ATTR attrtype, OciHandle errhp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIBindByName(OciHandle stmtp, out IntPtr bindpp, OciHandle errhp, [In][MarshalAs(UnmanagedType.LPArray)] byte[] placeholder, int placeh_len, IntPtr valuep, int value_sz, [In][MarshalAs(UnmanagedType.U2)] OCI.DATATYPE dty, IntPtr indp, IntPtr alenp, IntPtr rcodep, uint maxarr_len, IntPtr curelap, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCICharSetToUnicode(OciHandle hndl, IntPtr dst, uint dstsz, IntPtr src, uint srcsz, out uint size);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIDateTimeFromArray(OciHandle hndl, OciHandle err, [In][MarshalAs(UnmanagedType.LPArray)] byte[] inarray, uint len, byte type, OciHandle datetime, OciHandle reftz, byte fsprec);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIDateTimeToArray(OciHandle hndl, OciHandle err, OciHandle datetime, OciHandle reftz, [In][MarshalAs(UnmanagedType.LPArray)] byte[] outarray, ref uint len, byte fsprec);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIDateTimeGetTimeZoneOffset(OciHandle hndl, OciHandle err, OciHandle datetime, out sbyte hour, out sbyte min);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIDefineArrayOfStruct(OciHandle defnp, OciHandle errhp, uint pvskip, uint indskip, uint rlskip, uint rcskip);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIDefineByPos(OciHandle stmtp, out IntPtr hndlpp, OciHandle errhp, uint position, IntPtr valuep, int value_sz, [In][MarshalAs(UnmanagedType.U2)] OCI.DATATYPE dty, IntPtr indp, IntPtr alenp, IntPtr rcodep, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIDefineDynamic(OciHandle defnp, OciHandle errhp, IntPtr octxp, OCI.Callback.OCICallbackDefine ocbfp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern int OCIDescriptorAlloc(OciHandle parenth, out IntPtr descp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE type, uint xtramem_sz, IntPtr usrmempp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern int OCIDescriptorFree(IntPtr hndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE type);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIEnvCreate(out IntPtr envhpp, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode, IntPtr ctxp, IntPtr malocfp, IntPtr ralocfp, IntPtr mfreefp, uint xtramemsz, IntPtr usrmempp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIEnvNlsCreate(out IntPtr envhpp, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode, IntPtr ctxp, IntPtr malocfp, IntPtr ralocfp, IntPtr mfreefp, uint xtramemsz, IntPtr usrmempp, ushort charset, ushort ncharset);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIErrorGet(OciHandle hndlp, uint recordno, IntPtr sqlstate, out int errcodep, NativeBuffer bufp, uint bufsiz, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE type);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern int OCIHandleAlloc(OciHandle parenth, out IntPtr hndlpp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE type, uint xtramemsz, IntPtr usrmempp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern int OCIHandleFree(IntPtr hndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE type);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobAppend(OciHandle svchp, OciHandle errhp, OciHandle dst_locp, OciHandle src_locp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobClose(OciHandle svchp, OciHandle errhp, OciHandle locp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobCopy(OciHandle svchp, OciHandle errhp, OciHandle dst_locp, OciHandle src_locp, uint amount, uint dst_offset, uint src_offset);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobCopy2(IntPtr svchp, IntPtr errhp, IntPtr dst_locp, IntPtr src_locp, ulong amount, ulong dst_offset, ulong src_offset);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobCreateTemporary(OciHandle svchp, OciHandle errhp, OciHandle locp, ushort csid, [In][MarshalAs(UnmanagedType.U1)] OCI.CHARSETFORM csfrm, [In][MarshalAs(UnmanagedType.U1)] OCI.LOB_TYPE lobtype, int cache, [In][MarshalAs(UnmanagedType.U2)] OCI.DURATION duration);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobErase(OciHandle svchp, OciHandle errhp, OciHandle locp, ref uint amount, uint offset);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobFileExists(OciHandle svchp, OciHandle errhp, OciHandle locp, out int flag);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobFileGetName(OciHandle envhp, OciHandle errhp, OciHandle filep, IntPtr dir_alias, ref ushort d_length, IntPtr filename, ref ushort f_length);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
		internal static extern int OCILobFileSetName(OciHandle envhp, OciHandle errhp, ref IntPtr filep, [In][MarshalAs(UnmanagedType.LPArray)] byte[] dir_alias, ushort d_length, [In][MarshalAs(UnmanagedType.LPArray)] byte[] filename, ushort f_length);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobFreeTemporary(OciHandle svchp, OciHandle errhp, OciHandle locp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobGetChunkSize(OciHandle svchp, OciHandle errhp, OciHandle locp, out uint lenp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobGetLength(OciHandle svchp, OciHandle errhp, OciHandle locp, out uint lenp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobIsOpen(OciHandle svchp, OciHandle errhp, OciHandle locp, out int flag);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobIsTemporary(OciHandle envhp, OciHandle errhp, OciHandle locp, out int flag);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobLoadFromFile(OciHandle svchp, OciHandle errhp, OciHandle dst_locp, OciHandle src_locp, uint amount, uint dst_offset, uint src_offset);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobOpen(OciHandle svchp, OciHandle errhp, OciHandle locp, byte mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobRead(OciHandle svchp, OciHandle errhp, OciHandle locp, ref uint amtp, uint offset, IntPtr bufp, uint bufl, IntPtr ctxp, IntPtr cbfp, ushort csid, [In][MarshalAs(UnmanagedType.U1)] OCI.CHARSETFORM csfrm);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobTrim(OciHandle svchp, OciHandle errhp, OciHandle locp, uint newlen);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCILobWrite(OciHandle svchp, OciHandle errhp, OciHandle locp, ref uint amtp, uint offset, IntPtr bufp, uint buflen, byte piece, IntPtr ctxp, IntPtr cbfp, ushort csid, [In][MarshalAs(UnmanagedType.U1)] OCI.CHARSETFORM csfrm);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberAbs(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberAdd(OciHandle err, byte[] number1, byte[] number2, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberArcCos(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberArcSin(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberArcTan(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberArcTan2(OciHandle err, byte[] number1, byte[] number2, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberCeil(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberCmp(OciHandle err, byte[] number1, byte[] number2, out int result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberCos(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberDiv(OciHandle err, byte[] number1, byte[] number2, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberExp(OciHandle err, byte[] p, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberFloor(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberFromInt(OciHandle err, ref int inum, uint inum_length, OCI.SIGN inum_s_flag, byte[] number);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberFromInt(OciHandle err, ref uint inum, uint inum_length, [In][MarshalAs(UnmanagedType.U4)] OCI.SIGN inum_s_flag, byte[] number);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberFromInt(OciHandle err, ref long inum, uint inum_length, [In][MarshalAs(UnmanagedType.U4)] OCI.SIGN inum_s_flag, byte[] number);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberFromInt(OciHandle err, ref ulong inum, uint inum_length, [In][MarshalAs(UnmanagedType.U4)] OCI.SIGN inum_s_flag, byte[] number);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberFromReal(OciHandle err, ref double rnum, uint rnum_length, byte[] number);

		[DllImport("oci.dll", BestFitMapping = false, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true)]
		internal static extern int OCINumberFromText(OciHandle err, [In][MarshalAs(UnmanagedType.LPStr)] string str, uint str_length, [In][MarshalAs(UnmanagedType.LPStr)] string fmt, uint fmt_length, IntPtr nls_params, uint nls_p_length, byte[] number);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberHypCos(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberHypSin(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberHypTan(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberIntPower(OciHandle err, byte[] baseNumber, int exponent, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberIsInt(OciHandle err, byte[] number, out int result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberLn(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberLog(OciHandle err, byte[] b, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberMod(OciHandle err, byte[] number1, byte[] number2, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberMul(OciHandle err, byte[] number1, byte[] number2, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberNeg(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberPower(OciHandle err, byte[] baseNumber, byte[] exponent, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberRound(OciHandle err, byte[] number, int decplace, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberShift(OciHandle err, byte[] baseNumber, int nDig, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberSign(OciHandle err, byte[] number, out int result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberSin(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberSqrt(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberSub(OciHandle err, byte[] number1, byte[] number2, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberTan(OciHandle err, byte[] number, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberToInt(OciHandle err, byte[] number, uint rsl_length, [In][MarshalAs(UnmanagedType.U4)] OCI.SIGN rsl_flag, out int rsl);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberToInt(OciHandle err, byte[] number, uint rsl_length, [In][MarshalAs(UnmanagedType.U4)] OCI.SIGN rsl_flag, out uint rsl);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberToInt(OciHandle err, byte[] number, uint rsl_length, [In][MarshalAs(UnmanagedType.U4)] OCI.SIGN rsl_flag, out long rsl);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberToInt(OciHandle err, byte[] number, uint rsl_length, [In][MarshalAs(UnmanagedType.U4)] OCI.SIGN rsl_flag, out ulong rsl);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberToReal(OciHandle err, byte[] number, uint rsl_length, out double rsl);

		[DllImport("oci.dll", BestFitMapping = false, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true)]
		internal static extern int OCINumberToText(OciHandle err, byte[] number, [In][MarshalAs(UnmanagedType.LPStr)] string fmt, int fmt_length, IntPtr nls_params, uint nls_p_length, ref uint buf_size, [In][Out][MarshalAs(UnmanagedType.LPArray)] byte[] buffer);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCINumberTrunc(OciHandle err, byte[] number, int decplace, byte[] result);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIParamGet(OciHandle hndlp, [In][MarshalAs(UnmanagedType.U4)] OCI.HTYPE htype, OciHandle errhp, out IntPtr paramdpp, uint pos);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIRowidToChar(OciHandle rowidDesc, NativeBuffer outbfp, ref ushort outbflp, OciHandle errhp);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIServerAttach(OciHandle srvhp, OciHandle errhp, [In][MarshalAs(UnmanagedType.LPArray)] byte[] dblink, int dblink_len, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern int OCIServerDetach(IntPtr srvhp, IntPtr errhp, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIServerVersion(OciHandle hndlp, OciHandle errhp, NativeBuffer bufp, uint bufsz, [In][MarshalAs(UnmanagedType.U1)] byte hndltype);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCISessionBegin(OciHandle svchp, OciHandle errhp, OciHandle usrhp, [In][MarshalAs(UnmanagedType.U4)] OCI.CRED credt, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCISessionEnd(IntPtr svchp, IntPtr errhp, IntPtr usrhp, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIStmtExecute(OciHandle svchp, OciHandle stmtp, OciHandle errhp, uint iters, uint rowoff, IntPtr snap_in, IntPtr snap_out, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIStmtFetch(OciHandle stmtp, OciHandle errhp, uint nrows, [In][MarshalAs(UnmanagedType.U2)] OCI.FETCH orientation, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIStmtPrepare(OciHandle stmtp, OciHandle errhp, [In][MarshalAs(UnmanagedType.LPArray)] byte[] stmt, uint stmt_len, [In][MarshalAs(UnmanagedType.U4)] OCI.SYNTAX language, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE mode);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCITransCommit(OciHandle svchp, OciHandle errhp, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE flags);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCITransRollback(OciHandle svchp, OciHandle errhp, [In][MarshalAs(UnmanagedType.U4)] OCI.MODE flags);

		[DllImport("oci.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int OCIUnicodeToCharSet(OciHandle hndl, IntPtr dst, uint dstsz, IntPtr src, uint srcsz, out uint size);
	}
}
namespace System.Data.ProviderBase
{
	internal sealed class FieldNameLookup
	{
		private Hashtable _fieldNameLookup;

		private string[] _fieldNames;

		private CompareInfo _compareInfo;

		private int _defaultLocaleID;

		public FieldNameLookup(IDataReader reader, int defaultLocaleID)
		{
			int fieldCount = reader.FieldCount;
			string[] array = new string[fieldCount];
			for (int i = 0; i < fieldCount; i++)
			{
				array[i] = reader.GetName(i);
			}
			_fieldNames = array;
			_defaultLocaleID = defaultLocaleID;
		}

		public int GetOrdinal(string fieldName)
		{
			if (fieldName == null)
			{
				throw System.Data.Common.ADP.ArgumentNull("fieldName");
			}
			int num = IndexOf(fieldName);
			if (-1 == num)
			{
				throw System.Data.Common.ADP.IndexOutOfRange(fieldName);
			}
			return num;
		}

		public int IndexOf(string fieldName)
		{
			if (_fieldNameLookup == null)
			{
				GenerateLookup();
			}
			object obj = _fieldNameLookup[fieldName];
			int num;
			if (obj != null)
			{
				num = (int)obj;
			}
			else
			{
				num = LinearIndexOf(fieldName, CompareOptions.IgnoreCase);
				if (-1 == num)
				{
					num = LinearIndexOf(fieldName, CompareOptions.IgnoreCase | CompareOptions.IgnoreKanaType | CompareOptions.IgnoreWidth);
				}
			}
			return num;
		}

		private int LinearIndexOf(string fieldName, CompareOptions compareOptions)
		{
			CompareInfo compareInfo = _compareInfo;
			if (compareInfo == null)
			{
				if (-1 != _defaultLocaleID)
				{
					compareInfo = CompareInfo.GetCompareInfo(_defaultLocaleID);
				}
				if (compareInfo == null)
				{
					compareInfo = CultureInfo.InvariantCulture.CompareInfo;
				}
				_compareInfo = compareInfo;
			}
			int num = _fieldNames.Length;
			for (int i = 0; i < num; i++)
			{
				if (compareInfo.Compare(fieldName, _fieldNames[i], compareOptions) == 0)
				{
					_fieldNameLookup[fieldName] = i;
					return i;
				}
			}
			return -1;
		}

		private void GenerateLookup()
		{
			int num = _fieldNames.Length;
			Hashtable hashtable = new Hashtable(num);
			int num2 = num - 1;
			while (0 <= num2)
			{
				string key = _fieldNames[num2];
				hashtable[key] = num2;
				num2--;
			}
			_fieldNameLookup = hashtable;
		}
	}
}
namespace System.Data.OracleClient
{
	[Serializable]
	internal sealed class NameValuePair
	{
		private readonly string _name;

		private readonly string _value;

		[OptionalField(VersionAdded = 2)]
		private readonly int _length;

		private NameValuePair _next;

		internal int Length => _length;

		internal string Name => _name;

		internal NameValuePair Next
		{
			get
			{
				return _next;
			}
			set
			{
				if (_next != null || value == null)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.NameValuePairNext);
				}
				_next = value;
			}
		}

		internal string Value => _value;

		internal NameValuePair(string name, string value, int length)
		{
			_name = name;
			_value = value;
			_length = length;
		}
	}
	[Serializable]
	internal sealed class NameValuePermission : IComparable
	{
		private string _value;

		private DBConnectionString _entry;

		private NameValuePermission[] _tree;

		internal static readonly NameValuePermission Default;

		internal NameValuePermission()
		{
		}

		private NameValuePermission(string keyword)
		{
			_value = keyword;
		}

		private NameValuePermission(string value, DBConnectionString entry)
		{
			_value = value;
			_entry = entry;
		}

		private NameValuePermission(NameValuePermission permit)
		{
			_value = permit._value;
			_entry = permit._entry;
			_tree = permit._tree;
			if (_tree == null)
			{
				return;
			}
			NameValuePermission[] array = _tree.Clone() as NameValuePermission[];
			for (int i = 0; i < array.Length; i++)
			{
				if (array[i] != null)
				{
					array[i] = array[i].CopyNameValue();
				}
			}
			_tree = array;
		}

		int IComparable.CompareTo(object a)
		{
			return StringComparer.Ordinal.Compare(_value, ((NameValuePermission)a)._value);
		}

		internal static void AddEntry(NameValuePermission kvtree, ArrayList entries, DBConnectionString entry)
		{
			if (entry.KeyChain != null)
			{
				for (NameValuePair nameValuePair = entry.KeyChain; nameValuePair != null; nameValuePair = nameValuePair.Next)
				{
					NameValuePermission nameValuePermission = kvtree.CheckKeyForValue(nameValuePair.Name);
					if (nameValuePermission == null)
					{
						nameValuePermission = new NameValuePermission(nameValuePair.Name);
						kvtree.Add(nameValuePermission);
					}
					kvtree = nameValuePermission;
					nameValuePermission = kvtree.CheckKeyForValue(nameValuePair.Value);
					if (nameValuePermission == null)
					{
						DBConnectionString dBConnectionString = ((nameValuePair.Next != null) ? null : entry);
						nameValuePermission = new NameValuePermission(nameValuePair.Value, dBConnectionString);
						kvtree.Add(nameValuePermission);
						if (dBConnectionString != null)
						{
							entries.Add(dBConnectionString);
						}
					}
					else if (nameValuePair.Next == null)
					{
						if (nameValuePermission._entry != null)
						{
							entries.Remove(nameValuePermission._entry);
							nameValuePermission._entry = nameValuePermission._entry.Intersect(entry);
						}
						else
						{
							nameValuePermission._entry = entry;
						}
						entries.Add(nameValuePermission._entry);
					}
					kvtree = nameValuePermission;
				}
			}
			else
			{
				DBConnectionString entry2 = kvtree._entry;
				if (entry2 != null)
				{
					entries.Remove(entry2);
					kvtree._entry = entry2.Intersect(entry);
				}
				else
				{
					kvtree._entry = entry;
				}
				entries.Add(kvtree._entry);
			}
		}

		internal void Intersect(ArrayList entries, NameValuePermission target)
		{
			if (target == null)
			{
				_tree = null;
				_entry = null;
				return;
			}
			if (_entry != null)
			{
				entries.Remove(_entry);
				_entry = _entry.Intersect(target._entry);
				entries.Add(_entry);
			}
			else if (target._entry != null)
			{
				_entry = target._entry.Intersect(null);
				entries.Add(_entry);
			}
			if (_tree == null)
			{
				return;
			}
			int num = _tree.Length;
			for (int i = 0; i < _tree.Length; i++)
			{
				NameValuePermission nameValuePermission = target.CheckKeyForValue(_tree[i]._value);
				if (nameValuePermission != null)
				{
					_tree[i].Intersect(entries, nameValuePermission);
					continue;
				}
				_tree[i] = null;
				num--;
			}
			if (num == 0)
			{
				_tree = null;
			}
			else
			{
				if (num >= _tree.Length)
				{
					return;
				}
				NameValuePermission[] array = new NameValuePermission[num];
				int j = 0;
				int num2 = 0;
				for (; j < _tree.Length; j++)
				{
					if (_tree[j] != null)
					{
						array[num2++] = _tree[j];
					}
				}
				_tree = array;
			}
		}

		private void Add(NameValuePermission permit)
		{
			NameValuePermission[] tree = _tree;
			int num = ((tree != null) ? tree.Length : 0);
			NameValuePermission[] array = new NameValuePermission[1 + num];
			for (int i = 0; i < array.Length - 1; i++)
			{
				array[i] = tree[i];
			}
			array[num] = permit;
			Array.Sort(array);
			_tree = array;
		}

		internal bool CheckValueForKeyPermit(DBConnectionString parsetable)
		{
			if (parsetable == null)
			{
				return false;
			}
			bool flag = false;
			NameValuePermission[] tree = _tree;
			if (tree != null)
			{
				flag = parsetable.IsEmpty;
				if (!flag)
				{
					foreach (NameValuePermission nameValuePermission in tree)
					{
						if (nameValuePermission == null)
						{
							continue;
						}
						string value = nameValuePermission._value;
						if (parsetable.ContainsKey(value))
						{
							string keyInQuestion = parsetable[value];
							NameValuePermission nameValuePermission2 = nameValuePermission.CheckKeyForValue(keyInQuestion);
							if (nameValuePermission2 == null)
							{
								return false;
							}
							if (!nameValuePermission2.CheckValueForKeyPermit(parsetable))
							{
								return false;
							}
							flag = true;
						}
					}
				}
			}
			DBConnectionString entry = _entry;
			if (entry != null)
			{
				flag = entry.IsSupersetOf(parsetable);
			}
			return flag;
		}

		private NameValuePermission CheckKeyForValue(string keyInQuestion)
		{
			NameValuePermission[] tree = _tree;
			if (tree != null)
			{
				foreach (NameValuePermission nameValuePermission in tree)
				{
					if (string.Equals(keyInQuestion, nameValuePermission._value, StringComparison.OrdinalIgnoreCase))
					{
						return nameValuePermission;
					}
				}
			}
			return null;
		}

		internal NameValuePermission CopyNameValue()
		{
			return new NameValuePermission(this);
		}
	}
	[Serializable]
	internal sealed class DBConnectionString
	{
		private readonly string _encryptedUsersConnectionString;

		private readonly Hashtable _parsetable;

		private readonly NameValuePair _keychain;

		private readonly bool _hasPassword;

		private readonly string[] _restrictionValues;

		private readonly string _restrictions;

		private readonly KeyRestrictionBehavior _behavior;

		private readonly string _encryptedActualConnectionString;

		internal KeyRestrictionBehavior Behavior => _behavior;

		internal string ConnectionString => _encryptedUsersConnectionString;

		internal bool IsEmpty => null == _keychain;

		internal NameValuePair KeyChain => _keychain;

		internal string Restrictions
		{
			get
			{
				string text = _restrictions;
				if (text == null)
				{
					string[] restrictionValues = _restrictionValues;
					if (restrictionValues != null && 0 < restrictionValues.Length)
					{
						StringBuilder stringBuilder = new StringBuilder();
						for (int i = 0; i < restrictionValues.Length; i++)
						{
							if (!System.Data.Common.ADP.IsEmpty(restrictionValues[i]))
							{
								stringBuilder.Append(restrictionValues[i]);
								stringBuilder.Append("=;");
							}
						}
						text = stringBuilder.ToString();
					}
				}
				if (text == null)
				{
					return "";
				}
				return text;
			}
		}

		internal string this[string keyword] => (string)_parsetable[keyword];

		internal DBConnectionString(string value, string restrictions, KeyRestrictionBehavior behavior, Hashtable synonyms, bool useOdbcRules)
			: this(new System.Data.Common.DbConnectionOptions(value, synonyms, useOdbcRules), restrictions, behavior, synonyms, mustCloneDictionary: false)
		{
		}

		internal DBConnectionString(System.Data.Common.DbConnectionOptions connectionOptions)
			: this(connectionOptions, null, KeyRestrictionBehavior.AllowOnly, null, mustCloneDictionary: true)
		{
		}

		private DBConnectionString(System.Data.Common.DbConnectionOptions connectionOptions, string restrictions, KeyRestrictionBehavior behavior, Hashtable synonyms, bool mustCloneDictionary)
		{
			switch (behavior)
			{
			case KeyRestrictionBehavior.AllowOnly:
			case KeyRestrictionBehavior.PreventUsage:
				_behavior = behavior;
				_encryptedUsersConnectionString = connectionOptions.UsersConnectionString(hidePassword: false);
				_hasPassword = connectionOptions.HasPasswordKeyword;
				_parsetable = connectionOptions.Parsetable;
				_keychain = connectionOptions.KeyChain;
				if (_hasPassword && !connectionOptions.HasPersistablePassword)
				{
					if (mustCloneDictionary)
					{
						_parsetable = (Hashtable)_parsetable.Clone();
					}
					if (_parsetable.ContainsKey("password"))
					{
						_parsetable["password"] = "*";
					}
					if (_parsetable.ContainsKey("pwd"))
					{
						_parsetable["pwd"] = "*";
					}
					_keychain = connectionOptions.ReplacePasswordPwd(out _encryptedUsersConnectionString, fakePassword: true);
				}
				if (!System.Data.Common.ADP.IsEmpty(restrictions))
				{
					_restrictionValues = ParseRestrictions(restrictions, synonyms);
					_restrictions = restrictions;
				}
				break;
			default:
				throw System.Data.Common.ADP.InvalidKeyRestrictionBehavior(behavior);
			}
		}

		private DBConnectionString(DBConnectionString connectionString, string[] restrictionValues, KeyRestrictionBehavior behavior)
		{
			_encryptedUsersConnectionString = connectionString._encryptedUsersConnectionString;
			_parsetable = connectionString._parsetable;
			_keychain = connectionString._keychain;
			_hasPassword = connectionString._hasPassword;
			_restrictionValues = restrictionValues;
			_restrictions = null;
			_behavior = behavior;
		}

		internal bool ContainsKey(string keyword)
		{
			return _parsetable.ContainsKey(keyword);
		}

		internal DBConnectionString Intersect(DBConnectionString entry)
		{
			KeyRestrictionBehavior behavior = _behavior;
			string[] restrictionValues = null;
			if (entry == null)
			{
				behavior = KeyRestrictionBehavior.AllowOnly;
			}
			else if (_behavior != entry._behavior)
			{
				behavior = KeyRestrictionBehavior.AllowOnly;
				if (entry._behavior == KeyRestrictionBehavior.AllowOnly)
				{
					if (!System.Data.Common.ADP.IsEmptyArray(_restrictionValues))
					{
						if (!System.Data.Common.ADP.IsEmptyArray(entry._restrictionValues))
						{
							restrictionValues = NewRestrictionAllowOnly(entry._restrictionValues, _restrictionValues);
						}
					}
					else
					{
						restrictionValues = entry._restrictionValues;
					}
				}
				else if (!System.Data.Common.ADP.IsEmptyArray(_restrictionValues))
				{
					restrictionValues = (System.Data.Common.ADP.IsEmptyArray(entry._restrictionValues) ? _restrictionValues : NewRestrictionAllowOnly(_restrictionValues, entry._restrictionValues));
				}
			}
			else if (KeyRestrictionBehavior.PreventUsage == _behavior)
			{
				restrictionValues = (System.Data.Common.ADP.IsEmptyArray(_restrictionValues) ? entry._restrictionValues : ((!System.Data.Common.ADP.IsEmptyArray(entry._restrictionValues)) ? NoDuplicateUnion(_restrictionValues, entry._restrictionValues) : _restrictionValues));
			}
			else if (!System.Data.Common.ADP.IsEmptyArray(_restrictionValues) && !System.Data.Common.ADP.IsEmptyArray(entry._restrictionValues))
			{
				restrictionValues = ((_restrictionValues.Length > entry._restrictionValues.Length) ? NewRestrictionIntersect(entry._restrictionValues, _restrictionValues) : NewRestrictionIntersect(_restrictionValues, entry._restrictionValues));
			}
			return new DBConnectionString(this, restrictionValues, behavior);
		}

		private bool IsRestrictedKeyword(string key)
		{
			if (_restrictionValues != null)
			{
				return 0 > Array.BinarySearch(_restrictionValues, key, StringComparer.Ordinal);
			}
			return true;
		}

		internal bool IsSupersetOf(DBConnectionString entry)
		{
			switch (_behavior)
			{
			case KeyRestrictionBehavior.AllowOnly:
			{
				for (NameValuePair nameValuePair = entry.KeyChain; nameValuePair != null; nameValuePair = nameValuePair.Next)
				{
					if (!ContainsKey(nameValuePair.Name) && IsRestrictedKeyword(nameValuePair.Name))
					{
						return false;
					}
				}
				break;
			}
			case KeyRestrictionBehavior.PreventUsage:
			{
				if (_restrictionValues == null)
				{
					break;
				}
				string[] restrictionValues = _restrictionValues;
				foreach (string keyword in restrictionValues)
				{
					if (entry.ContainsKey(keyword))
					{
						return false;
					}
				}
				break;
			}
			default:
				throw System.Data.Common.ADP.InvalidKeyRestrictionBehavior(_behavior);
			}
			return true;
		}

		private static string[] NewRestrictionAllowOnly(string[] allowonly, string[] preventusage)
		{
			List<string> list = null;
			for (int i = 0; i < allowonly.Length; i++)
			{
				if (0 > Array.BinarySearch(preventusage, allowonly[i], StringComparer.Ordinal))
				{
					if (list == null)
					{
						list = new List<string>();
					}
					list.Add(allowonly[i]);
				}
			}
			string[] result = null;
			if (list != null)
			{
				result = list.ToArray();
			}
			return result;
		}

		private static string[] NewRestrictionIntersect(string[] a, string[] b)
		{
			List<string> list = null;
			for (int i = 0; i < a.Length; i++)
			{
				if (0 <= Array.BinarySearch(b, a[i], StringComparer.Ordinal))
				{
					if (list == null)
					{
						list = new List<string>();
					}
					list.Add(a[i]);
				}
			}
			string[] result = null;
			if (list != null)
			{
				result = list.ToArray();
			}
			return result;
		}

		private static string[] NoDuplicateUnion(string[] a, string[] b)
		{
			List<string> list = new List<string>(a.Length + b.Length);
			for (int i = 0; i < a.Length; i++)
			{
				list.Add(a[i]);
			}
			for (int j = 0; j < b.Length; j++)
			{
				if (0 > Array.BinarySearch(a, b[j], StringComparer.Ordinal))
				{
					list.Add(b[j]);
				}
			}
			string[] array = list.ToArray();
			Array.Sort(array, StringComparer.Ordinal);
			return array;
		}

		private static string[] ParseRestrictions(string restrictions, Hashtable synonyms)
		{
			List<string> list = new List<string>();
			StringBuilder buffer = new StringBuilder(restrictions.Length);
			int num = 0;
			int length = restrictions.Length;
			while (num < length)
			{
				int currentPosition = num;
				num = System.Data.Common.DbConnectionOptions.GetKeyValuePair(restrictions, currentPosition, buffer, useOdbcRules: false, out var keyname, out var _);
				if (!System.Data.Common.ADP.IsEmpty(keyname))
				{
					string text = ((synonyms != null) ? ((string)synonyms[keyname]) : keyname);
					if (System.Data.Common.ADP.IsEmpty(text))
					{
						throw System.Data.Common.ADP.KeywordNotSupported(keyname);
					}
					list.Add(text);
				}
			}
			return RemoveDuplicates(list.ToArray());
		}

		internal static string[] RemoveDuplicates(string[] restrictions)
		{
			int num = restrictions.Length;
			if (0 < num)
			{
				Array.Sort(restrictions, StringComparer.Ordinal);
				for (int i = 1; i < restrictions.Length; i++)
				{
					string text = restrictions[i - 1];
					if (text.Length == 0 || text == restrictions[i])
					{
						restrictions[i - 1] = null;
						num--;
					}
				}
				if (restrictions[restrictions.Length - 1].Length == 0)
				{
					restrictions[restrictions.Length - 1] = null;
					num--;
				}
				if (num != restrictions.Length)
				{
					string[] array = new string[num];
					num = 0;
					for (int j = 0; j < restrictions.Length; j++)
					{
						if (restrictions[j] != null)
						{
							array[num++] = restrictions[j];
						}
					}
					restrictions = array;
				}
			}
			return restrictions;
		}

		[Conditional("DEBUG")]
		private static void Verify(string[] restrictionValues)
		{
			if (restrictionValues != null)
			{
				for (int i = 1; i < restrictionValues.Length; i++)
				{
				}
			}
		}
	}
}
namespace System.Data.Common
{
	internal class DbConnectionStringBuilderDescriptor : PropertyDescriptor
	{
		private Type _componentType;

		private Type _propertyType;

		private bool _isReadOnly;

		private bool _refreshOnChange;

		internal bool RefreshOnChange
		{
			get
			{
				return _refreshOnChange;
			}
			set
			{
				_refreshOnChange = value;
			}
		}

		public override Type ComponentType => _componentType;

		public override bool IsReadOnly => _isReadOnly;

		public override Type PropertyType => _propertyType;

		internal DbConnectionStringBuilderDescriptor(string propertyName, Type componentType, Type propertyType, bool isReadOnly, Attribute[] attributes)
			: base(propertyName, attributes)
		{
			_componentType = componentType;
			_propertyType = propertyType;
			_isReadOnly = isReadOnly;
		}

		public override bool CanResetValue(object component)
		{
			if (component is DbConnectionStringBuilder dbConnectionStringBuilder)
			{
				return dbConnectionStringBuilder.ShouldSerialize(DisplayName);
			}
			return false;
		}

		public override object GetValue(object component)
		{
			if (component is DbConnectionStringBuilder dbConnectionStringBuilder && dbConnectionStringBuilder.TryGetValue(DisplayName, out var value))
			{
				return value;
			}
			return null;
		}

		public override void ResetValue(object component)
		{
			if (component is DbConnectionStringBuilder dbConnectionStringBuilder)
			{
				dbConnectionStringBuilder.Remove(DisplayName);
				if (RefreshOnChange)
				{
					((OracleConnectionStringBuilder)dbConnectionStringBuilder).ClearPropertyDescriptors();
				}
			}
		}

		public override void SetValue(object component, object value)
		{
			if (component is DbConnectionStringBuilder dbConnectionStringBuilder)
			{
				if (typeof(string) == PropertyType && string.Empty.Equals(value))
				{
					value = null;
				}
				dbConnectionStringBuilder[DisplayName] = value;
				if (RefreshOnChange)
				{
					((OracleConnectionStringBuilder)dbConnectionStringBuilder).ClearPropertyDescriptors();
				}
			}
		}

		public override bool ShouldSerializeValue(object component)
		{
			if (component is DbConnectionStringBuilder dbConnectionStringBuilder)
			{
				return dbConnectionStringBuilder.ShouldSerialize(DisplayName);
			}
			return false;
		}
	}
	[Serializable]
	internal sealed class ReadOnlyCollection<T> : ICollection, ICollection<T>, IEnumerable<T>, IEnumerable
	{
		[Serializable]
		internal struct Enumerator<K> : IEnumerator<K>, IDisposable, IEnumerator
		{
			private K[] _items;

			private int _index;

			public K Current => _items[_index];

			object IEnumerator.Current => _items[_index];

			internal Enumerator(K[] items)
			{
				_items = items;
				_index = -1;
			}

			public void Dispose()
			{
			}

			public bool MoveNext()
			{
				return ++_index < _items.Length;
			}

			void IEnumerator.Reset()
			{
				_index = -1;
			}
		}

		private T[] _items;

		bool ICollection.IsSynchronized => false;

		object ICollection.SyncRoot => _items;

		bool ICollection<T>.IsReadOnly => true;

		public int Count => _items.Length;

		internal ReadOnlyCollection(T[] items)
		{
			_items = items;
		}

		public void CopyTo(T[] array, int arrayIndex)
		{
			Array.Copy(_items, 0, array, arrayIndex, _items.Length);
		}

		void ICollection.CopyTo(Array array, int arrayIndex)
		{
			Array.Copy(_items, 0, array, arrayIndex, _items.Length);
		}

		IEnumerator<T> IEnumerable<T>.GetEnumerator()
		{
			return new Enumerator<T>(_items);
		}

		public IEnumerator GetEnumerator()
		{
			return new Enumerator<T>(_items);
		}

		void ICollection<T>.Add(T value)
		{
			throw new NotSupportedException();
		}

		void ICollection<T>.Clear()
		{
			throw new NotSupportedException();
		}

		bool ICollection<T>.Contains(T value)
		{
			return Array.IndexOf(_items, value) >= 0;
		}

		bool ICollection<T>.Remove(T value)
		{
			throw new NotSupportedException();
		}
	}
	internal static class DbConnectionStringBuilderUtil
	{
		private const string ApplicationIntentReadWriteString = "ReadWrite";

		private const string ApplicationIntentReadOnlyString = "ReadOnly";

		internal static bool ConvertToBoolean(object value)
		{
			//Discarded unreachable code: IL_00df
			if (value is string text)
			{
				if (StringComparer.OrdinalIgnoreCase.Equals(text, "true") || StringComparer.OrdinalIgnoreCase.Equals(text, "yes"))
				{
					return true;
				}
				if (StringComparer.OrdinalIgnoreCase.Equals(text, "false") || StringComparer.OrdinalIgnoreCase.Equals(text, "no"))
				{
					return false;
				}
				string x = text.Trim();
				if (StringComparer.OrdinalIgnoreCase.Equals(x, "true") || StringComparer.OrdinalIgnoreCase.Equals(x, "yes"))
				{
					return true;
				}
				if (StringComparer.OrdinalIgnoreCase.Equals(x, "false") || StringComparer.OrdinalIgnoreCase.Equals(x, "no"))
				{
					return false;
				}
				return bool.Parse(text);
			}
			try
			{
				return ((IConvertible)value).ToBoolean(CultureInfo.InvariantCulture);
			}
			catch (InvalidCastException innerException)
			{
				throw ADP.ConvertFailed(value.GetType(), typeof(bool), innerException);
			}
		}

		internal static bool ConvertToIntegratedSecurity(object value)
		{
			//Discarded unreachable code: IL_0103
			if (value is string text)
			{
				if (StringComparer.OrdinalIgnoreCase.Equals(text, "sspi") || StringComparer.OrdinalIgnoreCase.Equals(text, "true") || StringComparer.OrdinalIgnoreCase.Equals(text, "yes"))
				{
					return true;
				}
				if (StringComparer.OrdinalIgnoreCase.Equals(text, "false") || StringComparer.OrdinalIgnoreCase.Equals(text, "no"))
				{
					return false;
				}
				string x = text.Trim();
				if (StringComparer.OrdinalIgnoreCase.Equals(x, "sspi") || StringComparer.OrdinalIgnoreCase.Equals(x, "true") || StringComparer.OrdinalIgnoreCase.Equals(x, "yes"))
				{
					return true;
				}
				if (StringComparer.OrdinalIgnoreCase.Equals(x, "false") || StringComparer.OrdinalIgnoreCase.Equals(x, "no"))
				{
					return false;
				}
				return bool.Parse(text);
			}
			try
			{
				return ((IConvertible)value).ToBoolean(CultureInfo.InvariantCulture);
			}
			catch (InvalidCastException innerException)
			{
				throw ADP.ConvertFailed(value.GetType(), typeof(bool), innerException);
			}
		}

		internal static int ConvertToInt32(object value)
		{
			//Discarded unreachable code: IL_002b
			try
			{
				return ((IConvertible)value).ToInt32(CultureInfo.InvariantCulture);
			}
			catch (InvalidCastException innerException)
			{
				throw ADP.ConvertFailed(value.GetType(), typeof(int), innerException);
			}
		}

		internal static string ConvertToString(object value)
		{
			//Discarded unreachable code: IL_002b
			try
			{
				return ((IConvertible)value).ToString(CultureInfo.InvariantCulture);
			}
			catch (InvalidCastException innerException)
			{
				throw ADP.ConvertFailed(value.GetType(), typeof(string), innerException);
			}
		}

		internal static bool TryConvertToApplicationIntent(string value, out ApplicationIntent result)
		{
			if (StringComparer.OrdinalIgnoreCase.Equals(value, "ReadOnly"))
			{
				result = ApplicationIntent.ReadOnly;
				return true;
			}
			if (StringComparer.OrdinalIgnoreCase.Equals(value, "ReadWrite"))
			{
				result = ApplicationIntent.ReadWrite;
				return true;
			}
			result = ApplicationIntent.ReadWrite;
			return false;
		}

		internal static bool IsValidApplicationIntentValue(ApplicationIntent value)
		{
			if (value != ApplicationIntent.ReadOnly)
			{
				return value == ApplicationIntent.ReadWrite;
			}
			return true;
		}

		internal static string ApplicationIntentToString(ApplicationIntent value)
		{
			if (value == ApplicationIntent.ReadOnly)
			{
				return "ReadOnly";
			}
			return "ReadWrite";
		}

		internal static ApplicationIntent ConvertToApplicationIntent(string keyword, object value)
		{
			//Discarded unreachable code: IL_0096
			if (value is string text)
			{
				if (TryConvertToApplicationIntent(text, out var result))
				{
					return result;
				}
				string value2 = text.Trim();
				if (TryConvertToApplicationIntent(value2, out result))
				{
					return result;
				}
				throw ADP.InvalidConnectionOptionValue(keyword);
			}
			ApplicationIntent applicationIntent;
			if (value is ApplicationIntent)
			{
				applicationIntent = (ApplicationIntent)value;
			}
			else
			{
				if (value.GetType().IsEnum)
				{
					throw ADP.ConvertFailed(value.GetType(), typeof(ApplicationIntent), null);
				}
				try
				{
					applicationIntent = (ApplicationIntent)Enum.ToObject(typeof(ApplicationIntent), value);
				}
				catch (ArgumentException innerException)
				{
					throw ADP.ConvertFailed(value.GetType(), typeof(ApplicationIntent), innerException);
				}
			}
			if (IsValidApplicationIntentValue(applicationIntent))
			{
				return applicationIntent;
			}
			throw ADP.InvalidEnumerationValue(typeof(ApplicationIntent), (int)applicationIntent);
		}
	}
}
namespace System.Data.ProviderBase
{
	internal abstract class DbConnectionClosed : DbConnectionInternal
	{
		public override string ServerVersion
		{
			get
			{
				throw System.Data.Common.ADP.ClosedConnectionError();
			}
		}

		protected DbConnectionClosed(ConnectionState state, bool hidePassword, bool allowSetConnectionString)
			: base(state, hidePassword, allowSetConnectionString)
		{
		}

		protected override void Activate(Transaction transaction)
		{
			throw System.Data.Common.ADP.ClosedConnectionError();
		}

		public override DbTransaction BeginTransaction(IsolationLevel il)
		{
			throw System.Data.Common.ADP.ClosedConnectionError();
		}

		public override void ChangeDatabase(string database)
		{
			throw System.Data.Common.ADP.ClosedConnectionError();
		}

		internal override void CloseConnection(DbConnection owningObject, DbConnectionFactory connectionFactory)
		{
		}

		protected override void Deactivate()
		{
			throw System.Data.Common.ADP.ClosedConnectionError();
		}

		public override void EnlistTransaction(Transaction transaction)
		{
			throw System.Data.Common.ADP.ClosedConnectionError();
		}

		protected internal override DataTable GetSchema(DbConnectionFactory factory, DbConnectionPoolGroup poolGroup, DbConnection outerConnection, string collectionName, string[] restrictions)
		{
			throw System.Data.Common.ADP.ClosedConnectionError();
		}

		internal override void OpenConnection(DbConnection outerConnection, DbConnectionFactory connectionFactory)
		{
			//Discarded unreachable code: IL_002d
			if (connectionFactory.SetInnerConnectionFrom(outerConnection, DbConnectionClosedConnecting.SingletonInstance, this))
			{
				DbConnectionInternal dbConnectionInternal = null;
				try
				{
					connectionFactory.PermissionDemand(outerConnection);
					dbConnectionInternal = connectionFactory.GetConnection(outerConnection);
				}
				catch
				{
					connectionFactory.SetInnerConnectionTo(outerConnection, this);
					throw;
				}
				if (dbConnectionInternal == null)
				{
					connectionFactory.SetInnerConnectionTo(outerConnection, this);
					throw System.Data.Common.ADP.InternalConnectionError(System.Data.Common.ADP.ConnectionError.GetConnectionReturnsNull);
				}
				connectionFactory.SetInnerConnectionEvent(outerConnection, dbConnectionInternal);
			}
		}
	}
	internal abstract class DbConnectionBusy : DbConnectionClosed
	{
		protected DbConnectionBusy(ConnectionState state)
			: base(state, hidePassword: true, allowSetConnectionString: false)
		{
		}

		internal override void OpenConnection(DbConnection outerConnection, DbConnectionFactory connectionFactory)
		{
			throw System.Data.Common.ADP.ConnectionAlreadyOpen(base.State);
		}
	}
	internal sealed class DbConnectionClosedBusy : DbConnectionBusy
	{
		internal static readonly DbConnectionInternal SingletonInstance = new DbConnectionClosedBusy();

		private DbConnectionClosedBusy()
			: base(ConnectionState.Closed)
		{
		}
	}
	internal sealed class DbConnectionOpenBusy : DbConnectionBusy
	{
		internal static readonly DbConnectionInternal SingletonInstance = new DbConnectionOpenBusy();

		private DbConnectionOpenBusy()
			: base(ConnectionState.Open)
		{
		}
	}
	internal sealed class DbConnectionClosedConnecting : DbConnectionBusy
	{
		internal static readonly DbConnectionInternal SingletonInstance = new DbConnectionClosedConnecting();

		private DbConnectionClosedConnecting()
			: base(ConnectionState.Connecting)
		{
		}
	}
	internal sealed class DbConnectionClosedNeverOpened : DbConnectionClosed
	{
		internal static readonly DbConnectionInternal SingletonInstance = new DbConnectionClosedNeverOpened();

		private DbConnectionClosedNeverOpened()
			: base(ConnectionState.Closed, hidePassword: false, allowSetConnectionString: true)
		{
		}
	}
	internal sealed class DbConnectionClosedPreviouslyOpened : DbConnectionClosed
	{
		internal static readonly DbConnectionInternal SingletonInstance = new DbConnectionClosedPreviouslyOpened();

		private DbConnectionClosedPreviouslyOpened()
			: base(ConnectionState.Closed, hidePassword: true, allowSetConnectionString: true)
		{
		}
	}
	internal sealed class DbConnectionPool
	{
		private enum State
		{
			Initializing,
			Running,
			ShuttingDown
		}

		private sealed class TransactedConnectionList : List<DbConnectionInternal>
		{
			private Transaction _transaction;

			internal TransactedConnectionList(int initialAllocation, Transaction tx)
				: base(initialAllocation)
			{
				_transaction = tx;
			}

			internal void Dispose()
			{
				if (null != _transaction)
				{
					_transaction.Dispose();
				}
			}
		}

		private sealed class TransactedConnectionPool : Hashtable
		{
			private DbConnectionPool _pool;

			private static int _objectTypeCount;

			internal readonly int _objectID = Interlocked.Increment(ref _objectTypeCount);

			internal int ObjectID => _objectID;

			internal DbConnectionPool Pool => _pool;

			internal TransactedConnectionPool(DbConnectionPool pool)
			{
				_pool = pool;
				Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.TransactedConnectionPool|RES|CPOOL> %d#, Constructed for connection pool %d#\n", ObjectID, _pool.ObjectID);
			}

			internal DbConnectionInternal GetTransactedObject(Transaction transaction)
			{
				DbConnectionInternal dbConnectionInternal = null;
				TransactedConnectionList transactedConnectionList = (TransactedConnectionList)this[transaction];
				if (transactedConnectionList != null)
				{
					lock (transactedConnectionList)
					{
						int num = transactedConnectionList.Count - 1;
						if (0 <= num)
						{
							dbConnectionInternal = transactedConnectionList[num];
							transactedConnectionList.RemoveAt(num);
						}
					}
				}
				if (dbConnectionInternal != null)
				{
					Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.GetTransactedObject|RES|CPOOL> %d#, Transaction %d#, Connection %d#, Popped.\n", ObjectID, transaction.GetHashCode(), dbConnectionInternal.ObjectID);
				}
				return dbConnectionInternal;
			}

			internal void PutTransactedObject(Transaction transaction, DbConnectionInternal transactedObject)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.PutTransactedObject|RES|CPOOL> %d#, Transaction %d#, Connection %d#, Pushing.\n", ObjectID, transaction.GetHashCode(), transactedObject.ObjectID);
				TransactedConnectionList transactedConnectionList = (TransactedConnectionList)this[transaction];
				if (transactedConnectionList != null)
				{
					lock (transactedConnectionList)
					{
						transactedConnectionList.Add(transactedObject);
						Pool.PerformanceCounters.NumberOfFreeConnections.Increment();
					}
				}
			}

			internal void TransactionBegin(Transaction transaction)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.TransactionBegin|RES|CPOOL> %d#, Transaction %d#, Begin.\n", ObjectID, transaction.GetHashCode());
				TransactedConnectionList transactedConnectionList = (TransactedConnectionList)this[transaction];
				if (transactedConnectionList != null)
				{
					return;
				}
				Transaction transaction2 = null;
				try
				{
					transaction2 = transaction.Clone();
					TransactedConnectionList transactedConnectionList2 = new TransactedConnectionList(2, transaction2);
					Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.TransactionBegin|RES|CPOOL> %d#, Transaction %d#, Adding List to transacted pool.\n", ObjectID, transaction.GetHashCode());
					lock (this)
					{
						transactedConnectionList = (TransactedConnectionList)this[transaction2];
						if (transactedConnectionList == null)
						{
							transactedConnectionList = transactedConnectionList2;
							Add(transaction2, transactedConnectionList);
							transaction2 = null;
						}
					}
				}
				finally
				{
					if (null != transaction2)
					{
						transaction2.Dispose();
					}
				}
				Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.TransactionBegin|RES|CPOOL> %d#, Transaction %d#, Added.\n", ObjectID, transaction.GetHashCode());
			}

			internal void TransactionEnded(Transaction transaction, DbConnectionInternal transactedObject)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.TransactionEnded|RES|CPOOL> %d#, Transaction %d#, Connection %d#, Transaction Completed\n", ObjectID, transaction.GetHashCode(), transactedObject.ObjectID);
				TransactedConnectionList transactedConnectionList = (TransactedConnectionList)this[transaction];
				int num = -1;
				if (transactedConnectionList != null)
				{
					lock (transactedConnectionList)
					{
						num = transactedConnectionList.IndexOf(transactedObject);
						if (num >= 0)
						{
							transactedConnectionList.RemoveAt(num);
						}
						if (0 >= transactedConnectionList.Count)
						{
							Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.TransactionEnded|RES|CPOOL> %d#, Transaction %d#, Removing List from transacted pool.\n", ObjectID, transaction.GetHashCode());
							lock (this)
							{
								Remove(transaction);
							}
							Bid.PoolerTrace("<prov.DbConnectionPool.TransactedConnectionPool.TransactionEnded|RES|CPOOL> %d#, Transaction %d#, Removed.\n", ObjectID, transaction.GetHashCode());
							transactedConnectionList.Dispose();
						}
					}
				}
				if (0 <= num)
				{
					Pool.PerformanceCounters.NumberOfFreeConnections.Decrement();
					Pool.PutObjectFromTransactedPool(transactedObject);
				}
			}
		}

		private sealed class PoolWaitHandles : DbBuffer
		{
			private readonly Semaphore _poolSemaphore;

			private readonly ManualResetEvent _errorEvent;

			private readonly Semaphore _creationSemaphore;

			private readonly SafeHandle _poolHandle;

			private readonly SafeHandle _errorHandle;

			private readonly SafeHandle _creationHandle;

			private readonly int _releaseFlags;

			internal SafeHandle CreationHandle
			{
				[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
				get
				{
					return _creationHandle;
				}
			}

			internal Semaphore CreationSemaphore => _creationSemaphore;

			internal ManualResetEvent ErrorEvent => _errorEvent;

			internal Semaphore PoolSemaphore => _poolSemaphore;

			internal PoolWaitHandles(Semaphore poolSemaphore, ManualResetEvent errorEvent, Semaphore creationSemaphore)
				: base(3 * IntPtr.Size)
			{
				bool success = false;
				bool success2 = false;
				bool success3 = false;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					_poolSemaphore = poolSemaphore;
					_errorEvent = errorEvent;
					_creationSemaphore = creationSemaphore;
					_poolHandle = poolSemaphore.SafeWaitHandle;
					_errorHandle = errorEvent.SafeWaitHandle;
					_creationHandle = creationSemaphore.SafeWaitHandle;
					_poolHandle.DangerousAddRef(ref success);
					_errorHandle.DangerousAddRef(ref success2);
					_creationHandle.DangerousAddRef(ref success3);
					_ = IntPtr.Size;
					WriteIntPtr(0, _poolHandle.DangerousGetHandle());
					WriteIntPtr(IntPtr.Size, _errorHandle.DangerousGetHandle());
					WriteIntPtr(2 * IntPtr.Size, _creationHandle.DangerousGetHandle());
				}
				finally
				{
					if (success)
					{
						_releaseFlags |= 1;
					}
					if (success2)
					{
						_releaseFlags |= 2;
					}
					if (success3)
					{
						_releaseFlags |= 4;
					}
				}
			}

			protected override bool ReleaseHandle()
			{
				if (((true ? 1u : 0u) & (uint)_releaseFlags) != 0)
				{
					_poolHandle.DangerousRelease();
				}
				if ((2u & (uint)_releaseFlags) != 0)
				{
					_errorHandle.DangerousRelease();
				}
				if ((4u & (uint)_releaseFlags) != 0)
				{
					_creationHandle.DangerousRelease();
				}
				return base.ReleaseHandle();
			}
		}

		private class DbConnectionInternalListStack
		{
			private DbConnectionInternal _stack;

			internal int Count
			{
				get
				{
					int num = 0;
					lock (this)
					{
						for (DbConnectionInternal dbConnectionInternal = _stack; dbConnectionInternal != null; dbConnectionInternal = dbConnectionInternal.NextPooledObject)
						{
							num++;
						}
						return num;
					}
				}
			}

			internal DbConnectionInternalListStack()
			{
			}

			internal DbConnectionInternal SynchronizedPop()
			{
				lock (this)
				{
					DbConnectionInternal stack = _stack;
					if (stack != null)
					{
						_stack = stack.NextPooledObject;
						stack.NextPooledObject = null;
						return stack;
					}
					return stack;
				}
			}

			internal void SynchronizedPush(DbConnectionInternal value)
			{
				lock (this)
				{
					value.NextPooledObject = _stack;
					_stack = value;
				}
			}
		}

		internal const Bid.ApiGroup PoolerTracePoints = (Bid.ApiGroup)4096u;

		private const int MAX_Q_SIZE = 1048576;

		private const int SEMAPHORE_HANDLE = 0;

		private const int ERROR_HANDLE = 1;

		private const int CREATION_HANDLE = 2;

		private const int BOGUS_HANDLE = 3;

		private const int WAIT_OBJECT_0 = 0;

		private const int WAIT_TIMEOUT = 258;

		private const int WAIT_ABANDONED = 128;

		private const int WAIT_FAILED = -1;

		private const int ERROR_WAIT_DEFAULT = 5000;

		private static readonly Random _random = new Random(5101977);

		private readonly int _cleanupWait;

		private readonly DbConnectionPoolIdentity _identity;

		private readonly DbConnectionFactory _connectionFactory;

		private readonly DbConnectionPoolGroup _connectionPoolGroup;

		private readonly DbConnectionPoolGroupOptions _connectionPoolGroupOptions;

		private DbConnectionPoolProviderInfo _connectionPoolProviderInfo;

		private State _state;

		private readonly DbConnectionInternalListStack _stackOld = new DbConnectionInternalListStack();

		private readonly DbConnectionInternalListStack _stackNew = new DbConnectionInternalListStack();

		private readonly WaitCallback _poolCreateRequest;

		private readonly Queue _deactivateQueue;

		private readonly WaitCallback _deactivateCallback;

		private int _waitCount;

		private readonly PoolWaitHandles _waitHandles;

		private Exception _resError;

		private volatile bool _errorOccurred;

		private int _errorWait;

		private Timer _errorTimer;

		private Timer _cleanupTimer;

		private readonly TransactedConnectionPool _transactedConnectionPool;

		private readonly List<DbConnectionInternal> _objectList;

		private int _totalObjects;

		private static int _objectTypeCount;

		internal readonly int _objectID = Interlocked.Increment(ref _objectTypeCount);

		private int CreationTimeout => PoolGroupOptions.CreationTimeout;

		internal int Count => _totalObjects;

		internal DbConnectionFactory ConnectionFactory => _connectionFactory;

		internal bool ErrorOccurred => _errorOccurred;

		private bool HasTransactionAffinity => PoolGroupOptions.HasTransactionAffinity;

		internal TimeSpan LoadBalanceTimeout => PoolGroupOptions.LoadBalanceTimeout;

		private bool NeedToReplenish
		{
			get
			{
				if (State.Running != _state)
				{
					return false;
				}
				int count = Count;
				if (count >= MaxPoolSize)
				{
					return false;
				}
				if (count < MinPoolSize)
				{
					return true;
				}
				int num = _stackNew.Count + _stackOld.Count;
				int waitCount = _waitCount;
				return num < waitCount || (num == waitCount && count > 1);
			}
		}

		internal DbConnectionPoolIdentity Identity => _identity;

		internal bool IsRunning => State.Running == _state;

		private int MaxPoolSize => PoolGroupOptions.MaxPoolSize;

		private int MinPoolSize => PoolGroupOptions.MinPoolSize;

		internal int ObjectID => _objectID;

		internal DbConnectionPoolCounters PerformanceCounters => _connectionFactory.PerformanceCounters;

		internal DbConnectionPoolGroup PoolGroup => _connectionPoolGroup;

		internal DbConnectionPoolGroupOptions PoolGroupOptions => _connectionPoolGroupOptions;

		internal DbConnectionPoolProviderInfo ProviderInfo => _connectionPoolProviderInfo;

		private bool UseDeactivateQueue => PoolGroupOptions.UseDeactivateQueue;

		internal bool UseLoadBalancing => PoolGroupOptions.UseLoadBalancing;

		private bool UsingIntegrateSecurity
		{
			get
			{
				if (_identity != null)
				{
					return DbConnectionPoolIdentity.NoIdentity != _identity;
				}
				return false;
			}
		}

		internal DbConnectionPool(DbConnectionFactory connectionFactory, DbConnectionPoolGroup connectionPoolGroup, DbConnectionPoolIdentity identity, DbConnectionPoolProviderInfo connectionPoolProviderInfo)
		{
			if (identity != null && identity.IsRestricted)
			{
				throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.AttemptingToPoolOnRestrictedToken);
			}
			_state = State.Initializing;
			lock (_random)
			{
				_cleanupWait = _random.Next(12, 24) * 10 * 1000;
			}
			_connectionFactory = connectionFactory;
			_connectionPoolGroup = connectionPoolGroup;
			_connectionPoolGroupOptions = connectionPoolGroup.PoolGroupOptions;
			_connectionPoolProviderInfo = connectionPoolProviderInfo;
			_identity = identity;
			if (UseDeactivateQueue)
			{
				_deactivateQueue = new Queue();
				_deactivateCallback = ProcessDeactivateQueue;
			}
			_waitHandles = new PoolWaitHandles(new Semaphore(0, 1048576), new ManualResetEvent(initialState: false), new Semaphore(1, 1));
			_errorWait = 5000;
			_errorTimer = null;
			_objectList = new List<DbConnectionInternal>(MaxPoolSize);
			if (System.Data.Common.ADP.IsPlatformNT5)
			{
				_transactedConnectionPool = new TransactedConnectionPool(this);
			}
			_poolCreateRequest = PoolCreateRequest;
			_state = State.Running;
			Bid.PoolerTrace("<prov.DbConnectionPool.DbConnectionPool|RES|CPOOL> %d#, Constructed.\n", ObjectID);
		}

		private void CleanupCallback(object state)
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.CleanupCallback|RES|INFO|CPOOL> %d#\n", ObjectID);
			while (Count > MinPoolSize && _waitHandles.PoolSemaphore.WaitOne(0, exitContext: false))
			{
				DbConnectionInternal dbConnectionInternal = _stackOld.SynchronizedPop();
				if (dbConnectionInternal != null)
				{
					PerformanceCounters.NumberOfFreeConnections.Decrement();
					bool flag = true;
					lock (dbConnectionInternal)
					{
						if (dbConnectionInternal.IsTransactionRoot)
						{
							flag = false;
						}
					}
					if (flag)
					{
						DestroyObject(dbConnectionInternal);
					}
					else
					{
						dbConnectionInternal.SetInStasis();
					}
					continue;
				}
				_waitHandles.PoolSemaphore.Release(1);
				break;
			}
			if (_waitHandles.PoolSemaphore.WaitOne(0, exitContext: false))
			{
				while (true)
				{
					DbConnectionInternal dbConnectionInternal2 = _stackNew.SynchronizedPop();
					if (dbConnectionInternal2 == null)
					{
						break;
					}
					Bid.PoolerTrace("<prov.DbConnectionPool.CleanupCallback|RES|INFO|CPOOL> %d#, ChangeStacks=%d#\n", ObjectID, dbConnectionInternal2.ObjectID);
					_stackOld.SynchronizedPush(dbConnectionInternal2);
				}
				_waitHandles.PoolSemaphore.Release(1);
			}
			QueuePoolCreateRequest();
		}

		internal void Clear()
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.Clear|RES|CPOOL> %d#, Clearing.\n", ObjectID);
			lock (_objectList)
			{
				int count = _objectList.Count;
				for (int i = 0; i < count; i++)
				{
					_objectList[i]?.DoNotPoolThisConnection();
				}
			}
			DbConnectionInternal obj;
			while ((obj = _stackNew.SynchronizedPop()) != null)
			{
				PerformanceCounters.NumberOfFreeConnections.Decrement();
				DestroyObject(obj);
			}
			while ((obj = _stackOld.SynchronizedPop()) != null)
			{
				PerformanceCounters.NumberOfFreeConnections.Decrement();
				DestroyObject(obj);
			}
			ReclaimEmancipatedObjects();
			Bid.PoolerTrace("<prov.DbConnectionPool.Clear|RES|CPOOL> %d#, Cleared.\n", ObjectID);
		}

		private Timer CreateCleanupTimer()
		{
			return new Timer(CleanupCallback, null, _cleanupWait, _cleanupWait);
		}

		private DbConnectionInternal CreateObject(DbConnection owningObject)
		{
			//Discarded unreachable code: IL_0126
			DbConnectionInternal dbConnectionInternal = null;
			try
			{
				dbConnectionInternal = _connectionFactory.CreatePooledConnection(owningObject, this, _connectionPoolGroup.ConnectionOptions);
				if (dbConnectionInternal == null)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.CreateObjectReturnedNull);
				}
				if (!dbConnectionInternal.CanBePooled)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.NewObjectCannotBePooled);
				}
				dbConnectionInternal.PrePush(null);
				lock (_objectList)
				{
					_objectList.Add(dbConnectionInternal);
					_totalObjects = _objectList.Count;
					PerformanceCounters.NumberOfPooledConnections.Increment();
				}
				Bid.PoolerTrace("<prov.DbConnectionPool.CreateObject|RES|CPOOL> %d#, Connection %d#, Added to pool.\n", ObjectID, dbConnectionInternal.ObjectID);
				_errorWait = 5000;
				return dbConnectionInternal;
			}
			catch (Exception ex)
			{
				if (!System.Data.Common.ADP.IsCatchableExceptionType(ex))
				{
					throw;
				}
				System.Data.Common.ADP.TraceExceptionForCapture(ex);
				dbConnectionInternal = null;
				_resError = ex;
				_waitHandles.ErrorEvent.Set();
				_errorOccurred = true;
				_errorTimer = new Timer(ErrorCallback, null, _errorWait, _errorWait);
				if (30000 < _errorWait)
				{
					_errorWait = 60000;
				}
				else
				{
					_errorWait *= 2;
				}
				throw;
			}
		}

		private void DeactivateObject(DbConnectionInternal obj)
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.DeactivateObject|RES|CPOOL> %d#, Connection %d#, Deactivating.\n", ObjectID, obj.ObjectID);
			obj.DeactivateConnection();
			bool flag = false;
			bool flag2 = false;
			if (obj.IsConnectionDoomed)
			{
				flag2 = true;
			}
			else
			{
				lock (obj)
				{
					if (_state == State.ShuttingDown)
					{
						if (obj.IsTransactionRoot)
						{
							obj.SetInStasis();
						}
						else
						{
							flag2 = true;
						}
					}
					else if (obj.IsNonPoolableTransactionRoot)
					{
						obj.SetInStasis();
					}
					else if (obj.CanBePooled)
					{
						Transaction enlistedTransaction = obj.EnlistedTransaction;
						if (null != enlistedTransaction)
						{
							_transactedConnectionPool.TransactionBegin(enlistedTransaction);
							_transactedConnectionPool.PutTransactedObject(enlistedTransaction, obj);
						}
						else
						{
							flag = true;
						}
					}
					else if (obj.IsTransactionRoot && !obj.IsConnectionDoomed)
					{
						obj.SetInStasis();
					}
					else
					{
						flag2 = true;
					}
				}
			}
			if (flag)
			{
				PutNewObject(obj);
			}
			else if (flag2)
			{
				DestroyObject(obj);
				QueuePoolCreateRequest();
			}
		}

		private void DestroyObject(DbConnectionInternal obj)
		{
			if (obj.IsTxRootWaitingForTxEnd)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.DestroyObject|RES|CPOOL> %d#, Connection %d#, Has Delegated Transaction, waiting to Dispose.\n", ObjectID, obj.ObjectID);
				return;
			}
			Bid.PoolerTrace("<prov.DbConnectionPool.DestroyObject|RES|CPOOL> %d#, Connection %d#, Removing from pool.\n", ObjectID, obj.ObjectID);
			bool flag = false;
			lock (_objectList)
			{
				flag = _objectList.Remove(obj);
				_totalObjects = _objectList.Count;
			}
			if (flag)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.DestroyObject|RES|CPOOL> %d#, Connection %d#, Removed from pool.\n", ObjectID, obj.ObjectID);
				PerformanceCounters.NumberOfPooledConnections.Decrement();
			}
			obj.Dispose();
			Bid.PoolerTrace("<prov.DbConnectionPool.DestroyObject|RES|CPOOL> %d#, Connection %d#, Disposed.\n", ObjectID, obj.ObjectID);
			PerformanceCounters.HardDisconnectsPerSecond.Increment();
		}

		private void ErrorCallback(object state)
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.ErrorCallback|RES|CPOOL> %d#, Resetting Error handling.\n", ObjectID);
			_errorOccurred = false;
			_waitHandles.ErrorEvent.Reset();
			Timer errorTimer = _errorTimer;
			_errorTimer = null;
			errorTimer?.Dispose();
		}

		internal DbConnectionInternal GetConnection(DbConnection owningObject)
		{
			//Discarded unreachable code: IL_0156, IL_0310
			DbConnectionInternal dbConnectionInternal = null;
			Transaction transaction = null;
			PerformanceCounters.SoftConnectsPerSecond.Increment();
			if (_state != State.Running)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, DbConnectionInternal State != Running.\n", ObjectID);
				return null;
			}
			Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Getting connection.\n", ObjectID);
			if (HasTransactionAffinity)
			{
				dbConnectionInternal = GetFromTransactedPool(out transaction);
			}
			if (dbConnectionInternal == null)
			{
				Interlocked.Increment(ref _waitCount);
				uint nCount = 3u;
				uint creationTimeout = (uint)CreationTimeout;
				do
				{
					int num = 3;
					int num2 = 0;
					bool success = false;
					RuntimeHelpers.PrepareConstrainedRegions();
					try
					{
						_waitHandles.DangerousAddRef(ref success);
						RuntimeHelpers.PrepareConstrainedRegions();
						try
						{
						}
						finally
						{
							num = System.Data.Common.SafeNativeMethods.WaitForMultipleObjectsEx(nCount, _waitHandles.DangerousGetHandle(), bWaitAll: false, creationTimeout, bAlertable: false);
						}
						switch (num)
						{
						case 258:
							Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Wait timed out.\n", ObjectID);
							Interlocked.Decrement(ref _waitCount);
							return null;
						case 1:
							Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Errors are set.\n", ObjectID);
							Interlocked.Decrement(ref _waitCount);
							throw _resError;
						case 2:
							Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Creating new connection.\n", ObjectID);
							try
							{
								dbConnectionInternal = UserCreateRequest(owningObject);
							}
							catch
							{
								if (dbConnectionInternal == null)
								{
									Interlocked.Decrement(ref _waitCount);
								}
								throw;
							}
							finally
							{
								if (dbConnectionInternal != null)
								{
									Interlocked.Decrement(ref _waitCount);
								}
							}
							if (dbConnectionInternal == null && Count >= MaxPoolSize && MaxPoolSize != 0 && !ReclaimEmancipatedObjects())
							{
								nCount = 2u;
							}
							goto end_IL_007a;
						case 0:
							Interlocked.Decrement(ref _waitCount);
							dbConnectionInternal = GetFromGeneralPool();
							goto end_IL_007a;
						case -1:
							Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Wait failed.\n", ObjectID);
							Interlocked.Decrement(ref _waitCount);
							Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
							break;
						case 128:
							Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Semaphore handle abandonded.\n", ObjectID);
							Interlocked.Decrement(ref _waitCount);
							throw new AbandonedMutexException(0, _waitHandles.PoolSemaphore);
						case 129:
							Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Error handle abandonded.\n", ObjectID);
							Interlocked.Decrement(ref _waitCount);
							throw new AbandonedMutexException(1, _waitHandles.ErrorEvent);
						case 130:
							Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, Creation handle abandoned.\n", ObjectID);
							Interlocked.Decrement(ref _waitCount);
							throw new AbandonedMutexException(2, _waitHandles.CreationSemaphore);
						}
						Bid.PoolerTrace("<prov.DbConnectionPool.GetConnection|RES|CPOOL> %d#, WaitForMultipleObjects=%d\n", ObjectID, num);
						Interlocked.Decrement(ref _waitCount);
						throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.UnexpectedWaitAnyResult);
						end_IL_007a:;
					}
					finally
					{
						if (2 == num && System.Data.Common.SafeNativeMethods.ReleaseSemaphore(_waitHandles.CreationHandle.DangerousGetHandle(), 1, IntPtr.Zero) == 0)
						{
							num2 = Marshal.GetHRForLastWin32Error();
						}
						if (success)
						{
							_waitHandles.DangerousRelease();
						}
					}
					if (num2 != 0)
					{
						Marshal.ThrowExceptionForHR(num2);
					}
				}
				while (dbConnectionInternal == null);
			}
			if (dbConnectionInternal != null)
			{
				lock (dbConnectionInternal)
				{
					dbConnectionInternal.PostPop(owningObject);
				}
				try
				{
					dbConnectionInternal.ActivateConnection(transaction);
					return dbConnectionInternal;
				}
				catch (SecurityException)
				{
					PutObject(dbConnectionInternal, owningObject);
					throw;
				}
			}
			return dbConnectionInternal;
		}

		private DbConnectionInternal GetFromGeneralPool()
		{
			DbConnectionInternal dbConnectionInternal = null;
			dbConnectionInternal = _stackNew.SynchronizedPop();
			if (dbConnectionInternal == null)
			{
				dbConnectionInternal = _stackOld.SynchronizedPop();
			}
			if (dbConnectionInternal != null)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.GetFromGeneralPool|RES|CPOOL> %d#, Connection %d#, Popped from general pool.\n", ObjectID, dbConnectionInternal.ObjectID);
				PerformanceCounters.NumberOfFreeConnections.Decrement();
			}
			return dbConnectionInternal;
		}

		private DbConnectionInternal GetFromTransactedPool(out Transaction transaction)
		{
			transaction = System.Data.Common.ADP.GetCurrentTransaction();
			DbConnectionInternal dbConnectionInternal = null;
			if (null != transaction && _transactedConnectionPool != null)
			{
				dbConnectionInternal = _transactedConnectionPool.GetTransactedObject(transaction);
				if (dbConnectionInternal != null)
				{
					Bid.PoolerTrace("<prov.DbConnectionPool.GetFromTransactedPool|RES|CPOOL> %d#, Connection %d#, Popped from transacted pool.\n", ObjectID, dbConnectionInternal.ObjectID);
					PerformanceCounters.NumberOfFreeConnections.Decrement();
				}
			}
			return dbConnectionInternal;
		}

		private void PoolCreateRequest(object state)
		{
			Bid.PoolerScopeEnter(out var hScp, "<prov.DbConnectionPool.PoolCreateRequest|RES|INFO|CPOOL> %d#\n", ObjectID);
			try
			{
				if (State.Running != _state)
				{
					return;
				}
				ReclaimEmancipatedObjects();
				if (ErrorOccurred || !NeedToReplenish || (UsingIntegrateSecurity && !_identity.Equals(DbConnectionPoolIdentity.GetCurrent())))
				{
					return;
				}
				bool success = false;
				int num = 3;
				uint creationTimeout = (uint)CreationTimeout;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					_waitHandles.DangerousAddRef(ref success);
					RuntimeHelpers.PrepareConstrainedRegions();
					try
					{
					}
					finally
					{
						num = System.Data.Common.SafeNativeMethods.WaitForSingleObjectEx(_waitHandles.CreationHandle.DangerousGetHandle(), creationTimeout, bAlertable: false);
					}
					if (num == 0)
					{
						if (ErrorOccurred)
						{
							return;
						}
						while (NeedToReplenish)
						{
							DbConnectionInternal dbConnectionInternal = CreateObject(null);
							if (dbConnectionInternal != null)
							{
								PutNewObject(dbConnectionInternal);
								continue;
							}
							break;
						}
					}
					else if (258 == num)
					{
						QueuePoolCreateRequest();
					}
					else
					{
						Bid.PoolerTrace("<prov.DbConnectionPool.PoolCreateRequest|RES|CPOOL> %d#, PoolCreateRequest called WaitForSingleObject failed %d", ObjectID, num);
					}
				}
				catch (Exception ex)
				{
					if (!System.Data.Common.ADP.IsCatchableExceptionType(ex))
					{
						throw;
					}
					Bid.PoolerTrace("<prov.DbConnectionPool.PoolCreateRequest|RES|CPOOL> %d#, PoolCreateRequest called CreateConnection which threw an exception: " + ex.ToString(), ObjectID);
				}
				finally
				{
					if (num == 0)
					{
						num = System.Data.Common.SafeNativeMethods.ReleaseSemaphore(_waitHandles.CreationHandle.DangerousGetHandle(), 1, IntPtr.Zero);
					}
					if (success)
					{
						_waitHandles.DangerousRelease();
					}
				}
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		private void ProcessDeactivateQueue(object state)
		{
			Bid.PoolerScopeEnter(out var hScp, "<prov.DbConnectionPool.ProcessDeactivateQueue|RES|INFO|CPOOL> %d#\n", ObjectID);
			try
			{
				object[] array;
				lock (_deactivateQueue.SyncRoot)
				{
					array = _deactivateQueue.ToArray();
					_deactivateQueue.Clear();
				}
				object[] array2 = array;
				for (int i = 0; i < array2.Length; i++)
				{
					DbConnectionInternal obj = (DbConnectionInternal)array2[i];
					PerformanceCounters.NumberOfStasisConnections.Decrement();
					DeactivateObject(obj);
				}
			}
			finally
			{
				Bid.ScopeLeave(ref hScp);
			}
		}

		internal void PutNewObject(DbConnectionInternal obj)
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.PutNewObject|RES|CPOOL> %d#, Connection %d#, Pushing to general pool.\n", ObjectID, obj.ObjectID);
			_stackNew.SynchronizedPush(obj);
			_waitHandles.PoolSemaphore.Release(1);
			PerformanceCounters.NumberOfFreeConnections.Increment();
		}

		internal void PutObject(DbConnectionInternal obj, object owningObject)
		{
			PerformanceCounters.SoftDisconnectsPerSecond.Increment();
			lock (obj)
			{
				obj.PrePush(owningObject);
			}
			if (UseDeactivateQueue)
			{
				Bid.PoolerTrace("<prov.DbConnectionPool.PutObject|RES|CPOOL> %d#, Connection %d#, Queueing for deactivation.\n", ObjectID, obj.ObjectID);
				PerformanceCounters.NumberOfStasisConnections.Increment();
				bool flag;
				lock (_deactivateQueue.SyncRoot)
				{
					flag = 0 == _deactivateQueue.Count;
					_deactivateQueue.Enqueue(obj);
				}
				if (flag)
				{
					ThreadPool.QueueUserWorkItem(_deactivateCallback, null);
				}
			}
			else
			{
				DeactivateObject(obj);
			}
		}

		internal void PutObjectFromTransactedPool(DbConnectionInternal obj)
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.PutObjectFromTransactedPool|RES|CPOOL> %d#, Connection %d#, Transaction has ended.\n", ObjectID, obj.ObjectID);
			if (_state == State.Running && obj.CanBePooled)
			{
				PutNewObject(obj);
				return;
			}
			DestroyObject(obj);
			QueuePoolCreateRequest();
		}

		private void QueuePoolCreateRequest()
		{
			if (State.Running == _state)
			{
				ThreadPool.QueueUserWorkItem(_poolCreateRequest);
			}
		}

		private bool ReclaimEmancipatedObjects()
		{
			bool result = false;
			Bid.PoolerTrace("<prov.DbConnectionPool.ReclaimEmancipatedObjects|RES|CPOOL> %d#\n", ObjectID);
			List<DbConnectionInternal> list = new List<DbConnectionInternal>();
			int count;
			lock (_objectList)
			{
				count = _objectList.Count;
				for (int i = 0; i < count; i++)
				{
					DbConnectionInternal dbConnectionInternal = _objectList[i];
					if (dbConnectionInternal == null)
					{
						continue;
					}
					bool flag = false;
					try
					{
						flag = Monitor.TryEnter(dbConnectionInternal);
						if (flag && dbConnectionInternal.IsEmancipated)
						{
							dbConnectionInternal.PrePush(null);
							list.Add(dbConnectionInternal);
						}
					}
					finally
					{
						if (flag)
						{
							Monitor.Exit(dbConnectionInternal);
						}
					}
				}
			}
			count = list.Count;
			for (int j = 0; j < count; j++)
			{
				DbConnectionInternal dbConnectionInternal2 = list[j];
				Bid.PoolerTrace("<prov.DbConnectionPool.ReclaimEmancipatedObjects|RES|CPOOL> %d#, Connection %d#, Reclaiming.\n", ObjectID, dbConnectionInternal2.ObjectID);
				PerformanceCounters.NumberOfReclaimedConnections.Increment();
				result = true;
				DeactivateObject(dbConnectionInternal2);
			}
			return result;
		}

		internal void Startup()
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.Startup|RES|INFO|CPOOL> %d#, CleanupWait=%d\n", ObjectID, _cleanupWait);
			_cleanupTimer = CreateCleanupTimer();
			if (NeedToReplenish)
			{
				QueuePoolCreateRequest();
			}
		}

		internal void Shutdown()
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.Shutdown|RES|INFO|CPOOL> %d#\n", ObjectID);
			_state = State.ShuttingDown;
			Timer cleanupTimer = _cleanupTimer;
			_cleanupTimer = null;
			cleanupTimer?.Dispose();
			cleanupTimer = _errorTimer;
			_errorTimer = null;
			cleanupTimer?.Dispose();
		}

		internal void TransactionEnded(Transaction transaction, DbConnectionInternal transactedObject)
		{
			Bid.PoolerTrace("<prov.DbConnectionPool.TransactionEnded|RES|CPOOL> %d#, Transaction %d#, Connection %d#, Transaction Completed\n", ObjectID, transaction.GetHashCode(), transactedObject.ObjectID);
			_transactedConnectionPool?.TransactionEnded(transaction, transactedObject);
		}

		private DbConnectionInternal UserCreateRequest(DbConnection owningObject)
		{
			DbConnectionInternal result = null;
			if (ErrorOccurred)
			{
				throw _resError;
			}
			if ((Count < MaxPoolSize || MaxPoolSize == 0) && ((Count & 1) == 1 || !ReclaimEmancipatedObjects()))
			{
				result = CreateObject(owningObject);
			}
			return result;
		}
	}
	internal sealed class DbConnectionPoolCountersNoCounters : DbConnectionPoolCounters
	{
		public static readonly DbConnectionPoolCountersNoCounters SingletonInstance = new DbConnectionPoolCountersNoCounters();

		private DbConnectionPoolCountersNoCounters()
		{
		}
	}
	internal sealed class DbConnectionPoolGroup
	{
		private const int PoolGroupStateActive = 1;

		private const int PoolGroupStateIdle = 2;

		private const int PoolGroupStateDisabled = 4;

		private readonly System.Data.Common.DbConnectionOptions _connectionOptions;

		private readonly DbConnectionPoolGroupOptions _poolGroupOptions;

		private HybridDictionary _poolCollection;

		private int _poolCount;

		private int _state;

		private DbConnectionPoolGroupProviderInfo _providerInfo;

		private DbMetaDataFactory _metaDataFactory;

		private static int _objectTypeCount;

		internal readonly int _objectID = Interlocked.Increment(ref _objectTypeCount);

		internal System.Data.Common.DbConnectionOptions ConnectionOptions => _connectionOptions;

		internal int Count => _poolCount;

		internal DbConnectionPoolGroupProviderInfo ProviderInfo
		{
			get
			{
				return _providerInfo;
			}
			set
			{
				_providerInfo = value;
				if (value != null)
				{
					_providerInfo.PoolGroup = this;
				}
			}
		}

		internal bool IsDisabled => 4 == _state;

		internal int ObjectID => _objectID;

		internal DbConnectionPoolGroupOptions PoolGroupOptions => _poolGroupOptions;

		internal DbMetaDataFactory MetaDataFactory
		{
			get
			{
				return _metaDataFactory;
			}
			set
			{
				_metaDataFactory = value;
			}
		}

		internal DbConnectionPoolGroup(System.Data.Common.DbConnectionOptions connectionOptions, DbConnectionPoolGroupOptions poolGroupOptions)
		{
			_connectionOptions = connectionOptions;
			_poolGroupOptions = poolGroupOptions;
			_poolCollection = new HybridDictionary(1, caseInsensitive: false);
			_state = 1;
		}

		internal void Clear()
		{
			ClearInternal(clearing: true);
		}

		private bool ClearInternal(bool clearing)
		{
			lock (this)
			{
				HybridDictionary poolCollection = _poolCollection;
				if (0 < poolCollection.Count)
				{
					HybridDictionary hybridDictionary = new HybridDictionary(poolCollection.Count, caseInsensitive: false);
					foreach (DictionaryEntry item in poolCollection)
					{
						if (item.Value != null)
						{
							DbConnectionPool dbConnectionPool = (DbConnectionPool)item.Value;
							if (clearing || (!dbConnectionPool.ErrorOccurred && dbConnectionPool.Count == 0))
							{
								DbConnectionFactory connectionFactory = dbConnectionPool.ConnectionFactory;
								connectionFactory.PerformanceCounters.NumberOfActiveConnectionPools.Decrement();
								connectionFactory.QueuePoolForRelease(dbConnectionPool, clearing);
							}
							else
							{
								hybridDictionary.Add(item.Key, item.Value);
							}
						}
					}
					_poolCollection = hybridDictionary;
					_poolCount = hybridDictionary.Count;
				}
				if (!clearing && _poolCount == 0)
				{
					if (1 == _state)
					{
						_state = 2;
						Bid.Trace("<prov.DbConnectionPoolGroup.ClearInternal|RES|INFO|CPOOL> %d#, Idle\n", ObjectID);
					}
					else if (2 == _state)
					{
						_state = 4;
						Bid.Trace("<prov.DbConnectionPoolGroup.ReadyToRemove|RES|INFO|CPOOL> %d#, Disabled\n", ObjectID);
					}
				}
				return 4 == _state;
			}
		}

		internal DbConnectionPool GetConnectionPool(DbConnectionFactory connectionFactory)
		{
			object obj = null;
			if (_poolGroupOptions != null)
			{
				DbConnectionPoolIdentity dbConnectionPoolIdentity = DbConnectionPoolIdentity.NoIdentity;
				if (_poolGroupOptions.PoolByIdentity)
				{
					dbConnectionPoolIdentity = DbConnectionPoolIdentity.GetCurrent();
					if (dbConnectionPoolIdentity.IsRestricted)
					{
						dbConnectionPoolIdentity = null;
					}
				}
				if (dbConnectionPoolIdentity != null)
				{
					HybridDictionary poolCollection = _poolCollection;
					obj = poolCollection[dbConnectionPoolIdentity];
					if (obj == null)
					{
						DbConnectionPoolProviderInfo connectionPoolProviderInfo = connectionFactory.CreateConnectionPoolProviderInfo(ConnectionOptions);
						DbConnectionPool dbConnectionPool = new DbConnectionPool(connectionFactory, this, dbConnectionPoolIdentity, connectionPoolProviderInfo);
						lock (this)
						{
							poolCollection = _poolCollection;
							obj = poolCollection[dbConnectionPoolIdentity];
							if (obj == null && MarkPoolGroupAsActive())
							{
								dbConnectionPool.Startup();
								HybridDictionary hybridDictionary = new HybridDictionary(1 + poolCollection.Count, caseInsensitive: false);
								foreach (DictionaryEntry item in poolCollection)
								{
									hybridDictionary.Add(item.Key, item.Value);
								}
								hybridDictionary.Add(dbConnectionPoolIdentity, dbConnectionPool);
								connectionFactory.PerformanceCounters.NumberOfActiveConnectionPools.Increment();
								_poolCollection = hybridDictionary;
								_poolCount = hybridDictionary.Count;
								obj = dbConnectionPool;
								dbConnectionPool = null;
							}
						}
						dbConnectionPool?.Shutdown();
					}
				}
			}
			if (obj == null)
			{
				lock (this)
				{
					MarkPoolGroupAsActive();
				}
			}
			return (DbConnectionPool)obj;
		}

		private bool MarkPoolGroupAsActive()
		{
			if (2 == _state)
			{
				_state = 1;
				Bid.Trace("<prov.DbConnectionPoolGroup.ClearInternal|RES|INFO|CPOOL> %d#, Active\n", ObjectID);
			}
			return 1 == _state;
		}

		internal bool Prune()
		{
			return ClearInternal(clearing: false);
		}
	}
	[Serializable]
	internal sealed class DbConnectionPoolIdentity
	{
		private const int E_NotImpersonationToken = -2147023587;

		private const int Win32_CheckTokenMembership = 1;

		private const int Win32_GetTokenInformation_1 = 2;

		private const int Win32_GetTokenInformation_2 = 3;

		private const int Win32_ConvertSidToStringSidW = 4;

		private const int Win32_CreateWellKnownSid = 5;

		public static readonly DbConnectionPoolIdentity NoIdentity = new DbConnectionPoolIdentity(string.Empty, isRestricted: false, isNetwork: true);

		private static readonly byte[] NetworkSid = (System.Data.Common.ADP.IsWindowsNT ? CreateWellKnownSid(WellKnownSidType.NetworkSid) : null);

		private readonly string _sidString;

		private readonly bool _isRestricted;

		private readonly bool _isNetwork;

		internal bool IsRestricted => _isRestricted;

		private DbConnectionPoolIdentity(string sidString, bool isRestricted, bool isNetwork)
		{
			_sidString = sidString;
			_isRestricted = isRestricted;
			_isNetwork = isNetwork;
		}

		private static byte[] CreateWellKnownSid(WellKnownSidType sidType)
		{
			uint resultSidLength = (uint)SecurityIdentifier.MaxBinaryLength;
			byte[] array = new byte[resultSidLength];
			if (System.Data.Common.UnsafeNativeMethods.CreateWellKnownSid((int)sidType, null, array, ref resultSidLength) == 0)
			{
				IntegratedSecurityError(5);
			}
			return array;
		}

		public override bool Equals(object value)
		{
			bool flag = this == NoIdentity || this == value;
			if (!flag && value != null)
			{
				DbConnectionPoolIdentity dbConnectionPoolIdentity = (DbConnectionPoolIdentity)value;
				flag = _sidString == dbConnectionPoolIdentity._sidString && _isRestricted == dbConnectionPoolIdentity._isRestricted && _isNetwork == dbConnectionPoolIdentity._isNetwork;
			}
			return flag;
		}

		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.ControlPrincipal)]
		internal static WindowsIdentity GetCurrentWindowsIdentity()
		{
			return WindowsIdentity.GetCurrent();
		}

		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		private static IntPtr GetWindowsIdentityToken(WindowsIdentity identity)
		{
			return identity.Token;
		}

		internal static DbConnectionPoolIdentity GetCurrent()
		{
			if (!System.Data.Common.ADP.IsWindowsNT)
			{
				return NoIdentity;
			}
			WindowsIdentity currentWindowsIdentity = GetCurrentWindowsIdentity();
			IntPtr windowsIdentityToken = GetWindowsIdentityToken(currentWindowsIdentity);
			uint num = 2048u;
			uint tokenString = 0u;
			IntPtr intPtr = IntPtr.Zero;
			IntPtr stringSid = IntPtr.Zero;
			System.Data.Common.UnsafeNativeMethods.SetLastError(0);
			bool isRestricted = System.Data.Common.UnsafeNativeMethods.IsTokenRestricted(windowsIdentityToken);
			if (Marshal.GetLastWin32Error() != 0)
			{
				Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
			}
			DbConnectionPoolIdentity dbConnectionPoolIdentity = null;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				if (!System.Data.Common.UnsafeNativeMethods.CheckTokenMembership(windowsIdentityToken, NetworkSid, out var isMember))
				{
					IntegratedSecurityError(1);
				}
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					intPtr = System.Data.Common.SafeNativeMethods.LocalAlloc(0, (IntPtr)num);
				}
				if (IntPtr.Zero == intPtr)
				{
					throw new OutOfMemoryException();
				}
				if (!System.Data.Common.UnsafeNativeMethods.GetTokenInformation(windowsIdentityToken, 1u, intPtr, num, ref tokenString))
				{
					if (tokenString > num)
					{
						num = tokenString;
						RuntimeHelpers.PrepareConstrainedRegions();
						try
						{
						}
						finally
						{
							System.Data.Common.SafeNativeMethods.LocalFree(intPtr);
							intPtr = IntPtr.Zero;
							intPtr = System.Data.Common.SafeNativeMethods.LocalAlloc(0, (IntPtr)num);
						}
						if (IntPtr.Zero == intPtr)
						{
							throw new OutOfMemoryException();
						}
						if (!System.Data.Common.UnsafeNativeMethods.GetTokenInformation(windowsIdentityToken, 1u, intPtr, num, ref tokenString))
						{
							IntegratedSecurityError(2);
						}
					}
					else
					{
						IntegratedSecurityError(3);
					}
				}
				currentWindowsIdentity.Dispose();
				IntPtr sid = Marshal.ReadIntPtr(intPtr, 0);
				if (!System.Data.Common.UnsafeNativeMethods.ConvertSidToStringSidW(sid, out stringSid))
				{
					IntegratedSecurityError(4);
				}
				if (IntPtr.Zero == stringSid)
				{
					throw System.Data.Common.ADP.InternalError(System.Data.Common.ADP.InternalErrorCode.ConvertSidToStringSidWReturnedNull);
				}
				string sidString = Marshal.PtrToStringUni(stringSid);
				return new DbConnectionPoolIdentity(sidString, isRestricted, isMember);
			}
			finally
			{
				if (IntPtr.Zero != intPtr)
				{
					System.Data.Common.SafeNativeMethods.LocalFree(intPtr);
					intPtr = IntPtr.Zero;
				}
				if (IntPtr.Zero != stringSid)
				{
					System.Data.Common.SafeNativeMethods.LocalFree(stringSid);
					stringSid = IntPtr.Zero;
				}
			}
		}

		public override int GetHashCode()
		{
			if (_sidString == null)
			{
				return 0;
			}
			return _sidString.GetHashCode();
		}

		private static void IntegratedSecurityError(int caller)
		{
			int hRForLastWin32Error = Marshal.GetHRForLastWin32Error();
			if (1 != caller || -2147023587 != hRForLastWin32Error)
			{
				Marshal.ThrowExceptionForHR(hRForLastWin32Error);
			}
		}
	}
	internal sealed class DbConnectionPoolGroupOptions
	{
		private readonly bool _poolByIdentity;

		private readonly int _minPoolSize;

		private readonly int _maxPoolSize;

		private readonly int _creationTimeout;

		private readonly TimeSpan _loadBalanceTimeout;

		private readonly bool _hasTransactionAffinity;

		private readonly bool _useDeactivateQueue;

		private readonly bool _useLoadBalancing;

		public int CreationTimeout => _creationTimeout;

		public bool HasTransactionAffinity => _hasTransactionAffinity;

		public TimeSpan LoadBalanceTimeout => _loadBalanceTimeout;

		public int MaxPoolSize => _maxPoolSize;

		public int MinPoolSize => _minPoolSize;

		public bool PoolByIdentity => _poolByIdentity;

		public bool UseDeactivateQueue => _useDeactivateQueue;

		public bool UseLoadBalancing => _useLoadBalancing;

		public DbConnectionPoolGroupOptions(bool poolByIdentity, int minPoolSize, int maxPoolSize, int creationTimeout, int loadBalanceTimeout, bool hasTransactionAffinity, bool useDeactivateQueue)
		{
			_poolByIdentity = poolByIdentity;
			_minPoolSize = minPoolSize;
			_maxPoolSize = maxPoolSize;
			_creationTimeout = creationTimeout;
			if (loadBalanceTimeout != 0)
			{
				_loadBalanceTimeout = new TimeSpan(0, 0, loadBalanceTimeout);
				_useLoadBalancing = true;
			}
			_hasTransactionAffinity = hasTransactionAffinity;
			_useDeactivateQueue = useDeactivateQueue;
		}
	}
	internal class DbConnectionPoolGroupProviderInfo
	{
		private DbConnectionPoolGroup _poolGroup;

		internal DbConnectionPoolGroup PoolGroup
		{
			get
			{
				return _poolGroup;
			}
			set
			{
				_poolGroup = value;
			}
		}
	}
	internal class DbConnectionPoolProviderInfo
	{
	}
	internal class DbMetaDataFactory
	{
		private const string _collectionName = "CollectionName";

		private const string _populationMechanism = "PopulationMechanism";

		private const string _populationString = "PopulationString";

		private const string _maximumVersion = "MaximumVersion";

		private const string _minimumVersion = "MinimumVersion";

		private const string _dataSourceProductVersionNormalized = "DataSourceProductVersionNormalized";

		private const string _dataSourceProductVersion = "DataSourceProductVersion";

		private const string _restrictionDefault = "RestrictionDefault";

		private const string _restrictionNumber = "RestrictionNumber";

		private const string _numberOfRestrictions = "NumberOfRestrictions";

		private const string _restrictionName = "RestrictionName";

		private const string _parameterName = "ParameterName";

		private const string _dataTable = "DataTable";

		private const string _sqlCommand = "SQLCommand";

		private const string _prepareCollection = "PrepareCollection";

		private DataSet _metaDataCollectionsDataSet;

		private string _normalizedServerVersion;

		private string _serverVersionString;

		public DbMetaDataFactory(Stream xmlStream, string serverVersion, string normalizedServerVersion)
		{
			System.Data.Common.ADP.CheckArgumentNull(xmlStream, "xmlStream");
			System.Data.Common.ADP.CheckArgumentNull(serverVersion, "serverVersion");
			System.Data.Common.ADP.CheckArgumentNull(normalizedServerVersion, "normalizedServerVersion");
			LoadDataSetFromXml(xmlStream);
			_serverVersionString = serverVersion;
			_normalizedServerVersion = normalizedServerVersion;
		}

		protected DataTable CloneAndFilterCollection(string collectionName, string[] hiddenColumnNames)
		{
			DataTable dataTable = _metaDataCollectionsDataSet.Tables[collectionName];
			if (dataTable == null || collectionName != dataTable.TableName)
			{
				throw System.Data.Common.ADP.DataTableDoesNotExist(collectionName);
			}
			DataTable dataTable2 = new DataTable(collectionName);
			dataTable2.Locale = CultureInfo.InvariantCulture;
			DataColumnCollection columns = dataTable2.Columns;
			DataColumn[] array = FilterColumns(dataTable, hiddenColumnNames, columns);
			foreach (DataRow row in dataTable.Rows)
			{
				if (SupportedByCurrentVersion(row))
				{
					DataRow dataRow2 = dataTable2.NewRow();
					for (int i = 0; i < columns.Count; i++)
					{
						dataRow2[columns[i]] = row[array[i], DataRowVersion.Current];
					}
					dataTable2.Rows.Add(dataRow2);
					dataRow2.AcceptChanges();
				}
			}
			return dataTable2;
		}

		public void Dispose()
		{
			Dispose(disposing: true);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing)
			{
				_normalizedServerVersion = null;
				_serverVersionString = null;
				_metaDataCollectionsDataSet.Dispose();
			}
		}

		private DataTable ExecuteCommand(DataRow requestedCollectionRow, string[] restrictions, DbConnection connection)
		{
			//Discarded unreachable code: IL_014f
			DataTable dataTable = _metaDataCollectionsDataSet.Tables[DbMetaDataCollectionNames.MetaDataCollections];
			DataColumn column = dataTable.Columns["PopulationString"];
			DataColumn column2 = dataTable.Columns["NumberOfRestrictions"];
			DataColumn column3 = dataTable.Columns["CollectionName"];
			DataTable dataTable2 = null;
			DbCommand dbCommand = null;
			DataTable dataTable3 = null;
			string commandText = requestedCollectionRow[column, DataRowVersion.Current] as string;
			int num = (int)requestedCollectionRow[column2, DataRowVersion.Current];
			string text = requestedCollectionRow[column3, DataRowVersion.Current] as string;
			if (restrictions != null && restrictions.Length > num)
			{
				throw System.Data.Common.ADP.TooManyRestrictions(text);
			}
			dbCommand = connection.CreateCommand();
			dbCommand.CommandText = commandText;
			dbCommand.CommandTimeout = Math.Max(dbCommand.CommandTimeout, 180);
			for (int i = 0; i < num; i++)
			{
				DbParameter dbParameter = dbCommand.CreateParameter();
				if (restrictions != null && restrictions.Length > i && restrictions[i] != null)
				{
					dbParameter.Value = restrictions[i];
				}
				else
				{
					dbParameter.Value = DBNull.Value;
				}
				dbParameter.ParameterName = GetParameterName(text, i + 1);
				dbParameter.Direction = ParameterDirection.Input;
				dbCommand.Parameters.Add(dbParameter);
			}
			DbDataReader dbDataReader = null;
			try
			{
				try
				{
					dbDataReader = dbCommand.ExecuteReader();
				}
				catch (Exception e)
				{
					if (!System.Data.Common.ADP.IsCatchableExceptionType(e))
					{
						throw;
					}
					throw System.Data.Common.ADP.QueryFailed(text, e);
				}
				dataTable2 = new DataTable(text);
				dataTable2.Locale = CultureInfo.InvariantCulture;
				dataTable3 = dbDataReader.GetSchemaTable();
				foreach (DataRow row in dataTable3.Rows)
				{
					dataTable2.Columns.Add(row["ColumnName"] as string, (Type)row["DataType"]);
				}
				object[] values = new object[dataTable2.Columns.Count];
				while (dbDataReader.Read())
				{
					dbDataReader.GetValues(values);
					dataTable2.Rows.Add(values);
				}
				return dataTable2;
			}
			finally
			{
				if (dbDataReader != null)
				{
					dbDataReader.Dispose();
					dbDataReader = null;
				}
			}
		}

		private DataColumn[] FilterColumns(DataTable sourceTable, string[] hiddenColumnNames, DataColumnCollection destinationColumns)
		{
			DataColumn[] array = null;
			int num = 0;
			foreach (DataColumn column2 in sourceTable.Columns)
			{
				if (IncludeThisColumn(column2, hiddenColumnNames))
				{
					num++;
				}
			}
			if (num == 0)
			{
				throw System.Data.Common.ADP.NoColumns();
			}
			int num2 = 0;
			array = new DataColumn[num];
			foreach (DataColumn column3 in sourceTable.Columns)
			{
				if (IncludeThisColumn(column3, hiddenColumnNames))
				{
					DataColumn column = new DataColumn(column3.ColumnName, column3.DataType);
					destinationColumns.Add(column);
					array[num2] = column3;
					num2++;
				}
			}
			return array;
		}

		internal DataRow FindMetaDataCollectionRow(string collectionName)
		{
			DataTable dataTable = _metaDataCollectionsDataSet.Tables[DbMetaDataCollectionNames.MetaDataCollections];
			if (dataTable == null)
			{
				throw System.Data.Common.ADP.InvalidXml();
			}
			DataColumn dataColumn = dataTable.Columns[DbMetaDataColumnNames.CollectionName];
			if (dataColumn == null || typeof(string) != dataColumn.DataType)
			{
				throw System.Data.Common.ADP.InvalidXmlMissingColumn(DbMetaDataCollectionNames.MetaDataCollections, DbMetaDataColumnNames.CollectionName);
			}
			DataRow dataRow = null;
			string text = null;
			bool flag = false;
			bool flag2 = false;
			bool flag3 = false;
			foreach (DataRow row in dataTable.Rows)
			{
				string text2 = row[dataColumn, DataRowVersion.Current] as string;
				if (System.Data.Common.ADP.IsEmpty(text2))
				{
					throw System.Data.Common.ADP.InvalidXmlInvalidValue(DbMetaDataCollectionNames.MetaDataCollections, DbMetaDataColumnNames.CollectionName);
				}
				if (!System.Data.Common.ADP.CompareInsensitiveInvariant(text2, collectionName))
				{
					continue;
				}
				if (!SupportedByCurrentVersion(row))
				{
					flag = true;
				}
				else if (collectionName == text2)
				{
					if (flag2)
					{
						throw System.Data.Common.ADP.CollectionNameIsNotUnique(collectionName);
					}
					dataRow = row;
					text = text2;
					flag2 = true;
				}
				else
				{
					if (text != null)
					{
						flag3 = true;
					}
					dataRow = row;
					text = text2;
				}
			}
			if (dataRow == null)
			{
				if (!flag)
				{
					throw System.Data.Common.ADP.UndefinedCollection(collectionName);
				}
				throw System.Data.Common.ADP.UnsupportedVersion(collectionName);
			}
			if (!flag2 && flag3)
			{
				throw System.Data.Common.ADP.AmbigousCollectionName(collectionName);
			}
			return dataRow;
		}

		private void FixUpVersion(DataTable dataSourceInfoTable)
		{
			DataColumn dataColumn = dataSourceInfoTable.Columns["DataSourceProductVersion"];
			DataColumn dataColumn2 = dataSourceInfoTable.Columns["DataSourceProductVersionNormalized"];
			if (dataColumn == null || dataColumn2 == null)
			{
				throw System.Data.Common.ADP.MissingDataSourceInformationColumn();
			}
			if (dataSourceInfoTable.Rows.Count != 1)
			{
				throw System.Data.Common.ADP.IncorrectNumberOfDataSourceInformationRows();
			}
			DataRow dataRow = dataSourceInfoTable.Rows[0];
			dataRow[dataColumn] = _serverVersionString;
			dataRow[dataColumn2] = _normalizedServerVersion;
			dataRow.AcceptChanges();
		}

		private string GetParameterName(string neededCollectionName, int neededRestrictionNumber)
		{
			DataTable dataTable = null;
			DataColumnCollection dataColumnCollection = null;
			DataColumn dataColumn = null;
			DataColumn dataColumn2 = null;
			DataColumn dataColumn3 = null;
			DataColumn dataColumn4 = null;
			string text = null;
			dataTable = _metaDataCollectionsDataSet.Tables[DbMetaDataCollectionNames.Restrictions];
			if (dataTable != null)
			{
				dataColumnCollection = dataTable.Columns;
				if (dataColumnCollection != null)
				{
					dataColumn = dataColumnCollection["CollectionName"];
					dataColumn2 = dataColumnCollection["ParameterName"];
					dataColumn3 = dataColumnCollection["RestrictionName"];
					dataColumn4 = dataColumnCollection["RestrictionNumber"];
				}
			}
			if (dataColumn2 == null || dataColumn == null || dataColumn3 == null || dataColumn4 == null)
			{
				throw System.Data.Common.ADP.MissingRestrictionColumn();
			}
			foreach (DataRow row in dataTable.Rows)
			{
				if ((string)row[dataColumn] == neededCollectionName && (int)row[dataColumn4] == neededRestrictionNumber && SupportedByCurrentVersion(row))
				{
					text = (string)row[dataColumn2];
					break;
				}
			}
			if (text == null)
			{
				throw System.Data.Common.ADP.MissingRestrictionRow();
			}
			return text;
		}

		public virtual DataTable GetSchema(DbConnection connection, string collectionName, string[] restrictions)
		{
			DataTable dataTable = _metaDataCollectionsDataSet.Tables[DbMetaDataCollectionNames.MetaDataCollections];
			DataColumn column = dataTable.Columns["PopulationMechanism"];
			DataColumn column2 = dataTable.Columns[DbMetaDataColumnNames.CollectionName];
			DataRow dataRow = null;
			DataTable dataTable2 = null;
			string text = null;
			dataRow = FindMetaDataCollectionRow(collectionName);
			text = dataRow[column2, DataRowVersion.Current] as string;
			if (!System.Data.Common.ADP.IsEmptyArray(restrictions))
			{
				for (int i = 0; i < restrictions.Length; i++)
				{
					if (restrictions[i] != null && restrictions[i].Length > 4096)
					{
						throw System.Data.Common.ADP.NotSupported();
					}
				}
			}
			string text2 = dataRow[column, DataRowVersion.Current] as string;
			switch (text2)
			{
			case "DataTable":
			{
				string[] hiddenColumnNames = ((!(text == DbMetaDataCollectionNames.MetaDataCollections)) ? null : new string[2] { "PopulationMechanism", "PopulationString" });
				if (!System.Data.Common.ADP.IsEmptyArray(restrictions))
				{
					throw System.Data.Common.ADP.TooManyRestrictions(text);
				}
				dataTable2 = CloneAndFilterCollection(text, hiddenColumnNames);
				if (text == DbMetaDataCollectionNames.DataSourceInformation)
				{
					FixUpVersion(dataTable2);
				}
				break;
			}
			case "SQLCommand":
				dataTable2 = ExecuteCommand(dataRow, restrictions, connection);
				break;
			case "PrepareCollection":
				dataTable2 = PrepareCollection(text, restrictions, connection);
				break;
			default:
				throw System.Data.Common.ADP.UndefinedPopulationMechanism(text2);
			}
			return dataTable2;
		}

		private bool IncludeThisColumn(DataColumn sourceColumn, string[] hiddenColumnNames)
		{
			bool result = true;
			string columnName = sourceColumn.ColumnName;
			switch (columnName)
			{
			case "MinimumVersion":
			case "MaximumVersion":
				result = false;
				break;
			default:
			{
				if (hiddenColumnNames == null)
				{
					break;
				}
				for (int i = 0; i < hiddenColumnNames.Length; i++)
				{
					if (hiddenColumnNames[i] == columnName)
					{
						result = false;
						break;
					}
				}
				break;
			}
			}
			return result;
		}

		private void LoadDataSetFromXml(Stream XmlStream)
		{
			_metaDataCollectionsDataSet = new DataSet();
			_metaDataCollectionsDataSet.Locale = CultureInfo.InvariantCulture;
			_metaDataCollectionsDataSet.ReadXml(XmlStream);
		}

		protected virtual DataTable PrepareCollection(string collectionName, string[] restrictions, DbConnection connection)
		{
			throw System.Data.Common.ADP.NotSupported();
		}

		private bool SupportedByCurrentVersion(DataRow requestedCollectionRow)
		{
			bool flag = true;
			DataColumnCollection columns = requestedCollectionRow.Table.Columns;
			DataColumn dataColumn = columns["MinimumVersion"];
			if (dataColumn != null)
			{
				object obj = requestedCollectionRow[dataColumn];
				if (obj != null && obj != DBNull.Value && 0 > string.Compare(_normalizedServerVersion, (string)obj, StringComparison.OrdinalIgnoreCase))
				{
					flag = false;
				}
			}
			if (flag)
			{
				dataColumn = columns["MaximumVersion"];
				if (dataColumn != null)
				{
					object obj = requestedCollectionRow[dataColumn];
					if (obj != null && obj != DBNull.Value && 0 < string.Compare(_normalizedServerVersion, (string)obj, StringComparison.OrdinalIgnoreCase))
					{
						flag = false;
					}
				}
			}
			return flag;
		}
	}
	internal abstract class DbReferenceCollection
	{
		public abstract void Add(object value, int tag);

		public abstract void Notify(int message);

		public abstract void Remove(object value);
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
