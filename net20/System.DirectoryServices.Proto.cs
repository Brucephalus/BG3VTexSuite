
// C:\WINDOWS\assembly\GAC_MSIL\System.DirectoryServices.Protocols\2.0.0.0__b03f5f7f11d50a3a\System.DirectoryServices.Protocols.dll
// System.DirectoryServices.Protocols, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
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
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using Microsoft.Win32.SafeHandles;

[assembly: ComVisible(false)]
[assembly: CompilationRelaxations(8)]
[assembly: CLSCompliant(true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyDefaultAlias("System.DirectoryServices.Protocols.dll")]
[assembly: AssemblyTitle("System.DirectoryServices.Protocols.dll")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDescription("System.DirectoryServices.Protocols.dll")]
[assembly: NetworkInformationPermission(SecurityAction.RequestMinimum, Unrestricted = true)]
[assembly: EnvironmentPermission(SecurityAction.RequestMinimum, Unrestricted = true)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, UnmanagedCode = true)]
[assembly: WebPermission(SecurityAction.RequestMinimum, Unrestricted = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
namespace System.DirectoryServices.Protocols
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
		internal const string DsmlNonHttpUri = "DsmlNonHttpUri";

		internal const string NoNegativeTime = "NoNegativeTime";

		internal const string NoNegativeSizeLimit = "NoNegativeSizeLimit";

		internal const string InvalidDocument = "InvalidDocument";

		internal const string MissingSessionId = "MissingSessionId";

		internal const string MissingResponse = "MissingResponse";

		internal const string ErrorResponse = "ErrorResponse";

		internal const string BadControl = "BadControl";

		internal const string NullDirectoryAttribute = "NullDirectoryAttribute";

		internal const string NullDirectoryAttributeCollection = "NullDirectoryAttributeCollection";

		internal const string WhiteSpaceServerName = "WhiteSpaceServerName";

		internal const string DirectoryAttributeConversion = "DirectoryAttributeConversion";

		internal const string WrongNumValuesCompare = "WrongNumValuesCompare";

		internal const string WrongAssertionCompare = "WrongAssertionCompare";

		internal const string DefaultOperationsError = "DefaultOperationsError";

		internal const string BadSearchLDAPFilter = "BadSearchLDAPFilter";

		internal const string ReadOnlyProperty = "ReadOnlyProperty";

		internal const string MissingOperationResponseResultCode = "MissingOperationResponseResultCode";

		internal const string MissingSearchResultEntryDN = "MissingSearchResultEntryDN";

		internal const string MissingSearchResultEntryAttributeName = "MissingSearchResultEntryAttributeName";

		internal const string BadOperationResponseResultCode = "BadOperationResponseResultCode";

		internal const string MissingErrorResponseType = "MissingErrorResponseType";

		internal const string ErrorResponseInvalidValue = "ErrorResponseInvalidValue";

		internal const string NotSupportOnDsmlErrRes = "NotSupportOnDsmlErrRes";

		internal const string BadBase64Value = "BadBase64Value";

		internal const string WrongAuthType = "WrongAuthType";

		internal const string SessionInUse = "SessionInUse";

		internal const string ReadOnlyDocument = "ReadOnlyDocument";

		internal const string NotWellFormedResponse = "NotWellFormedResponse";

		internal const string NoCurrentSession = "NoCurrentSession";

		internal const string UnknownResponseElement = "UnknownResponseElement";

		internal const string InvalidClientCertificates = "InvalidClientCertificates";

		internal const string InvalidAuthCredential = "InvalidAuthCredential";

		internal const string InvalidLdapSearchRequestFilter = "InvalidLdapSearchRequestFilter";

		internal const string PartialResultsNotSupported = "PartialResultsNotSupported";

		internal const string BerConverterNotMatch = "BerConverterNotMatch";

		internal const string BerConverterUndefineChar = "BerConverterUndefineChar";

		internal const string BerConversionError = "BerConversionError";

		internal const string TLSStopFailure = "TLSStopFailure";

		internal const string NoPartialResults = "NoPartialResults";

		internal const string DefaultLdapError = "DefaultLdapError";

		internal const string LDAP_PARTIAL_RESULTS = "LDAP_PARTIAL_RESULTS";

		internal const string LDAP_IS_LEAF = "LDAP_IS_LEAF";

		internal const string LDAP_SORT_CONTROL_MISSING = "LDAP_SORT_CONTROL_MISSING";

		internal const string LDAP_OFFSET_RANGE_ERROR = "LDAP_OFFSET_RANGE_ERROR";

		internal const string LDAP_RESULTS_TOO_LARGE = "LDAP_RESULTS_TOO_LARGE";

		internal const string LDAP_SERVER_DOWN = "LDAP_SERVER_DOWN";

		internal const string LDAP_LOCAL_ERROR = "LDAP_LOCAL_ERROR";

		internal const string LDAP_ENCODING_ERROR = "LDAP_ENCODING_ERROR";

		internal const string LDAP_DECODING_ERROR = "LDAP_DECODING_ERROR";

		internal const string LDAP_TIMEOUT = "LDAP_TIMEOUT";

		internal const string LDAP_AUTH_UNKNOWN = "LDAP_AUTH_UNKNOWN";

		internal const string LDAP_FILTER_ERROR = "LDAP_FILTER_ERROR";

		internal const string LDAP_USER_CANCELLED = "LDAP_USER_CANCELLED";

		internal const string LDAP_PARAM_ERROR = "LDAP_PARAM_ERROR";

		internal const string LDAP_NO_MEMORY = "LDAP_NO_MEMORY";

		internal const string LDAP_CONNECT_ERROR = "LDAP_CONNECT_ERROR";

		internal const string LDAP_NOT_SUPPORTED = "LDAP_NOT_SUPPORTED";

		internal const string LDAP_NO_RESULTS_RETURNED = "LDAP_NO_RESULTS_RETURNED";

		internal const string LDAP_CONTROL_NOT_FOUND = "LDAP_CONTROL_NOT_FOUND";

		internal const string LDAP_MORE_RESULTS_TO_RETURN = "LDAP_MORE_RESULTS_TO_RETURN";

		internal const string LDAP_CLIENT_LOOP = "LDAP_CLIENT_LOOP";

		internal const string LDAP_REFERRAL_LIMIT_EXCEEDED = "LDAP_REFERRAL_LIMIT_EXCEEDED";

		internal const string LDAP_INVALID_CREDENTIALS = "LDAP_INVALID_CREDENTIALS";

		internal const string LDAP_SUCCESS = "LDAP_SUCCESS";

		internal const string NoSessionIDReturned = "NoSessionIDReturned";

		internal const string LDAP_OPERATIONS_ERROR = "LDAP_OPERATIONS_ERROR";

		internal const string LDAP_PROTOCOL_ERROR = "LDAP_PROTOCOL_ERROR";

		internal const string LDAP_TIMELIMIT_EXCEEDED = "LDAP_TIMELIMIT_EXCEEDED";

		internal const string LDAP_SIZELIMIT_EXCEEDED = "LDAP_SIZELIMIT_EXCEEDED";

		internal const string LDAP_COMPARE_FALSE = "LDAP_COMPARE_FALSE";

		internal const string LDAP_COMPARE_TRUE = "LDAP_COMPARE_TRUE";

		internal const string LDAP_AUTH_METHOD_NOT_SUPPORTED = "LDAP_AUTH_METHOD_NOT_SUPPORTED";

		internal const string LDAP_STRONG_AUTH_REQUIRED = "LDAP_STRONG_AUTH_REQUIRED";

		internal const string LDAP_REFERRAL = "LDAP_REFERRAL";

		internal const string LDAP_ADMIN_LIMIT_EXCEEDED = "LDAP_ADMIN_LIMIT_EXCEEDED";

		internal const string LDAP_UNAVAILABLE_CRIT_EXTENSION = "LDAP_UNAVAILABLE_CRIT_EXTENSION";

		internal const string LDAP_CONFIDENTIALITY_REQUIRED = "LDAP_CONFIDENTIALITY_REQUIRED";

		internal const string LDAP_SASL_BIND_IN_PROGRESS = "LDAP_SASL_BIND_IN_PROGRESS";

		internal const string LDAP_NO_SUCH_ATTRIBUTE = "LDAP_NO_SUCH_ATTRIBUTE";

		internal const string LDAP_UNDEFINED_TYPE = "LDAP_UNDEFINED_TYPE";

		internal const string LDAP_INAPPROPRIATE_MATCHING = "LDAP_INAPPROPRIATE_MATCHING";

		internal const string LDAP_CONSTRAINT_VIOLATION = "LDAP_CONSTRAINT_VIOLATION";

		internal const string LDAP_ATTRIBUTE_OR_VALUE_EXISTS = "LDAP_ATTRIBUTE_OR_VALUE_EXISTS";

		internal const string LDAP_INVALID_SYNTAX = "LDAP_INVALID_SYNTAX";

		internal const string LDAP_NO_SUCH_OBJECT = "LDAP_NO_SUCH_OBJECT";

		internal const string LDAP_ALIAS_PROBLEM = "LDAP_ALIAS_PROBLEM";

		internal const string LDAP_INVALID_DN_SYNTAX = "LDAP_INVALID_DN_SYNTAX";

		internal const string LDAP_ALIAS_DEREF_PROBLEM = "LDAP_ALIAS_DEREF_PROBLEM";

		internal const string LDAP_INAPPROPRIATE_AUTH = "LDAP_INAPPROPRIATE_AUTH";

		internal const string LDAP_INSUFFICIENT_RIGHTS = "LDAP_INSUFFICIENT_RIGHTS";

		internal const string LDAP_BUSY = "LDAP_BUSY";

		internal const string LDAP_UNAVAILABLE = "LDAP_UNAVAILABLE";

		internal const string LDAP_UNWILLING_TO_PERFORM = "LDAP_UNWILLING_TO_PERFORM";

		internal const string LDAP_LOOP_DETECT = "LDAP_LOOP_DETECT";

		internal const string LDAP_NAMING_VIOLATION = "LDAP_NAMING_VIOLATION";

		internal const string LDAP_OBJECT_CLASS_VIOLATION = "LDAP_OBJECT_CLASS_VIOLATION";

		internal const string LDAP_NOT_ALLOWED_ON_NONLEAF = "LDAP_NOT_ALLOWED_ON_NONLEAF";

		internal const string LDAP_NOT_ALLOWED_ON_RDN = "LDAP_NOT_ALLOWED_ON_RDN";

		internal const string LDAP_ALREADY_EXISTS = "LDAP_ALREADY_EXISTS";

		internal const string LDAP_NO_OBJECT_CLASS_MODS = "LDAP_NO_OBJECT_CLASS_MODS";

		internal const string LDAP_AFFECTS_MULTIPLE_DSAS = "LDAP_AFFECTS_MULTIPLE_DSAS";

		internal const string LDAP_VIRTUAL_LIST_VIEW_ERROR = "LDAP_VIRTUAL_LIST_VIEW_ERROR";

		internal const string LDAP_OTHER = "LDAP_OTHER";

		internal const string LDAP_SEND_TIMEOUT = "LDAP_SEND_TIMEOUT";

		internal const string InvalidAsyncResult = "InvalidAsyncResult";

		internal const string ValidDirectoryAttributeType = "ValidDirectoryAttributeType";

		internal const string ValidFilterType = "ValidFilterType";

		internal const string ValidValuesType = "ValidValuesType";

		internal const string ValidValueType = "ValidValueType";

		internal const string SupportedPlatforms = "SupportedPlatforms";

		internal const string TLSNotSupported = "TLSNotSupported";

		internal const string InvalidValueType = "InvalidValueType";

		internal const string ValidValue = "ValidValue";

		internal const string ContainNullControl = "ContainNullControl";

		internal const string InvalidFilterType = "InvalidFilterType";

		internal const string NotReturnedAsyncResult = "NotReturnedAsyncResult";

		internal const string DsmlAuthRequestNotSupported = "DsmlAuthRequestNotSupported";

		internal const string CallBackIsNull = "CallBackIsNull";

		internal const string NullValueArray = "NullValueArray";

		internal const string NonCLSException = "NonCLSException";

		internal const string ConcurrentBindNotSupport = "ConcurrentBindNotSupport";

		internal const string TimespanExceedMax = "TimespanExceedMax";

		internal const string InvliadRequestType = "InvliadRequestType";

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
			resources = new ResourceManager("System.DirectoryServices.Protocols", GetType().Assembly);
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
}
namespace System.DirectoryServices.Protocols
{
	public enum AuthType
	{
		Anonymous,
		Basic,
		Negotiate,
		Ntlm,
		Digest,
		Sicily,
		Dpa,
		Msn,
		External,
		Kerberos
	}
	public enum PartialResultProcessing
	{
		NoPartialResultSupport,
		ReturnPartialResults,
		ReturnPartialResultsAndNotifyCallback
	}
	public sealed class BerConverter
	{
		private BerConverter()
		{
		}

		public static byte[] Encode(string format, params object[] value)
		{
			Utility.CheckOSVersion();
			if (format == null)
			{
				throw new ArgumentNullException("format");
			}
			UTF8Encoding uTF8Encoding = new UTF8Encoding();
			byte[] array = null;
			if (value == null)
			{
				value = new object[0];
			}
			BerSafeHandle berElement = new BerSafeHandle();
			int num = 0;
			int num2 = 0;
			foreach (char c in format)
			{
				switch (c)
				{
				case '[':
				case ']':
				case 'n':
				case '{':
				case '}':
					num2 = Wldap32.ber_printf_emptyarg(berElement, new string(c, 1));
					break;
				case 'e':
				case 'i':
				case 't':
					if (num >= value.Length)
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					if (!(value[num] is int))
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					num2 = Wldap32.ber_printf_int(berElement, new string(c, 1), (int)value[num]);
					num++;
					break;
				case 'b':
					if (num >= value.Length)
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					if (!(value[num] is bool))
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					num2 = Wldap32.ber_printf_int(berElement, new string(c, 1), ((bool)value[num]) ? 1 : 0);
					num++;
					break;
				case 's':
				{
					if (num >= value.Length)
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					if (value[num] != null && !(value[num] is string))
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					byte[] tempValue2 = null;
					if (value[num] != null)
					{
						tempValue2 = uTF8Encoding.GetBytes((string)value[num]);
					}
					num2 = EncodingByteArrayHelper(berElement, tempValue2, 'o');
					num++;
					break;
				}
				case 'X':
				case 'o':
				{
					if (num >= value.Length)
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					if (value[num] != null && !(value[num] is byte[]))
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					byte[] tempValue3 = (byte[])value[num];
					num2 = EncodingByteArrayHelper(berElement, tempValue3, c);
					num++;
					break;
				}
				case 'v':
				{
					if (num >= value.Length)
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					if (value[num] != null && !(value[num] is string[]))
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					string[] array2 = (string[])value[num];
					byte[][] array3 = null;
					if (array2 != null)
					{
						array3 = new byte[array2.Length][];
						for (int j = 0; j < array2.Length; j++)
						{
							string text = array2[j];
							if (text == null)
							{
								array3[j] = null;
							}
							else
							{
								array3[j] = uTF8Encoding.GetBytes(text);
							}
						}
					}
					num2 = EncodingMultiByteArrayHelper(berElement, array3, 'V');
					num++;
					break;
				}
				case 'V':
				{
					if (num >= value.Length)
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					if (value[num] != null && !(value[num] is byte[][]))
					{
						throw new ArgumentException(Res.GetString("BerConverterNotMatch"));
					}
					byte[][] tempValue = (byte[][])value[num];
					num2 = EncodingMultiByteArrayHelper(berElement, tempValue, c);
					num++;
					break;
				}
				default:
					throw new ArgumentException(Res.GetString("BerConverterUndefineChar"));
				}
				if (num2 == -1)
				{
					throw new BerConversionException();
				}
			}
			berval berval2 = new berval();
			IntPtr value2 = (IntPtr)0;
			try
			{
				num2 = Wldap32.ber_flatten(berElement, ref value2);
				if (num2 == -1)
				{
					throw new BerConversionException();
				}
				if (value2 != (IntPtr)0)
				{
					Marshal.PtrToStructure(value2, berval2);
				}
				if (berval2 == null || berval2.bv_len == 0)
				{
					return new byte[0];
				}
				array = new byte[berval2.bv_len];
				Marshal.Copy(berval2.bv_val, array, 0, berval2.bv_len);
				return array;
			}
			finally
			{
				if (value2 != (IntPtr)0)
				{
					Wldap32.ber_bvfree(value2);
				}
			}
		}

		public static object[] Decode(string format, byte[] value)
		{
			bool decodeSucceeded;
			object[] result = TryDecode(format, value, out decodeSucceeded);
			if (decodeSucceeded)
			{
				return result;
			}
			throw new BerConversionException();
		}

		internal static object[] TryDecode(string format, byte[] value, out bool decodeSucceeded)
		{
			Utility.CheckOSVersion();
			if (format == null)
			{
				throw new ArgumentNullException("format");
			}
			UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
			berval berval2 = new berval();
			ArrayList arrayList = new ArrayList();
			BerSafeHandle berElement = null;
			object[] result = null;
			decodeSucceeded = false;
			if (value == null)
			{
				berval2.bv_len = 0;
				berval2.bv_val = (IntPtr)0;
			}
			else
			{
				berval2.bv_len = value.Length;
				berval2.bv_val = Marshal.AllocHGlobal(value.Length);
				Marshal.Copy(value, 0, berval2.bv_val, value.Length);
			}
			try
			{
				berElement = new BerSafeHandle(berval2);
			}
			finally
			{
				if (berval2.bv_val != (IntPtr)0)
				{
					Marshal.FreeHGlobal(berval2.bv_val);
				}
			}
			int error = 0;
			foreach (char c in format)
			{
				switch (c)
				{
				case '[':
				case ']':
				case 'n':
				case 'x':
				case '{':
				case '}':
					error = Wldap32.ber_scanf(berElement, new string(c, 1));
					if (error == 0)
					{
					}
					break;
				case 'b':
				case 'e':
				case 'i':
				{
					int value5 = 0;
					error = Wldap32.ber_scanf_int(berElement, new string(c, 1), ref value5);
					if (error == 0)
					{
						if (c == 'b')
						{
							bool flag = false;
							flag = ((value5 != 0) ? true : false);
							arrayList.Add(flag);
						}
						else
						{
							arrayList.Add(value5);
						}
					}
					break;
				}
				case 'a':
				{
					byte[] array5 = DecodingByteArrayHelper(berElement, 'O', ref error);
					if (error == 0)
					{
						string value3 = null;
						if (array5 != null)
						{
							value3 = uTF8Encoding.GetString(array5);
						}
						arrayList.Add(value3);
					}
					break;
				}
				case 'O':
				{
					byte[] value4 = DecodingByteArrayHelper(berElement, c, ref error);
					if (error == 0)
					{
						arrayList.Add(value4);
					}
					break;
				}
				case 'B':
				{
					IntPtr value2 = (IntPtr)0;
					int length = 0;
					error = Wldap32.ber_scanf_bitstring(berElement, "B", ref value2, ref length);
					if (error == 0)
					{
						byte[] array2 = null;
						if (value2 != (IntPtr)0)
						{
							array2 = new byte[length];
							Marshal.Copy(value2, array2, 0, length);
						}
						arrayList.Add(array2);
					}
					break;
				}
				case 'v':
				{
					byte[][] array3 = null;
					string[] array4 = null;
					array3 = DecodingMultiByteArrayHelper(berElement, 'V', ref error);
					if (error != 0)
					{
						break;
					}
					if (array3 != null)
					{
						array4 = new string[array3.Length];
						for (int j = 0; j < array3.Length; j++)
						{
							if (array3[j] == null)
							{
								array4[j] = null;
							}
							else
							{
								array4[j] = uTF8Encoding.GetString(array3[j]);
							}
						}
					}
					arrayList.Add(array4);
					break;
				}
				case 'V':
				{
					byte[][] array = null;
					array = DecodingMultiByteArrayHelper(berElement, c, ref error);
					if (error == 0)
					{
						arrayList.Add(array);
					}
					break;
				}
				default:
					throw new ArgumentException(Res.GetString("BerConverterUndefineChar"));
				}
				if (error != 0)
				{
					return result;
				}
			}
			result = new object[arrayList.Count];
			for (int k = 0; k < arrayList.Count; k++)
			{
				result[k] = arrayList[k];
			}
			decodeSucceeded = true;
			return result;
		}

		private static int EncodingByteArrayHelper(BerSafeHandle berElement, byte[] tempValue, char fmt)
		{
			int num = 0;
			if (tempValue != null)
			{
				IntPtr intPtr = Marshal.AllocHGlobal(tempValue.Length);
				Marshal.Copy(tempValue, 0, intPtr, tempValue.Length);
				HGlobalMemHandle value = new HGlobalMemHandle(intPtr);
				return Wldap32.ber_printf_bytearray(berElement, new string(fmt, 1), value, tempValue.Length);
			}
			return Wldap32.ber_printf_bytearray(berElement, new string(fmt, 1), new HGlobalMemHandle((IntPtr)0), 0);
		}

		private static byte[] DecodingByteArrayHelper(BerSafeHandle berElement, char fmt, ref int error)
		{
			error = 0;
			IntPtr value = (IntPtr)0;
			berval berval2 = new berval();
			byte[] result = null;
			error = Wldap32.ber_scanf_ptr(berElement, new string(fmt, 1), ref value);
			try
			{
				if (error == 0)
				{
					if (value != (IntPtr)0)
					{
						Marshal.PtrToStructure(value, berval2);
						result = new byte[berval2.bv_len];
						Marshal.Copy(berval2.bv_val, result, 0, berval2.bv_len);
						return result;
					}
					return result;
				}
				return result;
			}
			finally
			{
				if (value != (IntPtr)0)
				{
					Wldap32.ber_bvfree(value);
				}
			}
		}

		private static int EncodingMultiByteArrayHelper(BerSafeHandle berElement, byte[][] tempValue, char fmt)
		{
			IntPtr intPtr = (IntPtr)0;
			IntPtr intPtr2 = (IntPtr)0;
			SafeBerval[] array = null;
			int num = 0;
			try
			{
				if (tempValue != null)
				{
					int num2 = 0;
					intPtr = Utility.AllocHGlobalIntPtrArray(tempValue.Length + 1);
					int cb = Marshal.SizeOf(typeof(SafeBerval));
					array = new SafeBerval[tempValue.Length];
					for (num2 = 0; num2 < tempValue.Length; num2++)
					{
						byte[] array2 = tempValue[num2];
						array[num2] = new SafeBerval();
						if (array2 == null)
						{
							array[num2].bv_len = 0;
							array[num2].bv_val = (IntPtr)0;
						}
						else
						{
							array[num2].bv_len = array2.Length;
							array[num2].bv_val = Marshal.AllocHGlobal(array2.Length);
							Marshal.Copy(array2, 0, array[num2].bv_val, array2.Length);
						}
						IntPtr intPtr3 = Marshal.AllocHGlobal(cb);
						Marshal.StructureToPtr(array[num2], intPtr3, fDeleteOld: false);
						intPtr2 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * num2);
						Marshal.WriteIntPtr(intPtr2, intPtr3);
					}
					intPtr2 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * num2);
					Marshal.WriteIntPtr(intPtr2, (IntPtr)0);
				}
				num = Wldap32.ber_printf_berarray(berElement, new string(fmt, 1), intPtr);
				GC.KeepAlive(array);
				return num;
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					for (int i = 0; i < tempValue.Length; i++)
					{
						IntPtr intPtr4 = Marshal.ReadIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * i);
						if (intPtr4 != (IntPtr)0)
						{
							Marshal.FreeHGlobal(intPtr4);
						}
					}
					Marshal.FreeHGlobal(intPtr);
				}
			}
		}

		private static byte[][] DecodingMultiByteArrayHelper(BerSafeHandle berElement, char fmt, ref int error)
		{
			error = 0;
			IntPtr value = (IntPtr)0;
			int num = 0;
			ArrayList arrayList = new ArrayList();
			IntPtr intPtr = (IntPtr)0;
			byte[][] result = null;
			try
			{
				error = Wldap32.ber_scanf_ptr(berElement, new string(fmt, 1), ref value);
				if (error == 0)
				{
					if (value != (IntPtr)0)
					{
						intPtr = Marshal.ReadIntPtr(value);
						while (intPtr != (IntPtr)0)
						{
							berval berval2 = new berval();
							Marshal.PtrToStructure(intPtr, berval2);
							byte[] array = new byte[berval2.bv_len];
							Marshal.Copy(berval2.bv_val, array, 0, berval2.bv_len);
							arrayList.Add(array);
							num++;
							intPtr = Marshal.ReadIntPtr(value, num * Marshal.SizeOf(typeof(IntPtr)));
						}
						result = new byte[arrayList.Count][];
						for (int i = 0; i < arrayList.Count; i++)
						{
							result[i] = (byte[])arrayList[i];
						}
						return result;
					}
					return result;
				}
				return result;
			}
			finally
			{
				if (value != (IntPtr)0)
				{
					Wldap32.ber_bvecfree(value);
				}
			}
		}
	}
	public enum DereferenceAlias
	{
		Never,
		InSearching,
		FindingBaseObject,
		Always
	}
	public class DirectoryAttribute : CollectionBase
	{
		private string attributeName = "";

		internal bool isSearchResult;

		private static UTF8Encoding utf8EncoderWithErrorDetection = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

		private static UTF8Encoding encoder = new UTF8Encoding();

		public string Name
		{
			get
			{
				return attributeName;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				attributeName = value;
			}
		}

		public object this[int index]
		{
			get
			{
				if (!isSearchResult)
				{
					return base.List[index];
				}
				if (base.List[index] is byte[] bytes)
				{
					try
					{
						return utf8EncoderWithErrorDetection.GetString(bytes);
					}
					catch (ArgumentException)
					{
						return base.List[index];
					}
				}
				return base.List[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (value is string || value is byte[] || value is Uri)
				{
					base.List[index] = value;
					return;
				}
				throw new ArgumentException(Res.GetString("ValidValueType"), "value");
			}
		}

		public DirectoryAttribute()
		{
			Utility.CheckOSVersion();
		}

		public DirectoryAttribute(string name, string value)
			: this(name, (object)value)
		{
		}

		public DirectoryAttribute(string name, byte[] value)
			: this(name, (object)value)
		{
		}

		public DirectoryAttribute(string name, Uri value)
			: this(name, (object)value)
		{
		}

		internal DirectoryAttribute(string name, object value)
			: this()
		{
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			Name = name;
			Add(value);
		}

		public DirectoryAttribute(string name, params object[] values)
			: this()
		{
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			if (values == null)
			{
				throw new ArgumentNullException("values");
			}
			Name = name;
			for (int i = 0; i < values.Length; i++)
			{
				Add(values[i]);
			}
		}

		internal DirectoryAttribute(XmlElement node)
		{
			string xpath = "@dsml:name";
			string xpath2 = "@name";
			XmlNamespaceManager dsmlNamespaceManager = NamespaceUtils.GetDsmlNamespaceManager();
			XmlAttribute xmlAttribute = (XmlAttribute)node.SelectSingleNode(xpath, dsmlNamespaceManager);
			if (xmlAttribute == null)
			{
				xmlAttribute = (XmlAttribute)node.SelectSingleNode(xpath2, dsmlNamespaceManager);
				if (xmlAttribute == null)
				{
					throw new DsmlInvalidDocumentException(Res.GetString("MissingSearchResultEntryAttributeName"));
				}
				attributeName = xmlAttribute.Value;
			}
			else
			{
				attributeName = xmlAttribute.Value;
			}
			XmlNodeList xmlNodeList = node.SelectNodes("dsml:value", dsmlNamespaceManager);
			if (xmlNodeList.Count == 0)
			{
				return;
			}
			foreach (XmlNode item in xmlNodeList)
			{
				XmlAttribute xmlAttribute2 = (XmlAttribute)item.SelectSingleNode("@xsi:type", dsmlNamespaceManager);
				if (xmlAttribute2 == null)
				{
					Add(item.InnerText);
				}
				else if (string.Compare(xmlAttribute2.Value, "xsd:string", StringComparison.OrdinalIgnoreCase) == 0)
				{
					Add(item.InnerText);
				}
				else if (string.Compare(xmlAttribute2.Value, "xsd:base64Binary", StringComparison.OrdinalIgnoreCase) == 0)
				{
					string innerText = item.InnerText;
					byte[] value;
					try
					{
						value = Convert.FromBase64String(innerText);
					}
					catch (FormatException)
					{
						throw new DsmlInvalidDocumentException(Res.GetString("BadBase64Value"));
					}
					Add(value);
				}
				else if (string.Compare(xmlAttribute2.Value, "xsd:anyURI", StringComparison.OrdinalIgnoreCase) == 0)
				{
					Uri value2 = new Uri(item.InnerText);
					Add(value2);
				}
			}
		}

		public object[] GetValues(Type valuesType)
		{
			if (valuesType == typeof(byte[]))
			{
				int count = base.List.Count;
				byte[][] array = new byte[count][];
				for (int i = 0; i < count; i++)
				{
					if (base.List[i] is string)
					{
						array[i] = encoder.GetBytes((string)base.List[i]);
						continue;
					}
					if (base.List[i] is byte[])
					{
						array[i] = (byte[])base.List[i];
						continue;
					}
					throw new NotSupportedException(Res.GetString("DirectoryAttributeConversion"));
				}
				return array;
			}
			if (valuesType == typeof(string))
			{
				int count2 = base.List.Count;
				string[] array2 = new string[count2];
				for (int j = 0; j < count2; j++)
				{
					if (base.List[j] is string)
					{
						array2[j] = (string)base.List[j];
						continue;
					}
					if (base.List[j] is byte[])
					{
						array2[j] = encoder.GetString((byte[])base.List[j]);
						continue;
					}
					throw new NotSupportedException(Res.GetString("DirectoryAttributeConversion"));
				}
				return array2;
			}
			throw new ArgumentException(Res.GetString("ValidDirectoryAttributeType"), "valuesType");
		}

		public int Add(byte[] value)
		{
			return Add((object)value);
		}

		public int Add(string value)
		{
			return Add((object)value);
		}

		public int Add(Uri value)
		{
			return Add((object)value);
		}

		internal int Add(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is string) && !(value is byte[]) && !(value is Uri))
			{
				throw new ArgumentException(Res.GetString("ValidValueType"), "value");
			}
			return base.List.Add(value);
		}

		public void AddRange(object[] values)
		{
			if (values == null)
			{
				throw new ArgumentNullException("values");
			}
			if (!(values is string[]) && !(values is byte[][]) && !(values is Uri[]))
			{
				throw new ArgumentException(Res.GetString("ValidValuesType"), "values");
			}
			for (int i = 0; i < values.Length; i++)
			{
				if (values[i] == null)
				{
					throw new ArgumentException(Res.GetString("NullValueArray"), "values");
				}
			}
			base.InnerList.AddRange(values);
		}

		public bool Contains(object value)
		{
			return base.List.Contains(value);
		}

		public void CopyTo(object[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(object value)
		{
			return base.List.IndexOf(value);
		}

		public void Insert(int index, byte[] value)
		{
			Insert(index, (object)value);
		}

		public void Insert(int index, string value)
		{
			Insert(index, (object)value);
		}

		public void Insert(int index, Uri value)
		{
			Insert(index, (object)value);
		}

		private void Insert(int index, object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			base.List.Insert(index, value);
		}

		public void Remove(object value)
		{
			base.List.Remove(value);
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is string) && !(value is byte[]) && !(value is Uri))
			{
				throw new ArgumentException(Res.GetString("ValidValueType"), "value");
			}
		}

		internal void ToXmlNodeCommon(XmlElement elemBase)
		{
			XmlDocument ownerDocument = elemBase.OwnerDocument;
			XmlAttribute xmlAttribute = ownerDocument.CreateAttribute("name", null);
			xmlAttribute.InnerText = Name;
			elemBase.Attributes.Append(xmlAttribute);
			if (base.Count == 0)
			{
				return;
			}
			foreach (object inner in base.InnerList)
			{
				XmlElement xmlElement = ownerDocument.CreateElement("value", "urn:oasis:names:tc:DSML:2:0:core");
				if (inner is byte[])
				{
					xmlElement.InnerText = Convert.ToBase64String((byte[])inner);
					XmlAttribute xmlAttribute2 = ownerDocument.CreateAttribute("xsi:type", "http://www.w3.org/2001/XMLSchema-instance");
					xmlAttribute2.InnerText = "xsd:base64Binary";
					xmlElement.Attributes.Append(xmlAttribute2);
				}
				else if (inner is Uri)
				{
					xmlElement.InnerText = inner.ToString();
					XmlAttribute xmlAttribute3 = ownerDocument.CreateAttribute("xsi:type", "http://www.w3.org/2001/XMLSchema-instance");
					xmlAttribute3.InnerText = "xsd:anyURI";
					xmlElement.Attributes.Append(xmlAttribute3);
				}
				else
				{
					xmlElement.InnerText = inner.ToString();
					if (xmlElement.InnerText.StartsWith(" ", StringComparison.Ordinal) || xmlElement.InnerText.EndsWith(" ", StringComparison.Ordinal))
					{
						XmlAttribute xmlAttribute4 = ownerDocument.CreateAttribute("xml:space");
						xmlAttribute4.InnerText = "preserve";
						xmlElement.Attributes.Append(xmlAttribute4);
					}
				}
				elemBase.AppendChild(xmlElement);
			}
		}

		internal XmlElement ToXmlNode(XmlDocument doc, string elementName)
		{
			XmlElement xmlElement = doc.CreateElement(elementName, "urn:oasis:names:tc:DSML:2:0:core");
			ToXmlNodeCommon(xmlElement);
			return xmlElement;
		}
	}
	public class DirectoryAttributeModification : DirectoryAttribute
	{
		private DirectoryAttributeOperation attributeOperation = DirectoryAttributeOperation.Replace;

		public DirectoryAttributeOperation Operation
		{
			get
			{
				return attributeOperation;
			}
			set
			{
				if (value < DirectoryAttributeOperation.Add || value > DirectoryAttributeOperation.Replace)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(DirectoryAttributeOperation));
				}
				attributeOperation = value;
			}
		}

		internal XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = doc.CreateElement("modification", "urn:oasis:names:tc:DSML:2:0:core");
			ToXmlNodeCommon(xmlElement);
			XmlAttribute xmlAttribute = doc.CreateAttribute("operation", null);
			switch (Operation)
			{
			case DirectoryAttributeOperation.Replace:
				xmlAttribute.InnerText = "replace";
				break;
			case DirectoryAttributeOperation.Add:
				xmlAttribute.InnerText = "add";
				break;
			case DirectoryAttributeOperation.Delete:
				xmlAttribute.InnerText = "delete";
				break;
			default:
				throw new InvalidEnumArgumentException("Operation", (int)Operation, typeof(DirectoryAttributeOperation));
			}
			xmlElement.Attributes.Append(xmlAttribute);
			return xmlElement;
		}
	}
	public class SearchResultAttributeCollection : DictionaryBase
	{
		public DirectoryAttribute this[string attributeName]
		{
			get
			{
				if (attributeName == null)
				{
					throw new ArgumentNullException("attributeName");
				}
				object key = attributeName.ToLower(CultureInfo.InvariantCulture);
				return (DirectoryAttribute)base.InnerHashtable[key];
			}
		}

		public ICollection AttributeNames => base.Dictionary.Keys;

		public ICollection Values => base.Dictionary.Values;

		internal SearchResultAttributeCollection()
		{
		}

		internal void Add(string name, DirectoryAttribute value)
		{
			base.Dictionary.Add(name.ToLower(CultureInfo.InvariantCulture), value);
		}

		public bool Contains(string attributeName)
		{
			if (attributeName == null)
			{
				throw new ArgumentNullException("attributeName");
			}
			object key = attributeName.ToLower(CultureInfo.InvariantCulture);
			return base.Dictionary.Contains(key);
		}

		public void CopyTo(DirectoryAttribute[] array, int index)
		{
			base.Dictionary.Values.CopyTo(array, index);
		}
	}
	public class DirectoryAttributeCollection : CollectionBase
	{
		public DirectoryAttribute this[int index]
		{
			get
			{
				return (DirectoryAttribute)base.List[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
				}
				base.List[index] = value;
			}
		}

		public DirectoryAttributeCollection()
		{
			Utility.CheckOSVersion();
		}

		public int Add(DirectoryAttribute attribute)
		{
			if (attribute == null)
			{
				throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
			}
			return base.List.Add(attribute);
		}

		public void AddRange(DirectoryAttribute[] attributes)
		{
			if (attributes == null)
			{
				throw new ArgumentNullException("attributes");
			}
			foreach (DirectoryAttribute directoryAttribute in attributes)
			{
				if (directoryAttribute == null)
				{
					throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
				}
			}
			base.InnerList.AddRange(attributes);
		}

		public void AddRange(DirectoryAttributeCollection attributeCollection)
		{
			if (attributeCollection == null)
			{
				throw new ArgumentNullException("attributeCollection");
			}
			int count = attributeCollection.Count;
			for (int i = 0; i < count; i++)
			{
				Add(attributeCollection[i]);
			}
		}

		public bool Contains(DirectoryAttribute value)
		{
			return base.List.Contains(value);
		}

		public void CopyTo(DirectoryAttribute[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(DirectoryAttribute value)
		{
			return base.List.IndexOf(value);
		}

		public void Insert(int index, DirectoryAttribute value)
		{
			if (value == null)
			{
				throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
			}
			base.List.Insert(index, value);
		}

		public void Remove(DirectoryAttribute value)
		{
			base.List.Remove(value);
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
			}
			if (!(value is DirectoryAttribute))
			{
				throw new ArgumentException(Res.GetString("InvalidValueType", "DirectoryAttribute"), "value");
			}
		}
	}
	public class DirectoryAttributeModificationCollection : CollectionBase
	{
		public DirectoryAttributeModification this[int index]
		{
			get
			{
				return (DirectoryAttributeModification)base.List[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
				}
				base.List[index] = value;
			}
		}

		public DirectoryAttributeModificationCollection()
		{
			Utility.CheckOSVersion();
		}

		public int Add(DirectoryAttributeModification attribute)
		{
			if (attribute == null)
			{
				throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
			}
			return base.List.Add(attribute);
		}

		public void AddRange(DirectoryAttributeModification[] attributes)
		{
			if (attributes == null)
			{
				throw new ArgumentNullException("attributes");
			}
			foreach (DirectoryAttributeModification directoryAttributeModification in attributes)
			{
				if (directoryAttributeModification == null)
				{
					throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
				}
			}
			base.InnerList.AddRange(attributes);
		}

		public void AddRange(DirectoryAttributeModificationCollection attributeCollection)
		{
			if (attributeCollection == null)
			{
				throw new ArgumentNullException("attributeCollection");
			}
			int count = attributeCollection.Count;
			for (int i = 0; i < count; i++)
			{
				Add(attributeCollection[i]);
			}
		}

		public bool Contains(DirectoryAttributeModification value)
		{
			return base.List.Contains(value);
		}

		public void CopyTo(DirectoryAttributeModification[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(DirectoryAttributeModification value)
		{
			return base.List.IndexOf(value);
		}

		public void Insert(int index, DirectoryAttributeModification value)
		{
			if (value == null)
			{
				throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
			}
			base.List.Insert(index, value);
		}

		public void Remove(DirectoryAttributeModification value)
		{
			base.List.Remove(value);
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentException(Res.GetString("NullDirectoryAttributeCollection"));
			}
			if (!(value is DirectoryAttributeModification))
			{
				throw new ArgumentException(Res.GetString("InvalidValueType", "DirectoryAttributeModification"), "value");
			}
		}
	}
	public enum DirectoryAttributeOperation
	{
		Add,
		Delete,
		Replace
	}
	public abstract class DirectoryConnection
	{
		internal NetworkCredential directoryCredential;

		internal X509CertificateCollection certificatesCollection;

		internal TimeSpan connectionTimeOut = new TimeSpan(0, 0, 30);

		internal DirectoryIdentifier directoryIdentifier;

		public virtual DirectoryIdentifier Directory => directoryIdentifier;

		public X509CertificateCollection ClientCertificates => certificatesCollection;

		public virtual TimeSpan Timeout
		{
			get
			{
				return connectionTimeOut;
			}
			set
			{
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				connectionTimeOut = value;
			}
		}

		public virtual NetworkCredential Credential
		{
			[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
			[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			set
			{
				directoryCredential = ((value != null) ? new NetworkCredential(value.UserName, value.Password, value.Domain) : null);
			}
		}

		protected DirectoryConnection()
		{
			Utility.CheckOSVersion();
			certificatesCollection = new X509CertificateCollection();
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract DirectoryResponse SendRequest(DirectoryRequest request);

		internal NetworkCredential GetCredential()
		{
			return directoryCredential;
		}
	}
	public enum ExtendedDNFlag
	{
		HexString,
		StandardString
	}
	[Flags]
	public enum SecurityMasks
	{
		None = 0,
		Owner = 1,
		Group = 2,
		Dacl = 4,
		Sacl = 8
	}
	[Flags]
	public enum DirectorySynchronizationOptions : long
	{
		None = 0L,
		ObjectSecurity = 1L,
		ParentsFirst = 0x800L,
		PublicDataOnly = 0x2000L,
		IncrementalValues = 0x80000000L
	}
	public enum SearchOption
	{
		DomainScope = 1,
		PhantomRoot
	}
	internal class UtilityHandle
	{
		private static ConnectionHandle handle = new ConnectionHandle();

		public static ConnectionHandle GetHandle()
		{
			return handle;
		}
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public class SortKey
	{
		private string name;

		private string rule;

		private bool order;

		public string AttributeName
		{
			get
			{
				return name;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				name = value;
			}
		}

		public string MatchingRule
		{
			get
			{
				return rule;
			}
			set
			{
				rule = value;
			}
		}

		public bool ReverseOrder
		{
			get
			{
				return order;
			}
			set
			{
				order = value;
			}
		}

		public SortKey()
		{
			Utility.CheckOSVersion();
		}

		public SortKey(string attributeName, string matchingRule, bool reverseOrder)
		{
			Utility.CheckOSVersion();
			AttributeName = attributeName;
			rule = matchingRule;
			order = reverseOrder;
		}
	}
	public class DirectoryControl
	{
		internal byte[] directoryControlValue;

		private string directoryControlType = "";

		private bool directoryControlCriticality = true;

		private bool directoryControlServerSide = true;

		public string Type => directoryControlType;

		public bool IsCritical
		{
			get
			{
				return directoryControlCriticality;
			}
			set
			{
				directoryControlCriticality = value;
			}
		}

		public bool ServerSide
		{
			get
			{
				return directoryControlServerSide;
			}
			set
			{
				directoryControlServerSide = value;
			}
		}

		public DirectoryControl(string type, byte[] value, bool isCritical, bool serverSide)
		{
			Utility.CheckOSVersion();
			directoryControlType = type;
			if (type == null)
			{
				throw new ArgumentNullException("type");
			}
			if (value != null)
			{
				directoryControlValue = new byte[value.Length];
				for (int i = 0; i < value.Length; i++)
				{
					directoryControlValue[i] = value[i];
				}
			}
			directoryControlCriticality = isCritical;
			directoryControlServerSide = serverSide;
		}

		internal DirectoryControl(XmlElement el)
		{
			XmlNamespaceManager dsmlNamespaceManager = NamespaceUtils.GetDsmlNamespaceManager();
			XmlAttribute xmlAttribute = (XmlAttribute)el.SelectSingleNode("@dsml:criticality", dsmlNamespaceManager);
			if (xmlAttribute == null)
			{
				xmlAttribute = (XmlAttribute)el.SelectSingleNode("@criticality", dsmlNamespaceManager);
			}
			if (xmlAttribute == null)
			{
				directoryControlCriticality = false;
			}
			else
			{
				switch (xmlAttribute.Value)
				{
				case "true":
				case "1":
					directoryControlCriticality = true;
					break;
				case "false":
				case "0":
					directoryControlCriticality = false;
					break;
				default:
					throw new DsmlInvalidDocumentException(Res.GetString("BadControl"));
				}
			}
			XmlAttribute xmlAttribute2 = (XmlAttribute)el.SelectSingleNode("@dsml:type", dsmlNamespaceManager);
			if (xmlAttribute2 == null)
			{
				xmlAttribute2 = (XmlAttribute)el.SelectSingleNode("@type", dsmlNamespaceManager);
			}
			if (xmlAttribute2 == null)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("BadControl"));
			}
			directoryControlType = xmlAttribute2.Value;
			XmlElement xmlElement = (XmlElement)el.SelectSingleNode("dsml:controlValue", dsmlNamespaceManager);
			if (xmlElement != null)
			{
				try
				{
					directoryControlValue = Convert.FromBase64String(xmlElement.InnerText);
				}
				catch (FormatException)
				{
					throw new DsmlInvalidDocumentException(Res.GetString("BadControl"));
				}
			}
		}

		public virtual byte[] GetValue()
		{
			if (directoryControlValue == null)
			{
				return new byte[0];
			}
			byte[] array = new byte[directoryControlValue.Length];
			for (int i = 0; i < directoryControlValue.Length; i++)
			{
				array[i] = directoryControlValue[i];
			}
			return array;
		}

		internal XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = doc.CreateElement("control", "urn:oasis:names:tc:DSML:2:0:core");
			XmlAttribute xmlAttribute = doc.CreateAttribute("type", null);
			xmlAttribute.InnerText = Type;
			xmlElement.Attributes.Append(xmlAttribute);
			XmlAttribute xmlAttribute2 = doc.CreateAttribute("criticality", null);
			xmlAttribute2.InnerText = (IsCritical ? "true" : "false");
			xmlElement.Attributes.Append(xmlAttribute2);
			byte[] value = GetValue();
			if (value.Length != 0)
			{
				XmlElement xmlElement2 = doc.CreateElement("controlValue", "urn:oasis:names:tc:DSML:2:0:core");
				XmlAttribute xmlAttribute3 = doc.CreateAttribute("xsi:type", "http://www.w3.org/2001/XMLSchema-instance");
				xmlAttribute3.InnerText = "xsd:base64Binary";
				xmlElement2.Attributes.Append(xmlAttribute3);
				string text2 = (xmlElement2.InnerText = Convert.ToBase64String(value));
				xmlElement.AppendChild(xmlElement2);
			}
			return xmlElement;
		}

		internal static void TransformControls(DirectoryControl[] controls)
		{
			for (int i = 0; i < controls.Length; i++)
			{
				byte[] value = controls[i].GetValue();
				if (controls[i].Type == "1.2.840.113556.1.4.319")
				{
					object[] array = BerConverter.Decode("{iO}", value);
					int count = (int)array[0];
					byte[] array2 = (byte[])array[1];
					if (array2 == null)
					{
						array2 = new byte[0];
					}
					PageResultResponseControl pageResultResponseControl = (PageResultResponseControl)(controls[i] = new PageResultResponseControl(count, array2, controls[i].IsCritical, controls[i].GetValue()));
				}
				else if (controls[i].Type == "1.2.840.113556.1.4.1504")
				{
					object[] array3 = null;
					array3 = ((!Utility.IsWin2kOS) ? BerConverter.Decode("{e}", value) : BerConverter.Decode("{i}", value));
					int result = (int)array3[0];
					AsqResponseControl asqResponseControl = (AsqResponseControl)(controls[i] = new AsqResponseControl(result, controls[i].IsCritical, controls[i].GetValue()));
				}
				else if (controls[i].Type == "1.2.840.113556.1.4.841")
				{
					object[] array4 = BerConverter.Decode("{iiO}", value);
					int num = (int)array4[0];
					int resultSize = (int)array4[1];
					byte[] cookie = (byte[])array4[2];
					DirSyncResponseControl dirSyncResponseControl = (DirSyncResponseControl)(controls[i] = new DirSyncResponseControl(cookie, (num != 0) ? true : false, resultSize, controls[i].IsCritical, controls[i].GetValue()));
				}
				else if (controls[i].Type == "1.2.840.113556.1.4.474")
				{
					object[] array5 = null;
					int num2 = 0;
					string attributeName = null;
					array5 = ((!Utility.IsWin2kOS) ? BerConverter.TryDecode("{ea}", value, out var decodeSucceeded) : BerConverter.TryDecode("{ia}", value, out decodeSucceeded));
					if (decodeSucceeded)
					{
						num2 = (int)array5[0];
						attributeName = (string)array5[1];
					}
					else
					{
						array5 = ((!Utility.IsWin2kOS) ? BerConverter.Decode("{e}", value) : BerConverter.Decode("{i}", value));
						num2 = (int)array5[0];
					}
					SortResponseControl sortResponseControl = (SortResponseControl)(controls[i] = new SortResponseControl((ResultCode)num2, attributeName, controls[i].IsCritical, controls[i].GetValue()));
				}
				else if (controls[i].Type == "2.16.840.1.113730.3.4.10")
				{
					byte[] context = null;
					object[] array6 = null;
					bool decodeSucceeded2 = false;
					array6 = ((!Utility.IsWin2kOS) ? BerConverter.TryDecode("{iieO}", value, out decodeSucceeded2) : BerConverter.TryDecode("{iiiO}", value, out decodeSucceeded2));
					int targetPosition;
					int count2;
					int result2;
					if (decodeSucceeded2)
					{
						targetPosition = (int)array6[0];
						count2 = (int)array6[1];
						result2 = (int)array6[2];
						context = (byte[])array6[3];
					}
					else
					{
						array6 = ((!Utility.IsWin2kOS) ? BerConverter.Decode("{iie}", value) : BerConverter.Decode("{iii}", value));
						targetPosition = (int)array6[0];
						count2 = (int)array6[1];
						result2 = (int)array6[2];
					}
					VlvResponseControl vlvResponseControl = (VlvResponseControl)(controls[i] = new VlvResponseControl(targetPosition, count2, context, (ResultCode)result2, controls[i].IsCritical, controls[i].GetValue()));
				}
			}
		}
	}
	public class AsqRequestControl : DirectoryControl
	{
		private string name;

		public string AttributeName
		{
			get
			{
				return name;
			}
			set
			{
				name = value;
			}
		}

		public AsqRequestControl()
			: base("1.2.840.113556.1.4.1504", null, isCritical: true, serverSide: true)
		{
		}

		public AsqRequestControl(string attributeName)
			: this()
		{
			name = attributeName;
		}

		public override byte[] GetValue()
		{
			directoryControlValue = BerConverter.Encode("{s}", name);
			return base.GetValue();
		}
	}
	public class AsqResponseControl : DirectoryControl
	{
		private ResultCode result;

		public ResultCode Result => result;

		internal AsqResponseControl(int result, bool criticality, byte[] controlValue)
			: base("1.2.840.113556.1.4.1504", controlValue, criticality, serverSide: true)
		{
			this.result = (ResultCode)result;
		}
	}
	public class CrossDomainMoveControl : DirectoryControl
	{
		private string dcName;

		public string TargetDomainController
		{
			get
			{
				return dcName;
			}
			set
			{
				dcName = value;
			}
		}

		public CrossDomainMoveControl()
			: base("1.2.840.113556.1.4.521", null, isCritical: true, serverSide: true)
		{
		}

		public CrossDomainMoveControl(string targetDomainController)
			: this()
		{
			dcName = targetDomainController;
		}

		public override byte[] GetValue()
		{
			if (dcName != null)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding();
				byte[] bytes = uTF8Encoding.GetBytes(dcName);
				directoryControlValue = new byte[bytes.Length + 2];
				for (int i = 0; i < bytes.Length; i++)
				{
					directoryControlValue[i] = bytes[i];
				}
			}
			return base.GetValue();
		}
	}
	public class DomainScopeControl : DirectoryControl
	{
		public DomainScopeControl()
			: base("1.2.840.113556.1.4.1339", null, isCritical: true, serverSide: true)
		{
		}
	}
	public class ExtendedDNControl : DirectoryControl
	{
		private ExtendedDNFlag format;

		public ExtendedDNFlag Flag
		{
			get
			{
				return format;
			}
			set
			{
				if (value < ExtendedDNFlag.HexString || value > ExtendedDNFlag.StandardString)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ExtendedDNFlag));
				}
				format = value;
			}
		}

		public ExtendedDNControl()
			: base("1.2.840.113556.1.4.529", null, isCritical: true, serverSide: true)
		{
		}

		public ExtendedDNControl(ExtendedDNFlag flag)
			: this()
		{
			Flag = flag;
		}

		public override byte[] GetValue()
		{
			directoryControlValue = BerConverter.Encode("{i}", (int)format);
			return base.GetValue();
		}
	}
	public class LazyCommitControl : DirectoryControl
	{
		public LazyCommitControl()
			: base("1.2.840.113556.1.4.619", null, isCritical: true, serverSide: true)
		{
		}
	}
	public class DirectoryNotificationControl : DirectoryControl
	{
		public DirectoryNotificationControl()
			: base("1.2.840.113556.1.4.528", null, isCritical: true, serverSide: true)
		{
		}
	}
	public class PermissiveModifyControl : DirectoryControl
	{
		public PermissiveModifyControl()
			: base("1.2.840.113556.1.4.1413", null, isCritical: true, serverSide: true)
		{
		}
	}
	public class SecurityDescriptorFlagControl : DirectoryControl
	{
		private SecurityMasks flag;

		public SecurityMasks SecurityMasks
		{
			get
			{
				return flag;
			}
			set
			{
				flag = value;
			}
		}

		public SecurityDescriptorFlagControl()
			: base("1.2.840.113556.1.4.801", null, isCritical: true, serverSide: true)
		{
		}

		public SecurityDescriptorFlagControl(SecurityMasks masks)
			: this()
		{
			SecurityMasks = masks;
		}

		public override byte[] GetValue()
		{
			directoryControlValue = BerConverter.Encode("{i}", (int)flag);
			return base.GetValue();
		}
	}
	public class SearchOptionsControl : DirectoryControl
	{
		private SearchOption flag = SearchOption.DomainScope;

		public SearchOption SearchOption
		{
			get
			{
				return flag;
			}
			set
			{
				if (value < SearchOption.DomainScope || value > SearchOption.PhantomRoot)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(SearchOption));
				}
				flag = value;
			}
		}

		public SearchOptionsControl()
			: base("1.2.840.113556.1.4.1340", null, isCritical: true, serverSide: true)
		{
		}

		public SearchOptionsControl(SearchOption flags)
			: this()
		{
			SearchOption = flags;
		}

		public override byte[] GetValue()
		{
			directoryControlValue = BerConverter.Encode("{i}", (int)flag);
			return base.GetValue();
		}
	}
	public class ShowDeletedControl : DirectoryControl
	{
		public ShowDeletedControl()
			: base("1.2.840.113556.1.4.417", null, isCritical: true, serverSide: true)
		{
		}
	}
	public class TreeDeleteControl : DirectoryControl
	{
		public TreeDeleteControl()
			: base("1.2.840.113556.1.4.805", null, isCritical: true, serverSide: true)
		{
		}
	}
	public class VerifyNameControl : DirectoryControl
	{
		private string name;

		private int flag;

		public string ServerName
		{
			get
			{
				return name;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				name = value;
			}
		}

		public int Flag
		{
			get
			{
				return flag;
			}
			set
			{
				flag = value;
			}
		}

		public VerifyNameControl()
			: base("1.2.840.113556.1.4.1338", null, isCritical: true, serverSide: true)
		{
		}

		public VerifyNameControl(string serverName)
			: this()
		{
			if (serverName == null)
			{
				throw new ArgumentNullException("serverName");
			}
			name = serverName;
		}

		public VerifyNameControl(string serverName, int flag)
			: this(serverName)
		{
			this.flag = flag;
		}

		public override byte[] GetValue()
		{
			byte[] array = null;
			if (ServerName != null)
			{
				UnicodeEncoding unicodeEncoding = new UnicodeEncoding();
				array = unicodeEncoding.GetBytes(ServerName);
			}
			directoryControlValue = BerConverter.Encode("{io}", flag, array);
			return base.GetValue();
		}
	}
	public class DirSyncRequestControl : DirectoryControl
	{
		private byte[] dirsyncCookie;

		private DirectorySynchronizationOptions flag;

		private int count = 1048576;

		public byte[] Cookie
		{
			get
			{
				if (dirsyncCookie == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[dirsyncCookie.Length];
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = dirsyncCookie[i];
				}
				return array;
			}
			set
			{
				dirsyncCookie = value;
			}
		}

		public DirectorySynchronizationOptions Option
		{
			get
			{
				return flag;
			}
			set
			{
				flag = value;
			}
		}

		public int AttributeCount
		{
			get
			{
				return count;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				count = value;
			}
		}

		public DirSyncRequestControl()
			: base("1.2.840.113556.1.4.841", null, isCritical: true, serverSide: true)
		{
		}

		public DirSyncRequestControl(byte[] cookie)
			: this()
		{
			dirsyncCookie = cookie;
		}

		public DirSyncRequestControl(byte[] cookie, DirectorySynchronizationOptions option)
			: this(cookie)
		{
			Option = option;
		}

		public DirSyncRequestControl(byte[] cookie, DirectorySynchronizationOptions option, int attributeCount)
			: this(cookie, option)
		{
			AttributeCount = attributeCount;
		}

		public override byte[] GetValue()
		{
			object[] value = new object[3]
			{
				(int)flag,
				count,
				dirsyncCookie
			};
			directoryControlValue = BerConverter.Encode("{iio}", value);
			return base.GetValue();
		}
	}
	public class DirSyncResponseControl : DirectoryControl
	{
		private byte[] dirsyncCookie;

		private bool moreResult;

		private int size;

		public byte[] Cookie
		{
			get
			{
				if (dirsyncCookie == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[dirsyncCookie.Length];
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = dirsyncCookie[i];
				}
				return array;
			}
		}

		public bool MoreData => moreResult;

		public int ResultSize => size;

		internal DirSyncResponseControl(byte[] cookie, bool moreData, int resultSize, bool criticality, byte[] controlValue)
			: base("1.2.840.113556.1.4.841", controlValue, criticality, serverSide: true)
		{
			dirsyncCookie = cookie;
			moreResult = moreData;
			size = resultSize;
		}
	}
	public class PageResultRequestControl : DirectoryControl
	{
		private int size = 512;

		private byte[] pageCookie;

		public int PageSize
		{
			get
			{
				return size;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				size = value;
			}
		}

		public byte[] Cookie
		{
			get
			{
				if (pageCookie == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[pageCookie.Length];
				for (int i = 0; i < pageCookie.Length; i++)
				{
					array[i] = pageCookie[i];
				}
				return array;
			}
			set
			{
				pageCookie = value;
			}
		}

		public PageResultRequestControl()
			: base("1.2.840.113556.1.4.319", null, isCritical: true, serverSide: true)
		{
		}

		public PageResultRequestControl(int pageSize)
			: this()
		{
			PageSize = pageSize;
		}

		public PageResultRequestControl(byte[] cookie)
			: this()
		{
			pageCookie = cookie;
		}

		public override byte[] GetValue()
		{
			object[] value = new object[2] { size, pageCookie };
			directoryControlValue = BerConverter.Encode("{io}", value);
			return base.GetValue();
		}
	}
	public class PageResultResponseControl : DirectoryControl
	{
		private byte[] pageCookie;

		private int count;

		public byte[] Cookie
		{
			get
			{
				if (pageCookie == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[pageCookie.Length];
				for (int i = 0; i < pageCookie.Length; i++)
				{
					array[i] = pageCookie[i];
				}
				return array;
			}
		}

		public int TotalCount => count;

		internal PageResultResponseControl(int count, byte[] cookie, bool criticality, byte[] controlValue)
			: base("1.2.840.113556.1.4.319", controlValue, criticality, serverSide: true)
		{
			this.count = count;
			pageCookie = cookie;
		}
	}
	public class SortRequestControl : DirectoryControl
	{
		private SortKey[] keys = new SortKey[0];

		public SortKey[] SortKeys
		{
			get
			{
				if (keys == null)
				{
					return new SortKey[0];
				}
				SortKey[] array = new SortKey[keys.Length];
				for (int i = 0; i < keys.Length; i++)
				{
					array[i] = new SortKey(keys[i].AttributeName, keys[i].MatchingRule, keys[i].ReverseOrder);
				}
				return array;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				for (int i = 0; i < value.Length; i++)
				{
					if (value[i] == null)
					{
						throw new ArgumentException(Res.GetString("NullValueArray"), "value");
					}
				}
				keys = new SortKey[value.Length];
				for (int j = 0; j < value.Length; j++)
				{
					keys[j] = new SortKey(value[j].AttributeName, value[j].MatchingRule, value[j].ReverseOrder);
				}
			}
		}

		public SortRequestControl(params SortKey[] sortKeys)
			: base("1.2.840.113556.1.4.473", null, isCritical: true, serverSide: true)
		{
			if (sortKeys == null)
			{
				throw new ArgumentNullException("sortKeys");
			}
			for (int i = 0; i < sortKeys.Length; i++)
			{
				if (sortKeys[i] == null)
				{
					throw new ArgumentException(Res.GetString("NullValueArray"), "sortKeys");
				}
			}
			keys = new SortKey[sortKeys.Length];
			for (int j = 0; j < sortKeys.Length; j++)
			{
				keys[j] = new SortKey(sortKeys[j].AttributeName, sortKeys[j].MatchingRule, sortKeys[j].ReverseOrder);
			}
		}

		public SortRequestControl(string attributeName, bool reverseOrder)
			: this(attributeName, null, reverseOrder)
		{
		}

		public SortRequestControl(string attributeName, string matchingRule, bool reverseOrder)
			: base("1.2.840.113556.1.4.473", null, isCritical: true, serverSide: true)
		{
			SortKey sortKey = new SortKey(attributeName, matchingRule, reverseOrder);
			keys = new SortKey[1];
			keys[0] = sortKey;
		}

		public override byte[] GetValue()
		{
			IntPtr control = (IntPtr)0;
			int cb = Marshal.SizeOf(typeof(SortKey));
			int num = keys.Length;
			IntPtr intPtr = Utility.AllocHGlobalIntPtrArray(num + 1);
			try
			{
				IntPtr intPtr2 = (IntPtr)0;
				IntPtr intPtr3 = (IntPtr)0;
				int num2 = 0;
				for (num2 = 0; num2 < num; num2++)
				{
					intPtr3 = Marshal.AllocHGlobal(cb);
					Marshal.StructureToPtr(keys[num2], intPtr3, fDeleteOld: false);
					intPtr2 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * num2);
					Marshal.WriteIntPtr(intPtr2, intPtr3);
				}
				intPtr2 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * num2);
				Marshal.WriteIntPtr(intPtr2, (IntPtr)0);
				bool isCritical = base.IsCritical;
				int num3 = Wldap32.ldap_create_sort_control(UtilityHandle.GetHandle(), intPtr, (byte)(isCritical ? 1 : 0), ref control);
				if (num3 != 0)
				{
					if (Utility.IsLdapError((LdapError)num3))
					{
						string message = LdapErrorMappings.MapResultCode(num3);
						throw new LdapException(num3, message);
					}
					throw new LdapException(num3);
				}
				LdapControl ldapControl = new LdapControl();
				Marshal.PtrToStructure(control, ldapControl);
				berval ldctl_value = ldapControl.ldctl_value;
				directoryControlValue = null;
				if (ldctl_value != null)
				{
					directoryControlValue = new byte[ldctl_value.bv_len];
					Marshal.Copy(ldctl_value.bv_val, directoryControlValue, 0, ldctl_value.bv_len);
				}
			}
			finally
			{
				if (control != (IntPtr)0)
				{
					Wldap32.ldap_control_free(control);
				}
				if (intPtr != (IntPtr)0)
				{
					for (int i = 0; i < num; i++)
					{
						IntPtr intPtr4 = Marshal.ReadIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * i);
						if (intPtr4 != (IntPtr)0)
						{
							IntPtr intPtr5 = Marshal.ReadIntPtr(intPtr4);
							if (intPtr5 != (IntPtr)0)
							{
								Marshal.FreeHGlobal(intPtr5);
							}
							intPtr5 = Marshal.ReadIntPtr(intPtr4, Marshal.SizeOf(typeof(IntPtr)));
							if (intPtr5 != (IntPtr)0)
							{
								Marshal.FreeHGlobal(intPtr5);
							}
							Marshal.FreeHGlobal(intPtr4);
						}
					}
					Marshal.FreeHGlobal(intPtr);
				}
			}
			return base.GetValue();
		}
	}
	public class SortResponseControl : DirectoryControl
	{
		private ResultCode result;

		private string name;

		public ResultCode Result => result;

		public string AttributeName => name;

		internal SortResponseControl(ResultCode result, string attributeName, bool critical, byte[] value)
			: base("1.2.840.113556.1.4.474", value, critical, serverSide: true)
		{
			this.result = result;
			name = attributeName;
		}
	}
	public class VlvRequestControl : DirectoryControl
	{
		private int before;

		private int after;

		private int offset;

		private int estimateCount;

		private byte[] target;

		private byte[] context;

		public int BeforeCount
		{
			get
			{
				return before;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				before = value;
			}
		}

		public int AfterCount
		{
			get
			{
				return after;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				after = value;
			}
		}

		public int Offset
		{
			get
			{
				return offset;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				offset = value;
			}
		}

		public int EstimateCount
		{
			get
			{
				return estimateCount;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				estimateCount = value;
			}
		}

		public byte[] Target
		{
			get
			{
				if (target == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[target.Length];
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = target[i];
				}
				return array;
			}
			set
			{
				target = value;
			}
		}

		public byte[] ContextId
		{
			get
			{
				if (context == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[context.Length];
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = context[i];
				}
				return array;
			}
			set
			{
				context = value;
			}
		}

		public VlvRequestControl()
			: base("2.16.840.1.113730.3.4.9", null, isCritical: true, serverSide: true)
		{
		}

		public VlvRequestControl(int beforeCount, int afterCount, int offset)
			: this()
		{
			BeforeCount = beforeCount;
			AfterCount = afterCount;
			Offset = offset;
		}

		public VlvRequestControl(int beforeCount, int afterCount, string target)
			: this()
		{
			BeforeCount = beforeCount;
			AfterCount = afterCount;
			if (target != null)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding();
				byte[] array = (this.target = uTF8Encoding.GetBytes(target));
			}
		}

		public VlvRequestControl(int beforeCount, int afterCount, byte[] target)
			: this()
		{
			BeforeCount = beforeCount;
			AfterCount = afterCount;
			Target = target;
		}

		public override byte[] GetValue()
		{
			StringBuilder stringBuilder = new StringBuilder(10);
			ArrayList arrayList = new ArrayList();
			stringBuilder.Append("{ii");
			arrayList.Add(BeforeCount);
			arrayList.Add(AfterCount);
			if (Target.Length != 0)
			{
				stringBuilder.Append("t");
				arrayList.Add(129);
				stringBuilder.Append("o");
				arrayList.Add(Target);
			}
			else
			{
				stringBuilder.Append("t{");
				arrayList.Add(160);
				stringBuilder.Append("ii");
				arrayList.Add(Offset);
				arrayList.Add(EstimateCount);
				stringBuilder.Append("}");
			}
			if (ContextId.Length != 0)
			{
				stringBuilder.Append("o");
				arrayList.Add(ContextId);
			}
			stringBuilder.Append("}");
			object[] array = new object[arrayList.Count];
			for (int i = 0; i < arrayList.Count; i++)
			{
				array[i] = arrayList[i];
			}
			directoryControlValue = BerConverter.Encode(stringBuilder.ToString(), array);
			return base.GetValue();
		}
	}
	public class VlvResponseControl : DirectoryControl
	{
		private int position;

		private int count;

		private byte[] context;

		private ResultCode result;

		public int TargetPosition => position;

		public int ContentCount => count;

		public byte[] ContextId
		{
			get
			{
				if (context == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[context.Length];
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = context[i];
				}
				return array;
			}
		}

		public ResultCode Result => result;

		internal VlvResponseControl(int targetPosition, int count, byte[] context, ResultCode result, bool criticality, byte[] value)
			: base("2.16.840.1.113730.3.4.10", value, criticality, serverSide: true)
		{
			position = targetPosition;
			this.count = count;
			this.context = context;
			this.result = result;
		}
	}
	public class QuotaControl : DirectoryControl
	{
		private byte[] sid;

		public SecurityIdentifier QuerySid
		{
			get
			{
				if (sid == null)
				{
					return null;
				}
				return new SecurityIdentifier(sid, 0);
			}
			set
			{
				if (value == null)
				{
					sid = null;
					return;
				}
				sid = new byte[value.BinaryLength];
				value.GetBinaryForm(sid, 0);
			}
		}

		public QuotaControl()
			: base("1.2.840.113556.1.4.1852", null, isCritical: true, serverSide: true)
		{
		}

		public QuotaControl(SecurityIdentifier querySid)
			: this()
		{
			QuerySid = querySid;
		}

		public override byte[] GetValue()
		{
			directoryControlValue = BerConverter.Encode("{o}", sid);
			return base.GetValue();
		}
	}
	public class DirectoryControlCollection : CollectionBase
	{
		public DirectoryControl this[int index]
		{
			get
			{
				return (DirectoryControl)base.List[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				base.List[index] = value;
			}
		}

		public DirectoryControlCollection()
		{
			Utility.CheckOSVersion();
		}

		public int Add(DirectoryControl control)
		{
			if (control == null)
			{
				throw new ArgumentNullException("control");
			}
			return base.List.Add(control);
		}

		public void AddRange(DirectoryControl[] controls)
		{
			if (controls == null)
			{
				throw new ArgumentNullException("controls");
			}
			foreach (DirectoryControl directoryControl in controls)
			{
				if (directoryControl == null)
				{
					throw new ArgumentException(Res.GetString("ContainNullControl"), "controls");
				}
			}
			base.InnerList.AddRange(controls);
		}

		public void AddRange(DirectoryControlCollection controlCollection)
		{
			if (controlCollection == null)
			{
				throw new ArgumentNullException("controlCollection");
			}
			int count = controlCollection.Count;
			for (int i = 0; i < count; i++)
			{
				Add(controlCollection[i]);
			}
		}

		public bool Contains(DirectoryControl value)
		{
			return base.List.Contains(value);
		}

		public void CopyTo(DirectoryControl[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(DirectoryControl value)
		{
			return base.List.IndexOf(value);
		}

		public void Insert(int index, DirectoryControl value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			base.List.Insert(index, value);
		}

		public void Remove(DirectoryControl value)
		{
			base.List.Remove(value);
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is DirectoryControl))
			{
				throw new ArgumentException(Res.GetString("InvalidValueType", "DirectoryControl"), "value");
			}
		}
	}
	[Serializable]
	public class DirectoryException : Exception
	{
		protected DirectoryException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		public DirectoryException(string message, Exception inner)
			: base(message, inner)
		{
			Utility.CheckOSVersion();
		}

		public DirectoryException(string message)
			: base(message)
		{
			Utility.CheckOSVersion();
		}

		public DirectoryException()
		{
			Utility.CheckOSVersion();
		}
	}
	[Serializable]
	public class DirectoryOperationException : DirectoryException, ISerializable
	{
		internal DirectoryResponse response;

		public DirectoryResponse Response => response;

		protected DirectoryOperationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		public DirectoryOperationException()
		{
		}

		public DirectoryOperationException(string message)
			: base(message)
		{
		}

		public DirectoryOperationException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public DirectoryOperationException(DirectoryResponse response)
			: base(Res.GetString("DefaultOperationsError"))
		{
			this.response = response;
		}

		public DirectoryOperationException(DirectoryResponse response, string message)
			: base(message)
		{
			this.response = response;
		}

		public DirectoryOperationException(DirectoryResponse response, string message, Exception inner)
			: base(message, inner)
		{
			this.response = response;
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	[Serializable]
	public class BerConversionException : DirectoryException
	{
		protected BerConversionException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		public BerConversionException()
			: base(Res.GetString("BerConversionError"))
		{
		}

		public BerConversionException(string message)
			: base(message)
		{
		}

		public BerConversionException(string message, Exception inner)
			: base(message, inner)
		{
		}
	}
	public abstract class DirectoryIdentifier
	{
		protected DirectoryIdentifier()
		{
			Utility.CheckOSVersion();
		}
	}
	public abstract class DirectoryOperation
	{
		internal string directoryRequestID;
	}
	public abstract class DirectoryRequest : DirectoryOperation
	{
		internal DirectoryControlCollection directoryControlCollection;

		public string RequestId
		{
			get
			{
				return directoryRequestID;
			}
			set
			{
				directoryRequestID = value;
			}
		}

		public DirectoryControlCollection Controls => directoryControlCollection;

		internal DirectoryRequest()
		{
			Utility.CheckOSVersion();
			directoryControlCollection = new DirectoryControlCollection();
		}

		internal XmlElement ToXmlNodeHelper(XmlDocument doc)
		{
			return ToXmlNode(doc);
		}

		protected abstract XmlElement ToXmlNode(XmlDocument doc);

		internal XmlElement CreateRequestElement(XmlDocument doc, string requestName, bool includeDistinguishedName, string distinguishedName)
		{
			XmlElement xmlElement = doc.CreateElement(requestName, "urn:oasis:names:tc:DSML:2:0:core");
			if (includeDistinguishedName)
			{
				XmlAttribute xmlAttribute = doc.CreateAttribute("dn", null);
				xmlAttribute.InnerText = distinguishedName;
				xmlElement.Attributes.Append(xmlAttribute);
			}
			if (directoryRequestID != null)
			{
				XmlAttribute xmlAttribute2 = doc.CreateAttribute("requestID", null);
				xmlAttribute2.InnerText = directoryRequestID;
				xmlElement.Attributes.Append(xmlAttribute2);
			}
			if (directoryControlCollection != null)
			{
				foreach (DirectoryControl item in directoryControlCollection)
				{
					XmlElement newChild = item.ToXmlNode(doc);
					xmlElement.AppendChild(newChild);
				}
				return xmlElement;
			}
			return xmlElement;
		}
	}
	public class DeleteRequest : DirectoryRequest
	{
		private string dn;

		public string DistinguishedName
		{
			get
			{
				return dn;
			}
			set
			{
				dn = value;
			}
		}

		public DeleteRequest()
		{
		}

		public DeleteRequest(string distinguishedName)
		{
			dn = distinguishedName;
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			return CreateRequestElement(doc, "delRequest", includeDistinguishedName: true, dn);
		}
	}
	public class AddRequest : DirectoryRequest
	{
		private string dn;

		private DirectoryAttributeCollection attributeList;

		public string DistinguishedName
		{
			get
			{
				return dn;
			}
			set
			{
				dn = value;
			}
		}

		public DirectoryAttributeCollection Attributes => attributeList;

		public AddRequest()
		{
			attributeList = new DirectoryAttributeCollection();
		}

		public AddRequest(string distinguishedName, params DirectoryAttribute[] attributes)
			: this()
		{
			dn = distinguishedName;
			if (attributes != null)
			{
				for (int i = 0; i < attributes.Length; i++)
				{
					attributeList.Add(attributes[i]);
				}
			}
		}

		public AddRequest(string distinguishedName, string objectClass)
			: this()
		{
			if (objectClass == null)
			{
				throw new ArgumentNullException("objectClass");
			}
			dn = distinguishedName;
			DirectoryAttribute directoryAttribute = new DirectoryAttribute();
			directoryAttribute.Name = "objectClass";
			directoryAttribute.Add(objectClass);
			attributeList.Add(directoryAttribute);
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = CreateRequestElement(doc, "addRequest", includeDistinguishedName: true, dn);
			if (attributeList != null)
			{
				foreach (DirectoryAttribute attribute in attributeList)
				{
					XmlElement newChild = attribute.ToXmlNode(doc, "attr");
					xmlElement.AppendChild(newChild);
				}
				return xmlElement;
			}
			return xmlElement;
		}
	}
	public class ModifyRequest : DirectoryRequest
	{
		private string dn;

		private DirectoryAttributeModificationCollection attributeModificationList;

		public string DistinguishedName
		{
			get
			{
				return dn;
			}
			set
			{
				dn = value;
			}
		}

		public DirectoryAttributeModificationCollection Modifications => attributeModificationList;

		public ModifyRequest()
		{
			attributeModificationList = new DirectoryAttributeModificationCollection();
		}

		public ModifyRequest(string distinguishedName, params DirectoryAttributeModification[] modifications)
			: this()
		{
			dn = distinguishedName;
			attributeModificationList.AddRange(modifications);
		}

		public ModifyRequest(string distinguishedName, DirectoryAttributeOperation operation, string attributeName, params object[] values)
			: this()
		{
			dn = distinguishedName;
			if (attributeName == null)
			{
				throw new ArgumentNullException("attributeName");
			}
			DirectoryAttributeModification directoryAttributeModification = new DirectoryAttributeModification
			{
				Operation = operation,
				Name = attributeName
			};
			if (values != null)
			{
				for (int i = 0; i < values.Length; i++)
				{
					directoryAttributeModification.Add(values[i]);
				}
			}
			attributeModificationList.Add(directoryAttributeModification);
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = CreateRequestElement(doc, "modifyRequest", includeDistinguishedName: true, dn);
			if (attributeModificationList != null)
			{
				foreach (DirectoryAttributeModification attributeModification in attributeModificationList)
				{
					XmlElement newChild = attributeModification.ToXmlNode(doc);
					xmlElement.AppendChild(newChild);
				}
				return xmlElement;
			}
			return xmlElement;
		}
	}
	public class CompareRequest : DirectoryRequest
	{
		private string dn;

		private DirectoryAttribute attribute = new DirectoryAttribute();

		public string DistinguishedName
		{
			get
			{
				return dn;
			}
			set
			{
				dn = value;
			}
		}

		public DirectoryAttribute Assertion => attribute;

		public CompareRequest()
		{
		}

		public CompareRequest(string distinguishedName, string attributeName, string value)
		{
			CompareRequestHelper(distinguishedName, attributeName, value);
		}

		public CompareRequest(string distinguishedName, string attributeName, byte[] value)
		{
			CompareRequestHelper(distinguishedName, attributeName, value);
		}

		public CompareRequest(string distinguishedName, string attributeName, Uri value)
		{
			CompareRequestHelper(distinguishedName, attributeName, value);
		}

		public CompareRequest(string distinguishedName, DirectoryAttribute assertion)
		{
			if (assertion == null)
			{
				throw new ArgumentNullException("assertion");
			}
			if (assertion.Count != 1)
			{
				throw new ArgumentException(Res.GetString("WrongNumValuesCompare"));
			}
			CompareRequestHelper(distinguishedName, assertion.Name, assertion[0]);
		}

		private void CompareRequestHelper(string distinguishedName, string attributeName, object value)
		{
			if (attributeName == null)
			{
				throw new ArgumentNullException("attributeName");
			}
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			dn = distinguishedName;
			attribute.Name = attributeName;
			attribute.Add(value);
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = CreateRequestElement(doc, "compareRequest", includeDistinguishedName: true, dn);
			if (attribute.Count != 1)
			{
				throw new ArgumentException(Res.GetString("WrongNumValuesCompare"));
			}
			XmlElement newChild = attribute.ToXmlNode(doc, "assertion");
			xmlElement.AppendChild(newChild);
			return xmlElement;
		}
	}
	public class ModifyDNRequest : DirectoryRequest
	{
		private string dn;

		private string newSuperior;

		private string newRDN;

		private bool deleteOldRDN = true;

		public string DistinguishedName
		{
			get
			{
				return dn;
			}
			set
			{
				dn = value;
			}
		}

		public string NewParentDistinguishedName
		{
			get
			{
				return newSuperior;
			}
			set
			{
				newSuperior = value;
			}
		}

		public string NewName
		{
			get
			{
				return newRDN;
			}
			set
			{
				newRDN = value;
			}
		}

		public bool DeleteOldRdn
		{
			get
			{
				return deleteOldRDN;
			}
			set
			{
				deleteOldRDN = value;
			}
		}

		public ModifyDNRequest()
		{
		}

		public ModifyDNRequest(string distinguishedName, string newParentDistinguishedName, string newName)
		{
			dn = distinguishedName;
			newSuperior = newParentDistinguishedName;
			newRDN = newName;
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = CreateRequestElement(doc, "modDNRequest", includeDistinguishedName: true, dn);
			XmlAttribute xmlAttribute = doc.CreateAttribute("newrdn", null);
			xmlAttribute.InnerText = newRDN;
			xmlElement.Attributes.Append(xmlAttribute);
			XmlAttribute xmlAttribute2 = doc.CreateAttribute("deleteoldrdn", null);
			xmlAttribute2.InnerText = (deleteOldRDN ? "true" : "false");
			xmlElement.Attributes.Append(xmlAttribute2);
			if (newSuperior != null)
			{
				XmlAttribute xmlAttribute3 = doc.CreateAttribute("newSuperior", null);
				xmlAttribute3.InnerText = newSuperior;
				xmlElement.Attributes.Append(xmlAttribute3);
			}
			return xmlElement;
		}
	}
	public class ExtendedRequest : DirectoryRequest
	{
		private string requestName;

		private byte[] requestValue;

		public string RequestName
		{
			get
			{
				return requestName;
			}
			set
			{
				requestName = value;
			}
		}

		public byte[] RequestValue
		{
			get
			{
				if (requestValue == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[requestValue.Length];
				for (int i = 0; i < requestValue.Length; i++)
				{
					array[i] = requestValue[i];
				}
				return array;
			}
			set
			{
				requestValue = value;
			}
		}

		public ExtendedRequest()
		{
		}

		public ExtendedRequest(string requestName)
		{
			this.requestName = requestName;
		}

		public ExtendedRequest(string requestName, byte[] requestValue)
			: this(requestName)
		{
			this.requestValue = requestValue;
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = CreateRequestElement(doc, "extendedRequest", includeDistinguishedName: false, null);
			XmlElement xmlElement2 = doc.CreateElement("requestName", "urn:oasis:names:tc:DSML:2:0:core");
			xmlElement2.InnerText = requestName;
			xmlElement.AppendChild(xmlElement2);
			if (requestValue != null)
			{
				XmlElement xmlElement3 = doc.CreateElement("requestValue", "urn:oasis:names:tc:DSML:2:0:core");
				xmlElement3.InnerText = Convert.ToBase64String(requestValue);
				XmlAttribute xmlAttribute = doc.CreateAttribute("xsi:type", "http://www.w3.org/2001/XMLSchema-instance");
				xmlAttribute.InnerText = "xsd:base64Binary";
				xmlElement3.Attributes.Append(xmlAttribute);
				xmlElement.AppendChild(xmlElement3);
			}
			return xmlElement;
		}
	}
	public class SearchRequest : DirectoryRequest
	{
		private string dn;

		private StringCollection directoryAttributes = new StringCollection();

		private object directoryFilter;

		private SearchScope directoryScope = SearchScope.Subtree;

		private DereferenceAlias directoryRefAlias;

		private int directorySizeLimit;

		private TimeSpan directoryTimeLimit = new TimeSpan(0L);

		private bool directoryTypesOnly;

		public string DistinguishedName
		{
			get
			{
				return dn;
			}
			set
			{
				dn = value;
			}
		}

		public StringCollection Attributes => directoryAttributes;

		public object Filter
		{
			get
			{
				return directoryFilter;
			}
			set
			{
				if (value is string || value is XmlDocument || value == null)
				{
					directoryFilter = value;
					return;
				}
				throw new ArgumentException(Res.GetString("ValidFilterType"), "value");
			}
		}

		public SearchScope Scope
		{
			get
			{
				return directoryScope;
			}
			set
			{
				if (value < SearchScope.Base || value > SearchScope.Subtree)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(SearchScope));
				}
				directoryScope = value;
			}
		}

		public DereferenceAlias Aliases
		{
			get
			{
				return directoryRefAlias;
			}
			set
			{
				if (value < DereferenceAlias.Never || value > DereferenceAlias.Always)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(DereferenceAlias));
				}
				directoryRefAlias = value;
			}
		}

		public int SizeLimit
		{
			get
			{
				return directorySizeLimit;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("NoNegativeSizeLimit"), "value");
				}
				directorySizeLimit = value;
			}
		}

		public TimeSpan TimeLimit
		{
			get
			{
				return directoryTimeLimit;
			}
			set
			{
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				if (value.TotalSeconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				directoryTimeLimit = value;
			}
		}

		public bool TypesOnly
		{
			get
			{
				return directoryTypesOnly;
			}
			set
			{
				directoryTypesOnly = value;
			}
		}

		public SearchRequest()
		{
			directoryAttributes = new StringCollection();
		}

		public SearchRequest(string distinguishedName, XmlDocument filter, SearchScope searchScope, params string[] attributeList)
			: this()
		{
			dn = distinguishedName;
			if (attributeList != null)
			{
				for (int i = 0; i < attributeList.Length; i++)
				{
					directoryAttributes.Add(attributeList[i]);
				}
			}
			Scope = searchScope;
			Filter = filter;
		}

		public SearchRequest(string distinguishedName, string ldapFilter, SearchScope searchScope, params string[] attributeList)
			: this()
		{
			dn = distinguishedName;
			if (attributeList != null)
			{
				for (int i = 0; i < attributeList.Length; i++)
				{
					directoryAttributes.Add(attributeList[i]);
				}
			}
			Scope = searchScope;
			Filter = ldapFilter;
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = CreateRequestElement(doc, "searchRequest", includeDistinguishedName: true, dn);
			XmlAttribute xmlAttribute = doc.CreateAttribute("scope", null);
			switch (directoryScope)
			{
			case SearchScope.Subtree:
				xmlAttribute.InnerText = "wholeSubtree";
				break;
			case SearchScope.OneLevel:
				xmlAttribute.InnerText = "singleLevel";
				break;
			case SearchScope.Base:
				xmlAttribute.InnerText = "baseObject";
				break;
			}
			xmlElement.Attributes.Append(xmlAttribute);
			XmlAttribute xmlAttribute2 = doc.CreateAttribute("derefAliases", null);
			switch (directoryRefAlias)
			{
			case DereferenceAlias.Never:
				xmlAttribute2.InnerText = "neverDerefAliases";
				break;
			case DereferenceAlias.InSearching:
				xmlAttribute2.InnerText = "derefInSearching";
				break;
			case DereferenceAlias.FindingBaseObject:
				xmlAttribute2.InnerText = "derefFindingBaseObj";
				break;
			case DereferenceAlias.Always:
				xmlAttribute2.InnerText = "derefAlways";
				break;
			}
			xmlElement.Attributes.Append(xmlAttribute2);
			XmlAttribute xmlAttribute3 = doc.CreateAttribute("sizeLimit", null);
			xmlAttribute3.InnerText = directorySizeLimit.ToString(CultureInfo.InvariantCulture);
			xmlElement.Attributes.Append(xmlAttribute3);
			XmlAttribute xmlAttribute4 = doc.CreateAttribute("timeLimit", null);
			xmlAttribute4.InnerText = (directoryTimeLimit.Ticks / 10000000).ToString(CultureInfo.InvariantCulture);
			xmlElement.Attributes.Append(xmlAttribute4);
			XmlAttribute xmlAttribute5 = doc.CreateAttribute("typesOnly", null);
			xmlAttribute5.InnerText = (directoryTypesOnly ? "true" : "false");
			xmlElement.Attributes.Append(xmlAttribute5);
			XmlElement xmlElement2 = doc.CreateElement("filter", "urn:oasis:names:tc:DSML:2:0:core");
			if (Filter != null)
			{
				StringWriter stringWriter = new StringWriter(CultureInfo.InvariantCulture);
				XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);
				try
				{
					if (Filter is XmlDocument)
					{
						if (((XmlDocument)Filter).NamespaceURI.Length == 0)
						{
							CopyFilter((XmlDocument)Filter, xmlTextWriter);
							xmlElement2.InnerXml = stringWriter.ToString();
						}
						else
						{
							xmlElement2.InnerXml = ((XmlDocument)Filter).OuterXml;
						}
					}
					else if (Filter is string)
					{
						string text = (string)Filter;
						if (!text.StartsWith("(", StringComparison.Ordinal) && !text.EndsWith(")", StringComparison.Ordinal))
						{
							text = text.Insert(0, "(");
							text += ")";
						}
						ADFilter aDFilter = FilterParser.ParseFilterString(text);
						if (aDFilter == null)
						{
							throw new ArgumentException(Res.GetString("BadSearchLDAPFilter"));
						}
						DSMLFilterWriter dSMLFilterWriter = new DSMLFilterWriter();
						dSMLFilterWriter.WriteFilter(aDFilter, filterTags: false, xmlTextWriter, "urn:oasis:names:tc:DSML:2:0:core");
						xmlElement2.InnerXml = stringWriter.ToString();
					}
				}
				finally
				{
					xmlTextWriter.Close();
				}
			}
			else
			{
				xmlElement2.InnerXml = "<present name='objectClass' xmlns=\"urn:oasis:names:tc:DSML:2:0:core\"/>";
			}
			xmlElement.AppendChild(xmlElement2);
			if (directoryAttributes != null && directoryAttributes.Count != 0)
			{
				XmlElement xmlElement3 = doc.CreateElement("attributes", "urn:oasis:names:tc:DSML:2:0:core");
				xmlElement.AppendChild(xmlElement3);
				StringEnumerator enumerator = directoryAttributes.GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						string current = enumerator.Current;
						DirectoryAttribute directoryAttribute = new DirectoryAttribute();
						directoryAttribute.Name = current;
						XmlElement newChild = directoryAttribute.ToXmlNode(doc, "attribute");
						xmlElement3.AppendChild(newChild);
					}
					return xmlElement;
				}
				finally
				{
					if (enumerator is IDisposable disposable)
					{
						disposable.Dispose();
					}
				}
			}
			return xmlElement;
		}

		private void CopyFilter(XmlNode node, XmlTextWriter writer)
		{
			for (XmlNode xmlNode = node.FirstChild; xmlNode != null; xmlNode = xmlNode.NextSibling)
			{
				if (xmlNode != null)
				{
					CopyXmlTree(xmlNode, writer);
				}
			}
		}

		private void CopyXmlTree(XmlNode node, XmlTextWriter writer)
		{
			XmlNodeType nodeType = node.NodeType;
			if (nodeType == XmlNodeType.Element)
			{
				writer.WriteStartElement(node.LocalName, "urn:oasis:names:tc:DSML:2:0:core");
				foreach (XmlAttribute attribute in node.Attributes)
				{
					writer.WriteAttributeString(attribute.LocalName, attribute.Value);
				}
				for (XmlNode xmlNode = node.FirstChild; xmlNode != null; xmlNode = xmlNode.NextSibling)
				{
					CopyXmlTree(xmlNode, writer);
				}
				writer.WriteEndElement();
			}
			else
			{
				writer.WriteRaw(node.OuterXml);
			}
		}
	}
	public class DsmlAuthRequest : DirectoryRequest
	{
		private string directoryPrincipal = "";

		public string Principal
		{
			get
			{
				return directoryPrincipal;
			}
			set
			{
				directoryPrincipal = value;
			}
		}

		public DsmlAuthRequest()
		{
		}

		public DsmlAuthRequest(string principal)
		{
			directoryPrincipal = principal;
		}

		protected override XmlElement ToXmlNode(XmlDocument doc)
		{
			XmlElement xmlElement = CreateRequestElement(doc, "authRequest", includeDistinguishedName: false, null);
			XmlAttribute xmlAttribute = doc.CreateAttribute("principal", null);
			xmlAttribute.InnerText = Principal;
			xmlElement.Attributes.Append(xmlAttribute);
			return xmlElement;
		}
	}
	public abstract class DirectoryResponse : DirectoryOperation
	{
		internal XmlNode dsmlNode;

		internal XmlNamespaceManager dsmlNS;

		internal bool dsmlRequest;

		internal string dn;

		internal DirectoryControl[] directoryControls;

		internal ResultCode result = (ResultCode)(-1);

		internal string directoryMessage;

		internal Uri[] directoryReferral;

		private string requestID;

		public string RequestId
		{
			get
			{
				if (dsmlRequest && requestID == null)
				{
					XmlAttribute xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode("@dsml:requestID", dsmlNS);
					if (xmlAttribute == null)
					{
						xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode("@requestID", dsmlNS);
					}
					if (xmlAttribute != null)
					{
						requestID = xmlAttribute.Value;
					}
				}
				return requestID;
			}
		}

		public virtual string MatchedDN
		{
			get
			{
				if (dsmlRequest && dn == null)
				{
					dn = MatchedDNHelper("@dsml:matchedDN", "@matchedDN");
				}
				return dn;
			}
		}

		public virtual DirectoryControl[] Controls
		{
			get
			{
				if (dsmlRequest && directoryControls == null)
				{
					directoryControls = ControlsHelper("dsml:control");
				}
				if (directoryControls == null)
				{
					return new DirectoryControl[0];
				}
				DirectoryControl[] array = new DirectoryControl[directoryControls.Length];
				for (int i = 0; i < directoryControls.Length; i++)
				{
					array[i] = new DirectoryControl(directoryControls[i].Type, directoryControls[i].GetValue(), directoryControls[i].IsCritical, directoryControls[i].ServerSide);
				}
				DirectoryControl.TransformControls(array);
				return array;
			}
		}

		public virtual ResultCode ResultCode
		{
			get
			{
				if (dsmlRequest && result == (ResultCode)(-1))
				{
					result = ResultCodeHelper("dsml:resultCode/@dsml:code", "dsml:resultCode/@code");
				}
				return result;
			}
		}

		public virtual string ErrorMessage
		{
			get
			{
				if (dsmlRequest && directoryMessage == null)
				{
					directoryMessage = ErrorMessageHelper("dsml:errorMessage");
				}
				return directoryMessage;
			}
		}

		public virtual Uri[] Referral
		{
			get
			{
				if (dsmlRequest && directoryReferral == null)
				{
					directoryReferral = ReferralHelper("dsml:referral");
				}
				if (directoryReferral == null)
				{
					return new Uri[0];
				}
				Uri[] array = new Uri[directoryReferral.Length];
				for (int i = 0; i < directoryReferral.Length; i++)
				{
					array[i] = new Uri(directoryReferral[i].AbsoluteUri);
				}
				return array;
			}
		}

		internal DirectoryResponse(XmlNode node)
		{
			dsmlNode = node;
			dsmlNS = NamespaceUtils.GetDsmlNamespaceManager();
			dsmlRequest = true;
		}

		internal DirectoryResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
		{
			this.dn = dn;
			directoryControls = controls;
			this.result = result;
			directoryMessage = message;
			directoryReferral = referral;
		}

		internal string MatchedDNHelper(string primaryXPath, string secondaryXPath)
		{
			XmlAttribute xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode(primaryXPath, dsmlNS);
			if (xmlAttribute == null)
			{
				return ((XmlAttribute)dsmlNode.SelectSingleNode(secondaryXPath, dsmlNS))?.Value;
			}
			return xmlAttribute.Value;
		}

		internal DirectoryControl[] ControlsHelper(string primaryXPath)
		{
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes(primaryXPath, dsmlNS);
			if (xmlNodeList.Count == 0)
			{
				return new DirectoryControl[0];
			}
			DirectoryControl[] array = new DirectoryControl[xmlNodeList.Count];
			int num = 0;
			foreach (XmlNode item in xmlNodeList)
			{
				array[num] = new DirectoryControl((XmlElement)item);
				num++;
			}
			return array;
		}

		internal ResultCode ResultCodeHelper(string primaryXPath, string secondaryXPath)
		{
			XmlAttribute xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode(primaryXPath, dsmlNS);
			if (xmlAttribute == null)
			{
				xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode(secondaryXPath, dsmlNS);
				if (xmlAttribute == null)
				{
					throw new DsmlInvalidDocumentException(Res.GetString("MissingOperationResponseResultCode"));
				}
			}
			string value = xmlAttribute.Value;
			int code;
			try
			{
				code = int.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
			}
			catch (FormatException)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("BadOperationResponseResultCode", value));
			}
			catch (OverflowException)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("BadOperationResponseResultCode", value));
			}
			if (!Utility.IsResultCode((ResultCode)code))
			{
				throw new DsmlInvalidDocumentException(Res.GetString("BadOperationResponseResultCode", value));
			}
			return (ResultCode)code;
		}

		internal string ErrorMessageHelper(string primaryXPath)
		{
			return ((XmlElement)dsmlNode.SelectSingleNode(primaryXPath, dsmlNS))?.InnerText;
		}

		internal Uri[] ReferralHelper(string primaryXPath)
		{
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes(primaryXPath, dsmlNS);
			if (xmlNodeList.Count == 0)
			{
				return new Uri[0];
			}
			Uri[] array = new Uri[xmlNodeList.Count];
			int num = 0;
			foreach (XmlNode item in xmlNodeList)
			{
				array[num] = new Uri(item.InnerText);
				num++;
			}
			return array;
		}
	}
	public class DeleteResponse : DirectoryResponse
	{
		internal DeleteResponse(XmlNode node)
			: base(node)
		{
		}

		internal DeleteResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
			: base(dn, controls, result, message, referral)
		{
		}
	}
	public class AddResponse : DirectoryResponse
	{
		internal AddResponse(XmlNode node)
			: base(node)
		{
		}

		internal AddResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
			: base(dn, controls, result, message, referral)
		{
		}
	}
	public class ModifyResponse : DirectoryResponse
	{
		internal ModifyResponse(XmlNode node)
			: base(node)
		{
		}

		internal ModifyResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
			: base(dn, controls, result, message, referral)
		{
		}
	}
	public class ModifyDNResponse : DirectoryResponse
	{
		internal ModifyDNResponse(XmlNode node)
			: base(node)
		{
		}

		internal ModifyDNResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
			: base(dn, controls, result, message, referral)
		{
		}
	}
	public class CompareResponse : DirectoryResponse
	{
		internal CompareResponse(XmlNode node)
			: base(node)
		{
		}

		internal CompareResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
			: base(dn, controls, result, message, referral)
		{
		}
	}
	public class ExtendedResponse : DirectoryResponse
	{
		internal string name;

		internal byte[] value;

		public string ResponseName
		{
			get
			{
				if (dsmlRequest && name == null)
				{
					XmlElement xmlElement = (XmlElement)dsmlNode.SelectSingleNode("dsml:responseName", dsmlNS);
					if (xmlElement != null)
					{
						name = xmlElement.InnerText;
					}
				}
				return name;
			}
		}

		public byte[] ResponseValue
		{
			get
			{
				if (dsmlRequest && value == null)
				{
					XmlElement xmlElement = (XmlElement)dsmlNode.SelectSingleNode("dsml:response", dsmlNS);
					if (xmlElement != null)
					{
						string innerText = xmlElement.InnerText;
						try
						{
							value = Convert.FromBase64String(innerText);
						}
						catch (FormatException)
						{
							throw new DsmlInvalidDocumentException(Res.GetString("BadBase64Value"));
						}
					}
				}
				if (value == null)
				{
					return new byte[0];
				}
				byte[] array = new byte[value.Length];
				for (int i = 0; i < value.Length; i++)
				{
					array[i] = value[i];
				}
				return array;
			}
		}

		internal ExtendedResponse(XmlNode node)
			: base(node)
		{
		}

		internal ExtendedResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
			: base(dn, controls, result, message, referral)
		{
		}
	}
	public class SearchResponse : DirectoryResponse
	{
		private SearchResultReferenceCollection referenceCollection = new SearchResultReferenceCollection();

		private SearchResultEntryCollection entryCollection = new SearchResultEntryCollection();

		internal bool searchDone;

		public override string MatchedDN
		{
			get
			{
				if (dsmlRequest && dn == null)
				{
					dn = MatchedDNHelper("dsml:searchResultDone/@dsml:matchedDN", "dsml:searchResultDone/@matchedDN");
				}
				return dn;
			}
		}

		public override DirectoryControl[] Controls
		{
			get
			{
				DirectoryControl[] array = null;
				if (dsmlRequest && directoryControls == null)
				{
					directoryControls = ControlsHelper("dsml:searchResultDone/dsml:control");
				}
				if (directoryControls == null)
				{
					return new DirectoryControl[0];
				}
				array = new DirectoryControl[directoryControls.Length];
				for (int i = 0; i < directoryControls.Length; i++)
				{
					array[i] = new DirectoryControl(directoryControls[i].Type, directoryControls[i].GetValue(), directoryControls[i].IsCritical, directoryControls[i].ServerSide);
				}
				DirectoryControl.TransformControls(array);
				return array;
			}
		}

		public override ResultCode ResultCode
		{
			get
			{
				if (dsmlRequest && result == (ResultCode)(-1))
				{
					result = ResultCodeHelper("dsml:searchResultDone/dsml:resultCode/@dsml:code", "dsml:searchResultDone/dsml:resultCode/@code");
				}
				return result;
			}
		}

		public override string ErrorMessage
		{
			get
			{
				if (dsmlRequest && directoryMessage == null)
				{
					directoryMessage = ErrorMessageHelper("dsml:searchResultDone/dsml:errorMessage");
				}
				return directoryMessage;
			}
		}

		public override Uri[] Referral
		{
			get
			{
				if (dsmlRequest && directoryReferral == null)
				{
					directoryReferral = ReferralHelper("dsml:searchResultDone/dsml:referral");
				}
				if (directoryReferral == null)
				{
					return new Uri[0];
				}
				Uri[] array = new Uri[directoryReferral.Length];
				for (int i = 0; i < directoryReferral.Length; i++)
				{
					array[i] = new Uri(directoryReferral[i].AbsoluteUri);
				}
				return array;
			}
		}

		public SearchResultReferenceCollection References
		{
			get
			{
				if (dsmlRequest && referenceCollection.Count == 0)
				{
					referenceCollection = ReferenceHelper();
				}
				return referenceCollection;
			}
		}

		public SearchResultEntryCollection Entries
		{
			get
			{
				if (dsmlRequest && entryCollection.Count == 0)
				{
					entryCollection = EntryHelper();
				}
				return entryCollection;
			}
		}

		internal SearchResponse(XmlNode node)
			: base(node)
		{
		}

		internal SearchResponse(string dn, DirectoryControl[] controls, ResultCode result, string message, Uri[] referral)
			: base(dn, controls, result, message, referral)
		{
		}

		internal void SetReferences(SearchResultReferenceCollection col)
		{
			referenceCollection = col;
		}

		internal void SetEntries(SearchResultEntryCollection col)
		{
			entryCollection = col;
		}

		private SearchResultReferenceCollection ReferenceHelper()
		{
			SearchResultReferenceCollection searchResultReferenceCollection = new SearchResultReferenceCollection();
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes("dsml:searchResultReference", dsmlNS);
			if (xmlNodeList.Count != 0)
			{
				foreach (XmlNode item in xmlNodeList)
				{
					SearchResultReference reference = new SearchResultReference((XmlElement)item);
					searchResultReferenceCollection.Add(reference);
				}
				return searchResultReferenceCollection;
			}
			return searchResultReferenceCollection;
		}

		private SearchResultEntryCollection EntryHelper()
		{
			SearchResultEntryCollection searchResultEntryCollection = new SearchResultEntryCollection();
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes("dsml:searchResultEntry", dsmlNS);
			if (xmlNodeList.Count != 0)
			{
				foreach (XmlNode item in xmlNodeList)
				{
					SearchResultEntry entry = new SearchResultEntry((XmlElement)item);
					searchResultEntryCollection.Add(entry);
				}
				return searchResultEntryCollection;
			}
			return searchResultEntryCollection;
		}
	}
	public class DsmlErrorResponse : DirectoryResponse
	{
		private string message;

		private string detail;

		private ErrorResponseCategory category = (ErrorResponseCategory)(-1);

		public string Message
		{
			get
			{
				if (message == null)
				{
					XmlElement xmlElement = (XmlElement)dsmlNode.SelectSingleNode("dsml:message", dsmlNS);
					if (xmlElement != null)
					{
						message = xmlElement.InnerText;
					}
				}
				return message;
			}
		}

		public string Detail
		{
			get
			{
				if (detail == null)
				{
					XmlElement xmlElement = (XmlElement)dsmlNode.SelectSingleNode("dsml:detail", dsmlNS);
					if (xmlElement != null)
					{
						detail = xmlElement.InnerXml;
					}
				}
				return detail;
			}
		}

		public ErrorResponseCategory Type
		{
			get
			{
				if (category == (ErrorResponseCategory)(-1))
				{
					XmlAttribute xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode("@dsml:type", dsmlNS);
					if (xmlAttribute == null)
					{
						xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode("@type", dsmlNS);
					}
					if (xmlAttribute == null)
					{
						throw new DsmlInvalidDocumentException(Res.GetString("MissingErrorResponseType"));
					}
					switch (xmlAttribute.Value)
					{
					case "notAttempted":
						category = ErrorResponseCategory.NotAttempted;
						break;
					case "couldNotConnect":
						category = ErrorResponseCategory.CouldNotConnect;
						break;
					case "connectionClosed":
						category = ErrorResponseCategory.ConnectionClosed;
						break;
					case "malformedRequest":
						category = ErrorResponseCategory.MalformedRequest;
						break;
					case "gatewayInternalError":
						category = ErrorResponseCategory.GatewayInternalError;
						break;
					case "authenticationFailed":
						category = ErrorResponseCategory.AuthenticationFailed;
						break;
					case "unresolvableURI":
						category = ErrorResponseCategory.UnresolvableUri;
						break;
					case "other":
						category = ErrorResponseCategory.Other;
						break;
					default:
						throw new DsmlInvalidDocumentException(Res.GetString("ErrorResponseInvalidValue", xmlAttribute.Value));
					}
				}
				return category;
			}
		}

		public override string MatchedDN
		{
			get
			{
				throw new NotSupportedException(Res.GetString("NotSupportOnDsmlErrRes"));
			}
		}

		public override DirectoryControl[] Controls
		{
			get
			{
				throw new NotSupportedException(Res.GetString("NotSupportOnDsmlErrRes"));
			}
		}

		public override ResultCode ResultCode
		{
			get
			{
				throw new NotSupportedException(Res.GetString("NotSupportOnDsmlErrRes"));
			}
		}

		public override string ErrorMessage
		{
			get
			{
				throw new NotSupportedException(Res.GetString("NotSupportOnDsmlErrRes"));
			}
		}

		public override Uri[] Referral
		{
			get
			{
				throw new NotSupportedException(Res.GetString("NotSupportOnDsmlErrRes"));
			}
		}

		internal DsmlErrorResponse(XmlNode node)
			: base(node)
		{
		}
	}
	public class DsmlAuthResponse : DirectoryResponse
	{
		internal DsmlAuthResponse(XmlNode node)
			: base(node)
		{
		}
	}
	public class PartialResultsCollection : ReadOnlyCollectionBase
	{
		public object this[int index] => base.InnerList[index];

		internal PartialResultsCollection()
		{
		}

		internal int Add(object value)
		{
			return base.InnerList.Add(value);
		}

		public bool Contains(object value)
		{
			return base.InnerList.Contains(value);
		}

		public int IndexOf(object value)
		{
			return base.InnerList.IndexOf(value);
		}

		public void CopyTo(object[] values, int index)
		{
			base.InnerList.CopyTo(values, index);
		}
	}
	[Flags]
	public enum ReferralChasingOptions
	{
		None = 0,
		Subordinate = 0x20,
		External = 0x40,
		All = 0x60
	}
	public enum ResultCode
	{
		Success = 0,
		OperationsError = 1,
		ProtocolError = 2,
		TimeLimitExceeded = 3,
		SizeLimitExceeded = 4,
		CompareFalse = 5,
		CompareTrue = 6,
		AuthMethodNotSupported = 7,
		StrongAuthRequired = 8,
		ReferralV2 = 9,
		Referral = 10,
		AdminLimitExceeded = 11,
		UnavailableCriticalExtension = 12,
		ConfidentialityRequired = 13,
		SaslBindInProgress = 14,
		NoSuchAttribute = 16,
		UndefinedAttributeType = 17,
		InappropriateMatching = 18,
		ConstraintViolation = 19,
		AttributeOrValueExists = 20,
		InvalidAttributeSyntax = 21,
		NoSuchObject = 32,
		AliasProblem = 33,
		InvalidDNSyntax = 34,
		AliasDereferencingProblem = 36,
		InappropriateAuthentication = 48,
		InsufficientAccessRights = 50,
		Busy = 51,
		Unavailable = 52,
		UnwillingToPerform = 53,
		LoopDetect = 54,
		SortControlMissing = 60,
		OffsetRangeError = 61,
		NamingViolation = 64,
		ObjectClassViolation = 65,
		NotAllowedOnNonLeaf = 66,
		NotAllowedOnRdn = 67,
		EntryAlreadyExists = 68,
		ObjectClassModificationsProhibited = 69,
		ResultsTooLarge = 70,
		AffectsMultipleDsas = 71,
		VirtualListViewError = 76,
		Other = 80
	}
	internal class OperationErrorMappings
	{
		private static Hashtable ResultCodeHash;

		static OperationErrorMappings()
		{
			ResultCodeHash = new Hashtable();
			ResultCodeHash.Add(ResultCode.Success, Res.GetString("LDAP_SUCCESS"));
			ResultCodeHash.Add(ResultCode.OperationsError, Res.GetString("LDAP_OPERATIONS_ERROR"));
			ResultCodeHash.Add(ResultCode.ProtocolError, Res.GetString("LDAP_PROTOCOL_ERROR"));
			ResultCodeHash.Add(ResultCode.TimeLimitExceeded, Res.GetString("LDAP_TIMELIMIT_EXCEEDED"));
			ResultCodeHash.Add(ResultCode.SizeLimitExceeded, Res.GetString("LDAP_SIZELIMIT_EXCEEDED"));
			ResultCodeHash.Add(ResultCode.CompareFalse, Res.GetString("LDAP_COMPARE_FALSE"));
			ResultCodeHash.Add(ResultCode.CompareTrue, Res.GetString("LDAP_COMPARE_TRUE"));
			ResultCodeHash.Add(ResultCode.AuthMethodNotSupported, Res.GetString("LDAP_AUTH_METHOD_NOT_SUPPORTED"));
			ResultCodeHash.Add(ResultCode.StrongAuthRequired, Res.GetString("LDAP_STRONG_AUTH_REQUIRED"));
			ResultCodeHash.Add(ResultCode.ReferralV2, Res.GetString("LDAP_PARTIAL_RESULTS"));
			ResultCodeHash.Add(ResultCode.Referral, Res.GetString("LDAP_REFERRAL"));
			ResultCodeHash.Add(ResultCode.AdminLimitExceeded, Res.GetString("LDAP_ADMIN_LIMIT_EXCEEDED"));
			ResultCodeHash.Add(ResultCode.UnavailableCriticalExtension, Res.GetString("LDAP_UNAVAILABLE_CRIT_EXTENSION"));
			ResultCodeHash.Add(ResultCode.ConfidentialityRequired, Res.GetString("LDAP_CONFIDENTIALITY_REQUIRED"));
			ResultCodeHash.Add(ResultCode.SaslBindInProgress, Res.GetString("LDAP_SASL_BIND_IN_PROGRESS"));
			ResultCodeHash.Add(ResultCode.NoSuchAttribute, Res.GetString("LDAP_NO_SUCH_ATTRIBUTE"));
			ResultCodeHash.Add(ResultCode.UndefinedAttributeType, Res.GetString("LDAP_UNDEFINED_TYPE"));
			ResultCodeHash.Add(ResultCode.InappropriateMatching, Res.GetString("LDAP_INAPPROPRIATE_MATCHING"));
			ResultCodeHash.Add(ResultCode.ConstraintViolation, Res.GetString("LDAP_CONSTRAINT_VIOLATION"));
			ResultCodeHash.Add(ResultCode.AttributeOrValueExists, Res.GetString("LDAP_ATTRIBUTE_OR_VALUE_EXISTS"));
			ResultCodeHash.Add(ResultCode.InvalidAttributeSyntax, Res.GetString("LDAP_INVALID_SYNTAX"));
			ResultCodeHash.Add(ResultCode.NoSuchObject, Res.GetString("LDAP_NO_SUCH_OBJECT"));
			ResultCodeHash.Add(ResultCode.AliasProblem, Res.GetString("LDAP_ALIAS_PROBLEM"));
			ResultCodeHash.Add(ResultCode.InvalidDNSyntax, Res.GetString("LDAP_INVALID_DN_SYNTAX"));
			ResultCodeHash.Add(ResultCode.AliasDereferencingProblem, Res.GetString("LDAP_ALIAS_DEREF_PROBLEM"));
			ResultCodeHash.Add(ResultCode.InappropriateAuthentication, Res.GetString("LDAP_INAPPROPRIATE_AUTH"));
			ResultCodeHash.Add(ResultCode.InsufficientAccessRights, Res.GetString("LDAP_INSUFFICIENT_RIGHTS"));
			ResultCodeHash.Add(ResultCode.Busy, Res.GetString("LDAP_BUSY"));
			ResultCodeHash.Add(ResultCode.Unavailable, Res.GetString("LDAP_UNAVAILABLE"));
			ResultCodeHash.Add(ResultCode.UnwillingToPerform, Res.GetString("LDAP_UNWILLING_TO_PERFORM"));
			ResultCodeHash.Add(ResultCode.LoopDetect, Res.GetString("LDAP_LOOP_DETECT"));
			ResultCodeHash.Add(ResultCode.SortControlMissing, Res.GetString("LDAP_SORT_CONTROL_MISSING"));
			ResultCodeHash.Add(ResultCode.OffsetRangeError, Res.GetString("LDAP_OFFSET_RANGE_ERROR"));
			ResultCodeHash.Add(ResultCode.NamingViolation, Res.GetString("LDAP_NAMING_VIOLATION"));
			ResultCodeHash.Add(ResultCode.ObjectClassViolation, Res.GetString("LDAP_OBJECT_CLASS_VIOLATION"));
			ResultCodeHash.Add(ResultCode.NotAllowedOnNonLeaf, Res.GetString("LDAP_NOT_ALLOWED_ON_NONLEAF"));
			ResultCodeHash.Add(ResultCode.NotAllowedOnRdn, Res.GetString("LDAP_NOT_ALLOWED_ON_RDN"));
			ResultCodeHash.Add(ResultCode.EntryAlreadyExists, Res.GetString("LDAP_ALREADY_EXISTS"));
			ResultCodeHash.Add(ResultCode.ObjectClassModificationsProhibited, Res.GetString("LDAP_NO_OBJECT_CLASS_MODS"));
			ResultCodeHash.Add(ResultCode.ResultsTooLarge, Res.GetString("LDAP_RESULTS_TOO_LARGE"));
			ResultCodeHash.Add(ResultCode.AffectsMultipleDsas, Res.GetString("LDAP_AFFECTS_MULTIPLE_DSAS"));
			ResultCodeHash.Add(ResultCode.VirtualListViewError, Res.GetString("LDAP_VIRTUAL_LIST_VIEW_ERROR"));
			ResultCodeHash.Add(ResultCode.Other, Res.GetString("LDAP_OTHER"));
		}

		public static string MapResultCode(int errorCode)
		{
			return (string)ResultCodeHash[(ResultCode)errorCode];
		}
	}
	internal enum LdapOperation
	{
		LdapAdd,
		LdapModify,
		LdapSearch,
		LdapDelete,
		LdapModifyDn,
		LdapCompare,
		LdapExtendedRequest
	}
	public class SearchResultReference
	{
		private XmlNode dsmlNode;

		private XmlNamespaceManager dsmlNS;

		private bool dsmlRequest;

		private Uri[] resultReferences;

		private DirectoryControl[] resultControls;

		public Uri[] Reference
		{
			get
			{
				if (dsmlRequest && resultReferences == null)
				{
					resultReferences = UriHelper();
				}
				if (resultReferences == null)
				{
					return new Uri[0];
				}
				Uri[] array = new Uri[resultReferences.Length];
				for (int i = 0; i < resultReferences.Length; i++)
				{
					array[i] = new Uri(resultReferences[i].AbsoluteUri);
				}
				return array;
			}
		}

		public DirectoryControl[] Controls
		{
			get
			{
				DirectoryControl[] array = null;
				if (dsmlRequest && resultControls == null)
				{
					resultControls = ControlsHelper();
				}
				if (resultControls == null)
				{
					return new DirectoryControl[0];
				}
				array = new DirectoryControl[resultControls.Length];
				for (int i = 0; i < resultControls.Length; i++)
				{
					array[i] = new DirectoryControl(resultControls[i].Type, resultControls[i].GetValue(), resultControls[i].IsCritical, resultControls[i].ServerSide);
				}
				DirectoryControl.TransformControls(array);
				return array;
			}
		}

		internal SearchResultReference(XmlNode node)
		{
			dsmlNode = node;
			dsmlNS = NamespaceUtils.GetDsmlNamespaceManager();
			dsmlRequest = true;
		}

		internal SearchResultReference(Uri[] uris)
		{
			resultReferences = uris;
		}

		private Uri[] UriHelper()
		{
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes("dsml:ref", dsmlNS);
			if (xmlNodeList.Count == 0)
			{
				return new Uri[0];
			}
			Uri[] array = new Uri[xmlNodeList.Count];
			int num = 0;
			foreach (XmlNode item in xmlNodeList)
			{
				array[num] = new Uri(item.InnerText);
				num++;
			}
			return array;
		}

		private DirectoryControl[] ControlsHelper()
		{
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes("dsml:control", dsmlNS);
			if (xmlNodeList.Count == 0)
			{
				return new DirectoryControl[0];
			}
			DirectoryControl[] array = new DirectoryControl[xmlNodeList.Count];
			int num = 0;
			foreach (XmlNode item in xmlNodeList)
			{
				array[num] = new DirectoryControl((XmlElement)item);
				num++;
			}
			return array;
		}
	}
	public class SearchResultReferenceCollection : ReadOnlyCollectionBase
	{
		public SearchResultReference this[int index] => (SearchResultReference)base.InnerList[index];

		internal SearchResultReferenceCollection()
		{
		}

		internal int Add(SearchResultReference reference)
		{
			return base.InnerList.Add(reference);
		}

		public bool Contains(SearchResultReference value)
		{
			return base.InnerList.Contains(value);
		}

		public int IndexOf(SearchResultReference value)
		{
			return base.InnerList.IndexOf(value);
		}

		public void CopyTo(SearchResultReference[] values, int index)
		{
			base.InnerList.CopyTo(values, index);
		}

		internal void Clear()
		{
			base.InnerList.Clear();
		}
	}
	public class SearchResultEntry
	{
		private XmlNode dsmlNode;

		private XmlNamespaceManager dsmlNS;

		private bool dsmlRequest;

		private string distinguishedName;

		private SearchResultAttributeCollection attributes = new SearchResultAttributeCollection();

		private DirectoryControl[] resultControls;

		public string DistinguishedName
		{
			get
			{
				if (dsmlRequest && distinguishedName == null)
				{
					distinguishedName = DNHelper("@dsml:dn", "@dn");
				}
				return distinguishedName;
			}
		}

		public SearchResultAttributeCollection Attributes
		{
			get
			{
				if (dsmlRequest && attributes.Count == 0)
				{
					attributes = AttributesHelper();
				}
				return attributes;
			}
		}

		public DirectoryControl[] Controls
		{
			get
			{
				DirectoryControl[] array = null;
				if (dsmlRequest && resultControls == null)
				{
					resultControls = ControlsHelper();
				}
				if (resultControls == null)
				{
					return new DirectoryControl[0];
				}
				array = new DirectoryControl[resultControls.Length];
				for (int i = 0; i < resultControls.Length; i++)
				{
					array[i] = new DirectoryControl(resultControls[i].Type, resultControls[i].GetValue(), resultControls[i].IsCritical, resultControls[i].ServerSide);
				}
				DirectoryControl.TransformControls(array);
				return array;
			}
		}

		internal SearchResultEntry(XmlNode node)
		{
			dsmlNode = node;
			dsmlNS = NamespaceUtils.GetDsmlNamespaceManager();
			dsmlRequest = true;
		}

		internal SearchResultEntry(string dn, SearchResultAttributeCollection attrs)
		{
			distinguishedName = dn;
			attributes = attrs;
		}

		internal SearchResultEntry(string dn)
		{
			distinguishedName = dn;
		}

		private string DNHelper(string primaryXPath, string secondaryXPath)
		{
			XmlAttribute xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode(primaryXPath, dsmlNS);
			if (xmlAttribute == null)
			{
				xmlAttribute = (XmlAttribute)dsmlNode.SelectSingleNode(secondaryXPath, dsmlNS);
				if (xmlAttribute == null)
				{
					throw new DsmlInvalidDocumentException(Res.GetString("MissingSearchResultEntryDN"));
				}
				return xmlAttribute.Value;
			}
			return xmlAttribute.Value;
		}

		private SearchResultAttributeCollection AttributesHelper()
		{
			SearchResultAttributeCollection searchResultAttributeCollection = new SearchResultAttributeCollection();
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes("dsml:attr", dsmlNS);
			if (xmlNodeList.Count != 0)
			{
				foreach (XmlNode item in xmlNodeList)
				{
					DirectoryAttribute directoryAttribute = new DirectoryAttribute((XmlElement)item);
					searchResultAttributeCollection.Add(directoryAttribute.Name, directoryAttribute);
				}
				return searchResultAttributeCollection;
			}
			return searchResultAttributeCollection;
		}

		private DirectoryControl[] ControlsHelper()
		{
			XmlNodeList xmlNodeList = dsmlNode.SelectNodes("dsml:control", dsmlNS);
			if (xmlNodeList.Count == 0)
			{
				return new DirectoryControl[0];
			}
			DirectoryControl[] array = new DirectoryControl[xmlNodeList.Count];
			int num = 0;
			foreach (XmlNode item in xmlNodeList)
			{
				array[num] = new DirectoryControl((XmlElement)item);
				num++;
			}
			return array;
		}
	}
	public class SearchResultEntryCollection : ReadOnlyCollectionBase
	{
		public SearchResultEntry this[int index] => (SearchResultEntry)base.InnerList[index];

		internal SearchResultEntryCollection()
		{
		}

		internal int Add(SearchResultEntry entry)
		{
			return base.InnerList.Add(entry);
		}

		public bool Contains(SearchResultEntry value)
		{
			return base.InnerList.Contains(value);
		}

		public int IndexOf(SearchResultEntry value)
		{
			return base.InnerList.IndexOf(value);
		}

		public void CopyTo(SearchResultEntry[] values, int index)
		{
			base.InnerList.CopyTo(values, index);
		}

		internal void Clear()
		{
			base.InnerList.Clear();
		}
	}
	public enum SearchScope
	{
		Base,
		OneLevel,
		Subtree
	}
	internal class ADFilter
	{
		public enum FilterType
		{
			And,
			Or,
			Not,
			EqualityMatch,
			Substrings,
			GreaterOrEqual,
			LessOrEqual,
			Present,
			ApproxMatch,
			ExtensibleMatch
		}

		public struct FilterContent
		{
			public ArrayList And;

			public ArrayList Or;

			public ADFilter Not;

			public ADAttribute EqualityMatch;

			public ADSubstringFilter Substrings;

			public ADAttribute GreaterOrEqual;

			public ADAttribute LessOrEqual;

			public string Present;

			public ADAttribute ApproxMatch;

			public ADExtenMatchFilter ExtensibleMatch;
		}

		public FilterType Type;

		public FilterContent Filter;

		public ADFilter()
		{
			Filter = default(FilterContent);
		}
	}
	internal class ADExtenMatchFilter
	{
		public string Name;

		public ADValue Value;

		public bool DNAttributes;

		public string MatchingRule;

		public ADExtenMatchFilter()
		{
			Value = null;
			DNAttributes = false;
		}
	}
	internal class ADSubstringFilter
	{
		public string Name;

		public ADValue Initial;

		public ADValue Final;

		public ArrayList Any;

		public ADSubstringFilter()
		{
			Initial = null;
			Final = null;
			Any = new ArrayList();
		}
	}
	internal class ADAttribute
	{
		public string Name;

		public ArrayList Values;

		public ADAttribute()
		{
			Values = new ArrayList();
		}

		public override int GetHashCode()
		{
			return Name.GetHashCode();
		}
	}
	internal class ADValue
	{
		public bool IsBinary;

		public string StringVal;

		public byte[] BinaryVal;

		public ADValue()
		{
			IsBinary = false;
			BinaryVal = null;
		}
	}
	internal class DsmlAsyncResult : IAsyncResult
	{
		internal sealed class DsmlAsyncWaitHandle : WaitHandle
		{
			public DsmlAsyncWaitHandle(SafeWaitHandle handle)
			{
				base.SafeWaitHandle = handle;
			}

			~DsmlAsyncWaitHandle()
			{
				base.SafeWaitHandle = null;
			}
		}

		private DsmlAsyncWaitHandle asyncWaitHandle;

		internal AsyncCallback callback;

		internal bool completed;

		private bool completedSynchronously;

		internal ManualResetEvent manualResetEvent;

		private object stateObject;

		internal RequestState resultObject;

		internal bool hasValidRequest;

		object IAsyncResult.AsyncState => stateObject;

		WaitHandle IAsyncResult.AsyncWaitHandle
		{
			get
			{
				if (asyncWaitHandle == null)
				{
					asyncWaitHandle = new DsmlAsyncWaitHandle(manualResetEvent.SafeWaitHandle);
				}
				return asyncWaitHandle;
			}
		}

		bool IAsyncResult.CompletedSynchronously => completedSynchronously;

		bool IAsyncResult.IsCompleted => completed;

		public DsmlAsyncResult(AsyncCallback callbackRoutine, object state)
		{
			stateObject = state;
			callback = callbackRoutine;
			manualResetEvent = new ManualResetEvent(initialState: false);
		}

		public override int GetHashCode()
		{
			return manualResetEvent.GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (!(o is DsmlAsyncResult) || o == null)
			{
				return false;
			}
			return this == (DsmlAsyncResult)o;
		}
	}
	internal class RequestState
	{
		public const int bufferSize = 1024;

		public StringBuilder responseString = new StringBuilder(1024);

		public string requestString;

		public HttpWebRequest request;

		public Stream requestStream;

		public Stream responseStream;

		public byte[] bufferRead;

		public UTF8Encoding encoder = new UTF8Encoding();

		public DsmlAsyncResult dsmlAsync;

		internal bool abortCalled;

		internal Exception exception;

		public RequestState()
		{
			bufferRead = new byte[1024];
		}
	}
	internal class DsmlConstants
	{
		public const string DsmlUri = "urn:oasis:names:tc:DSML:2:0:core";

		public const string XsiUri = "http://www.w3.org/2001/XMLSchema-instance";

		public const string XsdUri = "http://www.w3.org/2001/XMLSchema";

		public const string SoapUri = "http://schemas.xmlsoap.org/soap/envelope/";

		public const string ADSessionUri = "urn:schema-microsoft-com:activedirectory:dsmlv2";

		public const string DefaultSearchFilter = "<present name='objectClass' xmlns=\"urn:oasis:names:tc:DSML:2:0:core\"/>";

		public const string HttpPostMethod = "POST";

		public const string SOAPEnvelopeBegin = "<se:Envelope xmlns:se=\"http://schemas.xmlsoap.org/soap/envelope/\">";

		public const string SOAPEnvelopeEnd = "</se:Envelope>";

		public const string SOAPBodyBegin = "<se:Body xmlns=\"urn:oasis:names:tc:DSML:2:0:core\">";

		public const string SOAPBodyEnd = "</se:Body>";

		public const string SOAPHeaderBegin = "<se:Header>";

		public const string SOAPHeaderEnd = "</se:Header>";

		public const string SOAPSession1 = "<ad:Session xmlns:ad=\"urn:schema-microsoft-com:activedirectory:dsmlv2\" ad:SessionID=\"";

		public const string SOAPSession2 = "\" se:mustUnderstand=\"1\"/>";

		public const string SOAPBeginSession = "<ad:BeginSession xmlns:ad=\"urn:schema-microsoft-com:activedirectory:dsmlv2\" se:mustUnderstand=\"1\"/>";

		public const string SOAPEndSession1 = "<ad:EndSession xmlns:ad=\"urn:schema-microsoft-com:activedirectory:dsmlv2\" ad:SessionID=\"";

		public const string SOAPEndSession2 = "\" se:mustUnderstand=\"1\"/>";

		public const string DsmlErrorResponse = "errorResponse";

		public const string DsmlSearchResponse = "searchResponse";

		public const string DsmlModifyResponse = "modifyResponse";

		public const string DsmlAddResponse = "addResponse";

		public const string DsmlDelResponse = "delResponse";

		public const string DsmlModDNResponse = "modDNResponse";

		public const string DsmlCompareResponse = "compareResponse";

		public const string DsmlExtendedResponse = "extendedResponse";

		public const string DsmlAuthResponse = "authResponse";

		public const string AttrTypePrefixedName = "xsi:type";

		public const string AttrBinaryTypePrefixedValue = "xsd:base64Binary";

		public const string AttrDsmlAttrName = "name";

		public const string ElementDsmlAttrValue = "value";

		public const string ElementSearchReqFilter = "filter";

		public const string ElementSearchReqFilterAnd = "and";

		public const string ElementSearchReqFilterOr = "or";

		public const string ElementSearchReqFilterNot = "not";

		public const string ElementSearchReqFilterSubstr = "substrings";

		public const string ElementSearchReqFilterEqual = "equalityMatch";

		public const string ElementSearchReqFilterGrteq = "greaterOrEqual";

		public const string ElementSearchReqFilterLesseq = "lessOrEqual";

		public const string ElementSearchReqFilterApprox = "approxMatch";

		public const string ElementSearchReqFilterPresent = "present";

		public const string ElementSearchReqFilterExtenmatch = "extensibleMatch";

		public const string ElementSearchReqFilterExtenmatchValue = "value";

		public const string AttrSearchReqFilterPresentName = "name";

		public const string AttrSearchReqFilterExtenmatchName = "name";

		public const string AttrSearchReqFilterExtenmatchMatchrule = "matchingRule";

		public const string AttrSearchReqFilterExtenmatchDnattr = "dnAttributes";

		public const string AttrSearchReqFilterSubstrName = "name";

		public const string ElementSearchReqFilterSubstrInit = "initial";

		public const string ElementSearchReqFilterSubstrAny = "any";

		public const string ElementSearchReqFilterSubstrFinal = "final";

		private DsmlConstants()
		{
		}
	}
	public class DsmlDirectoryIdentifier : DirectoryIdentifier
	{
		private Uri uri;

		public Uri ServerUri => uri;

		public DsmlDirectoryIdentifier(Uri serverUri)
		{
			if (serverUri == null)
			{
				throw new ArgumentNullException("serverUri");
			}
			if (string.Compare(serverUri.Scheme, "http", StringComparison.OrdinalIgnoreCase) != 0 && string.Compare(serverUri.Scheme, "https", StringComparison.OrdinalIgnoreCase) != 0)
			{
				throw new ArgumentException(Res.GetString("DsmlNonHttpUri"));
			}
			uri = serverUri;
		}
	}
	public abstract class DsmlDocument
	{
		internal string dsmlRequestID;

		public abstract XmlDocument ToXml();
	}
	public class DsmlRequestDocument : DsmlDocument, IList, ICollection, IEnumerable
	{
		private DsmlDocumentProcessing docProcessing;

		private DsmlResponseOrder resOrder;

		private DsmlErrorProcessing errProcessing = DsmlErrorProcessing.Exit;

		private ArrayList dsmlRequests;

		public DsmlDocumentProcessing DocumentProcessing
		{
			get
			{
				return docProcessing;
			}
			set
			{
				if (value < DsmlDocumentProcessing.Sequential || value > DsmlDocumentProcessing.Parallel)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(DsmlDocumentProcessing));
				}
				docProcessing = value;
			}
		}

		public DsmlResponseOrder ResponseOrder
		{
			get
			{
				return resOrder;
			}
			set
			{
				if (value < DsmlResponseOrder.Sequential || value > DsmlResponseOrder.Unordered)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(DsmlResponseOrder));
				}
				resOrder = value;
			}
		}

		public DsmlErrorProcessing ErrorProcessing
		{
			get
			{
				return errProcessing;
			}
			set
			{
				if (value < DsmlErrorProcessing.Resume || value > DsmlErrorProcessing.Exit)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(DsmlErrorProcessing));
				}
				errProcessing = value;
			}
		}

		public string RequestId
		{
			get
			{
				return dsmlRequestID;
			}
			set
			{
				dsmlRequestID = value;
			}
		}

		bool IList.IsFixedSize => false;

		bool IList.IsReadOnly => false;

		object ICollection.SyncRoot => dsmlRequests.SyncRoot;

		bool ICollection.IsSynchronized => dsmlRequests.IsSynchronized;

		protected bool IsFixedSize => false;

		protected bool IsReadOnly => false;

		protected object SyncRoot => dsmlRequests.SyncRoot;

		protected bool IsSynchronized => dsmlRequests.IsSynchronized;

		public int Count => dsmlRequests.Count;

		int ICollection.Count => dsmlRequests.Count;

		public DirectoryRequest this[int index]
		{
			get
			{
				return (DirectoryRequest)dsmlRequests[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				dsmlRequests[index] = value;
			}
		}

		object IList.this[int index]
		{
			get
			{
				return this[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!(value is DirectoryRequest))
				{
					throw new ArgumentException(Res.GetString("InvalidValueType", "DirectoryRequest"), "value");
				}
				dsmlRequests[index] = (DirectoryRequest)value;
			}
		}

		public DsmlRequestDocument()
		{
			Utility.CheckOSVersion();
			dsmlRequests = new ArrayList();
		}

		public IEnumerator GetEnumerator()
		{
			return dsmlRequests.GetEnumerator();
		}

		public int Add(DirectoryRequest request)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}
			return dsmlRequests.Add(request);
		}

		int IList.Add(object request)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}
			if (!(request is DirectoryRequest))
			{
				throw new ArgumentException(Res.GetString("InvalidValueType", "DirectoryRequest"), "request");
			}
			return Add((DirectoryRequest)request);
		}

		public void Clear()
		{
			dsmlRequests.Clear();
		}

		void IList.Clear()
		{
			Clear();
		}

		public bool Contains(DirectoryRequest value)
		{
			return dsmlRequests.Contains(value);
		}

		bool IList.Contains(object value)
		{
			return Contains((DirectoryRequest)value);
		}

		public int IndexOf(DirectoryRequest value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			return dsmlRequests.IndexOf(value);
		}

		int IList.IndexOf(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			return IndexOf((DirectoryRequest)value);
		}

		public void Insert(int index, DirectoryRequest value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			dsmlRequests.Insert(index, value);
		}

		void IList.Insert(int index, object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is DirectoryRequest))
			{
				throw new ArgumentException(Res.GetString("InvalidValueType", "DirectoryRequest"), "value");
			}
			Insert(index, (DirectoryRequest)value);
		}

		public void Remove(DirectoryRequest value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			dsmlRequests.Remove(value);
		}

		void IList.Remove(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			Remove((DirectoryRequest)value);
		}

		public void RemoveAt(int index)
		{
			dsmlRequests.RemoveAt(index);
		}

		void IList.RemoveAt(int index)
		{
			RemoveAt(index);
		}

		public void CopyTo(DirectoryRequest[] value, int i)
		{
			dsmlRequests.CopyTo(value, i);
		}

		void ICollection.CopyTo(Array value, int i)
		{
			dsmlRequests.CopyTo(value, i);
		}

		public override XmlDocument ToXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			StartBatchRequest(xmlDocument);
			foreach (DirectoryRequest dsmlRequest in dsmlRequests)
			{
				xmlDocument.DocumentElement.AppendChild(dsmlRequest.ToXmlNodeHelper(xmlDocument));
			}
			return xmlDocument;
		}

		private void StartBatchRequest(XmlDocument xmldoc)
		{
			string xml = "<batchRequest xmlns=\"urn:oasis:names:tc:DSML:2:0:core\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" />";
			xmldoc.LoadXml(xml);
			XmlAttribute xmlAttribute = xmldoc.CreateAttribute("processing", null);
			switch (docProcessing)
			{
			case DsmlDocumentProcessing.Sequential:
				xmlAttribute.InnerText = "sequential";
				break;
			case DsmlDocumentProcessing.Parallel:
				xmlAttribute.InnerText = "parallel";
				break;
			}
			xmldoc.DocumentElement.Attributes.Append(xmlAttribute);
			xmlAttribute = xmldoc.CreateAttribute("responseOrder", null);
			switch (resOrder)
			{
			case DsmlResponseOrder.Sequential:
				xmlAttribute.InnerText = "sequential";
				break;
			case DsmlResponseOrder.Unordered:
				xmlAttribute.InnerText = "unordered";
				break;
			}
			xmldoc.DocumentElement.Attributes.Append(xmlAttribute);
			xmlAttribute = xmldoc.CreateAttribute("onError", null);
			switch (errProcessing)
			{
			case DsmlErrorProcessing.Exit:
				xmlAttribute.InnerText = "exit";
				break;
			case DsmlErrorProcessing.Resume:
				xmlAttribute.InnerText = "resume";
				break;
			}
			xmldoc.DocumentElement.Attributes.Append(xmlAttribute);
			if (dsmlRequestID != null)
			{
				xmlAttribute = xmldoc.CreateAttribute("requestID", null);
				xmlAttribute.InnerText = dsmlRequestID;
				xmldoc.DocumentElement.Attributes.Append(xmlAttribute);
			}
		}
	}
	public class DsmlResponseDocument : DsmlDocument, ICollection, IEnumerable
	{
		private ArrayList dsmlResponse;

		private XmlDocument dsmlDocument;

		private XmlElement dsmlBatchResponse;

		private XmlNamespaceManager dsmlNS;

		public bool IsErrorResponse
		{
			get
			{
				foreach (DirectoryResponse item in dsmlResponse)
				{
					if (item is DsmlErrorResponse)
					{
						return true;
					}
				}
				return false;
			}
		}

		public bool IsOperationError
		{
			get
			{
				foreach (DirectoryResponse item in dsmlResponse)
				{
					if (!(item is DsmlErrorResponse))
					{
						ResultCode resultCode = item.ResultCode;
						if (resultCode != 0 && ResultCode.CompareTrue != resultCode && ResultCode.CompareFalse != resultCode && ResultCode.Referral != resultCode && ResultCode.ReferralV2 != resultCode)
						{
							return true;
						}
					}
				}
				return false;
			}
		}

		public string RequestId
		{
			get
			{
				XmlAttribute xmlAttribute = (XmlAttribute)dsmlBatchResponse.SelectSingleNode("@dsml:requestID", dsmlNS);
				if (xmlAttribute == null)
				{
					return ((XmlAttribute)dsmlBatchResponse.SelectSingleNode("@requestID", dsmlNS))?.Value;
				}
				return xmlAttribute.Value;
			}
		}

		internal string ResponseString
		{
			get
			{
				if (dsmlDocument != null)
				{
					return dsmlDocument.InnerXml;
				}
				return null;
			}
		}

		object ICollection.SyncRoot => dsmlResponse.SyncRoot;

		bool ICollection.IsSynchronized => dsmlResponse.IsSynchronized;

		int ICollection.Count => dsmlResponse.Count;

		protected object SyncRoot => dsmlResponse.SyncRoot;

		protected bool IsSynchronized => dsmlResponse.IsSynchronized;

		public int Count => dsmlResponse.Count;

		public DirectoryResponse this[int index] => (DirectoryResponse)dsmlResponse[index];

		private DsmlResponseDocument()
		{
			dsmlResponse = new ArrayList();
		}

		internal DsmlResponseDocument(HttpWebResponse resp, string xpathToResponse)
			: this()
		{
			Stream responseStream = resp.GetResponseStream();
			StreamReader streamReader = new StreamReader(responseStream);
			try
			{
				dsmlDocument = new XmlDocument();
				try
				{
					dsmlDocument.Load(streamReader);
				}
				catch (XmlException)
				{
					throw new DsmlInvalidDocumentException(Res.GetString("NotWellFormedResponse"));
				}
				dsmlNS = NamespaceUtils.GetDsmlNamespaceManager();
				dsmlBatchResponse = (XmlElement)dsmlDocument.SelectSingleNode(xpathToResponse, dsmlNS);
				if (dsmlBatchResponse == null)
				{
					throw new DsmlInvalidDocumentException(Res.GetString("NotWellFormedResponse"));
				}
				XmlNodeList childNodes = dsmlBatchResponse.ChildNodes;
				foreach (XmlNode item in childNodes)
				{
					if (item.NodeType == XmlNodeType.Element)
					{
						DirectoryResponse value = ConstructElement((XmlElement)item);
						dsmlResponse.Add(value);
					}
				}
			}
			finally
			{
				streamReader.Close();
			}
		}

		internal DsmlResponseDocument(StringBuilder responseString, string xpathToResponse)
			: this()
		{
			dsmlDocument = new XmlDocument();
			try
			{
				dsmlDocument.LoadXml(responseString.ToString());
			}
			catch (XmlException)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("NotWellFormedResponse"));
			}
			dsmlNS = NamespaceUtils.GetDsmlNamespaceManager();
			dsmlBatchResponse = (XmlElement)dsmlDocument.SelectSingleNode(xpathToResponse, dsmlNS);
			if (dsmlBatchResponse == null)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("NotWellFormedResponse"));
			}
			XmlNodeList childNodes = dsmlBatchResponse.ChildNodes;
			foreach (XmlNode item in childNodes)
			{
				if (item.NodeType == XmlNodeType.Element)
				{
					DirectoryResponse value = ConstructElement((XmlElement)item);
					dsmlResponse.Add(value);
				}
			}
		}

		private DsmlResponseDocument(string responseString)
			: this(new StringBuilder(responseString), "se:Envelope/se:Body/dsml:batchResponse")
		{
		}

		public override XmlDocument ToXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.LoadXml(dsmlBatchResponse.OuterXml);
			return xmlDocument;
		}

		void ICollection.CopyTo(Array value, int i)
		{
			dsmlResponse.CopyTo(value, i);
		}

		public IEnumerator GetEnumerator()
		{
			return dsmlResponse.GetEnumerator();
		}

		public void CopyTo(DirectoryResponse[] value, int i)
		{
			dsmlResponse.CopyTo(value, i);
		}

		private DirectoryResponse ConstructElement(XmlElement node)
		{
			DirectoryResponse directoryResponse = null;
			return node.LocalName switch
			{
				"errorResponse" => new DsmlErrorResponse(node), 
				"searchResponse" => new SearchResponse(node), 
				"modifyResponse" => new ModifyResponse(node), 
				"addResponse" => new AddResponse(node), 
				"delResponse" => new DeleteResponse(node), 
				"modDNResponse" => new ModifyDNResponse(node), 
				"compareResponse" => new CompareResponse(node), 
				"extendedResponse" => new ExtendedResponse(node), 
				"authResponse" => new DsmlAuthResponse(node), 
				_ => throw new DsmlInvalidDocumentException(Res.GetString("UnknownResponseElement")), 
			};
		}
	}
	public enum DsmlDocumentProcessing
	{
		Sequential,
		Parallel
	}
	public enum DsmlResponseOrder
	{
		Sequential,
		Unordered
	}
	public enum DsmlErrorProcessing
	{
		Resume,
		Exit
	}
	public enum ErrorResponseCategory
	{
		NotAttempted,
		CouldNotConnect,
		ConnectionClosed,
		MalformedRequest,
		GatewayInternalError,
		AuthenticationFailed,
		UnresolvableUri,
		Other
	}
	[Serializable]
	public class DsmlInvalidDocumentException : DirectoryException
	{
		public DsmlInvalidDocumentException()
			: base(Res.GetString("InvalidDocument"))
		{
		}

		public DsmlInvalidDocumentException(string message)
			: base(message)
		{
		}

		public DsmlInvalidDocumentException(string message, Exception inner)
			: base(message, inner)
		{
		}

		protected DsmlInvalidDocumentException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[Serializable]
	public class ErrorResponseException : DirectoryException, ISerializable
	{
		private DsmlErrorResponse errorResponse;

		public DsmlErrorResponse Response => errorResponse;

		protected ErrorResponseException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		public ErrorResponseException()
		{
		}

		public ErrorResponseException(string message)
			: base(message)
		{
		}

		public ErrorResponseException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public ErrorResponseException(DsmlErrorResponse response)
			: this(response, Res.GetString("ErrorResponse"), null)
		{
		}

		public ErrorResponseException(DsmlErrorResponse response, string message)
			: this(response, message, null)
		{
		}

		public ErrorResponseException(DsmlErrorResponse response, string message, Exception inner)
			: base(message, inner)
		{
			errorResponse = response;
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	internal class DSMLFilterWriter
	{
		protected void WriteValue(string valueElt, ADValue value, XmlWriter mXmlWriter, string strNamespace)
		{
			if (strNamespace != null)
			{
				mXmlWriter.WriteStartElement(valueElt, strNamespace);
			}
			else
			{
				mXmlWriter.WriteStartElement(valueElt);
			}
			if (value.IsBinary && value.BinaryVal != null)
			{
				mXmlWriter.WriteAttributeString("xsi", "type", "http://www.w3.org/2001/XMLSchema-instance", "xsd:base64Binary");
				mXmlWriter.WriteBase64(value.BinaryVal, 0, value.BinaryVal.Length);
			}
			else
			{
				mXmlWriter.WriteString(value.StringVal);
			}
			mXmlWriter.WriteEndElement();
		}

		protected void WriteAttrib(string attrName, ADAttribute attrib, XmlWriter mXmlWriter, string strNamespace)
		{
			if (strNamespace != null)
			{
				mXmlWriter.WriteStartElement(attrName, strNamespace);
			}
			else
			{
				mXmlWriter.WriteStartElement(attrName);
			}
			mXmlWriter.WriteAttributeString("name", attrib.Name);
			foreach (ADValue value in attrib.Values)
			{
				WriteValue("value", value, mXmlWriter, strNamespace);
			}
			mXmlWriter.WriteEndElement();
		}

		public void WriteFilter(ADFilter filter, bool filterTags, XmlWriter mXmlWriter, string strNamespace)
		{
			if (filterTags)
			{
				if (strNamespace != null)
				{
					mXmlWriter.WriteStartElement("filter", strNamespace);
				}
				else
				{
					mXmlWriter.WriteStartElement("filter");
				}
			}
			switch (filter.Type)
			{
			case ADFilter.FilterType.And:
				if (strNamespace != null)
				{
					mXmlWriter.WriteStartElement("and", strNamespace);
				}
				else
				{
					mXmlWriter.WriteStartElement("and");
				}
				foreach (object item in filter.Filter.And)
				{
					WriteFilter((ADFilter)item, filterTags: false, mXmlWriter, strNamespace);
				}
				mXmlWriter.WriteEndElement();
				break;
			case ADFilter.FilterType.Or:
				if (strNamespace != null)
				{
					mXmlWriter.WriteStartElement("or", strNamespace);
				}
				else
				{
					mXmlWriter.WriteStartElement("or");
				}
				foreach (object item2 in filter.Filter.Or)
				{
					WriteFilter((ADFilter)item2, filterTags: false, mXmlWriter, strNamespace);
				}
				mXmlWriter.WriteEndElement();
				break;
			case ADFilter.FilterType.Not:
				if (strNamespace != null)
				{
					mXmlWriter.WriteStartElement("not", strNamespace);
				}
				else
				{
					mXmlWriter.WriteStartElement("not");
				}
				WriteFilter(filter.Filter.Not, filterTags: false, mXmlWriter, strNamespace);
				mXmlWriter.WriteEndElement();
				break;
			case ADFilter.FilterType.EqualityMatch:
				WriteAttrib("equalityMatch", filter.Filter.EqualityMatch, mXmlWriter, strNamespace);
				break;
			case ADFilter.FilterType.Present:
				if (strNamespace != null)
				{
					mXmlWriter.WriteStartElement("present", strNamespace);
				}
				else
				{
					mXmlWriter.WriteStartElement("present");
				}
				mXmlWriter.WriteAttributeString("name", filter.Filter.Present);
				mXmlWriter.WriteEndElement();
				break;
			case ADFilter.FilterType.GreaterOrEqual:
				WriteAttrib("greaterOrEqual", filter.Filter.GreaterOrEqual, mXmlWriter, strNamespace);
				break;
			case ADFilter.FilterType.LessOrEqual:
				WriteAttrib("lessOrEqual", filter.Filter.LessOrEqual, mXmlWriter, strNamespace);
				break;
			case ADFilter.FilterType.ApproxMatch:
				WriteAttrib("approxMatch", filter.Filter.ApproxMatch, mXmlWriter, strNamespace);
				break;
			case ADFilter.FilterType.ExtensibleMatch:
			{
				ADExtenMatchFilter extensibleMatch = filter.Filter.ExtensibleMatch;
				if (strNamespace != null)
				{
					mXmlWriter.WriteStartElement("extensibleMatch", strNamespace);
				}
				else
				{
					mXmlWriter.WriteStartElement("extensibleMatch");
				}
				if (extensibleMatch.Name != null && extensibleMatch.Name.Length != 0)
				{
					mXmlWriter.WriteAttributeString("name", extensibleMatch.Name);
				}
				if (extensibleMatch.MatchingRule != null && extensibleMatch.MatchingRule.Length != 0)
				{
					mXmlWriter.WriteAttributeString("matchingRule", extensibleMatch.MatchingRule);
				}
				mXmlWriter.WriteAttributeString("dnAttributes", XmlConvert.ToString(extensibleMatch.DNAttributes));
				WriteValue("value", extensibleMatch.Value, mXmlWriter, strNamespace);
				mXmlWriter.WriteEndElement();
				break;
			}
			case ADFilter.FilterType.Substrings:
			{
				ADSubstringFilter substrings = filter.Filter.Substrings;
				if (strNamespace != null)
				{
					mXmlWriter.WriteStartElement("substrings", strNamespace);
				}
				else
				{
					mXmlWriter.WriteStartElement("substrings");
				}
				mXmlWriter.WriteAttributeString("name", substrings.Name);
				if (substrings.Initial != null)
				{
					WriteValue("initial", substrings.Initial, mXmlWriter, strNamespace);
				}
				if (substrings.Any != null)
				{
					foreach (object item3 in substrings.Any)
					{
						WriteValue("any", (ADValue)item3, mXmlWriter, strNamespace);
					}
				}
				if (substrings.Final != null)
				{
					WriteValue("final", substrings.Final, mXmlWriter, strNamespace);
				}
				mXmlWriter.WriteEndElement();
				break;
			}
			default:
				throw new ArgumentException(Res.GetString("InvalidFilterType", filter.Type));
			}
			if (filterTags)
			{
				mXmlWriter.WriteEndElement();
			}
		}
	}
	public abstract class DsmlSoapConnection : DirectoryConnection
	{
		internal XmlNode soapHeaders;

		public abstract string SessionId { get; }

		public XmlNode SoapRequestHeader
		{
			get
			{
				return soapHeaders;
			}
			set
			{
				soapHeaders = value;
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract void BeginSession();

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract void EndSession();
	}
	public class DsmlSoapHttpConnection : DsmlSoapConnection
	{
		private HttpWebRequest dsmlHttpConnection;

		private string dsmlSoapAction = "\"#batchRequest\"";

		private AuthType dsmlAuthType = AuthType.Negotiate;

		private string dsmlSessionID;

		private Hashtable httpConnectionTable;

		private string debugResponse;

		public override TimeSpan Timeout
		{
			get
			{
				return connectionTimeOut;
			}
			set
			{
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				if (value.TotalMilliseconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				connectionTimeOut = value;
			}
		}

		public string SoapActionHeader
		{
			get
			{
				return dsmlSoapAction;
			}
			set
			{
				dsmlSoapAction = value;
			}
		}

		public AuthType AuthType
		{
			get
			{
				return dsmlAuthType;
			}
			set
			{
				switch (value)
				{
				default:
					throw new InvalidEnumArgumentException("value", (int)value, typeof(AuthType));
				case AuthType.Sicily:
				case AuthType.Dpa:
				case AuthType.Msn:
				case AuthType.External:
				case AuthType.Kerberos:
					throw new ArgumentException(Res.GetString("WrongAuthType", value), "value");
				case AuthType.Anonymous:
				case AuthType.Basic:
				case AuthType.Negotiate:
				case AuthType.Ntlm:
				case AuthType.Digest:
					dsmlAuthType = value;
					break;
				}
			}
		}

		public override string SessionId => dsmlSessionID;

		private string ResponseString => debugResponse;

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DsmlSoapHttpConnection(Uri uri)
			: this(new DsmlDirectoryIdentifier(uri))
		{
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		[WebPermission(SecurityAction.Assert, Unrestricted = true)]
		public DsmlSoapHttpConnection(DsmlDirectoryIdentifier identifier)
		{
			if (identifier == null)
			{
				throw new ArgumentNullException("identifier");
			}
			directoryIdentifier = identifier;
			dsmlHttpConnection = (HttpWebRequest)WebRequest.Create(((DsmlDirectoryIdentifier)directoryIdentifier).ServerUri);
			Hashtable table = new Hashtable();
			httpConnectionTable = Hashtable.Synchronized(table);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
		public DsmlSoapHttpConnection(DsmlDirectoryIdentifier identifier, NetworkCredential credential)
			: this(identifier)
		{
			directoryCredential = ((credential != null) ? new NetworkCredential(credential.UserName, credential.Password, credential.Domain) : null);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DsmlSoapHttpConnection(DsmlDirectoryIdentifier identifier, NetworkCredential credential, AuthType authType)
			: this(identifier, credential)
		{
			AuthType = authType;
		}

		[NetworkInformationPermission(SecurityAction.Assert, Unrestricted = true)]
		[WebPermission(SecurityAction.Assert, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override void BeginSession()
		{
			if (dsmlSessionID != null)
			{
				throw new InvalidOperationException(Res.GetString("SessionInUse"));
			}
			try
			{
				PrepareHttpWebRequest(dsmlHttpConnection);
				StreamWriter webRequestStreamWriter = GetWebRequestStreamWriter();
				try
				{
					webRequestStreamWriter.Write("<se:Envelope xmlns:se=\"http://schemas.xmlsoap.org/soap/envelope/\">");
					webRequestStreamWriter.Write("<se:Header>");
					webRequestStreamWriter.Write("<ad:BeginSession xmlns:ad=\"urn:schema-microsoft-com:activedirectory:dsmlv2\" se:mustUnderstand=\"1\"/>");
					if (soapHeaders != null)
					{
						webRequestStreamWriter.Write(soapHeaders.OuterXml);
					}
					webRequestStreamWriter.Write("</se:Header>");
					webRequestStreamWriter.Write("<se:Body xmlns=\"urn:oasis:names:tc:DSML:2:0:core\">");
					webRequestStreamWriter.Write(new DsmlRequestDocument().ToXml().InnerXml);
					webRequestStreamWriter.Write("</se:Body>");
					webRequestStreamWriter.Write("</se:Envelope>");
					webRequestStreamWriter.Flush();
				}
				finally
				{
					webRequestStreamWriter.BaseStream.Close();
					webRequestStreamWriter.Close();
				}
				HttpWebResponse httpWebResponse = (HttpWebResponse)dsmlHttpConnection.GetResponse();
				try
				{
					dsmlSessionID = ExtractSessionID(httpWebResponse);
				}
				finally
				{
					httpWebResponse.Close();
				}
			}
			finally
			{
				dsmlHttpConnection = (HttpWebRequest)WebRequest.Create(((DsmlDirectoryIdentifier)directoryIdentifier).ServerUri);
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[NetworkInformationPermission(SecurityAction.Assert, Unrestricted = true)]
		[WebPermission(SecurityAction.Assert, Unrestricted = true)]
		public override void EndSession()
		{
			if (dsmlSessionID == null)
			{
				throw new InvalidOperationException(Res.GetString("NoCurrentSession"));
			}
			try
			{
				try
				{
					PrepareHttpWebRequest(dsmlHttpConnection);
					StreamWriter webRequestStreamWriter = GetWebRequestStreamWriter();
					try
					{
						webRequestStreamWriter.Write("<se:Envelope xmlns:se=\"http://schemas.xmlsoap.org/soap/envelope/\">");
						webRequestStreamWriter.Write("<se:Header>");
						webRequestStreamWriter.Write("<ad:EndSession xmlns:ad=\"urn:schema-microsoft-com:activedirectory:dsmlv2\" ad:SessionID=\"");
						webRequestStreamWriter.Write(dsmlSessionID);
						webRequestStreamWriter.Write("\" se:mustUnderstand=\"1\"/>");
						if (soapHeaders != null)
						{
							webRequestStreamWriter.Write(soapHeaders.OuterXml);
						}
						webRequestStreamWriter.Write("</se:Header>");
						webRequestStreamWriter.Write("<se:Body xmlns=\"urn:oasis:names:tc:DSML:2:0:core\">");
						webRequestStreamWriter.Write(new DsmlRequestDocument().ToXml().InnerXml);
						webRequestStreamWriter.Write("</se:Body>");
						webRequestStreamWriter.Write("</se:Envelope>");
						webRequestStreamWriter.Flush();
					}
					finally
					{
						webRequestStreamWriter.BaseStream.Close();
						webRequestStreamWriter.Close();
					}
					HttpWebResponse httpWebResponse = (HttpWebResponse)dsmlHttpConnection.GetResponse();
					httpWebResponse.Close();
				}
				catch (WebException ex)
				{
					if (ex.Status != WebExceptionStatus.ConnectFailure && ex.Status != WebExceptionStatus.NameResolutionFailure && ex.Status != WebExceptionStatus.ProxyNameResolutionFailure && ex.Status != WebExceptionStatus.SendFailure && ex.Status != WebExceptionStatus.TrustFailure)
					{
						dsmlSessionID = null;
					}
					throw;
				}
				dsmlSessionID = null;
			}
			finally
			{
				dsmlHttpConnection = (HttpWebRequest)WebRequest.Create(((DsmlDirectoryIdentifier)directoryIdentifier).ServerUri);
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override DirectoryResponse SendRequest(DirectoryRequest request)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}
			DsmlRequestDocument dsmlRequestDocument = new DsmlRequestDocument();
			dsmlRequestDocument.Add(request);
			DsmlResponseDocument dsmlResponseDocument = SendRequestHelper(dsmlRequestDocument.ToXml().InnerXml);
			if (dsmlResponseDocument.Count == 0)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("MissingResponse"));
			}
			DirectoryResponse directoryResponse = dsmlResponseDocument[0];
			if (directoryResponse is DsmlErrorResponse)
			{
				ErrorResponseException ex = new ErrorResponseException((DsmlErrorResponse)directoryResponse);
				throw ex;
			}
			ResultCode resultCode = directoryResponse.ResultCode;
			if (resultCode == ResultCode.Success || resultCode == ResultCode.CompareFalse || resultCode == ResultCode.CompareTrue || resultCode == ResultCode.Referral || resultCode == ResultCode.ReferralV2)
			{
				return directoryResponse;
			}
			throw new DirectoryOperationException(directoryResponse, OperationErrorMappings.MapResultCode((int)resultCode));
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public DsmlResponseDocument SendRequest(DsmlRequestDocument request)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}
			DsmlResponseDocument dsmlResponseDocument = SendRequestHelper(request.ToXml().InnerXml);
			if (request.Count > 0 && dsmlResponseDocument.Count == 0)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("MissingResponse"));
			}
			return dsmlResponseDocument;
		}

		[NetworkInformationPermission(SecurityAction.Assert, Unrestricted = true)]
		[WebPermission(SecurityAction.Assert, Unrestricted = true)]
		private DsmlResponseDocument SendRequestHelper(string reqstring)
		{
			StringBuilder buffer = new StringBuilder(1024);
			try
			{
				PrepareHttpWebRequest(dsmlHttpConnection);
				StreamWriter webRequestStreamWriter = GetWebRequestStreamWriter();
				try
				{
					BeginSOAPRequest(ref buffer);
					buffer.Append(reqstring);
					EndSOAPRequest(ref buffer);
					webRequestStreamWriter.Write(buffer.ToString());
					webRequestStreamWriter.Flush();
				}
				finally
				{
					webRequestStreamWriter.BaseStream.Close();
					webRequestStreamWriter.Close();
				}
				HttpWebResponse httpWebResponse = (HttpWebResponse)dsmlHttpConnection.GetResponse();
				DsmlResponseDocument dsmlResponseDocument;
				try
				{
					dsmlResponseDocument = new DsmlResponseDocument(httpWebResponse, "se:Envelope/se:Body/dsml:batchResponse");
					debugResponse = dsmlResponseDocument.ResponseString;
				}
				finally
				{
					httpWebResponse.Close();
				}
				return dsmlResponseDocument;
			}
			finally
			{
				dsmlHttpConnection = (HttpWebRequest)WebRequest.Create(((DsmlDirectoryIdentifier)directoryIdentifier).ServerUri);
			}
		}

		[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
		private void PrepareHttpWebRequest(HttpWebRequest dsmlConnection)
		{
			if (directoryCredential == null)
			{
				dsmlConnection.Credentials = CredentialCache.DefaultCredentials;
			}
			else
			{
				string authType = "negotiate";
				if (dsmlAuthType == AuthType.Ntlm)
				{
					authType = "NTLM";
				}
				else if (dsmlAuthType == AuthType.Basic)
				{
					authType = "basic";
				}
				else if (dsmlAuthType == AuthType.Anonymous)
				{
					authType = "anonymous";
				}
				else if (dsmlAuthType == AuthType.Digest)
				{
					authType = "digest";
				}
				CredentialCache credentialCache = new CredentialCache();
				credentialCache.Add(dsmlConnection.RequestUri, authType, directoryCredential);
				dsmlConnection.Credentials = credentialCache;
			}
			foreach (X509Certificate clientCertificate in base.ClientCertificates)
			{
				dsmlConnection.ClientCertificates.Add(clientCertificate);
			}
			if (connectionTimeOut.Ticks != 0)
			{
				dsmlConnection.Timeout = (int)(connectionTimeOut.Ticks / 10000);
			}
			if (dsmlSoapAction != null)
			{
				WebHeaderCollection headers = dsmlConnection.Headers;
				headers.Set("SOAPAction", dsmlSoapAction);
			}
			dsmlConnection.Method = "POST";
		}

		private StreamWriter GetWebRequestStreamWriter()
		{
			Stream requestStream = dsmlHttpConnection.GetRequestStream();
			return new StreamWriter(requestStream);
		}

		private void BeginSOAPRequest(ref StringBuilder buffer)
		{
			buffer.Append("<se:Envelope xmlns:se=\"http://schemas.xmlsoap.org/soap/envelope/\">");
			if (dsmlSessionID != null || soapHeaders != null)
			{
				buffer.Append("<se:Header>");
				if (dsmlSessionID != null)
				{
					buffer.Append("<ad:Session xmlns:ad=\"urn:schema-microsoft-com:activedirectory:dsmlv2\" ad:SessionID=\"");
					buffer.Append(dsmlSessionID);
					buffer.Append("\" se:mustUnderstand=\"1\"/>");
				}
				if (soapHeaders != null)
				{
					buffer.Append(soapHeaders.OuterXml);
				}
				buffer.Append("</se:Header>");
			}
			buffer.Append("<se:Body xmlns=\"urn:oasis:names:tc:DSML:2:0:core\">");
		}

		private void EndSOAPRequest(ref StringBuilder buffer)
		{
			buffer.Append("</se:Body>");
			buffer.Append("</se:Envelope>");
		}

		private string ExtractSessionID(HttpWebResponse resp)
		{
			Stream responseStream = resp.GetResponseStream();
			StreamReader streamReader = new StreamReader(responseStream);
			try
			{
				XmlDocument xmlDocument = new XmlDocument();
				try
				{
					xmlDocument.Load(streamReader);
				}
				catch (XmlException)
				{
					throw new DsmlInvalidDocumentException();
				}
				XmlNamespaceManager dsmlNamespaceManager = NamespaceUtils.GetDsmlNamespaceManager();
				XmlAttribute xmlAttribute = (XmlAttribute)xmlDocument.SelectSingleNode("se:Envelope/se:Header/ad:Session/@ad:SessionID", dsmlNamespaceManager);
				if (xmlAttribute == null)
				{
					xmlAttribute = (XmlAttribute)xmlDocument.SelectSingleNode("se:Envelope/se:Header/ad:Session/@SessionID", dsmlNamespaceManager);
					if (xmlAttribute == null)
					{
						throw new DsmlInvalidDocumentException(Res.GetString("NoSessionIDReturned"));
					}
				}
				return xmlAttribute.Value;
			}
			finally
			{
				streamReader.Close();
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[NetworkInformationPermission(SecurityAction.Assert, Unrestricted = true)]
		[WebPermission(SecurityAction.Assert, Unrestricted = true)]
		public IAsyncResult BeginSendRequest(DsmlRequestDocument request, AsyncCallback callback, object state)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}
			HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(((DsmlDirectoryIdentifier)directoryIdentifier).ServerUri);
			PrepareHttpWebRequest(httpWebRequest);
			StringBuilder buffer = new StringBuilder(1024);
			BeginSOAPRequest(ref buffer);
			buffer.Append(request.ToXml().InnerXml);
			EndSOAPRequest(ref buffer);
			RequestState requestState = new RequestState();
			requestState.request = httpWebRequest;
			requestState.requestString = buffer.ToString();
			DsmlAsyncResult dsmlAsyncResult = new DsmlAsyncResult(callback, state);
			dsmlAsyncResult.resultObject = requestState;
			if (request.Count > 0)
			{
				dsmlAsyncResult.hasValidRequest = true;
			}
			requestState.dsmlAsync = dsmlAsyncResult;
			httpConnectionTable.Add(dsmlAsyncResult, httpWebRequest);
			httpWebRequest.BeginGetRequestStream(RequestStreamCallback, requestState);
			return dsmlAsyncResult;
		}

		private static void RequestStreamCallback(IAsyncResult asyncResult)
		{
			RequestState requestState = (RequestState)asyncResult.AsyncState;
			HttpWebRequest request = requestState.request;
			try
			{
				requestState.requestStream = request.EndGetRequestStream(asyncResult);
				byte[] bytes = requestState.encoder.GetBytes(requestState.requestString);
				requestState.requestStream.BeginWrite(bytes, 0, bytes.Length, WriteCallback, requestState);
			}
			catch (Exception exception)
			{
				if (requestState.requestStream != null)
				{
					requestState.requestStream.Close();
				}
				requestState.exception = exception;
				WakeupRoutine(requestState);
			}
			catch
			{
				if (requestState.requestStream != null)
				{
					requestState.requestStream.Close();
				}
				requestState.exception = new Exception(Res.GetString("NonCLSException"));
				WakeupRoutine(requestState);
			}
		}

		private static void WriteCallback(IAsyncResult asyncResult)
		{
			RequestState requestState = (RequestState)asyncResult.AsyncState;
			try
			{
				requestState.requestStream.EndWrite(asyncResult);
				requestState.request.BeginGetResponse(ResponseCallback, requestState);
			}
			catch (Exception exception)
			{
				Exception ex = (requestState.exception = exception);
				WakeupRoutine(requestState);
			}
			catch
			{
				requestState.exception = new Exception(Res.GetString("NonCLSException"));
				WakeupRoutine(requestState);
			}
			finally
			{
				requestState.requestStream.Close();
			}
		}

		private static void ResponseCallback(IAsyncResult asyncResult)
		{
			RequestState requestState = (RequestState)asyncResult.AsyncState;
			WebResponse webResponse = null;
			try
			{
				webResponse = requestState.request.EndGetResponse(asyncResult);
				requestState.responseStream = webResponse.GetResponseStream();
				requestState.responseStream.BeginRead(requestState.bufferRead, 0, 1024, ReadCallback, requestState);
			}
			catch (Exception exception)
			{
				if (requestState.responseStream != null)
				{
					requestState.responseStream.Close();
				}
				requestState.exception = exception;
				WakeupRoutine(requestState);
			}
			catch
			{
				if (requestState.responseStream != null)
				{
					requestState.responseStream.Close();
				}
				requestState.exception = new Exception(Res.GetString("NonCLSException"));
				WakeupRoutine(requestState);
			}
		}

		private static void ReadCallback(IAsyncResult asyncResult)
		{
			RequestState requestState = (RequestState)asyncResult.AsyncState;
			int num = 0;
			string text = null;
			try
			{
				num = requestState.responseStream.EndRead(asyncResult);
				if (num > 0)
				{
					text = requestState.encoder.GetString(requestState.bufferRead);
					int count = Math.Min(text.Length, num);
					requestState.responseString.Append(text, 0, count);
					requestState.responseStream.BeginRead(requestState.bufferRead, 0, 1024, ReadCallback, requestState);
				}
				else
				{
					requestState.responseStream.Close();
					WakeupRoutine(requestState);
				}
			}
			catch (Exception exception)
			{
				requestState.responseStream.Close();
				requestState.exception = exception;
				WakeupRoutine(requestState);
			}
			catch
			{
				requestState.responseStream.Close();
				requestState.exception = new Exception(Res.GetString("NonCLSException"));
				WakeupRoutine(requestState);
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public void Abort(IAsyncResult asyncResult)
		{
			if (asyncResult == null)
			{
				throw new ArgumentNullException("asyncResult");
			}
			if (!(asyncResult is DsmlAsyncResult))
			{
				throw new ArgumentException(Res.GetString("NotReturnedAsyncResult", "asyncResult"));
			}
			if (!httpConnectionTable.Contains(asyncResult))
			{
				throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
			}
			HttpWebRequest httpWebRequest = (HttpWebRequest)httpConnectionTable[asyncResult];
			httpConnectionTable.Remove(asyncResult);
			httpWebRequest.Abort();
			DsmlAsyncResult dsmlAsyncResult = (DsmlAsyncResult)asyncResult;
			dsmlAsyncResult.resultObject.abortCalled = true;
		}

		public DsmlResponseDocument EndSendRequest(IAsyncResult asyncResult)
		{
			if (asyncResult == null)
			{
				throw new ArgumentNullException("asyncResult");
			}
			if (!(asyncResult is DsmlAsyncResult))
			{
				throw new ArgumentException(Res.GetString("NotReturnedAsyncResult", "asyncResult"));
			}
			if (!httpConnectionTable.Contains(asyncResult))
			{
				throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
			}
			httpConnectionTable.Remove(asyncResult);
			DsmlAsyncResult dsmlAsyncResult = (DsmlAsyncResult)asyncResult;
			asyncResult.AsyncWaitHandle.WaitOne();
			if (dsmlAsyncResult.resultObject.exception != null)
			{
				throw dsmlAsyncResult.resultObject.exception;
			}
			DsmlResponseDocument dsmlResponseDocument = new DsmlResponseDocument(dsmlAsyncResult.resultObject.responseString, "se:Envelope/se:Body/dsml:batchResponse");
			debugResponse = dsmlResponseDocument.ResponseString;
			if (dsmlAsyncResult.hasValidRequest && dsmlResponseDocument.Count == 0)
			{
				throw new DsmlInvalidDocumentException(Res.GetString("MissingResponse"));
			}
			return dsmlResponseDocument;
		}

		private static void WakeupRoutine(RequestState rs)
		{
			rs.dsmlAsync.manualResetEvent.Set();
			rs.dsmlAsync.completed = true;
			if (rs.dsmlAsync.callback != null && !rs.abortCalled)
			{
				rs.dsmlAsync.callback(rs.dsmlAsync);
			}
		}
	}
	internal class FilterParser
	{
		private const string mAttrRE = "(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*";

		private const string mValueRE = "(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?";

		private const string mExtenAttrRE = "(?<extenattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*";

		private const string mExtenValueRE = "(?<extenvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*";

		private const string mDNAttrRE = "(?<dnattr>\\:dn){0,1}\\s*";

		private const string mMatchRuleOptionalRE = "(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+))){0,1}\\s*";

		private const string mMatchRuleRE = "(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+)))\\s*";

		private const string mExtenRE = "(?<extensible>(((?<extenattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+))){0,1}\\s*)|((?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+)))\\s*))\\:\\=\\s*(?<extenvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*";

		private const string mSubstrAttrRE = "(?<substrattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*";

		private const string mInitialRE = "\\s*(?<initialvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*";

		private const string mFinalRE = "\\s*(?<finalvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*";

		private const string mAnyRE = "(\\*\\s*((?<anyvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\*\\s*)*)";

		private const string mSubstrRE = "(?<substr>(?<substrattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*\\=\\s*\\s*(?<initialvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*(\\*\\s*((?<anyvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\*\\s*)*)\\s*(?<finalvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*)\\s*";

		private const string mSimpleValueRE = "(?<simplevalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*";

		private const string mSimpleAttrRE = "(?<simpleattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*";

		private const string mFiltertypeRE = "(?<filtertype>\\=|\\~\\=|\\>\\=|\\<\\=)\\s*";

		private const string mSimpleRE = "(?<simple>(?<simpleattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<filtertype>\\=|\\~\\=|\\>\\=|\\<\\=)\\s*(?<simplevalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*";

		private const string mPresentRE = "(?<present>(?<presentattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\=\\*)\\s*";

		private const string mItemRE = "(?<item>(?<simple>(?<simpleattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<filtertype>\\=|\\~\\=|\\>\\=|\\<\\=)\\s*(?<simplevalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*|(?<present>(?<presentattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\=\\*)\\s*|(?<substr>(?<substrattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*\\=\\s*\\s*(?<initialvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*(\\*\\s*((?<anyvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\*\\s*)*)\\s*(?<finalvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*)\\s*|(?<extensible>(((?<extenattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+))){0,1}\\s*)|((?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+)))\\s*))\\:\\=\\s*(?<extenvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*)\\s*";

		private const string mFiltercompRE = "(?<filtercomp>\\!|\\&|\\|)\\s*";

		private const string mFilterlistRE = "(?<filterlist>.+)\\s*";

		private const string mFilterRE = "^\\s*\\(\\s*(((?<filtercomp>\\!|\\&|\\|)\\s*(?<filterlist>.+)\\s*)|((?<item>(?<simple>(?<simpleattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<filtertype>\\=|\\~\\=|\\>\\=|\\<\\=)\\s*(?<simplevalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*|(?<present>(?<presentattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\=\\*)\\s*|(?<substr>(?<substrattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*\\=\\s*\\s*(?<initialvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*(\\*\\s*((?<anyvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\*\\s*)*)\\s*(?<finalvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*)\\s*|(?<extensible>(((?<extenattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+))){0,1}\\s*)|((?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+)))\\s*))\\:\\=\\s*(?<extenvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*)\\s*))\\)\\s*$";

		private static Regex mFilter = new Regex("^\\s*\\(\\s*(((?<filtercomp>\\!|\\&|\\|)\\s*(?<filterlist>.+)\\s*)|((?<item>(?<simple>(?<simpleattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<filtertype>\\=|\\~\\=|\\>\\=|\\<\\=)\\s*(?<simplevalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*|(?<present>(?<presentattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\=\\*)\\s*|(?<substr>(?<substrattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*\\=\\s*\\s*(?<initialvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*(\\*\\s*((?<anyvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\*\\s*)*)\\s*(?<finalvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?){0,1}\\s*)\\s*|(?<extensible>(((?<extenattr>(([0-2](\\.[0-9]+)+)|([a-zA-Z]+([a-zA-Z0-9]|[-])*))(;([a-zA-Z0-9]|[-])+)*)\\s*(?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+))){0,1}\\s*)|((?<dnattr>\\:dn){0,1}\\s*(\\:(?<matchrule>([a-zA-Z][a-zA-Z0-9]*)|([0-9]+(\\.[0-9]+)+)))\\s*))\\:\\=\\s*(?<extenvalue>(([^\\*\\(\\)\\\\])|(\\\\[a-fA-F0-9][a-fA-F0-9]))+?)\\s*)\\s*)\\s*))\\)\\s*$", RegexOptions.ExplicitCapture);

		public static ADFilter ParseFilterString(string filter)
		{
			Match match = mFilter.Match(filter);
			if (!match.Success)
			{
				return null;
			}
			ADFilter aDFilter = new ADFilter();
			if (match.Groups["item"].ToString().Length != 0)
			{
				if (match.Groups["present"].ToString().Length != 0)
				{
					aDFilter.Type = ADFilter.FilterType.Present;
					aDFilter.Filter.Present = match.Groups["presentattr"].ToString();
				}
				else if (match.Groups["simple"].ToString().Length != 0)
				{
					ADAttribute aDAttribute = new ADAttribute();
					if (match.Groups["simplevalue"].ToString().Length != 0)
					{
						ADValue value = StringFilterValueToADValue(match.Groups["simplevalue"].ToString());
						aDAttribute.Values.Add(value);
					}
					aDAttribute.Name = match.Groups["simpleattr"].ToString();
					switch (match.Groups["filtertype"].ToString())
					{
					case "=":
						aDFilter.Type = ADFilter.FilterType.EqualityMatch;
						aDFilter.Filter.EqualityMatch = aDAttribute;
						break;
					case "~=":
						aDFilter.Type = ADFilter.FilterType.ApproxMatch;
						aDFilter.Filter.ApproxMatch = aDAttribute;
						break;
					case "<=":
						aDFilter.Type = ADFilter.FilterType.LessOrEqual;
						aDFilter.Filter.LessOrEqual = aDAttribute;
						break;
					case ">=":
						aDFilter.Type = ADFilter.FilterType.GreaterOrEqual;
						aDFilter.Filter.GreaterOrEqual = aDAttribute;
						break;
					default:
						return null;
					}
				}
				else if (match.Groups["substr"].ToString().Length != 0)
				{
					aDFilter.Type = ADFilter.FilterType.Substrings;
					ADSubstringFilter aDSubstringFilter = new ADSubstringFilter();
					aDSubstringFilter.Initial = StringFilterValueToADValue(match.Groups["initialvalue"].ToString());
					aDSubstringFilter.Final = StringFilterValueToADValue(match.Groups["finalvalue"].ToString());
					if (match.Groups["anyvalue"].ToString().Length != 0)
					{
						foreach (Capture capture in match.Groups["anyvalue"].Captures)
						{
							aDSubstringFilter.Any.Add(StringFilterValueToADValue(capture.ToString()));
						}
					}
					aDSubstringFilter.Name = match.Groups["substrattr"].ToString();
					aDFilter.Filter.Substrings = aDSubstringFilter;
				}
				else
				{
					if (match.Groups["extensible"].ToString().Length == 0)
					{
						return null;
					}
					aDFilter.Type = ADFilter.FilterType.ExtensibleMatch;
					ADExtenMatchFilter aDExtenMatchFilter = new ADExtenMatchFilter();
					aDExtenMatchFilter.Value = StringFilterValueToADValue(match.Groups["extenvalue"].ToString());
					aDExtenMatchFilter.DNAttributes = match.Groups["dnattr"].ToString().Length != 0;
					aDExtenMatchFilter.Name = match.Groups["extenattr"].ToString();
					aDExtenMatchFilter.MatchingRule = match.Groups["matchrule"].ToString();
					aDFilter.Filter.ExtensibleMatch = aDExtenMatchFilter;
				}
			}
			else
			{
				ArrayList arrayList = new ArrayList();
				string text = match.Groups["filterlist"].ToString().Trim();
				while (text.Length > 0)
				{
					if (text[0] != '(')
					{
						return null;
					}
					int i = 1;
					int num = 1;
					bool flag = false;
					for (; i < text.Length; i++)
					{
						if (flag)
						{
							break;
						}
						if (text[i] == '(')
						{
							num++;
						}
						if (text[i] == ')')
						{
							if (num < 1)
							{
								return null;
							}
							if (num == 1)
							{
								flag = true;
							}
							else
							{
								num--;
							}
						}
					}
					if (!flag)
					{
						return null;
					}
					arrayList.Add(text.Substring(0, i));
					text = text.Substring(i).TrimStart();
				}
				ADFilter aDFilter2 = null;
				switch (match.Groups["filtercomp"].ToString())
				{
				case "|":
					aDFilter.Type = ADFilter.FilterType.Or;
					aDFilter.Filter.Or = new ArrayList();
					foreach (string item in arrayList)
					{
						aDFilter2 = ParseFilterString(item);
						if (aDFilter2 == null)
						{
							return null;
						}
						aDFilter.Filter.Or.Add(aDFilter2);
					}
					if (aDFilter.Filter.Or.Count < 1)
					{
						return null;
					}
					break;
				case "&":
					aDFilter.Type = ADFilter.FilterType.And;
					aDFilter.Filter.And = new ArrayList();
					foreach (string item2 in arrayList)
					{
						aDFilter2 = ParseFilterString(item2);
						if (aDFilter2 == null)
						{
							return null;
						}
						aDFilter.Filter.And.Add(aDFilter2);
					}
					if (aDFilter.Filter.And.Count < 1)
					{
						return null;
					}
					break;
				case "!":
					aDFilter.Type = ADFilter.FilterType.Not;
					aDFilter2 = ParseFilterString((string)arrayList[0]);
					if (arrayList.Count > 1 || aDFilter2 == null)
					{
						return null;
					}
					aDFilter.Filter.Not = aDFilter2;
					break;
				default:
					return null;
				}
			}
			return aDFilter;
		}

		protected static ADValue StringFilterValueToADValue(string strVal)
		{
			if (strVal == null || strVal.Length == 0)
			{
				return null;
			}
			ADValue aDValue = new ADValue();
			string[] array = strVal.Split('\\');
			if (array.Length == 1)
			{
				aDValue.IsBinary = false;
				aDValue.StringVal = strVal;
				aDValue.BinaryVal = null;
				return aDValue;
			}
			ArrayList arrayList = new ArrayList(array.Length);
			UTF8Encoding uTF8Encoding = new UTF8Encoding();
			aDValue.IsBinary = true;
			aDValue.StringVal = null;
			if (array[0].Length != 0)
			{
				arrayList.Add(uTF8Encoding.GetBytes(array[0]));
			}
			for (int i = 1; i < array.Length; i++)
			{
				string s = array[i].Substring(0, 2);
				arrayList.Add(new byte[1] { byte.Parse(s, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture) });
				if (array[i].Length > 2)
				{
					arrayList.Add(uTF8Encoding.GetBytes(array[i].Substring(2)));
				}
			}
			int num = 0;
			foreach (byte[] item in arrayList)
			{
				num += item.Length;
			}
			aDValue.BinaryVal = new byte[num];
			int num2 = 0;
			foreach (byte[] item2 in arrayList)
			{
				item2.CopyTo(aDValue.BinaryVal, num2);
				num2 += item2.Length;
			}
			return aDValue;
		}
	}
	internal class NamespaceUtils
	{
		private static XmlNamespaceManager xmlNamespace;

		private NamespaceUtils()
		{
		}

		static NamespaceUtils()
		{
			xmlNamespace = new XmlNamespaceManager(new NameTable());
			xmlNamespace.AddNamespace("se", "http://schemas.xmlsoap.org/soap/envelope/");
			xmlNamespace.AddNamespace("dsml", "urn:oasis:names:tc:DSML:2:0:core");
			xmlNamespace.AddNamespace("ad", "urn:schema-microsoft-com:activedirectory:dsmlv2");
			xmlNamespace.AddNamespace("xsd", "http://www.w3.org/2001/XMLSchema");
			xmlNamespace.AddNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		}

		public static XmlNamespaceManager GetDsmlNamespaceManager()
		{
			return xmlNamespace;
		}
	}
	internal class Utility
	{
		private static bool platformSupported;

		private static bool isWin2kOS;

		private static bool isWin2k3Above;

		internal static bool IsWin2kOS => isWin2kOS;

		internal static bool IsWin2k3AboveOS => isWin2k3Above;

		static Utility()
		{
			OperatingSystem oSVersion = Environment.OSVersion;
			if (oSVersion.Platform == PlatformID.Win32NT && oSVersion.Version.Major >= 5)
			{
				platformSupported = true;
				if (oSVersion.Version.Major == 5 && oSVersion.Version.Minor == 0)
				{
					isWin2kOS = true;
				}
				if (oSVersion.Version.Major > 5 || oSVersion.Version.Minor >= 2)
				{
					isWin2k3Above = true;
				}
			}
		}

		internal static void CheckOSVersion()
		{
			if (!platformSupported)
			{
				throw new PlatformNotSupportedException(Res.GetString("SupportedPlatforms"));
			}
		}

		internal static bool IsLdapError(LdapError error)
		{
			switch (error)
			{
			case LdapError.IsLeaf:
			case LdapError.InvalidCredentials:
			case LdapError.SendTimeOut:
				return true;
			case LdapError.ServerDown:
			case LdapError.LocalError:
			case LdapError.EncodingError:
			case LdapError.DecodingError:
			case LdapError.TimeOut:
			case LdapError.AuthUnknown:
			case LdapError.FilterError:
			case LdapError.UserCancelled:
			case LdapError.ParameterError:
			case LdapError.NoMemory:
			case LdapError.ConnectError:
			case LdapError.NotSupported:
			case LdapError.ControlNotFound:
			case LdapError.NoResultsReturned:
			case LdapError.MoreResults:
			case LdapError.ClientLoop:
			case LdapError.ReferralLimitExceeded:
				return true;
			default:
				return false;
			}
		}

		internal static bool IsResultCode(ResultCode code)
		{
			if (code >= ResultCode.Success && code <= ResultCode.SaslBindInProgress)
			{
				return true;
			}
			if (code >= ResultCode.NoSuchAttribute && code <= ResultCode.InvalidAttributeSyntax)
			{
				return true;
			}
			if (code >= ResultCode.NoSuchObject && code <= ResultCode.InvalidDNSyntax)
			{
				return true;
			}
			if (code >= ResultCode.InsufficientAccessRights && code <= ResultCode.LoopDetect)
			{
				return true;
			}
			if (code >= ResultCode.NamingViolation && code <= ResultCode.AffectsMultipleDsas)
			{
				return true;
			}
			if (code == ResultCode.AliasDereferencingProblem || code == ResultCode.InappropriateAuthentication || code == ResultCode.SortControlMissing || code == ResultCode.OffsetRangeError || code == ResultCode.VirtualListViewError || code == ResultCode.Other)
			{
				return true;
			}
			return false;
		}

		internal static IntPtr AllocHGlobalIntPtrArray(int size)
		{
			IntPtr intPtr = (IntPtr)0;
			checked
			{
				intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)) * size);
				for (int i = 0; i < size; i++)
				{
					IntPtr ptr = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * i);
					Marshal.WriteIntPtr(ptr, IntPtr.Zero);
				}
				return intPtr;
			}
		}
	}
	internal class LdapAsyncResult : IAsyncResult
	{
		internal sealed class LdapAsyncWaitHandle : WaitHandle
		{
			public LdapAsyncWaitHandle(SafeWaitHandle handle)
			{
				base.SafeWaitHandle = handle;
			}

			~LdapAsyncWaitHandle()
			{
				base.SafeWaitHandle = null;
			}
		}

		private LdapAsyncWaitHandle asyncWaitHandle;

		internal AsyncCallback callback;

		internal bool completed;

		private bool completedSynchronously;

		internal ManualResetEvent manualResetEvent;

		private object stateObject;

		internal LdapRequestState resultObject;

		internal bool partialResults;

		object IAsyncResult.AsyncState => stateObject;

		WaitHandle IAsyncResult.AsyncWaitHandle
		{
			get
			{
				if (asyncWaitHandle == null)
				{
					asyncWaitHandle = new LdapAsyncWaitHandle(manualResetEvent.SafeWaitHandle);
				}
				return asyncWaitHandle;
			}
		}

		bool IAsyncResult.CompletedSynchronously => completedSynchronously;

		bool IAsyncResult.IsCompleted => completed;

		public LdapAsyncResult(AsyncCallback callbackRoutine, object state, bool partialResults)
		{
			stateObject = state;
			callback = callbackRoutine;
			manualResetEvent = new ManualResetEvent(initialState: false);
			this.partialResults = partialResults;
		}

		public override int GetHashCode()
		{
			return manualResetEvent.GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (!(o is LdapAsyncResult) || o == null)
			{
				return false;
			}
			return this == (LdapAsyncResult)o;
		}
	}
	internal class LdapRequestState
	{
		internal DirectoryResponse response;

		internal LdapAsyncResult ldapAsync;

		internal Exception exception;

		internal bool abortCalled;
	}
	internal enum ResultsStatus
	{
		PartialResult,
		CompleteResult,
		Done
	}
	internal class LdapPartialAsyncResult : LdapAsyncResult
	{
		internal LdapConnection con;

		internal int messageID = -1;

		internal bool partialCallback;

		internal ResultsStatus resultStatus;

		internal TimeSpan requestTimeout;

		internal SearchResponse response;

		internal Exception exception;

		internal DateTime startTime;

		public LdapPartialAsyncResult(int messageID, AsyncCallback callbackRoutine, object state, bool partialResults, LdapConnection con, bool partialCallback, TimeSpan requestTimeout)
			: base(callbackRoutine, state, partialResults)
		{
			this.messageID = messageID;
			this.con = con;
			base.partialResults = true;
			this.partialCallback = partialCallback;
			this.requestTimeout = requestTimeout;
			startTime = DateTime.Now;
		}
	}
	internal delegate DirectoryResponse GetLdapResponseCallback(int messageId, LdapOperation operation, ResultAll resultType, TimeSpan requestTimeout, bool exceptionOnTimeOut);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal delegate bool QUERYCLIENTCERT(IntPtr Connection, IntPtr trusted_CAs, ref IntPtr certificateHandle);
	public class LdapConnection : DirectoryConnection, IDisposable
	{
		internal enum LdapResult
		{
			LDAP_RES_SEARCH_RESULT = 101,
			LDAP_RES_SEARCH_ENTRY = 100,
			LDAP_RES_MODIFY = 103,
			LDAP_RES_ADD = 105,
			LDAP_RES_DELETE = 107,
			LDAP_RES_MODRDN = 109,
			LDAP_RES_COMPARE = 111,
			LDAP_RES_REFERRAL = 115,
			LDAP_RES_EXTENDED = 120
		}

		private const int LDAP_MOD_BVALUES = 128;

		private AuthType connectionAuthType = AuthType.Negotiate;

		private LdapSessionOptions options;

		internal IntPtr ldapHandle = (IntPtr)0;

		internal bool disposed;

		private bool bounded;

		private bool needRebind;

		internal static Hashtable handleTable;

		internal static object objectLock;

		private GetLdapResponseCallback fd;

		private static Hashtable asyncResultTable;

		private static LdapPartialResultsProcessor partialResultsProcessor;

		private static ManualResetEvent waitHandle;

		private static PartialResultsRetriever retriever;

		private bool setFQDNDone;

		internal bool automaticBind = true;

		internal bool needDispose = true;

		private bool connected;

		internal QUERYCLIENTCERT clientCertificateRoutine;

		public override TimeSpan Timeout
		{
			get
			{
				return connectionTimeOut;
			}
			set
			{
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				if (value.TotalSeconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				connectionTimeOut = value;
			}
		}

		public AuthType AuthType
		{
			get
			{
				return connectionAuthType;
			}
			set
			{
				if (value < AuthType.Anonymous || value > AuthType.Kerberos)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(AuthType));
				}
				if (bounded && value != connectionAuthType)
				{
					needRebind = true;
				}
				connectionAuthType = value;
			}
		}

		public LdapSessionOptions SessionOptions => options;

		public override NetworkCredential Credential
		{
			[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
			[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			set
			{
				if (bounded && !SameCredential(directoryCredential, value))
				{
					needRebind = true;
				}
				directoryCredential = ((value != null) ? new NetworkCredential(value.UserName, value.Password, value.Domain) : null);
			}
		}

		public bool AutoBind
		{
			get
			{
				return automaticBind;
			}
			set
			{
				automaticBind = value;
			}
		}

		static LdapConnection()
		{
			handleTable = new Hashtable();
			objectLock = new object();
			Hashtable table = new Hashtable();
			asyncResultTable = Hashtable.Synchronized(table);
			waitHandle = new ManualResetEvent(initialState: false);
			partialResultsProcessor = new LdapPartialResultsProcessor(waitHandle);
			retriever = new PartialResultsRetriever(waitHandle, partialResultsProcessor);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public LdapConnection(string server)
			: this(new LdapDirectoryIdentifier(server))
		{
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public LdapConnection(LdapDirectoryIdentifier identifier)
			: this(identifier, null, AuthType.Negotiate)
		{
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public LdapConnection(LdapDirectoryIdentifier identifier, NetworkCredential credential)
			: this(identifier, credential, AuthType.Negotiate)
		{
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
		public LdapConnection(LdapDirectoryIdentifier identifier, NetworkCredential credential, AuthType authType)
		{
			fd = ConstructResponse;
			directoryIdentifier = identifier;
			directoryCredential = ((credential != null) ? new NetworkCredential(credential.UserName, credential.Password, credential.Domain) : null);
			connectionAuthType = authType;
			if (authType < AuthType.Anonymous || authType > AuthType.Kerberos)
			{
				throw new InvalidEnumArgumentException("authType", (int)authType, typeof(AuthType));
			}
			if (AuthType == AuthType.Anonymous && directoryCredential != null && ((directoryCredential.Password != null && directoryCredential.Password.Length != 0) || (directoryCredential.UserName != null && directoryCredential.UserName.Length != 0)))
			{
				throw new ArgumentException(Res.GetString("InvalidAuthCredential"));
			}
			Init();
			options = new LdapSessionOptions(this);
			clientCertificateRoutine = ProcessClientCertificate;
		}

		internal LdapConnection(LdapDirectoryIdentifier identifier, NetworkCredential credential, AuthType authType, IntPtr handle)
		{
			directoryIdentifier = identifier;
			ldapHandle = handle;
			directoryCredential = credential;
			connectionAuthType = authType;
			options = new LdapSessionOptions(this);
			needDispose = false;
			clientCertificateRoutine = ProcessClientCertificate;
		}

		~LdapConnection()
		{
			Dispose(disposing: false);
		}

		internal void Init()
		{
			string hostName = null;
			string[] array = ((directoryIdentifier == null) ? null : ((LdapDirectoryIdentifier)directoryIdentifier).Servers);
			if (array != null && array.Length != 0)
			{
				StringBuilder stringBuilder = new StringBuilder(200);
				for (int i = 0; i < array.Length; i++)
				{
					if (array[i] != null)
					{
						stringBuilder.Append(array[i]);
						if (i < array.Length - 1)
						{
							stringBuilder.Append(" ");
						}
					}
				}
				if (stringBuilder.Length != 0)
				{
					hostName = stringBuilder.ToString();
				}
			}
			if (((LdapDirectoryIdentifier)directoryIdentifier).Connectionless)
			{
				ldapHandle = Wldap32.cldap_open(hostName, ((LdapDirectoryIdentifier)directoryIdentifier).PortNumber);
			}
			else
			{
				ldapHandle = Wldap32.ldap_init(hostName, ((LdapDirectoryIdentifier)directoryIdentifier).PortNumber);
			}
			if (ldapHandle == (IntPtr)0)
			{
				int num = Wldap32.LdapGetLastError();
				if (Utility.IsLdapError((LdapError)num))
				{
					string message = LdapErrorMappings.MapResultCode(num);
					throw new LdapException(num, message);
				}
				throw new LdapException(num);
			}
			lock (objectLock)
			{
				if (handleTable[ldapHandle] != null)
				{
					handleTable.Remove(ldapHandle);
				}
				handleTable.Add(ldapHandle, new WeakReference(this));
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override DirectoryResponse SendRequest(DirectoryRequest request)
		{
			return SendRequest(request, connectionTimeOut);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public DirectoryResponse SendRequest(DirectoryRequest request, TimeSpan requestTimeout)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}
			if (request is DsmlAuthRequest)
			{
				throw new NotSupportedException(Res.GetString("DsmlAuthRequestNotSupported"));
			}
			int messageID = 0;
			int num = SendRequestHelper(request, ref messageID);
			LdapOperation operation = LdapOperation.LdapSearch;
			if (request is DeleteRequest)
			{
				operation = LdapOperation.LdapDelete;
			}
			else if (request is AddRequest)
			{
				operation = LdapOperation.LdapAdd;
			}
			else if (request is ModifyRequest)
			{
				operation = LdapOperation.LdapModify;
			}
			else if (request is SearchRequest)
			{
				operation = LdapOperation.LdapSearch;
			}
			else if (request is ModifyDNRequest)
			{
				operation = LdapOperation.LdapModifyDn;
			}
			else if (request is CompareRequest)
			{
				operation = LdapOperation.LdapCompare;
			}
			else if (request is ExtendedRequest)
			{
				operation = LdapOperation.LdapExtendedRequest;
			}
			if (num == 0 && messageID != -1)
			{
				return ConstructResponse(messageID, operation, ResultAll.LDAP_MSG_ALL, requestTimeout, exceptionOnTimeOut: true);
			}
			if (num == 0)
			{
				num = Wldap32.LdapGetLastError();
			}
			throw ConstructException(num, operation);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public IAsyncResult BeginSendRequest(DirectoryRequest request, PartialResultProcessing partialMode, AsyncCallback callback, object state)
		{
			return BeginSendRequest(request, connectionTimeOut, partialMode, callback, state);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public IAsyncResult BeginSendRequest(DirectoryRequest request, TimeSpan requestTimeout, PartialResultProcessing partialMode, AsyncCallback callback, object state)
		{
			int messageID = 0;
			int num = 0;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}
			switch (partialMode)
			{
			default:
				throw new InvalidEnumArgumentException("partialMode", (int)partialMode, typeof(PartialResultProcessing));
			case PartialResultProcessing.ReturnPartialResults:
			case PartialResultProcessing.ReturnPartialResultsAndNotifyCallback:
				if (!(request is SearchRequest))
				{
					throw new NotSupportedException(Res.GetString("PartialResultsNotSupported"));
				}
				break;
			case PartialResultProcessing.NoPartialResultSupport:
				break;
			}
			if (partialMode == PartialResultProcessing.ReturnPartialResultsAndNotifyCallback && callback == null)
			{
				throw new ArgumentException(Res.GetString("CallBackIsNull"), "callback");
			}
			num = SendRequestHelper(request, ref messageID);
			LdapOperation operation = LdapOperation.LdapSearch;
			if (request is DeleteRequest)
			{
				operation = LdapOperation.LdapDelete;
			}
			else if (request is AddRequest)
			{
				operation = LdapOperation.LdapAdd;
			}
			else if (request is ModifyRequest)
			{
				operation = LdapOperation.LdapModify;
			}
			else if (request is SearchRequest)
			{
				operation = LdapOperation.LdapSearch;
			}
			else if (request is ModifyDNRequest)
			{
				operation = LdapOperation.LdapModifyDn;
			}
			else if (request is CompareRequest)
			{
				operation = LdapOperation.LdapCompare;
			}
			else if (request is ExtendedRequest)
			{
				operation = LdapOperation.LdapExtendedRequest;
			}
			if (num == 0 && messageID != -1)
			{
				if (partialMode == PartialResultProcessing.NoPartialResultSupport)
				{
					LdapRequestState ldapRequestState = new LdapRequestState();
					LdapAsyncResult ldapAsyncResult = (ldapRequestState.ldapAsync = new LdapAsyncResult(callback, state, partialResults: false));
					ldapAsyncResult.resultObject = ldapRequestState;
					asyncResultTable.Add(ldapAsyncResult, messageID);
					fd.BeginInvoke(messageID, operation, ResultAll.LDAP_MSG_ALL, requestTimeout, exceptionOnTimeOut: true, ResponseCallback, ldapRequestState);
					return ldapAsyncResult;
				}
				bool partialCallback = false;
				if (partialMode == PartialResultProcessing.ReturnPartialResultsAndNotifyCallback)
				{
					partialCallback = true;
				}
				LdapPartialAsyncResult ldapPartialAsyncResult = new LdapPartialAsyncResult(messageID, callback, state, partialResults: true, this, partialCallback, requestTimeout);
				partialResultsProcessor.Add(ldapPartialAsyncResult);
				return ldapPartialAsyncResult;
			}
			if (num == 0)
			{
				num = Wldap32.LdapGetLastError();
			}
			throw ConstructException(num, operation);
		}

		private void ResponseCallback(IAsyncResult asyncResult)
		{
			LdapRequestState ldapRequestState = (LdapRequestState)asyncResult.AsyncState;
			try
			{
				DirectoryResponse directoryResponse = (ldapRequestState.response = fd.EndInvoke(asyncResult));
			}
			catch (Exception exception)
			{
				Exception ex = (ldapRequestState.exception = exception);
				ldapRequestState.response = null;
			}
			catch
			{
				ldapRequestState.exception = new Exception(Res.GetString("NonCLSException"));
				ldapRequestState.response = null;
			}
			ldapRequestState.ldapAsync.manualResetEvent.Set();
			ldapRequestState.ldapAsync.completed = true;
			if (ldapRequestState.ldapAsync.callback != null && !ldapRequestState.abortCalled)
			{
				ldapRequestState.ldapAsync.callback(ldapRequestState.ldapAsync);
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public void Abort(IAsyncResult asyncResult)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (asyncResult == null)
			{
				throw new ArgumentNullException("asyncResult");
			}
			if (!(asyncResult is LdapAsyncResult))
			{
				throw new ArgumentException(Res.GetString("NotReturnedAsyncResult", "asyncResult"));
			}
			int num = -1;
			LdapAsyncResult ldapAsyncResult = (LdapAsyncResult)asyncResult;
			if (!ldapAsyncResult.partialResults)
			{
				if (!asyncResultTable.Contains(asyncResult))
				{
					throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
				}
				num = (int)asyncResultTable[asyncResult];
				asyncResultTable.Remove(asyncResult);
			}
			else
			{
				partialResultsProcessor.Remove((LdapPartialAsyncResult)asyncResult);
				num = ((LdapPartialAsyncResult)asyncResult).messageID;
			}
			Wldap32.ldap_abandon(ldapHandle, num);
			LdapRequestState resultObject = ldapAsyncResult.resultObject;
			if (resultObject != null)
			{
				resultObject.abortCalled = true;
			}
		}

		public PartialResultsCollection GetPartialResults(IAsyncResult asyncResult)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (asyncResult == null)
			{
				throw new ArgumentNullException("asyncResult");
			}
			if (!(asyncResult is LdapAsyncResult))
			{
				throw new ArgumentException(Res.GetString("NotReturnedAsyncResult", "asyncResult"));
			}
			if (!(asyncResult is LdapPartialAsyncResult))
			{
				throw new InvalidOperationException(Res.GetString("NoPartialResults"));
			}
			return partialResultsProcessor.GetPartialResults((LdapPartialAsyncResult)asyncResult);
		}

		public DirectoryResponse EndSendRequest(IAsyncResult asyncResult)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (asyncResult == null)
			{
				throw new ArgumentNullException("asyncResult");
			}
			if (!(asyncResult is LdapAsyncResult))
			{
				throw new ArgumentException(Res.GetString("NotReturnedAsyncResult", "asyncResult"));
			}
			LdapAsyncResult ldapAsyncResult = (LdapAsyncResult)asyncResult;
			if (!ldapAsyncResult.partialResults)
			{
				if (!asyncResultTable.Contains(asyncResult))
				{
					throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
				}
				asyncResultTable.Remove(asyncResult);
				asyncResult.AsyncWaitHandle.WaitOne();
				if (ldapAsyncResult.resultObject.exception != null)
				{
					throw ldapAsyncResult.resultObject.exception;
				}
				return ldapAsyncResult.resultObject.response;
			}
			partialResultsProcessor.NeedCompleteResult((LdapPartialAsyncResult)asyncResult);
			asyncResult.AsyncWaitHandle.WaitOne();
			return partialResultsProcessor.GetCompleteResult((LdapPartialAsyncResult)asyncResult);
		}

		private int SendRequestHelper(DirectoryRequest request, ref int messageID)
		{
			IntPtr intPtr = (IntPtr)0;
			LdapControl[] array = null;
			IntPtr intPtr2 = (IntPtr)0;
			LdapControl[] array2 = null;
			string strValue = null;
			ArrayList arrayList = new ArrayList();
			LdapMod[] array3 = null;
			IntPtr intPtr3 = (IntPtr)0;
			int num = 0;
			berval berval2 = null;
			IntPtr intPtr4 = (IntPtr)0;
			int num2 = 0;
			int num3 = 0;
			if (!connected)
			{
				Connect();
				connected = true;
			}
			if (AutoBind && (!bounded || needRebind) && !((LdapDirectoryIdentifier)Directory).Connectionless)
			{
				Bind();
			}
			try
			{
				IntPtr intPtr5 = (IntPtr)0;
				IntPtr intPtr6 = (IntPtr)0;
				array = BuildControlArray(request.Controls, serverControl: true);
				int cb = Marshal.SizeOf(typeof(LdapControl));
				if (array != null)
				{
					intPtr = Utility.AllocHGlobalIntPtrArray(array.Length + 1);
					for (int i = 0; i < array.Length; i++)
					{
						intPtr5 = Marshal.AllocHGlobal(cb);
						Marshal.StructureToPtr(array[i], intPtr5, fDeleteOld: false);
						intPtr6 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * i);
						Marshal.WriteIntPtr(intPtr6, intPtr5);
					}
					intPtr6 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * array.Length);
					Marshal.WriteIntPtr(intPtr6, (IntPtr)0);
				}
				array2 = BuildControlArray(request.Controls, serverControl: false);
				if (array2 != null)
				{
					intPtr2 = Utility.AllocHGlobalIntPtrArray(array2.Length + 1);
					for (int j = 0; j < array2.Length; j++)
					{
						intPtr5 = Marshal.AllocHGlobal(cb);
						Marshal.StructureToPtr(array2[j], intPtr5, fDeleteOld: false);
						intPtr6 = (IntPtr)((long)intPtr2 + Marshal.SizeOf(typeof(IntPtr)) * j);
						Marshal.WriteIntPtr(intPtr6, intPtr5);
					}
					intPtr6 = (IntPtr)((long)intPtr2 + Marshal.SizeOf(typeof(IntPtr)) * array2.Length);
					Marshal.WriteIntPtr(intPtr6, (IntPtr)0);
				}
				if (request is DeleteRequest)
				{
					num3 = Wldap32.ldap_delete_ext(ldapHandle, ((DeleteRequest)request).DistinguishedName, intPtr, intPtr2, ref messageID);
				}
				else if (request is ModifyDNRequest)
				{
					num3 = Wldap32.ldap_rename(ldapHandle, ((ModifyDNRequest)request).DistinguishedName, ((ModifyDNRequest)request).NewName, ((ModifyDNRequest)request).NewParentDistinguishedName, ((ModifyDNRequest)request).DeleteOldRdn ? 1 : 0, intPtr, intPtr2, ref messageID);
				}
				else if (request is CompareRequest)
				{
					DirectoryAttribute assertion = ((CompareRequest)request).Assertion;
					if (assertion == null)
					{
						throw new ArgumentException(Res.GetString("WrongAssertionCompare"));
					}
					if (assertion.Count != 1)
					{
						throw new ArgumentException(Res.GetString("WrongNumValuesCompare"));
					}
					if (assertion[0] is byte[] array4)
					{
						if (array4 != null && array4.Length != 0)
						{
							berval2 = new berval();
							berval2.bv_len = array4.Length;
							berval2.bv_val = Marshal.AllocHGlobal(array4.Length);
							Marshal.Copy(array4, 0, berval2.bv_val, array4.Length);
						}
					}
					else
					{
						strValue = assertion[0].ToString();
					}
					num3 = Wldap32.ldap_compare(ldapHandle, ((CompareRequest)request).DistinguishedName, assertion.Name, strValue, berval2, intPtr, intPtr2, ref messageID);
				}
				else if (request is AddRequest || request is ModifyRequest)
				{
					array3 = ((!(request is AddRequest)) ? BuildAttributes(((ModifyRequest)request).Modifications, arrayList) : BuildAttributes(((AddRequest)request).Attributes, arrayList));
					num = ((array3 == null) ? 1 : (array3.Length + 1));
					intPtr3 = Utility.AllocHGlobalIntPtrArray(num);
					int cb2 = Marshal.SizeOf(typeof(LdapMod));
					int num4 = 0;
					for (num4 = 0; num4 < num - 1; num4++)
					{
						intPtr5 = Marshal.AllocHGlobal(cb2);
						Marshal.StructureToPtr(array3[num4], intPtr5, fDeleteOld: false);
						intPtr6 = (IntPtr)((long)intPtr3 + Marshal.SizeOf(typeof(IntPtr)) * num4);
						Marshal.WriteIntPtr(intPtr6, intPtr5);
					}
					intPtr6 = (IntPtr)((long)intPtr3 + Marshal.SizeOf(typeof(IntPtr)) * num4);
					Marshal.WriteIntPtr(intPtr6, (IntPtr)0);
					num3 = ((!(request is AddRequest)) ? Wldap32.ldap_modify(ldapHandle, ((ModifyRequest)request).DistinguishedName, intPtr3, intPtr, intPtr2, ref messageID) : Wldap32.ldap_add(ldapHandle, ((AddRequest)request).DistinguishedName, intPtr3, intPtr, intPtr2, ref messageID));
				}
				else if (request is ExtendedRequest)
				{
					string requestName = ((ExtendedRequest)request).RequestName;
					byte[] requestValue = ((ExtendedRequest)request).RequestValue;
					if (requestValue != null && requestValue.Length != 0)
					{
						berval2 = new berval();
						berval2.bv_len = requestValue.Length;
						berval2.bv_val = Marshal.AllocHGlobal(requestValue.Length);
						Marshal.Copy(requestValue, 0, berval2.bv_val, requestValue.Length);
					}
					num3 = Wldap32.ldap_extended_operation(ldapHandle, requestName, berval2, intPtr, intPtr2, ref messageID);
				}
				else
				{
					if (!(request is SearchRequest))
					{
						throw new NotSupportedException(Res.GetString("InvliadRequestType"));
					}
					SearchRequest searchRequest = (SearchRequest)request;
					object filter = searchRequest.Filter;
					if (filter != null && filter is XmlDocument)
					{
						throw new ArgumentException(Res.GetString("InvalidLdapSearchRequestFilter"));
					}
					string filter2 = (string)filter;
					num2 = ((searchRequest.Attributes != null) ? searchRequest.Attributes.Count : 0);
					if (num2 != 0)
					{
						intPtr4 = Utility.AllocHGlobalIntPtrArray(num2 + 1);
						int num5 = 0;
						for (num5 = 0; num5 < num2; num5++)
						{
							intPtr5 = Marshal.StringToHGlobalUni(searchRequest.Attributes[num5]);
							intPtr6 = (IntPtr)((long)intPtr4 + Marshal.SizeOf(typeof(IntPtr)) * num5);
							Marshal.WriteIntPtr(intPtr6, intPtr5);
						}
						intPtr6 = (IntPtr)((long)intPtr4 + Marshal.SizeOf(typeof(IntPtr)) * num5);
						Marshal.WriteIntPtr(intPtr6, (IntPtr)0);
					}
					int scope = (int)searchRequest.Scope;
					int timelimit = (int)(searchRequest.TimeLimit.Ticks / 10000000);
					DereferenceAlias derefAlias = options.DerefAlias;
					options.DerefAlias = searchRequest.Aliases;
					try
					{
						num3 = Wldap32.ldap_search(ldapHandle, searchRequest.DistinguishedName, scope, filter2, intPtr4, searchRequest.TypesOnly, intPtr, intPtr2, timelimit, searchRequest.SizeLimit, ref messageID);
					}
					finally
					{
						options.DerefAlias = derefAlias;
					}
				}
				if (num3 == 85)
				{
					num3 = 112;
				}
				return num3;
			}
			finally
			{
				GC.KeepAlive(array3);
				if (intPtr != (IntPtr)0)
				{
					for (int k = 0; k < array.Length; k++)
					{
						IntPtr intPtr7 = Marshal.ReadIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * k);
						if (intPtr7 != (IntPtr)0)
						{
							Marshal.FreeHGlobal(intPtr7);
						}
					}
					Marshal.FreeHGlobal(intPtr);
				}
				if (array != null)
				{
					for (int l = 0; l < array.Length; l++)
					{
						if (array[l].ldctl_oid != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array[l].ldctl_oid);
						}
						if (array[l].ldctl_value != null && array[l].ldctl_value.bv_val != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array[l].ldctl_value.bv_val);
						}
					}
				}
				if (intPtr2 != (IntPtr)0)
				{
					for (int m = 0; m < array2.Length; m++)
					{
						IntPtr intPtr8 = Marshal.ReadIntPtr(intPtr2, Marshal.SizeOf(typeof(IntPtr)) * m);
						if (intPtr8 != (IntPtr)0)
						{
							Marshal.FreeHGlobal(intPtr8);
						}
					}
					Marshal.FreeHGlobal(intPtr2);
				}
				if (array2 != null)
				{
					for (int n = 0; n < array2.Length; n++)
					{
						if (array2[n].ldctl_oid != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array2[n].ldctl_oid);
						}
						if (array2[n].ldctl_value != null && array2[n].ldctl_value.bv_val != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array2[n].ldctl_value.bv_val);
						}
					}
				}
				if (intPtr3 != (IntPtr)0)
				{
					for (int num6 = 0; num6 < num - 1; num6++)
					{
						IntPtr intPtr9 = Marshal.ReadIntPtr(intPtr3, Marshal.SizeOf(typeof(IntPtr)) * num6);
						if (intPtr9 != (IntPtr)0)
						{
							Marshal.FreeHGlobal(intPtr9);
						}
					}
					Marshal.FreeHGlobal(intPtr3);
				}
				for (int num7 = 0; num7 < arrayList.Count; num7++)
				{
					IntPtr hglobal = (IntPtr)arrayList[num7];
					Marshal.FreeHGlobal(hglobal);
				}
				if (berval2 != null && berval2.bv_val != (IntPtr)0)
				{
					Marshal.FreeHGlobal(berval2.bv_val);
				}
				if (intPtr4 != (IntPtr)0)
				{
					for (int num8 = 0; num8 < num2; num8++)
					{
						IntPtr intPtr10 = Marshal.ReadIntPtr(intPtr4, Marshal.SizeOf(typeof(IntPtr)) * num8);
						if (intPtr10 != (IntPtr)0)
						{
							Marshal.FreeHGlobal(intPtr10);
						}
					}
					Marshal.FreeHGlobal(intPtr4);
				}
			}
		}

		private bool ProcessClientCertificate(IntPtr ldapHandle, IntPtr CAs, ref IntPtr certificate)
		{
			ArrayList arrayList = new ArrayList();
			byte[][] array = null;
			if ((base.ClientCertificates == null || base.ClientCertificates.Count == 0) && options.clientCertificateDelegate == null)
			{
				return false;
			}
			if (options.clientCertificateDelegate == null)
			{
				certificate = base.ClientCertificates[0].Handle;
				return true;
			}
			if (CAs != (IntPtr)0)
			{
				SecPkgContext_IssuerListInfoEx secPkgContext_IssuerListInfoEx = (SecPkgContext_IssuerListInfoEx)Marshal.PtrToStructure(CAs, typeof(SecPkgContext_IssuerListInfoEx));
				int cIssuers = secPkgContext_IssuerListInfoEx.cIssuers;
				IntPtr intPtr = (IntPtr)0;
				for (int i = 0; i < cIssuers; i++)
				{
					intPtr = (IntPtr)((long)secPkgContext_IssuerListInfoEx.aIssuers + Marshal.SizeOf(typeof(CRYPTOAPI_BLOB)) * i);
					CRYPTOAPI_BLOB cRYPTOAPI_BLOB = (CRYPTOAPI_BLOB)Marshal.PtrToStructure(intPtr, typeof(CRYPTOAPI_BLOB));
					int cbData = cRYPTOAPI_BLOB.cbData;
					byte[] array2 = new byte[cbData];
					Marshal.Copy(cRYPTOAPI_BLOB.pbData, array2, 0, cbData);
					arrayList.Add(array2);
				}
			}
			if (arrayList.Count != 0)
			{
				array = new byte[arrayList.Count][];
				for (int j = 0; j < arrayList.Count; j++)
				{
					array[j] = (byte[])arrayList[j];
				}
			}
			X509Certificate x509Certificate = options.clientCertificateDelegate(this, array);
			if (x509Certificate != null)
			{
				certificate = x509Certificate.Handle;
				return true;
			}
			certificate = (IntPtr)0;
			return false;
		}

		private void Connect()
		{
			int num = 0;
			if (base.ClientCertificates.Count > 1)
			{
				throw new InvalidOperationException(Res.GetString("InvalidClientCertificates"));
			}
			if (base.ClientCertificates.Count != 0)
			{
				int num2 = Wldap32.ldap_set_option_clientcert(ldapHandle, LdapOption.LDAP_OPT_CLIENT_CERTIFICATE, clientCertificateRoutine);
				if (num2 != 0)
				{
					if (Utility.IsLdapError((LdapError)num2))
					{
						string message = LdapErrorMappings.MapResultCode(num2);
						throw new LdapException(num2, message);
					}
					throw new LdapException(num2);
				}
				automaticBind = false;
			}
			if (((LdapDirectoryIdentifier)Directory).FullyQualifiedDnsHostName && !setFQDNDone)
			{
				SessionOptions.FQDN = true;
				setFQDNDone = true;
			}
			LDAP_TIMEVAL lDAP_TIMEVAL = new LDAP_TIMEVAL();
			lDAP_TIMEVAL.tv_sec = (int)(connectionTimeOut.Ticks / 10000000);
			num = Wldap32.ldap_connect(ldapHandle, lDAP_TIMEVAL);
			if (num != 0)
			{
				if (Utility.IsLdapError((LdapError)num))
				{
					string message2 = LdapErrorMappings.MapResultCode(num);
					throw new LdapException(num, message2);
				}
				throw new LdapException(num);
			}
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public void Bind()
		{
			BindHelper(directoryCredential, needSetCredential: false);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public void Bind(NetworkCredential newCredential)
		{
			BindHelper(newCredential, needSetCredential: true);
		}

		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
		private void BindHelper(NetworkCredential newCredential, bool needSetCredential)
		{
			int num = 0;
			NetworkCredential networkCredential = null;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (AuthType == AuthType.Anonymous && newCredential != null && ((newCredential.Password != null && newCredential.Password.Length != 0) || (newCredential.UserName != null && newCredential.UserName.Length != 0)))
			{
				throw new InvalidOperationException(Res.GetString("InvalidAuthCredential"));
			}
			networkCredential = ((!needSetCredential) ? directoryCredential : (directoryCredential = ((newCredential != null) ? new NetworkCredential(newCredential.UserName, newCredential.Password, newCredential.Domain) : null)));
			if (!connected)
			{
				Connect();
				connected = true;
			}
			string text;
			string text2;
			string text3;
			if (networkCredential != null && networkCredential.UserName.Length == 0 && networkCredential.Password.Length == 0 && networkCredential.Domain.Length == 0)
			{
				text = null;
				text2 = null;
				text3 = null;
			}
			else
			{
				text = networkCredential?.UserName;
				text2 = networkCredential?.Domain;
				text3 = networkCredential?.Password;
			}
			if (AuthType == AuthType.Anonymous)
			{
				num = Wldap32.ldap_simple_bind_s(ldapHandle, null, null);
			}
			else if (AuthType == AuthType.Basic)
			{
				StringBuilder stringBuilder = new StringBuilder(100);
				if (text2 != null && text2.Length != 0)
				{
					stringBuilder.Append(text2);
					stringBuilder.Append("\\");
				}
				stringBuilder.Append(text);
				num = Wldap32.ldap_simple_bind_s(ldapHandle, stringBuilder.ToString(), text3);
			}
			else
			{
				SEC_WINNT_AUTH_IDENTITY_EX sEC_WINNT_AUTH_IDENTITY_EX = new SEC_WINNT_AUTH_IDENTITY_EX();
				sEC_WINNT_AUTH_IDENTITY_EX.version = 512;
				sEC_WINNT_AUTH_IDENTITY_EX.length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX));
				sEC_WINNT_AUTH_IDENTITY_EX.flags = 2;
				if (AuthType == AuthType.Kerberos)
				{
					sEC_WINNT_AUTH_IDENTITY_EX.packageList = "Kerberos";
					sEC_WINNT_AUTH_IDENTITY_EX.packageListLength = sEC_WINNT_AUTH_IDENTITY_EX.packageList.Length;
				}
				if (networkCredential != null)
				{
					sEC_WINNT_AUTH_IDENTITY_EX.user = text;
					sEC_WINNT_AUTH_IDENTITY_EX.userLength = text?.Length ?? 0;
					sEC_WINNT_AUTH_IDENTITY_EX.domain = text2;
					sEC_WINNT_AUTH_IDENTITY_EX.domainLength = text2?.Length ?? 0;
					sEC_WINNT_AUTH_IDENTITY_EX.password = text3;
					sEC_WINNT_AUTH_IDENTITY_EX.passwordLength = text3?.Length ?? 0;
				}
				BindMethod method = BindMethod.LDAP_AUTH_NEGOTIATE;
				switch (AuthType)
				{
				case AuthType.Negotiate:
					method = BindMethod.LDAP_AUTH_NEGOTIATE;
					break;
				case AuthType.Kerberos:
					method = BindMethod.LDAP_AUTH_NEGOTIATE;
					break;
				case AuthType.Ntlm:
					method = BindMethod.LDAP_AUTH_NTLM;
					break;
				case AuthType.Digest:
					method = BindMethod.LDAP_AUTH_DIGEST;
					break;
				case AuthType.Sicily:
					method = BindMethod.LDAP_AUTH_SICILY;
					break;
				case AuthType.Dpa:
					method = BindMethod.LDAP_AUTH_DPA;
					break;
				case AuthType.Msn:
					method = BindMethod.LDAP_AUTH_MSN;
					break;
				case AuthType.External:
					method = BindMethod.LDAP_AUTH_EXTERNAL;
					break;
				}
				num = ((networkCredential != null || AuthType != AuthType.External) ? Wldap32.ldap_bind_s(ldapHandle, null, sEC_WINNT_AUTH_IDENTITY_EX, method) : Wldap32.ldap_bind_s(ldapHandle, null, null, method));
			}
			if (num != 0)
			{
				if (Utility.IsResultCode((ResultCode)num))
				{
					string message = OperationErrorMappings.MapResultCode(num);
					throw new DirectoryOperationException(null, message);
				}
				if (Utility.IsLdapError((LdapError)num))
				{
					string message = LdapErrorMappings.MapResultCode(num);
					string serverErrorMessage = options.ServerErrorMessage;
					if (serverErrorMessage != null && serverErrorMessage.Length > 0)
					{
						throw new LdapException(num, message, serverErrorMessage);
					}
					throw new LdapException(num, message);
				}
				throw new LdapException(num);
			}
			bounded = true;
			needRebind = false;
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing)
			{
				lock (objectLock)
				{
					handleTable.Remove(ldapHandle);
				}
			}
			if (needDispose && ldapHandle != (IntPtr)0)
			{
				Wldap32.ldap_unbind(ldapHandle);
			}
			ldapHandle = (IntPtr)0;
			disposed = true;
		}

		internal LdapControl[] BuildControlArray(DirectoryControlCollection controls, bool serverControl)
		{
			int num = 0;
			LdapControl[] array = null;
			if (controls != null && controls.Count != 0)
			{
				ArrayList arrayList = new ArrayList();
				foreach (DirectoryControl control in controls)
				{
					if (serverControl)
					{
						if (control.ServerSide)
						{
							arrayList.Add(control);
						}
					}
					else if (!control.ServerSide)
					{
						arrayList.Add(control);
					}
				}
				if (arrayList.Count != 0)
				{
					num = arrayList.Count;
					array = new LdapControl[num];
					for (int i = 0; i < num; i++)
					{
						array[i] = new LdapControl();
						array[i].ldctl_oid = Marshal.StringToHGlobalUni(((DirectoryControl)arrayList[i]).Type);
						array[i].ldctl_iscritical = ((DirectoryControl)arrayList[i]).IsCritical;
						DirectoryControl directoryControl2 = (DirectoryControl)arrayList[i];
						byte[] value = directoryControl2.GetValue();
						if (value == null || value.Length == 0)
						{
							array[i].ldctl_value = new berval();
							array[i].ldctl_value.bv_len = 0;
							array[i].ldctl_value.bv_val = (IntPtr)0;
						}
						else
						{
							array[i].ldctl_value = new berval();
							array[i].ldctl_value.bv_len = value.Length;
							array[i].ldctl_value.bv_val = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(byte)) * array[i].ldctl_value.bv_len);
							Marshal.Copy(value, 0, array[i].ldctl_value.bv_val, array[i].ldctl_value.bv_len);
						}
					}
				}
			}
			return array;
		}

		internal LdapMod[] BuildAttributes(CollectionBase directoryAttributes, ArrayList ptrToFree)
		{
			LdapMod[] array = null;
			UTF8Encoding uTF8Encoding = new UTF8Encoding();
			DirectoryAttributeCollection directoryAttributeCollection = null;
			DirectoryAttributeModificationCollection directoryAttributeModificationCollection = null;
			DirectoryAttribute directoryAttribute = null;
			if (directoryAttributes != null && directoryAttributes.Count != 0)
			{
				if (directoryAttributes is DirectoryAttributeModificationCollection)
				{
					directoryAttributeModificationCollection = (DirectoryAttributeModificationCollection)directoryAttributes;
				}
				else
				{
					directoryAttributeCollection = (DirectoryAttributeCollection)directoryAttributes;
				}
				array = new LdapMod[directoryAttributes.Count];
				for (int i = 0; i < directoryAttributes.Count; i++)
				{
					directoryAttribute = ((directoryAttributeCollection == null) ? directoryAttributeModificationCollection[i] : directoryAttributeCollection[i]);
					array[i] = new LdapMod();
					if (directoryAttribute is DirectoryAttributeModification)
					{
						array[i].type = (int)((DirectoryAttributeModification)directoryAttribute).Operation;
					}
					else
					{
						array[i].type = 0;
					}
					array[i].type |= 128;
					array[i].attribute = Marshal.StringToHGlobalUni(directoryAttribute.Name);
					int num = 0;
					berval[] array2 = null;
					if (directoryAttribute.Count > 0)
					{
						num = directoryAttribute.Count;
						array2 = new berval[num];
						for (int j = 0; j < num; j++)
						{
							byte[] array3 = null;
							array3 = ((!(directoryAttribute[j] is string)) ? ((!(directoryAttribute[j] is Uri)) ? ((byte[])directoryAttribute[j]) : uTF8Encoding.GetBytes(((Uri)directoryAttribute[j]).ToString())) : uTF8Encoding.GetBytes((string)directoryAttribute[j]));
							array2[j] = new berval();
							array2[j].bv_len = array3.Length;
							array2[j].bv_val = Marshal.AllocHGlobal(array2[j].bv_len);
							ptrToFree.Add(array2[j].bv_val);
							Marshal.Copy(array3, 0, array2[j].bv_val, array2[j].bv_len);
						}
					}
					array[i].values = Utility.AllocHGlobalIntPtrArray(num + 1);
					int cb = Marshal.SizeOf(typeof(berval));
					IntPtr intPtr = (IntPtr)0;
					IntPtr intPtr2 = (IntPtr)0;
					int num2 = 0;
					for (num2 = 0; num2 < num; num2++)
					{
						intPtr = Marshal.AllocHGlobal(cb);
						ptrToFree.Add(intPtr);
						Marshal.StructureToPtr(array2[num2], intPtr, fDeleteOld: false);
						intPtr2 = (IntPtr)((long)array[i].values + Marshal.SizeOf(typeof(IntPtr)) * num2);
						Marshal.WriteIntPtr(intPtr2, intPtr);
					}
					intPtr2 = (IntPtr)((long)array[i].values + Marshal.SizeOf(typeof(IntPtr)) * num2);
					Marshal.WriteIntPtr(intPtr2, (IntPtr)0);
				}
			}
			return array;
		}

		internal DirectoryResponse ConstructResponse(int messageId, LdapOperation operation, ResultAll resultType, TimeSpan requestTimeOut, bool exceptionOnTimeOut)
		{
			LDAP_TIMEVAL lDAP_TIMEVAL = new LDAP_TIMEVAL();
			lDAP_TIMEVAL.tv_sec = (int)(requestTimeOut.Ticks / 10000000);
			IntPtr Mesage = (IntPtr)0;
			DirectoryResponse directoryResponse = null;
			IntPtr oid = (IntPtr)0;
			IntPtr data = (IntPtr)0;
			IntPtr intPtr = (IntPtr)0;
			bool flag = true;
			if (resultType != ResultAll.LDAP_MSG_ALL)
			{
				lDAP_TIMEVAL.tv_sec = 0;
				lDAP_TIMEVAL.tv_usec = 0;
				if (resultType == ResultAll.LDAP_MSG_POLLINGALL)
				{
					resultType = ResultAll.LDAP_MSG_ALL;
				}
				flag = false;
			}
			int num = Wldap32.ldap_result(ldapHandle, messageId, (int)resultType, lDAP_TIMEVAL, ref Mesage);
			if (num != -1 && num != 0)
			{
				int serverError = 0;
				try
				{
					int num2 = 0;
					string responseDn = null;
					string responseMessage = null;
					Uri[] responseReferral = null;
					DirectoryControl[] responseControl = null;
					if (num != 100 && num != 115)
					{
						num2 = ConstructParsedResult(Mesage, ref serverError, ref responseDn, ref responseMessage, ref responseReferral, ref responseControl);
					}
					if (num2 == 0)
					{
						num2 = serverError;
						switch (num)
						{
						case 105:
							directoryResponse = new AddResponse(responseDn, responseControl, (ResultCode)num2, responseMessage, responseReferral);
							break;
						case 103:
							directoryResponse = new ModifyResponse(responseDn, responseControl, (ResultCode)num2, responseMessage, responseReferral);
							break;
						case 107:
							directoryResponse = new DeleteResponse(responseDn, responseControl, (ResultCode)num2, responseMessage, responseReferral);
							break;
						case 109:
							directoryResponse = new ModifyDNResponse(responseDn, responseControl, (ResultCode)num2, responseMessage, responseReferral);
							break;
						case 111:
							directoryResponse = new CompareResponse(responseDn, responseControl, (ResultCode)num2, responseMessage, responseReferral);
							break;
						case 120:
						{
							directoryResponse = new ExtendedResponse(responseDn, responseControl, (ResultCode)num2, responseMessage, responseReferral);
							if (num2 != 0)
							{
								break;
							}
							num2 = Wldap32.ldap_parse_extended_result(ldapHandle, Mesage, ref oid, ref data, 0);
							if (num2 != 0)
							{
								break;
							}
							string name = null;
							if (oid != (IntPtr)0)
							{
								name = Marshal.PtrToStringUni(oid);
							}
							berval berval2 = null;
							byte[] array = null;
							if (data != (IntPtr)0)
							{
								berval2 = new berval();
								Marshal.PtrToStructure(data, berval2);
								if (berval2.bv_len != 0 && berval2.bv_val != (IntPtr)0)
								{
									array = new byte[berval2.bv_len];
									Marshal.Copy(berval2.bv_val, array, 0, berval2.bv_len);
								}
							}
							((ExtendedResponse)directoryResponse).name = name;
							((ExtendedResponse)directoryResponse).value = array;
							break;
						}
						case 100:
						case 101:
						case 115:
						{
							directoryResponse = new SearchResponse(responseDn, responseControl, (ResultCode)num2, responseMessage, responseReferral);
							if (num == 101)
							{
								((SearchResponse)directoryResponse).searchDone = true;
							}
							SearchResultEntryCollection searchResultEntryCollection = new SearchResultEntryCollection();
							SearchResultReferenceCollection searchResultReferenceCollection = new SearchResultReferenceCollection();
							intPtr = Wldap32.ldap_first_entry(ldapHandle, Mesage);
							int num3 = 0;
							while (intPtr != (IntPtr)0)
							{
								SearchResultEntry searchResultEntry = ConstructEntry(intPtr);
								if (searchResultEntry != null)
								{
									searchResultEntryCollection.Add(searchResultEntry);
								}
								num3++;
								intPtr = Wldap32.ldap_next_entry(ldapHandle, intPtr);
							}
							IntPtr intPtr2 = Wldap32.ldap_first_reference(ldapHandle, Mesage);
							while (intPtr2 != (IntPtr)0)
							{
								SearchResultReference searchResultReference = ConstructReference(intPtr2);
								if (searchResultReference != null)
								{
									searchResultReferenceCollection.Add(searchResultReference);
								}
								intPtr2 = Wldap32.ldap_next_reference(ldapHandle, intPtr2);
							}
							((SearchResponse)directoryResponse).SetEntries(searchResultEntryCollection);
							((SearchResponse)directoryResponse).SetReferences(searchResultReferenceCollection);
							break;
						}
						}
						if (num2 != 0 && num2 != 5 && num2 != 6 && num2 != 10 && num2 != 9)
						{
							if (Utility.IsResultCode((ResultCode)num2))
							{
								throw new DirectoryOperationException(directoryResponse, OperationErrorMappings.MapResultCode(num2));
							}
							throw new DirectoryOperationException(directoryResponse);
						}
						return directoryResponse;
					}
					num = num2;
				}
				finally
				{
					if (oid != (IntPtr)0)
					{
						Wldap32.ldap_memfree(oid);
					}
					if (data != (IntPtr)0)
					{
						Wldap32.ldap_memfree(data);
					}
					if (Mesage != (IntPtr)0)
					{
						Wldap32.ldap_msgfree(Mesage);
					}
				}
			}
			else
			{
				if (num == 0)
				{
					if (!exceptionOnTimeOut)
					{
						return null;
					}
					num = 85;
				}
				else
				{
					num = Wldap32.LdapGetLastError();
				}
				if (flag)
				{
					Wldap32.ldap_abandon(ldapHandle, messageId);
				}
			}
			throw ConstructException(num, operation);
		}

		internal unsafe int ConstructParsedResult(IntPtr ldapResult, ref int serverError, ref string responseDn, ref string responseMessage, ref Uri[] responseReferral, ref DirectoryControl[] responseControl)
		{
			IntPtr dn = (IntPtr)0;
			IntPtr message = (IntPtr)0;
			IntPtr referral = (IntPtr)0;
			IntPtr control = (IntPtr)0;
			int num = 0;
			try
			{
				num = Wldap32.ldap_parse_result(ldapHandle, ldapResult, ref serverError, ref dn, ref message, ref referral, ref control, 0);
				switch (num)
				{
				case 0:
					responseDn = Marshal.PtrToStringUni(dn);
					responseMessage = Marshal.PtrToStringUni(message);
					if (referral != (IntPtr)0)
					{
						char** ptr = (char**)(void*)referral;
						char* ptr2 = *(char**)((byte*)ptr + 0);
						int num3 = 0;
						ArrayList arrayList = new ArrayList();
						while (ptr2 != null)
						{
							string value = Marshal.PtrToStringUni((IntPtr)ptr2);
							arrayList.Add(value);
							num3++;
							ptr2 = ptr[num3];
						}
						if (arrayList.Count > 0)
						{
							responseReferral = new Uri[arrayList.Count];
							for (int i = 0; i < arrayList.Count; i++)
							{
								responseReferral[i] = new Uri((string)arrayList[i]);
							}
						}
					}
					if (control != (IntPtr)0)
					{
						int num4 = 0;
						IntPtr ptr3 = control;
						IntPtr intPtr = Marshal.ReadIntPtr(ptr3, 0);
						ArrayList arrayList2 = new ArrayList();
						while (intPtr != (IntPtr)0)
						{
							DirectoryControl value2 = ConstructControl(intPtr);
							arrayList2.Add(value2);
							num4++;
							intPtr = Marshal.ReadIntPtr(ptr3, num4 * Marshal.SizeOf(typeof(IntPtr)));
						}
						responseControl = new DirectoryControl[arrayList2.Count];
						arrayList2.CopyTo(responseControl);
						return num;
					}
					return num;
				case 82:
				{
					int num2 = Wldap32.ldap_result2error(ldapHandle, ldapResult, 0);
					if (num2 != 0)
					{
						return num2;
					}
					return num;
				}
				default:
					return num;
				}
			}
			finally
			{
				if (dn != (IntPtr)0)
				{
					Wldap32.ldap_memfree(dn);
				}
				if (message != (IntPtr)0)
				{
					Wldap32.ldap_memfree(message);
				}
				if (referral != (IntPtr)0)
				{
					Wldap32.ldap_value_free(referral);
				}
				if (control != (IntPtr)0)
				{
					Wldap32.ldap_controls_free(control);
				}
			}
		}

		internal SearchResultEntry ConstructEntry(IntPtr entryMessage)
		{
			IntPtr intPtr = (IntPtr)0;
			string dn = null;
			IntPtr intPtr2 = (IntPtr)0;
			IntPtr address = (IntPtr)0;
			SearchResultAttributeCollection searchResultAttributeCollection = null;
			try
			{
				intPtr = Wldap32.ldap_get_dn(ldapHandle, entryMessage);
				if (intPtr != (IntPtr)0)
				{
					dn = Marshal.PtrToStringUni(intPtr);
					Wldap32.ldap_memfree(intPtr);
					intPtr = (IntPtr)0;
				}
				SearchResultEntry searchResultEntry = new SearchResultEntry(dn);
				searchResultAttributeCollection = searchResultEntry.Attributes;
				intPtr2 = Wldap32.ldap_first_attribute(ldapHandle, entryMessage, ref address);
				int num = 0;
				while (intPtr2 != (IntPtr)0)
				{
					DirectoryAttribute directoryAttribute = ConstructAttribute(entryMessage, intPtr2);
					searchResultAttributeCollection.Add(directoryAttribute.Name, directoryAttribute);
					Wldap32.ldap_memfree(intPtr2);
					num++;
					intPtr2 = Wldap32.ldap_next_attribute(ldapHandle, entryMessage, address);
				}
				if (address != (IntPtr)0)
				{
					Wldap32.ber_free(address, 0);
					address = (IntPtr)0;
				}
				return searchResultEntry;
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					Wldap32.ldap_memfree(intPtr);
				}
				if (intPtr2 != (IntPtr)0)
				{
					Wldap32.ldap_memfree(intPtr2);
				}
				if (address != (IntPtr)0)
				{
					Wldap32.ber_free(address, 0);
				}
			}
		}

		internal DirectoryAttribute ConstructAttribute(IntPtr entryMessage, IntPtr attributeName)
		{
			DirectoryAttribute directoryAttribute = new DirectoryAttribute();
			directoryAttribute.isSearchResult = true;
			IntPtr intPtr = Wldap32.ldap_get_values_len(name: directoryAttribute.Name = Marshal.PtrToStringUni(attributeName), ldapHandle: ldapHandle, result: entryMessage);
			try
			{
				IntPtr intPtr2 = (IntPtr)0;
				int num = 0;
				if (intPtr != (IntPtr)0)
				{
					intPtr2 = Marshal.ReadIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * num);
					while (intPtr2 != (IntPtr)0)
					{
						berval berval2 = new berval();
						Marshal.PtrToStructure(intPtr2, berval2);
						byte[] array = null;
						if (berval2.bv_len > 0 && berval2.bv_val != (IntPtr)0)
						{
							array = new byte[berval2.bv_len];
							Marshal.Copy(berval2.bv_val, array, 0, berval2.bv_len);
							directoryAttribute.Add(array);
						}
						num++;
						intPtr2 = Marshal.ReadIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * num);
					}
					return directoryAttribute;
				}
				return directoryAttribute;
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					Wldap32.ldap_value_free_len(intPtr);
				}
			}
		}

		internal SearchResultReference ConstructReference(IntPtr referenceMessage)
		{
			SearchResultReference result = null;
			ArrayList arrayList = new ArrayList();
			Uri[] array = null;
			IntPtr referrals = (IntPtr)0;
			int num = Wldap32.ldap_parse_reference(ldapHandle, referenceMessage, ref referrals);
			try
			{
				if (num == 0)
				{
					IntPtr intPtr = (IntPtr)0;
					int num2 = 0;
					if (referrals != (IntPtr)0)
					{
						intPtr = Marshal.ReadIntPtr(referrals, Marshal.SizeOf(typeof(IntPtr)) * num2);
						while (intPtr != (IntPtr)0)
						{
							string value = Marshal.PtrToStringUni(intPtr);
							arrayList.Add(value);
							num2++;
							intPtr = Marshal.ReadIntPtr(referrals, Marshal.SizeOf(typeof(IntPtr)) * num2);
						}
						Wldap32.ldap_value_free(referrals);
						referrals = (IntPtr)0;
					}
					if (arrayList.Count > 0)
					{
						array = new Uri[arrayList.Count];
						for (int i = 0; i < arrayList.Count; i++)
						{
							array[i] = new Uri((string)arrayList[i]);
						}
						return new SearchResultReference(array);
					}
					return result;
				}
				return result;
			}
			finally
			{
				if (referrals != (IntPtr)0)
				{
					Wldap32.ldap_value_free(referrals);
				}
			}
		}

		private DirectoryException ConstructException(int error, LdapOperation operation)
		{
			DirectoryResponse response = null;
			if (Utility.IsResultCode((ResultCode)error))
			{
				switch (operation)
				{
				case LdapOperation.LdapAdd:
					response = new AddResponse(null, null, (ResultCode)error, OperationErrorMappings.MapResultCode(error), null);
					break;
				case LdapOperation.LdapModify:
					response = new ModifyResponse(null, null, (ResultCode)error, OperationErrorMappings.MapResultCode(error), null);
					break;
				case LdapOperation.LdapDelete:
					response = new DeleteResponse(null, null, (ResultCode)error, OperationErrorMappings.MapResultCode(error), null);
					break;
				case LdapOperation.LdapModifyDn:
					response = new ModifyDNResponse(null, null, (ResultCode)error, OperationErrorMappings.MapResultCode(error), null);
					break;
				case LdapOperation.LdapCompare:
					response = new CompareResponse(null, null, (ResultCode)error, OperationErrorMappings.MapResultCode(error), null);
					break;
				case LdapOperation.LdapSearch:
					response = new SearchResponse(null, null, (ResultCode)error, OperationErrorMappings.MapResultCode(error), null);
					break;
				case LdapOperation.LdapExtendedRequest:
					response = new ExtendedResponse(null, null, (ResultCode)error, OperationErrorMappings.MapResultCode(error), null);
					break;
				}
				string message = OperationErrorMappings.MapResultCode(error);
				return new DirectoryOperationException(response, message);
			}
			if (Utility.IsLdapError((LdapError)error))
			{
				string message2 = LdapErrorMappings.MapResultCode(error);
				string serverErrorMessage = options.ServerErrorMessage;
				if (serverErrorMessage != null && serverErrorMessage.Length > 0)
				{
					throw new LdapException(error, message2, serverErrorMessage);
				}
				return new LdapException(error, message2);
			}
			return new LdapException(error);
		}

		private DirectoryControl ConstructControl(IntPtr controlPtr)
		{
			LdapControl ldapControl = new LdapControl();
			Marshal.PtrToStructure(controlPtr, ldapControl);
			string type = Marshal.PtrToStringUni(ldapControl.ldctl_oid);
			byte[] array = new byte[ldapControl.ldctl_value.bv_len];
			Marshal.Copy(ldapControl.ldctl_value.bv_val, array, 0, ldapControl.ldctl_value.bv_len);
			bool ldctl_iscritical = ldapControl.ldctl_iscritical;
			return new DirectoryControl(type, array, ldctl_iscritical, serverSide: true);
		}

		private bool SameCredential(NetworkCredential oldCredential, NetworkCredential newCredential)
		{
			if (oldCredential == null && newCredential == null)
			{
				return true;
			}
			if (oldCredential == null && newCredential != null)
			{
				return false;
			}
			if (oldCredential != null && newCredential == null)
			{
				return false;
			}
			if (oldCredential.Domain == newCredential.Domain && oldCredential.UserName == newCredential.UserName && oldCredential.Password == newCredential.Password)
			{
				return true;
			}
			return false;
		}
	}
	public class LdapDirectoryIdentifier : DirectoryIdentifier
	{
		private string[] servers;

		private bool fullyQualifiedDnsHostName;

		private bool connectionless;

		private int portNumber = 389;

		public string[] Servers
		{
			get
			{
				if (servers == null)
				{
					return new string[0];
				}
				string[] array = new string[servers.Length];
				for (int i = 0; i < servers.Length; i++)
				{
					if (servers[i] != null)
					{
						array[i] = string.Copy(servers[i]);
					}
					else
					{
						array[i] = null;
					}
				}
				return array;
			}
		}

		public bool Connectionless => connectionless;

		public bool FullyQualifiedDnsHostName => fullyQualifiedDnsHostName;

		public int PortNumber => portNumber;

		public LdapDirectoryIdentifier(string server)
			: this((server != null) ? new string[1] { server } : null, fullyQualifiedDnsHostName: false, connectionless: false)
		{
		}

		public LdapDirectoryIdentifier(string server, int portNumber)
			: this((server != null) ? new string[1] { server } : null, portNumber, fullyQualifiedDnsHostName: false, connectionless: false)
		{
		}

		public LdapDirectoryIdentifier(string server, bool fullyQualifiedDnsHostName, bool connectionless)
			: this((server != null) ? new string[1] { server } : null, fullyQualifiedDnsHostName, connectionless)
		{
		}

		public LdapDirectoryIdentifier(string server, int portNumber, bool fullyQualifiedDnsHostName, bool connectionless)
			: this((server != null) ? new string[1] { server } : null, portNumber, fullyQualifiedDnsHostName, connectionless)
		{
		}

		public LdapDirectoryIdentifier(string[] servers, bool fullyQualifiedDnsHostName, bool connectionless)
		{
			if (servers != null)
			{
				this.servers = new string[servers.Length];
				for (int i = 0; i < servers.Length; i++)
				{
					if (servers[i] != null)
					{
						string text = servers[i].Trim();
						string[] array = text.Split(' ');
						if (array.Length > 1)
						{
							throw new ArgumentException(Res.GetString("WhiteSpaceServerName"));
						}
						this.servers[i] = text;
					}
				}
			}
			this.fullyQualifiedDnsHostName = fullyQualifiedDnsHostName;
			this.connectionless = connectionless;
		}

		public LdapDirectoryIdentifier(string[] servers, int portNumber, bool fullyQualifiedDnsHostName, bool connectionless)
			: this(servers, fullyQualifiedDnsHostName, connectionless)
		{
			this.portNumber = portNumber;
		}
	}
	internal enum LdapError
	{
		IsLeaf = 35,
		InvalidCredentials = 49,
		ServerDown = 81,
		LocalError = 82,
		EncodingError = 83,
		DecodingError = 84,
		TimeOut = 85,
		AuthUnknown = 86,
		FilterError = 87,
		UserCancelled = 88,
		ParameterError = 89,
		NoMemory = 90,
		ConnectError = 91,
		NotSupported = 92,
		NoResultsReturned = 94,
		ControlNotFound = 93,
		MoreResults = 95,
		ClientLoop = 96,
		ReferralLimitExceeded = 97,
		SendTimeOut = 112
	}
	internal class LdapErrorMappings
	{
		private static Hashtable ResultCodeHash;

		static LdapErrorMappings()
		{
			ResultCodeHash = new Hashtable();
			ResultCodeHash.Add(LdapError.IsLeaf, Res.GetString("LDAP_IS_LEAF"));
			ResultCodeHash.Add(LdapError.InvalidCredentials, Res.GetString("LDAP_INVALID_CREDENTIALS"));
			ResultCodeHash.Add(LdapError.ServerDown, Res.GetString("LDAP_SERVER_DOWN"));
			ResultCodeHash.Add(LdapError.LocalError, Res.GetString("LDAP_LOCAL_ERROR"));
			ResultCodeHash.Add(LdapError.EncodingError, Res.GetString("LDAP_ENCODING_ERROR"));
			ResultCodeHash.Add(LdapError.DecodingError, Res.GetString("LDAP_DECODING_ERROR"));
			ResultCodeHash.Add(LdapError.TimeOut, Res.GetString("LDAP_TIMEOUT"));
			ResultCodeHash.Add(LdapError.AuthUnknown, Res.GetString("LDAP_AUTH_UNKNOWN"));
			ResultCodeHash.Add(LdapError.FilterError, Res.GetString("LDAP_FILTER_ERROR"));
			ResultCodeHash.Add(LdapError.UserCancelled, Res.GetString("LDAP_USER_CANCELLED"));
			ResultCodeHash.Add(LdapError.ParameterError, Res.GetString("LDAP_PARAM_ERROR"));
			ResultCodeHash.Add(LdapError.NoMemory, Res.GetString("LDAP_NO_MEMORY"));
			ResultCodeHash.Add(LdapError.ConnectError, Res.GetString("LDAP_CONNECT_ERROR"));
			ResultCodeHash.Add(LdapError.NotSupported, Res.GetString("LDAP_NOT_SUPPORTED"));
			ResultCodeHash.Add(LdapError.NoResultsReturned, Res.GetString("LDAP_NO_RESULTS_RETURNED"));
			ResultCodeHash.Add(LdapError.ControlNotFound, Res.GetString("LDAP_CONTROL_NOT_FOUND"));
			ResultCodeHash.Add(LdapError.MoreResults, Res.GetString("LDAP_MORE_RESULTS_TO_RETURN"));
			ResultCodeHash.Add(LdapError.ClientLoop, Res.GetString("LDAP_CLIENT_LOOP"));
			ResultCodeHash.Add(LdapError.ReferralLimitExceeded, Res.GetString("LDAP_REFERRAL_LIMIT_EXCEEDED"));
			ResultCodeHash.Add(LdapError.SendTimeOut, Res.GetString("LDAP_SEND_TIMEOUT"));
		}

		public static string MapResultCode(int errorCode)
		{
			return (string)ResultCodeHash[(LdapError)errorCode];
		}
	}
	[Serializable]
	public class LdapException : DirectoryException, ISerializable
	{
		private int errorCode;

		private string serverErrorMessage;

		internal PartialResultsCollection results = new PartialResultsCollection();

		public int ErrorCode => errorCode;

		public string ServerErrorMessage => serverErrorMessage;

		public PartialResultsCollection PartialResults => results;

		protected LdapException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		public LdapException()
		{
		}

		public LdapException(string message)
			: base(message)
		{
		}

		public LdapException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public LdapException(int errorCode)
			: base(Res.GetString("DefaultLdapError"))
		{
			this.errorCode = errorCode;
		}

		public LdapException(int errorCode, string message)
			: base(message)
		{
			this.errorCode = errorCode;
		}

		public LdapException(int errorCode, string message, string serverErrorMessage)
			: base(message)
		{
			this.errorCode = errorCode;
			this.serverErrorMessage = serverErrorMessage;
		}

		public LdapException(int errorCode, string message, Exception inner)
			: base(message, inner)
		{
			this.errorCode = errorCode;
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	[Serializable]
	public class TlsOperationException : DirectoryOperationException
	{
		protected TlsOperationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		public TlsOperationException()
		{
		}

		public TlsOperationException(string message)
			: base(message)
		{
		}

		public TlsOperationException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public TlsOperationException(DirectoryResponse response)
			: base(response)
		{
		}

		public TlsOperationException(DirectoryResponse response, string message)
			: base(response, message)
		{
		}

		public TlsOperationException(DirectoryResponse response, string message, Exception inner)
			: base(response, message, inner)
		{
		}
	}
	internal class ErrorChecking
	{
		public static void CheckAndSetLdapError(int error)
		{
			if (error != 0)
			{
				if (Utility.IsResultCode((ResultCode)error))
				{
					string message = OperationErrorMappings.MapResultCode(error);
					throw new DirectoryOperationException(null, message);
				}
				if (Utility.IsLdapError((LdapError)error))
				{
					string message = LdapErrorMappings.MapResultCode(error);
					throw new LdapException(error, message);
				}
				throw new LdapException(error);
			}
		}
	}
	internal class LdapPartialResultsProcessor
	{
		private ArrayList resultList;

		private ManualResetEvent workThreadWaitHandle;

		private bool workToDo;

		private int currentIndex;

		internal LdapPartialResultsProcessor(ManualResetEvent eventHandle)
		{
			resultList = new ArrayList();
			workThreadWaitHandle = eventHandle;
		}

		public void Add(LdapPartialAsyncResult asyncResult)
		{
			lock (this)
			{
				resultList.Add(asyncResult);
				if (!workToDo)
				{
					workThreadWaitHandle.Set();
					workToDo = true;
				}
			}
		}

		public void Remove(LdapPartialAsyncResult asyncResult)
		{
			lock (this)
			{
				if (!resultList.Contains(asyncResult))
				{
					throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
				}
				resultList.Remove(asyncResult);
			}
		}

		public void RetrievingSearchResults()
		{
			int num = 0;
			int num2 = 0;
			LdapPartialAsyncResult ldapPartialAsyncResult = null;
			AsyncCallback asyncCallback = null;
			lock (this)
			{
				num = resultList.Count;
				if (num == 0)
				{
					workThreadWaitHandle.Reset();
					workToDo = false;
					return;
				}
				while (true)
				{
					if (currentIndex >= num)
					{
						currentIndex = 0;
					}
					ldapPartialAsyncResult = (LdapPartialAsyncResult)resultList[currentIndex];
					num2++;
					currentIndex++;
					if (ldapPartialAsyncResult.resultStatus != ResultsStatus.Done)
					{
						break;
					}
					if (num2 >= num)
					{
						workToDo = false;
						workThreadWaitHandle.Reset();
						return;
					}
				}
				GetResultsHelper(ldapPartialAsyncResult);
				if (ldapPartialAsyncResult.resultStatus == ResultsStatus.Done)
				{
					ldapPartialAsyncResult.manualResetEvent.Set();
					ldapPartialAsyncResult.completed = true;
					if (ldapPartialAsyncResult.callback != null)
					{
						asyncCallback = ldapPartialAsyncResult.callback;
					}
				}
				else if (ldapPartialAsyncResult.callback != null && ldapPartialAsyncResult.partialCallback && ldapPartialAsyncResult.response != null && (ldapPartialAsyncResult.response.Entries.Count > 0 || ldapPartialAsyncResult.response.References.Count > 0))
				{
					asyncCallback = ldapPartialAsyncResult.callback;
				}
			}
			asyncCallback?.Invoke(ldapPartialAsyncResult);
		}

		private void GetResultsHelper(LdapPartialAsyncResult asyncResult)
		{
			LdapConnection con = asyncResult.con;
			_ = con.ldapHandle;
			_ = (IntPtr)0;
			_ = (IntPtr)0;
			ResultAll resultType = ResultAll.LDAP_MSG_RECEIVED;
			if (asyncResult.resultStatus == ResultsStatus.CompleteResult)
			{
				resultType = ResultAll.LDAP_MSG_POLLINGALL;
			}
			try
			{
				SearchResponse searchResponse = (SearchResponse)con.ConstructResponse(asyncResult.messageID, LdapOperation.LdapSearch, resultType, asyncResult.requestTimeout, exceptionOnTimeOut: false);
				if (searchResponse == null)
				{
					if (asyncResult.startTime.Ticks + asyncResult.requestTimeout.Ticks <= DateTime.Now.Ticks)
					{
						throw new LdapException(85, LdapErrorMappings.MapResultCode(85));
					}
					return;
				}
				if (asyncResult.response != null)
				{
					AddResult(asyncResult.response, searchResponse);
				}
				else
				{
					asyncResult.response = searchResponse;
				}
				if (searchResponse.searchDone)
				{
					asyncResult.resultStatus = ResultsStatus.Done;
				}
			}
			catch (Exception ex)
			{
				if (ex is DirectoryOperationException)
				{
					SearchResponse searchResponse2 = (SearchResponse)((DirectoryOperationException)ex).Response;
					if (asyncResult.response != null)
					{
						AddResult(asyncResult.response, searchResponse2);
					}
					else
					{
						asyncResult.response = searchResponse2;
					}
					((DirectoryOperationException)ex).response = asyncResult.response;
				}
				else if (ex is LdapException)
				{
					LdapException ex2 = (LdapException)ex;
					_ = ex2.ErrorCode;
					if (asyncResult.response != null)
					{
						if (asyncResult.response.Entries != null)
						{
							for (int i = 0; i < asyncResult.response.Entries.Count; i++)
							{
								ex2.results.Add(asyncResult.response.Entries[i]);
							}
						}
						if (asyncResult.response.References != null)
						{
							for (int j = 0; j < asyncResult.response.References.Count; j++)
							{
								ex2.results.Add(asyncResult.response.References[j]);
							}
						}
					}
				}
				asyncResult.exception = ex;
				asyncResult.resultStatus = ResultsStatus.Done;
				Wldap32.ldap_abandon(con.ldapHandle, asyncResult.messageID);
			}
			catch
			{
				asyncResult.exception = new Exception(Res.GetString("NonCLSException"));
				asyncResult.resultStatus = ResultsStatus.Done;
				Wldap32.ldap_abandon(con.ldapHandle, asyncResult.messageID);
			}
		}

		public void NeedCompleteResult(LdapPartialAsyncResult asyncResult)
		{
			lock (this)
			{
				if (resultList.Contains(asyncResult))
				{
					if (asyncResult.resultStatus == ResultsStatus.PartialResult)
					{
						asyncResult.resultStatus = ResultsStatus.CompleteResult;
					}
					return;
				}
				throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
			}
		}

		public PartialResultsCollection GetPartialResults(LdapPartialAsyncResult asyncResult)
		{
			lock (this)
			{
				if (!resultList.Contains(asyncResult))
				{
					throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
				}
				if (asyncResult.exception != null)
				{
					resultList.Remove(asyncResult);
					throw asyncResult.exception;
				}
				PartialResultsCollection partialResultsCollection = new PartialResultsCollection();
				if (asyncResult.response != null)
				{
					if (asyncResult.response.Entries != null)
					{
						for (int i = 0; i < asyncResult.response.Entries.Count; i++)
						{
							partialResultsCollection.Add(asyncResult.response.Entries[i]);
						}
						asyncResult.response.Entries.Clear();
					}
					if (asyncResult.response.References != null)
					{
						for (int j = 0; j < asyncResult.response.References.Count; j++)
						{
							partialResultsCollection.Add(asyncResult.response.References[j]);
						}
						asyncResult.response.References.Clear();
					}
				}
				return partialResultsCollection;
			}
		}

		public DirectoryResponse GetCompleteResult(LdapPartialAsyncResult asyncResult)
		{
			lock (this)
			{
				if (!resultList.Contains(asyncResult))
				{
					throw new ArgumentException(Res.GetString("InvalidAsyncResult"));
				}
				resultList.Remove(asyncResult);
				if (asyncResult.exception != null)
				{
					throw asyncResult.exception;
				}
				return asyncResult.response;
			}
		}

		private void AddResult(SearchResponse partialResults, SearchResponse newResult)
		{
			if (newResult == null)
			{
				return;
			}
			if (newResult.Entries != null)
			{
				for (int i = 0; i < newResult.Entries.Count; i++)
				{
					partialResults.Entries.Add(newResult.Entries[i]);
				}
			}
			if (newResult.References != null)
			{
				for (int j = 0; j < newResult.References.Count; j++)
				{
					partialResults.References.Add(newResult.References[j]);
				}
			}
		}
	}
	internal class PartialResultsRetriever
	{
		private ManualResetEvent workThreadWaitHandle;

		private Thread oThread;

		private LdapPartialResultsProcessor processor;

		internal PartialResultsRetriever(ManualResetEvent eventHandle, LdapPartialResultsProcessor processor)
		{
			workThreadWaitHandle = eventHandle;
			this.processor = processor;
			oThread = new Thread(ThreadRoutine);
			oThread.IsBackground = true;
			oThread.Start();
		}

		private void ThreadRoutine()
		{
			while (true)
			{
				workThreadWaitHandle.WaitOne();
				try
				{
					processor.RetrievingSearchResults();
				}
				catch (Exception)
				{
				}
				catch
				{
				}
				Thread.Sleep(250);
			}
		}
	}
	public delegate LdapConnection QueryForConnectionCallback(LdapConnection primaryConnection, LdapConnection referralFromConnection, string newDistinguishedName, LdapDirectoryIdentifier identifier, NetworkCredential credential, long currentUserToken);
	public delegate bool NotifyOfNewConnectionCallback(LdapConnection primaryConnection, LdapConnection referralFromConnection, string newDistinguishedName, LdapDirectoryIdentifier identifier, LdapConnection newConnection, NetworkCredential credential, long currentUserToken, int errorCodeFromBind);
	public delegate void DereferenceConnectionCallback(LdapConnection primaryConnection, LdapConnection connectionToDereference);
	public delegate X509Certificate QueryClientCertificateCallback(LdapConnection connection, byte[][] trustedCAs);
	public delegate bool VerifyServerCertificateCallback(LdapConnection connection, X509Certificate certificate);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal delegate int QUERYFORCONNECTIONInternal(IntPtr Connection, IntPtr ReferralFromConnection, IntPtr NewDNPtr, string HostName, int PortNumber, SEC_WINNT_AUTH_IDENTITY_EX SecAuthIdentity, Luid CurrentUserToken, ref IntPtr ConnectionToUse);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal delegate bool NOTIFYOFNEWCONNECTIONInternal(IntPtr Connection, IntPtr ReferralFromConnection, IntPtr NewDNPtr, string HostName, IntPtr NewConnection, int PortNumber, SEC_WINNT_AUTH_IDENTITY_EX SecAuthIdentity, Luid CurrentUser, int ErrorCodeFromBind);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal delegate int DEREFERENCECONNECTIONInternal(IntPtr Connection, IntPtr ConnectionToDereference);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal delegate bool VERIFYSERVERCERT(IntPtr Connection, IntPtr pServerCert);
	[Flags]
	public enum LocatorFlags : long
	{
		None = 0L,
		ForceRediscovery = 1L,
		DirectoryServicesRequired = 0x10L,
		DirectoryServicesPreferred = 0x20L,
		GCRequired = 0x40L,
		PdcRequired = 0x80L,
		IPRequired = 0x200L,
		KdcRequired = 0x400L,
		TimeServerRequired = 0x800L,
		WriteableRequired = 0x1000L,
		GoodTimeServerPreferred = 0x2000L,
		AvoidSelf = 0x4000L,
		OnlyLdapNeeded = 0x8000L,
		IsFlatName = 0x10000L,
		IsDnsName = 0x20000L,
		ReturnDnsName = 0x40000000L,
		ReturnFlatName = 0x80000000L
	}
	public enum SecurityProtocol
	{
		Pct1Server = 1,
		Pct1Client = 2,
		Ssl2Server = 4,
		Ssl2Client = 8,
		Ssl3Server = 0x10,
		Ssl3Client = 0x20,
		Tls1Server = 0x40,
		Tls1Client = 0x80
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public class SecurityPackageContextConnectionInformation
	{
		private SecurityProtocol securityProtocol;

		private CipherAlgorithmType identifier;

		private int strength;

		private HashAlgorithmType hashAlgorithm;

		private int hashStrength;

		private int keyExchangeAlgorithm;

		private int exchangeStrength;

		public SecurityProtocol Protocol => securityProtocol;

		public CipherAlgorithmType AlgorithmIdentifier => identifier;

		public int CipherStrength => strength;

		public HashAlgorithmType Hash => hashAlgorithm;

		public int HashStrength => hashStrength;

		public int KeyExchangeAlgorithm => keyExchangeAlgorithm;

		public int ExchangeStrength => exchangeStrength;

		internal SecurityPackageContextConnectionInformation()
		{
		}
	}
	public sealed class ReferralCallback
	{
		private QueryForConnectionCallback query;

		private NotifyOfNewConnectionCallback notify;

		private DereferenceConnectionCallback dereference;

		public QueryForConnectionCallback QueryForConnection
		{
			get
			{
				return query;
			}
			set
			{
				query = value;
			}
		}

		public NotifyOfNewConnectionCallback NotifyNewConnection
		{
			get
			{
				return notify;
			}
			set
			{
				notify = value;
			}
		}

		public DereferenceConnectionCallback DereferenceConnection
		{
			get
			{
				return dereference;
			}
			set
			{
				dereference = value;
			}
		}

		public ReferralCallback()
		{
			Utility.CheckOSVersion();
		}
	}
	internal struct SecurityHandle
	{
		public IntPtr Lower;

		public IntPtr Upper;
	}
	public class LdapSessionOptions
	{
		private LdapConnection connection;

		private ReferralCallback callbackRoutine = new ReferralCallback();

		internal QueryClientCertificateCallback clientCertificateDelegate;

		private VerifyServerCertificateCallback serverCertificateDelegate;

		private QUERYFORCONNECTIONInternal queryDelegate;

		private NOTIFYOFNEWCONNECTIONInternal notifiyDelegate;

		private DEREFERENCECONNECTIONInternal dereferenceDelegate;

		private VERIFYSERVERCERT serverCertificateRoutine;

		public ReferralChasingOptions ReferralChasing
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_REFERRALS);
				if (intValueHelper == 1)
				{
					return ReferralChasingOptions.All;
				}
				return (ReferralChasingOptions)intValueHelper;
			}
			set
			{
				if (((uint)value & 0xFFFFFF9Fu) != 0)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ReferralChasingOptions));
				}
				SetIntValueHelper(LdapOption.LDAP_OPT_REFERRALS, (int)value);
			}
		}

		public bool SecureSocketLayer
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_SSL);
				if (intValueHelper == 1)
				{
					return true;
				}
				return false;
			}
			set
			{
				int value2 = (value ? 1 : 0);
				SetIntValueHelper(LdapOption.LDAP_OPT_SSL, value2);
			}
		}

		public int ReferralHopLimit
		{
			get
			{
				return GetIntValueHelper(LdapOption.LDAP_OPT_REFERRAL_HOP_LIMIT);
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				SetIntValueHelper(LdapOption.LDAP_OPT_REFERRAL_HOP_LIMIT, value);
			}
		}

		public int ProtocolVersion
		{
			get
			{
				return GetIntValueHelper(LdapOption.LDAP_OPT_VERSION);
			}
			set
			{
				SetIntValueHelper(LdapOption.LDAP_OPT_VERSION, value);
			}
		}

		public string HostName
		{
			get
			{
				return GetStringValueHelper(LdapOption.LDAP_OPT_HOST_NAME, releasePtr: false);
			}
			set
			{
				SetStringValueHelper(LdapOption.LDAP_OPT_HOST_NAME, value);
			}
		}

		public string DomainName
		{
			get
			{
				return GetStringValueHelper(LdapOption.LDAP_OPT_DNSDOMAIN_NAME, releasePtr: true);
			}
			set
			{
				SetStringValueHelper(LdapOption.LDAP_OPT_DNSDOMAIN_NAME, value);
			}
		}

		public LocatorFlags LocatorFlag
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_GETDSNAME_FLAGS);
				return (LocatorFlags)intValueHelper;
			}
			set
			{
				SetIntValueHelper(LdapOption.LDAP_OPT_GETDSNAME_FLAGS, (int)value);
			}
		}

		public bool HostReachable
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_HOST_REACHABLE);
				if (intValueHelper == 1)
				{
					return true;
				}
				return false;
			}
		}

		public TimeSpan PingKeepAliveTimeout
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_PING_KEEP_ALIVE);
				return new TimeSpan((long)intValueHelper * 10000000L);
			}
			set
			{
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				if (value.TotalSeconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				int value2 = (int)(value.Ticks / 10000000);
				SetIntValueHelper(LdapOption.LDAP_OPT_PING_KEEP_ALIVE, value2);
			}
		}

		public int PingLimit
		{
			get
			{
				return GetIntValueHelper(LdapOption.LDAP_OPT_PING_LIMIT);
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("ValidValue"), "value");
				}
				SetIntValueHelper(LdapOption.LDAP_OPT_PING_LIMIT, value);
			}
		}

		public TimeSpan PingWaitTimeout
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_PING_WAIT_TIME);
				return new TimeSpan((long)intValueHelper * 10000L);
			}
			set
			{
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				if (value.TotalMilliseconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				int value2 = (int)(value.Ticks / 10000);
				SetIntValueHelper(LdapOption.LDAP_OPT_PING_WAIT_TIME, value2);
			}
		}

		public bool AutoReconnect
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_AUTO_RECONNECT);
				if (intValueHelper == 1)
				{
					return true;
				}
				return false;
			}
			set
			{
				int value2 = (value ? 1 : 0);
				SetIntValueHelper(LdapOption.LDAP_OPT_AUTO_RECONNECT, value2);
			}
		}

		public int SspiFlag
		{
			get
			{
				return GetIntValueHelper(LdapOption.LDAP_OPT_SSPI_FLAGS);
			}
			set
			{
				SetIntValueHelper(LdapOption.LDAP_OPT_SSPI_FLAGS, value);
			}
		}

		public SecurityPackageContextConnectionInformation SslInformation
		{
			get
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				SecurityPackageContextConnectionInformation securityPackageContextConnectionInformation = new SecurityPackageContextConnectionInformation();
				int error = Wldap32.ldap_get_option_secInfo(connection.ldapHandle, LdapOption.LDAP_OPT_SSL_INFO, securityPackageContextConnectionInformation);
				ErrorChecking.CheckAndSetLdapError(error);
				return securityPackageContextConnectionInformation;
			}
		}

		public object SecurityContext
		{
			get
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				SecurityHandle outValue = default(SecurityHandle);
				int error = Wldap32.ldap_get_option_sechandle(connection.ldapHandle, LdapOption.LDAP_OPT_SECURITY_CONTEXT, ref outValue);
				ErrorChecking.CheckAndSetLdapError(error);
				return outValue;
			}
		}

		public bool Signing
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_SIGN);
				if (intValueHelper == 1)
				{
					return true;
				}
				return false;
			}
			set
			{
				int value2 = (value ? 1 : 0);
				SetIntValueHelper(LdapOption.LDAP_OPT_SIGN, value2);
			}
		}

		public bool Sealing
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_ENCRYPT);
				if (intValueHelper == 1)
				{
					return true;
				}
				return false;
			}
			set
			{
				int value2 = (value ? 1 : 0);
				SetIntValueHelper(LdapOption.LDAP_OPT_ENCRYPT, value2);
			}
		}

		public string SaslMethod
		{
			get
			{
				return GetStringValueHelper(LdapOption.LDAP_OPT_SASL_METHOD, releasePtr: true);
			}
			set
			{
				SetStringValueHelper(LdapOption.LDAP_OPT_SASL_METHOD, value);
			}
		}

		public bool RootDseCache
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_ROOTDSE_CACHE);
				if (intValueHelper == 1)
				{
					return true;
				}
				return false;
			}
			set
			{
				int value2 = (value ? 1 : 0);
				SetIntValueHelper(LdapOption.LDAP_OPT_ROOTDSE_CACHE, value2);
			}
		}

		public bool TcpKeepAlive
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_TCP_KEEPALIVE);
				if (intValueHelper == 1)
				{
					return true;
				}
				return false;
			}
			set
			{
				int value2 = (value ? 1 : 0);
				SetIntValueHelper(LdapOption.LDAP_OPT_TCP_KEEPALIVE, value2);
			}
		}

		public TimeSpan SendTimeout
		{
			get
			{
				int intValueHelper = GetIntValueHelper(LdapOption.LDAP_OPT_SEND_TIMEOUT);
				return new TimeSpan((long)intValueHelper * 10000000L);
			}
			set
			{
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				if (value.TotalSeconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				int value2 = (int)(value.Ticks / 10000000);
				SetIntValueHelper(LdapOption.LDAP_OPT_SEND_TIMEOUT, value2);
			}
		}

		public ReferralCallback ReferralCallback
		{
			get
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return callbackRoutine;
			}
			set
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				ReferralCallback referralCallback = new ReferralCallback();
				if (value != null)
				{
					referralCallback.QueryForConnection = value.QueryForConnection;
					referralCallback.NotifyNewConnection = value.NotifyNewConnection;
					referralCallback.DereferenceConnection = value.DereferenceConnection;
				}
				else
				{
					referralCallback.QueryForConnection = null;
					referralCallback.NotifyNewConnection = null;
					referralCallback.DereferenceConnection = null;
				}
				ProcessCallBackRoutine(referralCallback);
				callbackRoutine = value;
			}
		}

		public QueryClientCertificateCallback QueryClientCertificate
		{
			get
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return clientCertificateDelegate;
			}
			set
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (value != null)
				{
					int num = Wldap32.ldap_set_option_clientcert(connection.ldapHandle, LdapOption.LDAP_OPT_CLIENT_CERTIFICATE, connection.clientCertificateRoutine);
					if (num != 0)
					{
						if (Utility.IsLdapError((LdapError)num))
						{
							string message = LdapErrorMappings.MapResultCode(num);
							throw new LdapException(num, message);
						}
						throw new LdapException(num);
					}
					connection.automaticBind = false;
				}
				clientCertificateDelegate = value;
			}
		}

		public VerifyServerCertificateCallback VerifyServerCertificate
		{
			get
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return serverCertificateDelegate;
			}
			set
			{
				if (connection.disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (value != null)
				{
					int error = Wldap32.ldap_set_option_servercert(connection.ldapHandle, LdapOption.LDAP_OPT_SERVER_CERTIFICATE, serverCertificateRoutine);
					ErrorChecking.CheckAndSetLdapError(error);
				}
				serverCertificateDelegate = value;
			}
		}

		internal string ServerErrorMessage => GetStringValueHelper(LdapOption.LDAP_OPT_SERVER_ERROR, releasePtr: true);

		internal DereferenceAlias DerefAlias
		{
			get
			{
				return (DereferenceAlias)GetIntValueHelper(LdapOption.LDAP_OPT_DEREF);
			}
			set
			{
				SetIntValueHelper(LdapOption.LDAP_OPT_DEREF, (int)value);
			}
		}

		internal bool FQDN
		{
			set
			{
				SetIntValueHelper(LdapOption.LDAP_OPT_AREC_EXCLUSIVE, 1);
			}
		}

		internal LdapSessionOptions(LdapConnection connection)
		{
			this.connection = connection;
			queryDelegate = ProcessQueryConnection;
			notifiyDelegate = ProcessNotifyConnection;
			dereferenceDelegate = ProcessDereferenceConnection;
			serverCertificateRoutine = ProcessServerCertificate;
		}

		public void FastConcurrentBind()
		{
			if (connection.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			int inValue = 1;
			ProtocolVersion = 3;
			int num = Wldap32.ldap_set_option_int(connection.ldapHandle, LdapOption.LDAP_OPT_FAST_CONCURRENT_BIND, ref inValue);
			if (num == 89 && !Utility.IsWin2k3AboveOS)
			{
				throw new PlatformNotSupportedException(Res.GetString("ConcurrentBindNotSupport"));
			}
			ErrorChecking.CheckAndSetLdapError(num);
		}

		public unsafe void StartTransportLayerSecurity(DirectoryControlCollection controls)
		{
			IntPtr intPtr = (IntPtr)0;
			LdapControl[] array = null;
			IntPtr intPtr2 = (IntPtr)0;
			LdapControl[] array2 = null;
			IntPtr Message = (IntPtr)0;
			IntPtr referral = (IntPtr)0;
			int ServerReturnValue = 0;
			Uri[] array3 = null;
			if (Utility.IsWin2kOS)
			{
				throw new PlatformNotSupportedException(Res.GetString("TLSNotSupported"));
			}
			if (connection.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				IntPtr intPtr3 = (IntPtr)0;
				IntPtr intPtr4 = (IntPtr)0;
				array = connection.BuildControlArray(controls, serverControl: true);
				int cb = Marshal.SizeOf(typeof(LdapControl));
				if (array != null)
				{
					intPtr = Utility.AllocHGlobalIntPtrArray(array.Length + 1);
					for (int i = 0; i < array.Length; i++)
					{
						intPtr3 = Marshal.AllocHGlobal(cb);
						Marshal.StructureToPtr(array[i], intPtr3, fDeleteOld: false);
						intPtr4 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * i);
						Marshal.WriteIntPtr(intPtr4, intPtr3);
					}
					intPtr4 = (IntPtr)((long)intPtr + Marshal.SizeOf(typeof(IntPtr)) * array.Length);
					Marshal.WriteIntPtr(intPtr4, (IntPtr)0);
				}
				array2 = connection.BuildControlArray(controls, serverControl: false);
				if (array2 != null)
				{
					intPtr2 = Utility.AllocHGlobalIntPtrArray(array2.Length + 1);
					for (int j = 0; j < array2.Length; j++)
					{
						intPtr3 = Marshal.AllocHGlobal(cb);
						Marshal.StructureToPtr(array2[j], intPtr3, fDeleteOld: false);
						intPtr4 = (IntPtr)((long)intPtr2 + Marshal.SizeOf(typeof(IntPtr)) * j);
						Marshal.WriteIntPtr(intPtr4, intPtr3);
					}
					intPtr4 = (IntPtr)((long)intPtr2 + Marshal.SizeOf(typeof(IntPtr)) * array2.Length);
					Marshal.WriteIntPtr(intPtr4, (IntPtr)0);
				}
				int num = Wldap32.ldap_start_tls(connection.ldapHandle, ref ServerReturnValue, ref Message, intPtr, intPtr2);
				if (Message != (IntPtr)0 && Wldap32.ldap_parse_result_referral(connection.ldapHandle, Message, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref referral, (IntPtr)0, 0) == 0 && referral != (IntPtr)0)
				{
					char** ptr = (char**)(void*)referral;
					char* ptr2 = *(char**)((byte*)ptr + 0);
					int num2 = 0;
					ArrayList arrayList = new ArrayList();
					while (ptr2 != null)
					{
						string value = Marshal.PtrToStringUni((IntPtr)ptr2);
						arrayList.Add(value);
						num2++;
						ptr2 = ptr[num2];
					}
					if (referral != (IntPtr)0)
					{
						Wldap32.ldap_value_free(referral);
						referral = (IntPtr)0;
					}
					if (arrayList.Count > 0)
					{
						array3 = new Uri[arrayList.Count];
						for (int k = 0; k < arrayList.Count; k++)
						{
							array3[k] = new Uri((string)arrayList[k]);
						}
					}
				}
				if (num == 0)
				{
					return;
				}
				string @string = Res.GetString("DefaultLdapError");
				if (Utility.IsResultCode((ResultCode)num))
				{
					if (num == 80)
					{
						num = ServerReturnValue;
					}
					@string = OperationErrorMappings.MapResultCode(num);
					ExtendedResponse extendedResponse = new ExtendedResponse(null, null, (ResultCode)num, @string, array3);
					extendedResponse.name = "1.3.6.1.4.1.1466.20037";
					throw new TlsOperationException(extendedResponse);
				}
				if (Utility.IsLdapError((LdapError)num))
				{
					@string = LdapErrorMappings.MapResultCode(num);
					throw new LdapException(num, @string);
				}
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					for (int l = 0; l < array.Length; l++)
					{
						IntPtr intPtr5 = Marshal.ReadIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * l);
						if (intPtr5 != (IntPtr)0)
						{
							Marshal.FreeHGlobal(intPtr5);
						}
					}
					Marshal.FreeHGlobal(intPtr);
				}
				if (array != null)
				{
					for (int m = 0; m < array.Length; m++)
					{
						if (array[m].ldctl_oid != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array[m].ldctl_oid);
						}
						if (array[m].ldctl_value != null && array[m].ldctl_value.bv_val != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array[m].ldctl_value.bv_val);
						}
					}
				}
				if (intPtr2 != (IntPtr)0)
				{
					for (int n = 0; n < array2.Length; n++)
					{
						IntPtr intPtr6 = Marshal.ReadIntPtr(intPtr2, Marshal.SizeOf(typeof(IntPtr)) * n);
						if (intPtr6 != (IntPtr)0)
						{
							Marshal.FreeHGlobal(intPtr6);
						}
					}
					Marshal.FreeHGlobal(intPtr2);
				}
				if (array2 != null)
				{
					for (int num3 = 0; num3 < array2.Length; num3++)
					{
						if (array2[num3].ldctl_oid != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array2[num3].ldctl_oid);
						}
						if (array2[num3].ldctl_value != null && array2[num3].ldctl_value.bv_val != (IntPtr)0)
						{
							Marshal.FreeHGlobal(array2[num3].ldctl_value.bv_val);
						}
					}
				}
				if (referral != (IntPtr)0)
				{
					Wldap32.ldap_value_free(referral);
				}
			}
		}

		public void StopTransportLayerSecurity()
		{
			if (Utility.IsWin2kOS)
			{
				throw new PlatformNotSupportedException(Res.GetString("TLSNotSupported"));
			}
			if (connection.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (Wldap32.ldap_stop_tls(connection.ldapHandle) == 0)
			{
				throw new TlsOperationException(null, Res.GetString("TLSStopFailure"));
			}
		}

		private int GetIntValueHelper(LdapOption option)
		{
			if (connection.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			int outValue = 0;
			int error = Wldap32.ldap_get_option_int(connection.ldapHandle, option, ref outValue);
			ErrorChecking.CheckAndSetLdapError(error);
			return outValue;
		}

		private void SetIntValueHelper(LdapOption option, int value)
		{
			if (connection.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			int inValue = value;
			int error = Wldap32.ldap_set_option_int(connection.ldapHandle, option, ref inValue);
			ErrorChecking.CheckAndSetLdapError(error);
		}

		private string GetStringValueHelper(LdapOption option, bool releasePtr)
		{
			if (connection.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			IntPtr outValue = new IntPtr(0);
			int error = Wldap32.ldap_get_option_ptr(connection.ldapHandle, option, ref outValue);
			ErrorChecking.CheckAndSetLdapError(error);
			string result = null;
			if (outValue != (IntPtr)0)
			{
				result = Marshal.PtrToStringUni(outValue);
			}
			if (releasePtr)
			{
				Wldap32.ldap_memfree(outValue);
			}
			return result;
		}

		private void SetStringValueHelper(LdapOption option, string value)
		{
			if (connection.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			IntPtr inValue = new IntPtr(0);
			if (value != null)
			{
				inValue = Marshal.StringToHGlobalUni(value);
			}
			try
			{
				int error = Wldap32.ldap_set_option_ptr(connection.ldapHandle, option, ref inValue);
				ErrorChecking.CheckAndSetLdapError(error);
			}
			finally
			{
				if (inValue != (IntPtr)0)
				{
					Marshal.FreeHGlobal(inValue);
				}
			}
		}

		private void ProcessCallBackRoutine(ReferralCallback tempCallback)
		{
			LdapReferralCallback outValue = default(LdapReferralCallback);
			outValue.sizeofcallback = Marshal.SizeOf(typeof(LdapReferralCallback));
			outValue.query = ((tempCallback.QueryForConnection == null) ? null : queryDelegate);
			outValue.notify = ((tempCallback.NotifyNewConnection == null) ? null : notifiyDelegate);
			outValue.dereference = ((tempCallback.DereferenceConnection == null) ? null : dereferenceDelegate);
			int error = Wldap32.ldap_set_option_referral(connection.ldapHandle, LdapOption.LDAP_OPT_REFERRAL_CALLBACK, ref outValue);
			ErrorChecking.CheckAndSetLdapError(error);
		}

		private int ProcessQueryConnection(IntPtr PrimaryConnection, IntPtr ReferralFromConnection, IntPtr NewDNPtr, string HostName, int PortNumber, SEC_WINNT_AUTH_IDENTITY_EX SecAuthIdentity, Luid CurrentUserToken, ref IntPtr ConnectionToUse)
		{
			ConnectionToUse = (IntPtr)0;
			string newDistinguishedName = null;
			if (callbackRoutine.QueryForConnection != null)
			{
				if (NewDNPtr != (IntPtr)0)
				{
					newDistinguishedName = Marshal.PtrToStringUni(NewDNPtr);
				}
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(HostName);
				stringBuilder.Append(":");
				stringBuilder.Append(PortNumber);
				LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(stringBuilder.ToString());
				NetworkCredential credential = ProcessSecAuthIdentity(SecAuthIdentity);
				LdapConnection ldapConnection = null;
				WeakReference weakReference = null;
				if (ReferralFromConnection != (IntPtr)0)
				{
					lock (LdapConnection.objectLock)
					{
						weakReference = (WeakReference)LdapConnection.handleTable[ReferralFromConnection];
						if (weakReference != null && weakReference.IsAlive)
						{
							ldapConnection = (LdapConnection)weakReference.Target;
						}
						else
						{
							if (weakReference != null)
							{
								LdapConnection.handleTable.Remove(ReferralFromConnection);
							}
							ldapConnection = new LdapConnection((LdapDirectoryIdentifier)connection.Directory, connection.GetCredential(), connection.AuthType, ReferralFromConnection);
							LdapConnection.handleTable.Add(ReferralFromConnection, new WeakReference(ldapConnection));
						}
					}
				}
				long currentUserToken = (uint)CurrentUserToken.LowPart + ((long)CurrentUserToken.HighPart << 32);
				LdapConnection ldapConnection2 = callbackRoutine.QueryForConnection(connection, ldapConnection, newDistinguishedName, identifier, credential, currentUserToken);
				if (ldapConnection2 != null)
				{
					ConnectionToUse = ldapConnection2.ldapHandle;
				}
				return 0;
			}
			return 1;
		}

		private bool ProcessNotifyConnection(IntPtr PrimaryConnection, IntPtr ReferralFromConnection, IntPtr NewDNPtr, string HostName, IntPtr NewConnection, int PortNumber, SEC_WINNT_AUTH_IDENTITY_EX SecAuthIdentity, Luid CurrentUser, int ErrorCodeFromBind)
		{
			string newDistinguishedName = null;
			if (NewConnection != (IntPtr)0 && callbackRoutine.NotifyNewConnection != null)
			{
				if (NewDNPtr != (IntPtr)0)
				{
					newDistinguishedName = Marshal.PtrToStringUni(NewDNPtr);
				}
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(HostName);
				stringBuilder.Append(":");
				stringBuilder.Append(PortNumber);
				LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(stringBuilder.ToString());
				NetworkCredential credential = ProcessSecAuthIdentity(SecAuthIdentity);
				LdapConnection ldapConnection = null;
				LdapConnection ldapConnection2 = null;
				WeakReference weakReference = null;
				lock (LdapConnection.objectLock)
				{
					if (ReferralFromConnection != (IntPtr)0)
					{
						weakReference = (WeakReference)LdapConnection.handleTable[ReferralFromConnection];
						if (weakReference != null && weakReference.IsAlive)
						{
							ldapConnection2 = (LdapConnection)weakReference.Target;
						}
						else
						{
							if (weakReference != null)
							{
								LdapConnection.handleTable.Remove(ReferralFromConnection);
							}
							ldapConnection2 = new LdapConnection((LdapDirectoryIdentifier)connection.Directory, connection.GetCredential(), connection.AuthType, ReferralFromConnection);
							LdapConnection.handleTable.Add(ReferralFromConnection, new WeakReference(ldapConnection2));
						}
					}
					if (NewConnection != (IntPtr)0)
					{
						weakReference = (WeakReference)LdapConnection.handleTable[NewConnection];
						if (weakReference != null && weakReference.IsAlive)
						{
							ldapConnection = (LdapConnection)weakReference.Target;
						}
						else
						{
							if (weakReference != null)
							{
								LdapConnection.handleTable.Remove(NewConnection);
							}
							ldapConnection = new LdapConnection(identifier, credential, connection.AuthType, NewConnection);
							LdapConnection.handleTable.Add(NewConnection, new WeakReference(ldapConnection));
						}
					}
				}
				long currentUserToken = (uint)CurrentUser.LowPart + ((long)CurrentUser.HighPart << 32);
				bool flag = callbackRoutine.NotifyNewConnection(connection, ldapConnection2, newDistinguishedName, identifier, ldapConnection, credential, currentUserToken, ErrorCodeFromBind);
				if (flag)
				{
					ldapConnection.needDispose = true;
				}
				return flag;
			}
			return false;
		}

		private int ProcessDereferenceConnection(IntPtr PrimaryConnection, IntPtr ConnectionToDereference)
		{
			if (ConnectionToDereference != (IntPtr)0 && callbackRoutine.DereferenceConnection != null)
			{
				LdapConnection ldapConnection = null;
				WeakReference weakReference = null;
				lock (LdapConnection.objectLock)
				{
					weakReference = (WeakReference)LdapConnection.handleTable[ConnectionToDereference];
				}
				ldapConnection = ((weakReference != null && weakReference.IsAlive) ? ((LdapConnection)weakReference.Target) : new LdapConnection((LdapDirectoryIdentifier)connection.Directory, connection.GetCredential(), connection.AuthType, ConnectionToDereference));
				callbackRoutine.DereferenceConnection(connection, ldapConnection);
			}
			return 1;
		}

		private NetworkCredential ProcessSecAuthIdentity(SEC_WINNT_AUTH_IDENTITY_EX SecAuthIdentit)
		{
			if (SecAuthIdentit == null)
			{
				return new NetworkCredential();
			}
			string user = SecAuthIdentit.user;
			string domain = SecAuthIdentit.domain;
			string password = SecAuthIdentit.password;
			return new NetworkCredential(user, password, domain);
		}

		private bool ProcessServerCertificate(IntPtr Connection, IntPtr pServerCert)
		{
			bool result = true;
			if (serverCertificateDelegate != null)
			{
				IntPtr intPtr = (IntPtr)0;
				X509Certificate certificate = null;
				try
				{
					intPtr = Marshal.ReadIntPtr(pServerCert);
					certificate = new X509Certificate(intPtr);
				}
				finally
				{
					Wldap32.CertFreeCRLContext(intPtr);
				}
				result = serverCertificateDelegate(connection, certificate);
			}
			return result;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal sealed class BerSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal BerSafeHandle()
			: base(ownsHandle: true)
		{
			SetHandle(Wldap32.ber_alloc(1));
			if (handle == (IntPtr)0)
			{
				throw new OutOfMemoryException();
			}
		}

		internal BerSafeHandle(berval value)
			: base(ownsHandle: true)
		{
			SetHandle(Wldap32.ber_init(value));
			if (handle == (IntPtr)0)
			{
				throw new BerConversionException();
			}
		}

		protected override bool ReleaseHandle()
		{
			Wldap32.ber_free(handle, 1);
			return true;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal sealed class HGlobalMemHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal HGlobalMemHandle(IntPtr value)
			: base(ownsHandle: true)
		{
			SetHandle(value);
		}

		protected override bool ReleaseHandle()
		{
			Marshal.FreeHGlobal(handle);
			return true;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal sealed class ConnectionHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal ConnectionHandle()
			: base(ownsHandle: true)
		{
			SetHandle(Wldap32.ldap_init(null, 389));
			if (handle == (IntPtr)0)
			{
				int num = Wldap32.LdapGetLastError();
				if (Utility.IsLdapError((LdapError)num))
				{
					string message = LdapErrorMappings.MapResultCode(num);
					throw new LdapException(num, message);
				}
				throw new LdapException(num);
			}
		}

		protected override bool ReleaseHandle()
		{
			Wldap32.ldap_unbind(handle);
			return true;
		}
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal class Luid
	{
		internal int lowPart;

		internal int highPart;

		public int LowPart => lowPart;

		public int HighPart => highPart;

		internal Luid()
		{
		}
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class SEC_WINNT_AUTH_IDENTITY_EX
	{
		public int version;

		public int length;

		public string user;

		public int userLength;

		public string domain;

		public int domainLength;

		public string password;

		public int passwordLength;

		public int flags;

		public string packageList;

		public int packageListLength;
	}
	internal enum BindMethod : uint
	{
		LDAP_AUTH_SIMPLE = 128u,
		LDAP_AUTH_SASL = 131u,
		LDAP_AUTH_OTHERKIND = 134u,
		LDAP_AUTH_SICILY = 646u,
		LDAP_AUTH_MSN = 2182u,
		LDAP_AUTH_NTLM = 4230u,
		LDAP_AUTH_DPA = 8326u,
		LDAP_AUTH_NEGOTIATE = 1158u,
		LDAP_AUTH_SSPI = 1158u,
		LDAP_AUTH_DIGEST = 16518u,
		LDAP_AUTH_EXTERNAL = 166u
	}
	internal enum LdapOption
	{
		LDAP_OPT_DESC = 1,
		LDAP_OPT_DEREF = 2,
		LDAP_OPT_SIZELIMIT = 3,
		LDAP_OPT_TIMELIMIT = 4,
		LDAP_OPT_REFERRALS = 8,
		LDAP_OPT_RESTART = 9,
		LDAP_OPT_SSL = 10,
		LDAP_OPT_REFERRAL_HOP_LIMIT = 16,
		LDAP_OPT_VERSION = 17,
		LDAP_OPT_API_FEATURE_INFO = 21,
		LDAP_OPT_HOST_NAME = 48,
		LDAP_OPT_ERROR_NUMBER = 49,
		LDAP_OPT_ERROR_STRING = 50,
		LDAP_OPT_SERVER_ERROR = 51,
		LDAP_OPT_SERVER_EXT_ERROR = 52,
		LDAP_OPT_HOST_REACHABLE = 62,
		LDAP_OPT_PING_KEEP_ALIVE = 54,
		LDAP_OPT_PING_WAIT_TIME = 55,
		LDAP_OPT_PING_LIMIT = 56,
		LDAP_OPT_DNSDOMAIN_NAME = 59,
		LDAP_OPT_GETDSNAME_FLAGS = 61,
		LDAP_OPT_PROMPT_CREDENTIALS = 63,
		LDAP_OPT_TCP_KEEPALIVE = 64,
		LDAP_OPT_FAST_CONCURRENT_BIND = 65,
		LDAP_OPT_SEND_TIMEOUT = 66,
		LDAP_OPT_REFERRAL_CALLBACK = 112,
		LDAP_OPT_CLIENT_CERTIFICATE = 128,
		LDAP_OPT_SERVER_CERTIFICATE = 129,
		LDAP_OPT_AUTO_RECONNECT = 145,
		LDAP_OPT_SSPI_FLAGS = 146,
		LDAP_OPT_SSL_INFO = 147,
		LDAP_OPT_SIGN = 149,
		LDAP_OPT_ENCRYPT = 150,
		LDAP_OPT_SASL_METHOD = 151,
		LDAP_OPT_AREC_EXCLUSIVE = 152,
		LDAP_OPT_SECURITY_CONTEXT = 153,
		LDAP_OPT_ROOTDSE_CACHE = 154
	}
	internal enum ResultAll
	{
		LDAP_MSG_ONE,
		LDAP_MSG_ALL,
		LDAP_MSG_RECEIVED,
		LDAP_MSG_POLLINGALL
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LDAP_TIMEVAL
	{
		public int tv_sec;

		public int tv_usec;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class berval
	{
		public int bv_len;

		public IntPtr bv_val = (IntPtr)0;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class SafeBerval
	{
		public int bv_len;

		public IntPtr bv_val = (IntPtr)0;

		~SafeBerval()
		{
			if (bv_val != (IntPtr)0)
			{
				Marshal.FreeHGlobal(bv_val);
			}
		}
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class LdapControl
	{
		public IntPtr ldctl_oid = (IntPtr)0;

		public berval ldctl_value;

		public bool ldctl_iscritical;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal struct LdapReferralCallback
	{
		public int sizeofcallback;

		public QUERYFORCONNECTIONInternal query;

		public NOTIFYOFNEWCONNECTIONInternal notify;

		public DEREFERENCECONNECTIONInternal dereference;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal struct CRYPTOAPI_BLOB
	{
		public int cbData;

		public IntPtr pbData;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal struct SecPkgContext_IssuerListInfoEx
	{
		public IntPtr aIssuers;

		public int cIssuers;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class LdapMod
	{
		public int type;

		public IntPtr attribute = (IntPtr)0;

		public IntPtr values = (IntPtr)0;

		~LdapMod()
		{
			if (attribute != (IntPtr)0)
			{
				Marshal.FreeHGlobal(attribute);
			}
			if (values != (IntPtr)0)
			{
				Marshal.FreeHGlobal(values);
			}
		}
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class LdapVlvInfo
	{
		private int version = 1;

		private int beforeCount;

		private int afterCount;

		private int offset;

		private int count;

		private IntPtr attrvalue = (IntPtr)0;

		private IntPtr context = (IntPtr)0;

		private IntPtr extraData = (IntPtr)0;

		public LdapVlvInfo(int version, int before, int after, int offset, int count, IntPtr attribute, IntPtr context)
		{
			this.version = version;
			beforeCount = before;
			afterCount = after;
			this.offset = offset;
			this.count = count;
			attrvalue = attribute;
			this.context = context;
		}
	}
	[ComVisible(false)]
	[SuppressUnmanagedCodeSecurity]
	internal class Wldap32
	{
		public const int SEC_WINNT_AUTH_IDENTITY_UNICODE = 2;

		public const int SEC_WINNT_AUTH_IDENTITY_VERSION = 512;

		public const string MICROSOFT_KERBEROS_NAME_W = "Kerberos";

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_bind_sW")]
		public static extern int ldap_bind_s([In] IntPtr ldapHandle, string dn, SEC_WINNT_AUTH_IDENTITY_EX credentials, BindMethod method);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_initW", SetLastError = true)]
		public static extern IntPtr ldap_init(string hostName, int portNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
		public static extern int ldap_connect([In] IntPtr ldapHandle, LDAP_TIMEVAL timeout);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
		public static extern int ldap_unbind([In] IntPtr ldapHandle);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
		public static extern int ldap_get_option_int([In] IntPtr ldapHandle, [In] LdapOption option, ref int outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
		public static extern int ldap_set_option_int([In] IntPtr ldapHandle, [In] LdapOption option, ref int inValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
		public static extern int ldap_get_option_ptr([In] IntPtr ldapHandle, [In] LdapOption option, ref IntPtr outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
		public static extern int ldap_set_option_ptr([In] IntPtr ldapHandle, [In] LdapOption option, ref IntPtr inValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
		public static extern int ldap_get_option_sechandle([In] IntPtr ldapHandle, [In] LdapOption option, ref SecurityHandle outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
		public static extern int ldap_get_option_secInfo([In] IntPtr ldapHandle, [In] LdapOption option, [In][Out] SecurityPackageContextConnectionInformation outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
		public static extern int ldap_set_option_referral([In] IntPtr ldapHandle, [In] LdapOption option, ref LdapReferralCallback outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
		public static extern int ldap_set_option_clientcert([In] IntPtr ldapHandle, [In] LdapOption option, QUERYCLIENTCERT outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
		public static extern int ldap_set_option_servercert([In] IntPtr ldapHandle, [In] LdapOption option, VERIFYSERVERCERT outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
		public static extern int LdapGetLastError();

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "cldap_openW", SetLastError = true)]
		public static extern IntPtr cldap_open(string hostName, int portNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_simple_bind_sW")]
		public static extern int ldap_simple_bind_s([In] IntPtr ldapHandle, string distinguishedName, string password);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_delete_extW")]
		public static extern int ldap_delete_ext([In] IntPtr ldapHandle, string dn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern int ldap_result([In] IntPtr ldapHandle, int messageId, int all, LDAP_TIMEVAL timeout, ref IntPtr Mesage);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_resultW")]
		public static extern int ldap_parse_result([In] IntPtr ldapHandle, [In] IntPtr result, ref int serverError, ref IntPtr dn, ref IntPtr message, ref IntPtr referral, ref IntPtr control, byte freeIt);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_resultW")]
		public static extern int ldap_parse_result_referral([In] IntPtr ldapHandle, [In] IntPtr result, IntPtr serverError, IntPtr dn, IntPtr message, ref IntPtr referral, IntPtr control, byte freeIt);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_memfreeW")]
		public static extern void ldap_memfree([In] IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_value_freeW")]
		public static extern int ldap_value_free([In] IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_controls_freeW")]
		public static extern int ldap_controls_free([In] IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ldap_abandon([In] IntPtr ldapHandle, [In] int messagId);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_start_tls_sW")]
		public static extern int ldap_start_tls(IntPtr ldapHandle, ref int ServerReturnValue, ref IntPtr Message, IntPtr ServerControls, IntPtr ClientControls);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_stop_tls_s")]
		public static extern byte ldap_stop_tls(IntPtr ldapHandle);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_rename_extW")]
		public static extern int ldap_rename([In] IntPtr ldapHandle, string dn, string newRdn, string newParentDn, int deleteOldRdn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_compare_extW")]
		public static extern int ldap_compare([In] IntPtr ldapHandle, string dn, string attributeName, string strValue, berval binaryValue, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_add_extW")]
		public static extern int ldap_add([In] IntPtr ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_modify_extW")]
		public static extern int ldap_modify([In] IntPtr ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_extended_operationW")]
		public static extern int ldap_extended_operation([In] IntPtr ldapHandle, string oid, berval data, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_extended_resultW")]
		public static extern int ldap_parse_extended_result([In] IntPtr ldapHandle, [In] IntPtr result, ref IntPtr oid, ref IntPtr data, byte freeIt);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ldap_msgfree([In] IntPtr result);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_search_extW")]
		public static extern int ldap_search([In] IntPtr ldapHandle, string dn, int scope, string filter, IntPtr attributes, bool attributeOnly, IntPtr servercontrol, IntPtr clientcontrol, int timelimit, int sizelimit, ref int messageNumber);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_first_entry([In] IntPtr ldapHandle, [In] IntPtr result);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_next_entry([In] IntPtr ldapHandle, [In] IntPtr result);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_first_reference([In] IntPtr ldapHandle, [In] IntPtr result);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_next_reference([In] IntPtr ldapHandle, [In] IntPtr result);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_dnW")]
		public static extern IntPtr ldap_get_dn([In] IntPtr ldapHandle, [In] IntPtr result);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_first_attributeW")]
		public static extern IntPtr ldap_first_attribute([In] IntPtr ldapHandle, [In] IntPtr result, ref IntPtr address);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_next_attributeW")]
		public static extern IntPtr ldap_next_attribute([In] IntPtr ldapHandle, [In] IntPtr result, [In][Out] IntPtr address);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ber_free([In] IntPtr berelement, int option);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_values_lenW")]
		public static extern IntPtr ldap_get_values_len([In] IntPtr ldapHandle, [In] IntPtr result, string name);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_value_free_len([In] IntPtr berelement);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_referenceW")]
		public static extern int ldap_parse_reference([In] IntPtr ldapHandle, [In] IntPtr result, ref IntPtr referrals);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_alloc_t")]
		public static extern IntPtr ber_alloc(int option);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_printf")]
		public static extern int ber_printf_emptyarg(BerSafeHandle berElement, string format);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_printf")]
		public static extern int ber_printf_int(BerSafeHandle berElement, string format, int value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_printf")]
		public static extern int ber_printf_bytearray(BerSafeHandle berElement, string format, HGlobalMemHandle value, int length);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_printf")]
		public static extern int ber_printf_berarray(BerSafeHandle berElement, string format, IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ber_flatten(BerSafeHandle berElement, ref IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ber_init(berval value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ber_scanf(BerSafeHandle berElement, string format);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_scanf")]
		public static extern int ber_scanf_int(BerSafeHandle berElement, string format, ref int value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_scanf")]
		public static extern int ber_scanf_ptr(BerSafeHandle berElement, string format, ref IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ber_scanf")]
		public static extern int ber_scanf_bitstring(BerSafeHandle berElement, string format, ref IntPtr value, ref int length);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ber_bvfree(IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ber_bvecfree(IntPtr value);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_create_sort_controlW")]
		public static extern int ldap_create_sort_control(ConnectionHandle handle, IntPtr keys, byte critical, ref IntPtr control);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_control_freeW")]
		public static extern int ldap_control_free(IntPtr control);

		[DllImport("Crypt32.dll", CharSet = CharSet.Unicode)]
		public static extern int CertFreeCRLContext(IntPtr certContext);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ldap_result2error([In] IntPtr ldapHandle, [In] IntPtr result, int freeIt);
	}
}
