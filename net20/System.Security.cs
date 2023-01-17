
// C:\WINDOWS\assembly\GAC_MSIL\System.Security\2.0.0.0__b03f5f7f11d50a3a\System.Security.dll
// System.Security, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Permissions;
using System.Security.Policy;
using System.Text;
using System.Threading;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Xsl;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: ComVisible(false)]
[assembly: AssemblyFileVersion("2.0.50727.9156")]
[assembly: CLSCompliant(true)]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyInformationalVersion("2.0.50727.9156")]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDefaultAlias("System.Security.dll")]
[assembly: AssemblyDescription("System.Security.dll")]
[assembly: AssemblyTitle("System.Security.dll")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
namespace System.Security
{
	internal static class SecurityResources
	{
		private static ResourceManager s_resMgr;

		internal static string GetResourceString(string key)
		{
			if (s_resMgr == null)
			{
				s_resMgr = new ResourceManager("system.security", typeof(SecurityResources).Assembly);
			}
			return s_resMgr.GetString(key, null);
		}
	}
}
namespace System.Security.Cryptography
{
	internal sealed class BigInt
	{
		private const int m_maxbytes = 128;

		private const int m_base = 256;

		private byte[] m_elements;

		private int m_size;

		private static readonly char[] decValues = new char[10] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

		internal int Size
		{
			get
			{
				return m_size;
			}
			set
			{
				if (value > 128)
				{
					m_size = 128;
				}
				if (value < 0)
				{
					m_size = 0;
				}
				m_size = value;
			}
		}

		internal BigInt()
		{
			m_elements = new byte[128];
		}

		internal BigInt(byte b)
		{
			m_elements = new byte[128];
			SetDigit(0, b);
		}

		internal byte GetDigit(int index)
		{
			if (index < 0 || index >= m_size)
			{
				return 0;
			}
			return m_elements[index];
		}

		internal void SetDigit(int index, byte digit)
		{
			if (index >= 0 && index < 128)
			{
				m_elements[index] = digit;
				if (index >= m_size && digit != 0)
				{
					m_size = index + 1;
				}
				if (index == m_size - 1 && digit == 0)
				{
					m_size--;
				}
			}
		}

		internal void SetDigit(int index, byte digit, ref int size)
		{
			if (index >= 0 && index < 128)
			{
				m_elements[index] = digit;
				if (index >= size && digit != 0)
				{
					size = index + 1;
				}
				if (index == size - 1 && digit == 0)
				{
					size--;
				}
			}
		}

		public static bool operator <(BigInt value1, BigInt value2)
		{
			if (value1 == null)
			{
				return true;
			}
			if (value2 == null)
			{
				return false;
			}
			int size = value1.Size;
			int size2 = value2.Size;
			if (size != size2)
			{
				return size < size2;
			}
			while (size-- > 0)
			{
				if (value1.m_elements[size] != value2.m_elements[size])
				{
					return value1.m_elements[size] < value2.m_elements[size];
				}
			}
			return false;
		}

		public static bool operator >(BigInt value1, BigInt value2)
		{
			if (value1 == null)
			{
				return false;
			}
			if (value2 == null)
			{
				return true;
			}
			int size = value1.Size;
			int size2 = value2.Size;
			if (size != size2)
			{
				return size > size2;
			}
			while (size-- > 0)
			{
				if (value1.m_elements[size] != value2.m_elements[size])
				{
					return value1.m_elements[size] > value2.m_elements[size];
				}
			}
			return false;
		}

		public static bool operator ==(BigInt value1, BigInt value2)
		{
			if ((object)value1 == null)
			{
				return (object)value2 == null;
			}
			if ((object)value2 == null)
			{
				return (object)value1 == null;
			}
			int size = value1.Size;
			int size2 = value2.Size;
			if (size != size2)
			{
				return false;
			}
			for (int i = 0; i < size; i++)
			{
				if (value1.m_elements[i] != value2.m_elements[i])
				{
					return false;
				}
			}
			return true;
		}

		public static bool operator !=(BigInt value1, BigInt value2)
		{
			return !(value1 == value2);
		}

		public override bool Equals(object obj)
		{
			if (obj is BigInt)
			{
				return this == (BigInt)obj;
			}
			return false;
		}

		public override int GetHashCode()
		{
			int num = 0;
			for (int i = 0; i < m_size; i++)
			{
				num += GetDigit(i);
			}
			return num;
		}

		internal static void Add(BigInt a, byte b, ref BigInt c)
		{
			byte b2 = b;
			int num = 0;
			int size = a.Size;
			int size2 = 0;
			for (int i = 0; i < size; i++)
			{
				num = a.GetDigit(i) + b2;
				c.SetDigit(i, (byte)((uint)num & 0xFFu), ref size2);
				b2 = (byte)((uint)(num >> 8) & 0xFFu);
			}
			if (b2 != 0)
			{
				c.SetDigit(a.Size, b2, ref size2);
			}
			c.Size = size2;
		}

		internal static void Negate(ref BigInt a)
		{
			int size = 0;
			for (int i = 0; i < 128; i++)
			{
				a.SetDigit(i, (byte)((uint)(~a.GetDigit(i)) & 0xFFu), ref size);
			}
			for (int j = 0; j < 128; j++)
			{
				a.SetDigit(j, (byte)(a.GetDigit(j) + 1), ref size);
				if ((a.GetDigit(j) & 0xFFu) != 0)
				{
					break;
				}
				a.SetDigit(j, (byte)(a.GetDigit(j) & 0xFFu), ref size);
			}
			a.Size = size;
		}

		internal static void Subtract(BigInt a, BigInt b, ref BigInt c)
		{
			byte b2 = 0;
			int num = 0;
			if (a < b)
			{
				Subtract(b, a, ref c);
				Negate(ref c);
				return;
			}
			int num2 = 0;
			int size = a.Size;
			int size2 = 0;
			for (num2 = 0; num2 < size; num2++)
			{
				num = a.GetDigit(num2) - b.GetDigit(num2) - b2;
				b2 = 0;
				if (num < 0)
				{
					num += 256;
					b2 = 1;
				}
				c.SetDigit(num2, (byte)((uint)num & 0xFFu), ref size2);
			}
			c.Size = size2;
		}

		private void Multiply(int b)
		{
			if (b == 0)
			{
				Clear();
				return;
			}
			int num = 0;
			int num2 = 0;
			int size = Size;
			int size2 = 0;
			for (int i = 0; i < size; i++)
			{
				num2 = b * GetDigit(i) + num;
				num = num2 / 256;
				SetDigit(i, (byte)(num2 % 256), ref size2);
			}
			if (num != 0)
			{
				byte[] bytes = BitConverter.GetBytes(num);
				for (int j = 0; j < bytes.Length; j++)
				{
					SetDigit(size + j, bytes[j], ref size2);
				}
			}
			Size = size2;
		}

		private static void Multiply(BigInt a, int b, ref BigInt c)
		{
			if (b == 0)
			{
				c.Clear();
				return;
			}
			int num = 0;
			int num2 = 0;
			int size = a.Size;
			int size2 = 0;
			for (int i = 0; i < size; i++)
			{
				num2 = b * a.GetDigit(i) + num;
				num = num2 / 256;
				c.SetDigit(i, (byte)(num2 % 256), ref size2);
			}
			if (num != 0)
			{
				byte[] bytes = BitConverter.GetBytes(num);
				for (int j = 0; j < bytes.Length; j++)
				{
					c.SetDigit(size + j, bytes[j], ref size2);
				}
			}
			c.Size = size2;
		}

		private void Divide(int b)
		{
			int num = 0;
			int num2 = 0;
			int size = Size;
			int size2 = 0;
			while (size-- > 0)
			{
				num2 = 256 * num + GetDigit(size);
				num = num2 % b;
				SetDigit(size, (byte)(num2 / b), ref size2);
			}
			Size = size2;
		}

		internal static void Divide(BigInt numerator, BigInt denominator, ref BigInt quotient, ref BigInt remainder)
		{
			if (numerator < denominator)
			{
				quotient.Clear();
				remainder.CopyFrom(numerator);
				return;
			}
			if (numerator == denominator)
			{
				quotient.Clear();
				quotient.SetDigit(0, 1);
				remainder.Clear();
				return;
			}
			BigInt c = new BigInt();
			c.CopyFrom(numerator);
			BigInt bigInt = new BigInt();
			bigInt.CopyFrom(denominator);
			uint num = 0u;
			while (bigInt.Size < c.Size)
			{
				bigInt.Multiply(256);
				num++;
			}
			if (bigInt > c)
			{
				bigInt.Divide(256);
				num--;
			}
			int num2 = 0;
			int num3 = 0;
			int num4 = 0;
			BigInt c2 = new BigInt();
			quotient.Clear();
			for (int i = 0; i <= num; i++)
			{
				num2 = ((c.Size == bigInt.Size) ? c.GetDigit(c.Size - 1) : (256 * c.GetDigit(c.Size - 1) + c.GetDigit(c.Size - 2)));
				num3 = bigInt.GetDigit(bigInt.Size - 1);
				num4 = num2 / num3;
				if (num4 >= 256)
				{
					num4 = 255;
				}
				Multiply(bigInt, num4, ref c2);
				while (c2 > c)
				{
					num4--;
					Multiply(bigInt, num4, ref c2);
				}
				quotient.Multiply(256);
				Add(quotient, (byte)num4, ref quotient);
				Subtract(c, c2, ref c);
				bigInt.Divide(256);
			}
			remainder.CopyFrom(c);
		}

		internal void CopyFrom(BigInt a)
		{
			Array.Copy(a.m_elements, m_elements, 128);
			m_size = a.m_size;
		}

		internal bool IsZero()
		{
			for (int i = 0; i < m_size; i++)
			{
				if (m_elements[i] != 0)
				{
					return false;
				}
			}
			return true;
		}

		internal byte[] ToByteArray()
		{
			byte[] array = new byte[Size];
			Array.Copy(m_elements, array, Size);
			return array;
		}

		internal void Clear()
		{
			m_size = 0;
		}

		internal void FromHexadecimal(string hexNum)
		{
			byte[] array = System.Security.Cryptography.X509Certificates.X509Utils.DecodeHexString(hexNum);
			Array.Reverse(array);
			int hexArraySize = System.Security.Cryptography.Xml.Utils.GetHexArraySize(array);
			Array.Copy(array, m_elements, hexArraySize);
			Size = hexArraySize;
		}

		internal void FromDecimal(string decNum)
		{
			BigInt c = new BigInt();
			BigInt c2 = new BigInt();
			int length = decNum.Length;
			for (int i = 0; i < length; i++)
			{
				if (decNum[i] <= '9' && decNum[i] >= '0')
				{
					Multiply(c, 10, ref c2);
					Add(c2, (byte)(decNum[i] - 48), ref c);
				}
			}
			CopyFrom(c);
		}

		internal string ToDecimal()
		{
			if (IsZero())
			{
				return "0";
			}
			BigInt denominator = new BigInt(10);
			BigInt bigInt = new BigInt();
			BigInt quotient = new BigInt();
			BigInt remainder = new BigInt();
			bigInt.CopyFrom(this);
			char[] array = new char[(int)Math.Ceiling((double)(m_size * 2) * 1.21)];
			int length = 0;
			do
			{
				Divide(bigInt, denominator, ref quotient, ref remainder);
				array[length++] = decValues[(!remainder.IsZero()) ? remainder.m_elements[0] : 0];
				bigInt.CopyFrom(quotient);
			}
			while (!quotient.IsZero());
			Array.Reverse(array, 0, length);
			return new string(array, 0, length);
		}
	}
	internal abstract class CAPIBase
	{
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct BLOBHEADER
		{
			internal byte bType;

			internal byte bVersion;

			internal short reserved;

			internal uint aiKeyAlg;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_ALT_NAME_INFO
		{
			internal uint cAltEntry;

			internal IntPtr rgAltEntry;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_BASIC_CONSTRAINTS_INFO
		{
			internal CRYPT_BIT_BLOB SubjectType;

			internal bool fPathLenConstraint;

			internal uint dwPathLenConstraint;

			internal uint cSubtreesConstraint;

			internal IntPtr rgSubtreesConstraint;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_BASIC_CONSTRAINTS2_INFO
		{
			internal int fCA;

			internal int fPathLenConstraint;

			internal uint dwPathLenConstraint;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_CHAIN_PARA
		{
			internal uint cbSize;

			internal CERT_USAGE_MATCH RequestedUsage;

			internal CERT_USAGE_MATCH RequestedIssuancePolicy;

			internal uint dwUrlRetrievalTimeout;

			internal bool fCheckRevocationFreshnessTime;

			internal uint dwRevocationFreshnessTime;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_CHAIN_POLICY_PARA
		{
			internal uint cbSize;

			internal uint dwFlags;

			internal IntPtr pvExtraPolicyPara;

			internal CERT_CHAIN_POLICY_PARA(int size)
			{
				cbSize = (uint)size;
				dwFlags = 0u;
				pvExtraPolicyPara = IntPtr.Zero;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_CHAIN_POLICY_STATUS
		{
			internal uint cbSize;

			internal uint dwError;

			internal IntPtr lChainIndex;

			internal IntPtr lElementIndex;

			internal IntPtr pvExtraPolicyStatus;

			internal CERT_CHAIN_POLICY_STATUS(int size)
			{
				cbSize = (uint)size;
				dwError = 0u;
				lChainIndex = IntPtr.Zero;
				lElementIndex = IntPtr.Zero;
				pvExtraPolicyStatus = IntPtr.Zero;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_CONTEXT
		{
			internal uint dwCertEncodingType;

			internal IntPtr pbCertEncoded;

			internal uint cbCertEncoded;

			internal IntPtr pCertInfo;

			internal IntPtr hCertStore;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_DSS_PARAMETERS
		{
			internal CRYPTOAPI_BLOB p;

			internal CRYPTOAPI_BLOB q;

			internal CRYPTOAPI_BLOB g;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_ENHKEY_USAGE
		{
			internal uint cUsageIdentifier;

			internal IntPtr rgpszUsageIdentifier;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_EXTENSION
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			internal bool fCritical;

			internal CRYPTOAPI_BLOB Value;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_ID
		{
			internal uint dwIdChoice;

			internal CERT_ID_UNION Value;
		}

		[StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
		internal struct CERT_ID_UNION
		{
			[FieldOffset(0)]
			internal CERT_ISSUER_SERIAL_NUMBER IssuerSerialNumber;

			[FieldOffset(0)]
			internal CRYPTOAPI_BLOB KeyId;

			[FieldOffset(0)]
			internal CRYPTOAPI_BLOB HashId;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_ISSUER_SERIAL_NUMBER
		{
			internal CRYPTOAPI_BLOB Issuer;

			internal CRYPTOAPI_BLOB SerialNumber;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_INFO
		{
			internal uint dwVersion;

			internal CRYPTOAPI_BLOB SerialNumber;

			internal CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;

			internal CRYPTOAPI_BLOB Issuer;

			internal System.Runtime.InteropServices.ComTypes.FILETIME NotBefore;

			internal System.Runtime.InteropServices.ComTypes.FILETIME NotAfter;

			internal CRYPTOAPI_BLOB Subject;

			internal CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;

			internal CRYPT_BIT_BLOB IssuerUniqueId;

			internal CRYPT_BIT_BLOB SubjectUniqueId;

			internal uint cExtension;

			internal IntPtr rgExtension;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_KEY_USAGE_RESTRICTION_INFO
		{
			internal uint cCertPolicyId;

			internal IntPtr rgCertPolicyId;

			internal CRYPT_BIT_BLOB RestrictedKeyUsage;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_NAME_INFO
		{
			internal uint cRDN;

			internal IntPtr rgRDN;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_NAME_VALUE
		{
			internal uint dwValueType;

			internal CRYPTOAPI_BLOB Value;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_OTHER_NAME
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			internal CRYPTOAPI_BLOB Value;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_POLICY_ID
		{
			internal uint cCertPolicyElementId;

			internal IntPtr rgpszCertPolicyElementId;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_POLICIES_INFO
		{
			internal uint cPolicyInfo;

			internal IntPtr rgPolicyInfo;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_POLICY_INFO
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszPolicyIdentifier;

			internal uint cPolicyQualifier;

			internal IntPtr rgPolicyQualifier;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_POLICY_QUALIFIER_INFO
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszPolicyQualifierId;

			private CRYPTOAPI_BLOB Qualifier;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_PUBLIC_KEY_INFO
		{
			internal CRYPT_ALGORITHM_IDENTIFIER Algorithm;

			internal CRYPT_BIT_BLOB PublicKey;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_PUBLIC_KEY_INFO2
		{
			internal CRYPT_ALGORITHM_IDENTIFIER2 Algorithm;

			internal CRYPT_BIT_BLOB PublicKey;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_RDN
		{
			internal uint cRDNAttr;

			internal IntPtr rgRDNAttr;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_RDN_ATTR
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			internal uint dwValueType;

			internal CRYPTOAPI_BLOB Value;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_TEMPLATE_EXT
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			internal uint dwMajorVersion;

			private bool fMinorVersion;

			private uint dwMinorVersion;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_TRUST_STATUS
		{
			internal uint dwErrorStatus;

			internal uint dwInfoStatus;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_USAGE_MATCH
		{
			internal uint dwType;

			internal CERT_ENHKEY_USAGE Usage;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CMS_RECIPIENT_INFO
		{
			internal uint dwRecipientChoice;

			internal IntPtr pRecipientInfo;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CMS_SIGNER_INFO
		{
			internal uint dwVersion;

			internal CERT_ID SignerId;

			internal CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;

			internal CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;

			internal CRYPTOAPI_BLOB EncryptedHash;

			internal CRYPT_ATTRIBUTES AuthAttrs;

			internal CRYPT_ATTRIBUTES UnauthAttrs;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA
		{
			internal uint cbSize;

			internal uint dwSignerIndex;

			internal CRYPTOAPI_BLOB blob;

			internal CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA(int size)
			{
				cbSize = (uint)size;
				dwSignerIndex = 0u;
				blob = default(CRYPTOAPI_BLOB);
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CTRL_DECRYPT_PARA
		{
			internal uint cbSize;

			internal IntPtr hCryptProv;

			internal uint dwKeySpec;

			internal uint dwRecipientIndex;

			internal CMSG_CTRL_DECRYPT_PARA(int size)
			{
				cbSize = (uint)size;
				hCryptProv = IntPtr.Zero;
				dwKeySpec = 0u;
				dwRecipientIndex = 0u;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA
		{
			internal uint cbSize;

			internal uint dwSignerIndex;

			internal uint dwUnauthAttrIndex;

			internal CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA(int size)
			{
				cbSize = (uint)size;
				dwSignerIndex = 0u;
				dwUnauthAttrIndex = 0u;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CTRL_KEY_TRANS_DECRYPT_PARA
		{
			internal uint cbSize;

			internal SafeCryptProvHandle hCryptProv;

			internal uint dwKeySpec;

			internal IntPtr pKeyTrans;

			internal uint dwRecipientIndex;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO
		{
			internal uint cbSize;

			internal CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;

			internal IntPtr pvKeyEncryptionAuxInfo;

			internal CRYPT_ALGORITHM_IDENTIFIER KeyWrapAlgorithm;

			internal IntPtr pvKeyWrapAuxInfo;

			internal IntPtr hCryptProv;

			internal uint dwKeySpec;

			internal uint dwKeyChoice;

			internal IntPtr pEphemeralAlgorithmOrSenderId;

			internal CRYPTOAPI_BLOB UserKeyingMaterial;

			internal uint cRecipientEncryptedKeys;

			internal IntPtr rgpRecipientEncryptedKeys;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO
		{
			internal uint cbSize;

			internal CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;

			internal IntPtr pvKeyEncryptionAuxInfo;

			internal IntPtr hCryptProv;

			internal CRYPT_BIT_BLOB RecipientPublicKey;

			internal CERT_ID RecipientId;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_RC2_AUX_INFO
		{
			internal uint cbSize;

			internal uint dwBitLen;

			internal CMSG_RC2_AUX_INFO(int size)
			{
				cbSize = (uint)size;
				dwBitLen = 0u;
			}
		}

		internal struct CMSG_RECIPIENT_ENCODE_INFO
		{
			internal uint dwRecipientChoice;

			internal IntPtr pRecipientInfo;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO
		{
			internal uint cbSize;

			internal CRYPT_BIT_BLOB RecipientPublicKey;

			internal CERT_ID RecipientId;

			internal System.Runtime.InteropServices.ComTypes.FILETIME Date;

			internal IntPtr pOtherAttr;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_ENVELOPED_ENCODE_INFO
		{
			internal uint cbSize;

			internal IntPtr hCryptProv;

			internal CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;

			internal IntPtr pvEncryptionAuxInfo;

			internal uint cRecipients;

			internal IntPtr rgpRecipients;

			internal IntPtr rgCmsRecipients;

			internal uint cCertEncoded;

			internal IntPtr rgCertEncoded;

			internal uint cCrlEncoded;

			internal IntPtr rgCrlEncoded;

			internal uint cAttrCertEncoded;

			internal IntPtr rgAttrCertEncoded;

			internal uint cUnprotectedAttr;

			internal IntPtr rgUnprotectedAttr;

			internal CMSG_ENVELOPED_ENCODE_INFO(int size)
			{
				cbSize = (uint)size;
				hCryptProv = IntPtr.Zero;
				ContentEncryptionAlgorithm = default(CRYPT_ALGORITHM_IDENTIFIER);
				pvEncryptionAuxInfo = IntPtr.Zero;
				cRecipients = 0u;
				rgpRecipients = IntPtr.Zero;
				rgCmsRecipients = IntPtr.Zero;
				cCertEncoded = 0u;
				rgCertEncoded = IntPtr.Zero;
				cCrlEncoded = 0u;
				rgCrlEncoded = IntPtr.Zero;
				cAttrCertEncoded = 0u;
				rgAttrCertEncoded = IntPtr.Zero;
				cUnprotectedAttr = 0u;
				rgUnprotectedAttr = IntPtr.Zero;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CTRL_KEY_AGREE_DECRYPT_PARA
		{
			internal uint cbSize;

			internal IntPtr hCryptProv;

			internal uint dwKeySpec;

			internal IntPtr pKeyAgree;

			internal uint dwRecipientIndex;

			internal uint dwRecipientEncryptedKeyIndex;

			internal CRYPT_BIT_BLOB OriginatorPublicKey;

			internal CMSG_CTRL_KEY_AGREE_DECRYPT_PARA(int size)
			{
				cbSize = (uint)size;
				hCryptProv = IntPtr.Zero;
				dwKeySpec = 0u;
				pKeyAgree = IntPtr.Zero;
				dwRecipientIndex = 0u;
				dwRecipientEncryptedKeyIndex = 0u;
				OriginatorPublicKey = default(CRYPT_BIT_BLOB);
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_KEY_AGREE_RECIPIENT_INFO
		{
			internal uint dwVersion;

			internal uint dwOriginatorChoice;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO
		{
			internal uint dwVersion;

			internal uint dwOriginatorChoice;

			internal CERT_ID OriginatorCertId;

			internal IntPtr Padding;

			internal CRYPTOAPI_BLOB UserKeyingMaterial;

			internal CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;

			internal uint cRecipientEncryptedKeys;

			internal IntPtr rgpRecipientEncryptedKeys;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO
		{
			internal uint dwVersion;

			internal uint dwOriginatorChoice;

			internal CERT_PUBLIC_KEY_INFO OriginatorPublicKeyInfo;

			internal CRYPTOAPI_BLOB UserKeyingMaterial;

			internal CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;

			internal uint cRecipientEncryptedKeys;

			internal IntPtr rgpRecipientEncryptedKeys;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_RECIPIENT_ENCRYPTED_KEY_INFO
		{
			internal CERT_ID RecipientId;

			internal CRYPTOAPI_BLOB EncryptedKey;

			internal System.Runtime.InteropServices.ComTypes.FILETIME Date;

			internal IntPtr pOtherAttr;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA
		{
			internal uint cbSize;

			internal IntPtr hCryptProv;

			internal uint dwSignerIndex;

			internal uint dwSignerType;

			internal IntPtr pvSigner;

			internal CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA(int size)
			{
				cbSize = (uint)size;
				hCryptProv = IntPtr.Zero;
				dwSignerIndex = 0u;
				dwSignerType = 0u;
				pvSigner = IntPtr.Zero;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_KEY_TRANS_RECIPIENT_INFO
		{
			internal uint dwVersion;

			internal CERT_ID RecipientId;

			internal CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;

			internal CRYPTOAPI_BLOB EncryptedKey;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_SIGNED_ENCODE_INFO
		{
			internal uint cbSize;

			internal uint cSigners;

			internal IntPtr rgSigners;

			internal uint cCertEncoded;

			internal IntPtr rgCertEncoded;

			internal uint cCrlEncoded;

			internal IntPtr rgCrlEncoded;

			internal uint cAttrCertEncoded;

			internal IntPtr rgAttrCertEncoded;

			internal CMSG_SIGNED_ENCODE_INFO(int size)
			{
				cbSize = (uint)size;
				cSigners = 0u;
				rgSigners = IntPtr.Zero;
				cCertEncoded = 0u;
				rgCertEncoded = IntPtr.Zero;
				cCrlEncoded = 0u;
				rgCrlEncoded = IntPtr.Zero;
				cAttrCertEncoded = 0u;
				rgAttrCertEncoded = IntPtr.Zero;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_SIGNER_ENCODE_INFO
		{
			internal uint cbSize;

			internal IntPtr pCertInfo;

			internal IntPtr hCryptProv;

			internal uint dwKeySpec;

			internal CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;

			internal IntPtr pvHashAuxInfo;

			internal uint cAuthAttr;

			internal IntPtr rgAuthAttr;

			internal uint cUnauthAttr;

			internal IntPtr rgUnauthAttr;

			internal CERT_ID SignerId;

			internal CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;

			internal IntPtr pvHashEncryptionAuxInfo;

			[DllImport("kernel32.dll", SetLastError = true)]
			internal static extern IntPtr LocalFree(IntPtr hMem);

			[DllImport("advapi32.dll", SetLastError = true)]
			internal static extern bool CryptReleaseContext([In] IntPtr hProv, [In] uint dwFlags);

			internal CMSG_SIGNER_ENCODE_INFO(int size)
			{
				cbSize = (uint)size;
				pCertInfo = IntPtr.Zero;
				hCryptProv = IntPtr.Zero;
				dwKeySpec = 0u;
				HashAlgorithm = default(CRYPT_ALGORITHM_IDENTIFIER);
				pvHashAuxInfo = IntPtr.Zero;
				cAuthAttr = 0u;
				rgAuthAttr = IntPtr.Zero;
				cUnauthAttr = 0u;
				rgUnauthAttr = IntPtr.Zero;
				SignerId = default(CERT_ID);
				HashEncryptionAlgorithm = default(CRYPT_ALGORITHM_IDENTIFIER);
				pvHashEncryptionAuxInfo = IntPtr.Zero;
			}

			internal void Dispose()
			{
				if (hCryptProv != IntPtr.Zero)
				{
					CryptReleaseContext(hCryptProv, 0u);
				}
				if (SignerId.Value.KeyId.pbData != IntPtr.Zero)
				{
					LocalFree(SignerId.Value.KeyId.pbData);
				}
				if (rgAuthAttr != IntPtr.Zero)
				{
					LocalFree(rgAuthAttr);
				}
				if (rgUnauthAttr != IntPtr.Zero)
				{
					LocalFree(rgUnauthAttr);
				}
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CMSG_SIGNER_INFO
		{
			internal uint dwVersion;

			internal CRYPTOAPI_BLOB Issuer;

			internal CRYPTOAPI_BLOB SerialNumber;

			internal CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;

			internal CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;

			internal CRYPTOAPI_BLOB EncryptedHash;

			internal CRYPT_ATTRIBUTES AuthAttrs;

			internal CRYPT_ATTRIBUTES UnauthAttrs;
		}

		internal delegate bool PFN_CMSG_STREAM_OUTPUT(IntPtr pvArg, IntPtr pbData, uint cbData, bool fFinal);

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal class CMSG_STREAM_INFO
		{
			internal uint cbContent;

			internal PFN_CMSG_STREAM_OUTPUT pfnStreamOutput;

			internal IntPtr pvArg;

			internal CMSG_STREAM_INFO(uint cbContent, PFN_CMSG_STREAM_OUTPUT pfnStreamOutput, IntPtr pvArg)
			{
				this.cbContent = cbContent;
				this.pfnStreamOutput = pfnStreamOutput;
				this.pvArg = pvArg;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_ALGORITHM_IDENTIFIER
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			internal CRYPTOAPI_BLOB Parameters;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_ALGORITHM_IDENTIFIER2
		{
			internal IntPtr pszObjId;

			internal CRYPTOAPI_BLOB Parameters;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_ATTRIBUTE
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			internal uint cValue;

			internal IntPtr rgValue;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_ATTRIBUTES
		{
			internal uint cAttr;

			internal IntPtr rgAttr;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_ATTRIBUTE_TYPE_VALUE
		{
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			internal CRYPTOAPI_BLOB Value;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_BIT_BLOB
		{
			internal uint cbData;

			internal IntPtr pbData;

			internal uint cUnusedBits;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_KEY_PROV_INFO
		{
			internal string pwszContainerName;

			internal string pwszProvName;

			internal uint dwProvType;

			internal uint dwFlags;

			internal uint cProvParam;

			internal IntPtr rgProvParam;

			internal uint dwKeySpec;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_OID_INFO
		{
			internal uint cbSize;

			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszOID;

			internal string pwszName;

			internal uint dwGroupId;

			internal uint Algid;

			internal CRYPTOAPI_BLOB ExtraInfo;

			internal CRYPT_OID_INFO(int size)
			{
				cbSize = (uint)size;
				pszOID = null;
				pwszName = null;
				dwGroupId = 0u;
				Algid = 0u;
				ExtraInfo = default(CRYPTOAPI_BLOB);
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_RC2_CBC_PARAMETERS
		{
			internal uint dwVersion;

			internal bool fIV;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			internal byte[] rgbIV;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPTOAPI_BLOB
		{
			internal uint cbData;

			internal IntPtr pbData;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal class CRYPTUI_SELECTCERTIFICATE_STRUCTW
		{
			internal uint dwSize;

			internal IntPtr hwndParent;

			internal uint dwFlags;

			internal string szTitle;

			internal uint dwDontUseColumn;

			internal string szDisplayString;

			internal IntPtr pFilterCallback;

			internal IntPtr pDisplayCallback;

			internal IntPtr pvCallbackData;

			internal uint cDisplayStores;

			internal IntPtr rghDisplayStores;

			internal uint cStores;

			internal IntPtr rghStores;

			internal uint cPropSheetPages;

			internal IntPtr rgPropSheetPages;

			internal IntPtr hSelectedCertStore;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal class CRYPTUI_VIEWCERTIFICATE_STRUCTW
		{
			internal uint dwSize;

			internal IntPtr hwndParent;

			internal uint dwFlags;

			internal string szTitle;

			internal IntPtr pCertContext;

			internal IntPtr rgszPurposes;

			internal uint cPurposes;

			internal IntPtr pCryptProviderData;

			internal bool fpCryptProviderDataTrustedUsage;

			internal uint idxSigner;

			internal uint idxCert;

			internal bool fCounterSigner;

			internal uint idxCounterSigner;

			internal uint cStores;

			internal IntPtr rghStores;

			internal uint cPropSheetPages;

			internal IntPtr rgPropSheetPages;

			internal uint nStartPage;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct DSSPUBKEY
		{
			internal uint magic;

			internal uint bitlen;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct PROV_ENUMALGS_EX
		{
			internal uint aiAlgid;

			internal uint dwDefaultLen;

			internal uint dwMinLen;

			internal uint dwMaxLen;

			internal uint dwProtocols;

			internal uint dwNameLen;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
			internal byte[] szName;

			internal uint dwLongNameLen;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
			internal byte[] szLongName;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct RSAPUBKEY
		{
			internal uint magic;

			internal uint bitlen;

			internal uint pubexp;
		}

		internal const string ADVAPI32 = "advapi32.dll";

		internal const string CRYPT32 = "crypt32.dll";

		internal const string CRYPTUI = "cryptui.dll";

		internal const string KERNEL32 = "kernel32.dll";

		internal const uint LMEM_FIXED = 0u;

		internal const uint LMEM_ZEROINIT = 64u;

		internal const uint LPTR = 64u;

		internal const int S_OK = 0;

		internal const int S_FALSE = 1;

		internal const uint FORMAT_MESSAGE_FROM_SYSTEM = 4096u;

		internal const uint FORMAT_MESSAGE_IGNORE_INSERTS = 512u;

		internal const uint VER_PLATFORM_WIN32s = 0u;

		internal const uint VER_PLATFORM_WIN32_WINDOWS = 1u;

		internal const uint VER_PLATFORM_WIN32_NT = 2u;

		internal const uint VER_PLATFORM_WINCE = 3u;

		internal const uint ASN_TAG_NULL = 5u;

		internal const uint ASN_TAG_OBJID = 6u;

		internal const uint CERT_QUERY_OBJECT_FILE = 1u;

		internal const uint CERT_QUERY_OBJECT_BLOB = 2u;

		internal const uint CERT_QUERY_CONTENT_CERT = 1u;

		internal const uint CERT_QUERY_CONTENT_CTL = 2u;

		internal const uint CERT_QUERY_CONTENT_CRL = 3u;

		internal const uint CERT_QUERY_CONTENT_SERIALIZED_STORE = 4u;

		internal const uint CERT_QUERY_CONTENT_SERIALIZED_CERT = 5u;

		internal const uint CERT_QUERY_CONTENT_SERIALIZED_CTL = 6u;

		internal const uint CERT_QUERY_CONTENT_SERIALIZED_CRL = 7u;

		internal const uint CERT_QUERY_CONTENT_PKCS7_SIGNED = 8u;

		internal const uint CERT_QUERY_CONTENT_PKCS7_UNSIGNED = 9u;

		internal const uint CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10u;

		internal const uint CERT_QUERY_CONTENT_PKCS10 = 11u;

		internal const uint CERT_QUERY_CONTENT_PFX = 12u;

		internal const uint CERT_QUERY_CONTENT_CERT_PAIR = 13u;

		internal const uint CERT_QUERY_CONTENT_FLAG_CERT = 2u;

		internal const uint CERT_QUERY_CONTENT_FLAG_CTL = 4u;

		internal const uint CERT_QUERY_CONTENT_FLAG_CRL = 8u;

		internal const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = 16u;

		internal const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = 32u;

		internal const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = 64u;

		internal const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = 128u;

		internal const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 256u;

		internal const uint CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = 512u;

		internal const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1024u;

		internal const uint CERT_QUERY_CONTENT_FLAG_PKCS10 = 2048u;

		internal const uint CERT_QUERY_CONTENT_FLAG_PFX = 4096u;

		internal const uint CERT_QUERY_CONTENT_FLAG_CERT_PAIR = 8192u;

		internal const uint CERT_QUERY_CONTENT_FLAG_ALL = 16382u;

		internal const uint CERT_QUERY_FORMAT_BINARY = 1u;

		internal const uint CERT_QUERY_FORMAT_BASE64_ENCODED = 2u;

		internal const uint CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3u;

		internal const uint CERT_QUERY_FORMAT_FLAG_BINARY = 2u;

		internal const uint CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = 4u;

		internal const uint CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = 8u;

		internal const uint CERT_QUERY_FORMAT_FLAG_ALL = 14u;

		internal const uint CRYPTPROTECT_UI_FORBIDDEN = 1u;

		internal const uint CRYPTPROTECT_LOCAL_MACHINE = 4u;

		internal const uint CRYPTPROTECT_CRED_SYNC = 8u;

		internal const uint CRYPTPROTECT_AUDIT = 16u;

		internal const uint CRYPTPROTECT_NO_RECOVERY = 32u;

		internal const uint CRYPTPROTECT_VERIFY_PROTECTION = 64u;

		internal const uint CRYPTPROTECTMEMORY_BLOCK_SIZE = 16u;

		internal const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0u;

		internal const uint CRYPTPROTECTMEMORY_CROSS_PROCESS = 1u;

		internal const uint CRYPTPROTECTMEMORY_SAME_LOGON = 2u;

		internal const uint CRYPT_OID_INFO_OID_KEY = 1u;

		internal const uint CRYPT_OID_INFO_NAME_KEY = 2u;

		internal const uint CRYPT_OID_INFO_ALGID_KEY = 3u;

		internal const uint CRYPT_OID_INFO_SIGN_KEY = 4u;

		internal const uint CRYPT_HASH_ALG_OID_GROUP_ID = 1u;

		internal const uint CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2u;

		internal const uint CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3u;

		internal const uint CRYPT_SIGN_ALG_OID_GROUP_ID = 4u;

		internal const uint CRYPT_RDN_ATTR_OID_GROUP_ID = 5u;

		internal const uint CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6u;

		internal const uint CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7u;

		internal const uint CRYPT_POLICY_OID_GROUP_ID = 8u;

		internal const uint CRYPT_TEMPLATE_OID_GROUP_ID = 9u;

		internal const uint CRYPT_LAST_OID_GROUP_ID = 9u;

		internal const uint CRYPT_FIRST_ALG_OID_GROUP_ID = 1u;

		internal const uint CRYPT_LAST_ALG_OID_GROUP_ID = 4u;

		internal const uint CRYPT_ASN_ENCODING = 1u;

		internal const uint CRYPT_NDR_ENCODING = 2u;

		internal const uint X509_ASN_ENCODING = 1u;

		internal const uint X509_NDR_ENCODING = 2u;

		internal const uint PKCS_7_ASN_ENCODING = 65536u;

		internal const uint PKCS_7_NDR_ENCODING = 131072u;

		internal const uint PKCS_7_OR_X509_ASN_ENCODING = 65537u;

		internal const uint CERT_STORE_PROV_MSG = 1u;

		internal const uint CERT_STORE_PROV_MEMORY = 2u;

		internal const uint CERT_STORE_PROV_FILE = 3u;

		internal const uint CERT_STORE_PROV_REG = 4u;

		internal const uint CERT_STORE_PROV_PKCS7 = 5u;

		internal const uint CERT_STORE_PROV_SERIALIZED = 6u;

		internal const uint CERT_STORE_PROV_FILENAME_A = 7u;

		internal const uint CERT_STORE_PROV_FILENAME_W = 8u;

		internal const uint CERT_STORE_PROV_FILENAME = 8u;

		internal const uint CERT_STORE_PROV_SYSTEM_A = 9u;

		internal const uint CERT_STORE_PROV_SYSTEM_W = 10u;

		internal const uint CERT_STORE_PROV_SYSTEM = 10u;

		internal const uint CERT_STORE_PROV_COLLECTION = 11u;

		internal const uint CERT_STORE_PROV_SYSTEM_REGISTRY_A = 12u;

		internal const uint CERT_STORE_PROV_SYSTEM_REGISTRY_W = 13u;

		internal const uint CERT_STORE_PROV_SYSTEM_REGISTRY = 13u;

		internal const uint CERT_STORE_PROV_PHYSICAL_W = 14u;

		internal const uint CERT_STORE_PROV_PHYSICAL = 14u;

		internal const uint CERT_STORE_PROV_SMART_CARD_W = 15u;

		internal const uint CERT_STORE_PROV_SMART_CARD = 15u;

		internal const uint CERT_STORE_PROV_LDAP_W = 16u;

		internal const uint CERT_STORE_PROV_LDAP = 16u;

		internal const uint CERT_STORE_NO_CRYPT_RELEASE_FLAG = 1u;

		internal const uint CERT_STORE_SET_LOCALIZED_NAME_FLAG = 2u;

		internal const uint CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = 4u;

		internal const uint CERT_STORE_DELETE_FLAG = 16u;

		internal const uint CERT_STORE_SHARE_STORE_FLAG = 64u;

		internal const uint CERT_STORE_SHARE_CONTEXT_FLAG = 128u;

		internal const uint CERT_STORE_MANIFOLD_FLAG = 256u;

		internal const uint CERT_STORE_ENUM_ARCHIVED_FLAG = 512u;

		internal const uint CERT_STORE_UPDATE_KEYID_FLAG = 1024u;

		internal const uint CERT_STORE_BACKUP_RESTORE_FLAG = 2048u;

		internal const uint CERT_STORE_READONLY_FLAG = 32768u;

		internal const uint CERT_STORE_OPEN_EXISTING_FLAG = 16384u;

		internal const uint CERT_STORE_CREATE_NEW_FLAG = 8192u;

		internal const uint CERT_STORE_MAXIMUM_ALLOWED_FLAG = 4096u;

		internal const uint CERT_SYSTEM_STORE_UNPROTECTED_FLAG = 1073741824u;

		internal const uint CERT_SYSTEM_STORE_LOCATION_MASK = 16711680u;

		internal const uint CERT_SYSTEM_STORE_LOCATION_SHIFT = 16u;

		internal const uint CERT_SYSTEM_STORE_CURRENT_USER_ID = 1u;

		internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2u;

		internal const uint CERT_SYSTEM_STORE_CURRENT_SERVICE_ID = 4u;

		internal const uint CERT_SYSTEM_STORE_SERVICES_ID = 5u;

		internal const uint CERT_SYSTEM_STORE_USERS_ID = 6u;

		internal const uint CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID = 7u;

		internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID = 8u;

		internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID = 9u;

		internal const uint CERT_SYSTEM_STORE_CURRENT_USER = 65536u;

		internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = 131072u;

		internal const uint CERT_SYSTEM_STORE_CURRENT_SERVICE = 262144u;

		internal const uint CERT_SYSTEM_STORE_SERVICES = 327680u;

		internal const uint CERT_SYSTEM_STORE_USERS = 393216u;

		internal const uint CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = 458752u;

		internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = 524288u;

		internal const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = 589824u;

		internal const uint CERT_NAME_EMAIL_TYPE = 1u;

		internal const uint CERT_NAME_RDN_TYPE = 2u;

		internal const uint CERT_NAME_ATTR_TYPE = 3u;

		internal const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4u;

		internal const uint CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5u;

		internal const uint CERT_NAME_DNS_TYPE = 6u;

		internal const uint CERT_NAME_URL_TYPE = 7u;

		internal const uint CERT_NAME_UPN_TYPE = 8u;

		internal const uint CERT_SIMPLE_NAME_STR = 1u;

		internal const uint CERT_OID_NAME_STR = 2u;

		internal const uint CERT_X500_NAME_STR = 3u;

		internal const uint CERT_NAME_STR_SEMICOLON_FLAG = 1073741824u;

		internal const uint CERT_NAME_STR_NO_PLUS_FLAG = 536870912u;

		internal const uint CERT_NAME_STR_NO_QUOTING_FLAG = 268435456u;

		internal const uint CERT_NAME_STR_CRLF_FLAG = 134217728u;

		internal const uint CERT_NAME_STR_COMMA_FLAG = 67108864u;

		internal const uint CERT_NAME_STR_REVERSE_FLAG = 33554432u;

		internal const uint CERT_NAME_ISSUER_FLAG = 1u;

		internal const uint CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG = 65536u;

		internal const uint CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG = 131072u;

		internal const uint CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG = 262144u;

		internal const uint CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG = 524288u;

		internal const uint CERT_KEY_PROV_HANDLE_PROP_ID = 1u;

		internal const uint CERT_KEY_PROV_INFO_PROP_ID = 2u;

		internal const uint CERT_SHA1_HASH_PROP_ID = 3u;

		internal const uint CERT_MD5_HASH_PROP_ID = 4u;

		internal const uint CERT_HASH_PROP_ID = 3u;

		internal const uint CERT_KEY_CONTEXT_PROP_ID = 5u;

		internal const uint CERT_KEY_SPEC_PROP_ID = 6u;

		internal const uint CERT_IE30_RESERVED_PROP_ID = 7u;

		internal const uint CERT_PUBKEY_HASH_RESERVED_PROP_ID = 8u;

		internal const uint CERT_ENHKEY_USAGE_PROP_ID = 9u;

		internal const uint CERT_CTL_USAGE_PROP_ID = 9u;

		internal const uint CERT_NEXT_UPDATE_LOCATION_PROP_ID = 10u;

		internal const uint CERT_FRIENDLY_NAME_PROP_ID = 11u;

		internal const uint CERT_PVK_FILE_PROP_ID = 12u;

		internal const uint CERT_DESCRIPTION_PROP_ID = 13u;

		internal const uint CERT_ACCESS_STATE_PROP_ID = 14u;

		internal const uint CERT_SIGNATURE_HASH_PROP_ID = 15u;

		internal const uint CERT_SMART_CARD_DATA_PROP_ID = 16u;

		internal const uint CERT_EFS_PROP_ID = 17u;

		internal const uint CERT_FORTEZZA_DATA_PROP_ID = 18u;

		internal const uint CERT_ARCHIVED_PROP_ID = 19u;

		internal const uint CERT_KEY_IDENTIFIER_PROP_ID = 20u;

		internal const uint CERT_AUTO_ENROLL_PROP_ID = 21u;

		internal const uint CERT_PUBKEY_ALG_PARA_PROP_ID = 22u;

		internal const uint CERT_CROSS_CERT_DIST_POINTS_PROP_ID = 23u;

		internal const uint CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = 24u;

		internal const uint CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = 25u;

		internal const uint CERT_ENROLLMENT_PROP_ID = 26u;

		internal const uint CERT_DATE_STAMP_PROP_ID = 27u;

		internal const uint CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = 28u;

		internal const uint CERT_SUBJECT_NAME_MD5_HASH_PROP_ID = 29u;

		internal const uint CERT_EXTENDED_ERROR_INFO_PROP_ID = 30u;

		internal const uint CERT_RENEWAL_PROP_ID = 64u;

		internal const uint CERT_ARCHIVED_KEY_HASH_PROP_ID = 65u;

		internal const uint CERT_FIRST_RESERVED_PROP_ID = 66u;

		internal const uint CERT_DELETE_KEYSET_PROP_ID = 101u;

		internal const uint CERT_INFO_VERSION_FLAG = 1u;

		internal const uint CERT_INFO_SERIAL_NUMBER_FLAG = 2u;

		internal const uint CERT_INFO_SIGNATURE_ALGORITHM_FLAG = 3u;

		internal const uint CERT_INFO_ISSUER_FLAG = 4u;

		internal const uint CERT_INFO_NOT_BEFORE_FLAG = 5u;

		internal const uint CERT_INFO_NOT_AFTER_FLAG = 6u;

		internal const uint CERT_INFO_SUBJECT_FLAG = 7u;

		internal const uint CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG = 8u;

		internal const uint CERT_INFO_ISSUER_UNIQUE_ID_FLAG = 9u;

		internal const uint CERT_INFO_SUBJECT_UNIQUE_ID_FLAG = 10u;

		internal const uint CERT_INFO_EXTENSION_FLAG = 11u;

		internal const uint CERT_COMPARE_MASK = 65535u;

		internal const uint CERT_COMPARE_SHIFT = 16u;

		internal const uint CERT_COMPARE_ANY = 0u;

		internal const uint CERT_COMPARE_SHA1_HASH = 1u;

		internal const uint CERT_COMPARE_NAME = 2u;

		internal const uint CERT_COMPARE_ATTR = 3u;

		internal const uint CERT_COMPARE_MD5_HASH = 4u;

		internal const uint CERT_COMPARE_PROPERTY = 5u;

		internal const uint CERT_COMPARE_PUBLIC_KEY = 6u;

		internal const uint CERT_COMPARE_HASH = 1u;

		internal const uint CERT_COMPARE_NAME_STR_A = 7u;

		internal const uint CERT_COMPARE_NAME_STR_W = 8u;

		internal const uint CERT_COMPARE_KEY_SPEC = 9u;

		internal const uint CERT_COMPARE_ENHKEY_USAGE = 10u;

		internal const uint CERT_COMPARE_CTL_USAGE = 10u;

		internal const uint CERT_COMPARE_SUBJECT_CERT = 11u;

		internal const uint CERT_COMPARE_ISSUER_OF = 12u;

		internal const uint CERT_COMPARE_EXISTING = 13u;

		internal const uint CERT_COMPARE_SIGNATURE_HASH = 14u;

		internal const uint CERT_COMPARE_KEY_IDENTIFIER = 15u;

		internal const uint CERT_COMPARE_CERT_ID = 16u;

		internal const uint CERT_COMPARE_CROSS_CERT_DIST_POINTS = 17u;

		internal const uint CERT_COMPARE_PUBKEY_MD5_HASH = 18u;

		internal const uint CERT_FIND_ANY = 0u;

		internal const uint CERT_FIND_SHA1_HASH = 65536u;

		internal const uint CERT_FIND_MD5_HASH = 262144u;

		internal const uint CERT_FIND_SIGNATURE_HASH = 917504u;

		internal const uint CERT_FIND_KEY_IDENTIFIER = 983040u;

		internal const uint CERT_FIND_HASH = 65536u;

		internal const uint CERT_FIND_PROPERTY = 327680u;

		internal const uint CERT_FIND_PUBLIC_KEY = 393216u;

		internal const uint CERT_FIND_SUBJECT_NAME = 131079u;

		internal const uint CERT_FIND_SUBJECT_ATTR = 196615u;

		internal const uint CERT_FIND_ISSUER_NAME = 131076u;

		internal const uint CERT_FIND_ISSUER_ATTR = 196612u;

		internal const uint CERT_FIND_SUBJECT_STR_A = 458759u;

		internal const uint CERT_FIND_SUBJECT_STR_W = 524295u;

		internal const uint CERT_FIND_SUBJECT_STR = 524295u;

		internal const uint CERT_FIND_ISSUER_STR_A = 458756u;

		internal const uint CERT_FIND_ISSUER_STR_W = 524292u;

		internal const uint CERT_FIND_ISSUER_STR = 524292u;

		internal const uint CERT_FIND_KEY_SPEC = 589824u;

		internal const uint CERT_FIND_ENHKEY_USAGE = 655360u;

		internal const uint CERT_FIND_CTL_USAGE = 655360u;

		internal const uint CERT_FIND_SUBJECT_CERT = 720896u;

		internal const uint CERT_FIND_ISSUER_OF = 786432u;

		internal const uint CERT_FIND_EXISTING = 851968u;

		internal const uint CERT_FIND_CERT_ID = 1048576u;

		internal const uint CERT_FIND_CROSS_CERT_DIST_POINTS = 1114112u;

		internal const uint CERT_FIND_PUBKEY_MD5_HASH = 1179648u;

		internal const uint CERT_ENCIPHER_ONLY_KEY_USAGE = 1u;

		internal const uint CERT_CRL_SIGN_KEY_USAGE = 2u;

		internal const uint CERT_KEY_CERT_SIGN_KEY_USAGE = 4u;

		internal const uint CERT_KEY_AGREEMENT_KEY_USAGE = 8u;

		internal const uint CERT_DATA_ENCIPHERMENT_KEY_USAGE = 16u;

		internal const uint CERT_KEY_ENCIPHERMENT_KEY_USAGE = 32u;

		internal const uint CERT_NON_REPUDIATION_KEY_USAGE = 64u;

		internal const uint CERT_DIGITAL_SIGNATURE_KEY_USAGE = 128u;

		internal const uint CERT_DECIPHER_ONLY_KEY_USAGE = 32768u;

		internal const uint CERT_STORE_ADD_NEW = 1u;

		internal const uint CERT_STORE_ADD_USE_EXISTING = 2u;

		internal const uint CERT_STORE_ADD_REPLACE_EXISTING = 3u;

		internal const uint CERT_STORE_ADD_ALWAYS = 4u;

		internal const uint CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5u;

		internal const uint CERT_STORE_ADD_NEWER = 6u;

		internal const uint CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7u;

		internal const uint CERT_STORE_SAVE_AS_STORE = 1u;

		internal const uint CERT_STORE_SAVE_AS_PKCS7 = 2u;

		internal const uint CERT_STORE_SAVE_TO_FILE = 1u;

		internal const uint CERT_STORE_SAVE_TO_MEMORY = 2u;

		internal const uint CERT_STORE_SAVE_TO_FILENAME_A = 3u;

		internal const uint CERT_STORE_SAVE_TO_FILENAME_W = 4u;

		internal const uint CERT_STORE_SAVE_TO_FILENAME = 4u;

		internal const uint CERT_CA_SUBJECT_FLAG = 128u;

		internal const uint CERT_END_ENTITY_SUBJECT_FLAG = 64u;

		internal const uint RSA_CSP_PUBLICKEYBLOB = 19u;

		internal const uint X509_MULTI_BYTE_UINT = 38u;

		internal const uint X509_DSS_PUBLICKEY = 38u;

		internal const uint X509_DSS_PARAMETERS = 39u;

		internal const uint X509_DSS_SIGNATURE = 40u;

		internal const uint X509_EXTENSIONS = 5u;

		internal const uint X509_NAME_VALUE = 6u;

		internal const uint X509_NAME = 7u;

		internal const uint X509_AUTHORITY_KEY_ID = 9u;

		internal const uint X509_KEY_USAGE_RESTRICTION = 11u;

		internal const uint X509_BASIC_CONSTRAINTS = 13u;

		internal const uint X509_KEY_USAGE = 14u;

		internal const uint X509_BASIC_CONSTRAINTS2 = 15u;

		internal const uint X509_CERT_POLICIES = 16u;

		internal const uint PKCS_UTC_TIME = 17u;

		internal const uint PKCS_ATTRIBUTE = 22u;

		internal const uint X509_UNICODE_NAME_VALUE = 24u;

		internal const uint X509_OCTET_STRING = 25u;

		internal const uint X509_BITS = 26u;

		internal const uint X509_ANY_STRING = 6u;

		internal const uint X509_UNICODE_ANY_STRING = 24u;

		internal const uint X509_ENHANCED_KEY_USAGE = 36u;

		internal const uint PKCS_RC2_CBC_PARAMETERS = 41u;

		internal const uint X509_CERTIFICATE_TEMPLATE = 64u;

		internal const uint PKCS7_SIGNER_INFO = 500u;

		internal const uint CMS_SIGNER_INFO = 501u;

		internal const string szOID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.1";

		internal const string szOID_KEY_USAGE_RESTRICTION = "2.5.29.4";

		internal const string szOID_KEY_USAGE = "2.5.29.15";

		internal const string szOID_KEYID_RDN = "1.3.6.1.4.1.311.10.7.1";

		internal const string szOID_RDN_DUMMY_SIGNER = "1.3.6.1.4.1.311.21.9";

		internal const uint CERT_CHAIN_POLICY_BASE = 1u;

		internal const uint CERT_CHAIN_POLICY_AUTHENTICODE = 2u;

		internal const uint CERT_CHAIN_POLICY_AUTHENTICODE_TS = 3u;

		internal const uint CERT_CHAIN_POLICY_SSL = 4u;

		internal const uint CERT_CHAIN_POLICY_BASIC_CONSTRAINTS = 5u;

		internal const uint CERT_CHAIN_POLICY_NT_AUTH = 6u;

		internal const uint CERT_CHAIN_POLICY_MICROSOFT_ROOT = 7u;

		internal const uint USAGE_MATCH_TYPE_AND = 0u;

		internal const uint USAGE_MATCH_TYPE_OR = 1u;

		internal const uint CERT_CHAIN_REVOCATION_CHECK_END_CERT = 268435456u;

		internal const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN = 536870912u;

		internal const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 1073741824u;

		internal const uint CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY = 2147483648u;

		internal const uint CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT = 134217728u;

		internal const uint CERT_TRUST_NO_ERROR = 0u;

		internal const uint CERT_TRUST_IS_NOT_TIME_VALID = 1u;

		internal const uint CERT_TRUST_IS_NOT_TIME_NESTED = 2u;

		internal const uint CERT_TRUST_IS_REVOKED = 4u;

		internal const uint CERT_TRUST_IS_NOT_SIGNATURE_VALID = 8u;

		internal const uint CERT_TRUST_IS_NOT_VALID_FOR_USAGE = 16u;

		internal const uint CERT_TRUST_IS_UNTRUSTED_ROOT = 32u;

		internal const uint CERT_TRUST_REVOCATION_STATUS_UNKNOWN = 64u;

		internal const uint CERT_TRUST_IS_CYCLIC = 128u;

		internal const uint CERT_TRUST_INVALID_EXTENSION = 256u;

		internal const uint CERT_TRUST_INVALID_POLICY_CONSTRAINTS = 512u;

		internal const uint CERT_TRUST_INVALID_BASIC_CONSTRAINTS = 1024u;

		internal const uint CERT_TRUST_INVALID_NAME_CONSTRAINTS = 2048u;

		internal const uint CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 4096u;

		internal const uint CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT = 8192u;

		internal const uint CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT = 16384u;

		internal const uint CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT = 32768u;

		internal const uint CERT_TRUST_IS_OFFLINE_REVOCATION = 16777216u;

		internal const uint CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY = 33554432u;

		internal const uint CERT_TRUST_IS_PARTIAL_CHAIN = 65536u;

		internal const uint CERT_TRUST_CTL_IS_NOT_TIME_VALID = 131072u;

		internal const uint CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID = 262144u;

		internal const uint CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE = 524288u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG = 1u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG = 2u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG = 4u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG = 8u;

		internal const uint CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG = 16u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG = 32u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG = 64u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG = 128u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG = 256u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG = 512u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG = 1024u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG = 2048u;

		internal const uint CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS = 3840u;

		internal const uint CERT_TRUST_HAS_EXACT_MATCH_ISSUER = 1u;

		internal const uint CERT_TRUST_HAS_KEY_MATCH_ISSUER = 2u;

		internal const uint CERT_TRUST_HAS_NAME_MATCH_ISSUER = 4u;

		internal const uint CERT_TRUST_IS_SELF_SIGNED = 8u;

		internal const uint CERT_TRUST_HAS_PREFERRED_ISSUER = 256u;

		internal const uint CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY = 512u;

		internal const uint CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS = 1024u;

		internal const uint CERT_TRUST_IS_COMPLEX_CHAIN = 65536u;

		internal const string szOID_PKIX_NO_SIGNATURE = "1.3.6.1.5.5.7.6.2";

		internal const string szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

		internal const string szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

		internal const string szOID_PKIX_KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";

		internal const string szOID_PKIX_KP_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";

		internal const string SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID = "1.3.6.1.4.1.311.2.1.21";

		internal const string SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID = "1.3.6.1.4.1.311.2.1.22";

		internal const uint HCCE_CURRENT_USER = 0u;

		internal const uint HCCE_LOCAL_MACHINE = 1u;

		internal const string szOID_PKCS_1 = "1.2.840.113549.1.1";

		internal const string szOID_PKCS_2 = "1.2.840.113549.1.2";

		internal const string szOID_PKCS_3 = "1.2.840.113549.1.3";

		internal const string szOID_PKCS_4 = "1.2.840.113549.1.4";

		internal const string szOID_PKCS_5 = "1.2.840.113549.1.5";

		internal const string szOID_PKCS_6 = "1.2.840.113549.1.6";

		internal const string szOID_PKCS_7 = "1.2.840.113549.1.7";

		internal const string szOID_PKCS_8 = "1.2.840.113549.1.8";

		internal const string szOID_PKCS_9 = "1.2.840.113549.1.9";

		internal const string szOID_PKCS_10 = "1.2.840.113549.1.10";

		internal const string szOID_PKCS_12 = "1.2.840.113549.1.12";

		internal const string szOID_RSA_data = "1.2.840.113549.1.7.1";

		internal const string szOID_RSA_signedData = "1.2.840.113549.1.7.2";

		internal const string szOID_RSA_envelopedData = "1.2.840.113549.1.7.3";

		internal const string szOID_RSA_signEnvData = "1.2.840.113549.1.7.4";

		internal const string szOID_RSA_digestedData = "1.2.840.113549.1.7.5";

		internal const string szOID_RSA_hashedData = "1.2.840.113549.1.7.5";

		internal const string szOID_RSA_encryptedData = "1.2.840.113549.1.7.6";

		internal const string szOID_RSA_emailAddr = "1.2.840.113549.1.9.1";

		internal const string szOID_RSA_unstructName = "1.2.840.113549.1.9.2";

		internal const string szOID_RSA_contentType = "1.2.840.113549.1.9.3";

		internal const string szOID_RSA_messageDigest = "1.2.840.113549.1.9.4";

		internal const string szOID_RSA_signingTime = "1.2.840.113549.1.9.5";

		internal const string szOID_RSA_counterSign = "1.2.840.113549.1.9.6";

		internal const string szOID_RSA_challengePwd = "1.2.840.113549.1.9.7";

		internal const string szOID_RSA_unstructAddr = "1.2.840.113549.1.9.8";

		internal const string szOID_RSA_extCertAttrs = "1.2.840.113549.1.9.9";

		internal const string szOID_RSA_SMIMECapabilities = "1.2.840.113549.1.9.15";

		internal const string szOID_CAPICOM = "1.3.6.1.4.1.311.88";

		internal const string szOID_CAPICOM_version = "1.3.6.1.4.1.311.88.1";

		internal const string szOID_CAPICOM_attribute = "1.3.6.1.4.1.311.88.2";

		internal const string szOID_CAPICOM_documentName = "1.3.6.1.4.1.311.88.2.1";

		internal const string szOID_CAPICOM_documentDescription = "1.3.6.1.4.1.311.88.2.2";

		internal const string szOID_CAPICOM_encryptedData = "1.3.6.1.4.1.311.88.3";

		internal const string szOID_CAPICOM_encryptedContent = "1.3.6.1.4.1.311.88.3.1";

		internal const string szOID_OIWSEC_sha1 = "1.3.14.3.2.26";

		internal const string szOID_RSA_MD5 = "1.2.840.113549.2.5";

		internal const string szOID_OIWSEC_SHA256 = "2.16.840.1.101.3.4.1";

		internal const string szOID_OIWSEC_SHA384 = "2.16.840.1.101.3.4.2";

		internal const string szOID_OIWSEC_SHA512 = "2.16.840.1.101.3.4.3";

		internal const string szOID_RSA_RC2CBC = "1.2.840.113549.3.2";

		internal const string szOID_RSA_RC4 = "1.2.840.113549.3.4";

		internal const string szOID_RSA_DES_EDE3_CBC = "1.2.840.113549.3.7";

		internal const string szOID_OIWSEC_desCBC = "1.3.14.3.2.7";

		internal const string szOID_RSA_SMIMEalg = "1.2.840.113549.1.9.16.3";

		internal const string szOID_RSA_SMIMEalgESDH = "1.2.840.113549.1.9.16.3.5";

		internal const string szOID_RSA_SMIMEalgCMS3DESwrap = "1.2.840.113549.1.9.16.3.6";

		internal const string szOID_RSA_SMIMEalgCMSRC2wrap = "1.2.840.113549.1.9.16.3.7";

		internal const string szOID_X957_DSA = "1.2.840.10040.4.1";

		internal const string szOID_X957_sha1DSA = "1.2.840.10040.4.3";

		internal const string szOID_OIWSEC_sha1RSASign = "1.3.14.3.2.29";

		internal const uint CERT_ALT_NAME_OTHER_NAME = 1u;

		internal const uint CERT_ALT_NAME_RFC822_NAME = 2u;

		internal const uint CERT_ALT_NAME_DNS_NAME = 3u;

		internal const uint CERT_ALT_NAME_X400_ADDRESS = 4u;

		internal const uint CERT_ALT_NAME_DIRECTORY_NAME = 5u;

		internal const uint CERT_ALT_NAME_EDI_PARTY_NAME = 6u;

		internal const uint CERT_ALT_NAME_URL = 7u;

		internal const uint CERT_ALT_NAME_IP_ADDRESS = 8u;

		internal const uint CERT_ALT_NAME_REGISTERED_ID = 9u;

		internal const uint CERT_RDN_ANY_TYPE = 0u;

		internal const uint CERT_RDN_ENCODED_BLOB = 1u;

		internal const uint CERT_RDN_OCTET_STRING = 2u;

		internal const uint CERT_RDN_NUMERIC_STRING = 3u;

		internal const uint CERT_RDN_PRINTABLE_STRING = 4u;

		internal const uint CERT_RDN_TELETEX_STRING = 5u;

		internal const uint CERT_RDN_T61_STRING = 5u;

		internal const uint CERT_RDN_VIDEOTEX_STRING = 6u;

		internal const uint CERT_RDN_IA5_STRING = 7u;

		internal const uint CERT_RDN_GRAPHIC_STRING = 8u;

		internal const uint CERT_RDN_VISIBLE_STRING = 9u;

		internal const uint CERT_RDN_ISO646_STRING = 9u;

		internal const uint CERT_RDN_GENERAL_STRING = 10u;

		internal const uint CERT_RDN_UNIVERSAL_STRING = 11u;

		internal const uint CERT_RDN_INT4_STRING = 11u;

		internal const uint CERT_RDN_BMP_STRING = 12u;

		internal const uint CERT_RDN_UNICODE_STRING = 12u;

		internal const uint CERT_RDN_UTF8_STRING = 13u;

		internal const uint CERT_RDN_TYPE_MASK = 255u;

		internal const uint CERT_RDN_FLAGS_MASK = 4278190080u;

		internal const uint CERT_STORE_CTRL_RESYNC = 1u;

		internal const uint CERT_STORE_CTRL_NOTIFY_CHANGE = 2u;

		internal const uint CERT_STORE_CTRL_COMMIT = 3u;

		internal const uint CERT_STORE_CTRL_AUTO_RESYNC = 4u;

		internal const uint CERT_STORE_CTRL_CANCEL_NOTIFY = 5u;

		internal const uint CERT_ID_ISSUER_SERIAL_NUMBER = 1u;

		internal const uint CERT_ID_KEY_IDENTIFIER = 2u;

		internal const uint CERT_ID_SHA1_HASH = 3u;

		internal const string MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";

		internal const string MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";

		internal const string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";

		internal const string MS_DEF_DSS_DH_PROV = "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider";

		internal const string MS_ENH_DSS_DH_PROV = "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider";

		internal const string DummySignerCommonName = "CN=Dummy Signer";

		internal const uint PROV_RSA_FULL = 1u;

		internal const uint PROV_DSS_DH = 13u;

		internal const uint ALG_TYPE_ANY = 0u;

		internal const uint ALG_TYPE_DSS = 512u;

		internal const uint ALG_TYPE_RSA = 1024u;

		internal const uint ALG_TYPE_BLOCK = 1536u;

		internal const uint ALG_TYPE_STREAM = 2048u;

		internal const uint ALG_TYPE_DH = 2560u;

		internal const uint ALG_TYPE_SECURECHANNEL = 3072u;

		internal const uint ALG_CLASS_ANY = 0u;

		internal const uint ALG_CLASS_SIGNATURE = 8192u;

		internal const uint ALG_CLASS_MSG_ENCRYPT = 16384u;

		internal const uint ALG_CLASS_DATA_ENCRYPT = 24576u;

		internal const uint ALG_CLASS_HASH = 32768u;

		internal const uint ALG_CLASS_KEY_EXCHANGE = 40960u;

		internal const uint ALG_CLASS_ALL = 57344u;

		internal const uint ALG_SID_ANY = 0u;

		internal const uint ALG_SID_RSA_ANY = 0u;

		internal const uint ALG_SID_RSA_PKCS = 1u;

		internal const uint ALG_SID_RSA_MSATWORK = 2u;

		internal const uint ALG_SID_RSA_ENTRUST = 3u;

		internal const uint ALG_SID_RSA_PGP = 4u;

		internal const uint ALG_SID_DSS_ANY = 0u;

		internal const uint ALG_SID_DSS_PKCS = 1u;

		internal const uint ALG_SID_DSS_DMS = 2u;

		internal const uint ALG_SID_DES = 1u;

		internal const uint ALG_SID_3DES = 3u;

		internal const uint ALG_SID_DESX = 4u;

		internal const uint ALG_SID_IDEA = 5u;

		internal const uint ALG_SID_CAST = 6u;

		internal const uint ALG_SID_SAFERSK64 = 7u;

		internal const uint ALG_SID_SAFERSK128 = 8u;

		internal const uint ALG_SID_3DES_112 = 9u;

		internal const uint ALG_SID_CYLINK_MEK = 12u;

		internal const uint ALG_SID_RC5 = 13u;

		internal const uint ALG_SID_AES_128 = 14u;

		internal const uint ALG_SID_AES_192 = 15u;

		internal const uint ALG_SID_AES_256 = 16u;

		internal const uint ALG_SID_AES = 17u;

		internal const uint ALG_SID_SKIPJACK = 10u;

		internal const uint ALG_SID_TEK = 11u;

		internal const uint ALG_SID_RC2 = 2u;

		internal const uint ALG_SID_RC4 = 1u;

		internal const uint ALG_SID_SEAL = 2u;

		internal const uint ALG_SID_DH_SANDF = 1u;

		internal const uint ALG_SID_DH_EPHEM = 2u;

		internal const uint ALG_SID_AGREED_KEY_ANY = 3u;

		internal const uint ALG_SID_KEA = 4u;

		internal const uint ALG_SID_MD2 = 1u;

		internal const uint ALG_SID_MD4 = 2u;

		internal const uint ALG_SID_MD5 = 3u;

		internal const uint ALG_SID_SHA = 4u;

		internal const uint ALG_SID_SHA1 = 4u;

		internal const uint ALG_SID_MAC = 5u;

		internal const uint ALG_SID_RIPEMD = 6u;

		internal const uint ALG_SID_RIPEMD160 = 7u;

		internal const uint ALG_SID_SSL3SHAMD5 = 8u;

		internal const uint ALG_SID_HMAC = 9u;

		internal const uint ALG_SID_TLS1PRF = 10u;

		internal const uint ALG_SID_HASH_REPLACE_OWF = 11u;

		internal const uint ALG_SID_SSL3_MASTER = 1u;

		internal const uint ALG_SID_SCHANNEL_MASTER_HASH = 2u;

		internal const uint ALG_SID_SCHANNEL_MAC_KEY = 3u;

		internal const uint ALG_SID_PCT1_MASTER = 4u;

		internal const uint ALG_SID_SSL2_MASTER = 5u;

		internal const uint ALG_SID_TLS1_MASTER = 6u;

		internal const uint ALG_SID_SCHANNEL_ENC_KEY = 7u;

		internal const uint CALG_MD2 = 32769u;

		internal const uint CALG_MD4 = 32770u;

		internal const uint CALG_MD5 = 32771u;

		internal const uint CALG_SHA = 32772u;

		internal const uint CALG_SHA1 = 32772u;

		internal const uint CALG_MAC = 32773u;

		internal const uint CALG_RSA_SIGN = 9216u;

		internal const uint CALG_DSS_SIGN = 8704u;

		internal const uint CALG_NO_SIGN = 8192u;

		internal const uint CALG_RSA_KEYX = 41984u;

		internal const uint CALG_DES = 26113u;

		internal const uint CALG_3DES_112 = 26121u;

		internal const uint CALG_3DES = 26115u;

		internal const uint CALG_DESX = 26116u;

		internal const uint CALG_RC2 = 26114u;

		internal const uint CALG_RC4 = 26625u;

		internal const uint CALG_SEAL = 26626u;

		internal const uint CALG_DH_SF = 43521u;

		internal const uint CALG_DH_EPHEM = 43522u;

		internal const uint CALG_AGREEDKEY_ANY = 43523u;

		internal const uint CALG_KEA_KEYX = 43524u;

		internal const uint CALG_HUGHES_MD5 = 40963u;

		internal const uint CALG_SKIPJACK = 26122u;

		internal const uint CALG_TEK = 26123u;

		internal const uint CALG_CYLINK_MEK = 26124u;

		internal const uint CALG_SSL3_SHAMD5 = 32776u;

		internal const uint CALG_SSL3_MASTER = 19457u;

		internal const uint CALG_SCHANNEL_MASTER_HASH = 19458u;

		internal const uint CALG_SCHANNEL_MAC_KEY = 19459u;

		internal const uint CALG_SCHANNEL_ENC_KEY = 19463u;

		internal const uint CALG_PCT1_MASTER = 19460u;

		internal const uint CALG_SSL2_MASTER = 19461u;

		internal const uint CALG_TLS1_MASTER = 19462u;

		internal const uint CALG_RC5 = 26125u;

		internal const uint CALG_HMAC = 32777u;

		internal const uint CALG_TLS1PRF = 32778u;

		internal const uint CALG_HASH_REPLACE_OWF = 32779u;

		internal const uint CALG_AES_128 = 26126u;

		internal const uint CALG_AES_192 = 26127u;

		internal const uint CALG_AES_256 = 26128u;

		internal const uint CALG_AES = 26129u;

		internal const uint CRYPT_FIRST = 1u;

		internal const uint CRYPT_NEXT = 2u;

		internal const uint PP_ENUMALGS_EX = 22u;

		internal const uint CRYPT_VERIFYCONTEXT = 4026531840u;

		internal const uint CRYPT_NEWKEYSET = 8u;

		internal const uint CRYPT_DELETEKEYSET = 16u;

		internal const uint CRYPT_MACHINE_KEYSET = 32u;

		internal const uint CRYPT_SILENT = 64u;

		internal const uint CRYPT_USER_KEYSET = 4096u;

		internal const uint CRYPT_EXPORTABLE = 1u;

		internal const uint CRYPT_USER_PROTECTED = 2u;

		internal const uint CRYPT_CREATE_SALT = 4u;

		internal const uint CRYPT_UPDATE_KEY = 8u;

		internal const uint CRYPT_NO_SALT = 16u;

		internal const uint CRYPT_PREGEN = 64u;

		internal const uint CRYPT_RECIPIENT = 16u;

		internal const uint CRYPT_INITIATOR = 64u;

		internal const uint CRYPT_ONLINE = 128u;

		internal const uint CRYPT_SF = 256u;

		internal const uint CRYPT_CREATE_IV = 512u;

		internal const uint CRYPT_KEK = 1024u;

		internal const uint CRYPT_DATA_KEY = 2048u;

		internal const uint CRYPT_VOLATILE = 4096u;

		internal const uint CRYPT_SGCKEY = 8192u;

		internal const uint CRYPT_ARCHIVABLE = 16384u;

		internal const byte CUR_BLOB_VERSION = 2;

		internal const byte SIMPLEBLOB = 1;

		internal const byte PUBLICKEYBLOB = 6;

		internal const byte PRIVATEKEYBLOB = 7;

		internal const byte PLAINTEXTKEYBLOB = 8;

		internal const byte OPAQUEKEYBLOB = 9;

		internal const byte PUBLICKEYBLOBEX = 10;

		internal const byte SYMMETRICWRAPKEYBLOB = 11;

		internal const uint DSS_MAGIC = 827544388u;

		internal const uint DSS_PRIVATE_MAGIC = 844321604u;

		internal const uint DSS_PUB_MAGIC_VER3 = 861098820u;

		internal const uint DSS_PRIV_MAGIC_VER3 = 877876036u;

		internal const uint RSA_PUB_MAGIC = 826364754u;

		internal const uint RSA_PRIV_MAGIC = 843141970u;

		internal const uint CRYPT_ACQUIRE_CACHE_FLAG = 1u;

		internal const uint CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 2u;

		internal const uint CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 4u;

		internal const uint CRYPT_ACQUIRE_SILENT_FLAG = 64u;

		internal const uint CMSG_BARE_CONTENT_FLAG = 1u;

		internal const uint CMSG_LENGTH_ONLY_FLAG = 2u;

		internal const uint CMSG_DETACHED_FLAG = 4u;

		internal const uint CMSG_AUTHENTICATED_ATTRIBUTES_FLAG = 8u;

		internal const uint CMSG_CONTENTS_OCTETS_FLAG = 16u;

		internal const uint CMSG_MAX_LENGTH_FLAG = 32u;

		internal const uint CMSG_TYPE_PARAM = 1u;

		internal const uint CMSG_CONTENT_PARAM = 2u;

		internal const uint CMSG_BARE_CONTENT_PARAM = 3u;

		internal const uint CMSG_INNER_CONTENT_TYPE_PARAM = 4u;

		internal const uint CMSG_SIGNER_COUNT_PARAM = 5u;

		internal const uint CMSG_SIGNER_INFO_PARAM = 6u;

		internal const uint CMSG_SIGNER_CERT_INFO_PARAM = 7u;

		internal const uint CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8u;

		internal const uint CMSG_SIGNER_AUTH_ATTR_PARAM = 9u;

		internal const uint CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10u;

		internal const uint CMSG_CERT_COUNT_PARAM = 11u;

		internal const uint CMSG_CERT_PARAM = 12u;

		internal const uint CMSG_CRL_COUNT_PARAM = 13u;

		internal const uint CMSG_CRL_PARAM = 14u;

		internal const uint CMSG_ENVELOPE_ALGORITHM_PARAM = 15u;

		internal const uint CMSG_RECIPIENT_COUNT_PARAM = 17u;

		internal const uint CMSG_RECIPIENT_INDEX_PARAM = 18u;

		internal const uint CMSG_RECIPIENT_INFO_PARAM = 19u;

		internal const uint CMSG_HASH_ALGORITHM_PARAM = 20u;

		internal const uint CMSG_HASH_DATA_PARAM = 21u;

		internal const uint CMSG_COMPUTED_HASH_PARAM = 22u;

		internal const uint CMSG_ENCRYPT_PARAM = 26u;

		internal const uint CMSG_ENCRYPTED_DIGEST = 27u;

		internal const uint CMSG_ENCODED_SIGNER = 28u;

		internal const uint CMSG_ENCODED_MESSAGE = 29u;

		internal const uint CMSG_VERSION_PARAM = 30u;

		internal const uint CMSG_ATTR_CERT_COUNT_PARAM = 31u;

		internal const uint CMSG_ATTR_CERT_PARAM = 32u;

		internal const uint CMSG_CMS_RECIPIENT_COUNT_PARAM = 33u;

		internal const uint CMSG_CMS_RECIPIENT_INDEX_PARAM = 34u;

		internal const uint CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35u;

		internal const uint CMSG_CMS_RECIPIENT_INFO_PARAM = 36u;

		internal const uint CMSG_UNPROTECTED_ATTR_PARAM = 37u;

		internal const uint CMSG_SIGNER_CERT_ID_PARAM = 38u;

		internal const uint CMSG_CMS_SIGNER_INFO_PARAM = 39u;

		internal const uint CMSG_CTRL_VERIFY_SIGNATURE = 1u;

		internal const uint CMSG_CTRL_DECRYPT = 2u;

		internal const uint CMSG_CTRL_VERIFY_HASH = 5u;

		internal const uint CMSG_CTRL_ADD_SIGNER = 6u;

		internal const uint CMSG_CTRL_DEL_SIGNER = 7u;

		internal const uint CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR = 8u;

		internal const uint CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR = 9u;

		internal const uint CMSG_CTRL_ADD_CERT = 10u;

		internal const uint CMSG_CTRL_DEL_CERT = 11u;

		internal const uint CMSG_CTRL_ADD_CRL = 12u;

		internal const uint CMSG_CTRL_DEL_CRL = 13u;

		internal const uint CMSG_CTRL_ADD_ATTR_CERT = 14u;

		internal const uint CMSG_CTRL_DEL_ATTR_CERT = 15u;

		internal const uint CMSG_CTRL_KEY_TRANS_DECRYPT = 16u;

		internal const uint CMSG_CTRL_KEY_AGREE_DECRYPT = 17u;

		internal const uint CMSG_CTRL_MAIL_LIST_DECRYPT = 18u;

		internal const uint CMSG_CTRL_VERIFY_SIGNATURE_EX = 19u;

		internal const uint CMSG_CTRL_ADD_CMS_SIGNER_INFO = 20u;

		internal const uint CMSG_VERIFY_SIGNER_PUBKEY = 1u;

		internal const uint CMSG_VERIFY_SIGNER_CERT = 2u;

		internal const uint CMSG_VERIFY_SIGNER_CHAIN = 3u;

		internal const uint CMSG_VERIFY_SIGNER_NULL = 4u;

		internal const uint CMSG_DATA = 1u;

		internal const uint CMSG_SIGNED = 2u;

		internal const uint CMSG_ENVELOPED = 3u;

		internal const uint CMSG_SIGNED_AND_ENVELOPED = 4u;

		internal const uint CMSG_HASHED = 5u;

		internal const uint CMSG_ENCRYPTED = 6u;

		internal const uint CMSG_KEY_TRANS_RECIPIENT = 1u;

		internal const uint CMSG_KEY_AGREE_RECIPIENT = 2u;

		internal const uint CMSG_MAIL_LIST_RECIPIENT = 3u;

		internal const uint CMSG_KEY_AGREE_ORIGINATOR_CERT = 1u;

		internal const uint CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY = 2u;

		internal const uint CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE = 1u;

		internal const uint CMSG_KEY_AGREE_STATIC_KEY_CHOICE = 2u;

		internal const uint CMSG_ENVELOPED_RECIPIENT_V0 = 0u;

		internal const uint CMSG_ENVELOPED_RECIPIENT_V2 = 2u;

		internal const uint CMSG_ENVELOPED_RECIPIENT_V3 = 3u;

		internal const uint CMSG_ENVELOPED_RECIPIENT_V4 = 4u;

		internal const uint CMSG_KEY_TRANS_PKCS_1_5_VERSION = 0u;

		internal const uint CMSG_KEY_TRANS_CMS_VERSION = 2u;

		internal const uint CMSG_KEY_AGREE_VERSION = 3u;

		internal const uint CMSG_MAIL_LIST_VERSION = 4u;

		internal const uint CRYPT_RC2_40BIT_VERSION = 160u;

		internal const uint CRYPT_RC2_56BIT_VERSION = 52u;

		internal const uint CRYPT_RC2_64BIT_VERSION = 120u;

		internal const uint CRYPT_RC2_128BIT_VERSION = 58u;

		internal const int E_NOTIMPL = -2147483647;

		internal const int E_OUTOFMEMORY = -2147024882;

		internal const int NTE_NO_KEY = -2146893811;

		internal const int NTE_BAD_PUBLIC_KEY = -2146893803;

		internal const int NTE_BAD_KEYSET = -2146893802;

		internal const int CRYPT_E_MSG_ERROR = -2146889727;

		internal const int CRYPT_E_UNKNOWN_ALGO = -2146889726;

		internal const int CRYPT_E_INVALID_MSG_TYPE = -2146889724;

		internal const int CRYPT_E_RECIPIENT_NOT_FOUND = -2146889717;

		internal const int CRYPT_E_SIGNER_NOT_FOUND = -2146889714;

		internal const int CRYPT_E_ATTRIBUTES_MISSING = -2146889713;

		internal const int CRYPT_E_BAD_ENCODE = -2146885630;

		internal const int CRYPT_E_NOT_FOUND = -2146885628;

		internal const int CRYPT_E_NO_MATCH = -2146885623;

		internal const int CRYPT_E_NO_SIGNER = -2146885618;

		internal const int CRYPT_E_REVOKED = -2146885616;

		internal const int CRYPT_E_NO_REVOCATION_CHECK = -2146885614;

		internal const int CRYPT_E_REVOCATION_OFFLINE = -2146885613;

		internal const int CRYPT_E_ASN1_BADTAG = -2146881269;

		internal const int TRUST_E_CERT_SIGNATURE = -2146869244;

		internal const int TRUST_E_BASIC_CONSTRAINTS = -2146869223;

		internal const int CERT_E_EXPIRED = -2146762495;

		internal const int CERT_E_VALIDITYPERIODNESTING = -2146762494;

		internal const int CERT_E_UNTRUSTEDROOT = -2146762487;

		internal const int CERT_E_CHAINING = -2146762486;

		internal const int TRUST_E_FAIL = -2146762485;

		internal const int CERT_E_REVOKED = -2146762484;

		internal const int CERT_E_UNTRUSTEDTESTROOT = -2146762483;

		internal const int CERT_E_REVOCATION_FAILURE = -2146762482;

		internal const int CERT_E_WRONG_USAGE = -2146762480;

		internal const int CERT_E_INVALID_POLICY = -2146762477;

		internal const int CERT_E_INVALID_NAME = -2146762476;

		internal const int ERROR_SUCCESS = 0;

		internal const int ERROR_CALL_NOT_IMPLEMENTED = 120;

		internal const int ERROR_CANCELLED = 1223;
	}
	internal abstract class CAPINative : CAPIBase
	{
	}
	[SuppressUnmanagedCodeSecurity]
	internal abstract class CAPISafe : CAPINative
	{
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern bool FreeLibrary([In] IntPtr hModule);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern IntPtr GetProcAddress([In] IntPtr hModule, [In][MarshalAs(UnmanagedType.LPStr)] string lpProcName);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern SafeLocalAllocHandle LocalAlloc([In] uint uFlags, [In] IntPtr sizetdwBytes);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, EntryPoint = "LoadLibraryA", SetLastError = true)]
		internal static extern IntPtr LoadLibrary([In][MarshalAs(UnmanagedType.LPStr)] string lpFileName);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern SafeCertContextHandle CertCreateCertificateContext([In] uint dwCertEncodingType, [In] SafeLocalAllocHandle pbCertEncoded, [In] uint cbCertEncoded);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern SafeCertContextHandle CertDuplicateCertificateContext([In] IntPtr pCertContext);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern bool CertFreeCertificateContext([In] IntPtr pCertContext);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CertGetCertificateChain([In] IntPtr hChainEngine, [In] SafeCertContextHandle pCertContext, [In] ref System.Runtime.InteropServices.ComTypes.FILETIME pTime, [In] SafeCertStoreHandle hAdditionalStore, [In] ref CERT_CHAIN_PARA pChainPara, [In] uint dwFlags, [In] IntPtr pvReserved, [In][Out] ref SafeCertChainHandle ppChainContext);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CertGetCertificateContextProperty([In] SafeCertContextHandle pCertContext, [In] uint dwPropId, [In][Out] SafeLocalAllocHandle pvData, [In][Out] ref uint pcbData);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern uint CertGetPublicKeyLength([In] uint dwCertEncodingType, [In] IntPtr pPublicKey);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern uint CertNameToStrW([In] uint dwCertEncodingType, [In] IntPtr pName, [In] uint dwStrType, [In][Out] SafeLocalAllocHandle psz, [In] uint csz);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CertVerifyCertificateChainPolicy([In] IntPtr pszPolicyOID, [In] SafeCertChainHandle pChainContext, [In] ref CERT_CHAIN_POLICY_PARA pPolicyPara, [In][Out] ref CERT_CHAIN_POLICY_STATUS pPolicyStatus);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptAcquireCertificatePrivateKey([In] SafeCertContextHandle pCert, [In] uint dwFlags, [In] IntPtr pvReserved, [In][Out] ref SafeCryptProvHandle phCryptProv, [In][Out] ref uint pdwKeySpec, [In][Out] ref bool pfCallerFreeProv);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptDecodeObject([In] uint dwCertEncodingType, [In] IntPtr lpszStructType, [In] IntPtr pbEncoded, [In] uint cbEncoded, [In] uint dwFlags, [In][Out] SafeLocalAllocHandle pvStructInfo, [In][Out] IntPtr pcbStructInfo);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptDecodeObject([In] uint dwCertEncodingType, [In] IntPtr lpszStructType, [In] byte[] pbEncoded, [In] uint cbEncoded, [In] uint dwFlags, [In][Out] SafeLocalAllocHandle pvStructInfo, [In][Out] IntPtr pcbStructInfo);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptEncodeObject([In] uint dwCertEncodingType, [In] IntPtr lpszStructType, [In] IntPtr pvStructInfo, [In][Out] SafeLocalAllocHandle pbEncoded, [In][Out] IntPtr pcbEncoded);

		[DllImport("crypt32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptEncodeObject([In] uint dwCertEncodingType, [In][MarshalAs(UnmanagedType.LPStr)] string lpszStructType, [In] IntPtr pvStructInfo, [In][Out] SafeLocalAllocHandle pbEncoded, [In][Out] IntPtr pcbEncoded);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern IntPtr CryptFindOIDInfo([In] uint dwKeyType, [In] IntPtr pvKey, [In] uint dwGroupId);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern IntPtr CryptFindOIDInfo([In] uint dwKeyType, [In] SafeLocalAllocHandle pvKey, [In] uint dwGroupId);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptGetProvParam([In] SafeCryptProvHandle hProv, [In] uint dwParam, [In] IntPtr pbData, [In] IntPtr pdwDataLen, [In] uint dwFlags);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptMsgGetParam([In] SafeCryptMsgHandle hCryptMsg, [In] uint dwParamType, [In] uint dwIndex, [In][Out] IntPtr pvData, [In][Out] IntPtr pcbData);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptMsgGetParam([In] SafeCryptMsgHandle hCryptMsg, [In] uint dwParamType, [In] uint dwIndex, [In][Out] SafeLocalAllocHandle pvData, [In][Out] IntPtr pcbData);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern SafeCryptMsgHandle CryptMsgOpenToDecode([In] uint dwMsgEncodingType, [In] uint dwFlags, [In] uint dwMsgType, [In] IntPtr hCryptProv, [In] IntPtr pRecipientInfo, [In] IntPtr pStreamInfo);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptMsgUpdate([In] SafeCryptMsgHandle hCryptMsg, [In] byte[] pbData, [In] uint cbData, [In] bool fFinal);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptMsgUpdate([In] SafeCryptMsgHandle hCryptMsg, [In] IntPtr pbData, [In] uint cbData, [In] bool fFinal);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptMsgVerifyCountersignatureEncoded([In] IntPtr hCryptProv, [In] uint dwEncodingType, [In] IntPtr pbSignerInfo, [In] uint cbSignerInfo, [In] IntPtr pbSignerInfoCountersignature, [In] uint cbSignerInfoCountersignature, [In] IntPtr pciCountersigner);

		[DllImport("kernel32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern IntPtr LocalFree(IntPtr handle);

		[DllImport("kernel32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern void ZeroMemory(IntPtr handle, uint length);

		[DllImport("advapi32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		internal static extern int LsaNtStatusToWinError([In] int status);
	}
	[SuppressUnmanagedCodeSecurity]
	internal abstract class CAPIUnsafe : CAPISafe
	{
		[DllImport("advapi32.dll", BestFitMapping = false, CharSet = CharSet.Auto, EntryPoint = "CryptAcquireContextA")]
		protected internal static extern bool CryptAcquireContext([In][Out] ref SafeCryptProvHandle hCryptProv, [In][MarshalAs(UnmanagedType.LPStr)] string pszContainer, [In][MarshalAs(UnmanagedType.LPStr)] string pszProvider, [In] uint dwProvType, [In] uint dwFlags);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern bool CertAddCertificateContextToStore([In] SafeCertStoreHandle hCertStore, [In] SafeCertContextHandle pCertContext, [In] uint dwAddDisposition, [In][Out] SafeCertContextHandle ppStoreContext);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern bool CertAddCertificateLinkToStore([In] SafeCertStoreHandle hCertStore, [In] SafeCertContextHandle pCertContext, [In] uint dwAddDisposition, [In][Out] SafeCertContextHandle ppStoreContext);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern IntPtr CertEnumCertificatesInStore([In] SafeCertStoreHandle hCertStore, [In] IntPtr pPrevCertContext);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern SafeCertContextHandle CertFindCertificateInStore([In] SafeCertStoreHandle hCertStore, [In] uint dwCertEncodingType, [In] uint dwFindFlags, [In] uint dwFindType, [In] IntPtr pvFindPara, [In] SafeCertContextHandle pPrevCertContext);

		[DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		protected internal static extern SafeCertStoreHandle CertOpenStore([In] IntPtr lpszStoreProvider, [In] uint dwMsgAndCertEncodingType, [In] IntPtr hCryptProv, [In] uint dwFlags, [In] string pvPara);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern SafeCertContextHandle CertCreateSelfSignCertificate([In] SafeCryptProvHandle hProv, [In] IntPtr pSubjectIssuerBlob, [In] uint dwFlags, [In] IntPtr pKeyProvInfo, [In] IntPtr pSignatureAlgorithm, [In] IntPtr pStartTime, [In] IntPtr pEndTime, [In] IntPtr pExtensions);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern bool CryptMsgControl([In] SafeCryptMsgHandle hCryptMsg, [In] uint dwFlags, [In] uint dwCtrlType, [In] IntPtr pvCtrlPara);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern bool CryptMsgCountersign([In] SafeCryptMsgHandle hCryptMsg, [In] uint dwIndex, [In] uint cCountersigners, [In] IntPtr rgCountersigners);

		[DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern SafeCryptMsgHandle CryptMsgOpenToEncode([In] uint dwMsgEncodingType, [In] uint dwFlags, [In] uint dwMsgType, [In] IntPtr pvMsgEncodeInfo, [In] IntPtr pszInnerContentObjID, [In] IntPtr pStreamInfo);

		[DllImport("crypt32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		protected internal static extern SafeCryptMsgHandle CryptMsgOpenToEncode([In] uint dwMsgEncodingType, [In] uint dwFlags, [In] uint dwMsgType, [In] IntPtr pvMsgEncodeInfo, [In][MarshalAs(UnmanagedType.LPStr)] string pszInnerContentObjID, [In] IntPtr pStreamInfo);

		[DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool CryptProtectData([In] IntPtr pDataIn, [In] string szDataDescr, [In] IntPtr pOptionalEntropy, [In] IntPtr pvReserved, [In] IntPtr pPromptStruct, [In] uint dwFlags, [In][Out] IntPtr pDataBlob);

		[DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool CryptUnprotectData([In] IntPtr pDataIn, [In] IntPtr ppszDataDescr, [In] IntPtr pOptionalEntropy, [In] IntPtr pvReserved, [In] IntPtr pPromptStruct, [In] uint dwFlags, [In][Out] IntPtr pDataBlob);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern int SystemFunction040([In][Out] byte[] pDataIn, [In] uint cbDataIn, [In] uint dwFlags);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern int SystemFunction041([In][Out] byte[] pDataIn, [In] uint cbDataIn, [In] uint dwFlags);

		[DllImport("cryptui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		protected internal static extern SafeCertContextHandle CryptUIDlgSelectCertificateW([In][Out][MarshalAs(UnmanagedType.LPStruct)] CRYPTUI_SELECTCERTIFICATE_STRUCTW csc);

		[DllImport("cryptui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		protected internal static extern bool CryptUIDlgViewCertificateW([In][MarshalAs(UnmanagedType.LPStruct)] CRYPTUI_VIEWCERTIFICATE_STRUCTW ViewInfo, [In][Out] IntPtr pfPropertiesChanged);
	}
	internal abstract class CAPIMethods : CAPIUnsafe
	{
	}
	internal sealed class CAPI : CAPIMethods
	{
		private CAPI()
		{
		}

		internal static byte[] BlobToByteArray(IntPtr pBlob)
		{
			CRYPTOAPI_BLOB blob = (CRYPTOAPI_BLOB)Marshal.PtrToStructure(pBlob, typeof(CRYPTOAPI_BLOB));
			if (blob.cbData == 0)
			{
				return new byte[0];
			}
			return BlobToByteArray(blob);
		}

		internal static byte[] BlobToByteArray(CRYPTOAPI_BLOB blob)
		{
			if (blob.cbData == 0)
			{
				return new byte[0];
			}
			byte[] array = new byte[blob.cbData];
			Marshal.Copy(blob.pbData, array, 0, array.Length);
			return array;
		}

		internal unsafe static bool DecodeObject(IntPtr pszStructType, IntPtr pbEncoded, uint cbEncoded, out SafeLocalAllocHandle decodedValue, out uint cbDecodedValue)
		{
			decodedValue = SafeLocalAllocHandle.InvalidHandle;
			cbDecodedValue = 0u;
			uint num = 0u;
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			if (!CAPISafe.CryptDecodeObject(65537u, pszStructType, pbEncoded, cbEncoded, 0u, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			invalidHandle = LocalAlloc(0u, new IntPtr(num));
			if (!CAPISafe.CryptDecodeObject(65537u, pszStructType, pbEncoded, cbEncoded, 0u, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			decodedValue = invalidHandle;
			cbDecodedValue = num;
			return true;
		}

		internal unsafe static bool DecodeObject(IntPtr pszStructType, byte[] pbEncoded, out SafeLocalAllocHandle decodedValue, out uint cbDecodedValue)
		{
			decodedValue = SafeLocalAllocHandle.InvalidHandle;
			cbDecodedValue = 0u;
			uint num = 0u;
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			if (!CAPISafe.CryptDecodeObject(65537u, pszStructType, pbEncoded, (uint)pbEncoded.Length, 0u, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			invalidHandle = LocalAlloc(0u, new IntPtr(num));
			if (!CAPISafe.CryptDecodeObject(65537u, pszStructType, pbEncoded, (uint)pbEncoded.Length, 0u, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			decodedValue = invalidHandle;
			cbDecodedValue = num;
			return true;
		}

		internal unsafe static bool EncodeObject(IntPtr lpszStructType, IntPtr pvStructInfo, out byte[] encodedData)
		{
			encodedData = new byte[0];
			uint num = 0u;
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			if (!CAPISafe.CryptEncodeObject(65537u, lpszStructType, pvStructInfo, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			invalidHandle = LocalAlloc(0u, new IntPtr(num));
			if (!CAPISafe.CryptEncodeObject(65537u, lpszStructType, pvStructInfo, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			encodedData = new byte[num];
			Marshal.Copy(invalidHandle.DangerousGetHandle(), encodedData, 0, (int)num);
			invalidHandle.Dispose();
			return true;
		}

		internal unsafe static bool EncodeObject(string lpszStructType, IntPtr pvStructInfo, out byte[] encodedData)
		{
			encodedData = new byte[0];
			uint num = 0u;
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			if (!CAPISafe.CryptEncodeObject(65537u, lpszStructType, pvStructInfo, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			invalidHandle = LocalAlloc(0u, new IntPtr(num));
			if (!CAPISafe.CryptEncodeObject(65537u, lpszStructType, pvStructInfo, invalidHandle, new IntPtr(&num)))
			{
				return false;
			}
			encodedData = new byte[num];
			Marshal.Copy(invalidHandle.DangerousGetHandle(), encodedData, 0, (int)num);
			invalidHandle.Dispose();
			return true;
		}

		internal new static SafeLocalAllocHandle LocalAlloc(uint uFlags, IntPtr sizetdwBytes)
		{
			SafeLocalAllocHandle safeLocalAllocHandle = CAPISafe.LocalAlloc(uFlags, sizetdwBytes);
			if (safeLocalAllocHandle == null || safeLocalAllocHandle.IsInvalid)
			{
				throw new OutOfMemoryException();
			}
			return safeLocalAllocHandle;
		}

		internal new static bool CryptAcquireContext([In][Out] ref SafeCryptProvHandle hCryptProv, [In][MarshalAs(UnmanagedType.LPStr)] string pwszContainer, [In][MarshalAs(UnmanagedType.LPStr)] string pwszProvider, [In] uint dwProvType, [In] uint dwFlags)
		{
			CspParameters cspParameters = new CspParameters();
			cspParameters.ProviderName = pwszProvider;
			cspParameters.KeyContainerName = pwszContainer;
			cspParameters.ProviderType = (int)dwProvType;
			cspParameters.KeyNumber = -1;
			cspParameters.Flags = (((dwFlags & 0x20) == 32) ? CspProviderFlags.UseMachineKeyStore : CspProviderFlags.NoFlags);
			KeyContainerPermission keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);
			KeyContainerPermissionAccessEntry accessEntry = new KeyContainerPermissionAccessEntry(cspParameters, KeyContainerPermissionFlags.Open);
			keyContainerPermission.AccessEntries.Add(accessEntry);
			keyContainerPermission.Demand();
			bool flag = CAPIUnsafe.CryptAcquireContext(ref hCryptProv, pwszContainer, pwszProvider, dwProvType, dwFlags);
			if (!flag && Marshal.GetLastWin32Error() == -2146893802)
			{
				flag = CAPIUnsafe.CryptAcquireContext(ref hCryptProv, pwszContainer, pwszProvider, dwProvType, dwFlags | 8u);
			}
			return flag;
		}

		internal static bool CryptAcquireContext(ref SafeCryptProvHandle hCryptProv, IntPtr pwszContainer, IntPtr pwszProvider, uint dwProvType, uint dwFlags)
		{
			string pwszContainer2 = null;
			if (pwszContainer != IntPtr.Zero)
			{
				pwszContainer2 = Marshal.PtrToStringUni(pwszContainer);
			}
			string pwszProvider2 = null;
			if (pwszProvider != IntPtr.Zero)
			{
				pwszProvider2 = Marshal.PtrToStringUni(pwszProvider);
			}
			return CryptAcquireContext(ref hCryptProv, pwszContainer2, pwszProvider2, dwProvType, dwFlags);
		}

		internal new static CRYPT_OID_INFO CryptFindOIDInfo([In] uint dwKeyType, [In] IntPtr pvKey, [In] uint dwGroupId)
		{
			if (pvKey == IntPtr.Zero)
			{
				throw new ArgumentNullException("pvKey");
			}
			CRYPT_OID_INFO result = new CRYPT_OID_INFO(Marshal.SizeOf(typeof(CRYPT_OID_INFO)));
			IntPtr intPtr = CAPISafe.CryptFindOIDInfo(dwKeyType, pvKey, dwGroupId);
			if (intPtr != IntPtr.Zero)
			{
				return (CRYPT_OID_INFO)Marshal.PtrToStructure(intPtr, typeof(CRYPT_OID_INFO));
			}
			return result;
		}

		internal new static CRYPT_OID_INFO CryptFindOIDInfo([In] uint dwKeyType, [In] SafeLocalAllocHandle pvKey, [In] uint dwGroupId)
		{
			if (pvKey == null)
			{
				throw new ArgumentNullException("pvKey");
			}
			if (pvKey.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "pvKey");
			}
			CRYPT_OID_INFO result = new CRYPT_OID_INFO(Marshal.SizeOf(typeof(CRYPT_OID_INFO)));
			IntPtr intPtr = CAPISafe.CryptFindOIDInfo(dwKeyType, pvKey, dwGroupId);
			if (intPtr != IntPtr.Zero)
			{
				return (CRYPT_OID_INFO)Marshal.PtrToStructure(intPtr, typeof(CRYPT_OID_INFO));
			}
			return result;
		}

		internal new static bool CryptMsgControl([In] SafeCryptMsgHandle hCryptMsg, [In] uint dwFlags, [In] uint dwCtrlType, [In] IntPtr pvCtrlPara)
		{
			return CAPIUnsafe.CryptMsgControl(hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara);
		}

		internal new static bool CryptMsgCountersign([In] SafeCryptMsgHandle hCryptMsg, [In] uint dwIndex, [In] uint cCountersigners, [In] IntPtr rgCountersigners)
		{
			return CAPIUnsafe.CryptMsgCountersign(hCryptMsg, dwIndex, cCountersigners, rgCountersigners);
		}

		internal new static SafeCryptMsgHandle CryptMsgOpenToEncode([In] uint dwMsgEncodingType, [In] uint dwFlags, [In] uint dwMsgType, [In] IntPtr pvMsgEncodeInfo, [In] IntPtr pszInnerContentObjID, [In] IntPtr pStreamInfo)
		{
			return CAPIUnsafe.CryptMsgOpenToEncode(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo);
		}

		internal new static SafeCryptMsgHandle CryptMsgOpenToEncode([In] uint dwMsgEncodingType, [In] uint dwFlags, [In] uint dwMsgType, [In] IntPtr pvMsgEncodeInfo, [In] string pszInnerContentObjID, [In] IntPtr pStreamInfo)
		{
			return CAPIUnsafe.CryptMsgOpenToEncode(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo);
		}

		internal new static SafeCertContextHandle CertDuplicateCertificateContext([In] IntPtr pCertContext)
		{
			if (pCertContext == IntPtr.Zero)
			{
				return SafeCertContextHandle.InvalidHandle;
			}
			return CAPISafe.CertDuplicateCertificateContext(pCertContext);
		}

		internal new static IntPtr CertEnumCertificatesInStore([In] SafeCertStoreHandle hCertStore, [In] IntPtr pPrevCertContext)
		{
			if (hCertStore == null)
			{
				throw new ArgumentNullException("hCertStore");
			}
			if (hCertStore.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "hCertStore");
			}
			if (pPrevCertContext == IntPtr.Zero)
			{
				StorePermission storePermission = new StorePermission(StorePermissionFlags.EnumerateCertificates);
				storePermission.Demand();
			}
			IntPtr intPtr = CAPIUnsafe.CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
			if (intPtr == IntPtr.Zero)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if (lastWin32Error != -2146885628)
				{
					CAPISafe.CertFreeCertificateContext(intPtr);
					throw new CryptographicException(lastWin32Error);
				}
			}
			return intPtr;
		}

		internal new static bool CertAddCertificateContextToStore([In] SafeCertStoreHandle hCertStore, [In] SafeCertContextHandle pCertContext, [In] uint dwAddDisposition, [In][Out] SafeCertContextHandle ppStoreContext)
		{
			if (hCertStore == null)
			{
				throw new ArgumentNullException("hCertStore");
			}
			if (hCertStore.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "hCertStore");
			}
			if (pCertContext == null)
			{
				throw new ArgumentNullException("pCertContext");
			}
			if (pCertContext.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "pCertContext");
			}
			StorePermission storePermission = new StorePermission(StorePermissionFlags.AddToStore);
			storePermission.Demand();
			return CAPIUnsafe.CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext);
		}

		internal new static bool CertAddCertificateLinkToStore([In] SafeCertStoreHandle hCertStore, [In] SafeCertContextHandle pCertContext, [In] uint dwAddDisposition, [In][Out] SafeCertContextHandle ppStoreContext)
		{
			if (hCertStore == null)
			{
				throw new ArgumentNullException("hCertStore");
			}
			if (hCertStore.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "hCertStore");
			}
			if (pCertContext == null)
			{
				throw new ArgumentNullException("pCertContext");
			}
			if (pCertContext.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "pCertContext");
			}
			StorePermission storePermission = new StorePermission(StorePermissionFlags.AddToStore);
			storePermission.Demand();
			return CAPIUnsafe.CertAddCertificateLinkToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext);
		}

		internal new static SafeCertStoreHandle CertOpenStore([In] IntPtr lpszStoreProvider, [In] uint dwMsgAndCertEncodingType, [In] IntPtr hCryptProv, [In] uint dwFlags, [In] string pvPara)
		{
			if (lpszStoreProvider != new IntPtr(2L) && lpszStoreProvider != new IntPtr(10L))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Argument_InvalidValue"), "lpszStoreProvider");
			}
			if (((dwFlags & 0x20000) == 131072 || (dwFlags & 0x80000) == 524288 || (dwFlags & 0x90000) == 589824) && pvPara != null && pvPara.StartsWith("\\\\", StringComparison.Ordinal))
			{
				new PermissionSet(PermissionState.Unrestricted).Demand();
			}
			if ((dwFlags & 0x10) == 16)
			{
				StorePermission storePermission = new StorePermission(StorePermissionFlags.DeleteStore);
				storePermission.Demand();
			}
			else
			{
				StorePermission storePermission2 = new StorePermission(StorePermissionFlags.OpenStore);
				storePermission2.Demand();
			}
			if ((dwFlags & 0x2000) == 8192)
			{
				StorePermission storePermission3 = new StorePermission(StorePermissionFlags.CreateStore);
				storePermission3.Demand();
			}
			if ((dwFlags & 0x4000) == 0)
			{
				StorePermission storePermission4 = new StorePermission(StorePermissionFlags.CreateStore);
				storePermission4.Demand();
			}
			return CAPIUnsafe.CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags | 4u, pvPara);
		}

		internal new static bool CryptProtectData([In] IntPtr pDataIn, [In] string szDataDescr, [In] IntPtr pOptionalEntropy, [In] IntPtr pvReserved, [In] IntPtr pPromptStruct, [In] uint dwFlags, [In][Out] IntPtr pDataBlob)
		{
			DataProtectionPermission dataProtectionPermission = new DataProtectionPermission(DataProtectionPermissionFlags.ProtectData);
			dataProtectionPermission.Demand();
			return CAPIUnsafe.CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataBlob);
		}

		internal new static bool CryptUnprotectData([In] IntPtr pDataIn, [In] IntPtr ppszDataDescr, [In] IntPtr pOptionalEntropy, [In] IntPtr pvReserved, [In] IntPtr pPromptStruct, [In] uint dwFlags, [In][Out] IntPtr pDataBlob)
		{
			DataProtectionPermission dataProtectionPermission = new DataProtectionPermission(DataProtectionPermissionFlags.UnprotectData);
			dataProtectionPermission.Demand();
			return CAPIUnsafe.CryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataBlob);
		}

		internal new static int SystemFunction040([In][Out] byte[] pDataIn, [In] uint cbDataIn, [In] uint dwFlags)
		{
			DataProtectionPermission dataProtectionPermission = new DataProtectionPermission(DataProtectionPermissionFlags.ProtectMemory);
			dataProtectionPermission.Demand();
			return CAPIUnsafe.SystemFunction040(pDataIn, cbDataIn, dwFlags);
		}

		internal new static int SystemFunction041([In][Out] byte[] pDataIn, [In] uint cbDataIn, [In] uint dwFlags)
		{
			DataProtectionPermission dataProtectionPermission = new DataProtectionPermission(DataProtectionPermissionFlags.UnprotectMemory);
			dataProtectionPermission.Demand();
			return CAPIUnsafe.SystemFunction041(pDataIn, cbDataIn, dwFlags);
		}

		internal new static SafeCertContextHandle CryptUIDlgSelectCertificateW([In][Out][MarshalAs(UnmanagedType.LPStruct)] CRYPTUI_SELECTCERTIFICATE_STRUCTW csc)
		{
			if (!Environment.UserInteractive)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Environment_NotInteractive"));
			}
			UIPermission uIPermission = new UIPermission(UIPermissionWindow.SafeTopLevelWindows);
			uIPermission.Demand();
			return CAPIUnsafe.CryptUIDlgSelectCertificateW(csc);
		}

		internal new static bool CryptUIDlgViewCertificateW([In][MarshalAs(UnmanagedType.LPStruct)] CRYPTUI_VIEWCERTIFICATE_STRUCTW ViewInfo, [In][Out] IntPtr pfPropertiesChanged)
		{
			if (!Environment.UserInteractive)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Environment_NotInteractive"));
			}
			UIPermission uIPermission = new UIPermission(UIPermissionWindow.SafeTopLevelWindows);
			uIPermission.Demand();
			return CAPIUnsafe.CryptUIDlgViewCertificateW(ViewInfo, pfPropertiesChanged);
		}

		internal new static SafeCertContextHandle CertFindCertificateInStore([In] SafeCertStoreHandle hCertStore, [In] uint dwCertEncodingType, [In] uint dwFindFlags, [In] uint dwFindType, [In] IntPtr pvFindPara, [In] SafeCertContextHandle pPrevCertContext)
		{
			if (hCertStore == null)
			{
				throw new ArgumentNullException("hCertStore");
			}
			if (hCertStore.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "hCertStore");
			}
			return CAPIUnsafe.CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext);
		}
	}
	internal sealed class SafeLocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeLocalAllocHandle InvalidHandle => new SafeLocalAllocHandle(IntPtr.Zero);

		private SafeLocalAllocHandle()
			: base(ownsHandle: true)
		{
		}

		internal SafeLocalAllocHandle(IntPtr handle)
			: base(ownsHandle: true)
		{
			SetHandle(handle);
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SuppressUnmanagedCodeSecurity]
		private static extern IntPtr LocalFree(IntPtr handle);

		protected override bool ReleaseHandle()
		{
			return LocalFree(handle) == IntPtr.Zero;
		}
	}
	internal sealed class SafeCryptProvHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeCryptProvHandle InvalidHandle => new SafeCryptProvHandle(IntPtr.Zero);

		private SafeCryptProvHandle()
			: base(ownsHandle: true)
		{
		}

		internal SafeCryptProvHandle(IntPtr handle)
			: base(ownsHandle: true)
		{
			SetHandle(handle);
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		private static extern bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags);

		protected override bool ReleaseHandle()
		{
			return CryptReleaseContext(handle, 0u);
		}
	}
	internal sealed class SafeCertContextHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeCertContextHandle InvalidHandle => new SafeCertContextHandle(IntPtr.Zero);

		private SafeCertContextHandle()
			: base(ownsHandle: true)
		{
		}

		internal SafeCertContextHandle(IntPtr handle)
			: base(ownsHandle: true)
		{
			SetHandle(handle);
		}

		[DllImport("crypt32.dll", SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SuppressUnmanagedCodeSecurity]
		private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

		protected override bool ReleaseHandle()
		{
			return CertFreeCertificateContext(handle);
		}
	}
	internal sealed class SafeCertStoreHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeCertStoreHandle InvalidHandle => new SafeCertStoreHandle(IntPtr.Zero);

		private SafeCertStoreHandle()
			: base(ownsHandle: true)
		{
		}

		internal SafeCertStoreHandle(IntPtr handle)
			: base(ownsHandle: true)
		{
			SetHandle(handle);
		}

		[DllImport("crypt32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		private static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

		protected override bool ReleaseHandle()
		{
			return CertCloseStore(handle, 0u);
		}
	}
	internal sealed class SafeCryptMsgHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeCryptMsgHandle InvalidHandle => new SafeCryptMsgHandle(IntPtr.Zero);

		private SafeCryptMsgHandle()
			: base(ownsHandle: true)
		{
		}

		internal SafeCryptMsgHandle(IntPtr handle)
			: base(ownsHandle: true)
		{
			SetHandle(handle);
		}

		[DllImport("crypt32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		private static extern bool CryptMsgClose(IntPtr handle);

		protected override bool ReleaseHandle()
		{
			return CryptMsgClose(handle);
		}
	}
	internal sealed class SafeCertChainHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal static SafeCertChainHandle InvalidHandle => new SafeCertChainHandle(IntPtr.Zero);

		private SafeCertChainHandle()
			: base(ownsHandle: true)
		{
		}

		internal SafeCertChainHandle(IntPtr handle)
			: base(ownsHandle: true)
		{
			SetHandle(handle);
		}

		[DllImport("crypt32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		private static extern void CertFreeCertificateChain(IntPtr handle);

		protected override bool ReleaseHandle()
		{
			CertFreeCertificateChain(handle);
			return true;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CryptographicAttributeObject
	{
		private Oid m_oid;

		private AsnEncodedDataCollection m_values;

		public Oid Oid => new Oid(m_oid);

		public AsnEncodedDataCollection Values => m_values;

		private CryptographicAttributeObject()
		{
		}

		internal CryptographicAttributeObject(IntPtr pAttribute)
			: this((CAPIBase.CRYPT_ATTRIBUTE)Marshal.PtrToStructure(pAttribute, typeof(CAPIBase.CRYPT_ATTRIBUTE)))
		{
		}

		internal CryptographicAttributeObject(CAPIBase.CRYPT_ATTRIBUTE cryptAttribute)
			: this(new Oid(cryptAttribute.pszObjId), PkcsUtils.GetAsnEncodedDataCollection(cryptAttribute))
		{
		}

		internal CryptographicAttributeObject(CAPIBase.CRYPT_ATTRIBUTE_TYPE_VALUE cryptAttribute)
			: this(new Oid(cryptAttribute.pszObjId), PkcsUtils.GetAsnEncodedDataCollection(cryptAttribute))
		{
		}

		internal CryptographicAttributeObject(AsnEncodedData asnEncodedData)
			: this(asnEncodedData.Oid, new AsnEncodedDataCollection(asnEncodedData))
		{
		}

		public CryptographicAttributeObject(Oid oid)
			: this(oid, new AsnEncodedDataCollection())
		{
		}

		public CryptographicAttributeObject(Oid oid, AsnEncodedDataCollection values)
		{
			m_oid = new Oid(oid);
			if (values == null)
			{
				m_values = new AsnEncodedDataCollection();
				return;
			}
			AsnEncodedDataEnumerator enumerator = values.GetEnumerator();
			while (enumerator.MoveNext())
			{
				AsnEncodedData current = enumerator.Current;
				if (string.Compare(current.Oid.Value, oid.Value, StringComparison.Ordinal) != 0)
				{
					throw new InvalidOperationException(SecurityResources.GetResourceString("InvalidOperation_DuplicateItemNotAllowed"));
				}
			}
			m_values = values;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CryptographicAttributeObjectCollection : ICollection, IEnumerable
	{
		private ArrayList m_list;

		public CryptographicAttributeObject this[int index] => (CryptographicAttributeObject)m_list[index];

		public int Count => m_list.Count;

		public bool IsSynchronized => false;

		public object SyncRoot => this;

		public CryptographicAttributeObjectCollection()
		{
			m_list = new ArrayList();
		}

		private CryptographicAttributeObjectCollection(IntPtr pCryptAttributes)
			: this((CAPIBase.CRYPT_ATTRIBUTES)Marshal.PtrToStructure(pCryptAttributes, typeof(CAPIBase.CRYPT_ATTRIBUTES)))
		{
		}

		internal CryptographicAttributeObjectCollection(SafeLocalAllocHandle pCryptAttributes)
			: this(pCryptAttributes.DangerousGetHandle())
		{
		}

		internal CryptographicAttributeObjectCollection(CAPIBase.CRYPT_ATTRIBUTES cryptAttributes)
		{
			m_list = new ArrayList();
			for (uint num = 0u; num < cryptAttributes.cAttr; num++)
			{
				IntPtr pAttribute = new IntPtr((long)cryptAttributes.rgAttr + num * Marshal.SizeOf(typeof(CAPIBase.CRYPT_ATTRIBUTE)));
				m_list.Add(new CryptographicAttributeObject(pAttribute));
			}
		}

		public CryptographicAttributeObjectCollection(CryptographicAttributeObject attribute)
		{
			m_list = new ArrayList();
			m_list.Add(attribute);
		}

		public int Add(AsnEncodedData asnEncodedData)
		{
			if (asnEncodedData == null)
			{
				throw new ArgumentNullException("asnEncodedData");
			}
			return Add(new CryptographicAttributeObject(asnEncodedData));
		}

		public int Add(CryptographicAttributeObject attribute)
		{
			if (attribute == null)
			{
				throw new ArgumentNullException("attribute");
			}
			string text = null;
			if (attribute.Oid != null)
			{
				text = attribute.Oid.Value;
			}
			for (int i = 0; i < m_list.Count; i++)
			{
				CryptographicAttributeObject cryptographicAttributeObject = (CryptographicAttributeObject)m_list[i];
				if (cryptographicAttributeObject.Values == attribute.Values)
				{
					throw new InvalidOperationException(SecurityResources.GetResourceString("InvalidOperation_DuplicateItemNotAllowed"));
				}
				string text2 = null;
				if (cryptographicAttributeObject.Oid != null)
				{
					text2 = cryptographicAttributeObject.Oid.Value;
				}
				if (text == null && text2 == null)
				{
					AsnEncodedDataEnumerator enumerator = attribute.Values.GetEnumerator();
					while (enumerator.MoveNext())
					{
						AsnEncodedData current = enumerator.Current;
						cryptographicAttributeObject.Values.Add(current);
					}
					return i;
				}
				if (text != null && text2 != null && string.Compare(text, text2, StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (string.Compare(text, "1.2.840.113549.1.9.5", StringComparison.OrdinalIgnoreCase) == 0)
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Pkcs9_MultipleSigningTimeNotAllowed"));
					}
					AsnEncodedDataEnumerator enumerator2 = attribute.Values.GetEnumerator();
					while (enumerator2.MoveNext())
					{
						AsnEncodedData current2 = enumerator2.Current;
						cryptographicAttributeObject.Values.Add(current2);
					}
					return i;
				}
			}
			return m_list.Add(attribute);
		}

		public void Remove(CryptographicAttributeObject attribute)
		{
			if (attribute == null)
			{
				throw new ArgumentNullException("attribute");
			}
			m_list.Remove(attribute);
		}

		public CryptographicAttributeObjectEnumerator GetEnumerator()
		{
			return new CryptographicAttributeObjectEnumerator(this);
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return new CryptographicAttributeObjectEnumerator(this);
		}

		void ICollection.CopyTo(Array array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			if (array.Rank != 1)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Arg_RankMultiDimNotSupported"));
			}
			if (index < 0 || index >= array.Length)
			{
				throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
			}
			if (index + Count > array.Length)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Argument_InvalidOffLen"));
			}
			for (int i = 0; i < Count; i++)
			{
				array.SetValue(this[i], index);
				index++;
			}
		}

		public void CopyTo(CryptographicAttributeObject[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CryptographicAttributeObjectEnumerator : IEnumerator
	{
		private CryptographicAttributeObjectCollection m_attributes;

		private int m_current;

		public CryptographicAttributeObject Current => m_attributes[m_current];

		object IEnumerator.Current => m_attributes[m_current];

		private CryptographicAttributeObjectEnumerator()
		{
		}

		internal CryptographicAttributeObjectEnumerator(CryptographicAttributeObjectCollection attributes)
		{
			m_attributes = attributes;
			m_current = -1;
		}

		public bool MoveNext()
		{
			if (m_current == m_attributes.Count - 1)
			{
				return false;
			}
			m_current++;
			return true;
		}

		public void Reset()
		{
			m_current = -1;
		}
	}
	public enum DataProtectionScope
	{
		CurrentUser,
		LocalMachine
	}
	public enum MemoryProtectionScope
	{
		SameProcess,
		CrossProcess,
		SameLogon
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class ProtectedData
	{
		private ProtectedData()
		{
		}

		public unsafe static byte[] Protect(byte[] userData, byte[] optionalEntropy, DataProtectionScope scope)
		{
			if (userData == null)
			{
				throw new ArgumentNullException("userData");
			}
			if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
			GCHandle gCHandle = default(GCHandle);
			GCHandle gCHandle2 = default(GCHandle);
			CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = default(CAPIBase.CRYPTOAPI_BLOB);
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				gCHandle = GCHandle.Alloc(userData, GCHandleType.Pinned);
				CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB2 = default(CAPIBase.CRYPTOAPI_BLOB);
				cRYPTOAPI_BLOB2.cbData = (uint)userData.Length;
				cRYPTOAPI_BLOB2.pbData = gCHandle.AddrOfPinnedObject();
				CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB3 = default(CAPIBase.CRYPTOAPI_BLOB);
				if (optionalEntropy != null)
				{
					gCHandle2 = GCHandle.Alloc(optionalEntropy, GCHandleType.Pinned);
					cRYPTOAPI_BLOB3.cbData = (uint)optionalEntropy.Length;
					cRYPTOAPI_BLOB3.pbData = gCHandle2.AddrOfPinnedObject();
				}
				uint num = 1u;
				if (scope == DataProtectionScope.LocalMachine)
				{
					num |= 4u;
				}
				if (!CAPI.CryptProtectData(new IntPtr(&cRYPTOAPI_BLOB2), string.Empty, new IntPtr(&cRYPTOAPI_BLOB3), IntPtr.Zero, IntPtr.Zero, num, new IntPtr(&cRYPTOAPI_BLOB)))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				if (cRYPTOAPI_BLOB.pbData == IntPtr.Zero)
				{
					throw new OutOfMemoryException();
				}
				byte[] array = new byte[cRYPTOAPI_BLOB.cbData];
				Marshal.Copy(cRYPTOAPI_BLOB.pbData, array, 0, array.Length);
				return array;
			}
			catch (EntryPointNotFoundException)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
			finally
			{
				if (gCHandle.IsAllocated)
				{
					gCHandle.Free();
				}
				if (gCHandle2.IsAllocated)
				{
					gCHandle2.Free();
				}
				if (cRYPTOAPI_BLOB.pbData != IntPtr.Zero)
				{
					CAPISafe.ZeroMemory(cRYPTOAPI_BLOB.pbData, cRYPTOAPI_BLOB.cbData);
					CAPISafe.LocalFree(cRYPTOAPI_BLOB.pbData);
				}
			}
		}

		public unsafe static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
		{
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
			GCHandle gCHandle = default(GCHandle);
			GCHandle gCHandle2 = default(GCHandle);
			CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = default(CAPIBase.CRYPTOAPI_BLOB);
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				gCHandle = GCHandle.Alloc(encryptedData, GCHandleType.Pinned);
				CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB2 = default(CAPIBase.CRYPTOAPI_BLOB);
				cRYPTOAPI_BLOB2.cbData = (uint)encryptedData.Length;
				cRYPTOAPI_BLOB2.pbData = gCHandle.AddrOfPinnedObject();
				CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB3 = default(CAPIBase.CRYPTOAPI_BLOB);
				if (optionalEntropy != null)
				{
					gCHandle2 = GCHandle.Alloc(optionalEntropy, GCHandleType.Pinned);
					cRYPTOAPI_BLOB3.cbData = (uint)optionalEntropy.Length;
					cRYPTOAPI_BLOB3.pbData = gCHandle2.AddrOfPinnedObject();
				}
				uint num = 1u;
				if (scope == DataProtectionScope.LocalMachine)
				{
					num |= 4u;
				}
				if (!CAPI.CryptUnprotectData(new IntPtr(&cRYPTOAPI_BLOB2), IntPtr.Zero, new IntPtr(&cRYPTOAPI_BLOB3), IntPtr.Zero, IntPtr.Zero, num, new IntPtr(&cRYPTOAPI_BLOB)))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				if (cRYPTOAPI_BLOB.pbData == IntPtr.Zero)
				{
					throw new OutOfMemoryException();
				}
				byte[] array = new byte[cRYPTOAPI_BLOB.cbData];
				Marshal.Copy(cRYPTOAPI_BLOB.pbData, array, 0, array.Length);
				return array;
			}
			catch (EntryPointNotFoundException)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
			finally
			{
				if (gCHandle.IsAllocated)
				{
					gCHandle.Free();
				}
				if (gCHandle2.IsAllocated)
				{
					gCHandle2.Free();
				}
				if (cRYPTOAPI_BLOB.pbData != IntPtr.Zero)
				{
					CAPISafe.ZeroMemory(cRYPTOAPI_BLOB.pbData, cRYPTOAPI_BLOB.cbData);
					CAPISafe.LocalFree(cRYPTOAPI_BLOB.pbData);
				}
			}
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class ProtectedMemory
	{
		private ProtectedMemory()
		{
		}

		public static void Protect(byte[] userData, MemoryProtectionScope scope)
		{
			if (userData == null)
			{
				throw new ArgumentNullException("userData");
			}
			if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
			VerifyScope(scope);
			if (userData.Length == 0 || (long)userData.Length % 16L != 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_DpApi_InvalidMemoryLength"));
			}
			try
			{
				int num = CAPI.SystemFunction040(userData, (uint)userData.Length, (uint)scope);
				if (num < 0)
				{
					throw new CryptographicException(CAPISafe.LsaNtStatusToWinError(num));
				}
			}
			catch (EntryPointNotFoundException)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
		}

		public static void Unprotect(byte[] encryptedData, MemoryProtectionScope scope)
		{
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
			VerifyScope(scope);
			if (encryptedData.Length == 0 || (long)encryptedData.Length % 16L != 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_DpApi_InvalidMemoryLength"));
			}
			try
			{
				int num = CAPI.SystemFunction041(encryptedData, (uint)encryptedData.Length, (uint)scope);
				if (num < 0)
				{
					throw new CryptographicException(CAPISafe.LsaNtStatusToWinError(num));
				}
			}
			catch (EntryPointNotFoundException)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_PlatformRequiresNT"));
			}
		}

		private static void VerifyScope(MemoryProtectionScope scope)
		{
			if (scope != 0 && scope != MemoryProtectionScope.CrossProcess && scope != MemoryProtectionScope.SameLogon)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Arg_EnumIllegalVal"), (int)scope));
			}
		}
	}
}
namespace System.Security.Cryptography.Pkcs
{
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class EnvelopedCms
	{
		private struct CMSG_DECRYPT_PARAM
		{
			internal SafeCertContextHandle safeCertContextHandle;

			internal SafeCryptProvHandle safeCryptProvHandle;

			internal uint keySpec;
		}

		private struct CMSG_ENCRYPT_PARAM
		{
			internal bool useCms;

			internal SafeCryptProvHandle safeCryptProvHandle;

			internal SafeLocalAllocHandle pvEncryptionAuxInfo;

			internal SafeLocalAllocHandle rgpRecipients;

			internal SafeLocalAllocHandle rgCertEncoded;

			internal SafeLocalAllocHandle rgUnprotectedAttr;

			internal SafeLocalAllocHandle[] rgSubjectKeyIdentifier;

			internal SafeLocalAllocHandle[] rgszObjId;

			internal SafeLocalAllocHandle[] rgszKeyWrapObjId;

			internal SafeLocalAllocHandle[] rgKeyWrapAuxInfo;

			internal SafeLocalAllocHandle[] rgEphemeralIdentifier;

			internal SafeLocalAllocHandle[] rgszEphemeralObjId;

			internal SafeLocalAllocHandle[] rgUserKeyingMaterial;

			internal SafeLocalAllocHandle[] prgpEncryptedKey;

			internal SafeLocalAllocHandle[] rgpEncryptedKey;
		}

		private SafeCryptMsgHandle m_safeCryptMsgHandle;

		private int m_version;

		private SubjectIdentifierType m_recipientIdentifierType;

		private ContentInfo m_contentInfo;

		private AlgorithmIdentifier m_encryptionAlgorithm;

		private X509Certificate2Collection m_certificates;

		private CryptographicAttributeObjectCollection m_unprotectedAttributes;

		public int Version => m_version;

		public ContentInfo ContentInfo => m_contentInfo;

		public AlgorithmIdentifier ContentEncryptionAlgorithm => m_encryptionAlgorithm;

		public X509Certificate2Collection Certificates => m_certificates;

		public CryptographicAttributeObjectCollection UnprotectedAttributes => m_unprotectedAttributes;

		public RecipientInfoCollection RecipientInfos
		{
			get
			{
				if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
				{
					return new RecipientInfoCollection();
				}
				return new RecipientInfoCollection(m_safeCryptMsgHandle);
			}
		}

		public EnvelopedCms()
			: this(SubjectIdentifierType.IssuerAndSerialNumber, new ContentInfo("1.2.840.113549.1.7.1", new byte[0]), new AlgorithmIdentifier("1.2.840.113549.3.7"))
		{
		}

		public EnvelopedCms(ContentInfo contentInfo)
			: this(SubjectIdentifierType.IssuerAndSerialNumber, contentInfo, new AlgorithmIdentifier("1.2.840.113549.3.7"))
		{
		}

		public EnvelopedCms(SubjectIdentifierType recipientIdentifierType, ContentInfo contentInfo)
			: this(recipientIdentifierType, contentInfo, new AlgorithmIdentifier("1.2.840.113549.3.7"))
		{
		}

		public EnvelopedCms(ContentInfo contentInfo, AlgorithmIdentifier encryptionAlgorithm)
			: this(SubjectIdentifierType.IssuerAndSerialNumber, contentInfo, encryptionAlgorithm)
		{
		}

		public EnvelopedCms(SubjectIdentifierType recipientIdentifierType, ContentInfo contentInfo, AlgorithmIdentifier encryptionAlgorithm)
		{
			if (contentInfo == null)
			{
				throw new ArgumentNullException("contentInfo");
			}
			if (contentInfo.Content == null)
			{
				throw new ArgumentNullException("contentInfo.Content");
			}
			if (encryptionAlgorithm == null)
			{
				throw new ArgumentNullException("encryptionAlgorithm");
			}
			m_safeCryptMsgHandle = SafeCryptMsgHandle.InvalidHandle;
			m_version = ((recipientIdentifierType == SubjectIdentifierType.SubjectKeyIdentifier) ? 2 : 0);
			m_recipientIdentifierType = recipientIdentifierType;
			m_contentInfo = contentInfo;
			m_encryptionAlgorithm = encryptionAlgorithm;
			m_encryptionAlgorithm.Parameters = new byte[0];
			m_certificates = new X509Certificate2Collection();
			m_unprotectedAttributes = new CryptographicAttributeObjectCollection();
		}

		public byte[] Encode()
		{
			if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_MessageNotEncrypted"));
			}
			return PkcsUtils.GetContent(m_safeCryptMsgHandle);
		}

		public void Decode(byte[] encodedMessage)
		{
			if (encodedMessage == null)
			{
				throw new ArgumentNullException("encodedMessage");
			}
			if (m_safeCryptMsgHandle != null && !m_safeCryptMsgHandle.IsInvalid)
			{
				m_safeCryptMsgHandle.Dispose();
			}
			m_safeCryptMsgHandle = OpenToDecode(encodedMessage);
			m_version = (int)PkcsUtils.GetVersion(m_safeCryptMsgHandle);
			Oid contentType = PkcsUtils.GetContentType(m_safeCryptMsgHandle);
			byte[] content = PkcsUtils.GetContent(m_safeCryptMsgHandle);
			m_contentInfo = new ContentInfo(contentType, content);
			m_encryptionAlgorithm = PkcsUtils.GetAlgorithmIdentifier(m_safeCryptMsgHandle);
			m_certificates = PkcsUtils.GetCertificates(m_safeCryptMsgHandle);
			m_unprotectedAttributes = PkcsUtils.GetUnprotectedAttributes(m_safeCryptMsgHandle);
		}

		public void Encrypt()
		{
			Encrypt(new CmsRecipientCollection());
		}

		public void Encrypt(CmsRecipient recipient)
		{
			if (recipient == null)
			{
				throw new ArgumentNullException("recipient");
			}
			Encrypt(new CmsRecipientCollection(recipient));
		}

		public void Encrypt(CmsRecipientCollection recipients)
		{
			if (recipients == null)
			{
				throw new ArgumentNullException("recipients");
			}
			if (ContentInfo.Content.Length == 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Envelope_Empty_Content"));
			}
			if (recipients.Count == 0)
			{
				recipients = PkcsUtils.SelectRecipients(m_recipientIdentifierType);
			}
			EncryptContent(recipients);
		}

		public void Decrypt()
		{
			DecryptContent(RecipientInfos, null);
		}

		public void Decrypt(RecipientInfo recipientInfo)
		{
			if (recipientInfo == null)
			{
				throw new ArgumentNullException("recipientInfo");
			}
			DecryptContent(new RecipientInfoCollection(recipientInfo), null);
		}

		public void Decrypt(X509Certificate2Collection extraStore)
		{
			if (extraStore == null)
			{
				throw new ArgumentNullException("extraStore");
			}
			DecryptContent(RecipientInfos, extraStore);
		}

		public void Decrypt(RecipientInfo recipientInfo, X509Certificate2Collection extraStore)
		{
			if (recipientInfo == null)
			{
				throw new ArgumentNullException("recipientInfo");
			}
			if (extraStore == null)
			{
				throw new ArgumentNullException("extraStore");
			}
			DecryptContent(new RecipientInfoCollection(recipientInfo), extraStore);
		}

		private unsafe void DecryptContent(RecipientInfoCollection recipientInfos, X509Certificate2Collection extraStore)
		{
			int num = -2146889717;
			if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_NoEncryptedMessageToEncode"));
			}
			for (int i = 0; i < recipientInfos.Count; i++)
			{
				RecipientInfo recipientInfo = recipientInfos[i];
				CMSG_DECRYPT_PARAM cmsgDecryptParam = default(CMSG_DECRYPT_PARAM);
				int num2 = GetCspParams(recipientInfo, extraStore, ref cmsgDecryptParam);
				if (num2 == 0)
				{
					CspParameters parameters = new CspParameters();
					if (!System.Security.Cryptography.X509Certificates.X509Utils.GetPrivateKeyInfo(cmsgDecryptParam.safeCertContextHandle, ref parameters))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					KeyContainerPermission keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);
					KeyContainerPermissionAccessEntry accessEntry = new KeyContainerPermissionAccessEntry(parameters, KeyContainerPermissionFlags.Open | KeyContainerPermissionFlags.Decrypt);
					keyContainerPermission.AccessEntries.Add(accessEntry);
					keyContainerPermission.Demand();
					switch (recipientInfo.Type)
					{
					case RecipientInfoType.KeyTransport:
					{
						CAPIBase.CMSG_CTRL_DECRYPT_PARA cMSG_CTRL_DECRYPT_PARA = new CAPIBase.CMSG_CTRL_DECRYPT_PARA(Marshal.SizeOf(typeof(CAPIBase.CMSG_CTRL_DECRYPT_PARA)))
						{
							hCryptProv = cmsgDecryptParam.safeCryptProvHandle.DangerousGetHandle(),
							dwKeySpec = cmsgDecryptParam.keySpec,
							dwRecipientIndex = recipientInfo.Index
						};
						if (!CAPI.CryptMsgControl(m_safeCryptMsgHandle, 0u, 2u, new IntPtr(&cMSG_CTRL_DECRYPT_PARA)))
						{
							num2 = Marshal.GetHRForLastWin32Error();
						}
						GC.KeepAlive(cMSG_CTRL_DECRYPT_PARA);
						break;
					}
					case RecipientInfoType.KeyAgreement:
					{
						SafeCertContextHandle safeCertContextHandle = SafeCertContextHandle.InvalidHandle;
						KeyAgreeRecipientInfo keyAgreeRecipientInfo = (KeyAgreeRecipientInfo)recipientInfo;
						CAPIBase.CMSG_CMS_RECIPIENT_INFO cMSG_CMS_RECIPIENT_INFO = (CAPIBase.CMSG_CMS_RECIPIENT_INFO)Marshal.PtrToStructure(keyAgreeRecipientInfo.pCmsgRecipientInfo.DangerousGetHandle(), typeof(CAPIBase.CMSG_CMS_RECIPIENT_INFO));
						CAPIBase.CMSG_CTRL_KEY_AGREE_DECRYPT_PARA cMSG_CTRL_KEY_AGREE_DECRYPT_PARA = new CAPIBase.CMSG_CTRL_KEY_AGREE_DECRYPT_PARA(Marshal.SizeOf(typeof(CAPIBase.CMSG_CTRL_KEY_AGREE_DECRYPT_PARA)))
						{
							hCryptProv = cmsgDecryptParam.safeCryptProvHandle.DangerousGetHandle(),
							dwKeySpec = cmsgDecryptParam.keySpec,
							pKeyAgree = cMSG_CMS_RECIPIENT_INFO.pRecipientInfo,
							dwRecipientIndex = keyAgreeRecipientInfo.Index,
							dwRecipientEncryptedKeyIndex = keyAgreeRecipientInfo.SubIndex
						};
						if (keyAgreeRecipientInfo.SubType == RecipientSubType.CertIdKeyAgreement)
						{
							CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO cMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO = (CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO)keyAgreeRecipientInfo.CmsgRecipientInfo;
							SafeCertStoreHandle hCertStore = BuildOriginatorStore(Certificates, extraStore);
							safeCertContextHandle = CAPI.CertFindCertificateInStore(hCertStore, 65537u, 0u, 1048576u, new IntPtr(&cMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO.OriginatorCertId), SafeCertContextHandle.InvalidHandle);
							if (safeCertContextHandle == null || safeCertContextHandle.IsInvalid)
							{
								num2 = -2146885628;
								break;
							}
							cMSG_CTRL_KEY_AGREE_DECRYPT_PARA.OriginatorPublicKey = ((CAPIBase.CERT_INFO)Marshal.PtrToStructure(((CAPIBase.CERT_CONTEXT)Marshal.PtrToStructure(safeCertContextHandle.DangerousGetHandle(), typeof(CAPIBase.CERT_CONTEXT))).pCertInfo, typeof(CAPIBase.CERT_INFO))).SubjectPublicKeyInfo.PublicKey;
						}
						else
						{
							cMSG_CTRL_KEY_AGREE_DECRYPT_PARA.OriginatorPublicKey = ((CAPIBase.CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO)keyAgreeRecipientInfo.CmsgRecipientInfo).OriginatorPublicKeyInfo.PublicKey;
						}
						if (!CAPI.CryptMsgControl(m_safeCryptMsgHandle, 0u, 17u, new IntPtr(&cMSG_CTRL_KEY_AGREE_DECRYPT_PARA)))
						{
							num2 = Marshal.GetHRForLastWin32Error();
						}
						GC.KeepAlive(cMSG_CTRL_KEY_AGREE_DECRYPT_PARA);
						GC.KeepAlive(safeCertContextHandle);
						break;
					}
					default:
						throw new CryptographicException(-2147483647);
					}
					GC.KeepAlive(cmsgDecryptParam);
				}
				if (num2 == 0)
				{
					uint cbData = 0u;
					SafeLocalAllocHandle pvData = SafeLocalAllocHandle.InvalidHandle;
					PkcsUtils.GetParam(m_safeCryptMsgHandle, 2u, 0u, out pvData, out cbData);
					if (cbData != 0)
					{
						Oid contentType = PkcsUtils.GetContentType(m_safeCryptMsgHandle);
						byte[] array = new byte[cbData];
						Marshal.Copy(pvData.DangerousGetHandle(), array, 0, (int)cbData);
						m_contentInfo = new ContentInfo(contentType, array);
					}
					pvData.Dispose();
					num = 0;
					break;
				}
				num = num2;
			}
			if (num != 0)
			{
				throw new CryptographicException(num);
			}
		}

		private unsafe void EncryptContent(CmsRecipientCollection recipients)
		{
			CMSG_ENCRYPT_PARAM encryptParam = default(CMSG_ENCRYPT_PARAM);
			if (recipients.Count < 1)
			{
				throw new CryptographicException(-2146889717);
			}
			CmsRecipientEnumerator enumerator = recipients.GetEnumerator();
			while (enumerator.MoveNext())
			{
				CmsRecipient current = enumerator.Current;
				if (current.Certificate == null)
				{
					throw new ArgumentNullException(SecurityResources.GetResourceString("Cryptography_Cms_RecipientCertificateNotFound"));
				}
				if (PkcsUtils.GetRecipientInfoType(current.Certificate) == RecipientInfoType.KeyAgreement || current.RecipientIdentifierType == SubjectIdentifierType.SubjectKeyIdentifier)
				{
					encryptParam.useCms = true;
				}
			}
			if (!encryptParam.useCms && (Certificates.Count > 0 || UnprotectedAttributes.Count > 0))
			{
				encryptParam.useCms = true;
			}
			if (encryptParam.useCms && !PkcsUtils.CmsSupported())
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Not_Supported"));
			}
			CAPIBase.CMSG_ENVELOPED_ENCODE_INFO cMSG_ENVELOPED_ENCODE_INFO = new CAPIBase.CMSG_ENVELOPED_ENCODE_INFO(Marshal.SizeOf(typeof(CAPIBase.CMSG_ENVELOPED_ENCODE_INFO)));
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CMSG_ENVELOPED_ENCODE_INFO))));
			SetCspParams(ContentEncryptionAlgorithm, ref encryptParam);
			cMSG_ENVELOPED_ENCODE_INFO.ContentEncryptionAlgorithm.pszObjId = ContentEncryptionAlgorithm.Oid.Value;
			if (encryptParam.pvEncryptionAuxInfo != null && !encryptParam.pvEncryptionAuxInfo.IsInvalid)
			{
				cMSG_ENVELOPED_ENCODE_INFO.pvEncryptionAuxInfo = encryptParam.pvEncryptionAuxInfo.DangerousGetHandle();
			}
			cMSG_ENVELOPED_ENCODE_INFO.cRecipients = (uint)recipients.Count;
			List<SafeCertContextHandle> certContexts = null;
			if (encryptParam.useCms)
			{
				SetCmsRecipientParams(recipients, Certificates, UnprotectedAttributes, ContentEncryptionAlgorithm, ref encryptParam);
				cMSG_ENVELOPED_ENCODE_INFO.rgCmsRecipients = encryptParam.rgpRecipients.DangerousGetHandle();
				if (encryptParam.rgCertEncoded != null && !encryptParam.rgCertEncoded.IsInvalid)
				{
					cMSG_ENVELOPED_ENCODE_INFO.cCertEncoded = (uint)Certificates.Count;
					cMSG_ENVELOPED_ENCODE_INFO.rgCertEncoded = encryptParam.rgCertEncoded.DangerousGetHandle();
				}
				if (encryptParam.rgUnprotectedAttr != null && !encryptParam.rgUnprotectedAttr.IsInvalid)
				{
					cMSG_ENVELOPED_ENCODE_INFO.cUnprotectedAttr = (uint)UnprotectedAttributes.Count;
					cMSG_ENVELOPED_ENCODE_INFO.rgUnprotectedAttr = encryptParam.rgUnprotectedAttr.DangerousGetHandle();
				}
			}
			else
			{
				SetPkcs7RecipientParams(recipients, ref encryptParam, out certContexts);
				cMSG_ENVELOPED_ENCODE_INFO.rgpRecipients = encryptParam.rgpRecipients.DangerousGetHandle();
			}
			Marshal.StructureToPtr(cMSG_ENVELOPED_ENCODE_INFO, safeLocalAllocHandle.DangerousGetHandle(), fDeleteOld: false);
			try
			{
				SafeCryptMsgHandle safeCryptMsgHandle = CAPI.CryptMsgOpenToEncode(65537u, 0u, 3u, safeLocalAllocHandle.DangerousGetHandle(), ContentInfo.ContentType.Value, IntPtr.Zero);
				if (safeCryptMsgHandle == null || safeCryptMsgHandle.IsInvalid)
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				if (m_safeCryptMsgHandle != null && !m_safeCryptMsgHandle.IsInvalid)
				{
					m_safeCryptMsgHandle.Dispose();
				}
				m_safeCryptMsgHandle = safeCryptMsgHandle;
			}
			finally
			{
				Marshal.DestroyStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CMSG_ENVELOPED_ENCODE_INFO));
				safeLocalAllocHandle.Dispose();
			}
			byte[] encodedData = new byte[0];
			if (string.Compare(ContentInfo.ContentType.Value, "1.2.840.113549.1.7.1", StringComparison.OrdinalIgnoreCase) == 0)
			{
				byte[] content = ContentInfo.Content;
				fixed (byte* value = content)
				{
					CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = default(CAPIBase.CRYPTOAPI_BLOB);
					cRYPTOAPI_BLOB.cbData = (uint)content.Length;
					cRYPTOAPI_BLOB.pbData = new IntPtr(value);
					if (!CAPI.EncodeObject(new IntPtr(25L), new IntPtr(&cRYPTOAPI_BLOB), out encodedData))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
				}
			}
			else
			{
				encodedData = ContentInfo.Content;
			}
			if (encodedData.Length > 0 && !CAPISafe.CryptMsgUpdate(m_safeCryptMsgHandle, encodedData, (uint)encodedData.Length, fFinal: true))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			GC.KeepAlive(encryptParam);
			GC.KeepAlive(recipients);
			GC.KeepAlive(certContexts);
		}

		private static SafeCryptMsgHandle OpenToDecode(byte[] encodedMessage)
		{
			SafeCryptMsgHandle safeCryptMsgHandle = null;
			safeCryptMsgHandle = CAPISafe.CryptMsgOpenToDecode(65537u, 0u, 0u, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			if (safeCryptMsgHandle == null || safeCryptMsgHandle.IsInvalid)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (!CAPISafe.CryptMsgUpdate(safeCryptMsgHandle, encodedMessage, (uint)encodedMessage.Length, fFinal: true))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (3 != PkcsUtils.GetMessageType(safeCryptMsgHandle))
			{
				throw new CryptographicException(-2146889724);
			}
			return safeCryptMsgHandle;
		}

		private unsafe static int GetCspParams(RecipientInfo recipientInfo, X509Certificate2Collection extraStore, ref CMSG_DECRYPT_PARAM cmsgDecryptParam)
		{
			int result = -2146889717;
			SafeCertContextHandle safeCertContextHandle = SafeCertContextHandle.InvalidHandle;
			SafeCertStoreHandle hCertStore = BuildDecryptorStore(extraStore);
			switch (recipientInfo.Type)
			{
			case RecipientInfoType.KeyTransport:
			{
				if (recipientInfo.SubType == RecipientSubType.Pkcs7KeyTransport)
				{
					safeCertContextHandle = CAPI.CertFindCertificateInStore(hCertStore, 65537u, 0u, 720896u, recipientInfo.pCmsgRecipientInfo.DangerousGetHandle(), SafeCertContextHandle.InvalidHandle);
					break;
				}
				CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO cMSG_KEY_TRANS_RECIPIENT_INFO = (CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO)recipientInfo.CmsgRecipientInfo;
				safeCertContextHandle = CAPI.CertFindCertificateInStore(hCertStore, 65537u, 0u, 1048576u, new IntPtr(&cMSG_KEY_TRANS_RECIPIENT_INFO.RecipientId), SafeCertContextHandle.InvalidHandle);
				break;
			}
			case RecipientInfoType.KeyAgreement:
			{
				KeyAgreeRecipientInfo keyAgreeRecipientInfo = (KeyAgreeRecipientInfo)recipientInfo;
				CAPIBase.CERT_ID recipientId = keyAgreeRecipientInfo.RecipientId;
				safeCertContextHandle = CAPI.CertFindCertificateInStore(hCertStore, 65537u, 0u, 1048576u, new IntPtr(&recipientId), SafeCertContextHandle.InvalidHandle);
				break;
			}
			default:
				result = -2147483647;
				break;
			}
			if (safeCertContextHandle != null && !safeCertContextHandle.IsInvalid)
			{
				SafeCryptProvHandle hCryptProv = SafeCryptProvHandle.InvalidHandle;
				uint pdwKeySpec = 0u;
				bool pfCallerFreeProv = false;
				CspParameters parameters = new CspParameters();
				if (!System.Security.Cryptography.X509Certificates.X509Utils.GetPrivateKeyInfo(safeCertContextHandle, ref parameters))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				if (string.Compare(parameters.ProviderName, "Microsoft Base Cryptographic Provider v1.0", StringComparison.OrdinalIgnoreCase) == 0 && (CAPI.CryptAcquireContext(ref hCryptProv, parameters.KeyContainerName, "Microsoft Enhanced Cryptographic Provider v1.0", 1u, 0u) || CAPI.CryptAcquireContext(ref hCryptProv, parameters.KeyContainerName, "Microsoft Strong Cryptographic Provider", 1u, 0u)))
				{
					cmsgDecryptParam.safeCryptProvHandle = hCryptProv;
				}
				cmsgDecryptParam.safeCertContextHandle = safeCertContextHandle;
				cmsgDecryptParam.keySpec = (uint)parameters.KeyNumber;
				result = 0;
				if (hCryptProv == null || hCryptProv.IsInvalid)
				{
					if (CAPISafe.CryptAcquireCertificatePrivateKey(safeCertContextHandle, 6u, IntPtr.Zero, ref hCryptProv, ref pdwKeySpec, ref pfCallerFreeProv))
					{
						if (!pfCallerFreeProv)
						{
							GC.SuppressFinalize(hCryptProv);
						}
						cmsgDecryptParam.safeCryptProvHandle = hCryptProv;
					}
					else
					{
						result = Marshal.GetHRForLastWin32Error();
					}
				}
			}
			return result;
		}

		private static void SetCspParams(AlgorithmIdentifier contentEncryptionAlgorithm, ref CMSG_ENCRYPT_PARAM encryptParam)
		{
			encryptParam.safeCryptProvHandle = SafeCryptProvHandle.InvalidHandle;
			encryptParam.pvEncryptionAuxInfo = SafeLocalAllocHandle.InvalidHandle;
			SafeCryptProvHandle hCryptProv = SafeCryptProvHandle.InvalidHandle;
			if (!CAPI.CryptAcquireContext(ref hCryptProv, IntPtr.Zero, IntPtr.Zero, 1u, 4026531840u) && !CAPI.CryptAcquireContext(ref hCryptProv, IntPtr.Zero, IntPtr.Zero, 1u, 0u))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			uint num = System.Security.Cryptography.X509Certificates.X509Utils.OidToAlgId(contentEncryptionAlgorithm.Oid.Value);
			if (num == 26114 || num == 26625)
			{
				CAPIBase.CMSG_RC2_AUX_INFO cMSG_RC2_AUX_INFO = new CAPIBase.CMSG_RC2_AUX_INFO(Marshal.SizeOf(typeof(CAPIBase.CMSG_RC2_AUX_INFO)));
				uint num2 = (uint)contentEncryptionAlgorithm.KeyLength;
				if (num2 == 0)
				{
					num2 = (uint)PkcsUtils.GetMaxKeyLength(hCryptProv, num);
				}
				cMSG_RC2_AUX_INFO.dwBitLen = num2;
				SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CMSG_RC2_AUX_INFO))));
				Marshal.StructureToPtr(cMSG_RC2_AUX_INFO, safeLocalAllocHandle.DangerousGetHandle(), fDeleteOld: false);
				encryptParam.pvEncryptionAuxInfo = safeLocalAllocHandle;
			}
			encryptParam.safeCryptProvHandle = hCryptProv;
		}

		private unsafe static void SetCmsRecipientParams(CmsRecipientCollection recipients, X509Certificate2Collection certificates, CryptographicAttributeObjectCollection unprotectedAttributes, AlgorithmIdentifier contentEncryptionAlgorithm, ref CMSG_ENCRYPT_PARAM encryptParam)
		{
			int num = 0;
			uint[] array = new uint[recipients.Count];
			int num2 = 0;
			int num3 = recipients.Count * Marshal.SizeOf(typeof(CAPIBase.CMSG_RECIPIENT_ENCODE_INFO));
			int num4 = num3;
			for (num = 0; num < recipients.Count; num++)
			{
				array[num] = (uint)PkcsUtils.GetRecipientInfoType(recipients[num].Certificate);
				if (array[num] == 1)
				{
					num4 += Marshal.SizeOf(typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO));
					continue;
				}
				if (array[num] == 2)
				{
					num2++;
					num4 += Marshal.SizeOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO));
					continue;
				}
				throw new CryptographicException(-2146889726);
			}
			encryptParam.rgpRecipients = CAPI.LocalAlloc(64u, new IntPtr(num4));
			encryptParam.rgCertEncoded = SafeLocalAllocHandle.InvalidHandle;
			encryptParam.rgUnprotectedAttr = SafeLocalAllocHandle.InvalidHandle;
			encryptParam.rgSubjectKeyIdentifier = new SafeLocalAllocHandle[recipients.Count];
			encryptParam.rgszObjId = new SafeLocalAllocHandle[recipients.Count];
			if (num2 > 0)
			{
				encryptParam.rgszKeyWrapObjId = new SafeLocalAllocHandle[num2];
				encryptParam.rgKeyWrapAuxInfo = new SafeLocalAllocHandle[num2];
				encryptParam.rgEphemeralIdentifier = new SafeLocalAllocHandle[num2];
				encryptParam.rgszEphemeralObjId = new SafeLocalAllocHandle[num2];
				encryptParam.rgUserKeyingMaterial = new SafeLocalAllocHandle[num2];
				encryptParam.prgpEncryptedKey = new SafeLocalAllocHandle[num2];
				encryptParam.rgpEncryptedKey = new SafeLocalAllocHandle[num2];
			}
			if (certificates.Count > 0)
			{
				encryptParam.rgCertEncoded = CAPI.LocalAlloc(64u, new IntPtr(certificates.Count * Marshal.SizeOf(typeof(CAPIBase.CRYPTOAPI_BLOB))));
				for (num = 0; num < certificates.Count; num++)
				{
					CAPIBase.CERT_CONTEXT cERT_CONTEXT = (CAPIBase.CERT_CONTEXT)Marshal.PtrToStructure(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificates[num]).DangerousGetHandle(), typeof(CAPIBase.CERT_CONTEXT));
					CAPIBase.CRYPTOAPI_BLOB* ptr = (CAPIBase.CRYPTOAPI_BLOB*)(void*)new IntPtr((long)encryptParam.rgCertEncoded.DangerousGetHandle() + num * Marshal.SizeOf(typeof(CAPIBase.CRYPTOAPI_BLOB)));
					ptr->cbData = cERT_CONTEXT.cbCertEncoded;
					ptr->pbData = cERT_CONTEXT.pbCertEncoded;
				}
			}
			if (unprotectedAttributes.Count > 0)
			{
				encryptParam.rgUnprotectedAttr = new SafeLocalAllocHandle(PkcsUtils.CreateCryptAttributes(unprotectedAttributes));
			}
			num2 = 0;
			IntPtr intPtr = new IntPtr((long)encryptParam.rgpRecipients.DangerousGetHandle() + num3);
			for (num = 0; num < recipients.Count; num++)
			{
				CmsRecipient cmsRecipient = recipients[num];
				X509Certificate2 certificate = cmsRecipient.Certificate;
				CAPIBase.CERT_INFO cERT_INFO = (CAPIBase.CERT_INFO)Marshal.PtrToStructure(((CAPIBase.CERT_CONTEXT)Marshal.PtrToStructure(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate).DangerousGetHandle(), typeof(CAPIBase.CERT_CONTEXT))).pCertInfo, typeof(CAPIBase.CERT_INFO));
				CAPIBase.CMSG_RECIPIENT_ENCODE_INFO* ptr2 = (CAPIBase.CMSG_RECIPIENT_ENCODE_INFO*)(void*)new IntPtr((long)encryptParam.rgpRecipients.DangerousGetHandle() + num * Marshal.SizeOf(typeof(CAPIBase.CMSG_RECIPIENT_ENCODE_INFO)));
				ptr2->dwRecipientChoice = array[num];
				ptr2->pRecipientInfo = intPtr;
				if (array[num] == 1)
				{
					IntPtr ptr3 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO), "cbSize"));
					Marshal.WriteInt32(ptr3, Marshal.SizeOf(typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO)));
					IntPtr intPtr2 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO), "KeyEncryptionAlgorithm"));
					byte[] bytes = Encoding.ASCII.GetBytes(cERT_INFO.SubjectPublicKeyInfo.Algorithm.pszObjId);
					encryptParam.rgszObjId[num] = CAPI.LocalAlloc(64u, new IntPtr(bytes.Length + 1));
					Marshal.Copy(bytes, 0, encryptParam.rgszObjId[num].DangerousGetHandle(), bytes.Length);
					IntPtr ptr4 = new IntPtr((long)intPtr2 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER), "pszObjId"));
					Marshal.WriteIntPtr(ptr4, encryptParam.rgszObjId[num].DangerousGetHandle());
					IntPtr intPtr3 = new IntPtr((long)intPtr2 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER), "Parameters"));
					IntPtr ptr5 = new IntPtr((long)intPtr3 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
					Marshal.WriteInt32(ptr5, (int)cERT_INFO.SubjectPublicKeyInfo.Algorithm.Parameters.cbData);
					IntPtr ptr6 = new IntPtr((long)intPtr3 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
					Marshal.WriteIntPtr(ptr6, cERT_INFO.SubjectPublicKeyInfo.Algorithm.Parameters.pbData);
					IntPtr intPtr4 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO), "RecipientPublicKey"));
					ptr5 = new IntPtr((long)intPtr4 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_BIT_BLOB), "cbData"));
					Marshal.WriteInt32(ptr5, (int)cERT_INFO.SubjectPublicKeyInfo.PublicKey.cbData);
					ptr6 = new IntPtr((long)intPtr4 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_BIT_BLOB), "pbData"));
					Marshal.WriteIntPtr(ptr6, cERT_INFO.SubjectPublicKeyInfo.PublicKey.pbData);
					IntPtr ptr7 = new IntPtr((long)intPtr4 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_BIT_BLOB), "cUnusedBits"));
					Marshal.WriteInt32(ptr7, (int)cERT_INFO.SubjectPublicKeyInfo.PublicKey.cUnusedBits);
					IntPtr intPtr5 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO), "RecipientId"));
					if (cmsRecipient.RecipientIdentifierType == SubjectIdentifierType.SubjectKeyIdentifier)
					{
						uint pcbData = 0u;
						SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
						if (!CAPISafe.CertGetCertificateContextProperty(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), 20u, invalidHandle, ref pcbData))
						{
							throw new CryptographicException(Marshal.GetLastWin32Error());
						}
						invalidHandle = CAPI.LocalAlloc(64u, new IntPtr(pcbData));
						if (!CAPISafe.CertGetCertificateContextProperty(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), 20u, invalidHandle, ref pcbData))
						{
							throw new CryptographicException(Marshal.GetLastWin32Error());
						}
						encryptParam.rgSubjectKeyIdentifier[num] = invalidHandle;
						IntPtr ptr8 = new IntPtr((long)intPtr5 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ID), "dwIdChoice"));
						Marshal.WriteInt32(ptr8, 2);
						IntPtr intPtr6 = new IntPtr((long)intPtr5 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ID), "Value"));
						ptr5 = new IntPtr((long)intPtr6 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
						Marshal.WriteInt32(ptr5, (int)pcbData);
						ptr6 = new IntPtr((long)intPtr6 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
						Marshal.WriteIntPtr(ptr6, invalidHandle.DangerousGetHandle());
					}
					else
					{
						IntPtr ptr9 = new IntPtr((long)intPtr5 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ID), "dwIdChoice"));
						Marshal.WriteInt32(ptr9, 1);
						IntPtr intPtr7 = new IntPtr((long)intPtr5 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ID), "Value"));
						IntPtr intPtr8 = new IntPtr((long)intPtr7 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ISSUER_SERIAL_NUMBER), "Issuer"));
						ptr5 = new IntPtr((long)intPtr8 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
						Marshal.WriteInt32(ptr5, (int)cERT_INFO.Issuer.cbData);
						ptr6 = new IntPtr((long)intPtr8 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
						Marshal.WriteIntPtr(ptr6, cERT_INFO.Issuer.pbData);
						IntPtr intPtr9 = new IntPtr((long)intPtr7 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ISSUER_SERIAL_NUMBER), "SerialNumber"));
						ptr5 = new IntPtr((long)intPtr9 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
						Marshal.WriteInt32(ptr5, (int)cERT_INFO.SerialNumber.cbData);
						ptr6 = new IntPtr((long)intPtr9 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
						Marshal.WriteIntPtr(ptr6, cERT_INFO.SerialNumber.pbData);
					}
					intPtr = new IntPtr((long)intPtr + Marshal.SizeOf(typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO)));
				}
				else
				{
					if (array[num] != 2)
					{
						continue;
					}
					IntPtr ptr10 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "cbSize"));
					Marshal.WriteInt32(ptr10, Marshal.SizeOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO)));
					IntPtr intPtr10 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "KeyEncryptionAlgorithm"));
					byte[] bytes2 = Encoding.ASCII.GetBytes("1.2.840.113549.1.9.16.3.5");
					encryptParam.rgszObjId[num] = CAPI.LocalAlloc(64u, new IntPtr(bytes2.Length + 1));
					Marshal.Copy(bytes2, 0, encryptParam.rgszObjId[num].DangerousGetHandle(), bytes2.Length);
					IntPtr ptr11 = new IntPtr((long)intPtr10 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER), "pszObjId"));
					Marshal.WriteIntPtr(ptr11, encryptParam.rgszObjId[num].DangerousGetHandle());
					IntPtr intPtr11 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "KeyWrapAlgorithm"));
					uint num5 = System.Security.Cryptography.X509Certificates.X509Utils.OidToAlgId(contentEncryptionAlgorithm.Oid.Value);
					bytes2 = ((num5 != 26114) ? Encoding.ASCII.GetBytes("1.2.840.113549.1.9.16.3.6") : Encoding.ASCII.GetBytes("1.2.840.113549.1.9.16.3.7"));
					encryptParam.rgszKeyWrapObjId[num2] = CAPI.LocalAlloc(64u, new IntPtr(bytes2.Length + 1));
					Marshal.Copy(bytes2, 0, encryptParam.rgszKeyWrapObjId[num2].DangerousGetHandle(), bytes2.Length);
					ptr11 = new IntPtr((long)intPtr11 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER), "pszObjId"));
					Marshal.WriteIntPtr(ptr11, encryptParam.rgszKeyWrapObjId[num2].DangerousGetHandle());
					if (num5 == 26114)
					{
						IntPtr ptr12 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "pvKeyWrapAuxInfo"));
						Marshal.WriteIntPtr(ptr12, encryptParam.pvEncryptionAuxInfo.DangerousGetHandle());
					}
					IntPtr ptr13 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "dwKeyChoice"));
					Marshal.WriteInt32(ptr13, 1);
					IntPtr ptr14 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "pEphemeralAlgorithmOrSenderId"));
					encryptParam.rgEphemeralIdentifier[num2] = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER))));
					Marshal.WriteIntPtr(ptr14, encryptParam.rgEphemeralIdentifier[num2].DangerousGetHandle());
					bytes2 = Encoding.ASCII.GetBytes(cERT_INFO.SubjectPublicKeyInfo.Algorithm.pszObjId);
					encryptParam.rgszEphemeralObjId[num2] = CAPI.LocalAlloc(64u, new IntPtr(bytes2.Length + 1));
					Marshal.Copy(bytes2, 0, encryptParam.rgszEphemeralObjId[num2].DangerousGetHandle(), bytes2.Length);
					ptr11 = new IntPtr((long)encryptParam.rgEphemeralIdentifier[num2].DangerousGetHandle() + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER), "pszObjId"));
					Marshal.WriteIntPtr(ptr11, encryptParam.rgszEphemeralObjId[num2].DangerousGetHandle());
					IntPtr intPtr12 = new IntPtr((long)encryptParam.rgEphemeralIdentifier[num2].DangerousGetHandle() + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER), "Parameters"));
					IntPtr ptr15 = new IntPtr((long)intPtr12 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
					Marshal.WriteInt32(ptr15, (int)cERT_INFO.SubjectPublicKeyInfo.Algorithm.Parameters.cbData);
					IntPtr ptr16 = new IntPtr((long)intPtr12 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
					Marshal.WriteIntPtr(ptr16, cERT_INFO.SubjectPublicKeyInfo.Algorithm.Parameters.pbData);
					IntPtr ptr17 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "cRecipientEncryptedKeys"));
					Marshal.WriteInt32(ptr17, 1);
					encryptParam.prgpEncryptedKey[num2] = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(IntPtr))));
					IntPtr ptr18 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO), "rgpRecipientEncryptedKeys"));
					Marshal.WriteIntPtr(ptr18, encryptParam.prgpEncryptedKey[num2].DangerousGetHandle());
					encryptParam.rgpEncryptedKey[num2] = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO))));
					Marshal.WriteIntPtr(encryptParam.prgpEncryptedKey[num2].DangerousGetHandle(), encryptParam.rgpEncryptedKey[num2].DangerousGetHandle());
					ptr10 = new IntPtr((long)encryptParam.rgpEncryptedKey[num2].DangerousGetHandle() + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO), "cbSize"));
					Marshal.WriteInt32(ptr10, Marshal.SizeOf(typeof(CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO)));
					IntPtr intPtr13 = new IntPtr((long)encryptParam.rgpEncryptedKey[num2].DangerousGetHandle() + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO), "RecipientPublicKey"));
					ptr15 = new IntPtr((long)intPtr13 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_BIT_BLOB), "cbData"));
					Marshal.WriteInt32(ptr15, (int)cERT_INFO.SubjectPublicKeyInfo.PublicKey.cbData);
					ptr16 = new IntPtr((long)intPtr13 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_BIT_BLOB), "pbData"));
					Marshal.WriteIntPtr(ptr16, cERT_INFO.SubjectPublicKeyInfo.PublicKey.pbData);
					IntPtr ptr19 = new IntPtr((long)intPtr13 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_BIT_BLOB), "cUnusedBits"));
					Marshal.WriteInt32(ptr19, (int)cERT_INFO.SubjectPublicKeyInfo.PublicKey.cUnusedBits);
					IntPtr intPtr14 = new IntPtr((long)encryptParam.rgpEncryptedKey[num2].DangerousGetHandle() + (long)Marshal.OffsetOf(typeof(CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO), "RecipientId"));
					IntPtr ptr20 = new IntPtr((long)intPtr14 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ID), "dwIdChoice"));
					if (cmsRecipient.RecipientIdentifierType == SubjectIdentifierType.SubjectKeyIdentifier)
					{
						Marshal.WriteInt32(ptr20, 2);
						IntPtr intPtr15 = new IntPtr((long)intPtr14 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ID), "Value"));
						uint pcbData2 = 0u;
						SafeLocalAllocHandle invalidHandle2 = SafeLocalAllocHandle.InvalidHandle;
						if (!CAPISafe.CertGetCertificateContextProperty(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), 20u, invalidHandle2, ref pcbData2))
						{
							throw new CryptographicException(Marshal.GetLastWin32Error());
						}
						invalidHandle2 = CAPI.LocalAlloc(64u, new IntPtr(pcbData2));
						if (!CAPISafe.CertGetCertificateContextProperty(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), 20u, invalidHandle2, ref pcbData2))
						{
							throw new CryptographicException(Marshal.GetLastWin32Error());
						}
						encryptParam.rgSubjectKeyIdentifier[num2] = invalidHandle2;
						ptr15 = new IntPtr((long)intPtr15 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
						Marshal.WriteInt32(ptr15, (int)pcbData2);
						ptr16 = new IntPtr((long)intPtr15 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
						Marshal.WriteIntPtr(ptr16, invalidHandle2.DangerousGetHandle());
					}
					else
					{
						Marshal.WriteInt32(ptr20, 1);
						IntPtr intPtr16 = new IntPtr((long)intPtr14 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ID), "Value"));
						IntPtr intPtr17 = new IntPtr((long)intPtr16 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ISSUER_SERIAL_NUMBER), "Issuer"));
						ptr15 = new IntPtr((long)intPtr17 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
						Marshal.WriteInt32(ptr15, (int)cERT_INFO.Issuer.cbData);
						ptr16 = new IntPtr((long)intPtr17 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
						Marshal.WriteIntPtr(ptr16, cERT_INFO.Issuer.pbData);
						IntPtr intPtr18 = new IntPtr((long)intPtr16 + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_ISSUER_SERIAL_NUMBER), "SerialNumber"));
						ptr15 = new IntPtr((long)intPtr18 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
						Marshal.WriteInt32(ptr15, (int)cERT_INFO.SerialNumber.cbData);
						ptr16 = new IntPtr((long)intPtr18 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
						Marshal.WriteIntPtr(ptr16, cERT_INFO.SerialNumber.pbData);
					}
					num2++;
					intPtr = new IntPtr((long)intPtr + Marshal.SizeOf(typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO)));
				}
			}
		}

		private static void SetPkcs7RecipientParams(CmsRecipientCollection recipients, ref CMSG_ENCRYPT_PARAM encryptParam, out List<SafeCertContextHandle> certContexts)
		{
			int num = 0;
			int count = recipients.Count;
			certContexts = new List<SafeCertContextHandle>();
			uint num2 = (uint)(count * Marshal.SizeOf(typeof(IntPtr)));
			encryptParam.rgpRecipients = CAPI.LocalAlloc(64u, new IntPtr(num2));
			IntPtr intPtr = encryptParam.rgpRecipients.DangerousGetHandle();
			for (num = 0; num < count; num++)
			{
				SafeCertContextHandle certContext = System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(recipients[num].Certificate);
				certContexts.Add(certContext);
				IntPtr ptr = certContext.DangerousGetHandle();
				Marshal.WriteIntPtr(intPtr, ((CAPIBase.CERT_CONTEXT)Marshal.PtrToStructure(ptr, typeof(CAPIBase.CERT_CONTEXT))).pCertInfo);
				intPtr = new IntPtr((long)intPtr + Marshal.SizeOf(typeof(IntPtr)));
			}
		}

		private static SafeCertStoreHandle BuildDecryptorStore(X509Certificate2Collection extraStore)
		{
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			try
			{
				X509Store x509Store = new X509Store("MY", StoreLocation.CurrentUser);
				x509Store.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
				x509Certificate2Collection.AddRange(x509Store.Certificates);
			}
			catch (SecurityException)
			{
			}
			try
			{
				X509Store x509Store2 = new X509Store("MY", StoreLocation.LocalMachine);
				x509Store2.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
				x509Certificate2Collection.AddRange(x509Store2.Certificates);
			}
			catch (SecurityException)
			{
			}
			if (extraStore != null)
			{
				x509Certificate2Collection.AddRange(extraStore);
			}
			if (x509Certificate2Collection.Count == 0)
			{
				throw new CryptographicException(-2146889717);
			}
			return System.Security.Cryptography.X509Certificates.X509Utils.ExportToMemoryStore(x509Certificate2Collection);
		}

		private static SafeCertStoreHandle BuildOriginatorStore(X509Certificate2Collection bagOfCerts, X509Certificate2Collection extraStore)
		{
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			try
			{
				X509Store x509Store = new X509Store("AddressBook", StoreLocation.CurrentUser);
				x509Store.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
				x509Certificate2Collection.AddRange(x509Store.Certificates);
			}
			catch (SecurityException)
			{
			}
			try
			{
				X509Store x509Store2 = new X509Store("AddressBook", StoreLocation.LocalMachine);
				x509Store2.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
				x509Certificate2Collection.AddRange(x509Store2.Certificates);
			}
			catch (SecurityException)
			{
			}
			if (bagOfCerts != null)
			{
				x509Certificate2Collection.AddRange(bagOfCerts);
			}
			if (extraStore != null)
			{
				x509Certificate2Collection.AddRange(extraStore);
			}
			if (x509Certificate2Collection.Count == 0)
			{
				throw new CryptographicException(-2146885628);
			}
			return System.Security.Cryptography.X509Certificates.X509Utils.ExportToMemoryStore(x509Certificate2Collection);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CmsRecipient
	{
		private SubjectIdentifierType m_recipientIdentifierType;

		private X509Certificate2 m_certificate;

		public SubjectIdentifierType RecipientIdentifierType => m_recipientIdentifierType;

		public X509Certificate2 Certificate => m_certificate;

		private CmsRecipient()
		{
		}

		public CmsRecipient(X509Certificate2 certificate)
			: this(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
		{
		}

		public CmsRecipient(SubjectIdentifierType recipientIdentifierType, X509Certificate2 certificate)
		{
			Reset(recipientIdentifierType, certificate);
		}

		private void Reset(SubjectIdentifierType recipientIdentifierType, X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				throw new ArgumentNullException("certificate");
			}
			switch (recipientIdentifierType)
			{
			case SubjectIdentifierType.Unknown:
				recipientIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber;
				break;
			case SubjectIdentifierType.SubjectKeyIdentifier:
				if (!PkcsUtils.CmsSupported())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Not_Supported"));
				}
				break;
			default:
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type"), recipientIdentifierType.ToString());
			case SubjectIdentifierType.IssuerAndSerialNumber:
				break;
			}
			m_recipientIdentifierType = recipientIdentifierType;
			m_certificate = certificate;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CmsRecipientCollection : ICollection, IEnumerable
	{
		private ArrayList m_recipients;

		public CmsRecipient this[int index]
		{
			get
			{
				if (index < 0 || index >= m_recipients.Count)
				{
					throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
				}
				return (CmsRecipient)m_recipients[index];
			}
		}

		public int Count => m_recipients.Count;

		public bool IsSynchronized => false;

		public object SyncRoot => this;

		public CmsRecipientCollection()
		{
			m_recipients = new ArrayList();
		}

		public CmsRecipientCollection(CmsRecipient recipient)
		{
			m_recipients = new ArrayList(1);
			m_recipients.Add(recipient);
		}

		public CmsRecipientCollection(SubjectIdentifierType recipientIdentifierType, X509Certificate2Collection certificates)
		{
			m_recipients = new ArrayList(certificates.Count);
			for (int i = 0; i < certificates.Count; i++)
			{
				m_recipients.Add(new CmsRecipient(recipientIdentifierType, certificates[i]));
			}
		}

		public int Add(CmsRecipient recipient)
		{
			if (recipient == null)
			{
				throw new ArgumentNullException("recipient");
			}
			return m_recipients.Add(recipient);
		}

		public void Remove(CmsRecipient recipient)
		{
			if (recipient == null)
			{
				throw new ArgumentNullException("recipient");
			}
			m_recipients.Remove(recipient);
		}

		public CmsRecipientEnumerator GetEnumerator()
		{
			return new CmsRecipientEnumerator(this);
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return new CmsRecipientEnumerator(this);
		}

		public void CopyTo(Array array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			if (array.Rank != 1)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Arg_RankMultiDimNotSupported"));
			}
			if (index < 0 || index >= array.Length)
			{
				throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
			}
			if (index + Count > array.Length)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Argument_InvalidOffLen"));
			}
			for (int i = 0; i < Count; i++)
			{
				array.SetValue(this[i], index);
				index++;
			}
		}

		public void CopyTo(CmsRecipient[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CmsRecipientEnumerator : IEnumerator
	{
		private CmsRecipientCollection m_recipients;

		private int m_current;

		public CmsRecipient Current => m_recipients[m_current];

		object IEnumerator.Current => m_recipients[m_current];

		private CmsRecipientEnumerator()
		{
		}

		internal CmsRecipientEnumerator(CmsRecipientCollection recipients)
		{
			m_recipients = recipients;
			m_current = -1;
		}

		public bool MoveNext()
		{
			if (m_current == m_recipients.Count - 1)
			{
				return false;
			}
			m_current++;
			return true;
		}

		public void Reset()
		{
			m_current = -1;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CmsSigner
	{
		private SubjectIdentifierType m_signerIdentifierType;

		private X509Certificate2 m_certificate;

		private Oid m_digestAlgorithm;

		private CryptographicAttributeObjectCollection m_signedAttributes;

		private CryptographicAttributeObjectCollection m_unsignedAttributes;

		private X509Certificate2Collection m_certificates;

		private X509IncludeOption m_includeOption;

		private bool m_dummyCert;

		public SubjectIdentifierType SignerIdentifierType
		{
			get
			{
				return m_signerIdentifierType;
			}
			set
			{
				if (value != SubjectIdentifierType.IssuerAndSerialNumber && value != SubjectIdentifierType.SubjectKeyIdentifier && value != SubjectIdentifierType.NoSignature)
				{
					throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Arg_EnumIllegalVal"), "value"));
				}
				if (m_dummyCert && value != SubjectIdentifierType.SubjectKeyIdentifier)
				{
					throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Arg_EnumIllegalVal"), "value"));
				}
				m_signerIdentifierType = value;
			}
		}

		public X509Certificate2 Certificate
		{
			get
			{
				return m_certificate;
			}
			set
			{
				m_certificate = value;
			}
		}

		public Oid DigestAlgorithm
		{
			get
			{
				return m_digestAlgorithm;
			}
			set
			{
				m_digestAlgorithm = value;
			}
		}

		public CryptographicAttributeObjectCollection SignedAttributes => m_signedAttributes;

		public CryptographicAttributeObjectCollection UnsignedAttributes => m_unsignedAttributes;

		public X509Certificate2Collection Certificates => m_certificates;

		public X509IncludeOption IncludeOption
		{
			get
			{
				return m_includeOption;
			}
			set
			{
				if (value < X509IncludeOption.None || value > X509IncludeOption.WholeChain)
				{
					throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Arg_EnumIllegalVal"), "value"));
				}
				m_includeOption = value;
			}
		}

		public CmsSigner()
			: this(SubjectIdentifierType.IssuerAndSerialNumber, null)
		{
		}

		public CmsSigner(SubjectIdentifierType signerIdentifierType)
			: this(signerIdentifierType, null)
		{
		}

		public CmsSigner(X509Certificate2 certificate)
			: this(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
		{
		}

		public CmsSigner(CspParameters parameters)
			: this(SubjectIdentifierType.SubjectKeyIdentifier, PkcsUtils.CreateDummyCertificate(parameters))
		{
			m_dummyCert = true;
			IncludeOption = X509IncludeOption.None;
		}

		public CmsSigner(SubjectIdentifierType signerIdentifierType, X509Certificate2 certificate)
		{
			switch (signerIdentifierType)
			{
			case SubjectIdentifierType.Unknown:
				SignerIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber;
				IncludeOption = X509IncludeOption.ExcludeRoot;
				break;
			case SubjectIdentifierType.IssuerAndSerialNumber:
				SignerIdentifierType = signerIdentifierType;
				IncludeOption = X509IncludeOption.ExcludeRoot;
				break;
			case SubjectIdentifierType.SubjectKeyIdentifier:
				SignerIdentifierType = signerIdentifierType;
				IncludeOption = X509IncludeOption.ExcludeRoot;
				break;
			case SubjectIdentifierType.NoSignature:
				SignerIdentifierType = signerIdentifierType;
				IncludeOption = X509IncludeOption.None;
				break;
			default:
				SignerIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber;
				IncludeOption = X509IncludeOption.ExcludeRoot;
				break;
			}
			Certificate = certificate;
			DigestAlgorithm = new Oid("1.3.14.3.2.26");
			m_signedAttributes = new CryptographicAttributeObjectCollection();
			m_unsignedAttributes = new CryptographicAttributeObjectCollection();
			m_certificates = new X509Certificate2Collection();
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class Pkcs9AttributeObject : AsnEncodedData
	{
		public new Oid Oid => base.Oid;

		internal Pkcs9AttributeObject(string oid)
		{
			base.Oid = new Oid(oid);
		}

		public Pkcs9AttributeObject()
		{
		}

		public Pkcs9AttributeObject(string oid, byte[] encodedData)
			: this(new AsnEncodedData(oid, encodedData))
		{
		}

		public Pkcs9AttributeObject(Oid oid, byte[] encodedData)
			: this(new AsnEncodedData(oid, encodedData))
		{
		}

		public Pkcs9AttributeObject(AsnEncodedData asnEncodedData)
			: base(asnEncodedData)
		{
			if (asnEncodedData.Oid == null)
			{
				throw new ArgumentNullException("asnEncodedData.Oid");
			}
			string value = base.Oid.Value;
			if (value == null)
			{
				throw new ArgumentNullException("oid.Value");
			}
			if (value.Length == 0)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Arg_EmptyOrNullString"), "oid.Value");
			}
		}

		public override void CopyFrom(AsnEncodedData asnEncodedData)
		{
			if (asnEncodedData == null)
			{
				throw new ArgumentNullException("asnEncodedData");
			}
			if (!(asnEncodedData is Pkcs9AttributeObject))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Pkcs9_AttributeMismatch"));
			}
			base.CopyFrom(asnEncodedData);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class Pkcs9SigningTime : Pkcs9AttributeObject
	{
		private DateTime m_signingTime;

		private bool m_decoded;

		public DateTime SigningTime
		{
			get
			{
				if (!m_decoded && base.RawData != null)
				{
					Decode();
				}
				return m_signingTime;
			}
		}

		public Pkcs9SigningTime()
			: this(DateTime.Now)
		{
		}

		public Pkcs9SigningTime(DateTime signingTime)
			: base("1.2.840.113549.1.9.5", Encode(signingTime))
		{
			m_signingTime = signingTime;
			m_decoded = true;
		}

		public Pkcs9SigningTime(byte[] encodedSigningTime)
			: base("1.2.840.113549.1.9.5", encodedSigningTime)
		{
		}

		public override void CopyFrom(AsnEncodedData asnEncodedData)
		{
			base.CopyFrom(asnEncodedData);
			m_decoded = false;
		}

		private void Decode()
		{
			uint cbDecodedValue = 0u;
			SafeLocalAllocHandle decodedValue = null;
			if (!CAPI.DecodeObject(new IntPtr(17L), base.RawData, out decodedValue, out cbDecodedValue))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			long fileTime = Marshal.ReadInt64(decodedValue.DangerousGetHandle());
			decodedValue.Dispose();
			m_signingTime = DateTime.FromFileTimeUtc(fileTime);
			m_decoded = true;
		}

		private static byte[] Encode(DateTime signingTime)
		{
			long val = signingTime.ToFileTimeUtc();
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(long))));
			Marshal.WriteInt64(safeLocalAllocHandle.DangerousGetHandle(), val);
			byte[] encodedData = new byte[0];
			if (!CAPI.EncodeObject("1.2.840.113549.1.9.5", safeLocalAllocHandle.DangerousGetHandle(), out encodedData))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			safeLocalAllocHandle.Dispose();
			return encodedData;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class Pkcs9DocumentName : Pkcs9AttributeObject
	{
		private string m_documentName;

		private bool m_decoded;

		public string DocumentName
		{
			get
			{
				if (!m_decoded && base.RawData != null)
				{
					Decode();
				}
				return m_documentName;
			}
		}

		public Pkcs9DocumentName()
			: base("1.3.6.1.4.1.311.88.2.1")
		{
		}

		public Pkcs9DocumentName(string documentName)
			: base("1.3.6.1.4.1.311.88.2.1", Encode(documentName))
		{
			m_documentName = documentName;
			m_decoded = true;
		}

		public Pkcs9DocumentName(byte[] encodedDocumentName)
			: base("1.3.6.1.4.1.311.88.2.1", encodedDocumentName)
		{
		}

		public override void CopyFrom(AsnEncodedData asnEncodedData)
		{
			base.CopyFrom(asnEncodedData);
			m_decoded = false;
		}

		private void Decode()
		{
			m_documentName = PkcsUtils.DecodeOctetString(base.RawData);
			m_decoded = true;
		}

		private static byte[] Encode(string documentName)
		{
			if (string.IsNullOrEmpty(documentName))
			{
				throw new ArgumentNullException("documentName");
			}
			return PkcsUtils.EncodeOctetString(documentName);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class Pkcs9DocumentDescription : Pkcs9AttributeObject
	{
		private string m_documentDescription;

		private bool m_decoded;

		public string DocumentDescription
		{
			get
			{
				if (!m_decoded && base.RawData != null)
				{
					Decode();
				}
				return m_documentDescription;
			}
		}

		public Pkcs9DocumentDescription()
			: base("1.3.6.1.4.1.311.88.2.2")
		{
		}

		public Pkcs9DocumentDescription(string documentDescription)
			: base("1.3.6.1.4.1.311.88.2.2", Encode(documentDescription))
		{
			m_documentDescription = documentDescription;
			m_decoded = true;
		}

		public Pkcs9DocumentDescription(byte[] encodedDocumentDescription)
			: base("1.3.6.1.4.1.311.88.2.2", encodedDocumentDescription)
		{
		}

		public override void CopyFrom(AsnEncodedData asnEncodedData)
		{
			base.CopyFrom(asnEncodedData);
			m_decoded = false;
		}

		private void Decode()
		{
			m_documentDescription = PkcsUtils.DecodeOctetString(base.RawData);
			m_decoded = true;
		}

		private static byte[] Encode(string documentDescription)
		{
			if (string.IsNullOrEmpty(documentDescription))
			{
				throw new ArgumentNullException("documentDescription");
			}
			return PkcsUtils.EncodeOctetString(documentDescription);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class Pkcs9ContentType : Pkcs9AttributeObject
	{
		private Oid m_contentType;

		private bool m_decoded;

		public Oid ContentType
		{
			get
			{
				if (!m_decoded && base.RawData != null)
				{
					Decode();
				}
				return m_contentType;
			}
		}

		internal Pkcs9ContentType(byte[] encodedContentType)
			: base("1.2.840.113549.1.9.3", encodedContentType)
		{
		}

		public Pkcs9ContentType()
			: base("1.2.840.113549.1.9.3")
		{
		}

		public override void CopyFrom(AsnEncodedData asnEncodedData)
		{
			base.CopyFrom(asnEncodedData);
			m_decoded = false;
		}

		private void Decode()
		{
			if (base.RawData.Length < 2 || base.RawData[1] != base.RawData.Length - 2)
			{
				throw new CryptographicException(-2146885630);
			}
			if (base.RawData[0] != 6)
			{
				throw new CryptographicException(-2146881269);
			}
			m_contentType = new Oid(PkcsUtils.DecodeObjectIdentifier(base.RawData, 2));
			m_decoded = true;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class Pkcs9MessageDigest : Pkcs9AttributeObject
	{
		private byte[] m_messageDigest;

		private bool m_decoded;

		public byte[] MessageDigest
		{
			get
			{
				if (!m_decoded && base.RawData != null)
				{
					Decode();
				}
				return m_messageDigest;
			}
		}

		internal Pkcs9MessageDigest(byte[] encodedMessageDigest)
			: base("1.2.840.113549.1.9.4", encodedMessageDigest)
		{
		}

		public Pkcs9MessageDigest()
			: base("1.2.840.113549.1.9.4")
		{
		}

		public override void CopyFrom(AsnEncodedData asnEncodedData)
		{
			base.CopyFrom(asnEncodedData);
			m_decoded = false;
		}

		private void Decode()
		{
			m_messageDigest = PkcsUtils.DecodeOctetBytes(base.RawData);
			m_decoded = true;
		}
	}
	public enum RecipientInfoType
	{
		Unknown,
		KeyTransport,
		KeyAgreement
	}
	internal enum RecipientSubType
	{
		Unknown,
		Pkcs7KeyTransport,
		CmsKeyTransport,
		CertIdKeyAgreement,
		PublicKeyAgreement
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public abstract class RecipientInfo
	{
		private RecipientInfoType m_recipentInfoType;

		private RecipientSubType m_recipientSubType;

		private SafeLocalAllocHandle m_pCmsgRecipientInfo;

		private object m_cmsgRecipientInfo;

		private uint m_index;

		public RecipientInfoType Type => m_recipentInfoType;

		public abstract int Version { get; }

		public abstract SubjectIdentifier RecipientIdentifier { get; }

		public abstract AlgorithmIdentifier KeyEncryptionAlgorithm { get; }

		public abstract byte[] EncryptedKey { get; }

		internal RecipientSubType SubType => m_recipientSubType;

		internal SafeLocalAllocHandle pCmsgRecipientInfo => m_pCmsgRecipientInfo;

		internal object CmsgRecipientInfo => m_cmsgRecipientInfo;

		internal uint Index => m_index;

		internal RecipientInfo()
		{
		}

		internal RecipientInfo(RecipientInfoType recipientInfoType, RecipientSubType recipientSubType, SafeLocalAllocHandle pCmsgRecipientInfo, object cmsgRecipientInfo, uint index)
		{
			if (recipientInfoType < RecipientInfoType.Unknown || recipientInfoType > RecipientInfoType.KeyAgreement)
			{
				recipientInfoType = RecipientInfoType.Unknown;
			}
			if (recipientSubType < RecipientSubType.Unknown || recipientSubType > RecipientSubType.PublicKeyAgreement)
			{
				recipientSubType = RecipientSubType.Unknown;
			}
			m_recipentInfoType = recipientInfoType;
			m_recipientSubType = recipientSubType;
			m_pCmsgRecipientInfo = pCmsgRecipientInfo;
			m_cmsgRecipientInfo = cmsgRecipientInfo;
			m_index = index;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class KeyTransRecipientInfo : RecipientInfo
	{
		private int m_version;

		private SubjectIdentifier m_recipientIdentifier;

		private AlgorithmIdentifier m_encryptionAlgorithm;

		private byte[] m_encryptedKey;

		public override int Version => m_version;

		public override SubjectIdentifier RecipientIdentifier
		{
			get
			{
				if (m_recipientIdentifier == null)
				{
					if (base.SubType == RecipientSubType.CmsKeyTransport)
					{
						m_recipientIdentifier = new SubjectIdentifier(((CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO)base.CmsgRecipientInfo).RecipientId);
					}
					else
					{
						CAPIBase.CERT_INFO certInfo = (CAPIBase.CERT_INFO)base.CmsgRecipientInfo;
						m_recipientIdentifier = new SubjectIdentifier(certInfo);
					}
				}
				return m_recipientIdentifier;
			}
		}

		public override AlgorithmIdentifier KeyEncryptionAlgorithm
		{
			get
			{
				if (m_encryptionAlgorithm == null)
				{
					if (base.SubType == RecipientSubType.CmsKeyTransport)
					{
						m_encryptionAlgorithm = new AlgorithmIdentifier(((CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO)base.CmsgRecipientInfo).KeyEncryptionAlgorithm);
					}
					else
					{
						m_encryptionAlgorithm = new AlgorithmIdentifier(((CAPIBase.CERT_INFO)base.CmsgRecipientInfo).SignatureAlgorithm);
					}
				}
				return m_encryptionAlgorithm;
			}
		}

		public override byte[] EncryptedKey
		{
			get
			{
				if (m_encryptedKey.Length == 0 && base.SubType == RecipientSubType.CmsKeyTransport)
				{
					CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO cMSG_KEY_TRANS_RECIPIENT_INFO = (CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO)base.CmsgRecipientInfo;
					if (cMSG_KEY_TRANS_RECIPIENT_INFO.EncryptedKey.cbData != 0)
					{
						m_encryptedKey = new byte[cMSG_KEY_TRANS_RECIPIENT_INFO.EncryptedKey.cbData];
						Marshal.Copy(cMSG_KEY_TRANS_RECIPIENT_INFO.EncryptedKey.pbData, m_encryptedKey, 0, m_encryptedKey.Length);
					}
				}
				return m_encryptedKey;
			}
		}

		private KeyTransRecipientInfo()
		{
		}

		internal unsafe KeyTransRecipientInfo(SafeLocalAllocHandle pRecipientInfo, CAPIBase.CERT_INFO certInfo, uint index)
			: base(RecipientInfoType.KeyTransport, RecipientSubType.Pkcs7KeyTransport, pRecipientInfo, certInfo, index)
		{
			int version = 2;
			byte* ptr = (byte*)(void*)certInfo.SerialNumber.pbData;
			for (int i = 0; i < certInfo.SerialNumber.cbData; i++)
			{
				if (*(ptr++) != 0)
				{
					version = 0;
					break;
				}
			}
			Reset(version);
		}

		internal KeyTransRecipientInfo(SafeLocalAllocHandle pRecipientInfo, CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO keyTrans, uint index)
			: base(RecipientInfoType.KeyTransport, RecipientSubType.CmsKeyTransport, pRecipientInfo, keyTrans, index)
		{
			Reset((int)keyTrans.dwVersion);
		}

		private void Reset(int version)
		{
			m_version = version;
			m_recipientIdentifier = null;
			m_encryptionAlgorithm = null;
			m_encryptedKey = new byte[0];
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class KeyAgreeRecipientInfo : RecipientInfo
	{
		private CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO m_encryptedKeyInfo;

		private uint m_originatorChoice;

		private int m_version;

		private SubjectIdentifierOrKey m_originatorIdentifier;

		private byte[] m_userKeyMaterial;

		private AlgorithmIdentifier m_encryptionAlgorithm;

		private SubjectIdentifier m_recipientIdentifier;

		private byte[] m_encryptedKey;

		private DateTime m_date;

		private CryptographicAttributeObject m_otherKeyAttribute;

		private uint m_subIndex;

		public override int Version => m_version;

		public SubjectIdentifierOrKey OriginatorIdentifierOrKey
		{
			get
			{
				if (m_originatorIdentifier == null)
				{
					if (m_originatorChoice == 1)
					{
						m_originatorIdentifier = new SubjectIdentifierOrKey(((CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO)base.CmsgRecipientInfo).OriginatorCertId);
					}
					else
					{
						m_originatorIdentifier = new SubjectIdentifierOrKey(((CAPIBase.CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO)base.CmsgRecipientInfo).OriginatorPublicKeyInfo);
					}
				}
				return m_originatorIdentifier;
			}
		}

		public override SubjectIdentifier RecipientIdentifier
		{
			get
			{
				if (m_recipientIdentifier == null)
				{
					m_recipientIdentifier = new SubjectIdentifier(m_encryptedKeyInfo.RecipientId);
				}
				return m_recipientIdentifier;
			}
		}

		public DateTime Date
		{
			get
			{
				if (m_date == DateTime.MinValue)
				{
					if (RecipientIdentifier.Type != SubjectIdentifierType.SubjectKeyIdentifier)
					{
						throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_Key_Agree_Date_Not_Available"));
					}
					long fileTime = (long)(((ulong)(uint)m_encryptedKeyInfo.Date.dwHighDateTime << 32) | (uint)m_encryptedKeyInfo.Date.dwLowDateTime);
					m_date = DateTime.FromFileTimeUtc(fileTime);
				}
				return m_date;
			}
		}

		public CryptographicAttributeObject OtherKeyAttribute
		{
			get
			{
				if (m_otherKeyAttribute == null)
				{
					if (RecipientIdentifier.Type != SubjectIdentifierType.SubjectKeyIdentifier)
					{
						throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_Key_Agree_Other_Key_Attribute_Not_Available"));
					}
					if (m_encryptedKeyInfo.pOtherAttr != IntPtr.Zero)
					{
						CAPIBase.CRYPT_ATTRIBUTE_TYPE_VALUE cryptAttribute = (CAPIBase.CRYPT_ATTRIBUTE_TYPE_VALUE)Marshal.PtrToStructure(m_encryptedKeyInfo.pOtherAttr, typeof(CAPIBase.CRYPT_ATTRIBUTE_TYPE_VALUE));
						m_otherKeyAttribute = new CryptographicAttributeObject(cryptAttribute);
					}
				}
				return m_otherKeyAttribute;
			}
		}

		public override AlgorithmIdentifier KeyEncryptionAlgorithm
		{
			get
			{
				if (m_encryptionAlgorithm == null)
				{
					if (m_originatorChoice == 1)
					{
						m_encryptionAlgorithm = new AlgorithmIdentifier(((CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO)base.CmsgRecipientInfo).KeyEncryptionAlgorithm);
					}
					else
					{
						m_encryptionAlgorithm = new AlgorithmIdentifier(((CAPIBase.CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO)base.CmsgRecipientInfo).KeyEncryptionAlgorithm);
					}
				}
				return m_encryptionAlgorithm;
			}
		}

		public override byte[] EncryptedKey
		{
			get
			{
				if (m_encryptedKey.Length == 0 && m_encryptedKeyInfo.EncryptedKey.cbData != 0)
				{
					m_encryptedKey = new byte[m_encryptedKeyInfo.EncryptedKey.cbData];
					Marshal.Copy(m_encryptedKeyInfo.EncryptedKey.pbData, m_encryptedKey, 0, m_encryptedKey.Length);
				}
				return m_encryptedKey;
			}
		}

		internal CAPIBase.CERT_ID RecipientId => m_encryptedKeyInfo.RecipientId;

		internal uint SubIndex => m_subIndex;

		private KeyAgreeRecipientInfo()
		{
		}

		internal KeyAgreeRecipientInfo(SafeLocalAllocHandle pRecipientInfo, CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO certIdRecipient, uint index, uint subIndex)
			: base(RecipientInfoType.KeyAgreement, RecipientSubType.CertIdKeyAgreement, pRecipientInfo, certIdRecipient, index)
		{
			IntPtr ptr = Marshal.ReadIntPtr(new IntPtr((long)certIdRecipient.rgpRecipientEncryptedKeys + subIndex * Marshal.SizeOf(typeof(IntPtr))));
			CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO encryptedKeyInfo = (CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO)Marshal.PtrToStructure(ptr, typeof(CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO));
			Reset(1u, certIdRecipient.dwVersion, encryptedKeyInfo, subIndex);
		}

		internal KeyAgreeRecipientInfo(SafeLocalAllocHandle pRecipientInfo, CAPIBase.CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO publicKeyRecipient, uint index, uint subIndex)
			: base(RecipientInfoType.KeyAgreement, RecipientSubType.PublicKeyAgreement, pRecipientInfo, publicKeyRecipient, index)
		{
			IntPtr ptr = Marshal.ReadIntPtr(new IntPtr((long)publicKeyRecipient.rgpRecipientEncryptedKeys + subIndex * Marshal.SizeOf(typeof(IntPtr))));
			CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO encryptedKeyInfo = (CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO)Marshal.PtrToStructure(ptr, typeof(CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO));
			Reset(2u, publicKeyRecipient.dwVersion, encryptedKeyInfo, subIndex);
		}

		private void Reset(uint originatorChoice, uint version, CAPIBase.CMSG_RECIPIENT_ENCRYPTED_KEY_INFO encryptedKeyInfo, uint subIndex)
		{
			m_encryptedKeyInfo = encryptedKeyInfo;
			m_originatorChoice = originatorChoice;
			m_version = (int)version;
			m_originatorIdentifier = null;
			m_userKeyMaterial = new byte[0];
			m_encryptionAlgorithm = null;
			m_recipientIdentifier = null;
			m_encryptedKey = new byte[0];
			m_date = DateTime.MinValue;
			m_otherKeyAttribute = null;
			m_subIndex = subIndex;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class RecipientInfoCollection : ICollection, IEnumerable
	{
		private SafeCryptMsgHandle m_safeCryptMsgHandle;

		private ArrayList m_recipientInfos;

		public RecipientInfo this[int index]
		{
			get
			{
				if (index < 0 || index >= m_recipientInfos.Count)
				{
					throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
				}
				return (RecipientInfo)m_recipientInfos[index];
			}
		}

		public int Count => m_recipientInfos.Count;

		public bool IsSynchronized => false;

		public object SyncRoot => this;

		internal RecipientInfoCollection()
		{
			m_safeCryptMsgHandle = SafeCryptMsgHandle.InvalidHandle;
			m_recipientInfos = new ArrayList();
		}

		internal RecipientInfoCollection(RecipientInfo recipientInfo)
		{
			m_safeCryptMsgHandle = SafeCryptMsgHandle.InvalidHandle;
			m_recipientInfos = new ArrayList(1);
			m_recipientInfos.Add(recipientInfo);
		}

		internal unsafe RecipientInfoCollection(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			bool flag = PkcsUtils.CmsSupported();
			uint num = 0u;
			uint num2 = (uint)Marshal.SizeOf(typeof(uint));
			if (flag)
			{
				if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 33u, 0u, new IntPtr(&num), new IntPtr(&num2)))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
			}
			else if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 17u, 0u, new IntPtr(&num), new IntPtr(&num2)))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			m_recipientInfos = new ArrayList();
			for (uint num3 = 0u; num3 < num; num3++)
			{
				if (flag)
				{
					PkcsUtils.GetParam(safeCryptMsgHandle, 36u, num3, out SafeLocalAllocHandle pvData, out uint _);
					CAPIBase.CMSG_CMS_RECIPIENT_INFO cMSG_CMS_RECIPIENT_INFO = (CAPIBase.CMSG_CMS_RECIPIENT_INFO)Marshal.PtrToStructure(pvData.DangerousGetHandle(), typeof(CAPIBase.CMSG_CMS_RECIPIENT_INFO));
					switch (cMSG_CMS_RECIPIENT_INFO.dwRecipientChoice)
					{
					case 1u:
					{
						CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO keyTrans = (CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO)Marshal.PtrToStructure(cMSG_CMS_RECIPIENT_INFO.pRecipientInfo, typeof(CAPIBase.CMSG_KEY_TRANS_RECIPIENT_INFO));
						m_recipientInfos.Add(new KeyTransRecipientInfo(pvData, keyTrans, num3));
						break;
					}
					case 2u:
					{
						CAPIBase.CMSG_KEY_AGREE_RECIPIENT_INFO cMSG_KEY_AGREE_RECIPIENT_INFO = (CAPIBase.CMSG_KEY_AGREE_RECIPIENT_INFO)Marshal.PtrToStructure(cMSG_CMS_RECIPIENT_INFO.pRecipientInfo, typeof(CAPIBase.CMSG_KEY_AGREE_RECIPIENT_INFO));
						switch (cMSG_KEY_AGREE_RECIPIENT_INFO.dwOriginatorChoice)
						{
						case 1u:
						{
							CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO certIdRecipient = (CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO)Marshal.PtrToStructure(cMSG_CMS_RECIPIENT_INFO.pRecipientInfo, typeof(CAPIBase.CMSG_KEY_AGREE_CERT_ID_RECIPIENT_INFO));
							for (uint num5 = 0u; num5 < certIdRecipient.cRecipientEncryptedKeys; num5++)
							{
								m_recipientInfos.Add(new KeyAgreeRecipientInfo(pvData, certIdRecipient, num3, num5));
							}
							break;
						}
						case 2u:
						{
							CAPIBase.CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO publicKeyRecipient = (CAPIBase.CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO)Marshal.PtrToStructure(cMSG_CMS_RECIPIENT_INFO.pRecipientInfo, typeof(CAPIBase.CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO));
							for (uint num4 = 0u; num4 < publicKeyRecipient.cRecipientEncryptedKeys; num4++)
							{
								m_recipientInfos.Add(new KeyAgreeRecipientInfo(pvData, publicKeyRecipient, num3, num4));
							}
							break;
						}
						default:
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Originator_Identifier_Choice"), cMSG_KEY_AGREE_RECIPIENT_INFO.dwOriginatorChoice.ToString(CultureInfo.CurrentCulture));
						}
						break;
					}
					default:
						throw new CryptographicException(-2147483647);
					}
				}
				else
				{
					PkcsUtils.GetParam(safeCryptMsgHandle, 19u, num3, out SafeLocalAllocHandle pvData2, out uint _);
					CAPIBase.CERT_INFO certInfo = (CAPIBase.CERT_INFO)Marshal.PtrToStructure(pvData2.DangerousGetHandle(), typeof(CAPIBase.CERT_INFO));
					m_recipientInfos.Add(new KeyTransRecipientInfo(pvData2, certInfo, num3));
				}
			}
			m_safeCryptMsgHandle = safeCryptMsgHandle;
		}

		public RecipientInfoEnumerator GetEnumerator()
		{
			return new RecipientInfoEnumerator(this);
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return new RecipientInfoEnumerator(this);
		}

		public void CopyTo(Array array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			if (array.Rank != 1)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Arg_RankMultiDimNotSupported"));
			}
			if (index < 0 || index >= array.Length)
			{
				throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
			}
			if (index + Count > array.Length)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Argument_InvalidOffLen"));
			}
			for (int i = 0; i < Count; i++)
			{
				array.SetValue(this[i], index);
				index++;
			}
		}

		public void CopyTo(RecipientInfo[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class RecipientInfoEnumerator : IEnumerator
	{
		private RecipientInfoCollection m_recipientInfos;

		private int m_current;

		public RecipientInfo Current => m_recipientInfos[m_current];

		object IEnumerator.Current => m_recipientInfos[m_current];

		private RecipientInfoEnumerator()
		{
		}

		internal RecipientInfoEnumerator(RecipientInfoCollection RecipientInfos)
		{
			m_recipientInfos = RecipientInfos;
			m_current = -1;
		}

		public bool MoveNext()
		{
			if (m_current == m_recipientInfos.Count - 1)
			{
				return false;
			}
			m_current++;
			return true;
		}

		public void Reset()
		{
			m_current = -1;
		}
	}
	public enum KeyAgreeKeyChoice
	{
		Unknown,
		EphemeralKey,
		StaticKey
	}
	public enum SubjectIdentifierType
	{
		Unknown,
		IssuerAndSerialNumber,
		SubjectKeyIdentifier,
		NoSignature
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class SubjectIdentifier
	{
		private SubjectIdentifierType m_type;

		private object m_value;

		public SubjectIdentifierType Type => m_type;

		public object Value => m_value;

		private SubjectIdentifier()
		{
		}

		internal SubjectIdentifier(CAPIBase.CERT_INFO certInfo)
			: this(certInfo.Issuer, certInfo.SerialNumber)
		{
		}

		internal SubjectIdentifier(CAPIBase.CMSG_SIGNER_INFO signerInfo)
			: this(signerInfo.Issuer, signerInfo.SerialNumber)
		{
		}

		internal SubjectIdentifier(SubjectIdentifierType type, object value)
		{
			Reset(type, value);
		}

		internal unsafe SubjectIdentifier(CAPIBase.CRYPTOAPI_BLOB issuer, CAPIBase.CRYPTOAPI_BLOB serialNumber)
		{
			bool flag = true;
			byte* ptr = (byte*)(void*)serialNumber.pbData;
			for (uint num = 0u; num < serialNumber.cbData; num++)
			{
				if (*(ptr++) != 0)
				{
					flag = false;
					break;
				}
			}
			if (flag)
			{
				byte[] array = new byte[issuer.cbData];
				Marshal.Copy(issuer.pbData, array, 0, array.Length);
				X500DistinguishedName x500DistinguishedName = new X500DistinguishedName(array);
				if (string.Compare("CN=Dummy Signer", x500DistinguishedName.Name, StringComparison.OrdinalIgnoreCase) == 0)
				{
					Reset(SubjectIdentifierType.NoSignature, null);
					return;
				}
			}
			if (flag)
			{
				m_type = SubjectIdentifierType.SubjectKeyIdentifier;
				m_value = string.Empty;
				uint cbDecodedValue = 0u;
				SafeLocalAllocHandle decodedValue = SafeLocalAllocHandle.InvalidHandle;
				if (CAPI.DecodeObject(new IntPtr(7L), issuer.pbData, issuer.cbData, out decodedValue, out cbDecodedValue))
				{
					using (decodedValue)
					{
						CAPIBase.CERT_NAME_INFO cERT_NAME_INFO = (CAPIBase.CERT_NAME_INFO)Marshal.PtrToStructure(decodedValue.DangerousGetHandle(), typeof(CAPIBase.CERT_NAME_INFO));
						for (uint num2 = 0u; num2 < cERT_NAME_INFO.cRDN; num2++)
						{
							CAPIBase.CERT_RDN cERT_RDN = (CAPIBase.CERT_RDN)Marshal.PtrToStructure(new IntPtr((long)cERT_NAME_INFO.rgRDN + num2 * Marshal.SizeOf(typeof(CAPIBase.CERT_RDN))), typeof(CAPIBase.CERT_RDN));
							for (uint num3 = 0u; num3 < cERT_RDN.cRDNAttr; num3++)
							{
								CAPIBase.CERT_RDN_ATTR cERT_RDN_ATTR = (CAPIBase.CERT_RDN_ATTR)Marshal.PtrToStructure(new IntPtr((long)cERT_RDN.rgRDNAttr + num3 * Marshal.SizeOf(typeof(CAPIBase.CERT_RDN_ATTR))), typeof(CAPIBase.CERT_RDN_ATTR));
								if (string.Compare("1.3.6.1.4.1.311.10.7.1", cERT_RDN_ATTR.pszObjId, StringComparison.OrdinalIgnoreCase) == 0 && cERT_RDN_ATTR.dwValueType == 2)
								{
									byte[] array2 = new byte[cERT_RDN_ATTR.Value.cbData];
									Marshal.Copy(cERT_RDN_ATTR.Value.pbData, array2, 0, array2.Length);
									Reset(SubjectIdentifierType.SubjectKeyIdentifier, System.Security.Cryptography.X509Certificates.X509Utils.EncodeHexString(array2));
									return;
								}
							}
						}
					}
				}
			}
			CAPIBase.CERT_ISSUER_SERIAL_NUMBER pIssuerAndSerial = default(CAPIBase.CERT_ISSUER_SERIAL_NUMBER);
			pIssuerAndSerial.Issuer = issuer;
			pIssuerAndSerial.SerialNumber = serialNumber;
			X509IssuerSerial x509IssuerSerial = PkcsUtils.DecodeIssuerSerial(pIssuerAndSerial);
			Reset(SubjectIdentifierType.IssuerAndSerialNumber, x509IssuerSerial);
		}

		internal SubjectIdentifier(CAPIBase.CERT_ID certId)
		{
			switch (certId.dwIdChoice)
			{
			case 1u:
			{
				X509IssuerSerial x509IssuerSerial = PkcsUtils.DecodeIssuerSerial(certId.Value.IssuerSerialNumber);
				Reset(SubjectIdentifierType.IssuerAndSerialNumber, x509IssuerSerial);
				break;
			}
			case 2u:
			{
				byte[] array = new byte[certId.Value.KeyId.cbData];
				Marshal.Copy(certId.Value.KeyId.pbData, array, 0, array.Length);
				Reset(SubjectIdentifierType.SubjectKeyIdentifier, System.Security.Cryptography.X509Certificates.X509Utils.EncodeHexString(array));
				break;
			}
			default:
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type"), certId.dwIdChoice.ToString(CultureInfo.InvariantCulture));
			}
		}

		internal void Reset(SubjectIdentifierType type, object value)
		{
			switch (type)
			{
			case SubjectIdentifierType.IssuerAndSerialNumber:
				if (value.GetType() != typeof(X509IssuerSerial))
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type_Value_Mismatch"), value.GetType().ToString());
				}
				break;
			case SubjectIdentifierType.SubjectKeyIdentifier:
				if (!PkcsUtils.CmsSupported())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Not_Supported"));
				}
				if (value.GetType() != typeof(string))
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type_Value_Mismatch"), value.GetType().ToString());
				}
				break;
			default:
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type"), type.ToString());
			case SubjectIdentifierType.Unknown:
			case SubjectIdentifierType.NoSignature:
				break;
			}
			m_type = type;
			m_value = value;
		}
	}
	public enum SubjectIdentifierOrKeyType
	{
		Unknown,
		IssuerAndSerialNumber,
		SubjectKeyIdentifier,
		PublicKeyInfo
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class PublicKeyInfo
	{
		private AlgorithmIdentifier m_algorithm;

		private byte[] m_keyValue;

		public AlgorithmIdentifier Algorithm => m_algorithm;

		public byte[] KeyValue => m_keyValue;

		private PublicKeyInfo()
		{
		}

		internal PublicKeyInfo(CAPIBase.CERT_PUBLIC_KEY_INFO keyInfo)
		{
			m_algorithm = new AlgorithmIdentifier(keyInfo);
			m_keyValue = new byte[keyInfo.PublicKey.cbData];
			if (m_keyValue.Length > 0)
			{
				Marshal.Copy(keyInfo.PublicKey.pbData, m_keyValue, 0, m_keyValue.Length);
			}
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class SubjectIdentifierOrKey
	{
		private SubjectIdentifierOrKeyType m_type;

		private object m_value;

		public SubjectIdentifierOrKeyType Type => m_type;

		public object Value => m_value;

		private SubjectIdentifierOrKey()
		{
		}

		internal SubjectIdentifierOrKey(SubjectIdentifierOrKeyType type, object value)
		{
			Reset(type, value);
		}

		internal SubjectIdentifierOrKey(CAPIBase.CERT_ID certId)
		{
			switch (certId.dwIdChoice)
			{
			case 1u:
			{
				X509IssuerSerial x509IssuerSerial = PkcsUtils.DecodeIssuerSerial(certId.Value.IssuerSerialNumber);
				Reset(SubjectIdentifierOrKeyType.IssuerAndSerialNumber, x509IssuerSerial);
				break;
			}
			case 2u:
			{
				byte[] array = new byte[certId.Value.KeyId.cbData];
				Marshal.Copy(certId.Value.KeyId.pbData, array, 0, array.Length);
				Reset(SubjectIdentifierOrKeyType.SubjectKeyIdentifier, System.Security.Cryptography.X509Certificates.X509Utils.EncodeHexString(array));
				break;
			}
			default:
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type"), certId.dwIdChoice.ToString(CultureInfo.InvariantCulture));
			}
		}

		internal SubjectIdentifierOrKey(CAPIBase.CERT_PUBLIC_KEY_INFO publicKeyInfo)
		{
			Reset(SubjectIdentifierOrKeyType.PublicKeyInfo, new PublicKeyInfo(publicKeyInfo));
		}

		internal void Reset(SubjectIdentifierOrKeyType type, object value)
		{
			switch (type)
			{
			case SubjectIdentifierOrKeyType.IssuerAndSerialNumber:
				if (value.GetType() != typeof(X509IssuerSerial))
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type_Value_Mismatch"), value.GetType().ToString());
				}
				break;
			case SubjectIdentifierOrKeyType.SubjectKeyIdentifier:
				if (!PkcsUtils.CmsSupported())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Not_Supported"));
				}
				if (value.GetType() != typeof(string))
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type_Value_Mismatch"), value.GetType().ToString());
				}
				break;
			case SubjectIdentifierOrKeyType.PublicKeyInfo:
				if (!PkcsUtils.CmsSupported())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Not_Supported"));
				}
				if (value.GetType() != typeof(PublicKeyInfo))
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type_Value_Mismatch"), value.GetType().ToString());
				}
				break;
			default:
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Invalid_Subject_Identifier_Type"), type.ToString());
			case SubjectIdentifierOrKeyType.Unknown:
				break;
			}
			m_type = type;
			m_value = value;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class AlgorithmIdentifier
	{
		private Oid m_oid;

		private int m_keyLength;

		private byte[] m_parameters;

		public Oid Oid
		{
			get
			{
				return m_oid;
			}
			set
			{
				m_oid = value;
			}
		}

		public int KeyLength
		{
			get
			{
				return m_keyLength;
			}
			set
			{
				m_keyLength = value;
			}
		}

		public byte[] Parameters
		{
			get
			{
				return m_parameters;
			}
			set
			{
				m_parameters = value;
			}
		}

		public AlgorithmIdentifier()
		{
			Reset(new Oid("1.2.840.113549.3.7"), 0, new byte[0]);
		}

		public AlgorithmIdentifier(Oid oid)
		{
			Reset(oid, 0, new byte[0]);
		}

		public AlgorithmIdentifier(Oid oid, int keyLength)
		{
			Reset(oid, keyLength, new byte[0]);
		}

		internal AlgorithmIdentifier(string oidValue)
		{
			Reset(new Oid(oidValue), 0, new byte[0]);
		}

		internal AlgorithmIdentifier(CAPIBase.CERT_PUBLIC_KEY_INFO keyInfo)
		{
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CERT_PUBLIC_KEY_INFO))));
			Marshal.StructureToPtr(keyInfo, safeLocalAllocHandle.DangerousGetHandle(), fDeleteOld: false);
			int keyLength = (int)CAPISafe.CertGetPublicKeyLength(65537u, safeLocalAllocHandle.DangerousGetHandle());
			byte[] array = new byte[keyInfo.Algorithm.Parameters.cbData];
			if (array.Length > 0)
			{
				Marshal.Copy(keyInfo.Algorithm.Parameters.pbData, array, 0, array.Length);
			}
			Marshal.DestroyStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CERT_PUBLIC_KEY_INFO));
			safeLocalAllocHandle.Dispose();
			Reset(new Oid(keyInfo.Algorithm.pszObjId), keyLength, array);
		}

		internal AlgorithmIdentifier(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER algorithmIdentifier)
		{
			int keyLength = 0;
			uint cbDecodedValue = 0u;
			SafeLocalAllocHandle decodedValue = SafeLocalAllocHandle.InvalidHandle;
			byte[] array = new byte[0];
			uint num = System.Security.Cryptography.X509Certificates.X509Utils.OidToAlgId(algorithmIdentifier.pszObjId);
			switch (num)
			{
			case 26114u:
				if (algorithmIdentifier.Parameters.cbData != 0)
				{
					if (!CAPI.DecodeObject(new IntPtr(41L), algorithmIdentifier.Parameters.pbData, algorithmIdentifier.Parameters.cbData, out decodedValue, out cbDecodedValue))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					CAPIBase.CRYPT_RC2_CBC_PARAMETERS cRYPT_RC2_CBC_PARAMETERS = (CAPIBase.CRYPT_RC2_CBC_PARAMETERS)Marshal.PtrToStructure(decodedValue.DangerousGetHandle(), typeof(CAPIBase.CRYPT_RC2_CBC_PARAMETERS));
					switch (cRYPT_RC2_CBC_PARAMETERS.dwVersion)
					{
					case 160u:
						keyLength = 40;
						break;
					case 52u:
						keyLength = 56;
						break;
					case 58u:
						keyLength = 128;
						break;
					}
					if (cRYPT_RC2_CBC_PARAMETERS.fIV)
					{
						array = (byte[])cRYPT_RC2_CBC_PARAMETERS.rgbIV.Clone();
					}
				}
				break;
			case 26113u:
			case 26115u:
			case 26625u:
				if (algorithmIdentifier.Parameters.cbData != 0)
				{
					if (!CAPI.DecodeObject(new IntPtr(25L), algorithmIdentifier.Parameters.pbData, algorithmIdentifier.Parameters.cbData, out decodedValue, out cbDecodedValue))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					if (cbDecodedValue != 0)
					{
						if (num == 26625)
						{
							CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = (CAPIBase.CRYPTOAPI_BLOB)Marshal.PtrToStructure(decodedValue.DangerousGetHandle(), typeof(CAPIBase.CRYPTOAPI_BLOB));
							if (cRYPTOAPI_BLOB.cbData != 0)
							{
								array = new byte[cRYPTOAPI_BLOB.cbData];
								Marshal.Copy(cRYPTOAPI_BLOB.pbData, array, 0, array.Length);
							}
						}
						else
						{
							array = new byte[cbDecodedValue];
							Marshal.Copy(decodedValue.DangerousGetHandle(), array, 0, array.Length);
						}
					}
				}
				keyLength = num switch
				{
					26625u => 128 - array.Length * 8, 
					26113u => 64, 
					_ => 192, 
				};
				break;
			default:
				if (algorithmIdentifier.Parameters.cbData != 0)
				{
					array = new byte[algorithmIdentifier.Parameters.cbData];
					Marshal.Copy(algorithmIdentifier.Parameters.pbData, array, 0, array.Length);
				}
				break;
			}
			Reset(new Oid(algorithmIdentifier.pszObjId), keyLength, array);
			decodedValue.Dispose();
		}

		private void Reset(Oid oid, int keyLength, byte[] parameters)
		{
			m_oid = oid;
			m_keyLength = keyLength;
			m_parameters = parameters;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class ContentInfo
	{
		private Oid m_contentType;

		private byte[] m_content;

		private IntPtr m_pContent = IntPtr.Zero;

		private GCHandle m_gcHandle;

		public Oid ContentType => m_contentType;

		public byte[] Content => m_content;

		internal IntPtr pContent
		{
			get
			{
				if (IntPtr.Zero == m_pContent && m_content != null && m_content.Length != 0)
				{
					m_gcHandle = GCHandle.Alloc(m_content, GCHandleType.Pinned);
					m_pContent = Marshal.UnsafeAddrOfPinnedArrayElement(m_content, 0);
				}
				return m_pContent;
			}
		}

		private ContentInfo()
			: this(new Oid("1.2.840.113549.1.7.1"), new byte[0])
		{
		}

		public ContentInfo(byte[] content)
			: this(new Oid("1.2.840.113549.1.7.1"), content)
		{
		}

		internal ContentInfo(string contentType, byte[] content)
			: this(new Oid(contentType), content)
		{
		}

		public ContentInfo(Oid contentType, byte[] content)
		{
			if (contentType == null)
			{
				throw new ArgumentNullException("contentType");
			}
			if (content == null)
			{
				throw new ArgumentNullException("content");
			}
			m_contentType = contentType;
			m_content = content;
		}

		~ContentInfo()
		{
			if (m_gcHandle.IsAllocated)
			{
				m_gcHandle.Free();
			}
		}

		public static Oid GetContentType(byte[] encodedMessage)
		{
			if (encodedMessage == null)
			{
				throw new ArgumentNullException("encodedMessage");
			}
			SafeCryptMsgHandle safeCryptMsgHandle = CAPISafe.CryptMsgOpenToDecode(65537u, 0u, 0u, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			if (safeCryptMsgHandle == null || safeCryptMsgHandle.IsInvalid)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (!CAPISafe.CryptMsgUpdate(safeCryptMsgHandle, encodedMessage, (uint)encodedMessage.Length, fFinal: true))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			Oid result = PkcsUtils.GetMessageType(safeCryptMsgHandle) switch
			{
				1u => new Oid("1.2.840.113549.1.7.1"), 
				2u => new Oid("1.2.840.113549.1.7.2"), 
				3u => new Oid("1.2.840.113549.1.7.3"), 
				4u => new Oid("1.2.840.113549.1.7.4"), 
				5u => new Oid("1.2.840.113549.1.7.5"), 
				6u => new Oid("1.2.840.113549.1.7.6"), 
				_ => throw new CryptographicException(-2146889724), 
			};
			safeCryptMsgHandle.Dispose();
			return result;
		}
	}
	internal class PkcsUtils
	{
		private struct I_CRYPT_ATTRIBUTE
		{
			internal IntPtr pszObjId;

			internal uint cValue;

			internal IntPtr rgValue;
		}

		private static int m_cmsSupported = -1;

		private PkcsUtils()
		{
		}

		internal static uint AlignedLength(uint length)
		{
			return (length + 7) & 0xFFFFFFF8u;
		}

		internal static bool CmsSupported()
		{
			if (m_cmsSupported == -1)
			{
				IntPtr intPtr = CAPISafe.LoadLibrary("Crypt32.dll");
				if (intPtr != IntPtr.Zero)
				{
					IntPtr procAddress = CAPISafe.GetProcAddress(intPtr, "CryptMsgVerifyCountersignatureEncodedEx");
					m_cmsSupported = ((!(procAddress == IntPtr.Zero)) ? 1 : 0);
					CAPISafe.FreeLibrary(intPtr);
				}
			}
			if (m_cmsSupported != 0)
			{
				return true;
			}
			return false;
		}

		internal static RecipientInfoType GetRecipientInfoType(X509Certificate2 certificate)
		{
			RecipientInfoType result = RecipientInfoType.Unknown;
			if (certificate != null)
			{
				switch (System.Security.Cryptography.X509Certificates.X509Utils.OidToAlgId(((CAPIBase.CERT_INFO)Marshal.PtrToStructure(((CAPIBase.CERT_CONTEXT)Marshal.PtrToStructure(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate).DangerousGetHandle(), typeof(CAPIBase.CERT_CONTEXT))).pCertInfo, typeof(CAPIBase.CERT_INFO))).SubjectPublicKeyInfo.Algorithm.pszObjId))
				{
				case 41984u:
					result = RecipientInfoType.KeyTransport;
					break;
				case 43521u:
				case 43522u:
					result = RecipientInfoType.KeyAgreement;
					break;
				default:
					result = RecipientInfoType.Unknown;
					break;
				}
			}
			return result;
		}

		internal unsafe static int GetMaxKeyLength(SafeCryptProvHandle safeCryptProvHandle, uint algId)
		{
			uint dwFlags = 1u;
			uint num = (uint)Marshal.SizeOf(typeof(CAPIBase.PROV_ENUMALGS_EX));
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.PROV_ENUMALGS_EX))));
			using (safeLocalAllocHandle)
			{
				while (CAPISafe.CryptGetProvParam(safeCryptProvHandle, 22u, safeLocalAllocHandle.DangerousGetHandle(), new IntPtr(&num), dwFlags))
				{
					CAPIBase.PROV_ENUMALGS_EX pROV_ENUMALGS_EX = (CAPIBase.PROV_ENUMALGS_EX)Marshal.PtrToStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.PROV_ENUMALGS_EX));
					if (pROV_ENUMALGS_EX.aiAlgid == algId)
					{
						return (int)pROV_ENUMALGS_EX.dwMaxLen;
					}
					dwFlags = 0u;
				}
			}
			throw new CryptographicException(-2146889726);
		}

		internal unsafe static uint GetVersion(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			uint result = 0u;
			uint num = (uint)Marshal.SizeOf(typeof(uint));
			if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 30u, 0u, new IntPtr(&result), new IntPtr(&num)))
			{
				checkErr(Marshal.GetLastWin32Error());
			}
			return result;
		}

		internal unsafe static uint GetMessageType(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			uint result = 0u;
			uint num = (uint)Marshal.SizeOf(typeof(uint));
			if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 1u, 0u, new IntPtr(&result), new IntPtr(&num)))
			{
				checkErr(Marshal.GetLastWin32Error());
			}
			return result;
		}

		internal unsafe static AlgorithmIdentifier GetAlgorithmIdentifier(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			AlgorithmIdentifier result = new AlgorithmIdentifier();
			uint num = 0u;
			if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 15u, 0u, IntPtr.Zero, new IntPtr(&num)))
			{
				checkErr(Marshal.GetLastWin32Error());
			}
			if (num != 0)
			{
				SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(0u, new IntPtr(num));
				if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 15u, 0u, safeLocalAllocHandle, new IntPtr(&num)))
				{
					checkErr(Marshal.GetLastWin32Error());
				}
				CAPIBase.CRYPT_ALGORITHM_IDENTIFIER algorithmIdentifier = (CAPIBase.CRYPT_ALGORITHM_IDENTIFIER)Marshal.PtrToStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER));
				result = new AlgorithmIdentifier(algorithmIdentifier);
				safeLocalAllocHandle.Dispose();
			}
			return result;
		}

		internal unsafe static void GetParam(SafeCryptMsgHandle safeCryptMsgHandle, uint paramType, uint index, out SafeLocalAllocHandle pvData, out uint cbData)
		{
			cbData = 0u;
			pvData = SafeLocalAllocHandle.InvalidHandle;
			fixed (uint* value = &cbData)
			{
				if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, paramType, index, pvData, new IntPtr(value)))
				{
					checkErr(Marshal.GetLastWin32Error());
				}
				if (cbData != 0)
				{
					pvData = CAPI.LocalAlloc(64u, new IntPtr(cbData));
					if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, paramType, index, pvData, new IntPtr(value)))
					{
						checkErr(Marshal.GetLastWin32Error());
					}
				}
			}
		}

		internal unsafe static void GetParam(SafeCryptMsgHandle safeCryptMsgHandle, uint paramType, uint index, out byte[] pvData, out uint cbData)
		{
			cbData = 0u;
			pvData = new byte[0];
			fixed (uint* value = &cbData)
			{
				if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, paramType, index, IntPtr.Zero, new IntPtr(value)))
				{
					checkErr(Marshal.GetLastWin32Error());
				}
				if (cbData == 0)
				{
					return;
				}
				pvData = new byte[cbData];
				fixed (byte* value2 = &pvData[0])
				{
					if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, paramType, index, new IntPtr(value2), new IntPtr(value)))
					{
						checkErr(Marshal.GetLastWin32Error());
					}
				}
			}
		}

		internal unsafe static X509Certificate2Collection GetCertificates(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			uint num = 0u;
			uint num2 = (uint)Marshal.SizeOf(typeof(uint));
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 11u, 0u, new IntPtr(&num), new IntPtr(&num2)))
			{
				checkErr(Marshal.GetLastWin32Error());
			}
			for (uint num3 = 0u; num3 < num; num3++)
			{
				uint cbData = 0u;
				SafeLocalAllocHandle pvData = SafeLocalAllocHandle.InvalidHandle;
				GetParam(safeCryptMsgHandle, 12u, num3, out pvData, out cbData);
				if (cbData != 0)
				{
					SafeCertContextHandle safeCertContextHandle = CAPISafe.CertCreateCertificateContext(65537u, pvData, cbData);
					if (safeCertContextHandle == null || safeCertContextHandle.IsInvalid)
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					x509Certificate2Collection.Add(new X509Certificate2(safeCertContextHandle.DangerousGetHandle()));
					safeCertContextHandle.Dispose();
				}
			}
			return x509Certificate2Collection;
		}

		internal static byte[] GetContent(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			uint cbData = 0u;
			byte[] pvData = new byte[0];
			GetParam(safeCryptMsgHandle, 2u, 0u, out pvData, out cbData);
			return pvData;
		}

		internal static Oid GetContentType(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			uint cbData = 0u;
			byte[] pvData = new byte[0];
			GetParam(safeCryptMsgHandle, 4u, 0u, out pvData, out cbData);
			if (pvData.Length > 0 && pvData[pvData.Length - 1] == 0)
			{
				byte[] array = new byte[pvData.Length - 1];
				Array.Copy(pvData, 0, array, 0, array.Length);
				pvData = array;
			}
			return new Oid(Encoding.ASCII.GetString(pvData));
		}

		internal static byte[] GetMessage(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			uint cbData = 0u;
			byte[] pvData = new byte[0];
			GetParam(safeCryptMsgHandle, 29u, 0u, out pvData, out cbData);
			return pvData;
		}

		internal unsafe static int GetSignerIndex(SafeCryptMsgHandle safeCrytpMsgHandle, SignerInfo signerInfo, int startIndex)
		{
			uint num = 0u;
			uint num2 = (uint)Marshal.SizeOf(typeof(uint));
			if (!CAPISafe.CryptMsgGetParam(safeCrytpMsgHandle, 5u, 0u, new IntPtr(&num), new IntPtr(&num2)))
			{
				checkErr(Marshal.GetLastWin32Error());
			}
			for (int i = startIndex; i < (int)num; i++)
			{
				uint num3 = 0u;
				if (!CAPISafe.CryptMsgGetParam(safeCrytpMsgHandle, 6u, (uint)i, IntPtr.Zero, new IntPtr(&num3)))
				{
					checkErr(Marshal.GetLastWin32Error());
				}
				if (num3 != 0)
				{
					SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(0u, new IntPtr(num3));
					if (!CAPISafe.CryptMsgGetParam(safeCrytpMsgHandle, 6u, (uint)i, safeLocalAllocHandle, new IntPtr(&num3)))
					{
						checkErr(Marshal.GetLastWin32Error());
					}
					CAPIBase.CMSG_SIGNER_INFO cmsgSignerInfo = signerInfo.GetCmsgSignerInfo();
					CAPIBase.CMSG_SIGNER_INFO cMSG_SIGNER_INFO = (CAPIBase.CMSG_SIGNER_INFO)Marshal.PtrToStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CMSG_SIGNER_INFO));
					if (System.Security.Cryptography.X509Certificates.X509Utils.MemEqual((byte*)(void*)cmsgSignerInfo.Issuer.pbData, cmsgSignerInfo.Issuer.cbData, (byte*)(void*)cMSG_SIGNER_INFO.Issuer.pbData, cMSG_SIGNER_INFO.Issuer.cbData) && System.Security.Cryptography.X509Certificates.X509Utils.MemEqual((byte*)(void*)cmsgSignerInfo.SerialNumber.pbData, cmsgSignerInfo.SerialNumber.cbData, (byte*)(void*)cMSG_SIGNER_INFO.SerialNumber.pbData, cMSG_SIGNER_INFO.SerialNumber.cbData))
					{
						return i;
					}
					safeLocalAllocHandle.Dispose();
				}
			}
			throw new CryptographicException(-2146889714);
		}

		internal unsafe static CryptographicAttributeObjectCollection GetUnprotectedAttributes(SafeCryptMsgHandle safeCryptMsgHandle)
		{
			uint num = 0u;
			CryptographicAttributeObjectCollection result = new CryptographicAttributeObjectCollection();
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 37u, 0u, invalidHandle, new IntPtr(&num)))
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if (lastWin32Error != -2146889713)
				{
					checkErr(Marshal.GetLastWin32Error());
				}
			}
			if (num != 0)
			{
				using (invalidHandle = CAPI.LocalAlloc(64u, new IntPtr(num)))
				{
					if (!CAPISafe.CryptMsgGetParam(safeCryptMsgHandle, 37u, 0u, invalidHandle, new IntPtr(&num)))
					{
						checkErr(Marshal.GetLastWin32Error());
					}
					return new CryptographicAttributeObjectCollection(invalidHandle);
				}
			}
			return result;
		}

		internal unsafe static X509IssuerSerial DecodeIssuerSerial(CAPIBase.CERT_ISSUER_SERIAL_NUMBER pIssuerAndSerial)
		{
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			uint num = CAPISafe.CertNameToStrW(65537u, new IntPtr(&pIssuerAndSerial.Issuer), 33554435u, invalidHandle, 0u);
			if (num <= 1)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			invalidHandle = CAPI.LocalAlloc(0u, new IntPtr(2 * num));
			num = CAPISafe.CertNameToStrW(65537u, new IntPtr(&pIssuerAndSerial.Issuer), 33554435u, invalidHandle, num);
			if (num <= 1)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			X509IssuerSerial result = default(X509IssuerSerial);
			result.IssuerName = Marshal.PtrToStringUni(invalidHandle.DangerousGetHandle());
			byte[] array = new byte[pIssuerAndSerial.SerialNumber.cbData];
			Marshal.Copy(pIssuerAndSerial.SerialNumber.pbData, array, 0, array.Length);
			result.SerialNumber = System.Security.Cryptography.X509Certificates.X509Utils.EncodeHexStringFromInt(array);
			invalidHandle.Dispose();
			return result;
		}

		internal static string DecodeOctetString(byte[] encodedOctetString)
		{
			uint cbDecodedValue = 0u;
			SafeLocalAllocHandle decodedValue = null;
			if (!CAPI.DecodeObject(new IntPtr(25L), encodedOctetString, out decodedValue, out cbDecodedValue))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (cbDecodedValue == 0)
			{
				return string.Empty;
			}
			CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = (CAPIBase.CRYPTOAPI_BLOB)Marshal.PtrToStructure(decodedValue.DangerousGetHandle(), typeof(CAPIBase.CRYPTOAPI_BLOB));
			if (cRYPTOAPI_BLOB.cbData == 0)
			{
				return string.Empty;
			}
			int num = (int)(cRYPTOAPI_BLOB.cbData / 2u);
			for (int i = 0; i < num; i++)
			{
				if (Marshal.ReadInt16(cRYPTOAPI_BLOB.pbData, i * 2) == 0)
				{
					num = i;
					break;
				}
			}
			string result = Marshal.PtrToStringUni(cRYPTOAPI_BLOB.pbData, num);
			decodedValue.Dispose();
			return result;
		}

		internal static byte[] DecodeOctetBytes(byte[] encodedOctetString)
		{
			uint cbDecodedValue = 0u;
			SafeLocalAllocHandle decodedValue = null;
			if (!CAPI.DecodeObject(new IntPtr(25L), encodedOctetString, out decodedValue, out cbDecodedValue))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (cbDecodedValue == 0)
			{
				return new byte[0];
			}
			using (decodedValue)
			{
				return CAPI.BlobToByteArray(decodedValue.DangerousGetHandle());
			}
		}

		internal static byte[] EncodeOctetString(string octetString)
		{
			byte[] array = new byte[2 * (octetString.Length + 1)];
			Encoding.Unicode.GetBytes(octetString, 0, octetString.Length, array, 0);
			return EncodeOctetString(array);
		}

		internal unsafe static byte[] EncodeOctetString(byte[] octets)
		{
			fixed (byte* value = octets)
			{
				CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = default(CAPIBase.CRYPTOAPI_BLOB);
				cRYPTOAPI_BLOB.cbData = (uint)octets.Length;
				cRYPTOAPI_BLOB.pbData = new IntPtr(value);
				byte[] encodedData = new byte[0];
				if (!CAPI.EncodeObject(new IntPtr(25L), new IntPtr((long)(&cRYPTOAPI_BLOB)), out encodedData))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				return encodedData;
			}
		}

		internal static string DecodeObjectIdentifier(byte[] encodedObjId, int offset)
		{
			StringBuilder stringBuilder = new StringBuilder("");
			if (0 < encodedObjId.Length - offset)
			{
				byte b = encodedObjId[offset];
				stringBuilder.Append(((byte)((uint)b / 40u)).ToString(null, null));
				stringBuilder.Append(".");
				stringBuilder.Append(((byte)((uint)b % 40u)).ToString(null, null));
				ulong num = 0uL;
				for (int i = offset + 1; i < encodedObjId.Length; i++)
				{
					byte b2 = encodedObjId[i];
					num = (num << 7) + (ulong)(b2 & 0x7F);
					if ((b2 & 0x80) == 0)
					{
						stringBuilder.Append(".");
						stringBuilder.Append(num.ToString(null, null));
						num = 0uL;
					}
				}
				if (0 != num)
				{
					throw new CryptographicException(-2146885630);
				}
			}
			return stringBuilder.ToString();
		}

		internal static CmsRecipientCollection SelectRecipients(SubjectIdentifierType recipientIdentifierType)
		{
			X509Store x509Store = new X509Store("AddressBook");
			x509Store.Open(OpenFlags.OpenExistingOnly);
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection(x509Store.Certificates);
			X509Certificate2Enumerator enumerator = x509Store.Certificates.GetEnumerator();
			while (enumerator.MoveNext())
			{
				X509Certificate2 current = enumerator.Current;
				if (!(current.NotBefore <= DateTime.Now) || !(current.NotAfter >= DateTime.Now))
				{
					continue;
				}
				bool flag = true;
				X509ExtensionEnumerator enumerator2 = current.Extensions.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					X509Extension current2 = enumerator2.Current;
					if (string.Compare(current2.Oid.Value, "2.5.29.15", StringComparison.OrdinalIgnoreCase) == 0)
					{
						X509KeyUsageExtension x509KeyUsageExtension = new X509KeyUsageExtension();
						x509KeyUsageExtension.CopyFrom(current2);
						if ((x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.KeyEncipherment) == 0 && (x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.KeyAgreement) == 0)
						{
							flag = false;
						}
						break;
					}
				}
				if (flag)
				{
					x509Certificate2Collection.Add(current);
				}
			}
			if (x509Certificate2Collection.Count < 1)
			{
				throw new CryptographicException(-2146889717);
			}
			X509Certificate2Collection x509Certificate2Collection2 = X509Certificate2UI.SelectFromCollection(x509Certificate2Collection, null, null, X509SelectionFlag.MultiSelection);
			if (x509Certificate2Collection2.Count < 1)
			{
				throw new CryptographicException(1223);
			}
			return new CmsRecipientCollection(recipientIdentifierType, x509Certificate2Collection2);
		}

		internal static X509Certificate2 SelectSignerCertificate()
		{
			X509Store x509Store = new X509Store();
			x509Store.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			X509Certificate2Enumerator enumerator = x509Store.Certificates.GetEnumerator();
			while (enumerator.MoveNext())
			{
				X509Certificate2 current = enumerator.Current;
				if (!current.HasPrivateKey || !(current.NotBefore <= DateTime.Now) || !(current.NotAfter >= DateTime.Now))
				{
					continue;
				}
				bool flag = true;
				X509ExtensionEnumerator enumerator2 = current.Extensions.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					X509Extension current2 = enumerator2.Current;
					if (string.Compare(current2.Oid.Value, "2.5.29.15", StringComparison.OrdinalIgnoreCase) == 0)
					{
						X509KeyUsageExtension x509KeyUsageExtension = new X509KeyUsageExtension();
						x509KeyUsageExtension.CopyFrom(current2);
						if ((x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0 && (x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.NonRepudiation) == 0)
						{
							flag = false;
						}
						break;
					}
				}
				if (flag)
				{
					x509Certificate2Collection.Add(current);
				}
			}
			if (x509Certificate2Collection.Count < 1)
			{
				throw new CryptographicException(-2146889714);
			}
			x509Certificate2Collection = X509Certificate2UI.SelectFromCollection(x509Certificate2Collection, null, null, X509SelectionFlag.SingleSelection);
			if (x509Certificate2Collection.Count < 1)
			{
				throw new CryptographicException(1223);
			}
			return x509Certificate2Collection[0];
		}

		internal static AsnEncodedDataCollection GetAsnEncodedDataCollection(CAPIBase.CRYPT_ATTRIBUTE cryptAttribute)
		{
			AsnEncodedDataCollection asnEncodedDataCollection = new AsnEncodedDataCollection();
			Oid oid = new Oid(cryptAttribute.pszObjId);
			string value = oid.Value;
			for (uint num = 0u; num < cryptAttribute.cValue; num++)
			{
				IntPtr pBlob = new IntPtr((long)cryptAttribute.rgValue + num * Marshal.SizeOf(typeof(CAPIBase.CRYPTOAPI_BLOB)));
				Pkcs9AttributeObject asnEncodedData = new Pkcs9AttributeObject(oid, CAPI.BlobToByteArray(pBlob));
				if (CryptoConfig.CreateFromName(value) is Pkcs9AttributeObject pkcs9AttributeObject)
				{
					pkcs9AttributeObject.CopyFrom(asnEncodedData);
					asnEncodedData = pkcs9AttributeObject;
				}
				asnEncodedDataCollection.Add(asnEncodedData);
			}
			return asnEncodedDataCollection;
		}

		internal static AsnEncodedDataCollection GetAsnEncodedDataCollection(CAPIBase.CRYPT_ATTRIBUTE_TYPE_VALUE cryptAttribute)
		{
			AsnEncodedDataCollection asnEncodedDataCollection = new AsnEncodedDataCollection();
			asnEncodedDataCollection.Add(new Pkcs9AttributeObject(new Oid(cryptAttribute.pszObjId), CAPI.BlobToByteArray(cryptAttribute.Value)));
			return asnEncodedDataCollection;
		}

		internal unsafe static IntPtr CreateCryptAttributes(CryptographicAttributeObjectCollection attributes)
		{
			if (attributes.Count == 0)
			{
				return IntPtr.Zero;
			}
			uint num = 0u;
			uint num2 = AlignedLength((uint)Marshal.SizeOf(typeof(I_CRYPT_ATTRIBUTE)));
			uint num3 = AlignedLength((uint)Marshal.SizeOf(typeof(CAPIBase.CRYPTOAPI_BLOB)));
			CryptographicAttributeObjectEnumerator enumerator = attributes.GetEnumerator();
			while (enumerator.MoveNext())
			{
				CryptographicAttributeObject current = enumerator.Current;
				num += num2;
				num += AlignedLength((uint)(current.Oid.Value.Length + 1));
				AsnEncodedDataEnumerator enumerator2 = current.Values.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					AsnEncodedData current2 = enumerator2.Current;
					num += num3;
					num += AlignedLength((uint)current2.RawData.Length);
				}
			}
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(num));
			I_CRYPT_ATTRIBUTE* ptr = (I_CRYPT_ATTRIBUTE*)(void*)safeLocalAllocHandle.DangerousGetHandle();
			IntPtr intPtr = new IntPtr((long)safeLocalAllocHandle.DangerousGetHandle() + num2 * attributes.Count);
			CryptographicAttributeObjectEnumerator enumerator3 = attributes.GetEnumerator();
			while (enumerator3.MoveNext())
			{
				CryptographicAttributeObject current3 = enumerator3.Current;
				byte* ptr2 = (byte*)(void*)intPtr;
				byte[] array = new byte[current3.Oid.Value.Length + 1];
				CAPIBase.CRYPTOAPI_BLOB* ptr3 = (CAPIBase.CRYPTOAPI_BLOB*)(ptr2 + (int)AlignedLength((uint)array.Length));
				ptr->pszObjId = (IntPtr)ptr2;
				ptr->cValue = (uint)current3.Values.Count;
				ptr->rgValue = (IntPtr)ptr3;
				Encoding.ASCII.GetBytes(current3.Oid.Value, 0, current3.Oid.Value.Length, array, 0);
				Marshal.Copy(array, 0, ptr->pszObjId, array.Length);
				IntPtr intPtr2 = new IntPtr((long)ptr3 + current3.Values.Count * num3);
				AsnEncodedDataEnumerator enumerator4 = current3.Values.GetEnumerator();
				while (enumerator4.MoveNext())
				{
					AsnEncodedData current4 = enumerator4.Current;
					byte[] rawData = current4.RawData;
					if (rawData.Length > 0)
					{
						ptr3->cbData = (uint)rawData.Length;
						ptr3->pbData = intPtr2;
						Marshal.Copy(rawData, 0, intPtr2, rawData.Length);
						intPtr2 = new IntPtr((long)intPtr2 + AlignedLength((uint)rawData.Length));
					}
					ptr3++;
				}
				ptr++;
				intPtr = intPtr2;
			}
			GC.SuppressFinalize(safeLocalAllocHandle);
			return safeLocalAllocHandle.DangerousGetHandle();
		}

		internal static CAPIBase.CMSG_SIGNER_ENCODE_INFO CreateSignerEncodeInfo(CmsSigner signer)
		{
			return CreateSignerEncodeInfo(signer, silent: false);
		}

		internal unsafe static CAPIBase.CMSG_SIGNER_ENCODE_INFO CreateSignerEncodeInfo(CmsSigner signer, bool silent)
		{
			CAPIBase.CMSG_SIGNER_ENCODE_INFO result = new CAPIBase.CMSG_SIGNER_ENCODE_INFO(Marshal.SizeOf(typeof(CAPIBase.CMSG_SIGNER_ENCODE_INFO)));
			SafeCryptProvHandle hCryptProv = SafeCryptProvHandle.InvalidHandle;
			uint pdwKeySpec = 0u;
			bool pfCallerFreeProv = false;
			result.HashAlgorithm.pszObjId = signer.DigestAlgorithm.Value;
			if (string.Compare(signer.Certificate.PublicKey.Oid.Value, "1.2.840.10040.4.1", StringComparison.Ordinal) == 0)
			{
				result.HashEncryptionAlgorithm.pszObjId = "1.2.840.10040.4.3";
			}
			result.cAuthAttr = (uint)signer.SignedAttributes.Count;
			result.rgAuthAttr = CreateCryptAttributes(signer.SignedAttributes);
			result.cUnauthAttr = (uint)signer.UnsignedAttributes.Count;
			result.rgUnauthAttr = CreateCryptAttributes(signer.UnsignedAttributes);
			if (signer.SignerIdentifierType == SubjectIdentifierType.NoSignature)
			{
				result.HashEncryptionAlgorithm.pszObjId = "1.3.6.1.5.5.7.6.2";
				result.pCertInfo = IntPtr.Zero;
				result.dwKeySpec = pdwKeySpec;
				if (!CAPI.CryptAcquireContext(ref hCryptProv, null, null, 1u, 4026531840u) && !CAPI.CryptAcquireContext(ref hCryptProv, null, null, 1u, 0u))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				result.hCryptProv = hCryptProv.DangerousGetHandle();
				GC.SuppressFinalize(hCryptProv);
				result.SignerId.dwIdChoice = 1u;
				X500DistinguishedName x500DistinguishedName = new X500DistinguishedName("CN=Dummy Signer");
				x500DistinguishedName.Oid = new Oid("1.3.6.1.4.1.311.21.9");
				result.SignerId.Value.IssuerSerialNumber.Issuer.cbData = (uint)x500DistinguishedName.RawData.Length;
				SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(result.SignerId.Value.IssuerSerialNumber.Issuer.cbData));
				Marshal.Copy(x500DistinguishedName.RawData, 0, safeLocalAllocHandle.DangerousGetHandle(), x500DistinguishedName.RawData.Length);
				result.SignerId.Value.IssuerSerialNumber.Issuer.pbData = safeLocalAllocHandle.DangerousGetHandle();
				GC.SuppressFinalize(safeLocalAllocHandle);
				result.SignerId.Value.IssuerSerialNumber.SerialNumber.cbData = 1u;
				SafeLocalAllocHandle safeLocalAllocHandle2 = CAPI.LocalAlloc(64u, new IntPtr(result.SignerId.Value.IssuerSerialNumber.SerialNumber.cbData));
				byte* ptr = (byte*)(void*)safeLocalAllocHandle2.DangerousGetHandle();
				*ptr = 0;
				result.SignerId.Value.IssuerSerialNumber.SerialNumber.pbData = safeLocalAllocHandle2.DangerousGetHandle();
				GC.SuppressFinalize(safeLocalAllocHandle2);
				return result;
			}
			SafeCertContextHandle certContext = System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(signer.Certificate);
			if (!CAPISafe.CryptAcquireCertificatePrivateKey(certContext, silent ? 70u : 6u, IntPtr.Zero, ref hCryptProv, ref pdwKeySpec, ref pfCallerFreeProv))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			result.dwKeySpec = pdwKeySpec;
			result.hCryptProv = hCryptProv.DangerousGetHandle();
			GC.SuppressFinalize(hCryptProv);
			CAPIBase.CERT_CONTEXT cERT_CONTEXT = *(CAPIBase.CERT_CONTEXT*)(void*)certContext.DangerousGetHandle();
			result.pCertInfo = cERT_CONTEXT.pCertInfo;
			if (signer.SignerIdentifierType == SubjectIdentifierType.SubjectKeyIdentifier)
			{
				uint pcbData = 0u;
				SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
				if (!CAPISafe.CertGetCertificateContextProperty(certContext, 20u, invalidHandle, ref pcbData))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				if (pcbData != 0)
				{
					invalidHandle = CAPI.LocalAlloc(64u, new IntPtr(pcbData));
					if (!CAPISafe.CertGetCertificateContextProperty(certContext, 20u, invalidHandle, ref pcbData))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					result.SignerId.dwIdChoice = 2u;
					result.SignerId.Value.KeyId.cbData = pcbData;
					result.SignerId.Value.KeyId.pbData = invalidHandle.DangerousGetHandle();
					GC.SuppressFinalize(invalidHandle);
				}
			}
			return result;
		}

		internal static X509Certificate2Collection CreateBagOfCertificates(CmsSigner signer)
		{
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			x509Certificate2Collection.AddRange(signer.Certificates);
			if (signer.IncludeOption != 0)
			{
				if (signer.IncludeOption == X509IncludeOption.EndCertOnly)
				{
					x509Certificate2Collection.Add(signer.Certificate);
				}
				else
				{
					int num = 1;
					X509Chain x509Chain = new X509Chain();
					x509Chain.Build(signer.Certificate);
					if (x509Chain.ChainStatus.Length > 0 && (x509Chain.ChainStatus[0].Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain)
					{
						throw new CryptographicException(-2146762486);
					}
					if (signer.IncludeOption == X509IncludeOption.WholeChain)
					{
						num = x509Chain.ChainElements.Count;
					}
					else if (x509Chain.ChainElements.Count > 1)
					{
						num = x509Chain.ChainElements.Count - 1;
					}
					for (int i = 0; i < num; i++)
					{
						x509Certificate2Collection.Add(x509Chain.ChainElements[i].Certificate);
					}
				}
			}
			return x509Certificate2Collection;
		}

		internal unsafe static SafeLocalAllocHandle CreateEncodedCertBlob(X509Certificate2Collection certificates)
		{
			SafeLocalAllocHandle safeLocalAllocHandle = SafeLocalAllocHandle.InvalidHandle;
			if (certificates.Count > 0)
			{
				safeLocalAllocHandle = CAPI.LocalAlloc(0u, new IntPtr(certificates.Count * Marshal.SizeOf(typeof(CAPIBase.CRYPTOAPI_BLOB))));
				CAPIBase.CRYPTOAPI_BLOB* ptr = (CAPIBase.CRYPTOAPI_BLOB*)(void*)safeLocalAllocHandle.DangerousGetHandle();
				X509Certificate2Enumerator enumerator = certificates.GetEnumerator();
				while (enumerator.MoveNext())
				{
					X509Certificate2 current = enumerator.Current;
					SafeCertContextHandle certContext = System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(current);
					CAPIBase.CERT_CONTEXT cERT_CONTEXT = *(CAPIBase.CERT_CONTEXT*)(void*)certContext.DangerousGetHandle();
					ptr->cbData = cERT_CONTEXT.cbCertEncoded;
					ptr->pbData = cERT_CONTEXT.pbCertEncoded;
					ptr++;
				}
			}
			return safeLocalAllocHandle;
		}

		internal unsafe static uint AddCertsToMessage(SafeCryptMsgHandle safeCryptMsgHandle, X509Certificate2Collection bagOfCerts, X509Certificate2Collection chainOfCerts)
		{
			uint num = 0u;
			X509Certificate2Enumerator enumerator = chainOfCerts.GetEnumerator();
			while (enumerator.MoveNext())
			{
				X509Certificate2 current = enumerator.Current;
				X509Certificate2Collection x509Certificate2Collection = bagOfCerts.Find(X509FindType.FindByThumbprint, current.Thumbprint, validOnly: false);
				if (x509Certificate2Collection.Count == 0)
				{
					SafeCertContextHandle certContext = System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(current);
					CAPIBase.CERT_CONTEXT cERT_CONTEXT = *(CAPIBase.CERT_CONTEXT*)(void*)certContext.DangerousGetHandle();
					CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = default(CAPIBase.CRYPTOAPI_BLOB);
					cRYPTOAPI_BLOB.cbData = cERT_CONTEXT.cbCertEncoded;
					cRYPTOAPI_BLOB.pbData = cERT_CONTEXT.pbCertEncoded;
					if (!CAPI.CryptMsgControl(safeCryptMsgHandle, 0u, 10u, new IntPtr((long)(&cRYPTOAPI_BLOB))))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					num++;
				}
			}
			return num;
		}

		internal static X509Certificate2 FindCertificate(SubjectIdentifier identifier, X509Certificate2Collection certificates)
		{
			X509Certificate2 result = null;
			if (certificates != null && certificates.Count > 0)
			{
				switch (identifier.Type)
				{
				case SubjectIdentifierType.IssuerAndSerialNumber:
				{
					X509Certificate2Collection x509Certificate2Collection = certificates.Find(X509FindType.FindByIssuerDistinguishedName, ((X509IssuerSerial)identifier.Value).IssuerName, validOnly: false);
					if (x509Certificate2Collection.Count > 0)
					{
						x509Certificate2Collection = x509Certificate2Collection.Find(X509FindType.FindBySerialNumber, ((X509IssuerSerial)identifier.Value).SerialNumber, validOnly: false);
						if (x509Certificate2Collection.Count > 0)
						{
							result = x509Certificate2Collection[0];
						}
					}
					break;
				}
				case SubjectIdentifierType.SubjectKeyIdentifier:
				{
					X509Certificate2Collection x509Certificate2Collection = certificates.Find(X509FindType.FindBySubjectKeyIdentifier, identifier.Value, validOnly: false);
					if (x509Certificate2Collection.Count > 0)
					{
						result = x509Certificate2Collection[0];
					}
					break;
				}
				}
			}
			return result;
		}

		private static void checkErr(int err)
		{
			if (-2146889724 != err)
			{
				throw new CryptographicException(err);
			}
		}

		internal unsafe static X509Certificate2 CreateDummyCertificate(CspParameters parameters)
		{
			SafeCertContextHandle invalidHandle = SafeCertContextHandle.InvalidHandle;
			SafeCryptProvHandle hCryptProv = SafeCryptProvHandle.InvalidHandle;
			uint num = 0u;
			if ((parameters.Flags & CspProviderFlags.UseMachineKeyStore) != 0)
			{
				num |= 0x20u;
			}
			if ((parameters.Flags & CspProviderFlags.UseDefaultKeyContainer) != 0)
			{
				num |= 0xF0000000u;
			}
			if ((parameters.Flags & CspProviderFlags.NoPrompt) != 0)
			{
				num |= 0x40u;
			}
			if (!CAPI.CryptAcquireContext(ref hCryptProv, parameters.KeyContainerName, parameters.ProviderName, (uint)parameters.ProviderType, num))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			CAPIBase.CRYPT_KEY_PROV_INFO cRYPT_KEY_PROV_INFO = default(CAPIBase.CRYPT_KEY_PROV_INFO);
			cRYPT_KEY_PROV_INFO.pwszProvName = parameters.ProviderName;
			cRYPT_KEY_PROV_INFO.pwszContainerName = parameters.KeyContainerName;
			cRYPT_KEY_PROV_INFO.dwProvType = (uint)parameters.ProviderType;
			cRYPT_KEY_PROV_INFO.dwKeySpec = (uint)parameters.KeyNumber;
			cRYPT_KEY_PROV_INFO.dwFlags = (((parameters.Flags & CspProviderFlags.UseMachineKeyStore) == CspProviderFlags.UseMachineKeyStore) ? 32u : 0u);
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CRYPT_KEY_PROV_INFO))));
			Marshal.StructureToPtr(cRYPT_KEY_PROV_INFO, safeLocalAllocHandle.DangerousGetHandle(), fDeleteOld: false);
			CAPIBase.CRYPT_ALGORITHM_IDENTIFIER cRYPT_ALGORITHM_IDENTIFIER = default(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER);
			cRYPT_ALGORITHM_IDENTIFIER.pszObjId = "1.3.14.3.2.29";
			SafeLocalAllocHandle safeLocalAllocHandle2 = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER))));
			Marshal.StructureToPtr(cRYPT_ALGORITHM_IDENTIFIER, safeLocalAllocHandle2.DangerousGetHandle(), fDeleteOld: false);
			X500DistinguishedName x500DistinguishedName = new X500DistinguishedName("cn=CMS Signer Dummy Certificate");
			fixed (byte* value = x500DistinguishedName.RawData)
			{
				CAPIBase.CRYPTOAPI_BLOB cRYPTOAPI_BLOB = default(CAPIBase.CRYPTOAPI_BLOB);
				cRYPTOAPI_BLOB.cbData = (uint)x500DistinguishedName.RawData.Length;
				cRYPTOAPI_BLOB.pbData = new IntPtr(value);
				invalidHandle = CAPIUnsafe.CertCreateSelfSignCertificate(hCryptProv, new IntPtr(&cRYPTOAPI_BLOB), 1u, safeLocalAllocHandle.DangerousGetHandle(), safeLocalAllocHandle2.DangerousGetHandle(), IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			}
			Marshal.DestroyStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CRYPT_KEY_PROV_INFO));
			safeLocalAllocHandle.Dispose();
			Marshal.DestroyStructure(safeLocalAllocHandle2.DangerousGetHandle(), typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER));
			safeLocalAllocHandle2.Dispose();
			if (invalidHandle == null || invalidHandle.IsInvalid)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			X509Certificate2 result = new X509Certificate2(invalidHandle.DangerousGetHandle());
			invalidHandle.Dispose();
			return result;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class SignedCms
	{
		private SafeCryptMsgHandle m_safeCryptMsgHandle;

		private int m_version;

		private SubjectIdentifierType m_signerIdentifierType;

		private ContentInfo m_contentInfo;

		private bool m_detached;

		public int Version
		{
			get
			{
				if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
				{
					return m_version;
				}
				return (int)PkcsUtils.GetVersion(m_safeCryptMsgHandle);
			}
		}

		public ContentInfo ContentInfo => m_contentInfo;

		public bool Detached => m_detached;

		public X509Certificate2Collection Certificates
		{
			get
			{
				if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
				{
					return new X509Certificate2Collection();
				}
				return PkcsUtils.GetCertificates(m_safeCryptMsgHandle);
			}
		}

		public SignerInfoCollection SignerInfos
		{
			get
			{
				if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
				{
					return new SignerInfoCollection();
				}
				return new SignerInfoCollection(this);
			}
		}

		public SignedCms()
			: this(SubjectIdentifierType.IssuerAndSerialNumber, new ContentInfo(new Oid("1.2.840.113549.1.7.1"), new byte[0]), detached: false)
		{
		}

		public SignedCms(SubjectIdentifierType signerIdentifierType)
			: this(signerIdentifierType, new ContentInfo(new Oid("1.2.840.113549.1.7.1"), new byte[0]), detached: false)
		{
		}

		public SignedCms(ContentInfo contentInfo)
			: this(SubjectIdentifierType.IssuerAndSerialNumber, contentInfo, detached: false)
		{
		}

		public SignedCms(SubjectIdentifierType signerIdentifierType, ContentInfo contentInfo)
			: this(signerIdentifierType, contentInfo, detached: false)
		{
		}

		public SignedCms(ContentInfo contentInfo, bool detached)
			: this(SubjectIdentifierType.IssuerAndSerialNumber, contentInfo, detached)
		{
		}

		public SignedCms(SubjectIdentifierType signerIdentifierType, ContentInfo contentInfo, bool detached)
		{
			if (contentInfo == null)
			{
				throw new ArgumentNullException("contentInfo");
			}
			if (contentInfo.Content == null)
			{
				throw new ArgumentNullException("contentInfo.Content");
			}
			if (signerIdentifierType != SubjectIdentifierType.SubjectKeyIdentifier && signerIdentifierType != SubjectIdentifierType.IssuerAndSerialNumber && signerIdentifierType != SubjectIdentifierType.NoSignature)
			{
				signerIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber;
			}
			m_safeCryptMsgHandle = SafeCryptMsgHandle.InvalidHandle;
			m_signerIdentifierType = signerIdentifierType;
			m_version = 0;
			m_contentInfo = contentInfo;
			m_detached = detached;
		}

		public byte[] Encode()
		{
			if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_MessageNotSigned"));
			}
			return PkcsUtils.GetMessage(m_safeCryptMsgHandle);
		}

		public void Decode(byte[] encodedMessage)
		{
			if (encodedMessage == null)
			{
				throw new ArgumentNullException("encodedMessage");
			}
			if (m_safeCryptMsgHandle != null && !m_safeCryptMsgHandle.IsInvalid)
			{
				m_safeCryptMsgHandle.Dispose();
			}
			m_safeCryptMsgHandle = OpenToDecode(encodedMessage, ContentInfo, Detached);
			if (!Detached)
			{
				Oid contentType = PkcsUtils.GetContentType(m_safeCryptMsgHandle);
				byte[] content = PkcsUtils.GetContent(m_safeCryptMsgHandle);
				m_contentInfo = new ContentInfo(contentType, content);
			}
		}

		public void ComputeSignature()
		{
			ComputeSignature(new CmsSigner(m_signerIdentifierType), silent: true);
		}

		public void ComputeSignature(CmsSigner signer)
		{
			ComputeSignature(signer, silent: true);
		}

		public void ComputeSignature(CmsSigner signer, bool silent)
		{
			if (signer == null)
			{
				throw new ArgumentNullException("signer");
			}
			if (ContentInfo.Content.Length == 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Sign_Empty_Content"));
			}
			if (SubjectIdentifierType.NoSignature == signer.SignerIdentifierType)
			{
				if (m_safeCryptMsgHandle != null && !m_safeCryptMsgHandle.IsInvalid)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Cms_Sign_No_Signature_First_Signer"));
				}
				Sign(signer, silent);
				return;
			}
			if (signer.Certificate == null)
			{
				if (silent)
				{
					throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_RecipientCertificateNotFound"));
				}
				signer.Certificate = PkcsUtils.SelectSignerCertificate();
			}
			if (!signer.Certificate.HasPrivateKey)
			{
				throw new CryptographicException(-2146893811);
			}
			CspParameters parameters = new CspParameters();
			if (!System.Security.Cryptography.X509Certificates.X509Utils.GetPrivateKeyInfo(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(signer.Certificate), ref parameters))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			KeyContainerPermission keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);
			KeyContainerPermissionAccessEntry accessEntry = new KeyContainerPermissionAccessEntry(parameters, KeyContainerPermissionFlags.Open | KeyContainerPermissionFlags.Sign);
			keyContainerPermission.AccessEntries.Add(accessEntry);
			keyContainerPermission.Demand();
			if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
			{
				Sign(signer, silent);
			}
			else
			{
				CoSign(signer, silent);
			}
		}

		public unsafe void RemoveSignature(int index)
		{
			if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_MessageNotSigned"));
			}
			uint num = 0u;
			uint num2 = (uint)Marshal.SizeOf(typeof(uint));
			if (!CAPISafe.CryptMsgGetParam(m_safeCryptMsgHandle, 5u, 0u, new IntPtr(&num), new IntPtr(&num2)))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (index < 0 || index >= (int)num)
			{
				throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
			}
			if (!CAPI.CryptMsgControl(m_safeCryptMsgHandle, 0u, 7u, new IntPtr(&index)))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}

		public void RemoveSignature(SignerInfo signerInfo)
		{
			if (signerInfo == null)
			{
				throw new ArgumentNullException("signerInfo");
			}
			RemoveSignature(PkcsUtils.GetSignerIndex(m_safeCryptMsgHandle, signerInfo, 0));
		}

		public void CheckSignature(bool verifySignatureOnly)
		{
			CheckSignature(new X509Certificate2Collection(), verifySignatureOnly);
		}

		public void CheckSignature(X509Certificate2Collection extraStore, bool verifySignatureOnly)
		{
			if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_MessageNotSigned"));
			}
			if (extraStore == null)
			{
				throw new ArgumentNullException("extraStore");
			}
			CheckSignatures(SignerInfos, extraStore, verifySignatureOnly);
		}

		public void CheckHash()
		{
			if (m_safeCryptMsgHandle == null || m_safeCryptMsgHandle.IsInvalid)
			{
				throw new InvalidOperationException(SecurityResources.GetResourceString("Cryptography_Cms_MessageNotSigned"));
			}
			CheckHashes(SignerInfos);
		}

		internal SafeCryptMsgHandle GetCryptMsgHandle()
		{
			return m_safeCryptMsgHandle;
		}

		internal void ReopenToDecode()
		{
			byte[] message = PkcsUtils.GetMessage(m_safeCryptMsgHandle);
			if (m_safeCryptMsgHandle != null && !m_safeCryptMsgHandle.IsInvalid)
			{
				m_safeCryptMsgHandle.Dispose();
			}
			m_safeCryptMsgHandle = OpenToDecode(message, ContentInfo, Detached);
		}

		private unsafe void Sign(CmsSigner signer, bool silent)
		{
			SafeCryptMsgHandle safeCryptMsgHandle = null;
			CAPIBase.CMSG_SIGNED_ENCODE_INFO cMSG_SIGNED_ENCODE_INFO = new CAPIBase.CMSG_SIGNED_ENCODE_INFO(Marshal.SizeOf(typeof(CAPIBase.CMSG_SIGNED_ENCODE_INFO)));
			CAPIBase.CMSG_SIGNER_ENCODE_INFO cMSG_SIGNER_ENCODE_INFO = PkcsUtils.CreateSignerEncodeInfo(signer, silent);
			byte[] encodedMessage = null;
			try
			{
				SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(0u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CMSG_SIGNER_ENCODE_INFO))));
				try
				{
					Marshal.StructureToPtr(cMSG_SIGNER_ENCODE_INFO, safeLocalAllocHandle.DangerousGetHandle(), fDeleteOld: false);
					X509Certificate2Collection x509Certificate2Collection = PkcsUtils.CreateBagOfCertificates(signer);
					SafeLocalAllocHandle safeLocalAllocHandle2 = PkcsUtils.CreateEncodedCertBlob(x509Certificate2Collection);
					cMSG_SIGNED_ENCODE_INFO.cSigners = 1u;
					cMSG_SIGNED_ENCODE_INFO.rgSigners = safeLocalAllocHandle.DangerousGetHandle();
					cMSG_SIGNED_ENCODE_INFO.cCertEncoded = (uint)x509Certificate2Collection.Count;
					if (x509Certificate2Collection.Count > 0)
					{
						cMSG_SIGNED_ENCODE_INFO.rgCertEncoded = safeLocalAllocHandle2.DangerousGetHandle();
					}
					safeCryptMsgHandle = ((string.Compare(ContentInfo.ContentType.Value, "1.2.840.113549.1.7.1", StringComparison.OrdinalIgnoreCase) != 0) ? CAPI.CryptMsgOpenToEncode(65537u, Detached ? 4u : 0u, 2u, new IntPtr(&cMSG_SIGNED_ENCODE_INFO), ContentInfo.ContentType.Value, IntPtr.Zero) : CAPI.CryptMsgOpenToEncode(65537u, Detached ? 4u : 0u, 2u, new IntPtr(&cMSG_SIGNED_ENCODE_INFO), IntPtr.Zero, IntPtr.Zero));
					if (safeCryptMsgHandle == null || safeCryptMsgHandle.IsInvalid)
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					if (ContentInfo.Content.Length > 0 && !CAPISafe.CryptMsgUpdate(safeCryptMsgHandle, ContentInfo.pContent, (uint)ContentInfo.Content.Length, fFinal: true))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					encodedMessage = PkcsUtils.GetContent(safeCryptMsgHandle);
					safeCryptMsgHandle.Dispose();
					safeLocalAllocHandle2.Dispose();
				}
				finally
				{
					Marshal.DestroyStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CMSG_SIGNER_ENCODE_INFO));
					safeLocalAllocHandle.Dispose();
				}
			}
			finally
			{
				cMSG_SIGNER_ENCODE_INFO.Dispose();
			}
			safeCryptMsgHandle = OpenToDecode(encodedMessage, ContentInfo, Detached);
			if (m_safeCryptMsgHandle != null && !m_safeCryptMsgHandle.IsInvalid)
			{
				m_safeCryptMsgHandle.Dispose();
			}
			m_safeCryptMsgHandle = safeCryptMsgHandle;
			GC.KeepAlive(signer);
		}

		private void CoSign(CmsSigner signer, bool silent)
		{
			CAPIBase.CMSG_SIGNER_ENCODE_INFO cMSG_SIGNER_ENCODE_INFO = PkcsUtils.CreateSignerEncodeInfo(signer, silent);
			try
			{
				SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CMSG_SIGNER_ENCODE_INFO))));
				try
				{
					Marshal.StructureToPtr(cMSG_SIGNER_ENCODE_INFO, safeLocalAllocHandle.DangerousGetHandle(), fDeleteOld: false);
					if (!CAPI.CryptMsgControl(m_safeCryptMsgHandle, 0u, 6u, safeLocalAllocHandle.DangerousGetHandle()))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
				}
				finally
				{
					Marshal.DestroyStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CMSG_SIGNER_ENCODE_INFO));
					safeLocalAllocHandle.Dispose();
				}
			}
			finally
			{
				cMSG_SIGNER_ENCODE_INFO.Dispose();
			}
			PkcsUtils.AddCertsToMessage(m_safeCryptMsgHandle, Certificates, PkcsUtils.CreateBagOfCertificates(signer));
		}

		private static SafeCryptMsgHandle OpenToDecode(byte[] encodedMessage, ContentInfo contentInfo, bool detached)
		{
			SafeCryptMsgHandle safeCryptMsgHandle = CAPISafe.CryptMsgOpenToDecode(65537u, detached ? 4u : 0u, 0u, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			if (safeCryptMsgHandle == null || safeCryptMsgHandle.IsInvalid)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (!CAPISafe.CryptMsgUpdate(safeCryptMsgHandle, encodedMessage, (uint)encodedMessage.Length, fFinal: true))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			if (2 != PkcsUtils.GetMessageType(safeCryptMsgHandle))
			{
				throw new CryptographicException(-2146889724);
			}
			if (detached)
			{
				byte[] content = contentInfo.Content;
				if (content != null && content.Length > 0 && !CAPISafe.CryptMsgUpdate(safeCryptMsgHandle, content, (uint)content.Length, fFinal: true))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
			}
			return safeCryptMsgHandle;
		}

		private static void CheckSignatures(SignerInfoCollection signers, X509Certificate2Collection extraStore, bool verifySignatureOnly)
		{
			if (signers == null || signers.Count < 1)
			{
				throw new CryptographicException(-2146885618);
			}
			SignerInfoEnumerator enumerator = signers.GetEnumerator();
			while (enumerator.MoveNext())
			{
				SignerInfo current = enumerator.Current;
				current.CheckSignature(extraStore, verifySignatureOnly);
				if (current.CounterSignerInfos.Count > 0)
				{
					CheckSignatures(current.CounterSignerInfos, extraStore, verifySignatureOnly);
				}
			}
		}

		private static void CheckHashes(SignerInfoCollection signers)
		{
			if (signers == null || signers.Count < 1)
			{
				throw new CryptographicException(-2146885618);
			}
			SignerInfoEnumerator enumerator = signers.GetEnumerator();
			while (enumerator.MoveNext())
			{
				SignerInfo current = enumerator.Current;
				if (current.SignerIdentifier.Type == SubjectIdentifierType.NoSignature)
				{
					current.CheckHash();
				}
			}
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class SignerInfo
	{
		private X509Certificate2 m_certificate;

		private SubjectIdentifier m_signerIdentifier;

		private CryptographicAttributeObjectCollection m_signedAttributes;

		private CryptographicAttributeObjectCollection m_unsignedAttributes;

		private SignedCms m_signedCms;

		private SignerInfo m_parentSignerInfo;

		private byte[] m_encodedSignerInfo;

		private SafeLocalAllocHandle m_pbCmsgSignerInfo;

		private CAPIBase.CMSG_SIGNER_INFO m_cmsgSignerInfo;

		public int Version => (int)m_cmsgSignerInfo.dwVersion;

		public X509Certificate2 Certificate
		{
			get
			{
				if (m_certificate == null)
				{
					m_certificate = PkcsUtils.FindCertificate(SignerIdentifier, m_signedCms.Certificates);
				}
				return m_certificate;
			}
		}

		public SubjectIdentifier SignerIdentifier
		{
			get
			{
				if (m_signerIdentifier == null)
				{
					m_signerIdentifier = new SubjectIdentifier(m_cmsgSignerInfo);
				}
				return m_signerIdentifier;
			}
		}

		public Oid DigestAlgorithm => new Oid(m_cmsgSignerInfo.HashAlgorithm.pszObjId);

		public CryptographicAttributeObjectCollection SignedAttributes
		{
			get
			{
				if (m_signedAttributes == null)
				{
					m_signedAttributes = new CryptographicAttributeObjectCollection(m_cmsgSignerInfo.AuthAttrs);
				}
				return m_signedAttributes;
			}
		}

		public CryptographicAttributeObjectCollection UnsignedAttributes
		{
			get
			{
				if (m_unsignedAttributes == null)
				{
					m_unsignedAttributes = new CryptographicAttributeObjectCollection(m_cmsgSignerInfo.UnauthAttrs);
				}
				return m_unsignedAttributes;
			}
		}

		public SignerInfoCollection CounterSignerInfos
		{
			get
			{
				if (m_parentSignerInfo != null)
				{
					return new SignerInfoCollection();
				}
				return new SignerInfoCollection(m_signedCms, this);
			}
		}

		private SignerInfo()
		{
		}

		internal SignerInfo(SignedCms signedCms, SafeLocalAllocHandle pbCmsgSignerInfo)
		{
			m_signedCms = signedCms;
			m_parentSignerInfo = null;
			m_encodedSignerInfo = null;
			m_pbCmsgSignerInfo = pbCmsgSignerInfo;
			m_cmsgSignerInfo = (CAPIBase.CMSG_SIGNER_INFO)Marshal.PtrToStructure(pbCmsgSignerInfo.DangerousGetHandle(), typeof(CAPIBase.CMSG_SIGNER_INFO));
		}

		internal unsafe SignerInfo(SignedCms signedCms, SignerInfo parentSignerInfo, byte[] encodedSignerInfo)
		{
			uint cbDecodedValue = 0u;
			SafeLocalAllocHandle decodedValue = SafeLocalAllocHandle.InvalidHandle;
			fixed (byte* value = &encodedSignerInfo[0])
			{
				if (!CAPI.DecodeObject(new IntPtr(500L), new IntPtr(value), (uint)encodedSignerInfo.Length, out decodedValue, out cbDecodedValue))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
			}
			m_signedCms = signedCms;
			m_parentSignerInfo = parentSignerInfo;
			m_encodedSignerInfo = (byte[])encodedSignerInfo.Clone();
			m_pbCmsgSignerInfo = decodedValue;
			m_cmsgSignerInfo = (CAPIBase.CMSG_SIGNER_INFO)Marshal.PtrToStructure(decodedValue.DangerousGetHandle(), typeof(CAPIBase.CMSG_SIGNER_INFO));
		}

		public void ComputeCounterSignature()
		{
			ComputeCounterSignature(new CmsSigner((m_signedCms.Version != 2) ? SubjectIdentifierType.IssuerAndSerialNumber : SubjectIdentifierType.SubjectKeyIdentifier));
		}

		public void ComputeCounterSignature(CmsSigner signer)
		{
			if (m_parentSignerInfo != null)
			{
				throw new CryptographicException(-2147483647);
			}
			if (signer == null)
			{
				throw new ArgumentNullException("signer");
			}
			if (signer.Certificate == null)
			{
				signer.Certificate = PkcsUtils.SelectSignerCertificate();
			}
			if (!signer.Certificate.HasPrivateKey)
			{
				throw new CryptographicException(-2146893811);
			}
			CounterSign(signer);
		}

		public void RemoveCounterSignature(int index)
		{
			if (m_parentSignerInfo != null)
			{
				throw new CryptographicException(-2147483647);
			}
			RemoveCounterSignature(PkcsUtils.GetSignerIndex(m_signedCms.GetCryptMsgHandle(), this, 0), index);
		}

		public void RemoveCounterSignature(SignerInfo counterSignerInfo)
		{
			if (m_parentSignerInfo != null)
			{
				throw new CryptographicException(-2147483647);
			}
			if (counterSignerInfo == null)
			{
				throw new ArgumentNullException("counterSignerInfo");
			}
			CryptographicAttributeObjectEnumerator enumerator = UnsignedAttributes.GetEnumerator();
			while (enumerator.MoveNext())
			{
				CryptographicAttributeObject current = enumerator.Current;
				if (string.Compare(current.Oid.Value, "1.2.840.113549.1.9.6", StringComparison.OrdinalIgnoreCase) != 0)
				{
					continue;
				}
				for (int i = 0; i < current.Values.Count; i++)
				{
					AsnEncodedData asnEncodedData = current.Values[i];
					SignerInfo signerInfo = new SignerInfo(m_signedCms, m_parentSignerInfo, asnEncodedData.RawData);
					if (counterSignerInfo.SignerIdentifier.Type == SubjectIdentifierType.IssuerAndSerialNumber && signerInfo.SignerIdentifier.Type == SubjectIdentifierType.IssuerAndSerialNumber)
					{
						X509IssuerSerial x509IssuerSerial = (X509IssuerSerial)counterSignerInfo.SignerIdentifier.Value;
						X509IssuerSerial x509IssuerSerial2 = (X509IssuerSerial)signerInfo.SignerIdentifier.Value;
						if (string.Compare(x509IssuerSerial.IssuerName, x509IssuerSerial2.IssuerName, StringComparison.OrdinalIgnoreCase) == 0 && string.Compare(x509IssuerSerial.SerialNumber, x509IssuerSerial2.SerialNumber, StringComparison.OrdinalIgnoreCase) == 0)
						{
							RemoveCounterSignature(PkcsUtils.GetSignerIndex(m_signedCms.GetCryptMsgHandle(), this, 0), i);
							return;
						}
					}
					else if (counterSignerInfo.SignerIdentifier.Type == SubjectIdentifierType.SubjectKeyIdentifier && signerInfo.SignerIdentifier.Type == SubjectIdentifierType.SubjectKeyIdentifier)
					{
						string strA = counterSignerInfo.SignerIdentifier.Value as string;
						string strB = signerInfo.SignerIdentifier.Value as string;
						if (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0)
						{
							RemoveCounterSignature(PkcsUtils.GetSignerIndex(m_signedCms.GetCryptMsgHandle(), this, 0), i);
							return;
						}
					}
				}
			}
			throw new CryptographicException(-2146889714);
		}

		public void CheckSignature(bool verifySignatureOnly)
		{
			CheckSignature(new X509Certificate2Collection(), verifySignatureOnly);
		}

		public void CheckSignature(X509Certificate2Collection extraStore, bool verifySignatureOnly)
		{
			if (extraStore == null)
			{
				throw new ArgumentNullException("extraStore");
			}
			X509Certificate2 x509Certificate = Certificate;
			if (x509Certificate == null)
			{
				x509Certificate = PkcsUtils.FindCertificate(SignerIdentifier, extraStore);
				if (x509Certificate == null)
				{
					throw new CryptographicException(-2146889714);
				}
			}
			Verify(extraStore, x509Certificate, verifySignatureOnly);
		}

		public unsafe void CheckHash()
		{
			int size = Marshal.SizeOf(typeof(CAPIBase.CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA));
			CAPIBase.CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA cMSG_CTRL_VERIFY_SIGNATURE_EX_PARA = new CAPIBase.CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA(size)
			{
				dwSignerType = 4u,
				dwSignerIndex = (uint)PkcsUtils.GetSignerIndex(m_signedCms.GetCryptMsgHandle(), this, 0)
			};
			if (!CAPI.CryptMsgControl(m_signedCms.GetCryptMsgHandle(), 0u, 19u, new IntPtr(&cMSG_CTRL_VERIFY_SIGNATURE_EX_PARA)))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}

		internal CAPIBase.CMSG_SIGNER_INFO GetCmsgSignerInfo()
		{
			return m_cmsgSignerInfo;
		}

		private void CounterSign(CmsSigner signer)
		{
			CspParameters parameters = new CspParameters();
			if (!System.Security.Cryptography.X509Certificates.X509Utils.GetPrivateKeyInfo(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(signer.Certificate), ref parameters))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			KeyContainerPermission keyContainerPermission = new KeyContainerPermission(KeyContainerPermissionFlags.NoFlags);
			KeyContainerPermissionAccessEntry accessEntry = new KeyContainerPermissionAccessEntry(parameters, KeyContainerPermissionFlags.Open | KeyContainerPermissionFlags.Sign);
			keyContainerPermission.AccessEntries.Add(accessEntry);
			keyContainerPermission.Demand();
			uint signerIndex = (uint)PkcsUtils.GetSignerIndex(m_signedCms.GetCryptMsgHandle(), this, 0);
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CMSG_SIGNER_ENCODE_INFO))));
			CAPIBase.CMSG_SIGNER_ENCODE_INFO cMSG_SIGNER_ENCODE_INFO = PkcsUtils.CreateSignerEncodeInfo(signer);
			try
			{
				Marshal.StructureToPtr(cMSG_SIGNER_ENCODE_INFO, safeLocalAllocHandle.DangerousGetHandle(), fDeleteOld: false);
				if (!CAPI.CryptMsgCountersign(m_signedCms.GetCryptMsgHandle(), signerIndex, 1u, safeLocalAllocHandle.DangerousGetHandle()))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				m_signedCms.ReopenToDecode();
			}
			finally
			{
				Marshal.DestroyStructure(safeLocalAllocHandle.DangerousGetHandle(), typeof(CAPIBase.CMSG_SIGNER_ENCODE_INFO));
				safeLocalAllocHandle.Dispose();
				cMSG_SIGNER_ENCODE_INFO.Dispose();
			}
			PkcsUtils.AddCertsToMessage(m_signedCms.GetCryptMsgHandle(), m_signedCms.Certificates, PkcsUtils.CreateBagOfCertificates(signer));
		}

		private unsafe void Verify(X509Certificate2Collection extraStore, X509Certificate2 certificate, bool verifySignatureOnly)
		{
			SafeLocalAllocHandle safeLocalAllocHandle = SafeLocalAllocHandle.InvalidHandle;
			CAPIBase.CERT_CONTEXT cERT_CONTEXT = (CAPIBase.CERT_CONTEXT)Marshal.PtrToStructure(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate).DangerousGetHandle(), typeof(CAPIBase.CERT_CONTEXT));
			IntPtr intPtr = new IntPtr((long)cERT_CONTEXT.pCertInfo + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_INFO), "SubjectPublicKeyInfo"));
			IntPtr intPtr2 = new IntPtr((long)intPtr + (long)Marshal.OffsetOf(typeof(CAPIBase.CERT_PUBLIC_KEY_INFO), "Algorithm"));
			IntPtr intPtr3 = new IntPtr((long)intPtr2 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPT_ALGORITHM_IDENTIFIER), "Parameters"));
			IntPtr pvKey = Marshal.ReadIntPtr(intPtr2);
			if (CAPI.CryptFindOIDInfo(1u, pvKey, 3u).Algid == 8704)
			{
				bool flag = false;
				IntPtr ptr = new IntPtr((long)intPtr3 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "cbData"));
				IntPtr ptr2 = new IntPtr((long)intPtr3 + (long)Marshal.OffsetOf(typeof(CAPIBase.CRYPTOAPI_BLOB), "pbData"));
				if (Marshal.ReadInt32(ptr) == 0)
				{
					flag = true;
				}
				else if (Marshal.ReadIntPtr(ptr2) == IntPtr.Zero)
				{
					flag = true;
				}
				else
				{
					IntPtr ptr3 = Marshal.ReadIntPtr(ptr2);
					if (Marshal.ReadInt32(ptr3) == 5)
					{
						flag = true;
					}
				}
				if (flag)
				{
					SafeCertChainHandle ppChainContext = SafeCertChainHandle.InvalidHandle;
					System.Security.Cryptography.X509Certificates.X509Utils.BuildChain(new IntPtr(0L), System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), null, null, null, X509RevocationMode.NoCheck, X509RevocationFlag.ExcludeRoot, DateTime.Now, new TimeSpan(0, 0, 0), ref ppChainContext);
					ppChainContext.Dispose();
					uint pcbData = 0u;
					if (!CAPISafe.CertGetCertificateContextProperty(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), 22u, safeLocalAllocHandle, ref pcbData))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}
					if (pcbData != 0)
					{
						safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(pcbData));
						if (!CAPISafe.CertGetCertificateContextProperty(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), 22u, safeLocalAllocHandle, ref pcbData))
						{
							throw new CryptographicException(Marshal.GetLastWin32Error());
						}
						Marshal.WriteInt32(ptr, (int)pcbData);
						Marshal.WriteIntPtr(ptr2, safeLocalAllocHandle.DangerousGetHandle());
					}
				}
			}
			if (m_parentSignerInfo == null)
			{
				if (!CAPI.CryptMsgControl(m_signedCms.GetCryptMsgHandle(), 0u, 1u, cERT_CONTEXT.pCertInfo))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
			}
			else
			{
				int num = -1;
				int num2 = 0;
				SafeLocalAllocHandle pvData;
				while (true)
				{
					try
					{
						num = PkcsUtils.GetSignerIndex(m_signedCms.GetCryptMsgHandle(), m_parentSignerInfo, num + 1);
					}
					catch (CryptographicException)
					{
						if (num2 == 0)
						{
							throw;
						}
						throw new CryptographicException(num2);
					}
					uint cbData = 0u;
					pvData = SafeLocalAllocHandle.InvalidHandle;
					PkcsUtils.GetParam(m_signedCms.GetCryptMsgHandle(), 28u, (uint)num, out pvData, out cbData);
					if (cbData == 0)
					{
						num2 = -2146885618;
						continue;
					}
					try
					{
						fixed (byte* value = m_encodedSignerInfo)
						{
							if (!CAPISafe.CryptMsgVerifyCountersignatureEncoded(IntPtr.Zero, 65537u, pvData.DangerousGetHandle(), cbData, new IntPtr(value), (uint)m_encodedSignerInfo.Length, cERT_CONTEXT.pCertInfo))
							{
								num2 = Marshal.GetLastWin32Error();
								continue;
							}
						}
					}
					finally
					{
					}
					break;
				}
				pvData.Dispose();
			}
			if (!verifySignatureOnly)
			{
				int num3 = VerifyCertificate(certificate, extraStore);
				if (num3 != 0)
				{
					throw new CryptographicException(num3);
				}
			}
			safeLocalAllocHandle.Dispose();
		}

		private unsafe void RemoveCounterSignature(int parentIndex, int childIndex)
		{
			if (parentIndex < 0)
			{
				throw new ArgumentOutOfRangeException("parentIndex");
			}
			if (childIndex < 0)
			{
				throw new ArgumentOutOfRangeException("childIndex");
			}
			uint cbData = 0u;
			SafeLocalAllocHandle pvData = SafeLocalAllocHandle.InvalidHandle;
			uint cbData2 = 0u;
			SafeLocalAllocHandle pvData2 = SafeLocalAllocHandle.InvalidHandle;
			uint num = 0u;
			uint num2 = 0u;
			IntPtr zero = IntPtr.Zero;
			SafeCryptMsgHandle cryptMsgHandle = m_signedCms.GetCryptMsgHandle();
			if (PkcsUtils.CmsSupported())
			{
				PkcsUtils.GetParam(cryptMsgHandle, 39u, (uint)parentIndex, out pvData, out cbData);
				CAPIBase.CMSG_CMS_SIGNER_INFO cMSG_CMS_SIGNER_INFO = (CAPIBase.CMSG_CMS_SIGNER_INFO)Marshal.PtrToStructure(pvData.DangerousGetHandle(), typeof(CAPIBase.CMSG_CMS_SIGNER_INFO));
				num2 = cMSG_CMS_SIGNER_INFO.UnauthAttrs.cAttr;
				zero = new IntPtr((long)cMSG_CMS_SIGNER_INFO.UnauthAttrs.rgAttr);
			}
			else
			{
				PkcsUtils.GetParam(cryptMsgHandle, 6u, (uint)parentIndex, out pvData2, out cbData2);
				CAPIBase.CMSG_SIGNER_INFO cMSG_SIGNER_INFO = (CAPIBase.CMSG_SIGNER_INFO)Marshal.PtrToStructure(pvData2.DangerousGetHandle(), typeof(CAPIBase.CMSG_SIGNER_INFO));
				num2 = cMSG_SIGNER_INFO.UnauthAttrs.cAttr;
				zero = new IntPtr((long)cMSG_SIGNER_INFO.UnauthAttrs.rgAttr);
			}
			for (num = 0u; num < num2; num++)
			{
				CAPIBase.CRYPT_ATTRIBUTE cRYPT_ATTRIBUTE = (CAPIBase.CRYPT_ATTRIBUTE)Marshal.PtrToStructure(zero, typeof(CAPIBase.CRYPT_ATTRIBUTE));
				if (string.Compare(cRYPT_ATTRIBUTE.pszObjId, "1.2.840.113549.1.9.6", StringComparison.OrdinalIgnoreCase) == 0 && cRYPT_ATTRIBUTE.cValue != 0)
				{
					if (childIndex < (int)cRYPT_ATTRIBUTE.cValue)
					{
						CAPIBase.CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA cMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA = new CAPIBase.CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA(Marshal.SizeOf(typeof(CAPIBase.CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA)))
						{
							dwSignerIndex = (uint)parentIndex,
							dwUnauthAttrIndex = num
						};
						if (!CAPI.CryptMsgControl(cryptMsgHandle, 0u, 9u, new IntPtr(&cMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA)))
						{
							throw new CryptographicException(Marshal.GetLastWin32Error());
						}
						if (cRYPT_ATTRIBUTE.cValue <= 1)
						{
							return;
						}
						try
						{
							uint num3 = (uint)((cRYPT_ATTRIBUTE.cValue - 1) * Marshal.SizeOf(typeof(CAPIBase.CRYPTOAPI_BLOB)));
							SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(64u, new IntPtr(num3));
							CAPIBase.CRYPTOAPI_BLOB* ptr = (CAPIBase.CRYPTOAPI_BLOB*)(void*)cRYPT_ATTRIBUTE.rgValue;
							CAPIBase.CRYPTOAPI_BLOB* ptr2 = (CAPIBase.CRYPTOAPI_BLOB*)(void*)safeLocalAllocHandle.DangerousGetHandle();
							int num4 = 0;
							while (num4 < (int)cRYPT_ATTRIBUTE.cValue)
							{
								if (num4 != childIndex)
								{
									*ptr2 = *ptr;
								}
								num4++;
								ptr++;
								ptr2++;
							}
							CAPIBase.CRYPT_ATTRIBUTE cRYPT_ATTRIBUTE2 = default(CAPIBase.CRYPT_ATTRIBUTE);
							cRYPT_ATTRIBUTE2.pszObjId = cRYPT_ATTRIBUTE.pszObjId;
							cRYPT_ATTRIBUTE2.cValue = cRYPT_ATTRIBUTE.cValue - 1;
							cRYPT_ATTRIBUTE2.rgValue = safeLocalAllocHandle.DangerousGetHandle();
							SafeLocalAllocHandle safeLocalAllocHandle2 = CAPI.LocalAlloc(64u, new IntPtr(Marshal.SizeOf(typeof(CAPIBase.CRYPT_ATTRIBUTE))));
							Marshal.StructureToPtr(cRYPT_ATTRIBUTE2, safeLocalAllocHandle2.DangerousGetHandle(), fDeleteOld: false);
							byte[] encodedData;
							try
							{
								if (!CAPI.EncodeObject(new IntPtr(22L), safeLocalAllocHandle2.DangerousGetHandle(), out encodedData))
								{
									throw new CryptographicException(Marshal.GetLastWin32Error());
								}
							}
							finally
							{
								Marshal.DestroyStructure(safeLocalAllocHandle2.DangerousGetHandle(), typeof(CAPIBase.CRYPT_ATTRIBUTE));
								safeLocalAllocHandle2.Dispose();
							}
							try
							{
								fixed (byte* value = &encodedData[0])
								{
									CAPIBase.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA cMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA = new CAPIBase.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA(Marshal.SizeOf(typeof(CAPIBase.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA)))
									{
										dwSignerIndex = (uint)parentIndex,
										blob = 
										{
											cbData = (uint)encodedData.Length,
											pbData = new IntPtr(value)
										}
									};
									if (!CAPI.CryptMsgControl(cryptMsgHandle, 0u, 8u, new IntPtr(&cMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA)))
									{
										throw new CryptographicException(Marshal.GetLastWin32Error());
									}
								}
							}
							finally
							{
							}
							safeLocalAllocHandle.Dispose();
							return;
						}
						catch (CryptographicException)
						{
							if (CAPI.EncodeObject(new IntPtr(22L), zero, out var encodedData2))
							{
								fixed (byte* value2 = &encodedData2[0])
								{
									CAPIBase.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA cMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA2 = new CAPIBase.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA(Marshal.SizeOf(typeof(CAPIBase.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA)))
									{
										dwSignerIndex = (uint)parentIndex,
										blob = 
										{
											cbData = (uint)encodedData2.Length,
											pbData = new IntPtr(value2)
										}
									};
									CAPI.CryptMsgControl(cryptMsgHandle, 0u, 8u, new IntPtr(&cMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA2));
								}
							}
							throw;
						}
					}
					childIndex -= (int)cRYPT_ATTRIBUTE.cValue;
				}
				zero = new IntPtr((long)zero + Marshal.SizeOf(typeof(CAPIBase.CRYPT_ATTRIBUTE)));
			}
			if (pvData != null && !pvData.IsInvalid)
			{
				pvData.Dispose();
			}
			if (pvData2 != null && !pvData2.IsInvalid)
			{
				pvData2.Dispose();
			}
			throw new CryptographicException(-2146885618);
		}

		private unsafe static int VerifyCertificate(X509Certificate2 certificate, X509Certificate2Collection extraStore)
		{
			int result = default(int);
			int num = System.Security.Cryptography.X509Certificates.X509Utils.VerifyCertificate(System.Security.Cryptography.X509Certificates.X509Utils.GetCertContext(certificate), null, null, X509RevocationMode.Online, X509RevocationFlag.ExcludeRoot, DateTime.Now, new TimeSpan(0, 0, 0), extraStore, new IntPtr(1L), new IntPtr(&result));
			if (num != 0)
			{
				return result;
			}
			X509ExtensionEnumerator enumerator = certificate.Extensions.GetEnumerator();
			while (enumerator.MoveNext())
			{
				X509Extension current = enumerator.Current;
				if (string.Compare(current.Oid.Value, "2.5.29.15", StringComparison.OrdinalIgnoreCase) == 0)
				{
					X509KeyUsageExtension x509KeyUsageExtension = new X509KeyUsageExtension();
					x509KeyUsageExtension.CopyFrom(current);
					if ((x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0 && (x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.NonRepudiation) == 0)
					{
						num = -2146762480;
						break;
					}
				}
			}
			return num;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class SignerInfoCollection : ICollection, IEnumerable
	{
		private SignerInfo[] m_signerInfos;

		public SignerInfo this[int index]
		{
			get
			{
				if (index < 0 || index >= m_signerInfos.Length)
				{
					throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
				}
				return m_signerInfos[index];
			}
		}

		public int Count => m_signerInfos.Length;

		public bool IsSynchronized => false;

		public object SyncRoot => this;

		internal SignerInfoCollection()
		{
			m_signerInfos = new SignerInfo[0];
		}

		internal unsafe SignerInfoCollection(SignedCms signedCms)
		{
			uint num = 0u;
			uint num2 = (uint)Marshal.SizeOf(typeof(uint));
			SafeCryptMsgHandle cryptMsgHandle = signedCms.GetCryptMsgHandle();
			if (!CAPISafe.CryptMsgGetParam(cryptMsgHandle, 5u, 0u, new IntPtr(&num), new IntPtr(&num2)))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			SignerInfo[] array = new SignerInfo[num];
			for (int i = 0; i < num; i++)
			{
				uint num3 = 0u;
				if (!CAPISafe.CryptMsgGetParam(cryptMsgHandle, 6u, (uint)i, IntPtr.Zero, new IntPtr(&num3)))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(0u, new IntPtr(num3));
				if (!CAPISafe.CryptMsgGetParam(cryptMsgHandle, 6u, (uint)i, safeLocalAllocHandle, new IntPtr(&num3)))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
				array[i] = new SignerInfo(signedCms, safeLocalAllocHandle);
			}
			m_signerInfos = array;
		}

		internal SignerInfoCollection(SignedCms signedCms, SignerInfo signerInfo)
		{
			SignerInfo[] array = new SignerInfo[0];
			int num = 0;
			int num2 = 0;
			CryptographicAttributeObjectEnumerator enumerator = signerInfo.UnsignedAttributes.GetEnumerator();
			while (enumerator.MoveNext())
			{
				CryptographicAttributeObject current = enumerator.Current;
				if (current.Oid.Value == "1.2.840.113549.1.9.6")
				{
					num += current.Values.Count;
				}
			}
			array = new SignerInfo[num];
			CryptographicAttributeObjectEnumerator enumerator2 = signerInfo.UnsignedAttributes.GetEnumerator();
			while (enumerator2.MoveNext())
			{
				CryptographicAttributeObject current2 = enumerator2.Current;
				if (current2.Oid.Value == "1.2.840.113549.1.9.6")
				{
					for (int i = 0; i < current2.Values.Count; i++)
					{
						AsnEncodedData asnEncodedData = current2.Values[i];
						array[num2++] = new SignerInfo(signedCms, signerInfo, asnEncodedData.RawData);
					}
				}
			}
			m_signerInfos = array;
		}

		public SignerInfoEnumerator GetEnumerator()
		{
			return new SignerInfoEnumerator(this);
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return new SignerInfoEnumerator(this);
		}

		public void CopyTo(Array array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			if (array.Rank != 1)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Arg_RankMultiDimNotSupported"));
			}
			if (index < 0 || index >= array.Length)
			{
				throw new ArgumentOutOfRangeException("index", SecurityResources.GetResourceString("ArgumentOutOfRange_Index"));
			}
			if (index + Count > array.Length)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Argument_InvalidOffLen"));
			}
			for (int i = 0; i < Count; i++)
			{
				array.SetValue(this[i], index);
				index++;
			}
		}

		public void CopyTo(SignerInfo[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class SignerInfoEnumerator : IEnumerator
	{
		private SignerInfoCollection m_signerInfos;

		private int m_current;

		public SignerInfo Current => m_signerInfos[m_current];

		object IEnumerator.Current => m_signerInfos[m_current];

		private SignerInfoEnumerator()
		{
		}

		internal SignerInfoEnumerator(SignerInfoCollection signerInfos)
		{
			m_signerInfos = signerInfos;
			m_current = -1;
		}

		public bool MoveNext()
		{
			if (m_current == m_signerInfos.Count - 1)
			{
				return false;
			}
			m_current++;
			return true;
		}

		public void Reset()
		{
			m_current = -1;
		}
	}
}
namespace System.Security.Cryptography.X509Certificates
{
	internal class X509Utils
	{
		private static readonly char[] hexValues = new char[16]
		{
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'A', 'B', 'C', 'D', 'E', 'F'
		};

		private X509Utils()
		{
		}

		internal static uint MapRevocationFlags(X509RevocationMode revocationMode, X509RevocationFlag revocationFlag)
		{
			uint num = 0u;
			switch (revocationMode)
			{
			case X509RevocationMode.NoCheck:
				return num;
			case X509RevocationMode.Offline:
				num |= 0x80000000u;
				break;
			}
			return revocationFlag switch
			{
				X509RevocationFlag.EndCertificateOnly => num | 0x10000000u, 
				X509RevocationFlag.EntireChain => num | 0x20000000u, 
				_ => num | 0x40000000u, 
			};
		}

		internal static string EncodeHexString(byte[] sArray)
		{
			return EncodeHexString(sArray, 0u, (uint)sArray.Length);
		}

		internal static string EncodeHexString(byte[] sArray, uint start, uint end)
		{
			string result = null;
			if (sArray != null)
			{
				char[] array = new char[(end - start) * 2];
				uint num = start;
				uint num2 = 0u;
				for (; num < end; num++)
				{
					uint num3 = (uint)((sArray[num] & 0xF0) >> 4);
					array[num2++] = hexValues[num3];
					num3 = sArray[num] & 0xFu;
					array[num2++] = hexValues[num3];
				}
				result = new string(array);
			}
			return result;
		}

		internal static string EncodeHexStringFromInt(byte[] sArray)
		{
			return EncodeHexStringFromInt(sArray, 0u, (uint)sArray.Length);
		}

		internal static string EncodeHexStringFromInt(byte[] sArray, uint start, uint end)
		{
			string result = null;
			if (sArray != null)
			{
				char[] array = new char[(end - start) * 2];
				uint num = end;
				uint num2 = 0u;
				while (num-- > start)
				{
					uint num3 = (uint)(sArray[num] & 0xF0) >> 4;
					array[num2++] = hexValues[num3];
					num3 = sArray[num] & 0xFu;
					array[num2++] = hexValues[num3];
				}
				result = new string(array);
			}
			return result;
		}

		internal static byte HexToByte(char val)
		{
			if (val <= '9' && val >= '0')
			{
				return (byte)(val - 48);
			}
			if (val >= 'a' && val <= 'f')
			{
				return (byte)(val - 97 + 10);
			}
			if (val >= 'A' && val <= 'F')
			{
				return (byte)(val - 65 + 10);
			}
			return byte.MaxValue;
		}

		internal static byte[] DecodeHexString(string s)
		{
			string text = System.Security.Cryptography.Xml.Utils.DiscardWhiteSpaces(s);
			uint num = (uint)text.Length / 2u;
			byte[] array = new byte[num];
			int num2 = 0;
			for (int i = 0; i < num; i++)
			{
				array[i] = (byte)((HexToByte(text[num2]) << 4) | HexToByte(text[num2 + 1]));
				num2 += 2;
			}
			return array;
		}

		internal unsafe static bool MemEqual(byte* pbBuf1, uint cbBuf1, byte* pbBuf2, uint cbBuf2)
		{
			if (cbBuf1 != cbBuf2)
			{
				return false;
			}
			while (cbBuf1-- != 0)
			{
				if (*(pbBuf1++) != *(pbBuf2++))
				{
					return false;
				}
			}
			return true;
		}

		internal static SafeLocalAllocHandle StringToAnsiPtr(string s)
		{
			byte[] array = new byte[s.Length + 1];
			Encoding.ASCII.GetBytes(s, 0, s.Length, array, 0);
			SafeLocalAllocHandle safeLocalAllocHandle = CAPI.LocalAlloc(0u, new IntPtr(array.Length));
			Marshal.Copy(array, 0, safeLocalAllocHandle.DangerousGetHandle(), array.Length);
			return safeLocalAllocHandle;
		}

		internal static System.Security.Cryptography.SafeCertContextHandle GetCertContext(X509Certificate2 certificate)
		{
			System.Security.Cryptography.SafeCertContextHandle result = CAPI.CertDuplicateCertificateContext(certificate.Handle);
			GC.KeepAlive(certificate);
			return result;
		}

		internal static bool GetPrivateKeyInfo(System.Security.Cryptography.SafeCertContextHandle safeCertContext, ref CspParameters parameters)
		{
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			uint pcbData = 0u;
			if (!CAPISafe.CertGetCertificateContextProperty(safeCertContext, 2u, invalidHandle, ref pcbData))
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if (lastWin32Error == -2146885628)
				{
					return false;
				}
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			invalidHandle = CAPI.LocalAlloc(0u, new IntPtr(pcbData));
			if (!CAPISafe.CertGetCertificateContextProperty(safeCertContext, 2u, invalidHandle, ref pcbData))
			{
				int lastWin32Error2 = Marshal.GetLastWin32Error();
				if (lastWin32Error2 == -2146885628)
				{
					return false;
				}
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			CAPIBase.CRYPT_KEY_PROV_INFO cRYPT_KEY_PROV_INFO = (CAPIBase.CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(invalidHandle.DangerousGetHandle(), typeof(CAPIBase.CRYPT_KEY_PROV_INFO));
			parameters.ProviderName = cRYPT_KEY_PROV_INFO.pwszProvName;
			parameters.KeyContainerName = cRYPT_KEY_PROV_INFO.pwszContainerName;
			parameters.ProviderType = (int)cRYPT_KEY_PROV_INFO.dwProvType;
			parameters.KeyNumber = (int)cRYPT_KEY_PROV_INFO.dwKeySpec;
			parameters.Flags = (((cRYPT_KEY_PROV_INFO.dwFlags & 0x20) == 32) ? CspProviderFlags.UseMachineKeyStore : CspProviderFlags.NoFlags);
			invalidHandle.Dispose();
			return true;
		}

		internal static System.Security.Cryptography.SafeCertStoreHandle ExportToMemoryStore(X509Certificate2Collection collection)
		{
			StorePermission storePermission = new StorePermission(StorePermissionFlags.AllFlags);
			storePermission.Assert();
			System.Security.Cryptography.SafeCertStoreHandle invalidHandle = System.Security.Cryptography.SafeCertStoreHandle.InvalidHandle;
			invalidHandle = CAPI.CertOpenStore(new IntPtr(2L), 65537u, IntPtr.Zero, 8704u, null);
			if (invalidHandle == null || invalidHandle.IsInvalid)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			X509Certificate2Enumerator enumerator = collection.GetEnumerator();
			while (enumerator.MoveNext())
			{
				X509Certificate2 current = enumerator.Current;
				if (!CAPI.CertAddCertificateLinkToStore(invalidHandle, GetCertContext(current), 4u, System.Security.Cryptography.SafeCertContextHandle.InvalidHandle))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}
			}
			return invalidHandle;
		}

		internal static uint OidToAlgId(string value)
		{
			SafeLocalAllocHandle pvKey = StringToAnsiPtr(value);
			return CAPI.CryptFindOIDInfo(1u, pvKey, 0u).Algid;
		}

		internal static bool IsSelfSigned(X509Chain chain)
		{
			X509ChainElementCollection chainElements = chain.ChainElements;
			if (chainElements.Count != 1)
			{
				return false;
			}
			X509Certificate2 certificate = chainElements[0].Certificate;
			if (string.Compare(certificate.SubjectName.Name, certificate.IssuerName.Name, StringComparison.OrdinalIgnoreCase) == 0)
			{
				return true;
			}
			return false;
		}

		internal static SafeLocalAllocHandle CopyOidsToUnmanagedMemory(OidCollection oids)
		{
			SafeLocalAllocHandle invalidHandle = SafeLocalAllocHandle.InvalidHandle;
			if (oids == null || oids.Count == 0)
			{
				return invalidHandle;
			}
			int num = oids.Count * Marshal.SizeOf(typeof(IntPtr));
			int num2 = 0;
			OidEnumerator enumerator = oids.GetEnumerator();
			while (enumerator.MoveNext())
			{
				Oid current = enumerator.Current;
				num2 += current.Value.Length + 1;
			}
			invalidHandle = CAPI.LocalAlloc(64u, new IntPtr((uint)(num + num2)));
			IntPtr intPtr = new IntPtr((long)invalidHandle.DangerousGetHandle() + num);
			for (int i = 0; i < oids.Count; i++)
			{
				Marshal.WriteIntPtr(new IntPtr((long)invalidHandle.DangerousGetHandle() + i * Marshal.SizeOf(typeof(IntPtr))), intPtr);
				byte[] bytes = Encoding.ASCII.GetBytes(oids[i].Value);
				Marshal.Copy(bytes, 0, intPtr, bytes.Length);
				intPtr = new IntPtr((long)intPtr + oids[i].Value.Length + 1);
			}
			return invalidHandle;
		}

		internal static X509Certificate2Collection GetCertificates(System.Security.Cryptography.SafeCertStoreHandle safeCertStoreHandle)
		{
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			IntPtr intPtr = CAPI.CertEnumCertificatesInStore(safeCertStoreHandle, IntPtr.Zero);
			while (intPtr != IntPtr.Zero)
			{
				X509Certificate2 certificate = new X509Certificate2(intPtr);
				x509Certificate2Collection.Add(certificate);
				intPtr = CAPI.CertEnumCertificatesInStore(safeCertStoreHandle, intPtr);
			}
			return x509Certificate2Collection;
		}

		internal unsafe static int BuildChain(IntPtr hChainEngine, System.Security.Cryptography.SafeCertContextHandle pCertContext, X509Certificate2Collection extraStore, OidCollection applicationPolicy, OidCollection certificatePolicy, X509RevocationMode revocationMode, X509RevocationFlag revocationFlag, DateTime verificationTime, TimeSpan timeout, ref SafeCertChainHandle ppChainContext)
		{
			if (pCertContext == null || pCertContext.IsInvalid)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_InvalidContextHandle"), "pCertContext");
			}
			System.Security.Cryptography.SafeCertStoreHandle hAdditionalStore = System.Security.Cryptography.SafeCertStoreHandle.InvalidHandle;
			if (extraStore != null && extraStore.Count > 0)
			{
				hAdditionalStore = ExportToMemoryStore(extraStore);
			}
			CAPIBase.CERT_CHAIN_PARA pChainPara = default(CAPIBase.CERT_CHAIN_PARA);
			pChainPara.cbSize = (uint)Marshal.SizeOf(pChainPara);
			SafeLocalAllocHandle safeLocalAllocHandle = SafeLocalAllocHandle.InvalidHandle;
			if (applicationPolicy != null && applicationPolicy.Count > 0)
			{
				pChainPara.RequestedUsage.dwType = 0u;
				pChainPara.RequestedUsage.Usage.cUsageIdentifier = (uint)applicationPolicy.Count;
				safeLocalAllocHandle = CopyOidsToUnmanagedMemory(applicationPolicy);
				pChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = safeLocalAllocHandle.DangerousGetHandle();
			}
			SafeLocalAllocHandle safeLocalAllocHandle2 = SafeLocalAllocHandle.InvalidHandle;
			if (certificatePolicy != null && certificatePolicy.Count > 0)
			{
				pChainPara.RequestedIssuancePolicy.dwType = 0u;
				pChainPara.RequestedIssuancePolicy.Usage.cUsageIdentifier = (uint)certificatePolicy.Count;
				safeLocalAllocHandle2 = CopyOidsToUnmanagedMemory(certificatePolicy);
				pChainPara.RequestedIssuancePolicy.Usage.rgpszUsageIdentifier = safeLocalAllocHandle2.DangerousGetHandle();
			}
			pChainPara.dwUrlRetrievalTimeout = (uint)timeout.Milliseconds;
			System.Runtime.InteropServices.ComTypes.FILETIME pTime = default(System.Runtime.InteropServices.ComTypes.FILETIME);
			*(long*)(&pTime) = verificationTime.ToFileTime();
			uint dwFlags = MapRevocationFlags(revocationMode, revocationFlag);
			if (!CAPISafe.CertGetCertificateChain(hChainEngine, pCertContext, ref pTime, hAdditionalStore, ref pChainPara, dwFlags, IntPtr.Zero, ref ppChainContext))
			{
				return Marshal.GetHRForLastWin32Error();
			}
			safeLocalAllocHandle.Dispose();
			safeLocalAllocHandle2.Dispose();
			return 0;
		}

		internal unsafe static int VerifyCertificate(System.Security.Cryptography.SafeCertContextHandle pCertContext, OidCollection applicationPolicy, OidCollection certificatePolicy, X509RevocationMode revocationMode, X509RevocationFlag revocationFlag, DateTime verificationTime, TimeSpan timeout, X509Certificate2Collection extraStore, IntPtr pszPolicy, IntPtr pdwErrorStatus)
		{
			if (pCertContext == null || pCertContext.IsInvalid)
			{
				throw new ArgumentException("pCertContext");
			}
			CAPIBase.CERT_CHAIN_POLICY_PARA pPolicyPara = new CAPIBase.CERT_CHAIN_POLICY_PARA(Marshal.SizeOf(typeof(CAPIBase.CERT_CHAIN_POLICY_PARA)));
			CAPIBase.CERT_CHAIN_POLICY_STATUS pPolicyStatus = new CAPIBase.CERT_CHAIN_POLICY_STATUS(Marshal.SizeOf(typeof(CAPIBase.CERT_CHAIN_POLICY_STATUS)));
			SafeCertChainHandle ppChainContext = SafeCertChainHandle.InvalidHandle;
			int num = BuildChain(new IntPtr(0L), pCertContext, extraStore, applicationPolicy, certificatePolicy, revocationMode, revocationFlag, verificationTime, timeout, ref ppChainContext);
			if (num != 0)
			{
				return num;
			}
			if (CAPISafe.CertVerifyCertificateChainPolicy(pszPolicy, ppChainContext, ref pPolicyPara, ref pPolicyStatus))
			{
				if (pdwErrorStatus != IntPtr.Zero)
				{
					*(uint*)(void*)pdwErrorStatus = pPolicyStatus.dwError;
				}
				if (pPolicyStatus.dwError != 0)
				{
					return 1;
				}
				return 0;
			}
			return Marshal.GetHRForLastWin32Error();
		}
	}
	public enum X509SelectionFlag
	{
		SingleSelection,
		MultiSelection
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class X509Certificate2UI
	{
		private X509Certificate2UI()
		{
		}

		public static void DisplayCertificate(X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				throw new ArgumentNullException("certificate");
			}
			DisplayX509Certificate(X509Utils.GetCertContext(certificate), IntPtr.Zero);
		}

		[SecurityPermission(SecurityAction.InheritanceDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public static void DisplayCertificate(X509Certificate2 certificate, IntPtr hwndParent)
		{
			if (certificate == null)
			{
				throw new ArgumentNullException("certificate");
			}
			DisplayX509Certificate(X509Utils.GetCertContext(certificate), hwndParent);
		}

		public static X509Certificate2Collection SelectFromCollection(X509Certificate2Collection certificates, string title, string message, X509SelectionFlag selectionFlag)
		{
			return SelectFromCollectionHelper(certificates, title, message, selectionFlag, IntPtr.Zero);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		[SecurityPermission(SecurityAction.InheritanceDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public static X509Certificate2Collection SelectFromCollection(X509Certificate2Collection certificates, string title, string message, X509SelectionFlag selectionFlag, IntPtr hwndParent)
		{
			return SelectFromCollectionHelper(certificates, title, message, selectionFlag, hwndParent);
		}

		private static void DisplayX509Certificate(System.Security.Cryptography.SafeCertContextHandle safeCertContext, IntPtr hwndParent)
		{
			if (safeCertContext.IsInvalid)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_InvalidHandle"), "safeCertContext");
			}
			int num = 0;
			CAPIBase.CRYPTUI_VIEWCERTIFICATE_STRUCTW cRYPTUI_VIEWCERTIFICATE_STRUCTW = new CAPIBase.CRYPTUI_VIEWCERTIFICATE_STRUCTW();
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.dwSize = (uint)Marshal.SizeOf(cRYPTUI_VIEWCERTIFICATE_STRUCTW);
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.hwndParent = hwndParent;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.dwFlags = 0u;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.szTitle = null;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.pCertContext = safeCertContext.DangerousGetHandle();
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.rgszPurposes = IntPtr.Zero;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.cPurposes = 0u;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.pCryptProviderData = IntPtr.Zero;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.fpCryptProviderDataTrustedUsage = false;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.idxSigner = 0u;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.idxCert = 0u;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.fCounterSigner = false;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.idxCounterSigner = 0u;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.cStores = 0u;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.rghStores = IntPtr.Zero;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.cPropSheetPages = 0u;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.rgPropSheetPages = IntPtr.Zero;
			cRYPTUI_VIEWCERTIFICATE_STRUCTW.nStartPage = 0u;
			if (!CAPI.CryptUIDlgViewCertificateW(cRYPTUI_VIEWCERTIFICATE_STRUCTW, IntPtr.Zero))
			{
				num = Marshal.GetLastWin32Error();
			}
			if (num != 0 && num != 1223)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}

		private static X509Certificate2Collection SelectFromCollectionHelper(X509Certificate2Collection certificates, string title, string message, X509SelectionFlag selectionFlag, IntPtr hwndParent)
		{
			if (certificates == null)
			{
				throw new ArgumentNullException("certificates");
			}
			if (selectionFlag < X509SelectionFlag.SingleSelection || selectionFlag > X509SelectionFlag.MultiSelection)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Arg_EnumIllegalVal"), "selectionFlag"));
			}
			StorePermission storePermission = new StorePermission(StorePermissionFlags.AllFlags);
			storePermission.Assert();
			System.Security.Cryptography.SafeCertStoreHandle safeCertStoreHandle = X509Utils.ExportToMemoryStore(certificates);
			System.Security.Cryptography.SafeCertStoreHandle invalidHandle = System.Security.Cryptography.SafeCertStoreHandle.InvalidHandle;
			invalidHandle = SelectFromStore(safeCertStoreHandle, title, message, selectionFlag, hwndParent);
			X509Certificate2Collection certificates2 = X509Utils.GetCertificates(invalidHandle);
			invalidHandle.Dispose();
			safeCertStoreHandle.Dispose();
			return certificates2;
		}

		private unsafe static System.Security.Cryptography.SafeCertStoreHandle SelectFromStore(System.Security.Cryptography.SafeCertStoreHandle safeSourceStoreHandle, string title, string message, X509SelectionFlag selectionFlags, IntPtr hwndParent)
		{
			int num = 0;
			System.Security.Cryptography.SafeCertStoreHandle safeCertStoreHandle = CAPI.CertOpenStore((IntPtr)2L, 65537u, IntPtr.Zero, 0u, null);
			if (safeCertStoreHandle == null || safeCertStoreHandle.IsInvalid)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			CAPIBase.CRYPTUI_SELECTCERTIFICATE_STRUCTW cRYPTUI_SELECTCERTIFICATE_STRUCTW = new CAPIBase.CRYPTUI_SELECTCERTIFICATE_STRUCTW();
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.dwSize = (uint)(int)Marshal.OffsetOf(typeof(CAPIBase.CRYPTUI_SELECTCERTIFICATE_STRUCTW), "hSelectedCertStore");
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.hwndParent = hwndParent;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.dwFlags = (uint)selectionFlags;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.szTitle = title;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.dwDontUseColumn = 0u;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.szDisplayString = message;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.pFilterCallback = IntPtr.Zero;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.pDisplayCallback = IntPtr.Zero;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.pvCallbackData = IntPtr.Zero;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.cDisplayStores = 1u;
			IntPtr intPtr = safeSourceStoreHandle.DangerousGetHandle();
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.rghDisplayStores = new IntPtr(&intPtr);
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.cStores = 0u;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.rghStores = IntPtr.Zero;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.cPropSheetPages = 0u;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.rgPropSheetPages = IntPtr.Zero;
			cRYPTUI_SELECTCERTIFICATE_STRUCTW.hSelectedCertStore = safeCertStoreHandle.DangerousGetHandle();
			System.Security.Cryptography.SafeCertContextHandle safeCertContextHandle = CAPI.CryptUIDlgSelectCertificateW(cRYPTUI_SELECTCERTIFICATE_STRUCTW);
			if (safeCertContextHandle != null && !safeCertContextHandle.IsInvalid)
			{
				System.Security.Cryptography.SafeCertContextHandle invalidHandle = System.Security.Cryptography.SafeCertContextHandle.InvalidHandle;
				if (!CAPI.CertAddCertificateContextToStore(safeCertStoreHandle, safeCertContextHandle, 7u, invalidHandle))
				{
					num = Marshal.GetLastWin32Error();
				}
			}
			if (num != 0)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
			return safeCertStoreHandle;
		}
	}
}
namespace System.Security.Cryptography.Xml
{
	[Serializable]
	internal enum CertUsageType
	{
		Verification,
		Decryption
	}
	internal class MyXmlDocument : XmlDocument
	{
		protected override XmlAttribute CreateDefaultAttribute(string prefix, string localName, string namespaceURI)
		{
			return CreateAttribute(prefix, localName, namespaceURI);
		}
	}
	internal class Utils
	{
		private static long? maxCharactersFromEntities = null;

		private static bool? s_allowAmbiguousReferenceTarget = null;

		private static bool? s_allowDetachedSignature = null;

		private static bool s_readRequireNCNameIdentifier = false;

		private static bool s_requireNCNameIdentifier = true;

		private static bool s_readMaxTransformsPerReference = false;

		private static long s_maxTransformsPerReference = 10L;

		private static bool s_readMaxReferencesPerSignedInfo = false;

		private static long s_maxReferencesPerSignedInfo = 100L;

		private static bool s_readAllowAdditionalSignatureNodes = false;

		private static bool s_allowAdditionalSignatureNodes = false;

		private static bool s_readSkipSignatureAttributeEnforcement = false;

		private static bool s_skipSignatureAttributeEnforcement = false;

		private static bool s_readAllowBareTypeReference = false;

		private static bool s_allowBareTypeReference = false;

		private static bool s_readLeaveCipherValueUnchecked = false;

		private static bool s_leaveCipherValueUnchecked = false;

		private static readonly char[] s_invalidChars = new char[5] { ',', '`', '[', '*', '&' };

		private static int? xmlDsigSearchDepth = null;

		private Utils()
		{
		}

		private static bool HasNamespace(XmlElement element, string prefix, string value)
		{
			if (IsCommittedNamespace(element, prefix, value))
			{
				return true;
			}
			if (element.Prefix == prefix && element.NamespaceURI == value)
			{
				return true;
			}
			return false;
		}

		internal static bool IsCommittedNamespace(XmlElement element, string prefix, string value)
		{
			if (element == null)
			{
				throw new ArgumentNullException("element");
			}
			string name = ((prefix.Length > 0) ? ("xmlns:" + prefix) : "xmlns");
			if (element.HasAttribute(name) && element.GetAttribute(name) == value)
			{
				return true;
			}
			return false;
		}

		internal static bool IsRedundantNamespace(XmlElement element, string prefix, string value)
		{
			if (element == null)
			{
				throw new ArgumentNullException("element");
			}
			for (XmlNode parentNode = element.ParentNode; parentNode != null; parentNode = parentNode.ParentNode)
			{
				if (parentNode is XmlElement element2 && HasNamespace(element2, prefix, value))
				{
					return true;
				}
			}
			return false;
		}

		internal static string GetAttribute(XmlElement element, string localName, string namespaceURI)
		{
			string text = (element.HasAttribute(localName) ? element.GetAttribute(localName) : null);
			if (text == null && element.HasAttribute(localName, namespaceURI))
			{
				text = element.GetAttribute(localName, namespaceURI);
			}
			return text;
		}

		internal static bool HasAttribute(XmlElement element, string localName, string namespaceURI)
		{
			if (!element.HasAttribute(localName))
			{
				return element.HasAttribute(localName, namespaceURI);
			}
			return true;
		}

		internal static bool IsNamespaceNode(XmlNode n)
		{
			if (n.NodeType == XmlNodeType.Attribute)
			{
				if (!n.Prefix.Equals("xmlns"))
				{
					if (n.Prefix.Length == 0)
					{
						return n.LocalName.Equals("xmlns");
					}
					return false;
				}
				return true;
			}
			return false;
		}

		internal static bool IsXmlNamespaceNode(XmlNode n)
		{
			if (n.NodeType == XmlNodeType.Attribute)
			{
				return n.Prefix.Equals("xml");
			}
			return false;
		}

		internal static bool IsDefaultNamespaceNode(XmlNode n)
		{
			bool flag = n.NodeType == XmlNodeType.Attribute && n.Prefix.Length == 0 && n.LocalName.Equals("xmlns");
			bool result = IsXmlNamespaceNode(n);
			if (!flag)
			{
				return result;
			}
			return true;
		}

		internal static bool IsEmptyDefaultNamespaceNode(XmlNode n)
		{
			if (IsDefaultNamespaceNode(n))
			{
				return n.Value.Length == 0;
			}
			return false;
		}

		internal static string GetNamespacePrefix(XmlAttribute a)
		{
			if (a.Prefix.Length != 0)
			{
				return a.LocalName;
			}
			return string.Empty;
		}

		internal static bool HasNamespacePrefix(XmlAttribute a, string nsPrefix)
		{
			return GetNamespacePrefix(a).Equals(nsPrefix);
		}

		internal static bool IsNonRedundantNamespaceDecl(XmlAttribute a, XmlAttribute nearestAncestorWithSamePrefix)
		{
			if (nearestAncestorWithSamePrefix == null)
			{
				return !IsEmptyDefaultNamespaceNode(a);
			}
			return !nearestAncestorWithSamePrefix.Value.Equals(a.Value);
		}

		internal static bool IsXmlPrefixDefinitionNode(XmlAttribute a)
		{
			return false;
		}

		internal static string DiscardWhiteSpaces(string inputBuffer)
		{
			return DiscardWhiteSpaces(inputBuffer, 0, inputBuffer.Length);
		}

		internal static string DiscardWhiteSpaces(string inputBuffer, int inputOffset, int inputCount)
		{
			int num = 0;
			for (int i = 0; i < inputCount; i++)
			{
				if (char.IsWhiteSpace(inputBuffer[inputOffset + i]))
				{
					num++;
				}
			}
			char[] array = new char[inputCount - num];
			num = 0;
			for (int i = 0; i < inputCount; i++)
			{
				if (!char.IsWhiteSpace(inputBuffer[inputOffset + i]))
				{
					array[num++] = inputBuffer[inputOffset + i];
				}
			}
			return new string(array);
		}

		internal static void SBReplaceCharWithString(StringBuilder sb, char oldChar, string newString)
		{
			int num = 0;
			int length = newString.Length;
			while (num < sb.Length)
			{
				if (sb[num] == oldChar)
				{
					sb.Remove(num, 1);
					sb.Insert(num, newString);
					num += length;
				}
				else
				{
					num++;
				}
			}
		}

		internal static XmlReader PreProcessStreamInput(Stream inputStream, XmlResolver xmlResolver, string baseUri)
		{
			XmlReaderSettings secureXmlReaderSettings = GetSecureXmlReaderSettings(xmlResolver);
			return XmlReader.Create(inputStream, secureXmlReaderSettings, baseUri);
		}

		internal static XmlReaderSettings GetSecureXmlReaderSettings(XmlResolver xmlResolver)
		{
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			xmlReaderSettings.XmlResolver = xmlResolver;
			xmlReaderSettings.ProhibitDtd = false;
			xmlReaderSettings.MaxCharactersFromEntities = GetMaxCharactersFromEntities();
			return xmlReaderSettings;
		}

		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static long GetMaxCharactersFromEntities()
		{
			if (maxCharactersFromEntities.HasValue)
			{
				return maxCharactersFromEntities.Value;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("SignedXmlMaxCharactersFromEntities", 10000000L);
			maxCharactersFromEntities = netFxSecurityRegistryValue;
			return maxCharactersFromEntities.Value;
		}

		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool AllowAmbiguousReferenceTargets()
		{
			if (s_allowAmbiguousReferenceTarget.HasValue)
			{
				return s_allowAmbiguousReferenceTarget.Value;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("SignedXmlAllowAmbiguousReferenceTargets", 0L);
			bool value = netFxSecurityRegistryValue != 0;
			s_allowAmbiguousReferenceTarget = value;
			return s_allowAmbiguousReferenceTarget.Value;
		}

		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool AllowDetachedSignature()
		{
			if (s_allowDetachedSignature.HasValue)
			{
				return s_allowDetachedSignature.Value;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("SignedXmlAllowDetachedSignature", 0L);
			bool value = netFxSecurityRegistryValue != 0;
			s_allowDetachedSignature = value;
			return s_allowDetachedSignature.Value;
		}

		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool RequireNCNameIdentifier()
		{
			if (s_readRequireNCNameIdentifier)
			{
				return s_requireNCNameIdentifier;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("SignedXmlRequireNCNameIdentifier", 1L);
			bool flag = (s_requireNCNameIdentifier = netFxSecurityRegistryValue != 0);
			Thread.MemoryBarrier();
			s_readRequireNCNameIdentifier = true;
			return s_requireNCNameIdentifier;
		}

		[SecuritySafeCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static long GetMaxTransformsPerReference()
		{
			if (s_readMaxTransformsPerReference)
			{
				return s_maxTransformsPerReference;
			}
			long num = (s_maxTransformsPerReference = GetNetFxSecurityRegistryValue("SignedXmlMaxTransformsPerReference", 10L));
			Thread.MemoryBarrier();
			s_readMaxTransformsPerReference = true;
			return s_maxTransformsPerReference;
		}

		[SecuritySafeCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static long GetMaxReferencesPerSignedInfo()
		{
			if (s_readMaxReferencesPerSignedInfo)
			{
				return s_maxReferencesPerSignedInfo;
			}
			long num = (s_maxReferencesPerSignedInfo = GetNetFxSecurityRegistryValue("SignedXmlMaxReferencesPerSignedInfo", 100L));
			Thread.MemoryBarrier();
			s_readMaxReferencesPerSignedInfo = true;
			return s_maxReferencesPerSignedInfo;
		}

		[SecuritySafeCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool GetAllowAdditionalSignatureNodes()
		{
			if (s_readAllowAdditionalSignatureNodes)
			{
				return s_allowAdditionalSignatureNodes;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("SignedXmlAllowAdditionalSignatureNodes", 0L);
			bool flag = (s_allowAdditionalSignatureNodes = netFxSecurityRegistryValue != 0);
			Thread.MemoryBarrier();
			s_readAllowAdditionalSignatureNodes = true;
			return s_allowAdditionalSignatureNodes;
		}

		[SecuritySafeCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool GetSkipSignatureAttributeEnforcement()
		{
			if (s_readSkipSignatureAttributeEnforcement)
			{
				return s_skipSignatureAttributeEnforcement;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("SignedXmlSkipSignatureAttributeEnforcement", 0L);
			bool flag = (s_skipSignatureAttributeEnforcement = netFxSecurityRegistryValue != 0);
			Thread.MemoryBarrier();
			s_readSkipSignatureAttributeEnforcement = true;
			return s_skipSignatureAttributeEnforcement;
		}

		internal static bool VerifyAttributes(XmlElement element, string expectedAttrName)
		{
			return VerifyAttributes(element, (expectedAttrName == null) ? null : new string[1] { expectedAttrName });
		}

		internal static bool VerifyAttributes(XmlElement element, string[] expectedAttrNames)
		{
			if (!GetSkipSignatureAttributeEnforcement())
			{
				foreach (XmlAttribute attribute in element.Attributes)
				{
					bool flag = attribute.Name == "xmlns" || attribute.Name.StartsWith("xmlns:") || attribute.Name == "xml:space" || attribute.Name == "xml:lang" || attribute.Name == "xml:base";
					int num = 0;
					while (!flag && expectedAttrNames != null && num < expectedAttrNames.Length)
					{
						flag = attribute.Name == expectedAttrNames[num];
						num++;
					}
					if (!flag)
					{
						return false;
					}
				}
			}
			return true;
		}

		[SecuritySafeCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool GetAllowBareTypeReference()
		{
			if (s_readAllowBareTypeReference)
			{
				return s_allowBareTypeReference;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("CryptoXmlAllowBareTypeReference", 0L);
			bool flag = (s_allowBareTypeReference = netFxSecurityRegistryValue != 0);
			Thread.MemoryBarrier();
			s_readAllowBareTypeReference = true;
			return s_allowBareTypeReference;
		}

		[SecuritySafeCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool GetLeaveCipherValueUnchecked()
		{
			if (s_readLeaveCipherValueUnchecked)
			{
				return s_leaveCipherValueUnchecked;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("EncryptedXmlLeaveCipherValueUnchecked", 0L);
			bool flag = (s_leaveCipherValueUnchecked = netFxSecurityRegistryValue != 0);
			Thread.MemoryBarrier();
			s_readLeaveCipherValueUnchecked = true;
			return s_leaveCipherValueUnchecked;
		}

		internal static T CreateFromName<T>(string key) where T : class
		{
			if (GetAllowBareTypeReference())
			{
				return CryptoConfig.CreateFromName(key) as T;
			}
			if (key == null || key.IndexOfAny(s_invalidChars) >= 0)
			{
				return null;
			}
			try
			{
				return CryptoConfig.CreateFromName(key) as T;
			}
			catch (Exception)
			{
				return null;
			}
		}

		private static long GetNetFxSecurityRegistryValue(string regValueName, long defaultValue)
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\.NETFramework\\Security", writable: false);
				if (registryKey != null)
				{
					object value = registryKey.GetValue(regValueName);
					if (value != null)
					{
						RegistryValueKind valueKind = registryKey.GetValueKind(regValueName);
						if (valueKind == RegistryValueKind.DWord || valueKind == RegistryValueKind.QWord)
						{
							return Convert.ToInt64(value, CultureInfo.InvariantCulture);
						}
						return defaultValue;
					}
					return defaultValue;
				}
				return defaultValue;
			}
			catch (SecurityException)
			{
				return defaultValue;
			}
		}

		internal static XmlDocument PreProcessDocumentInput(XmlDocument document, XmlResolver xmlResolver, string baseUri)
		{
			if (document == null)
			{
				throw new ArgumentNullException("document");
			}
			MyXmlDocument myXmlDocument = new MyXmlDocument();
			myXmlDocument.PreserveWhitespace = document.PreserveWhitespace;
			using TextReader input = new StringReader(document.OuterXml);
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			xmlReaderSettings.XmlResolver = xmlResolver;
			xmlReaderSettings.ProhibitDtd = false;
			xmlReaderSettings.MaxCharactersFromEntities = GetMaxCharactersFromEntities();
			XmlReader reader = XmlReader.Create(input, xmlReaderSettings, baseUri);
			myXmlDocument.Load(reader);
			return myXmlDocument;
		}

		internal static XmlDocument PreProcessElementInput(XmlElement elem, XmlResolver xmlResolver, string baseUri)
		{
			if (elem == null)
			{
				throw new ArgumentNullException("elem");
			}
			MyXmlDocument myXmlDocument = new MyXmlDocument();
			myXmlDocument.PreserveWhitespace = true;
			using TextReader input = new StringReader(elem.OuterXml);
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			xmlReaderSettings.XmlResolver = xmlResolver;
			xmlReaderSettings.ProhibitDtd = false;
			xmlReaderSettings.MaxCharactersFromEntities = GetMaxCharactersFromEntities();
			XmlReader reader = XmlReader.Create(input, xmlReaderSettings, baseUri);
			myXmlDocument.Load(reader);
			return myXmlDocument;
		}

		internal static XmlDocument DiscardComments(XmlDocument document)
		{
			XmlNodeList xmlNodeList = document.SelectNodes("//comment()");
			if (xmlNodeList != null)
			{
				foreach (XmlNode item in xmlNodeList)
				{
					item.ParentNode.RemoveChild(item);
				}
				return document;
			}
			return document;
		}

		internal static XmlNodeList AllDescendantNodes(XmlNode node, bool includeComments)
		{
			CanonicalXmlNodeList canonicalXmlNodeList = new CanonicalXmlNodeList();
			CanonicalXmlNodeList canonicalXmlNodeList2 = new CanonicalXmlNodeList();
			CanonicalXmlNodeList canonicalXmlNodeList3 = new CanonicalXmlNodeList();
			CanonicalXmlNodeList canonicalXmlNodeList4 = new CanonicalXmlNodeList();
			int num = 0;
			canonicalXmlNodeList2.Add(node);
			do
			{
				XmlNode xmlNode = canonicalXmlNodeList2[num];
				XmlNodeList childNodes = xmlNode.ChildNodes;
				if (childNodes != null)
				{
					foreach (XmlNode item in childNodes)
					{
						if (includeComments || !(item is XmlComment))
						{
							canonicalXmlNodeList2.Add(item);
						}
					}
				}
				XmlAttributeCollection attributes = xmlNode.Attributes;
				if (attributes != null)
				{
					foreach (XmlNode attribute in xmlNode.Attributes)
					{
						if (attribute.LocalName == "xmlns" || attribute.Prefix == "xmlns")
						{
							canonicalXmlNodeList4.Add(attribute);
						}
						else
						{
							canonicalXmlNodeList3.Add(attribute);
						}
					}
				}
				num++;
			}
			while (num < canonicalXmlNodeList2.Count);
			foreach (XmlNode item2 in canonicalXmlNodeList2)
			{
				canonicalXmlNodeList.Add(item2);
			}
			foreach (XmlNode item3 in canonicalXmlNodeList3)
			{
				canonicalXmlNodeList.Add(item3);
			}
			foreach (XmlNode item4 in canonicalXmlNodeList4)
			{
				canonicalXmlNodeList.Add(item4);
			}
			return canonicalXmlNodeList;
		}

		internal static bool NodeInList(XmlNode node, XmlNodeList nodeList)
		{
			foreach (XmlNode node2 in nodeList)
			{
				if (node2 == node)
				{
					return true;
				}
			}
			return false;
		}

		internal static string GetIdFromLocalUri(string uri, out bool discardComments)
		{
			string text = uri.Substring(1);
			discardComments = true;
			if (text.StartsWith("xpointer(id(", StringComparison.Ordinal))
			{
				int num = text.IndexOf("id(", StringComparison.Ordinal);
				int num2 = text.IndexOf(")", StringComparison.Ordinal);
				if (num2 < 0 || num2 < num + 3)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidReference"));
				}
				text = text.Substring(num + 3, num2 - num - 3);
				text = text.Replace("'", "");
				text = text.Replace("\"", "");
				discardComments = false;
			}
			return text;
		}

		internal static string ExtractIdFromLocalUri(string uri)
		{
			string text = uri.Substring(1);
			if (text.StartsWith("xpointer(id(", StringComparison.Ordinal))
			{
				int num = text.IndexOf("id(", StringComparison.Ordinal);
				int num2 = text.IndexOf(")", StringComparison.Ordinal);
				if (num2 < 0 || num2 < num + 3)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidReference"));
				}
				text = text.Substring(num + 3, num2 - num - 3);
				text = text.Replace("'", "");
				text = text.Replace("\"", "");
			}
			return text;
		}

		internal static void RemoveAllChildren(XmlElement inputElement)
		{
			XmlNode xmlNode = inputElement.FirstChild;
			XmlNode xmlNode2 = null;
			while (xmlNode != null)
			{
				xmlNode2 = xmlNode.NextSibling;
				inputElement.RemoveChild(xmlNode);
				xmlNode = xmlNode2;
			}
		}

		internal static long Pump(Stream input, Stream output)
		{
			if (input is MemoryStream memoryStream && memoryStream.Position == 0)
			{
				memoryStream.WriteTo(output);
				return memoryStream.Length;
			}
			byte[] buffer = new byte[4096];
			long num = 0L;
			int num2;
			while ((num2 = input.Read(buffer, 0, 4096)) > 0)
			{
				output.Write(buffer, 0, num2);
				num += num2;
			}
			return num;
		}

		internal static Hashtable TokenizePrefixListString(string s)
		{
			Hashtable hashtable = new Hashtable();
			if (s != null)
			{
				string[] array = s.Split(null);
				string[] array2 = array;
				foreach (string text in array2)
				{
					if (text.Equals("#default"))
					{
						hashtable.Add(string.Empty, true);
					}
					else if (text.Length > 0)
					{
						hashtable.Add(text, true);
					}
				}
			}
			return hashtable;
		}

		internal static string EscapeWhitespaceData(string data)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append(data);
			SBReplaceCharWithString(stringBuilder, '\r', "&#xD;");
			return stringBuilder.ToString();
		}

		internal static string EscapeTextData(string data)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append(data);
			stringBuilder.Replace("&", "&amp;");
			stringBuilder.Replace("<", "&lt;");
			stringBuilder.Replace(">", "&gt;");
			SBReplaceCharWithString(stringBuilder, '\r', "&#xD;");
			return stringBuilder.ToString();
		}

		internal static string EscapeCData(string data)
		{
			return EscapeTextData(data);
		}

		internal static string EscapeAttributeValue(string value)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append(value);
			stringBuilder.Replace("&", "&amp;");
			stringBuilder.Replace("<", "&lt;");
			stringBuilder.Replace("\"", "&quot;");
			SBReplaceCharWithString(stringBuilder, '\t', "&#x9;");
			SBReplaceCharWithString(stringBuilder, '\n', "&#xA;");
			SBReplaceCharWithString(stringBuilder, '\r', "&#xD;");
			return stringBuilder.ToString();
		}

		internal static XmlDocument GetOwnerDocument(XmlNodeList nodeList)
		{
			foreach (XmlNode node in nodeList)
			{
				if (node.OwnerDocument != null)
				{
					return node.OwnerDocument;
				}
			}
			return null;
		}

		internal static void AddNamespaces(XmlElement elem, CanonicalXmlNodeList namespaces)
		{
			if (namespaces == null)
			{
				return;
			}
			foreach (XmlNode @namespace in namespaces)
			{
				string text = ((@namespace.Prefix.Length > 0) ? (@namespace.Prefix + ":" + @namespace.LocalName) : @namespace.LocalName);
				if (!elem.HasAttribute(text) && (!text.Equals("xmlns") || elem.Prefix.Length != 0))
				{
					XmlAttribute xmlAttribute = elem.OwnerDocument.CreateAttribute(text);
					xmlAttribute.Value = @namespace.Value;
					elem.SetAttributeNode(xmlAttribute);
				}
			}
		}

		internal static void AddNamespaces(XmlElement elem, Hashtable namespaces)
		{
			if (namespaces == null)
			{
				return;
			}
			foreach (string key in namespaces.Keys)
			{
				if (!elem.HasAttribute(key))
				{
					XmlAttribute xmlAttribute = elem.OwnerDocument.CreateAttribute(key);
					xmlAttribute.Value = namespaces[key] as string;
					elem.SetAttributeNode(xmlAttribute);
				}
			}
		}

		internal static CanonicalXmlNodeList GetPropagatedAttributes(XmlElement elem)
		{
			if (elem == null)
			{
				return null;
			}
			CanonicalXmlNodeList canonicalXmlNodeList = new CanonicalXmlNodeList();
			XmlNode xmlNode = elem;
			if (xmlNode == null)
			{
				return null;
			}
			bool flag = true;
			while (xmlNode != null)
			{
				if (!(xmlNode is XmlElement xmlElement))
				{
					xmlNode = xmlNode.ParentNode;
					continue;
				}
				if (!IsCommittedNamespace(xmlElement, xmlElement.Prefix, xmlElement.NamespaceURI) && !IsRedundantNamespace(xmlElement, xmlElement.Prefix, xmlElement.NamespaceURI))
				{
					string name = ((xmlElement.Prefix.Length > 0) ? ("xmlns:" + xmlElement.Prefix) : "xmlns");
					XmlAttribute xmlAttribute = elem.OwnerDocument.CreateAttribute(name);
					xmlAttribute.Value = xmlElement.NamespaceURI;
					canonicalXmlNodeList.Add(xmlAttribute);
				}
				if (xmlElement.HasAttributes)
				{
					XmlAttributeCollection attributes = xmlElement.Attributes;
					foreach (XmlAttribute item in attributes)
					{
						if (flag && item.LocalName == "xmlns")
						{
							XmlAttribute xmlAttribute3 = elem.OwnerDocument.CreateAttribute("xmlns");
							xmlAttribute3.Value = item.Value;
							canonicalXmlNodeList.Add(xmlAttribute3);
							flag = false;
						}
						else if (item.Prefix == "xmlns" || item.Prefix == "xml")
						{
							canonicalXmlNodeList.Add(item);
						}
						else if (item.NamespaceURI.Length > 0 && !IsCommittedNamespace(xmlElement, item.Prefix, item.NamespaceURI) && !IsRedundantNamespace(xmlElement, item.Prefix, item.NamespaceURI))
						{
							string name2 = ((item.Prefix.Length > 0) ? ("xmlns:" + item.Prefix) : "xmlns");
							XmlAttribute xmlAttribute4 = elem.OwnerDocument.CreateAttribute(name2);
							xmlAttribute4.Value = item.NamespaceURI;
							canonicalXmlNodeList.Add(xmlAttribute4);
						}
					}
				}
				xmlNode = xmlNode.ParentNode;
			}
			return canonicalXmlNodeList;
		}

		internal static byte[] ConvertIntToByteArray(int dwInput)
		{
			byte[] array = new byte[8];
			int num = 0;
			if (dwInput == 0)
			{
				return new byte[1];
			}
			int num2 = dwInput;
			while (num2 > 0)
			{
				int num3 = num2 % 256;
				array[num] = (byte)num3;
				num2 = (num2 - num3) / 256;
				num++;
			}
			byte[] array2 = new byte[num];
			for (int i = 0; i < num; i++)
			{
				array2[i] = array[num - i - 1];
			}
			return array2;
		}

		internal static int GetHexArraySize(byte[] hex)
		{
			int num = hex.Length;
			while (num-- > 0 && hex[num] == 0)
			{
			}
			return num + 1;
		}

		internal static X509Certificate2Collection BuildBagOfCerts(KeyInfoX509Data keyInfoX509Data, CertUsageType certUsageType)
		{
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			ArrayList arrayList = ((certUsageType == CertUsageType.Decryption) ? new ArrayList() : null);
			if (keyInfoX509Data.Certificates != null)
			{
				foreach (X509Certificate2 certificate in keyInfoX509Data.Certificates)
				{
					switch (certUsageType)
					{
					case CertUsageType.Verification:
						x509Certificate2Collection.Add(certificate);
						break;
					case CertUsageType.Decryption:
						arrayList.Add(new X509IssuerSerial(certificate.IssuerName.Name, certificate.SerialNumber));
						break;
					}
				}
			}
			if (keyInfoX509Data.SubjectNames == null && keyInfoX509Data.IssuerSerials == null && keyInfoX509Data.SubjectKeyIds == null && arrayList == null)
			{
				return x509Certificate2Collection;
			}
			StorePermission storePermission = new StorePermission(StorePermissionFlags.OpenStore);
			storePermission.Assert();
			X509Store[] array = new X509Store[2];
			string storeName = ((certUsageType == CertUsageType.Verification) ? "AddressBook" : "My");
			array[0] = new X509Store(storeName, StoreLocation.CurrentUser);
			array[1] = new X509Store(storeName, StoreLocation.LocalMachine);
			for (int i = 0; i < array.Length; i++)
			{
				if (array[i] == null)
				{
					continue;
				}
				X509Certificate2Collection x509Certificate2Collection2 = null;
				try
				{
					array[i].Open(OpenFlags.OpenExistingOnly);
					x509Certificate2Collection2 = array[i].Certificates;
					array[i].Close();
					if (keyInfoX509Data.SubjectNames != null)
					{
						foreach (string subjectName in keyInfoX509Data.SubjectNames)
						{
							x509Certificate2Collection2 = x509Certificate2Collection2.Find(X509FindType.FindBySubjectDistinguishedName, subjectName, validOnly: false);
						}
					}
					if (keyInfoX509Data.IssuerSerials != null)
					{
						foreach (X509IssuerSerial issuerSerial in keyInfoX509Data.IssuerSerials)
						{
							x509Certificate2Collection2 = x509Certificate2Collection2.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, validOnly: false);
							x509Certificate2Collection2 = x509Certificate2Collection2.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, validOnly: false);
						}
					}
					if (keyInfoX509Data.SubjectKeyIds != null)
					{
						foreach (byte[] subjectKeyId in keyInfoX509Data.SubjectKeyIds)
						{
							string findValue2 = System.Security.Cryptography.X509Certificates.X509Utils.EncodeHexString(subjectKeyId);
							x509Certificate2Collection2 = x509Certificate2Collection2.Find(X509FindType.FindBySubjectKeyIdentifier, findValue2, validOnly: false);
						}
					}
					if (arrayList != null)
					{
						foreach (X509IssuerSerial item in arrayList)
						{
							x509Certificate2Collection2 = x509Certificate2Collection2.Find(X509FindType.FindByIssuerDistinguishedName, item.IssuerName, validOnly: false);
							x509Certificate2Collection2 = x509Certificate2Collection2.Find(X509FindType.FindBySerialNumber, item.SerialNumber, validOnly: false);
						}
					}
				}
				catch (CryptographicException)
				{
				}
				if (x509Certificate2Collection2 != null)
				{
					x509Certificate2Collection.AddRange(x509Certificate2Collection2);
				}
			}
			return x509Certificate2Collection;
		}

		[SecuritySafeCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static int GetXmlDsigSearchDepth()
		{
			if (xmlDsigSearchDepth.HasValue)
			{
				return xmlDsigSearchDepth.Value;
			}
			long netFxSecurityRegistryValue = GetNetFxSecurityRegistryValue("SignedDigitalSignatureXmlMaxDepth", 20L);
			xmlDsigSearchDepth = (int)netFxSecurityRegistryValue;
			return xmlDsigSearchDepth.Value;
		}
	}
	internal enum DocPosition
	{
		BeforeRootElement,
		InRootElement,
		AfterRootElement
	}
	internal interface ICanonicalizableNode
	{
		bool IsInNodeSet { get; set; }

		void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc);

		void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc);
	}
	internal class CanonicalizationDispatcher
	{
		private CanonicalizationDispatcher()
		{
		}

		public static void Write(XmlNode node, StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (node is ICanonicalizableNode)
			{
				((ICanonicalizableNode)node).Write(strBuilder, docPos, anc);
			}
			else
			{
				WriteGenericNode(node, strBuilder, docPos, anc);
			}
		}

		public static void WriteGenericNode(XmlNode node, StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (node == null)
			{
				throw new ArgumentNullException("node");
			}
			XmlNodeList childNodes = node.ChildNodes;
			foreach (XmlNode item in childNodes)
			{
				Write(item, strBuilder, docPos, anc);
			}
		}

		public static void WriteHash(XmlNode node, HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (node is ICanonicalizableNode)
			{
				((ICanonicalizableNode)node).WriteHash(hash, docPos, anc);
			}
			else
			{
				WriteHashGenericNode(node, hash, docPos, anc);
			}
		}

		public static void WriteHashGenericNode(XmlNode node, HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (node == null)
			{
				throw new ArgumentNullException("node");
			}
			XmlNodeList childNodes = node.ChildNodes;
			foreach (XmlNode item in childNodes)
			{
				WriteHash(item, hash, docPos, anc);
			}
		}
	}
	internal class CanonicalXmlDocument : XmlDocument, ICanonicalizableNode
	{
		private bool m_defaultNodeSetInclusionState;

		private bool m_includeComments;

		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlDocument(bool defaultNodeSetInclusionState, bool includeComments)
		{
			base.PreserveWhitespace = true;
			m_includeComments = includeComments;
			m_isInNodeSet = (m_defaultNodeSetInclusionState = defaultNodeSetInclusionState);
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			docPos = DocPosition.BeforeRootElement;
			foreach (XmlNode childNode in ChildNodes)
			{
				if (childNode.NodeType == XmlNodeType.Element)
				{
					CanonicalizationDispatcher.Write(childNode, strBuilder, DocPosition.InRootElement, anc);
					docPos = DocPosition.AfterRootElement;
				}
				else
				{
					CanonicalizationDispatcher.Write(childNode, strBuilder, docPos, anc);
				}
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			docPos = DocPosition.BeforeRootElement;
			foreach (XmlNode childNode in ChildNodes)
			{
				if (childNode.NodeType == XmlNodeType.Element)
				{
					CanonicalizationDispatcher.WriteHash(childNode, hash, DocPosition.InRootElement, anc);
					docPos = DocPosition.AfterRootElement;
				}
				else
				{
					CanonicalizationDispatcher.WriteHash(childNode, hash, docPos, anc);
				}
			}
		}

		public override XmlElement CreateElement(string prefix, string localName, string namespaceURI)
		{
			return new CanonicalXmlElement(prefix, localName, namespaceURI, this, m_defaultNodeSetInclusionState);
		}

		public override XmlAttribute CreateAttribute(string prefix, string localName, string namespaceURI)
		{
			return new CanonicalXmlAttribute(prefix, localName, namespaceURI, this, m_defaultNodeSetInclusionState);
		}

		protected override XmlAttribute CreateDefaultAttribute(string prefix, string localName, string namespaceURI)
		{
			return new CanonicalXmlAttribute(prefix, localName, namespaceURI, this, m_defaultNodeSetInclusionState);
		}

		public override XmlText CreateTextNode(string text)
		{
			return new CanonicalXmlText(text, this, m_defaultNodeSetInclusionState);
		}

		public override XmlWhitespace CreateWhitespace(string prefix)
		{
			return new CanonicalXmlWhitespace(prefix, this, m_defaultNodeSetInclusionState);
		}

		public override XmlSignificantWhitespace CreateSignificantWhitespace(string text)
		{
			return new CanonicalXmlSignificantWhitespace(text, this, m_defaultNodeSetInclusionState);
		}

		public override XmlProcessingInstruction CreateProcessingInstruction(string target, string data)
		{
			return new CanonicalXmlProcessingInstruction(target, data, this, m_defaultNodeSetInclusionState);
		}

		public override XmlComment CreateComment(string data)
		{
			return new CanonicalXmlComment(data, this, m_defaultNodeSetInclusionState, m_includeComments);
		}

		public override XmlEntityReference CreateEntityReference(string name)
		{
			return new CanonicalXmlEntityReference(name, this, m_defaultNodeSetInclusionState);
		}

		public override XmlCDataSection CreateCDataSection(string data)
		{
			return new CanonicalXmlCDataSection(data, this, m_defaultNodeSetInclusionState);
		}
	}
	internal class CanonicalXmlElement : XmlElement, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlElement(string prefix, string localName, string namespaceURI, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(prefix, localName, namespaceURI, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			Hashtable nsLocallyDeclared = new Hashtable();
			SortedList sortedList = new SortedList(new NamespaceSortOrder());
			SortedList sortedList2 = new SortedList(new AttributeSortOrder());
			XmlAttributeCollection xmlAttributeCollection = Attributes;
			if (xmlAttributeCollection != null)
			{
				foreach (XmlAttribute item in xmlAttributeCollection)
				{
					if (((CanonicalXmlAttribute)item).IsInNodeSet || Utils.IsNamespaceNode(item) || Utils.IsXmlNamespaceNode(item))
					{
						if (Utils.IsNamespaceNode(item))
						{
							anc.TrackNamespaceNode(item, sortedList, nsLocallyDeclared);
						}
						else if (Utils.IsXmlNamespaceNode(item))
						{
							anc.TrackXmlNamespaceNode(item, sortedList, sortedList2, nsLocallyDeclared);
						}
						else if (IsInNodeSet)
						{
							sortedList2.Add(item, null);
						}
					}
				}
			}
			if (!Utils.IsCommittedNamespace(this, Prefix, NamespaceURI))
			{
				string text = ((Prefix.Length > 0) ? ("xmlns:" + Prefix) : "xmlns");
				XmlAttribute xmlAttribute2 = OwnerDocument.CreateAttribute(text);
				xmlAttribute2.Value = NamespaceURI;
				anc.TrackNamespaceNode(xmlAttribute2, sortedList, nsLocallyDeclared);
			}
			if (IsInNodeSet)
			{
				anc.GetNamespacesToRender(this, sortedList2, sortedList, nsLocallyDeclared);
				strBuilder.Append("<" + Name);
				foreach (object key in sortedList.GetKeyList())
				{
					(key as CanonicalXmlAttribute).Write(strBuilder, docPos, anc);
				}
				foreach (object key2 in sortedList2.GetKeyList())
				{
					(key2 as CanonicalXmlAttribute).Write(strBuilder, docPos, anc);
				}
				strBuilder.Append(">");
			}
			anc.EnterElementContext();
			anc.LoadUnrenderedNamespaces(nsLocallyDeclared);
			anc.LoadRenderedNamespaces(sortedList);
			XmlNodeList childNodes = ChildNodes;
			foreach (XmlNode item2 in childNodes)
			{
				CanonicalizationDispatcher.Write(item2, strBuilder, docPos, anc);
			}
			anc.ExitElementContext();
			if (IsInNodeSet)
			{
				strBuilder.Append("</" + Name + ">");
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			Hashtable nsLocallyDeclared = new Hashtable();
			SortedList sortedList = new SortedList(new NamespaceSortOrder());
			SortedList sortedList2 = new SortedList(new AttributeSortOrder());
			UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			XmlAttributeCollection xmlAttributeCollection = Attributes;
			if (xmlAttributeCollection != null)
			{
				foreach (XmlAttribute item in xmlAttributeCollection)
				{
					if (((CanonicalXmlAttribute)item).IsInNodeSet || Utils.IsNamespaceNode(item) || Utils.IsXmlNamespaceNode(item))
					{
						if (Utils.IsNamespaceNode(item))
						{
							anc.TrackNamespaceNode(item, sortedList, nsLocallyDeclared);
						}
						else if (Utils.IsXmlNamespaceNode(item))
						{
							anc.TrackXmlNamespaceNode(item, sortedList, sortedList2, nsLocallyDeclared);
						}
						else if (IsInNodeSet)
						{
							sortedList2.Add(item, null);
						}
					}
				}
			}
			if (!Utils.IsCommittedNamespace(this, Prefix, NamespaceURI))
			{
				string text = ((Prefix.Length > 0) ? ("xmlns:" + Prefix) : "xmlns");
				XmlAttribute xmlAttribute2 = OwnerDocument.CreateAttribute(text);
				xmlAttribute2.Value = NamespaceURI;
				anc.TrackNamespaceNode(xmlAttribute2, sortedList, nsLocallyDeclared);
			}
			if (IsInNodeSet)
			{
				anc.GetNamespacesToRender(this, sortedList2, sortedList, nsLocallyDeclared);
				byte[] bytes = uTF8Encoding.GetBytes("<" + Name);
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				foreach (object key in sortedList.GetKeyList())
				{
					(key as CanonicalXmlAttribute).WriteHash(hash, docPos, anc);
				}
				foreach (object key2 in sortedList2.GetKeyList())
				{
					(key2 as CanonicalXmlAttribute).WriteHash(hash, docPos, anc);
				}
				bytes = uTF8Encoding.GetBytes(">");
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			}
			anc.EnterElementContext();
			anc.LoadUnrenderedNamespaces(nsLocallyDeclared);
			anc.LoadRenderedNamespaces(sortedList);
			XmlNodeList childNodes = ChildNodes;
			foreach (XmlNode item2 in childNodes)
			{
				CanonicalizationDispatcher.WriteHash(item2, hash, docPos, anc);
			}
			anc.ExitElementContext();
			if (IsInNodeSet)
			{
				byte[] bytes = uTF8Encoding.GetBytes("</" + Name + ">");
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			}
		}
	}
	internal class CanonicalXmlAttribute : XmlAttribute, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlAttribute(string prefix, string localName, string namespaceURI, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(prefix, localName, namespaceURI, doc)
		{
			IsInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			strBuilder.Append(" " + Name + "=\"");
			strBuilder.Append(Utils.EscapeAttributeValue(Value));
			strBuilder.Append("\"");
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			byte[] bytes = uTF8Encoding.GetBytes(" " + Name + "=\"");
			hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			bytes = uTF8Encoding.GetBytes(Utils.EscapeAttributeValue(Value));
			hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			bytes = uTF8Encoding.GetBytes("\"");
			hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
		}
	}
	internal class CanonicalXmlText : XmlText, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlText(string strData, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(strData, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				strBuilder.Append(Utils.EscapeTextData(Value));
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
				byte[] bytes = uTF8Encoding.GetBytes(Utils.EscapeTextData(Value));
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			}
		}
	}
	internal class CanonicalXmlWhitespace : XmlWhitespace, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlWhitespace(string strData, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(strData, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet && docPos == DocPosition.InRootElement)
			{
				strBuilder.Append(Utils.EscapeWhitespaceData(Value));
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet && docPos == DocPosition.InRootElement)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
				byte[] bytes = uTF8Encoding.GetBytes(Utils.EscapeWhitespaceData(Value));
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			}
		}
	}
	internal class CanonicalXmlSignificantWhitespace : XmlSignificantWhitespace, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlSignificantWhitespace(string strData, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(strData, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet && docPos == DocPosition.InRootElement)
			{
				strBuilder.Append(Utils.EscapeWhitespaceData(Value));
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet && docPos == DocPosition.InRootElement)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
				byte[] bytes = uTF8Encoding.GetBytes(Utils.EscapeWhitespaceData(Value));
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			}
		}
	}
	internal class CanonicalXmlComment : XmlComment, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		private bool m_includeComments;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public bool IncludeComments => m_includeComments;

		public CanonicalXmlComment(string comment, XmlDocument doc, bool defaultNodeSetInclusionState, bool includeComments)
			: base(comment, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
			m_includeComments = includeComments;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet && IncludeComments)
			{
				if (docPos == DocPosition.AfterRootElement)
				{
					strBuilder.Append('\n');
				}
				strBuilder.Append("<!--");
				strBuilder.Append(Value);
				strBuilder.Append("-->");
				if (docPos == DocPosition.BeforeRootElement)
				{
					strBuilder.Append('\n');
				}
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet && IncludeComments)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
				byte[] bytes = uTF8Encoding.GetBytes("(char) 10");
				if (docPos == DocPosition.AfterRootElement)
				{
					hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				}
				bytes = uTF8Encoding.GetBytes("<!--");
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				bytes = uTF8Encoding.GetBytes(Value);
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				bytes = uTF8Encoding.GetBytes("-->");
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				if (docPos == DocPosition.BeforeRootElement)
				{
					bytes = uTF8Encoding.GetBytes("(char) 10");
					hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				}
			}
		}
	}
	internal class CanonicalXmlProcessingInstruction : XmlProcessingInstruction, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlProcessingInstruction(string target, string data, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(target, data, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				if (docPos == DocPosition.AfterRootElement)
				{
					strBuilder.Append('\n');
				}
				strBuilder.Append("<?");
				strBuilder.Append(Name);
				if (Value != null && Value.Length > 0)
				{
					strBuilder.Append(" " + Value);
				}
				strBuilder.Append("?>");
				if (docPos == DocPosition.BeforeRootElement)
				{
					strBuilder.Append('\n');
				}
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
				byte[] bytes;
				if (docPos == DocPosition.AfterRootElement)
				{
					bytes = uTF8Encoding.GetBytes("(char) 10");
					hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				}
				bytes = uTF8Encoding.GetBytes("<?");
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				bytes = uTF8Encoding.GetBytes(Name);
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				if (Value != null && Value.Length > 0)
				{
					bytes = uTF8Encoding.GetBytes(" " + Value);
					hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				}
				bytes = uTF8Encoding.GetBytes("?>");
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				if (docPos == DocPosition.BeforeRootElement)
				{
					bytes = uTF8Encoding.GetBytes("(char) 10");
					hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
				}
			}
		}
	}
	internal class CanonicalXmlEntityReference : XmlEntityReference, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlEntityReference(string name, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(name, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				CanonicalizationDispatcher.WriteGenericNode(this, strBuilder, docPos, anc);
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				CanonicalizationDispatcher.WriteHashGenericNode(this, hash, docPos, anc);
			}
		}
	}
	internal class CanonicalXmlCDataSection : XmlCDataSection, ICanonicalizableNode
	{
		private bool m_isInNodeSet;

		public bool IsInNodeSet
		{
			get
			{
				return m_isInNodeSet;
			}
			set
			{
				m_isInNodeSet = value;
			}
		}

		public CanonicalXmlCDataSection(string data, XmlDocument doc, bool defaultNodeSetInclusionState)
			: base(data, doc)
		{
			m_isInNodeSet = defaultNodeSetInclusionState;
		}

		public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				strBuilder.Append(Utils.EscapeCData(Data));
			}
		}

		public void WriteHash(HashAlgorithm hash, DocPosition docPos, AncestralNamespaceContextManager anc)
		{
			if (IsInNodeSet)
			{
				UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
				byte[] bytes = uTF8Encoding.GetBytes(Utils.EscapeCData(Data));
				hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
			}
		}
	}
	internal class CanonicalXmlNodeList : XmlNodeList, IList, ICollection, IEnumerable
	{
		private ArrayList m_nodeArray;

		public override int Count => m_nodeArray.Count;

		public bool IsFixedSize => m_nodeArray.IsFixedSize;

		public bool IsReadOnly => m_nodeArray.IsReadOnly;

		object IList.this[int index]
		{
			get
			{
				return m_nodeArray[index];
			}
			set
			{
				if (!(value is XmlNode))
				{
					throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
				}
				m_nodeArray[index] = value;
			}
		}

		public object SyncRoot => m_nodeArray.SyncRoot;

		public bool IsSynchronized => m_nodeArray.IsSynchronized;

		internal CanonicalXmlNodeList()
		{
			m_nodeArray = new ArrayList();
		}

		public override XmlNode Item(int index)
		{
			return (XmlNode)m_nodeArray[index];
		}

		public override IEnumerator GetEnumerator()
		{
			return m_nodeArray.GetEnumerator();
		}

		public int Add(object value)
		{
			if (!(value is XmlNode))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "node");
			}
			return m_nodeArray.Add(value);
		}

		public void Clear()
		{
			m_nodeArray.Clear();
		}

		public bool Contains(object value)
		{
			return m_nodeArray.Contains(value);
		}

		public int IndexOf(object value)
		{
			return m_nodeArray.IndexOf(value);
		}

		public void Insert(int index, object value)
		{
			if (!(value is XmlNode))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			m_nodeArray.Insert(index, value);
		}

		public void Remove(object value)
		{
			m_nodeArray.Remove(value);
		}

		public void RemoveAt(int index)
		{
			m_nodeArray.RemoveAt(index);
		}

		public void CopyTo(Array array, int index)
		{
			m_nodeArray.CopyTo(array, index);
		}
	}
	internal class AttributeSortOrder : IComparer
	{
		internal AttributeSortOrder()
		{
		}

		public int Compare(object a, object b)
		{
			XmlNode xmlNode = a as XmlNode;
			XmlNode xmlNode2 = b as XmlNode;
			if (a == null || b == null)
			{
				throw new ArgumentException();
			}
			int num = string.CompareOrdinal(xmlNode.NamespaceURI, xmlNode2.NamespaceURI);
			if (num != 0)
			{
				return num;
			}
			return string.CompareOrdinal(xmlNode.LocalName, xmlNode2.LocalName);
		}
	}
	internal class NamespaceSortOrder : IComparer
	{
		internal NamespaceSortOrder()
		{
		}

		public int Compare(object a, object b)
		{
			XmlNode xmlNode = a as XmlNode;
			XmlNode xmlNode2 = b as XmlNode;
			if (a == null || b == null)
			{
				throw new ArgumentException();
			}
			bool flag = Utils.IsDefaultNamespaceNode(xmlNode);
			bool flag2 = Utils.IsDefaultNamespaceNode(xmlNode2);
			if (flag && flag2)
			{
				return 0;
			}
			if (flag)
			{
				return -1;
			}
			if (flag2)
			{
				return 1;
			}
			return string.CompareOrdinal(xmlNode.LocalName, xmlNode2.LocalName);
		}
	}
	internal class NamespaceFrame
	{
		private Hashtable m_rendered = new Hashtable();

		private Hashtable m_unrendered = new Hashtable();

		internal NamespaceFrame()
		{
		}

		internal void AddRendered(XmlAttribute attr)
		{
			m_rendered.Add(Utils.GetNamespacePrefix(attr), attr);
		}

		internal XmlAttribute GetRendered(string nsPrefix)
		{
			return (XmlAttribute)m_rendered[nsPrefix];
		}

		internal void AddUnrendered(XmlAttribute attr)
		{
			m_unrendered.Add(Utils.GetNamespacePrefix(attr), attr);
		}

		internal XmlAttribute GetUnrendered(string nsPrefix)
		{
			return (XmlAttribute)m_unrendered[nsPrefix];
		}

		internal Hashtable GetUnrendered()
		{
			return m_unrendered;
		}
	}
	internal abstract class AncestralNamespaceContextManager
	{
		internal ArrayList m_ancestorStack = new ArrayList();

		internal NamespaceFrame GetScopeAt(int i)
		{
			return (NamespaceFrame)m_ancestorStack[i];
		}

		internal NamespaceFrame GetCurrentScope()
		{
			return GetScopeAt(m_ancestorStack.Count - 1);
		}

		protected XmlAttribute GetNearestRenderedNamespaceWithMatchingPrefix(string nsPrefix, out int depth)
		{
			XmlAttribute xmlAttribute = null;
			depth = -1;
			for (int num = m_ancestorStack.Count - 1; num >= 0; num--)
			{
				if ((xmlAttribute = GetScopeAt(num).GetRendered(nsPrefix)) != null)
				{
					depth = num;
					return xmlAttribute;
				}
			}
			return null;
		}

		protected XmlAttribute GetNearestUnrenderedNamespaceWithMatchingPrefix(string nsPrefix, out int depth)
		{
			XmlAttribute xmlAttribute = null;
			depth = -1;
			for (int num = m_ancestorStack.Count - 1; num >= 0; num--)
			{
				if ((xmlAttribute = GetScopeAt(num).GetUnrendered(nsPrefix)) != null)
				{
					depth = num;
					return xmlAttribute;
				}
			}
			return null;
		}

		internal void EnterElementContext()
		{
			m_ancestorStack.Add(new NamespaceFrame());
		}

		internal void ExitElementContext()
		{
			m_ancestorStack.RemoveAt(m_ancestorStack.Count - 1);
		}

		internal abstract void TrackNamespaceNode(XmlAttribute attr, SortedList nsListToRender, Hashtable nsLocallyDeclared);

		internal abstract void TrackXmlNamespaceNode(XmlAttribute attr, SortedList nsListToRender, SortedList attrListToRender, Hashtable nsLocallyDeclared);

		internal abstract void GetNamespacesToRender(XmlElement element, SortedList attrListToRender, SortedList nsListToRender, Hashtable nsLocallyDeclared);

		internal void LoadUnrenderedNamespaces(Hashtable nsLocallyDeclared)
		{
			object[] array = new object[nsLocallyDeclared.Count];
			nsLocallyDeclared.Values.CopyTo(array, 0);
			object[] array2 = array;
			foreach (object obj in array2)
			{
				AddUnrendered((XmlAttribute)obj);
			}
		}

		internal void LoadRenderedNamespaces(SortedList nsRenderedList)
		{
			foreach (object key in nsRenderedList.GetKeyList())
			{
				AddRendered((XmlAttribute)key);
			}
		}

		internal void AddRendered(XmlAttribute attr)
		{
			GetCurrentScope().AddRendered(attr);
		}

		internal void AddUnrendered(XmlAttribute attr)
		{
			GetCurrentScope().AddUnrendered(attr);
		}
	}
	internal class CanonicalXml
	{
		private CanonicalXmlDocument m_c14nDoc;

		private C14NAncestralNamespaceContextManager m_ancMgr;

		internal CanonicalXml(Stream inputStream, bool includeComments, XmlResolver resolver, string strBaseUri)
		{
			if (inputStream == null)
			{
				throw new ArgumentNullException("inputStream");
			}
			m_c14nDoc = new CanonicalXmlDocument(defaultNodeSetInclusionState: true, includeComments);
			m_c14nDoc.XmlResolver = resolver;
			m_c14nDoc.Load(Utils.PreProcessStreamInput(inputStream, resolver, strBaseUri));
			m_ancMgr = new C14NAncestralNamespaceContextManager();
		}

		internal CanonicalXml(XmlDocument document, XmlResolver resolver)
			: this(document, resolver, includeComments: false)
		{
		}

		internal CanonicalXml(XmlDocument document, XmlResolver resolver, bool includeComments)
		{
			if (document == null)
			{
				throw new ArgumentNullException("document");
			}
			m_c14nDoc = new CanonicalXmlDocument(defaultNodeSetInclusionState: true, includeComments);
			m_c14nDoc.XmlResolver = resolver;
			m_c14nDoc.Load(new XmlNodeReader(document));
			m_ancMgr = new C14NAncestralNamespaceContextManager();
		}

		internal CanonicalXml(XmlNodeList nodeList, XmlResolver resolver, bool includeComments)
		{
			if (nodeList == null)
			{
				throw new ArgumentNullException("nodeList");
			}
			XmlDocument ownerDocument = Utils.GetOwnerDocument(nodeList);
			if (ownerDocument == null)
			{
				throw new ArgumentException("nodeList");
			}
			m_c14nDoc = new CanonicalXmlDocument(defaultNodeSetInclusionState: false, includeComments);
			m_c14nDoc.XmlResolver = resolver;
			m_c14nDoc.Load(new XmlNodeReader(ownerDocument));
			m_ancMgr = new C14NAncestralNamespaceContextManager();
			MarkInclusionStateForNodes(nodeList, ownerDocument, m_c14nDoc);
		}

		private static void MarkNodeAsIncluded(XmlNode node)
		{
			if (node is ICanonicalizableNode)
			{
				((ICanonicalizableNode)node).IsInNodeSet = true;
			}
		}

		private static void MarkInclusionStateForNodes(XmlNodeList nodeList, XmlDocument inputRoot, XmlDocument root)
		{
			CanonicalXmlNodeList canonicalXmlNodeList = new CanonicalXmlNodeList();
			CanonicalXmlNodeList canonicalXmlNodeList2 = new CanonicalXmlNodeList();
			canonicalXmlNodeList.Add(inputRoot);
			canonicalXmlNodeList2.Add(root);
			int num = 0;
			do
			{
				XmlNode xmlNode = canonicalXmlNodeList[num];
				XmlNode xmlNode2 = canonicalXmlNodeList2[num];
				XmlNodeList childNodes = xmlNode.ChildNodes;
				XmlNodeList childNodes2 = xmlNode2.ChildNodes;
				for (int i = 0; i < childNodes.Count; i++)
				{
					canonicalXmlNodeList.Add(childNodes[i]);
					canonicalXmlNodeList2.Add(childNodes2[i]);
					if (Utils.NodeInList(childNodes[i], nodeList))
					{
						MarkNodeAsIncluded(childNodes2[i]);
					}
					XmlAttributeCollection attributes = childNodes[i].Attributes;
					if (attributes == null)
					{
						continue;
					}
					for (int j = 0; j < attributes.Count; j++)
					{
						if (Utils.NodeInList(attributes[j], nodeList))
						{
							MarkNodeAsIncluded(childNodes2[i].Attributes.Item(j));
						}
					}
				}
				num++;
			}
			while (num < canonicalXmlNodeList.Count);
		}

		internal byte[] GetBytes()
		{
			StringBuilder stringBuilder = new StringBuilder();
			m_c14nDoc.Write(stringBuilder, DocPosition.BeforeRootElement, m_ancMgr);
			UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			return uTF8Encoding.GetBytes(stringBuilder.ToString());
		}

		internal byte[] GetDigestedBytes(HashAlgorithm hash)
		{
			m_c14nDoc.WriteHash(hash, DocPosition.BeforeRootElement, m_ancMgr);
			hash.TransformFinalBlock(new byte[0], 0, 0);
			byte[] result = (byte[])hash.Hash.Clone();
			hash.Initialize();
			return result;
		}
	}
	internal class C14NAncestralNamespaceContextManager : AncestralNamespaceContextManager
	{
		internal C14NAncestralNamespaceContextManager()
		{
		}

		private void GetNamespaceToRender(string nsPrefix, SortedList attrListToRender, SortedList nsListToRender, Hashtable nsLocallyDeclared)
		{
			foreach (object key in nsListToRender.GetKeyList())
			{
				if (Utils.HasNamespacePrefix((XmlAttribute)key, nsPrefix))
				{
					return;
				}
			}
			foreach (object key2 in attrListToRender.GetKeyList())
			{
				if (((XmlAttribute)key2).LocalName.Equals(nsPrefix))
				{
					return;
				}
			}
			XmlAttribute xmlAttribute = (XmlAttribute)nsLocallyDeclared[nsPrefix];
			int depth;
			XmlAttribute nearestRenderedNamespaceWithMatchingPrefix = GetNearestRenderedNamespaceWithMatchingPrefix(nsPrefix, out depth);
			if (xmlAttribute != null)
			{
				if (Utils.IsNonRedundantNamespaceDecl(xmlAttribute, nearestRenderedNamespaceWithMatchingPrefix))
				{
					nsLocallyDeclared.Remove(nsPrefix);
					if (Utils.IsXmlNamespaceNode(xmlAttribute))
					{
						attrListToRender.Add(xmlAttribute, null);
					}
					else
					{
						nsListToRender.Add(xmlAttribute, null);
					}
				}
				return;
			}
			int depth2;
			XmlAttribute nearestUnrenderedNamespaceWithMatchingPrefix = GetNearestUnrenderedNamespaceWithMatchingPrefix(nsPrefix, out depth2);
			if (nearestUnrenderedNamespaceWithMatchingPrefix != null && depth2 > depth && Utils.IsNonRedundantNamespaceDecl(nearestUnrenderedNamespaceWithMatchingPrefix, nearestRenderedNamespaceWithMatchingPrefix))
			{
				if (Utils.IsXmlNamespaceNode(nearestUnrenderedNamespaceWithMatchingPrefix))
				{
					attrListToRender.Add(nearestUnrenderedNamespaceWithMatchingPrefix, null);
				}
				else
				{
					nsListToRender.Add(nearestUnrenderedNamespaceWithMatchingPrefix, null);
				}
			}
		}

		internal override void GetNamespacesToRender(XmlElement element, SortedList attrListToRender, SortedList nsListToRender, Hashtable nsLocallyDeclared)
		{
			XmlAttribute xmlAttribute = null;
			object[] array = new object[nsLocallyDeclared.Count];
			nsLocallyDeclared.Values.CopyTo(array, 0);
			object[] array2 = array;
			foreach (object obj in array2)
			{
				xmlAttribute = (XmlAttribute)obj;
				int depth;
				XmlAttribute nearestRenderedNamespaceWithMatchingPrefix = GetNearestRenderedNamespaceWithMatchingPrefix(Utils.GetNamespacePrefix(xmlAttribute), out depth);
				if (Utils.IsNonRedundantNamespaceDecl(xmlAttribute, nearestRenderedNamespaceWithMatchingPrefix))
				{
					nsLocallyDeclared.Remove(Utils.GetNamespacePrefix(xmlAttribute));
					if (Utils.IsXmlNamespaceNode(xmlAttribute))
					{
						attrListToRender.Add(xmlAttribute, null);
					}
					else
					{
						nsListToRender.Add(xmlAttribute, null);
					}
				}
			}
			for (int num = m_ancestorStack.Count - 1; num >= 0; num--)
			{
				foreach (object value in GetScopeAt(num).GetUnrendered().Values)
				{
					xmlAttribute = (XmlAttribute)value;
					if (xmlAttribute != null)
					{
						GetNamespaceToRender(Utils.GetNamespacePrefix(xmlAttribute), attrListToRender, nsListToRender, nsLocallyDeclared);
					}
				}
			}
		}

		internal override void TrackNamespaceNode(XmlAttribute attr, SortedList nsListToRender, Hashtable nsLocallyDeclared)
		{
			nsLocallyDeclared.Add(Utils.GetNamespacePrefix(attr), attr);
		}

		internal override void TrackXmlNamespaceNode(XmlAttribute attr, SortedList nsListToRender, SortedList attrListToRender, Hashtable nsLocallyDeclared)
		{
			nsLocallyDeclared.Add(Utils.GetNamespacePrefix(attr), attr);
		}
	}
	internal class ExcCanonicalXml
	{
		private CanonicalXmlDocument m_c14nDoc;

		private ExcAncestralNamespaceContextManager m_ancMgr;

		internal ExcCanonicalXml(Stream inputStream, bool includeComments, string inclusiveNamespacesPrefixList, XmlResolver resolver, string strBaseUri)
		{
			if (inputStream == null)
			{
				throw new ArgumentNullException("inputStream");
			}
			m_c14nDoc = new CanonicalXmlDocument(defaultNodeSetInclusionState: true, includeComments);
			m_c14nDoc.XmlResolver = resolver;
			m_c14nDoc.Load(Utils.PreProcessStreamInput(inputStream, resolver, strBaseUri));
			m_ancMgr = new ExcAncestralNamespaceContextManager(inclusiveNamespacesPrefixList);
		}

		internal ExcCanonicalXml(XmlDocument document, bool includeComments, string inclusiveNamespacesPrefixList, XmlResolver resolver)
		{
			if (document == null)
			{
				throw new ArgumentNullException("document");
			}
			m_c14nDoc = new CanonicalXmlDocument(defaultNodeSetInclusionState: true, includeComments);
			m_c14nDoc.XmlResolver = resolver;
			m_c14nDoc.Load(new XmlNodeReader(document));
			m_ancMgr = new ExcAncestralNamespaceContextManager(inclusiveNamespacesPrefixList);
		}

		internal ExcCanonicalXml(XmlNodeList nodeList, bool includeComments, string inclusiveNamespacesPrefixList, XmlResolver resolver)
		{
			if (nodeList == null)
			{
				throw new ArgumentNullException("nodeList");
			}
			XmlDocument ownerDocument = Utils.GetOwnerDocument(nodeList);
			if (ownerDocument == null)
			{
				throw new ArgumentException("nodeList");
			}
			m_c14nDoc = new CanonicalXmlDocument(defaultNodeSetInclusionState: false, includeComments);
			m_c14nDoc.XmlResolver = resolver;
			m_c14nDoc.Load(new XmlNodeReader(ownerDocument));
			m_ancMgr = new ExcAncestralNamespaceContextManager(inclusiveNamespacesPrefixList);
			MarkInclusionStateForNodes(nodeList, ownerDocument, m_c14nDoc);
		}

		internal byte[] GetBytes()
		{
			StringBuilder stringBuilder = new StringBuilder();
			m_c14nDoc.Write(stringBuilder, DocPosition.BeforeRootElement, m_ancMgr);
			UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			return uTF8Encoding.GetBytes(stringBuilder.ToString());
		}

		internal byte[] GetDigestedBytes(HashAlgorithm hash)
		{
			m_c14nDoc.WriteHash(hash, DocPosition.BeforeRootElement, m_ancMgr);
			hash.TransformFinalBlock(new byte[0], 0, 0);
			byte[] result = (byte[])hash.Hash.Clone();
			hash.Initialize();
			return result;
		}

		private static void MarkInclusionStateForNodes(XmlNodeList nodeList, XmlDocument inputRoot, XmlDocument root)
		{
			CanonicalXmlNodeList canonicalXmlNodeList = new CanonicalXmlNodeList();
			CanonicalXmlNodeList canonicalXmlNodeList2 = new CanonicalXmlNodeList();
			canonicalXmlNodeList.Add(inputRoot);
			canonicalXmlNodeList2.Add(root);
			int num = 0;
			do
			{
				XmlNode xmlNode = canonicalXmlNodeList[num];
				XmlNode xmlNode2 = canonicalXmlNodeList2[num];
				XmlNodeList childNodes = xmlNode.ChildNodes;
				XmlNodeList childNodes2 = xmlNode2.ChildNodes;
				for (int i = 0; i < childNodes.Count; i++)
				{
					canonicalXmlNodeList.Add(childNodes[i]);
					canonicalXmlNodeList2.Add(childNodes2[i]);
					if (Utils.NodeInList(childNodes[i], nodeList))
					{
						MarkNodeAsIncluded(childNodes2[i]);
					}
					XmlAttributeCollection attributes = childNodes[i].Attributes;
					if (attributes == null)
					{
						continue;
					}
					for (int j = 0; j < attributes.Count; j++)
					{
						if (Utils.NodeInList(attributes[j], nodeList))
						{
							MarkNodeAsIncluded(childNodes2[i].Attributes.Item(j));
						}
					}
				}
				num++;
			}
			while (num < canonicalXmlNodeList.Count);
		}

		private static void MarkNodeAsIncluded(XmlNode node)
		{
			if (node is ICanonicalizableNode)
			{
				((ICanonicalizableNode)node).IsInNodeSet = true;
			}
		}
	}
	internal class ExcAncestralNamespaceContextManager : AncestralNamespaceContextManager
	{
		private Hashtable m_inclusivePrefixSet;

		internal ExcAncestralNamespaceContextManager(string inclusiveNamespacesPrefixList)
		{
			m_inclusivePrefixSet = Utils.TokenizePrefixListString(inclusiveNamespacesPrefixList);
		}

		private bool HasNonRedundantInclusivePrefix(XmlAttribute attr)
		{
			string namespacePrefix = Utils.GetNamespacePrefix(attr);
			int depth;
			if (m_inclusivePrefixSet.ContainsKey(namespacePrefix))
			{
				return Utils.IsNonRedundantNamespaceDecl(attr, GetNearestRenderedNamespaceWithMatchingPrefix(namespacePrefix, out depth));
			}
			return false;
		}

		private void GatherNamespaceToRender(string nsPrefix, SortedList nsListToRender, Hashtable nsLocallyDeclared)
		{
			foreach (object key in nsListToRender.GetKeyList())
			{
				if (Utils.HasNamespacePrefix((XmlAttribute)key, nsPrefix))
				{
					return;
				}
			}
			XmlAttribute xmlAttribute = (XmlAttribute)nsLocallyDeclared[nsPrefix];
			int depth;
			XmlAttribute nearestRenderedNamespaceWithMatchingPrefix = GetNearestRenderedNamespaceWithMatchingPrefix(nsPrefix, out depth);
			if (xmlAttribute != null)
			{
				if (Utils.IsNonRedundantNamespaceDecl(xmlAttribute, nearestRenderedNamespaceWithMatchingPrefix))
				{
					nsLocallyDeclared.Remove(nsPrefix);
					nsListToRender.Add(xmlAttribute, null);
				}
			}
			else
			{
				int depth2;
				XmlAttribute nearestUnrenderedNamespaceWithMatchingPrefix = GetNearestUnrenderedNamespaceWithMatchingPrefix(nsPrefix, out depth2);
				if (nearestUnrenderedNamespaceWithMatchingPrefix != null && depth2 > depth && Utils.IsNonRedundantNamespaceDecl(nearestUnrenderedNamespaceWithMatchingPrefix, nearestRenderedNamespaceWithMatchingPrefix))
				{
					nsListToRender.Add(nearestUnrenderedNamespaceWithMatchingPrefix, null);
				}
			}
		}

		internal override void GetNamespacesToRender(XmlElement element, SortedList attrListToRender, SortedList nsListToRender, Hashtable nsLocallyDeclared)
		{
			GatherNamespaceToRender(element.Prefix, nsListToRender, nsLocallyDeclared);
			foreach (object key in attrListToRender.GetKeyList())
			{
				string prefix = ((XmlAttribute)key).Prefix;
				if (prefix.Length > 0)
				{
					GatherNamespaceToRender(prefix, nsListToRender, nsLocallyDeclared);
				}
			}
		}

		internal override void TrackNamespaceNode(XmlAttribute attr, SortedList nsListToRender, Hashtable nsLocallyDeclared)
		{
			if (!Utils.IsXmlPrefixDefinitionNode(attr))
			{
				if (HasNonRedundantInclusivePrefix(attr))
				{
					nsListToRender.Add(attr, null);
				}
				else
				{
					nsLocallyDeclared.Add(Utils.GetNamespacePrefix(attr), attr);
				}
			}
		}

		internal override void TrackXmlNamespaceNode(XmlAttribute attr, SortedList nsListToRender, SortedList attrListToRender, Hashtable nsLocallyDeclared)
		{
			attrListToRender.Add(attr, null);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class DataObject
	{
		private string m_id;

		private string m_mimeType;

		private string m_encoding;

		private CanonicalXmlNodeList m_elData;

		private XmlElement m_cachedXml;

		public string Id
		{
			get
			{
				return m_id;
			}
			set
			{
				m_id = value;
				m_cachedXml = null;
			}
		}

		public string MimeType
		{
			get
			{
				return m_mimeType;
			}
			set
			{
				m_mimeType = value;
				m_cachedXml = null;
			}
		}

		public string Encoding
		{
			get
			{
				return m_encoding;
			}
			set
			{
				m_encoding = value;
				m_cachedXml = null;
			}
		}

		public XmlNodeList Data
		{
			get
			{
				return m_elData;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				m_elData = new CanonicalXmlNodeList();
				foreach (XmlNode item in value)
				{
					m_elData.Add(item);
				}
				m_cachedXml = null;
			}
		}

		private bool CacheValid => m_cachedXml != null;

		public DataObject()
		{
			m_cachedXml = null;
			m_elData = new CanonicalXmlNodeList();
		}

		public DataObject(string id, string mimeType, string encoding, XmlElement data)
		{
			if (data == null)
			{
				throw new ArgumentNullException("data");
			}
			m_id = id;
			m_mimeType = mimeType;
			m_encoding = encoding;
			m_elData = new CanonicalXmlNodeList();
			m_elData.Add(data);
			m_cachedXml = null;
		}

		public XmlElement GetXml()
		{
			if (CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("Object", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(m_id))
			{
				xmlElement.SetAttribute("Id", m_id);
			}
			if (!string.IsNullOrEmpty(m_mimeType))
			{
				xmlElement.SetAttribute("MimeType", m_mimeType);
			}
			if (!string.IsNullOrEmpty(m_encoding))
			{
				xmlElement.SetAttribute("Encoding", m_encoding);
			}
			if (m_elData != null)
			{
				foreach (XmlNode elDatum in m_elData)
				{
					xmlElement.AppendChild(document.ImportNode(elDatum, deep: true));
				}
				return xmlElement;
			}
			return xmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2000/09/xmldsig#");
			m_mimeType = Utils.GetAttribute(value, "MimeType", "http://www.w3.org/2000/09/xmldsig#");
			m_encoding = Utils.GetAttribute(value, "Encoding", "http://www.w3.org/2000/09/xmldsig#");
			foreach (XmlNode childNode in value.ChildNodes)
			{
				m_elData.Add(childNode);
			}
			m_cachedXml = value;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class KeyInfo : IEnumerable
	{
		private string m_id;

		private ArrayList m_KeyInfoClauses;

		public string Id
		{
			get
			{
				return m_id;
			}
			set
			{
				m_id = value;
			}
		}

		public int Count => m_KeyInfoClauses.Count;

		public KeyInfo()
		{
			m_KeyInfoClauses = new ArrayList();
		}

		public XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument xmlDocument)
		{
			XmlElement xmlElement = xmlDocument.CreateElement("KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(m_id))
			{
				xmlElement.SetAttribute("Id", m_id);
			}
			for (int i = 0; i < m_KeyInfoClauses.Count; i++)
			{
				XmlElement xml = ((KeyInfoClause)m_KeyInfoClauses[i]).GetXml(xmlDocument);
				if (xml != null)
				{
					xmlElement.AppendChild(xml);
				}
			}
			return xmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2000/09/xmldsig#");
			if (!Utils.VerifyAttributes(value, "Id"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "KeyInfo");
			}
			for (XmlNode xmlNode = value.FirstChild; xmlNode != null; xmlNode = xmlNode.NextSibling)
			{
				if (xmlNode is XmlElement xmlElement)
				{
					string text = xmlElement.NamespaceURI + " " + xmlElement.LocalName;
					if (text == "http://www.w3.org/2000/09/xmldsig# KeyValue")
					{
						if (!Utils.VerifyAttributes(xmlElement, (string[])null))
						{
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "KeyInfo/KeyValue");
						}
						XmlNodeList childNodes = xmlElement.ChildNodes;
						foreach (XmlNode item in childNodes)
						{
							if (item is XmlElement xmlElement2)
							{
								text = text + "/" + xmlElement2.LocalName;
								break;
							}
						}
					}
					KeyInfoClause keyInfoClause = Utils.CreateFromName<KeyInfoClause>(text);
					if (keyInfoClause == null)
					{
						keyInfoClause = new KeyInfoNode();
					}
					keyInfoClause.LoadXml(xmlElement);
					AddClause(keyInfoClause);
				}
			}
		}

		public void AddClause(KeyInfoClause clause)
		{
			m_KeyInfoClauses.Add(clause);
		}

		public IEnumerator GetEnumerator()
		{
			return m_KeyInfoClauses.GetEnumerator();
		}

		public IEnumerator GetEnumerator(Type requestedObjectType)
		{
			ArrayList arrayList = new ArrayList();
			IEnumerator enumerator = m_KeyInfoClauses.GetEnumerator();
			while (enumerator.MoveNext())
			{
				object current = enumerator.Current;
				if (requestedObjectType.Equals(current.GetType()))
				{
					arrayList.Add(current);
				}
			}
			return arrayList.GetEnumerator();
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public abstract class KeyInfoClause
	{
		public abstract XmlElement GetXml();

		internal virtual XmlElement GetXml(XmlDocument xmlDocument)
		{
			XmlElement xml = GetXml();
			return (XmlElement)xmlDocument.ImportNode(xml, deep: true);
		}

		public abstract void LoadXml(XmlElement element);
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class KeyInfoName : KeyInfoClause
	{
		private string m_keyName;

		public string Value
		{
			get
			{
				return m_keyName;
			}
			set
			{
				m_keyName = value;
			}
		}

		public KeyInfoName()
			: this(null)
		{
		}

		public KeyInfoName(string keyName)
		{
			Value = keyName;
		}

		public override XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal override XmlElement GetXml(XmlDocument xmlDocument)
		{
			XmlElement xmlElement = xmlDocument.CreateElement("KeyName", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement.AppendChild(xmlDocument.CreateTextNode(m_keyName));
			return xmlElement;
		}

		public override void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_keyName = value.InnerText.Trim();
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class DSAKeyValue : KeyInfoClause
	{
		private DSA m_key;

		public DSA Key
		{
			get
			{
				return m_key;
			}
			set
			{
				m_key = value;
			}
		}

		public DSAKeyValue()
		{
			m_key = DSA.Create();
		}

		public DSAKeyValue(DSA key)
		{
			m_key = key;
		}

		public override XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal override XmlElement GetXml(XmlDocument xmlDocument)
		{
			DSAParameters dSAParameters = m_key.ExportParameters(includePrivateParameters: false);
			XmlElement xmlElement = xmlDocument.CreateElement("KeyValue", "http://www.w3.org/2000/09/xmldsig#");
			XmlElement xmlElement2 = xmlDocument.CreateElement("DSAKeyValue", "http://www.w3.org/2000/09/xmldsig#");
			XmlElement xmlElement3 = xmlDocument.CreateElement("P", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement3.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(dSAParameters.P)));
			xmlElement2.AppendChild(xmlElement3);
			XmlElement xmlElement4 = xmlDocument.CreateElement("Q", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement4.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(dSAParameters.Q)));
			xmlElement2.AppendChild(xmlElement4);
			XmlElement xmlElement5 = xmlDocument.CreateElement("G", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement5.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(dSAParameters.G)));
			xmlElement2.AppendChild(xmlElement5);
			XmlElement xmlElement6 = xmlDocument.CreateElement("Y", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement6.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(dSAParameters.Y)));
			xmlElement2.AppendChild(xmlElement6);
			if (dSAParameters.J != null)
			{
				XmlElement xmlElement7 = xmlDocument.CreateElement("J", "http://www.w3.org/2000/09/xmldsig#");
				xmlElement7.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(dSAParameters.J)));
				xmlElement2.AppendChild(xmlElement7);
			}
			if (dSAParameters.Seed != null)
			{
				XmlElement xmlElement8 = xmlDocument.CreateElement("Seed", "http://www.w3.org/2000/09/xmldsig#");
				xmlElement8.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(dSAParameters.Seed)));
				xmlElement2.AppendChild(xmlElement8);
				XmlElement xmlElement9 = xmlDocument.CreateElement("PgenCounter", "http://www.w3.org/2000/09/xmldsig#");
				xmlElement9.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(Utils.ConvertIntToByteArray(dSAParameters.Counter))));
				xmlElement2.AppendChild(xmlElement9);
			}
			xmlElement.AppendChild(xmlElement2);
			return xmlElement;
		}

		public override void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_key.FromXmlString(value.OuterXml);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class RSAKeyValue : KeyInfoClause
	{
		private RSA m_key;

		public RSA Key
		{
			get
			{
				return m_key;
			}
			set
			{
				m_key = value;
			}
		}

		public RSAKeyValue()
		{
			m_key = RSA.Create();
		}

		public RSAKeyValue(RSA key)
		{
			m_key = key;
		}

		public override XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal override XmlElement GetXml(XmlDocument xmlDocument)
		{
			RSAParameters rSAParameters = m_key.ExportParameters(includePrivateParameters: false);
			XmlElement xmlElement = xmlDocument.CreateElement("KeyValue", "http://www.w3.org/2000/09/xmldsig#");
			XmlElement xmlElement2 = xmlDocument.CreateElement("RSAKeyValue", "http://www.w3.org/2000/09/xmldsig#");
			XmlElement xmlElement3 = xmlDocument.CreateElement("Modulus", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement3.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(rSAParameters.Modulus)));
			xmlElement2.AppendChild(xmlElement3);
			XmlElement xmlElement4 = xmlDocument.CreateElement("Exponent", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement4.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(rSAParameters.Exponent)));
			xmlElement2.AppendChild(xmlElement4);
			xmlElement.AppendChild(xmlElement2);
			return xmlElement;
		}

		public override void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_key.FromXmlString(value.OuterXml);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class KeyInfoRetrievalMethod : KeyInfoClause
	{
		private string m_uri;

		private string m_type;

		public string Uri
		{
			get
			{
				return m_uri;
			}
			set
			{
				m_uri = value;
			}
		}

		[ComVisible(false)]
		public string Type
		{
			get
			{
				return m_type;
			}
			set
			{
				m_type = value;
			}
		}

		public KeyInfoRetrievalMethod()
		{
		}

		public KeyInfoRetrievalMethod(string strUri)
		{
			m_uri = strUri;
		}

		public KeyInfoRetrievalMethod(string strUri, string typeName)
		{
			m_uri = strUri;
			m_type = typeName;
		}

		public override XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal override XmlElement GetXml(XmlDocument xmlDocument)
		{
			XmlElement xmlElement = xmlDocument.CreateElement("RetrievalMethod", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(m_uri))
			{
				xmlElement.SetAttribute("URI", m_uri);
			}
			if (!string.IsNullOrEmpty(m_type))
			{
				xmlElement.SetAttribute("Type", m_type);
			}
			return xmlElement;
		}

		public override void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_uri = Utils.GetAttribute(value, "URI", "http://www.w3.org/2000/09/xmldsig#");
			m_type = Utils.GetAttribute(value, "Type", "http://www.w3.org/2000/09/xmldsig#");
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class KeyInfoEncryptedKey : KeyInfoClause
	{
		private EncryptedKey m_encryptedKey;

		public EncryptedKey EncryptedKey
		{
			get
			{
				return m_encryptedKey;
			}
			set
			{
				m_encryptedKey = value;
			}
		}

		public KeyInfoEncryptedKey()
		{
		}

		public KeyInfoEncryptedKey(EncryptedKey encryptedKey)
		{
			m_encryptedKey = encryptedKey;
		}

		public override XmlElement GetXml()
		{
			if (m_encryptedKey == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "KeyInfoEncryptedKey");
			}
			return m_encryptedKey.GetXml();
		}

		internal override XmlElement GetXml(XmlDocument xmlDocument)
		{
			if (m_encryptedKey == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "KeyInfoEncryptedKey");
			}
			return m_encryptedKey.GetXml(xmlDocument);
		}

		public override void LoadXml(XmlElement value)
		{
			m_encryptedKey = new EncryptedKey();
			m_encryptedKey.LoadXml(value);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public struct X509IssuerSerial
	{
		private string issuerName;

		private string serialNumber;

		public string IssuerName
		{
			get
			{
				return issuerName;
			}
			set
			{
				issuerName = value;
			}
		}

		public string SerialNumber
		{
			get
			{
				return serialNumber;
			}
			set
			{
				serialNumber = value;
			}
		}

		internal X509IssuerSerial(string issuerName, string serialNumber)
		{
			if (issuerName == null || issuerName.Length == 0)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Arg_EmptyOrNullString"), "issuerName");
			}
			if (serialNumber == null || serialNumber.Length == 0)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Arg_EmptyOrNullString"), "serialNumber");
			}
			this.issuerName = issuerName;
			this.serialNumber = serialNumber;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class KeyInfoX509Data : KeyInfoClause
	{
		private ArrayList m_certificates;

		private ArrayList m_issuerSerials;

		private ArrayList m_subjectKeyIds;

		private ArrayList m_subjectNames;

		private byte[] m_CRL;

		public ArrayList Certificates => m_certificates;

		public ArrayList SubjectKeyIds => m_subjectKeyIds;

		public ArrayList SubjectNames => m_subjectNames;

		public ArrayList IssuerSerials => m_issuerSerials;

		public byte[] CRL
		{
			get
			{
				return m_CRL;
			}
			set
			{
				m_CRL = value;
			}
		}

		public KeyInfoX509Data()
		{
		}

		public KeyInfoX509Data(byte[] rgbCert)
		{
			X509Certificate2 certificate = new X509Certificate2(rgbCert);
			AddCertificate(certificate);
		}

		public KeyInfoX509Data(X509Certificate cert)
		{
			AddCertificate(cert);
		}

		public KeyInfoX509Data(X509Certificate cert, X509IncludeOption includeOption)
		{
			if (cert == null)
			{
				throw new ArgumentNullException("cert");
			}
			X509Certificate2 certificate = new X509Certificate2(cert);
			X509ChainElementCollection x509ChainElementCollection = null;
			X509Chain x509Chain = null;
			switch (includeOption)
			{
			case X509IncludeOption.ExcludeRoot:
			{
				x509Chain = new X509Chain();
				x509Chain.Build(certificate);
				if (x509Chain.ChainStatus.Length > 0 && (x509Chain.ChainStatus[0].Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain)
				{
					throw new CryptographicException(-2146762486);
				}
				x509ChainElementCollection = x509Chain.ChainElements;
				for (int i = 0; i < (System.Security.Cryptography.X509Certificates.X509Utils.IsSelfSigned(x509Chain) ? 1 : (x509ChainElementCollection.Count - 1)); i++)
				{
					AddCertificate(x509ChainElementCollection[i].Certificate);
				}
				break;
			}
			case X509IncludeOption.EndCertOnly:
				AddCertificate(certificate);
				break;
			case X509IncludeOption.WholeChain:
			{
				x509Chain = new X509Chain();
				x509Chain.Build(certificate);
				if (x509Chain.ChainStatus.Length > 0 && (x509Chain.ChainStatus[0].Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain)
				{
					throw new CryptographicException(-2146762486);
				}
				x509ChainElementCollection = x509Chain.ChainElements;
				X509ChainElementEnumerator enumerator = x509ChainElementCollection.GetEnumerator();
				while (enumerator.MoveNext())
				{
					X509ChainElement current = enumerator.Current;
					AddCertificate(current.Certificate);
				}
				break;
			}
			}
		}

		public void AddCertificate(X509Certificate certificate)
		{
			if (certificate == null)
			{
				throw new ArgumentNullException("certificate");
			}
			if (m_certificates == null)
			{
				m_certificates = new ArrayList();
			}
			X509Certificate2 value = new X509Certificate2(certificate);
			m_certificates.Add(value);
		}

		public void AddSubjectKeyId(byte[] subjectKeyId)
		{
			if (m_subjectKeyIds == null)
			{
				m_subjectKeyIds = new ArrayList();
			}
			m_subjectKeyIds.Add(subjectKeyId);
		}

		[ComVisible(false)]
		public void AddSubjectKeyId(string subjectKeyId)
		{
			if (m_subjectKeyIds == null)
			{
				m_subjectKeyIds = new ArrayList();
			}
			m_subjectKeyIds.Add(System.Security.Cryptography.X509Certificates.X509Utils.DecodeHexString(subjectKeyId));
		}

		public void AddSubjectName(string subjectName)
		{
			if (m_subjectNames == null)
			{
				m_subjectNames = new ArrayList();
			}
			m_subjectNames.Add(subjectName);
		}

		public void AddIssuerSerial(string issuerName, string serialNumber)
		{
			BigInt bigInt = new BigInt();
			bigInt.FromHexadecimal(serialNumber);
			if (m_issuerSerials == null)
			{
				m_issuerSerials = new ArrayList();
			}
			m_issuerSerials.Add(new X509IssuerSerial(issuerName, bigInt.ToDecimal()));
		}

		internal void InternalAddIssuerSerial(string issuerName, string serialNumber)
		{
			if (m_issuerSerials == null)
			{
				m_issuerSerials = new ArrayList();
			}
			m_issuerSerials.Add(new X509IssuerSerial(issuerName, serialNumber));
		}

		private void Clear()
		{
			m_CRL = null;
			if (m_subjectKeyIds != null)
			{
				m_subjectKeyIds.Clear();
			}
			if (m_subjectNames != null)
			{
				m_subjectNames.Clear();
			}
			if (m_issuerSerials != null)
			{
				m_issuerSerials.Clear();
			}
			if (m_certificates != null)
			{
				m_certificates.Clear();
			}
		}

		public override XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal override XmlElement GetXml(XmlDocument xmlDocument)
		{
			XmlElement xmlElement = xmlDocument.CreateElement("X509Data", "http://www.w3.org/2000/09/xmldsig#");
			if (m_issuerSerials != null)
			{
				foreach (X509IssuerSerial issuerSerial in m_issuerSerials)
				{
					XmlElement xmlElement2 = xmlDocument.CreateElement("X509IssuerSerial", "http://www.w3.org/2000/09/xmldsig#");
					XmlElement xmlElement3 = xmlDocument.CreateElement("X509IssuerName", "http://www.w3.org/2000/09/xmldsig#");
					xmlElement3.AppendChild(xmlDocument.CreateTextNode(issuerSerial.IssuerName));
					xmlElement2.AppendChild(xmlElement3);
					XmlElement xmlElement4 = xmlDocument.CreateElement("X509SerialNumber", "http://www.w3.org/2000/09/xmldsig#");
					xmlElement4.AppendChild(xmlDocument.CreateTextNode(issuerSerial.SerialNumber));
					xmlElement2.AppendChild(xmlElement4);
					xmlElement.AppendChild(xmlElement2);
				}
			}
			if (m_subjectKeyIds != null)
			{
				foreach (byte[] subjectKeyId in m_subjectKeyIds)
				{
					XmlElement xmlElement5 = xmlDocument.CreateElement("X509SKI", "http://www.w3.org/2000/09/xmldsig#");
					xmlElement5.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(subjectKeyId)));
					xmlElement.AppendChild(xmlElement5);
				}
			}
			if (m_subjectNames != null)
			{
				foreach (string subjectName in m_subjectNames)
				{
					XmlElement xmlElement6 = xmlDocument.CreateElement("X509SubjectName", "http://www.w3.org/2000/09/xmldsig#");
					xmlElement6.AppendChild(xmlDocument.CreateTextNode(subjectName));
					xmlElement.AppendChild(xmlElement6);
				}
			}
			if (m_certificates != null)
			{
				foreach (X509Certificate certificate in m_certificates)
				{
					XmlElement xmlElement7 = xmlDocument.CreateElement("X509Certificate", "http://www.w3.org/2000/09/xmldsig#");
					xmlElement7.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(certificate.GetRawCertData())));
					xmlElement.AppendChild(xmlElement7);
				}
			}
			if (m_CRL != null)
			{
				XmlElement xmlElement8 = xmlDocument.CreateElement("X509CRL", "http://www.w3.org/2000/09/xmldsig#");
				xmlElement8.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(m_CRL)));
				xmlElement.AppendChild(xmlElement8);
			}
			return xmlElement;
		}

		public override void LoadXml(XmlElement element)
		{
			if (element == null)
			{
				throw new ArgumentNullException("element");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(element.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			XmlNodeList xmlNodeList = element.SelectNodes("ds:X509IssuerSerial", xmlNamespaceManager);
			XmlNodeList xmlNodeList2 = element.SelectNodes("ds:X509SKI", xmlNamespaceManager);
			XmlNodeList xmlNodeList3 = element.SelectNodes("ds:X509SubjectName", xmlNamespaceManager);
			XmlNodeList xmlNodeList4 = element.SelectNodes("ds:X509Certificate", xmlNamespaceManager);
			XmlNodeList xmlNodeList5 = element.SelectNodes("ds:X509CRL", xmlNamespaceManager);
			if (xmlNodeList5.Count == 0 && xmlNodeList.Count == 0 && xmlNodeList2.Count == 0 && xmlNodeList3.Count == 0 && xmlNodeList4.Count == 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "X509Data");
			}
			Clear();
			if (xmlNodeList5.Count != 0)
			{
				m_CRL = Convert.FromBase64String(Utils.DiscardWhiteSpaces(xmlNodeList5.Item(0).InnerText));
			}
			foreach (XmlNode item in xmlNodeList)
			{
				XmlNode xmlNode2 = item.SelectSingleNode("ds:X509IssuerName", xmlNamespaceManager);
				XmlNode xmlNode3 = item.SelectSingleNode("ds:X509SerialNumber", xmlNamespaceManager);
				if (xmlNode2 == null || xmlNode3 == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "IssuerSerial");
				}
				InternalAddIssuerSerial(xmlNode2.InnerText.Trim(), xmlNode3.InnerText.Trim());
			}
			foreach (XmlNode item2 in xmlNodeList2)
			{
				AddSubjectKeyId(Convert.FromBase64String(Utils.DiscardWhiteSpaces(item2.InnerText)));
			}
			foreach (XmlNode item3 in xmlNodeList3)
			{
				AddSubjectName(item3.InnerText.Trim());
			}
			foreach (XmlNode item4 in xmlNodeList4)
			{
				AddCertificate(new X509Certificate2(Convert.FromBase64String(Utils.DiscardWhiteSpaces(item4.InnerText))));
			}
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class KeyInfoNode : KeyInfoClause
	{
		private XmlElement m_node;

		public XmlElement Value
		{
			get
			{
				return m_node;
			}
			set
			{
				m_node = value;
			}
		}

		public KeyInfoNode()
		{
		}

		public KeyInfoNode(XmlElement node)
		{
			m_node = node;
		}

		public override XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal override XmlElement GetXml(XmlDocument xmlDocument)
		{
			return xmlDocument.ImportNode(m_node, deep: true) as XmlElement;
		}

		public override void LoadXml(XmlElement value)
		{
			m_node = value;
		}
	}
	[Serializable]
	internal enum ReferenceTargetType
	{
		Stream,
		XmlElement,
		UriReference
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class Reference
	{
		private string m_id;

		private string m_uri;

		private string m_type;

		private TransformChain m_transformChain;

		private string m_digestMethod;

		private byte[] m_digestValue;

		private HashAlgorithm m_hashAlgorithm;

		private object m_refTarget;

		private ReferenceTargetType m_refTargetType;

		private XmlElement m_cachedXml;

		private SignedXml m_signedXml;

		internal CanonicalXmlNodeList m_namespaces;

		public string Id
		{
			get
			{
				return m_id;
			}
			set
			{
				m_id = value;
			}
		}

		public string Uri
		{
			get
			{
				return m_uri;
			}
			set
			{
				m_uri = value;
				m_cachedXml = null;
			}
		}

		public string Type
		{
			get
			{
				return m_type;
			}
			set
			{
				m_type = value;
				m_cachedXml = null;
			}
		}

		public string DigestMethod
		{
			get
			{
				return m_digestMethod;
			}
			set
			{
				m_digestMethod = value;
				m_cachedXml = null;
			}
		}

		public byte[] DigestValue
		{
			get
			{
				return m_digestValue;
			}
			set
			{
				m_digestValue = value;
				m_cachedXml = null;
			}
		}

		public TransformChain TransformChain
		{
			get
			{
				if (m_transformChain == null)
				{
					m_transformChain = new TransformChain();
				}
				return m_transformChain;
			}
			[ComVisible(false)]
			set
			{
				m_transformChain = value;
				m_cachedXml = null;
			}
		}

		internal bool CacheValid => m_cachedXml != null;

		internal SignedXml SignedXml
		{
			get
			{
				return m_signedXml;
			}
			set
			{
				m_signedXml = value;
			}
		}

		internal ReferenceTargetType ReferenceTargetType => m_refTargetType;

		public Reference()
		{
			m_transformChain = new TransformChain();
			m_refTarget = null;
			m_refTargetType = ReferenceTargetType.UriReference;
			m_cachedXml = null;
			m_digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
		}

		public Reference(Stream stream)
		{
			m_transformChain = new TransformChain();
			m_refTarget = stream;
			m_refTargetType = ReferenceTargetType.Stream;
			m_cachedXml = null;
			m_digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
		}

		public Reference(string uri)
		{
			m_transformChain = new TransformChain();
			m_refTarget = uri;
			m_uri = uri;
			m_refTargetType = ReferenceTargetType.UriReference;
			m_cachedXml = null;
			m_digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
		}

		internal Reference(XmlElement element)
		{
			m_transformChain = new TransformChain();
			m_refTarget = element;
			m_refTargetType = ReferenceTargetType.XmlElement;
			m_cachedXml = null;
			m_digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
		}

		public XmlElement GetXml()
		{
			if (CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("Reference", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(m_id))
			{
				xmlElement.SetAttribute("Id", m_id);
			}
			if (m_uri != null)
			{
				xmlElement.SetAttribute("URI", m_uri);
			}
			if (!string.IsNullOrEmpty(m_type))
			{
				xmlElement.SetAttribute("Type", m_type);
			}
			if (TransformChain.Count != 0)
			{
				xmlElement.AppendChild(TransformChain.GetXml(document, "http://www.w3.org/2000/09/xmldsig#"));
			}
			if (string.IsNullOrEmpty(m_digestMethod))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_DigestMethodRequired"));
			}
			XmlElement xmlElement2 = document.CreateElement("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement2.SetAttribute("Algorithm", m_digestMethod);
			xmlElement.AppendChild(xmlElement2);
			if (DigestValue == null)
			{
				if (m_hashAlgorithm.Hash == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_DigestValueRequired"));
				}
				DigestValue = m_hashAlgorithm.Hash;
			}
			XmlElement xmlElement3 = document.CreateElement("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement3.AppendChild(document.CreateTextNode(Convert.ToBase64String(m_digestValue)));
			xmlElement.AppendChild(xmlElement3);
			return xmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2000/09/xmldsig#");
			m_uri = Utils.GetAttribute(value, "URI", "http://www.w3.org/2000/09/xmldsig#");
			m_type = Utils.GetAttribute(value, "Type", "http://www.w3.org/2000/09/xmldsig#");
			if (!Utils.VerifyAttributes(value, new string[3] { "Id", "URI", "Type" }))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			bool flag = false;
			TransformChain = new TransformChain();
			XmlNodeList xmlNodeList = value.SelectNodes("ds:Transforms", xmlNamespaceManager);
			if (xmlNodeList != null && xmlNodeList.Count != 0)
			{
				if (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList.Count > 1)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/Transforms");
				}
				flag = true;
				XmlElement xmlElement = xmlNodeList[0] as XmlElement;
				if (!Utils.VerifyAttributes(xmlElement, (string[])null))
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/Transforms");
				}
				XmlNodeList xmlNodeList2 = xmlElement.SelectNodes("ds:Transform", xmlNamespaceManager);
				if (xmlNodeList2 != null)
				{
					if (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList2.Count != xmlElement.SelectNodes("*").Count)
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/Transforms");
					}
					if (xmlNodeList2.Count > Utils.GetMaxTransformsPerReference())
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/Transforms");
					}
					foreach (XmlNode item in xmlNodeList2)
					{
						XmlElement xmlElement2 = item as XmlElement;
						string attribute = Utils.GetAttribute(xmlElement2, "Algorithm", "http://www.w3.org/2000/09/xmldsig#");
						if ((attribute == null && !Utils.GetSkipSignatureAttributeEnforcement()) || !Utils.VerifyAttributes(xmlElement2, "Algorithm"))
						{
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
						}
						Transform transform = Utils.CreateFromName<Transform>(attribute);
						if (transform == null)
						{
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
						}
						AddTransform(transform);
						transform.LoadInnerXml(xmlElement2.ChildNodes);
						if (!(transform is XmlDsigEnvelopedSignatureTransform))
						{
							continue;
						}
						XmlNode xmlNode2 = xmlElement2.SelectSingleNode("ancestor::ds:Signature[1]", xmlNamespaceManager);
						XmlNodeList xmlNodeList3 = xmlElement2.SelectNodes("//ds:Signature", xmlNamespaceManager);
						if (xmlNodeList3 == null)
						{
							continue;
						}
						int num = 0;
						foreach (XmlNode item2 in xmlNodeList3)
						{
							num++;
							if (item2 == xmlNode2)
							{
								((XmlDsigEnvelopedSignatureTransform)transform).SignaturePosition = num;
								break;
							}
						}
					}
				}
			}
			XmlNodeList xmlNodeList4 = value.SelectNodes("ds:DigestMethod", xmlNamespaceManager);
			if (xmlNodeList4 == null || xmlNodeList4.Count == 0 || (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList4.Count > 1))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/DigestMethod");
			}
			XmlElement element = xmlNodeList4[0] as XmlElement;
			m_digestMethod = Utils.GetAttribute(element, "Algorithm", "http://www.w3.org/2000/09/xmldsig#");
			if ((m_digestMethod == null && !Utils.GetSkipSignatureAttributeEnforcement()) || !Utils.VerifyAttributes(element, "Algorithm"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/DigestMethod");
			}
			XmlNodeList xmlNodeList5 = value.SelectNodes("ds:DigestValue", xmlNamespaceManager);
			if (xmlNodeList5 == null || xmlNodeList5.Count == 0 || (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList5.Count > 1))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/DigestValue");
			}
			XmlElement xmlElement3 = xmlNodeList5[0] as XmlElement;
			m_digestValue = Convert.FromBase64String(Utils.DiscardWhiteSpaces(xmlElement3.InnerText));
			if (!Utils.VerifyAttributes(xmlElement3, (string[])null))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference/DigestValue");
			}
			int num2 = (flag ? 3 : 2);
			if (!Utils.GetAllowAdditionalSignatureNodes() && value.SelectNodes("*").Count != num2)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Reference");
			}
			m_cachedXml = value;
		}

		public void AddTransform(Transform transform)
		{
			if (transform == null)
			{
				throw new ArgumentNullException("transform");
			}
			transform.Reference = this;
			TransformChain.Add(transform);
		}

		internal void UpdateHashValue(XmlDocument document, CanonicalXmlNodeList refList)
		{
			DigestValue = CalculateHashValue(document, refList);
		}

		internal byte[] CalculateHashValue(XmlDocument document, CanonicalXmlNodeList refList)
		{
			m_hashAlgorithm = Utils.CreateFromName<HashAlgorithm>(m_digestMethod);
			if (m_hashAlgorithm == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CreateHashAlgorithmFailed"));
			}
			string text = ((document == null) ? (Environment.CurrentDirectory + "\\") : document.BaseURI);
			Stream stream = null;
			WebRequest webRequest = null;
			WebResponse webResponse = null;
			Stream stream2 = null;
			XmlResolver xmlResolver = null;
			byte[] array = null;
			try
			{
				switch (m_refTargetType)
				{
				case ReferenceTargetType.Stream:
					xmlResolver = (SignedXml.ResolverSet ? SignedXml.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
					stream = TransformChain.TransformToOctetStream((Stream)m_refTarget, xmlResolver, text);
					break;
				case ReferenceTargetType.UriReference:
					if (m_uri == null)
					{
						xmlResolver = (SignedXml.ResolverSet ? SignedXml.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
						stream = TransformChain.TransformToOctetStream((Stream)null, xmlResolver, text);
						break;
					}
					if (m_uri.Length == 0)
					{
						if (document == null)
						{
							throw new CryptographicException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Cryptography_Xml_SelfReferenceRequiresContext"), m_uri));
						}
						xmlResolver = (SignedXml.ResolverSet ? SignedXml.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
						XmlDocument document2 = Utils.DiscardComments(Utils.PreProcessDocumentInput(document, xmlResolver, text));
						stream = TransformChain.TransformToOctetStream(document2, xmlResolver, text);
						break;
					}
					if (m_uri[0] == '#')
					{
						bool discardComments = true;
						string idFromLocalUri = Utils.GetIdFromLocalUri(m_uri, out discardComments);
						if (idFromLocalUri == "xpointer(/)")
						{
							if (document == null)
							{
								throw new CryptographicException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Cryptography_Xml_SelfReferenceRequiresContext"), m_uri));
							}
							xmlResolver = (SignedXml.ResolverSet ? SignedXml.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
							stream = TransformChain.TransformToOctetStream(Utils.PreProcessDocumentInput(document, xmlResolver, text), xmlResolver, text);
							break;
						}
						XmlElement xmlElement = SignedXml.GetIdElement(document, idFromLocalUri);
						if (xmlElement != null)
						{
							m_namespaces = Utils.GetPropagatedAttributes(xmlElement.ParentNode as XmlElement);
						}
						if (xmlElement == null && refList != null)
						{
							foreach (XmlNode @ref in refList)
							{
								if (@ref is XmlElement xmlElement2 && Utils.HasAttribute(xmlElement2, "Id", "http://www.w3.org/2000/09/xmldsig#") && Utils.GetAttribute(xmlElement2, "Id", "http://www.w3.org/2000/09/xmldsig#").Equals(idFromLocalUri))
								{
									xmlElement = xmlElement2;
									if (m_signedXml.m_context != null)
									{
										m_namespaces = Utils.GetPropagatedAttributes(m_signedXml.m_context);
									}
									break;
								}
							}
						}
						if (xmlElement == null)
						{
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidReference"));
						}
						XmlDocument xmlDocument = Utils.PreProcessElementInput(xmlElement, xmlResolver, text);
						Utils.AddNamespaces(xmlDocument.DocumentElement, m_namespaces);
						xmlResolver = (SignedXml.ResolverSet ? SignedXml.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
						if (discardComments)
						{
							XmlDocument document3 = Utils.DiscardComments(xmlDocument);
							stream = TransformChain.TransformToOctetStream(document3, xmlResolver, text);
						}
						else
						{
							stream = TransformChain.TransformToOctetStream(xmlDocument, xmlResolver, text);
						}
						break;
					}
					if (Utils.AllowDetachedSignature())
					{
						Uri uri = new Uri(m_uri, UriKind.RelativeOrAbsolute);
						if (!uri.IsAbsoluteUri)
						{
							uri = new Uri(new Uri(text), uri);
						}
						webRequest = WebRequest.Create(uri);
						if (webRequest != null)
						{
							webResponse = webRequest.GetResponse();
							if (webResponse != null)
							{
								stream2 = webResponse.GetResponseStream();
								if (stream2 != null)
								{
									xmlResolver = (SignedXml.ResolverSet ? SignedXml.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
									stream = TransformChain.TransformToOctetStream(stream2, xmlResolver, m_uri);
									break;
								}
							}
						}
						goto default;
					}
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotResolved"), m_uri);
				case ReferenceTargetType.XmlElement:
					xmlResolver = (SignedXml.ResolverSet ? SignedXml.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
					stream = TransformChain.TransformToOctetStream(Utils.PreProcessElementInput((XmlElement)m_refTarget, xmlResolver, text), xmlResolver, text);
					break;
				default:
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotResolved"), m_uri);
				}
				return m_hashAlgorithm.ComputeHash(stream);
			}
			finally
			{
				stream?.Close();
				webResponse?.Close();
				stream2?.Close();
			}
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class Signature
	{
		private string m_id;

		private SignedInfo m_signedInfo;

		private byte[] m_signatureValue;

		private string m_signatureValueId;

		private KeyInfo m_keyInfo;

		private IList m_embeddedObjects;

		private CanonicalXmlNodeList m_referencedItems;

		private SignedXml m_signedXml;

		internal SignedXml SignedXml
		{
			get
			{
				return m_signedXml;
			}
			set
			{
				m_signedXml = value;
			}
		}

		public string Id
		{
			get
			{
				return m_id;
			}
			set
			{
				m_id = value;
			}
		}

		public SignedInfo SignedInfo
		{
			get
			{
				return m_signedInfo;
			}
			set
			{
				m_signedInfo = value;
				if (SignedXml != null && m_signedInfo != null)
				{
					m_signedInfo.SignedXml = SignedXml;
				}
			}
		}

		public byte[] SignatureValue
		{
			get
			{
				return m_signatureValue;
			}
			set
			{
				m_signatureValue = value;
			}
		}

		public KeyInfo KeyInfo
		{
			get
			{
				if (m_keyInfo == null)
				{
					m_keyInfo = new KeyInfo();
				}
				return m_keyInfo;
			}
			set
			{
				m_keyInfo = value;
			}
		}

		public IList ObjectList
		{
			get
			{
				return m_embeddedObjects;
			}
			set
			{
				m_embeddedObjects = value;
			}
		}

		internal CanonicalXmlNodeList ReferencedItems => m_referencedItems;

		public Signature()
		{
			m_embeddedObjects = new ArrayList();
			m_referencedItems = new CanonicalXmlNodeList();
		}

		public XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(m_id))
			{
				xmlElement.SetAttribute("Id", m_id);
			}
			if (m_signedInfo == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignedInfoRequired"));
			}
			xmlElement.AppendChild(m_signedInfo.GetXml(document));
			if (m_signatureValue == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignatureValueRequired"));
			}
			XmlElement xmlElement2 = document.CreateElement("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement2.AppendChild(document.CreateTextNode(Convert.ToBase64String(m_signatureValue)));
			if (!string.IsNullOrEmpty(m_signatureValueId))
			{
				xmlElement2.SetAttribute("Id", m_signatureValueId);
			}
			xmlElement.AppendChild(xmlElement2);
			if (KeyInfo.Count > 0)
			{
				xmlElement.AppendChild(KeyInfo.GetXml(document));
			}
			foreach (object embeddedObject in m_embeddedObjects)
			{
				if (embeddedObject is DataObject dataObject)
				{
					xmlElement.AppendChild(dataObject.GetXml(document));
				}
			}
			return xmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!value.LocalName.Equals("Signature"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Signature");
			}
			m_id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2000/09/xmldsig#");
			if (!Utils.VerifyAttributes(value, "Id"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Signature");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			int num = 0;
			XmlNodeList xmlNodeList = value.SelectNodes("ds:SignedInfo", xmlNamespaceManager);
			if (xmlNodeList == null || xmlNodeList.Count == 0 || (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList.Count > 1))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo");
			}
			XmlElement value2 = xmlNodeList[0] as XmlElement;
			num += xmlNodeList.Count;
			SignedInfo = new SignedInfo();
			SignedInfo.LoadXml(value2);
			XmlNodeList xmlNodeList2 = value.SelectNodes("ds:SignatureValue", xmlNamespaceManager);
			if (xmlNodeList2 == null || xmlNodeList2.Count == 0 || (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList2.Count > 1))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignatureValue");
			}
			XmlElement xmlElement = xmlNodeList2[0] as XmlElement;
			num += xmlNodeList2.Count;
			m_signatureValue = Convert.FromBase64String(Utils.DiscardWhiteSpaces(xmlElement.InnerText));
			m_signatureValueId = Utils.GetAttribute(xmlElement, "Id", "http://www.w3.org/2000/09/xmldsig#");
			if (!Utils.VerifyAttributes(xmlElement, "Id"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignatureValue");
			}
			XmlNodeList xmlNodeList3 = value.SelectNodes("ds:KeyInfo", xmlNamespaceManager);
			m_keyInfo = new KeyInfo();
			if (xmlNodeList3 != null)
			{
				if (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList3.Count > 1)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "KeyInfo");
				}
				foreach (XmlNode item in xmlNodeList3)
				{
					if (item is XmlElement value3)
					{
						m_keyInfo.LoadXml(value3);
					}
				}
				num += xmlNodeList3.Count;
			}
			XmlNodeList xmlNodeList4 = value.SelectNodes("ds:Object", xmlNamespaceManager);
			m_embeddedObjects.Clear();
			if (xmlNodeList4 != null)
			{
				foreach (XmlNode item2 in xmlNodeList4)
				{
					if (item2 is XmlElement value4)
					{
						DataObject dataObject = new DataObject();
						dataObject.LoadXml(value4);
						m_embeddedObjects.Add(dataObject);
					}
				}
				num += xmlNodeList4.Count;
			}
			XmlNodeList xmlNodeList5 = value.SelectNodes("//*[@Id]", xmlNamespaceManager);
			if (xmlNodeList5 != null)
			{
				foreach (XmlNode item3 in xmlNodeList5)
				{
					m_referencedItems.Add(item3);
				}
			}
			if (!Utils.GetAllowAdditionalSignatureNodes() && value.SelectNodes("*").Count != num)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Signature");
			}
		}

		public void AddObject(DataObject dataObject)
		{
			m_embeddedObjects.Add(dataObject);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class SignedInfo : ICollection, IEnumerable
	{
		private string m_id;

		private string m_canonicalizationMethod;

		private string m_signatureMethod;

		private string m_signatureLength;

		private ArrayList m_references;

		private XmlElement m_cachedXml;

		private SignedXml m_signedXml;

		private Transform m_canonicalizationMethodTransform;

		internal SignedXml SignedXml
		{
			get
			{
				return m_signedXml;
			}
			set
			{
				m_signedXml = value;
			}
		}

		public int Count
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public bool IsReadOnly
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public bool IsSynchronized
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public object SyncRoot
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public string Id
		{
			get
			{
				return m_id;
			}
			set
			{
				m_id = value;
				m_cachedXml = null;
			}
		}

		public string CanonicalizationMethod
		{
			get
			{
				if (m_canonicalizationMethod == null)
				{
					return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
				}
				return m_canonicalizationMethod;
			}
			set
			{
				m_canonicalizationMethod = value;
				m_cachedXml = null;
			}
		}

		[ComVisible(false)]
		public Transform CanonicalizationMethodObject
		{
			get
			{
				if (m_canonicalizationMethodTransform == null)
				{
					m_canonicalizationMethodTransform = Utils.CreateFromName<Transform>(CanonicalizationMethod);
					if (m_canonicalizationMethodTransform == null)
					{
						throw new CryptographicException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Cryptography_Xml_CreateTransformFailed"), CanonicalizationMethod));
					}
					m_canonicalizationMethodTransform.SignedXml = SignedXml;
					m_canonicalizationMethodTransform.Reference = null;
				}
				return m_canonicalizationMethodTransform;
			}
		}

		public string SignatureMethod
		{
			get
			{
				return m_signatureMethod;
			}
			set
			{
				m_signatureMethod = value;
				m_cachedXml = null;
			}
		}

		public string SignatureLength
		{
			get
			{
				return m_signatureLength;
			}
			set
			{
				m_signatureLength = value;
				m_cachedXml = null;
			}
		}

		public ArrayList References => m_references;

		internal bool CacheValid
		{
			get
			{
				if (m_cachedXml == null)
				{
					return false;
				}
				foreach (Reference reference in References)
				{
					if (!reference.CacheValid)
					{
						return false;
					}
				}
				return true;
			}
		}

		public SignedInfo()
		{
			m_references = new ArrayList();
		}

		public IEnumerator GetEnumerator()
		{
			throw new NotSupportedException();
		}

		public void CopyTo(Array array, int index)
		{
			throw new NotSupportedException();
		}

		public XmlElement GetXml()
		{
			if (CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("SignedInfo", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(m_id))
			{
				xmlElement.SetAttribute("Id", m_id);
			}
			XmlElement xml = CanonicalizationMethodObject.GetXml(document, "CanonicalizationMethod");
			xmlElement.AppendChild(xml);
			if (string.IsNullOrEmpty(m_signatureMethod))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignatureMethodRequired"));
			}
			XmlElement xmlElement2 = document.CreateElement("SignatureMethod", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement2.SetAttribute("Algorithm", m_signatureMethod);
			if (m_signatureLength != null)
			{
				XmlElement xmlElement3 = document.CreateElement(null, "HMACOutputLength", "http://www.w3.org/2000/09/xmldsig#");
				XmlText newChild = document.CreateTextNode(m_signatureLength);
				xmlElement3.AppendChild(newChild);
				xmlElement2.AppendChild(xmlElement3);
			}
			xmlElement.AppendChild(xmlElement2);
			if (m_references.Count == 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_ReferenceElementRequired"));
			}
			for (int i = 0; i < m_references.Count; i++)
			{
				Reference reference = (Reference)m_references[i];
				xmlElement.AppendChild(reference.GetXml(document));
			}
			return xmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!value.LocalName.Equals("SignedInfo"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			int num = 0;
			m_id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2000/09/xmldsig#");
			if (!Utils.VerifyAttributes(value, "Id"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo");
			}
			XmlNodeList xmlNodeList = value.SelectNodes("ds:CanonicalizationMethod", xmlNamespaceManager);
			if (xmlNodeList == null || xmlNodeList.Count == 0 || (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList.Count > 1))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo/CanonicalizationMethod");
			}
			XmlElement xmlElement = xmlNodeList.Item(0) as XmlElement;
			num += xmlNodeList.Count;
			m_canonicalizationMethod = Utils.GetAttribute(xmlElement, "Algorithm", "http://www.w3.org/2000/09/xmldsig#");
			if ((!Utils.GetSkipSignatureAttributeEnforcement() && m_canonicalizationMethod == null) || !Utils.VerifyAttributes(xmlElement, "Algorithm"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo/CanonicalizationMethod");
			}
			m_canonicalizationMethodTransform = null;
			if (xmlElement.ChildNodes.Count > 0)
			{
				CanonicalizationMethodObject.LoadInnerXml(xmlElement.ChildNodes);
			}
			XmlNodeList xmlNodeList2 = value.SelectNodes("ds:SignatureMethod", xmlNamespaceManager);
			if (xmlNodeList2 == null || xmlNodeList2.Count == 0 || (!Utils.GetAllowAdditionalSignatureNodes() && xmlNodeList2.Count > 1))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo/SignatureMethod");
			}
			XmlElement xmlElement2 = xmlNodeList2.Item(0) as XmlElement;
			num += xmlNodeList2.Count;
			m_signatureMethod = Utils.GetAttribute(xmlElement2, "Algorithm", "http://www.w3.org/2000/09/xmldsig#");
			if ((!Utils.GetSkipSignatureAttributeEnforcement() && m_signatureMethod == null) || !Utils.VerifyAttributes(xmlElement2, "Algorithm"))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo/SignatureMethod");
			}
			if (xmlElement2.SelectSingleNode("ds:HMACOutputLength", xmlNamespaceManager) is XmlElement xmlElement3)
			{
				m_signatureLength = xmlElement3.InnerXml;
			}
			m_references.Clear();
			XmlNodeList xmlNodeList3 = value.SelectNodes("ds:Reference", xmlNamespaceManager);
			if (xmlNodeList3 != null)
			{
				if (xmlNodeList3.Count > Utils.GetMaxReferencesPerSignedInfo())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo/Reference");
				}
				foreach (XmlNode item in xmlNodeList3)
				{
					XmlElement value2 = item as XmlElement;
					Reference reference = new Reference();
					AddReference(reference);
					reference.LoadXml(value2);
				}
				num += xmlNodeList3.Count;
			}
			if (!Utils.GetAllowAdditionalSignatureNodes() && value.SelectNodes("*").Count != num)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "SignedInfo");
			}
			m_cachedXml = value;
		}

		public void AddReference(Reference reference)
		{
			if (reference == null)
			{
				throw new ArgumentNullException("reference");
			}
			reference.SignedXml = SignedXml;
			m_references.Add(reference);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class SignedXml
	{
		private class ReferenceLevelSortOrder : IComparer
		{
			private ArrayList m_references;

			public ArrayList References
			{
				get
				{
					return m_references;
				}
				set
				{
					m_references = value;
				}
			}

			public int Compare(object a, object b)
			{
				Reference reference = a as Reference;
				Reference reference2 = b as Reference;
				int index = 0;
				int index2 = 0;
				int num = 0;
				foreach (Reference reference3 in References)
				{
					if (reference3 == reference)
					{
						index = num;
					}
					if (reference3 == reference2)
					{
						index2 = num;
					}
					num++;
				}
				int referenceLevel = reference.SignedXml.GetReferenceLevel(index, References);
				int referenceLevel2 = reference2.SignedXml.GetReferenceLevel(index2, References);
				return referenceLevel.CompareTo(referenceLevel2);
			}
		}

		private const string XmlDsigMoreHMACMD5Url = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";

		private const string XmlDsigMoreHMACSHA256Url = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";

		private const string XmlDsigMoreHMACSHA384Url = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";

		private const string XmlDsigMoreHMACSHA512Url = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";

		private const string XmlDsigMoreHMACRIPEMD160Url = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";

		public const string XmlDsigNamespaceUrl = "http://www.w3.org/2000/09/xmldsig#";

		public const string XmlDsigMinimalCanonicalizationUrl = "http://www.w3.org/2000/09/xmldsig#minimal";

		public const string XmlDsigCanonicalizationUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

		public const string XmlDsigCanonicalizationWithCommentsUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

		public const string XmlDsigSHA1Url = "http://www.w3.org/2000/09/xmldsig#sha1";

		public const string XmlDsigDSAUrl = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";

		public const string XmlDsigRSASHA1Url = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

		internal const string XmlDsigSHA256Url = "http://www.w3.org/2001/04/xmlenc#sha256";

		internal const string XmlDsigRSASHA256Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

		internal const string XmlDsigSHA384Url = "http://www.w3.org/2001/04/xmldsig-more#sha384";

		internal const string XmlDsigRSASHA384Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

		internal const string XmlDsigSHA512Url = "http://www.w3.org/2001/04/xmlenc#sha512";

		internal const string XmlDsigRSASHA512Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

		public const string XmlDsigHMACSHA1Url = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

		public const string XmlDsigC14NTransformUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

		public const string XmlDsigC14NWithCommentsTransformUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

		public const string XmlDsigExcC14NTransformUrl = "http://www.w3.org/2001/10/xml-exc-c14n#";

		public const string XmlDsigExcC14NWithCommentsTransformUrl = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

		public const string XmlDsigBase64TransformUrl = "http://www.w3.org/2000/09/xmldsig#base64";

		public const string XmlDsigXPathTransformUrl = "http://www.w3.org/TR/1999/REC-xpath-19991116";

		public const string XmlDsigXsltTransformUrl = "http://www.w3.org/TR/1999/REC-xslt-19991116";

		public const string XmlDsigEnvelopedSignatureTransformUrl = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

		public const string XmlDecryptionTransformUrl = "http://www.w3.org/2002/07/decrypt#XML";

		public const string XmlLicenseTransformUrl = "urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform";

		private const string AllowHMACTruncationValue = "AllowHMACTruncation";

		protected Signature m_signature;

		protected string m_strSigningKeyName;

		private AsymmetricAlgorithm m_signingKey;

		private XmlDocument m_containingDocument;

		private IEnumerator m_keyInfoEnum;

		private X509Certificate2Collection m_x509Collection;

		private IEnumerator m_x509Enum;

		private bool[] m_refProcessed;

		private int[] m_refLevelCache;

		internal XmlResolver m_xmlResolver;

		internal XmlElement m_context;

		private bool m_bResolverSet;

		private EncryptedXml m_exml;

		private static bool? s_allowHmacTruncation;

		private static List<string> s_safeCanonicalizationMethods;

		private static List<string> s_defaultSafeTransformMethods;

		private bool bCacheValid;

		private byte[] _digestedSignedInfo;

		public string SigningKeyName
		{
			get
			{
				return m_strSigningKeyName;
			}
			set
			{
				m_strSigningKeyName = value;
			}
		}

		[ComVisible(false)]
		public XmlResolver Resolver
		{
			set
			{
				m_xmlResolver = value;
				m_bResolverSet = true;
			}
		}

		internal bool ResolverSet => m_bResolverSet;

		public AsymmetricAlgorithm SigningKey
		{
			get
			{
				return m_signingKey;
			}
			set
			{
				m_signingKey = value;
			}
		}

		[ComVisible(false)]
		public EncryptedXml EncryptedXml
		{
			get
			{
				if (m_exml == null)
				{
					m_exml = new EncryptedXml(m_containingDocument);
				}
				return m_exml;
			}
			set
			{
				m_exml = value;
			}
		}

		public Signature Signature => m_signature;

		public SignedInfo SignedInfo => m_signature.SignedInfo;

		public string SignatureMethod => m_signature.SignedInfo.SignatureMethod;

		public string SignatureLength => m_signature.SignedInfo.SignatureLength;

		public byte[] SignatureValue => m_signature.SignatureValue;

		public KeyInfo KeyInfo
		{
			get
			{
				return m_signature.KeyInfo;
			}
			set
			{
				m_signature.KeyInfo = value;
			}
		}

		private static bool AllowHmacTruncation
		{
			get
			{
				if (!s_allowHmacTruncation.HasValue)
				{
					s_allowHmacTruncation = ReadHmacTruncationSetting();
				}
				return s_allowHmacTruncation.Value;
			}
		}

		private static IList<string> SafeCanonicalizationMethods
		{
			get
			{
				if (s_safeCanonicalizationMethods == null)
				{
					List<string> list = ReadAdditionalSafeCanonicalizationMethods();
					list.Add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
					list.Add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
					list.Add("http://www.w3.org/2001/10/xml-exc-c14n#");
					list.Add("http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
					s_safeCanonicalizationMethods = list;
				}
				return s_safeCanonicalizationMethods;
			}
		}

		private static IList<string> DefaultSafeTransformMethods
		{
			get
			{
				if (s_defaultSafeTransformMethods == null)
				{
					List<string> list = ReadAdditionalSafeTransformMethods();
					list.Add("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
					list.Add("http://www.w3.org/2000/09/xmldsig#base64");
					list.Add("urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform");
					list.Add("http://www.w3.org/2002/07/decrypt#XML");
					s_defaultSafeTransformMethods = list;
				}
				return s_defaultSafeTransformMethods;
			}
		}

		public SignedXml()
		{
			Initialize(null);
		}

		public SignedXml(XmlDocument document)
		{
			if (document == null)
			{
				throw new ArgumentNullException("document");
			}
			Initialize(document.DocumentElement);
		}

		public SignedXml(XmlElement elem)
		{
			if (elem == null)
			{
				throw new ArgumentNullException("elem");
			}
			Initialize(elem);
		}

		private void Initialize(XmlElement element)
		{
			m_containingDocument = element?.OwnerDocument;
			m_context = element;
			m_signature = new Signature();
			m_signature.SignedXml = this;
			m_signature.SignedInfo = new SignedInfo();
			m_signingKey = null;
		}

		public XmlElement GetXml()
		{
			if (m_containingDocument != null)
			{
				return m_signature.GetXml(m_containingDocument);
			}
			return m_signature.GetXml();
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			m_signature.LoadXml(value);
			m_context = value;
			bCacheValid = false;
		}

		public void AddReference(Reference reference)
		{
			m_signature.SignedInfo.AddReference(reference);
		}

		public void AddObject(DataObject dataObject)
		{
			m_signature.AddObject(dataObject);
		}

		public bool CheckSignature()
		{
			bool flag = false;
			AsymmetricAlgorithm publicKey;
			do
			{
				publicKey = GetPublicKey();
				if (publicKey != null)
				{
					flag = CheckSignature(publicKey);
				}
			}
			while (publicKey != null && !flag);
			return flag;
		}

		public bool CheckSignatureReturningKey(out AsymmetricAlgorithm signingKey)
		{
			bool flag = false;
			AsymmetricAlgorithm asymmetricAlgorithm = null;
			do
			{
				asymmetricAlgorithm = GetPublicKey();
				if (asymmetricAlgorithm != null)
				{
					flag = CheckSignature(asymmetricAlgorithm);
				}
			}
			while (asymmetricAlgorithm != null && !flag);
			signingKey = asymmetricAlgorithm;
			return flag;
		}

		public bool CheckSignature(AsymmetricAlgorithm key)
		{
			if (!DefaultSignatureFormatValidator(this))
			{
				return false;
			}
			if (!CheckSignedInfo(key))
			{
				return false;
			}
			return CheckDigestedReferences();
		}

		public bool CheckSignature(KeyedHashAlgorithm macAlg)
		{
			if (!DefaultSignatureFormatValidator(this))
			{
				return false;
			}
			if (!CheckSignedInfo(macAlg))
			{
				return false;
			}
			return CheckDigestedReferences();
		}

		[ComVisible(false)]
		public bool CheckSignature(X509Certificate2 certificate, bool verifySignatureOnly)
		{
			if (!verifySignatureOnly)
			{
				X509ExtensionEnumerator enumerator = certificate.Extensions.GetEnumerator();
				while (enumerator.MoveNext())
				{
					X509Extension current = enumerator.Current;
					if (string.Compare(current.Oid.Value, "2.5.29.15", StringComparison.OrdinalIgnoreCase) == 0)
					{
						X509KeyUsageExtension x509KeyUsageExtension = new X509KeyUsageExtension();
						x509KeyUsageExtension.CopyFrom(current);
						if ((x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0 || (x509KeyUsageExtension.KeyUsages & X509KeyUsageFlags.NonRepudiation) != 0)
						{
							break;
						}
						return false;
					}
				}
				X509Chain x509Chain = new X509Chain();
				x509Chain.ChainPolicy.ExtraStore.AddRange(BuildBagOfCerts());
				if (!x509Chain.Build(certificate))
				{
					return false;
				}
			}
			if (!DefaultSignatureFormatValidator(this))
			{
				return false;
			}
			if (!CheckSignedInfo(certificate.PublicKey.Key))
			{
				return false;
			}
			if (!CheckDigestedReferences())
			{
				return false;
			}
			return true;
		}

		public void ComputeSignature()
		{
			BuildDigestedReferences();
			AsymmetricAlgorithm signingKey = SigningKey;
			if (signingKey == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_LoadKeyFailed"));
			}
			if (SignedInfo.SignatureMethod == null)
			{
				if (signingKey is DSA)
				{
					SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
				}
				else
				{
					if (!(signingKey is RSA))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CreatedKeyFailed"));
					}
					if (SignedInfo.SignatureMethod == null)
					{
						SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
					}
				}
			}
			SignatureDescription signatureDescription = CreateSignatureDescriptionFromName(SignedInfo.SignatureMethod);
			if (signatureDescription == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignatureDescriptionNotCreated"));
			}
			HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
			if (hashAlgorithm == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CreateHashAlgorithmFailed"));
			}
			GetC14NDigest(hashAlgorithm);
			AsymmetricSignatureFormatter asymmetricSignatureFormatter = signatureDescription.CreateFormatter(signingKey);
			m_signature.SignatureValue = asymmetricSignatureFormatter.CreateSignature(hashAlgorithm);
		}

		public void ComputeSignature(KeyedHashAlgorithm macAlg)
		{
			if (macAlg == null)
			{
				throw new ArgumentNullException("macAlg");
			}
			if (!(macAlg is HMAC hMAC))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignatureMethodKeyMismatch"));
			}
			int num = ((m_signature.SignedInfo.SignatureLength != null) ? Convert.ToInt32(m_signature.SignedInfo.SignatureLength, null) : hMAC.HashSize);
			if (num < 0 || num > hMAC.HashSize)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidSignatureLength"));
			}
			if (num % 8 != 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidSignatureLength2"));
			}
			BuildDigestedReferences();
			switch (hMAC.HashName)
			{
			case "SHA1":
				SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
				break;
			case "SHA256":
				SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
				break;
			case "SHA384":
				SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
				break;
			case "SHA512":
				SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
				break;
			case "MD5":
				SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";
				break;
			case "RIPEMD160":
				SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";
				break;
			default:
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignatureMethodKeyMismatch"));
			}
			byte[] c14NDigest = GetC14NDigest(hMAC);
			m_signature.SignatureValue = new byte[num / 8];
			Buffer.BlockCopy(c14NDigest, 0, m_signature.SignatureValue, 0, num / 8);
		}

		protected virtual AsymmetricAlgorithm GetPublicKey()
		{
			if (KeyInfo == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_KeyInfoRequired"));
			}
			if (m_x509Enum != null)
			{
				AsymmetricAlgorithm nextCertificatePublicKey = GetNextCertificatePublicKey();
				if (nextCertificatePublicKey != null)
				{
					return nextCertificatePublicKey;
				}
			}
			if (m_keyInfoEnum == null)
			{
				m_keyInfoEnum = KeyInfo.GetEnumerator();
			}
			while (m_keyInfoEnum.MoveNext())
			{
				if (m_keyInfoEnum.Current is RSAKeyValue rSAKeyValue)
				{
					return rSAKeyValue.Key;
				}
				if (m_keyInfoEnum.Current is DSAKeyValue dSAKeyValue)
				{
					return dSAKeyValue.Key;
				}
				if (!(m_keyInfoEnum.Current is KeyInfoX509Data keyInfoX509Data))
				{
					continue;
				}
				m_x509Collection = Utils.BuildBagOfCerts(keyInfoX509Data, CertUsageType.Verification);
				if (m_x509Collection.Count > 0)
				{
					m_x509Enum = m_x509Collection.GetEnumerator();
					AsymmetricAlgorithm nextCertificatePublicKey2 = GetNextCertificatePublicKey();
					if (nextCertificatePublicKey2 != null)
					{
						return nextCertificatePublicKey2;
					}
				}
			}
			return null;
		}

		private X509Certificate2Collection BuildBagOfCerts()
		{
			X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
			if (KeyInfo != null)
			{
				foreach (KeyInfoClause item in KeyInfo)
				{
					if (item is KeyInfoX509Data keyInfoX509Data)
					{
						x509Certificate2Collection.AddRange(Utils.BuildBagOfCerts(keyInfoX509Data, CertUsageType.Verification));
					}
				}
				return x509Certificate2Collection;
			}
			return x509Certificate2Collection;
		}

		private AsymmetricAlgorithm GetNextCertificatePublicKey()
		{
			while (m_x509Enum.MoveNext())
			{
				X509Certificate2 x509Certificate = (X509Certificate2)m_x509Enum.Current;
				if (x509Certificate != null)
				{
					return x509Certificate.PublicKey.Key;
				}
			}
			return null;
		}

		public virtual XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			return DefaultGetIdElement(document, idValue);
		}

		internal static XmlElement DefaultGetIdElement(XmlDocument document, string idValue)
		{
			if (document == null)
			{
				return null;
			}
			if (Utils.RequireNCNameIdentifier())
			{
				try
				{
					XmlConvert.VerifyNCName(idValue);
				}
				catch (XmlException)
				{
					return null;
				}
			}
			XmlElement elementById = document.GetElementById(idValue);
			if (elementById != null)
			{
				if (!Utils.AllowAmbiguousReferenceTargets())
				{
					XmlDocument xmlDocument = (XmlDocument)document.CloneNode(deep: true);
					XmlElement elementById2 = xmlDocument.GetElementById(idValue);
					if (elementById2 != null)
					{
						elementById2.Attributes.RemoveAll();
						XmlElement elementById3 = xmlDocument.GetElementById(idValue);
						if (elementById3 != null)
						{
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidReference"));
						}
					}
				}
				return elementById;
			}
			elementById = GetSingleReferenceTarget(document, "Id", idValue);
			if (elementById != null)
			{
				return elementById;
			}
			elementById = GetSingleReferenceTarget(document, "id", idValue);
			if (elementById != null)
			{
				return elementById;
			}
			return GetSingleReferenceTarget(document, "ID", idValue);
		}

		private byte[] GetC14NDigest(HashAlgorithm hash)
		{
			if (!bCacheValid || !SignedInfo.CacheValid)
			{
				string text = ((m_containingDocument == null) ? null : m_containingDocument.BaseURI);
				XmlResolver xmlResolver = (m_bResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), text));
				XmlDocument xmlDocument = Utils.PreProcessElementInput(SignedInfo.GetXml(), xmlResolver, text);
				CanonicalXmlNodeList namespaces = ((m_context == null) ? null : Utils.GetPropagatedAttributes(m_context));
				Utils.AddNamespaces(xmlDocument.DocumentElement, namespaces);
				Transform canonicalizationMethodObject = SignedInfo.CanonicalizationMethodObject;
				canonicalizationMethodObject.Resolver = xmlResolver;
				canonicalizationMethodObject.BaseURI = text;
				canonicalizationMethodObject.LoadInput(xmlDocument);
				_digestedSignedInfo = canonicalizationMethodObject.GetDigestedOutput(hash);
				bCacheValid = true;
			}
			return _digestedSignedInfo;
		}

		private int GetReferenceLevel(int index, ArrayList references)
		{
			if (m_refProcessed[index])
			{
				return m_refLevelCache[index];
			}
			m_refProcessed[index] = true;
			Reference reference = (Reference)references[index];
			if (reference.Uri == null || reference.Uri.Length == 0 || (reference.Uri.Length > 0 && reference.Uri[0] != '#'))
			{
				m_refLevelCache[index] = 0;
				return 0;
			}
			if (reference.Uri.Length > 0 && reference.Uri[0] == '#')
			{
				string text = Utils.ExtractIdFromLocalUri(reference.Uri);
				if (text == "xpointer(/)")
				{
					m_refLevelCache[index] = 0;
					return 0;
				}
				for (int i = 0; i < references.Count; i++)
				{
					if (((Reference)references[i]).Id == text)
					{
						m_refLevelCache[index] = GetReferenceLevel(i, references) + 1;
						return m_refLevelCache[index];
					}
				}
				m_refLevelCache[index] = 0;
				return 0;
			}
			throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidReference"));
		}

		private void BuildDigestedReferences()
		{
			ArrayList references = SignedInfo.References;
			m_refProcessed = new bool[references.Count];
			m_refLevelCache = new int[references.Count];
			ReferenceLevelSortOrder referenceLevelSortOrder = new ReferenceLevelSortOrder();
			referenceLevelSortOrder.References = references;
			ArrayList arrayList = new ArrayList();
			foreach (Reference item in references)
			{
				arrayList.Add(item);
			}
			arrayList.Sort(referenceLevelSortOrder);
			CanonicalXmlNodeList canonicalXmlNodeList = new CanonicalXmlNodeList();
			foreach (DataObject @object in m_signature.ObjectList)
			{
				canonicalXmlNodeList.Add(@object.GetXml());
			}
			foreach (Reference item2 in arrayList)
			{
				if (item2.DigestMethod == null)
				{
					item2.DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
				}
				item2.UpdateHashValue(m_containingDocument, canonicalXmlNodeList);
				if (item2.Id != null)
				{
					canonicalXmlNodeList.Add(item2.GetXml());
				}
			}
		}

		private bool CheckDigestedReferences()
		{
			ArrayList references = m_signature.SignedInfo.References;
			for (int i = 0; i < references.Count; i++)
			{
				Reference reference = (Reference)references[i];
				if (!ReferenceUsesSafeTransformMethods(reference))
				{
					return false;
				}
				byte[] array = null;
				try
				{
					array = reference.CalculateHashValue(m_containingDocument, m_signature.ReferencedItems);
				}
				catch (CryptoSignedXmlRecursionException)
				{
					return false;
				}
				if (!CryptographicEquals(array, reference.DigestValue))
				{
					return false;
				}
			}
			return true;
		}

		private static bool CryptographicEquals(byte[] a, byte[] b)
		{
			int num = 0;
			if (a.Length != b.Length)
			{
				return false;
			}
			int num2 = a.Length;
			for (int i = 0; i < num2; i++)
			{
				num |= a[i] - b[i];
			}
			return 0 == num;
		}

		private bool CheckSignedInfo(AsymmetricAlgorithm key)
		{
			if (key == null)
			{
				throw new ArgumentNullException("key");
			}
			SignatureDescription signatureDescription = CreateSignatureDescriptionFromName(SignatureMethod);
			if (signatureDescription == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignatureDescriptionNotCreated"));
			}
			Type type = Type.GetType(signatureDescription.KeyAlgorithm);
			Type type2 = key.GetType();
			if (type != type2 && !type.IsSubclassOf(type2) && !type2.IsSubclassOf(type))
			{
				return false;
			}
			HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
			if (hashAlgorithm == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CreateHashAlgorithmFailed"));
			}
			byte[] c14NDigest = GetC14NDigest(hashAlgorithm);
			AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = signatureDescription.CreateDeformatter(key);
			return asymmetricSignatureDeformatter.VerifySignature(c14NDigest, m_signature.SignatureValue);
		}

		private bool CheckSignedInfo(KeyedHashAlgorithm macAlg)
		{
			if (macAlg == null)
			{
				throw new ArgumentNullException("macAlg");
			}
			int num = ((m_signature.SignedInfo.SignatureLength != null) ? Convert.ToInt32(m_signature.SignedInfo.SignatureLength, null) : macAlg.HashSize);
			if (num < 0 || num > macAlg.HashSize)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidSignatureLength"));
			}
			if (num % 8 != 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidSignatureLength2"));
			}
			if (m_signature.SignatureValue == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_SignatureValueRequired"));
			}
			if (m_signature.SignatureValue.Length != num / 8)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidSignatureLength"));
			}
			byte[] c14NDigest = GetC14NDigest(macAlg);
			for (int i = 0; i < m_signature.SignatureValue.Length; i++)
			{
				if (m_signature.SignatureValue[i] != c14NDigest[i])
				{
					return false;
				}
			}
			return true;
		}

		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		private static List<string> ReadAdditionalSafeCanonicalizationMethods()
		{
			return ReadFxSecurityStringValues("SafeCanonicalizationMethods");
		}

		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		private static List<string> ReadAdditionalSafeTransformMethods()
		{
			return ReadFxSecurityStringValues("SafeTransformMethods");
		}

		private static List<string> ReadFxSecurityStringValues(string subkey)
		{
			List<string> list = new List<string>();
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\.NETFramework\\Security\\" + subkey, writable: false);
				if (registryKey != null)
				{
					string[] valueNames = registryKey.GetValueNames();
					foreach (string name in valueNames)
					{
						if (registryKey.GetValueKind(name) == RegistryValueKind.String)
						{
							string text = registryKey.GetValue(name) as string;
							if (!string.IsNullOrEmpty(text))
							{
								list.Add(text);
							}
						}
					}
					return list;
				}
				return list;
			}
			catch (SecurityException)
			{
				return list;
			}
		}

		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		private static bool ReadHmacTruncationSetting()
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\.NETFramework", writable: false);
				if (registryKey == null)
				{
					return false;
				}
				object value = registryKey.GetValue("AllowHMACTruncation");
				if (value == null)
				{
					return false;
				}
				if (registryKey.GetValueKind("AllowHMACTruncation") != RegistryValueKind.DWord)
				{
					return false;
				}
				return (int)value != 0;
			}
			catch (SecurityException)
			{
				return false;
			}
		}

		private static bool DefaultSignatureFormatValidator(SignedXml signedXml)
		{
			if (!AllowHmacTruncation && signedXml.DoesSignatureUseTruncatedHmac())
			{
				return false;
			}
			if (!signedXml.DoesSignatureUseSafeCanonicalizationMethod())
			{
				return false;
			}
			return true;
		}

		private bool DoesSignatureUseSafeCanonicalizationMethod()
		{
			foreach (string safeCanonicalizationMethod in SafeCanonicalizationMethods)
			{
				if (string.Equals(safeCanonicalizationMethod, SignedInfo.CanonicalizationMethod, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			return false;
		}

		private bool ReferenceUsesSafeTransformMethods(Reference reference)
		{
			TransformChain transformChain = reference.TransformChain;
			int count = transformChain.Count;
			for (int i = 0; i < count; i++)
			{
				Transform transform = transformChain[i];
				if (!IsSafeTransform(transform.Algorithm))
				{
					return false;
				}
			}
			return true;
		}

		private bool IsSafeTransform(string transformAlgorithm)
		{
			foreach (string safeCanonicalizationMethod in SafeCanonicalizationMethods)
			{
				if (string.Equals(safeCanonicalizationMethod, transformAlgorithm, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			foreach (string defaultSafeTransformMethod in DefaultSafeTransformMethods)
			{
				if (string.Equals(defaultSafeTransformMethod, transformAlgorithm, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			return false;
		}

		private bool DoesSignatureUseTruncatedHmac()
		{
			if (SignedInfo == null || SignedInfo.SignatureLength == null)
			{
				return false;
			}
			HMAC hMAC = Utils.CreateFromName<HMAC>(SignatureMethod);
			if (hMAC == null)
			{
				if (string.Equals(SignatureMethod, "http://www.w3.org/2000/09/xmldsig#hmac-sha1", StringComparison.Ordinal))
				{
					hMAC = new HMACSHA1();
				}
				else if (string.Equals(SignatureMethod, "http://www.w3.org/2001/04/xmldsig-more#hmac-md5", StringComparison.Ordinal))
				{
					hMAC = new HMACMD5();
				}
			}
			if (hMAC == null)
			{
				return false;
			}
			int result = 0;
			if (!int.TryParse(SignedInfo.SignatureLength, NumberStyles.Integer, CultureInfo.InvariantCulture, out result))
			{
				return true;
			}
			int num = Math.Max(80, hMAC.HashSize / 2);
			return result < num;
		}

		private static XmlElement GetSingleReferenceTarget(XmlDocument document, string idAttributeName, string idValue)
		{
			string xpath = "//*[@" + idAttributeName + "=\"" + idValue + "\"]";
			if (Utils.AllowAmbiguousReferenceTargets())
			{
				return document.SelectSingleNode(xpath) as XmlElement;
			}
			XmlNodeList xmlNodeList = document.SelectNodes(xpath);
			if (xmlNodeList == null || xmlNodeList.Count == 0)
			{
				return null;
			}
			if (xmlNodeList.Count == 1)
			{
				return xmlNodeList[0] as XmlElement;
			}
			throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidReference"));
		}

		private SignatureDescription CreateSignatureDescriptionFromName(string name)
		{
			SignatureDescription signatureDescription = Utils.CreateFromName<SignatureDescription>(name);
			if (signatureDescription != null)
			{
				return signatureDescription;
			}
			StringComparison comparisonType = StringComparison.OrdinalIgnoreCase;
			if (name.Equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", comparisonType))
			{
				return new RSAPKCS1SHA256SignatureDescription();
			}
			if (name.Equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", comparisonType))
			{
				return new RSAPKCS1SHA384SignatureDescription();
			}
			if (name.Equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", comparisonType))
			{
				return new RSAPKCS1SHA512SignatureDescription();
			}
			return null;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class TransformChain
	{
		private ArrayList m_transforms;

		public int Count => m_transforms.Count;

		public Transform this[int index]
		{
			get
			{
				if (index >= m_transforms.Count)
				{
					throw new ArgumentException(SecurityResources.GetResourceString("ArgumentOutOfRange_Index"), "index");
				}
				return (Transform)m_transforms[index];
			}
		}

		public TransformChain()
		{
			m_transforms = new ArrayList();
		}

		public void Add(Transform transform)
		{
			if (transform != null)
			{
				m_transforms.Add(transform);
			}
		}

		public IEnumerator GetEnumerator()
		{
			return m_transforms.GetEnumerator();
		}

		internal Stream TransformToOctetStream(object inputObject, Type inputType, XmlResolver resolver, string baseUri)
		{
			object obj = inputObject;
			foreach (Transform transform in m_transforms)
			{
				if (obj == null || transform.AcceptsType(obj.GetType()))
				{
					transform.Resolver = resolver;
					transform.BaseURI = baseUri;
					transform.LoadInput(obj);
					obj = transform.GetOutput();
				}
				else if (obj is Stream)
				{
					if (!transform.AcceptsType(typeof(XmlDocument)))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"));
					}
					Stream stream = obj as Stream;
					XmlDocument xmlDocument = new XmlDocument();
					xmlDocument.PreserveWhitespace = true;
					XmlReader reader = Utils.PreProcessStreamInput(stream, resolver, baseUri);
					xmlDocument.Load(reader);
					transform.LoadInput(xmlDocument);
					stream.Close();
					obj = transform.GetOutput();
				}
				else if (obj is XmlNodeList)
				{
					if (!transform.AcceptsType(typeof(Stream)))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"));
					}
					CanonicalXml canonicalXml = new CanonicalXml((XmlNodeList)obj, resolver, includeComments: false);
					MemoryStream memoryStream = new MemoryStream(canonicalXml.GetBytes());
					transform.LoadInput(memoryStream);
					obj = transform.GetOutput();
					memoryStream.Close();
				}
				else
				{
					if (!(obj is XmlDocument))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"));
					}
					if (!transform.AcceptsType(typeof(Stream)))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"));
					}
					CanonicalXml canonicalXml2 = new CanonicalXml((XmlDocument)obj, resolver);
					MemoryStream memoryStream2 = new MemoryStream(canonicalXml2.GetBytes());
					transform.LoadInput(memoryStream2);
					obj = transform.GetOutput();
					memoryStream2.Close();
				}
			}
			if (obj is Stream)
			{
				return obj as Stream;
			}
			if (obj is XmlNodeList)
			{
				CanonicalXml canonicalXml3 = new CanonicalXml((XmlNodeList)obj, resolver, includeComments: false);
				return new MemoryStream(canonicalXml3.GetBytes());
			}
			if (obj is XmlDocument)
			{
				CanonicalXml canonicalXml4 = new CanonicalXml((XmlDocument)obj, resolver);
				return new MemoryStream(canonicalXml4.GetBytes());
			}
			throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"));
		}

		internal Stream TransformToOctetStream(Stream input, XmlResolver resolver, string baseUri)
		{
			return TransformToOctetStream(input, typeof(Stream), resolver, baseUri);
		}

		internal Stream TransformToOctetStream(XmlDocument document, XmlResolver resolver, string baseUri)
		{
			return TransformToOctetStream(document, typeof(XmlDocument), resolver, baseUri);
		}

		internal XmlElement GetXml(XmlDocument document, string ns)
		{
			XmlElement xmlElement = document.CreateElement("Transforms", ns);
			foreach (Transform transform in m_transforms)
			{
				if (transform != null)
				{
					XmlElement xml = transform.GetXml(document);
					if (xml != null)
					{
						xmlElement.AppendChild(xml);
					}
				}
			}
			return xmlElement;
		}

		internal void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			XmlNodeList xmlNodeList = value.SelectNodes("ds:Transform", xmlNamespaceManager);
			if (xmlNodeList.Count == 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidElement"), "Transforms");
			}
			m_transforms.Clear();
			for (int i = 0; i < xmlNodeList.Count; i++)
			{
				XmlElement xmlElement = (XmlElement)xmlNodeList.Item(i);
				string attribute = Utils.GetAttribute(xmlElement, "Algorithm", "http://www.w3.org/2000/09/xmldsig#");
				Transform transform = Utils.CreateFromName<Transform>(attribute);
				if (transform == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
				}
				transform.LoadInnerXml(xmlElement.ChildNodes);
				m_transforms.Add(transform);
			}
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public abstract class Transform
	{
		private string m_algorithm;

		private string m_baseUri;

		internal XmlResolver m_xmlResolver;

		private bool m_bResolverSet;

		private SignedXml m_signedXml;

		private Reference m_reference;

		private Hashtable m_propagatedNamespaces;

		private XmlElement m_context;

		internal string BaseURI
		{
			get
			{
				return m_baseUri;
			}
			set
			{
				m_baseUri = value;
			}
		}

		internal SignedXml SignedXml
		{
			get
			{
				return m_signedXml;
			}
			set
			{
				m_signedXml = value;
			}
		}

		internal Reference Reference
		{
			get
			{
				return m_reference;
			}
			set
			{
				m_reference = value;
			}
		}

		public string Algorithm
		{
			get
			{
				return m_algorithm;
			}
			set
			{
				m_algorithm = value;
			}
		}

		[ComVisible(false)]
		public XmlResolver Resolver
		{
			set
			{
				m_xmlResolver = value;
				m_bResolverSet = true;
			}
		}

		internal bool ResolverSet => m_bResolverSet;

		public abstract Type[] InputTypes { get; }

		public abstract Type[] OutputTypes { get; }

		[ComVisible(false)]
		public XmlElement Context
		{
			get
			{
				if (m_context != null)
				{
					return m_context;
				}
				Reference reference = Reference;
				return ((reference == null) ? SignedXml : reference.SignedXml)?.m_context;
			}
			set
			{
				m_context = value;
			}
		}

		[ComVisible(false)]
		public Hashtable PropagatedNamespaces
		{
			get
			{
				if (m_propagatedNamespaces != null)
				{
					return m_propagatedNamespaces;
				}
				Reference reference = Reference;
				SignedXml signedXml = ((reference == null) ? SignedXml : reference.SignedXml);
				if (reference != null && (reference.ReferenceTargetType != ReferenceTargetType.UriReference || reference.Uri == null || reference.Uri.Length == 0 || reference.Uri[0] != '#'))
				{
					m_propagatedNamespaces = new Hashtable(0);
					return m_propagatedNamespaces;
				}
				CanonicalXmlNodeList canonicalXmlNodeList = null;
				if (reference != null)
				{
					canonicalXmlNodeList = reference.m_namespaces;
				}
				else if (signedXml.m_context != null)
				{
					canonicalXmlNodeList = Utils.GetPropagatedAttributes(signedXml.m_context);
				}
				if (canonicalXmlNodeList == null)
				{
					m_propagatedNamespaces = new Hashtable(0);
					return m_propagatedNamespaces;
				}
				m_propagatedNamespaces = new Hashtable(canonicalXmlNodeList.Count);
				foreach (XmlNode item in canonicalXmlNodeList)
				{
					string key = ((item.Prefix.Length > 0) ? (item.Prefix + ":" + item.LocalName) : item.LocalName);
					if (!m_propagatedNamespaces.Contains(key))
					{
						m_propagatedNamespaces.Add(key, item.Value);
					}
				}
				return m_propagatedNamespaces;
			}
		}

		internal bool AcceptsType(Type inputType)
		{
			if (InputTypes != null)
			{
				for (int i = 0; i < InputTypes.Length; i++)
				{
					if (inputType == InputTypes[i] || inputType.IsSubclassOf(InputTypes[i]))
					{
						return true;
					}
				}
			}
			return false;
		}

		public XmlElement GetXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			return GetXml(document, "Transform");
		}

		internal XmlElement GetXml(XmlDocument document, string name)
		{
			XmlElement xmlElement = document.CreateElement(name, "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(Algorithm))
			{
				xmlElement.SetAttribute("Algorithm", Algorithm);
			}
			XmlNodeList innerXml = GetInnerXml();
			if (innerXml != null)
			{
				foreach (XmlNode item in innerXml)
				{
					xmlElement.AppendChild(document.ImportNode(item, deep: true));
				}
				return xmlElement;
			}
			return xmlElement;
		}

		public abstract void LoadInnerXml(XmlNodeList nodeList);

		protected abstract XmlNodeList GetInnerXml();

		public abstract void LoadInput(object obj);

		public abstract object GetOutput();

		public abstract object GetOutput(Type type);

		[ComVisible(false)]
		public virtual byte[] GetDigestedOutput(HashAlgorithm hash)
		{
			return hash.ComputeHash((Stream)GetOutput(typeof(Stream)));
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigC14NTransform : Transform
	{
		private Type[] _inputTypes = new Type[3]
		{
			typeof(Stream),
			typeof(XmlDocument),
			typeof(XmlNodeList)
		};

		private Type[] _outputTypes = new Type[1] { typeof(Stream) };

		private CanonicalXml _cXml;

		private bool _includeComments;

		public override Type[] InputTypes => _inputTypes;

		public override Type[] OutputTypes => _outputTypes;

		public XmlDsigC14NTransform()
		{
			base.Algorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
		}

		public XmlDsigC14NTransform(bool includeComments)
		{
			_includeComments = includeComments;
			base.Algorithm = (includeComments ? "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" : "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (!Utils.GetAllowAdditionalSignatureNodes() && nodeList != null && nodeList.Count > 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
		}

		protected override XmlNodeList GetInnerXml()
		{
			return null;
		}

		public override void LoadInput(object obj)
		{
			XmlResolver resolver = (base.ResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), base.BaseURI));
			if (obj is Stream)
			{
				_cXml = new CanonicalXml((Stream)obj, _includeComments, resolver, base.BaseURI);
				return;
			}
			if (obj is XmlDocument)
			{
				_cXml = new CanonicalXml((XmlDocument)obj, resolver, _includeComments);
				return;
			}
			if (obj is XmlNodeList)
			{
				_cXml = new CanonicalXml((XmlNodeList)obj, resolver, _includeComments);
				return;
			}
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "obj");
		}

		public override object GetOutput()
		{
			return new MemoryStream(_cXml.GetBytes());
		}

		public override object GetOutput(Type type)
		{
			if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
			}
			return new MemoryStream(_cXml.GetBytes());
		}

		[ComVisible(false)]
		public override byte[] GetDigestedOutput(HashAlgorithm hash)
		{
			return _cXml.GetDigestedBytes(hash);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigC14NWithCommentsTransform : XmlDsigC14NTransform
	{
		public XmlDsigC14NWithCommentsTransform()
			: base(includeComments: true)
		{
			base.Algorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigExcC14NTransform : Transform
	{
		private Type[] _inputTypes = new Type[3]
		{
			typeof(Stream),
			typeof(XmlDocument),
			typeof(XmlNodeList)
		};

		private Type[] _outputTypes = new Type[1] { typeof(Stream) };

		private bool _includeComments;

		private string _inclusiveNamespacesPrefixList;

		private ExcCanonicalXml _excCanonicalXml;

		public string InclusiveNamespacesPrefixList
		{
			get
			{
				return _inclusiveNamespacesPrefixList;
			}
			set
			{
				_inclusiveNamespacesPrefixList = value;
			}
		}

		public override Type[] InputTypes => _inputTypes;

		public override Type[] OutputTypes => _outputTypes;

		public XmlDsigExcC14NTransform()
			: this(includeComments: false, null)
		{
		}

		public XmlDsigExcC14NTransform(bool includeComments)
			: this(includeComments, null)
		{
		}

		public XmlDsigExcC14NTransform(string inclusiveNamespacesPrefixList)
			: this(includeComments: false, inclusiveNamespacesPrefixList)
		{
		}

		public XmlDsigExcC14NTransform(bool includeComments, string inclusiveNamespacesPrefixList)
		{
			_includeComments = includeComments;
			_inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList;
			base.Algorithm = (includeComments ? "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" : "http://www.w3.org/2001/10/xml-exc-c14n#");
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (nodeList == null)
			{
				return;
			}
			foreach (XmlNode node in nodeList)
			{
				if (!(node is XmlElement xmlElement))
				{
					continue;
				}
				if (xmlElement.LocalName.Equals("InclusiveNamespaces") && xmlElement.NamespaceURI.Equals("http://www.w3.org/2001/10/xml-exc-c14n#") && Utils.HasAttribute(xmlElement, "PrefixList", "http://www.w3.org/2000/09/xmldsig#"))
				{
					if (!Utils.VerifyAttributes(xmlElement, "PrefixList"))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
					}
					InclusiveNamespacesPrefixList = Utils.GetAttribute(xmlElement, "PrefixList", "http://www.w3.org/2000/09/xmldsig#");
					break;
				}
				if (!Utils.GetAllowAdditionalSignatureNodes())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
				}
			}
		}

		public override void LoadInput(object obj)
		{
			XmlResolver resolver = (base.ResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), base.BaseURI));
			if (obj is Stream)
			{
				_excCanonicalXml = new ExcCanonicalXml((Stream)obj, _includeComments, _inclusiveNamespacesPrefixList, resolver, base.BaseURI);
				return;
			}
			if (obj is XmlDocument)
			{
				_excCanonicalXml = new ExcCanonicalXml((XmlDocument)obj, _includeComments, _inclusiveNamespacesPrefixList, resolver);
				return;
			}
			if (obj is XmlNodeList)
			{
				_excCanonicalXml = new ExcCanonicalXml((XmlNodeList)obj, _includeComments, _inclusiveNamespacesPrefixList, resolver);
				return;
			}
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "obj");
		}

		protected override XmlNodeList GetInnerXml()
		{
			if (InclusiveNamespacesPrefixList == null)
			{
				return null;
			}
			XmlDocument xmlDocument = new XmlDocument();
			XmlElement xmlElement = xmlDocument.CreateElement("Transform", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(base.Algorithm))
			{
				xmlElement.SetAttribute("Algorithm", base.Algorithm);
			}
			XmlElement xmlElement2 = xmlDocument.CreateElement("InclusiveNamespaces", "http://www.w3.org/2001/10/xml-exc-c14n#");
			xmlElement2.SetAttribute("PrefixList", InclusiveNamespacesPrefixList);
			xmlElement.AppendChild(xmlElement2);
			return xmlElement.ChildNodes;
		}

		public override object GetOutput()
		{
			return new MemoryStream(_excCanonicalXml.GetBytes());
		}

		public override object GetOutput(Type type)
		{
			if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
			}
			return new MemoryStream(_excCanonicalXml.GetBytes());
		}

		public override byte[] GetDigestedOutput(HashAlgorithm hash)
		{
			return _excCanonicalXml.GetDigestedBytes(hash);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigExcC14NWithCommentsTransform : XmlDsigExcC14NTransform
	{
		public XmlDsigExcC14NWithCommentsTransform()
			: base(includeComments: true)
		{
			base.Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
		}

		public XmlDsigExcC14NWithCommentsTransform(string inclusiveNamespacesPrefixList)
			: base(includeComments: true, inclusiveNamespacesPrefixList)
		{
			base.Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigBase64Transform : Transform
	{
		private Type[] _inputTypes = new Type[3]
		{
			typeof(Stream),
			typeof(XmlNodeList),
			typeof(XmlDocument)
		};

		private Type[] _outputTypes = new Type[1] { typeof(Stream) };

		private CryptoStream _cs;

		public override Type[] InputTypes => _inputTypes;

		public override Type[] OutputTypes => _outputTypes;

		public XmlDsigBase64Transform()
		{
			base.Algorithm = "http://www.w3.org/2000/09/xmldsig#base64";
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (!Utils.GetAllowAdditionalSignatureNodes() && nodeList != null && nodeList.Count > 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
		}

		protected override XmlNodeList GetInnerXml()
		{
			return null;
		}

		public override void LoadInput(object obj)
		{
			if (obj is Stream)
			{
				LoadStreamInput((Stream)obj);
			}
			else if (obj is XmlNodeList)
			{
				LoadXmlNodeListInput((XmlNodeList)obj);
			}
			else if (obj is XmlDocument)
			{
				LoadXmlNodeListInput(((XmlDocument)obj).SelectNodes("//."));
			}
		}

		private void LoadStreamInput(Stream inputStream)
		{
			if (inputStream == null)
			{
				throw new ArgumentException("obj");
			}
			MemoryStream memoryStream = new MemoryStream();
			byte[] array = new byte[1024];
			int num;
			do
			{
				num = inputStream.Read(array, 0, 1024);
				if (num <= 0)
				{
					continue;
				}
				int num2 = 0;
				int i;
				for (i = 0; i < num && !char.IsWhiteSpace((char)array[i]); i++)
				{
				}
				num2 = i;
				for (i++; i < num; i++)
				{
					if (!char.IsWhiteSpace((char)array[i]))
					{
						array[num2] = array[i];
						num2++;
					}
				}
				memoryStream.Write(array, 0, num2);
			}
			while (num > 0);
			memoryStream.Position = 0L;
			_cs = new CryptoStream(memoryStream, new FromBase64Transform(), CryptoStreamMode.Read);
		}

		private void LoadXmlNodeListInput(XmlNodeList nodeList)
		{
			StringBuilder stringBuilder = new StringBuilder();
			foreach (XmlNode node in nodeList)
			{
				XmlNode xmlNode2 = node.SelectSingleNode("self::text()");
				if (xmlNode2 != null)
				{
					stringBuilder.Append(xmlNode2.OuterXml);
				}
			}
			UTF8Encoding uTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			byte[] bytes = uTF8Encoding.GetBytes(stringBuilder.ToString());
			int num = 0;
			int i;
			for (i = 0; i < bytes.Length && !char.IsWhiteSpace((char)bytes[i]); i++)
			{
			}
			num = i;
			for (i++; i < bytes.Length; i++)
			{
				if (!char.IsWhiteSpace((char)bytes[i]))
				{
					bytes[num] = bytes[i];
					num++;
				}
			}
			MemoryStream stream = new MemoryStream(bytes, 0, num);
			_cs = new CryptoStream(stream, new FromBase64Transform(), CryptoStreamMode.Read);
		}

		public override object GetOutput()
		{
			return _cs;
		}

		public override object GetOutput(Type type)
		{
			if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
			}
			return _cs;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigXPathTransform : Transform
	{
		private Type[] _inputTypes = new Type[3]
		{
			typeof(Stream),
			typeof(XmlNodeList),
			typeof(XmlDocument)
		};

		private Type[] _outputTypes = new Type[1] { typeof(XmlNodeList) };

		private string _xpathexpr;

		private XmlDocument _document;

		private XmlNamespaceManager _nsm;

		public override Type[] InputTypes => _inputTypes;

		public override Type[] OutputTypes => _outputTypes;

		public XmlDsigXPathTransform()
		{
			base.Algorithm = "http://www.w3.org/TR/1999/REC-xpath-19991116";
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (nodeList == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
			foreach (XmlNode node in nodeList)
			{
				string text = null;
				string text2 = null;
				if (!(node is XmlElement xmlElement))
				{
					continue;
				}
				if (xmlElement.LocalName == "XPath")
				{
					_xpathexpr = xmlElement.InnerXml.Trim(null);
					XmlNodeReader xmlNodeReader = new XmlNodeReader(xmlElement);
					XmlNameTable nameTable = xmlNodeReader.NameTable;
					_nsm = new XmlNamespaceManager(nameTable);
					if (!Utils.VerifyAttributes(xmlElement, (string)null))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
					}
					foreach (XmlAttribute attribute in xmlElement.Attributes)
					{
						if (attribute.Prefix == "xmlns")
						{
							text = attribute.LocalName;
							text2 = attribute.Value;
							if (text == null)
							{
								text = xmlElement.Prefix;
								text2 = xmlElement.NamespaceURI;
							}
							_nsm.AddNamespace(text, text2);
						}
					}
					break;
				}
				if (!Utils.GetAllowAdditionalSignatureNodes())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
				}
			}
			if (_xpathexpr == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
		}

		protected override XmlNodeList GetInnerXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			XmlElement xmlElement = xmlDocument.CreateElement(null, "XPath", "http://www.w3.org/2000/09/xmldsig#");
			if (_nsm != null)
			{
				foreach (string item in _nsm)
				{
					switch (item)
					{
					case "xml":
					case "xmlns":
						continue;
					}
					if (item != null && item.Length > 0)
					{
						xmlElement.SetAttribute("xmlns:" + item, _nsm.LookupNamespace(item));
					}
				}
			}
			xmlElement.InnerXml = _xpathexpr;
			xmlDocument.AppendChild(xmlElement);
			return xmlDocument.ChildNodes;
		}

		public override void LoadInput(object obj)
		{
			if (obj is Stream)
			{
				LoadStreamInput((Stream)obj);
			}
			else if (obj is XmlNodeList)
			{
				LoadXmlNodeListInput((XmlNodeList)obj);
			}
			else if (obj is XmlDocument)
			{
				LoadXmlDocumentInput((XmlDocument)obj);
			}
		}

		private void LoadStreamInput(Stream stream)
		{
			XmlResolver xmlResolver = (base.ResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), base.BaseURI));
			XmlReader reader = Utils.PreProcessStreamInput(stream, xmlResolver, base.BaseURI);
			_document = new XmlDocument();
			_document.PreserveWhitespace = true;
			_document.Load(reader);
		}

		private void LoadXmlNodeListInput(XmlNodeList nodeList)
		{
			XmlResolver resolver = (base.ResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), base.BaseURI));
			CanonicalXml canonicalXml = new CanonicalXml(nodeList, resolver, includeComments: true);
			using MemoryStream stream = new MemoryStream(canonicalXml.GetBytes());
			LoadStreamInput(stream);
		}

		private void LoadXmlDocumentInput(XmlDocument doc)
		{
			_document = doc;
		}

		public override object GetOutput()
		{
			CanonicalXmlNodeList canonicalXmlNodeList = new CanonicalXmlNodeList();
			if (!string.IsNullOrEmpty(_xpathexpr))
			{
				XPathNavigator xPathNavigator = _document.CreateNavigator();
				XPathNodeIterator xPathNodeIterator = xPathNavigator.Select("//. | //@*");
				XPathExpression xPathExpression = xPathNavigator.Compile("boolean(" + _xpathexpr + ")");
				xPathExpression.SetContext(_nsm);
				while (xPathNodeIterator.MoveNext())
				{
					XmlNode node = ((IHasXmlNode)xPathNodeIterator.Current).GetNode();
					if ((bool)xPathNodeIterator.Current.Evaluate(xPathExpression))
					{
						canonicalXmlNodeList.Add(node);
					}
				}
				xPathNodeIterator = xPathNavigator.Select("//namespace::*");
				while (xPathNodeIterator.MoveNext())
				{
					XmlNode node2 = ((IHasXmlNode)xPathNodeIterator.Current).GetNode();
					canonicalXmlNodeList.Add(node2);
				}
			}
			return canonicalXmlNodeList;
		}

		public override object GetOutput(Type type)
		{
			if (type != typeof(XmlNodeList) && !type.IsSubclassOf(typeof(XmlNodeList)))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
			}
			return (XmlNodeList)GetOutput();
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigXsltTransform : Transform
	{
		private Type[] _inputTypes = new Type[3]
		{
			typeof(Stream),
			typeof(XmlDocument),
			typeof(XmlNodeList)
		};

		private Type[] _outputTypes = new Type[1] { typeof(Stream) };

		private XmlNodeList _xslNodes;

		private string _xslFragment;

		private Stream _inputStream;

		private bool _includeComments;

		public override Type[] InputTypes => _inputTypes;

		public override Type[] OutputTypes => _outputTypes;

		public XmlDsigXsltTransform()
		{
			base.Algorithm = "http://www.w3.org/TR/1999/REC-xslt-19991116";
		}

		public XmlDsigXsltTransform(bool includeComments)
		{
			_includeComments = includeComments;
			base.Algorithm = "http://www.w3.org/TR/1999/REC-xslt-19991116";
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (nodeList == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
			XmlElement xmlElement = null;
			int num = 0;
			foreach (XmlNode node in nodeList)
			{
				if (node is XmlWhitespace)
				{
					continue;
				}
				if (node is XmlElement)
				{
					if (num != 0)
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
					}
					xmlElement = node as XmlElement;
					num++;
				}
				else
				{
					num++;
				}
			}
			if (num != 1 || xmlElement == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
			_xslNodes = nodeList;
			_xslFragment = xmlElement.OuterXml.Trim(null);
		}

		protected override XmlNodeList GetInnerXml()
		{
			return _xslNodes;
		}

		public override void LoadInput(object obj)
		{
			if (_inputStream != null)
			{
				_inputStream.Close();
			}
			_inputStream = new MemoryStream();
			if (obj is Stream)
			{
				_inputStream = (Stream)obj;
			}
			else if (obj is XmlNodeList)
			{
				CanonicalXml canonicalXml = new CanonicalXml((XmlNodeList)obj, null, _includeComments);
				byte[] bytes = canonicalXml.GetBytes();
				if (bytes != null)
				{
					_inputStream.Write(bytes, 0, bytes.Length);
					_inputStream.Flush();
					_inputStream.Position = 0L;
				}
			}
			else if (obj is XmlDocument)
			{
				CanonicalXml canonicalXml2 = new CanonicalXml((XmlDocument)obj, null, _includeComments);
				byte[] bytes2 = canonicalXml2.GetBytes();
				if (bytes2 != null)
				{
					_inputStream.Write(bytes2, 0, bytes2.Length);
					_inputStream.Flush();
					_inputStream.Position = 0L;
				}
			}
		}

		public override object GetOutput()
		{
			XslCompiledTransform xslCompiledTransform = new XslCompiledTransform();
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			xmlReaderSettings.XmlResolver = null;
			xmlReaderSettings.MaxCharactersFromEntities = Utils.GetMaxCharactersFromEntities();
			using StringReader input = new StringReader(_xslFragment);
			XmlReader stylesheet = XmlReader.Create((TextReader)input, xmlReaderSettings, (string)null);
			xslCompiledTransform.Load(stylesheet, XsltSettings.Default, null);
			XmlReader reader = XmlReader.Create(_inputStream, xmlReaderSettings, base.BaseURI);
			XPathDocument input2 = new XPathDocument(reader, XmlSpace.Preserve);
			MemoryStream memoryStream = new MemoryStream();
			XmlWriter results = new XmlTextWriter(memoryStream, null);
			xslCompiledTransform.Transform(input2, null, results);
			memoryStream.Position = 0L;
			return memoryStream;
		}

		public override object GetOutput(Type type)
		{
			if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
			}
			return (Stream)GetOutput();
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDsigEnvelopedSignatureTransform : Transform
	{
		private Type[] _inputTypes = new Type[3]
		{
			typeof(Stream),
			typeof(XmlNodeList),
			typeof(XmlDocument)
		};

		private Type[] _outputTypes = new Type[2]
		{
			typeof(XmlNodeList),
			typeof(XmlDocument)
		};

		private XmlNodeList _inputNodeList;

		private bool _includeComments;

		private XmlNamespaceManager _nsm;

		private XmlDocument _containingDocument;

		private int _signaturePosition;

		internal int SignaturePosition
		{
			set
			{
				_signaturePosition = value;
			}
		}

		public override Type[] InputTypes => _inputTypes;

		public override Type[] OutputTypes => _outputTypes;

		public XmlDsigEnvelopedSignatureTransform()
		{
			base.Algorithm = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
		}

		public XmlDsigEnvelopedSignatureTransform(bool includeComments)
		{
			_includeComments = includeComments;
			base.Algorithm = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (!Utils.GetAllowAdditionalSignatureNodes() && nodeList != null && nodeList.Count > 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
		}

		protected override XmlNodeList GetInnerXml()
		{
			return null;
		}

		public override void LoadInput(object obj)
		{
			if (obj is Stream)
			{
				LoadStreamInput((Stream)obj);
			}
			else if (obj is XmlNodeList)
			{
				LoadXmlNodeListInput((XmlNodeList)obj);
			}
			else if (obj is XmlDocument)
			{
				LoadXmlDocumentInput((XmlDocument)obj);
			}
		}

		private void LoadStreamInput(Stream stream)
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			XmlResolver xmlResolver = (base.ResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), base.BaseURI));
			XmlReader reader = Utils.PreProcessStreamInput(stream, xmlResolver, base.BaseURI);
			xmlDocument.Load(reader);
			_containingDocument = xmlDocument;
			if (_containingDocument == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_EnvelopedSignatureRequiresContext"));
			}
			_nsm = new XmlNamespaceManager(_containingDocument.NameTable);
			_nsm.AddNamespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
		}

		private void LoadXmlNodeListInput(XmlNodeList nodeList)
		{
			if (nodeList == null)
			{
				throw new ArgumentNullException("nodeList");
			}
			_containingDocument = Utils.GetOwnerDocument(nodeList);
			if (_containingDocument == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_EnvelopedSignatureRequiresContext"));
			}
			_nsm = new XmlNamespaceManager(_containingDocument.NameTable);
			_nsm.AddNamespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
			_inputNodeList = nodeList;
		}

		private void LoadXmlDocumentInput(XmlDocument doc)
		{
			if (doc == null)
			{
				throw new ArgumentNullException("doc");
			}
			_containingDocument = doc;
			_nsm = new XmlNamespaceManager(_containingDocument.NameTable);
			_nsm.AddNamespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
		}

		public override object GetOutput()
		{
			if (_containingDocument == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_EnvelopedSignatureRequiresContext"));
			}
			if (_inputNodeList != null)
			{
				if (_signaturePosition == 0)
				{
					return _inputNodeList;
				}
				XmlNodeList xmlNodeList = _containingDocument.SelectNodes("//dsig:Signature", _nsm);
				if (xmlNodeList == null)
				{
					return _inputNodeList;
				}
				CanonicalXmlNodeList canonicalXmlNodeList = new CanonicalXmlNodeList();
				{
					foreach (XmlNode inputNode in _inputNodeList)
					{
						if (inputNode == null)
						{
							continue;
						}
						if (Utils.IsXmlNamespaceNode(inputNode) || Utils.IsNamespaceNode(inputNode))
						{
							canonicalXmlNodeList.Add(inputNode);
							continue;
						}
						try
						{
							XmlNode xmlNode2 = inputNode.SelectSingleNode("ancestor-or-self::dsig:Signature[1]", _nsm);
							int num = 0;
							foreach (XmlNode item in xmlNodeList)
							{
								num++;
								if (item == xmlNode2)
								{
									break;
								}
							}
							if (xmlNode2 == null || (xmlNode2 != null && num != _signaturePosition))
							{
								canonicalXmlNodeList.Add(inputNode);
							}
						}
						catch
						{
						}
					}
					return canonicalXmlNodeList;
				}
			}
			XmlNodeList xmlNodeList2 = _containingDocument.SelectNodes("//dsig:Signature", _nsm);
			if (xmlNodeList2 == null)
			{
				return _containingDocument;
			}
			if (xmlNodeList2.Count < _signaturePosition || _signaturePosition <= 0)
			{
				return _containingDocument;
			}
			xmlNodeList2[_signaturePosition - 1].ParentNode.RemoveChild(xmlNodeList2[_signaturePosition - 1]);
			return _containingDocument;
		}

		public override object GetOutput(Type type)
		{
			if (type == typeof(XmlNodeList) || type.IsSubclassOf(typeof(XmlNodeList)))
			{
				if (_inputNodeList == null)
				{
					_inputNodeList = Utils.AllDescendantNodes(_containingDocument, includeComments: true);
				}
				return (XmlNodeList)GetOutput();
			}
			if (type == typeof(XmlDocument) || type.IsSubclassOf(typeof(XmlDocument)))
			{
				if (_inputNodeList != null)
				{
					throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
				}
				return (XmlDocument)GetOutput();
			}
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
		}
	}
	[Serializable]
	internal enum TransformInputType
	{
		XmlDocument = 1,
		XmlStream,
		XmlNodeSet
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlDecryptionTransform : Transform
	{
		private const string XmlDecryptionTransformNamespaceUrl = "http://www.w3.org/2002/07/decrypt#";

		private Type[] m_inputTypes = new Type[2]
		{
			typeof(Stream),
			typeof(XmlDocument)
		};

		private Type[] m_outputTypes = new Type[1] { typeof(XmlDocument) };

		private XmlNodeList m_encryptedDataList;

		private ArrayList m_arrayListUri;

		private EncryptedXml m_exml;

		private XmlDocument m_containingDocument;

		private XmlNamespaceManager m_nsm;

		private ArrayList ExceptUris
		{
			get
			{
				if (m_arrayListUri == null)
				{
					m_arrayListUri = new ArrayList();
				}
				return m_arrayListUri;
			}
		}

		public EncryptedXml EncryptedXml
		{
			get
			{
				if (m_exml != null)
				{
					return m_exml;
				}
				Reference reference = base.Reference;
				SignedXml signedXml = ((reference == null) ? base.SignedXml : reference.SignedXml);
				if (signedXml == null || signedXml.EncryptedXml == null)
				{
					m_exml = new EncryptedXml(m_containingDocument);
				}
				else
				{
					m_exml = signedXml.EncryptedXml;
				}
				return m_exml;
			}
			set
			{
				m_exml = value;
			}
		}

		public override Type[] InputTypes => m_inputTypes;

		public override Type[] OutputTypes => m_outputTypes;

		public XmlDecryptionTransform()
		{
			base.Algorithm = "http://www.w3.org/2002/07/decrypt#XML";
		}

		protected virtual bool IsTargetElement(XmlElement inputElement, string idValue)
		{
			if (inputElement == null)
			{
				return false;
			}
			if (inputElement.GetAttribute("Id") == idValue || inputElement.GetAttribute("id") == idValue || inputElement.GetAttribute("ID") == idValue)
			{
				return true;
			}
			return false;
		}

		public void AddExceptUri(string uri)
		{
			if (uri == null)
			{
				throw new ArgumentNullException("uri");
			}
			ExceptUris.Add(uri);
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (nodeList == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
			ExceptUris.Clear();
			foreach (XmlNode node in nodeList)
			{
				if (!(node is XmlElement xmlElement))
				{
					continue;
				}
				if (xmlElement.LocalName == "Except" && xmlElement.NamespaceURI == "http://www.w3.org/2002/07/decrypt#")
				{
					string attribute = Utils.GetAttribute(xmlElement, "URI", "http://www.w3.org/2002/07/decrypt#");
					if (attribute == null || attribute.Length == 0 || attribute[0] != '#')
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriRequired"));
					}
					if (!Utils.VerifyAttributes(xmlElement, "URI"))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
					}
					string value = Utils.ExtractIdFromLocalUri(attribute);
					ExceptUris.Add(value);
				}
				else if (!Utils.GetAllowAdditionalSignatureNodes())
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
				}
			}
		}

		protected override XmlNodeList GetInnerXml()
		{
			if (ExceptUris.Count == 0)
			{
				return null;
			}
			XmlDocument xmlDocument = new XmlDocument();
			XmlElement xmlElement = xmlDocument.CreateElement("Transform", "http://www.w3.org/2000/09/xmldsig#");
			if (!string.IsNullOrEmpty(base.Algorithm))
			{
				xmlElement.SetAttribute("Algorithm", base.Algorithm);
			}
			foreach (string exceptUri in ExceptUris)
			{
				XmlElement xmlElement2 = xmlDocument.CreateElement("Except", "http://www.w3.org/2002/07/decrypt#");
				xmlElement2.SetAttribute("URI", exceptUri);
				xmlElement.AppendChild(xmlElement2);
			}
			return xmlElement.ChildNodes;
		}

		public override void LoadInput(object obj)
		{
			if (obj is Stream)
			{
				LoadStreamInput((Stream)obj);
			}
			else if (obj is XmlDocument)
			{
				LoadXmlDocumentInput((XmlDocument)obj);
			}
		}

		private void LoadStreamInput(Stream stream)
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			XmlResolver xmlResolver = (base.ResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), base.BaseURI));
			XmlReader reader = Utils.PreProcessStreamInput(stream, xmlResolver, base.BaseURI);
			xmlDocument.Load(reader);
			m_containingDocument = xmlDocument;
			m_nsm = new XmlNamespaceManager(m_containingDocument.NameTable);
			m_nsm.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			m_encryptedDataList = xmlDocument.SelectNodes("//enc:EncryptedData", m_nsm);
		}

		private void LoadXmlDocumentInput(XmlDocument document)
		{
			if (document == null)
			{
				throw new ArgumentNullException("document");
			}
			m_containingDocument = document;
			m_nsm = new XmlNamespaceManager(document.NameTable);
			m_nsm.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			m_encryptedDataList = document.SelectNodes("//enc:EncryptedData", m_nsm);
		}

		private bool ProcessEncryptedDataItem(XmlElement encryptedDataElement)
		{
			if (ExceptUris.Count > 0)
			{
				for (int i = 0; i < ExceptUris.Count; i++)
				{
					if (IsTargetElement(encryptedDataElement, (string)ExceptUris[i]))
					{
						return false;
					}
				}
			}
			EncryptedData encryptedData = new EncryptedData();
			encryptedData.LoadXml(encryptedDataElement);
			SymmetricAlgorithm decryptionKey = EncryptedXml.GetDecryptionKey(encryptedData, null);
			if (decryptionKey == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingDecryptionKey"));
			}
			byte[] decryptedData = EncryptedXml.DecryptData(encryptedData, decryptionKey);
			EncryptedXml.ReplaceData(encryptedDataElement, decryptedData);
			return true;
		}

		private void ProcessElementRecursively(XmlNodeList encryptedDatas)
		{
			if (encryptedDatas == null || encryptedDatas.Count == 0)
			{
				return;
			}
			Queue queue = new Queue();
			foreach (XmlNode encryptedData in encryptedDatas)
			{
				queue.Enqueue(encryptedData);
			}
			for (XmlNode xmlNode = queue.Dequeue() as XmlNode; xmlNode != null; xmlNode = queue.Dequeue() as XmlNode)
			{
				if (xmlNode is XmlElement xmlElement && xmlElement.LocalName == "EncryptedData" && xmlElement.NamespaceURI == "http://www.w3.org/2001/04/xmlenc#")
				{
					XmlNode nextSibling = xmlElement.NextSibling;
					XmlNode parentNode = xmlElement.ParentNode;
					if (ProcessEncryptedDataItem(xmlElement))
					{
						XmlNode xmlNode2 = parentNode.FirstChild;
						while (xmlNode2 != null && xmlNode2.NextSibling != nextSibling)
						{
							xmlNode2 = xmlNode2.NextSibling;
						}
						if (xmlNode2 != null)
						{
							XmlNodeList xmlNodeList = xmlNode2.SelectNodes("//enc:EncryptedData", m_nsm);
							if (xmlNodeList.Count > 0)
							{
								foreach (XmlNode item in xmlNodeList)
								{
									queue.Enqueue(item);
								}
							}
						}
					}
				}
				if (queue.Count == 0)
				{
					break;
				}
			}
		}

		public override object GetOutput()
		{
			if (m_encryptedDataList != null)
			{
				ProcessElementRecursively(m_encryptedDataList);
			}
			Utils.AddNamespaces(m_containingDocument.DocumentElement, base.PropagatedNamespaces);
			return m_containingDocument;
		}

		public override object GetOutput(Type type)
		{
			if (type == typeof(XmlDocument))
			{
				return (XmlDocument)GetOutput();
			}
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class XmlLicenseTransform : Transform
	{
		private const string ElementIssuer = "issuer";

		private const string NamespaceUriCore = "urn:mpeg:mpeg21:2003:01-REL-R-NS";

		private Type[] inputTypes = new Type[1] { typeof(XmlDocument) };

		private Type[] outputTypes = new Type[1] { typeof(XmlDocument) };

		private XmlNamespaceManager namespaceManager;

		private XmlDocument license;

		private IRelDecryptor relDecryptor;

		public override Type[] InputTypes => inputTypes;

		public override Type[] OutputTypes => outputTypes;

		public IRelDecryptor Decryptor
		{
			get
			{
				return relDecryptor;
			}
			set
			{
				relDecryptor = value;
			}
		}

		public XmlLicenseTransform()
		{
			base.Algorithm = "urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform";
		}

		private void DecryptEncryptedGrants(XmlNodeList encryptedGrantList, IRelDecryptor decryptor)
		{
			XmlElement xmlElement = null;
			XmlElement xmlElement2 = null;
			XmlElement xmlElement3 = null;
			EncryptionMethod encryptionMethod = null;
			KeyInfo keyInfo = null;
			CipherData cipherData = null;
			int i = 0;
			for (int count = encryptedGrantList.Count; i < count; i++)
			{
				xmlElement = encryptedGrantList[i].SelectSingleNode("//r:encryptedGrant/enc:EncryptionMethod", namespaceManager) as XmlElement;
				xmlElement2 = encryptedGrantList[i].SelectSingleNode("//r:encryptedGrant/dsig:KeyInfo", namespaceManager) as XmlElement;
				xmlElement3 = encryptedGrantList[i].SelectSingleNode("//r:encryptedGrant/enc:CipherData", namespaceManager) as XmlElement;
				if (xmlElement != null && xmlElement2 != null && xmlElement3 != null)
				{
					encryptionMethod = new EncryptionMethod();
					keyInfo = new KeyInfo();
					cipherData = new CipherData();
					encryptionMethod.LoadXml(xmlElement);
					keyInfo.LoadXml(xmlElement2);
					cipherData.LoadXml(xmlElement3);
					MemoryStream memoryStream = null;
					Stream stream = null;
					StreamReader streamReader = null;
					try
					{
						memoryStream = new MemoryStream(cipherData.CipherValue);
						stream = relDecryptor.Decrypt(encryptionMethod, keyInfo, memoryStream);
						if (stream == null || stream.Length == 0)
						{
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_XrmlUnableToDecryptGrant"));
						}
						streamReader = new StreamReader(stream);
						string innerXml = streamReader.ReadToEnd();
						encryptedGrantList[i].ParentNode.InnerXml = innerXml;
					}
					finally
					{
						memoryStream?.Close();
						stream?.Close();
						streamReader?.Close();
					}
					encryptionMethod = null;
					keyInfo = null;
					cipherData = null;
				}
				xmlElement = null;
				xmlElement2 = null;
				xmlElement3 = null;
			}
		}

		protected override XmlNodeList GetInnerXml()
		{
			return null;
		}

		public override object GetOutput()
		{
			return license;
		}

		public override object GetOutput(Type type)
		{
			if (type != typeof(XmlDocument) || !type.IsSubclassOf(typeof(XmlDocument)))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_TransformIncorrectInputType"), "type");
			}
			return GetOutput();
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (!Utils.GetAllowAdditionalSignatureNodes() && nodeList != null && nodeList.Count > 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UnknownTransform"));
			}
		}

		public override void LoadInput(object obj)
		{
			if (base.Context == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_XrmlMissingContext"));
			}
			license = new XmlDocument();
			license.PreserveWhitespace = true;
			namespaceManager = new XmlNamespaceManager(license.NameTable);
			namespaceManager.AddNamespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
			namespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			namespaceManager.AddNamespace("r", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
			XmlElement xmlElement = null;
			XmlElement xmlElement2 = null;
			XmlNode xmlNode = null;
			if (!(base.Context.SelectSingleNode("ancestor-or-self::r:issuer[1]", namespaceManager) is XmlElement xmlElement3))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_XrmlMissingIssuer"));
			}
			xmlNode = xmlElement3.SelectSingleNode("descendant-or-self::dsig:Signature[1]", namespaceManager) as XmlElement;
			xmlNode?.ParentNode.RemoveChild(xmlNode);
			if (!(xmlElement3.SelectSingleNode("ancestor-or-self::r:license[1]", namespaceManager) is XmlElement xmlElement4))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_XrmlMissingLicence"));
			}
			XmlNodeList xmlNodeList = xmlElement4.SelectNodes("descendant-or-self::r:license[1]/r:issuer", namespaceManager);
			int i = 0;
			for (int count = xmlNodeList.Count; i < count; i++)
			{
				if (xmlNodeList[i] != xmlElement3 && xmlNodeList[i].LocalName == "issuer" && xmlNodeList[i].NamespaceURI == "urn:mpeg:mpeg21:2003:01-REL-R-NS")
				{
					xmlNodeList[i].ParentNode.RemoveChild(xmlNodeList[i]);
				}
			}
			XmlNodeList xmlNodeList2 = xmlElement4.SelectNodes("/r:license/r:grant/r:encryptedGrant", namespaceManager);
			if (xmlNodeList2.Count > 0)
			{
				if (relDecryptor == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_XrmlMissingIRelDecryptor"));
				}
				DecryptEncryptedGrants(xmlNodeList2, relDecryptor);
			}
			license.InnerXml = xmlElement4.OuterXml;
		}
	}
	public interface IRelDecryptor
	{
		Stream Decrypt(EncryptionMethod encryptionMethod, KeyInfo keyInfo, Stream toDecrypt);
	}
	internal static class SymmetricKeyWrap
	{
		private static readonly byte[] s_rgbTripleDES_KW_IV = new byte[8] { 74, 221, 162, 44, 121, 232, 33, 5 };

		private static readonly byte[] s_rgbAES_KW_IV = new byte[8] { 166, 166, 166, 166, 166, 166, 166, 166 };

		internal static byte[] TripleDESKeyWrapEncrypt(byte[] rgbKey, byte[] rgbWrappedKeyData)
		{
			SHA1CryptoServiceProvider sHA1CryptoServiceProvider = new SHA1CryptoServiceProvider();
			byte[] src = sHA1CryptoServiceProvider.ComputeHash(rgbWrappedKeyData);
			RNGCryptoServiceProvider rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
			byte[] array = new byte[8];
			rNGCryptoServiceProvider.GetBytes(array);
			byte[] array2 = new byte[rgbWrappedKeyData.Length + 8];
			TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
			tripleDESCryptoServiceProvider.Padding = PaddingMode.None;
			ICryptoTransform cryptoTransform = tripleDESCryptoServiceProvider.CreateEncryptor(rgbKey, array);
			Buffer.BlockCopy(rgbWrappedKeyData, 0, array2, 0, rgbWrappedKeyData.Length);
			Buffer.BlockCopy(src, 0, array2, rgbWrappedKeyData.Length, 8);
			byte[] array3 = cryptoTransform.TransformFinalBlock(array2, 0, array2.Length);
			byte[] array4 = new byte[array.Length + array3.Length];
			Buffer.BlockCopy(array, 0, array4, 0, array.Length);
			Buffer.BlockCopy(array3, 0, array4, array.Length, array3.Length);
			Array.Reverse(array4);
			ICryptoTransform cryptoTransform2 = tripleDESCryptoServiceProvider.CreateEncryptor(rgbKey, s_rgbTripleDES_KW_IV);
			return cryptoTransform2.TransformFinalBlock(array4, 0, array4.Length);
		}

		internal static byte[] TripleDESKeyWrapDecrypt(byte[] rgbKey, byte[] rgbEncryptedWrappedKeyData)
		{
			if (rgbEncryptedWrappedKeyData.Length != 32 && rgbEncryptedWrappedKeyData.Length != 40 && rgbEncryptedWrappedKeyData.Length != 48)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_KW_BadKeySize"));
			}
			TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
			tripleDESCryptoServiceProvider.Padding = PaddingMode.None;
			ICryptoTransform cryptoTransform = tripleDESCryptoServiceProvider.CreateDecryptor(rgbKey, s_rgbTripleDES_KW_IV);
			byte[] array = cryptoTransform.TransformFinalBlock(rgbEncryptedWrappedKeyData, 0, rgbEncryptedWrappedKeyData.Length);
			Array.Reverse(array);
			byte[] array2 = new byte[8];
			Buffer.BlockCopy(array, 0, array2, 0, 8);
			byte[] array3 = new byte[array.Length - array2.Length];
			Buffer.BlockCopy(array, 8, array3, 0, array3.Length);
			ICryptoTransform cryptoTransform2 = tripleDESCryptoServiceProvider.CreateDecryptor(rgbKey, array2);
			byte[] array4 = cryptoTransform2.TransformFinalBlock(array3, 0, array3.Length);
			byte[] array5 = new byte[array4.Length - 8];
			Buffer.BlockCopy(array4, 0, array5, 0, array5.Length);
			SHA1CryptoServiceProvider sHA1CryptoServiceProvider = new SHA1CryptoServiceProvider();
			byte[] array6 = sHA1CryptoServiceProvider.ComputeHash(array5);
			int num = array5.Length;
			int num2 = 0;
			while (num < array4.Length)
			{
				if (array4[num] != array6[num2])
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_BadWrappedKeySize"));
				}
				num++;
				num2++;
			}
			return array5;
		}

		internal static byte[] AESKeyWrapEncrypt(byte[] rgbKey, byte[] rgbWrappedKeyData)
		{
			int num = rgbWrappedKeyData.Length >> 3;
			if (rgbWrappedKeyData.Length % 8 != 0 || num <= 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_KW_BadKeySize"));
			}
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			rijndaelManaged.Key = rgbKey;
			rijndaelManaged.Mode = CipherMode.ECB;
			rijndaelManaged.Padding = PaddingMode.None;
			ICryptoTransform cryptoTransform = rijndaelManaged.CreateEncryptor();
			if (num == 1)
			{
				byte[] array = new byte[s_rgbAES_KW_IV.Length + rgbWrappedKeyData.Length];
				Buffer.BlockCopy(s_rgbAES_KW_IV, 0, array, 0, s_rgbAES_KW_IV.Length);
				Buffer.BlockCopy(rgbWrappedKeyData, 0, array, s_rgbAES_KW_IV.Length, rgbWrappedKeyData.Length);
				return cryptoTransform.TransformFinalBlock(array, 0, array.Length);
			}
			long num2 = 0L;
			byte[] array2 = new byte[num + 1 << 3];
			Buffer.BlockCopy(rgbWrappedKeyData, 0, array2, 8, rgbWrappedKeyData.Length);
			byte[] array3 = new byte[8];
			byte[] array4 = new byte[16];
			Buffer.BlockCopy(s_rgbAES_KW_IV, 0, array3, 0, 8);
			for (int i = 0; i <= 5; i++)
			{
				for (int j = 1; j <= num; j++)
				{
					num2 = j + i * num;
					Buffer.BlockCopy(array3, 0, array4, 0, 8);
					Buffer.BlockCopy(array2, 8 * j, array4, 8, 8);
					byte[] array5 = cryptoTransform.TransformFinalBlock(array4, 0, 16);
					for (int k = 0; k < 8; k++)
					{
						byte b = (byte)((num2 >> 8 * (7 - k)) & 0xFF);
						array3[k] = (byte)(b ^ array5[k]);
					}
					Buffer.BlockCopy(array5, 8, array2, 8 * j, 8);
				}
			}
			Buffer.BlockCopy(array3, 0, array2, 0, 8);
			return array2;
		}

		internal static byte[] AESKeyWrapDecrypt(byte[] rgbKey, byte[] rgbEncryptedWrappedKeyData)
		{
			int num = (rgbEncryptedWrappedKeyData.Length >> 3) - 1;
			if (rgbEncryptedWrappedKeyData.Length % 8 != 0 || num <= 0)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_KW_BadKeySize"));
			}
			byte[] array = new byte[num << 3];
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			rijndaelManaged.Key = rgbKey;
			rijndaelManaged.Mode = CipherMode.ECB;
			rijndaelManaged.Padding = PaddingMode.None;
			ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor();
			if (num == 1)
			{
				byte[] array2 = cryptoTransform.TransformFinalBlock(rgbEncryptedWrappedKeyData, 0, rgbEncryptedWrappedKeyData.Length);
				for (int i = 0; i < 8; i++)
				{
					if (array2[i] != s_rgbAES_KW_IV[i])
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_BadWrappedKeySize"));
					}
				}
				Buffer.BlockCopy(array2, 8, array, 0, 8);
				return array;
			}
			long num2 = 0L;
			Buffer.BlockCopy(rgbEncryptedWrappedKeyData, 8, array, 0, array.Length);
			byte[] array3 = new byte[8];
			byte[] array4 = new byte[16];
			Buffer.BlockCopy(rgbEncryptedWrappedKeyData, 0, array3, 0, 8);
			for (int num3 = 5; num3 >= 0; num3--)
			{
				for (int num4 = num; num4 >= 1; num4--)
				{
					num2 = num4 + num3 * num;
					for (int j = 0; j < 8; j++)
					{
						byte b = (byte)((num2 >> 8 * (7 - j)) & 0xFF);
						array3[j] ^= b;
					}
					Buffer.BlockCopy(array3, 0, array4, 0, 8);
					Buffer.BlockCopy(array, 8 * (num4 - 1), array4, 8, 8);
					byte[] src = cryptoTransform.TransformFinalBlock(array4, 0, 16);
					Buffer.BlockCopy(src, 8, array, 8 * (num4 - 1), 8);
					Buffer.BlockCopy(src, 0, array3, 0, 8);
				}
			}
			for (int k = 0; k < 8; k++)
			{
				if (array3[k] != s_rgbAES_KW_IV[k])
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_BadWrappedKeySize"));
				}
			}
			return array;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public abstract class EncryptedType
	{
		private string m_id;

		private string m_type;

		private string m_mimeType;

		private string m_encoding;

		private EncryptionMethod m_encryptionMethod;

		private CipherData m_cipherData;

		private EncryptionPropertyCollection m_props;

		private KeyInfo m_keyInfo;

		internal XmlElement m_cachedXml;

		internal bool CacheValid => m_cachedXml != null;

		public virtual string Id
		{
			get
			{
				return m_id;
			}
			set
			{
				m_id = value;
				m_cachedXml = null;
			}
		}

		public virtual string Type
		{
			get
			{
				return m_type;
			}
			set
			{
				m_type = value;
				m_cachedXml = null;
			}
		}

		public virtual string MimeType
		{
			get
			{
				return m_mimeType;
			}
			set
			{
				m_mimeType = value;
				m_cachedXml = null;
			}
		}

		public virtual string Encoding
		{
			get
			{
				return m_encoding;
			}
			set
			{
				m_encoding = value;
				m_cachedXml = null;
			}
		}

		public KeyInfo KeyInfo
		{
			get
			{
				if (m_keyInfo == null)
				{
					m_keyInfo = new KeyInfo();
				}
				return m_keyInfo;
			}
			set
			{
				m_keyInfo = value;
			}
		}

		public virtual EncryptionMethod EncryptionMethod
		{
			get
			{
				return m_encryptionMethod;
			}
			set
			{
				m_encryptionMethod = value;
				m_cachedXml = null;
			}
		}

		public virtual EncryptionPropertyCollection EncryptionProperties
		{
			get
			{
				if (m_props == null)
				{
					m_props = new EncryptionPropertyCollection();
				}
				return m_props;
			}
		}

		public virtual CipherData CipherData
		{
			get
			{
				if (m_cipherData == null)
				{
					m_cipherData = new CipherData();
				}
				return m_cipherData;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				m_cipherData = value;
				m_cachedXml = null;
			}
		}

		public void AddProperty(EncryptionProperty ep)
		{
			EncryptionProperties.Add(ep);
		}

		public abstract void LoadXml(XmlElement value);

		public abstract XmlElement GetXml();
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class EncryptionMethod
	{
		private XmlElement m_cachedXml;

		private int m_keySize;

		private string m_algorithm;

		private bool CacheValid => m_cachedXml != null;

		public int KeySize
		{
			get
			{
				return m_keySize;
			}
			set
			{
				if (value <= 0)
				{
					throw new ArgumentOutOfRangeException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidKeySize"));
				}
				m_keySize = value;
				m_cachedXml = null;
			}
		}

		public string KeyAlgorithm
		{
			get
			{
				return m_algorithm;
			}
			set
			{
				m_algorithm = value;
				m_cachedXml = null;
			}
		}

		public EncryptionMethod()
		{
			m_cachedXml = null;
		}

		public EncryptionMethod(string algorithm)
		{
			m_algorithm = algorithm;
			m_cachedXml = null;
		}

		public XmlElement GetXml()
		{
			if (CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("EncryptionMethod", "http://www.w3.org/2001/04/xmlenc#");
			if (!string.IsNullOrEmpty(m_algorithm))
			{
				xmlElement.SetAttribute("Algorithm", m_algorithm);
			}
			if (m_keySize > 0)
			{
				XmlElement xmlElement2 = document.CreateElement("KeySize", "http://www.w3.org/2001/04/xmlenc#");
				xmlElement2.AppendChild(document.CreateTextNode(m_keySize.ToString(null, null)));
				xmlElement.AppendChild(xmlElement2);
			}
			return xmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			m_algorithm = Utils.GetAttribute(value, "Algorithm", "http://www.w3.org/2001/04/xmlenc#");
			XmlNode xmlNode = value.SelectSingleNode("enc:KeySize", xmlNamespaceManager);
			if (xmlNode != null)
			{
				KeySize = Convert.ToInt32(Utils.DiscardWhiteSpaces(xmlNode.InnerText), null);
			}
			m_cachedXml = value;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class EncryptionProperty
	{
		private string m_target;

		private string m_id;

		private XmlElement m_elemProp;

		private XmlElement m_cachedXml;

		public string Id => m_id;

		public string Target => m_target;

		public XmlElement PropertyElement
		{
			get
			{
				return m_elemProp;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (value.LocalName != "EncryptionProperty" || value.NamespaceURI != "http://www.w3.org/2001/04/xmlenc#")
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidEncryptionProperty"));
				}
				m_elemProp = value;
				m_cachedXml = null;
			}
		}

		private bool CacheValid => m_cachedXml != null;

		public EncryptionProperty()
		{
		}

		public EncryptionProperty(XmlElement elementProperty)
		{
			if (elementProperty == null)
			{
				throw new ArgumentNullException("elementProperty");
			}
			if (elementProperty.LocalName != "EncryptionProperty" || elementProperty.NamespaceURI != "http://www.w3.org/2001/04/xmlenc#")
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidEncryptionProperty"));
			}
			m_elemProp = elementProperty;
			m_cachedXml = null;
		}

		public XmlElement GetXml()
		{
			if (CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			return document.ImportNode(m_elemProp, deep: true) as XmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (value.LocalName != "EncryptionProperty" || value.NamespaceURI != "http://www.w3.org/2001/04/xmlenc#")
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_InvalidEncryptionProperty"));
			}
			m_cachedXml = value;
			m_id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2001/04/xmlenc#");
			m_target = Utils.GetAttribute(value, "Target", "http://www.w3.org/2001/04/xmlenc#");
			m_elemProp = value;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class EncryptionPropertyCollection : IList, ICollection, IEnumerable
	{
		private ArrayList m_props;

		public int Count => m_props.Count;

		public bool IsFixedSize => m_props.IsFixedSize;

		public bool IsReadOnly => m_props.IsReadOnly;

		[IndexerName("ItemOf")]
		public EncryptionProperty this[int index]
		{
			get
			{
				return (EncryptionProperty)((IList)this)[index];
			}
			set
			{
				((IList)this)[index] = value;
			}
		}

		object IList.this[int index]
		{
			get
			{
				return m_props[index];
			}
			set
			{
				if (!(value is EncryptionProperty))
				{
					throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
				}
				m_props[index] = value;
			}
		}

		public object SyncRoot => m_props.SyncRoot;

		public bool IsSynchronized => m_props.IsSynchronized;

		public EncryptionPropertyCollection()
		{
			m_props = new ArrayList();
		}

		public IEnumerator GetEnumerator()
		{
			return m_props.GetEnumerator();
		}

		int IList.Add(object value)
		{
			if (!(value is EncryptionProperty))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			return m_props.Add(value);
		}

		public int Add(EncryptionProperty value)
		{
			return m_props.Add(value);
		}

		public void Clear()
		{
			m_props.Clear();
		}

		bool IList.Contains(object value)
		{
			if (!(value is EncryptionProperty))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			return m_props.Contains(value);
		}

		public bool Contains(EncryptionProperty value)
		{
			return m_props.Contains(value);
		}

		int IList.IndexOf(object value)
		{
			if (!(value is EncryptionProperty))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			return m_props.IndexOf(value);
		}

		public int IndexOf(EncryptionProperty value)
		{
			return m_props.IndexOf(value);
		}

		void IList.Insert(int index, object value)
		{
			if (!(value is EncryptionProperty))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			m_props.Insert(index, value);
		}

		public void Insert(int index, EncryptionProperty value)
		{
			m_props.Insert(index, value);
		}

		void IList.Remove(object value)
		{
			if (!(value is EncryptionProperty))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			m_props.Remove(value);
		}

		public void Remove(EncryptionProperty value)
		{
			m_props.Remove(value);
		}

		public void RemoveAt(int index)
		{
			m_props.RemoveAt(index);
		}

		public EncryptionProperty Item(int index)
		{
			return (EncryptionProperty)m_props[index];
		}

		public void CopyTo(Array array, int index)
		{
			m_props.CopyTo(array, index);
		}

		public void CopyTo(EncryptionProperty[] array, int index)
		{
			m_props.CopyTo(array, index);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public abstract class EncryptedReference
	{
		private string m_uri;

		private string m_referenceType;

		private TransformChain m_transformChain;

		internal XmlElement m_cachedXml;

		public string Uri
		{
			get
			{
				return m_uri;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException(SecurityResources.GetResourceString("Cryptography_Xml_UriRequired"));
				}
				m_uri = value;
				m_cachedXml = null;
			}
		}

		public TransformChain TransformChain
		{
			get
			{
				if (m_transformChain == null)
				{
					m_transformChain = new TransformChain();
				}
				return m_transformChain;
			}
			set
			{
				m_transformChain = value;
				m_cachedXml = null;
			}
		}

		protected string ReferenceType
		{
			get
			{
				return m_referenceType;
			}
			set
			{
				m_referenceType = value;
				m_cachedXml = null;
			}
		}

		protected internal bool CacheValid => m_cachedXml != null;

		protected EncryptedReference()
			: this(string.Empty, new TransformChain())
		{
		}

		protected EncryptedReference(string uri)
			: this(uri, new TransformChain())
		{
		}

		protected EncryptedReference(string uri, TransformChain transformChain)
		{
			TransformChain = transformChain;
			Uri = uri;
			m_cachedXml = null;
		}

		public void AddTransform(Transform transform)
		{
			TransformChain.Add(transform);
		}

		public virtual XmlElement GetXml()
		{
			if (CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			if (ReferenceType == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_ReferenceTypeRequired"));
			}
			XmlElement xmlElement = document.CreateElement(ReferenceType, "http://www.w3.org/2001/04/xmlenc#");
			if (!string.IsNullOrEmpty(m_uri))
			{
				xmlElement.SetAttribute("URI", m_uri);
			}
			if (TransformChain.Count > 0)
			{
				xmlElement.AppendChild(TransformChain.GetXml(document, "http://www.w3.org/2000/09/xmldsig#"));
			}
			return xmlElement;
		}

		public virtual void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			ReferenceType = value.LocalName;
			Uri = Utils.GetAttribute(value, "URI", "http://www.w3.org/2001/04/xmlenc#");
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			XmlNode xmlNode = value.SelectSingleNode("ds:Transforms", xmlNamespaceManager);
			if (xmlNode != null)
			{
				TransformChain.LoadXml(xmlNode as XmlElement);
			}
			m_cachedXml = value;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CipherReference : EncryptedReference
	{
		private byte[] m_cipherValue;

		internal byte[] CipherValue
		{
			get
			{
				if (!base.CacheValid)
				{
					return null;
				}
				return m_cipherValue;
			}
			set
			{
				m_cipherValue = value;
			}
		}

		public CipherReference()
		{
			base.ReferenceType = "CipherReference";
		}

		public CipherReference(string uri)
			: base(uri)
		{
			base.ReferenceType = "CipherReference";
		}

		public CipherReference(string uri, TransformChain transformChain)
			: base(uri, transformChain)
		{
			base.ReferenceType = "CipherReference";
		}

		public override XmlElement GetXml()
		{
			if (base.CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal new XmlElement GetXml(XmlDocument document)
		{
			if (base.ReferenceType == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_ReferenceTypeRequired"));
			}
			XmlElement xmlElement = document.CreateElement(base.ReferenceType, "http://www.w3.org/2001/04/xmlenc#");
			if (!string.IsNullOrEmpty(base.Uri))
			{
				xmlElement.SetAttribute("URI", base.Uri);
			}
			if (base.TransformChain.Count > 0)
			{
				xmlElement.AppendChild(base.TransformChain.GetXml(document, "http://www.w3.org/2001/04/xmlenc#"));
			}
			return xmlElement;
		}

		public override void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			base.ReferenceType = value.LocalName;
			string attribute = Utils.GetAttribute(value, "URI", "http://www.w3.org/2001/04/xmlenc#");
			if (!Utils.GetSkipSignatureAttributeEnforcement() && attribute == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriRequired"));
			}
			base.Uri = attribute;
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			XmlNode xmlNode = value.SelectSingleNode("enc:Transforms", xmlNamespaceManager);
			if (xmlNode != null)
			{
				base.TransformChain.LoadXml(xmlNode as XmlElement);
			}
			m_cachedXml = value;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class DataReference : EncryptedReference
	{
		public DataReference()
		{
			base.ReferenceType = "DataReference";
		}

		public DataReference(string uri)
			: base(uri)
		{
			base.ReferenceType = "DataReference";
		}

		public DataReference(string uri, TransformChain transformChain)
			: base(uri, transformChain)
		{
			base.ReferenceType = "DataReference";
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class KeyReference : EncryptedReference
	{
		public KeyReference()
		{
			base.ReferenceType = "KeyReference";
		}

		public KeyReference(string uri)
			: base(uri)
		{
			base.ReferenceType = "KeyReference";
		}

		public KeyReference(string uri, TransformChain transformChain)
			: base(uri, transformChain)
		{
			base.ReferenceType = "KeyReference";
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class EncryptedData : EncryptedType
	{
		public override void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			Id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2001/04/xmlenc#");
			Type = Utils.GetAttribute(value, "Type", "http://www.w3.org/2001/04/xmlenc#");
			MimeType = Utils.GetAttribute(value, "MimeType", "http://www.w3.org/2001/04/xmlenc#");
			Encoding = Utils.GetAttribute(value, "Encoding", "http://www.w3.org/2001/04/xmlenc#");
			XmlNode xmlNode = value.SelectSingleNode("enc:EncryptionMethod", xmlNamespaceManager);
			EncryptionMethod = new EncryptionMethod();
			if (xmlNode != null)
			{
				EncryptionMethod.LoadXml(xmlNode as XmlElement);
			}
			base.KeyInfo = new KeyInfo();
			XmlNode xmlNode2 = value.SelectSingleNode("ds:KeyInfo", xmlNamespaceManager);
			if (xmlNode2 != null)
			{
				base.KeyInfo.LoadXml(xmlNode2 as XmlElement);
			}
			XmlNode xmlNode3 = value.SelectSingleNode("enc:CipherData", xmlNamespaceManager);
			if (xmlNode3 == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingCipherData"));
			}
			CipherData = new CipherData();
			CipherData.LoadXml(xmlNode3 as XmlElement);
			XmlNode xmlNode4 = value.SelectSingleNode("enc:EncryptionProperties", xmlNamespaceManager);
			if (xmlNode4 != null)
			{
				XmlNodeList xmlNodeList = xmlNode4.SelectNodes("enc:EncryptionProperty", xmlNamespaceManager);
				if (xmlNodeList != null)
				{
					foreach (XmlNode item in xmlNodeList)
					{
						EncryptionProperty encryptionProperty = new EncryptionProperty();
						encryptionProperty.LoadXml(item as XmlElement);
						EncryptionProperties.Add(encryptionProperty);
					}
				}
			}
			m_cachedXml = value;
		}

		public override XmlElement GetXml()
		{
			if (base.CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("EncryptedData", "http://www.w3.org/2001/04/xmlenc#");
			if (!string.IsNullOrEmpty(Id))
			{
				xmlElement.SetAttribute("Id", Id);
			}
			if (!string.IsNullOrEmpty(Type))
			{
				xmlElement.SetAttribute("Type", Type);
			}
			if (!string.IsNullOrEmpty(MimeType))
			{
				xmlElement.SetAttribute("MimeType", MimeType);
			}
			if (!string.IsNullOrEmpty(Encoding))
			{
				xmlElement.SetAttribute("Encoding", Encoding);
			}
			if (EncryptionMethod != null)
			{
				xmlElement.AppendChild(EncryptionMethod.GetXml(document));
			}
			if (base.KeyInfo.Count > 0)
			{
				xmlElement.AppendChild(base.KeyInfo.GetXml(document));
			}
			if (CipherData == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingCipherData"));
			}
			xmlElement.AppendChild(CipherData.GetXml(document));
			if (EncryptionProperties.Count > 0)
			{
				XmlElement xmlElement2 = document.CreateElement("EncryptionProperties", "http://www.w3.org/2001/04/xmlenc#");
				for (int i = 0; i < EncryptionProperties.Count; i++)
				{
					EncryptionProperty encryptionProperty = EncryptionProperties.Item(i);
					xmlElement2.AppendChild(encryptionProperty.GetXml(document));
				}
				xmlElement.AppendChild(xmlElement2);
			}
			return xmlElement;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class EncryptedKey : EncryptedType
	{
		private string m_recipient;

		private string m_carriedKeyName;

		private ReferenceList m_referenceList;

		public string Recipient
		{
			get
			{
				if (m_recipient == null)
				{
					m_recipient = string.Empty;
				}
				return m_recipient;
			}
			set
			{
				m_recipient = value;
				m_cachedXml = null;
			}
		}

		public string CarriedKeyName
		{
			get
			{
				return m_carriedKeyName;
			}
			set
			{
				m_carriedKeyName = value;
				m_cachedXml = null;
			}
		}

		public ReferenceList ReferenceList
		{
			get
			{
				if (m_referenceList == null)
				{
					m_referenceList = new ReferenceList();
				}
				return m_referenceList;
			}
		}

		public void AddReference(DataReference dataReference)
		{
			ReferenceList.Add(dataReference);
		}

		public void AddReference(KeyReference keyReference)
		{
			ReferenceList.Add(keyReference);
		}

		public override void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			Id = Utils.GetAttribute(value, "Id", "http://www.w3.org/2001/04/xmlenc#");
			Type = Utils.GetAttribute(value, "Type", "http://www.w3.org/2001/04/xmlenc#");
			MimeType = Utils.GetAttribute(value, "MimeType", "http://www.w3.org/2001/04/xmlenc#");
			Encoding = Utils.GetAttribute(value, "Encoding", "http://www.w3.org/2001/04/xmlenc#");
			Recipient = Utils.GetAttribute(value, "Recipient", "http://www.w3.org/2001/04/xmlenc#");
			XmlNode xmlNode = value.SelectSingleNode("enc:EncryptionMethod", xmlNamespaceManager);
			EncryptionMethod = new EncryptionMethod();
			if (xmlNode != null)
			{
				EncryptionMethod.LoadXml(xmlNode as XmlElement);
			}
			base.KeyInfo = new KeyInfo();
			XmlNode xmlNode2 = value.SelectSingleNode("ds:KeyInfo", xmlNamespaceManager);
			if (xmlNode2 != null)
			{
				base.KeyInfo.LoadXml(xmlNode2 as XmlElement);
			}
			XmlNode xmlNode3 = value.SelectSingleNode("enc:CipherData", xmlNamespaceManager);
			if (xmlNode3 == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingCipherData"));
			}
			CipherData = new CipherData();
			CipherData.LoadXml(xmlNode3 as XmlElement);
			XmlNode xmlNode4 = value.SelectSingleNode("enc:EncryptionProperties", xmlNamespaceManager);
			if (xmlNode4 != null)
			{
				XmlNodeList xmlNodeList = xmlNode4.SelectNodes("enc:EncryptionProperty", xmlNamespaceManager);
				if (xmlNodeList != null)
				{
					foreach (XmlNode item in xmlNodeList)
					{
						EncryptionProperty encryptionProperty = new EncryptionProperty();
						encryptionProperty.LoadXml(item as XmlElement);
						EncryptionProperties.Add(encryptionProperty);
					}
				}
			}
			XmlNode xmlNode6 = value.SelectSingleNode("enc:CarriedKeyName", xmlNamespaceManager);
			if (xmlNode6 != null)
			{
				CarriedKeyName = xmlNode6.InnerText;
			}
			XmlNode xmlNode7 = value.SelectSingleNode("enc:ReferenceList", xmlNamespaceManager);
			if (xmlNode7 != null)
			{
				XmlNodeList xmlNodeList2 = xmlNode7.SelectNodes("enc:DataReference", xmlNamespaceManager);
				if (xmlNodeList2 != null)
				{
					foreach (XmlNode item2 in xmlNodeList2)
					{
						DataReference dataReference = new DataReference();
						dataReference.LoadXml(item2 as XmlElement);
						ReferenceList.Add(dataReference);
					}
				}
				XmlNodeList xmlNodeList3 = xmlNode7.SelectNodes("enc:KeyReference", xmlNamespaceManager);
				if (xmlNodeList3 != null)
				{
					foreach (XmlNode item3 in xmlNodeList3)
					{
						KeyReference keyReference = new KeyReference();
						keyReference.LoadXml(item3 as XmlElement);
						ReferenceList.Add(keyReference);
					}
				}
			}
			m_cachedXml = value;
		}

		public override XmlElement GetXml()
		{
			if (base.CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("EncryptedKey", "http://www.w3.org/2001/04/xmlenc#");
			if (!string.IsNullOrEmpty(Id))
			{
				xmlElement.SetAttribute("Id", Id);
			}
			if (!string.IsNullOrEmpty(Type))
			{
				xmlElement.SetAttribute("Type", Type);
			}
			if (!string.IsNullOrEmpty(MimeType))
			{
				xmlElement.SetAttribute("MimeType", MimeType);
			}
			if (!string.IsNullOrEmpty(Encoding))
			{
				xmlElement.SetAttribute("Encoding", Encoding);
			}
			if (!string.IsNullOrEmpty(Recipient))
			{
				xmlElement.SetAttribute("Recipient", Recipient);
			}
			if (EncryptionMethod != null)
			{
				xmlElement.AppendChild(EncryptionMethod.GetXml(document));
			}
			if (base.KeyInfo.Count > 0)
			{
				xmlElement.AppendChild(base.KeyInfo.GetXml(document));
			}
			if (CipherData == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingCipherData"));
			}
			xmlElement.AppendChild(CipherData.GetXml(document));
			if (EncryptionProperties.Count > 0)
			{
				XmlElement xmlElement2 = document.CreateElement("EncryptionProperties", "http://www.w3.org/2001/04/xmlenc#");
				for (int i = 0; i < EncryptionProperties.Count; i++)
				{
					EncryptionProperty encryptionProperty = EncryptionProperties.Item(i);
					xmlElement2.AppendChild(encryptionProperty.GetXml(document));
				}
				xmlElement.AppendChild(xmlElement2);
			}
			if (ReferenceList.Count > 0)
			{
				XmlElement xmlElement3 = document.CreateElement("ReferenceList", "http://www.w3.org/2001/04/xmlenc#");
				for (int j = 0; j < ReferenceList.Count; j++)
				{
					xmlElement3.AppendChild(ReferenceList[j].GetXml(document));
				}
				xmlElement.AppendChild(xmlElement3);
			}
			if (CarriedKeyName != null)
			{
				XmlElement xmlElement4 = document.CreateElement("CarriedKeyName", "http://www.w3.org/2001/04/xmlenc#");
				XmlText newChild = document.CreateTextNode(CarriedKeyName);
				xmlElement4.AppendChild(newChild);
				xmlElement.AppendChild(xmlElement4);
			}
			return xmlElement;
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class ReferenceList : IList, ICollection, IEnumerable
	{
		private ArrayList m_references;

		public int Count => m_references.Count;

		[IndexerName("ItemOf")]
		public EncryptedReference this[int index]
		{
			get
			{
				return Item(index);
			}
			set
			{
				((IList)this)[index] = value;
			}
		}

		object IList.this[int index]
		{
			get
			{
				return m_references[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!(value is DataReference) && !(value is KeyReference))
				{
					throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
				}
				m_references[index] = value;
			}
		}

		bool IList.IsFixedSize => m_references.IsFixedSize;

		bool IList.IsReadOnly => m_references.IsReadOnly;

		public object SyncRoot => m_references.SyncRoot;

		public bool IsSynchronized => m_references.IsSynchronized;

		public ReferenceList()
		{
			m_references = new ArrayList();
		}

		public IEnumerator GetEnumerator()
		{
			return m_references.GetEnumerator();
		}

		public int Add(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is DataReference) && !(value is KeyReference))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			return m_references.Add(value);
		}

		public void Clear()
		{
			m_references.Clear();
		}

		public bool Contains(object value)
		{
			return m_references.Contains(value);
		}

		public int IndexOf(object value)
		{
			return m_references.IndexOf(value);
		}

		public void Insert(int index, object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is DataReference) && !(value is KeyReference))
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}
			m_references.Insert(index, value);
		}

		public void Remove(object value)
		{
			m_references.Remove(value);
		}

		public void RemoveAt(int index)
		{
			m_references.RemoveAt(index);
		}

		public EncryptedReference Item(int index)
		{
			return (EncryptedReference)m_references[index];
		}

		public void CopyTo(Array array, int index)
		{
			m_references.CopyTo(array, index);
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class CipherData
	{
		private XmlElement m_cachedXml;

		private CipherReference m_cipherReference;

		private byte[] m_cipherValue;

		private bool CacheValid => m_cachedXml != null;

		public CipherReference CipherReference
		{
			get
			{
				return m_cipherReference;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (CipherValue != null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CipherValueElementRequired"));
				}
				m_cipherReference = value;
				m_cachedXml = null;
			}
		}

		public byte[] CipherValue
		{
			get
			{
				return m_cipherValue;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (CipherReference != null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CipherValueElementRequired"));
				}
				m_cipherValue = (byte[])value.Clone();
				m_cachedXml = null;
			}
		}

		public CipherData()
		{
		}

		public CipherData(byte[] cipherValue)
		{
			CipherValue = cipherValue;
		}

		public CipherData(CipherReference cipherReference)
		{
			CipherReference = cipherReference;
		}

		public XmlElement GetXml()
		{
			if (CacheValid)
			{
				return m_cachedXml;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			return GetXml(xmlDocument);
		}

		internal XmlElement GetXml(XmlDocument document)
		{
			XmlElement xmlElement = document.CreateElement("CipherData", "http://www.w3.org/2001/04/xmlenc#");
			if (CipherValue != null)
			{
				XmlElement xmlElement2 = document.CreateElement("CipherValue", "http://www.w3.org/2001/04/xmlenc#");
				xmlElement2.AppendChild(document.CreateTextNode(Convert.ToBase64String(CipherValue)));
				xmlElement.AppendChild(xmlElement2);
			}
			else
			{
				if (CipherReference == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CipherValueElementRequired"));
				}
				xmlElement.AppendChild(CipherReference.GetXml(document));
			}
			return xmlElement;
		}

		public void LoadXml(XmlElement value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			XmlNode xmlNode = value.SelectSingleNode("enc:CipherValue", xmlNamespaceManager);
			XmlNode xmlNode2 = value.SelectSingleNode("enc:CipherReference", xmlNamespaceManager);
			if (xmlNode != null)
			{
				if (xmlNode2 != null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CipherValueElementRequired"));
				}
				m_cipherValue = Convert.FromBase64String(Utils.DiscardWhiteSpaces(xmlNode.InnerText));
			}
			else
			{
				if (xmlNode2 == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_CipherValueElementRequired"));
				}
				m_cipherReference = new CipherReference();
				m_cipherReference.LoadXml((XmlElement)xmlNode2);
			}
			m_cachedXml = value;
		}
	}
	[Serializable]
	internal class CryptoSignedXmlRecursionException : XmlException
	{
		public CryptoSignedXmlRecursionException()
		{
		}

		public CryptoSignedXmlRecursionException(string message)
			: base(message)
		{
		}

		public CryptoSignedXmlRecursionException(string message, Exception inner)
			: base(message, inner)
		{
		}

		protected CryptoSignedXmlRecursionException(SerializationInfo info, StreamingContext context)
		{
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public class EncryptedXml
	{
		public const string XmlEncNamespaceUrl = "http://www.w3.org/2001/04/xmlenc#";

		public const string XmlEncElementUrl = "http://www.w3.org/2001/04/xmlenc#Element";

		public const string XmlEncElementContentUrl = "http://www.w3.org/2001/04/xmlenc#Content";

		public const string XmlEncEncryptedKeyUrl = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

		public const string XmlEncDESUrl = "http://www.w3.org/2001/04/xmlenc#des-cbc";

		public const string XmlEncTripleDESUrl = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";

		public const string XmlEncAES128Url = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

		public const string XmlEncAES256Url = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

		public const string XmlEncAES192Url = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";

		public const string XmlEncRSA15Url = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

		public const string XmlEncRSAOAEPUrl = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

		public const string XmlEncTripleDESKeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";

		public const string XmlEncAES128KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes128";

		public const string XmlEncAES256KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes256";

		public const string XmlEncAES192KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes192";

		public const string XmlEncSHA256Url = "http://www.w3.org/2001/04/xmlenc#sha256";

		public const string XmlEncSHA512Url = "http://www.w3.org/2001/04/xmlenc#sha512";

		private const int m_capacity = 4;

		private XmlDocument m_document;

		private Evidence m_evidence;

		private XmlResolver m_xmlResolver;

		private Hashtable m_keyNameMapping;

		private PaddingMode m_padding;

		private CipherMode m_mode;

		private Encoding m_encoding;

		private string m_recipient;

		private int m_xmlDsigSearchDepthCounter;

		private int m_xmlDsigSearchDepth;

		public Evidence DocumentEvidence
		{
			get
			{
				return m_evidence;
			}
			set
			{
				m_evidence = value;
			}
		}

		public XmlResolver Resolver
		{
			get
			{
				return m_xmlResolver;
			}
			set
			{
				m_xmlResolver = value;
			}
		}

		public PaddingMode Padding
		{
			get
			{
				return m_padding;
			}
			set
			{
				m_padding = value;
			}
		}

		public CipherMode Mode
		{
			get
			{
				return m_mode;
			}
			set
			{
				m_mode = value;
			}
		}

		public Encoding Encoding
		{
			get
			{
				return m_encoding;
			}
			set
			{
				m_encoding = value;
			}
		}

		public string Recipient
		{
			get
			{
				if (m_recipient == null)
				{
					m_recipient = string.Empty;
				}
				return m_recipient;
			}
			set
			{
				m_recipient = value;
			}
		}

		public EncryptedXml()
			: this(new XmlDocument())
		{
		}

		public EncryptedXml(XmlDocument document)
			: this(document, null)
		{
		}

		public EncryptedXml(XmlDocument document, Evidence evidence)
		{
			m_document = document;
			m_evidence = evidence;
			m_xmlResolver = null;
			m_padding = PaddingMode.ISO10126;
			m_mode = CipherMode.CBC;
			m_encoding = Encoding.UTF8;
			m_keyNameMapping = new Hashtable(4);
			m_xmlDsigSearchDepth = Utils.GetXmlDsigSearchDepth();
		}

		private bool IsOverXmlDsigRecursionLimit()
		{
			if (m_xmlDsigSearchDepthCounter > m_xmlDsigSearchDepth)
			{
				return true;
			}
			return false;
		}

		private byte[] GetCipherValue(CipherData cipherData)
		{
			if (cipherData == null)
			{
				throw new ArgumentNullException("cipherData");
			}
			WebResponse response = null;
			Stream inputStream = null;
			if (cipherData.CipherValue != null)
			{
				return cipherData.CipherValue;
			}
			if (cipherData.CipherReference != null)
			{
				if (cipherData.CipherReference.CipherValue != null)
				{
					return cipherData.CipherReference.CipherValue;
				}
				Stream decInputStream = null;
				if (!Utils.GetLeaveCipherValueUnchecked() && cipherData.CipherReference.Uri == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotSupported"));
				}
				if (cipherData.CipherReference.Uri.Length == 0)
				{
					string baseUri = ((m_document == null) ? null : m_document.BaseURI);
					TransformChain transformChain = cipherData.CipherReference.TransformChain;
					if (!Utils.GetLeaveCipherValueUnchecked() && transformChain == null)
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotSupported"));
					}
					decInputStream = transformChain.TransformToOctetStream(m_document, m_xmlResolver, baseUri);
				}
				else if (cipherData.CipherReference.Uri[0] == '#')
				{
					string idValue = Utils.ExtractIdFromLocalUri(cipherData.CipherReference.Uri);
					if (Utils.GetLeaveCipherValueUnchecked())
					{
						inputStream = new MemoryStream(m_encoding.GetBytes(GetIdElement(m_document, idValue).OuterXml));
					}
					else
					{
						XmlElement idElement = GetIdElement(m_document, idValue);
						if (idElement == null || idElement.OuterXml == null)
						{
							throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotSupported"));
						}
						inputStream = new MemoryStream(m_encoding.GetBytes(idElement.OuterXml));
					}
					string baseUri2 = ((m_document == null) ? null : m_document.BaseURI);
					TransformChain transformChain2 = cipherData.CipherReference.TransformChain;
					if (!Utils.GetLeaveCipherValueUnchecked() && transformChain2 == null)
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotSupported"));
					}
					decInputStream = transformChain2.TransformToOctetStream(inputStream, m_xmlResolver, baseUri2);
				}
				else
				{
					DownloadCipherValue(cipherData, out inputStream, out decInputStream, out response);
				}
				byte[] array = null;
				using (MemoryStream memoryStream = new MemoryStream())
				{
					Utils.Pump(decInputStream, memoryStream);
					array = memoryStream.ToArray();
					response?.Close();
					inputStream?.Close();
					decInputStream.Close();
				}
				cipherData.CipherReference.CipherValue = array;
				return array;
			}
			throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingCipherData"));
		}

		private void DownloadCipherValue(CipherData cipherData, out Stream inputStream, out Stream decInputStream, out WebResponse response)
		{
			PermissionSet permissionSet = SecurityManager.ResolvePolicy(m_evidence);
			permissionSet.PermitOnly();
			WebRequest webRequest = WebRequest.Create(cipherData.CipherReference.Uri);
			if (webRequest == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotResolved"), cipherData.CipherReference.Uri);
			}
			response = webRequest.GetResponse();
			if (response == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotResolved"), cipherData.CipherReference.Uri);
			}
			inputStream = response.GetResponseStream();
			if (inputStream == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotResolved"), cipherData.CipherReference.Uri);
			}
			TransformChain transformChain = cipherData.CipherReference.TransformChain;
			decInputStream = transformChain.TransformToOctetStream(inputStream, m_xmlResolver, cipherData.CipherReference.Uri);
		}

		public virtual XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			return SignedXml.DefaultGetIdElement(document, idValue);
		}

		public virtual byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			int num = 0;
			if (symmetricAlgorithmUri == null)
			{
				if (encryptedData.EncryptionMethod == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingAlgorithm"));
				}
				symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
			}
			switch (symmetricAlgorithmUri)
			{
			case "http://www.w3.org/2001/04/xmlenc#des-cbc":
			case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
				num = 8;
				break;
			case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
			case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
			case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
				num = 16;
				break;
			default:
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_UriNotSupported"));
			}
			byte[] array = new byte[num];
			byte[] cipherValue = GetCipherValue(encryptedData.CipherData);
			Buffer.BlockCopy(cipherValue, 0, array, 0, array.Length);
			return array;
		}

		public virtual SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			if (encryptedData.KeyInfo == null)
			{
				return null;
			}
			IEnumerator enumerator = encryptedData.KeyInfo.GetEnumerator();
			EncryptedKey encryptedKey = null;
			while (enumerator.MoveNext())
			{
				if (enumerator.Current is KeyInfoName keyInfoName)
				{
					string value = keyInfoName.Value;
					if ((SymmetricAlgorithm)m_keyNameMapping[value] != null)
					{
						return (SymmetricAlgorithm)m_keyNameMapping[value];
					}
					XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(m_document.NameTable);
					xmlNamespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
					XmlNodeList xmlNodeList = m_document.SelectNodes("//enc:EncryptedKey", xmlNamespaceManager);
					if (xmlNodeList == null)
					{
						break;
					}
					foreach (XmlNode item in xmlNodeList)
					{
						XmlElement value2 = item as XmlElement;
						EncryptedKey encryptedKey2 = new EncryptedKey();
						encryptedKey2.LoadXml(value2);
						if (encryptedKey2.CarriedKeyName == value && encryptedKey2.Recipient == Recipient)
						{
							encryptedKey = encryptedKey2;
							break;
						}
					}
					break;
				}
				if (enumerator.Current is KeyInfoRetrievalMethod keyInfoRetrievalMethod)
				{
					string idValue = Utils.ExtractIdFromLocalUri(keyInfoRetrievalMethod.Uri);
					encryptedKey = new EncryptedKey();
					encryptedKey.LoadXml(GetIdElement(m_document, idValue));
					break;
				}
				if (enumerator.Current is KeyInfoEncryptedKey keyInfoEncryptedKey)
				{
					encryptedKey = keyInfoEncryptedKey.EncryptedKey;
					break;
				}
			}
			if (encryptedKey != null)
			{
				if (symmetricAlgorithmUri == null)
				{
					if (encryptedData.EncryptionMethod == null)
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingAlgorithm"));
					}
					symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
				}
				byte[] array = DecryptEncryptedKey(encryptedKey);
				if (array == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingDecryptionKey"));
				}
				SymmetricAlgorithm symmetricAlgorithm = Utils.CreateFromName<SymmetricAlgorithm>(symmetricAlgorithmUri);
				if (symmetricAlgorithm == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingAlgorithm"));
				}
				symmetricAlgorithm.Key = array;
				return symmetricAlgorithm;
			}
			return null;
		}

		public virtual byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
		{
			if (encryptedKey == null)
			{
				throw new ArgumentNullException("encryptedKey");
			}
			if (encryptedKey.KeyInfo == null)
			{
				return null;
			}
			IEnumerator enumerator = encryptedKey.KeyInfo.GetEnumerator();
			EncryptedKey encryptedKey2 = null;
			bool flag = false;
			while (enumerator.MoveNext())
			{
				if (enumerator.Current is KeyInfoName keyInfoName)
				{
					string value = keyInfoName.Value;
					object obj = m_keyNameMapping[value];
					if (obj == null)
					{
						break;
					}
					if (!Utils.GetLeaveCipherValueUnchecked() && (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingAlgorithm"));
					}
					if (obj is SymmetricAlgorithm)
					{
						return DecryptKey(encryptedKey.CipherData.CipherValue, (SymmetricAlgorithm)obj);
					}
					flag = encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
					return DecryptKey(encryptedKey.CipherData.CipherValue, (RSA)obj, flag);
				}
				if (enumerator.Current is KeyInfoX509Data keyInfoX509Data)
				{
					X509Certificate2Collection x509Certificate2Collection = Utils.BuildBagOfCerts(keyInfoX509Data, CertUsageType.Decryption);
					X509Certificate2Enumerator enumerator2 = x509Certificate2Collection.GetEnumerator();
					while (enumerator2.MoveNext())
					{
						X509Certificate2 current = enumerator2.Current;
						if (current.PrivateKey is RSA rsa)
						{
							if (!Utils.GetLeaveCipherValueUnchecked() && (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null))
							{
								throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingAlgorithm"));
							}
							flag = encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
							return DecryptKey(encryptedKey.CipherData.CipherValue, rsa, flag);
						}
					}
					break;
				}
				if (enumerator.Current is KeyInfoRetrievalMethod keyInfoRetrievalMethod)
				{
					string idValue = Utils.ExtractIdFromLocalUri(keyInfoRetrievalMethod.Uri);
					encryptedKey2 = new EncryptedKey();
					encryptedKey2.LoadXml(GetIdElement(m_document, idValue));
					try
					{
						m_xmlDsigSearchDepthCounter++;
						if (IsOverXmlDsigRecursionLimit())
						{
							throw new CryptoSignedXmlRecursionException();
						}
						return DecryptEncryptedKey(encryptedKey2);
					}
					finally
					{
						m_xmlDsigSearchDepthCounter--;
					}
				}
				if (!(enumerator.Current is KeyInfoEncryptedKey keyInfoEncryptedKey))
				{
					continue;
				}
				encryptedKey2 = keyInfoEncryptedKey.EncryptedKey;
				byte[] array = DecryptEncryptedKey(encryptedKey2);
				if (array != null)
				{
					SymmetricAlgorithm symmetricAlgorithm = Utils.CreateFromName<SymmetricAlgorithm>(encryptedKey.EncryptionMethod.KeyAlgorithm);
					if (symmetricAlgorithm == null)
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingAlgorithm"));
					}
					symmetricAlgorithm.Key = array;
					if (!Utils.GetLeaveCipherValueUnchecked() && (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null))
					{
						throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingAlgorithm"));
					}
					return DecryptKey(encryptedKey.CipherData.CipherValue, symmetricAlgorithm);
				}
			}
			return null;
		}

		public void AddKeyNameMapping(string keyName, object keyObject)
		{
			if (keyName == null)
			{
				throw new ArgumentNullException("keyName");
			}
			if (keyObject == null)
			{
				throw new ArgumentNullException("keyObject");
			}
			if (!(keyObject is SymmetricAlgorithm) && !(keyObject is RSA))
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_NotSupportedCryptographicTransform"));
			}
			m_keyNameMapping.Add(keyName, keyObject);
		}

		public void ClearKeyNameMappings()
		{
			m_keyNameMapping.Clear();
		}

		public EncryptedData Encrypt(XmlElement inputElement, X509Certificate2 certificate)
		{
			if (inputElement == null)
			{
				throw new ArgumentNullException("inputElement");
			}
			if (certificate == null)
			{
				throw new ArgumentNullException("certificate");
			}
			if (System.Security.Cryptography.X509Certificates.X509Utils.OidToAlgId(certificate.PublicKey.Oid.Value) != 41984)
			{
				throw new NotSupportedException(SecurityResources.GetResourceString("NotSupported_KeyAlgorithm"));
			}
			EncryptedData encryptedData = new EncryptedData();
			encryptedData.Type = "http://www.w3.org/2001/04/xmlenc#Element";
			encryptedData.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
			EncryptedKey encryptedKey = new EncryptedKey();
			encryptedKey.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
			encryptedKey.KeyInfo.AddClause(new KeyInfoX509Data(certificate));
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			encryptedKey.CipherData.CipherValue = EncryptKey(rijndaelManaged.Key, certificate.PublicKey.Key as RSA, useOAEP: false);
			KeyInfoEncryptedKey clause = new KeyInfoEncryptedKey(encryptedKey);
			encryptedData.KeyInfo.AddClause(clause);
			encryptedData.CipherData.CipherValue = EncryptData(inputElement, rijndaelManaged, content: false);
			return encryptedData;
		}

		public EncryptedData Encrypt(XmlElement inputElement, string keyName)
		{
			if (inputElement == null)
			{
				throw new ArgumentNullException("inputElement");
			}
			if (keyName == null)
			{
				throw new ArgumentNullException("keyName");
			}
			object obj = null;
			if (m_keyNameMapping != null)
			{
				obj = m_keyNameMapping[keyName];
			}
			if (obj == null)
			{
				throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingEncryptionKey"));
			}
			SymmetricAlgorithm symmetricAlgorithm = obj as SymmetricAlgorithm;
			RSA rsa = obj as RSA;
			EncryptedData encryptedData = new EncryptedData();
			encryptedData.Type = "http://www.w3.org/2001/04/xmlenc#Element";
			encryptedData.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
			string algorithm = null;
			if (symmetricAlgorithm == null)
			{
				algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
			}
			else if (symmetricAlgorithm is TripleDES)
			{
				algorithm = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";
			}
			else
			{
				if (!(symmetricAlgorithm is Rijndael))
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_NotSupportedCryptographicTransform"));
				}
				switch (symmetricAlgorithm.KeySize)
				{
				case 128:
					algorithm = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
					break;
				case 192:
					algorithm = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
					break;
				case 256:
					algorithm = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
					break;
				}
			}
			EncryptedKey encryptedKey = new EncryptedKey();
			encryptedKey.EncryptionMethod = new EncryptionMethod(algorithm);
			encryptedKey.KeyInfo.AddClause(new KeyInfoName(keyName));
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			encryptedKey.CipherData.CipherValue = ((symmetricAlgorithm == null) ? EncryptKey(rijndaelManaged.Key, rsa, useOAEP: false) : EncryptKey(rijndaelManaged.Key, symmetricAlgorithm));
			KeyInfoEncryptedKey clause = new KeyInfoEncryptedKey(encryptedKey);
			encryptedData.KeyInfo.AddClause(clause);
			encryptedData.CipherData.CipherValue = EncryptData(inputElement, rijndaelManaged, content: false);
			return encryptedData;
		}

		public void DecryptDocument()
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(m_document.NameTable);
			xmlNamespaceManager.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
			XmlNodeList xmlNodeList = m_document.SelectNodes("//enc:EncryptedData", xmlNamespaceManager);
			if (xmlNodeList == null)
			{
				return;
			}
			foreach (XmlNode item in xmlNodeList)
			{
				XmlElement xmlElement = item as XmlElement;
				EncryptedData encryptedData = new EncryptedData();
				encryptedData.LoadXml(xmlElement);
				SymmetricAlgorithm decryptionKey = GetDecryptionKey(encryptedData, null);
				if (decryptionKey == null)
				{
					throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_MissingDecryptionKey"));
				}
				byte[] decryptedData = DecryptData(encryptedData, decryptionKey);
				ReplaceData(xmlElement, decryptedData);
			}
		}

		public byte[] EncryptData(byte[] plaintext, SymmetricAlgorithm symmetricAlgorithm)
		{
			if (plaintext == null)
			{
				throw new ArgumentNullException("plaintext");
			}
			if (symmetricAlgorithm == null)
			{
				throw new ArgumentNullException("symmetricAlgorithm");
			}
			CipherMode mode = symmetricAlgorithm.Mode;
			PaddingMode padding = symmetricAlgorithm.Padding;
			byte[] array = null;
			try
			{
				symmetricAlgorithm.Mode = m_mode;
				symmetricAlgorithm.Padding = m_padding;
				ICryptoTransform cryptoTransform = symmetricAlgorithm.CreateEncryptor();
				array = cryptoTransform.TransformFinalBlock(plaintext, 0, plaintext.Length);
			}
			finally
			{
				symmetricAlgorithm.Mode = mode;
				symmetricAlgorithm.Padding = padding;
			}
			byte[] array2 = null;
			if (m_mode == CipherMode.ECB)
			{
				array2 = array;
			}
			else
			{
				byte[] iV = symmetricAlgorithm.IV;
				array2 = new byte[array.Length + iV.Length];
				Buffer.BlockCopy(iV, 0, array2, 0, iV.Length);
				Buffer.BlockCopy(array, 0, array2, iV.Length, array.Length);
			}
			return array2;
		}

		public byte[] EncryptData(XmlElement inputElement, SymmetricAlgorithm symmetricAlgorithm, bool content)
		{
			if (inputElement == null)
			{
				throw new ArgumentNullException("inputElement");
			}
			if (symmetricAlgorithm == null)
			{
				throw new ArgumentNullException("symmetricAlgorithm");
			}
			byte[] plaintext = (content ? m_encoding.GetBytes(inputElement.InnerXml) : m_encoding.GetBytes(inputElement.OuterXml));
			return EncryptData(plaintext, symmetricAlgorithm);
		}

		public byte[] DecryptData(EncryptedData encryptedData, SymmetricAlgorithm symmetricAlgorithm)
		{
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			if (symmetricAlgorithm == null)
			{
				throw new ArgumentNullException("symmetricAlgorithm");
			}
			byte[] cipherValue = GetCipherValue(encryptedData.CipherData);
			CipherMode mode = symmetricAlgorithm.Mode;
			PaddingMode padding = symmetricAlgorithm.Padding;
			byte[] iV = symmetricAlgorithm.IV;
			byte[] array = null;
			if (m_mode != CipherMode.ECB)
			{
				array = GetDecryptionIV(encryptedData, null);
			}
			byte[] array2 = null;
			try
			{
				int num = 0;
				if (array != null)
				{
					symmetricAlgorithm.IV = array;
					num = array.Length;
				}
				symmetricAlgorithm.Mode = m_mode;
				symmetricAlgorithm.Padding = m_padding;
				ICryptoTransform cryptoTransform = symmetricAlgorithm.CreateDecryptor();
				return cryptoTransform.TransformFinalBlock(cipherValue, num, cipherValue.Length - num);
			}
			finally
			{
				symmetricAlgorithm.Mode = mode;
				symmetricAlgorithm.Padding = padding;
				symmetricAlgorithm.IV = iV;
			}
		}

		public void ReplaceData(XmlElement inputElement, byte[] decryptedData)
		{
			if (inputElement == null)
			{
				throw new ArgumentNullException("inputElement");
			}
			if (decryptedData == null)
			{
				throw new ArgumentNullException("decryptedData");
			}
			XmlNode parentNode = inputElement.ParentNode;
			if (parentNode.NodeType == XmlNodeType.Document)
			{
				parentNode.InnerXml = m_encoding.GetString(decryptedData);
				return;
			}
			XmlNode xmlNode = parentNode.OwnerDocument.CreateElement(parentNode.Prefix, parentNode.LocalName, parentNode.NamespaceURI);
			try
			{
				parentNode.AppendChild(xmlNode);
				xmlNode.InnerXml = m_encoding.GetString(decryptedData);
				XmlNode xmlNode2 = xmlNode.FirstChild;
				XmlNode nextSibling = inputElement.NextSibling;
				XmlNode xmlNode3 = null;
				while (xmlNode2 != null)
				{
					xmlNode3 = xmlNode2.NextSibling;
					parentNode.InsertBefore(xmlNode2, nextSibling);
					xmlNode2 = xmlNode3;
				}
			}
			finally
			{
				parentNode.RemoveChild(xmlNode);
			}
			parentNode.RemoveChild(inputElement);
		}

		public static void ReplaceElement(XmlElement inputElement, EncryptedData encryptedData, bool content)
		{
			if (inputElement == null)
			{
				throw new ArgumentNullException("inputElement");
			}
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			XmlElement xml = encryptedData.GetXml(inputElement.OwnerDocument);
			switch (content)
			{
			case true:
				Utils.RemoveAllChildren(inputElement);
				inputElement.AppendChild(xml);
				break;
			case false:
			{
				XmlNode parentNode = inputElement.ParentNode;
				parentNode.ReplaceChild(xml, inputElement);
				break;
			}
			}
		}

		public static byte[] EncryptKey(byte[] keyData, SymmetricAlgorithm symmetricAlgorithm)
		{
			if (keyData == null)
			{
				throw new ArgumentNullException("keyData");
			}
			if (symmetricAlgorithm == null)
			{
				throw new ArgumentNullException("symmetricAlgorithm");
			}
			if (symmetricAlgorithm is TripleDES)
			{
				return SymmetricKeyWrap.TripleDESKeyWrapEncrypt(symmetricAlgorithm.Key, keyData);
			}
			if (symmetricAlgorithm is Rijndael)
			{
				return SymmetricKeyWrap.AESKeyWrapEncrypt(symmetricAlgorithm.Key, keyData);
			}
			throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_NotSupportedCryptographicTransform"));
		}

		public static byte[] EncryptKey(byte[] keyData, RSA rsa, bool useOAEP)
		{
			if (keyData == null)
			{
				throw new ArgumentNullException("keyData");
			}
			if (rsa == null)
			{
				throw new ArgumentNullException("rsa");
			}
			if (useOAEP)
			{
				RSAOAEPKeyExchangeFormatter rSAOAEPKeyExchangeFormatter = new RSAOAEPKeyExchangeFormatter(rsa);
				return rSAOAEPKeyExchangeFormatter.CreateKeyExchange(keyData);
			}
			RSAPKCS1KeyExchangeFormatter rSAPKCS1KeyExchangeFormatter = new RSAPKCS1KeyExchangeFormatter(rsa);
			return rSAPKCS1KeyExchangeFormatter.CreateKeyExchange(keyData);
		}

		public static byte[] DecryptKey(byte[] keyData, SymmetricAlgorithm symmetricAlgorithm)
		{
			if (keyData == null)
			{
				throw new ArgumentNullException("keyData");
			}
			if (symmetricAlgorithm == null)
			{
				throw new ArgumentNullException("symmetricAlgorithm");
			}
			if (symmetricAlgorithm is TripleDES)
			{
				return SymmetricKeyWrap.TripleDESKeyWrapDecrypt(symmetricAlgorithm.Key, keyData);
			}
			if (symmetricAlgorithm is Rijndael)
			{
				return SymmetricKeyWrap.AESKeyWrapDecrypt(symmetricAlgorithm.Key, keyData);
			}
			throw new CryptographicException(SecurityResources.GetResourceString("Cryptography_Xml_NotSupportedCryptographicTransform"));
		}

		public static byte[] DecryptKey(byte[] keyData, RSA rsa, bool useOAEP)
		{
			if (keyData == null)
			{
				throw new ArgumentNullException("keyData");
			}
			if (rsa == null)
			{
				throw new ArgumentNullException("rsa");
			}
			if (useOAEP)
			{
				RSAOAEPKeyExchangeDeformatter rSAOAEPKeyExchangeDeformatter = new RSAOAEPKeyExchangeDeformatter(rsa);
				return rSAOAEPKeyExchangeDeformatter.DecryptKeyExchange(keyData);
			}
			RSAPKCS1KeyExchangeDeformatter rSAPKCS1KeyExchangeDeformatter = new RSAPKCS1KeyExchangeDeformatter(rsa);
			return rSAPKCS1KeyExchangeDeformatter.DecryptKeyExchange(keyData);
		}
	}
	internal abstract class RSAPKCS1SignatureDescription : SignatureDescription
	{
		public RSAPKCS1SignatureDescription(string hashAlgorithmName)
		{
			base.KeyAlgorithm = "System.Security.Cryptography.RSA";
			base.DigestAlgorithm = hashAlgorithmName;
			base.FormatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureFormatter";
			base.DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
		}

		public sealed override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
		{
			AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = new RSAPKCS1SHA2Deformatter();
			asymmetricSignatureDeformatter.SetKey(key);
			asymmetricSignatureDeformatter.SetHashAlgorithm(base.DigestAlgorithm);
			return asymmetricSignatureDeformatter;
		}

		public sealed override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
		{
			AsymmetricSignatureFormatter asymmetricSignatureFormatter = new RSAPKCS1SHA2Formatter();
			asymmetricSignatureFormatter.SetKey(key);
			asymmetricSignatureFormatter.SetHashAlgorithm(base.DigestAlgorithm);
			return asymmetricSignatureFormatter;
		}

		public abstract override HashAlgorithm CreateDigest();
	}
	internal class RSAPKCS1SHA256SignatureDescription : RSAPKCS1SignatureDescription
	{
		public RSAPKCS1SHA256SignatureDescription()
			: base("SHA256")
		{
		}

		public sealed override HashAlgorithm CreateDigest()
		{
			return (HashAlgorithm)CryptoConfig.CreateFromName("http://www.w3.org/2001/04/xmlenc#sha256");
		}
	}
	internal class RSAPKCS1SHA384SignatureDescription : RSAPKCS1SignatureDescription
	{
		public RSAPKCS1SHA384SignatureDescription()
			: base("SHA384")
		{
		}

		public sealed override HashAlgorithm CreateDigest()
		{
			return (HashAlgorithm)CryptoConfig.CreateFromName("http://www.w3.org/2001/04/xmldsig-more#sha384");
		}
	}
	internal class RSAPKCS1SHA512SignatureDescription : RSAPKCS1SignatureDescription
	{
		public RSAPKCS1SHA512SignatureDescription()
			: base("SHA512")
		{
		}

		public sealed override HashAlgorithm CreateDigest()
		{
			return (HashAlgorithm)CryptoConfig.CreateFromName("http://www.w3.org/2001/04/xmlenc#sha512");
		}
	}
	internal class RSAPKCS1SHA2Formatter : AsymmetricSignatureFormatter
	{
		private RSA _key;

		private string _hashAlgorithm;

		public override void SetKey(AsymmetricAlgorithm key)
		{
			_key = (RSA)key;
		}

		public override void SetHashAlgorithm(string strName)
		{
			_hashAlgorithm = strName;
		}

		public override byte[] CreateSignature(byte[] rgbHash)
		{
			if (_key is RSACryptoServiceProvider rSACryptoServiceProvider)
			{
				using RSACryptoServiceProvider rSACryptoServiceProvider2 = UpgradeCspIfNeeded(rSACryptoServiceProvider);
				RSACryptoServiceProvider rSACryptoServiceProvider3 = rSACryptoServiceProvider2 ?? rSACryptoServiceProvider;
				return rSACryptoServiceProvider3.SignHash(rgbHash, _hashAlgorithm);
			}
			AsymmetricSignatureFormatter asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(_key);
			asymmetricSignatureFormatter.SetHashAlgorithm(_hashAlgorithm);
			return asymmetricSignatureFormatter.CreateSignature(rgbHash);
		}

		private static bool ShouldUpgrade(CspKeyContainerInfo keyContainerInfo)
		{
			switch (keyContainerInfo.ProviderType)
			{
			case 24:
				return false;
			default:
				return false;
			case 1:
			case 2:
			case 12:
			{
				string providerName = keyContainerInfo.ProviderName;
				StringComparison comparisonType = StringComparison.OrdinalIgnoreCase;
				if (!providerName.Equals("Microsoft Base Cryptographic Provider v1.0", comparisonType) && !providerName.Equals("Microsoft RSA Schannel Cryptographic Provider", comparisonType) && !providerName.Equals("Microsoft RSA Signature Cryptographic Provider", comparisonType) && !providerName.Equals("Microsoft Enhanced Cryptographic Provider v1.0", comparisonType) && !providerName.Equals("Microsoft Strong Cryptographic Provider", comparisonType) && !providerName.Equals("Microsoft Enhanced RSA and AES Cryptographic Provider", comparisonType) && !providerName.Equals("Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)", comparisonType))
				{
					return false;
				}
				return true;
			}
			}
		}

		private static RSACryptoServiceProvider UpgradeCspIfNeeded(RSACryptoServiceProvider rsaCsp)
		{
			CspKeyContainerInfo cspKeyContainerInfo = rsaCsp.CspKeyContainerInfo;
			if (!ShouldUpgrade(cspKeyContainerInfo))
			{
				return null;
			}
			CspParameters cspParameters = new CspParameters(24);
			cspParameters.KeyContainerName = cspKeyContainerInfo.KeyContainerName;
			cspParameters.Flags = CspProviderFlags.UseExistingKey;
			if (cspKeyContainerInfo.MachineKeyStore)
			{
				cspParameters.Flags |= CspProviderFlags.UseMachineKeyStore;
			}
			cspParameters.KeyNumber = (int)cspKeyContainerInfo.KeyNumber;
			try
			{
				return new RSACryptoServiceProvider(cspParameters);
			}
			catch (CryptographicException)
			{
				return null;
			}
		}
	}
	internal class RSAPKCS1SHA2Deformatter : AsymmetricSignatureDeformatter
	{
		private RSA _key;

		private string _hashAlgorithm;

		public override void SetKey(AsymmetricAlgorithm key)
		{
			_key = (RSA)key;
		}

		public override void SetHashAlgorithm(string strName)
		{
			_hashAlgorithm = strName;
		}

		public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
		{
			if (_key is RSACryptoServiceProvider rSACryptoServiceProvider && rSACryptoServiceProvider.CspKeyContainerInfo.ProviderType != 24)
			{
				RSAParameters parameters = _key.ExportParameters(includePrivateParameters: false);
				using RSACryptoServiceProvider rSACryptoServiceProvider2 = new RSACryptoServiceProvider();
				rSACryptoServiceProvider2.ImportParameters(parameters);
				return rSACryptoServiceProvider2.VerifyHash(rgbHash, _hashAlgorithm, rgbSignature);
			}
			AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = new RSAPKCS1SignatureDeformatter(_key);
			asymmetricSignatureDeformatter.SetHashAlgorithm(_hashAlgorithm);
			return asymmetricSignatureDeformatter.VerifySignature(rgbHash, rgbSignature);
		}
	}
}
namespace System.Security.Permissions
{
	[Serializable]
	public sealed class DataProtectionPermission : CodeAccessPermission, IUnrestrictedPermission
	{
		private DataProtectionPermissionFlags m_flags;

		public DataProtectionPermissionFlags Flags
		{
			get
			{
				return m_flags;
			}
			set
			{
				VerifyFlags(value);
				m_flags = value;
			}
		}

		public DataProtectionPermission(PermissionState state)
		{
			switch (state)
			{
			case PermissionState.Unrestricted:
				m_flags = DataProtectionPermissionFlags.AllFlags;
				break;
			case PermissionState.None:
				m_flags = DataProtectionPermissionFlags.NoFlags;
				break;
			default:
				throw new ArgumentException(SecurityResources.GetResourceString("Argument_InvalidPermissionState"));
			}
		}

		public DataProtectionPermission(DataProtectionPermissionFlags flag)
		{
			Flags = flag;
		}

		public bool IsUnrestricted()
		{
			return m_flags == DataProtectionPermissionFlags.AllFlags;
		}

		public override IPermission Union(IPermission target)
		{
			if (target == null)
			{
				return Copy();
			}
			try
			{
				DataProtectionPermission dataProtectionPermission = (DataProtectionPermission)target;
				DataProtectionPermissionFlags dataProtectionPermissionFlags = m_flags | dataProtectionPermission.m_flags;
				if (dataProtectionPermissionFlags == DataProtectionPermissionFlags.NoFlags)
				{
					return null;
				}
				return new DataProtectionPermission(dataProtectionPermissionFlags);
			}
			catch (InvalidCastException)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Argument_WrongType"), GetType().FullName));
			}
		}

		public override bool IsSubsetOf(IPermission target)
		{
			if (target == null)
			{
				return m_flags == DataProtectionPermissionFlags.NoFlags;
			}
			try
			{
				DataProtectionPermission dataProtectionPermission = (DataProtectionPermission)target;
				DataProtectionPermissionFlags flags = m_flags;
				DataProtectionPermissionFlags flags2 = dataProtectionPermission.m_flags;
				return (flags & flags2) == flags;
			}
			catch (InvalidCastException)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Argument_WrongType"), GetType().FullName));
			}
		}

		public override IPermission Intersect(IPermission target)
		{
			if (target == null)
			{
				return null;
			}
			try
			{
				DataProtectionPermission dataProtectionPermission = (DataProtectionPermission)target;
				DataProtectionPermissionFlags dataProtectionPermissionFlags = dataProtectionPermission.m_flags & m_flags;
				if (dataProtectionPermissionFlags == DataProtectionPermissionFlags.NoFlags)
				{
					return null;
				}
				return new DataProtectionPermission(dataProtectionPermissionFlags);
			}
			catch (InvalidCastException)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Argument_WrongType"), GetType().FullName));
			}
		}

		public override IPermission Copy()
		{
			if (Flags == DataProtectionPermissionFlags.NoFlags)
			{
				return null;
			}
			return new DataProtectionPermission(m_flags);
		}

		public override SecurityElement ToXml()
		{
			SecurityElement securityElement = new SecurityElement("IPermission");
			securityElement.AddAttribute("class", GetType().FullName + ", " + GetType().Module.Assembly.FullName.Replace('"', '\''));
			securityElement.AddAttribute("version", "1");
			if (!IsUnrestricted())
			{
				securityElement.AddAttribute("Flags", m_flags.ToString());
			}
			else
			{
				securityElement.AddAttribute("Unrestricted", "true");
			}
			return securityElement;
		}

		public override void FromXml(SecurityElement securityElement)
		{
			if (securityElement == null)
			{
				throw new ArgumentNullException("securityElement");
			}
			string text = securityElement.Attribute("class");
			if (text == null || text.IndexOf(GetType().FullName, StringComparison.Ordinal) == -1)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Argument_InvalidClassAttribute"), "securityElement");
			}
			string text2 = securityElement.Attribute("Unrestricted");
			if (text2 != null && string.Compare(text2, "true", StringComparison.OrdinalIgnoreCase) == 0)
			{
				m_flags = DataProtectionPermissionFlags.AllFlags;
				return;
			}
			m_flags = DataProtectionPermissionFlags.NoFlags;
			string text3 = securityElement.Attribute("Flags");
			if (text3 != null)
			{
				DataProtectionPermissionFlags flags = (DataProtectionPermissionFlags)Enum.Parse(typeof(DataProtectionPermissionFlags), text3);
				VerifyFlags(flags);
				m_flags = flags;
			}
		}

		internal static void VerifyFlags(DataProtectionPermissionFlags flags)
		{
			if (((uint)flags & 0xFFFFFFF0u) != 0)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SecurityResources.GetResourceString("Arg_EnumIllegalVal"), (int)flags));
			}
		}
	}
	[Serializable]
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Constructor | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	public sealed class DataProtectionPermissionAttribute : CodeAccessSecurityAttribute
	{
		private DataProtectionPermissionFlags m_flags;

		public DataProtectionPermissionFlags Flags
		{
			get
			{
				return m_flags;
			}
			set
			{
				DataProtectionPermission.VerifyFlags(value);
				m_flags = value;
			}
		}

		public bool ProtectData
		{
			get
			{
				return (m_flags & DataProtectionPermissionFlags.ProtectData) != 0;
			}
			set
			{
				m_flags = (value ? (m_flags | DataProtectionPermissionFlags.ProtectData) : (m_flags & ~DataProtectionPermissionFlags.ProtectData));
			}
		}

		public bool UnprotectData
		{
			get
			{
				return (m_flags & DataProtectionPermissionFlags.UnprotectData) != 0;
			}
			set
			{
				m_flags = (value ? (m_flags | DataProtectionPermissionFlags.UnprotectData) : (m_flags & ~DataProtectionPermissionFlags.UnprotectData));
			}
		}

		public bool ProtectMemory
		{
			get
			{
				return (m_flags & DataProtectionPermissionFlags.ProtectMemory) != 0;
			}
			set
			{
				m_flags = (value ? (m_flags | DataProtectionPermissionFlags.ProtectMemory) : (m_flags & ~DataProtectionPermissionFlags.ProtectMemory));
			}
		}

		public bool UnprotectMemory
		{
			get
			{
				return (m_flags & DataProtectionPermissionFlags.UnprotectMemory) != 0;
			}
			set
			{
				m_flags = (value ? (m_flags | DataProtectionPermissionFlags.UnprotectMemory) : (m_flags & ~DataProtectionPermissionFlags.UnprotectMemory));
			}
		}

		public DataProtectionPermissionAttribute(SecurityAction action)
			: base(action)
		{
		}

		public override IPermission CreatePermission()
		{
			if (base.Unrestricted)
			{
				return new DataProtectionPermission(PermissionState.Unrestricted);
			}
			return new DataProtectionPermission(m_flags);
		}
	}
	[Serializable]
	[Flags]
	public enum DataProtectionPermissionFlags
	{
		NoFlags = 0,
		ProtectData = 1,
		UnprotectData = 2,
		ProtectMemory = 4,
		UnprotectMemory = 8,
		AllFlags = 0xF
	}
}
