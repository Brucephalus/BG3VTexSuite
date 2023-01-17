
// C:\WINDOWS\assembly\GAC_MSIL\System.DirectoryServices\2.0.0.0__b03f5f7f11d50a3a\System.DirectoryServices.dll
// System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
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
using System.Configuration;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Design;
using System.DirectoryServices.Interop;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Xml;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyDescription("System.DirectoryServices.dll")]
[assembly: CLSCompliant(true)]
[assembly: ComVisible(false)]
[assembly: AssemblyDefaultAlias("System.DirectoryServices.dll")]
[assembly: AssemblyTitle("System.DirectoryServices.dll")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: CompilationRelaxations(8)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: AssemblyInformationalVersion("2.0.50727.9162")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.50727.9162")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: FileIOPermission(SecurityAction.RequestMinimum, AllFiles = FileIOPermissionAccess.PathDiscovery)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, UnmanagedCode = true)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: EnvironmentPermission(SecurityAction.RequestMinimum, Unrestricted = true)]
[assembly: DnsPermission(SecurityAction.RequestMinimum, Unrestricted = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
internal static class FXAssembly
{
	internal const string Version = "2.0.0.0";
}
internal static class ThisAssembly
{
	internal const string Title = "System.DirectoryServices.dll";

	internal const string Description = "System.DirectoryServices.dll";

	internal const string DefaultAlias = "System.DirectoryServices.dll";

	internal const string Copyright = "© Microsoft Corporation.  All rights reserved.";

	internal const string Version = "2.0.0.0";

	internal const string InformationalVersion = "2.0.50727.9162";

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
namespace System.DirectoryServices
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
		internal const string DSDoesNotImplementIADs = "DSDoesNotImplementIADs";

		internal const string DSNoObject = "DSNoObject";

		internal const string DSInvalidPath = "DSInvalidPath";

		internal const string DSNotAContainer = "DSNotAContainer";

		internal const string DSCannotDelete = "DSCannotDelete";

		internal const string DSNotInCollection = "DSNotInCollection";

		internal const string DSNoCurrentChild = "DSNoCurrentChild";

		internal const string DSCannotBeIndexed = "DSCannotBeIndexed";

		internal const string DSCannotCount = "DSCannotCount";

		internal const string DSCannotGetKeys = "DSCannotGetKeys";

		internal const string DSCannotEmunerate = "DSCannotEmunerate";

		internal const string DSNoCurrentProperty = "DSNoCurrentProperty";

		internal const string DSNoCurrentValue = "DSNoCurrentValue";

		internal const string DSBadPageSize = "DSBadPageSize";

		internal const string DSBadSizeLimit = "DSBadSizeLimit";

		internal const string DSSearchUnsupported = "DSSearchUnsupported";

		internal const string DSNoCurrentEntry = "DSNoCurrentEntry";

		internal const string DSInvalidSearchFilter = "DSInvalidSearchFilter";

		internal const string DSPropertyNotFound = "DSPropertyNotFound";

		internal const string DSConvertFailed = "DSConvertFailed";

		internal const string DSConvertTypeInvalid = "DSConvertTypeInvalid";

		internal const string DSAdsvalueTypeNYI = "DSAdsvalueTypeNYI";

		internal const string DSAdsiNotInstalled = "DSAdsiNotInstalled";

		internal const string DSNotSet = "DSNotSet";

		internal const string DSEnumerator = "DSEnumerator";

		internal const string DSPathIsNotSet = "DSPathIsNotSet";

		internal const string DSPropertySetSupported = "DSPropertySetSupported";

		internal const string DSAddNotSupported = "DSAddNotSupported";

		internal const string DSClearNotSupported = "DSClearNotSupported";

		internal const string DSRemoveNotSupported = "DSRemoveNotSupported";

		internal const string DSSearchPreferencesNotAccepted = "DSSearchPreferencesNotAccepted";

		internal const string DSBeforeCount = "DSBeforeCount";

		internal const string DSBadBeforeCount = "DSBadBeforeCount";

		internal const string DSAfterCount = "DSAfterCount";

		internal const string DSBadAfterCount = "DSBadAfterCount";

		internal const string DSOffset = "DSOffset";

		internal const string DSBadOffset = "DSBadOffset";

		internal const string DSTargetPercentage = "DSTargetPercentage";

		internal const string DSBadTargetPercentage = "DSBadTargetPercentage";

		internal const string DSTarget = "DSTarget";

		internal const string DSApproximateTotal = "DSApproximateTotal";

		internal const string DSBadApproximateTotal = "DSBadApproximateTotal";

		internal const string DSDirectoryVirtualListViewContext = "DSDirectoryVirtualListViewContext";

		internal const string DSVirtualListView = "DSVirtualListView";

		internal const string DSBadPageSizeDirsync = "DSBadPageSizeDirsync";

		internal const string DSBadCacheResultsVLV = "DSBadCacheResultsVLV";

		internal const string DSBadDirectorySynchronizationFlag = "DSBadDirectorySynchronizationFlag";

		internal const string DSBadASQSearchScope = "DSBadASQSearchScope";

		internal const string DSDoesNotImplementIADsObjectOptions = "DSDoesNotImplementIADsObjectOptions";

		internal const string DSPropertyValueSupportOneOperation = "DSPropertyValueSupportOneOperation";

		internal const string ConfigSectionsUnique = "ConfigSectionsUnique";

		internal const string Invalid_boolean_attribute = "Invalid_boolean_attribute";

		internal const string DSUnknownFailure = "DSUnknownFailure";

		internal const string DSNotSupportOnClient = "DSNotSupportOnClient";

		internal const string DSNotSupportOnDC = "DSNotSupportOnDC";

		internal const string DirectoryContextNeedHost = "DirectoryContextNeedHost";

		internal const string DSSyncAllFailure = "DSSyncAllFailure";

		internal const string UnknownTransport = "UnknownTransport";

		internal const string NotSupportTransportSMTP = "NotSupportTransportSMTP";

		internal const string CannotDelete = "CannotDelete";

		internal const string CannotGetObject = "CannotGetObject";

		internal const string DSNotFound = "DSNotFound";

		internal const string InvalidContextTarget = "InvalidContextTarget";

		internal const string TransportNotFound = "TransportNotFound";

		internal const string SiteNotExist = "SiteNotExist";

		internal const string SiteNotCommitted = "SiteNotCommitted";

		internal const string NoCurrentSite = "NoCurrentSite";

		internal const string SubnetNotCommitted = "SubnetNotCommitted";

		internal const string SiteLinkNotCommitted = "SiteLinkNotCommitted";

		internal const string ConnectionNotCommitted = "ConnectionNotCommitted";

		internal const string AlreadyExistingForestTrust = "AlreadyExistingForestTrust";

		internal const string AlreadyExistingDomainTrust = "AlreadyExistingDomainTrust";

		internal const string NotFoundInCollection = "NotFoundInCollection";

		internal const string AlreadyExistingInCollection = "AlreadyExistingInCollection";

		internal const string NTDSSiteSetting = "NTDSSiteSetting";

		internal const string NotWithinSite = "NotWithinSite";

		internal const string InvalidTime = "InvalidTime";

		internal const string EmptyStringParameter = "EmptyStringParameter";

		internal const string SupportedPlatforms = "SupportedPlatforms";

		internal const string TargetShouldBeADAMServer = "TargetShouldBeADAMServer";

		internal const string TargetShouldBeDC = "TargetShouldBeDC";

		internal const string TargetShouldBeAppNCDnsName = "TargetShouldBeAppNCDnsName";

		internal const string TargetShouldBeServerORForest = "TargetShouldBeServerORForest";

		internal const string TargetShouldBeServerORDomain = "TargetShouldBeServerORDomain";

		internal const string TargetShouldBeDomain = "TargetShouldBeDomain";

		internal const string TargetShouldBeForest = "TargetShouldBeForest";

		internal const string TargetShouldBeConfigSet = "TargetShouldBeConfigSet";

		internal const string TargetShouldBeServerORConfigSet = "TargetShouldBeServerORConfigSet";

		internal const string TargetShouldBeGC = "TargetShouldBeGC";

		internal const string TargetShouldBeServer = "TargetShouldBeServer";

		internal const string NotADOrADAM = "NotADOrADAM";

		internal const string ServerNotAReplica = "ServerNotAReplica";

		internal const string AppNCNotFound = "AppNCNotFound";

		internal const string ReplicaNotFound = "ReplicaNotFound";

		internal const string GCNotFoundInForest = "GCNotFoundInForest";

		internal const string DCNotFoundInDomain = "DCNotFoundInDomain";

		internal const string ADAMInstanceNotFoundInConfigSet = "ADAMInstanceNotFoundInConfigSet";

		internal const string DCNotFound = "DCNotFound";

		internal const string GCNotFound = "GCNotFound";

		internal const string AINotFound = "AINotFound";

		internal const string ServerNotFound = "ServerNotFound";

		internal const string DomainNotFound = "DomainNotFound";

		internal const string ForestNotFound = "ForestNotFound";

		internal const string ConfigSetNotFound = "ConfigSetNotFound";

		internal const string NDNCNotFound = "NDNCNotFound";

		internal const string PropertyNotFoundOnObject = "PropertyNotFoundOnObject";

		internal const string PropertyNotFound = "PropertyNotFound";

		internal const string PropertyNotSet = "PropertyNotSet";

		internal const string ADAMInstanceNotFound = "ADAMInstanceNotFound";

		internal const string CannotPerformOperationOnUncommittedObject = "CannotPerformOperationOnUncommittedObject";

		internal const string LinkIdNotEvenNumber = "LinkIdNotEvenNumber";

		internal const string InvalidServerNameFormat = "InvalidServerNameFormat";

		internal const string NoObjectClassForADPartition = "NoObjectClassForADPartition";

		internal const string InvalidDNFormat = "InvalidDNFormat";

		internal const string InvalidDnsName = "InvalidDnsName";

		internal const string ApplicationPartitionTypeUnknown = "ApplicationPartitionTypeUnknown";

		internal const string UnknownSyntax = "UnknownSyntax";

		internal const string InvalidMode = "InvalidMode";

		internal const string NoW2K3DCs = "NoW2K3DCs";

		internal const string DCInfoNotFound = "DCInfoNotFound";

		internal const string NoW2K3DCsInForest = "NoW2K3DCsInForest";

		internal const string SchemaObjectNotCommitted = "SchemaObjectNotCommitted";

		internal const string InvalidFlags = "InvalidFlags";

		internal const string CannotPerformOnGCObject = "CannotPerformOnGCObject";

		internal const string CannotPerformOnGC = "CannotPerformOnGC";

		internal const string ValueCannotBeModified = "ValueCannotBeModified";

		internal const string ServerShouldBeW2K3 = "ServerShouldBeW2K3";

		internal const string LinkedPropertyNotFound = "LinkedPropertyNotFound";

		internal const string GCDisabled = "GCDisabled";

		internal const string PropertyInvalidForADAM = "PropertyInvalidForADAM";

		internal const string OperationInvalidForADAM = "OperationInvalidForADAM";

		internal const string ContextNotAssociatedWithDomain = "ContextNotAssociatedWithDomain";

		internal const string ComputerNotJoinedToDomain = "ComputerNotJoinedToDomain";

		internal const string VersionFailure = "VersionFailure";

		internal const string NoHostName = "NoHostName";

		internal const string NoHostNameOrPortNumber = "NoHostNameOrPortNumber";

		internal const string NTAuthority = "NTAuthority";

		internal const string Name = "Name";

		internal const string OneLevelPartitionNotSupported = "OneLevelPartitionNotSupported";

		internal const string SiteNameNotFound = "SiteNameNotFound";

		internal const string SiteObjectNameNotFound = "SiteObjectNameNotFound";

		internal const string ComputerObjectNameNotFound = "ComputerObjectNameNotFound";

		internal const string ServerObjectNameNotFound = "ServerObjectNameNotFound";

		internal const string NtdsaObjectNameNotFound = "NtdsaObjectNameNotFound";

		internal const string NtdsaObjectGuidNotFound = "NtdsaObjectGuidNotFound";

		internal const string OnlyDomainOrForest = "OnlyDomainOrForest";

		internal const string ServerShouldBeDC = "ServerShouldBeDC";

		internal const string ServerShouldBeAI = "ServerShouldBeAI";

		internal const string CannotModifySacl = "CannotModifySacl";

		internal const string CannotModifyDacl = "CannotModifyDacl";

		internal const string ForestTrustCollision = "ForestTrustCollision";

		internal const string ForestTrustDoesNotExist = "ForestTrustDoesNotExist";

		internal const string DomainTrustDoesNotExist = "DomainTrustDoesNotExist";

		internal const string WrongForestTrust = "WrongForestTrust";

		internal const string WrongTrustDirection = "WrongTrustDirection";

		internal const string NT4NotSupported = "NT4NotSupported";

		internal const string KerberosNotSupported = "KerberosNotSupported";

		internal const string DSPropertyListUnsupported = "DSPropertyListUnsupported";

		internal const string DSMultipleSDNotSupported = "DSMultipleSDNotSupported";

		internal const string DSSDNoValues = "DSSDNoValues";

		internal const string ConnectionSourcServerShouldBeDC = "ConnectionSourcServerShouldBeDC";

		internal const string ConnectionSourcServerShouldBeADAM = "ConnectionSourcServerShouldBeADAM";

		internal const string ConnectionSourcServerSameForest = "ConnectionSourcServerSameForest";

		internal const string ConnectionSourcServerSameConfigSet = "ConnectionSourcServerSameConfigSet";

		internal const string TrustVerificationNotSupport = "TrustVerificationNotSupport";

		internal const string DSChildren = "DSChildren";

		internal const string DSGuid = "DSGuid";

		internal const string DSName = "DSName";

		internal const string DSNativeObject = "DSNativeObject";

		internal const string DSParent = "DSParent";

		internal const string DSPassword = "DSPassword";

		internal const string DSPath = "DSPath";

		internal const string DSProperties = "DSProperties";

		internal const string DSSchemaClassName = "DSSchemaClassName";

		internal const string DSSchemaEntry = "DSSchemaEntry";

		internal const string DSUsePropertyCache = "DSUsePropertyCache";

		internal const string DSUsername = "DSUsername";

		internal const string DSAuthenticationType = "DSAuthenticationType";

		internal const string DSNativeGuid = "DSNativeGuid";

		internal const string DSCacheResults = "DSCacheResults";

		internal const string DSClientTimeout = "DSClientTimeout";

		internal const string DSPropertyNamesOnly = "DSPropertyNamesOnly";

		internal const string DSFilter = "DSFilter";

		internal const string DSPageSize = "DSPageSize";

		internal const string DSPropertiesToLoad = "DSPropertiesToLoad";

		internal const string DSReferralChasing = "DSReferralChasing";

		internal const string DSSearchScope = "DSSearchScope";

		internal const string DSServerPageTimeLimit = "DSServerPageTimeLimit";

		internal const string DSServerTimeLimit = "DSServerTimeLimit";

		internal const string DSSizeLimit = "DSSizeLimit";

		internal const string DSSearchRoot = "DSSearchRoot";

		internal const string DSSort = "DSSort";

		internal const string DSSortName = "DSSortName";

		internal const string DSSortDirection = "DSSortDirection";

		internal const string DSAsynchronous = "DSAsynchronous";

		internal const string DSTombstone = "DSTombstone";

		internal const string DSAttributeQuery = "DSAttributeQuery";

		internal const string DSDerefAlias = "DSDerefAlias";

		internal const string DSSecurityMasks = "DSSecurityMasks";

		internal const string DSExtendedDn = "DSExtendedDn";

		internal const string DSDirectorySynchronizationFlag = "DSDirectorySynchronizationFlag";

		internal const string DSDirectorySynchronizationCookie = "DSDirectorySynchronizationCookie";

		internal const string DSDirectorySynchronization = "DSDirectorySynchronization";

		internal const string DSUnknown = "DSUnknown";

		internal const string DSOptions = "DSOptions";

		internal const string DSObjectSecurity = "DSObjectSecurity";

		internal const string DirectoryEntryDesc = "DirectoryEntryDesc";

		internal const string DirectorySearcherDesc = "DirectorySearcherDesc";

		internal const string OnlyAllowSingleDimension = "OnlyAllowSingleDimension";

		internal const string LessThanZero = "LessThanZero";

		internal const string DestinationArrayNotLargeEnough = "DestinationArrayNotLargeEnough";

		internal const string NoNegativeTime = "NoNegativeTime";

		internal const string ReplicationIntervalExceedMax = "ReplicationIntervalExceedMax";

		internal const string ReplicationIntervalInMinutes = "ReplicationIntervalInMinutes";

		internal const string TimespanExceedMax = "TimespanExceedMax";

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
			resources = new ResourceManager("System.DirectoryServices", GetType().Assembly);
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
namespace System.DirectoryServices
{
	[Flags]
	public enum ActiveDirectoryRights
	{
		Delete = 0x10000,
		ReadControl = 0x20000,
		WriteDacl = 0x40000,
		WriteOwner = 0x80000,
		Synchronize = 0x100000,
		AccessSystemSecurity = 0x1000000,
		GenericRead = 0x20094,
		GenericWrite = 0x20028,
		GenericExecute = 0x20004,
		GenericAll = 0xF01FF,
		CreateChild = 1,
		DeleteChild = 2,
		ListChildren = 4,
		Self = 8,
		ReadProperty = 0x10,
		WriteProperty = 0x20,
		DeleteTree = 0x40,
		ListObject = 0x80,
		ExtendedRight = 0x100
	}
	public enum ActiveDirectorySecurityInheritance
	{
		None,
		All,
		Descendents,
		SelfAndChildren,
		Children
	}
	public enum PropertyAccess
	{
		Read,
		Write
	}
	public class ActiveDirectorySecurity : DirectoryObjectSecurity
	{
		private SecurityMasks securityMaskUsedInRetrieval = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;

		public override Type AccessRightType => typeof(ActiveDirectoryRights);

		public override Type AccessRuleType => typeof(ActiveDirectoryAccessRule);

		public override Type AuditRuleType => typeof(ActiveDirectoryAuditRule);

		public ActiveDirectorySecurity()
		{
		}

		internal ActiveDirectorySecurity(byte[] sdBinaryForm, SecurityMasks securityMask)
			: base(new CommonSecurityDescriptor(isContainer: true, isDS: true, sdBinaryForm, 0))
		{
			securityMaskUsedInRetrieval = securityMask;
		}

		public void AddAccessRule(ActiveDirectoryAccessRule rule)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			AddAccessRule((ObjectAccessRule)rule);
		}

		public void SetAccessRule(ActiveDirectoryAccessRule rule)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			SetAccessRule((ObjectAccessRule)rule);
		}

		public void ResetAccessRule(ActiveDirectoryAccessRule rule)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			ResetAccessRule((ObjectAccessRule)rule);
		}

		public void RemoveAccess(IdentityReference identity, AccessControlType type)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			ActiveDirectoryAccessRule rule = new ActiveDirectoryAccessRule(identity, ActiveDirectoryRights.GenericRead, type, ActiveDirectorySecurityInheritance.None);
			RemoveAccessRuleAll(rule);
		}

		public bool RemoveAccessRule(ActiveDirectoryAccessRule rule)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			return RemoveAccessRule((ObjectAccessRule)rule);
		}

		public void RemoveAccessRuleSpecific(ActiveDirectoryAccessRule rule)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			RemoveAccessRuleSpecific((ObjectAccessRule)rule);
		}

		public override bool ModifyAccessRule(AccessControlModification modification, AccessRule rule, out bool modified)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			return base.ModifyAccessRule(modification, rule, out modified);
		}

		public override void PurgeAccessRules(IdentityReference identity)
		{
			if (!DaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifyDacl"));
			}
			base.PurgeAccessRules(identity);
		}

		public void AddAuditRule(ActiveDirectoryAuditRule rule)
		{
			if (!SaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifySacl"));
			}
			AddAuditRule((ObjectAuditRule)rule);
		}

		public void SetAuditRule(ActiveDirectoryAuditRule rule)
		{
			if (!SaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifySacl"));
			}
			SetAuditRule((ObjectAuditRule)rule);
		}

		public void RemoveAudit(IdentityReference identity)
		{
			if (!SaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifySacl"));
			}
			ActiveDirectoryAuditRule rule = new ActiveDirectoryAuditRule(identity, ActiveDirectoryRights.GenericRead, AuditFlags.Success | AuditFlags.Failure, ActiveDirectorySecurityInheritance.None);
			RemoveAuditRuleAll(rule);
		}

		public bool RemoveAuditRule(ActiveDirectoryAuditRule rule)
		{
			if (!SaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifySacl"));
			}
			return RemoveAuditRule((ObjectAuditRule)rule);
		}

		public void RemoveAuditRuleSpecific(ActiveDirectoryAuditRule rule)
		{
			if (!SaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifySacl"));
			}
			RemoveAuditRuleSpecific((ObjectAuditRule)rule);
		}

		public override bool ModifyAuditRule(AccessControlModification modification, AuditRule rule, out bool modified)
		{
			if (!SaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifySacl"));
			}
			return base.ModifyAuditRule(modification, rule, out modified);
		}

		public override void PurgeAuditRules(IdentityReference identity)
		{
			if (!SaclRetrieved())
			{
				throw new InvalidOperationException(Res.GetString("CannotModifySacl"));
			}
			base.PurgeAuditRules(identity);
		}

		public sealed override AccessRule AccessRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
		{
			return new ActiveDirectoryAccessRule(identityReference, accessMask, type, Guid.Empty, isInherited, inheritanceFlags, propagationFlags, Guid.Empty);
		}

		public sealed override AccessRule AccessRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type, Guid objectGuid, Guid inheritedObjectGuid)
		{
			return new ActiveDirectoryAccessRule(identityReference, accessMask, type, objectGuid, isInherited, inheritanceFlags, propagationFlags, inheritedObjectGuid);
		}

		public sealed override AuditRule AuditRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
		{
			return new ActiveDirectoryAuditRule(identityReference, accessMask, flags, Guid.Empty, isInherited, inheritanceFlags, propagationFlags, Guid.Empty);
		}

		public sealed override AuditRule AuditRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags, Guid objectGuid, Guid inheritedObjectGuid)
		{
			return new ActiveDirectoryAuditRule(identityReference, accessMask, flags, objectGuid, isInherited, inheritanceFlags, propagationFlags, inheritedObjectGuid);
		}

		internal bool IsModified()
		{
			ReadLock();
			try
			{
				return base.OwnerModified || base.GroupModified || base.AccessRulesModified || base.AuditRulesModified;
			}
			finally
			{
				ReadUnlock();
			}
		}

		private bool DaclRetrieved()
		{
			return (securityMaskUsedInRetrieval & SecurityMasks.Dacl) != 0;
		}

		private bool SaclRetrieved()
		{
			return (securityMaskUsedInRetrieval & SecurityMasks.Sacl) != 0;
		}
	}
	internal sealed class ActiveDirectoryRightsTranslator
	{
		internal static int AccessMaskFromRights(ActiveDirectoryRights adRights)
		{
			return (int)adRights;
		}

		internal static ActiveDirectoryRights RightsFromAccessMask(int accessMask)
		{
			return (ActiveDirectoryRights)accessMask;
		}
	}
	internal sealed class PropertyAccessTranslator
	{
		internal static int AccessMaskFromPropertyAccess(PropertyAccess access)
		{
			int num = 0;
			if (access < PropertyAccess.Read || access > PropertyAccess.Write)
			{
				throw new InvalidEnumArgumentException("access", (int)access, typeof(PropertyAccess));
			}
			return access switch
			{
				PropertyAccess.Read => ActiveDirectoryRightsTranslator.AccessMaskFromRights(ActiveDirectoryRights.ReadProperty), 
				PropertyAccess.Write => ActiveDirectoryRightsTranslator.AccessMaskFromRights(ActiveDirectoryRights.WriteProperty), 
				_ => throw new ArgumentException("access"), 
			};
		}
	}
	internal sealed class ActiveDirectoryInheritanceTranslator
	{
		internal static InheritanceFlags[] ITToIF = new InheritanceFlags[5]
		{
			InheritanceFlags.None,
			InheritanceFlags.ContainerInherit,
			InheritanceFlags.ContainerInherit,
			InheritanceFlags.ContainerInherit,
			InheritanceFlags.ContainerInherit
		};

		internal static PropagationFlags[] ITToPF = new PropagationFlags[5]
		{
			PropagationFlags.None,
			PropagationFlags.None,
			PropagationFlags.InheritOnly,
			PropagationFlags.NoPropagateInherit,
			PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly
		};

		internal static InheritanceFlags GetInheritanceFlags(ActiveDirectorySecurityInheritance inheritanceType)
		{
			if (inheritanceType < ActiveDirectorySecurityInheritance.None || inheritanceType > ActiveDirectorySecurityInheritance.Children)
			{
				throw new InvalidEnumArgumentException("inheritanceType", (int)inheritanceType, typeof(ActiveDirectorySecurityInheritance));
			}
			return ITToIF[(int)inheritanceType];
		}

		internal static PropagationFlags GetPropagationFlags(ActiveDirectorySecurityInheritance inheritanceType)
		{
			if (inheritanceType < ActiveDirectorySecurityInheritance.None || inheritanceType > ActiveDirectorySecurityInheritance.Children)
			{
				throw new InvalidEnumArgumentException("inheritanceType", (int)inheritanceType, typeof(ActiveDirectorySecurityInheritance));
			}
			return ITToPF[(int)inheritanceType];
		}

		internal static ActiveDirectorySecurityInheritance GetEffectiveInheritanceFlags(InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
		{
			ActiveDirectorySecurityInheritance result = ActiveDirectorySecurityInheritance.None;
			if ((inheritanceFlags & InheritanceFlags.ContainerInherit) != 0)
			{
				result = propagationFlags switch
				{
					PropagationFlags.None => ActiveDirectorySecurityInheritance.All, 
					PropagationFlags.InheritOnly => ActiveDirectorySecurityInheritance.Descendents, 
					PropagationFlags.NoPropagateInherit => ActiveDirectorySecurityInheritance.SelfAndChildren, 
					PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly => ActiveDirectorySecurityInheritance.Children, 
					_ => throw new ArgumentException("propagationFlags"), 
				};
			}
			return result;
		}
	}
	public class ActiveDirectoryAccessRule : ObjectAccessRule
	{
		public ActiveDirectoryRights ActiveDirectoryRights => ActiveDirectoryRightsTranslator.RightsFromAccessMask(base.AccessMask);

		public ActiveDirectorySecurityInheritance InheritanceType => ActiveDirectoryInheritanceTranslator.GetEffectiveInheritanceFlags(base.InheritanceFlags, base.PropagationFlags);

		public ActiveDirectoryAccessRule(IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), type, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public ActiveDirectoryAccessRule(IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type, Guid objectType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), type, objectType, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public ActiveDirectoryAccessRule(IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public ActiveDirectoryAccessRule(IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type, Guid objectType, ActiveDirectorySecurityInheritance inheritanceType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), type, objectType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public ActiveDirectoryAccessRule(IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		public ActiveDirectoryAccessRule(IdentityReference identity, ActiveDirectoryRights adRights, AccessControlType type, Guid objectType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), type, objectType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		internal ActiveDirectoryAccessRule(IdentityReference identity, int accessMask, AccessControlType type, Guid objectType, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, Guid inheritedObjectType)
			: base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, objectType, inheritedObjectType, type)
		{
		}
	}
	public sealed class ListChildrenAccessRule : ActiveDirectoryAccessRule
	{
		public ListChildrenAccessRule(IdentityReference identity, AccessControlType type)
			: base(identity, 4, type, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public ListChildrenAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 4, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public ListChildrenAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 4, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}
	}
	public sealed class CreateChildAccessRule : ActiveDirectoryAccessRule
	{
		public CreateChildAccessRule(IdentityReference identity, AccessControlType type)
			: base(identity, 1, type, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public CreateChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType)
			: base(identity, 1, type, childType, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public CreateChildAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 1, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public CreateChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 1, type, childType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public CreateChildAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 1, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		public CreateChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 1, type, childType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}
	}
	public sealed class DeleteChildAccessRule : ActiveDirectoryAccessRule
	{
		public DeleteChildAccessRule(IdentityReference identity, AccessControlType type)
			: base(identity, 2, type, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public DeleteChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType)
			: base(identity, 2, type, childType, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public DeleteChildAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 2, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public DeleteChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 2, type, childType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public DeleteChildAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 2, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		public DeleteChildAccessRule(IdentityReference identity, AccessControlType type, Guid childType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 2, type, childType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}
	}
	public sealed class PropertyAccessRule : ActiveDirectoryAccessRule
	{
		public PropertyAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public PropertyAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertyType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, propertyType, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public PropertyAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public PropertyAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertyType, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, propertyType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public PropertyAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		public PropertyAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertyType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, propertyType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}
	}
	public sealed class PropertySetAccessRule : ActiveDirectoryAccessRule
	{
		public PropertySetAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertySetType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, propertySetType, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public PropertySetAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertySetType, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, propertySetType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public PropertySetAccessRule(IdentityReference identity, AccessControlType type, PropertyAccess access, Guid propertySetType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, PropertyAccessTranslator.AccessMaskFromPropertyAccess(access), type, propertySetType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}
	}
	public sealed class ExtendedRightAccessRule : ActiveDirectoryAccessRule
	{
		public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type)
			: base(identity, 256, type, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type, Guid extendedRightType)
			: base(identity, 256, type, extendedRightType, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 256, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type, Guid extendedRightType, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 256, type, extendedRightType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 256, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		public ExtendedRightAccessRule(IdentityReference identity, AccessControlType type, Guid extendedRightType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 256, type, extendedRightType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}
	}
	public sealed class DeleteTreeAccessRule : ActiveDirectoryAccessRule
	{
		public DeleteTreeAccessRule(IdentityReference identity, AccessControlType type)
			: base(identity, 64, type, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public DeleteTreeAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType)
			: base(identity, 64, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public DeleteTreeAccessRule(IdentityReference identity, AccessControlType type, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: base(identity, 64, type, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}
	}
	public class ActiveDirectoryAuditRule : ObjectAuditRule
	{
		public ActiveDirectoryRights ActiveDirectoryRights => ActiveDirectoryRightsTranslator.RightsFromAccessMask(base.AccessMask);

		public ActiveDirectorySecurityInheritance InheritanceType => ActiveDirectoryInheritanceTranslator.GetEffectiveInheritanceFlags(base.InheritanceFlags, base.PropagationFlags);

		public ActiveDirectoryAuditRule(IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), auditFlags, Guid.Empty, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public ActiveDirectoryAuditRule(IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags, Guid objectType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), auditFlags, objectType, isInherited: false, InheritanceFlags.None, PropagationFlags.None, Guid.Empty)
		{
		}

		public ActiveDirectoryAuditRule(IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags, ActiveDirectorySecurityInheritance inheritanceType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), auditFlags, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public ActiveDirectoryAuditRule(IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags, Guid objectType, ActiveDirectorySecurityInheritance inheritanceType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), auditFlags, objectType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), Guid.Empty)
		{
		}

		public ActiveDirectoryAuditRule(IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), auditFlags, Guid.Empty, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		public ActiveDirectoryAuditRule(IdentityReference identity, ActiveDirectoryRights adRights, AuditFlags auditFlags, Guid objectType, ActiveDirectorySecurityInheritance inheritanceType, Guid inheritedObjectType)
			: this(identity, ActiveDirectoryRightsTranslator.AccessMaskFromRights(adRights), auditFlags, objectType, isInherited: false, ActiveDirectoryInheritanceTranslator.GetInheritanceFlags(inheritanceType), ActiveDirectoryInheritanceTranslator.GetPropagationFlags(inheritanceType), inheritedObjectType)
		{
		}

		internal ActiveDirectoryAuditRule(IdentityReference identity, int accessMask, AuditFlags auditFlags, Guid objectGuid, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, Guid inheritedObjectType)
			: base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, objectGuid, inheritedObjectType, auditFlags)
		{
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class AdsVLV
	{
		public int beforeCount;

		public int afterCount;

		public int offset;

		public int contentCount;

		public IntPtr target;

		public int contextIDlength;

		public IntPtr contextID;
	}
	[Flags]
	public enum AuthenticationTypes
	{
		None = 0,
		Secure = 1,
		Encryption = 2,
		SecureSocketsLayer = 2,
		ReadonlyServer = 4,
		Anonymous = 0x10,
		FastBind = 0x20,
		Signing = 0x40,
		Sealing = 0x80,
		Delegation = 0x100,
		ServerBind = 0x200
	}
	public enum DereferenceAlias
	{
		Never,
		InSearching,
		FindingBaseObject,
		Always
	}
	[AttributeUsage(AttributeTargets.All)]
	public class DSDescriptionAttribute : DescriptionAttribute
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

		public DSDescriptionAttribute(string description)
			: base(description)
		{
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class DirectoryEntries : IEnumerable
	{
		private class ChildEnumerator : IEnumerator
		{
			private DirectoryEntry container;

			private SafeNativeMethods.EnumVariant enumVariant;

			private DirectoryEntry currentEntry;

			public DirectoryEntry Current
			{
				get
				{
					if (enumVariant == null)
					{
						throw new InvalidOperationException(Res.GetString("DSNoCurrentChild"));
					}
					if (currentEntry == null)
					{
						currentEntry = new DirectoryEntry(enumVariant.GetValue(), container.UsePropertyCache, container.GetUsername(), container.GetPassword(), container.AuthenticationType);
					}
					return currentEntry;
				}
			}

			object IEnumerator.Current => Current;

			internal ChildEnumerator(DirectoryEntry container)
			{
				this.container = container;
				if (container.IsContainer)
				{
					enumVariant = new SafeNativeMethods.EnumVariant((SafeNativeMethods.IEnumVariant)container.ContainerObject._NewEnum);
				}
			}

			public bool MoveNext()
			{
				if (enumVariant == null)
				{
					return false;
				}
				currentEntry = null;
				return enumVariant.GetNext();
			}

			public void Reset()
			{
				if (enumVariant != null)
				{
					try
					{
						enumVariant.Reset();
					}
					catch (NotImplementedException)
					{
						enumVariant = new SafeNativeMethods.EnumVariant((SafeNativeMethods.IEnumVariant)container.ContainerObject._NewEnum);
					}
					currentEntry = null;
				}
			}
		}

		private DirectoryEntry container;

		public SchemaNameCollection SchemaFilter
		{
			get
			{
				CheckIsContainer();
				SchemaNameCollection.FilterDelegateWrapper filterDelegateWrapper = new SchemaNameCollection.FilterDelegateWrapper(container.ContainerObject);
				return new SchemaNameCollection(filterDelegateWrapper.Getter, filterDelegateWrapper.Setter);
			}
		}

		internal DirectoryEntries(DirectoryEntry parent)
		{
			container = parent;
		}

		private void CheckIsContainer()
		{
			if (!container.IsContainer)
			{
				throw new InvalidOperationException(Res.GetString("DSNotAContainer", container.Path));
			}
		}

		public DirectoryEntry Add(string name, string schemaClassName)
		{
			CheckIsContainer();
			object adsObject = container.ContainerObject.Create(schemaClassName, name);
			DirectoryEntry directoryEntry = new DirectoryEntry(adsObject, container.UsePropertyCache, container.GetUsername(), container.GetPassword(), container.AuthenticationType);
			directoryEntry.JustCreated = true;
			return directoryEntry;
		}

		public DirectoryEntry Find(string name)
		{
			return Find(name, null);
		}

		public DirectoryEntry Find(string name, string schemaClassName)
		{
			CheckIsContainer();
			object obj = null;
			try
			{
				obj = container.ContainerObject.GetObject(schemaClassName, name);
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			return new DirectoryEntry(obj, container.UsePropertyCache, container.GetUsername(), container.GetPassword(), container.AuthenticationType);
		}

		public void Remove(DirectoryEntry entry)
		{
			CheckIsContainer();
			try
			{
				container.ContainerObject.Delete(entry.SchemaClassName, entry.Name);
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
		}

		public IEnumerator GetEnumerator()
		{
			return new ChildEnumerator(container);
		}
	}
	[DSDescription("DirectoryEntryDesc")]
	[TypeConverter(typeof(DirectoryEntryConverter))]
	[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
	[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class DirectoryEntry : System.ComponentModel.Component
	{
		private string path = "";

		private System.DirectoryServices.Interop.UnsafeNativeMethods.IAds adsObject;

		private bool useCache = true;

		private bool cacheFilled;

		internal bool propertiesAlreadyEnumerated;

		private bool justCreated;

		private bool disposed;

		private AuthenticationTypes authenticationType = AuthenticationTypes.Secure;

		private NetworkCredential credentials;

		private DirectoryEntryConfiguration options;

		private PropertyCollection propertyCollection;

		internal bool allowMultipleChange;

		private bool userNameIsNull;

		private bool passwordIsNull;

		private bool objectSecurityInitialized;

		private bool objectSecurityModified;

		private ActiveDirectorySecurity objectSecurity;

		private static string securityDescriptorProperty = "ntSecurityDescriptor";

		internal System.DirectoryServices.Interop.UnsafeNativeMethods.IAds AdsObject
		{
			get
			{
				Bind();
				return adsObject;
			}
		}

		[DefaultValue(AuthenticationTypes.Secure)]
		[DSDescription("DSAuthenticationType")]
		public AuthenticationTypes AuthenticationType
		{
			get
			{
				return authenticationType;
			}
			set
			{
				if (authenticationType != value)
				{
					authenticationType = value;
					Unbind();
				}
			}
		}

		private bool Bound => adsObject != null;

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[DSDescription("DSChildren")]
		[Browsable(false)]
		public DirectoryEntries Children => new DirectoryEntries(this);

		internal System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsContainer ContainerObject
		{
			get
			{
				Bind();
				return (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsContainer)adsObject;
			}
		}

		[DSDescription("DSGuid")]
		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public Guid Guid
		{
			get
			{
				string nativeGuid = NativeGuid;
				if (nativeGuid.Length == 32)
				{
					byte[] array = new byte[16];
					for (int i = 0; i < 16; i++)
					{
						array[i] = Convert.ToByte(new string(new char[2]
						{
							nativeGuid[i * 2],
							nativeGuid[i * 2 + 1]
						}), 16);
					}
					return new Guid(array);
				}
				return new Guid(nativeGuid);
			}
		}

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false)]
		[DSDescription("DSObjectSecurity")]
		public ActiveDirectorySecurity ObjectSecurity
		{
			get
			{
				if (!objectSecurityInitialized)
				{
					objectSecurity = GetObjectSecurityFromCache();
					objectSecurityInitialized = true;
				}
				return objectSecurity;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				objectSecurity = value;
				objectSecurityInitialized = true;
				objectSecurityModified = true;
				CommitIfNotCaching();
			}
		}

		internal bool IsContainer
		{
			get
			{
				Bind();
				return adsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsContainer;
			}
		}

		internal bool JustCreated
		{
			get
			{
				return justCreated;
			}
			set
			{
				justCreated = value;
			}
		}

		[DSDescription("DSName")]
		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public string Name
		{
			get
			{
				Bind();
				string name = adsObject.Name;
				GC.KeepAlive(this);
				return name;
			}
		}

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[DSDescription("DSNativeGuid")]
		[Browsable(false)]
		public string NativeGuid
		{
			get
			{
				FillCache("GUID");
				string gUID = adsObject.GUID;
				GC.KeepAlive(this);
				return gUID;
			}
		}

		[DSDescription("DSNativeObject")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false)]
		public object NativeObject
		{
			get
			{
				Bind();
				return adsObject;
			}
		}

		[DSDescription("DSParent")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false)]
		public DirectoryEntry Parent
		{
			get
			{
				Bind();
				return new DirectoryEntry(adsObject.Parent, UsePropertyCache, GetUsername(), GetPassword(), AuthenticationType);
			}
		}

		[DefaultValue(null)]
		[Browsable(false)]
		[DSDescription("DSPassword")]
		public string Password
		{
			set
			{
				if (!(value == GetPassword()))
				{
					if (credentials == null)
					{
						credentials = new NetworkCredential();
						userNameIsNull = true;
					}
					if (value == null)
					{
						passwordIsNull = true;
					}
					else
					{
						passwordIsNull = false;
					}
					credentials.Password = value;
					Unbind();
				}
			}
		}

		[SettingsBindable(true)]
		[DefaultValue("")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[DSDescription("DSPath")]
		public string Path
		{
			get
			{
				return path;
			}
			set
			{
				if (value == null)
				{
					value = "";
				}
				if (Utils.Compare(path, value) != 0)
				{
					path = value;
					Unbind();
				}
			}
		}

		[DSDescription("DSProperties")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[Browsable(false)]
		public PropertyCollection Properties
		{
			get
			{
				if (propertyCollection == null)
				{
					propertyCollection = new PropertyCollection(this);
				}
				return propertyCollection;
			}
		}

		[DSDescription("DSSchemaClassName")]
		[Browsable(false)]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public string SchemaClassName
		{
			get
			{
				Bind();
				string @class = adsObject.Class;
				GC.KeepAlive(this);
				return @class;
			}
		}

		[Browsable(false)]
		[DSDescription("DSSchemaEntry")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		public DirectoryEntry SchemaEntry
		{
			get
			{
				Bind();
				return new DirectoryEntry(adsObject.Schema, UsePropertyCache, GetUsername(), GetPassword(), AuthenticationType);
			}
		}

		[DefaultValue(true)]
		[DSDescription("DSUsePropertyCache")]
		public bool UsePropertyCache
		{
			get
			{
				return useCache;
			}
			set
			{
				if (value != useCache)
				{
					if (!value)
					{
						CommitChanges();
					}
					cacheFilled = false;
					useCache = value;
				}
			}
		}

		[DSDescription("DSUsername")]
		[DefaultValue(null)]
		[Browsable(false)]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public string Username
		{
			get
			{
				if (credentials == null || userNameIsNull)
				{
					return null;
				}
				return credentials.UserName;
			}
			set
			{
				if (!(value == GetUsername()))
				{
					if (credentials == null)
					{
						credentials = new NetworkCredential();
						passwordIsNull = true;
					}
					if (value == null)
					{
						userNameIsNull = true;
					}
					else
					{
						userNameIsNull = false;
					}
					credentials.UserName = value;
					Unbind();
				}
			}
		}

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
		[ComVisible(false)]
		[DSDescription("DSOptions")]
		[Browsable(false)]
		public DirectoryEntryConfiguration Options
		{
			get
			{
				if (!(AdsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions))
				{
					return null;
				}
				return options;
			}
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryEntry()
		{
			options = new DirectoryEntryConfiguration(this);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryEntry(string path)
			: this()
		{
			Path = path;
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryEntry(string path, string username, string password)
			: this(path, username, password, AuthenticationTypes.Secure)
		{
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryEntry(string path, string username, string password, AuthenticationTypes authenticationType)
			: this(path)
		{
			credentials = new NetworkCredential(username, password);
			if (username == null)
			{
				userNameIsNull = true;
			}
			if (password == null)
			{
				passwordIsNull = true;
			}
			this.authenticationType = authenticationType;
		}

		internal DirectoryEntry(string path, bool useCache, string username, string password, AuthenticationTypes authenticationType)
		{
			this.path = path;
			this.useCache = useCache;
			credentials = new NetworkCredential(username, password);
			if (username == null)
			{
				userNameIsNull = true;
			}
			if (password == null)
			{
				passwordIsNull = true;
			}
			this.authenticationType = authenticationType;
			options = new DirectoryEntryConfiguration(this);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryEntry(object adsObject)
			: this(adsObject, useCache: true, null, null, AuthenticationTypes.Secure, AdsObjIsExternal: true)
		{
		}

		internal DirectoryEntry(object adsObject, bool useCache, string username, string password, AuthenticationTypes authenticationType)
			: this(adsObject, useCache, username, password, authenticationType, AdsObjIsExternal: false)
		{
		}

		internal DirectoryEntry(object adsObject, bool useCache, string username, string password, AuthenticationTypes authenticationType, bool AdsObjIsExternal)
		{
			this.adsObject = adsObject as System.DirectoryServices.Interop.UnsafeNativeMethods.IAds;
			if (this.adsObject == null)
			{
				throw new ArgumentException(Res.GetString("DSDoesNotImplementIADs"));
			}
			path = this.adsObject.ADsPath;
			this.useCache = useCache;
			this.authenticationType = authenticationType;
			credentials = new NetworkCredential(username, password);
			if (username == null)
			{
				userNameIsNull = true;
			}
			if (password == null)
			{
				passwordIsNull = true;
			}
			if (!useCache)
			{
				CommitChanges();
			}
			options = new DirectoryEntryConfiguration(this);
			if (!AdsObjIsExternal)
			{
				InitADsObjectOptions();
			}
		}

		internal void InitADsObjectOptions()
		{
			if (adsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions2)
			{
				object value = null;
				int num = 0;
				num = ((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions2)adsObject).GetOption(8, out value);
				switch (num)
				{
				case -2147467263:
				case -2147463160:
					break;
				default:
					throw COMExceptionHelper.CreateFormattedComException(num);
				case 0:
				{
					System.DirectoryServices.Interop.Variant value2 = default(System.DirectoryServices.Interop.Variant);
					value2.varType = 11;
					value2.boolvalue = -1;
					((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions2)adsObject).SetOption(8, value2);
					allowMultipleChange = true;
					break;
				}
				}
			}
		}

		private void Bind()
		{
			Bind(throwIfFail: true);
		}

		internal void Bind(bool throwIfFail)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (adsObject != null)
			{
				return;
			}
			string text = Path;
			if (text == null || text.Length == 0)
			{
				DirectoryEntry directoryEntry = new DirectoryEntry("LDAP://RootDSE", useCache: true, null, null, AuthenticationTypes.Secure);
				string text2 = (string)directoryEntry.Properties["defaultNamingContext"][0];
				directoryEntry.Dispose();
				text = "LDAP://" + text2;
			}
			if (Thread.CurrentThread.GetApartmentState() == ApartmentState.Unknown)
			{
				Thread.CurrentThread.SetApartmentState(ApartmentState.MTA);
			}
			Guid iid = new Guid("00000000-0000-0000-c000-000000000046");
			object ppObject = null;
			int num = System.DirectoryServices.Interop.UnsafeNativeMethods.ADsOpenObject(text, GetUsername(), GetPassword(), (int)authenticationType, ref iid, out ppObject);
			if (num != 0)
			{
				if (throwIfFail)
				{
					throw COMExceptionHelper.CreateFormattedComException(num);
				}
			}
			else
			{
				adsObject = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAds)ppObject;
			}
			InitADsObjectOptions();
		}

		internal DirectoryEntry CloneBrowsable()
		{
			return new DirectoryEntry(Path, UsePropertyCache, GetUsername(), GetPassword(), AuthenticationType);
		}

		public void Close()
		{
			Unbind();
		}

		public void CommitChanges()
		{
			if (justCreated)
			{
				try
				{
					SetObjectSecurityInCache();
					adsObject.SetInfo();
				}
				catch (COMException e)
				{
					throw COMExceptionHelper.CreateFormattedComException(e);
				}
				justCreated = false;
				objectSecurityInitialized = false;
				objectSecurityModified = false;
				propertyCollection = null;
			}
			else if ((useCache || (objectSecurity != null && objectSecurity.IsModified())) && Bound)
			{
				try
				{
					SetObjectSecurityInCache();
					adsObject.SetInfo();
					objectSecurityInitialized = false;
					objectSecurityModified = false;
				}
				catch (COMException e2)
				{
					throw COMExceptionHelper.CreateFormattedComException(e2);
				}
				propertyCollection = null;
			}
		}

		internal void CommitIfNotCaching()
		{
			if (!justCreated && !useCache && Bound)
			{
				new DirectoryServicesPermission(PermissionState.Unrestricted).Demand();
				try
				{
					SetObjectSecurityInCache();
					adsObject.SetInfo();
					objectSecurityInitialized = false;
					objectSecurityModified = false;
				}
				catch (COMException e)
				{
					throw COMExceptionHelper.CreateFormattedComException(e);
				}
				propertyCollection = null;
			}
		}

		public DirectoryEntry CopyTo(DirectoryEntry newParent)
		{
			return CopyTo(newParent, null);
		}

		public DirectoryEntry CopyTo(DirectoryEntry newParent, string newName)
		{
			if (!newParent.IsContainer)
			{
				throw new InvalidOperationException(Res.GetString("DSNotAContainer", newParent.Path));
			}
			object obj = null;
			try
			{
				obj = newParent.ContainerObject.CopyHere(Path, newName);
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			return new DirectoryEntry(obj, newParent.UsePropertyCache, GetUsername(), GetPassword(), AuthenticationType);
		}

		public void DeleteTree()
		{
			if (!(AdsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsDeleteOps))
			{
				throw new InvalidOperationException(Res.GetString("DSCannotDelete"));
			}
			System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsDeleteOps adsDeleteOps = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsDeleteOps)AdsObject;
			try
			{
				adsDeleteOps.DeleteObject(0);
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			GC.KeepAlive(this);
		}

		protected override void Dispose(bool disposing)
		{
			if (!disposed)
			{
				Unbind();
				disposed = true;
			}
			base.Dispose(disposing);
		}

		public static bool Exists(string path)
		{
			DirectoryEntry directoryEntry = new DirectoryEntry(path);
			try
			{
				directoryEntry.Bind(throwIfFail: true);
				return directoryEntry.Bound;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147016656 || ex.ErrorCode == -2147024893 || ex.ErrorCode == -2147022676)
				{
					return false;
				}
				throw;
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		internal void FillCache(string propertyName)
		{
			if (UsePropertyCache)
			{
				if (!cacheFilled)
				{
					RefreshCache();
					cacheFilled = true;
				}
				return;
			}
			Bind();
			try
			{
				if (propertyName.Length > 0)
				{
					adsObject.GetInfoEx(new object[1] { propertyName }, 0);
				}
				else
				{
					adsObject.GetInfo();
				}
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
		}

		public object Invoke(string methodName, params object[] args)
		{
			object nativeObject = NativeObject;
			Type type = nativeObject.GetType();
			object obj = null;
			try
			{
				obj = type.InvokeMember(methodName, BindingFlags.InvokeMethod, null, nativeObject, args, CultureInfo.InvariantCulture);
				GC.KeepAlive(this);
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			catch (TargetInvocationException ex)
			{
				if (ex.InnerException != null && ex.InnerException is COMException)
				{
					COMException e2 = (COMException)ex.InnerException;
					throw new TargetInvocationException(ex.Message, COMExceptionHelper.CreateFormattedComException(e2));
				}
				throw ex;
			}
			if (obj is System.DirectoryServices.Interop.UnsafeNativeMethods.IAds)
			{
				return new DirectoryEntry(obj, UsePropertyCache, GetUsername(), GetPassword(), AuthenticationType);
			}
			return obj;
		}

		[ComVisible(false)]
		public object InvokeGet(string propertyName)
		{
			object nativeObject = NativeObject;
			Type type = nativeObject.GetType();
			object obj = null;
			try
			{
				obj = type.InvokeMember(propertyName, BindingFlags.GetProperty, null, nativeObject, null, CultureInfo.InvariantCulture);
				GC.KeepAlive(this);
				return obj;
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			catch (TargetInvocationException ex)
			{
				if (ex.InnerException != null && ex.InnerException is COMException)
				{
					COMException e2 = (COMException)ex.InnerException;
					throw new TargetInvocationException(ex.Message, COMExceptionHelper.CreateFormattedComException(e2));
				}
				throw ex;
			}
		}

		[ComVisible(false)]
		public void InvokeSet(string propertyName, params object[] args)
		{
			object nativeObject = NativeObject;
			Type type = nativeObject.GetType();
			try
			{
				type.InvokeMember(propertyName, BindingFlags.SetProperty, null, nativeObject, args, CultureInfo.InvariantCulture);
				GC.KeepAlive(this);
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			catch (TargetInvocationException ex)
			{
				if (ex.InnerException != null && ex.InnerException is COMException)
				{
					COMException e2 = (COMException)ex.InnerException;
					throw new TargetInvocationException(ex.Message, COMExceptionHelper.CreateFormattedComException(e2));
				}
				throw ex;
			}
		}

		public void MoveTo(DirectoryEntry newParent)
		{
			MoveTo(newParent, null);
		}

		public void MoveTo(DirectoryEntry newParent, string newName)
		{
			object obj = null;
			if (!(newParent.AdsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsContainer))
			{
				throw new InvalidOperationException(Res.GetString("DSNotAContainer", newParent.Path));
			}
			try
			{
				if (AdsObject.ADsPath.StartsWith("WinNT:", StringComparison.Ordinal))
				{
					string text = AdsObject.ADsPath;
					string aDsPath = newParent.AdsObject.ADsPath;
					if (Utils.Compare(text, 0, aDsPath.Length, aDsPath, 0, aDsPath.Length) == 0)
					{
						uint compareFlags = Utils.NORM_IGNORENONSPACE | Utils.NORM_IGNOREKANATYPE | Utils.NORM_IGNOREWIDTH | Utils.SORT_STRINGSORT;
						if (Utils.Compare(text, 0, aDsPath.Length, aDsPath, 0, aDsPath.Length, compareFlags) != 0)
						{
							text = aDsPath + text.Substring(aDsPath.Length);
						}
					}
					obj = newParent.ContainerObject.MoveHere(text, newName);
				}
				else
				{
					obj = newParent.ContainerObject.MoveHere(Path, newName);
				}
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			if (Bound)
			{
				Marshal.ReleaseComObject(adsObject);
			}
			adsObject = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAds)obj;
			path = adsObject.ADsPath;
			InitADsObjectOptions();
			if (!useCache)
			{
				CommitChanges();
			}
			else
			{
				RefreshCache();
			}
		}

		public void RefreshCache()
		{
			Bind();
			try
			{
				adsObject.GetInfo();
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			cacheFilled = true;
			propertyCollection = null;
			objectSecurityInitialized = false;
			objectSecurityModified = false;
		}

		public void RefreshCache(string[] propertyNames)
		{
			Bind();
			object[] array = new object[propertyNames.Length];
			for (int i = 0; i < propertyNames.Length; i++)
			{
				array[i] = propertyNames[i];
			}
			try
			{
				AdsObject.GetInfoEx(array, 0);
			}
			catch (COMException e)
			{
				throw COMExceptionHelper.CreateFormattedComException(e);
			}
			cacheFilled = true;
			if (propertyCollection == null || propertyNames == null)
			{
				return;
			}
			for (int j = 0; j < propertyNames.Length; j++)
			{
				if (propertyNames[j] == null)
				{
					continue;
				}
				string text = propertyNames[j].ToLower(CultureInfo.InvariantCulture);
				propertyCollection.valueTable.Remove(text);
				string[] array2 = text.Split(';');
				if (array2.Length != 1)
				{
					string text2 = "";
					for (int k = 0; k < array2.Length; k++)
					{
						if (!array2[k].StartsWith("range=", StringComparison.Ordinal))
						{
							text2 += array2[k];
							text2 += ";";
						}
					}
					text2 = text2.Remove(text2.Length - 1, 1);
					propertyCollection.valueTable.Remove(text2);
				}
				if (string.Compare(propertyNames[j], securityDescriptorProperty, StringComparison.OrdinalIgnoreCase) == 0)
				{
					objectSecurityInitialized = false;
					objectSecurityModified = false;
				}
			}
		}

		public void Rename(string newName)
		{
			MoveTo(Parent, newName);
		}

		private void Unbind()
		{
			if (adsObject != null)
			{
				Marshal.ReleaseComObject(adsObject);
			}
			adsObject = null;
			propertyCollection = null;
			objectSecurityInitialized = false;
			objectSecurityModified = false;
		}

		internal string GetUsername()
		{
			if (credentials == null || userNameIsNull)
			{
				return null;
			}
			return credentials.UserName;
		}

		internal string GetPassword()
		{
			if (credentials == null || passwordIsNull)
			{
				return null;
			}
			return credentials.Password;
		}

		private ActiveDirectorySecurity GetObjectSecurityFromCache()
		{
			try
			{
				if (!JustCreated)
				{
					SecurityMasks securityMasks = Options.SecurityMasks;
					RefreshCache(new string[1] { securityDescriptorProperty });
					if (!(NativeObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList))
					{
						throw new NotSupportedException(Res.GetString("DSPropertyListUnsupported"));
					}
					System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList adsPropertyList = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)NativeObject;
					System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyEntry adsPropertyEntry = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyEntry)adsPropertyList.GetPropertyItem(securityDescriptorProperty, 8);
					GC.KeepAlive(this);
					object[] array = (object[])adsPropertyEntry.Values;
					if (array.Length < 1)
					{
						throw new InvalidOperationException(Res.GetString("DSSDNoValues"));
					}
					if (array.Length > 1)
					{
						throw new NotSupportedException(Res.GetString("DSMultipleSDNotSupported"));
					}
					System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyValue adsPropertyValue = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyValue)array[0];
					return new ActiveDirectorySecurity((byte[])adsPropertyValue.OctetString, securityMasks);
				}
				return null;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147463155)
				{
					return null;
				}
				throw;
			}
		}

		private void SetObjectSecurityInCache()
		{
			if (objectSecurity != null && (objectSecurityModified || objectSecurity.IsModified()))
			{
				System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyValue adsPropertyValue = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyValue)new System.DirectoryServices.Interop.UnsafeNativeMethods.PropertyValue();
				adsPropertyValue.ADsType = 8;
				adsPropertyValue.OctetString = objectSecurity.GetSecurityDescriptorBinaryForm();
				System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyEntry adsPropertyEntry = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyEntry)new System.DirectoryServices.Interop.UnsafeNativeMethods.PropertyEntry();
				adsPropertyEntry.Name = securityDescriptorProperty;
				adsPropertyEntry.ADsType = 8;
				adsPropertyEntry.ControlCode = 2;
				adsPropertyEntry.Values = new object[1] { adsPropertyValue };
				((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)NativeObject).PutPropertyItem(adsPropertyEntry);
			}
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class DirectoryEntryConfiguration
	{
		private const int ISC_RET_MUTUAL_AUTH = 2;

		private DirectoryEntry entry;

		public ReferralChasingOption Referral
		{
			get
			{
				return (ReferralChasingOption)((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).GetOption(1);
			}
			set
			{
				if (value != 0 && value != ReferralChasingOption.Subordinate && value != ReferralChasingOption.External && value != ReferralChasingOption.All)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ReferralChasingOption));
				}
				((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).SetOption(1, value);
			}
		}

		public SecurityMasks SecurityMasks
		{
			get
			{
				return (SecurityMasks)((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).GetOption(3);
			}
			set
			{
				if (value > (SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl))
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(SecurityMasks));
				}
				((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).SetOption(3, value);
			}
		}

		public int PageSize
		{
			get
			{
				return (int)((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).GetOption(2);
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("DSBadPageSize"));
				}
				((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).SetOption(2, value);
			}
		}

		public int PasswordPort
		{
			get
			{
				return (int)((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).GetOption(6);
			}
			set
			{
				((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).SetOption(6, value);
			}
		}

		public PasswordEncodingMethod PasswordEncoding
		{
			get
			{
				return (PasswordEncodingMethod)((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).GetOption(7);
			}
			set
			{
				if (value < PasswordEncodingMethod.PasswordEncodingSsl || value > PasswordEncodingMethod.PasswordEncodingClear)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(PasswordEncodingMethod));
				}
				((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).SetOption(7, value);
			}
		}

		internal DirectoryEntryConfiguration(DirectoryEntry entry)
		{
			this.entry = entry;
		}

		public string GetCurrentServerName()
		{
			return (string)((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).GetOption(0);
		}

		public bool IsMutuallyAuthenticated()
		{
			try
			{
				int num = (int)((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).GetOption(4);
				if (((uint)num & 2u) != 0)
				{
					return true;
				}
				return false;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147463160)
				{
					return false;
				}
				throw;
			}
		}

		public void SetUserNameQueryQuota(string accountName)
		{
			((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsObjectOptions)entry.AdsObject).SetOption(5, accountName);
		}
	}
	[DSDescription("DirectorySearcherDesc")]
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class DirectorySearcher : System.ComponentModel.Component
	{
		private const string defaultFilter = "(objectClass=*)";

		private DirectoryEntry searchRoot;

		private string filter = "(objectClass=*)";

		private StringCollection propertiesToLoad;

		private bool disposed;

		private static readonly TimeSpan minusOneSecond = new TimeSpan(0, 0, -1);

		private SearchScope scope = SearchScope.Subtree;

		private bool scopeSpecified;

		private int sizeLimit;

		private TimeSpan serverTimeLimit = minusOneSecond;

		private bool propertyNamesOnly;

		private TimeSpan clientTimeout = minusOneSecond;

		private int pageSize;

		private TimeSpan serverPageTimeLimit = minusOneSecond;

		private ReferralChasingOption referralChasing = ReferralChasingOption.External;

		private SortOption sort = new SortOption();

		private bool cacheResults = true;

		private bool cacheResultsSpecified;

		private bool rootEntryAllocated;

		private string assertDefaultNamingContext;

		private bool asynchronous;

		private bool tombstone;

		private string attributeScopeQuery = "";

		private bool attributeScopeQuerySpecified;

		private DereferenceAlias derefAlias;

		private SecurityMasks securityMask;

		private ExtendedDN extendedDN = ExtendedDN.None;

		private DirectorySynchronization sync;

		internal bool directorySynchronizationSpecified;

		private DirectoryVirtualListView vlv;

		internal bool directoryVirtualListViewSpecified;

		internal SearchResultCollection searchResult;

		[DSDescription("DSCacheResults")]
		[DefaultValue(true)]
		public bool CacheResults
		{
			get
			{
				return cacheResults;
			}
			set
			{
				if (directoryVirtualListViewSpecified && value)
				{
					throw new ArgumentException(Res.GetString("DSBadCacheResultsVLV"));
				}
				cacheResults = value;
				cacheResultsSpecified = true;
			}
		}

		[DSDescription("DSClientTimeout")]
		public TimeSpan ClientTimeout
		{
			get
			{
				return clientTimeout;
			}
			set
			{
				if (value.TotalSeconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				clientTimeout = value;
			}
		}

		[DSDescription("DSPropertyNamesOnly")]
		[DefaultValue(false)]
		public bool PropertyNamesOnly
		{
			get
			{
				return propertyNamesOnly;
			}
			set
			{
				propertyNamesOnly = value;
			}
		}

		[DefaultValue("(objectClass=*)")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		[SettingsBindable(true)]
		[DSDescription("DSFilter")]
		public string Filter
		{
			get
			{
				return filter;
			}
			set
			{
				if (value == null || value.Length == 0)
				{
					value = "(objectClass=*)";
				}
				filter = value;
			}
		}

		[DefaultValue(0)]
		[DSDescription("DSPageSize")]
		public int PageSize
		{
			get
			{
				return pageSize;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("DSBadPageSize"));
				}
				if (directorySynchronizationSpecified && value != 0)
				{
					throw new ArgumentException(Res.GetString("DSBadPageSizeDirsync"));
				}
				pageSize = value;
			}
		}

		[DSDescription("DSPropertiesToLoad")]
		[DesignerSerializationVisibility(DesignerSerializationVisibility.Content)]
		[Editor("System.Windows.Forms.Design.StringCollectionEditor, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Drawing.Design.UITypeEditor, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public StringCollection PropertiesToLoad
		{
			get
			{
				if (propertiesToLoad == null)
				{
					propertiesToLoad = new StringCollection();
				}
				return propertiesToLoad;
			}
		}

		[DSDescription("DSReferralChasing")]
		[DefaultValue(ReferralChasingOption.External)]
		public ReferralChasingOption ReferralChasing
		{
			get
			{
				return referralChasing;
			}
			set
			{
				if (value != 0 && value != ReferralChasingOption.Subordinate && value != ReferralChasingOption.External && value != ReferralChasingOption.All)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ReferralChasingOption));
				}
				referralChasing = value;
			}
		}

		[SettingsBindable(true)]
		[DefaultValue(SearchScope.Subtree)]
		[DSDescription("DSSearchScope")]
		public SearchScope SearchScope
		{
			get
			{
				return scope;
			}
			set
			{
				if (value < SearchScope.Base || value > SearchScope.Subtree)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(SearchScope));
				}
				if (attributeScopeQuerySpecified && value != 0)
				{
					throw new ArgumentException(Res.GetString("DSBadASQSearchScope"));
				}
				scope = value;
				scopeSpecified = true;
			}
		}

		[DSDescription("DSServerPageTimeLimit")]
		public TimeSpan ServerPageTimeLimit
		{
			get
			{
				return serverPageTimeLimit;
			}
			set
			{
				if (value.TotalSeconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				serverPageTimeLimit = value;
			}
		}

		[DSDescription("DSServerTimeLimit")]
		public TimeSpan ServerTimeLimit
		{
			get
			{
				return serverTimeLimit;
			}
			set
			{
				if (value.TotalSeconds > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("TimespanExceedMax"), "value");
				}
				serverTimeLimit = value;
			}
		}

		[DSDescription("DSSizeLimit")]
		[DefaultValue(0)]
		public int SizeLimit
		{
			get
			{
				return sizeLimit;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("DSBadSizeLimit"));
				}
				sizeLimit = value;
			}
		}

		[DSDescription("DSSearchRoot")]
		[DefaultValue(null)]
		public DirectoryEntry SearchRoot
		{
			get
			{
				if (searchRoot == null && !base.DesignMode)
				{
					DirectoryEntry directoryEntry = new DirectoryEntry("LDAP://RootDSE", useCache: true, null, null, AuthenticationTypes.Secure);
					string text = (string)directoryEntry.Properties["defaultNamingContext"][0];
					directoryEntry.Dispose();
					searchRoot = new DirectoryEntry("LDAP://" + text, useCache: true, null, null, AuthenticationTypes.Secure);
					rootEntryAllocated = true;
					assertDefaultNamingContext = "LDAP://" + text;
				}
				return searchRoot;
			}
			set
			{
				if (rootEntryAllocated)
				{
					searchRoot.Dispose();
				}
				rootEntryAllocated = false;
				assertDefaultNamingContext = null;
				searchRoot = value;
			}
		}

		[DesignerSerializationVisibility(DesignerSerializationVisibility.Content)]
		[TypeConverter(typeof(ExpandableObjectConverter))]
		[DSDescription("DSSort")]
		public SortOption Sort
		{
			get
			{
				return sort;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				sort = value;
			}
		}

		[DSDescription("DSAsynchronous")]
		[ComVisible(false)]
		[DefaultValue(false)]
		public bool Asynchronous
		{
			get
			{
				return asynchronous;
			}
			set
			{
				asynchronous = value;
			}
		}

		[ComVisible(false)]
		[DefaultValue(false)]
		[DSDescription("DSTombstone")]
		public bool Tombstone
		{
			get
			{
				return tombstone;
			}
			set
			{
				tombstone = value;
			}
		}

		[DefaultValue("")]
		[ComVisible(false)]
		[DSDescription("DSAttributeQuery")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public string AttributeScopeQuery
		{
			get
			{
				return attributeScopeQuery;
			}
			set
			{
				if (value == null)
				{
					value = "";
				}
				if (value.Length != 0)
				{
					if (scopeSpecified && SearchScope != 0)
					{
						throw new ArgumentException(Res.GetString("DSBadASQSearchScope"));
					}
					scope = SearchScope.Base;
					attributeScopeQuerySpecified = true;
				}
				else
				{
					attributeScopeQuerySpecified = false;
				}
				attributeScopeQuery = value;
			}
		}

		[ComVisible(false)]
		[DSDescription("DSDerefAlias")]
		[DefaultValue(DereferenceAlias.Never)]
		public DereferenceAlias DerefAlias
		{
			get
			{
				return derefAlias;
			}
			set
			{
				if (value < DereferenceAlias.Never || value > DereferenceAlias.Always)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(DereferenceAlias));
				}
				derefAlias = value;
			}
		}

		[DSDescription("DSSecurityMasks")]
		[ComVisible(false)]
		[DefaultValue(SecurityMasks.None)]
		public SecurityMasks SecurityMasks
		{
			get
			{
				return securityMask;
			}
			set
			{
				if (value > (SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl))
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(SecurityMasks));
				}
				securityMask = value;
			}
		}

		[DefaultValue(ExtendedDN.None)]
		[DSDescription("DSExtendedDn")]
		[ComVisible(false)]
		public ExtendedDN ExtendedDN
		{
			get
			{
				return extendedDN;
			}
			set
			{
				if (value < ExtendedDN.None || value > ExtendedDN.Standard)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ExtendedDN));
				}
				extendedDN = value;
			}
		}

		[DefaultValue(null)]
		[ComVisible(false)]
		[DSDescription("DSDirectorySynchronization")]
		[Browsable(false)]
		public DirectorySynchronization DirectorySynchronization
		{
			get
			{
				if (directorySynchronizationSpecified && searchResult != null)
				{
					sync.ResetDirectorySynchronizationCookie(searchResult.DirsyncCookie);
				}
				return sync;
			}
			set
			{
				if (value != null)
				{
					if (PageSize != 0)
					{
						throw new ArgumentException(Res.GetString("DSBadPageSizeDirsync"));
					}
					directorySynchronizationSpecified = true;
				}
				else
				{
					directorySynchronizationSpecified = false;
				}
				sync = value;
			}
		}

		[DSDescription("DSVirtualListView")]
		[Browsable(false)]
		[ComVisible(false)]
		[DefaultValue(null)]
		public DirectoryVirtualListView VirtualListView
		{
			get
			{
				if (directoryVirtualListViewSpecified && searchResult != null)
				{
					DirectoryVirtualListView vLVResponse = searchResult.VLVResponse;
					vlv.Offset = vLVResponse.Offset;
					vlv.ApproximateTotal = vLVResponse.ApproximateTotal;
					vlv.DirectoryVirtualListViewContext = vLVResponse.DirectoryVirtualListViewContext;
					if (vlv.ApproximateTotal != 0)
					{
						vlv.TargetPercentage = (int)((double)vlv.Offset / (double)vlv.ApproximateTotal * 100.0);
					}
					else
					{
						vlv.TargetPercentage = 0;
					}
				}
				return vlv;
			}
			set
			{
				if (value != null)
				{
					if (cacheResultsSpecified && CacheResults)
					{
						throw new ArgumentException(Res.GetString("DSBadCacheResultsVLV"));
					}
					directoryVirtualListViewSpecified = true;
					cacheResults = false;
				}
				else
				{
					directoryVirtualListViewSpecified = false;
				}
				vlv = value;
			}
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher()
			: this(null, "(objectClass=*)", null, SearchScope.Subtree)
		{
			scopeSpecified = false;
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher(DirectoryEntry searchRoot)
			: this(searchRoot, "(objectClass=*)", null, SearchScope.Subtree)
		{
			scopeSpecified = false;
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher(DirectoryEntry searchRoot, string filter)
			: this(searchRoot, filter, null, SearchScope.Subtree)
		{
			scopeSpecified = false;
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher(DirectoryEntry searchRoot, string filter, string[] propertiesToLoad)
			: this(searchRoot, filter, propertiesToLoad, SearchScope.Subtree)
		{
			scopeSpecified = false;
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher(string filter)
			: this(null, filter, null, SearchScope.Subtree)
		{
			scopeSpecified = false;
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher(string filter, string[] propertiesToLoad)
			: this(null, filter, propertiesToLoad, SearchScope.Subtree)
		{
			scopeSpecified = false;
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher(string filter, string[] propertiesToLoad, SearchScope scope)
			: this(null, filter, propertiesToLoad, scope)
		{
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectorySearcher(DirectoryEntry searchRoot, string filter, string[] propertiesToLoad, SearchScope scope)
		{
			this.searchRoot = searchRoot;
			this.filter = filter;
			if (propertiesToLoad != null)
			{
				PropertiesToLoad.AddRange(propertiesToLoad);
			}
			SearchScope = scope;
		}

		protected override void Dispose(bool disposing)
		{
			if (!disposed && disposing)
			{
				if (rootEntryAllocated)
				{
					searchRoot.Dispose();
				}
				rootEntryAllocated = false;
				disposed = true;
			}
			base.Dispose(disposing);
		}

		public SearchResult FindOne()
		{
			SearchResult result = null;
			SearchResultCollection searchResultCollection = FindAll(findMoreThanOne: false);
			try
			{
				IEnumerator enumerator = searchResultCollection.GetEnumerator();
				try
				{
					if (enumerator.MoveNext())
					{
						SearchResult result2 = (SearchResult)enumerator.Current;
						if (directorySynchronizationSpecified)
						{
							_ = DirectorySynchronization;
						}
						if (directoryVirtualListViewSpecified)
						{
							_ = VirtualListView;
						}
						return result2;
					}
					return result;
				}
				finally
				{
					IDisposable disposable = enumerator as IDisposable;
					if (disposable != null)
					{
						disposable.Dispose();
					}
				}
			}
			finally
			{
				searchResult = null;
				searchResultCollection.Dispose();
			}
		}

		public SearchResultCollection FindAll()
		{
			return FindAll(findMoreThanOne: true);
		}

		private SearchResultCollection FindAll(bool findMoreThanOne)
		{
			searchResult = null;
			DirectoryEntry directoryEntry = null;
			directoryEntry = ((assertDefaultNamingContext != null) ? SearchRoot.CloneBrowsable() : SearchRoot.CloneBrowsable());
			System.DirectoryServices.Interop.UnsafeNativeMethods.IAds adsObject = directoryEntry.AdsObject;
			if (!(adsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch))
			{
				throw new NotSupportedException(Res.GetString("DSSearchUnsupported", SearchRoot.Path));
			}
			if (directoryVirtualListViewSpecified)
			{
				SearchRoot.Bind(throwIfFail: true);
			}
			System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch directorySearch = (System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch)adsObject;
			SetSearchPreferences(directorySearch, findMoreThanOne);
			string[] array = null;
			if (PropertiesToLoad.Count > 0)
			{
				if (!PropertiesToLoad.Contains("ADsPath"))
				{
					PropertiesToLoad.Add("ADsPath");
				}
				array = new string[PropertiesToLoad.Count];
				PropertiesToLoad.CopyTo(array, 0);
			}
			IntPtr hSearchResult;
			if (array != null)
			{
				directorySearch.ExecuteSearch(Filter, array, array.Length, out hSearchResult);
			}
			else
			{
				directorySearch.ExecuteSearch(Filter, null, -1, out hSearchResult);
				array = new string[0];
			}
			return searchResult = new SearchResultCollection(directoryEntry, hSearchResult, array, this);
		}

		private unsafe void SetSearchPreferences(System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch adsSearch, bool findMoreThanOne)
		{
			ArrayList arrayList = new ArrayList();
			AdsSearchPreferenceInfo adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
			adsSearchPreferenceInfo.dwSearchPref = 5;
			adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)SearchScope).GetStruct();
			arrayList.Add(adsSearchPreferenceInfo);
			if (sizeLimit != 0 || !findMoreThanOne)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 2;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper((!findMoreThanOne) ? 1 : SizeLimit).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (ServerTimeLimit >= new TimeSpan(0L))
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 3;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)ServerTimeLimit.TotalSeconds).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
			adsSearchPreferenceInfo.dwSearchPref = 4;
			adsSearchPreferenceInfo.vValue = new AdsValueHelper(PropertyNamesOnly).GetStruct();
			arrayList.Add(adsSearchPreferenceInfo);
			if (ClientTimeout >= new TimeSpan(0L))
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 6;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)ClientTimeout.TotalSeconds).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (PageSize != 0)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 7;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper(PageSize).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (ServerPageTimeLimit >= new TimeSpan(0L))
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 8;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)ServerPageTimeLimit.TotalSeconds).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
			adsSearchPreferenceInfo.dwSearchPref = 9;
			adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)ReferralChasing).GetStruct();
			arrayList.Add(adsSearchPreferenceInfo);
			if (Asynchronous)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 0;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper(Asynchronous).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (Tombstone)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 13;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper(Tombstone).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (attributeScopeQuerySpecified)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 15;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper(AttributeScopeQuery, AdsType.ADSTYPE_CASE_IGNORE_STRING).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (DerefAlias != 0)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 1;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)DerefAlias).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (SecurityMasks != 0)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 16;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)SecurityMasks).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (ExtendedDN != ExtendedDN.None)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 18;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)ExtendedDN).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
			}
			if (directorySynchronizationSpecified)
			{
				adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
				adsSearchPreferenceInfo.dwSearchPref = 12;
				adsSearchPreferenceInfo.vValue = new AdsValueHelper(DirectorySynchronization.GetDirectorySynchronizationCookie(), AdsType.ADSTYPE_PROV_SPECIFIC).GetStruct();
				arrayList.Add(adsSearchPreferenceInfo);
				if (DirectorySynchronization.Option != DirectorySynchronizationOptions.None)
				{
					adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
					adsSearchPreferenceInfo.dwSearchPref = 17;
					adsSearchPreferenceInfo.vValue = new AdsValueHelper((int)DirectorySynchronization.Option).GetStruct();
					arrayList.Add(adsSearchPreferenceInfo);
				}
			}
			IntPtr intPtr = (IntPtr)0;
			IntPtr intPtr2 = (IntPtr)0;
			IntPtr intPtr3 = (IntPtr)0;
			try
			{
				if (Sort.PropertyName != null && Sort.PropertyName.Length > 0)
				{
					adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
					adsSearchPreferenceInfo.dwSearchPref = 10;
					AdsSortKey adsSortKey = default(AdsSortKey);
					adsSortKey.pszAttrType = Marshal.StringToCoTaskMemUni(Sort.PropertyName);
					intPtr = adsSortKey.pszAttrType;
					adsSortKey.pszReserved = (IntPtr)0;
					adsSortKey.fReverseOrder = ((Sort.Direction == SortDirection.Descending) ? (-1) : 0);
					byte[] array = new byte[Marshal.SizeOf(adsSortKey)];
					Marshal.Copy((IntPtr)(&adsSortKey), array, 0, array.Length);
					adsSearchPreferenceInfo.vValue = new AdsValueHelper(array, AdsType.ADSTYPE_PROV_SPECIFIC).GetStruct();
					arrayList.Add(adsSearchPreferenceInfo);
				}
				if (directoryVirtualListViewSpecified)
				{
					adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
					adsSearchPreferenceInfo.dwSearchPref = 14;
					AdsVLV adsVLV = new AdsVLV();
					adsVLV.beforeCount = vlv.BeforeCount;
					adsVLV.afterCount = vlv.AfterCount;
					adsVLV.offset = vlv.Offset;
					if (vlv.Target.Length != 0)
					{
						adsVLV.target = Marshal.StringToCoTaskMemUni(vlv.Target);
					}
					else
					{
						adsVLV.target = IntPtr.Zero;
					}
					intPtr2 = adsVLV.target;
					if (vlv.DirectoryVirtualListViewContext == null)
					{
						adsVLV.contextIDlength = 0;
						adsVLV.contextID = (IntPtr)0;
					}
					else
					{
						adsVLV.contextIDlength = vlv.DirectoryVirtualListViewContext.context.Length;
						adsVLV.contextID = Marshal.AllocCoTaskMem(adsVLV.contextIDlength);
						intPtr3 = adsVLV.contextID;
						Marshal.Copy(vlv.DirectoryVirtualListViewContext.context, 0, adsVLV.contextID, adsVLV.contextIDlength);
					}
					IntPtr intPtr4 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(AdsVLV)));
					byte[] array2 = new byte[Marshal.SizeOf(adsVLV)];
					try
					{
						Marshal.StructureToPtr(adsVLV, intPtr4, fDeleteOld: false);
						Marshal.Copy(intPtr4, array2, 0, array2.Length);
					}
					finally
					{
						Marshal.FreeHGlobal(intPtr4);
					}
					adsSearchPreferenceInfo.vValue = new AdsValueHelper(array2, AdsType.ADSTYPE_PROV_SPECIFIC).GetStruct();
					arrayList.Add(adsSearchPreferenceInfo);
				}
				if (cacheResultsSpecified)
				{
					adsSearchPreferenceInfo = default(AdsSearchPreferenceInfo);
					adsSearchPreferenceInfo.dwSearchPref = 11;
					adsSearchPreferenceInfo.vValue = new AdsValueHelper(CacheResults).GetStruct();
					arrayList.Add(adsSearchPreferenceInfo);
				}
				AdsSearchPreferenceInfo[] array3 = new AdsSearchPreferenceInfo[arrayList.Count];
				for (int i = 0; i < arrayList.Count; i++)
				{
					ref AdsSearchPreferenceInfo reference = ref array3[i];
					reference = (AdsSearchPreferenceInfo)arrayList[i];
				}
				DoSetSearchPrefs(adsSearch, array3);
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					Marshal.FreeCoTaskMem(intPtr);
				}
				if (intPtr2 != (IntPtr)0)
				{
					Marshal.FreeCoTaskMem(intPtr2);
				}
				if (intPtr3 != (IntPtr)0)
				{
					Marshal.FreeCoTaskMem(intPtr3);
				}
			}
		}

		private static void DoSetSearchPrefs(System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch adsSearch, AdsSearchPreferenceInfo[] prefs)
		{
			int num = Marshal.SizeOf(typeof(AdsSearchPreferenceInfo));
			IntPtr intPtr = Marshal.AllocHGlobal((IntPtr)(num * prefs.Length));
			try
			{
				IntPtr intPtr2 = intPtr;
				for (int i = 0; i < prefs.Length; i++)
				{
					Marshal.StructureToPtr(prefs[i], intPtr2, fDeleteOld: false);
					intPtr2 = Utils.AddToIntPtr(intPtr2, num);
				}
				adsSearch.SetSearchPreference(intPtr, prefs.Length);
				intPtr2 = intPtr;
				for (int j = 0; j < prefs.Length; j++)
				{
					if (Marshal.ReadInt32(intPtr2, 32) != 0)
					{
						int dwSearchPref = prefs[j].dwSearchPref;
						string text = "";
						switch (dwSearchPref)
						{
						case 5:
							text = "SearchScope";
							break;
						case 2:
							text = "SizeLimit";
							break;
						case 3:
							text = "ServerTimeLimit";
							break;
						case 4:
							text = "PropertyNamesOnly";
							break;
						case 6:
							text = "ClientTimeout";
							break;
						case 7:
							text = "PageSize";
							break;
						case 8:
							text = "ServerPageTimeLimit";
							break;
						case 9:
							text = "ReferralChasing";
							break;
						case 10:
							text = "Sort";
							break;
						case 11:
							text = "CacheResults";
							break;
						case 0:
							text = "Asynchronous";
							break;
						case 13:
							text = "Tombstone";
							break;
						case 15:
							text = "AttributeScopeQuery";
							break;
						case 1:
							text = "DerefAlias";
							break;
						case 16:
							text = "SecurityMasks";
							break;
						case 18:
							text = "ExtendedDn";
							break;
						case 12:
							text = "DirectorySynchronization";
							break;
						case 17:
							text = "DirectorySynchronizationFlag";
							break;
						case 14:
							text = "VirtualListView";
							break;
						}
						throw new InvalidOperationException(Res.GetString("DSSearchPreferencesNotAccepted", text));
					}
					intPtr2 = Utils.AddToIntPtr(intPtr2, num);
				}
			}
			finally
			{
				Marshal.FreeHGlobal(intPtr);
			}
		}
	}
	[Serializable]
	public sealed class DirectoryServicesPermission : ResourcePermissionBase
	{
		private DirectoryServicesPermissionEntryCollection innerCollection;

		public DirectoryServicesPermissionEntryCollection PermissionEntries
		{
			get
			{
				if (innerCollection == null)
				{
					innerCollection = new DirectoryServicesPermissionEntryCollection(this, GetPermissionEntries());
				}
				return innerCollection;
			}
		}

		public DirectoryServicesPermission()
		{
			SetNames();
		}

		public DirectoryServicesPermission(PermissionState state)
			: base(state)
		{
			SetNames();
		}

		public DirectoryServicesPermission(DirectoryServicesPermissionAccess permissionAccess, string path)
		{
			SetNames();
			AddPermissionAccess(new DirectoryServicesPermissionEntry(permissionAccess, path));
		}

		public DirectoryServicesPermission(DirectoryServicesPermissionEntry[] permissionAccessEntries)
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

		internal void AddPermissionAccess(DirectoryServicesPermissionEntry entry)
		{
			AddPermissionAccess(entry.GetBaseEntry());
		}

		internal new void Clear()
		{
			base.Clear();
		}

		internal void RemovePermissionAccess(DirectoryServicesPermissionEntry entry)
		{
			RemovePermissionAccess(entry.GetBaseEntry());
		}

		private void SetNames()
		{
			base.PermissionAccessType = typeof(DirectoryServicesPermissionAccess);
			base.TagNames = new string[1] { "Path" };
		}
	}
	[Flags]
	public enum DirectoryServicesPermissionAccess
	{
		None = 0,
		Browse = 2,
		Write = 6
	}
	[Serializable]
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Constructor | AttributeTargets.Method | AttributeTargets.Event, AllowMultiple = true, Inherited = false)]
	public class DirectoryServicesPermissionAttribute : CodeAccessSecurityAttribute
	{
		private string path;

		private DirectoryServicesPermissionAccess permissionAccess;

		public string Path
		{
			get
			{
				return path;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				path = value;
			}
		}

		public DirectoryServicesPermissionAccess PermissionAccess
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

		public DirectoryServicesPermissionAttribute(SecurityAction action)
			: base(action)
		{
			path = "*";
			permissionAccess = DirectoryServicesPermissionAccess.Browse;
		}

		public override IPermission CreatePermission()
		{
			if (base.Unrestricted)
			{
				return new DirectoryServicesPermission(PermissionState.Unrestricted);
			}
			DirectoryServicesPermissionAccess directoryServicesPermissionAccess = permissionAccess;
			string text = Path;
			return new DirectoryServicesPermission(directoryServicesPermissionAccess, text);
		}
	}
	[Serializable]
	public class DirectoryServicesPermissionEntry
	{
		private string path;

		private DirectoryServicesPermissionAccess permissionAccess;

		public string Path => path;

		public DirectoryServicesPermissionAccess PermissionAccess => permissionAccess;

		public DirectoryServicesPermissionEntry(DirectoryServicesPermissionAccess permissionAccess, string path)
		{
			if (path == null)
			{
				throw new ArgumentNullException("path");
			}
			this.permissionAccess = permissionAccess;
			this.path = path;
		}

		internal DirectoryServicesPermissionEntry(ResourcePermissionBaseEntry baseEntry)
		{
			permissionAccess = (DirectoryServicesPermissionAccess)baseEntry.PermissionAccess;
			path = baseEntry.PermissionAccessPath[0];
		}

		internal ResourcePermissionBaseEntry GetBaseEntry()
		{
			return new ResourcePermissionBaseEntry((int)PermissionAccess, new string[1] { Path });
		}
	}
	[Serializable]
	public class DirectoryServicesPermissionEntryCollection : CollectionBase
	{
		private DirectoryServicesPermission owner;

		public DirectoryServicesPermissionEntry this[int index]
		{
			get
			{
				return (DirectoryServicesPermissionEntry)base.List[index];
			}
			set
			{
				base.List[index] = value;
			}
		}

		internal DirectoryServicesPermissionEntryCollection(DirectoryServicesPermission owner, ResourcePermissionBaseEntry[] entries)
		{
			this.owner = owner;
			for (int i = 0; i < entries.Length; i++)
			{
				base.InnerList.Add(new DirectoryServicesPermissionEntry(entries[i]));
			}
		}

		internal DirectoryServicesPermissionEntryCollection()
		{
		}

		public int Add(DirectoryServicesPermissionEntry value)
		{
			return base.List.Add(value);
		}

		public void AddRange(DirectoryServicesPermissionEntry[] value)
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

		public void AddRange(DirectoryServicesPermissionEntryCollection value)
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

		public bool Contains(DirectoryServicesPermissionEntry value)
		{
			return base.List.Contains(value);
		}

		public void CopyTo(DirectoryServicesPermissionEntry[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(DirectoryServicesPermissionEntry value)
		{
			return base.List.IndexOf(value);
		}

		public void Insert(int index, DirectoryServicesPermissionEntry value)
		{
			base.List.Insert(index, value);
		}

		public void Remove(DirectoryServicesPermissionEntry value)
		{
			base.List.Remove(value);
		}

		protected override void OnClear()
		{
			owner.Clear();
		}

		protected override void OnInsert(int index, object value)
		{
			owner.AddPermissionAccess((DirectoryServicesPermissionEntry)value);
		}

		protected override void OnRemove(int index, object value)
		{
			owner.RemovePermissionAccess((DirectoryServicesPermissionEntry)value);
		}

		protected override void OnSet(int index, object oldValue, object newValue)
		{
			owner.RemovePermissionAccess((DirectoryServicesPermissionEntry)oldValue);
			owner.AddPermissionAccess((DirectoryServicesPermissionEntry)newValue);
		}
	}
	public class DirectorySynchronization
	{
		private DirectorySynchronizationOptions flag;

		private byte[] cookie = new byte[0];

		[DefaultValue(DirectorySynchronizationOptions.None)]
		[DSDescription("DSDirectorySynchronizationFlag")]
		public DirectorySynchronizationOptions Option
		{
			get
			{
				return flag;
			}
			set
			{
				long num = (long)(value & ~(DirectorySynchronizationOptions.ObjectSecurity | DirectorySynchronizationOptions.ParentsFirst | DirectorySynchronizationOptions.PublicDataOnly | DirectorySynchronizationOptions.IncrementalValues));
				if (num != 0)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(DirectorySynchronizationOptions));
				}
				flag = value;
			}
		}

		public DirectorySynchronization()
		{
		}

		public DirectorySynchronization(DirectorySynchronizationOptions option)
		{
			Option = option;
		}

		public DirectorySynchronization(DirectorySynchronization sync)
		{
			if (sync != null)
			{
				Option = sync.Option;
				ResetDirectorySynchronizationCookie(sync.GetDirectorySynchronizationCookie());
			}
		}

		public DirectorySynchronization(byte[] cookie)
		{
			ResetDirectorySynchronizationCookie(cookie);
		}

		public DirectorySynchronization(DirectorySynchronizationOptions option, byte[] cookie)
		{
			Option = option;
			ResetDirectorySynchronizationCookie(cookie);
		}

		public byte[] GetDirectorySynchronizationCookie()
		{
			byte[] array = new byte[cookie.Length];
			for (int i = 0; i < cookie.Length; i++)
			{
				array[i] = cookie[i];
			}
			return array;
		}

		public void ResetDirectorySynchronizationCookie()
		{
			cookie = new byte[0];
		}

		public void ResetDirectorySynchronizationCookie(byte[] cookie)
		{
			if (cookie == null)
			{
				this.cookie = new byte[0];
				return;
			}
			this.cookie = new byte[cookie.Length];
			for (int i = 0; i < cookie.Length; i++)
			{
				this.cookie[i] = cookie[i];
			}
		}

		public DirectorySynchronization Copy()
		{
			return new DirectorySynchronization(flag, cookie);
		}
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
	public class DirectoryVirtualListView
	{
		private int beforeCount;

		private int afterCount;

		private int offset;

		private string target = "";

		private int approximateTotal;

		private int targetPercentage;

		private DirectoryVirtualListViewContext context;

		[DefaultValue(0)]
		[DSDescription("DSBeforeCount")]
		public int BeforeCount
		{
			get
			{
				return beforeCount;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("DSBadBeforeCount"));
				}
				beforeCount = value;
			}
		}

		[DSDescription("DSAfterCount")]
		[DefaultValue(0)]
		public int AfterCount
		{
			get
			{
				return afterCount;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("DSBadAfterCount"));
				}
				afterCount = value;
			}
		}

		[DefaultValue(0)]
		[DSDescription("DSOffset")]
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
					throw new ArgumentException(Res.GetString("DSBadOffset"));
				}
				offset = value;
				if (approximateTotal != 0)
				{
					targetPercentage = (int)((double)offset / (double)approximateTotal * 100.0);
				}
				else
				{
					targetPercentage = 0;
				}
			}
		}

		[DSDescription("DSTargetPercentage")]
		[DefaultValue(0)]
		public int TargetPercentage
		{
			get
			{
				return targetPercentage;
			}
			set
			{
				if (value > 100 || value < 0)
				{
					throw new ArgumentException(Res.GetString("DSBadTargetPercentage"));
				}
				targetPercentage = value;
				offset = approximateTotal * targetPercentage / 100;
			}
		}

		[DSDescription("DSTarget")]
		[DefaultValue("")]
		[TypeConverter("System.Diagnostics.Design.StringValueConverter, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
		public string Target
		{
			get
			{
				return target;
			}
			set
			{
				if (value == null)
				{
					value = "";
				}
				target = value;
			}
		}

		[DSDescription("DSApproximateTotal")]
		[DefaultValue(0)]
		public int ApproximateTotal
		{
			get
			{
				return approximateTotal;
			}
			set
			{
				if (value < 0)
				{
					throw new ArgumentException(Res.GetString("DSBadApproximateTotal"));
				}
				approximateTotal = value;
			}
		}

		[DSDescription("DSDirectoryVirtualListViewContext")]
		[DefaultValue(null)]
		public DirectoryVirtualListViewContext DirectoryVirtualListViewContext
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

		public DirectoryVirtualListView()
		{
		}

		public DirectoryVirtualListView(int afterCount)
		{
			AfterCount = afterCount;
		}

		public DirectoryVirtualListView(int beforeCount, int afterCount, int offset)
		{
			BeforeCount = beforeCount;
			AfterCount = afterCount;
			Offset = offset;
		}

		public DirectoryVirtualListView(int beforeCount, int afterCount, string target)
		{
			BeforeCount = beforeCount;
			AfterCount = afterCount;
			Target = target;
		}

		public DirectoryVirtualListView(int beforeCount, int afterCount, int offset, DirectoryVirtualListViewContext context)
		{
			BeforeCount = beforeCount;
			AfterCount = afterCount;
			Offset = offset;
			this.context = context;
		}

		public DirectoryVirtualListView(int beforeCount, int afterCount, string target, DirectoryVirtualListViewContext context)
		{
			BeforeCount = beforeCount;
			AfterCount = afterCount;
			Target = target;
			this.context = context;
		}
	}
	public class DirectoryVirtualListViewContext
	{
		internal byte[] context;

		public DirectoryVirtualListViewContext()
			: this(new byte[0])
		{
		}

		internal DirectoryVirtualListViewContext(byte[] context)
		{
			if (context == null)
			{
				this.context = new byte[0];
				return;
			}
			this.context = new byte[context.Length];
			for (int i = 0; i < context.Length; i++)
			{
				this.context[i] = context[i];
			}
		}

		public DirectoryVirtualListViewContext Copy()
		{
			return new DirectoryVirtualListViewContext(context);
		}
	}
	public enum ExtendedDN
	{
		None = -1,
		HexString,
		Standard
	}
	public enum PasswordEncodingMethod
	{
		PasswordEncodingSsl,
		PasswordEncodingClear
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class PropertyCollection : IDictionary, ICollection, IEnumerable
	{
		private class PropertyEnumerator : IDictionaryEnumerator, IEnumerator, IDisposable
		{
			private DirectoryEntry entry;

			private DirectoryEntry parentEntry;

			private string currentPropName;

			public object Current => Entry.Value;

			public DictionaryEntry Entry
			{
				get
				{
					if (currentPropName == null)
					{
						throw new InvalidOperationException(Res.GetString("DSNoCurrentProperty"));
					}
					return new DictionaryEntry(currentPropName, new PropertyValueCollection(parentEntry, currentPropName));
				}
			}

			public object Key => Entry.Key;

			public object Value => Entry.Value;

			public PropertyEnumerator(DirectoryEntry parent, DirectoryEntry clone)
			{
				entry = clone;
				parentEntry = parent;
			}

			~PropertyEnumerator()
			{
				Dispose(disposing: true);
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
					entry.Dispose();
				}
			}

			public bool MoveNext()
			{
				int num = 0;
				object nextProp;
				try
				{
					num = ((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)entry.AdsObject).Next(out nextProp);
				}
				catch (COMException ex)
				{
					num = ex.ErrorCode;
					nextProp = null;
				}
				if (num == 0)
				{
					if (nextProp != null)
					{
						currentPropName = ((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyEntry)nextProp).Name;
					}
					else
					{
						currentPropName = null;
					}
					return true;
				}
				currentPropName = null;
				return false;
			}

			public void Reset()
			{
				((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)entry.AdsObject).Reset();
				currentPropName = null;
			}
		}

		private class ValuesCollection : ICollection, IEnumerable
		{
			protected PropertyCollection props;

			public int Count => props.Count;

			public bool IsReadOnly => true;

			public bool IsSynchronized => false;

			public object SyncRoot => ((ICollection)props).SyncRoot;

			public ValuesCollection(PropertyCollection props)
			{
				this.props = props;
			}

			public void CopyTo(Array array, int index)
			{
				IEnumerator enumerator = GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						object current = enumerator.Current;
						array.SetValue(current, index++);
					}
				}
				finally
				{
					IDisposable disposable = enumerator as IDisposable;
					if (disposable != null)
					{
						disposable.Dispose();
					}
				}
			}

			public virtual IEnumerator GetEnumerator()
			{
				return new ValuesEnumerator(props);
			}
		}

		private class KeysCollection : ValuesCollection
		{
			public KeysCollection(PropertyCollection props)
				: base(props)
			{
			}

			public override IEnumerator GetEnumerator()
			{
				props.entry.FillCache("");
				return new KeysEnumerator(props);
			}
		}

		private class ValuesEnumerator : IEnumerator
		{
			private int currentIndex = -1;

			protected PropertyCollection propCollection;

			protected int CurrentIndex
			{
				get
				{
					if (currentIndex == -1)
					{
						throw new InvalidOperationException(Res.GetString("DSNoCurrentValue"));
					}
					return currentIndex;
				}
			}

			public virtual object Current
			{
				get
				{
					System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList adsPropertyList = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)propCollection.entry.AdsObject;
					return propCollection[((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyEntry)adsPropertyList.Item(CurrentIndex)).Name];
				}
			}

			public ValuesEnumerator(PropertyCollection propCollection)
			{
				this.propCollection = propCollection;
			}

			public bool MoveNext()
			{
				currentIndex++;
				if (currentIndex >= propCollection.Count)
				{
					currentIndex = -1;
					return false;
				}
				return true;
			}

			public void Reset()
			{
				currentIndex = -1;
			}
		}

		private class KeysEnumerator : ValuesEnumerator
		{
			public override object Current
			{
				get
				{
					System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList adsPropertyList = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)propCollection.entry.AdsObject;
					return ((System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyEntry)adsPropertyList.Item(base.CurrentIndex)).Name;
				}
			}

			public KeysEnumerator(PropertyCollection collection)
				: base(collection)
			{
			}
		}

		private DirectoryEntry entry;

		internal Hashtable valueTable;

		public PropertyValueCollection this[string propertyName]
		{
			get
			{
				if (propertyName == null)
				{
					throw new ArgumentNullException("propertyName");
				}
				string key = propertyName.ToLower(CultureInfo.InvariantCulture);
				if (valueTable.Contains(key))
				{
					return (PropertyValueCollection)valueTable[key];
				}
				PropertyValueCollection propertyValueCollection = new PropertyValueCollection(entry, propertyName);
				valueTable.Add(key, propertyValueCollection);
				return propertyValueCollection;
			}
		}

		public int Count
		{
			get
			{
				if (!(entry.AdsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList))
				{
					throw new NotSupportedException(Res.GetString("DSCannotCount"));
				}
				entry.FillCache("");
				System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList adsPropertyList = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)entry.AdsObject;
				return adsPropertyList.PropertyCount;
			}
		}

		public ICollection PropertyNames => new KeysCollection(this);

		public ICollection Values => new ValuesCollection(this);

		object IDictionary.this[object key]
		{
			get
			{
				return this[(string)key];
			}
			set
			{
				throw new NotSupportedException(Res.GetString("DSPropertySetSupported"));
			}
		}

		bool IDictionary.IsFixedSize => true;

		bool IDictionary.IsReadOnly => true;

		ICollection IDictionary.Keys => new KeysCollection(this);

		bool ICollection.IsSynchronized => false;

		object ICollection.SyncRoot => this;

		internal PropertyCollection(DirectoryEntry entry)
		{
			this.entry = entry;
			Hashtable table = new Hashtable();
			valueTable = Hashtable.Synchronized(table);
		}

		public bool Contains(string propertyName)
		{
			object value;
			int ex = entry.AdsObject.GetEx(propertyName, out value);
			switch (ex)
			{
			case -2147463162:
			case -2147463155:
				return false;
			default:
				throw COMExceptionHelper.CreateFormattedComException(ex);
			case 0:
				return true;
			}
		}

		public void CopyTo(PropertyValueCollection[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}

		public IDictionaryEnumerator GetEnumerator()
		{
			if (!(entry.AdsObject is System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList))
			{
				throw new NotSupportedException(Res.GetString("DSCannotEmunerate"));
			}
			DirectoryEntry directoryEntry = entry.CloneBrowsable();
			directoryEntry.FillCache("");
			_ = (System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsPropertyList)directoryEntry.AdsObject;
			directoryEntry.propertiesAlreadyEnumerated = true;
			return new PropertyEnumerator(entry, directoryEntry);
		}

		void IDictionary.Add(object key, object value)
		{
			throw new NotSupportedException(Res.GetString("DSAddNotSupported"));
		}

		void IDictionary.Clear()
		{
			throw new NotSupportedException(Res.GetString("DSClearNotSupported"));
		}

		bool IDictionary.Contains(object value)
		{
			return Contains((string)value);
		}

		void IDictionary.Remove(object key)
		{
			throw new NotSupportedException(Res.GetString("DSRemoveNotSupported"));
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}

		void ICollection.CopyTo(Array array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			if (array.Rank != 1)
			{
				throw new ArgumentException(Res.GetString("OnlyAllowSingleDimension"), "array");
			}
			if (index < 0)
			{
				throw new ArgumentOutOfRangeException(Res.GetString("LessThanZero"), "index");
			}
			if (index + Count > array.Length || index + Count < index)
			{
				throw new ArgumentException(Res.GetString("DestinationArrayNotLargeEnough"));
			}
			IDictionaryEnumerator dictionaryEnumerator = GetEnumerator();
			try
			{
				while (dictionaryEnumerator.MoveNext())
				{
					PropertyValueCollection value = (PropertyValueCollection)dictionaryEnumerator.Current;
					array.SetValue(value, index);
					index++;
				}
			}
			finally
			{
				IDisposable disposable = dictionaryEnumerator as IDisposable;
				if (disposable != null)
				{
					disposable.Dispose();
				}
			}
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class PropertyValueCollection : CollectionBase
	{
		internal enum UpdateType
		{
			Add,
			Delete,
			Update,
			None
		}

		private DirectoryEntry entry;

		private string propertyName;

		private UpdateType updateType = UpdateType.None;

		private ArrayList changeList;

		private bool allowMultipleChange;

		private bool needNewBehavior;

		public object this[int index]
		{
			get
			{
				return base.List[index];
			}
			set
			{
				if (needNewBehavior && !allowMultipleChange)
				{
					throw new NotSupportedException();
				}
				base.List[index] = value;
			}
		}

		[ComVisible(false)]
		public string PropertyName => propertyName;

		public object Value
		{
			get
			{
				if (base.Count == 0)
				{
					return null;
				}
				if (base.Count == 1)
				{
					return base.List[0];
				}
				object[] array = new object[base.Count];
				base.List.CopyTo(array, 0);
				return array;
			}
			set
			{
				try
				{
					Clear();
				}
				catch (COMException ex)
				{
					if (ex.ErrorCode != -2147467259 || value == null)
					{
						throw;
					}
				}
				if (value == null)
				{
					return;
				}
				changeList.Clear();
				if (value is Array)
				{
					if (value is byte[])
					{
						changeList.Add(value);
					}
					else if (value is object[])
					{
						changeList.AddRange((object[])value);
					}
					else
					{
						object[] array = new object[((Array)value).Length];
						((Array)value).CopyTo(array, 0);
						changeList.AddRange(array);
					}
				}
				else
				{
					changeList.Add(value);
				}
				object[] array2 = new object[changeList.Count];
				changeList.CopyTo(array2, 0);
				entry.AdsObject.PutEx(2, propertyName, array2);
				entry.CommitIfNotCaching();
				PopulateList();
			}
		}

		internal PropertyValueCollection(DirectoryEntry entry, string propertyName)
		{
			this.entry = entry;
			this.propertyName = propertyName;
			PopulateList();
			ArrayList arrayList = new ArrayList();
			changeList = ArrayList.Synchronized(arrayList);
			allowMultipleChange = entry.allowMultipleChange;
			string path = entry.Path;
			if (path == null || path.Length == 0)
			{
				needNewBehavior = true;
			}
			else if (path.StartsWith("LDAP:", StringComparison.Ordinal))
			{
				needNewBehavior = true;
			}
		}

		public int Add(object value)
		{
			return base.List.Add(value);
		}

		public void AddRange(object[] value)
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

		public void AddRange(PropertyValueCollection value)
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

		public void Insert(int index, object value)
		{
			base.List.Insert(index, value);
		}

		private void PopulateList()
		{
			object value;
			int ex = entry.AdsObject.GetEx(propertyName, out value);
			switch (ex)
			{
			case -2147463162:
			case -2147463155:
				break;
			default:
				throw COMExceptionHelper.CreateFormattedComException(ex);
			case 0:
				if (value is ICollection)
				{
					base.InnerList.AddRange((ICollection)value);
				}
				else
				{
					base.InnerList.Add(value);
				}
				break;
			}
		}

		public void Remove(object value)
		{
			if (needNewBehavior)
			{
				try
				{
					base.List.Remove(value);
					return;
				}
				catch (ArgumentException)
				{
					OnRemoveComplete(0, value);
					return;
				}
			}
			base.List.Remove(value);
		}

		protected override void OnClearComplete()
		{
			if (needNewBehavior && !allowMultipleChange && updateType != UpdateType.None && updateType != UpdateType.Update)
			{
				throw new InvalidOperationException(Res.GetString("DSPropertyValueSupportOneOperation"));
			}
			entry.AdsObject.PutEx(1, propertyName, null);
			updateType = UpdateType.Update;
			try
			{
				entry.CommitIfNotCaching();
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode != -2147016694)
				{
					throw;
				}
			}
		}

		protected override void OnInsertComplete(int index, object value)
		{
			if (needNewBehavior)
			{
				if (!allowMultipleChange)
				{
					if (updateType != UpdateType.None && updateType != 0)
					{
						throw new InvalidOperationException(Res.GetString("DSPropertyValueSupportOneOperation"));
					}
					changeList.Add(value);
					object[] array = new object[changeList.Count];
					changeList.CopyTo(array, 0);
					entry.AdsObject.PutEx(3, propertyName, array);
					updateType = UpdateType.Add;
				}
				else
				{
					entry.AdsObject.PutEx(3, propertyName, new object[1] { value });
				}
			}
			else
			{
				object[] array2 = new object[base.InnerList.Count];
				base.InnerList.CopyTo(array2, 0);
				entry.AdsObject.PutEx(2, propertyName, array2);
			}
			entry.CommitIfNotCaching();
		}

		protected override void OnRemoveComplete(int index, object value)
		{
			if (needNewBehavior)
			{
				if (!allowMultipleChange)
				{
					if (updateType != UpdateType.None && updateType != UpdateType.Delete)
					{
						throw new InvalidOperationException(Res.GetString("DSPropertyValueSupportOneOperation"));
					}
					changeList.Add(value);
					object[] array = new object[changeList.Count];
					changeList.CopyTo(array, 0);
					entry.AdsObject.PutEx(4, propertyName, array);
					updateType = UpdateType.Delete;
				}
				else
				{
					entry.AdsObject.PutEx(4, propertyName, new object[1] { value });
				}
			}
			else
			{
				object[] array2 = new object[base.InnerList.Count];
				base.InnerList.CopyTo(array2, 0);
				entry.AdsObject.PutEx(2, propertyName, array2);
			}
			entry.CommitIfNotCaching();
		}

		protected override void OnSetComplete(int index, object oldValue, object newValue)
		{
			if (base.Count <= 1)
			{
				entry.AdsObject.Put(propertyName, newValue);
			}
			else if (needNewBehavior)
			{
				entry.AdsObject.PutEx(4, propertyName, new object[1] { oldValue });
				entry.AdsObject.PutEx(3, propertyName, new object[1] { newValue });
			}
			else
			{
				object[] array = new object[base.InnerList.Count];
				base.InnerList.CopyTo(array, 0);
				entry.AdsObject.PutEx(2, propertyName, array);
			}
			entry.CommitIfNotCaching();
		}
	}
	public enum ReferralChasingOption
	{
		None = 0,
		Subordinate = 32,
		External = 64,
		All = 96
	}
	public class ResultPropertyCollection : DictionaryBase
	{
		public ResultPropertyValueCollection this[string name]
		{
			get
			{
				object obj = name.ToLower(CultureInfo.InvariantCulture);
				if (Contains((string)obj))
				{
					return (ResultPropertyValueCollection)base.InnerHashtable[obj];
				}
				return new ResultPropertyValueCollection(new object[0]);
			}
		}

		public ICollection PropertyNames => base.Dictionary.Keys;

		public ICollection Values => base.Dictionary.Values;

		internal ResultPropertyCollection()
		{
		}

		internal void Add(string name, ResultPropertyValueCollection value)
		{
			base.Dictionary.Add(name.ToLower(CultureInfo.InvariantCulture), value);
		}

		public bool Contains(string propertyName)
		{
			object key = propertyName.ToLower(CultureInfo.InvariantCulture);
			return base.Dictionary.Contains(key);
		}

		public void CopyTo(ResultPropertyValueCollection[] array, int index)
		{
			base.Dictionary.Values.CopyTo(array, index);
		}
	}
	public class ResultPropertyValueCollection : ReadOnlyCollectionBase
	{
		public object this[int index]
		{
			get
			{
				object obj = base.InnerList[index];
				if (obj is Exception)
				{
					throw (Exception)obj;
				}
				return obj;
			}
		}

		internal ResultPropertyValueCollection(object[] values)
		{
			if (values == null)
			{
				values = new object[0];
			}
			base.InnerList.AddRange(values);
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
	public class SchemaNameCollection : IList, ICollection, IEnumerable
	{
		internal delegate object VariantPropGetter();

		internal delegate void VariantPropSetter(object value);

		internal class FilterDelegateWrapper
		{
			private System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsContainer obj;

			public VariantPropGetter Getter => GetFilter;

			public VariantPropSetter Setter => SetFilter;

			internal FilterDelegateWrapper(System.DirectoryServices.Interop.UnsafeNativeMethods.IAdsContainer wrapped)
			{
				obj = wrapped;
			}

			private object GetFilter()
			{
				return obj.Filter;
			}

			private void SetFilter(object value)
			{
				obj.Filter = value;
			}
		}

		private VariantPropGetter propGetter;

		private VariantPropSetter propSetter;

		public string this[int index]
		{
			get
			{
				object[] value = GetValue();
				return (string)value[index];
			}
			set
			{
				object[] value2 = GetValue();
				value2[index] = value;
				propSetter(value2);
			}
		}

		public int Count
		{
			get
			{
				object[] value = GetValue();
				return value.Length;
			}
		}

		bool IList.IsReadOnly => false;

		bool IList.IsFixedSize => false;

		bool ICollection.IsSynchronized => false;

		object ICollection.SyncRoot => this;

		object IList.this[int index]
		{
			get
			{
				return this[index];
			}
			set
			{
				this[index] = (string)value;
			}
		}

		internal SchemaNameCollection(VariantPropGetter propGetter, VariantPropSetter propSetter)
		{
			this.propGetter = propGetter;
			this.propSetter = propSetter;
		}

		public int Add(string value)
		{
			object[] value2 = GetValue();
			object[] array = new object[value2.Length + 1];
			for (int i = 0; i < value2.Length; i++)
			{
				array[i] = value2[i];
			}
			array[array.Length - 1] = value;
			propSetter(array);
			return array.Length - 1;
		}

		public void AddRange(string[] value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			object[] value2 = GetValue();
			object[] array = new object[value2.Length + value.Length];
			for (int i = 0; i < value2.Length; i++)
			{
				array[i] = value2[i];
			}
			for (int j = value2.Length; j < array.Length; j++)
			{
				array[j] = value[j - value2.Length];
			}
			propSetter(array);
		}

		public void AddRange(SchemaNameCollection value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			object[] value2 = GetValue();
			object[] array = new object[value2.Length + value.Count];
			for (int i = 0; i < value2.Length; i++)
			{
				array[i] = value2[i];
			}
			for (int j = value2.Length; j < array.Length; j++)
			{
				array[j] = value[j - value2.Length];
			}
			propSetter(array);
		}

		public void Clear()
		{
			object[] value = new object[0];
			propSetter(value);
		}

		public bool Contains(string value)
		{
			return IndexOf(value) != -1;
		}

		public void CopyTo(string[] stringArray, int index)
		{
			object[] value = GetValue();
			value.CopyTo(stringArray, index);
		}

		public IEnumerator GetEnumerator()
		{
			object[] value = GetValue();
			return value.GetEnumerator();
		}

		private object[] GetValue()
		{
			object obj = propGetter();
			if (obj == null)
			{
				return new object[0];
			}
			return (object[])obj;
		}

		public int IndexOf(string value)
		{
			object[] value2 = GetValue();
			for (int i = 0; i < value2.Length; i++)
			{
				if (value == (string)value2[i])
				{
					return i;
				}
			}
			return -1;
		}

		public void Insert(int index, string value)
		{
			ArrayList arrayList = new ArrayList(GetValue());
			arrayList.Insert(index, value);
			propSetter(arrayList.ToArray());
		}

		public void Remove(string value)
		{
			int index = IndexOf(value);
			RemoveAt(index);
		}

		public void RemoveAt(int index)
		{
			object[] value = GetValue();
			if (index >= value.Length || index < 0)
			{
				throw new ArgumentOutOfRangeException("index");
			}
			object[] array = new object[value.Length - 1];
			for (int i = 0; i < index; i++)
			{
				array[i] = value[i];
			}
			for (int j = index + 1; j < value.Length; j++)
			{
				array[j - 1] = value[j];
			}
			propSetter(array);
		}

		void ICollection.CopyTo(Array array, int index)
		{
			object[] value = GetValue();
			value.CopyTo(array, index);
		}

		int IList.Add(object value)
		{
			return Add((string)value);
		}

		bool IList.Contains(object value)
		{
			return Contains((string)value);
		}

		int IList.IndexOf(object value)
		{
			return IndexOf((string)value);
		}

		void IList.Insert(int index, object value)
		{
			Insert(index, (string)value);
		}

		void IList.Remove(object value)
		{
			Remove((string)value);
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class SearchResult
	{
		private NetworkCredential parentCredentials;

		private AuthenticationTypes parentAuthenticationType;

		private ResultPropertyCollection properties = new ResultPropertyCollection();

		public string Path => (string)Properties["ADsPath"][0];

		public ResultPropertyCollection Properties => properties;

		internal SearchResult(NetworkCredential parentCredentials, AuthenticationTypes parentAuthenticationType)
		{
			this.parentCredentials = parentCredentials;
			this.parentAuthenticationType = parentAuthenticationType;
		}

		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
		public DirectoryEntry GetDirectoryEntry()
		{
			if (parentCredentials != null)
			{
				return new DirectoryEntry(Path, useCache: true, parentCredentials.UserName, parentCredentials.Password, parentAuthenticationType);
			}
			return new DirectoryEntry(Path, useCache: true, null, null, parentAuthenticationType);
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class SearchResultCollection : MarshalByRefObject, ICollection, IEnumerable, IDisposable
	{
		private class ResultsEnumerator : IEnumerator
		{
			private NetworkCredential parentCredentials;

			private AuthenticationTypes parentAuthenticationType;

			private SearchResultCollection results;

			private bool initialized;

			private SearchResult currentResult;

			private bool eof;

			private bool waitForResult;

			public SearchResult Current
			{
				get
				{
					if (!initialized || eof)
					{
						throw new InvalidOperationException(Res.GetString("DSNoCurrentEntry"));
					}
					if (currentResult == null)
					{
						currentResult = GetCurrentResult();
					}
					return currentResult;
				}
			}

			object IEnumerator.Current => Current;

			internal ResultsEnumerator(SearchResultCollection results, string parentUserName, string parentPassword, AuthenticationTypes parentAuthenticationType)
			{
				if (parentUserName != null && parentPassword != null)
				{
					parentCredentials = new NetworkCredential(parentUserName, parentPassword);
				}
				this.parentAuthenticationType = parentAuthenticationType;
				this.results = results;
				initialized = false;
				object section = System.Configuration.PrivilegedConfigurationManager.GetSection("system.directoryservices");
				if (section != null && section is bool)
				{
					waitForResult = (bool)section;
				}
			}

			private unsafe SearchResult GetCurrentResult()
			{
				SearchResult searchResult = new SearchResult(parentCredentials, parentAuthenticationType);
				int num = 0;
				IntPtr intPtr = (IntPtr)0;
				for (num = results.SearchObject.GetNextColumnName(results.Handle, (IntPtr)(&intPtr)); num == 0; num = results.SearchObject.GetNextColumnName(results.Handle, (IntPtr)(&intPtr)))
				{
					try
					{
						AdsSearchColumn adsSearchColumn = default(AdsSearchColumn);
						AdsSearchColumn* ptr = &adsSearchColumn;
						results.SearchObject.GetColumn(results.Handle, intPtr, (IntPtr)ptr);
						try
						{
							int dwNumValues = adsSearchColumn.dwNumValues;
							AdsValue* ptr2 = adsSearchColumn.pADsValues;
							object[] array = new object[dwNumValues];
							for (int i = 0; i < dwNumValues; i++)
							{
								array[i] = new AdsValueHelper(*ptr2).GetValue();
								ptr2++;
							}
							searchResult.Properties.Add(Marshal.PtrToStringUni(intPtr), new ResultPropertyValueCollection(array));
						}
						finally
						{
							try
							{
								results.SearchObject.FreeColumn((IntPtr)ptr);
							}
							catch (COMException)
							{
							}
						}
					}
					finally
					{
						SafeNativeMethods.FreeADsMem(intPtr);
					}
				}
				return searchResult;
			}

			public bool MoveNext()
			{
				int num = 0;
				if (eof)
				{
					return false;
				}
				currentResult = null;
				if (!initialized)
				{
					int firstRow = results.SearchObject.GetFirstRow(results.Handle);
					switch (firstRow)
					{
					case -2147016642:
						throw new ArgumentException(Res.GetString("DSInvalidSearchFilter", results.Filter));
					default:
						throw COMExceptionHelper.CreateFormattedComException(firstRow);
					case 0:
						eof = false;
						initialized = true;
						return true;
					case 20498:
						break;
					}
					initialized = true;
				}
				do
				{
					CleanLastError();
					num = 0;
					int nextRow = results.SearchObject.GetNextRow(results.Handle);
					switch (nextRow)
					{
					case -2147016669:
					case 20498:
						if (nextRow == 20498)
						{
							nextRow = GetLastError(ref num);
							if (nextRow != 0)
							{
								throw COMExceptionHelper.CreateFormattedComException(nextRow);
							}
						}
						if (num != 234)
						{
							if (results.srch.directorySynchronizationSpecified)
							{
								_ = results.srch.DirectorySynchronization;
							}
							if (results.srch.directoryVirtualListViewSpecified)
							{
								_ = results.srch.VirtualListView;
							}
							results.srch.searchResult = null;
							eof = true;
							initialized = false;
							return false;
						}
						break;
					case -2147016642:
						throw new ArgumentException(Res.GetString("DSInvalidSearchFilter", results.Filter));
					default:
						throw COMExceptionHelper.CreateFormattedComException(nextRow);
					case 0:
						eof = false;
						return true;
					}
				}
				while (waitForResult);
				uint num2 = (uint)num;
				num2 = (num2 & 0xFFFFu) | 0x70000u | 0x80000000u;
				throw COMExceptionHelper.CreateFormattedComException((int)num2);
			}

			public void Reset()
			{
				eof = false;
				initialized = false;
			}

			private void CleanLastError()
			{
				SafeNativeMethods.ADsSetLastError(0, null, null);
			}

			private int GetLastError(ref int errorCode)
			{
				StringBuilder errorBuffer = new StringBuilder();
				StringBuilder nameBuffer = new StringBuilder();
				errorCode = 0;
				return SafeNativeMethods.ADsGetLastError(out errorCode, errorBuffer, 0, nameBuffer, 0);
			}
		}

		private const string ADS_DIRSYNC_COOKIE = "fc8cb04d-311d-406c-8cb9-1ae8b843b418";

		private const string ADS_VLV_RESPONSE = "fc8cb04d-311d-406c-8cb9-1ae8b843b419";

		private IntPtr handle;

		private string[] properties;

		private System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch searchObject;

		private string filter;

		private ArrayList innerList;

		private bool disposed;

		private DirectoryEntry rootEntry;

		private IntPtr AdsDirsynCookieName = Marshal.StringToCoTaskMemUni("fc8cb04d-311d-406c-8cb9-1ae8b843b418");

		private IntPtr AdsVLVResponseName = Marshal.StringToCoTaskMemUni("fc8cb04d-311d-406c-8cb9-1ae8b843b419");

		internal DirectorySearcher srch;

		public SearchResult this[int index] => (SearchResult)InnerList[index];

		public int Count => InnerList.Count;

		internal string Filter => filter;

		private ArrayList InnerList
		{
			get
			{
				if (innerList == null)
				{
					innerList = new ArrayList();
					IEnumerator enumerator = new ResultsEnumerator(this, rootEntry.GetUsername(), rootEntry.GetPassword(), rootEntry.AuthenticationType);
					while (enumerator.MoveNext())
					{
						innerList.Add(enumerator.Current);
					}
				}
				return innerList;
			}
		}

		internal System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch SearchObject
		{
			get
			{
				if (searchObject == null)
				{
					searchObject = (System.DirectoryServices.Interop.UnsafeNativeMethods.IDirectorySearch)rootEntry.AdsObject;
				}
				return searchObject;
			}
		}

		public IntPtr Handle
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return handle;
			}
		}

		public string[] PropertiesLoaded => properties;

		internal byte[] DirsyncCookie => RetrieveDirectorySynchronizationCookie();

		internal DirectoryVirtualListView VLVResponse => RetrieveVLVResponse();

		bool ICollection.IsSynchronized => false;

		object ICollection.SyncRoot => this;

		internal SearchResultCollection(DirectoryEntry root, IntPtr searchHandle, string[] propertiesLoaded, DirectorySearcher srch)
		{
			handle = searchHandle;
			properties = propertiesLoaded;
			filter = srch.Filter;
			rootEntry = root;
			this.srch = srch;
		}

		internal unsafe byte[] RetrieveDirectorySynchronizationCookie()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			AdsSearchColumn adsSearchColumn = default(AdsSearchColumn);
			AdsSearchColumn* ptr = &adsSearchColumn;
			SearchObject.GetColumn(Handle, AdsDirsynCookieName, (IntPtr)ptr);
			try
			{
				AdsValue* pADsValues = adsSearchColumn.pADsValues;
				return (byte[])new AdsValueHelper(*pADsValues).GetValue();
			}
			finally
			{
				try
				{
					SearchObject.FreeColumn((IntPtr)ptr);
				}
				catch (COMException)
				{
				}
			}
		}

		internal unsafe DirectoryVirtualListView RetrieveVLVResponse()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			AdsSearchColumn adsSearchColumn = default(AdsSearchColumn);
			AdsSearchColumn* ptr = &adsSearchColumn;
			SearchObject.GetColumn(Handle, AdsVLVResponseName, (IntPtr)ptr);
			try
			{
				AdsValue* pADsValues = adsSearchColumn.pADsValues;
				return (DirectoryVirtualListView)new AdsValueHelper(*pADsValues).GetVlvValue();
			}
			finally
			{
				try
				{
					SearchObject.FreeColumn((IntPtr)ptr);
				}
				catch (COMException)
				{
				}
			}
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (!disposed)
			{
				if (handle != (IntPtr)0 && searchObject != null && disposing)
				{
					searchObject.CloseSearchHandle(handle);
					handle = (IntPtr)0;
				}
				if (disposing)
				{
					rootEntry.Dispose();
				}
				if (AdsDirsynCookieName != (IntPtr)0)
				{
					Marshal.FreeCoTaskMem(AdsDirsynCookieName);
				}
				if (AdsVLVResponseName != (IntPtr)0)
				{
					Marshal.FreeCoTaskMem(AdsVLVResponseName);
				}
				disposed = true;
			}
		}

		~SearchResultCollection()
		{
			Dispose(disposing: false);
		}

		public IEnumerator GetEnumerator()
		{
			return new ResultsEnumerator(this, rootEntry.GetUsername(), rootEntry.GetPassword(), rootEntry.AuthenticationType);
		}

		public bool Contains(SearchResult result)
		{
			return InnerList.Contains(result);
		}

		public void CopyTo(SearchResult[] results, int index)
		{
			InnerList.CopyTo(results, index);
		}

		public int IndexOf(SearchResult result)
		{
			return InnerList.IndexOf(result);
		}

		void ICollection.CopyTo(Array array, int index)
		{
			InnerList.CopyTo(array, index);
		}
	}
	public enum SearchScope
	{
		Base,
		OneLevel,
		Subtree
	}
	internal class SearchWaitHandler : IConfigurationSectionHandler
	{
		public virtual object Create(object parent, object configContext, XmlNode section)
		{
			bool flag = false;
			bool value = false;
			foreach (XmlNode childNode in section.ChildNodes)
			{
				string name;
				if ((name = childNode.Name) != null && name == "DirectorySearcher")
				{
					if (flag)
					{
						throw new ConfigurationErrorsException(Res.GetString("ConfigSectionsUnique", "DirectorySearcher"));
					}
					HandlerBase.RemoveBooleanAttribute(childNode, "waitForPagedSearchData", ref value);
					flag = true;
				}
			}
			return value;
		}
	}
	internal class HandlerBase
	{
		private HandlerBase()
		{
		}

		internal static void RemoveBooleanAttribute(XmlNode node, string name, ref bool value)
		{
			value = false;
			XmlNode xmlNode = node.Attributes.RemoveNamedItem(name);
			if (xmlNode != null)
			{
				try
				{
					value = bool.Parse(xmlNode.Value);
				}
				catch (FormatException)
				{
					throw new ConfigurationErrorsException(Res.GetString("Invalid_boolean_attribute", name));
				}
			}
		}
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
	public enum SortDirection
	{
		Ascending,
		Descending
	}
	[TypeConverter(typeof(ExpandableObjectConverter))]
	public class SortOption
	{
		private string propertyName;

		private SortDirection sortDirection;

		[DefaultValue(null)]
		[DSDescription("DSSortName")]
		public string PropertyName
		{
			get
			{
				return propertyName;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				propertyName = value;
			}
		}

		[DefaultValue(SortDirection.Ascending)]
		[DSDescription("DSSortDirection")]
		public SortDirection Direction
		{
			get
			{
				return sortDirection;
			}
			set
			{
				if (value < SortDirection.Ascending || value > SortDirection.Descending)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(SortDirection));
				}
				sortDirection = value;
			}
		}

		public SortOption()
		{
		}

		public SortOption(string propertyName, SortDirection direction)
		{
			PropertyName = propertyName;
			Direction = sortDirection;
		}
	}
	[Serializable]
	public class DirectoryServicesCOMException : COMException, ISerializable
	{
		private int extendederror;

		private string extendedmessage = "";

		public int ExtendedError => extendederror;

		public string ExtendedErrorMessage => extendedmessage;

		public DirectoryServicesCOMException()
		{
		}

		public DirectoryServicesCOMException(string message)
			: base(message)
		{
		}

		public DirectoryServicesCOMException(string message, Exception inner)
			: base(message, inner)
		{
		}

		protected DirectoryServicesCOMException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		internal DirectoryServicesCOMException(string extendedMessage, int extendedError, COMException e)
			: base(e.Message, e.ErrorCode)
		{
			extendederror = extendedError;
			extendedmessage = extendedMessage;
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	internal class COMExceptionHelper
	{
		internal static Exception CreateFormattedComException(int hr)
		{
			string text = "";
			StringBuilder stringBuilder = new StringBuilder(256);
			int num = SafeNativeMethods.FormatMessageW(12800, 0, hr, 0, stringBuilder, stringBuilder.Capacity + 1, 0);
			text = ((num == 0) ? Res.GetString("DSUnknown", Convert.ToString(hr, 16)) : stringBuilder.ToString(0, num));
			return CreateFormattedComException(new COMException(text, hr));
		}

		internal static Exception CreateFormattedComException(COMException e)
		{
			StringBuilder stringBuilder = new StringBuilder(256);
			StringBuilder nameBuffer = new StringBuilder();
			int error = 0;
			SafeNativeMethods.ADsGetLastError(out error, stringBuilder, 256, nameBuffer, 0);
			if (error != 0)
			{
				return new DirectoryServicesCOMException(stringBuilder.ToString(), error, e);
			}
			return e;
		}
	}
}
namespace System.DirectoryServices.Design
{
	internal class DirectoryEntryConverter : TypeConverter
	{
		private static StandardValuesCollection values;

		private static Hashtable componentsCreated = new Hashtable(StringComparer.OrdinalIgnoreCase);

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
			if (value != null && value is string)
			{
				string text = ((string)value).Trim();
				if (text.Length == 0)
				{
					return null;
				}
				if (text.CompareTo(Res.GetString("DSNotSet")) != 0)
				{
					DirectoryEntry fromCache = GetFromCache(text);
					if (fromCache == null)
					{
						fromCache = new DirectoryEntry(text);
						componentsCreated[text] = fromCache;
						context?.Container.Add(fromCache);
						return fromCache;
					}
				}
			}
			return null;
		}

		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
		{
			if (destinationType != null && destinationType == typeof(string))
			{
				if (value != null)
				{
					return ((DirectoryEntry)value).Path;
				}
				return Res.GetString("DSNotSet");
			}
			return base.ConvertTo(context, culture, value, destinationType);
		}

		public override StandardValuesCollection GetStandardValues(ITypeDescriptorContext context)
		{
			if (values == null)
			{
				object[] array = new object[1];
				values = new StandardValuesCollection(array);
			}
			return values;
		}

		internal static DirectoryEntry GetFromCache(string path)
		{
			if (componentsCreated.ContainsKey(path))
			{
				DirectoryEntry directoryEntry = (DirectoryEntry)componentsCreated[path];
				if (directoryEntry.Site == null)
				{
					componentsCreated.Remove(path);
				}
				else
				{
					if (directoryEntry.Path == path)
					{
						return directoryEntry;
					}
					componentsCreated.Remove(path);
				}
			}
			return null;
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
namespace System.DirectoryServices.Interop
{
	internal enum AdsAuthentication
	{
		ADS_SECURE_AUTHENTICATION = 1,
		ADS_USE_ENCRYPTION = 2,
		ADS_USE_SSL = 2,
		ADS_READONLY_SERVER = 4,
		ADS_PROMPT_CREDENTIALS = 8,
		ADS_NO_AUTHENTICATION = 16,
		ADS_FAST_BIND = 32,
		ADS_USE_SIGNING = 64,
		ADS_USE_SEALING = 128
	}
	internal enum AdsOptions
	{
		ADS_OPTION_SERVERNAME,
		ADS_OPTION_REFERRALS,
		ADS_OPTION_PAGE_SIZE,
		ADS_OPTION_SECURITY_MASK,
		ADS_OPTION_MUTUAL_AUTH_STATUS,
		ADS_OPTION_QUOTA,
		ADS_OPTION_PASSWORD_PORTNUMBER,
		ADS_OPTION_PASSWORD_METHOD
	}
	internal enum AdsPropertyOperation
	{
		Clear = 1,
		Update,
		Append,
		Delete
	}
	internal struct AdsSearchColumn
	{
		public IntPtr pszAttrName;

		public int dwADsType;

		public unsafe AdsValue* pADsValues;

		public int dwNumValues;

		public IntPtr hReserved;
	}
	internal struct AdsSearchPreferenceInfo
	{
		public int dwSearchPref;

		internal int pad;

		public AdsValue vValue;

		public int dwStatus;

		internal int pad2;
	}
	internal enum AdsSearchPreferences
	{
		ASYNCHRONOUS,
		DEREF_ALIASES,
		SIZE_LIMIT,
		TIME_LIMIT,
		ATTRIBTYPES_ONLY,
		SEARCH_SCOPE,
		TIMEOUT,
		PAGESIZE,
		PAGED_TIME_LIMIT,
		CHASE_REFERRALS,
		SORT_ON,
		CACHE_RESULTS,
		DIRSYNC,
		TOMBSTONE,
		VLV,
		ATTRIBUTE_QUERY,
		SECURITY_MASK,
		DIRSYNC_FLAG,
		EXTENDED_DN
	}
	internal struct AdsSortKey
	{
		public IntPtr pszAttrType;

		public IntPtr pszReserved;

		public int fReverseOrder;
	}
	internal enum AdsStatusEnum
	{
		ADS_STATUS_S_OK,
		ADS_STATUS_INVALID_SEARCHPREF,
		ADS_STATUS_INVALID_SEARCHPREFVALUE
	}
	internal enum AdsType
	{
		ADSTYPE_INVALID,
		ADSTYPE_DN_STRING,
		ADSTYPE_CASE_EXACT_STRING,
		ADSTYPE_CASE_IGNORE_STRING,
		ADSTYPE_PRINTABLE_STRING,
		ADSTYPE_NUMERIC_STRING,
		ADSTYPE_BOOLEAN,
		ADSTYPE_INTEGER,
		ADSTYPE_OCTET_STRING,
		ADSTYPE_UTC_TIME,
		ADSTYPE_LARGE_INTEGER,
		ADSTYPE_PROV_SPECIFIC,
		ADSTYPE_OBJECT_CLASS,
		ADSTYPE_CASEIGNORE_LIST,
		ADSTYPE_OCTET_LIST,
		ADSTYPE_PATH,
		ADSTYPE_POSTALADDRESS,
		ADSTYPE_TIMESTAMP,
		ADSTYPE_BACKLINK,
		ADSTYPE_TYPEDNAME,
		ADSTYPE_HOLD,
		ADSTYPE_NETADDRESS,
		ADSTYPE_REPLICAPOINTER,
		ADSTYPE_FAXNUMBER,
		ADSTYPE_EMAIL,
		ADSTYPE_NT_SECURITY_DESCRIPTOR,
		ADSTYPE_UNKNOWN,
		ADSTYPE_DN_WITH_BINARY,
		ADSTYPE_DN_WITH_STRING
	}
	internal struct Ads_Pointer
	{
		public IntPtr value;
	}
	internal struct Ads_OctetString
	{
		public int length;

		public IntPtr value;
	}
	internal struct Ads_Generic
	{
		public int a;

		public int b;

		public int c;

		public int d;
	}
	[StructLayout(LayoutKind.Explicit)]
	internal struct AdsValue
	{
		[FieldOffset(0)]
		public int dwType;

		[FieldOffset(4)]
		internal int pad;

		[FieldOffset(8)]
		public Ads_Pointer pointer;

		[FieldOffset(8)]
		public Ads_OctetString octetString;

		[FieldOffset(8)]
		public Ads_Generic generic;
	}
	internal struct SystemTime
	{
		public ushort wYear;

		public ushort wMonth;

		public ushort wDayOfWeek;

		public ushort wDay;

		public ushort wHour;

		public ushort wMinute;

		public ushort wSecond;

		public ushort wMilliseconds;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class DnWithBinary
	{
		public int dwLength;

		public IntPtr lpBinaryValue;

		public IntPtr pszDNString;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class DnWithString
	{
		public IntPtr pszStringValue;

		public IntPtr pszDNString;
	}
	internal class AdsValueHelper
	{
		public AdsValue adsvalue;

		private GCHandle pinnedHandle;

		public long LowInt64
		{
			get
			{
				return (uint)adsvalue.generic.a + ((long)adsvalue.generic.b << 32);
			}
			set
			{
				adsvalue.generic.a = (int)(value & 0xFFFFFFFFu);
				adsvalue.generic.b = (int)(value >> 32);
			}
		}

		public AdsValueHelper(AdsValue adsvalue)
		{
			this.adsvalue = adsvalue;
		}

		public AdsValueHelper(object managedValue)
		{
			AdsType adsTypeForManagedType = GetAdsTypeForManagedType(managedValue.GetType());
			SetValue(managedValue, adsTypeForManagedType);
		}

		public AdsValueHelper(object managedValue, AdsType adsType)
		{
			SetValue(managedValue, adsType);
		}

		~AdsValueHelper()
		{
			if (pinnedHandle.IsAllocated)
			{
				pinnedHandle.Free();
			}
		}

		private AdsType GetAdsTypeForManagedType(Type type)
		{
			if (type == typeof(int))
			{
				return AdsType.ADSTYPE_INTEGER;
			}
			if (type == typeof(long))
			{
				return AdsType.ADSTYPE_LARGE_INTEGER;
			}
			if (type == typeof(bool))
			{
				return AdsType.ADSTYPE_BOOLEAN;
			}
			return AdsType.ADSTYPE_UNKNOWN;
		}

		public AdsValue GetStruct()
		{
			return adsvalue;
		}

		private static ushort LowOfInt(int i)
		{
			return (ushort)((uint)i & 0xFFFFu);
		}

		private static ushort HighOfInt(int i)
		{
			return (ushort)((uint)(i >> 16) & 0xFFFFu);
		}

		public object GetValue()
		{
			switch (adsvalue.dwType)
			{
			case 9:
			{
				SystemTime systemTime = default(SystemTime);
				systemTime.wYear = LowOfInt(adsvalue.generic.a);
				systemTime.wMonth = HighOfInt(adsvalue.generic.a);
				systemTime.wDayOfWeek = LowOfInt(adsvalue.generic.b);
				systemTime.wDay = HighOfInt(adsvalue.generic.b);
				systemTime.wHour = LowOfInt(adsvalue.generic.c);
				systemTime.wMinute = HighOfInt(adsvalue.generic.c);
				systemTime.wSecond = LowOfInt(adsvalue.generic.d);
				systemTime.wMilliseconds = HighOfInt(adsvalue.generic.d);
				return new DateTime(systemTime.wYear, systemTime.wMonth, systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);
			}
			case 27:
			{
				DnWithBinary dnWithBinary = new DnWithBinary();
				Marshal.PtrToStructure(adsvalue.pointer.value, dnWithBinary);
				byte[] array2 = new byte[dnWithBinary.dwLength];
				Marshal.Copy(dnWithBinary.lpBinaryValue, array2, 0, dnWithBinary.dwLength);
				StringBuilder stringBuilder2 = new StringBuilder();
				StringBuilder stringBuilder3 = new StringBuilder();
				for (int i = 0; i < array2.Length; i++)
				{
					string text2 = array2[i].ToString("X", CultureInfo.InvariantCulture);
					if (text2.Length == 1)
					{
						stringBuilder3.Append("0");
					}
					stringBuilder3.Append(text2);
				}
				stringBuilder2.Append("B:");
				stringBuilder2.Append(stringBuilder3.Length);
				stringBuilder2.Append(":");
				stringBuilder2.Append(stringBuilder3.ToString());
				stringBuilder2.Append(":");
				stringBuilder2.Append(Marshal.PtrToStringUni(dnWithBinary.pszDNString));
				return stringBuilder2.ToString();
			}
			case 28:
			{
				DnWithString dnWithString = new DnWithString();
				Marshal.PtrToStructure(adsvalue.pointer.value, dnWithString);
				string text = Marshal.PtrToStringUni(dnWithString.pszStringValue);
				if (text == null)
				{
					text = "";
				}
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append("S:");
				stringBuilder.Append(text.Length);
				stringBuilder.Append(":");
				stringBuilder.Append(text);
				stringBuilder.Append(":");
				stringBuilder.Append(Marshal.PtrToStringUni(dnWithString.pszDNString));
				return stringBuilder.ToString();
			}
			case 1:
			case 2:
			case 3:
			case 4:
			case 5:
			case 12:
				return Marshal.PtrToStringUni(adsvalue.pointer.value);
			case 6:
				return adsvalue.generic.a != 0;
			case 7:
				return adsvalue.generic.a;
			case 8:
			case 11:
			case 25:
			{
				int length = adsvalue.octetString.length;
				byte[] array = new byte[length];
				Marshal.Copy(adsvalue.octetString.value, array, 0, length);
				return array;
			}
			case 0:
				throw new InvalidOperationException(Res.GetString("DSConvertTypeInvalid"));
			case 10:
				return LowInt64;
			case 13:
			case 14:
			case 15:
			case 16:
			case 17:
			case 18:
			case 19:
			case 20:
			case 21:
			case 22:
			case 23:
			case 24:
			case 26:
				return new NotImplementedException(Res.GetString("DSAdsvalueTypeNYI", "0x" + Convert.ToString(adsvalue.dwType, 16)));
			default:
				return new ArgumentException(Res.GetString("DSConvertFailed", "0x" + Convert.ToString(LowInt64, 16), "0x" + Convert.ToString(adsvalue.dwType, 16)));
			}
		}

		public object GetVlvValue()
		{
			AdsVLV adsVLV = new AdsVLV();
			Marshal.PtrToStructure(adsvalue.octetString.value, adsVLV);
			byte[] array = null;
			if (adsVLV.contextID != (IntPtr)0 && adsVLV.contextIDlength != 0)
			{
				array = new byte[adsVLV.contextIDlength];
				Marshal.Copy(adsVLV.contextID, array, 0, adsVLV.contextIDlength);
			}
			DirectoryVirtualListView directoryVirtualListView = new DirectoryVirtualListView();
			directoryVirtualListView.Offset = adsVLV.offset;
			directoryVirtualListView.ApproximateTotal = adsVLV.contentCount;
			DirectoryVirtualListViewContext directoryVirtualListViewContext2 = (directoryVirtualListView.DirectoryVirtualListViewContext = new DirectoryVirtualListViewContext(array));
			return directoryVirtualListView;
		}

		private void SetValue(object managedValue, AdsType adsType)
		{
			adsvalue = default(AdsValue);
			adsvalue.dwType = (int)adsType;
			switch (adsType)
			{
			case AdsType.ADSTYPE_INTEGER:
				adsvalue.generic.a = (int)managedValue;
				adsvalue.generic.b = 0;
				break;
			case AdsType.ADSTYPE_LARGE_INTEGER:
				LowInt64 = (long)managedValue;
				break;
			case AdsType.ADSTYPE_BOOLEAN:
				if ((bool)managedValue)
				{
					LowInt64 = -1L;
				}
				else
				{
					LowInt64 = 0L;
				}
				break;
			case AdsType.ADSTYPE_CASE_IGNORE_STRING:
				pinnedHandle = GCHandle.Alloc(managedValue, GCHandleType.Pinned);
				adsvalue.pointer.value = pinnedHandle.AddrOfPinnedObject();
				break;
			case AdsType.ADSTYPE_PROV_SPECIFIC:
			{
				byte[] array = (byte[])managedValue;
				adsvalue.octetString.length = array.Length;
				pinnedHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
				adsvalue.octetString.value = pinnedHandle.AddrOfPinnedObject();
				break;
			}
			default:
				throw new NotImplementedException(Res.GetString("DSAdsvalueTypeNYI", "0x" + Convert.ToString((int)adsType, 16)));
			}
		}
	}
	[ComVisible(false)]
	internal class NativeMethods
	{
		public enum AuthenticationModes
		{
			SecureAuthentication = 1,
			UseEncryption = 2,
			UseSSL = 2,
			ReadonlyServer = 4,
			NoAuthentication = 16,
			FastBind = 32,
			UseSigning = 64,
			UseSealing = 128,
			UseDelegation = 256,
			UseServerBinding = 512
		}
	}
	[ComVisible(false)]
	[SuppressUnmanagedCodeSecurity]
	internal class SafeNativeMethods
	{
		[ComVisible(false)]
		public class EnumVariant
		{
			private static readonly object NoMoreValues = new object();

			private object currentValue = NoMoreValues;

			private IEnumVariant enumerator;

			public EnumVariant(IEnumVariant en)
			{
				if (en == null)
				{
					throw new ArgumentNullException("en");
				}
				enumerator = en;
			}

			public bool GetNext()
			{
				Advance();
				return currentValue != NoMoreValues;
			}

			public object GetValue()
			{
				if (currentValue == NoMoreValues)
				{
					throw new InvalidOperationException(Res.GetString("DSEnumerator"));
				}
				return currentValue;
			}

			public void Reset()
			{
				enumerator.Reset();
				currentValue = NoMoreValues;
			}

			private void Advance()
			{
				currentValue = NoMoreValues;
				IntPtr intPtr = Marshal.AllocCoTaskMem(16);
				try
				{
					int[] array = new int[1];
					int[] array2 = array;
					VariantInit(intPtr);
					enumerator.Next(1, intPtr, array2);
					try
					{
						if (array2[0] > 0)
						{
							currentValue = Marshal.GetObjectForNativeVariant(intPtr);
						}
					}
					finally
					{
						VariantClear(intPtr);
					}
				}
				finally
				{
					Marshal.FreeCoTaskMem(intPtr);
				}
			}
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("00020404-0000-0000-C000-000000000046")]
		public interface IEnumVariant
		{
			[SuppressUnmanagedCodeSecurity]
			void Next([In][MarshalAs(UnmanagedType.U4)] int celt, [In][Out] IntPtr rgvar, [Out][MarshalAs(UnmanagedType.LPArray)] int[] pceltFetched);

			[SuppressUnmanagedCodeSecurity]
			void Skip([In][MarshalAs(UnmanagedType.U4)] int celt);

			[SuppressUnmanagedCodeSecurity]
			void Reset();

			[SuppressUnmanagedCodeSecurity]
			void Clone([Out][MarshalAs(UnmanagedType.LPArray)] IEnumVariant[] ppenum);
		}

		public const int FORMAT_MESSAGE_ALLOCATE_BUFFER = 256;

		public const int FORMAT_MESSAGE_IGNORE_INSERTS = 512;

		public const int FORMAT_MESSAGE_FROM_STRING = 1024;

		public const int FORMAT_MESSAGE_FROM_HMODULE = 2048;

		public const int FORMAT_MESSAGE_FROM_SYSTEM = 4096;

		public const int FORMAT_MESSAGE_ARGUMENT_ARRAY = 8192;

		public const int FORMAT_MESSAGE_MAX_WIDTH_MASK = 255;

		public const int ERROR_MORE_DATA = 234;

		public const int ERROR_SUCCESS = 0;

		[DllImport("oleaut32.dll", PreserveSig = false)]
		public static extern void VariantClear(IntPtr pObject);

		[DllImport("oleaut32.dll")]
		public static extern void VariantInit(IntPtr pObject);

		[DllImport("activeds.dll")]
		public static extern bool FreeADsMem(IntPtr pVoid);

		[DllImport("activeds.dll", CharSet = CharSet.Unicode)]
		public static extern int ADsGetLastError(out int error, StringBuilder errorBuffer, int errorBufferLength, StringBuilder nameBuffer, int nameBufferLength);

		[DllImport("activeds.dll", CharSet = CharSet.Unicode)]
		public static extern int ADsSetLastError(int error, string errorString, string provider);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		public static extern int FormatMessageW(int dwFlags, int lpSource, int dwMessageId, int dwLanguageId, StringBuilder lpBuffer, int nSize, int arguments);
	}
	[StructLayout(LayoutKind.Explicit)]
	internal struct Variant
	{
		[FieldOffset(0)]
		public ushort varType;

		[FieldOffset(2)]
		public ushort reserved1;

		[FieldOffset(4)]
		public ushort reserved2;

		[FieldOffset(6)]
		public ushort reserved3;

		[FieldOffset(8)]
		public short boolvalue;

		[FieldOffset(8)]
		public IntPtr ptr1;

		[FieldOffset(12)]
		public IntPtr ptr2;
	}
	[SuppressUnmanagedCodeSecurity]
	[ComVisible(false)]
	internal class UnsafeNativeMethods
	{
		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		[Guid("FD8256D0-FD15-11CE-ABC4-02608C9E7553")]
		public interface IAds
		{
			string Name
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Class
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string GUID
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string ADsPath
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Parent
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Schema
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			[SuppressUnmanagedCodeSecurity]
			void GetInfo();

			[SuppressUnmanagedCodeSecurity]
			void SetInfo();

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Struct)]
			object Get([In][MarshalAs(UnmanagedType.BStr)] string bstrName);

			[SuppressUnmanagedCodeSecurity]
			void Put([In][MarshalAs(UnmanagedType.BStr)] string bstrName, [In][MarshalAs(UnmanagedType.Struct)] object vProp);

			[PreserveSig]
			[SuppressUnmanagedCodeSecurity]
			int GetEx([In][MarshalAs(UnmanagedType.BStr)] string bstrName, [MarshalAs(UnmanagedType.Struct)] out object value);

			[SuppressUnmanagedCodeSecurity]
			void PutEx([In][MarshalAs(UnmanagedType.U4)] int lnControlCode, [In][MarshalAs(UnmanagedType.BStr)] string bstrName, [In][MarshalAs(UnmanagedType.Struct)] object vProp);

			[SuppressUnmanagedCodeSecurity]
			void GetInfoEx([In][MarshalAs(UnmanagedType.Struct)] object vProperties, [In][MarshalAs(UnmanagedType.U4)] int lnReserved);
		}

		[ComImport]
		[Guid("001677D0-FD16-11CE-ABC4-02608C9E7553")]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		public interface IAdsContainer
		{
			int Count
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.U4)]
				get;
			}

			object _NewEnum
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Interface)]
				get;
			}

			object Filter
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[SuppressUnmanagedCodeSecurity]
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object Hints
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[SuppressUnmanagedCodeSecurity]
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Interface)]
			object GetObject([In][MarshalAs(UnmanagedType.BStr)] string className, [In][MarshalAs(UnmanagedType.BStr)] string relativeName);

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Interface)]
			object Create([In][MarshalAs(UnmanagedType.BStr)] string className, [In][MarshalAs(UnmanagedType.BStr)] string relativeName);

			[SuppressUnmanagedCodeSecurity]
			void Delete([In][MarshalAs(UnmanagedType.BStr)] string className, [In][MarshalAs(UnmanagedType.BStr)] string relativeName);

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Interface)]
			object CopyHere([In][MarshalAs(UnmanagedType.BStr)] string sourceName, [In][MarshalAs(UnmanagedType.BStr)] string newName);

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Interface)]
			object MoveHere([In][MarshalAs(UnmanagedType.BStr)] string sourceName, [In][MarshalAs(UnmanagedType.BStr)] string newName);
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		[Guid("B2BD0902-8878-11D1-8C21-00C04FD8D503")]
		public interface IAdsDeleteOps
		{
			[SuppressUnmanagedCodeSecurity]
			void DeleteObject(int flags);
		}

		[ComImport]
		[Guid("7b9e38b0-a97c-11d0-8534-00c04fd8d503")]
		public class PropertyValue
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			public extern PropertyValue();
		}

		[ComImport]
		[Guid("79FA9AD0-A97C-11D0-8534-00C04FD8D503")]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		public interface IAdsPropertyValue
		{
			int ADsType
			{
				[SuppressUnmanagedCodeSecurity]
				get;
				[SuppressUnmanagedCodeSecurity]
				set;
			}

			string DNString
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			string CaseExactString
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			string CaseIgnoreString
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			string PrintableString
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			string NumericString
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			bool Boolean { get; set; }

			int Integer { get; set; }

			object OctetString
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[SuppressUnmanagedCodeSecurity]
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object SecurityDescriptor
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object LargeInteger
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object UTCTime
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			[SuppressUnmanagedCodeSecurity]
			void Clear();
		}

		[ComImport]
		[Guid("72d3edc2-a4c4-11d0-8533-00c04fd8d503")]
		public class PropertyEntry
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			public extern PropertyEntry();
		}

		[ComImport]
		[Guid("05792C8E-941F-11D0-8529-00C04FD8D503")]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		public interface IAdsPropertyEntry
		{
			string Name
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[SuppressUnmanagedCodeSecurity]
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			int ADsType
			{
				[SuppressUnmanagedCodeSecurity]
				get;
				[SuppressUnmanagedCodeSecurity]
				set;
			}

			int ControlCode
			{
				[SuppressUnmanagedCodeSecurity]
				get;
				[SuppressUnmanagedCodeSecurity]
				set;
			}

			object Values
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[SuppressUnmanagedCodeSecurity]
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			[SuppressUnmanagedCodeSecurity]
			void Clear();
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		[Guid("C6F602B6-8F69-11D0-8528-00C04FD8D503")]
		public interface IAdsPropertyList
		{
			int PropertyCount
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.U4)]
				get;
			}

			[PreserveSig]
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.I4)]
			int Next([MarshalAs(UnmanagedType.Struct)] out object nextProp);

			void Skip([In] int cElements);

			[SuppressUnmanagedCodeSecurity]
			void Reset();

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Struct)]
			object Item([In][MarshalAs(UnmanagedType.Struct)] object varIndex);

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Struct)]
			object GetPropertyItem([In][MarshalAs(UnmanagedType.BStr)] string bstrName, int ADsType);

			[SuppressUnmanagedCodeSecurity]
			void PutPropertyItem([In][MarshalAs(UnmanagedType.Struct)] object varData);

			void ResetPropertyItem([In][MarshalAs(UnmanagedType.Struct)] object varEntry);

			void PurgePropertyList();
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("109BA8EC-92F0-11D0-A790-00C04FD8D5A8")]
		public interface IDirectorySearch
		{
			[SuppressUnmanagedCodeSecurity]
			void SetSearchPreference([In] IntPtr pSearchPrefs, int dwNumPrefs);

			[SuppressUnmanagedCodeSecurity]
			void ExecuteSearch([In][MarshalAs(UnmanagedType.LPWStr)] string pszSearchFilter, [In][MarshalAs(UnmanagedType.LPArray)] string[] pAttributeNames, [In] int dwNumberAttributes, out IntPtr hSearchResult);

			[SuppressUnmanagedCodeSecurity]
			void AbandonSearch([In] IntPtr hSearchResult);

			[PreserveSig]
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.U4)]
			int GetFirstRow([In] IntPtr hSearchResult);

			[PreserveSig]
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.U4)]
			int GetNextRow([In] IntPtr hSearchResult);

			[PreserveSig]
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.U4)]
			int GetPreviousRow([In] IntPtr hSearchResult);

			[PreserveSig]
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.U4)]
			int GetNextColumnName([In] IntPtr hSearchResult, [Out] IntPtr ppszColumnName);

			[SuppressUnmanagedCodeSecurity]
			void GetColumn([In] IntPtr hSearchResult, [In] IntPtr szColumnName, [In] IntPtr pSearchColumn);

			[SuppressUnmanagedCodeSecurity]
			void FreeColumn([In] IntPtr pSearchColumn);

			[SuppressUnmanagedCodeSecurity]
			void CloseSearchHandle([In] IntPtr hSearchResult);
		}

		[ComImport]
		[Guid("46F14FDA-232B-11D1-A808-00C04FD8D5A8")]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		public interface IAdsObjectOptions
		{
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Struct)]
			object GetOption(int flag);

			[SuppressUnmanagedCodeSecurity]
			void SetOption(int flag, [In][MarshalAs(UnmanagedType.Struct)] object varValue);
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		[Guid("46f14fda-232b-11d1-a808-00c04fd8d5a8")]
		public interface IAdsObjectOptions2
		{
			[PreserveSig]
			[SuppressUnmanagedCodeSecurity]
			int GetOption(int flag, [MarshalAs(UnmanagedType.Struct)] out object value);

			[SuppressUnmanagedCodeSecurity]
			void SetOption(int option, Variant value);
		}

		internal const int S_ADS_NOMORE_ROWS = 20498;

		internal const int INVALID_FILTER = -2147016642;

		internal const int SIZE_LIMIT_EXCEEDED = -2147016669;

		[DllImport("activeds.dll", CharSet = CharSet.Unicode, EntryPoint = "ADsOpenObject", ExactSpelling = true)]
		private static extern int IntADsOpenObject(string path, string userName, string password, int flags, [In][Out] ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out object ppObject);

		public static int ADsOpenObject(string path, string userName, string password, int flags, [In][Out] ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out object ppObject)
		{
			try
			{
				return IntADsOpenObject(path, userName, password, flags, ref iid, out ppObject);
			}
			catch (EntryPointNotFoundException)
			{
				throw new InvalidOperationException(Res.GetString("DSAdsiNotInstalled"));
			}
		}
	}
}
namespace System.DirectoryServices.ActiveDirectory
{
	public abstract class ActiveDirectoryPartition : IDisposable
	{
		private bool disposed;

		internal string partitionName;

		internal DirectoryContext context;

		internal DirectoryEntryManager directoryEntryMgr;

		public string Name
		{
			get
			{
				CheckIfDisposed();
				return partitionName;
			}
		}

		protected ActiveDirectoryPartition()
		{
		}

		internal ActiveDirectoryPartition(DirectoryContext context, string name)
		{
			this.context = context;
			partitionName = name;
		}

		public void Dispose()
		{
			Dispose(disposing: true);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			if (disposing)
			{
				foreach (DirectoryEntry cachedDirectoryEntry in directoryEntryMgr.GetCachedDirectoryEntries())
				{
					cachedDirectoryEntry.Dispose();
				}
			}
			disposed = true;
		}

		public override string ToString()
		{
			return Name;
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract DirectoryEntry GetDirectoryEntry();

		internal void CheckIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}
	}
	public class ActiveDirectoryReplicationMetadata : DictionaryBase
	{
		private DirectoryServer server;

		private Hashtable nameTable;

		private AttributeMetadataCollection dataValueCollection = new AttributeMetadataCollection();

		private ReadOnlyStringCollection dataNameCollection = new ReadOnlyStringCollection();

		public AttributeMetadata this[string name]
		{
			get
			{
				string text = name.ToLower(CultureInfo.InvariantCulture);
				if (Contains(text))
				{
					return (AttributeMetadata)base.InnerHashtable[text];
				}
				return null;
			}
		}

		public ReadOnlyStringCollection AttributeNames => dataNameCollection;

		public AttributeMetadataCollection Values => dataValueCollection;

		internal ActiveDirectoryReplicationMetadata(DirectoryServer server)
		{
			this.server = server;
			Hashtable table = new Hashtable();
			nameTable = Hashtable.Synchronized(table);
		}

		public bool Contains(string attributeName)
		{
			string key = attributeName.ToLower(CultureInfo.InvariantCulture);
			return base.Dictionary.Contains(key);
		}

		public void CopyTo(AttributeMetadata[] array, int index)
		{
			base.Dictionary.Values.CopyTo(array, index);
		}

		private void Add(string name, AttributeMetadata value)
		{
			base.Dictionary.Add(name.ToLower(CultureInfo.InvariantCulture), value);
			dataNameCollection.Add(name);
			dataValueCollection.Add(value);
		}

		internal void AddHelper(int count, IntPtr info, bool advanced)
		{
			IntPtr intPtr = (IntPtr)0;
			for (int i = 0; i < count; i++)
			{
				if (advanced)
				{
					intPtr = Utils.AddToIntPtr(info, Marshal.SizeOf(typeof(int)) * 2 + i * Marshal.SizeOf(typeof(DS_REPL_ATTR_META_DATA_2)));
					AttributeMetadata attributeMetadata = new AttributeMetadata(intPtr, advanced: true, server, nameTable);
					Add(attributeMetadata.Name, attributeMetadata);
				}
				else
				{
					intPtr = Utils.AddToIntPtr(info, Marshal.SizeOf(typeof(int)) * 2 + i * Marshal.SizeOf(typeof(DS_REPL_ATTR_META_DATA)));
					AttributeMetadata attributeMetadata2 = new AttributeMetadata(intPtr, advanced: false, server, nameTable);
					Add(attributeMetadata2.Name, attributeMetadata2);
				}
			}
		}
	}
	public enum HourOfDay
	{
		Zero,
		One,
		Two,
		Three,
		Four,
		Five,
		Six,
		Seven,
		Eight,
		Nine,
		Ten,
		Eleven,
		Twelve,
		Thirteen,
		Fourteen,
		Fifteen,
		Sixteen,
		Seventeen,
		Eighteen,
		Nineteen,
		Twenty,
		TwentyOne,
		TwentyTwo,
		TwentyThree
	}
	public enum MinuteOfHour
	{
		Zero = 0,
		Fifteen = 15,
		Thirty = 30,
		FortyFive = 45
	}
	public class ActiveDirectorySchedule
	{
		private bool[] scheduleArray = new bool[672];

		private long utcOffSet;

		public bool[,,] RawSchedule
		{
			get
			{
				bool[,,] array = new bool[7, 24, 4];
				for (int i = 0; i < 7; i++)
				{
					for (int j = 0; j < 24; j++)
					{
						for (int k = 0; k < 4; k++)
						{
							array[i, j, k] = scheduleArray[i * 24 * 4 + j * 4 + k];
						}
					}
				}
				return array;
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				ValidateRawArray(value);
				for (int i = 0; i < 7; i++)
				{
					for (int j = 0; j < 24; j++)
					{
						for (int k = 0; k < 4; k++)
						{
							scheduleArray[i * 24 * 4 + j * 4 + k] = value[i, j, k];
						}
					}
				}
			}
		}

		public ActiveDirectorySchedule()
		{
			utcOffSet = TimeZone.CurrentTimeZone.GetUtcOffset(DateTime.Now).Ticks / 36000000000L;
		}

		public ActiveDirectorySchedule(ActiveDirectorySchedule schedule)
			: this()
		{
			if (schedule == null)
			{
				throw new ArgumentNullException();
			}
			bool[] array = schedule.scheduleArray;
			for (int i = 0; i < 672; i++)
			{
				scheduleArray[i] = array[i];
			}
		}

		internal ActiveDirectorySchedule(bool[] schedule)
			: this()
		{
			for (int i = 0; i < 672; i++)
			{
				scheduleArray[i] = schedule[i];
			}
		}

		public void SetSchedule(DayOfWeek day, HourOfDay fromHour, MinuteOfHour fromMinute, HourOfDay toHour, MinuteOfHour toMinute)
		{
			if (day < DayOfWeek.Sunday || day > DayOfWeek.Saturday)
			{
				throw new InvalidEnumArgumentException("day", (int)day, typeof(DayOfWeek));
			}
			if (fromHour < HourOfDay.Zero || fromHour > HourOfDay.TwentyThree)
			{
				throw new InvalidEnumArgumentException("fromHour", (int)fromHour, typeof(HourOfDay));
			}
			if (fromMinute != 0 && fromMinute != MinuteOfHour.Fifteen && fromMinute != MinuteOfHour.Thirty && fromMinute != MinuteOfHour.FortyFive)
			{
				throw new InvalidEnumArgumentException("fromMinute", (int)fromMinute, typeof(MinuteOfHour));
			}
			if (toHour < HourOfDay.Zero || toHour > HourOfDay.TwentyThree)
			{
				throw new InvalidEnumArgumentException("toHour", (int)toHour, typeof(HourOfDay));
			}
			if (toMinute != 0 && toMinute != MinuteOfHour.Fifteen && toMinute != MinuteOfHour.Thirty && toMinute != MinuteOfHour.FortyFive)
			{
				throw new InvalidEnumArgumentException("toMinute", (int)toMinute, typeof(MinuteOfHour));
			}
			if ((int)fromHour * 60 + fromMinute > (int)toHour * 60 + toMinute)
			{
				throw new ArgumentException(Res.GetString("InvalidTime"));
			}
			int num = (int)day * 24 * 4 + (int)fromHour * 4 + (int)fromMinute / 15;
			int num2 = (int)day * 24 * 4 + (int)toHour * 4 + (int)toMinute / 15;
			for (int i = num; i <= num2; i++)
			{
				scheduleArray[i] = true;
			}
		}

		public void SetSchedule(DayOfWeek[] days, HourOfDay fromHour, MinuteOfHour fromMinute, HourOfDay toHour, MinuteOfHour toMinute)
		{
			if (days == null)
			{
				throw new ArgumentNullException("days");
			}
			for (int i = 0; i < days.Length; i++)
			{
				if (days[i] < DayOfWeek.Sunday || days[i] > DayOfWeek.Saturday)
				{
					throw new InvalidEnumArgumentException("days", (int)days[i], typeof(DayOfWeek));
				}
			}
			for (int j = 0; j < days.Length; j++)
			{
				SetSchedule(days[j], fromHour, fromMinute, toHour, toMinute);
			}
		}

		public void SetDailySchedule(HourOfDay fromHour, MinuteOfHour fromMinute, HourOfDay toHour, MinuteOfHour toMinute)
		{
			for (int i = 0; i < 7; i++)
			{
				SetSchedule((DayOfWeek)i, fromHour, fromMinute, toHour, toMinute);
			}
		}

		public void ResetSchedule()
		{
			for (int i = 0; i < 672; i++)
			{
				scheduleArray[i] = false;
			}
		}

		private void ValidateRawArray(bool[,,] array)
		{
			if (array.Length != 672)
			{
				throw new ArgumentException("value");
			}
			int length = array.GetLength(0);
			int length2 = array.GetLength(1);
			int length3 = array.GetLength(2);
			if (length != 7 || length2 != 24 || length3 != 4)
			{
				throw new ArgumentException("value");
			}
		}

		internal byte[] GetUnmanagedSchedule()
		{
			byte b = 0;
			int num = 0;
			byte[] array = new byte[188];
			int num2 = 0;
			array[0] = 188;
			array[8] = 1;
			array[16] = 20;
			for (int i = 20; i < 188; i++)
			{
				b = 0;
				num = (i - 20) * 4;
				if (scheduleArray[num])
				{
					b = (byte)(b | 1u);
				}
				if (scheduleArray[num + 1])
				{
					b = (byte)(b | 2u);
				}
				if (scheduleArray[num + 2])
				{
					b = (byte)(b | 4u);
				}
				if (scheduleArray[num + 3])
				{
					b = (byte)(b | 8u);
				}
				num2 = i - (int)utcOffSet;
				if (num2 >= 188)
				{
					num2 = num2 - 188 + 20;
				}
				else if (num2 < 20)
				{
					num2 = 188 - (20 - num2);
				}
				array[num2] = b;
			}
			return array;
		}

		internal void SetUnmanagedSchedule(byte[] unmanagedSchedule)
		{
			int num = 0;
			int num2 = 0;
			int num3 = 0;
			for (int i = 20; i < 188; i++)
			{
				num = 0;
				num2 = (i - 20) * 4;
				num3 = i - (int)utcOffSet;
				if (num3 >= 188)
				{
					num3 = num3 - 188 + 20;
				}
				else if (num3 < 20)
				{
					num3 = 188 - (20 - num3);
				}
				num = unmanagedSchedule[num3];
				if (((uint)num & (true ? 1u : 0u)) != 0)
				{
					scheduleArray[num2] = true;
				}
				if (((uint)num & 2u) != 0)
				{
					scheduleArray[num2 + 1] = true;
				}
				if (((uint)num & 4u) != 0)
				{
					scheduleArray[num2 + 2] = true;
				}
				if (((uint)num & 8u) != 0)
				{
					scheduleArray[num2 + 3] = true;
				}
			}
		}
	}
	public enum SchemaClassType
	{
		Type88,
		Structural,
		Abstract,
		Auxiliary
	}
	[Flags]
	public enum PropertyTypes
	{
		Indexed = 2,
		InGlobalCatalog = 4
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectorySchema : ActiveDirectoryPartition
	{
		private bool disposed;

		private DirectoryEntry schemaEntry;

		private DirectoryEntry abstractSchemaEntry;

		private DirectoryServer cachedSchemaRoleOwner;

		public DirectoryServer SchemaRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedSchemaRoleOwner == null)
				{
					cachedSchemaRoleOwner = GetSchemaRoleOwner();
				}
				return cachedSchemaRoleOwner;
			}
		}

		internal ActiveDirectorySchema(DirectoryContext context, string distinguishedName)
			: base(context, distinguishedName)
		{
			directoryEntryMgr = new DirectoryEntryManager(context);
			schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, distinguishedName);
		}

		internal ActiveDirectorySchema(DirectoryContext context, string distinguishedName, DirectoryEntryManager directoryEntryMgr)
			: base(context, distinguishedName)
		{
			base.directoryEntryMgr = directoryEntryMgr;
			schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, distinguishedName);
		}

		protected override void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			try
			{
				if (disposing)
				{
					if (schemaEntry != null)
					{
						schemaEntry.Dispose();
						schemaEntry = null;
					}
					if (abstractSchemaEntry != null)
					{
						abstractSchemaEntry.Dispose();
						abstractSchemaEntry = null;
					}
				}
				disposed = true;
			}
			finally
			{
				Dispose();
			}
		}

		public static ActiveDirectorySchema GetSchema(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest && context.ContextType != DirectoryContextType.ConfigurationSet && context.ContextType != DirectoryContextType.DirectoryServer)
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ContextNotAssociatedWithDomain"), typeof(ActiveDirectorySchema), null);
			}
			if (context.Name != null && !context.isRootDomain() && !context.isADAMConfigSet() && !context.isServer())
			{
				if (context.ContextType == DirectoryContextType.Forest)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestNotFound"), typeof(ActiveDirectorySchema), context.Name);
				}
				if (context.ContextType == DirectoryContextType.ConfigurationSet)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ConfigSetNotFound"), typeof(ActiveDirectorySchema), context.Name);
				}
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ServerNotFound", context.Name), typeof(ActiveDirectorySchema), null);
			}
			context = new DirectoryContext(context);
			DirectoryEntryManager directoryEntryManager = new DirectoryEntryManager(context);
			string text = null;
			try
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (context.isServer() && !Utils.CheckCapability(cachedDirectoryEntry, Capability.ActiveDirectoryOrADAM))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ServerNotFound", context.Name), typeof(ActiveDirectorySchema), null);
				}
				text = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.SchemaNamingContext);
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					if (context.ContextType == DirectoryContextType.Forest)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestNotFound"), typeof(ActiveDirectorySchema), context.Name);
					}
					if (context.ContextType == DirectoryContextType.ConfigurationSet)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ConfigSetNotFound"), typeof(ActiveDirectorySchema), context.Name);
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ServerNotFound", context.Name), typeof(ActiveDirectorySchema), null);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				if (context.ContextType == DirectoryContextType.ConfigurationSet)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ConfigSetNotFound"), typeof(ActiveDirectorySchema), context.Name);
				}
				throw;
			}
			return new ActiveDirectorySchema(context, text, directoryEntryManager);
		}

		public void RefreshSchema()
		{
			CheckIfDisposed();
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				directoryEntry.Properties[PropertyManager.SchemaUpdateNow].Value = 1;
				directoryEntry.CommitChanges();
				if (abstractSchemaEntry == null)
				{
					abstractSchemaEntry = directoryEntryMgr.GetCachedDirectoryEntry("Schema");
				}
				abstractSchemaEntry.RefreshCache();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
		}

		public ActiveDirectorySchemaClass FindClass(string ldapDisplayName)
		{
			CheckIfDisposed();
			return ActiveDirectorySchemaClass.FindByName(context, ldapDisplayName);
		}

		public ActiveDirectorySchemaClass FindDefunctClass(string commonName)
		{
			CheckIfDisposed();
			if (commonName == null)
			{
				throw new ArgumentNullException("commonName");
			}
			if (commonName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "commonName");
			}
			Hashtable propertiesFromSchemaContainer = ActiveDirectorySchemaClass.GetPropertiesFromSchemaContainer(context, schemaEntry, commonName, isDefunctOnServer: true);
			return new ActiveDirectorySchemaClass(context, commonName, propertiesFromSchemaContainer, schemaEntry);
		}

		public ReadOnlyActiveDirectorySchemaClassCollection FindAllClasses()
		{
			CheckIfDisposed();
			string filter = "(&(" + PropertyManager.ObjectCategory + "=classSchema)(!(" + PropertyManager.IsDefunct + "=TRUE)))";
			return GetAllClasses(context, schemaEntry, filter);
		}

		public ReadOnlyActiveDirectorySchemaClassCollection FindAllClasses(SchemaClassType type)
		{
			CheckIfDisposed();
			if (type < SchemaClassType.Type88 || type > SchemaClassType.Auxiliary)
			{
				throw new InvalidEnumArgumentException("type", (int)type, typeof(SchemaClassType));
			}
			string filter = "(&(" + PropertyManager.ObjectCategory + "=classSchema)(" + PropertyManager.ObjectClassCategory + "=" + (int)type + ")(!(" + PropertyManager.IsDefunct + "=TRUE)))";
			return GetAllClasses(context, schemaEntry, filter);
		}

		public ReadOnlyActiveDirectorySchemaClassCollection FindAllDefunctClasses()
		{
			CheckIfDisposed();
			string filter = "(&(" + PropertyManager.ObjectCategory + "=classSchema)(" + PropertyManager.IsDefunct + "=TRUE))";
			return GetAllClasses(context, schemaEntry, filter);
		}

		public ActiveDirectorySchemaProperty FindProperty(string ldapDisplayName)
		{
			CheckIfDisposed();
			return ActiveDirectorySchemaProperty.FindByName(context, ldapDisplayName);
		}

		public ActiveDirectorySchemaProperty FindDefunctProperty(string commonName)
		{
			CheckIfDisposed();
			if (commonName == null)
			{
				throw new ArgumentNullException("commonName");
			}
			if (commonName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "commonName");
			}
			SearchResult propertiesFromSchemaContainer = ActiveDirectorySchemaProperty.GetPropertiesFromSchemaContainer(context, schemaEntry, commonName, isDefunctOnServer: true);
			return new ActiveDirectorySchemaProperty(context, commonName, propertiesFromSchemaContainer, schemaEntry);
		}

		public ReadOnlyActiveDirectorySchemaPropertyCollection FindAllProperties()
		{
			CheckIfDisposed();
			string filter = "(&(" + PropertyManager.ObjectCategory + "=attributeSchema)(!(" + PropertyManager.IsDefunct + "=TRUE)))";
			return GetAllProperties(context, schemaEntry, filter);
		}

		public ReadOnlyActiveDirectorySchemaPropertyCollection FindAllProperties(PropertyTypes type)
		{
			CheckIfDisposed();
			if (((uint)type & 0xFFFFFFF9u) != 0)
			{
				throw new ArgumentException(Res.GetString("InvalidFlags"), "type");
			}
			StringBuilder stringBuilder = new StringBuilder(25);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=attributeSchema)");
			stringBuilder.Append("(!(");
			stringBuilder.Append(PropertyManager.IsDefunct);
			stringBuilder.Append("=TRUE))");
			if ((type & PropertyTypes.Indexed) != 0)
			{
				stringBuilder.Append("(");
				stringBuilder.Append(PropertyManager.SearchFlags);
				stringBuilder.Append(":1.2.840.113556.1.4.804:=");
				stringBuilder.Append(1);
				stringBuilder.Append(")");
			}
			if ((type & PropertyTypes.InGlobalCatalog) != 0)
			{
				stringBuilder.Append("(");
				stringBuilder.Append(PropertyManager.IsMemberOfPartialAttributeSet);
				stringBuilder.Append("=TRUE)");
			}
			stringBuilder.Append(")");
			return GetAllProperties(context, schemaEntry, stringBuilder.ToString());
		}

		public ReadOnlyActiveDirectorySchemaPropertyCollection FindAllDefunctProperties()
		{
			CheckIfDisposed();
			string filter = "(&(" + PropertyManager.ObjectCategory + "=attributeSchema)(" + PropertyManager.IsDefunct + "=TRUE))";
			return GetAllProperties(context, schemaEntry, filter);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override DirectoryEntry GetDirectoryEntry()
		{
			CheckIfDisposed();
			return DirectoryEntryManager.GetDirectoryEntry(context, base.Name);
		}

		public static ActiveDirectorySchema GetCurrentSchema()
		{
			return GetSchema(new DirectoryContext(DirectoryContextType.Forest));
		}

		internal static ReadOnlyActiveDirectorySchemaPropertyCollection GetAllProperties(DirectoryContext context, DirectoryEntry schemaEntry, string filter)
		{
			ArrayList arrayList = new ArrayList();
			ADSearcher aDSearcher = new ADSearcher(schemaEntry, filter, new string[3]
			{
				PropertyManager.LdapDisplayName,
				PropertyManager.Cn,
				PropertyManager.IsDefunct
			}, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
				foreach (SearchResult item in searchResultCollection)
				{
					string ldapDisplayName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.LdapDisplayName);
					DirectoryEntry directoryEntry = item.GetDirectoryEntry();
					directoryEntry.AuthenticationType = Utils.DefaultAuthType;
					directoryEntry.Username = context.UserName;
					directoryEntry.Password = context.Password;
					bool flag = false;
					if (item.Properties[PropertyManager.IsDefunct] != null && item.Properties[PropertyManager.IsDefunct].Count > 0)
					{
						flag = (bool)item.Properties[PropertyManager.IsDefunct][0];
					}
					if (flag)
					{
						string commonName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn);
						arrayList.Add(new ActiveDirectorySchemaProperty(context, commonName, ldapDisplayName, directoryEntry, schemaEntry));
					}
					else
					{
						arrayList.Add(new ActiveDirectorySchemaProperty(context, ldapDisplayName, directoryEntry, schemaEntry));
					}
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
			}
			return new ReadOnlyActiveDirectorySchemaPropertyCollection(arrayList);
		}

		internal static ReadOnlyActiveDirectorySchemaClassCollection GetAllClasses(DirectoryContext context, DirectoryEntry schemaEntry, string filter)
		{
			ArrayList arrayList = new ArrayList();
			ADSearcher aDSearcher = new ADSearcher(schemaEntry, filter, new string[3]
			{
				PropertyManager.LdapDisplayName,
				PropertyManager.Cn,
				PropertyManager.IsDefunct
			}, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
				foreach (SearchResult item in searchResultCollection)
				{
					string ldapDisplayName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.LdapDisplayName);
					DirectoryEntry directoryEntry = item.GetDirectoryEntry();
					directoryEntry.AuthenticationType = Utils.DefaultAuthType;
					directoryEntry.Username = context.UserName;
					directoryEntry.Password = context.Password;
					bool flag = false;
					if (item.Properties[PropertyManager.IsDefunct] != null && item.Properties[PropertyManager.IsDefunct].Count > 0)
					{
						flag = (bool)item.Properties[PropertyManager.IsDefunct][0];
					}
					if (flag)
					{
						string commonName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn);
						arrayList.Add(new ActiveDirectorySchemaClass(context, commonName, ldapDisplayName, directoryEntry, schemaEntry));
					}
					else
					{
						arrayList.Add(new ActiveDirectorySchemaClass(context, ldapDisplayName, directoryEntry, schemaEntry));
					}
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
			}
			return new ReadOnlyActiveDirectorySchemaClassCollection(arrayList);
		}

		private DirectoryServer GetSchemaRoleOwner()
		{
			try
			{
				schemaEntry.RefreshCache();
				if (context.isADAMConfigSet())
				{
					string adamDnsHostNameFromNTDSA = Utils.GetAdamDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, schemaEntry, PropertyManager.FsmoRoleOwner));
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(adamDnsHostNameFromNTDSA, DirectoryContextType.DirectoryServer, context);
					return new AdamInstance(newDirectoryContext, adamDnsHostNameFromNTDSA);
				}
				DirectoryServer directoryServer = null;
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (Utils.CheckCapability(cachedDirectoryEntry, Capability.ActiveDirectory))
				{
					string dnsHostNameFromNTDSA = Utils.GetDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, schemaEntry, PropertyManager.FsmoRoleOwner));
					DirectoryContext newDirectoryContext2 = Utils.GetNewDirectoryContext(dnsHostNameFromNTDSA, DirectoryContextType.DirectoryServer, context);
					return new DomainController(newDirectoryContext2, dnsHostNameFromNTDSA);
				}
				string adamDnsHostNameFromNTDSA2 = Utils.GetAdamDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, schemaEntry, PropertyManager.FsmoRoleOwner));
				DirectoryContext newDirectoryContext3 = Utils.GetNewDirectoryContext(adamDnsHostNameFromNTDSA2, DirectoryContextType.DirectoryServer, context);
				return new AdamInstance(newDirectoryContext3, adamDnsHostNameFromNTDSA2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectorySchemaClass : IDisposable
	{
		private DirectoryEntry classEntry;

		private DirectoryEntry schemaEntry;

		private DirectoryEntry abstractClassEntry;

		private NativeComInterfaces.IAdsClass iadsClass;

		private DirectoryContext context;

		internal bool isBound;

		private bool disposed;

		private ActiveDirectorySchema schema;

		private bool propertiesFromSchemaContainerInitialized;

		private bool isDefunctOnServer;

		private Hashtable propertyValuesFromServer;

		private string ldapDisplayName;

		private string commonName;

		private string oid;

		private string description;

		private bool descriptionInitialized;

		private bool isDefunct;

		private ActiveDirectorySchemaClassCollection possibleSuperiors;

		private ActiveDirectorySchemaClassCollection auxiliaryClasses;

		private ReadOnlyActiveDirectorySchemaClassCollection possibleInferiors;

		private ActiveDirectorySchemaPropertyCollection mandatoryProperties;

		private ActiveDirectorySchemaPropertyCollection optionalProperties;

		private ActiveDirectorySchemaClass subClassOf;

		private SchemaClassType type = SchemaClassType.Structural;

		private bool typeInitialized;

		private byte[] schemaGuidBinaryForm;

		private string defaultSDSddlForm;

		private bool defaultSDSddlFormInitialized;

		public string Name
		{
			get
			{
				CheckIfDisposed();
				return ldapDisplayName;
			}
		}

		public string CommonName
		{
			get
			{
				CheckIfDisposed();
				if (isBound && commonName == null)
				{
					commonName = (string)GetValueFromCache(PropertyManager.Cn, mustExist: true);
				}
				return commonName;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.Cn, value);
				}
				commonName = value;
			}
		}

		public string Oid
		{
			get
			{
				CheckIfDisposed();
				if (isBound && oid == null)
				{
					if (!isDefunctOnServer)
					{
						try
						{
							oid = iadsClass.OID;
						}
						catch (COMException e)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(context, e);
						}
					}
					else
					{
						oid = (string)GetValueFromCache(PropertyManager.GovernsID, mustExist: true);
					}
				}
				return oid;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.GovernsID, value);
				}
				oid = value;
			}
		}

		public string Description
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !descriptionInitialized)
				{
					description = (string)GetValueFromCache(PropertyManager.Description, mustExist: false);
					descriptionInitialized = true;
				}
				return description;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.Description, value);
				}
				description = value;
			}
		}

		public bool IsDefunct
		{
			get
			{
				CheckIfDisposed();
				return isDefunct;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.IsDefunct, value);
				}
				isDefunct = value;
			}
		}

		public ActiveDirectorySchemaClassCollection PossibleSuperiors
		{
			get
			{
				CheckIfDisposed();
				if (possibleSuperiors == null)
				{
					if (isBound)
					{
						if (!isDefunctOnServer)
						{
							ArrayList arrayList = new ArrayList();
							bool flag = false;
							object obj = null;
							try
							{
								obj = iadsClass.PossibleSuperiors;
							}
							catch (COMException ex)
							{
								if (ex.ErrorCode != -2147463155)
								{
									throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
								}
								flag = true;
							}
							if (!flag)
							{
								if (obj is ICollection)
								{
									arrayList.AddRange((ICollection)obj);
								}
								else
								{
									arrayList.Add((string)obj);
								}
								possibleSuperiors = new ActiveDirectorySchemaClassCollection(context, this, isBound: true, PropertyManager.PossibleSuperiors, arrayList, onlyNames: true);
							}
							else
							{
								possibleSuperiors = new ActiveDirectorySchemaClassCollection(context, this, isBound: true, PropertyManager.PossibleSuperiors, new ArrayList());
							}
						}
						else
						{
							ArrayList arrayList2 = new ArrayList();
							arrayList2.AddRange(GetValuesFromCache(PropertyManager.PossibleSuperiors));
							arrayList2.AddRange(GetValuesFromCache(PropertyManager.SystemPossibleSuperiors));
							possibleSuperiors = new ActiveDirectorySchemaClassCollection(context, this, isBound: true, PropertyManager.PossibleSuperiors, GetClasses(arrayList2));
						}
					}
					else
					{
						possibleSuperiors = new ActiveDirectorySchemaClassCollection(context, this, isBound: false, PropertyManager.PossibleSuperiors, new ArrayList());
					}
				}
				return possibleSuperiors;
			}
		}

		public ReadOnlyActiveDirectorySchemaClassCollection PossibleInferiors
		{
			get
			{
				CheckIfDisposed();
				if (possibleInferiors == null)
				{
					if (isBound)
					{
						possibleInferiors = new ReadOnlyActiveDirectorySchemaClassCollection(GetClasses(GetValuesFromCache(PropertyManager.PossibleInferiors)));
					}
					else
					{
						possibleInferiors = new ReadOnlyActiveDirectorySchemaClassCollection(new ArrayList());
					}
				}
				return possibleInferiors;
			}
		}

		public ActiveDirectorySchemaPropertyCollection MandatoryProperties
		{
			get
			{
				CheckIfDisposed();
				if (mandatoryProperties == null)
				{
					if (isBound)
					{
						if (!isDefunctOnServer)
						{
							ArrayList arrayList = new ArrayList();
							bool flag = false;
							object obj = null;
							try
							{
								obj = iadsClass.MandatoryProperties;
							}
							catch (COMException ex)
							{
								if (ex.ErrorCode != -2147463155)
								{
									throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
								}
								flag = true;
							}
							if (!flag)
							{
								if (obj is ICollection)
								{
									arrayList.AddRange((ICollection)obj);
								}
								else
								{
									arrayList.Add((string)obj);
								}
								mandatoryProperties = new ActiveDirectorySchemaPropertyCollection(context, this, isBound: true, PropertyManager.MustContain, arrayList, onlyNames: true);
							}
							else
							{
								mandatoryProperties = new ActiveDirectorySchemaPropertyCollection(context, this, isBound: true, PropertyManager.MustContain, new ArrayList());
							}
						}
						else
						{
							mandatoryProperties = new ActiveDirectorySchemaPropertyCollection(properties: GetProperties(GetPropertyValuesRecursively(new string[2]
							{
								PropertyManager.SystemMustContain,
								PropertyManager.MustContain
							})), context: context, schemaClass: this, isBound: true, propertyName: PropertyManager.MustContain);
						}
					}
					else
					{
						mandatoryProperties = new ActiveDirectorySchemaPropertyCollection(context, this, isBound: false, PropertyManager.MustContain, new ArrayList());
					}
				}
				return mandatoryProperties;
			}
		}

		public ActiveDirectorySchemaPropertyCollection OptionalProperties
		{
			get
			{
				CheckIfDisposed();
				if (optionalProperties == null)
				{
					if (isBound)
					{
						if (!isDefunctOnServer)
						{
							ArrayList arrayList = new ArrayList();
							bool flag = false;
							object obj = null;
							try
							{
								obj = iadsClass.OptionalProperties;
							}
							catch (COMException ex)
							{
								if (ex.ErrorCode != -2147463155)
								{
									throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
								}
								flag = true;
							}
							if (!flag)
							{
								if (obj is ICollection)
								{
									arrayList.AddRange((ICollection)obj);
								}
								else
								{
									arrayList.Add((string)obj);
								}
								optionalProperties = new ActiveDirectorySchemaPropertyCollection(context, this, isBound: true, PropertyManager.MayContain, arrayList, onlyNames: true);
							}
							else
							{
								optionalProperties = new ActiveDirectorySchemaPropertyCollection(context, this, isBound: true, PropertyManager.MayContain, new ArrayList());
							}
						}
						else
						{
							string[] propertyNames = new string[2]
							{
								PropertyManager.SystemMayContain,
								PropertyManager.MayContain
							};
							ArrayList arrayList2 = new ArrayList();
							foreach (string item in GetPropertyValuesRecursively(propertyNames))
							{
								if (!MandatoryProperties.Contains(item))
								{
									arrayList2.Add(item);
								}
							}
							optionalProperties = new ActiveDirectorySchemaPropertyCollection(context, this, isBound: true, PropertyManager.MayContain, GetProperties(arrayList2));
						}
					}
					else
					{
						optionalProperties = new ActiveDirectorySchemaPropertyCollection(context, this, isBound: false, PropertyManager.MayContain, new ArrayList());
					}
				}
				return optionalProperties;
			}
		}

		public ActiveDirectorySchemaClassCollection AuxiliaryClasses
		{
			get
			{
				CheckIfDisposed();
				if (auxiliaryClasses == null)
				{
					if (isBound)
					{
						if (!isDefunctOnServer)
						{
							ArrayList arrayList = new ArrayList();
							bool flag = false;
							object obj = null;
							try
							{
								obj = iadsClass.AuxDerivedFrom;
							}
							catch (COMException ex)
							{
								if (ex.ErrorCode != -2147463155)
								{
									throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
								}
								flag = true;
							}
							if (!flag)
							{
								if (obj is ICollection)
								{
									arrayList.AddRange((ICollection)obj);
								}
								else
								{
									arrayList.Add((string)obj);
								}
								auxiliaryClasses = new ActiveDirectorySchemaClassCollection(context, this, isBound: true, PropertyManager.AuxiliaryClass, arrayList, onlyNames: true);
							}
							else
							{
								auxiliaryClasses = new ActiveDirectorySchemaClassCollection(context, this, isBound: true, PropertyManager.AuxiliaryClass, new ArrayList());
							}
						}
						else
						{
							auxiliaryClasses = new ActiveDirectorySchemaClassCollection(classes: GetClasses(GetPropertyValuesRecursively(new string[2]
							{
								PropertyManager.AuxiliaryClass,
								PropertyManager.SystemAuxiliaryClass
							})), context: context, schemaClass: this, isBound: true, propertyName: PropertyManager.AuxiliaryClass);
						}
					}
					else
					{
						auxiliaryClasses = new ActiveDirectorySchemaClassCollection(context, this, isBound: false, PropertyManager.AuxiliaryClass, new ArrayList());
					}
				}
				return auxiliaryClasses;
			}
		}

		public ActiveDirectorySchemaClass SubClassOf
		{
			get
			{
				CheckIfDisposed();
				if (isBound && subClassOf == null)
				{
					subClassOf = new ActiveDirectorySchemaClass(context, (string)GetValueFromCache(PropertyManager.SubClassOf, mustExist: true), (DirectoryEntry)null, schemaEntry);
				}
				return subClassOf;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.SubClassOf, value);
				}
				subClassOf = value;
			}
		}

		public SchemaClassType Type
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !typeInitialized)
				{
					type = (SchemaClassType)(int)GetValueFromCache(PropertyManager.ObjectClassCategory, mustExist: true);
					typeInitialized = true;
				}
				return type;
			}
			set
			{
				CheckIfDisposed();
				if (value < SchemaClassType.Type88 || value > SchemaClassType.Auxiliary)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(SchemaClassType));
				}
				if (isBound)
				{
					SetProperty(PropertyManager.ObjectClassCategory, value);
				}
				type = value;
			}
		}

		public Guid SchemaGuid
		{
			get
			{
				CheckIfDisposed();
				_ = Guid.Empty;
				if (isBound && schemaGuidBinaryForm == null)
				{
					schemaGuidBinaryForm = (byte[])GetValueFromCache(PropertyManager.SchemaIDGuid, mustExist: true);
				}
				return new Guid(schemaGuidBinaryForm);
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.SchemaIDGuid, value.Equals(Guid.Empty) ? null : value.ToByteArray());
				}
				schemaGuidBinaryForm = (value.Equals(Guid.Empty) ? null : value.ToByteArray());
			}
		}

		public ActiveDirectorySecurity DefaultObjectSecurityDescriptor
		{
			get
			{
				CheckIfDisposed();
				ActiveDirectorySecurity activeDirectorySecurity = null;
				if (isBound && !defaultSDSddlFormInitialized)
				{
					defaultSDSddlForm = (string)GetValueFromCache(PropertyManager.DefaultSecurityDescriptor, mustExist: false);
					defaultSDSddlFormInitialized = true;
				}
				if (defaultSDSddlForm != null)
				{
					activeDirectorySecurity = new ActiveDirectorySecurity();
					activeDirectorySecurity.SetSecurityDescriptorSddlForm(defaultSDSddlForm);
				}
				return activeDirectorySecurity;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.DefaultSecurityDescriptor, value?.GetSecurityDescriptorSddlForm(AccessControlSections.All));
				}
				defaultSDSddlForm = value?.GetSecurityDescriptorSddlForm(AccessControlSections.All);
			}
		}

		public ActiveDirectorySchemaClass(DirectoryContext context, string ldapDisplayName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isADAMConfigSet() && !context.isServer())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (ldapDisplayName == null)
			{
				throw new ArgumentNullException("ldapDisplayName");
			}
			if (ldapDisplayName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "ldapDisplayName");
			}
			this.context = new DirectoryContext(context);
			schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
			schemaEntry.Bind(throwIfFail: true);
			this.ldapDisplayName = ldapDisplayName;
			commonName = ldapDisplayName;
			isBound = false;
		}

		internal ActiveDirectorySchemaClass(DirectoryContext context, string ldapDisplayName, DirectoryEntry classEntry, DirectoryEntry schemaEntry)
		{
			this.context = context;
			this.ldapDisplayName = ldapDisplayName;
			this.classEntry = classEntry;
			this.schemaEntry = schemaEntry;
			isDefunctOnServer = false;
			isDefunct = isDefunctOnServer;
			try
			{
				abstractClassEntry = DirectoryEntryManager.GetDirectoryEntryInternal(context, "LDAP://" + context.GetServerName() + "/schema/" + ldapDisplayName);
				iadsClass = (NativeComInterfaces.IAdsClass)abstractClassEntry.NativeObject;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147463168)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySchemaClass), ldapDisplayName);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			catch (InvalidCastException)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySchemaClass), ldapDisplayName);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			isBound = true;
		}

		internal ActiveDirectorySchemaClass(DirectoryContext context, string commonName, Hashtable propertyValuesFromServer, DirectoryEntry schemaEntry)
		{
			this.context = context;
			this.schemaEntry = schemaEntry;
			this.propertyValuesFromServer = propertyValuesFromServer;
			propertiesFromSchemaContainerInitialized = true;
			classEntry = GetSchemaClassDirectoryEntry();
			this.commonName = commonName;
			ldapDisplayName = (string)GetValueFromCache(PropertyManager.LdapDisplayName, mustExist: true);
			isDefunctOnServer = true;
			isDefunct = isDefunctOnServer;
			isBound = true;
		}

		internal ActiveDirectorySchemaClass(DirectoryContext context, string commonName, string ldapDisplayName, DirectoryEntry classEntry, DirectoryEntry schemaEntry)
		{
			this.context = context;
			this.schemaEntry = schemaEntry;
			this.classEntry = classEntry;
			this.commonName = commonName;
			this.ldapDisplayName = ldapDisplayName;
			isDefunctOnServer = true;
			isDefunct = isDefunctOnServer;
			isBound = true;
		}

		public void Dispose()
		{
			Dispose(disposing: true);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			if (disposing)
			{
				if (schemaEntry != null)
				{
					schemaEntry.Dispose();
					schemaEntry = null;
				}
				if (classEntry != null)
				{
					classEntry.Dispose();
					classEntry = null;
				}
				if (abstractClassEntry != null)
				{
					abstractClassEntry.Dispose();
					abstractClassEntry = null;
				}
				if (schema != null)
				{
					schema.Dispose();
				}
			}
			disposed = true;
		}

		public static ActiveDirectorySchemaClass FindByName(DirectoryContext context, string ldapDisplayName)
		{
			ActiveDirectorySchemaClass activeDirectorySchemaClass = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isServer() && !context.isADAMConfigSet())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (ldapDisplayName == null)
			{
				throw new ArgumentNullException("ldapDisplayName");
			}
			if (ldapDisplayName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "ldapDisplayName");
			}
			context = new DirectoryContext(context);
			return new ActiveDirectorySchemaClass(context, ldapDisplayName, (DirectoryEntry)null, (DirectoryEntry)null);
		}

		public ReadOnlyActiveDirectorySchemaPropertyCollection GetAllProperties()
		{
			CheckIfDisposed();
			ArrayList arrayList = new ArrayList();
			arrayList.AddRange(MandatoryProperties);
			arrayList.AddRange(OptionalProperties);
			return new ReadOnlyActiveDirectorySchemaPropertyCollection(arrayList);
		}

		public void Save()
		{
			CheckIfDisposed();
			if (!isBound)
			{
				try
				{
					if (schemaEntry == null)
					{
						schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
					}
					string originalPath = "CN=" + commonName;
					originalPath = Utils.GetEscapedPath(originalPath);
					classEntry = schemaEntry.Children.Add(originalPath, "classSchema");
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
				}
				SetProperty(PropertyManager.LdapDisplayName, ldapDisplayName);
				SetProperty(PropertyManager.GovernsID, oid);
				SetProperty(PropertyManager.Description, description);
				if (possibleSuperiors != null)
				{
					classEntry.Properties[PropertyManager.PossibleSuperiors].AddRange(possibleSuperiors.GetMultiValuedProperty());
				}
				if (mandatoryProperties != null)
				{
					classEntry.Properties[PropertyManager.MustContain].AddRange(mandatoryProperties.GetMultiValuedProperty());
				}
				if (optionalProperties != null)
				{
					classEntry.Properties[PropertyManager.MayContain].AddRange(optionalProperties.GetMultiValuedProperty());
				}
				if (subClassOf != null)
				{
					SetProperty(PropertyManager.SubClassOf, subClassOf.Name);
				}
				else
				{
					SetProperty(PropertyManager.SubClassOf, "top");
				}
				SetProperty(PropertyManager.ObjectClassCategory, type);
				if (schemaGuidBinaryForm != null)
				{
					SetProperty(PropertyManager.SchemaIDGuid, schemaGuidBinaryForm);
				}
				if (defaultSDSddlForm != null)
				{
					SetProperty(PropertyManager.DefaultSecurityDescriptor, defaultSDSddlForm);
				}
			}
			try
			{
				classEntry.CommitChanges();
				if (schema == null)
				{
					ActiveDirectorySchema activeDirectorySchema = ActiveDirectorySchema.GetSchema(context);
					bool flag = false;
					DirectoryServer directoryServer = null;
					try
					{
						directoryServer = activeDirectorySchema.SchemaRoleOwner;
						if (Utils.Compare(directoryServer.Name, context.GetServerName()) != 0)
						{
							DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(directoryServer.Name, DirectoryContextType.DirectoryServer, context);
							schema = ActiveDirectorySchema.GetSchema(newDirectoryContext);
						}
						else
						{
							flag = true;
							schema = activeDirectorySchema;
						}
					}
					finally
					{
						directoryServer?.Dispose();
						if (!flag)
						{
							activeDirectorySchema.Dispose();
						}
					}
				}
				schema.RefreshSchema();
			}
			catch (COMException e2)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
			}
			isDefunctOnServer = isDefunct;
			commonName = null;
			oid = null;
			description = null;
			descriptionInitialized = false;
			possibleSuperiors = null;
			auxiliaryClasses = null;
			possibleInferiors = null;
			mandatoryProperties = null;
			optionalProperties = null;
			subClassOf = null;
			typeInitialized = false;
			schemaGuidBinaryForm = null;
			defaultSDSddlForm = null;
			defaultSDSddlFormInitialized = false;
			propertiesFromSchemaContainerInitialized = false;
			isBound = true;
		}

		public override string ToString()
		{
			return Name;
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			CheckIfDisposed();
			if (!isBound)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			GetSchemaClassDirectoryEntry();
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, classEntry.Path);
		}

		private void CheckIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		private object GetValueFromCache(string propertyName, bool mustExist)
		{
			object result = null;
			InitializePropertiesFromSchemaContainer();
			ArrayList arrayList = (ArrayList)propertyValuesFromServer[propertyName.ToLower(CultureInfo.InvariantCulture)];
			if (arrayList.Count < 1 && mustExist)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("PropertyNotFound", propertyName));
			}
			if (arrayList.Count > 0)
			{
				result = arrayList[0];
			}
			return result;
		}

		private ICollection GetValuesFromCache(string propertyName)
		{
			InitializePropertiesFromSchemaContainer();
			return (ArrayList)propertyValuesFromServer[propertyName.ToLower(CultureInfo.InvariantCulture)];
		}

		private void InitializePropertiesFromSchemaContainer()
		{
			if (!propertiesFromSchemaContainerInitialized)
			{
				if (schemaEntry == null)
				{
					schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
				}
				propertyValuesFromServer = GetPropertiesFromSchemaContainer(context, schemaEntry, isDefunctOnServer ? commonName : ldapDisplayName, isDefunctOnServer);
				propertiesFromSchemaContainerInitialized = true;
			}
		}

		internal static Hashtable GetPropertiesFromSchemaContainer(DirectoryContext context, DirectoryEntry schemaEntry, string name, bool isDefunctOnServer)
		{
			Hashtable hashtable = null;
			StringBuilder stringBuilder = new StringBuilder(15);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=classSchema)");
			stringBuilder.Append("(");
			if (!isDefunctOnServer)
			{
				stringBuilder.Append(PropertyManager.LdapDisplayName);
			}
			else
			{
				stringBuilder.Append(PropertyManager.Cn);
			}
			stringBuilder.Append("=");
			stringBuilder.Append(Utils.GetEscapedFilterValue(name));
			stringBuilder.Append(")");
			if (!isDefunctOnServer)
			{
				stringBuilder.Append("(!(");
			}
			else
			{
				stringBuilder.Append("(");
			}
			stringBuilder.Append(PropertyManager.IsDefunct);
			if (!isDefunctOnServer)
			{
				stringBuilder.Append("=TRUE)))");
			}
			else
			{
				stringBuilder.Append("=TRUE))");
			}
			ArrayList arrayList = new ArrayList();
			ArrayList arrayList2 = new ArrayList();
			arrayList2.Add(PropertyManager.DistinguishedName);
			arrayList2.Add(PropertyManager.Cn);
			arrayList2.Add(PropertyManager.Description);
			arrayList2.Add(PropertyManager.PossibleInferiors);
			arrayList2.Add(PropertyManager.SubClassOf);
			arrayList2.Add(PropertyManager.ObjectClassCategory);
			arrayList2.Add(PropertyManager.SchemaIDGuid);
			arrayList2.Add(PropertyManager.DefaultSecurityDescriptor);
			arrayList.Add(PropertyManager.AuxiliaryClass);
			arrayList.Add(PropertyManager.SystemAuxiliaryClass);
			arrayList.Add(PropertyManager.MustContain);
			arrayList.Add(PropertyManager.SystemMustContain);
			arrayList.Add(PropertyManager.MayContain);
			arrayList.Add(PropertyManager.SystemMayContain);
			if (isDefunctOnServer)
			{
				arrayList2.Add(PropertyManager.LdapDisplayName);
				arrayList2.Add(PropertyManager.GovernsID);
				arrayList.Add(PropertyManager.SystemPossibleSuperiors);
				arrayList.Add(PropertyManager.PossibleSuperiors);
			}
			try
			{
				return Utils.GetValuesWithRangeRetrieval(schemaEntry, stringBuilder.ToString(), arrayList, arrayList2, SearchScope.OneLevel);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147016656)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySchemaClass), name);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
		}

		internal DirectoryEntry GetSchemaClassDirectoryEntry()
		{
			if (classEntry == null)
			{
				InitializePropertiesFromSchemaContainer();
				classEntry = DirectoryEntryManager.GetDirectoryEntry(context, (string)GetValueFromCache(PropertyManager.DistinguishedName, mustExist: true));
			}
			return classEntry;
		}

		private void SetProperty(string propertyName, object value)
		{
			GetSchemaClassDirectoryEntry();
			try
			{
				if (value == null)
				{
					if (classEntry.Properties.Contains(propertyName))
					{
						classEntry.Properties[propertyName].Clear();
					}
				}
				else
				{
					classEntry.Properties[propertyName].Value = value;
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		private ArrayList GetClasses(ICollection ldapDisplayNames)
		{
			ArrayList arrayList = new ArrayList();
			SearchResultCollection searchResultCollection = null;
			try
			{
				if (ldapDisplayNames.Count < 1)
				{
					return arrayList;
				}
				if (schemaEntry == null)
				{
					schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
				}
				StringBuilder stringBuilder = new StringBuilder(100);
				if (ldapDisplayNames.Count > 1)
				{
					stringBuilder.Append("(|");
				}
				foreach (string ldapDisplayName in ldapDisplayNames)
				{
					stringBuilder.Append("(");
					stringBuilder.Append(PropertyManager.LdapDisplayName);
					stringBuilder.Append("=");
					stringBuilder.Append(Utils.GetEscapedFilterValue(ldapDisplayName));
					stringBuilder.Append(")");
				}
				if (ldapDisplayNames.Count > 1)
				{
					stringBuilder.Append(")");
				}
				string filter = "(&(" + PropertyManager.ObjectCategory + "=classSchema)" + stringBuilder.ToString() + "(!(" + PropertyManager.IsDefunct + "=TRUE)))";
				ADSearcher aDSearcher = new ADSearcher(propertiesToLoad: new string[1] { PropertyManager.LdapDisplayName }, searchRoot: schemaEntry, filter: filter, scope: SearchScope.OneLevel);
				searchResultCollection = aDSearcher.FindAll();
				foreach (SearchResult item in searchResultCollection)
				{
					string text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.LdapDisplayName);
					DirectoryEntry directoryEntry = item.GetDirectoryEntry();
					directoryEntry.AuthenticationType = Utils.DefaultAuthType;
					directoryEntry.Username = context.UserName;
					directoryEntry.Password = context.Password;
					ActiveDirectorySchemaClass value = new ActiveDirectorySchemaClass(context, text, directoryEntry, schemaEntry);
					arrayList.Add(value);
				}
				return arrayList;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
			}
		}

		private ArrayList GetProperties(ICollection ldapDisplayNames)
		{
			ArrayList arrayList = new ArrayList();
			SearchResultCollection searchResultCollection = null;
			try
			{
				if (ldapDisplayNames.Count < 1)
				{
					return arrayList;
				}
				if (schemaEntry == null)
				{
					schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
				}
				StringBuilder stringBuilder = new StringBuilder(100);
				if (ldapDisplayNames.Count > 1)
				{
					stringBuilder.Append("(|");
				}
				foreach (string ldapDisplayName in ldapDisplayNames)
				{
					stringBuilder.Append("(");
					stringBuilder.Append(PropertyManager.LdapDisplayName);
					stringBuilder.Append("=");
					stringBuilder.Append(Utils.GetEscapedFilterValue(ldapDisplayName));
					stringBuilder.Append(")");
				}
				if (ldapDisplayNames.Count > 1)
				{
					stringBuilder.Append(")");
				}
				string filter = "(&(" + PropertyManager.ObjectCategory + "=attributeSchema)" + stringBuilder.ToString() + "(!(" + PropertyManager.IsDefunct + "=TRUE)))";
				ADSearcher aDSearcher = new ADSearcher(propertiesToLoad: new string[1] { PropertyManager.LdapDisplayName }, searchRoot: schemaEntry, filter: filter, scope: SearchScope.OneLevel);
				searchResultCollection = aDSearcher.FindAll();
				foreach (SearchResult item in searchResultCollection)
				{
					string text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.LdapDisplayName);
					DirectoryEntry directoryEntry = item.GetDirectoryEntry();
					directoryEntry.AuthenticationType = Utils.DefaultAuthType;
					directoryEntry.Username = context.UserName;
					directoryEntry.Password = context.Password;
					ActiveDirectorySchemaProperty value = new ActiveDirectorySchemaProperty(context, text, directoryEntry, schemaEntry);
					arrayList.Add(value);
				}
				return arrayList;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
			}
		}

		private ArrayList GetPropertyValuesRecursively(string[] propertyNames)
		{
			ArrayList arrayList = new ArrayList();
			try
			{
				if (Utils.Compare(SubClassOf.Name, Name) != 0)
				{
					foreach (string item in SubClassOf.GetPropertyValuesRecursively(propertyNames))
					{
						if (!arrayList.Contains(item))
						{
							arrayList.Add(item);
						}
					}
				}
				foreach (string item2 in GetValuesFromCache(PropertyManager.AuxiliaryClass))
				{
					ActiveDirectorySchemaClass activeDirectorySchemaClass = new ActiveDirectorySchemaClass(context, item2, (DirectoryEntry)null, (DirectoryEntry)null);
					foreach (string item3 in activeDirectorySchemaClass.GetPropertyValuesRecursively(propertyNames))
					{
						if (!arrayList.Contains(item3))
						{
							arrayList.Add(item3);
						}
					}
				}
				foreach (string item4 in GetValuesFromCache(PropertyManager.SystemAuxiliaryClass))
				{
					ActiveDirectorySchemaClass activeDirectorySchemaClass2 = new ActiveDirectorySchemaClass(context, item4, (DirectoryEntry)null, (DirectoryEntry)null);
					foreach (string item5 in activeDirectorySchemaClass2.GetPropertyValuesRecursively(propertyNames))
					{
						if (!arrayList.Contains(item5))
						{
							arrayList.Add(item5);
						}
					}
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			foreach (string propertyName in propertyNames)
			{
				foreach (string item6 in GetValuesFromCache(propertyName))
				{
					if (!arrayList.Contains(item6))
					{
						arrayList.Add(item6);
					}
				}
			}
			return arrayList;
		}
	}
	public class ActiveDirectorySchemaClassCollection : CollectionBase
	{
		private DirectoryEntry classEntry;

		private string propertyName;

		private ActiveDirectorySchemaClass schemaClass;

		private bool isBound;

		private DirectoryContext context;

		public ActiveDirectorySchemaClass this[int index]
		{
			get
			{
				return (ActiveDirectorySchemaClass)base.List[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!value.isBound)
				{
					throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", value.Name));
				}
				if (!Contains(value))
				{
					base.List[index] = value;
					return;
				}
				throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", value), "value");
			}
		}

		internal ActiveDirectorySchemaClassCollection(DirectoryContext context, ActiveDirectorySchemaClass schemaClass, bool isBound, string propertyName, ICollection classNames, bool onlyNames)
		{
			this.schemaClass = schemaClass;
			this.propertyName = propertyName;
			this.isBound = isBound;
			this.context = context;
			foreach (string className in classNames)
			{
				base.InnerList.Add(new ActiveDirectorySchemaClass(context, className, (DirectoryEntry)null, (DirectoryEntry)null));
			}
		}

		internal ActiveDirectorySchemaClassCollection(DirectoryContext context, ActiveDirectorySchemaClass schemaClass, bool isBound, string propertyName, ICollection classes)
		{
			this.schemaClass = schemaClass;
			this.propertyName = propertyName;
			this.isBound = isBound;
			this.context = context;
			foreach (ActiveDirectorySchemaClass @class in classes)
			{
				base.InnerList.Add(@class);
			}
		}

		public int Add(ActiveDirectorySchemaClass schemaClass)
		{
			if (schemaClass == null)
			{
				throw new ArgumentNullException("schemaClass");
			}
			if (!schemaClass.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaClass.Name));
			}
			if (!Contains(schemaClass))
			{
				return base.List.Add(schemaClass);
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", schemaClass), "schemaClass");
		}

		public void AddRange(ActiveDirectorySchemaClass[] schemaClasses)
		{
			if (schemaClasses == null)
			{
				throw new ArgumentNullException("schemaClasses");
			}
			foreach (ActiveDirectorySchemaClass activeDirectorySchemaClass in schemaClasses)
			{
				if (activeDirectorySchemaClass == null)
				{
					throw new ArgumentException("schemaClasses");
				}
			}
			for (int j = 0; j < schemaClasses.Length; j++)
			{
				Add(schemaClasses[j]);
			}
		}

		public void AddRange(ActiveDirectorySchemaClassCollection schemaClasses)
		{
			if (schemaClasses == null)
			{
				throw new ArgumentNullException("schemaClasses");
			}
			foreach (ActiveDirectorySchemaClass schemaClass in schemaClasses)
			{
				if (schemaClass == null)
				{
					throw new ArgumentException("schemaClasses");
				}
			}
			int count = schemaClasses.Count;
			for (int i = 0; i < count; i++)
			{
				Add(schemaClasses[i]);
			}
		}

		public void AddRange(ReadOnlyActiveDirectorySchemaClassCollection schemaClasses)
		{
			if (schemaClasses == null)
			{
				throw new ArgumentNullException("schemaClasses");
			}
			foreach (ActiveDirectorySchemaClass schemaClass in schemaClasses)
			{
				if (schemaClass == null)
				{
					throw new ArgumentException("schemaClasses");
				}
			}
			int count = schemaClasses.Count;
			for (int i = 0; i < count; i++)
			{
				Add(schemaClasses[i]);
			}
		}

		public void Remove(ActiveDirectorySchemaClass schemaClass)
		{
			if (schemaClass == null)
			{
				throw new ArgumentNullException("schemaClass");
			}
			if (!schemaClass.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaClass.Name));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaClass activeDirectorySchemaClass = (ActiveDirectorySchemaClass)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaClass.Name, schemaClass.Name) == 0)
				{
					base.List.Remove(activeDirectorySchemaClass);
					return;
				}
			}
			throw new ArgumentException(Res.GetString("NotFoundInCollection", schemaClass), "schemaClass");
		}

		public void Insert(int index, ActiveDirectorySchemaClass schemaClass)
		{
			if (schemaClass == null)
			{
				throw new ArgumentNullException("schemaClass");
			}
			if (!schemaClass.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaClass.Name));
			}
			if (!Contains(schemaClass))
			{
				base.List.Insert(index, schemaClass);
				return;
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", schemaClass), "schemaClass");
		}

		public bool Contains(ActiveDirectorySchemaClass schemaClass)
		{
			if (schemaClass == null)
			{
				throw new ArgumentNullException("schemaClass");
			}
			if (!schemaClass.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaClass.Name));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaClass activeDirectorySchemaClass = (ActiveDirectorySchemaClass)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaClass.Name, schemaClass.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public void CopyTo(ActiveDirectorySchemaClass[] schemaClasses, int index)
		{
			base.List.CopyTo(schemaClasses, index);
		}

		public int IndexOf(ActiveDirectorySchemaClass schemaClass)
		{
			if (schemaClass == null)
			{
				throw new ArgumentNullException("schemaClass");
			}
			if (!schemaClass.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaClass.Name));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaClass activeDirectorySchemaClass = (ActiveDirectorySchemaClass)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaClass.Name, schemaClass.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		protected override void OnClearComplete()
		{
			if (!isBound)
			{
				return;
			}
			if (classEntry == null)
			{
				classEntry = schemaClass.GetSchemaClassDirectoryEntry();
			}
			try
			{
				if (classEntry.Properties.Contains(propertyName))
				{
					classEntry.Properties[propertyName].Clear();
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnInsertComplete(int index, object value)
		{
			if (isBound)
			{
				if (classEntry == null)
				{
					classEntry = schemaClass.GetSchemaClassDirectoryEntry();
				}
				try
				{
					classEntry.Properties[propertyName].Add(((ActiveDirectorySchemaClass)value).Name);
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		protected override void OnRemoveComplete(int index, object value)
		{
			if (!isBound)
			{
				return;
			}
			if (classEntry == null)
			{
				classEntry = schemaClass.GetSchemaClassDirectoryEntry();
			}
			string name = ((ActiveDirectorySchemaClass)value).Name;
			try
			{
				if (classEntry.Properties[propertyName].Contains(name))
				{
					classEntry.Properties[propertyName].Remove(name);
					return;
				}
				throw new ActiveDirectoryOperationException(Res.GetString("ValueCannotBeModified"));
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnSetComplete(int index, object oldValue, object newValue)
		{
			if (isBound)
			{
				OnRemoveComplete(index, oldValue);
				OnInsertComplete(index, newValue);
			}
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is ActiveDirectorySchemaClass))
			{
				throw new ArgumentException("value");
			}
			if (!((ActiveDirectorySchemaClass)value).isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", ((ActiveDirectorySchemaClass)value).Name));
			}
		}

		internal string[] GetMultiValuedProperty()
		{
			string[] array = new string[base.InnerList.Count];
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				array[i] = ((ActiveDirectorySchemaClass)base.InnerList[i]).Name;
			}
			return array;
		}
	}
	internal enum SearchFlags
	{
		None = 0,
		IsIndexed = 1,
		IsIndexedOverContainer = 2,
		IsInAnr = 4,
		IsOnTombstonedObject = 8,
		IsTupleIndexed = 0x20
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectorySchemaProperty : IDisposable
	{
		private DirectoryEntry schemaEntry;

		private DirectoryEntry propertyEntry;

		private DirectoryEntry abstractPropertyEntry;

		private NativeComInterfaces.IAdsProperty iadsProperty;

		private DirectoryContext context;

		internal bool isBound;

		private bool disposed;

		private ActiveDirectorySchema schema;

		private bool propertiesFromSchemaContainerInitialized;

		private bool isDefunctOnServer;

		private SearchResult propertyValuesFromServer;

		private string ldapDisplayName;

		private string commonName;

		private string oid;

		private ActiveDirectorySyntax syntax = (ActiveDirectorySyntax)(-1);

		private bool syntaxInitialized;

		private string description;

		private bool descriptionInitialized;

		private bool isSingleValued;

		private bool isSingleValuedInitialized;

		private bool isInGlobalCatalog;

		private bool isInGlobalCatalogInitialized;

		private int? rangeLower = null;

		private bool rangeLowerInitialized;

		private int? rangeUpper = null;

		private bool rangeUpperInitialized;

		private bool isDefunct;

		private SearchFlags searchFlags;

		private bool searchFlagsInitialized;

		private ActiveDirectorySchemaProperty linkedProperty;

		private bool linkedPropertyInitialized;

		private int? linkId = null;

		private bool linkIdInitialized;

		private byte[] schemaGuidBinaryForm;

		private static OMObjectClass dnOMObjectClass = new OMObjectClass(new byte[9] { 43, 12, 2, 135, 115, 28, 0, 133, 74 });

		private static OMObjectClass dNWithStringOMObjectClass = new OMObjectClass(new byte[10] { 42, 134, 72, 134, 247, 20, 1, 1, 1, 12 });

		private static OMObjectClass dNWithBinaryOMObjectClass = new OMObjectClass(new byte[10] { 42, 134, 72, 134, 247, 20, 1, 1, 1, 11 });

		private static OMObjectClass replicaLinkOMObjectClass = new OMObjectClass(new byte[10] { 42, 134, 72, 134, 247, 20, 1, 1, 1, 6 });

		private static OMObjectClass presentationAddressOMObjectClass = new OMObjectClass(new byte[9] { 43, 12, 2, 135, 115, 28, 0, 133, 92 });

		private static OMObjectClass accessPointDnOMObjectClass = new OMObjectClass(new byte[9] { 43, 12, 2, 135, 115, 28, 0, 133, 62 });

		private static OMObjectClass oRNameOMObjectClass = new OMObjectClass(new byte[7] { 86, 6, 1, 2, 5, 11, 29 });

		private static int SyntaxesCount = 23;

		private static Syntax[] syntaxes = new Syntax[23]
		{
			new Syntax("2.5.5.3", 27, null),
			new Syntax("2.5.5.4", 20, null),
			new Syntax("2.5.5.6", 18, null),
			new Syntax("2.5.5.12", 64, null),
			new Syntax("2.5.5.10", 4, null),
			new Syntax("2.5.5.15", 66, null),
			new Syntax("2.5.5.9", 2, null),
			new Syntax("2.5.5.16", 65, null),
			new Syntax("2.5.5.8", 1, null),
			new Syntax("2.5.5.2", 6, null),
			new Syntax("2.5.5.11", 24, null),
			new Syntax("2.5.5.11", 23, null),
			new Syntax("2.5.5.1", 127, dnOMObjectClass),
			new Syntax("2.5.5.7", 127, dNWithBinaryOMObjectClass),
			new Syntax("2.5.5.14", 127, dNWithStringOMObjectClass),
			new Syntax("2.5.5.9", 10, null),
			new Syntax("2.5.5.5", 22, null),
			new Syntax("2.5.5.5", 19, null),
			new Syntax("2.5.5.17", 4, null),
			new Syntax("2.5.5.14", 127, accessPointDnOMObjectClass),
			new Syntax("2.5.5.7", 127, oRNameOMObjectClass),
			new Syntax("2.5.5.13", 127, presentationAddressOMObjectClass),
			new Syntax("2.5.5.10", 127, replicaLinkOMObjectClass)
		};

		public string Name
		{
			get
			{
				CheckIfDisposed();
				return ldapDisplayName;
			}
		}

		public string CommonName
		{
			get
			{
				CheckIfDisposed();
				if (isBound && commonName == null)
				{
					commonName = (string)GetValueFromCache(PropertyManager.Cn, mustExist: true);
				}
				return commonName;
			}
			set
			{
				CheckIfDisposed();
				if (value != null && value.Length == 0)
				{
					throw new ArgumentException(Res.GetString("EmptyStringParameter"), "value");
				}
				if (isBound)
				{
					SetProperty(PropertyManager.Cn, value);
				}
				commonName = value;
			}
		}

		public string Oid
		{
			get
			{
				CheckIfDisposed();
				if (isBound && oid == null)
				{
					if (!isDefunctOnServer)
					{
						try
						{
							oid = iadsProperty.OID;
						}
						catch (COMException e)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(context, e);
						}
					}
					else
					{
						oid = (string)GetValueFromCache(PropertyManager.AttributeID, mustExist: true);
					}
				}
				return oid;
			}
			set
			{
				CheckIfDisposed();
				if (value != null && value.Length == 0)
				{
					throw new ArgumentException(Res.GetString("EmptyStringParameter"), "value");
				}
				if (isBound)
				{
					SetProperty(PropertyManager.AttributeID, value);
				}
				oid = value;
			}
		}

		public ActiveDirectorySyntax Syntax
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !syntaxInitialized)
				{
					byte[] array = (byte[])GetValueFromCache(PropertyManager.OMObjectClass, mustExist: false);
					OMObjectClass oMObjectClass = ((array != null) ? new OMObjectClass(array) : null);
					syntax = MapSyntax((string)GetValueFromCache(PropertyManager.AttributeSyntax, mustExist: true), (int)GetValueFromCache(PropertyManager.OMSyntax, mustExist: true), oMObjectClass);
					syntaxInitialized = true;
				}
				return syntax;
			}
			set
			{
				CheckIfDisposed();
				if (value < ActiveDirectorySyntax.CaseExactString || value > ActiveDirectorySyntax.ReplicaLink)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ActiveDirectorySyntax));
				}
				if (isBound)
				{
					SetSyntax(value);
				}
				syntax = value;
			}
		}

		public string Description
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !descriptionInitialized)
				{
					description = (string)GetValueFromCache(PropertyManager.Description, mustExist: false);
					descriptionInitialized = true;
				}
				return description;
			}
			set
			{
				CheckIfDisposed();
				if (value != null && value.Length == 0)
				{
					throw new ArgumentException(Res.GetString("EmptyStringParameter"), "value");
				}
				if (isBound)
				{
					SetProperty(PropertyManager.Description, value);
				}
				description = value;
			}
		}

		public bool IsSingleValued
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !isSingleValuedInitialized)
				{
					if (!isDefunctOnServer)
					{
						try
						{
							isSingleValued = !iadsProperty.MultiValued;
						}
						catch (COMException e)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(context, e);
						}
					}
					else
					{
						isSingleValued = (bool)GetValueFromCache(PropertyManager.IsSingleValued, mustExist: true);
					}
					isSingleValuedInitialized = true;
				}
				return isSingleValued;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					GetSchemaPropertyDirectoryEntry();
					propertyEntry.Properties[PropertyManager.IsSingleValued].Value = value;
				}
				isSingleValued = value;
			}
		}

		public bool IsIndexed
		{
			get
			{
				CheckIfDisposed();
				return IsSetInSearchFlags(SearchFlags.IsIndexed);
			}
			set
			{
				CheckIfDisposed();
				if (value)
				{
					SetBitInSearchFlags(SearchFlags.IsIndexed);
				}
				else
				{
					ResetBitInSearchFlags(SearchFlags.IsIndexed);
				}
			}
		}

		public bool IsIndexedOverContainer
		{
			get
			{
				CheckIfDisposed();
				return IsSetInSearchFlags(SearchFlags.IsIndexedOverContainer);
			}
			set
			{
				CheckIfDisposed();
				if (value)
				{
					SetBitInSearchFlags(SearchFlags.IsIndexedOverContainer);
				}
				else
				{
					ResetBitInSearchFlags(SearchFlags.IsIndexedOverContainer);
				}
			}
		}

		public bool IsInAnr
		{
			get
			{
				CheckIfDisposed();
				return IsSetInSearchFlags(SearchFlags.IsInAnr);
			}
			set
			{
				CheckIfDisposed();
				if (value)
				{
					SetBitInSearchFlags(SearchFlags.IsInAnr);
				}
				else
				{
					ResetBitInSearchFlags(SearchFlags.IsInAnr);
				}
			}
		}

		public bool IsOnTombstonedObject
		{
			get
			{
				CheckIfDisposed();
				return IsSetInSearchFlags(SearchFlags.IsOnTombstonedObject);
			}
			set
			{
				CheckIfDisposed();
				if (value)
				{
					SetBitInSearchFlags(SearchFlags.IsOnTombstonedObject);
				}
				else
				{
					ResetBitInSearchFlags(SearchFlags.IsOnTombstonedObject);
				}
			}
		}

		public bool IsTupleIndexed
		{
			get
			{
				CheckIfDisposed();
				return IsSetInSearchFlags(SearchFlags.IsTupleIndexed);
			}
			set
			{
				CheckIfDisposed();
				if (value)
				{
					SetBitInSearchFlags(SearchFlags.IsTupleIndexed);
				}
				else
				{
					ResetBitInSearchFlags(SearchFlags.IsTupleIndexed);
				}
			}
		}

		public bool IsInGlobalCatalog
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !isInGlobalCatalogInitialized)
				{
					object valueFromCache = GetValueFromCache(PropertyManager.IsMemberOfPartialAttributeSet, mustExist: false);
					isInGlobalCatalog = valueFromCache != null && (bool)valueFromCache;
					isInGlobalCatalogInitialized = true;
				}
				return isInGlobalCatalog;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					GetSchemaPropertyDirectoryEntry();
					propertyEntry.Properties[PropertyManager.IsMemberOfPartialAttributeSet].Value = value;
				}
				isInGlobalCatalog = value;
			}
		}

		public int? RangeLower
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !rangeLowerInitialized)
				{
					object valueFromCache = GetValueFromCache(PropertyManager.RangeLower, mustExist: false);
					if (valueFromCache == null)
					{
						rangeLower = null;
					}
					else
					{
						rangeLower = (int)valueFromCache;
					}
					rangeLowerInitialized = true;
				}
				return rangeLower;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					GetSchemaPropertyDirectoryEntry();
					if (!value.HasValue)
					{
						if (propertyEntry.Properties.Contains(PropertyManager.RangeLower))
						{
							propertyEntry.Properties[PropertyManager.RangeLower].Clear();
						}
					}
					else
					{
						propertyEntry.Properties[PropertyManager.RangeLower].Value = value.Value;
					}
				}
				rangeLower = value;
			}
		}

		public int? RangeUpper
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !rangeUpperInitialized)
				{
					object valueFromCache = GetValueFromCache(PropertyManager.RangeUpper, mustExist: false);
					if (valueFromCache == null)
					{
						rangeUpper = null;
					}
					else
					{
						rangeUpper = (int)valueFromCache;
					}
					rangeUpperInitialized = true;
				}
				return rangeUpper;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					GetSchemaPropertyDirectoryEntry();
					if (!value.HasValue)
					{
						if (propertyEntry.Properties.Contains(PropertyManager.RangeUpper))
						{
							propertyEntry.Properties[PropertyManager.RangeUpper].Clear();
						}
					}
					else
					{
						propertyEntry.Properties[PropertyManager.RangeUpper].Value = value.Value;
					}
				}
				rangeUpper = value;
			}
		}

		public bool IsDefunct
		{
			get
			{
				CheckIfDisposed();
				return isDefunct;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.IsDefunct, value);
				}
				isDefunct = value;
			}
		}

		public ActiveDirectorySchemaProperty Link
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !linkedPropertyInitialized)
				{
					object valueFromCache = GetValueFromCache(PropertyManager.LinkID, mustExist: false);
					int num = ((valueFromCache != null) ? ((int)valueFromCache) : (-1));
					if (num != -1)
					{
						int num2 = num - 2 * (num % 2) + 1;
						try
						{
							if (schemaEntry == null)
							{
								schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
							}
							string filter = "(&(" + PropertyManager.ObjectCategory + "=attributeSchema)(" + PropertyManager.LinkID + "=" + num2 + "))";
							ReadOnlyActiveDirectorySchemaPropertyCollection allProperties = ActiveDirectorySchema.GetAllProperties(context, schemaEntry, filter);
							if (allProperties.Count != 1)
							{
								throw new ActiveDirectoryObjectNotFoundException(Res.GetString("LinkedPropertyNotFound", num2), typeof(ActiveDirectorySchemaProperty), null);
							}
							linkedProperty = allProperties[0];
						}
						catch (COMException e)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(context, e);
						}
					}
					linkedPropertyInitialized = true;
				}
				return linkedProperty;
			}
		}

		public int? LinkId
		{
			get
			{
				CheckIfDisposed();
				if (isBound && !linkIdInitialized)
				{
					object valueFromCache = GetValueFromCache(PropertyManager.LinkID, mustExist: false);
					if (valueFromCache == null)
					{
						linkId = null;
					}
					else
					{
						linkId = (int)valueFromCache;
					}
					linkIdInitialized = true;
				}
				return linkId;
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					GetSchemaPropertyDirectoryEntry();
					if (!value.HasValue)
					{
						if (propertyEntry.Properties.Contains(PropertyManager.LinkID))
						{
							propertyEntry.Properties[PropertyManager.LinkID].Clear();
						}
					}
					else
					{
						propertyEntry.Properties[PropertyManager.LinkID].Value = value.Value;
					}
				}
				linkId = value;
			}
		}

		public Guid SchemaGuid
		{
			get
			{
				CheckIfDisposed();
				_ = Guid.Empty;
				if (isBound && schemaGuidBinaryForm == null)
				{
					schemaGuidBinaryForm = (byte[])GetValueFromCache(PropertyManager.SchemaIDGuid, mustExist: true);
				}
				return new Guid(schemaGuidBinaryForm);
			}
			set
			{
				CheckIfDisposed();
				if (isBound)
				{
					SetProperty(PropertyManager.SchemaIDGuid, value.Equals(Guid.Empty) ? null : value.ToByteArray());
				}
				schemaGuidBinaryForm = (value.Equals(Guid.Empty) ? null : value.ToByteArray());
			}
		}

		public ActiveDirectorySchemaProperty(DirectoryContext context, string ldapDisplayName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isADAMConfigSet() && !context.isServer())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (ldapDisplayName == null)
			{
				throw new ArgumentNullException("ldapDisplayName");
			}
			if (ldapDisplayName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "ldapDisplayName");
			}
			this.context = new DirectoryContext(context);
			schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
			schemaEntry.Bind(throwIfFail: true);
			this.ldapDisplayName = ldapDisplayName;
			commonName = ldapDisplayName;
			isBound = false;
		}

		internal ActiveDirectorySchemaProperty(DirectoryContext context, string ldapDisplayName, DirectoryEntry propertyEntry, DirectoryEntry schemaEntry)
		{
			this.context = context;
			this.ldapDisplayName = ldapDisplayName;
			this.propertyEntry = propertyEntry;
			isDefunctOnServer = false;
			isDefunct = isDefunctOnServer;
			try
			{
				abstractPropertyEntry = DirectoryEntryManager.GetDirectoryEntryInternal(context, "LDAP://" + context.GetServerName() + "/schema/" + ldapDisplayName);
				iadsProperty = (NativeComInterfaces.IAdsProperty)abstractPropertyEntry.NativeObject;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147463168)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySchemaProperty), ldapDisplayName);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			catch (InvalidCastException)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySchemaProperty), ldapDisplayName);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			isBound = true;
		}

		internal ActiveDirectorySchemaProperty(DirectoryContext context, string commonName, SearchResult propertyValuesFromServer, DirectoryEntry schemaEntry)
		{
			this.context = context;
			this.schemaEntry = schemaEntry;
			this.propertyValuesFromServer = propertyValuesFromServer;
			propertiesFromSchemaContainerInitialized = true;
			propertyEntry = GetSchemaPropertyDirectoryEntry();
			this.commonName = commonName;
			ldapDisplayName = (string)GetValueFromCache(PropertyManager.LdapDisplayName, mustExist: true);
			isDefunctOnServer = true;
			isDefunct = isDefunctOnServer;
			isBound = true;
		}

		internal ActiveDirectorySchemaProperty(DirectoryContext context, string commonName, string ldapDisplayName, DirectoryEntry propertyEntry, DirectoryEntry schemaEntry)
		{
			this.context = context;
			this.schemaEntry = schemaEntry;
			this.propertyEntry = propertyEntry;
			this.commonName = commonName;
			this.ldapDisplayName = ldapDisplayName;
			isDefunctOnServer = true;
			isDefunct = isDefunctOnServer;
			isBound = true;
		}

		public void Dispose()
		{
			Dispose(disposing: true);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			if (disposing)
			{
				if (schemaEntry != null)
				{
					schemaEntry.Dispose();
					schemaEntry = null;
				}
				if (propertyEntry != null)
				{
					propertyEntry.Dispose();
					propertyEntry = null;
				}
				if (abstractPropertyEntry != null)
				{
					abstractPropertyEntry.Dispose();
					abstractPropertyEntry = null;
				}
				if (schema != null)
				{
					schema.Dispose();
				}
			}
			disposed = true;
		}

		public static ActiveDirectorySchemaProperty FindByName(DirectoryContext context, string ldapDisplayName)
		{
			ActiveDirectorySchemaProperty activeDirectorySchemaProperty = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isADAMConfigSet() && !context.isServer())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (ldapDisplayName == null)
			{
				throw new ArgumentNullException("ldapDisplayName");
			}
			if (ldapDisplayName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "ldapDisplayName");
			}
			context = new DirectoryContext(context);
			return new ActiveDirectorySchemaProperty(context, ldapDisplayName, (DirectoryEntry)null, (DirectoryEntry)null);
		}

		public void Save()
		{
			CheckIfDisposed();
			if (!isBound)
			{
				try
				{
					if (schemaEntry == null)
					{
						schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
					}
					string originalPath = "CN=" + commonName;
					originalPath = Utils.GetEscapedPath(originalPath);
					propertyEntry = schemaEntry.Children.Add(originalPath, "attributeSchema");
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
				}
				SetProperty(PropertyManager.LdapDisplayName, ldapDisplayName);
				SetProperty(PropertyManager.AttributeID, oid);
				if (syntax != (ActiveDirectorySyntax)(-1))
				{
					SetSyntax(syntax);
				}
				SetProperty(PropertyManager.Description, description);
				propertyEntry.Properties[PropertyManager.IsSingleValued].Value = isSingleValued;
				propertyEntry.Properties[PropertyManager.IsMemberOfPartialAttributeSet].Value = isInGlobalCatalog;
				propertyEntry.Properties[PropertyManager.IsDefunct].Value = isDefunct;
				if (rangeLower.HasValue)
				{
					propertyEntry.Properties[PropertyManager.RangeLower].Value = rangeLower.Value;
				}
				if (rangeUpper.HasValue)
				{
					propertyEntry.Properties[PropertyManager.RangeUpper].Value = rangeUpper.Value;
				}
				if (searchFlags != 0)
				{
					propertyEntry.Properties[PropertyManager.SearchFlags].Value = (int)searchFlags;
				}
				if (linkId.HasValue)
				{
					propertyEntry.Properties[PropertyManager.LinkID].Value = linkId.Value;
				}
				if (schemaGuidBinaryForm != null)
				{
					SetProperty(PropertyManager.SchemaIDGuid, schemaGuidBinaryForm);
				}
			}
			try
			{
				propertyEntry.CommitChanges();
				if (schema == null)
				{
					ActiveDirectorySchema activeDirectorySchema = ActiveDirectorySchema.GetSchema(context);
					bool flag = false;
					DirectoryServer directoryServer = null;
					try
					{
						directoryServer = activeDirectorySchema.SchemaRoleOwner;
						if (Utils.Compare(directoryServer.Name, context.GetServerName()) != 0)
						{
							DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(directoryServer.Name, DirectoryContextType.DirectoryServer, context);
							schema = ActiveDirectorySchema.GetSchema(newDirectoryContext);
						}
						else
						{
							flag = true;
							schema = activeDirectorySchema;
						}
					}
					finally
					{
						directoryServer?.Dispose();
						if (!flag)
						{
							activeDirectorySchema.Dispose();
						}
					}
				}
				schema.RefreshSchema();
			}
			catch (COMException e2)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
			}
			isDefunctOnServer = isDefunct;
			commonName = null;
			oid = null;
			syntaxInitialized = false;
			descriptionInitialized = false;
			isSingleValuedInitialized = false;
			isInGlobalCatalogInitialized = false;
			rangeLowerInitialized = false;
			rangeUpperInitialized = false;
			searchFlagsInitialized = false;
			linkedPropertyInitialized = false;
			linkIdInitialized = false;
			schemaGuidBinaryForm = null;
			propertiesFromSchemaContainerInitialized = false;
			isBound = true;
		}

		public override string ToString()
		{
			return Name;
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			CheckIfDisposed();
			if (!isBound)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			GetSchemaPropertyDirectoryEntry();
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, propertyEntry.Path);
		}

		private void CheckIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		private object GetValueFromCache(string propertyName, bool mustExist)
		{
			object result = null;
			InitializePropertiesFromSchemaContainer();
			ResultPropertyValueCollection resultPropertyValueCollection = null;
			try
			{
				resultPropertyValueCollection = propertyValuesFromServer.Properties[propertyName];
				if (resultPropertyValueCollection == null || resultPropertyValueCollection.Count < 1)
				{
					if (mustExist)
					{
						throw new ActiveDirectoryOperationException(Res.GetString("PropertyNotFound", propertyName));
					}
					return result;
				}
				return resultPropertyValueCollection[0];
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		private void InitializePropertiesFromSchemaContainer()
		{
			if (!propertiesFromSchemaContainerInitialized)
			{
				if (schemaEntry == null)
				{
					schemaEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.SchemaNamingContext);
				}
				propertyValuesFromServer = GetPropertiesFromSchemaContainer(context, schemaEntry, isDefunctOnServer ? commonName : ldapDisplayName, isDefunctOnServer);
				propertiesFromSchemaContainerInitialized = true;
			}
		}

		internal static SearchResult GetPropertiesFromSchemaContainer(DirectoryContext context, DirectoryEntry schemaEntry, string name, bool isDefunctOnServer)
		{
			SearchResult searchResult = null;
			StringBuilder stringBuilder = new StringBuilder(15);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=attributeSchema)");
			stringBuilder.Append("(");
			if (!isDefunctOnServer)
			{
				stringBuilder.Append(PropertyManager.LdapDisplayName);
			}
			else
			{
				stringBuilder.Append(PropertyManager.Cn);
			}
			stringBuilder.Append("=");
			stringBuilder.Append(Utils.GetEscapedFilterValue(name));
			stringBuilder.Append(")");
			if (!isDefunctOnServer)
			{
				stringBuilder.Append("(!(");
			}
			else
			{
				stringBuilder.Append("(");
			}
			stringBuilder.Append(PropertyManager.IsDefunct);
			if (!isDefunctOnServer)
			{
				stringBuilder.Append("=TRUE)))");
			}
			else
			{
				stringBuilder.Append("=TRUE))");
			}
			string[] array = null;
			ADSearcher aDSearcher = new ADSearcher(propertiesToLoad: (!isDefunctOnServer) ? new string[12]
			{
				PropertyManager.DistinguishedName,
				PropertyManager.Cn,
				PropertyManager.AttributeSyntax,
				PropertyManager.OMSyntax,
				PropertyManager.OMObjectClass,
				PropertyManager.Description,
				PropertyManager.SearchFlags,
				PropertyManager.IsMemberOfPartialAttributeSet,
				PropertyManager.LinkID,
				PropertyManager.SchemaIDGuid,
				PropertyManager.RangeLower,
				PropertyManager.RangeUpper
			} : new string[15]
			{
				PropertyManager.DistinguishedName,
				PropertyManager.Cn,
				PropertyManager.AttributeSyntax,
				PropertyManager.OMSyntax,
				PropertyManager.OMObjectClass,
				PropertyManager.Description,
				PropertyManager.SearchFlags,
				PropertyManager.IsMemberOfPartialAttributeSet,
				PropertyManager.LinkID,
				PropertyManager.SchemaIDGuid,
				PropertyManager.AttributeID,
				PropertyManager.IsSingleValued,
				PropertyManager.RangeLower,
				PropertyManager.RangeUpper,
				PropertyManager.LdapDisplayName
			}, searchRoot: schemaEntry, filter: stringBuilder.ToString(), scope: SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
			try
			{
				searchResult = aDSearcher.FindOne();
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147016656)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySchemaProperty), name);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			if (searchResult == null)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySchemaProperty), name);
			}
			return searchResult;
		}

		internal DirectoryEntry GetSchemaPropertyDirectoryEntry()
		{
			if (propertyEntry == null)
			{
				InitializePropertiesFromSchemaContainer();
				propertyEntry = DirectoryEntryManager.GetDirectoryEntry(context, (string)GetValueFromCache(PropertyManager.DistinguishedName, mustExist: true));
			}
			return propertyEntry;
		}

		private bool IsSetInSearchFlags(SearchFlags searchFlagBit)
		{
			if (isBound && !searchFlagsInitialized)
			{
				object valueFromCache = GetValueFromCache(PropertyManager.SearchFlags, mustExist: false);
				if (valueFromCache != null)
				{
					searchFlags = (SearchFlags)(int)valueFromCache;
				}
				searchFlagsInitialized = true;
			}
			return (searchFlags & searchFlagBit) != 0;
		}

		private void SetBitInSearchFlags(SearchFlags searchFlagBit)
		{
			searchFlags |= searchFlagBit;
			if (isBound)
			{
				GetSchemaPropertyDirectoryEntry();
				propertyEntry.Properties[PropertyManager.SearchFlags].Value = (int)searchFlags;
			}
		}

		private void ResetBitInSearchFlags(SearchFlags searchFlagBit)
		{
			searchFlags &= ~searchFlagBit;
			if (isBound)
			{
				GetSchemaPropertyDirectoryEntry();
				propertyEntry.Properties[PropertyManager.SearchFlags].Value = (int)searchFlags;
			}
		}

		private void SetProperty(string propertyName, object value)
		{
			GetSchemaPropertyDirectoryEntry();
			if (value == null)
			{
				if (propertyEntry.Properties.Contains(propertyName))
				{
					propertyEntry.Properties[propertyName].Clear();
				}
			}
			else
			{
				propertyEntry.Properties[propertyName].Value = value;
			}
		}

		private ActiveDirectorySyntax MapSyntax(string syntaxId, int oMID, OMObjectClass oMObjectClass)
		{
			for (int i = 0; i < SyntaxesCount; i++)
			{
				if (syntaxes[i].Equals(new Syntax(syntaxId, oMID, oMObjectClass)))
				{
					return (ActiveDirectorySyntax)i;
				}
			}
			throw new ActiveDirectoryOperationException(Res.GetString("UnknownSyntax", ldapDisplayName));
		}

		private void SetSyntax(ActiveDirectorySyntax syntax)
		{
			if (syntax < ActiveDirectorySyntax.CaseExactString || (int)syntax > SyntaxesCount - 1)
			{
				throw new InvalidEnumArgumentException("syntax", (int)syntax, typeof(ActiveDirectorySyntax));
			}
			GetSchemaPropertyDirectoryEntry();
			propertyEntry.Properties[PropertyManager.AttributeSyntax].Value = syntaxes[(int)syntax].attributeSyntax;
			propertyEntry.Properties[PropertyManager.OMSyntax].Value = syntaxes[(int)syntax].oMSyntax;
			OMObjectClass oMObjectClass = syntaxes[(int)syntax].oMObjectClass;
			if (oMObjectClass != null)
			{
				propertyEntry.Properties[PropertyManager.OMObjectClass].Value = oMObjectClass.Data;
			}
		}
	}
	public class ActiveDirectorySchemaPropertyCollection : CollectionBase
	{
		private DirectoryEntry classEntry;

		private string propertyName;

		private ActiveDirectorySchemaClass schemaClass;

		private bool isBound;

		private DirectoryContext context;

		public ActiveDirectorySchemaProperty this[int index]
		{
			get
			{
				return (ActiveDirectorySchemaProperty)base.List[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!value.isBound)
				{
					throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", value.Name));
				}
				if (!Contains(value))
				{
					base.List[index] = value;
					return;
				}
				throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", value), "value");
			}
		}

		internal ActiveDirectorySchemaPropertyCollection(DirectoryContext context, ActiveDirectorySchemaClass schemaClass, bool isBound, string propertyName, ICollection propertyNames, bool onlyNames)
		{
			this.schemaClass = schemaClass;
			this.propertyName = propertyName;
			this.isBound = isBound;
			this.context = context;
			foreach (string propertyName2 in propertyNames)
			{
				base.InnerList.Add(new ActiveDirectorySchemaProperty(context, propertyName2, (DirectoryEntry)null, (DirectoryEntry)null));
			}
		}

		internal ActiveDirectorySchemaPropertyCollection(DirectoryContext context, ActiveDirectorySchemaClass schemaClass, bool isBound, string propertyName, ICollection properties)
		{
			this.schemaClass = schemaClass;
			this.propertyName = propertyName;
			this.isBound = isBound;
			this.context = context;
			foreach (ActiveDirectorySchemaProperty property in properties)
			{
				base.InnerList.Add(property);
			}
		}

		public int Add(ActiveDirectorySchemaProperty schemaProperty)
		{
			if (schemaProperty == null)
			{
				throw new ArgumentNullException("schemaProperty");
			}
			if (!schemaProperty.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaProperty.Name));
			}
			if (!Contains(schemaProperty))
			{
				return base.List.Add(schemaProperty);
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", schemaProperty), "schemaProperty");
		}

		public void AddRange(ActiveDirectorySchemaProperty[] properties)
		{
			if (properties == null)
			{
				throw new ArgumentNullException("properties");
			}
			foreach (ActiveDirectorySchemaProperty activeDirectorySchemaProperty in properties)
			{
				if (activeDirectorySchemaProperty == null)
				{
					throw new ArgumentException("properties");
				}
			}
			for (int j = 0; j < properties.Length; j++)
			{
				Add(properties[j]);
			}
		}

		public void AddRange(ActiveDirectorySchemaPropertyCollection properties)
		{
			if (properties == null)
			{
				throw new ArgumentNullException("properties");
			}
			foreach (ActiveDirectorySchemaProperty property in properties)
			{
				if (property == null)
				{
					throw new ArgumentException("properties");
				}
			}
			int count = properties.Count;
			for (int i = 0; i < count; i++)
			{
				Add(properties[i]);
			}
		}

		public void AddRange(ReadOnlyActiveDirectorySchemaPropertyCollection properties)
		{
			if (properties == null)
			{
				throw new ArgumentNullException("properties");
			}
			foreach (ActiveDirectorySchemaProperty property in properties)
			{
				if (property == null)
				{
					throw new ArgumentException("properties");
				}
			}
			int count = properties.Count;
			for (int i = 0; i < count; i++)
			{
				Add(properties[i]);
			}
		}

		public void Remove(ActiveDirectorySchemaProperty schemaProperty)
		{
			if (schemaProperty == null)
			{
				throw new ArgumentNullException("schemaProperty");
			}
			if (!schemaProperty.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaProperty.Name));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaProperty activeDirectorySchemaProperty = (ActiveDirectorySchemaProperty)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaProperty.Name, schemaProperty.Name) == 0)
				{
					base.List.Remove(activeDirectorySchemaProperty);
					return;
				}
			}
			throw new ArgumentException(Res.GetString("NotFoundInCollection", schemaProperty), "schemaProperty");
		}

		public void Insert(int index, ActiveDirectorySchemaProperty schemaProperty)
		{
			if (schemaProperty == null)
			{
				throw new ArgumentNullException("schemaProperty");
			}
			if (!schemaProperty.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaProperty.Name));
			}
			if (!Contains(schemaProperty))
			{
				base.List.Insert(index, schemaProperty);
				return;
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", schemaProperty), "schemaProperty");
		}

		public bool Contains(ActiveDirectorySchemaProperty schemaProperty)
		{
			if (schemaProperty == null)
			{
				throw new ArgumentNullException("schemaProperty");
			}
			if (!schemaProperty.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaProperty.Name));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaProperty activeDirectorySchemaProperty = (ActiveDirectorySchemaProperty)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaProperty.Name, schemaProperty.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		internal bool Contains(string propertyName)
		{
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaProperty activeDirectorySchemaProperty = (ActiveDirectorySchemaProperty)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaProperty.Name, propertyName) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public void CopyTo(ActiveDirectorySchemaProperty[] properties, int index)
		{
			base.List.CopyTo(properties, index);
		}

		public int IndexOf(ActiveDirectorySchemaProperty schemaProperty)
		{
			if (schemaProperty == null)
			{
				throw new ArgumentNullException("schemaProperty");
			}
			if (!schemaProperty.isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", schemaProperty.Name));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaProperty activeDirectorySchemaProperty = (ActiveDirectorySchemaProperty)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaProperty.Name, schemaProperty.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		protected override void OnClearComplete()
		{
			if (!isBound)
			{
				return;
			}
			if (classEntry == null)
			{
				classEntry = schemaClass.GetSchemaClassDirectoryEntry();
			}
			try
			{
				if (classEntry.Properties.Contains(propertyName))
				{
					classEntry.Properties[propertyName].Clear();
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnInsertComplete(int index, object value)
		{
			if (isBound)
			{
				if (classEntry == null)
				{
					classEntry = schemaClass.GetSchemaClassDirectoryEntry();
				}
				try
				{
					classEntry.Properties[propertyName].Add(((ActiveDirectorySchemaProperty)value).Name);
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		protected override void OnRemoveComplete(int index, object value)
		{
			if (!isBound)
			{
				return;
			}
			if (classEntry == null)
			{
				classEntry = schemaClass.GetSchemaClassDirectoryEntry();
			}
			string name = ((ActiveDirectorySchemaProperty)value).Name;
			try
			{
				if (classEntry.Properties[propertyName].Contains(name))
				{
					classEntry.Properties[propertyName].Remove(name);
					return;
				}
				throw new ActiveDirectoryOperationException(Res.GetString("ValueCannotBeModified"));
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnSetComplete(int index, object oldValue, object newValue)
		{
			if (isBound)
			{
				OnRemoveComplete(index, oldValue);
				OnInsertComplete(index, newValue);
			}
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is ActiveDirectorySchemaProperty))
			{
				throw new ArgumentException("value");
			}
			if (!((ActiveDirectorySchemaProperty)value).isBound)
			{
				throw new InvalidOperationException(Res.GetString("SchemaObjectNotCommitted", ((ActiveDirectorySchemaProperty)value).Name));
			}
		}

		internal string[] GetMultiValuedProperty()
		{
			string[] array = new string[base.InnerList.Count];
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				array[i] = ((ActiveDirectorySchemaProperty)base.InnerList[i]).Name;
			}
			return array;
		}
	}
	[Flags]
	public enum ActiveDirectorySiteOptions
	{
		None = 0,
		AutoTopologyDisabled = 1,
		TopologyCleanupDisabled = 2,
		AutoMinimumHopDisabled = 4,
		StaleServerDetectDisabled = 8,
		AutoInterSiteTopologyDisabled = 0x10,
		GroupMembershipCachingEnabled = 0x20,
		ForceKccWindows2003Behavior = 0x40,
		UseWindows2000IstgElection = 0x80,
		RandomBridgeHeaderServerSelectionDisabled = 0x100,
		UseHashingForReplicationSchedule = 0x200,
		RedundantServerTopologyEnabled = 0x400
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectorySite : IDisposable
	{
		internal DirectoryContext context;

		private string name;

		internal DirectoryEntry cachedEntry;

		private DirectoryEntry ntdsEntry;

		private ActiveDirectorySubnetCollection subnets;

		private DirectoryServer topologyGenerator;

		private ReadOnlySiteCollection adjacentSites = new ReadOnlySiteCollection();

		private bool disposed;

		private DomainCollection domains = new DomainCollection(null);

		private ReadOnlyDirectoryServerCollection servers = new ReadOnlyDirectoryServerCollection();

		private ReadOnlySiteLinkCollection links = new ReadOnlySiteLinkCollection();

		private ActiveDirectorySiteOptions siteOptions;

		private ReadOnlyDirectoryServerCollection bridgeheadServers = new ReadOnlyDirectoryServerCollection();

		private DirectoryServerCollection SMTPBridgeheadServers;

		private DirectoryServerCollection RPCBridgeheadServers;

		private byte[] replicationSchedule;

		internal bool existing;

		private bool subnetRetrieved;

		private bool isADAMServer;

		private bool checkADAM;

		private bool topologyTouched;

		private bool adjacentSitesRetrieved;

		private string siteDN;

		private bool domainsRetrieved;

		private bool serversRetrieved;

		private bool belongLinksRetrieved;

		private bool bridgeheadServerRetrieved;

		private bool SMTPBridgeRetrieved;

		private bool RPCBridgeRetrieved;

		private static int ERROR_NO_SITENAME = 1919;

		public string Name
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return name;
			}
		}

		public DomainCollection Domains
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !domainsRetrieved)
				{
					domains.Clear();
					GetDomains();
					domainsRetrieved = true;
				}
				return domains;
			}
		}

		public ActiveDirectorySubnetCollection Subnets
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !subnetRetrieved)
				{
					subnets.initialized = false;
					subnets.Clear();
					GetSubnets();
					subnetRetrieved = true;
				}
				subnets.initialized = true;
				return subnets;
			}
		}

		public ReadOnlyDirectoryServerCollection Servers
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !serversRetrieved)
				{
					servers.Clear();
					GetServers();
					serversRetrieved = true;
				}
				return servers;
			}
		}

		public ReadOnlySiteCollection AdjacentSites
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !adjacentSitesRetrieved)
				{
					adjacentSites.Clear();
					GetAdjacentSites();
					adjacentSitesRetrieved = true;
				}
				return adjacentSites;
			}
		}

		public ReadOnlySiteLinkCollection SiteLinks
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !belongLinksRetrieved)
				{
					links.Clear();
					GetLinks();
					belongLinksRetrieved = true;
				}
				return links;
			}
		}

		public DirectoryServer InterSiteTopologyGenerator
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && topologyGenerator == null && !topologyTouched)
				{
					bool flag;
					try
					{
						flag = NTDSSiteEntry.Properties.Contains("interSiteTopologyGenerator");
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					if (flag)
					{
						string dn = (string)PropertyManager.GetPropertyValue(context, NTDSSiteEntry, PropertyManager.InterSiteTopologyGenerator);
						string text = null;
						DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
						try
						{
							text = (string)PropertyManager.GetPropertyValue(context, directoryEntry.Parent, PropertyManager.DnsHostName);
						}
						catch (COMException ex)
						{
							if (ex.ErrorCode == -2147016656)
							{
								return null;
							}
						}
						if (IsADAM)
						{
							int num = (int)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.MsDSPortLDAP);
							string adamInstanceName = text;
							if (num != 389)
							{
								adamInstanceName = text + ":" + num;
							}
							topologyGenerator = new AdamInstance(Utils.GetNewDirectoryContext(adamInstanceName, DirectoryContextType.DirectoryServer, context), adamInstanceName);
						}
						else
						{
							topologyGenerator = new DomainController(Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context), text);
						}
					}
				}
				return topologyGenerator;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (existing)
				{
					_ = NTDSSiteEntry;
				}
				topologyTouched = true;
				topologyGenerator = value;
			}
		}

		public ActiveDirectorySiteOptions Options
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing)
				{
					try
					{
						if (NTDSSiteEntry.Properties.Contains("options"))
						{
							return (ActiveDirectorySiteOptions)NTDSSiteEntry.Properties["options"][0];
						}
						return ActiveDirectorySiteOptions.None;
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
				return siteOptions;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing)
				{
					try
					{
						NTDSSiteEntry.Properties["options"].Value = value;
						return;
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
				siteOptions = value;
			}
		}

		public string Location
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (cachedEntry.Properties.Contains("location"))
					{
						return (string)cachedEntry.Properties["location"][0];
					}
					return null;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (value == null)
					{
						if (cachedEntry.Properties.Contains("location"))
						{
							cachedEntry.Properties["location"].Clear();
						}
					}
					else
					{
						cachedEntry.Properties["location"].Value = value;
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public ReadOnlyDirectoryServerCollection BridgeheadServers
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (!bridgeheadServerRetrieved)
				{
					bridgeheadServers = GetBridgeheadServers();
					bridgeheadServerRetrieved = true;
				}
				return bridgeheadServers;
			}
		}

		public DirectoryServerCollection PreferredSmtpBridgeheadServers
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !SMTPBridgeRetrieved)
				{
					SMTPBridgeheadServers.initialized = false;
					SMTPBridgeheadServers.Clear();
					GetPreferredBridgeheadServers(ActiveDirectoryTransportType.Smtp);
					SMTPBridgeRetrieved = true;
				}
				SMTPBridgeheadServers.initialized = true;
				return SMTPBridgeheadServers;
			}
		}

		public DirectoryServerCollection PreferredRpcBridgeheadServers
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !RPCBridgeRetrieved)
				{
					RPCBridgeheadServers.initialized = false;
					RPCBridgeheadServers.Clear();
					GetPreferredBridgeheadServers(ActiveDirectoryTransportType.Rpc);
					RPCBridgeRetrieved = true;
				}
				RPCBridgeheadServers.initialized = true;
				return RPCBridgeheadServers;
			}
		}

		public ActiveDirectorySchedule IntraSiteReplicationSchedule
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				ActiveDirectorySchedule activeDirectorySchedule = null;
				if (existing)
				{
					try
					{
						if (!NTDSSiteEntry.Properties.Contains("schedule"))
						{
							return activeDirectorySchedule;
						}
						byte[] unmanagedSchedule = (byte[])NTDSSiteEntry.Properties["schedule"][0];
						activeDirectorySchedule = new ActiveDirectorySchedule();
						activeDirectorySchedule.SetUnmanagedSchedule(unmanagedSchedule);
						return activeDirectorySchedule;
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
				if (replicationSchedule != null)
				{
					activeDirectorySchedule = new ActiveDirectorySchedule();
					activeDirectorySchedule.SetUnmanagedSchedule(replicationSchedule);
				}
				return activeDirectorySchedule;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing)
				{
					try
					{
						if (value == null)
						{
							if (NTDSSiteEntry.Properties.Contains("schedule"))
							{
								NTDSSiteEntry.Properties["schedule"].Clear();
							}
						}
						else
						{
							NTDSSiteEntry.Properties["schedule"].Value = value.GetUnmanagedSchedule();
						}
						return;
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
				if (value == null)
				{
					replicationSchedule = null;
				}
				else
				{
					replicationSchedule = value.GetUnmanagedSchedule();
				}
			}
		}

		private bool IsADAM
		{
			get
			{
				if (!checkADAM)
				{
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					PropertyValueCollection propertyValueCollection = null;
					try
					{
						propertyValueCollection = directoryEntry.Properties["supportedCapabilities"];
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					if (propertyValueCollection.Contains(SupportedCapability.ADAMOid))
					{
						isADAMServer = true;
					}
				}
				return isADAMServer;
			}
		}

		private DirectoryEntry NTDSSiteEntry
		{
			get
			{
				if (ntdsEntry == null)
				{
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, "CN=NTDS Site Settings," + (string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName));
					try
					{
						directoryEntry.RefreshCache();
					}
					catch (COMException ex)
					{
						if (ex.ErrorCode == -2147016656)
						{
							string @string = Res.GetString("NTDSSiteSetting", name);
							throw new ActiveDirectoryOperationException(@string, ex, 8240);
						}
						throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
					}
					ntdsEntry = directoryEntry;
				}
				return ntdsEntry;
			}
		}

		public static ActiveDirectorySite FindByName(DirectoryContext context, string siteName)
		{
			ValidateArgument(context, siteName);
			context = new DirectoryContext(context);
			DirectoryEntry directoryEntry;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string dn = "CN=Sites," + (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			try
			{
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=site)(objectCategory=site)(name=" + Utils.GetEscapedFilterValue(siteName) + "))", new string[1] { "distinguishedName" }, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
				SearchResult searchResult = aDSearcher.FindOne();
				if (searchResult == null)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySite), siteName);
				}
				return new ActiveDirectorySite(context, siteName, existing: true);
			}
			catch (COMException ex2)
			{
				if (ex2.ErrorCode == -2147016656)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySite), siteName);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		public ActiveDirectorySite(DirectoryContext context, string siteName)
		{
			ValidateArgument(context, siteName);
			context = new DirectoryContext(context);
			this.context = context;
			name = siteName;
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				siteDN = "CN=Sites," + text;
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, siteDN);
				string originalPath = "cn=" + name;
				originalPath = Utils.GetEscapedPath(originalPath);
				cachedEntry = directoryEntry.Children.Add(originalPath, "site");
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			subnets = new ActiveDirectorySubnetCollection(context, "CN=" + siteName + "," + siteDN);
			string transportName = "CN=IP,CN=Inter-Site Transports," + siteDN;
			RPCBridgeheadServers = new DirectoryServerCollection(context, "CN=" + siteName + "," + siteDN, transportName);
			transportName = "CN=SMTP,CN=Inter-Site Transports," + siteDN;
			SMTPBridgeheadServers = new DirectoryServerCollection(context, "CN=" + siteName + "," + siteDN, transportName);
		}

		internal ActiveDirectorySite(DirectoryContext context, string siteName, bool existing)
		{
			this.context = context;
			name = siteName;
			this.existing = existing;
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			siteDN = "CN=Sites," + (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
			cachedEntry = DirectoryEntryManager.GetDirectoryEntry(context, "CN=" + siteName + "," + siteDN);
			subnets = new ActiveDirectorySubnetCollection(context, "CN=" + siteName + "," + siteDN);
			string transportName = "CN=IP,CN=Inter-Site Transports," + siteDN;
			RPCBridgeheadServers = new DirectoryServerCollection(context, (string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName), transportName);
			transportName = "CN=SMTP,CN=Inter-Site Transports," + siteDN;
			SMTPBridgeheadServers = new DirectoryServerCollection(context, (string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName), transportName);
		}

		public static ActiveDirectorySite GetComputerSite()
		{
			new DirectoryContext(DirectoryContextType.Forest);
			IntPtr ptr = (IntPtr)0;
			int num = UnsafeNativeMethods.DsGetSiteName(null, ref ptr);
			if (num != 0)
			{
				if (num == ERROR_NO_SITENAME)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("NoCurrentSite"), typeof(ActiveDirectorySite), null);
				}
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			}
			try
			{
				string siteName = Marshal.PtrToStringUni(ptr);
				string dnsForestName = Locator.GetDomainControllerInfo(null, null, null, 16L).DnsForestName;
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(dnsForestName, DirectoryContextType.Forest, null);
				return FindByName(newDirectoryContext, siteName);
			}
			finally
			{
				if (ptr != (IntPtr)0)
				{
					Marshal.FreeHGlobal(ptr);
				}
			}
		}

		public void Save()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				cachedEntry.CommitChanges();
				foreach (DictionaryEntry change in subnets.changeList)
				{
					try
					{
						((DirectoryEntry)change.Value).CommitChanges();
					}
					catch (COMException ex)
					{
						if (ex.ErrorCode != -2147016694)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(ex);
						}
					}
				}
				subnets.changeList.Clear();
				subnetRetrieved = false;
				foreach (DictionaryEntry change2 in SMTPBridgeheadServers.changeList)
				{
					try
					{
						((DirectoryEntry)change2.Value).CommitChanges();
					}
					catch (COMException ex2)
					{
						if (IsADAM && ex2.ErrorCode == -2147016657)
						{
							throw new NotSupportedException(Res.GetString("NotSupportTransportSMTP"));
						}
						if (ex2.ErrorCode != -2147016694)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(ex2);
						}
					}
				}
				SMTPBridgeheadServers.changeList.Clear();
				SMTPBridgeRetrieved = false;
				foreach (DictionaryEntry change3 in RPCBridgeheadServers.changeList)
				{
					try
					{
						((DirectoryEntry)change3.Value).CommitChanges();
					}
					catch (COMException ex3)
					{
						if (ex3.ErrorCode != -2147016694)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(ex3);
						}
					}
				}
				RPCBridgeheadServers.changeList.Clear();
				RPCBridgeRetrieved = false;
				if (existing)
				{
					if (topologyTouched)
					{
						try
						{
							DirectoryServer interSiteTopologyGenerator = InterSiteTopologyGenerator;
							string value = ((interSiteTopologyGenerator is DomainController) ? ((DomainController)interSiteTopologyGenerator).NtdsaObjectName : ((AdamInstance)interSiteTopologyGenerator).NtdsaObjectName);
							NTDSSiteEntry.Properties["interSiteTopologyGenerator"].Value = value;
						}
						catch (COMException e)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(context, e);
						}
					}
					NTDSSiteEntry.CommitChanges();
					topologyTouched = false;
					return;
				}
				try
				{
					DirectoryEntry directoryEntry = cachedEntry.Children.Add("CN=NTDS Site Settings", "nTDSSiteSettings");
					DirectoryServer interSiteTopologyGenerator2 = InterSiteTopologyGenerator;
					if (interSiteTopologyGenerator2 != null)
					{
						string value2 = ((interSiteTopologyGenerator2 is DomainController) ? ((DomainController)interSiteTopologyGenerator2).NtdsaObjectName : ((AdamInstance)interSiteTopologyGenerator2).NtdsaObjectName);
						directoryEntry.Properties["interSiteTopologyGenerator"].Value = value2;
					}
					directoryEntry.Properties["options"].Value = siteOptions;
					if (replicationSchedule != null)
					{
						directoryEntry.Properties["schedule"].Value = replicationSchedule;
					}
					directoryEntry.CommitChanges();
					ntdsEntry = directoryEntry;
					directoryEntry = cachedEntry.Children.Add("CN=Servers", "serversContainer");
					directoryEntry.CommitChanges();
					if (!IsADAM)
					{
						directoryEntry = cachedEntry.Children.Add("CN=Licensing Site Settings", "licensingSiteSettings");
						directoryEntry.CommitChanges();
					}
				}
				finally
				{
					existing = true;
				}
			}
			catch (COMException e2)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
			}
		}

		public void Delete()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotDelete"));
			}
			try
			{
				cachedEntry.DeleteTree();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public override string ToString()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			return name;
		}

		private ReadOnlyDirectoryServerCollection GetBridgeheadServers()
		{
			NativeComInterfaces.IAdsPathname adsPathname = (NativeComInterfaces.IAdsPathname)new NativeComInterfaces.Pathname();
			adsPathname.EscapedMode = 4;
			ReadOnlyDirectoryServerCollection readOnlyDirectoryServerCollection = new ReadOnlyDirectoryServerCollection();
			if (existing)
			{
				Hashtable hashtable = new Hashtable();
				Hashtable hashtable2 = new Hashtable();
				Hashtable hashtable3 = new Hashtable();
				string dn = "CN=Servers," + (string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName);
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
				try
				{
					ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(|(objectCategory=server)(objectCategory=NTDSConnection))", new string[4] { "fromServer", "distinguishedName", "dNSHostName", "objectCategory" }, SearchScope.Subtree, pagedSearch: true, cacheResults: true);
					SearchResultCollection searchResultCollection = null;
					try
					{
						searchResultCollection = aDSearcher.FindAll();
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					try
					{
						foreach (SearchResult item in searchResultCollection)
						{
							string s = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.ObjectCategory);
							if (Utils.Compare(s, 0, "CN=Server".Length, "CN=Server", 0, "CN=Server".Length) == 0)
							{
								hashtable3.Add((string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DistinguishedName), (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsHostName));
							}
						}
						foreach (SearchResult item2 in searchResultCollection)
						{
							string s2 = (string)PropertyManager.GetSearchResultPropertyValue(item2, PropertyManager.ObjectCategory);
							if (Utils.Compare(s2, 0, "CN=Server".Length, "CN=Server", 0, "CN=Server".Length) == 0)
							{
								continue;
							}
							string distinguishedName = (string)PropertyManager.GetSearchResultPropertyValue(item2, PropertyManager.FromServer);
							string partialDN = Utils.GetPartialDN(distinguishedName, 3);
							adsPathname.Set(partialDN, 4);
							partialDN = adsPathname.Retrieve(11);
							partialDN = partialDN.Substring(3);
							string partialDN2 = Utils.GetPartialDN((string)PropertyManager.GetSearchResultPropertyValue(item2, PropertyManager.DistinguishedName), 2);
							if (!hashtable.Contains(partialDN2))
							{
								string value = (string)hashtable3[partialDN2];
								if (!hashtable2.Contains(partialDN2))
								{
									hashtable2.Add(partialDN2, value);
								}
								if (Utils.Compare((string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.Cn), partialDN) != 0)
								{
									hashtable.Add(partialDN2, value);
									hashtable2.Remove(partialDN2);
								}
							}
						}
					}
					finally
					{
						searchResultCollection.Dispose();
					}
				}
				finally
				{
					directoryEntry.Dispose();
				}
				if (hashtable2.Count != 0)
				{
					DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, siteDN);
					StringBuilder stringBuilder = new StringBuilder(100);
					if (hashtable2.Count > 1)
					{
						stringBuilder.Append("(|");
					}
					foreach (DictionaryEntry item3 in hashtable2)
					{
						stringBuilder.Append("(fromServer=");
						stringBuilder.Append("CN=NTDS Settings,");
						stringBuilder.Append(Utils.GetEscapedFilterValue((string)item3.Key));
						stringBuilder.Append(")");
					}
					if (hashtable2.Count > 1)
					{
						stringBuilder.Append(")");
					}
					ADSearcher aDSearcher2 = new ADSearcher(directoryEntry2, "(&(objectClass=nTDSConnection)(objectCategory=NTDSConnection)" + stringBuilder.ToString() + ")", new string[2] { "fromServer", "distinguishedName" }, SearchScope.Subtree);
					SearchResultCollection searchResultCollection2 = null;
					try
					{
						searchResultCollection2 = aDSearcher2.FindAll();
					}
					catch (COMException e2)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
					}
					try
					{
						foreach (SearchResult item4 in searchResultCollection2)
						{
							string text = (string)PropertyManager.GetSearchResultPropertyValue(item4, PropertyManager.FromServer);
							string key = text.Substring(17);
							if (hashtable2.Contains(key))
							{
								string partialDN3 = Utils.GetPartialDN((string)PropertyManager.GetSearchResultPropertyValue(item4, PropertyManager.DistinguishedName), 4);
								adsPathname.Set(partialDN3, 4);
								partialDN3 = adsPathname.Retrieve(11);
								partialDN3 = partialDN3.Substring(3);
								if (Utils.Compare(partialDN3, (string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.Cn)) != 0)
								{
									string value2 = (string)hashtable2[key];
									hashtable2.Remove(key);
									hashtable.Add(key, value2);
								}
							}
						}
					}
					finally
					{
						searchResultCollection2.Dispose();
						directoryEntry2.Dispose();
					}
				}
				DirectoryEntry directoryEntry3 = null;
				{
					foreach (DictionaryEntry item5 in hashtable)
					{
						DirectoryServer directoryServer = null;
						string text2 = (string)item5.Value;
						if (IsADAM)
						{
							directoryEntry3 = DirectoryEntryManager.GetDirectoryEntry(context, "CN=NTDS Settings," + item5.Key);
							int num = (int)PropertyManager.GetPropertyValue(context, directoryEntry3, PropertyManager.MsDSPortLDAP);
							string adamInstanceName = text2;
							if (num != 389)
							{
								adamInstanceName = text2 + ":" + num;
							}
							directoryServer = new AdamInstance(Utils.GetNewDirectoryContext(adamInstanceName, DirectoryContextType.DirectoryServer, context), adamInstanceName);
						}
						else
						{
							directoryServer = new DomainController(Utils.GetNewDirectoryContext(text2, DirectoryContextType.DirectoryServer, context), text2);
						}
						readOnlyDirectoryServerCollection.Add(directoryServer);
					}
					return readOnlyDirectoryServerCollection;
				}
			}
			return readOnlyDirectoryServerCollection;
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, cachedEntry.Path);
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
				if (cachedEntry != null)
				{
					cachedEntry.Dispose();
				}
				if (ntdsEntry != null)
				{
					ntdsEntry.Dispose();
				}
			}
			disposed = true;
		}

		private static void ValidateArgument(DirectoryContext context, string siteName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isServer() && !context.isADAMConfigSet())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
		}

		private void GetSubnets()
		{
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
			string dn = "CN=Subnets,CN=Sites," + text;
			directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=subnet)(objectCategory=subnet)(siteObject=" + Utils.GetEscapedFilterValue((string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName)) + "))", new string[2] { "cn", "location" }, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			try
			{
				string text2 = null;
				foreach (SearchResult item in searchResultCollection)
				{
					text2 = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn);
					ActiveDirectorySubnet activeDirectorySubnet = new ActiveDirectorySubnet(context, text2, null, existing: true);
					activeDirectorySubnet.cachedEntry = item.GetDirectoryEntry();
					activeDirectorySubnet.Site = this;
					subnets.Add(activeDirectorySubnet);
				}
			}
			finally
			{
				searchResultCollection.Dispose();
				directoryEntry.Dispose();
			}
		}

		private void GetAdjacentSites()
		{
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			string text = (string)directoryEntry.Properties["configurationNamingContext"][0];
			string dn = "CN=Inter-Site Transports,CN=Sites," + text;
			directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=siteLink)(objectCategory=SiteLink)(siteList=" + Utils.GetEscapedFilterValue((string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName)) + "))", new string[2] { "cn", "distinguishedName" }, SearchScope.Subtree);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			try
			{
				ActiveDirectorySiteLink activeDirectorySiteLink = null;
				foreach (SearchResult item in searchResultCollection)
				{
					string distinguishedName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DistinguishedName);
					string siteLinkName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn);
					string value = Utils.GetDNComponents(distinguishedName)[1].Value;
					ActiveDirectoryTransportType transport;
					if (string.Compare(value, "IP", StringComparison.OrdinalIgnoreCase) == 0)
					{
						transport = ActiveDirectoryTransportType.Rpc;
					}
					else
					{
						if (string.Compare(value, "SMTP", StringComparison.OrdinalIgnoreCase) != 0)
						{
							string @string = Res.GetString("UnknownTransport", value);
							throw new ActiveDirectoryOperationException(@string);
						}
						transport = ActiveDirectoryTransportType.Smtp;
					}
					try
					{
						activeDirectorySiteLink = new ActiveDirectorySiteLink(context, siteLinkName, transport, existing: true, item.GetDirectoryEntry());
						foreach (ActiveDirectorySite site in activeDirectorySiteLink.Sites)
						{
							if (Utils.Compare(site.Name, Name) != 0 && !adjacentSites.Contains(site))
							{
								adjacentSites.Add(site);
							}
						}
					}
					finally
					{
						activeDirectorySiteLink.Dispose();
					}
				}
			}
			finally
			{
				searchResultCollection.Dispose();
				directoryEntry.Dispose();
			}
		}

		private void GetLinks()
		{
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
			string dn = "CN=Inter-Site Transports,CN=Sites," + text;
			directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=siteLink)(objectCategory=SiteLink)(siteList=" + Utils.GetEscapedFilterValue((string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName)) + "))", new string[2] { "cn", "distinguishedName" }, SearchScope.Subtree);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			try
			{
				foreach (SearchResult item in searchResultCollection)
				{
					DirectoryEntry directoryEntry2 = item.GetDirectoryEntry();
					string siteLinkName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn);
					string value = Utils.GetDNComponents((string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DistinguishedName))[1].Value;
					ActiveDirectorySiteLink activeDirectorySiteLink = null;
					if (string.Compare(value, "IP", StringComparison.OrdinalIgnoreCase) == 0)
					{
						activeDirectorySiteLink = new ActiveDirectorySiteLink(context, siteLinkName, ActiveDirectoryTransportType.Rpc, existing: true, directoryEntry2);
					}
					else
					{
						if (string.Compare(value, "SMTP", StringComparison.OrdinalIgnoreCase) != 0)
						{
							string @string = Res.GetString("UnknownTransport", value);
							throw new ActiveDirectoryOperationException(@string);
						}
						activeDirectorySiteLink = new ActiveDirectorySiteLink(context, siteLinkName, ActiveDirectoryTransportType.Smtp, existing: true, directoryEntry2);
					}
					links.Add(activeDirectorySiteLink);
				}
			}
			finally
			{
				searchResultCollection.Dispose();
				directoryEntry.Dispose();
			}
		}

		private void GetDomains()
		{
			if (IsADAM)
			{
				return;
			}
			string currentServerName = cachedEntry.Options.GetCurrentServerName();
			DomainController domainController = DomainController.GetDomainController(Utils.GetNewDirectoryContext(currentServerName, DirectoryContextType.DirectoryServer, context));
			IntPtr handle = domainController.Handle;
			IntPtr info = (IntPtr)0;
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsListDomainsInSiteW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			UnsafeNativeMethods.DsListDomainsInSiteW dsListDomainsInSiteW = (UnsafeNativeMethods.DsListDomainsInSiteW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsListDomainsInSiteW));
			int num = dsListDomainsInSiteW(handle, (string)PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName), ref info);
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num, currentServerName);
			}
			try
			{
				DS_NAME_RESULT dS_NAME_RESULT = new DS_NAME_RESULT();
				Marshal.PtrToStructure(info, dS_NAME_RESULT);
				int cItems = dS_NAME_RESULT.cItems;
				IntPtr rItems = dS_NAME_RESULT.rItems;
				if (cItems <= 0)
				{
					return;
				}
				Marshal.ReadInt32(rItems);
				IntPtr intPtr = (IntPtr)0;
				for (int i = 0; i < cItems; i++)
				{
					intPtr = Utils.AddToIntPtr(rItems, Marshal.SizeOf(typeof(DS_NAME_RESULT_ITEM)) * i);
					DS_NAME_RESULT_ITEM dS_NAME_RESULT_ITEM = new DS_NAME_RESULT_ITEM();
					Marshal.PtrToStructure(intPtr, dS_NAME_RESULT_ITEM);
					if (dS_NAME_RESULT_ITEM.status == DS_NAME_ERROR.DS_NAME_NO_ERROR || dS_NAME_RESULT_ITEM.status == DS_NAME_ERROR.DS_NAME_ERROR_DOMAIN_ONLY)
					{
						string text = Marshal.PtrToStringUni(dS_NAME_RESULT_ITEM.pName);
						if (text != null && text.Length > 0)
						{
							string dnsNameFromDN = Utils.GetDnsNameFromDN(text);
							Domain domain = new Domain(Utils.GetNewDirectoryContext(dnsNameFromDN, DirectoryContextType.Domain, context), dnsNameFromDN);
							domains.Add(domain);
						}
					}
				}
			}
			finally
			{
				procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsFreeNameResultW");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				UnsafeNativeMethods.DsFreeNameResultW dsFreeNameResultW = (UnsafeNativeMethods.DsFreeNameResultW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsFreeNameResultW));
				dsFreeNameResultW(info);
			}
		}

		private void GetServers()
		{
			ADSearcher aDSearcher = new ADSearcher(cachedEntry, "(&(objectClass=server)(objectCategory=server))", new string[1] { "dNSHostName" }, SearchScope.Subtree);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			try
			{
				foreach (SearchResult item in searchResultCollection)
				{
					string text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsHostName);
					DirectoryEntry directoryEntry = item.GetDirectoryEntry();
					DirectoryEntry directoryEntry2 = null;
					DirectoryServer directoryServer = null;
					try
					{
						directoryEntry2 = directoryEntry.Children.Find("CN=NTDS Settings", "nTDSDSA");
					}
					catch (COMException ex)
					{
						if (ex.ErrorCode == -2147016656)
						{
							continue;
						}
						throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
					}
					if (IsADAM)
					{
						int num = (int)PropertyManager.GetPropertyValue(context, directoryEntry2, PropertyManager.MsDSPortLDAP);
						string adamInstanceName = text;
						if (num != 389)
						{
							adamInstanceName = text + ":" + num;
						}
						directoryServer = new AdamInstance(Utils.GetNewDirectoryContext(adamInstanceName, DirectoryContextType.DirectoryServer, context), adamInstanceName);
					}
					else
					{
						directoryServer = new DomainController(Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context), text);
					}
					servers.Add(directoryServer);
				}
			}
			finally
			{
				searchResultCollection.Dispose();
			}
		}

		private void GetPreferredBridgeheadServers(ActiveDirectoryTransportType transport)
		{
			string dn = "CN=Servers," + PropertyManager.GetPropertyValue(context, cachedEntry, PropertyManager.DistinguishedName);
			string text = null;
			text = ((transport != ActiveDirectoryTransportType.Smtp) ? ("CN=IP,CN=Inter-Site Transports," + siteDN) : ("CN=SMTP,CN=Inter-Site Transports," + siteDN));
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=server)(objectCategory=Server)(bridgeheadTransportList=" + Utils.GetEscapedFilterValue(text) + "))", new string[2] { "dNSHostName", "distinguishedName" }, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			try
			{
				DirectoryEntry directoryEntry2 = null;
				foreach (SearchResult item in searchResultCollection)
				{
					string text2 = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsHostName);
					DirectoryEntry directoryEntry3 = item.GetDirectoryEntry();
					DirectoryServer directoryServer = null;
					try
					{
						directoryEntry2 = directoryEntry3.Children.Find("CN=NTDS Settings", "nTDSDSA");
					}
					catch (COMException e2)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
					}
					if (IsADAM)
					{
						int num = (int)PropertyManager.GetPropertyValue(context, directoryEntry2, PropertyManager.MsDSPortLDAP);
						string adamInstanceName = text2;
						if (num != 389)
						{
							adamInstanceName = text2 + ":" + num;
						}
						directoryServer = new AdamInstance(Utils.GetNewDirectoryContext(adamInstanceName, DirectoryContextType.DirectoryServer, context), adamInstanceName);
					}
					else
					{
						directoryServer = new DomainController(Utils.GetNewDirectoryContext(text2, DirectoryContextType.DirectoryServer, context), text2);
					}
					if (transport == ActiveDirectoryTransportType.Smtp)
					{
						SMTPBridgeheadServers.Add(directoryServer);
					}
					else
					{
						RPCBridgeheadServers.Add(directoryServer);
					}
				}
			}
			finally
			{
				directoryEntry.Dispose();
				searchResultCollection.Dispose();
			}
		}
	}
	public class ActiveDirectorySiteCollection : CollectionBase
	{
		internal DirectoryEntry de;

		internal bool initialized;

		internal DirectoryContext context;

		public ActiveDirectorySite this[int index]
		{
			get
			{
				return (ActiveDirectorySite)base.InnerList[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!value.existing)
				{
					throw new InvalidOperationException(Res.GetString("SiteNotCommitted", value.Name));
				}
				if (!Contains(value))
				{
					base.List[index] = value;
					return;
				}
				throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", value), "value");
			}
		}

		internal ActiveDirectorySiteCollection()
		{
		}

		internal ActiveDirectorySiteCollection(ArrayList sites)
		{
			for (int i = 0; i < sites.Count; i++)
			{
				Add((ActiveDirectorySite)sites[i]);
			}
		}

		public int Add(ActiveDirectorySite site)
		{
			if (site == null)
			{
				throw new ArgumentNullException("site");
			}
			if (!site.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteNotCommitted", site.Name));
			}
			if (!Contains(site))
			{
				return base.List.Add(site);
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", site), "site");
		}

		public void AddRange(ActiveDirectorySite[] sites)
		{
			if (sites == null)
			{
				throw new ArgumentNullException("sites");
			}
			for (int i = 0; i < sites.Length; i++)
			{
				Add(sites[i]);
			}
		}

		public void AddRange(ActiveDirectorySiteCollection sites)
		{
			if (sites == null)
			{
				throw new ArgumentNullException("sites");
			}
			int count = sites.Count;
			for (int i = 0; i < count; i++)
			{
				Add(sites[i]);
			}
		}

		public bool Contains(ActiveDirectorySite site)
		{
			if (site == null)
			{
				throw new ArgumentNullException("site");
			}
			if (!site.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteNotCommitted", site.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(site.context, site.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public void CopyTo(ActiveDirectorySite[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(ActiveDirectorySite site)
		{
			if (site == null)
			{
				throw new ArgumentNullException("site");
			}
			if (!site.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteNotCommitted", site.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(site.context, site.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void Insert(int index, ActiveDirectorySite site)
		{
			if (site == null)
			{
				throw new ArgumentNullException("site");
			}
			if (!site.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteNotCommitted", site.Name));
			}
			if (!Contains(site))
			{
				base.List.Insert(index, site);
				return;
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", site), "site");
		}

		public void Remove(ActiveDirectorySite site)
		{
			if (site == null)
			{
				throw new ArgumentNullException("site");
			}
			if (!site.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteNotCommitted", site.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(site.context, site.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					base.List.Remove(activeDirectorySite);
					return;
				}
			}
			throw new ArgumentException(Res.GetString("NotFoundInCollection", site), "site");
		}

		protected override void OnClearComplete()
		{
			if (!initialized)
			{
				return;
			}
			try
			{
				if (de.Properties.Contains("siteList"))
				{
					de.Properties["siteList"].Clear();
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnInsertComplete(int index, object value)
		{
			if (initialized)
			{
				ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)value;
				string value2 = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
				try
				{
					de.Properties["siteList"].Add(value2);
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		protected override void OnRemoveComplete(int index, object value)
		{
			ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)value;
			string value2 = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
			try
			{
				de.Properties["siteList"].Remove(value2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnSetComplete(int index, object oldValue, object newValue)
		{
			ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)newValue;
			string value = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
			try
			{
				de.Properties["siteList"][index] = value;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is ActiveDirectorySite))
			{
				throw new ArgumentException("value");
			}
			if (!((ActiveDirectorySite)value).existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteNotCommitted", ((ActiveDirectorySite)value).Name));
			}
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectorySiteLink : IDisposable
	{
		private const int systemDefaultCost = 0;

		private const int appDefaultCost = 100;

		private const int appDefaultInterval = 180;

		internal DirectoryContext context;

		private string name;

		private ActiveDirectoryTransportType transport;

		private bool disposed;

		internal bool existing;

		internal DirectoryEntry cachedEntry;

		private TimeSpan systemDefaultInterval = new TimeSpan(0, 15, 0);

		private ActiveDirectorySiteCollection sites = new ActiveDirectorySiteCollection();

		private bool siteRetrieved;

		public string Name
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return name;
			}
		}

		public ActiveDirectoryTransportType TransportType
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return transport;
			}
		}

		public ActiveDirectorySiteCollection Sites
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !siteRetrieved)
				{
					sites.initialized = false;
					sites.Clear();
					GetSites();
					siteRetrieved = true;
				}
				sites.initialized = true;
				sites.de = cachedEntry;
				sites.context = context;
				return sites;
			}
		}

		public int Cost
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (cachedEntry.Properties.Contains("cost"))
					{
						return (int)cachedEntry.Properties["cost"][0];
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				return 0;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (value < 0)
				{
					throw new ArgumentException("value");
				}
				try
				{
					cachedEntry.Properties["cost"].Value = value;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public TimeSpan ReplicationInterval
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (cachedEntry.Properties.Contains("replInterval"))
					{
						int minutes = (int)cachedEntry.Properties["replInterval"][0];
						return new TimeSpan(0, minutes, 0);
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				return systemDefaultInterval;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (value < TimeSpan.Zero)
				{
					throw new ArgumentException(Res.GetString("NoNegativeTime"), "value");
				}
				double totalMinutes = value.TotalMinutes;
				if (totalMinutes > 2147483647.0)
				{
					throw new ArgumentException(Res.GetString("ReplicationIntervalExceedMax"), "value");
				}
				int num = (int)totalMinutes;
				if ((double)num < totalMinutes)
				{
					throw new ArgumentException(Res.GetString("ReplicationIntervalInMinutes"), "value");
				}
				try
				{
					cachedEntry.Properties["replInterval"].Value = num;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public bool ReciprocalReplicationEnabled
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count != 0)
				{
					num = (int)propertyValueCollection[0];
				}
				if ((num & 2) == 0)
				{
					return false;
				}
				return true;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedEntry.Properties["options"];
					if (propertyValueCollection.Count != 0)
					{
						num = (int)propertyValueCollection[0];
					}
					num = ((!value) ? (num & -3) : (num | 2));
					cachedEntry.Properties["options"].Value = num;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public bool NotificationEnabled
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count != 0)
				{
					num = (int)propertyValueCollection[0];
				}
				if ((num & 1) == 0)
				{
					return false;
				}
				return true;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedEntry.Properties["options"];
					if (propertyValueCollection.Count != 0)
					{
						num = (int)propertyValueCollection[0];
					}
					num = ((!value) ? (num & -2) : (num | 1));
					cachedEntry.Properties["options"].Value = num;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public bool DataCompressionEnabled
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count != 0)
				{
					num = (int)propertyValueCollection[0];
				}
				if ((num & 4) == 0)
				{
					return true;
				}
				return false;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedEntry.Properties["options"];
					if (propertyValueCollection.Count != 0)
					{
						num = (int)propertyValueCollection[0];
					}
					num = (value ? (num & -5) : (num | 4));
					cachedEntry.Properties["options"].Value = num;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public ActiveDirectorySchedule InterSiteReplicationSchedule
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				ActiveDirectorySchedule result = null;
				try
				{
					if (cachedEntry.Properties.Contains("schedule"))
					{
						byte[] unmanagedSchedule = (byte[])cachedEntry.Properties["schedule"][0];
						result = new ActiveDirectorySchedule();
						result.SetUnmanagedSchedule(unmanagedSchedule);
						return result;
					}
					return result;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (value == null)
					{
						if (cachedEntry.Properties.Contains("schedule"))
						{
							cachedEntry.Properties["schedule"].Clear();
						}
					}
					else
					{
						cachedEntry.Properties["schedule"].Value = value.GetUnmanagedSchedule();
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public ActiveDirectorySiteLink(DirectoryContext context, string siteLinkName)
			: this(context, siteLinkName, ActiveDirectoryTransportType.Rpc, null)
		{
		}

		public ActiveDirectorySiteLink(DirectoryContext context, string siteLinkName, ActiveDirectoryTransportType transport)
			: this(context, siteLinkName, transport, null)
		{
		}

		public ActiveDirectorySiteLink(DirectoryContext context, string siteLinkName, ActiveDirectoryTransportType transport, ActiveDirectorySchedule schedule)
		{
			ValidateArgument(context, siteLinkName, transport);
			context = new DirectoryContext(context);
			this.context = context;
			name = siteLinkName;
			this.transport = transport;
			DirectoryEntry directoryEntry;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				string text2 = null;
				text2 = ((transport != 0) ? ("CN=SMTP,CN=Inter-Site Transports,CN=Sites," + text) : ("CN=IP,CN=Inter-Site Transports,CN=Sites," + text));
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			try
			{
				string originalPath = "cn=" + name;
				originalPath = Utils.GetEscapedPath(originalPath);
				cachedEntry = directoryEntry.Children.Add(originalPath, "siteLink");
				cachedEntry.Properties["cost"].Value = 100;
				cachedEntry.Properties["replInterval"].Value = 180;
				if (schedule != null)
				{
					cachedEntry.Properties["schedule"].Value = schedule.GetUnmanagedSchedule();
				}
			}
			catch (COMException ex2)
			{
				if (ex2.ErrorCode == -2147016656)
				{
					DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					if (Utils.CheckCapability(directoryEntry2, Capability.ActiveDirectoryApplicationMode) && transport == ActiveDirectoryTransportType.Smtp)
					{
						throw new NotSupportedException(Res.GetString("NotSupportTransportSMTP"));
					}
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		internal ActiveDirectorySiteLink(DirectoryContext context, string siteLinkName, ActiveDirectoryTransportType transport, bool existing, DirectoryEntry entry)
		{
			this.context = context;
			name = siteLinkName;
			this.transport = transport;
			this.existing = existing;
			cachedEntry = entry;
		}

		public static ActiveDirectorySiteLink FindByName(DirectoryContext context, string siteLinkName)
		{
			return FindByName(context, siteLinkName, ActiveDirectoryTransportType.Rpc);
		}

		public static ActiveDirectorySiteLink FindByName(DirectoryContext context, string siteLinkName, ActiveDirectoryTransportType transport)
		{
			ValidateArgument(context, siteLinkName, transport);
			context = new DirectoryContext(context);
			DirectoryEntry directoryEntry;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				string text2 = "CN=Inter-Site Transports,CN=Sites," + text;
				text2 = ((transport != 0) ? ("CN=SMTP," + text2) : ("CN=IP," + text2));
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			try
			{
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=siteLink)(objectCategory=SiteLink)(name=" + Utils.GetEscapedFilterValue(siteLinkName) + "))", new string[1] { "distinguishedName" }, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
				SearchResult searchResult = aDSearcher.FindOne();
				if (searchResult == null)
				{
					Exception ex2 = new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySiteLink), siteLinkName);
					throw ex2;
				}
				DirectoryEntry directoryEntry2 = searchResult.GetDirectoryEntry();
				return new ActiveDirectorySiteLink(context, siteLinkName, transport, existing: true, directoryEntry2);
			}
			catch (COMException ex3)
			{
				if (ex3.ErrorCode == -2147016656)
				{
					DirectoryEntry directoryEntry3 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					if (Utils.CheckCapability(directoryEntry3, Capability.ActiveDirectoryApplicationMode) && transport == ActiveDirectoryTransportType.Smtp)
					{
						throw new NotSupportedException(Res.GetString("NotSupportTransportSMTP"));
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySiteLink), siteLinkName);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex3);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		public void Save()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				cachedEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			if (existing)
			{
				siteRetrieved = false;
			}
			else
			{
				existing = true;
			}
		}

		public void Delete()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotDelete"));
			}
			try
			{
				cachedEntry.Parent.Children.Remove(cachedEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public override string ToString()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			return name;
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, cachedEntry.Path);
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing && cachedEntry != null)
			{
				cachedEntry.Dispose();
			}
			disposed = true;
		}

		private static void ValidateArgument(DirectoryContext context, string siteLinkName, ActiveDirectoryTransportType transport)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isServer() && !context.isADAMConfigSet())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (siteLinkName == null)
			{
				throw new ArgumentNullException("siteLinkName");
			}
			if (siteLinkName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteLinkName");
			}
			if (transport < ActiveDirectoryTransportType.Rpc || transport > ActiveDirectoryTransportType.Smtp)
			{
				throw new InvalidEnumArgumentException("value", (int)transport, typeof(ActiveDirectoryTransportType));
			}
		}

		private void GetSites()
		{
			NativeComInterfaces.IAdsPathname adsPathname = null;
			adsPathname = (NativeComInterfaces.IAdsPathname)new NativeComInterfaces.Pathname();
			ArrayList arrayList = new ArrayList();
			adsPathname.EscapedMode = 4;
			string text = "siteList";
			arrayList.Add(text);
			Hashtable valuesWithRangeRetrieval = Utils.GetValuesWithRangeRetrieval(cachedEntry, "(objectClass=*)", arrayList, SearchScope.Base);
			ArrayList arrayList2 = (ArrayList)valuesWithRangeRetrieval[text.ToLower(CultureInfo.InvariantCulture)];
			if (arrayList2 != null)
			{
				for (int i = 0; i < arrayList2.Count; i++)
				{
					string bstrADsPath = (string)arrayList2[i];
					adsPathname.Set(bstrADsPath, 4);
					string text2 = adsPathname.Retrieve(11);
					text2 = text2.Substring(3);
					ActiveDirectorySite site = new ActiveDirectorySite(context, text2, existing: true);
					sites.Add(site);
				}
			}
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectorySiteLinkBridge : IDisposable
	{
		internal DirectoryContext context;

		private string name;

		private ActiveDirectoryTransportType transport;

		private bool disposed;

		private bool existing;

		internal DirectoryEntry cachedEntry;

		private ActiveDirectorySiteLinkCollection links = new ActiveDirectorySiteLinkCollection();

		private bool linksRetrieved;

		public string Name
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return name;
			}
		}

		public ActiveDirectorySiteLinkCollection SiteLinks
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existing && !linksRetrieved)
				{
					links.initialized = false;
					links.Clear();
					GetLinks();
					linksRetrieved = true;
				}
				links.initialized = true;
				links.de = cachedEntry;
				links.context = context;
				return links;
			}
		}

		public ActiveDirectoryTransportType TransportType
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return transport;
			}
		}

		public ActiveDirectorySiteLinkBridge(DirectoryContext context, string bridgeName)
			: this(context, bridgeName, ActiveDirectoryTransportType.Rpc)
		{
		}

		public ActiveDirectorySiteLinkBridge(DirectoryContext context, string bridgeName, ActiveDirectoryTransportType transport)
		{
			ValidateArgument(context, bridgeName, transport);
			context = new DirectoryContext(context);
			this.context = context;
			name = bridgeName;
			this.transport = transport;
			DirectoryEntry directoryEntry;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				string text2 = null;
				text2 = ((transport != 0) ? ("CN=SMTP,CN=Inter-Site Transports,CN=Sites," + text) : ("CN=IP,CN=Inter-Site Transports,CN=Sites," + text));
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			try
			{
				string originalPath = "cn=" + name;
				originalPath = Utils.GetEscapedPath(originalPath);
				cachedEntry = directoryEntry.Children.Add(originalPath, "siteLinkBridge");
			}
			catch (COMException ex2)
			{
				if (ex2.ErrorCode == -2147016656)
				{
					DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					if (Utils.CheckCapability(directoryEntry2, Capability.ActiveDirectoryApplicationMode) && transport == ActiveDirectoryTransportType.Smtp)
					{
						throw new NotSupportedException(Res.GetString("NotSupportTransportSMTP"));
					}
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		internal ActiveDirectorySiteLinkBridge(DirectoryContext context, string bridgeName, ActiveDirectoryTransportType transport, bool existing)
		{
			this.context = context;
			name = bridgeName;
			this.transport = transport;
			this.existing = existing;
		}

		public static ActiveDirectorySiteLinkBridge FindByName(DirectoryContext context, string bridgeName)
		{
			return FindByName(context, bridgeName, ActiveDirectoryTransportType.Rpc);
		}

		public static ActiveDirectorySiteLinkBridge FindByName(DirectoryContext context, string bridgeName, ActiveDirectoryTransportType transport)
		{
			ValidateArgument(context, bridgeName, transport);
			context = new DirectoryContext(context);
			DirectoryEntry directoryEntry;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				string text2 = "CN=Inter-Site Transports,CN=Sites," + text;
				text2 = ((transport != 0) ? ("CN=SMTP," + text2) : ("CN=IP," + text2));
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			try
			{
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=siteLinkBridge)(objectCategory=SiteLinkBridge)(name=" + Utils.GetEscapedFilterValue(bridgeName) + "))", new string[1] { "distinguishedName" }, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
				SearchResult searchResult = aDSearcher.FindOne();
				if (searchResult == null)
				{
					Exception ex2 = new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySiteLinkBridge), bridgeName);
					throw ex2;
				}
				DirectoryEntry directoryEntry2 = searchResult.GetDirectoryEntry();
				ActiveDirectorySiteLinkBridge activeDirectorySiteLinkBridge = new ActiveDirectorySiteLinkBridge(context, bridgeName, transport, existing: true);
				activeDirectorySiteLinkBridge.cachedEntry = directoryEntry2;
				return activeDirectorySiteLinkBridge;
			}
			catch (COMException ex3)
			{
				if (ex3.ErrorCode == -2147016656)
				{
					DirectoryEntry directoryEntry3 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					if (Utils.CheckCapability(directoryEntry3, Capability.ActiveDirectoryApplicationMode) && transport == ActiveDirectoryTransportType.Smtp)
					{
						throw new NotSupportedException(Res.GetString("NotSupportTransportSMTP"));
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySiteLinkBridge), bridgeName);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex3);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		public void Save()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				cachedEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			if (existing)
			{
				linksRetrieved = false;
			}
			else
			{
				existing = true;
			}
		}

		public void Delete()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotDelete"));
			}
			try
			{
				cachedEntry.Parent.Children.Remove(cachedEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public override string ToString()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			return name;
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, cachedEntry.Path);
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing && cachedEntry != null)
			{
				cachedEntry.Dispose();
			}
			disposed = true;
		}

		private static void ValidateArgument(DirectoryContext context, string bridgeName, ActiveDirectoryTransportType transport)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isServer() && !context.isADAMConfigSet())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (bridgeName == null)
			{
				throw new ArgumentNullException("bridgeName");
			}
			if (bridgeName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "bridgeName");
			}
			if (transport < ActiveDirectoryTransportType.Rpc || transport > ActiveDirectoryTransportType.Smtp)
			{
				throw new InvalidEnumArgumentException("value", (int)transport, typeof(ActiveDirectoryTransportType));
			}
		}

		private void GetLinks()
		{
			ArrayList arrayList = new ArrayList();
			NativeComInterfaces.IAdsPathname adsPathname = null;
			adsPathname = (NativeComInterfaces.IAdsPathname)new NativeComInterfaces.Pathname();
			adsPathname.EscapedMode = 4;
			string text = "siteLinkList";
			arrayList.Add(text);
			Hashtable valuesWithRangeRetrieval = Utils.GetValuesWithRangeRetrieval(cachedEntry, "(objectClass=*)", arrayList, SearchScope.Base);
			ArrayList arrayList2 = (ArrayList)valuesWithRangeRetrieval[text.ToLower(CultureInfo.InvariantCulture)];
			if (arrayList2 != null)
			{
				for (int i = 0; i < arrayList2.Count; i++)
				{
					string text2 = (string)arrayList2[i];
					adsPathname.Set(text2, 4);
					string text3 = adsPathname.Retrieve(11);
					text3 = text3.Substring(3);
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text2);
					ActiveDirectorySiteLink link = new ActiveDirectorySiteLink(context, text3, transport, existing: true, directoryEntry);
					links.Add(link);
				}
			}
		}
	}
	public class ActiveDirectorySiteLinkCollection : CollectionBase
	{
		internal DirectoryEntry de;

		internal bool initialized;

		internal DirectoryContext context;

		public ActiveDirectorySiteLink this[int index]
		{
			get
			{
				return (ActiveDirectorySiteLink)base.InnerList[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!value.existing)
				{
					throw new InvalidOperationException(Res.GetString("SiteLinkNotCommitted", value.Name));
				}
				if (!Contains(value))
				{
					base.List[index] = value;
					return;
				}
				throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", value), "value");
			}
		}

		internal ActiveDirectorySiteLinkCollection()
		{
		}

		public int Add(ActiveDirectorySiteLink link)
		{
			if (link == null)
			{
				throw new ArgumentNullException("link");
			}
			if (!link.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteLinkNotCommitted", link.Name));
			}
			if (!Contains(link))
			{
				return base.List.Add(link);
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", link), "link");
		}

		public void AddRange(ActiveDirectorySiteLink[] links)
		{
			if (links == null)
			{
				throw new ArgumentNullException("links");
			}
			for (int i = 0; i < links.Length; i++)
			{
				Add(links[i]);
			}
		}

		public void AddRange(ActiveDirectorySiteLinkCollection links)
		{
			if (links == null)
			{
				throw new ArgumentNullException("links");
			}
			int count = links.Count;
			for (int i = 0; i < count; i++)
			{
				Add(links[i]);
			}
		}

		public bool Contains(ActiveDirectorySiteLink link)
		{
			if (link == null)
			{
				throw new ArgumentNullException("link");
			}
			if (!link.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteLinkNotCommitted", link.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(link.context, link.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public void CopyTo(ActiveDirectorySiteLink[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(ActiveDirectorySiteLink link)
		{
			if (link == null)
			{
				throw new ArgumentNullException("link");
			}
			if (!link.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteLinkNotCommitted", link.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(link.context, link.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void Insert(int index, ActiveDirectorySiteLink link)
		{
			if (link == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!link.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteLinkNotCommitted", link.Name));
			}
			if (!Contains(link))
			{
				base.List.Insert(index, link);
				return;
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", link), "link");
		}

		public void Remove(ActiveDirectorySiteLink link)
		{
			if (link == null)
			{
				throw new ArgumentNullException("link");
			}
			if (!link.existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteLinkNotCommitted", link.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(link.context, link.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					base.List.Remove(activeDirectorySiteLink);
					return;
				}
			}
			throw new ArgumentException(Res.GetString("NotFoundInCollection", link), "link");
		}

		protected override void OnClearComplete()
		{
			if (!initialized)
			{
				return;
			}
			try
			{
				if (de.Properties.Contains("siteLinkList"))
				{
					de.Properties["siteLinkList"].Clear();
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnInsertComplete(int index, object value)
		{
			if (initialized)
			{
				ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)value;
				string value2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
				try
				{
					de.Properties["siteLinkList"].Add(value2);
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		protected override void OnRemoveComplete(int index, object value)
		{
			ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)value;
			string value2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
			try
			{
				de.Properties["siteLinkList"].Remove(value2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnSetComplete(int index, object oldValue, object newValue)
		{
			ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)newValue;
			string value = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
			try
			{
				de.Properties["siteLinkList"][index] = value;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is ActiveDirectorySiteLink))
			{
				throw new ArgumentException("value");
			}
			if (!((ActiveDirectorySiteLink)value).existing)
			{
				throw new InvalidOperationException(Res.GetString("SiteLinkNotCommitted", ((ActiveDirectorySiteLink)value).Name));
			}
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectorySubnet : IDisposable
	{
		private ActiveDirectorySite site;

		private string name;

		internal DirectoryContext context;

		private bool disposed;

		internal bool existing;

		internal DirectoryEntry cachedEntry;

		public string Name
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return name;
			}
		}

		public ActiveDirectorySite Site
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return site;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (value != null && !value.existing)
				{
					throw new InvalidOperationException(Res.GetString("SiteNotCommitted", value));
				}
				site = value;
			}
		}

		public string Location
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (cachedEntry.Properties.Contains("location"))
					{
						return (string)cachedEntry.Properties["location"][0];
					}
					return null;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (value == null)
					{
						if (cachedEntry.Properties.Contains("location"))
						{
							cachedEntry.Properties["location"].Clear();
						}
					}
					else
					{
						cachedEntry.Properties["location"].Value = value;
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public static ActiveDirectorySubnet FindByName(DirectoryContext context, string subnetName)
		{
			ValidateArgument(context, subnetName);
			context = new DirectoryContext(context);
			DirectoryEntry directoryEntry;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				string dn = "CN=Subnets,CN=Sites," + text;
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			try
			{
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=subnet)(objectCategory=subnet)(name=" + Utils.GetEscapedFilterValue(subnetName) + "))", new string[1] { "distinguishedName" }, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
				SearchResult searchResult = aDSearcher.FindOne();
				if (searchResult == null)
				{
					Exception ex2 = new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySubnet), subnetName);
					throw ex2;
				}
				string text2 = null;
				DirectoryEntry directoryEntry2 = searchResult.GetDirectoryEntry();
				if (directoryEntry2.Properties.Contains("siteObject"))
				{
					NativeComInterfaces.IAdsPathname adsPathname = (NativeComInterfaces.IAdsPathname)new NativeComInterfaces.Pathname();
					adsPathname.EscapedMode = 4;
					string bstrADsPath = (string)directoryEntry2.Properties["siteObject"][0];
					adsPathname.Set(bstrADsPath, 4);
					string text3 = adsPathname.Retrieve(11);
					text2 = text3.Substring(3);
				}
				ActiveDirectorySubnet activeDirectorySubnet = null;
				activeDirectorySubnet = ((text2 != null) ? new ActiveDirectorySubnet(context, subnetName, text2, existing: true) : new ActiveDirectorySubnet(context, subnetName, null, existing: true));
				activeDirectorySubnet.cachedEntry = directoryEntry2;
				return activeDirectorySubnet;
			}
			catch (COMException ex3)
			{
				if (ex3.ErrorCode == -2147016656)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ActiveDirectorySubnet), subnetName);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex3);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
		}

		public ActiveDirectorySubnet(DirectoryContext context, string subnetName)
		{
			ValidateArgument(context, subnetName);
			context = new DirectoryContext(context);
			this.context = context;
			name = subnetName;
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				string dn = "CN=Subnets,CN=Sites," + text;
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
				string originalPath = "cn=" + name;
				originalPath = Utils.GetEscapedPath(originalPath);
				cachedEntry = directoryEntry.Children.Add(originalPath, "subnet");
			}
			catch (COMException e)
			{
				ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			finally
			{
				directoryEntry?.Dispose();
			}
		}

		public ActiveDirectorySubnet(DirectoryContext context, string subnetName, string siteName)
			: this(context, subnetName)
		{
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			try
			{
				site = ActiveDirectorySite.FindByName(this.context, siteName);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ArgumentException(Res.GetString("SiteNotExist", siteName), "siteName");
			}
		}

		internal ActiveDirectorySubnet(DirectoryContext context, string subnetName, string siteName, bool existing)
		{
			this.context = context;
			name = subnetName;
			if (siteName != null)
			{
				try
				{
					site = ActiveDirectorySite.FindByName(context, siteName);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ArgumentException(Res.GetString("SiteNotExist", siteName), "siteName");
				}
			}
			this.existing = true;
		}

		public void Save()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				if (existing)
				{
					if (site == null)
					{
						if (cachedEntry.Properties.Contains("siteObject"))
						{
							cachedEntry.Properties["siteObject"].Clear();
						}
					}
					else
					{
						cachedEntry.Properties["siteObject"].Value = site.cachedEntry.Properties["distinguishedName"][0];
					}
					cachedEntry.CommitChanges();
				}
				else
				{
					if (Site != null)
					{
						cachedEntry.Properties["siteObject"].Add(site.cachedEntry.Properties["distinguishedName"][0]);
					}
					cachedEntry.CommitChanges();
					existing = true;
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public void Delete()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotDelete"));
			}
			try
			{
				cachedEntry.Parent.Children.Remove(cachedEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public override string ToString()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			return Name;
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existing)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, cachedEntry.Path);
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing && cachedEntry != null)
			{
				cachedEntry.Dispose();
			}
			disposed = true;
		}

		private static void ValidateArgument(DirectoryContext context, string subnetName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isServer() && !context.isADAMConfigSet())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (subnetName == null)
			{
				throw new ArgumentNullException("subnetName");
			}
			if (subnetName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "subnetName");
			}
		}
	}
	public class ActiveDirectorySubnetCollection : CollectionBase
	{
		internal Hashtable changeList;

		internal bool initialized;

		private string siteDN;

		private DirectoryContext context;

		private ArrayList copyList = new ArrayList();

		public ActiveDirectorySubnet this[int index]
		{
			get
			{
				return (ActiveDirectorySubnet)base.InnerList[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!value.existing)
				{
					throw new InvalidOperationException(Res.GetString("SubnetNotCommitted", value.Name));
				}
				if (!Contains(value))
				{
					base.List[index] = value;
					return;
				}
				throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", value), "value");
			}
		}

		internal ActiveDirectorySubnetCollection(DirectoryContext context, string siteDN)
		{
			this.context = context;
			this.siteDN = siteDN;
			Hashtable table = new Hashtable();
			changeList = Hashtable.Synchronized(table);
		}

		public int Add(ActiveDirectorySubnet subnet)
		{
			if (subnet == null)
			{
				throw new ArgumentNullException("subnet");
			}
			if (!subnet.existing)
			{
				throw new InvalidOperationException(Res.GetString("SubnetNotCommitted", subnet.Name));
			}
			if (!Contains(subnet))
			{
				return base.List.Add(subnet);
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", subnet), "subnet");
		}

		public void AddRange(ActiveDirectorySubnet[] subnets)
		{
			if (subnets == null)
			{
				throw new ArgumentNullException("subnets");
			}
			foreach (ActiveDirectorySubnet activeDirectorySubnet in subnets)
			{
				if (activeDirectorySubnet == null)
				{
					throw new ArgumentException("subnets");
				}
			}
			for (int j = 0; j < subnets.Length; j++)
			{
				Add(subnets[j]);
			}
		}

		public void AddRange(ActiveDirectorySubnetCollection subnets)
		{
			if (subnets == null)
			{
				throw new ArgumentNullException("subnets");
			}
			int count = subnets.Count;
			for (int i = 0; i < count; i++)
			{
				Add(subnets[i]);
			}
		}

		public bool Contains(ActiveDirectorySubnet subnet)
		{
			if (subnet == null)
			{
				throw new ArgumentNullException("subnet");
			}
			if (!subnet.existing)
			{
				throw new InvalidOperationException(Res.GetString("SubnetNotCommitted", subnet.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(subnet.context, subnet.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySubnet activeDirectorySubnet = (ActiveDirectorySubnet)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySubnet.context, activeDirectorySubnet.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public void CopyTo(ActiveDirectorySubnet[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(ActiveDirectorySubnet subnet)
		{
			if (subnet == null)
			{
				throw new ArgumentNullException("subnet");
			}
			if (!subnet.existing)
			{
				throw new InvalidOperationException(Res.GetString("SubnetNotCommitted", subnet.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(subnet.context, subnet.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySubnet activeDirectorySubnet = (ActiveDirectorySubnet)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySubnet.context, activeDirectorySubnet.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void Insert(int index, ActiveDirectorySubnet subnet)
		{
			if (subnet == null)
			{
				throw new ArgumentNullException("subnet");
			}
			if (!subnet.existing)
			{
				throw new InvalidOperationException(Res.GetString("SubnetNotCommitted", subnet.Name));
			}
			if (!Contains(subnet))
			{
				base.List.Insert(index, subnet);
				return;
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", subnet), "subnet");
		}

		public void Remove(ActiveDirectorySubnet subnet)
		{
			if (subnet == null)
			{
				throw new ArgumentNullException("subnet");
			}
			if (!subnet.existing)
			{
				throw new InvalidOperationException(Res.GetString("SubnetNotCommitted", subnet.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(subnet.context, subnet.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySubnet activeDirectorySubnet = (ActiveDirectorySubnet)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySubnet.context, activeDirectorySubnet.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					base.List.Remove(activeDirectorySubnet);
					return;
				}
			}
			throw new ArgumentException(Res.GetString("NotFoundInCollection", subnet), "subnet");
		}

		protected override void OnClear()
		{
			if (!initialized)
			{
				return;
			}
			copyList.Clear();
			foreach (object item in base.List)
			{
				copyList.Add(item);
			}
		}

		protected override void OnClearComplete()
		{
			if (initialized)
			{
				for (int i = 0; i < copyList.Count; i++)
				{
					OnRemoveComplete(i, copyList[i]);
				}
			}
		}

		protected override void OnInsertComplete(int index, object value)
		{
			if (!initialized)
			{
				return;
			}
			ActiveDirectorySubnet activeDirectorySubnet = (ActiveDirectorySubnet)value;
			string text = (string)PropertyManager.GetPropertyValue(activeDirectorySubnet.context, activeDirectorySubnet.cachedEntry, PropertyManager.DistinguishedName);
			try
			{
				if (changeList.Contains(text))
				{
					((DirectoryEntry)changeList[text]).Properties["siteObject"].Value = siteDN;
					return;
				}
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, MakePath(text));
				directoryEntry.Properties["siteObject"].Value = siteDN;
				changeList.Add(text, directoryEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnRemoveComplete(int index, object value)
		{
			ActiveDirectorySubnet activeDirectorySubnet = (ActiveDirectorySubnet)value;
			string text = (string)PropertyManager.GetPropertyValue(activeDirectorySubnet.context, activeDirectorySubnet.cachedEntry, PropertyManager.DistinguishedName);
			try
			{
				if (changeList.Contains(text))
				{
					((DirectoryEntry)changeList[text]).Properties["siteObject"].Clear();
					return;
				}
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, MakePath(text));
				directoryEntry.Properties["siteObject"].Clear();
				changeList.Add(text, directoryEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		protected override void OnSetComplete(int index, object oldValue, object newValue)
		{
			OnRemoveComplete(index, oldValue);
			OnInsertComplete(index, newValue);
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (!(value is ActiveDirectorySubnet))
			{
				throw new ArgumentException("value");
			}
			if (!((ActiveDirectorySubnet)value).existing)
			{
				throw new InvalidOperationException(Res.GetString("SubnetNotCommitted", ((ActiveDirectorySubnet)value).Name));
			}
		}

		private string MakePath(string subnetDN)
		{
			string rdnFromDN = Utils.GetRdnFromDN(subnetDN);
			StringBuilder stringBuilder = new StringBuilder();
			for (int i = 0; i < rdnFromDN.Length; i++)
			{
				if (rdnFromDN[i] == '/')
				{
					stringBuilder.Append('\\');
				}
				stringBuilder.Append(rdnFromDN[i]);
			}
			return stringBuilder.ToString() + "," + subnetDN.Substring(rdnFromDN.Length + 1);
		}
	}
	public enum ActiveDirectorySyntax
	{
		CaseExactString,
		CaseIgnoreString,
		NumericString,
		DirectoryString,
		OctetString,
		SecurityDescriptor,
		Int,
		Int64,
		Bool,
		Oid,
		GeneralizedTime,
		UtcTime,
		DN,
		DNWithBinary,
		DNWithString,
		Enumeration,
		IA5String,
		PrintableString,
		Sid,
		AccessPointDN,
		ORName,
		PresentationAddress,
		ReplicaLink
	}
	internal class OMObjectClass
	{
		public byte[] data;

		public byte[] Data => data;

		public OMObjectClass(byte[] data)
		{
			this.data = data;
		}

		public bool Equals(OMObjectClass OMObjectClass)
		{
			bool result = true;
			if (data.Length == OMObjectClass.data.Length)
			{
				for (int i = 0; i < data.Length; i++)
				{
					if (data[i] != OMObjectClass.data[i])
					{
						result = false;
						break;
					}
				}
			}
			else
			{
				result = false;
			}
			return result;
		}
	}
	internal class Syntax
	{
		public string attributeSyntax;

		public int oMSyntax;

		public OMObjectClass oMObjectClass;

		public Syntax(string attributeSyntax, int oMSyntax, OMObjectClass oMObjectClass)
		{
			this.attributeSyntax = attributeSyntax;
			this.oMSyntax = oMSyntax;
			this.oMObjectClass = oMObjectClass;
		}

		public bool Equals(Syntax syntax)
		{
			bool result = true;
			if (!syntax.attributeSyntax.Equals(attributeSyntax) || syntax.oMSyntax != oMSyntax)
			{
				result = false;
			}
			else if ((oMObjectClass != null && syntax.oMObjectClass == null) || (oMObjectClass == null && syntax.oMObjectClass != null) || (oMObjectClass != null && syntax.oMObjectClass != null && !oMObjectClass.Equals(syntax.oMObjectClass)))
			{
				result = false;
			}
			return result;
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public abstract class DirectoryServer : IDisposable
	{
		internal const int DS_REPSYNC_ASYNCHRONOUS_OPERATION = 1;

		internal const int DS_REPSYNC_ALL_SOURCES = 16;

		internal const int DS_REPSYNCALL_ID_SERVERS_BY_DN = 4;

		internal const int DS_REPL_NOTSUPPORTED = 50;

		private const int DS_REPL_INFO_FLAG_IMPROVE_LINKED_ATTRS = 1;

		private bool disposed;

		internal DirectoryContext context;

		internal string replicaName;

		internal DirectoryEntryManager directoryEntryMgr;

		internal bool siteInfoModified;

		internal string cachedSiteName;

		internal string cachedSiteObjectName;

		internal string cachedServerObjectName;

		internal string cachedNtdsaObjectName;

		internal Guid cachedNtdsaObjectGuid = Guid.Empty;

		internal string cachedIPAddress;

		internal ReadOnlyStringCollection cachedPartitions;

		private ReplicationConnectionCollection inbound;

		private ReplicationConnectionCollection outbound;

		public string Name
		{
			get
			{
				CheckIfDisposed();
				return replicaName;
			}
		}

		public ReadOnlyStringCollection Partitions
		{
			get
			{
				CheckIfDisposed();
				if (cachedPartitions == null)
				{
					cachedPartitions = new ReadOnlyStringCollection(GetPartitions());
				}
				return cachedPartitions;
			}
		}

		public abstract string IPAddress
		{
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			get;
		}

		public abstract string SiteName
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get;
		}

		public abstract SyncUpdateCallback SyncFromAllServersCallback
		{
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			get;
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			set;
		}

		public abstract ReplicationConnectionCollection InboundConnections
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get;
		}

		public abstract ReplicationConnectionCollection OutboundConnections
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get;
		}

		internal DirectoryContext Context => context;

		~DirectoryServer()
		{
			Dispose(disposing: false);
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			if (disposing)
			{
				foreach (DirectoryEntry cachedDirectoryEntry in directoryEntryMgr.GetCachedDirectoryEntries())
				{
					cachedDirectoryEntry.Dispose();
				}
			}
			disposed = true;
		}

		public override string ToString()
		{
			return Name;
		}

		public void MoveToAnotherSite(string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			if (Utils.Compare(SiteName, siteName) == 0)
			{
				return;
			}
			DirectoryEntry directoryEntry = null;
			try
			{
				string dn = "CN=Servers,CN=" + siteName + "," + directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SitesContainer);
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
				string distinguishedName = ((this is DomainController) ? ((DomainController)this).ServerObjectName : ((AdamInstance)this).ServerObjectName);
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(distinguishedName);
				_ = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.DistinguishedName);
				cachedDirectoryEntry.MoveTo(directoryEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			siteInfoModified = true;
			cachedSiteName = null;
			if (cachedSiteObjectName != null)
			{
				directoryEntryMgr.RemoveIfExists(cachedSiteObjectName);
				cachedSiteObjectName = null;
			}
			if (cachedServerObjectName != null)
			{
				directoryEntryMgr.RemoveIfExists(cachedServerObjectName);
				cachedServerObjectName = null;
			}
			if (cachedNtdsaObjectName != null)
			{
				directoryEntryMgr.RemoveIfExists(cachedNtdsaObjectName);
				cachedNtdsaObjectName = null;
			}
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			CheckIfDisposed();
			string dn = ((this is DomainController) ? ((DomainController)this).ServerObjectName : ((AdamInstance)this).ServerObjectName);
			return DirectoryEntryManager.GetDirectoryEntry(context, dn);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public abstract void CheckReplicationConsistency();

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public abstract ReplicationCursorCollection GetReplicationCursors(string partition);

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public abstract ReplicationOperationInformation GetReplicationOperationInformation();

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public abstract ReplicationNeighborCollection GetReplicationNeighbors(string partition);

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract ReplicationNeighborCollection GetAllReplicationNeighbors();

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract ReplicationFailureCollection GetReplicationConnectionFailures();

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public abstract ActiveDirectoryReplicationMetadata GetReplicationMetadata(string objectPath);

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract void SyncReplicaFromServer(string partition, string sourceServer);

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract void TriggerSyncReplicaFromNeighbors(string partition);

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public abstract void SyncReplicaFromAllServers(string partition, SyncFromAllServersOptions options);

		internal ArrayList GetPartitions()
		{
			ArrayList arrayList = new ArrayList();
			DirectoryEntry directoryEntry = null;
			DirectoryEntry directoryEntry2 = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				foreach (string item in directoryEntry.Properties[PropertyManager.NamingContexts])
				{
					arrayList.Add(item);
				}
				string dn = ((this is DomainController) ? ((DomainController)this).NtdsaObjectName : ((AdamInstance)this).NtdsaObjectName);
				directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, dn);
				ArrayList arrayList2 = new ArrayList();
				arrayList2.Add(PropertyManager.HasPartialReplicaNCs);
				Hashtable hashtable = null;
				try
				{
					hashtable = Utils.GetValuesWithRangeRetrieval(directoryEntry2, null, arrayList2, SearchScope.Base);
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				ArrayList arrayList3 = (ArrayList)hashtable[PropertyManager.HasPartialReplicaNCs.ToLower(CultureInfo.InvariantCulture)];
				foreach (string item2 in arrayList3)
				{
					arrayList.Add(item2);
				}
				return arrayList;
			}
			catch (COMException e2)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
			}
			finally
			{
				directoryEntry?.Dispose();
				directoryEntry2?.Dispose();
			}
		}

		internal void CheckIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		internal void CheckConsistencyHelper(IntPtr dsHandle, LoadLibrarySafeHandle libHandle)
		{
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsReplicaConsistencyCheck");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			UnsafeNativeMethods.DsReplicaConsistencyCheck dsReplicaConsistencyCheck = (UnsafeNativeMethods.DsReplicaConsistencyCheck)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsReplicaConsistencyCheck));
			int num = dsReplicaConsistencyCheck(dsHandle, 0, 0);
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num, Name);
			}
		}

		internal IntPtr GetReplicationInfoHelper(IntPtr dsHandle, int type, int secondaryType, string partition, ref bool advanced, int context, LoadLibrarySafeHandle libHandle)
		{
			IntPtr info = (IntPtr)0;
			int num = 0;
			bool flag = true;
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsReplicaGetInfo2W");
			if (procAddress == (IntPtr)0)
			{
				procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsReplicaGetInfoW");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				UnsafeNativeMethods.DsReplicaGetInfoW dsReplicaGetInfoW = (UnsafeNativeMethods.DsReplicaGetInfoW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsReplicaGetInfoW));
				num = dsReplicaGetInfoW(dsHandle, secondaryType, partition, (IntPtr)0, ref info);
				advanced = false;
				flag = false;
			}
			else
			{
				UnsafeNativeMethods.DsReplicaGetInfo2W dsReplicaGetInfo2W = (UnsafeNativeMethods.DsReplicaGetInfo2W)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsReplicaGetInfo2W));
				num = dsReplicaGetInfo2W(dsHandle, type, partition, (IntPtr)0, null, null, 0, context, ref info);
			}
			if (flag && num == 50)
			{
				procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsReplicaGetInfoW");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				UnsafeNativeMethods.DsReplicaGetInfoW dsReplicaGetInfoW2 = (UnsafeNativeMethods.DsReplicaGetInfoW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsReplicaGetInfoW));
				num = dsReplicaGetInfoW2(dsHandle, secondaryType, partition, (IntPtr)0, ref info);
				advanced = false;
			}
			if (num != 0)
			{
				if (partition != null)
				{
					if (type == 9)
					{
						if (num == ExceptionHelper.ERROR_DS_DRA_BAD_DN || num == ExceptionHelper.ERROR_DS_NAME_UNPARSEABLE)
						{
							throw new ArgumentException(ExceptionHelper.GetErrorMessage(num, hresult: false), "objectPath");
						}
						DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(this.context, partition);
						try
						{
							directoryEntry.RefreshCache(new string[1] { "name" });
						}
						catch (COMException ex)
						{
							if ((ex.ErrorCode == -2147016672) | (ex.ErrorCode == -2147016656))
							{
								throw new ArgumentException(Res.GetString("DSNoObject"), "objectPath");
							}
							if ((ex.ErrorCode == -2147463168) | (ex.ErrorCode == -2147016654))
							{
								throw new ArgumentException(Res.GetString("DSInvalidPath"), "objectPath");
							}
						}
					}
					else if (!Partitions.Contains(partition))
					{
						throw new ArgumentException(Res.GetString("ServerNotAReplica"), "partition");
					}
				}
				throw ExceptionHelper.GetExceptionFromErrorCode(num, Name);
			}
			return info;
		}

		internal ReplicationCursorCollection ConstructReplicationCursors(IntPtr dsHandle, bool advanced, IntPtr info, string partition, DirectoryServer server, LoadLibrarySafeHandle libHandle)
		{
			int num = 0;
			int num2 = 0;
			ReplicationCursorCollection replicationCursorCollection = new ReplicationCursorCollection(server);
			if (advanced)
			{
				while (true)
				{
					try
					{
						if (!(info != (IntPtr)0))
						{
							return replicationCursorCollection;
						}
						DS_REPL_CURSORS_3 dS_REPL_CURSORS_ = new DS_REPL_CURSORS_3();
						Marshal.PtrToStructure(info, dS_REPL_CURSORS_);
						num2 = dS_REPL_CURSORS_.cNumCursors;
						if (num2 > 0)
						{
							replicationCursorCollection.AddHelper(partition, dS_REPL_CURSORS_, advanced, info);
						}
						num = dS_REPL_CURSORS_.dwEnumerationContext;
						if (num == -1)
						{
							return replicationCursorCollection;
						}
						if (num2 == 0)
						{
							return replicationCursorCollection;
						}
					}
					finally
					{
						FreeReplicaInfo(DS_REPL_INFO_TYPE.DS_REPL_INFO_CURSORS_3_FOR_NC, info, libHandle);
					}
					info = GetReplicationInfoHelper(dsHandle, 8, 1, partition, ref advanced, num, libHandle);
				}
			}
			try
			{
				if (info != (IntPtr)0)
				{
					DS_REPL_CURSORS dS_REPL_CURSORS = new DS_REPL_CURSORS();
					Marshal.PtrToStructure(info, dS_REPL_CURSORS);
					replicationCursorCollection.AddHelper(partition, dS_REPL_CURSORS, advanced, info);
					return replicationCursorCollection;
				}
				return replicationCursorCollection;
			}
			finally
			{
				FreeReplicaInfo(DS_REPL_INFO_TYPE.DS_REPL_INFO_CURSORS_FOR_NC, info, libHandle);
			}
		}

		internal ReplicationOperationInformation ConstructPendingOperations(IntPtr info, DirectoryServer server, LoadLibrarySafeHandle libHandle)
		{
			ReplicationOperationInformation replicationOperationInformation = new ReplicationOperationInformation();
			ReplicationOperationCollection replicationOperationCollection = (replicationOperationInformation.collection = new ReplicationOperationCollection(server));
			int num = 0;
			try
			{
				if (info != (IntPtr)0)
				{
					DS_REPL_PENDING_OPS dS_REPL_PENDING_OPS = new DS_REPL_PENDING_OPS();
					Marshal.PtrToStructure(info, dS_REPL_PENDING_OPS);
					num = dS_REPL_PENDING_OPS.cNumPendingOps;
					if (num > 0)
					{
						replicationOperationCollection.AddHelper(dS_REPL_PENDING_OPS, info);
						replicationOperationInformation.startTime = DateTime.FromFileTime(dS_REPL_PENDING_OPS.ftimeCurrentOpStarted);
						replicationOperationInformation.currentOp = replicationOperationCollection.GetFirstOperation();
						return replicationOperationInformation;
					}
					return replicationOperationInformation;
				}
				return replicationOperationInformation;
			}
			finally
			{
				FreeReplicaInfo(DS_REPL_INFO_TYPE.DS_REPL_INFO_PENDING_OPS, info, libHandle);
			}
		}

		internal ReplicationNeighborCollection ConstructNeighbors(IntPtr info, DirectoryServer server, LoadLibrarySafeHandle libHandle)
		{
			ReplicationNeighborCollection replicationNeighborCollection = new ReplicationNeighborCollection(server);
			int num = 0;
			try
			{
				if (info != (IntPtr)0)
				{
					DS_REPL_NEIGHBORS dS_REPL_NEIGHBORS = new DS_REPL_NEIGHBORS();
					Marshal.PtrToStructure(info, dS_REPL_NEIGHBORS);
					num = dS_REPL_NEIGHBORS.cNumNeighbors;
					if (num > 0)
					{
						replicationNeighborCollection.AddHelper(dS_REPL_NEIGHBORS, info);
						return replicationNeighborCollection;
					}
					return replicationNeighborCollection;
				}
				return replicationNeighborCollection;
			}
			finally
			{
				FreeReplicaInfo(DS_REPL_INFO_TYPE.DS_REPL_INFO_NEIGHBORS, info, libHandle);
			}
		}

		internal ReplicationFailureCollection ConstructFailures(IntPtr info, DirectoryServer server, LoadLibrarySafeHandle libHandle)
		{
			ReplicationFailureCollection replicationFailureCollection = new ReplicationFailureCollection(server);
			int num = 0;
			try
			{
				if (info != (IntPtr)0)
				{
					DS_REPL_KCC_DSA_FAILURES dS_REPL_KCC_DSA_FAILURES = new DS_REPL_KCC_DSA_FAILURES();
					Marshal.PtrToStructure(info, dS_REPL_KCC_DSA_FAILURES);
					num = dS_REPL_KCC_DSA_FAILURES.cNumEntries;
					if (num > 0)
					{
						replicationFailureCollection.AddHelper(dS_REPL_KCC_DSA_FAILURES, info);
						return replicationFailureCollection;
					}
					return replicationFailureCollection;
				}
				return replicationFailureCollection;
			}
			finally
			{
				FreeReplicaInfo(DS_REPL_INFO_TYPE.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES, info, libHandle);
			}
		}

		internal ActiveDirectoryReplicationMetadata ConstructMetaData(bool advanced, IntPtr info, DirectoryServer server, LoadLibrarySafeHandle libHandle)
		{
			ActiveDirectoryReplicationMetadata activeDirectoryReplicationMetadata = new ActiveDirectoryReplicationMetadata(server);
			int num = 0;
			if (advanced)
			{
				try
				{
					if (!(info != (IntPtr)0))
					{
						return activeDirectoryReplicationMetadata;
					}
					DS_REPL_OBJ_META_DATA_2 dS_REPL_OBJ_META_DATA_ = new DS_REPL_OBJ_META_DATA_2();
					Marshal.PtrToStructure(info, dS_REPL_OBJ_META_DATA_);
					num = dS_REPL_OBJ_META_DATA_.cNumEntries;
					if (num <= 0)
					{
						return activeDirectoryReplicationMetadata;
					}
					activeDirectoryReplicationMetadata.AddHelper(num, info, advanced: true);
					return activeDirectoryReplicationMetadata;
				}
				finally
				{
					FreeReplicaInfo(DS_REPL_INFO_TYPE.DS_REPL_INFO_METADATA_2_FOR_OBJ, info, libHandle);
				}
			}
			try
			{
				DS_REPL_OBJ_META_DATA dS_REPL_OBJ_META_DATA = new DS_REPL_OBJ_META_DATA();
				Marshal.PtrToStructure(info, dS_REPL_OBJ_META_DATA);
				num = dS_REPL_OBJ_META_DATA.cNumEntries;
				if (num > 0)
				{
					activeDirectoryReplicationMetadata.AddHelper(num, info, advanced: false);
					return activeDirectoryReplicationMetadata;
				}
				return activeDirectoryReplicationMetadata;
			}
			finally
			{
				FreeReplicaInfo(DS_REPL_INFO_TYPE.DS_REPL_INFO_METADATA_FOR_OBJ, info, libHandle);
			}
		}

		internal bool SyncAllCallbackRoutine(IntPtr data, IntPtr update)
		{
			if (SyncFromAllServersCallback == null)
			{
				return true;
			}
			DS_REPSYNCALL_UPDATE dS_REPSYNCALL_UPDATE = new DS_REPSYNCALL_UPDATE();
			Marshal.PtrToStructure(update, dS_REPSYNCALL_UPDATE);
			SyncFromAllServersEvent eventType = dS_REPSYNCALL_UPDATE.eventType;
			IntPtr pErrInfo = dS_REPSYNCALL_UPDATE.pErrInfo;
			SyncFromAllServersOperationException ex = null;
			if (pErrInfo != (IntPtr)0)
			{
				ex = ExceptionHelper.CreateSyncAllException(pErrInfo, singleError: true);
				if (ex == null)
				{
					return true;
				}
			}
			string targetServer = null;
			string sourceServer = null;
			pErrInfo = dS_REPSYNCALL_UPDATE.pSync;
			if (pErrInfo != (IntPtr)0)
			{
				DS_REPSYNCALL_SYNC dS_REPSYNCALL_SYNC = new DS_REPSYNCALL_SYNC();
				Marshal.PtrToStructure(pErrInfo, dS_REPSYNCALL_SYNC);
				targetServer = Marshal.PtrToStringUni(dS_REPSYNCALL_SYNC.pszDstId);
				sourceServer = Marshal.PtrToStringUni(dS_REPSYNCALL_SYNC.pszSrcId);
			}
			SyncUpdateCallback syncFromAllServersCallback = SyncFromAllServersCallback;
			return syncFromAllServersCallback(eventType, targetServer, sourceServer, ex);
		}

		internal void SyncReplicaAllHelper(IntPtr handle, SyncReplicaFromAllServersCallback syncAllFunctionPointer, string partition, SyncFromAllServersOptions option, SyncUpdateCallback callback, LoadLibrarySafeHandle libHandle)
		{
			IntPtr error = (IntPtr)0;
			if (!Partitions.Contains(partition))
			{
				throw new ArgumentException(Res.GetString("ServerNotAReplica"), "partition");
			}
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsReplicaSyncAllW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			UnsafeNativeMethods.DsReplicaSyncAllW dsReplicaSyncAllW = (UnsafeNativeMethods.DsReplicaSyncAllW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsReplicaSyncAllW));
			int num = dsReplicaSyncAllW(handle, partition, (int)(option | (SyncFromAllServersOptions)4), syncAllFunctionPointer, (IntPtr)0, ref error);
			try
			{
				if (error != (IntPtr)0)
				{
					SyncFromAllServersOperationException ex = ExceptionHelper.CreateSyncAllException(error, singleError: false);
					if (ex != null)
					{
						throw ex;
					}
				}
				else if (num != 0)
				{
					throw new SyncFromAllServersOperationException(ExceptionHelper.GetErrorMessage(num, hresult: false));
				}
			}
			finally
			{
				if (error != (IntPtr)0)
				{
					UnsafeNativeMethods.LocalFree(error);
				}
			}
		}

		private void FreeReplicaInfo(DS_REPL_INFO_TYPE type, IntPtr value, LoadLibrarySafeHandle libHandle)
		{
			if (value != (IntPtr)0)
			{
				IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsReplicaFreeInfo");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				UnsafeNativeMethods.DsReplicaFreeInfo dsReplicaFreeInfo = (UnsafeNativeMethods.DsReplicaFreeInfo)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsReplicaFreeInfo));
				dsReplicaFreeInfo((int)type, value);
			}
		}

		internal void SyncReplicaHelper(IntPtr dsHandle, bool isADAM, string partition, string sourceServer, int option, LoadLibrarySafeHandle libHandle)
		{
			int cb = Marshal.SizeOf(typeof(Guid));
			IntPtr intPtr = (IntPtr)0;
			Guid empty = Guid.Empty;
			AdamInstance adamInstance = null;
			DomainController domainController = null;
			intPtr = Marshal.AllocHGlobal(cb);
			try
			{
				if (sourceServer != null)
				{
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(sourceServer, DirectoryContextType.DirectoryServer, context);
					if (isADAM)
					{
						adamInstance = AdamInstance.GetAdamInstance(newDirectoryContext);
						empty = adamInstance.NtdsaObjectGuid;
					}
					else
					{
						domainController = DomainController.GetDomainController(newDirectoryContext);
						empty = domainController.NtdsaObjectGuid;
					}
					Marshal.StructureToPtr(empty, intPtr, fDeleteOld: false);
				}
				IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsReplicaSyncW");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				UnsafeNativeMethods.DsReplicaSyncW dsReplicaSyncW = (UnsafeNativeMethods.DsReplicaSyncW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsReplicaSyncW));
				int num = dsReplicaSyncW(dsHandle, partition, intPtr, option);
				if (num != 0)
				{
					if (!Partitions.Contains(partition))
					{
						throw new ArgumentException(Res.GetString("ServerNotAReplica"), "partition");
					}
					string targetName = null;
					if (num == ExceptionHelper.RPC_S_SERVER_UNAVAILABLE)
					{
						targetName = sourceServer;
					}
					else if (num == ExceptionHelper.RPC_S_CALL_FAILED)
					{
						targetName = Name;
					}
					throw ExceptionHelper.GetExceptionFromErrorCode(num, targetName);
				}
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					Marshal.FreeHGlobal(intPtr);
				}
				adamInstance?.Dispose();
				domainController?.Dispose();
			}
		}

		internal ReplicationConnectionCollection GetInboundConnectionsHelper()
		{
			if (inbound == null)
			{
				inbound = new ReplicationConnectionCollection();
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(Name, DirectoryContextType.DirectoryServer, context);
				string text = ((this is DomainController) ? ((DomainController)this).ServerObjectName : ((AdamInstance)this).ServerObjectName);
				string dn = "CN=NTDS Settings," + text;
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(Utils.GetNewDirectoryContext(Name, DirectoryContextType.DirectoryServer, context), dn);
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=nTDSConnection)(objectCategory=nTDSConnection))", new string[1] { "cn" }, SearchScope.OneLevel);
				SearchResultCollection searchResultCollection = null;
				try
				{
					searchResultCollection = aDSearcher.FindAll();
					foreach (SearchResult item in searchResultCollection)
					{
						ReplicationConnection value = new ReplicationConnection(newDirectoryContext, item.GetDirectoryEntry(), (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn));
						inbound.Add(value);
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(newDirectoryContext, e);
				}
				finally
				{
					searchResultCollection?.Dispose();
					directoryEntry.Dispose();
				}
			}
			return inbound;
		}

		internal ReplicationConnectionCollection GetOutboundConnectionsHelper()
		{
			if (outbound == null)
			{
				string dn = ((this is DomainController) ? ((DomainController)this).SiteObjectName : ((AdamInstance)this).SiteObjectName);
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(Utils.GetNewDirectoryContext(Name, DirectoryContextType.DirectoryServer, context), dn);
				string text = ((this is DomainController) ? ((DomainController)this).ServerObjectName : ((AdamInstance)this).ServerObjectName);
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=nTDSConnection)(objectCategory=nTDSConnection)(fromServer=CN=NTDS Settings," + text + "))", new string[2] { "objectClass", "cn" }, SearchScope.Subtree);
				SearchResultCollection searchResultCollection = null;
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(Name, DirectoryContextType.DirectoryServer, context);
				try
				{
					searchResultCollection = aDSearcher.FindAll();
					outbound = new ReplicationConnectionCollection();
					foreach (SearchResult item in searchResultCollection)
					{
						ReplicationConnection value = new ReplicationConnection(newDirectoryContext, item.GetDirectoryEntry(), (string)item.Properties["cn"][0]);
						outbound.Add(value);
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(newDirectoryContext, e);
				}
				finally
				{
					searchResultCollection?.Dispose();
					directoryEntry.Dispose();
				}
			}
			return outbound;
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class AdamInstance : DirectoryServer
	{
		private string[] becomeRoleOwnerAttrs;

		private bool disposed;

		private string cachedHostName;

		private int cachedLdapPort = -1;

		private int cachedSslPort = -1;

		private bool defaultPartitionInitialized;

		private bool defaultPartitionModified;

		private ConfigurationSet currentConfigSet;

		private string cachedDefaultPartition;

		private AdamRoleCollection cachedRoles;

		private IntPtr ADAMHandle = (IntPtr)0;

		private IntPtr authIdentity = IntPtr.Zero;

		private SyncUpdateCallback userDelegate;

		private SyncReplicaFromAllServersCallback syncAllFunctionPointer;

		public ConfigurationSet ConfigurationSet
		{
			get
			{
				CheckIfDisposed();
				if (currentConfigSet == null)
				{
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(base.Name, DirectoryContextType.DirectoryServer, context);
					currentConfigSet = ConfigurationSet.GetConfigurationSet(newDirectoryContext);
				}
				return currentConfigSet;
			}
		}

		public string HostName
		{
			get
			{
				CheckIfDisposed();
				if (cachedHostName == null)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(ServerObjectName);
					cachedHostName = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.DnsHostName);
				}
				return cachedHostName;
			}
		}

		public int LdapPort
		{
			get
			{
				CheckIfDisposed();
				if (cachedLdapPort == -1)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
					cachedLdapPort = (int)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.MsDSPortLDAP);
				}
				return cachedLdapPort;
			}
		}

		public int SslPort
		{
			get
			{
				CheckIfDisposed();
				if (cachedSslPort == -1)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
					cachedSslPort = (int)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.MsDSPortSSL);
				}
				return cachedSslPort;
			}
		}

		public AdamRoleCollection Roles
		{
			get
			{
				CheckIfDisposed();
				DirectoryEntry directoryEntry = null;
				DirectoryEntry directoryEntry2 = null;
				try
				{
					if (cachedRoles == null)
					{
						ArrayList arrayList = new ArrayList();
						directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext));
						if (NtdsaObjectName.Equals((string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner)))
						{
							arrayList.Add(AdamRole.SchemaRole);
						}
						directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
						if (NtdsaObjectName.Equals((string)PropertyManager.GetPropertyValue(context, directoryEntry2, PropertyManager.FsmoRoleOwner)))
						{
							arrayList.Add(AdamRole.NamingRole);
						}
						cachedRoles = new AdamRoleCollection(arrayList);
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				finally
				{
					directoryEntry?.Dispose();
					directoryEntry2?.Dispose();
				}
				return cachedRoles;
			}
		}

		public string DefaultPartition
		{
			get
			{
				CheckIfDisposed();
				if (!defaultPartitionInitialized || defaultPartitionModified)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
					try
					{
						cachedDirectoryEntry.RefreshCache();
						if (cachedDirectoryEntry.Properties[PropertyManager.MsDSDefaultNamingContext].Value == null)
						{
							cachedDefaultPartition = null;
						}
						else
						{
							cachedDefaultPartition = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.MsDSDefaultNamingContext);
						}
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					defaultPartitionInitialized = true;
				}
				return cachedDefaultPartition;
			}
			set
			{
				CheckIfDisposed();
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
				if (value == null)
				{
					if (cachedDirectoryEntry.Properties.Contains(PropertyManager.MsDSDefaultNamingContext))
					{
						cachedDirectoryEntry.Properties[PropertyManager.MsDSDefaultNamingContext].Clear();
					}
				}
				else
				{
					if (!Utils.IsValidDNFormat(value))
					{
						throw new ArgumentException(Res.GetString("InvalidDNFormat"), "value");
					}
					if (!base.Partitions.Contains(value))
					{
						throw new ArgumentException(Res.GetString("ServerNotAReplica", value), "value");
					}
					cachedDirectoryEntry.Properties[PropertyManager.MsDSDefaultNamingContext].Value = value;
				}
				defaultPartitionModified = true;
			}
		}

		public override string IPAddress
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DnsPermission(SecurityAction.Assert, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get
			{
				CheckIfDisposed();
				IPHostEntry hostEntry = Dns.GetHostEntry(HostName);
				if (hostEntry.AddressList.GetLength(0) > 0)
				{
					return hostEntry.AddressList[0].ToString();
				}
				return null;
			}
		}

		public override string SiteName
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get
			{
				CheckIfDisposed();
				if (cachedSiteName == null)
				{
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, SiteObjectName);
					try
					{
						cachedSiteName = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.Cn);
					}
					finally
					{
						directoryEntry.Dispose();
					}
				}
				return cachedSiteName;
			}
		}

		internal string SiteObjectName
		{
			get
			{
				CheckIfDisposed();
				if (cachedSiteObjectName == null)
				{
					string[] array = ServerObjectName.Split(',');
					if (array.GetLength(0) < 3)
					{
						throw new ActiveDirectoryOperationException(Res.GetString("InvalidServerNameFormat"));
					}
					cachedSiteObjectName = array[2];
					for (int i = 3; i < array.GetLength(0); i++)
					{
						cachedSiteObjectName = cachedSiteObjectName + "," + array[i];
					}
				}
				return cachedSiteObjectName;
			}
		}

		internal string ServerObjectName
		{
			get
			{
				CheckIfDisposed();
				if (cachedServerObjectName == null)
				{
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					try
					{
						cachedServerObjectName = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ServerName);
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					finally
					{
						directoryEntry.Dispose();
					}
				}
				return cachedServerObjectName;
			}
		}

		internal string NtdsaObjectName
		{
			get
			{
				CheckIfDisposed();
				if (cachedNtdsaObjectName == null)
				{
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					try
					{
						cachedNtdsaObjectName = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.DsServiceName);
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					finally
					{
						directoryEntry.Dispose();
					}
				}
				return cachedNtdsaObjectName;
			}
		}

		internal Guid NtdsaObjectGuid
		{
			get
			{
				CheckIfDisposed();
				if (cachedNtdsaObjectGuid == Guid.Empty)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
					byte[] b = (byte[])PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.ObjectGuid);
					cachedNtdsaObjectGuid = new Guid(b);
				}
				return cachedNtdsaObjectGuid;
			}
		}

		public override SyncUpdateCallback SyncFromAllServersCallback
		{
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return userDelegate;
			}
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				userDelegate = value;
			}
		}

		public override ReplicationConnectionCollection InboundConnections
		{
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			get
			{
				return GetInboundConnectionsHelper();
			}
		}

		public override ReplicationConnectionCollection OutboundConnections
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get
			{
				return GetOutboundConnectionsHelper();
			}
		}

		internal AdamInstance(DirectoryContext context, string adamInstanceName)
			: this(context, adamInstanceName, new DirectoryEntryManager(context), nameIncludesPort: true)
		{
		}

		internal AdamInstance(DirectoryContext context, string adamInstanceName, DirectoryEntryManager directoryEntryMgr, bool nameIncludesPort)
		{
			base.context = context;
			replicaName = adamInstanceName;
			base.directoryEntryMgr = directoryEntryMgr;
			becomeRoleOwnerAttrs = new string[2];
			becomeRoleOwnerAttrs[0] = PropertyManager.BecomeSchemaMaster;
			becomeRoleOwnerAttrs[1] = PropertyManager.BecomeDomainMaster;
			syncAllFunctionPointer = base.SyncAllCallbackRoutine;
		}

		internal AdamInstance(DirectoryContext context, string adamHostName, DirectoryEntryManager directoryEntryMgr)
		{
			base.context = context;
			replicaName = adamHostName;
			Utils.SplitServerNameAndPortNumber(context.Name, out var portNumber);
			if (portNumber != null)
			{
				replicaName = replicaName + ":" + portNumber;
			}
			base.directoryEntryMgr = directoryEntryMgr;
			becomeRoleOwnerAttrs = new string[2];
			becomeRoleOwnerAttrs[0] = PropertyManager.BecomeSchemaMaster;
			becomeRoleOwnerAttrs[1] = PropertyManager.BecomeDomainMaster;
			syncAllFunctionPointer = base.SyncAllCallbackRoutine;
		}

		~AdamInstance()
		{
			Dispose(disposing: false);
		}

		protected override void Dispose(bool disposing)
		{
			if (!disposed)
			{
				try
				{
					FreeADAMHandle();
					disposed = true;
				}
				finally
				{
					Dispose();
				}
			}
		}

		public static AdamInstance GetAdamInstance(DirectoryContext context)
		{
			DirectoryEntryManager directoryEntryManager = null;
			string text = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.DirectoryServer)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeADAMServer"), "context");
			}
			if (!context.isServer())
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AINotFound", context.Name), typeof(AdamInstance), context.Name);
			}
			context = new DirectoryContext(context);
			try
			{
				directoryEntryManager = new DirectoryEntryManager(context);
				DirectoryEntry cachedDirectoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (!Utils.CheckCapability(cachedDirectoryEntry, Capability.ActiveDirectoryApplicationMode))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AINotFound", context.Name), typeof(AdamInstance), context.Name);
				}
				text = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.DnsHostName);
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AINotFound", context.Name), typeof(AdamInstance), context.Name);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			return new AdamInstance(context, text, directoryEntryManager);
		}

		public static AdamInstance FindOne(DirectoryContext context, string partitionName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.ConfigurationSet)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeConfigSet"), "context");
			}
			if (partitionName == null)
			{
				throw new ArgumentNullException("partitionName");
			}
			if (partitionName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partitionName");
			}
			context = new DirectoryContext(context);
			return ConfigurationSet.FindOneAdamInstance(context, partitionName, null);
		}

		public static AdamInstanceCollection FindAll(DirectoryContext context, string partitionName)
		{
			AdamInstanceCollection adamInstanceCollection = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.ConfigurationSet)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeConfigSet"), "context");
			}
			if (partitionName == null)
			{
				throw new ArgumentNullException("partitionName");
			}
			if (partitionName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partitionName");
			}
			context = new DirectoryContext(context);
			try
			{
				return ConfigurationSet.FindAdamInstances(context, partitionName, null);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				return new AdamInstanceCollection(new ArrayList());
			}
		}

		public void TransferRoleOwnership(AdamRole role)
		{
			CheckIfDisposed();
			if (role < AdamRole.SchemaRole || role > AdamRole.NamingRole)
			{
				throw new InvalidEnumArgumentException("role", (int)role, typeof(AdamRole));
			}
			try
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				cachedDirectoryEntry.Properties[becomeRoleOwnerAttrs[(int)role]].Value = 1;
				cachedDirectoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			cachedRoles = null;
		}

		public void SeizeRoleOwnership(AdamRole role)
		{
			string text = null;
			CheckIfDisposed();
			text = role switch
			{
				AdamRole.SchemaRole => directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext), 
				AdamRole.NamingRole => directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer), 
				_ => throw new InvalidEnumArgumentException("role", (int)role, typeof(AdamRole)), 
			};
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text);
				directoryEntry.Properties[PropertyManager.FsmoRoleOwner].Value = NtdsaObjectName;
				directoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			cachedRoles = null;
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override void CheckReplicationConsistency()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetADAMHandle();
			CheckConsistencyHelper(ADAMHandle, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override ReplicationCursorCollection GetReplicationCursors(string partition)
		{
			IntPtr intPtr = (IntPtr)0;
			int num = 0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetADAMHandle();
			intPtr = GetReplicationInfoHelper(ADAMHandle, 8, 1, partition, ref advanced, num, DirectoryContext.ADAMHandle);
			return ConstructReplicationCursors(ADAMHandle, advanced, intPtr, partition, this, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override ReplicationOperationInformation GetReplicationOperationInformation()
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetADAMHandle();
			intPtr = GetReplicationInfoHelper(ADAMHandle, 5, 5, null, ref advanced, 0, DirectoryContext.ADAMHandle);
			return ConstructPendingOperations(intPtr, this, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override ReplicationNeighborCollection GetReplicationNeighbors(string partition)
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetADAMHandle();
			intPtr = GetReplicationInfoHelper(ADAMHandle, 0, 0, partition, ref advanced, 0, DirectoryContext.ADAMHandle);
			return ConstructNeighbors(intPtr, this, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override ReplicationNeighborCollection GetAllReplicationNeighbors()
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetADAMHandle();
			intPtr = GetReplicationInfoHelper(ADAMHandle, 0, 0, null, ref advanced, 0, DirectoryContext.ADAMHandle);
			return ConstructNeighbors(intPtr, this, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override ReplicationFailureCollection GetReplicationConnectionFailures()
		{
			return GetReplicationFailures(DS_REPL_INFO_TYPE.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override ActiveDirectoryReplicationMetadata GetReplicationMetadata(string objectPath)
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (objectPath == null)
			{
				throw new ArgumentNullException("objectPath");
			}
			if (objectPath.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "objectPath");
			}
			GetADAMHandle();
			intPtr = GetReplicationInfoHelper(ADAMHandle, 9, 2, objectPath, ref advanced, 0, DirectoryContext.ADAMHandle);
			return ConstructMetaData(advanced, intPtr, this, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override void SyncReplicaFromServer(string partition, string sourceServer)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			if (sourceServer == null)
			{
				throw new ArgumentNullException("sourceServer");
			}
			if (sourceServer.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "sourceServer");
			}
			GetADAMHandle();
			SyncReplicaHelper(ADAMHandle, isADAM: true, partition, sourceServer, 0, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override void TriggerSyncReplicaFromNeighbors(string partition)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetADAMHandle();
			SyncReplicaHelper(ADAMHandle, isADAM: true, partition, null, 17, DirectoryContext.ADAMHandle);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override void SyncReplicaFromAllServers(string partition, SyncFromAllServersOptions options)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetADAMHandle();
			SyncReplicaAllHelper(ADAMHandle, syncAllFunctionPointer, partition, options, SyncFromAllServersCallback, DirectoryContext.ADAMHandle);
		}

		public void Save()
		{
			CheckIfDisposed();
			if (defaultPartitionModified)
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
				try
				{
					cachedDirectoryEntry.CommitChanges();
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
			defaultPartitionInitialized = false;
			defaultPartitionModified = false;
		}

		private ReplicationFailureCollection GetReplicationFailures(DS_REPL_INFO_TYPE type)
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetADAMHandle();
			intPtr = GetReplicationInfoHelper(ADAMHandle, (int)type, (int)type, null, ref advanced, 0, DirectoryContext.ADAMHandle);
			return ConstructFailures(intPtr, this, DirectoryContext.ADAMHandle);
		}

		private void GetADAMHandle()
		{
			try
			{
				Monitor.Enter(this);
				if (ADAMHandle == IntPtr.Zero)
				{
					if (authIdentity == IntPtr.Zero)
					{
						authIdentity = Utils.GetAuthIdentity(context, DirectoryContext.ADAMHandle);
					}
					string domainControllerName = HostName + ":" + LdapPort;
					ADAMHandle = Utils.GetDSHandle(domainControllerName, null, authIdentity, DirectoryContext.ADAMHandle);
				}
			}
			finally
			{
				Monitor.Exit(this);
			}
		}

		private void FreeADAMHandle()
		{
			Monitor.Enter(this);
			Utils.FreeDSHandle(ADAMHandle, DirectoryContext.ADAMHandle);
			Utils.FreeAuthIdentity(authIdentity, DirectoryContext.ADAMHandle);
			Monitor.Exit(this);
		}
	}
	public class AdamInstanceCollection : ReadOnlyCollectionBase
	{
		public AdamInstance this[int index] => (AdamInstance)base.InnerList[index];

		internal AdamInstanceCollection()
		{
		}

		internal AdamInstanceCollection(ArrayList values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(AdamInstance adamInstance)
		{
			if (adamInstance == null)
			{
				throw new ArgumentNullException("adamInstance");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				AdamInstance adamInstance2 = (AdamInstance)base.InnerList[i];
				if (Utils.Compare(adamInstance2.Name, adamInstance.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(AdamInstance adamInstance)
		{
			if (adamInstance == null)
			{
				throw new ArgumentNullException("adamInstance");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				AdamInstance adamInstance2 = (AdamInstance)base.InnerList[i];
				if (Utils.Compare(adamInstance2.Name, adamInstance.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(AdamInstance[] adamInstances, int index)
		{
			base.InnerList.CopyTo(adamInstances, index);
		}
	}
	[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
	internal class ADSearcher
	{
		private DirectorySearcher searcher;

		private static TimeSpan defaultTimeSpan = new TimeSpan(0, 120, 0);

		public StringCollection PropertiesToLoad => searcher.PropertiesToLoad;

		public string Filter
		{
			get
			{
				return searcher.Filter;
			}
			set
			{
				searcher.Filter = value;
			}
		}

		public ADSearcher(DirectoryEntry searchRoot, string filter, string[] propertiesToLoad, SearchScope scope)
		{
			searcher = new DirectorySearcher(searchRoot, filter, propertiesToLoad, scope);
			searcher.CacheResults = false;
			searcher.ClientTimeout = defaultTimeSpan;
			searcher.ServerPageTimeLimit = defaultTimeSpan;
			searcher.PageSize = 512;
		}

		public ADSearcher(DirectoryEntry searchRoot, string filter, string[] propertiesToLoad, SearchScope scope, bool pagedSearch, bool cacheResults)
		{
			searcher = new DirectorySearcher(searchRoot, filter, propertiesToLoad, scope);
			searcher.ClientTimeout = defaultTimeSpan;
			if (pagedSearch)
			{
				searcher.PageSize = 512;
				searcher.ServerPageTimeLimit = defaultTimeSpan;
			}
			if (cacheResults)
			{
				searcher.CacheResults = true;
			}
			else
			{
				searcher.CacheResults = false;
			}
		}

		public SearchResult FindOne()
		{
			return searcher.FindOne();
		}

		public SearchResultCollection FindAll()
		{
			return searcher.FindAll();
		}

		public void Dispose()
		{
			searcher.Dispose();
		}
	}
	internal enum NCFlags
	{
		InstanceTypeIsNCHead = 1,
		InstanceTypeIsWriteable = 4
	}
	internal enum ApplicationPartitionType
	{
		Unknown = -1,
		ADApplicationPartition,
		ADAMApplicationPartition
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ApplicationPartition : ActiveDirectoryPartition
	{
		private bool disposed;

		private ApplicationPartitionType appType = ApplicationPartitionType.Unknown;

		private bool committed = true;

		private DirectoryEntry domainDNSEntry;

		private DirectoryEntry crossRefEntry;

		private string dnsName;

		private DirectoryServerCollection cachedDirectoryServers;

		private bool securityRefDomainModified;

		private string securityRefDomain;

		public DirectoryServerCollection DirectoryServers
		{
			get
			{
				CheckIfDisposed();
				if (cachedDirectoryServers == null)
				{
					ReadOnlyDirectoryServerCollection servers = (committed ? FindAllDirectoryServers() : new ReadOnlyDirectoryServerCollection());
					bool isADAM = appType == ApplicationPartitionType.ADAMApplicationPartition;
					if (committed)
					{
						GetCrossRefEntry();
					}
					cachedDirectoryServers = new DirectoryServerCollection(context, committed ? crossRefEntry : null, isADAM, servers);
				}
				return cachedDirectoryServers;
			}
		}

		public string SecurityReferenceDomain
		{
			get
			{
				CheckIfDisposed();
				if (appType == ApplicationPartitionType.ADAMApplicationPartition)
				{
					throw new NotSupportedException(Res.GetString("PropertyInvalidForADAM"));
				}
				if (committed)
				{
					GetCrossRefEntry();
					try
					{
						if (crossRefEntry.Properties[PropertyManager.MsDSSDReferenceDomain].Count > 0)
						{
							return (string)crossRefEntry.Properties[PropertyManager.MsDSSDReferenceDomain].Value;
						}
						return null;
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
				return securityRefDomain;
			}
			set
			{
				CheckIfDisposed();
				if (appType == ApplicationPartitionType.ADAMApplicationPartition)
				{
					throw new NotSupportedException(Res.GetString("PropertyInvalidForADAM"));
				}
				if (committed)
				{
					GetCrossRefEntry();
					if (value == null)
					{
						if (crossRefEntry.Properties.Contains(PropertyManager.MsDSSDReferenceDomain))
						{
							crossRefEntry.Properties[PropertyManager.MsDSSDReferenceDomain].Clear();
							securityRefDomainModified = true;
						}
					}
					else
					{
						crossRefEntry.Properties[PropertyManager.MsDSSDReferenceDomain].Value = value;
						securityRefDomainModified = true;
					}
				}
				else if (securityRefDomain != null || value != null)
				{
					securityRefDomain = value;
					securityRefDomainModified = true;
				}
			}
		}

		public ApplicationPartition(DirectoryContext context, string distinguishedName)
		{
			ValidateApplicationPartitionParameters(context, distinguishedName, null, objectClassSpecified: false);
			CreateApplicationPartition(distinguishedName, "domainDns");
		}

		public ApplicationPartition(DirectoryContext context, string distinguishedName, string objectClass)
		{
			ValidateApplicationPartitionParameters(context, distinguishedName, objectClass, objectClassSpecified: true);
			CreateApplicationPartition(distinguishedName, objectClass);
		}

		internal ApplicationPartition(DirectoryContext context, string distinguishedName, string dnsName, ApplicationPartitionType appType, DirectoryEntryManager directoryEntryMgr)
			: base(context, distinguishedName)
		{
			base.directoryEntryMgr = directoryEntryMgr;
			this.appType = appType;
			this.dnsName = dnsName;
		}

		internal ApplicationPartition(DirectoryContext context, string distinguishedName, string dnsName, DirectoryEntryManager directoryEntryMgr)
			: this(context, distinguishedName, dnsName, GetApplicationPartitionType(context), directoryEntryMgr)
		{
		}

		protected override void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			try
			{
				if (crossRefEntry != null)
				{
					crossRefEntry.Dispose();
					crossRefEntry = null;
				}
				if (domainDNSEntry != null)
				{
					domainDNSEntry.Dispose();
					domainDNSEntry = null;
				}
				disposed = true;
			}
			finally
			{
				Dispose();
			}
		}

		public static ApplicationPartition GetApplicationPartition(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.ApplicationPartition)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeAppNCDnsName"), "context");
			}
			if (!context.isNdnc())
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("NDNCNotFound"), typeof(ApplicationPartition), context.Name);
			}
			context = new DirectoryContext(context);
			string dNFromDnsName = Utils.GetDNFromDnsName(context.Name);
			DirectoryEntryManager directoryEntryManager = new DirectoryEntryManager(context);
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = directoryEntryManager.GetCachedDirectoryEntry(dNFromDnsName);
				directoryEntry.Bind(throwIfFail: true);
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("NDNCNotFound"), typeof(ApplicationPartition), context.Name);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			return new ApplicationPartition(context, dNFromDnsName, context.Name, ApplicationPartitionType.ADApplicationPartition, directoryEntryManager);
		}

		public static ApplicationPartition FindByName(DirectoryContext context, string distinguishedName)
		{
			ApplicationPartition applicationPartition = null;
			DirectoryEntryManager directoryEntryManager = null;
			DirectoryContext directoryContext = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isADAMConfigSet() && !context.isServer())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (distinguishedName == null)
			{
				throw new ArgumentNullException("distinguishedName");
			}
			if (distinguishedName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "distinguishedName");
			}
			if (!Utils.IsValidDNFormat(distinguishedName))
			{
				throw new ArgumentException(Res.GetString("InvalidDNFormat"), "distinguishedName");
			}
			context = new DirectoryContext(context);
			directoryEntryManager = new DirectoryEntryManager(context);
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryManager.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			StringBuilder stringBuilder = new StringBuilder(15);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=crossRef)(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.804:=");
			stringBuilder.Append(1);
			stringBuilder.Append(")(!(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.803:=");
			stringBuilder.Append(2);
			stringBuilder.Append("))(");
			stringBuilder.Append(PropertyManager.NCName);
			stringBuilder.Append("=");
			stringBuilder.Append(Utils.GetEscapedFilterValue(distinguishedName));
			stringBuilder.Append("))");
			string filter = stringBuilder.ToString();
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, filter, new string[2]
			{
				PropertyManager.DnsRoot,
				PropertyManager.NCName
			}, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
			SearchResult searchResult = null;
			try
			{
				searchResult = aDSearcher.FindOne();
			}
			catch (COMException ex2)
			{
				if (ex2.ErrorCode == -2147016656)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AppNCNotFound"), typeof(ApplicationPartition), distinguishedName);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
			}
			finally
			{
				directoryEntry.Dispose();
			}
			if (searchResult == null)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AppNCNotFound"), typeof(ApplicationPartition), distinguishedName);
			}
			string text = null;
			try
			{
				text = ((searchResult.Properties[PropertyManager.DnsRoot].Count > 0) ? ((string)searchResult.Properties[PropertyManager.DnsRoot][0]) : null);
			}
			catch (COMException e2)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
			}
			ApplicationPartitionType applicationPartitionType = GetApplicationPartitionType(context);
			if (context.ContextType == DirectoryContextType.DirectoryServer)
			{
				bool flag = false;
				DistinguishedName dn = new DistinguishedName(distinguishedName);
				DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				try
				{
					foreach (string item in directoryEntry2.Properties[PropertyManager.NamingContexts])
					{
						DistinguishedName distinguishedName2 = new DistinguishedName(item);
						if (distinguishedName2.Equals(dn))
						{
							flag = true;
							break;
						}
					}
				}
				catch (COMException e3)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e3);
				}
				finally
				{
					directoryEntry2.Dispose();
				}
				if (!flag)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AppNCNotFound"), typeof(ApplicationPartition), distinguishedName);
				}
				directoryContext = context;
			}
			else if (applicationPartitionType == ApplicationPartitionType.ADApplicationPartition)
			{
				int num = 0;
				num = Locator.DsGetDcNameWrapper(null, text, null, 32768L, out var domainControllerInfo);
				switch (num)
				{
				case 1355:
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AppNCNotFound"), typeof(ApplicationPartition), distinguishedName);
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(num);
				case 0:
					break;
				}
				string name = domainControllerInfo.DomainControllerName.Substring(2);
				directoryContext = Utils.GetNewDirectoryContext(name, DirectoryContextType.DirectoryServer, context);
			}
			else
			{
				string name2 = ConfigurationSet.FindOneAdamInstance(context.Name, context, distinguishedName, null).Name;
				directoryContext = Utils.GetNewDirectoryContext(name2, DirectoryContextType.DirectoryServer, context);
			}
			return new ApplicationPartition(directoryContext, (string)PropertyManager.GetSearchResultPropertyValue(searchResult, PropertyManager.NCName), text, applicationPartitionType, directoryEntryManager);
		}

		public DirectoryServer FindDirectoryServer()
		{
			DirectoryServer directoryServer = null;
			CheckIfDisposed();
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindDirectoryServerInternal(null, forceRediscovery: false);
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			return ConfigurationSet.FindOneAdamInstance(context, base.Name, null);
		}

		public DirectoryServer FindDirectoryServer(string siteName)
		{
			DirectoryServer directoryServer = null;
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindDirectoryServerInternal(siteName, forceRediscovery: false);
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			return ConfigurationSet.FindOneAdamInstance(context, base.Name, siteName);
		}

		public DirectoryServer FindDirectoryServer(bool forceRediscovery)
		{
			DirectoryServer directoryServer = null;
			CheckIfDisposed();
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindDirectoryServerInternal(null, forceRediscovery);
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			return ConfigurationSet.FindOneAdamInstance(context, base.Name, null);
		}

		public DirectoryServer FindDirectoryServer(string siteName, bool forceRediscovery)
		{
			DirectoryServer directoryServer = null;
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindDirectoryServerInternal(siteName, forceRediscovery);
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			return ConfigurationSet.FindOneAdamInstance(context, base.Name, siteName);
		}

		public ReadOnlyDirectoryServerCollection FindAllDirectoryServers()
		{
			CheckIfDisposed();
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindAllDirectoryServersInternal(null);
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			ReadOnlyDirectoryServerCollection readOnlyDirectoryServerCollection = new ReadOnlyDirectoryServerCollection();
			readOnlyDirectoryServerCollection.AddRange(ConfigurationSet.FindAdamInstances(context, base.Name, null));
			return readOnlyDirectoryServerCollection;
		}

		public ReadOnlyDirectoryServerCollection FindAllDirectoryServers(string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindAllDirectoryServersInternal(siteName);
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			ReadOnlyDirectoryServerCollection readOnlyDirectoryServerCollection = new ReadOnlyDirectoryServerCollection();
			readOnlyDirectoryServerCollection.AddRange(ConfigurationSet.FindAdamInstances(context, base.Name, siteName));
			return readOnlyDirectoryServerCollection;
		}

		public ReadOnlyDirectoryServerCollection FindAllDiscoverableDirectoryServers()
		{
			CheckIfDisposed();
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindAllDiscoverableDirectoryServersInternal(null);
			}
			throw new NotSupportedException(Res.GetString("OperationInvalidForADAM"));
		}

		public ReadOnlyDirectoryServerCollection FindAllDiscoverableDirectoryServers(string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				return FindAllDiscoverableDirectoryServersInternal(siteName);
			}
			throw new NotSupportedException(Res.GetString("OperationInvalidForADAM"));
		}

		public void Delete()
		{
			CheckIfDisposed();
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
			try
			{
				GetCrossRefEntry();
				directoryEntry.Children.Remove(crossRefEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		public void Save()
		{
			CheckIfDisposed();
			if (!committed)
			{
				bool flag = false;
				if (appType == ApplicationPartitionType.ADApplicationPartition)
				{
					try
					{
						domainDNSEntry.CommitChanges();
					}
					catch (COMException ex)
					{
						if (ex.ErrorCode != -2147016663)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
						}
						flag = true;
					}
				}
				else
				{
					flag = true;
				}
				if (flag)
				{
					try
					{
						InitializeCrossRef(partitionName);
						crossRefEntry.CommitChanges();
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					try
					{
						domainDNSEntry.CommitChanges();
					}
					catch (COMException e3)
					{
						DirectoryEntry parent = crossRefEntry.Parent;
						try
						{
							parent.Children.Remove(crossRefEntry);
						}
						catch (COMException e2)
						{
							throw ExceptionHelper.GetExceptionFromCOMException(e2);
						}
						throw ExceptionHelper.GetExceptionFromCOMException(context, e3);
					}
					try
					{
						crossRefEntry.RefreshCache();
					}
					catch (COMException e4)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e4);
					}
				}
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.DsServiceName);
				if (appType == ApplicationPartitionType.ADApplicationPartition)
				{
					GetCrossRefEntry();
				}
				string text2 = (string)PropertyManager.GetPropertyValue(context, crossRefEntry, PropertyManager.DistinguishedName);
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(GetNamingRoleOwner(), DirectoryContextType.DirectoryServer, context);
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(newDirectoryContext, WellKnownDN.RootDSE);
				try
				{
					directoryEntry.Properties[PropertyManager.ReplicateSingleObject].Value = text + ":" + text2;
					directoryEntry.CommitChanges();
				}
				catch (COMException e5)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e5);
				}
				finally
				{
					directoryEntry.Dispose();
				}
				committed = true;
				if (cachedDirectoryServers != null || securityRefDomainModified)
				{
					if (cachedDirectoryServers != null)
					{
						crossRefEntry.Properties[PropertyManager.MsDSNCReplicaLocations].AddRange(cachedDirectoryServers.GetMultiValuedProperty());
					}
					if (securityRefDomainModified)
					{
						crossRefEntry.Properties[PropertyManager.MsDSSDReferenceDomain].Value = securityRefDomain;
					}
					try
					{
						crossRefEntry.CommitChanges();
					}
					catch (COMException e6)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e6);
					}
				}
			}
			else if (cachedDirectoryServers != null || securityRefDomainModified)
			{
				try
				{
					crossRefEntry.CommitChanges();
				}
				catch (COMException e7)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e7);
				}
			}
			cachedDirectoryServers = null;
			securityRefDomainModified = false;
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override DirectoryEntry GetDirectoryEntry()
		{
			CheckIfDisposed();
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			return DirectoryEntryManager.GetDirectoryEntry(context, base.Name);
		}

		private void ValidateApplicationPartitionParameters(DirectoryContext context, string distinguishedName, string objectClass, bool objectClassSpecified)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null || !context.isServer())
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeServer"), "context");
			}
			if (distinguishedName == null)
			{
				throw new ArgumentNullException("distinguishedName");
			}
			if (distinguishedName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "distinguishedName");
			}
			base.context = new DirectoryContext(context);
			directoryEntryMgr = new DirectoryEntryManager(base.context);
			dnsName = Utils.GetDnsNameFromDN(distinguishedName);
			partitionName = distinguishedName;
			Component[] dNComponents = Utils.GetDNComponents(distinguishedName);
			if (dNComponents.Length == 1)
			{
				throw new NotSupportedException(Res.GetString("OneLevelPartitionNotSupported"));
			}
			appType = GetApplicationPartitionType(base.context);
			if (appType == ApplicationPartitionType.ADApplicationPartition && objectClassSpecified)
			{
				throw new InvalidOperationException(Res.GetString("NoObjectClassForADPartition"));
			}
			if (objectClassSpecified)
			{
				if (objectClass == null)
				{
					throw new ArgumentNullException("objectClass");
				}
				if (objectClass.Length == 0)
				{
					throw new ArgumentException(Res.GetString("EmptyStringParameter"), "objectClass");
				}
			}
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				string name = null;
				try
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
					name = (string)PropertyManager.GetPropertyValue(base.context, cachedDirectoryEntry, PropertyManager.DnsHostName);
				}
				catch (COMException e)
				{
					ExceptionHelper.GetExceptionFromCOMException(base.context, e);
				}
				base.context = Utils.GetNewDirectoryContext(name, DirectoryContextType.DirectoryServer, context);
			}
		}

		[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
		private void CreateApplicationPartition(string distinguishedName, string objectClass)
		{
			if (appType == ApplicationPartitionType.ADApplicationPartition)
			{
				DirectoryEntry directoryEntry = null;
				DirectoryEntry directoryEntry2 = null;
				try
				{
					AuthenticationTypes authenticationTypes = Utils.DefaultAuthType | AuthenticationTypes.FastBind | AuthenticationTypes.Delegation;
					if (DirectoryContext.ServerBindSupported)
					{
						authenticationTypes |= AuthenticationTypes.ServerBind;
					}
					directoryEntry = new DirectoryEntry("LDAP://" + context.GetServerName() + "/" + distinguishedName, context.UserName, context.Password, authenticationTypes);
					directoryEntry2 = directoryEntry.Parent;
					domainDNSEntry = directoryEntry2.Children.Add(Utils.GetRdnFromDN(distinguishedName), PropertyManager.DomainDNS);
					domainDNSEntry.Properties[PropertyManager.InstanceType].Value = (NCFlags)5;
					committed = false;
					return;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				finally
				{
					directoryEntry2?.Dispose();
					directoryEntry?.Dispose();
				}
			}
			try
			{
				InitializeCrossRef(distinguishedName);
				DirectoryEntry directoryEntry3 = null;
				DirectoryEntry directoryEntry4 = null;
				try
				{
					AuthenticationTypes authenticationTypes2 = Utils.DefaultAuthType | AuthenticationTypes.FastBind;
					if (DirectoryContext.ServerBindSupported)
					{
						authenticationTypes2 |= AuthenticationTypes.ServerBind;
					}
					directoryEntry3 = new DirectoryEntry("LDAP://" + context.Name + "/" + distinguishedName, context.UserName, context.Password, authenticationTypes2);
					directoryEntry4 = directoryEntry3.Parent;
					domainDNSEntry = directoryEntry4.Children.Add(Utils.GetRdnFromDN(distinguishedName), objectClass);
					domainDNSEntry.Properties[PropertyManager.InstanceType].Value = (NCFlags)5;
					committed = false;
				}
				finally
				{
					directoryEntry4?.Dispose();
					directoryEntry3?.Dispose();
				}
			}
			catch (COMException e2)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
			}
		}

		private void InitializeCrossRef(string distinguishedName)
		{
			if (crossRefEntry != null)
			{
				return;
			}
			DirectoryEntry directoryEntry = null;
			try
			{
				string namingRoleOwner = GetNamingRoleOwner();
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(namingRoleOwner, DirectoryContextType.DirectoryServer, context);
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(newDirectoryContext, WellKnownDN.PartitionsContainer);
				string name = string.Concat("CN={", Guid.NewGuid(), "}");
				crossRefEntry = directoryEntry.Children.Add(name, "crossRef");
				string text = null;
				if (appType == ApplicationPartitionType.ADAMApplicationPartition)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
					string dn = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.DsServiceName);
					text = Utils.GetAdamHostNameAndPortsFromNTDSA(context, dn);
				}
				else
				{
					text = context.Name;
				}
				crossRefEntry.Properties[PropertyManager.DnsRoot].Value = text;
				crossRefEntry.Properties[PropertyManager.Enabled].Value = false;
				crossRefEntry.Properties[PropertyManager.NCName].Value = distinguishedName;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
		}

		private static ApplicationPartitionType GetApplicationPartitionType(DirectoryContext context)
		{
			ApplicationPartitionType applicationPartitionType = ApplicationPartitionType.Unknown;
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			try
			{
				foreach (string item in directoryEntry.Properties[PropertyManager.SupportedCapabilities])
				{
					if (string.Compare(item, SupportedCapability.ADOid, StringComparison.OrdinalIgnoreCase) == 0)
					{
						applicationPartitionType = ApplicationPartitionType.ADApplicationPartition;
					}
					if (string.Compare(item, SupportedCapability.ADAMOid, StringComparison.OrdinalIgnoreCase) == 0)
					{
						applicationPartitionType = ApplicationPartitionType.ADAMApplicationPartition;
					}
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry.Dispose();
			}
			if (applicationPartitionType == ApplicationPartitionType.Unknown)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ApplicationPartitionTypeUnknown"));
			}
			return applicationPartitionType;
		}

		internal DirectoryEntry GetCrossRefEntry()
		{
			if (crossRefEntry != null)
			{
				return crossRefEntry;
			}
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
			try
			{
				crossRefEntry = Utils.GetCrossRefEntry(context, directoryEntry, base.Name);
			}
			finally
			{
				directoryEntry.Dispose();
			}
			return crossRefEntry;
		}

		internal string GetNamingRoleOwner()
		{
			string text = null;
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
			try
			{
				if (appType == ApplicationPartitionType.ADApplicationPartition)
				{
					return Utils.GetDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner));
				}
				return Utils.GetAdamDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner));
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		private DirectoryServer FindDirectoryServerInternal(string siteName, bool forceRediscovery)
		{
			DirectoryServer directoryServer = null;
			LocatorOptions locatorOptions = (LocatorOptions)0L;
			int num = 0;
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			if (forceRediscovery)
			{
				locatorOptions = LocatorOptions.ForceRediscovery;
			}
			num = Locator.DsGetDcNameWrapper(null, dnsName, siteName, (long)(locatorOptions | (LocatorOptions)32768L), out var domainControllerInfo);
			switch (num)
			{
			case 1355:
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ReplicaNotFound"), typeof(DirectoryServer), null);
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			case 0:
			{
				string text = domainControllerInfo.DomainControllerName.Substring(2);
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context);
				return new DomainController(newDirectoryContext, text);
			}
			}
		}

		private ReadOnlyDirectoryServerCollection FindAllDirectoryServersInternal(string siteName)
		{
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			ArrayList arrayList = new ArrayList();
			foreach (string replica in Utils.GetReplicaList(context, base.Name, siteName, isDefaultNC: false, isADAM: false, isGC: false))
			{
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(replica, DirectoryContextType.DirectoryServer, context);
				arrayList.Add(new DomainController(newDirectoryContext, replica));
			}
			return new ReadOnlyDirectoryServerCollection(arrayList);
		}

		private ReadOnlyDirectoryServerCollection FindAllDiscoverableDirectoryServersInternal(string siteName)
		{
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			if (!committed)
			{
				throw new InvalidOperationException(Res.GetString("CannotPerformOperationOnUncommittedObject"));
			}
			long dcFlags = 32768L;
			return new ReadOnlyDirectoryServerCollection(Locator.EnumerateDomainControllers(context, dnsName, siteName, dcFlags));
		}
	}
	public class ApplicationPartitionCollection : ReadOnlyCollectionBase
	{
		public ApplicationPartition this[int index] => (ApplicationPartition)base.InnerList[index];

		internal ApplicationPartitionCollection()
		{
		}

		internal ApplicationPartitionCollection(ArrayList values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(ApplicationPartition applicationPartition)
		{
			if (applicationPartition == null)
			{
				throw new ArgumentNullException("applicationPartition");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ApplicationPartition applicationPartition2 = (ApplicationPartition)base.InnerList[i];
				if (Utils.Compare(applicationPartition2.Name, applicationPartition.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ApplicationPartition applicationPartition)
		{
			if (applicationPartition == null)
			{
				throw new ArgumentNullException("applicationPartition");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ApplicationPartition applicationPartition2 = (ApplicationPartition)base.InnerList[i];
				if (Utils.Compare(applicationPartition2.Name, applicationPartition.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ApplicationPartition[] applicationPartitions, int index)
		{
			base.InnerList.CopyTo(applicationPartitions, index);
		}
	}
	public class AttributeMetadata
	{
		private string pszAttributeName;

		private int dwVersion;

		private DateTime ftimeLastOriginatingChange;

		private Guid uuidLastOriginatingDsaInvocationID;

		private long usnOriginatingChange;

		private long usnLocalChange;

		private string pszLastOriginatingDsaDN;

		private string originatingServerName;

		private DirectoryServer server;

		private Hashtable nameTable;

		private bool advanced;

		public string Name => pszAttributeName;

		public int Version => dwVersion;

		public DateTime LastOriginatingChangeTime => ftimeLastOriginatingChange;

		public Guid LastOriginatingInvocationId => uuidLastOriginatingDsaInvocationID;

		public long OriginatingChangeUsn => usnOriginatingChange;

		public long LocalChangeUsn => usnLocalChange;

		public string OriginatingServer
		{
			get
			{
				if (originatingServerName == null)
				{
					if (nameTable.Contains(LastOriginatingInvocationId))
					{
						originatingServerName = (string)nameTable[LastOriginatingInvocationId];
					}
					else if (!advanced || (advanced && pszLastOriginatingDsaDN != null))
					{
						originatingServerName = Utils.GetServerNameFromInvocationID(pszLastOriginatingDsaDN, LastOriginatingInvocationId, server);
						nameTable.Add(LastOriginatingInvocationId, originatingServerName);
					}
				}
				return originatingServerName;
			}
		}

		internal AttributeMetadata(IntPtr info, bool advanced, DirectoryServer server, Hashtable table)
		{
			if (advanced)
			{
				DS_REPL_ATTR_META_DATA_2 dS_REPL_ATTR_META_DATA_ = new DS_REPL_ATTR_META_DATA_2();
				Marshal.PtrToStructure(info, dS_REPL_ATTR_META_DATA_);
				pszAttributeName = Marshal.PtrToStringUni(dS_REPL_ATTR_META_DATA_.pszAttributeName);
				dwVersion = dS_REPL_ATTR_META_DATA_.dwVersion;
				long fileTime = (uint)dS_REPL_ATTR_META_DATA_.ftimeLastOriginatingChange1 + ((long)dS_REPL_ATTR_META_DATA_.ftimeLastOriginatingChange2 << 32);
				ftimeLastOriginatingChange = DateTime.FromFileTime(fileTime);
				uuidLastOriginatingDsaInvocationID = dS_REPL_ATTR_META_DATA_.uuidLastOriginatingDsaInvocationID;
				usnOriginatingChange = dS_REPL_ATTR_META_DATA_.usnOriginatingChange;
				usnLocalChange = dS_REPL_ATTR_META_DATA_.usnLocalChange;
				pszLastOriginatingDsaDN = Marshal.PtrToStringUni(dS_REPL_ATTR_META_DATA_.pszLastOriginatingDsaDN);
			}
			else
			{
				DS_REPL_ATTR_META_DATA dS_REPL_ATTR_META_DATA = new DS_REPL_ATTR_META_DATA();
				Marshal.PtrToStructure(info, dS_REPL_ATTR_META_DATA);
				pszAttributeName = Marshal.PtrToStringUni(dS_REPL_ATTR_META_DATA.pszAttributeName);
				dwVersion = dS_REPL_ATTR_META_DATA.dwVersion;
				long fileTime2 = (uint)dS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange1 + ((long)dS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange2 << 32);
				ftimeLastOriginatingChange = DateTime.FromFileTime(fileTime2);
				uuidLastOriginatingDsaInvocationID = dS_REPL_ATTR_META_DATA.uuidLastOriginatingDsaInvocationID;
				usnOriginatingChange = dS_REPL_ATTR_META_DATA.usnOriginatingChange;
				usnLocalChange = dS_REPL_ATTR_META_DATA.usnLocalChange;
			}
			this.server = server;
			nameTable = table;
			this.advanced = advanced;
		}
	}
	public class AttributeMetadataCollection : ReadOnlyCollectionBase
	{
		public AttributeMetadata this[int index] => (AttributeMetadata)base.InnerList[index];

		internal AttributeMetadataCollection()
		{
		}

		public bool Contains(AttributeMetadata metadata)
		{
			if (metadata == null)
			{
				throw new ArgumentNullException("metadata");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				AttributeMetadata attributeMetadata = (AttributeMetadata)base.InnerList[i];
				string name = attributeMetadata.Name;
				if (Utils.Compare(name, metadata.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(AttributeMetadata metadata)
		{
			if (metadata == null)
			{
				throw new ArgumentNullException("metadata");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				AttributeMetadata attributeMetadata = (AttributeMetadata)base.InnerList[i];
				if (Utils.Compare(attributeMetadata.Name, metadata.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(AttributeMetadata[] metadata, int index)
		{
			base.InnerList.CopyTo(metadata, index);
		}

		internal int Add(AttributeMetadata metadata)
		{
			return base.InnerList.Add(metadata);
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ConfigurationSet
	{
		private DirectoryContext context;

		private DirectoryEntryManager directoryEntryMgr;

		private bool disposed;

		private string configSetName;

		private ReadOnlySiteCollection cachedSites;

		private AdamInstanceCollection cachedADAMInstances;

		private ApplicationPartitionCollection cachedApplicationPartitions;

		private ActiveDirectorySchema cachedSchema;

		private AdamInstance cachedSchemaRoleOwner;

		private AdamInstance cachedNamingRoleOwner;

		private ReplicationSecurityLevel cachedSecurityLevel = (ReplicationSecurityLevel)(-1);

		private static TimeSpan locationTimeout = new TimeSpan(0, 4, 0);

		public string Name
		{
			get
			{
				CheckIfDisposed();
				return configSetName;
			}
		}

		public ReadOnlySiteCollection Sites
		{
			get
			{
				CheckIfDisposed();
				if (cachedSites == null)
				{
					cachedSites = new ReadOnlySiteCollection(GetSites());
				}
				return cachedSites;
			}
		}

		public AdamInstanceCollection AdamInstances
		{
			get
			{
				CheckIfDisposed();
				if (cachedADAMInstances == null)
				{
					cachedADAMInstances = FindAllAdamInstances();
				}
				return cachedADAMInstances;
			}
		}

		public ApplicationPartitionCollection ApplicationPartitions
		{
			get
			{
				CheckIfDisposed();
				if (cachedApplicationPartitions == null)
				{
					cachedApplicationPartitions = new ApplicationPartitionCollection(GetApplicationPartitions());
				}
				return cachedApplicationPartitions;
			}
		}

		public ActiveDirectorySchema Schema
		{
			get
			{
				CheckIfDisposed();
				if (cachedSchema == null)
				{
					try
					{
						cachedSchema = new ActiveDirectorySchema(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext));
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
				return cachedSchema;
			}
		}

		public AdamInstance SchemaRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedSchemaRoleOwner == null)
				{
					cachedSchemaRoleOwner = GetRoleOwner(AdamRole.SchemaRole);
				}
				return cachedSchemaRoleOwner;
			}
		}

		public AdamInstance NamingRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedNamingRoleOwner == null)
				{
					cachedNamingRoleOwner = GetRoleOwner(AdamRole.NamingRole);
				}
				return cachedNamingRoleOwner;
			}
		}

		internal ConfigurationSet(DirectoryContext context, string configSetName, DirectoryEntryManager directoryEntryMgr)
		{
			this.context = context;
			this.configSetName = configSetName;
			this.directoryEntryMgr = directoryEntryMgr;
		}

		internal ConfigurationSet(DirectoryContext context, string configSetName)
			: this(context, configSetName, new DirectoryEntryManager(context))
		{
		}

		public void Dispose()
		{
			Dispose(disposing: true);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			if (disposing)
			{
				foreach (DirectoryEntry cachedDirectoryEntry in directoryEntryMgr.GetCachedDirectoryEntries())
				{
					cachedDirectoryEntry.Dispose();
				}
			}
			disposed = true;
		}

		public static ConfigurationSet GetConfigurationSet(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.ConfigurationSet && context.ContextType != DirectoryContextType.DirectoryServer)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeServerORConfigSet"), "context");
			}
			if (!context.isServer() && !context.isADAMConfigSet())
			{
				if (context.ContextType == DirectoryContextType.ConfigurationSet)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ConfigSetNotFound"), typeof(ConfigurationSet), context.Name);
				}
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AINotFound", context.Name), typeof(ConfigurationSet), null);
			}
			context = new DirectoryContext(context);
			DirectoryEntryManager directoryEntryManager = new DirectoryEntryManager(context);
			DirectoryEntry directoryEntry = null;
			string text = null;
			try
			{
				directoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (context.isServer() && !Utils.CheckCapability(directoryEntry, Capability.ActiveDirectoryApplicationMode))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AINotFound", context.Name), typeof(ConfigurationSet), null);
				}
				text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					if (context.ContextType == DirectoryContextType.ConfigurationSet)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ConfigSetNotFound"), typeof(ConfigurationSet), context.Name);
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AINotFound", context.Name), typeof(ConfigurationSet), null);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				if (context.ContextType == DirectoryContextType.ConfigurationSet)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ConfigSetNotFound"), typeof(ConfigurationSet), context.Name);
				}
				throw;
			}
			return new ConfigurationSet(context, text, directoryEntryManager);
		}

		public AdamInstance FindAdamInstance()
		{
			CheckIfDisposed();
			return FindOneAdamInstance(Name, context, null, null);
		}

		public AdamInstance FindAdamInstance(string partitionName)
		{
			CheckIfDisposed();
			if (partitionName == null)
			{
				throw new ArgumentNullException("partitionName");
			}
			return FindOneAdamInstance(Name, context, partitionName, null);
		}

		public AdamInstance FindAdamInstance(string partitionName, string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return FindOneAdamInstance(Name, context, partitionName, siteName);
		}

		public AdamInstanceCollection FindAllAdamInstances()
		{
			CheckIfDisposed();
			return FindAdamInstances(context, null, null);
		}

		public AdamInstanceCollection FindAllAdamInstances(string partitionName)
		{
			CheckIfDisposed();
			if (partitionName == null)
			{
				throw new ArgumentNullException("partitionName");
			}
			return FindAdamInstances(context, partitionName, null);
		}

		public AdamInstanceCollection FindAllAdamInstances(string partitionName, string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return FindAdamInstances(context, partitionName, siteName);
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			CheckIfDisposed();
			return DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.ConfigurationNamingContext);
		}

		public ReplicationSecurityLevel GetSecurityLevel()
		{
			CheckIfDisposed();
			if (cachedSecurityLevel == (ReplicationSecurityLevel)(-1))
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.ConfigurationNamingContext);
				cachedSecurityLevel = (ReplicationSecurityLevel)(int)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.MsDSReplAuthenticationMode);
			}
			return cachedSecurityLevel;
		}

		public void SetSecurityLevel(ReplicationSecurityLevel securityLevel)
		{
			CheckIfDisposed();
			if (securityLevel < ReplicationSecurityLevel.NegotiatePassThrough || securityLevel > ReplicationSecurityLevel.MutualAuthentication)
			{
				throw new InvalidEnumArgumentException("securityLevel", (int)securityLevel, typeof(ReplicationSecurityLevel));
			}
			try
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.ConfigurationNamingContext);
				cachedDirectoryEntry.Properties[PropertyManager.MsDSReplAuthenticationMode].Value = (int)securityLevel;
				cachedDirectoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			cachedSecurityLevel = (ReplicationSecurityLevel)(-1);
		}

		public override string ToString()
		{
			return Name;
		}

		[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
		private static DirectoryEntry GetSearchRootEntry(Forest forest)
		{
			DirectoryContext directoryContext = forest.GetDirectoryContext();
			bool flag = false;
			bool flag2 = false;
			AuthenticationTypes authenticationTypes = Utils.DefaultAuthType;
			if (directoryContext.ContextType == DirectoryContextType.DirectoryServer)
			{
				flag = true;
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(directoryContext, WellKnownDN.RootDSE);
				string s = (string)PropertyManager.GetPropertyValue(directoryContext, directoryEntry, PropertyManager.IsGlobalCatalogReady);
				flag2 = Utils.Compare(s, "TRUE") == 0;
			}
			if (flag)
			{
				if (DirectoryContext.ServerBindSupported)
				{
					authenticationTypes |= AuthenticationTypes.ServerBind;
				}
				if (flag2)
				{
					return new DirectoryEntry("GC://" + directoryContext.GetServerName(), directoryContext.UserName, directoryContext.Password, authenticationTypes);
				}
				return new DirectoryEntry("LDAP://" + directoryContext.GetServerName(), directoryContext.UserName, directoryContext.Password, authenticationTypes);
			}
			return new DirectoryEntry("GC://" + forest.Name, directoryContext.UserName, directoryContext.Password, authenticationTypes);
		}

		internal static AdamInstance FindAnyAdamInstance(DirectoryContext context)
		{
			if (context.ContextType != DirectoryContextType.ConfigurationSet)
			{
				DirectoryEntryManager directoryEntryManager = new DirectoryEntryManager(context);
				DirectoryEntry cachedDirectoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (!Utils.CheckCapability(cachedDirectoryEntry, Capability.ActiveDirectoryApplicationMode))
				{
					directoryEntryManager.RemoveIfExists(directoryEntryManager.ExpandWellKnownDN(WellKnownDN.RootDSE));
					throw new ArgumentException(Res.GetString("TargetShouldBeServerORConfigSet"), "context");
				}
				string adamHostName = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.DnsHostName);
				return new AdamInstance(context, adamHostName, directoryEntryManager);
			}
			DirectoryEntry searchRootEntry = GetSearchRootEntry(Forest.GetCurrentForest());
			ArrayList arrayList = new ArrayList();
			try
			{
				_ = (string)searchRootEntry.Properties["distinguishedName"].Value;
				StringBuilder stringBuilder = new StringBuilder(15);
				stringBuilder.Append("(&(");
				stringBuilder.Append(PropertyManager.ObjectCategory);
				stringBuilder.Append("=serviceConnectionPoint)");
				stringBuilder.Append("(");
				stringBuilder.Append(PropertyManager.Keywords);
				stringBuilder.Append("=1.2.840.113556.1.4.1851)(");
				stringBuilder.Append(PropertyManager.Keywords);
				stringBuilder.Append("=");
				stringBuilder.Append(Utils.GetEscapedFilterValue(context.Name));
				stringBuilder.Append("))");
				string filter = stringBuilder.ToString();
				ADSearcher aDSearcher = new ADSearcher(searchRootEntry, filter, new string[1] { PropertyManager.ServiceBindingInformation }, SearchScope.Subtree, pagedSearch: false, cacheResults: false);
				SearchResultCollection searchResultCollection = aDSearcher.FindAll();
				try
				{
					foreach (SearchResult item in searchResultCollection)
					{
						string text = "ldap://";
						foreach (string item2 in item.Properties[PropertyManager.ServiceBindingInformation])
						{
							if (item2.Length > text.Length && string.Compare(item2.Substring(0, text.Length), text, StringComparison.OrdinalIgnoreCase) == 0)
							{
								arrayList.Add(item2.Substring(text.Length));
							}
						}
					}
				}
				finally
				{
					searchResultCollection.Dispose();
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchRootEntry.Dispose();
			}
			return FindAliveAdamInstance(null, context, arrayList);
		}

		internal static AdamInstance FindOneAdamInstance(DirectoryContext context, string partitionName, string siteName)
		{
			return FindOneAdamInstance(null, context, partitionName, siteName);
		}

		internal static AdamInstance FindOneAdamInstance(string configSetName, DirectoryContext context, string partitionName, string siteName)
		{
			if (partitionName != null && partitionName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partitionName");
			}
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			ArrayList replicaList = Utils.GetReplicaList(context, partitionName, siteName, isDefaultNC: false, isADAM: true, isGC: false);
			if (replicaList.Count < 1)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ADAMInstanceNotFound"), typeof(AdamInstance), null);
			}
			return FindAliveAdamInstance(configSetName, context, replicaList);
		}

		internal static AdamInstanceCollection FindAdamInstances(DirectoryContext context, string partitionName, string siteName)
		{
			if (partitionName != null && partitionName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partitionName");
			}
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			ArrayList arrayList = new ArrayList();
			foreach (string replica in Utils.GetReplicaList(context, partitionName, siteName, isDefaultNC: false, isADAM: true, isGC: false))
			{
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(replica, DirectoryContextType.DirectoryServer, context);
				arrayList.Add(new AdamInstance(newDirectoryContext, replica));
			}
			return new AdamInstanceCollection(arrayList);
		}

		internal static AdamInstance FindAliveAdamInstance(string configSetName, DirectoryContext context, ArrayList adamInstanceNames)
		{
			bool flag = false;
			AdamInstance result = null;
			DateTime utcNow = DateTime.UtcNow;
			foreach (string adamInstanceName in adamInstanceNames)
			{
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(adamInstanceName, DirectoryContextType.DirectoryServer, context);
				DirectoryEntryManager directoryEntryManager = new DirectoryEntryManager(newDirectoryContext);
				DirectoryEntry cachedDirectoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				try
				{
					cachedDirectoryEntry.Bind(throwIfFail: true);
					result = new AdamInstance(newDirectoryContext, adamInstanceName, directoryEntryManager, nameIncludesPort: true);
					flag = true;
				}
				catch (COMException ex)
				{
					if (ex.ErrorCode != -2147016646 && ex.ErrorCode != -2147016690 && ex.ErrorCode != -2147016689 && ex.ErrorCode != -2147023436)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
					}
					if (DateTime.UtcNow.Subtract(utcNow) > locationTimeout)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ADAMInstanceNotFoundInConfigSet", (configSetName != null) ? configSetName : context.Name), typeof(AdamInstance), null);
					}
				}
				if (flag)
				{
					return result;
				}
			}
			throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ADAMInstanceNotFoundInConfigSet", (configSetName != null) ? configSetName : context.Name), typeof(AdamInstance), null);
		}

		private AdamInstance GetRoleOwner(AdamRole role)
		{
			DirectoryEntry directoryEntry = null;
			string text = null;
			try
			{
				switch (role)
				{
				case AdamRole.SchemaRole:
					directoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.SchemaNamingContext);
					break;
				case AdamRole.NamingRole:
					directoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.PartitionsContainer);
					break;
				}
				directoryEntry.RefreshCache();
				text = Utils.GetAdamDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner));
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context);
			return new AdamInstance(newDirectoryContext, text);
		}

		private ArrayList GetSites()
		{
			ArrayList arrayList = new ArrayList();
			DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.SitesContainer);
			string filter = "(" + PropertyManager.ObjectCategory + "=site)";
			ADSearcher aDSearcher = new ADSearcher(cachedDirectoryEntry, filter, new string[1] { PropertyManager.Cn }, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
				foreach (SearchResult item in searchResultCollection)
				{
					arrayList.Add(new ActiveDirectorySite(context, (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn), existing: true));
				}
				return arrayList;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
			}
		}

		private ArrayList GetApplicationPartitions()
		{
			ArrayList arrayList = new ArrayList();
			DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
			DirectoryEntry cachedDirectoryEntry2 = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.PartitionsContainer);
			StringBuilder stringBuilder = new StringBuilder(100);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=crossRef)(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.804:=");
			stringBuilder.Append(1);
			stringBuilder.Append(")(!(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.803:=");
			stringBuilder.Append(2);
			stringBuilder.Append(")))");
			string filter = stringBuilder.ToString();
			ADSearcher aDSearcher = new ADSearcher(cachedDirectoryEntry2, filter, new string[2]
			{
				PropertyManager.NCName,
				PropertyManager.MsDSNCReplicaLocations
			}, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
				string value = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.SchemaNamingContext);
				string value2 = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.ConfigurationNamingContext);
				foreach (SearchResult item in searchResultCollection)
				{
					string text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.NCName);
					if (!text.Equals(value) && !text.Equals(value2))
					{
						ResultPropertyValueCollection resultPropertyValueCollection = item.Properties[PropertyManager.MsDSNCReplicaLocations];
						if (resultPropertyValueCollection.Count > 0)
						{
							string adamDnsHostNameFromNTDSA = Utils.GetAdamDnsHostNameFromNTDSA(context, (string)resultPropertyValueCollection[Utils.GetRandomIndex(resultPropertyValueCollection.Count)]);
							DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(adamDnsHostNameFromNTDSA, DirectoryContextType.DirectoryServer, context);
							arrayList.Add(new ApplicationPartition(newDirectoryContext, text, null, ApplicationPartitionType.ADAMApplicationPartition, new DirectoryEntryManager(newDirectoryContext)));
						}
					}
				}
				return arrayList;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
			}
		}

		private void CheckIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}
	}
	public enum DirectoryContextType
	{
		Domain,
		Forest,
		DirectoryServer,
		ConfigurationSet,
		ApplicationPartition
	}
	[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
	public class DirectoryContext
	{
		private string name;

		private DirectoryContextType contextType;

		private NetworkCredential credential;

		internal string serverName;

		internal bool usernameIsNull;

		internal bool passwordIsNull;

		private bool validated;

		private bool contextIsValid;

		private static bool platformSupported;

		private static bool serverBindSupported;

		private static bool dnsgetdcSupported;

		private static bool w2k;

		internal static LoadLibrarySafeHandle ADHandle;

		internal static LoadLibrarySafeHandle ADAMHandle;

		internal static bool ServerBindSupported => serverBindSupported;

		internal static bool DnsgetdcSupported => dnsgetdcSupported;

		public string Name => name;

		public string UserName
		{
			get
			{
				if (usernameIsNull)
				{
					return null;
				}
				return credential.UserName;
			}
		}

		internal string Password
		{
			[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
			get
			{
				if (passwordIsNull)
				{
					return null;
				}
				return credential.Password;
			}
		}

		public DirectoryContextType ContextType => contextType;

		internal NetworkCredential Credential => credential;

		static DirectoryContext()
		{
			platformSupported = true;
			serverBindSupported = true;
			dnsgetdcSupported = true;
			w2k = false;
			OperatingSystem oSVersion = Environment.OSVersion;
			if (oSVersion.Platform == PlatformID.Win32NT && oSVersion.Version.Major >= 5)
			{
				if (oSVersion.Version.Major == 5 && oSVersion.Version.Minor == 0)
				{
					w2k = true;
					dnsgetdcSupported = false;
					OSVersionInfoEx oSVersionInfoEx = new OSVersionInfoEx();
					if (!NativeMethods.GetVersionEx(oSVersionInfoEx))
					{
						int lastError = NativeMethods.GetLastError();
						throw new SystemException(Res.GetString("VersionFailure", lastError));
					}
					if (oSVersionInfoEx.servicePackMajor < 3)
					{
						serverBindSupported = false;
					}
				}
				GetLibraryHandle();
			}
			else
			{
				platformSupported = false;
				serverBindSupported = false;
				dnsgetdcSupported = false;
			}
		}

		internal void InitializeDirectoryContext(DirectoryContextType contextType, string name, string username, string password)
		{
			if (!platformSupported)
			{
				throw new PlatformNotSupportedException(Res.GetString("SupportedPlatforms"));
			}
			this.name = name;
			this.contextType = contextType;
			credential = new NetworkCredential(username, password);
			if (username == null)
			{
				usernameIsNull = true;
			}
			if (password == null)
			{
				passwordIsNull = true;
			}
		}

		internal DirectoryContext(DirectoryContextType contextType, string name, DirectoryContext context)
		{
			this.name = name;
			this.contextType = contextType;
			if (context != null)
			{
				credential = context.Credential;
				usernameIsNull = context.usernameIsNull;
				passwordIsNull = context.passwordIsNull;
			}
			else
			{
				credential = new NetworkCredential(null, null, null);
				usernameIsNull = true;
				passwordIsNull = true;
			}
		}

		internal DirectoryContext(DirectoryContext context)
		{
			name = context.Name;
			contextType = context.ContextType;
			credential = context.Credential;
			usernameIsNull = context.usernameIsNull;
			passwordIsNull = context.passwordIsNull;
			if (context.ContextType != DirectoryContextType.ConfigurationSet)
			{
				serverName = context.serverName;
			}
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryContext(DirectoryContextType contextType)
		{
			if (contextType != 0 && contextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("OnlyDomainOrForest"), "contextType");
			}
			InitializeDirectoryContext(contextType, null, null, null);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryContext(DirectoryContextType contextType, string name)
		{
			if (contextType < DirectoryContextType.Domain || contextType > DirectoryContextType.ApplicationPartition)
			{
				throw new InvalidEnumArgumentException("contextType", (int)contextType, typeof(DirectoryContextType));
			}
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			if (name.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "name");
			}
			InitializeDirectoryContext(contextType, name, null, null);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryContext(DirectoryContextType contextType, string username, string password)
		{
			if (contextType != 0 && contextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("OnlyDomainOrForest"), "contextType");
			}
			InitializeDirectoryContext(contextType, null, username, password);
		}

		[DirectoryServicesPermission(SecurityAction.Demand, Unrestricted = true)]
		public DirectoryContext(DirectoryContextType contextType, string name, string username, string password)
		{
			if (contextType < DirectoryContextType.Domain || contextType > DirectoryContextType.ApplicationPartition)
			{
				throw new InvalidEnumArgumentException("contextType", (int)contextType, typeof(DirectoryContextType));
			}
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			if (name.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "name");
			}
			InitializeDirectoryContext(contextType, name, username, password);
		}

		[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static bool IsContextValid(DirectoryContext context, DirectoryContextType contextType)
		{
			bool flag = false;
			if (contextType == DirectoryContextType.Domain || (contextType == DirectoryContextType.Forest && context.Name == null))
			{
				string text = context.Name;
				if (text == null)
				{
					context.serverName = GetLoggedOnDomain();
					return true;
				}
				int num = 0;
				num = Locator.DsGetDcNameWrapper(null, text, null, 16L, out var domainControllerInfo);
				switch (num)
				{
				case 1355:
					num = Locator.DsGetDcNameWrapper(null, text, null, 17L, out domainControllerInfo);
					switch (num)
					{
					case 1355:
						return false;
					default:
						throw ExceptionHelper.GetExceptionFromErrorCode(num);
					case 0:
						context.serverName = domainControllerInfo.DomainName;
						return true;
					}
				case 1212:
					return false;
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(num);
				case 0:
					context.serverName = domainControllerInfo.DomainName;
					return true;
				}
			}
			switch (contextType)
			{
			case DirectoryContextType.Forest:
			{
				int num3 = 0;
				num3 = Locator.DsGetDcNameWrapper(null, context.Name, null, 80L, out var domainControllerInfo3);
				switch (num3)
				{
				case 1355:
					num3 = Locator.DsGetDcNameWrapper(null, context.Name, null, 81L, out domainControllerInfo3);
					switch (num3)
					{
					case 1355:
						return false;
					default:
						throw ExceptionHelper.GetExceptionFromErrorCode(num3);
					case 0:
						context.serverName = domainControllerInfo3.DnsForestName;
						return true;
					}
				case 1212:
					return false;
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(num3);
				case 0:
					context.serverName = domainControllerInfo3.DnsForestName;
					return true;
				}
			}
			case DirectoryContextType.ApplicationPartition:
			{
				int num2 = 0;
				num2 = Locator.DsGetDcNameWrapper(null, context.Name, null, 32768L, out var domainControllerInfo2);
				switch (num2)
				{
				case 1355:
					num2 = Locator.DsGetDcNameWrapper(null, context.Name, null, 32769L, out domainControllerInfo2);
					return num2 switch
					{
						1355 => false, 
						0 => true, 
						_ => throw ExceptionHelper.GetExceptionFromErrorCode(num2), 
					};
				case 1212:
					return false;
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(num2);
				case 0:
					return true;
				}
			}
			case DirectoryContextType.DirectoryServer:
			{
				string text2 = null;
				text2 = Utils.SplitServerNameAndPortNumber(context.Name, out var _);
				DirectoryEntry directoryEntry = new DirectoryEntry("WinNT://" + text2 + ",computer", context.UserName, context.Password, Utils.DefaultAuthType);
				try
				{
					directoryEntry.Bind(throwIfFail: true);
					return true;
				}
				catch (COMException ex)
				{
					if (ex.ErrorCode == -2147024843 || ex.ErrorCode == -2147024845 || ex.ErrorCode == -2147463168)
					{
						return false;
					}
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
				}
				finally
				{
					directoryEntry.Dispose();
				}
			}
			default:
				return true;
			}
		}

		internal bool isRootDomain()
		{
			if (contextType != DirectoryContextType.Forest)
			{
				return false;
			}
			if (!validated)
			{
				contextIsValid = IsContextValid(this, DirectoryContextType.Forest);
				validated = true;
			}
			return contextIsValid;
		}

		internal bool isDomain()
		{
			if (contextType != 0)
			{
				return false;
			}
			if (!validated)
			{
				contextIsValid = IsContextValid(this, DirectoryContextType.Domain);
				validated = true;
			}
			return contextIsValid;
		}

		internal bool isNdnc()
		{
			if (contextType != DirectoryContextType.ApplicationPartition)
			{
				return false;
			}
			if (!validated)
			{
				contextIsValid = IsContextValid(this, DirectoryContextType.ApplicationPartition);
				validated = true;
			}
			return contextIsValid;
		}

		internal bool isServer()
		{
			if (contextType != DirectoryContextType.DirectoryServer)
			{
				return false;
			}
			if (!validated)
			{
				if (w2k)
				{
					contextIsValid = IsContextValid(this, DirectoryContextType.DirectoryServer) && !IsContextValid(this, DirectoryContextType.Domain) && !IsContextValid(this, DirectoryContextType.ApplicationPartition);
				}
				else
				{
					contextIsValid = IsContextValid(this, DirectoryContextType.DirectoryServer);
				}
				validated = true;
			}
			return contextIsValid;
		}

		internal bool isADAMConfigSet()
		{
			if (contextType != DirectoryContextType.ConfigurationSet)
			{
				return false;
			}
			if (!validated)
			{
				contextIsValid = IsContextValid(this, DirectoryContextType.ConfigurationSet);
				validated = true;
			}
			return contextIsValid;
		}

		internal bool isCurrentForest()
		{
			bool result = false;
			DomainControllerInfo domainControllerInfo = Locator.GetDomainControllerInfo(null, name, null, 1073741840L);
			string loggedOnDomain = GetLoggedOnDomain();
			DomainControllerInfo domainControllerInfo2;
			int num = Locator.DsGetDcNameWrapper(null, loggedOnDomain, null, 1073741840L, out domainControllerInfo2);
			switch (num)
			{
			case 0:
				result = Utils.Compare(domainControllerInfo.DnsForestName, domainControllerInfo2.DnsForestName) == 0;
				break;
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			case 1355:
				break;
			}
			return result;
		}

		internal bool useServerBind()
		{
			if (ContextType != DirectoryContextType.DirectoryServer)
			{
				return ContextType == DirectoryContextType.ConfigurationSet;
			}
			return true;
		}

		internal string GetServerName()
		{
			if (serverName == null)
			{
				switch (contextType)
				{
				case DirectoryContextType.ConfigurationSet:
				{
					AdamInstance adamInstance = ConfigurationSet.FindAnyAdamInstance(this);
					try
					{
						serverName = adamInstance.Name;
					}
					finally
					{
						adamInstance.Dispose();
					}
					break;
				}
				case DirectoryContextType.Domain:
				case DirectoryContextType.Forest:
					if (name == null || (contextType == DirectoryContextType.Forest && isCurrentForest()))
					{
						serverName = GetLoggedOnDomain();
					}
					else
					{
						serverName = GetDnsDomainName(name);
					}
					break;
				case DirectoryContextType.ApplicationPartition:
					serverName = name;
					break;
				case DirectoryContextType.DirectoryServer:
					serverName = name;
					break;
				}
			}
			return serverName;
		}

		internal static string GetLoggedOnDomain()
		{
			string text = null;
			NegotiateCallerNameRequest negotiateCallerNameRequest = new NegotiateCallerNameRequest();
			int submitBufferLength = Marshal.SizeOf(negotiateCallerNameRequest);
			IntPtr protocolReturnBuffer = IntPtr.Zero;
			NegotiateCallerNameResponse negotiateCallerNameResponse = new NegotiateCallerNameResponse();
			int num = NativeMethods.LsaConnectUntrusted(out var lsaHandle);
			switch (num)
			{
			case 0:
			{
				negotiateCallerNameRequest.messageType = 1;
				num = NativeMethods.LsaCallAuthenticationPackage(lsaHandle, 0, negotiateCallerNameRequest, submitBufferLength, out protocolReturnBuffer, out var _, out var protocolStatus);
				try
				{
					if (num != 0 || protocolStatus != 0)
					{
						switch (num)
						{
						case -1073741756:
							throw new OutOfMemoryException();
						case 0:
						{
							if (UnsafeNativeMethods.LsaNtStatusToWinError(protocolStatus) != 1312)
							{
								break;
							}
							WindowsIdentity current = WindowsIdentity.GetCurrent();
							int length = current.Name.IndexOf('\\');
							text = current.Name.Substring(0, length);
							goto end_IL_0045;
						}
						}
						throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError((num != 0) ? num : protocolStatus));
					}
					Marshal.PtrToStructure(protocolReturnBuffer, negotiateCallerNameResponse);
					int length2 = negotiateCallerNameResponse.callerName.IndexOf('\\');
					text = negotiateCallerNameResponse.callerName.Substring(0, length2);
					end_IL_0045:;
				}
				finally
				{
					if (protocolReturnBuffer != IntPtr.Zero)
					{
						NativeMethods.LsaFreeReturnBuffer(protocolReturnBuffer);
					}
				}
				text = ((text == null || Utils.Compare(text, Utils.GetNtAuthorityString()) != 0) ? GetDnsDomainName(text) : GetDnsDomainName(null));
				if (text == null)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("ContextNotAssociatedWithDomain"));
				}
				return text;
			}
			case -1073741756:
				throw new OutOfMemoryException();
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError(num));
			}
		}

		internal static string GetDnsDomainName(string domainName)
		{
			int num = 0;
			num = Locator.DsGetDcNameWrapper(null, domainName, null, 16L, out var domainControllerInfo);
			switch (num)
			{
			case 1355:
				num = Locator.DsGetDcNameWrapper(null, domainName, null, 17L, out domainControllerInfo);
				switch (num)
				{
				case 1355:
					return null;
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(num);
				case 0:
					break;
				}
				break;
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			case 0:
				break;
			}
			return domainControllerInfo.DomainName;
		}

		[FileIOPermission(SecurityAction.Assert, AllFiles = FileIOPermissionAccess.PathDiscovery)]
		private static void GetLibraryHandle()
		{
			string text = Environment.SystemDirectory + "\\ntdsapi.dll";
			IntPtr intPtr = UnsafeNativeMethods.LoadLibrary(text);
			if (intPtr == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			ADHandle = new LoadLibrarySafeHandle(intPtr);
			string text2 = Environment.CurrentDirectory + "\\ntdsapi.dll";
			intPtr = UnsafeNativeMethods.LoadLibrary(text2);
			if (intPtr == (IntPtr)0)
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(Environment.SystemDirectory, 0, Environment.SystemDirectory.Length - 8);
				intPtr = UnsafeNativeMethods.LoadLibrary(stringBuilder.ToString() + "ADAM\\ntdsapi.dll");
				if (intPtr == (IntPtr)0)
				{
					ADAMHandle = ADHandle;
				}
				else
				{
					ADAMHandle = new LoadLibrarySafeHandle(intPtr);
				}
			}
			else
			{
				ADAMHandle = new LoadLibrarySafeHandle(intPtr);
			}
		}
	}
	internal class DistinguishedName
	{
		private Component[] components;

		public Component[] Components => components;

		public DistinguishedName(string dn)
		{
			components = Utils.GetDNComponents(dn);
		}

		public bool Equals(DistinguishedName dn)
		{
			bool result = true;
			if (dn == null || components.GetLength(0) != dn.Components.GetLength(0))
			{
				result = false;
			}
			else
			{
				for (int i = 0; i < components.GetLength(0); i++)
				{
					if (Utils.Compare(components[i].Name, dn.Components[i].Name) != 0 || Utils.Compare(components[i].Value, dn.Components[i].Value) != 0)
					{
						result = false;
						break;
					}
				}
			}
			return result;
		}

		public override bool Equals(object obj)
		{
			if (obj == null || !(obj is DistinguishedName))
			{
				return false;
			}
			return Equals((DistinguishedName)obj);
		}

		public override int GetHashCode()
		{
			int num = 0;
			for (int i = 0; i < components.GetLength(0); i++)
			{
				num = num + components[i].Name.ToUpperInvariant().GetHashCode() + components[i].Value.ToUpperInvariant().GetHashCode();
			}
			return num;
		}

		public override string ToString()
		{
			string text = components[0].Name + "=" + components[0].Value;
			for (int i = 1; i < components.GetLength(0); i++)
			{
				text = text + "," + components[i].Name + "=" + components[i].Value;
			}
			return text;
		}
	}
	[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
	internal class DirectoryEntryManager
	{
		private Hashtable directoryEntries = new Hashtable();

		private string bindingPrefix;

		private DirectoryContext context;

		private NativeComInterfaces.IAdsPathname pathCracker;

		internal DirectoryEntryManager(DirectoryContext context)
		{
			this.context = context;
			pathCracker = (NativeComInterfaces.IAdsPathname)new NativeComInterfaces.Pathname();
			pathCracker.EscapedMode = 2;
		}

		internal ICollection GetCachedDirectoryEntries()
		{
			return directoryEntries.Values;
		}

		internal DirectoryEntry GetCachedDirectoryEntry(WellKnownDN dn)
		{
			return GetCachedDirectoryEntry(ExpandWellKnownDN(dn));
		}

		internal DirectoryEntry GetCachedDirectoryEntry(string distinguishedName)
		{
			object key = distinguishedName;
			if (string.Compare(distinguishedName, "rootdse", StringComparison.OrdinalIgnoreCase) != 0 && string.Compare(distinguishedName, "schema", StringComparison.OrdinalIgnoreCase) != 0)
			{
				key = new DistinguishedName(distinguishedName);
			}
			if (!directoryEntries.ContainsKey(key))
			{
				DirectoryEntry newDirectoryEntry = GetNewDirectoryEntry(distinguishedName);
				directoryEntries.Add(key, newDirectoryEntry);
			}
			return (DirectoryEntry)directoryEntries[key];
		}

		internal void RemoveIfExists(string distinguishedName)
		{
			object key = distinguishedName;
			if (string.Compare(distinguishedName, "rootdse", StringComparison.OrdinalIgnoreCase) != 0)
			{
				key = new DistinguishedName(distinguishedName);
			}
			if (directoryEntries.ContainsKey(key))
			{
				DirectoryEntry directoryEntry = (DirectoryEntry)directoryEntries[key];
				if (directoryEntry != null)
				{
					directoryEntries.Remove(key);
					directoryEntry.Dispose();
				}
			}
		}

		private DirectoryEntry GetNewDirectoryEntry(string dn)
		{
			if (bindingPrefix == null)
			{
				bindingPrefix = "LDAP://" + context.GetServerName() + "/";
			}
			pathCracker.Set(dn, 4);
			string text = pathCracker.Retrieve(7);
			return Bind(bindingPrefix + text, context.UserName, context.Password, context.useServerBind());
		}

		internal string ExpandWellKnownDN(WellKnownDN dn)
		{
			string text = null;
			switch (dn)
			{
			case WellKnownDN.RootDSE:
				return "RootDSE";
			case WellKnownDN.RootDomainNamingContext:
			{
				DirectoryEntry cachedDirectoryEntry4 = GetCachedDirectoryEntry("RootDSE");
				return (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry4, PropertyManager.RootDomainNamingContext);
			}
			case WellKnownDN.DefaultNamingContext:
			{
				DirectoryEntry cachedDirectoryEntry3 = GetCachedDirectoryEntry("RootDSE");
				return (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry3, PropertyManager.DefaultNamingContext);
			}
			case WellKnownDN.SchemaNamingContext:
			{
				DirectoryEntry cachedDirectoryEntry2 = GetCachedDirectoryEntry("RootDSE");
				return (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry2, PropertyManager.SchemaNamingContext);
			}
			case WellKnownDN.ConfigurationNamingContext:
			{
				DirectoryEntry cachedDirectoryEntry = GetCachedDirectoryEntry("RootDSE");
				return (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.ConfigurationNamingContext);
			}
			case WellKnownDN.PartitionsContainer:
				return "CN=Partitions," + ExpandWellKnownDN(WellKnownDN.ConfigurationNamingContext);
			case WellKnownDN.SitesContainer:
				return "CN=Sites," + ExpandWellKnownDN(WellKnownDN.ConfigurationNamingContext);
			case WellKnownDN.SystemContainer:
				return "CN=System," + ExpandWellKnownDN(WellKnownDN.DefaultNamingContext);
			case WellKnownDN.RidManager:
				return "CN=RID Manager$," + ExpandWellKnownDN(WellKnownDN.SystemContainer);
			case WellKnownDN.Infrastructure:
				return "CN=Infrastructure," + ExpandWellKnownDN(WellKnownDN.DefaultNamingContext);
			default:
				throw new InvalidEnumArgumentException("dn", (int)dn, typeof(WellKnownDN));
			}
		}

		internal static DirectoryEntry GetDirectoryEntry(DirectoryContext context, WellKnownDN dn)
		{
			return GetDirectoryEntry(context, ExpandWellKnownDN(context, dn));
		}

		internal static DirectoryEntry GetDirectoryEntry(DirectoryContext context, string dn)
		{
			string text = "LDAP://" + context.GetServerName() + "/";
			NativeComInterfaces.IAdsPathname adsPathname = (NativeComInterfaces.IAdsPathname)new NativeComInterfaces.Pathname();
			adsPathname.EscapedMode = 2;
			adsPathname.Set(dn, 4);
			string text2 = adsPathname.Retrieve(7);
			return Bind(text + text2, context.UserName, context.Password, context.useServerBind());
		}

		internal static DirectoryEntry GetDirectoryEntryInternal(DirectoryContext context, string path)
		{
			return Bind(path, context.UserName, context.Password, context.useServerBind());
		}

		internal static DirectoryEntry Bind(string ldapPath, string username, string password, bool useServerBind)
		{
			DirectoryEntry directoryEntry = null;
			AuthenticationTypes authenticationTypes = Utils.DefaultAuthType;
			if (DirectoryContext.ServerBindSupported && useServerBind)
			{
				authenticationTypes |= AuthenticationTypes.ServerBind;
			}
			return new DirectoryEntry(ldapPath, username, password, authenticationTypes);
		}

		internal static string ExpandWellKnownDN(DirectoryContext context, WellKnownDN dn)
		{
			string text = null;
			switch (dn)
			{
			case WellKnownDN.RootDSE:
				return "RootDSE";
			case WellKnownDN.RootDomainNamingContext:
			{
				DirectoryEntry directoryEntry4 = GetDirectoryEntry(context, "RootDSE");
				try
				{
					return (string)PropertyManager.GetPropertyValue(context, directoryEntry4, PropertyManager.RootDomainNamingContext);
				}
				finally
				{
					directoryEntry4.Dispose();
				}
			}
			case WellKnownDN.DefaultNamingContext:
			{
				DirectoryEntry directoryEntry3 = GetDirectoryEntry(context, "RootDSE");
				try
				{
					return (string)PropertyManager.GetPropertyValue(context, directoryEntry3, PropertyManager.DefaultNamingContext);
				}
				finally
				{
					directoryEntry3.Dispose();
				}
			}
			case WellKnownDN.SchemaNamingContext:
			{
				DirectoryEntry directoryEntry2 = GetDirectoryEntry(context, "RootDSE");
				try
				{
					return (string)PropertyManager.GetPropertyValue(context, directoryEntry2, PropertyManager.SchemaNamingContext);
				}
				finally
				{
					directoryEntry2.Dispose();
				}
			}
			case WellKnownDN.ConfigurationNamingContext:
			{
				DirectoryEntry directoryEntry = GetDirectoryEntry(context, "RootDSE");
				try
				{
					return (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				}
				finally
				{
					directoryEntry.Dispose();
				}
			}
			case WellKnownDN.PartitionsContainer:
				return "CN=Partitions," + ExpandWellKnownDN(context, WellKnownDN.ConfigurationNamingContext);
			case WellKnownDN.SitesContainer:
				return "CN=Sites," + ExpandWellKnownDN(context, WellKnownDN.ConfigurationNamingContext);
			case WellKnownDN.SystemContainer:
				return "CN=System," + ExpandWellKnownDN(context, WellKnownDN.DefaultNamingContext);
			case WellKnownDN.RidManager:
				return "CN=RID Manager$," + ExpandWellKnownDN(context, WellKnownDN.SystemContainer);
			case WellKnownDN.Infrastructure:
				return "CN=Infrastructure," + ExpandWellKnownDN(context, WellKnownDN.DefaultNamingContext);
			default:
				throw new InvalidEnumArgumentException("dn", (int)dn, typeof(WellKnownDN));
			}
		}
	}
	public class DirectoryServerCollection : CollectionBase
	{
		internal string siteDN;

		internal string transportDN;

		internal DirectoryContext context;

		internal bool initialized;

		internal Hashtable changeList;

		private ArrayList copyList = new ArrayList();

		private DirectoryEntry crossRefEntry;

		private bool isADAM;

		private bool isForNC;

		public DirectoryServer this[int index]
		{
			get
			{
				return (DirectoryServer)base.InnerList[index];
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (!Contains(value))
				{
					base.List[index] = value;
					return;
				}
				throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", value), "value");
			}
		}

		internal DirectoryServerCollection(DirectoryContext context, string siteDN, string transportName)
		{
			Hashtable table = new Hashtable();
			changeList = Hashtable.Synchronized(table);
			this.context = context;
			this.siteDN = siteDN;
			transportDN = transportName;
		}

		internal DirectoryServerCollection(DirectoryContext context, DirectoryEntry crossRefEntry, bool isADAM, ReadOnlyDirectoryServerCollection servers)
		{
			this.context = context;
			this.crossRefEntry = crossRefEntry;
			this.isADAM = isADAM;
			isForNC = true;
			foreach (DirectoryServer server in servers)
			{
				base.InnerList.Add(server);
			}
		}

		public int Add(DirectoryServer server)
		{
			if (server == null)
			{
				throw new ArgumentNullException("server");
			}
			if (isForNC)
			{
				if (!isADAM)
				{
					if (!(server is DomainController))
					{
						throw new ArgumentException(Res.GetString("ServerShouldBeDC"), "server");
					}
					if (((DomainController)server).NumericOSVersion < 5.2)
					{
						throw new ArgumentException(Res.GetString("ServerShouldBeW2K3"), "server");
					}
				}
				if (!Contains(server))
				{
					return base.List.Add(server);
				}
				throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", server), "server");
			}
			string s = ((server is DomainController) ? ((DomainController)server).SiteObjectName : ((AdamInstance)server).SiteObjectName);
			if (Utils.Compare(siteDN, s) != 0)
			{
				throw new ArgumentException(Res.GetString("NotWithinSite"));
			}
			if (!Contains(server))
			{
				return base.List.Add(server);
			}
			throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", server), "server");
		}

		public void AddRange(DirectoryServer[] servers)
		{
			if (servers == null)
			{
				throw new ArgumentNullException("servers");
			}
			foreach (DirectoryServer directoryServer in servers)
			{
				if (directoryServer == null)
				{
					throw new ArgumentException("servers");
				}
			}
			for (int j = 0; j < servers.Length; j++)
			{
				Add(servers[j]);
			}
		}

		public bool Contains(DirectoryServer server)
		{
			if (server == null)
			{
				throw new ArgumentNullException("server");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DirectoryServer directoryServer = (DirectoryServer)base.InnerList[i];
				if (Utils.Compare(directoryServer.Name, server.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public void CopyTo(DirectoryServer[] array, int index)
		{
			base.List.CopyTo(array, index);
		}

		public int IndexOf(DirectoryServer server)
		{
			if (server == null)
			{
				throw new ArgumentNullException("server");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DirectoryServer directoryServer = (DirectoryServer)base.InnerList[i];
				if (Utils.Compare(directoryServer.Name, server.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void Insert(int index, DirectoryServer server)
		{
			if (server == null)
			{
				throw new ArgumentNullException("server");
			}
			if (isForNC)
			{
				if (!isADAM)
				{
					if (!(server is DomainController))
					{
						throw new ArgumentException(Res.GetString("ServerShouldBeDC"), "server");
					}
					if (((DomainController)server).NumericOSVersion < 5.2)
					{
						throw new ArgumentException(Res.GetString("ServerShouldBeW2K3"), "server");
					}
				}
				if (Contains(server))
				{
					throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", server), "server");
				}
				base.List.Insert(index, server);
			}
			else
			{
				string s = ((server is DomainController) ? ((DomainController)server).SiteObjectName : ((AdamInstance)server).SiteObjectName);
				if (Utils.Compare(siteDN, s) != 0)
				{
					throw new ArgumentException(Res.GetString("NotWithinSite"), "server");
				}
				if (Contains(server))
				{
					throw new ArgumentException(Res.GetString("AlreadyExistingInCollection", server));
				}
				base.List.Insert(index, server);
			}
		}

		public void Remove(DirectoryServer server)
		{
			if (server == null)
			{
				throw new ArgumentNullException("server");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DirectoryServer directoryServer = (DirectoryServer)base.InnerList[i];
				if (Utils.Compare(directoryServer.Name, server.Name) == 0)
				{
					base.List.Remove(directoryServer);
					return;
				}
			}
			throw new ArgumentException(Res.GetString("NotFoundInCollection", server), "server");
		}

		protected override void OnClear()
		{
			if (!initialized || isForNC)
			{
				return;
			}
			copyList.Clear();
			foreach (object item in base.List)
			{
				copyList.Add(item);
			}
		}

		protected override void OnClearComplete()
		{
			if (isForNC)
			{
				if (crossRefEntry == null)
				{
					return;
				}
				try
				{
					if (crossRefEntry.Properties.Contains(PropertyManager.MsDSNCReplicaLocations))
					{
						crossRefEntry.Properties[PropertyManager.MsDSNCReplicaLocations].Clear();
					}
					return;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
			if (initialized)
			{
				for (int i = 0; i < copyList.Count; i++)
				{
					OnRemoveComplete(i, copyList[i]);
				}
			}
		}

		protected override void OnInsertComplete(int index, object value)
		{
			if (isForNC)
			{
				if (crossRefEntry != null)
				{
					try
					{
						DirectoryServer directoryServer = (DirectoryServer)value;
						string value2 = ((directoryServer is DomainController) ? ((DomainController)directoryServer).NtdsaObjectName : ((AdamInstance)directoryServer).NtdsaObjectName);
						crossRefEntry.Properties[PropertyManager.MsDSNCReplicaLocations].Add(value2);
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
			}
			else
			{
				if (!initialized)
				{
					return;
				}
				DirectoryServer directoryServer2 = (DirectoryServer)value;
				string name = directoryServer2.Name;
				string dn = ((directoryServer2 is DomainController) ? ((DomainController)directoryServer2).ServerObjectName : ((AdamInstance)directoryServer2).ServerObjectName);
				try
				{
					if (changeList.Contains(name))
					{
						((DirectoryEntry)changeList[name]).Properties["bridgeheadTransportList"].Value = transportDN;
						return;
					}
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
					directoryEntry.Properties["bridgeheadTransportList"].Value = transportDN;
					changeList.Add(name, directoryEntry);
				}
				catch (COMException e2)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
				}
			}
		}

		protected override void OnRemoveComplete(int index, object value)
		{
			if (isForNC)
			{
				try
				{
					if (crossRefEntry != null)
					{
						string value2 = ((value is DomainController) ? ((DomainController)value).NtdsaObjectName : ((AdamInstance)value).NtdsaObjectName);
						crossRefEntry.Properties[PropertyManager.MsDSNCReplicaLocations].Remove(value2);
					}
					return;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
			DirectoryServer directoryServer = (DirectoryServer)value;
			string name = directoryServer.Name;
			string dn = ((directoryServer is DomainController) ? ((DomainController)directoryServer).ServerObjectName : ((AdamInstance)directoryServer).ServerObjectName);
			try
			{
				if (changeList.Contains(name))
				{
					((DirectoryEntry)changeList[name]).Properties["bridgeheadTransportList"].Clear();
					return;
				}
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
				directoryEntry.Properties["bridgeheadTransportList"].Clear();
				changeList.Add(name, directoryEntry);
			}
			catch (COMException e2)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e2);
			}
		}

		protected override void OnSetComplete(int index, object oldValue, object newValue)
		{
			OnRemoveComplete(index, oldValue);
			OnInsertComplete(index, newValue);
		}

		protected override void OnValidate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if (isForNC)
			{
				if (isADAM)
				{
					if (!(value is AdamInstance))
					{
						throw new ArgumentException(Res.GetString("ServerShouldBeAI"), "value");
					}
				}
				else if (!(value is DomainController))
				{
					throw new ArgumentException(Res.GetString("ServerShouldBeDC"), "value");
				}
			}
			else if (!(value is DirectoryServer))
			{
				throw new ArgumentException("value");
			}
		}

		internal string[] GetMultiValuedProperty()
		{
			ArrayList arrayList = new ArrayList();
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DirectoryServer directoryServer = (DirectoryServer)base.InnerList[i];
				string value = ((directoryServer is DomainController) ? ((DomainController)directoryServer).NtdsaObjectName : ((AdamInstance)directoryServer).NtdsaObjectName);
				arrayList.Add(value);
			}
			return (string[])arrayList.ToArray(typeof(string));
		}
	}
	public enum DomainMode
	{
		Windows2000MixedDomain,
		Windows2000NativeDomain,
		Windows2003InterimDomain,
		Windows2003Domain,
		Windows2008Domain,
		Windows2008R2Domain
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class Domain : ActiveDirectoryPartition
	{
		private string crossRefDN;

		private string trustParent;

		private DomainControllerCollection cachedDomainControllers;

		private DomainCollection cachedChildren;

		private DomainMode currentDomainMode = (DomainMode)(-1);

		private DomainController cachedPdcRoleOwner;

		private DomainController cachedRidRoleOwner;

		private DomainController cachedInfrastructureRoleOwner;

		private Domain cachedParent;

		private Forest cachedForest;

		private bool isParentInitialized;

		public Forest Forest
		{
			get
			{
				CheckIfDisposed();
				if (cachedForest == null)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
					string distinguishedName = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.RootDomainNamingContext);
					string dnsNameFromDN = Utils.GetDnsNameFromDN(distinguishedName);
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(dnsNameFromDN, DirectoryContextType.Forest, context);
					cachedForest = new Forest(newDirectoryContext, dnsNameFromDN);
				}
				return cachedForest;
			}
		}

		public DomainControllerCollection DomainControllers
		{
			get
			{
				CheckIfDisposed();
				if (cachedDomainControllers == null)
				{
					cachedDomainControllers = FindAllDomainControllers();
				}
				return cachedDomainControllers;
			}
		}

		public DomainCollection Children
		{
			get
			{
				CheckIfDisposed();
				if (cachedChildren == null)
				{
					cachedChildren = new DomainCollection(GetChildDomains());
				}
				return cachedChildren;
			}
		}

		public DomainMode DomainMode
		{
			get
			{
				CheckIfDisposed();
				if (currentDomainMode == (DomainMode)(-1))
				{
					currentDomainMode = GetDomainMode();
				}
				return currentDomainMode;
			}
		}

		public Domain Parent
		{
			get
			{
				CheckIfDisposed();
				if (!isParentInitialized)
				{
					cachedParent = GetParent();
					isParentInitialized = true;
				}
				return cachedParent;
			}
		}

		public DomainController PdcRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedPdcRoleOwner == null)
				{
					cachedPdcRoleOwner = GetRoleOwner(ActiveDirectoryRole.PdcRole);
				}
				return cachedPdcRoleOwner;
			}
		}

		public DomainController RidRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedRidRoleOwner == null)
				{
					cachedRidRoleOwner = GetRoleOwner(ActiveDirectoryRole.RidRole);
				}
				return cachedRidRoleOwner;
			}
		}

		public DomainController InfrastructureRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedInfrastructureRoleOwner == null)
				{
					cachedInfrastructureRoleOwner = GetRoleOwner(ActiveDirectoryRole.InfrastructureRole);
				}
				return cachedInfrastructureRoleOwner;
			}
		}

		internal Domain(DirectoryContext context, string domainName, DirectoryEntryManager directoryEntryMgr)
			: base(context, domainName)
		{
			base.directoryEntryMgr = directoryEntryMgr;
		}

		internal Domain(DirectoryContext context, string domainName)
			: this(context, domainName, new DirectoryEntryManager(context))
		{
		}

		public static Domain GetDomain(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != 0 && context.ContextType != DirectoryContextType.DirectoryServer)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeServerORDomain"), "context");
			}
			if (context.Name == null && !context.isDomain())
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ContextNotAssociatedWithDomain"), typeof(Domain), null);
			}
			if (context.Name != null && !context.isDomain() && !context.isServer())
			{
				if (context.ContextType == DirectoryContextType.Domain)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainNotFound"), typeof(Domain), context.Name);
				}
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(Domain), null);
			}
			context = new DirectoryContext(context);
			DirectoryEntryManager directoryEntryManager = new DirectoryEntryManager(context);
			DirectoryEntry directoryEntry = null;
			string text = null;
			try
			{
				directoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (context.isServer() && !Utils.CheckCapability(directoryEntry, Capability.ActiveDirectory))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(Domain), null);
				}
				text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.DefaultNamingContext);
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					if (context.ContextType == DirectoryContextType.Domain)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainNotFound"), typeof(Domain), context.Name);
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(Domain), null);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			return new Domain(context, Utils.GetDnsNameFromDN(text), directoryEntryManager);
		}

		public static Domain GetComputerDomain()
		{
			string dnsDomainName = DirectoryContext.GetDnsDomainName(null);
			if (dnsDomainName == null)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ComputerNotJoinedToDomain"), typeof(Domain), null);
			}
			return GetDomain(new DirectoryContext(DirectoryContextType.Domain, dnsDomainName));
		}

		public void RaiseDomainFunctionality(DomainMode domainMode)
		{
			CheckIfDisposed();
			if (domainMode < DomainMode.Windows2000MixedDomain || domainMode > DomainMode.Windows2008R2Domain)
			{
				throw new InvalidEnumArgumentException("domainMode", (int)domainMode, typeof(DomainMode));
			}
			DomainMode domainMode2 = GetDomainMode();
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.DefaultNamingContext));
				switch (domainMode2)
				{
				case DomainMode.Windows2000MixedDomain:
					switch (domainMode)
					{
					case DomainMode.Windows2000NativeDomain:
						directoryEntry.Properties[PropertyManager.NTMixedDomain].Value = 0;
						break;
					case DomainMode.Windows2003InterimDomain:
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 1;
						break;
					case DomainMode.Windows2003Domain:
						directoryEntry.Properties[PropertyManager.NTMixedDomain].Value = 0;
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 2;
						break;
					default:
						throw new ArgumentException(Res.GetString("InvalidMode"), "domainMode");
					}
					break;
				case DomainMode.Windows2000NativeDomain:
					switch (domainMode)
					{
					case DomainMode.Windows2003Domain:
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 2;
						break;
					case DomainMode.Windows2008Domain:
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 3;
						break;
					case DomainMode.Windows2008R2Domain:
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 4;
						break;
					default:
						throw new ArgumentException(Res.GetString("InvalidMode"), "domainMode");
					}
					break;
				case DomainMode.Windows2003InterimDomain:
					if (domainMode == DomainMode.Windows2003Domain)
					{
						directoryEntry.Properties[PropertyManager.NTMixedDomain].Value = 0;
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 2;
						break;
					}
					throw new ArgumentException(Res.GetString("InvalidMode"), "domainMode");
				case DomainMode.Windows2003Domain:
					switch (domainMode)
					{
					case DomainMode.Windows2008Domain:
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 3;
						break;
					case DomainMode.Windows2008R2Domain:
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 4;
						break;
					default:
						throw new ArgumentException(Res.GetString("InvalidMode"), "domainMode");
					}
					break;
				case DomainMode.Windows2008Domain:
					if (domainMode == DomainMode.Windows2008R2Domain)
					{
						directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = 4;
						break;
					}
					throw new ArgumentException(Res.GetString("InvalidMode"), "domainMode");
				case DomainMode.Windows2008R2Domain:
					throw new ArgumentException(Res.GetString("InvalidMode"), "domainMode");
				default:
					throw new ActiveDirectoryOperationException();
				}
				directoryEntry.CommitChanges();
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147016694)
				{
					throw new ArgumentException(Res.GetString("NoW2K3DCs"), "domainMode");
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			currentDomainMode = (DomainMode)(-1);
		}

		public DomainController FindDomainController()
		{
			CheckIfDisposed();
			return DomainController.FindOneInternal(context, base.Name, null, (LocatorOptions)0L);
		}

		public DomainController FindDomainController(string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return DomainController.FindOneInternal(context, base.Name, siteName, (LocatorOptions)0L);
		}

		public DomainController FindDomainController(LocatorOptions flag)
		{
			CheckIfDisposed();
			return DomainController.FindOneInternal(context, base.Name, null, flag);
		}

		public DomainController FindDomainController(string siteName, LocatorOptions flag)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return DomainController.FindOneInternal(context, base.Name, siteName, flag);
		}

		public DomainControllerCollection FindAllDomainControllers()
		{
			CheckIfDisposed();
			return DomainController.FindAllInternal(context, base.Name, isDnsDomainName: true, null);
		}

		public DomainControllerCollection FindAllDomainControllers(string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return DomainController.FindAllInternal(context, base.Name, isDnsDomainName: true, siteName);
		}

		public DomainControllerCollection FindAllDiscoverableDomainControllers()
		{
			long dcFlags = 4096L;
			CheckIfDisposed();
			return new DomainControllerCollection(Locator.EnumerateDomainControllers(context, base.Name, null, dcFlags));
		}

		public DomainControllerCollection FindAllDiscoverableDomainControllers(string siteName)
		{
			long dcFlags = 4096L;
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			return new DomainControllerCollection(Locator.EnumerateDomainControllers(context, base.Name, siteName, dcFlags));
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override DirectoryEntry GetDirectoryEntry()
		{
			CheckIfDisposed();
			return DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.DefaultNamingContext));
		}

		public TrustRelationshipInformationCollection GetAllTrustRelationships()
		{
			CheckIfDisposed();
			ArrayList trustsHelper = GetTrustsHelper(null);
			return new TrustRelationshipInformationCollection(context, base.Name, trustsHelper);
		}

		public TrustRelationshipInformation GetTrustRelationship(string targetDomainName)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			ArrayList trustsHelper = GetTrustsHelper(targetDomainName);
			TrustRelationshipInformationCollection trustRelationshipInformationCollection = new TrustRelationshipInformationCollection(context, base.Name, trustsHelper);
			if (trustRelationshipInformationCollection.Count == 0)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainTrustDoesNotExist", base.Name, targetDomainName), typeof(TrustRelationshipInformation), null);
			}
			return trustRelationshipInformationCollection[0];
		}

		public bool GetSelectiveAuthenticationStatus(string targetDomainName)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			return TrustHelper.GetTrustedDomainInfoStatus(context, base.Name, targetDomainName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION, isForest: false);
		}

		public void SetSelectiveAuthenticationStatus(string targetDomainName, bool enable)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			TrustHelper.SetTrustedDomainInfoStatus(context, base.Name, targetDomainName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION, enable, isForest: false);
		}

		public bool GetSidFilteringStatus(string targetDomainName)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			return TrustHelper.GetTrustedDomainInfoStatus(context, base.Name, targetDomainName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN, isForest: false);
		}

		public void SetSidFilteringStatus(string targetDomainName, bool enable)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			TrustHelper.SetTrustedDomainInfoStatus(context, base.Name, targetDomainName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN, enable, isForest: false);
		}

		public void DeleteLocalSideOfTrustRelationship(string targetDomainName)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			TrustHelper.DeleteTrust(context, base.Name, targetDomainName, isForest: false);
		}

		public void DeleteTrustRelationship(Domain targetDomain)
		{
			CheckIfDisposed();
			if (targetDomain == null)
			{
				throw new ArgumentNullException("targetDomain");
			}
			TrustHelper.DeleteTrust(targetDomain.GetDirectoryContext(), targetDomain.Name, base.Name, isForest: false);
			TrustHelper.DeleteTrust(context, base.Name, targetDomain.Name, isForest: false);
		}

		public void VerifyOutboundTrustRelationship(string targetDomainName)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			TrustHelper.VerifyTrust(context, base.Name, targetDomainName, isForest: false, TrustDirection.Outbound, forceSecureChannelReset: false, null);
		}

		public void VerifyTrustRelationship(Domain targetDomain, TrustDirection direction)
		{
			CheckIfDisposed();
			if (targetDomain == null)
			{
				throw new ArgumentNullException("targetDomain");
			}
			if (direction < TrustDirection.Inbound || direction > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("direction", (int)direction, typeof(TrustDirection));
			}
			if ((direction & TrustDirection.Outbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(context, base.Name, targetDomain.Name, isForest: false, TrustDirection.Outbound, forceSecureChannelReset: false, null);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", base.Name, targetDomain.Name, direction), typeof(TrustRelationshipInformation), null);
				}
			}
			if ((direction & TrustDirection.Inbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(targetDomain.GetDirectoryContext(), targetDomain.Name, base.Name, isForest: false, TrustDirection.Outbound, forceSecureChannelReset: false, null);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", base.Name, targetDomain.Name, direction), typeof(TrustRelationshipInformation), null);
				}
			}
		}

		public void CreateLocalSideOfTrustRelationship(string targetDomainName, TrustDirection direction, string trustPassword)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			if (direction < TrustDirection.Inbound || direction > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("direction", (int)direction, typeof(TrustDirection));
			}
			if (trustPassword == null)
			{
				throw new ArgumentNullException("trustPassword");
			}
			if (trustPassword.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "trustPassword");
			}
			Locator.GetDomainControllerInfo(null, targetDomainName, null, 16L);
			DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(targetDomainName, DirectoryContextType.Domain, context);
			TrustHelper.CreateTrust(context, base.Name, newDirectoryContext, targetDomainName, isForest: false, direction, trustPassword);
		}

		public void CreateTrustRelationship(Domain targetDomain, TrustDirection direction)
		{
			CheckIfDisposed();
			if (targetDomain == null)
			{
				throw new ArgumentNullException("targetDomain");
			}
			if (direction < TrustDirection.Inbound || direction > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("direction", (int)direction, typeof(TrustDirection));
			}
			string password = TrustHelper.CreateTrustPassword();
			TrustHelper.CreateTrust(context, base.Name, targetDomain.GetDirectoryContext(), targetDomain.Name, isForest: false, direction, password);
			int num = 0;
			if ((direction & TrustDirection.Inbound) != 0)
			{
				num |= 2;
			}
			if ((direction & TrustDirection.Outbound) != 0)
			{
				num |= 1;
			}
			TrustHelper.CreateTrust(targetDomain.GetDirectoryContext(), targetDomain.Name, context, base.Name, isForest: false, (TrustDirection)num, password);
		}

		public void UpdateLocalSideOfTrustRelationship(string targetDomainName, string newTrustPassword)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			if (newTrustPassword == null)
			{
				throw new ArgumentNullException("newTrustPassword");
			}
			if (newTrustPassword.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "newTrustPassword");
			}
			TrustHelper.UpdateTrust(context, base.Name, targetDomainName, newTrustPassword, isForest: false);
		}

		public void UpdateLocalSideOfTrustRelationship(string targetDomainName, TrustDirection newTrustDirection, string newTrustPassword)
		{
			CheckIfDisposed();
			if (targetDomainName == null)
			{
				throw new ArgumentNullException("targetDomainName");
			}
			if (targetDomainName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetDomainName");
			}
			if (newTrustDirection < TrustDirection.Inbound || newTrustDirection > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("newTrustDirection", (int)newTrustDirection, typeof(TrustDirection));
			}
			if (newTrustPassword == null)
			{
				throw new ArgumentNullException("newTrustPassword");
			}
			if (newTrustPassword.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "newTrustPassword");
			}
			TrustHelper.UpdateTrustDirection(context, base.Name, targetDomainName, newTrustPassword, isForest: false, newTrustDirection);
		}

		public void UpdateTrustRelationship(Domain targetDomain, TrustDirection newTrustDirection)
		{
			CheckIfDisposed();
			if (targetDomain == null)
			{
				throw new ArgumentNullException("targetDomain");
			}
			if (newTrustDirection < TrustDirection.Inbound || newTrustDirection > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("newTrustDirection", (int)newTrustDirection, typeof(TrustDirection));
			}
			string password = TrustHelper.CreateTrustPassword();
			TrustHelper.UpdateTrustDirection(context, base.Name, targetDomain.Name, password, isForest: false, newTrustDirection);
			TrustDirection trustDirection = (TrustDirection)0;
			if ((newTrustDirection & TrustDirection.Inbound) != 0)
			{
				trustDirection |= TrustDirection.Outbound;
			}
			if ((newTrustDirection & TrustDirection.Outbound) != 0)
			{
				trustDirection |= TrustDirection.Inbound;
			}
			TrustHelper.UpdateTrustDirection(targetDomain.GetDirectoryContext(), targetDomain.Name, base.Name, password, isForest: false, trustDirection);
		}

		public void RepairTrustRelationship(Domain targetDomain)
		{
			TrustDirection trustDirection = TrustDirection.Bidirectional;
			CheckIfDisposed();
			if (targetDomain == null)
			{
				throw new ArgumentNullException("targetDomain");
			}
			try
			{
				trustDirection = GetTrustRelationship(targetDomain.Name).TrustDirection;
				if ((trustDirection & TrustDirection.Outbound) != 0)
				{
					TrustHelper.VerifyTrust(context, base.Name, targetDomain.Name, isForest: false, TrustDirection.Outbound, forceSecureChannelReset: true, null);
				}
				if ((trustDirection & TrustDirection.Inbound) != 0)
				{
					TrustHelper.VerifyTrust(targetDomain.GetDirectoryContext(), targetDomain.Name, base.Name, isForest: false, TrustDirection.Outbound, forceSecureChannelReset: true, null);
				}
			}
			catch (ActiveDirectoryOperationException)
			{
				RepairTrustHelper(targetDomain, trustDirection);
			}
			catch (UnauthorizedAccessException)
			{
				RepairTrustHelper(targetDomain, trustDirection);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", base.Name, targetDomain.Name, trustDirection), typeof(TrustRelationshipInformation), null);
			}
		}

		public static Domain GetCurrentDomain()
		{
			return GetDomain(new DirectoryContext(DirectoryContextType.Domain));
		}

		internal DirectoryContext GetDirectoryContext()
		{
			return context;
		}

		private DomainMode GetDomainMode()
		{
			DirectoryEntry directoryEntry = null;
			DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			int num = 0;
			try
			{
				if (directoryEntry2.Properties.Contains(PropertyManager.DomainFunctionality))
				{
					num = int.Parse((string)PropertyManager.GetPropertyValue(context, directoryEntry2, PropertyManager.DomainFunctionality), NumberFormatInfo.InvariantInfo);
				}
				switch (num)
				{
				case 0:
					directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.DefaultNamingContext));
					if ((int)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.NTMixedDomain) == 0)
					{
						return DomainMode.Windows2000NativeDomain;
					}
					return DomainMode.Windows2000MixedDomain;
				case 1:
					return DomainMode.Windows2003InterimDomain;
				case 2:
					return DomainMode.Windows2003Domain;
				case 3:
					return DomainMode.Windows2008Domain;
				case 4:
					return DomainMode.Windows2008R2Domain;
				default:
					throw new ActiveDirectoryOperationException(Res.GetString("InvalidMode"));
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry2.Dispose();
				directoryEntry?.Dispose();
			}
		}

		private DomainController GetRoleOwner(ActiveDirectoryRole role)
		{
			DirectoryEntry directoryEntry = null;
			string text = null;
			try
			{
				switch (role)
				{
				case ActiveDirectoryRole.PdcRole:
					directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.DefaultNamingContext));
					break;
				case ActiveDirectoryRole.RidRole:
					directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.RidManager));
					break;
				case ActiveDirectoryRole.InfrastructureRole:
					directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.Infrastructure));
					break;
				}
				text = Utils.GetDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner));
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context);
			return new DomainController(newDirectoryContext, text);
		}

		private void LoadCrossRefAttributes()
		{
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
				StringBuilder stringBuilder = new StringBuilder(15);
				stringBuilder.Append("(&(");
				stringBuilder.Append(PropertyManager.ObjectCategory);
				stringBuilder.Append("=crossRef)(");
				stringBuilder.Append(PropertyManager.SystemFlags);
				stringBuilder.Append(":1.2.840.113556.1.4.804:=");
				stringBuilder.Append(1);
				stringBuilder.Append(")(");
				stringBuilder.Append(PropertyManager.SystemFlags);
				stringBuilder.Append(":1.2.840.113556.1.4.804:=");
				stringBuilder.Append(2);
				stringBuilder.Append(")(");
				stringBuilder.Append(PropertyManager.DnsRoot);
				stringBuilder.Append("=");
				stringBuilder.Append(Utils.GetEscapedFilterValue(partitionName));
				stringBuilder.Append("))");
				string filter = stringBuilder.ToString();
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, filter, new string[2]
				{
					PropertyManager.DistinguishedName,
					PropertyManager.TrustParent
				}, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
				SearchResult searchResult = aDSearcher.FindOne();
				crossRefDN = (string)PropertyManager.GetSearchResultPropertyValue(searchResult, PropertyManager.DistinguishedName);
				if (searchResult.Properties[PropertyManager.TrustParent].Count > 0)
				{
					trustParent = (string)searchResult.Properties[PropertyManager.TrustParent][0];
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
		}

		private Domain GetParent()
		{
			if (crossRefDN == null)
			{
				LoadCrossRefAttributes();
			}
			if (trustParent != null)
			{
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, trustParent);
				string text = null;
				DirectoryContext directoryContext = null;
				try
				{
					text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.DnsRoot);
					directoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.Domain, context);
				}
				finally
				{
					directoryEntry.Dispose();
				}
				return new Domain(directoryContext, text);
			}
			return null;
		}

		private ArrayList GetChildDomains()
		{
			ArrayList arrayList = new ArrayList();
			if (crossRefDN == null)
			{
				LoadCrossRefAttributes();
			}
			DirectoryEntry directoryEntry = null;
			SearchResultCollection searchResultCollection = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
				StringBuilder stringBuilder = new StringBuilder(15);
				stringBuilder.Append("(&(");
				stringBuilder.Append(PropertyManager.ObjectCategory);
				stringBuilder.Append("=crossRef)(");
				stringBuilder.Append(PropertyManager.SystemFlags);
				stringBuilder.Append(":1.2.840.113556.1.4.804:=");
				stringBuilder.Append(1);
				stringBuilder.Append(")(");
				stringBuilder.Append(PropertyManager.SystemFlags);
				stringBuilder.Append(":1.2.840.113556.1.4.804:=");
				stringBuilder.Append(2);
				stringBuilder.Append(")(");
				stringBuilder.Append(PropertyManager.TrustParent);
				stringBuilder.Append("=");
				stringBuilder.Append(Utils.GetEscapedFilterValue(crossRefDN));
				stringBuilder.Append("))");
				string filter = stringBuilder.ToString();
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, filter, new string[1] { PropertyManager.DnsRoot }, SearchScope.OneLevel);
				searchResultCollection = aDSearcher.FindAll();
				foreach (SearchResult item in searchResultCollection)
				{
					string text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsRoot);
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.Domain, context);
					arrayList.Add(new Domain(newDirectoryContext, text));
				}
				return arrayList;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
				directoryEntry?.Dispose();
			}
		}

		private ArrayList GetTrustsHelper(string targetDomainName)
		{
			string text = null;
			IntPtr domains = (IntPtr)0;
			int count = 0;
			ArrayList arrayList = new ArrayList();
			ArrayList arrayList2 = new ArrayList();
			new TrustRelationshipInformationCollection();
			int num = 0;
			string text2 = null;
			int num2 = 0;
			bool flag = false;
			text = ((!context.isServer()) ? DomainController.FindOne(context).Name : context.Name);
			flag = Utils.Impersonate(context);
			try
			{
				try
				{
					num2 = UnsafeNativeMethods.DsEnumerateDomainTrustsW(text, 35, out domains, out count);
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
				}
			}
			catch
			{
				throw;
			}
			if (num2 != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num2, text);
			}
			try
			{
				if (domains != (IntPtr)0 && count != 0)
				{
					IntPtr intPtr = (IntPtr)0;
					int num3 = 0;
					for (int i = 0; i < count; i++)
					{
						intPtr = Utils.AddToIntPtr(domains, i * Marshal.SizeOf(typeof(DS_DOMAIN_TRUSTS)));
						DS_DOMAIN_TRUSTS dS_DOMAIN_TRUSTS = new DS_DOMAIN_TRUSTS();
						Marshal.PtrToStructure(intPtr, dS_DOMAIN_TRUSTS);
						arrayList.Add(dS_DOMAIN_TRUSTS);
					}
					for (int j = 0; j < arrayList.Count; j++)
					{
						DS_DOMAIN_TRUSTS dS_DOMAIN_TRUSTS2 = (DS_DOMAIN_TRUSTS)arrayList[j];
						if ((dS_DOMAIN_TRUSTS2.Flags & 0x2A) == 0 || dS_DOMAIN_TRUSTS2.TrustType == TrustHelper.TRUST_TYPE_DOWNLEVEL)
						{
							continue;
						}
						TrustObject trustObject = new TrustObject();
						trustObject.TrustType = TrustType.Unknown;
						if (dS_DOMAIN_TRUSTS2.DnsDomainName != (IntPtr)0)
						{
							trustObject.DnsDomainName = Marshal.PtrToStringUni(dS_DOMAIN_TRUSTS2.DnsDomainName);
						}
						if (dS_DOMAIN_TRUSTS2.NetbiosDomainName != (IntPtr)0)
						{
							trustObject.NetbiosDomainName = Marshal.PtrToStringUni(dS_DOMAIN_TRUSTS2.NetbiosDomainName);
						}
						trustObject.Flags = dS_DOMAIN_TRUSTS2.Flags;
						trustObject.TrustAttributes = dS_DOMAIN_TRUSTS2.TrustAttributes;
						trustObject.OriginalIndex = j;
						trustObject.ParentIndex = dS_DOMAIN_TRUSTS2.ParentIndex;
						if (targetDomainName != null)
						{
							bool flag2 = false;
							if (trustObject.DnsDomainName != null && Utils.Compare(targetDomainName, trustObject.DnsDomainName) == 0)
							{
								flag2 = true;
							}
							else if (trustObject.NetbiosDomainName != null && Utils.Compare(targetDomainName, trustObject.NetbiosDomainName) == 0)
							{
								flag2 = true;
							}
							if (!flag2 && (trustObject.Flags & 8) == 0)
							{
								continue;
							}
						}
						if (((uint)trustObject.Flags & 8u) != 0)
						{
							num = num3;
							if ((trustObject.Flags & 4) == 0)
							{
								DS_DOMAIN_TRUSTS dS_DOMAIN_TRUSTS3 = (DS_DOMAIN_TRUSTS)arrayList[trustObject.ParentIndex];
								if (dS_DOMAIN_TRUSTS3.DnsDomainName != (IntPtr)0)
								{
									text2 = Marshal.PtrToStringUni(dS_DOMAIN_TRUSTS3.DnsDomainName);
								}
							}
							trustObject.TrustType = (TrustType)7;
						}
						else if (dS_DOMAIN_TRUSTS2.TrustType == 3)
						{
							trustObject.TrustType = TrustType.Kerberos;
						}
						num3++;
						arrayList2.Add(trustObject);
					}
					for (int k = 0; k < arrayList2.Count; k++)
					{
						TrustObject trustObject2 = (TrustObject)arrayList2[k];
						if (k == num || trustObject2.TrustType == TrustType.Kerberos)
						{
							continue;
						}
						if (text2 != null && Utils.Compare(text2, trustObject2.DnsDomainName) == 0)
						{
							trustObject2.TrustType = TrustType.ParentChild;
						}
						else if (((uint)trustObject2.Flags & (true ? 1u : 0u)) != 0)
						{
							if (trustObject2.ParentIndex == ((TrustObject)arrayList2[num]).OriginalIndex)
							{
								trustObject2.TrustType = TrustType.ParentChild;
							}
							else if (((uint)trustObject2.Flags & 4u) != 0 && ((uint)((TrustObject)arrayList2[num]).Flags & 4u) != 0)
							{
								string text3 = null;
								string distinguishedName = directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.RootDomainNamingContext);
								text3 = Utils.GetDnsNameFromDN(distinguishedName);
								DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(context.Name, DirectoryContextType.Forest, context);
								if (newDirectoryContext.isRootDomain() || Utils.Compare(trustObject2.DnsDomainName, text3) == 0)
								{
									trustObject2.TrustType = TrustType.TreeRoot;
								}
								else
								{
									trustObject2.TrustType = TrustType.CrossLink;
								}
							}
							else
							{
								trustObject2.TrustType = TrustType.CrossLink;
							}
						}
						else if (((uint)trustObject2.TrustAttributes & 8u) != 0)
						{
							trustObject2.TrustType = TrustType.Forest;
						}
						else
						{
							trustObject2.TrustType = TrustType.External;
						}
					}
				}
				return arrayList2;
			}
			finally
			{
				if (domains != (IntPtr)0)
				{
					UnsafeNativeMethods.NetApiBufferFree(domains);
				}
			}
		}

		private void RepairTrustHelper(Domain targetDomain, TrustDirection direction)
		{
			string password = TrustHelper.CreateTrustPassword();
			string preferredTargetServer = TrustHelper.UpdateTrust(targetDomain.GetDirectoryContext(), targetDomain.Name, base.Name, password, isForest: false);
			string preferredTargetServer2 = TrustHelper.UpdateTrust(context, base.Name, targetDomain.Name, password, isForest: false);
			if ((direction & TrustDirection.Outbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(context, base.Name, targetDomain.Name, isForest: false, TrustDirection.Outbound, forceSecureChannelReset: true, preferredTargetServer);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", base.Name, targetDomain.Name, direction), typeof(TrustRelationshipInformation), null);
				}
			}
			if ((direction & TrustDirection.Inbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(targetDomain.GetDirectoryContext(), targetDomain.Name, base.Name, isForest: false, TrustDirection.Outbound, forceSecureChannelReset: true, preferredTargetServer2);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", base.Name, targetDomain.Name, direction), typeof(TrustRelationshipInformation), null);
				}
			}
		}
	}
	public class DomainCollection : ReadOnlyCollectionBase
	{
		public Domain this[int index] => (Domain)base.InnerList[index];

		internal DomainCollection()
		{
		}

		internal DomainCollection(ArrayList values)
		{
			if (values != null)
			{
				for (int i = 0; i < values.Count; i++)
				{
					Add((Domain)values[i]);
				}
			}
		}

		public bool Contains(Domain domain)
		{
			if (domain == null)
			{
				throw new ArgumentNullException("domain");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				Domain domain2 = (Domain)base.InnerList[i];
				if (Utils.Compare(domain2.Name, domain.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(Domain domain)
		{
			if (domain == null)
			{
				throw new ArgumentNullException("domain");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				Domain domain2 = (Domain)base.InnerList[i];
				if (Utils.Compare(domain2.Name, domain.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(Domain[] domains, int index)
		{
			base.InnerList.CopyTo(domains, index);
		}

		internal int Add(Domain domain)
		{
			return base.InnerList.Add(domain);
		}

		internal void Clear()
		{
			base.InnerList.Clear();
		}
	}
	[Flags]
	public enum SyncFromAllServersOptions
	{
		None = 0,
		AbortIfServerUnavailable = 1,
		SyncAdjacentServerOnly = 2,
		CheckServerAlivenessOnly = 8,
		SkipInitialCheck = 0x10,
		PushChangeOutward = 0x20,
		CrossSite = 0x40
	}
	public enum SyncFromAllServersEvent
	{
		Error,
		SyncStarted,
		SyncCompleted,
		Finished
	}
	public enum SyncFromAllServersErrorCategory
	{
		ErrorContactingServer,
		ErrorReplicating,
		ServerUnreachable
	}
	public delegate bool SyncUpdateCallback(SyncFromAllServersEvent eventType, string targetServer, string sourceServer, SyncFromAllServersOperationException exception);
	internal delegate bool SyncReplicaFromAllServersCallback(IntPtr data, IntPtr update);
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class DomainController : DirectoryServer
	{
		private IntPtr dsHandle = IntPtr.Zero;

		private IntPtr authIdentity = IntPtr.Zero;

		private string[] becomeRoleOwnerAttrs;

		private bool disposed;

		private string cachedComputerObjectName;

		private string cachedOSVersion;

		private double cachedNumericOSVersion;

		private Forest currentForest;

		private Domain cachedDomain;

		private ActiveDirectoryRoleCollection cachedRoles;

		private bool dcInfoInitialized;

		internal SyncUpdateCallback userDelegate;

		internal SyncReplicaFromAllServersCallback syncAllFunctionPointer;

		public Forest Forest
		{
			get
			{
				CheckIfDisposed();
				if (currentForest == null)
				{
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(base.Name, DirectoryContextType.DirectoryServer, context);
					currentForest = Forest.GetForest(newDirectoryContext);
				}
				return currentForest;
			}
		}

		public DateTime CurrentTime
		{
			get
			{
				CheckIfDisposed();
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string dateTime = null;
				try
				{
					dateTime = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.CurrentTime);
				}
				finally
				{
					directoryEntry.Dispose();
				}
				return ParseDateTime(dateTime);
			}
		}

		public long HighestCommittedUsn
		{
			get
			{
				CheckIfDisposed();
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string s = null;
				try
				{
					s = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.HighestCommittedUSN);
				}
				finally
				{
					directoryEntry.Dispose();
				}
				return long.Parse(s, NumberFormatInfo.InvariantInfo);
			}
		}

		public string OSVersion
		{
			get
			{
				CheckIfDisposed();
				if (cachedOSVersion == null)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(ComputerObjectName);
					cachedOSVersion = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.OperatingSystem);
				}
				return cachedOSVersion;
			}
		}

		internal double NumericOSVersion
		{
			get
			{
				CheckIfDisposed();
				if (cachedNumericOSVersion == 0.0)
				{
					DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(ComputerObjectName);
					string text = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.OperatingSystemVersion);
					int num = text.IndexOf('(');
					if (num != -1)
					{
						text = text.Substring(0, num);
					}
					cachedNumericOSVersion = double.Parse(text, NumberFormatInfo.InvariantInfo);
				}
				return cachedNumericOSVersion;
			}
		}

		public ActiveDirectoryRoleCollection Roles
		{
			get
			{
				CheckIfDisposed();
				if (cachedRoles == null)
				{
					cachedRoles = new ActiveDirectoryRoleCollection(GetRoles());
				}
				return cachedRoles;
			}
		}

		public Domain Domain
		{
			get
			{
				CheckIfDisposed();
				if (cachedDomain == null)
				{
					string text = null;
					try
					{
						string distinguishedName = directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.DefaultNamingContext);
						text = Utils.GetDnsNameFromDN(distinguishedName);
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(base.Name, DirectoryContextType.DirectoryServer, context);
					cachedDomain = new Domain(newDirectoryContext, text);
				}
				return cachedDomain;
			}
		}

		public override string IPAddress
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DnsPermission(SecurityAction.Assert, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get
			{
				CheckIfDisposed();
				IPHostEntry hostEntry = Dns.GetHostEntry(base.Name);
				if (hostEntry.AddressList.GetLength(0) > 0)
				{
					return hostEntry.AddressList[0].ToString();
				}
				return null;
			}
		}

		public override string SiteName
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get
			{
				CheckIfDisposed();
				if (!dcInfoInitialized || siteInfoModified)
				{
					GetDomainControllerInfo();
				}
				if (cachedSiteName == null)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("SiteNameNotFound", base.Name));
				}
				return cachedSiteName;
			}
		}

		internal string SiteObjectName
		{
			get
			{
				CheckIfDisposed();
				if (!dcInfoInitialized || siteInfoModified)
				{
					GetDomainControllerInfo();
				}
				if (cachedSiteObjectName == null)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("SiteObjectNameNotFound", base.Name));
				}
				return cachedSiteObjectName;
			}
		}

		internal string ComputerObjectName
		{
			get
			{
				CheckIfDisposed();
				if (!dcInfoInitialized)
				{
					GetDomainControllerInfo();
				}
				if (cachedComputerObjectName == null)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("ComputerObjectNameNotFound", base.Name));
				}
				return cachedComputerObjectName;
			}
		}

		internal string ServerObjectName
		{
			get
			{
				CheckIfDisposed();
				if (!dcInfoInitialized || siteInfoModified)
				{
					GetDomainControllerInfo();
				}
				if (cachedServerObjectName == null)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("ServerObjectNameNotFound", base.Name));
				}
				return cachedServerObjectName;
			}
		}

		internal string NtdsaObjectName
		{
			get
			{
				CheckIfDisposed();
				if (!dcInfoInitialized || siteInfoModified)
				{
					GetDomainControllerInfo();
				}
				if (cachedNtdsaObjectName == null)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("NtdsaObjectNameNotFound", base.Name));
				}
				return cachedNtdsaObjectName;
			}
		}

		internal Guid NtdsaObjectGuid
		{
			get
			{
				CheckIfDisposed();
				if (!dcInfoInitialized || siteInfoModified)
				{
					GetDomainControllerInfo();
				}
				if (cachedNtdsaObjectGuid.Equals(Guid.Empty))
				{
					throw new ActiveDirectoryOperationException(Res.GetString("NtdsaObjectGuidNotFound", base.Name));
				}
				return cachedNtdsaObjectGuid;
			}
		}

		public override SyncUpdateCallback SyncFromAllServersCallback
		{
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return userDelegate;
			}
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				userDelegate = value;
			}
		}

		public override ReplicationConnectionCollection InboundConnections
		{
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			get
			{
				return GetInboundConnectionsHelper();
			}
		}

		public override ReplicationConnectionCollection OutboundConnections
		{
			[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
			[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
			get
			{
				return GetOutboundConnectionsHelper();
			}
		}

		internal IntPtr Handle
		{
			get
			{
				GetDSHandle();
				return dsHandle;
			}
		}

		protected DomainController()
		{
		}

		internal DomainController(DirectoryContext context, string domainControllerName)
			: this(context, domainControllerName, new DirectoryEntryManager(context))
		{
		}

		internal DomainController(DirectoryContext context, string domainControllerName, DirectoryEntryManager directoryEntryMgr)
		{
			base.context = context;
			replicaName = domainControllerName;
			base.directoryEntryMgr = directoryEntryMgr;
			becomeRoleOwnerAttrs = new string[5];
			becomeRoleOwnerAttrs[0] = PropertyManager.BecomeSchemaMaster;
			becomeRoleOwnerAttrs[1] = PropertyManager.BecomeDomainMaster;
			becomeRoleOwnerAttrs[2] = PropertyManager.BecomePdc;
			becomeRoleOwnerAttrs[3] = PropertyManager.BecomeRidMaster;
			becomeRoleOwnerAttrs[4] = PropertyManager.BecomeInfrastructureMaster;
			syncAllFunctionPointer = base.SyncAllCallbackRoutine;
		}

		~DomainController()
		{
			Dispose(disposing: false);
		}

		protected override void Dispose(bool disposing)
		{
			if (!disposed)
			{
				try
				{
					FreeDSHandle();
					disposed = true;
				}
				finally
				{
					Dispose();
				}
			}
		}

		public static DomainController GetDomainController(DirectoryContext context)
		{
			string text = null;
			DirectoryEntryManager directoryEntryManager = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.DirectoryServer)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeDC"), "context");
			}
			if (!context.isServer())
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(DomainController), context.Name);
			}
			context = new DirectoryContext(context);
			try
			{
				directoryEntryManager = new DirectoryEntryManager(context);
				DirectoryEntry cachedDirectoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (!Utils.CheckCapability(cachedDirectoryEntry, Capability.ActiveDirectory))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(DomainController), context.Name);
				}
				text = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.DnsHostName);
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(DomainController), context.Name);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			return new DomainController(context, text, directoryEntryManager);
		}

		public static DomainController FindOne(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != 0)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeDomain"), "context");
			}
			return FindOneWithCredentialValidation(context, null, (LocatorOptions)0L);
		}

		public static DomainController FindOne(DirectoryContext context, string siteName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != 0)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeDomain"), "context");
			}
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return FindOneWithCredentialValidation(context, siteName, (LocatorOptions)0L);
		}

		public static DomainController FindOne(DirectoryContext context, LocatorOptions flag)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != 0)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeDomain"), "context");
			}
			return FindOneWithCredentialValidation(context, null, flag);
		}

		public static DomainController FindOne(DirectoryContext context, string siteName, LocatorOptions flag)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != 0)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeDomain"), "context");
			}
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return FindOneWithCredentialValidation(context, siteName, flag);
		}

		public static DomainControllerCollection FindAll(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != 0)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeDomain"), "context");
			}
			context = new DirectoryContext(context);
			return FindAllInternal(context, context.Name, isDnsDomainName: false, null);
		}

		public static DomainControllerCollection FindAll(DirectoryContext context, string siteName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != 0)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeDomain"), "context");
			}
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			context = new DirectoryContext(context);
			return FindAllInternal(context, context.Name, isDnsDomainName: false, siteName);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public virtual GlobalCatalog EnableGlobalCatalog()
		{
			CheckIfDisposed();
			try
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
				int num = 0;
				if (cachedDirectoryEntry.Properties[PropertyManager.Options].Value != null)
				{
					num = (int)cachedDirectoryEntry.Properties[PropertyManager.Options].Value;
				}
				cachedDirectoryEntry.Properties[PropertyManager.Options].Value = num | 1;
				cachedDirectoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			return new GlobalCatalog(context, base.Name);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public virtual bool IsGlobalCatalog()
		{
			CheckIfDisposed();
			try
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(NtdsaObjectName);
				cachedDirectoryEntry.RefreshCache();
				int num = 0;
				if (cachedDirectoryEntry.Properties[PropertyManager.Options].Value != null)
				{
					num = (int)cachedDirectoryEntry.Properties[PropertyManager.Options].Value;
				}
				if ((num & 1) == 1)
				{
					return true;
				}
				return false;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public void TransferRoleOwnership(ActiveDirectoryRole role)
		{
			CheckIfDisposed();
			if (role < ActiveDirectoryRole.SchemaRole || role > ActiveDirectoryRole.InfrastructureRole)
			{
				throw new InvalidEnumArgumentException("role", (int)role, typeof(ActiveDirectoryRole));
			}
			try
			{
				DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				cachedDirectoryEntry.Properties[becomeRoleOwnerAttrs[(int)role]].Value = 1;
				cachedDirectoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			cachedRoles = null;
		}

		public void SeizeRoleOwnership(ActiveDirectoryRole role)
		{
			string text = null;
			CheckIfDisposed();
			text = role switch
			{
				ActiveDirectoryRole.SchemaRole => directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext), 
				ActiveDirectoryRole.NamingRole => directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer), 
				ActiveDirectoryRole.PdcRole => directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.DefaultNamingContext), 
				ActiveDirectoryRole.RidRole => directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.RidManager), 
				ActiveDirectoryRole.InfrastructureRole => directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.Infrastructure), 
				_ => throw new InvalidEnumArgumentException("role", (int)role, typeof(ActiveDirectoryRole)), 
			};
			DirectoryEntry directoryEntry = null;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text);
				directoryEntry.Properties[PropertyManager.FsmoRoleOwner].Value = NtdsaObjectName;
				directoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			cachedRoles = null;
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public virtual DirectorySearcher GetDirectorySearcher()
		{
			CheckIfDisposed();
			return InternalGetDirectorySearcher();
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override void CheckReplicationConsistency()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetDSHandle();
			CheckConsistencyHelper(dsHandle, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override ReplicationCursorCollection GetReplicationCursors(string partition)
		{
			IntPtr intPtr = (IntPtr)0;
			int num = 0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetDSHandle();
			intPtr = GetReplicationInfoHelper(dsHandle, 8, 1, partition, ref advanced, num, DirectoryContext.ADHandle);
			return ConstructReplicationCursors(dsHandle, advanced, intPtr, partition, this, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override ReplicationOperationInformation GetReplicationOperationInformation()
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetDSHandle();
			intPtr = GetReplicationInfoHelper(dsHandle, 5, 5, null, ref advanced, 0, DirectoryContext.ADHandle);
			return ConstructPendingOperations(intPtr, this, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override ReplicationNeighborCollection GetReplicationNeighbors(string partition)
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetDSHandle();
			intPtr = GetReplicationInfoHelper(dsHandle, 0, 0, partition, ref advanced, 0, DirectoryContext.ADHandle);
			return ConstructNeighbors(intPtr, this, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override ReplicationNeighborCollection GetAllReplicationNeighbors()
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetDSHandle();
			intPtr = GetReplicationInfoHelper(dsHandle, 0, 0, null, ref advanced, 0, DirectoryContext.ADHandle);
			return ConstructNeighbors(intPtr, this, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override ReplicationFailureCollection GetReplicationConnectionFailures()
		{
			return GetReplicationFailures(DS_REPL_INFO_TYPE.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override ActiveDirectoryReplicationMetadata GetReplicationMetadata(string objectPath)
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (objectPath == null)
			{
				throw new ArgumentNullException("objectPath");
			}
			if (objectPath.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "objectPath");
			}
			GetDSHandle();
			intPtr = GetReplicationInfoHelper(dsHandle, 9, 2, objectPath, ref advanced, 0, DirectoryContext.ADHandle);
			return ConstructMetaData(advanced, intPtr, this, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override void SyncReplicaFromServer(string partition, string sourceServer)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			if (sourceServer == null)
			{
				throw new ArgumentNullException("sourceServer");
			}
			if (sourceServer.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "sourceServer");
			}
			GetDSHandle();
			SyncReplicaHelper(dsHandle, isADAM: false, partition, sourceServer, 0, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override void TriggerSyncReplicaFromNeighbors(string partition)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetDSHandle();
			SyncReplicaHelper(dsHandle, isADAM: false, partition, null, 17, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override void SyncReplicaFromAllServers(string partition, SyncFromAllServersOptions options)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (partition == null)
			{
				throw new ArgumentNullException("partition");
			}
			if (partition.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "partition");
			}
			GetDSHandle();
			SyncReplicaAllHelper(dsHandle, syncAllFunctionPointer, partition, options, SyncFromAllServersCallback, DirectoryContext.ADHandle);
		}

		[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
		internal static void ValidateCredential(DomainController dc, DirectoryContext context)
		{
			DirectoryEntry directoryEntry = ((!DirectoryContext.ServerBindSupported) ? new DirectoryEntry("LDAP://" + dc.Name + "/RootDSE", context.UserName, context.Password, Utils.DefaultAuthType) : new DirectoryEntry("LDAP://" + dc.Name + "/RootDSE", context.UserName, context.Password, Utils.DefaultAuthType | AuthenticationTypes.ServerBind));
			directoryEntry.Bind(throwIfFail: true);
		}

		internal static DomainController FindOneWithCredentialValidation(DirectoryContext context, string siteName, LocatorOptions flag)
		{
			bool flag2 = false;
			bool flag3 = false;
			context = new DirectoryContext(context);
			DomainController domainController = FindOneInternal(context, context.Name, siteName, flag);
			try
			{
				ValidateCredential(domainController, context);
				flag3 = true;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode != -2147016646)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
				}
				if ((flag & LocatorOptions.ForceRediscovery) != 0)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFoundInDomain", context.Name), typeof(DomainController), null);
				}
				flag2 = true;
			}
			finally
			{
				if (!flag3)
				{
					domainController.Dispose();
				}
			}
			if (flag2)
			{
				flag3 = false;
				domainController = FindOneInternal(context, context.Name, siteName, flag | LocatorOptions.ForceRediscovery);
				try
				{
					ValidateCredential(domainController, context);
					flag3 = true;
				}
				catch (COMException ex2)
				{
					if (ex2.ErrorCode == -2147016646)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFoundInDomain", context.Name), typeof(DomainController), null);
					}
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
				}
				finally
				{
					if (!flag3)
					{
						domainController.Dispose();
					}
				}
			}
			return domainController;
		}

		internal static DomainController FindOneInternal(DirectoryContext context, string domainName, string siteName, LocatorOptions flag)
		{
			int num = 0;
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			if ((flag & ~(LocatorOptions.ForceRediscovery | LocatorOptions.KdcRequired | LocatorOptions.TimeServerRequired | LocatorOptions.WriteableRequired | LocatorOptions.AvoidSelf)) != 0)
			{
				throw new ArgumentException(Res.GetString("InvalidFlags"), "flag");
			}
			if (domainName == null)
			{
				domainName = DirectoryContext.GetLoggedOnDomain();
			}
			num = Locator.DsGetDcNameWrapper(null, domainName, siteName, (long)(flag | (LocatorOptions)16L), out var domainControllerInfo);
			switch (num)
			{
			case 1355:
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFoundInDomain", domainName), typeof(DomainController), null);
			case 1004:
				throw new ArgumentException(Res.GetString("InvalidFlags"), "flag");
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			case 0:
			{
				string text = domainControllerInfo.DomainControllerName.Substring(2);
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context);
				return new DomainController(newDirectoryContext, text);
			}
			}
		}

		internal static DomainControllerCollection FindAllInternal(DirectoryContext context, string domainName, bool isDnsDomainName, string siteName)
		{
			ArrayList arrayList = new ArrayList();
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			if (domainName == null || !isDnsDomainName)
			{
				DomainControllerInfo domainControllerInfo;
				int num = Locator.DsGetDcNameWrapper(null, (domainName != null) ? domainName : DirectoryContext.GetLoggedOnDomain(), null, 16L, out domainControllerInfo);
				switch (num)
				{
				case 1355:
					return new DomainControllerCollection(arrayList);
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(num);
				case 0:
					break;
				}
				domainName = domainControllerInfo.DomainName;
			}
			foreach (string replica in Utils.GetReplicaList(context, Utils.GetDNFromDnsName(domainName), siteName, isDefaultNC: true, isADAM: false, isGC: false))
			{
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(replica, DirectoryContextType.DirectoryServer, context);
				arrayList.Add(new DomainController(newDirectoryContext, replica));
			}
			return new DomainControllerCollection(arrayList);
		}

		private void GetDomainControllerInfo()
		{
			int num = 0;
			int dcCount = 0;
			IntPtr dcInfo = IntPtr.Zero;
			int num2 = 0;
			bool flag = false;
			GetDSHandle();
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsGetDomainControllerInfoW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			NativeMethods.DsGetDomainControllerInfo dsGetDomainControllerInfo = (NativeMethods.DsGetDomainControllerInfo)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsGetDomainControllerInfo));
			num2 = 3;
			num = dsGetDomainControllerInfo(dsHandle, Domain.Name, num2, out dcCount, out dcInfo);
			if (num != 0)
			{
				num2 = 2;
				num = dsGetDomainControllerInfo(dsHandle, Domain.Name, num2, out dcCount, out dcInfo);
			}
			if (num == 0)
			{
				try
				{
					IntPtr intPtr = dcInfo;
					for (int i = 0; i < dcCount; i++)
					{
						if (num2 == 3)
						{
							DsDomainControllerInfo3 dsDomainControllerInfo = new DsDomainControllerInfo3();
							Marshal.PtrToStructure(intPtr, dsDomainControllerInfo);
							if (dsDomainControllerInfo != null && Utils.Compare(dsDomainControllerInfo.dnsHostName, replicaName) == 0)
							{
								flag = true;
								cachedSiteName = dsDomainControllerInfo.siteName;
								cachedSiteObjectName = dsDomainControllerInfo.siteObjectName;
								cachedComputerObjectName = dsDomainControllerInfo.computerObjectName;
								cachedServerObjectName = dsDomainControllerInfo.serverObjectName;
								cachedNtdsaObjectName = dsDomainControllerInfo.ntdsaObjectName;
								cachedNtdsaObjectGuid = dsDomainControllerInfo.ntdsDsaObjectGuid;
							}
							intPtr = Utils.AddToIntPtr(intPtr, Marshal.SizeOf(dsDomainControllerInfo));
						}
						else
						{
							DsDomainControllerInfo2 dsDomainControllerInfo2 = new DsDomainControllerInfo2();
							Marshal.PtrToStructure(intPtr, dsDomainControllerInfo2);
							if (dsDomainControllerInfo2 != null && Utils.Compare(dsDomainControllerInfo2.dnsHostName, replicaName) == 0)
							{
								flag = true;
								cachedSiteName = dsDomainControllerInfo2.siteName;
								cachedSiteObjectName = dsDomainControllerInfo2.siteObjectName;
								cachedComputerObjectName = dsDomainControllerInfo2.computerObjectName;
								cachedServerObjectName = dsDomainControllerInfo2.serverObjectName;
								cachedNtdsaObjectName = dsDomainControllerInfo2.ntdsaObjectName;
								cachedNtdsaObjectGuid = dsDomainControllerInfo2.ntdsDsaObjectGuid;
							}
							intPtr = Utils.AddToIntPtr(intPtr, Marshal.SizeOf(dsDomainControllerInfo2));
						}
					}
				}
				finally
				{
					if (dcInfo != IntPtr.Zero)
					{
						procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsFreeDomainControllerInfoW");
						if (procAddress == (IntPtr)0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
						}
						NativeMethods.DsFreeDomainControllerInfo dsFreeDomainControllerInfo = (NativeMethods.DsFreeDomainControllerInfo)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsFreeDomainControllerInfo));
						dsFreeDomainControllerInfo(num2, dcCount, dcInfo);
					}
				}
				if (!flag)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("DCInfoNotFound"));
				}
				dcInfoInitialized = true;
				siteInfoModified = false;
				return;
			}
			throw ExceptionHelper.GetExceptionFromErrorCode(num, base.Name);
		}

		internal void GetDSHandle()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				Monitor.Enter(this);
				if (dsHandle == IntPtr.Zero)
				{
					if (authIdentity == IntPtr.Zero)
					{
						authIdentity = Utils.GetAuthIdentity(context, DirectoryContext.ADHandle);
					}
					dsHandle = Utils.GetDSHandle(replicaName, null, authIdentity, DirectoryContext.ADHandle);
				}
			}
			finally
			{
				Monitor.Exit(this);
			}
		}

		internal void FreeDSHandle()
		{
			Monitor.Enter(this);
			Utils.FreeDSHandle(dsHandle, DirectoryContext.ADHandle);
			Utils.FreeAuthIdentity(authIdentity, DirectoryContext.ADHandle);
			Monitor.Exit(this);
		}

		internal ReplicationFailureCollection GetReplicationFailures(DS_REPL_INFO_TYPE type)
		{
			IntPtr intPtr = (IntPtr)0;
			bool advanced = true;
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			GetDSHandle();
			intPtr = GetReplicationInfoHelper(dsHandle, (int)type, (int)type, null, ref advanced, 0, DirectoryContext.ADHandle);
			return ConstructFailures(intPtr, this, DirectoryContext.ADHandle);
		}

		private ArrayList GetRoles()
		{
			ArrayList arrayList = new ArrayList();
			int num = 0;
			IntPtr roles = IntPtr.Zero;
			GetDSHandle();
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsListRolesW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			NativeMethods.DsListRoles dsListRoles = (NativeMethods.DsListRoles)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsListRoles));
			num = dsListRoles(dsHandle, out roles);
			if (num == 0)
			{
				try
				{
					DsNameResult dsNameResult = new DsNameResult();
					Marshal.PtrToStructure(roles, dsNameResult);
					IntPtr intPtr = dsNameResult.items;
					for (int i = 0; i < dsNameResult.itemCount; i++)
					{
						DsNameResultItem dsNameResultItem = new DsNameResultItem();
						Marshal.PtrToStructure(intPtr, dsNameResultItem);
						if (dsNameResultItem.status == 0 && dsNameResultItem.name.Equals(NtdsaObjectName))
						{
							arrayList.Add((ActiveDirectoryRole)i);
						}
						intPtr = Utils.AddToIntPtr(intPtr, Marshal.SizeOf(dsNameResultItem));
					}
					return arrayList;
				}
				finally
				{
					if (roles != IntPtr.Zero)
					{
						procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsFreeNameResultW");
						if (procAddress == (IntPtr)0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
						}
						UnsafeNativeMethods.DsFreeNameResultW dsFreeNameResultW = (UnsafeNativeMethods.DsFreeNameResultW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsFreeNameResultW));
						dsFreeNameResultW(roles);
					}
				}
			}
			throw ExceptionHelper.GetExceptionFromErrorCode(num, base.Name);
		}

		private DateTime ParseDateTime(string dateTime)
		{
			int year = int.Parse(dateTime.Substring(0, 4), NumberFormatInfo.InvariantInfo);
			int month = int.Parse(dateTime.Substring(4, 2), NumberFormatInfo.InvariantInfo);
			int day = int.Parse(dateTime.Substring(6, 2), NumberFormatInfo.InvariantInfo);
			int hour = int.Parse(dateTime.Substring(8, 2), NumberFormatInfo.InvariantInfo);
			int minute = int.Parse(dateTime.Substring(10, 2), NumberFormatInfo.InvariantInfo);
			int second = int.Parse(dateTime.Substring(12, 2), NumberFormatInfo.InvariantInfo);
			return new DateTime(year, month, day, hour, minute, second, 0);
		}

		[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
		private DirectorySearcher InternalGetDirectorySearcher()
		{
			DirectoryEntry directoryEntry = new DirectoryEntry("LDAP://" + base.Name);
			if (DirectoryContext.ServerBindSupported)
			{
				directoryEntry.AuthenticationType = Utils.DefaultAuthType | AuthenticationTypes.ServerBind;
			}
			else
			{
				directoryEntry.AuthenticationType = Utils.DefaultAuthType;
			}
			directoryEntry.Username = context.UserName;
			directoryEntry.Password = context.Password;
			return new DirectorySearcher(directoryEntry);
		}
	}
	public class DomainControllerCollection : ReadOnlyCollectionBase
	{
		public DomainController this[int index] => (DomainController)base.InnerList[index];

		internal DomainControllerCollection()
		{
		}

		internal DomainControllerCollection(ArrayList values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(DomainController domainController)
		{
			if (domainController == null)
			{
				throw new ArgumentNullException("domainController");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DomainController domainController2 = (DomainController)base.InnerList[i];
				if (Utils.Compare(domainController2.Name, domainController.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(DomainController domainController)
		{
			if (domainController == null)
			{
				throw new ArgumentNullException("domainController");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DomainController domainController2 = (DomainController)base.InnerList[i];
				if (Utils.Compare(domainController2.Name, domainController.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(DomainController[] domainControllers, int index)
		{
			base.InnerList.CopyTo(domainControllers, index);
		}
	}
	public class SyncFromAllServersErrorInformation
	{
		private SyncFromAllServersErrorCategory category;

		private int errorCode;

		private string errorMessage;

		private string sourceServer;

		private string targetServer;

		public SyncFromAllServersErrorCategory ErrorCategory => category;

		public int ErrorCode => errorCode;

		public string ErrorMessage => errorMessage;

		public string TargetServer => targetServer;

		public string SourceServer => sourceServer;

		internal SyncFromAllServersErrorInformation(SyncFromAllServersErrorCategory category, int errorCode, string errorMessage, string sourceServer, string targetServer)
		{
			this.category = category;
			this.errorCode = errorCode;
			this.errorMessage = errorMessage;
			this.sourceServer = sourceServer;
			this.targetServer = targetServer;
		}
	}
	[Serializable]
	public class ActiveDirectoryObjectNotFoundException : Exception, ISerializable
	{
		private Type objectType;

		private string name;

		public Type Type => objectType;

		public string Name => name;

		public ActiveDirectoryObjectNotFoundException(string message, Type type, string name)
			: base(message)
		{
			objectType = type;
			this.name = name;
		}

		public ActiveDirectoryObjectNotFoundException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public ActiveDirectoryObjectNotFoundException(string message)
			: base(message)
		{
		}

		public ActiveDirectoryObjectNotFoundException()
		{
		}

		protected ActiveDirectoryObjectNotFoundException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	[Serializable]
	public class ActiveDirectoryOperationException : Exception, ISerializable
	{
		private int errorCode;

		public int ErrorCode => errorCode;

		public ActiveDirectoryOperationException(string message, Exception inner, int errorCode)
			: base(message, inner)
		{
			this.errorCode = errorCode;
		}

		public ActiveDirectoryOperationException(string message, int errorCode)
			: base(message)
		{
			this.errorCode = errorCode;
		}

		public ActiveDirectoryOperationException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public ActiveDirectoryOperationException(string message)
			: base(message)
		{
		}

		public ActiveDirectoryOperationException()
			: base(Res.GetString("DSUnknownFailure"))
		{
		}

		protected ActiveDirectoryOperationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	[Serializable]
	public class ActiveDirectoryServerDownException : Exception, ISerializable
	{
		private int errorCode;

		private string name;

		public int ErrorCode => errorCode;

		public string Name => name;

		public override string Message
		{
			get
			{
				string message = base.Message;
				if (name != null && name.Length != 0)
				{
					return message + Environment.NewLine + Res.GetString("Name", name) + Environment.NewLine;
				}
				return message;
			}
		}

		public ActiveDirectoryServerDownException(string message, Exception inner, int errorCode, string name)
			: base(message, inner)
		{
			this.errorCode = errorCode;
			this.name = name;
		}

		public ActiveDirectoryServerDownException(string message, int errorCode, string name)
			: base(message)
		{
			this.errorCode = errorCode;
			this.name = name;
		}

		public ActiveDirectoryServerDownException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public ActiveDirectoryServerDownException(string message)
			: base(message)
		{
		}

		public ActiveDirectoryServerDownException()
		{
		}

		protected ActiveDirectoryServerDownException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	[Serializable]
	public class ActiveDirectoryObjectExistsException : Exception
	{
		public ActiveDirectoryObjectExistsException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public ActiveDirectoryObjectExistsException(string message)
			: base(message)
		{
		}

		public ActiveDirectoryObjectExistsException()
		{
		}

		protected ActiveDirectoryObjectExistsException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[Serializable]
	public class SyncFromAllServersOperationException : ActiveDirectoryOperationException, ISerializable
	{
		private SyncFromAllServersErrorInformation[] errors;

		public SyncFromAllServersErrorInformation[] ErrorInformation
		{
			get
			{
				if (errors == null)
				{
					return new SyncFromAllServersErrorInformation[0];
				}
				SyncFromAllServersErrorInformation[] array = new SyncFromAllServersErrorInformation[errors.Length];
				for (int i = 0; i < errors.Length; i++)
				{
					array[i] = new SyncFromAllServersErrorInformation(errors[i].ErrorCategory, errors[i].ErrorCode, errors[i].ErrorMessage, errors[i].SourceServer, errors[i].TargetServer);
				}
				return array;
			}
		}

		public SyncFromAllServersOperationException(string message, Exception inner, SyncFromAllServersErrorInformation[] errors)
			: base(message, inner)
		{
			this.errors = errors;
		}

		public SyncFromAllServersOperationException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public SyncFromAllServersOperationException(string message)
			: base(message)
		{
		}

		public SyncFromAllServersOperationException()
			: base(Res.GetString("DSSyncAllFailure"))
		{
		}

		protected SyncFromAllServersOperationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	[Serializable]
	public class ForestTrustCollisionException : ActiveDirectoryOperationException, ISerializable
	{
		private ForestTrustRelationshipCollisionCollection collisions = new ForestTrustRelationshipCollisionCollection();

		public ForestTrustRelationshipCollisionCollection Collisions => collisions;

		public ForestTrustCollisionException(string message, Exception inner, ForestTrustRelationshipCollisionCollection collisions)
			: base(message, inner)
		{
			this.collisions = collisions;
		}

		public ForestTrustCollisionException(string message, Exception inner)
			: base(message, inner)
		{
		}

		public ForestTrustCollisionException(string message)
			: base(message)
		{
		}

		public ForestTrustCollisionException()
			: base(Res.GetString("ForestTrustCollision"))
		{
		}

		protected ForestTrustCollisionException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo serializationInfo, StreamingContext streamingContext)
		{
			base.GetObjectData(serializationInfo, streamingContext);
		}
	}
	internal class ExceptionHelper
	{
		private static int ERROR_NOT_ENOUGH_MEMORY = 8;

		private static int ERROR_OUTOFMEMORY = 14;

		private static int ERROR_DS_DRA_OUT_OF_MEM = 8446;

		private static int ERROR_NO_SUCH_DOMAIN = 1355;

		private static int ERROR_ACCESS_DENIED = 5;

		private static int ERROR_NO_LOGON_SERVERS = 1311;

		private static int ERROR_DS_DRA_ACCESS_DENIED = 8453;

		private static int RPC_S_OUT_OF_RESOURCES = 1721;

		internal static int RPC_S_SERVER_UNAVAILABLE = 1722;

		internal static int RPC_S_CALL_FAILED = 1726;

		private static int ERROR_CANCELLED = 1223;

		internal static int ERROR_DS_DRA_BAD_DN = 8439;

		internal static int ERROR_DS_NAME_UNPARSEABLE = 8350;

		internal static int ERROR_DS_UNKNOWN_ERROR = 8431;

		internal static Exception GetExceptionFromCOMException(COMException e)
		{
			return GetExceptionFromCOMException(null, e);
		}

		internal static Exception GetExceptionFromCOMException(DirectoryContext context, COMException e)
		{
			int errorCode = e.ErrorCode;
			string message = e.Message;
			switch (errorCode)
			{
			case -2147024891:
				return new UnauthorizedAccessException(message, e);
			case -2147023570:
				return new AuthenticationException(message, e);
			case -2147016657:
				return new InvalidOperationException(message, e);
			case -2147016651:
				return new InvalidOperationException(message, e);
			case -2147019886:
				return new ActiveDirectoryObjectExistsException(message, e);
			case -2147024888:
				return new OutOfMemoryException();
			case -2147016690:
			case -2147016689:
			case -2147016646:
				if (context != null)
				{
					return new ActiveDirectoryServerDownException(message, e, errorCode, context.GetServerName());
				}
				return new ActiveDirectoryServerDownException(message, e, errorCode, null);
			default:
				return new ActiveDirectoryOperationException(message, e, errorCode);
			}
		}

		internal static Exception GetExceptionFromErrorCode(int errorCode)
		{
			return GetExceptionFromErrorCode(errorCode, null);
		}

		internal static Exception GetExceptionFromErrorCode(int errorCode, string targetName)
		{
			string errorMessage = GetErrorMessage(errorCode, hresult: false);
			if (errorCode == ERROR_ACCESS_DENIED || errorCode == ERROR_DS_DRA_ACCESS_DENIED)
			{
				return new UnauthorizedAccessException(errorMessage);
			}
			if (errorCode == ERROR_NOT_ENOUGH_MEMORY || errorCode == ERROR_OUTOFMEMORY || errorCode == ERROR_DS_DRA_OUT_OF_MEM || errorCode == RPC_S_OUT_OF_RESOURCES)
			{
				return new OutOfMemoryException();
			}
			if (errorCode == ERROR_NO_LOGON_SERVERS || errorCode == ERROR_NO_SUCH_DOMAIN || errorCode == RPC_S_SERVER_UNAVAILABLE || errorCode == RPC_S_CALL_FAILED)
			{
				return new ActiveDirectoryServerDownException(errorMessage, errorCode, targetName);
			}
			return new ActiveDirectoryOperationException(errorMessage, errorCode);
		}

		internal static string GetErrorMessage(int errorCode, bool hresult)
		{
			uint num = (uint)errorCode;
			if (!hresult)
			{
				num = (num & 0xFFFFu) | 0x70000u | 0x80000000u;
			}
			string text = "";
			StringBuilder stringBuilder = new StringBuilder(256);
			int num2 = UnsafeNativeMethods.FormatMessageW(12800, 0, (int)num, 0, stringBuilder, stringBuilder.Capacity + 1, 0);
			if (num2 != 0)
			{
				return stringBuilder.ToString(0, num2);
			}
			return Res.GetString("DSUnknown", Convert.ToString(num, 16));
		}

		internal static SyncFromAllServersOperationException CreateSyncAllException(IntPtr errorInfo, bool singleError)
		{
			if (errorInfo == (IntPtr)0)
			{
				return new SyncFromAllServersOperationException();
			}
			if (singleError)
			{
				DS_REPSYNCALL_ERRINFO dS_REPSYNCALL_ERRINFO = new DS_REPSYNCALL_ERRINFO();
				Marshal.PtrToStructure(errorInfo, dS_REPSYNCALL_ERRINFO);
				string errorMessage = GetErrorMessage(dS_REPSYNCALL_ERRINFO.dwWin32Err, hresult: false);
				string sourceServer = Marshal.PtrToStringUni(dS_REPSYNCALL_ERRINFO.pszSrcId);
				string targetServer = Marshal.PtrToStringUni(dS_REPSYNCALL_ERRINFO.pszSvrId);
				if (dS_REPSYNCALL_ERRINFO.dwWin32Err == ERROR_CANCELLED)
				{
					return null;
				}
				SyncFromAllServersErrorInformation syncFromAllServersErrorInformation = new SyncFromAllServersErrorInformation(dS_REPSYNCALL_ERRINFO.error, dS_REPSYNCALL_ERRINFO.dwWin32Err, errorMessage, sourceServer, targetServer);
				return new SyncFromAllServersOperationException(Res.GetString("DSSyncAllFailure"), null, new SyncFromAllServersErrorInformation[1] { syncFromAllServersErrorInformation });
			}
			IntPtr intPtr = Marshal.ReadIntPtr(errorInfo);
			ArrayList arrayList = new ArrayList();
			int num = 0;
			while (intPtr != (IntPtr)0)
			{
				DS_REPSYNCALL_ERRINFO dS_REPSYNCALL_ERRINFO2 = new DS_REPSYNCALL_ERRINFO();
				Marshal.PtrToStructure(intPtr, dS_REPSYNCALL_ERRINFO2);
				if (dS_REPSYNCALL_ERRINFO2.dwWin32Err != ERROR_CANCELLED)
				{
					string errorMessage2 = GetErrorMessage(dS_REPSYNCALL_ERRINFO2.dwWin32Err, hresult: false);
					string sourceServer2 = Marshal.PtrToStringUni(dS_REPSYNCALL_ERRINFO2.pszSrcId);
					string targetServer2 = Marshal.PtrToStringUni(dS_REPSYNCALL_ERRINFO2.pszSvrId);
					SyncFromAllServersErrorInformation value = new SyncFromAllServersErrorInformation(dS_REPSYNCALL_ERRINFO2.error, dS_REPSYNCALL_ERRINFO2.dwWin32Err, errorMessage2, sourceServer2, targetServer2);
					arrayList.Add(value);
				}
				num++;
				intPtr = Marshal.ReadIntPtr(errorInfo, num * Marshal.SizeOf(typeof(IntPtr)));
			}
			if (arrayList.Count == 0)
			{
				return null;
			}
			SyncFromAllServersErrorInformation[] array = new SyncFromAllServersErrorInformation[arrayList.Count];
			for (int i = 0; i < arrayList.Count; i++)
			{
				SyncFromAllServersErrorInformation syncFromAllServersErrorInformation2 = (SyncFromAllServersErrorInformation)arrayList[i];
				array[i] = new SyncFromAllServersErrorInformation(syncFromAllServersErrorInformation2.ErrorCategory, syncFromAllServersErrorInformation2.ErrorCode, syncFromAllServersErrorInformation2.ErrorMessage, syncFromAllServersErrorInformation2.SourceServer, syncFromAllServersErrorInformation2.TargetServer);
			}
			return new SyncFromAllServersOperationException(Res.GetString("DSSyncAllFailure"), null, array);
		}

		internal static Exception CreateForestTrustCollisionException(IntPtr collisionInfo)
		{
			ForestTrustRelationshipCollisionCollection forestTrustRelationshipCollisionCollection = new ForestTrustRelationshipCollisionCollection();
			LSA_FOREST_TRUST_COLLISION_INFORMATION lSA_FOREST_TRUST_COLLISION_INFORMATION = new LSA_FOREST_TRUST_COLLISION_INFORMATION();
			Marshal.PtrToStructure(collisionInfo, lSA_FOREST_TRUST_COLLISION_INFORMATION);
			int recordCount = lSA_FOREST_TRUST_COLLISION_INFORMATION.RecordCount;
			IntPtr intPtr = (IntPtr)0;
			for (int i = 0; i < recordCount; i++)
			{
				intPtr = Marshal.ReadIntPtr(lSA_FOREST_TRUST_COLLISION_INFORMATION.Entries, i * Marshal.SizeOf(typeof(IntPtr)));
				LSA_FOREST_TRUST_COLLISION_RECORD lSA_FOREST_TRUST_COLLISION_RECORD = new LSA_FOREST_TRUST_COLLISION_RECORD();
				Marshal.PtrToStructure(intPtr, lSA_FOREST_TRUST_COLLISION_RECORD);
				ForestTrustCollisionType type = lSA_FOREST_TRUST_COLLISION_RECORD.Type;
				string record = Marshal.PtrToStringUni(lSA_FOREST_TRUST_COLLISION_RECORD.Name.Buffer, lSA_FOREST_TRUST_COLLISION_RECORD.Name.Length / 2);
				TopLevelNameCollisionOptions tLNFlag = TopLevelNameCollisionOptions.None;
				DomainCollisionOptions domainFlag = DomainCollisionOptions.None;
				switch (type)
				{
				case ForestTrustCollisionType.TopLevelName:
					tLNFlag = (TopLevelNameCollisionOptions)lSA_FOREST_TRUST_COLLISION_RECORD.Flags;
					break;
				case ForestTrustCollisionType.Domain:
					domainFlag = (DomainCollisionOptions)lSA_FOREST_TRUST_COLLISION_RECORD.Flags;
					break;
				}
				ForestTrustRelationshipCollision collision = new ForestTrustRelationshipCollision(type, tLNFlag, domainFlag, record);
				forestTrustRelationshipCollisionCollection.Add(collision);
			}
			return new ForestTrustCollisionException(Res.GetString("ForestTrustCollision"), null, forestTrustRelationshipCollisionCollection);
		}
	}
	public enum ForestMode
	{
		Windows2000Forest,
		Windows2003InterimForest,
		Windows2003Forest,
		Windows2008Forest,
		Windows2008R2Forest
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class Forest : IDisposable
	{
		private DirectoryContext context;

		private DirectoryEntryManager directoryEntryMgr;

		private IntPtr dsHandle = IntPtr.Zero;

		private IntPtr authIdentity = IntPtr.Zero;

		private bool disposed;

		private string forestDnsName;

		private ReadOnlySiteCollection cachedSites;

		private DomainCollection cachedDomains;

		private GlobalCatalogCollection cachedGlobalCatalogs;

		private ApplicationPartitionCollection cachedApplicationPartitions;

		private ForestMode currentForestMode = (ForestMode)(-1);

		private Domain cachedRootDomain;

		private ActiveDirectorySchema cachedSchema;

		private DomainController cachedSchemaRoleOwner;

		private DomainController cachedNamingRoleOwner;

		public string Name
		{
			get
			{
				CheckIfDisposed();
				return forestDnsName;
			}
		}

		public ReadOnlySiteCollection Sites
		{
			get
			{
				CheckIfDisposed();
				if (cachedSites == null)
				{
					cachedSites = new ReadOnlySiteCollection(GetSites());
				}
				return cachedSites;
			}
		}

		public DomainCollection Domains
		{
			get
			{
				CheckIfDisposed();
				if (cachedDomains == null)
				{
					cachedDomains = new DomainCollection(GetDomains());
				}
				return cachedDomains;
			}
		}

		public GlobalCatalogCollection GlobalCatalogs
		{
			get
			{
				CheckIfDisposed();
				if (cachedGlobalCatalogs == null)
				{
					cachedGlobalCatalogs = FindAllGlobalCatalogs();
				}
				return cachedGlobalCatalogs;
			}
		}

		public ApplicationPartitionCollection ApplicationPartitions
		{
			get
			{
				CheckIfDisposed();
				if (cachedApplicationPartitions == null)
				{
					cachedApplicationPartitions = new ApplicationPartitionCollection(GetApplicationPartitions());
				}
				return cachedApplicationPartitions;
			}
		}

		public ForestMode ForestMode
		{
			get
			{
				CheckIfDisposed();
				if (currentForestMode == (ForestMode)(-1))
				{
					currentForestMode = GetForestMode();
				}
				return currentForestMode;
			}
		}

		public Domain RootDomain
		{
			get
			{
				CheckIfDisposed();
				if (cachedRootDomain == null)
				{
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(Name, DirectoryContextType.Domain, context);
					cachedRootDomain = new Domain(newDirectoryContext, Name);
				}
				return cachedRootDomain;
			}
		}

		public ActiveDirectorySchema Schema
		{
			get
			{
				CheckIfDisposed();
				if (cachedSchema == null)
				{
					try
					{
						cachedSchema = new ActiveDirectorySchema(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext));
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
				}
				return cachedSchema;
			}
		}

		public DomainController SchemaRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedSchemaRoleOwner == null)
				{
					cachedSchemaRoleOwner = GetRoleOwner(ActiveDirectoryRole.SchemaRole);
				}
				return cachedSchemaRoleOwner;
			}
		}

		public DomainController NamingRoleOwner
		{
			get
			{
				CheckIfDisposed();
				if (cachedNamingRoleOwner == null)
				{
					cachedNamingRoleOwner = GetRoleOwner(ActiveDirectoryRole.NamingRole);
				}
				return cachedNamingRoleOwner;
			}
		}

		internal Forest(DirectoryContext context, string forestDnsName, DirectoryEntryManager directoryEntryMgr)
		{
			this.context = context;
			this.directoryEntryMgr = directoryEntryMgr;
			this.forestDnsName = forestDnsName;
		}

		internal Forest(DirectoryContext context, string name)
			: this(context, name, new DirectoryEntryManager(context))
		{
		}

		public void Dispose()
		{
			Dispose(disposing: true);
		}

		protected void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}
			if (disposing)
			{
				foreach (DirectoryEntry cachedDirectoryEntry in directoryEntryMgr.GetCachedDirectoryEntries())
				{
					cachedDirectoryEntry.Dispose();
				}
			}
			disposed = true;
		}

		public static Forest GetForest(DirectoryContext context)
		{
			DirectoryEntryManager directoryEntryManager = null;
			DirectoryEntry directoryEntry = null;
			string text = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest && context.ContextType != DirectoryContextType.DirectoryServer)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeServerORForest"), "context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ContextNotAssociatedWithDomain"), typeof(Forest), null);
			}
			if (context.Name != null && !context.isRootDomain() && !context.isServer())
			{
				if (context.ContextType == DirectoryContextType.Forest)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestNotFound"), typeof(Forest), context.Name);
				}
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(Forest), null);
			}
			context = new DirectoryContext(context);
			directoryEntryManager = new DirectoryEntryManager(context);
			try
			{
				directoryEntry = directoryEntryManager.GetCachedDirectoryEntry(WellKnownDN.RootDSE);
				if (context.isServer() && !Utils.CheckCapability(directoryEntry, Capability.ActiveDirectory))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(Forest), null);
				}
				text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.RootDomainNamingContext);
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					if (context.ContextType == DirectoryContextType.Forest)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestNotFound"), typeof(Forest), context.Name);
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DCNotFound", context.Name), typeof(Forest), null);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			return new Forest(context, Utils.GetDnsNameFromDN(text), directoryEntryManager);
		}

		public void RaiseForestFunctionality(ForestMode forestMode)
		{
			CheckIfDisposed();
			if (forestMode < ForestMode.Windows2000Forest || forestMode > ForestMode.Windows2008R2Forest)
			{
				throw new InvalidEnumArgumentException("forestMode", (int)forestMode, typeof(ForestMode));
			}
			if (forestMode <= GetForestMode())
			{
				throw new ArgumentException(Res.GetString("InvalidMode"), "forestMode");
			}
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
			try
			{
				directoryEntry.Properties[PropertyManager.MsDSBehaviorVersion].Value = (int)forestMode;
				directoryEntry.CommitChanges();
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147016694)
				{
					throw new ArgumentException(Res.GetString("NoW2K3DCsInForest"), "forestMode");
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			finally
			{
				directoryEntry.Dispose();
			}
			currentForestMode = (ForestMode)(-1);
		}

		public override string ToString()
		{
			return Name;
		}

		public GlobalCatalog FindGlobalCatalog()
		{
			CheckIfDisposed();
			return GlobalCatalog.FindOneInternal(context, Name, null, (LocatorOptions)0L);
		}

		public GlobalCatalog FindGlobalCatalog(string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return GlobalCatalog.FindOneInternal(context, Name, siteName, (LocatorOptions)0L);
		}

		public GlobalCatalog FindGlobalCatalog(LocatorOptions flag)
		{
			CheckIfDisposed();
			return GlobalCatalog.FindOneInternal(context, Name, null, flag);
		}

		public GlobalCatalog FindGlobalCatalog(string siteName, LocatorOptions flag)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return GlobalCatalog.FindOneInternal(context, Name, siteName, flag);
		}

		public GlobalCatalogCollection FindAllGlobalCatalogs()
		{
			CheckIfDisposed();
			return GlobalCatalog.FindAllInternal(context, null);
		}

		public GlobalCatalogCollection FindAllGlobalCatalogs(string siteName)
		{
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return GlobalCatalog.FindAllInternal(context, siteName);
		}

		public GlobalCatalogCollection FindAllDiscoverableGlobalCatalogs()
		{
			long dcFlags = 64L;
			CheckIfDisposed();
			return new GlobalCatalogCollection(Locator.EnumerateDomainControllers(context, Name, null, dcFlags));
		}

		public GlobalCatalogCollection FindAllDiscoverableGlobalCatalogs(string siteName)
		{
			long dcFlags = 64L;
			CheckIfDisposed();
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			if (siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			return new GlobalCatalogCollection(Locator.EnumerateDomainControllers(context, Name, siteName, dcFlags));
		}

		public TrustRelationshipInformationCollection GetAllTrustRelationships()
		{
			CheckIfDisposed();
			return GetTrustsHelper(null);
		}

		public ForestTrustRelationshipInformation GetTrustRelationship(string targetForestName)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			TrustRelationshipInformationCollection trustsHelper = GetTrustsHelper(targetForestName);
			if (trustsHelper.Count != 0)
			{
				return (ForestTrustRelationshipInformation)trustsHelper[0];
			}
			throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", Name, targetForestName), typeof(TrustRelationshipInformation), null);
		}

		public bool GetSelectiveAuthenticationStatus(string targetForestName)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			return TrustHelper.GetTrustedDomainInfoStatus(context, Name, targetForestName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION, isForest: true);
		}

		public void SetSelectiveAuthenticationStatus(string targetForestName, bool enable)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			TrustHelper.SetTrustedDomainInfoStatus(context, Name, targetForestName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION, enable, isForest: true);
		}

		public bool GetSidFilteringStatus(string targetForestName)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			return TrustHelper.GetTrustedDomainInfoStatus(context, Name, targetForestName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL, isForest: true);
		}

		public void SetSidFilteringStatus(string targetForestName, bool enable)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			TrustHelper.SetTrustedDomainInfoStatus(context, Name, targetForestName, TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL, enable, isForest: true);
		}

		public void DeleteLocalSideOfTrustRelationship(string targetForestName)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			TrustHelper.DeleteTrust(context, Name, targetForestName, isForest: true);
		}

		public void DeleteTrustRelationship(Forest targetForest)
		{
			CheckIfDisposed();
			if (targetForest == null)
			{
				throw new ArgumentNullException("targetForest");
			}
			TrustHelper.DeleteTrust(targetForest.GetDirectoryContext(), targetForest.Name, Name, isForest: true);
			TrustHelper.DeleteTrust(context, Name, targetForest.Name, isForest: true);
		}

		public void VerifyOutboundTrustRelationship(string targetForestName)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			TrustHelper.VerifyTrust(context, Name, targetForestName, isForest: true, TrustDirection.Outbound, forceSecureChannelReset: false, null);
		}

		public void VerifyTrustRelationship(Forest targetForest, TrustDirection direction)
		{
			CheckIfDisposed();
			if (targetForest == null)
			{
				throw new ArgumentNullException("targetForest");
			}
			if (direction < TrustDirection.Inbound || direction > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("direction", (int)direction, typeof(TrustDirection));
			}
			if ((direction & TrustDirection.Outbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(context, Name, targetForest.Name, isForest: true, TrustDirection.Outbound, forceSecureChannelReset: false, null);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", Name, targetForest.Name, direction), typeof(ForestTrustRelationshipInformation), null);
				}
			}
			if ((direction & TrustDirection.Inbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(targetForest.GetDirectoryContext(), targetForest.Name, Name, isForest: true, TrustDirection.Outbound, forceSecureChannelReset: false, null);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", Name, targetForest.Name, direction), typeof(ForestTrustRelationshipInformation), null);
				}
			}
		}

		public void CreateLocalSideOfTrustRelationship(string targetForestName, TrustDirection direction, string trustPassword)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			if (direction < TrustDirection.Inbound || direction > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("direction", (int)direction, typeof(TrustDirection));
			}
			if (trustPassword == null)
			{
				throw new ArgumentNullException("trustPassword");
			}
			if (trustPassword.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "trustPassword");
			}
			Locator.GetDomainControllerInfo(null, targetForestName, null, 80L);
			DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(targetForestName, DirectoryContextType.Forest, context);
			TrustHelper.CreateTrust(context, Name, newDirectoryContext, targetForestName, isForest: true, direction, trustPassword);
		}

		public void CreateTrustRelationship(Forest targetForest, TrustDirection direction)
		{
			CheckIfDisposed();
			if (targetForest == null)
			{
				throw new ArgumentNullException("targetForest");
			}
			if (direction < TrustDirection.Inbound || direction > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("direction", (int)direction, typeof(TrustDirection));
			}
			string password = TrustHelper.CreateTrustPassword();
			TrustHelper.CreateTrust(context, Name, targetForest.GetDirectoryContext(), targetForest.Name, isForest: true, direction, password);
			int num = 0;
			if ((direction & TrustDirection.Inbound) != 0)
			{
				num |= 2;
			}
			if ((direction & TrustDirection.Outbound) != 0)
			{
				num |= 1;
			}
			TrustHelper.CreateTrust(targetForest.GetDirectoryContext(), targetForest.Name, context, Name, isForest: true, (TrustDirection)num, password);
		}

		public void UpdateLocalSideOfTrustRelationship(string targetForestName, string newTrustPassword)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			if (newTrustPassword == null)
			{
				throw new ArgumentNullException("newTrustPassword");
			}
			if (newTrustPassword.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "newTrustPassword");
			}
			TrustHelper.UpdateTrust(context, Name, targetForestName, newTrustPassword, isForest: true);
		}

		public void UpdateLocalSideOfTrustRelationship(string targetForestName, TrustDirection newTrustDirection, string newTrustPassword)
		{
			CheckIfDisposed();
			if (targetForestName == null)
			{
				throw new ArgumentNullException("targetForestName");
			}
			if (targetForestName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "targetForestName");
			}
			if (newTrustDirection < TrustDirection.Inbound || newTrustDirection > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("newTrustDirection", (int)newTrustDirection, typeof(TrustDirection));
			}
			if (newTrustPassword == null)
			{
				throw new ArgumentNullException("newTrustPassword");
			}
			if (newTrustPassword.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "newTrustPassword");
			}
			TrustHelper.UpdateTrustDirection(context, Name, targetForestName, newTrustPassword, isForest: true, newTrustDirection);
		}

		public void UpdateTrustRelationship(Forest targetForest, TrustDirection newTrustDirection)
		{
			CheckIfDisposed();
			if (targetForest == null)
			{
				throw new ArgumentNullException("targetForest");
			}
			if (newTrustDirection < TrustDirection.Inbound || newTrustDirection > TrustDirection.Bidirectional)
			{
				throw new InvalidEnumArgumentException("newTrustDirection", (int)newTrustDirection, typeof(TrustDirection));
			}
			string password = TrustHelper.CreateTrustPassword();
			TrustHelper.UpdateTrustDirection(context, Name, targetForest.Name, password, isForest: true, newTrustDirection);
			TrustDirection trustDirection = (TrustDirection)0;
			if ((newTrustDirection & TrustDirection.Inbound) != 0)
			{
				trustDirection |= TrustDirection.Outbound;
			}
			if ((newTrustDirection & TrustDirection.Outbound) != 0)
			{
				trustDirection |= TrustDirection.Inbound;
			}
			TrustHelper.UpdateTrustDirection(targetForest.GetDirectoryContext(), targetForest.Name, Name, password, isForest: true, trustDirection);
		}

		public void RepairTrustRelationship(Forest targetForest)
		{
			TrustDirection trustDirection = TrustDirection.Bidirectional;
			CheckIfDisposed();
			if (targetForest == null)
			{
				throw new ArgumentNullException("targetForest");
			}
			try
			{
				trustDirection = GetTrustRelationship(targetForest.Name).TrustDirection;
				if ((trustDirection & TrustDirection.Outbound) != 0)
				{
					TrustHelper.VerifyTrust(context, Name, targetForest.Name, isForest: true, TrustDirection.Outbound, forceSecureChannelReset: true, null);
				}
				if ((trustDirection & TrustDirection.Inbound) != 0)
				{
					TrustHelper.VerifyTrust(targetForest.GetDirectoryContext(), targetForest.Name, Name, isForest: true, TrustDirection.Outbound, forceSecureChannelReset: true, null);
				}
			}
			catch (ActiveDirectoryOperationException)
			{
				RepairTrustHelper(targetForest, trustDirection);
			}
			catch (UnauthorizedAccessException)
			{
				RepairTrustHelper(targetForest, trustDirection);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", Name, targetForest.Name, trustDirection), typeof(ForestTrustRelationshipInformation), null);
			}
		}

		public static Forest GetCurrentForest()
		{
			return GetForest(new DirectoryContext(DirectoryContextType.Forest));
		}

		internal DirectoryContext GetDirectoryContext()
		{
			return context;
		}

		private ForestMode GetForestMode()
		{
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			try
			{
				if (!directoryEntry.Properties.Contains(PropertyManager.ForestFunctionality))
				{
					return ForestMode.Windows2000Forest;
				}
				return (ForestMode)int.Parse((string)directoryEntry.Properties[PropertyManager.ForestFunctionality].Value, NumberFormatInfo.InvariantInfo);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		private DomainController GetRoleOwner(ActiveDirectoryRole role)
		{
			DirectoryEntry directoryEntry = null;
			string text = null;
			try
			{
				switch (role)
				{
				case ActiveDirectoryRole.SchemaRole:
					directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext));
					break;
				case ActiveDirectoryRole.NamingRole:
					directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
					break;
				}
				text = Utils.GetDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner));
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Dispose();
			}
			DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context);
			return new DomainController(newDirectoryContext, text);
		}

		private ArrayList GetSites()
		{
			ArrayList arrayList = new ArrayList();
			int num = 0;
			IntPtr zero = IntPtr.Zero;
			IntPtr zero2 = IntPtr.Zero;
			IntPtr sites = IntPtr.Zero;
			try
			{
				GetDSHandle(out zero, out zero2);
				IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsListSitesW");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				NativeMethods.DsListSites dsListSites = (NativeMethods.DsListSites)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsListSites));
				num = dsListSites(zero, out sites);
				if (num == 0)
				{
					try
					{
						DsNameResult dsNameResult = new DsNameResult();
						Marshal.PtrToStructure(sites, dsNameResult);
						IntPtr intPtr = dsNameResult.items;
						for (int i = 0; i < dsNameResult.itemCount; i++)
						{
							DsNameResultItem dsNameResultItem = new DsNameResultItem();
							Marshal.PtrToStructure(intPtr, dsNameResultItem);
							if (dsNameResultItem.status == 0)
							{
								string value = Utils.GetDNComponents(dsNameResultItem.name)[0].Value;
								arrayList.Add(new ActiveDirectorySite(context, value, existing: true));
							}
							intPtr = Utils.AddToIntPtr(intPtr, Marshal.SizeOf(dsNameResultItem));
						}
						return arrayList;
					}
					finally
					{
						if (sites != IntPtr.Zero)
						{
							procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsFreeNameResultW");
							if (procAddress == (IntPtr)0)
							{
								throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
							}
							UnsafeNativeMethods.DsFreeNameResultW dsFreeNameResultW = (UnsafeNativeMethods.DsFreeNameResultW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsFreeNameResultW));
							dsFreeNameResultW(sites);
						}
					}
				}
				throw ExceptionHelper.GetExceptionFromErrorCode(num, context.GetServerName());
			}
			finally
			{
				if (zero != (IntPtr)0)
				{
					Utils.FreeDSHandle(zero, DirectoryContext.ADHandle);
				}
				if (zero2 != (IntPtr)0)
				{
					Utils.FreeAuthIdentity(zero2, DirectoryContext.ADHandle);
				}
			}
		}

		private ArrayList GetApplicationPartitions()
		{
			ArrayList arrayList = new ArrayList();
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
			StringBuilder stringBuilder = new StringBuilder(15);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=crossRef)(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.804:=");
			stringBuilder.Append(1);
			stringBuilder.Append(")(!(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.803:=");
			stringBuilder.Append(2);
			stringBuilder.Append(")))");
			string filter = stringBuilder.ToString();
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, filter, new string[2]
			{
				PropertyManager.DnsRoot,
				PropertyManager.NCName
			}, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
				string value = directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext);
				string value2 = directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.ConfigurationNamingContext);
				foreach (SearchResult item in searchResultCollection)
				{
					string text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.NCName);
					if (!text.Equals(value) && !text.Equals(value2))
					{
						string name = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsRoot);
						DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(name, DirectoryContextType.ApplicationPartition, context);
						arrayList.Add(new ApplicationPartition(newDirectoryContext, text, (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsRoot), ApplicationPartitionType.ADApplicationPartition, new DirectoryEntryManager(newDirectoryContext)));
					}
				}
				return arrayList;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
				directoryEntry.Dispose();
			}
		}

		private ArrayList GetDomains()
		{
			ArrayList arrayList = new ArrayList();
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.PartitionsContainer));
			StringBuilder stringBuilder = new StringBuilder(15);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=crossRef)(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.804:=");
			stringBuilder.Append(1);
			stringBuilder.Append(")(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.804:=");
			stringBuilder.Append(2);
			stringBuilder.Append("))");
			string filter = stringBuilder.ToString();
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, filter, new string[1] { PropertyManager.DnsRoot }, SearchScope.OneLevel);
			SearchResultCollection searchResultCollection = null;
			try
			{
				searchResultCollection = aDSearcher.FindAll();
				foreach (SearchResult item in searchResultCollection)
				{
					string text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsRoot);
					DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.Domain, context);
					arrayList.Add(new Domain(newDirectoryContext, text));
				}
				return arrayList;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				searchResultCollection?.Dispose();
				directoryEntry.Dispose();
			}
		}

		private void GetDSHandle(out IntPtr dsHandle, out IntPtr authIdentity)
		{
			authIdentity = Utils.GetAuthIdentity(context, DirectoryContext.ADHandle);
			if (context.ContextType == DirectoryContextType.DirectoryServer)
			{
				dsHandle = Utils.GetDSHandle(context.GetServerName(), null, authIdentity, DirectoryContext.ADHandle);
			}
			else
			{
				dsHandle = Utils.GetDSHandle(null, context.GetServerName(), authIdentity, DirectoryContext.ADHandle);
			}
		}

		private void CheckIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		private TrustRelationshipInformationCollection GetTrustsHelper(string targetForestName)
		{
			string text = null;
			IntPtr domains = (IntPtr)0;
			int count = 0;
			TrustRelationshipInformationCollection trustRelationshipInformationCollection = new TrustRelationshipInformationCollection();
			bool flag = false;
			int num = 0;
			text = Utils.GetPolicyServerName(context, isForest: true, needPdc: false, Name);
			flag = Utils.Impersonate(context);
			try
			{
				try
				{
					num = UnsafeNativeMethods.DsEnumerateDomainTrustsW(text, 42, out domains, out count);
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
				}
			}
			catch
			{
				throw;
			}
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num, text);
			}
			try
			{
				if (domains != (IntPtr)0 && count != 0)
				{
					IntPtr intPtr = (IntPtr)0;
					for (int i = 0; i < count; i++)
					{
						intPtr = Utils.AddToIntPtr(domains, i * Marshal.SizeOf(typeof(DS_DOMAIN_TRUSTS)));
						DS_DOMAIN_TRUSTS dS_DOMAIN_TRUSTS = new DS_DOMAIN_TRUSTS();
						Marshal.PtrToStructure(intPtr, dS_DOMAIN_TRUSTS);
						if (targetForestName != null)
						{
							bool flag2 = false;
							string text2 = null;
							string text3 = null;
							if (dS_DOMAIN_TRUSTS.DnsDomainName != (IntPtr)0)
							{
								text2 = Marshal.PtrToStringUni(dS_DOMAIN_TRUSTS.DnsDomainName);
							}
							if (dS_DOMAIN_TRUSTS.NetbiosDomainName != (IntPtr)0)
							{
								text3 = Marshal.PtrToStringUni(dS_DOMAIN_TRUSTS.NetbiosDomainName);
							}
							if (text2 != null && Utils.Compare(targetForestName, text2) == 0)
							{
								flag2 = true;
							}
							else if (text3 != null && Utils.Compare(targetForestName, text3) == 0)
							{
								flag2 = true;
							}
							if (!flag2)
							{
								continue;
							}
						}
						if (dS_DOMAIN_TRUSTS.TrustType == TrustHelper.TRUST_TYPE_UPLEVEL && ((uint)dS_DOMAIN_TRUSTS.TrustAttributes & 8u) != 0 && (dS_DOMAIN_TRUSTS.Flags & 8) == 0)
						{
							TrustRelationshipInformation info = new ForestTrustRelationshipInformation(context, Name, dS_DOMAIN_TRUSTS, TrustType.Forest);
							trustRelationshipInformationCollection.Add(info);
						}
					}
				}
				return trustRelationshipInformationCollection;
			}
			finally
			{
				if (domains != (IntPtr)0)
				{
					UnsafeNativeMethods.NetApiBufferFree(domains);
				}
			}
		}

		private void RepairTrustHelper(Forest targetForest, TrustDirection direction)
		{
			string password = TrustHelper.CreateTrustPassword();
			string preferredTargetServer = TrustHelper.UpdateTrust(targetForest.GetDirectoryContext(), targetForest.Name, Name, password, isForest: true);
			string preferredTargetServer2 = TrustHelper.UpdateTrust(context, Name, targetForest.Name, password, isForest: true);
			if ((direction & TrustDirection.Outbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(context, Name, targetForest.Name, isForest: true, TrustDirection.Outbound, forceSecureChannelReset: true, preferredTargetServer);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", Name, targetForest.Name, direction), typeof(ForestTrustRelationshipInformation), null);
				}
			}
			if ((direction & TrustDirection.Inbound) != 0)
			{
				try
				{
					TrustHelper.VerifyTrust(targetForest.GetDirectoryContext(), targetForest.Name, Name, isForest: true, TrustDirection.Outbound, forceSecureChannelReset: true, preferredTargetServer2);
				}
				catch (ActiveDirectoryObjectNotFoundException)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", Name, targetForest.Name, direction), typeof(ForestTrustRelationshipInformation), null);
				}
			}
		}
	}
	public class ForestTrustRelationshipCollision
	{
		private ForestTrustCollisionType type;

		private TopLevelNameCollisionOptions tlnFlag;

		private DomainCollisionOptions domainFlag;

		private string record;

		public ForestTrustCollisionType CollisionType => type;

		public TopLevelNameCollisionOptions TopLevelNameCollisionOption => tlnFlag;

		public DomainCollisionOptions DomainCollisionOption => domainFlag;

		public string CollisionRecord => record;

		internal ForestTrustRelationshipCollision(ForestTrustCollisionType collisionType, TopLevelNameCollisionOptions TLNFlag, DomainCollisionOptions domainFlag, string record)
		{
			type = collisionType;
			tlnFlag = TLNFlag;
			this.domainFlag = domainFlag;
			this.record = record;
		}
	}
	public class ForestTrustRelationshipCollisionCollection : ReadOnlyCollectionBase
	{
		public ForestTrustRelationshipCollision this[int index] => (ForestTrustRelationshipCollision)base.InnerList[index];

		internal ForestTrustRelationshipCollisionCollection()
		{
		}

		public bool Contains(ForestTrustRelationshipCollision collision)
		{
			if (collision == null)
			{
				throw new ArgumentNullException("collision");
			}
			return base.InnerList.Contains(collision);
		}

		public int IndexOf(ForestTrustRelationshipCollision collision)
		{
			if (collision == null)
			{
				throw new ArgumentNullException("collision");
			}
			return base.InnerList.IndexOf(collision);
		}

		public void CopyTo(ForestTrustRelationshipCollision[] array, int index)
		{
			base.InnerList.CopyTo(array, index);
		}

		internal int Add(ForestTrustRelationshipCollision collision)
		{
			return base.InnerList.Add(collision);
		}
	}
	public class ForestTrustDomainInfoCollection : ReadOnlyCollectionBase
	{
		public ForestTrustDomainInformation this[int index] => (ForestTrustDomainInformation)base.InnerList[index];

		internal ForestTrustDomainInfoCollection()
		{
		}

		public bool Contains(ForestTrustDomainInformation information)
		{
			if (information == null)
			{
				throw new ArgumentNullException("information");
			}
			return base.InnerList.Contains(information);
		}

		public int IndexOf(ForestTrustDomainInformation information)
		{
			if (information == null)
			{
				throw new ArgumentNullException("information");
			}
			return base.InnerList.IndexOf(information);
		}

		public void CopyTo(ForestTrustDomainInformation[] array, int index)
		{
			base.InnerList.CopyTo(array, index);
		}

		internal int Add(ForestTrustDomainInformation info)
		{
			return base.InnerList.Add(info);
		}
	}
	public enum ForestTrustDomainStatus
	{
		Enabled = 0,
		SidAdminDisabled = 1,
		SidConflictDisabled = 2,
		NetBiosNameAdminDisabled = 4,
		NetBiosNameConflictDisabled = 8
	}
	public class ForestTrustDomainInformation
	{
		private string dnsName;

		private string nbName;

		private string sid;

		private ForestTrustDomainStatus status;

		internal LARGE_INTEGER time;

		public string DnsName => dnsName;

		public string NetBiosName => nbName;

		public string DomainSid => sid;

		public ForestTrustDomainStatus Status
		{
			get
			{
				return status;
			}
			set
			{
				if (value != 0 && value != ForestTrustDomainStatus.SidAdminDisabled && value != ForestTrustDomainStatus.SidConflictDisabled && value != ForestTrustDomainStatus.NetBiosNameAdminDisabled && value != ForestTrustDomainStatus.NetBiosNameConflictDisabled)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(ForestTrustDomainStatus));
				}
				status = value;
			}
		}

		internal ForestTrustDomainInformation(int flag, LSA_FOREST_TRUST_DOMAIN_INFO domainInfo, LARGE_INTEGER time)
		{
			status = (ForestTrustDomainStatus)flag;
			dnsName = Marshal.PtrToStringUni(domainInfo.DNSNameBuffer, domainInfo.DNSNameLength / 2);
			nbName = Marshal.PtrToStringUni(domainInfo.NetBIOSNameBuffer, domainInfo.NetBIOSNameLength / 2);
			IntPtr stringSid = (IntPtr)0;
			if (UnsafeNativeMethods.ConvertSidToStringSidW(domainInfo.sid, ref stringSid) == 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			try
			{
				sid = Marshal.PtrToStringUni(stringSid);
			}
			finally
			{
				UnsafeNativeMethods.LocalFree(stringSid);
			}
			this.time = time;
		}
	}
	public class TrustRelationshipInformation
	{
		internal string source;

		internal string target;

		internal TrustType type;

		internal TrustDirection direction;

		internal DirectoryContext context;

		public string SourceName => source;

		public string TargetName => target;

		public TrustType TrustType => type;

		public TrustDirection TrustDirection => direction;

		internal TrustRelationshipInformation()
		{
		}

		internal TrustRelationshipInformation(DirectoryContext context, string source, TrustObject obj)
		{
			this.context = context;
			this.source = source;
			target = ((obj.DnsDomainName == null) ? obj.NetbiosDomainName : obj.DnsDomainName);
			if (((uint)obj.Flags & 2u) != 0 && ((uint)obj.Flags & 0x20u) != 0)
			{
				direction = TrustDirection.Bidirectional;
			}
			else if (((uint)obj.Flags & 2u) != 0)
			{
				direction = TrustDirection.Outbound;
			}
			else if (((uint)obj.Flags & 0x20u) != 0)
			{
				direction = TrustDirection.Inbound;
			}
			type = obj.TrustType;
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ForestTrustRelationshipInformation : TrustRelationshipInformation
	{
		private TopLevelNameCollection topLevelNames = new TopLevelNameCollection();

		private StringCollection excludedNames = new StringCollection();

		private ForestTrustDomainInfoCollection domainInfo = new ForestTrustDomainInfoCollection();

		private ArrayList binaryData = new ArrayList();

		private ArrayList binaryRecordType = new ArrayList();

		private Hashtable excludedNameTime = new Hashtable();

		private ArrayList binaryDataTime = new ArrayList();

		internal bool retrieved;

		public TopLevelNameCollection TopLevelNames
		{
			get
			{
				if (!retrieved)
				{
					GetForestTrustInfoHelper();
				}
				return topLevelNames;
			}
		}

		public StringCollection ExcludedTopLevelNames
		{
			get
			{
				if (!retrieved)
				{
					GetForestTrustInfoHelper();
				}
				return excludedNames;
			}
		}

		public ForestTrustDomainInfoCollection TrustedDomainInformation
		{
			get
			{
				if (!retrieved)
				{
					GetForestTrustInfoHelper();
				}
				return domainInfo;
			}
		}

		internal ForestTrustRelationshipInformation(DirectoryContext context, string source, DS_DOMAIN_TRUSTS unmanagedTrust, TrustType type)
		{
			string text = null;
			string text2 = null;
			base.context = context;
			base.source = source;
			if (unmanagedTrust.DnsDomainName != (IntPtr)0)
			{
				text = Marshal.PtrToStringUni(unmanagedTrust.DnsDomainName);
			}
			if (unmanagedTrust.NetbiosDomainName != (IntPtr)0)
			{
				text2 = Marshal.PtrToStringUni(unmanagedTrust.NetbiosDomainName);
			}
			target = ((text == null) ? text2 : text);
			if (((uint)unmanagedTrust.Flags & 2u) != 0 && ((uint)unmanagedTrust.Flags & 0x20u) != 0)
			{
				direction = TrustDirection.Bidirectional;
			}
			else if (((uint)unmanagedTrust.Flags & 2u) != 0)
			{
				direction = TrustDirection.Outbound;
			}
			else if (((uint)unmanagedTrust.Flags & 0x20u) != 0)
			{
				direction = TrustDirection.Inbound;
			}
			base.type = type;
		}

		public void Save()
		{
			int num = 0;
			IntPtr intPtr = (IntPtr)0;
			int num2 = 0;
			IntPtr intPtr2 = (IntPtr)0;
			IntPtr intPtr3 = (IntPtr)0;
			PolicySafeHandle policySafeHandle = null;
			IntPtr collisionInfo = (IntPtr)0;
			ArrayList arrayList = new ArrayList();
			ArrayList arrayList2 = new ArrayList();
			bool flag = false;
			IntPtr intPtr4 = (IntPtr)0;
			string text = null;
			IntPtr intPtr5 = (IntPtr)0;
			int count = TopLevelNames.Count;
			int count2 = ExcludedTopLevelNames.Count;
			int count3 = TrustedDomainInformation.Count;
			int count4 = binaryData.Count;
			checked
			{
				num += count;
				num += count2;
				num += count3;
				num += count4;
				intPtr = Marshal.AllocHGlobal(num * Marshal.SizeOf(typeof(IntPtr)));
			}
			try
			{
				try
				{
					IntPtr intPtr6 = (IntPtr)0;
					intPtr5 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileTime)));
					UnsafeNativeMethods.GetSystemTimeAsFileTime(intPtr5);
					FileTime fileTime = new FileTime();
					Marshal.PtrToStructure(intPtr5, fileTime);
					for (int i = 0; i < count; i++)
					{
						LSA_FOREST_TRUST_RECORD lSA_FOREST_TRUST_RECORD = new LSA_FOREST_TRUST_RECORD();
						lSA_FOREST_TRUST_RECORD.Flags = (int)topLevelNames[i].Status;
						lSA_FOREST_TRUST_RECORD.ForestTrustType = LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelName;
						TopLevelName topLevelName = topLevelNames[i];
						lSA_FOREST_TRUST_RECORD.Time = topLevelName.time;
						lSA_FOREST_TRUST_RECORD.TopLevelName = new LSA_UNICODE_STRING();
						intPtr6 = Marshal.StringToHGlobalUni(topLevelName.Name);
						arrayList.Add(intPtr6);
						UnsafeNativeMethods.RtlInitUnicodeString(lSA_FOREST_TRUST_RECORD.TopLevelName, intPtr6);
						intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_FOREST_TRUST_RECORD)));
						arrayList.Add(intPtr2);
						Marshal.StructureToPtr(lSA_FOREST_TRUST_RECORD, intPtr2, fDeleteOld: false);
						Marshal.WriteIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * num2, intPtr2);
						num2++;
					}
					for (int j = 0; j < count2; j++)
					{
						LSA_FOREST_TRUST_RECORD lSA_FOREST_TRUST_RECORD2 = new LSA_FOREST_TRUST_RECORD();
						lSA_FOREST_TRUST_RECORD2.Flags = 0;
						lSA_FOREST_TRUST_RECORD2.ForestTrustType = LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelNameEx;
						if (excludedNameTime.Contains(excludedNames[j]))
						{
							lSA_FOREST_TRUST_RECORD2.Time = (LARGE_INTEGER)excludedNameTime[j];
						}
						else
						{
							lSA_FOREST_TRUST_RECORD2.Time = new LARGE_INTEGER();
							lSA_FOREST_TRUST_RECORD2.Time.lowPart = fileTime.lower;
							lSA_FOREST_TRUST_RECORD2.Time.highPart = fileTime.higher;
						}
						lSA_FOREST_TRUST_RECORD2.TopLevelName = new LSA_UNICODE_STRING();
						intPtr6 = Marshal.StringToHGlobalUni(excludedNames[j]);
						arrayList.Add(intPtr6);
						UnsafeNativeMethods.RtlInitUnicodeString(lSA_FOREST_TRUST_RECORD2.TopLevelName, intPtr6);
						intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_FOREST_TRUST_RECORD)));
						arrayList.Add(intPtr2);
						Marshal.StructureToPtr(lSA_FOREST_TRUST_RECORD2, intPtr2, fDeleteOld: false);
						Marshal.WriteIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * num2, intPtr2);
						num2++;
					}
					for (int k = 0; k < count3; k++)
					{
						LSA_FOREST_TRUST_RECORD lSA_FOREST_TRUST_RECORD3 = new LSA_FOREST_TRUST_RECORD();
						lSA_FOREST_TRUST_RECORD3.Flags = (int)domainInfo[k].Status;
						lSA_FOREST_TRUST_RECORD3.ForestTrustType = LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustDomainInfo;
						ForestTrustDomainInformation forestTrustDomainInformation = domainInfo[k];
						lSA_FOREST_TRUST_RECORD3.Time = forestTrustDomainInformation.time;
						IntPtr pSid = (IntPtr)0;
						IntPtr intPtr7 = (IntPtr)0;
						intPtr7 = Marshal.StringToHGlobalUni(forestTrustDomainInformation.DomainSid);
						arrayList.Add(intPtr7);
						if (UnsafeNativeMethods.ConvertStringSidToSidW(intPtr7, ref pSid) == 0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
						}
						lSA_FOREST_TRUST_RECORD3.DomainInfo = new LSA_FOREST_TRUST_DOMAIN_INFO();
						lSA_FOREST_TRUST_RECORD3.DomainInfo.sid = pSid;
						arrayList2.Add(pSid);
						lSA_FOREST_TRUST_RECORD3.DomainInfo.DNSNameBuffer = Marshal.StringToHGlobalUni(forestTrustDomainInformation.DnsName);
						arrayList.Add(lSA_FOREST_TRUST_RECORD3.DomainInfo.DNSNameBuffer);
						lSA_FOREST_TRUST_RECORD3.DomainInfo.DNSNameLength = (short)((forestTrustDomainInformation.DnsName != null) ? (forestTrustDomainInformation.DnsName.Length * 2) : 0);
						lSA_FOREST_TRUST_RECORD3.DomainInfo.DNSNameMaximumLength = (short)((forestTrustDomainInformation.DnsName != null) ? (forestTrustDomainInformation.DnsName.Length * 2) : 0);
						lSA_FOREST_TRUST_RECORD3.DomainInfo.NetBIOSNameBuffer = Marshal.StringToHGlobalUni(forestTrustDomainInformation.NetBiosName);
						arrayList.Add(lSA_FOREST_TRUST_RECORD3.DomainInfo.NetBIOSNameBuffer);
						lSA_FOREST_TRUST_RECORD3.DomainInfo.NetBIOSNameLength = (short)((forestTrustDomainInformation.NetBiosName != null) ? (forestTrustDomainInformation.NetBiosName.Length * 2) : 0);
						lSA_FOREST_TRUST_RECORD3.DomainInfo.NetBIOSNameMaximumLength = (short)((forestTrustDomainInformation.NetBiosName != null) ? (forestTrustDomainInformation.NetBiosName.Length * 2) : 0);
						intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_FOREST_TRUST_RECORD)));
						arrayList.Add(intPtr2);
						Marshal.StructureToPtr(lSA_FOREST_TRUST_RECORD3, intPtr2, fDeleteOld: false);
						Marshal.WriteIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * num2, intPtr2);
						num2++;
					}
					for (int l = 0; l < count4; l++)
					{
						LSA_FOREST_TRUST_RECORD lSA_FOREST_TRUST_RECORD4 = new LSA_FOREST_TRUST_RECORD();
						lSA_FOREST_TRUST_RECORD4.Flags = 0;
						lSA_FOREST_TRUST_RECORD4.Time = (LARGE_INTEGER)binaryDataTime[l];
						lSA_FOREST_TRUST_RECORD4.ForestTrustType = (LSA_FOREST_TRUST_RECORD_TYPE)binaryRecordType[l];
						lSA_FOREST_TRUST_RECORD4.Data = new LSA_FOREST_TRUST_BINARY_DATA();
						lSA_FOREST_TRUST_RECORD4.Data.Length = ((byte[])binaryData[l]).Length;
						if (lSA_FOREST_TRUST_RECORD4.Data.Length == 0)
						{
							lSA_FOREST_TRUST_RECORD4.Data.Buffer = (IntPtr)0;
						}
						else
						{
							lSA_FOREST_TRUST_RECORD4.Data.Buffer = Marshal.AllocHGlobal(lSA_FOREST_TRUST_RECORD4.Data.Length);
							arrayList.Add(lSA_FOREST_TRUST_RECORD4.Data.Buffer);
							Marshal.Copy((byte[])binaryData[l], 0, lSA_FOREST_TRUST_RECORD4.Data.Buffer, lSA_FOREST_TRUST_RECORD4.Data.Length);
						}
						intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_FOREST_TRUST_RECORD)));
						arrayList.Add(intPtr2);
						Marshal.StructureToPtr(lSA_FOREST_TRUST_RECORD4, intPtr2, fDeleteOld: false);
						Marshal.WriteIntPtr(intPtr, Marshal.SizeOf(typeof(IntPtr)) * num2, intPtr2);
						num2++;
					}
					LSA_FOREST_TRUST_INFORMATION lSA_FOREST_TRUST_INFORMATION = new LSA_FOREST_TRUST_INFORMATION();
					lSA_FOREST_TRUST_INFORMATION.RecordCount = num;
					lSA_FOREST_TRUST_INFORMATION.Entries = intPtr;
					intPtr3 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_FOREST_TRUST_INFORMATION)));
					Marshal.StructureToPtr(lSA_FOREST_TRUST_INFORMATION, intPtr3, fDeleteOld: false);
					text = Utils.GetPolicyServerName(context, isForest: true, needPdc: true, base.SourceName);
					flag = Utils.Impersonate(context);
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					LSA_UNICODE_STRING result = new LSA_UNICODE_STRING();
					intPtr4 = Marshal.StringToHGlobalUni(base.TargetName);
					UnsafeNativeMethods.RtlInitUnicodeString(result, intPtr4);
					int num3 = UnsafeNativeMethods.LsaSetForestTrustInformation(policySafeHandle, result, intPtr3, 1, out collisionInfo);
					if (num3 != 0)
					{
						throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError(num3), text);
					}
					if (collisionInfo != (IntPtr)0)
					{
						throw ExceptionHelper.CreateForestTrustCollisionException(collisionInfo);
					}
					num3 = UnsafeNativeMethods.LsaSetForestTrustInformation(policySafeHandle, result, intPtr3, 0, out collisionInfo);
					if (num3 != 0)
					{
						throw ExceptionHelper.GetExceptionFromErrorCode(num3, text);
					}
					retrieved = false;
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					for (int m = 0; m < arrayList.Count; m++)
					{
						Marshal.FreeHGlobal((IntPtr)arrayList[m]);
					}
					for (int n = 0; n < arrayList2.Count; n++)
					{
						UnsafeNativeMethods.LocalFree((IntPtr)arrayList2[n]);
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (intPtr3 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr3);
					}
					if (collisionInfo != (IntPtr)0)
					{
						UnsafeNativeMethods.LsaFreeMemory(collisionInfo);
					}
					if (intPtr4 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr4);
					}
					if (intPtr5 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr5);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		private void GetForestTrustInfoHelper()
		{
			IntPtr ForestTrustInfo = (IntPtr)0;
			PolicySafeHandle policySafeHandle = null;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = null;
			bool flag = false;
			IntPtr intPtr = (IntPtr)0;
			string text = null;
			TopLevelNameCollection topLevelNameCollection = new TopLevelNameCollection();
			StringCollection stringCollection = new StringCollection();
			ForestTrustDomainInfoCollection forestTrustDomainInfoCollection = new ForestTrustDomainInfoCollection();
			ArrayList arrayList = new ArrayList();
			Hashtable hashtable = new Hashtable();
			ArrayList arrayList2 = new ArrayList();
			ArrayList arrayList3 = new ArrayList();
			try
			{
				try
				{
					lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
					intPtr = Marshal.StringToHGlobalUni(base.TargetName);
					UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr);
					text = Utils.GetPolicyServerName(context, isForest: true, needPdc: false, source);
					flag = Utils.Impersonate(context);
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					int num = UnsafeNativeMethods.LsaQueryForestTrustInformation(policySafeHandle, lSA_UNICODE_STRING, ref ForestTrustInfo);
					if (num != 0)
					{
						int num2 = UnsafeNativeMethods.LsaNtStatusToWinError(num);
						if (num2 != 0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(num2, text);
						}
					}
					try
					{
						if (ForestTrustInfo != (IntPtr)0)
						{
							LSA_FOREST_TRUST_INFORMATION lSA_FOREST_TRUST_INFORMATION = new LSA_FOREST_TRUST_INFORMATION();
							Marshal.PtrToStructure(ForestTrustInfo, lSA_FOREST_TRUST_INFORMATION);
							int recordCount = lSA_FOREST_TRUST_INFORMATION.RecordCount;
							IntPtr intPtr2 = (IntPtr)0;
							for (int i = 0; i < recordCount; i++)
							{
								intPtr2 = Marshal.ReadIntPtr(lSA_FOREST_TRUST_INFORMATION.Entries, i * Marshal.SizeOf(typeof(IntPtr)));
								LSA_FOREST_TRUST_RECORD lSA_FOREST_TRUST_RECORD = new LSA_FOREST_TRUST_RECORD();
								Marshal.PtrToStructure(intPtr2, lSA_FOREST_TRUST_RECORD);
								if (lSA_FOREST_TRUST_RECORD.ForestTrustType == LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelName)
								{
									IntPtr ptr = Utils.AddToIntPtr(intPtr2, 16);
									Marshal.PtrToStructure(ptr, lSA_FOREST_TRUST_RECORD.TopLevelName);
									TopLevelName name = new TopLevelName(lSA_FOREST_TRUST_RECORD.Flags, lSA_FOREST_TRUST_RECORD.TopLevelName, lSA_FOREST_TRUST_RECORD.Time);
									topLevelNameCollection.Add(name);
									continue;
								}
								if (lSA_FOREST_TRUST_RECORD.ForestTrustType == LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelNameEx)
								{
									IntPtr ptr2 = Utils.AddToIntPtr(intPtr2, 16);
									Marshal.PtrToStructure(ptr2, lSA_FOREST_TRUST_RECORD.TopLevelName);
									string text2 = Marshal.PtrToStringUni(lSA_FOREST_TRUST_RECORD.TopLevelName.Buffer, lSA_FOREST_TRUST_RECORD.TopLevelName.Length / 2);
									stringCollection.Add(text2);
									hashtable.Add(text2, lSA_FOREST_TRUST_RECORD.Time);
									continue;
								}
								if (lSA_FOREST_TRUST_RECORD.ForestTrustType == LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustDomainInfo)
								{
									IntPtr ptr3 = Utils.AddToIntPtr(intPtr2, 16);
									Marshal.PtrToStructure(ptr3, lSA_FOREST_TRUST_RECORD.DomainInfo);
									ForestTrustDomainInformation info = new ForestTrustDomainInformation(lSA_FOREST_TRUST_RECORD.Flags, lSA_FOREST_TRUST_RECORD.DomainInfo, lSA_FOREST_TRUST_RECORD.Time);
									forestTrustDomainInfoCollection.Add(info);
									continue;
								}
								IntPtr ptr4 = Utils.AddToIntPtr(intPtr2, 16);
								Marshal.PtrToStructure(ptr4, lSA_FOREST_TRUST_RECORD.Data);
								int length = lSA_FOREST_TRUST_RECORD.Data.Length;
								byte[] array = new byte[length];
								if (lSA_FOREST_TRUST_RECORD.Data.Buffer != (IntPtr)0 && length != 0)
								{
									Marshal.Copy(lSA_FOREST_TRUST_RECORD.Data.Buffer, array, 0, length);
								}
								arrayList.Add(array);
								arrayList2.Add(lSA_FOREST_TRUST_RECORD.Time);
								arrayList3.Add((int)lSA_FOREST_TRUST_RECORD.ForestTrustType);
							}
						}
					}
					finally
					{
						UnsafeNativeMethods.LsaFreeMemory(ForestTrustInfo);
					}
					topLevelNames = topLevelNameCollection;
					excludedNames = stringCollection;
					domainInfo = forestTrustDomainInfoCollection;
					binaryData = arrayList;
					excludedNameTime = hashtable;
					binaryDataTime = arrayList2;
					binaryRecordType = arrayList3;
					retrieved = true;
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
				}
			}
			catch
			{
				throw;
			}
		}
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class GlobalCatalog : DomainController
	{
		private ActiveDirectorySchema schema;

		private bool disabled;

		internal GlobalCatalog(DirectoryContext context, string globalCatalogName)
			: base(context, globalCatalogName)
		{
		}

		internal GlobalCatalog(DirectoryContext context, string globalCatalogName, DirectoryEntryManager directoryEntryMgr)
			: base(context, globalCatalogName, directoryEntryMgr)
		{
		}

		public static GlobalCatalog GetGlobalCatalog(DirectoryContext context)
		{
			string text = null;
			bool flag = false;
			DirectoryEntryManager directoryEntryManager = null;
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.DirectoryServer)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeGC"), "context");
			}
			if (!context.isServer())
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("GCNotFound", context.Name), typeof(GlobalCatalog), context.Name);
			}
			context = new DirectoryContext(context);
			try
			{
				directoryEntryManager = new DirectoryEntryManager(context);
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				if (!Utils.CheckCapability(directoryEntry, Capability.ActiveDirectory))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("GCNotFound", context.Name), typeof(GlobalCatalog), context.Name);
				}
				text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.DnsHostName);
				if (!bool.Parse((string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.IsGlobalCatalogReady)))
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("GCNotFound", context.Name), typeof(GlobalCatalog), context.Name);
				}
			}
			catch (COMException ex)
			{
				int errorCode = ex.ErrorCode;
				if (errorCode == -2147016646)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("GCNotFound", context.Name), typeof(GlobalCatalog), context.Name);
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
			}
			return new GlobalCatalog(context, text, directoryEntryManager);
		}

		public new static GlobalCatalog FindOne(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeForest"), "context");
			}
			return FindOneWithCredentialValidation(context, null, (LocatorOptions)0L);
		}

		public new static GlobalCatalog FindOne(DirectoryContext context, string siteName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeForest"), "context");
			}
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return FindOneWithCredentialValidation(context, siteName, (LocatorOptions)0L);
		}

		public new static GlobalCatalog FindOne(DirectoryContext context, LocatorOptions flag)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeForest"), "context");
			}
			return FindOneWithCredentialValidation(context, null, flag);
		}

		public new static GlobalCatalog FindOne(DirectoryContext context, string siteName, LocatorOptions flag)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeForest"), "context");
			}
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			return FindOneWithCredentialValidation(context, siteName, flag);
		}

		public new static GlobalCatalogCollection FindAll(DirectoryContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeForest"), "context");
			}
			context = new DirectoryContext(context);
			return FindAllInternal(context, null);
		}

		public new static GlobalCatalogCollection FindAll(DirectoryContext context, string siteName)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.ContextType != DirectoryContextType.Forest)
			{
				throw new ArgumentException(Res.GetString("TargetShouldBeForest"), "context");
			}
			if (siteName == null)
			{
				throw new ArgumentNullException("siteName");
			}
			context = new DirectoryContext(context);
			return FindAllInternal(context, siteName);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override GlobalCatalog EnableGlobalCatalog()
		{
			CheckIfDisposed();
			throw new InvalidOperationException(Res.GetString("CannotPerformOnGCObject"));
		}

		public DomainController DisableGlobalCatalog()
		{
			CheckIfDisposed();
			CheckIfDisabled();
			DirectoryEntry cachedDirectoryEntry = directoryEntryMgr.GetCachedDirectoryEntry(base.NtdsaObjectName);
			int num = 0;
			try
			{
				if (cachedDirectoryEntry.Properties[PropertyManager.Options].Value != null)
				{
					num = (int)cachedDirectoryEntry.Properties[PropertyManager.Options].Value;
				}
				cachedDirectoryEntry.Properties[PropertyManager.Options].Value = num & -2;
				cachedDirectoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			disabled = true;
			return new DomainController(context, base.Name);
		}

		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		public override bool IsGlobalCatalog()
		{
			CheckIfDisposed();
			CheckIfDisabled();
			return true;
		}

		public ReadOnlyActiveDirectorySchemaPropertyCollection FindAllProperties()
		{
			CheckIfDisposed();
			CheckIfDisabled();
			if (schema == null)
			{
				string text = null;
				try
				{
					text = directoryEntryMgr.ExpandWellKnownDN(WellKnownDN.SchemaNamingContext);
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				Utils.GetNewDirectoryContext(base.Name, DirectoryContextType.DirectoryServer, context);
				schema = new ActiveDirectorySchema(context, text);
			}
			return schema.FindAllProperties(PropertyTypes.InGlobalCatalog);
		}

		[DirectoryServicesPermission(SecurityAction.InheritanceDemand, Unrestricted = true)]
		[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
		public override DirectorySearcher GetDirectorySearcher()
		{
			CheckIfDisposed();
			CheckIfDisabled();
			return InternalGetDirectorySearcher();
		}

		private void CheckIfDisabled()
		{
			if (disabled)
			{
				throw new InvalidOperationException(Res.GetString("GCDisabled"));
			}
		}

		internal new static GlobalCatalog FindOneWithCredentialValidation(DirectoryContext context, string siteName, LocatorOptions flag)
		{
			bool flag2 = false;
			bool flag3 = false;
			context = new DirectoryContext(context);
			GlobalCatalog globalCatalog = FindOneInternal(context, context.Name, siteName, flag);
			try
			{
				DomainController.ValidateCredential(globalCatalog, context);
				flag3 = true;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode != -2147016646)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
				}
				if ((flag & LocatorOptions.ForceRediscovery) != 0)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("GCNotFoundInForest", context.Name), typeof(GlobalCatalog), null);
				}
				flag2 = true;
			}
			finally
			{
				if (!flag3)
				{
					globalCatalog.Dispose();
				}
			}
			if (flag2)
			{
				flag3 = false;
				globalCatalog = FindOneInternal(context, context.Name, siteName, flag | LocatorOptions.ForceRediscovery);
				try
				{
					DomainController.ValidateCredential(globalCatalog, context);
					flag3 = true;
				}
				catch (COMException ex2)
				{
					if (ex2.ErrorCode == -2147016646)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("GCNotFoundInForest", context.Name), typeof(GlobalCatalog), null);
					}
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
				}
				finally
				{
					if (!flag3)
					{
						globalCatalog.Dispose();
					}
				}
			}
			return globalCatalog;
		}

		internal new static GlobalCatalog FindOneInternal(DirectoryContext context, string forestName, string siteName, LocatorOptions flag)
		{
			int errorCode = 0;
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			if ((flag & ~(LocatorOptions.ForceRediscovery | LocatorOptions.KdcRequired | LocatorOptions.TimeServerRequired | LocatorOptions.WriteableRequired | LocatorOptions.AvoidSelf)) != 0)
			{
				throw new ArgumentException(Res.GetString("InvalidFlags"), "flag");
			}
			if (forestName == null)
			{
				DomainControllerInfo domainControllerInfo;
				switch (Locator.DsGetDcNameWrapper(null, DirectoryContext.GetLoggedOnDomain(), null, 16L, out domainControllerInfo))
				{
				case 1355:
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ContextNotAssociatedWithDomain"), typeof(GlobalCatalog), null);
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(errorCode);
				case 0:
					break;
				}
				forestName = domainControllerInfo.DnsForestName;
			}
			errorCode = Locator.DsGetDcNameWrapper(null, forestName, siteName, (long)(flag | (LocatorOptions)80L), out var domainControllerInfo2);
			switch (errorCode)
			{
			case 1355:
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("GCNotFoundInForest", forestName), typeof(GlobalCatalog), null);
			case 1004:
				throw new ArgumentException(Res.GetString("InvalidFlags"), "flag");
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(errorCode);
			case 0:
			{
				string text = domainControllerInfo2.DomainControllerName.Substring(2);
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(text, DirectoryContextType.DirectoryServer, context);
				return new GlobalCatalog(newDirectoryContext, text);
			}
			}
		}

		internal static GlobalCatalogCollection FindAllInternal(DirectoryContext context, string siteName)
		{
			ArrayList arrayList = new ArrayList();
			if (siteName != null && siteName.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "siteName");
			}
			foreach (string replica in Utils.GetReplicaList(context, null, siteName, isDefaultNC: false, isADAM: false, isGC: true))
			{
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(replica, DirectoryContextType.DirectoryServer, context);
				arrayList.Add(new GlobalCatalog(newDirectoryContext, replica));
			}
			return new GlobalCatalogCollection(arrayList);
		}

		[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
		private DirectorySearcher InternalGetDirectorySearcher()
		{
			DirectoryEntry directoryEntry = new DirectoryEntry("GC://" + base.Name);
			if (DirectoryContext.ServerBindSupported)
			{
				directoryEntry.AuthenticationType = Utils.DefaultAuthType | AuthenticationTypes.ServerBind;
			}
			else
			{
				directoryEntry.AuthenticationType = Utils.DefaultAuthType;
			}
			directoryEntry.Username = context.UserName;
			directoryEntry.Password = context.Password;
			return new DirectorySearcher(directoryEntry);
		}
	}
	public class GlobalCatalogCollection : ReadOnlyCollectionBase
	{
		public GlobalCatalog this[int index] => (GlobalCatalog)base.InnerList[index];

		internal GlobalCatalogCollection()
		{
		}

		internal GlobalCatalogCollection(ArrayList values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(GlobalCatalog globalCatalog)
		{
			if (globalCatalog == null)
			{
				throw new ArgumentNullException("globalCatalog");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				GlobalCatalog globalCatalog2 = (GlobalCatalog)base.InnerList[i];
				if (Utils.Compare(globalCatalog2.Name, globalCatalog.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(GlobalCatalog globalCatalog)
		{
			if (globalCatalog == null)
			{
				throw new ArgumentNullException("globalCatalog");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				GlobalCatalog globalCatalog2 = (GlobalCatalog)base.InnerList[i];
				if (Utils.Compare(globalCatalog2.Name, globalCatalog.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(GlobalCatalog[] globalCatalogs, int index)
		{
			base.InnerList.CopyTo(globalCatalogs, index);
		}
	}
	internal sealed class Locator
	{
		private Locator()
		{
		}

		internal static DomainControllerInfo GetDomainControllerInfo(string computerName, string domainName, string siteName, long flags)
		{
			int num = 0;
			num = DsGetDcNameWrapper(computerName, domainName, siteName, flags, out var domainControllerInfo);
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num, domainName);
			}
			return domainControllerInfo;
		}

		internal static int DsGetDcNameWrapper(string computerName, string domainName, string siteName, long flags, out DomainControllerInfo domainControllerInfo)
		{
			IntPtr domainControllerInfo2 = IntPtr.Zero;
			int num = 0;
			if (computerName != null && computerName.Length == 0)
			{
				computerName = null;
			}
			if (siteName != null && siteName.Length == 0)
			{
				siteName = null;
			}
			num = NativeMethods.DsGetDcName(computerName, domainName, IntPtr.Zero, siteName, (int)(flags | 0x40000000), out domainControllerInfo2);
			if (num == 0)
			{
				try
				{
					domainControllerInfo = new DomainControllerInfo();
					Marshal.PtrToStructure(domainControllerInfo2, domainControllerInfo);
				}
				finally
				{
					if (domainControllerInfo2 != IntPtr.Zero)
					{
						num = NativeMethods.NetApiBufferFree(domainControllerInfo2);
					}
				}
			}
			else
			{
				domainControllerInfo = new DomainControllerInfo();
			}
			return num;
		}

		internal static ArrayList EnumerateDomainControllers(DirectoryContext context, string domainName, string siteName, long dcFlags)
		{
			Hashtable hashtable = null;
			ArrayList arrayList = new ArrayList();
			if (siteName == null)
			{
				DomainControllerInfo domainControllerInfo;
				int num = DsGetDcNameWrapper(null, domainName, null, dcFlags & 0x9040, out domainControllerInfo);
				switch (num)
				{
				case 0:
					break;
				case 1355:
					return arrayList;
				default:
					throw ExceptionHelper.GetExceptionFromErrorCode(num);
				}
				siteName = domainControllerInfo.ClientSiteName;
			}
			if (DirectoryContext.DnsgetdcSupported)
			{
				hashtable = DnsGetDcWrapper(domainName, siteName, dcFlags);
			}
			else
			{
				hashtable = DnsQueryWrapper(domainName, null, dcFlags);
				if (siteName != null)
				{
					foreach (string key in DnsQueryWrapper(domainName, siteName, dcFlags).Keys)
					{
						if (!hashtable.Contains(key))
						{
							hashtable.Add(key, null);
						}
					}
				}
			}
			foreach (string key2 in hashtable.Keys)
			{
				DirectoryContext newDirectoryContext = Utils.GetNewDirectoryContext(key2, DirectoryContextType.DirectoryServer, context);
				if ((dcFlags & 0x40) != 0)
				{
					arrayList.Add(new GlobalCatalog(newDirectoryContext, key2));
				}
				else
				{
					arrayList.Add(new DomainController(newDirectoryContext, key2));
				}
			}
			return arrayList;
		}

		private static Hashtable DnsGetDcWrapper(string domainName, string siteName, long dcFlags)
		{
			Hashtable hashtable = new Hashtable();
			int optionFlags = 0;
			IntPtr retGetDcContext = IntPtr.Zero;
			IntPtr dnsHostName = IntPtr.Zero;
			int value = 0;
			IntPtr sockAddressCount = new IntPtr(value);
			IntPtr sockAdresses = IntPtr.Zero;
			string text = null;
			int num = 0;
			num = NativeMethods.DsGetDcOpen(domainName, optionFlags, siteName, IntPtr.Zero, null, (int)dcFlags, out retGetDcContext);
			if (num == 0)
			{
				try
				{
					num = NativeMethods.DsGetDcNext(retGetDcContext, ref sockAddressCount, out sockAdresses, out dnsHostName);
					if (num != 0 && num != 1101 && num != 9003 && num != 259)
					{
						throw ExceptionHelper.GetExceptionFromErrorCode(num);
					}
					while (num != 259)
					{
						if (num != 1101 && num != 9003)
						{
							try
							{
								text = Marshal.PtrToStringUni(dnsHostName);
								string key = text.ToLower(CultureInfo.InvariantCulture);
								if (!hashtable.Contains(key))
								{
									hashtable.Add(key, null);
								}
							}
							finally
							{
								if (dnsHostName != IntPtr.Zero)
								{
									num = NativeMethods.NetApiBufferFree(dnsHostName);
								}
							}
						}
						num = NativeMethods.DsGetDcNext(retGetDcContext, ref sockAddressCount, out sockAdresses, out dnsHostName);
						if (num != 0 && num != 1101 && num != 9003 && num != 259)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(num);
						}
					}
					return hashtable;
				}
				finally
				{
					NativeMethods.DsGetDcClose(retGetDcContext);
				}
			}
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			}
			return hashtable;
		}

		private static Hashtable DnsQueryWrapper(string domainName, string siteName, long dcFlags)
		{
			Hashtable hashtable = new Hashtable();
			string text = "_ldap._tcp.";
			int num = 0;
			int num2 = 0;
			IntPtr dnsResultList = IntPtr.Zero;
			if (siteName != null && siteName.Length != 0)
			{
				text = text + siteName + "._sites.";
			}
			if ((dcFlags & 0x40) != 0)
			{
				text += "gc._msdcs.";
			}
			else if ((dcFlags & 0x1000) != 0)
			{
				text += "dc._msdcs.";
			}
			text += domainName;
			if ((dcFlags & 1) != 0)
			{
				num2 |= 8;
			}
			num = NativeMethods.DnsQuery(text, 33, num2, IntPtr.Zero, out dnsResultList, IntPtr.Zero);
			if (num == 0)
			{
				try
				{
					IntPtr intPtr = dnsResultList;
					while (intPtr != IntPtr.Zero)
					{
						PartialDnsRecord partialDnsRecord = new PartialDnsRecord();
						Marshal.PtrToStructure(intPtr, partialDnsRecord);
						if (partialDnsRecord.type == 33)
						{
							DnsRecord dnsRecord = new DnsRecord();
							Marshal.PtrToStructure(intPtr, dnsRecord);
							string targetName = dnsRecord.data.targetName;
							string key = targetName.ToLower(CultureInfo.InvariantCulture);
							if (!hashtable.Contains(key))
							{
								hashtable.Add(key, null);
							}
						}
						intPtr = partialDnsRecord.next;
					}
					return hashtable;
				}
				finally
				{
					if (dnsResultList != IntPtr.Zero)
					{
						NativeMethods.DnsRecordListFree(dnsResultList, dnsFreeType: true);
					}
				}
			}
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			}
			return hashtable;
		}
	}
	[Flags]
	public enum LocatorOptions : long
	{
		ForceRediscovery = 1L,
		KdcRequired = 0x400L,
		TimeServerRequired = 0x800L,
		WriteableRequired = 0x1000L,
		AvoidSelf = 0x4000L
	}
	[Flags]
	internal enum PrivateLocatorFlags : long
	{
		DirectoryServicesRequired = 0x10L,
		DirectoryServicesPreferred = 0x20L,
		GCRequired = 0x40L,
		PdcRequired = 0x80L,
		BackgroundOnly = 0x100L,
		IPRequired = 0x200L,
		DSWriteableRequired = 0x1000L,
		GoodTimeServerPreferred = 0x2000L,
		OnlyLDAPNeeded = 0x8000L,
		IsFlatName = 0x10000L,
		IsDNSName = 0x20000L,
		ReturnDNSName = 0x40000000L,
		ReturnFlatName = 0x80000000L
	}
	[Flags]
	internal enum DcEnumFlag
	{
		OnlyDoSiteName = 1,
		NotifyAfterSiteRecords = 2
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class DomainControllerInfo
	{
		public string DomainControllerName;

		public string DomainControllerAddress;

		public int DomainControllerAddressType;

		public Guid DomainGuid;

		public string DomainName;

		public string DnsForestName;

		public int Flags;

		public string DcSiteName;

		public string ClientSiteName;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class DsDomainControllerInfo2
	{
		public string netBiosName;

		public string dnsHostName;

		public string siteName;

		public string siteObjectName;

		public string computerObjectName;

		public string serverObjectName;

		public string ntdsaObjectName;

		public bool isPdc;

		public bool dsEnabled;

		public bool isGC;

		public Guid siteObjectGuid;

		public Guid computerObjectGuid;

		public Guid serverObjectGuid;

		public Guid ntdsDsaObjectGuid;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class DsDomainControllerInfo3
	{
		public string netBiosName;

		public string dnsHostName;

		public string siteName;

		public string siteObjectName;

		public string computerObjectName;

		public string serverObjectName;

		public string ntdsaObjectName;

		public bool isPdc;

		public bool dsEnabled;

		public bool isGC;

		public bool isRodc;

		public Guid siteObjectGuid;

		public Guid computerObjectGuid;

		public Guid serverObjectGuid;

		public Guid ntdsDsaObjectGuid;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DsNameResult
	{
		public int itemCount;

		public IntPtr items;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class DsNameResultItem
	{
		public int status;

		public string domain;

		public string name;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class DnsRecord
	{
		public IntPtr next;

		public string name;

		public short type;

		public short dataLength;

		public int flags;

		public int ttl;

		public int reserved;

		public DnsSrvData data;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class PartialDnsRecord
	{
		public IntPtr next;

		public string name;

		public short type;

		public short dataLength;

		public int flags;

		public int ttl;

		public int reserved;

		public IntPtr data;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class DnsSrvData
	{
		public string targetName;

		public short priority;

		public short weight;

		public short port;

		public short pad;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class OSVersionInfoEx
	{
		public int osVersionInfoSize;

		public int majorVersion;

		public int minorVersion;

		public int buildNumber;

		public int platformId;

		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
		public string csdVersion;

		public short servicePackMajor;

		public short servicePackMinor;

		public short suiteMask;

		public byte productType;

		public byte reserved;

		public OSVersionInfoEx()
		{
			osVersionInfoSize = Marshal.SizeOf(this);
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LUID
	{
		public int LowPart;

		public int HighPart;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class NegotiateCallerNameRequest
	{
		public int messageType;

		public LUID logonId;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal sealed class NegotiateCallerNameResponse
	{
		public int messageType;

		public string callerName;
	}
	[ComVisible(false)]
	[SuppressUnmanagedCodeSecurity]
	internal sealed class NativeMethods
	{
		[SuppressUnmanagedCodeSecurity]
		internal delegate int DsMakePasswordCredentials([MarshalAs(UnmanagedType.LPWStr)] string user, [MarshalAs(UnmanagedType.LPWStr)] string domain, [MarshalAs(UnmanagedType.LPWStr)] string password, out IntPtr authIdentity);

		[SuppressUnmanagedCodeSecurity]
		internal delegate void DsFreePasswordCredentials([In] IntPtr authIdentity);

		[SuppressUnmanagedCodeSecurity]
		internal delegate int DsBindWithCred([MarshalAs(UnmanagedType.LPWStr)] string domainController, [MarshalAs(UnmanagedType.LPWStr)] string dnsDomainName, [In] IntPtr authIdentity, out IntPtr handle);

		[SuppressUnmanagedCodeSecurity]
		internal delegate int DsUnBind([In] ref IntPtr handle);

		[SuppressUnmanagedCodeSecurity]
		internal delegate int DsGetDomainControllerInfo([In] IntPtr handle, [MarshalAs(UnmanagedType.LPWStr)] string domainName, [In] int infoLevel, out int dcCount, out IntPtr dcInfo);

		[SuppressUnmanagedCodeSecurity]
		internal delegate void DsFreeDomainControllerInfo([In] int infoLevel, [In] int dcInfoListCount, [In] IntPtr dcInfoList);

		[SuppressUnmanagedCodeSecurity]
		internal delegate int DsListSites([In] IntPtr dsHandle, out IntPtr sites);

		[SuppressUnmanagedCodeSecurity]
		internal delegate int DsListRoles([In] IntPtr dsHandle, out IntPtr roles);

		[SuppressUnmanagedCodeSecurity]
		internal delegate int DsCrackNames([In] IntPtr hDS, [In] int flags, [In] int formatOffered, [In] int formatDesired, [In] int nameCount, [In] IntPtr names, out IntPtr results);

		internal const int VER_PLATFORM_WIN32_NT = 2;

		internal const int ERROR_INVALID_DOMAIN_NAME_FORMAT = 1212;

		internal const int ERROR_NO_SUCH_DOMAIN = 1355;

		internal const int ERROR_NOT_ENOUGH_MEMORY = 8;

		internal const int ERROR_INVALID_FLAGS = 1004;

		internal const int DS_NAME_NO_ERROR = 0;

		internal const int ERROR_NO_MORE_ITEMS = 259;

		internal const int ERROR_FILE_MARK_DETECTED = 1101;

		internal const int DNS_ERROR_RCODE_NAME_ERROR = 9003;

		internal const int ERROR_NO_SUCH_LOGON_SESSION = 1312;

		internal const int DS_NAME_FLAG_SYNTACTICAL_ONLY = 1;

		internal const int DS_FQDN_1779_NAME = 1;

		internal const int DS_CANONICAL_NAME = 7;

		internal const int DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = 6;

		internal const int STATUS_QUOTA_EXCEEDED = -1073741756;

		internal const int DsDomainControllerInfoLevel2 = 2;

		internal const int DsDomainControllerInfoLevel3 = 3;

		internal const int DsNameNoError = 0;

		internal const int DnsSrvData = 33;

		internal const int DnsQueryBypassCache = 8;

		internal const int NegGetCallerName = 1;

		private NativeMethods()
		{
		}

		[DllImport("Netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "DsGetDcNameW")]
		internal static extern int DsGetDcName([In] string computerName, [In] string domainName, [In] IntPtr domainGuid, [In] string siteName, [In] int flags, out IntPtr domainControllerInfo);

		[DllImport("Netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "DsGetDcOpenW")]
		internal static extern int DsGetDcOpen([In] string dnsName, [In] int optionFlags, [In] string siteName, [In] IntPtr domainGuid, [In] string dnsForestName, [In] int dcFlags, out IntPtr retGetDcContext);

		[DllImport("Netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "DsGetDcNextW")]
		internal static extern int DsGetDcNext([In] IntPtr getDcContextHandle, [In][Out] ref IntPtr sockAddressCount, out IntPtr sockAdresses, out IntPtr dnsHostName);

		[DllImport("Netapi32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "DsGetDcCloseW")]
		internal static extern void DsGetDcClose([In] IntPtr getDcContextHandle);

		[DllImport("Netapi32.dll")]
		internal static extern int NetApiBufferFree([In] IntPtr buffer);

		[DllImport("Kernel32.dll")]
		internal static extern int GetLastError();

		[DllImport("Dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
		internal static extern int DnsQuery([In] string recordName, [In] short recordType, [In] int options, [In] IntPtr servers, out IntPtr dnsResultList, [Out] IntPtr reserved);

		[DllImport("Dnsapi.dll", CharSet = CharSet.Unicode)]
		internal static extern void DnsRecordListFree([In] IntPtr dnsResultList, [In] bool dnsFreeType);

		[DllImport("Kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetVersionExW", SetLastError = true)]
		internal static extern bool GetVersionEx([In][Out] OSVersionInfoEx ver);

		[DllImport("Secur32.dll")]
		internal static extern int LsaConnectUntrusted(out LsaLogonProcessSafeHandle lsaHandle);

		[DllImport("Secur32.dll")]
		internal static extern int LsaCallAuthenticationPackage([In] LsaLogonProcessSafeHandle lsaHandle, [In] int authenticationPackage, [In] NegotiateCallerNameRequest protocolSubmitBuffer, [In] int submitBufferLength, out IntPtr protocolReturnBuffer, out int returnBufferLength, out int protocolStatus);

		[DllImport("Secur32.dll")]
		internal static extern uint LsaFreeReturnBuffer([In] IntPtr buffer);

		[DllImport("Secur32.dll")]
		internal static extern int LsaDeregisterLogonProcess([In] IntPtr lsaHandle);

		[DllImport("Kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CompareStringW", SetLastError = true)]
		internal static extern int CompareString([In] uint locale, [In] uint dwCmpFlags, [In] IntPtr lpString1, [In] int cchCount1, [In] IntPtr lpString2, [In] int cchCount2);
	}
	[SuppressUnmanagedCodeSecurity]
	[ComVisible(false)]
	internal sealed class NativeComInterfaces
	{
		[ComImport]
		[Guid("080d0d78-f421-11d0-a36e-00c04fb950dc")]
		internal class Pathname
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			public extern Pathname();
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		[Guid("D592AED4-F420-11D0-A36E-00C04FB950DC")]
		internal interface IAdsPathname
		{
			int EscapedMode
			{
				get; [SuppressUnmanagedCodeSecurity]
				set;
			}

			[SuppressUnmanagedCodeSecurity]
			int Set([In][MarshalAs(UnmanagedType.BStr)] string bstrADsPath, [In][MarshalAs(UnmanagedType.U4)] int lnSetType);

			int SetDisplayType([In][MarshalAs(UnmanagedType.U4)] int lnDisplayType);

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.BStr)]
			string Retrieve([In][MarshalAs(UnmanagedType.U4)] int lnFormatType);

			[return: MarshalAs(UnmanagedType.U4)]
			int GetNumElements();

			[return: MarshalAs(UnmanagedType.BStr)]
			string GetElement([In][MarshalAs(UnmanagedType.U4)] int lnElementIndex);

			void AddLeafElement([In][MarshalAs(UnmanagedType.BStr)] string bstrLeafElement);

			void RemoveLeafElement();

			[return: MarshalAs(UnmanagedType.Interface)]
			object CopyPath();

			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.BStr)]
			string GetEscapedElement([In][MarshalAs(UnmanagedType.U4)] int lnReserved, [In][MarshalAs(UnmanagedType.BStr)] string bstrInStr);
		}

		[ComImport]
		[Guid("C8F93DD3-4AE0-11CF-9E73-00AA004A5691")]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		internal interface IAdsProperty
		{
			string Name
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Class
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string GUID
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string ADsPath
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Parent
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Schema
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string OID
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			string Syntax
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			int MaxRange
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.U4)]
				get;
				[param: MarshalAs(UnmanagedType.U4)]
				set;
			}

			int MinRange
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.U4)]
				get;
				[param: MarshalAs(UnmanagedType.U4)]
				set;
			}

			bool MultiValued
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.VariantBool)]
				get;
				[param: MarshalAs(UnmanagedType.VariantBool)]
				set;
			}

			void GetInfo();

			void SetInfo();

			[return: MarshalAs(UnmanagedType.Struct)]
			object Get([In][MarshalAs(UnmanagedType.BStr)] string bstrName);

			void Put([In][MarshalAs(UnmanagedType.BStr)] string bstrName, [In][MarshalAs(UnmanagedType.Struct)] object vProp);

			[return: MarshalAs(UnmanagedType.Struct)]
			object GetEx([In][MarshalAs(UnmanagedType.BStr)] string bstrName);

			void PutEx([In][MarshalAs(UnmanagedType.U4)] int lnControlCode, [In][MarshalAs(UnmanagedType.BStr)] string bstrName, [In][MarshalAs(UnmanagedType.Struct)] object vProp);

			void GetInfoEx([In][MarshalAs(UnmanagedType.Struct)] object vProperties, [In][MarshalAs(UnmanagedType.U4)] int lnReserved);

			object Qualifiers();
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsDual)]
		[Guid("C8F93DD0-4AE0-11CF-9E73-00AA004A5691")]
		internal interface IAdsClass
		{
			string Name
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Class
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string GUID
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string ADsPath
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Parent
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string Schema
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string PrimaryInterface
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
			}

			string CLSID
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			string OID
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			bool Abstract
			{
				[return: MarshalAs(UnmanagedType.VariantBool)]
				get;
				[param: MarshalAs(UnmanagedType.VariantBool)]
				set;
			}

			bool Auxiliary
			{
				[return: MarshalAs(UnmanagedType.VariantBool)]
				get;
				[param: MarshalAs(UnmanagedType.VariantBool)]
				set;
			}

			object MandatoryProperties
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object OptionalProperties
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object NamingProperties
			{
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object DerivedFrom
			{
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object AuxDerivedFrom
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object PossibleSuperiors
			{
				[SuppressUnmanagedCodeSecurity]
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			object Containment
			{
				[return: MarshalAs(UnmanagedType.Struct)]
				get;
				[param: MarshalAs(UnmanagedType.Struct)]
				set;
			}

			bool Container
			{
				[return: MarshalAs(UnmanagedType.VariantBool)]
				get;
				[param: MarshalAs(UnmanagedType.VariantBool)]
				set;
			}

			string HelpFileName
			{
				[return: MarshalAs(UnmanagedType.BStr)]
				get;
				[param: MarshalAs(UnmanagedType.BStr)]
				set;
			}

			int HelpFileContext
			{
				[return: MarshalAs(UnmanagedType.U4)]
				get;
				[param: MarshalAs(UnmanagedType.U4)]
				set;
			}

			void GetInfo();

			void SetInfo();

			[return: MarshalAs(UnmanagedType.Struct)]
			object Get([In][MarshalAs(UnmanagedType.BStr)] string bstrName);

			void Put([In][MarshalAs(UnmanagedType.BStr)] string bstrName, [In][MarshalAs(UnmanagedType.Struct)] object vProp);

			[return: MarshalAs(UnmanagedType.Struct)]
			object GetEx([In][MarshalAs(UnmanagedType.BStr)] string bstrName);

			void PutEx([In][MarshalAs(UnmanagedType.U4)] int lnControlCode, [In][MarshalAs(UnmanagedType.BStr)] string bstrName, [In][MarshalAs(UnmanagedType.Struct)] object vProp);

			void GetInfoEx([In][MarshalAs(UnmanagedType.Struct)] object vProperties, [In][MarshalAs(UnmanagedType.U4)] int lnReserved);

			[return: MarshalAs(UnmanagedType.Interface)]
			object Qualifiers();
		}

		internal const int ADS_SETTYPE_DN = 4;

		internal const int ADS_FORMAT_X500_DN = 7;

		internal const int ADS_ESCAPEDMODE_ON = 2;

		internal const int ADS_ESCAPEDMODE_OFF_EX = 4;

		internal const int ADS_FORMAT_LEAF = 11;
	}
	internal class PropertyManager
	{
		public static string DefaultNamingContext = "defaultNamingContext";

		public static string SchemaNamingContext = "schemaNamingContext";

		public static string ConfigurationNamingContext = "configurationNamingContext";

		public static string RootDomainNamingContext = "rootDomainNamingContext";

		public static string MsDSBehaviorVersion = "msDS-Behavior-Version";

		public static string FsmoRoleOwner = "fsmoRoleOwner";

		public static string ForestFunctionality = "forestFunctionality";

		public static string NTMixedDomain = "ntMixedDomain";

		public static string DomainFunctionality = "domainFunctionality";

		public static string ObjectCategory = "objectCategory";

		public static string SystemFlags = "systemFlags";

		public static string DnsRoot = "dnsRoot";

		public static string DistinguishedName = "distinguishedName";

		public static string TrustParent = "trustParent";

		public static string FlatName = "flatName";

		public static string Name = "name";

		public static string Flags = "flags";

		public static string TrustType = "trustType";

		public static string TrustAttributes = "trustAttributes";

		public static string BecomeSchemaMaster = "becomeSchemaMaster";

		public static string BecomeDomainMaster = "becomeDomainMaster";

		public static string BecomePdc = "becomePdc";

		public static string BecomeRidMaster = "becomeRidMaster";

		public static string BecomeInfrastructureMaster = "becomeInfrastructureMaster";

		public static string DnsHostName = "dnsHostName";

		public static string Options = "options";

		public static string CurrentTime = "currentTime";

		public static string HighestCommittedUSN = "highestCommittedUSN";

		public static string OperatingSystem = "operatingSystem";

		public static string HasMasterNCs = "hasMasterNCs";

		public static string MsDSHasMasterNCs = "msDS-HasMasterNCs";

		public static string MsDSHasFullReplicaNCs = "msDS-hasFullReplicaNCs";

		public static string NCName = "nCName";

		public static string Cn = "cn";

		public static string NETBIOSName = "nETBIOSName";

		public static string DomainDNS = "domainDNS";

		public static string InstanceType = "instanceType";

		public static string MsDSSDReferenceDomain = "msDS-SDReferenceDomain";

		public static string MsDSPortLDAP = "msDS-PortLDAP";

		public static string MsDSPortSSL = "msDS-PortSSL";

		public static string MsDSNCReplicaLocations = "msDS-NC-Replica-Locations";

		public static string MsDSNCROReplicaLocations = "msDS-NC-RO-Replica-Locations";

		public static string SupportedCapabilities = "supportedCapabilities";

		public static string ServerName = "serverName";

		public static string Enabled = "Enabled";

		public static string ObjectGuid = "objectGuid";

		public static string Keywords = "keywords";

		public static string ServiceBindingInformation = "serviceBindingInformation";

		public static string MsDSReplAuthenticationMode = "msDS-ReplAuthenticationMode";

		public static string HasPartialReplicaNCs = "hasPartialReplicaNCs";

		public static string Container = "container";

		public static string LdapDisplayName = "ldapDisplayName";

		public static string AttributeID = "attributeID";

		public static string AttributeSyntax = "attributeSyntax";

		public static string Description = "description";

		public static string SearchFlags = "searchFlags";

		public static string OMSyntax = "oMSyntax";

		public static string OMObjectClass = "oMObjectClass";

		public static string IsSingleValued = "isSingleValued";

		public static string IsDefunct = "isDefunct";

		public static string RangeUpper = "rangeUpper";

		public static string RangeLower = "rangeLower";

		public static string IsMemberOfPartialAttributeSet = "isMemberOfPartialAttributeSet";

		public static string ObjectVersion = "objectVersion";

		public static string LinkID = "linkID";

		public static string ObjectClassCategory = "objectClassCategory";

		public static string SchemaUpdateNow = "schemaUpdateNow";

		public static string SubClassOf = "subClassOf";

		public static string SchemaIDGuid = "schemaIDGUID";

		public static string PossibleSuperiors = "possSuperiors";

		public static string PossibleInferiors = "possibleInferiors";

		public static string MustContain = "mustContain";

		public static string MayContain = "mayContain";

		public static string SystemMustContain = "systemMustContain";

		public static string SystemMayContain = "systemMayContain";

		public static string GovernsID = "governsID";

		public static string IsGlobalCatalogReady = "isGlobalCatalogReady";

		public static string NTSecurityDescriptor = "ntSecurityDescriptor";

		public static string DsServiceName = "dsServiceName";

		public static string ReplicateSingleObject = "replicateSingleObject";

		public static string MsDSMasteredBy = "msDS-masteredBy";

		public static string DefaultSecurityDescriptor = "defaultSecurityDescriptor";

		public static string NamingContexts = "namingContexts";

		public static string MsDSDefaultNamingContext = "msDS-DefaultNamingContext";

		public static string OperatingSystemVersion = "operatingSystemVersion";

		public static string AuxiliaryClass = "auxiliaryClass";

		public static string SystemAuxiliaryClass = "systemAuxiliaryClass";

		public static string SystemPossibleSuperiors = "systemPossSuperiors";

		public static string InterSiteTopologyGenerator = "interSiteTopologyGenerator";

		public static string FromServer = "fromServer";

		public static string SiteList = "siteList";

		public static string MsDSHasInstantiatedNCs = "msDS-HasInstantiatedNCs";

		public static object GetPropertyValue(DirectoryEntry directoryEntry, string propertyName)
		{
			return GetPropertyValue(null, directoryEntry, propertyName);
		}

		public static object GetPropertyValue(DirectoryContext context, DirectoryEntry directoryEntry, string propertyName)
		{
			try
			{
				if (directoryEntry.Properties[propertyName].Count == 0)
				{
					if (directoryEntry.Properties[DistinguishedName].Count != 0)
					{
						throw new ActiveDirectoryOperationException(Res.GetString("PropertyNotFoundOnObject", propertyName, directoryEntry.Properties[DistinguishedName].Value));
					}
					throw new ActiveDirectoryOperationException(Res.GetString("PropertyNotFound", propertyName));
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			return directoryEntry.Properties[propertyName].Value;
		}

		public static object GetSearchResultPropertyValue(SearchResult res, string propertyName)
		{
			ResultPropertyValueCollection resultPropertyValueCollection = null;
			try
			{
				resultPropertyValueCollection = res.Properties[propertyName];
				if (resultPropertyValueCollection == null || resultPropertyValueCollection.Count < 1)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("PropertyNotFound", propertyName));
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(e);
			}
			return resultPropertyValueCollection[0];
		}
	}
	public class ReadOnlyActiveDirectorySchemaClassCollection : ReadOnlyCollectionBase
	{
		public ActiveDirectorySchemaClass this[int index] => (ActiveDirectorySchemaClass)base.InnerList[index];

		internal ReadOnlyActiveDirectorySchemaClassCollection()
		{
		}

		internal ReadOnlyActiveDirectorySchemaClassCollection(ICollection values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(ActiveDirectorySchemaClass schemaClass)
		{
			if (schemaClass == null)
			{
				throw new ArgumentNullException("schemaClass");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaClass activeDirectorySchemaClass = (ActiveDirectorySchemaClass)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaClass.Name, schemaClass.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ActiveDirectorySchemaClass schemaClass)
		{
			if (schemaClass == null)
			{
				throw new ArgumentNullException("schemaClass");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaClass activeDirectorySchemaClass = (ActiveDirectorySchemaClass)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaClass.Name, schemaClass.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ActiveDirectorySchemaClass[] classes, int index)
		{
			base.InnerList.CopyTo(classes, index);
		}
	}
	public class ReadOnlyActiveDirectorySchemaPropertyCollection : ReadOnlyCollectionBase
	{
		public ActiveDirectorySchemaProperty this[int index] => (ActiveDirectorySchemaProperty)base.InnerList[index];

		internal ReadOnlyActiveDirectorySchemaPropertyCollection()
		{
		}

		internal ReadOnlyActiveDirectorySchemaPropertyCollection(ArrayList values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(ActiveDirectorySchemaProperty schemaProperty)
		{
			if (schemaProperty == null)
			{
				throw new ArgumentNullException("schemaProperty");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaProperty activeDirectorySchemaProperty = (ActiveDirectorySchemaProperty)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaProperty.Name, schemaProperty.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ActiveDirectorySchemaProperty schemaProperty)
		{
			if (schemaProperty == null)
			{
				throw new ArgumentNullException("schemaProperty");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySchemaProperty activeDirectorySchemaProperty = (ActiveDirectorySchemaProperty)base.InnerList[i];
				if (Utils.Compare(activeDirectorySchemaProperty.Name, schemaProperty.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ActiveDirectorySchemaProperty[] properties, int index)
		{
			base.InnerList.CopyTo(properties, index);
		}
	}
	public class ReadOnlyDirectoryServerCollection : ReadOnlyCollectionBase
	{
		public DirectoryServer this[int index] => (DirectoryServer)base.InnerList[index];

		internal ReadOnlyDirectoryServerCollection()
		{
		}

		internal ReadOnlyDirectoryServerCollection(ArrayList values)
		{
			if (values != null)
			{
				for (int i = 0; i < values.Count; i++)
				{
					Add((DirectoryServer)values[i]);
				}
			}
		}

		public bool Contains(DirectoryServer directoryServer)
		{
			if (directoryServer == null)
			{
				throw new ArgumentNullException("directoryServer");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DirectoryServer directoryServer2 = (DirectoryServer)base.InnerList[i];
				if (Utils.Compare(directoryServer2.Name, directoryServer.Name) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(DirectoryServer directoryServer)
		{
			if (directoryServer == null)
			{
				throw new ArgumentNullException("directoryServer");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				DirectoryServer directoryServer2 = (DirectoryServer)base.InnerList[i];
				if (Utils.Compare(directoryServer2.Name, directoryServer.Name) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(DirectoryServer[] directoryServers, int index)
		{
			base.InnerList.CopyTo(directoryServers, index);
		}

		internal int Add(DirectoryServer server)
		{
			return base.InnerList.Add(server);
		}

		internal void AddRange(ICollection servers)
		{
			base.InnerList.AddRange(servers);
		}

		internal void Clear()
		{
			base.InnerList.Clear();
		}
	}
	public class ReadOnlySiteCollection : ReadOnlyCollectionBase
	{
		public ActiveDirectorySite this[int index] => (ActiveDirectorySite)base.InnerList[index];

		internal ReadOnlySiteCollection()
		{
		}

		internal ReadOnlySiteCollection(ArrayList sites)
		{
			for (int i = 0; i < sites.Count; i++)
			{
				Add((ActiveDirectorySite)sites[i]);
			}
		}

		public bool Contains(ActiveDirectorySite site)
		{
			if (site == null)
			{
				throw new ArgumentNullException("site");
			}
			string s = (string)PropertyManager.GetPropertyValue(site.context, site.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ActiveDirectorySite site)
		{
			if (site == null)
			{
				throw new ArgumentNullException("site");
			}
			string s = (string)PropertyManager.GetPropertyValue(site.context, site.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySite activeDirectorySite = (ActiveDirectorySite)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySite.context, activeDirectorySite.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ActiveDirectorySite[] sites, int index)
		{
			base.InnerList.CopyTo(sites, index);
		}

		internal int Add(ActiveDirectorySite site)
		{
			return base.InnerList.Add(site);
		}

		internal void Clear()
		{
			base.InnerList.Clear();
		}
	}
	public class ReadOnlySiteLinkBridgeCollection : ReadOnlyCollectionBase
	{
		public ActiveDirectorySiteLinkBridge this[int index] => (ActiveDirectorySiteLinkBridge)base.InnerList[index];

		internal ReadOnlySiteLinkBridgeCollection()
		{
		}

		public bool Contains(ActiveDirectorySiteLinkBridge bridge)
		{
			if (bridge == null)
			{
				throw new ArgumentNullException("bridge");
			}
			string s = (string)PropertyManager.GetPropertyValue(bridge.context, bridge.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySiteLinkBridge activeDirectorySiteLinkBridge = (ActiveDirectorySiteLinkBridge)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLinkBridge.context, activeDirectorySiteLinkBridge.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ActiveDirectorySiteLinkBridge bridge)
		{
			if (bridge == null)
			{
				throw new ArgumentNullException("bridge");
			}
			string s = (string)PropertyManager.GetPropertyValue(bridge.context, bridge.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySiteLinkBridge activeDirectorySiteLinkBridge = (ActiveDirectorySiteLinkBridge)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLinkBridge.context, activeDirectorySiteLinkBridge.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ActiveDirectorySiteLinkBridge[] bridges, int index)
		{
			base.InnerList.CopyTo(bridges, index);
		}

		internal int Add(ActiveDirectorySiteLinkBridge bridge)
		{
			return base.InnerList.Add(bridge);
		}

		internal void Clear()
		{
			base.InnerList.Clear();
		}
	}
	public class ReadOnlySiteLinkCollection : ReadOnlyCollectionBase
	{
		public ActiveDirectorySiteLink this[int index] => (ActiveDirectorySiteLink)base.InnerList[index];

		internal ReadOnlySiteLinkCollection()
		{
		}

		public bool Contains(ActiveDirectorySiteLink link)
		{
			if (link == null)
			{
				throw new ArgumentNullException("link");
			}
			string s = (string)PropertyManager.GetPropertyValue(link.context, link.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ActiveDirectorySiteLink link)
		{
			if (link == null)
			{
				throw new ArgumentNullException("link");
			}
			string s = (string)PropertyManager.GetPropertyValue(link.context, link.cachedEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ActiveDirectorySiteLink activeDirectorySiteLink = (ActiveDirectorySiteLink)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(activeDirectorySiteLink.context, activeDirectorySiteLink.cachedEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ActiveDirectorySiteLink[] links, int index)
		{
			base.InnerList.CopyTo(links, index);
		}

		internal int Add(ActiveDirectorySiteLink link)
		{
			return base.InnerList.Add(link);
		}

		internal void Clear()
		{
			base.InnerList.Clear();
		}
	}
	public class ReadOnlyStringCollection : ReadOnlyCollectionBase
	{
		public string this[int index]
		{
			get
			{
				object obj = base.InnerList[index];
				if (obj is Exception)
				{
					throw (Exception)obj;
				}
				return (string)obj;
			}
		}

		internal ReadOnlyStringCollection()
		{
		}

		internal ReadOnlyStringCollection(ArrayList values)
		{
			if (values == null)
			{
				values = new ArrayList();
			}
			base.InnerList.AddRange(values);
		}

		public bool Contains(string value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				string s = (string)base.InnerList[i];
				if (Utils.Compare(s, value) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(string value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				string s = (string)base.InnerList[i];
				if (Utils.Compare(s, value) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(string[] values, int index)
		{
			base.InnerList.CopyTo(values, index);
		}

		internal void Add(string value)
		{
			base.InnerList.Add(value);
		}
	}
	public enum NotificationStatus
	{
		NoNotification,
		IntraSiteOnly,
		NotificationAlways
	}
	public enum ReplicationSpan
	{
		IntraSite,
		InterSite
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ReplicationConnection : IDisposable
	{
		private const string ADAMGuid = "1.2.840.113556.1.4.1851";

		internal DirectoryContext context;

		internal DirectoryEntry cachedDirectoryEntry;

		internal bool existingConnection;

		private bool disposed;

		private bool checkADAM;

		private bool isADAMServer;

		private int options;

		private string connectionName;

		private string sourceServerName;

		private string destinationServerName;

		private ActiveDirectoryTransportType transport;

		public string Name
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return connectionName;
			}
		}

		public string SourceServer
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (sourceServerName == null)
				{
					string dn = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.FromServer);
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
					if (IsADAM)
					{
						int num = (int)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.MsDSPortLDAP);
						string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry.Parent, PropertyManager.DnsHostName);
						if (num != 389)
						{
							sourceServerName = text + ":" + num;
						}
					}
					else
					{
						sourceServerName = (string)PropertyManager.GetPropertyValue(context, directoryEntry.Parent, PropertyManager.DnsHostName);
					}
				}
				return sourceServerName;
			}
		}

		public string DestinationServer
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (destinationServerName == null)
				{
					DirectoryEntry directoryEntry = null;
					DirectoryEntry directoryEntry2 = null;
					try
					{
						directoryEntry = cachedDirectoryEntry.Parent;
						directoryEntry2 = directoryEntry.Parent;
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry2, PropertyManager.DnsHostName);
					if (IsADAM)
					{
						int num = (int)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.MsDSPortLDAP);
						if (num != 389)
						{
							destinationServerName = text + ":" + num;
						}
						else
						{
							destinationServerName = text;
						}
					}
					else
					{
						destinationServerName = text;
					}
				}
				return destinationServerName;
			}
		}

		public bool Enabled
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (cachedDirectoryEntry.Properties.Contains("enabledConnection"))
					{
						return (bool)cachedDirectoryEntry.Properties["enabledConnection"][0];
					}
					return false;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					cachedDirectoryEntry.Properties["enabledConnection"].Value = value;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public ActiveDirectoryTransportType TransportType
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (existingConnection)
				{
					PropertyValueCollection propertyValueCollection = null;
					try
					{
						propertyValueCollection = cachedDirectoryEntry.Properties["transportType"];
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					if (propertyValueCollection.Count == 0)
					{
						return ActiveDirectoryTransportType.Rpc;
					}
					return Utils.GetTransportTypeFromDN((string)propertyValueCollection[0]);
				}
				return transport;
			}
		}

		public bool GeneratedByKcc
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedDirectoryEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count == 0)
				{
					options = 0;
				}
				else
				{
					options = (int)propertyValueCollection[0];
				}
				if ((options & 1) == 0)
				{
					return false;
				}
				return true;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					PropertyValueCollection propertyValueCollection = cachedDirectoryEntry.Properties["options"];
					if (propertyValueCollection.Count == 0)
					{
						options = 0;
					}
					else
					{
						options = (int)propertyValueCollection[0];
					}
					if (value)
					{
						options |= 1;
					}
					else
					{
						options &= -2;
					}
					cachedDirectoryEntry.Properties["options"].Value = options;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public bool ReciprocalReplicationEnabled
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedDirectoryEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count == 0)
				{
					options = 0;
				}
				else
				{
					options = (int)propertyValueCollection[0];
				}
				if ((options & 2) == 0)
				{
					return false;
				}
				return true;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					PropertyValueCollection propertyValueCollection = cachedDirectoryEntry.Properties["options"];
					if (propertyValueCollection.Count == 0)
					{
						options = 0;
					}
					else
					{
						options = (int)propertyValueCollection[0];
					}
					if (value)
					{
						options |= 2;
					}
					else
					{
						options &= -3;
					}
					cachedDirectoryEntry.Properties["options"].Value = options;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public NotificationStatus ChangeNotificationStatus
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedDirectoryEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count == 0)
				{
					options = 0;
				}
				else
				{
					options = (int)propertyValueCollection[0];
				}
				int num = options & 4;
				int num2 = options & 8;
				if (num == 4 && num2 == 0)
				{
					return NotificationStatus.NoNotification;
				}
				if (num == 4 && num2 == 8)
				{
					return NotificationStatus.NotificationAlways;
				}
				return NotificationStatus.IntraSiteOnly;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (value < NotificationStatus.NoNotification || value > NotificationStatus.NotificationAlways)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(NotificationStatus));
				}
				try
				{
					PropertyValueCollection propertyValueCollection = cachedDirectoryEntry.Properties["options"];
					if (propertyValueCollection.Count == 0)
					{
						options = 0;
					}
					else
					{
						options = (int)propertyValueCollection[0];
					}
					switch (value)
					{
					case NotificationStatus.IntraSiteOnly:
						options &= -5;
						options &= -9;
						break;
					case NotificationStatus.NoNotification:
						options |= 4;
						options &= -9;
						break;
					default:
						options |= 4;
						options |= 8;
						break;
					}
					cachedDirectoryEntry.Properties["options"].Value = options;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public bool DataCompressionEnabled
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedDirectoryEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count == 0)
				{
					options = 0;
				}
				else
				{
					options = (int)propertyValueCollection[0];
				}
				if ((options & 0x10) == 0)
				{
					return true;
				}
				return false;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					PropertyValueCollection propertyValueCollection = cachedDirectoryEntry.Properties["options"];
					if (propertyValueCollection.Count == 0)
					{
						options = 0;
					}
					else
					{
						options = (int)propertyValueCollection[0];
					}
					if (!value)
					{
						options |= 16;
					}
					else
					{
						options &= -17;
					}
					cachedDirectoryEntry.Properties["options"].Value = options;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public bool ReplicationScheduleOwnedByUser
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				PropertyValueCollection propertyValueCollection = null;
				try
				{
					propertyValueCollection = cachedDirectoryEntry.Properties["options"];
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (propertyValueCollection.Count == 0)
				{
					options = 0;
				}
				else
				{
					options = (int)propertyValueCollection[0];
				}
				if ((options & 0x20) == 0)
				{
					return false;
				}
				return true;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					PropertyValueCollection propertyValueCollection = cachedDirectoryEntry.Properties["options"];
					if (propertyValueCollection.Count == 0)
					{
						options = 0;
					}
					else
					{
						options = (int)propertyValueCollection[0];
					}
					if (value)
					{
						options |= 32;
					}
					else
					{
						options &= -33;
					}
					cachedDirectoryEntry.Properties["options"].Value = options;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public ReplicationSpan ReplicationSpan
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				string distinguishedName = (string)PropertyManager.GetPropertyValue(context, cachedDirectoryEntry, PropertyManager.FromServer);
				string value = Utils.GetDNComponents(distinguishedName)[3].Value;
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string distinguishedName2 = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ServerName);
				string value2 = Utils.GetDNComponents(distinguishedName2)[2].Value;
				if (Utils.Compare(value, value2) == 0)
				{
					return ReplicationSpan.IntraSite;
				}
				return ReplicationSpan.InterSite;
			}
		}

		public ActiveDirectorySchedule ReplicationSchedule
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				ActiveDirectorySchedule activeDirectorySchedule = null;
				bool flag = false;
				try
				{
					flag = cachedDirectoryEntry.Properties.Contains("schedule");
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (flag)
				{
					byte[] unmanagedSchedule = (byte[])cachedDirectoryEntry.Properties["schedule"][0];
					activeDirectorySchedule = new ActiveDirectorySchedule();
					activeDirectorySchedule.SetUnmanagedSchedule(unmanagedSchedule);
				}
				return activeDirectorySchedule;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				try
				{
					if (value == null)
					{
						if (cachedDirectoryEntry.Properties.Contains("schedule"))
						{
							cachedDirectoryEntry.Properties["schedule"].Clear();
						}
					}
					else
					{
						cachedDirectoryEntry.Properties["schedule"].Value = value.GetUnmanagedSchedule();
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		private bool IsADAM
		{
			get
			{
				if (!checkADAM)
				{
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					PropertyValueCollection propertyValueCollection = null;
					try
					{
						propertyValueCollection = directoryEntry.Properties["supportedCapabilities"];
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					if (propertyValueCollection.Contains("1.2.840.113556.1.4.1851"))
					{
						isADAMServer = true;
					}
				}
				return isADAMServer;
			}
		}

		public static ReplicationConnection FindByName(DirectoryContext context, string name)
		{
			ValidateArgument(context, name);
			context = new DirectoryContext(context);
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			try
			{
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ServerName);
				string dn = "CN=NTDS Settings," + text;
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
				ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=nTDSConnection)(objectCategory=NTDSConnection)(name=" + Utils.GetEscapedFilterValue(name) + "))", new string[1] { "distinguishedName" }, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
				SearchResult searchResult = null;
				try
				{
					searchResult = aDSearcher.FindOne();
				}
				catch (COMException ex)
				{
					if (ex.ErrorCode == -2147016656)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ReplicationConnection), name);
					}
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
				}
				if (searchResult == null)
				{
					Exception ex2 = new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"), typeof(ReplicationConnection), name);
					throw ex2;
				}
				DirectoryEntry directoryEntry2 = searchResult.GetDirectoryEntry();
				return new ReplicationConnection(context, directoryEntry2, name);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		internal ReplicationConnection(DirectoryContext context, DirectoryEntry connectionEntry, string name)
		{
			this.context = context;
			cachedDirectoryEntry = connectionEntry;
			connectionName = name;
			existingConnection = true;
		}

		public ReplicationConnection(DirectoryContext context, string name, DirectoryServer sourceServer)
			: this(context, name, sourceServer, null, ActiveDirectoryTransportType.Rpc)
		{
		}

		public ReplicationConnection(DirectoryContext context, string name, DirectoryServer sourceServer, ActiveDirectorySchedule schedule)
			: this(context, name, sourceServer, schedule, ActiveDirectoryTransportType.Rpc)
		{
		}

		public ReplicationConnection(DirectoryContext context, string name, DirectoryServer sourceServer, ActiveDirectoryTransportType transport)
			: this(context, name, sourceServer, null, transport)
		{
		}

		public ReplicationConnection(DirectoryContext context, string name, DirectoryServer sourceServer, ActiveDirectorySchedule schedule, ActiveDirectoryTransportType transport)
		{
			ValidateArgument(context, name);
			if (sourceServer == null)
			{
				throw new ArgumentNullException("sourceServer");
			}
			if (transport < ActiveDirectoryTransportType.Rpc || transport > ActiveDirectoryTransportType.Smtp)
			{
				throw new InvalidEnumArgumentException("value", (int)transport, typeof(ActiveDirectoryTransportType));
			}
			context = new DirectoryContext(context);
			ValidateTargetAndSourceServer(context, sourceServer);
			this.context = context;
			connectionName = name;
			this.transport = transport;
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			try
			{
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ServerName);
				string dn = "CN=NTDS Settings," + text;
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn);
				string originalPath = "cn=" + connectionName;
				originalPath = Utils.GetEscapedPath(originalPath);
				cachedDirectoryEntry = directoryEntry.Children.Add(originalPath, "nTDSConnection");
				DirectoryContext directoryContext = sourceServer.Context;
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(directoryContext, WellKnownDN.RootDSE);
				string text2 = (string)PropertyManager.GetPropertyValue(directoryContext, directoryEntry, PropertyManager.ServerName);
				text2 = "CN=NTDS Settings," + text2;
				cachedDirectoryEntry.Properties["fromServer"].Add(text2);
				if (schedule != null)
				{
					cachedDirectoryEntry.Properties["schedule"].Value = schedule.GetUnmanagedSchedule();
				}
				string dNFromTransportType = Utils.GetDNFromTransportType(TransportType, context);
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dNFromTransportType);
				try
				{
					directoryEntry.Bind(throwIfFail: true);
				}
				catch (COMException ex)
				{
					if (ex.ErrorCode == -2147016656)
					{
						DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
						if (Utils.CheckCapability(directoryEntry2, Capability.ActiveDirectoryApplicationMode) && transport == ActiveDirectoryTransportType.Smtp)
						{
							throw new NotSupportedException(Res.GetString("NotSupportTransportSMTP"));
						}
					}
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex);
				}
				cachedDirectoryEntry.Properties["transportType"].Add(dNFromTransportType);
				cachedDirectoryEntry.Properties["enabledConnection"].Value = false;
				cachedDirectoryEntry.Properties["options"].Value = 0;
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry.Close();
			}
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (!disposed)
			{
				if (disposing && cachedDirectoryEntry != null)
				{
					cachedDirectoryEntry.Dispose();
				}
				disposed = true;
			}
		}

		~ReplicationConnection()
		{
			Dispose(disposing: false);
		}

		public void Delete()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existingConnection)
			{
				throw new InvalidOperationException(Res.GetString("CannotDelete"));
			}
			try
			{
				cachedDirectoryEntry.Parent.Children.Remove(cachedDirectoryEntry);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public void Save()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				cachedDirectoryEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			if (!existingConnection)
			{
				existingConnection = true;
			}
		}

		public override string ToString()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			return Name;
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			if (!existingConnection)
			{
				throw new InvalidOperationException(Res.GetString("CannotGetObject"));
			}
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, cachedDirectoryEntry.Path);
		}

		private static void ValidateArgument(DirectoryContext context, string name)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null || !context.isServer())
			{
				throw new ArgumentException(Res.GetString("DirectoryContextNeedHost"));
			}
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			if (name.Length == 0)
			{
				throw new ArgumentException(Res.GetString("EmptyStringParameter"), "name");
			}
		}

		private void ValidateTargetAndSourceServer(DirectoryContext context, DirectoryServer sourceServer)
		{
			bool flag = false;
			DirectoryEntry directoryEntry = null;
			DirectoryEntry directoryEntry2 = null;
			directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
			try
			{
				if (Utils.CheckCapability(directoryEntry, Capability.ActiveDirectory))
				{
					flag = true;
				}
				else if (!Utils.CheckCapability(directoryEntry, Capability.ActiveDirectoryApplicationMode))
				{
					throw new ArgumentException(Res.GetString("DirectoryContextNeedHost"), "context");
				}
				if (flag && !(sourceServer is DomainController))
				{
					throw new ArgumentException(Res.GetString("ConnectionSourcServerShouldBeDC"), "sourceServer");
				}
				if (!flag && sourceServer is DomainController)
				{
					throw new ArgumentException(Res.GetString("ConnectionSourcServerShouldBeADAM"), "sourceServer");
				}
				directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(sourceServer.Context, WellKnownDN.RootDSE);
				if (flag)
				{
					string s = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.RootDomainNamingContext);
					string s2 = (string)PropertyManager.GetPropertyValue(sourceServer.Context, directoryEntry2, PropertyManager.RootDomainNamingContext);
					if (Utils.Compare(s, s2) != 0)
					{
						throw new ArgumentException(Res.GetString("ConnectionSourcServerSameForest"), "sourceServer");
					}
				}
				else
				{
					string s3 = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
					string s4 = (string)PropertyManager.GetPropertyValue(sourceServer.Context, directoryEntry2, PropertyManager.ConfigurationNamingContext);
					if (Utils.Compare(s3, s4) != 0)
					{
						throw new ArgumentException(Res.GetString("ConnectionSourcServerSameConfigSet"), "sourceServer");
					}
				}
			}
			catch (COMException e)
			{
				ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			finally
			{
				directoryEntry?.Close();
				directoryEntry2?.Close();
			}
		}
	}
	public class ReplicationConnectionCollection : ReadOnlyCollectionBase
	{
		public ReplicationConnection this[int index] => (ReplicationConnection)base.InnerList[index];

		internal ReplicationConnectionCollection()
		{
		}

		public bool Contains(ReplicationConnection connection)
		{
			if (connection == null)
			{
				throw new ArgumentNullException("connection");
			}
			if (!connection.existingConnection)
			{
				throw new InvalidOperationException(Res.GetString("ConnectionNotCommitted", connection.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(connection.context, connection.cachedDirectoryEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ReplicationConnection replicationConnection = (ReplicationConnection)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(replicationConnection.context, replicationConnection.cachedDirectoryEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ReplicationConnection connection)
		{
			if (connection == null)
			{
				throw new ArgumentNullException("connection");
			}
			if (!connection.existingConnection)
			{
				throw new InvalidOperationException(Res.GetString("ConnectionNotCommitted", connection.Name));
			}
			string s = (string)PropertyManager.GetPropertyValue(connection.context, connection.cachedDirectoryEntry, PropertyManager.DistinguishedName);
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				ReplicationConnection replicationConnection = (ReplicationConnection)base.InnerList[i];
				string s2 = (string)PropertyManager.GetPropertyValue(replicationConnection.context, replicationConnection.cachedDirectoryEntry, PropertyManager.DistinguishedName);
				if (Utils.Compare(s2, s) == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ReplicationConnection[] connections, int index)
		{
			base.InnerList.CopyTo(connections, index);
		}

		internal int Add(ReplicationConnection value)
		{
			return base.InnerList.Add(value);
		}
	}
	public class ReplicationCursor
	{
		private string partition;

		private Guid invocationID;

		private long USN;

		private string serverDN;

		private DateTime syncTime;

		private bool advanced;

		private string sourceServer;

		private DirectoryServer server;

		public string PartitionName => partition;

		public Guid SourceInvocationId => invocationID;

		public long UpToDatenessUsn => USN;

		public string SourceServer
		{
			get
			{
				if (!advanced || (advanced && serverDN != null))
				{
					sourceServer = Utils.GetServerNameFromInvocationID(serverDN, SourceInvocationId, server);
				}
				return sourceServer;
			}
		}

		public DateTime LastSuccessfulSyncTime
		{
			get
			{
				if (advanced)
				{
					return syncTime;
				}
				if (Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor == 0)
				{
					throw new PlatformNotSupportedException(Res.GetString("DSNotSupportOnClient"));
				}
				throw new PlatformNotSupportedException(Res.GetString("DSNotSupportOnDC"));
			}
		}

		private ReplicationCursor()
		{
		}

		internal ReplicationCursor(DirectoryServer server, string partition, Guid guid, long filter, long time, IntPtr dn)
		{
			this.partition = partition;
			invocationID = guid;
			USN = filter;
			syncTime = DateTime.FromFileTime(time);
			serverDN = Marshal.PtrToStringUni(dn);
			advanced = true;
			this.server = server;
		}

		internal ReplicationCursor(DirectoryServer server, string partition, Guid guid, long filter)
		{
			this.partition = partition;
			invocationID = guid;
			USN = filter;
			this.server = server;
		}
	}
	public class ReplicationCursorCollection : ReadOnlyCollectionBase
	{
		private DirectoryServer server;

		public ReplicationCursor this[int index] => (ReplicationCursor)base.InnerList[index];

		internal ReplicationCursorCollection(DirectoryServer server)
		{
			this.server = server;
		}

		public bool Contains(ReplicationCursor cursor)
		{
			if (cursor == null)
			{
				throw new ArgumentNullException("cursor");
			}
			return base.InnerList.Contains(cursor);
		}

		public int IndexOf(ReplicationCursor cursor)
		{
			if (cursor == null)
			{
				throw new ArgumentNullException("cursor");
			}
			return base.InnerList.IndexOf(cursor);
		}

		public void CopyTo(ReplicationCursor[] values, int index)
		{
			base.InnerList.CopyTo(values, index);
		}

		private int Add(ReplicationCursor cursor)
		{
			return base.InnerList.Add(cursor);
		}

		internal void AddHelper(string partition, object cursors, bool advanced, IntPtr info)
		{
			int num = 0;
			num = ((!advanced) ? ((DS_REPL_CURSORS)cursors).cNumCursors : ((DS_REPL_CURSORS_3)cursors).cNumCursors);
			IntPtr intPtr = (IntPtr)0;
			for (int i = 0; i < num; i++)
			{
				if (advanced)
				{
					intPtr = Utils.AddToIntPtr(info, Marshal.SizeOf(typeof(int)) * 2 + i * Marshal.SizeOf(typeof(DS_REPL_CURSOR_3)));
					DS_REPL_CURSOR_3 dS_REPL_CURSOR_ = new DS_REPL_CURSOR_3();
					Marshal.PtrToStructure(intPtr, dS_REPL_CURSOR_);
					ReplicationCursor cursor = new ReplicationCursor(server, partition, dS_REPL_CURSOR_.uuidSourceDsaInvocationID, dS_REPL_CURSOR_.usnAttributeFilter, dS_REPL_CURSOR_.ftimeLastSyncSuccess, dS_REPL_CURSOR_.pszSourceDsaDN);
					Add(cursor);
				}
				else
				{
					intPtr = Utils.AddToIntPtr(info, Marshal.SizeOf(typeof(int)) * 2 + i * Marshal.SizeOf(typeof(DS_REPL_CURSOR)));
					DS_REPL_CURSOR dS_REPL_CURSOR = new DS_REPL_CURSOR();
					Marshal.PtrToStructure(intPtr, dS_REPL_CURSOR);
					ReplicationCursor cursor2 = new ReplicationCursor(server, partition, dS_REPL_CURSOR.uuidSourceDsaInvocationID, dS_REPL_CURSOR.usnAttributeFilter);
					Add(cursor2);
				}
			}
		}
	}
	public class ReplicationFailure
	{
		private string sourceDsaDN;

		private Guid uuidDsaObjGuid;

		private DateTime timeFirstFailure;

		private int numFailures;

		internal int lastResult;

		private DirectoryServer server;

		private string sourceServer;

		private Hashtable nameTable;

		public string SourceServer
		{
			get
			{
				if (sourceServer == null)
				{
					if (nameTable.Contains(SourceServerGuid))
					{
						sourceServer = (string)nameTable[SourceServerGuid];
					}
					else if (sourceDsaDN != null)
					{
						sourceServer = Utils.GetServerNameFromInvocationID(sourceDsaDN, SourceServerGuid, server);
						nameTable.Add(SourceServerGuid, sourceServer);
					}
				}
				return sourceServer;
			}
		}

		private Guid SourceServerGuid => uuidDsaObjGuid;

		public DateTime FirstFailureTime => timeFirstFailure;

		public int ConsecutiveFailureCount => numFailures;

		public int LastErrorCode => lastResult;

		public string LastErrorMessage => ExceptionHelper.GetErrorMessage(lastResult, hresult: false);

		internal ReplicationFailure(IntPtr addr, DirectoryServer server, Hashtable table)
		{
			DS_REPL_KCC_DSA_FAILURE dS_REPL_KCC_DSA_FAILURE = new DS_REPL_KCC_DSA_FAILURE();
			Marshal.PtrToStructure(addr, dS_REPL_KCC_DSA_FAILURE);
			sourceDsaDN = Marshal.PtrToStringUni(dS_REPL_KCC_DSA_FAILURE.pszDsaDN);
			uuidDsaObjGuid = dS_REPL_KCC_DSA_FAILURE.uuidDsaObjGuid;
			timeFirstFailure = DateTime.FromFileTime(dS_REPL_KCC_DSA_FAILURE.ftimeFirstFailure);
			numFailures = dS_REPL_KCC_DSA_FAILURE.cNumFailures;
			lastResult = dS_REPL_KCC_DSA_FAILURE.dwLastResult;
			this.server = server;
			nameTable = table;
		}
	}
	public class ReplicationFailureCollection : ReadOnlyCollectionBase
	{
		private DirectoryServer server;

		private Hashtable nameTable;

		public ReplicationFailure this[int index] => (ReplicationFailure)base.InnerList[index];

		internal ReplicationFailureCollection(DirectoryServer server)
		{
			this.server = server;
			Hashtable table = new Hashtable();
			nameTable = Hashtable.Synchronized(table);
		}

		public bool Contains(ReplicationFailure failure)
		{
			if (failure == null)
			{
				throw new ArgumentNullException("failure");
			}
			return base.InnerList.Contains(failure);
		}

		public int IndexOf(ReplicationFailure failure)
		{
			if (failure == null)
			{
				throw new ArgumentNullException("failure");
			}
			return base.InnerList.IndexOf(failure);
		}

		public void CopyTo(ReplicationFailure[] failures, int index)
		{
			base.InnerList.CopyTo(failures, index);
		}

		private int Add(ReplicationFailure failure)
		{
			return base.InnerList.Add(failure);
		}

		internal void AddHelper(DS_REPL_KCC_DSA_FAILURES failures, IntPtr info)
		{
			int cNumEntries = failures.cNumEntries;
			IntPtr intPtr = (IntPtr)0;
			for (int i = 0; i < cNumEntries; i++)
			{
				intPtr = Utils.AddToIntPtr(info, Marshal.SizeOf(typeof(int)) * 2 + i * Marshal.SizeOf(typeof(DS_REPL_KCC_DSA_FAILURE)));
				ReplicationFailure replicationFailure = new ReplicationFailure(intPtr, server, nameTable);
				if (replicationFailure.LastErrorCode == 0)
				{
					replicationFailure.lastResult = ExceptionHelper.ERROR_DS_UNKNOWN_ERROR;
				}
				Add(replicationFailure);
			}
		}
	}
	public enum ActiveDirectoryTransportType
	{
		Rpc,
		Smtp
	}
	public class ReplicationNeighbor
	{
		[Flags]
		public enum ReplicationNeighborOptions : long
		{
			Writeable = 0x10L,
			SyncOnStartup = 0x20L,
			ScheduledSync = 0x40L,
			UseInterSiteTransport = 0x80L,
			TwoWaySync = 0x200L,
			ReturnObjectParent = 0x800L,
			FullSyncInProgress = 0x10000L,
			FullSyncNextPacket = 0x20000L,
			NeverSynced = 0x200000L,
			Preempted = 0x1000000L,
			IgnoreChangeNotifications = 0x4000000L,
			DisableScheduledSync = 0x8000000L,
			CompressChanges = 0x10000000L,
			NoChangeNotifications = 0x20000000L,
			PartialAttributeSet = 0x40000000L
		}

		private string namingContext;

		private string sourceServerDN;

		private ActiveDirectoryTransportType transportType;

		private ReplicationNeighborOptions replicaFlags;

		private Guid uuidSourceDsaInvocationID;

		private long usnLastObjChangeSynced;

		private long usnAttributeFilter;

		private DateTime timeLastSyncSuccess;

		private DateTime timeLastSyncAttempt;

		private int lastSyncResult;

		private int consecutiveSyncFailures;

		private DirectoryServer server;

		private string sourceServer;

		private Hashtable nameTable;

		public string PartitionName => namingContext;

		public string SourceServer
		{
			get
			{
				if (sourceServer == null)
				{
					if (nameTable.Contains(SourceInvocationId))
					{
						sourceServer = (string)nameTable[SourceInvocationId];
					}
					else if (sourceServerDN != null)
					{
						sourceServer = Utils.GetServerNameFromInvocationID(sourceServerDN, SourceInvocationId, server);
						nameTable.Add(SourceInvocationId, sourceServer);
					}
				}
				return sourceServer;
			}
		}

		public ActiveDirectoryTransportType TransportType => transportType;

		public ReplicationNeighborOptions ReplicationNeighborOption => replicaFlags;

		public Guid SourceInvocationId => uuidSourceDsaInvocationID;

		public long UsnLastObjectChangeSynced => usnLastObjChangeSynced;

		public long UsnAttributeFilter => usnAttributeFilter;

		public DateTime LastSuccessfulSync => timeLastSyncSuccess;

		public DateTime LastAttemptedSync => timeLastSyncAttempt;

		public int LastSyncResult => lastSyncResult;

		public string LastSyncMessage => ExceptionHelper.GetErrorMessage(lastSyncResult, hresult: false);

		public int ConsecutiveFailureCount => consecutiveSyncFailures;

		internal ReplicationNeighbor(IntPtr addr, DirectoryServer server, Hashtable table)
		{
			DS_REPL_NEIGHBOR dS_REPL_NEIGHBOR = new DS_REPL_NEIGHBOR();
			Marshal.PtrToStructure(addr, dS_REPL_NEIGHBOR);
			namingContext = Marshal.PtrToStringUni(dS_REPL_NEIGHBOR.pszNamingContext);
			sourceServerDN = Marshal.PtrToStringUni(dS_REPL_NEIGHBOR.pszSourceDsaDN);
			string text = Marshal.PtrToStringUni(dS_REPL_NEIGHBOR.pszAsyncIntersiteTransportDN);
			if (text != null)
			{
				string rdnFromDN = Utils.GetRdnFromDN(text);
				string value = Utils.GetDNComponents(rdnFromDN)[0].Value;
				if (string.Compare(value, "SMTP", StringComparison.OrdinalIgnoreCase) == 0)
				{
					transportType = ActiveDirectoryTransportType.Smtp;
				}
				else
				{
					transportType = ActiveDirectoryTransportType.Rpc;
				}
			}
			replicaFlags = (ReplicationNeighborOptions)dS_REPL_NEIGHBOR.dwReplicaFlags;
			uuidSourceDsaInvocationID = dS_REPL_NEIGHBOR.uuidSourceDsaInvocationID;
			usnLastObjChangeSynced = dS_REPL_NEIGHBOR.usnLastObjChangeSynced;
			usnAttributeFilter = dS_REPL_NEIGHBOR.usnAttributeFilter;
			timeLastSyncSuccess = DateTime.FromFileTime(dS_REPL_NEIGHBOR.ftimeLastSyncSuccess);
			timeLastSyncAttempt = DateTime.FromFileTime(dS_REPL_NEIGHBOR.ftimeLastSyncAttempt);
			lastSyncResult = dS_REPL_NEIGHBOR.dwLastSyncResult;
			consecutiveSyncFailures = dS_REPL_NEIGHBOR.cNumConsecutiveSyncFailures;
			this.server = server;
			nameTable = table;
		}
	}
	public class ReplicationNeighborCollection : ReadOnlyCollectionBase
	{
		private DirectoryServer server;

		private Hashtable nameTable;

		public ReplicationNeighbor this[int index] => (ReplicationNeighbor)base.InnerList[index];

		internal ReplicationNeighborCollection(DirectoryServer server)
		{
			this.server = server;
			Hashtable table = new Hashtable();
			nameTable = Hashtable.Synchronized(table);
		}

		public bool Contains(ReplicationNeighbor neighbor)
		{
			if (neighbor == null)
			{
				throw new ArgumentNullException("neighbor");
			}
			return base.InnerList.Contains(neighbor);
		}

		public int IndexOf(ReplicationNeighbor neighbor)
		{
			if (neighbor == null)
			{
				throw new ArgumentNullException("neighbor");
			}
			return base.InnerList.IndexOf(neighbor);
		}

		public void CopyTo(ReplicationNeighbor[] neighbors, int index)
		{
			base.InnerList.CopyTo(neighbors, index);
		}

		private int Add(ReplicationNeighbor neighbor)
		{
			return base.InnerList.Add(neighbor);
		}

		internal void AddHelper(DS_REPL_NEIGHBORS neighbors, IntPtr info)
		{
			int cNumNeighbors = neighbors.cNumNeighbors;
			IntPtr intPtr = (IntPtr)0;
			for (int i = 0; i < cNumNeighbors; i++)
			{
				intPtr = Utils.AddToIntPtr(info, Marshal.SizeOf(typeof(int)) * 2 + i * Marshal.SizeOf(typeof(DS_REPL_NEIGHBOR)));
				ReplicationNeighbor neighbor = new ReplicationNeighbor(intPtr, server, nameTable);
				Add(neighbor);
			}
		}
	}
	public class ReplicationOperation
	{
		private DateTime timeEnqueued;

		private int serialNumber;

		private int priority;

		private ReplicationOperationType operationType;

		private string namingContext;

		private string dsaDN;

		private Guid uuidDsaObjGuid;

		private DirectoryServer server;

		private string sourceServer;

		private Hashtable nameTable;

		public DateTime TimeEnqueued => timeEnqueued;

		public int OperationNumber => serialNumber;

		public int Priority => priority;

		public ReplicationOperationType OperationType => operationType;

		public string PartitionName => namingContext;

		public string SourceServer
		{
			get
			{
				if (sourceServer == null)
				{
					if (nameTable.Contains(SourceServerGuid))
					{
						sourceServer = (string)nameTable[SourceServerGuid];
					}
					else if (dsaDN != null)
					{
						sourceServer = Utils.GetServerNameFromInvocationID(dsaDN, SourceServerGuid, server);
						nameTable.Add(SourceServerGuid, sourceServer);
					}
				}
				return sourceServer;
			}
		}

		private Guid SourceServerGuid => uuidDsaObjGuid;

		internal ReplicationOperation(IntPtr addr, DirectoryServer server, Hashtable table)
		{
			DS_REPL_OP dS_REPL_OP = new DS_REPL_OP();
			Marshal.PtrToStructure(addr, dS_REPL_OP);
			timeEnqueued = DateTime.FromFileTime(dS_REPL_OP.ftimeEnqueued);
			serialNumber = dS_REPL_OP.ulSerialNumber;
			priority = dS_REPL_OP.ulPriority;
			operationType = dS_REPL_OP.OpType;
			namingContext = Marshal.PtrToStringUni(dS_REPL_OP.pszNamingContext);
			dsaDN = Marshal.PtrToStringUni(dS_REPL_OP.pszDsaDN);
			uuidDsaObjGuid = dS_REPL_OP.uuidDsaObjGuid;
			this.server = server;
			nameTable = table;
		}
	}
	public class ReplicationOperationCollection : ReadOnlyCollectionBase
	{
		private DirectoryServer server;

		private Hashtable nameTable;

		public ReplicationOperation this[int index] => (ReplicationOperation)base.InnerList[index];

		internal ReplicationOperationCollection(DirectoryServer server)
		{
			this.server = server;
			Hashtable table = new Hashtable();
			nameTable = Hashtable.Synchronized(table);
		}

		public bool Contains(ReplicationOperation operation)
		{
			if (operation == null)
			{
				throw new ArgumentNullException("operation");
			}
			return base.InnerList.Contains(operation);
		}

		public int IndexOf(ReplicationOperation operation)
		{
			if (operation == null)
			{
				throw new ArgumentNullException("operation");
			}
			return base.InnerList.IndexOf(operation);
		}

		public void CopyTo(ReplicationOperation[] operations, int index)
		{
			base.InnerList.CopyTo(operations, index);
		}

		private int Add(ReplicationOperation operation)
		{
			return base.InnerList.Add(operation);
		}

		internal void AddHelper(DS_REPL_PENDING_OPS operations, IntPtr info)
		{
			int cNumPendingOps = operations.cNumPendingOps;
			IntPtr intPtr = (IntPtr)0;
			for (int i = 0; i < cNumPendingOps; i++)
			{
				intPtr = Utils.AddToIntPtr(info, Marshal.SizeOf(typeof(DS_REPL_PENDING_OPS)) + i * Marshal.SizeOf(typeof(DS_REPL_OP)));
				ReplicationOperation operation = new ReplicationOperation(intPtr, server, nameTable);
				Add(operation);
			}
		}

		internal ReplicationOperation GetFirstOperation()
		{
			ReplicationOperation result = (ReplicationOperation)base.InnerList[0];
			base.InnerList.RemoveAt(0);
			return result;
		}
	}
	public class ReplicationOperationInformation
	{
		internal DateTime startTime;

		internal ReplicationOperation currentOp;

		internal ReplicationOperationCollection collection;

		public DateTime OperationStartTime => startTime;

		public ReplicationOperation CurrentOperation => currentOp;

		public ReplicationOperationCollection PendingOperations => collection;
	}
	[DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
	public class ActiveDirectoryInterSiteTransport : IDisposable
	{
		private DirectoryContext context;

		private DirectoryEntry cachedEntry;

		private ActiveDirectoryTransportType transport;

		private bool disposed;

		private bool linkRetrieved;

		private bool bridgeRetrieved;

		private ReadOnlySiteLinkCollection siteLinkCollection = new ReadOnlySiteLinkCollection();

		private ReadOnlySiteLinkBridgeCollection bridgeCollection = new ReadOnlySiteLinkBridgeCollection();

		public ActiveDirectoryTransportType TransportType
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				return transport;
			}
		}

		public bool IgnoreReplicationSchedule
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				try
				{
					if (cachedEntry.Properties.Contains("options"))
					{
						num = (int)cachedEntry.Properties["options"][0];
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (((uint)num & (true ? 1u : 0u)) != 0)
				{
					return true;
				}
				return false;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				try
				{
					if (cachedEntry.Properties.Contains("options"))
					{
						num = (int)cachedEntry.Properties["options"][0];
					}
					num = ((!value) ? (num & -2) : (num | 1));
					cachedEntry.Properties["options"].Value = num;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public bool BridgeAllSiteLinks
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				try
				{
					if (cachedEntry.Properties.Contains("options"))
					{
						num = (int)cachedEntry.Properties["options"][0];
					}
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
				if (((uint)num & 2u) != 0)
				{
					return false;
				}
				return true;
			}
			set
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				int num = 0;
				try
				{
					if (cachedEntry.Properties.Contains("options"))
					{
						num = (int)cachedEntry.Properties["options"][0];
					}
					num = ((!value) ? (num | 2) : (num & -3));
					cachedEntry.Properties["options"].Value = num;
				}
				catch (COMException e)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e);
				}
			}
		}

		public ReadOnlySiteLinkCollection SiteLinks
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (!linkRetrieved)
				{
					siteLinkCollection.Clear();
					ADSearcher aDSearcher = new ADSearcher(cachedEntry, "(&(objectClass=siteLink)(objectCategory=SiteLink))", new string[1] { "cn" }, SearchScope.OneLevel);
					SearchResultCollection searchResultCollection = null;
					try
					{
						searchResultCollection = aDSearcher.FindAll();
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					try
					{
						foreach (SearchResult item in searchResultCollection)
						{
							DirectoryEntry directoryEntry = item.GetDirectoryEntry();
							string siteLinkName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn);
							ActiveDirectorySiteLink link = new ActiveDirectorySiteLink(context, siteLinkName, transport, existing: true, directoryEntry);
							siteLinkCollection.Add(link);
						}
					}
					finally
					{
						searchResultCollection.Dispose();
					}
					linkRetrieved = true;
				}
				return siteLinkCollection;
			}
		}

		public ReadOnlySiteLinkBridgeCollection SiteLinkBridges
		{
			get
			{
				if (disposed)
				{
					throw new ObjectDisposedException(GetType().Name);
				}
				if (!bridgeRetrieved)
				{
					bridgeCollection.Clear();
					ADSearcher aDSearcher = new ADSearcher(cachedEntry, "(&(objectClass=siteLinkBridge)(objectCategory=SiteLinkBridge))", new string[1] { "cn" }, SearchScope.OneLevel);
					SearchResultCollection searchResultCollection = null;
					try
					{
						searchResultCollection = aDSearcher.FindAll();
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(context, e);
					}
					try
					{
						foreach (SearchResult item in searchResultCollection)
						{
							DirectoryEntry directoryEntry = item.GetDirectoryEntry();
							string bridgeName = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.Cn);
							ActiveDirectorySiteLinkBridge activeDirectorySiteLinkBridge = new ActiveDirectorySiteLinkBridge(context, bridgeName, transport, existing: true);
							activeDirectorySiteLinkBridge.cachedEntry = directoryEntry;
							bridgeCollection.Add(activeDirectorySiteLinkBridge);
						}
					}
					finally
					{
						searchResultCollection.Dispose();
					}
					bridgeRetrieved = true;
				}
				return bridgeCollection;
			}
		}

		internal ActiveDirectoryInterSiteTransport(DirectoryContext context, ActiveDirectoryTransportType transport, DirectoryEntry entry)
		{
			this.context = context;
			this.transport = transport;
			cachedEntry = entry;
		}

		public static ActiveDirectoryInterSiteTransport FindByTransportType(DirectoryContext context, ActiveDirectoryTransportType transport)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			if (context.Name == null && !context.isRootDomain())
			{
				throw new ArgumentException(Res.GetString("ContextNotAssociatedWithDomain"), "context");
			}
			if (context.Name != null && !context.isRootDomain() && !context.isServer() && !context.isADAMConfigSet())
			{
				throw new ArgumentException(Res.GetString("NotADOrADAM"), "context");
			}
			if (transport < ActiveDirectoryTransportType.Rpc || transport > ActiveDirectoryTransportType.Smtp)
			{
				throw new InvalidEnumArgumentException("value", (int)transport, typeof(ActiveDirectoryTransportType));
			}
			context = new DirectoryContext(context);
			DirectoryEntry directoryEntry;
			try
			{
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
				string text = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.ConfigurationNamingContext);
				string text2 = "CN=Inter-Site Transports,CN=Sites," + text;
				text2 = ((transport != 0) ? ("CN=SMTP," + text2) : ("CN=IP," + text2));
				directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, text2);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			catch (ActiveDirectoryObjectNotFoundException)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("ADAMInstanceNotFoundInConfigSet", context.Name));
			}
			try
			{
				directoryEntry.RefreshCache(new string[1] { "options" });
			}
			catch (COMException ex2)
			{
				if (ex2.ErrorCode == -2147016656)
				{
					DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					if (Utils.CheckCapability(directoryEntry2, Capability.ActiveDirectoryApplicationMode) && transport == ActiveDirectoryTransportType.Smtp)
					{
						throw new NotSupportedException(Res.GetString("NotSupportTransportSMTP"));
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("TransportNotFound", transport.ToString()), typeof(ActiveDirectoryInterSiteTransport), transport.ToString());
				}
				throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
			}
			return new ActiveDirectoryInterSiteTransport(context, transport, directoryEntry);
		}

		public void Save()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			try
			{
				cachedEntry.CommitChanges();
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
		}

		public DirectoryEntry GetDirectoryEntry()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			return DirectoryEntryManager.GetDirectoryEntryInternal(context, cachedEntry.Path);
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		public override string ToString()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
			return transport.ToString();
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing && cachedEntry != null)
			{
				cachedEntry.Dispose();
			}
			disposed = true;
		}
	}
	public enum ActiveDirectoryRole
	{
		SchemaRole,
		NamingRole,
		PdcRole,
		RidRole,
		InfrastructureRole
	}
	public enum AdamRole
	{
		SchemaRole,
		NamingRole
	}
	public class ActiveDirectoryRoleCollection : ReadOnlyCollectionBase
	{
		public ActiveDirectoryRole this[int index] => (ActiveDirectoryRole)base.InnerList[index];

		internal ActiveDirectoryRoleCollection()
		{
		}

		internal ActiveDirectoryRoleCollection(ArrayList values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(ActiveDirectoryRole role)
		{
			if (role < ActiveDirectoryRole.SchemaRole || role > ActiveDirectoryRole.InfrastructureRole)
			{
				throw new InvalidEnumArgumentException("role", (int)role, typeof(ActiveDirectoryRole));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				int num = (int)base.InnerList[i];
				if (num == (int)role)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(ActiveDirectoryRole role)
		{
			if (role < ActiveDirectoryRole.SchemaRole || role > ActiveDirectoryRole.InfrastructureRole)
			{
				throw new InvalidEnumArgumentException("role", (int)role, typeof(ActiveDirectoryRole));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				int num = (int)base.InnerList[i];
				if (num == (int)role)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(ActiveDirectoryRole[] roles, int index)
		{
			base.InnerList.CopyTo(roles, index);
		}
	}
	public class AdamRoleCollection : ReadOnlyCollectionBase
	{
		public AdamRole this[int index] => (AdamRole)base.InnerList[index];

		internal AdamRoleCollection()
		{
		}

		internal AdamRoleCollection(ArrayList values)
		{
			if (values != null)
			{
				base.InnerList.AddRange(values);
			}
		}

		public bool Contains(AdamRole role)
		{
			if (role < AdamRole.SchemaRole || role > AdamRole.NamingRole)
			{
				throw new InvalidEnumArgumentException("role", (int)role, typeof(AdamRole));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				int num = (int)base.InnerList[i];
				if (num == (int)role)
				{
					return true;
				}
			}
			return false;
		}

		public int IndexOf(AdamRole role)
		{
			if (role < AdamRole.SchemaRole || role > AdamRole.NamingRole)
			{
				throw new InvalidEnumArgumentException("role", (int)role, typeof(AdamRole));
			}
			for (int i = 0; i < base.InnerList.Count; i++)
			{
				int num = (int)base.InnerList[i];
				if (num == (int)role)
				{
					return i;
				}
			}
			return -1;
		}

		public void CopyTo(AdamRole[] roles, int index)
		{
			base.InnerList.CopyTo(roles, index);
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal sealed class PolicySafeHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal PolicySafeHandle(IntPtr value)
			: base(ownsHandle: true)
		{
			SetHandle(value);
		}

		protected override bool ReleaseHandle()
		{
			return UnsafeNativeMethods.LsaClose(handle) == 0;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal sealed class LsaLogonProcessSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private LsaLogonProcessSafeHandle()
			: base(ownsHandle: true)
		{
		}

		internal LsaLogonProcessSafeHandle(IntPtr value)
			: base(ownsHandle: true)
		{
			SetHandle(value);
		}

		protected override bool ReleaseHandle()
		{
			return NativeMethods.LsaDeregisterLogonProcess(handle) == 0;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal sealed class LoadLibrarySafeHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private LoadLibrarySafeHandle()
			: base(ownsHandle: true)
		{
		}

		internal LoadLibrarySafeHandle(IntPtr value)
			: base(ownsHandle: true)
		{
			SetHandle(value);
		}

		protected override bool ReleaseHandle()
		{
			return UnsafeNativeMethods.FreeLibrary(handle) != 0;
		}
	}
	public enum ReplicationSecurityLevel
	{
		MutualAuthentication = 2,
		Negotiate = 1,
		NegotiatePassThrough = 0
	}
	internal enum SystemFlag
	{
		SystemFlagNtdsNC = 1,
		SystemFlagNtdsDomain
	}
	public enum TopLevelNameStatus
	{
		Enabled = 0,
		NewlyCreated = 1,
		AdminDisabled = 2,
		ConflictDisabled = 4
	}
	public class TopLevelName
	{
		private string name;

		private TopLevelNameStatus status;

		internal LARGE_INTEGER time;

		public string Name => name;

		public TopLevelNameStatus Status
		{
			get
			{
				return status;
			}
			set
			{
				if (value != 0 && value != TopLevelNameStatus.NewlyCreated && value != TopLevelNameStatus.AdminDisabled && value != TopLevelNameStatus.ConflictDisabled)
				{
					throw new InvalidEnumArgumentException("value", (int)value, typeof(TopLevelNameStatus));
				}
				status = value;
			}
		}

		internal TopLevelName(int flag, LSA_UNICODE_STRING val, LARGE_INTEGER time)
		{
			status = (TopLevelNameStatus)flag;
			name = Marshal.PtrToStringUni(val.Buffer, val.Length / 2);
			this.time = time;
		}
	}
	public class TopLevelNameCollection : ReadOnlyCollectionBase
	{
		public TopLevelName this[int index] => (TopLevelName)base.InnerList[index];

		internal TopLevelNameCollection()
		{
		}

		public bool Contains(TopLevelName name)
		{
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			return base.InnerList.Contains(name);
		}

		public int IndexOf(TopLevelName name)
		{
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			return base.InnerList.IndexOf(name);
		}

		public void CopyTo(TopLevelName[] names, int index)
		{
			base.InnerList.CopyTo(names, index);
		}

		internal int Add(TopLevelName name)
		{
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			return base.InnerList.Add(name);
		}
	}
	internal enum TRUSTED_INFORMATION_CLASS
	{
		TrustedDomainNameInformation = 1,
		TrustedControllersInformation,
		TrustedPosixOffsetInformation,
		TrustedPasswordInformation,
		TrustedDomainInformationBasic,
		TrustedDomainInformationEx,
		TrustedDomainAuthInformation,
		TrustedDomainFullInformation,
		TrustedDomainAuthInformationInternal,
		TrustedDomainFullInformationInternal,
		TrustedDomainInformationEx2Internal,
		TrustedDomainFullInformation2Internal
	}
	[Flags]
	internal enum TRUST_ATTRIBUTE
	{
		TRUST_ATTRIBUTE_NON_TRANSITIVE = 1,
		TRUST_ATTRIBUTE_UPLEVEL_ONLY = 2,
		TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 4,
		TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 8,
		TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10,
		TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20,
		TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x40
	}
	internal class TrustHelper
	{
		private static int STATUS_OBJECT_NAME_NOT_FOUND = 2;

		internal static int ERROR_NOT_FOUND = 1168;

		internal static int NETLOGON_QUERY_LEVEL = 2;

		internal static int NETLOGON_CONTROL_REDISCOVER = 5;

		private static int NETLOGON_CONTROL_TC_VERIFY = 10;

		private static int NETLOGON_VERIFY_STATUS_RETURNED = 128;

		private static int PASSWORD_LENGTH = 15;

		private static int TRUST_AUTH_TYPE_CLEAR = 2;

		private static int PolicyDnsDomainInformation = 12;

		private static int TRUSTED_SET_POSIX = 16;

		private static int TRUSTED_SET_AUTH = 32;

		internal static int TRUST_TYPE_DOWNLEVEL = 1;

		internal static int TRUST_TYPE_UPLEVEL = 2;

		internal static int TRUST_TYPE_MIT = 3;

		private static int ERROR_ALREADY_EXISTS = 183;

		private static int ERROR_INVALID_LEVEL = 124;

		private static char[] punctuations = "!@#$%^&*()_-+=[{]};:>|./?".ToCharArray();

		private TrustHelper()
		{
		}

		internal static bool GetTrustedDomainInfoStatus(DirectoryContext context, string sourceName, string targetName, TRUST_ATTRIBUTE attribute, bool isForest)
		{
			PolicySafeHandle policySafeHandle = null;
			IntPtr buffer = (IntPtr)0;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = null;
			bool flag = false;
			IntPtr intPtr = (IntPtr)0;
			string text = null;
			text = Utils.GetPolicyServerName(context, isForest, needPdc: false, sourceName);
			flag = Utils.Impersonate(context);
			try
			{
				try
				{
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
					intPtr = Marshal.StringToHGlobalUni(targetName);
					UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr);
					int num = UnsafeNativeMethods.LsaQueryTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx, ref buffer);
					if (num != 0)
					{
						int num2 = UnsafeNativeMethods.LsaNtStatusToWinError(num);
						if (num2 == STATUS_OBJECT_NAME_NOT_FOUND)
						{
							if (isForest)
							{
								throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", sourceName, targetName), typeof(ForestTrustRelationshipInformation), null);
							}
							throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainTrustDoesNotExist", sourceName, targetName), typeof(TrustRelationshipInformation), null);
						}
						throw ExceptionHelper.GetExceptionFromErrorCode(num2, text);
					}
					TRUSTED_DOMAIN_INFORMATION_EX tRUSTED_DOMAIN_INFORMATION_EX = new TRUSTED_DOMAIN_INFORMATION_EX();
					Marshal.PtrToStructure(buffer, tRUSTED_DOMAIN_INFORMATION_EX);
					ValidateTrustAttribute(tRUSTED_DOMAIN_INFORMATION_EX, isForest, sourceName, targetName);
					switch (attribute)
					{
					case TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION:
						if ((tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes & TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION) == 0)
						{
							return false;
						}
						return true;
					case TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL:
						if ((tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes & TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL) == 0)
						{
							return true;
						}
						return false;
					case TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN:
						if ((tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes & TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) == 0)
						{
							return false;
						}
						return true;
					default:
						throw new ArgumentException("attribute");
					}
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (buffer != (IntPtr)0)
					{
						UnsafeNativeMethods.LsaFreeMemory(buffer);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		internal static void SetTrustedDomainInfoStatus(DirectoryContext context, string sourceName, string targetName, TRUST_ATTRIBUTE attribute, bool status, bool isForest)
		{
			PolicySafeHandle policySafeHandle = null;
			IntPtr buffer = (IntPtr)0;
			IntPtr intPtr = (IntPtr)0;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = null;
			bool flag = false;
			IntPtr intPtr2 = (IntPtr)0;
			string text = null;
			text = Utils.GetPolicyServerName(context, isForest, needPdc: false, sourceName);
			flag = Utils.Impersonate(context);
			try
			{
				try
				{
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
					intPtr2 = Marshal.StringToHGlobalUni(targetName);
					UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr2);
					int num = UnsafeNativeMethods.LsaQueryTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx, ref buffer);
					if (num != 0)
					{
						int num2 = UnsafeNativeMethods.LsaNtStatusToWinError(num);
						if (num2 == STATUS_OBJECT_NAME_NOT_FOUND)
						{
							if (isForest)
							{
								throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", sourceName, targetName), typeof(ForestTrustRelationshipInformation), null);
							}
							throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainTrustDoesNotExist", sourceName, targetName), typeof(TrustRelationshipInformation), null);
						}
						throw ExceptionHelper.GetExceptionFromErrorCode(num2, text);
					}
					TRUSTED_DOMAIN_INFORMATION_EX tRUSTED_DOMAIN_INFORMATION_EX = new TRUSTED_DOMAIN_INFORMATION_EX();
					Marshal.PtrToStructure(buffer, tRUSTED_DOMAIN_INFORMATION_EX);
					ValidateTrustAttribute(tRUSTED_DOMAIN_INFORMATION_EX, isForest, sourceName, targetName);
					switch (attribute)
					{
					case TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION:
						if (status)
						{
							tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes |= TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION;
						}
						else
						{
							tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes &= ~TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_CROSS_ORGANIZATION;
						}
						break;
					case TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL:
						if (status)
						{
							tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes &= ~TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL;
						}
						else
						{
							tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes |= TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL;
						}
						break;
					case TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN:
						if (status)
						{
							tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes |= TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN;
						}
						else
						{
							tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes &= ~TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN;
						}
						break;
					default:
						throw new ArgumentException("attribute");
					}
					intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TRUSTED_DOMAIN_INFORMATION_EX)));
					Marshal.StructureToPtr(tRUSTED_DOMAIN_INFORMATION_EX, intPtr, fDeleteOld: false);
					num = UnsafeNativeMethods.LsaSetTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx, intPtr);
					if (num != 0)
					{
						throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError(num), text);
					}
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr2 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr2);
					}
					if (buffer != (IntPtr)0)
					{
						UnsafeNativeMethods.LsaFreeMemory(buffer);
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		internal static void DeleteTrust(DirectoryContext sourceContext, string sourceName, string targetName, bool isForest)
		{
			PolicySafeHandle policySafeHandle = null;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = null;
			int num = 0;
			bool flag = false;
			IntPtr intPtr = (IntPtr)0;
			string text = null;
			IntPtr buffer = (IntPtr)0;
			text = Utils.GetPolicyServerName(sourceContext, isForest, needPdc: false, sourceName);
			flag = Utils.Impersonate(sourceContext);
			try
			{
				try
				{
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
					intPtr = Marshal.StringToHGlobalUni(targetName);
					UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr);
					int num2 = UnsafeNativeMethods.LsaQueryTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx, ref buffer);
					if (num2 != 0)
					{
						num = UnsafeNativeMethods.LsaNtStatusToWinError(num2);
						if (num == STATUS_OBJECT_NAME_NOT_FOUND)
						{
							if (isForest)
							{
								throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", sourceName, targetName), typeof(ForestTrustRelationshipInformation), null);
							}
							throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainTrustDoesNotExist", sourceName, targetName), typeof(TrustRelationshipInformation), null);
						}
						throw ExceptionHelper.GetExceptionFromErrorCode(num, text);
					}
					try
					{
						TRUSTED_DOMAIN_INFORMATION_EX tRUSTED_DOMAIN_INFORMATION_EX = new TRUSTED_DOMAIN_INFORMATION_EX();
						Marshal.PtrToStructure(buffer, tRUSTED_DOMAIN_INFORMATION_EX);
						ValidateTrustAttribute(tRUSTED_DOMAIN_INFORMATION_EX, isForest, sourceName, targetName);
						num2 = UnsafeNativeMethods.LsaDeleteTrustedDomain(policySafeHandle, tRUSTED_DOMAIN_INFORMATION_EX.Sid);
						if (num2 != 0)
						{
							num = UnsafeNativeMethods.LsaNtStatusToWinError(num2);
							throw ExceptionHelper.GetExceptionFromErrorCode(num, text);
						}
					}
					finally
					{
						if (buffer != (IntPtr)0)
						{
							UnsafeNativeMethods.LsaFreeMemory(buffer);
						}
					}
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		internal static void VerifyTrust(DirectoryContext context, string sourceName, string targetName, bool isForest, TrustDirection direction, bool forceSecureChannelReset, string preferredTargetServer)
		{
			PolicySafeHandle policySafeHandle = null;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = null;
			int num = 0;
			IntPtr intPtr = (IntPtr)0;
			IntPtr intPtr2 = (IntPtr)0;
			IntPtr buffer = (IntPtr)0;
			IntPtr buffer2 = (IntPtr)0;
			bool flag = true;
			IntPtr intPtr3 = (IntPtr)0;
			string text = null;
			text = Utils.GetPolicyServerName(context, isForest, needPdc: false, sourceName);
			flag = Utils.Impersonate(context);
			try
			{
				try
				{
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
					intPtr3 = Marshal.StringToHGlobalUni(targetName);
					UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr3);
					ValidateTrust(policySafeHandle, lSA_UNICODE_STRING, sourceName, targetName, isForest, (int)direction, text);
					intPtr = ((preferredTargetServer != null) ? Marshal.StringToHGlobalUni(targetName + "\\" + preferredTargetServer) : Marshal.StringToHGlobalUni(targetName));
					intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
					Marshal.WriteIntPtr(intPtr2, intPtr);
					if (!forceSecureChannelReset)
					{
						num = UnsafeNativeMethods.I_NetLogonControl2(text, NETLOGON_CONTROL_TC_VERIFY, NETLOGON_QUERY_LEVEL, intPtr2, out buffer);
						if (num != 0)
						{
							if (num == ERROR_INVALID_LEVEL)
							{
								throw new NotSupportedException(Res.GetString("TrustVerificationNotSupport"));
							}
							throw ExceptionHelper.GetExceptionFromErrorCode(num);
						}
						NETLOGON_INFO_2 nETLOGON_INFO_ = new NETLOGON_INFO_2();
						Marshal.PtrToStructure(buffer, nETLOGON_INFO_);
						if ((nETLOGON_INFO_.netlog2_flags & NETLOGON_VERIFY_STATUS_RETURNED) == 0)
						{
							int netlog2_tc_connection_status = nETLOGON_INFO_.netlog2_tc_connection_status;
							throw ExceptionHelper.GetExceptionFromErrorCode(netlog2_tc_connection_status);
						}
						int netlog2_pdc_connection_status = nETLOGON_INFO_.netlog2_pdc_connection_status;
						if (netlog2_pdc_connection_status != 0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(netlog2_pdc_connection_status);
						}
					}
					else
					{
						num = UnsafeNativeMethods.I_NetLogonControl2(text, NETLOGON_CONTROL_REDISCOVER, NETLOGON_QUERY_LEVEL, intPtr2, out buffer2);
						if (num != 0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(num);
						}
					}
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr3 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr3);
					}
					if (intPtr2 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr2);
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (buffer != (IntPtr)0)
					{
						UnsafeNativeMethods.NetApiBufferFree(buffer);
					}
					if (buffer2 != (IntPtr)0)
					{
						UnsafeNativeMethods.NetApiBufferFree(buffer2);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		internal static void CreateTrust(DirectoryContext sourceContext, string sourceName, DirectoryContext targetContext, string targetName, bool isForest, TrustDirection direction, string password)
		{
			LSA_AUTH_INFORMATION lSA_AUTH_INFORMATION = null;
			TRUSTED_DOMAIN_AUTH_INFORMATION tRUSTED_DOMAIN_AUTH_INFORMATION = null;
			TRUSTED_DOMAIN_INFORMATION_EX tRUSTED_DOMAIN_INFORMATION_EX = null;
			IntPtr intPtr = (IntPtr)0;
			IntPtr intPtr2 = (IntPtr)0;
			IntPtr intPtr3 = (IntPtr)0;
			IntPtr domainHandle = (IntPtr)0;
			PolicySafeHandle policySafeHandle = null;
			IntPtr intPtr4 = (IntPtr)0;
			bool flag = false;
			string text = null;
			intPtr3 = GetTrustedDomainInfo(targetContext, targetName, isForest);
			try
			{
				try
				{
					POLICY_DNS_DOMAIN_INFO pOLICY_DNS_DOMAIN_INFO = new POLICY_DNS_DOMAIN_INFO();
					Marshal.PtrToStructure(intPtr3, pOLICY_DNS_DOMAIN_INFO);
					lSA_AUTH_INFORMATION = new LSA_AUTH_INFORMATION();
					intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileTime)));
					UnsafeNativeMethods.GetSystemTimeAsFileTime(intPtr);
					FileTime fileTime = new FileTime();
					Marshal.PtrToStructure(intPtr, fileTime);
					lSA_AUTH_INFORMATION.LastUpdateTime = new LARGE_INTEGER();
					lSA_AUTH_INFORMATION.LastUpdateTime.lowPart = fileTime.lower;
					lSA_AUTH_INFORMATION.LastUpdateTime.highPart = fileTime.higher;
					lSA_AUTH_INFORMATION.AuthType = TRUST_AUTH_TYPE_CLEAR;
					intPtr2 = (lSA_AUTH_INFORMATION.AuthInfo = Marshal.StringToHGlobalUni(password));
					lSA_AUTH_INFORMATION.AuthInfoLength = password.Length * 2;
					intPtr4 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_AUTH_INFORMATION)));
					Marshal.StructureToPtr(lSA_AUTH_INFORMATION, intPtr4, fDeleteOld: false);
					tRUSTED_DOMAIN_AUTH_INFORMATION = new TRUSTED_DOMAIN_AUTH_INFORMATION();
					if ((direction & TrustDirection.Inbound) != 0)
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthInfos = 1;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthenticationInformation = intPtr4;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingPreviousAuthenticationInformation = (IntPtr)0;
					}
					if ((direction & TrustDirection.Outbound) != 0)
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthInfos = 1;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthenticationInformation = intPtr4;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingPreviousAuthenticationInformation = (IntPtr)0;
					}
					tRUSTED_DOMAIN_INFORMATION_EX = new TRUSTED_DOMAIN_INFORMATION_EX();
					tRUSTED_DOMAIN_INFORMATION_EX.FlatName = pOLICY_DNS_DOMAIN_INFO.Name;
					tRUSTED_DOMAIN_INFORMATION_EX.Name = pOLICY_DNS_DOMAIN_INFO.DnsDomainName;
					tRUSTED_DOMAIN_INFORMATION_EX.Sid = pOLICY_DNS_DOMAIN_INFO.Sid;
					tRUSTED_DOMAIN_INFORMATION_EX.TrustType = TRUST_TYPE_UPLEVEL;
					tRUSTED_DOMAIN_INFORMATION_EX.TrustDirection = (int)direction;
					if (isForest)
					{
						tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes = TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_FOREST_TRANSITIVE;
					}
					else
					{
						tRUSTED_DOMAIN_INFORMATION_EX.TrustAttributes = TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN;
					}
					text = Utils.GetPolicyServerName(sourceContext, isForest, needPdc: false, sourceName);
					flag = Utils.Impersonate(sourceContext);
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					int num = UnsafeNativeMethods.LsaCreateTrustedDomainEx(policySafeHandle, tRUSTED_DOMAIN_INFORMATION_EX, tRUSTED_DOMAIN_AUTH_INFORMATION, TRUSTED_SET_POSIX | TRUSTED_SET_AUTH, out domainHandle);
					if (num == 0)
					{
						return;
					}
					num = UnsafeNativeMethods.LsaNtStatusToWinError(num);
					if (num == ERROR_ALREADY_EXISTS)
					{
						if (isForest)
						{
							throw new ActiveDirectoryObjectExistsException(Res.GetString("AlreadyExistingForestTrust", sourceName, targetName));
						}
						throw new ActiveDirectoryObjectExistsException(Res.GetString("AlreadyExistingDomainTrust", sourceName, targetName));
					}
					throw ExceptionHelper.GetExceptionFromErrorCode(num, text);
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (domainHandle != (IntPtr)0)
					{
						UnsafeNativeMethods.LsaClose(domainHandle);
					}
					if (intPtr3 != (IntPtr)0)
					{
						UnsafeNativeMethods.LsaFreeMemory(intPtr3);
					}
					if (intPtr2 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr2);
					}
					if (intPtr4 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr4);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		internal static string UpdateTrust(DirectoryContext context, string sourceName, string targetName, string password, bool isForest)
		{
			PolicySafeHandle policySafeHandle = null;
			IntPtr buffer = (IntPtr)0;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = null;
			IntPtr intPtr = (IntPtr)0;
			bool flag = false;
			LSA_AUTH_INFORMATION lSA_AUTH_INFORMATION = null;
			IntPtr intPtr2 = (IntPtr)0;
			IntPtr intPtr3 = (IntPtr)0;
			IntPtr intPtr4 = (IntPtr)0;
			TRUSTED_DOMAIN_AUTH_INFORMATION tRUSTED_DOMAIN_AUTH_INFORMATION = null;
			IntPtr intPtr5 = (IntPtr)0;
			string text = null;
			text = Utils.GetPolicyServerName(context, isForest, needPdc: false, sourceName);
			flag = Utils.Impersonate(context);
			try
			{
				try
				{
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
					intPtr5 = Marshal.StringToHGlobalUni(targetName);
					UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr5);
					int num = UnsafeNativeMethods.LsaQueryTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation, ref buffer);
					if (num != 0)
					{
						int num2 = UnsafeNativeMethods.LsaNtStatusToWinError(num);
						if (num2 == STATUS_OBJECT_NAME_NOT_FOUND)
						{
							if (isForest)
							{
								throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", sourceName, targetName), typeof(ForestTrustRelationshipInformation), null);
							}
							throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainTrustDoesNotExist", sourceName, targetName), typeof(TrustRelationshipInformation), null);
						}
						throw ExceptionHelper.GetExceptionFromErrorCode(num2, text);
					}
					TRUSTED_DOMAIN_FULL_INFORMATION tRUSTED_DOMAIN_FULL_INFORMATION = new TRUSTED_DOMAIN_FULL_INFORMATION();
					Marshal.PtrToStructure(buffer, tRUSTED_DOMAIN_FULL_INFORMATION);
					ValidateTrustAttribute(tRUSTED_DOMAIN_FULL_INFORMATION.Information, isForest, sourceName, targetName);
					TrustDirection trustDirection = (TrustDirection)tRUSTED_DOMAIN_FULL_INFORMATION.Information.TrustDirection;
					lSA_AUTH_INFORMATION = new LSA_AUTH_INFORMATION();
					intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileTime)));
					UnsafeNativeMethods.GetSystemTimeAsFileTime(intPtr2);
					FileTime fileTime = new FileTime();
					Marshal.PtrToStructure(intPtr2, fileTime);
					lSA_AUTH_INFORMATION.LastUpdateTime = new LARGE_INTEGER();
					lSA_AUTH_INFORMATION.LastUpdateTime.lowPart = fileTime.lower;
					lSA_AUTH_INFORMATION.LastUpdateTime.highPart = fileTime.higher;
					lSA_AUTH_INFORMATION.AuthType = TRUST_AUTH_TYPE_CLEAR;
					intPtr3 = (lSA_AUTH_INFORMATION.AuthInfo = Marshal.StringToHGlobalUni(password));
					lSA_AUTH_INFORMATION.AuthInfoLength = password.Length * 2;
					intPtr4 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_AUTH_INFORMATION)));
					Marshal.StructureToPtr(lSA_AUTH_INFORMATION, intPtr4, fDeleteOld: false);
					tRUSTED_DOMAIN_AUTH_INFORMATION = new TRUSTED_DOMAIN_AUTH_INFORMATION();
					if ((trustDirection & TrustDirection.Inbound) != 0)
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthInfos = 1;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthenticationInformation = intPtr4;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingPreviousAuthenticationInformation = (IntPtr)0;
					}
					if ((trustDirection & TrustDirection.Outbound) != 0)
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthInfos = 1;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthenticationInformation = intPtr4;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingPreviousAuthenticationInformation = (IntPtr)0;
					}
					tRUSTED_DOMAIN_FULL_INFORMATION.AuthInformation = tRUSTED_DOMAIN_AUTH_INFORMATION;
					intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TRUSTED_DOMAIN_FULL_INFORMATION)));
					Marshal.StructureToPtr(tRUSTED_DOMAIN_FULL_INFORMATION, intPtr, fDeleteOld: false);
					num = UnsafeNativeMethods.LsaSetTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation, intPtr);
					if (num != 0)
					{
						throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError(num), text);
					}
					return text;
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr5 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr5);
					}
					if (buffer != (IntPtr)0)
					{
						UnsafeNativeMethods.LsaFreeMemory(buffer);
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (intPtr2 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr2);
					}
					if (intPtr3 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr3);
					}
					if (intPtr4 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr4);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		internal static void UpdateTrustDirection(DirectoryContext context, string sourceName, string targetName, string password, bool isForest, TrustDirection newTrustDirection)
		{
			PolicySafeHandle policySafeHandle = null;
			IntPtr buffer = (IntPtr)0;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = null;
			IntPtr intPtr = (IntPtr)0;
			bool flag = false;
			LSA_AUTH_INFORMATION lSA_AUTH_INFORMATION = null;
			IntPtr intPtr2 = (IntPtr)0;
			IntPtr intPtr3 = (IntPtr)0;
			IntPtr intPtr4 = (IntPtr)0;
			TRUSTED_DOMAIN_AUTH_INFORMATION tRUSTED_DOMAIN_AUTH_INFORMATION = null;
			IntPtr intPtr5 = (IntPtr)0;
			string text = null;
			text = Utils.GetPolicyServerName(context, isForest, needPdc: false, sourceName);
			flag = Utils.Impersonate(context);
			try
			{
				try
				{
					policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
					intPtr5 = Marshal.StringToHGlobalUni(targetName);
					UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr5);
					int num = UnsafeNativeMethods.LsaQueryTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation, ref buffer);
					if (num != 0)
					{
						int num2 = UnsafeNativeMethods.LsaNtStatusToWinError(num);
						if (num2 == STATUS_OBJECT_NAME_NOT_FOUND)
						{
							if (isForest)
							{
								throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", sourceName, targetName), typeof(ForestTrustRelationshipInformation), null);
							}
							throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainTrustDoesNotExist", sourceName, targetName), typeof(TrustRelationshipInformation), null);
						}
						throw ExceptionHelper.GetExceptionFromErrorCode(num2, text);
					}
					TRUSTED_DOMAIN_FULL_INFORMATION tRUSTED_DOMAIN_FULL_INFORMATION = new TRUSTED_DOMAIN_FULL_INFORMATION();
					Marshal.PtrToStructure(buffer, tRUSTED_DOMAIN_FULL_INFORMATION);
					ValidateTrustAttribute(tRUSTED_DOMAIN_FULL_INFORMATION.Information, isForest, sourceName, targetName);
					lSA_AUTH_INFORMATION = new LSA_AUTH_INFORMATION();
					intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileTime)));
					UnsafeNativeMethods.GetSystemTimeAsFileTime(intPtr2);
					FileTime fileTime = new FileTime();
					Marshal.PtrToStructure(intPtr2, fileTime);
					lSA_AUTH_INFORMATION.LastUpdateTime = new LARGE_INTEGER();
					lSA_AUTH_INFORMATION.LastUpdateTime.lowPart = fileTime.lower;
					lSA_AUTH_INFORMATION.LastUpdateTime.highPart = fileTime.higher;
					lSA_AUTH_INFORMATION.AuthType = TRUST_AUTH_TYPE_CLEAR;
					intPtr3 = (lSA_AUTH_INFORMATION.AuthInfo = Marshal.StringToHGlobalUni(password));
					lSA_AUTH_INFORMATION.AuthInfoLength = password.Length * 2;
					intPtr4 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_AUTH_INFORMATION)));
					Marshal.StructureToPtr(lSA_AUTH_INFORMATION, intPtr4, fDeleteOld: false);
					tRUSTED_DOMAIN_AUTH_INFORMATION = new TRUSTED_DOMAIN_AUTH_INFORMATION();
					if ((newTrustDirection & TrustDirection.Inbound) != 0)
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthInfos = 1;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthenticationInformation = intPtr4;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingPreviousAuthenticationInformation = (IntPtr)0;
					}
					else
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthInfos = 0;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingAuthenticationInformation = (IntPtr)0;
						tRUSTED_DOMAIN_AUTH_INFORMATION.IncomingPreviousAuthenticationInformation = (IntPtr)0;
					}
					if ((newTrustDirection & TrustDirection.Outbound) != 0)
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthInfos = 1;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthenticationInformation = intPtr4;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingPreviousAuthenticationInformation = (IntPtr)0;
					}
					else
					{
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthInfos = 0;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingAuthenticationInformation = (IntPtr)0;
						tRUSTED_DOMAIN_AUTH_INFORMATION.OutgoingPreviousAuthenticationInformation = (IntPtr)0;
					}
					tRUSTED_DOMAIN_FULL_INFORMATION.AuthInformation = tRUSTED_DOMAIN_AUTH_INFORMATION;
					tRUSTED_DOMAIN_FULL_INFORMATION.Information.TrustDirection = (int)newTrustDirection;
					intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TRUSTED_DOMAIN_FULL_INFORMATION)));
					Marshal.StructureToPtr(tRUSTED_DOMAIN_FULL_INFORMATION, intPtr, fDeleteOld: false);
					num = UnsafeNativeMethods.LsaSetTrustedDomainInfoByName(policySafeHandle, lSA_UNICODE_STRING, TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation, intPtr);
					if (num != 0)
					{
						throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError(num), text);
					}
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
					if (intPtr5 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr5);
					}
					if (buffer != (IntPtr)0)
					{
						UnsafeNativeMethods.LsaFreeMemory(buffer);
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (intPtr2 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr2);
					}
					if (intPtr3 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr3);
					}
					if (intPtr4 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr4);
					}
				}
			}
			catch
			{
				throw;
			}
		}

		private static void ValidateTrust(PolicySafeHandle handle, LSA_UNICODE_STRING trustedDomainName, string sourceName, string targetName, bool isForest, int direction, string serverName)
		{
			IntPtr buffer = (IntPtr)0;
			int num = UnsafeNativeMethods.LsaQueryTrustedDomainInfoByName(handle, trustedDomainName, TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx, ref buffer);
			if (num != 0)
			{
				int num2 = UnsafeNativeMethods.LsaNtStatusToWinError(num);
				if (num2 == STATUS_OBJECT_NAME_NOT_FOUND)
				{
					if (isForest)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", sourceName, targetName), typeof(ForestTrustRelationshipInformation), null);
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DomainTrustDoesNotExist", sourceName, targetName), typeof(TrustRelationshipInformation), null);
				}
				throw ExceptionHelper.GetExceptionFromErrorCode(num2, serverName);
			}
			try
			{
				TRUSTED_DOMAIN_INFORMATION_EX tRUSTED_DOMAIN_INFORMATION_EX = new TRUSTED_DOMAIN_INFORMATION_EX();
				Marshal.PtrToStructure(buffer, tRUSTED_DOMAIN_INFORMATION_EX);
				ValidateTrustAttribute(tRUSTED_DOMAIN_INFORMATION_EX, isForest, sourceName, targetName);
				if (direction != 0 && (direction & tRUSTED_DOMAIN_INFORMATION_EX.TrustDirection) == 0)
				{
					if (isForest)
					{
						throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", sourceName, targetName, (TrustDirection)direction), typeof(ForestTrustRelationshipInformation), null);
					}
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongTrustDirection", sourceName, targetName, (TrustDirection)direction), typeof(TrustRelationshipInformation), null);
				}
			}
			finally
			{
				if (buffer != (IntPtr)0)
				{
					UnsafeNativeMethods.LsaFreeMemory(buffer);
				}
			}
		}

		private static void ValidateTrustAttribute(TRUSTED_DOMAIN_INFORMATION_EX domainInfo, bool isForest, string sourceName, string targetName)
		{
			if (isForest)
			{
				if ((domainInfo.TrustAttributes & TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_FOREST_TRANSITIVE) == 0)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("ForestTrustDoesNotExist", sourceName, targetName), typeof(ForestTrustRelationshipInformation), null);
				}
				return;
			}
			if ((domainInfo.TrustAttributes & TRUST_ATTRIBUTE.TRUST_ATTRIBUTE_FOREST_TRANSITIVE) != 0)
			{
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("WrongForestTrust", sourceName, targetName), typeof(TrustRelationshipInformation), null);
			}
			if (domainInfo.TrustType == TRUST_TYPE_DOWNLEVEL)
			{
				throw new InvalidOperationException(Res.GetString("NT4NotSupported"));
			}
			if (domainInfo.TrustType == TRUST_TYPE_MIT)
			{
				throw new InvalidOperationException(Res.GetString("KerberosNotSupported"));
			}
		}

		internal static string CreateTrustPassword()
		{
			byte[] array = new byte[PASSWORD_LENGTH];
			char[] array2 = new char[PASSWORD_LENGTH];
			new RNGCryptoServiceProvider().GetBytes(array);
			for (int i = 0; i < PASSWORD_LENGTH; i++)
			{
				int num = (int)array[i] % 87;
				if (num < 10)
				{
					array2[i] = (char)(48 + num);
				}
				else if (num < 36)
				{
					array2[i] = (char)(65 + num - 10);
				}
				else if (num < 62)
				{
					array2[i] = (char)(97 + num - 36);
				}
				else
				{
					array2[i] = punctuations[num - 62];
				}
			}
			return new string(array2);
		}

		private static IntPtr GetTrustedDomainInfo(DirectoryContext targetContext, string targetName, bool isForest)
		{
			PolicySafeHandle policySafeHandle = null;
			IntPtr buffer = (IntPtr)0;
			bool flag = false;
			string text = null;
			try
			{
				try
				{
					text = Utils.GetPolicyServerName(targetContext, isForest, needPdc: false, targetName);
					flag = Utils.Impersonate(targetContext);
					try
					{
						policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					}
					catch (ActiveDirectoryOperationException)
					{
						if (flag)
						{
							Utils.Revert();
							flag = false;
						}
						Utils.ImpersonateAnonymous();
						flag = true;
						policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					}
					catch (UnauthorizedAccessException)
					{
						if (flag)
						{
							Utils.Revert();
							flag = false;
						}
						Utils.ImpersonateAnonymous();
						flag = true;
						policySafeHandle = new PolicySafeHandle(Utils.GetPolicyHandle(text));
					}
					int num = UnsafeNativeMethods.LsaQueryInformationPolicy(policySafeHandle, PolicyDnsDomainInformation, out buffer);
					if (num != 0)
					{
						throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError(num), text);
					}
					return buffer;
				}
				finally
				{
					if (flag)
					{
						Utils.Revert();
					}
				}
			}
			catch
			{
				throw;
			}
		}
	}
	public enum TrustType
	{
		TreeRoot,
		ParentChild,
		CrossLink,
		External,
		Forest,
		Kerberos,
		Unknown
	}
	public enum TrustDirection
	{
		Inbound = 1,
		Outbound,
		Bidirectional
	}
	public class TrustRelationshipInformationCollection : ReadOnlyCollectionBase
	{
		public TrustRelationshipInformation this[int index] => (TrustRelationshipInformation)base.InnerList[index];

		internal TrustRelationshipInformationCollection()
		{
		}

		internal TrustRelationshipInformationCollection(DirectoryContext context, string source, ArrayList trusts)
		{
			for (int i = 0; i < trusts.Count; i++)
			{
				TrustObject trustObject = (TrustObject)trusts[i];
				if (trustObject.TrustType != TrustType.Forest && trustObject.TrustType != (TrustType)7)
				{
					TrustRelationshipInformation info = new TrustRelationshipInformation(context, source, trustObject);
					Add(info);
				}
			}
		}

		public bool Contains(TrustRelationshipInformation information)
		{
			if (information == null)
			{
				throw new ArgumentNullException("information");
			}
			return base.InnerList.Contains(information);
		}

		public int IndexOf(TrustRelationshipInformation information)
		{
			if (information == null)
			{
				throw new ArgumentNullException("information");
			}
			return base.InnerList.IndexOf(information);
		}

		public void CopyTo(TrustRelationshipInformation[] array, int index)
		{
			base.InnerList.CopyTo(array, index);
		}

		internal int Add(TrustRelationshipInformation info)
		{
			return base.InnerList.Add(info);
		}
	}
	internal enum DS_REPL_INFO_TYPE
	{
		DS_REPL_INFO_NEIGHBORS,
		DS_REPL_INFO_CURSORS_FOR_NC,
		DS_REPL_INFO_METADATA_FOR_OBJ,
		DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES,
		DS_REPL_INFO_KCC_DSA_LINK_FAILURES,
		DS_REPL_INFO_PENDING_OPS,
		DS_REPL_INFO_METADATA_FOR_ATTR_VALUE,
		DS_REPL_INFO_CURSORS_2_FOR_NC,
		DS_REPL_INFO_CURSORS_3_FOR_NC,
		DS_REPL_INFO_METADATA_2_FOR_OBJ,
		DS_REPL_INFO_METADATA_2_FOR_ATTR_VALUE
	}
	public enum ReplicationOperationType
	{
		Sync,
		Add,
		Delete,
		Modify,
		UpdateReference
	}
	internal enum DS_NAME_ERROR
	{
		DS_NAME_NO_ERROR,
		DS_NAME_ERROR_RESOLVING,
		DS_NAME_ERROR_NOT_FOUND,
		DS_NAME_ERROR_NOT_UNIQUE,
		DS_NAME_ERROR_NO_MAPPING,
		DS_NAME_ERROR_DOMAIN_ONLY,
		DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING,
		DS_NAME_ERROR_TRUST_REFERRAL
	}
	[Flags]
	internal enum DS_DOMAINTRUST_FLAG
	{
		DS_DOMAIN_IN_FOREST = 1,
		DS_DOMAIN_DIRECT_OUTBOUND = 2,
		DS_DOMAIN_TREE_ROOT = 4,
		DS_DOMAIN_PRIMARY = 8,
		DS_DOMAIN_NATIVE_MODE = 0x10,
		DS_DOMAIN_DIRECT_INBOUND = 0x20
	}
	internal enum LSA_FOREST_TRUST_RECORD_TYPE
	{
		ForestTrustTopLevelName,
		ForestTrustTopLevelNameEx,
		ForestTrustDomainInfo,
		ForestTrustRecordTypeLast
	}
	public enum ForestTrustCollisionType
	{
		TopLevelName,
		Domain,
		Other
	}
	[Flags]
	public enum TopLevelNameCollisionOptions
	{
		None = 0,
		NewlyCreated = 1,
		DisabledByAdmin = 2,
		DisabledByConflict = 4
	}
	[Flags]
	public enum DomainCollisionOptions
	{
		None = 0,
		SidDisabledByAdmin = 1,
		SidDisabledByConflict = 2,
		NetBiosNameDisabledByAdmin = 4,
		NetBiosNameDisabledByConflict = 8
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class FileTime
	{
		public int lower;

		public int higher;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class SystemTime
	{
		public ushort wYear;

		public ushort wMonth;

		public ushort wDayOfWeek;

		public ushort wDay;

		public ushort wHour;

		public ushort wMinute;

		public ushort wSecond;

		public ushort wMilliseconds;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_CURSORS_3
	{
		public int cNumCursors;

		public int dwEnumerationContext;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_CURSORS
	{
		public int cNumCursors;

		public int reserved;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_CURSOR_3
	{
		public Guid uuidSourceDsaInvocationID;

		public long usnAttributeFilter;

		public long ftimeLastSyncSuccess;

		public IntPtr pszSourceDsaDN;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_CURSOR
	{
		public Guid uuidSourceDsaInvocationID;

		public long usnAttributeFilter;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_PENDING_OPS
	{
		public long ftimeCurrentOpStarted;

		public int cNumPendingOps;
	}
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	internal sealed class DS_REPL_OP
	{
		public long ftimeEnqueued;

		public int ulSerialNumber;

		public int ulPriority;

		public ReplicationOperationType OpType;

		public int ulOptions;

		public IntPtr pszNamingContext;

		public IntPtr pszDsaDN;

		public IntPtr pszDsaAddress;

		public Guid uuidNamingContextObjGuid;

		public Guid uuidDsaObjGuid;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_NEIGHBORS
	{
		public int cNumNeighbors;

		public int dwReserved;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_NEIGHBOR
	{
		public IntPtr pszNamingContext;

		public IntPtr pszSourceDsaDN;

		public IntPtr pszSourceDsaAddress;

		public IntPtr pszAsyncIntersiteTransportDN;

		public int dwReplicaFlags;

		public int dwReserved;

		public Guid uuidNamingContextObjGuid;

		public Guid uuidSourceDsaObjGuid;

		public Guid uuidSourceDsaInvocationID;

		public Guid uuidAsyncIntersiteTransportObjGuid;

		public long usnLastObjChangeSynced;

		public long usnAttributeFilter;

		public long ftimeLastSyncSuccess;

		public long ftimeLastSyncAttempt;

		public int dwLastSyncResult;

		public int cNumConsecutiveSyncFailures;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_KCC_DSA_FAILURES
	{
		public int cNumEntries;

		public int dwReserved;
	}
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	internal sealed class DS_REPL_KCC_DSA_FAILURE
	{
		public IntPtr pszDsaDN;

		public Guid uuidDsaObjGuid;

		public long ftimeFirstFailure;

		public int cNumFailures;

		public int dwLastResult;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_OBJ_META_DATA_2
	{
		public int cNumEntries;

		public int dwReserved;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_ATTR_META_DATA_2
	{
		public IntPtr pszAttributeName;

		public int dwVersion;

		public int ftimeLastOriginatingChange1;

		public int ftimeLastOriginatingChange2;

		public Guid uuidLastOriginatingDsaInvocationID;

		public long usnOriginatingChange;

		public long usnLocalChange;

		public IntPtr pszLastOriginatingDsaDN;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_OBJ_META_DATA
	{
		public int cNumEntries;

		public int dwReserved;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPL_ATTR_META_DATA
	{
		public IntPtr pszAttributeName;

		public int dwVersion;

		public int ftimeLastOriginatingChange1;

		public int ftimeLastOriginatingChange2;

		public Guid uuidLastOriginatingDsaInvocationID;

		public long usnOriginatingChange;

		public long usnLocalChange;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPSYNCALL_UPDATE
	{
		public SyncFromAllServersEvent eventType;

		public IntPtr pErrInfo;

		public IntPtr pSync;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPSYNCALL_ERRINFO
	{
		public IntPtr pszSvrId;

		public SyncFromAllServersErrorCategory error;

		public int dwWin32Err;

		public IntPtr pszSrcId;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_REPSYNCALL_SYNC
	{
		public IntPtr pszSrcId;

		public IntPtr pszDstId;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_NAME_RESULT_ITEM
	{
		public DS_NAME_ERROR status;

		public IntPtr pDomain;

		public IntPtr pName;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_NAME_RESULT
	{
		public int cItems;

		public IntPtr rItems;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class DS_DOMAIN_TRUSTS
	{
		public IntPtr NetbiosDomainName;

		public IntPtr DnsDomainName;

		public int Flags;

		public int ParentIndex;

		public int TrustType;

		public int TrustAttributes;

		public IntPtr DomainSid;

		public Guid DomainGuid;
	}
	internal sealed class TrustObject
	{
		public string NetbiosDomainName;

		public string DnsDomainName;

		public int Flags;

		public int ParentIndex;

		public TrustType TrustType;

		public int TrustAttributes;

		public int OriginalIndex;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_FOREST_TRUST_INFORMATION
	{
		public int RecordCount;

		public IntPtr Entries;
	}
	[StructLayout(LayoutKind.Explicit)]
	internal sealed class LSA_FOREST_TRUST_RECORD
	{
		[FieldOffset(0)]
		public int Flags;

		[FieldOffset(4)]
		public LSA_FOREST_TRUST_RECORD_TYPE ForestTrustType;

		[FieldOffset(8)]
		public LARGE_INTEGER Time;

		[FieldOffset(16)]
		public LSA_UNICODE_STRING TopLevelName;

		[FieldOffset(16)]
		public LSA_FOREST_TRUST_BINARY_DATA Data;

		[FieldOffset(16)]
		public LSA_FOREST_TRUST_DOMAIN_INFO DomainInfo;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LARGE_INTEGER
	{
		public int lowPart;

		public int highPart;

		public LARGE_INTEGER()
		{
			lowPart = 0;
			highPart = 0;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_UNICODE_STRING
	{
		public short Length;

		public short MaximumLength;

		public IntPtr Buffer;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_FOREST_TRUST_DOMAIN_INFO
	{
		public IntPtr sid;

		public short DNSNameLength;

		public short DNSNameMaximumLength;

		public IntPtr DNSNameBuffer;

		public short NetBIOSNameLength;

		public short NetBIOSNameMaximumLength;

		public IntPtr NetBIOSNameBuffer;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_FOREST_TRUST_BINARY_DATA
	{
		public int Length;

		public IntPtr Buffer;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_OBJECT_ATTRIBUTES
	{
		internal int Length;

		private IntPtr RootDirectory;

		private IntPtr ObjectName;

		internal int Attributes;

		private IntPtr SecurityDescriptor;

		private IntPtr SecurityQualityOfService;

		public LSA_OBJECT_ATTRIBUTES()
		{
			Length = 0;
			RootDirectory = (IntPtr)0;
			ObjectName = (IntPtr)0;
			Attributes = 0;
			SecurityDescriptor = (IntPtr)0;
			SecurityQualityOfService = (IntPtr)0;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class TRUSTED_DOMAIN_INFORMATION_EX
	{
		public LSA_UNICODE_STRING Name;

		public LSA_UNICODE_STRING FlatName;

		public IntPtr Sid;

		public int TrustDirection;

		public int TrustType;

		public TRUST_ATTRIBUTE TrustAttributes;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_FOREST_TRUST_COLLISION_INFORMATION
	{
		public int RecordCount;

		public IntPtr Entries;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_FOREST_TRUST_COLLISION_RECORD
	{
		public int Index;

		public ForestTrustCollisionType Type;

		public int Flags;

		public LSA_UNICODE_STRING Name;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class NETLOGON_INFO_2
	{
		public int netlog2_flags;

		public int netlog2_pdc_connection_status;

		public IntPtr netlog2_trusted_dc_name;

		public int netlog2_tc_connection_status;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class TRUSTED_DOMAIN_AUTH_INFORMATION
	{
		public int IncomingAuthInfos;

		public IntPtr IncomingAuthenticationInformation;

		public IntPtr IncomingPreviousAuthenticationInformation;

		public int OutgoingAuthInfos;

		public IntPtr OutgoingAuthenticationInformation;

		public IntPtr OutgoingPreviousAuthenticationInformation;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class LSA_AUTH_INFORMATION
	{
		public LARGE_INTEGER LastUpdateTime;

		public int AuthType;

		public int AuthInfoLength;

		public IntPtr AuthInfo;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class POLICY_DNS_DOMAIN_INFO
	{
		public LSA_UNICODE_STRING Name;

		public LSA_UNICODE_STRING DnsDomainName;

		public LSA_UNICODE_STRING DnsForestName;

		public Guid DomainGuid;

		public IntPtr Sid;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class TRUSTED_POSIX_OFFSET_INFO
	{
		internal int Offset;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal sealed class TRUSTED_DOMAIN_FULL_INFORMATION
	{
		public TRUSTED_DOMAIN_INFORMATION_EX Information;

		internal TRUSTED_POSIX_OFFSET_INFO PosixOffset;

		public TRUSTED_DOMAIN_AUTH_INFORMATION AuthInformation;
	}
	[ComVisible(false)]
	[SuppressUnmanagedCodeSecurity]
	internal class UnsafeNativeMethods
	{
		[SuppressUnmanagedCodeSecurity]
		public delegate int DsReplicaConsistencyCheck([In] IntPtr handle, int taskID, int flags);

		[SuppressUnmanagedCodeSecurity]
		public delegate int DsReplicaGetInfo2W(IntPtr handle, int type, [MarshalAs(UnmanagedType.LPWStr)] string objectPath, IntPtr sourceGUID, string attributeName, string value, int flag, int context, ref IntPtr info);

		[SuppressUnmanagedCodeSecurity]
		public delegate int DsReplicaGetInfoW(IntPtr handle, int type, [MarshalAs(UnmanagedType.LPWStr)] string objectPath, IntPtr sourceGUID, ref IntPtr info);

		[SuppressUnmanagedCodeSecurity]
		public delegate int DsReplicaFreeInfo(int type, IntPtr value);

		[SuppressUnmanagedCodeSecurity]
		public delegate int DsReplicaSyncW(IntPtr handle, [MarshalAs(UnmanagedType.LPWStr)] string partition, IntPtr uuid, int option);

		[SuppressUnmanagedCodeSecurity]
		public delegate int DsReplicaSyncAllW(IntPtr handle, [MarshalAs(UnmanagedType.LPWStr)] string partition, int flags, SyncReplicaFromAllServersCallback callback, IntPtr data, ref IntPtr error);

		[SuppressUnmanagedCodeSecurity]
		public delegate int DsListDomainsInSiteW(IntPtr handle, [MarshalAs(UnmanagedType.LPWStr)] string site, ref IntPtr info);

		[SuppressUnmanagedCodeSecurity]
		public delegate void DsFreeNameResultW(IntPtr result);

		public const int FORMAT_MESSAGE_ALLOCATE_BUFFER = 256;

		public const int FORMAT_MESSAGE_IGNORE_INSERTS = 512;

		public const int FORMAT_MESSAGE_FROM_STRING = 1024;

		public const int FORMAT_MESSAGE_FROM_HMODULE = 2048;

		public const int FORMAT_MESSAGE_FROM_SYSTEM = 4096;

		public const int FORMAT_MESSAGE_ARGUMENT_ARRAY = 8192;

		public const int FORMAT_MESSAGE_MAX_WIDTH_MASK = 255;

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		public static extern int FormatMessageW(int dwFlags, int lpSource, int dwMessageId, int dwLanguageId, StringBuilder lpBuffer, int nSize, int arguments);

		[DllImport("kernel32.dll")]
		public static extern int LocalFree(IntPtr mem);

		[DllImport("activeds.dll", CharSet = CharSet.Unicode)]
		public static extern int ADsEncodeBinaryData(byte[] data, int length, ref IntPtr result);

		[DllImport("activeds.dll")]
		public static extern bool FreeADsMem(IntPtr pVoid);

		[DllImport("netapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "DsGetSiteNameW")]
		public static extern int DsGetSiteName(string dcName, ref IntPtr ptr);

		[DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int DsEnumerateDomainTrustsW(string serverName, int flags, out IntPtr domains, out int count);

		[DllImport("Netapi32.dll")]
		public static extern int NetApiBufferFree(IntPtr buffer);

		[DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern int LogonUserW(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

		[DllImport("Advapi32.dll", SetLastError = true)]
		public static extern int ImpersonateLoggedOnUser(IntPtr hToken);

		[DllImport("Advapi32.dll", SetLastError = true)]
		public static extern int RevertToSelf();

		[DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern int ConvertSidToStringSidW(IntPtr pSid, ref IntPtr stringSid);

		[DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern int ConvertStringSidToSidW(IntPtr stringSid, ref IntPtr pSid);

		[DllImport("Advapi32.dll")]
		public static extern int LsaSetForestTrustInformation(PolicySafeHandle handle, LSA_UNICODE_STRING target, IntPtr forestTrustInfo, int checkOnly, out IntPtr collisionInfo);

		[DllImport("Advapi32.dll")]
		public static extern int LsaOpenPolicy(LSA_UNICODE_STRING target, LSA_OBJECT_ATTRIBUTES objectAttributes, int access, out IntPtr handle);

		[DllImport("Advapi32.dll")]
		public static extern int LsaClose(IntPtr handle);

		[DllImport("Advapi32.dll")]
		public static extern int LsaQueryForestTrustInformation(PolicySafeHandle handle, LSA_UNICODE_STRING target, ref IntPtr ForestTrustInfo);

		[DllImport("Advapi32.dll")]
		public static extern int LsaQueryTrustedDomainInfoByName(PolicySafeHandle handle, LSA_UNICODE_STRING trustedDomain, TRUSTED_INFORMATION_CLASS infoClass, ref IntPtr buffer);

		[DllImport("Advapi32.dll")]
		public static extern int LsaNtStatusToWinError(int status);

		[DllImport("Advapi32.dll")]
		public static extern int LsaFreeMemory(IntPtr ptr);

		[DllImport("Advapi32.dll")]
		public static extern int LsaSetTrustedDomainInfoByName(PolicySafeHandle handle, LSA_UNICODE_STRING trustedDomain, TRUSTED_INFORMATION_CLASS infoClass, IntPtr buffer);

		[DllImport("Advapi32.dll")]
		public static extern int LsaOpenTrustedDomainByName(PolicySafeHandle policyHandle, LSA_UNICODE_STRING trustedDomain, int access, ref IntPtr trustedDomainHandle);

		[DllImport("Advapi32.dll")]
		public static extern int LsaDeleteTrustedDomain(PolicySafeHandle handle, IntPtr pSid);

		[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
		public static extern int I_NetLogonControl2(string serverName, int FunctionCode, int QueryLevel, IntPtr data, out IntPtr buffer);

		[DllImport("Kernel32.dll")]
		public static extern void GetSystemTimeAsFileTime(IntPtr fileTime);

		[DllImport("Advapi32.dll")]
		public static extern int LsaQueryInformationPolicy(PolicySafeHandle handle, int infoClass, out IntPtr buffer);

		[DllImport("Advapi32.dll")]
		public static extern int LsaCreateTrustedDomainEx(PolicySafeHandle handle, TRUSTED_DOMAIN_INFORMATION_EX domainEx, TRUSTED_DOMAIN_AUTH_INFORMATION authInfo, int classInfo, out IntPtr domainHandle);

		[DllImport("Kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenThread(uint desiredAccess, bool inheirted, int threadID);

		[DllImport("Kernel32.dll")]
		public static extern int GetCurrentThreadId();

		[DllImport("Advapi32.dll", SetLastError = true)]
		public static extern int ImpersonateAnonymousToken(IntPtr token);

		[DllImport("Kernel32.dll")]
		public static extern int CloseHandle(IntPtr handle);

		[DllImport("ntdll.dll")]
		public static extern int RtlInitUnicodeString(LSA_UNICODE_STRING result, IntPtr s);

		[DllImport("Kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "LoadLibraryW", SetLastError = true)]
		public static extern IntPtr LoadLibrary(string name);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		public static extern uint FreeLibrary(IntPtr libName);

		[DllImport("kernel32.dll", BestFitMapping = false, SetLastError = true)]
		public static extern IntPtr GetProcAddress(LoadLibrarySafeHandle hModule, string entryPoint);
	}
	internal struct Component
	{
		public string Name;

		public string Value;
	}
	internal enum Capability
	{
		ActiveDirectory,
		ActiveDirectoryApplicationMode,
		ActiveDirectoryOrADAM
	}
	[StructLayout(LayoutKind.Sequential, Size = 1)]
	internal struct SupportedCapability
	{
		public static string ADOid = "1.2.840.113556.1.4.800";

		public static string ADAMOid = "1.2.840.113556.1.4.1851";
	}
	[DirectoryServicesPermission(SecurityAction.Assert, Unrestricted = true)]
	internal sealed class Utils
	{
		private static int LOGON32_LOGON_NEW_CREDENTIALS = 9;

		private static int LOGON32_PROVIDER_WINNT50 = 3;

		private static int POLICY_VIEW_LOCAL_INFORMATION = 1;

		private static uint STANDARD_RIGHTS_REQUIRED = 983040u;

		private static uint SYNCHRONIZE = 1048576u;

		private static uint THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FFu;

		internal static AuthenticationTypes DefaultAuthType = AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing;

		private static uint LANG_ENGLISH = 9u;

		private static uint SUBLANG_ENGLISH_US = 1u;

		private static uint SORT_DEFAULT = 0u;

		private static uint LANGID = (uint)(((ushort)SUBLANG_ENGLISH_US << 10) | (ushort)LANG_ENGLISH);

		private static uint LCID = (uint)(((ushort)SORT_DEFAULT << 16) | (ushort)LANGID);

		internal static uint NORM_IGNORECASE = 1u;

		internal static uint NORM_IGNORENONSPACE = 2u;

		internal static uint NORM_IGNOREKANATYPE = 65536u;

		internal static uint NORM_IGNOREWIDTH = 131072u;

		internal static uint SORT_STRINGSORT = 4096u;

		internal static uint DEFAULT_CMP_FLAGS = NORM_IGNORECASE | NORM_IGNOREKANATYPE | NORM_IGNORENONSPACE | NORM_IGNOREWIDTH | SORT_STRINGSORT;

		private static string NTAuthorityString = null;

		private Utils()
		{
		}

		internal static string GetDnsNameFromDN(string distinguishedName)
		{
			int num = 0;
			string result = null;
			IntPtr results = IntPtr.Zero;
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsCrackNamesW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			NativeMethods.DsCrackNames dsCrackNames = (NativeMethods.DsCrackNames)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsCrackNames));
			IntPtr intPtr = Marshal.StringToHGlobalUni(distinguishedName);
			IntPtr intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
			Marshal.WriteIntPtr(intPtr2, intPtr);
			num = dsCrackNames(IntPtr.Zero, 1, 1, 7, 1, intPtr2, out results);
			switch (num)
			{
			case 0:
				try
				{
					DsNameResult dsNameResult = new DsNameResult();
					Marshal.PtrToStructure(results, dsNameResult);
					if (dsNameResult.itemCount >= 1)
					{
						if (dsNameResult.items != IntPtr.Zero)
						{
							DsNameResultItem dsNameResultItem = new DsNameResultItem();
							Marshal.PtrToStructure(dsNameResult.items, dsNameResultItem);
							if (dsNameResultItem.status == 6 || dsNameResultItem.name == null)
							{
								throw new ArgumentException(Res.GetString("InvalidDNFormat"), "distinguishedName");
							}
							if (dsNameResultItem.status != 0)
							{
								throw ExceptionHelper.GetExceptionFromErrorCode(num);
							}
							if (dsNameResultItem.name.Length - 1 == dsNameResultItem.name.IndexOf('/'))
							{
								return dsNameResultItem.name.Substring(0, dsNameResultItem.name.Length - 1);
							}
							return dsNameResultItem.name;
						}
						return result;
					}
					return result;
				}
				finally
				{
					if (intPtr2 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr2);
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (results != IntPtr.Zero)
					{
						procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsFreeNameResultW");
						if (procAddress == (IntPtr)0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
						}
						UnsafeNativeMethods.DsFreeNameResultW dsFreeNameResultW = (UnsafeNativeMethods.DsFreeNameResultW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsFreeNameResultW));
						dsFreeNameResultW(results);
					}
				}
			case 6:
				throw new ArgumentException(Res.GetString("InvalidDNFormat"), "distinguishedName");
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			}
		}

		internal static string GetDNFromDnsName(string dnsName)
		{
			int num = 0;
			string result = null;
			IntPtr results = IntPtr.Zero;
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsCrackNamesW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			NativeMethods.DsCrackNames dsCrackNames = (NativeMethods.DsCrackNames)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsCrackNames));
			IntPtr intPtr = Marshal.StringToHGlobalUni(dnsName + "/");
			IntPtr intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
			Marshal.WriteIntPtr(intPtr2, intPtr);
			num = dsCrackNames(IntPtr.Zero, 1, 7, 1, 1, intPtr2, out results);
			switch (num)
			{
			case 0:
				try
				{
					DsNameResult dsNameResult = new DsNameResult();
					Marshal.PtrToStructure(results, dsNameResult);
					if (dsNameResult.itemCount >= 1)
					{
						if (dsNameResult.items != IntPtr.Zero)
						{
							DsNameResultItem dsNameResultItem = new DsNameResultItem();
							Marshal.PtrToStructure(dsNameResult.items, dsNameResultItem);
							return dsNameResultItem.name;
						}
						return result;
					}
					return result;
				}
				finally
				{
					if (intPtr2 != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr2);
					}
					if (intPtr != (IntPtr)0)
					{
						Marshal.FreeHGlobal(intPtr);
					}
					if (results != IntPtr.Zero)
					{
						procAddress = UnsafeNativeMethods.GetProcAddress(DirectoryContext.ADHandle, "DsFreeNameResultW");
						if (procAddress == (IntPtr)0)
						{
							throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
						}
						UnsafeNativeMethods.DsFreeNameResultW dsFreeNameResultW = (UnsafeNativeMethods.DsFreeNameResultW)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(UnsafeNativeMethods.DsFreeNameResultW));
						dsFreeNameResultW(results);
					}
				}
			case 6:
				throw new ArgumentException(Res.GetString("InvalidDNFormat"));
			default:
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			}
		}

		internal static string GetDnsHostNameFromNTDSA(DirectoryContext context, string dn)
		{
			string text = null;
			int num = dn.IndexOf(',');
			if (num == -1)
			{
				throw new ArgumentException(Res.GetString("InvalidDNFormat"), "dn");
			}
			string dn2 = dn.Substring(num + 1);
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, dn2);
			try
			{
				return (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.DnsHostName);
			}
			finally
			{
				directoryEntry.Dispose();
			}
		}

		internal static string GetAdamDnsHostNameFromNTDSA(DirectoryContext context, string dn)
		{
			string text = null;
			int num = -1;
			string partialDN = GetPartialDN(dn, 1);
			string partialDN2 = GetPartialDN(dn, 2);
			string text2 = "CN=NTDS-DSA";
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, partialDN2);
			string filter = "(|(&(" + PropertyManager.ObjectCategory + "=server)(" + PropertyManager.DistinguishedName + "=" + GetEscapedFilterValue(partialDN) + "))(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.DistinguishedName + "=" + GetEscapedFilterValue(dn) + ")))";
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, filter, new string[3]
			{
				PropertyManager.DnsHostName,
				PropertyManager.MsDSPortLDAP,
				PropertyManager.ObjectCategory
			}, SearchScope.Subtree, pagedSearch: true, cacheResults: true);
			SearchResultCollection searchResultCollection = aDSearcher.FindAll();
			try
			{
				if (searchResultCollection.Count != 2)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("NoHostNameOrPortNumber", dn));
				}
				foreach (SearchResult item in searchResultCollection)
				{
					string text3 = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.ObjectCategory);
					if (text3.Length >= text2.Length && Compare(text3, 0, text2.Length, text2, 0, text2.Length) == 0)
					{
						num = (int)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.MsDSPortLDAP);
					}
					else
					{
						text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsHostName);
					}
				}
			}
			finally
			{
				searchResultCollection.Dispose();
				directoryEntry.Dispose();
			}
			if (num == -1 || text == null)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("NoHostNameOrPortNumber", dn));
			}
			return text + ":" + num;
		}

		internal static string GetAdamHostNameAndPortsFromNTDSA(DirectoryContext context, string dn)
		{
			string text = null;
			int num = -1;
			int num2 = -1;
			string partialDN = GetPartialDN(dn, 1);
			string partialDN2 = GetPartialDN(dn, 2);
			string text2 = "CN=NTDS-DSA";
			DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, partialDN2);
			string filter = "(|(&(" + PropertyManager.ObjectCategory + "=server)(" + PropertyManager.DistinguishedName + "=" + GetEscapedFilterValue(partialDN) + "))(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.DistinguishedName + "=" + GetEscapedFilterValue(dn) + ")))";
			ADSearcher aDSearcher = new ADSearcher(directoryEntry, filter, new string[4]
			{
				PropertyManager.DnsHostName,
				PropertyManager.MsDSPortLDAP,
				PropertyManager.MsDSPortSSL,
				PropertyManager.ObjectCategory
			}, SearchScope.Subtree, pagedSearch: true, cacheResults: true);
			SearchResultCollection searchResultCollection = aDSearcher.FindAll();
			try
			{
				if (searchResultCollection.Count != 2)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("NoHostNameOrPortNumber", dn));
				}
				foreach (SearchResult item in searchResultCollection)
				{
					string text3 = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.ObjectCategory);
					if (text3.Length >= text2.Length && Compare(text3, 0, text2.Length, text2, 0, text2.Length) == 0)
					{
						num = (int)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.MsDSPortLDAP);
						num2 = (int)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.MsDSPortSSL);
					}
					else
					{
						text = (string)PropertyManager.GetSearchResultPropertyValue(item, PropertyManager.DnsHostName);
					}
				}
			}
			finally
			{
				searchResultCollection.Dispose();
				directoryEntry.Dispose();
			}
			if (num == -1 || num2 == -1 || text == null)
			{
				throw new ActiveDirectoryOperationException(Res.GetString("NoHostNameOrPortNumber", dn));
			}
			return text + ":" + num + ":" + num2;
		}

		internal static string GetRdnFromDN(string distinguishedName)
		{
			Component[] dNComponents = GetDNComponents(distinguishedName);
			return dNComponents[0].Name + "=" + dNComponents[0].Value;
		}

		internal static string GetPartialDN(string distinguishedName, int startingIndex)
		{
			string text = "";
			Component[] dNComponents = GetDNComponents(distinguishedName);
			bool flag = true;
			for (int i = startingIndex; i < dNComponents.GetLength(0); i++)
			{
				if (flag)
				{
					text = dNComponents[i].Name + "=" + dNComponents[i].Value;
					flag = false;
					continue;
				}
				string text2 = text;
				text = text2 + "," + dNComponents[i].Name + "=" + dNComponents[i].Value;
			}
			return text;
		}

		internal static Component[] GetDNComponents(string distinguishedName)
		{
			string[] array = Split(distinguishedName, ',');
			Component[] array2 = new Component[array.GetLength(0)];
			for (int i = 0; i < array.GetLength(0); i++)
			{
				string[] array3 = Split(array[i], '=');
				if (array3.GetLength(0) != 2)
				{
					throw new ArgumentException(Res.GetString("InvalidDNFormat"), "distinguishedName");
				}
				array2[i].Name = array3[0].Trim();
				if (array2[i].Name.Length == 0)
				{
					throw new ArgumentException(Res.GetString("InvalidDNFormat"), "distinguishedName");
				}
				array2[i].Value = array3[1].Trim();
				if (array2[i].Value.Length == 0)
				{
					throw new ArgumentException(Res.GetString("InvalidDNFormat"), "distinguishedName");
				}
			}
			return array2;
		}

		internal static bool IsValidDNFormat(string distinguishedName)
		{
			string[] array = Split(distinguishedName, ',');
			Component[] array2 = new Component[array.GetLength(0)];
			for (int i = 0; i < array.GetLength(0); i++)
			{
				string[] array3 = Split(array[i], '=');
				if (array3.GetLength(0) != 2)
				{
					return false;
				}
				array2[i].Name = array3[0].Trim();
				if (array2[i].Name.Length == 0)
				{
					return false;
				}
				array2[i].Value = array3[1].Trim();
				if (array2[i].Value.Length == 0)
				{
					return false;
				}
			}
			return true;
		}

		public static string[] Split(string distinguishedName, char delim)
		{
			bool flag = false;
			char c = '"';
			char c2 = '\\';
			int num = 0;
			ArrayList arrayList = new ArrayList();
			for (int i = 0; i < distinguishedName.Length; i++)
			{
				char c3 = distinguishedName[i];
				if (c3 == c)
				{
					flag = !flag;
				}
				else if (c3 == c2)
				{
					if (i < distinguishedName.Length - 1)
					{
						i++;
					}
				}
				else if (!flag && c3 == delim)
				{
					arrayList.Add(distinguishedName.Substring(num, i - num));
					num = i + 1;
				}
				if (i == distinguishedName.Length - 1)
				{
					if (flag)
					{
						throw new ArgumentException(Res.GetString("InvalidDNFormat"), "distinguishedName");
					}
					arrayList.Add(distinguishedName.Substring(num, i - num + 1));
				}
			}
			string[] array = new string[arrayList.Count];
			for (int j = 0; j < arrayList.Count; j++)
			{
				array[j] = (string)arrayList[j];
			}
			return array;
		}

		internal static DirectoryContext GetNewDirectoryContext(string name, DirectoryContextType contextType, DirectoryContext context)
		{
			return new DirectoryContext(contextType, name, context);
		}

		internal static void GetDomainAndUsername(DirectoryContext context, out string username, out string domain)
		{
			if (context.UserName != null && context.UserName.Length > 0)
			{
				string userName = context.UserName;
				int num = -1;
				if ((num = userName.IndexOf('\\')) != -1)
				{
					domain = userName.Substring(0, num);
					username = userName.Substring(num + 1, userName.Length - num - 1);
				}
				else
				{
					username = userName;
					domain = null;
				}
			}
			else
			{
				username = context.UserName;
				domain = null;
			}
		}

		internal static IntPtr GetAuthIdentity(DirectoryContext context, LoadLibrarySafeHandle libHandle)
		{
			int num = 0;
			GetDomainAndUsername(context, out var username, out var domain);
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsMakePasswordCredentialsW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			NativeMethods.DsMakePasswordCredentials dsMakePasswordCredentials = (NativeMethods.DsMakePasswordCredentials)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsMakePasswordCredentials));
			num = dsMakePasswordCredentials(username, domain, context.Password, out var authIdentity);
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num);
			}
			return authIdentity;
		}

		internal static void FreeAuthIdentity(IntPtr authIdentity, LoadLibrarySafeHandle libHandle)
		{
			if (authIdentity != IntPtr.Zero)
			{
				IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsFreePasswordCredentials");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				NativeMethods.DsFreePasswordCredentials dsFreePasswordCredentials = (NativeMethods.DsFreePasswordCredentials)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsFreePasswordCredentials));
				dsFreePasswordCredentials(authIdentity);
			}
		}

		internal static IntPtr GetDSHandle(string domainControllerName, string domainName, IntPtr authIdentity, LoadLibrarySafeHandle libHandle)
		{
			int num = 0;
			IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsBindWithCredW");
			if (procAddress == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			NativeMethods.DsBindWithCred dsBindWithCred = (NativeMethods.DsBindWithCred)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsBindWithCred));
			num = dsBindWithCred(domainControllerName, domainName, authIdentity, out var handle);
			if (num != 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(num, (domainControllerName != null) ? domainControllerName : domainName);
			}
			return handle;
		}

		internal static void FreeDSHandle(IntPtr dsHandle, LoadLibrarySafeHandle libHandle)
		{
			if (dsHandle != IntPtr.Zero)
			{
				IntPtr procAddress = UnsafeNativeMethods.GetProcAddress(libHandle, "DsUnBindW");
				if (procAddress == (IntPtr)0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
				NativeMethods.DsUnBind dsUnBind = (NativeMethods.DsUnBind)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(NativeMethods.DsUnBind));
				dsUnBind(ref dsHandle);
			}
		}

		internal static bool CheckCapability(DirectoryEntry rootDSE, Capability capability)
		{
			bool result = false;
			if (rootDSE != null)
			{
				switch (capability)
				{
				case Capability.ActiveDirectory:
				{
					foreach (string item in rootDSE.Properties[PropertyManager.SupportedCapabilities])
					{
						if (string.Compare(item, SupportedCapability.ADOid, StringComparison.OrdinalIgnoreCase) == 0)
						{
							return true;
						}
					}
					return result;
				}
				case Capability.ActiveDirectoryApplicationMode:
				{
					foreach (string item2 in rootDSE.Properties[PropertyManager.SupportedCapabilities])
					{
						if (string.Compare(item2, SupportedCapability.ADAMOid, StringComparison.OrdinalIgnoreCase) == 0)
						{
							return true;
						}
					}
					return result;
				}
				case Capability.ActiveDirectoryOrADAM:
				{
					foreach (string item3 in rootDSE.Properties[PropertyManager.SupportedCapabilities])
					{
						if (string.Compare(item3, SupportedCapability.ADAMOid, StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(item3, SupportedCapability.ADOid, StringComparison.OrdinalIgnoreCase) == 0)
						{
							return true;
						}
					}
					return result;
				}
				}
			}
			return result;
		}

		internal static DirectoryEntry GetCrossRefEntry(DirectoryContext context, DirectoryEntry partitionsEntry, string partitionName)
		{
			StringBuilder stringBuilder = new StringBuilder(15);
			stringBuilder.Append("(&(");
			stringBuilder.Append(PropertyManager.ObjectCategory);
			stringBuilder.Append("=crossRef)(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.804:=");
			stringBuilder.Append(1);
			stringBuilder.Append(")(!(");
			stringBuilder.Append(PropertyManager.SystemFlags);
			stringBuilder.Append(":1.2.840.113556.1.4.803:=");
			stringBuilder.Append(2);
			stringBuilder.Append("))(");
			stringBuilder.Append(PropertyManager.NCName);
			stringBuilder.Append("=");
			stringBuilder.Append(GetEscapedFilterValue(partitionName));
			stringBuilder.Append("))");
			string filter = stringBuilder.ToString();
			ADSearcher aDSearcher = new ADSearcher(partitionsEntry, filter, new string[1] { PropertyManager.DistinguishedName }, SearchScope.OneLevel, pagedSearch: false, cacheResults: false);
			SearchResult searchResult = null;
			try
			{
				searchResult = aDSearcher.FindOne();
				if (searchResult == null)
				{
					throw new ActiveDirectoryObjectNotFoundException(Res.GetString("AppNCNotFound"), typeof(ActiveDirectoryPartition), partitionName);
				}
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			_ = (string)PropertyManager.GetSearchResultPropertyValue(searchResult, PropertyManager.DistinguishedName);
			return searchResult.GetDirectoryEntry();
		}

		internal static ActiveDirectoryTransportType GetTransportTypeFromDN(string DN)
		{
			string rdnFromDN = GetRdnFromDN(DN);
			Component[] dNComponents = GetDNComponents(rdnFromDN);
			string value = dNComponents[0].Value;
			if (string.Compare(value, "IP", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return ActiveDirectoryTransportType.Rpc;
			}
			if (string.Compare(value, "SMTP", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return ActiveDirectoryTransportType.Smtp;
			}
			string @string = Res.GetString("UnknownTransport", value);
			throw new ActiveDirectoryOperationException(@string);
		}

		internal static string GetDNFromTransportType(ActiveDirectoryTransportType transport, DirectoryContext context)
		{
			string text = DirectoryEntryManager.ExpandWellKnownDN(context, WellKnownDN.SitesContainer);
			string text2 = "CN=Inter-Site Transports," + text;
			if (transport == ActiveDirectoryTransportType.Rpc)
			{
				return "CN=IP," + text2;
			}
			return "CN=SMTP," + text2;
		}

		internal static string GetServerNameFromInvocationID(string serverObjectDN, Guid invocationID, DirectoryServer server)
		{
			string result = null;
			if (serverObjectDN == null)
			{
				string dn = ((server is DomainController) ? ((DomainController)server).SiteObjectName : ((AdamInstance)server).SiteObjectName);
				DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(server.Context, dn);
				byte[] array = invocationID.ToByteArray();
				IntPtr result2 = (IntPtr)0;
				string text = null;
				int num = UnsafeNativeMethods.ADsEncodeBinaryData(array, array.Length, ref result2);
				if (num == 0)
				{
					try
					{
						text = Marshal.PtrToStringUni(result2);
					}
					finally
					{
						if (result2 != (IntPtr)0)
						{
							UnsafeNativeMethods.FreeADsMem(result2);
						}
					}
					ADSearcher aDSearcher = new ADSearcher(directoryEntry, "(&(objectClass=nTDSDSA)(invocationID=" + text + "))", new string[1] { "distinguishedName" }, SearchScope.Subtree, pagedSearch: false, cacheResults: false);
					SearchResult searchResult = null;
					try
					{
						searchResult = aDSearcher.FindOne();
						if (searchResult != null)
						{
							DirectoryEntry parent = searchResult.GetDirectoryEntry().Parent;
							return (string)PropertyManager.GetPropertyValue(server.Context, parent, PropertyManager.DnsHostName);
						}
						return result;
					}
					catch (COMException e)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(server.Context, e);
					}
				}
				throw ExceptionHelper.GetExceptionFromCOMException(new COMException(ExceptionHelper.GetErrorMessage(num, hresult: true), num));
			}
			DirectoryEntry directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(server.Context, serverObjectDN);
			try
			{
				result = (string)PropertyManager.GetPropertyValue(directoryEntry2.Parent, PropertyManager.DnsHostName);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147016656)
				{
					return null;
				}
				throw ExceptionHelper.GetExceptionFromCOMException(server.Context, ex);
			}
			if (server is AdamInstance)
			{
				int num2 = (int)PropertyManager.GetPropertyValue(server.Context, directoryEntry2, PropertyManager.MsDSPortLDAP);
				if (num2 != 389)
				{
					result = result + ":" + num2;
				}
			}
			return result;
		}

		internal static int GetRandomIndex(int count)
		{
			Random random = new Random();
			int num = random.Next();
			return num % count;
		}

		internal static bool Impersonate(DirectoryContext context)
		{
			IntPtr phToken = (IntPtr)0;
			if (context.UserName == null && context.Password == null)
			{
				return false;
			}
			GetDomainAndUsername(context, out var username, out var domain);
			if (UnsafeNativeMethods.LogonUserW(username, domain, context.Password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, ref phToken) == 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			try
			{
				if (UnsafeNativeMethods.ImpersonateLoggedOnUser(phToken) == 0)
				{
					int lastWin32Error = Marshal.GetLastWin32Error();
					throw ExceptionHelper.GetExceptionFromErrorCode(lastWin32Error);
				}
			}
			finally
			{
				if (phToken != (IntPtr)0)
				{
					UnsafeNativeMethods.CloseHandle(phToken);
				}
			}
			return true;
		}

		internal static void ImpersonateAnonymous()
		{
			IntPtr intPtr = (IntPtr)0;
			intPtr = UnsafeNativeMethods.OpenThread(THREAD_ALL_ACCESS, inheirted: false, UnsafeNativeMethods.GetCurrentThreadId());
			if (intPtr == (IntPtr)0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
			try
			{
				if (UnsafeNativeMethods.ImpersonateAnonymousToken(intPtr) == 0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					UnsafeNativeMethods.CloseHandle(intPtr);
				}
			}
		}

		internal static void Revert()
		{
			if (UnsafeNativeMethods.RevertToSelf() == 0)
			{
				throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
			}
		}

		internal static string GetPolicyServerName(DirectoryContext context, bool isForest, bool needPdc, string source)
		{
			string text = null;
			PrivateLocatorFlags privateLocatorFlags = PrivateLocatorFlags.DirectoryServicesRequired;
			if (context.isDomain())
			{
				if (needPdc)
				{
					privateLocatorFlags |= PrivateLocatorFlags.PdcRequired;
				}
				return Locator.GetDomainControllerInfo(null, source, null, (long)privateLocatorFlags).DomainControllerName.Substring(2);
			}
			if (isForest)
			{
				if (needPdc)
				{
					privateLocatorFlags |= PrivateLocatorFlags.PdcRequired;
					return Locator.GetDomainControllerInfo(null, source, null, (long)privateLocatorFlags).DomainControllerName.Substring(2);
				}
				if (context.ContextType == DirectoryContextType.DirectoryServer)
				{
					DirectoryEntry directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, WellKnownDN.RootDSE);
					string s = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.DefaultNamingContext);
					string s2 = (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.RootDomainNamingContext);
					if (Compare(s, s2) == 0)
					{
						return context.Name;
					}
					return Locator.GetDomainControllerInfo(null, source, null, (long)privateLocatorFlags).DomainControllerName.Substring(2);
				}
				return Locator.GetDomainControllerInfo(null, source, null, (long)privateLocatorFlags).DomainControllerName.Substring(2);
			}
			return context.Name;
		}

		internal static IntPtr GetPolicyHandle(string serverName)
		{
			IntPtr handle = (IntPtr)0;
			LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES();
			IntPtr intPtr = (IntPtr)0;
			int pOLICY_VIEW_LOCAL_INFORMATION = POLICY_VIEW_LOCAL_INFORMATION;
			LSA_UNICODE_STRING lSA_UNICODE_STRING = new LSA_UNICODE_STRING();
			intPtr = Marshal.StringToHGlobalUni(serverName);
			UnsafeNativeMethods.RtlInitUnicodeString(lSA_UNICODE_STRING, intPtr);
			try
			{
				int num = UnsafeNativeMethods.LsaOpenPolicy(lSA_UNICODE_STRING, objectAttributes, pOLICY_VIEW_LOCAL_INFORMATION, out handle);
				if (num != 0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(UnsafeNativeMethods.LsaNtStatusToWinError(num), serverName);
				}
				return handle;
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					Marshal.FreeHGlobal(intPtr);
				}
			}
		}

		internal static Hashtable GetValuesWithRangeRetrieval(DirectoryEntry searchRootEntry, string filter, ArrayList propertiesToLoad, SearchScope searchScope)
		{
			return GetValuesWithRangeRetrieval(searchRootEntry, filter, propertiesToLoad, new ArrayList(), searchScope);
		}

		internal static Hashtable GetValuesWithRangeRetrieval(DirectoryEntry searchRootEntry, string filter, ArrayList propertiesWithRangeRetrieval, ArrayList propertiesWithoutRangeRetrieval, SearchScope searchScope)
		{
			ADSearcher aDSearcher = new ADSearcher(searchRootEntry, filter, new string[0], searchScope, pagedSearch: false, cacheResults: false);
			SearchResult searchResult = null;
			int num = 0;
			Hashtable hashtable = new Hashtable();
			Hashtable hashtable2 = new Hashtable();
			ArrayList arrayList = new ArrayList();
			ArrayList arrayList2 = new ArrayList();
			foreach (string item in propertiesWithoutRangeRetrieval)
			{
				string text2 = item.ToLower(CultureInfo.InvariantCulture);
				arrayList.Add(text2);
				hashtable.Add(text2, new ArrayList());
				aDSearcher.PropertiesToLoad.Add(item);
			}
			foreach (string item2 in propertiesWithRangeRetrieval)
			{
				string text4 = item2.ToLower(CultureInfo.InvariantCulture);
				arrayList2.Add(text4);
				hashtable.Add(text4, new ArrayList());
			}
			do
			{
				foreach (string item3 in arrayList2)
				{
					string value = item3 + ";range=" + num + "-*";
					aDSearcher.PropertiesToLoad.Add(value);
					hashtable2.Add(item3.ToLower(CultureInfo.InvariantCulture), value);
				}
				arrayList2.Clear();
				searchResult = aDSearcher.FindOne();
				if (searchResult != null)
				{
					foreach (string propertyName in searchResult.Properties.PropertyNames)
					{
						int num2 = propertyName.IndexOf(';');
						string text7 = null;
						text7 = ((num2 == -1) ? propertyName : propertyName.Substring(0, num2));
						if (!hashtable2.Contains(text7) && !arrayList.Contains(text7))
						{
							continue;
						}
						ArrayList arrayList3 = (ArrayList)hashtable[text7];
						arrayList3.AddRange(searchResult.Properties[propertyName]);
						if (hashtable2.Contains(text7))
						{
							string text8 = (string)hashtable2[text7];
							if (propertyName.Length >= text8.Length && Compare(text8, 0, text8.Length, propertyName, 0, text8.Length) != 0)
							{
								arrayList2.Add(text7);
								num += searchResult.Properties[propertyName].Count;
							}
						}
					}
					aDSearcher.PropertiesToLoad.Clear();
					hashtable2.Clear();
					continue;
				}
				throw new ActiveDirectoryObjectNotFoundException(Res.GetString("DSNotFound"));
			}
			while (arrayList2.Count > 0);
			return hashtable;
		}

		internal static ArrayList GetReplicaList(DirectoryContext context, string partitionName, string siteName, bool isDefaultNC, bool isADAM, bool isGC)
		{
			ArrayList arrayList = new ArrayList();
			ArrayList arrayList2 = new ArrayList();
			Hashtable hashtable = new Hashtable();
			Hashtable hashtable2 = new Hashtable();
			StringBuilder stringBuilder = new StringBuilder(10);
			StringBuilder stringBuilder2 = new StringBuilder(10);
			StringBuilder stringBuilder3 = new StringBuilder(10);
			StringBuilder stringBuilder4 = new StringBuilder(10);
			bool flag = false;
			string text = null;
			try
			{
				text = DirectoryEntryManager.ExpandWellKnownDN(context, WellKnownDN.ConfigurationNamingContext);
			}
			catch (COMException e)
			{
				throw ExceptionHelper.GetExceptionFromCOMException(context, e);
			}
			if (partitionName != null && !isDefaultNC)
			{
				DistinguishedName dn = new DistinguishedName(partitionName);
				DistinguishedName distinguishedName = new DistinguishedName(text);
				DistinguishedName distinguishedName2 = new DistinguishedName("CN=Schema," + text);
				if (!distinguishedName.Equals(dn) && !distinguishedName2.Equals(dn))
				{
					flag = true;
				}
			}
			if (flag)
			{
				DirectoryEntry directoryEntry = null;
				DirectoryEntry directoryEntry2 = null;
				try
				{
					directoryEntry = DirectoryEntryManager.GetDirectoryEntry(context, "CN=Partitions," + text);
					string text2 = null;
					text2 = ((!isADAM) ? GetDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner)) : GetAdamDnsHostNameFromNTDSA(context, (string)PropertyManager.GetPropertyValue(context, directoryEntry, PropertyManager.FsmoRoleOwner)));
					DirectoryContext newDirectoryContext = GetNewDirectoryContext(text2, DirectoryContextType.DirectoryServer, context);
					directoryEntry2 = DirectoryEntryManager.GetDirectoryEntry(newDirectoryContext, "CN=Partitions," + text);
					string filter = "(&(" + PropertyManager.ObjectCategory + "=crossRef)(" + PropertyManager.NCName + "=" + GetEscapedFilterValue(partitionName) + "))";
					ArrayList arrayList3 = new ArrayList();
					arrayList3.Add(PropertyManager.MsDSNCReplicaLocations);
					arrayList3.Add(PropertyManager.MsDSNCROReplicaLocations);
					Hashtable hashtable3 = null;
					try
					{
						hashtable3 = GetValuesWithRangeRetrieval(directoryEntry2, filter, arrayList3, SearchScope.OneLevel);
					}
					catch (COMException e2)
					{
						throw ExceptionHelper.GetExceptionFromCOMException(newDirectoryContext, e2);
					}
					catch (ActiveDirectoryObjectNotFoundException)
					{
						return arrayList2;
					}
					ArrayList arrayList4 = (ArrayList)hashtable3[PropertyManager.MsDSNCReplicaLocations.ToLower(CultureInfo.InvariantCulture)];
					ArrayList arrayList5 = (ArrayList)hashtable3[PropertyManager.MsDSNCROReplicaLocations.ToLower(CultureInfo.InvariantCulture)];
					if (arrayList4.Count == 0)
					{
						return arrayList2;
					}
					foreach (string item in arrayList4)
					{
						stringBuilder.Append("(");
						stringBuilder.Append(PropertyManager.DistinguishedName);
						stringBuilder.Append("=");
						stringBuilder.Append(GetEscapedFilterValue(item));
						stringBuilder.Append(")");
						stringBuilder2.Append("(");
						stringBuilder2.Append(PropertyManager.DistinguishedName);
						stringBuilder2.Append("=");
						stringBuilder2.Append(GetEscapedFilterValue(GetPartialDN(item, 1)));
						stringBuilder2.Append(")");
					}
					foreach (string item2 in arrayList5)
					{
						stringBuilder3.Append("(");
						stringBuilder3.Append(PropertyManager.DistinguishedName);
						stringBuilder3.Append("=");
						stringBuilder3.Append(GetEscapedFilterValue(item2));
						stringBuilder3.Append(")");
						stringBuilder4.Append("(");
						stringBuilder4.Append(PropertyManager.DistinguishedName);
						stringBuilder4.Append("=");
						stringBuilder4.Append(GetEscapedFilterValue(GetPartialDN(item2, 1)));
						stringBuilder4.Append(")");
					}
				}
				catch (COMException e3)
				{
					throw ExceptionHelper.GetExceptionFromCOMException(context, e3);
				}
				finally
				{
					directoryEntry?.Dispose();
					directoryEntry2?.Dispose();
				}
			}
			string text5 = null;
			DirectoryEntry directoryEntry3 = null;
			try
			{
				text5 = ((siteName == null) ? ("CN=Sites," + text) : ("CN=Servers,CN=" + siteName + ",CN=Sites," + text));
				directoryEntry3 = DirectoryEntryManager.GetDirectoryEntry(context, text5);
				string text6 = null;
				text6 = ((stringBuilder.ToString().Length == 0) ? (isDefaultNC ? ("(|(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.HasMasterNCs + "=" + GetEscapedFilterValue(partitionName) + "))(&(" + PropertyManager.ObjectCategory + "=nTDSDSARO)(" + PropertyManager.MsDSHasFullReplicaNCs + "=" + GetEscapedFilterValue(partitionName) + "))(" + PropertyManager.ObjectCategory + "=server))") : ((!isGC) ? ("(|(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.ObjectCategory + "=nTDSDSARO)(" + PropertyManager.ObjectCategory + "=server))") : ("(|(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.Options + ":1.2.840.113556.1.4.804:=1))(&(" + PropertyManager.ObjectCategory + "=nTDSDSARO)(" + PropertyManager.Options + ":1.2.840.113556.1.4.804:=1))(" + PropertyManager.ObjectCategory + "=server))"))) : (isGC ? ((stringBuilder3.Length <= 0) ? ("(|(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.Options + ":1.2.840.113556.1.4.804:=1)(" + PropertyManager.MsDSHasMasterNCs + "=" + GetEscapedFilterValue(partitionName) + ")(|" + stringBuilder.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=server)(|" + stringBuilder2.ToString() + ")))") : ("(|(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.Options + ":1.2.840.113556.1.4.804:=1)(" + PropertyManager.MsDSHasMasterNCs + "=" + GetEscapedFilterValue(partitionName) + ")(|" + stringBuilder.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=nTDSDSARO)(" + PropertyManager.Options + ":1.2.840.113556.1.4.804:=1)(|" + stringBuilder3.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=server)(|" + stringBuilder2.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=server)(|" + stringBuilder4.ToString() + ")))")) : ((stringBuilder3.Length <= 0) ? ("(|(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.MsDSHasMasterNCs + "=" + GetEscapedFilterValue(partitionName) + ")(|" + stringBuilder.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=server)(|" + stringBuilder2.ToString() + ")))") : ("(|(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)(" + PropertyManager.MsDSHasMasterNCs + "=" + GetEscapedFilterValue(partitionName) + ")(|" + stringBuilder.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=nTDSDSARO)(|" + stringBuilder3.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=server)(|" + stringBuilder2.ToString() + "))(&(" + PropertyManager.ObjectCategory + "=server)(|" + stringBuilder4.ToString() + ")))"))));
				ADSearcher aDSearcher = new ADSearcher(directoryEntry3, text6, new string[0], SearchScope.Subtree);
				SearchResultCollection searchResultCollection = null;
				bool flag2 = false;
				ArrayList arrayList6 = new ArrayList();
				int num = 0;
				string text7 = PropertyManager.MsDSHasInstantiatedNCs + ";range=0-*";
				aDSearcher.PropertiesToLoad.Add(PropertyManager.DistinguishedName);
				aDSearcher.PropertiesToLoad.Add(PropertyManager.DnsHostName);
				aDSearcher.PropertiesToLoad.Add(text7);
				aDSearcher.PropertiesToLoad.Add(PropertyManager.ObjectCategory);
				if (isADAM)
				{
					aDSearcher.PropertiesToLoad.Add(PropertyManager.MsDSPortLDAP);
				}
				try
				{
					string text8 = "CN=NTDS-DSA";
					string text9 = "CN=NTDS-DSA-RO";
					searchResultCollection = aDSearcher.FindAll();
					try
					{
						foreach (SearchResult item3 in searchResultCollection)
						{
							string text10 = (string)PropertyManager.GetSearchResultPropertyValue(item3, PropertyManager.ObjectCategory);
							if (text10.Length >= text8.Length && Compare(text10, 0, text8.Length, text8, 0, text8.Length) == 0)
							{
								string text11 = (string)PropertyManager.GetSearchResultPropertyValue(item3, PropertyManager.DistinguishedName);
								if (flag)
								{
									if (text10.Length >= text9.Length && Compare(text10, 0, text9.Length, text9, 0, text9.Length) == 0)
									{
										arrayList.Add(text11);
										if (isADAM)
										{
											hashtable2.Add(text11, (int)PropertyManager.GetSearchResultPropertyValue(item3, PropertyManager.MsDSPortLDAP));
										}
										continue;
									}
									string text12 = null;
									if (!item3.Properties.Contains(text7))
									{
										foreach (string propertyName in item3.Properties.PropertyNames)
										{
											if (propertyName.Length >= PropertyManager.MsDSHasInstantiatedNCs.Length && Compare(propertyName, 0, PropertyManager.MsDSHasInstantiatedNCs.Length, PropertyManager.MsDSHasInstantiatedNCs, 0, PropertyManager.MsDSHasInstantiatedNCs.Length) == 0)
											{
												text12 = propertyName;
												break;
											}
										}
									}
									else
									{
										text12 = text7;
									}
									if (text12 == null)
									{
										continue;
									}
									bool flag3 = false;
									int num2 = 0;
									foreach (string item4 in item3.Properties[text12])
									{
										if (item4.Length - 13 >= partitionName.Length && Compare(item4, 13, partitionName.Length, partitionName, 0, partitionName.Length) == 0)
										{
											flag3 = true;
											if (string.Compare(item4, 10, "0", 0, 1, StringComparison.OrdinalIgnoreCase) == 0)
											{
												arrayList.Add(text11);
												if (isADAM)
												{
													hashtable2.Add(text11, (int)PropertyManager.GetSearchResultPropertyValue(item3, PropertyManager.MsDSPortLDAP));
												}
												break;
											}
										}
										num2++;
									}
									if (!flag3 && text12.Length >= text7.Length && Compare(text12, 0, text7.Length, text7, 0, text7.Length) != 0)
									{
										flag2 = true;
										arrayList6.Add(text11);
										num = num2;
									}
								}
								else
								{
									arrayList.Add(text11);
									if (isADAM)
									{
										hashtable2.Add(text11, (int)PropertyManager.GetSearchResultPropertyValue(item3, PropertyManager.MsDSPortLDAP));
									}
								}
							}
							else if (item3.Properties.Contains(PropertyManager.DnsHostName))
							{
								hashtable.Add("CN=NTDS Settings," + (string)PropertyManager.GetSearchResultPropertyValue(item3, PropertyManager.DistinguishedName), (string)PropertyManager.GetSearchResultPropertyValue(item3, PropertyManager.DnsHostName));
							}
						}
					}
					finally
					{
						searchResultCollection?.Dispose();
					}
					if (flag2)
					{
						do
						{
							StringBuilder stringBuilder5 = new StringBuilder(20);
							if (arrayList6.Count > 1)
							{
								stringBuilder5.Append("(|");
							}
							foreach (string item5 in arrayList6)
							{
								stringBuilder5.Append("(");
								stringBuilder5.Append(PropertyManager.NCName);
								stringBuilder5.Append("=");
								stringBuilder5.Append(GetEscapedFilterValue(item5));
								stringBuilder5.Append(")");
							}
							if (arrayList6.Count > 1)
							{
								stringBuilder5.Append(")");
							}
							arrayList6.Clear();
							flag2 = false;
							aDSearcher.Filter = "(&(" + PropertyManager.ObjectCategory + "=nTDSDSA)" + stringBuilder5.ToString() + ")";
							string text15 = PropertyManager.MsDSHasInstantiatedNCs + ";range=" + num + "-*";
							aDSearcher.PropertiesToLoad.Clear();
							aDSearcher.PropertiesToLoad.Add(text15);
							aDSearcher.PropertiesToLoad.Add(PropertyManager.DistinguishedName);
							SearchResultCollection searchResultCollection2 = aDSearcher.FindAll();
							try
							{
								foreach (SearchResult item6 in searchResultCollection2)
								{
									string text16 = (string)PropertyManager.GetSearchResultPropertyValue(item6, PropertyManager.DistinguishedName);
									string text17 = null;
									if (!item6.Properties.Contains(text15))
									{
										foreach (string propertyName2 in item6.Properties.PropertyNames)
										{
											if (string.Compare(propertyName2, 0, PropertyManager.MsDSHasInstantiatedNCs, 0, PropertyManager.MsDSHasInstantiatedNCs.Length, StringComparison.OrdinalIgnoreCase) == 0)
											{
												text17 = propertyName2;
												break;
											}
										}
									}
									else
									{
										text17 = text15;
									}
									if (text17 == null)
									{
										continue;
									}
									bool flag4 = false;
									int num3 = 0;
									foreach (string item7 in item6.Properties[text17])
									{
										if (item7.Length - 13 >= partitionName.Length && Compare(item7, 13, partitionName.Length, partitionName, 0, partitionName.Length) == 0)
										{
											flag4 = true;
											if (string.Compare(item7, 10, "0", 0, 1, StringComparison.OrdinalIgnoreCase) == 0)
											{
												arrayList.Add(text16);
												if (isADAM)
												{
													hashtable2.Add(text16, (int)PropertyManager.GetSearchResultPropertyValue(item6, PropertyManager.MsDSPortLDAP));
												}
												break;
											}
										}
										num3++;
									}
									if (!flag4 && text17.Length >= text15.Length && Compare(text17, 0, text15.Length, text15, 0, text15.Length) != 0)
									{
										flag2 = true;
										arrayList6.Add(text16);
										num += num3;
									}
								}
							}
							finally
							{
								searchResultCollection2.Dispose();
							}
						}
						while (flag2);
					}
				}
				catch (COMException ex2)
				{
					if (ex2.ErrorCode == -2147016656 && siteName != null)
					{
						return arrayList2;
					}
					throw ExceptionHelper.GetExceptionFromCOMException(context, ex2);
				}
			}
			finally
			{
				directoryEntry3?.Dispose();
			}
			foreach (string item8 in arrayList)
			{
				string text21 = (string)hashtable[item8];
				if (text21 == null)
				{
					if (isADAM)
					{
						throw new ActiveDirectoryOperationException(Res.GetString("NoHostNameOrPortNumber", item8));
					}
					throw new ActiveDirectoryOperationException(Res.GetString("NoHostName", item8));
				}
				if (isADAM && hashtable2[item8] == null)
				{
					throw new ActiveDirectoryOperationException(Res.GetString("NoHostNameOrPortNumber", item8));
				}
				if (isADAM)
				{
					arrayList2.Add(text21 + ":" + (int)hashtable2[item8]);
				}
				else
				{
					arrayList2.Add(text21);
				}
			}
			return arrayList2;
		}

		internal static string GetEscapedFilterValue(string filterValue)
		{
			int num = -1;
			char[] anyOf = new char[4] { '(', ')', '*', '\\' };
			num = filterValue.IndexOfAny(anyOf);
			if (num != -1)
			{
				StringBuilder stringBuilder = new StringBuilder(2 * filterValue.Length);
				stringBuilder.Append(filterValue.Substring(0, num));
				for (int i = num; i < filterValue.Length; i++)
				{
					switch (filterValue[i])
					{
					case '(':
						stringBuilder.Append("\\28");
						break;
					case ')':
						stringBuilder.Append("\\29");
						break;
					case '*':
						stringBuilder.Append("\\2A");
						break;
					case '\\':
						stringBuilder.Append("\\5C");
						break;
					default:
						stringBuilder.Append(filterValue[i]);
						break;
					}
				}
				return stringBuilder.ToString();
			}
			return filterValue;
		}

		internal static string GetEscapedPath(string originalPath)
		{
			NativeComInterfaces.IAdsPathname adsPathname = (NativeComInterfaces.IAdsPathname)new NativeComInterfaces.Pathname();
			return adsPathname.GetEscapedElement(0, originalPath);
		}

		internal static int Compare(string s1, string s2, uint compareFlags)
		{
			int num = 0;
			IntPtr intPtr = IntPtr.Zero;
			IntPtr intPtr2 = IntPtr.Zero;
			int num2 = 0;
			int num3 = 0;
			try
			{
				intPtr = Marshal.StringToHGlobalUni(s1);
				num2 = s1.Length;
				intPtr2 = Marshal.StringToHGlobalUni(s2);
				num3 = s2.Length;
				num = NativeMethods.CompareString(LCID, compareFlags, intPtr, num2, intPtr2, num3);
				if (num == 0)
				{
					throw ExceptionHelper.GetExceptionFromErrorCode(Marshal.GetLastWin32Error());
				}
			}
			finally
			{
				if (intPtr != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(intPtr);
				}
				if (intPtr2 != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(intPtr2);
				}
			}
			return num - 2;
		}

		internal static int Compare(string s1, string s2)
		{
			return Compare(s1, s2, DEFAULT_CMP_FLAGS);
		}

		internal static int Compare(string s1, int offset1, int length1, string s2, int offset2, int length2)
		{
			return Compare(s1.Substring(offset1, length1), s2.Substring(offset2, length2));
		}

		internal static int Compare(string s1, int offset1, int length1, string s2, int offset2, int length2, uint compareFlags)
		{
			return Compare(s1.Substring(offset1, length1), s2.Substring(offset2, length2), compareFlags);
		}

		internal static string SplitServerNameAndPortNumber(string serverName, out string portNumber)
		{
			portNumber = null;
			int num = serverName.LastIndexOf(':');
			if (num == -1)
			{
				return serverName;
			}
			if (serverName.StartsWith("["))
			{
				if (serverName.EndsWith("]"))
				{
					serverName = serverName.Substring(1, serverName.Length - 2);
					return serverName;
				}
				int num2 = serverName.LastIndexOf("]:");
				if (num2 == -1 || num2 + 1 != num)
				{
					return serverName;
				}
				portNumber = serverName.Substring(num + 1);
				serverName = serverName.Substring(1, num2 - 1);
				return serverName;
			}
			try
			{
				IPAddress iPAddress = IPAddress.Parse(serverName);
				if (iPAddress.AddressFamily == AddressFamily.InterNetworkV6)
				{
					return serverName;
				}
			}
			catch (FormatException)
			{
			}
			portNumber = serverName.Substring(num + 1);
			serverName = serverName.Substring(0, num);
			return serverName;
		}

		internal static string GetNtAuthorityString()
		{
			if (NTAuthorityString == null)
			{
				SecurityIdentifier securityIdentifier = new SecurityIdentifier("S-1-5-18");
				NTAccount nTAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));
				int length = nTAccount.Value.IndexOf('\\');
				NTAuthorityString = nTAccount.Value.Substring(0, length);
			}
			return NTAuthorityString;
		}

		internal unsafe static IntPtr AddToIntPtr(IntPtr intptr, int offset)
		{
			if (IntPtr.Size == 4)
			{
				uint num = checked((uint)intptr.ToPointer() + (uint)offset);
				return new IntPtr((void*)num);
			}
			return (IntPtr)checked((long)intptr + offset);
		}
	}
	internal enum WellKnownDN
	{
		RootDSE,
		DefaultNamingContext,
		SchemaNamingContext,
		ConfigurationNamingContext,
		PartitionsContainer,
		SitesContainer,
		SystemContainer,
		RidManager,
		Infrastructure,
		RootDomainNamingContext,
		Schema
	}
}
