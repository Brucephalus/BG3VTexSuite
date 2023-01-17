
// C:\WINDOWS\assembly\GAC_32\System.EnterpriseServices\2.0.0.0__b03f5f7f11d50a3a\System.EnterpriseServices.dll
// System.EnterpriseServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: x86
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Collections;
using System.Diagnostics;
using System.DirectoryServices;
using System.EnterpriseServices;
using System.EnterpriseServices.Admin;
using System.EnterpriseServices.Thunk;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Reflection.Emit;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Activation;
using System.Runtime.Remoting.Contexts;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Remoting.MetadataServices;
using System.Runtime.Remoting.Proxies;
using System.Runtime.Remoting.Services;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using System.Text;
using System.Threading;
using System.Transactions;
using System.Xml;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDescription("System.EnterpriseServices.dll")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyDefaultAlias("System.EnterpriseServices.dll")]
[assembly: AssemblyTitle("System.EnterpriseServices.dll")]
[assembly: ComVisible(true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: CLSCompliant(true)]
[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: ApplicationName(".NET Utilities")]
[assembly: ApplicationID("1e246775-2281-484f-8ad4-044c15b86eb7")]
[assembly: Guid("4fb2d46f-efc8-4643-bcd0-6e5bfa6a174c")]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
namespace System.EnterpriseServices
{
	[Serializable]
	[ComVisible(false)]
	public enum TransactionVote
	{
		Commit,
		Abort
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("3C05E54B-A42A-11D2-AFC4-00C04F8EE1C4")]
	internal interface IContextState
	{
		void SetDeactivateOnReturn([In][MarshalAs(UnmanagedType.Bool)] bool bDeactivate);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool GetDeactivateOnReturn();

		void SetMyTransactionVote([In][MarshalAs(UnmanagedType.I4)] TransactionVote txVote);

		[return: MarshalAs(UnmanagedType.I4)]
		TransactionVote GetMyTransactionVote();
	}
	internal enum DtcIsolationLevel
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
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("7D40FCC8-F81E-462e-BBA1-8A99EBDC826C")]
	internal interface IContextTransactionInfo
	{
		[return: MarshalAs(UnmanagedType.Interface)]
		object FetchTransaction();

		void RegisterTransactionProxy([In][MarshalAs(UnmanagedType.Interface)] ITransactionProxy proxy, out Guid guid);

		void GetTxIsolationLevelAndTimeout(out DtcIsolationLevel isoLevel, out int timeout);
	}
	[ComImport]
	[Guid("51372AF4-CAE7-11CF-BE81-00AA00A2FA25")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IGetContextProperties
	{
		int Count { get; }

		object GetProperty([In][MarshalAs(UnmanagedType.BStr)] string name);

		void GetEnumerator(out IEnumerator pEnum);
	}
	[ComImport]
	[Guid("D396DA85-BF8F-11d1-BBAE-00C04FC2FA5F")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IContextProperties
	{
		int Count { get; }

		IEnumerator Enumerate { get; }

		object GetProperty([In][MarshalAs(UnmanagedType.BStr)] string name);

		void SetProperty([In][MarshalAs(UnmanagedType.BStr)] string name, [In][MarshalAs(UnmanagedType.Struct)] object value);

		void RemoveProperty([In][MarshalAs(UnmanagedType.BStr)] string name);
	}
	[ComImport]
	[Guid("41C4F8B3-7439-11D2-98CB-00C04F8EE1C4")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IObjectConstruct
	{
		void Construct([In][MarshalAs(UnmanagedType.Interface)] object obj);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsDual)]
	[Guid("41C4F8B2-7439-11D2-98CB-00C04F8EE1C4")]
	internal interface IObjectConstructString
	{
		string ConstructString
		{
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}
	}
	[ComImport]
	[Guid("51372AE0-CAE7-11CF-BE81-00AA00A2FA25")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IObjectContext
	{
		[return: MarshalAs(UnmanagedType.Interface)]
		object CreateInstance([MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, [MarshalAs(UnmanagedType.LPStruct)] Guid riid);

		void SetComplete();

		void SetAbort();

		void EnableCommit();

		void DisableCommit();

		[PreserveSig]
		[return: MarshalAs(UnmanagedType.Bool)]
		bool IsInTransaction();

		[PreserveSig]
		[return: MarshalAs(UnmanagedType.Bool)]
		bool IsSecurityEnabled();

		[return: MarshalAs(UnmanagedType.Bool)]
		bool IsCallerInRole([In][MarshalAs(UnmanagedType.BStr)] string role);
	}
	[ComImport]
	[Guid("74C08646-CEDB-11CF-8B49-00AA00B8A790")]
	internal interface IDispatchContext
	{
		void CreateInstance([In][MarshalAs(UnmanagedType.BStr)] string bstrProgID, out object pObject);

		void SetComplete();

		void SetAbort();

		void EnableCommit();

		void DisableCommit();

		bool IsInTransaction();

		bool IsSecurityEnabled();

		bool IsCallerInRole([In][MarshalAs(UnmanagedType.BStr)] string bstrRole);

		void Count(out int plCount);

		void Item([In][MarshalAs(UnmanagedType.BStr)] string name, out object pItem);

		void _NewEnum([MarshalAs(UnmanagedType.Interface)] out object ppEnum);

		[return: MarshalAs(UnmanagedType.Interface)]
		object Security();

		[return: MarshalAs(UnmanagedType.Interface)]
		object ContextInfo();
	}
	[ComImport]
	[Guid("E74A7215-014D-11D1-A63C-00A0C911B4E0")]
	internal interface SecurityProperty
	{
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetDirectCallerName();

		[return: MarshalAs(UnmanagedType.BStr)]
		string GetDirectCreatorName();

		[return: MarshalAs(UnmanagedType.BStr)]
		string GetOriginalCallerName();

		[return: MarshalAs(UnmanagedType.BStr)]
		string GetOriginalCreatorName();
	}
	[ComImport]
	[Guid("75B52DDB-E8ED-11D1-93AD-00AA00BA3258")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IObjectContextInfo
	{
		[return: MarshalAs(UnmanagedType.Bool)]
		bool IsInTransaction();

		[return: MarshalAs(UnmanagedType.Interface)]
		object GetTransaction();

		Guid GetTransactionId();

		Guid GetActivityId();

		Guid GetContextId();
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("594BE71A-4BC4-438b-9197-CFD176248B09")]
	internal interface IObjectContextInfo2
	{
		[return: MarshalAs(UnmanagedType.Bool)]
		bool IsInTransaction();

		[return: MarshalAs(UnmanagedType.Interface)]
		object GetTransaction();

		Guid GetTransactionId();

		Guid GetActivityId();

		Guid GetContextId();

		Guid GetPartitionId();

		Guid GetApplicationId();

		Guid GetApplicationInstanceId();
	}
	[ComImport]
	[Guid("51372AEC-CAE7-11CF-BE81-00AA00A2FA25")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IObjectControl
	{
		void Activate();

		void Deactivate();

		[PreserveSig]
		[return: MarshalAs(UnmanagedType.Bool)]
		bool CanBePooled();
	}
	[ComImport]
	[Guid("51372AFD-CAE7-11CF-BE81-00AA00A2FA25")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IPlaybackControl
	{
		void FinalClientRetry();

		void FinalServerRetry();
	}
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	[ComVisible(false)]
	public struct BOID
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
		public byte[] rgb;
	}
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	[ComVisible(false)]
	public struct XACTTRANSINFO
	{
		public BOID uow;

		public int isoLevel;

		public int isoFlags;

		public int grfTCSupported;

		public int grfRMSupported;

		public int grfTCSupportedRetaining;

		public int grfRMSupportedRetaining;
	}
	[ComImport]
	[Guid("0FB15084-AF41-11CE-BD2B-204C4F4F5020")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface ITransaction
	{
		void Commit(int fRetaining, int grfTC, int grfRM);

		void Abort(ref BOID pboidReason, int fRetaining, int fAsync);

		void GetTransactionInfo(out XACTTRANSINFO pinfo);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[SuppressUnmanagedCodeSecurity]
	[Guid("02558374-DF2E-4dae-BD6B-1D5C994F9BDC")]
	internal interface ITransactionProxy
	{
		void Commit(Guid guid);

		void Abort();

		[return: MarshalAs(UnmanagedType.Interface)]
		IDtcTransaction Promote();

		void CreateVoter([MarshalAs(UnmanagedType.Interface)] ITransactionVoterNotifyAsync2 voterNotification, [MarshalAs(UnmanagedType.Interface)] out ITransactionVoterBallotAsync2 voterBallot);

		DtcIsolationLevel GetIsolationLevel();

		Guid GetIdentifier();

		[return: MarshalAs(UnmanagedType.Bool)]
		bool IsReusable();
	}
	[ComImport]
	[SuppressUnmanagedCodeSecurity]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("5433376C-414D-11d3-B206-00C04FC2F3EF")]
	internal interface ITransactionVoterBallotAsync2
	{
		void VoteRequestDone(int hr, int reason);
	}
	[ComImport]
	[SuppressUnmanagedCodeSecurity]
	[Guid("3A6AD9E2-23B9-11cf-AD60-00AA00A74CCD")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ITransactionOutcomeEvents
	{
		void Committed([MarshalAs(UnmanagedType.Bool)] bool retaining, int newUow, int hr);

		void Aborted(int reason, [MarshalAs(UnmanagedType.Bool)] bool retaining, int newUow, int hr);

		void HeuristicDecision(int decision, int reason, int hr);

		void InDoubt();
	}
	[ComImport]
	[Guid("5433376B-414D-11d3-B206-00C04FC2F3EF")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[SuppressUnmanagedCodeSecurity]
	internal interface ITransactionVoterNotifyAsync2
	{
		void Committed([MarshalAs(UnmanagedType.Bool)] bool retaining, int newUow, int hr);

		void Aborted(int reason, [MarshalAs(UnmanagedType.Bool)] bool retaining, int newUow, int hr);

		void HeuristicDecision(int decision, int reason, int hr);

		void InDoubt();

		void VoteRequest();
	}
	[Serializable]
	[ComVisible(false)]
	public enum PropertyLockMode
	{
		SetGet,
		Method
	}
	[Serializable]
	[ComVisible(false)]
	public enum PropertyReleaseMode
	{
		Standard,
		Process
	}
	[ComImport]
	[Guid("2A005C01-A5DE-11CF-9E66-00AA00A3F464")]
	internal interface ISharedProperty
	{
		object Value { get; set; }
	}
	[ComImport]
	[Guid("2A005C07-A5DE-11CF-9E66-00AA00A3F464")]
	internal interface ISharedPropertyGroup
	{
		ISharedProperty CreatePropertyByPosition([In][MarshalAs(UnmanagedType.I4)] int position, out bool fExists);

		ISharedProperty PropertyByPosition(int position);

		ISharedProperty CreateProperty([In][MarshalAs(UnmanagedType.BStr)] string name, out bool fExists);

		ISharedProperty Property([In][MarshalAs(UnmanagedType.BStr)] string name);
	}
	[ComImport]
	[Guid("2A005C0D-A5DE-11CF-9E66-00AA00A3F464")]
	internal interface ISharedPropertyGroupManager
	{
		ISharedPropertyGroup CreatePropertyGroup([In][MarshalAs(UnmanagedType.BStr)] string name, [In][Out][MarshalAs(UnmanagedType.I4)] ref PropertyLockMode dwIsoMode, [In][Out][MarshalAs(UnmanagedType.I4)] ref PropertyReleaseMode dwRelMode, out bool fExist);

		ISharedPropertyGroup Group(string name);

		void GetEnumerator(out IEnumerator pEnum);
	}
	[ComImport]
	[Guid("2A005C11-A5DE-11CF-9E66-00AA00A3F464")]
	internal class xSharedPropertyGroupManager
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		public extern xSharedPropertyGroupManager();
	}
	[ComVisible(false)]
	public sealed class SharedProperty
	{
		private ISharedProperty _x;

		public object Value
		{
			get
			{
				return _x.Value;
			}
			set
			{
				_x.Value = value;
			}
		}

		internal SharedProperty(ISharedProperty prop)
		{
			_x = prop;
		}
	}
	[ComVisible(false)]
	public sealed class SharedPropertyGroup
	{
		private ISharedPropertyGroup _x;

		internal SharedPropertyGroup(ISharedPropertyGroup grp)
		{
			_x = grp;
		}

		public SharedProperty CreatePropertyByPosition(int position, out bool fExists)
		{
			return new SharedProperty(_x.CreatePropertyByPosition(position, out fExists));
		}

		public SharedProperty PropertyByPosition(int position)
		{
			return new SharedProperty(_x.PropertyByPosition(position));
		}

		public SharedProperty CreateProperty(string name, out bool fExists)
		{
			return new SharedProperty(_x.CreateProperty(name, out fExists));
		}

		public SharedProperty Property(string name)
		{
			return new SharedProperty(_x.Property(name));
		}
	}
	[ComVisible(false)]
	public sealed class SharedPropertyGroupManager : IEnumerable
	{
		private ISharedPropertyGroupManager _ex;

		public SharedPropertyGroupManager()
		{
			Platform.Assert(Platform.MTS, "SharedPropertyGroupManager");
			_ex = (ISharedPropertyGroupManager)new xSharedPropertyGroupManager();
		}

		public SharedPropertyGroup CreatePropertyGroup(string name, ref PropertyLockMode dwIsoMode, ref PropertyReleaseMode dwRelMode, out bool fExist)
		{
			return new SharedPropertyGroup(_ex.CreatePropertyGroup(name, ref dwIsoMode, ref dwRelMode, out fExist));
		}

		public SharedPropertyGroup Group(string name)
		{
			return new SharedPropertyGroup(_ex.Group(name));
		}

		public IEnumerator GetEnumerator()
		{
			IEnumerator pEnum = null;
			_ex.GetEnumerator(out pEnum);
			return pEnum;
		}
	}
	[Guid("6619a740-8154-43be-a186-0319578e02db")]
	public interface IRemoteDispatch
	{
		[AutoComplete(true)]
		string RemoteDispatchAutoDone(string s);

		[AutoComplete(false)]
		string RemoteDispatchNotAutoDone(string s);
	}
	[Guid("8165B19E-8D3A-4d0b-80C8-97DE310DB583")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IServicedComponentInfo
	{
		void GetComponentInfo(ref int infoMask, out string[] infoArray);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("C3FCC19E-A970-11d2-8B5A-00A0C9B7C9C4")]
	internal interface IManagedObject
	{
		void GetSerializedBuffer(ref string s);

		void GetObjectIdentity(ref string s, ref int AppDomainID, ref int ccw);
	}
	[Serializable]
	[ServicedComponentProxy]
	public abstract class ServicedComponent : ContextBoundObject, IRemoteDispatch, IDisposable, IManagedObject, IServicedComponentInfo
	{
		private const string c_strFieldGetterName = "FieldGetter";

		private const string c_strFieldSetterName = "FieldSetter";

		private const string c_strIsInstanceOfTypeName = "IsInstanceOfType";

		private const BindingFlags bfLookupAll = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

		private bool _denyRemoteDispatch;

		private MethodInfo _finalize;

		private bool _calledDispose;

		private static RWHashTableEx _finalizeCache;

		private static Type _typeofSC;

		private static MethodBase s_mbFieldGetter;

		private static MethodBase s_mbFieldSetter;

		private static MethodBase s_mbIsInstanceOfType;

		static ServicedComponent()
		{
			_finalizeCache = new RWHashTableEx();
			_typeofSC = typeof(ServicedComponent);
		}

		public ServicedComponent()
		{
			ServicedComponentProxy servicedComponentProxy = RemotingServices.GetRealProxy(this) as ServicedComponentProxy;
			servicedComponentProxy.SuppressFinalizeServer();
			Type type = GetType();
			_denyRemoteDispatch = ServicedComponentInfo.AreMethodsSecure(type);
			bool bFound = false;
			_finalize = _finalizeCache.Get(type, out bFound) as MethodInfo;
			if (!bFound)
			{
				_finalize = GetDeclaredFinalizer(type);
				_finalizeCache.Put(type, _finalize);
			}
			_calledDispose = false;
		}

		void IServicedComponentInfo.GetComponentInfo(ref int infoMask, out string[] infoArray)
		{
			int num = 0;
			ArrayList arrayList = new ArrayList();
			if ((infoMask & System.EnterpriseServices.Thunk.Proxy.INFO_PROCESSID) != 0)
			{
				arrayList.Add(RemotingConfiguration.ProcessId);
				num |= System.EnterpriseServices.Thunk.Proxy.INFO_PROCESSID;
			}
			if ((infoMask & System.EnterpriseServices.Thunk.Proxy.INFO_APPDOMAINID) != 0)
			{
				arrayList.Add(RemotingConfiguration.ApplicationId);
				num |= System.EnterpriseServices.Thunk.Proxy.INFO_APPDOMAINID;
			}
			if ((infoMask & System.EnterpriseServices.Thunk.Proxy.INFO_URI) != 0)
			{
				string objectUri = RemotingServices.GetObjectUri(this);
				if (objectUri == null)
				{
					RemotingServices.Marshal(this);
					objectUri = RemotingServices.GetObjectUri(this);
				}
				arrayList.Add(objectUri);
				num |= System.EnterpriseServices.Thunk.Proxy.INFO_URI;
			}
			infoArray = (string[])arrayList.ToArray(typeof(string));
			infoMask = num;
		}

		private static MethodInfo GetDeclaredFinalizer(Type t)
		{
			MethodInfo methodInfo = null;
			while (t != _typeofSC)
			{
				methodInfo = t.GetMethod("Finalize", BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.NonPublic);
				if (methodInfo != null)
				{
					break;
				}
				t = t.BaseType;
			}
			return methodInfo;
		}

		public static void DisposeObject(ServicedComponent sc)
		{
			RealProxy realProxy = RemotingServices.GetRealProxy(sc);
			if (realProxy is ServicedComponentProxy)
			{
				ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)realProxy;
				RemotingServices.Disconnect(sc);
				servicedComponentProxy.Dispose(disposing: true);
			}
			else if (realProxy is RemoteServicedComponentProxy)
			{
				RemoteServicedComponentProxy remoteServicedComponentProxy = (RemoteServicedComponentProxy)realProxy;
				sc.Dispose();
				remoteServicedComponentProxy.Dispose(disposing: true);
			}
			else
			{
				sc.Dispose();
			}
		}

		protected internal virtual void Activate()
		{
		}

		protected internal virtual void Deactivate()
		{
		}

		protected internal virtual bool CanBePooled()
		{
			return false;
		}

		protected internal virtual void Construct(string s)
		{
		}

		[AutoComplete(true)]
		string IRemoteDispatch.RemoteDispatchAutoDone(string s)
		{
			bool failed = false;
			string result = RemoteDispatchHelper(s, out failed);
			if (failed)
			{
				ContextUtil.SetAbort();
			}
			return result;
		}

		[AutoComplete(false)]
		string IRemoteDispatch.RemoteDispatchNotAutoDone(string s)
		{
			bool failed = false;
			return RemoteDispatchHelper(s, out failed);
		}

		private void CheckMethodAccess(IMessage request)
		{
			MethodBase methodBase = null;
			MethodBase methodBase2 = null;
			if (!(request is IMethodMessage methodMessage))
			{
				throw new UnauthorizedAccessException();
			}
			methodBase = methodMessage.MethodBase;
			if (!(ReflectionCache.ConvertToClassMI(GetType(), methodBase) is MethodBase m))
			{
				throw new UnauthorizedAccessException();
			}
			if (ServicedComponentInfo.HasSpecialMethodAttributes(m))
			{
				throw new UnauthorizedAccessException(Resource.FormatString("ServicedComponentException_SecurityMapping"));
			}
			if ((!methodBase.IsPublic || methodBase.IsStatic) && !IsMethodAllowedRemotely(methodBase))
			{
				throw new UnauthorizedAccessException(Resource.FormatString("ServicedComponentException_SecurityNoPrivateAccess"));
			}
			Type declaringType = methodBase.DeclaringType;
			if (!declaringType.IsPublic && !declaringType.IsNestedPublic)
			{
				throw new UnauthorizedAccessException(Resource.FormatString("ServicedComponentException_SecurityNoPrivateAccess"));
			}
			for (declaringType = methodBase.DeclaringType.DeclaringType; declaringType != null; declaringType = declaringType.DeclaringType)
			{
				if (!declaringType.IsPublic && !declaringType.IsNestedPublic)
				{
					throw new UnauthorizedAccessException(Resource.FormatString("ServicedComponentException_SecurityNoPrivateAccess"));
				}
			}
		}

		internal static bool IsMethodAllowedRemotely(MethodBase method)
		{
			if (s_mbFieldGetter == null)
			{
				s_mbFieldGetter = typeof(object).GetMethod("FieldGetter", BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
			}
			if (s_mbFieldSetter == null)
			{
				s_mbFieldSetter = typeof(object).GetMethod("FieldSetter", BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
			}
			if (s_mbIsInstanceOfType == null)
			{
				s_mbIsInstanceOfType = typeof(MarshalByRefObject).GetMethod("IsInstanceOfType", BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
			}
			if (method != s_mbFieldGetter && method != s_mbFieldSetter)
			{
				return method == s_mbIsInstanceOfType;
			}
			return true;
		}

		private string RemoteDispatchHelper(string s, out bool failed)
		{
			if (_denyRemoteDispatch)
			{
				throw new UnauthorizedAccessException(Resource.FormatString("ServicedComponentException_SecurityMapping"));
			}
			IMessage message = ComponentServices.ConvertToMessage(s, this);
			CheckMethodAccess(message);
			RealProxy realProxy = RemotingServices.GetRealProxy(this);
			IMessage message2 = realProxy.Invoke(message);
			if (message2 is IMethodReturnMessage methodReturnMessage && methodReturnMessage.Exception != null)
			{
				failed = true;
			}
			else
			{
				failed = false;
			}
			return ComponentServices.ConvertToString(message2);
		}

		public void Dispose()
		{
			DisposeObject(this);
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		internal void _callFinalize(bool disposing)
		{
			if (!_calledDispose)
			{
				_calledDispose = true;
				Dispose(disposing);
			}
			if (_finalize != null)
			{
				_finalize.Invoke(this, new object[0]);
			}
		}

		internal void _internalDeactivate(bool disposing)
		{
			ComponentServices.DeactivateObject(this, disposing);
		}

		internal void DoSetCOMIUnknown(IntPtr pUnk)
		{
			RealProxy realProxy = RemotingServices.GetRealProxy(this);
			realProxy.SetCOMIUnknown(pUnk);
		}

		void IManagedObject.GetSerializedBuffer(ref string s)
		{
			throw new NotSupportedException(Resource.GetString("Err_IManagedObjectGetSerializedBuffer"));
		}

		void IManagedObject.GetObjectIdentity(ref string s, ref int AppDomainID, ref int ccw)
		{
			throw new NotSupportedException(Resource.GetString("Err_IManagedObjectGetObjectIdentity"));
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("da91b74e-5388-4783-949d-c1cd5fb00506")]
	internal interface IManagedPoolAction
	{
		void LastRelease();
	}
	internal abstract class ProxyTearoff
	{
		internal ProxyTearoff()
		{
		}

		internal abstract void Init(ServicedComponentProxy scp);

		internal abstract void SetCanBePooled(bool fCanBePooled);
	}
	internal class ClassicProxyTearoff : ProxyTearoff, IObjectControl, IObjectConstruct
	{
		private ServicedComponentProxy _scp;

		private bool _fCanBePooled;

		internal override void Init(ServicedComponentProxy scp)
		{
			_scp = scp;
		}

		internal override void SetCanBePooled(bool fCanBePooled)
		{
			_fCanBePooled = fCanBePooled;
		}

		void IObjectControl.Activate()
		{
			_scp.ActivateObject();
		}

		void IObjectControl.Deactivate()
		{
			ComponentServices.DeactivateObject(_scp.GetTransparentProxy(), disposing: true);
		}

		bool IObjectControl.CanBePooled()
		{
			return _fCanBePooled;
		}

		void IObjectConstruct.Construct(object obj)
		{
			_scp.DispatchConstruct(((IObjectConstructString)obj).ConstructString);
		}
	}
	internal class WeakProxyTearoff : ProxyTearoff, IObjectControl, IObjectConstruct
	{
		private WeakReference _scp;

		private bool _fCanBePooled;

		internal override void Init(ServicedComponentProxy scp)
		{
			_scp = new WeakReference(scp, trackResurrection: true);
		}

		internal override void SetCanBePooled(bool fCanBePooled)
		{
			_fCanBePooled = fCanBePooled;
		}

		void IObjectControl.Activate()
		{
			ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)_scp.Target;
			servicedComponentProxy.ActivateObject();
		}

		void IObjectControl.Deactivate()
		{
			ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)_scp.Target;
			if (servicedComponentProxy != null)
			{
				ComponentServices.DeactivateObject(servicedComponentProxy.GetTransparentProxy(), disposing: true);
			}
		}

		bool IObjectControl.CanBePooled()
		{
			return _fCanBePooled;
		}

		void IObjectConstruct.Construct(object obj)
		{
			ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)_scp.Target;
			servicedComponentProxy.DispatchConstruct(((IObjectConstructString)obj).ConstructString);
		}
	}
	[ComImport]
	[Guid("1427c51a-4584-49d8-90a0-c50d8086cbe9")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IManagedObjectInfo
	{
		void GetIUnknown(out IntPtr pUnk);

		void GetIObjectControl(out IObjectControl pCtrl);

		void SetInPool([MarshalAs(UnmanagedType.Bool)] bool fInPool, IntPtr pPooledObject);

		void SetWrapperStrength([MarshalAs(UnmanagedType.Bool)] bool bStrong);
	}
	internal class ServicedComponentStub : IManagedObjectInfo
	{
		private WeakReference _scp;

		internal ServicedComponentStub(ServicedComponentProxy scp)
		{
			Refresh(scp);
		}

		internal void Refresh(ServicedComponentProxy scp)
		{
			_scp = new WeakReference(scp, trackResurrection: true);
		}

		void IManagedObjectInfo.GetIObjectControl(out IObjectControl pCtrl)
		{
			ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)_scp.Target;
			pCtrl = servicedComponentProxy.GetProxyTearoff() as IObjectControl;
		}

		void IManagedObjectInfo.GetIUnknown(out IntPtr pUnk)
		{
			_ = IntPtr.Zero;
			ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)_scp.Target;
			pUnk = servicedComponentProxy.GetOuterIUnknown();
		}

		void IManagedObjectInfo.SetInPool(bool fInPool, IntPtr pPooledObject)
		{
			ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)_scp.Target;
			servicedComponentProxy.SetInPool(fInPool, pPooledObject);
		}

		void IManagedObjectInfo.SetWrapperStrength(bool bStrong)
		{
			ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)_scp.Target;
			Marshal.ChangeWrapperHandleStrength(servicedComponentProxy.GetTransparentProxy(), !bStrong);
		}
	}
	internal class ServicedComponentProxy : RealProxy, System.EnterpriseServices.Thunk.IProxyInvoke, IManagedPoolAction
	{
		private static readonly IntPtr NegativeOne;

		private static IntPtr _stub;

		private static MethodInfo _getTypeMethod;

		private static MethodInfo _getHashCodeMethod;

		private static MethodBase _getIDisposableDispose;

		private static MethodBase _getServicedComponentDispose;

		private static MethodInfo _internalDeactivateMethod;

		private static MethodInfo _initializeLifetimeServiceMethod;

		private static MethodInfo _getLifetimeServiceMethod;

		private static MethodInfo _getComIUnknownMethod;

		private static MethodInfo _setCOMIUnknownMethod;

		private int _gitCookie;

		private IntPtr _token;

		private IntPtr _context;

		private IntPtr _pPoolUnk;

		private System.EnterpriseServices.Thunk.Tracker _tracker;

		private bool _fIsObjectPooled;

		private bool _fIsJitActivated;

		private bool _fDeliverADC;

		private bool _fUseIntfDispatch;

		private bool _fIsServerActivated;

		private bool _fIsActive;

		private bool _tabled;

		private bool _fFinalized;

		private bool _fReturnedByFinalizer;

		private bool _filterConstructors;

		private ProxyTearoff _proxyTearoff;

		private ServicedComponentStub _scstub;

		private System.EnterpriseServices.Thunk.Callback _callback;

		private static bool _asyncFinalizeEnabled;

		private static Queue _ctxQueue;

		private static Queue _gitQueue;

		private static Thread _cleanupThread;

		private static AutoResetEvent _Wakeup;

		private static ManualResetEvent _exitCleanupThread;

		private static int _QueuedItemsCount;

		private static Guid _s_IID_IObjectControl;

		private static Guid _s_IID_IObjectConstruct;

		private static Guid _s_IID_IManagedObjectInfo;

		private static Guid _s_IID_IManagedPoolAction;

		internal IntPtr HomeToken => _token;

		internal bool IsProxyDeactivated => !_fIsActive;

		internal bool IsJitActivated => _fIsJitActivated;

		internal bool IsObjectPooled => _fIsObjectPooled;

		internal bool AreMethodsSecure => _fUseIntfDispatch;

		static ServicedComponentProxy()
		{
			NegativeOne = new IntPtr(-1);
			_stub = System.EnterpriseServices.Thunk.Proxy.GetContextCheck();
			_getTypeMethod = typeof(object).GetMethod("GetType");
			_getHashCodeMethod = typeof(object).GetMethod("GetHashCode");
			_getIDisposableDispose = typeof(IDisposable).GetMethod("Dispose", new Type[0]);
			_getServicedComponentDispose = typeof(ServicedComponent).GetMethod("Dispose", new Type[0]);
			_internalDeactivateMethod = typeof(ServicedComponent).GetMethod("_internalDeactivate", BindingFlags.Instance | BindingFlags.NonPublic);
			_initializeLifetimeServiceMethod = typeof(MarshalByRefObject).GetMethod("InitializeLifetimeService", new Type[0]);
			_getLifetimeServiceMethod = typeof(MarshalByRefObject).GetMethod("GetLifetimeService", new Type[0]);
			_getComIUnknownMethod = typeof(MarshalByRefObject).GetMethod("GetComIUnknown", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, new Type[1] { typeof(bool) }, null);
			_setCOMIUnknownMethod = typeof(ServicedComponent).GetMethod("DoSetCOMIUnknown", BindingFlags.Instance | BindingFlags.NonPublic);
			_s_IID_IObjectControl = Marshal.GenerateGuidForType(typeof(IObjectControl));
			_s_IID_IObjectConstruct = Marshal.GenerateGuidForType(typeof(IObjectConstruct));
			_s_IID_IManagedObjectInfo = Marshal.GenerateGuidForType(typeof(IManagedObjectInfo));
			_s_IID_IManagedPoolAction = Marshal.GenerateGuidForType(typeof(IManagedPoolAction));
			_asyncFinalizeEnabled = true;
			try
			{
				BooleanSwitch booleanSwitch = new BooleanSwitch("DisableAsyncFinalization");
				_asyncFinalizeEnabled = !booleanSwitch.Enabled;
			}
			catch
			{
				_asyncFinalizeEnabled = true;
			}
			if (_asyncFinalizeEnabled)
			{
				_ctxQueue = new Queue();
				_gitQueue = new Queue();
				_Wakeup = new AutoResetEvent(initialState: false);
				_exitCleanupThread = new ManualResetEvent(initialState: false);
				_cleanupThread = new Thread(QueueCleaner);
				_cleanupThread.IsBackground = true;
				_cleanupThread.Start();
				AppDomain.CurrentDomain.DomainUnload += ShutdownDomain;
			}
		}

		private static void ShutdownDomain(object sender, EventArgs e)
		{
			_exitCleanupThread.Set();
			_Wakeup.Set();
			while (!CleanupQueues(bGit: true))
			{
			}
		}

		private ServicedComponentProxy()
		{
		}

		internal ServicedComponentProxy(Type serverType, bool fIsJitActivated, bool fIsPooled, bool fAreMethodsSecure, bool fCreateRealServer)
			: base(serverType, _stub, -1)
		{
			_gitCookie = 0;
			_fIsObjectPooled = fIsPooled;
			_fIsJitActivated = fIsJitActivated;
			_fDeliverADC = _fIsObjectPooled || _fIsJitActivated;
			_fIsActive = !_fDeliverADC;
			_tabled = false;
			_fUseIntfDispatch = fAreMethodsSecure;
			_context = NegativeOne;
			_token = NegativeOne;
			_tracker = null;
			_callback = new System.EnterpriseServices.Thunk.Callback();
			_pPoolUnk = IntPtr.Zero;
			if (Util.ExtendedLifetime)
			{
				_scstub = new ServicedComponentStub(this);
			}
			if (!fCreateRealServer)
			{
				return;
			}
			try
			{
				ConstructServer();
			}
			catch
			{
				ReleaseContext();
				if (!Util.ExtendedLifetime)
				{
					ReleaseGitCookie();
				}
				_fIsServerActivated = false;
				GC.SuppressFinalize(this);
				throw;
			}
			SendCreationEvents();
		}

		private static void QueueCleaner()
		{
			while (!_exitCleanupThread.WaitOne(0, exitContext: false))
			{
				CleanupQueues(bGit: true);
				if (_gitQueue.Count == 0 && _ctxQueue.Count == 0)
				{
					_Wakeup.WaitOne(2500, exitContext: false);
				}
			}
		}

		internal static bool CleanupQueues(bool bGit)
		{
			bool flag = true;
			bool flag2 = true;
			if (!_asyncFinalizeEnabled)
			{
				return true;
			}
			if (bGit)
			{
				if (_gitQueue.Count > 0)
				{
					bool flag3 = false;
					int cookie = 0;
					lock (_gitQueue)
					{
						if (_gitQueue.Count > 0)
						{
							cookie = (int)_gitQueue.Dequeue();
							flag3 = true;
							flag = _gitQueue.Count <= 0;
						}
					}
					if (flag3)
					{
						System.EnterpriseServices.Thunk.Proxy.RevokeObject(cookie);
					}
				}
			}
			else if (_gitQueue.Count > 0)
			{
				lock (_gitQueue)
				{
					if (_gitQueue.Count > 0 && _QueuedItemsCount < 25)
					{
						try
						{
							ThreadPool.QueueUserWorkItem(RevokeAsync, _gitQueue.Count);
							Interlocked.Increment(ref _QueuedItemsCount);
						}
						catch
						{
						}
					}
				}
			}
			object obj2 = null;
			if (_ctxQueue.Count > 0)
			{
				lock (_ctxQueue)
				{
					if (_ctxQueue.Count > 0)
					{
						obj2 = _ctxQueue.Dequeue();
						flag2 = _ctxQueue.Count <= 0;
					}
				}
				if (obj2 != null)
				{
					if (!Util.ExtendedLifetime)
					{
						Marshal.Release((IntPtr)obj2);
					}
					else
					{
						ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)obj2;
						try
						{
							servicedComponentProxy.SendDestructionEvents(disposing: false);
						}
						catch
						{
						}
						try
						{
							servicedComponentProxy.ReleaseContext();
						}
						catch
						{
						}
					}
				}
			}
			return flag2 && flag;
		}

		internal static void RevokeAsync(object o)
		{
			int num = (int)o;
			try
			{
				for (int i = 0; i < num; i++)
				{
					if (CleanupQueues(bGit: true))
					{
						break;
					}
				}
			}
			catch
			{
			}
			Interlocked.Decrement(ref _QueuedItemsCount);
		}

		private void AssertValid()
		{
			if (_context == NegativeOne || _context == IntPtr.Zero)
			{
				throw new ObjectDisposedException("ServicedComponent");
			}
		}

		private void DispatchActivate()
		{
			if (!_fDeliverADC)
			{
				return;
			}
			_fIsServerActivated = true;
			ServicedComponent servicedComponent = (ServicedComponent)GetTransparentProxy();
			try
			{
				servicedComponent.Activate();
			}
			catch (Exception ex)
			{
				SendDestructionEvents(disposing: false);
				ReleasePoolUnk();
				ReleaseContext();
				ReleaseGitCookie();
				_fIsServerActivated = false;
				try
				{
					EventLog eventLog = new EventLog();
					eventLog.Source = "System.EnterpriseServices";
					string message = Resource.FormatString("Err_ActivationFailed", ex.ToString());
					eventLog.WriteEntry(message, EventLogEntryType.Error);
				}
				catch
				{
				}
				throw new COMException(Resource.FormatString("ServicedComponentException_ActivationFailed"), -2147164123);
			}
			catch
			{
				try
				{
					EventLog eventLog2 = new EventLog();
					eventLog2.Source = "System.EnterpriseServices";
					string message2 = Resource.FormatString("Err_ActivationFailed", Resource.FormatString("Err_NonClsException", "ServicedComponentProxy.DispatchActivate"));
					eventLog2.WriteEntry(message2, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
		}

		private void DispatchDeactivate()
		{
			if (!_fDeliverADC)
			{
				return;
			}
			ServicedComponent servicedComponent = (ServicedComponent)GetTransparentProxy();
			_fIsServerActivated = false;
			try
			{
				if (!_fFinalized)
				{
					servicedComponent.Deactivate();
				}
			}
			catch
			{
			}
			if (!IsObjectPooled)
			{
				return;
			}
			bool canBePooled = false;
			try
			{
				if (!_fFinalized)
				{
					canBePooled = servicedComponent.CanBePooled();
				}
				_proxyTearoff.SetCanBePooled(canBePooled);
			}
			catch
			{
				_proxyTearoff.SetCanBePooled(fCanBePooled: false);
			}
		}

		internal void DispatchConstruct(string str)
		{
			ServicedComponent servicedComponent = (ServicedComponent)GetTransparentProxy();
			servicedComponent.Construct(str);
		}

		internal void ConnectForPooling(ServicedComponentProxy oldscp, ServicedComponent server, ProxyTearoff proxyTearoff, bool fForJit)
		{
			if (oldscp != null)
			{
				_fReturnedByFinalizer = oldscp._fFinalized;
				if (fForJit)
				{
					_pPoolUnk = oldscp._pPoolUnk;
					oldscp._pPoolUnk = IntPtr.Zero;
				}
			}
			if (server != null)
			{
				AttachServer(server);
			}
			_proxyTearoff = proxyTearoff;
			_proxyTearoff.Init(this);
		}

		internal ServicedComponent DisconnectForPooling(ref ProxyTearoff proxyTearoff)
		{
			if (_fIsServerActivated)
			{
				DispatchDeactivate();
			}
			proxyTearoff = _proxyTearoff;
			_proxyTearoff = null;
			if (GetUnwrappedServer() != null)
			{
				return (ServicedComponent)DetachServer();
			}
			return null;
		}

		internal void DeactivateProxy(bool disposing)
		{
			if (_fIsActive)
			{
				object transparentProxy = GetTransparentProxy();
				if (GetUnwrappedServer() != null)
				{
					DispatchDeactivate();
					ServicedComponent servicedComponent = (ServicedComponent)transparentProxy;
					servicedComponent._callFinalize(disposing);
					DetachServer();
				}
				RealProxy.SetStubData(this, NegativeOne);
				_fIsActive = false;
				if (!IsJitActivated)
				{
					ReleaseGitCookie();
				}
				ReleasePoolUnk();
			}
		}

		internal void ActivateObject()
		{
			IntPtr currentContextToken = System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken();
			if (IsObjectPooled && IsJitActivated && HomeToken != currentContextToken)
			{
				object obj = IdentityTable.FindObject(currentContextToken);
				if (obj != null)
				{
					ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)RemotingServices.GetRealProxy(obj);
					ProxyTearoff proxyTearoff = null;
					ServicedComponent server = DisconnectForPooling(ref proxyTearoff);
					proxyTearoff.SetCanBePooled(fCanBePooled: false);
					servicedComponentProxy.ConnectForPooling(this, server, proxyTearoff, fForJit: true);
					EnterpriseServicesHelper.SwitchWrappers(this, servicedComponentProxy);
					servicedComponentProxy.ActivateProxy();
					return;
				}
			}
			ActivateProxy();
		}

		internal void SendCreationEvents()
		{
			if (!Util.ExtendedLifetime || !(_context != IntPtr.Zero) || !(_context != NegativeOne))
			{
				return;
			}
			IntPtr intPtr = SupportsInterface(ref _s_IID_IManagedObjectInfo);
			if (intPtr != IntPtr.Zero)
			{
				try
				{
					System.EnterpriseServices.Thunk.Proxy.SendCreationEvents(_context, intPtr, IsJitActivated);
				}
				finally
				{
					Marshal.Release(intPtr);
				}
			}
		}

		private void ReleasePoolUnk()
		{
			if (_pPoolUnk != IntPtr.Zero)
			{
				IntPtr pPoolUnk = _pPoolUnk;
				_pPoolUnk = IntPtr.Zero;
				System.EnterpriseServices.Thunk.Proxy.PoolUnmark(pPoolUnk);
			}
		}

		internal void SendDestructionEvents(bool disposing)
		{
			if (!Util.ExtendedLifetime || !(_context != IntPtr.Zero) || !(_context != NegativeOne))
			{
				return;
			}
			IntPtr intPtr = SupportsInterface(ref _s_IID_IManagedObjectInfo);
			if (intPtr != IntPtr.Zero)
			{
				try
				{
					System.EnterpriseServices.Thunk.Proxy.SendDestructionEvents(_context, intPtr, disposing);
				}
				finally
				{
					Marshal.Release(intPtr);
				}
			}
		}

		private void SendDestructionEventsAsync()
		{
			if (AppDomain.CurrentDomain.IsFinalizingForUnload())
			{
				SendDestructionEvents(disposing: false);
				return;
			}
			lock (_ctxQueue)
			{
				_ctxQueue.Enqueue(this);
			}
		}

		internal void ConstructServer()
		{
			SetupContext(construction: true);
			IConstructionReturnMessage constructionReturnMessage = InitializeServerObject(null);
			if (constructionReturnMessage != null && constructionReturnMessage.Exception != null)
			{
				ServicedComponent servicedComponent = (ServicedComponent)GetTransparentProxy();
				servicedComponent._callFinalize(disposing: true);
				DetachServer();
				throw constructionReturnMessage.Exception;
			}
		}

		internal void SuppressFinalizeServer()
		{
			GC.SuppressFinalize(GetUnwrappedServer());
		}

		internal void ActivateProxy()
		{
			if (!_fIsActive)
			{
				_fIsActive = true;
				SetupContext(construction: false);
				DispatchActivate();
			}
		}

		internal void FilterConstructors()
		{
			if (_fIsJitActivated)
			{
				throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_BadConfiguration"));
			}
			_filterConstructors = true;
			RealProxy.SetStubData(this, NegativeOne);
		}

		public IntPtr GetOuterIUnknown()
		{
			IntPtr intPtr = IntPtr.Zero;
			IntPtr ppv = IntPtr.Zero;
			try
			{
				intPtr = base.GetCOMIUnknown(fIsMarshalled: false);
				Guid iid = Util.IID_IUnknown;
				int num = Marshal.QueryInterface(intPtr, ref iid, out ppv);
				if (num != 0)
				{
					Marshal.ThrowExceptionForHR(num);
					return ppv;
				}
				return ppv;
			}
			finally
			{
				if (intPtr != IntPtr.Zero)
				{
					Marshal.Release(intPtr);
				}
			}
		}

		public override IntPtr GetCOMIUnknown(bool fIsBeingMarshalled)
		{
			if (_token == IntPtr.Zero || _token == NegativeOne || _token == System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken())
			{
				if (fIsBeingMarshalled)
				{
					IntPtr intPtr = IntPtr.Zero;
					IntPtr zero = IntPtr.Zero;
					try
					{
						intPtr = base.GetCOMIUnknown(fIsMarshalled: false);
						return System.EnterpriseServices.Thunk.Proxy.GetStandardMarshal(intPtr);
					}
					finally
					{
						if (intPtr != IntPtr.Zero)
						{
							Marshal.Release(intPtr);
						}
					}
				}
				return base.GetCOMIUnknown(fIsMarshalled: false);
			}
			if (Util.ExtendedLifetime)
			{
				IntPtr cOMIUnknown = base.GetCOMIUnknown(fIsMarshalled: false);
				IntPtr zero2 = IntPtr.Zero;
				try
				{
					byte[] b = _callback.SwitchMarshal(_context, cOMIUnknown);
					return System.EnterpriseServices.Thunk.Proxy.UnmarshalObject(b);
				}
				finally
				{
					if (cOMIUnknown != IntPtr.Zero)
					{
						Marshal.Release(cOMIUnknown);
					}
				}
			}
			if (_gitCookie == 0)
			{
				return base.GetCOMIUnknown(fIsMarshalled: false);
			}
			return System.EnterpriseServices.Thunk.Proxy.GetObject(_gitCookie);
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public override void SetCOMIUnknown(IntPtr i)
		{
			bool flag = false;
			if (_gitCookie != 0 || Util.ExtendedLifetime)
			{
				return;
			}
			try
			{
				if (i == IntPtr.Zero)
				{
					flag = true;
					i = Marshal.GetIUnknownForObject(GetTransparentProxy());
				}
				_gitCookie = System.EnterpriseServices.Thunk.Proxy.StoreObject(i);
				if (_proxyTearoff != null)
				{
					Marshal.ChangeWrapperHandleStrength(_proxyTearoff, fIsWeak: true);
				}
				Marshal.ChangeWrapperHandleStrength(GetTransparentProxy(), fIsWeak: true);
			}
			finally
			{
				if (flag && i != IntPtr.Zero)
				{
					Marshal.Release(i);
				}
			}
		}

		internal ProxyTearoff GetProxyTearoff()
		{
			if (_proxyTearoff == null)
			{
				if (Util.ExtendedLifetime)
				{
					_proxyTearoff = new WeakProxyTearoff();
				}
				else
				{
					_proxyTearoff = new ClassicProxyTearoff();
				}
				_proxyTearoff.Init(this);
			}
			return _proxyTearoff;
		}

		public override IntPtr SupportsInterface(ref Guid iid)
		{
			if (_s_IID_IObjectControl.Equals(iid))
			{
				return Marshal.GetComInterfaceForObject(GetProxyTearoff(), typeof(IObjectControl));
			}
			if (_s_IID_IObjectConstruct.Equals(iid))
			{
				return Marshal.GetComInterfaceForObject(GetProxyTearoff(), typeof(IObjectConstruct));
			}
			if (_s_IID_IManagedPoolAction.Equals(iid))
			{
				return Marshal.GetComInterfaceForObject(this, typeof(IManagedPoolAction));
			}
			if (Util.ExtendedLifetime && _s_IID_IManagedObjectInfo.Equals(iid))
			{
				return Marshal.GetComInterfaceForObject(_scstub, typeof(IManagedObjectInfo));
			}
			return IntPtr.Zero;
		}

		public override ObjRef CreateObjRef(Type requestedType)
		{
			return new ServicedComponentMarshaler((MarshalByRefObject)GetTransparentProxy(), requestedType);
		}

		public override IMessage Invoke(IMessage request)
		{
			IMessage message = null;
			if (_token == System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken())
			{
				return LocalInvoke(request);
			}
			return CrossCtxInvoke(request);
		}

		public IMessage LocalInvoke(IMessage reqMsg)
		{
			IMessage result = null;
			if (reqMsg is IConstructionCallMessage)
			{
				ActivateProxy();
				if (_filterConstructors)
				{
					_filterConstructors = false;
					RealProxy.SetStubData(this, _token);
				}
				if (((IConstructionCallMessage)reqMsg).ArgCount > 0)
				{
					throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_ConstructorArguments"));
				}
				MarshalByRefObject retObj = (MarshalByRefObject)GetTransparentProxy();
				result = EnterpriseServicesHelper.CreateConstructionReturnMessage((IConstructionCallMessage)reqMsg, retObj);
			}
			else if (reqMsg is IMethodCallMessage)
			{
				result = HandleSpecialMethods(reqMsg);
				if (result != null)
				{
					return result;
				}
				if (GetUnwrappedServer() == null || (IntPtr)RealProxy.GetStubData(this) == NegativeOne)
				{
					throw new ObjectDisposedException("ServicedComponent");
				}
				bool flag = SendMethodCall(reqMsg);
				try
				{
					result = RemotingServices.ExecuteMessage((MarshalByRefObject)GetTransparentProxy(), (IMethodCallMessage)reqMsg);
					if (flag)
					{
						SendMethodReturn(reqMsg, ((IMethodReturnMessage)result).Exception);
						return result;
					}
					return result;
				}
				catch (Exception except)
				{
					if (flag)
					{
						SendMethodReturn(reqMsg, except);
					}
					throw;
				}
				catch
				{
					if (flag)
					{
						SendMethodReturn(reqMsg, null);
					}
					throw;
				}
			}
			return result;
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		private IMessage CrossCtxInvoke(IMessage reqMsg)
		{
			IMessage message = null;
			AssertValid();
			message = HandleDispose(reqMsg);
			if (message != null)
			{
				return message;
			}
			message = HandleSetCOMIUnknown(reqMsg);
			if (message != null)
			{
				return message;
			}
			message = HandleSpecialMethods(reqMsg);
			if (message != null)
			{
				return message;
			}
			object transparentProxy = GetTransparentProxy();
			MethodBase methodBase = ((IMethodMessage)reqMsg).MethodBase;
			MemberInfo memberInfo = methodBase;
			MemberInfo memberInfo2 = memberInfo;
			MemberInfo memberInfo3 = null;
			MemberInfo m = ReflectionCache.ConvertToClassMI(GetProxiedType(), memberInfo);
			bool fIsAutoDone = false;
			int num = ServicedComponentInfo.MICachedLookup(m);
			if (reqMsg is IConstructionCallMessage)
			{
				ComMemberType memberType = ComMemberType.Method;
				memberInfo2 = Marshal.GetMethodInfoForComSlot(typeof(IManagedObject), 3, ref memberType);
			}
			else if ((memberInfo3 = AliasCall(methodBase as MethodInfo)) != null)
			{
				memberInfo2 = memberInfo3;
			}
			else if (_fUseIntfDispatch || ((uint)num & 4u) != 0)
			{
				memberInfo2 = ReflectionCache.ConvertToInterfaceMI(memberInfo);
				if (memberInfo2 == null)
				{
					throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_SecurityMapping"));
				}
			}
			else
			{
				fIsAutoDone = (num & 2) != 0;
			}
			return _callback.DoCallback(transparentProxy, reqMsg, _context, fIsAutoDone, memberInfo2, _gitCookie != 0);
		}

		private MemberInfo AliasCall(MethodInfo mi)
		{
			if (mi == null)
			{
				return null;
			}
			MethodInfo baseDefinition = mi.GetBaseDefinition();
			if (baseDefinition == _internalDeactivateMethod)
			{
				return _getIDisposableDispose;
			}
			if (baseDefinition == _initializeLifetimeServiceMethod || baseDefinition == _getLifetimeServiceMethod || baseDefinition == _getComIUnknownMethod || baseDefinition == _setCOMIUnknownMethod)
			{
				ComMemberType memberType = ComMemberType.Method;
				return Marshal.GetMethodInfoForComSlot(typeof(IManagedObject), 3, ref memberType);
			}
			return null;
		}

		private IMessage HandleDispose(IMessage msg)
		{
			if (msg is IMethodCallMessage methodCallMessage)
			{
				MethodBase methodBase = methodCallMessage.MethodBase;
				if (methodBase == _getServicedComponentDispose || methodBase == _getIDisposableDispose)
				{
					ServicedComponent.DisposeObject((ServicedComponent)GetTransparentProxy());
					IMethodCallMessage methodCallMessage2 = (IMethodCallMessage)msg;
					return new ReturnMessage(null, null, 0, methodCallMessage2.LogicalCallContext, methodCallMessage2);
				}
			}
			return null;
		}

		private IMessage HandleSetCOMIUnknown(IMessage reqMsg)
		{
			MethodBase methodBase = ((IMethodMessage)reqMsg).MethodBase;
			if (methodBase == _setCOMIUnknownMethod)
			{
				IMethodCallMessage methodCallMessage = (IMethodCallMessage)reqMsg;
				IntPtr intPtr = (IntPtr)methodCallMessage.InArgs[0];
				if (intPtr != IntPtr.Zero)
				{
					SetCOMIUnknown(intPtr);
					return new ReturnMessage(null, null, 0, methodCallMessage.LogicalCallContext, methodCallMessage);
				}
			}
			return null;
		}

		private IMessage HandleSpecialMethods(IMessage reqMsg)
		{
			MethodBase methodBase = ((IMethodMessage)reqMsg).MethodBase;
			if (methodBase == _getTypeMethod)
			{
				IMethodCallMessage methodCallMessage = (IMethodCallMessage)reqMsg;
				return new ReturnMessage(GetProxiedType(), null, 0, methodCallMessage.LogicalCallContext, methodCallMessage);
			}
			if (methodBase == _getHashCodeMethod)
			{
				int hashCode = GetHashCode();
				IMethodCallMessage methodCallMessage2 = (IMethodCallMessage)reqMsg;
				return new ReturnMessage(hashCode, null, 0, methodCallMessage2.LogicalCallContext, methodCallMessage2);
			}
			return null;
		}

		private bool IsRealCall(MethodBase mb)
		{
			if (mb == _internalDeactivateMethod || mb == _initializeLifetimeServiceMethod || mb == _getLifetimeServiceMethod || mb == _getComIUnknownMethod || mb == _setCOMIUnknownMethod || mb == _getTypeMethod || mb == _getHashCodeMethod)
			{
				return false;
			}
			return true;
		}

		private bool SendMethodCall(IMessage req)
		{
			bool result = false;
			if (_tracker != null)
			{
				IntPtr intPtr = IntPtr.Zero;
				try
				{
					IMethodCallMessage methodCallMessage = req as IMethodCallMessage;
					if (!IsRealCall(methodCallMessage.MethodBase))
					{
						return false;
					}
					intPtr = ((!Util.ExtendedLifetime) ? GetOuterIUnknown() : SupportsInterface(ref _s_IID_IManagedObjectInfo));
					if (ReflectionCache.ConvertToInterfaceMI(methodCallMessage.MethodBase) is MethodBase method)
					{
						_tracker.SendMethodCall(intPtr, method);
						result = true;
						return result;
					}
					return result;
				}
				catch
				{
					return result;
				}
				finally
				{
					if (intPtr != IntPtr.Zero)
					{
						Marshal.Release(intPtr);
					}
				}
			}
			return result;
		}

		private void SendMethodReturn(IMessage req, Exception except)
		{
			if (_tracker == null)
			{
				return;
			}
			IntPtr intPtr = IntPtr.Zero;
			try
			{
				IMethodCallMessage methodCallMessage = req as IMethodCallMessage;
				if (IsRealCall(methodCallMessage.MethodBase))
				{
					intPtr = ((!Util.ExtendedLifetime) ? GetOuterIUnknown() : SupportsInterface(ref _s_IID_IManagedObjectInfo));
					if (ReflectionCache.ConvertToInterfaceMI(methodCallMessage.MethodBase) is MethodBase method)
					{
						_tracker.SendMethodReturn(intPtr, method, except);
					}
				}
			}
			catch
			{
			}
			finally
			{
				if (intPtr != IntPtr.Zero)
				{
					Marshal.Release(intPtr);
				}
			}
		}

		private void ReleaseGitCookie()
		{
			int num = Interlocked.Exchange(ref _gitCookie, 0);
			if (num != 0)
			{
				System.EnterpriseServices.Thunk.Proxy.RevokeObject(num);
			}
		}

		private void SetupContext(bool construction)
		{
			IntPtr currentContextToken = System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken();
			System.EnterpriseServices.Thunk.IdentityManager.NoticeApartment();
			if (_token != currentContextToken)
			{
				if (_token != NegativeOne)
				{
					ReleaseContext();
				}
				_token = currentContextToken;
				_context = System.EnterpriseServices.Thunk.Proxy.GetCurrentContext();
				_tracker = System.EnterpriseServices.Thunk.Proxy.FindTracker(_context);
			}
			if (!_filterConstructors)
			{
				RealProxy.SetStubData(this, _token);
			}
			if (IsJitActivated && !_tabled && !construction)
			{
				IdentityTable.AddObject(_token, GetTransparentProxy());
				_tabled = true;
			}
		}

		private void ReleaseContext()
		{
			if (_token != NegativeOne)
			{
				object transparentProxy = GetTransparentProxy();
				if (IsJitActivated && _tabled)
				{
					IdentityTable.RemoveObject(_token, transparentProxy);
					_tabled = false;
				}
				if (_tracker != null)
				{
					_tracker.Release();
				}
				Marshal.Release(_context);
				_context = NegativeOne;
				_token = NegativeOne;
			}
		}

		internal void SetInPool(bool fInPool, IntPtr pPooledObject)
		{
			if (!fInPool)
			{
				System.EnterpriseServices.Thunk.Proxy.PoolMark(pPooledObject);
				_pPoolUnk = pPooledObject;
			}
		}

		void IManagedPoolAction.LastRelease()
		{
			if (IsObjectPooled && GetUnwrappedServer() != null)
			{
				ReleaseContext();
				IntPtr currentContextToken = System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken();
				IntPtr currentContext = System.EnterpriseServices.Thunk.Proxy.GetCurrentContext();
				try
				{
					RealProxy.SetStubData(this, currentContextToken);
					((ServicedComponent)GetTransparentProxy())._callFinalize(!_fFinalized && !_fReturnedByFinalizer);
					GC.SuppressFinalize(this);
				}
				finally
				{
					Marshal.Release(currentContext);
					RealProxy.SetStubData(this, _token);
				}
			}
		}

		private void FinalizeHere()
		{
			IntPtr currentContextToken = System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken();
			IntPtr currentContext = System.EnterpriseServices.Thunk.Proxy.GetCurrentContext();
			try
			{
				RealProxy.SetStubData(this, currentContextToken);
				((ServicedComponent)GetTransparentProxy())._callFinalize(disposing: false);
			}
			finally
			{
				Marshal.Release(currentContext);
				RealProxy.SetStubData(this, NegativeOne);
			}
		}

		private void ReleaseContextAsync()
		{
			if (!(_token != NegativeOne))
			{
				return;
			}
			if (AppDomain.CurrentDomain.IsFinalizingForUnload())
			{
				ReleaseContext();
				return;
			}
			object transparentProxy = GetTransparentProxy();
			if (IsJitActivated && _tabled)
			{
				IdentityTable.RemoveObject(_token, transparentProxy);
				_tabled = false;
			}
			lock (_ctxQueue)
			{
				_ctxQueue.Enqueue(_context);
			}
			_context = NegativeOne;
			_token = NegativeOne;
		}

		private void ReleaseGitCookieAsync()
		{
			if (_gitCookie == 0)
			{
				return;
			}
			if (AppDomain.CurrentDomain.IsFinalizingForUnload())
			{
				ReleaseGitCookie();
				return;
			}
			int gitCookie = _gitCookie;
			_gitCookie = 0;
			lock (_gitQueue)
			{
				_gitQueue.Enqueue(gitCookie);
			}
		}

		internal void Dispose(bool disposing)
		{
			if (Util.ExtendedLifetime && (disposing || !_asyncFinalizeEnabled))
			{
				SendDestructionEvents(disposing);
			}
			if (_fIsActive)
			{
				ServicedComponent servicedComponent = (ServicedComponent)GetTransparentProxy();
				try
				{
					servicedComponent._internalDeactivate(disposing);
				}
				catch (ObjectDisposedException)
				{
				}
			}
			if (!disposing && IsObjectPooled && GetUnwrappedServer() != null)
			{
				FinalizeHere();
			}
			ReleasePoolUnk();
			if (Util.ExtendedLifetime && !disposing && _asyncFinalizeEnabled)
			{
				SendDestructionEventsAsync();
			}
			ReleaseGitCookie();
			if (disposing || !_asyncFinalizeEnabled || AppDomain.CurrentDomain.IsFinalizingForUnload())
			{
				ReleaseContext();
			}
			else if (!Util.ExtendedLifetime)
			{
				ReleaseContextAsync();
			}
			_fIsActive = false;
			if (disposing)
			{
				GC.SuppressFinalize(this);
			}
		}

		private void RefreshStub()
		{
			if (_proxyTearoff != null)
			{
				_proxyTearoff.Init(this);
			}
			if (_scstub != null)
			{
				_scstub.Refresh(this);
			}
		}

		~ServicedComponentProxy()
		{
			_fFinalized = true;
			try
			{
				if (_gitCookie != 0)
				{
					GC.ReRegisterForFinalize(this);
					if (_asyncFinalizeEnabled)
					{
						ReleaseGitCookieAsync();
					}
					else
					{
						ReleaseGitCookie();
					}
					if (_proxyTearoff != null)
					{
						Marshal.ChangeWrapperHandleStrength(_proxyTearoff, fIsWeak: false);
					}
					Marshal.ChangeWrapperHandleStrength(GetTransparentProxy(), fIsWeak: false);
				}
				else
				{
					if (Util.ExtendedLifetime)
					{
						RefreshStub();
					}
					Dispose((!(_pPoolUnk == IntPtr.Zero)) ? true : false);
				}
			}
			catch
			{
			}
		}
	}
	internal class MethodCallMessageWrapperEx : MethodCallMessageWrapper
	{
		private MethodBase _mb;

		public override MethodBase MethodBase => _mb;

		public MethodCallMessageWrapperEx(IMethodCallMessage imcmsg, MethodBase mb)
			: base(imcmsg)
		{
			_mb = mb;
		}
	}
	internal class RemoteServicedComponentProxy : RealProxy
	{
		private IntPtr _pUnk;

		private object _server;

		private bool _fUseIntfDispatch;

		private bool _fAttachedServer;

		private volatile RemotingIntermediary _intermediary;

		private static MethodInfo _getTypeMethod = typeof(object).GetMethod("GetType");

		private static MethodInfo _getHashCodeMethod = typeof(object).GetMethod("GetHashCode");

		private static MethodBase _getIDisposableDispose = typeof(IDisposable).GetMethod("Dispose", new Type[0]);

		private static MethodBase _getServicedComponentDispose = typeof(ServicedComponent).GetMethod("Dispose", new Type[0]);

		private Type _pt;

		private Type ProxiedType
		{
			get
			{
				if (_pt == null)
				{
					_pt = GetProxiedType();
				}
				return _pt;
			}
		}

		internal RemotingIntermediary RemotingIntermediary
		{
			get
			{
				if (_intermediary == null)
				{
					lock (this)
					{
						if (_intermediary == null)
						{
							_intermediary = new RemotingIntermediary(this);
						}
					}
				}
				return _intermediary;
			}
		}

		private RemoteServicedComponentProxy()
		{
		}

		private void AssertValid()
		{
			if (_server == null)
			{
				throw new ObjectDisposedException("ServicedComponent");
			}
		}

		private bool IsDisposeRequest(IMessage msg)
		{
			if (msg is IMethodCallMessage methodCallMessage)
			{
				MethodBase methodBase = methodCallMessage.MethodBase;
				if (methodBase == _getServicedComponentDispose || methodBase == _getIDisposableDispose)
				{
					return true;
				}
			}
			return false;
		}

		internal RemoteServicedComponentProxy(Type serverType, IntPtr pUnk, bool fAttachServer)
			: base(serverType)
		{
			_fUseIntfDispatch = ServicedComponentInfo.IsTypeEventSource(serverType) || ServicedComponentInfo.AreMethodsSecure(serverType);
			if (pUnk != IntPtr.Zero)
			{
				_pUnk = pUnk;
				_server = EnterpriseServicesHelper.WrapIUnknownWithComObject(pUnk);
				if (fAttachServer)
				{
					AttachServer((MarshalByRefObject)_server);
					_fAttachedServer = true;
				}
			}
		}

		internal void Dispose(bool disposing)
		{
			object server = _server;
			_server = null;
			if (server != null)
			{
				_pUnk = IntPtr.Zero;
				if (disposing)
				{
					Marshal.ReleaseComObject(server);
				}
				if (_fAttachedServer)
				{
					DetachServer();
					_fAttachedServer = false;
				}
			}
		}

		public override IntPtr GetCOMIUnknown(bool fIsMarshalled)
		{
			if (_server != null)
			{
				return Marshal.GetIUnknownForObject(_server);
			}
			return IntPtr.Zero;
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public override void SetCOMIUnknown(IntPtr pUnk)
		{
			if (_server == null)
			{
				_pUnk = pUnk;
				_server = EnterpriseServicesHelper.WrapIUnknownWithComObject(pUnk);
			}
		}

		public override ObjRef CreateObjRef(Type requestedType)
		{
			return new ServicedComponentMarshaler((MarshalByRefObject)GetTransparentProxy(), requestedType);
		}

		public override IMessage Invoke(IMessage reqMsg)
		{
			AssertValid();
			IMessage message = null;
			if (reqMsg is IConstructionCallMessage)
			{
				if (((IConstructionCallMessage)reqMsg).ArgCount > 0)
				{
					throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_ConstructorArguments"));
				}
				MarshalByRefObject retObj = (MarshalByRefObject)GetTransparentProxy();
				return EnterpriseServicesHelper.CreateConstructionReturnMessage((IConstructionCallMessage)reqMsg, retObj);
			}
			MethodBase methodBase = ((IMethodMessage)reqMsg).MethodBase;
			MemberInfo mi = methodBase;
			if (methodBase == _getTypeMethod)
			{
				IMethodCallMessage methodCallMessage = (IMethodCallMessage)reqMsg;
				return new ReturnMessage(ProxiedType, null, 0, methodCallMessage.LogicalCallContext, methodCallMessage);
			}
			if (methodBase == _getHashCodeMethod)
			{
				int hashCode = GetHashCode();
				IMethodCallMessage methodCallMessage2 = (IMethodCallMessage)reqMsg;
				return new ReturnMessage(hashCode, null, 0, methodCallMessage2.LogicalCallContext, methodCallMessage2);
			}
			MemberInfo m = ReflectionCache.ConvertToClassMI(ProxiedType, mi);
			try
			{
				int num;
				if (_fUseIntfDispatch || ((uint)(num = ServicedComponentInfo.MICachedLookup(m)) & 4u) != 0 || ((uint)num & 8u) != 0)
				{
					MemberInfo memberInfo = ReflectionCache.ConvertToInterfaceMI(mi);
					if (memberInfo == null)
					{
						throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_SecurityMapping"));
					}
					MethodCallMessageWrapperEx reqMsg2 = new MethodCallMessageWrapperEx((IMethodCallMessage)reqMsg, (MethodBase)memberInfo);
					message = RemotingServices.ExecuteMessage((MarshalByRefObject)_server, reqMsg2);
				}
				else
				{
					bool flag = (num & 2) != 0;
					string s = ComponentServices.ConvertToString(reqMsg);
					IRemoteDispatch remoteDispatch = (IRemoteDispatch)_server;
					string s2 = ((!flag) ? remoteDispatch.RemoteDispatchNotAutoDone(s) : remoteDispatch.RemoteDispatchAutoDone(s));
					message = ComponentServices.ConvertToReturnMessage(s2, reqMsg);
				}
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode != Util.CONTEXT_E_ABORTED && ex.ErrorCode != Util.CONTEXT_E_ABORTING)
				{
					throw;
				}
				if (!IsDisposeRequest(reqMsg))
				{
					throw;
				}
				IMethodCallMessage methodCallMessage3 = reqMsg as IMethodCallMessage;
				message = new ReturnMessage(null, null, 0, methodCallMessage3.LogicalCallContext, methodCallMessage3);
			}
			if (IsDisposeRequest(reqMsg))
			{
				Dispose(disposing: true);
			}
			return message;
		}

		~RemoteServicedComponentProxy()
		{
			Dispose(disposing: false);
		}
	}
	internal class BlindMBRO : MarshalByRefObject
	{
		private MarshalByRefObject _holder;

		public BlindMBRO(MarshalByRefObject holder)
		{
			_holder = holder;
		}
	}
	internal class RemotingIntermediary : RealProxy
	{
		private static MethodInfo _initializeLifetimeServiceMethod = typeof(MarshalByRefObject).GetMethod("InitializeLifetimeService", new Type[0]);

		private static MethodInfo _getLifetimeServiceMethod = typeof(MarshalByRefObject).GetMethod("GetLifetimeService", new Type[0]);

		private static MethodInfo _getCOMIUnknownMethod = typeof(MarshalByRefObject).GetMethod("GetComIUnknown", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, new Type[1] { typeof(bool) }, null);

		private static MethodInfo _setCOMIUnknownMethod = typeof(ServicedComponent).GetMethod("DoSetCOMIUnknown", BindingFlags.Instance | BindingFlags.NonPublic);

		private RealProxy _pxy;

		private BlindMBRO _blind;

		internal RemotingIntermediary(RealProxy pxy)
			: base(pxy.GetProxiedType())
		{
			_pxy = pxy;
			_blind = new BlindMBRO((MarshalByRefObject)GetTransparentProxy());
		}

		public override IntPtr GetCOMIUnknown(bool fIsMarshalled)
		{
			return _pxy.GetCOMIUnknown(fIsMarshalled);
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public override void SetCOMIUnknown(IntPtr pUnk)
		{
			_pxy.SetCOMIUnknown(pUnk);
		}

		public override ObjRef CreateObjRef(Type requestedType)
		{
			return new IntermediaryObjRef((MarshalByRefObject)GetTransparentProxy(), requestedType, _pxy);
		}

		private IMessage HandleSpecialMessages(IMessage reqmsg)
		{
			IMethodCallMessage methodCallMessage = reqmsg as IMethodCallMessage;
			MethodBase methodBase = methodCallMessage.MethodBase;
			if (methodBase == _initializeLifetimeServiceMethod)
			{
				return new ReturnMessage(_blind.InitializeLifetimeService(), null, 0, methodCallMessage.LogicalCallContext, methodCallMessage);
			}
			if (methodBase == _getLifetimeServiceMethod)
			{
				return new ReturnMessage(_blind.GetLifetimeService(), null, 0, methodCallMessage.LogicalCallContext, methodCallMessage);
			}
			return null;
		}

		public override IMessage Invoke(IMessage reqmsg)
		{
			IMessage message = HandleSpecialMessages(reqmsg);
			if (message != null)
			{
				return message;
			}
			return _pxy.Invoke(reqmsg);
		}
	}
	internal class IntermediaryObjRef : ObjRef
	{
		private ObjRef _custom;

		public IntermediaryObjRef(MarshalByRefObject mbro, Type reqtype, RealProxy pxy)
			: base(mbro, reqtype)
		{
			_custom = pxy.CreateObjRef(reqtype);
		}

		public override void GetObjectData(SerializationInfo info, StreamingContext ctx)
		{
			object data = CallContext.GetData("__ClientIsClr");
			if (data != null && (bool)data)
			{
				base.GetObjectData(info, ctx);
			}
			else
			{
				_custom.GetObjectData(info, ctx);
			}
		}
	}
	[AttributeUsage(AttributeTargets.Class)]
	internal class ServicedComponentProxyAttribute : ProxyAttribute, ICustomFactory
	{
		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public override MarshalByRefObject CreateInstance(Type serverType)
		{
			RealProxy realProxy = null;
			MarshalByRefObject marshalByRefObject = null;
			ServicedComponentProxy.CleanupQueues(bGit: false);
			if (RemotingConfiguration.IsWellKnownClientType(serverType) != null || RemotingConfiguration.IsRemotelyActivatedClientType(serverType) != null)
			{
				marshalByRefObject = base.CreateInstance(serverType);
				realProxy = RemotingServices.GetRealProxy(marshalByRefObject);
			}
			else
			{
				bool bIsAnotherProcess = false;
				string uri = "";
				bool flag = ServicedComponentInfo.IsTypeEventSource(serverType);
				IntPtr intPtr = System.EnterpriseServices.Thunk.Proxy.CoCreateObject(serverType, !flag, ref bIsAnotherProcess, ref uri);
				if (intPtr != IntPtr.Zero)
				{
					try
					{
						if (flag)
						{
							realProxy = new RemoteServicedComponentProxy(serverType, intPtr, fAttachServer: true);
							marshalByRefObject = (MarshalByRefObject)realProxy.GetTransparentProxy();
						}
						else
						{
							bool flag2 = RemotingConfiguration.IsWellKnownClientType(serverType) != null || null != RemotingConfiguration.IsRemotelyActivatedClientType(serverType);
							if (bIsAnotherProcess && !flag2)
							{
								FastRSCPObjRef objectRef = new FastRSCPObjRef(intPtr, serverType, uri);
								marshalByRefObject = (MarshalByRefObject)RemotingServices.Unmarshal(objectRef);
							}
							else
							{
								marshalByRefObject = (MarshalByRefObject)Marshal.GetObjectForIUnknown(intPtr);
								if (!serverType.IsInstanceOfType(marshalByRefObject))
								{
									throw new InvalidCastException(Resource.FormatString("ServicedComponentException_UnexpectedType", serverType, marshalByRefObject.GetType()));
								}
								realProxy = RemotingServices.GetRealProxy(marshalByRefObject);
								if (!bIsAnotherProcess && !(realProxy is ServicedComponentProxy) && !(realProxy is RemoteServicedComponentProxy))
								{
									ServicedComponent servicedComponent = (ServicedComponent)marshalByRefObject;
									servicedComponent.DoSetCOMIUnknown(intPtr);
								}
							}
						}
					}
					finally
					{
						Marshal.Release(intPtr);
					}
				}
			}
			if (realProxy is ServicedComponentProxy)
			{
				ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)realProxy;
				if (servicedComponentProxy.HomeToken == System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken())
				{
					servicedComponentProxy.FilterConstructors();
				}
			}
			return marshalByRefObject;
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		MarshalByRefObject ICustomFactory.CreateInstance(Type serverType)
		{
			System.EnterpriseServices.Thunk.IdentityManager.NoticeApartment();
			RealProxy realProxy = null;
			ServicedComponentProxy.CleanupQueues(bGit: false);
			int num = ServicedComponentInfo.SCICachedLookup(serverType);
			bool flag = (num & 8) != 0;
			bool fIsPooled = (num & 0x10) != 0;
			bool fAreMethodsSecure = (num & 0x20) != 0;
			if (flag)
			{
				IntPtr currentContextToken = System.EnterpriseServices.Thunk.Proxy.GetCurrentContextToken();
				object obj = IdentityTable.FindObject(currentContextToken);
				if (obj != null)
				{
					realProxy = RemotingServices.GetRealProxy(obj);
				}
			}
			if (realProxy == null)
			{
				realProxy = new ServicedComponentProxy(serverType, flag, fIsPooled, fAreMethodsSecure, fCreateRealServer: true);
			}
			else if (realProxy is ServicedComponentProxy)
			{
				ServicedComponentProxy servicedComponentProxy = (ServicedComponentProxy)realProxy;
				servicedComponentProxy.ConstructServer();
			}
			return (MarshalByRefObject)realProxy.GetTransparentProxy();
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public override RealProxy CreateProxy(ObjRef objRef, Type serverType, object serverObject, Context serverContext)
		{
			if (objRef == null)
			{
				return base.CreateProxy(objRef, serverType, serverObject, serverContext);
			}
			if (objRef is FastRSCPObjRef || (objRef is ServicedComponentMarshaler && (!objRef.IsFromThisProcess() || ServicedComponentInfo.IsTypeEventSource(serverType))))
			{
				object realObject = objRef.GetRealObject(new StreamingContext(StreamingContextStates.Remoting));
				return RemotingServices.GetRealProxy(realObject);
			}
			return base.CreateProxy(objRef, serverType, serverObject, serverContext);
		}
	}
	internal class InterlockedStack
	{
		private class Node
		{
			public object Object;

			public Node Next;

			public Node(object o)
			{
				Object = o;
				Next = null;
			}
		}

		private object _head;

		private int _count;

		public int Count => _count;

		public InterlockedStack()
		{
			_head = null;
		}

		public void Push(object o)
		{
			Node node = new Node(o);
			object head;
			do
			{
				head = _head;
				node.Next = (Node)head;
			}
			while (Interlocked.CompareExchange(ref _head, node, head) != head);
			Interlocked.Increment(ref _count);
		}

		public object Pop()
		{
			object head;
			object next;
			do
			{
				head = _head;
				if (head == null)
				{
					return null;
				}
				next = ((Node)head).Next;
			}
			while (Interlocked.CompareExchange(ref _head, next, head) != head);
			Interlocked.Decrement(ref _count);
			return ((Node)head).Object;
		}
	}
	internal sealed class ComSurrogateSelector : ISurrogateSelector, ISerializationSurrogate
	{
		private ISurrogateSelector _deleg;

		public ComSurrogateSelector()
		{
			_deleg = new RemotingSurrogateSelector();
		}

		public void ChainSelector(ISurrogateSelector next)
		{
			_deleg.ChainSelector(next);
		}

		public ISurrogateSelector GetNextSelector()
		{
			return _deleg.GetNextSelector();
		}

		public ISerializationSurrogate GetSurrogate(Type type, StreamingContext ctx, out ISurrogateSelector selector)
		{
			selector = null;
			if (type.IsCOMObject)
			{
				selector = this;
				return this;
			}
			return _deleg.GetSurrogate(type, ctx, out selector);
		}

		public void GetObjectData(object obj, SerializationInfo info, StreamingContext ctx)
		{
			if (!obj.GetType().IsCOMObject)
			{
				throw new NotSupportedException();
			}
			info.SetType(typeof(ComObjRef));
			info.AddValue("buffer", ComponentServices.GetDCOMBuffer(obj));
		}

		public object SetObjectData(object obj, SerializationInfo info, StreamingContext ctx, ISurrogateSelector sel)
		{
			throw new NotSupportedException();
		}
	}
	[Serializable]
	internal sealed class ComObjRef : IObjectReference, ISerializable
	{
		private object _realobj;

		public ComObjRef(SerializationInfo info, StreamingContext ctx)
		{
			byte[] b = null;
			IntPtr intPtr = IntPtr.Zero;
			SerializationInfoEnumerator enumerator = info.GetEnumerator();
			while (enumerator.MoveNext())
			{
				if (enumerator.Name.Equals("buffer"))
				{
					b = (byte[])enumerator.Value;
				}
			}
			try
			{
				intPtr = System.EnterpriseServices.Thunk.Proxy.UnmarshalObject(b);
				_realobj = Marshal.GetObjectForIUnknown(intPtr);
			}
			finally
			{
				if (intPtr != IntPtr.Zero)
				{
					Marshal.Release(intPtr);
				}
			}
			if (_realobj == null)
			{
				throw new NotSupportedException();
			}
		}

		public object GetRealObject(StreamingContext ctx)
		{
			return _realobj;
		}

		public void GetObjectData(SerializationInfo info, StreamingContext ctx)
		{
			throw new NotSupportedException();
		}
	}
	internal sealed class ComponentSerializer
	{
		private static readonly int MaxBuffersCached = 40;

		private static readonly int MaxCachedBufferLength = 262144;

		private static InterlockedStack _stack = new InterlockedStack();

		private MemoryStream _stream;

		private ISurrogateSelector _selector;

		private BinaryFormatter _formatter;

		private StreamingContext _streamingCtx;

		private HeaderHandler _headerhandler;

		private object _tp;

		public ComponentSerializer()
		{
			_stream = new MemoryStream(0);
			_selector = new ComSurrogateSelector();
			_formatter = new BinaryFormatter();
			_streamingCtx = new StreamingContext(StreamingContextStates.Other);
			_formatter.Context = _streamingCtx;
			_headerhandler = TPHeaderHandler;
		}

		internal void SetStream(byte[] b)
		{
			_stream.SetLength(0L);
			if (b != null)
			{
				_stream.Write(b, 0, b.Length);
				_stream.Position = 0L;
			}
		}

		internal byte[] MarshalToBuffer(object o, out long numBytes)
		{
			SetStream(null);
			_formatter.SurrogateSelector = _selector;
			_formatter.AssemblyFormat = FormatterAssemblyStyle.Full;
			_formatter.Serialize(_stream, o, null);
			numBytes = _stream.Position;
			if (numBytes % 2 != 0)
			{
				_stream.WriteByte(0);
				numBytes++;
			}
			return _stream.GetBuffer();
		}

		public object TPHeaderHandler(Header[] Headers)
		{
			return _tp;
		}

		internal object UnmarshalFromBuffer(byte[] b, object tp)
		{
			object obj = null;
			SetStream(b);
			_tp = tp;
			try
			{
				_formatter.SurrogateSelector = null;
				_formatter.AssemblyFormat = FormatterAssemblyStyle.Simple;
				return _formatter.Deserialize(_stream, _headerhandler);
			}
			finally
			{
				_tp = null;
			}
		}

		internal object UnmarshalReturnMessageFromBuffer(byte[] b, IMethodCallMessage msg)
		{
			SetStream(b);
			_formatter.SurrogateSelector = null;
			_formatter.AssemblyFormat = FormatterAssemblyStyle.Simple;
			return _formatter.DeserializeMethodResponse(_stream, null, msg);
		}

		internal static ComponentSerializer Get()
		{
			ComponentSerializer componentSerializer = (ComponentSerializer)_stack.Pop();
			if (componentSerializer == null)
			{
				componentSerializer = new ComponentSerializer();
			}
			return componentSerializer;
		}

		internal void Release()
		{
			if (_stack.Count < MaxBuffersCached && _stream.Capacity < MaxCachedBufferLength)
			{
				_stack.Push(this);
			}
		}
	}
	internal sealed class ComponentServices
	{
		public static byte[] GetDCOMBuffer(object o)
		{
			int marshalSize = System.EnterpriseServices.Thunk.Proxy.GetMarshalSize(o);
			if (marshalSize == -1)
			{
				throw new RemotingException(Resource.FormatString("Remoting_InteropError"));
			}
			byte[] array = new byte[marshalSize];
			if (!System.EnterpriseServices.Thunk.Proxy.MarshalObject(o, array, marshalSize))
			{
				throw new RemotingException(Resource.FormatString("Remoting_InteropError"));
			}
			return array;
		}

		internal static void InitializeRemotingChannels()
		{
		}

		public static void DeactivateObject(object otp, bool disposing)
		{
			RealProxy realProxy = RemotingServices.GetRealProxy(otp);
			ServicedComponentProxy servicedComponentProxy = realProxy as ServicedComponentProxy;
			if (!servicedComponentProxy.IsProxyDeactivated)
			{
				if (servicedComponentProxy.IsObjectPooled)
				{
					ReconnectForPooling(servicedComponentProxy);
				}
				servicedComponentProxy.DeactivateProxy(disposing);
			}
		}

		private static void ReconnectForPooling(ServicedComponentProxy scp)
		{
			Type proxiedType = scp.GetProxiedType();
			bool isJitActivated = scp.IsJitActivated;
			bool isObjectPooled = scp.IsObjectPooled;
			bool areMethodsSecure = scp.AreMethodsSecure;
			ProxyTearoff proxyTearoff = null;
			ServicedComponent server = scp.DisconnectForPooling(ref proxyTearoff);
			ServicedComponentProxy servicedComponentProxy = new ServicedComponentProxy(proxiedType, isJitActivated, isObjectPooled, areMethodsSecure, fCreateRealServer: false);
			servicedComponentProxy.ConnectForPooling(scp, server, proxyTearoff, fForJit: false);
			EnterpriseServicesHelper.SwitchWrappers(scp, servicedComponentProxy);
			if (proxyTearoff != null)
			{
				Marshal.ChangeWrapperHandleStrength(proxyTearoff, fIsWeak: false);
			}
			Marshal.ChangeWrapperHandleStrength(servicedComponentProxy.GetTransparentProxy(), fIsWeak: false);
		}

		private ComponentServices()
		{
		}

		internal static string ConvertToString(IMessage reqMsg)
		{
			ComponentSerializer componentSerializer = ComponentSerializer.Get();
			long numBytes;
			byte[] bytes = componentSerializer.MarshalToBuffer(reqMsg, out numBytes);
			string @string = GetString(bytes, (int)numBytes);
			componentSerializer.Release();
			return @string;
		}

		internal static IMessage ConvertToMessage(string s, object tp)
		{
			ComponentSerializer componentSerializer = ComponentSerializer.Get();
			byte[] bytes = GetBytes(s);
			IMessage result = (IMessage)componentSerializer.UnmarshalFromBuffer(bytes, tp);
			componentSerializer.Release();
			return result;
		}

		internal static IMessage ConvertToReturnMessage(string s, IMessage mcMsg)
		{
			ComponentSerializer componentSerializer = ComponentSerializer.Get();
			byte[] bytes = GetBytes(s);
			IMessage result = (IMessage)componentSerializer.UnmarshalReturnMessageFromBuffer(bytes, (IMethodCallMessage)mcMsg);
			componentSerializer.Release();
			return result;
		}

		internal unsafe static string GetString(byte[] bytes, int count)
		{
			fixed (byte* ptr = bytes)
			{
				return Marshal.PtrToStringUni((IntPtr)ptr, count / 2);
			}
		}

		internal unsafe static byte[] GetBytes(string s)
		{
			int num = s.Length * 2;
			_ = IntPtr.Zero;
			fixed (char* ptr = s.ToCharArray())
			{
				byte[] array = new byte[num];
				Marshal.Copy((IntPtr)ptr, array, 0, num);
				return array;
			}
		}
	}
	[Serializable]
	[ComVisible(false)]
	public sealed class ServicedComponentException : SystemException
	{
		private const int COR_E_SERVICEDCOMPONENT = -2146233073;

		private static string _default;

		private static string DefaultMessage
		{
			get
			{
				if (_default == null)
				{
					_default = Resource.FormatString("ServicedComponentException_Default");
				}
				return _default;
			}
		}

		public ServicedComponentException()
			: base(DefaultMessage)
		{
			base.HResult = -2146233073;
		}

		public ServicedComponentException(string message)
			: base(message)
		{
			base.HResult = -2146233073;
		}

		public ServicedComponentException(string message, Exception innerException)
			: base(message, innerException)
		{
			base.HResult = -2146233073;
		}

		private ServicedComponentException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	internal class SCUnMarshaler
	{
		private byte[] buffer;

		private Type servertype;

		private RealProxy _rp;

		private bool _fUnMarshaled;

		internal SCUnMarshaler(Type _servertype, byte[] _buffer)
		{
			buffer = _buffer;
			servertype = _servertype;
			_rp = null;
			_fUnMarshaled = false;
		}

		private RealProxy UnmarshalRemoteReference()
		{
			IntPtr intPtr = IntPtr.Zero;
			RealProxy realProxy = null;
			try
			{
				_fUnMarshaled = true;
				if (buffer != null)
				{
					intPtr = System.EnterpriseServices.Thunk.Proxy.UnmarshalObject(buffer);
				}
				return new RemoteServicedComponentProxy(servertype, intPtr, fAttachServer: false);
			}
			finally
			{
				if (intPtr != IntPtr.Zero)
				{
					Marshal.Release(intPtr);
				}
				buffer = null;
			}
		}

		internal RealProxy GetRealProxy()
		{
			if (_rp == null && !_fUnMarshaled)
			{
				_rp = UnmarshalRemoteReference();
			}
			return _rp;
		}

		internal void Dispose()
		{
			if (!_fUnMarshaled && buffer != null)
			{
				System.EnterpriseServices.Thunk.Proxy.ReleaseMarshaledObject(buffer);
			}
		}
	}
	[Serializable]
	internal class ServicedComponentMarshaler : ObjRef
	{
		private RealProxy _rp;

		private SCUnMarshaler _um;

		private Type _rt;

		private bool _marshalled;

		private bool IsMarshaledObject => _marshalled;

		private ServicedComponentMarshaler()
		{
		}

		protected ServicedComponentMarshaler(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
			byte[] buffer = null;
			Type type = null;
			bool flag = false;
			ComponentServices.InitializeRemotingChannels();
			SerializationInfoEnumerator enumerator = info.GetEnumerator();
			while (enumerator.MoveNext())
			{
				if (enumerator.Name.Equals("servertype"))
				{
					type = (Type)enumerator.Value;
				}
				else if (enumerator.Name.Equals("dcomInfo"))
				{
					buffer = (byte[])enumerator.Value;
				}
				else if (enumerator.Name.Equals("fIsMarshalled"))
				{
					int num = 0;
					object value = enumerator.Value;
					if (((value.GetType() != typeof(string)) ? ((int)value) : ((IConvertible)value).ToInt32(null)) == 0)
					{
						flag = true;
					}
				}
			}
			if (!flag)
			{
				_marshalled = true;
			}
			_um = new SCUnMarshaler(type, buffer);
			_rt = type;
			if (IsFromThisProcess() && !ServicedComponentInfo.IsTypeEventSource(type))
			{
				_rp = RemotingServices.GetRealProxy(base.GetRealObject(context));
			}
			else
			{
				if (ServicedComponentInfo.IsTypeEventSource(type))
				{
					TypeInfo = new SCMTypeName(type);
				}
				object realObject = base.GetRealObject(context);
				_rp = RemotingServices.GetRealProxy(realObject);
			}
			_um.Dispose();
		}

		internal ServicedComponentMarshaler(MarshalByRefObject o, Type requestedType)
			: base(o, requestedType)
		{
			_rp = RemotingServices.GetRealProxy(o);
			_rt = requestedType;
		}

		public override object GetRealObject(StreamingContext context)
		{
			if (!IsMarshaledObject)
			{
				return this;
			}
			if (IsFromThisProcess() && !ServicedComponentInfo.IsTypeEventSource(_rt))
			{
				object realObject = base.GetRealObject(context);
				((ServicedComponent)realObject).DoSetCOMIUnknown(IntPtr.Zero);
				return realObject;
			}
			if (_rp == null)
			{
				_rp = _um.GetRealProxy();
			}
			return _rp.GetTransparentProxy();
		}

		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			ComponentServices.InitializeRemotingChannels();
			if (info == null)
			{
				throw new ArgumentNullException("info");
			}
			object data = CallContext.GetData("__ClientIsClr");
			if (data != null && (bool)data)
			{
				if (_rp is RemoteServicedComponentProxy remoteServicedComponentProxy)
				{
					ObjRef objRef = RemotingServices.Marshal((MarshalByRefObject)remoteServicedComponentProxy.RemotingIntermediary.GetTransparentProxy(), null, null);
					objRef.GetObjectData(info, context);
				}
				else
				{
					base.GetObjectData(info, context);
				}
				return;
			}
			base.GetObjectData(info, context);
			info.SetType(typeof(ServicedComponentMarshaler));
			info.AddValue("servertype", _rp.GetProxiedType());
			byte[] dCOMBuffer = ComponentServices.GetDCOMBuffer((MarshalByRefObject)_rp.GetTransparentProxy());
			if (dCOMBuffer != null)
			{
				info.AddValue("dcomInfo", dCOMBuffer);
			}
		}
	}
	[Serializable]
	internal class FastRSCPObjRef : ObjRef
	{
		private IntPtr _pUnk;

		private Type _serverType;

		private RealProxy _rp;

		internal FastRSCPObjRef(IntPtr pUnk, Type serverType, string uri)
		{
			_pUnk = pUnk;
			_serverType = serverType;
			URI = uri;
			TypeInfo = new SCMTypeName(serverType);
			ChannelInfo = new SCMChannelInfo();
		}

		public override object GetRealObject(StreamingContext context)
		{
			return (MarshalByRefObject)(_rp = new RemoteServicedComponentProxy(_serverType, _pUnk, fAttachServer: false)).GetTransparentProxy();
		}

		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			ComponentServices.InitializeRemotingChannels();
			if (info == null)
			{
				throw new ArgumentNullException("info");
			}
			object data = CallContext.GetData("__ClientIsClr");
			if (data != null && (bool)data)
			{
				if (_rp is RemoteServicedComponentProxy remoteServicedComponentProxy)
				{
					ObjRef objRef = RemotingServices.Marshal((MarshalByRefObject)remoteServicedComponentProxy.RemotingIntermediary.GetTransparentProxy(), null, null);
					objRef.GetObjectData(info, context);
				}
				else
				{
					base.GetObjectData(info, context);
				}
				return;
			}
			base.GetObjectData(info, context);
			info.SetType(typeof(ServicedComponentMarshaler));
			info.AddValue("servertype", _rp.GetProxiedType());
			byte[] dCOMBuffer = ComponentServices.GetDCOMBuffer((MarshalByRefObject)_rp.GetTransparentProxy());
			if (dCOMBuffer != null)
			{
				info.AddValue("dcomInfo", dCOMBuffer);
			}
		}
	}
	[Serializable]
	internal class SCMChannelInfo : IChannelInfo
	{
		public virtual object[] ChannelData
		{
			get
			{
				return new object[0];
			}
			set
			{
			}
		}
	}
	[Serializable]
	internal class SCMTypeName : IRemotingTypeInfo
	{
		private Type _serverType;

		private string _serverTypeName;

		public virtual string TypeName
		{
			get
			{
				return _serverTypeName;
			}
			set
			{
				_serverTypeName = value;
			}
		}

		internal SCMTypeName(Type serverType)
		{
			_serverType = serverType;
			_serverTypeName = serverType.AssemblyQualifiedName;
		}

		public virtual bool CanCastTo(Type castType, object o)
		{
			return castType.IsAssignableFrom(_serverType);
		}
	}
	internal static class IdentityTable
	{
		private static Hashtable _table;

		static IdentityTable()
		{
			_table = new Hashtable();
		}

		public static void RemoveObject(IntPtr key, object val)
		{
			lock (_table)
			{
				if (_table[key] is WeakReference weakReference && (weakReference.Target == val || weakReference.Target == null))
				{
					_table.Remove(key);
					weakReference.Target = null;
				}
			}
		}

		public static object FindObject(IntPtr key)
		{
			object result = null;
			lock (_table)
			{
				if (_table[key] is WeakReference weakReference)
				{
					return weakReference.Target;
				}
				return result;
			}
		}

		public static void AddObject(IntPtr key, object val)
		{
			lock (_table)
			{
				if (!(_table[key] is WeakReference weakReference))
				{
					WeakReference value = new WeakReference(val, trackResurrection: false);
					_table.Add(key, value);
				}
				else if (weakReference.Target == null)
				{
					weakReference.Target = val;
				}
			}
		}
	}
	internal class Cachetable
	{
		private Hashtable _cache;

		private ReaderWriterLock _rwlock;

		public Cachetable()
		{
			_cache = new Hashtable();
			_rwlock = new ReaderWriterLock();
		}

		public object Get(object key)
		{
			_rwlock.AcquireReaderLock(-1);
			try
			{
				return _cache[key];
			}
			finally
			{
				_rwlock.ReleaseReaderLock();
			}
		}

		public object Set(object key, object nv)
		{
			_rwlock.AcquireWriterLock(-1);
			try
			{
				object obj = _cache[key];
				if (obj == null)
				{
					_cache[key] = nv;
					return nv;
				}
				return obj;
			}
			finally
			{
				_rwlock.ReleaseWriterLock();
			}
		}

		public void Reset(object key, object nv)
		{
			_rwlock.AcquireWriterLock(-1);
			try
			{
				_cache[key] = nv;
			}
			finally
			{
				_rwlock.ReleaseWriterLock();
			}
		}
	}
	internal static class ReflectionCache
	{
		private static Cachetable Cache = new Cachetable();

		public static MemberInfo ConvertToInterfaceMI(MemberInfo mi)
		{
			MemberInfo memberInfo = (MemberInfo)Cache.Get(mi);
			if (memberInfo != null)
			{
				return memberInfo;
			}
			if (!(mi is MethodInfo methodInfo))
			{
				return null;
			}
			MethodInfo methodInfo2 = null;
			Type reflectedType = methodInfo.ReflectedType;
			if (reflectedType.IsInterface)
			{
				methodInfo2 = methodInfo;
			}
			else
			{
				Type[] interfaces = reflectedType.GetInterfaces();
				if (interfaces == null)
				{
					return null;
				}
				for (int i = 0; i < interfaces.Length; i++)
				{
					InterfaceMapping interfaceMap = reflectedType.GetInterfaceMap(interfaces[i]);
					if (interfaceMap.TargetMethods == null)
					{
						continue;
					}
					for (int j = 0; j < interfaceMap.TargetMethods.Length; j++)
					{
						if (interfaceMap.TargetMethods[j] == methodInfo)
						{
							methodInfo2 = interfaceMap.InterfaceMethods[j];
							break;
						}
					}
					if (methodInfo2 != null)
					{
						break;
					}
				}
			}
			Cache.Reset(mi, methodInfo2);
			return methodInfo2;
		}

		public static MemberInfo ConvertToClassMI(Type t, MemberInfo mi)
		{
			Type reflectedType = mi.ReflectedType;
			if (!reflectedType.IsInterface)
			{
				return mi;
			}
			Cachetable cachetable = (Cachetable)Cache.Get(t);
			if (cachetable != null)
			{
				MemberInfo memberInfo = (MemberInfo)cachetable.Get(mi);
				if (memberInfo != null)
				{
					return memberInfo;
				}
			}
			MethodInfo methodInfo = (MethodInfo)mi;
			MethodInfo methodInfo2 = null;
			InterfaceMapping interfaceMap = t.GetInterfaceMap(reflectedType);
			if (interfaceMap.TargetMethods == null)
			{
				throw new InvalidCastException();
			}
			for (int i = 0; i < interfaceMap.TargetMethods.Length; i++)
			{
				if (interfaceMap.InterfaceMethods[i] == methodInfo)
				{
					methodInfo2 = interfaceMap.TargetMethods[i];
					break;
				}
			}
			if (cachetable == null)
			{
				cachetable = (Cachetable)Cache.Set(t, new Cachetable());
			}
			cachetable.Reset(mi, methodInfo2);
			return methodInfo2;
		}
	}
	[ComImport]
	[Guid("000001c0-0000-0000-C000-000000000046")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IContext
	{
		void SetProperty([In][MarshalAs(UnmanagedType.LPStruct)] Guid policyId, [In] int flags, [In][MarshalAs(UnmanagedType.Interface)] object punk);

		void RemoveProperty([In][MarshalAs(UnmanagedType.LPStruct)] Guid policyId);

		void GetProperty([In][MarshalAs(UnmanagedType.LPStruct)] Guid policyId, out int flags, [MarshalAs(UnmanagedType.Interface)] out object pUnk);
	}
	[ComImport]
	[Guid("a5f325af-572f-46da-b8ab-827c3d95d99e")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IManagedActivationEvents
	{
		void CreateManagedStub(IManagedObjectInfo pInfo, [MarshalAs(UnmanagedType.Bool)] bool fDist);

		void DestroyManagedStub(IManagedObjectInfo pInfo);
	}
	[ComImport]
	[Guid("4E31107F-8E81-11d1-9DCE-00C04FC2FBA2")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ITxStreamInternal
	{
		void GetTransaction(out ITransaction ptx);

		[PreserveSig]
		Guid GetGuid();

		[PreserveSig]
		[return: MarshalAs(UnmanagedType.Bool)]
		bool TxIsDoomed();
	}
	[ComImport]
	[Guid("788ea814-87b1-11d1-bba6-00c04fc2fa5f")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ITransactionProperty
	{
		[PreserveSig]
		void SetConsistent(bool fConsistent);

		void GetTransaction(out ITransaction ptx);

		[PreserveSig]
		void GetTxStream(out ITxStreamInternal ptsi);

		[PreserveSig]
		Guid GetTxStreamGuid();

		[PreserveSig]
		int GetTxStreamMarshalSize();

		[PreserveSig]
		int GetTxStreamMarshalBuffer();

		[PreserveSig]
		short GetUnmarshalVariant();

		[PreserveSig]
		[return: MarshalAs(UnmanagedType.Bool)]
		bool NeedEnvoy();

		[PreserveSig]
		short GetRootDtcCapabilities();

		[PreserveSig]
		int GetTransactionResourcePool(out ITransactionResourcePool pool);

		void GetTransactionId(ref Guid guid);

		object GetClassInfo();

		[PreserveSig]
		[return: MarshalAs(UnmanagedType.Bool)]
		bool IsRoot();
	}
	[Serializable]
	internal sealed class TransactionProxyException : COMException
	{
		private TransactionProxyException(int hr, TransactionException exception)
			: base(null, exception)
		{
			base.HResult = hr;
		}

		private TransactionProxyException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}

		public static void ThrowTransactionProxyException(int hr, TransactionException exception)
		{
			throw new TransactionProxyException(hr, exception);
		}
	}
	internal sealed class TransactionProxy : MarshalByRefObject, ITransactionProxy
	{
		private CommittableTransaction committableTx;

		private Transaction systemTx;

		private Guid ownerGuid;

		private bool owned;

		internal Transaction SystemTransaction => systemTx;

		private void MapTxExceptionToHR(TransactionException txException)
		{
			MapTxExceptionToHR(txException, isInCommit: false);
		}

		private void MapTxExceptionToHR(TransactionException txException, bool isInCommit)
		{
			if (txException is TransactionAbortedException exception)
			{
				if (isInCommit)
				{
					TransactionProxyException.ThrowTransactionProxyException(Util.CONTEXT_E_ABORTED, exception);
				}
				else
				{
					TransactionProxyException.ThrowTransactionProxyException(Util.CONTEXT_E_ABORTING, exception);
				}
			}
			if (txException is TransactionManagerCommunicationException exception2)
			{
				TransactionProxyException.ThrowTransactionProxyException(Util.CONTEXT_E_TMNOTAVAILABLE, exception2);
			}
			if (txException.GetBaseException() is COMException ex)
			{
				TransactionProxyException.ThrowTransactionProxyException(ex.ErrorCode, txException);
			}
			else
			{
				TransactionProxyException.ThrowTransactionProxyException(Util.E_UNEXPECTED, txException);
			}
		}

		public TransactionProxy(DtcIsolationLevel isoLevel, int timeout)
		{
			committableTx = new CommittableTransaction(new TransactionOptions
			{
				Timeout = TimeSpan.FromSeconds(timeout),
				IsolationLevel = ConvertIsolationLevelFromDtc(isoLevel)
			});
			systemTx = committableTx.Clone();
			owned = false;
		}

		public Guid GetIdentifier()
		{
			try
			{
				_ = (ITransaction)TransactionInterop.GetDtcTransaction(systemTx);
				return systemTx.TransactionInformation.DistributedIdentifier;
			}
			catch (TransactionException txException)
			{
				MapTxExceptionToHR(txException);
			}
			return Guid.Empty;
		}

		public bool IsReusable()
		{
			return false;
		}

		public void SetOwnerGuid(Guid guid)
		{
			ownerGuid = guid;
			owned = true;
		}

		public TransactionProxy(Transaction systemTx)
		{
			this.systemTx = systemTx;
			owned = false;
		}

		internal static IsolationLevel ConvertIsolationLevelFromDtc(DtcIsolationLevel proxyIsolationLevel)
		{
			return proxyIsolationLevel switch
			{
				DtcIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE => IsolationLevel.Serializable, 
				DtcIsolationLevel.ISOLATIONLEVEL_REPEATABLEREAD => IsolationLevel.RepeatableRead, 
				DtcIsolationLevel.ISOLATIONLEVEL_CURSORSTABILITY => IsolationLevel.ReadCommitted, 
				DtcIsolationLevel.ISOLATIONLEVEL_READUNCOMMITTED => IsolationLevel.ReadUncommitted, 
				_ => IsolationLevel.Serializable, 
			};
		}

		public void Commit(Guid guid)
		{
			try
			{
				if (committableTx == null)
				{
					Marshal.ThrowExceptionForHR(Util.E_UNEXPECTED);
				}
				else if (owned)
				{
					if (guid == ownerGuid)
					{
						committableTx.Commit();
					}
					else
					{
						Marshal.ThrowExceptionForHR(Util.E_UNEXPECTED);
					}
				}
				else
				{
					committableTx.Commit();
				}
			}
			catch (TransactionException txException)
			{
				MapTxExceptionToHR(txException, isInCommit: true);
			}
			finally
			{
				committableTx.Dispose();
				committableTx = null;
				systemTx = null;
			}
		}

		public void Abort()
		{
			try
			{
				systemTx.Rollback();
			}
			catch (TransactionException txException)
			{
				MapTxExceptionToHR(txException);
			}
			finally
			{
				if (committableTx != null)
				{
					committableTx.Dispose();
					committableTx = null;
					systemTx = null;
				}
			}
		}

		public IDtcTransaction Promote()
		{
			try
			{
				return TransactionInterop.GetDtcTransaction(systemTx);
			}
			catch (TransactionException txException)
			{
				MapTxExceptionToHR(txException);
			}
			return null;
		}

		public void CreateVoter(ITransactionVoterNotifyAsync2 voterNotification, out ITransactionVoterBallotAsync2 voterBallot)
		{
			voterBallot = null;
			try
			{
				if (voterNotification == null)
				{
					throw new ArgumentNullException("voterNotification");
				}
				voterBallot = new VoterBallot(voterNotification, systemTx);
			}
			catch (TransactionException txException)
			{
				MapTxExceptionToHR(txException);
			}
		}

		public DtcIsolationLevel GetIsolationLevel()
		{
			try
			{
				return systemTx.IsolationLevel switch
				{
					IsolationLevel.Serializable => DtcIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE, 
					IsolationLevel.RepeatableRead => DtcIsolationLevel.ISOLATIONLEVEL_REPEATABLEREAD, 
					IsolationLevel.ReadCommitted => DtcIsolationLevel.ISOLATIONLEVEL_CURSORSTABILITY, 
					IsolationLevel.ReadUncommitted => DtcIsolationLevel.ISOLATIONLEVEL_READUNCOMMITTED, 
					_ => DtcIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE, 
				};
			}
			catch (TransactionException txException)
			{
				MapTxExceptionToHR(txException);
			}
			return DtcIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE;
		}
	}
	internal class VoterBallot : ITransactionVoterBallotAsync2, IEnlistmentNotification
	{
		private const int S_OK = 0;

		private ITransactionVoterNotifyAsync2 notification;

		private Transaction transaction;

		private Enlistment enlistment;

		private PreparingEnlistment preparingEnlistment;

		internal VoterBallot(ITransactionVoterNotifyAsync2 notification, Transaction transaction)
		{
			this.transaction = transaction;
			this.notification = notification;
			enlistment = transaction.EnlistVolatile(this, EnlistmentOptions.None);
		}

		public void Prepare(PreparingEnlistment enlistment)
		{
			preparingEnlistment = enlistment;
			notification.VoteRequest();
		}

		public void Rollback(Enlistment enlistment)
		{
			enlistment.Done();
			notification.Aborted(0, retaining: false, 0, 0);
			Marshal.ReleaseComObject(notification);
			notification = null;
		}

		public void Commit(Enlistment enlistment)
		{
			enlistment.Done();
			notification.Committed(retaining: false, 0, 0);
			Marshal.ReleaseComObject(notification);
			notification = null;
		}

		public void InDoubt(Enlistment enlistment)
		{
			enlistment.Done();
			notification.InDoubt();
			Marshal.ReleaseComObject(notification);
			notification = null;
		}

		public void VoteRequestDone(int hr, int reason)
		{
			if (preparingEnlistment == null)
			{
				Marshal.ThrowExceptionForHR(Util.E_FAIL);
			}
			if (hr == 0)
			{
				preparingEnlistment.Prepared();
			}
			else
			{
				preparingEnlistment.ForceRollback();
			}
		}
	}
	public sealed class ContextUtil
	{
		internal static readonly Guid GUID_TransactionProperty = new Guid("ecabaeb1-7f19-11d2-978e-0000f8757e2a");

		internal static readonly Guid GUID_JitActivationPolicy = new Guid("ecabaeb2-7f19-11d2-978e-0000f8757e2a");

		internal static object ObjectContext
		{
			get
			{
				Platform.Assert(Platform.MTS, "ContextUtil.ObjectContext");
				IObjectContext pCtx = null;
				int objectContext = Util.GetObjectContext(out pCtx);
				if (objectContext == 0)
				{
					return pCtx;
				}
				if (objectContext == Util.E_NOINTERFACE || objectContext == Util.CONTEXT_E_NOCONTEXT)
				{
					throw new COMException(Resource.FormatString("Err_NoContext"), Util.CONTEXT_E_NOCONTEXT);
				}
				Marshal.ThrowExceptionForHR(objectContext);
				return null;
			}
		}

		internal static object SafeObjectContext
		{
			get
			{
				Platform.Assert(Platform.MTS, "ContextUtil.ObjectContext");
				IObjectContext pCtx = null;
				int objectContext = Util.GetObjectContext(out pCtx);
				if (objectContext == 0)
				{
					return pCtx;
				}
				if (objectContext != Util.E_NOINTERFACE && objectContext != Util.CONTEXT_E_NOCONTEXT)
				{
					Marshal.ThrowExceptionForHR(objectContext);
				}
				return null;
			}
		}

		public static bool IsInTransaction => System.EnterpriseServices.Thunk.ContextThunk.IsInTransaction();

		public static bool IsSecurityEnabled
		{
			get
			{
				Platform.Assert(Platform.MTS, "ContextUtil.IsSecurityEnabled");
				try
				{
					return ((IObjectContext)ObjectContext).IsSecurityEnabled();
				}
				catch
				{
					return false;
				}
			}
		}

		public static object Transaction
		{
			get
			{
				Platform.Assert(Platform.W2K, "ContextUtil.Transaction");
				return System.EnterpriseServices.Thunk.ContextThunk.GetTransaction();
			}
		}

		public static Transaction SystemTransaction
		{
			get
			{
				Platform.Assert(Platform.W2K, "ContextUtil.SystemTransaction");
				object ppTx = null;
				System.EnterpriseServices.Thunk.TxInfo txInfo = new System.EnterpriseServices.Thunk.TxInfo();
				if (System.EnterpriseServices.Thunk.ContextThunk.GetTransactionProxyOrTransaction(ref ppTx, txInfo))
				{
					if (txInfo.isDtcTransaction)
					{
						return TransactionInterop.GetTransactionFromDtcTransaction((IDtcTransaction)ppTx);
					}
					if (ppTx == null)
					{
						TransactionProxy transactionProxy = new TransactionProxy((DtcIsolationLevel)txInfo.IsolationLevel, txInfo.timeout);
						Guid ownerGuid = System.EnterpriseServices.Thunk.ContextThunk.RegisterTransactionProxy(transactionProxy);
						transactionProxy.SetOwnerGuid(ownerGuid);
						return transactionProxy.SystemTransaction;
					}
					if (ppTx is TransactionProxy transactionProxy2)
					{
						return transactionProxy2.SystemTransaction;
					}
					IDtcTransaction transactionNative = System.EnterpriseServices.Thunk.ContextThunk.GetTransaction() as IDtcTransaction;
					Transaction transactionFromDtcTransaction = TransactionInterop.GetTransactionFromDtcTransaction(transactionNative);
					Marshal.ReleaseComObject(ppTx);
					return transactionFromDtcTransaction;
				}
				return null;
			}
		}

		public static Guid TransactionId
		{
			get
			{
				Platform.Assert(Platform.W2K, "ContextUtil.TransactionId");
				return System.EnterpriseServices.Thunk.ContextThunk.GetTransactionId();
			}
		}

		public static Guid ContextId
		{
			get
			{
				Platform.Assert(Platform.W2K, "ContextUtil.ContextId");
				return ((IObjectContextInfo)ObjectContext).GetContextId();
			}
		}

		public static Guid ActivityId
		{
			get
			{
				Platform.Assert(Platform.W2K, "ContextUtil.ActivityId");
				return ((IObjectContextInfo)ObjectContext).GetActivityId();
			}
		}

		public static TransactionVote MyTransactionVote
		{
			get
			{
				Platform.Assert(Platform.W2K, "ContextUtil.MyTransactionVote");
				return (TransactionVote)System.EnterpriseServices.Thunk.ContextThunk.GetMyTransactionVote();
			}
			set
			{
				Platform.Assert(Platform.W2K, "ContextUtil.MyTransactionVote");
				System.EnterpriseServices.Thunk.ContextThunk.SetMyTransactionVote((int)value);
			}
		}

		public static bool DeactivateOnReturn
		{
			get
			{
				Platform.Assert(Platform.W2K, "ContextUtil.DeactivateOnReturn");
				return System.EnterpriseServices.Thunk.ContextThunk.GetDeactivateOnReturn();
			}
			set
			{
				Platform.Assert(Platform.W2K, "ContextUtil.DeactivateOnReturn");
				System.EnterpriseServices.Thunk.ContextThunk.SetDeactivateOnReturn(value);
			}
		}

		public static Guid PartitionId
		{
			get
			{
				Platform.Assert(Platform.Whistler, "ContextUtil.PartitionId");
				return ((IObjectContextInfo2)ObjectContext).GetPartitionId();
			}
		}

		public static Guid ApplicationId
		{
			get
			{
				Platform.Assert(Platform.Whistler, "ContextUtil.ApplicationId");
				return ((IObjectContextInfo2)ObjectContext).GetApplicationId();
			}
		}

		public static Guid ApplicationInstanceId
		{
			get
			{
				Platform.Assert(Platform.Whistler, "ContextUtil.ApplicationInstanceId");
				return ((IObjectContextInfo2)ObjectContext).GetApplicationInstanceId();
			}
		}

		private ContextUtil()
		{
		}

		public static void EnableCommit()
		{
			Platform.Assert(Platform.MTS, "ContextUtil.EnableCommit");
			System.EnterpriseServices.Thunk.ContextThunk.EnableCommit();
		}

		public static void DisableCommit()
		{
			Platform.Assert(Platform.MTS, "ContextUtil.DisableCommit");
			System.EnterpriseServices.Thunk.ContextThunk.DisableCommit();
		}

		public static void SetComplete()
		{
			Platform.Assert(Platform.MTS, "ContextUtil.SetComplete");
			System.EnterpriseServices.Thunk.ContextThunk.SetComplete();
		}

		public static void SetAbort()
		{
			Platform.Assert(Platform.MTS, "ContextUtil.SetAbort");
			System.EnterpriseServices.Thunk.ContextThunk.SetAbort();
		}

		public static bool IsCallerInRole(string role)
		{
			Platform.Assert(Platform.MTS, "ContextUtil.IsCallerInRole");
			return ((IObjectContext)ObjectContext).IsCallerInRole(role);
		}

		public static bool IsDefaultContext()
		{
			return System.EnterpriseServices.Thunk.ContextThunk.IsDefaultContext();
		}

		public static object GetNamedProperty(string name)
		{
			Platform.Assert(Platform.W2K, "ContextUtil.GetNamedProperty");
			return ((IGetContextProperties)ObjectContext).GetProperty(name);
		}

		public static void SetNamedProperty(string name, object value)
		{
			Platform.Assert(Platform.W2K, "ContextUtil.SetNamedProperty");
			IContextProperties contextProperties = (IContextProperties)ObjectContext;
			contextProperties.SetProperty(name, value);
		}
	}
	[ComImport]
	[Guid("CAFC823D-B441-11D1-B82B-0000F8757E2A")]
	internal interface ISecurityCallersColl
	{
		int Count
		{
			[DispId(1610743808)]
			get;
		}

		[DispId(0)]
		ISecurityIdentityColl GetItem(int lIndex);

		[DispId(-4)]
		void GetEnumerator(out IEnumerator pEnum);
	}
	[ComImport]
	[Guid("CAFC823C-B441-11D1-B82B-0000F8757E2A")]
	internal interface ISecurityIdentityColl
	{
		int Count
		{
			[DispId(1610743808)]
			get;
		}

		[DispId(0)]
		object GetItem([In][MarshalAs(UnmanagedType.BStr)] string lIndex);

		[DispId(-4)]
		void GetEnumerator(out IEnumerator pEnum);
	}
	[ComImport]
	[Guid("CAFC823E-B441-11D1-B82B-0000F8757E2A")]
	internal interface ISecurityCallContext
	{
		int Count
		{
			[DispId(1610743813)]
			get;
		}

		[DispId(0)]
		object GetItem([In][MarshalAs(UnmanagedType.BStr)] string name);

		[DispId(-4)]
		void GetEnumerator(out IEnumerator pEnum);

		[DispId(1610743814)]
		bool IsCallerInRole([In][MarshalAs(UnmanagedType.BStr)] string role);

		[DispId(1610743815)]
		bool IsSecurityEnabled();

		[DispId(1610743816)]
		bool IsUserInRole([In][MarshalAs(UnmanagedType.Struct)] ref object pUser, [In][MarshalAs(UnmanagedType.BStr)] string role);
	}
	public sealed class SecurityIdentity
	{
		private ISecurityIdentityColl _ex;

		public string AccountName => (string)_ex.GetItem("AccountName");

		public int AuthenticationService => (int)_ex.GetItem("AuthenticationService");

		public ImpersonationLevelOption ImpersonationLevel => (ImpersonationLevelOption)_ex.GetItem("ImpersonationLevel");

		public AuthenticationOption AuthenticationLevel => (AuthenticationOption)_ex.GetItem("AuthenticationLevel");

		private SecurityIdentity()
		{
		}

		internal SecurityIdentity(ISecurityIdentityColl ifc)
		{
			_ex = ifc;
		}
	}
	internal class SecurityIdentityEnumerator : IEnumerator
	{
		private IEnumerator _E;

		private SecurityCallers _callers;

		public object Current
		{
			get
			{
				object current = _E.Current;
				return _callers[(int)current];
			}
		}

		internal SecurityIdentityEnumerator(IEnumerator E, SecurityCallers c)
		{
			_E = E;
			_callers = c;
		}

		public bool MoveNext()
		{
			return _E.MoveNext();
		}

		public void Reset()
		{
			_E.Reset();
		}
	}
	public sealed class SecurityCallers : IEnumerable
	{
		private ISecurityCallersColl _ex;

		public int Count => _ex.Count;

		public SecurityIdentity this[int idx] => new SecurityIdentity(_ex.GetItem(idx));

		private SecurityCallers()
		{
		}

		internal SecurityCallers(ISecurityCallersColl ifc)
		{
			_ex = ifc;
		}

		public IEnumerator GetEnumerator()
		{
			IEnumerator pEnum = null;
			_ex.GetEnumerator(out pEnum);
			return new SecurityIdentityEnumerator(pEnum, this);
		}
	}
	public sealed class SecurityCallContext
	{
		private ISecurityCallContext _ex;

		public static SecurityCallContext CurrentCall
		{
			get
			{
				Platform.Assert(Platform.W2K, "SecurityCallContext");
				try
				{
					Util.CoGetCallContext(Util.IID_ISecurityCallContext, out var iface);
					return new SecurityCallContext(iface);
				}
				catch (InvalidCastException)
				{
					throw new COMException(Resource.FormatString("Err_NoSecurityContext"), Util.E_NOINTERFACE);
				}
			}
		}

		public bool IsSecurityEnabled => _ex.IsSecurityEnabled();

		public SecurityIdentity DirectCaller
		{
			get
			{
				ISecurityIdentityColl ifc = (ISecurityIdentityColl)_ex.GetItem("DirectCaller");
				return new SecurityIdentity(ifc);
			}
		}

		public SecurityIdentity OriginalCaller
		{
			get
			{
				ISecurityIdentityColl ifc = (ISecurityIdentityColl)_ex.GetItem("OriginalCaller");
				return new SecurityIdentity(ifc);
			}
		}

		public int NumCallers => (int)_ex.GetItem("NumCallers");

		public int MinAuthenticationLevel => (int)_ex.GetItem("MinAuthenticationLevel");

		public SecurityCallers Callers
		{
			get
			{
				ISecurityCallersColl ifc = (ISecurityCallersColl)_ex.GetItem("Callers");
				return new SecurityCallers(ifc);
			}
		}

		private SecurityCallContext()
		{
		}

		private SecurityCallContext(ISecurityCallContext ctx)
		{
			_ex = ctx;
		}

		public bool IsCallerInRole(string role)
		{
			return _ex.IsCallerInRole(role);
		}

		public bool IsUserInRole(string user, string role)
		{
			object pUser = user;
			return _ex.IsUserInRole(ref pUser, role);
		}
	}
}
namespace System.EnterpriseServices.Admin
{
	[Serializable]
	internal enum ApplicationInstallOptions
	{
		NoUsers,
		Users,
		ForceOverwriteOfFiles
	}
	[Serializable]
	internal enum ApplicationExportOptions
	{
		NoUsers = 0,
		Users = 1,
		ApplicationProxy = 2,
		ForceOverwriteOfFiles = 4
	}
	[Serializable]
	internal enum AuthenticationCapabilitiesOptions
	{
		None = 0,
		StaticCloaking = 32,
		DynamicCloaking = 64,
		SecureReference = 2
	}
	[Serializable]
	internal enum ServiceStatusOptions
	{
		Stopped,
		StartPending,
		StopPending,
		Running,
		ContinuePending,
		PausePending,
		Paused,
		UnknownState
	}
	[Serializable]
	internal enum FileFlags
	{
		Loadable = 1,
		COM = 2,
		ContainsPS = 4,
		ContainsComp = 8,
		ContainsTLB = 0x10,
		SelfReg = 0x20,
		SelfUnReg = 0x40,
		UnloadableDLL = 0x80,
		DoesNotExists = 0x100,
		AlreadyInstalled = 0x200,
		BadTLB = 0x400,
		GetClassObjFailed = 0x800,
		ClassNotAvailable = 0x1000,
		Registrar = 0x2000,
		NoRegistrar = 0x4000,
		DLLRegsvrFailed = 0x8000,
		RegTLBFailed = 0x10000,
		RegistrarFailed = 0x20000,
		Error = 0x40000
	}
	[Serializable]
	internal enum ComponentFlags
	{
		TypeInfoFound = 1,
		COMPlusPropertiesFound = 2,
		ProxyFound = 4,
		InterfacesFound = 8,
		AlreadyInstalled = 0x10,
		NotInApplication = 0x20
	}
	internal enum Bitness
	{
		Bitness32 = 1,
		Bitness64
	}
	[ComImport]
	[SuppressUnmanagedCodeSecurity]
	[Guid("6EB22870-8A19-11D0-81B6-00A0C9231C29")]
	internal interface IMtsCatalog
	{
		[DispId(1)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetCollection([In][MarshalAs(UnmanagedType.BStr)] string bstrCollName);

		[DispId(2)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object Connect([In][MarshalAs(UnmanagedType.BStr)] string connectStr);

		[DispId(3)]
		int MajorVersion();

		[DispId(4)]
		int MinorVersion();
	}
	[ComImport]
	[Guid("6EB22873-8A19-11D0-81B6-00A0C9231C29")]
	internal interface IComponentUtil
	{
		[DispId(1)]
		void InstallComponent([In][MarshalAs(UnmanagedType.BStr)] string bstrDLLFile, [In][MarshalAs(UnmanagedType.BStr)] string bstrTypelibFile, [In][MarshalAs(UnmanagedType.BStr)] string bstrProxyStubDLLFile);

		[DispId(2)]
		void ImportComponent([In][MarshalAs(UnmanagedType.BStr)] string bstrCLSID);

		[DispId(3)]
		void ImportComponentByName([In][MarshalAs(UnmanagedType.BStr)] string bstrProgID);

		[DispId(4)]
		void GetCLSIDs([In][MarshalAs(UnmanagedType.BStr)] string bstrDLLFile, [In][MarshalAs(UnmanagedType.BStr)] string bstrTypelibFile, [MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] out object[] CLSIDS);
	}
	[ComImport]
	[Guid("6EB22876-8A19-11D0-81B6-00A0C9231C29")]
	internal interface IRoleAssociationUtil
	{
		[DispId(1)]
		void AssociateRole([In][MarshalAs(UnmanagedType.BStr)] string bstrRoleID);

		[DispId(2)]
		void AssociateRoleByName([In][MarshalAs(UnmanagedType.BStr)] string bstrRoleName);
	}
	[ComImport]
	[SuppressUnmanagedCodeSecurity]
	[Guid("DD662187-DFC2-11D1-A2CF-00805FC79235")]
	internal interface ICatalog
	{
		[DispId(1)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetCollection([In][MarshalAs(UnmanagedType.BStr)] string bstrCollName);

		[DispId(2)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object Connect([In][MarshalAs(UnmanagedType.BStr)] string connectStr);

		[DispId(3)]
		int MajorVersion();

		[DispId(4)]
		int MinorVersion();

		[DispId(5)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetCollectionByQuery([In][MarshalAs(UnmanagedType.BStr)] string collName, [In][MarshalAs(UnmanagedType.SafeArray)] ref object[] aQuery);

		[DispId(6)]
		void ImportComponent([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrCLSIDOrProgId);

		[DispId(7)]
		void InstallComponent([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrDLL, [In][MarshalAs(UnmanagedType.BStr)] string bstrTLB, [In][MarshalAs(UnmanagedType.BStr)] string bstrPSDLL);

		[DispId(8)]
		void ShutdownApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName);

		[DispId(9)]
		void ExportApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationFile, [In] int lOptions);

		[DispId(10)]
		void InstallApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationFile, [In][MarshalAs(UnmanagedType.BStr)] string bstrDestinationDirectory, [In] int lOptions, [In][MarshalAs(UnmanagedType.BStr)] string bstrUserId, [In][MarshalAs(UnmanagedType.BStr)] string bstrPassword, [In][MarshalAs(UnmanagedType.BStr)] string bstrRSN);

		[DispId(11)]
		void StopRouter();

		[DispId(12)]
		void RefreshRouter();

		[DispId(13)]
		void StartRouter();

		[DispId(14)]
		void Reserved1();

		[DispId(15)]
		void Reserved2();

		[DispId(16)]
		void InstallMultipleComponents([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] fileNames, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] CLSIDS);

		[DispId(17)]
		void GetMultipleComponentsInfo([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In] object varFileNames, [MarshalAs(UnmanagedType.SafeArray)] out object[] varCLSIDS, [MarshalAs(UnmanagedType.SafeArray)] out object[] varClassNames, [MarshalAs(UnmanagedType.SafeArray)] out object[] varFileFlags, [MarshalAs(UnmanagedType.SafeArray)] out object[] varComponentFlags);

		[DispId(18)]
		void RefreshComponents();

		[DispId(19)]
		void BackupREGDB([In][MarshalAs(UnmanagedType.BStr)] string bstrBackupFilePath);

		[DispId(20)]
		void RestoreREGDB([In][MarshalAs(UnmanagedType.BStr)] string bstrBackupFilePath);

		[DispId(21)]
		void QueryApplicationFile([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationFile, [MarshalAs(UnmanagedType.BStr)] out string bstrApplicationName, [MarshalAs(UnmanagedType.BStr)] out string bstrApplicationDescription, [MarshalAs(UnmanagedType.VariantBool)] out bool bHasUsers, [MarshalAs(UnmanagedType.VariantBool)] out bool bIsProxy, [MarshalAs(UnmanagedType.SafeArray)] out object[] varFileNames);

		[DispId(22)]
		void StartApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName);

		[DispId(23)]
		int ServiceCheck([In] int lService);

		[DispId(24)]
		void InstallMultipleEventClasses([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] fileNames, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] CLSIDS);

		[DispId(25)]
		void InstallEventClass([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrDLL, [In][MarshalAs(UnmanagedType.BStr)] string bstrTLB, [In][MarshalAs(UnmanagedType.BStr)] string bstrPSDLL);

		[DispId(26)]
		void GetEventClassesForIID([In] string bstrIID, [In][Out][MarshalAs(UnmanagedType.SafeArray)] ref object[] varCLSIDS, [In][Out][MarshalAs(UnmanagedType.SafeArray)] ref object[] varProgIDs, [In][Out][MarshalAs(UnmanagedType.SafeArray)] ref object[] varDescriptions);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsDual)]
	[Guid("790C6E0B-9194-4cc9-9426-A48A63185696")]
	[SuppressUnmanagedCodeSecurity]
	internal interface ICatalog2
	{
		[DispId(1)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetCollection([In][MarshalAs(UnmanagedType.BStr)] string bstrCollName);

		[DispId(2)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object Connect([In][MarshalAs(UnmanagedType.BStr)] string connectStr);

		[DispId(3)]
		int MajorVersion();

		[DispId(4)]
		int MinorVersion();

		[DispId(5)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetCollectionByQuery([In][MarshalAs(UnmanagedType.BStr)] string collName, [In][MarshalAs(UnmanagedType.SafeArray)] ref object[] aQuery);

		[DispId(6)]
		void ImportComponent([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrCLSIDOrProgId);

		[DispId(7)]
		void InstallComponent([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrDLL, [In][MarshalAs(UnmanagedType.BStr)] string bstrTLB, [In][MarshalAs(UnmanagedType.BStr)] string bstrPSDLL);

		[DispId(8)]
		void ShutdownApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName);

		[DispId(9)]
		void ExportApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationFile, [In] int lOptions);

		[DispId(10)]
		void InstallApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationFile, [In][MarshalAs(UnmanagedType.BStr)] string bstrDestinationDirectory, [In] int lOptions, [In][MarshalAs(UnmanagedType.BStr)] string bstrUserId, [In][MarshalAs(UnmanagedType.BStr)] string bstrPassword, [In][MarshalAs(UnmanagedType.BStr)] string bstrRSN);

		[DispId(11)]
		void StopRouter();

		[DispId(12)]
		void RefreshRouter();

		[DispId(13)]
		void StartRouter();

		[DispId(14)]
		void Reserved1();

		[DispId(15)]
		void Reserved2();

		[DispId(16)]
		void InstallMultipleComponents([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] fileNames, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] CLSIDS);

		[DispId(17)]
		void GetMultipleComponentsInfo([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In] object varFileNames, [MarshalAs(UnmanagedType.SafeArray)] out object[] varCLSIDS, [MarshalAs(UnmanagedType.SafeArray)] out object[] varClassNames, [MarshalAs(UnmanagedType.SafeArray)] out object[] varFileFlags, [MarshalAs(UnmanagedType.SafeArray)] out object[] varComponentFlags);

		[DispId(18)]
		void RefreshComponents();

		[DispId(19)]
		void BackupREGDB([In][MarshalAs(UnmanagedType.BStr)] string bstrBackupFilePath);

		[DispId(20)]
		void RestoreREGDB([In][MarshalAs(UnmanagedType.BStr)] string bstrBackupFilePath);

		[DispId(21)]
		void QueryApplicationFile([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationFile, [MarshalAs(UnmanagedType.BStr)] out string bstrApplicationName, [MarshalAs(UnmanagedType.BStr)] out string bstrApplicationDescription, [MarshalAs(UnmanagedType.VariantBool)] out bool bHasUsers, [MarshalAs(UnmanagedType.VariantBool)] out bool bIsProxy, [MarshalAs(UnmanagedType.SafeArray)] out object[] varFileNames);

		[DispId(22)]
		void StartApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName);

		[DispId(23)]
		int ServiceCheck([In] int lService);

		[DispId(24)]
		void InstallMultipleEventClasses([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] fileNames, [In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref object[] CLSIDS);

		[DispId(25)]
		void InstallEventClass([In][MarshalAs(UnmanagedType.BStr)] string bstrApplIdOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrDLL, [In][MarshalAs(UnmanagedType.BStr)] string bstrTLB, [In][MarshalAs(UnmanagedType.BStr)] string bstrPSDLL);

		[DispId(26)]
		void GetEventClassesForIID([In] string bstrIID, [In][Out][MarshalAs(UnmanagedType.SafeArray)] ref object[] varCLSIDS, [In][Out][MarshalAs(UnmanagedType.SafeArray)] ref object[] varProgIDs, [In][Out][MarshalAs(UnmanagedType.SafeArray)] ref object[] varDescriptions);

		[DispId(27)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetCollectionByQuery2([In][MarshalAs(UnmanagedType.BStr)] string bstrCollectionName, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarQueryStrings);

		[DispId(28)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetApplicationInstanceIDFromProcessID([In][MarshalAs(UnmanagedType.I4)] int lProcessID);

		[DispId(29)]
		void ShutdownApplicationInstances([In][MarshalAs(UnmanagedType.LPStruct)] object pVarApplicationInstanceID);

		[DispId(30)]
		void PauseApplicationInstances([In][MarshalAs(UnmanagedType.LPStruct)] object pVarApplicationInstanceID);

		[DispId(31)]
		void ResumeApplicationInstances([In][MarshalAs(UnmanagedType.LPStruct)] object pVarApplicationInstanceID);

		[DispId(32)]
		void RecycleApplicationInstances([In][MarshalAs(UnmanagedType.LPStruct)] object pVarApplicationInstanceID, [In][MarshalAs(UnmanagedType.I4)] int lReasonCode);

		[DispId(33)]
		[return: MarshalAs(UnmanagedType.VariantBool)]
		bool AreApplicationInstancesPaused([In][MarshalAs(UnmanagedType.LPStruct)] object pVarApplicationInstanceID);

		[DispId(34)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string DumpApplicationInstance([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationInstanceID, [In][MarshalAs(UnmanagedType.BStr)] string bstrDirectory, [In][MarshalAs(UnmanagedType.I4)] int lMaxImages);

		[DispId(35)]
		[return: MarshalAs(UnmanagedType.VariantBool)]
		bool IsApplicationInstanceDumpSupported();

		[DispId(36)]
		void CreateServiceForApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationIDOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrServiceName, [In][MarshalAs(UnmanagedType.BStr)] string bstrStartType, [In][MarshalAs(UnmanagedType.BStr)] string bstrErrorControl, [In][MarshalAs(UnmanagedType.BStr)] string bstrDependencies, [In][MarshalAs(UnmanagedType.BStr)] string bstrRunAs, [In][MarshalAs(UnmanagedType.BStr)] string bstrPassword, [In][MarshalAs(UnmanagedType.VariantBool)] bool bDesktopOk);

		[DispId(37)]
		void DeleteServiceForApplication([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationIDOrName);

		[DispId(38)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetPartitionID([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationIDOrName);

		[DispId(39)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetPartitionName([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationIDOrName);

		[DispId(40)]
		void CurrentPartition([In][MarshalAs(UnmanagedType.BStr)] string bstrPartitionIDOrName);

		[DispId(41)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string CurrentPartitionID();

		[DispId(42)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string CurrentPartitionName();

		[DispId(43)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GlobalPartitionID();

		[DispId(44)]
		void FlushPartitionCache();

		[DispId(45)]
		void CopyApplications([In][MarshalAs(UnmanagedType.BStr)] string bstrSourcePartitionIDOrName, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarApplicationID, [In][MarshalAs(UnmanagedType.BStr)] string bstrDestinationPartitionIDOrName);

		[DispId(46)]
		void CopyComponents([In][MarshalAs(UnmanagedType.BStr)] string bstrSourceApplicationIDOrName, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarCLSIDOrProgID, [In][MarshalAs(UnmanagedType.BStr)] string bstrDestinationApplicationIDOrName);

		[DispId(47)]
		void MoveComponents([In][MarshalAs(UnmanagedType.BStr)] string bstrSourceApplicationIDOrName, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarCLSIDOrProgID, [In][MarshalAs(UnmanagedType.BStr)] string bstrDestinationApplicationIDOrName);

		[DispId(48)]
		void AliasComponent([In][MarshalAs(UnmanagedType.BStr)] string bstrSrcApplicationIDOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrCLSIDOrProgID, [In][MarshalAs(UnmanagedType.BStr)] string bstrDestApplicationIDOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrNewProgId, [In][MarshalAs(UnmanagedType.BStr)] string bstrNewClsid);

		[DispId(49)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object IsSafeToDelete([In][MarshalAs(UnmanagedType.BStr)] string bstrDllName);

		[DispId(50)]
		void ImportUnconfiguredComponents([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationIDOrName, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarCLSIDOrProgID, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarComponentType);

		[DispId(51)]
		void PromoteUnconfiguredComponents([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationIDOrName, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarCLSIDOrProgID, [In][MarshalAs(UnmanagedType.LPStruct)] object pVarComponentType);

		[DispId(52)]
		void ImportComponents([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationIDOrName, [In] ref object pVarCLSIDOrProgID, [In] ref object pVarComponentType);

		[DispId(53)]
		[return: MarshalAs(UnmanagedType.VariantBool)]
		bool Is64BitCatalogServer();

		[DispId(54)]
		void ExportPartition([In][MarshalAs(UnmanagedType.BStr)] string bstrPartitionIDOrName, [In][MarshalAs(UnmanagedType.BStr)] string bstrPartitionFileName, [In][MarshalAs(UnmanagedType.I4)] int lOptions);

		[DispId(55)]
		void InstallPartition([In][MarshalAs(UnmanagedType.BStr)] string bstrFileName, [In][MarshalAs(UnmanagedType.BStr)] string bstrDestDirectory, [In][MarshalAs(UnmanagedType.I4)] int lOptions, [In][MarshalAs(UnmanagedType.BStr)] string bstrUserID, [In][MarshalAs(UnmanagedType.BStr)] string bstrPassword, [In][MarshalAs(UnmanagedType.BStr)] string bstrRSN);

		[DispId(56)]
		[return: MarshalAs(UnmanagedType.IDispatch)]
		object QueryApplicationFile2([In][MarshalAs(UnmanagedType.BStr)] string bstrApplicationFile);

		[DispId(57)]
		[return: MarshalAs(UnmanagedType.I4)]
		int GetComponentVersionCount([In][MarshalAs(UnmanagedType.BStr)] string bstrCLSIDOrProgID);
	}
	[ComImport]
	[Guid("6EB22871-8A19-11D0-81B6-00A0C9231C29")]
	[SuppressUnmanagedCodeSecurity]
	internal interface ICatalogObject
	{
		bool Valid
		{
			[DispId(5)]
			[return: MarshalAs(UnmanagedType.VariantBool)]
			get;
		}

		[DispId(1)]
		object GetValue([In][MarshalAs(UnmanagedType.BStr)] string propName);

		[DispId(1)]
		void SetValue([In][MarshalAs(UnmanagedType.BStr)] string propName, [In] object value);

		[DispId(2)]
		object Key();

		[DispId(3)]
		object Name();

		[DispId(4)]
		[return: MarshalAs(UnmanagedType.VariantBool)]
		bool IsPropertyReadOnly([In][MarshalAs(UnmanagedType.BStr)] string bstrPropName);

		[DispId(6)]
		[return: MarshalAs(UnmanagedType.VariantBool)]
		bool IsPropertyWriteOnly([In][MarshalAs(UnmanagedType.BStr)] string bstrPropName);
	}
	[ComImport]
	[Guid("6EB22872-8A19-11D0-81B6-00A0C9231C29")]
	[InterfaceType(ComInterfaceType.InterfaceIsDual)]
	[SuppressUnmanagedCodeSecurity]
	internal interface ICatalogCollection
	{
		bool IsAddEnabled
		{
			[DispId(7)]
			[return: MarshalAs(UnmanagedType.VariantBool)]
			get;
		}

		bool IsRemoveEnabled
		{
			[DispId(8)]
			[return: MarshalAs(UnmanagedType.VariantBool)]
			get;
		}

		int DataStoreMajorVersion
		{
			[DispId(10)]
			get;
		}

		int DataStoreMinorVersion
		{
			[DispId(11)]
			get;
		}

		[DispId(-4)]
		void GetEnumerator(out IEnumerator pEnum);

		[DispId(1)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object Item([In] int lIndex);

		[DispId(1610743810)]
		int Count();

		[DispId(1610743811)]
		void Remove([In] int lIndex);

		[DispId(1610743812)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object Add();

		[DispId(2)]
		void Populate();

		[DispId(3)]
		int SaveChanges();

		[DispId(4)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetCollection([In][MarshalAs(UnmanagedType.BStr)] string bstrCollName, [In] object varObjectKey);

		[DispId(6)]
		object Name();

		[DispId(9)]
		[return: MarshalAs(UnmanagedType.Interface)]
		object GetUtilInterface();

		void PopulateByKey([In][MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] object[] aKeys);

		[DispId(13)]
		void PopulateByQuery([In][MarshalAs(UnmanagedType.BStr)] string bstrQueryString, [In] int lQueryType);
	}
	[ComImport]
	[Guid("F618C514-DFB8-11D1-A2CF-00805FC79235")]
	internal class xCatalog
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		public extern xCatalog();
	}
	[ComImport]
	[Guid("6EB22881-8A19-11D0-81B6-00A0C9231C29")]
	internal class xMtsCatalog
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		public extern xMtsCatalog();
	}
	internal class CollectionName
	{
		private static volatile bool _initialized;

		private static string _apps;

		private static string _comps;

		private static string _interfaces;

		private static string _meths;

		private static string _roles;

		private static string _user;

		internal static string Applications
		{
			get
			{
				Initialize();
				return _apps;
			}
		}

		internal static string Components
		{
			get
			{
				Initialize();
				return _comps;
			}
		}

		internal static string Interfaces
		{
			get
			{
				Initialize();
				return _interfaces;
			}
		}

		internal static string Methods
		{
			get
			{
				Initialize();
				return _meths;
			}
		}

		internal static string Roles
		{
			get
			{
				Initialize();
				return _roles;
			}
		}

		internal static string UsersInRole
		{
			get
			{
				Initialize();
				return _user;
			}
		}

		private static void Initialize()
		{
			if (_initialized)
			{
				return;
			}
			lock (typeof(CollectionName))
			{
				if (!_initialized)
				{
					if (Platform.IsLessThan(Platform.W2K))
					{
						_apps = "Packages";
						_comps = "ComponentsInPackage";
						_interfaces = "InterfacesForComponent";
						_meths = "MethodsForInterface";
						_roles = "RolesInPackage";
						_user = "UsersInRole";
					}
					else
					{
						_apps = "Applications";
						_comps = "Components";
						_interfaces = "InterfacesForComponent";
						_meths = "MethodsForInterface";
						_roles = "Roles";
						_user = "UsersInRole";
					}
					_initialized = true;
				}
			}
		}

		internal static string RolesFor(string target)
		{
			if (Platform.IsLessThan(Platform.W2K))
			{
				if (target == "Component")
				{
					return "RolesForPackageComponent";
				}
				if (target == "Interface")
				{
					return "RolesForPackageComponentInterface";
				}
				return null;
			}
			return "RolesFor" + target;
		}
	}
}
namespace System.EnterpriseServices
{
	[Serializable]
	public enum TransactionOption
	{
		Disabled,
		NotSupported,
		Supported,
		Required,
		RequiresNew
	}
	[Serializable]
	public enum TransactionIsolationLevel
	{
		Any,
		ReadUncommitted,
		ReadCommitted,
		RepeatableRead,
		Serializable
	}
	[Serializable]
	public enum SynchronizationOption
	{
		Disabled,
		NotSupported,
		Supported,
		Required,
		RequiresNew
	}
	[Serializable]
	public enum ActivationOption
	{
		Library,
		Server
	}
	internal interface IConfigurationAttribute
	{
		bool IsValidTarget(string s);

		bool Apply(Hashtable info);

		bool AfterSaveChanges(Hashtable info);
	}
	[ComImport]
	[Guid("1113f52d-dc7f-4943-aed6-88d04027e32a")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IProcessInitializer
	{
		void Startup([In][MarshalAs(UnmanagedType.IUnknown)] object punkProcessControl);

		void Shutdown();
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("72380d55-8d2b-43a3-8513-2b6ef31434e9")]
	public interface IProcessInitControl
	{
		void ResetInitializerTimeout(int dwSecondsRemaining);
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class TransactionAttribute : Attribute, IConfigurationAttribute
	{
		private TransactionOption _value;

		private TransactionIsolationLevel _isolation;

		private int _timeout;

		public TransactionOption Value => _value;

		public TransactionIsolationLevel Isolation
		{
			get
			{
				return _isolation;
			}
			set
			{
				_isolation = value;
			}
		}

		public int Timeout
		{
			get
			{
				return _timeout;
			}
			set
			{
				_timeout = value;
			}
		}

		public TransactionAttribute()
			: this(TransactionOption.Required)
		{
		}

		public TransactionAttribute(TransactionOption val)
		{
			_value = val;
			_isolation = TransactionIsolationLevel.Serializable;
			_timeout = -1;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			object value = _value;
			Platform.Assert(Platform.MTS, "TransactionAttribute");
			if (Platform.IsLessThan(Platform.W2K))
			{
				switch (_value)
				{
				case TransactionOption.Required:
					value = "Required";
					break;
				case TransactionOption.RequiresNew:
					value = "Requires New";
					break;
				case TransactionOption.Supported:
					value = "Supported";
					break;
				case TransactionOption.NotSupported:
					value = "NotSupported";
					break;
				case TransactionOption.Disabled:
					value = "NotSupported";
					break;
				}
			}
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("Transaction", value);
			if (_isolation != TransactionIsolationLevel.Serializable)
			{
				Platform.Assert(Platform.Whistler, "TransactionAttribute.Isolation");
				catalogObject.SetValue("TxIsolationLevel", _isolation);
			}
			if (_timeout != -1)
			{
				Platform.Assert(Platform.W2K, "TransactionAttribute.Timeout");
				catalogObject.SetValue("ComponentTransactionTimeout", _timeout);
				catalogObject.SetValue("ComponentTransactionTimeoutEnabled", true);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	[ComVisible(false)]
	public sealed class JustInTimeActivationAttribute : Attribute, IConfigurationAttribute
	{
		private bool _enabled;

		public bool Value => _enabled;

		public JustInTimeActivationAttribute()
			: this(val: true)
		{
		}

		public JustInTimeActivationAttribute(bool val)
		{
			_enabled = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "JustInTimeActivationAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("JustInTimeActivation", _enabled);
			if (_enabled && (int)catalogObject.GetValue("Synchronization") == 0)
			{
				catalogObject.SetValue("Synchronization", SynchronizationOption.Required);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class SynchronizationAttribute : Attribute, IConfigurationAttribute
	{
		private SynchronizationOption _value;

		public SynchronizationOption Value => _value;

		public SynchronizationAttribute()
			: this(SynchronizationOption.Required)
		{
		}

		public SynchronizationAttribute(SynchronizationOption val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "SynchronizationAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("Synchronization", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class MustRunInClientContextAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public MustRunInClientContextAttribute()
			: this(val: true)
		{
		}

		public MustRunInClientContextAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "MustRunInClientContextAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("MustRunInClientContext", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	[ComVisible(false)]
	public sealed class ConstructionEnabledAttribute : Attribute, IConfigurationAttribute
	{
		private bool _enabled;

		private string _default;

		public string Default
		{
			get
			{
				return _default;
			}
			set
			{
				_default = value;
			}
		}

		public bool Enabled
		{
			get
			{
				return _enabled;
			}
			set
			{
				_enabled = value;
			}
		}

		public ConstructionEnabledAttribute()
		{
			_enabled = true;
			_default = "";
		}

		public ConstructionEnabledAttribute(bool val)
		{
			_enabled = val;
			_default = "";
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "ConstructionEnabledAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("ConstructionEnabled", _enabled);
			if (_default != null && _default != "")
			{
				catalogObject.SetValue("ConstructorString", _default);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class ObjectPoolingAttribute : Attribute, IConfigurationAttribute
	{
		private bool _enable;

		private int _maxSize;

		private int _minSize;

		private int _timeout;

		public bool Enabled
		{
			get
			{
				return _enable;
			}
			set
			{
				_enable = value;
			}
		}

		public int MaxPoolSize
		{
			get
			{
				return _maxSize;
			}
			set
			{
				_maxSize = value;
			}
		}

		public int MinPoolSize
		{
			get
			{
				return _minSize;
			}
			set
			{
				_minSize = value;
			}
		}

		public int CreationTimeout
		{
			get
			{
				return _timeout;
			}
			set
			{
				_timeout = value;
			}
		}

		public ObjectPoolingAttribute()
		{
			_enable = true;
			_maxSize = -1;
			_minSize = -1;
			_timeout = -1;
		}

		public ObjectPoolingAttribute(int minPoolSize, int maxPoolSize)
		{
			_enable = true;
			_maxSize = maxPoolSize;
			_minSize = minPoolSize;
			_timeout = -1;
		}

		public ObjectPoolingAttribute(bool enable)
		{
			_enable = enable;
			_maxSize = -1;
			_minSize = -1;
			_timeout = -1;
		}

		public ObjectPoolingAttribute(bool enable, int minPoolSize, int maxPoolSize)
		{
			_enable = enable;
			_maxSize = maxPoolSize;
			_minSize = minPoolSize;
			_timeout = -1;
		}

		public bool IsValidTarget(string s)
		{
			return s == "Component";
		}

		public bool Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "ObjectPoolingAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("ObjectPoolingEnabled", _enable);
			if (_minSize >= 0)
			{
				catalogObject.SetValue("MinPoolSize", _minSize);
			}
			if (_maxSize >= 0)
			{
				catalogObject.SetValue("MaxPoolSize", _maxSize);
			}
			if (_timeout >= 0)
			{
				catalogObject.SetValue("CreationTimeout", _timeout);
			}
			return true;
		}

		public bool AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class COMTIIntrinsicsAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public COMTIIntrinsicsAttribute()
			: this(val: true)
		{
		}

		public COMTIIntrinsicsAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "COMTIIntrinsicsAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("COMTIIntrinsics", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class IISIntrinsicsAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public IISIntrinsicsAttribute()
			: this(val: true)
		{
		}

		public IISIntrinsicsAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "IISIntrinsicsAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("IISIntrinsics", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	[ComVisible(false)]
	public sealed class EventTrackingEnabledAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public EventTrackingEnabledAttribute()
			: this(val: true)
		{
		}

		public EventTrackingEnabledAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "EventTrackingEnabledAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("EventTrackingEnabled", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	[ComVisible(false)]
	public sealed class ExceptionClassAttribute : Attribute, IConfigurationAttribute
	{
		private string _value;

		public string Value => _value;

		public ExceptionClassAttribute(string name)
		{
			_value = name;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "ExceptionClassAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("ExceptionClass", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class LoadBalancingSupportedAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public LoadBalancingSupportedAttribute()
			: this(val: true)
		{
		}

		public LoadBalancingSupportedAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "LoadBalancingSupportedAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("LoadBalancingSupported", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	public sealed class EventClassAttribute : Attribute, IConfigurationAttribute
	{
		private bool _fireInParallel;

		private bool _allowInprocSubscribers;

		private string _filter;

		public bool FireInParallel
		{
			get
			{
				return _fireInParallel;
			}
			set
			{
				_fireInParallel = value;
			}
		}

		public bool AllowInprocSubscribers
		{
			get
			{
				return _allowInprocSubscribers;
			}
			set
			{
				_allowInprocSubscribers = value;
			}
		}

		public string PublisherFilter
		{
			get
			{
				return _filter;
			}
			set
			{
				_filter = value;
			}
		}

		public EventClassAttribute()
		{
			_fireInParallel = false;
			_allowInprocSubscribers = true;
			_filter = null;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "EventClassAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("FireInParallel", _fireInParallel);
			catalogObject.SetValue("AllowInprocSubscribers", _allowInprocSubscribers);
			if (_filter != null)
			{
				catalogObject.SetValue("MultiInterfacePublisherFilterCLSID", _filter);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	[ComVisible(false)]
	public sealed class PrivateComponentAttribute : Attribute, IConfigurationAttribute
	{
		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.Whistler, "PrivateComponentAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			catalogObject.SetValue("IsPrivateComponent", true);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Method, Inherited = true)]
	[ComVisible(false)]
	public sealed class AutoCompleteAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public AutoCompleteAttribute()
			: this(val: true)
		{
		}

		public AutoCompleteAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Method";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "AutoCompleteAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Method"];
			catalogObject.SetValue("AutoComplete", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Assembly, Inherited = true)]
	[ComVisible(false)]
	public sealed class ApplicationActivationAttribute : Attribute, IConfigurationAttribute
	{
		private ActivationOption _value;

		private string _SoapVRoot;

		private string _SoapMailbox;

		public ActivationOption Value => _value;

		public string SoapVRoot
		{
			get
			{
				return _SoapVRoot;
			}
			set
			{
				_SoapVRoot = value;
			}
		}

		public string SoapMailbox
		{
			get
			{
				return _SoapMailbox;
			}
			set
			{
				_SoapMailbox = value;
			}
		}

		public ApplicationActivationAttribute(ActivationOption opt)
		{
			_value = opt;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Application";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.MTS, "ApplicationActivationAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Application"];
			if (Platform.IsLessThan(Platform.W2K))
			{
				switch (_value)
				{
				case ActivationOption.Server:
					catalogObject.SetValue("Activation", "Local");
					break;
				case ActivationOption.Library:
					catalogObject.SetValue("Activation", "Inproc");
					break;
				}
			}
			else
			{
				catalogObject.SetValue("Activation", _value);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			bool result = false;
			if (_SoapVRoot != null)
			{
				ICatalogObject catalogObject = (ICatalogObject)info["Application"];
				Platform.Assert(Platform.Whistler, "ApplicationActivationAttribute.SoapVRoot");
				catalogObject.SetValue("SoapActivated", true);
				catalogObject.SetValue("SoapVRoot", _SoapVRoot);
				result = true;
			}
			if (_SoapMailbox != null)
			{
				ICatalogObject catalogObject2 = (ICatalogObject)info["Application"];
				Platform.Assert(Platform.Whistler, "ApplicationActivationAttribute.SoapMailbox");
				catalogObject2.SetValue("SoapActivated", true);
				catalogObject2.SetValue("SoapMailTo", _SoapMailbox);
				result = true;
			}
			return result;
		}
	}
	[AttributeUsage(AttributeTargets.Assembly, Inherited = true)]
	[ComVisible(false)]
	public sealed class ApplicationNameAttribute : Attribute, IConfigurationAttribute
	{
		private string _value;

		public string Value => _value;

		public ApplicationNameAttribute(string name)
		{
			_value = name;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Application";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.MTS, "ApplicationNameAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Application"];
			catalogObject.SetValue("Name", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Assembly, Inherited = true)]
	[ComVisible(false)]
	public sealed class ApplicationIDAttribute : Attribute, IConfigurationAttribute
	{
		private Guid _value;

		public Guid Value => _value;

		public ApplicationIDAttribute(string guid)
		{
			_value = new Guid(guid);
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Application";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			return false;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Assembly, Inherited = true)]
	[ComVisible(false)]
	public sealed class ApplicationQueuingAttribute : Attribute, IConfigurationAttribute
	{
		private bool _enabled;

		private bool _listen;

		private int _maxthreads;

		public bool Enabled
		{
			get
			{
				return _enabled;
			}
			set
			{
				_enabled = value;
			}
		}

		public bool QueueListenerEnabled
		{
			get
			{
				return _listen;
			}
			set
			{
				_listen = value;
			}
		}

		public int MaxListenerThreads
		{
			get
			{
				return _maxthreads;
			}
			set
			{
				_maxthreads = value;
			}
		}

		public ApplicationQueuingAttribute()
		{
			_enabled = true;
			_listen = false;
			_maxthreads = 0;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Application";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "ApplicationQueueingAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Application"];
			catalogObject.SetValue("QueuingEnabled", _enabled);
			catalogObject.SetValue("QueueListenerEnabled", _listen);
			if (_maxthreads != 0)
			{
				Platform.Assert(Platform.Whistler, "ApplicationQueuingAttribute.MaxListenerThreads");
				catalogObject.SetValue("QCListenerMaxThreads", _maxthreads);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Interface, Inherited = true, AllowMultiple = true)]
	public sealed class InterfaceQueuingAttribute : Attribute, IConfigurationAttribute
	{
		private bool _enabled;

		private string _interface;

		public bool Enabled
		{
			get
			{
				return _enabled;
			}
			set
			{
				_enabled = value;
			}
		}

		public string Interface
		{
			get
			{
				return _interface;
			}
			set
			{
				_interface = value;
			}
		}

		public InterfaceQueuingAttribute()
		{
			_enabled = true;
		}

		public InterfaceQueuingAttribute(bool enabled)
		{
			_enabled = enabled;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			if (_interface == null)
			{
				return s == "Interface";
			}
			return s == "Component";
		}

		private bool ConfigureInterface(ICatalogObject obj)
		{
			bool flag = (bool)obj.GetValue("QueuingSupported");
			if (_enabled && flag)
			{
				obj.SetValue("QueuingEnabled", _enabled);
			}
			else
			{
				if (_enabled)
				{
					throw new RegistrationException(Resource.FormatString("Reg_QueueingNotSupported", (string)obj.Name()));
				}
				obj.SetValue("QueuingEnabled", _enabled);
			}
			return true;
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "InterfaceQueuingAttribute");
			if (_interface == null)
			{
				ICatalogObject obj = (ICatalogObject)info["Interface"];
				ConfigureInterface(obj);
			}
			return true;
		}

		internal static Type ResolveTypeRelativeTo(string typeName, Type serverType)
		{
			Type type = null;
			Type type2 = null;
			bool flag = false;
			bool flag2 = false;
			Type[] interfaces = serverType.GetInterfaces();
			for (int i = 0; i < interfaces.Length; i++)
			{
				type = interfaces[i];
				string fullName = type.FullName;
				int num = fullName.Length - typeName.Length;
				if (num < 0 || string.CompareOrdinal(typeName, 0, fullName, num, typeName.Length) != 0 || (num != 0 && (num <= 0 || fullName[num - 1] != '.')))
				{
					continue;
				}
				if (type2 == null)
				{
					type2 = type;
					flag = num == 0;
					continue;
				}
				if (type2 != null)
				{
					flag2 = true;
				}
				if (type2 != null && flag)
				{
					if (num == 0)
					{
						throw new AmbiguousMatchException(Resource.FormatString("Reg_IfcAmbiguousMatch", typeName, type, type2));
					}
				}
				else if (type2 != null && !flag && num == 0)
				{
					type2 = type;
					flag = true;
				}
			}
			if (flag2 && !flag)
			{
				throw new AmbiguousMatchException(Resource.FormatString("Reg_IfcAmbiguousMatch", typeName, type, type2));
			}
			return type2;
		}

		internal static Type FindInterfaceByName(string name, Type component)
		{
			Type type = ResolveTypeRelativeTo(name, component);
			if (type == null)
			{
				type = Type.GetType(name, throwOnError: false);
			}
			return type;
		}

		private void FindInterfaceByKey(string key, ICatalogCollection coll, Type comp, out ICatalogObject ifcObj, out Type ifcType)
		{
			ifcType = FindInterfaceByName(key, comp);
			if (ifcType == null)
			{
				throw new RegistrationException(Resource.FormatString("Reg_TypeFindError", key, comp.ToString()));
			}
			Guid guid = Marshal.GenerateGuidForType(ifcType);
			object[] aKeys = new object[1] { string.Concat("{", guid, "}") };
			coll.PopulateByKey(aKeys);
			if (coll.Count() != 1)
			{
				throw new RegistrationException(Resource.FormatString("Reg_TypeFindError", key, comp.ToString()));
			}
			ifcObj = (ICatalogObject)coll.Item(0);
		}

		private void StashModification(Hashtable cache, Type comp, Type ifc)
		{
			if (cache[comp] == null)
			{
				cache[comp] = new Hashtable();
			}
			((Hashtable)cache[comp])[ifc] = true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			if (_interface != null)
			{
				ICatalogCollection catalogCollection = (ICatalogCollection)info["ComponentCollection"];
				ICatalogObject catalogObject = (ICatalogObject)info["Component"];
				Type comp = (Type)info["ComponentType"];
				ICatalogCollection catalogCollection2 = (ICatalogCollection)catalogCollection.GetCollection("InterfacesForComponent", catalogObject.Key());
				FindInterfaceByKey(_interface, catalogCollection2, comp, out var ifcObj, out var ifcType);
				ConfigureInterface(ifcObj);
				catalogCollection2.SaveChanges();
				StashModification(info, comp, ifcType);
			}
			return false;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Method | AttributeTargets.Interface, Inherited = true)]
	public sealed class DescriptionAttribute : Attribute, IConfigurationAttribute
	{
		private string _desc;

		private string Description => _desc;

		public DescriptionAttribute(string desc)
		{
			_desc = desc;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			switch (s)
			{
			default:
				return s == "Method";
			case "Application":
			case "Component":
			case "Interface":
				return true;
			}
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.MTS, "DescriptionAttribute");
			string key = (string)info["CurrentTarget"];
			ICatalogObject catalogObject = (ICatalogObject)info[key];
			catalogObject.SetValue("Description", Description);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	internal static class ServicedComponentInfo
	{
		internal const int SCI_PRESENT = 1;

		internal const int SCI_SERVICEDCOMPONENT = 2;

		internal const int SCI_EVENTSOURCE = 4;

		internal const int SCI_JIT = 8;

		internal const int SCI_OBJECTPOOLED = 16;

		internal const int SCI_METHODSSECURE = 32;

		internal const int SCI_CLASSINTERFACE = 64;

		internal const int MI_PRESENT = 1;

		internal const int MI_AUTODONE = 2;

		internal const int MI_HASSPECIALATTRIBUTES = 4;

		internal const int MI_EXECUTEMESSAGEVALID = 8;

		private static RWHashTable _SCICache;

		private static RWHashTable _MICache;

		private static Hashtable _ExecuteMessageCache;

		static ServicedComponentInfo()
		{
			_SCICache = new RWHashTable();
			_MICache = new RWHashTable();
			_ExecuteMessageCache = new Hashtable();
			AddExecuteMethodValidTypes();
		}

		private static bool IsTypeServicedComponent2(Type t)
		{
			return t.IsSubclassOf(typeof(ServicedComponent));
		}

		private static bool IsTypeJITActivated2(Type t)
		{
			object[] customAttributes = t.GetCustomAttributes(inherit: true);
			object[] array = customAttributes;
			foreach (object obj in array)
			{
				if (obj is JustInTimeActivationAttribute)
				{
					return ((JustInTimeActivationAttribute)obj).Value;
				}
				if (obj is TransactionAttribute)
				{
					int value = (int)((TransactionAttribute)obj).Value;
					if (value >= 2)
					{
						return true;
					}
				}
			}
			return false;
		}

		private static bool IsTypeEventSource2(Type t)
		{
			object[] customAttributes = t.GetCustomAttributes(inherit: true);
			object[] array = customAttributes;
			foreach (object obj in array)
			{
				if (obj is EventClassAttribute)
				{
					return true;
				}
			}
			return false;
		}

		public static bool IsTypeEventSource(Type t)
		{
			return (SCICachedLookup(t) & 4) != 0;
		}

		public static bool IsTypeJITActivated(Type t)
		{
			return (SCICachedLookup(t) & 8) != 0;
		}

		public static bool IsTypeServicedComponent(Type t)
		{
			return (SCICachedLookup(t) & 2) != 0;
		}

		public static bool IsTypeObjectPooled(Type t)
		{
			return (SCICachedLookup(t) & 0x10) != 0;
		}

		internal static bool AreMethodsSecure(Type t)
		{
			return (SCICachedLookup(t) & 0x20) != 0;
		}

		internal static int SCICachedLookup(Type t)
		{
			object obj = _SCICache.Get(t);
			if (obj != null)
			{
				return (int)obj;
			}
			int num = 0;
			if (IsTypeServicedComponent2(t))
			{
				num |= 2;
				if (IsTypeEventSource2(t))
				{
					num |= 4;
				}
				if (IsTypeJITActivated2(t))
				{
					num |= 8;
				}
				if (IsTypeObjectPooled2(t))
				{
					num |= 0x10;
				}
			}
			if (AreMethodsSecure2(t))
			{
				num |= 0x20;
			}
			if (HasClassInterface2(t))
			{
				num |= 0x40;
			}
			_SCICache.Put(t, num);
			return num;
		}

		private static bool IsTypeObjectPooled2(Type t)
		{
			object[] customAttributes = t.GetCustomAttributes(typeof(ObjectPoolingAttribute), inherit: true);
			if (customAttributes != null && customAttributes.Length > 0)
			{
				return ((ObjectPoolingAttribute)customAttributes[0]).Enabled;
			}
			return false;
		}

		public static bool IsMethodAutoDone(MemberInfo m)
		{
			return (MICachedLookup(m) & 2) != 0;
		}

		public static bool HasSpecialMethodAttributes(MemberInfo m)
		{
			return (MICachedLookup(m) & 4) != 0;
		}

		internal static int MICachedLookup(MemberInfo m)
		{
			object obj = _MICache.Get(m);
			if (obj != null)
			{
				return (int)obj;
			}
			int num = 0;
			if (IsMethodAutoDone2(m))
			{
				num |= 2;
			}
			if (HasSpecialMethodAttributes2(m))
			{
				num |= 4;
			}
			if (IsExecuteMessageValid2(m))
			{
				num |= 8;
			}
			_MICache.Put(m, num);
			return num;
		}

		private static bool IsExecuteMessageValid2(MemberInfo m)
		{
			MemberInfo memberInfo = ReflectionCache.ConvertToInterfaceMI(m);
			if (memberInfo == null)
			{
				return false;
			}
			if (!(m is MethodInfo methodInfo))
			{
				return false;
			}
			ParameterInfo[] parameters = methodInfo.GetParameters();
			foreach (ParameterInfo parameterInfo in parameters)
			{
				if (!IsTypeExecuteMethodValid(parameterInfo.ParameterType))
				{
					return false;
				}
			}
			if (!IsTypeExecuteMethodValid(methodInfo.ReturnType))
			{
				return false;
			}
			return true;
		}

		private static bool IsTypeExecuteMethodValid(Type t)
		{
			if (t.IsEnum)
			{
				return true;
			}
			Type elementType = t.GetElementType();
			if (elementType != null && (t.IsByRef || t.IsArray))
			{
				if (_ExecuteMessageCache[elementType] == null)
				{
					return false;
				}
			}
			else if (_ExecuteMessageCache[t] == null)
			{
				return false;
			}
			return true;
		}

		private static void AddExecuteMethodValidTypes()
		{
			_ExecuteMessageCache.Add(typeof(bool), true);
			_ExecuteMessageCache.Add(typeof(byte), true);
			_ExecuteMessageCache.Add(typeof(char), true);
			_ExecuteMessageCache.Add(typeof(DateTime), true);
			_ExecuteMessageCache.Add(typeof(decimal), true);
			_ExecuteMessageCache.Add(typeof(double), true);
			_ExecuteMessageCache.Add(typeof(Guid), true);
			_ExecuteMessageCache.Add(typeof(short), true);
			_ExecuteMessageCache.Add(typeof(int), true);
			_ExecuteMessageCache.Add(typeof(long), true);
			_ExecuteMessageCache.Add(typeof(IntPtr), true);
			_ExecuteMessageCache.Add(typeof(sbyte), true);
			_ExecuteMessageCache.Add(typeof(float), true);
			_ExecuteMessageCache.Add(typeof(string), true);
			_ExecuteMessageCache.Add(typeof(TimeSpan), true);
			_ExecuteMessageCache.Add(typeof(ushort), true);
			_ExecuteMessageCache.Add(typeof(uint), true);
			_ExecuteMessageCache.Add(typeof(ulong), true);
			_ExecuteMessageCache.Add(typeof(UIntPtr), true);
			_ExecuteMessageCache.Add(typeof(void), true);
		}

		private static bool IsMethodAutoDone2(MemberInfo m)
		{
			object[] customAttributes = m.GetCustomAttributes(typeof(AutoCompleteAttribute), inherit: true);
			object[] array = customAttributes;
			int num = 0;
			if (num < array.Length)
			{
				object obj = array[num];
				return ((AutoCompleteAttribute)obj).Value;
			}
			return false;
		}

		private static bool HasSpecialMethodAttributes2(MemberInfo m)
		{
			object[] customAttributes = m.GetCustomAttributes(inherit: true);
			object[] array = customAttributes;
			foreach (object obj in array)
			{
				if (obj is IConfigurationAttribute && !(obj is AutoCompleteAttribute))
				{
					return true;
				}
			}
			return false;
		}

		private static bool AreMethodsSecure2(Type t)
		{
			object[] customAttributes = t.GetCustomAttributes(typeof(SecureMethodAttribute), inherit: true);
			if (customAttributes != null && customAttributes.Length > 0)
			{
				return true;
			}
			return false;
		}

		private static bool HasClassInterface2(Type t)
		{
			object[] customAttributes = t.GetCustomAttributes(typeof(ClassInterfaceAttribute), inherit: false);
			if (customAttributes != null && customAttributes.Length > 0)
			{
				ClassInterfaceAttribute classInterfaceAttribute = (ClassInterfaceAttribute)customAttributes[0];
				if (classInterfaceAttribute.Value == ClassInterfaceType.AutoDual || classInterfaceAttribute.Value == ClassInterfaceType.AutoDispatch)
				{
					return true;
				}
			}
			customAttributes = t.Assembly.GetCustomAttributes(typeof(ClassInterfaceAttribute), inherit: true);
			if (customAttributes != null && customAttributes.Length > 0)
			{
				ClassInterfaceAttribute classInterfaceAttribute2 = (ClassInterfaceAttribute)customAttributes[0];
				if (classInterfaceAttribute2.Value == ClassInterfaceType.AutoDual || classInterfaceAttribute2.Value == ClassInterfaceType.AutoDispatch)
				{
					return true;
				}
			}
			return false;
		}

		internal static ClassInterfaceType GetClassInterfaceType(Type t)
		{
			object[] customAttributes = t.GetCustomAttributes(typeof(ClassInterfaceAttribute), inherit: false);
			if (customAttributes == null || customAttributes.Length == 0)
			{
				customAttributes = t.Assembly.GetCustomAttributes(typeof(ClassInterfaceAttribute), inherit: true);
				if (customAttributes == null || customAttributes.Length == 0)
				{
					return ClassInterfaceType.None;
				}
			}
			return ((ClassInterfaceAttribute)customAttributes[0]).Value;
		}
	}
	[Serializable]
	[Flags]
	public enum InstallationFlags
	{
		Default = 0,
		ExpectExistingTypeLib = 1,
		CreateTargetApplication = 2,
		FindOrCreateTargetApplication = 4,
		ReconfigureExistingApplication = 8,
		ConfigureComponentsOnly = 0x10,
		ReportWarningsToConsole = 0x20,
		Register = 0x100,
		Install = 0x200,
		Configure = 0x400
	}
	[Serializable]
	[Flags]
	internal enum ClassTypes
	{
		Event = 1,
		Normal = 2,
		All = 3
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("04C6BE1E-1DB1-4058-AB7A-700CCCFBF254")]
	internal interface ICatalogServices
	{
		[AutoComplete(true)]
		void Autodone();

		[AutoComplete(false)]
		void NotAutodone();
	}
	[Serializable]
	public sealed class RegistrationErrorInfo
	{
		private string _majorRef;

		private string _minorRef;

		private string _name;

		private int _errorCode;

		private string _errorString;

		public string MajorRef => _majorRef;

		public string MinorRef => _minorRef;

		public string Name => _name;

		public int ErrorCode => _errorCode;

		public string ErrorString => _errorString;

		internal RegistrationErrorInfo(string majorRef, string minorRef, string name, int errorCode)
		{
			_majorRef = majorRef;
			_minorRef = minorRef;
			_name = name;
			_errorCode = errorCode;
			if (_majorRef == null)
			{
				_majorRef = "";
			}
			if (_minorRef == null)
			{
				_minorRef = "<invalid>";
			}
			_errorString = Util.GetErrorString(_errorCode);
			if (_errorString == null)
			{
				_errorString = Resource.FormatString("Err_UnknownHR", _errorCode);
			}
		}
	}
	[Serializable]
	public sealed class RegistrationException : SystemException
	{
		private RegistrationErrorInfo[] _errorInfo;

		public RegistrationErrorInfo[] ErrorInfo => _errorInfo;

		public RegistrationException()
		{
		}

		public RegistrationException(string msg)
			: base(msg)
		{
			_errorInfo = null;
		}

		public RegistrationException(string msg, Exception inner)
			: base(msg, inner)
		{
			_errorInfo = null;
		}

		internal RegistrationException(string msg, RegistrationErrorInfo[] errorInfo)
			: base(msg)
		{
			_errorInfo = errorInfo;
		}

		internal RegistrationException(string msg, RegistrationErrorInfo[] errorInfo, Exception inner)
			: base(msg, inner)
		{
			_errorInfo = errorInfo;
		}

		internal RegistrationException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
			try
			{
				_errorInfo = (RegistrationErrorInfo[])info.GetValue("RegistrationException._errorInfo", typeof(RegistrationErrorInfo[]));
			}
			catch (SerializationException)
			{
				_errorInfo = null;
			}
		}

		public override void GetObjectData(SerializationInfo info, StreamingContext ctx)
		{
			if (info == null)
			{
				throw new ArgumentException(Resource.FormatString("Err_info"));
			}
			base.GetObjectData(info, ctx);
			if (_errorInfo != null)
			{
				info.AddValue("RegistrationException._errorInfo", _errorInfo, typeof(RegistrationErrorInfo[]));
			}
		}
	}
	internal delegate void Report(string msg);
	internal class RegistrationExporterNotifySink : ITypeLibExporterNotifySink
	{
		private string _tlb;

		private Report _report;

		internal RegistrationExporterNotifySink(string tlb, Report report)
		{
			_tlb = tlb;
			_report = report;
		}

		public void ReportEvent(ExporterEventKind EventKind, int EventCode, string EventMsg)
		{
			if (EventKind != 0 && _report != null)
			{
				_report(EventMsg);
			}
		}

		public object ResolveRef(Assembly asm)
		{
			ITypeLib typeLib = null;
			string directoryName = Path.GetDirectoryName(asm.Location);
			string text = Path.Combine(directoryName, asm.GetName().Name) + ".tlb";
			if (_report != null)
			{
				_report(Resource.FormatString("Reg_AutoExportMsg", asm.FullName, text));
			}
			return (ITypeLib)RegistrationDriver.GenerateTypeLibrary(asm, text, _report);
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("00020406-0000-0000-C000-000000000046")]
	internal interface ICreateTypeLib
	{
		[return: MarshalAs(UnmanagedType.Interface)]
		object CreateTypeInfo([In][MarshalAs(UnmanagedType.LPStr)] string szName, int tkind);

		void SetName(string szName);

		void SetVersion(short wMajorVerNum, short wMinorVerNum);

		void SetGuid([In][MarshalAs(UnmanagedType.LPStruct)] Guid guid);

		void SetDocString([In][MarshalAs(UnmanagedType.LPStr)] string szDoc);

		void SetHelpFileName([In][MarshalAs(UnmanagedType.LPStr)] string szHelpFileName);

		void SetHelpContext(int dwHelpContext);

		void SetLcid(int lcid);

		void SetLibFlags(int uLibFlags);

		void SaveAllChanges();
	}
	internal class ApplicationSpec
	{
		private RegistrationConfig _regConfig;

		private Assembly _asm;

		private Type[] _events;

		private Type[] _normal;

		private Type[] _cfgtypes;

		private string _appid;

		internal string Partition
		{
			get
			{
				return _regConfig.Partition;
			}
			set
			{
				_regConfig.Partition = value;
			}
		}

		internal string Name
		{
			get
			{
				return _regConfig.Application;
			}
			set
			{
				_regConfig.Application = value;
			}
		}

		internal string ID => _appid;

		internal string TypeLib => _regConfig.TypeLibrary;

		internal string File => _regConfig.AssemblyFile;

		internal string AppRootDir => _regConfig.ApplicationRootDirectory;

		internal Assembly Assembly => _asm;

		internal Type[] EventTypes => _events;

		internal Type[] NormalTypes => _normal;

		internal Type[] ConfigurableTypes => _cfgtypes;

		internal string DefinitiveName
		{
			get
			{
				if (ID != null)
				{
					return ID;
				}
				return Name;
			}
		}

		internal ApplicationSpec(Assembly asm, RegistrationConfig regConfig)
		{
			_asm = asm;
			_regConfig = regConfig;
			GenerateNames();
			ReadTypes();
		}

		private string FormatApplicationName(Assembly asm)
		{
			string text = null;
			object[] customAttributes = asm.GetCustomAttributes(typeof(ApplicationNameAttribute), inherit: true);
			if (customAttributes.Length > 0)
			{
				return ((ApplicationNameAttribute)customAttributes[0]).Value;
			}
			return asm.GetName().Name;
		}

		private void GenerateNames()
		{
			if (_regConfig.TypeLibrary == null || _regConfig.TypeLibrary.Length == 0)
			{
				string directoryName = Path.GetDirectoryName(File);
				_regConfig.TypeLibrary = Path.Combine(directoryName, _asm.GetName().Name + ".tlb");
			}
			else
			{
				_regConfig.TypeLibrary = Path.GetFullPath(_regConfig.TypeLibrary);
			}
			if (Name != null && Name.Length != 0 && '{' == Name[0])
			{
				_appid = string.Concat("{", new Guid(Name), "}");
				Name = null;
			}
			if (Name == null || Name.Length == 0)
			{
				Name = FormatApplicationName(_asm);
			}
			object[] customAttributes = _asm.GetCustomAttributes(typeof(ApplicationIDAttribute), inherit: true);
			if (customAttributes.Length > 0)
			{
				ApplicationIDAttribute applicationIDAttribute = (ApplicationIDAttribute)customAttributes[0];
				_appid = "{" + new Guid(applicationIDAttribute.Value.ToString()).ToString() + "}";
			}
		}

		public bool Matches(ICatalogObject obj)
		{
			if (ID != null)
			{
				Guid guid = new Guid(ID);
				Guid guid2 = new Guid((string)obj.GetValue("ID"));
				if (guid == guid2)
				{
					return true;
				}
			}
			else
			{
				string text = ((string)obj.GetValue("Name")).ToLower(CultureInfo.InvariantCulture);
				if (Name.ToLower(CultureInfo.InvariantCulture) == text)
				{
					return true;
				}
			}
			return false;
		}

		public override string ToString()
		{
			if (ID != null)
			{
				return "id=" + ID;
			}
			return "name=" + Name;
		}

		private void ReadTypes()
		{
			ArrayList arrayList = new ArrayList();
			ArrayList arrayList2 = new ArrayList();
			Type[] registrableTypesInAssembly = new RegistrationServices().GetRegistrableTypesInAssembly(_asm);
			Type[] array = registrableTypesInAssembly;
			foreach (Type type in array)
			{
				if (ServicedComponentInfo.IsTypeServicedComponent(type))
				{
					object[] customAttributes = type.GetCustomAttributes(typeof(EventClassAttribute), inherit: true);
					if (customAttributes != null && customAttributes.Length > 0)
					{
						arrayList.Add(type);
					}
					else
					{
						arrayList2.Add(type);
					}
				}
			}
			if (arrayList.Count > 0)
			{
				_events = new Type[arrayList.Count];
				arrayList.CopyTo(_events);
			}
			else
			{
				_events = null;
			}
			if (arrayList2.Count > 0)
			{
				_normal = new Type[arrayList2.Count];
				arrayList2.CopyTo(_normal);
			}
			else
			{
				_normal = null;
			}
			int num = ((_normal != null) ? _normal.Length : 0) + ((_events != null) ? _events.Length : 0);
			if (num > 0)
			{
				_cfgtypes = new Type[num];
				if (_events != null)
				{
					_events.CopyTo(_cfgtypes, 0);
				}
				if (_normal != null)
				{
					_normal.CopyTo(_cfgtypes, num - _normal.Length);
				}
			}
		}
	}
	internal class RegistrationDriver
	{
		private ICatalog _cat;

		private IMtsCatalog _mts;

		private ICatalogCollection _appColl;

		private Hashtable _cache;

		private InstallationFlags _installFlags;

		internal static void SaveChanges(ICatalogCollection coll)
		{
			coll.SaveChanges();
		}

		internal static void Populate(ICatalogCollection coll)
		{
			try
			{
				coll.Populate();
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode != Util.COMADMIN_E_OBJECTERRORS)
				{
					throw;
				}
			}
		}

		private static RegistrationErrorInfo[] BuildErrorInfoChain(ICatalogCollection coll)
		{
			try
			{
				Populate(coll);
				int num = coll.Count();
				RegistrationErrorInfo[] array = null;
				if (num > 0)
				{
					array = new RegistrationErrorInfo[num];
					for (int i = 0; i < num; i++)
					{
						string majorRef = null;
						string minorRef = null;
						int num2 = 0;
						ICatalogObject catalogObject = (ICatalogObject)coll.Item(i);
						string name = (string)catalogObject.GetValue("Name");
						num2 = (int)catalogObject.GetValue("ErrorCode");
						if (!Platform.IsLessThan(Platform.W2K))
						{
							majorRef = (string)catalogObject.GetValue("MajorRef");
							minorRef = (string)catalogObject.GetValue("MinorRef");
						}
						array[i] = new RegistrationErrorInfo(majorRef, minorRef, name, num2);
					}
				}
				return array;
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_ErrCollectionErr"), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.BuildErrorInfoChain"));
			}
		}

		private static void RegisterTypeLibrary(string tlb)
		{
			IntPtr pptlib = (IntPtr)0;
			tlb = Path.GetFullPath(tlb);
			int num = Util.LoadTypeLibEx(tlb, 1, out pptlib);
			if (num < 0 || pptlib == (IntPtr)0)
			{
				Exception exceptionForHR = Marshal.GetExceptionForHR(num);
				throw new RegistrationException(Resource.FormatString("Reg_TypeLibRegErr", tlb), exceptionForHR);
			}
			num = Util.RegisterTypeLib(pptlib, tlb, Path.GetDirectoryName(tlb));
			if (num < 0 || pptlib == (IntPtr)0)
			{
				Exception exceptionForHR2 = Marshal.GetExceptionForHR(num);
				throw new RegistrationException(Resource.FormatString("Reg_TypeLibRegErr", tlb), exceptionForHR2);
			}
			Marshal.Release(pptlib);
		}

		private RegistrationException WrapCOMException(ICatalogCollection coll, COMException e, string msg)
		{
			RegistrationErrorInfo[] errorInfo = null;
			if (e.ErrorCode == Util.COMADMIN_E_OBJECTERRORS)
			{
				ICatalogCollection catalogCollection = null;
				catalogCollection = ((coll != null) ? ((ICatalogCollection)coll.GetCollection("ErrorInfo", "")) : ((ICatalogCollection)_cat.GetCollection("ErrorInfo")));
				if (catalogCollection != null)
				{
					errorInfo = BuildErrorInfoChain(catalogCollection);
				}
			}
			return new RegistrationException(msg, errorInfo);
		}

		internal void ReportWarning(string msg)
		{
			if ((_installFlags & InstallationFlags.ReportWarningsToConsole) != 0)
			{
				Console.WriteLine(msg);
			}
		}

		public void CheckForAppSecurityAttribute(Assembly asm)
		{
			object[] customAttributes = asm.GetCustomAttributes(typeof(ApplicationAccessControlAttribute), inherit: true);
			if (customAttributes.Length <= 0)
			{
				ReportWarning(Resource.FormatString("Reg_NoApplicationSecurity"));
			}
		}

		public void CheckAssemblySCValidity(Assembly asm)
		{
			Type[] types = asm.GetTypes();
			bool flag = true;
			ArrayList arrayList = null;
			RegistrationServices registrationServices = new RegistrationServices();
			Type[] array = types;
			foreach (Type type in array)
			{
				if (!type.IsClass || !type.IsSubclassOf(typeof(ServicedComponent)))
				{
					continue;
				}
				if (!registrationServices.TypeRequiresRegistration(type) && !type.IsAbstract)
				{
					flag = false;
					if (arrayList == null)
					{
						arrayList = new ArrayList();
					}
					RegistrationErrorInfo value = new RegistrationErrorInfo(null, null, type.ToString(), -2147467259);
					arrayList.Add(value);
				}
				ClassInterfaceType classInterfaceType = ServicedComponentInfo.GetClassInterfaceType(type);
				MethodInfo[] methods = type.GetMethods();
				MethodInfo[] array2 = methods;
				foreach (MethodInfo methodInfo in array2)
				{
					MemberInfo memberInfo = ReflectionCache.ConvertToInterfaceMI(methodInfo);
					if (memberInfo == null)
					{
						if (ServicedComponentInfo.HasSpecialMethodAttributes(methodInfo))
						{
							ReportWarning(Resource.FormatString("Reg_NoClassInterfaceSecure", type.FullName, methodInfo.Name));
						}
						if (classInterfaceType == ClassInterfaceType.AutoDispatch && ServicedComponentInfo.IsMethodAutoDone(methodInfo))
						{
							ReportWarning(Resource.FormatString("Reg_NoClassInterface", type.FullName, methodInfo.Name));
						}
					}
				}
			}
			if (!flag)
			{
				RegistrationErrorInfo[] errorInfo = (RegistrationErrorInfo[])arrayList.ToArray(typeof(RegistrationErrorInfo));
				throw new RegistrationException(Resource.FormatString("Reg_InvalidServicedComponents"), errorInfo);
			}
		}

		internal bool AssemblyHasStrongName(Assembly asm)
		{
			return asm.GetName().GetPublicKeyToken().Length > 0;
		}

		internal Assembly NewLoadAssembly(string assembly)
		{
			Assembly assembly2;
			if (!File.Exists(assembly))
			{
				assembly2 = Assembly.Load(assembly);
				CheckAssemblySCValidity(assembly2);
			}
			else
			{
				assembly2 = LoadAssembly(assembly);
				CheckAssemblySCValidity(assembly2);
				if (!AssemblyHasStrongName(assembly2))
				{
					throw new RegistrationException(Resource.FormatString("Reg_NoStrongName", assembly));
				}
			}
			return assembly2;
		}

		internal Assembly LoadAssembly(string assembly)
		{
			assembly = Path.GetFullPath(assembly).ToLower(CultureInfo.InvariantCulture);
			bool flag = false;
			string text = null;
			string directoryName = Path.GetDirectoryName(assembly);
			text = Environment.CurrentDirectory;
			if (text != directoryName)
			{
				Environment.CurrentDirectory = directoryName;
				flag = true;
			}
			Assembly assembly2 = null;
			try
			{
				assembly2 = Assembly.LoadFrom(assembly);
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_AssemblyLoadErr", assembly), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.LoadAssembly"));
			}
			if (flag)
			{
				Environment.CurrentDirectory = text;
			}
			if (assembly2 == null)
			{
				throw new RegistrationException(Resource.FormatString("Reg_AssemblyLoadErr", assembly));
			}
			if (assembly2.GetName().Name == "System.EnterpriseServices")
			{
				throw new RegistrationException(Resource.FormatString("RegSvcs_NoBootstrap"));
			}
			return assembly2;
		}

		internal static object GenerateTypeLibrary(Assembly asm, string tlb, Report report)
		{
			try
			{
				TypeLibConverter typeLibConverter = new TypeLibConverter();
				RegistrationExporterNotifySink notifySink = new RegistrationExporterNotifySink(tlb, report);
				object obj = typeLibConverter.ConvertAssemblyToTypeLib(asm, tlb, TypeLibExporterFlags.OnlyReferenceRegistered, notifySink);
				ICreateTypeLib createTypeLib = (ICreateTypeLib)obj;
				createTypeLib.SaveAllChanges();
				RegisterTypeLibrary(tlb);
				return obj;
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_TypeLibGenErr", tlb, asm), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.GenerateTypeLibrary"));
			}
		}

		private void PostProcessApplication(ICatalogObject app, ApplicationSpec spec)
		{
			try
			{
				if (AfterSaveChanges(spec.Assembly, app, _appColl, "Application", _cache))
				{
					SaveChanges(_appColl);
				}
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_ConfigUnkErr"), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.PostProcessApplication"));
			}
		}

		private ICatalogObject CreateApplication(ApplicationSpec spec, bool checkExistence)
		{
			if (checkExistence)
			{
				ICatalogObject catalogObject = FindApplication(_appColl, spec);
				if (catalogObject != null)
				{
					throw new RegistrationException(Resource.FormatString("Reg_AppExistsErr", spec));
				}
			}
			ICatalogObject catalogObject2 = (ICatalogObject)_appColl.Add();
			CheckForAppSecurityAttribute(spec.Assembly);
			ApplicationDefaults(catalogObject2, _appColl);
			catalogObject2.SetValue("Name", spec.Name);
			if (spec.ID != null)
			{
				catalogObject2.SetValue("ID", spec.ID);
			}
			if (spec.AppRootDir != null)
			{
				Platform.Assert(Platform.Whistler, "ApplicationRootDirectory");
				catalogObject2.SetValue("ApplicationDirectory", spec.AppRootDir);
			}
			SaveChanges(_appColl);
			ConfigureObject(spec.Assembly, catalogObject2, _appColl, "Application", _cache);
			spec.Name = (string)catalogObject2.GetValue("Name");
			SaveChanges(_appColl);
			return catalogObject2;
		}

		private ICatalogObject FindOrCreateApplication(ApplicationSpec spec, bool configure)
		{
			ICatalogObject catalogObject = FindApplication(_appColl, spec);
			if (catalogObject == null)
			{
				catalogObject = CreateApplication(spec, checkExistence: false);
			}
			else if (configure)
			{
				CheckForAppSecurityAttribute(spec.Assembly);
				ApplicationDefaults(catalogObject, _appColl);
				catalogObject.SetValue("Name", spec.Name);
				if (!Platform.IsLessThan(Platform.Whistler))
				{
					catalogObject.SetValue("ApplicationDirectory", (spec.AppRootDir == null) ? "" : spec.AppRootDir);
				}
				ConfigureObject(spec.Assembly, catalogObject, _appColl, "Application", _cache);
				spec.Name = (string)catalogObject.GetValue("Name");
				SaveChanges(_appColl);
			}
			return catalogObject;
		}

		private void InstallTypeLibrary(ApplicationSpec spec)
		{
			if (Platform.IsLessThan(Platform.W2K))
			{
				InstallTypeLibrary_MTS(spec);
			}
			else
			{
				InstallTypeLibrary_W2K(spec);
			}
		}

		private void InstallTypeLibrary_W2K(ApplicationSpec spec)
		{
			try
			{
				object[] fileNames = new object[1] { spec.TypeLib };
				Type[] normalTypes = spec.NormalTypes;
				if (normalTypes != null)
				{
					if (normalTypes == null || normalTypes.Length == 0)
					{
						throw new RegistrationException(Resource.FormatString("Reg_NoConfigTypesErr"));
					}
					object[] CLSIDS = new object[normalTypes.Length];
					for (int i = 0; i < normalTypes.Length; i++)
					{
						CLSIDS[i] = "{" + Marshal.GenerateGuidForType(normalTypes[i]).ToString() + "}";
					}
					_cat.InstallMultipleComponents(spec.DefinitiveName, ref fileNames, ref CLSIDS);
				}
				normalTypes = spec.EventTypes;
				if (normalTypes != null)
				{
					if (normalTypes == null || normalTypes.Length == 0)
					{
						throw new RegistrationException(Resource.FormatString("Reg_NoConfigTypesErr"));
					}
					object[] CLSIDS2 = new object[normalTypes.Length];
					for (int j = 0; j < normalTypes.Length; j++)
					{
						CLSIDS2[j] = "{" + Marshal.GenerateGuidForType(normalTypes[j]).ToString() + "}";
					}
					_cat.InstallMultipleEventClasses(spec.DefinitiveName, ref fileNames, ref CLSIDS2);
				}
			}
			catch (COMException e)
			{
				throw WrapCOMException(null, e, Resource.FormatString("Reg_TypeLibInstallErr", spec.TypeLib, spec.Name));
			}
		}

		private void InstallTypeLibrary_MTS(ApplicationSpec spec)
		{
			ICatalogCollection catalogCollection = null;
			try
			{
				ICatalogObject catalogObject = FindApplication(_appColl, spec);
				catalogCollection = (ICatalogCollection)_appColl.GetCollection(CollectionName.Components, catalogObject.Key());
				Populate(catalogCollection);
				IComponentUtil componentUtil = (IComponentUtil)catalogCollection.GetUtilInterface();
				Type[] normalTypes = spec.NormalTypes;
				foreach (Type type in normalTypes)
				{
					Guid guid = Marshal.GenerateGuidForType(type);
					bool flag = false;
					for (int j = 0; j < catalogCollection.Count(); j++)
					{
						ICatalogObject catalogObject2 = (ICatalogObject)catalogCollection.Item(j);
						Guid guid2 = new Guid((string)catalogObject2.Key());
						if (guid2 == guid)
						{
							flag = true;
							break;
						}
					}
					if (!flag)
					{
						componentUtil.ImportComponent(string.Concat("{", guid, "}"));
					}
				}
			}
			catch (COMException e)
			{
				throw WrapCOMException(catalogCollection, e, Resource.FormatString("Reg_TypeLibInstallErr", spec.TypeLib, spec.Name));
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_TypeLibInstallErr", spec.TypeLib, spec.Name), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.InstallTypeLibrary_MTS"));
			}
		}

		private ICatalogObject FindApplication(ICatalogCollection apps, ApplicationSpec spec)
		{
			for (int i = 0; i < apps.Count(); i++)
			{
				ICatalogObject catalogObject = (ICatalogObject)apps.Item(i);
				if (spec.Matches(catalogObject))
				{
					return catalogObject;
				}
			}
			return null;
		}

		private void ApplicationDefaults(ICatalogObject obj, ICatalogCollection coll)
		{
			if (Platform.IsLessThan(Platform.W2K))
			{
				obj.SetValue("Activation", "Inproc");
				obj.SetValue("SecurityEnabled", "N");
				obj.SetValue("Authentication", AuthenticationOption.Packet);
			}
			else
			{
				obj.SetValue("Activation", ActivationOption.Library);
				obj.SetValue("AccessChecksLevel", AccessChecksLevelOption.Application);
				obj.SetValue("ApplicationAccessChecksEnabled", true);
				obj.SetValue("Authentication", AuthenticationOption.Packet);
				obj.SetValue("CRMEnabled", false);
				obj.SetValue("EventsEnabled", true);
				obj.SetValue("ImpersonationLevel", ImpersonationLevelOption.Impersonate);
				obj.SetValue("QueuingEnabled", false);
				obj.SetValue("QueueListenerEnabled", false);
			}
			if (!Platform.IsLessThan(Platform.Whistler))
			{
				obj.SetValue("SoapActivated", false);
				obj.SetValue("QCListenerMaxThreads", 0);
			}
		}

		internal bool ConfigureObject(ICustomAttributeProvider t, ICatalogObject obj, ICatalogCollection coll, string prefix, Hashtable cache)
		{
			bool result = false;
			object[] customAttributes = t.GetCustomAttributes(inherit: true);
			cache[prefix] = obj;
			cache[prefix + "Type"] = t;
			cache[prefix + "Collection"] = coll;
			cache["CurrentTarget"] = prefix;
			object[] array = customAttributes;
			foreach (object obj2 in array)
			{
				if (!(obj2 is IConfigurationAttribute))
				{
					continue;
				}
				try
				{
					IConfigurationAttribute configurationAttribute = (IConfigurationAttribute)obj2;
					if (configurationAttribute.IsValidTarget(prefix) && configurationAttribute.Apply(cache))
					{
						result = true;
					}
				}
				catch (Exception inner)
				{
					throw new RegistrationException(Resource.FormatString("Reg_ComponentAttrErr", obj.Name(), obj2), inner);
				}
				catch
				{
					throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.ConfigureObject"));
				}
			}
			return result;
		}

		internal bool AfterSaveChanges(ICustomAttributeProvider t, ICatalogObject obj, ICatalogCollection coll, string prefix, Hashtable cache)
		{
			bool result = false;
			object[] customAttributes = t.GetCustomAttributes(inherit: true);
			cache[prefix] = obj;
			cache[prefix + "Type"] = t;
			cache[prefix + "Collection"] = coll;
			cache["CurrentTarget"] = prefix;
			object[] array = customAttributes;
			foreach (object obj2 in array)
			{
				if (obj2 is IConfigurationAttribute)
				{
					IConfigurationAttribute configurationAttribute = (IConfigurationAttribute)obj2;
					if (configurationAttribute.IsValidTarget(prefix) && configurationAttribute.AfterSaveChanges(cache))
					{
						result = true;
					}
				}
			}
			return result;
		}

		internal void ConfigureCollection(ICatalogCollection coll, IConfigCallback cb)
		{
			bool flag = false;
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			securityPermission.Assert();
			foreach (object item in cb)
			{
				object a = cb.FindObject(coll, item);
				cb.ConfigureDefaults(a, item);
			}
			SaveChanges(coll);
			flag = false;
			foreach (object item2 in cb)
			{
				object a2 = cb.FindObject(coll, item2);
				if (cb.Configure(a2, item2))
				{
					flag = true;
				}
			}
			SaveChanges(coll);
			flag = false;
			foreach (object item3 in cb)
			{
				object a3 = cb.FindObject(coll, item3);
				if (cb.AfterSaveChanges(a3, item3))
				{
					flag = true;
				}
			}
			if (flag)
			{
				SaveChanges(coll);
			}
			cb.ConfigureSubCollections(coll);
		}

		private void ConfigureComponents(ApplicationSpec spec)
		{
			ICatalogCollection coll = null;
			try
			{
				ICatalogObject catalogObject = FindApplication(_appColl, spec);
				if (catalogObject == null)
				{
					throw new RegistrationException(Resource.FormatString("Reg_AppNotFoundErr", spec));
				}
				_cache["Application"] = catalogObject;
				_cache["ApplicationType"] = spec.Assembly;
				_cache["ApplicationCollection"] = _appColl;
				coll = (ICatalogCollection)_appColl.GetCollection(CollectionName.Components, catalogObject.Key());
				ConfigureCollection(coll, new ComponentConfigCallback(coll, spec, _cache, this, _installFlags));
			}
			catch (RegistrationException)
			{
				throw;
			}
			catch (COMException e)
			{
				throw WrapCOMException(coll, e, Resource.FormatString("Reg_ConfigErr"));
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_ConfigUnkErr"), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.ConfigureComponents"));
			}
		}

		internal bool IsAssemblyRegistered(ApplicationSpec spec)
		{
			bool result = false;
			if (spec == null || spec.ConfigurableTypes == null)
			{
				return false;
			}
			RegistryKey registryKey = Registry.ClassesRoot.OpenSubKey("CLSID");
			if (registryKey == null)
			{
				throw new RegistrationException(Resource.FormatString("Reg_RegistryErr"));
			}
			Type[] configurableTypes = spec.ConfigurableTypes;
			foreach (Type type in configurableTypes)
			{
				string name = "{" + Marshal.GenerateGuidForType(type).ToString() + "}";
				RegistryKey registryKey2 = null;
				RegistryKey registryKey3 = null;
				try
				{
					registryKey2 = registryKey.OpenSubKey(name);
					if (registryKey2 != null)
					{
						registryKey3 = registryKey2.OpenSubKey("InprocServer32");
						if (registryKey3 != null && registryKey3.GetValue("Assembly") != null && registryKey3.GetValue("Class") != null)
						{
							result = true;
							break;
						}
					}
				}
				catch
				{
				}
				finally
				{
					registryKey3?.Close();
					registryKey2?.Close();
				}
			}
			registryKey.Close();
			return result;
		}

		internal void UnregisterAssembly(Assembly asm, ApplicationSpec spec)
		{
			bool flag = true;
			if (asm == null || spec == null || spec.ConfigurableTypes == null)
			{
				return;
			}
			if (!Platform.IsLessThan(Platform.Whistler) && _cat != null)
			{
				Type[] configurableTypes = spec.ConfigurableTypes;
				foreach (Type type in configurableTypes)
				{
					string text = "{" + Marshal.GenerateGuidForType(type).ToString() + "}";
					try
					{
						int num = 0;
						Type type2 = _cat.GetType();
						try
						{
							num = (int)InvokeMemberHelper(type2, "GetComponentVersions", BindingFlags.InvokeMethod, null, _cat, new object[5] { text, null, null, null, null });
						}
						catch (COMException ex)
						{
							if (Util.DISP_E_UNKNOWNNAME != ex.ErrorCode)
							{
								throw;
							}
							num = (int)InvokeMemberHelper(type2, "GetComponentVersionCount", BindingFlags.InvokeMethod, null, _cat, new object[1] { text });
						}
						if (num > 0)
						{
							flag = false;
							break;
						}
					}
					catch (COMException ex2)
					{
						if (Util.REGDB_E_CLASSNOTREG != ex2.ErrorCode)
						{
							throw;
						}
					}
				}
			}
			if (!flag)
			{
				return;
			}
			ClassicUnregistration(asm);
			try
			{
				UnregisterTypeLib(asm);
			}
			catch
			{
			}
		}

		internal void ClassicRegistration(Assembly asm)
		{
			RegistryPermission registryPermission = new RegistryPermission(PermissionState.Unrestricted);
			registryPermission.Demand();
			registryPermission.Assert();
			try
			{
				RegistrationServices registrationServices = new RegistrationServices();
				registrationServices.RegisterAssembly(asm, AssemblyRegistrationFlags.SetCodeBase);
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_AssemblyRegErr", asm), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.ClassicRegistration"));
			}
		}

		internal void ClassicUnregistration(Assembly asm)
		{
			try
			{
				new RegistrationServices().UnregisterAssembly(asm);
			}
			catch (Exception inner)
			{
				throw new RegistrationException(Resource.FormatString("Reg_AssemblyUnregErr", asm), inner);
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.ClassicUnregistration"));
			}
		}

		internal void UnregisterTypeLib(Assembly asm)
		{
			IntPtr ppTLibAttr = IntPtr.Zero;
			object pptlib = null;
			ITypeLib typeLib = null;
			try
			{
				Guid typeLibGuidForAssembly = Marshal.GetTypeLibGuidForAssembly(asm);
				Version version = asm.GetName().Version;
				if (version.Major == 0 && version.Minor == 0)
				{
					version = new Version(1, 0);
				}
				if (Util.LoadRegTypeLib(typeLibGuidForAssembly, (short)version.Major, (short)version.Minor, 0, out pptlib) == 0)
				{
					typeLib = (ITypeLib)pptlib;
					typeLib.GetLibAttr(out ppTLibAttr);
					System.Runtime.InteropServices.ComTypes.TYPELIBATTR tYPELIBATTR = (System.Runtime.InteropServices.ComTypes.TYPELIBATTR)Marshal.PtrToStructure(ppTLibAttr, typeof(System.Runtime.InteropServices.ComTypes.TYPELIBATTR));
					Util.UnRegisterTypeLib(tYPELIBATTR.guid, tYPELIBATTR.wMajorVerNum, tYPELIBATTR.wMinorVerNum, tYPELIBATTR.lcid, tYPELIBATTR.syskind);
				}
			}
			finally
			{
				if (typeLib != null && ppTLibAttr != IntPtr.Zero)
				{
					typeLib.ReleaseTLibAttr(ppTLibAttr);
				}
				if (typeLib != null)
				{
					Marshal.ReleaseComObject(typeLib);
				}
			}
		}

		private object InvokeMemberHelper(Type type, string name, BindingFlags invokeAttr, Binder binder, object target, object[] args)
		{
			try
			{
				return type.InvokeMember(name, invokeAttr, binder, target, args, CultureInfo.InvariantCulture);
			}
			catch (TargetInvocationException ex)
			{
				throw ex.InnerException;
			}
		}

		private void PrepDriver(ref ApplicationSpec spec)
		{
			if (Platform.IsLessThan(Platform.W2K))
			{
				try
				{
					_cat = null;
					_mts = (IMtsCatalog)new xMtsCatalog();
					_appColl = (ICatalogCollection)_mts.GetCollection(CollectionName.Applications);
					Populate(_appColl);
				}
				catch (Exception inner)
				{
					throw new RegistrationException(Resource.FormatString("Reg_CatalogErr"), inner);
				}
				catch
				{
					throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.PrepDriver"));
				}
			}
			else if (Platform.IsLessThan(Platform.Whistler))
			{
				try
				{
					_mts = null;
					_cat = (ICatalog)new xCatalog();
					_appColl = (ICatalogCollection)_cat.GetCollection(CollectionName.Applications);
					Populate(_appColl);
				}
				catch (Exception inner2)
				{
					throw new RegistrationException(Resource.FormatString("Reg_CatalogErr"), inner2);
				}
				catch
				{
					throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.PrepDriver"));
				}
			}
			else
			{
				try
				{
					_cat = (ICatalog)new xCatalog();
				}
				catch (Exception inner3)
				{
					throw new RegistrationException(Resource.FormatString("Reg_CatalogErr"), inner3);
				}
				catch
				{
					throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.PrepDriver"));
				}
				if ((spec.Partition == null || spec.Partition.Length == 0) && spec.ID != null)
				{
					try
					{
						Type type = _cat.GetType();
						try
						{
							spec.Partition = (string)InvokeMemberHelper(type, "GetAppPartitionId", BindingFlags.InvokeMethod, null, _cat, new object[1] { spec.ID });
						}
						catch (COMException ex)
						{
							if (Util.DISP_E_UNKNOWNNAME == ex.ErrorCode)
							{
								spec.Partition = (string)InvokeMemberHelper(type, "GetPartitionID", BindingFlags.InvokeMethod, null, _cat, new object[1] { spec.ID });
							}
						}
					}
					catch
					{
					}
				}
				if (spec.Partition != null && spec.Partition.Length != 0)
				{
					try
					{
						Type type2 = _cat.GetType();
						try
						{
							InvokeMemberHelper(type2, "SetApplicationPartition", BindingFlags.InvokeMethod, null, _cat, new object[1] { spec.Partition });
						}
						catch (COMException ex2)
						{
							if (Util.DISP_E_UNKNOWNNAME != ex2.ErrorCode)
							{
								throw;
							}
							InvokeMemberHelper(type2, "CurrentPartition", BindingFlags.SetProperty, null, _cat, new object[1] { spec.Partition });
						}
					}
					catch (Exception inner4)
					{
						throw new RegistrationException(Resource.FormatString("Reg_PartitionErr", spec.Partition), inner4);
					}
					catch
					{
						throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.PrepDriver"));
					}
				}
				try
				{
					_mts = null;
					_appColl = (ICatalogCollection)_cat.GetCollection(CollectionName.Applications);
					Populate(_appColl);
				}
				catch (Exception inner5)
				{
					throw new RegistrationException(Resource.FormatString("Reg_CatalogErr"), inner5);
				}
				catch
				{
					throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.PrepDriver"));
				}
			}
			_cache = new Hashtable();
		}

		private void CleanupDriver()
		{
			_cat = null;
			_cache = null;
			_appColl = null;
		}

		private void PrepArguments(RegistrationConfig regConfig)
		{
			if (regConfig.AssemblyFile == null || regConfig.AssemblyFile.Length == 0)
			{
				throw new RegistrationException(Resource.FormatString("Reg_ArgumentAssembly"));
			}
			if ((regConfig.InstallationFlags & InstallationFlags.ExpectExistingTypeLib) != 0 && (regConfig.TypeLibrary == null || regConfig.TypeLibrary.Length == 0))
			{
				throw new RegistrationException(Resource.FormatString("Reg_ExpectExisting"));
			}
			if ((regConfig.InstallationFlags & InstallationFlags.CreateTargetApplication) != 0 && (regConfig.InstallationFlags & InstallationFlags.FindOrCreateTargetApplication) != 0)
			{
				throw new RegistrationException(Resource.FormatString("Reg_CreateFlagErr"));
			}
			if ((regConfig.InstallationFlags & InstallationFlags.Register) == 0 && (regConfig.InstallationFlags & InstallationFlags.Install) == 0 && (regConfig.InstallationFlags & InstallationFlags.Configure) == 0)
			{
				regConfig.InstallationFlags |= InstallationFlags.Register | InstallationFlags.Install | InstallationFlags.Configure;
			}
			_installFlags = regConfig.InstallationFlags;
			if (Platform.IsLessThan(Platform.W2K))
			{
				_installFlags |= InstallationFlags.ConfigureComponentsOnly;
			}
			if (regConfig.Partition != null && regConfig.Partition.Length != 0)
			{
				string strB = "Base Application Partition";
				string strB2 = "{41E90F3E-56C1-4633-81C3-6E8BAC8BDD70}";
				if (string.Compare(regConfig.Partition, strB2, StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(regConfig.Partition, strB, StringComparison.OrdinalIgnoreCase) == 0)
				{
					regConfig.Partition = null;
				}
				if (regConfig.Partition != null && Platform.IsLessThan(Platform.Whistler))
				{
					throw new RegistrationException(Resource.FormatString("Reg_PartitionsNotSupported"));
				}
			}
			if (regConfig.ApplicationRootDirectory != null && !Directory.Exists(regConfig.ApplicationRootDirectory))
			{
				throw new RegistrationException(Resource.FormatString("Reg_BadAppRootDir"));
			}
		}

		private bool ValidateBitness(ApplicationSpec spec, out string message)
		{
			bool flag = false;
			bool result = true;
			message = string.Empty;
			if (!Wow64Helper.IsWow64Supported())
			{
				return result;
			}
			flag = Wow64Helper.IsWow64Process();
			ICatalogObject catalogObject = FindApplication(_appColl, spec);
			if (catalogObject == null)
			{
				return result;
			}
			ICatalogCollection catalogCollection = (ICatalogCollection)_appColl.GetCollection(CollectionName.Components, catalogObject.Key());
			Populate(catalogCollection);
			int num = catalogCollection.Count();
			if (num <= 0)
			{
				return result;
			}
			Guid[] array = new Guid[spec.ConfigurableTypes.Length];
			for (int i = 0; i < spec.ConfigurableTypes.Length; i++)
			{
				ref Guid reference = ref array[i];
				reference = Marshal.GenerateGuidForType(spec.ConfigurableTypes[i]);
			}
			for (int j = 0; j < num; j++)
			{
				ICatalogObject catalogObject2 = (ICatalogObject)catalogCollection.Item(j);
				string g = (string)catalogObject2.Key();
				Guid key = new Guid(g);
				if (FindIndexOf(array, key) != -1)
				{
					int num2 = (int)catalogObject2.GetValue("Bitness");
					if (flag && num2 == 2)
					{
						message = Resource.FormatString("Reg_Already64bit");
						result = false;
						break;
					}
					if (!flag && num2 == 1)
					{
						message = Resource.FormatString("Reg_Already32bit");
						result = false;
						break;
					}
				}
			}
			return result;
		}

		public void InstallAssembly(RegistrationConfig regConfig, object obSync)
		{
			Assembly assembly = null;
			ApplicationSpec applicationSpec = null;
			CatalogSync catalogSync = null;
			bool flag = false;
			bool flag2 = false;
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			try
			{
				securityPermission.Demand();
				securityPermission.Assert();
				ICatalogObject catalogObject = null;
				PrepArguments(regConfig);
				assembly = NewLoadAssembly(regConfig.AssemblyFile);
				applicationSpec = new ApplicationSpec(assembly, regConfig);
				if (applicationSpec.ConfigurableTypes == null)
				{
					regConfig.Application = null;
					regConfig.TypeLibrary = null;
					return;
				}
				if (obSync != null)
				{
					if (!(obSync is CatalogSync))
					{
						throw new ArgumentException(Resource.FormatString("Err_obSync"));
					}
					catalogSync = (CatalogSync)obSync;
				}
				PrepDriver(ref applicationSpec);
				string message = string.Empty;
				if (!ValidateBitness(applicationSpec, out message))
				{
					throw new RegistrationException(message);
				}
				if ((regConfig.InstallationFlags & InstallationFlags.Register) != 0)
				{
					flag = !IsAssemblyRegistered(applicationSpec);
					ClassicRegistration(applicationSpec.Assembly);
					if ((regConfig.InstallationFlags & InstallationFlags.ExpectExistingTypeLib) != 0)
					{
						RegisterTypeLibrary(applicationSpec.TypeLib);
					}
					else
					{
						flag2 = true;
						GenerateTypeLibrary(applicationSpec.Assembly, applicationSpec.TypeLib, ReportWarning);
					}
				}
				if ((regConfig.InstallationFlags & InstallationFlags.Install) != 0 && applicationSpec.ConfigurableTypes != null)
				{
					if ((regConfig.InstallationFlags & InstallationFlags.CreateTargetApplication) != 0)
					{
						catalogObject = CreateApplication(applicationSpec, checkExistence: true);
					}
					else if ((regConfig.InstallationFlags & InstallationFlags.FindOrCreateTargetApplication) != 0)
					{
						catalogObject = FindOrCreateApplication(applicationSpec, (regConfig.InstallationFlags & InstallationFlags.ReconfigureExistingApplication) != 0);
					}
					InstallTypeLibrary(applicationSpec);
					catalogSync?.Set();
				}
				if ((regConfig.InstallationFlags & InstallationFlags.Configure) != 0 && applicationSpec.ConfigurableTypes != null)
				{
					ConfigureComponents(applicationSpec);
					catalogSync?.Set();
				}
				if (catalogObject != null)
				{
					PostProcessApplication(catalogObject, applicationSpec);
				}
				CleanupDriver();
			}
			catch (Exception ex)
			{
				if (ex is SecurityException || ex is UnauthorizedAccessException || (ex.InnerException != null && (ex.InnerException is SecurityException || ex.InnerException is UnauthorizedAccessException)))
				{
					ex = new RegistrationException(Resource.FormatString("Reg_Unauthorized"), ex);
				}
				if (flag && assembly != null)
				{
					try
					{
						ClassicUnregistration(assembly);
					}
					catch
					{
					}
				}
				if (flag2 && assembly != null)
				{
					try
					{
						UnregisterTypeLib(assembly);
					}
					catch
					{
					}
				}
				throw ex;
			}
			catch
			{
				throw new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationDriver.InstallAssembly"));
			}
		}

		private int FindIndexOf(string[] arr, string key)
		{
			for (int i = 0; i < arr.Length; i++)
			{
				if (arr[i] == key)
				{
					return i;
				}
			}
			return -1;
		}

		private int FindIndexOf(Guid[] arr, Guid key)
		{
			for (int i = 0; i < arr.Length; i++)
			{
				if (arr[i] == key)
				{
					return i;
				}
			}
			return -1;
		}

		public void UninstallAssembly(RegistrationConfig regConfig, object obSync)
		{
			CatalogSync catalogSync = null;
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			securityPermission.Assert();
			if (obSync != null)
			{
				if (!(obSync is CatalogSync))
				{
					throw new ArgumentException(Resource.FormatString("Err_obSync"));
				}
				catalogSync = (CatalogSync)obSync;
			}
			Assembly asm = NewLoadAssembly(regConfig.AssemblyFile);
			ApplicationSpec spec = new ApplicationSpec(asm, regConfig);
			if (spec.ConfigurableTypes == null)
			{
				return;
			}
			PrepDriver(ref spec);
			if (spec.ConfigurableTypes != null)
			{
				ICatalogObject catalogObject = FindApplication(_appColl, spec);
				if (catalogObject == null)
				{
					throw new RegistrationException(Resource.FormatString("Reg_AppNotFoundErr", spec));
				}
				ICatalogCollection catalogCollection = (ICatalogCollection)_appColl.GetCollection(CollectionName.Components, catalogObject.Key());
				string[] array = new string[spec.ConfigurableTypes.Length];
				int num = 0;
				Type[] configurableTypes = spec.ConfigurableTypes;
				foreach (Type type in configurableTypes)
				{
					array[num] = Marshal.GenerateGuidForType(type).ToString();
					num++;
				}
				Populate(catalogCollection);
				bool flag = true;
				int num2 = 0;
				while (num2 < catalogCollection.Count())
				{
					ICatalogObject catalogObject2 = (ICatalogObject)catalogCollection.Item(num2);
					string g = (string)catalogObject2.Key();
					g = new Guid(g).ToString();
					if (FindIndexOf(array, g) != -1)
					{
						catalogCollection.Remove(num2);
						catalogSync?.Set();
					}
					else
					{
						num2++;
						flag = false;
					}
				}
				SaveChanges(catalogCollection);
				if (flag)
				{
					for (int j = 0; j < _appColl.Count(); j++)
					{
						ICatalogObject catalogObject3 = (ICatalogObject)_appColl.Item(j);
						if (catalogObject3.Key().Equals(catalogObject.Key()))
						{
							_appColl.Remove(j);
							catalogSync?.Set();
							break;
						}
					}
					SaveChanges(_appColl);
				}
			}
			UnregisterAssembly(asm, spec);
			CleanupDriver();
		}
	}
	internal class Wow64Helper
	{
		private const uint ERROR_CALL_NOT_IMPLEMENTED = 120u;

		private const int MAX_PATH = 260;

		[DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern uint GetSystemWow64Directory(char[] buffer, int length);

		[DllImport("KERNEL32.DLL", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
		private static extern bool IsWow64Process(IntPtr hProcess, ref bool bIsWow);

		[DllImport("KERNEL32.DLL", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
		private static extern IntPtr GetCurrentProcess();

		private Wow64Helper()
		{
		}

		public static bool IsWow64Supported()
		{
			bool result = false;
			char[] buffer = new char[260];
			uint num = 0u;
			try
			{
				num = GetSystemWow64Directory(buffer, 260);
			}
			catch (EntryPointNotFoundException)
			{
				return result;
			}
			if (num == 0)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if ((long)lastWin32Error != 120)
				{
					throw new RegistrationException(Resource.FormatString("Reg_CannotDetermineWow64", lastWin32Error));
				}
			}
			else
			{
				if (num == 0)
				{
					throw new RegistrationException(Resource.FormatString("Reg_CannotDetermineWow64Ex", num));
				}
				result = true;
			}
			return result;
		}

		public static bool IsWow64Process()
		{
			bool bIsWow = false;
			if (!IsWow64Supported())
			{
				return bIsWow;
			}
			try
			{
				if (!IsWow64Process(GetCurrentProcess(), ref bIsWow))
				{
					throw new RegistrationException(Resource.FormatString("Reg_CannotDetermineBitness", Marshal.GetLastWin32Error()));
				}
				return bIsWow;
			}
			catch (EntryPointNotFoundException)
			{
				return false;
			}
		}
	}
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("55e3ea25-55cb-4650-8887-18e8d30bb4bc")]
	public interface IRegistrationHelper
	{
		void InstallAssembly([In][MarshalAs(UnmanagedType.BStr)] string assembly, [In][Out][MarshalAs(UnmanagedType.BStr)] ref string application, [In][Out][MarshalAs(UnmanagedType.BStr)] ref string tlb, [In] InstallationFlags installFlags);

		void UninstallAssembly([In][MarshalAs(UnmanagedType.BStr)] string assembly, [In][MarshalAs(UnmanagedType.BStr)] string application);
	}
	[Serializable]
	[Guid("36dcda30-dc3b-4d93-be42-90b2d74c64e7")]
	public class RegistrationConfig
	{
		private string _assmfile;

		private InstallationFlags _flags;

		private string _application;

		private string _typelib;

		private string _partition;

		private string _approotdir;

		public string AssemblyFile
		{
			get
			{
				return _assmfile;
			}
			set
			{
				_assmfile = value;
			}
		}

		public InstallationFlags InstallationFlags
		{
			get
			{
				return _flags;
			}
			set
			{
				_flags = value;
			}
		}

		public string Application
		{
			get
			{
				return _application;
			}
			set
			{
				_application = value;
			}
		}

		public string TypeLibrary
		{
			get
			{
				return _typelib;
			}
			set
			{
				_typelib = value;
			}
		}

		public string Partition
		{
			get
			{
				return _partition;
			}
			set
			{
				_partition = value;
			}
		}

		public string ApplicationRootDirectory
		{
			get
			{
				return _approotdir;
			}
			set
			{
				_approotdir = value;
			}
		}
	}
	internal class RegistrationThreadWrapper
	{
		private RegistrationHelper _helper;

		private RegistrationConfig _regConfig;

		private Exception _exception;

		internal RegistrationThreadWrapper(RegistrationHelper helper, RegistrationConfig regConfig)
		{
			_regConfig = regConfig;
			_helper = helper;
			_exception = null;
		}

		internal void InstallThread()
		{
			try
			{
				_helper.InstallAssemblyFromConfig(ref _regConfig);
			}
			catch (Exception exception)
			{
				Exception ex = (_exception = exception);
			}
			catch
			{
				_exception = new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationThreadWrapper, InstallThread"));
			}
		}

		internal void UninstallThread()
		{
			try
			{
				_helper.UninstallAssemblyFromConfig(ref _regConfig);
			}
			catch (Exception exception)
			{
				Exception ex = (_exception = exception);
			}
			catch
			{
				_exception = new RegistrationException(Resource.FormatString("Err_NonClsException", "RegistrationThreadWrapper, UninstallThread"));
			}
		}

		internal void PropInstallResult()
		{
			if (_exception != null)
			{
				throw _exception;
			}
		}

		internal void PropUninstallResult()
		{
			if (_exception != null)
			{
				throw _exception;
			}
		}
	}
	[Guid("89a86e7b-c229-4008-9baa-2f5c8411d7e0")]
	public sealed class RegistrationHelper : MarshalByRefObject, IRegistrationHelper, System.EnterpriseServices.Thunk.IThunkInstallation
	{
		void System.EnterpriseServices.Thunk.IThunkInstallation.DefaultInstall(string asm)
		{
			string application = null;
			string tlb = null;
			InstallAssembly(asm, ref application, ref tlb, InstallationFlags.FindOrCreateTargetApplication | InstallationFlags.ReconfigureExistingApplication);
		}

		public void InstallAssembly(string assembly, ref string application, ref string tlb, InstallationFlags installFlags)
		{
			InstallAssembly(assembly, ref application, null, ref tlb, installFlags);
		}

		public void InstallAssembly(string assembly, ref string application, string partition, ref string tlb, InstallationFlags installFlags)
		{
			RegistrationConfig regConfig = new RegistrationConfig();
			regConfig.AssemblyFile = assembly;
			regConfig.Application = application;
			regConfig.Partition = partition;
			regConfig.TypeLibrary = tlb;
			regConfig.InstallationFlags = installFlags;
			InstallAssemblyFromConfig(ref regConfig);
			application = regConfig.Application;
			tlb = regConfig.TypeLibrary;
		}

		public void InstallAssemblyFromConfig([MarshalAs(UnmanagedType.IUnknown)] ref RegistrationConfig regConfig)
		{
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			securityPermission.Assert();
			Platform.Assert(Platform.W2K, "RegistrationHelper.InstallAssemblyFromConfig");
			if (Thread.CurrentThread.GetApartmentState() == ApartmentState.STA)
			{
				RegistrationThreadWrapper registrationThreadWrapper = new RegistrationThreadWrapper(this, regConfig);
				Thread thread = new Thread(registrationThreadWrapper.InstallThread);
				thread.Start();
				thread.Join();
				registrationThreadWrapper.PropInstallResult();
				return;
			}
			if (!Platform.Supports(PlatformFeature.SWC))
			{
				if (Platform.IsLessThan(Platform.W2K) || !TryTransactedInstall(regConfig))
				{
					RegistrationDriver registrationDriver = new RegistrationDriver();
					registrationDriver.InstallAssembly(regConfig, null);
				}
				return;
			}
			TransactionOptions transactionOptions = default(TransactionOptions);
			transactionOptions.Timeout = TimeSpan.FromSeconds(0.0);
			transactionOptions.IsolationLevel = IsolationLevel.Serializable;
			CatalogSync catalogSync = new CatalogSync();
			using (TransactionScope transactionScope = new TransactionScope(TransactionScopeOption.Required, transactionOptions, EnterpriseServicesInteropOption.Full))
			{
				RegistrationDriver registrationDriver2 = new RegistrationDriver();
				registrationDriver2.InstallAssembly(regConfig, catalogSync);
				transactionScope.Complete();
			}
			catalogSync.Wait();
		}

		public void UninstallAssembly(string assembly, string application)
		{
			UninstallAssembly(assembly, application, null);
		}

		public void UninstallAssembly(string assembly, string application, string partition)
		{
			RegistrationConfig regConfig = new RegistrationConfig();
			regConfig.AssemblyFile = assembly;
			regConfig.Application = application;
			regConfig.Partition = partition;
			UninstallAssemblyFromConfig(ref regConfig);
		}

		public void UninstallAssemblyFromConfig([MarshalAs(UnmanagedType.IUnknown)] ref RegistrationConfig regConfig)
		{
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			securityPermission.Assert();
			Platform.Assert(Platform.W2K, "RegistrationHelper.UninstallAssemblyFromConfig");
			if (Thread.CurrentThread.GetApartmentState() == ApartmentState.STA)
			{
				RegistrationThreadWrapper registrationThreadWrapper = new RegistrationThreadWrapper(this, regConfig);
				Thread thread = new Thread(registrationThreadWrapper.UninstallThread);
				thread.Start();
				thread.Join();
				registrationThreadWrapper.PropUninstallResult();
				return;
			}
			if (!Platform.Supports(PlatformFeature.SWC))
			{
				if (Platform.IsLessThan(Platform.W2K) || !TryTransactedUninstall(regConfig))
				{
					RegistrationDriver registrationDriver = new RegistrationDriver();
					registrationDriver.UninstallAssembly(regConfig, null);
				}
				return;
			}
			TransactionOptions transactionOptions = default(TransactionOptions);
			transactionOptions.Timeout = TimeSpan.FromMinutes(0.0);
			transactionOptions.IsolationLevel = IsolationLevel.Serializable;
			CatalogSync catalogSync = new CatalogSync();
			using (TransactionScope transactionScope = new TransactionScope(TransactionScopeOption.Required, transactionOptions, EnterpriseServicesInteropOption.Full))
			{
				RegistrationDriver registrationDriver2 = new RegistrationDriver();
				registrationDriver2.UninstallAssembly(regConfig, catalogSync);
				transactionScope.Complete();
			}
			catalogSync.Wait();
		}

		private bool TryTransactedInstall(RegistrationConfig regConfig)
		{
			RegistrationHelperTx registrationHelperTx = null;
			try
			{
				registrationHelperTx = new RegistrationHelperTx();
				if (!registrationHelperTx.IsInTransaction())
				{
					registrationHelperTx = null;
				}
			}
			catch (Exception ex)
			{
				try
				{
					EventLog eventLog = new EventLog();
					eventLog.Source = "System.EnterpriseServices";
					string message = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrTxInst"), ex);
					eventLog.WriteEntry(message, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
			catch
			{
				try
				{
					EventLog eventLog2 = new EventLog();
					eventLog2.Source = "System.EnterpriseServices";
					string message2 = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrTxInst"), Resource.FormatString("Err_NonClsException", "RegistrationHelper.TryTransactedInstall"));
					eventLog2.WriteEntry(message2, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
			if (registrationHelperTx == null)
			{
				return false;
			}
			CatalogSync catalogSync = new CatalogSync();
			registrationHelperTx.InstallAssemblyFromConfig(ref regConfig, catalogSync);
			catalogSync.Wait();
			return true;
		}

		private bool TryTransactedUninstall(RegistrationConfig regConfig)
		{
			RegistrationHelperTx registrationHelperTx = null;
			try
			{
				registrationHelperTx = new RegistrationHelperTx();
				if (!registrationHelperTx.IsInTransaction())
				{
					registrationHelperTx = null;
				}
			}
			catch (Exception ex)
			{
				try
				{
					EventLog eventLog = new EventLog();
					eventLog.Source = "System.EnterpriseServices";
					string message = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrTxUninst"), ex);
					eventLog.WriteEntry(message, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
			catch
			{
				try
				{
					EventLog eventLog2 = new EventLog();
					eventLog2.Source = "System.EnterpriseServices";
					string message2 = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrTxInst"), Resource.FormatString("Err_NonClsException", "RegistrationHelper.TryTransactedUninstall"));
					eventLog2.WriteEntry(message2, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
			if (registrationHelperTx == null)
			{
				return false;
			}
			CatalogSync catalogSync = new CatalogSync();
			registrationHelperTx.UninstallAssemblyFromConfig(ref regConfig, catalogSync);
			catalogSync.Wait();
			return true;
		}
	}
	internal class CatalogSync
	{
		private bool _set;

		private int _version;

		internal CatalogSync()
		{
			_set = false;
			_version = 0;
		}

		internal void Set()
		{
			try
			{
				if (!_set && ContextUtil.IsInTransaction)
				{
					_set = true;
					RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Classes\\CLSID");
					_version = (int)registryKey.GetValue("CLBVersion", 0);
				}
			}
			catch
			{
				_set = false;
				_version = 0;
			}
		}

		internal void Wait()
		{
			if (!_set)
			{
				return;
			}
			RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Classes\\CLSID");
			while (true)
			{
				int num = (int)registryKey.GetValue("CLBVersion", 0);
				if (num != _version)
				{
					break;
				}
				Thread.Sleep(0);
			}
			_set = false;
		}
	}
	[Transaction(TransactionOption.RequiresNew)]
	[Guid("c89ac250-e18a-4fc7-abd5-b8897b6a78a5")]
	public sealed class RegistrationHelperTx : ServicedComponent
	{
		private static Guid _appid;

		private static string _appname;

		private static bool _isRunningInWow64;

		private static Guid _appidNoWow64;

		private static string _appnameNoWow64;

		private static Guid _appidWow64;

		private static string _appnameWow64;

		static RegistrationHelperTx()
		{
			_appidNoWow64 = new Guid("1e246775-2281-484f-8ad4-044c15b86eb7");
			_appnameNoWow64 = ".NET Utilities";
			_appidWow64 = new Guid("57926702-ab7c-402b-abce-e262da1dd7c9");
			_appnameWow64 = ".NET Utilities (32 bit)";
			if (Wow64Helper.IsWow64Process())
			{
				_appid = _appidWow64;
				_appname = _appnameWow64;
				_isRunningInWow64 = true;
			}
			else
			{
				_appid = _appidNoWow64;
				_appname = _appnameNoWow64;
				_isRunningInWow64 = false;
			}
		}

		private static ICatalogObject FindApplication(ICatalogCollection coll, Guid appid, ref int idx)
		{
			int num = coll.Count();
			for (int i = 0; i < num; i++)
			{
				ICatalogObject catalogObject = (ICatalogObject)coll.Item(i);
				Guid guid = new Guid((string)catalogObject.GetValue("ID"));
				if (guid == appid)
				{
					idx = i;
					return catalogObject;
				}
			}
			return null;
		}

		private static ICatalogObject FindComponent(ICatalogCollection coll, Guid clsid, ref int idx)
		{
			RegistrationDriver.Populate(coll);
			int num = coll.Count();
			for (int i = 0; i < num; i++)
			{
				ICatalogObject catalogObject = (ICatalogObject)coll.Item(i);
				Guid guid = new Guid((string)catalogObject.GetValue("CLSID"));
				if (guid == clsid)
				{
					idx = i;
					return catalogObject;
				}
			}
			return null;
		}

		private static void ConfigureComponent(ICatalogCollection coll, ICatalogObject obj)
		{
			obj.SetValue("Transaction", TransactionOption.RequiresNew);
			obj.SetValue("ComponentTransactionTimeoutEnabled", true);
			obj.SetValue("ComponentTransactionTimeout", 0);
			coll.SaveChanges();
		}

		[ComRegisterFunction]
		internal static void InstallUtilityApplication(Type t)
		{
			if (Platform.Supports(PlatformFeature.SWC))
			{
				return;
			}
			try
			{
				if (Platform.IsLessThan(Platform.W2K))
				{
					return;
				}
				ICatalog catalog = null;
				ICatalogCollection catalogCollection = null;
				ICatalogObject catalogObject = null;
				int idx = 0;
				catalog = (ICatalog)new xCatalog();
				if (!Platform.IsLessThan(Platform.Whistler) && catalog is ICatalog2 catalog2)
				{
					catalog2.CurrentPartition(catalog2.GlobalPartitionID());
				}
				catalogCollection = (ICatalogCollection)catalog.GetCollection("Applications");
				RegistrationDriver.Populate(catalogCollection);
				catalogObject = FindApplication(catalogCollection, _appid, ref idx);
				if (catalogObject == null)
				{
					catalogObject = (ICatalogObject)catalogCollection.Add();
					catalogObject.SetValue("Name", _appname);
					catalogObject.SetValue("Activation", ActivationOption.Library);
					catalogObject.SetValue("ID", "{" + _appid.ToString() + "}");
					if (!Platform.IsLessThan(Platform.Whistler))
					{
						try
						{
							catalogObject.SetValue("Replicable", 0);
						}
						catch
						{
						}
					}
					catalogCollection.SaveChanges();
				}
				else
				{
					catalogObject.SetValue("Changeable", true);
					catalogObject.SetValue("Deleteable", true);
					catalogCollection.SaveChanges();
					catalogObject.SetValue("Name", _appname);
					if (!Platform.IsLessThan(Platform.Whistler))
					{
						try
						{
							catalogObject.SetValue("Replicable", 0);
						}
						catch
						{
						}
					}
					catalogCollection.SaveChanges();
				}
				Guid guid = Marshal.GenerateGuidForType(typeof(RegistrationHelperTx));
				ICatalogCollection coll = (ICatalogCollection)catalogCollection.GetCollection("Components", catalogObject.Key());
				ICatalogObject catalogObject2 = FindComponent(coll, guid, ref idx);
				if (catalogObject2 == null)
				{
					if (_isRunningInWow64)
					{
						ICatalog2 catalog3 = catalog as ICatalog2;
						string text = string.Concat("{", guid, "}");
						int num = 1;
						object pVarCLSIDOrProgID = text;
						object pVarComponentType = num;
						catalog3.ImportComponents(string.Concat("{", _appid, "}"), ref pVarCLSIDOrProgID, ref pVarComponentType);
					}
					else
					{
						catalog.ImportComponent(string.Concat("{", _appid, "}"), string.Concat("{", guid, "}"));
					}
					coll = (ICatalogCollection)catalogCollection.GetCollection("Components", catalogObject.Key());
					catalogObject2 = FindComponent(coll, guid, ref idx);
				}
				ConfigureComponent(coll, catalogObject2);
				catalogObject.SetValue("Changeable", false);
				catalogObject.SetValue("Deleteable", false);
				catalogCollection.SaveChanges();
				System.EnterpriseServices.Thunk.Proxy.RegisterProxyStub();
				RegistryPermission registryPermission = new RegistryPermission(PermissionState.Unrestricted);
				registryPermission.Demand();
				registryPermission.Assert();
				RegistryKey registryKey = Registry.LocalMachine.CreateSubKey("SOFTWARE\\MICROSOFT\\OLE\\NONREDIST");
				registryKey.SetValue("System.EnterpriseServices.Thunk.dll", "");
				registryKey.Close();
			}
			catch (Exception ex)
			{
				try
				{
					EventLog eventLog = new EventLog();
					eventLog.Source = "System.EnterpriseServices";
					string message = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrInstSysEnt"), ex);
					eventLog.WriteEntry(message, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
			catch
			{
				try
				{
					EventLog eventLog2 = new EventLog();
					eventLog2.Source = "System.EnterpriseServices";
					string message2 = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrTxInst"), Resource.FormatString("Err_NonClsException", "RegistrationHelperTx.InstallUtilityApplication"));
					eventLog2.WriteEntry(message2, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
		}

		[ComUnregisterFunction]
		internal static void UninstallUtilityApplication(Type t)
		{
			if (Platform.Supports(PlatformFeature.SWC))
			{
				return;
			}
			try
			{
				if (Platform.IsLessThan(Platform.W2K))
				{
					return;
				}
				ICatalog catalog = null;
				ICatalogCollection catalogCollection = null;
				ICatalogObject catalogObject = null;
				int idx = 0;
				catalog = (ICatalog)new xCatalog();
				if (!Platform.IsLessThan(Platform.Whistler) && catalog is ICatalog2 catalog2)
				{
					catalog2.CurrentPartition(catalog2.GlobalPartitionID());
				}
				catalogCollection = (ICatalogCollection)catalog.GetCollection("Applications");
				RegistrationDriver.Populate(catalogCollection);
				catalogObject = FindApplication(catalogCollection, _appid, ref idx);
				if (catalogObject != null)
				{
					catalogObject.SetValue("Changeable", true);
					catalogObject.SetValue("Deleteable", true);
					catalogCollection.SaveChanges();
					int idx2 = 0;
					int num = 0;
					Guid clsid = Marshal.GenerateGuidForType(typeof(RegistrationHelperTx));
					ICatalogCollection catalogCollection2 = (ICatalogCollection)catalogCollection.GetCollection("Components", catalogObject.Key());
					ICatalogObject catalogObject2 = FindComponent(catalogCollection2, clsid, ref idx2);
					num = catalogCollection2.Count();
					if (catalogObject2 != null)
					{
						catalogCollection2.Remove(idx2);
						catalogCollection2.SaveChanges();
					}
					if (catalogObject2 != null && num == 1)
					{
						catalogCollection.Remove(idx);
						catalogCollection.SaveChanges();
					}
					else
					{
						catalogObject.SetValue("Changeable", false);
						catalogObject.SetValue("Deleteable", false);
						catalogCollection.SaveChanges();
					}
				}
			}
			catch (Exception ex)
			{
				try
				{
					EventLog eventLog = new EventLog();
					eventLog.Source = "System.EnterpriseServices";
					string message = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrUninstSysEnt"), ex);
					eventLog.WriteEntry(message, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
			catch
			{
				try
				{
					EventLog eventLog2 = new EventLog();
					eventLog2.Source = "System.EnterpriseServices";
					string message2 = string.Format(CultureInfo.CurrentCulture, Resource.FormatString("Reg_ErrTxInst"), Resource.FormatString("Err_NonClsException", "RegistrationHelperTx.UninstallUtilityApplication"));
					eventLog2.WriteEntry(message2, EventLogEntryType.Error);
				}
				catch
				{
				}
			}
		}

		public void InstallAssembly(string assembly, ref string application, ref string tlb, InstallationFlags installFlags, object sync)
		{
			InstallAssembly(assembly, ref application, null, ref tlb, installFlags, sync);
		}

		public void InstallAssembly(string assembly, ref string application, string partition, ref string tlb, InstallationFlags installFlags, object sync)
		{
			RegistrationConfig regConfig = new RegistrationConfig();
			regConfig.AssemblyFile = assembly;
			regConfig.Application = application;
			regConfig.Partition = partition;
			regConfig.TypeLibrary = tlb;
			regConfig.InstallationFlags = installFlags;
			InstallAssemblyFromConfig(ref regConfig, sync);
			application = regConfig.AssemblyFile;
			tlb = regConfig.TypeLibrary;
		}

		public void InstallAssemblyFromConfig([MarshalAs(UnmanagedType.IUnknown)] ref RegistrationConfig regConfig, object sync)
		{
			bool flag = false;
			try
			{
				RegistrationDriver registrationDriver = new RegistrationDriver();
				registrationDriver.InstallAssembly(regConfig, sync);
				ContextUtil.SetComplete();
				flag = true;
			}
			finally
			{
				if (!flag)
				{
					ContextUtil.SetAbort();
				}
			}
		}

		public void UninstallAssembly(string assembly, string application, object sync)
		{
			UninstallAssembly(assembly, application, null, sync);
		}

		public void UninstallAssembly(string assembly, string application, string partition, object sync)
		{
			RegistrationConfig regConfig = new RegistrationConfig();
			regConfig.AssemblyFile = assembly;
			regConfig.Application = application;
			regConfig.Partition = partition;
			UninstallAssemblyFromConfig(ref regConfig, sync);
		}

		public void UninstallAssemblyFromConfig([MarshalAs(UnmanagedType.IUnknown)] ref RegistrationConfig regConfig, object sync)
		{
			bool flag = false;
			try
			{
				RegistrationDriver registrationDriver = new RegistrationDriver();
				registrationDriver.UninstallAssembly(regConfig, sync);
				ContextUtil.SetComplete();
				flag = true;
			}
			finally
			{
				if (!flag)
				{
					ContextUtil.SetAbort();
				}
			}
		}

		public bool IsInTransaction()
		{
			return ContextUtil.IsInTransaction;
		}

		protected internal override void Activate()
		{
		}

		protected internal override void Deactivate()
		{
		}
	}
	[AttributeUsage(AttributeTargets.Class, Inherited = true)]
	[ComVisible(false)]
	public sealed class ComponentAccessControlAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public ComponentAccessControlAttribute()
			: this(val: true)
		{
		}

		public ComponentAccessControlAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Component";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.MTS, "ComponentAccessControlAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Component"];
			if (Platform.IsLessThan(Platform.W2K))
			{
				catalogObject.SetValue("SecurityEnabled", _value ? "Y" : "N");
			}
			else
			{
				catalogObject.SetValue("ComponentAccessChecksEnabled", _value);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[Serializable]
	public enum AccessChecksLevelOption
	{
		Application,
		ApplicationComponent
	}
	[Serializable]
	public enum AuthenticationOption
	{
		Default,
		None,
		Connect,
		Call,
		Packet,
		Integrity,
		Privacy
	}
	[Serializable]
	public enum ImpersonationLevelOption
	{
		Default,
		Anonymous,
		Identify,
		Impersonate,
		Delegate
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Assembly, Inherited = true)]
	public sealed class ApplicationAccessControlAttribute : Attribute, IConfigurationAttribute
	{
		private bool _val;

		private AccessChecksLevelOption _checkLevel;

		private AuthenticationOption _authLevel;

		private ImpersonationLevelOption _impLevel;

		public bool Value
		{
			get
			{
				return _val;
			}
			set
			{
				_val = value;
			}
		}

		public AccessChecksLevelOption AccessChecksLevel
		{
			get
			{
				return _checkLevel;
			}
			set
			{
				Platform.Assert(Platform.W2K, "ApplicationAccessControlAttribute.AccessChecksLevel");
				_checkLevel = value;
			}
		}

		public AuthenticationOption Authentication
		{
			get
			{
				return _authLevel;
			}
			set
			{
				_authLevel = value;
			}
		}

		public ImpersonationLevelOption ImpersonationLevel
		{
			get
			{
				return _impLevel;
			}
			set
			{
				Platform.Assert(Platform.W2K, "ApplicationAccessControlAttribute.ImpersonationLevel");
				_impLevel = value;
			}
		}

		public ApplicationAccessControlAttribute()
			: this(val: true)
		{
		}

		public ApplicationAccessControlAttribute(bool val)
		{
			_val = val;
			_authLevel = (AuthenticationOption)(-1);
			_impLevel = (ImpersonationLevelOption)(-1);
			if (_val)
			{
				_checkLevel = AccessChecksLevelOption.ApplicationComponent;
			}
			else
			{
				_checkLevel = AccessChecksLevelOption.Application;
			}
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Application";
		}

		bool IConfigurationAttribute.Apply(Hashtable cache)
		{
			Platform.Assert(Platform.MTS, "ApplicationAccessControlAttribute");
			ICatalogObject catalogObject = (ICatalogObject)cache["Application"];
			if (Platform.IsLessThan(Platform.W2K))
			{
				bool val = _val;
				catalogObject.SetValue("SecurityEnabled", val ? "Y" : "N");
			}
			else
			{
				catalogObject.SetValue("ApplicationAccessChecksEnabled", _val);
				catalogObject.SetValue("AccessChecksLevel", _checkLevel);
			}
			if (_authLevel != (AuthenticationOption)(-1))
			{
				catalogObject.SetValue("Authentication", _authLevel);
			}
			if (_impLevel != (ImpersonationLevelOption)(-1))
			{
				catalogObject.SetValue("ImpersonationLevel", _impLevel);
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Method | AttributeTargets.Interface, Inherited = true, AllowMultiple = true)]
	[ComVisible(false)]
	public sealed class SecurityRoleAttribute : Attribute, IConfigurationAttribute
	{
		private string _role;

		private bool _setEveryoneAccess;

		private string _description;

		private static readonly string RoleCacheString = "RoleAttribute::ApplicationRoleCache";

		private static string _everyone;

		private static string EveryoneAccount
		{
			get
			{
				if (_everyone == null)
				{
					_everyone = System.EnterpriseServices.Thunk.Security.GetEveryoneAccountName();
				}
				return _everyone;
			}
		}

		public string Role
		{
			get
			{
				return _role;
			}
			set
			{
				_role = value;
			}
		}

		public bool SetEveryoneAccess
		{
			get
			{
				return _setEveryoneAccess;
			}
			set
			{
				_setEveryoneAccess = value;
			}
		}

		public string Description
		{
			get
			{
				return _description;
			}
			set
			{
				_description = value;
			}
		}

		public SecurityRoleAttribute(string role)
			: this(role, everyone: false)
		{
		}

		public SecurityRoleAttribute(string role, bool everyone)
		{
			_role = role;
			_setEveryoneAccess = everyone;
			_description = null;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			switch (s)
			{
			case "Component":
			case "Method":
			case "Application":
			case "Interface":
				return true;
			default:
				return false;
			}
		}

		private ICatalogObject Search(ICatalogCollection coll, string key, string value)
		{
			for (int i = 0; i < coll.Count(); i++)
			{
				ICatalogObject catalogObject = (ICatalogObject)coll.Item(i);
				string text = (string)catalogObject.GetValue(key);
				if (text == value)
				{
					return catalogObject;
				}
			}
			return null;
		}

		private void EnsureRole(Hashtable cache)
		{
			ICatalogCollection catalogCollection = null;
			ICatalogObject catalogObject = null;
			ICatalogCollection catalogCollection2 = null;
			Hashtable hashtable = (Hashtable)cache[RoleCacheString];
			if (hashtable == null)
			{
				hashtable = new Hashtable();
				cache[RoleCacheString] = hashtable;
			}
			if (hashtable[_role] != null)
			{
				return;
			}
			catalogCollection = (ICatalogCollection)cache["ApplicationCollection"];
			catalogObject = (ICatalogObject)cache["Application"];
			catalogCollection2 = (ICatalogCollection)catalogCollection.GetCollection(CollectionName.Roles, catalogObject.Key());
			catalogCollection2.Populate();
			ICatalogObject catalogObject2 = Search(catalogCollection2, "Name", _role);
			if (catalogObject2 == null)
			{
				catalogObject2 = (ICatalogObject)catalogCollection2.Add();
				catalogObject2.SetValue("Name", _role);
				if (_description != null)
				{
					catalogObject2.SetValue("Description", _description);
				}
				catalogCollection2.SaveChanges();
				if (_setEveryoneAccess)
				{
					ICatalogCollection catalogCollection3 = (ICatalogCollection)catalogCollection2.GetCollection(CollectionName.UsersInRole, catalogObject2.Key());
					catalogCollection3.Populate();
					ICatalogObject catalogObject3 = (ICatalogObject)catalogCollection3.Add();
					catalogObject3.SetValue("User", EveryoneAccount);
					catalogCollection3.SaveChanges();
				}
			}
			hashtable[_role] = true;
		}

		private void AddRoleFor(string target, Hashtable cache)
		{
			ICatalogCollection catalogCollection = (ICatalogCollection)cache[target + "Collection"];
			ICatalogObject catalogObject = (ICatalogObject)cache[target];
			ICatalogCollection catalogCollection2 = (ICatalogCollection)catalogCollection.GetCollection(CollectionName.RolesFor(target), catalogObject.Key());
			catalogCollection2.Populate();
			if (Platform.IsLessThan(Platform.W2K))
			{
				IRoleAssociationUtil roleAssociationUtil = (IRoleAssociationUtil)catalogCollection2.GetUtilInterface();
				roleAssociationUtil.AssociateRoleByName(_role);
				return;
			}
			ICatalogObject catalogObject2 = Search(catalogCollection2, "Name", _role);
			if (catalogObject2 == null)
			{
				ICatalogObject catalogObject3 = (ICatalogObject)catalogCollection2.Add();
				catalogObject3.SetValue("Name", _role);
				catalogCollection2.SaveChanges();
				catalogCollection2.Populate();
				for (int i = 0; i < catalogCollection2.Count(); i++)
				{
					_ = (ICatalogObject)catalogCollection2.Item(i);
				}
			}
		}

		bool IConfigurationAttribute.Apply(Hashtable cache)
		{
			EnsureRole(cache);
			string text = (string)cache["CurrentTarget"];
			if (text == "Method")
			{
				cache["SecurityOnMethods"] = true;
			}
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable cache)
		{
			string text = (string)cache["CurrentTarget"];
			switch (text)
			{
			case "Component":
				Platform.Assert(Platform.MTS, "SecurityRoleAttribute");
				AddRoleFor("Component", cache);
				break;
			case "Method":
				Platform.Assert(Platform.W2K, "SecurityRoleAttribute");
				AddRoleFor("Method", cache);
				break;
			case "Interface":
				AddRoleFor("Interface", cache);
				break;
			default:
				_ = text == "Application";
				break;
			}
			return true;
		}
	}
	[ComVisible(false)]
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = false)]
	public sealed class SecureMethodAttribute : Attribute, IConfigurationAttribute
	{
		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			if (!(s == "Method"))
			{
				return s == "Component";
			}
			return true;
		}

		bool IConfigurationAttribute.Apply(Hashtable cache)
		{
			string text = (string)cache["CurrentTarget"];
			if (text == "Method")
			{
				cache["SecurityOnMethods"] = true;
			}
			return false;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
	internal static class Perf
	{
		private static long _count;

		private static long _freq;

		static Perf()
		{
			Util.QueryPerformanceFrequency(out _freq);
		}

		[Conditional("_DEBUG_PERF")]
		internal static void Tick(string name)
		{
			Util.QueryPerformanceCounter(out var count);
			if (_count != 0)
			{
				_ = (double)(count - _count) / (double)_freq;
			}
			_count = count;
		}
	}
	internal class Util
	{
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
		internal class OSVERSIONINFOEX
		{
			internal int OSVersionInfoSize;

			internal int MajorVersion;

			internal int MinorVersion;

			internal int BuildNumber;

			internal int PlatformId;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			internal string CSDVersion;

			internal short ServicePackMajor;

			internal short ServicePackMinor;

			internal short SuiteMask;

			internal byte ProductType;

			internal byte Reserved;

			public OSVERSIONINFOEX()
			{
				OSVersionInfoSize = Marshal.SizeOf(this);
			}
		}

		internal static readonly int FORMAT_MESSAGE_IGNORE_INSERTS = 512;

		internal static readonly int FORMAT_MESSAGE_FROM_SYSTEM = 4096;

		internal static readonly int FORMAT_MESSAGE_ARGUMENT_ARRAY = 8192;

		internal static readonly int CLSCTX_SERVER = 21;

		internal static readonly Guid GUID_NULL = new Guid("00000000-0000-0000-0000-000000000000");

		internal static readonly Guid IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046");

		internal static readonly Guid IID_IObjectContext = new Guid("51372AE0-CAE7-11CF-BE81-00AA00A2FA25");

		internal static readonly Guid IID_ISecurityCallContext = new Guid("CAFC823E-B441-11D1-B82B-0000F8757E2A");

		internal static readonly int E_FAIL = -2147467259;

		internal static readonly int E_UNEXPECTED = -2147418113;

		internal static readonly int E_ACCESSDENIED = -2147024891;

		internal static readonly int E_NOINTERFACE = -2147467262;

		internal static readonly int REGDB_E_CLASSNOTREG = -2147221164;

		internal static readonly int COMADMIN_E_OBJECTERRORS = -2146368511;

		internal static readonly int CONTEXT_E_NOCONTEXT = -2147164156;

		internal static readonly int DISP_E_UNKNOWNNAME = -2147352570;

		internal static readonly int CONTEXT_E_ABORTED = -2147164158;

		internal static readonly int CONTEXT_E_ABORTING = -2147164157;

		internal static readonly int XACT_E_INDOUBT = -2147168234;

		internal static readonly int CONTEXT_E_TMNOTAVAILABLE = -2147164145;

		internal static readonly int SECURITY_NULL_SID_AUTHORITY = 0;

		internal static readonly int SECURITY_WORLD_SID_AUTHORITY = 1;

		internal static readonly int SECURITY_LOCAL_SID_AUTHORITY = 2;

		internal static readonly int SECURITY_CREATOR_SID_AUTHORITY = 3;

		internal static readonly int SECURITY_NT_SID_AUTHORITY = 5;

		internal static readonly int ERROR_SUCCESS = 0;

		internal static readonly int ERROR_NO_TOKEN = 1008;

		internal static readonly int MB_ABORTRETRYIGNORE = 2;

		internal static readonly int MB_ICONEXCLAMATION = 48;

		internal static bool ExtendedLifetime => (System.EnterpriseServices.Thunk.Proxy.GetManagedExts() & 1) != 0;

		[DllImport("oleaut32.dll")]
		internal static extern int LoadTypeLibEx([In][MarshalAs(UnmanagedType.LPWStr)] string str, int regKind, out IntPtr pptlib);

		[DllImport("user32.dll")]
		internal static extern int MessageBox(int hWnd, string lpText, string lpCaption, int type);

		[DllImport("kernel32.dll")]
		internal static extern void OutputDebugString(string msg);

		[DllImport("ole32.dll", PreserveSig = false)]
		internal static extern void CoGetCallContext([MarshalAs(UnmanagedType.LPStruct)] Guid riid, [MarshalAs(UnmanagedType.Interface)] out ISecurityCallContext iface);

		[DllImport("oleaut32.dll")]
		internal static extern int RegisterTypeLib(IntPtr pptlib, [In][MarshalAs(UnmanagedType.LPWStr)] string str, [In][MarshalAs(UnmanagedType.LPWStr)] string help);

		[DllImport("oleaut32.dll", PreserveSig = false)]
		internal static extern void UnRegisterTypeLib([In][MarshalAs(UnmanagedType.LPStruct)] Guid libID, short wVerMajor, short wVerMinor, int lcid, System.Runtime.InteropServices.ComTypes.SYSKIND syskind);

		[DllImport("oleaut32.dll")]
		internal static extern int LoadRegTypeLib([In][MarshalAs(UnmanagedType.LPStruct)] Guid lidID, short wVerMajor, short wVerMinor, int lcid, [MarshalAs(UnmanagedType.Interface)] out object pptlib);

		[DllImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool QueryPerformanceCounter(out long count);

		[DllImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool QueryPerformanceFrequency(out long count);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		internal static extern int FormatMessage(int dwFlags, IntPtr lpSource, int dwMessageId, int dwLanguageId, StringBuilder lpBuffer, int nSize, int arguments);

		[DllImport("mtxex.dll", CallingConvention = CallingConvention.Cdecl)]
		internal static extern int GetObjectContext([MarshalAs(UnmanagedType.Interface)] out IObjectContext pCtx);

		[DllImport("KERNEL32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool GetVersionEx([In][Out] OSVERSIONINFOEX ver);

		internal static string GetErrorString(int hr)
		{
			StringBuilder stringBuilder = new StringBuilder(1024);
			if (FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY, (IntPtr)0, hr, 0, stringBuilder, stringBuilder.Capacity + 1, 0) != 0)
			{
				int num;
				for (num = stringBuilder.Length; num > 0; num--)
				{
					char c = stringBuilder[num - 1];
					if (c > ' ' && c != '.')
					{
						break;
					}
				}
				return stringBuilder.ToString(0, num);
			}
			return null;
		}
	}
	internal enum PlatformFeature
	{
		SWC,
		UserContextProperties
	}
	internal class Platform
	{
		private static Version _mts;

		private static Version _w2k;

		private static Version _whistler;

		private static Version _current;

		private static volatile bool _initialized;

		private static Hashtable _features = new Hashtable();

		internal static Version MTS
		{
			get
			{
				Initialize();
				return _mts;
			}
		}

		internal static Version W2K
		{
			get
			{
				Initialize();
				return _w2k;
			}
		}

		internal static Version Whistler
		{
			get
			{
				Initialize();
				return _whistler;
			}
		}

		private Platform()
		{
		}

		private static void Initialize()
		{
			if (_initialized)
			{
				return;
			}
			lock (typeof(Platform))
			{
				if (_initialized)
				{
					return;
				}
				IntPtr hToken = IntPtr.Zero;
				_mts = new Version(2, 0);
				_w2k = new Version(3, 0);
				_whistler = new Version(4, 0);
				try
				{
					try
					{
						hToken = System.EnterpriseServices.Thunk.Security.SuspendImpersonation();
						IMtsCatalog mtsCatalog = (IMtsCatalog)new xMtsCatalog();
						_current = new Version(mtsCatalog.MajorVersion(), mtsCatalog.MinorVersion());
					}
					catch (COMException)
					{
						_current = new Version(0, 0);
					}
					finally
					{
						System.EnterpriseServices.Thunk.Security.ResumeImpersonation(hToken);
					}
				}
				catch
				{
					throw;
				}
				_initialized = true;
			}
		}

		private static void SetFeatureData(PlatformFeature feature, object value)
		{
			lock (_features)
			{
				if (FindFeatureData(feature) == null)
				{
					_features.Add(feature, value);
				}
			}
		}

		private static object FindFeatureData(PlatformFeature feature)
		{
			return _features[feature];
		}

		internal static void Assert(Version platform, string function)
		{
			Initialize();
			if (_current.Major < platform.Major || (_current.Major == platform.Major && _current.Minor < platform.Minor))
			{
				Assert(fSuccess: false, function);
			}
		}

		internal static void Assert(bool fSuccess, string function)
		{
			if (!fSuccess)
			{
				throw new PlatformNotSupportedException(Resource.FormatString("Err_PlatformSupport", function));
			}
		}

		internal static bool CheckUserContextPropertySupport()
		{
			bool result = false;
			Util.OSVERSIONINFOEX oSVERSIONINFOEX = new Util.OSVERSIONINFOEX();
			if (Util.GetVersionEx(oSVERSIONINFOEX))
			{
				if (oSVERSIONINFOEX.MajorVersion > 5)
				{
					return true;
				}
				if (oSVERSIONINFOEX.MajorVersion == 5 && oSVERSIONINFOEX.MinorVersion == 1 && oSVERSIONINFOEX.ServicePackMajor >= 2)
				{
					result = true;
				}
				else if (oSVERSIONINFOEX.MajorVersion == 5 && oSVERSIONINFOEX.MinorVersion == 2 && oSVERSIONINFOEX.ServicePackMajor >= 1)
				{
					result = true;
				}
			}
			return result;
		}

		internal static object GetFeatureData(PlatformFeature feature)
		{
			object obj = FindFeatureData(feature);
			if (obj != null)
			{
				return obj;
			}
			switch (feature)
			{
			case PlatformFeature.SWC:
				obj = System.EnterpriseServices.Thunk.SWCThunk.IsSWCSupported();
				break;
			case PlatformFeature.UserContextProperties:
				obj = CheckUserContextPropertySupport();
				break;
			default:
				return null;
			}
			SetFeatureData(feature, obj);
			return obj;
		}

		internal static bool Supports(PlatformFeature feature)
		{
			return (bool)GetFeatureData(feature);
		}

		internal static bool IsLessThan(Version platform)
		{
			Initialize();
			if (_current.Major >= platform.Major)
			{
				if (_current.Major == platform.Major)
				{
					return _current.Minor < platform.Minor;
				}
				return false;
			}
			return true;
		}
	}
	internal class BaseSwitch
	{
		private int _value;

		private string _name;

		internal static string Path => "SOFTWARE\\Microsoft\\COM3\\System.EnterpriseServices";

		protected int Value => _value;

		internal string Name => _name;

		internal BaseSwitch(string name)
		{
			RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(Path);
			_name = name;
			if (registryKey == null)
			{
				_value = 0;
				return;
			}
			object value = registryKey.GetValue(name);
			if (value != null)
			{
				_value = (int)value;
			}
		}
	}
	internal class BooleanSwitch : BaseSwitch
	{
		internal bool Enabled => base.Value != 0;

		internal BooleanSwitch(string name)
			: base(name)
		{
		}
	}
	internal class TraceSwitch : BaseSwitch
	{
		internal int Level => base.Value;

		internal TraceSwitch(string name)
			: base(name)
		{
		}
	}
	[Serializable]
	internal enum TraceLevel
	{
		None,
		Error,
		Warning,
		Status,
		Info
	}
	internal static class DBG
	{
		private static TraceSwitch _genSwitch;

		private static TraceSwitch _regSwitch;

		private static TraceSwitch _platSwitch;

		private static TraceSwitch _crmSwitch;

		private static TraceSwitch _perfSwitch;

		private static TraceSwitch _poolSwitch;

		private static TraceSwitch _thkSwitch;

		private static TraceSwitch _scSwitch;

		private static BooleanSwitch _conSwitch;

		private static BooleanSwitch _dbgDisable;

		private static BooleanSwitch _stackSwitch;

		private static volatile bool _initialized;

		private static object initializeLock = new object();

		public static TraceSwitch General
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _genSwitch;
			}
		}

		public static TraceSwitch Registration
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _regSwitch;
			}
		}

		public static TraceSwitch Pool
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _poolSwitch;
			}
		}

		public static TraceSwitch Platform
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _platSwitch;
			}
		}

		public static TraceSwitch CRM
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _crmSwitch;
			}
		}

		public static TraceSwitch Perf
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _perfSwitch;
			}
		}

		public static TraceSwitch Thunk
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _thkSwitch;
			}
		}

		public static TraceSwitch SC
		{
			get
			{
				if (!_initialized)
				{
					InitDBG();
				}
				return _scSwitch;
			}
		}

		public static void InitDBG()
		{
			if (_initialized)
			{
				return;
			}
			lock (initializeLock)
			{
				if (!_initialized)
				{
					RegistryPermission registryPermission = new RegistryPermission(PermissionState.Unrestricted);
					registryPermission.Assert();
					_genSwitch = new TraceSwitch("General");
					_platSwitch = new TraceSwitch("Platform");
					_regSwitch = new TraceSwitch("Registration");
					_crmSwitch = new TraceSwitch("CRM");
					_perfSwitch = new TraceSwitch("PerfLog");
					_poolSwitch = new TraceSwitch("ObjectPool");
					_thkSwitch = new TraceSwitch("Thunk");
					_scSwitch = new TraceSwitch("ServicedComponent");
					_conSwitch = new BooleanSwitch("ConsoleOutput");
					_dbgDisable = new BooleanSwitch("DisableDebugOutput");
					_stackSwitch = new BooleanSwitch("PrintStacks");
					_initialized = true;
				}
			}
		}

		private static int TID()
		{
			return Thread.CurrentThread.GetHashCode();
		}

		[Conditional("_DEBUG")]
		public static void Trace(TraceLevel level, TraceSwitch sw, string msg)
		{
			if (!_initialized)
			{
				InitDBG();
			}
			if (sw.Level != 0 && sw.Level >= (int)level)
			{
				string text = TID() + ": " + sw.Name + ": " + msg;
				if (_stackSwitch.Enabled)
				{
					text += new StackTrace(2).ToString();
				}
				if (_conSwitch.Enabled)
				{
					Console.WriteLine(text);
				}
				if (!_dbgDisable.Enabled)
				{
					Util.OutputDebugString(text + "\n");
				}
			}
		}

		[Conditional("_DEBUG")]
		public static void Info(TraceSwitch sw, string msg)
		{
		}

		[Conditional("_DEBUG")]
		public static void Status(TraceSwitch sw, string msg)
		{
		}

		[Conditional("_DEBUG")]
		public static void Warning(TraceSwitch sw, string msg)
		{
		}

		[Conditional("_DEBUG")]
		public static void Error(TraceSwitch sw, string msg)
		{
		}

		[Conditional("_DEBUG")]
		private static void DoAssert(string msg, string detail)
		{
			StackTrace stackTrace = new StackTrace();
			string text = string.Concat(msg, "\n\n", detail, "\n", stackTrace, "\n\nPress RETRY to launch a debugger.");
			string text2 = "ALERT: System.EnterpriseServices,  TID=" + TID();
			Util.OutputDebugString(text2 + "\n\n" + text);
			if (!Debugger.IsAttached)
			{
				switch (Util.MessageBox(0, text, text2, Util.MB_ABORTRETRYIGNORE | Util.MB_ICONEXCLAMATION))
				{
				case 3:
					Environment.Exit(1);
					break;
				case 4:
					if (!Debugger.IsAttached)
					{
						Debugger.Launch();
					}
					else
					{
						Debugger.Break();
					}
					break;
				}
			}
			else
			{
				Debugger.Break();
			}
		}

		[Conditional("_DEBUG")]
		public static void Assert(bool cond, string msg)
		{
			if (!_initialized)
			{
				InitDBG();
			}
		}

		[Conditional("_DEBUG")]
		public static void Assert(bool cond, string msg, string detail)
		{
			if (!_initialized)
			{
				InitDBG();
			}
		}
	}
	internal static class Resource
	{
		private static ResourceManager _resmgr;

		private static void InitResourceManager()
		{
			if (_resmgr == null)
			{
				_resmgr = new ResourceManager("System.EnterpriseServices", typeof(Resource).Module.Assembly);
			}
		}

		internal static string GetString(string key)
		{
			InitResourceManager();
			return _resmgr.GetString(key, null);
		}

		internal static string FormatString(string key)
		{
			return GetString(key);
		}

		internal static string FormatString(string key, object a1)
		{
			return string.Format(CultureInfo.CurrentCulture, GetString(key), a1);
		}

		internal static string FormatString(string key, object a1, object a2)
		{
			return string.Format(CultureInfo.CurrentCulture, GetString(key), a1, a2);
		}

		internal static string FormatString(string key, object a1, object a2, object a3)
		{
			return string.Format(CultureInfo.CurrentCulture, GetString(key), a1, a2, a3);
		}
	}
	internal interface IConfigCallback
	{
		object FindObject(ICatalogCollection coll, object key);

		void ConfigureDefaults(object a, object key);

		bool Configure(object a, object key);

		bool AfterSaveChanges(object a, object key);

		void ConfigureSubCollections(ICatalogCollection coll);

		IEnumerator GetEnumerator();
	}
	internal class ComponentConfigCallback : IConfigCallback
	{
		private ApplicationSpec _spec;

		private ICatalogCollection _coll;

		private Hashtable _cache;

		private RegistrationDriver _driver;

		private InstallationFlags _installFlags;

		public ComponentConfigCallback(ICatalogCollection coll, ApplicationSpec spec, Hashtable cache, RegistrationDriver driver, InstallationFlags installFlags)
		{
			_spec = spec;
			_coll = coll;
			_cache = cache;
			_driver = driver;
			_installFlags = installFlags;
			RegistrationDriver.Populate(coll);
		}

		public object FindObject(ICatalogCollection coll, object key)
		{
			Guid guid = Marshal.GenerateGuidForType((Type)key);
			for (int i = 0; i < coll.Count(); i++)
			{
				ICatalogObject catalogObject = (ICatalogObject)coll.Item(i);
				Guid guid2 = new Guid((string)catalogObject.Key());
				if (guid2 == guid)
				{
					return catalogObject;
				}
			}
			throw new RegistrationException(Resource.FormatString("Reg_ComponentMissing", ((Type)key).FullName));
		}

		public void ConfigureDefaults(object a, object key)
		{
			ICatalogObject catalogObject = (ICatalogObject)a;
			if (Platform.IsLessThan(Platform.W2K))
			{
				catalogObject.SetValue("Transaction", "Not Supported");
				catalogObject.SetValue("SecurityEnabled", "N");
			}
			else
			{
				catalogObject.SetValue("AllowInprocSubscribers", true);
				catalogObject.SetValue("ComponentAccessChecksEnabled", false);
				catalogObject.SetValue("COMTIIntrinsics", false);
				catalogObject.SetValue("ConstructionEnabled", false);
				catalogObject.SetValue("EventTrackingEnabled", false);
				catalogObject.SetValue("FireInParallel", false);
				catalogObject.SetValue("IISIntrinsics", false);
				catalogObject.SetValue("JustInTimeActivation", false);
				catalogObject.SetValue("LoadBalancingSupported", false);
				catalogObject.SetValue("MustRunInClientContext", false);
				catalogObject.SetValue("ObjectPoolingEnabled", false);
				catalogObject.SetValue("Synchronization", SynchronizationOption.Disabled);
				catalogObject.SetValue("Transaction", TransactionOption.Disabled);
				catalogObject.SetValue("ComponentTransactionTimeoutEnabled", false);
			}
			if (!Platform.IsLessThan(Platform.Whistler))
			{
				catalogObject.SetValue("TxIsolationLevel", TransactionIsolationLevel.Serializable);
			}
		}

		public bool Configure(object a, object key)
		{
			return _driver.ConfigureObject((Type)key, (ICatalogObject)a, _coll, "Component", _cache);
		}

		public bool AfterSaveChanges(object a, object key)
		{
			return _driver.AfterSaveChanges((Type)key, (ICatalogObject)a, _coll, "Component", _cache);
		}

		public IEnumerator GetEnumerator()
		{
			return _spec.ConfigurableTypes.GetEnumerator();
		}

		public void ConfigureSubCollections(ICatalogCollection coll)
		{
			if ((_installFlags & InstallationFlags.ConfigureComponentsOnly) != 0)
			{
				return;
			}
			Type[] configurableTypes = _spec.ConfigurableTypes;
			foreach (Type type in configurableTypes)
			{
				ICatalogObject catalogObject = (ICatalogObject)FindObject(coll, type);
				ICatalogCollection coll2 = (ICatalogCollection)coll.GetCollection(CollectionName.Interfaces, catalogObject.Key());
				_cache["Component"] = catalogObject;
				_cache["ComponentType"] = type;
				InterfaceConfigCallback cb = new InterfaceConfigCallback(coll2, type, _cache, _driver);
				_driver.ConfigureCollection(coll2, cb);
				if (_cache["SecurityOnMethods"] != null || ServicedComponentInfo.AreMethodsSecure(type))
				{
					FixupMethodSecurity(coll2);
					_cache["SecurityOnMethods"] = null;
				}
			}
		}

		private void FixupMethodSecurity(ICatalogCollection coll)
		{
			FixupMethodSecurityForInterface(coll, typeof(IManagedObject));
			FixupMethodSecurityForInterface(coll, typeof(IServicedComponentInfo));
			FixupMethodSecurityForInterface(coll, typeof(IDisposable));
		}

		private void FixupMethodSecurityForInterface(ICatalogCollection coll, Type InterfaceType)
		{
			ICatalogObject catalogObject = null;
			Guid guid = Marshal.GenerateGuidForType(InterfaceType);
			int num = coll.Count();
			for (int i = 0; i < num; i++)
			{
				ICatalogObject catalogObject2 = (ICatalogObject)coll.Item(i);
				if (new Guid((string)catalogObject2.Key()) == guid)
				{
					catalogObject = catalogObject2;
					break;
				}
			}
			if (catalogObject != null)
			{
				SecurityRoleAttribute securityRoleAttribute = new SecurityRoleAttribute("Marshaler", everyone: false);
				securityRoleAttribute.Description = Resource.FormatString("Reg_MarshalerDesc");
				IConfigurationAttribute configurationAttribute = securityRoleAttribute;
				_cache["CurrentTarget"] = "Interface";
				_cache["InterfaceCollection"] = coll;
				_cache["Interface"] = catalogObject;
				_cache["InterfaceType"] = InterfaceType;
				if (configurationAttribute.Apply(_cache))
				{
					coll.SaveChanges();
				}
				if (configurationAttribute.AfterSaveChanges(_cache))
				{
					coll.SaveChanges();
				}
			}
		}
	}
	internal class InterfaceConfigCallback : IConfigCallback
	{
		private static readonly Guid IID_IProcessInitializer = new Guid("1113f52d-dc7f-4943-aed6-88d04027e32a");

		private Type _type;

		private ICatalogCollection _coll;

		private Type[] _ifcs;

		private Hashtable _cache;

		private RegistrationDriver _driver;

		private Type[] GetInteropInterfaces(Type t)
		{
			Type type = t;
			ArrayList arrayList = new ArrayList(t.GetInterfaces());
			while (type != null)
			{
				arrayList.Add(type);
				type = type.BaseType;
			}
			arrayList.Add(typeof(IManagedObject));
			Type[] array = new Type[arrayList.Count];
			arrayList.CopyTo(array);
			return array;
		}

		private Type FindInterfaceByID(ICatalogObject ifcObj, Type t, Type[] interfaces)
		{
			Guid guid = new Guid((string)ifcObj.GetValue("IID"));
			foreach (Type type in interfaces)
			{
				Guid guid2 = Marshal.GenerateGuidForType(type);
				if (guid2 == guid)
				{
					return type;
				}
			}
			return null;
		}

		private Type FindInterfaceByName(ICatalogObject ifcObj, Type t, Type[] interfaces)
		{
			string text = (string)ifcObj.GetValue("Name");
			foreach (Type type in interfaces)
			{
				if (type.IsInterface)
				{
					if (type.Name == text)
					{
						return type;
					}
				}
				else if ("_" + type.Name == text)
				{
					return type;
				}
			}
			return null;
		}

		public InterfaceConfigCallback(ICatalogCollection coll, Type t, Hashtable cache, RegistrationDriver driver)
		{
			_type = t;
			_coll = coll;
			_cache = cache;
			_driver = driver;
			_ifcs = GetInteropInterfaces(_type);
			Type[] ifcs = _ifcs;
			foreach (Type type in ifcs)
			{
				if (Marshal.GenerateGuidForType(type) == IID_IProcessInitializer)
				{
					try
					{
						ICatalogObject catalogObject = cache["Component"] as ICatalogObject;
						ICatalogCollection catalogCollection = cache["ComponentCollection"] as ICatalogCollection;
						catalogObject.SetValue("InitializesServerApplication", 1);
						catalogCollection.SaveChanges();
					}
					catch (Exception inner)
					{
						throw new RegistrationException(Resource.FormatString("Reg_FailPIT", _type), inner);
					}
					catch
					{
						throw new RegistrationException(Resource.FormatString("Err_NonClsException", "InterfaceConfigCallback.InterfaceConfigCallback"));
					}
				}
			}
			RegistrationDriver.Populate(_coll);
		}

		public object FindObject(ICatalogCollection coll, object key)
		{
			ICatalogObject ifcObj = (ICatalogObject)key;
			Type type = null;
			type = FindInterfaceByID(ifcObj, _type, _ifcs);
			if (type == null)
			{
				type = FindInterfaceByName(ifcObj, _type, _ifcs);
			}
			return type;
		}

		public void ConfigureDefaults(object a, object key)
		{
			if (Platform.IsLessThan(Platform.W2K))
			{
				return;
			}
			bool flag = true;
			ICatalogObject catalogObject = (ICatalogObject)key;
			if (_cache[_type] != null)
			{
				object obj = _cache[_type];
				if (obj is Hashtable && ((Hashtable)obj)[a] != null)
				{
					flag = false;
				}
			}
			if (flag)
			{
				catalogObject.SetValue("QueuingEnabled", false);
			}
		}

		public bool Configure(object a, object key)
		{
			if (a == null)
			{
				return false;
			}
			return _driver.ConfigureObject((Type)a, (ICatalogObject)key, _coll, "Interface", _cache);
		}

		public bool AfterSaveChanges(object a, object key)
		{
			if (a == null)
			{
				return false;
			}
			return _driver.AfterSaveChanges((Type)a, (ICatalogObject)key, _coll, "Interface", _cache);
		}

		public IEnumerator GetEnumerator()
		{
			IEnumerator pEnum = null;
			_coll.GetEnumerator(out pEnum);
			return pEnum;
		}

		public void ConfigureSubCollections(ICatalogCollection coll)
		{
			IEnumerator enumerator = GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					ICatalogObject catalogObject = (ICatalogObject)enumerator.Current;
					Type type = (Type)FindObject(coll, catalogObject);
					if (type != null)
					{
						ICatalogCollection coll2 = (ICatalogCollection)coll.GetCollection(CollectionName.Methods, catalogObject.Key());
						_driver.ConfigureCollection(coll2, new MethodConfigCallback(coll2, type, _type, _cache, _driver));
					}
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
	}
	internal class MethodConfigCallback : IConfigCallback
	{
		private Type _type;

		private Type _impl;

		private ICatalogCollection _coll;

		private Hashtable _cache;

		private RegistrationDriver _driver;

		private InterfaceMapping _map;

		public MethodConfigCallback(ICatalogCollection coll, Type t, Type impl, Hashtable cache, RegistrationDriver driver)
		{
			_type = t;
			_impl = impl;
			_coll = coll;
			_cache = cache;
			_driver = driver;
			try
			{
				_map = _impl.GetInterfaceMap(_type);
			}
			catch (ArgumentException)
			{
				_map.InterfaceMethods = null;
				_map.InterfaceType = null;
				_map.TargetMethods = null;
				_map.TargetType = null;
			}
			RegistrationDriver.Populate(coll);
		}

		public object FindObject(ICatalogCollection coll, object key)
		{
			ICatalogObject catalogObject = (ICatalogObject)key;
			int slot = (int)catalogObject.GetValue("Index");
			ComMemberType memberType = ComMemberType.Method;
			MemberInfo memberInfo = Marshal.GetMethodInfoForComSlot(_type, slot, ref memberType);
			if (memberInfo is PropertyInfo)
			{
				switch (memberType)
				{
				case ComMemberType.PropSet:
					memberInfo = ((PropertyInfo)memberInfo).GetSetMethod();
					break;
				case ComMemberType.PropGet:
					memberInfo = ((PropertyInfo)memberInfo).GetGetMethod();
					break;
				}
			}
			if (_map.InterfaceMethods != null)
			{
				for (int i = 0; i < _map.InterfaceMethods.Length; i++)
				{
					if (_map.InterfaceMethods[i] == memberInfo)
					{
						return _map.TargetMethods[i];
					}
				}
			}
			return memberInfo;
		}

		public void ConfigureDefaults(object a, object key)
		{
			if (!Platform.IsLessThan(Platform.W2K))
			{
				ICatalogObject catalogObject = (ICatalogObject)key;
				catalogObject.SetValue("AutoComplete", false);
			}
		}

		public bool Configure(object a, object key)
		{
			if (a == null)
			{
				return false;
			}
			return _driver.ConfigureObject((MethodInfo)a, (ICatalogObject)key, _coll, "Method", _cache);
		}

		public bool AfterSaveChanges(object a, object key)
		{
			if (a == null)
			{
				return false;
			}
			return _driver.AfterSaveChanges((MethodInfo)a, (ICatalogObject)key, _coll, "Method", _cache);
		}

		public IEnumerator GetEnumerator()
		{
			IEnumerator pEnum = null;
			_coll.GetEnumerator(out pEnum);
			return pEnum;
		}

		public void ConfigureSubCollections(ICatalogCollection coll)
		{
		}
	}
}
namespace System.EnterpriseServices.CompensatingResourceManager
{
	[Serializable]
	[Flags]
	public enum LogRecordFlags
	{
		ForgetTarget = 1,
		WrittenDuringPrepare = 2,
		WrittenDuringCommit = 4,
		WrittenDuringAbort = 8,
		WrittenDurringRecovery = 0x10,
		WrittenDuringReplay = 0x20,
		ReplayInProgress = 0x40
	}
	[Serializable]
	[Flags]
	public enum CompensatorOptions
	{
		PreparePhase = 1,
		CommitPhase = 2,
		AbortPhase = 4,
		AllPhases = 7,
		FailIfInDoubtsRemain = 0x10
	}
	[Serializable]
	public enum TransactionState
	{
		Active,
		Committed,
		Aborted,
		Indoubt
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("BBC01830-8D3B-11D1-82EC-00A0C91EEDE9")]
	internal interface _ICompensator
	{
		void _SetLogControl(IntPtr logControl);

		void _BeginPrepare();

		[return: MarshalAs(UnmanagedType.Bool)]
		bool _PrepareRecord(_LogRecord record);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool _EndPrepare();

		void _BeginCommit(bool fRecovery);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool _CommitRecord(_LogRecord record);

		void _EndCommit();

		void _BeginAbort(bool fRecovery);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool _AbortRecord(_LogRecord record);

		void _EndAbort();
	}
	[ComImport]
	[Guid("70C8E441-C7ED-11D1-82FB-00A0C91EEDE9")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface _IMonitorLogRecords
	{
		int Count { get; }

		TransactionState TransactionState { get; }

		bool StructuredRecords
		{
			[return: MarshalAs(UnmanagedType.VariantBool)]
			get;
		}

		void GetLogRecord([In] int dwIndex, [In][Out][MarshalAs(UnmanagedType.LPStruct)] ref _LogRecord pRecord);

		object GetLogRecordVariants([In] object IndexNumber);
	}
	[ComImport]
	[Guid("9C51D821-C98B-11D1-82FB-00A0C91EEDE9")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface _IFormatLogRecords
	{
		int GetColumnCount();

		object GetColumnHeaders();

		object GetColumn([In] _LogRecord crmLogRec);

		object GetColumnVariants([In] object logRecord);
	}
	internal interface IFormatLogRecords
	{
		int ColumnCount { get; }

		string[] ColumnHeaders { get; }

		string[] Format(LogRecord r);
	}
	internal class BlobPackage
	{
		private byte[] _bits;

		internal _BLOB Blob;

		internal BlobPackage(_BLOB b)
		{
			Blob = b;
			_bits = null;
		}

		internal byte[] GetBits()
		{
			if (_bits != null)
			{
				return _bits;
			}
			byte[] array = new byte[Blob.cbSize];
			Marshal.Copy(Blob.pBlobData, array, 0, Blob.cbSize);
			return array;
		}
	}
	internal class Packager
	{
		private static BinaryFormatter _ser;

		private static volatile bool _initialized;

		private static void Init()
		{
			if (_initialized)
			{
				return;
			}
			lock (typeof(Packager))
			{
				if (!_initialized)
				{
					StreamingContext context = new StreamingContext(StreamingContextStates.File | StreamingContextStates.Persistence);
					_ser = new BinaryFormatter(null, context);
					_initialized = true;
				}
			}
		}

		internal static object Deserialize(BlobPackage b)
		{
			Init();
			byte[] bits = b.GetBits();
			return _ser.Deserialize(new MemoryStream(bits, writable: false));
		}

		internal static byte[] Serialize(object o)
		{
			Init();
			MemoryStream memoryStream = new MemoryStream();
			_ser.Serialize(memoryStream, o);
			return memoryStream.GetBuffer();
		}
	}
	public sealed class LogRecord
	{
		internal LogRecordFlags _flags;

		internal int _seq;

		internal object _data;

		public LogRecordFlags Flags => _flags;

		public int Sequence => _seq;

		public object Record => _data;

		internal LogRecord()
		{
			_flags = (LogRecordFlags)0;
			_seq = 0;
			_data = null;
		}

		internal LogRecord(_LogRecord r)
		{
			_flags = (LogRecordFlags)r.dwCrmFlags;
			_seq = r.dwSequenceNumber;
			_data = Packager.Deserialize(new BlobPackage(r.blobUserData));
		}
	}
	public class Compensator : ServicedComponent, _ICompensator, _IFormatLogRecords
	{
		private Clerk _clerk;

		public Clerk Clerk => _clerk;

		void _ICompensator._SetLogControl(IntPtr logControl)
		{
			_clerk = new Clerk(new CrmLogControl(logControl));
		}

		bool _ICompensator._PrepareRecord(_LogRecord record)
		{
			LogRecord rec = new LogRecord(record);
			return PrepareRecord(rec);
		}

		bool _ICompensator._CommitRecord(_LogRecord record)
		{
			LogRecord rec = new LogRecord(record);
			return CommitRecord(rec);
		}

		bool _ICompensator._AbortRecord(_LogRecord record)
		{
			LogRecord rec = new LogRecord(record);
			return AbortRecord(rec);
		}

		void _ICompensator._BeginPrepare()
		{
			BeginPrepare();
		}

		bool _ICompensator._EndPrepare()
		{
			return EndPrepare();
		}

		void _ICompensator._BeginCommit(bool fRecovery)
		{
			BeginCommit(fRecovery);
		}

		void _ICompensator._EndCommit()
		{
			EndCommit();
		}

		void _ICompensator._BeginAbort(bool fRecovery)
		{
			BeginAbort(fRecovery);
		}

		void _ICompensator._EndAbort()
		{
			EndAbort();
		}

		public Compensator()
		{
			_clerk = null;
		}

		public virtual void BeginPrepare()
		{
		}

		public virtual bool PrepareRecord(LogRecord rec)
		{
			return false;
		}

		public virtual bool EndPrepare()
		{
			return true;
		}

		public virtual void BeginCommit(bool fRecovery)
		{
		}

		public virtual bool CommitRecord(LogRecord rec)
		{
			return false;
		}

		public virtual void EndCommit()
		{
		}

		public virtual void BeginAbort(bool fRecovery)
		{
		}

		public virtual bool AbortRecord(LogRecord rec)
		{
			return false;
		}

		public virtual void EndAbort()
		{
		}

		int _IFormatLogRecords.GetColumnCount()
		{
			if (this is IFormatLogRecords)
			{
				return ((IFormatLogRecords)this).ColumnCount;
			}
			return 3;
		}

		object _IFormatLogRecords.GetColumnHeaders()
		{
			if (this is IFormatLogRecords)
			{
				return ((IFormatLogRecords)this).ColumnHeaders;
			}
			return new string[3]
			{
				Resource.FormatString("CRM_HeaderFlags"),
				Resource.FormatString("CRM_HeaderRecord"),
				Resource.FormatString("CRM_HeaderString")
			};
		}

		object _IFormatLogRecords.GetColumn(_LogRecord r)
		{
			LogRecord logRecord = new LogRecord(r);
			if (this is IFormatLogRecords)
			{
				return ((IFormatLogRecords)this).Format(logRecord);
			}
			return new string[3]
			{
				logRecord.Flags.ToString(),
				logRecord.Sequence.ToString(CultureInfo.CurrentUICulture),
				logRecord.Record.ToString()
			};
		}

		object _IFormatLogRecords.GetColumnVariants(object logRecord)
		{
			throw new NotSupportedException();
		}
	}
	public sealed class Clerk
	{
		private CrmLogControl _control;

		private CrmMonitorLogRecords _monitor;

		public string TransactionUOW => _control.GetTransactionUOW();

		public int LogRecordCount => _monitor.GetCount();

		private TransactionState TransactionState => (TransactionState)_monitor.GetTransactionState();

		internal Clerk(CrmLogControl logControl)
		{
			_control = logControl;
			_monitor = _control.GetMonitor();
		}

		private void ValidateCompensator(Type compensator)
		{
			if (!compensator.IsSubclassOf(typeof(Compensator)))
			{
				throw new ArgumentException(Resource.FormatString("CRM_CompensatorDerive"));
			}
			if (!new RegistrationServices().TypeRequiresRegistration(compensator))
			{
				throw new ArgumentException(Resource.FormatString("CRM_CompensatorConstructor"));
			}
			ServicedComponent servicedComponent = (ServicedComponent)Activator.CreateInstance(compensator);
			if (servicedComponent == null)
			{
				throw new ArgumentException(Resource.FormatString("CRM_CompensatorActivate"));
			}
			ServicedComponent.DisposeObject(servicedComponent);
		}

		private void Init(string compensator, string description, CompensatorOptions flags)
		{
			_control = new CrmLogControl();
			_control.RegisterCompensator(compensator, description, (int)flags);
			_monitor = _control.GetMonitor();
		}

		public Clerk(Type compensator, string description, CompensatorOptions flags)
		{
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			securityPermission.Assert();
			Platform.Assert(Platform.W2K, "CRM");
			ValidateCompensator(compensator);
			string compensator2 = string.Concat("{", Marshal.GenerateGuidForType(compensator), "}");
			Init(compensator2, description, flags);
		}

		public Clerk(string compensator, string description, CompensatorOptions flags)
		{
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			securityPermission.Assert();
			Init(compensator, description, flags);
		}

		public void ForceLog()
		{
			_control.ForceLog();
		}

		public void ForgetLogRecord()
		{
			_control.ForgetLogRecord();
		}

		public void ForceTransactionToAbort()
		{
			_control.ForceTransactionToAbort();
		}

		public void WriteLogRecord(object record)
		{
			byte[] b = Packager.Serialize(record);
			_control.WriteLogRecord(b);
		}

		~Clerk()
		{
			if (_monitor != null)
			{
				_monitor.Dispose();
			}
			if (_control != null)
			{
				_control.Dispose();
			}
		}
	}
	[Guid("70C8E442-C7ED-11D1-82FB-00A0C91EEDE9")]
	internal interface _IMonitorClerks
	{
		object Item(object index);

		[return: MarshalAs(UnmanagedType.Interface)]
		object _NewEnum();

		int Count();

		object ProgIdCompensator(object index);

		object Description(object index);

		object TransactionUOW(object index);

		object ActivityId(object index);
	}
	internal class ClerkMonitorEnumerator : IEnumerator
	{
		private ClerkMonitor _monitor;

		private int _version;

		private int _curIndex = -1;

		private int _endIndex;

		private object _curElement;

		public virtual object Current
		{
			get
			{
				if (_curIndex < 0)
				{
					throw new InvalidOperationException(Resource.FormatString("InvalidOperation_EnumNotStarted"));
				}
				if (_curIndex >= _endIndex)
				{
					throw new InvalidOperationException(Resource.FormatString("InvalidOperation_EnumEnded"));
				}
				return _curElement;
			}
		}

		internal ClerkMonitorEnumerator(ClerkMonitor c)
		{
			_monitor = c;
			_version = c._version;
			_endIndex = c.Count;
			_curElement = null;
		}

		public virtual bool MoveNext()
		{
			if (_version != _monitor._version)
			{
				throw new InvalidOperationException(Resource.FormatString("InvalidOperation_EnumFailedVersion"));
			}
			if (_curIndex < _endIndex)
			{
				_curIndex++;
			}
			if (_curIndex < _endIndex)
			{
				_curElement = _monitor[_curIndex];
				return true;
			}
			_curElement = null;
			return false;
		}

		public virtual void Reset()
		{
			if (_version != _monitor._version)
			{
				throw new InvalidOperationException(Resource.FormatString("InvalidOperation_EnumFailedVersion"));
			}
			_curIndex = -1;
			_curElement = null;
		}
	}
	public sealed class ClerkMonitor : IEnumerable
	{
		internal CrmMonitor _monitor;

		internal _IMonitorClerks _clerks;

		internal int _version;

		public int Count
		{
			get
			{
				if (_clerks == null)
				{
					return 0;
				}
				return _clerks.Count();
			}
		}

		public ClerkInfo this[int index]
		{
			get
			{
				if (_clerks == null)
				{
					return null;
				}
				return new ClerkInfo(index, _monitor, _clerks);
			}
		}

		public ClerkInfo this[string index]
		{
			get
			{
				if (_clerks == null)
				{
					return null;
				}
				return new ClerkInfo(index, _monitor, _clerks);
			}
		}

		public ClerkMonitor()
		{
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			securityPermission.Assert();
			_monitor = new CrmMonitor();
			_version = 0;
		}

		public void Populate()
		{
			_clerks = (_IMonitorClerks)_monitor.GetClerks();
			_version++;
		}

		public IEnumerator GetEnumerator()
		{
			return new ClerkMonitorEnumerator(this);
		}

		~ClerkMonitor()
		{
			_monitor.Release();
		}
	}
	public sealed class ClerkInfo
	{
		private object _index;

		private CrmMonitor _monitor;

		private _IMonitorClerks _clerks;

		public Clerk Clerk => new Clerk(_monitor.HoldClerk(InstanceId));

		public string InstanceId => (string)_clerks.Item(_index);

		public string Compensator => (string)_clerks.ProgIdCompensator(_index);

		public string Description => (string)_clerks.Description(_index);

		public string TransactionUOW => (string)_clerks.TransactionUOW(_index);

		public string ActivityId => (string)_clerks.ActivityId(_index);

		internal ClerkInfo(object index, CrmMonitor monitor, _IMonitorClerks clerks)
		{
			_index = index;
			_clerks = clerks;
			_monitor = monitor;
			_monitor.AddRef();
		}

		~ClerkInfo()
		{
			_monitor.Release();
		}
	}
	[ComVisible(false)]
	[ProgId("System.EnterpriseServices.Crm.ApplicationCrmEnabledAttribute")]
	[AttributeUsage(AttributeTargets.Assembly, Inherited = true)]
	public sealed class ApplicationCrmEnabledAttribute : Attribute, IConfigurationAttribute
	{
		private bool _value;

		public bool Value => _value;

		public ApplicationCrmEnabledAttribute()
			: this(val: true)
		{
		}

		public ApplicationCrmEnabledAttribute(bool val)
		{
			_value = val;
		}

		bool IConfigurationAttribute.IsValidTarget(string s)
		{
			return s == "Application";
		}

		bool IConfigurationAttribute.Apply(Hashtable info)
		{
			Platform.Assert(Platform.W2K, "CrmEnabledAttribute");
			ICatalogObject catalogObject = (ICatalogObject)info["Application"];
			catalogObject.SetValue("CRMEnabled", _value);
			return true;
		}

		bool IConfigurationAttribute.AfterSaveChanges(Hashtable info)
		{
			return false;
		}
	}
}
namespace System.EnterpriseServices.Internal
{
	[ComImport]
	[Guid("391ffbb9-a8ee-432a-abc8-baa238dab90f")]
	internal interface IAssemblyLocator
	{
		string[] GetModules(string applicationDir, string applicationName, string assemblyName);
	}
	[Guid("458aa3b5-265a-4b75-bc05-9bea4630cf18")]
	public class AssemblyLocator : MarshalByRefObject, IAssemblyLocator
	{
		string[] IAssemblyLocator.GetModules(string appdir, string appName, string name)
		{
			if (appdir != null && appdir.Length > 0)
			{
				AssemblyLocator assemblyLocator = null;
				try
				{
					AppDomainSetup appDomainSetup = new AppDomainSetup();
					appDomainSetup.ApplicationBase = appdir;
					AppDomain appDomain = AppDomain.CreateDomain(appName, null, appDomainSetup);
					if (appDomain != null)
					{
						ObjectHandle objectHandle = appDomain.CreateInstance(typeof(AssemblyLocator).Assembly.FullName, typeof(AssemblyLocator).FullName);
						if (objectHandle != null)
						{
							assemblyLocator = (AssemblyLocator)objectHandle.Unwrap();
						}
					}
				}
				catch (Exception)
				{
					return null;
				}
				catch
				{
					return null;
				}
				return ((IAssemblyLocator)assemblyLocator).GetModules((string)null, (string)null, name);
			}
			try
			{
				Module[] modules = Assembly.Load(name).GetModules();
				string[] array = new string[modules.Length];
				for (int i = 0; i < modules.Length; i++)
				{
					array[i] = modules[i].FullyQualifiedName;
				}
				return array;
			}
			catch (Exception ex2)
			{
				throw ex2;
			}
			catch
			{
				throw;
			}
		}
	}
	[ComImport]
	[Guid("c7b67079-8255-42c6-9ec0-6994a3548780")]
	internal interface IAppDomainHelper
	{
		void Initialize(IntPtr pUnkAD, IntPtr pfnShutdownCB, IntPtr data);

		void DoCallback(IntPtr pUnkAD, IntPtr pfnCallbackCB, IntPtr data);
	}
	[Guid("ef24f689-14f8-4d92-b4af-d7b1f0e70fd4")]
	public class AppDomainHelper : IAppDomainHelper
	{
		private class CallbackWrapper
		{
			private IntPtr _pfnCB;

			private IntPtr _pv;

			public CallbackWrapper(IntPtr pfnCB, IntPtr pv)
			{
				_pfnCB = pfnCB;
				_pv = pv;
			}

			public void ReceiveCallback()
			{
				int num = System.EnterpriseServices.Thunk.Proxy.CallFunction(_pfnCB, _pv);
				if (num < 0)
				{
					Marshal.ThrowExceptionForHR(num);
				}
			}
		}

		private AppDomain _ad;

		private IntPtr _pfnShutdownCB;

		private IntPtr _punkPool;

		void IAppDomainHelper.Initialize(IntPtr pUnkAD, IntPtr pfnShutdownCB, IntPtr punkPool)
		{
			_ad = (AppDomain)Marshal.GetObjectForIUnknown(pUnkAD);
			_pfnShutdownCB = pfnShutdownCB;
			_punkPool = punkPool;
			Marshal.AddRef(_punkPool);
			_ad.DomainUnload += OnDomainUnload;
		}

		void IAppDomainHelper.DoCallback(IntPtr pUnkAD, IntPtr pfnCallbackCB, IntPtr data)
		{
			CallbackWrapper callbackWrapper = new CallbackWrapper(pfnCallbackCB, data);
			if (_ad != AppDomain.CurrentDomain)
			{
				_ad.DoCallBack(callbackWrapper.ReceiveCallback);
			}
			else
			{
				callbackWrapper.ReceiveCallback();
			}
		}

		private void OnDomainUnload(object sender, EventArgs e)
		{
			if (_pfnShutdownCB != IntPtr.Zero)
			{
				System.EnterpriseServices.Thunk.Proxy.CallFunction(_pfnShutdownCB, _punkPool);
				_pfnShutdownCB = IntPtr.Zero;
				Marshal.Release(_punkPool);
				_punkPool = IntPtr.Zero;
			}
		}

		~AppDomainHelper()
		{
			if (_punkPool != IntPtr.Zero)
			{
				Marshal.Release(_punkPool);
				_punkPool = IntPtr.Zero;
			}
		}
	}
	[Guid("c3f8f66b-91be-4c99-a94f-ce3b0a951039")]
	public interface IComManagedImportUtil
	{
		[DispId(4)]
		void GetComponentInfo([MarshalAs(UnmanagedType.BStr)] string assemblyPath, [MarshalAs(UnmanagedType.BStr)] out string numComponents, [MarshalAs(UnmanagedType.BStr)] out string componentInfo);

		[DispId(5)]
		void InstallAssembly([MarshalAs(UnmanagedType.BStr)] string filename, [MarshalAs(UnmanagedType.BStr)] string parname, [MarshalAs(UnmanagedType.BStr)] string appname);
	}
	[Guid("3b0398c9-7812-4007-85cb-18c771f2206f")]
	public class ComManagedImportUtil : IComManagedImportUtil
	{
		public void GetComponentInfo(string assemblyPath, out string numComponents, out string componentInfo)
		{
			RegistrationServices registrationServices = new RegistrationServices();
			Assembly assembly = LoadAssembly(assemblyPath);
			Type[] registrableTypesInAssembly = registrationServices.GetRegistrableTypesInAssembly(assembly);
			int num = 0;
			string text = "";
			Type[] array = registrableTypesInAssembly;
			foreach (Type type in array)
			{
				if (type.IsClass && type.IsSubclassOf(typeof(ServicedComponent)))
				{
					num++;
					string text2 = Marshal.GenerateGuidForType(type).ToString();
					string text3 = Marshal.GenerateProgIdForType(type);
					if (text2.Length == 0 || text3.Length == 0)
					{
						throw new COMException();
					}
					string text4 = text;
					text = text4 + text3 + ",{" + text2 + "},";
				}
			}
			numComponents = num.ToString(CultureInfo.InvariantCulture);
			componentInfo = text;
		}

		private Assembly LoadAssembly(string assemblyFile)
		{
			string text = Path.GetFullPath(assemblyFile).ToLower(CultureInfo.InvariantCulture);
			bool flag = false;
			string directoryName = Path.GetDirectoryName(text);
			string currentDirectory = Environment.CurrentDirectory;
			if (currentDirectory != directoryName)
			{
				Environment.CurrentDirectory = directoryName;
				flag = true;
			}
			Assembly result = null;
			try
			{
				result = Assembly.LoadFrom(text);
			}
			catch
			{
			}
			if (flag)
			{
				Environment.CurrentDirectory = currentDirectory;
			}
			return result;
		}

		public void InstallAssembly(string asmpath, string parname, string appname)
		{
			try
			{
				string tlb = null;
				InstallationFlags installFlags = InstallationFlags.Default;
				RegistrationHelper registrationHelper = new RegistrationHelper();
				registrationHelper.InstallAssembly(asmpath, ref appname, parname, ref tlb, installFlags);
			}
			catch (Exception ex)
			{
				EventLog.WriteEntry(Resource.FormatString("Reg_InstallTitle"), Resource.FormatString("Reg_FailInstall", asmpath, appname) + "\n\n" + ex.ToString(), EventLogEntryType.Error);
				throw;
			}
			catch
			{
				EventLog.WriteEntry(Resource.FormatString("Reg_InstallTitle"), Resource.FormatString("Reg_FailInstall", asmpath, appname) + "\n\n" + Resource.FormatString("Err_NonClsException", "ComManagedImportUtil.InstallAssembly"), EventLogEntryType.Error);
				throw;
			}
		}
	}
}
namespace System.EnterpriseServices
{
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("7D8805A0-2EA7-11D1-B1CC-00AA00BA3258")]
	internal interface IObjPool
	{
		void Init([MarshalAs(UnmanagedType.Interface)] object pClassInfo);

		[return: MarshalAs(UnmanagedType.Interface)]
		object Get();

		void SetOption(int eOption, int dwOption);

		void PutNew([In][MarshalAs(UnmanagedType.Interface)] object pObj);

		void PutEndTx([In][MarshalAs(UnmanagedType.Interface)] object pObj);

		void PutDeactivated([In][MarshalAs(UnmanagedType.Interface)] object pObj);

		void Shutdown();
	}
	[ComImport]
	[Guid("C5FEB7C1-346A-11D1-B1CC-00AA00BA3258")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ITransactionResourcePool
	{
		[PreserveSig]
		int PutResource(IntPtr pPool, [MarshalAs(UnmanagedType.Interface)] object pUnk);

		[PreserveSig]
		int GetResource(IntPtr pPool, [MarshalAs(UnmanagedType.Interface)] out object obj);
	}
	public sealed class ResourcePool : IObjPool
	{
		public delegate void TransactionEndDelegate(object resource);

		private static readonly Guid GUID_TransactionProperty = new Guid("ecabaeb1-7f19-11d2-978e-0000f8757e2a");

		private TransactionEndDelegate _cb;

		public ResourcePool(TransactionEndDelegate cb)
		{
			Platform.Assert(Platform.W2K, "ResourcePool");
			_cb = cb;
		}

		private IntPtr GetToken()
		{
			return Marshal.GetComInterfaceForObject(this, typeof(IObjPool));
		}

		private void ReleaseToken()
		{
			IntPtr comInterfaceForObject = Marshal.GetComInterfaceForObject(this, typeof(IObjPool));
			Marshal.Release(comInterfaceForObject);
			Marshal.Release(comInterfaceForObject);
		}

		public bool PutResource(object resource)
		{
			ITransactionResourcePool transactionResourcePool = null;
			IntPtr intPtr = (IntPtr)0;
			bool flag = false;
			try
			{
				transactionResourcePool = GetResourcePool();
				if (transactionResourcePool != null)
				{
					intPtr = GetToken();
					int num = transactionResourcePool.PutResource(intPtr, resource);
					flag = num >= 0;
				}
			}
			finally
			{
				if (!flag && intPtr != (IntPtr)0)
				{
					Marshal.Release(intPtr);
				}
				if (transactionResourcePool != null)
				{
					Marshal.ReleaseComObject(transactionResourcePool);
				}
			}
			return flag;
		}

		public object GetResource()
		{
			object obj = null;
			ITransactionResourcePool transactionResourcePool = null;
			IntPtr intPtr = (IntPtr)0;
			try
			{
				intPtr = GetToken();
				transactionResourcePool = GetResourcePool();
				if (transactionResourcePool != null)
				{
					int resource = transactionResourcePool.GetResource(intPtr, out obj);
					if (resource >= 0)
					{
						Marshal.Release(intPtr);
						return obj;
					}
					return obj;
				}
				return obj;
			}
			finally
			{
				if (intPtr != (IntPtr)0)
				{
					Marshal.Release(intPtr);
				}
				if (transactionResourcePool != null)
				{
					Marshal.ReleaseComObject(transactionResourcePool);
				}
			}
		}

		private static ITransactionResourcePool GetResourcePool()
		{
			ITransactionResourcePool pool = null;
			object pUnk = null;
			int flags = 0;
			int num = 0;
			((IContext)ContextUtil.ObjectContext).GetProperty(GUID_TransactionProperty, out flags, out pUnk);
			num = ((ITransactionProperty)pUnk).GetTransactionResourcePool(out pool);
			if (num >= 0)
			{
				return pool;
			}
			return null;
		}

		void IObjPool.Init(object p)
		{
			throw new NotSupportedException();
		}

		object IObjPool.Get()
		{
			throw new NotSupportedException();
		}

		void IObjPool.SetOption(int o, int dw)
		{
			throw new NotSupportedException();
		}

		void IObjPool.PutNew(object o)
		{
			throw new NotSupportedException();
		}

		void IObjPool.PutDeactivated(object p)
		{
			throw new NotSupportedException();
		}

		void IObjPool.Shutdown()
		{
			throw new NotSupportedException();
		}

		void IObjPool.PutEndTx(object p)
		{
			_cb(p);
			ReleaseToken();
		}
	}
	[ComImport]
	[Guid("455ACF59-5345-11D2-99CF-00C04F797BC9")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ICreateWithTipTransactionEx
	{
		[return: MarshalAs(UnmanagedType.Interface)]
		object CreateInstance(string bstrTipUrl, [In][MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, [In][MarshalAs(UnmanagedType.LPStruct)] Guid riid);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("455ACF57-5345-11D2-99CF-00C04F797BC9")]
	internal interface ICreateWithTransactionEx
	{
		[return: MarshalAs(UnmanagedType.Interface)]
		object CreateInstance(ITransaction pTransaction, [In][MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, [In][MarshalAs(UnmanagedType.LPStruct)] Guid riid);
	}
	[ComImport]
	[Guid("227AC7A8-8423-42ce-B7CF-03061EC9AAA3")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ICreateWithLocalTransaction
	{
		[return: MarshalAs(UnmanagedType.Interface)]
		object CreateInstanceWithSysTx(ITransactionProxy pTransaction, [In][MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, [In][MarshalAs(UnmanagedType.LPStruct)] Guid riid);
	}
	[ComImport]
	[Guid("ECABB0AA-7F19-11D2-978E-0000F8757E2A")]
	internal class xByotServer
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		public extern xByotServer();
	}
	public sealed class BYOT
	{
		private BYOT()
		{
		}

		private static object GetByotServer()
		{
			return new xByotServer();
		}

		public static object CreateWithTransaction(object transaction, Type t)
		{
			Guid rclsid = Marshal.GenerateGuidForType(t);
			ITransaction transaction2 = null;
			Transaction transaction3 = transaction as Transaction;
			if (transaction3 != null)
			{
				object byotServer = GetByotServer();
				if (byotServer is ICreateWithLocalTransaction createWithLocalTransaction)
				{
					return createWithLocalTransaction.CreateInstanceWithSysTx(new TransactionProxy(transaction3), rclsid, Util.IID_IUnknown);
				}
				transaction2 = (ITransaction)TransactionInterop.GetDtcTransaction(transaction3);
			}
			else
			{
				transaction2 = (ITransaction)transaction;
			}
			return ((ICreateWithTransactionEx)GetByotServer()).CreateInstance(transaction2, rclsid, Util.IID_IUnknown);
		}

		public static object CreateWithTipTransaction(string url, Type t)
		{
			Guid rclsid = Marshal.GenerateGuidForType(t);
			return ((ICreateWithTipTransactionEx)GetByotServer()).CreateInstance(url, rclsid, Util.IID_IUnknown);
		}
	}
}
namespace System.EnterpriseServices.Internal
{
	[Guid("d8013eee-730b-45e2-ba24-874b7242c425")]
	public interface IComSoapPublisher
	{
		[DispId(4)]
		void CreateVirtualRoot([MarshalAs(UnmanagedType.BStr)] string Operation, [MarshalAs(UnmanagedType.BStr)] string FullUrl, [MarshalAs(UnmanagedType.BStr)] out string BaseUrl, [MarshalAs(UnmanagedType.BStr)] out string VirtualRoot, [MarshalAs(UnmanagedType.BStr)] out string PhysicalPath, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(5)]
		void DeleteVirtualRoot([MarshalAs(UnmanagedType.BStr)] string RootWebServer, [MarshalAs(UnmanagedType.BStr)] string FullUrl, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(6)]
		void CreateMailBox([MarshalAs(UnmanagedType.BStr)] string RootMailServer, [MarshalAs(UnmanagedType.BStr)] string MailBox, [MarshalAs(UnmanagedType.BStr)] out string SmtpName, [MarshalAs(UnmanagedType.BStr)] out string Domain, [MarshalAs(UnmanagedType.BStr)] out string PhysicalPath, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(7)]
		void DeleteMailBox([MarshalAs(UnmanagedType.BStr)] string RootMailServer, [MarshalAs(UnmanagedType.BStr)] string MailBox, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(8)]
		void ProcessServerTlb([MarshalAs(UnmanagedType.BStr)] string ProgId, [MarshalAs(UnmanagedType.BStr)] string SrcTlbPath, [MarshalAs(UnmanagedType.BStr)] string PhysicalPath, [MarshalAs(UnmanagedType.BStr)] string Operation, [MarshalAs(UnmanagedType.BStr)] out string AssemblyName, [MarshalAs(UnmanagedType.BStr)] out string TypeName, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(9)]
		void ProcessClientTlb([MarshalAs(UnmanagedType.BStr)] string ProgId, [MarshalAs(UnmanagedType.BStr)] string SrcTlbPath, [MarshalAs(UnmanagedType.BStr)] string PhysicalPath, [MarshalAs(UnmanagedType.BStr)] string VRoot, [MarshalAs(UnmanagedType.BStr)] string BaseUrl, [MarshalAs(UnmanagedType.BStr)] string Mode, [MarshalAs(UnmanagedType.BStr)] string Transport, [MarshalAs(UnmanagedType.BStr)] out string AssemblyName, [MarshalAs(UnmanagedType.BStr)] out string TypeName, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(10)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetTypeNameFromProgId([MarshalAs(UnmanagedType.BStr)] string AssemblyPath, [MarshalAs(UnmanagedType.BStr)] string ProgId);

		[DispId(11)]
		void RegisterAssembly([MarshalAs(UnmanagedType.BStr)] string AssemblyPath);

		[DispId(12)]
		void UnRegisterAssembly([MarshalAs(UnmanagedType.BStr)] string AssemblyPath);

		[DispId(13)]
		void GacInstall([MarshalAs(UnmanagedType.BStr)] string AssemblyPath);

		[DispId(14)]
		void GacRemove([MarshalAs(UnmanagedType.BStr)] string AssemblyPath);

		[DispId(15)]
		void GetAssemblyNameForCache([MarshalAs(UnmanagedType.BStr)] string TypeLibPath, [MarshalAs(UnmanagedType.BStr)] out string CachePath);
	}
	[Guid("d8013ef0-730b-45e2-ba24-874b7242c425")]
	public interface IComSoapIISVRoot
	{
		[DispId(1)]
		void Create([MarshalAs(UnmanagedType.BStr)] string RootWeb, [MarshalAs(UnmanagedType.BStr)] string PhysicalDirectory, [MarshalAs(UnmanagedType.BStr)] string VirtualDirectory, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(2)]
		void Delete([MarshalAs(UnmanagedType.BStr)] string RootWeb, [MarshalAs(UnmanagedType.BStr)] string PhysicalDirectory, [MarshalAs(UnmanagedType.BStr)] string VirtualDirectory, [MarshalAs(UnmanagedType.BStr)] out string Error);
	}
	[Guid("d8013ff0-730b-45e2-ba24-874b7242c425")]
	public interface IComSoapMetadata
	{
		[DispId(1)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string Generate([MarshalAs(UnmanagedType.BStr)] string SrcTypeLibFileName, [MarshalAs(UnmanagedType.BStr)] string OutPath);

		[DispId(2)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GenerateSigned([MarshalAs(UnmanagedType.BStr)] string SrcTypeLibFileName, [MarshalAs(UnmanagedType.BStr)] string OutPath, [MarshalAs(UnmanagedType.Bool)] bool InstallGac, [MarshalAs(UnmanagedType.BStr)] out string Error);
	}
	[Guid("6261e4b5-572a-4142-a2f9-1fe1a0c97097")]
	public interface IServerWebConfig
	{
		[DispId(1)]
		void AddElement([MarshalAs(UnmanagedType.BStr)] string FilePath, [MarshalAs(UnmanagedType.BStr)] string AssemblyName, [MarshalAs(UnmanagedType.BStr)] string TypeName, [MarshalAs(UnmanagedType.BStr)] string ProgId, [MarshalAs(UnmanagedType.BStr)] string Mode, [MarshalAs(UnmanagedType.BStr)] out string Error);

		[DispId(2)]
		void Create([MarshalAs(UnmanagedType.BStr)] string FilePath, [MarshalAs(UnmanagedType.BStr)] string FileRootName, [MarshalAs(UnmanagedType.BStr)] out string Error);
	}
	[ComImport]
	[Guid("7c23ff90-33af-11d3-95da-00a024a85b51")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IApplicationContext
	{
		void SetContextNameObject(IAssemblyName pName);

		void GetContextNameObject(out IAssemblyName ppName);

		void Set([MarshalAs(UnmanagedType.LPWStr)] string szName, int pvValue, uint cbValue, uint dwFlags);

		void Get([MarshalAs(UnmanagedType.LPWStr)] string szName, out int pvValue, ref uint pcbValue, uint dwFlags);

		void GetDynamicDirectory(out int wzDynamicDir, ref uint pdwSize);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("CD193BC0-B4BC-11d2-9833-00C04FC31D2E")]
	internal interface IAssemblyName
	{
		[PreserveSig]
		int SetProperty(uint PropertyId, IntPtr pvProperty, uint cbProperty);

		[PreserveSig]
		int GetProperty(uint PropertyId, IntPtr pvProperty, ref uint pcbProperty);

		[PreserveSig]
		int Finalize();

		[PreserveSig]
		int GetDisplayName(IntPtr szDisplayName, ref uint pccDisplayName, uint dwDisplayFlags);

		[PreserveSig]
		int BindToObject(object refIID, object pAsmBindSink, IApplicationContext pApplicationContext, [MarshalAs(UnmanagedType.LPWStr)] string szCodeBase, long llFlags, int pvReserved, uint cbReserved, out int ppv);

		[PreserveSig]
		int GetName(out uint lpcwBuffer, out int pwzName);

		[PreserveSig]
		int GetVersion(out uint pdwVersionHi, out uint pdwVersionLow);

		[PreserveSig]
		int IsEqual(IAssemblyName pName, uint dwCmpFlags);

		[PreserveSig]
		int Clone(out IAssemblyName pName);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("9e3aaeb4-d1cd-11d2-bab9-00c04f8eceae")]
	internal interface IAssemblyCacheItem
	{
		void CreateStream([MarshalAs(UnmanagedType.LPWStr)] string pszName, uint dwFormat, uint dwFlags, uint dwMaxSize, out System.Runtime.InteropServices.ComTypes.IStream ppStream);

		void IsNameEqual(IAssemblyName pName);

		void Commit(uint dwFlags);

		void MarkAssemblyVisible(uint dwFlags);
	}
	[ComImport]
	[Guid("e707dcde-d1cd-11d2-bab9-00c04f8eceae")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IAssemblyCache
	{
		[PreserveSig]
		int UninstallAssembly(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName, IntPtr pvReserved, out uint pulDisposition);

		[PreserveSig]
		int QueryAssemblyInfo(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName, IntPtr pAsmInfo);

		[PreserveSig]
		int CreateAssemblyCacheItem(uint dwFlags, IntPtr pvReserved, out IAssemblyCacheItem ppAsmItem, [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName);

		[PreserveSig]
		int CreateAssemblyScavenger(out object ppAsmScavenger);

		[PreserveSig]
		int InstallAssembly(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)] string pszManifestFilePath, IntPtr pvReserved);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("00020411-0000-0000-C000-000000000046")]
	internal interface ITypeLib2
	{
		int GetTypeInfoCount();

		int GetTypeInfo(int index, out ITypeInfo ti);

		int GetTypeInfoType(int index, out System.Runtime.InteropServices.ComTypes.TYPEKIND tkind);

		int GetTypeInfoOfGuid(ref Guid guid, ITypeInfo ti);

		int GetLibAttr(out System.Runtime.InteropServices.ComTypes.TYPELIBATTR tlibattr);

		int GetTypeComp(out ITypeComp tcomp);

		int GetDocumentation(int index, [MarshalAs(UnmanagedType.BStr)] out string name, [MarshalAs(UnmanagedType.BStr)] out string docString, out int helpContext, [MarshalAs(UnmanagedType.BStr)] out string helpFile);

		int IsName([MarshalAs(UnmanagedType.LPWStr)] ref string nameBuf, int hashVal, out int isName);

		int FindName([MarshalAs(UnmanagedType.LPWStr)] ref string szNameBuf, int hashVal, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.Interface, SizeParamIndex = 5)] out ITypeInfo[] tis, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.I4, SizeParamIndex = 5)] out int[] memIds, ref short foundCount);

		void ReleaseTLibAttr(System.Runtime.InteropServices.ComTypes.TYPELIBATTR libattr);

		int GetCustData(ref Guid guid, out object value);

		int GetLibStatistics(out int uniqueNames, out int chUniqueNames);

		int GetDocumentation2(int index, int lcid, [MarshalAs(UnmanagedType.BStr)] out string helpString, out int helpStringContext, [MarshalAs(UnmanagedType.BStr)] string helpStringDll);

		int GetAllCustData(out IntPtr custdata);
	}
	[Serializable]
	internal enum REGKIND
	{
		REGKIND_DEFAULT,
		REGKIND_REGISTER,
		REGKIND_NONE
	}
	public class ComSoapPublishError
	{
		public static void Report(string s)
		{
			try
			{
				EventLog eventLog = new EventLog();
				eventLog.Source = "COM+ SOAP Services";
				eventLog.WriteEntry(s, EventLogEntryType.Warning);
			}
			catch
			{
			}
		}
	}
	public class ClientRemotingConfig
	{
		private const string indent = "  ";

		public static bool Write(string DestinationDirectory, string VRoot, string BaseUrl, string AssemblyName, string TypeName, string ProgId, string Mode, string Transport)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
				securityPermission.Demand();
				string text = "<configuration>\r\n";
				text += "  <system.runtime.remoting>\r\n";
				text += "    <application>\r\n";
				string text2 = BaseUrl;
				if (text2.Length > 0 && !text2.EndsWith("/", StringComparison.Ordinal))
				{
					text2 += "/";
				}
				text2 += VRoot;
				text = text + "      <client url=\"" + text2 + "\">\r\n";
				if (Mode.Length <= 0 || "WELLKNOWNOBJECT" == Mode.ToUpper(CultureInfo.InvariantCulture))
				{
					text += "        ";
					string text3 = text;
					text = text3 + "<wellknown type=\"" + TypeName + ", " + AssemblyName + "\" url=\"" + text2;
					if (!text2.EndsWith("/", StringComparison.Ordinal))
					{
						text += "/";
					}
					text = text + ProgId + ".soap\" />\r\n";
				}
				else
				{
					text += "        ";
					string text4 = text;
					text = text4 + "<activated type=\"" + TypeName + ", " + AssemblyName + "\"/>\r\n";
				}
				text += "      </client>\r\n";
				text += "    </application>\r\n";
				text += "  </system.runtime.remoting>\r\n";
				text += "</configuration>\r\n";
				string text5 = DestinationDirectory;
				if (text5.Length > 0 && !text5.EndsWith("\\", StringComparison.Ordinal))
				{
					text5 += "\\";
				}
				text5 = text5 + TypeName + ".config";
				if (File.Exists(text5))
				{
					File.Delete(text5);
				}
				FileStream fileStream = new FileStream(text5, FileMode.Create);
				StreamWriter streamWriter = new StreamWriter(fileStream);
				streamWriter.Write(text);
				streamWriter.Close();
				fileStream.Close();
				return true;
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				return false;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ClientRemotingConfig.Write"));
				return false;
			}
		}
	}
	internal class HomePage
	{
		public void Create(string FilePath, string VirtualRoot, string PageName, string DiscoRef)
		{
			try
			{
				if (!FilePath.EndsWith("/", StringComparison.Ordinal) && !FilePath.EndsWith("\\", StringComparison.Ordinal))
				{
					FilePath += "\\";
				}
				if (!File.Exists(FilePath + PageName))
				{
					SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
					securityPermission.Demand();
					string text = FilePath + "web.config";
					string text2 = "<%@ Import Namespace=\"System.Collections\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.IO\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.Xml.Serialization\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.Xml\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.Xml.Schema\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.Web.Services.Description\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.Globalization\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.Resources\" %>\r\n";
					text2 += "<%@ Import Namespace=\"System.Diagnostics\" %>\r\n";
					text2 += "<html>\r\n";
					text2 += "<script language=\"C#\" runat=\"server\">\r\n";
					text2 += "    string soapNs = \"http://schemas.xmlsoap.org/soap/envelope/\";\r\n";
					text2 += "    string soapEncNs = \"http://schemas.xmlsoap.org/soap/encoding/\";\r\n";
					text2 += "    string urtNs = \"urn:schemas-microsoft-com:urt-types\";\r\n";
					text2 += "    string wsdlNs = \"http://schemas.xmlsoap.org/wsdl/\";\r\n";
					text2 = text2 + "    string VRoot = \"" + VirtualRoot + "\";\r\n";
					text2 += "    string ServiceName() { return VRoot; }\r\n";
					text2 += "\r\n";
					text2 += "   XmlNode GetNextNamedSiblingNode(XmlNode inNode, string name)\r\n";
					text2 += "    {\r\n";
					text2 += "       if (inNode == null ) return inNode;\r\n";
					text2 += "      if (inNode.Name == name) return inNode;\r\n";
					text2 += "       XmlNode newNode = inNode.NextSibling;\r\n";
					text2 += "       if (newNode == null) return newNode;\r\n";
					text2 += "       if (newNode.Name == name ) return newNode;\r\n";
					text2 += "       bool found = false;\r\n";
					text2 += "       while (!found)\r\n";
					text2 += "       {\r\n";
					text2 += "           XmlNode oldNode = newNode;\r\n";
					text2 += "           newNode = oldNode.NextSibling;\r\n";
					text2 += "           if (null == newNode || newNode == oldNode)\r\n";
					text2 += "           {\r\n";
					text2 += "               newNode = null;\r\n";
					text2 += "               break;\r\n";
					text2 += "           }\r\n";
					text2 += "           if (newNode.Name == name) found = true;\r\n";
					text2 += "       }\r\n";
					text2 += "       return newNode;\r\n";
					text2 += "   }\r\n";
					text2 += "\r\n";
					text2 += "   string GetNodes()\r\n";
					text2 += "   {\r\n";
					text2 += "       string retval = \"\";\r\n";
					text2 += "       XmlDocument configXml = new XmlDocument();\r\n";
					text2 = text2 + "      configXml.Load(@\"" + text + "\");\r\n";
					text2 += "       XmlNode node= configXml.DocumentElement;\r\n";
					text2 += "        node = GetNextNamedSiblingNode(node,\"configuration\");\r\n";
					text2 += "        node = GetNextNamedSiblingNode(node.FirstChild, \"system.runtime.remoting\");\r\n";
					text2 += "        node = GetNextNamedSiblingNode(node.FirstChild, \"application\");\r\n";
					text2 += "        node = GetNextNamedSiblingNode(node.FirstChild, \"service\");\r\n";
					text2 += "        node = GetNextNamedSiblingNode(node.FirstChild, \"wellknown\");\r\n";
					text2 += "       while (node != null)\r\n";
					text2 += "       {\r\n";
					text2 += "           XmlNode attribType = node.Attributes.GetNamedItem(\"objectUri\");\r\n";
					text2 += "           retval += \"<a href=\" + attribType.Value + \"?WSDL>\" + attribType.Value +\"?WSDL</a><br><br>\";\r\n";
					text2 += "           node = GetNextNamedSiblingNode(node.NextSibling, \"wellknown\");\r\n";
					text2 += "       }\r\n";
					text2 += "        return retval;\r\n";
					text2 += "    }\r\n";
					text2 += "\r\n";
					text2 += "</script>\r\n";
					text2 += "<title><% = ServiceName() %></title>\r\n";
					text2 += "<head>\r\n";
					text2 = text2 + "<link type='text/xml' rel='alternate' href='" + DiscoRef + "' />\r\n";
					text2 += "\r\n";
					text2 += "   <style type=\"text/css\">\r\n";
					text2 += " \r\n";
					text2 += "       BODY { color: #000000; background-color: white; font-family: \"Verdana\"; margin-left: 0px; margin-top: 0px; }\r\n";
					text2 += "       #content { margin-left: 30px; font-size: .70em; padding-bottom: 2em; }\r\n";
					text2 += "       A:link { color: #336699; font-weight: bold; text-decoration: underline; }\r\n";
					text2 += "       A:visited { color: #6699cc; font-weight: bold; text-decoration: underline; }\r\n";
					text2 += "       A:active { color: #336699; font-weight: bold; text-decoration: underline; }\r\n";
					text2 += "       A:hover { color: cc3300; font-weight: bold; text-decoration: underline; }\r\n";
					text2 += "       P { color: #000000; margin-top: 0px; margin-bottom: 12px; font-family: \"Verdana\"; }\r\n";
					text2 += "       pre { background-color: #e5e5cc; padding: 5px; font-family: \"Courier New\"; font-size: x-small; margin-top: -5px; border: 1px #f0f0e0 solid; }\r\n";
					text2 += "       td { color: #000000; font-family: verdana; font-size: .7em; }\r\n";
					text2 += "       h2 { font-size: 1.5em; font-weight: bold; margin-top: 25px; margin-bottom: 10px; border-top: 1px solid #003366; margin-left: -15px; color: #003366; }\r\n";
					text2 += "       h3 { font-size: 1.1em; color: #000000; margin-left: -15px; margin-top: 10px; margin-bottom: 10px; }\r\n";
					text2 += "       ul, ol { margin-top: 10px; margin-left: 20px; }\r\n";
					text2 += "       li { margin-top: 10px; color: #000000; }\r\n";
					text2 += "       font.value { color: darkblue; font: bold; }\r\n";
					text2 += "       font.key { color: darkgreen; font: bold; }\r\n";
					text2 += "       .heading1 { color: #ffffff; font-family: \"Tahoma\"; font-size: 26px; font-weight: normal; background-color: #003366; margin-top: 0px; margin-bottom: 0px; margin-left: 0px; padding-top: 10px; padding-bottom: 3px; padding-left: 15px; width: 105%; }\r\n";
					text2 += "       .button { background-color: #dcdcdc; font-family: \"Verdana\"; font-size: 1em; border-top: #cccccc 1px solid; border-bottom: #666666 1px solid; border-left: #cccccc 1px solid; border-right: #666666 1px solid; }\r\n";
					text2 += "       .frmheader { color: #000000; background: #dcdcdc; font-family: \"Verdana\"; font-size: .7em; font-weight: normal; border-bottom: 1px solid #dcdcdc; padding-top: 2px; padding-bottom: 2px; }\r\n";
					text2 += "       .frmtext { font-family: \"Verdana\"; font-size: .7em; margin-top: 8px; margin-bottom: 0px; margin-left: 32px; }\r\n";
					text2 += "       .frmInput { font-family: \"Verdana\"; font-size: 1em; }\r\n";
					text2 += "       .intro { margin-left: -15px; }\r\n";
					text2 += " \r\n";
					text2 += "    </style>\r\n";
					text2 += "\r\n";
					text2 += "</head>\r\n";
					text2 += "<body>\r\n";
					text2 += "<p class=\"heading1\"><% = ServiceName() %></p><br>\r\n";
					text2 += "<% = GetNodes() %>\r\n";
					text2 += "</body>\r\n";
					text2 += "</html>\r\n";
					FileStream fileStream = new FileStream(FilePath + PageName, FileMode.Create);
					StreamWriter streamWriter = new StreamWriter(fileStream);
					streamWriter.Write(text2);
					streamWriter.Close();
					fileStream.Close();
				}
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "HomePage.Create"));
			}
		}
	}
	internal class DiscoFile
	{
		public void Create(string FilePath, string DiscoRef)
		{
			try
			{
				if (!FilePath.EndsWith("/", StringComparison.Ordinal) && !FilePath.EndsWith("\\", StringComparison.Ordinal))
				{
					FilePath += "\\";
				}
				if (!File.Exists(FilePath + DiscoRef))
				{
					SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
					securityPermission.Demand();
					string text = "<?xml version=\"1.0\" ?>\n";
					text += "<discovery xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://schemas.xmlsoap.org/disco/\">\n";
					text += "</discovery>\n";
					FileStream fileStream = new FileStream(FilePath + DiscoRef, FileMode.Create);
					StreamWriter streamWriter = new StreamWriter(fileStream);
					streamWriter.Write(text);
					streamWriter.Close();
					fileStream.Close();
				}
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "DiscoFile.Create"));
			}
		}

		internal void DeleteElement(string FilePath, string SoapPageRef)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
				securityPermission.Demand();
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(FilePath);
				XmlNode xmlNode = xmlDocument.DocumentElement;
				while (xmlNode.Name != "discovery")
				{
					xmlNode = xmlNode.NextSibling;
				}
				XmlNodeList xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::ref='" + SoapPageRef + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode2 = xmlNodeList.Item(0);
					if (xmlNode2.ParentNode != null)
					{
						xmlNode2.ParentNode.RemoveChild(xmlNode2);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::ref='" + SoapPageRef + "']");
					}
				}
				xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::address='" + SoapPageRef + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode3 = xmlNodeList.Item(0);
					if (xmlNode3.ParentNode != null)
					{
						xmlNode3.ParentNode.RemoveChild(xmlNode3);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::address='" + SoapPageRef + "']");
					}
				}
				xmlDocument.Save(FilePath);
			}
			catch (DirectoryNotFoundException)
			{
			}
			catch (FileNotFoundException)
			{
			}
			catch (Exception ex3)
			{
				ComSoapPublishError.Report(ex3.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "DiscoFile.DeleteElement"));
			}
		}

		public void AddElement(string FilePath, string SoapPageRef)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
				securityPermission.Demand();
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(FilePath);
				XmlNode xmlNode = xmlDocument.DocumentElement;
				while (xmlNode.Name != "discovery")
				{
					xmlNode = xmlNode.NextSibling;
				}
				XmlNodeList xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::ref='" + SoapPageRef + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode2 = xmlNodeList.Item(0);
					if (xmlNode2.ParentNode != null)
					{
						xmlNode2.ParentNode.RemoveChild(xmlNode2);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::ref='" + SoapPageRef + "']");
					}
				}
				xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::address='" + SoapPageRef + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode3 = xmlNodeList.Item(0);
					if (xmlNode3.ParentNode != null)
					{
						xmlNode3.ParentNode.RemoveChild(xmlNode3);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::address='" + SoapPageRef + "']");
					}
				}
				XmlElement xmlElement = xmlDocument.CreateElement("", "contractRef", "");
				xmlElement.SetAttribute("ref", SoapPageRef);
				xmlElement.SetAttribute("docRef", SoapPageRef);
				xmlElement.SetAttribute("xmlns", "http://schemas.xmlsoap.org/disco/scl/");
				xmlNode.AppendChild(xmlElement);
				XmlElement xmlElement2 = xmlDocument.CreateElement("", "soap", "");
				xmlElement2.SetAttribute("address", SoapPageRef);
				xmlElement2.SetAttribute("xmlns", "http://schemas.xmlsoap.org/disco/soap/");
				xmlNode.AppendChild(xmlElement2);
				xmlDocument.Save(FilePath);
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "DiscoFile.AddElement"));
			}
		}
	}
	public class ServerWebConfig : IServerWebConfig
	{
		private const string indent = "  ";

		private string webconfig = "";

		public void Create(string FilePath, string FilePrefix, out string Error)
		{
			Error = "";
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
				securityPermission.Demand();
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ServerWebConfig.Create"));
				throw;
			}
			if (!FilePath.EndsWith("/", StringComparison.Ordinal) && !FilePath.EndsWith("\\", StringComparison.Ordinal))
			{
				FilePath += "\\";
			}
			if (!File.Exists(FilePath + FilePrefix + ".config"))
			{
				webconfig = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n";
				webconfig += "<configuration>\r\n";
				webconfig += "  <system.runtime.remoting>\r\n";
				webconfig += "    <application>\r\n";
				webconfig += "      <service>\r\n";
				webconfig += "      </service>\r\n";
				webconfig += "    </application>\r\n";
				webconfig += "  </system.runtime.remoting>\r\n";
				webconfig += "</configuration>\r\n";
				if (!WriteFile(FilePath, FilePrefix, ".config"))
				{
					Error = Resource.FormatString("Soap_WebConfigFailed");
					ComSoapPublishError.Report(Error);
				}
			}
		}

		public void AddElement(string FilePath, string AssemblyName, string TypeName, string ProgId, string WkoMode, out string Error)
		{
			Error = "";
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
				securityPermission.Demand();
				string text = TypeName + ", " + AssemblyName;
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(FilePath);
				XmlNode xmlNode = xmlDocument.DocumentElement;
				while (xmlNode.Name != "configuration")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "system.runtime.remoting")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "application")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "service")
				{
					xmlNode = xmlNode.NextSibling;
				}
				XmlNodeList xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode2 = xmlNodeList.Item(0);
					if (xmlNode2.ParentNode != null)
					{
						xmlNode2.ParentNode.RemoveChild(xmlNode2);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text + "']");
					}
				}
				XmlElement xmlElement = xmlDocument.CreateElement("", "wellknown", "");
				xmlElement.SetAttribute("mode", WkoMode);
				xmlElement.SetAttribute("type", text);
				xmlElement.SetAttribute("objectUri", ProgId + ".soap");
				xmlNode.AppendChild(xmlElement);
				XmlElement xmlElement2 = xmlDocument.CreateElement("", "activated", "");
				xmlElement2.SetAttribute("type", text);
				xmlNode.AppendChild(xmlElement2);
				xmlDocument.Save(FilePath);
			}
			catch (Exception ex)
			{
				Error = ex.ToString();
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ServerWebConfig.AddElement"));
			}
		}

		internal void AddGacElement(string FilePath, string AssemblyName, string TypeName, string ProgId, string WkoMode, string AssemblyFile)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
				securityPermission.Demand();
				AssemblyManager assemblyManager = new AssemblyManager();
				string text = TypeName + ", " + assemblyManager.GetFullName(AssemblyFile, AssemblyName);
				string text2 = TypeName + ", " + AssemblyName;
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(FilePath);
				XmlNode xmlNode = xmlDocument.DocumentElement;
				while (xmlNode.Name != "configuration")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "system.runtime.remoting")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "application")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "service")
				{
					xmlNode = xmlNode.NextSibling;
				}
				XmlNodeList xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode2 = xmlNodeList.Item(0);
					if (xmlNode2.ParentNode != null)
					{
						xmlNode2.ParentNode.RemoveChild(xmlNode2);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
					}
				}
				xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode3 = xmlNodeList.Item(0);
					if (xmlNode3.ParentNode != null)
					{
						xmlNode3.ParentNode.RemoveChild(xmlNode3);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text + "']");
					}
				}
				XmlElement xmlElement = xmlDocument.CreateElement("", "wellknown", "");
				xmlElement.SetAttribute("mode", WkoMode);
				xmlElement.SetAttribute("type", text);
				xmlElement.SetAttribute("objectUri", ProgId + ".soap");
				xmlNode.AppendChild(xmlElement);
				XmlElement xmlElement2 = xmlDocument.CreateElement("", "activated", "");
				xmlElement2.SetAttribute("type", text2);
				xmlNode.AppendChild(xmlElement2);
				xmlDocument.Save(FilePath);
			}
			catch (RegistrationException)
			{
				throw;
			}
			catch (Exception ex2)
			{
				ComSoapPublishError.Report(ex2.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ServerWebConfig.AddGacElement"));
			}
		}

		internal void DeleteElement(string FilePath, string AssemblyName, string TypeName, string ProgId, string WkoMode, string AssemblyFile)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.RemotingConfiguration);
				securityPermission.Demand();
				AssemblyManager assemblyManager = new AssemblyManager();
				string text = TypeName + ", " + assemblyManager.GetFullName(AssemblyFile, AssemblyName);
				string text2 = TypeName + ", " + AssemblyName;
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(FilePath);
				XmlNode xmlNode = xmlDocument.DocumentElement;
				while (xmlNode.Name != "configuration")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "system.runtime.remoting")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "application")
				{
					xmlNode = xmlNode.NextSibling;
				}
				xmlNode = xmlNode.FirstChild;
				while (xmlNode.Name != "service")
				{
					xmlNode = xmlNode.NextSibling;
				}
				XmlNodeList xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode2 = xmlNodeList.Item(0);
					if (xmlNode2.ParentNode != null)
					{
						xmlNode2.ParentNode.RemoveChild(xmlNode2);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
					}
				}
				xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode3 = xmlNodeList.Item(0);
					if (xmlNode3.ParentNode != null)
					{
						xmlNode3.ParentNode.RemoveChild(xmlNode3);
						xmlNodeList = xmlNode.SelectNodes("descendant::*[attribute::type='" + text + "']");
					}
				}
				xmlDocument.Save(FilePath);
			}
			catch (DirectoryNotFoundException)
			{
			}
			catch (FileNotFoundException)
			{
			}
			catch (Exception ex3)
			{
				ComSoapPublishError.Report(ex3.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ServerWebConfig.DeleteElement"));
			}
		}

		private bool WriteFile(string PhysicalDirectory, string FilePrefix, string FileSuffix)
		{
			try
			{
				string path = PhysicalDirectory + FilePrefix + FileSuffix;
				if (File.Exists(path))
				{
					File.Delete(path);
				}
				FileStream fileStream = new FileStream(path, FileMode.Create);
				StreamWriter streamWriter = new StreamWriter(fileStream);
				streamWriter.Write(webconfig);
				streamWriter.Close();
				fileStream.Close();
				return true;
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				return false;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ServerWebConfig.WriteFile"));
				return false;
			}
		}
	}
	[Guid("d8013ef1-730b-45e2-ba24-874b7242c425")]
	public class IISVirtualRoot : IComSoapIISVRoot
	{
		internal bool CheckIfExists(string RootWeb, string VirtualDirectory)
		{
			DirectoryEntry directoryEntry = new DirectoryEntry(RootWeb + "/" + VirtualDirectory);
			try
			{
				_ = directoryEntry.Name;
			}
			catch
			{
				return false;
			}
			return true;
		}

		public void Create(string RootWeb, string inPhysicalDirectory, string VirtualDirectory, out string Error)
		{
			Error = "";
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				string text = inPhysicalDirectory;
				while (text.EndsWith("/", StringComparison.Ordinal) || text.EndsWith("\\", StringComparison.Ordinal))
				{
					text = text.Remove(text.Length - 1, 1);
				}
				if (!CheckIfExists(RootWeb, VirtualDirectory))
				{
					DirectoryEntry directoryEntry = new DirectoryEntry(RootWeb);
					DirectoryEntry directoryEntry2 = directoryEntry.Children.Add(VirtualDirectory, "IIsWebVirtualDir");
					directoryEntry2.CommitChanges();
					directoryEntry2.Properties["Path"][0] = text;
					directoryEntry2.Properties["AuthFlags"][0] = 5;
					directoryEntry2.Properties["EnableDefaultDoc"][0] = true;
					directoryEntry2.Properties["DirBrowseFlags"][0] = 1073741886;
					directoryEntry2.Properties["AccessFlags"][0] = 513;
					directoryEntry2.CommitChanges();
					directoryEntry2.Invoke("AppCreate2", 2);
					Error = "";
				}
			}
			catch (Exception ex)
			{
				Error = ex.ToString();
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "IISVirtualRoot.Create"));
			}
		}

		public void Delete(string RootWeb, string PhysicalDirectory, string VirtualDirectory, out string Error)
		{
			Error = "";
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				if (CheckIfExists(RootWeb, VirtualDirectory))
				{
					DirectoryEntry directoryEntry = new DirectoryEntry(RootWeb);
					DirectoryEntry directoryEntry2 = new DirectoryEntry(RootWeb + "/" + VirtualDirectory);
					directoryEntry2.Invoke("AppDelete", null);
					directoryEntry.Invoke("Delete", "IIsWebVirtualDir", VirtualDirectory);
					Directory.Delete(PhysicalDirectory, recursive: true);
				}
			}
			catch (Exception ex)
			{
				Error = ex.ToString();
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "IISVirtualRoot.Delete"));
			}
		}
	}
	internal static class CacheInfo
	{
		internal static string GetCacheName(string AssemblyPath, string srcTypeLib)
		{
			string empty = string.Empty;
			try
			{
				FileInfo fileInfo = new FileInfo(srcTypeLib);
				string cachePath = GetCachePath(CreateDir: true);
				string text = fileInfo.Length.ToString(CultureInfo.InvariantCulture);
				string text2 = fileInfo.Name.ToString();
				string text3 = fileInfo.LastWriteTime.Year.ToString(CultureInfo.InvariantCulture);
				text3 = text3 + "_" + fileInfo.LastWriteTime.Month.ToString(CultureInfo.InvariantCulture);
				text3 = text3 + "_" + fileInfo.LastWriteTime.Day.ToString(CultureInfo.InvariantCulture);
				text3 = text3 + "_" + fileInfo.LastWriteTime.Hour.ToString(CultureInfo.InvariantCulture);
				text3 = text3 + "_" + fileInfo.LastWriteTime.Minute.ToString(CultureInfo.InvariantCulture);
				text3 = text3 + "_" + fileInfo.LastWriteTime.Second.ToString(CultureInfo.InvariantCulture);
				string text4 = text2 + "_" + text + "_" + text3;
				text4 = cachePath + text4 + "\\";
				if (!Directory.Exists(text4))
				{
					Directory.CreateDirectory(text4);
				}
				char[] anyOf = new char[2] { '/', '\\' };
				int num = AssemblyPath.LastIndexOfAny(anyOf) + 1;
				if (num <= 0)
				{
					num = 0;
				}
				string text5 = AssemblyPath.Substring(num, AssemblyPath.Length - num);
				return text4 + text5;
			}
			catch (Exception ex)
			{
				empty = string.Empty;
				ComSoapPublishError.Report(ex.ToString());
				return empty;
			}
			catch
			{
				empty = string.Empty;
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "CacheInfo.GetCacheName"));
				return empty;
			}
		}

		internal static string GetCachePath(bool CreateDir)
		{
			StringBuilder stringBuilder = new StringBuilder(1024, 1024);
			uint uSize = 1024u;
			Publish.GetSystemDirectory(stringBuilder, uSize);
			string text = stringBuilder.ToString();
			text += "\\com\\SOAPCache\\";
			if (CreateDir)
			{
				try
				{
					if (Directory.Exists(text))
					{
						return text;
					}
					Directory.CreateDirectory(text);
					return text;
				}
				catch (Exception ex)
				{
					ComSoapPublishError.Report(ex.ToString());
					return text;
				}
				catch
				{
					ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "CacheInfo.GetCachePath"));
					return text;
				}
			}
			return text;
		}

		internal static string GetMetadataName(string strSrcTypeLib, ITypeLib TypeLib, out string strMetaFileRoot)
		{
			string result = "";
			strMetaFileRoot = "";
			if (TypeLib == null)
			{
				TypeLib = GetTypeLib(strSrcTypeLib);
				if (TypeLib == null)
				{
					return result;
				}
			}
			result = Marshal.GetTypeLibName(TypeLib);
			strMetaFileRoot = result + ".dll";
			char[] anyOf = new char[2] { '/', '\\' };
			int num = strSrcTypeLib.LastIndexOfAny(anyOf) + 1;
			if (num <= 0)
			{
				num = 0;
			}
			string text = strSrcTypeLib.Substring(num, strSrcTypeLib.Length - num);
			if (text.ToLower(CultureInfo.InvariantCulture) == strMetaFileRoot.ToLower(CultureInfo.InvariantCulture))
			{
				result += "SoapLib";
				strMetaFileRoot = result + ".dll";
			}
			return result;
		}

		internal static ITypeLib GetTypeLib(string strTypeLibPath)
		{
			ITypeLib TypeLib = null;
			try
			{
				LoadTypeLibEx(strTypeLibPath, REGKIND.REGKIND_NONE, out TypeLib);
				return TypeLib;
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147312566)
				{
					string text = Resource.FormatString("Soap_InputFileNotValidTypeLib");
					ComSoapPublishError.Report(text + " " + strTypeLibPath);
				}
				else
				{
					ComSoapPublishError.Report(ex.ToString());
				}
				return null;
			}
		}

		[DllImport("oleaut32.dll", CharSet = CharSet.Unicode)]
		private static extern void LoadTypeLibEx(string strTypeLibName, REGKIND regKind, out ITypeLib TypeLib);
	}
	internal class AssemblyManager : MarshalByRefObject
	{
		internal string InternalGetGacName(string fName)
		{
			string result = "";
			try
			{
				AssemblyName assemblyName = AssemblyName.GetAssemblyName(fName);
				result = assemblyName.Name + ",Version=" + assemblyName.Version.ToString();
				return result;
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				return result;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "AssemblyManager.InternalGetGacName"));
				return result;
			}
		}

		public string GetGacName(string fName)
		{
			string result = "";
			AssemblyManager assemblyManager = null;
			AppDomainSetup info = new AppDomainSetup();
			AppDomain appDomain = AppDomain.CreateDomain("SoapDomain", null, info);
			if (appDomain != null)
			{
				try
				{
					ObjectHandle objectHandle = appDomain.CreateInstance(typeof(AssemblyManager).Assembly.FullName, typeof(AssemblyManager).FullName);
					if (objectHandle != null)
					{
						assemblyManager = (AssemblyManager)objectHandle.Unwrap();
						return assemblyManager.InternalGetGacName(fName);
					}
					return result;
				}
				finally
				{
					AppDomain.Unload(appDomain);
				}
			}
			return result;
		}

		internal string InternalGetFullName(string fName, string strAssemblyName)
		{
			string result = "";
			try
			{
				if (File.Exists(fName))
				{
					AssemblyName assemblyName = AssemblyName.GetAssemblyName(fName);
					result = assemblyName.FullName;
					return result;
				}
				try
				{
					Assembly assembly = Assembly.LoadWithPartialName(strAssemblyName, null);
					result = assembly.FullName;
					return result;
				}
				catch
				{
					throw new RegistrationException(Resource.FormatString("ServicedComponentException_AssemblyNotInGAC"));
				}
			}
			catch (RegistrationException)
			{
				throw;
			}
			catch (Exception ex2)
			{
				ComSoapPublishError.Report(ex2.ToString());
				return result;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "AssemblyManager.InternalGetFullName"));
				return result;
			}
		}

		public string GetFullName(string fName, string strAssemblyName)
		{
			string result = "";
			AssemblyManager assemblyManager = null;
			AppDomainSetup info = new AppDomainSetup();
			AppDomain appDomain = AppDomain.CreateDomain("SoapDomain", null, info);
			if (appDomain != null)
			{
				try
				{
					ObjectHandle objectHandle = appDomain.CreateInstance(typeof(AssemblyManager).Assembly.FullName, typeof(AssemblyManager).FullName);
					if (objectHandle != null)
					{
						assemblyManager = (AssemblyManager)objectHandle.Unwrap();
						return assemblyManager.InternalGetFullName(fName, strAssemblyName);
					}
					return result;
				}
				finally
				{
					AppDomain.Unload(appDomain);
				}
			}
			return result;
		}

		internal string InternalGetTypeNameFromClassId(string assemblyPath, string classId)
		{
			string result = "";
			Assembly assembly = Assembly.LoadFrom(assemblyPath);
			Guid guid = new Guid(classId);
			Type[] types = assembly.GetTypes();
			Type[] array = types;
			foreach (Type type in array)
			{
				if (guid.Equals(type.GUID))
				{
					result = type.FullName;
					break;
				}
			}
			return result;
		}

		internal string InternalGetTypeNameFromProgId(string AssemblyPath, string ProgId)
		{
			string result = "";
			Assembly assembly = Assembly.LoadFrom(AssemblyPath);
			try
			{
				RegistryKey registryKey = Registry.ClassesRoot.OpenSubKey(ProgId + "\\CLSID");
				string g = (string)registryKey.GetValue("");
				Guid guid = new Guid(g);
				Type[] types = assembly.GetTypes();
				Type[] array = types;
				foreach (Type type in array)
				{
					if (guid.Equals(type.GUID))
					{
						return type.FullName;
					}
				}
				return result;
			}
			catch
			{
				result = string.Empty;
				throw;
			}
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool CopyFile(string source, string dest, bool failifexists);

		internal bool GetFromCache(string AssemblyPath, string srcTypeLib)
		{
			try
			{
				string cacheName = CacheInfo.GetCacheName(AssemblyPath, srcTypeLib);
				if (File.Exists(cacheName))
				{
					return CopyFile(cacheName, AssemblyPath, failifexists: true);
				}
				return false;
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "AssemblyManager.GetFromCache"));
			}
			return false;
		}

		internal bool CopyToCache(string AssemblyPath, string srcTypeLib)
		{
			bool result = false;
			try
			{
				string cacheName = CacheInfo.GetCacheName(AssemblyPath, srcTypeLib);
				if (File.Exists(cacheName))
				{
					return true;
				}
				return CopyFile(AssemblyPath, cacheName, failifexists: false);
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				return result;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "AssemblyManager.CopyToCache"));
				return result;
			}
		}

		internal bool CompareToCache(string AssemblyPath, string srcTypeLib)
		{
			bool result = true;
			try
			{
				string cacheName = CacheInfo.GetCacheName(AssemblyPath, srcTypeLib);
				if (!File.Exists(AssemblyPath))
				{
					return false;
				}
				if (!File.Exists(cacheName))
				{
					return false;
				}
				return result;
			}
			catch (Exception ex)
			{
				result = false;
				ComSoapPublishError.Report(ex.ToString());
				return result;
			}
			catch
			{
				result = false;
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "AssemblyManager.CompareToCache"));
				return result;
			}
		}
	}
	[Guid("d8013eef-730b-45e2-ba24-874b7242c425")]
	public class Publish : IComSoapPublisher
	{
		private static string MsCorLibDirectory
		{
			get
			{
				string path = Assembly.GetAssembly(typeof(object)).Location.Replace('/', '\\');
				return Path.GetDirectoryName(path);
			}
		}

		public void RegisterAssembly(string AssemblyPath)
		{
			try
			{
				RegistryPermission registryPermission = new RegistryPermission(PermissionState.Unrestricted);
				registryPermission.Demand();
				registryPermission.Assert();
				Assembly assembly = Assembly.LoadFrom(AssemblyPath);
				RegistrationServices registrationServices = new RegistrationServices();
				registrationServices.RegisterAssembly(assembly, AssemblyRegistrationFlags.SetCodeBase);
				Version version = Assembly.GetExecutingAssembly().GetName().Version;
				AssemblyName[] referencedAssemblies = assembly.GetReferencedAssemblies();
				foreach (AssemblyName assemblyName in referencedAssemblies)
				{
					if (!(assemblyName.Name == "System.EnterpriseServices") || !(version < assemblyName.Version))
					{
						continue;
					}
					Uri uri = new Uri(assembly.Location);
					if (!uri.IsFile || !(uri.LocalPath != ""))
					{
						continue;
					}
					string path = uri.LocalPath.Remove(uri.LocalPath.Length - Path.GetFileName(uri.LocalPath).Length, Path.GetFileName(uri.LocalPath).Length);
					string[] files = Directory.GetFiles(path, "*.tlb");
					string[] array = files;
					foreach (string text in array)
					{
						Guid guid = new Guid("90883F05-3D28-11D2-8F17-00A0C9A6186D");
						Marshal.ThrowExceptionForHR(LoadTypeLib(text, out var tlib));
						if (((ITypeLib2)tlib).GetCustData(ref guid, out var value) == 0 && (string)value == assembly.FullName)
						{
							Marshal.ReleaseComObject(tlib);
							RegistrationDriver.GenerateTypeLibrary(assembly, text, null);
						}
					}
				}
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.RegisterAssembly"));
				throw;
			}
		}

		public void UnRegisterAssembly(string AssemblyPath)
		{
			try
			{
				RegistryPermission registryPermission = new RegistryPermission(PermissionState.Unrestricted);
				registryPermission.Demand();
				registryPermission.Assert();
				Assembly assembly = Assembly.LoadFrom(AssemblyPath);
				new RegistrationServices().UnregisterAssembly(assembly);
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.UnregisterAssembly"));
				throw;
			}
		}

		public void GacInstall(string AssemblyPath)
		{
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			string text = Path.Combine(MsCorLibDirectory, "fusion.dll");
			IntPtr intPtr = LoadLibrary(text);
			if (intPtr == IntPtr.Zero)
			{
				throw new DllNotFoundException(text);
			}
			PrivateGacInstall(AssemblyPath);
		}

		private void PrivateGacInstall(string AssemblyPath)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				IAssemblyCache ppAsmCache = null;
				int num = CreateAssemblyCache(out ppAsmCache, 0u);
				if (num == 0)
				{
					num = ppAsmCache.InstallAssembly(0u, AssemblyPath, (IntPtr)0);
				}
				if (num != 0)
				{
					string text = Resource.FormatString("Soap_GacInstallFailed");
					ComSoapPublishError.Report(text + " " + AssemblyPath);
				}
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.PrivateGacInstall"));
				throw;
			}
		}

		public void GacRemove(string AssemblyPath)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				AssemblyManager assemblyManager = new AssemblyManager();
				string gacName = assemblyManager.GetGacName(AssemblyPath);
				IAssemblyCache ppAsmCache = null;
				int num = CreateAssemblyCache(out ppAsmCache, 0u);
				uint pulDisposition = 0u;
				if (num == 0)
				{
					num = ppAsmCache.UninstallAssembly(0u, gacName, (IntPtr)0, out pulDisposition);
				}
				if (num != 0)
				{
					string text = Resource.FormatString("Soap_GacRemoveFailed");
					ComSoapPublishError.Report(text + " " + AssemblyPath + " " + gacName);
				}
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.GacRemove"));
				throw;
			}
		}

		public void GetAssemblyNameForCache(string TypeLibPath, out string CachePath)
		{
			CacheInfo.GetMetadataName(TypeLibPath, null, out CachePath);
			CachePath = CacheInfo.GetCacheName(CachePath, TypeLibPath);
		}

		public static string GetClientPhysicalPath(bool CreateDir)
		{
			StringBuilder stringBuilder = new StringBuilder(1024, 1024);
			uint uSize = 1024u;
			GetSystemDirectory(stringBuilder, uSize);
			string text = stringBuilder.ToString() + "\\com\\SOAPAssembly\\";
			if (CreateDir)
			{
				try
				{
					if (Directory.Exists(text))
					{
						return text;
					}
					Directory.CreateDirectory(text);
					return text;
				}
				catch (Exception ex)
				{
					text = string.Empty;
					ComSoapPublishError.Report(ex.ToString());
					return text;
				}
				catch
				{
					text = string.Empty;
					ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.GetClientPhysicalPath"));
					return text;
				}
			}
			return text;
		}

		private bool GetVRootPhysicalPath(string VirtualRoot, out string PhysicalPath, out string BinDirectory, bool CreateDir)
		{
			bool result = true;
			StringBuilder stringBuilder = new StringBuilder(1024, 1024);
			uint uSize = 1024u;
			GetSystemDirectory(stringBuilder, uSize);
			string text = stringBuilder.ToString();
			text += "\\com\\SOAPVRoots\\";
			PhysicalPath = text + VirtualRoot + "\\";
			BinDirectory = PhysicalPath + "bin\\";
			if (CreateDir)
			{
				try
				{
					try
					{
						if (!Directory.Exists(text))
						{
							Directory.CreateDirectory(text);
						}
					}
					catch
					{
					}
					try
					{
						if (!Directory.Exists(PhysicalPath))
						{
							Directory.CreateDirectory(PhysicalPath);
						}
					}
					catch
					{
					}
					try
					{
						if (Directory.Exists(BinDirectory))
						{
							return result;
						}
						Directory.CreateDirectory(BinDirectory);
						result = false;
						return result;
					}
					catch
					{
						return result;
					}
				}
				catch (Exception ex)
				{
					PhysicalPath = string.Empty;
					BinDirectory = string.Empty;
					ComSoapPublishError.Report(ex.ToString());
					return result;
				}
				catch
				{
					PhysicalPath = string.Empty;
					BinDirectory = string.Empty;
					ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.GetVRootPhysicalPath"));
					return result;
				}
			}
			return Directory.Exists(BinDirectory);
		}

		public static void ParseUrl(string FullUrl, out string BaseUrl, out string VirtualRoot)
		{
			try
			{
				Uri uri = new Uri(FullUrl);
				string[] segments = uri.Segments;
				VirtualRoot = segments[segments.GetUpperBound(0)];
				BaseUrl = FullUrl.Substring(0, FullUrl.Length - VirtualRoot.Length);
				char[] trimChars = new char[1] { '/' };
				VirtualRoot = VirtualRoot.TrimEnd(trimChars);
			}
			catch
			{
				BaseUrl = string.Empty;
				VirtualRoot = FullUrl;
			}
			if (BaseUrl.Length <= 0)
			{
				try
				{
					BaseUrl = "http://";
					BaseUrl += Dns.GetHostName();
					BaseUrl += "/";
				}
				catch (Exception ex)
				{
					ComSoapPublishError.Report(ex.ToString());
				}
				catch
				{
					ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.ParseUrl"));
				}
			}
		}

		public void CreateVirtualRoot(string Operation, string FullUrl, out string BaseUrl, out string VirtualRoot, out string PhysicalPath, out string Error)
		{
			BaseUrl = "";
			VirtualRoot = "";
			PhysicalPath = "";
			Error = "";
			if (FullUrl.Length <= 0)
			{
				return;
			}
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				ParseUrl(FullUrl, out BaseUrl, out VirtualRoot);
				if (VirtualRoot.Length <= 0)
				{
					return;
				}
				string rootWeb = "IIS://localhost/W3SVC/1/ROOT";
				bool flag = true;
				if (Operation.ToLower(CultureInfo.InvariantCulture) == "delete" || Operation.ToLower(CultureInfo.InvariantCulture) == "addcomponent")
				{
					flag = false;
				}
				string BinDirectory = "";
				GetVRootPhysicalPath(VirtualRoot, out PhysicalPath, out BinDirectory, flag);
				if (PhysicalPath.Length <= 0)
				{
					Error = Resource.FormatString("Soap_VRootDirectoryCreationFailed");
				}
				else
				{
					if (!flag)
					{
						return;
					}
					ServerWebConfig serverWebConfig = new ServerWebConfig();
					string Error2 = "";
					serverWebConfig.Create(PhysicalPath, "Web", out Error2);
					DiscoFile discoFile = new DiscoFile();
					discoFile.Create(PhysicalPath, "Default.disco");
					HomePage homePage = new HomePage();
					homePage.Create(PhysicalPath, VirtualRoot, "Default.aspx", "Default.disco");
					string Error3 = "";
					try
					{
						IISVirtualRoot iISVirtualRoot = new IISVirtualRoot();
						iISVirtualRoot.Create(rootWeb, PhysicalPath, VirtualRoot, out Error3);
					}
					catch (Exception ex)
					{
						if (Error3.Length <= 0)
						{
							string text = Resource.FormatString("Soap_VRootCreationFailed");
							Error3 = string.Format(CultureInfo.CurrentCulture, text + " " + VirtualRoot + " " + ex.ToString());
						}
					}
					catch
					{
						if (Error3.Length <= 0)
						{
							Error3 = Resource.FormatString("Soap_VRootCreationFailed") + VirtualRoot + " " + Resource.FormatString("Err_NonClsException", "Publish.CreateVirtualRoot");
						}
					}
					if (Error3.Length > 0)
					{
						Error = Error3;
					}
				}
			}
			catch (Exception ex2)
			{
				Error = ex2.ToString();
				ComSoapPublishError.Report(Error);
			}
			catch
			{
				Error = Resource.FormatString("Err_NonClsException", "Publish.CreateVirtualRoot");
				ComSoapPublishError.Report(Error);
			}
		}

		public void DeleteVirtualRoot(string RootWebServer, string FullUrl, out string Error)
		{
			Error = "";
			try
			{
				if (FullUrl.Length <= 0)
				{
					return;
				}
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				_ = RootWebServer.Length;
				_ = 0;
				string BaseUrl = "";
				string VirtualRoot = "";
				ParseUrl(FullUrl, out BaseUrl, out VirtualRoot);
				if (VirtualRoot.Length > 0)
				{
					string PhysicalPath = "";
					string BinDirectory = "";
					GetVRootPhysicalPath(VirtualRoot, out PhysicalPath, out BinDirectory, CreateDir: false);
					if (PhysicalPath.Length > 0)
					{
					}
				}
			}
			catch (Exception ex)
			{
				Error = ex.ToString();
				ComSoapPublishError.Report(ex.ToString());
			}
			catch
			{
				Error = Resource.FormatString("Err_NonClsException", "Publish.DeleteVirtualRoot");
				ComSoapPublishError.Report(Error);
			}
		}

		public void CreateMailBox(string RootMailServer, string MailBox, out string SmtpName, out string Domain, out string PhysicalPath, out string Error)
		{
			SmtpName = "";
			Domain = "";
			PhysicalPath = "";
			Error = "";
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			string s = Resource.FormatString("Soap_SmtpNotImplemented");
			ComSoapPublishError.Report(s);
			if (MailBox.Length > 0)
			{
			}
		}

		public void DeleteMailBox(string RootMailServer, string MailBox, out string Error)
		{
			Error = "";
			SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
			securityPermission.Demand();
			string s = Resource.FormatString("Soap_SmtpNotImplemented");
			ComSoapPublishError.Report(s);
			if (MailBox.Length > 0)
			{
			}
		}

		public void ProcessServerTlb(string ProgId, string SrcTlbPath, string PhysicalPath, string Operation, out string strAssemblyName, out string TypeName, out string Error)
		{
			strAssemblyName = "";
			TypeName = "";
			Error = "";
			bool flag = false;
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				if (Operation != null && Operation.ToLower(CultureInfo.InvariantCulture) == "delete")
				{
					flag = true;
				}
				if (SrcTlbPath.Length <= 0)
				{
					return;
				}
				if (!PhysicalPath.EndsWith("/", StringComparison.Ordinal) && !PhysicalPath.EndsWith("\\", StringComparison.Ordinal))
				{
					PhysicalPath += "\\";
				}
				string text = SrcTlbPath.ToLower(CultureInfo.InvariantCulture);
				if (text.EndsWith("mscoree.dll", StringComparison.Ordinal))
				{
					Type typeFromProgID = Type.GetTypeFromProgID(ProgId);
					if (typeFromProgID.FullName == "System.__ComObject")
					{
						throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_DependencyNotInGAC"));
					}
					TypeName = typeFromProgID.FullName;
					Assembly assembly = typeFromProgID.Assembly;
					strAssemblyName = assembly.GetName().Name;
				}
				else if (text.EndsWith("scrobj.dll", StringComparison.Ordinal))
				{
					if (!flag)
					{
						throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_WSCNotSupported"));
					}
				}
				else
				{
					GenerateMetadata generateMetadata = new GenerateMetadata();
					if (flag)
					{
						strAssemblyName = generateMetadata.GetAssemblyName(SrcTlbPath, PhysicalPath + "bin\\");
					}
					else
					{
						strAssemblyName = generateMetadata.GenerateSigned(SrcTlbPath, PhysicalPath + "bin\\", InstallGac: false, out Error);
					}
					if (strAssemblyName.Length > 0)
					{
						try
						{
							TypeName = GetTypeNameFromProgId(PhysicalPath + "bin\\" + strAssemblyName + ".dll", ProgId);
						}
						catch (DirectoryNotFoundException)
						{
							if (!flag)
							{
								throw;
							}
						}
						catch (FileNotFoundException)
						{
							if (!flag)
							{
								throw;
							}
						}
					}
				}
				if (ProgId.Length > 0 && strAssemblyName.Length > 0 && TypeName.Length > 0)
				{
					ServerWebConfig serverWebConfig = new ServerWebConfig();
					DiscoFile discoFile = new DiscoFile();
					string assemblyFile = PhysicalPath + "bin\\" + strAssemblyName + ".dll";
					if (flag)
					{
						serverWebConfig.DeleteElement(PhysicalPath + "Web.Config", strAssemblyName, TypeName, ProgId, "SingleCall", assemblyFile);
						discoFile.DeleteElement(PhysicalPath + "Default.disco", ProgId + ".soap?WSDL");
					}
					else
					{
						serverWebConfig.AddGacElement(PhysicalPath + "Web.Config", strAssemblyName, TypeName, ProgId, "SingleCall", assemblyFile);
						discoFile.AddElement(PhysicalPath + "Default.disco", ProgId + ".soap?WSDL");
					}
				}
			}
			catch (Exception ex3)
			{
				Error = ex3.ToString();
				ComSoapPublishError.Report(Error);
				if (typeof(ServicedComponentException) == ex3.GetType() || typeof(RegistrationException) == ex3.GetType())
				{
					throw;
				}
			}
			catch
			{
				Error = Resource.FormatString("Err_NonClsException", "Publish.ProcessServerTlb");
				ComSoapPublishError.Report(Error);
			}
		}

		public string GetTypeNameFromProgId(string AssemblyPath, string ProgId)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "Publish.GetTypeNameFromProgId"));
				throw;
			}
			string result = "";
			AssemblyManager assemblyManager = null;
			AppDomainSetup info = new AppDomainSetup();
			AppDomain appDomain = AppDomain.CreateDomain("SoapDomain", null, info);
			if (appDomain != null)
			{
				try
				{
					ObjectHandle objectHandle = appDomain.CreateInstance(typeof(AssemblyManager).Assembly.FullName, typeof(AssemblyManager).FullName);
					if (objectHandle != null)
					{
						assemblyManager = (AssemblyManager)objectHandle.Unwrap();
						return assemblyManager.InternalGetTypeNameFromProgId(AssemblyPath, ProgId);
					}
					return result;
				}
				finally
				{
					AppDomain.Unload(appDomain);
				}
			}
			return result;
		}

		public void ProcessClientTlb(string ProgId, string SrcTlbPath, string PhysicalPath, string VRoot, string BaseUrl, string Mode, string Transport, out string AssemblyName, out string TypeName, out string Error)
		{
			AssemblyName = "";
			TypeName = "";
			Error = "";
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				string clientPhysicalPath = GetClientPhysicalPath(CreateDir: true);
				string text = SrcTlbPath.ToLower(CultureInfo.InvariantCulture);
				if (!text.EndsWith("mscoree.dll", StringComparison.Ordinal) && SrcTlbPath.Length > 0)
				{
					GenerateMetadata generateMetadata = new GenerateMetadata();
					AssemblyName = generateMetadata.Generate(SrcTlbPath, clientPhysicalPath);
					if (ProgId.Length > 0)
					{
						TypeName = GetTypeNameFromProgId(clientPhysicalPath + AssemblyName + ".dll", ProgId);
					}
				}
				else if (ProgId.Length > 0)
				{
					RegistryKey registryKey = Registry.ClassesRoot.OpenSubKey(ProgId + "\\CLSID");
					string g = (string)registryKey.GetValue("");
					Guid guid = new Guid(g);
					RegistryKey registryKey2 = Registry.ClassesRoot.OpenSubKey(string.Concat("CLSID\\{", guid, "}\\InprocServer32"));
					AssemblyName = (string)registryKey2.GetValue("Assembly");
					int num = AssemblyName.IndexOf(",");
					if (num > 0)
					{
						AssemblyName = AssemblyName.Substring(0, num);
					}
					TypeName = (string)registryKey2.GetValue("Class");
				}
				if (ProgId.Length > 0)
				{
					Uri baseUri = new Uri(BaseUrl);
					Uri uri = new Uri(baseUri, VRoot);
					if (uri.Scheme.ToLower(CultureInfo.InvariantCulture) == "https")
					{
						string authentication = "Windows";
						SoapClientConfig.Write(clientPhysicalPath, uri.AbsoluteUri, AssemblyName, TypeName, ProgId, authentication);
					}
					else
					{
						ClientRemotingConfig.Write(clientPhysicalPath, VRoot, BaseUrl, AssemblyName, TypeName, ProgId, Mode, Transport);
					}
				}
			}
			catch (Exception ex)
			{
				Error = ex.ToString();
				ComSoapPublishError.Report(Error);
			}
			catch
			{
				Error = Resource.FormatString("Err_NonClsException", "Publish.ProcessClientTlb");
				ComSoapPublishError.Report(Error);
			}
		}

		[DllImport("Fusion.dll", CharSet = CharSet.Auto)]
		internal static extern int CreateAssemblyCache(out IAssemblyCache ppAsmCache, uint dwReserved);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		internal static extern uint GetSystemDirectory(StringBuilder lpBuf, uint uSize);

		[DllImport("oleaut32.dll", CharSet = CharSet.Unicode)]
		internal static extern int LoadTypeLib([MarshalAs(UnmanagedType.LPWStr)] string file, out ITypeLib tlib);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		internal static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPWStr)] string filename);
	}
	[Guid("d8013ff1-730b-45e2-ba24-874b7242c425")]
	public class GenerateMetadata : IComSoapMetadata
	{
		internal class ImporterCallback : ITypeLibImporterNotifySink
		{
			private string m_strOutputDir = "";

			internal string OutputDir
			{
				set
				{
					m_strOutputDir = value;
				}
			}

			public void ReportEvent(ImporterEventKind EventKind, int EventCode, string EventMsg)
			{
			}

			internal string GetTlbPath(string guidAttr, string strMajorVer, string strMinorVer)
			{
				string text = "";
				string name = "TypeLib\\{" + guidAttr + "}\\" + strMajorVer + "." + strMinorVer + "\\0\\win32";
				RegistryKey registryKey = Registry.ClassesRoot.OpenSubKey(name);
				if (registryKey == null)
				{
					throw new COMException(Resource.FormatString("Soap_ResolutionForTypeLibFailed") + " " + guidAttr, Util.REGDB_E_CLASSNOTREG);
				}
				return (string)registryKey.GetValue("");
			}

			public Assembly ResolveRef(object TypeLib)
			{
				Assembly assembly = null;
				IntPtr ppTLibAttr = (IntPtr)0;
				try
				{
					((ITypeLib)TypeLib).GetLibAttr(out ppTLibAttr);
					System.Runtime.InteropServices.ComTypes.TYPELIBATTR tYPELIBATTR = (System.Runtime.InteropServices.ComTypes.TYPELIBATTR)Marshal.PtrToStructure(ppTLibAttr, typeof(System.Runtime.InteropServices.ComTypes.TYPELIBATTR));
					string tlbPath = GetTlbPath(tYPELIBATTR.guid.ToString(string.Empty, CultureInfo.InvariantCulture), tYPELIBATTR.wMajorVerNum.ToString(CultureInfo.InvariantCulture), tYPELIBATTR.wMinorVerNum.ToString(CultureInfo.InvariantCulture));
					if (tlbPath.Length > 0)
					{
						GenerateMetadata generateMetadata = new GenerateMetadata();
						string Error = "";
						string text = generateMetadata.GenerateSigned(tlbPath, m_strOutputDir, InstallGac: true, out Error);
						if (text.Length > 0)
						{
							assembly = Assembly.Load(text, null);
						}
					}
				}
				finally
				{
					if (ppTLibAttr != (IntPtr)0)
					{
						((ITypeLib)TypeLib).ReleaseTLibAttr(ppTLibAttr);
					}
				}
				if (assembly == null)
				{
					string typeLibName = Marshal.GetTypeLibName((ITypeLib)TypeLib);
					string text2 = Resource.FormatString("Soap_ResolutionForTypeLibFailed");
					ComSoapPublishError.Report(text2 + " " + typeLibName);
				}
				return assembly;
			}
		}

		internal bool _signed;

		internal bool _nameonly;

		internal string GetAssemblyName(string strSrcTypeLib, string outPath)
		{
			_nameonly = true;
			return Generate(strSrcTypeLib, outPath);
		}

		public string Generate(string strSrcTypeLib, string outPath)
		{
			return GenerateMetaData(strSrcTypeLib, outPath, null, null);
		}

		public string GenerateSigned(string strSrcTypeLib, string outPath, bool InstallGac, out string Error)
		{
			string result = "";
			_signed = true;
			try
			{
				Error = "";
				uint dwFlags = 0u;
				IntPtr ppbKeyBlob = IntPtr.Zero;
				uint pcbKeyBlob = 0u;
				StrongNameKeyGen(strSrcTypeLib, dwFlags, out ppbKeyBlob, out pcbKeyBlob);
				byte[] array = new byte[pcbKeyBlob];
				Marshal.Copy(ppbKeyBlob, array, 0, (int)pcbKeyBlob);
				StrongNameFreeBuffer(ppbKeyBlob);
				StrongNameKeyPair keyPair = new StrongNameKeyPair(array);
				result = GenerateMetaData(strSrcTypeLib, outPath, null, keyPair);
				return result;
			}
			catch (Exception ex)
			{
				Error = ex.ToString();
				ComSoapPublishError.Report(Error);
				return result;
			}
			catch
			{
				Error = Resource.FormatString("Err_NonClsException", "GenerateMetadata.GenerateSigned");
				ComSoapPublishError.Report(Error);
				return result;
			}
		}

		public string GenerateMetaData(string strSrcTypeLib, string outPath, byte[] PublicKey, StrongNameKeyPair KeyPair)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "GenerateMetadata.GenerateMetaData"));
				throw;
			}
			string result = "";
			if (0 >= strSrcTypeLib.Length || 0 >= outPath.Length)
			{
				return result;
			}
			if (!outPath.EndsWith("/", StringComparison.Ordinal) && !outPath.EndsWith("\\", StringComparison.Ordinal))
			{
				outPath += "\\";
			}
			ITypeLib typeLib = null;
			typeLib = CacheInfo.GetTypeLib(strSrcTypeLib);
			if (typeLib == null)
			{
				return result;
			}
			result = CacheInfo.GetMetadataName(strSrcTypeLib, typeLib, out var strMetaFileRoot);
			if (result.Length == 0)
			{
				return result;
			}
			if (_nameonly)
			{
				return result;
			}
			string text = outPath + strMetaFileRoot;
			if (_signed)
			{
				try
				{
					AssemblyManager assemblyManager = new AssemblyManager();
					if (assemblyManager.CompareToCache(text, strSrcTypeLib))
					{
						Publish publish = new Publish();
						publish.GacInstall(text);
						return result;
					}
					if (assemblyManager.GetFromCache(text, strSrcTypeLib))
					{
						Publish publish2 = new Publish();
						publish2.GacInstall(text);
						return result;
					}
				}
				catch (Exception ex2)
				{
					ComSoapPublishError.Report(ex2.ToString());
				}
				catch
				{
					ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "GenerateMetadata.GenerateMetaData"));
				}
			}
			else if (File.Exists(text))
			{
				return result;
			}
			try
			{
				ITypeLibConverter typeLibConverter = new TypeLibConverter();
				ImporterCallback importerCallback = new ImporterCallback();
				importerCallback.OutputDir = outPath;
				AssemblyBuilder assemblyBuilder = typeLibConverter.ConvertTypeLibToAssembly(typeLib, text, TypeLibImporterFlags.UnsafeInterfaces, importerCallback, PublicKey, KeyPair, null, null);
				FileInfo fileInfo = new FileInfo(text);
				assemblyBuilder.Save(fileInfo.Name);
				if (_signed)
				{
					AssemblyManager assemblyManager2 = new AssemblyManager();
					assemblyManager2.CopyToCache(text, strSrcTypeLib);
					Publish publish3 = new Publish();
					publish3.GacInstall(text);
					return result;
				}
				return result;
			}
			catch (ReflectionTypeLoadException ex3)
			{
				Exception[] loaderExceptions = ex3.LoaderExceptions;
				for (int i = 0; i < loaderExceptions.Length; i++)
				{
					try
					{
						ComSoapPublishError.Report(loaderExceptions[i].ToString());
					}
					catch (Exception ex4)
					{
						ComSoapPublishError.Report(ex4.ToString());
					}
					catch
					{
						ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "GenerateMetaData.GenerateMetaData"));
					}
				}
				return string.Empty;
			}
			catch (Exception ex5)
			{
				ComSoapPublishError.Report(ex5.ToString());
				return string.Empty;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "GenerateMetaData.GenerateMetaData"));
				return string.Empty;
			}
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern int SearchPath(string path, string fileName, string extension, int numBufferChars, string buffer, int[] filePart);

		[DllImport("mscoree.dll")]
		private static extern int StrongNameKeyGen(string wszKeyContainer, uint dwFlags, out IntPtr ppbKeyBlob, out uint pcbKeyBlob);

		[DllImport("mscoree.dll")]
		private static extern void StrongNameFreeBuffer(IntPtr ppbKeyBlob);
	}
	[Guid("ecabafd2-7f19-11d2-978e-0000f8757e2a")]
	public interface IClrObjectFactory
	{
		[DispId(1)]
		[return: MarshalAs(UnmanagedType.IDispatch)]
		object CreateFromAssembly(string assembly, string type, string mode);

		[DispId(2)]
		[return: MarshalAs(UnmanagedType.IDispatch)]
		object CreateFromVroot(string VrootUrl, string Mode);

		[DispId(3)]
		[return: MarshalAs(UnmanagedType.IDispatch)]
		object CreateFromWsdl(string WsdlUrl, string Mode);

		[DispId(4)]
		[return: MarshalAs(UnmanagedType.IDispatch)]
		object CreateFromMailbox(string Mailbox, string Mode);
	}
	[Guid("ecabafd1-7f19-11d2-978e-0000f8757e2a")]
	public class ClrObjectFactory : IClrObjectFactory
	{
		private static Hashtable _htTypes = new Hashtable();

		public object CreateFromAssembly(string AssemblyName, string TypeName, string Mode)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				if (AssemblyName.StartsWith("System.EnterpriseServices", StringComparison.Ordinal))
				{
					return null;
				}
				string clientPhysicalPath = Publish.GetClientPhysicalPath(CreateDir: false);
				string text = clientPhysicalPath + TypeName + ".config";
				if (File.Exists(text))
				{
					lock (_htTypes)
					{
						if (!_htTypes.ContainsKey(text))
						{
							RemotingConfiguration.Configure(text, ensureSecurity: false);
							_htTypes.Add(text, text);
						}
					}
					Assembly assembly = Assembly.LoadWithPartialName(AssemblyName, null);
					if (assembly == null)
					{
						throw new COMException(Resource.FormatString("Err_ClassNotReg"), Util.REGDB_E_CLASSNOTREG);
					}
					object obj = assembly.CreateInstance(TypeName);
					if (obj == null)
					{
						throw new COMException(Resource.FormatString("Err_ClassNotReg"), Util.REGDB_E_CLASSNOTREG);
					}
					return obj;
				}
				throw new COMException(Resource.FormatString("Err_ClassNotReg"), Util.REGDB_E_CLASSNOTREG);
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ClrObjectFactory.CreateFromAssembly"));
				throw;
			}
		}

		private string Url2File(string InUrl)
		{
			string text = InUrl;
			text = text.Replace("/", "0");
			text = text.Replace(":", "1");
			text = text.Replace("?", "2");
			text = text.Replace("\\", "3");
			text = text.Replace(".", "4");
			text = text.Replace("\"", "5");
			text = text.Replace("'", "6");
			text = text.Replace(" ", "7");
			text = text.Replace(";", "8");
			text = text.Replace("=", "9");
			text = text.Replace("|", "A");
			text = text.Replace("<", "[");
			return text.Replace(">", "]");
		}

		public object CreateFromVroot(string VrootUrl, string Mode)
		{
			string wsdlUrl = VrootUrl + "?wsdl";
			return CreateFromWsdl(wsdlUrl, Mode);
		}

		public object CreateFromWsdl(string WsdlUrl, string Mode)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				string clientPhysicalPath = Publish.GetClientPhysicalPath(CreateDir: true);
				string typeName = "";
				string text = Url2File(WsdlUrl);
				if (text.Length + clientPhysicalPath.Length > 250)
				{
					text = text.Remove(0, text.Length + clientPhysicalPath.Length - 250);
				}
				string text2 = text + ".dll";
				if (!File.Exists(clientPhysicalPath + text2))
				{
					GenAssemblyFromWsdl genAssemblyFromWsdl = new GenAssemblyFromWsdl();
					genAssemblyFromWsdl.Run(WsdlUrl, text2, clientPhysicalPath);
				}
				Assembly assembly = Assembly.LoadFrom(clientPhysicalPath + text2);
				Type[] types = assembly.GetTypes();
				for (long num = 0L; num < types.GetLength(0); num++)
				{
					if (types[num].IsClass)
					{
						typeName = types[num].ToString();
					}
				}
				return assembly.CreateInstance(typeName);
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "ClrObjectFactory.CreateFromWsdl"));
				throw;
			}
		}

		public object CreateFromMailbox(string Mailbox, string Mode)
		{
			string text = Resource.FormatString("Soap_SmtpNotImplemented");
			ComSoapPublishError.Report(text);
			throw new COMException(text);
		}
	}
	internal sealed class NativeMethods
	{
		private NativeMethods()
		{
		}

		[DllImport("KERNEL32", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CloseHandle(IntPtr Handle);

		[DllImport("ADVAPI32", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

		[DllImport("ADVAPI32", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);

		[DllImport("Kernel32", CharSet = CharSet.Auto)]
		internal static extern IntPtr GetCurrentThread();
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	internal sealed class SafeUserTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		internal SafeUserTokenHandle()
			: base(ownsHandle: true)
		{
		}

		internal SafeUserTokenHandle(IntPtr existingHandle, bool ownsHandle)
			: base(ownsHandle)
		{
			SetHandle(existingHandle);
		}

		protected override bool ReleaseHandle()
		{
			return NativeMethods.CloseHandle(handle);
		}
	}
	internal class GenAssemblyFromWsdl
	{
		private const uint TOKEN_IMPERSONATE = 4u;

		private string wsdlurl = "";

		private string filename = "";

		private string pathname = "";

		private Thread thisthread;

		private IntPtr threadtoken = IntPtr.Zero;

		private Exception SavedException;

		private bool ExceptionThrown;

		public GenAssemblyFromWsdl()
		{
			thisthread = new Thread(Generate);
		}

		public void Run(string WsdlUrl, string FileName, string PathName)
		{
			try
			{
				if (WsdlUrl.Length <= 0 || FileName.Length <= 0)
				{
					return;
				}
				wsdlurl = WsdlUrl;
				filename = PathName + FileName;
				pathname = PathName;
				if (!NativeMethods.OpenThreadToken(NativeMethods.GetCurrentThread(), 4u, OpenAsSelf: true, ref threadtoken) && Marshal.GetLastWin32Error() != Util.ERROR_NO_TOKEN)
				{
					throw new COMException(Resource.FormatString("Err_OpenThreadToken"), Marshal.GetHRForLastWin32Error());
				}
				SafeUserTokenHandle safeUserTokenHandle = null;
				try
				{
					safeUserTokenHandle = new SafeUserTokenHandle(System.EnterpriseServices.Thunk.Security.SuspendImpersonation(), ownsHandle: true);
					thisthread.Start();
				}
				finally
				{
					if (safeUserTokenHandle != null)
					{
						System.EnterpriseServices.Thunk.Security.ResumeImpersonation(safeUserTokenHandle.DangerousGetHandle());
						safeUserTokenHandle.Dispose();
					}
				}
				thisthread.Join();
				if (!ExceptionThrown)
				{
					return;
				}
				throw SavedException;
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "GenAssemblyFromWsdl.Run"));
				throw;
			}
		}

		public void Generate()
		{
			try
			{
				if (threadtoken != IntPtr.Zero && !NativeMethods.SetThreadToken(IntPtr.Zero, threadtoken))
				{
					throw new COMException(Resource.FormatString("Err_SetThreadToken"), Marshal.GetHRForLastWin32Error());
				}
				if (wsdlurl.Length > 0)
				{
					Stream stream = new MemoryStream();
					ArrayList outCodeStreamList = new ArrayList();
					MetaData.RetrieveSchemaFromUrlToStream(wsdlurl, stream);
					stream.Position = 0L;
					MetaData.ConvertSchemaStreamToCodeSourceStream(clientProxy: true, pathname, stream, outCodeStreamList);
					MetaData.ConvertCodeSourceStreamToAssemblyFile(outCodeStreamList, filename, null);
				}
			}
			catch (Exception ex)
			{
				ComSoapPublishError.Report(ex.ToString());
				SavedException = ex;
				ExceptionThrown = true;
			}
			catch
			{
				string text = Resource.FormatString("Err_NonClsException", "GenAssemblyFromWsdl.Generate");
				ComSoapPublishError.Report(text);
				SavedException = new RegistrationException(text);
				ExceptionThrown = true;
				throw;
			}
		}
	}
}
namespace System.EnterpriseServices
{
	internal sealed class RWHashTable
	{
		private Hashtable _hashtable;

		private ReaderWriterLock _rwlock;

		public RWHashTable()
		{
			_hashtable = new Hashtable();
			_rwlock = new ReaderWriterLock();
		}

		public object Get(object o)
		{
			try
			{
				_rwlock.AcquireReaderLock(-1);
				return _hashtable[o];
			}
			finally
			{
				_rwlock.ReleaseReaderLock();
			}
		}

		public void Put(object key, object val)
		{
			try
			{
				_rwlock.AcquireWriterLock(-1);
				_hashtable[key] = val;
			}
			finally
			{
				_rwlock.ReleaseWriterLock();
			}
		}
	}
	internal sealed class RWHashTableEx
	{
		internal class RWTableEntry
		{
			internal object _realObject;

			public RWTableEntry(object o)
			{
				_realObject = o;
			}
		}

		private Hashtable _hashtable;

		private ReaderWriterLock _rwlock;

		public RWHashTableEx()
		{
			_hashtable = new Hashtable();
			_rwlock = new ReaderWriterLock();
		}

		public object Get(object o, out bool bFound)
		{
			bFound = false;
			try
			{
				_rwlock.AcquireReaderLock(-1);
				object obj = _hashtable[o];
				if (obj != null)
				{
					bFound = true;
					return ((RWTableEntry)obj)._realObject;
				}
				return null;
			}
			finally
			{
				_rwlock.ReleaseReaderLock();
			}
		}

		public void Put(object key, object val)
		{
			RWTableEntry value = new RWTableEntry(val);
			try
			{
				_rwlock.AcquireWriterLock(-1);
				_hashtable[key] = value;
			}
			finally
			{
				_rwlock.ReleaseWriterLock();
			}
		}
	}
	[Serializable]
	[ComVisible(false)]
	public enum ThreadPoolOption
	{
		None,
		Inherit,
		STA,
		MTA
	}
	[Serializable]
	[ComVisible(false)]
	public enum TransactionStatus
	{
		Commited,
		LocallyOk,
		NoTransaction,
		Aborting,
		Aborted
	}
	[Serializable]
	[ComVisible(false)]
	public enum InheritanceOption
	{
		Inherit,
		Ignore
	}
	[Serializable]
	[ComVisible(false)]
	public enum BindingOption
	{
		NoBinding,
		BindingToPoolThread
	}
	[Serializable]
	[ComVisible(false)]
	public enum SxsOption
	{
		Ignore,
		Inherit,
		New
	}
	[Serializable]
	[ComVisible(false)]
	public enum PartitionOption
	{
		Ignore,
		Inherit,
		New
	}
	[ComVisible(false)]
	public sealed class ServiceConfig
	{
		private System.EnterpriseServices.Thunk.ServiceConfigThunk m_sct;

		private ThreadPoolOption m_thrpool;

		private InheritanceOption m_inheritance;

		private BindingOption m_binding;

		private TransactionOption m_txn;

		private TransactionIsolationLevel m_txniso;

		private int m_timeout;

		private string m_strTipUrl;

		private string m_strTxDesc;

		private ITransaction m_txnByot;

		private TransactionProxy m_txnProxyByot;

		private SynchronizationOption m_sync;

		private bool m_bIISIntrinsics;

		private bool m_bComTIIntrinsics;

		private bool m_bTracker;

		private string m_strTrackerAppName;

		private string m_strTrackerCompName;

		private SxsOption m_sxs;

		private string m_strSxsDirectory;

		private string m_strSxsName;

		private PartitionOption m_part;

		private Guid m_guidPart;

		public ThreadPoolOption ThreadPool
		{
			get
			{
				return m_thrpool;
			}
			set
			{
				m_sct.ThreadPool = (int)value;
				m_thrpool = value;
			}
		}

		public InheritanceOption Inheritance
		{
			get
			{
				return m_inheritance;
			}
			set
			{
				m_sct.Inheritance = (int)value;
				m_inheritance = value;
				switch (value)
				{
				case InheritanceOption.Inherit:
					m_thrpool = ThreadPoolOption.Inherit;
					m_txn = TransactionOption.Supported;
					m_sync = SynchronizationOption.Supported;
					m_bIISIntrinsics = true;
					m_bComTIIntrinsics = true;
					m_sxs = SxsOption.Inherit;
					m_part = PartitionOption.Inherit;
					break;
				case InheritanceOption.Ignore:
					m_thrpool = ThreadPoolOption.None;
					m_txn = TransactionOption.Disabled;
					m_sync = SynchronizationOption.Disabled;
					m_bIISIntrinsics = false;
					m_bComTIIntrinsics = false;
					m_sxs = SxsOption.Ignore;
					m_part = PartitionOption.Ignore;
					break;
				default:
					throw new ArgumentException(Resource.FormatString("Err_value"));
				}
			}
		}

		public BindingOption Binding
		{
			get
			{
				return m_binding;
			}
			set
			{
				m_sct.Binding = (int)value;
				m_binding = value;
			}
		}

		public TransactionOption Transaction
		{
			get
			{
				return m_txn;
			}
			set
			{
				m_sct.Transaction = (int)value;
				m_txn = value;
			}
		}

		public TransactionIsolationLevel IsolationLevel
		{
			get
			{
				return m_txniso;
			}
			set
			{
				m_sct.TxIsolationLevel = (int)value;
				m_txniso = value;
			}
		}

		public int TransactionTimeout
		{
			get
			{
				return m_timeout;
			}
			set
			{
				m_sct.TxTimeout = value;
				m_timeout = value;
			}
		}

		public string TipUrl
		{
			get
			{
				return m_strTipUrl;
			}
			set
			{
				m_sct.TipUrl = value;
				m_strTipUrl = value;
			}
		}

		public string TransactionDescription
		{
			get
			{
				return m_strTxDesc;
			}
			set
			{
				m_sct.TxDesc = value;
				m_strTxDesc = value;
			}
		}

		public ITransaction BringYourOwnTransaction
		{
			get
			{
				return m_txnByot;
			}
			set
			{
				m_sct.Byot = value;
				m_txnByot = value;
			}
		}

		public Transaction BringYourOwnSystemTransaction
		{
			get
			{
				if (m_txnByot != null)
				{
					return TransactionInterop.GetTransactionFromDtcTransaction(m_txnByot as IDtcTransaction);
				}
				if (m_txnProxyByot != null)
				{
					return m_txnProxyByot.SystemTransaction;
				}
				return null;
			}
			set
			{
				if (!m_sct.SupportsSysTxn)
				{
					m_txnByot = (ITransaction)TransactionInterop.GetDtcTransaction(value);
					m_sct.Byot = m_txnByot;
					m_txnProxyByot = null;
					return;
				}
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				m_txnByot = null;
				m_txnProxyByot = new TransactionProxy(value);
				m_sct.ByotSysTxn = m_txnProxyByot;
			}
		}

		public SynchronizationOption Synchronization
		{
			get
			{
				return m_sync;
			}
			set
			{
				m_sct.Synchronization = (int)value;
				m_sync = value;
			}
		}

		public bool IISIntrinsicsEnabled
		{
			get
			{
				return m_bIISIntrinsics;
			}
			set
			{
				m_sct.IISIntrinsics = value;
				m_bIISIntrinsics = value;
			}
		}

		public bool COMTIIntrinsicsEnabled
		{
			get
			{
				return m_bComTIIntrinsics;
			}
			set
			{
				m_sct.COMTIIntrinsics = value;
				m_bComTIIntrinsics = value;
			}
		}

		public bool TrackingEnabled
		{
			get
			{
				return m_bTracker;
			}
			set
			{
				m_sct.Tracker = value;
				m_bTracker = value;
			}
		}

		public string TrackingAppName
		{
			get
			{
				return m_strTrackerAppName;
			}
			set
			{
				m_sct.TrackerAppName = value;
				m_strTrackerAppName = value;
			}
		}

		public string TrackingComponentName
		{
			get
			{
				return m_strTrackerCompName;
			}
			set
			{
				m_sct.TrackerCtxName = value;
				m_strTrackerCompName = value;
			}
		}

		public SxsOption SxsOption
		{
			get
			{
				return m_sxs;
			}
			set
			{
				m_sct.Sxs = (int)value;
				m_sxs = value;
			}
		}

		public string SxsDirectory
		{
			get
			{
				return m_strSxsDirectory;
			}
			set
			{
				m_sct.SxsDirectory = value;
				m_strSxsDirectory = value;
			}
		}

		public string SxsName
		{
			get
			{
				return m_strSxsName;
			}
			set
			{
				m_sct.SxsName = value;
				m_strSxsName = value;
			}
		}

		public PartitionOption PartitionOption
		{
			get
			{
				return m_part;
			}
			set
			{
				m_sct.Partition = (int)value;
				m_part = value;
			}
		}

		public Guid PartitionId
		{
			get
			{
				return m_guidPart;
			}
			set
			{
				m_sct.PartitionId = value;
				m_guidPart = value;
			}
		}

		internal System.EnterpriseServices.Thunk.ServiceConfigThunk SCT => m_sct;

		private void Init()
		{
			m_sct = new System.EnterpriseServices.Thunk.ServiceConfigThunk();
		}

		public ServiceConfig()
		{
			Platform.Assert(Platform.Supports(PlatformFeature.SWC), "ServiceConfig");
			Init();
		}
	}
	[ComVisible(false)]
	public sealed class ServiceDomain
	{
		private const int S_OK = 0;

		private const int XACT_S_LOCALLY_OK = 315402;

		private const int XACT_E_NOTRANSACTION = -2147168242;

		private const int XACT_E_ABORTING = -2147168215;

		private const int XACT_E_ABORTED = -2147168231;

		private ServiceDomain()
		{
		}

		public static void Enter(ServiceConfig cfg)
		{
			Platform.Assert(Platform.Supports(PlatformFeature.SWC), "ServiceDomain");
			System.EnterpriseServices.Thunk.ServiceDomainThunk.EnterServiceDomain(cfg.SCT);
		}

		public static TransactionStatus Leave()
		{
			Platform.Assert(Platform.Supports(PlatformFeature.SWC), "ServiceDomain");
			int num = System.EnterpriseServices.Thunk.ServiceDomainThunk.LeaveServiceDomain();
			switch (num)
			{
			case 0:
				return TransactionStatus.Commited;
			case 315402:
				return TransactionStatus.LocallyOk;
			case -2147168242:
				return TransactionStatus.NoTransaction;
			case -2147168215:
				return TransactionStatus.Aborting;
			case -2147168231:
				return TransactionStatus.Aborted;
			default:
				Marshal.ThrowExceptionForHR(num);
				return TransactionStatus.Commited;
			}
		}
	}
	[ComImport]
	[Guid("BD3E2E12-42DD-40f4-A09A-95A50C58304B")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IServiceCall
	{
		void OnCall();
	}
	[ComImport]
	[Guid("FE6777FB-A674-4177-8F32-6D707E113484")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IAsyncErrorNotify
	{
		void OnError(int hresult);
	}
	[ComVisible(false)]
	public sealed class Activity
	{
		private System.EnterpriseServices.Thunk.ServiceActivityThunk m_sat;

		public Activity(ServiceConfig cfg)
		{
			Platform.Assert(Platform.Supports(PlatformFeature.SWC), "Activity");
			m_sat = new System.EnterpriseServices.Thunk.ServiceActivityThunk(cfg.SCT);
		}

		public void SynchronousCall(IServiceCall serviceCall)
		{
			m_sat.SynchronousCall(serviceCall);
		}

		public void AsynchronousCall(IServiceCall serviceCall)
		{
			m_sat.AsynchronousCall(serviceCall);
		}

		public void BindToCurrentThread()
		{
			m_sat.BindToCurrentThread();
		}

		public void UnbindFromThread()
		{
			m_sat.UnbindFromThread();
		}
	}
}
namespace System.EnterpriseServices.Internal
{
	[Guid("A31B6577-71D2-4344-AEDF-ADC1B0DC5347")]
	public interface ISoapServerVRoot
	{
		[DispId(1)]
		void CreateVirtualRootEx([MarshalAs(UnmanagedType.BStr)] string rootWebServer, [MarshalAs(UnmanagedType.BStr)] string inBaseUrl, [MarshalAs(UnmanagedType.BStr)] string inVirtualRoot, [MarshalAs(UnmanagedType.BStr)] string homePage, [MarshalAs(UnmanagedType.BStr)] string discoFile, [MarshalAs(UnmanagedType.BStr)] string secureSockets, [MarshalAs(UnmanagedType.BStr)] string authentication, [MarshalAs(UnmanagedType.BStr)] string operation, [MarshalAs(UnmanagedType.BStr)] out string baseUrl, [MarshalAs(UnmanagedType.BStr)] out string virtualRoot, [MarshalAs(UnmanagedType.BStr)] out string physicalPath);

		[DispId(2)]
		void DeleteVirtualRootEx([MarshalAs(UnmanagedType.BStr)] string rootWebServer, [MarshalAs(UnmanagedType.BStr)] string baseUrl, [MarshalAs(UnmanagedType.BStr)] string virtualRoot);

		[DispId(3)]
		void GetVirtualRootStatus([MarshalAs(UnmanagedType.BStr)] string rootWebServer, [MarshalAs(UnmanagedType.BStr)] string inBaseUrl, [MarshalAs(UnmanagedType.BStr)] string inVirtualRoot, [MarshalAs(UnmanagedType.BStr)] out string exists, [MarshalAs(UnmanagedType.BStr)] out string secureSockets, [MarshalAs(UnmanagedType.BStr)] out string windowsAuth, [MarshalAs(UnmanagedType.BStr)] out string anonymous, [MarshalAs(UnmanagedType.BStr)] out string homePage, [MarshalAs(UnmanagedType.BStr)] out string discoFile, [MarshalAs(UnmanagedType.BStr)] out string physicalPath, [MarshalAs(UnmanagedType.BStr)] out string baseUrl, [MarshalAs(UnmanagedType.BStr)] out string virtualRoot);
	}
	[Guid("CAA817CC-0C04-4d22-A05C-2B7E162F4E8F")]
	public sealed class SoapServerVRoot : ISoapServerVRoot
	{
		public void CreateVirtualRootEx(string rootWebServer, string inBaseUrl, string inVirtualRoot, string homePage, string discoFile, string secureSockets, string authentication, string operation, out string baseUrl, out string virtualRoot, out string physicalPath)
		{
			baseUrl = "";
			virtualRoot = "";
			physicalPath = "";
			bool inDefault = true;
			bool windowsAuth = true;
			bool anonymous = false;
			bool inDefault2 = false;
			bool inDefault3 = false;
			bool impersonate = true;
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				Platform.Assert(Platform.Whistler, "SoapServerVRoot.CreateVirtualRootEx");
				if (inBaseUrl.Length <= 0 && inVirtualRoot.Length <= 0)
				{
					return;
				}
				string text = "IIS://localhost/W3SVC/1/ROOT";
				if (rootWebServer.Length > 0)
				{
					text = rootWebServer;
				}
				if (authentication.ToLower(CultureInfo.InvariantCulture) == "anonymous")
				{
					anonymous = true;
					windowsAuth = false;
					impersonate = false;
				}
				inDefault2 = SoapServerInfo.BoolFromString(discoFile, inDefault2);
				inDefault3 = SoapServerInfo.BoolFromString(homePage, inDefault3);
				inDefault = SoapServerInfo.BoolFromString(secureSockets, inDefault);
				string inProtocol = "https";
				if (!inDefault)
				{
					inProtocol = "http";
				}
				SoapServerInfo.CheckUrl(inBaseUrl, inVirtualRoot, inProtocol);
				SoapServerInfo.ParseUrl(inBaseUrl, inVirtualRoot, inProtocol, out baseUrl, out virtualRoot);
				physicalPath = SoapServerInfo.ServerPhysicalPath(text, inBaseUrl, inVirtualRoot, createDir: true);
				SoapServerConfig.Create(physicalPath, impersonate, windowsAuth);
				if (inDefault2)
				{
					DiscoFile discoFile2 = new DiscoFile();
					discoFile2.Create(physicalPath, "Default.disco");
				}
				else if (File.Exists(physicalPath + "\\Default.disco"))
				{
					File.Delete(physicalPath + "\\Default.disco");
				}
				if (inDefault3)
				{
					HomePage homePage2 = new HomePage();
					string discoRef = "";
					if (inDefault2)
					{
						discoRef = "Default.disco";
					}
					homePage2.Create(physicalPath, virtualRoot, "Default.aspx", discoRef);
				}
				else if (File.Exists(physicalPath + "\\Default.aspx"))
				{
					File.Delete(physicalPath + "\\Default.aspx");
				}
				IISVirtualRootEx.CreateOrModify(text, physicalPath, virtualRoot, inDefault, windowsAuth, anonymous, inDefault3);
			}
			catch
			{
				string text2 = Resource.FormatString("Soap_VRootCreationFailed");
				ComSoapPublishError.Report(text2 + " " + virtualRoot);
				throw;
			}
		}

		public void DeleteVirtualRootEx(string rootWebServer, string inBaseUrl, string inVirtualRoot)
		{
			try
			{
				try
				{
					SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
					securityPermission.Demand();
				}
				catch (SecurityException)
				{
					string s = Resource.FormatString("Soap_SecurityFailure");
					ComSoapPublishError.Report(s);
					throw;
				}
				Platform.Assert(Platform.Whistler, "SoapServerVRoot.DeleteVirtualRootEx");
				if (inBaseUrl.Length > 0 || inVirtualRoot.Length > 0)
				{
					_ = rootWebServer.Length;
					_ = 0;
					string inProtocol = "";
					string baseUrl = "";
					string virtualRoot = "";
					SoapServerInfo.ParseUrl(inBaseUrl, inVirtualRoot, inProtocol, out baseUrl, out virtualRoot);
				}
			}
			catch
			{
				string s2 = Resource.FormatString("Soap_VRootDirectoryDeletionFailed");
				ComSoapPublishError.Report(s2);
				throw;
			}
		}

		public void GetVirtualRootStatus(string RootWebServer, string inBaseUrl, string inVirtualRoot, out string Exists, out string SSL, out string WindowsAuth, out string Anonymous, out string HomePage, out string DiscoFile, out string PhysicalPath, out string BaseUrl, out string VirtualRoot)
		{
			string text = "IIS://localhost/W3SVC/1/ROOT";
			if (RootWebServer.Length > 0)
			{
				text = RootWebServer;
			}
			Exists = "false";
			SSL = "false";
			WindowsAuth = "false";
			Anonymous = "false";
			HomePage = "false";
			DiscoFile = "false";
			SoapServerInfo.ParseUrl(inBaseUrl, inVirtualRoot, "http", out BaseUrl, out VirtualRoot);
			PhysicalPath = SoapServerInfo.ServerPhysicalPath(text, BaseUrl, VirtualRoot, createDir: false);
			bool bExists = false;
			bool bSSL = false;
			bool bWindowsAuth = false;
			bool bAnonymous = false;
			bool bHomePage = false;
			bool bDiscoFile = false;
			IISVirtualRootEx.GetStatus(text, PhysicalPath, VirtualRoot, out bExists, out bSSL, out bWindowsAuth, out bAnonymous, out bHomePage, out bDiscoFile);
			if (bExists)
			{
				Exists = "true";
			}
			if (bSSL)
			{
				SSL = "true";
				SoapServerInfo.ParseUrl(inBaseUrl, inVirtualRoot, "https", out BaseUrl, out VirtualRoot);
			}
			if (bWindowsAuth)
			{
				WindowsAuth = "true";
			}
			if (bAnonymous)
			{
				Anonymous = "true";
			}
			if (bHomePage)
			{
				HomePage = "true";
			}
			if (bDiscoFile)
			{
				DiscoFile = "true";
			}
		}
	}
	internal static class IISVirtualRootEx
	{
		private const uint MD_ACCESS_SSL = 8u;

		private const uint MD_AUTH_ANONYMOUS = 1u;

		private const uint MD_AUTH_NT = 4u;

		private const uint MD_DIRBROW_NONE = 0u;

		private const uint MD_DIRBROW_LOADDEFAULT = 1073741854u;

		private const uint MD_ACCESS_READ = 1u;

		private const uint MD_ACCESS_SCRIPT = 512u;

		private const int POOLED = 2;

		internal static bool CheckIfExists(string rootWeb, string virtualDirectory)
		{
			DirectoryEntry directoryEntry = new DirectoryEntry(rootWeb + "/" + virtualDirectory);
			try
			{
				_ = directoryEntry.Name;
			}
			catch
			{
				return false;
			}
			return true;
		}

		internal static void GetStatus(string RootWeb, string PhysicalPath, string VirtualDirectory, out bool bExists, out bool bSSL, out bool bWindowsAuth, out bool bAnonymous, out bool bHomePage, out bool bDiscoFile)
		{
			bSSL = false;
			bWindowsAuth = false;
			bAnonymous = false;
			bHomePage = false;
			bDiscoFile = false;
			bExists = CheckIfExists(RootWeb, VirtualDirectory);
			if (!bExists)
			{
				return;
			}
			DirectoryEntry directoryEntry = new DirectoryEntry(RootWeb);
			if (directoryEntry == null)
			{
				return;
			}
			DirectoryEntry directoryEntry2 = directoryEntry.Children.Find(VirtualDirectory, "IIsWebVirtualDir");
			if (directoryEntry2 != null)
			{
				uint num = uint.Parse(directoryEntry2.Properties["AccessSSLFlags"][0].ToString(), CultureInfo.InvariantCulture);
				if ((num & 8u) != 0)
				{
					bSSL = true;
				}
				uint num2 = uint.Parse(directoryEntry2.Properties["AuthFlags"][0].ToString(), CultureInfo.InvariantCulture);
				if ((num2 & (true ? 1u : 0u)) != 0)
				{
					bAnonymous = true;
				}
				if ((num2 & 4u) != 0)
				{
					bWindowsAuth = true;
				}
				bHomePage = (bool)directoryEntry2.Properties["EnableDefaultDoc"][0];
				if (File.Exists(PhysicalPath + "\\default.disco"))
				{
					bDiscoFile = true;
				}
			}
		}

		internal static void CreateOrModify(string rootWeb, string inPhysicalDirectory, string virtualDirectory, bool secureSockets, bool windowsAuth, bool anonymous, bool homePage)
		{
			string text = inPhysicalDirectory;
			while (text.EndsWith("/", StringComparison.Ordinal) || text.EndsWith("\\", StringComparison.Ordinal))
			{
				text = text.Remove(text.Length - 1, 1);
			}
			bool flag = CheckIfExists(rootWeb, virtualDirectory);
			DirectoryEntry directoryEntry = new DirectoryEntry(rootWeb);
			DirectoryEntry directoryEntry2 = null;
			directoryEntry2 = ((!flag) ? directoryEntry.Children.Add(virtualDirectory, "IIsWebVirtualDir") : directoryEntry.Children.Find(virtualDirectory, "IIsWebVirtualDir"));
			if (directoryEntry2 == null)
			{
				throw new ServicedComponentException(Resource.FormatString("Soap_VRootCreationFailed"));
			}
			directoryEntry2.CommitChanges();
			directoryEntry2.Properties["Path"][0] = text;
			if (secureSockets)
			{
				uint num = uint.Parse(directoryEntry2.Properties["AccessSSLFlags"][0].ToString(), CultureInfo.InvariantCulture);
				num |= 8u;
				directoryEntry2.Properties["AccessSSLFlags"][0] = num;
			}
			uint num2 = uint.Parse(directoryEntry2.Properties["AuthFlags"][0].ToString(), CultureInfo.InvariantCulture);
			if (!flag && anonymous)
			{
				num2 |= 1u;
			}
			if (windowsAuth)
			{
				num2 = 4u;
			}
			directoryEntry2.Properties["AuthFlags"][0] = num2;
			directoryEntry2.Properties["EnableDefaultDoc"][0] = homePage;
			if (secureSockets && windowsAuth && !anonymous)
			{
				directoryEntry2.Properties["DirBrowseFlags"][0] = 0u;
			}
			else if (!flag)
			{
				directoryEntry2.Properties["DirBrowseFlags"][0] = 1073741854u;
			}
			directoryEntry2.Properties["AccessFlags"][0] = 513u;
			directoryEntry2.Properties["AppFriendlyName"][0] = virtualDirectory;
			directoryEntry2.CommitChanges();
			directoryEntry2.Invoke("AppCreate2", 2);
		}
	}
	internal static class SoapServerConfig
	{
		internal static bool Create(string inFilePath, bool impersonate, bool windowsAuth)
		{
			string text = inFilePath;
			if (text.Length <= 0)
			{
				return false;
			}
			if (!text.EndsWith("/", StringComparison.Ordinal) && !text.EndsWith("\\", StringComparison.Ordinal))
			{
				text += "\\";
			}
			string text2 = text + "web.config";
			if (!File.Exists(text2))
			{
				XmlTextWriter xmlTextWriter = new XmlTextWriter(text2, new UTF8Encoding());
				xmlTextWriter.Formatting = Formatting.Indented;
				xmlTextWriter.WriteStartDocument();
				xmlTextWriter.WriteStartElement("configuration");
				xmlTextWriter.Flush();
				xmlTextWriter.Close();
			}
			return ChangeSecuritySettings(text2, impersonate, windowsAuth);
		}

		internal static XmlElement FindOrCreateElement(XmlDocument configXml, XmlNode node, string elemName)
		{
			XmlElement xmlElement = null;
			XmlNodeList xmlNodeList = node.SelectNodes(elemName);
			if (xmlNodeList.Count == 0)
			{
				XmlElement xmlElement2 = configXml.CreateElement(elemName);
				node.AppendChild(xmlElement2);
				return xmlElement2;
			}
			return (XmlElement)xmlNodeList[0];
		}

		internal static bool UpdateChannels(XmlDocument configXml)
		{
			XmlNode documentElement = configXml.DocumentElement;
			XmlElement node = FindOrCreateElement(configXml, documentElement, "system.runtime.remoting");
			node = FindOrCreateElement(configXml, node, "application");
			node = FindOrCreateElement(configXml, node, "channels");
			node = FindOrCreateElement(configXml, node, "channel");
			node.SetAttribute("ref", "http server");
			return true;
		}

		internal static bool UpdateSystemWeb(XmlDocument configXml, bool impersonate, bool authentication)
		{
			XmlNode documentElement = configXml.DocumentElement;
			XmlElement node = FindOrCreateElement(configXml, documentElement, "system.web");
			if (impersonate)
			{
				XmlElement xmlElement = FindOrCreateElement(configXml, node, "identity");
				xmlElement.SetAttribute("impersonate", "true");
			}
			if (authentication)
			{
				XmlElement xmlElement2 = FindOrCreateElement(configXml, node, "authentication");
				xmlElement2.SetAttribute("mode", "Windows");
			}
			return true;
		}

		internal static bool ChangeSecuritySettings(string fileName, bool impersonate, bool authentication)
		{
			if (!File.Exists(fileName))
			{
				return false;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.Load(fileName);
			bool flag = UpdateChannels(xmlDocument);
			if (flag)
			{
				flag = UpdateSystemWeb(xmlDocument, impersonate, authentication);
				try
				{
					if (flag)
					{
						xmlDocument.Save(fileName);
					}
				}
				catch
				{
					string s = Resource.FormatString("Soap_WebConfigFailed");
					ComSoapPublishError.Report(s);
					throw;
				}
			}
			if (!flag)
			{
				string s2 = Resource.FormatString("Soap_WebConfigFailed");
				ComSoapPublishError.Report(s2);
			}
			return flag;
		}

		internal static void AddComponent(string filePath, string assemblyName, string typeName, string progId, string assemblyFile, string wkoMode, bool wellKnown, bool clientActivated)
		{
			try
			{
				AssemblyManager assemblyManager = new AssemblyManager();
				string text = typeName + ", " + assemblyManager.GetFullName(assemblyFile, assemblyName);
				string text2 = typeName + ", " + assemblyName;
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(filePath);
				XmlNode documentElement = xmlDocument.DocumentElement;
				documentElement = FindOrCreateElement(xmlDocument, documentElement, "system.runtime.remoting");
				documentElement = FindOrCreateElement(xmlDocument, documentElement, "application");
				documentElement = FindOrCreateElement(xmlDocument, documentElement, "service");
				XmlNodeList xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode = xmlNodeList.Item(0);
					if (xmlNode.ParentNode != null)
					{
						xmlNode.ParentNode.RemoveChild(xmlNode);
						xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
					}
				}
				xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode2 = xmlNodeList.Item(0);
					if (xmlNode2.ParentNode != null)
					{
						xmlNode2.ParentNode.RemoveChild(xmlNode2);
						xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text + "']");
					}
				}
				if (wellKnown)
				{
					XmlElement xmlElement = xmlDocument.CreateElement("wellknown");
					xmlElement.SetAttribute("mode", wkoMode);
					xmlElement.SetAttribute("type", text);
					xmlElement.SetAttribute("objectUri", progId + ".soap");
					documentElement.AppendChild(xmlElement);
				}
				if (clientActivated)
				{
					XmlElement xmlElement2 = xmlDocument.CreateElement("activated");
					xmlElement2.SetAttribute("type", text2);
					documentElement.AppendChild(xmlElement2);
				}
				xmlDocument.Save(filePath);
			}
			catch (Exception ex)
			{
				string text3 = Resource.FormatString("Soap_ConfigAdditionFailure");
				ComSoapPublishError.Report(text3 + " " + ex.Message);
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "SoapServerConfig.AddComponent"));
				throw;
			}
		}

		internal static void DeleteComponent(string filePath, string assemblyName, string typeName, string progId, string assemblyFile)
		{
			try
			{
				AssemblyManager assemblyManager = new AssemblyManager();
				string text = typeName + ", " + assemblyManager.GetFullName(assemblyFile, assemblyName);
				string text2 = typeName + ", " + assemblyName;
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(filePath);
				XmlNode documentElement = xmlDocument.DocumentElement;
				documentElement = FindOrCreateElement(xmlDocument, documentElement, "system.runtime.remoting");
				documentElement = FindOrCreateElement(xmlDocument, documentElement, "application");
				documentElement = FindOrCreateElement(xmlDocument, documentElement, "service");
				XmlNodeList xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode = xmlNodeList.Item(0);
					if (xmlNode.ParentNode != null)
					{
						xmlNode.ParentNode.RemoveChild(xmlNode);
						xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text2 + "']");
					}
				}
				xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text + "']");
				while (xmlNodeList != null && xmlNodeList.Count > 0)
				{
					XmlNode xmlNode2 = xmlNodeList.Item(0);
					if (xmlNode2.ParentNode != null)
					{
						xmlNode2.ParentNode.RemoveChild(xmlNode2);
						xmlNodeList = documentElement.SelectNodes("descendant::*[attribute::type='" + text + "']");
					}
				}
				xmlDocument.Save(filePath);
			}
			catch (DirectoryNotFoundException)
			{
			}
			catch (FileNotFoundException)
			{
			}
			catch (RegistrationException)
			{
			}
			catch (Exception ex4)
			{
				string text3 = Resource.FormatString("Soap_ConfigDeletionFailure");
				ComSoapPublishError.Report(text3 + " " + ex4.Message);
				throw;
			}
			catch
			{
				ComSoapPublishError.Report(Resource.FormatString("Err_NonClsException", "SoapServerConfig.DeleteComponent"));
				throw;
			}
		}
	}
	[Guid("E7F0F021-9201-47e4-94DA-1D1416DEC27A")]
	public interface ISoapClientImport
	{
		[DispId(1)]
		void ProcessClientTlbEx([MarshalAs(UnmanagedType.BStr)] string progId, [MarshalAs(UnmanagedType.BStr)] string virtualRoot, [MarshalAs(UnmanagedType.BStr)] string baseUrl, [MarshalAs(UnmanagedType.BStr)] string authentication, [MarshalAs(UnmanagedType.BStr)] string assemblyName, [MarshalAs(UnmanagedType.BStr)] string typeName);
	}
	[Guid("346D5B9F-45E1-45c0-AADF-1B7D221E9063")]
	public sealed class SoapClientImport : ISoapClientImport
	{
		public void ProcessClientTlbEx(string progId, string virtualRoot, string baseUrl, string authentication, string assemblyName, string typeName)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
			}
			catch (SecurityException)
			{
				ComSoapPublishError.Report(Resource.FormatString("Soap_SecurityFailure"));
				throw;
			}
			try
			{
				Platform.Assert(Platform.Whistler, "SoapClientImport.ProcessClientTlbEx");
				string clientPhysicalPath = GetClientPhysicalPath(createDir: true);
				if (progId.Length > 0)
				{
					Uri baseUri = new Uri(baseUrl);
					Uri uri = new Uri(baseUri, virtualRoot);
					string text = authentication;
					if (text.Length <= 0 && uri.Scheme.ToLower(CultureInfo.InvariantCulture) == "https")
					{
						text = "Windows";
					}
					SoapClientConfig.Write(clientPhysicalPath, uri.AbsoluteUri, assemblyName, typeName, progId, text);
				}
			}
			catch
			{
				string s = Resource.FormatString("Soap_ClientConfigAddFailure");
				ComSoapPublishError.Report(s);
				throw;
			}
		}

		internal static string GetClientPhysicalPath(bool createDir)
		{
			uint num = 1024u;
			StringBuilder stringBuilder = new StringBuilder((int)num, (int)num);
			if (GetSystemDirectory(stringBuilder, num) == 0)
			{
				throw new ServicedComponentException(Resource.FormatString("Soap_GetSystemDirectoryFailure"));
			}
			string text = stringBuilder.ToString() + "\\com\\SOAPAssembly\\";
			if (createDir && !Directory.Exists(text))
			{
				Directory.CreateDirectory(text);
			}
			return text;
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		internal static extern uint GetSystemDirectory(StringBuilder lpBuf, uint uSize);
	}
	internal static class SoapClientConfig
	{
		internal static bool Write(string destinationDirectory, string fullUrl, string assemblyName, string typeName, string progId, string authentication)
		{
			bool flag = false;
			string text = "<configuration>\r\n";
			text += "  <system.runtime.remoting>\r\n";
			text += "    <application>\r\n";
			text = text + "      <client url=\"" + fullUrl + "\">\r\n";
			text += "        ";
			string text2 = text;
			text = text2 + "<activated type=\"" + typeName + ", " + assemblyName + "\"/>\r\n";
			text += "      </client>\r\n";
			if (authentication.ToLower(CultureInfo.InvariantCulture) == "windows")
			{
				text += "      <channels>\r\n";
				text += "        <channel ref=\"http\" useDefaultCredentials=\"true\" />\r\n";
				text += "      </channels>\r\n";
			}
			text += "    </application>\r\n";
			text += "  </system.runtime.remoting>\r\n";
			text += "</configuration>\r\n";
			string text3 = destinationDirectory;
			if (text3.Length > 0 && !text3.EndsWith("\\", StringComparison.Ordinal))
			{
				text3 += "\\";
			}
			text3 = text3 + typeName + ".config";
			if (File.Exists(text3))
			{
				File.Delete(text3);
			}
			FileStream fileStream = new FileStream(text3, FileMode.Create);
			StreamWriter streamWriter = new StreamWriter(fileStream);
			streamWriter.Write(text);
			streamWriter.Close();
			fileStream.Close();
			return true;
		}
	}
	[Guid("5AC4CB7E-F89F-429b-926B-C7F940936BF4")]
	public interface ISoapUtility
	{
		[DispId(1)]
		void GetServerPhysicalPath([MarshalAs(UnmanagedType.BStr)] string rootWebServer, [MarshalAs(UnmanagedType.BStr)] string inBaseUrl, [MarshalAs(UnmanagedType.BStr)] string inVirtualRoot, [MarshalAs(UnmanagedType.BStr)] out string physicalPath);

		[DispId(2)]
		void GetServerBinPath([MarshalAs(UnmanagedType.BStr)] string rootWebServer, [MarshalAs(UnmanagedType.BStr)] string inBaseUrl, [MarshalAs(UnmanagedType.BStr)] string inVirtualRoot, [MarshalAs(UnmanagedType.BStr)] out string binPath);

		[DispId(3)]
		void Present();
	}
	[Guid("5F9A955F-AA55-4127-A32B-33496AA8A44E")]
	public sealed class SoapUtility : ISoapUtility
	{
		public void GetServerPhysicalPath(string rootWebServer, string inBaseUrl, string inVirtualRoot, out string physicalPath)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				Platform.Assert(Platform.Whistler, "SoapUtility.GetServerPhysicalPath");
				physicalPath = SoapServerInfo.ServerPhysicalPath(rootWebServer, inBaseUrl, inVirtualRoot, createDir: false);
			}
			catch (SecurityException)
			{
				ComSoapPublishError.Report(Resource.FormatString("Soap_SecurityFailure"));
				throw;
			}
		}

		public void GetServerBinPath(string rootWebServer, string inBaseUrl, string inVirtualRoot, out string binPath)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				Platform.Assert(Platform.Whistler, "SoapUtility.GetServerBinPath");
				binPath = SoapServerInfo.ServerPhysicalPath(rootWebServer, inBaseUrl, inVirtualRoot, createDir: false) + "\\bin\\";
			}
			catch (SecurityException)
			{
				ComSoapPublishError.Report(Resource.FormatString("Soap_SecurityFailure"));
				throw;
			}
		}

		public void Present()
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
				Platform.Assert(Platform.Whistler, "SoapUtility.Present");
			}
			catch (SecurityException)
			{
				ComSoapPublishError.Report(Resource.FormatString("Soap_SecurityFailure"));
				throw;
			}
		}
	}
	internal class NonRootVRootException : Exception
	{
	}
	internal static class SoapServerInfo
	{
		internal static bool BoolFromString(string inVal, bool inDefault)
		{
			if (inVal == null)
			{
				return inDefault;
			}
			string text = inVal.ToLower(CultureInfo.InvariantCulture);
			bool result = inDefault;
			if (text == "true")
			{
				result = true;
			}
			if (text == "false")
			{
				result = false;
			}
			return result;
		}

		internal static string ServerPhysicalPath(string rootWebServer, string inBaseUrl, string inVirtualRoot, bool createDir)
		{
			string result = "";
			string baseUrl = "";
			string virtualRoot = "";
			ParseUrl(inBaseUrl, inVirtualRoot, "", out baseUrl, out virtualRoot);
			if (virtualRoot.Length <= 0)
			{
				return result;
			}
			StringBuilder stringBuilder = new StringBuilder(1024, 1024);
			uint uSize = 1024u;
			if (GetSystemDirectory(stringBuilder, uSize) == 0)
			{
				throw new ServicedComponentException(Resource.FormatString("Soap_GetSystemDirectoryFailure"));
			}
			if (stringBuilder.ToString().Length <= 0)
			{
				return result;
			}
			result = stringBuilder.ToString() + "\\com\\SoapVRoots\\" + virtualRoot;
			if (createDir)
			{
				string path = result + "\\bin";
				if (!Directory.Exists(path))
				{
					Directory.CreateDirectory(path);
				}
			}
			return result;
		}

		internal static void CheckUrl(string inBaseUrl, string inVirtualRoot, string inProtocol)
		{
			string text = inBaseUrl;
			if (text.Length <= 0)
			{
				text = inProtocol + "://";
				text += Dns.GetHostName();
				text += "/";
			}
			Uri uri = new Uri(text);
			int upperBound = uri.Segments.GetUpperBound(0);
			Uri uri2 = new Uri(uri, inVirtualRoot);
			if (uri2.Segments.GetUpperBound(0) > upperBound + 1)
			{
				throw new NonRootVRootException();
			}
		}

		internal static void ParseUrl(string inBaseUrl, string inVirtualRoot, string inProtocol, out string baseUrl, out string virtualRoot)
		{
			string text = "https";
			if (inProtocol.ToLower(CultureInfo.InvariantCulture) == "http")
			{
				text = inProtocol;
			}
			baseUrl = inBaseUrl;
			if (baseUrl.Length <= 0)
			{
				baseUrl = text + "://";
				baseUrl += Dns.GetHostName();
				baseUrl += "/";
			}
			Uri baseUri = new Uri(baseUrl);
			Uri uri = new Uri(baseUri, inVirtualRoot);
			if (uri.Scheme != text)
			{
				UriBuilder uriBuilder = new UriBuilder(uri.AbsoluteUri);
				uriBuilder.Scheme = text;
				if (text == "https" && uriBuilder.Port == 80)
				{
					uriBuilder.Port = 443;
				}
				if (text == "http" && uriBuilder.Port == 443)
				{
					uriBuilder.Port = 80;
				}
				uri = uriBuilder.Uri;
			}
			string[] segments = uri.Segments;
			virtualRoot = segments[segments.GetUpperBound(0)];
			baseUrl = uri.AbsoluteUri.Substring(0, uri.AbsoluteUri.Length - virtualRoot.Length);
			char[] trimChars = new char[1] { '/' };
			virtualRoot = virtualRoot.TrimEnd(trimChars);
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		internal static extern uint GetSystemDirectory(StringBuilder lpBuf, uint uSize);
	}
	[Guid("1E7BA9F7-21DB-4482-929E-21BDE2DFE51C")]
	public interface ISoapServerTlb
	{
		[DispId(1)]
		void AddServerTlb([MarshalAs(UnmanagedType.BStr)] string progId, [MarshalAs(UnmanagedType.BStr)] string classId, [MarshalAs(UnmanagedType.BStr)] string interfaceId, [MarshalAs(UnmanagedType.BStr)] string srcTlbPath, [MarshalAs(UnmanagedType.BStr)] string rootWebServer, [MarshalAs(UnmanagedType.BStr)] string baseUrl, [MarshalAs(UnmanagedType.BStr)] string virtualRoot, [MarshalAs(UnmanagedType.BStr)] string clientActivated, [MarshalAs(UnmanagedType.BStr)] string wellKnown, [MarshalAs(UnmanagedType.BStr)] string discoFile, [MarshalAs(UnmanagedType.BStr)] string operation, [MarshalAs(UnmanagedType.BStr)] out string assemblyName, [MarshalAs(UnmanagedType.BStr)] out string typeName);

		[DispId(2)]
		void DeleteServerTlb([MarshalAs(UnmanagedType.BStr)] string progId, [MarshalAs(UnmanagedType.BStr)] string classId, [MarshalAs(UnmanagedType.BStr)] string interfaceId, [MarshalAs(UnmanagedType.BStr)] string srcTlbPath, [MarshalAs(UnmanagedType.BStr)] string rootWebServer, [MarshalAs(UnmanagedType.BStr)] string baseUrl, [MarshalAs(UnmanagedType.BStr)] string virtualRoot, [MarshalAs(UnmanagedType.BStr)] string operation, [MarshalAs(UnmanagedType.BStr)] string assemblyName, [MarshalAs(UnmanagedType.BStr)] string typeName);
	}
	[Guid("F6B6768F-F99E-4152-8ED2-0412F78517FB")]
	public sealed class SoapServerTlb : ISoapServerTlb
	{
		public void AddServerTlb(string progId, string classId, string interfaceId, string srcTlbPath, string rootWebServer, string inBaseUrl, string inVirtualRoot, string clientActivated, string wellKnown, string discoFile, string operation, out string strAssemblyName, out string typeName)
		{
			strAssemblyName = "";
			typeName = "";
			bool flag = false;
			bool inDefault = false;
			bool inDefault2 = false;
			bool inDefault3 = true;
			try
			{
				try
				{
					SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
					securityPermission.Demand();
				}
				catch (SecurityException)
				{
					string s = Resource.FormatString("Soap_SecurityFailure");
					ComSoapPublishError.Report(s);
					throw;
				}
				Platform.Assert(Platform.Whistler, "SoapServerTlb.AddServerTlb");
				if (operation != null && operation.ToLower(CultureInfo.InvariantCulture) == "delete")
				{
					flag = true;
				}
				if (srcTlbPath.Length <= 0)
				{
					return;
				}
				inDefault = SoapServerInfo.BoolFromString(discoFile, inDefault);
				inDefault2 = SoapServerInfo.BoolFromString(wellKnown, inDefault2);
				inDefault3 = SoapServerInfo.BoolFromString(clientActivated, inDefault3);
				string text = SoapServerInfo.ServerPhysicalPath(rootWebServer, inBaseUrl, inVirtualRoot, !flag);
				string text2 = srcTlbPath.ToLower(CultureInfo.InvariantCulture);
				if (text2.EndsWith("mscoree.dll", StringComparison.Ordinal))
				{
					Type typeFromProgID = Type.GetTypeFromProgID(progId);
					typeName = typeFromProgID.FullName;
					strAssemblyName = typeFromProgID.Assembly.GetName().Name;
				}
				else if (text2.EndsWith("scrobj.dll", StringComparison.Ordinal))
				{
					if (!flag)
					{
						throw new ServicedComponentException(Resource.FormatString("ServicedComponentException_WSCNotSupported"));
					}
				}
				else
				{
					string Error = "";
					GenerateMetadata generateMetadata = new GenerateMetadata();
					if (flag)
					{
						strAssemblyName = generateMetadata.GetAssemblyName(srcTlbPath, text + "\\bin\\");
					}
					else
					{
						strAssemblyName = generateMetadata.GenerateSigned(srcTlbPath, text + "\\bin\\", InstallGac: false, out Error);
					}
					if (strAssemblyName.Length > 0)
					{
						try
						{
							typeName = GetTypeName(text + "\\bin\\" + strAssemblyName + ".dll", progId, classId);
						}
						catch (DirectoryNotFoundException)
						{
							if (!flag)
							{
								throw;
							}
						}
						catch (FileNotFoundException)
						{
							if (!flag)
							{
								throw;
							}
						}
					}
				}
				if (progId.Length <= 0 || strAssemblyName.Length <= 0 || typeName.Length <= 0)
				{
					return;
				}
				DiscoFile discoFile2 = new DiscoFile();
				string assemblyFile = text + "\\bin\\" + strAssemblyName + ".dll";
				if (flag)
				{
					SoapServerConfig.DeleteComponent(text + "\\Web.Config", strAssemblyName, typeName, progId, assemblyFile);
					discoFile2.DeleteElement(text + "\\Default.disco", progId + ".soap?WSDL");
					return;
				}
				SoapServerConfig.AddComponent(text + "\\Web.Config", strAssemblyName, typeName, progId, assemblyFile, "SingleCall", inDefault2, inDefault3);
				if (inDefault)
				{
					discoFile2.AddElement(text + "\\Default.disco", progId + ".soap?WSDL");
				}
			}
			catch (ServicedComponentException e)
			{
				ThrowHelper("Soap_PublishServerTlbFailure", e);
			}
			catch (RegistrationException e2)
			{
				ThrowHelper("Soap_PublishServerTlbFailure", e2);
			}
			catch
			{
				ThrowHelper("Soap_PublishServerTlbFailure", null);
			}
		}

		private void ThrowHelper(string messageId, Exception e)
		{
			string s = Resource.FormatString(messageId);
			ComSoapPublishError.Report(s);
			if (e != null)
			{
				throw e;
			}
		}

		public void DeleteServerTlb(string progId, string classId, string interfaceId, string srcTlbPath, string rootWebServer, string baseUrl, string virtualRoot, string operation, string assemblyName, string typeName)
		{
			try
			{
				SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
				securityPermission.Demand();
			}
			catch (SecurityException)
			{
				string s = Resource.FormatString("Soap_SecurityFailure");
				ComSoapPublishError.Report(s);
				throw;
			}
			Platform.Assert(Platform.Whistler, "SoapServerTlb.DeleteServerTlb");
			string text = assemblyName;
			if ((progId.Length <= 0 && classId.Length <= 0 && assemblyName.Length <= 0 && typeName.Length <= 0) || (baseUrl.Length <= 0 && virtualRoot.Length <= 0))
			{
				return;
			}
			string text2 = SoapServerInfo.ServerPhysicalPath(rootWebServer, baseUrl, virtualRoot, createDir: false);
			string text3 = srcTlbPath.ToLower(CultureInfo.InvariantCulture);
			if (text3.EndsWith("scrobj.dll", StringComparison.Ordinal))
			{
				return;
			}
			if (text3.EndsWith("mscoree.dll", StringComparison.Ordinal))
			{
				Type typeFromProgID = Type.GetTypeFromProgID(progId);
				typeName = typeFromProgID.FullName;
				text = typeFromProgID.Assembly.GetName().Name;
			}
			else
			{
				GenerateMetadata generateMetadata = new GenerateMetadata();
				text = generateMetadata.GetAssemblyName(srcTlbPath, text2 + "\\bin\\");
				if (text.Length > 0)
				{
					try
					{
						typeName = GetTypeName(text2 + "\\bin\\" + text + ".dll", progId, classId);
					}
					catch (DirectoryNotFoundException)
					{
					}
					catch (FileNotFoundException)
					{
					}
				}
			}
			if (progId.Length > 0 && text.Length > 0 && typeName.Length > 0)
			{
				DiscoFile discoFile = new DiscoFile();
				string assemblyFile = text2 + "\\bin\\" + text + ".dll";
				SoapServerConfig.DeleteComponent(text2 + "\\Web.Config", text, typeName, progId, assemblyFile);
				discoFile.DeleteElement(text2 + "\\Default.disco", progId + ".soap?WSDL");
			}
		}

		internal string GetTypeName(string assemblyPath, string progId, string classId)
		{
			string result = "";
			AssemblyManager assemblyManager = null;
			AppDomain appDomain = AppDomain.CreateDomain("SoapDomain");
			if (appDomain != null)
			{
				try
				{
					AssemblyName name = typeof(AssemblyManager).Assembly.GetName();
					Evidence evidence = AppDomain.CurrentDomain.Evidence;
					Evidence evidence2 = new Evidence(evidence);
					evidence2.AddAssembly(name);
					ObjectHandle objectHandle = appDomain.CreateInstance(name.FullName, typeof(AssemblyManager).FullName, ignoreCase: false, BindingFlags.Default, null, null, null, null, evidence2);
					if (objectHandle != null)
					{
						assemblyManager = (AssemblyManager)objectHandle.Unwrap();
						if (classId.Length > 0)
						{
							return assemblyManager.InternalGetTypeNameFromClassId(assemblyPath, classId);
						}
						return assemblyManager.InternalGetTypeNameFromProgId(assemblyPath, progId);
					}
					return result;
				}
				finally
				{
					AppDomain.Unload(appDomain);
				}
			}
			return result;
		}
	}
}
