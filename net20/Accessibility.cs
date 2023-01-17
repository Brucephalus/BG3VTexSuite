
// C:\WINDOWS\assembly\GAC_MSIL\Accessibility\2.0.0.0__b03f5f7f11d50a3a\Accessibility.dll
// Accessibility, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

[assembly: ImportedFromTypeLib("Accessibility")]
[assembly: AssemblyDefaultAlias("Accessibility.dll")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: CompilationRelaxations(8)]
[assembly: TypeLibVersion(1, 1)]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyDescription("Accessibility.dll")]
[assembly: CLSCompliant(true)]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Guid("1ea4dbf0-3c3b-11cf-810c-00aa00389b71")]
[assembly: ComVisible(true)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyTitle("Accessibility.dll")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyVersion("2.0.0.0")]
namespace Accessibility
{
	[ComImport]
	[TypeLibType(4176)]
	[Guid("618736E0-3C3D-11CF-810C-00AA00389B71")]
	public interface IAccessible
	{
		[DispId(-5000)]
		object accParent
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5000)]
			[return: MarshalAs(UnmanagedType.IDispatch)]
			get;
		}

		[DispId(-5001)]
		int accChildCount
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5001)]
			get;
		}

		[DispId(-5002)]
		object accChild
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5002)]
			[TypeLibFunc(64)]
			[return: MarshalAs(UnmanagedType.IDispatch)]
			get;
		}

		[DispId(-5003)]
		string accName
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5003)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5003)]
			[param: In]
			[param: MarshalAs(UnmanagedType.BStr)]
			set;
		}

		[DispId(-5004)]
		string accValue
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5004)]
			[TypeLibFunc(64)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5004)]
			[param: In]
			[param: MarshalAs(UnmanagedType.BStr)]
			set;
		}

		[DispId(-5005)]
		string accDescription
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5005)]
			[TypeLibFunc(64)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		[DispId(-5006)]
		object accRole
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5006)]
			[TypeLibFunc(64)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		[DispId(-5007)]
		object accState
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5007)]
			[TypeLibFunc(64)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		[DispId(-5008)]
		string accHelp
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5008)]
			[TypeLibFunc(64)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		[DispId(-5009)]
		int accHelpTopic
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5009)]
			[TypeLibFunc(64)]
			get;
		}

		[DispId(-5010)]
		string accKeyboardShortcut
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5010)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		[DispId(-5011)]
		object accFocus
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5011)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		[DispId(-5012)]
		object accSelection
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5012)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		[DispId(-5013)]
		string accDefaultAction
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(64)]
			[DispId(-5013)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		[TypeLibFunc(64)]
		[DispId(-5014)]
		void accSelect([In] int flagsSelect, [Optional][In][MarshalAs(UnmanagedType.Struct)] object varChild);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[TypeLibFunc(64)]
		[DispId(-5015)]
		void accLocation(out int pxLeft, out int pyTop, out int pcxWidth, out int pcyHeight, [Optional][In][MarshalAs(UnmanagedType.Struct)] object varChild);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[TypeLibFunc(64)]
		[DispId(-5016)]
		[return: MarshalAs(UnmanagedType.Struct)]
		object accNavigate([In] int navDir, [Optional][In][MarshalAs(UnmanagedType.Struct)] object varStart);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[TypeLibFunc(64)]
		[DispId(-5017)]
		[return: MarshalAs(UnmanagedType.Struct)]
		object accHitTest([In] int xLeft, [In] int yTop);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(-5018)]
		[TypeLibFunc(64)]
		void accDoDefaultAction([Optional][In][MarshalAs(UnmanagedType.Struct)] object varChild);
	}
	[ComImport]
	[InterfaceType(1)]
	[TypeLibType(272)]
	[Guid("03022430-ABC4-11D0-BDE2-00AA001A1953")]
	public interface IAccessibleHandler
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		void AccessibleObjectFromID([In] int hwnd, [In] int lObjectID, [MarshalAs(UnmanagedType.Interface)] out IAccessible pIAccessible);
	}
	[ComImport]
	[Guid("7852B78D-1CFD-41C1-A615-9C0C85960B5F")]
	[InterfaceType(1)]
	[ComConversionLoss]
	public interface IAccIdentity
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		void GetIdentityString([In] uint dwIDChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);
	}
	[ComImport]
	[Guid("76C0DBBB-15E0-4E7B-B61B-20EEEA2001E0")]
	[InterfaceType(1)]
	public interface IAccPropServer
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		void GetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [MarshalAs(UnmanagedType.Struct)] out object pvarValue, out int pfHasProp);
	}
	[ComImport]
	[ComConversionLoss]
	[Guid("6E26E776-04F0-495D-80E4-3330352E3169")]
	[InterfaceType(1)]
	public interface IAccPropServices
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetPropServer([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void ClearProps([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHwndProp([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHwndPropStr([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHwndPropServer([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void ClearHwndProps([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void ComposeHwndIdentityString([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void DecomposeHwndIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHWND")] IntPtr phwnd, out uint pidObject, out uint pidChild);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHmenuProp([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHmenuPropStr([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHmenuPropServer([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void ClearHmenuProps([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void ComposeHmenuIdentityString([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		[MethodImpl(MethodImplOptions.InternalCall)]
		void DecomposeHmenuIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHMENU")] IntPtr phmenu, out uint pidChild);
	}
	public enum AnnoScope
	{
		ANNO_THIS,
		ANNO_CONTAINER
	}
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	public struct _RemotableHandle
	{
		public int fContext;

		public __MIDL_IWinTypes_0009 u;
	}
	[StructLayout(LayoutKind.Explicit, Pack = 4)]
	public struct __MIDL_IWinTypes_0009
	{
		[FieldOffset(0)]
		public int hInproc;

		[FieldOffset(0)]
		public int hRemote;
	}
	[ComImport]
	[TypeLibType(2)]
	[ClassInterface(0)]
	[Guid("B5F8350B-0548-48B1-A6EE-88BD00B4A5E7")]
	[ComConversionLoss]
	public class CAccPropServicesClass : IAccPropServices, CAccPropServices
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		public extern CAccPropServicesClass();

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		void IAccPropServices.SetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetPropValue
			this.SetPropValue(ref pIDString, dwIDStringLen, idProp, var);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetPropServer([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		void IAccPropServices.SetPropServer([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetPropServer
			this.SetPropServer(ref pIDString, dwIDStringLen, ref paProps, cProps, pServer, AnnoScope);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ClearProps([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps);

		void IAccPropServices.ClearProps([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ClearProps
			this.ClearProps(ref pIDString, dwIDStringLen, ref paProps, cProps);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHwndProp([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		void IAccPropServices.SetHwndProp([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHwndProp
			this.SetHwndProp(ref hwnd, idObject, idChild, idProp, var);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHwndPropStr([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		void IAccPropServices.SetHwndPropStr([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHwndPropStr
			this.SetHwndPropStr(ref hwnd, idObject, idChild, idProp, str);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHwndPropServer([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		void IAccPropServices.SetHwndPropServer([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHwndPropServer
			this.SetHwndPropServer(ref hwnd, idObject, idChild, ref paProps, cProps, pServer, AnnoScope);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ClearHwndProps([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		void IAccPropServices.ClearHwndProps([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ClearHwndProps
			this.ClearHwndProps(ref hwnd, idObject, idChild, ref paProps, cProps);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ComposeHwndIdentityString([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		void IAccPropServices.ComposeHwndIdentityString([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ComposeHwndIdentityString
			this.ComposeHwndIdentityString(ref hwnd, idObject, idChild, ppIDString, out pdwIDStringLen);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void DecomposeHwndIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHWND")] IntPtr phwnd, out uint pidObject, out uint pidChild);

		void IAccPropServices.DecomposeHwndIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHWND")] IntPtr phwnd, out uint pidObject, out uint pidChild)
		{
			//ILSpy generated this explicit interface implementation from .override directive in DecomposeHwndIdentityString
			this.DecomposeHwndIdentityString(ref pIDString, dwIDStringLen, phwnd, out pidObject, out pidChild);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHmenuProp([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		void IAccPropServices.SetHmenuProp([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHmenuProp
			this.SetHmenuProp(ref hmenu, idChild, idProp, var);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHmenuPropStr([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		void IAccPropServices.SetHmenuPropStr([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHmenuPropStr
			this.SetHmenuPropStr(ref hmenu, idChild, idProp, str);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHmenuPropServer([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		void IAccPropServices.SetHmenuPropServer([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHmenuPropServer
			this.SetHmenuPropServer(ref hmenu, idChild, ref paProps, cProps, pServer, AnnoScope);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ClearHmenuProps([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		void IAccPropServices.ClearHmenuProps([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ClearHmenuProps
			this.ClearHmenuProps(ref hmenu, idChild, ref paProps, cProps);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ComposeHmenuIdentityString([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		void IAccPropServices.ComposeHmenuIdentityString([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ComposeHmenuIdentityString
			this.ComposeHmenuIdentityString(ref hmenu, idChild, ppIDString, out pdwIDStringLen);
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void DecomposeHmenuIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHMENU")] IntPtr phmenu, out uint pidChild);

		void IAccPropServices.DecomposeHmenuIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHMENU")] IntPtr phmenu, out uint pidChild)
		{
			//ILSpy generated this explicit interface implementation from .override directive in DecomposeHmenuIdentityString
			this.DecomposeHmenuIdentityString(ref pIDString, dwIDStringLen, phmenu, out pidChild);
		}
	}
	[ComImport]
	[Guid("6E26E776-04F0-495D-80E4-3330352E3169")]
	[CoClass(typeof(CAccPropServicesClass))]
	public interface CAccPropServices : IAccPropServices
	{
	}
}
