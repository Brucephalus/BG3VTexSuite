
// C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\Accessibility\v4.0_4.0.0.0__b03f5f7f11d50a3a\Accessibility.dll
// Accessibility, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v4.0.30319
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Diagnostics;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

[assembly: AssemblyDescription("Accessibility.dll")]
[assembly: ComVisible(true)]
[assembly: CLSCompliant(true)]
[assembly: AllowPartiallyTrustedCallers]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: ImportedFromTypeLib("Accessibility")]
[assembly: AssemblyFileVersion("4.8.9037.0")]
[assembly: AssemblyTitle("Accessibility.dll")]
[assembly: CompilationRelaxations(8)]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyDefaultAlias("Accessibility.dll")]
[assembly: SatelliteContractVersion("4.0.0.0")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: TypeLibVersion(1, 1)]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32 | DllImportSearchPath.AssemblyDirectory)]
[assembly: SecurityRules(SecurityRuleSet.Level2, SkipVerificationInFullTrust = true)]
[assembly: AssemblyDelaySign(true)]
[assembly: Guid("1EA4DBF0-3C3B-11CF-810C-00AA00389B71")]
[assembly: AssemblyInformationalVersion("4.8.9037.0")]
[assembly: AssemblyKeyFile("f:\\dd\\tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyVersion("4.0.0.0")]
namespace Accessibility
{
	/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
	[ComImport]
	[ComConversionLoss]
	[Guid("6E26E776-04F0-495D-80E4-3330352E3169")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IAccPropServices
	{
		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Identifies the accessible element that is to be annotated.</param>
		/// <param name="dwIDStringLen">Specifies the length of the string identified by the <paramref name="pIDString" /> parameter.</param>
		/// <param name="idProp">Specifies the property of the accessible element to be annotated.</param>
		/// <param name="var">Specifies a new value for the property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Identifies the accessible element that is to be annotated.</param>
		/// <param name="dwIDStringLen">Specifies the length of the string identified by the <paramref name="pIDString" /> parameter.</param>
		/// <param name="paProps">Specifies an array of properties to be handled by the specified callback object.</param>
		/// <param name="cProps">Specifies an array of properties to be handled by the specified callback object.</param>
		/// <param name="pServer">Specifies the callback object that will be invoked when a client requests one of the overridden properties.</param>
		/// <param name="AnnoScope">May be ANNO_THIS, indicating that the annotation affects the indicated accessible element only; or ANNO_CONTAINER, indicating that it applies to the element and its immediate element children.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetPropServer([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Identifies the accessible element that is to be un-annotated.</param>
		/// <param name="dwIDStringLen">Length of <paramref name="pIDString" />.</param>
		/// <param name="paProps">Specifies an array of properties that is to be reset. These properties will revert to the default behavior they displayed before they were annotated.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void ClearProps([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idProp">Specifies which property of that element is to be annotated.</param>
		/// <param name="var">Specifies a new value for that property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHwndProp([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idProp">Specifies which property of that element is to be annotated.</param>
		/// <param name="str">Specifies a new value for that property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHwndPropStr([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="paProps">Specifies an array of properties that is to be handled by the specified callback object.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		/// <param name="pServer">Specifies the callback object, which will be invoked when a client requests one of the overridden properties.</param>
		/// <param name="AnnoScope">May be ANNO_THIS, indicating that the annotation affects the indicated accessible element only; or ANNO_CONTAINER, indicating that it applies to the element and its immediate element children.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHwndPropServer([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="paProps">Specifies an array of properties that is to be reset. These properties will revert to the default behavior that they displayed before they were annotated.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void ClearHwndProps([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Specifies the HWND of the accessible element that the caller wants to identify.</param>
		/// <param name="idObject">Specifies the object ID of the accessible element.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="ppIDString">Pointer to a buffer that receives the identity string. The callee allocates this buffer using <see langword="CoTaskMemAlloc" />. When finished, the caller must free the buffer by calling <see langword="CoTaskMemFree" />.</param>
		/// <param name="pdwIDStringLen">Pointer to a buffer that receives the length of the identity string.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void ComposeHwndIdentityString([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Pointer to a buffer containing identity string of an Hwnd-based accessible element.</param>
		/// <param name="dwIDStringLen">Specifies the length of the identity string specified by <paramref name="pIDString" />.</param>
		/// <param name="phwnd">Pointer to a buffer that receives the HWND of the accessible element.</param>
		/// <param name="pidObject">Pointer to a buffer that receives the object ID of the accessible element.</param>
		/// <param name="pidChild">Pointer to a buffer that receives the child ID of the accessible element.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void DecomposeHwndIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHWND")] IntPtr phwnd, out uint pidObject, out uint pidChild);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element to be annotated.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="idProp">Specifies which property of the accessible element is to be annotated.</param>
		/// <param name="var">Specifies a new value for the <paramref name="idProp" /> property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHmenuProp([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element to be annotated.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="idProp">Specifies which property of the accessible element is to be annotated.</param>
		/// <param name="str">Specifies a new value for the <paramref name="idProp" /> property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHmenuPropStr([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-accessible element to be annotated.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="paProps">Specifies an array of properties that is to be handled by the specified callback object.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		/// <param name="pServer">Specifies the callback object, which will be invoked when a client requests one of the overridden properties.</param>
		/// <param name="AnnoScope">May be ANNO_THIS, indicating that the annotation affects the indicated accessible element only; or ANNO_CONTAINER, indicating that it applies to the element and its immediate element children.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void SetHmenuPropServer([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element to be annotated.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="paProps">Specifies an array of properties to be reset. These properties will revert to the default behavior that they displayed before they were annotated.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void ClearHmenuProps([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="ppIDString">Pointer to a buffer that receives the identity string. The callee allocates this buffer using <see langword="CoTaskMemAlloc" />. When finished, the caller must free the buffer by calling <see langword="CoTaskMemFree" />.</param>
		/// <param name="pdwIDStringLen">Pointer to a buffer that receives the length of the identity string.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void ComposeHmenuIdentityString([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		/// <summary>The <see cref="T:Accessibility.IAccPropServices" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Pointer to a buffer containing identity string of an HMENU-based accessible element.</param>
		/// <param name="dwIDStringLen">Specifies the length of the identity string specified by <paramref name="pIDString" />.</param>
		/// <param name="phmenu">Pointer to a buffer that receives the HMENU of the accessible element.</param>
		/// <param name="pidChild">Pointer to a buffer that receives the child ID of the accessible element.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void DecomposeHmenuIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHMENU")] IntPtr phmenu, out uint pidChild);
	}
	/// <summary>The <see cref="T:Accessibility.IAccPropServer" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServer" /> interface.</summary>
	[ComImport]
	[Guid("76C0DBBB-15E0-4E7B-B61B-20EEEA2001E0")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IAccPropServer
	{
		/// <summary>The <see cref="T:Accessibility.IAccPropServer" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServer" /> interface.</summary>
		/// <param name="pIDString">Contains a string that identifies the property being requested.</param>
		/// <param name="dwIDStringLen">Specifies the length of the identity string specified by the <paramref name="pIDString" /> parameter.</param>
		/// <param name="idProp">Specifies a GUID indicating the desired property.</param>
		/// <param name="pvarValue">Specifies the value of the overridden property. This parameter is valid only if <paramref name="pfHasProp" /> is TRUE. The server must set this to VT_EMPTY if <paramref name="pfHasProp" /> is set to FALSE.</param>
		/// <param name="pfHasProp">Indicates whether the server is supplying a value for the requested property. The server should set this to TRUE if it is returning an overriding property or to FALSE if it is not returning a property (in which case it should also set <paramref name="pvarValue" /> to VT_EMPTY).</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void GetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [MarshalAs(UnmanagedType.Struct)] out object pvarValue, out int pfHasProp);
	}
	/// <summary>The <see cref="T:Accessibility.AnnoScope" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) accessibility interface.</summary>
	public enum AnnoScope
	{
		/// <summary>Annotation is scoped to the immediate object.</summary>
		ANNO_THIS,
		/// <summary>Annotation is scoped to the container object.</summary>
		ANNO_CONTAINER
	}
	/// <summary>The <see cref="T:Accessibility.IAccessibleHandler" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) accessibility interface.</summary>
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	public struct _RemotableHandle
	{
		/// <summary>The <see cref="T:Accessibility.IAccessibleHandler" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) accessibility interface.</summary>
		public int fContext;

		/// <summary>The <see cref="T:Accessibility.IAccessibleHandler" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) accessibility interface.</summary>
		public __MIDL_IWinTypes_0009 u;
	}
	/// <summary>The <see cref="T:Accessibility.CAccPropServices" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
	[ComImport]
	[Guid("6E26E776-04F0-495D-80E4-3330352E3169")]
	[CoClass(typeof(CAccPropServicesClass))]
	public interface CAccPropServices : IAccPropServices
	{
	}
	/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
	[ComImport]
	[Guid("B5F8350B-0548-48B1-A6EE-88BD00B4A5E7")]
	[ClassInterface(ClassInterfaceType.None)]
	[TypeLibType(TypeLibTypeFlags.FCanCreate)]
	[ComConversionLoss]
	public class CAccPropServicesClass : IAccPropServices, CAccPropServices
	{
		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public extern CAccPropServicesClass();

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Identifies the accessible element that is to be annotated.</param>
		/// <param name="dwIDStringLen">Specifies the length of the string identified by the <paramref name="pIDString" /> parameter.</param>
		/// <param name="idProp">Specifies the property of the accessible element to be annotated.</param>
		/// <param name="var">Specifies a new value for the property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		void IAccPropServices.SetPropValue([In] ref byte pIDString, [In] uint dwIDStringLen, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetPropValue
			this.SetPropValue(ref pIDString, dwIDStringLen, idProp, var);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Identifies the accessible element that is to be annotated.</param>
		/// <param name="dwIDStringLen">Specifies the length of the string identified by the <paramref name="pIDString" /> parameter.</param>
		/// <param name="paProps">Specifies an array of properties to be handled by the specified callback object.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		/// <param name="pServer">Specifies the callback object that will be invoked when a client requests one of the overridden properties.</param>
		/// <param name="AnnoScope">May be ANNO_THIS, indicating that the annotation affects the indicated accessible element only; or ANNO_CONTAINER, indicating that it applies to the element and its immediate element children.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetPropServer([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		void IAccPropServices.SetPropServer([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetPropServer
			this.SetPropServer(ref pIDString, dwIDStringLen, ref paProps, cProps, pServer, AnnoScope);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Identify the accessible element that is to be un-annotated.</param>
		/// <param name="dwIDStringLen">Length of <paramref name="pIDString" />.</param>
		/// <param name="paProps">Specify an array of properties that is to be reset. These properties will revert to the default behavior they displayed before they were annotated.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ClearProps([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps);

		void IAccPropServices.ClearProps([In] ref byte pIDString, [In] uint dwIDStringLen, [In] ref Guid paProps, [In] int cProps)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ClearProps
			this.ClearProps(ref pIDString, dwIDStringLen, ref paProps, cProps);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idProp">Specifies which property of that element is to be annotated.</param>
		/// <param name="var">Specifies a new value for the <paramref name="idProp" /> property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHwndProp([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		void IAccPropServices.SetHwndProp([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHwndProp
			this.SetHwndProp(ref hwnd, idObject, idChild, idProp, var);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idProp">Specifies which property of that element is to be annotated.</param>
		/// <param name="str">Specifies a new value for the <paramref name="idProp" /> property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHwndPropStr([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		void IAccPropServices.SetHwndPropStr([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHwndPropStr
			this.SetHwndPropStr(ref hwnd, idObject, idChild, idProp, str);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="paProps">Specifies an array of properties that is to be handled by the specified callback object.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		/// <param name="pServer">Specifies the callback object, which will be invoked when a client requests one of the overridden properties.</param>
		/// <param name="AnnoScope">May be ANNO_THIS, indicating that the annotation affects the indicated accessible element only; or ANNO_CONTAINER, indicating that it applies to the element and its immediate element children.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHwndPropServer([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		void IAccPropServices.SetHwndPropServer([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHwndPropServer
			this.SetHwndPropServer(ref hwnd, idObject, idChild, ref paProps, cProps, pServer, AnnoScope);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idObject">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="paProps">Specifies an array of properties that is to be reset. These properties will revert to the default behavior that they displayed before they were annotated.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ClearHwndProps([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		void IAccPropServices.ClearHwndProps([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [In] ref Guid paProps, [In] int cProps)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ClearHwndProps
			this.ClearHwndProps(ref hwnd, idObject, idChild, ref paProps, cProps);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hwnd">Specifies the HWND of the accessible element that the caller wants to identify.</param>
		/// <param name="idObject">Specifies the object ID of the accessible element.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="ppIDString">Pointer to a buffer that receives the identity string. The callee allocates this buffer using <see langword="CoTaskMemAlloc" />. When finished, the caller must free the buffer by calling <see langword="CoTaskMemFree" />.</param>
		/// <param name="pdwIDStringLen">Pointer to a buffer that receives the length of the identity string.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ComposeHwndIdentityString([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		void IAccPropServices.ComposeHwndIdentityString([In][ComAliasName("Accessibility.wireHWND")] ref _RemotableHandle hwnd, [In] uint idObject, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ComposeHwndIdentityString
			this.ComposeHwndIdentityString(ref hwnd, idObject, idChild, ppIDString, out pdwIDStringLen);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Pointer to a buffer containing identity string of an Hwnd-based accessible element.</param>
		/// <param name="dwIDStringLen">Specifies the length of the identity string specified by <paramref name="pIDString" />.</param>
		/// <param name="phwnd">Pointer to a buffer that receives the HWND of the accessible element.</param>
		/// <param name="pidObject">Pointer to a buffer that receives the object ID of the accessible element.</param>
		/// <param name="pidChild">Pointer to a buffer that receives the child ID of the accessible element.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void DecomposeHwndIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHWND")] IntPtr phwnd, out uint pidObject, out uint pidChild);

		void IAccPropServices.DecomposeHwndIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHWND")] IntPtr phwnd, out uint pidObject, out uint pidChild)
		{
			//ILSpy generated this explicit interface implementation from .override directive in DecomposeHwndIdentityString
			this.DecomposeHwndIdentityString(ref pIDString, dwIDStringLen, phwnd, out pidObject, out pidChild);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element to be annotated.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="idProp">Specifies which property of the accessible element is to be annotated.</param>
		/// <param name="var">Specifies a new value for the <paramref name="idProp" /> property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHmenuProp([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var);

		void IAccPropServices.SetHmenuProp([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.Struct)] object var)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHmenuProp
			this.SetHmenuProp(ref hmenu, idChild, idProp, var);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element to be annotated.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="idProp">Specifies which property of the accessible element is to be annotated.</param>
		/// <param name="str">Specifies a new value for the <paramref name="idProp" /> property.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHmenuPropStr([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str);

		void IAccPropServices.SetHmenuPropStr([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] Guid idProp, [In][MarshalAs(UnmanagedType.LPWStr)] string str)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHmenuPropStr
			this.SetHmenuPropStr(ref hmenu, idChild, idProp, str);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-accessible element to be annotated.</param>
		/// <param name="idChild">Identifies the accessible element that is to be annotated. This replaces the identity string.</param>
		/// <param name="paProps">Specifies an array of properties that is to be handled by the specified callback object.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		/// <param name="pServer">Specifies the callback object, which will be invoked when a client requests one of the overridden properties.</param>
		/// <param name="AnnoScope">May be ANNO_THIS, indicating that the annotation affects the indicated accessible element only; or ANNO_CONTAINER, indicating that it applies to the element and its immediate element children.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void SetHmenuPropServer([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope);

		void IAccPropServices.SetHmenuPropServer([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps, [In][MarshalAs(UnmanagedType.Interface)] IAccPropServer pServer, [In] AnnoScope AnnoScope)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetHmenuPropServer
			this.SetHmenuPropServer(ref hmenu, idChild, ref paProps, cProps, pServer, AnnoScope);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element to be annotated.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="paProps">Specifies an array of properties to be reset. These properties will revert to the default behavior that they displayed before they were annotated.</param>
		/// <param name="cProps">Specifies the number of properties in the <paramref name="paProps" /> array.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ClearHmenuProps([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps);

		void IAccPropServices.ClearHmenuProps([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [In] ref Guid paProps, [In] int cProps)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ClearHmenuProps
			this.ClearHmenuProps(ref hmenu, idChild, ref paProps, cProps);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="hmenu">Identifies the HMENU-based accessible element.</param>
		/// <param name="idChild">Specifies the child ID of the accessible element.</param>
		/// <param name="ppIDString">Pointer to a buffer that receives the identity string. The callee allocates this buffer using <see langword="CoTaskMemAlloc" />. When finished, the caller must free the buffer by calling <see langword="CoTaskMemFree" />.</param>
		/// <param name="pdwIDStringLen">Pointer to a buffer that receives the length of the identity string.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void ComposeHmenuIdentityString([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);

		void IAccPropServices.ComposeHmenuIdentityString([In][ComAliasName("Accessibility.wireHMENU")] ref _RemotableHandle hmenu, [In] uint idChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen)
		{
			//ILSpy generated this explicit interface implementation from .override directive in ComposeHmenuIdentityString
			this.ComposeHmenuIdentityString(ref hmenu, idChild, ppIDString, out pdwIDStringLen);
		}

		/// <summary>The <see cref="T:Accessibility.CAccPropServicesClass" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccPropServices" /> interface.</summary>
		/// <param name="pIDString">Pointer to a buffer containing identity string of an HMENU-based accessible element.</param>
		/// <param name="dwIDStringLen">Specifies the length of the identity string specified by <paramref name="pIDString" />.</param>
		/// <param name="phmenu">Pointer to a buffer that receives the HMENU of the accessible element.</param>
		/// <param name="pidChild">Pointer to a buffer that receives the child ID of the accessible element.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		public virtual extern void DecomposeHmenuIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHMENU")] IntPtr phmenu, out uint pidChild);

		void IAccPropServices.DecomposeHmenuIdentityString([In] ref byte pIDString, [In] uint dwIDStringLen, [Out][ComAliasName("Accessibility.wireHMENU")] IntPtr phmenu, out uint pidChild)
		{
			//ILSpy generated this explicit interface implementation from .override directive in DecomposeHmenuIdentityString
			this.DecomposeHmenuIdentityString(ref pIDString, dwIDStringLen, phmenu, out pidChild);
		}
	}
	/// <summary>The <see cref="T:Accessibility.__MIDL_IWinTypes_0009" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) accessibility interface.</summary>
	[StructLayout(LayoutKind.Explicit, Pack = 4, Size = 4)]
	public struct __MIDL_IWinTypes_0009
	{
		/// <summary>The <see cref="T:Accessibility.__MIDL_IWinTypes_0009" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) accessibility interface.</summary>
		[FieldOffset(0)]
		public int hInproc;

		/// <summary>The <see cref="T:Accessibility.__MIDL_IWinTypes_0009" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) accessibility interface.</summary>
		[FieldOffset(0)]
		public int hRemote;
	}
	/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
	[ComImport]
	[Guid("618736E0-3C3D-11CF-810C-00AA00389B71")]
	[TypeLibType(TypeLibTypeFlags.FHidden | TypeLibTypeFlags.FDual | TypeLibTypeFlags.FDispatchable)]
	public interface IAccessible
	{
		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <returns>An object.</returns>
		[DispId(-5000)]
		object accParent
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5000)]
			[return: MarshalAs(UnmanagedType.IDispatch)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <returns>An integer representing the count.</returns>
		[DispId(-5001)]
		int accChildCount
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5001)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>An object.</returns>
		[DispId(-5002)]
		object accChild
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5002)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[return: MarshalAs(UnmanagedType.IDispatch)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>A string.</returns>
		[DispId(-5003)]
		string accName
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5003)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5003)]
			[param: In]
			[param: MarshalAs(UnmanagedType.BStr)]
			set;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>A string.</returns>
		[DispId(-5004)]
		string accValue
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5004)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5004)]
			[param: In]
			[param: MarshalAs(UnmanagedType.BStr)]
			set;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>A string representing the description.</returns>
		[DispId(-5005)]
		string accDescription
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5005)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>An object.</returns>
		[DispId(-5006)]
		object accRole
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5006)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>An object.</returns>
		[DispId(-5007)]
		object accState
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5007)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>A string.</returns>
		[DispId(-5008)]
		string accHelp
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5008)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="pszHelpFile">This parameter is intended for internal use only.</param>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>An integer.</returns>
		[DispId(-5009)]
		int accHelpTopic
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5009)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>A string.</returns>
		[DispId(-5010)]
		string accKeyboardShortcut
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[DispId(-5010)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <returns>If successful, returns S_OK. Otherwise, returns another standard COM error code.</returns>
		[DispId(-5011)]
		object accFocus
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5011)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <returns>An object.</returns>
		[DispId(-5012)]
		object accSelection
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5012)]
			[return: MarshalAs(UnmanagedType.Struct)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		/// <returns>A string representing the action.</returns>
		[DispId(-5013)]
		string accDefaultAction
		{
			[MethodImpl(MethodImplOptions.InternalCall)]
			[TypeLibFunc(TypeLibFuncFlags.FHidden)]
			[DispId(-5013)]
			[return: MarshalAs(UnmanagedType.BStr)]
			get;
		}

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="flagsSelect">This parameter is intended for internal use only.</param>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		[TypeLibFunc(TypeLibFuncFlags.FHidden)]
		[DispId(-5014)]
		void accSelect([In] int flagsSelect, [Optional][In][MarshalAs(UnmanagedType.Struct)] object varChild);

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="pxLeft">This parameter is intended for internal use only.</param>
		/// <param name="pyTop">This parameter is intended for internal use only.</param>
		/// <param name="pcxWidth">This parameter is intended for internal use only.</param>
		/// <param name="pcyHeight">This parameter is intended for internal use only.</param>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(-5015)]
		[TypeLibFunc(TypeLibFuncFlags.FHidden)]
		void accLocation(out int pxLeft, out int pyTop, out int pcxWidth, out int pcyHeight, [Optional][In][MarshalAs(UnmanagedType.Struct)] object varChild);

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="navDir">This parameter is intended for internal use only.</param>
		/// <param name="varStart">This parameter is intended for internal use only.</param>
		/// <returns>If successful, returns S_OK. For other possible return values, see the documentation for <see langword="IAccessible::accNavigate" />.</returns>
		[MethodImpl(MethodImplOptions.InternalCall)]
		[TypeLibFunc(TypeLibFuncFlags.FHidden)]
		[DispId(-5016)]
		[return: MarshalAs(UnmanagedType.Struct)]
		object accNavigate([In] int navDir, [Optional][In][MarshalAs(UnmanagedType.Struct)] object varStart);

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="xLeft">This parameter is intended for internal use only.</param>
		/// <param name="yTop">This parameter is intended for internal use only.</param>
		/// <returns>An object.</returns>
		[MethodImpl(MethodImplOptions.InternalCall)]
		[TypeLibFunc(TypeLibFuncFlags.FHidden)]
		[DispId(-5017)]
		[return: MarshalAs(UnmanagedType.Struct)]
		object accHitTest([In] int xLeft, [In] int yTop);

		/// <summary>The <see cref="T:Accessibility.IAccessible" /> interface and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessible" /> interface.</summary>
		/// <param name="varChild">This parameter is intended for internal use only.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(-5018)]
		[TypeLibFunc(TypeLibFuncFlags.FHidden)]
		void accDoDefaultAction([Optional][In][MarshalAs(UnmanagedType.Struct)] object varChild);
	}
	/// <summary>The <see cref="T:Accessibility.IAccessibleHandler" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessibleHandler" /> interface.</summary>
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[TypeLibType(TypeLibTypeFlags.FHidden | TypeLibTypeFlags.FOleAutomation)]
	[Guid("03022430-ABC4-11D0-BDE2-00AA001A1953")]
	public interface IAccessibleHandler
	{
		/// <summary>The <see cref="T:Accessibility.IAccessibleHandler" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccessibleHandler" /> interface.</summary>
		/// <param name="hwnd">Specifies the handle of a window for which an IAccessible interface pointer is to be retrieved.</param>
		/// <param name="lObjectID">Specifies the object ID.</param>
		/// <param name="pIAccessible">Specifies the address of a pointer variable that receives the address of the object's IAccessible interface.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void AccessibleObjectFromID([In] int hwnd, [In] int lObjectID, [MarshalAs(UnmanagedType.Interface)] out IAccessible pIAccessible);
	}
	/// <summary>The <see cref="T:Accessibility.IAccIdentity" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccIdentity" /> interface.</summary>
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("7852B78D-1CFD-41C1-A615-9C0C85960B5F")]
	[ComConversionLoss]
	public interface IAccIdentity
	{
		/// <summary>The <see cref="T:Accessibility.IAccIdentity" /> and all of its exposed members are part of a managed wrapper for the Component Object Model (COM) <see langword="IAccIndentity" /> interface.</summary>
		/// <param name="dwIDChild">Specifies which child of the IAccessible object the caller wants to identify.</param>
		/// <param name="ppIDString">Address of a variable that receives a pointer to a callee-allocated identity string. The callee allocates the identity string using <see langword="CoTaskMemAlloc" />; the caller must release the identity string by using <see langword="CoTaskMemFree" /> when finished.</param>
		/// <param name="pdwIDStringLen">Address of a variable that receives the length, in bytes, of the callee-allocated identity string.</param>
		[MethodImpl(MethodImplOptions.InternalCall)]
		void GetIdentityString([In] uint dwIDChild, [Out] IntPtr ppIDString, out uint pdwIDStringLen);
	}
}
