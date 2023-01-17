
// C:\WINDOWS\assembly\GAC_MSIL\System.Drawing.Design\2.0.0.0__b03f5f7f11d50a3a\System.Drawing.Design.dll
// System.Drawing.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Collections;
using System.ComponentModel;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Lifetime;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Permissions;
using System.Threading;
using System.Windows.Forms;
using System.Windows.Forms.Design;

[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyDefaultAlias("System.Drawing.Design.dll")]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyDescription("System.Drawing.Design.dll")]
[assembly: AssemblyTitle("System.Drawing.Design.dll")]
[assembly: CLSCompliant(true)]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("2.0.0.0")]
namespace System.Drawing.Design
{
	[AttributeUsage(AttributeTargets.All)]
	internal sealed class SRDescriptionAttribute : DescriptionAttribute
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
		internal const string imageFileDescription = "imageFileDescription";

		internal const string ColorEditorSystemTab = "ColorEditorSystemTab";

		internal const string ColorEditorStandardTab = "ColorEditorStandardTab";

		internal const string bitmapFileDescription = "bitmapFileDescription";

		internal const string ColorEditorPaletteTab = "ColorEditorPaletteTab";

		internal const string iconFileDescription = "iconFileDescription";

		internal const string metafileFileDescription = "metafileFileDescription";

		internal const string ContentAlignmentEditorAccName = "ContentAlignmentEditorAccName";

		internal const string ContentAlignmentEditorTopLeftAccName = "ContentAlignmentEditorTopLeftAccName";

		internal const string ContentAlignmentEditorTopCenterAccName = "ContentAlignmentEditorTopCenterAccName";

		internal const string ContentAlignmentEditorTopRightAccName = "ContentAlignmentEditorTopRightAccName";

		internal const string ContentAlignmentEditorMiddleLeftAccName = "ContentAlignmentEditorMiddleLeftAccName";

		internal const string ContentAlignmentEditorMiddleCenterAccName = "ContentAlignmentEditorMiddleCenterAccName";

		internal const string ContentAlignmentEditorMiddleRightAccName = "ContentAlignmentEditorMiddleRightAccName";

		internal const string ContentAlignmentEditorBottomLeftAccName = "ContentAlignmentEditorBottomLeftAccName";

		internal const string ContentAlignmentEditorBottomCenterAccName = "ContentAlignmentEditorBottomCenterAccName";

		internal const string ContentAlignmentEditorBottomRightAccName = "ContentAlignmentEditorBottomRightAccName";

		internal const string ColorEditorAccName = "ColorEditorAccName";

		internal const string ToolboxServiceBadToolboxItem = "ToolboxServiceBadToolboxItem";

		internal const string ToolboxServiceBadToolboxItemWithException = "ToolboxServiceBadToolboxItemWithException";

		internal const string ToolboxServiceAssemblyNotFound = "ToolboxServiceAssemblyNotFound";

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
			resources = new ResourceManager("System.Drawing.Design.SR", GetType().Assembly);
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
namespace System.Drawing.Design
{
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	public class ImageEditor : UITypeEditor
	{
		internal static Type[] imageExtenders = new Type[2]
		{
			typeof(BitmapEditor),
			typeof(MetafileEditor)
		};

		internal FileDialog fileDialog;

		protected virtual Type[] GetImageExtenders()
		{
			return imageExtenders;
		}

		protected static string CreateExtensionsString(string[] extensions, string sep)
		{
			if (extensions == null || extensions.Length == 0)
			{
				return null;
			}
			string text = null;
			for (int i = 0; i < extensions.Length - 1; i++)
			{
				text = text + "*." + extensions[i] + sep;
			}
			return text + "*." + extensions[extensions.Length - 1];
		}

		protected static string CreateFilterEntry(ImageEditor e)
		{
			string fileDialogDescription = e.GetFileDialogDescription();
			string text = CreateExtensionsString(e.GetExtensions(), ",");
			string text2 = CreateExtensionsString(e.GetExtensions(), ";");
			return fileDialogDescription + "(" + text + ")|" + text2;
		}

		public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			if (provider != null)
			{
				IWindowsFormsEditorService windowsFormsEditorService = (IWindowsFormsEditorService)provider.GetService(typeof(IWindowsFormsEditorService));
				if (windowsFormsEditorService != null)
				{
					if (fileDialog == null)
					{
						fileDialog = new OpenFileDialog();
						string text = CreateFilterEntry(this);
						for (int i = 0; i < GetImageExtenders().Length; i++)
						{
							ImageEditor imageEditor = (ImageEditor)Activator.CreateInstance(GetImageExtenders()[i], BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.CreateInstance, null, null, null);
							Type type = GetType();
							Type type2 = imageEditor.GetType();
							if (!type.Equals(type2) && imageEditor != null && type.IsInstanceOfType(imageEditor))
							{
								text = text + "|" + CreateFilterEntry(imageEditor);
							}
						}
						fileDialog.Filter = text;
					}
					IntPtr focus = UnsafeNativeMethods.GetFocus();
					try
					{
						if (fileDialog.ShowDialog() == DialogResult.OK)
						{
							FileStream stream = new FileStream(fileDialog.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
							value = LoadFromStream(stream);
							return value;
						}
						return value;
					}
					finally
					{
						if (focus != IntPtr.Zero)
						{
							UnsafeNativeMethods.SetFocus(new HandleRef(null, focus));
						}
					}
				}
			}
			return value;
		}

		public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.Modal;
		}

		protected virtual string GetFileDialogDescription()
		{
			return SR.GetString("imageFileDescription");
		}

		protected virtual string[] GetExtensions()
		{
			ArrayList arrayList = new ArrayList();
			for (int i = 0; i < GetImageExtenders().Length; i++)
			{
				ImageEditor imageEditor = (ImageEditor)Activator.CreateInstance(GetImageExtenders()[i], BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.CreateInstance, null, null, null);
				if (!imageEditor.GetType().Equals(typeof(ImageEditor)))
				{
					arrayList.AddRange(new ArrayList(imageEditor.GetExtensions()));
				}
			}
			return (string[])arrayList.ToArray(typeof(string));
		}

		public override bool GetPaintValueSupported(ITypeDescriptorContext context)
		{
			return true;
		}

		protected virtual Image LoadFromStream(Stream stream)
		{
			byte[] buffer = new byte[stream.Length];
			stream.Read(buffer, 0, (int)stream.Length);
			MemoryStream stream2 = new MemoryStream(buffer);
			return Image.FromStream(stream2);
		}

		public override void PaintValue(PaintValueEventArgs e)
		{
			if (e.Value is Image image)
			{
				Rectangle bounds = e.Bounds;
				bounds.Width--;
				bounds.Height--;
				e.Graphics.DrawRectangle(SystemPens.WindowFrame, bounds);
				e.Graphics.DrawImage(image, e.Bounds);
			}
		}
	}
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	[PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
	public class BitmapEditor : ImageEditor
	{
		protected override string GetFileDialogDescription()
		{
			return SR.GetString("bitmapFileDescription");
		}

		protected override string[] GetExtensions()
		{
			return new string[6] { "bmp", "gif", "jpg", "jpeg", "png", "ico" };
		}

		protected override Image LoadFromStream(Stream stream)
		{
			return new Bitmap(stream);
		}
	}
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	public class ColorEditor : UITypeEditor
	{
		private class ColorPalette : Control
		{
			[ComVisible(true)]
			public class ColorPaletteAccessibleObject : ControlAccessibleObject
			{
				[ComVisible(true)]
				public class ColorCellAccessibleObject : AccessibleObject
				{
					private Color color;

					private ColorPaletteAccessibleObject parent;

					private int cell;

					public override Rectangle Bounds
					{
						get
						{
							Point point = Get2DFrom1D(cell);
							Rectangle rect = default(Rectangle);
							FillRectWithCellBounds(point.X, point.Y, ref rect);
							NativeMethods.POINT pOINT = new NativeMethods.POINT(rect.X, rect.Y);
							UnsafeNativeMethods.ClientToScreen(new HandleRef(parent.ColorPalette, parent.ColorPalette.Handle), pOINT);
							return new Rectangle(pOINT.x, pOINT.y, rect.Width, rect.Height);
						}
					}

					public override string Name => color.ToString();

					public override AccessibleObject Parent => parent;

					public override AccessibleRole Role => AccessibleRole.Cell;

					public override AccessibleStates State
					{
						get
						{
							AccessibleStates accessibleStates = base.State;
							if (cell == parent.ColorPalette.FocusedCell)
							{
								accessibleStates |= AccessibleStates.Focused;
							}
							return accessibleStates;
						}
					}

					public override string Value => color.ToString();

					public ColorCellAccessibleObject(ColorPaletteAccessibleObject parent, Color color, int cell)
					{
						this.color = color;
						this.parent = parent;
						this.cell = cell;
					}
				}

				private ColorCellAccessibleObject[] cells;

				internal ColorPalette ColorPalette => (ColorPalette)base.Owner;

				public ColorPaletteAccessibleObject(ColorPalette owner)
					: base(owner)
				{
					cells = new ColorCellAccessibleObject[64];
				}

				public override int GetChildCount()
				{
					return 64;
				}

				public override AccessibleObject GetChild(int id)
				{
					if (id < 0 || id >= 64)
					{
						return null;
					}
					if (cells[id] == null)
					{
						cells[id] = new ColorCellAccessibleObject(this, ColorPalette.GetColorFromCell(id), id);
					}
					return cells[id];
				}

				public override AccessibleObject HitTest(int x, int y)
				{
					NativeMethods.POINT pOINT = new NativeMethods.POINT(x, y);
					UnsafeNativeMethods.ScreenToClient(new HandleRef(ColorPalette, ColorPalette.Handle), pOINT);
					int cellFromLocationMouse = GetCellFromLocationMouse(pOINT.x, pOINT.y);
					if (cellFromLocationMouse != -1)
					{
						return GetChild(cellFromLocationMouse);
					}
					return base.HitTest(x, y);
				}
			}

			public const int CELLS_ACROSS = 8;

			public const int CELLS_DOWN = 8;

			public const int CELLS_CUSTOM = 16;

			public const int CELLS = 64;

			public const int CELL_SIZE = 16;

			public const int MARGIN = 8;

			private static readonly int[] staticCells = new int[48]
			{
				16777215, 12632319, 12640511, 12648447, 12648384, 16777152, 16761024, 16761087, 14737632, 8421631,
				8438015, 8454143, 8454016, 16777088, 16744576, 16744703, 12632256, 255, 33023, 65535,
				65280, 16776960, 16711680, 16711935, 8421504, 192, 16576, 49344, 49152, 12632064,
				12582912, 12583104, 4210752, 128, 16512, 32896, 32768, 8421376, 8388608, 8388736,
				0, 64, 4210816, 16448, 16384, 4210688, 4194304, 4194368
			};

			private Color[] staticColors;

			private Color selectedColor;

			private Point focus = new Point(0, 0);

			private Color[] customColors;

			private EventHandler onPicked;

			private ColorUI colorUI;

			public Color[] CustomColors => customColors;

			internal int FocusedCell => Get1DFrom2D(focus);

			public Color SelectedColor
			{
				get
				{
					return selectedColor;
				}
				set
				{
					if (!value.Equals(selectedColor))
					{
						InvalidateSelection();
						selectedColor = value;
						SetFocus(GetCellFromColor(value));
						InvalidateSelection();
					}
				}
			}

			public event EventHandler Picked
			{
				add
				{
					onPicked = (EventHandler)Delegate.Combine(onPicked, value);
				}
				remove
				{
					onPicked = (EventHandler)Delegate.Remove(onPicked, value);
				}
			}

			public ColorPalette(ColorUI colorUI, Color[] customColors)
			{
				this.colorUI = colorUI;
				SetStyle(ControlStyles.Opaque, value: true);
				BackColor = SystemColors.Control;
				base.Size = new Size(202, 202);
				staticColors = new Color[48];
				for (int i = 0; i < staticCells.Length; i++)
				{
					ref Color reference = ref staticColors[i];
					reference = ColorTranslator.FromOle(staticCells[i]);
				}
				this.customColors = customColors;
			}

			protected override AccessibleObject CreateAccessibilityInstance()
			{
				return new ColorPaletteAccessibleObject(this);
			}

			protected void OnPicked(EventArgs e)
			{
				if (onPicked != null)
				{
					onPicked(this, e);
				}
			}

			private static void FillRectWithCellBounds(int across, int down, ref Rectangle rect)
			{
				rect.X = 8 + across * 24;
				rect.Y = 8 + down * 24;
				rect.Width = 16;
				rect.Height = 16;
			}

			private Point GetCellFromColor(Color c)
			{
				for (int i = 0; i < 8; i++)
				{
					for (int j = 0; j < 8; j++)
					{
						if (GetColorFromCell(j, i).Equals(c))
						{
							return new Point(j, i);
						}
					}
				}
				return Point.Empty;
			}

			private Color GetColorFromCell(int across, int down)
			{
				return GetColorFromCell(Get1DFrom2D(across, down));
			}

			private Color GetColorFromCell(int index)
			{
				if (index < 48)
				{
					return staticColors[index];
				}
				return customColors[index - 64 + 16];
			}

			private static Point GetCell2DFromLocationMouse(int x, int y)
			{
				int num = x / 24;
				int num2 = y / 24;
				if (num < 0 || num2 < 0 || num >= 8 || num2 >= 8)
				{
					return new Point(-1, -1);
				}
				if (x - 24 * num < 8 || y - 24 * num2 < 8)
				{
					return new Point(-1, -1);
				}
				return new Point(num, num2);
			}

			private static int GetCellFromLocationMouse(int x, int y)
			{
				return Get1DFrom2D(GetCell2DFromLocationMouse(x, y));
			}

			private static int Get1DFrom2D(Point pt)
			{
				return Get1DFrom2D(pt.X, pt.Y);
			}

			private static int Get1DFrom2D(int x, int y)
			{
				if (x == -1 || y == -1)
				{
					return -1;
				}
				return x + 8 * y;
			}

			internal static Point Get2DFrom1D(int cell)
			{
				int num = cell % 8;
				int num2 = cell / 8;
				return new Point(num, num2);
			}

			private void InvalidateSelection()
			{
				for (int i = 0; i < 8; i++)
				{
					for (int j = 0; j < 8; j++)
					{
						if (SelectedColor.Equals(GetColorFromCell(j, i)))
						{
							Rectangle rect = default(Rectangle);
							FillRectWithCellBounds(j, i, ref rect);
							Invalidate(Rectangle.Inflate(rect, 5, 5));
							break;
						}
					}
				}
			}

			private void InvalidateFocus()
			{
				Rectangle rect = default(Rectangle);
				FillRectWithCellBounds(focus.X, focus.Y, ref rect);
				Invalidate(Rectangle.Inflate(rect, 5, 5));
				UnsafeNativeMethods.NotifyWinEvent(32773, new HandleRef(this, base.Handle), -4, 1 + Get1DFrom2D(focus.X, focus.Y));
			}

			protected override bool IsInputKey(Keys keyData)
			{
				switch (keyData)
				{
				case Keys.Return:
				case Keys.Left:
				case Keys.Up:
				case Keys.Right:
				case Keys.Down:
					return true;
				case Keys.F2:
					return false;
				default:
					return base.IsInputKey(keyData);
				}
			}

			protected virtual void LaunchDialog(int customIndex)
			{
				Invalidate();
				colorUI.EditorService.CloseDropDown();
				CustomColorDialog customColorDialog = new CustomColorDialog();
				IntPtr intPtr = UnsafeNativeMethods.GetFocus();
				try
				{
					DialogResult dialogResult = customColorDialog.ShowDialog();
					if (dialogResult != DialogResult.Cancel)
					{
						_ = customColorDialog.Color;
						ref Color reference = ref customColors[customIndex];
						reference = customColorDialog.Color;
						SelectedColor = customColors[customIndex];
						OnPicked(EventArgs.Empty);
					}
					customColorDialog.Dispose();
				}
				finally
				{
					if (intPtr != IntPtr.Zero)
					{
						UnsafeNativeMethods.SetFocus(new HandleRef(null, intPtr));
					}
				}
			}

			protected override void OnGotFocus(EventArgs e)
			{
				base.OnGotFocus(e);
				InvalidateFocus();
			}

			protected override void OnKeyDown(KeyEventArgs e)
			{
				base.OnKeyDown(e);
				switch (e.KeyCode)
				{
				case Keys.Return:
					SelectedColor = GetColorFromCell(focus.X, focus.Y);
					InvalidateFocus();
					OnPicked(EventArgs.Empty);
					break;
				case Keys.Space:
					SelectedColor = GetColorFromCell(focus.X, focus.Y);
					InvalidateFocus();
					break;
				case Keys.Left:
					SetFocus(new Point(focus.X - 1, focus.Y));
					break;
				case Keys.Right:
					SetFocus(new Point(focus.X + 1, focus.Y));
					break;
				case Keys.Up:
					SetFocus(new Point(focus.X, focus.Y - 1));
					break;
				case Keys.Down:
					SetFocus(new Point(focus.X, focus.Y + 1));
					break;
				}
			}

			protected override void OnLostFocus(EventArgs e)
			{
				base.OnLostFocus(e);
				InvalidateFocus();
			}

			protected override void OnMouseDown(MouseEventArgs me)
			{
				base.OnMouseDown(me);
				if (me.Button == MouseButtons.Left)
				{
					Point cell2DFromLocationMouse = GetCell2DFromLocationMouse(me.X, me.Y);
					if (cell2DFromLocationMouse.X != -1 && cell2DFromLocationMouse.Y != -1 && cell2DFromLocationMouse != focus)
					{
						SetFocus(cell2DFromLocationMouse);
					}
				}
			}

			protected override void OnMouseMove(MouseEventArgs me)
			{
				base.OnMouseMove(me);
				if (me.Button == MouseButtons.Left && base.Bounds.Contains(me.X, me.Y))
				{
					Point cell2DFromLocationMouse = GetCell2DFromLocationMouse(me.X, me.Y);
					if (cell2DFromLocationMouse.X != -1 && cell2DFromLocationMouse.Y != -1 && cell2DFromLocationMouse != focus)
					{
						SetFocus(cell2DFromLocationMouse);
					}
				}
			}

			protected override void OnMouseUp(MouseEventArgs me)
			{
				base.OnMouseUp(me);
				if (me.Button == MouseButtons.Left)
				{
					Point cell2DFromLocationMouse = GetCell2DFromLocationMouse(me.X, me.Y);
					if (cell2DFromLocationMouse.X != -1 && cell2DFromLocationMouse.Y != -1)
					{
						SetFocus(cell2DFromLocationMouse);
						SelectedColor = GetColorFromCell(focus.X, focus.Y);
						OnPicked(EventArgs.Empty);
					}
				}
				else if (me.Button == MouseButtons.Right)
				{
					int cellFromLocationMouse = GetCellFromLocationMouse(me.X, me.Y);
					if (cellFromLocationMouse != -1 && cellFromLocationMouse >= 48 && cellFromLocationMouse < 64)
					{
						LaunchDialog(cellFromLocationMouse - 64 + 16);
					}
				}
			}

			protected override void OnPaint(PaintEventArgs pe)
			{
				Graphics graphics = pe.Graphics;
				graphics.FillRectangle(new SolidBrush(BackColor), base.ClientRectangle);
				Rectangle rect = default(Rectangle);
				rect.Width = 16;
				rect.Height = 16;
				rect.X = 8;
				rect.Y = 8;
				bool flag = false;
				for (int i = 0; i < 8; i++)
				{
					for (int j = 0; j < 8; j++)
					{
						Color colorFromCell = GetColorFromCell(Get1DFrom2D(j, i));
						FillRectWithCellBounds(j, i, ref rect);
						if (colorFromCell.Equals(SelectedColor) && !flag)
						{
							ControlPaint.DrawBorder(graphics, Rectangle.Inflate(rect, 3, 3), SystemColors.ControlText, ButtonBorderStyle.Solid);
							flag = true;
						}
						if (focus.X == j && focus.Y == i && Focused)
						{
							ControlPaint.DrawFocusRectangle(graphics, Rectangle.Inflate(rect, 5, 5), SystemColors.ControlText, SystemColors.Control);
						}
						ControlPaint.DrawBorder(graphics, Rectangle.Inflate(rect, 2, 2), SystemColors.Control, 2, ButtonBorderStyle.Inset, SystemColors.Control, 2, ButtonBorderStyle.Inset, SystemColors.Control, 2, ButtonBorderStyle.Inset, SystemColors.Control, 2, ButtonBorderStyle.Inset);
						PaintValue(colorFromCell, graphics, rect);
					}
				}
			}

			private static void PaintValue(Color color, Graphics g, Rectangle rect)
			{
				g.FillRectangle(new SolidBrush(color), rect);
			}

			protected override bool ProcessDialogKey(Keys keyData)
			{
				if (keyData == Keys.F2)
				{
					int num = Get1DFrom2D(focus.X, focus.Y);
					if (num >= 48 && num < 64)
					{
						LaunchDialog(num - 64 + 16);
						return true;
					}
				}
				return base.ProcessDialogKey(keyData);
			}

			private void SetFocus(Point newFocus)
			{
				if (newFocus.X < 0)
				{
					newFocus.X = 0;
				}
				if (newFocus.Y < 0)
				{
					newFocus.Y = 0;
				}
				if (newFocus.X >= 8)
				{
					newFocus.X = 7;
				}
				if (newFocus.Y >= 8)
				{
					newFocus.Y = 7;
				}
				if (focus != newFocus)
				{
					InvalidateFocus();
					focus = newFocus;
					InvalidateFocus();
				}
			}
		}

		private class ColorUI : Control
		{
			private class ColorEditorListBox : ListBox
			{
				protected override bool IsInputKey(Keys keyData)
				{
					if (keyData == Keys.Return)
					{
						return true;
					}
					return base.IsInputKey(keyData);
				}
			}

			private class ColorEditorTabControl : TabControl
			{
				protected override void OnGotFocus(EventArgs e)
				{
					TabPage selectedTab = base.SelectedTab;
					if (selectedTab != null && selectedTab.Controls.Count > 0)
					{
						selectedTab.Controls[0].Focus();
					}
				}
			}

			private ColorEditor editor;

			private IWindowsFormsEditorService edSvc;

			private object value;

			private ColorEditorTabControl tabControl;

			private TabPage systemTabPage;

			private TabPage commonTabPage;

			private TabPage paletteTabPage;

			private ListBox lbSystem;

			private ListBox lbCommon;

			private ColorPalette pal;

			private object[] systemColorConstants;

			private object[] colorConstants;

			private Color[] customColors;

			private bool commonHeightSet;

			private bool systemHeightSet;

			private object[] ColorValues
			{
				get
				{
					if (colorConstants == null)
					{
						colorConstants = GetConstants(typeof(Color));
					}
					return colorConstants;
				}
			}

			private Color[] CustomColors
			{
				get
				{
					if (customColors == null)
					{
						customColors = new Color[16];
						for (int i = 0; i < 16; i++)
						{
							ref Color reference = ref customColors[i];
							reference = Color.White;
						}
					}
					return customColors;
				}
				set
				{
					customColors = value;
					pal = null;
				}
			}

			public IWindowsFormsEditorService EditorService => edSvc;

			private object[] SystemColorValues
			{
				get
				{
					if (systemColorConstants == null)
					{
						systemColorConstants = GetConstants(typeof(SystemColors));
					}
					return systemColorConstants;
				}
			}

			public object Value => value;

			public ColorUI(ColorEditor editor)
			{
				this.editor = editor;
				InitializeComponent();
				AdjustListBoxItemHeight();
			}

			public void End()
			{
				edSvc = null;
				value = null;
			}

			private void AdjustColorUIHeight()
			{
				Size size = pal.Size;
				Rectangle tabRect = tabControl.GetTabRect(0);
				int num = 0;
				base.Size = new Size(size.Width + 2 * num, size.Height + 2 * num + tabRect.Height);
				tabControl.Size = base.Size;
			}

			private void AdjustListBoxItemHeight()
			{
				lbSystem.ItemHeight = Font.Height + 2;
				lbCommon.ItemHeight = Font.Height + 2;
			}

			private Color GetBestColor(Color color)
			{
				object[] colorValues = ColorValues;
				int num = color.ToArgb();
				for (int i = 0; i < colorValues.Length; i++)
				{
					if (((Color)colorValues[i]).ToArgb() == num)
					{
						return (Color)colorValues[i];
					}
				}
				return color;
			}

			private static object[] GetConstants(Type enumType)
			{
				MethodAttributes methodAttributes = MethodAttributes.Public | MethodAttributes.Static;
				PropertyInfo[] properties = enumType.GetProperties();
				ArrayList arrayList = new ArrayList();
				foreach (PropertyInfo propertyInfo in properties)
				{
					if (propertyInfo.PropertyType == typeof(Color))
					{
						MethodInfo getMethod = propertyInfo.GetGetMethod();
						if (getMethod != null && (getMethod.Attributes & methodAttributes) == methodAttributes)
						{
							object[] index = null;
							arrayList.Add(propertyInfo.GetValue(null, index));
						}
					}
				}
				return arrayList.ToArray();
			}

			private void InitializeComponent()
			{
				this.paletteTabPage = new System.Windows.Forms.TabPage(System.Drawing.Design.SR.GetString("ColorEditorPaletteTab"));
				this.commonTabPage = new System.Windows.Forms.TabPage(System.Drawing.Design.SR.GetString("ColorEditorStandardTab"));
				this.systemTabPage = new System.Windows.Forms.TabPage(System.Drawing.Design.SR.GetString("ColorEditorSystemTab"));
				base.AccessibleName = System.Drawing.Design.SR.GetString("ColorEditorAccName");
				this.tabControl = new System.Drawing.Design.ColorEditor.ColorUI.ColorEditorTabControl();
				this.tabControl.TabPages.Add(this.paletteTabPage);
				this.tabControl.TabPages.Add(this.commonTabPage);
				this.tabControl.TabPages.Add(this.systemTabPage);
				this.tabControl.TabStop = false;
				this.tabControl.SelectedTab = this.systemTabPage;
				this.tabControl.SelectedIndexChanged += new System.EventHandler(OnTabControlSelChange);
				this.tabControl.Dock = System.Windows.Forms.DockStyle.Fill;
				this.tabControl.Resize += new System.EventHandler(OnTabControlResize);
				this.lbSystem = new System.Drawing.Design.ColorEditor.ColorUI.ColorEditorListBox();
				this.lbSystem.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
				this.lbSystem.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
				this.lbSystem.IntegralHeight = false;
				this.lbSystem.Sorted = false;
				this.lbSystem.Click += new System.EventHandler(OnListClick);
				this.lbSystem.DrawItem += new System.Windows.Forms.DrawItemEventHandler(OnListDrawItem);
				this.lbSystem.KeyDown += new System.Windows.Forms.KeyEventHandler(OnListKeyDown);
				this.lbSystem.Dock = System.Windows.Forms.DockStyle.Fill;
				this.lbSystem.FontChanged += new System.EventHandler(OnFontChanged);
				this.lbCommon = new System.Drawing.Design.ColorEditor.ColorUI.ColorEditorListBox();
				this.lbCommon.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
				this.lbCommon.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
				this.lbCommon.IntegralHeight = false;
				this.lbCommon.Sorted = false;
				this.lbCommon.Click += new System.EventHandler(OnListClick);
				this.lbCommon.DrawItem += new System.Windows.Forms.DrawItemEventHandler(OnListDrawItem);
				this.lbCommon.KeyDown += new System.Windows.Forms.KeyEventHandler(OnListKeyDown);
				this.lbCommon.Dock = System.Windows.Forms.DockStyle.Fill;
				System.Array.Sort(this.ColorValues, new System.Drawing.Design.ColorEditor.StandardColorComparer());
				System.Array.Sort(this.SystemColorValues, new System.Drawing.Design.ColorEditor.SystemColorComparer());
				this.lbCommon.Items.Clear();
				object[] colorValues = this.ColorValues;
				foreach (object item in colorValues)
				{
					this.lbCommon.Items.Add(item);
				}
				this.lbSystem.Items.Clear();
				object[] systemColorValues = this.SystemColorValues;
				foreach (object item2 in systemColorValues)
				{
					this.lbSystem.Items.Add(item2);
				}
				this.pal = new System.Drawing.Design.ColorEditor.ColorPalette(this, this.CustomColors);
				this.pal.Picked += new System.EventHandler(OnPalettePick);
				this.paletteTabPage.Controls.Add(this.pal);
				this.systemTabPage.Controls.Add(this.lbSystem);
				this.commonTabPage.Controls.Add(this.lbCommon);
				base.Controls.Add(this.tabControl);
			}

			protected override void OnGotFocus(EventArgs e)
			{
				base.OnGotFocus(e);
				OnTabControlSelChange(this, EventArgs.Empty);
			}

			private void OnFontChanged(object sender, EventArgs e)
			{
				commonHeightSet = (systemHeightSet = false);
			}

			private void OnListClick(object sender, EventArgs e)
			{
				ListBox listBox = (ListBox)sender;
				if (listBox.SelectedItem != null)
				{
					value = (Color)listBox.SelectedItem;
				}
				edSvc.CloseDropDown();
			}

			private void OnListDrawItem(object sender, DrawItemEventArgs die)
			{
				ListBox listBox = (ListBox)sender;
				object obj = listBox.Items[die.Index];
				Font font = Font;
				if (listBox == lbCommon && !commonHeightSet)
				{
					listBox.ItemHeight = listBox.Font.Height;
					commonHeightSet = true;
				}
				else if (listBox == lbSystem && !systemHeightSet)
				{
					listBox.ItemHeight = listBox.Font.Height;
					systemHeightSet = true;
				}
				Graphics graphics = die.Graphics;
				die.DrawBackground();
				editor.PaintValue(obj, graphics, new Rectangle(die.Bounds.X + 2, die.Bounds.Y + 2, 22, die.Bounds.Height - 4));
				graphics.DrawRectangle(SystemPens.WindowText, new Rectangle(die.Bounds.X + 2, die.Bounds.Y + 2, 21, die.Bounds.Height - 4 - 1));
				Brush brush = new SolidBrush(die.ForeColor);
				graphics.DrawString(((Color)obj).Name, font, brush, die.Bounds.X + 26, die.Bounds.Y);
				brush.Dispose();
			}

			private void OnListKeyDown(object sender, KeyEventArgs ke)
			{
				if (ke.KeyCode == Keys.Return)
				{
					OnListClick(sender, EventArgs.Empty);
				}
			}

			private void OnPalettePick(object sender, EventArgs e)
			{
				ColorPalette colorPalette = (ColorPalette)sender;
				value = GetBestColor(colorPalette.SelectedColor);
				edSvc.CloseDropDown();
			}

			protected override void OnFontChanged(EventArgs e)
			{
				base.OnFontChanged(e);
				AdjustListBoxItemHeight();
				AdjustColorUIHeight();
			}

			private void OnTabControlResize(object sender, EventArgs e)
			{
				Rectangle clientRectangle = tabControl.TabPages[0].ClientRectangle;
				Rectangle tabRect = tabControl.GetTabRect(1);
				clientRectangle.Y = 0;
				clientRectangle.Height -= clientRectangle.Y;
				int num = 2;
				lbSystem.SetBounds(num, clientRectangle.Y + 2 * num, clientRectangle.Width - num, pal.Size.Height - tabRect.Height + 2 * num);
				lbCommon.Bounds = lbSystem.Bounds;
				pal.Location = new Point(0, clientRectangle.Y);
			}

			private void OnTabControlSelChange(object sender, EventArgs e)
			{
				TabPage selectedTab = tabControl.SelectedTab;
				if (selectedTab != null && selectedTab.Controls.Count > 0)
				{
					selectedTab.Controls[0].Focus();
				}
			}

			protected override bool ProcessDialogKey(Keys keyData)
			{
				if ((keyData & Keys.Alt) == 0 && (keyData & Keys.Control) == 0 && (keyData & Keys.KeyCode) == Keys.Tab)
				{
					bool flag = (keyData & Keys.Shift) == 0;
					int selectedIndex = tabControl.SelectedIndex;
					if (selectedIndex != -1)
					{
						int count = tabControl.TabPages.Count;
						selectedIndex = ((!flag) ? ((selectedIndex + count - 1) % count) : ((selectedIndex + 1) % count));
						tabControl.SelectedTab = tabControl.TabPages[selectedIndex];
						return true;
					}
				}
				return base.ProcessDialogKey(keyData);
			}

			public void Start(IWindowsFormsEditorService edSvc, object value)
			{
				this.edSvc = edSvc;
				this.value = value;
				AdjustColorUIHeight();
				if (value == null)
				{
					return;
				}
				object[] colorValues = ColorValues;
				TabPage tabPage = paletteTabPage;
				for (int i = 0; i < colorValues.Length; i++)
				{
					if (colorValues[i].Equals(value))
					{
						lbCommon.SelectedItem = value;
						tabPage = commonTabPage;
						break;
					}
				}
				if (tabPage == paletteTabPage)
				{
					colorValues = SystemColorValues;
					for (int j = 0; j < colorValues.Length; j++)
					{
						if (colorValues[j].Equals(value))
						{
							lbSystem.SelectedItem = value;
							tabPage = systemTabPage;
							break;
						}
					}
				}
				tabControl.SelectedTab = tabPage;
			}
		}

		private class CustomColorDialog : ColorDialog
		{
			private const int COLOR_HUE = 703;

			private const int COLOR_SAT = 704;

			private const int COLOR_LUM = 705;

			private const int COLOR_RED = 706;

			private const int COLOR_GREEN = 707;

			private const int COLOR_BLUE = 708;

			private const int COLOR_ADD = 712;

			private const int COLOR_MIX = 719;

			private IntPtr hInstance;

			protected override IntPtr Instance => hInstance;

			protected override int Options => 66;

			public CustomColorDialog()
			{
				Stream manifestResourceStream = typeof(ColorEditor).Module.Assembly.GetManifestResourceStream(typeof(ColorEditor), "colordlg.data");
				int num = (int)(manifestResourceStream.Length - manifestResourceStream.Position);
				byte[] array = new byte[num];
				manifestResourceStream.Read(array, 0, num);
				hInstance = Marshal.AllocHGlobal(num);
				Marshal.Copy(array, 0, hInstance, num);
			}

			protected override void Dispose(bool disposing)
			{
				try
				{
					if (hInstance != IntPtr.Zero)
					{
						Marshal.FreeHGlobal(hInstance);
						hInstance = IntPtr.Zero;
					}
				}
				finally
				{
					base.Dispose(disposing);
				}
			}

			protected override IntPtr HookProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam)
			{
				switch (msg)
				{
				case 272:
				{
					NativeMethods.SendDlgItemMessage(hwnd, 703, 211, (IntPtr)3, IntPtr.Zero);
					NativeMethods.SendDlgItemMessage(hwnd, 704, 211, (IntPtr)3, IntPtr.Zero);
					NativeMethods.SendDlgItemMessage(hwnd, 705, 211, (IntPtr)3, IntPtr.Zero);
					NativeMethods.SendDlgItemMessage(hwnd, 706, 211, (IntPtr)3, IntPtr.Zero);
					NativeMethods.SendDlgItemMessage(hwnd, 707, 211, (IntPtr)3, IntPtr.Zero);
					NativeMethods.SendDlgItemMessage(hwnd, 708, 211, (IntPtr)3, IntPtr.Zero);
					IntPtr dlgItem = NativeMethods.GetDlgItem(hwnd, 719);
					NativeMethods.EnableWindow(dlgItem, enable: false);
					NativeMethods.SetWindowPos(dlgItem, IntPtr.Zero, 0, 0, 0, 0, 128);
					dlgItem = NativeMethods.GetDlgItem(hwnd, 1);
					NativeMethods.EnableWindow(dlgItem, enable: false);
					NativeMethods.SetWindowPos(dlgItem, IntPtr.Zero, 0, 0, 0, 0, 128);
					base.Color = Color.Empty;
					break;
				}
				case 273:
				{
					int num = NativeMethods.Util.LOWORD((int)wParam);
					if (num == 712)
					{
						bool[] err = new bool[1];
						byte red = (byte)NativeMethods.GetDlgItemInt(hwnd, 706, err, signed: false);
						byte green = (byte)NativeMethods.GetDlgItemInt(hwnd, 707, err, signed: false);
						byte blue = (byte)NativeMethods.GetDlgItemInt(hwnd, 708, err, signed: false);
						base.Color = Color.FromArgb(red, green, blue);
						NativeMethods.PostMessage(hwnd, 273, (IntPtr)NativeMethods.Util.MAKELONG(1, 0), NativeMethods.GetDlgItem(hwnd, 1));
					}
					break;
				}
				}
				return base.HookProc(hwnd, msg, wParam, lParam);
			}
		}

		private class SystemColorComparer : IComparer
		{
			public int Compare(object x, object y)
			{
				return string.Compare(((Color)x).Name, ((Color)y).Name, ignoreCase: false, CultureInfo.InvariantCulture);
			}
		}

		private class StandardColorComparer : IComparer
		{
			public int Compare(object x, object y)
			{
				Color color = (Color)x;
				Color color2 = (Color)y;
				if (color.A < color2.A)
				{
					return -1;
				}
				if (color.A > color2.A)
				{
					return 1;
				}
				if (color.GetHue() < color2.GetHue())
				{
					return -1;
				}
				if (color.GetHue() > color2.GetHue())
				{
					return 1;
				}
				if (color.GetSaturation() < color2.GetSaturation())
				{
					return -1;
				}
				if (color.GetSaturation() > color2.GetSaturation())
				{
					return 1;
				}
				if (color.GetBrightness() < color2.GetBrightness())
				{
					return -1;
				}
				if (color.GetBrightness() > color2.GetBrightness())
				{
					return 1;
				}
				return 0;
			}
		}

		private ColorUI colorUI;

		public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			if (provider != null)
			{
				IWindowsFormsEditorService windowsFormsEditorService = (IWindowsFormsEditorService)provider.GetService(typeof(IWindowsFormsEditorService));
				if (windowsFormsEditorService != null)
				{
					if (colorUI == null)
					{
						colorUI = new ColorUI(this);
					}
					colorUI.Start(windowsFormsEditorService, value);
					windowsFormsEditorService.DropDownControl(colorUI);
					if (colorUI.Value != null && (Color)colorUI.Value != Color.Empty)
					{
						value = colorUI.Value;
					}
					colorUI.End();
				}
			}
			return value;
		}

		public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.DropDown;
		}

		public override bool GetPaintValueSupported(ITypeDescriptorContext context)
		{
			return true;
		}

		public override void PaintValue(PaintValueEventArgs e)
		{
			if (e.Value is Color)
			{
				Color color = (Color)e.Value;
				SolidBrush solidBrush = new SolidBrush(color);
				e.Graphics.FillRectangle(solidBrush, e.Bounds);
				solidBrush.Dispose();
			}
		}
	}
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
	public class ContentAlignmentEditor : UITypeEditor
	{
		private class ContentUI : Control
		{
			private IWindowsFormsEditorService edSvc;

			private object value;

			private RadioButton topLeft = new RadioButton();

			private RadioButton topCenter = new RadioButton();

			private RadioButton topRight = new RadioButton();

			private RadioButton middleLeft = new RadioButton();

			private RadioButton middleCenter = new RadioButton();

			private RadioButton middleRight = new RadioButton();

			private RadioButton bottomLeft = new RadioButton();

			private RadioButton bottomCenter = new RadioButton();

			private RadioButton bottomRight = new RadioButton();

			private ContentAlignment Align
			{
				get
				{
					if (topLeft.Checked)
					{
						return ContentAlignment.TopLeft;
					}
					if (topCenter.Checked)
					{
						return ContentAlignment.TopCenter;
					}
					if (topRight.Checked)
					{
						return ContentAlignment.TopRight;
					}
					if (middleLeft.Checked)
					{
						return ContentAlignment.MiddleLeft;
					}
					if (middleCenter.Checked)
					{
						return ContentAlignment.MiddleCenter;
					}
					if (middleRight.Checked)
					{
						return ContentAlignment.MiddleRight;
					}
					if (bottomLeft.Checked)
					{
						return ContentAlignment.BottomLeft;
					}
					if (bottomCenter.Checked)
					{
						return ContentAlignment.BottomCenter;
					}
					return ContentAlignment.BottomRight;
				}
				set
				{
					switch (value)
					{
					case ContentAlignment.TopLeft:
						topLeft.Checked = true;
						break;
					case ContentAlignment.TopCenter:
						topCenter.Checked = true;
						break;
					case ContentAlignment.TopRight:
						topRight.Checked = true;
						break;
					case ContentAlignment.MiddleLeft:
						middleLeft.Checked = true;
						break;
					case ContentAlignment.MiddleCenter:
						middleCenter.Checked = true;
						break;
					case ContentAlignment.MiddleRight:
						middleRight.Checked = true;
						break;
					case ContentAlignment.BottomLeft:
						bottomLeft.Checked = true;
						break;
					case ContentAlignment.BottomCenter:
						bottomCenter.Checked = true;
						break;
					case ContentAlignment.BottomRight:
						bottomRight.Checked = true;
						break;
					}
				}
			}

			protected internal override bool ShowFocusCues
			{
				protected get
				{
					return true;
				}
			}

			public object Value => value;

			private RadioButton CheckedControl
			{
				get
				{
					for (int i = 0; i < base.Controls.Count; i++)
					{
						if (base.Controls[i] is RadioButton && ((RadioButton)base.Controls[i]).Checked)
						{
							return (RadioButton)base.Controls[i];
						}
					}
					return middleLeft;
				}
				set
				{
					CheckedControl.Checked = false;
					value.Checked = true;
					if (value.IsHandleCreated)
					{
						UnsafeNativeMethods.NotifyWinEvent(32773, new HandleRef(value, value.Handle), -4, 0);
					}
				}
			}

			public ContentUI()
			{
				InitComponent();
			}

			public void End()
			{
				edSvc = null;
				value = null;
			}

			private void InitComponent()
			{
				base.Size = new Size(125, 89);
				BackColor = SystemColors.Control;
				ForeColor = SystemColors.ControlText;
				base.AccessibleName = SR.GetString("ContentAlignmentEditorAccName");
				topLeft.Size = new Size(24, 25);
				topLeft.TabIndex = 8;
				topLeft.Text = "";
				topLeft.Appearance = Appearance.Button;
				topLeft.Click += OptionClick;
				topLeft.AccessibleName = SR.GetString("ContentAlignmentEditorTopLeftAccName");
				topCenter.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
				topCenter.Location = new Point(32, 0);
				topCenter.Size = new Size(59, 25);
				topCenter.TabIndex = 0;
				topCenter.Text = "";
				topCenter.Appearance = Appearance.Button;
				topCenter.Click += OptionClick;
				topCenter.AccessibleName = SR.GetString("ContentAlignmentEditorTopCenterAccName");
				topRight.Anchor = AnchorStyles.Top | AnchorStyles.Right;
				topRight.Location = new Point(99, 0);
				topRight.Size = new Size(24, 25);
				topRight.TabIndex = 1;
				topRight.Text = "";
				topRight.Appearance = Appearance.Button;
				topRight.Click += OptionClick;
				topRight.AccessibleName = SR.GetString("ContentAlignmentEditorTopRightAccName");
				middleLeft.Location = new Point(0, 32);
				middleLeft.Size = new Size(24, 25);
				middleLeft.TabIndex = 2;
				middleLeft.Text = "";
				middleLeft.Appearance = Appearance.Button;
				middleLeft.Click += OptionClick;
				middleLeft.AccessibleName = SR.GetString("ContentAlignmentEditorMiddleLeftAccName");
				middleCenter.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
				middleCenter.Location = new Point(32, 32);
				middleCenter.Size = new Size(59, 25);
				middleCenter.TabIndex = 3;
				middleCenter.Text = "";
				middleCenter.Appearance = Appearance.Button;
				middleCenter.Click += OptionClick;
				middleCenter.AccessibleName = SR.GetString("ContentAlignmentEditorMiddleCenterAccName");
				middleRight.Anchor = AnchorStyles.Top | AnchorStyles.Right;
				middleRight.Location = new Point(99, 32);
				middleRight.Size = new Size(24, 25);
				middleRight.TabIndex = 4;
				middleRight.Text = "";
				middleRight.Appearance = Appearance.Button;
				middleRight.Click += OptionClick;
				middleRight.AccessibleName = SR.GetString("ContentAlignmentEditorMiddleRightAccName");
				bottomLeft.Location = new Point(0, 64);
				bottomLeft.Size = new Size(24, 25);
				bottomLeft.TabIndex = 5;
				bottomLeft.Text = "";
				bottomLeft.Appearance = Appearance.Button;
				bottomLeft.Click += OptionClick;
				bottomLeft.AccessibleName = SR.GetString("ContentAlignmentEditorBottomLeftAccName");
				bottomCenter.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
				bottomCenter.Location = new Point(32, 64);
				bottomCenter.Size = new Size(59, 25);
				bottomCenter.TabIndex = 6;
				bottomCenter.Text = "";
				bottomCenter.Appearance = Appearance.Button;
				bottomCenter.Click += OptionClick;
				bottomCenter.AccessibleName = SR.GetString("ContentAlignmentEditorBottomCenterAccName");
				bottomRight.Anchor = AnchorStyles.Top | AnchorStyles.Right;
				bottomRight.Location = new Point(99, 64);
				bottomRight.Size = new Size(24, 25);
				bottomRight.TabIndex = 7;
				bottomRight.Text = "";
				bottomRight.Appearance = Appearance.Button;
				bottomRight.Click += OptionClick;
				bottomRight.AccessibleName = SR.GetString("ContentAlignmentEditorBottomRightAccName");
				base.Controls.Clear();
				base.Controls.AddRange(new Control[9] { bottomRight, bottomCenter, bottomLeft, middleRight, middleCenter, middleLeft, topRight, topCenter, topLeft });
			}

			protected override bool IsInputKey(Keys keyData)
			{
				switch (keyData)
				{
				case Keys.Left:
				case Keys.Up:
				case Keys.Right:
				case Keys.Down:
					return false;
				default:
					return base.IsInputKey(keyData);
				}
			}

			private void OptionClick(object sender, EventArgs e)
			{
				value = Align;
				edSvc.CloseDropDown();
			}

			public void Start(IWindowsFormsEditorService edSvc, object value)
			{
				this.edSvc = edSvc;
				this.value = value;
				ContentAlignment contentAlignment2 = (Align = ((value != null) ? ((ContentAlignment)value) : ContentAlignment.MiddleLeft));
			}

			protected override bool ProcessDialogKey(Keys keyData)
			{
				RadioButton checkedControl = CheckedControl;
				if ((keyData & Keys.KeyCode) == Keys.Left)
				{
					if (checkedControl == bottomRight)
					{
						CheckedControl = bottomCenter;
					}
					else if (checkedControl == middleRight)
					{
						CheckedControl = middleCenter;
					}
					else if (checkedControl == topRight)
					{
						CheckedControl = topCenter;
					}
					else if (checkedControl == bottomCenter)
					{
						CheckedControl = bottomLeft;
					}
					else if (checkedControl == middleCenter)
					{
						CheckedControl = middleLeft;
					}
					else if (checkedControl == topCenter)
					{
						CheckedControl = topLeft;
					}
					return true;
				}
				if ((keyData & Keys.KeyCode) == Keys.Right)
				{
					if (checkedControl == bottomLeft)
					{
						CheckedControl = bottomCenter;
					}
					else if (checkedControl == middleLeft)
					{
						CheckedControl = middleCenter;
					}
					else if (checkedControl == topLeft)
					{
						CheckedControl = topCenter;
					}
					else if (checkedControl == bottomCenter)
					{
						CheckedControl = bottomRight;
					}
					else if (checkedControl == middleCenter)
					{
						CheckedControl = middleRight;
					}
					else if (checkedControl == topCenter)
					{
						CheckedControl = topRight;
					}
					return true;
				}
				if ((keyData & Keys.KeyCode) == Keys.Up)
				{
					if (checkedControl == bottomRight)
					{
						CheckedControl = middleRight;
					}
					else if (checkedControl == middleRight)
					{
						CheckedControl = topRight;
					}
					else if (checkedControl == bottomCenter)
					{
						CheckedControl = middleCenter;
					}
					else if (checkedControl == middleCenter)
					{
						CheckedControl = topCenter;
					}
					else if (checkedControl == bottomLeft)
					{
						CheckedControl = middleLeft;
					}
					else if (checkedControl == middleLeft)
					{
						CheckedControl = topLeft;
					}
					return true;
				}
				if ((keyData & Keys.KeyCode) == Keys.Down)
				{
					if (checkedControl == topRight)
					{
						CheckedControl = middleRight;
					}
					else if (checkedControl == middleRight)
					{
						CheckedControl = bottomRight;
					}
					else if (checkedControl == topCenter)
					{
						CheckedControl = middleCenter;
					}
					else if (checkedControl == middleCenter)
					{
						CheckedControl = bottomCenter;
					}
					else if (checkedControl == topLeft)
					{
						CheckedControl = middleLeft;
					}
					else if (checkedControl == middleLeft)
					{
						CheckedControl = bottomLeft;
					}
					return true;
				}
				if ((keyData & Keys.KeyCode) == Keys.Space)
				{
					OptionClick(this, EventArgs.Empty);
					return true;
				}
				if ((keyData & Keys.KeyCode) == Keys.Return && (keyData & (Keys.Control | Keys.Alt)) == 0)
				{
					OptionClick(this, EventArgs.Empty);
					return true;
				}
				if ((keyData & Keys.KeyCode) == Keys.Escape && (keyData & (Keys.Control | Keys.Alt)) == 0)
				{
					edSvc.CloseDropDown();
					return true;
				}
				if ((keyData & Keys.KeyCode) == Keys.Tab && (keyData & (Keys.Control | Keys.Alt)) == 0)
				{
					int num = CheckedControl.TabIndex + (((keyData & Keys.Shift) == 0) ? 1 : (-1));
					if (num < 0)
					{
						num = base.Controls.Count - 1;
					}
					else if (num >= base.Controls.Count)
					{
						num = 0;
					}
					for (int i = 0; i < base.Controls.Count; i++)
					{
						if (base.Controls[i] is RadioButton && base.Controls[i].TabIndex == num)
						{
							CheckedControl = (RadioButton)base.Controls[i];
							return true;
						}
					}
					return true;
				}
				return base.ProcessDialogKey(keyData);
			}
		}

		private ContentUI contentUI;

		public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			if (provider != null)
			{
				IWindowsFormsEditorService windowsFormsEditorService = (IWindowsFormsEditorService)provider.GetService(typeof(IWindowsFormsEditorService));
				if (windowsFormsEditorService != null)
				{
					if (contentUI == null)
					{
						contentUI = new ContentUI();
					}
					contentUI.Start(windowsFormsEditorService, value);
					windowsFormsEditorService.DropDownControl(contentUI);
					value = contentUI.Value;
					contentUI.End();
				}
			}
			return value;
		}

		public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.DropDown;
		}
	}
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
	public class CursorEditor : UITypeEditor
	{
		private class CursorUI : ListBox
		{
			private object value;

			private IWindowsFormsEditorService edSvc;

			private TypeConverter cursorConverter;

			private UITypeEditor editor;

			public object Value => value;

			public CursorUI(UITypeEditor editor)
			{
				this.editor = editor;
				base.Height = 310;
				ItemHeight = Math.Max(4 + Cursors.Default.Size.Height, Font.Height);
				DrawMode = DrawMode.OwnerDrawFixed;
				base.BorderStyle = BorderStyle.None;
				cursorConverter = TypeDescriptor.GetConverter(typeof(Cursor));
				if (!cursorConverter.GetStandardValuesSupported())
				{
					return;
				}
				foreach (object standardValue in cursorConverter.GetStandardValues())
				{
					base.Items.Add(standardValue);
				}
			}

			public void End()
			{
				edSvc = null;
				value = null;
			}

			protected override void OnClick(EventArgs e)
			{
				base.OnClick(e);
				value = base.SelectedItem;
				edSvc.CloseDropDown();
			}

			protected override void OnDrawItem(DrawItemEventArgs die)
			{
				base.OnDrawItem(die);
				if (die.Index != -1)
				{
					Cursor cursor = (Cursor)base.Items[die.Index];
					string s = cursorConverter.ConvertToString(cursor);
					Font font = die.Font;
					Brush brush = new SolidBrush(die.ForeColor);
					die.DrawBackground();
					die.Graphics.FillRectangle(SystemBrushes.Control, new Rectangle(die.Bounds.X + 2, die.Bounds.Y + 2, 32, die.Bounds.Height - 4));
					die.Graphics.DrawRectangle(SystemPens.WindowText, new Rectangle(die.Bounds.X + 2, die.Bounds.Y + 2, 31, die.Bounds.Height - 4 - 1));
					cursor.DrawStretched(die.Graphics, new Rectangle(die.Bounds.X + 2, die.Bounds.Y + 2, 32, die.Bounds.Height - 4));
					die.Graphics.DrawString(s, font, brush, die.Bounds.X + 36, die.Bounds.Y + (die.Bounds.Height - font.Height) / 2);
					brush.Dispose();
				}
			}

			protected override bool ProcessDialogKey(Keys keyData)
			{
				if ((keyData & Keys.KeyCode) == Keys.Return && (keyData & (Keys.Control | Keys.Alt)) == 0)
				{
					OnClick(EventArgs.Empty);
					return true;
				}
				return base.ProcessDialogKey(keyData);
			}

			public void Start(IWindowsFormsEditorService edSvc, object value)
			{
				this.edSvc = edSvc;
				this.value = value;
				if (value == null)
				{
					return;
				}
				for (int i = 0; i < base.Items.Count; i++)
				{
					if (base.Items[i] == value)
					{
						SelectedIndex = i;
						break;
					}
				}
			}
		}

		private CursorUI cursorUI;

		public override bool IsDropDownResizable => true;

		public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			if (provider != null)
			{
				IWindowsFormsEditorService windowsFormsEditorService = (IWindowsFormsEditorService)provider.GetService(typeof(IWindowsFormsEditorService));
				if (windowsFormsEditorService != null)
				{
					if (cursorUI == null)
					{
						cursorUI = new CursorUI(this);
					}
					cursorUI.Start(windowsFormsEditorService, value);
					windowsFormsEditorService.DropDownControl(cursorUI);
					value = cursorUI.Value;
					cursorUI.End();
				}
			}
			return value;
		}

		public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.DropDown;
		}
	}
	internal sealed class DesignerToolboxInfo : IDisposable
	{
		private ToolboxService _toolboxService;

		private IDesignerHost _host;

		private ISelectionService _selectionService;

		private ArrayList _filter;

		private IDesigner _filterDesigner;

		private IToolboxUser _toolboxUser;

		private Hashtable _attributeHash;

		internal IDesignerHost DesignerHost => _host;

		internal ICollection Filter
		{
			get
			{
				if (_filter == null)
				{
					Update();
				}
				return _filter;
			}
		}

		internal IToolboxUser ToolboxUser
		{
			get
			{
				if (_toolboxUser == null)
				{
					Update();
				}
				return _toolboxUser;
			}
		}

		internal DesignerToolboxInfo(ToolboxService toolboxService, IDesignerHost host)
		{
			_toolboxService = toolboxService;
			_host = host;
			_selectionService = host.GetService(typeof(ISelectionService)) as ISelectionService;
			if (_selectionService != null)
			{
				_selectionService.SelectionChanged += OnSelectionChanged;
			}
			if (_host.RootComponent != null)
			{
				_host.RootComponent.Disposed += OnDesignerDisposed;
			}
			TypeDescriptor.Refreshed += OnTypeDescriptorRefresh;
		}

		private void OnTypeDescriptorRefresh(RefreshEventArgs r)
		{
			if (r.ComponentChanged == _filterDesigner)
			{
				_filter = null;
				_filterDesigner = null;
			}
		}

		public AttributeCollection GetDesignerAttributes(IDesigner designer)
		{
			if (designer == null)
			{
				throw new ArgumentNullException("designer");
			}
			if (_attributeHash == null)
			{
				_attributeHash = new Hashtable();
			}
			else
			{
				_attributeHash.Clear();
			}
			if (!(designer is ITreeDesigner))
			{
				IComponent rootComponent = _host.RootComponent;
				if (rootComponent != null)
				{
					RecurseDesignerTree(_host.GetDesigner(rootComponent), _attributeHash);
				}
			}
			RecurseDesignerTree(designer, _attributeHash);
			Attribute[] array = new Attribute[_attributeHash.Values.Count];
			_attributeHash.Values.CopyTo(array, 0);
			return new AttributeCollection(array);
		}

		private void RecurseDesignerTree(IDesigner designer, Hashtable table)
		{
			if (designer is ITreeDesigner treeDesigner)
			{
				IDesigner parent = treeDesigner.Parent;
				if (parent != null)
				{
					RecurseDesignerTree(parent, table);
				}
			}
			foreach (Attribute attribute in TypeDescriptor.GetAttributes(designer))
			{
				table[attribute.TypeId] = attribute;
			}
		}

		private void OnDesignerDisposed(object sender, EventArgs e)
		{
			_host.RemoveService(typeof(DesignerToolboxInfo));
		}

		private void OnSelectionChanged(object sender, EventArgs e)
		{
			if (Update())
			{
				_toolboxService.OnDesignerInfoChanged(this);
			}
		}

		private bool Update()
		{
			bool result = false;
			IDesigner designer = null;
			if (_selectionService.PrimarySelection is IComponent component)
			{
				designer = _host.GetDesigner(component);
			}
			if (designer == null)
			{
				IComponent rootComponent = _host.RootComponent;
				if (rootComponent != null)
				{
					designer = _host.GetDesigner(rootComponent);
				}
			}
			if (designer != _filterDesigner)
			{
				ArrayList arrayList;
				if (designer != null)
				{
					AttributeCollection designerAttributes = GetDesignerAttributes(designer);
					arrayList = new ArrayList(designerAttributes.Count);
					foreach (Attribute item in designerAttributes)
					{
						if (item is ToolboxItemFilterAttribute)
						{
							arrayList.Add(item);
						}
					}
				}
				else
				{
					arrayList = new ArrayList();
				}
				if (_filter == null)
				{
					result = true;
				}
				else if (_filter.Count != arrayList.Count)
				{
					result = true;
				}
				else
				{
					IEnumerator enumerator2 = _filter.GetEnumerator();
					IEnumerator enumerator3 = arrayList.GetEnumerator();
					while (enumerator3.MoveNext())
					{
						enumerator2.MoveNext();
						if (!enumerator3.Current.Equals(enumerator2.Current))
						{
							result = true;
							break;
						}
						ToolboxItemFilterAttribute toolboxItemFilterAttribute = (ToolboxItemFilterAttribute)enumerator3.Current;
						if (toolboxItemFilterAttribute.FilterType == ToolboxItemFilterType.Custom)
						{
							result = true;
							break;
						}
					}
				}
				_filter = arrayList;
				_filterDesigner = designer;
				_toolboxUser = _filterDesigner as IToolboxUser;
				if (_toolboxUser == null)
				{
					ITreeDesigner treeDesigner = _filterDesigner as ITreeDesigner;
					while (_toolboxUser == null && treeDesigner != null)
					{
						IDesigner parent = treeDesigner.Parent;
						_toolboxUser = parent as IToolboxUser;
						treeDesigner = parent as ITreeDesigner;
					}
				}
				if (_toolboxUser == null && _host.RootComponent != null)
				{
					_toolboxUser = _host.GetDesigner(_host.RootComponent) as IToolboxUser;
				}
			}
			if (_filter == null)
			{
				_filter = new ArrayList();
			}
			return result;
		}

		void IDisposable.Dispose()
		{
			if (_selectionService != null)
			{
				_selectionService.SelectionChanged -= OnSelectionChanged;
			}
			if (_host.RootComponent != null)
			{
				_host.RootComponent.Disposed -= OnDesignerDisposed;
			}
			TypeDescriptor.Refreshed -= OnTypeDescriptorRefresh;
		}
	}
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	[PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
	public class FontEditor : UITypeEditor
	{
		private FontDialog fontDialog;

		private object value;

		public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			this.value = value;
			if (provider != null)
			{
				IWindowsFormsEditorService windowsFormsEditorService = (IWindowsFormsEditorService)provider.GetService(typeof(IWindowsFormsEditorService));
				if (windowsFormsEditorService != null)
				{
					if (fontDialog == null)
					{
						fontDialog = new FontDialog();
						fontDialog.ShowApply = false;
						fontDialog.ShowColor = false;
						fontDialog.AllowVerticalFonts = false;
					}
					if (value is Font font)
					{
						fontDialog.Font = font;
					}
					IntPtr focus = UnsafeNativeMethods.GetFocus();
					try
					{
						if (fontDialog.ShowDialog() == DialogResult.OK)
						{
							this.value = fontDialog.Font;
						}
					}
					finally
					{
						if (focus != IntPtr.Zero)
						{
							UnsafeNativeMethods.SetFocus(new HandleRef(null, focus));
						}
					}
				}
			}
			value = this.value;
			this.value = null;
			return value;
		}

		public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.Modal;
		}
	}
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
	public class FontNameEditor : UITypeEditor
	{
		public override bool GetPaintValueSupported(ITypeDescriptorContext context)
		{
			return true;
		}

		public override void PaintValue(PaintValueEventArgs e)
		{
			if (!(e.Value is string text) || text == "")
			{
				return;
			}
			e.Graphics.FillRectangle(SystemBrushes.ActiveCaption, e.Bounds);
			FontFamily fontFamily = null;
			try
			{
				fontFamily = new FontFamily(text);
			}
			catch
			{
			}
			if (fontFamily != null)
			{
				try
				{
					DrawFontSample(e, fontFamily, FontStyle.Regular);
				}
				catch
				{
					try
					{
						DrawFontSample(e, fontFamily, FontStyle.Italic);
					}
					catch
					{
						try
						{
							DrawFontSample(e, fontFamily, FontStyle.Bold);
							goto end_IL_005c;
						}
						catch
						{
							try
							{
								DrawFontSample(e, fontFamily, FontStyle.Bold | FontStyle.Italic);
								goto end_IL_005c;
							}
							catch
							{
								goto end_IL_005c;
							}
						}
						end_IL_005c:;
					}
				}
			}
			e.Graphics.DrawLine(SystemPens.WindowFrame, e.Bounds.Right, e.Bounds.Y, e.Bounds.Right, e.Bounds.Bottom);
		}

		private static void DrawFontSample(PaintValueEventArgs e, FontFamily fontFamily, FontStyle fontStyle)
		{
			float emSize = (float)((double)e.Bounds.Height / 1.2);
			Font font = new Font(fontFamily, emSize, fontStyle, GraphicsUnit.Pixel);
			if (font == null)
			{
				return;
			}
			try
			{
				e.Graphics.DrawString("abcd", font, SystemBrushes.ActiveCaptionText, e.Bounds);
			}
			finally
			{
				font.Dispose();
			}
		}
	}
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	public class IconEditor : UITypeEditor
	{
		internal static Type[] imageExtenders = new Type[0];

		internal FileDialog fileDialog;

		protected static string CreateExtensionsString(string[] extensions, string sep)
		{
			if (extensions == null || extensions.Length == 0)
			{
				return null;
			}
			string text = null;
			for (int i = 0; i < extensions.Length - 1; i++)
			{
				text = text + "*." + extensions[i] + sep;
			}
			return text + "*." + extensions[extensions.Length - 1];
		}

		protected static string CreateFilterEntry(IconEditor e)
		{
			string fileDialogDescription = e.GetFileDialogDescription();
			string text = CreateExtensionsString(e.GetExtensions(), ",");
			string text2 = CreateExtensionsString(e.GetExtensions(), ";");
			return fileDialogDescription + "(" + text + ")|" + text2;
		}

		public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			if (provider != null)
			{
				IWindowsFormsEditorService windowsFormsEditorService = (IWindowsFormsEditorService)provider.GetService(typeof(IWindowsFormsEditorService));
				if (windowsFormsEditorService != null)
				{
					if (fileDialog == null)
					{
						fileDialog = new OpenFileDialog();
						string filter = CreateFilterEntry(this);
						for (int i = 0; i < imageExtenders.Length; i++)
						{
						}
						fileDialog.Filter = filter;
					}
					IntPtr focus = UnsafeNativeMethods.GetFocus();
					try
					{
						if (fileDialog.ShowDialog() == DialogResult.OK)
						{
							FileStream stream = new FileStream(fileDialog.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
							value = LoadFromStream(stream);
							return value;
						}
						return value;
					}
					finally
					{
						if (focus != IntPtr.Zero)
						{
							UnsafeNativeMethods.SetFocus(new HandleRef(null, focus));
						}
					}
				}
			}
			return value;
		}

		public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.Modal;
		}

		protected virtual string GetFileDialogDescription()
		{
			return SR.GetString("iconFileDescription");
		}

		protected virtual string[] GetExtensions()
		{
			return new string[1] { "ico" };
		}

		public override bool GetPaintValueSupported(ITypeDescriptorContext context)
		{
			return true;
		}

		protected virtual Icon LoadFromStream(Stream stream)
		{
			return new Icon(stream);
		}

		public override void PaintValue(PaintValueEventArgs e)
		{
			if (e.Value is Icon icon)
			{
				_ = icon.Size;
				Rectangle bounds = e.Bounds;
				if (icon.Width < bounds.Width)
				{
					bounds.X = (bounds.Width - icon.Width) / 2;
					bounds.Width = icon.Width;
				}
				if (icon.Height < bounds.Height)
				{
					bounds.X = (bounds.Height - icon.Height) / 2;
					bounds.Height = icon.Height;
				}
				e.Graphics.DrawIcon(icon, bounds);
			}
		}
	}
	[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
	public class MetafileEditor : ImageEditor
	{
		protected override string GetFileDialogDescription()
		{
			return SR.GetString("metafileFileDescription");
		}

		protected override string[] GetExtensions()
		{
			return new string[2] { "emf", "wmf" };
		}

		protected override Image LoadFromStream(Stream stream)
		{
			return new Metafile(stream);
		}
	}
	internal class NativeMethods
	{
		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public class Util
		{
			private Util()
			{
			}

			public static int MAKELONG(int low, int high)
			{
				return (high << 16) | (low & 0xFFFF);
			}

			public static int MAKELPARAM(int low, int high)
			{
				return (high << 16) | (low & 0xFFFF);
			}

			public static int HIWORD(int n)
			{
				return (n >> 16) & 0xFFFF;
			}

			public static int LOWORD(int n)
			{
				return n & 0xFFFF;
			}

			public static int SignedHIWORD(int n)
			{
				int num = (short)((n >> 16) & 0xFFFF);
				num <<= 16;
				return num >> 16;
			}

			public static int SignedLOWORD(int n)
			{
				int num = (short)(n & 0xFFFF);
				num <<= 16;
				return num >> 16;
			}

			[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
			private static extern int lstrlen(string s);

			[DllImport("user32.dll", CharSet = CharSet.Auto)]
			internal static extern int RegisterWindowMessage(string msg);
		}

		[StructLayout(LayoutKind.Sequential)]
		public class POINT
		{
			public int x;

			public int y;

			public POINT()
			{
			}

			public POINT(int x, int y)
			{
				this.x = x;
				this.y = y;
			}
		}

		public const int EM_GETSEL = 176;

		public const int EM_SETSEL = 177;

		public const int EM_GETRECT = 178;

		public const int EM_SETRECT = 179;

		public const int EM_SETRECTNP = 180;

		public const int EM_SCROLL = 181;

		public const int EM_LINESCROLL = 182;

		public const int EM_SCROLLCARET = 183;

		public const int EM_GETMODIFY = 184;

		public const int EM_SETMODIFY = 185;

		public const int EM_GETLINECOUNT = 186;

		public const int EM_LINEINDEX = 187;

		public const int EM_SETHANDLE = 188;

		public const int EM_GETHANDLE = 189;

		public const int EM_GETTHUMB = 190;

		public const int EM_LINELENGTH = 193;

		public const int EM_REPLACESEL = 194;

		public const int EM_GETLINE = 196;

		public const int EM_LIMITTEXT = 197;

		public const int EM_CANUNDO = 198;

		public const int EM_UNDO = 199;

		public const int EM_FMTLINES = 200;

		public const int EM_LINEFROMCHAR = 201;

		public const int EM_SETTABSTOPS = 203;

		public const int EM_SETPASSWORDCHAR = 204;

		public const int EM_EMPTYUNDOBUFFER = 205;

		public const int EM_GETFIRSTVISIBLELINE = 206;

		public const int EM_SETREADONLY = 207;

		public const int EM_SETWORDBREAKPROC = 208;

		public const int EM_GETWORDBREAKPROC = 209;

		public const int EM_GETPASSWORDCHAR = 210;

		public const int EM_SETMARGINS = 211;

		public const int EM_GETMARGINS = 212;

		public const int EM_SETLIMITTEXT = 197;

		public const int EM_GETLIMITTEXT = 213;

		public const int EM_POSFROMCHAR = 214;

		public const int EM_CHARFROMPOS = 215;

		public const int EC_LEFTMARGIN = 1;

		public const int EC_RIGHTMARGIN = 2;

		public const int EC_USEFONTINFO = 65535;

		public const int IDOK = 1;

		public const int IDCANCEL = 2;

		public const int IDABORT = 3;

		public const int IDRETRY = 4;

		public const int IDIGNORE = 5;

		public const int IDYES = 6;

		public const int IDNO = 7;

		public const int IDCLOSE = 8;

		public const int IDHELP = 9;

		public const int WM_INITDIALOG = 272;

		public const int SWP_NOSIZE = 1;

		public const int SWP_NOMOVE = 2;

		public const int SWP_NOZORDER = 4;

		public const int SWP_NOREDRAW = 8;

		public const int SWP_NOACTIVATE = 16;

		public const int SWP_FRAMECHANGED = 32;

		public const int SWP_SHOWWINDOW = 64;

		public const int SWP_HIDEWINDOW = 128;

		public const int SWP_NOCOPYBITS = 256;

		public const int SWP_NOOWNERZORDER = 512;

		public const int SWP_NOSENDCHANGING = 1024;

		public const int SWP_DRAWFRAME = 32;

		public const int SWP_NOREPOSITION = 512;

		public const int SWP_DEFERERASE = 8192;

		public const int SWP_ASYNCWINDOWPOS = 16384;

		public const int WM_COMMAND = 273;

		public const int CC_FULLOPEN = 2;

		public const int CC_PREVENTFULLOPEN = 4;

		public const int CC_SHOWHELP = 8;

		public const int CC_ENABLEHOOK = 16;

		public const int CC_ENABLETEMPLATE = 32;

		public const int CC_ENABLETEMPLATEHANDLE = 64;

		public const int CC_SOLIDCOLOR = 128;

		public const int CC_ANYCOLOR = 256;

		public static IntPtr InvalidIntPtr = (IntPtr)(-1);

		private NativeMethods()
		{
		}

		[DllImport("user32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr SendDlgItemMessage(IntPtr hDlg, int nIDDlgItem, int Msg, IntPtr wParam, IntPtr lParam);

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern IntPtr GetDlgItem(IntPtr hWnd, int nIDDlgItem);

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern bool EnableWindow(IntPtr hWnd, bool enable);

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, int flags);

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern int GetDlgItemInt(IntPtr hWnd, int nIDDlgItem, bool[] err, bool signed);

		[DllImport("user32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr PostMessage(IntPtr hwnd, int msg, IntPtr wparam, IntPtr lparam);
	}
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	[PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
	public abstract class ToolboxService : IToolboxService, IComponentDiscoveryService
	{
		private class DomainProxyObject : MarshalByRefObject
		{
			internal byte[] GetToolboxItems(AssemblyName an, bool throwOnError)
			{
				Assembly assembly = null;
				try
				{
					assembly = Assembly.Load(an);
				}
				catch (FileNotFoundException)
				{
				}
				catch (BadImageFormatException)
				{
				}
				catch (IOException)
				{
				}
				if (assembly == null && an.CodeBase != null)
				{
					assembly = Assembly.LoadFrom(new Uri(an.CodeBase).LocalPath);
				}
				if (assembly == null)
				{
					throw new ArgumentException(SR.GetString("ToolboxServiceAssemblyNotFound", an.FullName));
				}
				ICollection collection = null;
				try
				{
					collection = ToolboxService.GetToolboxItems(assembly, (string)null, throwOnError);
				}
				catch (Exception ex4)
				{
					if (ex4 is ReflectionTypeLoadException ex5)
					{
						throw new ReflectionTypeLoadException(null, ex5.LoaderExceptions, ex5.Message);
					}
					throw;
				}
				BinaryFormatter binaryFormatter = new BinaryFormatter();
				MemoryStream memoryStream = new MemoryStream();
				binaryFormatter.Serialize(memoryStream, collection);
				memoryStream.Close();
				return memoryStream.GetBuffer();
			}
		}

		private enum FilterSupport
		{
			NotSupported,
			Supported,
			Custom
		}

		private IDesignerEventService _designerEventService;

		private ArrayList _globalCreators;

		private Hashtable _designerCreators;

		private IDesignerHost _lastMergedHost;

		private ICollection _lastMergedCreators;

		private DesignerToolboxInfo _lastState;

		private static DomainProxyObject _domainObject;

		private static AppDomain _domain;

		private static ClientSponsor _domainObjectSponsor;

		protected abstract CategoryNameCollection CategoryNames { get; }

		protected abstract string SelectedCategory { get; set; }

		protected abstract ToolboxItemContainer SelectedItemContainer { get; set; }

		CategoryNameCollection IToolboxService.CategoryNames => CategoryNames;

		string IToolboxService.SelectedCategory
		{
			get
			{
				return SelectedCategory;
			}
			set
			{
				SelectedCategory = value;
			}
		}

		protected virtual ToolboxItemContainer CreateItemContainer(ToolboxItem item, IDesignerHost link)
		{
			if (item == null)
			{
				throw new ArgumentNullException("item");
			}
			if (link != null)
			{
				return null;
			}
			return new ToolboxItemContainer(item);
		}

		protected virtual ToolboxItemContainer CreateItemContainer(IDataObject dataObject)
		{
			if (dataObject == null)
			{
				throw new ArgumentNullException("dataObject");
			}
			return new ToolboxItemContainer(dataObject);
		}

		protected virtual void FilterChanged()
		{
		}

		private ICollection GetCreatorCollection(IDesignerHost host)
		{
			if (host == null)
			{
				return _globalCreators;
			}
			if (host != _lastMergedHost)
			{
				ICollection collection = _globalCreators;
				ICollection collection2 = null;
				if (_designerCreators != null && _designerCreators[host] is ICollection collection3)
				{
					int num = collection3.Count;
					if (collection != null)
					{
						num += collection.Count;
					}
					ToolboxItemCreator[] array = new ToolboxItemCreator[num];
					collection3.CopyTo(array, 0);
					collection?.CopyTo(array, collection3.Count);
					collection = array;
				}
				_lastMergedCreators = collection;
				_lastMergedHost = host;
			}
			return _lastMergedCreators;
		}

		private static FilterSupport GetFilterSupport(ICollection itemFilter, ICollection targetFilter)
		{
			FilterSupport filterSupport = FilterSupport.Supported;
			int num = 0;
			int num2 = 0;
			foreach (ToolboxItemFilterAttribute item in itemFilter)
			{
				if (filterSupport == FilterSupport.NotSupported)
				{
					break;
				}
				if (item.FilterType == ToolboxItemFilterType.Require)
				{
					num++;
					foreach (object item2 in targetFilter)
					{
						if (item2 is ToolboxItemFilterAttribute obj && item.Match(obj))
						{
							num2++;
							break;
						}
					}
				}
				else if (item.FilterType == ToolboxItemFilterType.Prevent)
				{
					foreach (object item3 in targetFilter)
					{
						if (item3 is ToolboxItemFilterAttribute obj2 && item.Match(obj2))
						{
							filterSupport = FilterSupport.NotSupported;
							break;
						}
					}
				}
				else
				{
					if (filterSupport == FilterSupport.Custom || item.FilterType != ToolboxItemFilterType.Custom)
					{
						continue;
					}
					if (item.FilterString.Length == 0)
					{
						filterSupport = FilterSupport.Custom;
						continue;
					}
					foreach (ToolboxItemFilterAttribute item4 in targetFilter)
					{
						if (item.FilterString.Equals(item4.FilterString))
						{
							filterSupport = FilterSupport.Custom;
							break;
						}
					}
				}
			}
			if (filterSupport != 0 && num > 0 && num2 == 0)
			{
				filterSupport = FilterSupport.NotSupported;
			}
			if (filterSupport != 0)
			{
				num = 0;
				num2 = 0;
				foreach (ToolboxItemFilterAttribute item5 in targetFilter)
				{
					if (filterSupport == FilterSupport.NotSupported)
					{
						break;
					}
					if (item5.FilterType == ToolboxItemFilterType.Require)
					{
						num++;
						foreach (ToolboxItemFilterAttribute item6 in itemFilter)
						{
							if (item5.Match(item6))
							{
								num2++;
								break;
							}
						}
					}
					else if (item5.FilterType == ToolboxItemFilterType.Prevent)
					{
						foreach (ToolboxItemFilterAttribute item7 in itemFilter)
						{
							if (item5.Match(item7))
							{
								filterSupport = FilterSupport.NotSupported;
								break;
							}
						}
					}
					else
					{
						if (filterSupport == FilterSupport.Custom || item5.FilterType != ToolboxItemFilterType.Custom)
						{
							continue;
						}
						if (item5.FilterString.Length == 0)
						{
							filterSupport = FilterSupport.Custom;
							continue;
						}
						foreach (ToolboxItemFilterAttribute item8 in itemFilter)
						{
							if (item5.FilterString.Equals(item8.FilterString))
							{
								filterSupport = FilterSupport.Custom;
								break;
							}
						}
					}
				}
				if (filterSupport != 0 && num > 0 && num2 == 0)
				{
					filterSupport = FilterSupport.NotSupported;
				}
			}
			return filterSupport;
		}

		protected abstract IList GetItemContainers();

		protected abstract IList GetItemContainers(string categoryName);

		public static ToolboxItem GetToolboxItem(Type toolType)
		{
			return GetToolboxItem(toolType, nonPublic: false);
		}

		public static ToolboxItem GetToolboxItem(Type toolType, bool nonPublic)
		{
			ToolboxItem toolboxItem = null;
			if (toolType == null)
			{
				throw new ArgumentNullException("toolType");
			}
			if ((nonPublic || toolType.IsPublic || toolType.IsNestedPublic) && typeof(IComponent).IsAssignableFrom(toolType) && !toolType.IsAbstract)
			{
				ToolboxItemAttribute toolboxItemAttribute = (ToolboxItemAttribute)TypeDescriptor.GetAttributes(toolType)[typeof(ToolboxItemAttribute)];
				if (!toolboxItemAttribute.IsDefaultAttribute())
				{
					Type toolboxItemType = toolboxItemAttribute.ToolboxItemType;
					if (toolboxItemType != null)
					{
						ConstructorInfo constructor = toolboxItemType.GetConstructor(new Type[1] { typeof(Type) });
						if (constructor != null && toolType != null)
						{
							toolboxItem = (ToolboxItem)constructor.Invoke(new object[1] { toolType });
						}
						else
						{
							constructor = toolboxItemType.GetConstructor(new Type[0]);
							if (constructor != null)
							{
								toolboxItem = (ToolboxItem)constructor.Invoke(new object[0]);
								toolboxItem.Initialize(toolType);
							}
						}
					}
				}
				else if (!toolboxItemAttribute.Equals(ToolboxItemAttribute.None) && !toolType.ContainsGenericParameters)
				{
					toolboxItem = new ToolboxItem(toolType);
				}
			}
			else if (typeof(ToolboxItem).IsAssignableFrom(toolType))
			{
				toolboxItem = (ToolboxItem)Activator.CreateInstance(toolType, nonPublic: true);
			}
			return toolboxItem;
		}

		public static ICollection GetToolboxItems(Assembly a, string newCodeBase)
		{
			return GetToolboxItems(a, newCodeBase, throwOnError: false);
		}

		public static ICollection GetToolboxItems(Assembly a, string newCodeBase, bool throwOnError)
		{
			if (a == null)
			{
				throw new ArgumentNullException("a");
			}
			ArrayList arrayList = new ArrayList();
			AssemblyName assemblyName;
			if (a.GlobalAssemblyCache)
			{
				assemblyName = a.GetName();
				assemblyName.CodeBase = newCodeBase;
			}
			else
			{
				assemblyName = null;
			}
			try
			{
				Type[] types = a.GetTypes();
				foreach (Type type in types)
				{
					if (!typeof(IComponent).IsAssignableFrom(type))
					{
						continue;
					}
					ConstructorInfo constructor = type.GetConstructor(new Type[0]);
					if (constructor == null)
					{
						constructor = type.GetConstructor(new Type[1] { typeof(IContainer) });
					}
					if (constructor == null)
					{
						continue;
					}
					try
					{
						ToolboxItem toolboxItem = GetToolboxItem(type);
						if (toolboxItem != null)
						{
							if (assemblyName != null)
							{
								toolboxItem.AssemblyName = assemblyName;
							}
							arrayList.Add(toolboxItem);
						}
					}
					catch
					{
						if (throwOnError)
						{
							throw;
						}
					}
				}
				return arrayList;
			}
			catch
			{
				if (throwOnError)
				{
					throw;
				}
				return arrayList;
			}
		}

		public static ICollection GetToolboxItems(AssemblyName an)
		{
			return GetToolboxItems(an, throwOnError: false);
		}

		public static ICollection GetToolboxItems(AssemblyName an, bool throwOnError)
		{
			if (_domainObject == null)
			{
				_domain = AppDomain.CreateDomain("Assembly Enumeration Domain");
				_domainObject = (DomainProxyObject)_domain.CreateInstanceAndUnwrap(typeof(DomainProxyObject).Assembly.FullName, typeof(DomainProxyObject).FullName);
				_domainObjectSponsor = new ClientSponsor(new TimeSpan(0, 5, 0));
				_domainObjectSponsor.Register(_domainObject);
			}
			byte[] toolboxItems = _domainObject.GetToolboxItems(an, throwOnError);
			BinaryFormatter binaryFormatter = new BinaryFormatter();
			return (ICollection)binaryFormatter.Deserialize(new MemoryStream(toolboxItems));
		}

		protected virtual bool IsItemContainer(IDataObject dataObject, IDesignerHost host)
		{
			if (dataObject == null)
			{
				throw new ArgumentNullException("dataObject");
			}
			if (ToolboxItemContainer.ContainsFormat(dataObject))
			{
				return true;
			}
			ICollection creatorCollection = GetCreatorCollection(host);
			if (creatorCollection != null)
			{
				foreach (ToolboxItemCreator item in creatorCollection)
				{
					if (dataObject.GetDataPresent(item.Format))
					{
						return true;
					}
				}
			}
			return false;
		}

		protected bool IsItemContainerSupported(ToolboxItemContainer container, IDesignerHost host)
		{
			if (container == null)
			{
				throw new ArgumentNullException("container");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			ICollection creatorCollection = GetCreatorCollection(host);
			_lastState = host.GetService(typeof(DesignerToolboxInfo)) as DesignerToolboxInfo;
			if (_lastState == null)
			{
				_lastState = new DesignerToolboxInfo(this, host);
				host.AddService(typeof(DesignerToolboxInfo), _lastState);
			}
			switch (GetFilterSupport(container.GetFilter(creatorCollection), _lastState.Filter))
			{
			case FilterSupport.NotSupported:
				return false;
			case FilterSupport.Supported:
				return true;
			case FilterSupport.Custom:
				if (_lastState.ToolboxUser != null)
				{
					return _lastState.ToolboxUser.GetToolSupported(container.GetToolboxItem(creatorCollection));
				}
				break;
			}
			return false;
		}

		internal void OnDesignerInfoChanged(DesignerToolboxInfo state)
		{
			if (_designerEventService == null)
			{
				_designerEventService = state.DesignerHost.GetService(typeof(IDesignerEventService)) as IDesignerEventService;
			}
			if (_designerEventService != null && _designerEventService.ActiveDesigner == state.DesignerHost)
			{
				FilterChanged();
			}
		}

		protected abstract void Refresh();

		protected virtual void SelectedItemContainerUsed()
		{
			SelectedItemContainer = null;
		}

		protected virtual bool SetCursor()
		{
			if (SelectedItemContainer != null)
			{
				Cursor.Current = Cursors.Cross;
				return true;
			}
			return false;
		}

		public static void UnloadToolboxItems()
		{
			if (_domain != null)
			{
				AppDomain domain = _domain;
				_domainObjectSponsor.Close();
				_domainObjectSponsor = null;
				_domainObject = null;
				_domain = null;
				AppDomain.Unload(domain);
			}
		}

		void IToolboxService.AddCreator(ToolboxItemCreatorCallback creator, string format)
		{
			if (creator == null)
			{
				throw new ArgumentNullException("creator");
			}
			if (format == null)
			{
				throw new ArgumentNullException("format");
			}
			if (_globalCreators == null)
			{
				_globalCreators = new ArrayList();
			}
			_globalCreators.Add(new ToolboxItemCreator(creator, format));
			_lastMergedHost = null;
			_lastMergedCreators = null;
		}

		void IToolboxService.AddCreator(ToolboxItemCreatorCallback creator, string format, IDesignerHost host)
		{
			if (creator == null)
			{
				throw new ArgumentNullException("creator");
			}
			if (format == null)
			{
				throw new ArgumentNullException("format");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			if (_designerCreators == null)
			{
				_designerCreators = new Hashtable();
			}
			ArrayList arrayList = _designerCreators[host] as ArrayList;
			if (arrayList == null)
			{
				arrayList = new ArrayList(4);
				_designerCreators[host] = arrayList;
			}
			arrayList.Add(new ToolboxItemCreator(creator, format));
			_lastMergedHost = null;
			_lastMergedCreators = null;
		}

		void IToolboxService.AddLinkedToolboxItem(ToolboxItem toolboxItem, IDesignerHost host)
		{
			if (toolboxItem == null)
			{
				throw new ArgumentNullException("toolboxItem");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			ToolboxItemContainer toolboxItemContainer = CreateItemContainer(toolboxItem, host);
			if (toolboxItemContainer != null)
			{
				GetItemContainers(SelectedCategory).Add(toolboxItemContainer);
			}
		}

		void IToolboxService.AddLinkedToolboxItem(ToolboxItem toolboxItem, string category, IDesignerHost host)
		{
			if (toolboxItem == null)
			{
				throw new ArgumentNullException("toolboxItem");
			}
			if (category == null)
			{
				throw new ArgumentNullException("category");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			ToolboxItemContainer toolboxItemContainer = CreateItemContainer(toolboxItem, host);
			if (toolboxItemContainer != null)
			{
				GetItemContainers(category).Add(toolboxItemContainer);
			}
		}

		void IToolboxService.AddToolboxItem(ToolboxItem toolboxItem)
		{
			if (toolboxItem == null)
			{
				throw new ArgumentNullException("toolboxItem");
			}
			ToolboxItemContainer toolboxItemContainer = CreateItemContainer(toolboxItem, null);
			if (toolboxItemContainer != null)
			{
				GetItemContainers(SelectedCategory).Add(toolboxItemContainer);
			}
		}

		void IToolboxService.AddToolboxItem(ToolboxItem toolboxItem, string category)
		{
			if (toolboxItem == null)
			{
				throw new ArgumentNullException("toolboxItem");
			}
			if (category == null)
			{
				throw new ArgumentNullException("category");
			}
			ToolboxItemContainer toolboxItemContainer = CreateItemContainer(toolboxItem, null);
			if (toolboxItemContainer != null)
			{
				GetItemContainers(category).Add(toolboxItemContainer);
			}
		}

		ToolboxItem IToolboxService.DeserializeToolboxItem(object serializedObject)
		{
			if (serializedObject == null)
			{
				throw new ArgumentNullException("serializedObject");
			}
			IDataObject dataObject = serializedObject as IDataObject;
			if (dataObject == null)
			{
				dataObject = new DataObject(serializedObject);
			}
			return CreateItemContainer(dataObject)?.GetToolboxItem(GetCreatorCollection(null));
		}

		ToolboxItem IToolboxService.DeserializeToolboxItem(object serializedObject, IDesignerHost host)
		{
			if (serializedObject == null)
			{
				throw new ArgumentNullException("serializedObject");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			IDataObject dataObject = serializedObject as IDataObject;
			if (dataObject == null)
			{
				dataObject = new DataObject(serializedObject);
			}
			return CreateItemContainer(dataObject)?.GetToolboxItem(GetCreatorCollection(host));
		}

		ToolboxItem IToolboxService.GetSelectedToolboxItem()
		{
			return SelectedItemContainer?.GetToolboxItem(GetCreatorCollection(null));
		}

		ToolboxItem IToolboxService.GetSelectedToolboxItem(IDesignerHost host)
		{
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			return SelectedItemContainer?.GetToolboxItem(GetCreatorCollection(host));
		}

		ToolboxItemCollection IToolboxService.GetToolboxItems()
		{
			IList itemContainers = GetItemContainers();
			ArrayList arrayList = new ArrayList(itemContainers.Count);
			ICollection creatorCollection = GetCreatorCollection(null);
			foreach (ToolboxItemContainer item in itemContainers)
			{
				ToolboxItem toolboxItem = item.GetToolboxItem(creatorCollection);
				if (toolboxItem != null)
				{
					arrayList.Add(toolboxItem);
				}
			}
			ToolboxItem[] array = new ToolboxItem[arrayList.Count];
			arrayList.CopyTo(array, 0);
			return new ToolboxItemCollection(array);
		}

		ToolboxItemCollection IToolboxService.GetToolboxItems(IDesignerHost host)
		{
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			IList itemContainers = GetItemContainers();
			ArrayList arrayList = new ArrayList(itemContainers.Count);
			ICollection creatorCollection = GetCreatorCollection(host);
			foreach (ToolboxItemContainer item in itemContainers)
			{
				ToolboxItem toolboxItem = item.GetToolboxItem(creatorCollection);
				if (toolboxItem != null)
				{
					arrayList.Add(toolboxItem);
				}
			}
			ToolboxItem[] array = new ToolboxItem[arrayList.Count];
			arrayList.CopyTo(array, 0);
			return new ToolboxItemCollection(array);
		}

		ToolboxItemCollection IToolboxService.GetToolboxItems(string category)
		{
			if (category == null)
			{
				throw new ArgumentNullException("category");
			}
			IList itemContainers = GetItemContainers(category);
			ArrayList arrayList = new ArrayList(itemContainers.Count);
			ICollection creatorCollection = GetCreatorCollection(null);
			foreach (ToolboxItemContainer item in itemContainers)
			{
				ToolboxItem toolboxItem = item.GetToolboxItem(creatorCollection);
				if (toolboxItem != null)
				{
					arrayList.Add(toolboxItem);
				}
			}
			ToolboxItem[] array = new ToolboxItem[arrayList.Count];
			arrayList.CopyTo(array, 0);
			return new ToolboxItemCollection(array);
		}

		ToolboxItemCollection IToolboxService.GetToolboxItems(string category, IDesignerHost host)
		{
			if (category == null)
			{
				throw new ArgumentNullException("category");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			IList itemContainers = GetItemContainers(category);
			ArrayList arrayList = new ArrayList(itemContainers.Count);
			ICollection creatorCollection = GetCreatorCollection(host);
			foreach (ToolboxItemContainer item in itemContainers)
			{
				ToolboxItem toolboxItem = item.GetToolboxItem(creatorCollection);
				if (toolboxItem != null)
				{
					arrayList.Add(toolboxItem);
				}
			}
			ToolboxItem[] array = new ToolboxItem[arrayList.Count];
			arrayList.CopyTo(array, 0);
			return new ToolboxItemCollection(array);
		}

		bool IToolboxService.IsSupported(object serializedObject, IDesignerHost host)
		{
			if (serializedObject == null)
			{
				throw new ArgumentNullException("serializedObject");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			IDataObject dataObject = serializedObject as IDataObject;
			if (dataObject == null)
			{
				dataObject = new DataObject(serializedObject);
			}
			if (!IsItemContainer(dataObject, host))
			{
				return false;
			}
			ToolboxItemContainer container = CreateItemContainer(dataObject);
			return IsItemContainerSupported(container, host);
		}

		bool IToolboxService.IsSupported(object serializedObject, ICollection filterAttributes)
		{
			if (serializedObject == null)
			{
				throw new ArgumentNullException("serializedObject");
			}
			if (filterAttributes == null)
			{
				throw new ArgumentNullException("filterAttributes");
			}
			IDataObject dataObject = serializedObject as IDataObject;
			if (dataObject == null)
			{
				dataObject = new DataObject(serializedObject);
			}
			if (!IsItemContainer(dataObject, null))
			{
				return false;
			}
			ToolboxItemContainer toolboxItemContainer = CreateItemContainer(dataObject);
			return GetFilterSupport(toolboxItemContainer.GetFilter(GetCreatorCollection(null)), filterAttributes) == FilterSupport.Supported;
		}

		bool IToolboxService.IsToolboxItem(object serializedObject)
		{
			if (serializedObject == null)
			{
				throw new ArgumentNullException("serializedObject");
			}
			IDataObject dataObject = serializedObject as IDataObject;
			if (dataObject == null)
			{
				dataObject = new DataObject(serializedObject);
			}
			return IsItemContainer(dataObject, null);
		}

		bool IToolboxService.IsToolboxItem(object serializedObject, IDesignerHost host)
		{
			if (serializedObject == null)
			{
				throw new ArgumentNullException("serializedObject");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			IDataObject dataObject = serializedObject as IDataObject;
			if (dataObject == null)
			{
				dataObject = new DataObject(serializedObject);
			}
			return IsItemContainer(dataObject, host);
		}

		void IToolboxService.Refresh()
		{
			Refresh();
		}

		void IToolboxService.RemoveCreator(string format)
		{
			if (format == null)
			{
				throw new ArgumentNullException("format");
			}
			if (_globalCreators == null)
			{
				return;
			}
			for (int i = 0; i < _globalCreators.Count; i++)
			{
				ToolboxItemCreator toolboxItemCreator = _globalCreators[i] as ToolboxItemCreator;
				if (toolboxItemCreator.Format.Equals(format))
				{
					_globalCreators.RemoveAt(i);
					_lastMergedHost = null;
					_lastMergedCreators = null;
					break;
				}
			}
		}

		void IToolboxService.RemoveCreator(string format, IDesignerHost host)
		{
			if (format == null)
			{
				throw new ArgumentNullException("format");
			}
			if (host == null)
			{
				throw new ArgumentNullException("host");
			}
			if (_designerCreators == null || !(_designerCreators[host] is ArrayList arrayList))
			{
				return;
			}
			for (int i = 0; i < arrayList.Count; i++)
			{
				ToolboxItemCreator toolboxItemCreator = arrayList[i] as ToolboxItemCreator;
				if (toolboxItemCreator.Format.Equals(format))
				{
					arrayList.RemoveAt(i);
					_lastMergedHost = null;
					_lastMergedCreators = null;
					break;
				}
			}
		}

		void IToolboxService.RemoveToolboxItem(ToolboxItem toolboxItem)
		{
			if (toolboxItem == null)
			{
				throw new ArgumentNullException("toolboxItem");
			}
			GetItemContainers().Remove(CreateItemContainer(toolboxItem, null));
		}

		void IToolboxService.RemoveToolboxItem(ToolboxItem toolboxItem, string category)
		{
			if (toolboxItem == null)
			{
				throw new ArgumentNullException("toolboxItem");
			}
			if (category == null)
			{
				throw new ArgumentNullException("category");
			}
			GetItemContainers(category).Remove(CreateItemContainer(toolboxItem, null));
		}

		void IToolboxService.SelectedToolboxItemUsed()
		{
			SelectedItemContainerUsed();
		}

		object IToolboxService.SerializeToolboxItem(ToolboxItem toolboxItem)
		{
			if (toolboxItem == null)
			{
				throw new ArgumentNullException("toolboxItem");
			}
			return CreateItemContainer(toolboxItem, null).ToolboxData;
		}

		bool IToolboxService.SetCursor()
		{
			return SetCursor();
		}

		void IToolboxService.SetSelectedToolboxItem(ToolboxItem toolboxItem)
		{
			if (toolboxItem != null)
			{
				SelectedItemContainer = CreateItemContainer(toolboxItem, null);
			}
			else
			{
				SelectedItemContainer = null;
			}
		}

		ICollection IComponentDiscoveryService.GetComponentTypes(IDesignerHost designerHost, Type baseType)
		{
			Hashtable hashtable = new Hashtable();
			ToolboxItemCollection toolboxItems = ((IToolboxService)this).GetToolboxItems();
			if (toolboxItems != null)
			{
				Type typeFromHandle = typeof(IComponent);
				foreach (ToolboxItem item in toolboxItems)
				{
					Type type = item.GetType(designerHost);
					if (type != null && typeFromHandle.IsAssignableFrom(type) && (baseType == null || baseType.IsAssignableFrom(type)))
					{
						hashtable[type] = type;
					}
				}
			}
			return hashtable.Values;
		}
	}
	public sealed class ToolboxItemCreator
	{
		private ToolboxItemCreatorCallback _callback;

		private string _format;

		public string Format => _format;

		internal ToolboxItemCreator(ToolboxItemCreatorCallback callback, string format)
		{
			_callback = callback;
			_format = format;
		}

		public ToolboxItem Create(IDataObject data)
		{
			return _callback(data, _format);
		}
	}
	[Serializable]
	public class ToolboxItemContainer : ISerializable
	{
		private class BrokenToolboxItem : ToolboxItem
		{
			private string _exceptionString;

			public BrokenToolboxItem(string exceptionString)
				: base(typeof(Component))
			{
				_exceptionString = exceptionString;
				Lock();
			}

			protected override IComponent[] CreateComponentsCore(IDesignerHost host)
			{
				if (_exceptionString != null)
				{
					throw new InvalidOperationException(SR.GetString("ToolboxServiceBadToolboxItemWithException", _exceptionString));
				}
				throw new InvalidOperationException(SR.GetString("ToolboxServiceBadToolboxItem"));
			}
		}

		[Serializable]
		private sealed class ToolboxItemSerializer : ISerializable
		{
			private const string _assemblyNameKey = "AssemblyName";

			private const string _streamKey = "Stream";

			private static BinaryFormatter _formatter;

			private ToolboxItem _toolboxItem;

			internal ToolboxItem ToolboxItem => _toolboxItem;

			internal ToolboxItemSerializer(ToolboxItem toolboxItem)
			{
				_toolboxItem = toolboxItem;
			}

			private ToolboxItemSerializer(SerializationInfo info, StreamingContext context)
			{
				AssemblyName name = (AssemblyName)info.GetValue("AssemblyName", typeof(AssemblyName));
				byte[] buffer = (byte[])info.GetValue("Stream", typeof(byte[]));
				if (_formatter == null)
				{
					_formatter = new BinaryFormatter();
				}
				SerializationBinder binder = _formatter.Binder;
				_formatter.Binder = new ToolboxSerializationBinder(name);
				try
				{
					_toolboxItem = (ToolboxItem)_formatter.Deserialize(new MemoryStream(buffer));
				}
				finally
				{
					_formatter.Binder = binder;
				}
			}

			void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
			{
				if (_formatter == null)
				{
					_formatter = new BinaryFormatter();
				}
				MemoryStream memoryStream = new MemoryStream();
				_formatter.Serialize(memoryStream, _toolboxItem);
				memoryStream.Close();
				info.AddValue("AssemblyName", _toolboxItem.GetType().Assembly.GetName());
				info.AddValue("Stream", memoryStream.GetBuffer());
			}
		}

		private class ToolboxSerializationBinder : SerializationBinder
		{
			private Hashtable _assemblies;

			private AssemblyName _name;

			private string _namePart;

			public ToolboxSerializationBinder(AssemblyName name)
			{
				_assemblies = new Hashtable();
				_name = name;
				_namePart = name.Name + ",";
			}

			public override Type BindToType(string assemblyName, string typeName)
			{
				Assembly assembly = (Assembly)_assemblies[assemblyName];
				if (assembly == null)
				{
					try
					{
						assembly = Assembly.Load(assemblyName);
					}
					catch (FileNotFoundException)
					{
					}
					catch (BadImageFormatException)
					{
					}
					catch (IOException)
					{
					}
					if (assembly == null)
					{
						AssemblyName assemblyName2;
						if (assemblyName.StartsWith(_namePart))
						{
							assemblyName2 = _name;
							try
							{
								assembly = Assembly.Load(assemblyName2);
							}
							catch (FileNotFoundException)
							{
							}
							catch (BadImageFormatException)
							{
							}
							catch (IOException)
							{
							}
						}
						else
						{
							assemblyName2 = new AssemblyName(assemblyName);
						}
						if (assembly == null)
						{
							string codeBase = assemblyName2.CodeBase;
							if (codeBase != null && codeBase.Length > 0 && File.Exists(codeBase))
							{
								assembly = Assembly.LoadFrom(codeBase);
							}
						}
					}
					if (assembly != null)
					{
						_assemblies[assemblyName] = assembly;
					}
				}
				return assembly?.GetType(typeName);
			}
		}

		private const string _localClipboardFormat = "CF_TOOLBOXITEMCONTAINER";

		private const string _itemClipboardFormat = "CF_TOOLBOXITEMCONTAINER_CONTENTS";

		private const string _hashClipboardFormat = "CF_TOOLBOXITEMCONTAINER_HASH";

		private const string _serializationFormats = "TbxIC_DataObjectFormats";

		private const string _serializationValues = "TbxIC_DataObjectValues";

		private const short _clipboardVersion = 1;

		private int _hashCode;

		private ToolboxItem _toolboxItem;

		private IDataObject _dataObject;

		private ICollection _filter;

		public bool IsCreated => _toolboxItem != null;

		public bool IsTransient
		{
			get
			{
				if (_toolboxItem != null)
				{
					return _toolboxItem.IsTransient;
				}
				return false;
			}
		}

		public virtual IDataObject ToolboxData
		{
			get
			{
				if (_dataObject == null)
				{
					MemoryStream memoryStream = new MemoryStream();
					DataObject dataObject = new DataObject();
					BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
					binaryWriter.Write((short)1);
					binaryWriter.Write((short)_filter.Count);
					foreach (ToolboxItemFilterAttribute item in _filter)
					{
						binaryWriter.Write(item.FilterString);
						binaryWriter.Write((short)item.FilterType);
					}
					binaryWriter.Flush();
					memoryStream.Close();
					dataObject.SetData("CF_TOOLBOXITEMCONTAINER", memoryStream.GetBuffer());
					dataObject.SetData("CF_TOOLBOXITEMCONTAINER_HASH", _hashCode);
					dataObject.SetData("CF_TOOLBOXITEMCONTAINER_CONTENTS", new ToolboxItemSerializer(_toolboxItem));
					_dataObject = dataObject;
				}
				return _dataObject;
			}
		}

		protected ToolboxItemContainer(SerializationInfo info, StreamingContext context)
		{
			string[] array = (string[])info.GetValue("TbxIC_DataObjectFormats", typeof(string[]));
			object[] array2 = (object[])info.GetValue("TbxIC_DataObjectValues", typeof(object[]));
			DataObject dataObject = new DataObject();
			for (int i = 0; i < array.Length; i++)
			{
				dataObject.SetData(array[i], array2[i]);
			}
			_dataObject = dataObject;
		}

		public ToolboxItemContainer(ToolboxItem item)
		{
			if (item == null)
			{
				throw new ArgumentNullException("item");
			}
			_toolboxItem = item;
			UpdateFilter(item);
			_hashCode = item.DisplayName.GetHashCode();
			if (item.AssemblyName != null)
			{
				_hashCode ^= item.AssemblyName.GetHashCode();
			}
			if (item.TypeName != null)
			{
				_hashCode ^= item.TypeName.GetHashCode();
			}
			if (_hashCode == 0)
			{
				_hashCode = item.DisplayName.GetHashCode();
			}
		}

		public ToolboxItemContainer(IDataObject data)
		{
			if (data == null)
			{
				throw new ArgumentNullException("data");
			}
			_dataObject = data;
		}

		public void UpdateFilter(ToolboxItem item)
		{
			_filter = MergeFilter(item);
		}

		internal static bool ContainsFormat(IDataObject dataObject)
		{
			return dataObject.GetDataPresent("CF_TOOLBOXITEMCONTAINER");
		}

		public override bool Equals(object obj)
		{
			ToolboxItemContainer toolboxItemContainer = obj as ToolboxItemContainer;
			if (toolboxItemContainer == this)
			{
				return true;
			}
			if (toolboxItemContainer == null)
			{
				return false;
			}
			if (_toolboxItem != null && toolboxItemContainer._toolboxItem != null && _toolboxItem.Equals(toolboxItemContainer._toolboxItem))
			{
				return true;
			}
			if (_dataObject != null && toolboxItemContainer._dataObject != null && _dataObject.Equals(toolboxItemContainer._dataObject))
			{
				return true;
			}
			ToolboxItem toolboxItem = GetToolboxItem(null);
			ToolboxItem toolboxItem2 = toolboxItemContainer.GetToolboxItem(null);
			if (toolboxItem != null && toolboxItem2 != null)
			{
				return toolboxItem.Equals(toolboxItem2);
			}
			return false;
		}

		public virtual ICollection GetFilter(ICollection creators)
		{
			ICollection filter = _filter;
			if (_filter == null)
			{
				if (_dataObject.GetDataPresent("CF_TOOLBOXITEMCONTAINER"))
				{
					byte[] array = (byte[])_dataObject.GetData("CF_TOOLBOXITEMCONTAINER");
					if (array != null)
					{
						BinaryReader binaryReader = new BinaryReader(new MemoryStream(array));
						short num = binaryReader.ReadInt16();
						if (num != 1)
						{
							_filter = new ToolboxItemFilterAttribute[0];
						}
						else
						{
							short num2 = binaryReader.ReadInt16();
							ToolboxItemFilterAttribute[] array2 = new ToolboxItemFilterAttribute[num2];
							for (short num3 = 0; num3 < num2; num3 = (short)(num3 + 1))
							{
								string filterString = binaryReader.ReadString();
								short filterType = binaryReader.ReadInt16();
								array2[num3] = new ToolboxItemFilterAttribute(filterString, (ToolboxItemFilterType)filterType);
							}
							_filter = array2;
						}
					}
					else
					{
						_filter = new ToolboxItemFilterAttribute[0];
					}
					filter = _filter;
				}
				else if (creators != null)
				{
					foreach (ToolboxItemCreator creator in creators)
					{
						if (_dataObject.GetDataPresent(creator.Format))
						{
							ToolboxItem toolboxItem = creator.Create(_dataObject);
							if (toolboxItem != null)
							{
								return MergeFilter(toolboxItem);
							}
						}
					}
					return filter;
				}
			}
			return filter;
		}

		public override int GetHashCode()
		{
			if (_hashCode == 0 && _dataObject != null && _dataObject.GetDataPresent("CF_TOOLBOXITEMCONTAINER_HASH"))
			{
				_hashCode = (int)_dataObject.GetData("CF_TOOLBOXITEMCONTAINER_HASH");
			}
			if (_hashCode == 0)
			{
				_hashCode = base.GetHashCode();
			}
			return _hashCode;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
		protected virtual void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			IDataObject toolboxData = ToolboxData;
			string[] formats = toolboxData.GetFormats();
			object[] array = new object[formats.Length];
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = toolboxData.GetData(formats[i]);
			}
			info.AddValue("TbxIC_DataObjectFormats", formats);
			info.AddValue("TbxIC_DataObjectValues", array);
		}

		public virtual ToolboxItem GetToolboxItem(ICollection creators)
		{
			ToolboxItem toolboxItem = _toolboxItem;
			if (_toolboxItem == null)
			{
				if (_dataObject.GetDataPresent("CF_TOOLBOXITEMCONTAINER_CONTENTS"))
				{
					string exceptionString = null;
					try
					{
						ToolboxItemSerializer toolboxItemSerializer = (ToolboxItemSerializer)_dataObject.GetData("CF_TOOLBOXITEMCONTAINER_CONTENTS");
						_toolboxItem = toolboxItemSerializer.ToolboxItem;
					}
					catch (Exception ex)
					{
						exceptionString = ex.Message;
					}
					catch
					{
					}
					if (_toolboxItem == null)
					{
						_toolboxItem = new BrokenToolboxItem(exceptionString);
					}
					toolboxItem = _toolboxItem;
				}
				else if (creators != null)
				{
					foreach (ToolboxItemCreator creator in creators)
					{
						if (_dataObject.GetDataPresent(creator.Format))
						{
							toolboxItem = creator.Create(_dataObject);
							if (toolboxItem != null)
							{
								return toolboxItem;
							}
						}
					}
					return toolboxItem;
				}
			}
			return toolboxItem;
		}

		private static ICollection MergeFilter(ToolboxItem item)
		{
			ICollection filter = item.Filter;
			ArrayList arrayList = new ArrayList();
			foreach (Attribute attribute4 in TypeDescriptor.GetAttributes(item))
			{
				if (attribute4 is ToolboxItemFilterAttribute)
				{
					arrayList.Add(attribute4);
				}
			}
			if (filter == null || filter.Count == 0)
			{
				return arrayList;
			}
			if (arrayList.Count > 0)
			{
				Hashtable hashtable = new Hashtable(arrayList.Count + filter.Count);
				foreach (Attribute item2 in arrayList)
				{
					hashtable[item2.TypeId] = item2;
				}
				foreach (Attribute item3 in filter)
				{
					hashtable[item3.TypeId] = item3;
				}
				ToolboxItemFilterAttribute[] array = new ToolboxItemFilterAttribute[hashtable.Values.Count];
				hashtable.Values.CopyTo(array, 0);
				return array;
			}
			return filter;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.SerializationFormatter)]
		void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
		{
			GetObjectData(info, context);
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal class UnsafeNativeMethods
	{
		public const int OBJID_CLIENT = -4;

		private UnsafeNativeMethods()
		{
		}

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern int ClientToScreen(HandleRef hWnd, [In][Out] NativeMethods.POINT pt);

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern int ScreenToClient(HandleRef hWnd, [In][Out] NativeMethods.POINT pt);

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern IntPtr SetFocus(HandleRef hWnd);

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern IntPtr GetFocus();

		[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern void NotifyWinEvent(int winEvent, HandleRef hwnd, int objType, int objID);
	}
}
