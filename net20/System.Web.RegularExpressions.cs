
// C:\WINDOWS\assembly\GAC_MSIL\System.Web.RegularExpressions\2.0.0.0__b03f5f7f11d50a3a\System.Web.RegularExpressions.dll
// System.Web.RegularExpressions, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("System.Design, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyDefaultAlias("System.Web.RegularExpressions.dll")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: ComVisible(false)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyTitle("System.Web.RegularExpressions.dll")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyFileVersion("2.0.50727.9161")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: InternalsVisibleTo("System.Web, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: AssemblyDescription("System.Web.RegularExpressions.dll")]
[assembly: CLSCompliant(true)]
[assembly: CompilationRelaxations(8)]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyInformationalVersion("2.0.50727.9161")]
[assembly: AssemblyVersion("2.0.0.0")]
namespace System.Web.RegularExpressions
{
	internal class TagRegexRunner1 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			if (num4 == runtextstart && num4 < num3 && text[num4++] == '<')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				if (1 <= num3 - num4)
				{
					num4++;
					num7 = 1;
					while (RegexRunner.CharInClass(text[num4 - num7--], "\0\u0004\t./:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						if (num7 > 0)
						{
							continue;
						}
						goto IL_00fd;
					}
				}
			}
			goto IL_0ee8;
			IL_0e90:
			if (num4 < num3 && text[num4++] == '>')
			{
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_0edf;
			}
			goto IL_0ee8;
			IL_033e:
			num7 = array2[num6++];
			Capture(4, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			array2[--num6] = num4;
			array[--num5] = 1;
			array[--num5] = num4;
			array[--num5] = 6;
			int num8;
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 7;
			}
			goto IL_0412;
			IL_0c1f:
			num7 = array2[num6++];
			Capture(2, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			goto IL_0c7f;
			IL_0cf2:
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 26;
			}
			goto IL_0d66;
			IL_0edf:
			runtextpos = num4;
			return;
			IL_0d8f:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] == '/')
			{
				num7 = array2[num6++];
				Capture(6, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_0df6;
			}
			goto IL_0ee8;
			IL_00fd:
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0004\t./:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0171;
			IL_0412:
			if (num4 < num3 && text[num4++] == '=')
			{
				num7 = (num8 = num3 - num4) + 1;
				while (--num7 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num8 > num7)
				{
					array[--num5] = num8 - num7 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 8;
				}
				goto IL_04a5;
			}
			goto IL_0ee8;
			IL_0df6:
			num7 = array2[num6++];
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if ((num9 != num4 || num7 < 0) && num7 < 1)
			{
				array2[--num6] = num4;
				array2[--num6] = num7 + 1;
				array[--num5] = 28;
				if (num5 > 212 && num6 > 159)
				{
					goto IL_0d8f;
				}
				array[--num5] = 29;
				goto IL_0ee8;
			}
			array[--num5] = num7;
			array[--num5] = 30;
			goto IL_0e90;
			IL_0d66:
			array2[--num6] = -1;
			array2[--num6] = 0;
			array[--num5] = 27;
			goto IL_0df6;
			IL_0217:
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_028b;
			IL_028b:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num7 = (num8 = num3 - num4) + 1;
				while (--num7 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0004\t-.:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num8 > num7)
				{
					array[--num5] = num8 - num7 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 5;
				}
				goto IL_033e;
			}
			goto IL_0ee8;
			IL_0ee8:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 24:
					break;
				case 29:
					goto IL_0d8f;
				default:
					goto IL_0fa9;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0fc6;
				case 3:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 4:
					goto IL_1035;
				case 5:
					goto IL_1085;
				case 6:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 10;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 11;
					}
					goto IL_0622;
				case 7:
					goto IL_10e6;
				case 8:
					goto IL_1136;
				case 9:
					goto IL_1186;
				case 10:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 14;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_0832;
				case 11:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 11;
					}
					goto IL_0622;
				case 12:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 12;
					}
					goto IL_06b5;
				case 13:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 13;
					}
					goto IL_0752;
				case 14:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 18;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_0a50;
				case 15:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_0832;
				case 16:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_08c5;
				case 17:
					num4 = array[num5++];
					num8 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
					{
						continue;
					}
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 17;
					}
					goto IL_0959;
				case 18:
					num4 = array[num5++];
					array2[--num6] = num4;
					array[--num5] = 1;
					if ((num7 = num3 - num4) > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 22;
					}
					goto IL_0bef;
				case 19:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_0a50;
				case 20:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0ae3;
				case 21:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 21;
					}
					goto IL_0b6f;
				case 22:
					num4 = array[num5++];
					num8 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						continue;
					}
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 22;
					}
					goto IL_0bef;
				case 23:
					goto IL_155f;
				case 25:
					array2[--num6] = array[num5++];
					continue;
				case 26:
					goto IL_15a0;
				case 27:
					num6 += 2;
					continue;
				case 28:
					goto IL_15fc;
				case 30:
					{
						num7 = array[num5++];
						array2[--num6] = array[num5++];
						array2[--num6] = num7;
						continue;
					}
					IL_08c5:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (3 > num3 - num4 || text[num4] != '<' || text[num4 + 1] != '%' || text[num4 + 2] != '#')
					{
						continue;
					}
					num4 += 3;
					if ((num7 = num3 - num4) > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 17;
					}
					goto IL_0959;
					IL_06b5:
					if (num4 >= num3 || text[num4++] != '\'')
					{
						continue;
					}
					array2[--num6] = num4;
					array[--num5] = 1;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (text[num4++] == '\'')
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 13;
					}
					goto IL_0752;
					IL_0ae3:
					array2[--num6] = num4;
					array[--num5] = 1;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\u0001\u0004\u0001/0=?d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 21;
					}
					goto IL_0b6f;
					IL_0832:
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_08c5;
					IL_0bef:
					num7 = array2[num6++];
					Capture(5, num7, num4);
					array[--num5] = num7;
					array[--num5] = 3;
					goto IL_0c1f;
					IL_0622:
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 12;
					}
					goto IL_06b5;
					IL_0b6f:
					num7 = array2[num6++];
					Capture(5, num7, num4);
					array[--num5] = num7;
					array[--num5] = 3;
					goto IL_0c1f;
					IL_0752:
					num7 = array2[num6++];
					Capture(5, num7, num4);
					array[--num5] = num7;
					array[--num5] = 3;
					if (num4 >= num3)
					{
						continue;
					}
					goto IL_078b;
					IL_0959:
					if (2 > num3 - num4)
					{
						continue;
					}
					goto IL_0965;
					IL_0a50:
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0ae3;
				}
				break;
				IL_15fc:
				if ((num7 = array2[num6++] - 1) < 0)
				{
					array2[num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				}
				goto IL_1610;
				IL_078b:
				if (text[num4++] != '\'')
				{
					continue;
				}
				goto IL_0c1f;
				IL_0965:
				if (text[num4] != '%' || text[num4 + 1] != '>')
				{
					continue;
				}
				num4 += 2;
				num7 = array2[num6++];
				Capture(5, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_0c1f;
			}
			goto IL_01be;
			IL_1035:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_028b;
			IL_1186:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 9;
			}
			goto IL_0542;
			IL_1610:
			num4 = array2[num6++];
			array[--num5] = num7;
			array[--num5] = 30;
			goto IL_0e90;
			IL_1136:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 8;
			}
			goto IL_04a5;
			IL_0fa9:
			num4 = array[num5++];
			goto IL_0edf;
			IL_15a0:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 26;
			}
			goto IL_0d66;
			IL_0fc6:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0171;
			IL_1085:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 5;
			}
			goto IL_033e;
			IL_155f:
			num4 = array[num5++];
			_ = array2[num6++];
			array[--num5] = 25;
			goto IL_0cf2;
			IL_0171:
			num7 = array2[num6++];
			Capture(3, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			array2[--num6] = -1;
			array[--num5] = 1;
			goto IL_0c7f;
			IL_0c7f:
			int num10 = (num7 = array2[num6++]);
			array[--num5] = num7;
			if (num10 != num4)
			{
				array[--num5] = num4;
				array2[--num6] = num4;
				array[--num5] = 23;
				if (num5 > 212 && num6 > 159)
				{
					goto IL_01be;
				}
				array[--num5] = 24;
				goto IL_0ee8;
			}
			array[--num5] = 25;
			goto IL_0cf2;
			IL_0542:
			num7 = array2[num6++];
			Capture(5, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			if (num4 < num3 && text[num4++] == '"')
			{
				goto IL_0c1f;
			}
			goto IL_0ee8;
			IL_04a5:
			if (num4 < num3 && text[num4++] == '"')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				num7 = (num8 = num3 - num4) + 1;
				while (--num7 > 0)
				{
					if (text[num4++] == '"')
					{
						num4--;
						break;
					}
				}
				if (num8 > num7)
				{
					array[--num5] = num8 - num7 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 9;
				}
				goto IL_0542;
			}
			goto IL_0ee8;
			IL_10e6:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 7;
			}
			goto IL_0412;
			IL_01be:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (1 <= num3 - num4)
			{
				num4++;
				num7 = 1;
				while (RegexRunner.CharInClass(text[num4 - num7--], "\0\0\u0001d"))
				{
					if (num7 > 0)
					{
						continue;
					}
					goto IL_0217;
				}
			}
			goto IL_0ee8;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 53;
		}
	}
	internal class TagRegexFactory1 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new TagRegexRunner1();
		}
	}
	public class TagRegex : Regex
	{
		public TagRegex()
		{
			pattern = "\\G<(?<tagname>[\\w:\\.]+)(\\s+(?<attrname>\\w[-\\w:]*)(\\s*=\\s*\"(?<attrval>[^\"]*)\"|\\s*=\\s*'(?<attrval>[^']*)'|\\s*=\\s*(?<attrval><%#.*?%>)|\\s*=\\s*(?<attrval>[^\\s=/>]*)|(?<attrval>\\s*?)))*\\s*(?<empty>/)?>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new TagRegexFactory1();
			capnames = new Hashtable();
			capnames.Add("attrval", 5);
			capnames.Add("empty", 6);
			capnames.Add("1", 1);
			capnames.Add("0", 0);
			capnames.Add("tagname", 3);
			capnames.Add("2", 2);
			capnames.Add("attrname", 4);
			capslist = new string[7];
			capslist[0] = "0";
			capslist[1] = "1";
			capslist[2] = "2";
			capslist[3] = "tagname";
			capslist[4] = "attrname";
			capslist[5] = "attrval";
			capslist[6] = "empty";
			capsize = 7;
			InitializeReferences();
		}
	}
	internal class DirectiveRegexRunner2 : RegexRunner
	{
		public unsafe override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num8;
			int num7;
			if (num4 == runtextstart && 2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_012f;
			}
			goto IL_0ccc;
			IL_0fa3:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 12;
			}
			goto IL_05c0;
			IL_01f7:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0002\t:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_02aa;
			}
			goto IL_0ccc;
			IL_0de6:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01f7;
			IL_0c5d:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				goto IL_0cc3;
			}
			goto IL_0ccc;
			IL_0bb7:
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if (num9 != num4)
			{
				array[--num5] = num4;
				array2[--num6] = num4;
				array[--num5] = 22;
				if (num5 > 204 && num6 > 153)
				{
					goto IL_016b;
				}
				array[--num5] = 23;
				goto IL_0ccc;
			}
			array[--num5] = 24;
			goto IL_0c2a;
			IL_05c0:
			num8 = array2[num6++];
			Capture(5, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			if (num4 < num3 && text[num4++] == '"')
			{
				goto IL_0b57;
			}
			goto IL_0ccc;
			IL_0d96:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_012f;
			IL_0c2a:
			if ((num8 = num3 - num4) > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c5d;
			IL_0cc3:
			runtextpos = num4;
			return;
			IL_0ccc:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 23:
					break;
				default:
					goto IL_0d79;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0d96;
				case 3:
					goto IL_0de6;
				case 4:
					goto IL_0e36;
				case 5:
					num6 += 2;
					continue;
				case 6:
					array2[--num6] = array[num5++];
					continue;
				case 7:
				{
					int num10 = array[num5++];
					if (num10 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num10 != Crawlpos());
					}
					continue;
				}
				case 8:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 9:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 13;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_06a0;
				case 10:
					goto IL_0f03;
				case 11:
					goto IL_0f53;
				case 12:
					goto IL_0fa3;
				case 13:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 17;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08f8;
				case 14:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_06a0;
				case 15:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_077b;
				case 16:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_0818;
				case 17:
					num4 = array[num5++];
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					array2[--num6] = num4;
					array[--num5] = 1;
					if ((num8 = num3 - num4) > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b27;
				case 18:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08f8;
				case 19:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09d3;
				case 20:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a5f;
				case 21:
					num4 = array[num5++];
					num7 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						continue;
					}
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b27;
				case 22:
					goto IL_1260;
				case 24:
					array2[--num6] = array[num5++];
					continue;
				case 25:
					goto IL_12a1;
					IL_08f8:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09d3;
					IL_0818:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					if (num4 >= num3)
					{
						continue;
					}
					goto IL_0851;
					IL_077b:
					if (num4 >= num3 || text[num4++] != '\'')
					{
						continue;
					}
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (text[num4++] == '\'')
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_0818;
					IL_06a0:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_077b;
					IL_0b27:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b57;
					IL_09d3:
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\u0001\u0004\u0001%&>?d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a5f;
					IL_0a5f:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b57;
				}
				break;
				IL_12a1:
				num4 = array[num5++];
				num7 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					continue;
				}
				goto IL_12d7;
				IL_0851:
				if (text[num4++] != '\'')
				{
					continue;
				}
				goto IL_0b57;
			}
			goto IL_016b;
			IL_0b57:
			num8 = array2[num6++];
			Capture(2, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			goto IL_0bb7;
			IL_12d7:
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c5d;
			IL_02aa:
			array2[--num6] = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)num5);
			array2[--num6] = Crawlpos();
			array[--num5] = 5;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\u0001\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num4 = (array[--num5] = array2[num6++]);
				array[--num5] = 6;
				num8 = array2[num6++];
				num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
				array[--num5] = num8;
				array[--num5] = 7;
				num8 = array2[num6++];
				Capture(3, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				array2[--num6] = num4;
				array[--num5] = 1;
				array[--num5] = num4;
				array[--num5] = 9;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 10;
				}
				goto IL_0448;
			}
			goto IL_0ccc;
			IL_016b:
			array2[--num6] = num4;
			array[--num5] = 1;
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01f7;
			IL_1260:
			num4 = array[num5++];
			_ = array2[num6++];
			array[--num5] = 24;
			goto IL_0c2a;
			IL_0f03:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 10;
			}
			goto IL_0448;
			IL_0e36:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_02aa;
			IL_012f:
			if (num4 < num3 && text[num4++] == '@')
			{
				array2[--num6] = -1;
				array[--num5] = 1;
				goto IL_0bb7;
			}
			goto IL_0ccc;
			IL_0523:
			if (num4 < num3 && text[num4++] == '"')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (text[num4++] == '"')
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 12;
				}
				goto IL_05c0;
			}
			goto IL_0ccc;
			IL_0f53:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 11;
			}
			goto IL_0523;
			IL_0d79:
			num4 = array[num5++];
			goto IL_0cc3;
			IL_0448:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] == '=')
			{
				num8 = array2[num6++];
				Capture(4, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 11;
				}
				goto IL_0523;
			}
			goto IL_0ccc;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 51;
		}
	}
	internal class DirectiveRegexFactory2 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new DirectiveRegexRunner2();
		}
	}
	public class DirectiveRegex : Regex
	{
		public DirectiveRegex()
		{
			pattern = "\\G<%\\s*@(\\s*(?<attrname>\\w[\\w:]*(?=\\W))(\\s*(?<equal>=)\\s*\"(?<attrval>[^\"]*)\"|\\s*(?<equal>=)\\s*'(?<attrval>[^']*)'|\\s*(?<equal>=)\\s*(?<attrval>[^\\s%>]*)|(?<equal>)(?<attrval>\\s*?)))*\\s*?%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new DirectiveRegexFactory2();
			capnames = new Hashtable();
			capnames.Add("attrval", 5);
			capnames.Add("2", 2);
			capnames.Add("0", 0);
			capnames.Add("1", 1);
			capnames.Add("equal", 4);
			capnames.Add("attrname", 3);
			capslist = new string[6];
			capslist[0] = "0";
			capslist[1] = "1";
			capslist[2] = "2";
			capslist[3] = "attrname";
			capslist[4] = "equal";
			capslist[5] = "attrval";
			capsize = 6;
			InitializeReferences();
		}
	}
	internal class EndTagRegexRunner3 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			if (num4 == runtextstart && 2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '/')
			{
				num4 += 2;
				array2[--num6] = num4;
				array[--num5] = 1;
				if (1 <= num3 - num4)
				{
					num4++;
					num7 = 1;
					while (RegexRunner.CharInClass(text[num4 - num7--], "\0\u0004\t./:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						if (num7 > 0)
						{
							continue;
						}
						goto IL_0114;
					}
				}
			}
			goto IL_0284;
			IL_0114:
			int num8;
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0004\t./:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0188;
			IL_0284:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_02fa;
				case 3:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 4:
					goto IL_0369;
				}
				break;
			}
			num4 = array[num5++];
			goto IL_027b;
			IL_0188:
			num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_022c;
			IL_022c:
			if (num4 < num3 && text[num4++] == '>')
			{
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_027b;
			}
			goto IL_0284;
			IL_0369:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_022c;
			IL_02fa:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0188;
			IL_027b:
			runtextpos = num4;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 7;
		}
	}
	internal class EndTagRegexFactory3 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new EndTagRegexRunner3();
		}
	}
	public class EndTagRegex : Regex
	{
		public EndTagRegex()
		{
			pattern = "\\G</(?<tagname>[\\w:\\.]+)\\s*>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new EndTagRegexFactory3();
			capnames = new Hashtable();
			capnames.Add("0", 0);
			capnames.Add("tagname", 1);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "tagname";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class AspCodeRegexRunner4 : RegexRunner
	{
		public unsafe override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 == runtextstart && 2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				array2[--num6] = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)num5);
				array2[--num6] = Crawlpos();
				array[--num5] = 2;
				array[--num5] = num4;
				array[--num5] = 3;
				if (num4 < num3 && text[num4++] == '@')
				{
					int num7 = array2[num6++];
					num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
					if (num7 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num7 != Crawlpos());
					}
				}
			}
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				int num10;
				switch (array[num5++])
				{
				default:
					num4 = array[num5++];
					goto IL_0277;
				case 1:
					num6++;
					break;
				case 2:
					num6 += 2;
					break;
				case 3:
					num4 = array[num5++];
					num10 = array2[num6++];
					num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
					array[--num5] = num10;
					array[--num5] = 4;
					array2[--num6] = num4;
					array[--num5] = 1;
					if ((num10 = num3 - num4) > 0)
					{
						array[--num5] = num10 - 1;
						array[--num5] = num4;
						array[--num5] = 5;
					}
					goto IL_01e1;
				case 4:
				{
					int num9 = array[num5++];
					if (num9 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num9 != Crawlpos());
					}
					break;
				}
				case 5:
				{
					num4 = array[num5++];
					int num8 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
					{
						break;
					}
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 5;
					}
					goto IL_01e1;
				}
				case 6:
					{
						array2[--num6] = array[num5++];
						Uncapture();
						break;
					}
					IL_0277:
					runtextpos = num4;
					return;
					IL_01e1:
					num10 = array2[num6++];
					Capture(1, num10, num4);
					array[--num5] = num10;
					array[--num5] = 6;
					if (2 > num3 - num4 || text[num4] != '%' || text[num4 + 1] != '>')
					{
						break;
					}
					num4 += 2;
					num10 = array2[num6++];
					Capture(0, num10, num4);
					array[--num5] = num10;
					array[--num5] = 6;
					goto IL_0277;
				}
			}
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 10;
		}
	}
	internal class AspCodeRegexFactory4 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new AspCodeRegexRunner4();
		}
	}
	public class AspCodeRegex : Regex
	{
		public AspCodeRegex()
		{
			pattern = "\\G<%(?!@)(?<code>.*?)%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new AspCodeRegexFactory4();
			capnames = new Hashtable();
			capnames.Add("code", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "code";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class AspExprRegexRunner5 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			if (num4 == runtextstart && 2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				if ((num7 = num3 - num4) > 0)
				{
					array[--num5] = num7 - 1;
					array[--num5] = num4;
					array[--num5] = 2;
				}
				goto IL_00ee;
			}
			goto IL_02b4;
			IL_0245:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 5;
				goto IL_02ab;
			}
			goto IL_02b4;
			IL_03e7:
			int num8;
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 4;
			}
			goto IL_0181;
			IL_0370:
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 2;
			}
			goto IL_00ee;
			IL_01b1:
			num7 = array2[num6++];
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if ((num9 != num4 || num7 < 0) && num7 < 1)
			{
				array2[--num6] = num4;
				array2[--num6] = num7 + 1;
				array[--num5] = 6;
				if (num5 > 40 && num6 > 30)
				{
					goto IL_0136;
				}
				array[--num5] = 7;
				goto IL_02b4;
			}
			array[--num5] = num7;
			array[--num5] = 8;
			goto IL_0245;
			IL_00ee:
			if (num4 < num3 && text[num4++] == '=')
			{
				array2[--num6] = -1;
				array2[--num6] = 0;
				array[--num5] = 3;
				goto IL_01b1;
			}
			goto IL_02b4;
			IL_02b4:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 7:
					break;
				default:
					goto IL_031d;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_033a;
				case 3:
					num6 += 2;
					continue;
				case 4:
					goto IL_03b1;
				case 5:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 6:
					goto IL_043b;
				case 8:
					num7 = array[num5++];
					array2[--num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				}
				break;
				IL_043b:
				if ((num7 = array2[num6++] - 1) < 0)
				{
					array2[num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				}
				goto IL_044f;
				IL_033a:
				num4 = array[num5++];
				num8 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					continue;
				}
				goto IL_0370;
				IL_03b1:
				num4 = array[num5++];
				num8 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
				{
					continue;
				}
				goto IL_03e7;
			}
			goto IL_0136;
			IL_02ab:
			runtextpos = num4;
			return;
			IL_0181:
			num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 5;
			goto IL_01b1;
			IL_044f:
			num4 = array2[num6++];
			array[--num5] = num7;
			array[--num5] = 8;
			goto IL_0245;
			IL_0136:
			array2[--num6] = num4;
			array[--num5] = 1;
			if ((num7 = num3 - num4) > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 4;
			}
			goto IL_0181;
			IL_031d:
			num4 = array[num5++];
			goto IL_02ab;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 10;
		}
	}
	internal class AspExprRegexFactory5 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new AspExprRegexRunner5();
		}
	}
	public class AspExprRegex : Regex
	{
		public AspExprRegex()
		{
			pattern = "\\G<%\\s*?=(?<code>.*?)?%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new AspExprRegexFactory5();
			capnames = new Hashtable();
			capnames.Add("code", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "code";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class DatabindExprRegexRunner6 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 == runtextstart && 3 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%' && text[num4 + 2] == '#')
			{
				num4 += 3;
				array2[--num6] = -1;
				array2[--num6] = 0;
				array[--num5] = 2;
				goto IL_0172;
			}
			goto IL_0275;
			IL_0172:
			int num7 = array2[num6++];
			int num8;
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if ((num9 != num4 || num7 < 0) && num7 < 1)
			{
				array2[--num6] = num4;
				array2[--num6] = num7 + 1;
				array[--num5] = 5;
				if (num5 > 36 && num6 > 27)
				{
					goto IL_00f7;
				}
				array[--num5] = 6;
				goto IL_0275;
			}
			array[--num5] = num7;
			array[--num5] = 7;
			goto IL_0206;
			IL_02da:
			num4 = array[num5++];
			goto IL_026c;
			IL_00f7:
			array2[--num6] = num4;
			array[--num5] = 1;
			if ((num7 = num3 - num4) > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 3;
			}
			goto IL_0142;
			IL_0339:
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 3;
			}
			goto IL_0142;
			IL_0142:
			num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 4;
			goto IL_0172;
			IL_0275:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 6:
					break;
				default:
					goto IL_02da;
				case 1:
					num6++;
					continue;
				case 2:
					num6 += 2;
					continue;
				case 3:
					goto IL_0303;
				case 4:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 5:
					goto IL_038d;
				case 7:
					num7 = array[num5++];
					array2[--num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				}
				break;
				IL_038d:
				if ((num7 = array2[num6++] - 1) < 0)
				{
					array2[num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				}
				goto IL_03a1;
				IL_0303:
				num4 = array[num5++];
				num8 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
				{
					continue;
				}
				goto IL_0339;
			}
			goto IL_00f7;
			IL_026c:
			runtextpos = num4;
			return;
			IL_0206:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 4;
				goto IL_026c;
			}
			goto IL_0275;
			IL_03a1:
			num4 = array2[num6++];
			array[--num5] = num7;
			array[--num5] = 7;
			goto IL_0206;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 9;
		}
	}
	internal class DatabindExprRegexFactory6 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new DatabindExprRegexRunner6();
		}
	}
	public class DatabindExprRegex : Regex
	{
		public DatabindExprRegex()
		{
			pattern = "\\G<%#(?<code>.*?)?%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new DatabindExprRegexFactory6();
			capnames = new Hashtable();
			capnames.Add("code", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "code";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class CommentRegexRunner7 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 == runtextstart && 4 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%' && text[num4 + 2] == '-' && text[num4 + 3] == '-')
			{
				num4 += 4;
				array2[--num6] = -1;
				array[--num5] = 1;
				goto IL_0213;
			}
			goto IL_02f8;
			IL_02ef:
			runtextpos = num4;
			return;
			IL_01e3:
			int num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			goto IL_0213;
			IL_02f8:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0372;
				case 3:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 4:
					goto IL_03e1;
				case 5:
					array2[num6] = array[num5++];
					continue;
				}
				break;
				IL_03e1:
				num4 = array[num5++];
				array2[--num6] = num4;
				array[--num5] = 5;
				if (num5 > 40 && num6 > 30)
				{
					array2[--num6] = num4;
					array[--num5] = 1;
					array2[--num6] = num4;
					array[--num5] = 1;
					int num8;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (text[num4++] == '-')
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 2;
					}
					goto IL_0194;
				}
				array[--num5] = 6;
				continue;
				IL_0372:
				num4 = array[num5++];
				num7 = array[num5++];
				if (num7 > 0)
				{
					array[--num5] = num7 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_0194;
				IL_0194:
				num7 = array2[num6++];
				Capture(2, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				if (num4 >= num3 || text[num4++] != '-')
				{
					continue;
				}
				goto IL_01e3;
			}
			num4 = array[num5++];
			goto IL_02ef;
			IL_0213:
			int num9 = (num7 = array2[num6++]);
			if (num7 != -1)
			{
				array[--num5] = num7;
			}
			else
			{
				array[--num5] = num4;
			}
			if (num9 != num4)
			{
				array[--num5] = num4;
				array[--num5] = 4;
			}
			else
			{
				array2[--num6] = num7;
				array[--num5] = 5;
			}
			if (3 <= num3 - num4 && text[num4] == '-' && text[num4 + 1] == '%' && text[num4 + 2] == '>')
			{
				num4 += 3;
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_02ef;
			}
			goto IL_02f8;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 10;
		}
	}
	internal class CommentRegexFactory7 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new CommentRegexRunner7();
		}
	}
	public class CommentRegex : Regex
	{
		public CommentRegex()
		{
			pattern = "\\G<%--(([^-]*)-)*?-%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new CommentRegexFactory7();
			capsize = 3;
			InitializeReferences();
		}
	}
	internal class IncludeRegexRunner8 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			int num8;
			if (num4 == runtextstart && 4 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '!' && text[num4 + 2] == '-' && text[num4 + 3] == '-')
			{
				num4 += 4;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_0155;
			}
			goto IL_0730;
			IL_0921:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 7;
			}
			goto IL_04c7;
			IL_0727:
			runtextpos = num4;
			return;
			IL_08d1:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 6;
			}
			goto IL_0434;
			IL_07c2:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0155;
			IL_0543:
			array2[--num6] = num4;
			array[--num5] = 1;
			if ((num8 = num3 - num4) > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 9;
			}
			goto IL_058e;
			IL_0862:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_0390;
			IL_063a:
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 11;
			}
			goto IL_06ae;
			IL_0390:
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 5;
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 6;
			}
			goto IL_0434;
			IL_04c7:
			int num9 = num3 - num4;
			if (num9 >= 1)
			{
				num9 = 1;
			}
			num7 = num9;
			num8 = num9 + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0004\0\"#'("))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 8;
			}
			goto IL_0543;
			IL_0812:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_02c3;
			IL_058e:
			num8 = array2[num6++];
			Capture(2, num8, num4);
			array[--num5] = num8;
			array[--num5] = 5;
			int num10 = num3 - num4;
			if (num10 >= 1)
			{
				num10 = 1;
			}
			num7 = num10;
			num8 = num10 + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0004\0\"#'("))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 10;
			}
			goto IL_063a;
			IL_0730:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_07c2;
				case 3:
					goto IL_0812;
				case 4:
					goto IL_0862;
				case 5:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 6:
					goto IL_08d1;
				case 7:
					goto IL_0921;
				case 8:
					goto IL_0971;
				case 9:
					goto IL_09c1;
				case 10:
					goto IL_0a2c;
				case 11:
					goto IL_0a7c;
				}
				break;
				IL_09c1:
				num4 = array[num5++];
				num7 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\u0001\u0004\0\"#'("))
				{
					continue;
				}
				goto IL_09f7;
			}
			num4 = array[num5++];
			goto IL_0727;
			IL_0a7c:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 11;
			}
			goto IL_06ae;
			IL_0155:
			if (num4 < num3 && text[num4++] == '#' && 7 <= num3 - num4 && char.ToLower(text[num4], CultureInfo.CurrentCulture) == 'i' && char.ToLower(text[num4 + 1], CultureInfo.CurrentCulture) == 'n' && char.ToLower(text[num4 + 2], CultureInfo.CurrentCulture) == 'c' && char.ToLower(text[num4 + 3], CultureInfo.CurrentCulture) == 'l' && char.ToLower(text[num4 + 4], CultureInfo.CurrentCulture) == 'u' && char.ToLower(text[num4 + 5], CultureInfo.CurrentCulture) == 'd' && char.ToLower(text[num4 + 6], CultureInfo.CurrentCulture) == 'e')
			{
				num4 += 7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 3;
				}
				goto IL_02c3;
			}
			goto IL_0730;
			IL_0a2c:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 10;
			}
			goto IL_063a;
			IL_031c:
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_0390;
			IL_0434:
			if (num4 < num3 && text[num4++] == '=')
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 7;
				}
				goto IL_04c7;
			}
			goto IL_0730;
			IL_09f7:
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 9;
			}
			goto IL_058e;
			IL_06ae:
			if (3 <= num3 - num4 && text[num4] == '-' && text[num4 + 1] == '-' && text[num4 + 2] == '>')
			{
				num4 += 3;
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 5;
				goto IL_0727;
			}
			goto IL_0730;
			IL_0971:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 8;
			}
			goto IL_0543;
			IL_02c3:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (1 <= num3 - num4)
			{
				num4++;
				num8 = 1;
				while (RegexRunner.CharInClass(text[num4 - num8--], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
				{
					if (num8 > 0)
					{
						continue;
					}
					goto IL_031c;
				}
			}
			goto IL_0730;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 16;
		}
	}
	internal class IncludeRegexFactory8 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new IncludeRegexRunner8();
		}
	}
	public class IncludeRegex : Regex
	{
		public IncludeRegex()
		{
			pattern = "\\G<!--\\s*#(?i:include)\\s*(?<pathtype>[\\w]+)\\s*=\\s*[\"']?(?<filename>[^\\\"']*?)[\"']?\\s*-->";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new IncludeRegexFactory8();
			capnames = new Hashtable();
			capnames.Add("pathtype", 1);
			capnames.Add("filename", 2);
			capnames.Add("0", 0);
			capslist = new string[3];
			capslist[0] = "0";
			capslist[1] = "pathtype";
			capslist[2] = "filename";
			capsize = 3;
			InitializeReferences();
		}
	}
	internal class TextRegexRunner9 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			if (num4 == runtextstart && 1 <= num3 - num4)
			{
				num4++;
				num7 = 1;
				while (text[num4 - num7--] != '<')
				{
					if (num7 > 0)
					{
						continue;
					}
					goto IL_00bb;
				}
			}
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_01cc;
				case 3:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				}
				break;
			}
			num4 = array[num5++];
			goto IL_0151;
			IL_00bb:
			int num8;
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (text[num4++] == '<')
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0121;
			IL_0151:
			runtextpos = num4;
			return;
			IL_0121:
			num7 = array2[num6++];
			Capture(0, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			goto IL_0151;
			IL_01cc:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0121;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 4;
		}
	}
	internal class TextRegexFactory9 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new TextRegexRunner9();
		}
	}
	public class TextRegex : Regex
	{
		public TextRegex()
		{
			pattern = "\\G[^<]+";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new TextRegexFactory9();
			capsize = 1;
			InitializeReferences();
		}
	}
	internal class GTRegexRunner10 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] != '%' && num4 < num3 && text[num4++] == '>')
			{
				int num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 2;
			}
			else
			{
				while (true)
				{
					runtrackpos = num5;
					runstackpos = num6;
					EnsureStorage();
					num5 = runtrackpos;
					num6 = runstackpos;
					array = runtrack;
					array2 = runstack;
					switch (array[num5++])
					{
					case 1:
						num6++;
						continue;
					case 2:
						array2[--num6] = array[num5++];
						Uncapture();
						continue;
					}
					break;
				}
				num4 = array[num5++];
			}
			runtextpos = num4;
		}

		public override bool FindFirstChar()
		{
			int num = runtextpos;
			string text = runtext;
			int num2 = runtextend - num;
			if (num2 > 0)
			{
				int result;
				while (true)
				{
					num2--;
					if (!RegexRunner.CharInClass(text[num++], "\0\u0003\0\0%&"))
					{
						if (num2 <= 0)
						{
							result = 0;
							break;
						}
						continue;
					}
					num--;
					result = 1;
					break;
				}
				runtextpos = num;
				return (byte)result != 0;
			}
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 3;
		}
	}
	internal class GTRegexFactory10 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new GTRegexRunner10();
		}
	}
	public class GTRegex : Regex
	{
		public GTRegex()
		{
			pattern = "[^%]>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new GTRegexFactory10();
			capsize = 1;
			InitializeReferences();
		}
	}
	internal class LTRegexRunner11 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] == '<' && num4 < num3 && text[num4++] != '%')
			{
				int num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 2;
			}
			else
			{
				while (true)
				{
					runtrackpos = num5;
					runstackpos = num6;
					EnsureStorage();
					num5 = runtrackpos;
					num6 = runstackpos;
					array = runtrack;
					array2 = runstack;
					switch (array[num5++])
					{
					case 1:
						num6++;
						continue;
					case 2:
						array2[--num6] = array[num5++];
						Uncapture();
						continue;
					}
					break;
				}
				num4 = array[num5++];
			}
			runtextpos = num4;
		}

		public override bool FindFirstChar()
		{
			string text = runtext;
			int num = runtextend;
			int num2 = runtextpos + 0;
			while (num2 < num)
			{
				int num3;
				if ((num3 = text[num2]) != 60)
				{
					num2 = (((num3 -= 60) != 0) ? 1 : (num3 switch
					{
						_ => 0, 
					})) + num2;
					continue;
				}
				num3 = (runtextpos = num2);
				return true;
			}
			runtextpos = runtextend;
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 3;
		}
	}
	internal class LTRegexFactory11 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new LTRegexRunner11();
		}
	}
	public class LTRegex : Regex
	{
		public LTRegex()
		{
			pattern = "<[^%]";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new LTRegexFactory11();
			capsize = 1;
			InitializeReferences();
		}
	}
	internal class ServerTagsRegexRunner12 : RegexRunner
	{
		public unsafe override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				array2[--num6] = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)num5);
				array2[--num6] = Crawlpos();
				array[--num5] = 2;
				array[--num5] = num4;
				array[--num5] = 3;
				if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\0\u0002\0#%"))
				{
					int num7 = array2[num6++];
					num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
					if (num7 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num7 != Crawlpos());
					}
				}
			}
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				int num11;
				int num9;
				switch (array[num5++])
				{
				default:
					num4 = array[num5++];
					goto IL_0375;
				case 1:
					num6++;
					break;
				case 2:
					num6 += 2;
					break;
				case 3:
					num4 = array[num5++];
					num9 = array2[num6++];
					num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
					array[--num5] = num9;
					array[--num5] = 4;
					array2[--num6] = -1;
					array[--num5] = 1;
					goto IL_02c3;
				case 4:
				{
					int num10 = array[num5++];
					if (num10 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num10 != Crawlpos());
					}
					break;
				}
				case 5:
					num4 = array[num5++];
					num9 = array[num5++];
					if (num9 > 0)
					{
						array[--num5] = num9 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 5;
					}
					goto IL_0244;
				case 6:
					array2[--num6] = array[num5++];
					Uncapture();
					break;
				case 7:
					num4 = array[num5++];
					array2[--num6] = num4;
					array[--num5] = 8;
					if (num5 > 56 && num6 > 42)
					{
						array2[--num6] = num4;
						array[--num5] = 1;
						array2[--num6] = num4;
						array[--num5] = 1;
						int num8;
						num9 = (num8 = num3 - num4) + 1;
						while (--num9 > 0)
						{
							if (text[num4++] == '%')
							{
								num4--;
								break;
							}
						}
						if (num8 > num9)
						{
							array[--num5] = num8 - num9 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 5;
						}
						goto IL_0244;
					}
					array[--num5] = 9;
					break;
				case 8:
					{
						array2[num6] = array[num5++];
						break;
					}
					IL_02c3:
					num11 = (num9 = array2[num6++]);
					if (num9 != -1)
					{
						array[--num5] = num9;
					}
					else
					{
						array[--num5] = num4;
					}
					if (num11 != num4)
					{
						array[--num5] = num4;
						array[--num5] = 7;
					}
					else
					{
						array2[--num6] = num9;
						array[--num5] = 8;
					}
					if (num4 >= num3 || text[num4++] != '>')
					{
						break;
					}
					num9 = array2[num6++];
					Capture(0, num9, num4);
					array[--num5] = num9;
					array[--num5] = 6;
					goto IL_0375;
					IL_0375:
					runtextpos = num4;
					return;
					IL_0244:
					num9 = array2[num6++];
					Capture(2, num9, num4);
					array[--num5] = num9;
					array[--num5] = 6;
					if (num4 >= num3 || text[num4++] != '%')
					{
						break;
					}
					num9 = array2[num6++];
					Capture(1, num9, num4);
					array[--num5] = num9;
					array[--num5] = 6;
					goto IL_02c3;
				}
			}
		}

		public override bool FindFirstChar()
		{
			string text = runtext;
			int num = runtextend;
			int num2 = runtextpos + 1;
			while (num2 < num)
			{
				int num4;
				int num3;
				if ((num3 = text[num2]) != 37)
				{
					num4 = (((uint)(num3 -= 37) > 23u) ? 2 : (num3 switch
					{
						1 => 2, 
						2 => 2, 
						3 => 2, 
						4 => 2, 
						5 => 2, 
						6 => 2, 
						7 => 2, 
						8 => 2, 
						9 => 2, 
						10 => 2, 
						11 => 2, 
						12 => 2, 
						13 => 2, 
						14 => 2, 
						15 => 2, 
						16 => 2, 
						17 => 2, 
						18 => 2, 
						19 => 2, 
						20 => 2, 
						21 => 2, 
						22 => 2, 
						23 => 1, 
						_ => 0, 
					}));
				}
				else
				{
					num3 = num2;
					if (text[--num3] == '<')
					{
						runtextpos = num3;
						return true;
					}
					num4 = 1;
				}
				num2 = num4 + num2;
			}
			runtextpos = runtextend;
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 14;
		}
	}
	internal class ServerTagsRegexFactory12 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new ServerTagsRegexRunner12();
		}
	}
	public class ServerTagsRegex : Regex
	{
		public ServerTagsRegex()
		{
			pattern = "<%(?![#$])(([^%]*)%)*?>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new ServerTagsRegexFactory12();
			capsize = 3;
			InitializeReferences();
		}
	}
	internal class RunatServerRegexRunner13 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num8;
			if (5 <= num3 - num4 && char.ToLower(text[num4], CultureInfo.InvariantCulture) == 'r' && char.ToLower(text[num4 + 1], CultureInfo.InvariantCulture) == 'u' && char.ToLower(text[num4 + 2], CultureInfo.InvariantCulture) == 'n' && char.ToLower(text[num4 + 3], CultureInfo.InvariantCulture) == 'a' && char.ToLower(text[num4 + 4], CultureInfo.InvariantCulture) == 't')
			{
				num4 += 5;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\u0001\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_0197;
			}
			goto IL_028e;
			IL_0197:
			if (6 <= num3 - num4 && char.ToLower(text[num4], CultureInfo.InvariantCulture) == 's' && char.ToLower(text[num4 + 1], CultureInfo.InvariantCulture) == 'e' && char.ToLower(text[num4 + 2], CultureInfo.InvariantCulture) == 'r' && char.ToLower(text[num4 + 3], CultureInfo.InvariantCulture) == 'v' && char.ToLower(text[num4 + 4], CultureInfo.InvariantCulture) == 'e' && char.ToLower(text[num4 + 5], CultureInfo.InvariantCulture) == 'r')
			{
				num4 += 6;
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 3;
				goto IL_0285;
			}
			goto IL_028e;
			IL_028e:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0300;
				case 3:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				}
				break;
			}
			num4 = array[num5++];
			goto IL_0285;
			IL_0285:
			runtextpos = num4;
			return;
			IL_0300:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0197;
		}

		public override bool FindFirstChar()
		{
			string text = runtext;
			int num = runtextend;
			int num2 = runtextpos + 4;
			while (num2 < num)
			{
				int num4;
				int num3;
				if ((num3 = char.ToLower(text[num2], CultureInfo.InvariantCulture)) != 116)
				{
					num4 = (((uint)(num3 -= 97) > 20u) ? 5 : (num3 switch
					{
						1 => 5, 
						2 => 5, 
						3 => 5, 
						4 => 5, 
						5 => 5, 
						6 => 5, 
						7 => 5, 
						8 => 5, 
						9 => 5, 
						10 => 5, 
						11 => 5, 
						12 => 5, 
						13 => 2, 
						14 => 5, 
						15 => 5, 
						16 => 5, 
						17 => 4, 
						18 => 5, 
						19 => 0, 
						20 => 3, 
						_ => 1, 
					}));
				}
				else
				{
					num3 = num2;
					if (char.ToLower(text[--num3], CultureInfo.InvariantCulture) != 'a')
					{
						num4 = 1;
					}
					else if (char.ToLower(text[--num3], CultureInfo.InvariantCulture) != 'n')
					{
						num4 = 1;
					}
					else if (char.ToLower(text[--num3], CultureInfo.InvariantCulture) != 'u')
					{
						num4 = 1;
					}
					else
					{
						if (char.ToLower(text[--num3], CultureInfo.InvariantCulture) == 'r')
						{
							runtextpos = num3;
							return true;
						}
						num4 = 1;
					}
				}
				num2 = num4 + num2;
			}
			runtextpos = runtextend;
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 4;
		}
	}
	internal class RunatServerRegexFactory13 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new RunatServerRegexRunner13();
		}
	}
	public class RunatServerRegex : Regex
	{
		public RunatServerRegex()
		{
			pattern = "runat\\W*server";
			roptions = RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Singleline | RegexOptions.CultureInvariant;
			factory = new RunatServerRegexFactory13();
			capsize = 1;
			InitializeReferences();
		}
	}
	internal class SimpleDirectiveRegexRunner14 : RegexRunner
	{
		public unsafe override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			int num8;
			if (2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_0122;
			}
			goto IL_0cbf;
			IL_01ea:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0002\t:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_029d;
			}
			goto IL_0cbf;
			IL_0dd9:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01ea;
			IL_0c50:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				goto IL_0cb6;
			}
			goto IL_0cbf;
			IL_0baa:
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if (num9 != num4)
			{
				array[--num5] = num4;
				array2[--num6] = num4;
				array[--num5] = 22;
				if (num5 > 204 && num6 > 153)
				{
					goto IL_015e;
				}
				array[--num5] = 23;
				goto IL_0cbf;
			}
			array[--num5] = 24;
			goto IL_0c1d;
			IL_05b3:
			num8 = array2[num6++];
			Capture(5, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			if (num4 < num3 && text[num4++] == '"')
			{
				goto IL_0b4a;
			}
			goto IL_0cbf;
			IL_0d89:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0122;
			IL_0c1d:
			if ((num8 = num3 - num4) > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c50;
			IL_0cb6:
			runtextpos = num4;
			return;
			IL_0cbf:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 23:
					break;
				default:
					goto IL_0d6c;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0d89;
				case 3:
					goto IL_0dd9;
				case 4:
					goto IL_0e29;
				case 5:
					num6 += 2;
					continue;
				case 6:
					array2[--num6] = array[num5++];
					continue;
				case 7:
				{
					int num10 = array[num5++];
					if (num10 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num10 != Crawlpos());
					}
					continue;
				}
				case 8:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 9:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 13;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_0693;
				case 10:
					goto IL_0ef6;
				case 11:
					goto IL_0f46;
				case 12:
					goto IL_0f96;
				case 13:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 17;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08eb;
				case 14:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_0693;
				case 15:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_076e;
				case 16:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_080b;
				case 17:
					num4 = array[num5++];
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					array2[--num6] = num4;
					array[--num5] = 1;
					if ((num8 = num3 - num4) > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b1a;
				case 18:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08eb;
				case 19:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09c6;
				case 20:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a52;
				case 21:
					num4 = array[num5++];
					num7 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						continue;
					}
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b1a;
				case 22:
					goto IL_1253;
				case 24:
					array2[--num6] = array[num5++];
					continue;
				case 25:
					goto IL_1294;
					IL_08eb:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09c6;
					IL_080b:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					if (num4 >= num3)
					{
						continue;
					}
					goto IL_0844;
					IL_076e:
					if (num4 >= num3 || text[num4++] != '\'')
					{
						continue;
					}
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (text[num4++] == '\'')
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_080b;
					IL_0693:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_076e;
					IL_0b1a:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b4a;
					IL_09c6:
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\u0001\u0004\u0001%&>?d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a52;
					IL_0a52:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b4a;
				}
				break;
				IL_1294:
				num4 = array[num5++];
				num7 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					continue;
				}
				goto IL_12ca;
				IL_0844:
				if (text[num4++] != '\'')
				{
					continue;
				}
				goto IL_0b4a;
			}
			goto IL_015e;
			IL_0b4a:
			num8 = array2[num6++];
			Capture(2, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			goto IL_0baa;
			IL_12ca:
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c50;
			IL_029d:
			array2[--num6] = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)num5);
			array2[--num6] = Crawlpos();
			array[--num5] = 5;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\u0001\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num4 = (array[--num5] = array2[num6++]);
				array[--num5] = 6;
				num8 = array2[num6++];
				num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
				array[--num5] = num8;
				array[--num5] = 7;
				num8 = array2[num6++];
				Capture(3, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				array2[--num6] = num4;
				array[--num5] = 1;
				array[--num5] = num4;
				array[--num5] = 9;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 10;
				}
				goto IL_043b;
			}
			goto IL_0cbf;
			IL_015e:
			array2[--num6] = num4;
			array[--num5] = 1;
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01ea;
			IL_1253:
			num4 = array[num5++];
			_ = array2[num6++];
			array[--num5] = 24;
			goto IL_0c1d;
			IL_0ef6:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 10;
			}
			goto IL_043b;
			IL_0e29:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_029d;
			IL_0122:
			if (num4 < num3 && text[num4++] == '@')
			{
				array2[--num6] = -1;
				array[--num5] = 1;
				goto IL_0baa;
			}
			goto IL_0cbf;
			IL_0516:
			if (num4 < num3 && text[num4++] == '"')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (text[num4++] == '"')
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 12;
				}
				goto IL_05b3;
			}
			goto IL_0cbf;
			IL_0f46:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 11;
			}
			goto IL_0516;
			IL_0d6c:
			num4 = array[num5++];
			goto IL_0cb6;
			IL_043b:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] == '=')
			{
				num8 = array2[num6++];
				Capture(4, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 11;
				}
				goto IL_0516;
			}
			goto IL_0cbf;
			IL_0f96:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 12;
			}
			goto IL_05b3;
		}

		public override bool FindFirstChar()
		{
			string text = runtext;
			int num = runtextend;
			int num2 = runtextpos + 1;
			while (num2 < num)
			{
				int num4;
				int num3;
				if ((num3 = text[num2]) != 37)
				{
					num4 = (((uint)(num3 -= 37) > 23u) ? 2 : (num3 switch
					{
						1 => 2, 
						2 => 2, 
						3 => 2, 
						4 => 2, 
						5 => 2, 
						6 => 2, 
						7 => 2, 
						8 => 2, 
						9 => 2, 
						10 => 2, 
						11 => 2, 
						12 => 2, 
						13 => 2, 
						14 => 2, 
						15 => 2, 
						16 => 2, 
						17 => 2, 
						18 => 2, 
						19 => 2, 
						20 => 2, 
						21 => 2, 
						22 => 2, 
						23 => 1, 
						_ => 0, 
					}));
				}
				else
				{
					num3 = num2;
					if (text[--num3] == '<')
					{
						runtextpos = num3;
						return true;
					}
					num4 = 1;
				}
				num2 = num4 + num2;
			}
			runtextpos = runtextend;
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 51;
		}
	}
	internal class SimpleDirectiveRegexFactory14 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new SimpleDirectiveRegexRunner14();
		}
	}
	public class SimpleDirectiveRegex : Regex
	{
		public SimpleDirectiveRegex()
		{
			pattern = "<%\\s*@(\\s*(?<attrname>\\w[\\w:]*(?=\\W))(\\s*(?<equal>=)\\s*\"(?<attrval>[^\"]*)\"|\\s*(?<equal>=)\\s*'(?<attrval>[^']*)'|\\s*(?<equal>=)\\s*(?<attrval>[^\\s%>]*)|(?<equal>)(?<attrval>\\s*?)))*\\s*?%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new SimpleDirectiveRegexFactory14();
			capnames = new Hashtable();
			capnames.Add("attrval", 5);
			capnames.Add("2", 2);
			capnames.Add("0", 0);
			capnames.Add("1", 1);
			capnames.Add("equal", 4);
			capnames.Add("attrname", 3);
			capslist = new string[6];
			capslist[0] = "0";
			capslist[1] = "1";
			capslist[2] = "2";
			capslist[3] = "attrname";
			capslist[4] = "equal";
			capslist[5] = "attrval";
			capsize = 6;
			InitializeReferences();
		}
	}
	internal class DataBindRegexRunner15 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			int num8;
			if (num4 == runtextstart)
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_00f9;
			}
			goto IL_03a5;
			IL_0530:
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 5;
			}
			goto IL_01f5;
			IL_04b9:
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 3;
			}
			goto IL_0162;
			IL_01f5:
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 6;
			goto IL_0225;
			IL_0225:
			num8 = array2[num6++];
			int num9 = (num7 = array2[num6++]);
			array[--num5] = num7;
			if ((num9 != num4 || num8 < 0) && num8 < 1)
			{
				array2[--num6] = num4;
				array2[--num6] = num8 + 1;
				array[--num5] = 7;
				if (num5 > 48 && num6 > 36)
				{
					goto IL_01aa;
				}
				array[--num5] = 8;
				goto IL_03a5;
			}
			array[--num5] = num8;
			array[--num5] = 9;
			goto IL_02b9;
			IL_0363:
			if (num4 >= num3)
			{
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				goto IL_039c;
			}
			goto IL_03a5;
			IL_0162:
			if (num4 < num3 && text[num4++] == '#')
			{
				array2[--num6] = -1;
				array2[--num6] = 0;
				array[--num5] = 4;
				goto IL_0225;
			}
			goto IL_03a5;
			IL_03a5:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 8:
					break;
				default:
					goto IL_0416;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0433;
				case 3:
					goto IL_0483;
				case 4:
					num6 += 2;
					continue;
				case 5:
					goto IL_04fa;
				case 6:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 7:
					goto IL_0584;
				case 9:
					num8 = array[num5++];
					array2[--num6] = array[num5++];
					array2[--num6] = num8;
					continue;
				case 10:
					goto IL_0612;
				}
				break;
				IL_0584:
				if ((num8 = array2[num6++] - 1) < 0)
				{
					array2[num6] = array[num5++];
					array2[--num6] = num8;
					continue;
				}
				goto IL_0598;
				IL_0483:
				num4 = array[num5++];
				num7 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					continue;
				}
				goto IL_04b9;
				IL_04fa:
				num4 = array[num5++];
				num7 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
				{
					continue;
				}
				goto IL_0530;
			}
			goto IL_01aa;
			IL_0612:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 10;
			}
			goto IL_0363;
			IL_0433:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_00f9;
			IL_02b9:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 10;
				}
				goto IL_0363;
			}
			goto IL_03a5;
			IL_00f9:
			if (2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				if ((num8 = num3 - num4) > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4;
					array[--num5] = 3;
				}
				goto IL_0162;
			}
			goto IL_03a5;
			IL_0598:
			num4 = array2[num6++];
			array[--num5] = num8;
			array[--num5] = 9;
			goto IL_02b9;
			IL_0416:
			num4 = array[num5++];
			goto IL_039c;
			IL_01aa:
			array2[--num6] = num4;
			array[--num5] = 1;
			if ((num8 = num3 - num4) > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 5;
			}
			goto IL_01f5;
			IL_039c:
			runtextpos = num4;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 12;
		}
	}
	internal class DataBindRegexFactory15 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new DataBindRegexRunner15();
		}
	}
	public class DataBindRegex : Regex
	{
		public DataBindRegex()
		{
			pattern = "\\G\\s*<%\\s*?#(?<code>.*?)?%>\\s*\\z";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new DataBindRegexFactory15();
			capnames = new Hashtable();
			capnames.Add("code", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "code";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class ExpressionBuilderRegexRunner16 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num8;
			int num7;
			if (num4 == runtextstart)
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_00f9;
			}
			goto IL_049b;
			IL_05cd:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_0236;
			IL_00f9:
			if (2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 3;
				}
				goto IL_01a3;
			}
			goto IL_049b;
			IL_0459:
			if (num4 >= num3)
			{
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 7;
				goto IL_0492;
			}
			goto IL_049b;
			IL_031b:
			num8 = array2[num6++];
			int num9 = (num7 = array2[num6++]);
			array[--num5] = num7;
			if ((num9 != num4 || num8 < 0) && num8 < 1)
			{
				array2[--num6] = num4;
				array2[--num6] = num8 + 1;
				array[--num5] = 8;
				if (num5 > 52 && num6 > 39)
				{
					goto IL_025f;
				}
				array[--num5] = 9;
				goto IL_049b;
			}
			array[--num5] = num8;
			array[--num5] = 10;
			goto IL_03af;
			IL_057d:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01a3;
			IL_0236:
			array2[--num6] = -1;
			array2[--num6] = 0;
			array[--num5] = 5;
			goto IL_031b;
			IL_049b:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 9:
					break;
				default:
					goto IL_0510;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_052d;
				case 3:
					goto IL_057d;
				case 4:
					goto IL_05cd;
				case 5:
					num6 += 2;
					continue;
				case 6:
					goto IL_0629;
				case 7:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 8:
					goto IL_0698;
				case 10:
					num8 = array[num5++];
					array2[--num6] = array[num5++];
					array2[--num6] = num8;
					continue;
				case 11:
					goto IL_0726;
				}
				break;
				IL_0698:
				if ((num8 = array2[num6++] - 1) < 0)
				{
					array2[num6] = array[num5++];
					array2[--num6] = num8;
					continue;
				}
				goto IL_06ac;
			}
			goto IL_025f;
			IL_0726:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 11;
			}
			goto IL_0459;
			IL_052d:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_00f9;
			IL_0492:
			runtextpos = num4;
			return;
			IL_025f:
			array2[--num6] = num4;
			array[--num5] = 1;
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 6;
			}
			goto IL_02eb;
			IL_06ac:
			num4 = array2[num6++];
			array[--num5] = num8;
			array[--num5] = 10;
			goto IL_03af;
			IL_03af:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 11;
				}
				goto IL_0459;
			}
			goto IL_049b;
			IL_02eb:
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 7;
			goto IL_031b;
			IL_0629:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 6;
			}
			goto IL_02eb;
			IL_0510:
			num4 = array[num5++];
			goto IL_0492;
			IL_01a3:
			if (num4 < num3 && text[num4++] == '$')
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_0236;
			}
			goto IL_049b;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 13;
		}
	}
	internal class ExpressionBuilderRegexFactory16 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new ExpressionBuilderRegexRunner16();
		}
	}
	internal class ExpressionBuilderRegex : Regex
	{
		public ExpressionBuilderRegex()
		{
			pattern = "\\G\\s*<%\\s*\\$\\s*(?<code>.*)?%>\\s*\\z";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new ExpressionBuilderRegexFactory16();
			capnames = new Hashtable();
			capnames.Add("code", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "code";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class BindExpressionRegexRunner17 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num8;
			if (num4 <= num2 || text[num4 - 1] == '\n')
			{
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_010f;
			}
			goto IL_03e9;
			IL_03e9:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0467;
				case 3:
					goto IL_04b7;
				case 4:
					goto IL_0507;
				case 5:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 6:
					goto IL_0576;
				}
				break;
			}
			num4 = array[num5++];
			goto IL_03e0;
			IL_0507:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_02d0;
			IL_0576:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 6;
			}
			goto IL_03a7;
			IL_02d0:
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 5;
			if (num4 < num3 && char.ToLower(text[num4++], CultureInfo.InvariantCulture) == ')')
			{
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 6;
				}
				goto IL_03a7;
			}
			goto IL_03e9;
			IL_0211:
			if (num4 < num3 && char.ToLower(text[num4++], CultureInfo.InvariantCulture) == '(')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\u0001\0\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_02d0;
			}
			goto IL_03e9;
			IL_04b7:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_0211;
			IL_03a7:
			if (num4 >= num3)
			{
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 5;
				goto IL_03e0;
			}
			goto IL_03e9;
			IL_010f:
			if (4 <= num3 - num4 && char.ToLower(text[num4], CultureInfo.InvariantCulture) == 'b' && char.ToLower(text[num4 + 1], CultureInfo.InvariantCulture) == 'i' && char.ToLower(text[num4 + 2], CultureInfo.InvariantCulture) == 'n' && char.ToLower(text[num4 + 3], CultureInfo.InvariantCulture) == 'd')
			{
				num4 += 4;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 3;
				}
				goto IL_0211;
			}
			goto IL_03e9;
			IL_03e0:
			runtextpos = num4;
			return;
			IL_0467:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_010f;
		}

		public override bool FindFirstChar()
		{
			int num = runtextpos;
			string text = runtext;
			int num2 = runtextend - num;
			if (num2 > 0)
			{
				int result;
				while (true)
				{
					num2--;
					if (!RegexRunner.CharInClass(char.ToLower(text[num++], CultureInfo.InvariantCulture), "\0\u0002\u0001bcd"))
					{
						if (num2 <= 0)
						{
							result = 0;
							break;
						}
						continue;
					}
					num--;
					result = 1;
					break;
				}
				runtextpos = num;
				return (byte)result != 0;
			}
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 9;
		}
	}
	internal class BindExpressionRegexFactory17 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new BindExpressionRegexRunner17();
		}
	}
	internal class BindExpressionRegex : Regex
	{
		public BindExpressionRegex()
		{
			pattern = "^\\s*bind\\s*\\((?<params>.*)\\)\\s*\\z";
			roptions = RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Singleline | RegexOptions.CultureInvariant;
			factory = new BindExpressionRegexFactory17();
			capnames = new Hashtable();
			capnames.Add("params", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "params";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class BindParametersRegexRunner18 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			int num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			while (true)
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				array[--num5] = num4;
				array[--num5] = 3;
				array2[--num6] = num4;
				array[--num5] = 1;
				if (num4 < num3 && text[num4++] == '"')
				{
					array2[--num6] = num4;
					array[--num5] = 1;
					array2[--num6] = num4;
					array[--num5] = 1;
					array[--num5] = num4;
					array[--num5] = 4;
					array2[--num6] = num4;
					array[--num5] = 1;
					if (1 <= num3 - num4)
					{
						num4++;
						num8 = 1;
						while (RegexRunner.CharInClass(text[num4 - num8--], "\0\u0002\t./\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
						{
							if (num8 > 0)
							{
								continue;
							}
							goto IL_01f4;
						}
					}
				}
				goto IL_0e4c;
				IL_0cfc:
				num8 = array2[num6++];
				int num9 = (num7 = array2[num6++]);
				array[--num5] = num7;
				if ((num9 != num4 || num8 < 0) && num8 < 1)
				{
					array2[--num6] = num4;
					array2[--num6] = num8 + 1;
					array[--num5] = 18;
					if (num5 > 236 && num6 > 177)
					{
						goto IL_08c4;
					}
					array[--num5] = 19;
					goto IL_0e4c;
				}
				array[--num5] = num8;
				array[--num5] = 20;
				goto IL_0d96;
				IL_0d96:
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 21;
				}
				goto IL_0e0a;
				IL_07c7:
				num8 = array2[num6++];
				Capture(6, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				goto IL_07f7;
				IL_07f7:
				num8 = array2[num6++];
				Capture(1, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 11;
				}
				goto IL_089b;
				IL_01f4:
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0002\t./\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 5;
				}
				goto IL_0268;
				IL_0e0a:
				if (num4 >= num3)
				{
					num8 = array2[num6++];
					Capture(0, num8, num4);
					array[--num5] = num8;
					array[--num5] = 6;
					break;
				}
				goto IL_0e4c;
				IL_096f:
				array2[--num6] = num4;
				array[--num5] = 1;
				array[--num5] = num4;
				array[--num5] = 14;
				array2[--num6] = num4;
				array[--num5] = 1;
				if (num4 < num3 && text[num4++] == '"')
				{
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_0a62;
				}
				goto IL_0e4c;
				IL_0ccc:
				num8 = array2[num6++];
				Capture(10, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				goto IL_0cfc;
				IL_0e4c:
				while (true)
				{
					runtrackpos = num5;
					runstackpos = num6;
					EnsureStorage();
					num5 = runtrackpos;
					num6 = runstackpos;
					array = runtrack;
					array2 = runstack;
					switch (array[num5++])
					{
					case 19:
						break;
					default:
						goto IL_0ee9;
					case 1:
						num6++;
						continue;
					case 2:
						goto IL_0f06;
					case 3:
						num4 = array[num5++];
						array2[--num6] = num4;
						array[--num5] = 1;
						if (num4 >= num3 || text[num4++] != '\'')
						{
							continue;
						}
						array2[--num6] = num4;
						array[--num5] = 1;
						array2[--num6] = num4;
						array[--num5] = 1;
						array[--num5] = num4;
						array[--num5] = 8;
						array2[--num6] = num4;
						array[--num5] = 1;
						if (1 > num3 - num4)
						{
							continue;
						}
						num4++;
						num8 = 1;
						while (RegexRunner.CharInClass(text[num4 - num8--], "\0\u0002\t./\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
						{
							if (num8 > 0)
							{
								continue;
							}
							goto IL_0564;
						}
						continue;
					case 4:
						num4 = array[num5++];
						array2[--num6] = num4;
						array[--num5] = 1;
						if (num4 >= num3 || text[num4++] != '[' || 1 > num3 - num4)
						{
							continue;
						}
						num4++;
						num8 = 1;
						while (RegexRunner.CharInClass(text[num4 - num8--], "\0\u0001\0\0"))
						{
							if (num8 > 0)
							{
								continue;
							}
							goto IL_0315;
						}
						continue;
					case 5:
						goto IL_0f78;
					case 6:
						array2[--num6] = array[num5++];
						Uncapture();
						continue;
					case 7:
						num4 = array[num5++];
						num8 = array[num5++];
						if (num8 > 0)
						{
							array[--num5] = num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 7;
						}
						goto IL_0389;
					case 8:
						num4 = array[num5++];
						array2[--num6] = num4;
						array[--num5] = 1;
						if (num4 >= num3 || text[num4++] != '[' || 1 > num3 - num4)
						{
							continue;
						}
						num4++;
						num8 = 1;
						while (RegexRunner.CharInClass(text[num4 - num8--], "\0\u0001\0\0"))
						{
							if (num8 > 0)
							{
								continue;
							}
							goto IL_0685;
						}
						continue;
					case 9:
						num4 = array[num5++];
						num8 = array[num5++];
						if (num8 > 0)
						{
							array[--num5] = num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 9;
						}
						goto IL_05d8;
					case 10:
						num4 = array[num5++];
						num8 = array[num5++];
						if (num8 > 0)
						{
							array[--num5] = num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 10;
						}
						goto IL_06f9;
					case 11:
						goto IL_10e8;
					case 12:
						num6 += 2;
						continue;
					case 13:
						goto IL_1144;
					case 14:
						num4 = array[num5++];
						array2[--num6] = num4;
						array[--num5] = 1;
						if (num4 >= num3 || text[num4++] != '\'')
						{
							continue;
						}
						array2[--num6] = num4;
						array[--num5] = 1;
						num8 = (num7 = num3 - num4) + 1;
						while (--num8 > 0)
						{
							if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
							{
								num4--;
								break;
							}
						}
						if (num7 > num8)
						{
							array[--num5] = num7 - num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 16;
						}
						goto IL_0ba9;
					case 15:
						goto IL_11a5;
					case 16:
						num4 = array[num5++];
						num8 = array[num5++];
						if (num8 > 0)
						{
							array[--num5] = num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 16;
						}
						goto IL_0ba9;
					case 17:
						goto IL_1245;
					case 18:
						goto IL_1295;
					case 20:
						num8 = array[num5++];
						array2[--num6] = array[num5++];
						array2[--num6] = num8;
						continue;
					case 21:
						goto IL_1323;
						IL_0685:
						num8 = (num7 = num3 - num4) + 1;
						while (--num8 > 0)
						{
							if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
							{
								num4--;
								break;
							}
						}
						if (num7 > num8)
						{
							array[--num5] = num7 - num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 10;
						}
						goto IL_06f9;
						IL_0389:
						if (num4 >= num3)
						{
							continue;
						}
						goto IL_0392;
						IL_0564:
						num8 = (num7 = num3 - num4) + 1;
						while (--num8 > 0)
						{
							if (!RegexRunner.CharInClass(text[num4++], "\0\u0002\t./\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
							{
								num4--;
								break;
							}
						}
						if (num7 > num8)
						{
							array[--num5] = num7 - num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 9;
						}
						goto IL_05d8;
						IL_06f9:
						if (num4 >= num3 || text[num4++] != ']')
						{
							continue;
						}
						num8 = array2[num6++];
						Capture(9, num8, num4);
						array[--num5] = num8;
						array[--num5] = 6;
						goto IL_0748;
						IL_0315:
						num8 = (num7 = num3 - num4) + 1;
						while (--num8 > 0)
						{
							if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
							{
								num4--;
								break;
							}
						}
						if (num7 > num8)
						{
							array[--num5] = num7 - num8 - 1;
							array[--num5] = num4 - 1;
							array[--num5] = 7;
						}
						goto IL_0389;
						IL_0ba9:
						num8 = array2[num6++];
						Capture(15, num8, num4);
						array[--num5] = num8;
						array[--num5] = 6;
						if (num4 >= num3)
						{
							continue;
						}
						goto IL_0be2;
						IL_05d8:
						num8 = array2[num6++];
						Capture(8, num8, num4);
						array[--num5] = num8;
						array[--num5] = 6;
						goto IL_0748;
						IL_0748:
						num8 = array2[num6++];
						Capture(7, num8, num4);
						array[--num5] = num8;
						array[--num5] = 6;
						num8 = array2[num6++];
						Capture(14, num8, num4);
						array[--num5] = num8;
						array[--num5] = 6;
						if (num4 >= num3)
						{
							continue;
						}
						goto IL_07b1;
					}
					break;
					IL_1295:
					if ((num8 = array2[num6++] - 1) < 0)
					{
						array2[num6] = array[num5++];
						array2[--num6] = num8;
						continue;
					}
					goto IL_12a9;
					IL_07b1:
					if (text[num4++] != '\'')
					{
						continue;
					}
					goto IL_07c7;
					IL_0be2:
					if (text[num4++] != '\'')
					{
						continue;
					}
					goto IL_0bf8;
					IL_0392:
					if (text[num4++] != ']')
					{
						continue;
					}
					goto IL_03a8;
				}
				goto IL_08c4;
				IL_1323:
				num4 = array[num5++];
				num8 = array[num5++];
				if (num8 > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 21;
				}
				goto IL_0e0a;
				IL_089b:
				array2[--num6] = -1;
				array2[--num6] = 0;
				array[--num5] = 12;
				goto IL_0cfc;
				IL_12a9:
				num4 = array2[num6++];
				array[--num5] = num8;
				array[--num5] = 20;
				goto IL_0d96;
				IL_1245:
				num4 = array[num5++];
				num8 = array[num5++];
				if (num8 > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 17;
				}
				goto IL_0ccc;
				IL_0f06:
				num4 = array[num5++];
				num8 = array[num5++];
				if (num8 > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				continue;
				IL_11a5:
				num4 = array[num5++];
				num8 = array[num5++];
				if (num8 > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 15;
				}
				goto IL_0a62;
				IL_0c28:
				num8 = array2[num6++];
				Capture(11, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 17;
				}
				goto IL_0ccc;
				IL_0bf8:
				num8 = array2[num6++];
				Capture(13, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				goto IL_0c28;
				IL_1144:
				num4 = array[num5++];
				num8 = array[num5++];
				if (num8 > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 13;
				}
				goto IL_096f;
				IL_0ee9:
				num4 = array[num5++];
				break;
				IL_10e8:
				num4 = array[num5++];
				num8 = array[num5++];
				if (num8 > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 11;
				}
				goto IL_089b;
				IL_08c4:
				array2[--num6] = num4;
				array[--num5] = 1;
				if (num4 < num3 && text[num4++] == ',')
				{
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 13;
					}
					goto IL_096f;
				}
				goto IL_0e4c;
				IL_0f78:
				num4 = array[num5++];
				num8 = array[num5++];
				if (num8 > 0)
				{
					array[--num5] = num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 5;
				}
				goto IL_0268;
				IL_0a62:
				num8 = array2[num6++];
				Capture(15, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				if (num4 < num3 && text[num4++] == '"')
				{
					num8 = array2[num6++];
					Capture(12, num8, num4);
					array[--num5] = num8;
					array[--num5] = 6;
					goto IL_0c28;
				}
				goto IL_0e4c;
				IL_0268:
				num8 = array2[num6++];
				Capture(4, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				goto IL_03d8;
				IL_03a8:
				num8 = array2[num6++];
				Capture(5, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				goto IL_03d8;
				IL_03d8:
				num8 = array2[num6++];
				Capture(3, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				num8 = array2[num6++];
				Capture(14, num8, num4);
				array[--num5] = num8;
				array[--num5] = 6;
				if (num4 < num3 && text[num4++] == '"')
				{
					num8 = array2[num6++];
					Capture(2, num8, num4);
					array[--num5] = num8;
					array[--num5] = 6;
					goto IL_07f7;
				}
				goto IL_0e4c;
			}
			runtextpos = num4;
		}

		public override bool FindFirstChar()
		{
			int num = runtextpos;
			string text = runtext;
			int num2 = runtextend - num;
			if (num2 > 0)
			{
				int result;
				while (true)
				{
					num2--;
					if (!RegexRunner.CharInClass(text[num++], "\0\u0004\u0001\"#'(d"))
					{
						if (num2 <= 0)
						{
							result = 0;
							break;
						}
						continue;
					}
					num--;
					result = 1;
					break;
				}
				runtextpos = num;
				return (byte)result != 0;
			}
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 59;
		}
	}
	internal class BindParametersRegexFactory18 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new BindParametersRegexRunner18();
		}
	}
	internal class BindParametersRegex : Regex
	{
		public BindParametersRegex()
		{
			pattern = "\\s*((\"(?<fieldName>(([\\w\\.]+)|(\\[.+\\])))\")|('(?<fieldName>(([\\w\\.]+)|(\\[.+\\])))'))\\s*(,\\s*((\"(?<formatString>.*)\")|('(?<formatString>.*)'))\\s*)?\\s*\\z";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new BindParametersRegexFactory18();
			capnames = new Hashtable();
			capnames.Add("10", 10);
			capnames.Add("8", 8);
			capnames.Add("9", 9);
			capnames.Add("13", 13);
			capnames.Add("formatString", 15);
			capnames.Add("fieldName", 14);
			capnames.Add("0", 0);
			capnames.Add("1", 1);
			capnames.Add("2", 2);
			capnames.Add("3", 3);
			capnames.Add("4", 4);
			capnames.Add("5", 5);
			capnames.Add("6", 6);
			capnames.Add("7", 7);
			capnames.Add("11", 11);
			capnames.Add("12", 12);
			capslist = new string[16];
			capslist[0] = "0";
			capslist[1] = "1";
			capslist[2] = "2";
			capslist[3] = "3";
			capslist[4] = "4";
			capslist[5] = "5";
			capslist[6] = "6";
			capslist[7] = "7";
			capslist[8] = "8";
			capslist[9] = "9";
			capslist[10] = "10";
			capslist[11] = "11";
			capslist[12] = "12";
			capslist[13] = "13";
			capslist[14] = "fieldName";
			capslist[15] = "formatString";
			capsize = 16;
			InitializeReferences();
		}
	}
	internal class FormatStringRegexRunner19 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 <= num2 || text[num4 - 1] == '\n')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				array2[--num6] = -1;
				array[--num5] = 1;
				goto IL_02af;
			}
			goto IL_039b;
			IL_01eb:
			int num7 = array2[num6++];
			int num8;
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if ((num9 != num4 || num7 < 0) && num7 < 1)
			{
				array2[--num6] = num4;
				array2[--num6] = num7 + 1;
				array[--num5] = 5;
				if (num5 > 60 && num6 > 45)
				{
					goto IL_016d;
				}
				array[--num5] = 6;
				goto IL_039b;
			}
			array[--num5] = num7;
			array[--num5] = 7;
			goto IL_027f;
			IL_0392:
			runtextpos = num4;
			return;
			IL_02af:
			int num10 = (num7 = array2[num6++]);
			array[--num5] = num7;
			if (num10 != num4)
			{
				array[--num5] = num4;
				array2[--num6] = num4;
				array[--num5] = 8;
				if (num5 > 60 && num6 > 45)
				{
					goto IL_00c6;
				}
				array[--num5] = 9;
				goto IL_039b;
			}
			array[--num5] = 10;
			goto IL_031c;
			IL_0144:
			array2[--num6] = -1;
			array2[--num6] = 0;
			array[--num5] = 3;
			goto IL_01eb;
			IL_016d:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (2 <= num3 - num4 && text[num4] == '"' && text[num4 + 1] == '"')
			{
				num4 += 2;
				num7 = array2[num6++];
				Capture(3, num7, num4);
				array[--num5] = num7;
				array[--num5] = 4;
				goto IL_01eb;
			}
			goto IL_039b;
			IL_0532:
			num4 = array[num5++];
			_ = array2[num6++];
			array[--num5] = 10;
			goto IL_031c;
			IL_0429:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0144;
			IL_031c:
			num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 4;
			if (num4 >= num3 || text[num4] == '\n')
			{
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 4;
				goto IL_0392;
			}
			goto IL_039b;
			IL_04b8:
			num4 = array2[num6++];
			array[--num5] = num7;
			array[--num5] = 7;
			goto IL_027f;
			IL_039b:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 9:
					break;
				case 6:
					goto IL_016d;
				default:
					goto IL_040c;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0429;
				case 3:
					num6 += 2;
					continue;
				case 4:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 5:
					goto IL_04a4;
				case 7:
					num7 = array[num5++];
					array2[--num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				case 8:
					goto IL_0532;
				case 10:
					array2[--num6] = array[num5++];
					continue;
				}
				break;
				IL_04a4:
				if ((num7 = array2[num6++] - 1) < 0)
				{
					array2[num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				}
				goto IL_04b8;
			}
			goto IL_00c6;
			IL_040c:
			num4 = array[num5++];
			goto IL_0392;
			IL_00c6:
			array2[--num6] = num4;
			array[--num5] = 1;
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (text[num4++] == '"')
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0144;
			IL_027f:
			num7 = array2[num6++];
			Capture(2, num7, num4);
			array[--num5] = num7;
			array[--num5] = 4;
			goto IL_02af;
		}

		public override bool FindFirstChar()
		{
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 15;
		}
	}
	internal class FormatStringRegexFactory19 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new FormatStringRegexRunner19();
		}
	}
	internal class FormatStringRegex : Regex
	{
		public FormatStringRegex()
		{
			pattern = "^(([^\"]*(\"\")?)*)$";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new FormatStringRegexFactory19();
			capsize = 4;
			InitializeReferences();
		}
	}
	internal class WebResourceRegexRunner20 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num8;
			if (2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_0122;
			}
			goto IL_0483;
			IL_033a:
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 5;
			if (2 <= num3 - num4 && text[num4] == '"' && text[num4 + 1] == ')')
			{
				num4 += 2;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 6;
				}
				goto IL_0414;
			}
			goto IL_0483;
			IL_0414:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 5;
				goto IL_047a;
			}
			goto IL_0483;
			IL_05a1:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_033a;
			IL_0122:
			if (num4 < num3 && text[num4++] == '=')
			{
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 3;
				}
				goto IL_01b5;
			}
			goto IL_0483;
			IL_047a:
			runtextpos = num4;
			return;
			IL_0501:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0122;
			IL_0551:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01b5;
			IL_01b5:
			if (13 <= num3 - num4 && text[num4] == 'W' && text[num4 + 1] == 'e' && text[num4 + 2] == 'b' && text[num4 + 3] == 'R' && text[num4 + 4] == 'e' && text[num4 + 5] == 's' && text[num4 + 6] == 'o' && text[num4 + 7] == 'u' && text[num4 + 8] == 'r' && text[num4 + 9] == 'c' && text[num4 + 10] == 'e' && text[num4 + 11] == '(' && text[num4 + 12] == '"')
			{
				num4 += 13;
				array2[--num6] = num4;
				array[--num5] = 1;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (text[num4++] == '"')
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_033a;
			}
			goto IL_0483;
			IL_0483:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0501;
				case 3:
					goto IL_0551;
				case 4:
					goto IL_05a1;
				case 5:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 6:
					goto IL_0610;
				}
				break;
			}
			num4 = array[num5++];
			goto IL_047a;
			IL_0610:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 6;
			}
			goto IL_0414;
		}

		public override bool FindFirstChar()
		{
			string text = runtext;
			int num = runtextend;
			int num2 = runtextpos + 1;
			while (num2 < num)
			{
				int num4;
				int num3;
				if ((num3 = text[num2]) != 37)
				{
					num4 = (((uint)(num3 -= 37) > 23u) ? 2 : (num3 switch
					{
						1 => 2, 
						2 => 2, 
						3 => 2, 
						4 => 2, 
						5 => 2, 
						6 => 2, 
						7 => 2, 
						8 => 2, 
						9 => 2, 
						10 => 2, 
						11 => 2, 
						12 => 2, 
						13 => 2, 
						14 => 2, 
						15 => 2, 
						16 => 2, 
						17 => 2, 
						18 => 2, 
						19 => 2, 
						20 => 2, 
						21 => 2, 
						22 => 2, 
						23 => 1, 
						_ => 0, 
					}));
				}
				else
				{
					num3 = num2;
					if (text[--num3] == '<')
					{
						runtextpos = num3;
						return true;
					}
					num4 = 1;
				}
				num2 = num4 + num2;
			}
			runtextpos = runtextend;
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 9;
		}
	}
	internal class WebResourceRegexFactory20 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new WebResourceRegexRunner20();
		}
	}
	internal class WebResourceRegex : Regex
	{
		public WebResourceRegex()
		{
			pattern = "<%\\s*=\\s*WebResource\\(\"(?<resourceName>[^\"]*)\"\\)\\s*%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new WebResourceRegexFactory20();
			capnames = new Hashtable();
			capnames.Add("resourceName", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "resourceName";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class NonWordRegexRunner21 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\u0001\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				int num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 2;
			}
			else
			{
				while (true)
				{
					runtrackpos = num5;
					runstackpos = num6;
					EnsureStorage();
					num5 = runtrackpos;
					num6 = runstackpos;
					array = runtrack;
					array2 = runstack;
					switch (array[num5++])
					{
					case 1:
						num6++;
						continue;
					case 2:
						array2[--num6] = array[num5++];
						Uncapture();
						continue;
					}
					break;
				}
				num4 = array[num5++];
			}
			runtextpos = num4;
		}

		public override bool FindFirstChar()
		{
			int num = runtextpos;
			string text = runtext;
			int num2 = runtextend - num;
			if (num2 > 0)
			{
				int result;
				while (true)
				{
					num2--;
					if (!RegexRunner.CharInClass(text[num++], "\u0001\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						if (num2 <= 0)
						{
							result = 0;
							break;
						}
						continue;
					}
					num--;
					result = 1;
					break;
				}
				runtextpos = num;
				return (byte)result != 0;
			}
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 3;
		}
	}
	internal class NonWordRegexFactory21 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new NonWordRegexRunner21();
		}
	}
	internal class NonWordRegex : Regex
	{
		public NonWordRegex()
		{
			pattern = "\\W";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new NonWordRegexFactory21();
			capsize = 1;
			InitializeReferences();
		}
	}
	internal class EvalExpressionRegexRunner22 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num8;
			if (num4 <= num2 || text[num4 - 1] == '\n')
			{
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_010f;
			}
			goto IL_03e9;
			IL_03e9:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0467;
				case 3:
					goto IL_04b7;
				case 4:
					goto IL_0507;
				case 5:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 6:
					goto IL_0576;
				}
				break;
			}
			num4 = array[num5++];
			goto IL_03e0;
			IL_0507:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_02d0;
			IL_0576:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 6;
			}
			goto IL_03a7;
			IL_02d0:
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 5;
			if (num4 < num3 && char.ToLower(text[num4++], CultureInfo.InvariantCulture) == ')')
			{
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 6;
				}
				goto IL_03a7;
			}
			goto IL_03e9;
			IL_0211:
			if (num4 < num3 && char.ToLower(text[num4++], CultureInfo.InvariantCulture) == '(')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\u0001\0\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_02d0;
			}
			goto IL_03e9;
			IL_04b7:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_0211;
			IL_03a7:
			if (num4 >= num3)
			{
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 5;
				goto IL_03e0;
			}
			goto IL_03e9;
			IL_010f:
			if (4 <= num3 - num4 && char.ToLower(text[num4], CultureInfo.InvariantCulture) == 'e' && char.ToLower(text[num4 + 1], CultureInfo.InvariantCulture) == 'v' && char.ToLower(text[num4 + 2], CultureInfo.InvariantCulture) == 'a' && char.ToLower(text[num4 + 3], CultureInfo.InvariantCulture) == 'l')
			{
				num4 += 4;
				int num7;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(char.ToLower(text[num4++], CultureInfo.InvariantCulture), "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 3;
				}
				goto IL_0211;
			}
			goto IL_03e9;
			IL_03e0:
			runtextpos = num4;
			return;
			IL_0467:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_010f;
		}

		public override bool FindFirstChar()
		{
			int num = runtextpos;
			string text = runtext;
			int num2 = runtextend - num;
			if (num2 > 0)
			{
				int result;
				while (true)
				{
					num2--;
					if (!RegexRunner.CharInClass(char.ToLower(text[num++], CultureInfo.InvariantCulture), "\0\u0002\u0001efd"))
					{
						if (num2 <= 0)
						{
							result = 0;
							break;
						}
						continue;
					}
					num--;
					result = 1;
					break;
				}
				runtextpos = num;
				return (byte)result != 0;
			}
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 9;
		}
	}
	internal class EvalExpressionRegexFactory22 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new EvalExpressionRegexRunner22();
		}
	}
	internal class EvalExpressionRegex : Regex
	{
		public EvalExpressionRegex()
		{
			pattern = "^\\s*eval\\s*\\((?<params>.*)\\)\\s*\\z";
			roptions = RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Singleline | RegexOptions.CultureInvariant;
			factory = new EvalExpressionRegexFactory22();
			capnames = new Hashtable();
			capnames.Add("params", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "params";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class BrowserCapsRefRegexRunner23 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			if (2 <= num3 - num4 && text[num4] == '$' && text[num4 + 1] == '{')
			{
				num4 += 2;
				array2[--num6] = num4;
				array[--num5] = 1;
				if (1 <= num3 - num4)
				{
					num4++;
					num7 = 1;
					while (RegexRunner.CharInClass(text[num4 - num7--], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						if (num7 > 0)
						{
							continue;
						}
						goto IL_0107;
					}
				}
			}
			goto IL_0203;
			IL_0275:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_017b;
			IL_0107:
			int num8;
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_017b;
			IL_0203:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0275;
				case 3:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				}
				break;
			}
			num4 = array[num5++];
			goto IL_01fa;
			IL_01fa:
			runtextpos = num4;
			return;
			IL_017b:
			num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			if (num4 < num3 && text[num4++] == '}')
			{
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_01fa;
			}
			goto IL_0203;
		}

		public override bool FindFirstChar()
		{
			string text = runtext;
			int num = runtextend;
			int num2 = runtextpos + 1;
			while (num2 < num)
			{
				int num4;
				int num3;
				if ((num3 = text[num2]) != 123)
				{
					num4 = (((uint)(num3 -= 36) > 87u) ? 2 : (num3 switch
					{
						1 => 2, 
						2 => 2, 
						3 => 2, 
						4 => 2, 
						5 => 2, 
						6 => 2, 
						7 => 2, 
						8 => 2, 
						9 => 2, 
						10 => 2, 
						11 => 2, 
						12 => 2, 
						13 => 2, 
						14 => 2, 
						15 => 2, 
						16 => 2, 
						17 => 2, 
						18 => 2, 
						19 => 2, 
						20 => 2, 
						21 => 2, 
						22 => 2, 
						23 => 2, 
						24 => 2, 
						25 => 2, 
						26 => 2, 
						27 => 2, 
						28 => 2, 
						29 => 2, 
						30 => 2, 
						31 => 2, 
						32 => 2, 
						33 => 2, 
						34 => 2, 
						35 => 2, 
						36 => 2, 
						37 => 2, 
						38 => 2, 
						39 => 2, 
						40 => 2, 
						41 => 2, 
						42 => 2, 
						43 => 2, 
						44 => 2, 
						45 => 2, 
						46 => 2, 
						47 => 2, 
						48 => 2, 
						49 => 2, 
						50 => 2, 
						51 => 2, 
						52 => 2, 
						53 => 2, 
						54 => 2, 
						55 => 2, 
						56 => 2, 
						57 => 2, 
						58 => 2, 
						59 => 2, 
						60 => 2, 
						61 => 2, 
						62 => 2, 
						63 => 2, 
						64 => 2, 
						65 => 2, 
						66 => 2, 
						67 => 2, 
						68 => 2, 
						69 => 2, 
						70 => 2, 
						71 => 2, 
						72 => 2, 
						73 => 2, 
						74 => 2, 
						75 => 2, 
						76 => 2, 
						77 => 2, 
						78 => 2, 
						79 => 2, 
						80 => 2, 
						81 => 2, 
						82 => 2, 
						83 => 2, 
						84 => 2, 
						85 => 2, 
						86 => 2, 
						87 => 0, 
						_ => 1, 
					}));
				}
				else
				{
					num3 = num2;
					if (text[--num3] == '$')
					{
						runtextpos = num3;
						return true;
					}
					num4 = 1;
				}
				num2 = num4 + num2;
			}
			runtextpos = runtextend;
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 6;
		}
	}
	internal class BrowserCapsRefRegexFactory23 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new BrowserCapsRefRegexRunner23();
		}
	}
	internal class BrowserCapsRefRegex : Regex
	{
		public BrowserCapsRefRegex()
		{
			pattern = "\\$(?:\\{(?<name>\\w+)\\})";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new BrowserCapsRefRegexFactory23();
			capnames = new Hashtable();
			capnames.Add("name", 1);
			capnames.Add("0", 0);
			capslist = new string[2];
			capslist[0] = "0";
			capslist[1] = "name";
			capsize = 2;
			InitializeReferences();
		}
	}
	internal class TagRegex40Runner24 : RegexRunner
	{
		public override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			if (num4 == runtextstart && num4 < num3 && text[num4++] == '<')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				if (1 <= num3 - num4)
				{
					num4++;
					num7 = 1;
					while (RegexRunner.CharInClass(text[num4 - num7--], "\0\u0004\t./:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						if (num7 > 0)
						{
							continue;
						}
						goto IL_00fd;
					}
				}
			}
			goto IL_0ee8;
			IL_0e90:
			if (num4 < num3 && text[num4++] == '>')
			{
				num7 = array2[num6++];
				Capture(0, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_0edf;
			}
			goto IL_0ee8;
			IL_033e:
			num7 = array2[num6++];
			Capture(4, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			array2[--num6] = num4;
			array[--num5] = 1;
			array[--num5] = num4;
			array[--num5] = 6;
			int num8;
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 7;
			}
			goto IL_0412;
			IL_0c1f:
			num7 = array2[num6++];
			Capture(2, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			num7 = array2[num6++];
			Capture(1, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			goto IL_0c7f;
			IL_0cf2:
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 26;
			}
			goto IL_0d66;
			IL_0edf:
			runtextpos = num4;
			return;
			IL_0d8f:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] == '/')
			{
				num7 = array2[num6++];
				Capture(6, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_0df6;
			}
			goto IL_0ee8;
			IL_00fd:
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\u0004\t./:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0171;
			IL_0412:
			if (num4 < num3 && text[num4++] == '=')
			{
				num7 = (num8 = num3 - num4) + 1;
				while (--num7 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num8 > num7)
				{
					array[--num5] = num8 - num7 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 8;
				}
				goto IL_04a5;
			}
			goto IL_0ee8;
			IL_0df6:
			num7 = array2[num6++];
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if ((num9 != num4 || num7 < 0) && num7 < 1)
			{
				array2[--num6] = num4;
				array2[--num6] = num7 + 1;
				array[--num5] = 28;
				if (num5 > 212 && num6 > 159)
				{
					goto IL_0d8f;
				}
				array[--num5] = 29;
				goto IL_0ee8;
			}
			array[--num5] = num7;
			array[--num5] = 30;
			goto IL_0e90;
			IL_0d66:
			array2[--num6] = -1;
			array2[--num6] = 0;
			array[--num5] = 27;
			goto IL_0df6;
			IL_0217:
			num7 = (num8 = num3 - num4) + 1;
			while (--num7 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num8 > num7)
			{
				array[--num5] = num8 - num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_028b;
			IL_028b:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num7 = (num8 = num3 - num4) + 1;
				while (--num7 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0004\t-.:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num8 > num7)
				{
					array[--num5] = num8 - num7 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 5;
				}
				goto IL_033e;
			}
			goto IL_0ee8;
			IL_0ee8:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 24:
					break;
				case 29:
					goto IL_0d8f;
				default:
					goto IL_0fa9;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0fc6;
				case 3:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 4:
					goto IL_1035;
				case 5:
					goto IL_1085;
				case 6:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 10;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 11;
					}
					goto IL_0622;
				case 7:
					goto IL_10e6;
				case 8:
					goto IL_1136;
				case 9:
					goto IL_1186;
				case 10:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 14;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_0832;
				case 11:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 11;
					}
					goto IL_0622;
				case 12:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 12;
					}
					goto IL_06b5;
				case 13:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 13;
					}
					goto IL_0752;
				case 14:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 18;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_0a50;
				case 15:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_0832;
				case 16:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_08c5;
				case 17:
					num4 = array[num5++];
					num8 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0001\0\0"))
					{
						continue;
					}
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 17;
					}
					goto IL_0959;
				case 18:
					num4 = array[num5++];
					array2[--num6] = num4;
					array[--num5] = 1;
					if ((num7 = num3 - num4) > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 22;
					}
					goto IL_0bef;
				case 19:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_0a50;
				case 20:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0ae3;
				case 21:
					num4 = array[num5++];
					num7 = array[num5++];
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 21;
					}
					goto IL_0b6f;
				case 22:
					num4 = array[num5++];
					num8 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						continue;
					}
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 22;
					}
					goto IL_0bef;
				case 23:
					goto IL_155f;
				case 25:
					array2[--num6] = array[num5++];
					continue;
				case 26:
					goto IL_15a0;
				case 27:
					num6 += 2;
					continue;
				case 28:
					goto IL_15fc;
				case 30:
					{
						num7 = array[num5++];
						array2[--num6] = array[num5++];
						array2[--num6] = num7;
						continue;
					}
					IL_08c5:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (3 > num3 - num4 || text[num4] != '<' || text[num4 + 1] != '%' || text[num4 + 2] != '#')
					{
						continue;
					}
					num4 += 3;
					if ((num7 = num3 - num4) > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 17;
					}
					goto IL_0959;
					IL_06b5:
					if (num4 >= num3 || text[num4++] != '\'')
					{
						continue;
					}
					array2[--num6] = num4;
					array[--num5] = 1;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (text[num4++] == '\'')
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 13;
					}
					goto IL_0752;
					IL_0ae3:
					array2[--num6] = num4;
					array[--num5] = 1;
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\u0001\b\u0001\"#'(/0=?d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 21;
					}
					goto IL_0b6f;
					IL_0832:
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_08c5;
					IL_0bef:
					num7 = array2[num6++];
					Capture(5, num7, num4);
					array[--num5] = num7;
					array[--num5] = 3;
					goto IL_0c1f;
					IL_0622:
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 12;
					}
					goto IL_06b5;
					IL_0b6f:
					num7 = array2[num6++];
					Capture(5, num7, num4);
					array[--num5] = num7;
					array[--num5] = 3;
					goto IL_0c1f;
					IL_0752:
					num7 = array2[num6++];
					Capture(5, num7, num4);
					array[--num5] = num7;
					array[--num5] = 3;
					if (num4 >= num3)
					{
						continue;
					}
					goto IL_078b;
					IL_0959:
					if (2 > num3 - num4)
					{
						continue;
					}
					goto IL_0965;
					IL_0a50:
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num7 = (num8 = num3 - num4) + 1;
					while (--num7 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num8 > num7)
					{
						array[--num5] = num8 - num7 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0ae3;
				}
				break;
				IL_15fc:
				if ((num7 = array2[num6++] - 1) < 0)
				{
					array2[num6] = array[num5++];
					array2[--num6] = num7;
					continue;
				}
				goto IL_1610;
				IL_078b:
				if (text[num4++] != '\'')
				{
					continue;
				}
				goto IL_0c1f;
				IL_0965:
				if (text[num4] != '%' || text[num4 + 1] != '>')
				{
					continue;
				}
				num4 += 2;
				num7 = array2[num6++];
				Capture(5, num7, num4);
				array[--num5] = num7;
				array[--num5] = 3;
				goto IL_0c1f;
			}
			goto IL_01be;
			IL_1035:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_028b;
			IL_1186:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 9;
			}
			goto IL_0542;
			IL_1610:
			num4 = array2[num6++];
			array[--num5] = num7;
			array[--num5] = 30;
			goto IL_0e90;
			IL_1136:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 8;
			}
			goto IL_04a5;
			IL_0fa9:
			num4 = array[num5++];
			goto IL_0edf;
			IL_15a0:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 26;
			}
			goto IL_0d66;
			IL_0fc6:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0171;
			IL_1085:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 5;
			}
			goto IL_033e;
			IL_155f:
			num4 = array[num5++];
			_ = array2[num6++];
			array[--num5] = 25;
			goto IL_0cf2;
			IL_0171:
			num7 = array2[num6++];
			Capture(3, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			array2[--num6] = -1;
			array[--num5] = 1;
			goto IL_0c7f;
			IL_0c7f:
			int num10 = (num7 = array2[num6++]);
			array[--num5] = num7;
			if (num10 != num4)
			{
				array[--num5] = num4;
				array2[--num6] = num4;
				array[--num5] = 23;
				if (num5 > 212 && num6 > 159)
				{
					goto IL_01be;
				}
				array[--num5] = 24;
				goto IL_0ee8;
			}
			array[--num5] = 25;
			goto IL_0cf2;
			IL_0542:
			num7 = array2[num6++];
			Capture(5, num7, num4);
			array[--num5] = num7;
			array[--num5] = 3;
			if (num4 < num3 && text[num4++] == '"')
			{
				goto IL_0c1f;
			}
			goto IL_0ee8;
			IL_04a5:
			if (num4 < num3 && text[num4++] == '"')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				num7 = (num8 = num3 - num4) + 1;
				while (--num7 > 0)
				{
					if (text[num4++] == '"')
					{
						num4--;
						break;
					}
				}
				if (num8 > num7)
				{
					array[--num5] = num8 - num7 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 9;
				}
				goto IL_0542;
			}
			goto IL_0ee8;
			IL_10e6:
			num4 = array[num5++];
			num7 = array[num5++];
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 7;
			}
			goto IL_0412;
			IL_01be:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (1 <= num3 - num4)
			{
				num4++;
				num7 = 1;
				while (RegexRunner.CharInClass(text[num4 - num7--], "\0\0\u0001d"))
				{
					if (num7 > 0)
					{
						continue;
					}
					goto IL_0217;
				}
			}
			goto IL_0ee8;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 53;
		}
	}
	internal class TagRegex40Factory24 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new TagRegex40Runner24();
		}
	}
	internal class TagRegex40 : Regex
	{
		public TagRegex40()
		{
			pattern = "\\G<(?<tagname>[\\w:\\.]+)(\\s+(?<attrname>\\w[-\\w:]*)(\\s*=\\s*\"(?<attrval>[^\"]*)\"|\\s*=\\s*'(?<attrval>[^']*)'|\\s*=\\s*(?<attrval><%#.*?%>)|\\s*=\\s*(?<attrval>[^\\s=\"'/>]*)|(?<attrval>\\s*?)))*\\s*(?<empty>/)?>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new TagRegex40Factory24();
			capnames = new Hashtable();
			capnames.Add("attrval", 5);
			capnames.Add("empty", 6);
			capnames.Add("1", 1);
			capnames.Add("0", 0);
			capnames.Add("tagname", 3);
			capnames.Add("2", 2);
			capnames.Add("attrname", 4);
			capslist = new string[7];
			capslist[0] = "0";
			capslist[1] = "1";
			capslist[2] = "2";
			capslist[3] = "tagname";
			capslist[4] = "attrname";
			capslist[5] = "attrval";
			capslist[6] = "empty";
			capsize = 7;
			InitializeReferences();
		}
	}
	internal class DirectiveRegex40Runner25 : RegexRunner
	{
		public unsafe override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num8;
			int num7;
			if (num4 == runtextstart && 2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_012f;
			}
			goto IL_0ccc;
			IL_0fa3:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 12;
			}
			goto IL_05c0;
			IL_01f7:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0002\t:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_02aa;
			}
			goto IL_0ccc;
			IL_0de6:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01f7;
			IL_0c5d:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				goto IL_0cc3;
			}
			goto IL_0ccc;
			IL_0bb7:
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if (num9 != num4)
			{
				array[--num5] = num4;
				array2[--num6] = num4;
				array[--num5] = 22;
				if (num5 > 204 && num6 > 153)
				{
					goto IL_016b;
				}
				array[--num5] = 23;
				goto IL_0ccc;
			}
			array[--num5] = 24;
			goto IL_0c2a;
			IL_05c0:
			num8 = array2[num6++];
			Capture(5, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			if (num4 < num3 && text[num4++] == '"')
			{
				goto IL_0b57;
			}
			goto IL_0ccc;
			IL_0d96:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_012f;
			IL_0c2a:
			if ((num8 = num3 - num4) > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c5d;
			IL_0cc3:
			runtextpos = num4;
			return;
			IL_0ccc:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 23:
					break;
				default:
					goto IL_0d79;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0d96;
				case 3:
					goto IL_0de6;
				case 4:
					goto IL_0e36;
				case 5:
					num6 += 2;
					continue;
				case 6:
					array2[--num6] = array[num5++];
					continue;
				case 7:
				{
					int num10 = array[num5++];
					if (num10 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num10 != Crawlpos());
					}
					continue;
				}
				case 8:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 9:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 13;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_06a0;
				case 10:
					goto IL_0f03;
				case 11:
					goto IL_0f53;
				case 12:
					goto IL_0fa3;
				case 13:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 17;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08f8;
				case 14:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_06a0;
				case 15:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_077b;
				case 16:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_0818;
				case 17:
					num4 = array[num5++];
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					array2[--num6] = num4;
					array[--num5] = 1;
					if ((num8 = num3 - num4) > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b27;
				case 18:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08f8;
				case 19:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09d3;
				case 20:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a5f;
				case 21:
					num4 = array[num5++];
					num7 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						continue;
					}
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b27;
				case 22:
					goto IL_1260;
				case 24:
					array2[--num6] = array[num5++];
					continue;
				case 25:
					goto IL_12a1;
					IL_08f8:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09d3;
					IL_0818:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					if (num4 >= num3)
					{
						continue;
					}
					goto IL_0851;
					IL_077b:
					if (num4 >= num3 || text[num4++] != '\'')
					{
						continue;
					}
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (text[num4++] == '\'')
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_0818;
					IL_06a0:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_077b;
					IL_0b27:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b57;
					IL_09d3:
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\u0001\b\u0001\"#%&'(>?d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a5f;
					IL_0a5f:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b57;
				}
				break;
				IL_12a1:
				num4 = array[num5++];
				num7 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					continue;
				}
				goto IL_12d7;
				IL_0851:
				if (text[num4++] != '\'')
				{
					continue;
				}
				goto IL_0b57;
			}
			goto IL_016b;
			IL_0b57:
			num8 = array2[num6++];
			Capture(2, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			goto IL_0bb7;
			IL_12d7:
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c5d;
			IL_02aa:
			array2[--num6] = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)num5);
			array2[--num6] = Crawlpos();
			array[--num5] = 5;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\u0001\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num4 = (array[--num5] = array2[num6++]);
				array[--num5] = 6;
				num8 = array2[num6++];
				num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
				array[--num5] = num8;
				array[--num5] = 7;
				num8 = array2[num6++];
				Capture(3, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				array2[--num6] = num4;
				array[--num5] = 1;
				array[--num5] = num4;
				array[--num5] = 9;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 10;
				}
				goto IL_0448;
			}
			goto IL_0ccc;
			IL_016b:
			array2[--num6] = num4;
			array[--num5] = 1;
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01f7;
			IL_1260:
			num4 = array[num5++];
			_ = array2[num6++];
			array[--num5] = 24;
			goto IL_0c2a;
			IL_0f03:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 10;
			}
			goto IL_0448;
			IL_0e36:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_02aa;
			IL_012f:
			if (num4 < num3 && text[num4++] == '@')
			{
				array2[--num6] = -1;
				array[--num5] = 1;
				goto IL_0bb7;
			}
			goto IL_0ccc;
			IL_0523:
			if (num4 < num3 && text[num4++] == '"')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (text[num4++] == '"')
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 12;
				}
				goto IL_05c0;
			}
			goto IL_0ccc;
			IL_0f53:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 11;
			}
			goto IL_0523;
			IL_0d79:
			num4 = array[num5++];
			goto IL_0cc3;
			IL_0448:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] == '=')
			{
				num8 = array2[num6++];
				Capture(4, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 11;
				}
				goto IL_0523;
			}
			goto IL_0ccc;
		}

		public override bool FindFirstChar()
		{
			if (runtextpos > runtextstart)
			{
				runtextpos = runtextend;
				return false;
			}
			return true;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 51;
		}
	}
	internal class DirectiveRegex40Factory25 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new DirectiveRegex40Runner25();
		}
	}
	internal class DirectiveRegex40 : Regex
	{
		public DirectiveRegex40()
		{
			pattern = "\\G<%\\s*@(\\s*(?<attrname>\\w[\\w:]*(?=\\W))(\\s*(?<equal>=)\\s*\"(?<attrval>[^\"]*)\"|\\s*(?<equal>=)\\s*'(?<attrval>[^']*)'|\\s*(?<equal>=)\\s*(?<attrval>[^\\s\"'%>]*)|(?<equal>)(?<attrval>\\s*?)))*\\s*?%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new DirectiveRegex40Factory25();
			capnames = new Hashtable();
			capnames.Add("attrval", 5);
			capnames.Add("2", 2);
			capnames.Add("0", 0);
			capnames.Add("1", 1);
			capnames.Add("equal", 4);
			capnames.Add("attrname", 3);
			capslist = new string[6];
			capslist[0] = "0";
			capslist[1] = "1";
			capslist[2] = "2";
			capslist[3] = "attrname";
			capslist[4] = "equal";
			capslist[5] = "attrval";
			capsize = 6;
			InitializeReferences();
		}
	}
	internal class SimpleDirectiveRegex40Runner26 : RegexRunner
	{
		public unsafe override void Go()
		{
			string text = runtext;
			int num = runtextstart;
			int num2 = runtextbeg;
			int num3 = runtextend;
			int num4 = runtextpos;
			int[] array = runtrack;
			int num5 = runtrackpos;
			int[] array2 = runstack;
			int num6 = runstackpos;
			array[--num5] = num4;
			array[--num5] = 0;
			array2[--num6] = num4;
			array[--num5] = 1;
			int num7;
			int num8;
			if (2 <= num3 - num4 && text[num4] == '<' && text[num4 + 1] == '%')
			{
				num4 += 2;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 2;
				}
				goto IL_0122;
			}
			goto IL_0cbf;
			IL_01ea:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\0\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\u0002\t:;\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 4;
				}
				goto IL_029d;
			}
			goto IL_0cbf;
			IL_0dd9:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01ea;
			IL_0c50:
			if (2 <= num3 - num4 && text[num4] == '%' && text[num4 + 1] == '>')
			{
				num4 += 2;
				num8 = array2[num6++];
				Capture(0, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				goto IL_0cb6;
			}
			goto IL_0cbf;
			IL_0baa:
			int num9 = (num8 = array2[num6++]);
			array[--num5] = num8;
			if (num9 != num4)
			{
				array[--num5] = num4;
				array2[--num6] = num4;
				array[--num5] = 22;
				if (num5 > 204 && num6 > 153)
				{
					goto IL_015e;
				}
				array[--num5] = 23;
				goto IL_0cbf;
			}
			array[--num5] = 24;
			goto IL_0c1d;
			IL_05b3:
			num8 = array2[num6++];
			Capture(5, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			if (num4 < num3 && text[num4++] == '"')
			{
				goto IL_0b4a;
			}
			goto IL_0cbf;
			IL_0d89:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 2;
			}
			goto IL_0122;
			IL_0c1d:
			if ((num8 = num3 - num4) > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c50;
			IL_0cb6:
			runtextpos = num4;
			return;
			IL_0cbf:
			while (true)
			{
				runtrackpos = num5;
				runstackpos = num6;
				EnsureStorage();
				num5 = runtrackpos;
				num6 = runstackpos;
				array = runtrack;
				array2 = runstack;
				switch (array[num5++])
				{
				case 23:
					break;
				default:
					goto IL_0d6c;
				case 1:
					num6++;
					continue;
				case 2:
					goto IL_0d89;
				case 3:
					goto IL_0dd9;
				case 4:
					goto IL_0e29;
				case 5:
					num6 += 2;
					continue;
				case 6:
					array2[--num6] = array[num5++];
					continue;
				case 7:
				{
					int num10 = array[num5++];
					if (num10 != Crawlpos())
					{
						do
						{
							Uncapture();
						}
						while (num10 != Crawlpos());
					}
					continue;
				}
				case 8:
					array2[--num6] = array[num5++];
					Uncapture();
					continue;
				case 9:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 13;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_0693;
				case 10:
					goto IL_0ef6;
				case 11:
					goto IL_0f46;
				case 12:
					goto IL_0f96;
				case 13:
					num4 = array[num5++];
					array[--num5] = num4;
					array[--num5] = 17;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08eb;
				case 14:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 14;
					}
					goto IL_0693;
				case 15:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_076e;
				case 16:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_080b;
				case 17:
					num4 = array[num5++];
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					array2[--num6] = num4;
					array[--num5] = 1;
					if ((num8 = num3 - num4) > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b1a;
				case 18:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 18;
					}
					goto IL_08eb;
				case 19:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09c6;
				case 20:
					num4 = array[num5++];
					num8 = array[num5++];
					if (num8 > 0)
					{
						array[--num5] = num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a52;
				case 21:
					num4 = array[num5++];
					num7 = array[num5++];
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						continue;
					}
					if (num7 > 0)
					{
						array[--num5] = num7 - 1;
						array[--num5] = num4;
						array[--num5] = 21;
					}
					goto IL_0b1a;
				case 22:
					goto IL_1253;
				case 24:
					array2[--num6] = array[num5++];
					continue;
				case 25:
					goto IL_1294;
					IL_08eb:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 19;
					}
					goto IL_09c6;
					IL_080b:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					if (num4 >= num3)
					{
						continue;
					}
					goto IL_0844;
					IL_076e:
					if (num4 >= num3 || text[num4++] != '\'')
					{
						continue;
					}
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (text[num4++] == '\'')
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 16;
					}
					goto IL_080b;
					IL_0693:
					array2[--num6] = num4;
					array[--num5] = 1;
					if (num4 >= num3 || text[num4++] != '=')
					{
						continue;
					}
					num8 = array2[num6++];
					Capture(4, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 15;
					}
					goto IL_076e;
					IL_0b1a:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b4a;
					IL_09c6:
					array2[--num6] = num4;
					array[--num5] = 1;
					num8 = (num7 = num3 - num4) + 1;
					while (--num8 > 0)
					{
						if (!RegexRunner.CharInClass(text[num4++], "\u0001\b\u0001\"#%&'(>?d"))
						{
							num4--;
							break;
						}
					}
					if (num7 > num8)
					{
						array[--num5] = num7 - num8 - 1;
						array[--num5] = num4 - 1;
						array[--num5] = 20;
					}
					goto IL_0a52;
					IL_0a52:
					num8 = array2[num6++];
					Capture(5, num8, num4);
					array[--num5] = num8;
					array[--num5] = 8;
					goto IL_0b4a;
				}
				break;
				IL_1294:
				num4 = array[num5++];
				num7 = array[num5++];
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					continue;
				}
				goto IL_12ca;
				IL_0844:
				if (text[num4++] != '\'')
				{
					continue;
				}
				goto IL_0b4a;
			}
			goto IL_015e;
			IL_0b4a:
			num8 = array2[num6++];
			Capture(2, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			num8 = array2[num6++];
			Capture(1, num8, num4);
			array[--num5] = num8;
			array[--num5] = 8;
			goto IL_0baa;
			IL_12ca:
			if (num7 > 0)
			{
				array[--num5] = num7 - 1;
				array[--num5] = num4;
				array[--num5] = 25;
			}
			goto IL_0c50;
			IL_029d:
			array2[--num6] = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)num5);
			array2[--num6] = Crawlpos();
			array[--num5] = 5;
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && RegexRunner.CharInClass(text[num4++], "\u0001\0\t\0\u0002\u0004\u0005\u0003\u0001\t\u0013\0"))
			{
				num4 = (array[--num5] = array2[num6++]);
				array[--num5] = 6;
				num8 = array2[num6++];
				num5 = (int)((long)(IntPtr)(void*)runtrack.LongLength - (long)array2[num6++]);
				array[--num5] = num8;
				array[--num5] = 7;
				num8 = array2[num6++];
				Capture(3, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				array2[--num6] = num4;
				array[--num5] = 1;
				array[--num5] = num4;
				array[--num5] = 9;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 10;
				}
				goto IL_043b;
			}
			goto IL_0cbf;
			IL_015e:
			array2[--num6] = num4;
			array[--num5] = 1;
			num8 = (num7 = num3 - num4) + 1;
			while (--num8 > 0)
			{
				if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
				{
					num4--;
					break;
				}
			}
			if (num7 > num8)
			{
				array[--num5] = num7 - num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 3;
			}
			goto IL_01ea;
			IL_1253:
			num4 = array[num5++];
			_ = array2[num6++];
			array[--num5] = 24;
			goto IL_0c1d;
			IL_0ef6:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 10;
			}
			goto IL_043b;
			IL_0e29:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 4;
			}
			goto IL_029d;
			IL_0122:
			if (num4 < num3 && text[num4++] == '@')
			{
				array2[--num6] = -1;
				array[--num5] = 1;
				goto IL_0baa;
			}
			goto IL_0cbf;
			IL_0516:
			if (num4 < num3 && text[num4++] == '"')
			{
				array2[--num6] = num4;
				array[--num5] = 1;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (text[num4++] == '"')
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 12;
				}
				goto IL_05b3;
			}
			goto IL_0cbf;
			IL_0f46:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 11;
			}
			goto IL_0516;
			IL_0d6c:
			num4 = array[num5++];
			goto IL_0cb6;
			IL_043b:
			array2[--num6] = num4;
			array[--num5] = 1;
			if (num4 < num3 && text[num4++] == '=')
			{
				num8 = array2[num6++];
				Capture(4, num8, num4);
				array[--num5] = num8;
				array[--num5] = 8;
				num8 = (num7 = num3 - num4) + 1;
				while (--num8 > 0)
				{
					if (!RegexRunner.CharInClass(text[num4++], "\0\0\u0001d"))
					{
						num4--;
						break;
					}
				}
				if (num7 > num8)
				{
					array[--num5] = num7 - num8 - 1;
					array[--num5] = num4 - 1;
					array[--num5] = 11;
				}
				goto IL_0516;
			}
			goto IL_0cbf;
			IL_0f96:
			num4 = array[num5++];
			num8 = array[num5++];
			if (num8 > 0)
			{
				array[--num5] = num8 - 1;
				array[--num5] = num4 - 1;
				array[--num5] = 12;
			}
			goto IL_05b3;
		}

		public override bool FindFirstChar()
		{
			string text = runtext;
			int num = runtextend;
			int num2 = runtextpos + 1;
			while (num2 < num)
			{
				int num4;
				int num3;
				if ((num3 = text[num2]) != 37)
				{
					num4 = (((uint)(num3 -= 37) > 23u) ? 2 : (num3 switch
					{
						1 => 2, 
						2 => 2, 
						3 => 2, 
						4 => 2, 
						5 => 2, 
						6 => 2, 
						7 => 2, 
						8 => 2, 
						9 => 2, 
						10 => 2, 
						11 => 2, 
						12 => 2, 
						13 => 2, 
						14 => 2, 
						15 => 2, 
						16 => 2, 
						17 => 2, 
						18 => 2, 
						19 => 2, 
						20 => 2, 
						21 => 2, 
						22 => 2, 
						23 => 1, 
						_ => 0, 
					}));
				}
				else
				{
					num3 = num2;
					if (text[--num3] == '<')
					{
						runtextpos = num3;
						return true;
					}
					num4 = 1;
				}
				num2 = num4 + num2;
			}
			runtextpos = runtextend;
			return false;
		}

		public override void InitTrackCount()
		{
			runtrackcount = 51;
		}
	}
	internal class SimpleDirectiveRegex40Factory26 : RegexRunnerFactory
	{
		public override RegexRunner CreateInstance()
		{
			return new SimpleDirectiveRegex40Runner26();
		}
	}
	internal class SimpleDirectiveRegex40 : Regex
	{
		public SimpleDirectiveRegex40()
		{
			pattern = "<%\\s*@(\\s*(?<attrname>\\w[\\w:]*(?=\\W))(\\s*(?<equal>=)\\s*\"(?<attrval>[^\"]*)\"|\\s*(?<equal>=)\\s*'(?<attrval>[^']*)'|\\s*(?<equal>=)\\s*(?<attrval>[^\\s\"'%>]*)|(?<equal>)(?<attrval>\\s*?)))*\\s*?%>";
			roptions = RegexOptions.Multiline | RegexOptions.Singleline;
			factory = new SimpleDirectiveRegex40Factory26();
			capnames = new Hashtable();
			capnames.Add("attrval", 5);
			capnames.Add("2", 2);
			capnames.Add("0", 0);
			capnames.Add("1", 1);
			capnames.Add("equal", 4);
			capnames.Add("attrname", 3);
			capslist = new string[6];
			capslist[0] = "0";
			capslist[1] = "1";
			capslist[2] = "2";
			capslist[3] = "attrname";
			capslist[4] = "equal";
			capslist[5] = "attrval";
			capsize = 6;
			InitializeReferences();
		}
	}
}
namespace System.Web.Util
{
	internal sealed class CalliHelper
	{
		internal static void EventArgFunctionCaller(IntPtr fp, object o, object t, EventArgs e)
		{
			/*calli with instance method signature not supportd*/;
		}

		internal static void ArglessFunctionCaller(IntPtr fp, object o)
		{
			/*calli with instance method signature not supportd*/;
		}

		internal CalliHelper()
		{
		}
	}
}
