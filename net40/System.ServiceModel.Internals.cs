
// C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System.ServiceModel.Internals\v4.0_4.0.0.0__31bf3856ad364e35\System.ServiceModel.Internals.dll
// System.ServiceModel.Internals, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v4.0.30319
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9

#define TRACE
#define DEBUG
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.Diagnostics;
using System.Runtime.Interop;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.ServiceModel.Internals;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Win32.SafeHandles;

[assembly: CompilationRelaxations(8)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: Guid("a9b8c4b5-b4a9-4800-8268-e8ec3b93d9ac")]
[assembly: InternalsVisibleTo("System.Activities, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.Activities.Statements, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.Activities.Extended, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.Runtime.DurableInstancing, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.Runtime.Serialization.Xaml, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.Runtime.Xaml, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.ServiceModel.Activation, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.ServiceMoniker40, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.ServiceModel.Activities, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.Channels, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.LocalChannel, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.Discovery, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.Routing, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.Web, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("Microsoft.ServiceModel.Web.Test, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.WorkflowServices, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.WasHosting, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.Xaml.Hosting, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("XamlBuildTask, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("SMSvcHost, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("SMDiagnostics, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("Microsoft.Transactions.Bridge, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("System.IO.Log, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("System.Runtime.Serialization, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.IdentityModel, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.IdentityModel.Selectors, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("System.IdentityModel.Services, PublicKey=00000000000000000400000000000000")]
[assembly: InternalsVisibleTo("WorkflowManagementService, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.Activities.DurableInstancing, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("XsdBuildTask, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.ServiceModel.Friend, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("Microsoft.CDF.Test.Persistence, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("CDF.CIT.Scenarios.Common, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("WireTool, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("WsatTest, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("WCF.CIT.ChannelModel, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: InternalsVisibleTo("System.Activities.Core.Presentation, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("System.Activities.Presentation, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("Microsoft.Activities.Build, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: InternalsVisibleTo("Microsoft.VisualStudio.ServiceModel, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0bd333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c308055da9")]
[assembly: ComVisible(false)]
[assembly: CLSCompliant(true)]
[assembly: AllowPartiallyTrustedCallers]
[assembly: SecurityRules(SecurityRuleSet.Level2, SkipVerificationInFullTrust = true)]
[assembly: AssemblyTitle("System.ServiceModel.Internals.dll")]
[assembly: AssemblyDescription("System.ServiceModel.Internals.dll")]
[assembly: AssemblyDefaultAlias("System.ServiceModel.Internals.dll")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyFileVersion("4.8.9037.0")]
[assembly: AssemblyInformationalVersion("4.8.9037.0")]
[assembly: SatelliteContractVersion("4.0.0.0")]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyKeyFile("f:\\dd\\tools\\devdiv\\35MSSharedLib1024.snk")]
[assembly: AssemblySignatureKey("002400000c80000014010000060200000024000052534131000800000100010085aad0bef0688d1b994a0d78e1fd29fc24ac34ed3d3ac3fb9b3d0c48386ba834aa880035060a8848b2d8adf58e670ed20914be3681a891c9c8c01eef2ab22872547c39be00af0e6c72485d7cfd1a51df8947d36ceba9989106b58abe79e6a3e71a01ed6bdc867012883e0b1a4d35b1b5eeed6df21e401bb0c22f2246ccb69979dc9e61eef262832ed0f2064853725a75485fa8a3efb7e027319c86dec03dc3b1bca2b5081bab52a627b9917450dfad534799e1c7af58683bdfa135f1518ff1ea60e90d7b993a6c87fd3dd93408e35d1296f9a7f9a97c5db56c0f3cc25ad11e9777f94d138b3cea53b9a8331c2e6dcb8d2ea94e18bf1163ff112a22dbd92d429a", "8913ef869646d14971df222c210018ab394cfe63f8eb9b4d894c0dda7368cfb69df15d049b347f8a8b9205cdcc3d6bd6690f0bd24b3da3179feb8c03f410703027c7844ff654997e38015dfc97222c15061af2a1d3fe91775b9dd4b8ede64d3d59816270a9520e393c8e60619b80d40fc1dc4f12b5aa0c2df20d02ea32960851")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32 | DllImportSearchPath.AssemblyDirectory)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, Execution = true)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("4.0.0.0")]
[module: UnverifiableCode]
namespace System
{
	internal static class AppContextDefaultValues
	{
		public static void PopulateDefaultValues()
		{
			ParseTargetFrameworkName(out var identifier, out var profile, out var version);
			PopulateDefaultValuesPartial(identifier, profile, version);
		}

		private static void ParseTargetFrameworkName(out string identifier, out string profile, out int version)
		{
			string targetFrameworkName = AppDomain.CurrentDomain.SetupInformation.TargetFrameworkName;
			if (!TryParseFrameworkName(targetFrameworkName, out identifier, out version, out profile))
			{
				identifier = ".NETFramework";
				version = 40000;
				profile = string.Empty;
			}
		}

		private static bool TryParseFrameworkName(string frameworkName, out string identifier, out int version, out string profile)
		{
			identifier = (profile = string.Empty);
			version = 0;
			if (frameworkName == null || frameworkName.Length == 0)
			{
				return false;
			}
			string[] array = frameworkName.Split(',');
			version = 0;
			if (array.Length < 2 || array.Length > 3)
			{
				return false;
			}
			identifier = array[0].Trim();
			if (identifier.Length == 0)
			{
				return false;
			}
			bool flag = false;
			profile = null;
			for (int i = 1; i < array.Length; i++)
			{
				string[] array2 = array[i].Split('=');
				if (array2.Length != 2)
				{
					return false;
				}
				string text = array2[0].Trim();
				string text2 = array2[1].Trim();
				if (text.Equals("Version", StringComparison.OrdinalIgnoreCase))
				{
					flag = true;
					if (text2.Length > 0 && (text2[0] == 'v' || text2[0] == 'V'))
					{
						text2 = text2.Substring(1);
					}
					Version version2 = new Version(text2);
					version = version2.Major * 10000;
					if (version2.Minor > 0)
					{
						version += version2.Minor * 100;
					}
					if (version2.Build > 0)
					{
						version += version2.Build;
					}
				}
				else
				{
					if (!text.Equals("Profile", StringComparison.OrdinalIgnoreCase))
					{
						return false;
					}
					if (!string.IsNullOrEmpty(text2))
					{
						profile = text2;
					}
				}
			}
			if (!flag)
			{
				return false;
			}
			return true;
		}

		private static void PopulateDefaultValuesPartial(string platformIdentifier, string profile, int version)
		{
			if ((platformIdentifier == ".NETCore" || platformIdentifier == ".NETFramework") && version <= 40602)
			{
				LocalAppContext.DefineSwitchDefault("Switch.System.ServiceModel.Internals.IncludeNullExceptionMessageInETWTrace", initialValue: true);
			}
		}
	}
	internal static class LocalAppContext
	{
		private delegate bool TryGetSwitchDelegate(string switchName, out bool value);

		private static TryGetSwitchDelegate TryGetSwitchFromCentralAppContext;

		private static bool s_canForwardCalls;

		private static Dictionary<string, bool> s_switchMap;

		private static readonly object s_syncLock;

		private static bool DisableCaching { get; set; }

		static LocalAppContext()
		{
			s_switchMap = new Dictionary<string, bool>();
			s_syncLock = new object();
			s_canForwardCalls = SetupDelegate();
			AppContextDefaultValues.PopulateDefaultValues();
			DisableCaching = IsSwitchEnabled("TestSwitch.LocalAppContext.DisableCaching");
		}

		public static bool IsSwitchEnabled(string switchName)
		{
			if (s_canForwardCalls && TryGetSwitchFromCentralAppContext(switchName, out var value))
			{
				return value;
			}
			return IsSwitchEnabledLocal(switchName);
		}

		private static bool IsSwitchEnabledLocal(string switchName)
		{
			bool flag;
			bool value;
			lock (s_switchMap)
			{
				flag = s_switchMap.TryGetValue(switchName, out value);
			}
			if (flag)
			{
				return value;
			}
			return false;
		}

		private static bool SetupDelegate()
		{
			Type type = typeof(object).Assembly.GetType("System.AppContext");
			if (type == null)
			{
				return false;
			}
			MethodInfo method = type.GetMethod("TryGetSwitch", BindingFlags.Static | BindingFlags.Public, null, new Type[2]
			{
				typeof(string),
				typeof(bool).MakeByRefType()
			}, null);
			if (method == null)
			{
				return false;
			}
			TryGetSwitchFromCentralAppContext = (TryGetSwitchDelegate)Delegate.CreateDelegate(typeof(TryGetSwitchDelegate), method);
			return true;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static bool GetCachedSwitchValue(string switchName, ref int switchValue)
		{
			if (switchValue < 0)
			{
				return false;
			}
			if (switchValue > 0)
			{
				return true;
			}
			return GetCachedSwitchValueInternal(switchName, ref switchValue);
		}

		private static bool GetCachedSwitchValueInternal(string switchName, ref int switchValue)
		{
			if (DisableCaching)
			{
				return IsSwitchEnabled(switchName);
			}
			bool flag = IsSwitchEnabled(switchName);
			switchValue = (flag ? 1 : (-1));
			return flag;
		}

		internal static void DefineSwitchDefault(string switchName, bool initialValue)
		{
			s_switchMap[switchName] = initialValue;
		}
	}
}
namespace System.Runtime
{
	internal abstract class ActionItem
	{
		[SecurityCritical]
		private static class CallbackHelper
		{
			private static Action<object> invokeWithContextCallback;

			private static Action<object> invokeWithoutContextCallback;

			private static ContextCallback onContextAppliedCallback;

			public static Action<object> InvokeWithContextCallback
			{
				get
				{
					if (invokeWithContextCallback == null)
					{
						invokeWithContextCallback = InvokeWithContext;
					}
					return invokeWithContextCallback;
				}
			}

			public static Action<object> InvokeWithoutContextCallback
			{
				get
				{
					if (invokeWithoutContextCallback == null)
					{
						invokeWithoutContextCallback = InvokeWithoutContext;
					}
					return invokeWithoutContextCallback;
				}
			}

			public static ContextCallback OnContextAppliedCallback
			{
				get
				{
					if (onContextAppliedCallback == null)
					{
						onContextAppliedCallback = OnContextApplied;
					}
					return onContextAppliedCallback;
				}
			}

			private static void InvokeWithContext(object state)
			{
				SecurityContext securityContext = ((ActionItem)state).ExtractContext();
				SecurityContext.Run(securityContext, OnContextAppliedCallback, state);
			}

			private static void InvokeWithoutContext(object state)
			{
				((ActionItem)state).Invoke();
				((ActionItem)state).isScheduled = false;
			}

			private static void OnContextApplied(object o)
			{
				((ActionItem)o).Invoke();
				((ActionItem)o).isScheduled = false;
			}
		}

		private class DefaultActionItem : ActionItem
		{
			[SecurityCritical]
			private Action<object> callback;

			[SecurityCritical]
			private object state;

			private bool flowLegacyActivityId;

			private Guid activityId;

			private EventTraceActivity eventTraceActivity;

			[SecuritySafeCritical]
			public DefaultActionItem(Action<object> callback, object state, bool isLowPriority)
			{
				base.LowPriority = isLowPriority;
				this.callback = callback;
				this.state = state;
				if (WaitCallbackActionItem.ShouldUseActivity)
				{
					flowLegacyActivityId = true;
					activityId = DiagnosticTraceBase.ActivityId;
				}
				if (Fx.Trace.IsEnd2EndActivityTracingEnabled)
				{
					eventTraceActivity = EventTraceActivity.GetFromThreadOrCreate();
					if (TraceCore.ActionItemScheduledIsEnabled(Fx.Trace))
					{
						TraceCore.ActionItemScheduled(Fx.Trace, eventTraceActivity);
					}
				}
			}

			[SecurityCritical]
			protected override void Invoke()
			{
				if (flowLegacyActivityId || Fx.Trace.IsEnd2EndActivityTracingEnabled)
				{
					TraceAndInvoke();
				}
				else
				{
					callback(state);
				}
			}

			[SecurityCritical]
			private void TraceAndInvoke()
			{
				if (flowLegacyActivityId)
				{
					Guid guid = DiagnosticTraceBase.ActivityId;
					try
					{
						DiagnosticTraceBase.ActivityId = activityId;
						callback(state);
						return;
					}
					finally
					{
						DiagnosticTraceBase.ActivityId = guid;
					}
				}
				Guid empty = Guid.Empty;
				bool flag = false;
				try
				{
					if (eventTraceActivity != null)
					{
						empty = Trace.CorrelationManager.ActivityId;
						flag = true;
						Trace.CorrelationManager.ActivityId = eventTraceActivity.ActivityId;
						if (TraceCore.ActionItemCallbackInvokedIsEnabled(Fx.Trace))
						{
							TraceCore.ActionItemCallbackInvoked(Fx.Trace, eventTraceActivity);
						}
					}
					callback(state);
				}
				finally
				{
					if (flag)
					{
						Trace.CorrelationManager.ActivityId = empty;
					}
				}
			}
		}

		[SecurityCritical]
		private SecurityContext context;

		private bool isScheduled;

		private bool lowPriority;

		public bool LowPriority
		{
			get
			{
				return lowPriority;
			}
			protected set
			{
				lowPriority = value;
			}
		}

		public static void Schedule(Action<object> callback, object state)
		{
			Schedule(callback, state, lowPriority: false);
		}

		[SecuritySafeCritical]
		public static void Schedule(Action<object> callback, object state, bool lowPriority)
		{
			if (PartialTrustHelpers.ShouldFlowSecurityContext || WaitCallbackActionItem.ShouldUseActivity || Fx.Trace.IsEnd2EndActivityTracingEnabled)
			{
				new DefaultActionItem(callback, state, lowPriority).Schedule();
			}
			else
			{
				ScheduleCallback(callback, state, lowPriority);
			}
		}

		[SecurityCritical]
		protected abstract void Invoke();

		[SecurityCritical]
		protected void Schedule()
		{
			if (isScheduled)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.ActionItemIsAlreadyScheduled));
			}
			isScheduled = true;
			if (PartialTrustHelpers.ShouldFlowSecurityContext)
			{
				context = PartialTrustHelpers.CaptureSecurityContextNoIdentityFlow();
			}
			if (context != null)
			{
				ScheduleCallback(CallbackHelper.InvokeWithContextCallback);
			}
			else
			{
				ScheduleCallback(CallbackHelper.InvokeWithoutContextCallback);
			}
		}

		[SecurityCritical]
		protected void ScheduleWithContext(SecurityContext context)
		{
			if (context == null)
			{
				throw Fx.Exception.ArgumentNull("context");
			}
			if (isScheduled)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.ActionItemIsAlreadyScheduled));
			}
			isScheduled = true;
			this.context = context.CreateCopy();
			ScheduleCallback(CallbackHelper.InvokeWithContextCallback);
		}

		[SecurityCritical]
		protected void ScheduleWithoutContext()
		{
			if (isScheduled)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.ActionItemIsAlreadyScheduled));
			}
			isScheduled = true;
			ScheduleCallback(CallbackHelper.InvokeWithoutContextCallback);
		}

		[SecurityCritical]
		private static void ScheduleCallback(Action<object> callback, object state, bool lowPriority)
		{
			if (lowPriority)
			{
				IOThreadScheduler.ScheduleCallbackLowPriNoFlow(callback, state);
			}
			else
			{
				IOThreadScheduler.ScheduleCallbackNoFlow(callback, state);
			}
		}

		[SecurityCritical]
		private SecurityContext ExtractContext()
		{
			SecurityContext result = context;
			context = null;
			return result;
		}

		[SecurityCritical]
		private void ScheduleCallback(Action<object> callback)
		{
			ScheduleCallback(callback, this, lowPriority);
		}
	}
	internal static class AssertHelper
	{
		internal static void FireAssert(string message)
		{
			try
			{
			}
			finally
			{
				Debug.Assert(condition: false, message);
			}
		}
	}
	internal enum AsyncCompletionResult
	{
		Queued,
		Completed
	}
	internal abstract class AsyncEventArgs : IAsyncEventArgs
	{
		private enum OperationState
		{
			Created,
			PendingCompletion,
			CompletedSynchronously,
			CompletedAsynchronously
		}

		private OperationState state;

		private object asyncState;

		private AsyncEventArgsCallback callback;

		private Exception exception;

		public Exception Exception => exception;

		public object AsyncState => asyncState;

		private OperationState State
		{
			set
			{
				switch (value)
				{
				case OperationState.PendingCompletion:
					if (state == OperationState.PendingCompletion)
					{
						throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.AsyncEventArgsCompletionPending(GetType())));
					}
					break;
				case OperationState.CompletedSynchronously:
				case OperationState.CompletedAsynchronously:
					if (state != OperationState.PendingCompletion)
					{
						throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.AsyncEventArgsCompletedTwice(GetType())));
					}
					break;
				}
				state = value;
			}
		}

		public void Complete(bool completedSynchronously)
		{
			Complete(completedSynchronously, null);
		}

		public virtual void Complete(bool completedSynchronously, Exception exception)
		{
			this.exception = exception;
			if (completedSynchronously)
			{
				State = OperationState.CompletedSynchronously;
				return;
			}
			State = OperationState.CompletedAsynchronously;
			callback(this);
		}

		protected void SetAsyncState(AsyncEventArgsCallback callback, object state)
		{
			if (callback == null)
			{
				throw Fx.Exception.ArgumentNull("callback");
			}
			State = OperationState.PendingCompletion;
			asyncState = state;
			this.callback = callback;
		}
	}
	internal class AsyncEventArgs<TArgument> : AsyncEventArgs
	{
		public TArgument Arguments { get; private set; }

		public virtual void Set(AsyncEventArgsCallback callback, TArgument arguments, object state)
		{
			SetAsyncState(callback, state);
			Arguments = arguments;
		}
	}
	internal class AsyncEventArgs<TArgument, TResult> : AsyncEventArgs<TArgument>
	{
		public TResult Result { get; set; }
	}
	internal delegate void AsyncEventArgsCallback(IAsyncEventArgs eventArgs);
	internal abstract class AsyncResult : IAsyncResult
	{
		protected delegate bool AsyncCompletion(IAsyncResult result);

		private static AsyncCallback asyncCompletionWrapperCallback;

		private AsyncCallback callback;

		private bool completedSynchronously;

		private bool endCalled;

		private Exception exception;

		private bool isCompleted;

		private AsyncCompletion nextAsyncCompletion;

		private object state;

		private Action beforePrepareAsyncCompletionAction;

		private Func<IAsyncResult, bool> checkSyncValidationFunc;

		private ManualResetEvent manualResetEvent;

		private object thisLock;

		public object AsyncState => state;

		public WaitHandle AsyncWaitHandle
		{
			get
			{
				if (manualResetEvent != null)
				{
					return manualResetEvent;
				}
				lock (ThisLock)
				{
					if (manualResetEvent == null)
					{
						manualResetEvent = new ManualResetEvent(isCompleted);
					}
				}
				return manualResetEvent;
			}
		}

		public bool CompletedSynchronously => completedSynchronously;

		public bool HasCallback => callback != null;

		public bool IsCompleted => isCompleted;

		protected Action<AsyncResult, Exception> OnCompleting { get; set; }

		private object ThisLock => thisLock;

		protected Action<AsyncCallback, IAsyncResult> VirtualCallback { get; set; }

		protected AsyncResult(AsyncCallback callback, object state)
		{
			this.callback = callback;
			this.state = state;
			thisLock = new object();
		}

		protected void Complete(bool completedSynchronously)
		{
			if (isCompleted)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.AsyncResultCompletedTwice(GetType())));
			}
			this.completedSynchronously = completedSynchronously;
			if (OnCompleting != null)
			{
				try
				{
					OnCompleting(this, exception);
				}
				catch (Exception ex)
				{
					if (Fx.IsFatal(ex))
					{
						throw;
					}
					exception = ex;
				}
			}
			if (completedSynchronously)
			{
				isCompleted = true;
			}
			else
			{
				lock (ThisLock)
				{
					isCompleted = true;
					if (manualResetEvent != null)
					{
						manualResetEvent.Set();
					}
				}
			}
			if (callback == null)
			{
				return;
			}
			try
			{
				if (VirtualCallback != null)
				{
					VirtualCallback(callback, this);
				}
				else
				{
					callback(this);
				}
			}
			catch (Exception innerException)
			{
				if (Fx.IsFatal(innerException))
				{
					throw;
				}
				throw Fx.Exception.AsError(new CallbackException(InternalSR.AsyncCallbackThrewException, innerException));
			}
		}

		protected void Complete(bool completedSynchronously, Exception exception)
		{
			this.exception = exception;
			Complete(completedSynchronously);
		}

		private static void AsyncCompletionWrapperCallback(IAsyncResult result)
		{
			if (result == null)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.InvalidNullAsyncResult));
			}
			if (result.CompletedSynchronously)
			{
				return;
			}
			AsyncResult asyncResult = (AsyncResult)result.AsyncState;
			if (!asyncResult.OnContinueAsyncCompletion(result))
			{
				return;
			}
			AsyncCompletion nextCompletion = asyncResult.GetNextCompletion();
			if (nextCompletion == null)
			{
				ThrowInvalidAsyncResult(result);
			}
			bool flag = false;
			Exception ex = null;
			try
			{
				flag = nextCompletion(result);
			}
			catch (Exception ex2)
			{
				if (Fx.IsFatal(ex2))
				{
					throw;
				}
				flag = true;
				ex = ex2;
			}
			if (flag)
			{
				asyncResult.Complete(completedSynchronously: false, ex);
			}
		}

		protected virtual bool OnContinueAsyncCompletion(IAsyncResult result)
		{
			return true;
		}

		protected void SetBeforePrepareAsyncCompletionAction(Action beforePrepareAsyncCompletionAction)
		{
			this.beforePrepareAsyncCompletionAction = beforePrepareAsyncCompletionAction;
		}

		protected void SetCheckSyncValidationFunc(Func<IAsyncResult, bool> checkSyncValidationFunc)
		{
			this.checkSyncValidationFunc = checkSyncValidationFunc;
		}

		protected AsyncCallback PrepareAsyncCompletion(AsyncCompletion callback)
		{
			if (beforePrepareAsyncCompletionAction != null)
			{
				beforePrepareAsyncCompletionAction();
			}
			nextAsyncCompletion = callback;
			if (asyncCompletionWrapperCallback == null)
			{
				asyncCompletionWrapperCallback = Fx.ThunkCallback(AsyncCompletionWrapperCallback);
			}
			return asyncCompletionWrapperCallback;
		}

		protected bool CheckSyncContinue(IAsyncResult result)
		{
			AsyncCompletion asyncCompletion;
			return TryContinueHelper(result, out asyncCompletion);
		}

		protected bool SyncContinue(IAsyncResult result)
		{
			if (TryContinueHelper(result, out var asyncCompletion))
			{
				return asyncCompletion(result);
			}
			return false;
		}

		private bool TryContinueHelper(IAsyncResult result, out AsyncCompletion callback)
		{
			if (result == null)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.InvalidNullAsyncResult));
			}
			callback = null;
			if (checkSyncValidationFunc != null)
			{
				if (!checkSyncValidationFunc(result))
				{
					return false;
				}
			}
			else if (!result.CompletedSynchronously)
			{
				return false;
			}
			callback = GetNextCompletion();
			if (callback == null)
			{
				ThrowInvalidAsyncResult("Only call Check/SyncContinue once per async operation (once per PrepareAsyncCompletion).");
			}
			return true;
		}

		private AsyncCompletion GetNextCompletion()
		{
			AsyncCompletion result = nextAsyncCompletion;
			nextAsyncCompletion = null;
			return result;
		}

		protected static void ThrowInvalidAsyncResult(IAsyncResult result)
		{
			throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.InvalidAsyncResultImplementation(result.GetType())));
		}

		protected static void ThrowInvalidAsyncResult(string debugText)
		{
			string invalidAsyncResultImplementationGeneric = InternalSR.InvalidAsyncResultImplementationGeneric;
			throw Fx.Exception.AsError(new InvalidOperationException(invalidAsyncResultImplementationGeneric));
		}

		protected static TAsyncResult End<TAsyncResult>(IAsyncResult result) where TAsyncResult : AsyncResult
		{
			if (result == null)
			{
				throw Fx.Exception.ArgumentNull("result");
			}
			if (!(result is TAsyncResult val))
			{
				throw Fx.Exception.Argument("result", InternalSR.InvalidAsyncResult);
			}
			if (val.endCalled)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.AsyncResultAlreadyEnded));
			}
			val.endCalled = true;
			WaitHandle waitHandle = null;
			lock (val.ThisLock)
			{
				if (!val.isCompleted)
				{
					waitHandle = val.AsyncWaitHandle;
				}
			}
			waitHandle?.WaitOne();
			if (val.manualResetEvent != null)
			{
				val.manualResetEvent.Close();
			}
			if (val.exception != null)
			{
				throw Fx.Exception.AsError(val.exception);
			}
			return val;
		}
	}
	internal class AsyncWaitHandle
	{
		private class AsyncWaiter : ActionItem
		{
			[SecurityCritical]
			private Action<object, TimeoutException> callback;

			[SecurityCritical]
			private object state;

			private IOThreadTimer timer;

			private TimeSpan originalTimeout;

			public AsyncWaitHandle Parent { get; private set; }

			public bool TimedOut { get; set; }

			[SecuritySafeCritical]
			public AsyncWaiter(AsyncWaitHandle parent, Action<object, TimeoutException> callback, object state)
			{
				Parent = parent;
				this.callback = callback;
				this.state = state;
			}

			[SecuritySafeCritical]
			public void Call()
			{
				Schedule();
			}

			[SecurityCritical]
			protected override void Invoke()
			{
				callback(state, TimedOut ? new TimeoutException(InternalSR.TimeoutOnOperation(originalTimeout)) : null);
			}

			public void SetTimer(Action<object> callback, object state, TimeSpan timeout)
			{
				if (timer != null)
				{
					throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.MustCancelOldTimer));
				}
				originalTimeout = timeout;
				timer = new IOThreadTimer(callback, state, isTypicallyCanceledShortlyAfterBeingSet: false);
				timer.Set(timeout);
			}

			public void CancelTimer()
			{
				if (timer != null)
				{
					timer.Cancel();
					timer = null;
				}
			}
		}

		private static Action<object> timerCompleteCallback;

		private List<AsyncWaiter> asyncWaiters;

		private bool isSignaled;

		private EventResetMode resetMode;

		private object syncObject;

		private int syncWaiterCount;

		public AsyncWaitHandle()
			: this(EventResetMode.AutoReset)
		{
		}

		public AsyncWaitHandle(EventResetMode resetMode)
		{
			this.resetMode = resetMode;
			syncObject = new object();
		}

		public bool WaitAsync(Action<object, TimeoutException> callback, object state, TimeSpan timeout)
		{
			if (!isSignaled || (isSignaled && resetMode == EventResetMode.AutoReset))
			{
				lock (syncObject)
				{
					if (isSignaled && resetMode == EventResetMode.AutoReset)
					{
						isSignaled = false;
					}
					else if (!isSignaled)
					{
						AsyncWaiter asyncWaiter = new AsyncWaiter(this, callback, state);
						if (asyncWaiters == null)
						{
							asyncWaiters = new List<AsyncWaiter>();
						}
						asyncWaiters.Add(asyncWaiter);
						if (timeout != TimeSpan.MaxValue)
						{
							if (timerCompleteCallback == null)
							{
								timerCompleteCallback = OnTimerComplete;
							}
							asyncWaiter.SetTimer(timerCompleteCallback, asyncWaiter, timeout);
						}
						return false;
					}
				}
			}
			return true;
		}

		private static void OnTimerComplete(object state)
		{
			AsyncWaiter asyncWaiter = (AsyncWaiter)state;
			AsyncWaitHandle parent = asyncWaiter.Parent;
			bool flag = false;
			lock (parent.syncObject)
			{
				if (parent.asyncWaiters != null && parent.asyncWaiters.Remove(asyncWaiter))
				{
					asyncWaiter.TimedOut = true;
					flag = true;
				}
			}
			asyncWaiter.CancelTimer();
			if (flag)
			{
				asyncWaiter.Call();
			}
		}

		public bool Wait(TimeSpan timeout)
		{
			if (!isSignaled || (isSignaled && resetMode == EventResetMode.AutoReset))
			{
				lock (syncObject)
				{
					if (isSignaled && resetMode == EventResetMode.AutoReset)
					{
						isSignaled = false;
					}
					else if (!isSignaled)
					{
						bool flag = false;
						try
						{
							try
							{
							}
							finally
							{
								syncWaiterCount++;
								flag = true;
							}
							if (timeout == TimeSpan.MaxValue)
							{
								if (!Monitor.Wait(syncObject, -1))
								{
									return false;
								}
							}
							else if (!Monitor.Wait(syncObject, timeout))
							{
								return false;
							}
						}
						finally
						{
							if (flag)
							{
								syncWaiterCount--;
							}
						}
					}
				}
			}
			return true;
		}

		public void Set()
		{
			List<AsyncWaiter> list = null;
			AsyncWaiter asyncWaiter = null;
			if (!isSignaled)
			{
				lock (syncObject)
				{
					if (!isSignaled)
					{
						if (resetMode == EventResetMode.ManualReset)
						{
							isSignaled = true;
							Monitor.PulseAll(syncObject);
							list = asyncWaiters;
							asyncWaiters = null;
						}
						else if (syncWaiterCount > 0)
						{
							Monitor.Pulse(syncObject);
						}
						else if (asyncWaiters != null && asyncWaiters.Count > 0)
						{
							asyncWaiter = asyncWaiters[0];
							asyncWaiters.RemoveAt(0);
						}
						else
						{
							isSignaled = true;
						}
					}
				}
			}
			if (list != null)
			{
				foreach (AsyncWaiter item in list)
				{
					item.CancelTimer();
					item.Call();
				}
			}
			if (asyncWaiter != null)
			{
				asyncWaiter.CancelTimer();
				asyncWaiter.Call();
			}
		}

		public void Reset()
		{
			isSignaled = false;
		}
	}
	internal sealed class BackoffTimeoutHelper
	{
		private static readonly int maxSkewMilliseconds = (int)(IOThreadTimer.SystemTimeResolutionTicks / 10000);

		private static readonly long maxDriftTicks = IOThreadTimer.SystemTimeResolutionTicks * 2;

		private static readonly TimeSpan defaultInitialWaitTime = TimeSpan.FromMilliseconds(1.0);

		private static readonly TimeSpan defaultMaxWaitTime = TimeSpan.FromMinutes(1.0);

		private DateTime deadline;

		private TimeSpan maxWaitTime;

		private TimeSpan waitTime;

		private IOThreadTimer backoffTimer;

		private Action<object> backoffCallback;

		private object backoffState;

		private Random random;

		private TimeSpan originalTimeout;

		public TimeSpan OriginalTimeout => originalTimeout;

		internal BackoffTimeoutHelper(TimeSpan timeout)
			: this(timeout, defaultMaxWaitTime)
		{
		}

		internal BackoffTimeoutHelper(TimeSpan timeout, TimeSpan maxWaitTime)
			: this(timeout, maxWaitTime, defaultInitialWaitTime)
		{
		}

		internal BackoffTimeoutHelper(TimeSpan timeout, TimeSpan maxWaitTime, TimeSpan initialWaitTime)
		{
			random = new Random(GetHashCode());
			this.maxWaitTime = maxWaitTime;
			originalTimeout = timeout;
			Reset(timeout, initialWaitTime);
		}

		private void Reset(TimeSpan timeout, TimeSpan initialWaitTime)
		{
			if (timeout == TimeSpan.MaxValue)
			{
				deadline = DateTime.MaxValue;
			}
			else
			{
				deadline = DateTime.UtcNow + timeout;
			}
			waitTime = initialWaitTime;
		}

		public bool IsExpired()
		{
			if (deadline == DateTime.MaxValue)
			{
				return false;
			}
			return DateTime.UtcNow >= deadline;
		}

		public void WaitAndBackoff(Action<object> callback, object state)
		{
			if (backoffCallback != callback || backoffState != state)
			{
				if (backoffTimer != null)
				{
					backoffTimer.Cancel();
				}
				backoffCallback = callback;
				backoffState = state;
				backoffTimer = new IOThreadTimer(callback, state, isTypicallyCanceledShortlyAfterBeingSet: false, maxSkewMilliseconds);
			}
			TimeSpan timeFromNow = WaitTimeWithDrift();
			Backoff();
			backoffTimer.Set(timeFromNow);
		}

		public void WaitAndBackoff()
		{
			Thread.Sleep(WaitTimeWithDrift());
			Backoff();
		}

		private TimeSpan WaitTimeWithDrift()
		{
			return Ticks.ToTimeSpan(Math.Max(Ticks.FromTimeSpan(defaultInitialWaitTime), Ticks.Add(Ticks.FromTimeSpan(waitTime), (long)(uint)random.Next() % (2 * maxDriftTicks + 1) - maxDriftTicks)));
		}

		private void Backoff()
		{
			if (waitTime.Ticks >= maxWaitTime.Ticks / 2)
			{
				waitTime = maxWaitTime;
			}
			else
			{
				waitTime = TimeSpan.FromTicks(waitTime.Ticks * 2);
			}
			if (!(deadline != DateTime.MaxValue))
			{
				return;
			}
			TimeSpan timeSpan = deadline - DateTime.UtcNow;
			if (waitTime > timeSpan)
			{
				waitTime = timeSpan;
				if (waitTime < TimeSpan.Zero)
				{
					waitTime = TimeSpan.Zero;
				}
			}
		}
	}
	internal class BufferedOutputStream : Stream
	{
		private InternalBufferManager bufferManager;

		private byte[][] chunks;

		private int chunkCount;

		private byte[] currentChunk;

		private int currentChunkSize;

		private int maxSize;

		private int maxSizeQuota;

		private int totalSize;

		private bool callerReturnsBuffer;

		private bool bufferReturned;

		private bool initialized;

		public override bool CanRead => false;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length => totalSize;

		public override long Position
		{
			get
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.SeekNotSupported));
			}
			set
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.SeekNotSupported));
			}
		}

		public BufferedOutputStream()
		{
			chunks = new byte[4][];
		}

		public BufferedOutputStream(int initialSize, int maxSize, InternalBufferManager bufferManager)
			: this()
		{
			Reinitialize(initialSize, maxSize, bufferManager);
		}

		public BufferedOutputStream(int maxSize)
			: this(0, maxSize, InternalBufferManager.Create(0L, int.MaxValue))
		{
		}

		public void Reinitialize(int initialSize, int maxSizeQuota, InternalBufferManager bufferManager)
		{
			Reinitialize(initialSize, maxSizeQuota, maxSizeQuota, bufferManager);
		}

		public void Reinitialize(int initialSize, int maxSizeQuota, int effectiveMaxSize, InternalBufferManager bufferManager)
		{
			this.maxSizeQuota = maxSizeQuota;
			maxSize = effectiveMaxSize;
			this.bufferManager = bufferManager;
			currentChunk = bufferManager.TakeBuffer(initialSize);
			currentChunkSize = 0;
			totalSize = 0;
			chunkCount = 1;
			chunks[0] = currentChunk;
			initialized = true;
		}

		private void AllocNextChunk(int minimumChunkSize)
		{
			int num = ((currentChunk.Length <= 1073741823) ? (currentChunk.Length * 2) : int.MaxValue);
			if (minimumChunkSize > num)
			{
				num = minimumChunkSize;
			}
			byte[] array = bufferManager.TakeBuffer(num);
			if (chunkCount == chunks.Length)
			{
				byte[][] destinationArray = new byte[chunks.Length * 2][];
				Array.Copy(chunks, destinationArray, chunks.Length);
				chunks = destinationArray;
			}
			chunks[chunkCount++] = array;
			currentChunk = array;
			currentChunkSize = 0;
		}

		public override IAsyncResult BeginRead(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
		{
			throw Fx.Exception.AsError(new NotSupportedException(InternalSR.ReadNotSupported));
		}

		public override int EndRead(IAsyncResult result)
		{
			throw Fx.Exception.AsError(new NotSupportedException(InternalSR.ReadNotSupported));
		}

		public override IAsyncResult BeginWrite(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
		{
			Write(buffer, offset, size);
			return new CompletedAsyncResult(callback, state);
		}

		public override void EndWrite(IAsyncResult result)
		{
			CompletedAsyncResult.End(result);
		}

		public void Clear()
		{
			if (!callerReturnsBuffer)
			{
				for (int i = 0; i < chunkCount; i++)
				{
					bufferManager.ReturnBuffer(chunks[i]);
					chunks[i] = null;
				}
			}
			callerReturnsBuffer = false;
			initialized = false;
			bufferReturned = false;
			chunkCount = 0;
			currentChunk = null;
		}

		public override void Close()
		{
		}

		public override void Flush()
		{
		}

		public override int Read(byte[] buffer, int offset, int size)
		{
			throw Fx.Exception.AsError(new NotSupportedException(InternalSR.ReadNotSupported));
		}

		public override int ReadByte()
		{
			throw Fx.Exception.AsError(new NotSupportedException(InternalSR.ReadNotSupported));
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw Fx.Exception.AsError(new NotSupportedException(InternalSR.SeekNotSupported));
		}

		public override void SetLength(long value)
		{
			throw Fx.Exception.AsError(new NotSupportedException(InternalSR.SeekNotSupported));
		}

		public MemoryStream ToMemoryStream()
		{
			int bufferSize;
			byte[] buffer = ToArray(out bufferSize);
			return new MemoryStream(buffer, 0, bufferSize);
		}

		public byte[] ToArray(out int bufferSize)
		{
			byte[] array;
			if (chunkCount == 1)
			{
				array = currentChunk;
				bufferSize = currentChunkSize;
				callerReturnsBuffer = true;
			}
			else
			{
				array = bufferManager.TakeBuffer(totalSize);
				int num = 0;
				int num2 = chunkCount - 1;
				for (int i = 0; i < num2; i++)
				{
					byte[] array2 = chunks[i];
					Buffer.BlockCopy(array2, 0, array, num, array2.Length);
					num += array2.Length;
				}
				Buffer.BlockCopy(currentChunk, 0, array, num, currentChunkSize);
				bufferSize = totalSize;
			}
			bufferReturned = true;
			return array;
		}

		public void Skip(int size)
		{
			WriteCore(null, 0, size);
		}

		public override void Write(byte[] buffer, int offset, int size)
		{
			WriteCore(buffer, offset, size);
		}

		protected virtual Exception CreateQuotaExceededException(int maxSizeQuota)
		{
			return new InvalidOperationException(InternalSR.BufferedOutputStreamQuotaExceeded(maxSizeQuota));
		}

		private void WriteCore(byte[] buffer, int offset, int size)
		{
			if (size < 0)
			{
				throw Fx.Exception.ArgumentOutOfRange("size", size, InternalSR.ValueMustBeNonNegative);
			}
			if (int.MaxValue - size < totalSize)
			{
				throw Fx.Exception.AsError(CreateQuotaExceededException(maxSizeQuota));
			}
			int num = totalSize + size;
			if (num > maxSize)
			{
				throw Fx.Exception.AsError(CreateQuotaExceededException(maxSizeQuota));
			}
			int num2 = currentChunk.Length - currentChunkSize;
			if (size > num2)
			{
				if (num2 > 0)
				{
					if (buffer != null)
					{
						Buffer.BlockCopy(buffer, offset, currentChunk, currentChunkSize, num2);
					}
					currentChunkSize = currentChunk.Length;
					offset += num2;
					size -= num2;
				}
				AllocNextChunk(size);
			}
			if (buffer != null)
			{
				Buffer.BlockCopy(buffer, offset, currentChunk, currentChunkSize, size);
			}
			totalSize = num;
			currentChunkSize += size;
		}

		public override void WriteByte(byte value)
		{
			if (totalSize == maxSize)
			{
				throw Fx.Exception.AsError(CreateQuotaExceededException(maxSize));
			}
			if (currentChunkSize == currentChunk.Length)
			{
				AllocNextChunk(1);
			}
			currentChunk[currentChunkSize++] = value;
		}
	}
	[Serializable]
	internal class CallbackException : FatalException
	{
		public CallbackException()
		{
		}

		public CallbackException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected CallbackException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	internal class CompletedAsyncResult : AsyncResult
	{
		public CompletedAsyncResult(AsyncCallback callback, object state)
			: base(callback, state)
		{
			Complete(completedSynchronously: true);
		}

		public static void End(IAsyncResult result)
		{
			Fx.AssertAndThrowFatal(result.IsCompleted, "CompletedAsyncResult was not completed!");
			AsyncResult.End<CompletedAsyncResult>(result);
		}
	}
	internal class CompletedAsyncResult<T> : AsyncResult
	{
		private T data;

		public CompletedAsyncResult(T data, AsyncCallback callback, object state)
			: base(callback, state)
		{
			this.data = data;
			Complete(completedSynchronously: true);
		}

		public static T End(IAsyncResult result)
		{
			Fx.AssertAndThrowFatal(result.IsCompleted, "CompletedAsyncResult<T> was not completed!");
			CompletedAsyncResult<T> completedAsyncResult = AsyncResult.End<CompletedAsyncResult<T>>(result);
			return completedAsyncResult.data;
		}
	}
	internal class CompletedAsyncResult<TResult, TParameter> : AsyncResult
	{
		private TResult resultData;

		private TParameter parameter;

		public CompletedAsyncResult(TResult resultData, TParameter parameter, AsyncCallback callback, object state)
			: base(callback, state)
		{
			this.resultData = resultData;
			this.parameter = parameter;
			Complete(completedSynchronously: true);
		}

		public static TResult End(IAsyncResult result, out TParameter parameter)
		{
			Fx.AssertAndThrowFatal(result.IsCompleted, "CompletedAsyncResult<T> was not completed!");
			CompletedAsyncResult<TResult, TParameter> completedAsyncResult = AsyncResult.End<CompletedAsyncResult<TResult, TParameter>>(result);
			parameter = completedAsyncResult.parameter;
			return completedAsyncResult.resultData;
		}
	}
	internal enum ComputerNameFormat
	{
		NetBIOS,
		DnsHostName,
		Dns,
		DnsFullyQualified,
		PhysicalNetBIOS,
		PhysicalDnsHostName,
		PhysicalDnsDomain,
		PhysicalDnsFullyQualified
	}
	internal static class DiagnosticStrings
	{
		internal const string AppDomain = "AppDomain";

		internal const string ChannelTag = "Channel";

		internal const string Description = "Description";

		internal const string DataTag = "Data";

		internal const string DataItemsTag = "DataItems";

		internal const string DescriptionTag = "Description";

		internal const string ExceptionTag = "Exception";

		internal const string ExceptionTypeTag = "ExceptionType";

		internal const string ExceptionStringTag = "ExceptionString";

		internal const string ExtendedDataTag = "ExtendedData";

		internal const string InnerExceptionTag = "InnerException";

		internal const string KeyTag = "Key";

		internal const string MessageTag = "Message";

		internal const string NamespaceTag = "xmlns";

		internal const string NativeErrorCodeTag = "NativeErrorCode";

		internal const string Separator = ":";

		internal const string SeverityTag = "Severity";

		internal const string SourceTag = "Source";

		internal const string StackTraceTag = "StackTrace";

		internal const string Task = "Task";

		internal const string TraceCodeTag = "TraceIdentifier";

		internal const string TraceRecordTag = "TraceRecord";

		internal const string ValueTag = "Value";
	}
	internal class DuplicateDetector<T> where T : class
	{
		private LinkedList<T> fifoList;

		private Dictionary<T, LinkedListNode<T>> items;

		private int capacity;

		private object thisLock;

		public DuplicateDetector(int capacity)
		{
			this.capacity = capacity;
			items = new Dictionary<T, LinkedListNode<T>>();
			fifoList = new LinkedList<T>();
			thisLock = new object();
		}

		public bool AddIfNotDuplicate(T value)
		{
			bool result = false;
			lock (thisLock)
			{
				if (!items.ContainsKey(value))
				{
					Add(value);
					return true;
				}
				return result;
			}
		}

		private void Add(T value)
		{
			if (items.Count == capacity)
			{
				LinkedListNode<T> last = fifoList.Last;
				items.Remove(last.Value);
				fifoList.Remove(last);
			}
			items.Add(value, fifoList.AddFirst(value));
		}

		public bool Remove(T value)
		{
			bool result = false;
			lock (thisLock)
			{
				if (items.TryGetValue(value, out var value2))
				{
					items.Remove(value);
					fifoList.Remove(value2);
					return true;
				}
				return result;
			}
		}

		public void Clear()
		{
			lock (thisLock)
			{
				fifoList.Clear();
				items.Clear();
			}
		}
	}
	internal class ExceptionTrace
	{
		private const ushort FailFastEventLogCategory = 6;

		private string eventSourceName;

		private readonly EtwDiagnosticTrace diagnosticTrace;

		public ExceptionTrace(string eventSourceName, EtwDiagnosticTrace diagnosticTrace)
		{
			this.eventSourceName = eventSourceName;
			this.diagnosticTrace = diagnosticTrace;
		}

		public void AsInformation(Exception exception)
		{
			TraceCore.HandledException(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
		}

		public void AsWarning(Exception exception)
		{
			TraceCore.HandledExceptionWarning(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
		}

		public Exception AsError(Exception exception)
		{
			if (exception is AggregateException aggregateException)
			{
				return AsError<Exception>(aggregateException);
			}
			if (exception is TargetInvocationException ex && ex.InnerException != null)
			{
				return AsError(ex.InnerException);
			}
			return TraceException(exception);
		}

		public Exception AsError(Exception exception, string eventSource)
		{
			if (exception is AggregateException aggregateException)
			{
				return AsError<Exception>(aggregateException, eventSource);
			}
			if (exception is TargetInvocationException ex && ex.InnerException != null)
			{
				return AsError(ex.InnerException, eventSource);
			}
			return TraceException(exception, eventSource);
		}

		public Exception AsError(TargetInvocationException targetInvocationException, string eventSource)
		{
			if (Fx.IsFatal(targetInvocationException))
			{
				return targetInvocationException;
			}
			Exception innerException = targetInvocationException.InnerException;
			if (innerException != null)
			{
				return AsError(innerException, eventSource);
			}
			return TraceException((Exception)targetInvocationException, eventSource);
		}

		public Exception AsError<TPreferredException>(AggregateException aggregateException)
		{
			return AsError<TPreferredException>(aggregateException, eventSourceName);
		}

		public Exception AsError<TPreferredException>(AggregateException aggregateException, string eventSource)
		{
			if (Fx.IsFatal(aggregateException))
			{
				return aggregateException;
			}
			ReadOnlyCollection<Exception> innerExceptions = aggregateException.Flatten().InnerExceptions;
			if (innerExceptions.Count == 0)
			{
				return TraceException(aggregateException, eventSource);
			}
			Exception ex = null;
			foreach (Exception item in innerExceptions)
			{
				Exception ex3 = ((item is TargetInvocationException ex2 && ex2.InnerException != null) ? ex2.InnerException : item);
				if (ex3 is TPreferredException && ex == null)
				{
					ex = ex3;
				}
				TraceException(ex3, eventSource);
			}
			if (ex == null)
			{
				ex = innerExceptions[0];
			}
			return ex;
		}

		public ArgumentException Argument(string paramName, string message)
		{
			return TraceException(new ArgumentException(message, paramName));
		}

		public ArgumentNullException ArgumentNull(string paramName)
		{
			return TraceException(new ArgumentNullException(paramName));
		}

		public ArgumentNullException ArgumentNull(string paramName, string message)
		{
			return TraceException(new ArgumentNullException(paramName, message));
		}

		public ArgumentException ArgumentNullOrEmpty(string paramName)
		{
			return Argument(paramName, InternalSR.ArgumentNullOrEmpty(paramName));
		}

		public ArgumentOutOfRangeException ArgumentOutOfRange(string paramName, object actualValue, string message)
		{
			return TraceException(new ArgumentOutOfRangeException(paramName, actualValue, message));
		}

		public ObjectDisposedException ObjectDisposed(string message)
		{
			return TraceException(new ObjectDisposedException(null, message));
		}

		public void TraceUnhandledException(Exception exception)
		{
			TraceCore.UnhandledException(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
		}

		public void TraceHandledException(Exception exception, TraceEventType traceEventType)
		{
			switch (traceEventType)
			{
			case TraceEventType.Error:
				if (TraceCore.HandledExceptionErrorIsEnabled(diagnosticTrace))
				{
					TraceCore.HandledExceptionError(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
				}
				break;
			case TraceEventType.Warning:
				if (TraceCore.HandledExceptionWarningIsEnabled(diagnosticTrace))
				{
					TraceCore.HandledExceptionWarning(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
				}
				break;
			case TraceEventType.Verbose:
				if (TraceCore.HandledExceptionVerboseIsEnabled(diagnosticTrace))
				{
					TraceCore.HandledExceptionVerbose(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
				}
				break;
			default:
				if (TraceCore.HandledExceptionIsEnabled(diagnosticTrace))
				{
					TraceCore.HandledException(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
				}
				break;
			}
		}

		public void TraceEtwException(Exception exception, TraceEventType eventType)
		{
			switch (eventType)
			{
			case TraceEventType.Error:
			case TraceEventType.Warning:
				if (TraceCore.ThrowingEtwExceptionIsEnabled(diagnosticTrace))
				{
					TraceCore.ThrowingEtwException(diagnosticTrace, eventSourceName, (exception != null) ? exception.ToString() : string.Empty, exception);
				}
				break;
			case TraceEventType.Critical:
				if (TraceCore.EtwUnhandledExceptionIsEnabled(diagnosticTrace))
				{
					TraceCore.EtwUnhandledException(diagnosticTrace, (exception != null) ? exception.ToString() : string.Empty, exception);
				}
				break;
			default:
				if (TraceCore.ThrowingEtwExceptionVerboseIsEnabled(diagnosticTrace))
				{
					TraceCore.ThrowingEtwExceptionVerbose(diagnosticTrace, eventSourceName, (exception != null) ? exception.ToString() : string.Empty, exception);
				}
				break;
			}
		}

		private TException TraceException<TException>(TException exception) where TException : Exception
		{
			return TraceException(exception, eventSourceName);
		}

		[SecuritySafeCritical]
		private TException TraceException<TException>(TException exception, string eventSource) where TException : Exception
		{
			if (TraceCore.ThrowingExceptionIsEnabled(diagnosticTrace))
			{
				TraceCore.ThrowingException(diagnosticTrace, eventSource, (exception != null) ? exception.ToString() : string.Empty, exception);
			}
			BreakOnException(exception);
			return exception;
		}

		[SecuritySafeCritical]
		private void BreakOnException(Exception exception)
		{
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		internal void TraceFailFast(string message)
		{
			EventLogger eventLogger = null;
			eventLogger = new EventLogger(eventSourceName, diagnosticTrace);
			TraceFailFast(message, eventLogger);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		internal void TraceFailFast(string message, EventLogger logger)
		{
			if (logger == null)
			{
				return;
			}
			try
			{
				string text = null;
				try
				{
					text = new StackTrace().ToString();
				}
				catch (Exception ex)
				{
					text = ex.Message;
					if (Fx.IsFatal(ex))
					{
						throw;
					}
				}
				finally
				{
					logger.LogEvent(TraceEventType.Critical, 6, 3221291110u, message, text);
				}
			}
			catch (Exception ex2)
			{
				logger.LogEvent(TraceEventType.Critical, 6, 3221291111u, ex2.ToString());
				if (Fx.IsFatal(ex2))
				{
					throw;
				}
			}
		}
	}
	internal delegate void FastAsyncCallback(object state, Exception asyncException);
	[Serializable]
	internal class FatalException : SystemException
	{
		public FatalException()
		{
		}

		public FatalException(string message)
			: base(message)
		{
		}

		public FatalException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected FatalException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	internal static class Fx
	{
		public abstract class ExceptionHandler
		{
			public abstract bool HandleException(Exception exception);
		}

		public static class Tag
		{
			public enum CacheAttrition
			{
				None,
				ElementOnTimer,
				ElementOnGC,
				ElementOnCallback,
				FullPurgeOnTimer,
				FullPurgeOnEachAccess,
				PartialPurgeOnTimer,
				PartialPurgeOnEachAccess
			}

			public enum ThrottleAction
			{
				Reject,
				Pause
			}

			public enum ThrottleMetric
			{
				Count,
				Rate,
				Other
			}

			public enum Location
			{
				InProcess,
				OutOfProcess,
				LocalSystem,
				LocalOrRemoteSystem,
				RemoteSystem
			}

			public enum SynchronizationKind
			{
				LockStatement,
				MonitorWait,
				MonitorExplicit,
				InterlockedNoSpin,
				InterlockedWithSpin,
				FromFieldType
			}

			[Flags]
			public enum BlocksUsing
			{
				MonitorEnter = 0,
				MonitorWait = 1,
				ManualResetEvent = 2,
				AutoResetEvent = 3,
				AsyncResult = 4,
				IAsyncResult = 5,
				PInvoke = 6,
				InputQueue = 7,
				ThreadNeutralSemaphore = 8,
				PrivatePrimitive = 9,
				OtherInternalPrimitive = 0xA,
				OtherFrameworkPrimitive = 0xB,
				OtherInterop = 0xC,
				Other = 0xD,
				NonBlocking = 0xE
			}

			public static class Strings
			{
				internal const string ExternallyManaged = "externally managed";

				internal const string AppDomain = "AppDomain";

				internal const string DeclaringInstance = "instance of declaring class";

				internal const string Unbounded = "unbounded";

				internal const string Infinite = "infinite";
			}

			[AttributeUsage(AttributeTargets.Class | AttributeTargets.Constructor | AttributeTargets.Method | AttributeTargets.Property, AllowMultiple = true, Inherited = false)]
			[Conditional("DEBUG")]
			public sealed class FriendAccessAllowedAttribute : Attribute
			{
				public string AssemblyName { get; set; }

				public FriendAccessAllowedAttribute(string assemblyName)
				{
					AssemblyName = assemblyName;
				}
			}

			public static class Throws
			{
				[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
				[Conditional("CODE_ANALYSIS_CDF")]
				public sealed class TimeoutAttribute : ThrowsAttribute
				{
					public TimeoutAttribute()
						: this("The operation timed out.")
					{
					}

					public TimeoutAttribute(string diagnosis)
						: base(typeof(TimeoutException), diagnosis)
					{
					}
				}
			}

			[AttributeUsage(AttributeTargets.Field)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class CacheAttribute : Attribute
			{
				private readonly Type elementType;

				private readonly CacheAttrition cacheAttrition;

				public Type ElementType => elementType;

				public CacheAttrition CacheAttrition => cacheAttrition;

				public string Scope { get; set; }

				public string SizeLimit { get; set; }

				public string Timeout { get; set; }

				public CacheAttribute(Type elementType, CacheAttrition cacheAttrition)
				{
					Scope = "instance of declaring class";
					SizeLimit = "unbounded";
					Timeout = "infinite";
					if (elementType == null)
					{
						throw Exception.ArgumentNull("elementType");
					}
					this.elementType = elementType;
					this.cacheAttrition = cacheAttrition;
				}
			}

			[AttributeUsage(AttributeTargets.Field)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class QueueAttribute : Attribute
			{
				private readonly Type elementType;

				public Type ElementType => elementType;

				public string Scope { get; set; }

				public string SizeLimit { get; set; }

				public bool StaleElementsRemovedImmediately { get; set; }

				public bool EnqueueThrowsIfFull { get; set; }

				public QueueAttribute(Type elementType)
				{
					Scope = "instance of declaring class";
					SizeLimit = "unbounded";
					if (elementType == null)
					{
						throw Exception.ArgumentNull("elementType");
					}
					this.elementType = elementType;
				}
			}

			[AttributeUsage(AttributeTargets.Field)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class ThrottleAttribute : Attribute
			{
				private readonly ThrottleAction throttleAction;

				private readonly ThrottleMetric throttleMetric;

				private readonly string limit;

				public ThrottleAction ThrottleAction => throttleAction;

				public ThrottleMetric ThrottleMetric => throttleMetric;

				public string Limit => limit;

				public string Scope { get; set; }

				public ThrottleAttribute(ThrottleAction throttleAction, ThrottleMetric throttleMetric, string limit)
				{
					Scope = "AppDomain";
					if (string.IsNullOrEmpty(limit))
					{
						throw Exception.ArgumentNullOrEmpty("limit");
					}
					this.throttleAction = throttleAction;
					this.throttleMetric = throttleMetric;
					this.limit = limit;
				}
			}

			[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method | AttributeTargets.Field, AllowMultiple = true, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class ExternalResourceAttribute : Attribute
			{
				private readonly Location location;

				private readonly string description;

				public Location Location => location;

				public string Description => description;

				public ExternalResourceAttribute(Location location, string description)
				{
					this.location = location;
					this.description = description;
				}
			}

			[AttributeUsage(AttributeTargets.Class | AttributeTargets.Field, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class SynchronizationObjectAttribute : Attribute
			{
				public bool Blocking { get; set; }

				public string Scope { get; set; }

				public SynchronizationKind Kind { get; set; }

				public SynchronizationObjectAttribute()
				{
					Blocking = true;
					Scope = "instance of declaring class";
					Kind = SynchronizationKind.FromFieldType;
				}
			}

			[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = true)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class SynchronizationPrimitiveAttribute : Attribute
			{
				private readonly BlocksUsing blocksUsing;

				public BlocksUsing BlocksUsing => blocksUsing;

				public bool SupportsAsync { get; set; }

				public bool Spins { get; set; }

				public string ReleaseMethod { get; set; }

				public SynchronizationPrimitiveAttribute(BlocksUsing blocksUsing)
				{
					this.blocksUsing = blocksUsing;
				}
			}

			[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class BlockingAttribute : Attribute
			{
				public string CancelMethod { get; set; }

				public Type CancelDeclaringType { get; set; }

				public string Conditional { get; set; }
			}

			[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class GuaranteeNonBlockingAttribute : Attribute
			{
			}

			[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class NonThrowingAttribute : Attribute
			{
			}

			[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public class ThrowsAttribute : Attribute
			{
				private readonly Type exceptionType;

				private readonly string diagnosis;

				public Type ExceptionType => exceptionType;

				public string Diagnosis => diagnosis;

				public ThrowsAttribute(Type exceptionType, string diagnosis)
				{
					if (exceptionType == null)
					{
						throw Exception.ArgumentNull("exceptionType");
					}
					if (string.IsNullOrEmpty(diagnosis))
					{
						throw Exception.ArgumentNullOrEmpty("diagnosis");
					}
					this.exceptionType = exceptionType;
					this.diagnosis = diagnosis;
				}
			}

			[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class InheritThrowsAttribute : Attribute
			{
				public Type FromDeclaringType { get; set; }

				public string From { get; set; }
			}

			[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class KnownXamlExternalAttribute : Attribute
			{
			}

			[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class XamlVisibleAttribute : Attribute
			{
				public bool Visible { get; private set; }

				public XamlVisibleAttribute()
					: this(visible: true)
				{
				}

				public XamlVisibleAttribute(bool visible)
				{
					Visible = visible;
				}
			}

			[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Module | AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Enum | AttributeTargets.Constructor | AttributeTargets.Method | AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Event | AttributeTargets.Interface | AttributeTargets.Delegate, AllowMultiple = false, Inherited = false)]
			[Conditional("CODE_ANALYSIS_CDF")]
			public sealed class SecurityNoteAttribute : Attribute
			{
				public string Critical { get; set; }

				public string Safe { get; set; }

				public string Miscellaneous { get; set; }
			}
		}

		private abstract class Thunk<T> where T : class
		{
			[SecurityCritical]
			private T callback;

			internal T Callback
			{
				[SecuritySafeCritical]
				get
				{
					return callback;
				}
			}

			[SecuritySafeCritical]
			protected Thunk(T callback)
			{
				this.callback = callback;
			}
		}

		private sealed class ActionThunk<T1> : Thunk<Action<T1>>
		{
			public Action<T1> ThunkFrame => UnhandledExceptionFrame;

			public ActionThunk(Action<T1> callback)
				: base(callback)
			{
			}

			[SecuritySafeCritical]
			private void UnhandledExceptionFrame(T1 result)
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					base.Callback(result);
				}
				catch (Exception exception)
				{
					if (!HandleAtThreadBase(exception))
					{
						throw;
					}
				}
			}
		}

		private sealed class AsyncThunk : Thunk<AsyncCallback>
		{
			public AsyncCallback ThunkFrame => UnhandledExceptionFrame;

			public AsyncThunk(AsyncCallback callback)
				: base(callback)
			{
			}

			[SecuritySafeCritical]
			private void UnhandledExceptionFrame(IAsyncResult result)
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					base.Callback(result);
				}
				catch (Exception exception)
				{
					if (!HandleAtThreadBase(exception))
					{
						throw;
					}
				}
			}
		}

		private sealed class WaitThunk : Thunk<WaitCallback>
		{
			public WaitCallback ThunkFrame => UnhandledExceptionFrame;

			public WaitThunk(WaitCallback callback)
				: base(callback)
			{
			}

			[SecuritySafeCritical]
			private void UnhandledExceptionFrame(object state)
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					base.Callback(state);
				}
				catch (Exception exception)
				{
					if (!HandleAtThreadBase(exception))
					{
						throw;
					}
				}
			}
		}

		private sealed class TimerThunk : Thunk<TimerCallback>
		{
			public TimerCallback ThunkFrame => UnhandledExceptionFrame;

			public TimerThunk(TimerCallback callback)
				: base(callback)
			{
			}

			[SecuritySafeCritical]
			private void UnhandledExceptionFrame(object state)
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					base.Callback(state);
				}
				catch (Exception exception)
				{
					if (!HandleAtThreadBase(exception))
					{
						throw;
					}
				}
			}
		}

		private sealed class WaitOrTimerThunk : Thunk<WaitOrTimerCallback>
		{
			public WaitOrTimerCallback ThunkFrame => UnhandledExceptionFrame;

			public WaitOrTimerThunk(WaitOrTimerCallback callback)
				: base(callback)
			{
			}

			[SecuritySafeCritical]
			private void UnhandledExceptionFrame(object state, bool timedOut)
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					base.Callback(state, timedOut);
				}
				catch (Exception exception)
				{
					if (!HandleAtThreadBase(exception))
					{
						throw;
					}
				}
			}
		}

		private sealed class SendOrPostThunk : Thunk<SendOrPostCallback>
		{
			public SendOrPostCallback ThunkFrame => UnhandledExceptionFrame;

			public SendOrPostThunk(SendOrPostCallback callback)
				: base(callback)
			{
			}

			[SecuritySafeCritical]
			private void UnhandledExceptionFrame(object state)
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					base.Callback(state);
				}
				catch (Exception exception)
				{
					if (!HandleAtThreadBase(exception))
					{
						throw;
					}
				}
			}
		}

		[SecurityCritical]
		private sealed class IOCompletionThunk
		{
			private IOCompletionCallback callback;

			public IOCompletionCallback ThunkFrame => UnhandledExceptionFrame;

			public unsafe IOCompletionThunk(IOCompletionCallback callback)
			{
				this.callback = callback;
			}

			private unsafe void UnhandledExceptionFrame(uint error, uint bytesRead, NativeOverlapped* nativeOverlapped)
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					callback(error, bytesRead, nativeOverlapped);
				}
				catch (Exception exception)
				{
					if (!HandleAtThreadBase(exception))
					{
						throw;
					}
				}
			}
		}

		[Serializable]
		private class InternalException : SystemException
		{
			public InternalException(string description)
				: base(InternalSR.ShipAssertExceptionMessage(description))
			{
			}

			protected InternalException(SerializationInfo info, StreamingContext context)
				: base(info, context)
			{
			}
		}

		[Serializable]
		private class FatalInternalException : InternalException
		{
			public FatalInternalException(string description)
				: base(description)
			{
			}

			protected FatalInternalException(SerializationInfo info, StreamingContext context)
				: base(info, context)
			{
			}
		}

		private const string defaultEventSource = "System.Runtime";

		private static ExceptionTrace exceptionTrace;

		private static EtwDiagnosticTrace diagnosticTrace;

		[SecurityCritical]
		private static ExceptionHandler asynchronousThreadExceptionHandler;

		public static ExceptionTrace Exception
		{
			get
			{
				if (exceptionTrace == null)
				{
					exceptionTrace = new ExceptionTrace("System.Runtime", Trace);
				}
				return exceptionTrace;
			}
		}

		public static EtwDiagnosticTrace Trace
		{
			get
			{
				if (diagnosticTrace == null)
				{
					diagnosticTrace = InitializeTracing();
				}
				return diagnosticTrace;
			}
		}

		public static ExceptionHandler AsynchronousThreadExceptionHandler
		{
			[SecuritySafeCritical]
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			get
			{
				return asynchronousThreadExceptionHandler;
			}
			[SecurityCritical]
			set
			{
				asynchronousThreadExceptionHandler = value;
			}
		}

		internal static bool AssertsFailFast => false;

		internal static Type[] BreakOnExceptionTypes => null;

		internal static bool FastDebug => false;

		internal static bool StealthDebugger => false;

		[SecuritySafeCritical]
		private static EtwDiagnosticTrace InitializeTracing()
		{
			EtwDiagnosticTrace etwDiagnosticTrace = new EtwDiagnosticTrace("System.Runtime", EtwDiagnosticTrace.DefaultEtwProviderId);
			if (etwDiagnosticTrace.EtwProvider != null)
			{
				etwDiagnosticTrace.RefreshState = (Action)Delegate.Combine(etwDiagnosticTrace.RefreshState, (Action)delegate
				{
					UpdateLevel();
				});
			}
			UpdateLevel(etwDiagnosticTrace);
			return etwDiagnosticTrace;
		}

		[Conditional("DEBUG")]
		public static void Assert(bool condition, string description)
		{
		}

		[Conditional("DEBUG")]
		public static void Assert(string description)
		{
			AssertHelper.FireAssert(description);
		}

		public static void AssertAndThrow(bool condition, string description)
		{
			if (!condition)
			{
				AssertAndThrow(description);
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		public static Exception AssertAndThrow(string description)
		{
			TraceCore.ShipAssertExceptionMessage(Trace, description);
			throw new InternalException(description);
		}

		public static void AssertAndThrowFatal(bool condition, string description)
		{
			if (!condition)
			{
				AssertAndThrowFatal(description);
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		public static Exception AssertAndThrowFatal(string description)
		{
			TraceCore.ShipAssertExceptionMessage(Trace, description);
			throw new FatalInternalException(description);
		}

		public static void AssertAndFailFast(bool condition, string description)
		{
			if (!condition)
			{
				AssertAndFailFast(description);
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[SecuritySafeCritical]
		public static Exception AssertAndFailFast(string description)
		{
			string message = InternalSR.FailFastMessage(description);
			try
			{
				try
				{
					Exception.TraceFailFast(message);
				}
				finally
				{
					Environment.FailFast(message);
				}
			}
			catch
			{
				throw;
			}
			return null;
		}

		public static bool IsFatal(Exception exception)
		{
			while (exception != null)
			{
				if (exception is FatalException || (exception is OutOfMemoryException && !(exception is InsufficientMemoryException)) || exception is ThreadAbortException || exception is FatalInternalException)
				{
					return true;
				}
				if (exception is TypeInitializationException || exception is TargetInvocationException)
				{
					exception = exception.InnerException;
					continue;
				}
				if (!(exception is AggregateException))
				{
					break;
				}
				ReadOnlyCollection<Exception> innerExceptions = ((AggregateException)exception).InnerExceptions;
				foreach (Exception item in innerExceptions)
				{
					if (IsFatal(item))
					{
						return true;
					}
				}
				break;
			}
			return false;
		}

		public static Action<T1> ThunkCallback<T1>(Action<T1> callback)
		{
			return new ActionThunk<T1>(callback).ThunkFrame;
		}

		public static AsyncCallback ThunkCallback(AsyncCallback callback)
		{
			return new AsyncThunk(callback).ThunkFrame;
		}

		public static WaitCallback ThunkCallback(WaitCallback callback)
		{
			return new WaitThunk(callback).ThunkFrame;
		}

		public static TimerCallback ThunkCallback(TimerCallback callback)
		{
			return new TimerThunk(callback).ThunkFrame;
		}

		public static WaitOrTimerCallback ThunkCallback(WaitOrTimerCallback callback)
		{
			return new WaitOrTimerThunk(callback).ThunkFrame;
		}

		public static SendOrPostCallback ThunkCallback(SendOrPostCallback callback)
		{
			return new SendOrPostThunk(callback).ThunkFrame;
		}

		[SecurityCritical]
		public unsafe static IOCompletionCallback ThunkCallback(IOCompletionCallback callback)
		{
			return new IOCompletionThunk(callback).ThunkFrame;
		}

		public static Guid CreateGuid(string guidString)
		{
			bool flag = false;
			Guid empty = Guid.Empty;
			try
			{
				empty = new Guid(guidString);
				flag = true;
				return empty;
			}
			finally
			{
				if (!flag)
				{
					AssertAndThrow("Creation of the Guid failed.");
				}
			}
		}

		public static bool TryCreateGuid(string guidString, out Guid result)
		{
			bool result2 = false;
			result = Guid.Empty;
			try
			{
				result = new Guid(guidString);
				result2 = true;
				return result2;
			}
			catch (ArgumentException)
			{
				return result2;
			}
			catch (FormatException)
			{
				return result2;
			}
			catch (OverflowException)
			{
				return result2;
			}
		}

		public static byte[] AllocateByteArray(int size)
		{
			try
			{
				return new byte[size];
			}
			catch (OutOfMemoryException innerException)
			{
				throw Exception.AsError(new InsufficientMemoryException(InternalSR.BufferAllocationFailed(size), innerException));
			}
		}

		public static char[] AllocateCharArray(int size)
		{
			try
			{
				return new char[size];
			}
			catch (OutOfMemoryException innerException)
			{
				throw Exception.AsError(new InsufficientMemoryException(InternalSR.BufferAllocationFailed(size * 2), innerException));
			}
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		private static void TraceExceptionNoThrow(Exception exception)
		{
			try
			{
				Exception.TraceUnhandledException(exception);
			}
			catch
			{
			}
		}

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		private static bool HandleAtThreadBase(Exception exception)
		{
			if (exception == null)
			{
				return false;
			}
			TraceExceptionNoThrow(exception);
			try
			{
				return AsynchronousThreadExceptionHandler?.HandleException(exception) ?? false;
			}
			catch (Exception exception2)
			{
				TraceExceptionNoThrow(exception2);
			}
			return false;
		}

		private static void UpdateLevel(EtwDiagnosticTrace trace)
		{
			if (trace != null && (TraceCore.ActionItemCallbackInvokedIsEnabled(trace) || TraceCore.ActionItemScheduledIsEnabled(trace)))
			{
				trace.SetEnd2EndActivityTracingEnabled(isEnd2EndTracingEnabled: true);
			}
		}

		private static void UpdateLevel()
		{
			UpdateLevel(Trace);
		}
	}
	internal static class FxCop
	{
		public static class Category
		{
			public const string Design = "Microsoft.Design";

			public const string Globalization = "Microsoft.Globalization";

			public const string Maintainability = "Microsoft.Maintainability";

			public const string MSInternal = "Microsoft.MSInternal";

			public const string Naming = "Microsoft.Naming";

			public const string Performance = "Microsoft.Performance";

			public const string Reliability = "Microsoft.Reliability";

			public const string Security = "Microsoft.Security";

			public const string Usage = "Microsoft.Usage";

			public const string Configuration = "Configuration";

			public const string ReliabilityBasic = "Reliability";

			public const string Xaml = "XAML";
		}

		public static class Rule
		{
			public const string AptcaMethodsShouldOnlyCallAptcaMethods = "CA2116:AptcaMethodsShouldOnlyCallAptcaMethods";

			public const string AssembliesShouldHaveValidStrongNames = "CA2210:AssembliesShouldHaveValidStrongNames";

			public const string AvoidCallingProblematicMethods = "CA2001:AvoidCallingProblematicMethods";

			public const string AvoidExcessiveComplexity = "CA1502:AvoidExcessiveComplexity";

			public const string AvoidNamespacesWithFewTypes = "CA1020:AvoidNamespacesWithFewTypes";

			public const string AvoidOutParameters = "CA1021:AvoidOutParameters";

			public const string AvoidUncalledPrivateCode = "CA1811:AvoidUncalledPrivateCode";

			public const string AvoidUninstantiatedInternalClasses = "CA1812:AvoidUninstantiatedInternalClasses";

			public const string AvoidUnsealedAttributes = "CA1813:AvoidUnsealedAttributes";

			public const string CollectionPropertiesShouldBeReadOnly = "CA2227:CollectionPropertiesShouldBeReadOnly";

			public const string CollectionsShouldImplementGenericInterface = "CA1010:CollectionsShouldImplementGenericInterface";

			public const string ConfigurationPropertyAttributeRule = "Configuration102:ConfigurationPropertyAttributeRule";

			public const string ConfigurationValidatorAttributeRule = "Configuration104:ConfigurationValidatorAttributeRule";

			public const string ConsiderPassingBaseTypesAsParameters = "CA1011:ConsiderPassingBaseTypesAsParameters";

			public const string CommunicationObjectThrowIf = "Reliability106";

			public const string ConfigurationPropertyNameRule = "Configuration103:ConfigurationPropertyNameRule";

			public const string DefaultParametersShouldNotBeUsed = "CA1026:DefaultParametersShouldNotBeUsed";

			public const string DefineAccessorsForAttributeArguments = "CA1019:DefineAccessorsForAttributeArguments";

			public const string DiagnosticsUtilityIsFatal = "Reliability108";

			public const string DisposableFieldsShouldBeDisposed = "CA2213:DisposableFieldsShouldBeDisposed";

			public const string DoNotCallOverridableMethodsInConstructors = "CA2214:DoNotCallOverridableMethodsInConstructors";

			public const string DoNotCatchGeneralExceptionTypes = "CA1031:DoNotCatchGeneralExceptionTypes";

			public const string DoNotDeclareReadOnlyMutableReferenceTypes = "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes";

			public const string DoNotDeclareVisibleInstanceFields = "CA1051:DoNotDeclareVisibleInstanceFields";

			public const string DoNotLockOnObjectsWithWeakIdentity = "CA2002:DoNotLockOnObjectsWithWeakIdentity";

			public const string DoNotIgnoreMethodResults = "CA1806:DoNotIgnoreMethodResults";

			public const string DoNotIndirectlyExposeMethodsWithLinkDemands = "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands";

			public const string DoNotPassLiteralsAsLocalizedParameters = "CA1303:DoNotPassLiteralsAsLocalizedParameters";

			public const string DoNotRaiseReservedExceptionTypes = "CA2201:DoNotRaiseReservedExceptionTypes";

			public const string EnumsShouldHaveZeroValue = "CA1008:EnumsShouldHaveZeroValue";

			public const string FlagsEnumsShouldHavePluralNames = "CA1714:FlagsEnumsShouldHavePluralNames";

			public const string GenericMethodsShouldProvideTypeParameter = "CA1004:GenericMethodsShouldProvideTypeParameter";

			public const string IdentifiersShouldBeSpelledCorrectly = "CA1704:IdentifiersShouldBeSpelledCorrectly";

			public const string IdentifiersShouldHaveCorrectSuffix = "CA1710:IdentifiersShouldHaveCorrectSuffix";

			public const string IdentifiersShouldNotContainTypeNames = "CA1720:IdentifiersShouldNotContainTypeNames";

			public const string IdentifiersShouldNotHaveIncorrectSuffix = "CA1711:IdentifiersShouldNotHaveIncorrectSuffix";

			public const string IdentifiersShouldNotMatchKeywords = "CA1716:IdentifiersShouldNotMatchKeywords";

			public const string ImplementStandardExceptionConstructors = "CA1032:ImplementStandardExceptionConstructors";

			public const string InstantiateArgumentExceptionsCorrectly = "CA2208:InstantiateArgumentExceptionsCorrectly";

			public const string InitializeReferenceTypeStaticFieldsInline = "CA1810:InitializeReferenceTypeStaticFieldsInline";

			public const string InterfaceMethodsShouldBeCallableByChildTypes = "CA1033:InterfaceMethodsShouldBeCallableByChildTypes";

			public const string MarkISerializableTypesWithSerializable = "CA2237:MarkISerializableTypesWithSerializable";

			public const string InvariantAssertRule = "Reliability101:InvariantAssertRule";

			public const string IsFatalRule = "Reliability108:IsFatalRule";

			public const string MarkMembersAsStatic = "CA1822:MarkMembersAsStatic";

			public const string NestedTypesShouldNotBeVisible = "CA1034:NestedTypesShouldNotBeVisible";

			public const string NormalizeStringsToUppercase = "CA1308:NormalizeStringsToUppercase";

			public const string OperatorOverloadsHaveNamedAlternates = "CA2225:OperatorOverloadsHaveNamedAlternates";

			public const string PropertyNamesShouldNotMatchGetMethods = "CA1721:PropertyNamesShouldNotMatchGetMethods";

			public const string PropertyTypesMustBeXamlVisible = "XAML1002:PropertyTypesMustBeXamlVisible";

			public const string PropertyExternalTypesMustBeKnown = "XAML1010:PropertyExternalTypesMustBeKnown";

			public const string ReplaceRepetitiveArgumentsWithParamsArray = "CA1025:ReplaceRepetitiveArgumentsWithParamsArray";

			public const string ResourceStringsShouldBeSpelledCorrectly = "CA1703:ResourceStringsShouldBeSpelledCorrectly";

			public const string ReviewSuppressUnmanagedCodeSecurityUsage = "CA2118:ReviewSuppressUnmanagedCodeSecurityUsage";

			public const string ReviewUnusedParameters = "CA1801:ReviewUnusedParameters";

			public const string SecureAsserts = "CA2106:SecureAsserts";

			public const string SecureGetObjectDataOverrides = "CA2110:SecureGetObjectDataOverrides";

			public const string ShortAcronymsShouldBeUppercase = "CA1706:ShortAcronymsShouldBeUppercase";

			public const string SpecifyIFormatProvider = "CA1305:SpecifyIFormatProvider";

			public const string SpecifyMarshalingForPInvokeStringArguments = "CA2101:SpecifyMarshalingForPInvokeStringArguments";

			public const string StaticHolderTypesShouldNotHaveConstructors = "CA1053:StaticHolderTypesShouldNotHaveConstructors";

			public const string SystemAndMicrosoftNamespacesRequireApproval = "CA:SystemAndMicrosoftNamespacesRequireApproval";

			public const string UsePropertiesWhereAppropriate = "CA1024:UsePropertiesWhereAppropriate";

			public const string UriPropertiesShouldNotBeStrings = "CA1056:UriPropertiesShouldNotBeStrings";

			public const string VariableNamesShouldNotMatchFieldNames = "CA1500:VariableNamesShouldNotMatchFieldNames";

			public const string ThunkCallbackRule = "Reliability109:ThunkCallbackRule";

			public const string TransparentMethodsMustNotReferenceCriticalCode = "CA2140:TransparentMethodsMustNotReferenceCriticalCodeFxCopRule";

			public const string TypeConvertersMustBePublic = "XAML1004:TypeConvertersMustBePublic";

			public const string TypesMustHaveXamlCallableConstructors = "XAML1007:TypesMustHaveXamlCallableConstructors";

			public const string TypeNamesShouldNotMatchNamespaces = "CA1724:TypeNamesShouldNotMatchNamespaces";

			public const string TypesShouldHavePublicParameterlessConstructors = "XAML1009:TypesShouldHavePublicParameterlessConstructors";

			public const string UseEventsWhereAppropriate = "CA1030:UseEventsWhereAppropriate";

			public const string UseNewGuidHelperRule = "Reliability113:UseNewGuidHelperRule";

			public const string WrapExceptionsRule = "Reliability102:WrapExceptionsRule";
		}
	}
	internal static class HashHelper
	{
		public static byte[] ComputeHash(byte[] buffer)
		{
			int[] array = new int[16]
			{
				7, 12, 17, 22, 5, 9, 14, 20, 4, 11,
				16, 23, 6, 10, 15, 21
			};
			uint[] array2 = new uint[64]
			{
				3614090360u, 3905402710u, 606105819u, 3250441966u, 4118548399u, 1200080426u, 2821735955u, 4249261313u, 1770035416u, 2336552879u,
				4294925233u, 2304563134u, 1804603682u, 4254626195u, 2792965006u, 1236535329u, 4129170786u, 3225465664u, 643717713u, 3921069994u,
				3593408605u, 38016083u, 3634488961u, 3889429448u, 568446438u, 3275163606u, 4107603335u, 1163531501u, 2850285829u, 4243563512u,
				1735328473u, 2368359562u, 4294588738u, 2272392833u, 1839030562u, 4259657740u, 2763975236u, 1272893353u, 4139469664u, 3200236656u,
				681279174u, 3936430074u, 3572445317u, 76029189u, 3654602809u, 3873151461u, 530742520u, 3299628645u, 4096336452u, 1126891415u,
				2878612391u, 4237533241u, 1700485571u, 2399980690u, 4293915773u, 2240044497u, 1873313359u, 4264355552u, 2734768916u, 1309151649u,
				4149444226u, 3174756917u, 718787259u, 3951481745u
			};
			int num = (buffer.Length + 8) / 64 + 1;
			uint num2 = 1732584193u;
			uint num3 = 4023233417u;
			uint num4 = 2562383102u;
			uint num5 = 271733878u;
			for (int i = 0; i < num; i++)
			{
				byte[] array3 = buffer;
				int num6 = i * 64;
				if (num6 + 64 > buffer.Length)
				{
					array3 = new byte[64];
					for (int j = num6; j < buffer.Length; j++)
					{
						array3[j - num6] = buffer[j];
					}
					if (num6 <= buffer.Length)
					{
						array3[buffer.Length - num6] = 128;
					}
					if (i == num - 1)
					{
						array3[56] = (byte)(buffer.Length << 3);
						array3[57] = (byte)(buffer.Length >> 5);
						array3[58] = (byte)(buffer.Length >> 13);
						array3[59] = (byte)(buffer.Length >> 21);
					}
					num6 = 0;
				}
				uint num7 = num2;
				uint num8 = num3;
				uint num9 = num4;
				uint num10 = num5;
				for (int k = 0; k < 64; k++)
				{
					uint num11;
					int num12;
					if (k < 16)
					{
						num11 = (num8 & num9) | (~num8 & num10);
						num12 = k;
					}
					else if (k < 32)
					{
						num11 = (num8 & num10) | (num9 & ~num10);
						num12 = 5 * k + 1;
					}
					else if (k < 48)
					{
						num11 = num8 ^ num9 ^ num10;
						num12 = 3 * k + 5;
					}
					else
					{
						num11 = num9 ^ (num8 | ~num10);
						num12 = 7 * k;
					}
					num12 = (num12 & 0xF) * 4 + num6;
					uint num13 = num10;
					num10 = num9;
					num9 = num8;
					num8 = num7 + num11 + array2[k] + (uint)(array3[num12] + (array3[num12 + 1] << 8) + (array3[num12 + 2] << 16) + (array3[num12 + 3] << 24));
					num8 = (num8 << array[(k & 3) | ((k >> 2) & -4)]) | (num8 >> 32 - array[(k & 3) | ((k >> 2) & -4)]);
					num8 += num9;
					num7 = num13;
				}
				num2 += num7;
				num3 += num8;
				num4 += num9;
				num5 += num10;
			}
			return new byte[16]
			{
				(byte)num2,
				(byte)(num2 >> 8),
				(byte)(num2 >> 16),
				(byte)(num2 >> 24),
				(byte)num3,
				(byte)(num3 >> 8),
				(byte)(num3 >> 16),
				(byte)(num3 >> 24),
				(byte)num4,
				(byte)(num4 >> 8),
				(byte)(num4 >> 16),
				(byte)(num4 >> 24),
				(byte)num5,
				(byte)(num5 >> 8),
				(byte)(num5 >> 16),
				(byte)(num5 >> 24)
			};
		}
	}
	internal interface IAsyncEventArgs
	{
		object AsyncState { get; }

		Exception Exception { get; }
	}
	internal sealed class InputQueue<T> : IDisposable where T : class
	{
		private enum QueueState
		{
			Open,
			Shutdown,
			Closed
		}

		private interface IQueueReader
		{
			void Set(Item item);
		}

		private interface IQueueWaiter
		{
			void Set(bool itemAvailable);
		}

		private struct Item
		{
			private Action dequeuedCallback;

			private Exception exception;

			private T value;

			public Action DequeuedCallback => dequeuedCallback;

			public Exception Exception => exception;

			public T Value => value;

			public Item(T value, Action dequeuedCallback)
				: this(value, null, dequeuedCallback)
			{
			}

			public Item(Exception exception, Action dequeuedCallback)
				: this(null, exception, dequeuedCallback)
			{
			}

			private Item(T value, Exception exception, Action dequeuedCallback)
			{
				this.value = value;
				this.exception = exception;
				this.dequeuedCallback = dequeuedCallback;
			}

			public T GetValue()
			{
				if (exception != null)
				{
					throw Fx.Exception.AsError(exception);
				}
				return value;
			}
		}

		private class AsyncQueueReader : AsyncResult, IQueueReader
		{
			private static Action<object> timerCallback = TimerCallback;

			private bool expired;

			private InputQueue<T> inputQueue;

			private T item;

			private IOThreadTimer timer;

			public AsyncQueueReader(InputQueue<T> inputQueue, TimeSpan timeout, AsyncCallback callback, object state)
				: base(callback, state)
			{
				if (inputQueue.AsyncCallbackGenerator != null)
				{
					base.VirtualCallback = inputQueue.AsyncCallbackGenerator();
				}
				this.inputQueue = inputQueue;
				if (timeout != TimeSpan.MaxValue)
				{
					timer = new IOThreadTimer(timerCallback, this, isTypicallyCanceledShortlyAfterBeingSet: false);
					timer.Set(timeout);
				}
			}

			public static bool End(IAsyncResult result, out T value)
			{
				AsyncQueueReader asyncQueueReader = AsyncResult.End<AsyncQueueReader>(result);
				if (asyncQueueReader.expired)
				{
					value = null;
					return false;
				}
				value = asyncQueueReader.item;
				return true;
			}

			public void Set(Item item)
			{
				this.item = item.Value;
				if (timer != null)
				{
					timer.Cancel();
				}
				Complete(completedSynchronously: false, item.Exception);
			}

			private static void TimerCallback(object state)
			{
				AsyncQueueReader asyncQueueReader = (AsyncQueueReader)state;
				if (asyncQueueReader.inputQueue.RemoveReader(asyncQueueReader))
				{
					asyncQueueReader.expired = true;
					asyncQueueReader.Complete(completedSynchronously: false);
				}
			}
		}

		private class AsyncQueueWaiter : AsyncResult, IQueueWaiter
		{
			private static Action<object> timerCallback = TimerCallback;

			private bool itemAvailable;

			private object thisLock = new object();

			private IOThreadTimer timer;

			private object ThisLock => thisLock;

			public AsyncQueueWaiter(TimeSpan timeout, AsyncCallback callback, object state)
				: base(callback, state)
			{
				if (timeout != TimeSpan.MaxValue)
				{
					timer = new IOThreadTimer(timerCallback, this, isTypicallyCanceledShortlyAfterBeingSet: false);
					timer.Set(timeout);
				}
			}

			public static bool End(IAsyncResult result)
			{
				AsyncQueueWaiter asyncQueueWaiter = AsyncResult.End<AsyncQueueWaiter>(result);
				return asyncQueueWaiter.itemAvailable;
			}

			public void Set(bool itemAvailable)
			{
				bool flag;
				lock (ThisLock)
				{
					flag = timer == null || timer.Cancel();
					this.itemAvailable = itemAvailable;
				}
				if (flag)
				{
					Complete(completedSynchronously: false);
				}
			}

			private static void TimerCallback(object state)
			{
				AsyncQueueWaiter asyncQueueWaiter = (AsyncQueueWaiter)state;
				asyncQueueWaiter.Complete(completedSynchronously: false);
			}
		}

		private class ItemQueue
		{
			private int head;

			private Item[] items;

			private int pendingCount;

			private int totalCount;

			public bool HasAnyItem => totalCount > 0;

			public bool HasAvailableItem => totalCount > pendingCount;

			public int ItemCount => totalCount;

			public ItemQueue()
			{
				items = new Item[1];
			}

			public Item DequeueAnyItem()
			{
				if (pendingCount == totalCount)
				{
					pendingCount--;
				}
				return DequeueItemCore();
			}

			public Item DequeueAvailableItem()
			{
				Fx.AssertAndThrow(totalCount != pendingCount, "ItemQueue does not contain any available items");
				return DequeueItemCore();
			}

			public void EnqueueAvailableItem(Item item)
			{
				EnqueueItemCore(item);
			}

			public void EnqueuePendingItem(Item item)
			{
				EnqueueItemCore(item);
				pendingCount++;
			}

			public void MakePendingItemAvailable()
			{
				Fx.AssertAndThrow(pendingCount != 0, "ItemQueue does not contain any pending items");
				pendingCount--;
			}

			private Item DequeueItemCore()
			{
				Fx.AssertAndThrow(totalCount != 0, "ItemQueue does not contain any items");
				Item result = items[head];
				items[head] = default(Item);
				totalCount--;
				head = (head + 1) % items.Length;
				return result;
			}

			private void EnqueueItemCore(Item item)
			{
				if (totalCount == items.Length)
				{
					Item[] array = new Item[items.Length * 2];
					for (int i = 0; i < totalCount; i++)
					{
						array[i] = items[(head + i) % items.Length];
					}
					head = 0;
					items = array;
				}
				int num = (head + totalCount) % items.Length;
				items[num] = item;
				totalCount++;
			}
		}

		private class WaitQueueReader : IQueueReader
		{
			private Exception exception;

			private InputQueue<T> inputQueue;

			private T item;

			private ManualResetEvent waitEvent;

			public WaitQueueReader(InputQueue<T> inputQueue)
			{
				this.inputQueue = inputQueue;
				waitEvent = new ManualResetEvent(initialState: false);
			}

			public void Set(Item item)
			{
				lock (this)
				{
					exception = item.Exception;
					this.item = item.Value;
					waitEvent.Set();
				}
			}

			public bool Wait(TimeSpan timeout, out T value)
			{
				bool flag = false;
				try
				{
					if (!TimeoutHelper.WaitOne(waitEvent, timeout))
					{
						if (inputQueue.RemoveReader(this))
						{
							value = null;
							flag = true;
							return false;
						}
						waitEvent.WaitOne();
					}
					flag = true;
				}
				finally
				{
					if (flag)
					{
						waitEvent.Close();
					}
				}
				if (exception != null)
				{
					throw Fx.Exception.AsError(exception);
				}
				value = item;
				return true;
			}
		}

		private class WaitQueueWaiter : IQueueWaiter
		{
			private bool itemAvailable;

			private ManualResetEvent waitEvent;

			public WaitQueueWaiter()
			{
				waitEvent = new ManualResetEvent(initialState: false);
			}

			public void Set(bool itemAvailable)
			{
				lock (this)
				{
					this.itemAvailable = itemAvailable;
					waitEvent.Set();
				}
			}

			public bool Wait(TimeSpan timeout)
			{
				if (!TimeoutHelper.WaitOne(waitEvent, timeout))
				{
					return false;
				}
				return itemAvailable;
			}
		}

		private static Action<object> completeOutstandingReadersCallback;

		private static Action<object> completeWaitersFalseCallback;

		private static Action<object> completeWaitersTrueCallback;

		private static Action<object> onDispatchCallback;

		private static Action<object> onInvokeDequeuedCallback;

		private QueueState queueState;

		private ItemQueue itemQueue;

		private Queue<IQueueReader> readerQueue;

		private List<IQueueWaiter> waiterList;

		public int PendingCount
		{
			get
			{
				lock (ThisLock)
				{
					return itemQueue.ItemCount;
				}
			}
		}

		public Action<T> DisposeItemCallback { get; set; }

		private Func<Action<AsyncCallback, IAsyncResult>> AsyncCallbackGenerator { get; set; }

		private object ThisLock => itemQueue;

		public InputQueue()
		{
			itemQueue = new ItemQueue();
			readerQueue = new Queue<IQueueReader>();
			waiterList = new List<IQueueWaiter>();
			queueState = QueueState.Open;
		}

		public InputQueue(Func<Action<AsyncCallback, IAsyncResult>> asyncCallbackGenerator)
			: this()
		{
			AsyncCallbackGenerator = asyncCallbackGenerator;
		}

		public IAsyncResult BeginDequeue(TimeSpan timeout, AsyncCallback callback, object state)
		{
			Item item = default(Item);
			lock (ThisLock)
			{
				if (queueState == QueueState.Open)
				{
					if (!itemQueue.HasAvailableItem)
					{
						AsyncQueueReader asyncQueueReader = new AsyncQueueReader(this, timeout, callback, state);
						readerQueue.Enqueue(asyncQueueReader);
						return asyncQueueReader;
					}
					item = itemQueue.DequeueAvailableItem();
				}
				else if (queueState == QueueState.Shutdown)
				{
					if (itemQueue.HasAvailableItem)
					{
						item = itemQueue.DequeueAvailableItem();
					}
					else if (itemQueue.HasAnyItem)
					{
						AsyncQueueReader asyncQueueReader2 = new AsyncQueueReader(this, timeout, callback, state);
						readerQueue.Enqueue(asyncQueueReader2);
						return asyncQueueReader2;
					}
				}
			}
			InvokeDequeuedCallback(item.DequeuedCallback);
			return new CompletedAsyncResult<T>(item.GetValue(), callback, state);
		}

		public IAsyncResult BeginWaitForItem(TimeSpan timeout, AsyncCallback callback, object state)
		{
			lock (ThisLock)
			{
				if (queueState == QueueState.Open)
				{
					if (!itemQueue.HasAvailableItem)
					{
						AsyncQueueWaiter asyncQueueWaiter = new AsyncQueueWaiter(timeout, callback, state);
						waiterList.Add(asyncQueueWaiter);
						return asyncQueueWaiter;
					}
				}
				else if (queueState == QueueState.Shutdown && !itemQueue.HasAvailableItem && itemQueue.HasAnyItem)
				{
					AsyncQueueWaiter asyncQueueWaiter2 = new AsyncQueueWaiter(timeout, callback, state);
					waiterList.Add(asyncQueueWaiter2);
					return asyncQueueWaiter2;
				}
			}
			return new CompletedAsyncResult<bool>(data: true, callback, state);
		}

		public void Close()
		{
			Dispose();
		}

		public T Dequeue(TimeSpan timeout)
		{
			if (!Dequeue(timeout, out var value))
			{
				throw Fx.Exception.AsError(new TimeoutException(InternalSR.TimeoutInputQueueDequeue(timeout)));
			}
			return value;
		}

		public bool Dequeue(TimeSpan timeout, out T value)
		{
			WaitQueueReader waitQueueReader = null;
			Item item = default(Item);
			lock (ThisLock)
			{
				if (queueState == QueueState.Open)
				{
					if (itemQueue.HasAvailableItem)
					{
						item = itemQueue.DequeueAvailableItem();
					}
					else
					{
						waitQueueReader = new WaitQueueReader(this);
						readerQueue.Enqueue(waitQueueReader);
					}
				}
				else
				{
					if (queueState != QueueState.Shutdown)
					{
						value = null;
						return true;
					}
					if (itemQueue.HasAvailableItem)
					{
						item = itemQueue.DequeueAvailableItem();
					}
					else
					{
						if (!itemQueue.HasAnyItem)
						{
							value = null;
							return true;
						}
						waitQueueReader = new WaitQueueReader(this);
						readerQueue.Enqueue(waitQueueReader);
					}
				}
			}
			if (waitQueueReader != null)
			{
				return waitQueueReader.Wait(timeout, out value);
			}
			InvokeDequeuedCallback(item.DequeuedCallback);
			value = item.GetValue();
			return true;
		}

		public void Dispatch()
		{
			IQueueReader queueReader = null;
			Item item = default(Item);
			IQueueReader[] array = null;
			IQueueWaiter[] waiters = null;
			bool itemAvailable = true;
			lock (ThisLock)
			{
				itemAvailable = queueState != QueueState.Closed && queueState != QueueState.Shutdown;
				GetWaiters(out waiters);
				if (queueState != QueueState.Closed)
				{
					itemQueue.MakePendingItemAvailable();
					if (readerQueue.Count > 0)
					{
						item = itemQueue.DequeueAvailableItem();
						queueReader = readerQueue.Dequeue();
						if (queueState == QueueState.Shutdown && readerQueue.Count > 0 && itemQueue.ItemCount == 0)
						{
							array = new IQueueReader[readerQueue.Count];
							readerQueue.CopyTo(array, 0);
							readerQueue.Clear();
							itemAvailable = false;
						}
					}
				}
			}
			if (array != null)
			{
				if (completeOutstandingReadersCallback == null)
				{
					completeOutstandingReadersCallback = CompleteOutstandingReadersCallback;
				}
				ActionItem.Schedule(completeOutstandingReadersCallback, array);
			}
			if (waiters != null)
			{
				CompleteWaitersLater(itemAvailable, waiters);
			}
			if (queueReader != null)
			{
				InvokeDequeuedCallback(item.DequeuedCallback);
				queueReader.Set(item);
			}
		}

		public bool EndDequeue(IAsyncResult result, out T value)
		{
			if (result is CompletedAsyncResult<T>)
			{
				value = CompletedAsyncResult<T>.End(result);
				return true;
			}
			return AsyncQueueReader.End(result, out value);
		}

		public T EndDequeue(IAsyncResult result)
		{
			if (!EndDequeue(result, out var value))
			{
				throw Fx.Exception.AsError(new TimeoutException());
			}
			return value;
		}

		public bool EndWaitForItem(IAsyncResult result)
		{
			if (result is CompletedAsyncResult<bool>)
			{
				return CompletedAsyncResult<bool>.End(result);
			}
			return AsyncQueueWaiter.End(result);
		}

		public void EnqueueAndDispatch(T item)
		{
			EnqueueAndDispatch(item, null);
		}

		public void EnqueueAndDispatch(T item, Action dequeuedCallback)
		{
			EnqueueAndDispatch(item, dequeuedCallback, canDispatchOnThisThread: true);
		}

		public void EnqueueAndDispatch(Exception exception, Action dequeuedCallback, bool canDispatchOnThisThread)
		{
			EnqueueAndDispatch(new Item(exception, dequeuedCallback), canDispatchOnThisThread);
		}

		public void EnqueueAndDispatch(T item, Action dequeuedCallback, bool canDispatchOnThisThread)
		{
			EnqueueAndDispatch(new Item(item, dequeuedCallback), canDispatchOnThisThread);
		}

		public bool EnqueueWithoutDispatch(T item, Action dequeuedCallback)
		{
			return EnqueueWithoutDispatch(new Item(item, dequeuedCallback));
		}

		public bool EnqueueWithoutDispatch(Exception exception, Action dequeuedCallback)
		{
			return EnqueueWithoutDispatch(new Item(exception, dequeuedCallback));
		}

		public void Shutdown()
		{
			Shutdown(null);
		}

		public void Shutdown(Func<Exception> pendingExceptionGenerator)
		{
			IQueueReader[] array = null;
			lock (ThisLock)
			{
				if (queueState == QueueState.Shutdown || queueState == QueueState.Closed)
				{
					return;
				}
				queueState = QueueState.Shutdown;
				if (readerQueue.Count > 0 && itemQueue.ItemCount == 0)
				{
					array = new IQueueReader[readerQueue.Count];
					readerQueue.CopyTo(array, 0);
					readerQueue.Clear();
				}
			}
			if (array != null)
			{
				for (int i = 0; i < array.Length; i++)
				{
					Exception exception = pendingExceptionGenerator?.Invoke();
					array[i].Set(new Item(exception, null));
				}
			}
		}

		public bool WaitForItem(TimeSpan timeout)
		{
			WaitQueueWaiter waitQueueWaiter = null;
			bool flag = false;
			lock (ThisLock)
			{
				if (queueState == QueueState.Open)
				{
					if (itemQueue.HasAvailableItem)
					{
						flag = true;
					}
					else
					{
						waitQueueWaiter = new WaitQueueWaiter();
						waiterList.Add(waitQueueWaiter);
					}
				}
				else
				{
					if (queueState != QueueState.Shutdown)
					{
						return true;
					}
					if (itemQueue.HasAvailableItem)
					{
						flag = true;
					}
					else
					{
						if (!itemQueue.HasAnyItem)
						{
							return true;
						}
						waitQueueWaiter = new WaitQueueWaiter();
						waiterList.Add(waitQueueWaiter);
					}
				}
			}
			return waitQueueWaiter?.Wait(timeout) ?? flag;
		}

		public void Dispose()
		{
			bool flag = false;
			lock (ThisLock)
			{
				if (queueState != QueueState.Closed)
				{
					queueState = QueueState.Closed;
					flag = true;
				}
			}
			if (flag)
			{
				while (readerQueue.Count > 0)
				{
					IQueueReader queueReader = readerQueue.Dequeue();
					queueReader.Set(default(Item));
				}
				while (itemQueue.HasAnyItem)
				{
					Item item = itemQueue.DequeueAnyItem();
					DisposeItem(item);
					InvokeDequeuedCallback(item.DequeuedCallback);
				}
			}
		}

		private void DisposeItem(Item item)
		{
			T value = item.Value;
			if (value != null)
			{
				if (value is IDisposable)
				{
					((IDisposable)value).Dispose();
				}
				else
				{
					DisposeItemCallback?.Invoke(value);
				}
			}
		}

		private static void CompleteOutstandingReadersCallback(object state)
		{
			IQueueReader[] array = (IQueueReader[])state;
			for (int i = 0; i < array.Length; i++)
			{
				array[i].Set(default(Item));
			}
		}

		private static void CompleteWaiters(bool itemAvailable, IQueueWaiter[] waiters)
		{
			for (int i = 0; i < waiters.Length; i++)
			{
				waiters[i].Set(itemAvailable);
			}
		}

		private static void CompleteWaitersFalseCallback(object state)
		{
			CompleteWaiters(itemAvailable: false, (IQueueWaiter[])state);
		}

		private static void CompleteWaitersLater(bool itemAvailable, IQueueWaiter[] waiters)
		{
			if (itemAvailable)
			{
				if (completeWaitersTrueCallback == null)
				{
					completeWaitersTrueCallback = CompleteWaitersTrueCallback;
				}
				ActionItem.Schedule(completeWaitersTrueCallback, waiters);
			}
			else
			{
				if (completeWaitersFalseCallback == null)
				{
					completeWaitersFalseCallback = CompleteWaitersFalseCallback;
				}
				ActionItem.Schedule(completeWaitersFalseCallback, waiters);
			}
		}

		private static void CompleteWaitersTrueCallback(object state)
		{
			CompleteWaiters(itemAvailable: true, (IQueueWaiter[])state);
		}

		private static void InvokeDequeuedCallback(Action dequeuedCallback)
		{
			dequeuedCallback?.Invoke();
		}

		private static void InvokeDequeuedCallbackLater(Action dequeuedCallback)
		{
			if (dequeuedCallback != null)
			{
				if (onInvokeDequeuedCallback == null)
				{
					onInvokeDequeuedCallback = OnInvokeDequeuedCallback;
				}
				ActionItem.Schedule(onInvokeDequeuedCallback, dequeuedCallback);
			}
		}

		private static void OnDispatchCallback(object state)
		{
			((InputQueue<T>)state).Dispatch();
		}

		private static void OnInvokeDequeuedCallback(object state)
		{
			Action action = (Action)state;
			action();
		}

		private void EnqueueAndDispatch(Item item, bool canDispatchOnThisThread)
		{
			bool flag = false;
			IQueueReader queueReader = null;
			bool flag2 = false;
			IQueueWaiter[] waiters = null;
			bool itemAvailable = true;
			lock (ThisLock)
			{
				itemAvailable = queueState != QueueState.Closed && queueState != QueueState.Shutdown;
				GetWaiters(out waiters);
				if (queueState == QueueState.Open)
				{
					if (canDispatchOnThisThread)
					{
						if (readerQueue.Count == 0)
						{
							itemQueue.EnqueueAvailableItem(item);
						}
						else
						{
							queueReader = readerQueue.Dequeue();
						}
					}
					else if (readerQueue.Count == 0)
					{
						itemQueue.EnqueueAvailableItem(item);
					}
					else
					{
						itemQueue.EnqueuePendingItem(item);
						flag2 = true;
					}
				}
				else
				{
					flag = true;
				}
			}
			if (waiters != null)
			{
				if (canDispatchOnThisThread)
				{
					CompleteWaiters(itemAvailable, waiters);
				}
				else
				{
					CompleteWaitersLater(itemAvailable, waiters);
				}
			}
			if (queueReader != null)
			{
				InvokeDequeuedCallback(item.DequeuedCallback);
				queueReader.Set(item);
			}
			if (flag2)
			{
				if (onDispatchCallback == null)
				{
					onDispatchCallback = OnDispatchCallback;
				}
				ActionItem.Schedule(onDispatchCallback, this);
			}
			else if (flag)
			{
				InvokeDequeuedCallback(item.DequeuedCallback);
				DisposeItem(item);
			}
		}

		private bool EnqueueWithoutDispatch(Item item)
		{
			lock (ThisLock)
			{
				if (queueState != QueueState.Closed && queueState != QueueState.Shutdown)
				{
					if (readerQueue.Count == 0 && waiterList.Count == 0)
					{
						itemQueue.EnqueueAvailableItem(item);
						return false;
					}
					itemQueue.EnqueuePendingItem(item);
					return true;
				}
			}
			DisposeItem(item);
			InvokeDequeuedCallbackLater(item.DequeuedCallback);
			return false;
		}

		private void GetWaiters(out IQueueWaiter[] waiters)
		{
			if (waiterList.Count > 0)
			{
				waiters = waiterList.ToArray();
				waiterList.Clear();
			}
			else
			{
				waiters = null;
			}
		}

		private bool RemoveReader(IQueueReader reader)
		{
			lock (ThisLock)
			{
				if (queueState == QueueState.Open || queueState == QueueState.Shutdown)
				{
					bool result = false;
					for (int num = readerQueue.Count; num > 0; num--)
					{
						IQueueReader queueReader = readerQueue.Dequeue();
						if (queueReader == reader)
						{
							result = true;
						}
						else
						{
							readerQueue.Enqueue(queueReader);
						}
					}
					return result;
				}
			}
			return false;
		}
	}
	internal abstract class InternalBufferManager
	{
		private class PooledBufferManager : InternalBufferManager
		{
			private abstract class BufferPool
			{
				private class SynchronizedBufferPool : BufferPool
				{
					private SynchronizedPool<byte[]> innerPool;

					internal SynchronizedBufferPool(int bufferSize, int limit)
						: base(bufferSize, limit)
					{
						innerPool = new SynchronizedPool<byte[]>(limit);
					}

					internal override void OnClear()
					{
						innerPool.Clear();
					}

					internal override byte[] Take()
					{
						return innerPool.Take();
					}

					internal override bool Return(byte[] buffer)
					{
						return innerPool.Return(buffer);
					}
				}

				private class LargeBufferPool : BufferPool
				{
					private Stack<byte[]> items;

					private object ThisLock => items;

					internal LargeBufferPool(int bufferSize, int limit)
						: base(bufferSize, limit)
					{
						items = new Stack<byte[]>(limit);
					}

					internal override void OnClear()
					{
						lock (ThisLock)
						{
							items.Clear();
						}
					}

					internal override byte[] Take()
					{
						lock (ThisLock)
						{
							if (items.Count > 0)
							{
								return items.Pop();
							}
						}
						return null;
					}

					internal override bool Return(byte[] buffer)
					{
						lock (ThisLock)
						{
							if (items.Count < base.Limit)
							{
								items.Push(buffer);
								return true;
							}
						}
						return false;
					}
				}

				private int bufferSize;

				private int count;

				private int limit;

				private int misses;

				private int peak;

				public int BufferSize => bufferSize;

				public int Limit => limit;

				public int Misses
				{
					get
					{
						return misses;
					}
					set
					{
						misses = value;
					}
				}

				public int Peak => peak;

				public BufferPool(int bufferSize, int limit)
				{
					this.bufferSize = bufferSize;
					this.limit = limit;
				}

				public void Clear()
				{
					OnClear();
					count = 0;
				}

				public void DecrementCount()
				{
					int num = count - 1;
					if (num >= 0)
					{
						count = num;
					}
				}

				public void IncrementCount()
				{
					int num = count + 1;
					if (num <= limit)
					{
						count = num;
						if (num > peak)
						{
							peak = num;
						}
					}
				}

				internal abstract byte[] Take();

				internal abstract bool Return(byte[] buffer);

				internal abstract void OnClear();

				internal static BufferPool CreatePool(int bufferSize, int limit)
				{
					if (bufferSize < 85000)
					{
						return new SynchronizedBufferPool(bufferSize, limit);
					}
					return new LargeBufferPool(bufferSize, limit);
				}
			}

			private const int minBufferSize = 128;

			private const int maxMissesBeforeTuning = 8;

			private const int initialBufferCount = 1;

			private readonly object tuningLock;

			private int[] bufferSizes;

			private BufferPool[] bufferPools;

			private long memoryLimit;

			private long remainingMemory;

			private bool areQuotasBeingTuned;

			private int totalMisses;

			public PooledBufferManager(long maxMemoryToPool, int maxBufferSize)
			{
				tuningLock = new object();
				memoryLimit = maxMemoryToPool;
				remainingMemory = maxMemoryToPool;
				List<BufferPool> list = new List<BufferPool>();
				int num = 128;
				while (true)
				{
					long num2 = remainingMemory / num;
					int num3 = (int)((num2 > int.MaxValue) ? int.MaxValue : num2);
					if (num3 > 1)
					{
						num3 = 1;
					}
					list.Add(BufferPool.CreatePool(num, num3));
					remainingMemory -= (long)num3 * (long)num;
					if (num >= maxBufferSize)
					{
						break;
					}
					long num4 = (long)num * 2L;
					num = (int)((num4 <= maxBufferSize) ? num4 : maxBufferSize);
				}
				bufferPools = list.ToArray();
				bufferSizes = new int[bufferPools.Length];
				for (int i = 0; i < bufferPools.Length; i++)
				{
					bufferSizes[i] = bufferPools[i].BufferSize;
				}
			}

			public override void Clear()
			{
				for (int i = 0; i < bufferPools.Length; i++)
				{
					BufferPool bufferPool = bufferPools[i];
					bufferPool.Clear();
				}
			}

			private void ChangeQuota(ref BufferPool bufferPool, int delta)
			{
				if (TraceCore.BufferPoolChangeQuotaIsEnabled(Fx.Trace))
				{
					TraceCore.BufferPoolChangeQuota(Fx.Trace, bufferPool.BufferSize, delta);
				}
				BufferPool bufferPool2 = bufferPool;
				int num = bufferPool2.Limit + delta;
				BufferPool bufferPool3 = BufferPool.CreatePool(bufferPool2.BufferSize, num);
				for (int i = 0; i < num; i++)
				{
					byte[] array = bufferPool2.Take();
					if (array == null)
					{
						break;
					}
					bufferPool3.Return(array);
					bufferPool3.IncrementCount();
				}
				remainingMemory -= bufferPool2.BufferSize * delta;
				bufferPool = bufferPool3;
			}

			private void DecreaseQuota(ref BufferPool bufferPool)
			{
				ChangeQuota(ref bufferPool, -1);
			}

			private int FindMostExcessivePool()
			{
				long num = 0L;
				int result = -1;
				for (int i = 0; i < bufferPools.Length; i++)
				{
					BufferPool bufferPool = bufferPools[i];
					if (bufferPool.Peak < bufferPool.Limit)
					{
						long num2 = (long)(bufferPool.Limit - bufferPool.Peak) * (long)bufferPool.BufferSize;
						if (num2 > num)
						{
							result = i;
							num = num2;
						}
					}
				}
				return result;
			}

			private int FindMostStarvedPool()
			{
				long num = 0L;
				int result = -1;
				for (int i = 0; i < bufferPools.Length; i++)
				{
					BufferPool bufferPool = bufferPools[i];
					if (bufferPool.Peak == bufferPool.Limit)
					{
						long num2 = (long)bufferPool.Misses * (long)bufferPool.BufferSize;
						if (num2 > num)
						{
							result = i;
							num = num2;
						}
					}
				}
				return result;
			}

			private BufferPool FindPool(int desiredBufferSize)
			{
				for (int i = 0; i < bufferSizes.Length; i++)
				{
					if (desiredBufferSize <= bufferSizes[i])
					{
						return bufferPools[i];
					}
				}
				return null;
			}

			private void IncreaseQuota(ref BufferPool bufferPool)
			{
				ChangeQuota(ref bufferPool, 1);
			}

			public override void ReturnBuffer(byte[] buffer)
			{
				BufferPool bufferPool = FindPool(buffer.Length);
				if (bufferPool != null)
				{
					if (buffer.Length != bufferPool.BufferSize)
					{
						throw Fx.Exception.Argument("buffer", InternalSR.BufferIsNotRightSizeForBufferManager);
					}
					if (bufferPool.Return(buffer))
					{
						bufferPool.IncrementCount();
					}
				}
			}

			public override byte[] TakeBuffer(int bufferSize)
			{
				BufferPool bufferPool = FindPool(bufferSize);
				if (bufferPool != null)
				{
					byte[] array = bufferPool.Take();
					if (array != null)
					{
						bufferPool.DecrementCount();
						return array;
					}
					if (bufferPool.Peak == bufferPool.Limit)
					{
						bufferPool.Misses++;
						if (++totalMisses >= 8)
						{
							TuneQuotas();
						}
					}
					if (TraceCore.BufferPoolAllocationIsEnabled(Fx.Trace))
					{
						TraceCore.BufferPoolAllocation(Fx.Trace, bufferPool.BufferSize);
					}
					return Fx.AllocateByteArray(bufferPool.BufferSize);
				}
				if (TraceCore.BufferPoolAllocationIsEnabled(Fx.Trace))
				{
					TraceCore.BufferPoolAllocation(Fx.Trace, bufferSize);
				}
				return Fx.AllocateByteArray(bufferSize);
			}

			private void TuneQuotas()
			{
				if (areQuotasBeingTuned)
				{
					return;
				}
				bool lockTaken = false;
				try
				{
					Monitor.TryEnter(tuningLock, ref lockTaken);
					if (!lockTaken || areQuotasBeingTuned)
					{
						return;
					}
					areQuotasBeingTuned = true;
				}
				finally
				{
					if (lockTaken)
					{
						Monitor.Exit(tuningLock);
					}
				}
				int num = FindMostStarvedPool();
				if (num >= 0)
				{
					BufferPool bufferPool = bufferPools[num];
					if (remainingMemory < bufferPool.BufferSize)
					{
						int num2 = FindMostExcessivePool();
						if (num2 >= 0)
						{
							DecreaseQuota(ref bufferPools[num2]);
						}
					}
					if (remainingMemory >= bufferPool.BufferSize)
					{
						IncreaseQuota(ref bufferPools[num]);
					}
				}
				for (int i = 0; i < bufferPools.Length; i++)
				{
					BufferPool bufferPool2 = bufferPools[i];
					bufferPool2.Misses = 0;
				}
				totalMisses = 0;
				areQuotasBeingTuned = false;
			}
		}

		private class GCBufferManager : InternalBufferManager
		{
			private static GCBufferManager value = new GCBufferManager();

			public static GCBufferManager Value => value;

			private GCBufferManager()
			{
			}

			public override void Clear()
			{
			}

			public override byte[] TakeBuffer(int bufferSize)
			{
				return Fx.AllocateByteArray(bufferSize);
			}

			public override void ReturnBuffer(byte[] buffer)
			{
			}
		}

		public abstract byte[] TakeBuffer(int bufferSize);

		public abstract void ReturnBuffer(byte[] buffer);

		public abstract void Clear();

		public static InternalBufferManager Create(long maxBufferPoolSize, int maxBufferSize)
		{
			if (maxBufferPoolSize == 0L)
			{
				return GCBufferManager.Value;
			}
			return new PooledBufferManager(maxBufferPoolSize, maxBufferSize);
		}
	}
	internal class IOThreadCancellationTokenSource : IDisposable
	{
		private static readonly Action<object> onCancel = Fx.ThunkCallback<object>(OnCancel);

		private readonly TimeSpan timeout;

		private CancellationTokenSource source;

		private CancellationToken? token;

		private IOThreadTimer timer;

		public CancellationToken Token
		{
			get
			{
				if (!token.HasValue)
				{
					if (timeout >= TimeoutHelper.MaxWait)
					{
						token = CancellationToken.None;
					}
					else
					{
						timer = new IOThreadTimer(onCancel, this, isTypicallyCanceledShortlyAfterBeingSet: true);
						source = new CancellationTokenSource();
						timer.Set(timeout);
						token = source.Token;
					}
				}
				return token.Value;
			}
		}

		public IOThreadCancellationTokenSource(TimeSpan timeout)
		{
			TimeoutHelper.ThrowIfNegativeArgument(timeout);
			this.timeout = timeout;
		}

		public IOThreadCancellationTokenSource(int timeout)
			: this(TimeSpan.FromMilliseconds(timeout))
		{
		}

		public void Dispose()
		{
			if (source != null && timer.Cancel())
			{
				source.Dispose();
				source = null;
			}
		}

		private static void OnCancel(object obj)
		{
			IOThreadCancellationTokenSource iOThreadCancellationTokenSource = (IOThreadCancellationTokenSource)obj;
			iOThreadCancellationTokenSource.Cancel();
		}

		private void Cancel()
		{
			source.Cancel();
			source.Dispose();
			source = null;
		}
	}
	internal class IOThreadScheduler
	{
		private static class Bits
		{
			public const int HiShift = 16;

			public const int HiOne = 65536;

			public const int LoHiBit = 32768;

			public const int HiHiBit = int.MinValue;

			public const int LoCountMask = 32767;

			public const int HiCountMask = 2147418112;

			public const int LoMask = 65535;

			public const int HiMask = -65536;

			public const int HiBits = -2147450880;

			public static int Count(int slot)
			{
				return (((slot >> 16) - slot + 2) & 0xFFFF) - 1;
			}

			public static int CountNoIdle(int slot)
			{
				return ((slot >> 16) - slot + 1) & 0xFFFF;
			}

			public static int IncrementLo(int slot)
			{
				return ((slot + 1) & 0xFFFF) | (slot & -65536);
			}

			public static bool IsComplete(int gate)
			{
				return (gate & -65536) == gate << 16;
			}
		}

		private struct Slot
		{
			private int gate;

			private Action<object> callback;

			private object state;

			public bool TryEnqueueWorkItem(Action<object> callback, object state, out bool wrapped)
			{
				int num = Interlocked.Increment(ref gate);
				wrapped = (num & 0x7FFF) != 1;
				if (wrapped)
				{
					if (((uint)num & 0x8000u) != 0 && Bits.IsComplete(num))
					{
						Interlocked.CompareExchange(ref gate, 0, num);
					}
					return false;
				}
				this.state = state;
				this.callback = callback;
				num = Interlocked.Add(ref gate, 32768);
				if ((num & 0x7FFF0000) == 0)
				{
					return true;
				}
				this.state = null;
				this.callback = null;
				if (num >> 16 != (num & 0x7FFF) || Interlocked.CompareExchange(ref gate, 0, num) != num)
				{
					num = Interlocked.Add(ref gate, int.MinValue);
					if (Bits.IsComplete(num))
					{
						Interlocked.CompareExchange(ref gate, 0, num);
					}
				}
				return false;
			}

			public void DequeueWorkItem(out Action<object> callback, out object state)
			{
				int num = Interlocked.Add(ref gate, 65536);
				if ((num & 0x8000) == 0)
				{
					callback = null;
					state = null;
				}
				else if ((num & 0x7FFF0000) == 65536)
				{
					callback = this.callback;
					state = this.state;
					this.state = null;
					this.callback = null;
					if ((num & 0x7FFF) != 1 || Interlocked.CompareExchange(ref gate, 0, num) != num)
					{
						num = Interlocked.Add(ref gate, int.MinValue);
						if (Bits.IsComplete(num))
						{
							Interlocked.CompareExchange(ref gate, 0, num);
						}
					}
				}
				else
				{
					callback = null;
					state = null;
					if (Bits.IsComplete(num))
					{
						Interlocked.CompareExchange(ref gate, 0, num);
					}
				}
			}
		}

		[SecurityCritical]
		private class ScheduledOverlapped
		{
			private unsafe readonly NativeOverlapped* nativeOverlapped;

			private IOThreadScheduler scheduler;

			public unsafe ScheduledOverlapped()
			{
				nativeOverlapped = new Overlapped().UnsafePack(Fx.ThunkCallback(IOCallback), null);
			}

			private unsafe void IOCallback(uint errorCode, uint numBytes, NativeOverlapped* nativeOverlapped)
			{
				IOThreadScheduler iOThreadScheduler = scheduler;
				scheduler = null;
				Action<object> callback;
				object state;
				try
				{
				}
				finally
				{
					iOThreadScheduler.CompletionCallback(out callback, out state);
				}
				bool flag = true;
				while (flag)
				{
					callback?.Invoke(state);
					try
					{
					}
					finally
					{
						flag = iOThreadScheduler.TryCoalesce(out callback, out state);
					}
				}
			}

			public unsafe void Post(IOThreadScheduler iots)
			{
				scheduler = iots;
				ThreadPool.UnsafeQueueNativeOverlapped(nativeOverlapped);
			}

			public unsafe void Cleanup()
			{
				if (scheduler != null)
				{
					throw Fx.AssertAndThrowFatal("Cleanup called on an overlapped that is in-flight.");
				}
				Overlapped.Free(nativeOverlapped);
			}
		}

		private const int MaximumCapacity = 32768;

		private static IOThreadScheduler current = new IOThreadScheduler(32, 32);

		private readonly ScheduledOverlapped overlapped;

		[SecurityCritical]
		private readonly Slot[] slots;

		[SecurityCritical]
		private readonly Slot[] slotsLowPri;

		private int headTail = -131072;

		private int headTailLowPri = -65536;

		private int SlotMask
		{
			[SecurityCritical]
			get
			{
				return slots.Length - 1;
			}
		}

		private int SlotMaskLowPri
		{
			[SecurityCritical]
			get
			{
				return slotsLowPri.Length - 1;
			}
		}

		[SecuritySafeCritical]
		private IOThreadScheduler(int capacity, int capacityLowPri)
		{
			slots = new Slot[capacity];
			slotsLowPri = new Slot[capacityLowPri];
			overlapped = new ScheduledOverlapped();
		}

		[SecurityCritical]
		public static void ScheduleCallbackNoFlow(Action<object> callback, object state)
		{
			if (callback == null)
			{
				throw Fx.Exception.ArgumentNull("callback");
			}
			bool flag = false;
			while (!flag)
			{
				try
				{
				}
				finally
				{
					flag = current.ScheduleCallbackHelper(callback, state);
				}
			}
		}

		[SecurityCritical]
		public static void ScheduleCallbackLowPriNoFlow(Action<object> callback, object state)
		{
			if (callback == null)
			{
				throw Fx.Exception.ArgumentNull("callback");
			}
			bool flag = false;
			while (!flag)
			{
				try
				{
				}
				finally
				{
					flag = current.ScheduleCallbackLowPriHelper(callback, state);
				}
			}
		}

		[SecurityCritical]
		private bool ScheduleCallbackHelper(Action<object> callback, object state)
		{
			int num = Interlocked.Add(ref headTail, 65536);
			bool flag = Bits.Count(num) == 0;
			if (flag)
			{
				num = Interlocked.Add(ref headTail, 65536);
			}
			if (Bits.Count(num) == -1)
			{
				throw Fx.AssertAndThrowFatal("Head/Tail overflow!");
			}
			bool wrapped;
			bool result = slots[(num >> 16) & SlotMask].TryEnqueueWorkItem(callback, state, out wrapped);
			if (wrapped)
			{
				IOThreadScheduler value = new IOThreadScheduler(Math.Min(slots.Length * 2, 32768), slotsLowPri.Length);
				Interlocked.CompareExchange(ref current, value, this);
			}
			if (flag)
			{
				overlapped.Post(this);
			}
			return result;
		}

		[SecurityCritical]
		private bool ScheduleCallbackLowPriHelper(Action<object> callback, object state)
		{
			int num = Interlocked.Add(ref headTailLowPri, 65536);
			bool flag = false;
			if (Bits.CountNoIdle(num) == 1)
			{
				int num2 = headTail;
				if (Bits.Count(num2) == -1)
				{
					int num3 = Interlocked.CompareExchange(ref headTail, num2 + 65536, num2);
					if (num2 == num3)
					{
						flag = true;
					}
				}
			}
			if (Bits.CountNoIdle(num) == 0)
			{
				throw Fx.AssertAndThrowFatal("Low-priority Head/Tail overflow!");
			}
			bool wrapped;
			bool result = slotsLowPri[(num >> 16) & SlotMaskLowPri].TryEnqueueWorkItem(callback, state, out wrapped);
			if (wrapped)
			{
				IOThreadScheduler value = new IOThreadScheduler(slots.Length, Math.Min(slotsLowPri.Length * 2, 32768));
				Interlocked.CompareExchange(ref current, value, this);
			}
			if (flag)
			{
				overlapped.Post(this);
			}
			return result;
		}

		[SecurityCritical]
		private void CompletionCallback(out Action<object> callback, out object state)
		{
			int num = headTail;
			while (true)
			{
				bool flag = Bits.Count(num) == 0;
				if (flag)
				{
					int num2 = headTailLowPri;
					while (Bits.CountNoIdle(num2) != 0)
					{
						if (num2 == (num2 = Interlocked.CompareExchange(ref headTailLowPri, Bits.IncrementLo(num2), num2)))
						{
							overlapped.Post(this);
							slotsLowPri[num2 & SlotMaskLowPri].DequeueWorkItem(out callback, out state);
							return;
						}
					}
				}
				if (num == (num = Interlocked.CompareExchange(ref headTail, Bits.IncrementLo(num), num)))
				{
					if (!flag)
					{
						overlapped.Post(this);
						slots[num & SlotMask].DequeueWorkItem(out callback, out state);
						return;
					}
					int num2 = headTailLowPri;
					if (Bits.CountNoIdle(num2) == 0)
					{
						break;
					}
					num = Bits.IncrementLo(num);
					if (num != Interlocked.CompareExchange(ref headTail, num + 65536, num))
					{
						break;
					}
					num += 65536;
				}
			}
			callback = null;
			state = null;
		}

		[SecurityCritical]
		private bool TryCoalesce(out Action<object> callback, out object state)
		{
			int num = headTail;
			while (true)
			{
				if (Bits.Count(num) > 0)
				{
					if (num == (num = Interlocked.CompareExchange(ref headTail, Bits.IncrementLo(num), num)))
					{
						slots[num & SlotMask].DequeueWorkItem(out callback, out state);
						return true;
					}
					continue;
				}
				int num2 = headTailLowPri;
				if (Bits.CountNoIdle(num2) <= 0)
				{
					break;
				}
				if (num2 == (num2 = Interlocked.CompareExchange(ref headTailLowPri, Bits.IncrementLo(num2), num2)))
				{
					slotsLowPri[num2 & SlotMaskLowPri].DequeueWorkItem(out callback, out state);
					return true;
				}
				num = headTail;
			}
			callback = null;
			state = null;
			return false;
		}

		~IOThreadScheduler()
		{
			if (!Environment.HasShutdownStarted && !AppDomain.CurrentDomain.IsFinalizingForUnload())
			{
				Cleanup();
			}
		}

		[SecuritySafeCritical]
		private void Cleanup()
		{
			if (overlapped != null)
			{
				overlapped.Cleanup();
			}
		}
	}
	internal class IOThreadTimer
	{
		private class TimerManager
		{
			private const long maxTimeToWaitForMoreTimers = 10000000L;

			private static TimerManager value = new TimerManager();

			private Action<object> onWaitCallback;

			private TimerGroup stableTimerGroup;

			private TimerGroup volatileTimerGroup;

			private WaitableTimer[] waitableTimers;

			private bool waitScheduled;

			private object ThisLock => this;

			public static TimerManager Value => value;

			public TimerGroup StableTimerGroup => stableTimerGroup;

			public TimerGroup VolatileTimerGroup => volatileTimerGroup;

			public TimerManager()
			{
				onWaitCallback = OnWaitCallback;
				stableTimerGroup = new TimerGroup();
				volatileTimerGroup = new TimerGroup();
				waitableTimers = new WaitableTimer[2] { stableTimerGroup.WaitableTimer, volatileTimerGroup.WaitableTimer };
			}

			public void Set(IOThreadTimer timer, long dueTime)
			{
				long num = dueTime - timer.dueTime;
				if (num < 0)
				{
					num = -num;
				}
				if (num <= timer.maxSkew)
				{
					return;
				}
				lock (ThisLock)
				{
					TimerGroup timerGroup = timer.timerGroup;
					TimerQueue timerQueue = timerGroup.TimerQueue;
					if (timer.index > 0)
					{
						if (timerQueue.UpdateTimer(timer, dueTime))
						{
							UpdateWaitableTimer(timerGroup);
						}
					}
					else if (timerQueue.InsertTimer(timer, dueTime))
					{
						UpdateWaitableTimer(timerGroup);
						if (timerQueue.Count == 1)
						{
							EnsureWaitScheduled();
						}
					}
				}
			}

			public bool Cancel(IOThreadTimer timer)
			{
				lock (ThisLock)
				{
					if (timer.index > 0)
					{
						TimerGroup timerGroup = timer.timerGroup;
						TimerQueue timerQueue = timerGroup.TimerQueue;
						timerQueue.DeleteTimer(timer);
						if (timerQueue.Count > 0)
						{
							UpdateWaitableTimer(timerGroup);
						}
						else
						{
							TimerGroup otherTimerGroup = GetOtherTimerGroup(timerGroup);
							if (otherTimerGroup.TimerQueue.Count == 0)
							{
								long now = Ticks.Now;
								long num = timerGroup.WaitableTimer.DueTime - now;
								long num2 = otherTimerGroup.WaitableTimer.DueTime - now;
								if (num > 10000000 && num2 > 10000000)
								{
									timerGroup.WaitableTimer.Set(Ticks.Add(now, 10000000L));
								}
							}
						}
						return true;
					}
					return false;
				}
			}

			private void EnsureWaitScheduled()
			{
				if (!waitScheduled)
				{
					ScheduleWait();
				}
			}

			private TimerGroup GetOtherTimerGroup(TimerGroup timerGroup)
			{
				if (timerGroup == volatileTimerGroup)
				{
					return stableTimerGroup;
				}
				return volatileTimerGroup;
			}

			private void OnWaitCallback(object state)
			{
				WaitHandle[] waitHandles = waitableTimers;
				WaitHandle.WaitAny(waitHandles);
				long now = Ticks.Now;
				lock (ThisLock)
				{
					waitScheduled = false;
					ScheduleElapsedTimers(now);
					ReactivateWaitableTimers();
					ScheduleWaitIfAnyTimersLeft();
				}
			}

			private void ReactivateWaitableTimers()
			{
				ReactivateWaitableTimer(stableTimerGroup);
				ReactivateWaitableTimer(volatileTimerGroup);
			}

			private void ReactivateWaitableTimer(TimerGroup timerGroup)
			{
				TimerQueue timerQueue = timerGroup.TimerQueue;
				if (timerQueue.Count > 0)
				{
					timerGroup.WaitableTimer.Set(timerQueue.MinTimer.dueTime);
				}
				else
				{
					timerGroup.WaitableTimer.Set(long.MaxValue);
				}
			}

			private void ScheduleElapsedTimers(long now)
			{
				ScheduleElapsedTimers(stableTimerGroup, now);
				ScheduleElapsedTimers(volatileTimerGroup, now);
			}

			private void ScheduleElapsedTimers(TimerGroup timerGroup, long now)
			{
				TimerQueue timerQueue = timerGroup.TimerQueue;
				while (timerQueue.Count > 0)
				{
					IOThreadTimer minTimer = timerQueue.MinTimer;
					long num = minTimer.dueTime - now;
					if (num <= minTimer.maxSkew)
					{
						timerQueue.DeleteMinTimer();
						ActionItem.Schedule(minTimer.callback, minTimer.callbackState);
						continue;
					}
					break;
				}
			}

			private void ScheduleWait()
			{
				ActionItem.Schedule(onWaitCallback, null);
				waitScheduled = true;
			}

			private void ScheduleWaitIfAnyTimersLeft()
			{
				if (stableTimerGroup.TimerQueue.Count > 0 || volatileTimerGroup.TimerQueue.Count > 0)
				{
					ScheduleWait();
				}
			}

			private void UpdateWaitableTimer(TimerGroup timerGroup)
			{
				WaitableTimer waitableTimer = timerGroup.WaitableTimer;
				IOThreadTimer minTimer = timerGroup.TimerQueue.MinTimer;
				long num = waitableTimer.DueTime - minTimer.dueTime;
				if (num < 0)
				{
					num = -num;
				}
				if (num > minTimer.maxSkew)
				{
					waitableTimer.Set(minTimer.dueTime);
				}
			}
		}

		private class TimerGroup
		{
			private TimerQueue timerQueue;

			private WaitableTimer waitableTimer;

			public TimerQueue TimerQueue => timerQueue;

			public WaitableTimer WaitableTimer => waitableTimer;

			public TimerGroup()
			{
				waitableTimer = new WaitableTimer();
				waitableTimer.Set(long.MaxValue);
				timerQueue = new TimerQueue();
			}
		}

		private class TimerQueue
		{
			private int count;

			private IOThreadTimer[] timers;

			public int Count => count;

			public IOThreadTimer MinTimer => timers[1];

			public TimerQueue()
			{
				timers = new IOThreadTimer[4];
			}

			public void DeleteMinTimer()
			{
				IOThreadTimer minTimer = MinTimer;
				DeleteMinTimerCore();
				minTimer.index = 0;
				minTimer.dueTime = 0L;
			}

			public void DeleteTimer(IOThreadTimer timer)
			{
				int num = timer.index;
				IOThreadTimer[] array = timers;
				while (true)
				{
					int num2 = num / 2;
					if (num2 < 1)
					{
						break;
					}
					(array[num] = array[num2]).index = num;
					num = num2;
				}
				timer.index = 0;
				timer.dueTime = 0L;
				array[1] = null;
				DeleteMinTimerCore();
			}

			public bool InsertTimer(IOThreadTimer timer, long dueTime)
			{
				IOThreadTimer[] array = timers;
				int num = count + 1;
				if (num == array.Length)
				{
					array = new IOThreadTimer[array.Length * 2];
					Array.Copy(timers, array, timers.Length);
					timers = array;
				}
				count = num;
				if (num > 1)
				{
					while (true)
					{
						int num2 = num / 2;
						if (num2 == 0)
						{
							break;
						}
						IOThreadTimer iOThreadTimer = array[num2];
						if (iOThreadTimer.dueTime <= dueTime)
						{
							break;
						}
						array[num] = iOThreadTimer;
						iOThreadTimer.index = num;
						num = num2;
					}
				}
				array[num] = timer;
				timer.index = num;
				timer.dueTime = dueTime;
				return num == 1;
			}

			public bool UpdateTimer(IOThreadTimer timer, long dueTime)
			{
				int index = timer.index;
				IOThreadTimer[] array = timers;
				int num = count;
				int num2 = index / 2;
				if (num2 == 0 || array[num2].dueTime <= dueTime)
				{
					int num3 = index * 2;
					if (num3 > num || array[num3].dueTime >= dueTime)
					{
						int num4 = num3 + 1;
						if (num4 > num || array[num4].dueTime >= dueTime)
						{
							timer.dueTime = dueTime;
							return index == 1;
						}
					}
				}
				DeleteTimer(timer);
				InsertTimer(timer, dueTime);
				return true;
			}

			private void DeleteMinTimerCore()
			{
				int num = count;
				if (num == 1)
				{
					count = 0;
					timers[1] = null;
					return;
				}
				IOThreadTimer[] array = timers;
				IOThreadTimer iOThreadTimer = array[num];
				num = (count = num - 1);
				int num2 = 1;
				int num3;
				do
				{
					num3 = num2 * 2;
					if (num3 > num)
					{
						break;
					}
					IOThreadTimer iOThreadTimer4;
					int num5;
					if (num3 < num)
					{
						IOThreadTimer iOThreadTimer2 = array[num3];
						int num4 = num3 + 1;
						IOThreadTimer iOThreadTimer3 = array[num4];
						if (iOThreadTimer3.dueTime < iOThreadTimer2.dueTime)
						{
							iOThreadTimer4 = iOThreadTimer3;
							num5 = num4;
						}
						else
						{
							iOThreadTimer4 = iOThreadTimer2;
							num5 = num3;
						}
					}
					else
					{
						num5 = num3;
						iOThreadTimer4 = array[num5];
					}
					if (iOThreadTimer.dueTime <= iOThreadTimer4.dueTime)
					{
						break;
					}
					array[num2] = iOThreadTimer4;
					iOThreadTimer4.index = num2;
					num2 = num5;
				}
				while (num3 < num);
				array[num2] = iOThreadTimer;
				iOThreadTimer.index = num2;
				array[num + 1] = null;
			}
		}

		private class WaitableTimer : WaitHandle
		{
			[SecurityCritical]
			private static class TimerHelper
			{
				public static SafeWaitHandle CreateWaitableTimer()
				{
					SafeWaitHandle safeWaitHandle = UnsafeNativeMethods.CreateWaitableTimer(IntPtr.Zero, manualReset: false, null);
					if (safeWaitHandle.IsInvalid)
					{
						Exception exception = new Win32Exception();
						safeWaitHandle.SetHandleAsInvalid();
						throw Fx.Exception.AsError(exception);
					}
					return safeWaitHandle;
				}

				public static long Set(SafeWaitHandle timer, long dueTime)
				{
					if (!UnsafeNativeMethods.SetWaitableTimer(timer, ref dueTime, 0, IntPtr.Zero, IntPtr.Zero, resume: false))
					{
						throw Fx.Exception.AsError(new Win32Exception());
					}
					return dueTime;
				}
			}

			private long dueTime;

			public long DueTime => dueTime;

			[SecuritySafeCritical]
			public WaitableTimer()
			{
				base.SafeWaitHandle = TimerHelper.CreateWaitableTimer();
			}

			[SecuritySafeCritical]
			public void Set(long dueTime)
			{
				this.dueTime = TimerHelper.Set(base.SafeWaitHandle, dueTime);
			}
		}

		private const int maxSkewInMillisecondsDefault = 100;

		private static long systemTimeResolutionTicks = -1L;

		private Action<object> callback;

		private object callbackState;

		private long dueTime;

		private int index;

		private long maxSkew;

		private TimerGroup timerGroup;

		public static long SystemTimeResolutionTicks
		{
			get
			{
				if (systemTimeResolutionTicks == -1)
				{
					systemTimeResolutionTicks = GetSystemTimeResolution();
				}
				return systemTimeResolutionTicks;
			}
		}

		public IOThreadTimer(Action<object> callback, object callbackState, bool isTypicallyCanceledShortlyAfterBeingSet)
			: this(callback, callbackState, isTypicallyCanceledShortlyAfterBeingSet, 100)
		{
		}

		public IOThreadTimer(Action<object> callback, object callbackState, bool isTypicallyCanceledShortlyAfterBeingSet, int maxSkewInMilliseconds)
		{
			this.callback = callback;
			this.callbackState = callbackState;
			maxSkew = Ticks.FromMilliseconds(maxSkewInMilliseconds);
			timerGroup = (isTypicallyCanceledShortlyAfterBeingSet ? TimerManager.Value.VolatileTimerGroup : TimerManager.Value.StableTimerGroup);
		}

		[SecuritySafeCritical]
		private static long GetSystemTimeResolution()
		{
			if (UnsafeNativeMethods.GetSystemTimeAdjustment(out var _, out var increment, out var _) != 0)
			{
				return increment;
			}
			return 150000L;
		}

		public bool Cancel()
		{
			return TimerManager.Value.Cancel(this);
		}

		public void Set(TimeSpan timeFromNow)
		{
			if (timeFromNow != TimeSpan.MaxValue)
			{
				SetAt(Ticks.Add(Ticks.Now, Ticks.FromTimeSpan(timeFromNow)));
			}
		}

		public void Set(int millisecondsFromNow)
		{
			SetAt(Ticks.Add(Ticks.Now, Ticks.FromMilliseconds(millisecondsFromNow)));
		}

		public void SetAt(long dueTime)
		{
			TimerManager.Value.Set(this, dueTime);
		}
	}
	internal class NameGenerator
	{
		private static NameGenerator nameGenerator = new NameGenerator();

		private long id;

		private string prefix;

		private NameGenerator()
		{
			prefix = "_" + Guid.NewGuid().ToString().Replace('-', '_') + "_";
		}

		public static string Next()
		{
			return string.Concat(str1: Interlocked.Increment(ref nameGenerator.id).ToString(CultureInfo.InvariantCulture), str0: nameGenerator.prefix);
		}
	}
	internal static class PartialTrustHelpers
	{
		[SecurityCritical]
		private static Type aptca;

		[SecurityCritical]
		private static volatile bool checkedForFullTrust;

		[SecurityCritical]
		private static bool inFullTrust;

		internal static bool ShouldFlowSecurityContext
		{
			[SecurityCritical]
			get
			{
				return SecurityManager.CurrentThreadRequiresSecurityContextCapture();
			}
		}

		internal static bool AppDomainFullyTrusted
		{
			[SecuritySafeCritical]
			get
			{
				if (!checkedForFullTrust)
				{
					inFullTrust = AppDomain.CurrentDomain.IsFullyTrusted;
					checkedForFullTrust = true;
				}
				return inFullTrust;
			}
		}

		[SecurityCritical]
		internal static bool IsInFullTrust()
		{
			if (!SecurityManager.CurrentThreadRequiresSecurityContextCapture())
			{
				return true;
			}
			try
			{
				DemandForFullTrust();
				return true;
			}
			catch (SecurityException)
			{
				return false;
			}
		}

		[SecurityCritical]
		internal static SecurityContext CaptureSecurityContextNoIdentityFlow()
		{
			if (SecurityContext.IsWindowsIdentityFlowSuppressed())
			{
				return SecurityContext.Capture();
			}
			using (SecurityContext.SuppressFlowWindowsIdentity())
			{
				return SecurityContext.Capture();
			}
		}

		[SecurityCritical]
		internal static bool IsTypeAptca(Type type)
		{
			Assembly assembly = type.Assembly;
			if (!IsAssemblyAptca(assembly))
			{
				return !IsAssemblySigned(assembly);
			}
			return true;
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[SecuritySafeCritical]
		[PermissionSet(SecurityAction.Demand, Unrestricted = true)]
		internal static void DemandForFullTrust()
		{
		}

		[SecurityCritical]
		private static bool IsAssemblyAptca(Assembly assembly)
		{
			if (aptca == null)
			{
				aptca = typeof(AllowPartiallyTrustedCallersAttribute);
			}
			return assembly.GetCustomAttributes(aptca, inherit: false).Length != 0;
		}

		[SecurityCritical]
		[FileIOPermission(SecurityAction.Assert, Unrestricted = true)]
		private static bool IsAssemblySigned(Assembly assembly)
		{
			byte[] publicKeyToken = assembly.GetName().GetPublicKeyToken();
			return (publicKeyToken != null) & (publicKeyToken.Length != 0);
		}

		[SecurityCritical]
		internal static bool CheckAppDomainPermissions(PermissionSet permissions)
		{
			if (AppDomain.CurrentDomain.IsHomogenous)
			{
				return permissions.IsSubsetOf(AppDomain.CurrentDomain.PermissionSet);
			}
			return false;
		}

		[SecurityCritical]
		internal static bool HasEtwPermissions()
		{
			PermissionSet permissions = new PermissionSet(PermissionState.Unrestricted);
			return CheckAppDomainPermissions(permissions);
		}
	}
	internal class MruCache<TKey, TValue> where TKey : class where TValue : class
	{
		private struct CacheEntry
		{
			internal TValue value;

			internal LinkedListNode<TKey> node;
		}

		private LinkedList<TKey> mruList;

		private Dictionary<TKey, CacheEntry> items;

		private int lowWatermark;

		private int highWatermark;

		private CacheEntry mruEntry;

		public int Count => items.Count;

		public MruCache(int watermark)
			: this(watermark * 4 / 5, watermark)
		{
		}

		public MruCache(int lowWatermark, int highWatermark)
			: this(lowWatermark, highWatermark, (IEqualityComparer<TKey>)null)
		{
		}

		public MruCache(int lowWatermark, int highWatermark, IEqualityComparer<TKey> comparer)
		{
			this.lowWatermark = lowWatermark;
			this.highWatermark = highWatermark;
			mruList = new LinkedList<TKey>();
			if (comparer == null)
			{
				items = new Dictionary<TKey, CacheEntry>();
			}
			else
			{
				items = new Dictionary<TKey, CacheEntry>(comparer);
			}
		}

		public void Add(TKey key, TValue value)
		{
			bool flag = false;
			try
			{
				if (items.Count == highWatermark)
				{
					int num = highWatermark - lowWatermark;
					for (int i = 0; i < num; i++)
					{
						TKey value2 = mruList.Last.Value;
						mruList.RemoveLast();
						TValue value3 = items[value2].value;
						items.Remove(value2);
						OnSingleItemRemoved(value3);
						OnItemAgedOutOfCache(value3);
					}
				}
				CacheEntry value4 = default(CacheEntry);
				value4.node = mruList.AddFirst(key);
				value4.value = value;
				items.Add(key, value4);
				mruEntry = value4;
				flag = true;
			}
			finally
			{
				if (!flag)
				{
					Clear();
				}
			}
		}

		public void Clear()
		{
			mruList.Clear();
			items.Clear();
			mruEntry.value = null;
			mruEntry.node = null;
		}

		public bool Remove(TKey key)
		{
			if (items.TryGetValue(key, out var value))
			{
				items.Remove(key);
				OnSingleItemRemoved(value.value);
				mruList.Remove(value.node);
				if (mruEntry.node == value.node)
				{
					mruEntry.value = null;
					mruEntry.node = null;
				}
				return true;
			}
			return false;
		}

		protected virtual void OnSingleItemRemoved(TValue item)
		{
		}

		protected virtual void OnItemAgedOutOfCache(TValue item)
		{
		}

		public bool TryGetValue(TKey key, out TValue value)
		{
			if (mruEntry.node != null && key != null && key.Equals(mruEntry.node.Value))
			{
				value = mruEntry.value;
				return true;
			}
			CacheEntry value2;
			bool flag = items.TryGetValue(key, out value2);
			value = value2.value;
			if (flag && mruList.Count > 1 && mruList.First != value2.node)
			{
				mruList.Remove(value2.node);
				mruList.AddFirst(value2.node);
				mruEntry = value2;
			}
			return flag;
		}
	}
	[Serializable]
	internal class ReadOnlyDictionaryInternal<TKey, TValue> : IDictionary<TKey, TValue>, ICollection<KeyValuePair<TKey, TValue>>, IEnumerable<KeyValuePair<TKey, TValue>>, IEnumerable
	{
		private IDictionary<TKey, TValue> dictionary;

		public int Count => dictionary.Count;

		public bool IsReadOnly => true;

		public ICollection<TKey> Keys => dictionary.Keys;

		public ICollection<TValue> Values => dictionary.Values;

		public TValue this[TKey key]
		{
			get
			{
				return dictionary[key];
			}
			set
			{
				throw Fx.Exception.AsError(CreateReadOnlyException());
			}
		}

		public ReadOnlyDictionaryInternal(IDictionary<TKey, TValue> dictionary)
		{
			this.dictionary = dictionary;
		}

		public static IDictionary<TKey, TValue> Create(IDictionary<TKey, TValue> dictionary)
		{
			if (dictionary.IsReadOnly)
			{
				return dictionary;
			}
			return new ReadOnlyDictionaryInternal<TKey, TValue>(dictionary);
		}

		private Exception CreateReadOnlyException()
		{
			return new InvalidOperationException(InternalSR.DictionaryIsReadOnly);
		}

		public void Add(TKey key, TValue value)
		{
			throw Fx.Exception.AsError(CreateReadOnlyException());
		}

		public void Add(KeyValuePair<TKey, TValue> item)
		{
			throw Fx.Exception.AsError(CreateReadOnlyException());
		}

		public void Clear()
		{
			throw Fx.Exception.AsError(CreateReadOnlyException());
		}

		public bool Contains(KeyValuePair<TKey, TValue> item)
		{
			return dictionary.Contains(item);
		}

		public bool ContainsKey(TKey key)
		{
			return dictionary.ContainsKey(key);
		}

		public void CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
		{
			dictionary.CopyTo(array, arrayIndex);
		}

		public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
		{
			return dictionary.GetEnumerator();
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}

		public bool Remove(TKey key)
		{
			throw Fx.Exception.AsError(CreateReadOnlyException());
		}

		public bool Remove(KeyValuePair<TKey, TValue> item)
		{
			throw Fx.Exception.AsError(CreateReadOnlyException());
		}

		public bool TryGetValue(TKey key, out TValue value)
		{
			return dictionary.TryGetValue(key, out value);
		}
	}
	internal class ReadOnlyKeyedCollection<TKey, TValue> : ReadOnlyCollection<TValue>
	{
		private KeyedCollection<TKey, TValue> innerCollection;

		public TValue this[TKey key] => innerCollection[key];

		public ReadOnlyKeyedCollection(KeyedCollection<TKey, TValue> innerCollection)
			: base((IList<TValue>)innerCollection)
		{
			this.innerCollection = innerCollection;
		}
	}
	internal abstract class ScheduleActionItemAsyncResult : AsyncResult
	{
		private static Action<object> doWork = DoWork;

		protected ScheduleActionItemAsyncResult(AsyncCallback callback, object state)
			: base(callback, state)
		{
		}

		protected void Schedule()
		{
			ActionItem.Schedule(doWork, this);
		}

		private static void DoWork(object state)
		{
			ScheduleActionItemAsyncResult scheduleActionItemAsyncResult = (ScheduleActionItemAsyncResult)state;
			Exception ex = null;
			try
			{
				scheduleActionItemAsyncResult.OnDoWork();
			}
			catch (Exception ex2)
			{
				if (Fx.IsFatal(ex2))
				{
					throw;
				}
				ex = ex2;
			}
			scheduleActionItemAsyncResult.Complete(completedSynchronously: false, ex);
		}

		protected abstract void OnDoWork();

		public static void End(IAsyncResult result)
		{
			AsyncResult.End<ScheduleActionItemAsyncResult>(result);
		}
	}
	internal class SignalGate
	{
		private static class GateState
		{
			public const int Locked = 0;

			public const int SignalPending = 1;

			public const int Unlocked = 2;

			public const int Signalled = 3;
		}

		private int state;

		internal bool IsLocked => state == 0;

		internal bool IsSignalled => state == 3;

		public bool Signal()
		{
			int num = state;
			if (num == 0)
			{
				num = Interlocked.CompareExchange(ref state, 1, 0);
			}
			switch (num)
			{
			case 2:
				state = 3;
				return true;
			default:
				ThrowInvalidSignalGateState();
				break;
			case 0:
				break;
			}
			return false;
		}

		public bool Unlock()
		{
			int num = state;
			if (num == 0)
			{
				num = Interlocked.CompareExchange(ref state, 2, 0);
			}
			switch (num)
			{
			case 1:
				state = 3;
				return true;
			default:
				ThrowInvalidSignalGateState();
				break;
			case 0:
				break;
			}
			return false;
		}

		private void ThrowInvalidSignalGateState()
		{
			throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.InvalidSemaphoreExit));
		}
	}
	internal class SignalGate<T> : SignalGate
	{
		private T result;

		public bool Signal(T result)
		{
			this.result = result;
			return Signal();
		}

		public bool Unlock(out T result)
		{
			if (Unlock())
			{
				result = this.result;
				return true;
			}
			result = default(T);
			return false;
		}
	}
	internal class SynchronizedPool<T> where T : class
	{
		private struct Entry
		{
			public int threadID;

			public T value;
		}

		private struct PendingEntry
		{
			public int returnCount;

			public int threadID;
		}

		private static class SynchronizedPoolHelper
		{
			public static readonly int ProcessorCount = GetProcessorCount();

			[SecuritySafeCritical]
			[EnvironmentPermission(SecurityAction.Assert, Read = "NUMBER_OF_PROCESSORS")]
			private static int GetProcessorCount()
			{
				return Environment.ProcessorCount;
			}
		}

		private class GlobalPool
		{
			private Stack<T> items;

			private int maxCount;

			public int MaxCount
			{
				get
				{
					return maxCount;
				}
				set
				{
					lock (ThisLock)
					{
						while (items.Count > value)
						{
							items.Pop();
						}
						maxCount = value;
					}
				}
			}

			private object ThisLock => this;

			public GlobalPool(int maxCount)
			{
				items = new Stack<T>();
				this.maxCount = maxCount;
			}

			public void DecrementMaxCount()
			{
				lock (ThisLock)
				{
					if (items.Count == maxCount)
					{
						items.Pop();
					}
					maxCount--;
				}
			}

			public T Take()
			{
				if (items.Count > 0)
				{
					lock (ThisLock)
					{
						if (items.Count > 0)
						{
							return items.Pop();
						}
					}
				}
				return null;
			}

			public bool Return(T value)
			{
				if (items.Count < MaxCount)
				{
					lock (ThisLock)
					{
						if (items.Count < MaxCount)
						{
							items.Push(value);
							return true;
						}
					}
				}
				return false;
			}

			public void Clear()
			{
				lock (ThisLock)
				{
					items.Clear();
				}
			}
		}

		private const int maxPendingEntries = 128;

		private const int maxPromotionFailures = 64;

		private const int maxReturnsBeforePromotion = 64;

		private const int maxThreadItemsPerProcessor = 16;

		private Entry[] entries;

		private GlobalPool globalPool;

		private int maxCount;

		private PendingEntry[] pending;

		private int promotionFailures;

		private object ThisLock => this;

		public SynchronizedPool(int maxCount)
		{
			int num = maxCount;
			int num2 = 16 + SynchronizedPoolHelper.ProcessorCount;
			if (num > num2)
			{
				num = num2;
			}
			this.maxCount = maxCount;
			entries = new Entry[num];
			pending = new PendingEntry[4];
			globalPool = new GlobalPool(maxCount);
		}

		public void Clear()
		{
			Entry[] array = entries;
			for (int i = 0; i < array.Length; i++)
			{
				array[i].value = null;
			}
			globalPool.Clear();
		}

		private void HandlePromotionFailure(int thisThreadID)
		{
			int num = promotionFailures + 1;
			if (num >= 64)
			{
				lock (ThisLock)
				{
					entries = new Entry[entries.Length];
					globalPool.MaxCount = maxCount;
				}
				PromoteThread(thisThreadID);
			}
			else
			{
				promotionFailures = num;
			}
		}

		private bool PromoteThread(int thisThreadID)
		{
			lock (ThisLock)
			{
				for (int i = 0; i < entries.Length; i++)
				{
					int threadID = entries[i].threadID;
					if (threadID == thisThreadID)
					{
						return true;
					}
					if (threadID == 0)
					{
						globalPool.DecrementMaxCount();
						entries[i].threadID = thisThreadID;
						return true;
					}
				}
			}
			return false;
		}

		private void RecordReturnToGlobalPool(int thisThreadID)
		{
			PendingEntry[] array = pending;
			for (int i = 0; i < array.Length; i++)
			{
				int threadID = array[i].threadID;
				if (threadID == thisThreadID)
				{
					int num = array[i].returnCount + 1;
					if (num >= 64)
					{
						array[i].returnCount = 0;
						if (!PromoteThread(thisThreadID))
						{
							HandlePromotionFailure(thisThreadID);
						}
					}
					else
					{
						array[i].returnCount = num;
					}
					break;
				}
				if (threadID == 0)
				{
					break;
				}
			}
		}

		private void RecordTakeFromGlobalPool(int thisThreadID)
		{
			PendingEntry[] array = pending;
			for (int i = 0; i < array.Length; i++)
			{
				int threadID = array[i].threadID;
				if (threadID == thisThreadID)
				{
					return;
				}
				if (threadID != 0)
				{
					continue;
				}
				lock (array)
				{
					if (array[i].threadID == 0)
					{
						array[i].threadID = thisThreadID;
						return;
					}
				}
			}
			if (array.Length >= 128)
			{
				pending = new PendingEntry[array.Length];
				return;
			}
			PendingEntry[] destinationArray = new PendingEntry[array.Length * 2];
			Array.Copy(array, destinationArray, array.Length);
			pending = destinationArray;
		}

		public bool Return(T value)
		{
			int managedThreadId = Thread.CurrentThread.ManagedThreadId;
			if (managedThreadId == 0)
			{
				return false;
			}
			if (ReturnToPerThreadPool(managedThreadId, value))
			{
				return true;
			}
			return ReturnToGlobalPool(managedThreadId, value);
		}

		private bool ReturnToPerThreadPool(int thisThreadID, T value)
		{
			Entry[] array = entries;
			for (int i = 0; i < array.Length; i++)
			{
				int threadID = array[i].threadID;
				if (threadID == thisThreadID)
				{
					if (array[i].value == null)
					{
						array[i].value = value;
						return true;
					}
					return false;
				}
				if (threadID == 0)
				{
					break;
				}
			}
			return false;
		}

		private bool ReturnToGlobalPool(int thisThreadID, T value)
		{
			RecordReturnToGlobalPool(thisThreadID);
			return globalPool.Return(value);
		}

		public T Take()
		{
			int managedThreadId = Thread.CurrentThread.ManagedThreadId;
			if (managedThreadId == 0)
			{
				return null;
			}
			T val = TakeFromPerThreadPool(managedThreadId);
			if (val != null)
			{
				return val;
			}
			return TakeFromGlobalPool(managedThreadId);
		}

		private T TakeFromPerThreadPool(int thisThreadID)
		{
			Entry[] array = entries;
			for (int i = 0; i < array.Length; i++)
			{
				int threadID = array[i].threadID;
				if (threadID == thisThreadID)
				{
					T value = array[i].value;
					if (value != null)
					{
						array[i].value = null;
						return value;
					}
					return null;
				}
				if (threadID == 0)
				{
					break;
				}
			}
			return null;
		}

		private T TakeFromGlobalPool(int thisThreadID)
		{
			RecordTakeFromGlobalPool(thisThreadID);
			return globalPool.Take();
		}
	}
	internal static class TaskExtensions
	{
		public static IAsyncResult AsAsyncResult<T>(this Task<T> task, AsyncCallback callback, object state)
		{
			if (task == null)
			{
				throw Fx.Exception.ArgumentNull("task");
			}
			if (task.Status == TaskStatus.Created)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.SFxTaskNotStarted));
			}
			TaskCompletionSource<T> tcs = new TaskCompletionSource<T>(state);
			task.ContinueWith(delegate(Task<T> t)
			{
				if (t.IsFaulted)
				{
					tcs.TrySetException(t.Exception.InnerExceptions);
				}
				else if (t.IsCanceled)
				{
					tcs.TrySetCanceled();
				}
				else
				{
					tcs.TrySetResult(t.Result);
				}
				if (callback != null)
				{
					callback(tcs.Task);
				}
			}, TaskContinuationOptions.ExecuteSynchronously);
			return tcs.Task;
		}

		public static IAsyncResult AsAsyncResult(this Task task, AsyncCallback callback, object state)
		{
			if (task == null)
			{
				throw Fx.Exception.ArgumentNull("task");
			}
			if (task.Status == TaskStatus.Created)
			{
				throw Fx.Exception.AsError(new InvalidOperationException(InternalSR.SFxTaskNotStarted));
			}
			TaskCompletionSource<object> tcs = new TaskCompletionSource<object>(state);
			task.ContinueWith(delegate(Task t)
			{
				if (t.IsFaulted)
				{
					tcs.TrySetException(t.Exception.InnerExceptions);
				}
				else if (t.IsCanceled)
				{
					tcs.TrySetCanceled();
				}
				else
				{
					tcs.TrySetResult(null);
				}
				if (callback != null)
				{
					callback(tcs.Task);
				}
			}, TaskContinuationOptions.ExecuteSynchronously);
			return tcs.Task;
		}

		public static ConfiguredTaskAwaitable SuppressContextFlow(this Task task)
		{
			return task.ConfigureAwait(continueOnCapturedContext: false);
		}

		public static ConfiguredTaskAwaitable<T> SuppressContextFlow<T>(this Task<T> task)
		{
			return task.ConfigureAwait(continueOnCapturedContext: false);
		}

		public static ConfiguredTaskAwaitable ContinueOnCapturedContextFlow(this Task task)
		{
			return task.ConfigureAwait(continueOnCapturedContext: true);
		}

		public static ConfiguredTaskAwaitable<T> ContinueOnCapturedContextFlow<T>(this Task<T> task)
		{
			return task.ConfigureAwait(continueOnCapturedContext: true);
		}

		public static void Wait<TException>(this Task task)
		{
			try
			{
				task.Wait();
			}
			catch (AggregateException aggregateException)
			{
				throw Fx.Exception.AsError<TException>(aggregateException);
			}
		}

		public static bool Wait<TException>(this Task task, int millisecondsTimeout)
		{
			try
			{
				return task.Wait(millisecondsTimeout);
			}
			catch (AggregateException aggregateException)
			{
				throw Fx.Exception.AsError<TException>(aggregateException);
			}
		}

		public static bool Wait<TException>(this Task task, TimeSpan timeout)
		{
			try
			{
				if (timeout == TimeSpan.MaxValue)
				{
					return task.Wait(-1);
				}
				return task.Wait(timeout);
			}
			catch (AggregateException aggregateException)
			{
				throw Fx.Exception.AsError<TException>(aggregateException);
			}
		}

		public static void Wait(this Task task, TimeSpan timeout, Action<Exception, TimeSpan, string> exceptionConverter, string operationType)
		{
			bool flag = false;
			try
			{
				if (timeout > TimeoutHelper.MaxWait)
				{
					task.Wait();
				}
				else
				{
					flag = !task.Wait(timeout);
				}
			}
			catch (Exception ex)
			{
				if (Fx.IsFatal(ex) || exceptionConverter == null)
				{
					throw;
				}
				exceptionConverter(ex, timeout, operationType);
			}
			if (flag)
			{
				throw Fx.Exception.AsError(new TimeoutException(InternalSR.TaskTimedOutError(timeout)));
			}
		}

		public static Task<TBase> Upcast<TDerived, TBase>(this Task<TDerived> task) where TDerived : TBase
		{
			if (task.Status != TaskStatus.RanToCompletion)
			{
				return task.UpcastPrivate<TDerived, TBase>();
			}
			return Task.FromResult((TBase)(object)task.Result);
		}

		private static async Task<TBase> UpcastPrivate<TDerived, TBase>(this Task<TDerived> task) where TDerived : TBase
		{
			return (TBase)(object)(await task.ConfigureAwait(continueOnCapturedContext: false));
		}
	}
	internal class ThreadNeutralSemaphore
	{
		private class EnterAsyncData
		{
			public ThreadNeutralSemaphore Semaphore { get; set; }

			public AsyncWaitHandle Waiter { get; set; }

			public FastAsyncCallback Callback { get; set; }

			public object State { get; set; }

			public EnterAsyncData(ThreadNeutralSemaphore semaphore, AsyncWaitHandle waiter, FastAsyncCallback callback, object state)
			{
				Waiter = waiter;
				Semaphore = semaphore;
				Callback = callback;
				State = state;
			}
		}

		private static Action<object, TimeoutException> enteredAsyncCallback;

		private bool aborted;

		private Func<Exception> abortedExceptionGenerator;

		private int count;

		private int maxCount;

		private object ThisLock = new object();

		private Queue<AsyncWaitHandle> waiters;

		private static Action<object, TimeoutException> EnteredAsyncCallback
		{
			get
			{
				if (enteredAsyncCallback == null)
				{
					enteredAsyncCallback = OnEnteredAsync;
				}
				return enteredAsyncCallback;
			}
		}

		private Queue<AsyncWaitHandle> Waiters
		{
			get
			{
				if (waiters == null)
				{
					waiters = new Queue<AsyncWaitHandle>();
				}
				return waiters;
			}
		}

		public ThreadNeutralSemaphore(int maxCount)
			: this(maxCount, null)
		{
		}

		public ThreadNeutralSemaphore(int maxCount, Func<Exception> abortedExceptionGenerator)
		{
			this.maxCount = maxCount;
			this.abortedExceptionGenerator = abortedExceptionGenerator;
		}

		public bool EnterAsync(TimeSpan timeout, FastAsyncCallback callback, object state)
		{
			AsyncWaitHandle asyncWaitHandle = null;
			lock (ThisLock)
			{
				if (aborted)
				{
					throw Fx.Exception.AsError(CreateObjectAbortedException());
				}
				if (count < maxCount)
				{
					count++;
					return true;
				}
				asyncWaitHandle = new AsyncWaitHandle();
				Waiters.Enqueue(asyncWaitHandle);
			}
			return asyncWaitHandle.WaitAsync(EnteredAsyncCallback, new EnterAsyncData(this, asyncWaitHandle, callback, state), timeout);
		}

		private static void OnEnteredAsync(object state, TimeoutException exception)
		{
			EnterAsyncData enterAsyncData = (EnterAsyncData)state;
			ThreadNeutralSemaphore semaphore = enterAsyncData.Semaphore;
			Exception asyncException = exception;
			if (exception != null && !semaphore.RemoveWaiter(enterAsyncData.Waiter))
			{
				asyncException = null;
			}
			if (semaphore.aborted)
			{
				asyncException = semaphore.CreateObjectAbortedException();
			}
			enterAsyncData.Callback(enterAsyncData.State, asyncException);
		}

		public bool TryEnter()
		{
			lock (ThisLock)
			{
				if (count < maxCount)
				{
					count++;
					return true;
				}
				return false;
			}
		}

		public void Enter(TimeSpan timeout)
		{
			if (!TryEnter(timeout))
			{
				throw Fx.Exception.AsError(CreateEnterTimedOutException(timeout));
			}
		}

		public bool TryEnter(TimeSpan timeout)
		{
			AsyncWaitHandle asyncWaitHandle = EnterCore();
			if (asyncWaitHandle != null)
			{
				bool flag = !asyncWaitHandle.Wait(timeout);
				if (aborted)
				{
					throw Fx.Exception.AsError(CreateObjectAbortedException());
				}
				if (flag && !RemoveWaiter(asyncWaitHandle))
				{
					flag = false;
				}
				return !flag;
			}
			return true;
		}

		internal static TimeoutException CreateEnterTimedOutException(TimeSpan timeout)
		{
			return new TimeoutException(InternalSR.LockTimeoutExceptionMessage(timeout));
		}

		private Exception CreateObjectAbortedException()
		{
			if (abortedExceptionGenerator != null)
			{
				return abortedExceptionGenerator();
			}
			return new OperationCanceledException(InternalSR.ThreadNeutralSemaphoreAborted);
		}

		private bool RemoveWaiter(AsyncWaitHandle waiter)
		{
			bool result = false;
			lock (ThisLock)
			{
				for (int num = Waiters.Count; num > 0; num--)
				{
					AsyncWaitHandle asyncWaitHandle = Waiters.Dequeue();
					if (asyncWaitHandle == waiter)
					{
						result = true;
					}
					else
					{
						Waiters.Enqueue(asyncWaitHandle);
					}
				}
				return result;
			}
		}

		private AsyncWaitHandle EnterCore()
		{
			lock (ThisLock)
			{
				if (aborted)
				{
					throw Fx.Exception.AsError(CreateObjectAbortedException());
				}
				if (count < maxCount)
				{
					count++;
					return null;
				}
				AsyncWaitHandle asyncWaitHandle = new AsyncWaitHandle();
				Waiters.Enqueue(asyncWaitHandle);
				return asyncWaitHandle;
			}
		}

		public int Exit()
		{
			int result = -1;
			AsyncWaitHandle asyncWaitHandle;
			lock (ThisLock)
			{
				if (aborted)
				{
					return result;
				}
				if (count == 0)
				{
					string invalidSemaphoreExit = InternalSR.InvalidSemaphoreExit;
					throw Fx.Exception.AsError(new SynchronizationLockException(invalidSemaphoreExit));
				}
				if (waiters == null || waiters.Count == 0)
				{
					count--;
					return count;
				}
				asyncWaitHandle = waiters.Dequeue();
				result = count;
			}
			asyncWaitHandle.Set();
			return result;
		}

		public void Abort()
		{
			lock (ThisLock)
			{
				if (aborted)
				{
					return;
				}
				aborted = true;
				if (waiters != null)
				{
					while (waiters.Count > 0)
					{
						AsyncWaitHandle asyncWaitHandle = waiters.Dequeue();
						asyncWaitHandle.Set();
					}
				}
			}
		}
	}
	internal static class Ticks
	{
		public static long Now
		{
			[SecuritySafeCritical]
			get
			{
				UnsafeNativeMethods.GetSystemTimeAsFileTime(out var time);
				return time;
			}
		}

		public static long FromMilliseconds(int milliseconds)
		{
			checked
			{
				return unchecked((long)milliseconds) * 10000L;
			}
		}

		public static int ToMilliseconds(long ticks)
		{
			checked
			{
				return (int)unchecked(ticks / 10000);
			}
		}

		public static long FromTimeSpan(TimeSpan duration)
		{
			return duration.Ticks;
		}

		public static TimeSpan ToTimeSpan(long ticks)
		{
			return new TimeSpan(ticks);
		}

		public static long Add(long firstTicks, long secondTicks)
		{
			if (firstTicks == long.MaxValue || firstTicks == long.MinValue)
			{
				return firstTicks;
			}
			if (secondTicks == long.MaxValue || secondTicks == long.MinValue)
			{
				return secondTicks;
			}
			if (firstTicks >= 0 && long.MaxValue - firstTicks <= secondTicks)
			{
				return 9223372036854775806L;
			}
			if (firstTicks <= 0 && long.MinValue - firstTicks >= secondTicks)
			{
				return -9223372036854775807L;
			}
			return checked(firstTicks + secondTicks);
		}
	}
	internal struct TimeoutHelper
	{
		private DateTime deadline;

		private bool deadlineSet;

		private TimeSpan originalTimeout;

		public static readonly TimeSpan MaxWait = TimeSpan.FromMilliseconds(2147483647.0);

		public TimeSpan OriginalTimeout => originalTimeout;

		public TimeoutHelper(TimeSpan timeout)
		{
			originalTimeout = timeout;
			deadline = DateTime.MaxValue;
			deadlineSet = timeout == TimeSpan.MaxValue;
		}

		public static bool IsTooLarge(TimeSpan timeout)
		{
			if (timeout > MaxWait)
			{
				return timeout != TimeSpan.MaxValue;
			}
			return false;
		}

		public static TimeSpan FromMilliseconds(int milliseconds)
		{
			if (milliseconds == -1)
			{
				return TimeSpan.MaxValue;
			}
			return TimeSpan.FromMilliseconds(milliseconds);
		}

		public static int ToMilliseconds(TimeSpan timeout)
		{
			if (timeout == TimeSpan.MaxValue)
			{
				return -1;
			}
			long num = Ticks.FromTimeSpan(timeout);
			if (num / 10000 > int.MaxValue)
			{
				return int.MaxValue;
			}
			return Ticks.ToMilliseconds(num);
		}

		public static TimeSpan Min(TimeSpan val1, TimeSpan val2)
		{
			if (val1 > val2)
			{
				return val2;
			}
			return val1;
		}

		public static TimeSpan Add(TimeSpan timeout1, TimeSpan timeout2)
		{
			return Ticks.ToTimeSpan(Ticks.Add(Ticks.FromTimeSpan(timeout1), Ticks.FromTimeSpan(timeout2)));
		}

		public static DateTime Add(DateTime time, TimeSpan timeout)
		{
			if (timeout >= TimeSpan.Zero && DateTime.MaxValue - time <= timeout)
			{
				return DateTime.MaxValue;
			}
			if (timeout <= TimeSpan.Zero && DateTime.MinValue - time >= timeout)
			{
				return DateTime.MinValue;
			}
			return time + timeout;
		}

		public static DateTime Subtract(DateTime time, TimeSpan timeout)
		{
			return Add(time, TimeSpan.Zero - timeout);
		}

		public static TimeSpan Divide(TimeSpan timeout, int factor)
		{
			if (timeout == TimeSpan.MaxValue)
			{
				return TimeSpan.MaxValue;
			}
			return Ticks.ToTimeSpan(Ticks.FromTimeSpan(timeout) / factor + 1);
		}

		public TimeSpan RemainingTime()
		{
			if (!deadlineSet)
			{
				SetDeadline();
				return originalTimeout;
			}
			if (deadline == DateTime.MaxValue)
			{
				return TimeSpan.MaxValue;
			}
			TimeSpan timeSpan = deadline - DateTime.UtcNow;
			if (timeSpan <= TimeSpan.Zero)
			{
				return TimeSpan.Zero;
			}
			return timeSpan;
		}

		public TimeSpan ElapsedTime()
		{
			return originalTimeout - RemainingTime();
		}

		private void SetDeadline()
		{
			deadline = DateTime.UtcNow + originalTimeout;
			deadlineSet = true;
		}

		public static void ThrowIfNegativeArgument(TimeSpan timeout)
		{
			ThrowIfNegativeArgument(timeout, "timeout");
		}

		public static void ThrowIfNegativeArgument(TimeSpan timeout, string argumentName)
		{
			if (timeout < TimeSpan.Zero)
			{
				throw Fx.Exception.ArgumentOutOfRange(argumentName, timeout, InternalSR.TimeoutMustBeNonNegative(argumentName, timeout));
			}
		}

		public static void ThrowIfNonPositiveArgument(TimeSpan timeout)
		{
			ThrowIfNonPositiveArgument(timeout, "timeout");
		}

		public static void ThrowIfNonPositiveArgument(TimeSpan timeout, string argumentName)
		{
			if (timeout <= TimeSpan.Zero)
			{
				throw Fx.Exception.ArgumentOutOfRange(argumentName, timeout, InternalSR.TimeoutMustBePositive(argumentName, timeout));
			}
		}

		public static bool WaitOne(WaitHandle waitHandle, TimeSpan timeout)
		{
			ThrowIfNegativeArgument(timeout);
			if (timeout == TimeSpan.MaxValue)
			{
				waitHandle.WaitOne();
				return true;
			}
			return waitHandle.WaitOne(timeout, exitContext: false);
		}
	}
	internal enum TraceChannel
	{
		Admin = 16,
		Operational = 17,
		Analytic = 18,
		Debug = 19,
		Perf = 20,
		Application = 9
	}
	internal enum TraceEventLevel
	{
		LogAlways,
		Critical,
		Error,
		Warning,
		Informational,
		Verbose
	}
	internal enum TraceEventOpcode
	{
		Info = 0,
		Start = 1,
		Stop = 2,
		Reply = 6,
		Resume = 7,
		Suspend = 8,
		Send = 9,
		Receive = 240
	}
	internal class TraceLevelHelper
	{
		private static TraceEventType[] EtwLevelToTraceEventType = new TraceEventType[6]
		{
			TraceEventType.Critical,
			TraceEventType.Critical,
			TraceEventType.Error,
			TraceEventType.Warning,
			TraceEventType.Information,
			TraceEventType.Verbose
		};

		internal static TraceEventType GetTraceEventType(byte level, byte opcode)
		{
			return opcode switch
			{
				1 => TraceEventType.Start, 
				2 => TraceEventType.Stop, 
				8 => TraceEventType.Suspend, 
				7 => TraceEventType.Resume, 
				_ => EtwLevelToTraceEventType[level], 
			};
		}

		internal static TraceEventType GetTraceEventType(TraceEventLevel level)
		{
			return EtwLevelToTraceEventType[(int)level];
		}

		internal static TraceEventType GetTraceEventType(byte level)
		{
			return EtwLevelToTraceEventType[level];
		}

		internal static string LookupSeverity(TraceEventLevel level, TraceEventOpcode opcode)
		{
			return opcode switch
			{
				TraceEventOpcode.Start => "Start", 
				TraceEventOpcode.Stop => "Stop", 
				TraceEventOpcode.Suspend => "Suspend", 
				TraceEventOpcode.Resume => "Resume", 
				_ => level switch
				{
					TraceEventLevel.Critical => "Critical", 
					TraceEventLevel.Error => "Error", 
					TraceEventLevel.Warning => "Warning", 
					TraceEventLevel.Informational => "Information", 
					TraceEventLevel.Verbose => "Verbose", 
					_ => level.ToString(), 
				}, 
			};
		}
	}
	internal struct TracePayload
	{
		private string serializedException;

		private string eventSource;

		private string appDomainFriendlyName;

		private string extendedData;

		private string hostReference;

		public string SerializedException => serializedException;

		public string EventSource => eventSource;

		public string AppDomainFriendlyName => appDomainFriendlyName;

		public string ExtendedData => extendedData;

		public string HostReference => hostReference;

		public TracePayload(string serializedException, string eventSource, string appDomainFriendlyName, string extendedData, string hostReference)
		{
			this.serializedException = serializedException;
			this.eventSource = eventSource;
			this.appDomainFriendlyName = appDomainFriendlyName;
			this.extendedData = extendedData;
			this.hostReference = hostReference;
		}
	}
	internal abstract class TypedAsyncResult<T> : AsyncResult
	{
		private T data;

		public T Data => data;

		public TypedAsyncResult(AsyncCallback callback, object state)
			: base(callback, state)
		{
		}

		protected void Complete(T data, bool completedSynchronously)
		{
			this.data = data;
			Complete(completedSynchronously);
		}

		public static T End(IAsyncResult result)
		{
			TypedAsyncResult<T> typedAsyncResult = AsyncResult.End<TypedAsyncResult<T>>(result);
			return typedAsyncResult.Data;
		}
	}
	internal static class TypeHelper
	{
		public static readonly Type ArrayType = typeof(Array);

		public static readonly Type BoolType = typeof(bool);

		public static readonly Type GenericCollectionType = typeof(ICollection<>);

		public static readonly Type ByteType = typeof(byte);

		public static readonly Type SByteType = typeof(sbyte);

		public static readonly Type CharType = typeof(char);

		public static readonly Type ShortType = typeof(short);

		public static readonly Type UShortType = typeof(ushort);

		public static readonly Type IntType = typeof(int);

		public static readonly Type UIntType = typeof(uint);

		public static readonly Type LongType = typeof(long);

		public static readonly Type ULongType = typeof(ulong);

		public static readonly Type FloatType = typeof(float);

		public static readonly Type DoubleType = typeof(double);

		public static readonly Type DecimalType = typeof(decimal);

		public static readonly Type ExceptionType = typeof(Exception);

		public static readonly Type NullableType = typeof(Nullable<>);

		public static readonly Type ObjectType = typeof(object);

		public static readonly Type StringType = typeof(string);

		public static readonly Type TypeType = typeof(Type);

		public static readonly Type VoidType = typeof(void);

		public static bool AreTypesCompatible(object source, Type destinationType)
		{
			if (source == null)
			{
				if (destinationType.IsValueType)
				{
					return IsNullableType(destinationType);
				}
				return true;
			}
			return AreTypesCompatible(source.GetType(), destinationType);
		}

		public static bool AreTypesCompatible(Type sourceType, Type destinationType)
		{
			if ((object)sourceType == destinationType)
			{
				return true;
			}
			if (!IsImplicitNumericConversion(sourceType, destinationType) && !IsImplicitReferenceConversion(sourceType, destinationType) && !IsImplicitBoxingConversion(sourceType, destinationType))
			{
				return IsImplicitNullableConversion(sourceType, destinationType);
			}
			return true;
		}

		public static bool AreReferenceTypesCompatible(Type sourceType, Type destinationType)
		{
			if ((object)sourceType == destinationType)
			{
				return true;
			}
			return IsImplicitReferenceConversion(sourceType, destinationType);
		}

		public static IEnumerable<Type> GetCompatibleTypes(IEnumerable<Type> enumerable, Type targetType)
		{
			foreach (Type item in enumerable)
			{
				if (AreTypesCompatible(item, targetType))
				{
					yield return item;
				}
			}
		}

		public static bool ContainsCompatibleType(IEnumerable<Type> enumerable, Type targetType)
		{
			foreach (Type item in enumerable)
			{
				if (AreTypesCompatible(item, targetType))
				{
					return true;
				}
			}
			return false;
		}

		public static T Convert<T>(object source)
		{
			if (source is T)
			{
				return (T)source;
			}
			if (source == null)
			{
				if (typeof(T).IsValueType && !IsNullableType(typeof(T)))
				{
					throw Fx.Exception.AsError(new InvalidCastException(InternalSR.CannotConvertObject(source, typeof(T))));
				}
				return default(T);
			}
			if (TryNumericConversion<T>(source, out var result))
			{
				return result;
			}
			throw Fx.Exception.AsError(new InvalidCastException(InternalSR.CannotConvertObject(source, typeof(T))));
		}

		public static IEnumerable<Type> GetImplementedTypes(Type type)
		{
			Dictionary<Type, object> dictionary = new Dictionary<Type, object>();
			GetImplementedTypesHelper(type, dictionary);
			return dictionary.Keys;
		}

		private static void GetImplementedTypesHelper(Type type, Dictionary<Type, object> typesEncountered)
		{
			if (!typesEncountered.ContainsKey(type))
			{
				typesEncountered.Add(type, type);
				Type[] interfaces = type.GetInterfaces();
				for (int i = 0; i < interfaces.Length; i++)
				{
					GetImplementedTypesHelper(interfaces[i], typesEncountered);
				}
				Type baseType = type.BaseType;
				while (baseType != null && baseType != ObjectType)
				{
					GetImplementedTypesHelper(baseType, typesEncountered);
					baseType = baseType.BaseType;
				}
			}
		}

		private static bool IsImplicitNumericConversion(Type source, Type destination)
		{
			TypeCode typeCode = Type.GetTypeCode(source);
			TypeCode typeCode2 = Type.GetTypeCode(destination);
			switch (typeCode)
			{
			case TypeCode.SByte:
				switch (typeCode2)
				{
				case TypeCode.Int16:
				case TypeCode.Int32:
				case TypeCode.Int64:
				case TypeCode.Single:
				case TypeCode.Double:
				case TypeCode.Decimal:
					return true;
				default:
					return false;
				}
			case TypeCode.Byte:
				if ((uint)(typeCode2 - 7) <= 8u)
				{
					return true;
				}
				return false;
			case TypeCode.Int16:
				switch (typeCode2)
				{
				case TypeCode.Int32:
				case TypeCode.Int64:
				case TypeCode.Single:
				case TypeCode.Double:
				case TypeCode.Decimal:
					return true;
				default:
					return false;
				}
			case TypeCode.UInt16:
				if ((uint)(typeCode2 - 9) <= 6u)
				{
					return true;
				}
				return false;
			case TypeCode.Int32:
				if (typeCode2 == TypeCode.Int64 || (uint)(typeCode2 - 13) <= 2u)
				{
					return true;
				}
				return false;
			case TypeCode.UInt32:
				if ((uint)(typeCode2 - 10) <= 5u)
				{
					return true;
				}
				return false;
			case TypeCode.Int64:
			case TypeCode.UInt64:
				if ((uint)(typeCode2 - 13) <= 2u)
				{
					return true;
				}
				return false;
			case TypeCode.Char:
				if ((uint)(typeCode2 - 8) <= 7u)
				{
					return true;
				}
				return false;
			case TypeCode.Single:
				return typeCode2 == TypeCode.Double;
			default:
				return false;
			}
		}

		private static bool IsImplicitReferenceConversion(Type sourceType, Type destinationType)
		{
			return destinationType.IsAssignableFrom(sourceType);
		}

		private static bool IsImplicitBoxingConversion(Type sourceType, Type destinationType)
		{
			if (sourceType.IsValueType && (destinationType == ObjectType || destinationType == typeof(ValueType)))
			{
				return true;
			}
			if (sourceType.IsEnum && destinationType == typeof(Enum))
			{
				return true;
			}
			return false;
		}

		private static bool IsImplicitNullableConversion(Type sourceType, Type destinationType)
		{
			if (!IsNullableType(destinationType))
			{
				return false;
			}
			destinationType = destinationType.GetGenericArguments()[0];
			if (IsNullableType(sourceType))
			{
				sourceType = sourceType.GetGenericArguments()[0];
			}
			return AreTypesCompatible(sourceType, destinationType);
		}

		private static bool IsNullableType(Type type)
		{
			if (type.IsGenericType)
			{
				return type.GetGenericTypeDefinition() == NullableType;
			}
			return false;
		}

		private static bool TryNumericConversion<T>(object source, out T result)
		{
			TypeCode typeCode = Type.GetTypeCode(source.GetType());
			TypeCode typeCode2 = Type.GetTypeCode(typeof(T));
			switch (typeCode)
			{
			case TypeCode.SByte:
			{
				sbyte b = (sbyte)source;
				switch (typeCode2)
				{
				case TypeCode.Int16:
					result = (T)(object)(short)b;
					return true;
				case TypeCode.Int32:
					result = (T)(object)(int)b;
					return true;
				case TypeCode.Int64:
					result = (T)(object)(long)b;
					return true;
				case TypeCode.Single:
					result = (T)(object)(float)b;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)b;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)b;
					return true;
				}
				break;
			}
			case TypeCode.Byte:
			{
				byte b2 = (byte)source;
				switch (typeCode2)
				{
				case TypeCode.Int16:
					result = (T)(object)(short)b2;
					return true;
				case TypeCode.UInt16:
					result = (T)(object)(ushort)b2;
					return true;
				case TypeCode.Int32:
					result = (T)(object)(int)b2;
					return true;
				case TypeCode.UInt32:
					result = (T)(object)(uint)b2;
					return true;
				case TypeCode.Int64:
					result = (T)(object)(long)b2;
					return true;
				case TypeCode.UInt64:
					result = (T)(object)(ulong)b2;
					return true;
				case TypeCode.Single:
					result = (T)(object)(float)(int)b2;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)(int)b2;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)b2;
					return true;
				}
				break;
			}
			case TypeCode.Int16:
			{
				short num6 = (short)source;
				switch (typeCode2)
				{
				case TypeCode.Int32:
					result = (T)(object)(int)num6;
					return true;
				case TypeCode.Int64:
					result = (T)(object)(long)num6;
					return true;
				case TypeCode.Single:
					result = (T)(object)(float)num6;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)num6;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)num6;
					return true;
				}
				break;
			}
			case TypeCode.UInt16:
			{
				ushort num5 = (ushort)source;
				switch (typeCode2)
				{
				case TypeCode.Int32:
					result = (T)(object)(int)num5;
					return true;
				case TypeCode.UInt32:
					result = (T)(object)(uint)num5;
					return true;
				case TypeCode.Int64:
					result = (T)(object)(long)num5;
					return true;
				case TypeCode.UInt64:
					result = (T)(object)(ulong)num5;
					return true;
				case TypeCode.Single:
					result = (T)(object)(float)(int)num5;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)(int)num5;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)num5;
					return true;
				}
				break;
			}
			case TypeCode.Int32:
			{
				int num4 = (int)source;
				switch (typeCode2)
				{
				case TypeCode.Int64:
					result = (T)(object)(long)num4;
					return true;
				case TypeCode.Single:
					result = (T)(object)(float)num4;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)num4;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)num4;
					return true;
				}
				break;
			}
			case TypeCode.UInt32:
			{
				uint num3 = (uint)source;
				switch (typeCode2)
				{
				case TypeCode.UInt32:
					result = (T)(object)num3;
					return true;
				case TypeCode.Int64:
					result = (T)(object)(long)num3;
					return true;
				case TypeCode.UInt64:
					result = (T)(object)(ulong)num3;
					return true;
				case TypeCode.Single:
					result = (T)(object)(float)num3;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)num3;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)num3;
					return true;
				}
				break;
			}
			case TypeCode.Int64:
			{
				long num2 = (long)source;
				switch (typeCode2)
				{
				case TypeCode.Single:
					result = (T)(object)(float)num2;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)num2;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)num2;
					return true;
				}
				break;
			}
			case TypeCode.UInt64:
			{
				ulong num = (ulong)source;
				switch (typeCode2)
				{
				case TypeCode.Single:
					result = (T)(object)(float)num;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)num;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)num;
					return true;
				}
				break;
			}
			case TypeCode.Char:
			{
				char c = (char)source;
				switch (typeCode2)
				{
				case TypeCode.UInt16:
					result = (T)(object)(ushort)c;
					return true;
				case TypeCode.Int32:
					result = (T)(object)(int)c;
					return true;
				case TypeCode.UInt32:
					result = (T)(object)(uint)c;
					return true;
				case TypeCode.Int64:
					result = (T)(object)(long)c;
					return true;
				case TypeCode.UInt64:
					result = (T)(object)(ulong)c;
					return true;
				case TypeCode.Single:
					result = (T)(object)(float)(int)c;
					return true;
				case TypeCode.Double:
					result = (T)(object)(double)(int)c;
					return true;
				case TypeCode.Decimal:
					result = (T)(object)(decimal)c;
					return true;
				}
				break;
			}
			case TypeCode.Single:
				if (typeCode2 == TypeCode.Double)
				{
					result = (T)(object)(double)(float)source;
					return true;
				}
				break;
			}
			result = default(T);
			return false;
		}

		public static object GetDefaultValueForType(Type type)
		{
			if (!type.IsValueType)
			{
				return null;
			}
			if (type.IsEnum)
			{
				Array values = Enum.GetValues(type);
				if (values.Length > 0)
				{
					return values.GetValue(0);
				}
			}
			return Activator.CreateInstance(type);
		}

		public static bool IsNullableValueType(Type type)
		{
			if (type.IsValueType)
			{
				return IsNullableType(type);
			}
			return false;
		}

		public static bool IsNonNullableValueType(Type type)
		{
			if (!type.IsValueType)
			{
				return false;
			}
			if (type.IsGenericType)
			{
				return false;
			}
			return type != StringType;
		}

		public static bool ShouldFilterProperty(PropertyDescriptor property, Attribute[] attributes)
		{
			if (attributes == null || attributes.Length == 0)
			{
				return false;
			}
			foreach (Attribute attribute in attributes)
			{
				Attribute attribute2 = property.Attributes[attribute.GetType()];
				if (attribute2 == null)
				{
					if (!attribute.IsDefaultAttribute())
					{
						return true;
					}
				}
				else if (!attribute.Match(attribute2))
				{
					return true;
				}
			}
			return false;
		}
	}
	internal static class UrlUtility
	{
		private class UrlDecoder
		{
			private int _bufferSize;

			private int _numChars;

			private char[] _charBuffer;

			private int _numBytes;

			private byte[] _byteBuffer;

			private Encoding _encoding;

			private void FlushBytes()
			{
				if (_numBytes > 0)
				{
					_numChars += _encoding.GetChars(_byteBuffer, 0, _numBytes, _charBuffer, _numChars);
					_numBytes = 0;
				}
			}

			internal UrlDecoder(int bufferSize, Encoding encoding)
			{
				_bufferSize = bufferSize;
				_encoding = encoding;
				_charBuffer = new char[bufferSize];
			}

			internal void AddChar(char ch)
			{
				if (_numBytes > 0)
				{
					FlushBytes();
				}
				_charBuffer[_numChars++] = ch;
			}

			internal void AddByte(byte b)
			{
				if (_byteBuffer == null)
				{
					_byteBuffer = new byte[_bufferSize];
				}
				_byteBuffer[_numBytes++] = b;
			}

			internal string GetString()
			{
				if (_numBytes > 0)
				{
					FlushBytes();
				}
				if (_numChars > 0)
				{
					return new string(_charBuffer, 0, _numChars);
				}
				return string.Empty;
			}
		}

		[Serializable]
		private class HttpValueCollection : NameValueCollection
		{
			internal HttpValueCollection(string str, Encoding encoding)
				: base(StringComparer.OrdinalIgnoreCase)
			{
				if (!string.IsNullOrEmpty(str))
				{
					FillFromString(str, urlencoded: true, encoding);
				}
				base.IsReadOnly = false;
			}

			protected HttpValueCollection(SerializationInfo info, StreamingContext context)
				: base(info, context)
			{
			}

			internal void FillFromString(string s, bool urlencoded, Encoding encoding)
			{
				int num = s?.Length ?? 0;
				for (int i = 0; i < num; i++)
				{
					int num2 = i;
					int num3 = -1;
					for (; i < num; i++)
					{
						switch (s[i])
						{
						case '=':
							if (num3 < 0)
							{
								num3 = i;
							}
							continue;
						default:
							continue;
						case '&':
							break;
						}
						break;
					}
					string text = null;
					string text2 = null;
					if (num3 >= 0)
					{
						text = s.Substring(num2, num3 - num2);
						text2 = s.Substring(num3 + 1, i - num3 - 1);
					}
					else
					{
						text2 = s.Substring(num2, i - num2);
					}
					if (urlencoded)
					{
						base.Add(UrlDecode(text, encoding), UrlDecode(text2, encoding));
					}
					else
					{
						base.Add(text, text2);
					}
					if (i == num - 1 && s[i] == '&')
					{
						base.Add(null, string.Empty);
					}
				}
			}

			public override string ToString()
			{
				return ToString(urlencoded: true, null);
			}

			private string ToString(bool urlencoded, IDictionary excludeKeys)
			{
				int count = Count;
				if (count == 0)
				{
					return string.Empty;
				}
				StringBuilder stringBuilder = new StringBuilder();
				for (int i = 0; i < count; i++)
				{
					string text = GetKey(i);
					if (excludeKeys != null && text != null && excludeKeys[text] != null)
					{
						continue;
					}
					if (urlencoded)
					{
						text = UrlEncodeUnicode(text);
					}
					string value = ((!string.IsNullOrEmpty(text)) ? (text + "=") : string.Empty);
					ArrayList arrayList = (ArrayList)BaseGet(i);
					int num = arrayList?.Count ?? 0;
					if (stringBuilder.Length > 0)
					{
						stringBuilder.Append('&');
					}
					switch (num)
					{
					case 1:
					{
						stringBuilder.Append(value);
						string text2 = (string)arrayList[0];
						if (urlencoded)
						{
							text2 = UrlEncodeUnicode(text2);
						}
						stringBuilder.Append(text2);
						continue;
					}
					case 0:
						stringBuilder.Append(value);
						continue;
					}
					for (int j = 0; j < num; j++)
					{
						if (j > 0)
						{
							stringBuilder.Append('&');
						}
						stringBuilder.Append(value);
						string text2 = (string)arrayList[j];
						if (urlencoded)
						{
							text2 = UrlEncodeUnicode(text2);
						}
						stringBuilder.Append(text2);
					}
				}
				return stringBuilder.ToString();
			}
		}

		public static NameValueCollection ParseQueryString(string query)
		{
			return ParseQueryString(query, Encoding.UTF8);
		}

		public static NameValueCollection ParseQueryString(string query, Encoding encoding)
		{
			if (query == null)
			{
				throw Fx.Exception.ArgumentNull("query");
			}
			if (encoding == null)
			{
				throw Fx.Exception.ArgumentNull("encoding");
			}
			if (query.Length > 0 && query[0] == '?')
			{
				query = query.Substring(1);
			}
			return new HttpValueCollection(query, encoding);
		}

		public static string UrlEncode(string str)
		{
			if (str == null)
			{
				return null;
			}
			return UrlEncode(str, Encoding.UTF8);
		}

		public static string UrlPathEncode(string str)
		{
			if (str == null)
			{
				return null;
			}
			int num = str.IndexOf('?');
			if (num >= 0)
			{
				return UrlPathEncode(str.Substring(0, num)) + str.Substring(num);
			}
			return UrlEncodeSpaces(UrlEncodeNonAscii(str, Encoding.UTF8));
		}

		public static string UrlEncode(string str, Encoding encoding)
		{
			if (str == null)
			{
				return null;
			}
			return Encoding.ASCII.GetString(UrlEncodeToBytes(str, encoding));
		}

		public static string UrlEncodeUnicode(string str)
		{
			if (str == null)
			{
				return null;
			}
			return UrlEncodeUnicodeStringToStringInternal(str, ignoreAscii: false);
		}

		private static string UrlEncodeUnicodeStringToStringInternal(string s, bool ignoreAscii)
		{
			int length = s.Length;
			StringBuilder stringBuilder = new StringBuilder(length);
			for (int i = 0; i < length; i++)
			{
				char c = s[i];
				if ((c & 0xFF80) == 0)
				{
					if (ignoreAscii || IsSafe(c))
					{
						stringBuilder.Append(c);
						continue;
					}
					if (c == ' ')
					{
						stringBuilder.Append('+');
						continue;
					}
					stringBuilder.Append('%');
					stringBuilder.Append(IntToHex(((int)c >> 4) & 0xF));
					stringBuilder.Append(IntToHex(c & 0xF));
				}
				else
				{
					stringBuilder.Append("%u");
					stringBuilder.Append(IntToHex(((int)c >> 12) & 0xF));
					stringBuilder.Append(IntToHex(((int)c >> 8) & 0xF));
					stringBuilder.Append(IntToHex(((int)c >> 4) & 0xF));
					stringBuilder.Append(IntToHex(c & 0xF));
				}
			}
			return stringBuilder.ToString();
		}

		private static string UrlEncodeNonAscii(string str, Encoding e)
		{
			if (string.IsNullOrEmpty(str))
			{
				return str;
			}
			if (e == null)
			{
				e = Encoding.UTF8;
			}
			byte[] bytes = e.GetBytes(str);
			bytes = UrlEncodeBytesToBytesInternalNonAscii(bytes, 0, bytes.Length, alwaysCreateReturnValue: false);
			return Encoding.ASCII.GetString(bytes);
		}

		private static string UrlEncodeSpaces(string str)
		{
			if (str != null && str.IndexOf(' ') >= 0)
			{
				str = str.Replace(" ", "%20");
			}
			return str;
		}

		public static byte[] UrlEncodeToBytes(string str, Encoding e)
		{
			if (str == null)
			{
				return null;
			}
			byte[] bytes = e.GetBytes(str);
			return UrlEncodeBytesToBytesInternal(bytes, 0, bytes.Length, alwaysCreateReturnValue: false);
		}

		public static string UrlDecode(string str, Encoding e)
		{
			if (str == null)
			{
				return null;
			}
			return UrlDecodeStringFromStringInternal(str, e);
		}

		private static byte[] UrlEncodeBytesToBytesInternal(byte[] bytes, int offset, int count, bool alwaysCreateReturnValue)
		{
			int num = 0;
			int num2 = 0;
			for (int i = 0; i < count; i++)
			{
				char c = (char)bytes[offset + i];
				if (c == ' ')
				{
					num++;
				}
				else if (!IsSafe(c))
				{
					num2++;
				}
			}
			if (!alwaysCreateReturnValue && num == 0 && num2 == 0)
			{
				return bytes;
			}
			byte[] array = new byte[count + num2 * 2];
			int num3 = 0;
			for (int j = 0; j < count; j++)
			{
				byte b = bytes[offset + j];
				char c2 = (char)b;
				if (IsSafe(c2))
				{
					array[num3++] = b;
					continue;
				}
				if (c2 == ' ')
				{
					array[num3++] = 43;
					continue;
				}
				array[num3++] = 37;
				array[num3++] = (byte)IntToHex((b >> 4) & 0xF);
				array[num3++] = (byte)IntToHex(b & 0xF);
			}
			return array;
		}

		private static bool IsNonAsciiByte(byte b)
		{
			if (b < 127)
			{
				return b < 32;
			}
			return true;
		}

		private static byte[] UrlEncodeBytesToBytesInternalNonAscii(byte[] bytes, int offset, int count, bool alwaysCreateReturnValue)
		{
			int num = 0;
			for (int i = 0; i < count; i++)
			{
				if (IsNonAsciiByte(bytes[offset + i]))
				{
					num++;
				}
			}
			if (!alwaysCreateReturnValue && num == 0)
			{
				return bytes;
			}
			byte[] array = new byte[count + num * 2];
			int num2 = 0;
			for (int j = 0; j < count; j++)
			{
				byte b = bytes[offset + j];
				if (IsNonAsciiByte(b))
				{
					array[num2++] = 37;
					array[num2++] = (byte)IntToHex((b >> 4) & 0xF);
					array[num2++] = (byte)IntToHex(b & 0xF);
				}
				else
				{
					array[num2++] = b;
				}
			}
			return array;
		}

		private static string UrlDecodeStringFromStringInternal(string s, Encoding e)
		{
			int length = s.Length;
			UrlDecoder urlDecoder = new UrlDecoder(length, e);
			for (int i = 0; i < length; i++)
			{
				char c = s[i];
				switch (c)
				{
				case '+':
					c = ' ';
					break;
				case '%':
					if (i >= length - 2)
					{
						break;
					}
					if (s[i + 1] == 'u' && i < length - 5)
					{
						int num = HexToInt(s[i + 2]);
						int num2 = HexToInt(s[i + 3]);
						int num3 = HexToInt(s[i + 4]);
						int num4 = HexToInt(s[i + 5]);
						if (num >= 0 && num2 >= 0 && num3 >= 0 && num4 >= 0)
						{
							c = (char)((num << 12) | (num2 << 8) | (num3 << 4) | num4);
							i += 5;
							urlDecoder.AddChar(c);
							continue;
						}
					}
					else
					{
						int num5 = HexToInt(s[i + 1]);
						int num6 = HexToInt(s[i + 2]);
						if (num5 >= 0 && num6 >= 0)
						{
							byte b = (byte)((num5 << 4) | num6);
							i += 2;
							urlDecoder.AddByte(b);
							continue;
						}
					}
					break;
				}
				if ((c & 0xFF80) == 0)
				{
					urlDecoder.AddByte((byte)c);
				}
				else
				{
					urlDecoder.AddChar(c);
				}
			}
			return urlDecoder.GetString();
		}

		private static int HexToInt(char h)
		{
			if (h < '0' || h > '9')
			{
				if (h < 'a' || h > 'f')
				{
					if (h < 'A' || h > 'F')
					{
						return -1;
					}
					return h - 65 + 10;
				}
				return h - 97 + 10;
			}
			return h - 48;
		}

		private static char IntToHex(int n)
		{
			if (n <= 9)
			{
				return (char)(n + 48);
			}
			return (char)(n - 10 + 97);
		}

		internal static bool IsSafe(char ch)
		{
			if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))
			{
				return true;
			}
			switch (ch)
			{
			case '!':
			case '\'':
			case '(':
			case ')':
			case '*':
			case '-':
			case '.':
			case '_':
				return true;
			default:
				return false;
			}
		}
	}
	internal static class WaitCallbackActionItem
	{
		internal static bool ShouldUseActivity { get; set; }
	}
	internal class InternalSR
	{
		private static ResourceManager resourceManager;

		private static CultureInfo resourceCulture;

		internal static ResourceManager ResourceManager
		{
			get
			{
				if (InternalSR.resourceManager == null)
				{
					ResourceManager resourceManager = (InternalSR.resourceManager = new ResourceManager("System.Runtime.InternalSR", typeof(InternalSR).Assembly));
				}
				return InternalSR.resourceManager;
			}
		}

		internal static CultureInfo Culture
		{
			get
			{
				return resourceCulture;
			}
			set
			{
				resourceCulture = value;
			}
		}

		internal static string ActionItemIsAlreadyScheduled => ResourceManager.GetString("ActionItemIsAlreadyScheduled", Culture);

		internal static string AsyncCallbackThrewException => ResourceManager.GetString("AsyncCallbackThrewException", Culture);

		internal static string AsyncResultAlreadyEnded => ResourceManager.GetString("AsyncResultAlreadyEnded", Culture);

		internal static string DictionaryIsReadOnly => ResourceManager.GetString("DictionaryIsReadOnly", Culture);

		internal static string InvalidAsyncResult => ResourceManager.GetString("InvalidAsyncResult", Culture);

		internal static string InvalidSemaphoreExit => ResourceManager.GetString("InvalidSemaphoreExit", Culture);

		internal static string MustCancelOldTimer => ResourceManager.GetString("MustCancelOldTimer", Culture);

		internal static string BufferIsNotRightSizeForBufferManager => ResourceManager.GetString("BufferIsNotRightSizeForBufferManager", Culture);

		internal static string ReadNotSupported => ResourceManager.GetString("ReadNotSupported", Culture);

		internal static string SeekNotSupported => ResourceManager.GetString("SeekNotSupported", Culture);

		internal static string ThreadNeutralSemaphoreAborted => ResourceManager.GetString("ThreadNeutralSemaphoreAborted", Culture);

		internal static string ValueMustBeNonNegative => ResourceManager.GetString("ValueMustBeNonNegative", Culture);

		internal static string BadCopyToArray => ResourceManager.GetString("BadCopyToArray", Culture);

		internal static string KeyNotFoundInDictionary => ResourceManager.GetString("KeyNotFoundInDictionary", Culture);

		internal static string InvalidAsyncResultImplementationGeneric => ResourceManager.GetString("InvalidAsyncResultImplementationGeneric", Culture);

		internal static string InvalidNullAsyncResult => ResourceManager.GetString("InvalidNullAsyncResult", Culture);

		internal static string NullKeyAlreadyPresent => ResourceManager.GetString("NullKeyAlreadyPresent", Culture);

		internal static string KeyCollectionUpdatesNotAllowed => ResourceManager.GetString("KeyCollectionUpdatesNotAllowed", Culture);

		internal static string ValueCollectionUpdatesNotAllowed => ResourceManager.GetString("ValueCollectionUpdatesNotAllowed", Culture);

		internal static string SFxTaskNotStarted => ResourceManager.GetString("SFxTaskNotStarted", Culture);

		private InternalSR()
		{
		}

		internal static string ArgumentNullOrEmpty(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("ArgumentNullOrEmpty", Culture), new object[1] { param0 });
		}

		internal static string FailFastMessage(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("FailFastMessage", Culture), new object[1] { param0 });
		}

		internal static string IncompatibleArgumentType(object param0, object param1)
		{
			return string.Format(Culture, ResourceManager.GetString("IncompatibleArgumentType", Culture), new object[2] { param0, param1 });
		}

		internal static string LockTimeoutExceptionMessage(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("LockTimeoutExceptionMessage", Culture), new object[1] { param0 });
		}

		internal static string BufferAllocationFailed(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("BufferAllocationFailed", Culture), new object[1] { param0 });
		}

		internal static string BufferedOutputStreamQuotaExceeded(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("BufferedOutputStreamQuotaExceeded", Culture), new object[1] { param0 });
		}

		internal static string ShipAssertExceptionMessage(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("ShipAssertExceptionMessage", Culture), new object[1] { param0 });
		}

		internal static string TimeoutInputQueueDequeue(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("TimeoutInputQueueDequeue", Culture), new object[1] { param0 });
		}

		internal static string TimeoutMustBeNonNegative(object param0, object param1)
		{
			return string.Format(Culture, ResourceManager.GetString("TimeoutMustBeNonNegative", Culture), new object[2] { param0, param1 });
		}

		internal static string TimeoutMustBePositive(object param0, object param1)
		{
			return string.Format(Culture, ResourceManager.GetString("TimeoutMustBePositive", Culture), new object[2] { param0, param1 });
		}

		internal static string TimeoutOnOperation(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("TimeoutOnOperation", Culture), new object[1] { param0 });
		}

		internal static string CannotConvertObject(object param0, object param1)
		{
			return string.Format(Culture, ResourceManager.GetString("CannotConvertObject", Culture), new object[2] { param0, param1 });
		}

		internal static string EtwAPIMaxStringCountExceeded(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("EtwAPIMaxStringCountExceeded", Culture), new object[1] { param0 });
		}

		internal static string EtwMaxNumberArgumentsExceeded(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("EtwMaxNumberArgumentsExceeded", Culture), new object[1] { param0 });
		}

		internal static string EtwRegistrationFailed(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("EtwRegistrationFailed", Culture), new object[1] { param0 });
		}

		internal static string InvalidAsyncResultImplementation(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("InvalidAsyncResultImplementation", Culture), new object[1] { param0 });
		}

		internal static string AsyncResultCompletedTwice(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("AsyncResultCompletedTwice", Culture), new object[1] { param0 });
		}

		internal static string AsyncEventArgsCompletedTwice(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("AsyncEventArgsCompletedTwice", Culture), new object[1] { param0 });
		}

		internal static string AsyncEventArgsCompletionPending(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("AsyncEventArgsCompletionPending", Culture), new object[1] { param0 });
		}

		internal static string TaskTimedOutError(object param0)
		{
			return string.Format(Culture, ResourceManager.GetString("TaskTimedOutError", Culture), new object[1] { param0 });
		}
	}
	internal class TraceCore
	{
		private static ResourceManager resourceManager;

		private static CultureInfo resourceCulture;

		[SecurityCritical]
		private static System.Runtime.Diagnostics.EventDescriptor[] eventDescriptors;

		private static object syncLock = new object();

		private static volatile bool eventDescriptorsCreated;

		private static ResourceManager ResourceManager
		{
			get
			{
				if (resourceManager == null)
				{
					resourceManager = new ResourceManager("System.Runtime.TraceCore", typeof(TraceCore).Assembly);
				}
				return resourceManager;
			}
		}

		internal static CultureInfo Culture
		{
			get
			{
				return resourceCulture;
			}
			set
			{
				resourceCulture = value;
			}
		}

		private TraceCore()
		{
		}

		internal static bool AppDomainUnloadIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Informational))
			{
				return IsEtwEventEnabled(trace, 0);
			}
			return true;
		}

		internal static void AppDomainUnload(EtwDiagnosticTrace trace, string appdomainName, string processName, string processId)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, null);
			if (IsEtwEventEnabled(trace, 0))
			{
				WriteEtwEvent(trace, 0, null, appdomainName, processName, processId, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Informational))
			{
				string description = string.Format(Culture, ResourceManager.GetString("AppDomainUnload", Culture), new object[3] { appdomainName, processName, processId });
				WriteTraceSource(trace, 0, description, serializedPayload);
			}
		}

		internal static bool HandledExceptionIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Informational))
			{
				return IsEtwEventEnabled(trace, 1);
			}
			return true;
		}

		internal static void HandledException(EtwDiagnosticTrace trace, string param0, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 1))
			{
				WriteEtwEvent(trace, 1, null, param0, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Informational))
			{
				string description = string.Format(Culture, ResourceManager.GetString("HandledException", Culture), new object[1] { param0 });
				WriteTraceSource(trace, 1, description, serializedPayload);
			}
		}

		internal static bool ShipAssertExceptionMessageIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Error))
			{
				return IsEtwEventEnabled(trace, 2);
			}
			return true;
		}

		internal static void ShipAssertExceptionMessage(EtwDiagnosticTrace trace, string param0)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, null);
			if (IsEtwEventEnabled(trace, 2))
			{
				WriteEtwEvent(trace, 2, null, param0, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Error))
			{
				string description = string.Format(Culture, ResourceManager.GetString("ShipAssertExceptionMessage", Culture), new object[1] { param0 });
				WriteTraceSource(trace, 2, description, serializedPayload);
			}
		}

		internal static bool ThrowingExceptionIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Warning))
			{
				return IsEtwEventEnabled(trace, 3);
			}
			return true;
		}

		internal static void ThrowingException(EtwDiagnosticTrace trace, string param0, string param1, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 3))
			{
				WriteEtwEvent(trace, 3, null, param0, param1, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Warning))
			{
				string description = string.Format(Culture, ResourceManager.GetString("ThrowingException", Culture), new object[2] { param0, param1 });
				WriteTraceSource(trace, 3, description, serializedPayload);
			}
		}

		internal static bool UnhandledExceptionIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Critical))
			{
				return IsEtwEventEnabled(trace, 4);
			}
			return true;
		}

		internal static void UnhandledException(EtwDiagnosticTrace trace, string param0, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 4))
			{
				WriteEtwEvent(trace, 4, null, param0, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Critical))
			{
				string description = string.Format(Culture, ResourceManager.GetString("UnhandledException", Culture), new object[1] { param0 });
				WriteTraceSource(trace, 4, description, serializedPayload);
			}
		}

		internal static bool TraceCodeEventLogCriticalIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Critical))
			{
				return IsEtwEventEnabled(trace, 5);
			}
			return true;
		}

		internal static void TraceCodeEventLogCritical(EtwDiagnosticTrace trace, TraceRecord traceRecord)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, traceRecord, null);
			if (IsEtwEventEnabled(trace, 5))
			{
				WriteEtwEvent(trace, 5, null, serializedPayload.ExtendedData, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Critical))
			{
				string description = string.Format(Culture, ResourceManager.GetString("TraceCodeEventLogCritical", Culture));
				WriteTraceSource(trace, 5, description, serializedPayload);
			}
		}

		internal static bool TraceCodeEventLogErrorIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Error))
			{
				return IsEtwEventEnabled(trace, 6);
			}
			return true;
		}

		internal static void TraceCodeEventLogError(EtwDiagnosticTrace trace, TraceRecord traceRecord)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, traceRecord, null);
			if (IsEtwEventEnabled(trace, 6))
			{
				WriteEtwEvent(trace, 6, null, serializedPayload.ExtendedData, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Error))
			{
				string description = string.Format(Culture, ResourceManager.GetString("TraceCodeEventLogError", Culture));
				WriteTraceSource(trace, 6, description, serializedPayload);
			}
		}

		internal static bool TraceCodeEventLogInfoIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Informational))
			{
				return IsEtwEventEnabled(trace, 7);
			}
			return true;
		}

		internal static void TraceCodeEventLogInfo(EtwDiagnosticTrace trace, TraceRecord traceRecord)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, traceRecord, null);
			if (IsEtwEventEnabled(trace, 7))
			{
				WriteEtwEvent(trace, 7, null, serializedPayload.ExtendedData, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Informational))
			{
				string description = string.Format(Culture, ResourceManager.GetString("TraceCodeEventLogInfo", Culture));
				WriteTraceSource(trace, 7, description, serializedPayload);
			}
		}

		internal static bool TraceCodeEventLogVerboseIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Verbose))
			{
				return IsEtwEventEnabled(trace, 8);
			}
			return true;
		}

		internal static void TraceCodeEventLogVerbose(EtwDiagnosticTrace trace, TraceRecord traceRecord)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, traceRecord, null);
			if (IsEtwEventEnabled(trace, 8))
			{
				WriteEtwEvent(trace, 8, null, serializedPayload.ExtendedData, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Verbose))
			{
				string description = string.Format(Culture, ResourceManager.GetString("TraceCodeEventLogVerbose", Culture));
				WriteTraceSource(trace, 8, description, serializedPayload);
			}
		}

		internal static bool TraceCodeEventLogWarningIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Warning))
			{
				return IsEtwEventEnabled(trace, 9);
			}
			return true;
		}

		internal static void TraceCodeEventLogWarning(EtwDiagnosticTrace trace, TraceRecord traceRecord)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, traceRecord, null);
			if (IsEtwEventEnabled(trace, 9))
			{
				WriteEtwEvent(trace, 9, null, serializedPayload.ExtendedData, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Warning))
			{
				string description = string.Format(Culture, ResourceManager.GetString("TraceCodeEventLogWarning", Culture));
				WriteTraceSource(trace, 9, description, serializedPayload);
			}
		}

		internal static bool HandledExceptionWarningIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Warning))
			{
				return IsEtwEventEnabled(trace, 10);
			}
			return true;
		}

		internal static void HandledExceptionWarning(EtwDiagnosticTrace trace, string param0, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 10))
			{
				WriteEtwEvent(trace, 10, null, param0, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Warning))
			{
				string description = string.Format(Culture, ResourceManager.GetString("HandledExceptionWarning", Culture), new object[1] { param0 });
				WriteTraceSource(trace, 10, description, serializedPayload);
			}
		}

		internal static bool BufferPoolAllocationIsEnabled(EtwDiagnosticTrace trace)
		{
			return IsEtwEventEnabled(trace, 11);
		}

		internal static void BufferPoolAllocation(EtwDiagnosticTrace trace, int Size)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, null);
			if (IsEtwEventEnabled(trace, 11))
			{
				WriteEtwEvent(trace, 11, null, Size, serializedPayload.AppDomainFriendlyName);
			}
		}

		internal static bool BufferPoolChangeQuotaIsEnabled(EtwDiagnosticTrace trace)
		{
			return IsEtwEventEnabled(trace, 12);
		}

		internal static void BufferPoolChangeQuota(EtwDiagnosticTrace trace, int PoolSize, int Delta)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, null);
			if (IsEtwEventEnabled(trace, 12))
			{
				WriteEtwEvent(trace, 12, null, PoolSize, Delta, serializedPayload.AppDomainFriendlyName);
			}
		}

		internal static bool ActionItemScheduledIsEnabled(EtwDiagnosticTrace trace)
		{
			return IsEtwEventEnabled(trace, 13);
		}

		internal static void ActionItemScheduled(EtwDiagnosticTrace trace, EventTraceActivity eventTraceActivity)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, null);
			if (IsEtwEventEnabled(trace, 13))
			{
				WriteEtwEvent(trace, 13, eventTraceActivity, serializedPayload.AppDomainFriendlyName);
			}
		}

		internal static bool ActionItemCallbackInvokedIsEnabled(EtwDiagnosticTrace trace)
		{
			return IsEtwEventEnabled(trace, 14);
		}

		internal static void ActionItemCallbackInvoked(EtwDiagnosticTrace trace, EventTraceActivity eventTraceActivity)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, null);
			if (IsEtwEventEnabled(trace, 14))
			{
				WriteEtwEvent(trace, 14, eventTraceActivity, serializedPayload.AppDomainFriendlyName);
			}
		}

		internal static bool HandledExceptionErrorIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Error))
			{
				return IsEtwEventEnabled(trace, 15);
			}
			return true;
		}

		internal static void HandledExceptionError(EtwDiagnosticTrace trace, string param0, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 15))
			{
				WriteEtwEvent(trace, 15, null, param0, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Error))
			{
				string description = string.Format(Culture, ResourceManager.GetString("HandledExceptionError", Culture), new object[1] { param0 });
				WriteTraceSource(trace, 15, description, serializedPayload);
			}
		}

		internal static bool HandledExceptionVerboseIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Verbose))
			{
				return IsEtwEventEnabled(trace, 16);
			}
			return true;
		}

		internal static void HandledExceptionVerbose(EtwDiagnosticTrace trace, string param0, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 16))
			{
				WriteEtwEvent(trace, 16, null, param0, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Verbose))
			{
				string description = string.Format(Culture, ResourceManager.GetString("HandledExceptionVerbose", Culture), new object[1] { param0 });
				WriteTraceSource(trace, 16, description, serializedPayload);
			}
		}

		internal static bool EtwUnhandledExceptionIsEnabled(EtwDiagnosticTrace trace)
		{
			return IsEtwEventEnabled(trace, 17);
		}

		internal static void EtwUnhandledException(EtwDiagnosticTrace trace, string param0, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 17))
			{
				WriteEtwEvent(trace, 17, null, param0, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
		}

		internal static bool ThrowingEtwExceptionIsEnabled(EtwDiagnosticTrace trace)
		{
			return IsEtwEventEnabled(trace, 18);
		}

		internal static void ThrowingEtwException(EtwDiagnosticTrace trace, string param0, string param1, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 18))
			{
				WriteEtwEvent(trace, 18, null, param0, param1, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
		}

		internal static bool ThrowingEtwExceptionVerboseIsEnabled(EtwDiagnosticTrace trace)
		{
			return IsEtwEventEnabled(trace, 19);
		}

		internal static void ThrowingEtwExceptionVerbose(EtwDiagnosticTrace trace, string param0, string param1, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 19))
			{
				WriteEtwEvent(trace, 19, null, param0, param1, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
		}

		internal static bool ThrowingExceptionVerboseIsEnabled(EtwDiagnosticTrace trace)
		{
			if (!trace.ShouldTrace(TraceEventLevel.Verbose))
			{
				return IsEtwEventEnabled(trace, 20);
			}
			return true;
		}

		internal static void ThrowingExceptionVerbose(EtwDiagnosticTrace trace, string param0, string param1, Exception exception)
		{
			TracePayload serializedPayload = trace.GetSerializedPayload(null, null, exception);
			if (IsEtwEventEnabled(trace, 20))
			{
				WriteEtwEvent(trace, 20, null, param0, param1, serializedPayload.SerializedException, serializedPayload.AppDomainFriendlyName);
			}
			if (trace.ShouldTraceToTraceSource(TraceEventLevel.Verbose))
			{
				string description = string.Format(Culture, ResourceManager.GetString("ThrowingExceptionVerbose", Culture), new object[2] { param0, param1 });
				WriteTraceSource(trace, 20, description, serializedPayload);
			}
		}

		[SecuritySafeCritical]
		private static void CreateEventDescriptors()
		{
			eventDescriptors = new System.Runtime.Diagnostics.EventDescriptor[21]
			{
				new System.Runtime.Diagnostics.EventDescriptor(57393, 0, 19, 4, 0, 0, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(57394, 0, 18, 4, 0, 0, 2305843009213759488L),
				new System.Runtime.Diagnostics.EventDescriptor(57395, 0, 18, 2, 0, 0, 2305843009213759488L),
				new System.Runtime.Diagnostics.EventDescriptor(57396, 0, 18, 3, 0, 0, 2305843009213759488L),
				new System.Runtime.Diagnostics.EventDescriptor(57397, 0, 17, 1, 0, 0, 4611686018427453440L),
				new System.Runtime.Diagnostics.EventDescriptor(57399, 0, 19, 1, 0, 0, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(57400, 0, 19, 2, 0, 0, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(57401, 0, 19, 4, 0, 0, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(57402, 0, 19, 5, 0, 0, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(57403, 0, 19, 3, 0, 0, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(57404, 0, 18, 3, 0, 0, 2305843009213759488L),
				new System.Runtime.Diagnostics.EventDescriptor(131, 0, 19, 5, 12, 2509, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(132, 0, 19, 5, 13, 2509, 1152921504606912512L),
				new System.Runtime.Diagnostics.EventDescriptor(133, 0, 19, 5, 1, 2593, 1152921504608944128L),
				new System.Runtime.Diagnostics.EventDescriptor(134, 0, 19, 5, 2, 2593, 1152921504608944128L),
				new System.Runtime.Diagnostics.EventDescriptor(57405, 0, 17, 2, 0, 0, 4611686018427453440L),
				new System.Runtime.Diagnostics.EventDescriptor(57406, 0, 18, 5, 0, 0, 2305843009213759488L),
				new System.Runtime.Diagnostics.EventDescriptor(57408, 0, 17, 1, 0, 0, 4611686018427453440L),
				new System.Runtime.Diagnostics.EventDescriptor(57410, 0, 18, 3, 0, 0, 2305843009213759488L),
				new System.Runtime.Diagnostics.EventDescriptor(57409, 0, 18, 5, 0, 0, 2305843009213759488L),
				new System.Runtime.Diagnostics.EventDescriptor(57407, 0, 18, 5, 0, 0, 2305843009213759488L)
			};
		}

		private static void EnsureEventDescriptors()
		{
			if (eventDescriptorsCreated)
			{
				return;
			}
			Monitor.Enter(syncLock);
			try
			{
				if (!eventDescriptorsCreated)
				{
					CreateEventDescriptors();
					eventDescriptorsCreated = true;
				}
			}
			finally
			{
				Monitor.Exit(syncLock);
			}
		}

		[SecuritySafeCritical]
		private static bool IsEtwEventEnabled(EtwDiagnosticTrace trace, int eventIndex)
		{
			if (trace.IsEtwProviderEnabled)
			{
				EnsureEventDescriptors();
				return trace.IsEtwEventEnabled(ref eventDescriptors[eventIndex], fullCheck: false);
			}
			return false;
		}

		[SecuritySafeCritical]
		private static bool WriteEtwEvent(EtwDiagnosticTrace trace, int eventIndex, EventTraceActivity eventParam0, string eventParam1, string eventParam2, string eventParam3, string eventParam4)
		{
			EnsureEventDescriptors();
			return trace.EtwProvider.WriteEvent(ref eventDescriptors[eventIndex], eventParam0, eventParam1, eventParam2, eventParam3, eventParam4);
		}

		[SecuritySafeCritical]
		private static bool WriteEtwEvent(EtwDiagnosticTrace trace, int eventIndex, EventTraceActivity eventParam0, string eventParam1, string eventParam2, string eventParam3)
		{
			EnsureEventDescriptors();
			return trace.EtwProvider.WriteEvent(ref eventDescriptors[eventIndex], eventParam0, eventParam1, eventParam2, eventParam3);
		}

		[SecuritySafeCritical]
		private static bool WriteEtwEvent(EtwDiagnosticTrace trace, int eventIndex, EventTraceActivity eventParam0, string eventParam1, string eventParam2)
		{
			EnsureEventDescriptors();
			return trace.EtwProvider.WriteEvent(ref eventDescriptors[eventIndex], eventParam0, eventParam1, eventParam2);
		}

		[SecuritySafeCritical]
		private static bool WriteEtwEvent(EtwDiagnosticTrace trace, int eventIndex, EventTraceActivity eventParam0, int eventParam1, string eventParam2)
		{
			EnsureEventDescriptors();
			return trace.EtwProvider.WriteEvent(ref eventDescriptors[eventIndex], eventParam0, eventParam1, eventParam2);
		}

		[SecuritySafeCritical]
		private static bool WriteEtwEvent(EtwDiagnosticTrace trace, int eventIndex, EventTraceActivity eventParam0, int eventParam1, int eventParam2, string eventParam3)
		{
			EnsureEventDescriptors();
			return trace.EtwProvider.WriteEvent(ref eventDescriptors[eventIndex], eventParam0, eventParam1, eventParam2, eventParam3);
		}

		[SecuritySafeCritical]
		private static bool WriteEtwEvent(EtwDiagnosticTrace trace, int eventIndex, EventTraceActivity eventParam0, string eventParam1)
		{
			EnsureEventDescriptors();
			return trace.EtwProvider.WriteEvent(ref eventDescriptors[eventIndex], eventParam0, eventParam1);
		}

		[SecuritySafeCritical]
		private static void WriteTraceSource(EtwDiagnosticTrace trace, int eventIndex, string description, TracePayload payload)
		{
			EnsureEventDescriptors();
			trace.WriteTraceSource(ref eventDescriptors[eventIndex], description, payload);
		}
	}
}
namespace System.Runtime.Interop
{
	[SuppressUnmanagedCodeSecurity]
	internal static class UnsafeNativeMethods
	{
		[StructLayout(LayoutKind.Explicit, Size = 16)]
		public struct EventData
		{
			[FieldOffset(0)]
			internal ulong DataPointer;

			[FieldOffset(8)]
			internal uint Size;

			[FieldOffset(12)]
			internal int Reserved;
		}

		[SecurityCritical]
		internal unsafe delegate void EtwEnableCallback([In] ref Guid sourceId, [In] int isEnabled, [In] byte level, [In] long matchAnyKeywords, [In] long matchAllKeywords, [In] void* filterData, [In] void* callbackContext);

		public const string KERNEL32 = "kernel32.dll";

		public const string ADVAPI32 = "advapi32.dll";

		public const int ERROR_INVALID_HANDLE = 6;

		public const int ERROR_MORE_DATA = 234;

		public const int ERROR_ARITHMETIC_OVERFLOW = 534;

		public const int ERROR_NOT_ENOUGH_MEMORY = 8;

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto)]
		[SecurityCritical]
		public static extern SafeWaitHandle CreateWaitableTimer(IntPtr mustBeZero, bool manualReset, string timerName);

		[DllImport("kernel32.dll", ExactSpelling = true)]
		[SecurityCritical]
		public static extern bool SetWaitableTimer(SafeWaitHandle handle, ref long dueTime, int period, IntPtr mustBeZero, IntPtr mustBeZeroAlso, bool resume);

		[DllImport("kernel32.dll", SetLastError = true)]
		[SecurityCritical]
		public static extern int QueryPerformanceCounter(out long time);

		[DllImport("kernel32.dll")]
		[SecurityCritical]
		public static extern uint GetSystemTimeAdjustment(out int adjustment, out uint increment, out uint adjustmentDisabled);

		[DllImport("kernel32.dll", SetLastError = true)]
		[SecurityCritical]
		private static extern void GetSystemTimeAsFileTime(out System.Runtime.InteropServices.ComTypes.FILETIME time);

		[SecurityCritical]
		public static void GetSystemTimeAsFileTime(out long time)
		{
			GetSystemTimeAsFileTime(out System.Runtime.InteropServices.ComTypes.FILETIME time2);
			time = 0L;
			time |= (uint)time2.dwHighDateTime;
			time <<= 32;
			time |= (uint)time2.dwLowDateTime;
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		[SecurityCritical]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool GetComputerNameEx([In] ComputerNameFormat nameType, [In][Out][MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpBuffer, [In][Out] ref int size);

		[SecurityCritical]
		internal static string GetComputerName(ComputerNameFormat nameType)
		{
			int size = 0;
			if (!GetComputerNameEx(nameType, null, ref size))
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if (lastWin32Error != 234)
				{
					throw Fx.Exception.AsError(new Win32Exception(lastWin32Error));
				}
			}
			if (size < 0)
			{
				Fx.AssertAndThrow("GetComputerName returned an invalid length: " + size);
			}
			StringBuilder stringBuilder = new StringBuilder(size);
			if (!GetComputerNameEx(nameType, stringBuilder, ref size))
			{
				int lastWin32Error2 = Marshal.GetLastWin32Error();
				throw Fx.Exception.AsError(new Win32Exception(lastWin32Error2));
			}
			return stringBuilder.ToString();
		}

		[DllImport("kernel32.dll")]
		[SecurityCritical]
		internal static extern bool IsDebuggerPresent();

		[DllImport("kernel32.dll")]
		[SecurityCritical]
		internal static extern void DebugBreak();

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		[SecurityCritical]
		internal static extern void OutputDebugString(string lpOutputString);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		[SecurityCritical]
		internal unsafe static extern uint EventRegister([In] ref Guid providerId, [In] EtwEnableCallback enableCallback, [In] void* callbackContext, [In][Out] ref long registrationHandle);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		[SecurityCritical]
		internal static extern uint EventUnregister([In] long registrationHandle);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		[SecurityCritical]
		internal static extern bool EventEnabled([In] long registrationHandle, [In] ref System.Runtime.Diagnostics.EventDescriptor eventDescriptor);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		[SecurityCritical]
		internal unsafe static extern uint EventWrite([In] long registrationHandle, [In] ref System.Runtime.Diagnostics.EventDescriptor eventDescriptor, [In] uint userDataCount, [In] EventData* userData);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		[SecurityCritical]
		internal unsafe static extern uint EventWriteTransfer([In] long registrationHandle, [In] ref System.Runtime.Diagnostics.EventDescriptor eventDescriptor, [In] ref Guid activityId, [In] ref Guid relatedActivityId, [In] uint userDataCount, [In] EventData* userData);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		[SecurityCritical]
		internal unsafe static extern uint EventWriteString([In] long registrationHandle, [In] byte level, [In] long keywords, [In] char* message);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		[SecurityCritical]
		internal static extern uint EventActivityIdControl([In] int ControlCode, [In][Out] ref Guid ActivityId);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[SecurityCritical]
		internal static extern bool ReportEvent(SafeHandle hEventLog, ushort type, ushort category, uint eventID, byte[] userSID, ushort numStrings, uint dataLen, HandleRef strings, byte[] rawData);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[SecurityCritical]
		internal static extern SafeEventLogWriteHandle RegisterEventSource(string uncServerName, string sourceName);
	}
	[SecurityCritical]
	internal sealed class SafeEventLogWriteHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		[SecurityCritical]
		private SafeEventLogWriteHandle()
			: base(ownsHandle: true)
		{
		}

		[SecurityCritical]
		public static SafeEventLogWriteHandle RegisterEventSource(string uncServerName, string sourceName)
		{
			SafeEventLogWriteHandle safeEventLogWriteHandle = UnsafeNativeMethods.RegisterEventSource(uncServerName, sourceName);
			int lastWin32Error = Marshal.GetLastWin32Error();
			_ = safeEventLogWriteHandle.IsInvalid;
			return safeEventLogWriteHandle;
		}

		[DllImport("advapi32", SetLastError = true)]
		private static extern bool DeregisterEventSource(IntPtr hEventLog);

		[SecurityCritical]
		protected override bool ReleaseHandle()
		{
			return DeregisterEventSource(handle);
		}
	}
}
namespace System.Runtime.Diagnostics
{
	internal enum ActivityControl : uint
	{
		EVENT_ACTIVITY_CTRL_GET_ID = 1u,
		EVENT_ACTIVITY_CTRL_SET_ID,
		EVENT_ACTIVITY_CTRL_CREATE_ID,
		EVENT_ACTIVITY_CTRL_GET_SET_ID,
		EVENT_ACTIVITY_CTRL_CREATE_SET_ID
	}
	internal abstract class DiagnosticTraceBase
	{
		protected const string DefaultTraceListenerName = "Default";

		protected const string TraceRecordVersion = "http://schemas.microsoft.com/2004/10/E2ETraceEvent/TraceRecord";

		protected static string AppDomainFriendlyName = AppDomain.CurrentDomain.FriendlyName;

		private const ushort TracingEventLogCategory = 4;

		private object thisLock;

		private bool tracingEnabled = true;

		private bool calledShutdown;

		private bool haveListeners;

		private SourceLevels level;

		protected string TraceSourceName;

		private TraceSource traceSource;

		[SecurityCritical]
		private string eventSourceName;

		protected DateTime LastFailure { get; set; }

		public TraceSource TraceSource
		{
			get
			{
				return traceSource;
			}
			set
			{
				SetTraceSource(value);
			}
		}

		public bool HaveListeners => haveListeners;

		public SourceLevels Level
		{
			get
			{
				if (TraceSource != null && TraceSource.Switch.Level != level)
				{
					level = TraceSource.Switch.Level;
				}
				return level;
			}
			[SecurityCritical]
			set
			{
				SetLevelThreadSafe(value);
			}
		}

		protected string EventSourceName
		{
			[SecuritySafeCritical]
			get
			{
				return eventSourceName;
			}
			[SecurityCritical]
			set
			{
				eventSourceName = value;
			}
		}

		public bool TracingEnabled
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

		protected static string ProcessName
		{
			[SecuritySafeCritical]
			get
			{
				string text = null;
				using Process process = Process.GetCurrentProcess();
				return process.ProcessName;
			}
		}

		protected static int ProcessId
		{
			[SecuritySafeCritical]
			get
			{
				int num = -1;
				using Process process = Process.GetCurrentProcess();
				return process.Id;
			}
		}

		protected bool CalledShutdown => calledShutdown;

		public static Guid ActivityId
		{
			[SecuritySafeCritical]
			get
			{
				object obj = Trace.CorrelationManager.ActivityId;
				if (obj != null)
				{
					return (Guid)obj;
				}
				return Guid.Empty;
			}
			[SecuritySafeCritical]
			set
			{
				Trace.CorrelationManager.ActivityId = value;
			}
		}

		public DiagnosticTraceBase(string traceSourceName)
		{
			thisLock = new object();
			TraceSourceName = traceSourceName;
			LastFailure = DateTime.MinValue;
		}

		[SecurityCritical]
		[SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
		private static void UnsafeRemoveDefaultTraceListener(TraceSource traceSource)
		{
			traceSource.Listeners.Remove("Default");
		}

		[SecuritySafeCritical]
		protected void SetTraceSource(TraceSource traceSource)
		{
			if (traceSource != null)
			{
				UnsafeRemoveDefaultTraceListener(traceSource);
				this.traceSource = traceSource;
				haveListeners = this.traceSource.Listeners.Count > 0;
			}
		}

		private SourceLevels FixLevel(SourceLevels level)
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
			if (level == SourceLevels.ActivityTracing)
			{
				level = SourceLevels.Off;
			}
			return level;
		}

		protected virtual void OnSetLevel(SourceLevels level)
		{
		}

		[SecurityCritical]
		private void SetLevel(SourceLevels level)
		{
			SourceLevels sourceLevels = (this.level = FixLevel(level));
			if (TraceSource != null)
			{
				haveListeners = TraceSource.Listeners.Count > 0;
				OnSetLevel(level);
				tracingEnabled = HaveListeners && level != SourceLevels.Off;
				TraceSource.Switch.Level = level;
			}
		}

		[SecurityCritical]
		private void SetLevelThreadSafe(SourceLevels level)
		{
			lock (thisLock)
			{
				SetLevel(level);
			}
		}

		public virtual bool ShouldTrace(TraceEventLevel level)
		{
			return ShouldTraceToTraceSource(level);
		}

		public bool ShouldTrace(TraceEventType type)
		{
			if (TracingEnabled && HaveListeners && TraceSource != null)
			{
				return ((uint)type & (uint)Level) != 0;
			}
			return false;
		}

		public bool ShouldTraceToTraceSource(TraceEventLevel level)
		{
			return ShouldTrace(TraceLevelHelper.GetTraceEventType(level));
		}

		public static string XmlEncode(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return text;
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

		[SecuritySafeCritical]
		protected void AddDomainEventHandlersForCleanup()
		{
			AppDomain currentDomain = AppDomain.CurrentDomain;
			if (TraceSource != null)
			{
				haveListeners = TraceSource.Listeners.Count > 0;
			}
			tracingEnabled = haveListeners;
			if (TracingEnabled)
			{
				currentDomain.UnhandledException += UnhandledExceptionHandler;
				SetLevel(TraceSource.Switch.Level);
				currentDomain.DomainUnload += ExitOrUnloadEventHandler;
				currentDomain.ProcessExit += ExitOrUnloadEventHandler;
			}
		}

		private void ExitOrUnloadEventHandler(object sender, EventArgs e)
		{
			ShutdownTracing();
		}

		protected abstract void OnUnhandledException(Exception exception);

		protected void UnhandledExceptionHandler(object sender, UnhandledExceptionEventArgs args)
		{
			Exception exception = (Exception)args.ExceptionObject;
			OnUnhandledException(exception);
			ShutdownTracing();
		}

		protected static string CreateSourceString(object source)
		{
			if (source is ITraceSourceStringProvider traceSourceStringProvider)
			{
				return traceSourceStringProvider.GetSourceString();
			}
			return CreateDefaultSourceString(source);
		}

		internal static string CreateDefaultSourceString(object source)
		{
			if (source == null)
			{
				throw new ArgumentNullException("source");
			}
			return string.Format(CultureInfo.CurrentCulture, "{0}/{1}", new object[2]
			{
				source.GetType().ToString(),
				source.GetHashCode()
			});
		}

		protected static void AddExceptionToTraceString(XmlWriter xml, Exception exception)
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

		protected static string StackTraceString(Exception exception)
		{
			string text = exception.StackTrace;
			if (string.IsNullOrEmpty(text))
			{
				StackTrace stackTrace = new StackTrace(fNeedFileInfo: false);
				StackFrame[] frames = stackTrace.GetFrames();
				int num = 0;
				bool flag = false;
				StackFrame[] array = frames;
				foreach (StackFrame stackFrame in array)
				{
					string name = stackFrame.GetMethod().Name;
					switch (name)
					{
					case "StackTraceString":
					case "AddExceptionToTraceString":
					case "BuildTrace":
					case "TraceEvent":
					case "TraceException":
					case "GetAdditionalPayload":
						num++;
						break;
					default:
						if (name.StartsWith("ThrowHelper", StringComparison.Ordinal))
						{
							num++;
						}
						else
						{
							flag = true;
						}
						break;
					}
					if (flag)
					{
						break;
					}
				}
				stackTrace = new StackTrace(num, fNeedFileInfo: false);
				text = stackTrace.ToString();
			}
			return text;
		}

		[SecuritySafeCritical]
		protected void LogTraceFailure(string traceString, Exception exception)
		{
			TimeSpan timeSpan = TimeSpan.FromMinutes(10.0);
			try
			{
				lock (thisLock)
				{
					if (DateTime.UtcNow.Subtract(LastFailure) >= timeSpan)
					{
						LastFailure = DateTime.UtcNow;
						EventLogger eventLogger = EventLogger.UnsafeCreateEventLogger(eventSourceName, this);
						if (exception == null)
						{
							eventLogger.UnsafeLogEvent(TraceEventType.Error, 4, 3221291112u, false, traceString);
						}
						else
						{
							eventLogger.UnsafeLogEvent(TraceEventType.Error, 4, 3221291113u, false, traceString, exception.ToString());
						}
					}
				}
			}
			catch (Exception exception2)
			{
				if (Fx.IsFatal(exception2))
				{
					throw;
				}
			}
		}

		protected abstract void OnShutdownTracing();

		private void ShutdownTracing()
		{
			if (calledShutdown)
			{
				return;
			}
			calledShutdown = true;
			try
			{
				OnShutdownTracing();
			}
			catch (Exception exception)
			{
				if (Fx.IsFatal(exception))
				{
					throw;
				}
				LogTraceFailure(null, exception);
			}
		}

		protected static string LookupSeverity(TraceEventType type)
		{
			return type switch
			{
				TraceEventType.Critical => "Critical", 
				TraceEventType.Error => "Error", 
				TraceEventType.Warning => "Warning", 
				TraceEventType.Information => "Information", 
				TraceEventType.Verbose => "Verbose", 
				TraceEventType.Start => "Start", 
				TraceEventType.Stop => "Stop", 
				TraceEventType.Suspend => "Suspend", 
				TraceEventType.Transfer => "Transfer", 
				_ => type.ToString(), 
			};
		}

		public abstract bool IsEnabled();

		public abstract void TraceEventLogEvent(TraceEventType type, TraceRecord traceRecord);
	}
	internal class EventTraceActivity
	{
		public Guid ActivityId;

		private static EventTraceActivity empty;

		public static EventTraceActivity Empty
		{
			get
			{
				if (empty == null)
				{
					empty = new EventTraceActivity(Guid.Empty);
				}
				return empty;
			}
		}

		public static string Name => "E2EActivity";

		public EventTraceActivity(bool setOnThread = false)
			: this(Guid.NewGuid(), setOnThread)
		{
		}

		public EventTraceActivity(Guid guid, bool setOnThread = false)
		{
			ActivityId = guid;
			if (setOnThread)
			{
				SetActivityIdOnThread();
			}
		}

		[SecuritySafeCritical]
		public static EventTraceActivity GetFromThreadOrCreate(bool clearIdOnThread = false)
		{
			Guid guid = Trace.CorrelationManager.ActivityId;
			if (guid == Guid.Empty)
			{
				guid = Guid.NewGuid();
			}
			else if (clearIdOnThread)
			{
				Trace.CorrelationManager.ActivityId = Guid.Empty;
			}
			return new EventTraceActivity(guid);
		}

		[SecuritySafeCritical]
		public static Guid GetActivityIdFromThread()
		{
			return Trace.CorrelationManager.ActivityId;
		}

		public void SetActivityId(Guid guid)
		{
			ActivityId = guid;
		}

		[SecuritySafeCritical]
		private void SetActivityIdOnThread()
		{
			Trace.CorrelationManager.ActivityId = ActivityId;
		}
	}
	internal sealed class EtwDiagnosticTrace : DiagnosticTraceBase
	{
		private static class TraceCodes
		{
			public const string AppDomainUnload = "AppDomainUnload";

			public const string TraceHandledException = "TraceHandledException";

			public const string ThrowingException = "ThrowingException";

			public const string UnhandledException = "UnhandledException";
		}

		private static class EventIdsWithMsdnTraceCode
		{
			public const int AppDomainUnload = 57393;

			public const int ThrowingExceptionWarning = 57396;

			public const int ThrowingExceptionVerbose = 57407;

			public const int HandledExceptionInfo = 57394;

			public const int HandledExceptionWarning = 57404;

			public const int HandledExceptionError = 57405;

			public const int HandledExceptionVerbose = 57406;

			public const int UnhandledException = 57397;
		}

		private static class LegacyTraceEventIds
		{
			public const int Diagnostics = 131072;

			public const int AppDomainUnload = 131073;

			public const int EventLog = 131074;

			public const int ThrowingException = 131075;

			public const int TraceHandledException = 131076;

			public const int UnhandledException = 131077;
		}

		private static class StringBuilderPool
		{
			private const int maxPooledStringBuilders = 64;

			private static readonly ConcurrentQueue<StringBuilder> freeStringBuilders = new ConcurrentQueue<StringBuilder>();

			public static StringBuilder Take()
			{
				StringBuilder result = null;
				if (freeStringBuilders.TryDequeue(out result))
				{
					return result;
				}
				return new StringBuilder();
			}

			public static void Return(StringBuilder sb)
			{
				if (freeStringBuilders.Count <= 64)
				{
					sb.Clear();
					freeStringBuilders.Enqueue(sb);
				}
			}
		}

		private const int WindowsVistaMajorNumber = 6;

		private const string EventSourceVersion = "4.0.0.0";

		private const ushort TracingEventLogCategory = 4;

		private const int MaxExceptionStringLength = 28672;

		private const int MaxExceptionDepth = 64;

		private const string DiagnosticTraceSource = "System.ServiceModel.Diagnostics";

		private const int XmlBracketsLength = 5;

		private const int XmlBracketsLengthForNullValue = 4;

		public static readonly Guid ImmutableDefaultEtwProviderId;

		[SecurityCritical]
		private static Guid defaultEtwProviderId;

		private static Hashtable etwProviderCache;

		private static bool isVistaOrGreater;

		private static Func<string> traceAnnotation;

		[SecurityCritical]
		private EtwProvider etwProvider;

		private Guid etwProviderId;

		[SecurityCritical]
		private static EventDescriptor transferEventDescriptor;

		public static Guid DefaultEtwProviderId
		{
			[SecuritySafeCritical]
			get
			{
				return defaultEtwProviderId;
			}
			[SecurityCritical]
			set
			{
				defaultEtwProviderId = value;
			}
		}

		public EtwProvider EtwProvider
		{
			[SecurityCritical]
			get
			{
				return etwProvider;
			}
		}

		public bool IsEtwProviderEnabled
		{
			[SecuritySafeCritical]
			get
			{
				if (EtwTracingEnabled)
				{
					return etwProvider.IsEnabled();
				}
				return false;
			}
		}

		public Action RefreshState
		{
			[SecuritySafeCritical]
			get
			{
				return EtwProvider.ControllerCallBack;
			}
			[SecuritySafeCritical]
			set
			{
				EtwProvider.ControllerCallBack = value;
			}
		}

		public bool IsEnd2EndActivityTracingEnabled
		{
			[SecuritySafeCritical]
			get
			{
				if (IsEtwProviderEnabled)
				{
					return EtwProvider.IsEnd2EndActivityTracingEnabled;
				}
				return false;
			}
		}

		private bool EtwTracingEnabled
		{
			[SecuritySafeCritical]
			get
			{
				return etwProvider != null;
			}
		}

		[SecurityCritical]
		static EtwDiagnosticTrace()
		{
			ImmutableDefaultEtwProviderId = new Guid("{c651f5f6-1c0d-492e-8ae1-b4efd7c9d503}");
			defaultEtwProviderId = ImmutableDefaultEtwProviderId;
			etwProviderCache = new Hashtable();
			isVistaOrGreater = Environment.OSVersion.Version.Major >= 6;
			transferEventDescriptor = new EventDescriptor(499, 0, 18, 0, 0, 0, 2305843009215397989L);
			if (!PartialTrustHelpers.HasEtwPermissions())
			{
				defaultEtwProviderId = Guid.Empty;
			}
		}

		[SecurityCritical]
		public EtwDiagnosticTrace(string traceSourceName, Guid etwProviderId)
			: base(traceSourceName)
		{
			try
			{
				TraceSourceName = traceSourceName;
				base.EventSourceName = TraceSourceName + " " + "4.0.0.0";
				CreateTraceSource();
			}
			catch (Exception ex)
			{
				if (Fx.IsFatal(ex))
				{
					throw;
				}
				EventLogger eventLogger = new EventLogger(base.EventSourceName, null);
				eventLogger.LogEvent(TraceEventType.Error, 4, 3221291108u, false, ex.ToString());
			}
			try
			{
				CreateEtwProvider(etwProviderId);
			}
			catch (Exception ex2)
			{
				if (Fx.IsFatal(ex2))
				{
					throw;
				}
				etwProvider = null;
				EventLogger eventLogger2 = new EventLogger(base.EventSourceName, null);
				eventLogger2.LogEvent(TraceEventType.Error, 4, 3221291108u, false, ex2.ToString());
			}
			if (base.TracingEnabled || EtwTracingEnabled)
			{
				AddDomainEventHandlersForCleanup();
			}
		}

		[SecuritySafeCritical]
		public void SetEnd2EndActivityTracingEnabled(bool isEnd2EndTracingEnabled)
		{
			EtwProvider.SetEnd2EndActivityTracingEnabled(isEnd2EndTracingEnabled);
		}

		public void SetAnnotation(Func<string> annotation)
		{
			traceAnnotation = annotation;
		}

		public override bool ShouldTrace(TraceEventLevel level)
		{
			if (!base.ShouldTrace(level))
			{
				return ShouldTraceToEtw(level);
			}
			return true;
		}

		[SecuritySafeCritical]
		public bool ShouldTraceToEtw(TraceEventLevel level)
		{
			if (EtwProvider != null)
			{
				return EtwProvider.IsEnabled((byte)level, 0L);
			}
			return false;
		}

		[SecuritySafeCritical]
		public void Event(int eventId, TraceEventLevel traceEventLevel, TraceChannel channel, string description)
		{
			if (base.TracingEnabled)
			{
				EventDescriptor eventDescriptor = GetEventDescriptor(eventId, channel, traceEventLevel);
				Event(ref eventDescriptor, description);
			}
		}

		[SecurityCritical]
		public void Event(ref EventDescriptor eventDescriptor, string description)
		{
			if (base.TracingEnabled)
			{
				TracePayload serializedPayload = GetSerializedPayload(null, null, null);
				WriteTraceSource(ref eventDescriptor, description, serializedPayload);
			}
		}

		public void SetAndTraceTransfer(Guid newId, bool emitTransfer)
		{
			if (emitTransfer)
			{
				TraceTransfer(newId);
			}
			DiagnosticTraceBase.ActivityId = newId;
		}

		[SecuritySafeCritical]
		public void TraceTransfer(Guid newId)
		{
			Guid activityId = DiagnosticTraceBase.ActivityId;
			if (!(newId != activityId))
			{
				return;
			}
			try
			{
				if (base.HaveListeners)
				{
					base.TraceSource.TraceTransfer(0, null, newId);
				}
				if (IsEtwEventEnabled(ref transferEventDescriptor, fullCheck: false))
				{
					etwProvider.WriteTransferEvent(ref transferEventDescriptor, new EventTraceActivity(activityId), newId, (traceAnnotation == null) ? string.Empty : traceAnnotation(), DiagnosticTraceBase.AppDomainFriendlyName);
				}
			}
			catch (Exception exception)
			{
				if (Fx.IsFatal(exception))
				{
					throw;
				}
				LogTraceFailure(null, exception);
			}
		}

		[SecurityCritical]
		public void WriteTraceSource(ref EventDescriptor eventDescriptor, string description, TracePayload payload)
		{
			if (!base.TracingEnabled)
			{
				return;
			}
			XPathNavigator xPathNavigator = null;
			try
			{
				GenerateLegacyTraceCode(ref eventDescriptor, out var msdnTraceCode, out var legacyEventId);
				string xml = BuildTrace(ref eventDescriptor, description, payload, msdnTraceCode);
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.LoadXml(xml);
				xPathNavigator = xmlDocument.CreateNavigator();
				base.TraceSource.TraceData(TraceLevelHelper.GetTraceEventType(eventDescriptor.Level, eventDescriptor.Opcode), legacyEventId, xPathNavigator);
				if (base.CalledShutdown)
				{
					base.TraceSource.Flush();
				}
			}
			catch (Exception exception)
			{
				if (Fx.IsFatal(exception))
				{
					throw;
				}
				LogTraceFailure((xPathNavigator == null) ? string.Empty : xPathNavigator.ToString(), exception);
			}
		}

		[SecurityCritical]
		private static string BuildTrace(ref EventDescriptor eventDescriptor, string description, TracePayload payload, string msdnTraceCode)
		{
			StringBuilder stringBuilder = StringBuilderPool.Take();
			try
			{
				using StringWriter stringWriter = new StringWriter(stringBuilder, CultureInfo.CurrentCulture);
				using XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);
				xmlTextWriter.WriteStartElement("TraceRecord");
				xmlTextWriter.WriteAttributeString("xmlns", "http://schemas.microsoft.com/2004/10/E2ETraceEvent/TraceRecord");
				xmlTextWriter.WriteAttributeString("Severity", TraceLevelHelper.LookupSeverity((TraceEventLevel)eventDescriptor.Level, (TraceEventOpcode)eventDescriptor.Opcode));
				xmlTextWriter.WriteAttributeString("Channel", LookupChannel((TraceChannel)eventDescriptor.Channel));
				xmlTextWriter.WriteElementString("TraceIdentifier", msdnTraceCode);
				xmlTextWriter.WriteElementString("Description", description);
				xmlTextWriter.WriteElementString("AppDomain", payload.AppDomainFriendlyName);
				if (!string.IsNullOrEmpty(payload.EventSource))
				{
					xmlTextWriter.WriteElementString("Source", payload.EventSource);
				}
				if (!string.IsNullOrEmpty(payload.ExtendedData))
				{
					xmlTextWriter.WriteRaw(payload.ExtendedData);
				}
				if (!string.IsNullOrEmpty(payload.SerializedException))
				{
					xmlTextWriter.WriteRaw(payload.SerializedException);
				}
				xmlTextWriter.WriteEndElement();
				xmlTextWriter.Flush();
				stringWriter.Flush();
				return stringBuilder.ToString();
			}
			finally
			{
				StringBuilderPool.Return(stringBuilder);
			}
		}

		[SecurityCritical]
		private static void GenerateLegacyTraceCode(ref EventDescriptor eventDescriptor, out string msdnTraceCode, out int legacyEventId)
		{
			switch (eventDescriptor.EventId)
			{
			case 57393:
				msdnTraceCode = GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "AppDomainUnload");
				legacyEventId = 131073;
				break;
			case 57394:
			case 57404:
			case 57405:
			case 57406:
				msdnTraceCode = GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "TraceHandledException");
				legacyEventId = 131076;
				break;
			case 57396:
			case 57407:
				msdnTraceCode = GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "ThrowingException");
				legacyEventId = 131075;
				break;
			case 57397:
				msdnTraceCode = GenerateMsdnTraceCode("System.ServiceModel.Diagnostics", "UnhandledException");
				legacyEventId = 131077;
				break;
			default:
				msdnTraceCode = eventDescriptor.EventId.ToString(CultureInfo.InvariantCulture);
				legacyEventId = eventDescriptor.EventId;
				break;
			}
		}

		private static string GenerateMsdnTraceCode(string traceSource, string traceCodeString)
		{
			return string.Format(CultureInfo.InvariantCulture, "https://docs.microsoft.com/dotnet/framework/wcf/diagnostics/tracing/{0}-{1}", new object[2]
			{
				traceSource.Replace('.', '-'),
				traceCodeString
			});
		}

		private static string LookupChannel(TraceChannel traceChannel)
		{
			return traceChannel switch
			{
				TraceChannel.Admin => "Admin", 
				TraceChannel.Analytic => "Analytic", 
				TraceChannel.Application => "Application", 
				TraceChannel.Debug => "Debug", 
				TraceChannel.Operational => "Operational", 
				TraceChannel.Perf => "Perf", 
				_ => traceChannel.ToString(), 
			};
		}

		public TracePayload GetSerializedPayload(object source, TraceRecord traceRecord, Exception exception)
		{
			return GetSerializedPayload(source, traceRecord, exception, getServiceReference: false);
		}

		public TracePayload GetSerializedPayload(object source, TraceRecord traceRecord, Exception exception, bool getServiceReference)
		{
			string eventSource = null;
			string extendedData = null;
			string serializedException = null;
			if (source != null)
			{
				eventSource = DiagnosticTraceBase.CreateSourceString(source);
			}
			if (traceRecord != null)
			{
				StringBuilder stringBuilder = StringBuilderPool.Take();
				try
				{
					using StringWriter stringWriter = new StringWriter(stringBuilder, CultureInfo.CurrentCulture);
					using XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);
					xmlTextWriter.WriteStartElement("ExtendedData");
					traceRecord.WriteTo(xmlTextWriter);
					xmlTextWriter.WriteEndElement();
					xmlTextWriter.Flush();
					stringWriter.Flush();
					extendedData = stringBuilder.ToString();
				}
				finally
				{
					StringBuilderPool.Return(stringBuilder);
				}
			}
			if (exception != null)
			{
				serializedException = ExceptionToTraceString(exception, 28672);
			}
			if (getServiceReference && traceAnnotation != null)
			{
				return new TracePayload(serializedException, eventSource, DiagnosticTraceBase.AppDomainFriendlyName, extendedData, traceAnnotation());
			}
			return new TracePayload(serializedException, eventSource, DiagnosticTraceBase.AppDomainFriendlyName, extendedData, string.Empty);
		}

		[SecuritySafeCritical]
		public bool IsEtwEventEnabled(ref EventDescriptor eventDescriptor)
		{
			return IsEtwEventEnabled(ref eventDescriptor, fullCheck: true);
		}

		[SecuritySafeCritical]
		public bool IsEtwEventEnabled(ref EventDescriptor eventDescriptor, bool fullCheck)
		{
			if (fullCheck)
			{
				if (EtwTracingEnabled)
				{
					return etwProvider.IsEventEnabled(ref eventDescriptor);
				}
				return false;
			}
			if (EtwTracingEnabled)
			{
				return etwProvider.IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords);
			}
			return false;
		}

		[SecuritySafeCritical]
		private void CreateTraceSource()
		{
			if (!string.IsNullOrEmpty(TraceSourceName))
			{
				SetTraceSource(new DiagnosticTraceSource(TraceSourceName));
			}
		}

		[SecurityCritical]
		private void CreateEtwProvider(Guid etwProviderId)
		{
			if (!(etwProviderId != Guid.Empty) || !isVistaOrGreater)
			{
				return;
			}
			etwProvider = (EtwProvider)etwProviderCache[etwProviderId];
			if (etwProvider == null)
			{
				lock (etwProviderCache)
				{
					etwProvider = (EtwProvider)etwProviderCache[etwProviderId];
					if (etwProvider == null)
					{
						etwProvider = new EtwProvider(etwProviderId);
						etwProviderCache.Add(etwProviderId, etwProvider);
					}
				}
			}
			this.etwProviderId = etwProviderId;
		}

		[SecurityCritical]
		private static EventDescriptor GetEventDescriptor(int eventId, TraceChannel channel, TraceEventLevel traceEventLevel)
		{
			long num = 0L;
			switch (channel)
			{
			case TraceChannel.Admin:
				num |= long.MinValue;
				break;
			case TraceChannel.Operational:
				num |= 0x4000000000000000L;
				break;
			case TraceChannel.Analytic:
				num |= 0x2000000000000000L;
				break;
			case TraceChannel.Debug:
				num |= 0x100000000000000L;
				break;
			case TraceChannel.Perf:
				num |= 0x800000000000000L;
				break;
			}
			return new EventDescriptor(eventId, 0, (byte)channel, (byte)traceEventLevel, 0, 0, num);
		}

		protected override void OnShutdownTracing()
		{
			ShutdownTraceSource();
			ShutdownEtwProvider();
		}

		private void ShutdownTraceSource()
		{
			try
			{
				if (TraceCore.AppDomainUnloadIsEnabled(this))
				{
					TraceCore.AppDomainUnload(this, AppDomain.CurrentDomain.FriendlyName, DiagnosticTraceBase.ProcessName, DiagnosticTraceBase.ProcessId.ToString(CultureInfo.CurrentCulture));
				}
				base.TraceSource.Flush();
			}
			catch (Exception exception)
			{
				if (Fx.IsFatal(exception))
				{
					throw;
				}
				LogTraceFailure(null, exception);
			}
		}

		[SecuritySafeCritical]
		private void ShutdownEtwProvider()
		{
			try
			{
				if (etwProvider != null)
				{
					etwProvider.Dispose();
				}
			}
			catch (Exception exception)
			{
				if (Fx.IsFatal(exception))
				{
					throw;
				}
				LogTraceFailure(null, exception);
			}
		}

		public override bool IsEnabled()
		{
			if (!TraceCore.TraceCodeEventLogCriticalIsEnabled(this) && !TraceCore.TraceCodeEventLogVerboseIsEnabled(this) && !TraceCore.TraceCodeEventLogInfoIsEnabled(this) && !TraceCore.TraceCodeEventLogWarningIsEnabled(this))
			{
				return TraceCore.TraceCodeEventLogErrorIsEnabled(this);
			}
			return true;
		}

		public override void TraceEventLogEvent(TraceEventType type, TraceRecord traceRecord)
		{
			switch (type)
			{
			case TraceEventType.Critical:
				if (TraceCore.TraceCodeEventLogCriticalIsEnabled(this))
				{
					TraceCore.TraceCodeEventLogCritical(this, traceRecord);
				}
				break;
			case TraceEventType.Verbose:
				if (TraceCore.TraceCodeEventLogVerboseIsEnabled(this))
				{
					TraceCore.TraceCodeEventLogVerbose(this, traceRecord);
				}
				break;
			case TraceEventType.Information:
				if (TraceCore.TraceCodeEventLogInfoIsEnabled(this))
				{
					TraceCore.TraceCodeEventLogInfo(this, traceRecord);
				}
				break;
			case TraceEventType.Warning:
				if (TraceCore.TraceCodeEventLogWarningIsEnabled(this))
				{
					TraceCore.TraceCodeEventLogWarning(this, traceRecord);
				}
				break;
			case TraceEventType.Error:
				if (TraceCore.TraceCodeEventLogErrorIsEnabled(this))
				{
					TraceCore.TraceCodeEventLogError(this, traceRecord);
				}
				break;
			}
		}

		protected override void OnUnhandledException(Exception exception)
		{
			if (TraceCore.UnhandledExceptionIsEnabled(this))
			{
				TraceCore.UnhandledException(this, (exception != null) ? exception.ToString() : string.Empty, exception);
			}
		}

		internal static string ExceptionToTraceString(Exception exception, int maxTraceStringLength)
		{
			StringBuilder stringBuilder = StringBuilderPool.Take();
			try
			{
				using StringWriter stringWriter = new StringWriter(stringBuilder, CultureInfo.CurrentCulture);
				using XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);
				WriteExceptionToTraceString(xmlTextWriter, exception, maxTraceStringLength, 64);
				xmlTextWriter.Flush();
				stringWriter.Flush();
				return stringBuilder.ToString();
			}
			finally
			{
				StringBuilderPool.Return(stringBuilder);
			}
		}

		private static void WriteExceptionToTraceString(XmlTextWriter xml, Exception exception, int remainingLength, int remainingAllowedRecursionDepth)
		{
			if (remainingAllowedRecursionDepth < 1 || !WriteStartElement(xml, "Exception", ref remainingLength))
			{
				return;
			}
			try
			{
				IList<Tuple<string, string>> list = new List<Tuple<string, string>>
				{
					new Tuple<string, string>("ExceptionType", DiagnosticTraceBase.XmlEncode(exception.GetType().AssemblyQualifiedName)),
					new Tuple<string, string>("Message", DiagnosticTraceBase.XmlEncode(exception.Message)),
					new Tuple<string, string>("StackTrace", DiagnosticTraceBase.XmlEncode(DiagnosticTraceBase.StackTraceString(exception))),
					new Tuple<string, string>("ExceptionString", DiagnosticTraceBase.XmlEncode(exception.ToString()))
				};
				if (exception is Win32Exception ex)
				{
					list.Add(new Tuple<string, string>("NativeErrorCode", ex.NativeErrorCode.ToString("X", CultureInfo.InvariantCulture)));
				}
				foreach (Tuple<string, string> item in list)
				{
					if (!WriteXmlElementString(xml, item.Item1, item.Item2, ref remainingLength))
					{
						return;
					}
				}
				if (exception.Data != null && exception.Data.Count > 0)
				{
					string exceptionData = GetExceptionData(exception);
					if (exceptionData.Length < remainingLength)
					{
						xml.WriteRaw(exceptionData);
						remainingLength -= exceptionData.Length;
					}
				}
				if (exception.InnerException != null)
				{
					string innerException = GetInnerException(exception, remainingLength, remainingAllowedRecursionDepth - 1);
					if (!string.IsNullOrEmpty(innerException) && innerException.Length < remainingLength)
					{
						xml.WriteRaw(innerException);
					}
				}
			}
			finally
			{
				xml.WriteEndElement();
			}
		}

		private static string GetInnerException(Exception exception, int remainingLength, int remainingAllowedRecursionDepth)
		{
			if (remainingAllowedRecursionDepth < 1)
			{
				return null;
			}
			StringBuilder stringBuilder = StringBuilderPool.Take();
			try
			{
				using StringWriter stringWriter = new StringWriter(stringBuilder, CultureInfo.CurrentCulture);
				using XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);
				if (!WriteStartElement(xmlTextWriter, "InnerException", ref remainingLength))
				{
					return null;
				}
				WriteExceptionToTraceString(xmlTextWriter, exception.InnerException, remainingLength, remainingAllowedRecursionDepth);
				xmlTextWriter.WriteEndElement();
				xmlTextWriter.Flush();
				stringWriter.Flush();
				return stringBuilder.ToString();
			}
			finally
			{
				StringBuilderPool.Return(stringBuilder);
			}
		}

		private static string GetExceptionData(Exception exception)
		{
			StringBuilder stringBuilder = StringBuilderPool.Take();
			try
			{
				using StringWriter stringWriter = new StringWriter(stringBuilder, CultureInfo.CurrentCulture);
				using XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);
				xmlTextWriter.WriteStartElement("DataItems");
				foreach (object key in exception.Data.Keys)
				{
					xmlTextWriter.WriteStartElement("Data");
					xmlTextWriter.WriteElementString("Key", DiagnosticTraceBase.XmlEncode(key.ToString()));
					if (exception.Data[key] == null)
					{
						xmlTextWriter.WriteElementString("Value", string.Empty);
					}
					else
					{
						xmlTextWriter.WriteElementString("Value", DiagnosticTraceBase.XmlEncode(exception.Data[key].ToString()));
					}
					xmlTextWriter.WriteEndElement();
				}
				xmlTextWriter.WriteEndElement();
				xmlTextWriter.Flush();
				stringWriter.Flush();
				return stringBuilder.ToString();
			}
			finally
			{
				StringBuilderPool.Return(stringBuilder);
			}
		}

		private static bool WriteStartElement(XmlTextWriter xml, string localName, ref int remainingLength)
		{
			int num = localName.Length * 2 + 5;
			if (num <= remainingLength)
			{
				xml.WriteStartElement(localName);
				remainingLength -= num;
				return true;
			}
			return false;
		}

		private static bool WriteXmlElementString(XmlTextWriter xml, string localName, string value, ref int remainingLength)
		{
			int num = ((!string.IsNullOrEmpty(value) || System.ServiceModel.Internals.LocalAppContextSwitches.IncludeNullExceptionMessageInETWTrace) ? (localName.Length * 2 + 5 + value.Length) : (localName.Length + 4));
			if (num <= remainingLength)
			{
				xml.WriteElementString(localName, value);
				remainingLength -= num;
				return true;
			}
			return false;
		}
	}
	[Serializable]
	internal class TraceRecord
	{
		protected const string EventIdBase = "http://schemas.microsoft.com/2006/08/ServiceModel/";

		protected const string NamespaceSuffix = "TraceRecord";

		internal virtual string EventId => BuildEventId("Empty");

		internal virtual void WriteTo(XmlWriter writer)
		{
		}

		protected string BuildEventId(string eventId)
		{
			return "http://schemas.microsoft.com/2006/08/ServiceModel/" + eventId + "TraceRecord";
		}

		protected string XmlEncode(string text)
		{
			return DiagnosticTraceBase.XmlEncode(text);
		}
	}
	internal class StringTraceRecord : TraceRecord
	{
		private string elementName;

		private string content;

		internal override string EventId => BuildEventId("String");

		internal StringTraceRecord(string elementName, string content)
		{
			this.elementName = elementName;
			this.content = content;
		}

		internal override void WriteTo(XmlWriter writer)
		{
			writer.WriteElementString(elementName, content);
		}
	}
	internal class DictionaryTraceRecord : TraceRecord
	{
		private IDictionary dictionary;

		internal override string EventId => "http://schemas.microsoft.com/2006/08/ServiceModel/DictionaryTraceRecord";

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
				object obj = dictionary[key];
				xml.WriteElementString(key.ToString(), (obj == null) ? string.Empty : obj.ToString());
			}
		}
	}
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	internal abstract class DiagnosticsEventProvider : IDisposable
	{
		public enum WriteEventErrorCode
		{
			NoError,
			NoFreeBuffers,
			EventTooBig
		}

		[SecurityCritical]
		private UnsafeNativeMethods.EtwEnableCallback etwCallback;

		private long traceRegistrationHandle;

		private byte currentTraceLevel;

		private long anyKeywordMask;

		private long allKeywordMask;

		private bool isProviderEnabled;

		private Guid providerId;

		private int isDisposed;

		[ThreadStatic]
		private static WriteEventErrorCode errorCode;

		private const int basicTypeAllocationBufferSize = 16;

		private const int etwMaxNumberArguments = 32;

		private const int etwAPIMaxStringCount = 8;

		private const int maxEventDataDescriptors = 128;

		private const int traceEventMaximumSize = 65482;

		private const int traceEventMaximumStringSize = 32724;

		private const int WindowsVistaMajorNumber = 6;

		[SecurityCritical]
		[PermissionSet(SecurityAction.Demand, Unrestricted = true)]
		protected DiagnosticsEventProvider(Guid providerGuid)
		{
			providerId = providerGuid;
			EtwRegister();
		}

		[SecurityCritical]
		private unsafe void EtwRegister()
		{
			etwCallback = EtwEnableCallBack;
			uint num = UnsafeNativeMethods.EventRegister(ref providerId, etwCallback, null, ref traceRegistrationHandle);
			if (num != 0)
			{
				throw new InvalidOperationException(InternalSR.EtwRegistrationFailed(num.ToString("x", CultureInfo.CurrentCulture)));
			}
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		[SecuritySafeCritical]
		protected virtual void Dispose(bool disposing)
		{
			if (isDisposed != 1 && Interlocked.Exchange(ref isDisposed, 1) == 0)
			{
				isProviderEnabled = false;
				Deregister();
			}
		}

		public virtual void Close()
		{
			Dispose();
		}

		~DiagnosticsEventProvider()
		{
			Dispose(disposing: false);
		}

		[SecurityCritical]
		private void Deregister()
		{
			if (traceRegistrationHandle != 0L)
			{
				UnsafeNativeMethods.EventUnregister(traceRegistrationHandle);
				traceRegistrationHandle = 0L;
			}
		}

		[SecurityCritical]
		private unsafe void EtwEnableCallBack([In] ref Guid sourceId, [In] int isEnabled, [In] byte setLevel, [In] long anyKeyword, [In] long allKeyword, [In] void* filterData, [In] void* callbackContext)
		{
			isProviderEnabled = isEnabled != 0;
			currentTraceLevel = setLevel;
			anyKeywordMask = anyKeyword;
			allKeywordMask = allKeyword;
			OnControllerCommand();
		}

		protected abstract void OnControllerCommand();

		public bool IsEnabled()
		{
			return isProviderEnabled;
		}

		public bool IsEnabled(byte level, long keywords)
		{
			if (isProviderEnabled && (level <= currentTraceLevel || currentTraceLevel == 0) && (keywords == 0L || ((keywords & anyKeywordMask) != 0L && (keywords & allKeywordMask) == allKeywordMask)))
			{
				return true;
			}
			return false;
		}

		[SecurityCritical]
		public bool IsEventEnabled(ref EventDescriptor eventDescriptor)
		{
			if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
			{
				return UnsafeNativeMethods.EventEnabled(traceRegistrationHandle, ref eventDescriptor);
			}
			return false;
		}

		public static WriteEventErrorCode GetLastWriteEventError()
		{
			return errorCode;
		}

		private static void SetLastError(int error)
		{
			switch (error)
			{
			case 234:
			case 534:
				errorCode = WriteEventErrorCode.EventTooBig;
				break;
			case 8:
				errorCode = WriteEventErrorCode.NoFreeBuffers;
				break;
			}
		}

		[SecurityCritical]
		private unsafe static string EncodeObject(ref object data, UnsafeNativeMethods.EventData* dataDescriptor, byte* dataBuffer)
		{
			dataDescriptor->Reserved = 0;
			if (data is string text)
			{
				dataDescriptor->Size = (uint)((text.Length + 1) * 2);
				return text;
			}
			if (data is IntPtr)
			{
				dataDescriptor->Size = (uint)sizeof(IntPtr);
				*(IntPtr*)dataBuffer = (IntPtr)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is int)
			{
				dataDescriptor->Size = 4u;
				*(int*)dataBuffer = (int)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is long)
			{
				dataDescriptor->Size = 8u;
				*(long*)dataBuffer = (long)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is uint)
			{
				dataDescriptor->Size = 4u;
				*(uint*)dataBuffer = (uint)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is ulong)
			{
				dataDescriptor->Size = 8u;
				*(ulong*)dataBuffer = (ulong)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is char)
			{
				dataDescriptor->Size = 2u;
				*(char*)dataBuffer = (char)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is byte)
			{
				dataDescriptor->Size = 1u;
				*dataBuffer = (byte)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is short)
			{
				dataDescriptor->Size = 2u;
				*(short*)dataBuffer = (short)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is sbyte)
			{
				dataDescriptor->Size = 1u;
				*dataBuffer = (byte)(sbyte)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is ushort)
			{
				dataDescriptor->Size = 2u;
				*(ushort*)dataBuffer = (ushort)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is float)
			{
				dataDescriptor->Size = 4u;
				*(float*)dataBuffer = (float)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is double)
			{
				dataDescriptor->Size = 8u;
				*(double*)dataBuffer = (double)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is bool)
			{
				dataDescriptor->Size = 1u;
				*dataBuffer = (((bool)data) ? ((byte)1) : ((byte)0));
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is Guid)
			{
				dataDescriptor->Size = (uint)sizeof(Guid);
				*(Guid*)dataBuffer = (Guid)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else if (data is decimal)
			{
				dataDescriptor->Size = 16u;
				*(decimal*)dataBuffer = (decimal)data;
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			else
			{
				if (!(data is bool))
				{
					string text2 = data.ToString();
					dataDescriptor->Size = (uint)((text2.Length + 1) * 2);
					return text2;
				}
				dataDescriptor->Size = 1u;
				*dataBuffer = (((bool)data) ? ((byte)1) : ((byte)0));
				dataDescriptor->DataPointer = (ulong)dataBuffer;
			}
			return null;
		}

		[SecurityCritical]
		public unsafe bool WriteMessageEvent(EventTraceActivity eventTraceActivity, string eventMessage, byte eventLevel, long eventKeywords)
		{
			int num = 0;
			if (eventMessage == null)
			{
				throw Fx.Exception.AsError(new ArgumentNullException("eventMessage"));
			}
			if (eventTraceActivity != null)
			{
				SetActivityId(ref eventTraceActivity.ActivityId);
			}
			if (IsEnabled(eventLevel, eventKeywords))
			{
				if (eventMessage.Length > 32724)
				{
					errorCode = WriteEventErrorCode.EventTooBig;
					return false;
				}
				fixed (char* message = eventMessage)
				{
					num = (int)UnsafeNativeMethods.EventWriteString(traceRegistrationHandle, eventLevel, eventKeywords, message);
				}
				if (num != 0)
				{
					SetLastError(num);
					return false;
				}
			}
			return true;
		}

		[SecurityCritical]
		public bool WriteMessageEvent(EventTraceActivity eventTraceActivity, string eventMessage)
		{
			return WriteMessageEvent(eventTraceActivity, eventMessage, 0, 0L);
		}

		[SecurityCritical]
		public unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, params object[] eventPayload)
		{
			uint num = 0u;
			if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
			{
				int num2 = 0;
				if (eventTraceActivity != null)
				{
					SetActivityId(ref eventTraceActivity.ActivityId);
				}
				if (eventPayload == null || eventPayload.Length == 0 || eventPayload.Length == 1)
				{
					string text = null;
					byte* dataBuffer = stackalloc byte[16];
					UnsafeNativeMethods.EventData eventData = default(UnsafeNativeMethods.EventData);
					eventData.Size = 0u;
					if (eventPayload != null && eventPayload.Length != 0)
					{
						text = EncodeObject(ref eventPayload[0], &eventData, dataBuffer);
						num2 = 1;
					}
					if (eventData.Size > 65482)
					{
						errorCode = WriteEventErrorCode.EventTooBig;
						return false;
					}
					if (text == null)
					{
						num = ((num2 != 0) ? UnsafeNativeMethods.EventWrite(traceRegistrationHandle, ref eventDescriptor, (uint)num2, &eventData) : UnsafeNativeMethods.EventWrite(traceRegistrationHandle, ref eventDescriptor, 0u, null));
					}
					else
					{
						fixed (char* ptr = text)
						{
							eventData.DataPointer = (ulong)ptr;
							num = UnsafeNativeMethods.EventWrite(traceRegistrationHandle, ref eventDescriptor, (uint)num2, &eventData);
						}
					}
				}
				else
				{
					num2 = eventPayload.Length;
					if (num2 > 32)
					{
						throw Fx.Exception.AsError(new ArgumentOutOfRangeException("eventPayload", InternalSR.EtwMaxNumberArgumentsExceeded(32)));
					}
					uint num3 = 0u;
					int num4 = 0;
					int[] array = new int[8];
					string[] array2 = new string[8];
					UnsafeNativeMethods.EventData* ptr2 = stackalloc UnsafeNativeMethods.EventData[num2];
					UnsafeNativeMethods.EventData* ptr3 = ptr2;
					byte* ptr4 = stackalloc byte[(int)(uint)(16 * num2)];
					byte* ptr5 = ptr4;
					for (int i = 0; i < eventPayload.Length; i++)
					{
						if (eventPayload[i] == null)
						{
							continue;
						}
						string text2 = EncodeObject(ref eventPayload[i], ptr3, ptr5);
						ptr5 += 16;
						num3 += ptr3->Size;
						ptr3++;
						if (text2 != null)
						{
							if (num4 >= 8)
							{
								throw Fx.Exception.AsError(new ArgumentOutOfRangeException("eventPayload", InternalSR.EtwAPIMaxStringCountExceeded(8)));
							}
							array2[num4] = text2;
							array[num4] = i;
							num4++;
						}
					}
					if (num3 > 65482)
					{
						errorCode = WriteEventErrorCode.EventTooBig;
						return false;
					}
					fixed (char* ptr6 = array2[0])
					{
						fixed (char* ptr7 = array2[1])
						{
							fixed (char* ptr8 = array2[2])
							{
								fixed (char* ptr9 = array2[3])
								{
									fixed (char* ptr10 = array2[4])
									{
										fixed (char* ptr11 = array2[5])
										{
											fixed (char* ptr12 = array2[6])
											{
												fixed (char* ptr13 = array2[7])
												{
													ptr3 = ptr2;
													if (array2[0] != null)
													{
														ptr3[array[0]].DataPointer = (ulong)ptr6;
													}
													if (array2[1] != null)
													{
														ptr3[array[1]].DataPointer = (ulong)ptr7;
													}
													if (array2[2] != null)
													{
														ptr3[array[2]].DataPointer = (ulong)ptr8;
													}
													if (array2[3] != null)
													{
														ptr3[array[3]].DataPointer = (ulong)ptr9;
													}
													if (array2[4] != null)
													{
														ptr3[array[4]].DataPointer = (ulong)ptr10;
													}
													if (array2[5] != null)
													{
														ptr3[array[5]].DataPointer = (ulong)ptr11;
													}
													if (array2[6] != null)
													{
														ptr3[array[6]].DataPointer = (ulong)ptr12;
													}
													if (array2[7] != null)
													{
														ptr3[array[7]].DataPointer = (ulong)ptr13;
													}
													num = UnsafeNativeMethods.EventWrite(traceRegistrationHandle, ref eventDescriptor, (uint)num2, ptr2);
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			if (num != 0)
			{
				SetLastError((int)num);
				return false;
			}
			return true;
		}

		[SecurityCritical]
		public unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string data)
		{
			uint num = 0u;
			data = data ?? string.Empty;
			if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
			{
				if (data.Length > 32724)
				{
					errorCode = WriteEventErrorCode.EventTooBig;
					return false;
				}
				if (eventTraceActivity != null)
				{
					SetActivityId(ref eventTraceActivity.ActivityId);
				}
				UnsafeNativeMethods.EventData eventData = default(UnsafeNativeMethods.EventData);
				eventData.Size = (uint)((data.Length + 1) * 2);
				eventData.Reserved = 0;
				fixed (char* ptr = data)
				{
					eventData.DataPointer = (ulong)ptr;
					num = UnsafeNativeMethods.EventWrite(traceRegistrationHandle, ref eventDescriptor, 1u, &eventData);
				}
			}
			if (num != 0)
			{
				SetLastError((int)num);
				return false;
			}
			return true;
		}

		[SecurityCritical]
		protected internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, int dataCount, IntPtr data)
		{
			uint num = 0u;
			if (eventTraceActivity != null)
			{
				SetActivityId(ref eventTraceActivity.ActivityId);
			}
			num = UnsafeNativeMethods.EventWrite(traceRegistrationHandle, ref eventDescriptor, (uint)dataCount, (UnsafeNativeMethods.EventData*)(void*)data);
			if (num != 0)
			{
				SetLastError((int)num);
				return false;
			}
			return true;
		}

		[SecurityCritical]
		public unsafe bool WriteTransferEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid relatedActivityId, params object[] eventPayload)
		{
			if (eventTraceActivity == null)
			{
				eventTraceActivity = EventTraceActivity.Empty;
			}
			uint num = 0u;
			if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
			{
				if (eventPayload != null && eventPayload.Length != 0)
				{
					int num2 = eventPayload.Length;
					if (num2 > 32)
					{
						throw Fx.Exception.AsError(new ArgumentOutOfRangeException("eventPayload", InternalSR.EtwMaxNumberArgumentsExceeded(32)));
					}
					uint num3 = 0u;
					int num4 = 0;
					int[] array = new int[8];
					string[] array2 = new string[8];
					UnsafeNativeMethods.EventData* ptr = stackalloc UnsafeNativeMethods.EventData[num2];
					UnsafeNativeMethods.EventData* ptr2 = ptr;
					byte* ptr3 = stackalloc byte[(int)(uint)(16 * num2)];
					byte* ptr4 = ptr3;
					for (int i = 0; i < eventPayload.Length; i++)
					{
						if (eventPayload[i] == null)
						{
							continue;
						}
						string text = EncodeObject(ref eventPayload[i], ptr2, ptr4);
						ptr4 += 16;
						num3 += ptr2->Size;
						ptr2++;
						if (text != null)
						{
							if (num4 >= 8)
							{
								throw Fx.Exception.AsError(new ArgumentOutOfRangeException("eventPayload", InternalSR.EtwAPIMaxStringCountExceeded(8)));
							}
							array2[num4] = text;
							array[num4] = i;
							num4++;
						}
					}
					if (num3 > 65482)
					{
						errorCode = WriteEventErrorCode.EventTooBig;
						return false;
					}
					fixed (char* ptr5 = array2[0])
					{
						fixed (char* ptr6 = array2[1])
						{
							fixed (char* ptr7 = array2[2])
							{
								fixed (char* ptr8 = array2[3])
								{
									fixed (char* ptr9 = array2[4])
									{
										fixed (char* ptr10 = array2[5])
										{
											fixed (char* ptr11 = array2[6])
											{
												fixed (char* ptr12 = array2[7])
												{
													ptr2 = ptr;
													if (array2[0] != null)
													{
														ptr2[array[0]].DataPointer = (ulong)ptr5;
													}
													if (array2[1] != null)
													{
														ptr2[array[1]].DataPointer = (ulong)ptr6;
													}
													if (array2[2] != null)
													{
														ptr2[array[2]].DataPointer = (ulong)ptr7;
													}
													if (array2[3] != null)
													{
														ptr2[array[3]].DataPointer = (ulong)ptr8;
													}
													if (array2[4] != null)
													{
														ptr2[array[4]].DataPointer = (ulong)ptr9;
													}
													if (array2[5] != null)
													{
														ptr2[array[5]].DataPointer = (ulong)ptr10;
													}
													if (array2[6] != null)
													{
														ptr2[array[6]].DataPointer = (ulong)ptr11;
													}
													if (array2[7] != null)
													{
														ptr2[array[7]].DataPointer = (ulong)ptr12;
													}
													num = UnsafeNativeMethods.EventWriteTransfer(traceRegistrationHandle, ref eventDescriptor, ref eventTraceActivity.ActivityId, ref relatedActivityId, (uint)num2, ptr);
												}
											}
										}
									}
								}
							}
						}
					}
				}
				else
				{
					num = UnsafeNativeMethods.EventWriteTransfer(traceRegistrationHandle, ref eventDescriptor, ref eventTraceActivity.ActivityId, ref relatedActivityId, 0u, null);
				}
			}
			if (num != 0)
			{
				SetLastError((int)num);
				return false;
			}
			return true;
		}

		[SecurityCritical]
		protected unsafe bool WriteTransferEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid relatedActivityId, int dataCount, IntPtr data)
		{
			if (eventTraceActivity == null)
			{
				throw Fx.Exception.ArgumentNull("eventTraceActivity");
			}
			uint num = 0u;
			num = UnsafeNativeMethods.EventWriteTransfer(traceRegistrationHandle, ref eventDescriptor, ref eventTraceActivity.ActivityId, ref relatedActivityId, (uint)dataCount, (UnsafeNativeMethods.EventData*)(void*)data);
			if (num != 0)
			{
				SetLastError((int)num);
				return false;
			}
			return true;
		}

		[SecurityCritical]
		public static void SetActivityId(ref Guid id)
		{
			UnsafeNativeMethods.EventActivityIdControl(2, ref id);
		}
	}
	internal class DiagnosticTraceSource : TraceSource
	{
		private const string PropagateActivityValue = "propagateActivity";

		internal bool PropagateActivity
		{
			get
			{
				bool result = false;
				string value = base.Attributes["propagateActivity"];
				if (!string.IsNullOrEmpty(value) && !bool.TryParse(value, out result))
				{
					result = false;
				}
				return result;
			}
			set
			{
				base.Attributes["propagateActivity"] = value.ToString();
			}
		}

		internal DiagnosticTraceSource(string name)
			: base(name)
		{
		}

		protected override string[] GetSupportedAttributes()
		{
			return new string[1] { "propagateActivity" };
		}
	}
	[AttributeUsage(AttributeTargets.Field, Inherited = false)]
	internal sealed class PerformanceCounterNameAttribute : Attribute
	{
		public string Name { get; set; }

		public PerformanceCounterNameAttribute(string name)
		{
			Name = name;
		}
	}
	internal sealed class EventLogger
	{
		private const int MaxEventLogsInPT = 5;

		[SecurityCritical]
		private static int logCountForPT;

		private static bool canLogEvent = true;

		private DiagnosticTraceBase diagnosticTrace;

		[SecurityCritical]
		private string eventLogSourceName;

		private bool isInPartialTrust;

		private EventLogger()
		{
			isInPartialTrust = IsInPartialTrust();
		}

		[Obsolete("For System.Runtime.dll use only. Call FxTrace.EventLog instead")]
		public EventLogger(string eventLogSourceName, DiagnosticTraceBase diagnosticTrace)
		{
			try
			{
				this.diagnosticTrace = diagnosticTrace;
				if (canLogEvent)
				{
					SafeSetLogSourceName(eventLogSourceName);
				}
			}
			catch (SecurityException)
			{
				canLogEvent = false;
			}
		}

		[SecurityCritical]
		public static EventLogger UnsafeCreateEventLogger(string eventLogSourceName, DiagnosticTraceBase diagnosticTrace)
		{
			EventLogger eventLogger = new EventLogger();
			eventLogger.SetLogSourceName(eventLogSourceName, diagnosticTrace);
			return eventLogger;
		}

		[SecurityCritical]
		public void UnsafeLogEvent(TraceEventType type, ushort eventLogCategory, uint eventId, bool shouldTrace, params string[] values)
		{
			if (logCountForPT >= 5)
			{
				return;
			}
			try
			{
				int num = 0;
				string[] array = new string[values.Length + 2];
				for (int i = 0; i < values.Length; i++)
				{
					string text = values[i];
					num += (array[i] = (string.IsNullOrEmpty(text) ? string.Empty : NormalizeEventLogParameter(text))).Length + 1;
				}
				string text2 = NormalizeEventLogParameter(UnsafeGetProcessName());
				array[array.Length - 2] = text2;
				num += text2.Length + 1;
				string text3 = UnsafeGetProcessId().ToString(CultureInfo.InvariantCulture);
				array[array.Length - 1] = text3;
				num += text3.Length + 1;
				if (num > 25600)
				{
					int num2 = 25600 / array.Length - 1;
					for (int j = 0; j < array.Length; j++)
					{
						if (array[j].Length > num2)
						{
							array[j] = array[j].Substring(0, num2);
						}
					}
				}
				SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
				byte[] array2 = new byte[user.BinaryLength];
				user.GetBinaryForm(array2, 0);
				IntPtr[] array3 = new IntPtr[array.Length];
				GCHandle stringsRootHandle = default(GCHandle);
				GCHandle[] array4 = null;
				try
				{
					stringsRootHandle = GCHandle.Alloc(array3, GCHandleType.Pinned);
					array4 = new GCHandle[array.Length];
					for (int k = 0; k < array.Length; k++)
					{
						array4[k] = GCHandle.Alloc(array[k], GCHandleType.Pinned);
						array3[k] = array4[k].AddrOfPinnedObject();
					}
					UnsafeWriteEventLog(type, eventLogCategory, eventId, array, array2, stringsRootHandle);
				}
				finally
				{
					if (stringsRootHandle.AddrOfPinnedObject() != IntPtr.Zero)
					{
						stringsRootHandle.Free();
					}
					if (array4 != null)
					{
						GCHandle[] array5 = array4;
						foreach (GCHandle gCHandle in array5)
						{
							gCHandle.Free();
						}
					}
				}
				if (shouldTrace && diagnosticTrace != null && diagnosticTrace.IsEnabled())
				{
					Dictionary<string, string> dictionary = new Dictionary<string, string>(array.Length + 4);
					dictionary["CategoryID.Name"] = "EventLogCategory";
					dictionary["CategoryID.Value"] = eventLogCategory.ToString(CultureInfo.InvariantCulture);
					dictionary["InstanceID.Name"] = "EventId";
					dictionary["InstanceID.Value"] = eventId.ToString(CultureInfo.InvariantCulture);
					for (int m = 0; m < values.Length; m++)
					{
						dictionary.Add("Value" + m.ToString(CultureInfo.InvariantCulture), (values[m] == null) ? string.Empty : DiagnosticTraceBase.XmlEncode(values[m]));
					}
					diagnosticTrace.TraceEventLogEvent(type, new DictionaryTraceRecord(dictionary));
				}
			}
			catch (Exception exception)
			{
				if (Fx.IsFatal(exception))
				{
					throw;
				}
			}
			if (isInPartialTrust)
			{
				logCountForPT++;
			}
		}

		public void LogEvent(TraceEventType type, ushort eventLogCategory, uint eventId, bool shouldTrace, params string[] values)
		{
			if (!canLogEvent)
			{
				return;
			}
			try
			{
				SafeLogEvent(type, eventLogCategory, eventId, shouldTrace, values);
			}
			catch (SecurityException exception)
			{
				canLogEvent = false;
				if (shouldTrace)
				{
					Fx.Exception.TraceHandledException(exception, TraceEventType.Information);
				}
			}
		}

		public void LogEvent(TraceEventType type, ushort eventLogCategory, uint eventId, params string[] values)
		{
			LogEvent(type, eventLogCategory, eventId, shouldTrace: true, values);
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

		[SecuritySafeCritical]
		[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		private void SafeLogEvent(TraceEventType type, ushort eventLogCategory, uint eventId, bool shouldTrace, params string[] values)
		{
			UnsafeLogEvent(type, eventLogCategory, eventId, shouldTrace, values);
		}

		[SecuritySafeCritical]
		[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		private void SafeSetLogSourceName(string eventLogSourceName)
		{
			this.eventLogSourceName = eventLogSourceName;
		}

		[SecurityCritical]
		private void SetLogSourceName(string eventLogSourceName, DiagnosticTraceBase diagnosticTrace)
		{
			this.eventLogSourceName = eventLogSourceName;
			this.diagnosticTrace = diagnosticTrace;
		}

		[SecuritySafeCritical]
		private bool IsInPartialTrust()
		{
			bool flag = false;
			try
			{
				using Process process = Process.GetCurrentProcess();
				return string.IsNullOrEmpty(process.ProcessName);
			}
			catch (SecurityException)
			{
				return true;
			}
		}

		[SecurityCritical]
		[SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
		private void UnsafeWriteEventLog(TraceEventType type, ushort eventLogCategory, uint eventId, string[] logValues, byte[] sidBA, GCHandle stringsRootHandle)
		{
			using SafeEventLogWriteHandle safeEventLogWriteHandle = SafeEventLogWriteHandle.RegisterEventSource(null, eventLogSourceName);
			if (safeEventLogWriteHandle != null)
			{
				UnsafeNativeMethods.ReportEvent(strings: new HandleRef(safeEventLogWriteHandle, stringsRootHandle.AddrOfPinnedObject()), hEventLog: safeEventLogWriteHandle, type: (ushort)EventLogEntryTypeFromEventType(type), category: eventLogCategory, eventID: eventId, userSID: sidBA, numStrings: (ushort)logValues.Length, dataLen: 0u, rawData: null);
			}
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[SecurityCritical]
		[SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
		private string UnsafeGetProcessName()
		{
			string text = null;
			using Process process = Process.GetCurrentProcess();
			return process.ProcessName;
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[SecurityCritical]
		[SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
		private int UnsafeGetProcessId()
		{
			int num = -1;
			using Process process = Process.GetCurrentProcess();
			return process.Id;
		}

		internal static string NormalizeEventLogParameter(string eventLogParameter)
		{
			if (eventLogParameter.IndexOf('%') < 0)
			{
				return eventLogParameter;
			}
			StringBuilder stringBuilder = null;
			int length = eventLogParameter.Length;
			for (int i = 0; i < length; i++)
			{
				char c = eventLogParameter[i];
				if (c != '%')
				{
					stringBuilder?.Append(c);
					continue;
				}
				if (i + 1 >= length)
				{
					stringBuilder?.Append(c);
					continue;
				}
				if (eventLogParameter[i + 1] < '0' || eventLogParameter[i + 1] > '9')
				{
					stringBuilder?.Append(c);
					continue;
				}
				if (stringBuilder == null)
				{
					stringBuilder = new StringBuilder(length + 2);
					for (int j = 0; j < i; j++)
					{
						stringBuilder.Append(eventLogParameter[j]);
					}
				}
				stringBuilder.Append(c);
				stringBuilder.Append(' ');
			}
			if (stringBuilder == null)
			{
				return eventLogParameter;
			}
			return stringBuilder.ToString();
		}
	}
	internal enum EventLogCategory : ushort
	{
		ServiceAuthorization = 1,
		MessageAuthentication,
		ObjectAccess,
		Tracing,
		WebHost,
		FailFast,
		MessageLogging,
		PerformanceCounter,
		Wmi,
		ComPlus,
		StateMachine,
		Wsat,
		SharingService,
		ListenerAdapter
	}
	internal enum EventLogEventId : uint
	{
		FailedToSetupTracing = 3221291108u,
		FailedToInitializeTraceSource = 3221291109u,
		FailFast = 3221291110u,
		FailFastException = 3221291111u,
		FailedToTraceEvent = 3221291112u,
		FailedToTraceEventWithException = 3221291113u,
		InvariantAssertionFailed = 3221291114u,
		PiiLoggingOn = 3221291115u,
		PiiLoggingNotAllowed = 3221291116u,
		WebHostUnhandledException = 3221356545u,
		WebHostHttpError = 3221356546u,
		WebHostFailedToProcessRequest = 3221356547u,
		WebHostFailedToListen = 3221356548u,
		FailedToLogMessage = 3221356549u,
		RemovedBadFilter = 3221356550u,
		FailedToCreateMessageLoggingTraceSource = 3221356551u,
		MessageLoggingOn = 3221356552u,
		MessageLoggingOff = 3221356553u,
		FailedToLoadPerformanceCounter = 3221356554u,
		FailedToRemovePerformanceCounter = 3221356555u,
		WmiGetObjectFailed = 3221356556u,
		WmiPutInstanceFailed = 3221356557u,
		WmiDeleteInstanceFailed = 3221356558u,
		WmiCreateInstanceFailed = 3221356559u,
		WmiExecQueryFailed = 3221356560u,
		WmiExecMethodFailed = 3221356561u,
		WmiRegistrationFailed = 3221356562u,
		WmiUnregistrationFailed = 3221356563u,
		WmiAdminTypeMismatch = 3221356564u,
		WmiPropertyMissing = 3221356565u,
		ComPlusServiceHostStartingServiceError = 3221356566u,
		ComPlusDllHostInitializerStartingError = 3221356567u,
		ComPlusTLBImportError = 3221356568u,
		ComPlusInvokingMethodFailed = 3221356569u,
		ComPlusInstanceCreationError = 3221356570u,
		ComPlusInvokingMethodFailedMismatchedTransactions = 3221356571u,
		WebHostNotLoggingInsufficientMemoryExceptionsOnActivationForNextTimeInterval = 2147614748u,
		UnhandledStateMachineExceptionRecordDescription = 3221422081u,
		FatalUnexpectedStateMachineEvent = 3221422082u,
		ParticipantRecoveryLogEntryCorrupt = 3221422083u,
		CoordinatorRecoveryLogEntryCorrupt = 3221422084u,
		CoordinatorRecoveryLogEntryCreationFailure = 3221422085u,
		ParticipantRecoveryLogEntryCreationFailure = 3221422086u,
		ProtocolInitializationFailure = 3221422087u,
		ProtocolStartFailure = 3221422088u,
		ProtocolRecoveryBeginningFailure = 3221422089u,
		ProtocolRecoveryCompleteFailure = 3221422090u,
		TransactionBridgeRecoveryFailure = 3221422091u,
		ProtocolStopFailure = 3221422092u,
		NonFatalUnexpectedStateMachineEvent = 3221422093u,
		PerformanceCounterInitializationFailure = 3221422094u,
		ProtocolRecoveryComplete = 3221422095u,
		ProtocolStopped = 3221422096u,
		ThumbPrintNotFound = 3221422097u,
		ThumbPrintNotValidated = 3221422098u,
		SslNoPrivateKey = 3221422099u,
		SslNoAccessiblePrivateKey = 3221422100u,
		MissingNecessaryKeyUsage = 3221422101u,
		MissingNecessaryEnhancedKeyUsage = 3221422102u,
		StartErrorPublish = 3221487617u,
		BindingError = 3221487618u,
		LAFailedToListenForApp = 3221487619u,
		UnknownListenerAdapterError = 3221487620u,
		WasDisconnected = 3221487621u,
		WasConnectionTimedout = 3221487622u,
		ServiceStartFailed = 3221487623u,
		MessageQueueDuplicatedSocketLeak = 3221487624u,
		MessageQueueDuplicatedPipeLeak = 3221487625u,
		SharingUnhandledException = 3221487626u,
		ServiceAuthorizationSuccess = 1074135041u,
		ServiceAuthorizationFailure = 3221618690u,
		MessageAuthenticationSuccess = 1074135043u,
		MessageAuthenticationFailure = 3221618692u,
		SecurityNegotiationSuccess = 1074135045u,
		SecurityNegotiationFailure = 3221618694u,
		TransportAuthenticationSuccess = 1074135047u,
		TransportAuthenticationFailure = 3221618696u,
		ImpersonationSuccess = 1074135049u,
		ImpersonationFailure = 3221618698u
	}
	internal enum EventSeverity : uint
	{
		Success = 0u,
		Informational = 1073741824u,
		Warning = 2147483648u,
		Error = 3221225472u
	}
	internal enum EventFacility : uint
	{
		Tracing = 65536u,
		ServiceModel = 131072u,
		TransactionBridge = 196608u,
		SMSvcHost = 262144u,
		InfoCards = 327680u,
		SecurityAudit = 393216u
	}
	[StructLayout(LayoutKind.Explicit, Size = 16)]
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	internal struct EventDescriptor
	{
		[FieldOffset(0)]
		private ushort m_id;

		[FieldOffset(2)]
		private byte m_version;

		[FieldOffset(3)]
		private byte m_channel;

		[FieldOffset(4)]
		private byte m_level;

		[FieldOffset(5)]
		private byte m_opcode;

		[FieldOffset(6)]
		private ushort m_task;

		[FieldOffset(8)]
		private long m_keywords;

		public int EventId => m_id;

		public byte Version => m_version;

		public byte Channel => m_channel;

		public byte Level => m_level;

		public byte Opcode => m_opcode;

		public int Task => m_task;

		public long Keywords => m_keywords;

		public EventDescriptor(int id, byte version, byte channel, byte level, byte opcode, int task, long keywords)
		{
			if (id < 0)
			{
				throw Fx.Exception.ArgumentOutOfRange("id", id, InternalSR.ValueMustBeNonNegative);
			}
			if (id > 65535)
			{
				throw Fx.Exception.ArgumentOutOfRange("id", id, string.Empty);
			}
			m_id = (ushort)id;
			m_version = version;
			m_channel = channel;
			m_level = level;
			m_opcode = opcode;
			m_keywords = keywords;
			if (task < 0)
			{
				throw Fx.Exception.ArgumentOutOfRange("task", task, InternalSR.ValueMustBeNonNegative);
			}
			if (task > 65535)
			{
				throw Fx.Exception.ArgumentOutOfRange("task", task, string.Empty);
			}
			m_task = (ushort)task;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is EventDescriptor))
			{
				return false;
			}
			return Equals((EventDescriptor)obj);
		}

		public override int GetHashCode()
		{
			return m_id ^ m_version ^ m_channel ^ m_level ^ m_opcode ^ m_task ^ (int)m_keywords;
		}

		public bool Equals(EventDescriptor other)
		{
			if (m_id != other.m_id || m_version != other.m_version || m_channel != other.m_channel || m_level != other.m_level || m_opcode != other.m_opcode || m_task != other.m_task || m_keywords != other.m_keywords)
			{
				return false;
			}
			return true;
		}

		public static bool operator ==(EventDescriptor event1, EventDescriptor event2)
		{
			return event1.Equals(event2);
		}

		public static bool operator !=(EventDescriptor event1, EventDescriptor event2)
		{
			return !event1.Equals(event2);
		}
	}
	internal sealed class EtwProvider : DiagnosticsEventProvider
	{
		private Action invokeControllerCallback;

		private bool end2EndActivityTracingEnabled;

		internal Action ControllerCallBack
		{
			get
			{
				return invokeControllerCallback;
			}
			set
			{
				invokeControllerCallback = value;
			}
		}

		internal bool IsEnd2EndActivityTracingEnabled => end2EndActivityTracingEnabled;

		[SecurityCritical]
		[PermissionSet(SecurityAction.Assert, Unrestricted = true)]
		internal EtwProvider(Guid id)
			: base(id)
		{
		}

		protected override void OnControllerCommand()
		{
			end2EndActivityTracingEnabled = false;
			if (invokeControllerCallback != null)
			{
				invokeControllerCallback();
			}
		}

		internal void SetEnd2EndActivityTracingEnabled(bool isEnd2EndActivityTracingEnabled)
		{
			end2EndActivityTracingEnabled = isEnd2EndActivityTracingEnabled;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, string value2, string value3)
		{
			bool flag = true;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			fixed (char* ptr3 = value2)
			{
				fixed (char* ptr4 = value3)
				{
					byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 3)];
					UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
					ptr2->DataPointer = (ulong)(&value1);
					ptr2->Size = (uint)sizeof(Guid);
					ptr2[1].DataPointer = (ulong)ptr3;
					ptr2[1].Size = (uint)((value2.Length + 1) * 2);
					ptr2[2].DataPointer = (ulong)ptr4;
					ptr2[2].Size = (uint)((value3.Length + 1) * 2);
					flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 3, (IntPtr)ptr);
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteTransferEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid relatedActivityId, string value1, string value2)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 2)];
					UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
					ptr2->DataPointer = (ulong)ptr3;
					ptr2->Size = (uint)((value1.Length + 1) * 2);
					ptr2[1].DataPointer = (ulong)ptr4;
					ptr2[1].Size = (uint)((value2.Length + 1) * 2);
					flag = WriteTransferEvent(ref eventDescriptor, eventTraceActivity, relatedActivityId, 2, (IntPtr)ptr);
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 2)];
					UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
					ptr2->DataPointer = (ulong)ptr3;
					ptr2->Size = (uint)((value1.Length + 1) * 2);
					ptr2[1].DataPointer = (ulong)ptr4;
					ptr2[1].Size = (uint)((value2.Length + 1) * 2);
					flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 2, (IntPtr)ptr);
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 3)];
						UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
						ptr2->DataPointer = (ulong)ptr3;
						ptr2->Size = (uint)((value1.Length + 1) * 2);
						ptr2[1].DataPointer = (ulong)ptr4;
						ptr2[1].Size = (uint)((value2.Length + 1) * 2);
						ptr2[2].DataPointer = (ulong)ptr5;
						ptr2[2].Size = (uint)((value3.Length + 1) * 2);
						flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 3, (IntPtr)ptr);
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 4)];
							UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
							ptr2->DataPointer = (ulong)ptr3;
							ptr2->Size = (uint)((value1.Length + 1) * 2);
							ptr2[1].DataPointer = (ulong)ptr4;
							ptr2[1].Size = (uint)((value2.Length + 1) * 2);
							ptr2[2].DataPointer = (ulong)ptr5;
							ptr2[2].Size = (uint)((value3.Length + 1) * 2);
							ptr2[3].DataPointer = (ulong)ptr6;
							ptr2[3].Size = (uint)((value4.Length + 1) * 2);
							flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 4, (IntPtr)ptr);
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 5)];
								UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
								ptr2->DataPointer = (ulong)ptr3;
								ptr2->Size = (uint)((value1.Length + 1) * 2);
								ptr2[1].DataPointer = (ulong)ptr4;
								ptr2[1].Size = (uint)((value2.Length + 1) * 2);
								ptr2[2].DataPointer = (ulong)ptr5;
								ptr2[2].Size = (uint)((value3.Length + 1) * 2);
								ptr2[3].DataPointer = (ulong)ptr6;
								ptr2[3].Size = (uint)((value4.Length + 1) * 2);
								ptr2[4].DataPointer = (ulong)ptr7;
								ptr2[4].Size = (uint)((value5.Length + 1) * 2);
								flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 5, (IntPtr)ptr);
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 6)];
									UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
									ptr2->DataPointer = (ulong)ptr3;
									ptr2->Size = (uint)((value1.Length + 1) * 2);
									ptr2[1].DataPointer = (ulong)ptr4;
									ptr2[1].Size = (uint)((value2.Length + 1) * 2);
									ptr2[2].DataPointer = (ulong)ptr5;
									ptr2[2].Size = (uint)((value3.Length + 1) * 2);
									ptr2[3].DataPointer = (ulong)ptr6;
									ptr2[3].Size = (uint)((value4.Length + 1) * 2);
									ptr2[4].DataPointer = (ulong)ptr7;
									ptr2[4].Size = (uint)((value5.Length + 1) * 2);
									ptr2[5].DataPointer = (ulong)ptr8;
									ptr2[5].Size = (uint)((value6.Length + 1) * 2);
									flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 6, (IntPtr)ptr);
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6, string value7)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									fixed (char* ptr9 = value7)
									{
										byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 7)];
										UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
										ptr2->DataPointer = (ulong)ptr3;
										ptr2->Size = (uint)((value1.Length + 1) * 2);
										ptr2[1].DataPointer = (ulong)ptr4;
										ptr2[1].Size = (uint)((value2.Length + 1) * 2);
										ptr2[2].DataPointer = (ulong)ptr5;
										ptr2[2].Size = (uint)((value3.Length + 1) * 2);
										ptr2[3].DataPointer = (ulong)ptr6;
										ptr2[3].Size = (uint)((value4.Length + 1) * 2);
										ptr2[4].DataPointer = (ulong)ptr7;
										ptr2[4].Size = (uint)((value5.Length + 1) * 2);
										ptr2[5].DataPointer = (ulong)ptr8;
										ptr2[5].Size = (uint)((value6.Length + 1) * 2);
										ptr2[6].DataPointer = (ulong)ptr9;
										ptr2[6].Size = (uint)((value7.Length + 1) * 2);
										flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 7, (IntPtr)ptr);
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6, string value7, string value8)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									fixed (char* ptr9 = value7)
									{
										fixed (char* ptr10 = value8)
										{
											byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 8)];
											UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
											ptr2->DataPointer = (ulong)ptr3;
											ptr2->Size = (uint)((value1.Length + 1) * 2);
											ptr2[1].DataPointer = (ulong)ptr4;
											ptr2[1].Size = (uint)((value2.Length + 1) * 2);
											ptr2[2].DataPointer = (ulong)ptr5;
											ptr2[2].Size = (uint)((value3.Length + 1) * 2);
											ptr2[3].DataPointer = (ulong)ptr6;
											ptr2[3].Size = (uint)((value4.Length + 1) * 2);
											ptr2[4].DataPointer = (ulong)ptr7;
											ptr2[4].Size = (uint)((value5.Length + 1) * 2);
											ptr2[5].DataPointer = (ulong)ptr8;
											ptr2[5].Size = (uint)((value6.Length + 1) * 2);
											ptr2[6].DataPointer = (ulong)ptr9;
											ptr2[6].Size = (uint)((value7.Length + 1) * 2);
											ptr2[7].DataPointer = (ulong)ptr10;
											ptr2[7].Size = (uint)((value8.Length + 1) * 2);
											flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 8, (IntPtr)ptr);
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6, string value7, string value8, string value9)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									fixed (char* ptr9 = value7)
									{
										fixed (char* ptr10 = value8)
										{
											fixed (char* ptr11 = value9)
											{
												byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 9)];
												UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
												ptr2->DataPointer = (ulong)ptr3;
												ptr2->Size = (uint)((value1.Length + 1) * 2);
												ptr2[1].DataPointer = (ulong)ptr4;
												ptr2[1].Size = (uint)((value2.Length + 1) * 2);
												ptr2[2].DataPointer = (ulong)ptr5;
												ptr2[2].Size = (uint)((value3.Length + 1) * 2);
												ptr2[3].DataPointer = (ulong)ptr6;
												ptr2[3].Size = (uint)((value4.Length + 1) * 2);
												ptr2[4].DataPointer = (ulong)ptr7;
												ptr2[4].Size = (uint)((value5.Length + 1) * 2);
												ptr2[5].DataPointer = (ulong)ptr8;
												ptr2[5].Size = (uint)((value6.Length + 1) * 2);
												ptr2[6].DataPointer = (ulong)ptr9;
												ptr2[6].Size = (uint)((value7.Length + 1) * 2);
												ptr2[7].DataPointer = (ulong)ptr10;
												ptr2[7].Size = (uint)((value8.Length + 1) * 2);
												ptr2[8].DataPointer = (ulong)ptr11;
												ptr2[8].Size = (uint)((value9.Length + 1) * 2);
												flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 9, (IntPtr)ptr);
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									fixed (char* ptr9 = value7)
									{
										fixed (char* ptr10 = value8)
										{
											fixed (char* ptr11 = value9)
											{
												fixed (char* ptr12 = value10)
												{
													byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 10)];
													UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
													ptr2->DataPointer = (ulong)ptr3;
													ptr2->Size = (uint)((value1.Length + 1) * 2);
													ptr2[1].DataPointer = (ulong)ptr4;
													ptr2[1].Size = (uint)((value2.Length + 1) * 2);
													ptr2[2].DataPointer = (ulong)ptr5;
													ptr2[2].Size = (uint)((value3.Length + 1) * 2);
													ptr2[3].DataPointer = (ulong)ptr6;
													ptr2[3].Size = (uint)((value4.Length + 1) * 2);
													ptr2[4].DataPointer = (ulong)ptr7;
													ptr2[4].Size = (uint)((value5.Length + 1) * 2);
													ptr2[5].DataPointer = (ulong)ptr8;
													ptr2[5].Size = (uint)((value6.Length + 1) * 2);
													ptr2[6].DataPointer = (ulong)ptr9;
													ptr2[6].Size = (uint)((value7.Length + 1) * 2);
													ptr2[7].DataPointer = (ulong)ptr10;
													ptr2[7].Size = (uint)((value8.Length + 1) * 2);
													ptr2[8].DataPointer = (ulong)ptr11;
													ptr2[8].Size = (uint)((value9.Length + 1) * 2);
													ptr2[9].DataPointer = (ulong)ptr12;
													ptr2[9].Size = (uint)((value10.Length + 1) * 2);
													flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 10, (IntPtr)ptr);
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									fixed (char* ptr9 = value7)
									{
										fixed (char* ptr10 = value8)
										{
											fixed (char* ptr11 = value9)
											{
												fixed (char* ptr12 = value10)
												{
													fixed (char* ptr13 = value11)
													{
														byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 11)];
														UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
														ptr2->DataPointer = (ulong)ptr3;
														ptr2->Size = (uint)((value1.Length + 1) * 2);
														ptr2[1].DataPointer = (ulong)ptr4;
														ptr2[1].Size = (uint)((value2.Length + 1) * 2);
														ptr2[2].DataPointer = (ulong)ptr5;
														ptr2[2].Size = (uint)((value3.Length + 1) * 2);
														ptr2[3].DataPointer = (ulong)ptr6;
														ptr2[3].Size = (uint)((value4.Length + 1) * 2);
														ptr2[4].DataPointer = (ulong)ptr7;
														ptr2[4].Size = (uint)((value5.Length + 1) * 2);
														ptr2[5].DataPointer = (ulong)ptr8;
														ptr2[5].Size = (uint)((value6.Length + 1) * 2);
														ptr2[6].DataPointer = (ulong)ptr9;
														ptr2[6].Size = (uint)((value7.Length + 1) * 2);
														ptr2[7].DataPointer = (ulong)ptr10;
														ptr2[7].Size = (uint)((value8.Length + 1) * 2);
														ptr2[8].DataPointer = (ulong)ptr11;
														ptr2[8].Size = (uint)((value9.Length + 1) * 2);
														ptr2[9].DataPointer = (ulong)ptr12;
														ptr2[9].Size = (uint)((value10.Length + 1) * 2);
														ptr2[10].DataPointer = (ulong)ptr13;
														ptr2[10].Size = (uint)((value11.Length + 1) * 2);
														flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 11, (IntPtr)ptr);
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11, string value12)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			value12 = value12 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									fixed (char* ptr9 = value7)
									{
										fixed (char* ptr10 = value8)
										{
											fixed (char* ptr11 = value9)
											{
												fixed (char* ptr12 = value10)
												{
													fixed (char* ptr13 = value11)
													{
														fixed (char* ptr14 = value12)
														{
															byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 12)];
															UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
															ptr2->DataPointer = (ulong)ptr3;
															ptr2->Size = (uint)((value1.Length + 1) * 2);
															ptr2[1].DataPointer = (ulong)ptr4;
															ptr2[1].Size = (uint)((value2.Length + 1) * 2);
															ptr2[2].DataPointer = (ulong)ptr5;
															ptr2[2].Size = (uint)((value3.Length + 1) * 2);
															ptr2[3].DataPointer = (ulong)ptr6;
															ptr2[3].Size = (uint)((value4.Length + 1) * 2);
															ptr2[4].DataPointer = (ulong)ptr7;
															ptr2[4].Size = (uint)((value5.Length + 1) * 2);
															ptr2[5].DataPointer = (ulong)ptr8;
															ptr2[5].Size = (uint)((value6.Length + 1) * 2);
															ptr2[6].DataPointer = (ulong)ptr9;
															ptr2[6].Size = (uint)((value7.Length + 1) * 2);
															ptr2[7].DataPointer = (ulong)ptr10;
															ptr2[7].Size = (uint)((value8.Length + 1) * 2);
															ptr2[8].DataPointer = (ulong)ptr11;
															ptr2[8].Size = (uint)((value9.Length + 1) * 2);
															ptr2[9].DataPointer = (ulong)ptr12;
															ptr2[9].Size = (uint)((value10.Length + 1) * 2);
															ptr2[10].DataPointer = (ulong)ptr13;
															ptr2[10].Size = (uint)((value11.Length + 1) * 2);
															ptr2[11].DataPointer = (ulong)ptr14;
															ptr2[11].Size = (uint)((value12.Length + 1) * 2);
															flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 12, (IntPtr)ptr);
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, string value2, string value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11, string value12, string value13)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value2 = value2 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			value12 = value12 ?? string.Empty;
			value13 = value13 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value2)
				{
					fixed (char* ptr5 = value3)
					{
						fixed (char* ptr6 = value4)
						{
							fixed (char* ptr7 = value5)
							{
								fixed (char* ptr8 = value6)
								{
									fixed (char* ptr9 = value7)
									{
										fixed (char* ptr10 = value8)
										{
											fixed (char* ptr11 = value9)
											{
												fixed (char* ptr12 = value10)
												{
													fixed (char* ptr13 = value11)
													{
														fixed (char* ptr14 = value12)
														{
															fixed (char* ptr15 = value13)
															{
																byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 13)];
																UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
																ptr2->DataPointer = (ulong)ptr3;
																ptr2->Size = (uint)((value1.Length + 1) * 2);
																ptr2[1].DataPointer = (ulong)ptr4;
																ptr2[1].Size = (uint)((value2.Length + 1) * 2);
																ptr2[2].DataPointer = (ulong)ptr5;
																ptr2[2].Size = (uint)((value3.Length + 1) * 2);
																ptr2[3].DataPointer = (ulong)ptr6;
																ptr2[3].Size = (uint)((value4.Length + 1) * 2);
																ptr2[4].DataPointer = (ulong)ptr7;
																ptr2[4].Size = (uint)((value5.Length + 1) * 2);
																ptr2[5].DataPointer = (ulong)ptr8;
																ptr2[5].Size = (uint)((value6.Length + 1) * 2);
																ptr2[6].DataPointer = (ulong)ptr9;
																ptr2[6].Size = (uint)((value7.Length + 1) * 2);
																ptr2[7].DataPointer = (ulong)ptr10;
																ptr2[7].Size = (uint)((value8.Length + 1) * 2);
																ptr2[8].DataPointer = (ulong)ptr11;
																ptr2[8].Size = (uint)((value9.Length + 1) * 2);
																ptr2[9].DataPointer = (ulong)ptr12;
																ptr2[9].Size = (uint)((value10.Length + 1) * 2);
																ptr2[10].DataPointer = (ulong)ptr13;
																ptr2[10].Size = (uint)((value11.Length + 1) * 2);
																ptr2[11].DataPointer = (ulong)ptr14;
																ptr2[11].Size = (uint)((value12.Length + 1) * 2);
																ptr2[12].DataPointer = (ulong)ptr15;
																ptr2[12].Size = (uint)((value13.Length + 1) * 2);
																flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 13, (IntPtr)ptr);
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, int value1)
		{
			bool flag = true;
			byte* ptr = stackalloc byte[(int)(uint)sizeof(UnsafeNativeMethods.EventData)];
			UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
			ptr2->DataPointer = (ulong)(&value1);
			ptr2->Size = 4u;
			return WriteEvent(ref eventDescriptor, eventTraceActivity, 1, (IntPtr)ptr);
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, int value1, int value2)
		{
			bool flag = true;
			byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 2)];
			UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
			ptr2->DataPointer = (ulong)(&value1);
			ptr2->Size = 4u;
			ptr2[1].DataPointer = (ulong)(&value2);
			ptr2[1].Size = 4u;
			return WriteEvent(ref eventDescriptor, eventTraceActivity, 2, (IntPtr)ptr);
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, int value1, int value2, int value3)
		{
			bool flag = true;
			byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 3)];
			UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
			ptr2->DataPointer = (ulong)(&value1);
			ptr2->Size = 4u;
			ptr2[1].DataPointer = (ulong)(&value2);
			ptr2[1].Size = 4u;
			ptr2[2].DataPointer = (ulong)(&value3);
			ptr2[2].Size = 4u;
			return WriteEvent(ref eventDescriptor, eventTraceActivity, 3, (IntPtr)ptr);
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, long value1)
		{
			bool flag = true;
			byte* ptr = stackalloc byte[(int)(uint)sizeof(UnsafeNativeMethods.EventData)];
			UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
			ptr2->DataPointer = (ulong)(&value1);
			ptr2->Size = 8u;
			return WriteEvent(ref eventDescriptor, eventTraceActivity, 1, (IntPtr)ptr);
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, long value1, long value2)
		{
			bool flag = true;
			byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 2)];
			UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
			ptr2->DataPointer = (ulong)(&value1);
			ptr2->Size = 8u;
			ptr2[1].DataPointer = (ulong)(&value2);
			ptr2[1].Size = 8u;
			return WriteEvent(ref eventDescriptor, eventTraceActivity, 2, (IntPtr)ptr);
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, long value1, long value2, long value3)
		{
			bool flag = true;
			byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 3)];
			UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
			ptr2->DataPointer = (ulong)(&value1);
			ptr2->Size = 8u;
			ptr2[1].DataPointer = (ulong)(&value2);
			ptr2[1].Size = 8u;
			ptr2[2].DataPointer = (ulong)(&value3);
			ptr2[2].Size = 8u;
			return WriteEvent(ref eventDescriptor, eventTraceActivity, 3, (IntPtr)ptr);
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, long value2, long value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11, string value12, string value13, string value14, string value15)
		{
			bool flag = true;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			value12 = value12 ?? string.Empty;
			value13 = value13 ?? string.Empty;
			value14 = value14 ?? string.Empty;
			value15 = value15 ?? string.Empty;
			fixed (char* ptr3 = value4)
			{
				fixed (char* ptr4 = value5)
				{
					fixed (char* ptr5 = value6)
					{
						fixed (char* ptr6 = value7)
						{
							fixed (char* ptr7 = value8)
							{
								fixed (char* ptr8 = value9)
								{
									fixed (char* ptr9 = value10)
									{
										fixed (char* ptr10 = value11)
										{
											fixed (char* ptr11 = value12)
											{
												fixed (char* ptr12 = value13)
												{
													fixed (char* ptr13 = value14)
													{
														fixed (char* ptr14 = value15)
														{
															byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 15)];
															UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
															ptr2->DataPointer = (ulong)(&value1);
															ptr2->Size = (uint)sizeof(Guid);
															ptr2[1].DataPointer = (ulong)(&value2);
															ptr2[1].Size = 8u;
															ptr2[2].DataPointer = (ulong)(&value3);
															ptr2[2].Size = 8u;
															ptr2[3].DataPointer = (ulong)ptr3;
															ptr2[3].Size = (uint)((value4.Length + 1) * 2);
															ptr2[4].DataPointer = (ulong)ptr4;
															ptr2[4].Size = (uint)((value5.Length + 1) * 2);
															ptr2[5].DataPointer = (ulong)ptr5;
															ptr2[5].Size = (uint)((value6.Length + 1) * 2);
															ptr2[6].DataPointer = (ulong)ptr6;
															ptr2[6].Size = (uint)((value7.Length + 1) * 2);
															ptr2[7].DataPointer = (ulong)ptr7;
															ptr2[7].Size = (uint)((value8.Length + 1) * 2);
															ptr2[8].DataPointer = (ulong)ptr8;
															ptr2[8].Size = (uint)((value9.Length + 1) * 2);
															ptr2[9].DataPointer = (ulong)ptr9;
															ptr2[9].Size = (uint)((value10.Length + 1) * 2);
															ptr2[10].DataPointer = (ulong)ptr10;
															ptr2[10].Size = (uint)((value11.Length + 1) * 2);
															ptr2[11].DataPointer = (ulong)ptr11;
															ptr2[11].Size = (uint)((value12.Length + 1) * 2);
															ptr2[12].DataPointer = (ulong)ptr12;
															ptr2[12].Size = (uint)((value13.Length + 1) * 2);
															ptr2[13].DataPointer = (ulong)ptr13;
															ptr2[13].Size = (uint)((value14.Length + 1) * 2);
															ptr2[14].DataPointer = (ulong)ptr14;
															ptr2[14].Size = (uint)((value15.Length + 1) * 2);
															flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 15, (IntPtr)ptr);
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, long value2, long value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11, string value12, bool value13, string value14, string value15, string value16, string value17)
		{
			bool flag = true;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			value12 = value12 ?? string.Empty;
			value14 = value14 ?? string.Empty;
			value15 = value15 ?? string.Empty;
			value16 = value16 ?? string.Empty;
			value17 = value17 ?? string.Empty;
			fixed (char* ptr3 = value4)
			{
				fixed (char* ptr4 = value5)
				{
					fixed (char* ptr5 = value6)
					{
						fixed (char* ptr6 = value7)
						{
							fixed (char* ptr7 = value8)
							{
								fixed (char* ptr8 = value9)
								{
									fixed (char* ptr9 = value10)
									{
										fixed (char* ptr10 = value11)
										{
											fixed (char* ptr11 = value12)
											{
												fixed (char* ptr12 = value14)
												{
													fixed (char* ptr13 = value15)
													{
														fixed (char* ptr14 = value16)
														{
															fixed (char* ptr15 = value17)
															{
																byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 17)];
																UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
																ptr2->DataPointer = (ulong)(&value1);
																ptr2->Size = (uint)sizeof(Guid);
																ptr2[1].DataPointer = (ulong)(&value2);
																ptr2[1].Size = 8u;
																ptr2[2].DataPointer = (ulong)(&value3);
																ptr2[2].Size = 8u;
																ptr2[3].DataPointer = (ulong)ptr3;
																ptr2[3].Size = (uint)((value4.Length + 1) * 2);
																ptr2[4].DataPointer = (ulong)ptr4;
																ptr2[4].Size = (uint)((value5.Length + 1) * 2);
																ptr2[5].DataPointer = (ulong)ptr5;
																ptr2[5].Size = (uint)((value6.Length + 1) * 2);
																ptr2[6].DataPointer = (ulong)ptr6;
																ptr2[6].Size = (uint)((value7.Length + 1) * 2);
																ptr2[7].DataPointer = (ulong)ptr7;
																ptr2[7].Size = (uint)((value8.Length + 1) * 2);
																ptr2[8].DataPointer = (ulong)ptr8;
																ptr2[8].Size = (uint)((value9.Length + 1) * 2);
																ptr2[9].DataPointer = (ulong)ptr9;
																ptr2[9].Size = (uint)((value10.Length + 1) * 2);
																ptr2[10].DataPointer = (ulong)ptr10;
																ptr2[10].Size = (uint)((value11.Length + 1) * 2);
																ptr2[11].DataPointer = (ulong)ptr11;
																ptr2[11].Size = (uint)((value12.Length + 1) * 2);
																ptr2[12].DataPointer = (ulong)(&value13);
																ptr2[12].Size = 1u;
																ptr2[13].DataPointer = (ulong)ptr12;
																ptr2[13].Size = (uint)((value14.Length + 1) * 2);
																ptr2[14].DataPointer = (ulong)ptr13;
																ptr2[14].Size = (uint)((value15.Length + 1) * 2);
																ptr2[15].DataPointer = (ulong)ptr14;
																ptr2[15].Size = (uint)((value16.Length + 1) * 2);
																ptr2[16].DataPointer = (ulong)ptr15;
																ptr2[16].Size = (uint)((value17.Length + 1) * 2);
																flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 17, (IntPtr)ptr);
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, long value2, long value3, string value4, string value5, string value6, string value7, string value8, string value9)
		{
			bool flag = true;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			fixed (char* ptr3 = value4)
			{
				fixed (char* ptr4 = value5)
				{
					fixed (char* ptr5 = value6)
					{
						fixed (char* ptr6 = value7)
						{
							fixed (char* ptr7 = value8)
							{
								fixed (char* ptr8 = value9)
								{
									byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 9)];
									UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
									ptr2->DataPointer = (ulong)(&value1);
									ptr2->Size = (uint)sizeof(Guid);
									ptr2[1].DataPointer = (ulong)(&value2);
									ptr2[1].Size = 8u;
									ptr2[2].DataPointer = (ulong)(&value3);
									ptr2[2].Size = 8u;
									ptr2[3].DataPointer = (ulong)ptr3;
									ptr2[3].Size = (uint)((value4.Length + 1) * 2);
									ptr2[4].DataPointer = (ulong)ptr4;
									ptr2[4].Size = (uint)((value5.Length + 1) * 2);
									ptr2[5].DataPointer = (ulong)ptr5;
									ptr2[5].Size = (uint)((value6.Length + 1) * 2);
									ptr2[6].DataPointer = (ulong)ptr6;
									ptr2[6].Size = (uint)((value7.Length + 1) * 2);
									ptr2[7].DataPointer = (ulong)ptr7;
									ptr2[7].Size = (uint)((value8.Length + 1) * 2);
									ptr2[8].DataPointer = (ulong)ptr8;
									ptr2[8].Size = (uint)((value9.Length + 1) * 2);
									flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 9, (IntPtr)ptr);
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, long value2, long value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11)
		{
			bool flag = true;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			fixed (char* ptr3 = value4)
			{
				fixed (char* ptr4 = value5)
				{
					fixed (char* ptr5 = value6)
					{
						fixed (char* ptr6 = value7)
						{
							fixed (char* ptr7 = value8)
							{
								fixed (char* ptr8 = value9)
								{
									fixed (char* ptr9 = value10)
									{
										fixed (char* ptr10 = value11)
										{
											byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 11)];
											UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
											ptr2->DataPointer = (ulong)(&value1);
											ptr2->Size = (uint)sizeof(Guid);
											ptr2[1].DataPointer = (ulong)(&value2);
											ptr2[1].Size = 8u;
											ptr2[2].DataPointer = (ulong)(&value3);
											ptr2[2].Size = 8u;
											ptr2[3].DataPointer = (ulong)ptr3;
											ptr2[3].Size = (uint)((value4.Length + 1) * 2);
											ptr2[4].DataPointer = (ulong)ptr4;
											ptr2[4].Size = (uint)((value5.Length + 1) * 2);
											ptr2[5].DataPointer = (ulong)ptr5;
											ptr2[5].Size = (uint)((value6.Length + 1) * 2);
											ptr2[6].DataPointer = (ulong)ptr6;
											ptr2[6].Size = (uint)((value7.Length + 1) * 2);
											ptr2[7].DataPointer = (ulong)ptr7;
											ptr2[7].Size = (uint)((value8.Length + 1) * 2);
											ptr2[8].DataPointer = (ulong)ptr8;
											ptr2[8].Size = (uint)((value9.Length + 1) * 2);
											ptr2[9].DataPointer = (ulong)ptr9;
											ptr2[9].Size = (uint)((value10.Length + 1) * 2);
											ptr2[10].DataPointer = (ulong)ptr10;
											ptr2[10].Size = (uint)((value11.Length + 1) * 2);
											flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 11, (IntPtr)ptr);
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, long value2, long value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11, string value12, string value13)
		{
			bool flag = true;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			value12 = value12 ?? string.Empty;
			value13 = value13 ?? string.Empty;
			fixed (char* ptr3 = value4)
			{
				fixed (char* ptr4 = value5)
				{
					fixed (char* ptr5 = value6)
					{
						fixed (char* ptr6 = value7)
						{
							fixed (char* ptr7 = value8)
							{
								fixed (char* ptr8 = value9)
								{
									fixed (char* ptr9 = value10)
									{
										fixed (char* ptr10 = value11)
										{
											fixed (char* ptr11 = value12)
											{
												fixed (char* ptr12 = value13)
												{
													byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 13)];
													UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
													ptr2->DataPointer = (ulong)(&value1);
													ptr2->Size = (uint)sizeof(Guid);
													ptr2[1].DataPointer = (ulong)(&value2);
													ptr2[1].Size = 8u;
													ptr2[2].DataPointer = (ulong)(&value3);
													ptr2[2].Size = 8u;
													ptr2[3].DataPointer = (ulong)ptr3;
													ptr2[3].Size = (uint)((value4.Length + 1) * 2);
													ptr2[4].DataPointer = (ulong)ptr4;
													ptr2[4].Size = (uint)((value5.Length + 1) * 2);
													ptr2[5].DataPointer = (ulong)ptr5;
													ptr2[5].Size = (uint)((value6.Length + 1) * 2);
													ptr2[6].DataPointer = (ulong)ptr6;
													ptr2[6].Size = (uint)((value7.Length + 1) * 2);
													ptr2[7].DataPointer = (ulong)ptr7;
													ptr2[7].Size = (uint)((value8.Length + 1) * 2);
													ptr2[8].DataPointer = (ulong)ptr8;
													ptr2[8].Size = (uint)((value9.Length + 1) * 2);
													ptr2[9].DataPointer = (ulong)ptr9;
													ptr2[9].Size = (uint)((value10.Length + 1) * 2);
													ptr2[10].DataPointer = (ulong)ptr10;
													ptr2[10].Size = (uint)((value11.Length + 1) * 2);
													ptr2[11].DataPointer = (ulong)ptr11;
													ptr2[11].Size = (uint)((value12.Length + 1) * 2);
													ptr2[12].DataPointer = (ulong)ptr12;
													ptr2[12].Size = (uint)((value13.Length + 1) * 2);
													flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 13, (IntPtr)ptr);
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, long value2, long value3, string value4, string value5, string value6, string value7, string value8, string value9, string value10, string value11, string value12, string value13, string value14)
		{
			bool flag = true;
			value4 = value4 ?? string.Empty;
			value5 = value5 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			value12 = value12 ?? string.Empty;
			value13 = value13 ?? string.Empty;
			value14 = value14 ?? string.Empty;
			fixed (char* ptr3 = value4)
			{
				fixed (char* ptr4 = value5)
				{
					fixed (char* ptr5 = value6)
					{
						fixed (char* ptr6 = value7)
						{
							fixed (char* ptr7 = value8)
							{
								fixed (char* ptr8 = value9)
								{
									fixed (char* ptr9 = value10)
									{
										fixed (char* ptr10 = value11)
										{
											fixed (char* ptr11 = value12)
											{
												fixed (char* ptr12 = value13)
												{
													fixed (char* ptr13 = value14)
													{
														byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 14)];
														UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
														ptr2->DataPointer = (ulong)(&value1);
														ptr2->Size = (uint)sizeof(Guid);
														ptr2[1].DataPointer = (ulong)(&value2);
														ptr2[1].Size = 8u;
														ptr2[2].DataPointer = (ulong)(&value3);
														ptr2[2].Size = 8u;
														ptr2[3].DataPointer = (ulong)ptr3;
														ptr2[3].Size = (uint)((value4.Length + 1) * 2);
														ptr2[4].DataPointer = (ulong)ptr4;
														ptr2[4].Size = (uint)((value5.Length + 1) * 2);
														ptr2[5].DataPointer = (ulong)ptr5;
														ptr2[5].Size = (uint)((value6.Length + 1) * 2);
														ptr2[6].DataPointer = (ulong)ptr6;
														ptr2[6].Size = (uint)((value7.Length + 1) * 2);
														ptr2[7].DataPointer = (ulong)ptr7;
														ptr2[7].Size = (uint)((value8.Length + 1) * 2);
														ptr2[8].DataPointer = (ulong)ptr8;
														ptr2[8].Size = (uint)((value9.Length + 1) * 2);
														ptr2[9].DataPointer = (ulong)ptr9;
														ptr2[9].Size = (uint)((value10.Length + 1) * 2);
														ptr2[10].DataPointer = (ulong)ptr10;
														ptr2[10].Size = (uint)((value11.Length + 1) * 2);
														ptr2[11].DataPointer = (ulong)ptr11;
														ptr2[11].Size = (uint)((value12.Length + 1) * 2);
														ptr2[12].DataPointer = (ulong)ptr12;
														ptr2[12].Size = (uint)((value13.Length + 1) * 2);
														ptr2[13].DataPointer = (ulong)ptr13;
														ptr2[13].Size = (uint)((value14.Length + 1) * 2);
														flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 14, (IntPtr)ptr);
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, Guid value1, long value2, long value3, string value4, Guid value5, string value6, string value7, string value8, string value9, string value10, string value11, string value12, string value13)
		{
			bool flag = true;
			value4 = value4 ?? string.Empty;
			value6 = value6 ?? string.Empty;
			value7 = value7 ?? string.Empty;
			value8 = value8 ?? string.Empty;
			value9 = value9 ?? string.Empty;
			value10 = value10 ?? string.Empty;
			value11 = value11 ?? string.Empty;
			value12 = value12 ?? string.Empty;
			value13 = value13 ?? string.Empty;
			fixed (char* ptr3 = value4)
			{
				fixed (char* ptr4 = value6)
				{
					fixed (char* ptr5 = value7)
					{
						fixed (char* ptr6 = value8)
						{
							fixed (char* ptr7 = value9)
							{
								fixed (char* ptr8 = value10)
								{
									fixed (char* ptr9 = value11)
									{
										fixed (char* ptr10 = value12)
										{
											fixed (char* ptr11 = value13)
											{
												byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 13)];
												UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
												ptr2->DataPointer = (ulong)(&value1);
												ptr2->Size = (uint)sizeof(Guid);
												ptr2[1].DataPointer = (ulong)(&value2);
												ptr2[1].Size = 8u;
												ptr2[2].DataPointer = (ulong)(&value3);
												ptr2[2].Size = 8u;
												ptr2[3].DataPointer = (ulong)ptr3;
												ptr2[3].Size = (uint)((value4.Length + 1) * 2);
												ptr2[4].DataPointer = (ulong)(&value5);
												ptr2[4].Size = (uint)sizeof(Guid);
												ptr2[5].DataPointer = (ulong)ptr4;
												ptr2[5].Size = (uint)((value6.Length + 1) * 2);
												ptr2[6].DataPointer = (ulong)ptr5;
												ptr2[6].Size = (uint)((value7.Length + 1) * 2);
												ptr2[7].DataPointer = (ulong)ptr6;
												ptr2[7].Size = (uint)((value8.Length + 1) * 2);
												ptr2[8].DataPointer = (ulong)ptr7;
												ptr2[8].Size = (uint)((value9.Length + 1) * 2);
												ptr2[9].DataPointer = (ulong)ptr8;
												ptr2[9].Size = (uint)((value10.Length + 1) * 2);
												ptr2[10].DataPointer = (ulong)ptr9;
												ptr2[10].Size = (uint)((value11.Length + 1) * 2);
												ptr2[11].DataPointer = (ulong)ptr10;
												ptr2[11].Size = (uint)((value12.Length + 1) * 2);
												ptr2[12].DataPointer = (ulong)ptr11;
												ptr2[12].Size = (uint)((value13.Length + 1) * 2);
												flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 13, (IntPtr)ptr);
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return flag;
		}

		[SecurityCritical]
		internal unsafe bool WriteEvent(ref EventDescriptor eventDescriptor, EventTraceActivity eventTraceActivity, string value1, long value2, string value3, string value4)
		{
			bool flag = true;
			value1 = value1 ?? string.Empty;
			value3 = value3 ?? string.Empty;
			value4 = value4 ?? string.Empty;
			fixed (char* ptr3 = value1)
			{
				fixed (char* ptr4 = value3)
				{
					fixed (char* ptr5 = value4)
					{
						byte* ptr = stackalloc byte[(int)(uint)(sizeof(UnsafeNativeMethods.EventData) * 4)];
						UnsafeNativeMethods.EventData* ptr2 = (UnsafeNativeMethods.EventData*)ptr;
						ptr2->DataPointer = (ulong)ptr3;
						ptr2->Size = (uint)((value1.Length + 1) * 2);
						ptr2[1].DataPointer = (ulong)(&value2);
						ptr2[1].Size = 8u;
						ptr2[2].DataPointer = (ulong)ptr4;
						ptr2[2].Size = (uint)((value3.Length + 1) * 2);
						ptr2[3].DataPointer = (ulong)ptr5;
						ptr2[3].Size = (uint)((value4.Length + 1) * 2);
						flag = WriteEvent(ref eventDescriptor, eventTraceActivity, 4, (IntPtr)ptr);
					}
				}
			}
			return flag;
		}
	}
	internal interface ITraceSourceStringProvider
	{
		string GetSourceString();
	}
}
namespace System.Runtime.Collections
{
	internal class HopperCache
	{
		private class LastHolder
		{
			private readonly object key;

			private readonly object value;

			internal object Key => key;

			internal object Value => value;

			internal LastHolder(object key, object value)
			{
				this.key = key;
				this.value = value;
			}
		}

		private readonly int hopperSize;

		private readonly bool weak;

		private Hashtable outstandingHopper;

		private Hashtable strongHopper;

		private Hashtable limitedHopper;

		private int promoting;

		private LastHolder mruEntry;

		public HopperCache(int hopperSize, bool weak)
		{
			this.hopperSize = hopperSize;
			this.weak = weak;
			outstandingHopper = new Hashtable(hopperSize * 2);
			strongHopper = new Hashtable(hopperSize * 2);
			limitedHopper = new Hashtable(hopperSize * 2);
		}

		public void Add(object key, object value)
		{
			if (weak && value != DBNull.Value)
			{
				value = new WeakReference(value);
			}
			if (strongHopper.Count >= hopperSize * 2)
			{
				Hashtable hashtable = limitedHopper;
				hashtable.Clear();
				hashtable.Add(key, value);
				try
				{
					return;
				}
				finally
				{
					limitedHopper = strongHopper;
					strongHopper = hashtable;
				}
			}
			strongHopper[key] = value;
		}

		public object GetValue(object syncObject, object key)
		{
			LastHolder lastHolder = mruEntry;
			object target;
			if (lastHolder != null && key.Equals(lastHolder.Key))
			{
				if (!weak || !(lastHolder.Value is WeakReference weakReference))
				{
					return lastHolder.Value;
				}
				target = weakReference.Target;
				if (target != null)
				{
					return target;
				}
				mruEntry = null;
			}
			object obj = outstandingHopper[key];
			target = ((weak && obj is WeakReference weakReference2) ? weakReference2.Target : obj);
			if (target != null)
			{
				mruEntry = new LastHolder(key, obj);
				return target;
			}
			obj = strongHopper[key];
			target = ((weak && obj is WeakReference weakReference3) ? weakReference3.Target : obj);
			if (target == null)
			{
				obj = limitedHopper[key];
				target = ((weak && obj is WeakReference weakReference4) ? weakReference4.Target : obj);
				if (target == null)
				{
					return null;
				}
			}
			mruEntry = new LastHolder(key, obj);
			int num = 1;
			try
			{
				try
				{
				}
				finally
				{
					num = Interlocked.CompareExchange(ref promoting, 1, 0);
				}
				if (num == 0)
				{
					if (outstandingHopper.Count >= hopperSize)
					{
						lock (syncObject)
						{
							Hashtable hashtable = limitedHopper;
							hashtable.Clear();
							hashtable.Add(key, obj);
							try
							{
								return target;
							}
							finally
							{
								limitedHopper = strongHopper;
								strongHopper = outstandingHopper;
								outstandingHopper = hashtable;
							}
						}
					}
					outstandingHopper[key] = obj;
					return target;
				}
				return target;
			}
			finally
			{
				if (num == 0)
				{
					promoting = 0;
				}
			}
		}
	}
	internal class NullableKeyDictionary<TKey, TValue> : IDictionary<TKey, TValue>, ICollection<KeyValuePair<TKey, TValue>>, IEnumerable<KeyValuePair<TKey, TValue>>, IEnumerable
	{
		private class NullKeyDictionaryKeyCollection<TypeKey, TypeValue> : ICollection<TypeKey>, IEnumerable<TypeKey>, IEnumerable
		{
			private NullableKeyDictionary<TypeKey, TypeValue> nullKeyDictionary;

			public int Count
			{
				get
				{
					int num = nullKeyDictionary.innerDictionary.Keys.Count;
					if (nullKeyDictionary.isNullKeyPresent)
					{
						num++;
					}
					return num;
				}
			}

			public bool IsReadOnly => true;

			public NullKeyDictionaryKeyCollection(NullableKeyDictionary<TypeKey, TypeValue> nullKeyDictionary)
			{
				this.nullKeyDictionary = nullKeyDictionary;
			}

			public void Add(TypeKey item)
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.KeyCollectionUpdatesNotAllowed));
			}

			public void Clear()
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.KeyCollectionUpdatesNotAllowed));
			}

			public bool Contains(TypeKey item)
			{
				if (item != null)
				{
					return nullKeyDictionary.innerDictionary.Keys.Contains(item);
				}
				return nullKeyDictionary.isNullKeyPresent;
			}

			public void CopyTo(TypeKey[] array, int arrayIndex)
			{
				nullKeyDictionary.innerDictionary.Keys.CopyTo(array, arrayIndex);
				if (nullKeyDictionary.isNullKeyPresent)
				{
					array[arrayIndex + nullKeyDictionary.innerDictionary.Keys.Count] = default(TypeKey);
				}
			}

			public bool Remove(TypeKey item)
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.KeyCollectionUpdatesNotAllowed));
			}

			public IEnumerator<TypeKey> GetEnumerator()
			{
				foreach (TypeKey key in nullKeyDictionary.innerDictionary.Keys)
				{
					yield return key;
				}
				if (nullKeyDictionary.isNullKeyPresent)
				{
					yield return default(TypeKey);
				}
			}

			IEnumerator IEnumerable.GetEnumerator()
			{
				return ((IEnumerable<TypeKey>)this).GetEnumerator();
			}
		}

		private class NullKeyDictionaryValueCollection<TypeKey, TypeValue> : ICollection<TypeValue>, IEnumerable<TypeValue>, IEnumerable
		{
			private NullableKeyDictionary<TypeKey, TypeValue> nullKeyDictionary;

			public int Count
			{
				get
				{
					int num = nullKeyDictionary.innerDictionary.Values.Count;
					if (nullKeyDictionary.isNullKeyPresent)
					{
						num++;
					}
					return num;
				}
			}

			public bool IsReadOnly => true;

			public NullKeyDictionaryValueCollection(NullableKeyDictionary<TypeKey, TypeValue> nullKeyDictionary)
			{
				this.nullKeyDictionary = nullKeyDictionary;
			}

			public void Add(TypeValue item)
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.ValueCollectionUpdatesNotAllowed));
			}

			public void Clear()
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.ValueCollectionUpdatesNotAllowed));
			}

			public bool Contains(TypeValue item)
			{
				if (!nullKeyDictionary.innerDictionary.Values.Contains(item))
				{
					if (nullKeyDictionary.isNullKeyPresent)
					{
						return nullKeyDictionary.nullKeyValue.Equals(item);
					}
					return false;
				}
				return true;
			}

			public void CopyTo(TypeValue[] array, int arrayIndex)
			{
				nullKeyDictionary.innerDictionary.Values.CopyTo(array, arrayIndex);
				if (nullKeyDictionary.isNullKeyPresent)
				{
					array[arrayIndex + nullKeyDictionary.innerDictionary.Values.Count] = nullKeyDictionary.nullKeyValue;
				}
			}

			public bool Remove(TypeValue item)
			{
				throw Fx.Exception.AsError(new NotSupportedException(InternalSR.ValueCollectionUpdatesNotAllowed));
			}

			public IEnumerator<TypeValue> GetEnumerator()
			{
				foreach (TypeValue value in nullKeyDictionary.innerDictionary.Values)
				{
					yield return value;
				}
				if (nullKeyDictionary.isNullKeyPresent)
				{
					yield return nullKeyDictionary.nullKeyValue;
				}
			}

			IEnumerator IEnumerable.GetEnumerator()
			{
				return ((IEnumerable<TypeValue>)this).GetEnumerator();
			}
		}

		private bool isNullKeyPresent;

		private TValue nullKeyValue;

		private IDictionary<TKey, TValue> innerDictionary;

		public int Count => innerDictionary.Count + (isNullKeyPresent ? 1 : 0);

		public bool IsReadOnly => false;

		public ICollection<TKey> Keys => new NullKeyDictionaryKeyCollection<TKey, TValue>(this);

		public ICollection<TValue> Values => new NullKeyDictionaryValueCollection<TKey, TValue>(this);

		public TValue this[TKey key]
		{
			get
			{
				if (key == null)
				{
					if (isNullKeyPresent)
					{
						return nullKeyValue;
					}
					throw Fx.Exception.AsError(new KeyNotFoundException());
				}
				return innerDictionary[key];
			}
			set
			{
				if (key == null)
				{
					isNullKeyPresent = true;
					nullKeyValue = value;
				}
				else
				{
					innerDictionary[key] = value;
				}
			}
		}

		public NullableKeyDictionary()
		{
			innerDictionary = new Dictionary<TKey, TValue>();
		}

		public void Add(TKey key, TValue value)
		{
			if (key == null)
			{
				if (isNullKeyPresent)
				{
					throw Fx.Exception.Argument("key", InternalSR.NullKeyAlreadyPresent);
				}
				isNullKeyPresent = true;
				nullKeyValue = value;
			}
			else
			{
				innerDictionary.Add(key, value);
			}
		}

		public bool ContainsKey(TKey key)
		{
			if (key != null)
			{
				return innerDictionary.ContainsKey(key);
			}
			return isNullKeyPresent;
		}

		public bool Remove(TKey key)
		{
			if (key == null)
			{
				bool result = isNullKeyPresent;
				isNullKeyPresent = false;
				nullKeyValue = default(TValue);
				return result;
			}
			return innerDictionary.Remove(key);
		}

		public bool TryGetValue(TKey key, out TValue value)
		{
			if (key == null)
			{
				if (isNullKeyPresent)
				{
					value = nullKeyValue;
					return true;
				}
				value = default(TValue);
				return false;
			}
			return innerDictionary.TryGetValue(key, out value);
		}

		public void Add(KeyValuePair<TKey, TValue> item)
		{
			Add(item.Key, item.Value);
		}

		public void Clear()
		{
			isNullKeyPresent = false;
			nullKeyValue = default(TValue);
			innerDictionary.Clear();
		}

		public bool Contains(KeyValuePair<TKey, TValue> item)
		{
			if (item.Key == null)
			{
				if (isNullKeyPresent)
				{
					if (item.Value != null)
					{
						return item.Value.Equals(nullKeyValue);
					}
					return nullKeyValue == null;
				}
				return false;
			}
			return innerDictionary.Contains(item);
		}

		public void CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
		{
			innerDictionary.CopyTo(array, arrayIndex);
			if (isNullKeyPresent)
			{
				array[arrayIndex + innerDictionary.Count] = new KeyValuePair<TKey, TValue>(default(TKey), nullKeyValue);
			}
		}

		public bool Remove(KeyValuePair<TKey, TValue> item)
		{
			if (item.Key == null)
			{
				if (Contains(item))
				{
					isNullKeyPresent = false;
					nullKeyValue = default(TValue);
					return true;
				}
				return false;
			}
			return innerDictionary.Remove(item);
		}

		public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
		{
			IEnumerator<KeyValuePair<TKey, TValue>> innerEnumerator = innerDictionary.GetEnumerator();
			while (innerEnumerator.MoveNext())
			{
				yield return innerEnumerator.Current;
			}
			if (isNullKeyPresent)
			{
				yield return new KeyValuePair<TKey, TValue>(default(TKey), nullKeyValue);
			}
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return ((IEnumerable<KeyValuePair<TKey, TValue>>)this).GetEnumerator();
		}
	}
	internal class ObjectCache<TKey, TValue> where TValue : class
	{
		private class Item : ObjectCacheItem<TValue>
		{
			private readonly ObjectCache<TKey, TValue> parent;

			private readonly TKey key;

			private readonly Action<TValue> disposeItemCallback;

			private TValue value;

			private int referenceCount;

			public int ReferenceCount => referenceCount;

			public override TValue Value => value;

			public DateTime CreationTime { get; set; }

			public DateTime LastUsage { get; set; }

			public Item(TKey key, TValue value, Action<TValue> disposeItemCallback)
				: this(key, value)
			{
				this.disposeItemCallback = disposeItemCallback;
			}

			public Item(TKey key, TValue value, ObjectCache<TKey, TValue> parent)
				: this(key, value)
			{
				this.parent = parent;
			}

			private Item(TKey key, TValue value)
			{
				this.key = key;
				this.value = value;
				referenceCount = 1;
			}

			public override bool TryAddReference()
			{
				bool result;
				if (parent == null || referenceCount == -1)
				{
					result = false;
				}
				else
				{
					bool flag = false;
					lock (parent.ThisLock)
					{
						if (referenceCount == -1)
						{
							result = false;
						}
						else if (referenceCount == 0 && parent.ShouldPurgeItem(this, DateTime.UtcNow))
						{
							LockedDispose();
							flag = true;
							result = false;
							parent.cacheItems.Remove(key);
						}
						else
						{
							referenceCount++;
							result = true;
						}
					}
					if (flag)
					{
						LocalDispose();
					}
				}
				return result;
			}

			public override void ReleaseReference()
			{
				bool flag;
				if (parent == null)
				{
					referenceCount = -1;
					flag = true;
				}
				else
				{
					lock (parent.ThisLock)
					{
						if (referenceCount > 1)
						{
							InternalReleaseReference();
							flag = false;
						}
						else
						{
							flag = parent.Return(key, this);
						}
					}
				}
				if (flag)
				{
					LocalDispose();
				}
			}

			internal void InternalAddReference()
			{
				referenceCount++;
			}

			internal void InternalReleaseReference()
			{
				referenceCount--;
			}

			public void LockedDispose()
			{
				referenceCount = -1;
			}

			public void Dispose()
			{
				if (Value != null)
				{
					Action<TValue> action = disposeItemCallback;
					if (parent != null)
					{
						action = parent.DisposeItemCallback;
					}
					if (action != null)
					{
						action(Value);
					}
					else if (Value is IDisposable)
					{
						((IDisposable)Value).Dispose();
					}
				}
				value = null;
				referenceCount = -1;
			}

			public void LocalDispose()
			{
				Dispose();
			}
		}

		private const int timerThreshold = 1;

		private ObjectCacheSettings settings;

		private Dictionary<TKey, Item> cacheItems;

		private bool idleTimeoutEnabled;

		private bool leaseTimeoutEnabled;

		private IOThreadTimer idleTimer;

		private static Action<object> onIdle;

		private bool disposed;

		private object ThisLock => this;

		public Action<TValue> DisposeItemCallback { get; set; }

		public int Count => cacheItems.Count;

		public ObjectCache(ObjectCacheSettings settings)
			: this(settings, (IEqualityComparer<TKey>)null)
		{
		}

		public ObjectCache(ObjectCacheSettings settings, IEqualityComparer<TKey> comparer)
		{
			this.settings = settings.Clone();
			cacheItems = new Dictionary<TKey, Item>(comparer);
			idleTimeoutEnabled = settings.IdleTimeout != TimeSpan.MaxValue;
			leaseTimeoutEnabled = settings.LeaseTimeout != TimeSpan.MaxValue;
		}

		public ObjectCacheItem<TValue> Add(TKey key, TValue value)
		{
			lock (ThisLock)
			{
				if (Count >= settings.CacheLimit || cacheItems.ContainsKey(key))
				{
					return new Item(key, value, DisposeItemCallback);
				}
				return InternalAdd(key, value);
			}
		}

		public ObjectCacheItem<TValue> Take(TKey key)
		{
			return Take(key, null);
		}

		public ObjectCacheItem<TValue> Take(TKey key, Func<TValue> initializerDelegate)
		{
			Item value = null;
			lock (ThisLock)
			{
				if (cacheItems.TryGetValue(key, out value))
				{
					value.InternalAddReference();
					return value;
				}
				if (initializerDelegate == null)
				{
					return null;
				}
				TValue value2 = initializerDelegate();
				if (Count >= settings.CacheLimit)
				{
					return new Item(key, value2, DisposeItemCallback);
				}
				return InternalAdd(key, value2);
			}
		}

		private Item InternalAdd(TKey key, TValue value)
		{
			Item item = new Item(key, value, this);
			if (leaseTimeoutEnabled)
			{
				item.CreationTime = DateTime.UtcNow;
			}
			cacheItems.Add(key, item);
			StartTimerIfNecessary();
			return item;
		}

		private bool Return(TKey key, Item cacheItem)
		{
			bool result = false;
			if (disposed)
			{
				result = true;
			}
			else
			{
				cacheItem.InternalReleaseReference();
				DateTime utcNow = DateTime.UtcNow;
				if (idleTimeoutEnabled)
				{
					cacheItem.LastUsage = utcNow;
				}
				if (ShouldPurgeItem(cacheItem, utcNow))
				{
					bool flag = cacheItems.Remove(key);
					cacheItem.LockedDispose();
					result = true;
				}
			}
			return result;
		}

		private void StartTimerIfNecessary()
		{
			if (!idleTimeoutEnabled || Count <= 1)
			{
				return;
			}
			if (idleTimer == null)
			{
				if (onIdle == null)
				{
					onIdle = OnIdle;
				}
				idleTimer = new IOThreadTimer(onIdle, this, isTypicallyCanceledShortlyAfterBeingSet: false);
			}
			idleTimer.Set(settings.IdleTimeout);
		}

		private static void OnIdle(object state)
		{
			ObjectCache<TKey, TValue> objectCache = (ObjectCache<TKey, TValue>)state;
			objectCache.PurgeCache(calledFromTimer: true);
		}

		private static void Add<T>(ref List<T> list, T item)
		{
			if (list == null)
			{
				list = new List<T>();
			}
			list.Add(item);
		}

		private bool ShouldPurgeItem(Item cacheItem, DateTime now)
		{
			if (cacheItem.ReferenceCount > 0)
			{
				return false;
			}
			if (idleTimeoutEnabled && now >= cacheItem.LastUsage + settings.IdleTimeout)
			{
				return true;
			}
			if (leaseTimeoutEnabled && now - cacheItem.CreationTime >= settings.LeaseTimeout)
			{
				return true;
			}
			return false;
		}

		private void GatherExpiredItems(ref List<KeyValuePair<TKey, Item>> expiredItems, bool calledFromTimer)
		{
			if (Count == 0 || (!leaseTimeoutEnabled && !idleTimeoutEnabled))
			{
				return;
			}
			DateTime utcNow = DateTime.UtcNow;
			bool flag = false;
			lock (ThisLock)
			{
				foreach (KeyValuePair<TKey, Item> cacheItem in cacheItems)
				{
					if (ShouldPurgeItem(cacheItem.Value, utcNow))
					{
						cacheItem.Value.LockedDispose();
						Add(ref expiredItems, cacheItem);
					}
				}
				if (expiredItems != null)
				{
					for (int i = 0; i < expiredItems.Count; i++)
					{
						cacheItems.Remove(expiredItems[i].Key);
					}
				}
				flag = calledFromTimer && Count > 0;
			}
			if (flag)
			{
				idleTimer.Set(settings.IdleTimeout);
			}
		}

		private void PurgeCache(bool calledFromTimer)
		{
			List<KeyValuePair<TKey, Item>> expiredItems = null;
			lock (ThisLock)
			{
				GatherExpiredItems(ref expiredItems, calledFromTimer);
			}
			if (expiredItems != null)
			{
				for (int i = 0; i < expiredItems.Count; i++)
				{
					expiredItems[i].Value.LocalDispose();
				}
			}
		}

		public void Dispose()
		{
			lock (ThisLock)
			{
				foreach (Item value in cacheItems.Values)
				{
					value?.Dispose();
				}
				cacheItems.Clear();
				settings.CacheLimit = 0;
				disposed = true;
				if (idleTimer != null)
				{
					idleTimer.Cancel();
					idleTimer = null;
				}
			}
		}
	}
	internal abstract class ObjectCacheItem<T> where T : class
	{
		public abstract T Value { get; }

		public abstract bool TryAddReference();

		public abstract void ReleaseReference();
	}
	internal class ObjectCacheSettings
	{
		private int cacheLimit;

		private TimeSpan idleTimeout;

		private TimeSpan leaseTimeout;

		private int purgeFrequency;

		private const int DefaultCacheLimit = 64;

		private const int DefaultPurgeFrequency = 32;

		private static TimeSpan DefaultIdleTimeout = TimeSpan.FromMinutes(2.0);

		private static TimeSpan DefaultLeaseTimeout = TimeSpan.FromMinutes(5.0);

		public int CacheLimit
		{
			get
			{
				return cacheLimit;
			}
			set
			{
				cacheLimit = value;
			}
		}

		public TimeSpan IdleTimeout
		{
			get
			{
				return idleTimeout;
			}
			set
			{
				idleTimeout = value;
			}
		}

		public TimeSpan LeaseTimeout
		{
			get
			{
				return leaseTimeout;
			}
			set
			{
				leaseTimeout = value;
			}
		}

		public int PurgeFrequency
		{
			get
			{
				return purgeFrequency;
			}
			set
			{
				purgeFrequency = value;
			}
		}

		public ObjectCacheSettings()
		{
			CacheLimit = 64;
			IdleTimeout = DefaultIdleTimeout;
			LeaseTimeout = DefaultLeaseTimeout;
			PurgeFrequency = 32;
		}

		private ObjectCacheSettings(ObjectCacheSettings other)
		{
			CacheLimit = other.CacheLimit;
			IdleTimeout = other.IdleTimeout;
			LeaseTimeout = other.LeaseTimeout;
			PurgeFrequency = other.PurgeFrequency;
		}

		internal ObjectCacheSettings Clone()
		{
			return new ObjectCacheSettings(this);
		}
	}
	internal class ValidatingCollection<T> : Collection<T>
	{
		public Action<T> OnAddValidationCallback { get; set; }

		public Action OnMutateValidationCallback { get; set; }

		private void OnAdd(T item)
		{
			if (OnAddValidationCallback != null)
			{
				OnAddValidationCallback(item);
			}
		}

		private void OnMutate()
		{
			if (OnMutateValidationCallback != null)
			{
				OnMutateValidationCallback();
			}
		}

		protected override void ClearItems()
		{
			OnMutate();
			base.ClearItems();
		}

		protected override void InsertItem(int index, T item)
		{
			OnAdd(item);
			base.InsertItem(index, item);
		}

		protected override void RemoveItem(int index)
		{
			OnMutate();
			base.RemoveItem(index);
		}

		protected override void SetItem(int index, T item)
		{
			OnAdd(item);
			OnMutate();
			base.SetItem(index, item);
		}
	}
	internal class OrderedDictionary<TKey, TValue> : IDictionary<TKey, TValue>, ICollection<KeyValuePair<TKey, TValue>>, IEnumerable<KeyValuePair<TKey, TValue>>, IEnumerable, IDictionary, ICollection
	{
		private OrderedDictionary privateDictionary;

		public int Count => privateDictionary.Count;

		public bool IsReadOnly => false;

		public TValue this[TKey key]
		{
			get
			{
				if (key == null)
				{
					throw Fx.Exception.ArgumentNull("key");
				}
				if (privateDictionary.Contains(key))
				{
					return (TValue)privateDictionary[key];
				}
				throw Fx.Exception.AsError(new KeyNotFoundException(InternalSR.KeyNotFoundInDictionary));
			}
			set
			{
				if (key == null)
				{
					throw Fx.Exception.ArgumentNull("key");
				}
				privateDictionary[key] = value;
			}
		}

		public ICollection<TKey> Keys
		{
			get
			{
				List<TKey> list = new List<TKey>(privateDictionary.Count);
				foreach (TKey key in privateDictionary.Keys)
				{
					list.Add(key);
				}
				return list;
			}
		}

		public ICollection<TValue> Values
		{
			get
			{
				List<TValue> list = new List<TValue>(privateDictionary.Count);
				foreach (TValue value in privateDictionary.Values)
				{
					list.Add(value);
				}
				return list;
			}
		}

		bool IDictionary.IsFixedSize => ((IDictionary)privateDictionary).IsFixedSize;

		bool IDictionary.IsReadOnly => privateDictionary.IsReadOnly;

		ICollection IDictionary.Keys => privateDictionary.Keys;

		ICollection IDictionary.Values => privateDictionary.Values;

		object IDictionary.this[object key]
		{
			get
			{
				return privateDictionary[key];
			}
			set
			{
				privateDictionary[key] = value;
			}
		}

		int ICollection.Count => privateDictionary.Count;

		bool ICollection.IsSynchronized => ((ICollection)privateDictionary).IsSynchronized;

		object ICollection.SyncRoot => ((ICollection)privateDictionary).SyncRoot;

		public OrderedDictionary()
		{
			privateDictionary = new OrderedDictionary();
		}

		public OrderedDictionary(IDictionary<TKey, TValue> dictionary)
		{
			if (dictionary == null)
			{
				return;
			}
			privateDictionary = new OrderedDictionary();
			foreach (KeyValuePair<TKey, TValue> item in dictionary)
			{
				privateDictionary.Add(item.Key, item.Value);
			}
		}

		public void Add(KeyValuePair<TKey, TValue> item)
		{
			Add(item.Key, item.Value);
		}

		public void Add(TKey key, TValue value)
		{
			if (key == null)
			{
				throw Fx.Exception.ArgumentNull("key");
			}
			privateDictionary.Add(key, value);
		}

		public void Clear()
		{
			privateDictionary.Clear();
		}

		public bool Contains(KeyValuePair<TKey, TValue> item)
		{
			if (item.Key == null || !privateDictionary.Contains(item.Key))
			{
				return false;
			}
			return privateDictionary[item.Key].Equals(item.Value);
		}

		public bool ContainsKey(TKey key)
		{
			if (key == null)
			{
				throw Fx.Exception.ArgumentNull("key");
			}
			return privateDictionary.Contains(key);
		}

		public void CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
		{
			if (array == null)
			{
				throw Fx.Exception.ArgumentNull("array");
			}
			if (arrayIndex < 0)
			{
				throw Fx.Exception.AsError(new ArgumentOutOfRangeException("arrayIndex"));
			}
			if (array.Rank > 1 || arrayIndex >= array.Length || array.Length - arrayIndex < privateDictionary.Count)
			{
				throw Fx.Exception.Argument("array", InternalSR.BadCopyToArray);
			}
			int num = arrayIndex;
			foreach (DictionaryEntry item in privateDictionary)
			{
				array[num] = new KeyValuePair<TKey, TValue>((TKey)item.Key, (TValue)item.Value);
				num++;
			}
		}

		public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
		{
			foreach (DictionaryEntry item in privateDictionary)
			{
				yield return new KeyValuePair<TKey, TValue>((TKey)item.Key, (TValue)item.Value);
			}
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}

		public bool Remove(KeyValuePair<TKey, TValue> item)
		{
			if (Contains(item))
			{
				privateDictionary.Remove(item.Key);
				return true;
			}
			return false;
		}

		public bool Remove(TKey key)
		{
			if (key == null)
			{
				throw Fx.Exception.ArgumentNull("key");
			}
			if (privateDictionary.Contains(key))
			{
				privateDictionary.Remove(key);
				return true;
			}
			return false;
		}

		public bool TryGetValue(TKey key, out TValue value)
		{
			if (key == null)
			{
				throw Fx.Exception.ArgumentNull("key");
			}
			bool flag = privateDictionary.Contains(key);
			value = (flag ? ((TValue)privateDictionary[key]) : default(TValue));
			return flag;
		}

		void IDictionary.Add(object key, object value)
		{
			privateDictionary.Add(key, value);
		}

		void IDictionary.Clear()
		{
			privateDictionary.Clear();
		}

		bool IDictionary.Contains(object key)
		{
			return privateDictionary.Contains(key);
		}

		IDictionaryEnumerator IDictionary.GetEnumerator()
		{
			return privateDictionary.GetEnumerator();
		}

		void IDictionary.Remove(object key)
		{
			privateDictionary.Remove(key);
		}

		void ICollection.CopyTo(Array array, int index)
		{
			privateDictionary.CopyTo(array, index);
		}
	}
}
namespace System.ServiceModel.Internals
{
	internal static class LocalAppContextSwitches
	{
		private static int includeNullExceptionMessageInETWTrace;

		public static bool IncludeNullExceptionMessageInETWTrace
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				return LocalAppContext.GetCachedSwitchValue("Switch.System.ServiceModel.Internals.IncludeNullExceptionMessageInETWTrace", ref includeNullExceptionMessageInETWTrace);
			}
		}
	}
}
