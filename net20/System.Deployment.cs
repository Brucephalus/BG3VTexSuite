
// C:\WINDOWS\assembly\GAC_MSIL\System.Deployment\2.0.0.0__b03f5f7f11d50a3a\System.Deployment.dll
// System.Deployment, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
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
using System.Deployment.Application.Manifest;
using System.Deployment.Application.Win32InterOp;
using System.Deployment.Internal;
using System.Deployment.Internal.CodeSigning;
using System.Deployment.Internal.Isolation;
using System.Deployment.Internal.Isolation.Manifest;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Cache;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Remoting;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Permissions;
using System.Security.Policy;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Xml;
using System.Xml.Schema;
using Microsoft.Internal.Performance;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyDescription("System.Deployment.dll")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: CLSCompliant(true)]
[assembly: AssemblyDefaultAlias("System.Deployment.dll")]
[assembly: AssemblyTitle("System.Deployment.dll")]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: ComVisible(false)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: CompilationRelaxations(8)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: InternalsVisibleTo("dfsvc, PublicKey=002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDelaySign(true)]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
namespace System.Deployment.Application
{
	internal class ApplicationActivator
	{
		private class BrowserSettings
		{
			public enum ManagedFlags
			{
				URLPOLICY_ALLOW = 0,
				URLPOLICY_QUERY = 1,
				URLPOLICY_DISALLOW = 3
			}

			public ManagedFlags ManagedSignedFlag = ManagedFlags.URLPOLICY_DISALLOW;

			public ManagedFlags ManagedUnSignedFlag = ManagedFlags.URLPOLICY_DISALLOW;

			public void Validate(string manifestPath)
			{
				AssemblyManifest.CertificateStatus certificateStatus = AssemblyManifest.AnalyzeManifestCertificate(manifestPath);
				if (certificateStatus == AssemblyManifest.CertificateStatus.TrustedPublisher || certificateStatus == AssemblyManifest.CertificateStatus.AuthenticodedNotInTrustedList)
				{
					if (ManagedSignedFlag != 0 && ManagedSignedFlag != ManagedFlags.URLPOLICY_QUERY)
					{
						throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_SignedManifestDisallow"));
					}
				}
				else if (ManagedUnSignedFlag != 0 && ManagedUnSignedFlag != ManagedFlags.URLPOLICY_QUERY)
				{
					throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_UnSignedManifestDisallow"));
				}
			}

			public static ManagedFlags GetManagedFlagValue(int policyValue)
			{
				return policyValue switch
				{
					0 => ManagedFlags.URLPOLICY_ALLOW, 
					1 => ManagedFlags.URLPOLICY_QUERY, 
					3 => ManagedFlags.URLPOLICY_DISALLOW, 
					_ => ManagedFlags.URLPOLICY_DISALLOW, 
				};
			}
		}

		private const int _liveActivationLimitUINotVisible = 0;

		private const int _liveActivationLimitUIVisible = 1;

		private const int ActivateArgumentCount = 5;

		private static Hashtable _activationsInProgress = new Hashtable();

		private bool _remActivationInProgressEntry;

		private SubscriptionStore _subStore;

		private UserInterface _ui;

		private bool _fullTrust;

		private static int _liveActivationLimitUIStatus = 0;

		private void DisplayActivationFailureReason(Exception exception, string errorPageUrl)
		{
			string message = Resources.GetString("ErrorMessage_GenericActivationFailure");
			string @string = Resources.GetString("ErrorMessage_GenericLinkUrlMessage");
			Exception innerMostException = GetInnerMostException(exception);
			if (exception is DeploymentDownloadException)
			{
				message = Resources.GetString("ErrorMessage_NetworkError");
				DeploymentDownloadException ex = (DeploymentDownloadException)exception;
				if (ex.SubType == ExceptionTypes.SizeLimitForPartialTrustOnlineAppExceeded)
				{
					message = Resources.GetString("ErrorMessage_SizeLimitForPartialTrustOnlineAppExceeded");
				}
				if (innerMostException is WebException)
				{
					WebException ex2 = (WebException)innerMostException;
					if (ex2.Response != null && ex2.Response is HttpWebResponse)
					{
						HttpWebResponse httpWebResponse = (HttpWebResponse)ex2.Response;
						if (httpWebResponse.StatusCode == HttpStatusCode.NotFound)
						{
							message = Resources.GetString("ErrorMessage_FileMissing");
						}
						else if (httpWebResponse.StatusCode == HttpStatusCode.Unauthorized)
						{
							message = Resources.GetString("ErrorMessage_AuthenticationError");
						}
						else if (httpWebResponse.StatusCode == HttpStatusCode.Forbidden)
						{
							message = Resources.GetString("ErrorMessage_Forbidden");
						}
					}
				}
				else if (innerMostException is FileNotFoundException || innerMostException is DirectoryNotFoundException)
				{
					message = Resources.GetString("ErrorMessage_FileMissing");
				}
				else if (innerMostException is UnauthorizedAccessException)
				{
					message = Resources.GetString("ErrorMessage_AuthenticationError");
				}
				else if (innerMostException is IOException && !IsWebExceptionInExceptionStack(exception))
				{
					message = Resources.GetString("ErrorMessage_DownloadIOError");
				}
			}
			else if (exception is InvalidDeploymentException)
			{
				InvalidDeploymentException ex3 = (InvalidDeploymentException)exception;
				if (ex3.SubType == ExceptionTypes.ManifestLoad)
				{
					message = Resources.GetString("ErrorMessage_ManifestCannotBeLoaded");
				}
				else if (ex3.SubType == ExceptionTypes.Manifest || ex3.SubType == ExceptionTypes.ManifestParse || ex3.SubType == ExceptionTypes.ManifestSemanticValidation)
				{
					message = Resources.GetString("ErrorMessage_InvalidManifest");
				}
				else if (ex3.SubType == ExceptionTypes.Validation || ex3.SubType == ExceptionTypes.HashValidation || ex3.SubType == ExceptionTypes.SignatureValidation || ex3.SubType == ExceptionTypes.RefDefValidation || ex3.SubType == ExceptionTypes.ClrValidation || ex3.SubType == ExceptionTypes.StronglyNamedAssemblyVerification || ex3.SubType == ExceptionTypes.IdentityMatchValidationForMixedModeAssembly || ex3.SubType == ExceptionTypes.AppFileLocationValidation || ex3.SubType == ExceptionTypes.FileSizeValidation)
				{
					message = Resources.GetString("ErrorMessage_ValidationFailed");
				}
				else if (ex3.SubType == ExceptionTypes.UnsupportedElevetaionRequest)
				{
					message = Resources.GetString("ErrorMessage_ManifestExecutionLevelNotSupported");
				}
			}
			else if (exception is DeploymentException)
			{
				if (((DeploymentException)exception).SubType == ExceptionTypes.ComponentStore)
				{
					message = Resources.GetString("ErrorMessage_StoreError");
				}
				else if (((DeploymentException)exception).SubType == ExceptionTypes.ActivationLimitExceeded)
				{
					message = Resources.GetString("ErrorMessage_ConcurrentActivationLimitExceeded");
				}
				else if (((DeploymentException)exception).SubType == ExceptionTypes.DiskIsFull)
				{
					message = Resources.GetString("ErrorMessage_DiskIsFull");
				}
				else if (((DeploymentException)exception).SubType == ExceptionTypes.DeploymentUriDifferent)
				{
					message = exception.Message;
				}
				else if (((DeploymentException)exception).SubType == ExceptionTypes.GroupMultipleMatch)
				{
					message = exception.Message;
				}
			}
			string logFileLocation = Logger.GetLogFilePath();
			if (!Logger.FlushCurrentThreadLogs())
			{
				logFileLocation = null;
			}
			string text = null;
			if (errorPageUrl != null)
			{
				text = $"{errorPageUrl}?outer={exception.GetType().ToString()}&&inner={innerMostException.GetType().ToString()}&&msg={innerMostException.Message}";
				if (text.Length > 2048)
				{
					text = text.Substring(0, 2048);
				}
			}
			_ui.ShowError(Resources.GetString("UI_ErrorTitle"), message, logFileLocation, text, @string);
		}

		private void DisplayPlatformDetectionFailureUI(DependentPlatformMissingException ex)
		{
			Uri supportUrl = null;
			if (_fullTrust)
			{
				supportUrl = ex.SupportUrl;
			}
			_ui.ShowPlatform(ex.Message, supportUrl);
		}

		public void ActivateDeployment(string activationUrl, bool isShortcut)
		{
			LifetimeManager.StartOperation();
			bool flag = false;
			try
			{
				flag = ThreadPool.QueueUserWorkItem(state: new object[5] { activationUrl, isShortcut, null, null, null }, callBack: ActivateDeploymentWorker);
				if (!flag)
				{
					throw new OutOfMemoryException();
				}
			}
			finally
			{
				if (!flag)
				{
					LifetimeManager.EndOperation();
				}
			}
		}

		public void ActivateDeploymentEx(string activationUrl, int unsignedPolicy, int signedPolicy)
		{
			LifetimeManager.StartOperation();
			bool flag = false;
			try
			{
				BrowserSettings browserSettings = new BrowserSettings();
				browserSettings.ManagedSignedFlag = BrowserSettings.GetManagedFlagValue(signedPolicy);
				browserSettings.ManagedUnSignedFlag = BrowserSettings.GetManagedFlagValue(unsignedPolicy);
				flag = ThreadPool.QueueUserWorkItem(state: new object[5] { activationUrl, false, null, null, browserSettings }, callBack: ActivateDeploymentWorker);
				if (!flag)
				{
					throw new OutOfMemoryException();
				}
			}
			finally
			{
				if (!flag)
				{
					LifetimeManager.EndOperation();
				}
			}
		}

		public void ActivateApplicationExtension(string textualSubId, string deploymentProviderUrl, string targetAssociatedFile)
		{
			LifetimeManager.StartOperation();
			bool flag = false;
			try
			{
				flag = ThreadPool.QueueUserWorkItem(state: new object[5] { targetAssociatedFile, false, textualSubId, deploymentProviderUrl, null }, callBack: ActivateDeploymentWorker);
				if (!flag)
				{
					throw new OutOfMemoryException();
				}
			}
			finally
			{
				if (!flag)
				{
					LifetimeManager.EndOperation();
				}
			}
		}

		private void ActivateDeploymentWorker(object state)
		{
			string text = null;
			string textualSubId = null;
			string deploymentProviderUrlFromExtension = null;
			try
			{
				CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfNewApptBegin);
				object[] array = (object[])state;
				text = (string)array[0];
				bool isShortcut = (bool)array[1];
				if (array[2] != null)
				{
					textualSubId = (string)array[2];
				}
				if (array[3] != null)
				{
					deploymentProviderUrlFromExtension = (string)array[3];
				}
				BrowserSettings browserSettings = null;
				if (array[4] != null)
				{
					browserSettings = (BrowserSettings)array[4];
				}
				Logger.StartCurrentThreadLogging();
				Logger.SetSubscriptionUrl(text);
				Uri uri = null;
				string errorPageUrl = null;
				try
				{
					int num = CheckActivationInProgress(text);
					_ui = new UserInterface(wait: false);
					if (!PolicyKeys.SuppressLimitOnNumberOfActivations() && num > 8)
					{
						throw new DeploymentException(ExceptionTypes.ActivationLimitExceeded, Resources.GetString("Ex_TooManyLiveActivation"));
					}
					if (text.Length > 16384)
					{
						throw new DeploymentException(ExceptionTypes.Activation, Resources.GetString("Ex_UrlTooLong"));
					}
					uri = new Uri(text);
					try
					{
						UriHelper.ValidateSupportedSchemeInArgument(uri, "activationUrl");
					}
					catch (ArgumentException innerException)
					{
						throw new InvalidDeploymentException(ExceptionTypes.UriSchemeNotSupported, Resources.GetString("Ex_NotSupportedUriScheme"), innerException);
					}
					Logger.AddPhaseInformation(Resources.GetString("PhaseLog_StartOfActivation"), text);
					PerformDeploymentActivation(uri, isShortcut, textualSubId, deploymentProviderUrlFromExtension, browserSettings, ref errorPageUrl);
					Logger.AddPhaseInformation(Resources.GetString("ActivateManifestSucceeded"), text);
				}
				catch (DependentPlatformMissingException ex)
				{
					Logger.AddErrorInformation(ex, Resources.GetString("ActivateManifestException"), text);
					if (_ui == null)
					{
						_ui = new UserInterface();
					}
					if (!_ui.SplashCancelled())
					{
						DisplayPlatformDetectionFailureUI(ex);
					}
				}
				catch (DownloadCancelledException exception)
				{
					Logger.AddErrorInformation(exception, Resources.GetString("ActivateManifestException"), text);
				}
				catch (TrustNotGrantedException exception2)
				{
					Logger.AddErrorInformation(exception2, Resources.GetString("ActivateManifestException"), text);
				}
				catch (DeploymentException ex2)
				{
					Logger.AddErrorInformation(ex2, Resources.GetString("ActivateManifestException"), text);
					if (ex2.SubType == ExceptionTypes.ActivationInProgress)
					{
						return;
					}
					if (_ui == null)
					{
						_ui = new UserInterface();
					}
					if (_ui.SplashCancelled())
					{
						return;
					}
					if (ex2.SubType == ExceptionTypes.ActivationLimitExceeded)
					{
						if (Interlocked.CompareExchange(ref _liveActivationLimitUIStatus, 1, 0) == 0)
						{
							DisplayActivationFailureReason(ex2, errorPageUrl);
							Interlocked.CompareExchange(ref _liveActivationLimitUIStatus, 0, 1);
						}
					}
					else
					{
						DisplayActivationFailureReason(ex2, errorPageUrl);
					}
				}
				catch (Exception ex3)
				{
					if (ex3 is AccessViolationException || ex3 is OutOfMemoryException)
					{
						throw;
					}
					if (PolicyKeys.DisableGenericExceptionHandler())
					{
						throw;
					}
					Logger.AddErrorInformation(ex3, Resources.GetString("ActivateManifestException"), text);
					if (_ui == null)
					{
						_ui = new UserInterface();
					}
					if (!_ui.SplashCancelled())
					{
						DisplayActivationFailureReason(ex3, errorPageUrl);
					}
				}
			}
			finally
			{
				RemoveActivationInProgressEntry(text);
				if (_ui != null)
				{
					_ui.Dispose();
					_ui = null;
				}
				CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfNewApptEnd);
				Logger.EndCurrentThreadLogging();
				LifetimeManager.EndOperation();
			}
		}

		private void PerformDeploymentActivation(Uri activationUri, bool isShortcut, string textualSubId, string deploymentProviderUrlFromExtension, BrowserSettings browserSettings, ref string errorPageUrl)
		{
			TempFile deployFile = null;
			try
			{
				string text = null;
				Uri uri = null;
				bool flag = false;
				_subStore = SubscriptionStore.CurrentUser;
				_subStore.RefreshStorePointer();
				Uri sourceUri = activationUri;
				bool flag2 = false;
				ActivationDescription activationDescription;
				if (textualSubId != null)
				{
					flag2 = true;
					activationDescription = ProcessOrFollowExtension(activationUri, textualSubId, deploymentProviderUrlFromExtension, ref errorPageUrl, out deployFile);
					if (activationDescription == null)
					{
						return;
					}
				}
				else if (isShortcut)
				{
					text = activationUri.LocalPath;
					activationDescription = ProcessOrFollowShortcut(text, ref errorPageUrl, out deployFile);
					if (activationDescription == null)
					{
						return;
					}
				}
				else
				{
					SubscriptionState subState;
					AssemblyManifest assemblyManifest = DownloadManager.DownloadDeploymentManifestBypass(_subStore, ref sourceUri, out deployFile, out subState, null, null);
					if (browserSettings != null && deployFile != null)
					{
						browserSettings.Validate(deployFile.Path);
					}
					if (assemblyManifest.Description != null)
					{
						errorPageUrl = assemblyManifest.Description.ErrorReportUrl;
					}
					activationDescription = new ActivationDescription();
					if (subState != null)
					{
						text = null;
						activationDescription.SetApplicationManifest(subState.CurrentApplicationManifest, null, null);
						activationDescription.AppId = subState.CurrentBind;
						flag = true;
					}
					else
					{
						text = deployFile.Path;
					}
					Logger.SetDeploymentManifest(assemblyManifest);
					Logger.AddPhaseInformation(Resources.GetString("PhaseLog_ProcessingDeploymentManifestComplete"));
					activationDescription.SetDeploymentManifest(assemblyManifest, sourceUri, text);
					activationDescription.IsUpdate = false;
					activationDescription.ActType = ActivationType.InstallViaDotApplication;
					uri = activationUri;
				}
				if (_ui.SplashCancelled())
				{
					throw new DownloadCancelledException();
				}
				if (activationDescription.DeployManifest.Deployment != null)
				{
					bool flag3 = false;
					SubscriptionState subState2 = _subStore.GetSubscriptionState(activationDescription.DeployManifest);
					CheckDeploymentProviderValidity(activationDescription, subState2);
					if (!flag)
					{
						flag3 = InstallApplication(ref subState2, activationDescription);
						Logger.AddPhaseInformation(Resources.GetString("PhaseLog_InstallationComplete"));
					}
					else
					{
						_subStore.SetLastCheckTimeToNow(subState2);
					}
					if (activationDescription.DeployManifest.Deployment.DisallowUrlActivation && !isShortcut && (!activationUri.IsFile || activationUri.IsUnc))
					{
						if (flag3)
						{
							_ui.ShowMessage(Resources.GetString("Activation_DisallowUrlActivationMessageAfterInstall"), Resources.GetString("Activation_DisallowUrlActivationCaptionAfterInstall"));
						}
						else
						{
							_ui.ShowMessage(Resources.GetString("Activation_DisallowUrlActivationMessage"), Resources.GetString("Activation_DisallowUrlActivationCaption"));
						}
					}
					else if (flag2)
					{
						Activate(activationDescription.AppId, activationDescription.AppManifest, activationUri.AbsoluteUri, useActivationParameter: true);
					}
					else if (isShortcut)
					{
						string text2 = null;
						int num = text.IndexOf('|', 0);
						if (num > 0 && num + 1 < text.Length)
						{
							text2 = text.Substring(num + 1);
						}
						if (text2 == null)
						{
							Activate(activationDescription.AppId, activationDescription.AppManifest, null, useActivationParameter: false);
						}
						else
						{
							Activate(activationDescription.AppId, activationDescription.AppManifest, text2, useActivationParameter: true);
						}
					}
					else
					{
						Activate(activationDescription.AppId, activationDescription.AppManifest, uri.AbsoluteUri, useActivationParameter: false);
					}
					return;
				}
				throw new DeploymentException(ExceptionTypes.Activation, Resources.GetString("Ex_NotDeploymentOrShortcut"));
			}
			finally
			{
				deployFile?.Dispose();
			}
		}

		private ActivationDescription ProcessOrFollowExtension(Uri associatedFile, string textualSubId, string deploymentProviderUrlFromExtension, ref string errorPageUrl, out TempFile deployFile)
		{
			deployFile = null;
			DefinitionIdentity subId = new DefinitionIdentity(textualSubId);
			SubscriptionState subState = _subStore.GetSubscriptionState(subId);
			ActivationDescription activationDescription = null;
			if (subState.IsInstalled && subState.IsShellVisible)
			{
				PerformDeploymentUpdate(ref subState, ref errorPageUrl);
				Activate(subState.CurrentBind, subState.CurrentApplicationManifest, associatedFile.AbsoluteUri, useActivationParameter: true);
			}
			else
			{
				if (string.IsNullOrEmpty(deploymentProviderUrlFromExtension))
				{
					throw new DeploymentException(ExceptionTypes.Activation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileAssociationNoDpUrl"), textualSubId));
				}
				Uri sourceUri = new Uri(deploymentProviderUrlFromExtension);
				AssemblyManifest assemblyManifest = DownloadManager.DownloadDeploymentManifest(_subStore, ref sourceUri, out deployFile);
				if (assemblyManifest.Description != null)
				{
					errorPageUrl = assemblyManifest.Description.ErrorReportUrl;
				}
				if (!assemblyManifest.Deployment.Install)
				{
					throw new DeploymentException(ExceptionTypes.Activation, Resources.GetString("Ex_FileAssociationRefOnline"));
				}
				activationDescription = new ActivationDescription();
				activationDescription.SetDeploymentManifest(assemblyManifest, sourceUri, deployFile.Path);
				activationDescription.IsUpdate = false;
				activationDescription.ActType = ActivationType.InstallViaFileAssociation;
			}
			return activationDescription;
		}

		private ActivationDescription ProcessOrFollowShortcut(string shortcutFile, ref string errorPageUrl, out TempFile deployFile)
		{
			deployFile = null;
			string shortcutFile2 = shortcutFile;
			string text = null;
			int num = shortcutFile.IndexOf('|', 0);
			if (num > 0)
			{
				shortcutFile2 = shortcutFile.Substring(0, num);
				if (num + 1 < shortcutFile.Length)
				{
					text = shortcutFile.Substring(num + 1);
				}
			}
			ShellExposure.ParseAppShortcut(shortcutFile2, out var subId, out var providerUri);
			SubscriptionState subState = _subStore.GetSubscriptionState(subId);
			ActivationDescription activationDescription = null;
			if (subState.IsInstalled && subState.IsShellVisible)
			{
				PerformDeploymentUpdate(ref subState, ref errorPageUrl);
				if (text == null)
				{
					Activate(subState.CurrentBind, subState.CurrentApplicationManifest, null, useActivationParameter: false);
				}
				else
				{
					Activate(subState.CurrentBind, subState.CurrentApplicationManifest, text, useActivationParameter: true);
				}
			}
			else
			{
				Uri sourceUri = providerUri;
				AssemblyManifest assemblyManifest = DownloadManager.DownloadDeploymentManifest(_subStore, ref sourceUri, out deployFile);
				if (assemblyManifest.Description != null)
				{
					errorPageUrl = assemblyManifest.Description.ErrorReportUrl;
				}
				if (!assemblyManifest.Deployment.Install)
				{
					throw new DeploymentException(ExceptionTypes.Activation, Resources.GetString("Ex_ShortcutRefOnlineOnly"));
				}
				activationDescription = new ActivationDescription();
				activationDescription.SetDeploymentManifest(assemblyManifest, sourceUri, deployFile.Path);
				activationDescription.IsUpdate = false;
				activationDescription.ActType = ActivationType.InstallViaShortcut;
			}
			return activationDescription;
		}

		private void Activate(DefinitionAppId appId, AssemblyManifest appManifest, string activationParameter, bool useActivationParameter)
		{
			using ActivationContext appInfo = ActivationContext.CreatePartialActivationContext(appId.ToApplicationIdentity());
			InternalActivationContextHelper.PrepareForExecution(appInfo);
			_subStore.ActivateApplication(appId, activationParameter, useActivationParameter);
		}

		private void PerformDeploymentUpdate(ref SubscriptionState subState, ref string errorPageUrl)
		{
			bool flag = subState.CurrentDeploymentManifest.Deployment.DeploymentUpdate?.BeforeApplicationStartup ?? false;
			Logger.AddPhaseInformation(Resources.GetString("PhaseLog_DeploymentUpdateCheck"));
			if (!flag && (subState.PendingDeployment == null || SkipUpdate(subState, subState.PendingDeployment)))
			{
				return;
			}
			TempFile tempFile = null;
			try
			{
				Uri sourceUri = subState.DeploymentProviderUri;
				AssemblyManifest assemblyManifest;
				try
				{
					assemblyManifest = DownloadManager.DownloadDeploymentManifest(_subStore, ref sourceUri, out tempFile);
					if (assemblyManifest.Description != null)
					{
						errorPageUrl = assemblyManifest.Description.ErrorReportUrl;
					}
				}
				catch (DeploymentDownloadException exception)
				{
					Logger.AddErrorInformation(exception, Resources.GetString("Upd_UpdateCheckDownloadFailed"), subState.SubscriptionId.ToString());
					return;
				}
				if (_ui.SplashCancelled())
				{
					throw new DownloadCancelledException();
				}
				if (!SkipUpdate(subState, assemblyManifest.Identity) && _subStore.CheckUpdateInManifest(subState, sourceUri, assemblyManifest, subState.CurrentDeployment.Version) != null && !assemblyManifest.Identity.Equals(subState.ExcludedDeployment))
				{
					ActivationDescription activationDescription = new ActivationDescription();
					activationDescription.SetDeploymentManifest(assemblyManifest, sourceUri, tempFile.Path);
					activationDescription.IsUpdate = true;
					activationDescription.IsRequiredUpdate = false;
					activationDescription.ActType = ActivationType.UpdateViaShortcutOrFA;
					if (assemblyManifest.Deployment.MinimumRequiredVersion != null && assemblyManifest.Deployment.MinimumRequiredVersion.CompareTo(subState.CurrentDeployment.Version) > 0)
					{
						activationDescription.IsRequiredUpdate = true;
					}
					CheckDeploymentProviderValidity(activationDescription, subState);
					ConsumeUpdatedDeployment(ref subState, activationDescription);
				}
			}
			finally
			{
				tempFile?.Dispose();
			}
		}

		private void CheckDeploymentProviderValidity(ActivationDescription actDesc, SubscriptionState subState)
		{
			if (actDesc.DeployManifest.Deployment.Install && actDesc.DeployManifest.Deployment.ProviderCodebaseUri == null && subState != null && subState.DeploymentProviderUri != null)
			{
				Uri uri = ((subState.DeploymentProviderUri.Query != null && subState.DeploymentProviderUri.Query.Length > 0) ? new Uri(subState.DeploymentProviderUri.GetLeftPart(UriPartial.Path)) : subState.DeploymentProviderUri);
				if (!uri.Equals(actDesc.ToAppCodebase()))
				{
					throw new DeploymentException(ExceptionTypes.DeploymentUriDifferent, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("ErrorMessage_DeploymentUriDifferent"), actDesc.DeployManifest.Description.FilteredProduct), new DeploymentException(ExceptionTypes.DeploymentUriDifferent, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DeploymentUriDifferentExText"), actDesc.DeployManifest.Description.FilteredProduct, actDesc.DeploySourceUri.AbsoluteUri, subState.DeploymentProviderUri.AbsoluteUri)));
				}
			}
		}

		private void ConsumeUpdatedDeployment(ref SubscriptionState subState, ActivationDescription actDesc)
		{
			AssemblyManifest deployManifest = actDesc.DeployManifest;
			DefinitionIdentity identity = deployManifest.Identity;
			Uri deploySourceUri = actDesc.DeploySourceUri;
			Logger.AddPhaseInformation(Resources.GetString("PhaseLog_ConsumeUpdatedDeployment"));
			if (!actDesc.IsRequiredUpdate)
			{
				Description effectiveDescription = subState.EffectiveDescription;
				UserInterfaceInfo userInterfaceInfo = new UserInterfaceInfo();
				userInterfaceInfo.formTitle = Resources.GetString("UI_UpdateTitle");
				userInterfaceInfo.productName = effectiveDescription.Product;
				userInterfaceInfo.supportUrl = effectiveDescription.SupportUrl;
				userInterfaceInfo.sourceSite = UserInterface.GetDisplaySite(deploySourceUri);
				switch (_ui.ShowUpdate(userInterfaceInfo))
				{
				case UserInterfaceModalResult.Skip:
				{
					TimeSpan timeSpan = new TimeSpan(7, 0, 0, 0);
					DateTime updateSkipTime = DateTime.UtcNow + timeSpan;
					_subStore.SetUpdateSkipTime(subState, identity, updateSkipTime);
					Logger.AddPhaseInformation(Resources.GetString("Upd_DeployUpdateSkipping"));
					return;
				}
				case UserInterfaceModalResult.Cancel:
					return;
				}
			}
			InstallApplication(ref subState, actDesc);
			Logger.AddPhaseInformation(Resources.GetString("Upd_Consumed"), identity.ToString(), deploySourceUri);
		}

		private bool InstallApplication(ref SubscriptionState subState, ActivationDescription actDesc)
		{
			bool flag = false;
			Logger.AddPhaseInformation(Resources.GetString("PhaseLog_InstallApplication"));
			_subStore.CheckDeploymentSubscriptionState(subState, actDesc.DeployManifest);
			long transactionId;
			using (_subStore.AcquireReferenceTransaction(out transactionId))
			{
				TempDirectory downloadTemp = null;
				try
				{
					flag = DownloadApplication(subState, actDesc, transactionId, out downloadTemp);
					actDesc.CommitDeploy = true;
					actDesc.IsConfirmed = true;
					actDesc.TimeStamp = DateTime.UtcNow;
					Logger.AddPhaseInformation(Resources.GetString("PhaseLog_CommitApplication"));
					_subStore.CommitApplication(ref subState, actDesc);
					return flag;
				}
				finally
				{
					downloadTemp?.Dispose();
				}
			}
		}

		private bool DownloadApplication(SubscriptionState subState, ActivationDescription actDesc, long transactionId, out TempDirectory downloadTemp)
		{
			bool result = false;
			downloadTemp = _subStore.AcquireTempDirectory();
			Uri appSourceUri;
			string appManifestPath;
			AssemblyManifest assemblyManifest = DownloadManager.DownloadApplicationManifest(actDesc.DeployManifest, downloadTemp.Path, actDesc.DeploySourceUri, out appSourceUri, out appManifestPath);
			AssemblyManifest.ReValidateManifestSignatures(actDesc.DeployManifest, assemblyManifest);
			if (assemblyManifest.EntryPoints[0].HostInBrowser)
			{
				throw new DeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_HostInBrowserAppNotSupported"));
			}
			if (assemblyManifest.EntryPoints[0].CustomHostSpecified)
			{
				throw new DeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_CustomHostSpecifiedAppNotSupported"));
			}
			if (assemblyManifest.EntryPoints[0].CustomUX && (actDesc.ActType == ActivationType.InstallViaDotApplication || actDesc.ActType == ActivationType.InstallViaFileAssociation || actDesc.ActType == ActivationType.InstallViaShortcut || actDesc.ActType == ActivationType.None))
			{
				throw new DeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_CustomUXAppNotSupported"));
			}
			Logger.AddPhaseInformation(Resources.GetString("PhaseLog_ProcessingApplicationManifestComplete"));
			actDesc.SetApplicationManifest(assemblyManifest, appSourceUri, appManifestPath);
			Logger.SetApplicationManifest(assemblyManifest);
			_subStore.CheckCustomUXFlag(subState, actDesc.AppManifest);
			actDesc.AppId = new DefinitionAppId(actDesc.ToAppCodebase(), actDesc.DeployManifest.Identity, actDesc.AppManifest.Identity);
			if (assemblyManifest.EntryPoints[0].CustomUX)
			{
				actDesc.Trust = ApplicationTrust.PersistTrustWithoutEvaluation(actDesc.ToActivationContext());
			}
			else
			{
				_ui.Hide();
				if (_ui.SplashCancelled())
				{
					throw new DownloadCancelledException();
				}
				if (subState.IsInstalled && !string.Equals(subState.EffectiveCertificatePublicKeyToken, actDesc.EffectiveCertificatePublicKeyToken, StringComparison.Ordinal))
				{
					ApplicationTrust.RemoveCachedTrust(subState.CurrentBind);
				}
				actDesc.Trust = ApplicationTrust.RequestTrust(subState, actDesc.DeployManifest.Deployment.Install, actDesc.IsUpdate, actDesc.ToActivationContext());
			}
			_fullTrust = actDesc.Trust.DefaultGrantSet.PermissionSet.IsUnrestricted();
			if (!_fullTrust && actDesc.AppManifest.FileAssociations.Length > 0)
			{
				throw new DeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_FileExtensionNotSupported"));
			}
			PlatformDetector.VerifyPlatformDependencies(actDesc.AppManifest, actDesc.DeployManifest.Description.SupportUri, downloadTemp.Path);
			Logger.AddPhaseInformation(Resources.GetString("PhaseLog_PlatformDetectAndTrustGrantComplete"));
			if (!_subStore.CheckAndReferenceApplication(subState, actDesc.AppId, transactionId))
			{
				result = true;
				Description effectiveDescription = actDesc.EffectiveDescription;
				UserInterfaceInfo userInterfaceInfo = new UserInterfaceInfo();
				userInterfaceInfo.productName = effectiveDescription.Product;
				if (actDesc.IsUpdate)
				{
					if (actDesc.IsRequiredUpdate)
					{
						userInterfaceInfo.formTitle = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_ProgressTitleRequiredUpdate"), userInterfaceInfo.productName);
					}
					else
					{
						userInterfaceInfo.formTitle = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_ProgressTitleUpdate"), userInterfaceInfo.productName);
					}
				}
				else if (!actDesc.DeployManifest.Deployment.Install)
				{
					userInterfaceInfo.formTitle = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_ProgressTitleDownload"), userInterfaceInfo.productName);
				}
				else
				{
					userInterfaceInfo.formTitle = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_ProgressTitleInstall"), userInterfaceInfo.productName);
				}
				userInterfaceInfo.supportUrl = effectiveDescription.SupportUrl;
				userInterfaceInfo.sourceSite = UserInterface.GetDisplaySite(actDesc.DeploySourceUri);
				if (assemblyManifest.Description != null && assemblyManifest.Description.IconFileFS != null)
				{
					userInterfaceInfo.iconFilePath = Path.Combine(downloadTemp.Path, assemblyManifest.Description.IconFileFS);
				}
				ProgressPiece notification = _ui.ShowProgress(userInterfaceInfo);
				DownloadOptions downloadOptions = null;
				bool flag = !actDesc.DeployManifest.Deployment.Install;
				if (!_fullTrust && flag)
				{
					downloadOptions = new DownloadOptions();
					downloadOptions.EnforceSizeLimit = true;
					downloadOptions.SizeLimit = _subStore.GetSizeLimitInBytesForSemiTrustApps();
					downloadOptions.Size = actDesc.DeployManifest.SizeInBytes + actDesc.AppManifest.SizeInBytes;
				}
				DownloadManager.DownloadDependencies(subState, actDesc.DeployManifest, actDesc.AppManifest, actDesc.AppSourceUri, downloadTemp.Path, null, notification, downloadOptions);
				Logger.AddPhaseInformation(Resources.GetString("PhaseLog_DownloadDependenciesComplete"));
				actDesc.CommitApp = true;
				actDesc.AppPayloadPath = downloadTemp.Path;
				actDesc.AppGroup = null;
			}
			return result;
		}

		private static bool SkipUpdate(SubscriptionState subState, DefinitionIdentity targetIdentity)
		{
			if (subState.UpdateSkippedDeployment != null && targetIdentity != null && subState.UpdateSkippedDeployment.Equals(targetIdentity) && subState.UpdateSkipTime > DateTime.UtcNow)
			{
				return true;
			}
			return false;
		}

		private Exception GetInnerMostException(Exception exception)
		{
			if (exception.InnerException != null)
			{
				return GetInnerMostException(exception.InnerException);
			}
			return exception;
		}

		private bool IsWebExceptionInExceptionStack(Exception exception)
		{
			if (exception == null)
			{
				return false;
			}
			if (exception is WebException)
			{
				return true;
			}
			return IsWebExceptionInExceptionStack(exception.InnerException);
		}

		private int CheckActivationInProgress(string activationUrl)
		{
			lock (_activationsInProgress.SyncRoot)
			{
				if (_activationsInProgress.Contains(activationUrl))
				{
					ApplicationActivator applicationActivator = (ApplicationActivator)_activationsInProgress[activationUrl];
					applicationActivator.ActivateUI();
					_remActivationInProgressEntry = false;
					throw new DeploymentException(ExceptionTypes.ActivationInProgress, Resources.GetString("Ex_ActivationInProgressException"));
				}
				_activationsInProgress.Add(activationUrl, this);
				_remActivationInProgressEntry = true;
				return _activationsInProgress.Count;
			}
		}

		private void RemoveActivationInProgressEntry(string activationUrl)
		{
			if (!_remActivationInProgressEntry || activationUrl == null)
			{
				return;
			}
			lock (_activationsInProgress.SyncRoot)
			{
				_activationsInProgress.Remove(activationUrl);
			}
		}

		private void ActivateUI()
		{
			if (_ui != null)
			{
				_ui.Activate();
			}
		}
	}
	internal enum ActivationType
	{
		None,
		InstallViaDotApplication,
		InstallViaShortcut,
		InstallViaFileAssociation,
		UpdateViaShortcutOrFA
	}
	internal class CommitApplicationParams
	{
		public DefinitionAppId AppId;

		public bool CommitApp;

		public AssemblyManifest AppManifest;

		public Uri AppSourceUri;

		public string AppManifestPath;

		public string AppPayloadPath;

		public string AppGroup;

		public bool CommitDeploy;

		public AssemblyManifest DeployManifest;

		public Uri DeploySourceUri;

		public string DeployManifestPath;

		public DateTime TimeStamp = DateTime.MinValue;

		public bool IsConfirmed;

		public bool IsUpdate;

		public bool IsRequiredUpdate;

		public AppType appType;

		public System.Security.Policy.ApplicationTrust Trust;

		public Description EffectiveDescription
		{
			get
			{
				if (AppManifest != null && AppManifest.UseManifestForTrust)
				{
					return AppManifest.Description;
				}
				if (DeployManifest == null)
				{
					return null;
				}
				return DeployManifest.Description;
			}
		}

		public string EffectiveCertificatePublicKeyToken
		{
			get
			{
				if (AppManifest != null && AppManifest.UseManifestForTrust)
				{
					return AppManifest.Identity.PublicKeyToken;
				}
				if (DeployManifest == null)
				{
					return null;
				}
				return DeployManifest.Identity.PublicKeyToken;
			}
		}

		public CommitApplicationParams()
		{
		}

		public CommitApplicationParams(CommitApplicationParams src)
		{
			AppId = src.AppId;
			CommitApp = src.CommitApp;
			AppManifest = src.AppManifest;
			AppSourceUri = src.AppSourceUri;
			AppManifestPath = src.AppManifestPath;
			AppPayloadPath = src.AppPayloadPath;
			AppGroup = src.AppGroup;
			CommitDeploy = src.CommitDeploy;
			DeployManifest = src.DeployManifest;
			DeploySourceUri = src.DeploySourceUri;
			DeployManifestPath = src.DeployManifestPath;
			TimeStamp = src.TimeStamp;
			IsConfirmed = src.IsConfirmed;
			IsUpdate = src.IsUpdate;
			IsRequiredUpdate = src.IsRequiredUpdate;
			appType = src.appType;
			Trust = src.Trust;
		}
	}
	internal class ActivationDescription : CommitApplicationParams
	{
		private ActivationType activationType;

		public ActivationType ActType
		{
			get
			{
				return activationType;
			}
			set
			{
				activationType = value;
			}
		}

		public void SetApplicationManifest(AssemblyManifest manifest, Uri manifestUri, string manifestPath)
		{
			AppManifest = manifest;
			AppSourceUri = manifestUri;
			AppManifestPath = manifestPath;
			if (AppManifest.EntryPoints[0].CustomHostSpecified)
			{
				appType = AppType.CustomHostSpecified;
			}
			if (AppManifest.EntryPoints[0].CustomUX)
			{
				appType = AppType.CustomUX;
			}
		}

		public void SetDeploymentManifest(AssemblyManifest manifest, Uri manifestUri, string manifestPath)
		{
			DeploySourceUri = manifestUri;
			DeployManifest = manifest;
			DeployManifestPath = manifestPath;
		}

		public string ToAppCodebase()
		{
			Uri uri = ((DeploySourceUri.Query != null && DeploySourceUri.Query.Length > 0) ? new Uri(DeploySourceUri.GetLeftPart(UriPartial.Path)) : DeploySourceUri);
			return uri.AbsoluteUri;
		}

		public ActivationContext ToActivationContext()
		{
			ApplicationIdentity identity = AppId.ToApplicationIdentity();
			return ActivationContext.CreatePartialActivationContext(identity, new string[2] { DeployManifestPath, AppManifestPath });
		}
	}
	public sealed class ApplicationDeployment
	{
		private const int guardInitial = 0;

		private const int guardAsync = 1;

		private const int guardSync = 2;

		private static readonly object checkForUpdateCompletedKey = new object();

		private static readonly object updateCompletedKey = new object();

		private static readonly object downloadFileGroupCompletedKey = new object();

		private static readonly object checkForUpdateProgressChangedKey = new object();

		private static readonly object updateProgressChangedKey = new object();

		private static readonly object downloadFileGroupProgressChangedKey = new object();

		private static readonly object lockObject = new object();

		private static ApplicationDeployment _currentDeployment = null;

		private readonly AsyncOperation asyncOperation;

		private readonly CodeAccessPermission accessPermission;

		private int _guard;

		private bool _cancellationPending;

		private SubscriptionStore _subStore;

		private EventHandlerList _events;

		private DefinitionAppId _fullAppId;

		private Version _currentVersion;

		private SubscriptionState _subState;

		private object _syncGroupDeploymentManager;

		public static ApplicationDeployment CurrentDeployment
		{
			[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
			get
			{
				bool flag = false;
				if (_currentDeployment == null)
				{
					lock (lockObject)
					{
						if (_currentDeployment == null)
						{
							string text = null;
							ActivationContext activationContext = AppDomain.CurrentDomain.ActivationContext;
							if (activationContext != null)
							{
								text = activationContext.Identity.FullName;
							}
							if (string.IsNullOrEmpty(text))
							{
								throw new InvalidDeploymentException(Resources.GetString("Ex_AppIdNotSet"));
							}
							_currentDeployment = new ApplicationDeployment(text);
							flag = true;
						}
					}
				}
				if (!flag)
				{
					_currentDeployment.DemandPermission();
				}
				return _currentDeployment;
			}
		}

		public static bool IsNetworkDeployed
		{
			get
			{
				bool result = true;
				try
				{
					_ = CurrentDeployment;
					return result;
				}
				catch (InvalidDeploymentException)
				{
					return false;
				}
			}
		}

		public Version CurrentVersion => _currentVersion;

		public Version UpdatedVersion
		{
			[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
			get
			{
				_subState.Invalidate();
				return _subState.CurrentDeployment.Version;
			}
		}

		public string UpdatedApplicationFullName
		{
			[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
			get
			{
				_subState.Invalidate();
				return _subState.CurrentBind.ToString();
			}
		}

		public DateTime TimeOfLastUpdateCheck
		{
			[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
			get
			{
				_subState.Invalidate();
				return _subState.LastCheckTime;
			}
		}

		public Uri UpdateLocation
		{
			[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
			get
			{
				_subState.Invalidate();
				return _subState.DeploymentProviderUri;
			}
		}

		public Uri ActivationUri
		{
			[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
			get
			{
				_subState.Invalidate();
				if (!_subState.CurrentDeploymentManifest.Deployment.TrustURLParameters)
				{
					return null;
				}
				string[] activationData = AppDomain.CurrentDomain.SetupInformation.ActivationArguments.ActivationData;
				if (activationData == null || activationData[0] == null)
				{
					return null;
				}
				Uri uri = new Uri(activationData[0]);
				if (uri.IsFile || uri.IsUnc)
				{
					return null;
				}
				return uri;
			}
		}

		public string DataDirectory => AppDomain.CurrentDomain.GetData("DataDirectory")?.ToString();

		public bool IsFirstRun
		{
			[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
			get
			{
				ActivationContext activationContext = AppDomain.CurrentDomain.ActivationContext;
				return InternalActivationContextHelper.IsFirstRun(activationContext);
			}
		}

		private EventHandlerList Events => _events;

		private DeploymentManager SyncGroupDeploymentManager
		{
			get
			{
				if (_syncGroupDeploymentManager == null)
				{
					DeploymentManager deploymentManager = null;
					bool flag = false;
					try
					{
						deploymentManager = new DeploymentManager(_fullAppId.ToString(), isUpdate: true, isConfirmed: true, null, asyncOperation);
						deploymentManager.Callertype = DeploymentManager.CallerType.ApplicationDeployment;
						deploymentManager.Bind();
						flag = Interlocked.CompareExchange(ref _syncGroupDeploymentManager, deploymentManager, null) == null;
					}
					finally
					{
						if (!flag)
						{
							deploymentManager?.Dispose();
						}
					}
					if (flag)
					{
						deploymentManager.ProgressChanged += DownloadFileGroupProgressChangedEventHandler;
						deploymentManager.SynchronizeCompleted += SynchronizeGroupCompletedEventHandler;
					}
				}
				return (DeploymentManager)_syncGroupDeploymentManager;
			}
		}

		public event DeploymentProgressChangedEventHandler CheckForUpdateProgressChanged
		{
			add
			{
				Events.AddHandler(checkForUpdateProgressChangedKey, value);
			}
			remove
			{
				Events.RemoveHandler(checkForUpdateProgressChangedKey, value);
			}
		}

		public event CheckForUpdateCompletedEventHandler CheckForUpdateCompleted
		{
			add
			{
				Events.AddHandler(checkForUpdateCompletedKey, value);
			}
			remove
			{
				Events.RemoveHandler(checkForUpdateCompletedKey, value);
			}
		}

		public event DeploymentProgressChangedEventHandler UpdateProgressChanged
		{
			add
			{
				Events.AddHandler(updateProgressChangedKey, value);
			}
			remove
			{
				Events.RemoveHandler(updateProgressChangedKey, value);
			}
		}

		public event AsyncCompletedEventHandler UpdateCompleted
		{
			add
			{
				Events.AddHandler(updateCompletedKey, value);
			}
			remove
			{
				Events.RemoveHandler(updateCompletedKey, value);
			}
		}

		public event DeploymentProgressChangedEventHandler DownloadFileGroupProgressChanged
		{
			add
			{
				Events.AddHandler(downloadFileGroupProgressChangedKey, value);
			}
			remove
			{
				Events.RemoveHandler(downloadFileGroupProgressChangedKey, value);
			}
		}

		public event DownloadFileGroupCompletedEventHandler DownloadFileGroupCompleted
		{
			add
			{
				Events.AddHandler(downloadFileGroupCompletedKey, value);
			}
			remove
			{
				Events.RemoveHandler(downloadFileGroupCompletedKey, value);
			}
		}

		private ApplicationDeployment(string fullAppId)
		{
			if (fullAppId.Length > 65536)
			{
				throw new InvalidDeploymentException(Resources.GetString("Ex_AppIdTooLong"));
			}
			try
			{
				_fullAppId = new DefinitionAppId(fullAppId);
			}
			catch (COMException innerException)
			{
				throw new InvalidDeploymentException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_SubAppIdNotValid"), fullAppId), innerException);
			}
			catch (SEHException innerException2)
			{
				throw new InvalidDeploymentException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_SubAppIdNotValid"), fullAppId), innerException2);
			}
			DefinitionIdentity deploymentIdentity = _fullAppId.DeploymentIdentity;
			_currentVersion = deploymentIdentity.Version;
			DefinitionIdentity subId = deploymentIdentity.ToSubscriptionId();
			_subStore = SubscriptionStore.CurrentUser;
			_subState = _subStore.GetSubscriptionState(subId);
			if (!_subState.IsInstalled)
			{
				throw new InvalidDeploymentException(Resources.GetString("Ex_SubNotInstalled"));
			}
			if (!_fullAppId.Equals(_subState.CurrentBind))
			{
				throw new InvalidDeploymentException(Resources.GetString("Ex_AppIdNotMatchInstalled"));
			}
			Uri uri = new Uri(_fullAppId.Codebase);
			if (uri.IsFile)
			{
				accessPermission = new FileIOPermission(FileIOPermissionAccess.Read, uri.LocalPath);
			}
			else
			{
				accessPermission = new WebPermission(NetworkAccess.Connect, _fullAppId.Codebase);
			}
			accessPermission.Demand();
			_events = new EventHandlerList();
			asyncOperation = AsyncOperationManager.CreateOperation(null);
		}

		public UpdateCheckInfo CheckForDetailedUpdate()
		{
			return CheckForDetailedUpdate(persistUpdateCheckResult: true);
		}

		public UpdateCheckInfo CheckForDetailedUpdate(bool persistUpdateCheckResult)
		{
			new NamedPermissionSet("FullTrust").Demand();
			if (Interlocked.CompareExchange(ref _guard, 2, 0) != 0)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SingleOperation"));
			}
			_cancellationPending = false;
			UpdateCheckInfo updateCheckInfo = null;
			try
			{
				DeploymentManager deploymentManager = CreateDeploymentManager();
				try
				{
					deploymentManager.Bind();
					TrustParams trustParams = new TrustParams();
					trustParams.NoPrompt = true;
					deploymentManager.DetermineTrust(trustParams);
					deploymentManager.DeterminePlatformRequirements();
					updateCheckInfo = DetermineUpdateCheckResult(deploymentManager.ActivationDescription);
					if (persistUpdateCheckResult)
					{
						ProcessUpdateCheckResult(updateCheckInfo, deploymentManager.ActivationDescription);
						return updateCheckInfo;
					}
					return updateCheckInfo;
				}
				finally
				{
					deploymentManager.Dispose();
				}
			}
			finally
			{
				Interlocked.Exchange(ref _guard, 0);
			}
		}

		public bool CheckForUpdate()
		{
			return CheckForUpdate(persistUpdateCheckResult: true);
		}

		public bool CheckForUpdate(bool persistUpdateCheckResult)
		{
			UpdateCheckInfo updateCheckInfo = CheckForDetailedUpdate(persistUpdateCheckResult);
			return updateCheckInfo.UpdateAvailable;
		}

		public void CheckForUpdateAsync()
		{
			new NamedPermissionSet("FullTrust").Demand();
			if (Interlocked.CompareExchange(ref _guard, 1, 0) != 0)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SingleOperation"));
			}
			_cancellationPending = false;
			DeploymentManager deploymentManager = CreateDeploymentManager();
			deploymentManager.ProgressChanged += CheckForUpdateProgressChangedEventHandler;
			deploymentManager.BindCompleted += CheckForUpdateBindCompletedEventHandler;
			deploymentManager.BindAsync();
		}

		public void CheckForUpdateAsyncCancel()
		{
			if (_guard == 1)
			{
				_cancellationPending = true;
			}
		}

		public bool Update()
		{
			new NamedPermissionSet("FullTrust").Demand();
			if (Interlocked.CompareExchange(ref _guard, 2, 0) != 0)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SingleOperation"));
			}
			_cancellationPending = false;
			try
			{
				DeploymentManager deploymentManager = CreateDeploymentManager();
				try
				{
					deploymentManager.Bind();
					TrustParams trustParams = new TrustParams();
					trustParams.NoPrompt = true;
					deploymentManager.DetermineTrust(trustParams);
					deploymentManager.DeterminePlatformRequirements();
					UpdateCheckInfo updateCheckInfo = DetermineUpdateCheckResult(deploymentManager.ActivationDescription);
					ProcessUpdateCheckResult(updateCheckInfo, deploymentManager.ActivationDescription);
					if (!updateCheckInfo.UpdateAvailable)
					{
						return false;
					}
					deploymentManager.Synchronize();
				}
				finally
				{
					deploymentManager.Dispose();
				}
			}
			finally
			{
				Interlocked.Exchange(ref _guard, 0);
			}
			return true;
		}

		public void UpdateAsync()
		{
			new NamedPermissionSet("FullTrust").Demand();
			if (Interlocked.CompareExchange(ref _guard, 1, 0) != 0)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SingleOperation"));
			}
			_cancellationPending = false;
			DeploymentManager deploymentManager = CreateDeploymentManager();
			deploymentManager.ProgressChanged += UpdateProgressChangedEventHandler;
			deploymentManager.BindCompleted += UpdateBindCompletedEventHandler;
			deploymentManager.SynchronizeCompleted += SynchronizeNullCompletedEventHandler;
			deploymentManager.BindAsync();
		}

		public void UpdateAsyncCancel()
		{
			if (_guard == 1)
			{
				_cancellationPending = true;
			}
		}

		[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
		public void DownloadFileGroup(string groupName)
		{
			if (groupName == null)
			{
				throw new ArgumentNullException("groupName");
			}
			_subState.Invalidate();
			if (!_fullAppId.Equals(_subState.CurrentBind))
			{
				throw new InvalidOperationException(Resources.GetString("Ex_DownloadGroupAfterUpdate"));
			}
			SyncGroupDeploymentManager.Synchronize(groupName);
		}

		public void DownloadFileGroupAsync(string groupName)
		{
			DownloadFileGroupAsync(groupName, null);
		}

		[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
		public void DownloadFileGroupAsync(string groupName, object userState)
		{
			if (groupName == null)
			{
				throw new ArgumentNullException("groupName");
			}
			_subState.Invalidate();
			if (!_fullAppId.Equals(_subState.CurrentBind))
			{
				throw new InvalidOperationException(Resources.GetString("Ex_DownloadGroupAfterUpdate"));
			}
			SyncGroupDeploymentManager.SynchronizeAsync(groupName, userState);
		}

		[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
		public bool IsFileGroupDownloaded(string groupName)
		{
			return _subStore.CheckGroupInstalled(_subState, _fullAppId, groupName);
		}

		[PermissionSet(SecurityAction.Assert, Name = "FullTrust")]
		public void DownloadFileGroupAsyncCancel(string groupName)
		{
			if (groupName == null)
			{
				throw new ArgumentNullException("groupName");
			}
			SyncGroupDeploymentManager.CancelAsync(groupName);
		}

		private DeploymentManager CreateDeploymentManager()
		{
			_subState.Invalidate();
			DeploymentManager deploymentManager = new DeploymentManager(_subState.DeploymentProviderUri, isUpdate: true, isConfirmed: true, null, asyncOperation);
			deploymentManager.Callertype = DeploymentManager.CallerType.ApplicationDeployment;
			return deploymentManager;
		}

		private void CheckForUpdateProgressChangedEventHandler(object sender, DeploymentProgressChangedEventArgs e)
		{
			if (_cancellationPending)
			{
				((DeploymentManager)sender).CancelAsync();
			}
			((DeploymentProgressChangedEventHandler)Events[checkForUpdateProgressChangedKey])?.Invoke(this, e);
		}

		private void UpdateProgressChangedEventHandler(object sender, DeploymentProgressChangedEventArgs e)
		{
			if (_cancellationPending)
			{
				((DeploymentManager)sender).CancelAsync();
			}
			((DeploymentProgressChangedEventHandler)Events[updateProgressChangedKey])?.Invoke(this, e);
		}

		private void DownloadFileGroupProgressChangedEventHandler(object sender, DeploymentProgressChangedEventArgs e)
		{
			((DeploymentProgressChangedEventHandler)Events[downloadFileGroupProgressChangedKey])?.Invoke(this, e);
		}

		private void CheckForUpdateBindCompletedEventHandler(object sender, BindCompletedEventArgs e)
		{
			Exception error = null;
			DeploymentManager deploymentManager = null;
			bool updateAvailable = false;
			Version availableVersion = null;
			bool isUpdateRequired = false;
			Version minimumRequiredVersion = null;
			long updateSize = 0L;
			new NamedPermissionSet("FullTrust").Assert();
			try
			{
				deploymentManager = (DeploymentManager)sender;
				if (e.Error == null && !e.Cancelled)
				{
					TrustParams trustParams = new TrustParams();
					trustParams.NoPrompt = true;
					deploymentManager.DetermineTrust(trustParams);
					deploymentManager.DeterminePlatformRequirements();
					UpdateCheckInfo updateCheckInfo = DetermineUpdateCheckResult(deploymentManager.ActivationDescription);
					ProcessUpdateCheckResult(updateCheckInfo, deploymentManager.ActivationDescription);
					if (updateCheckInfo.UpdateAvailable)
					{
						updateAvailable = true;
						availableVersion = updateCheckInfo.AvailableVersion;
						isUpdateRequired = updateCheckInfo.IsUpdateRequired;
						minimumRequiredVersion = updateCheckInfo.MinimumRequiredVersion;
						updateSize = updateCheckInfo.UpdateSizeBytes;
					}
				}
				else
				{
					error = e.Error;
				}
			}
			catch (Exception ex)
			{
				error = ex;
			}
			finally
			{
				CodeAccessPermission.RevertAssert();
				Interlocked.Exchange(ref _guard, 0);
				CheckForUpdateCompletedEventArgs e2 = new CheckForUpdateCompletedEventArgs(error, e.Cancelled, null, updateAvailable, availableVersion, isUpdateRequired, minimumRequiredVersion, updateSize);
				((CheckForUpdateCompletedEventHandler)Events[checkForUpdateCompletedKey])?.Invoke(this, e2);
				if (deploymentManager != null)
				{
					deploymentManager.ProgressChanged -= CheckForUpdateProgressChangedEventHandler;
					deploymentManager.BindCompleted -= CheckForUpdateBindCompletedEventHandler;
					new NamedPermissionSet("FullTrust").Assert();
					try
					{
						deploymentManager.Dispose();
					}
					finally
					{
						CodeAccessPermission.RevertAssert();
					}
				}
			}
		}

		private void UpdateBindCompletedEventHandler(object sender, BindCompletedEventArgs e)
		{
			Exception error = null;
			DeploymentManager deploymentManager = null;
			bool flag = false;
			new NamedPermissionSet("FullTrust").Assert();
			try
			{
				deploymentManager = (DeploymentManager)sender;
				if (e.Error == null && !e.Cancelled)
				{
					TrustParams trustParams = new TrustParams();
					trustParams.NoPrompt = true;
					deploymentManager.DetermineTrust(trustParams);
					deploymentManager.DeterminePlatformRequirements();
					UpdateCheckInfo updateCheckInfo = DetermineUpdateCheckResult(deploymentManager.ActivationDescription);
					ProcessUpdateCheckResult(updateCheckInfo, deploymentManager.ActivationDescription);
					if (updateCheckInfo.UpdateAvailable)
					{
						flag = true;
						deploymentManager.SynchronizeAsync();
					}
				}
				else
				{
					error = e.Error;
				}
			}
			catch (Exception ex)
			{
				error = ex;
			}
			finally
			{
				CodeAccessPermission.RevertAssert();
				if (!flag)
				{
					EndUpdateAsync(deploymentManager, error, e.Cancelled);
				}
			}
		}

		private void EndUpdateAsync(DeploymentManager dm, Exception error, bool cancelled)
		{
			Interlocked.Exchange(ref _guard, 0);
			AsyncCompletedEventArgs e = new AsyncCompletedEventArgs(error, cancelled, null);
			((AsyncCompletedEventHandler)Events[updateCompletedKey])?.Invoke(this, e);
			if (dm != null)
			{
				dm.ProgressChanged -= UpdateProgressChangedEventHandler;
				dm.BindCompleted -= UpdateBindCompletedEventHandler;
				dm.SynchronizeCompleted -= SynchronizeNullCompletedEventHandler;
				new NamedPermissionSet("FullTrust").Assert();
				try
				{
					dm.Dispose();
				}
				finally
				{
					CodeAccessPermission.RevertAssert();
				}
			}
		}

		private void SynchronizeNullCompletedEventHandler(object sender, SynchronizeCompletedEventArgs e)
		{
			Exception error = null;
			DeploymentManager dm = null;
			new NamedPermissionSet("FullTrust").Assert();
			try
			{
				dm = (DeploymentManager)sender;
				error = e.Error;
			}
			catch (Exception ex)
			{
				error = ex;
			}
			finally
			{
				CodeAccessPermission.RevertAssert();
				EndUpdateAsync(dm, error, e.Cancelled);
			}
		}

		private void SynchronizeGroupCompletedEventHandler(object sender, SynchronizeCompletedEventArgs e)
		{
			try
			{
				_ = (DeploymentManager)sender;
				_ = e.Error;
			}
			catch (Exception)
			{
			}
			finally
			{
				DownloadFileGroupCompletedEventArgs e2 = new DownloadFileGroupCompletedEventArgs(e.Error, e.Cancelled, e.UserState, e.Group);
				((DownloadFileGroupCompletedEventHandler)Events[downloadFileGroupCompletedKey])?.Invoke(this, e2);
			}
		}

		private UpdateCheckInfo DetermineUpdateCheckResult(ActivationDescription actDesc)
		{
			bool updateAvailable = false;
			Version availableVersion = null;
			bool isUpdateRequired = false;
			Version version = null;
			long updateSize = 0L;
			AssemblyManifest deployManifest = actDesc.DeployManifest;
			_subState.Invalidate();
			Version version2 = _subStore.CheckUpdateInManifest(_subState, actDesc.DeploySourceUri, deployManifest, _currentVersion);
			if (version2 != null && !deployManifest.Identity.Equals(_subState.ExcludedDeployment))
			{
				updateAvailable = true;
				availableVersion = version2;
				version = deployManifest.Deployment.MinimumRequiredVersion;
				if (version != null && version.CompareTo(_currentVersion) > 0)
				{
					isUpdateRequired = true;
				}
				ulong num = actDesc.AppManifest.CalculateDependenciesSize();
				updateSize = (long)((num <= long.MaxValue) ? num : long.MaxValue);
			}
			return new UpdateCheckInfo(updateAvailable, availableVersion, isUpdateRequired, version, updateSize);
		}

		private void ProcessUpdateCheckResult(UpdateCheckInfo info, ActivationDescription actDesc)
		{
			if (_subState.IsShellVisible)
			{
				AssemblyManifest deployManifest = actDesc.DeployManifest;
				DefinitionIdentity deployId = (info.UpdateAvailable ? deployManifest.Identity : null);
				_subStore.SetPendingDeployment(_subState, deployId, DateTime.UtcNow);
			}
		}

		private void DemandPermission()
		{
			accessPermission.Demand();
		}
	}
	public class UpdateCheckInfo
	{
		private readonly bool _updateAvailable;

		private readonly Version _availableVersion;

		private readonly bool _isUpdateRequired;

		private readonly Version _minimumRequiredVersion;

		private readonly long _updateSize;

		public bool UpdateAvailable => _updateAvailable;

		public Version AvailableVersion
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _availableVersion;
			}
		}

		public bool IsUpdateRequired
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _isUpdateRequired;
			}
		}

		public Version MinimumRequiredVersion
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _minimumRequiredVersion;
			}
		}

		public long UpdateSizeBytes
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _updateSize;
			}
		}

		internal UpdateCheckInfo(bool updateAvailable, Version availableVersion, bool isUpdateRequired, Version minimumRequiredVersion, long updateSize)
		{
			_updateAvailable = updateAvailable;
			_availableVersion = availableVersion;
			_isUpdateRequired = isUpdateRequired;
			_minimumRequiredVersion = minimumRequiredVersion;
			_updateSize = updateSize;
		}

		private void RaiseExceptionIfUpdateNotAvailable()
		{
			if (!UpdateAvailable)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_UpdateNotAvailable"));
			}
		}
	}
	public delegate void CheckForUpdateCompletedEventHandler(object sender, CheckForUpdateCompletedEventArgs e);
	public class CheckForUpdateCompletedEventArgs : AsyncCompletedEventArgs
	{
		private readonly bool _updateAvailable;

		private readonly Version _availableVersion;

		private readonly bool _isUpdateRequired;

		private readonly Version _minimumRequiredVersion;

		private readonly long _updateSize;

		public bool UpdateAvailable
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _updateAvailable;
			}
		}

		public Version AvailableVersion
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _availableVersion;
			}
		}

		public bool IsUpdateRequired
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _isUpdateRequired;
			}
		}

		public Version MinimumRequiredVersion
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _minimumRequiredVersion;
			}
		}

		public long UpdateSizeBytes
		{
			get
			{
				RaiseExceptionIfUpdateNotAvailable();
				return _updateSize;
			}
		}

		internal CheckForUpdateCompletedEventArgs(Exception error, bool cancelled, object userState, bool updateAvailable, Version availableVersion, bool isUpdateRequired, Version minimumRequiredVersion, long updateSize)
			: base(error, cancelled, userState)
		{
			_updateAvailable = updateAvailable;
			_availableVersion = availableVersion;
			_isUpdateRequired = isUpdateRequired;
			_minimumRequiredVersion = minimumRequiredVersion;
			_updateSize = updateSize;
		}

		private void RaiseExceptionIfUpdateNotAvailable()
		{
			if (!UpdateAvailable)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_UpdateNotAvailable"));
			}
		}
	}
	public delegate void DownloadFileGroupCompletedEventHandler(object sender, DownloadFileGroupCompletedEventArgs e);
	public class DownloadFileGroupCompletedEventArgs : AsyncCompletedEventArgs
	{
		private readonly string _groupName;

		public string Group => _groupName;

		internal DownloadFileGroupCompletedEventArgs(Exception error, bool cancelled, object userState, string groupName)
			: base(error, cancelled, userState)
		{
			_groupName = groupName;
		}
	}
	internal class DefinitionAppId
	{
		private System.Deployment.Internal.Isolation.IDefinitionAppId _idComPtr;

		public ulong Hash => System.Deployment.Internal.Isolation.IsolationInterop.AppIdAuthority.HashDefinition(0u, _idComPtr);

		public System.Deployment.Internal.Isolation.IDefinitionAppId ComPointer => _idComPtr;

		public string Codebase => _idComPtr.get_Codebase();

		public DefinitionIdentity DeploymentIdentity => PathComponent(0u);

		public DefinitionIdentity ApplicationIdentity => PathComponent(1u);

		public DefinitionAppId()
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.AppIdAuthority.CreateDefinition();
		}

		public DefinitionAppId(params DefinitionIdentity[] idPath)
			: this(null, idPath)
		{
		}

		public DefinitionAppId(string codebase, params DefinitionIdentity[] idPath)
		{
			uint num = (uint)idPath.Length;
			System.Deployment.Internal.Isolation.IDefinitionIdentity[] array = new System.Deployment.Internal.Isolation.IDefinitionIdentity[num];
			for (uint num2 = 0u; num2 < num; num2++)
			{
				array[num2] = idPath[num2].ComPointer;
			}
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.AppIdAuthority.CreateDefinition();
			_idComPtr.put_Codebase(codebase);
			_idComPtr.SetAppPath(num, array);
		}

		public DefinitionAppId(string text)
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.AppIdAuthority.TextToDefinition(0u, text);
		}

		public DefinitionAppId(System.Deployment.Internal.Isolation.IDefinitionAppId idComPtr)
		{
			_idComPtr = idComPtr;
		}

		public DefinitionAppId ToDeploymentAppId()
		{
			return new DefinitionAppId(Codebase, DeploymentIdentity);
		}

		public ApplicationIdentity ToApplicationIdentity()
		{
			return new ApplicationIdentity(System.Deployment.Internal.Isolation.IsolationInterop.AppIdAuthority.DefinitionToText(0u, _idComPtr));
		}

		public override bool Equals(object obj)
		{
			if (obj is DefinitionAppId)
			{
				return System.Deployment.Internal.Isolation.IsolationInterop.AppIdAuthority.AreDefinitionsEqual(0u, ComPointer, ((DefinitionAppId)obj).ComPointer);
			}
			return false;
		}

		public override int GetHashCode()
		{
			return (int)Hash;
		}

		public override string ToString()
		{
			return System.Deployment.Internal.Isolation.IsolationInterop.AppIdAuthority.DefinitionToText(0u, _idComPtr);
		}

		private DefinitionIdentity PathComponent(uint index)
		{
			System.Deployment.Internal.Isolation.IEnumDefinitionIdentity enumDefinitionIdentity = null;
			try
			{
				enumDefinitionIdentity = _idComPtr.EnumAppPath();
				if (index != 0)
				{
					enumDefinitionIdentity.Skip(index);
				}
				System.Deployment.Internal.Isolation.IDefinitionIdentity[] array = new System.Deployment.Internal.Isolation.IDefinitionIdentity[1];
				uint num = enumDefinitionIdentity.Next(1u, array);
				return (num == 1) ? new DefinitionIdentity(array[0]) : null;
			}
			finally
			{
				if (enumDefinitionIdentity != null)
				{
					Marshal.ReleaseComObject(enumDefinitionIdentity);
				}
			}
		}
	}
	internal static class ApplicationTrust
	{
		public static System.Security.Policy.ApplicationTrust RequestTrust(SubscriptionState subState, bool isShellVisible, bool isUpdate, ActivationContext actCtx)
		{
			TrustManagerContext trustManagerContext = new TrustManagerContext();
			trustManagerContext.IgnorePersistedDecision = false;
			trustManagerContext.NoPrompt = false;
			trustManagerContext.Persist = true;
			return RequestTrust(subState, isShellVisible, isUpdate, actCtx, trustManagerContext);
		}

		public static System.Security.Policy.ApplicationTrust RequestTrust(SubscriptionState subState, bool isShellVisible, bool isUpdate, ActivationContext actCtx, TrustManagerContext tmc)
		{
			if (!subState.IsInstalled || subState.IsShellVisible != isShellVisible)
			{
				tmc.IgnorePersistedDecision = true;
			}
			if (isUpdate)
			{
				tmc.PreviousApplicationIdentity = subState.CurrentBind.ToApplicationIdentity();
			}
			bool flag = false;
			try
			{
				flag = ApplicationSecurityManager.DetermineApplicationTrust(actCtx, tmc);
			}
			catch (TypeLoadException innerException)
			{
				throw new InvalidDeploymentException(Resources.GetString("Ex_InvalidTrustInfo"), innerException);
			}
			if (!flag)
			{
				throw new TrustNotGrantedException(Resources.GetString("Ex_NoTrust"));
			}
			System.Security.Policy.ApplicationTrust applicationTrust = null;
			for (int i = 0; i < 5; i++)
			{
				applicationTrust = ApplicationSecurityManager.UserApplicationTrusts[actCtx.Identity.FullName];
				if (applicationTrust != null)
				{
					break;
				}
				Thread.Sleep(10);
			}
			if (applicationTrust == null)
			{
				throw new InvalidDeploymentException(Resources.GetString("Ex_InvalidMatchTrust"));
			}
			return applicationTrust;
		}

		public static void RemoveCachedTrust(DefinitionAppId appId)
		{
			ApplicationSecurityManager.UserApplicationTrusts.Remove(appId.ToApplicationIdentity(), ApplicationVersionMatch.MatchExactVersion);
		}

		public static System.Security.Policy.ApplicationTrust PersistTrustWithoutEvaluation(ActivationContext actCtx)
		{
			ApplicationSecurityInfo applicationSecurityInfo = new ApplicationSecurityInfo(actCtx);
			System.Security.Policy.ApplicationTrust applicationTrust = new System.Security.Policy.ApplicationTrust(actCtx.Identity);
			applicationTrust.IsApplicationTrustedToRun = true;
			applicationTrust.DefaultGrantSet = new PolicyStatement(applicationSecurityInfo.DefaultRequestSet, PolicyStatementAttribute.Nothing);
			applicationTrust.Persist = true;
			applicationTrust.ApplicationIdentity = actCtx.Identity;
			ApplicationSecurityManager.UserApplicationTrusts.Add(applicationTrust);
			return applicationTrust;
		}
	}
	internal static class AssemblyIdentityItems
	{
		public const string Name = "name";

		public const string PublicKeyToken = "publicKeyToken";

		public const string Version = "version";

		public const string ProcessorArchitecture = "processorArchitecture";

		public const string Culture = "culture";

		public const string Type = "type";

		public const string Language = "language";
	}
	internal class DefinitionIdentity : ICloneable
	{
		private System.Deployment.Internal.Isolation.IDefinitionIdentity _idComPtr;

		public string this[string name]
		{
			get
			{
				return _idComPtr.GetAttribute(null, name);
			}
			set
			{
				_idComPtr.SetAttribute(null, name, value);
			}
		}

		public string this[string ns, string name]
		{
			set
			{
				_idComPtr.SetAttribute(ns, name, value);
			}
		}

		public string Name
		{
			get
			{
				return this["name"];
			}
			set
			{
				this["name"] = value;
			}
		}

		public Version Version
		{
			get
			{
				string text = this["version"];
				if (text == null)
				{
					return null;
				}
				return new Version(text);
			}
		}

		public string PublicKeyToken => this["publicKeyToken"];

		public string ProcessorArchitecture => this["processorArchitecture"];

		public ulong Hash => System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.HashDefinition(0u, _idComPtr);

		public string KeyForm => System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.GenerateDefinitionKey(0u, _idComPtr);

		public System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] Attributes
		{
			get
			{
				System.Deployment.Internal.Isolation.IEnumIDENTITY_ATTRIBUTE enumIDENTITY_ATTRIBUTE = null;
				try
				{
					ArrayList arrayList = new ArrayList();
					enumIDENTITY_ATTRIBUTE = _idComPtr.EnumAttributes();
					System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] array = new System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[1];
					while (enumIDENTITY_ATTRIBUTE.Next(1u, array) == 1)
					{
						arrayList.Add(array[0]);
					}
					return (System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[])arrayList.ToArray(typeof(System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE));
				}
				finally
				{
					if (enumIDENTITY_ATTRIBUTE != null)
					{
						Marshal.ReleaseComObject(enumIDENTITY_ATTRIBUTE);
					}
				}
			}
		}

		public bool IsEmpty
		{
			get
			{
				System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] attributes = Attributes;
				System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] array = attributes;
				for (int i = 0; i < array.Length; i++)
				{
					System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE iDENTITY_ATTRIBUTE = array[i];
					if (!string.IsNullOrEmpty(iDENTITY_ATTRIBUTE.Value))
					{
						return false;
					}
				}
				return true;
			}
		}

		public System.Deployment.Internal.Isolation.IDefinitionIdentity ComPointer => _idComPtr;

		public DefinitionIdentity()
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.CreateDefinition();
		}

		public DefinitionIdentity(string text)
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.TextToDefinition(0u, text);
		}

		public DefinitionIdentity(System.Deployment.Internal.Isolation.IDefinitionIdentity idComPtr)
		{
			_idComPtr = idComPtr;
		}

		public DefinitionIdentity(ReferenceIdentity refId)
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.CreateDefinition();
			System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] attributes = refId.Attributes;
			System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] array = attributes;
			for (int i = 0; i < array.Length; i++)
			{
				System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE iDENTITY_ATTRIBUTE = array[i];
				this[iDENTITY_ATTRIBUTE.Namespace, iDENTITY_ATTRIBUTE.Name] = iDENTITY_ATTRIBUTE.Value;
			}
		}

		public DefinitionIdentity(AssemblyName asmName)
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.CreateDefinition();
			this["name"] = asmName.Name;
			this["version"] = asmName.Version.ToString();
			if (asmName.CultureInfo != null)
			{
				this["culture"] = asmName.CultureInfo.Name;
			}
			byte[] publicKeyToken = asmName.GetPublicKeyToken();
			if (publicKeyToken != null && publicKeyToken.Length > 0)
			{
				this["publicKeyToken"] = HexString.FromBytes(publicKeyToken);
			}
		}

		public bool Matches(ReferenceIdentity refId, bool exact)
		{
			if (System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.DoesDefinitionMatchReference(exact ? 1u : 0u, _idComPtr, refId.ComPointer))
			{
				return Version == refId.Version;
			}
			return false;
		}

		public DefinitionIdentity ToSubscriptionId()
		{
			DefinitionIdentity definitionIdentity = (DefinitionIdentity)Clone();
			definitionIdentity["version"] = null;
			return definitionIdentity;
		}

		public DefinitionIdentity ToPKTGroupId()
		{
			DefinitionIdentity definitionIdentity = (DefinitionIdentity)Clone();
			definitionIdentity["version"] = null;
			definitionIdentity["publicKeyToken"] = null;
			return definitionIdentity;
		}

		public override bool Equals(object obj)
		{
			if (obj is DefinitionIdentity)
			{
				return System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.AreDefinitionsEqual(0u, ComPointer, ((DefinitionIdentity)obj).ComPointer);
			}
			return false;
		}

		public override int GetHashCode()
		{
			return (int)Hash;
		}

		public override string ToString()
		{
			return System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.DefinitionToText(0u, _idComPtr);
		}

		public object Clone()
		{
			return new DefinitionIdentity(_idComPtr.Clone(IntPtr.Zero, null));
		}
	}
	internal class ReferenceIdentity : ICloneable
	{
		private System.Deployment.Internal.Isolation.IReferenceIdentity _idComPtr;

		public string this[string name]
		{
			get
			{
				return _idComPtr.GetAttribute(null, name);
			}
			set
			{
				_idComPtr.SetAttribute(null, name, value);
			}
		}

		public string Name => this["name"];

		public string Culture => this["culture"];

		public Version Version
		{
			get
			{
				string text = this["version"];
				if (text == null)
				{
					return null;
				}
				return new Version(text);
			}
		}

		public string PublicKeyToken => this["publicKeyToken"];

		public string ProcessorArchitecture
		{
			get
			{
				return this["processorArchitecture"];
			}
			set
			{
				this["processorArchitecture"] = value;
			}
		}

		public ulong Hash => System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.HashReference(0u, _idComPtr);

		public System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] Attributes
		{
			get
			{
				System.Deployment.Internal.Isolation.IEnumIDENTITY_ATTRIBUTE enumIDENTITY_ATTRIBUTE = null;
				try
				{
					ArrayList arrayList = new ArrayList();
					enumIDENTITY_ATTRIBUTE = _idComPtr.EnumAttributes();
					System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] array = new System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[1];
					while (enumIDENTITY_ATTRIBUTE.Next(1u, array) == 1)
					{
						arrayList.Add(array[0]);
					}
					return (System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[])arrayList.ToArray(typeof(System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE));
				}
				finally
				{
					if (enumIDENTITY_ATTRIBUTE != null)
					{
						Marshal.ReleaseComObject(enumIDENTITY_ATTRIBUTE);
					}
				}
			}
		}

		public System.Deployment.Internal.Isolation.IReferenceIdentity ComPointer => _idComPtr;

		public ReferenceIdentity()
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.CreateReference();
		}

		public ReferenceIdentity(string text)
		{
			_idComPtr = System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.TextToReference(0u, text);
		}

		public ReferenceIdentity(System.Deployment.Internal.Isolation.IReferenceIdentity idComPtr)
		{
			_idComPtr = idComPtr;
		}

		public override bool Equals(object obj)
		{
			if (obj is ReferenceIdentity)
			{
				return System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.AreReferencesEqual(0u, ComPointer, ((ReferenceIdentity)obj).ComPointer);
			}
			return false;
		}

		public override int GetHashCode()
		{
			return (int)Hash;
		}

		public override string ToString()
		{
			return System.Deployment.Internal.Isolation.IsolationInterop.IdentityAuthority.ReferenceToText(0u, _idComPtr);
		}

		public object Clone()
		{
			return new ReferenceIdentity(_idComPtr.Clone(IntPtr.Zero, null));
		}
	}
}
namespace System.Deployment.Application.Manifest
{
	internal enum timeUnitType
	{
		hours = 1,
		days,
		weeks
	}
	internal enum hashAlgorithmType
	{
		sha1 = 1,
		sha256,
		sha384,
		sha512,
		md5,
		md4,
		md2
	}
	internal class Description
	{
		private readonly string _publisher;

		private readonly string _product;

		private readonly string _suiteName;

		private readonly Uri _supportUri;

		private readonly Uri _errorReportUri;

		private readonly string _iconFile;

		private readonly string _iconFileFS;

		private readonly string _filteredPublisher;

		private readonly string _filteredProduct;

		private readonly string _filteredSuiteName;

		public string Publisher => _publisher;

		public string Product => _product;

		public Uri SupportUri => _supportUri;

		public string SupportUrl
		{
			get
			{
				if (!(_supportUri != null))
				{
					return null;
				}
				return _supportUri.AbsoluteUri;
			}
		}

		public string IconFile => _iconFile;

		public string IconFileFS => _iconFileFS;

		public Uri ErrorReportUri => _errorReportUri;

		public string ErrorReportUrl
		{
			get
			{
				if (!(_errorReportUri != null))
				{
					return null;
				}
				return _errorReportUri.AbsoluteUri;
			}
		}

		public string FilteredPublisher => _filteredPublisher;

		public string FilteredProduct => _filteredProduct;

		public string FilteredSuiteName => _filteredSuiteName;

		public Description(System.Deployment.Internal.Isolation.Manifest.DescriptionMetadataEntry descriptionMetadataEntry)
		{
			_publisher = descriptionMetadataEntry.Publisher;
			_product = descriptionMetadataEntry.Product;
			_suiteName = descriptionMetadataEntry.SuiteName;
			if (_suiteName == null)
			{
				_suiteName = "";
			}
			_supportUri = AssemblyManifest.UriFromMetadataEntry(descriptionMetadataEntry.SupportUrl, "Ex_DescriptionSupportUrlNotValid");
			_errorReportUri = AssemblyManifest.UriFromMetadataEntry(descriptionMetadataEntry.ErrorReportUrl, "Ex_DescriptionErrorReportUrlNotValid");
			_iconFile = descriptionMetadataEntry.IconFile;
			if (_iconFile != null)
			{
				_iconFileFS = UriHelper.NormalizePathDirectorySeparators(_iconFile);
			}
			_filteredPublisher = PathTwiddler.FilterString(_publisher, ' ', fMultiReplace: false);
			_filteredProduct = PathTwiddler.FilterString(_product, ' ', fMultiReplace: false);
			_filteredSuiteName = PathTwiddler.FilterString(_suiteName, ' ', fMultiReplace: false);
		}
	}
	internal class EntryPoint
	{
		private readonly string _name;

		private readonly string _commandLineFile;

		private readonly string _commandLineParamater;

		private readonly DependentAssembly _dependentAssembly;

		private readonly bool _hostInBrowser;

		private readonly bool _customHostSpecified;

		private readonly bool _customUX;

		public DependentAssembly Assembly => _dependentAssembly;

		public string CommandFile => _commandLineFile;

		public bool HostInBrowser => _hostInBrowser;

		public bool CustomHostSpecified => _customHostSpecified;

		public bool CustomUX => _customUX;

		public string CommandParameters => _commandLineParamater;

		public EntryPoint(System.Deployment.Internal.Isolation.Manifest.EntryPointEntry entryPointEntry, AssemblyManifest manifest)
		{
			_name = entryPointEntry.Name;
			_commandLineFile = entryPointEntry.CommandLine_File;
			_commandLineParamater = entryPointEntry.CommandLine_Parameters;
			_hostInBrowser = (entryPointEntry.Flags & 1) != 0;
			_customHostSpecified = (entryPointEntry.Flags & 2) != 0;
			_customUX = (entryPointEntry.Flags & 4) != 0;
			if (!_customHostSpecified)
			{
				if (entryPointEntry.Identity != null)
				{
					_dependentAssembly = manifest.GetDependentAssemblyByIdentity(entryPointEntry.Identity);
				}
				if (_dependentAssembly == null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, Resources.GetString("Ex_NoMatchingAssemblyForEntryPoint"));
				}
			}
		}
	}
	internal class DependentOS
	{
		private readonly ushort _majorVersion;

		private readonly ushort _minorVersion;

		private readonly ushort _buildNumber;

		private readonly byte _servicePackMajor;

		private readonly byte _servicePackMinor;

		private readonly Uri _supportUrl;

		public ushort MajorVersion => _majorVersion;

		public ushort MinorVersion => _minorVersion;

		public ushort BuildNumber => _buildNumber;

		public byte ServicePackMajor => _servicePackMajor;

		public byte ServicePackMinor => _servicePackMinor;

		public Uri SupportUrl => _supportUrl;

		public DependentOS(System.Deployment.Internal.Isolation.Manifest.DependentOSMetadataEntry dependentOSMetadataEntry)
		{
			_majorVersion = dependentOSMetadataEntry.MajorVersion;
			_minorVersion = dependentOSMetadataEntry.MinorVersion;
			_buildNumber = dependentOSMetadataEntry.BuildNumber;
			_servicePackMajor = dependentOSMetadataEntry.ServicePackMajor;
			_servicePackMinor = dependentOSMetadataEntry.ServicePackMinor;
			_supportUrl = AssemblyManifest.UriFromMetadataEntry(dependentOSMetadataEntry.SupportUrl, "Ex_DependentOSSupportUrlNotValid");
		}
	}
	internal class Deployment
	{
		private readonly Uri _codebaseUri;

		private readonly DeploymentUpdate _update;

		private readonly Version _minimumRequiredVersion;

		private readonly bool _disallowUrlActivation;

		private readonly bool _install;

		private readonly bool _trustURLParameters;

		private readonly bool _mapFileExtensions;

		private readonly bool _createDesktopShortcut;

		public Uri ProviderCodebaseUri => _codebaseUri;

		public DeploymentUpdate DeploymentUpdate => _update;

		public Version MinimumRequiredVersion => _minimumRequiredVersion;

		public bool DisallowUrlActivation => _disallowUrlActivation;

		public bool Install => _install;

		public bool TrustURLParameters => _trustURLParameters;

		public bool MapFileExtensions => _mapFileExtensions;

		public bool CreateDesktopShortcut => _createDesktopShortcut;

		public bool IsUpdateSectionPresent
		{
			get
			{
				if (!DeploymentUpdate.BeforeApplicationStartup && !DeploymentUpdate.MaximumAgeSpecified)
				{
					return false;
				}
				return true;
			}
		}

		public bool IsInstalledAndNoDeploymentProvider
		{
			get
			{
				if (Install)
				{
					return ProviderCodebaseUri == null;
				}
				return false;
			}
		}

		public Deployment(System.Deployment.Internal.Isolation.Manifest.DeploymentMetadataEntry deploymentMetadataEntry)
		{
			_disallowUrlActivation = (deploymentMetadataEntry.DeploymentFlags & 0x80) != 0;
			_install = (deploymentMetadataEntry.DeploymentFlags & 0x20) != 0;
			_trustURLParameters = (deploymentMetadataEntry.DeploymentFlags & 0x40) != 0;
			_mapFileExtensions = (deploymentMetadataEntry.DeploymentFlags & 0x100) != 0;
			_createDesktopShortcut = (deploymentMetadataEntry.DeploymentFlags & 0x200) != 0;
			_update = new DeploymentUpdate(deploymentMetadataEntry);
			_minimumRequiredVersion = ((deploymentMetadataEntry.MinimumRequiredVersion != null) ? new Version(deploymentMetadataEntry.MinimumRequiredVersion) : null);
			_codebaseUri = AssemblyManifest.UriFromMetadataEntry(deploymentMetadataEntry.DeploymentProviderCodebase, "Ex_DepProviderNotValid");
		}
	}
	internal class DeploymentUpdate
	{
		private readonly bool _beforeApplicationStartup;

		private readonly bool _maximumAgeSpecified;

		private readonly TimeSpan _maximumAgeAllowed;

		private readonly uint _maximumAgeCount;

		private readonly timeUnitType _maximumAgeUnit;

		public bool BeforeApplicationStartup => _beforeApplicationStartup;

		public bool MaximumAgeSpecified => _maximumAgeSpecified;

		public TimeSpan MaximumAgeAllowed => _maximumAgeAllowed;

		public DeploymentUpdate(System.Deployment.Internal.Isolation.Manifest.DeploymentMetadataEntry entry)
		{
			_beforeApplicationStartup = (entry.DeploymentFlags & 4) != 0;
			_maximumAgeAllowed = GetTimeSpanFromItem(entry.MaximumAge, entry.MaximumAge_Unit, out _maximumAgeCount, out _maximumAgeUnit, out _maximumAgeSpecified);
		}

		private static TimeSpan GetTimeSpanFromItem(ushort time, byte elapsedunit, out uint count, out timeUnitType unit, out bool specified)
		{
			specified = true;
			TimeSpan result;
			switch (elapsedunit)
			{
			case 1:
				result = TimeSpan.FromHours((int)time);
				count = time;
				unit = timeUnitType.hours;
				break;
			case 2:
				result = TimeSpan.FromDays((int)time);
				count = time;
				unit = timeUnitType.days;
				break;
			case 3:
				result = TimeSpan.FromDays(time * 7);
				count = time;
				unit = timeUnitType.weeks;
				break;
			default:
				specified = false;
				result = TimeSpan.Zero;
				count = 0u;
				unit = timeUnitType.days;
				break;
			}
			return result;
		}
	}
	internal class DependentAssembly
	{
		private readonly ulong _size;

		private readonly string _codebase;

		private readonly ReferenceIdentity _identity;

		private readonly string _group;

		private readonly string _codebaseFS;

		private readonly string _description;

		private readonly Uri _supportUrl;

		private readonly string _resourceFallbackCulture;

		private readonly bool _resourceFallbackCultureInternal;

		private readonly bool _optional;

		private readonly bool _visible;

		private readonly bool _preRequisite;

		private HashCollection _hashCollection = new HashCollection();

		public ReferenceIdentity Identity => _identity;

		public string Codebase => _codebase;

		public ulong Size => _size;

		public string Group => _group;

		public string CodebaseFS => _codebaseFS;

		public string Description => _description;

		public Uri SupportUrl => _supportUrl;

		public string ResourceFallbackCulture => _resourceFallbackCulture;

		public bool IsPreRequisite => _preRequisite;

		public bool IsOptional => _optional;

		public HashCollection HashCollection => _hashCollection;

		public DependentAssembly(ReferenceIdentity refId)
		{
			_identity = refId;
		}

		public DependentAssembly(System.Deployment.Internal.Isolation.Manifest.AssemblyReferenceEntry assemblyReferenceEntry)
		{
			System.Deployment.Internal.Isolation.Manifest.AssemblyReferenceDependentAssemblyEntry dependentAssembly = assemblyReferenceEntry.DependentAssembly;
			_size = dependentAssembly.Size;
			_codebase = dependentAssembly.Codebase;
			_group = dependentAssembly.Group;
			bool flag = false;
			System.Deployment.Internal.Isolation.ISection hashElements = dependentAssembly.HashElements;
			uint num = hashElements?.Count ?? 0;
			if (num != 0)
			{
				uint celtFetched = 0u;
				System.Deployment.Internal.Isolation.Manifest.IHashElementEntry[] array = new System.Deployment.Internal.Isolation.Manifest.IHashElementEntry[num];
				System.Deployment.Internal.Isolation.IEnumUnknown enumUnknown = (System.Deployment.Internal.Isolation.IEnumUnknown)hashElements._NewEnum;
				int errorCode = enumUnknown.Next(num, array, ref celtFetched);
				Marshal.ThrowExceptionForHR(errorCode);
				if (celtFetched != num)
				{
					throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_IsoEnumFetchNotEqualToCount"));
				}
				for (uint num2 = 0u; num2 < num; num2++)
				{
					System.Deployment.Internal.Isolation.Manifest.HashElementEntry allData = array[num2].AllData;
					if (allData.DigestValueSize != 0)
					{
						byte[] array2 = new byte[allData.DigestValueSize];
						Marshal.Copy(allData.DigestValue, array2, 0, (int)allData.DigestValueSize);
						_hashCollection.AddHash(array2, (System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD)allData.DigestMethod, (System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM)allData.Transform);
						flag = true;
					}
				}
			}
			if (!flag && dependentAssembly.HashValueSize != 0)
			{
				byte[] array3 = new byte[dependentAssembly.HashValueSize];
				Marshal.Copy(dependentAssembly.HashValue, array3, 0, (int)dependentAssembly.HashValueSize);
				_hashCollection.AddHash(array3, (System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD)dependentAssembly.HashAlgorithm, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_IDENTITY);
			}
			_preRequisite = (dependentAssembly.Flags & 4) != 0;
			_optional = (assemblyReferenceEntry.Flags & 1) != 0;
			_visible = (dependentAssembly.Flags & 2) != 0;
			_resourceFallbackCultureInternal = (dependentAssembly.Flags & 8) != 0;
			_resourceFallbackCulture = dependentAssembly.ResourceFallbackCulture;
			_description = dependentAssembly.Description;
			_supportUrl = AssemblyManifest.UriFromMetadataEntry(dependentAssembly.SupportUrl, "Ex_DependencySupportUrlNotValid");
			System.Deployment.Internal.Isolation.IReferenceIdentity referenceIdentity = assemblyReferenceEntry.ReferenceIdentity;
			_identity = new ReferenceIdentity(referenceIdentity);
			_codebaseFS = UriHelper.NormalizePathDirectorySeparators(_codebase);
		}
	}
	internal class FileAssociation
	{
		private readonly string _extension;

		private readonly string _description;

		private readonly string _progId;

		private readonly string _defaultIcon;

		private readonly string _parameter;

		public string Extension => _extension;

		public string Description => _description;

		public string ProgID => _progId;

		public string DefaultIcon => _defaultIcon;

		public string Parameter => _parameter;

		public FileAssociation(System.Deployment.Internal.Isolation.Manifest.FileAssociationEntry fileAssociationEntry)
		{
			_extension = fileAssociationEntry.Extension;
			_description = fileAssociationEntry.Description;
			_progId = fileAssociationEntry.ProgID;
			_defaultIcon = fileAssociationEntry.DefaultIcon;
			_parameter = fileAssociationEntry.Parameter;
		}
	}
	internal class File
	{
		private readonly string _name;

		private readonly string _loadFrom;

		private readonly ulong _size;

		private readonly string _group;

		private readonly bool _optional;

		private readonly bool _isData;

		private readonly string _nameFS;

		private HashCollection _hashCollection = new HashCollection();

		public string Name => _name;

		public ulong Size => _size;

		public string Group => _group;

		public bool IsOptional => _optional;

		public bool IsData => _isData;

		public string NameFS => _nameFS;

		public HashCollection HashCollection => _hashCollection;

		protected internal File(string name, ulong size)
		{
			_name = name;
			_size = size;
			_nameFS = UriHelper.NormalizePathDirectorySeparators(_name);
		}

		public File(string name, byte[] hash, ulong size)
		{
			_name = name;
			_hashCollection.AddHash(hash, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA1, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_IDENTITY);
			_size = size;
			_nameFS = UriHelper.NormalizePathDirectorySeparators(_name);
		}

		public File(System.Deployment.Internal.Isolation.Manifest.FileEntry fileEntry)
		{
			_name = fileEntry.Name;
			_loadFrom = fileEntry.LoadFrom;
			_size = fileEntry.Size;
			_group = fileEntry.Group;
			_optional = (fileEntry.Flags & 1) != 0;
			_isData = (fileEntry.WritableType & 2) != 0;
			bool flag = false;
			System.Deployment.Internal.Isolation.ISection hashElements = fileEntry.HashElements;
			uint num = hashElements?.Count ?? 0;
			if (num != 0)
			{
				uint celtFetched = 0u;
				System.Deployment.Internal.Isolation.Manifest.IHashElementEntry[] array = new System.Deployment.Internal.Isolation.Manifest.IHashElementEntry[num];
				System.Deployment.Internal.Isolation.IEnumUnknown enumUnknown = (System.Deployment.Internal.Isolation.IEnumUnknown)hashElements._NewEnum;
				int errorCode = enumUnknown.Next(num, array, ref celtFetched);
				Marshal.ThrowExceptionForHR(errorCode);
				if (celtFetched != num)
				{
					throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_IsoEnumFetchNotEqualToCount"));
				}
				for (uint num2 = 0u; num2 < num; num2++)
				{
					System.Deployment.Internal.Isolation.Manifest.HashElementEntry allData = array[num2].AllData;
					if (allData.DigestValueSize != 0)
					{
						byte[] array2 = new byte[allData.DigestValueSize];
						Marshal.Copy(allData.DigestValue, array2, 0, (int)allData.DigestValueSize);
						_hashCollection.AddHash(array2, (System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD)allData.DigestMethod, (System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM)allData.Transform);
						flag = true;
					}
				}
			}
			if (!flag && fileEntry.HashValueSize != 0)
			{
				byte[] array3 = new byte[fileEntry.HashValueSize];
				Marshal.Copy(fileEntry.HashValue, array3, 0, (int)fileEntry.HashValueSize);
				_hashCollection.AddHash(array3, (System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD)fileEntry.HashAlgorithm, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_IDENTITY);
			}
			_nameFS = UriHelper.NormalizePathDirectorySeparators(_name);
		}
	}
	internal enum ManifestSourceFormat
	{
		XmlFile,
		CompLib,
		ID_1,
		Stream,
		Unknown
	}
	internal class AssemblyManifest
	{
		internal enum ManifestType
		{
			Application,
			Deployment
		}

		protected class ManifestParseErrors : System.Deployment.Internal.Isolation.IManifestParseErrorCallback, IEnumerable
		{
			public class ManifestParseError
			{
				public uint StartLine;

				public uint nStartColumn;

				public uint cCharacterCount;

				public int hr;

				public string ErrorStatusHostFile;

				public uint ParameterCount;

				public string[] Parameters;
			}

			public class ParseErrorEnumerator : IEnumerator
			{
				private int _index;

				private ManifestParseErrors _manifestParseErrors;

				public ManifestParseError Current => (ManifestParseError)_manifestParseErrors._parsingErrors[_index];

				object IEnumerator.Current => _manifestParseErrors._parsingErrors[_index];

				public ParseErrorEnumerator(ManifestParseErrors manifestParseErrors)
				{
					_manifestParseErrors = manifestParseErrors;
					_index = -1;
				}

				public void Reset()
				{
					_index = -1;
				}

				public bool MoveNext()
				{
					_index++;
					return _index < _manifestParseErrors._parsingErrors.Count;
				}
			}

			protected ArrayList _parsingErrors = new ArrayList();

			public void OnError(uint StartLine, uint nStartColumn, uint cCharacterCount, int hr, string ErrorStatusHostFile, uint ParameterCount, string[] Parameters)
			{
				ManifestParseError manifestParseError = new ManifestParseError();
				manifestParseError.StartLine = StartLine;
				manifestParseError.nStartColumn = nStartColumn;
				manifestParseError.cCharacterCount = cCharacterCount;
				manifestParseError.hr = hr;
				manifestParseError.ErrorStatusHostFile = ErrorStatusHostFile;
				manifestParseError.ParameterCount = ParameterCount;
				manifestParseError.Parameters = Parameters;
				_parsingErrors.Add(manifestParseError);
			}

			public ParseErrorEnumerator GetEnumerator()
			{
				return new ParseErrorEnumerator(this);
			}

			IEnumerator IEnumerable.GetEnumerator()
			{
				return GetEnumerator();
			}
		}

		internal enum CertificateStatus
		{
			TrustedPublisher,
			AuthenticodedNotInTrustedList,
			NoCertificate,
			DistrustedPublisger,
			RevokedCertificate,
			UnknownCertificateStatus
		}

		private string _rawXmlFilePath;

		private byte[] _rawXmlBytes;

		private System.Deployment.Internal.Isolation.Manifest.ICMS _cms;

		private object _identity;

		private object _description;

		private object _entryPoints;

		private object _dependentAssemblies;

		private object _files;

		private object _fileAssociations;

		private object _deployment;

		private object _dependentOS;

		private object _manifestFlags;

		private object _requestedExecutionLevel;

		private object _requestedExecutionLevelUIAccess;

		private ManifestSourceFormat _manifestSourceFormat = ManifestSourceFormat.Unknown;

		private DefinitionIdentity _id1Identity;

		private DefinitionIdentity _complibIdentity;

		private bool _id1ManifestPresent;

		private string _id1RequestedExecutionLevel;

		private ulong _sizeInBytes;

		private bool _unhashedFilePresent;

		private bool _unhashedDependencyPresent;

		private bool _signed;

		private static char[] SpecificInvalidIdentityChars = new char[2] { '#', '&' };

		public string RawXmlFilePath => _rawXmlFilePath;

		public byte[] RawXmlBytes => _rawXmlBytes;

		public DefinitionIdentity Identity
		{
			get
			{
				if (_identity == null && _cms != null)
				{
					DefinitionIdentity definitionIdentity = null;
					Interlocked.CompareExchange(value: (_cms.Identity != null) ? new DefinitionIdentity(_cms.Identity) : new DefinitionIdentity(), location1: ref _identity, comparand: null);
				}
				return (DefinitionIdentity)_identity;
			}
		}

		public ulong SizeInBytes => _sizeInBytes;

		public DefinitionIdentity Id1Identity => _id1Identity;

		public DefinitionIdentity ComplibIdentity => _complibIdentity;

		public bool Id1ManifestPresent => _id1ManifestPresent;

		public string Id1RequestedExecutionLevel => _id1RequestedExecutionLevel;

		public uint ManifestFlags
		{
			get
			{
				if (_manifestFlags == null && _cms != null)
				{
					System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry metadataSectionEntry = (System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry)_cms.MetadataSectionEntry;
					uint num = 0u;
					num = metadataSectionEntry.ManifestFlags;
					Interlocked.CompareExchange(ref _manifestFlags, num, null);
				}
				return (uint)_manifestFlags;
			}
		}

		public string RequestedExecutionLevel
		{
			get
			{
				if (_requestedExecutionLevel == null && _cms != null)
				{
					System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry metadataSectionEntry = (System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry)_cms.MetadataSectionEntry;
					string requestedExecutionLevel = metadataSectionEntry.RequestedExecutionLevel;
					Interlocked.CompareExchange(ref _requestedExecutionLevel, requestedExecutionLevel, null);
				}
				return (string)_requestedExecutionLevel;
			}
		}

		public bool RequestedExecutionLevelUIAccess
		{
			get
			{
				if (_requestedExecutionLevelUIAccess == null && _cms != null)
				{
					System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry metadataSectionEntry = (System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry)_cms.MetadataSectionEntry;
					bool flag = false;
					flag = metadataSectionEntry.RequestedExecutionLevelUIAccess;
					Interlocked.CompareExchange(ref _requestedExecutionLevelUIAccess, flag, null);
				}
				return (bool)_requestedExecutionLevelUIAccess;
			}
		}

		public bool Application => (ManifestFlags & 4) != 0;

		public bool UseManifestForTrust => (ManifestFlags & 8) != 0;

		public Description Description
		{
			get
			{
				if (_description == null && _cms != null)
				{
					System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry metadataSectionEntry = (System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry)_cms.MetadataSectionEntry;
					System.Deployment.Internal.Isolation.Manifest.IDescriptionMetadataEntry descriptionData = metadataSectionEntry.DescriptionData;
					if (descriptionData != null)
					{
						Description value = new Description(descriptionData.AllData);
						Interlocked.CompareExchange(ref _description, value, null);
					}
				}
				return (Description)_description;
			}
		}

		public Deployment Deployment
		{
			get
			{
				if (_deployment == null && _cms != null)
				{
					System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry metadataSectionEntry = (System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry)_cms.MetadataSectionEntry;
					System.Deployment.Internal.Isolation.Manifest.IDeploymentMetadataEntry deploymentData = metadataSectionEntry.DeploymentData;
					if (deploymentData != null)
					{
						Deployment value = new Deployment(deploymentData.AllData);
						Interlocked.CompareExchange(ref _deployment, value, null);
					}
				}
				return (Deployment)_deployment;
			}
		}

		public DependentOS DependentOS
		{
			get
			{
				if (_dependentOS == null && _cms != null)
				{
					System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry metadataSectionEntry = (System.Deployment.Internal.Isolation.Manifest.IMetadataSectionEntry)_cms.MetadataSectionEntry;
					System.Deployment.Internal.Isolation.Manifest.IDependentOSMetadataEntry dependentOSData = metadataSectionEntry.DependentOSData;
					if (dependentOSData != null)
					{
						DependentOS value = new DependentOS(dependentOSData.AllData);
						Interlocked.CompareExchange(ref _dependentOS, value, null);
					}
				}
				return (DependentOS)_dependentOS;
			}
		}

		public DependentAssembly[] DependentAssemblies
		{
			get
			{
				if (_dependentAssemblies == null)
				{
					System.Deployment.Internal.Isolation.ISection section = ((_cms != null) ? _cms.AssemblyReferenceSection : null);
					uint num = section?.Count ?? 0;
					DependentAssembly[] array = new DependentAssembly[num];
					if (num != 0)
					{
						uint celtFetched = 0u;
						System.Deployment.Internal.Isolation.Manifest.IAssemblyReferenceEntry[] array2 = new System.Deployment.Internal.Isolation.Manifest.IAssemblyReferenceEntry[num];
						System.Deployment.Internal.Isolation.IEnumUnknown enumUnknown = (System.Deployment.Internal.Isolation.IEnumUnknown)section._NewEnum;
						int errorCode = enumUnknown.Next(num, array2, ref celtFetched);
						Marshal.ThrowExceptionForHR(errorCode);
						if (celtFetched != num)
						{
							throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_IsoEnumFetchNotEqualToCount"));
						}
						for (uint num2 = 0u; num2 < num; num2++)
						{
							array[num2] = new DependentAssembly(array2[num2].AllData);
						}
					}
					Interlocked.CompareExchange(ref _dependentAssemblies, array, null);
				}
				return (DependentAssembly[])_dependentAssemblies;
			}
		}

		public FileAssociation[] FileAssociations
		{
			get
			{
				if (_fileAssociations == null)
				{
					System.Deployment.Internal.Isolation.ISection section = ((_cms != null) ? _cms.FileAssociationSection : null);
					uint num = section?.Count ?? 0;
					FileAssociation[] array = new FileAssociation[num];
					if (num != 0)
					{
						uint celtFetched = 0u;
						System.Deployment.Internal.Isolation.Manifest.IFileAssociationEntry[] array2 = new System.Deployment.Internal.Isolation.Manifest.IFileAssociationEntry[num];
						System.Deployment.Internal.Isolation.IEnumUnknown enumUnknown = (System.Deployment.Internal.Isolation.IEnumUnknown)section._NewEnum;
						int errorCode = enumUnknown.Next(num, array2, ref celtFetched);
						Marshal.ThrowExceptionForHR(errorCode);
						if (celtFetched != num)
						{
							throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_IsoEnumFetchNotEqualToCount"));
						}
						for (uint num2 = 0u; num2 < num; num2++)
						{
							array[num2] = new FileAssociation(array2[num2].AllData);
						}
					}
					Interlocked.CompareExchange(ref _fileAssociations, array, null);
				}
				return (FileAssociation[])_fileAssociations;
			}
		}

		public File[] Files
		{
			get
			{
				if (_files == null)
				{
					System.Deployment.Internal.Isolation.ISection section = ((_cms != null) ? _cms.FileSection : null);
					uint num = section?.Count ?? 0;
					File[] array = new File[num];
					if (num != 0)
					{
						uint celtFetched = 0u;
						System.Deployment.Internal.Isolation.Manifest.IFileEntry[] array2 = new System.Deployment.Internal.Isolation.Manifest.IFileEntry[num];
						System.Deployment.Internal.Isolation.IEnumUnknown enumUnknown = (System.Deployment.Internal.Isolation.IEnumUnknown)section._NewEnum;
						int errorCode = enumUnknown.Next(num, array2, ref celtFetched);
						Marshal.ThrowExceptionForHR(errorCode);
						if (celtFetched != num)
						{
							throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_IsoEnumFetchNotEqualToCount"));
						}
						for (uint num2 = 0u; num2 < num; num2++)
						{
							array[num2] = new File(array2[num2].AllData);
						}
					}
					Interlocked.CompareExchange(ref _files, array, null);
				}
				return (File[])_files;
			}
		}

		public EntryPoint[] EntryPoints
		{
			get
			{
				if (_entryPoints == null)
				{
					System.Deployment.Internal.Isolation.ISection section = ((_cms != null) ? _cms.EntryPointSection : null);
					uint num = section?.Count ?? 0;
					EntryPoint[] array = new EntryPoint[num];
					if (num != 0)
					{
						uint celtFetched = 0u;
						System.Deployment.Internal.Isolation.Manifest.IEntryPointEntry[] array2 = new System.Deployment.Internal.Isolation.Manifest.IEntryPointEntry[num];
						System.Deployment.Internal.Isolation.IEnumUnknown enumUnknown = (System.Deployment.Internal.Isolation.IEnumUnknown)section._NewEnum;
						int errorCode = enumUnknown.Next(num, array2, ref celtFetched);
						Marshal.ThrowExceptionForHR(errorCode);
						if (celtFetched != num)
						{
							throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_IsoEnumFetchNotEqualToCount"));
						}
						for (uint num2 = 0u; num2 < num; num2++)
						{
							array[num2] = new EntryPoint(array2[num2].AllData, this);
						}
					}
					Interlocked.CompareExchange(ref _entryPoints, array, null);
				}
				return (EntryPoint[])_entryPoints;
			}
		}

		public DependentAssembly MainDependentAssembly => DependentAssemblies[0];

		public bool RequiredHashMissing
		{
			get
			{
				if (!_unhashedDependencyPresent)
				{
					return _unhashedFilePresent;
				}
				return true;
			}
		}

		public bool Signed => _signed;

		public ManifestSourceFormat ManifestSourceFormat => _manifestSourceFormat;

		public AssemblyManifest(FileStream fileStream)
		{
			LoadCMSFromStream(fileStream);
			_rawXmlFilePath = fileStream.Name;
			_manifestSourceFormat = ManifestSourceFormat.XmlFile;
			_sizeInBytes = (ulong)fileStream.Length;
		}

		public AssemblyManifest(Stream stream)
		{
			LoadCMSFromStream(stream);
			_manifestSourceFormat = ManifestSourceFormat.Stream;
			_sizeInBytes = (ulong)stream.Length;
		}

		public AssemblyManifest(string filePath)
		{
			string extension = Path.GetExtension(filePath);
			StringComparison comparisonType = StringComparison.InvariantCultureIgnoreCase;
			if (extension.Equals(".application", comparisonType) || extension.Equals(".manifest", comparisonType))
			{
				LoadFromRawXmlFile(filePath);
			}
			else if (extension.Equals(".dll", comparisonType) || extension.Equals(".exe", comparisonType))
			{
				LoadFromInternalManifestFile(filePath);
			}
			else
			{
				LoadFromUnknownFormatFile(filePath);
			}
		}

		public AssemblyManifest(System.Deployment.Internal.Isolation.Manifest.ICMS cms)
		{
			if (cms == null)
			{
				throw new ArgumentNullException("cms");
			}
			_cms = cms;
		}

		public void ValidateSemantics(ManifestType manifestType)
		{
			switch (manifestType)
			{
			case ManifestType.Deployment:
				ValidateSemanticsForDeploymentRole();
				break;
			case ManifestType.Application:
				ValidateSemanticsForApplicationRole();
				break;
			}
		}

		public File[] GetFilesInGroup(string group, bool optionalOnly)
		{
			StringComparison comparisonType = StringComparison.InvariantCultureIgnoreCase;
			ArrayList arrayList = new ArrayList();
			File[] files = Files;
			foreach (File file in files)
			{
				if ((group == null && !file.IsOptional) || (group != null && group.Equals(file.Group, comparisonType) && (file.IsOptional || !optionalOnly)))
				{
					arrayList.Add(file);
				}
			}
			return (File[])arrayList.ToArray(typeof(File));
		}

		private static bool IsResourceReference(DependentAssembly dependentAssembly)
		{
			if (dependentAssembly.ResourceFallbackCulture != null && dependentAssembly.Identity != null && dependentAssembly.Identity.Culture == null)
			{
				return true;
			}
			return false;
		}

		public DependentAssembly[] GetPrivateAssembliesInGroup(string group, bool optionalOnly)
		{
			StringComparison comparisonType = StringComparison.InvariantCultureIgnoreCase;
			Hashtable hashtable = new Hashtable();
			DependentAssembly[] dependentAssemblies = DependentAssemblies;
			foreach (DependentAssembly dependentAssembly in dependentAssemblies)
			{
				if (!dependentAssembly.IsPreRequisite && ((group == null && !dependentAssembly.IsOptional) || (group != null && group.Equals(dependentAssembly.Group, comparisonType) && (dependentAssembly.IsOptional || !optionalOnly))))
				{
					DependentAssembly dependentAssembly2 = null;
					if (IsResourceReference(dependentAssembly))
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_SatelliteResourcesNotSupported"));
					}
					dependentAssembly2 = dependentAssembly;
					if (dependentAssembly2 != null && !hashtable.Contains(dependentAssembly2.Identity))
					{
						hashtable.Add(dependentAssembly2.Identity, dependentAssembly2);
					}
				}
			}
			DependentAssembly[] array = new DependentAssembly[hashtable.Count];
			hashtable.Values.CopyTo(array, 0);
			return array;
		}

		public DependentAssembly GetDependentAssemblyByIdentity(System.Deployment.Internal.Isolation.IReferenceIdentity refid)
		{
			object ppUnknown = null;
			try
			{
				System.Deployment.Internal.Isolation.ISectionWithReferenceIdentityKey sectionWithReferenceIdentityKey = (System.Deployment.Internal.Isolation.ISectionWithReferenceIdentityKey)_cms.AssemblyReferenceSection;
				sectionWithReferenceIdentityKey.Lookup(refid, out ppUnknown);
			}
			catch (ArgumentException)
			{
				return null;
			}
			System.Deployment.Internal.Isolation.Manifest.IAssemblyReferenceEntry assemblyReferenceEntry = (System.Deployment.Internal.Isolation.Manifest.IAssemblyReferenceEntry)ppUnknown;
			return new DependentAssembly(assemblyReferenceEntry.AllData);
		}

		public File GetFileFromName(string fileName)
		{
			object ppUnknown = null;
			try
			{
				System.Deployment.Internal.Isolation.ISectionWithStringKey sectionWithStringKey = (System.Deployment.Internal.Isolation.ISectionWithStringKey)_cms.FileSection;
				sectionWithStringKey.Lookup(fileName, out ppUnknown);
			}
			catch (ArgumentException)
			{
				return null;
			}
			System.Deployment.Internal.Isolation.Manifest.IFileEntry fileEntry = (System.Deployment.Internal.Isolation.Manifest.IFileEntry)ppUnknown;
			return new File(fileEntry.AllData);
		}

		public ulong CalculateDependenciesSize()
		{
			ulong num = 0uL;
			File[] filesInGroup = GetFilesInGroup(null, optionalOnly: true);
			File[] array = filesInGroup;
			foreach (File file in array)
			{
				num += file.Size;
			}
			DependentAssembly[] privateAssembliesInGroup = GetPrivateAssembliesInGroup(null, optionalOnly: true);
			DependentAssembly[] array2 = privateAssembliesInGroup;
			foreach (DependentAssembly dependentAssembly in array2)
			{
				num += dependentAssembly.Size;
			}
			return num;
		}

		private void LoadCMSFromStream(Stream stream)
		{
			System.Deployment.Internal.Isolation.Manifest.ICMS iCMS = null;
			ManifestParseErrors manifestParseErrors = new ManifestParseErrors();
			int num;
			try
			{
				num = (int)stream.Length;
				_rawXmlBytes = new byte[num];
				if (stream.CanSeek)
				{
					stream.Seek(0L, SeekOrigin.Begin);
				}
				stream.Read(_rawXmlBytes, 0, num);
			}
			catch (IOException innerException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, Resources.GetString("Ex_ManifestReadException"), innerException);
			}
			try
			{
				iCMS = (System.Deployment.Internal.Isolation.Manifest.ICMS)System.Deployment.Internal.Isolation.IsolationInterop.CreateCMSFromXml(_rawXmlBytes, (uint)num, manifestParseErrors, ref System.Deployment.Internal.Isolation.IsolationInterop.IID_ICMS);
			}
			catch (COMException innerException2)
			{
				StringBuilder stringBuilder = new StringBuilder();
				foreach (ManifestParseErrors.ManifestParseError item in manifestParseErrors)
				{
					stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestParseCMSErrorMessage"), item.hr, item.StartLine, item.nStartColumn, item.ErrorStatusHostFile);
				}
				throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestCMSParsingException"), stringBuilder.ToString()), innerException2);
			}
			catch (SEHException innerException3)
			{
				StringBuilder stringBuilder2 = new StringBuilder();
				foreach (ManifestParseErrors.ManifestParseError item2 in manifestParseErrors)
				{
					stringBuilder2.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestParseCMSErrorMessage"), item2.hr, item2.StartLine, item2.nStartColumn, item2.ErrorStatusHostFile);
				}
				throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestCMSParsingException"), stringBuilder2.ToString()), innerException3);
			}
			catch (ArgumentException innerException4)
			{
				StringBuilder stringBuilder3 = new StringBuilder();
				foreach (ManifestParseErrors.ManifestParseError item3 in manifestParseErrors)
				{
					stringBuilder3.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestParseCMSErrorMessage"), item3.hr, item3.StartLine, item3.nStartColumn, item3.ErrorStatusHostFile);
				}
				throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestCMSParsingException"), stringBuilder3.ToString()), innerException4);
			}
			if (iCMS == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, Resources.GetString("Ex_IsoNullCmsCreated"));
			}
			_cms = iCMS;
		}

		private void LoadFromRawXmlFile(string filePath)
		{
			using FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
			LoadCMSFromStream(fileStream);
			_rawXmlFilePath = filePath;
			_manifestSourceFormat = ManifestSourceFormat.XmlFile;
			_sizeInBytes = (ulong)fileStream.Length;
		}

		private bool LoadFromPEResources(string filePath)
		{
			byte[] array = null;
			try
			{
				array = SystemUtils.GetManifestFromPEResources(filePath);
			}
			catch (Win32Exception exception)
			{
				ManifestLoadExceptionHelper(exception, filePath);
			}
			if (array != null)
			{
				using (MemoryStream stream = new MemoryStream(array))
				{
					LoadCMSFromStream(stream);
				}
				_id1Identity = (DefinitionIdentity)Identity.Clone();
				_id1RequestedExecutionLevel = RequestedExecutionLevel;
				_manifestSourceFormat = ManifestSourceFormat.ID_1;
				return true;
			}
			return false;
		}

		private static DefinitionIdentity ExtractIdentityFromCompLibAssembly(string filePath)
		{
			try
			{
				using AssemblyMetaDataImport assemblyMetaDataImport = new AssemblyMetaDataImport(filePath);
				_ = assemblyMetaDataImport.Name;
				return SystemUtils.GetDefinitionIdentityFromManagedAssembly(filePath);
			}
			catch (BadImageFormatException)
			{
				return null;
			}
			catch (COMException)
			{
				return null;
			}
			catch (SEHException)
			{
				return null;
			}
		}

		private bool LoadFromCompLibAssembly(string filePath)
		{
			try
			{
				using AssemblyMetaDataImport assemblyMetaDataImport = new AssemblyMetaDataImport(filePath);
				_ = assemblyMetaDataImport.Name;
				_identity = SystemUtils.GetDefinitionIdentityFromManagedAssembly(filePath);
				_complibIdentity = (DefinitionIdentity)Identity.Clone();
				AssemblyModule[] files = assemblyMetaDataImport.Files;
				AssemblyReference[] references = assemblyMetaDataImport.References;
				File[] array = new File[files.Length + 1];
				array[0] = new File(Path.GetFileName(filePath), 0uL);
				for (int i = 0; i < files.Length; i++)
				{
					array[i + 1] = new File(files[i].Name, files[i].Hash, 0uL);
				}
				_files = array;
				DependentAssembly[] array2 = new DependentAssembly[references.Length];
				for (int j = 0; j < references.Length; j++)
				{
					array2[j] = new DependentAssembly(new ReferenceIdentity(references[j].Name.ToString()));
				}
				_dependentAssemblies = array2;
				_manifestSourceFormat = ManifestSourceFormat.CompLib;
				return true;
			}
			catch (BadImageFormatException)
			{
				return false;
			}
			catch (COMException)
			{
				return false;
			}
			catch (SEHException)
			{
				return false;
			}
			catch (IOException)
			{
				return false;
			}
		}

		private void LoadFromInternalManifestFile(string filePath)
		{
			byte[] array = null;
			PEStream pEStream = null;
			MemoryStream memoryStream = null;
			AssemblyManifest assemblyManifest = null;
			bool flag = true;
			try
			{
				pEStream = new PEStream(filePath, partialConstruct: true);
				array = pEStream.GetDefaultId1ManifestResource();
				if (array != null)
				{
					memoryStream = new MemoryStream(array);
					assemblyManifest = new AssemblyManifest(memoryStream);
					_id1ManifestPresent = true;
				}
				flag = pEStream.IsImageFileDll;
			}
			catch (IOException exception)
			{
				ManifestLoadExceptionHelper(exception, filePath);
			}
			catch (Win32Exception exception2)
			{
				ManifestLoadExceptionHelper(exception2, filePath);
			}
			catch (InvalidDeploymentException exception3)
			{
				ManifestLoadExceptionHelper(exception3, filePath);
			}
			finally
			{
				pEStream?.Close();
				memoryStream?.Close();
			}
			if (assemblyManifest != null)
			{
				if (!assemblyManifest.Identity.IsEmpty)
				{
					if (!LoadFromPEResources(filePath))
					{
						ManifestLoadExceptionHelper(new DeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_CannotLoadInternalManifest")), filePath);
					}
					_complibIdentity = ExtractIdentityFromCompLibAssembly(filePath);
				}
				else if (!flag)
				{
					if (!LoadFromCompLibAssembly(filePath))
					{
						ManifestLoadExceptionHelper(new DeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_CannotLoadInternalManifest")), filePath);
					}
					_id1Identity = assemblyManifest.Identity;
					_id1RequestedExecutionLevel = assemblyManifest.RequestedExecutionLevel;
				}
				else
				{
					ManifestLoadExceptionHelper(new DeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_EmptyIdentityInternalManifest")), filePath);
				}
			}
			else if (!LoadFromCompLibAssembly(filePath))
			{
				ManifestLoadExceptionHelper(new DeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_CannotLoadInternalManifest")), filePath);
			}
		}

		private void LoadFromUnknownFormatFile(string filePath)
		{
			try
			{
				LoadFromRawXmlFile(filePath);
			}
			catch (InvalidDeploymentException ex)
			{
				if (ex.SubType == ExceptionTypes.ManifestParse || ex.SubType == ExceptionTypes.ManifestSemanticValidation)
				{
					LoadFromInternalManifestFile(filePath);
					return;
				}
				throw;
			}
		}

		internal void ValidateSignature(Stream s)
		{
			if (string.Equals(Identity.PublicKeyToken, "0000000000000000", StringComparison.Ordinal) && !PolicyKeys.RequireSignedManifests())
			{
				Logger.AddWarningInformation(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UnsignedManifest")));
				_signed = false;
				return;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			if (s != null)
			{
				xmlDocument.Load(s);
			}
			else
			{
				xmlDocument.Load(_rawXmlFilePath);
			}
			try
			{
				System.Deployment.Internal.CodeSigning.SignedCmiManifest signedCmiManifest = new System.Deployment.Internal.CodeSigning.SignedCmiManifest(xmlDocument);
				signedCmiManifest.Verify(System.Deployment.Internal.CodeSigning.CmiManifestVerifyFlags.StrongNameOnly);
			}
			catch (CryptographicException innerException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.SignatureValidation, Resources.GetString("Ex_InvalidXmlSignature"), innerException);
			}
			if (RequiredHashMissing)
			{
				throw new InvalidDeploymentException(ExceptionTypes.SignatureValidation, Resources.GetString("Ex_SignedManifestUnhashedComponent"));
			}
			_signed = true;
		}

		internal static void ReValidateManifestSignatures(AssemblyManifest depManifest, AssemblyManifest appManifest)
		{
			if (depManifest.Signed && !appManifest.Signed)
			{
				throw new InvalidDeploymentException(ExceptionTypes.SignatureValidation, Resources.GetString("Ex_DepSignedAppUnsigned"));
			}
			if (!depManifest.Signed && appManifest.Signed)
			{
				throw new InvalidDeploymentException(ExceptionTypes.SignatureValidation, Resources.GetString("Ex_AppSignedDepUnsigned"));
			}
		}

		internal void ValidateSemanticsForDeploymentRole()
		{
			try
			{
				ValidateAssemblyIdentity(Identity);
				if (Identity.PublicKeyToken == null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepNotStronglyNamed"));
				}
				if (!PlatformDetector.IsSupportedProcessorArchitecture(Identity.ProcessorArchitecture))
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepProcArchNotSupported"));
				}
				if (Deployment == null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepMissingDeploymentSection"));
				}
				if (UseManifestForTrust)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepWithUseManifestForTrust"));
				}
				if (Description == null || string.IsNullOrEmpty(Description.FilteredPublisher) || string.IsNullOrEmpty(Description.FilteredProduct))
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepPublisherProductRequired"));
				}
				if (Description.FilteredPublisher.Length + Description.FilteredProduct.Length > 260)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_PublisherProductNameTooLong"));
				}
				if (EntryPoints.Length != 0)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepEntryPointNotAllowed"));
				}
				if (Files.Length != 0)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepFileNotAllowed"));
				}
				if (FileAssociations.Length > 0)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepFileAssocNotAllowed"));
				}
				if (Description.IconFile != null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepIconFileNotAllowed"));
				}
				if (Deployment.DisallowUrlActivation && !Deployment.Install)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepOnlineOnlyAndDisallowUrlActivation"));
				}
				if (Deployment.DisallowUrlActivation && Deployment.TrustURLParameters)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepTrustUrlAndDisallowUrlActivation"));
				}
				if (Deployment.Install)
				{
					if (Deployment.ProviderCodebaseUri != null)
					{
						if (!Deployment.ProviderCodebaseUri.IsAbsoluteUri)
						{
							throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepProviderNotAbsolute"));
						}
						if (!UriHelper.IsSupportedScheme(Deployment.ProviderCodebaseUri))
						{
							throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepProviderNotSupportedUriScheme"));
						}
						if (Deployment.ProviderCodebaseUri.AbsoluteUri.Length > 16384)
						{
							throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepProviderTooLong"));
						}
					}
					if (Deployment.MinimumRequiredVersion != null && Deployment.MinimumRequiredVersion > Identity.Version)
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_MinimumRequiredVersionExceedDeployment"));
					}
				}
				else if (Deployment.MinimumRequiredVersion != null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepNoMinVerForOnlineApps"));
				}
				if (DependentAssemblies.Length != 1)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepApplicationDependencyRequired"));
				}
				ValidateApplicationDependency(DependentAssemblies[0]);
				if (DependentAssemblies[0].HashCollection.Count == 0)
				{
					_unhashedDependencyPresent = true;
				}
				if (Deployment.DeploymentUpdate.BeforeApplicationStartup && Deployment.DeploymentUpdate.MaximumAgeSpecified)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepBeforeStartupMaxAgeBothPresent"));
				}
				if (Deployment.DeploymentUpdate.MaximumAgeSpecified && Deployment.DeploymentUpdate.MaximumAgeAllowed > TimeSpan.FromDays(365.0))
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_MaxAgeTooLarge"));
				}
			}
			catch (InvalidDeploymentException innerException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_SemanticallyInvalidDeploymentManifest"), innerException);
			}
		}

		internal void ValidateSemanticsForApplicationRole()
		{
			try
			{
				ValidateAssemblyIdentity(Identity);
				if (EntryPoints.Length != 1)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppOneEntryPoint"));
				}
				EntryPoint entryPoint = EntryPoints[0];
				if (!entryPoint.CustomHostSpecified && (entryPoint.Assembly == null || entryPoint.Assembly.IsOptional || entryPoint.Assembly.IsPreRequisite || entryPoint.Assembly.Codebase == null || !UriHelper.IsValidRelativeFilePath(entryPoint.Assembly.Codebase) || UriHelper.PathContainDirectorySeparators(entryPoint.Assembly.Codebase) || !UriHelper.IsValidRelativeFilePath(entryPoint.CommandFile) || UriHelper.PathContainDirectorySeparators(entryPoint.CommandFile) || !entryPoint.CommandFile.Equals(entryPoint.Assembly.Codebase, StringComparison.OrdinalIgnoreCase) || string.Compare(Identity.ProcessorArchitecture, entryPoint.Assembly.Identity.ProcessorArchitecture, StringComparison.OrdinalIgnoreCase) != 0))
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppInvalidEntryPoint"));
				}
				if (Application && entryPoint.CommandParameters != null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppInvalidEntryPointParameters"));
				}
				if (DependentAssemblies == null || DependentAssemblies.Length == 0)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppAtLeastOneDependency"));
				}
				if (Deployment != null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppNoDeploymentAllowed"));
				}
				if (UseManifestForTrust)
				{
					if (Description == null || (Description != null && (Description.Publisher == null || Description.Product == null)))
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppNoOverridePublisherProduct"));
					}
				}
				else if (Description != null && (Description.Publisher != null || Description.Product != null))
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppNoPublisherProductAllowed"));
				}
				if (Description != null && Description.IconFile != null && !UriHelper.IsValidRelativeFilePath(Description.IconFile))
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_AppInvalidIconFile"));
				}
				if (Description != null && Description.SupportUri != null)
				{
					if (!Description.SupportUri.IsAbsoluteUri)
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DescriptionSupportUrlNotAbsolute"));
					}
					if (!UriHelper.IsSupportedScheme(Description.SupportUri))
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DescriptionSupportUrlNotSupportedUriScheme"));
					}
					if (Description.SupportUri.AbsoluteUri.Length > 16384)
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DescriptionSupportUrlTooLong"));
					}
				}
				if (Files.Length > 24576)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_TooManyFilesInManifest"));
				}
				Hashtable hashtable = new Hashtable();
				File[] files = Files;
				foreach (File file in files)
				{
					ValidateFile(file);
					if (!file.IsOptional && !hashtable.Contains(file.Name))
					{
						hashtable.Add(file.Name.ToLower(), file);
					}
					if (file.HashCollection.Count == 0)
					{
						_unhashedFilePresent = true;
					}
				}
				if (FileAssociations.Length > 0 && entryPoint.HostInBrowser)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_FileAssociationNotSupportedForHostInBrowser"));
				}
				if (FileAssociations.Length > 0 && entryPoint.CustomHostSpecified)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_FileAssociationNotSupportedForCustomHost"));
				}
				if (FileAssociations.Length > 8)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_TooManyFileAssociationsInManifest"), 8));
				}
				Hashtable hashtable2 = new Hashtable();
				FileAssociation[] fileAssociations = FileAssociations;
				foreach (FileAssociation fileAssociation in fileAssociations)
				{
					if (string.IsNullOrEmpty(fileAssociation.Extension) || string.IsNullOrEmpty(fileAssociation.Description) || string.IsNullOrEmpty(fileAssociation.ProgID) || string.IsNullOrEmpty(fileAssociation.DefaultIcon))
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_FileExtensionInfoMissing"));
					}
					if (fileAssociation.Extension.Length > 0)
					{
						char c = fileAssociation.Extension[0];
						if (c != '.')
						{
							throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileAssociationExtensionNoDot"), fileAssociation.Extension));
						}
					}
					string path = "file" + fileAssociation.Extension;
					if (!UriHelper.IsValidRelativeFilePath(path))
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileAssociationInvalid"), fileAssociation.Extension));
					}
					if (fileAssociation.Extension.Length > 24)
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileExtensionTooLong"), fileAssociation.Extension));
					}
					if (!hashtable.Contains(fileAssociation.DefaultIcon.ToLower()))
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileAssociationIconFileNotFound"), fileAssociation.DefaultIcon));
					}
					if (hashtable2.Contains(fileAssociation.Extension))
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_MultipleInstanceFileExtension"), fileAssociation.Extension));
					}
					hashtable2.Add(fileAssociation.Extension, fileAssociation);
				}
				if (DependentAssemblies.Length > 24576)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_TooManyAssembliesInManifest"));
				}
				bool flag = false;
				DependentAssembly[] dependentAssemblies = DependentAssemblies;
				foreach (DependentAssembly dependentAssembly in dependentAssemblies)
				{
					ValidateComponentDependency(dependentAssembly);
					if (dependentAssembly.IsPreRequisite && PlatformDetector.IsCLRDependencyText(dependentAssembly.Identity.Name))
					{
						flag = true;
					}
					if (!dependentAssembly.IsPreRequisite && dependentAssembly.HashCollection.Count == 0)
					{
						_unhashedDependencyPresent = true;
					}
				}
				if (DependentOS != null && DependentOS.SupportUrl != null)
				{
					if (!DependentOS.SupportUrl.IsAbsoluteUri)
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepenedentOSSupportUrlNotAbsolute"));
					}
					if (!UriHelper.IsSupportedScheme(DependentOS.SupportUrl))
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepenedentOSSupportUrlNotSupportedUriScheme"));
					}
					if (DependentOS.SupportUrl.AbsoluteUri.Length > 16384)
					{
						throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_DepenedentOSSupportUrlTooLong"));
					}
				}
				if (!flag)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_AppNoCLRDependency")));
				}
			}
			catch (InvalidDeploymentException innerException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_SemanticallyInvalidApplicationManifest"), innerException);
			}
		}

		internal static CertificateStatus AnalyzeManifestCertificate(string manifestPath)
		{
			CertificateStatus result = CertificateStatus.UnknownCertificateStatus;
			System.Deployment.Internal.CodeSigning.SignedCmiManifest signedCmiManifest = null;
			try
			{
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.PreserveWhitespace = true;
				xmlDocument.Load(manifestPath);
				signedCmiManifest = new System.Deployment.Internal.CodeSigning.SignedCmiManifest(xmlDocument);
				signedCmiManifest.Verify(System.Deployment.Internal.CodeSigning.CmiManifestVerifyFlags.None);
				if (signedCmiManifest == null || signedCmiManifest.AuthenticodeSignerInfo == null)
				{
					result = CertificateStatus.NoCertificate;
					return result;
				}
				result = CertificateStatus.TrustedPublisher;
				return result;
			}
			catch (Exception ex)
			{
				if (ex is CryptographicException)
				{
					if (signedCmiManifest.AuthenticodeSignerInfo != null)
					{
						return signedCmiManifest.AuthenticodeSignerInfo.ErrorCode switch
						{
							-2146762479 => CertificateStatus.DistrustedPublisger, 
							-2146885616 => CertificateStatus.RevokedCertificate, 
							-2146762748 => CertificateStatus.AuthenticodedNotInTrustedList, 
							_ => CertificateStatus.NoCertificate, 
						};
					}
					return result;
				}
				return result;
			}
		}

		private static void ValidateAssemblyIdentity(DefinitionIdentity identity)
		{
			if (identity.Name != null && (identity.Name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || identity.Name.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || identity.Name.IndexOfAny(SpecificInvalidIdentityChars) >= 0))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_IdentityWithInvalidChars"), identity.Name));
			}
			try
			{
				if (identity.ToString().Length > 2048)
				{
					throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_IdentityTooLong"));
				}
			}
			catch (COMException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_IdentityIsNotValid"));
			}
			catch (SEHException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_IdentityIsNotValid"));
			}
		}

		private static void ValidateAssemblyIdentity(ReferenceIdentity identity)
		{
			if (identity.Name != null && (identity.Name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || identity.Name.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || identity.Name.IndexOfAny(SpecificInvalidIdentityChars) >= 0))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_IdentityWithInvalidChars"), identity.Name));
			}
			try
			{
				if (identity.ToString().Length > 2048)
				{
					throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_IdentityTooLong"));
				}
			}
			catch (COMException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_IdentityIsNotValid"));
			}
			catch (SEHException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_IdentityIsNotValid"));
			}
		}

		private void ValidateApplicationDependency(DependentAssembly da)
		{
			ValidateAssemblyIdentity(da.Identity);
			if (da.Identity.PublicKeyToken == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_DepAppRefNotStrongNamed"));
			}
			if (IsInvalidHash(da.HashCollection))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_DepAppRefHashInvalid"));
			}
			if (string.Compare(Identity.ProcessorArchitecture, da.Identity.ProcessorArchitecture, StringComparison.OrdinalIgnoreCase) != 0)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DepAppRefProcArchMismatched"), da.Identity.ProcessorArchitecture, Identity.ProcessorArchitecture));
			}
			if (da.ResourceFallbackCulture != null || da.IsPreRequisite || da.IsOptional)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_DepAppRefPrereqOrOptionalOrResourceFallback"));
			}
			Uri uri = null;
			try
			{
				uri = new Uri(da.Codebase, UriKind.RelativeOrAbsolute);
			}
			catch (UriFormatException innerException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_DepAppRefInvalidCodebaseUri"), innerException);
			}
			if (uri.IsAbsoluteUri && !UriHelper.IsSupportedScheme(uri))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, Resources.GetString("Ex_DepAppRefInvalidCodebaseUri"));
			}
			if (!UriHelper.IsValidRelativeFilePath(da.Identity.Name) || UriHelper.PathContainDirectorySeparators(da.Identity.Name))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DepAppRefInvalidIdentityName"), da.Identity.Name));
			}
		}

		private static void ValidateComponentDependency(DependentAssembly da)
		{
			ValidateAssemblyIdentity(da.Identity);
			if (!da.IsPreRequisite)
			{
				if (da.ResourceFallbackCulture == null)
				{
					if (IsInvalidHash(da.HashCollection))
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyInvalidHash"), da.Identity.ToString()));
					}
					if (da.Codebase == null)
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyNoCodebase"), da.Identity.ToString()));
					}
					if (!UriHelper.IsValidRelativeFilePath(da.Codebase))
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyNotRelativePath"), da.Identity.ToString()));
					}
					if (da.IsOptional && da.Group == null)
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyOptionalButNoGroup"), da.Identity.ToString()));
					}
				}
				else if (da.Identity.Culture == null)
				{
					if (da.Codebase != null)
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyResourceWithCodebase"), da.Identity.ToString()));
					}
					if (da.HashCollection.Count > 0)
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyResourceWithHash"), da.Identity.ToString()));
					}
				}
				else
				{
					if (IsInvalidHash(da.HashCollection))
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyInvalidHash"), da.Identity.ToString()));
					}
					if (da.Codebase == null)
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyNoCodebase"), da.Identity.ToString()));
					}
					if (!UriHelper.IsValidRelativeFilePath(da.Codebase))
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyNotRelativePath"), da.Identity.ToString()));
					}
					if (da.ResourceFallbackCulture != null)
					{
						throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyResourceWithFallback"), da.Identity.ToString()));
					}
				}
			}
			else if (!PlatformDetector.IsCLRDependencyText(da.Identity.Name) && da.Identity.PublicKeyToken == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencyGACNoPKT"), da.Identity.ToString()));
			}
			if (da.SupportUrl != null)
			{
				if (!da.SupportUrl.IsAbsoluteUri)
				{
					throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencySupportUrlNoAbsolute"), da.Identity.ToString()));
				}
				if (!UriHelper.IsSupportedScheme(da.SupportUrl))
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencySupportUrlNotSupportedUriScheme"), da.Identity.ToString()));
				}
				if (da.SupportUrl.AbsoluteUri.Length > 16384)
				{
					throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DependencySupportUrlTooLong"), da.Identity.ToString()));
				}
			}
		}

		private static void ValidateFile(File f)
		{
			if (IsInvalidHash(f.HashCollection))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidFileHash"), f.Name));
			}
			if (!UriHelper.IsValidRelativeFilePath(f.Name))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FilePathNotRelative"), f.Name));
			}
			if (f.IsOptional && f.Group == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileOptionalButNoGroup"), f.Name));
			}
			if (f.IsOptional && f.IsData)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestComponentSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileOptionalAndData"), f.Name));
			}
		}

		private static bool IsInvalidHash(HashCollection hashCollection)
		{
			return !ComponentVerifier.IsVerifiableHashCollection(hashCollection);
		}

		internal static Uri UriFromMetadataEntry(string uriString, string exResourceStr)
		{
			try
			{
				return (uriString != null) ? new Uri(uriString) : null;
			}
			catch (UriFormatException innerException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.Manifest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString(exResourceStr), uriString), innerException);
			}
		}

		private static void ManifestLoadExceptionHelper(Exception exception, string filePath)
		{
			string fileName = Path.GetFileName(filePath);
			string message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestLoadFromFile"), fileName);
			throw new InvalidDeploymentException(ExceptionTypes.ManifestLoad, message, exception);
		}
	}
}
namespace System.Deployment.Internal.Isolation
{
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("ace1b703-1aac-4956-ab87-90cac8b93ce6")]
	internal interface IManifestParseErrorCallback
	{
		void OnError([In] uint StartLine, [In] uint nStartColumn, [In] uint cCharacterCount, [In] int hr, [In][MarshalAs(UnmanagedType.LPWStr)] string ErrorStatusHostFile, [In] uint ParameterCount, [In][MarshalAs(UnmanagedType.LPArray)] string[] Parameters);
	}
}
namespace System.Deployment.Application
{
	internal class ComponentStore
	{
		internal class CrossGroupApplicationData
		{
			public enum GroupType
			{
				UndefinedGroup,
				LocationGroup,
				IdentityGroup
			}

			public SubscriptionState SubState;

			public GroupType CrossGroupType;

			public CrossGroupApplicationData(SubscriptionState subState, GroupType groupType)
			{
				SubState = subState;
				CrossGroupType = groupType;
			}
		}

		private enum HostType
		{
			Default,
			AppLaunch,
			CorFlag
		}

		private class StoreTransactionContext : System.Deployment.Internal.Isolation.StoreTransaction
		{
			private object _scavengeContext;

			private ComponentStore _compStore;

			public ScavengeContext ScavengeContext
			{
				get
				{
					if (_scavengeContext == null)
					{
						Interlocked.CompareExchange(ref _scavengeContext, new ScavengeContext(_compStore), null);
					}
					return (ScavengeContext)_scavengeContext;
				}
			}

			public StoreTransactionContext(ComponentStore compStore)
			{
				_compStore = compStore;
			}
		}

		private class ScavengeContext
		{
			private class SubInstance : IComparable
			{
				public SubscriptionState SubState;

				public DateTime LastAccessTime;

				public int CompareTo(object other)
				{
					return ((SubInstance)other).LastAccessTime.CompareTo(LastAccessTime);
				}
			}

			private ComponentStore _compStore;

			private ArrayList _onlineDeploysToPin;

			private ArrayList _onlineDeploysToPinAlreadyPinned;

			private ArrayList _shellVisbleDeploysToUnpin;

			private ArrayList _addinDeploysToUnpin;

			private ArrayList _onlineDeploysToUnpin;

			private ulong _onlineToPinPrivateSizePreTransact;

			private ulong _onlineToPinPrivateSizePostTransact;

			private ulong _shellVisibleToUnpinSharedSize;

			private ulong _onlineToUnpinPrivateSize;

			private ulong _addinToUnpinSharedSize;

			public ScavengeContext(ComponentStore compStore)
			{
				_compStore = compStore;
			}

			public void CheckQuotaAndScavenge()
			{
				ulong onlineAppQuotaInBytes = _compStore.GetOnlineAppQuotaInBytes();
				ulong onlineAppQuotaUsageEstimate = GetOnlineAppQuotaUsageEstimate();
				long num = (long)(_onlineToPinPrivateSizePostTransact - _onlineToPinPrivateSizePreTransact - _onlineToUnpinPrivateSize + _shellVisibleToUnpinSharedSize + _addinToUnpinSharedSize);
				ulong num2;
				if (num >= 0)
				{
					num2 = onlineAppQuotaUsageEstimate + (ulong)num;
					if (num2 < onlineAppQuotaUsageEstimate)
					{
						num2 = ulong.MaxValue;
					}
				}
				else
				{
					num2 = onlineAppQuotaUsageEstimate - (ulong)(-num);
					if (num2 > onlineAppQuotaUsageEstimate)
					{
						num2 = ulong.MaxValue;
					}
				}
				if (num2 > onlineAppQuotaInBytes)
				{
					System.Deployment.Internal.Isolation.IDefinitionAppId[] deployAppIdPtrs;
					SubInstance[] subs = CollectOnlineAppsMRU(out deployAppIdPtrs);
					ulong privateSize = 0uL;
					ulong sharedSize = 0uL;
					if (deployAppIdPtrs.Length > 0)
					{
						_compStore.CalculateDeploymentsUnderQuota(deployAppIdPtrs.Length, deployAppIdPtrs, ulong.MaxValue, ref privateSize, ref sharedSize);
						if (privateSize > onlineAppQuotaInBytes)
						{
							ulong quotaSize = onlineAppQuotaInBytes / 2uL;
							int num3 = _compStore.CalculateDeploymentsUnderQuota(deployAppIdPtrs.Length, deployAppIdPtrs, quotaSize, ref privateSize, ref sharedSize);
							ScavengeAppsOverQuota(subs, deployAppIdPtrs.Length - num3, out var appExcluded);
							if (appExcluded)
							{
								CollectOnlineApps(out deployAppIdPtrs);
								_compStore.CalculateDeploymentsUnderQuota(deployAppIdPtrs.Length, deployAppIdPtrs, ulong.MaxValue, ref privateSize, ref sharedSize);
							}
						}
					}
					num2 = privateSize;
				}
				PersistOnlineAppQuotaUsageEstimate(num2);
			}

			public void AddOnlineAppToCommit(DefinitionAppId appId, SubscriptionState subState)
			{
				DefinitionAppId deployAppId = appId.ToDeploymentAppId();
				AddDeploymentToList(ref _onlineDeploysToPin, deployAppId);
				if (appId.Equals(subState.CurrentBind) || appId.Equals(subState.PreviousBind))
				{
					AddDeploymentToList(ref _onlineDeploysToPinAlreadyPinned, deployAppId);
				}
			}

			public void AddDeploymentToUnpin(DefinitionAppId deployAppId, SubscriptionState subState)
			{
				if (subState.IsShellVisible)
				{
					AddDeploymentToList(ref _shellVisbleDeploysToUnpin, deployAppId);
				}
				else if (subState.appType == AppType.CustomHostSpecified)
				{
					AddDeploymentToList(ref _addinDeploysToUnpin, deployAppId);
				}
				else
				{
					AddDeploymentToList(ref _onlineDeploysToUnpin, deployAppId);
				}
			}

			public void CalculateSizesPreTransact()
			{
				_onlineToPinPrivateSizePreTransact = _compStore.GetPrivateSize(_onlineDeploysToPinAlreadyPinned);
				_onlineToUnpinPrivateSize = _compStore.GetPrivateSize(_onlineDeploysToUnpin);
				_shellVisibleToUnpinSharedSize = _compStore.GetSharedSize(_shellVisbleDeploysToUnpin);
				_addinToUnpinSharedSize = _compStore.GetSharedSize(_addinDeploysToUnpin);
			}

			public void CalculateSizesPostTransact()
			{
				_onlineToPinPrivateSizePostTransact = _compStore.GetPrivateSize(_onlineDeploysToPin);
			}

			public void CleanOnlineAppCache()
			{
				SubInstance[] array = CollectOnlineApps(out var deployAppIdPtrs);
				using (StoreTransactionContext storeTxn = new StoreTransactionContext(_compStore))
				{
					SubInstance[] array2 = array;
					foreach (SubInstance subInstance in array2)
					{
						SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal(subInstance.SubState);
						subscriptionStateInternal.IsInstalled = false;
						_compStore.PrepareFinalizeSubscriptionState(storeTxn, subInstance.SubState, subscriptionStateInternal);
					}
					_compStore.SubmitStoreTransaction(storeTxn, null);
				}
				array = CollectOnlineApps(out deployAppIdPtrs);
				ulong privateSize = 0uL;
				ulong sharedSize = 0uL;
				if (deployAppIdPtrs.Length > 0)
				{
					_compStore.CalculateDeploymentsUnderQuota(deployAppIdPtrs.Length, deployAppIdPtrs, ulong.MaxValue, ref privateSize, ref sharedSize);
				}
				PersistOnlineAppQuotaUsageEstimate(privateSize);
			}

			private static void AddDeploymentToList(ref ArrayList list, DefinitionAppId deployAppId)
			{
				if (list == null)
				{
					list = new ArrayList();
				}
				if (!list.Contains(deployAppId))
				{
					list.Add(deployAppId);
				}
			}

			private SubInstance[] CollectOnlineApps(out System.Deployment.Internal.Isolation.IDefinitionAppId[] deployAppIdPtrs)
			{
				Hashtable hashtable = new Hashtable();
				System.Deployment.Internal.Isolation.StoreAssemblyEnumeration storeAssemblyEnumeration = _compStore._store.EnumAssemblies(System.Deployment.Internal.Isolation.Store.EnumAssembliesFlags.Nothing);
				foreach (System.Deployment.Internal.Isolation.STORE_ASSEMBLY item in storeAssemblyEnumeration)
				{
					DefinitionIdentity definitionIdentity = new DefinitionIdentity(item.DefinitionIdentity);
					DefinitionIdentity definitionIdentity2 = definitionIdentity.ToSubscriptionId();
					SubscriptionState subscriptionState = _compStore._subStore.GetSubscriptionState(definitionIdentity2);
					if (subscriptionState.IsInstalled && !subscriptionState.IsShellVisible && subscriptionState.appType != AppType.CustomHostSpecified && !hashtable.Contains(definitionIdentity2))
					{
						SubInstance subInstance = new SubInstance();
						subInstance.SubState = subscriptionState;
						subInstance.LastAccessTime = subscriptionState.LastCheckTime;
						hashtable.Add(definitionIdentity2, subInstance);
					}
				}
				SubInstance[] array = new SubInstance[hashtable.Count];
				hashtable.Values.CopyTo(array, 0);
				ArrayList arrayList = new ArrayList();
				for (int i = 0; i < array.Length; i++)
				{
					if (array[i].SubState.CurrentBind != null)
					{
						arrayList.Add(array[i].SubState.CurrentBind.ToDeploymentAppId().ComPointer);
					}
					if (array[i].SubState.PreviousBind != null)
					{
						arrayList.Add(array[i].SubState.PreviousBind.ToDeploymentAppId().ComPointer);
					}
				}
				deployAppIdPtrs = (System.Deployment.Internal.Isolation.IDefinitionAppId[])arrayList.ToArray(typeof(System.Deployment.Internal.Isolation.IDefinitionAppId));
				return array;
			}

			private SubInstance[] CollectOnlineAppsMRU(out System.Deployment.Internal.Isolation.IDefinitionAppId[] deployAppIdPtrs)
			{
				Hashtable hashtable = new Hashtable();
				System.Deployment.Internal.Isolation.StoreAssemblyEnumeration storeAssemblyEnumeration = _compStore._store.EnumAssemblies(System.Deployment.Internal.Isolation.Store.EnumAssembliesFlags.Nothing);
				foreach (System.Deployment.Internal.Isolation.STORE_ASSEMBLY item in storeAssemblyEnumeration)
				{
					DefinitionIdentity definitionIdentity = new DefinitionIdentity(item.DefinitionIdentity);
					DefinitionIdentity definitionIdentity2 = definitionIdentity.ToSubscriptionId();
					SubscriptionState subscriptionState = _compStore._subStore.GetSubscriptionState(definitionIdentity2);
					if (subscriptionState.IsInstalled && !subscriptionState.IsShellVisible && subscriptionState.appType != AppType.CustomHostSpecified && !hashtable.Contains(definitionIdentity2))
					{
						SubInstance subInstance = new SubInstance();
						subInstance.SubState = subscriptionState;
						subInstance.LastAccessTime = subscriptionState.LastCheckTime;
						hashtable.Add(definitionIdentity2, subInstance);
					}
				}
				SubInstance[] array = new SubInstance[hashtable.Count];
				hashtable.Values.CopyTo(array, 0);
				Array.Sort(array);
				ArrayList arrayList = new ArrayList();
				for (int i = 0; i < array.Length; i++)
				{
					if (array[i].SubState.CurrentBind != null)
					{
						arrayList.Add(array[i].SubState.CurrentBind.ToDeploymentAppId().ComPointer);
					}
					if (array[i].SubState.PreviousBind != null)
					{
						arrayList.Add(array[i].SubState.PreviousBind.ToDeploymentAppId().ComPointer);
					}
				}
				deployAppIdPtrs = (System.Deployment.Internal.Isolation.IDefinitionAppId[])arrayList.ToArray(typeof(System.Deployment.Internal.Isolation.IDefinitionAppId));
				return array;
			}

			private void ScavengeAppsOverQuota(SubInstance[] subs, int deploysToScavenge, out bool appExcluded)
			{
				appExcluded = false;
				DateTime dateTime = DateTime.UtcNow - Constants.OnlineAppScavengingGracePeriod;
				using StoreTransactionContext storeTxn = new StoreTransactionContext(_compStore);
				int num = subs.Length - 1;
				while (num >= 0 && deploysToScavenge > 0)
				{
					bool flag = false;
					bool flag2 = false;
					if (subs[num].SubState.PreviousBind != null)
					{
						if (subs[num].LastAccessTime >= dateTime)
						{
							appExcluded = true;
						}
						else
						{
							flag = true;
						}
						deploysToScavenge--;
					}
					if (deploysToScavenge > 0)
					{
						if (subs[num].LastAccessTime >= dateTime)
						{
							appExcluded = true;
						}
						else
						{
							flag2 = true;
						}
						deploysToScavenge--;
					}
					if (flag2 || flag)
					{
						SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal(subs[num].SubState);
						if (flag2)
						{
							subscriptionStateInternal.IsInstalled = false;
						}
						else
						{
							subscriptionStateInternal.PreviousBind = null;
						}
						_compStore.PrepareFinalizeSubscriptionState(storeTxn, subs[num].SubState, subscriptionStateInternal);
					}
					num--;
				}
				_compStore.SubmitStoreTransaction(storeTxn, null);
			}

			private ulong GetOnlineAppQuotaUsageEstimate()
			{
				ulong result = ulong.MaxValue;
				using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment");
				if (registryKey != null && registryKey.GetValue("OnlineAppQuotaUsageEstimate") is long num)
				{
					result = (ulong)((num >= 0) ? num : (-1 - -num + 1));
				}
				return result;
			}

			private static void PersistOnlineAppQuotaUsageEstimate(ulong usage)
			{
				using RegistryKey registryKey = Registry.CurrentUser.CreateSubKey("SOFTWARE\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment");
				registryKey?.SetValue("OnlineAppQuotaUsageEstimate", usage, RegistryValueKind.QWord);
			}
		}

		private const string DateTimeFormatString = "yyyy/MM/dd HH:mm:ss";

		private static object _installReference;

		private ComponentStoreType _storeType;

		private System.Deployment.Internal.Isolation.Store _store;

		private System.Deployment.Internal.Isolation.IStateManager _stateMgr;

		private SubscriptionStore _subStore;

		private bool _firstRefresh;

		private System.Deployment.Internal.Isolation.StoreApplicationReference InstallReference
		{
			get
			{
				if (_installReference == null)
				{
					Interlocked.CompareExchange(ref _installReference, new System.Deployment.Internal.Isolation.StoreApplicationReference(System.Deployment.Internal.Isolation.IsolationInterop.GUID_SXS_INSTALL_REFERENCE_SCHEME_OPAQUESTRING, "{3f471841-eef2-47d6-89c0-d028f03a4ad5}", null), null);
				}
				return (System.Deployment.Internal.Isolation.StoreApplicationReference)_installReference;
			}
		}

		public static ComponentStore GetStore(ComponentStoreType storeType, SubscriptionStore subStore)
		{
			return new ComponentStore(storeType, subStore);
		}

		private void RemoveInvalidCDFMSFiles()
		{
			RegistryKey registryKey = null;
			RegistryKey registryKey2 = null;
			RegistryKey registryKey3 = null;
			bool flag = false;
			try
			{
				registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment", writable: true);
				if (registryKey != null)
				{
					registryKey2 = registryKey.OpenSubKey("ClickOnce35SP1Update");
					registryKey3 = registryKey.OpenSubKey("SideBySide\\2.0");
					if (registryKey2 == null && registryKey3 != null)
					{
						string text = registryKey3.GetValue("ComponentStore_RandomString").ToString();
						string searchPattern = text.Substring(0, 8) + "." + text.Substring(8, 3);
						string searchPattern2 = text.Substring(11, 8) + "." + text.Substring(19, 3);
						string text2 = string.Empty;
						DirectoryInfo directoryInfo = new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
						ArrayList arrayList = new ArrayList();
						ArrayList arrayList2 = new ArrayList();
						arrayList2.Add(directoryInfo.Parent);
						arrayList2.Add(directoryInfo);
						foreach (DirectoryInfo item in arrayList2)
						{
							DirectoryInfo[] directories = item.GetDirectories("Apps");
							foreach (DirectoryInfo directoryInfo3 in directories)
							{
								DirectoryInfo[] directories2 = directoryInfo3.GetDirectories("2.0");
								foreach (DirectoryInfo directoryInfo4 in directories2)
								{
									DirectoryInfo[] directories3 = directoryInfo4.GetDirectories(searchPattern);
									foreach (DirectoryInfo directoryInfo5 in directories3)
									{
										DirectoryInfo[] directories4 = directoryInfo5.GetDirectories(searchPattern2);
										foreach (DirectoryInfo directoryInfo6 in directories4)
										{
											arrayList.AddRange(CleanCDFMSFilesInDirectory(directoryInfo6));
											text2 = text2 + directoryInfo6.FullName + "\n";
										}
									}
								}
							}
						}
						foreach (FileInfo item2 in arrayList)
						{
							if (item2.Exists)
							{
								item2.Delete();
							}
						}
						registryKey2 = registryKey.CreateSubKey("ClickOnce35SP1Update");
						if (registryKey2 != null)
						{
							registryKey2.SetValue("Action", "Purged CDF-MS Data");
							registryKey2.SetValue("AppData", directoryInfo.FullName.ToString());
							registryKey2.SetValue("Hits", text2);
						}
						flag = true;
					}
				}
				if (!flag)
				{
					if (registryKey == null)
					{
						registryKey = Registry.CurrentUser.CreateSubKey("SOFTWARE\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment");
					}
					if (registryKey != null && registryKey2 == null)
					{
						registryKey2 = registryKey.CreateSubKey("ClickOnce35SP1Update");
						registryKey2?.SetValue("Action", "No cleanup required");
					}
				}
			}
			catch (Exception)
			{
			}
			finally
			{
				registryKey3?.Close();
				registryKey2?.Close();
				registryKey?.Close();
			}
		}

		private ArrayList CleanCDFMSFilesInDirectory(DirectoryInfo Folder)
		{
			ArrayList arrayList = new ArrayList();
			FileInfo[] files = Folder.GetFiles("*.cdf-ms", SearchOption.AllDirectories);
			foreach (FileInfo fileInfo in files)
			{
				try
				{
					fileInfo.Delete();
				}
				catch (Exception)
				{
				}
				finally
				{
					if (fileInfo.Exists)
					{
						arrayList.Add(fileInfo);
					}
				}
			}
			return arrayList;
		}

		private ComponentStore(ComponentStoreType storeType, SubscriptionStore subStore)
		{
			if (storeType == ComponentStoreType.UserStore)
			{
				_storeType = storeType;
				_subStore = subStore;
				RemoveInvalidCDFMSFiles();
				_store = System.Deployment.Internal.Isolation.IsolationInterop.GetUserStore();
				Guid riid = System.Deployment.Internal.Isolation.IsolationInterop.GetGuidOfType(typeof(System.Deployment.Internal.Isolation.IStateManager));
				_stateMgr = System.Deployment.Internal.Isolation.IsolationInterop.GetUserStateManager(0u, IntPtr.Zero, ref riid) as System.Deployment.Internal.Isolation.IStateManager;
				_firstRefresh = true;
				return;
			}
			throw new NotImplementedException();
		}

		internal ulong GetOnlineAppQuotaInBytes()
		{
			uint num = 256000u;
			using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment"))
			{
				if (registryKey != null)
				{
					object value = registryKey.GetValue("OnlineAppQuotaInKB");
					if (value is int)
					{
						int num2 = (int)value;
						num = (uint)((num2 >= 0) ? num2 : (-1 - -num2 + 1));
					}
				}
			}
			return (ulong)num * 1024uL;
		}

		internal ulong GetPrivateSize(ArrayList deployAppIds)
		{
			GetPrivateAndSharedSizes(deployAppIds, out var privateSize, out var _);
			return privateSize;
		}

		internal ulong GetSharedSize(ArrayList deployAppIds)
		{
			GetPrivateAndSharedSizes(deployAppIds, out var _, out var sharedSize);
			return sharedSize;
		}

		internal ArrayList CollectCrossGroupApplications(Uri codebaseUri, DefinitionIdentity deploymentIdentity, ref bool identityGroupFound, ref bool locationGroupFound, ref string identityGroupProductName)
		{
			Hashtable hashtable = new Hashtable();
			ArrayList arrayList = new ArrayList();
			System.Deployment.Internal.Isolation.StoreAssemblyEnumeration storeAssemblyEnumeration = _store.EnumAssemblies(System.Deployment.Internal.Isolation.Store.EnumAssembliesFlags.Nothing);
			foreach (System.Deployment.Internal.Isolation.STORE_ASSEMBLY item in storeAssemblyEnumeration)
			{
				DefinitionIdentity definitionIdentity = new DefinitionIdentity(item.DefinitionIdentity);
				DefinitionIdentity definitionIdentity2 = definitionIdentity.ToSubscriptionId();
				SubscriptionState subscriptionState = _subStore.GetSubscriptionState(definitionIdentity2);
				if (!subscriptionState.IsInstalled)
				{
					continue;
				}
				bool flag = subscriptionState.DeploymentProviderUri.Equals(codebaseUri);
				bool flag2 = subscriptionState.PKTGroupId.Equals(deploymentIdentity.ToPKTGroupId());
				bool flag3 = subscriptionState.SubscriptionId.PublicKeyToken.Equals(deploymentIdentity.ToSubscriptionId().PublicKeyToken);
				if (flag && flag2 && flag3)
				{
					continue;
				}
				if (flag && flag2 && !flag3)
				{
					if (!hashtable.Contains(definitionIdentity2))
					{
						hashtable.Add(definitionIdentity2, subscriptionState);
						arrayList.Add(new CrossGroupApplicationData(subscriptionState, CrossGroupApplicationData.GroupType.LocationGroup));
						locationGroupFound = true;
					}
				}
				else if (!flag && flag2 && flag3 && !hashtable.Contains(definitionIdentity2))
				{
					hashtable.Add(definitionIdentity2, subscriptionState);
					arrayList.Add(new CrossGroupApplicationData(subscriptionState, CrossGroupApplicationData.GroupType.IdentityGroup));
					if (subscriptionState.CurrentDeploymentManifest != null && subscriptionState.CurrentDeploymentManifest.Description != null && subscriptionState.CurrentDeploymentManifest.Description.Product != null)
					{
						identityGroupProductName = subscriptionState.CurrentDeploymentManifest.Description.Product;
					}
					identityGroupFound = true;
				}
			}
			return arrayList;
		}

		internal void RemoveApplicationInstance(SubscriptionState subState, DefinitionAppId appId)
		{
			using StoreTransactionContext storeTxn = new StoreTransactionContext(this);
			PrepareRemoveDeployment(storeTxn, subState, appId);
			SubmitStoreTransaction(storeTxn, subState);
		}

		private void GetPrivateAndSharedSizes(ArrayList deployAppIds, out ulong privateSize, out ulong sharedSize)
		{
			privateSize = 0uL;
			sharedSize = 0uL;
			if (deployAppIds != null && deployAppIds.Count > 0)
			{
				System.Deployment.Internal.Isolation.IDefinitionAppId[] array = DeployAppIdsToComPtrs(deployAppIds);
				CalculateDeploymentsUnderQuota(array.Length, array, ulong.MaxValue, ref privateSize, ref sharedSize);
			}
		}

		private int CalculateDeploymentsUnderQuota(int numberOfDeployments, System.Deployment.Internal.Isolation.IDefinitionAppId[] deployAppIdPtrs, ulong quotaSize, ref ulong privateSize, ref ulong sharedSize)
		{
			uint Delimiter = 0u;
			System.Deployment.Internal.Isolation.StoreApplicationReference InstallerReference = InstallReference;
			_store.CalculateDelimiterOfDeploymentsBasedOnQuota(0u, (uint)numberOfDeployments, deployAppIdPtrs, ref InstallerReference, quotaSize, ref Delimiter, ref sharedSize, ref privateSize);
			return (int)Delimiter;
		}

		private static System.Deployment.Internal.Isolation.IDefinitionAppId[] DeployAppIdsToComPtrs(ArrayList deployAppIdList)
		{
			System.Deployment.Internal.Isolation.IDefinitionAppId[] array = new System.Deployment.Internal.Isolation.IDefinitionAppId[deployAppIdList.Count];
			for (int i = 0; i < deployAppIdList.Count; i++)
			{
				array[i] = ((DefinitionAppId)deployAppIdList[i]).ComPointer;
			}
			return array;
		}

		public void RefreshStorePointer()
		{
			if (_firstRefresh)
			{
				_firstRefresh = false;
				return;
			}
			if (_storeType == ComponentStoreType.UserStore)
			{
				Marshal.ReleaseComObject(_store.InternalStore);
				Marshal.ReleaseComObject(_stateMgr);
				RemoveInvalidCDFMSFiles();
				_store = System.Deployment.Internal.Isolation.IsolationInterop.GetUserStore();
				Guid riid = System.Deployment.Internal.Isolation.IsolationInterop.GetGuidOfType(typeof(System.Deployment.Internal.Isolation.IStateManager));
				_stateMgr = System.Deployment.Internal.Isolation.IsolationInterop.GetUserStateManager(0u, IntPtr.Zero, ref riid) as System.Deployment.Internal.Isolation.IStateManager;
				return;
			}
			throw new NotImplementedException();
		}

		public void CleanOnlineAppCache()
		{
			using StoreTransactionContext storeTransactionContext = new StoreTransactionContext(this);
			storeTransactionContext.ScavengeContext.CleanOnlineAppCache();
		}

		public void CommitApplication(SubscriptionState subState, CommitApplicationParams commitParams)
		{
			try
			{
				using StoreTransactionContext storeTxn = new StoreTransactionContext(this);
				PrepareCommitApplication(storeTxn, subState, commitParams);
				SubmitStoreTransactionCheckQuota(storeTxn, subState);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				if (ex.ErrorCode == -2147023590)
				{
					throw new DeploymentException(ExceptionTypes.ComponentStore, Resources.GetString("Ex_InplaceUpdateOfApplicationAttempted"), ex);
				}
				throw;
			}
		}

		public void RemoveSubscription(SubscriptionState subState)
		{
			try
			{
				using StoreTransactionContext storeTxn = new StoreTransactionContext(this);
				PrepareRemoveSubscription(storeTxn, subState);
				SubmitStoreTransactionCheckQuota(storeTxn, subState);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				throw;
			}
		}

		public void RollbackSubscription(SubscriptionState subState)
		{
			try
			{
				using StoreTransactionContext storeTxn = new StoreTransactionContext(this);
				PrepareRollbackSubscription(storeTxn, subState);
				SubmitStoreTransactionCheckQuota(storeTxn, subState);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				throw;
			}
		}

		public void SetPendingDeployment(SubscriptionState subState, DefinitionIdentity deployId, DateTime checkTime)
		{
			try
			{
				using StoreTransactionContext storeTxn = new StoreTransactionContext(this);
				PrepareSetPendingDeployment(storeTxn, subState, deployId, checkTime);
				SubmitStoreTransaction(storeTxn, subState);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				throw;
			}
		}

		public void SetUpdateSkipTime(SubscriptionState subState, DefinitionIdentity updateSkippedDeployment, DateTime updateSkipTime)
		{
			try
			{
				using StoreTransactionContext storeTxn = new StoreTransactionContext(this);
				PrepareUpdateSkipTime(storeTxn, subState, updateSkippedDeployment, updateSkipTime);
				SubmitStoreTransaction(storeTxn, subState);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				throw;
			}
		}

		public SubscriptionStateInternal GetSubscriptionStateInternal(SubscriptionState subState)
		{
			return GetSubscriptionStateInternal(subState.SubscriptionId);
		}

		public SubscriptionStateInternal GetSubscriptionStateInternal(DefinitionIdentity subId)
		{
			SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal();
			subscriptionStateInternal.IsInstalled = IsSubscriptionInstalled(subId);
			if (subscriptionStateInternal.IsInstalled)
			{
				DefinitionAppId appId = new DefinitionAppId(subId);
				subscriptionStateInternal.IsShellVisible = GetPropertyBoolean(appId, "IsShellVisible");
				subscriptionStateInternal.CurrentBind = GetPropertyDefinitionAppId(appId, "CurrentBind");
				subscriptionStateInternal.PreviousBind = GetPropertyDefinitionAppId(appId, "PreviousBind");
				subscriptionStateInternal.PendingBind = GetPropertyDefinitionAppId(appId, "PendingBind");
				subscriptionStateInternal.ExcludedDeployment = GetPropertyDefinitionIdentity(appId, "ExcludedDeployment");
				subscriptionStateInternal.PendingDeployment = GetPropertyDefinitionIdentity(appId, "PendingDeployment");
				subscriptionStateInternal.DeploymentProviderUri = GetPropertyUri(appId, "DeploymentProviderUri");
				subscriptionStateInternal.MinimumRequiredVersion = GetPropertyVersion(appId, "MinimumRequiredVersion");
				subscriptionStateInternal.LastCheckTime = GetPropertyDateTime(appId, "LastCheckTime");
				subscriptionStateInternal.UpdateSkippedDeployment = GetPropertyDefinitionIdentity(appId, "UpdateSkippedDeployment");
				subscriptionStateInternal.UpdateSkipTime = GetPropertyDateTime(appId, "UpdateSkipTime");
				subscriptionStateInternal.appType = GetPropertyAppType(appId, "AppType");
				if (subscriptionStateInternal.CurrentBind == null)
				{
					throw new InvalidDeploymentException(Resources.GetString("Ex_NoCurrentBind"));
				}
				subscriptionStateInternal.CurrentDeployment = subscriptionStateInternal.CurrentBind.DeploymentIdentity;
				subscriptionStateInternal.CurrentDeploymentManifest = GetAssemblyManifest(subscriptionStateInternal.CurrentDeployment);
				subscriptionStateInternal.CurrentDeploymentSourceUri = GetPropertyUri(subscriptionStateInternal.CurrentBind, "DeploymentSourceUri");
				subscriptionStateInternal.CurrentApplication = subscriptionStateInternal.CurrentBind.ApplicationIdentity;
				subscriptionStateInternal.CurrentApplicationManifest = GetAssemblyManifest(subscriptionStateInternal.CurrentBind.ApplicationIdentity);
				subscriptionStateInternal.CurrentApplicationSourceUri = GetPropertyUri(subscriptionStateInternal.CurrentBind, "ApplicationSourceUri");
				DefinitionIdentity definitionIdentity = ((subscriptionStateInternal.PreviousBind != null) ? subscriptionStateInternal.PreviousBind.DeploymentIdentity : null);
				subscriptionStateInternal.RollbackDeployment = ((definitionIdentity != null && (subscriptionStateInternal.MinimumRequiredVersion == null || definitionIdentity.Version >= subscriptionStateInternal.MinimumRequiredVersion)) ? definitionIdentity : null);
				if (subscriptionStateInternal.PreviousBind != null)
				{
					subscriptionStateInternal.PreviousApplication = subscriptionStateInternal.PreviousBind.ApplicationIdentity;
					subscriptionStateInternal.PreviousApplicationManifest = GetAssemblyManifest(subscriptionStateInternal.PreviousBind.ApplicationIdentity);
				}
			}
			return subscriptionStateInternal;
		}

		public void ActivateApplication(DefinitionAppId appId, string activationParameter, bool useActivationParameter)
		{
			HostType hostType = GetHostTypeFromMetadata(appId);
			uint num = 0u;
			switch (PolicyKeys.ClrHostType())
			{
			case PolicyKeys.HostType.AppLaunch:
				hostType = HostType.AppLaunch;
				break;
			case PolicyKeys.HostType.Cor:
				hostType = HostType.CorFlag;
				break;
			}
			string applicationFullName = appId.ToString();
			AssemblyManifest assemblyManifest = GetAssemblyManifest(appId.DeploymentIdentity);
			int activationDataCount = 0;
			string[] activationData = null;
			if (activationParameter != null && (assemblyManifest.Deployment.TrustURLParameters || useActivationParameter))
			{
				activationDataCount = 1;
				activationData = new string[1] { activationParameter };
			}
			num = (uint)hostType;
			if (!assemblyManifest.Deployment.Install)
			{
				num |= 0x80000000u;
			}
			try
			{
				NativeMethods.CorLaunchApplication(num, applicationFullName, 0, null, activationDataCount, activationData, new NativeMethods.PROCESS_INFORMATION());
			}
			catch (COMException ex)
			{
				int num2 = ex.ErrorCode & 0xFFFF;
				if (num2 >= 14000 && num2 <= 14999)
				{
					throw new DeploymentException(ExceptionTypes.Activation, Resources.GetString("Ex_ActivationFailureDueToSxSError"), ex);
				}
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				throw;
			}
			catch (UnauthorizedAccessException innerException)
			{
				throw new DeploymentException(ExceptionTypes.Activation, Resources.GetString("Ex_GenericActivationFailure"), innerException);
			}
			catch (IOException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.Activation, Resources.GetString("Ex_GenericActivationFailure"), innerException2);
			}
		}

		public bool IsAssemblyInstalled(DefinitionIdentity asmId)
		{
			System.Deployment.Internal.Isolation.IDefinitionIdentity definitionIdentity = null;
			try
			{
				definitionIdentity = _store.GetAssemblyIdentity(0u, asmId.ComPointer);
				return true;
			}
			catch (COMException)
			{
				return false;
			}
			finally
			{
				if (definitionIdentity != null)
				{
					Marshal.ReleaseComObject(definitionIdentity);
				}
			}
		}

		public System.Deployment.Internal.Isolation.Store.IPathLock LockApplicationPath(DefinitionAppId definitionAppId)
		{
			try
			{
				return _store.LockApplicationPath(definitionAppId.ComPointer);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				throw;
			}
		}

		public System.Deployment.Internal.Isolation.Store.IPathLock LockAssemblyPath(DefinitionIdentity asmId)
		{
			try
			{
				return _store.LockAssemblyPath(asmId.ComPointer);
			}
			catch (COMException ex)
			{
				if (ex.ErrorCode == -2147024784)
				{
					throw new DeploymentException(ExceptionTypes.DiskIsFull, Resources.GetString("Ex_StoreOperationFailed"), ex);
				}
				throw;
			}
		}

		public bool CheckGroupInstalled(DefinitionAppId appId, string groupName)
		{
			AssemblyManifest assemblyManifest = GetAssemblyManifest(appId.ApplicationIdentity);
			return CheckGroupInstalled(appId, assemblyManifest, groupName);
		}

		public bool CheckGroupInstalled(DefinitionAppId appId, AssemblyManifest appManifest, string groupName)
		{
			System.Deployment.Internal.Isolation.Store.IPathLock pathLock = null;
			try
			{
				pathLock = LockApplicationPath(appId);
				string path = pathLock.Path;
				System.Deployment.Application.Manifest.File[] filesInGroup = appManifest.GetFilesInGroup(groupName, optionalOnly: true);
				System.Deployment.Application.Manifest.File[] array = filesInGroup;
				foreach (System.Deployment.Application.Manifest.File file in array)
				{
					string path2 = Path.Combine(path, file.NameFS);
					if (!System.IO.File.Exists(path2))
					{
						return false;
					}
				}
				DependentAssembly[] privateAssembliesInGroup = appManifest.GetPrivateAssembliesInGroup(groupName, optionalOnly: true);
				DependentAssembly[] array2 = privateAssembliesInGroup;
				foreach (DependentAssembly dependentAssembly in array2)
				{
					string path3 = Path.Combine(path, dependentAssembly.CodebaseFS);
					if (!System.IO.File.Exists(path3))
					{
						return false;
					}
				}
				if (filesInGroup.Length + privateAssembliesInGroup.Length == 0)
				{
					throw new InvalidDeploymentException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_NoSuchDownloadGroup"), groupName));
				}
			}
			finally
			{
				pathLock?.Dispose();
			}
			return true;
		}

		private HostType GetHostTypeFromMetadata(DefinitionAppId defAppId)
		{
			HostType result = HostType.Default;
			try
			{
				if (GetPropertyBoolean(defAppId, "IsFullTrust"))
				{
					result = HostType.CorFlag;
					return result;
				}
				result = HostType.AppLaunch;
				return result;
			}
			catch (DeploymentException)
			{
				return result;
			}
		}

		private AssemblyManifest GetAssemblyManifest(DefinitionIdentity asmId)
		{
			System.Deployment.Internal.Isolation.Manifest.ICMS assemblyManifest = _store.GetAssemblyManifest(0u, asmId.ComPointer);
			return new AssemblyManifest(assemblyManifest);
		}

		private bool IsSubscriptionInstalled(DefinitionIdentity subId)
		{
			DefinitionAppId appId = new DefinitionAppId(subId);
			try
			{
				DefinitionAppId propertyDefinitionAppId = GetPropertyDefinitionAppId(appId, "CurrentBind");
				return propertyDefinitionAppId != null;
			}
			catch (DeploymentException)
			{
				return false;
			}
		}

		private string GetPropertyString(DefinitionAppId appId, string propName)
		{
			byte[] deploymentProperty;
			try
			{
				deploymentProperty = _store.GetDeploymentProperty(System.Deployment.Internal.Isolation.Store.GetPackagePropertyFlags.Nothing, appId.ComPointer, InstallReference, Constants.DeploymentPropertySet, propName);
			}
			catch (COMException)
			{
				return null;
			}
			int num = deploymentProperty.Length;
			if (num == 0 || deploymentProperty.Length % 2 != 0 || deploymentProperty[num - 2] != 0 || deploymentProperty[num - 1] != 0)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName));
			}
			return Encoding.Unicode.GetString(deploymentProperty, 0, num - 2);
		}

		private DefinitionIdentity GetPropertyDefinitionIdentity(DefinitionAppId appId, string propName)
		{
			try
			{
				string propertyString = GetPropertyString(appId, propName);
				return (propertyString != null && propertyString.Length > 0) ? new DefinitionIdentity(propertyString) : null;
			}
			catch (COMException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException);
			}
			catch (SEHException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException2);
			}
		}

		private DefinitionAppId GetPropertyDefinitionAppId(DefinitionAppId appId, string propName)
		{
			try
			{
				string propertyString = GetPropertyString(appId, propName);
				return (propertyString != null && propertyString.Length > 0) ? new DefinitionAppId(propertyString) : null;
			}
			catch (COMException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException);
			}
			catch (SEHException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException2);
			}
		}

		private bool GetPropertyBoolean(DefinitionAppId appId, string propName)
		{
			try
			{
				string propertyString = GetPropertyString(appId, propName);
				return propertyString != null && propertyString.Length > 0 && Convert.ToBoolean(propertyString, CultureInfo.InvariantCulture);
			}
			catch (FormatException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException);
			}
		}

		private Uri GetPropertyUri(DefinitionAppId appId, string propName)
		{
			try
			{
				string propertyString = GetPropertyString(appId, propName);
				return (propertyString != null && propertyString.Length > 0) ? new Uri(propertyString) : null;
			}
			catch (UriFormatException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException);
			}
		}

		private Version GetPropertyVersion(DefinitionAppId appId, string propName)
		{
			try
			{
				string propertyString = GetPropertyString(appId, propName);
				return (propertyString != null && propertyString.Length > 0) ? new Version(propertyString) : null;
			}
			catch (ArgumentException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException);
			}
			catch (FormatException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException2);
			}
		}

		private DateTime GetPropertyDateTime(DefinitionAppId appId, string propName)
		{
			try
			{
				string propertyString = GetPropertyString(appId, propName);
				return (propertyString != null && propertyString.Length > 0) ? DateTime.ParseExact(propertyString, "yyyy/MM/dd HH:mm:ss", DateTimeFormatInfo.InvariantInfo) : DateTime.MinValue;
			}
			catch (FormatException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException);
			}
		}

		private AppType GetPropertyAppType(DefinitionAppId appId, string propName)
		{
			try
			{
				string propertyString = GetPropertyString(appId, propName);
				if (propertyString == null)
				{
					return AppType.None;
				}
				return Convert.ToUInt16(propertyString) switch
				{
					0 => AppType.None, 
					1 => AppType.Installed, 
					2 => AppType.Online, 
					3 => AppType.CustomHostSpecified, 
					4 => AppType.CustomUX, 
					_ => AppType.None, 
				};
			}
			catch (DeploymentException)
			{
				return AppType.None;
			}
			catch (FormatException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException);
			}
			catch (OverflowException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidStoreMetaData"), propName), innerException2);
			}
		}

		private void PrepareCommitApplication(StoreTransactionContext storeTxn, SubscriptionState subState, CommitApplicationParams commitParams)
		{
			DefinitionAppId appId = commitParams.AppId;
			SubscriptionStateInternal subscriptionStateInternal = null;
			if (commitParams.CommitDeploy)
			{
				subscriptionStateInternal = PrepareCommitDeploymentState(storeTxn, subState, commitParams);
				if ((commitParams.IsConfirmed && appId.Equals(subscriptionStateInternal.CurrentBind)) || (!commitParams.IsConfirmed && appId.Equals(subscriptionStateInternal.PendingBind)))
				{
					PrepareStageDeploymentComponent(storeTxn, subState, commitParams);
				}
			}
			if (commitParams.CommitApp)
			{
				PrepareStageAppComponent(storeTxn, commitParams);
				if (!commitParams.DeployManifest.Deployment.Install && commitParams.appType != AppType.CustomHostSpecified)
				{
					storeTxn.ScavengeContext.AddOnlineAppToCommit(appId, subState);
				}
			}
			if (commitParams.CommitDeploy)
			{
				PrepareSetSubscriptionState(storeTxn, subState, subscriptionStateInternal);
			}
		}

		private SubscriptionStateInternal PrepareCommitDeploymentState(StoreTransactionContext storeTxn, SubscriptionState subState, CommitApplicationParams commitParams)
		{
			DefinitionAppId appId = commitParams.AppId;
			AssemblyManifest deployManifest = commitParams.DeployManifest;
			SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal(subState);
			if (commitParams.IsConfirmed)
			{
				subscriptionStateInternal.IsInstalled = true;
				subscriptionStateInternal.IsShellVisible = deployManifest.Deployment.Install;
				subscriptionStateInternal.DeploymentProviderUri = ((deployManifest.Deployment.ProviderCodebaseUri != null) ? deployManifest.Deployment.ProviderCodebaseUri : commitParams.DeploySourceUri);
				if (deployManifest.Deployment.MinimumRequiredVersion != null)
				{
					subscriptionStateInternal.MinimumRequiredVersion = deployManifest.Deployment.MinimumRequiredVersion;
				}
				if (!appId.Equals(subState.CurrentBind))
				{
					subscriptionStateInternal.CurrentBind = appId;
					subscriptionStateInternal.PreviousBind = ((subscriptionStateInternal.IsShellVisible && !subState.IsShellVisible) ? null : subState.CurrentBind);
				}
				subscriptionStateInternal.PendingBind = null;
				subscriptionStateInternal.PendingDeployment = null;
				subscriptionStateInternal.ExcludedDeployment = null;
				subscriptionStateInternal.appType = commitParams.appType;
				ResetUpdateSkippedState(subscriptionStateInternal);
			}
			else
			{
				subscriptionStateInternal.PendingBind = appId;
				subscriptionStateInternal.PendingDeployment = appId.DeploymentIdentity;
				if (!subscriptionStateInternal.PendingDeployment.Equals(subState.UpdateSkippedDeployment))
				{
					ResetUpdateSkippedState(subscriptionStateInternal);
				}
			}
			subscriptionStateInternal.LastCheckTime = commitParams.TimeStamp;
			FinalizeSubscriptionState(subscriptionStateInternal);
			return subscriptionStateInternal;
		}

		private void PrepareStageDeploymentComponent(StoreTransactionContext storeTxn, SubscriptionState subState, CommitApplicationParams commitParams)
		{
			DefinitionAppId definitionAppId = commitParams.AppId.ToDeploymentAppId();
			string deployManifestPath = commitParams.DeployManifestPath;
			storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationStageComponent(definitionAppId.ComPointer, deployManifestPath));
			PrepareSetDeploymentProperties(storeTxn, commitParams.AppId, commitParams);
		}

		private void PrepareSetDeploymentProperties(StoreTransactionContext storeTxn, DefinitionAppId appId, CommitApplicationParams commitParams)
		{
			string value = null;
			string value2 = null;
			string value3 = null;
			if (commitParams != null)
			{
				value = ToPropertyString(commitParams.DeploySourceUri);
				value2 = ToPropertyString(commitParams.AppSourceUri);
				value3 = ((commitParams.IsUpdate && commitParams.Trust == null) ? null : ((commitParams.appType != AppType.CustomHostSpecified) ? ToPropertyString(commitParams.Trust.DefaultGrantSet.PermissionSet.IsUnrestricted()) : null));
			}
			System.Deployment.Internal.Isolation.StoreOperationMetadataProperty[] setProperties = new System.Deployment.Internal.Isolation.StoreOperationMetadataProperty[3]
			{
				new System.Deployment.Internal.Isolation.StoreOperationMetadataProperty(Constants.DeploymentPropertySet, "DeploymentSourceUri", value),
				new System.Deployment.Internal.Isolation.StoreOperationMetadataProperty(Constants.DeploymentPropertySet, "ApplicationSourceUri", value2),
				new System.Deployment.Internal.Isolation.StoreOperationMetadataProperty(Constants.DeploymentPropertySet, "IsFullTrust", value3)
			};
			storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationSetDeploymentMetadata(appId.ComPointer, InstallReference, setProperties));
		}

		private void PrepareStageAppComponent(StoreTransactionContext storeTxn, CommitApplicationParams commitParams)
		{
			DefinitionAppId appId = commitParams.AppId;
			AssemblyManifest appManifest = commitParams.AppManifest;
			string appManifestPath = commitParams.AppManifestPath;
			string appPayloadPath = commitParams.AppPayloadPath;
			string appGroup = commitParams.AppGroup;
			if (appGroup == null)
			{
				if (appManifestPath == null)
				{
					throw new ArgumentNullException("commitParams");
				}
				storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationStageComponent(appId.ComPointer, appManifestPath));
			}
			System.Deployment.Application.Manifest.File[] filesInGroup = appManifest.GetFilesInGroup(appGroup, optionalOnly: true);
			System.Deployment.Application.Manifest.File[] array = filesInGroup;
			foreach (System.Deployment.Application.Manifest.File file in array)
			{
				PrepareInstallFile(storeTxn, file, appId, null, appPayloadPath);
			}
			DependentAssembly[] privateAssembliesInGroup = appManifest.GetPrivateAssembliesInGroup(appGroup, optionalOnly: true);
			DependentAssembly[] array2 = privateAssembliesInGroup;
			foreach (DependentAssembly privAsm in array2)
			{
				PrepareInstallPrivateAssembly(storeTxn, privAsm, appId, appPayloadPath);
			}
		}

		private void PrepareInstallFile(StoreTransactionContext storeTxn, System.Deployment.Application.Manifest.File file, DefinitionAppId appId, DefinitionIdentity asmId, string asmPayloadPath)
		{
			string srcFile = Path.Combine(asmPayloadPath, file.NameFS);
			string name = file.Name;
			storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationStageComponentFile(appId.ComPointer, asmId?.ComPointer, name, srcFile));
		}

		private void PrepareInstallPrivateAssembly(StoreTransactionContext storeTxn, DependentAssembly privAsm, DefinitionAppId appId, string appPayloadPath)
		{
			string codebaseFS = privAsm.CodebaseFS;
			string text = Path.Combine(appPayloadPath, codebaseFS);
			string directoryName = Path.GetDirectoryName(text);
			AssemblyManifest assemblyManifest = new AssemblyManifest(text);
			DefinitionIdentity definitionIdentity = assemblyManifest.Identity;
			string text2 = assemblyManifest.RawXmlFilePath;
			if (text2 == null)
			{
				text2 = text + ".genman";
				definitionIdentity = ManifestGenerator.GenerateManifest(privAsm.Identity, assemblyManifest, text2);
			}
			storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationStageComponent(appId.ComPointer, definitionIdentity.ComPointer, text2));
			System.Deployment.Application.Manifest.File[] files = assemblyManifest.Files;
			foreach (System.Deployment.Application.Manifest.File file in files)
			{
				PrepareInstallFile(storeTxn, file, appId, definitionIdentity, directoryName);
			}
		}

		private void PrepareRemoveSubscription(StoreTransactionContext storeTxn, SubscriptionState subState)
		{
			SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal(subState);
			subscriptionStateInternal.IsInstalled = false;
			PrepareFinalizeSubscriptionState(storeTxn, subState, subscriptionStateInternal);
		}

		private void PrepareRollbackSubscription(StoreTransactionContext storeTxn, SubscriptionState subState)
		{
			SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal(subState);
			subscriptionStateInternal.ExcludedDeployment = subState.CurrentBind.DeploymentIdentity;
			subscriptionStateInternal.CurrentBind = subState.PreviousBind;
			subscriptionStateInternal.PreviousBind = null;
			PrepareFinalizeSubscriptionState(storeTxn, subState, subscriptionStateInternal);
		}

		private void PrepareSetPendingDeployment(StoreTransactionContext storeTxn, SubscriptionState subState, DefinitionIdentity deployId, DateTime checkTime)
		{
			SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal(subState);
			subscriptionStateInternal.PendingDeployment = deployId;
			subscriptionStateInternal.LastCheckTime = checkTime;
			if (subscriptionStateInternal.PendingDeployment != null && !subscriptionStateInternal.PendingDeployment.Equals(subState.UpdateSkippedDeployment))
			{
				ResetUpdateSkippedState(subscriptionStateInternal);
			}
			PrepareFinalizeSubscriptionState(storeTxn, subState, subscriptionStateInternal);
		}

		private void PrepareUpdateSkipTime(StoreTransactionContext storeTxn, SubscriptionState subState, DefinitionIdentity updateSkippedDeployment, DateTime updateSkipTime)
		{
			SubscriptionStateInternal subscriptionStateInternal = new SubscriptionStateInternal(subState);
			subscriptionStateInternal.UpdateSkippedDeployment = updateSkippedDeployment;
			subscriptionStateInternal.UpdateSkipTime = updateSkipTime;
			PrepareFinalizeSubscriptionState(storeTxn, subState, subscriptionStateInternal);
		}

		private void PrepareFinalizeSubscriptionState(StoreTransactionContext storeTxn, SubscriptionState subState, SubscriptionStateInternal newState)
		{
			FinalizeSubscriptionState(newState);
			PrepareSetSubscriptionState(storeTxn, subState, newState);
		}

		private void PrepareSetSubscriptionState(StoreTransactionContext storeTxn, SubscriptionState subState, SubscriptionStateInternal newState)
		{
			PrepareFinalizeSubscription(storeTxn, subState, newState);
			PrepareSetSubscriptionProperties(storeTxn, subState, newState);
			PrepareRemoveOrphanedDeployments(storeTxn, subState, newState);
		}

		private static void FinalizeSubscriptionState(SubscriptionStateInternal newState)
		{
			if (!newState.IsInstalled)
			{
				newState.Reset();
				return;
			}
			DefinitionAppId currentBind = newState.CurrentBind;
			DefinitionIdentity deploymentIdentity = currentBind.DeploymentIdentity;
			DefinitionAppId definitionAppId = newState.PreviousBind;
			if (definitionAppId != null && definitionAppId.Equals(currentBind))
			{
				definitionAppId = (newState.PreviousBind = null);
			}
			DefinitionIdentity obj = definitionAppId?.DeploymentIdentity;
			DefinitionIdentity definitionIdentity = newState.ExcludedDeployment;
			if (definitionIdentity != null && (definitionIdentity.Equals(deploymentIdentity) || definitionIdentity.Equals(obj)))
			{
				definitionIdentity = (newState.ExcludedDeployment = null);
			}
			DefinitionIdentity definitionIdentity2 = newState.PendingDeployment;
			if (definitionIdentity2 != null && (definitionIdentity2.Equals(deploymentIdentity) || definitionIdentity2.Equals(definitionIdentity)))
			{
				definitionIdentity2 = (newState.PendingDeployment = null);
			}
			DefinitionAppId pendingBind = newState.PendingBind;
			if (pendingBind != null && (!pendingBind.DeploymentIdentity.Equals(definitionIdentity2) || pendingBind.Equals(definitionAppId)))
			{
				pendingBind = (newState.PendingBind = null);
			}
		}

		private static void ResetUpdateSkippedState(SubscriptionStateInternal newState)
		{
			newState.UpdateSkippedDeployment = null;
			newState.UpdateSkipTime = DateTime.MinValue;
		}

		private void PrepareSetSubscriptionProperties(StoreTransactionContext storeTxn, SubscriptionState subState, SubscriptionStateInternal newState)
		{
			SubscriptionStateVariable[] array = new SubscriptionStateVariable[12]
			{
				new SubscriptionStateVariable("IsShellVisible", newState.IsShellVisible, subState.IsShellVisible),
				new SubscriptionStateVariable("PreviousBind", newState.PreviousBind, subState.PreviousBind),
				new SubscriptionStateVariable("PendingBind", newState.PendingBind, subState.PendingBind),
				new SubscriptionStateVariable("ExcludedDeployment", newState.ExcludedDeployment, subState.ExcludedDeployment),
				new SubscriptionStateVariable("PendingDeployment", newState.PendingDeployment, subState.PendingDeployment),
				new SubscriptionStateVariable("DeploymentProviderUri", newState.DeploymentProviderUri, subState.DeploymentProviderUri),
				new SubscriptionStateVariable("MinimumRequiredVersion", newState.MinimumRequiredVersion, subState.MinimumRequiredVersion),
				new SubscriptionStateVariable("LastCheckTime", newState.LastCheckTime, subState.LastCheckTime),
				new SubscriptionStateVariable("UpdateSkippedDeployment", newState.UpdateSkippedDeployment, subState.UpdateSkippedDeployment),
				new SubscriptionStateVariable("UpdateSkipTime", newState.UpdateSkipTime, subState.UpdateSkipTime),
				new SubscriptionStateVariable("AppType", (ushort)newState.appType, (ushort)subState.appType),
				new SubscriptionStateVariable("CurrentBind", newState.CurrentBind, subState.CurrentBind)
			};
			ArrayList arrayList = new ArrayList();
			SubscriptionStateVariable[] array2 = array;
			foreach (SubscriptionStateVariable subscriptionStateVariable in array2)
			{
				if (!subState.IsInstalled || !subscriptionStateVariable.IsUnchanged || !newState.IsInstalled)
				{
					arrayList.Add(new System.Deployment.Internal.Isolation.StoreOperationMetadataProperty(Constants.DeploymentPropertySet, subscriptionStateVariable.PropertyName, newState.IsInstalled ? ToPropertyString(subscriptionStateVariable.NewValue) : null));
				}
			}
			if (arrayList.Count > 0)
			{
				System.Deployment.Internal.Isolation.StoreOperationMetadataProperty[] setProperties = (System.Deployment.Internal.Isolation.StoreOperationMetadataProperty[])arrayList.ToArray(typeof(System.Deployment.Internal.Isolation.StoreOperationMetadataProperty));
				DefinitionAppId definitionAppId = new DefinitionAppId(subState.SubscriptionId);
				storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationSetDeploymentMetadata(definitionAppId.ComPointer, InstallReference, setProperties));
			}
		}

		private void PrepareRemoveOrphanedDeployments(StoreTransactionContext storeTxn, SubscriptionState subState, SubscriptionStateInternal newState)
		{
			ArrayList arrayList = new ArrayList();
			arrayList.Add(subState.CurrentBind);
			arrayList.Add(subState.PreviousBind);
			arrayList.Add(subState.PendingBind);
			arrayList.Remove(newState.CurrentBind);
			arrayList.Remove(newState.PreviousBind);
			arrayList.Remove(newState.PendingBind);
			foreach (DefinitionAppId item in arrayList)
			{
				if (item != null)
				{
					PrepareRemoveDeployment(storeTxn, subState, item);
				}
			}
		}

		private void PrepareRemoveDeployment(StoreTransactionContext storeTxn, SubscriptionState subState, DefinitionAppId appId)
		{
			DefinitionAppId deployAppId = appId.ToDeploymentAppId();
			if (subState.IsShellVisible)
			{
				PrepareInstallUninstallDeployment(storeTxn, deployAppId, isInstall: false);
			}
			else
			{
				PreparePinUnpinDeployment(storeTxn, deployAppId, isPin: false);
			}
			PrepareSetDeploymentProperties(storeTxn, appId, null);
			storeTxn.ScavengeContext.AddDeploymentToUnpin(deployAppId, subState);
			ApplicationTrust.RemoveCachedTrust(appId);
		}

		private void PrepareFinalizeSubscription(StoreTransactionContext storeTxn, SubscriptionState subState, SubscriptionStateInternal newState)
		{
			if (newState.IsInstalled && (!subState.IsInstalled || newState.IsShellVisible != subState.IsShellVisible || !newState.CurrentBind.Equals(subState.CurrentBind)))
			{
				DefinitionAppId deployAppId = newState.CurrentBind.ToDeploymentAppId();
				if (newState.IsShellVisible)
				{
					PrepareInstallUninstallDeployment(storeTxn, deployAppId, isInstall: true);
				}
				else
				{
					PreparePinUnpinDeployment(storeTxn, deployAppId, isPin: true);
				}
			}
		}

		private void PreparePinUnpinDeployment(StoreTransactionContext storeTxn, DefinitionAppId deployAppId, bool isPin)
		{
			if (isPin)
			{
				storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationPinDeployment(deployAppId.ComPointer, InstallReference));
			}
			else
			{
				storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationUnpinDeployment(deployAppId.ComPointer, InstallReference));
			}
		}

		private void PrepareInstallUninstallDeployment(StoreTransactionContext storeTxn, DefinitionAppId deployAppId, bool isInstall)
		{
			if (isInstall)
			{
				storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationInstallDeployment(deployAppId.ComPointer, InstallReference));
			}
			else
			{
				storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationUninstallDeployment(deployAppId.ComPointer, InstallReference));
			}
		}

		private void SubmitStoreTransaction(StoreTransactionContext storeTxn, SubscriptionState subState)
		{
			CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfPersisterWriteStart);
			storeTxn.Add(new System.Deployment.Internal.Isolation.StoreOperationScavenge(Light: false));
			System.Deployment.Internal.Isolation.StoreTransactionOperation[] operations = storeTxn.Operations;
			if (operations.Length <= 0)
			{
				return;
			}
			uint[] rgDispositions = new uint[operations.Length];
			int[] rgResults = new int[operations.Length];
			try
			{
				_store.Transact(operations, rgDispositions, rgResults);
				_stateMgr.Scavenge(0u, out var _);
			}
			catch (DirectoryNotFoundException innerException)
			{
				throw new DeploymentException(ExceptionTypes.ComponentStore, Resources.GetString("Ex_TransactDirectoryNotFoundException"), innerException);
			}
			catch (ArgumentException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.ComponentStore, Resources.GetString("Ex_StoreOperationFailed"), innerException2);
			}
			catch (UnauthorizedAccessException innerException3)
			{
				throw new DeploymentException(ExceptionTypes.ComponentStore, Resources.GetString("Ex_StoreOperationFailed"), innerException3);
			}
			catch (IOException innerException4)
			{
				throw new DeploymentException(ExceptionTypes.ComponentStore, Resources.GetString("Ex_StoreOperationFailed"), innerException4);
			}
			finally
			{
				CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfPersisterWriteEnd);
				Logger.AddTransactionInformation(operations, rgDispositions, rgResults);
			}
			subState?.Invalidate();
		}

		private void SubmitStoreTransactionCheckQuota(StoreTransactionContext storeTxn, SubscriptionState subState)
		{
			storeTxn.ScavengeContext.CalculateSizesPreTransact();
			SubmitStoreTransaction(storeTxn, subState);
			storeTxn.ScavengeContext.CalculateSizesPostTransact();
			storeTxn.ScavengeContext.CheckQuotaAndScavenge();
		}

		private static string ToPropertyString(object propValue)
		{
			if (propValue == null)
			{
				return string.Empty;
			}
			if (propValue is bool flag)
			{
				return flag.ToString(CultureInfo.InvariantCulture);
			}
			if (propValue is DateTime dateTime)
			{
				return dateTime.ToString("yyyy/MM/dd HH:mm:ss", DateTimeFormatInfo.InvariantInfo);
			}
			if (propValue is Uri)
			{
				return ((Uri)propValue).AbsoluteUri;
			}
			return propValue.ToString();
		}
	}
}
namespace System.Deployment.Internal.Isolation
{
	internal class StoreTransaction : IDisposable
	{
		private ArrayList _list = new ArrayList();

		private StoreTransactionOperation[] _storeOps;

		public StoreTransactionOperation[] Operations
		{
			get
			{
				if (_storeOps == null)
				{
					_storeOps = GenerateStoreOpsList();
				}
				return _storeOps;
			}
		}

		public void Add(StoreOperationInstallDeployment o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationPinDeployment o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationSetCanonicalizationContext o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationSetDeploymentMetadata o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationStageComponent o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationStageComponentFile o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationUninstallDeployment o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationUnpinDeployment o)
		{
			_list.Add(o);
		}

		public void Add(StoreOperationScavenge o)
		{
			_list.Add(o);
		}

		~StoreTransaction()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		private void Dispose(bool fDisposing)
		{
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
			StoreTransactionOperation[] storeOps = _storeOps;
			_storeOps = null;
			if (storeOps == null)
			{
				return;
			}
			for (int i = 0; i != storeOps.Length; i++)
			{
				StoreTransactionOperation storeTransactionOperation = storeOps[i];
				if (storeTransactionOperation.Data.DataPtr != IntPtr.Zero)
				{
					switch (storeTransactionOperation.Operation)
					{
					case StoreTransactionOperationType.StageComponent:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationStageComponent));
						break;
					case StoreTransactionOperationType.StageComponentFile:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationStageComponentFile));
						break;
					case StoreTransactionOperationType.PinDeployment:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationPinDeployment));
						break;
					case StoreTransactionOperationType.UninstallDeployment:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationUninstallDeployment));
						break;
					case StoreTransactionOperationType.UnpinDeployment:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationUnpinDeployment));
						break;
					case StoreTransactionOperationType.InstallDeployment:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationInstallDeployment));
						break;
					case StoreTransactionOperationType.SetCanonicalizationContext:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationSetCanonicalizationContext));
						break;
					case StoreTransactionOperationType.SetDeploymentMetadata:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationSetDeploymentMetadata));
						break;
					case StoreTransactionOperationType.Scavenge:
						Marshal.DestroyStructure(storeTransactionOperation.Data.DataPtr, typeof(StoreOperationScavenge));
						break;
					}
					Marshal.FreeCoTaskMem(storeTransactionOperation.Data.DataPtr);
				}
			}
		}

		private StoreTransactionOperation[] GenerateStoreOpsList()
		{
			StoreTransactionOperation[] array = new StoreTransactionOperation[_list.Count];
			for (int i = 0; i != _list.Count; i++)
			{
				object obj = _list[i];
				Type type = obj.GetType();
				array[i].Data.DataPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(obj));
				Marshal.StructureToPtr(obj, array[i].Data.DataPtr, fDeleteOld: false);
				if (type == typeof(StoreOperationSetCanonicalizationContext))
				{
					array[i].Operation = StoreTransactionOperationType.SetCanonicalizationContext;
					continue;
				}
				if (type == typeof(StoreOperationStageComponent))
				{
					array[i].Operation = StoreTransactionOperationType.StageComponent;
					continue;
				}
				if (type == typeof(StoreOperationPinDeployment))
				{
					array[i].Operation = StoreTransactionOperationType.PinDeployment;
					continue;
				}
				if (type == typeof(StoreOperationUnpinDeployment))
				{
					array[i].Operation = StoreTransactionOperationType.UnpinDeployment;
					continue;
				}
				if (type == typeof(StoreOperationStageComponentFile))
				{
					array[i].Operation = StoreTransactionOperationType.StageComponentFile;
					continue;
				}
				if (type == typeof(StoreOperationInstallDeployment))
				{
					array[i].Operation = StoreTransactionOperationType.InstallDeployment;
					continue;
				}
				if (type == typeof(StoreOperationUninstallDeployment))
				{
					array[i].Operation = StoreTransactionOperationType.UninstallDeployment;
					continue;
				}
				if (type == typeof(StoreOperationSetDeploymentMetadata))
				{
					array[i].Operation = StoreTransactionOperationType.SetDeploymentMetadata;
					continue;
				}
				if (type == typeof(StoreOperationScavenge))
				{
					array[i].Operation = StoreTransactionOperationType.Scavenge;
					continue;
				}
				throw new Exception("How did you get here?");
			}
			return array;
		}
	}
}
namespace System.Deployment.Application
{
	internal class SubscriptionStateInternal
	{
		public bool IsInstalled;

		public bool IsShellVisible;

		public DefinitionAppId CurrentBind;

		public DefinitionAppId PreviousBind;

		public DefinitionAppId PendingBind;

		public DefinitionIdentity PendingDeployment;

		public DefinitionIdentity ExcludedDeployment;

		public Uri DeploymentProviderUri;

		public Version MinimumRequiredVersion;

		public DateTime LastCheckTime;

		public DateTime UpdateSkipTime;

		public DefinitionIdentity UpdateSkippedDeployment;

		public AppType appType;

		public DefinitionIdentity CurrentDeployment;

		public DefinitionIdentity RollbackDeployment;

		public AssemblyManifest CurrentDeploymentManifest;

		public Uri CurrentDeploymentSourceUri;

		public DefinitionIdentity CurrentApplication;

		public AssemblyManifest CurrentApplicationManifest;

		public Uri CurrentApplicationSourceUri;

		public DefinitionIdentity PreviousApplication;

		public AssemblyManifest PreviousApplicationManifest;

		public SubscriptionStateInternal()
		{
			Reset();
		}

		public SubscriptionStateInternal(SubscriptionState subState)
		{
			IsInstalled = subState.IsInstalled;
			IsShellVisible = subState.IsShellVisible;
			CurrentBind = subState.CurrentBind;
			PreviousBind = subState.PreviousBind;
			PendingBind = subState.PreviousBind;
			PendingDeployment = subState.PendingDeployment;
			ExcludedDeployment = subState.ExcludedDeployment;
			DeploymentProviderUri = subState.DeploymentProviderUri;
			MinimumRequiredVersion = subState.MinimumRequiredVersion;
			LastCheckTime = subState.LastCheckTime;
			UpdateSkippedDeployment = subState.UpdateSkippedDeployment;
			UpdateSkipTime = subState.UpdateSkipTime;
			appType = subState.appType;
		}

		public void Reset()
		{
			IsInstalled = (IsShellVisible = false);
			CurrentBind = (PreviousBind = (PendingBind = null));
			ExcludedDeployment = (PendingDeployment = null);
			DeploymentProviderUri = null;
			MinimumRequiredVersion = null;
			LastCheckTime = DateTime.MinValue;
			UpdateSkippedDeployment = null;
			UpdateSkipTime = DateTime.MinValue;
			CurrentDeployment = null;
			RollbackDeployment = null;
			CurrentDeploymentManifest = null;
			CurrentDeploymentSourceUri = null;
			CurrentApplication = null;
			CurrentApplicationManifest = null;
			CurrentApplicationSourceUri = null;
			PreviousApplication = null;
			PreviousApplicationManifest = null;
			appType = AppType.None;
		}
	}
	internal class SubscriptionStateVariable
	{
		public string PropertyName;

		public object NewValue;

		public object OldValue;

		public bool IsUnchanged
		{
			get
			{
				if (NewValue == null)
				{
					return OldValue == null;
				}
				return NewValue.Equals(OldValue);
			}
		}

		public SubscriptionStateVariable(string name, object newValue, object oldValue)
		{
			PropertyName = name;
			NewValue = newValue;
			OldValue = oldValue;
		}
	}
	internal enum ComponentStoreType
	{
		UserStore,
		SystemStore
	}
	internal class Hash
	{
		private byte[] _digestValue;

		private System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD _digestMethod;

		private System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM _transform;

		public byte[] DigestValue => _digestValue;

		public System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD DigestMethod => _digestMethod;

		public System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM Transform => _transform;

		public string CompositString => DigestMethodCodeString + TranformCodeString + HexString.FromBytes(DigestValue);

		protected string TranformCodeString => ToCodedString((uint)Transform);

		protected string DigestMethodCodeString => ToCodedString((uint)DigestMethod);

		public Hash(byte[] digestValue, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD digestMethod, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM transform)
		{
			if (digestValue == null)
			{
				throw new ArgumentException(Resources.GetString("Ex_HashNullDigestValue"));
			}
			_digestValue = digestValue;
			_digestMethod = digestMethod;
			_transform = transform;
		}

		protected static string ToCodedString(uint value)
		{
			if (value > 255)
			{
				throw new ArgumentException(Resources.GetString("Ex_CodeLimitExceeded"));
			}
			return string.Format(CultureInfo.InvariantCulture, "{0:x2}", value);
		}
	}
	internal class HashCollection : IEnumerable
	{
		public class HashEnumerator : IEnumerator
		{
			private int _index;

			private HashCollection _hashCollection;

			public Hash Current => (Hash)_hashCollection._hashes[_index];

			object IEnumerator.Current => _hashCollection._hashes[_index];

			public HashEnumerator(HashCollection hashCollection)
			{
				_hashCollection = hashCollection;
				_index = -1;
			}

			public void Reset()
			{
				_index = -1;
			}

			public bool MoveNext()
			{
				_index++;
				return _index < _hashCollection._hashes.Count;
			}
		}

		protected ArrayList _hashes = new ArrayList();

		public int Count => _hashes.Count;

		public void AddHash(byte[] digestValue, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD digestMethod, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM transform)
		{
			Hash value = new Hash(digestValue, digestMethod, transform);
			_hashes.Add(value);
		}

		public HashEnumerator GetEnumerator()
		{
			return new HashEnumerator(this);
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}
	}
	internal class ComponentVerifier
	{
		protected abstract class VerificationComponent
		{
			public abstract void Verify();
		}

		protected class FileComponent : VerificationComponent
		{
			protected string _filePath;

			protected HashCollection _hashCollection;

			public FileComponent(string filePath, HashCollection hashCollection)
			{
				_filePath = filePath;
				_hashCollection = hashCollection;
			}

			public override void Verify()
			{
				VerifyFileHash(_filePath, _hashCollection);
			}
		}

		protected class SimplyNamedAssemblyComponent : VerificationComponent
		{
			protected string _filePath;

			protected AssemblyManifest _assemblyManifest;

			public SimplyNamedAssemblyComponent(string filePath, AssemblyManifest assemblyManifest)
			{
				_filePath = filePath;
				_assemblyManifest = assemblyManifest;
			}

			public override void Verify()
			{
				VerifySimplyNamedAssembly(_filePath, _assemblyManifest);
			}
		}

		protected class StrongNameAssemblyComponent : VerificationComponent
		{
			protected string _filePath;

			protected AssemblyManifest _assemblyManifest;

			public StrongNameAssemblyComponent(string filePath, AssemblyManifest assemblyManifest)
			{
				_filePath = filePath;
				_assemblyManifest = assemblyManifest;
			}

			public override void Verify()
			{
				VerifyStrongNameAssembly(_filePath, _assemblyManifest);
			}
		}

		protected ArrayList _verificationComponents = new ArrayList();

		protected static System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD[] _supportedDigestMethods = new System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD[4]
		{
			System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA1,
			System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA256,
			System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA384,
			System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA512
		};

		protected static System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM[] _supportedTransforms = new System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM[2]
		{
			System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_MANIFESTINVARIANT,
			System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_IDENTITY
		};

		public static System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM[] VerifiableTransformTypes => _supportedTransforms;

		public static System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD[] VerifiableDigestMethods => _supportedDigestMethods;

		public void AddFileForVerification(string filePath, HashCollection verificationHashCollection)
		{
			FileComponent value = new FileComponent(filePath, verificationHashCollection);
			_verificationComponents.Add(value);
		}

		public void AddSimplyNamedAssemblyForVerification(string filePath, AssemblyManifest assemblyManifest)
		{
			SimplyNamedAssemblyComponent value = new SimplyNamedAssemblyComponent(filePath, assemblyManifest);
			_verificationComponents.Add(value);
		}

		public void AddStrongNameAssemblyForVerification(string filePath, AssemblyManifest assemblyManifest)
		{
			StrongNameAssemblyComponent value = new StrongNameAssemblyComponent(filePath, assemblyManifest);
			_verificationComponents.Add(value);
		}

		public void VerifyComponents()
		{
			foreach (VerificationComponent verificationComponent in _verificationComponents)
			{
				verificationComponent.Verify();
			}
		}

		public static void VerifyFileHash(string filePath, HashCollection hashCollection)
		{
			string fileName = Path.GetFileName(filePath);
			if (hashCollection.Count == 0)
			{
				if (PolicyKeys.RequireHashInManifests())
				{
					throw new InvalidDeploymentException(ExceptionTypes.HashValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_HashNotSpecified"), fileName));
				}
				Logger.AddWarningInformation(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("NoHashFile"), fileName));
			}
			foreach (Hash item in hashCollection)
			{
				VerifyFileHash(filePath, item);
			}
		}

		public static void VerifyFileHash(string filePath, Hash hash)
		{
			string fileName = Path.GetFileName(filePath);
			byte[] array;
			try
			{
				array = GenerateDigestValue(filePath, hash.DigestMethod, hash.Transform);
			}
			catch (IOException innerException)
			{
				throw new InvalidDeploymentException(ExceptionTypes.HashValidation, Resources.GetString("Ex_HashValidationException"), innerException);
			}
			byte[] digestValue = hash.DigestValue;
			bool flag = false;
			if (array.Length == digestValue.Length)
			{
				int i;
				for (i = 0; i < digestValue.Length && digestValue[i] == array[i]; i++)
				{
				}
				if (i >= digestValue.Length)
				{
					flag = true;
				}
			}
			if (!flag)
			{
				throw new InvalidDeploymentException(ExceptionTypes.HashValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DifferentHashes"), fileName));
			}
		}

		public static byte[] GenerateDigestValue(string filePath, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD digestMethod, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM transform)
		{
			Stream stream = null;
			byte[] array = null;
			try
			{
				HashAlgorithm hashAlgorithm = GetHashAlgorithm(digestMethod);
				stream = GetTransformedStream(filePath, transform);
				return hashAlgorithm.ComputeHash(stream);
			}
			finally
			{
				stream?.Close();
			}
		}

		public static bool IsVerifiableHashCollection(HashCollection hashCollection)
		{
			foreach (Hash item in hashCollection)
			{
				if (!IsVerifiableHash(item))
				{
					return false;
				}
			}
			return true;
		}

		public static bool IsVerifiableHash(Hash hash)
		{
			if (Array.IndexOf(VerifiableTransformTypes, hash.Transform) >= 0 && Array.IndexOf(VerifiableDigestMethods, hash.DigestMethod) >= 0 && hash.DigestValue != null && hash.DigestValue.Length > 0)
			{
				return true;
			}
			return false;
		}

		public static HashAlgorithm GetHashAlgorithm(System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD digestMethod)
		{
			return digestMethod switch
			{
				System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA1 => new SHA1CryptoServiceProvider(), 
				System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA256 => new SHA256Managed(), 
				System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA384 => new SHA384Managed(), 
				System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA512 => new SHA512Managed(), 
				_ => throw new NotSupportedException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DigestMethodNotSupported"), digestMethod.ToString())), 
			};
		}

		public static Stream GetTransformedStream(string filePath, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM transform)
		{
			Stream stream = null;
			switch (transform)
			{
			case System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_MANIFESTINVARIANT:
			{
				PEStream pEStream = null;
				try
				{
					pEStream = new PEStream(filePath, partialConstruct: true);
					pEStream.ZeroOutOptionalHeaderCheckSum();
					pEStream.ZeroOutDefaultId1ManifestResource();
					stream = pEStream;
				}
				finally
				{
					if (pEStream != stream)
					{
						pEStream?.Close();
					}
				}
				break;
			}
			case System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_IDENTITY:
				stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
				break;
			default:
				throw new NotSupportedException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_TransformAlgorithmNotSupported"), transform.ToString()));
			}
			return stream;
		}

		public static void VerifySimplyNamedAssembly(string filePath, AssemblyManifest assemblyManifest)
		{
			string fileName = Path.GetFileName(filePath);
			if (assemblyManifest.Identity.PublicKeyToken != null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.Validation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_SimplyNamedAsmWithPKT"), fileName));
			}
			if (assemblyManifest.ManifestSourceFormat == ManifestSourceFormat.ID_1 && assemblyManifest.ComplibIdentity != null && assemblyManifest.ComplibIdentity.PublicKeyToken != null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.IdentityMatchValidationForMixedModeAssembly, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_SimplyNamedAsmWithStrongNameComplib"), fileName));
			}
		}

		public static void VerifyStrongNameAssembly(string filePath, AssemblyManifest assemblyManifest)
		{
			string fileName = Path.GetFileName(filePath);
			if (assemblyManifest.Identity.PublicKeyToken == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.Validation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_StrongNameAsmWithNoPKT"), fileName));
			}
			bool ignoreSelfReferentialFileHash = false;
			if (assemblyManifest.ManifestSourceFormat == ManifestSourceFormat.XmlFile)
			{
				assemblyManifest.ValidateSignature(null);
			}
			else if (assemblyManifest.ManifestSourceFormat == ManifestSourceFormat.ID_1)
			{
				if (assemblyManifest.ComplibIdentity == null)
				{
					byte[] array = null;
					PEStream pEStream = null;
					MemoryStream memoryStream = null;
					try
					{
						pEStream = new PEStream(filePath, partialConstruct: true);
						array = pEStream.GetDefaultId1ManifestResource();
						if (array != null)
						{
							memoryStream = new MemoryStream(array);
						}
						if (memoryStream == null)
						{
							throw new InvalidDeploymentException(ExceptionTypes.StronglyNamedAssemblyVerification, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_StronglyNamedAssemblyNotVerifiable"), fileName));
						}
						assemblyManifest.ValidateSignature(memoryStream);
					}
					finally
					{
						pEStream?.Close();
						memoryStream?.Close();
					}
				}
				else
				{
					if (!assemblyManifest.ComplibIdentity.Equals(assemblyManifest.Identity))
					{
						throw new InvalidDeploymentException(ExceptionTypes.IdentityMatchValidationForMixedModeAssembly, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_IdentitiesDoNotMatchForMixedModeAssembly"), fileName));
					}
					if (NativeMethods.StrongNameSignatureVerificationEx(filePath, 0, out var _) == 0)
					{
						throw new InvalidDeploymentException(ExceptionTypes.SignatureValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_StrongNameSignatureInvalid"), fileName));
					}
					ignoreSelfReferentialFileHash = true;
				}
			}
			else
			{
				if (assemblyManifest.ManifestSourceFormat != ManifestSourceFormat.CompLib)
				{
					throw new InvalidDeploymentException(ExceptionTypes.StronglyNamedAssemblyVerification, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_StronglyNamedAssemblyNotVerifiable"), fileName));
				}
				if (NativeMethods.StrongNameSignatureVerificationEx(filePath, 0, out var _) == 0)
				{
					throw new InvalidDeploymentException(ExceptionTypes.SignatureValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_StrongNameSignatureInvalid"), fileName));
				}
				ignoreSelfReferentialFileHash = true;
			}
			VerifyManifestComponentFiles(assemblyManifest, filePath, ignoreSelfReferentialFileHash);
		}

		protected static void VerifyManifestComponentFiles(AssemblyManifest manifest, string componentPath, bool ignoreSelfReferentialFileHash)
		{
			string directoryName = Path.GetDirectoryName(componentPath);
			System.Deployment.Application.Manifest.File[] files = manifest.Files;
			foreach (System.Deployment.Application.Manifest.File file in files)
			{
				string text = Path.Combine(directoryName, file.NameFS);
				if ((!ignoreSelfReferentialFileHash || string.Compare(componentPath, text, StringComparison.OrdinalIgnoreCase) != 0) && System.IO.File.Exists(text))
				{
					VerifyFileHash(text, file.HashCollection);
				}
			}
		}
	}
	internal static class Constants
	{
		public const string ShimDll = "dfshim.dll";

		public const string DfDll = "dfdll.dll";

		public const string DeploymentFolder = "Deployment";

		public const string Dfsvc = "dfsvc.exe";

		public const string SystemDeploymentDll = "system.deployment.dll";

		public const string Kernel32Dll = "kernel32.dll";

		public const string MscoreeDll = "mscoree.dll";

		public const string WininetDll = "wininet.dll";

		public const string MscorwksDll = "mscorwks.dll";

		public const string SrClientDll = "srclient.dll";

		public const string WinInetDll = "wininet.dll";

		public const string Shell32Dll = "shell32.dll";

		public const string ShellAppShortcutExtension = ".appref-ms";

		public const string ShellSupportShortcutExtension = ".url";

		public const int SupportIconIndex = 0;

		public const string UninstallSubkeyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

		public const string DeploymentSubkeyName = "SOFTWARE\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment";

		public const string RandomKeyName = "SideBySide\\2.0";

		public const string RandomValueName = "ComponentStore_RandomString";

		public const string Sentinel35SP1Update = "ClickOnce35SP1Update";

		public const string LUAPolicyKeyName = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

		public const string OnlineAppQuotaInKBValueName = "OnlineAppQuotaInKB";

		public const string OnlineAppQuotaUsageEstimateValueName = "OnlineAppQuotaUsageEstimate";

		public const string LUAPolicyValueName = "EnableLUA";

		public const string ClassesSubKeyName = "Software\\Classes";

		public const string AppIdValueName = "AppId";

		public const string DPUrlValueName = "DeploymentProviderUrl";

		public const string IconFileValueName = "IconFile";

		public const string ContentTypeValueName = "Content Type";

		public const string ShellKeyName = "shell";

		public const string OpenCommandKeyName = "open\\command";

		public const string IconHandlerKeyName = "shellex\\IconHandler";

		public const string CLSIDKeyName = "CLSID";

		public const string InProcServerKeyName = "InProcServer32";

		public const string GuidValueName = "Guid";

		public const string RootKeyName = "Software\\Microsoft\\.NETFramework\\DeploymentFramework";

		public const string RequireSignedManifests = "RequireSignedManifests";

		public const string RequireHashInManifests = "RequireHashInManifests";

		public const string SkipSignatureValidationValueName = "SkipSignatureValidation";

		public const string SkipDeploymentProviderValueName = "SkipDeploymentProvider";

		public const string SkipSchemaValidationValueName = "SkipSchemaValidation";

		public const string SkipSemanticValidationValueName = "SkipSemanticValidation";

		public const string SkipApplicationDependencyHashCheckValueName = "SkipApplicationDependencyHashCheck";

		public const string SuppressLimitOnNumberOfActivationsValueName = "SuppressLimitOnNumberOfActivations";

		public const string DisableGenericExceptionHandler = "DisableGenericExceptionHandler";

		public const string DeploymentManifestSuffix = ".application";

		public const string ManifestSuffix = ".manifest";

		public const string DllSuffix = ".dll";

		public const string ExeSuffix = ".exe";

		public const string MapFileExtensionsSuffix = ".deploy";

		public const string InstallReferenceIdentifier = "{3f471841-eef2-47d6-89c0-d028f03a4ad5}";

		public const string SubscriptionStoreLock = "__SubscriptionStoreLock__";

		public const string IsShellVisible = "IsShellVisible";

		public const string CurrentBind = "CurrentBind";

		public const string PreviousBind = "PreviousBind";

		public const string PendingBind = "PendingBind";

		public const string ExcludedDeployment = "ExcludedDeployment";

		public const string PendingDeployment = "PendingDeployment";

		public const string DeploymentProviderUri = "DeploymentProviderUri";

		public const string MinimumRequiredVersion = "MinimumRequiredVersion";

		public const string LastCheckTime = "LastCheckTime";

		public const string UpdateSkipTime = "UpdateSkipTime";

		public const string UpdateSkippedDeployment = "UpdateSkippedDeployment";

		public const string AppType = "AppType";

		public const string UseApplicationManifestDescription = "UseApplicationManifestDescription";

		public const string DeploymentSourceUri = "DeploymentSourceUri";

		public const string ApplicationSourceUri = "ApplicationSourceUri";

		public const string IsFullTrust = "IsFullTrust";

		public const string CLRCoreComp = "Microsoft-Windows-CLRCoreComp";

		public const string CommonLanguageRuntime = "Microsoft.Windows.CommonLanguageRuntime";

		public const uint MinVersionCLRMajor = 2u;

		public const string MSIL = "msil";

		public const string X86 = "x86";

		public const string AMD64 = "amd64";

		public const string IA64 = "ia64";

		public const string AsmV1Namespace = "urn:schemas-microsoft-com:asm.v1";

		public const string AsmV2Namespace = "urn:schemas-microsoft-com:asm.v2";

		public const string XmlDSigNamespace = "http://www.w3.org/2000/09/xmldsig#";

		public const string AdaptiveSchemaResourceName = "manifest.2.0.0.15-pre.adaptive.xsd";

		public const string PublicIdForDTD4XMLSchemas = "-//W3C//DTD XMLSCHEMA 200102//EN";

		public const string XMLSchemaDTDResourceName = "XMLSchema.dtd";

		public const string PublicIdForDTD4DataTypes = "xs-datatypes";

		public const string DataTypesDTDResourceName = "datatypes.dtd";

		public const string UnsignedPublicKeyToken = "0000000000000000";

		public const string RequireAdministrator = "requireAdministrator";

		public const string HighestAvailable = "highestAvailable";

		public const int MaxNumberOfFilesInApplication = 24576;

		public const int MaxNumberOfFileAssociationsInApplication = 8;

		public const int MaxNumberOfFileExtensionLength = 24;

		public const int MaxNumberOfAssembliesInApplication = 24576;

		public const int MaxNumberOfGroupsInApplication = 49152;

		public const int MaxUrlLength = 16384;

		public const int MaxLiveActivation = 8;

		public const int MaxIdentityLength = 2048;

		public const int MaxAppIdLength = 65536;

		public const int MaxShortcutFileSize = 65536;

		public const int MaxManifestFileSize = 16777216;

		public const int MaxValueForMaximumAge = 365;

		public const int MaxErrorUrlLength = 2048;

		public const uint DefaultOnlineAppQuotaInKB = 256000u;

		public const int LifetimeDefaultMinutes = 10;

		public const int LockRetryIntervalMs = 1;

		public const int MinProgressCallbackIntervalInMs = 100;

		public const string DefaultLogTextualId = "__DeploymentDefaultLogFile__";

		public const int MAX_PATH = 260;

		public const string LogFileExtension = "log";

		public const string LogFilePathRegistryString = "LogFilePath";

		public const string WininetCacheLogUrlPrefix = "System_Deployment_Log_";

		public const string GACDetectionTempManifestAsmIdText = "GACDetectionTempManifest, version=1.0.0.0, type=win32";

		public const string DataDirectory = "DataDirectory";

		public const int HRESULT_DiskFull = -2147024784;

		public const uint MASK_NOTPINNABLE = 2147483648u;

		public const string Client35SP1SignatureAssembly = "Sentinel.v3.5Client, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a,processorArchitecture=msil";

		public const string Full35SP1SignatureAssembly = "System.Data.Entity, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089,processorArchitecture=msil";

		public const string DotNetFX35SP1 = ".NET Framework 3.5 SP1";

		public const string SkipSKUDetectionKeyName = "SOFTWARE\\Microsoft\\Fusion";

		public const string SkipSKUDetectionValueName = "NoClientChecks";

		public const int CLSCTX_INPROC_SERVER = 1;

		public static Guid DeploymentPropertySet = new Guid("2ad613da-6fdb-4671-af9e-18ab2e4df4d8");

		public static TimeSpan OnlineAppScavengingGracePeriod = TimeSpan.FromMinutes(1.0);

		public static TimeSpan LockTimeout = TimeSpan.FromMinutes(2.0);

		public static TimeSpan AssertApplicationRequirementsTimeout = TimeSpan.FromMinutes(2.0);

		public static Guid CLSID_StartMenuPin = new Guid("A2A9545D-A0C2-42B4-9708-A0B2BADD77C8");

		public static Guid IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046");

		public static Guid uuid = new Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe");
	}
	internal interface IDownloadNotification
	{
		void DownloadModified(object sender, DownloadEventArgs e);

		void DownloadCompleted(object sender, DownloadEventArgs e);
	}
	internal class DeploymentManager : IDisposable, IDownloadNotification
	{
		public enum CallerType
		{
			Other,
			ApplicationDeployment,
			InPlaceHostingManager
		}

		private static readonly object bindCompletedKey = new object();

		private static readonly object synchronizeCompletedKey = new object();

		private static readonly object progressChangedKey = new object();

		private readonly ThreadStart bindWorker;

		private readonly ThreadStart synchronizeWorker;

		private readonly WaitCallback synchronizeGroupWorker;

		private readonly SendOrPostCallback bindCompleted;

		private readonly SendOrPostCallback synchronizeCompleted;

		private readonly SendOrPostCallback progressReporter;

		private readonly AsyncOperation asyncOperation;

		private int _bindGuard;

		private int _syncGuard;

		private bool _cancellationPending;

		private bool _cached;

		private ManualResetEvent _trustNotGrantedEvent = new ManualResetEvent(initialState: false);

		private ManualResetEvent _platformRequirementsSucceededEvent = new ManualResetEvent(initialState: false);

		private ManualResetEvent _platformRequirementsFailedEvent = new ManualResetEvent(initialState: false);

		private ManualResetEvent[] _assertApplicationReqEvents;

		private CallerType _callerType;

		private Uri _deploySource;

		private DefinitionAppId _bindAppId;

		private SubscriptionStore _subStore;

		private bool _isupdate;

		private bool _isConfirmed = true;

		private DownloadOptions _downloadOptions;

		private EventHandlerList _events;

		private Hashtable _syncGroupMap;

		private ActivationDescription _actDesc;

		private ActivationContext _actCtx;

		private DeploymentProgressState _state = DeploymentProgressState.DownloadingApplicationFiles;

		private TempFile _tempDeployment;

		private TempDirectory _tempApplicationDirectory;

		private FileStream _referenceTransaction;

		private Logger.LogIdentity _log;

		private long _downloadedAppSize;

		public CallerType Callertype
		{
			get
			{
				return _callerType;
			}
			set
			{
				_callerType = value;
			}
		}

		public bool CancellationPending => _cancellationPending;

		public string ShortcutAppId
		{
			get
			{
				AssemblyManifest deployManifest = _actDesc.DeployManifest;
				SubscriptionState subscriptionState = _subStore.GetSubscriptionState(deployManifest);
				string result = null;
				if (subscriptionState.IsInstalled)
				{
					result = $"{subscriptionState.DeploymentProviderUri.AbsoluteUri}#{subscriptionState.SubscriptionId.ToString()}";
				}
				return result;
			}
		}

		public string LogFilePath
		{
			get
			{
				string result = Logger.GetLogFilePath(_log);
				if (!Logger.FlushLog(_log))
				{
					result = null;
				}
				return result;
			}
		}

		internal ActivationDescription ActivationDescription => _actDesc;

		private EventHandlerList Events => _events;

		public event BindCompletedEventHandler BindCompleted
		{
			add
			{
				Events.AddHandler(bindCompletedKey, value);
			}
			remove
			{
				Events.RemoveHandler(bindCompletedKey, value);
			}
		}

		public event SynchronizeCompletedEventHandler SynchronizeCompleted
		{
			add
			{
				Events.AddHandler(synchronizeCompletedKey, value);
			}
			remove
			{
				Events.RemoveHandler(synchronizeCompletedKey, value);
			}
		}

		public event DeploymentProgressChangedEventHandler ProgressChanged
		{
			add
			{
				Events.AddHandler(progressChangedKey, value);
			}
			remove
			{
				Events.RemoveHandler(progressChangedKey, value);
			}
		}

		[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
		public DeploymentManager(string appId)
			: this(appId, isUpdate: false, isConfirmed: true, null, null)
		{
			if (appId == null)
			{
				throw new ArgumentNullException("appId");
			}
		}

		[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
		public DeploymentManager(Uri deploymentSource)
			: this(deploymentSource, isUpdate: false, isConfirmed: true, null, null)
		{
			if (deploymentSource == null)
			{
				throw new ArgumentNullException("deploymentSource");
			}
			UriHelper.ValidateSupportedSchemeInArgument(deploymentSource, "deploymentSource");
		}

		internal DeploymentManager(Uri deploymentSource, bool isUpdate, bool isConfirmed, DownloadOptions downloadOptions, AsyncOperation optionalAsyncOp)
		{
			_deploySource = deploymentSource;
			_isupdate = isUpdate;
			_isConfirmed = isConfirmed;
			_downloadOptions = downloadOptions;
			_events = new EventHandlerList();
			_syncGroupMap = CollectionsUtil.CreateCaseInsensitiveHashtable();
			_subStore = SubscriptionStore.CurrentUser;
			bindWorker = BindAsyncWorker;
			synchronizeWorker = SynchronizeAsyncWorker;
			synchronizeGroupWorker = SynchronizeGroupAsyncWorker;
			bindCompleted = BindAsyncCompleted;
			synchronizeCompleted = SynchronizeAsyncCompleted;
			progressReporter = ProgressReporter;
			if (optionalAsyncOp == null)
			{
				asyncOperation = AsyncOperationManager.CreateOperation(null);
			}
			else
			{
				asyncOperation = optionalAsyncOp;
			}
			_log = Logger.StartLogging();
			if (deploymentSource != null)
			{
				Logger.SetSubscriptionUrl(_log, deploymentSource);
			}
			_assertApplicationReqEvents = new ManualResetEvent[3];
			_assertApplicationReqEvents[0] = _trustNotGrantedEvent;
			_assertApplicationReqEvents[1] = _platformRequirementsFailedEvent;
			_assertApplicationReqEvents[2] = _platformRequirementsSucceededEvent;
			_callerType = CallerType.Other;
			PolicyKeys.SkipApplicationDependencyHashCheck();
			PolicyKeys.SkipDeploymentProvider();
			PolicyKeys.SkipSchemaValidation();
			PolicyKeys.SkipSemanticValidation();
			PolicyKeys.SkipSignatureValidation();
		}

		internal DeploymentManager(string appId, bool isUpdate, bool isConfirmed, DownloadOptions downloadOptions, AsyncOperation optionalAsyncOp)
			: this((Uri)null, isUpdate, isConfirmed, downloadOptions, optionalAsyncOp)
		{
			_bindAppId = new DefinitionAppId(appId);
		}

		public void BindAsync()
		{
			if (!_cancellationPending)
			{
				if (Interlocked.Exchange(ref _bindGuard, 1) != 0)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_BindOnce"));
				}
				bindWorker.BeginInvoke(null, null);
			}
		}

		public ActivationContext Bind()
		{
			if (Interlocked.Exchange(ref _bindGuard, 1) != 0)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_BindOnce"));
			}
			bool flag = false;
			TempFile tempDeploy = null;
			TempDirectory tempAppDir = null;
			FileStream refTransaction = null;
			try
			{
				string productName = null;
				BindCore(blocking: true, ref tempDeploy, ref tempAppDir, ref refTransaction, ref productName);
			}
			catch (Exception)
			{
				flag = true;
				throw;
			}
			finally
			{
				_state = DeploymentProgressState.DownloadingApplicationFiles;
				if (flag)
				{
					tempAppDir?.Dispose();
					tempDeploy?.Dispose();
					refTransaction?.Close();
				}
			}
			return _actCtx;
		}

		public void DeterminePlatformRequirements()
		{
			try
			{
				if (_actDesc == null)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
				}
				DeterminePlatformRequirementsCore(blocking: true);
				_platformRequirementsSucceededEvent.Set();
			}
			catch (Exception)
			{
				_platformRequirementsFailedEvent.Set();
				throw;
			}
		}

		public void DetermineTrust(TrustParams trustParams)
		{
			try
			{
				if (_actDesc == null)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
				}
				DetermineTrustCore(blocking: true, trustParams);
			}
			catch (Exception)
			{
				_trustNotGrantedEvent.Set();
				throw;
			}
		}

		public void SynchronizeAsync()
		{
			if (!_cancellationPending)
			{
				if (_actDesc == null)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
				}
				if (Interlocked.Exchange(ref _syncGuard, 1) != 0)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_SyncNullOnce"));
				}
				synchronizeWorker.BeginInvoke(null, null);
			}
		}

		public void Synchronize()
		{
			if (_actDesc == null)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
			}
			if (Interlocked.Exchange(ref _syncGuard, 1) != 0)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SyncNullOnce"));
			}
			SynchronizeCore(blocking: true);
		}

		public void SynchronizeAsync(string groupName)
		{
			SynchronizeAsync(groupName, null);
		}

		public void SynchronizeAsync(string groupName, object userState)
		{
			if (groupName == null)
			{
				SynchronizeAsync();
				return;
			}
			if (_actDesc == null)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
			}
			if (!_cached)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SyncNullFirst"));
			}
			bool created;
			SyncGroupHelper state = AttachToGroup(groupName, userState, out created);
			if (created)
			{
				ThreadPool.QueueUserWorkItem(synchronizeGroupWorker, state);
				return;
			}
			throw new InvalidOperationException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_SyncGroupOnce"), groupName));
		}

		public void Synchronize(string groupName)
		{
			if (groupName == null)
			{
				Synchronize();
				return;
			}
			if (_actDesc == null)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
			}
			if (!_cached)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SyncNullFirst"));
			}
			bool created;
			SyncGroupHelper sgh = AttachToGroup(groupName, null, out created);
			if (created)
			{
				SynchronizeGroupCore(blocking: true, sgh);
				return;
			}
			throw new InvalidOperationException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_SyncGroupOnce"), groupName));
		}

		public ObjectHandle ExecuteNewDomain()
		{
			if (_actDesc == null)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
			}
			if (!_cached)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SyncNullFirst"));
			}
			return Activator.CreateInstance(_actCtx);
		}

		public void ExecuteNewProcess()
		{
			if (_actDesc == null)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_BindFirst"));
			}
			if (!_cached)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_SyncNullFirst"));
			}
			_subStore.ActivateApplication(_actDesc.AppId, null, useActivationParameter: false);
		}

		public void CancelAsync()
		{
			_cancellationPending = true;
		}

		public void CancelAsync(string groupName)
		{
			if (groupName == null)
			{
				CancelAsync();
				return;
			}
			lock (_syncGroupMap.SyncRoot)
			{
				((SyncGroupHelper)_syncGroupMap[groupName])?.CancelAsync();
			}
		}

		public void Dispose()
		{
			_events.Dispose();
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		void IDownloadNotification.DownloadModified(object sender, DownloadEventArgs e)
		{
			if (_cancellationPending)
			{
				((FileDownloader)sender).Cancel();
			}
			asyncOperation.Post(progressReporter, new DeploymentProgressChangedEventArgs(e.Progress, null, e.BytesCompleted, e.BytesTotal, _state, null));
		}

		void IDownloadNotification.DownloadCompleted(object sender, DownloadEventArgs e)
		{
			_downloadedAppSize = e.BytesCompleted;
		}

		private void BindAsyncCompleted(object arg)
		{
			BindCompletedEventArgs e = (BindCompletedEventArgs)arg;
			((BindCompletedEventHandler)Events[bindCompletedKey])?.Invoke(this, e);
		}

		private void SynchronizeAsyncCompleted(object arg)
		{
			SynchronizeCompletedEventArgs e = (SynchronizeCompletedEventArgs)arg;
			((SynchronizeCompletedEventHandler)Events[synchronizeCompletedKey])?.Invoke(this, e);
		}

		private void ProgressReporter(object arg)
		{
			DeploymentProgressChangedEventArgs e = (DeploymentProgressChangedEventArgs)arg;
			((DeploymentProgressChangedEventHandler)Events[progressChangedKey])?.Invoke(this, e);
		}

		private void BindAsyncWorker()
		{
			Exception ex = null;
			bool flag = false;
			string productName = null;
			TempFile tempDeploy = null;
			TempDirectory tempAppDir = null;
			FileStream refTransaction = null;
			try
			{
				flag = BindCore(blocking: false, ref tempDeploy, ref tempAppDir, ref refTransaction, ref productName);
			}
			catch (Exception ex2)
			{
				if (ex2 is DownloadCancelledException)
				{
					flag = true;
				}
				else
				{
					ex = ex2;
				}
			}
			finally
			{
				_state = DeploymentProgressState.DownloadingApplicationFiles;
				if (ex != null || flag)
				{
					tempAppDir?.Dispose();
					tempDeploy?.Dispose();
					refTransaction?.Close();
				}
				BindCompletedEventArgs arg = new BindCompletedEventArgs(ex, flag, null, _actCtx, productName, _cached);
				asyncOperation.Post(bindCompleted, arg);
			}
		}

		private bool BindCore(bool blocking, ref TempFile tempDeploy, ref TempDirectory tempAppDir, ref FileStream refTransaction, ref string productName)
		{
			try
			{
				if (_deploySource == null)
				{
					return BindCoreWithAppId(blocking, ref refTransaction, ref productName);
				}
				bool flag = false;
				AssemblyManifest assemblyManifest = null;
				string text = null;
				Uri sourceUri = _deploySource;
				_state = DeploymentProgressState.DownloadingDeploymentInformation;
				assemblyManifest = DownloadManager.DownloadDeploymentManifest(_subStore, ref sourceUri, out tempDeploy, blocking ? null : this, _downloadOptions);
				text = tempDeploy.Path;
				ActivationDescription activationDescription = new ActivationDescription();
				activationDescription.SetDeploymentManifest(assemblyManifest, sourceUri, text);
				Logger.SetDeploymentManifest(_log, assemblyManifest);
				activationDescription.IsUpdate = _isupdate;
				if (activationDescription.DeployManifest.Deployment == null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_NotDeploymentOrShortcut"));
				}
				if (!blocking && _cancellationPending)
				{
					return true;
				}
				refTransaction = _subStore.AcquireReferenceTransaction(out var transactionId);
				SubscriptionState subscriptionState = _subStore.GetSubscriptionState(activationDescription.DeployManifest);
				if (activationDescription.DeployManifest.Deployment.Install && activationDescription.DeployManifest.Deployment.ProviderCodebaseUri == null && subscriptionState != null && subscriptionState.DeploymentProviderUri != null && !subscriptionState.DeploymentProviderUri.Equals(sourceUri))
				{
					throw new DeploymentException(ExceptionTypes.DeploymentUriDifferent, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DeploymentUriDifferentExText"), activationDescription.DeployManifest.Description.FilteredProduct, sourceUri.AbsoluteUri, subscriptionState.DeploymentProviderUri.AbsoluteUri));
				}
				DefinitionAppId definitionAppId = null;
				try
				{
					definitionAppId = new DefinitionAppId(activationDescription.ToAppCodebase(), activationDescription.DeployManifest.Identity, new DefinitionIdentity(activationDescription.DeployManifest.MainDependentAssembly.Identity));
				}
				catch (COMException innerException)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_IdentityIsNotValid"), innerException);
				}
				catch (SEHException innerException2)
				{
					throw new InvalidDeploymentException(ExceptionTypes.InvalidManifest, Resources.GetString("Ex_IdentityIsNotValid"), innerException2);
				}
				if (_subStore.CheckAndReferenceApplication(subscriptionState, definitionAppId, transactionId) && definitionAppId.Equals(subscriptionState.CurrentBind))
				{
					_bindAppId = definitionAppId;
					return BindCoreWithAppId(blocking, ref refTransaction, ref productName);
				}
				if (!blocking && _cancellationPending)
				{
					return true;
				}
				_state = DeploymentProgressState.DownloadingApplicationInformation;
				tempAppDir = _subStore.AcquireTempDirectory();
				Uri appSourceUri;
				string appManifestPath;
				AssemblyManifest assemblyManifest2 = DownloadManager.DownloadApplicationManifest(activationDescription.DeployManifest, tempAppDir.Path, activationDescription.DeploySourceUri, blocking ? null : this, _downloadOptions, out appSourceUri, out appManifestPath);
				AssemblyManifest.ReValidateManifestSignatures(activationDescription.DeployManifest, assemblyManifest2);
				Logger.SetApplicationManifest(_log, assemblyManifest2);
				Logger.SetApplicationUrl(_log, appSourceUri);
				activationDescription.SetApplicationManifest(assemblyManifest2, appSourceUri, appManifestPath);
				activationDescription.AppId = new DefinitionAppId(activationDescription.ToAppCodebase(), activationDescription.DeployManifest.Identity, activationDescription.AppManifest.Identity);
				flag = _subStore.CheckAndReferenceApplication(subscriptionState, activationDescription.AppId, transactionId);
				if (!blocking && _cancellationPending)
				{
					return true;
				}
				Description effectiveDescription = activationDescription.EffectiveDescription;
				productName = effectiveDescription.Product;
				_cached = flag;
				_tempApplicationDirectory = tempAppDir;
				_tempDeployment = tempDeploy;
				_referenceTransaction = refTransaction;
				_actCtx = ConstructActivationContext(activationDescription);
				_actDesc = activationDescription;
			}
			catch (Exception ex)
			{
				LogError(Resources.GetString("Ex_FailedToDownloadManifest"), ex);
				throw;
			}
			return false;
		}

		private bool BindCoreWithAppId(bool blocking, ref FileStream refTransaction, ref string productName)
		{
			bool flag = false;
			DefinitionIdentity subId = _bindAppId.DeploymentIdentity.ToSubscriptionId();
			SubscriptionState subscriptionState = _subStore.GetSubscriptionState(subId);
			if (!subscriptionState.IsInstalled)
			{
				throw new InvalidDeploymentException(Resources.GetString("Ex_BindAppIdNotInstalled"));
			}
			if (!_bindAppId.Equals(subscriptionState.CurrentBind))
			{
				throw new InvalidDeploymentException(Resources.GetString("Ex_BindAppIdNotCurrrent"));
			}
			if (!blocking && _cancellationPending)
			{
				return true;
			}
			refTransaction = _subStore.AcquireReferenceTransaction(out var transactionId);
			flag = _subStore.CheckAndReferenceApplication(subscriptionState, _bindAppId, transactionId);
			ActivationDescription activationDescription = new ActivationDescription();
			activationDescription.SetDeploymentManifest(subscriptionState.CurrentDeploymentManifest, subscriptionState.CurrentDeploymentSourceUri, null);
			Logger.SetDeploymentManifest(_log, subscriptionState.CurrentDeploymentManifest);
			activationDescription.IsUpdate = _isupdate;
			activationDescription.SetApplicationManifest(subscriptionState.CurrentApplicationManifest, subscriptionState.CurrentApplicationSourceUri, null);
			Logger.SetApplicationManifest(_log, subscriptionState.CurrentApplicationManifest);
			Logger.SetApplicationUrl(_log, subscriptionState.CurrentApplicationSourceUri);
			activationDescription.AppId = new DefinitionAppId(activationDescription.ToAppCodebase(), activationDescription.DeployManifest.Identity, activationDescription.AppManifest.Identity);
			if (!blocking && _cancellationPending)
			{
				return true;
			}
			Description effectiveDescription = subscriptionState.EffectiveDescription;
			productName = effectiveDescription.Product;
			_cached = flag;
			_referenceTransaction = refTransaction;
			_actCtx = ConstructActivationContextFromStore(activationDescription.AppId);
			_actDesc = activationDescription;
			return false;
		}

		private bool DeterminePlatformRequirementsCore(bool blocking)
		{
			try
			{
				if (!blocking && _cancellationPending)
				{
					return true;
				}
				using TempDirectory tempDirectory = _subStore.AcquireTempDirectory();
				PlatformDetector.VerifyPlatformDependencies(_actDesc.AppManifest, _actDesc.DeployManifest.Description.SupportUri, tempDirectory.Path);
			}
			catch (Exception ex)
			{
				LogError(Resources.GetString("Ex_DeterminePlatformRequirementsFailed"), ex);
				throw;
			}
			return false;
		}

		private bool DetermineTrustCore(bool blocking, TrustParams tp)
		{
			try
			{
				SubscriptionState subscriptionState = _subStore.GetSubscriptionState(_actDesc.DeployManifest);
				TrustManagerContext trustManagerContext = new TrustManagerContext();
				trustManagerContext.IgnorePersistedDecision = false;
				trustManagerContext.NoPrompt = false;
				trustManagerContext.Persist = true;
				if (tp != null)
				{
					trustManagerContext.NoPrompt = tp.NoPrompt;
				}
				if (!blocking && _cancellationPending)
				{
					return true;
				}
				if (subscriptionState.IsInstalled && !string.Equals(subscriptionState.EffectiveCertificatePublicKeyToken, _actDesc.EffectiveCertificatePublicKeyToken, StringComparison.Ordinal))
				{
					ApplicationTrust.RemoveCachedTrust(subscriptionState.CurrentBind);
				}
				_actDesc.Trust = ApplicationTrust.RequestTrust(subscriptionState, _actDesc.DeployManifest.Deployment.Install, _actDesc.IsUpdate, _actCtx, trustManagerContext);
			}
			catch (Exception ex)
			{
				LogError(Resources.GetString("Ex_DetermineTrustFailed"), ex);
				throw;
			}
			return false;
		}

		public void PersistTrustWithoutEvaluation()
		{
			_actDesc.Trust = ApplicationTrust.PersistTrustWithoutEvaluation(_actCtx);
		}

		private void SynchronizeAsyncWorker()
		{
			Exception error = null;
			bool cancelled = false;
			try
			{
				cancelled = SynchronizeCore(blocking: false);
			}
			catch (Exception ex)
			{
				if (ex is DownloadCancelledException)
				{
					cancelled = true;
				}
				else
				{
					error = ex;
				}
			}
			finally
			{
				SynchronizeCompletedEventArgs arg = new SynchronizeCompletedEventArgs(error, cancelled, null, null);
				asyncOperation.Post(synchronizeCompleted, arg);
			}
		}

		private bool SynchronizeCore(bool blocking)
		{
			try
			{
				AssemblyManifest deployManifest = _actDesc.DeployManifest;
				SubscriptionState subState = _subStore.GetSubscriptionState(deployManifest);
				_subStore.CheckDeploymentSubscriptionState(subState, deployManifest);
				_subStore.CheckCustomUXFlag(subState, _actDesc.AppManifest);
				if (_actDesc.DeployManifestPath != null)
				{
					_actDesc.CommitDeploy = true;
					_actDesc.IsConfirmed = _isConfirmed;
					_actDesc.TimeStamp = DateTime.UtcNow;
				}
				else
				{
					_actDesc.CommitDeploy = false;
				}
				if (!blocking && _cancellationPending)
				{
					return true;
				}
				if (!_cached)
				{
					bool flag = false;
					if (_actDesc.appType != AppType.CustomHostSpecified)
					{
						if (_actDesc.Trust != null)
						{
							bool flag2 = _actDesc.Trust.DefaultGrantSet.PermissionSet.IsUnrestricted();
							if (!flag2 && _actDesc.AppManifest.FileAssociations.Length > 0)
							{
								throw new DeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_FileExtensionNotSupported"));
							}
							bool flag3 = !_actDesc.DeployManifest.Deployment.Install;
							if (!flag2 && flag3)
							{
								if (_downloadOptions == null)
								{
									_downloadOptions = new DownloadOptions();
								}
								_downloadOptions.EnforceSizeLimit = true;
								_downloadOptions.SizeLimit = _subStore.GetSizeLimitInBytesForSemiTrustApps();
								_downloadOptions.Size = _actDesc.DeployManifest.SizeInBytes + _actDesc.AppManifest.SizeInBytes;
							}
						}
						else
						{
							flag = true;
						}
					}
					DownloadManager.DownloadDependencies(subState, _actDesc.DeployManifest, _actDesc.AppManifest, _actDesc.AppSourceUri, _tempApplicationDirectory.Path, null, blocking ? null : this, _downloadOptions);
					if (!blocking && _cancellationPending)
					{
						return true;
					}
					WaitForAssertApplicationRequirements();
					if (flag)
					{
						CheckSizeLimit();
					}
					_actDesc.CommitApp = true;
					_actDesc.AppPayloadPath = _tempApplicationDirectory.Path;
				}
				if (_actDesc.CommitDeploy || _actDesc.CommitApp)
				{
					_subStore.CommitApplication(ref subState, _actDesc);
				}
				if (_tempApplicationDirectory != null)
				{
					_tempApplicationDirectory.Dispose();
					_tempApplicationDirectory = null;
				}
				if (_tempDeployment != null)
				{
					_tempDeployment.Dispose();
					_tempDeployment = null;
				}
				if (_referenceTransaction != null)
				{
					_referenceTransaction.Close();
					_referenceTransaction = null;
				}
				ActivationContext actCtx = _actCtx;
				_actCtx = ConstructActivationContextFromStore(_actDesc.AppId);
				actCtx.Dispose();
				_cached = true;
			}
			catch (Exception ex)
			{
				LogError(Resources.GetString("Ex_DownloadApplicationFailed"), ex);
				throw;
			}
			return false;
		}

		private void WaitForAssertApplicationRequirements()
		{
			if (_actDesc.appType != AppType.CustomHostSpecified && _callerType != CallerType.ApplicationDeployment)
			{
				switch (WaitHandle.WaitAny(_assertApplicationReqEvents, Constants.AssertApplicationRequirementsTimeout, exitContext: false))
				{
				case 258:
					throw new DeploymentException(Resources.GetString("Ex_CannotCommitNoTrustDecision"));
				case 0:
					throw new DeploymentException(Resources.GetString("Ex_CannotCommitTrustFailed"));
				case 1:
					throw new DeploymentException(Resources.GetString("Ex_CannotCommitPlatformRequirementsFailed"));
				}
			}
		}

		private void CheckSizeLimit()
		{
			if (_actDesc.appType == AppType.CustomHostSpecified)
			{
				return;
			}
			bool flag = _actDesc.Trust.DefaultGrantSet.PermissionSet.IsUnrestricted();
			bool flag2 = !_actDesc.DeployManifest.Deployment.Install;
			if (!flag && flag2)
			{
				ulong sizeLimitInBytesForSemiTrustApps = _subStore.GetSizeLimitInBytesForSemiTrustApps();
				if ((ulong)_downloadedAppSize > sizeLimitInBytesForSemiTrustApps)
				{
					throw new DeploymentDownloadException(ExceptionTypes.SizeLimitForPartialTrustOnlineAppExceeded, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_OnlineSemiTrustAppSizeLimitExceeded"), sizeLimitInBytesForSemiTrustApps));
				}
			}
		}

		private void SynchronizeGroupAsyncWorker(object arg)
		{
			Exception error = null;
			bool cancelled = false;
			string groupName = null;
			object userState = null;
			try
			{
				SyncGroupHelper syncGroupHelper = (SyncGroupHelper)arg;
				groupName = syncGroupHelper.Group;
				userState = syncGroupHelper.UserState;
				cancelled = SynchronizeGroupCore(blocking: false, syncGroupHelper);
			}
			catch (Exception ex)
			{
				if (ex is DownloadCancelledException)
				{
					cancelled = true;
				}
				else
				{
					error = ex;
				}
			}
			finally
			{
				SynchronizeCompletedEventArgs arg2 = new SynchronizeCompletedEventArgs(error, cancelled, userState, groupName);
				asyncOperation.Post(synchronizeCompleted, arg2);
			}
		}

		private bool SynchronizeGroupCore(bool blocking, SyncGroupHelper sgh)
		{
			TempDirectory tempDirectory = null;
			try
			{
				string group = sgh.Group;
				SubscriptionState subState = _subStore.GetSubscriptionState(_actDesc.DeployManifest);
				if (_subStore.CheckGroupInstalled(subState, _actDesc.AppId, _actDesc.AppManifest, group))
				{
					return false;
				}
				bool flag = AppDomain.CurrentDomain.ApplicationTrust.DefaultGrantSet.PermissionSet.IsUnrestricted();
				if (!flag && _actDesc.AppManifest.FileAssociations.Length > 0)
				{
					throw new DeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_FileExtensionNotSupported"));
				}
				bool flag2 = !_actDesc.DeployManifest.Deployment.Install;
				if (!flag && flag2)
				{
					if (_downloadOptions == null)
					{
						_downloadOptions = new DownloadOptions();
					}
					_downloadOptions.EnforceSizeLimit = true;
					_downloadOptions.SizeLimit = _subStore.GetSizeLimitInBytesForSemiTrustApps();
					_downloadOptions.Size = _subStore.GetPrivateSize(_actDesc.AppId);
				}
				tempDirectory = _subStore.AcquireTempDirectory();
				DownloadManager.DownloadDependencies(subState, _actDesc.DeployManifest, _actDesc.AppManifest, _actDesc.AppSourceUri, tempDirectory.Path, group, blocking ? null : sgh, _downloadOptions);
				if (!blocking && sgh.CancellationPending)
				{
					return true;
				}
				CommitApplicationParams commitApplicationParams = new CommitApplicationParams(_actDesc);
				commitApplicationParams.CommitApp = true;
				commitApplicationParams.AppPayloadPath = tempDirectory.Path;
				commitApplicationParams.AppManifestPath = null;
				commitApplicationParams.AppGroup = group;
				commitApplicationParams.CommitDeploy = false;
				_subStore.CommitApplication(ref subState, commitApplicationParams);
			}
			finally
			{
				DetachFromGroup(sgh);
				tempDirectory?.Dispose();
			}
			return false;
		}

		private SyncGroupHelper AttachToGroup(string groupName, object userState, out bool created)
		{
			created = false;
			SyncGroupHelper syncGroupHelper = null;
			lock (_syncGroupMap.SyncRoot)
			{
				syncGroupHelper = (SyncGroupHelper)_syncGroupMap[groupName];
				if (syncGroupHelper == null)
				{
					syncGroupHelper = new SyncGroupHelper(groupName, userState, asyncOperation, progressReporter);
					_syncGroupMap[groupName] = syncGroupHelper;
					created = true;
					return syncGroupHelper;
				}
				return syncGroupHelper;
			}
		}

		private void DetachFromGroup(SyncGroupHelper sgh)
		{
			string group = sgh.Group;
			lock (_syncGroupMap.SyncRoot)
			{
				_syncGroupMap.Remove(group);
			}
			sgh.SetComplete();
		}

		private void Dispose(bool disposing)
		{
			if (disposing)
			{
				Logger.EndLogging(_log);
				if (_tempDeployment != null)
				{
					_tempDeployment.Dispose();
				}
				if (_tempApplicationDirectory != null)
				{
					_tempApplicationDirectory.Dispose();
				}
				if (_referenceTransaction != null)
				{
					_referenceTransaction.Close();
				}
				if (_actCtx != null)
				{
					_actCtx.Dispose();
				}
				if (_events != null)
				{
					_events.Dispose();
				}
			}
		}

		private static ActivationContext ConstructActivationContext(ActivationDescription actDesc)
		{
			ApplicationIdentity identity = actDesc.AppId.ToApplicationIdentity();
			return ActivationContext.CreatePartialActivationContext(identity, new string[2] { actDesc.DeployManifestPath, actDesc.AppManifestPath });
		}

		private static ActivationContext ConstructActivationContextFromStore(DefinitionAppId defAppId)
		{
			return ActivationContext.CreatePartialActivationContext(defAppId.ToApplicationIdentity());
		}

		private void LogError(string message, Exception ex)
		{
			Logger.AddErrorInformation(_log, message, ex);
			Logger.FlushLog(_log);
		}
	}
	internal class TrustParams
	{
		private bool noPrompt;

		public bool NoPrompt
		{
			get
			{
				return noPrompt;
			}
			set
			{
				noPrompt = value;
			}
		}
	}
	internal delegate void BindCompletedEventHandler(object sender, BindCompletedEventArgs e);
	internal class BindCompletedEventArgs : AsyncCompletedEventArgs
	{
		private readonly ActivationContext _actCtx;

		private readonly string _name;

		private readonly bool _cached;

		public ActivationContext ActivationContext
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _actCtx;
			}
		}

		public string FriendlyName
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _name;
			}
		}

		public bool IsCached
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _cached;
			}
		}

		internal BindCompletedEventArgs(Exception error, bool cancelled, object userState, ActivationContext actCtx, string name, bool cached)
			: base(error, cancelled, userState)
		{
			_actCtx = actCtx;
			_name = name;
			_cached = cached;
		}
	}
	internal delegate void SynchronizeCompletedEventHandler(object sender, SynchronizeCompletedEventArgs e);
	internal class SynchronizeCompletedEventArgs : AsyncCompletedEventArgs
	{
		private readonly string _groupName;

		public string Group => _groupName;

		internal SynchronizeCompletedEventArgs(Exception error, bool cancelled, object userState, string groupName)
			: base(error, cancelled, userState)
		{
			_groupName = groupName;
		}
	}
	public delegate void DeploymentProgressChangedEventHandler(object sender, DeploymentProgressChangedEventArgs e);
	public class DeploymentProgressChangedEventArgs : ProgressChangedEventArgs
	{
		private readonly long _bytesCompleted;

		private readonly long _bytesTotal;

		private readonly DeploymentProgressState _state;

		private readonly string _groupName;

		public long BytesCompleted => _bytesCompleted;

		public long BytesTotal => _bytesTotal;

		public DeploymentProgressState State => _state;

		public string Group => _groupName;

		internal DeploymentProgressChangedEventArgs(int progressPercentage, object userState, long bytesCompleted, long bytesTotal, DeploymentProgressState state, string groupName)
			: base(progressPercentage, userState)
		{
			_bytesCompleted = bytesCompleted;
			_bytesTotal = bytesTotal;
			_state = state;
			_groupName = groupName;
		}
	}
	public enum DeploymentProgressState
	{
		DownloadingDeploymentInformation,
		DownloadingApplicationInformation,
		DownloadingApplicationFiles
	}
	internal class SyncGroupHelper : IDownloadNotification
	{
		private readonly string groupName;

		private readonly object userState;

		private readonly AsyncOperation asyncOperation;

		private readonly SendOrPostCallback progressReporter;

		private bool _cancellationPending;

		public bool CancellationPending => _cancellationPending;

		public string Group => groupName;

		public object UserState => userState;

		public SyncGroupHelper(string groupName, object userState, AsyncOperation asyncOp, SendOrPostCallback progressReporterDelegate)
		{
			if (groupName == null)
			{
				throw new ArgumentNullException("groupName");
			}
			this.groupName = groupName;
			this.userState = userState;
			asyncOperation = asyncOp;
			progressReporter = progressReporterDelegate;
		}

		public void SetComplete()
		{
		}

		public void CancelAsync()
		{
			_cancellationPending = true;
		}

		public void DownloadModified(object sender, DownloadEventArgs e)
		{
			if (_cancellationPending)
			{
				((FileDownloader)sender).Cancel();
			}
			asyncOperation.Post(progressReporter, new DeploymentProgressChangedEventArgs(e.Progress, userState, e.BytesCompleted, e.BytesTotal, DeploymentProgressState.DownloadingApplicationFiles, groupName));
		}

		public void DownloadCompleted(object sender, DownloadEventArgs e)
		{
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	[Guid("33246f92-d56f-4e34-837a-9a49bfc91df3")]
	[ClassInterface(ClassInterfaceType.AutoDispatch)]
	[ComVisible(true)]
	[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
	public class DeploymentServiceCom
	{
		public DeploymentServiceCom()
		{
			LifetimeManager.ExtendLifetime();
		}

		public void ActivateDeployment(string deploymentLocation, bool isShortcut)
		{
			new ApplicationActivator().ActivateDeployment(deploymentLocation, isShortcut);
		}

		public void ActivateDeploymentEx(string deploymentLocation, int unsignedPolicy, int signedPolicy)
		{
			new ApplicationActivator().ActivateDeploymentEx(deploymentLocation, unsignedPolicy, signedPolicy);
		}

		public void ActivateApplicationExtension(string textualSubId, string deploymentProviderUrl, string targetAssociatedFile)
		{
			new ApplicationActivator().ActivateApplicationExtension(textualSubId, deploymentProviderUrl, targetAssociatedFile);
		}

		public void MaintainSubscription(string textualSubId)
		{
			LifetimeManager.StartOperation();
			try
			{
				MaintainSubscriptionInternal(textualSubId);
			}
			finally
			{
				LifetimeManager.EndOperation();
			}
		}

		public void CheckForDeploymentUpdate(string textualSubId)
		{
			LifetimeManager.StartOperation();
			try
			{
				CheckForDeploymentUpdateInternal(textualSubId);
			}
			finally
			{
				LifetimeManager.EndOperation();
			}
		}

		public void EndServiceRightNow()
		{
			LifetimeManager.EndImmediately();
		}

		public void CleanOnlineAppCache()
		{
			LifetimeManager.StartOperation();
			try
			{
				CleanOnlineAppCacheInternal();
			}
			finally
			{
				LifetimeManager.EndOperation();
			}
		}

		private void MaintainSubscriptionInternal(string textualSubId)
		{
			bool flag = false;
			string[] array = new string[4] { "Maintain_Exception", "Maintain_Completed", "Maintain_Failed", "Maintain_FailedMsg" };
			bool flag2 = false;
			Exception ex = null;
			bool flag3 = false;
			bool flag4 = false;
			string @string = Resources.GetString("ErrorMessage_GenericLinkUrlMessage");
			string text = null;
			string text2 = null;
			Logger.StartCurrentThreadLogging();
			Logger.SetTextualSubscriptionIdentity(textualSubId);
			using UserInterface userInterface = new UserInterface();
			MaintenanceInfo maintenanceInfo = new MaintenanceInfo();
			try
			{
				UserInterfaceInfo userInterfaceInfo = new UserInterfaceInfo();
				Logger.AddPhaseInformation(Resources.GetString("PhaseLog_StoreQueryForMaintenanceInfo"));
				SubscriptionState subscriptionState = GetSubscriptionState(textualSubId);
				try
				{
					subscriptionState.SubscriptionStore.CheckInstalledAndShellVisible(subscriptionState);
					if (subscriptionState.RollbackDeployment == null)
					{
						maintenanceInfo.maintenanceFlags |= MaintenanceFlags.RemoveSelected;
					}
					else
					{
						maintenanceInfo.maintenanceFlags |= MaintenanceFlags.RestorationPossible;
						maintenanceInfo.maintenanceFlags |= MaintenanceFlags.RestoreSelected;
					}
					AssemblyManifest currentDeploymentManifest = subscriptionState.CurrentDeploymentManifest;
					if (currentDeploymentManifest != null && currentDeploymentManifest.Description != null)
					{
						text2 = currentDeploymentManifest.Description.ErrorReportUrl;
					}
					Description effectiveDescription = subscriptionState.EffectiveDescription;
					userInterfaceInfo.productName = effectiveDescription.Product;
					userInterfaceInfo.supportUrl = effectiveDescription.SupportUrl;
					userInterfaceInfo.formTitle = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_MaintenanceTitle"), userInterfaceInfo.productName);
					flag3 = true;
				}
				catch (DeploymentException exception)
				{
					flag3 = false;
					Logger.AddErrorInformation(Resources.GetString("MaintainLogMsg_FailedStoreLookup"), exception);
					maintenanceInfo.maintenanceFlags |= MaintenanceFlags.RemoveSelected;
				}
				catch (FormatException exception2)
				{
					flag3 = false;
					Logger.AddErrorInformation(Resources.GetString("MaintainLogMsg_FailedStoreLookup"), exception2);
					maintenanceInfo.maintenanceFlags |= MaintenanceFlags.RemoveSelected;
				}
				bool flag5 = false;
				if (flag3)
				{
					if (userInterface.ShowMaintenance(userInterfaceInfo, maintenanceInfo) == UserInterfaceModalResult.Ok)
					{
						flag5 = true;
					}
				}
				else
				{
					maintenanceInfo.maintenanceFlags = MaintenanceFlags.RemoveSelected;
					flag5 = true;
				}
				if (!flag5)
				{
					return;
				}
				flag2 = true;
				if ((maintenanceInfo.maintenanceFlags & MaintenanceFlags.RestoreSelected) != 0)
				{
					array = new string[4] { "Rollback_Exception", "Rollback_Completed", "Rollback_Failed", "Rollback_FailedMsg" };
					subscriptionState.SubscriptionStore.RollbackSubscription(subscriptionState);
					flag2 = false;
					userInterface.ShowMessage(Resources.GetString("UI_RollbackCompletedMsg"), Resources.GetString("UI_RollbackCompletedTitle"));
				}
				else if ((maintenanceInfo.maintenanceFlags & MaintenanceFlags.RemoveSelected) != 0)
				{
					array = new string[4] { "Uninstall_Exception", "Uninstall_Completed", "Uninstall_Failed", "Uninstall_FailedMsg" };
					try
					{
						subscriptionState.SubscriptionStore.UninstallSubscription(subscriptionState);
						flag2 = false;
					}
					catch (DeploymentException exception3)
					{
						Logger.AddErrorInformation(Resources.GetString("MaintainLogMsg_UninstallFailed"), exception3);
						flag4 = true;
						ShellExposure.RemoveSubscriptionShellExposure(subscriptionState);
						flag4 = false;
					}
				}
				flag = true;
			}
			catch (DeploymentException ex2)
			{
				Logger.AddErrorInformation(ex2, Resources.GetString(array[0]), textualSubId);
				ex = ex2;
			}
			finally
			{
				Logger.AddPhaseInformation(Resources.GetString(flag ? array[1] : array[2]), textualSubId);
				if (((maintenanceInfo.maintenanceFlags & MaintenanceFlags.RestoreSelected) != 0 && flag2) || ((maintenanceInfo.maintenanceFlags & MaintenanceFlags.RemoveSelected) != 0 && flag4 && flag2))
				{
					string logFileLocation = Logger.GetLogFilePath();
					if (!Logger.FlushCurrentThreadLogs())
					{
						logFileLocation = null;
					}
					if (text2 != null && ex != null)
					{
						Exception innerMostException = GetInnerMostException(ex);
						text = $"{text2}?outer={ex.GetType().ToString()}&&inner={innerMostException.GetType().ToString()}&&msg={innerMostException.Message}";
						if (text.Length > 2048)
						{
							text = text.Substring(0, 2048);
						}
					}
					userInterface.ShowError(Resources.GetString("UI_MaintenceErrorTitle"), Resources.GetString(array[3]), logFileLocation, text, @string);
				}
				Logger.EndCurrentThreadLogging();
			}
		}

		private void CheckForDeploymentUpdateInternal(string textualSubId)
		{
			bool flag = false;
			Logger.StartCurrentThreadLogging();
			Logger.SetTextualSubscriptionIdentity(textualSubId);
			try
			{
				SubscriptionState shellVisibleSubscriptionState = GetShellVisibleSubscriptionState(textualSubId);
				shellVisibleSubscriptionState.SubscriptionStore.CheckForDeploymentUpdate(shellVisibleSubscriptionState);
				flag = true;
			}
			catch (DeploymentException exception)
			{
				Logger.AddErrorInformation(Resources.GetString("Upd_Exception"), exception);
			}
			finally
			{
				Logger.AddPhaseInformation(Resources.GetString(flag ? "Upd_Completed" : "Upd_Failed"));
				Logger.EndCurrentThreadLogging();
			}
		}

		private void CleanOnlineAppCacheInternal()
		{
			bool flag = false;
			Logger.StartCurrentThreadLogging();
			try
			{
				SubscriptionStore.CurrentUser.CleanOnlineAppCache();
				flag = true;
			}
			catch (Exception exception)
			{
				Logger.AddErrorInformation(Resources.GetString("Ex_CleanOnlineAppCache"), exception);
				throw;
			}
			finally
			{
				Logger.AddPhaseInformation(Resources.GetString(flag ? "CleanOnlineCache_Completed" : "CleanOnlineCache_Failed"));
				Logger.EndCurrentThreadLogging();
			}
		}

		private SubscriptionState GetShellVisibleSubscriptionState(string textualSubId)
		{
			SubscriptionState subscriptionState = GetSubscriptionState(textualSubId);
			subscriptionState.SubscriptionStore.CheckInstalledAndShellVisible(subscriptionState);
			return subscriptionState;
		}

		private SubscriptionState GetSubscriptionState(string textualSubId)
		{
			if (textualSubId == null)
			{
				throw new ArgumentNullException("textualSubId", Resources.GetString("Ex_ComArgSubIdentityNull"));
			}
			DefinitionIdentity definitionIdentity = null;
			try
			{
				definitionIdentity = new DefinitionIdentity(textualSubId);
			}
			catch (COMException innerException)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), textualSubId), innerException);
			}
			catch (SEHException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), textualSubId), innerException2);
			}
			if (definitionIdentity.Version != null)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_ComArgSubIdentityWithVersion"));
			}
			SubscriptionStore currentUser = SubscriptionStore.CurrentUser;
			currentUser.RefreshStorePointer();
			return currentUser.GetSubscriptionState(definitionIdentity);
		}

		private Exception GetInnerMostException(Exception exception)
		{
			if (exception.InnerException != null)
			{
				return GetInnerMostException(exception.InnerException);
			}
			return exception;
		}
	}
	[ComImport]
	[Guid("B3CA4E79-0107-4CA7-9708-3BE0A97957FB")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IManagedDeploymentServiceCom
	{
		void ActivateDeployment(string deploymentLocation, bool isShortcut);

		void ActivateDeploymentEx(string deploymentLocation, int unsignedPolicy, int signedPolicy);

		void ActivateApplicationExtension(string textualSubId, string deploymentProviderUrl, string targetAssociatedFile);

		void MaintainSubscription(string textualSubId);

		void CheckForDeploymentUpdate(string textualSubId);

		void EndServiceRightNow();

		void CleanOnlineAppCache();
	}
	internal class DeploymentServiceComWrapper : IManagedDeploymentServiceCom
	{
		private DeploymentServiceCom m_deploymentServiceCom;

		public DeploymentServiceComWrapper()
		{
			m_deploymentServiceCom = new DeploymentServiceCom();
		}

		public void ActivateApplicationExtension(string textualSubId, string deploymentProviderUrl, string targetAssociatedFile)
		{
			m_deploymentServiceCom.ActivateApplicationExtension(textualSubId, deploymentProviderUrl, targetAssociatedFile);
		}

		public void ActivateDeployment(string deploymentLocation, bool isShortcut)
		{
			m_deploymentServiceCom.ActivateDeployment(deploymentLocation, isShortcut);
		}

		public void ActivateDeploymentEx(string deploymentLocation, int unsignedPolicy, int signedPolicy)
		{
			m_deploymentServiceCom.ActivateDeploymentEx(deploymentLocation, unsignedPolicy, signedPolicy);
		}

		public void CheckForDeploymentUpdate(string textualSubId)
		{
			m_deploymentServiceCom.CheckForDeploymentUpdate(textualSubId);
		}

		public void CleanOnlineAppCache()
		{
			m_deploymentServiceCom.CleanOnlineAppCache();
		}

		public void EndServiceRightNow()
		{
			m_deploymentServiceCom.EndServiceRightNow();
		}

		public void MaintainSubscription(string textualSubId)
		{
			m_deploymentServiceCom.MaintainSubscription(textualSubId);
		}
	}
	internal abstract class DisposableBase : IDisposable
	{
		private bool _disposed;

		public DisposableBase()
		{
		}

		~DisposableBase()
		{
			Dispose(disposing: false);
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		private void Dispose(bool disposing)
		{
			if (!_disposed)
			{
				if (disposing)
				{
					DisposeManagedResources();
				}
				DisposeUnmanagedResources();
			}
			_disposed = true;
		}

		protected virtual void DisposeManagedResources()
		{
		}

		protected virtual void DisposeUnmanagedResources()
		{
		}
	}
	internal static class DownloadManager
	{
		private class DependencyDownloadCookie
		{
			public readonly object ManifestElement;

			public readonly AssemblyManifest DeployManifest;

			public readonly AssemblyManifest AppManifest;

			public DependencyDownloadCookie(object manifestElement, AssemblyManifest deployManifest, AssemblyManifest appManifest)
			{
				ManifestElement = manifestElement;
				DeployManifest = deployManifest;
				AppManifest = appManifest;
			}
		}

		public static AssemblyManifest DownloadDeploymentManifest(SubscriptionStore subStore, ref Uri sourceUri, out TempFile tempFile)
		{
			return DownloadDeploymentManifest(subStore, ref sourceUri, out tempFile, null, null);
		}

		public static AssemblyManifest DownloadDeploymentManifest(SubscriptionStore subStore, ref Uri sourceUri, out TempFile tempFile, IDownloadNotification notification, DownloadOptions options)
		{
			tempFile = null;
			TempFile tempFile2 = null;
			TempFile tempFile3 = null;
			try
			{
				ServerInformation serverInformation;
				AssemblyManifest deployment = DownloadDeploymentManifestDirect(subStore, ref sourceUri, out tempFile2, notification, options, out serverInformation);
				Logger.SetSubscriptionServerInformation(serverInformation);
				bool flag = FollowDeploymentProviderUri(subStore, ref deployment, ref sourceUri, out tempFile3, notification, options);
				tempFile = (flag ? tempFile3 : tempFile2);
				return deployment;
			}
			finally
			{
				if (tempFile2 != null && tempFile2 != tempFile)
				{
					tempFile2.Dispose();
					tempFile2 = null;
				}
				if (tempFile3 != null && tempFile3 != tempFile)
				{
					tempFile3.Dispose();
					tempFile3 = null;
				}
			}
		}

		public static bool FollowDeploymentProviderUri(SubscriptionStore subStore, ref AssemblyManifest deployment, ref Uri sourceUri, out TempFile tempFile, IDownloadNotification notification, DownloadOptions options)
		{
			tempFile = null;
			bool result = false;
			Zone zone = Zone.CreateFromUrl(sourceUri.AbsoluteUri);
			bool flag = false;
			if (zone.SecurityZone != 0)
			{
				flag = true;
			}
			else
			{
				DependentAssembly mainDependentAssembly = deployment.MainDependentAssembly;
				if (mainDependentAssembly == null || mainDependentAssembly.Codebase == null)
				{
					throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_NoAppInDeploymentManifest"));
				}
				Uri uri = new Uri(sourceUri, mainDependentAssembly.Codebase);
				Zone zone2 = Zone.CreateFromUrl(uri.AbsoluteUri);
				if (zone2.SecurityZone == SecurityZone.MyComputer && !System.IO.File.Exists(uri.LocalPath))
				{
					flag = true;
				}
			}
			if (flag)
			{
				Uri sourceUri2 = deployment.Deployment.ProviderCodebaseUri;
				Logger.SetDeploymentProviderUrl(sourceUri2);
				if (!PolicyKeys.SkipDeploymentProvider() && sourceUri2 != null && !sourceUri2.Equals(sourceUri))
				{
					AssemblyManifest assemblyManifest = null;
					ServerInformation serverInformation;
					try
					{
						assemblyManifest = DownloadDeploymentManifestDirect(subStore, ref sourceUri2, out tempFile, notification, options, out serverInformation);
					}
					catch (InvalidDeploymentException ex)
					{
						if (ex.SubType == ExceptionTypes.Manifest || ex.SubType == ExceptionTypes.ManifestLoad || ex.SubType == ExceptionTypes.ManifestParse || ex.SubType == ExceptionTypes.ManifestSemanticValidation)
						{
							throw new InvalidDeploymentException(ExceptionTypes.Manifest, Resources.GetString("Ex_InvalidProviderManifest"), ex);
						}
						throw;
					}
					Logger.SetDeploymentProviderServerInformation(serverInformation);
					SubscriptionState subscriptionState = subStore.GetSubscriptionState(deployment);
					SubscriptionState subscriptionState2 = subStore.GetSubscriptionState(assemblyManifest);
					if (!subscriptionState2.SubscriptionId.Equals(subscriptionState.SubscriptionId))
					{
						throw new InvalidDeploymentException(ExceptionTypes.SubscriptionSemanticValidation, Resources.GetString("Ex_ProviderNotInSubscription"));
					}
					deployment = assemblyManifest;
					sourceUri = sourceUri2;
					result = true;
				}
			}
			return result;
		}

		public static AssemblyManifest DownloadDeploymentManifestBypass(SubscriptionStore subStore, ref Uri sourceUri, out TempFile tempFile, out SubscriptionState subState, IDownloadNotification notification, DownloadOptions options)
		{
			tempFile = null;
			subState = null;
			TempFile tempFile2 = null;
			TempFile tempFile3 = null;
			try
			{
				ServerInformation serverInformation;
				AssemblyManifest deployment = DownloadDeploymentManifestDirectBypass(subStore, ref sourceUri, out tempFile2, out subState, notification, options, out serverInformation);
				Logger.SetSubscriptionServerInformation(serverInformation);
				if (subState != null)
				{
					tempFile = tempFile2;
					return deployment;
				}
				bool flag = FollowDeploymentProviderUri(subStore, ref deployment, ref sourceUri, out tempFile3, notification, options);
				tempFile = (flag ? tempFile3 : tempFile2);
				return deployment;
			}
			finally
			{
				if (tempFile2 != null && tempFile2 != tempFile)
				{
					tempFile2.Dispose();
				}
				if (tempFile3 != null && tempFile3 != tempFile)
				{
					tempFile3.Dispose();
				}
			}
		}

		public static AssemblyManifest DownloadApplicationManifest(AssemblyManifest deploymentManifest, string targetDir, Uri deploymentUri, out Uri appSourceUri, out string appManifestPath)
		{
			return DownloadApplicationManifest(deploymentManifest, targetDir, deploymentUri, null, null, out appSourceUri, out appManifestPath);
		}

		public static AssemblyManifest DownloadApplicationManifest(AssemblyManifest deploymentManifest, string targetDir, Uri deploymentUri, IDownloadNotification notification, DownloadOptions options, out Uri appSourceUri, out string appManifestPath)
		{
			DependentAssembly mainDependentAssembly = deploymentManifest.MainDependentAssembly;
			if (mainDependentAssembly == null || mainDependentAssembly.Codebase == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_NoAppInDeploymentManifest"));
			}
			appSourceUri = new Uri(deploymentUri, mainDependentAssembly.Codebase);
			Zone zone = Zone.CreateFromUrl(deploymentUri.AbsoluteUri);
			Zone obj = Zone.CreateFromUrl(appSourceUri.AbsoluteUri);
			if (!zone.Equals(obj))
			{
				throw new InvalidDeploymentException(ExceptionTypes.Zone, Resources.GetString("Ex_DeployAppZoneMismatch"));
			}
			appManifestPath = Path.Combine(targetDir, mainDependentAssembly.Identity.Name + ".manifest");
			ServerInformation serverInformation;
			AssemblyManifest assemblyManifest = DownloadManifest(ref appSourceUri, appManifestPath, notification, options, AssemblyManifest.ManifestType.Application, out serverInformation);
			Logger.SetApplicationUrl(appSourceUri);
			Logger.SetApplicationServerInformation(serverInformation);
			obj = Zone.CreateFromUrl(appSourceUri.AbsoluteUri);
			if (!zone.Equals(obj))
			{
				throw new InvalidDeploymentException(ExceptionTypes.Zone, Resources.GetString("Ex_DeployAppZoneMismatch"));
			}
			if (assemblyManifest.Identity.Equals(deploymentManifest.Identity))
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DepSameDeploymentAndApplicationIdentity"), assemblyManifest.Identity.ToString()));
			}
			if (!assemblyManifest.Identity.Matches(mainDependentAssembly.Identity, assemblyManifest.Application))
			{
				throw new InvalidDeploymentException(ExceptionTypes.SubscriptionSemanticValidation, Resources.GetString("Ex_RefDefMismatch"));
			}
			if (!PolicyKeys.SkipApplicationDependencyHashCheck())
			{
				try
				{
					ComponentVerifier.VerifyFileHash(appManifestPath, mainDependentAssembly.HashCollection);
				}
				catch (InvalidDeploymentException ex)
				{
					if (ex.SubType == ExceptionTypes.HashValidation)
					{
						throw new InvalidDeploymentException(ExceptionTypes.HashValidation, Resources.GetString("Ex_AppManInvalidHash"), ex);
					}
					throw;
				}
			}
			if (assemblyManifest.RequestedExecutionLevel != null)
			{
				VerifyRequestedPrivilegesSupport(assemblyManifest.RequestedExecutionLevel);
			}
			return assemblyManifest;
		}

		public static void DownloadDependencies(SubscriptionState subState, AssemblyManifest deployManifest, AssemblyManifest appManifest, Uri sourceUriBase, string targetDirectory, string group, IDownloadNotification notification, DownloadOptions options)
		{
			FileDownloader fileDownloader = FileDownloader.Create();
			fileDownloader.Options = options;
			if (group == null)
			{
				fileDownloader.CheckForSizeLimit(appManifest.CalculateDependenciesSize(), addToSize: false);
			}
			AddDependencies(fileDownloader, deployManifest, appManifest, sourceUriBase, targetDirectory, group);
			fileDownloader.DownloadModified += ProcessDownloadedFile;
			if (notification != null)
			{
				fileDownloader.AddNotification(notification);
			}
			try
			{
				fileDownloader.Download(subState);
				fileDownloader.ComponentVerifier.VerifyComponents();
				VerifyRequestedPrivilegesSupport(appManifest, targetDirectory);
			}
			finally
			{
				if (notification != null)
				{
					fileDownloader.RemoveNotification(notification);
				}
				fileDownloader.DownloadModified -= ProcessDownloadedFile;
			}
		}

		private static void VerifyRequestedPrivilegesSupport(AssemblyManifest appManifest, string targetDirectory)
		{
			if (appManifest.EntryPoints[0].CustomHostSpecified)
			{
				return;
			}
			string text = Path.Combine(targetDirectory, appManifest.EntryPoints[0].Assembly.Codebase);
			if (System.IO.File.Exists(text))
			{
				AssemblyManifest assemblyManifest = new AssemblyManifest(text);
				if (assemblyManifest.Id1ManifestPresent && assemblyManifest.Id1RequestedExecutionLevel != null)
				{
					VerifyRequestedPrivilegesSupport(assemblyManifest.Id1RequestedExecutionLevel);
				}
			}
		}

		private static void VerifyRequestedPrivilegesSupport(string requestedExecutionLevel)
		{
			if (PlatformSpecific.OnVistaOrAbove)
			{
				bool flag = false;
				RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
				if (registryKey != null && registryKey.GetValue("EnableLUA") != null && (int)registryKey.GetValue("EnableLUA") != 0)
				{
					flag = true;
				}
				if (flag && (string.Compare(requestedExecutionLevel, "requireAdministrator", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(requestedExecutionLevel, "highestAvailable", StringComparison.OrdinalIgnoreCase) == 0))
				{
					throw new InvalidDeploymentException(ExceptionTypes.UnsupportedElevetaionRequest, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestExecutionLevelNotSupported")));
				}
			}
		}

		private static AssemblyManifest DownloadDeploymentManifestDirect(SubscriptionStore subStore, ref Uri sourceUri, out TempFile tempFile, IDownloadNotification notification, DownloadOptions options, out ServerInformation serverInformation)
		{
			tempFile = subStore.AcquireTempFile(".application");
			AssemblyManifest assemblyManifest = DownloadManifest(ref sourceUri, tempFile.Path, notification, options, AssemblyManifest.ManifestType.Deployment, out serverInformation);
			if (assemblyManifest.Identity.Version == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_DeploymentManifestNoVersion"));
			}
			if (assemblyManifest.Deployment == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_InvalidDeploymentManifest"));
			}
			return assemblyManifest;
		}

		private static AssemblyManifest DownloadDeploymentManifestDirectBypass(SubscriptionStore subStore, ref Uri sourceUri, out TempFile tempFile, out SubscriptionState subState, IDownloadNotification notification, DownloadOptions options, out ServerInformation serverInformation)
		{
			subState = null;
			tempFile = subStore.AcquireTempFile(".application");
			DownloadManifestAsRawFile(ref sourceUri, tempFile.Path, notification, options, out serverInformation);
			bool flag = false;
			AssemblyManifest assemblyManifest = null;
			DefinitionIdentity definitionIdentity = null;
			DefinitionIdentity definitionIdentity2 = null;
			DefinitionAppId definitionAppId = null;
			try
			{
				assemblyManifest = ManifestReader.FromDocumentNoValidation(tempFile.Path);
				definitionIdentity = assemblyManifest.Identity;
				definitionIdentity2 = new DefinitionIdentity(assemblyManifest.MainDependentAssembly.Identity);
				Uri uri = ((sourceUri.Query != null && sourceUri.Query.Length > 0) ? new Uri(sourceUri.GetLeftPart(UriPartial.Path)) : sourceUri);
				definitionAppId = new DefinitionAppId(uri.AbsoluteUri, definitionIdentity, definitionIdentity2);
			}
			catch (InvalidDeploymentException)
			{
				flag = true;
			}
			catch (COMException)
			{
				flag = true;
			}
			catch (SEHException)
			{
				flag = true;
			}
			catch (IndexOutOfRangeException)
			{
				flag = true;
			}
			if (!flag)
			{
				SubscriptionState subscriptionState = subStore.GetSubscriptionState(assemblyManifest);
				bool flag2 = false;
				long transactionId;
				using (subStore.AcquireReferenceTransaction(out transactionId))
				{
					flag2 = subStore.CheckAndReferenceApplication(subscriptionState, definitionAppId, transactionId);
				}
				if (flag2 && definitionAppId.Equals(subscriptionState.CurrentBind))
				{
					subState = subscriptionState;
					return subState.CurrentDeploymentManifest;
				}
				flag = true;
			}
			AssemblyManifest assemblyManifest2 = ManifestReader.FromDocument(tempFile.Path, AssemblyManifest.ManifestType.Deployment, sourceUri);
			if (assemblyManifest2.Identity.Version == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_DeploymentManifestNoVersion"));
			}
			if (assemblyManifest2.Deployment == null)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, Resources.GetString("Ex_InvalidDeploymentManifest"));
			}
			return assemblyManifest2;
		}

		private static AssemblyManifest DownloadManifest(ref Uri sourceUri, string targetPath, IDownloadNotification notification, DownloadOptions options, AssemblyManifest.ManifestType manifestType, out ServerInformation serverInformation)
		{
			DownloadManifestAsRawFile(ref sourceUri, targetPath, notification, options, out serverInformation);
			return ManifestReader.FromDocument(targetPath, manifestType, sourceUri);
		}

		private static void DownloadManifestAsRawFile(ref Uri sourceUri, string targetPath, IDownloadNotification notification, DownloadOptions options, out ServerInformation serverInformation)
		{
			FileDownloader fileDownloader = FileDownloader.Create();
			fileDownloader.Options = options;
			if (notification != null)
			{
				fileDownloader.AddNotification(notification);
			}
			try
			{
				fileDownloader.AddFile(sourceUri, targetPath, 16777216);
				fileDownloader.Download(null);
				sourceUri = fileDownloader.DownloadResults[0].ResponseUri;
				serverInformation = fileDownloader.DownloadResults[0].ServerInformation;
			}
			finally
			{
				if (notification != null)
				{
					fileDownloader.RemoveNotification(notification);
				}
			}
		}

		private static void AddDependencies(FileDownloader downloader, AssemblyManifest deployManifest, AssemblyManifest appManifest, Uri sourceUriBase, string targetDirectory, string group)
		{
			long num = 0L;
			System.Deployment.Application.Manifest.File[] filesInGroup = appManifest.GetFilesInGroup(group, optionalOnly: true);
			ReorderFilesForIconFile(appManifest, filesInGroup);
			System.Deployment.Application.Manifest.File[] array = filesInGroup;
			foreach (System.Deployment.Application.Manifest.File file in array)
			{
				Uri fileSourceUri = MapFileSourceUri(deployManifest, sourceUriBase, file.Name);
				AddFileToDownloader(downloader, deployManifest, appManifest, file, fileSourceUri, targetDirectory, file.NameFS, file.HashCollection);
				num += (long)file.Size;
			}
			DependentAssembly[] privateAssembliesInGroup = appManifest.GetPrivateAssembliesInGroup(group, optionalOnly: true);
			DependentAssembly[] array2 = privateAssembliesInGroup;
			foreach (DependentAssembly dependentAssembly in array2)
			{
				Uri fileSourceUri = MapFileSourceUri(deployManifest, sourceUriBase, dependentAssembly.Codebase);
				AddFileToDownloader(downloader, deployManifest, appManifest, dependentAssembly, fileSourceUri, targetDirectory, dependentAssembly.CodebaseFS, dependentAssembly.HashCollection);
				num += (long)dependentAssembly.Size;
			}
			downloader.SetExpectedBytesTotal(num);
			if (filesInGroup.Length == 0 && privateAssembliesInGroup.Length == 0)
			{
				throw new InvalidDeploymentException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_NoSuchDownloadGroup"), group));
			}
		}

		private static Uri MapFileSourceUri(AssemblyManifest deployManifest, Uri sourceUriBase, string fileName)
		{
			return UriHelper.UriFromRelativeFilePath(sourceUriBase, deployManifest.Deployment.MapFileExtensions ? (fileName + ".deploy") : fileName);
		}

		private static void AddFileToDownloader(FileDownloader downloader, AssemblyManifest deployManifest, AssemblyManifest appManifest, object manifestElement, Uri fileSourceUri, string targetDirectory, string targetFileName, HashCollection hashCollection)
		{
			string targetFilePath = Path.Combine(targetDirectory, targetFileName);
			DependencyDownloadCookie cookie = new DependencyDownloadCookie(manifestElement, deployManifest, appManifest);
			downloader.AddFile(fileSourceUri, targetFilePath, cookie, hashCollection);
		}

		private static void ProcessDownloadedFile(object sender, DownloadEventArgs e)
		{
			if (e.Cookie == null)
			{
				return;
			}
			string fileName = Path.GetFileName(e.FileLocalPath);
			FileDownloader fileDownloader = (FileDownloader)sender;
			if (e.FileResponseUri != null && !e.FileResponseUri.Equals(e.FileSourceUri))
			{
				throw new InvalidDeploymentException(ExceptionTypes.AppFileLocationValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DownloadAppFileAsmRedirected"), fileName));
			}
			DependencyDownloadCookie dependencyDownloadCookie = (DependencyDownloadCookie)e.Cookie;
			if (dependencyDownloadCookie.ManifestElement is DependentAssembly)
			{
				DependentAssembly dependentAssembly = (DependentAssembly)dependencyDownloadCookie.ManifestElement;
				AssemblyManifest deployManifest = dependencyDownloadCookie.DeployManifest;
				AssemblyManifest appManifest = dependencyDownloadCookie.AppManifest;
				AssemblyManifest assemblyManifest = new AssemblyManifest(e.FileLocalPath);
				if (!assemblyManifest.Identity.Matches(dependentAssembly.Identity, exact: true))
				{
					throw new InvalidDeploymentException(ExceptionTypes.RefDefValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_DownloadRefDefMismatch"), fileName));
				}
				if (assemblyManifest.Identity.Equals(deployManifest.Identity) || assemblyManifest.Identity.Equals(appManifest.Identity))
				{
					throw new InvalidDeploymentException(ExceptionTypes.ManifestSemanticValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_AppPrivAsmIdSameAsDeployOrApp"), assemblyManifest.Identity.ToString()));
				}
				System.Deployment.Application.Manifest.File[] files = assemblyManifest.Files;
				for (int i = 0; i < files.Length; i++)
				{
					Uri uri = MapFileSourceUri(deployManifest, e.FileSourceUri, files[i].Name);
					if (!uri.AbsoluteUri.Equals(e.FileSourceUri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
					{
						string directoryName = Path.GetDirectoryName(e.FileLocalPath);
						AddFileToDownloader(fileDownloader, deployManifest, appManifest, files[i], uri, directoryName, files[i].NameFS, files[i].HashCollection);
					}
				}
				fileDownloader.ComponentVerifier.AddFileForVerification(e.FileLocalPath, dependentAssembly.HashCollection);
				if (assemblyManifest.Identity.PublicKeyToken == null)
				{
					fileDownloader.ComponentVerifier.AddSimplyNamedAssemblyForVerification(e.FileLocalPath, assemblyManifest);
				}
				else
				{
					fileDownloader.ComponentVerifier.AddStrongNameAssemblyForVerification(e.FileLocalPath, assemblyManifest);
				}
			}
			else if (dependencyDownloadCookie.ManifestElement is System.Deployment.Application.Manifest.File)
			{
				System.Deployment.Application.Manifest.File file = (System.Deployment.Application.Manifest.File)dependencyDownloadCookie.ManifestElement;
				fileDownloader.ComponentVerifier.AddFileForVerification(e.FileLocalPath, file.HashCollection);
			}
		}

		private static void ReorderFilesForIconFile(AssemblyManifest manifest, System.Deployment.Application.Manifest.File[] files)
		{
			if (manifest.Description == null || manifest.Description.IconFile == null)
			{
				return;
			}
			for (int i = 0; i < files.Length; i++)
			{
				if (string.Compare(files[i].NameFS, manifest.Description.IconFileFS, StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (i != 0)
					{
						System.Deployment.Application.Manifest.File file = files[0];
						files[0] = files[i];
						files[i] = file;
					}
					break;
				}
			}
		}
	}
	internal class FormPiece : Panel
	{
		public virtual bool OnClosing()
		{
			return true;
		}
	}
	internal class ModalPiece : FormPiece
	{
		protected ManualResetEvent _modalEvent;

		protected UserInterfaceModalResult _modalResult;

		public UserInterfaceModalResult ModalResult => _modalResult;

		public override bool OnClosing()
		{
			bool result = base.OnClosing();
			_modalEvent.Set();
			return result;
		}

		protected override void Dispose(bool disposing)
		{
			base.Dispose(disposing);
			_modalEvent.Set();
		}
	}
	internal class ErrorPiece : ModalPiece
	{
		private Label lblMessage;

		private PictureBox pictureIcon;

		private Button btnOk;

		private Button btnSupport;

		private TableLayoutPanel okDetailsTableLayoutPanel;

		private TableLayoutPanel overarchingTableLayoutPanel;

		private LinkLabel errorLink;

		private string _errorMessage;

		private string _logFileLocation;

		private string _linkUrl;

		private string _linkUrlMessage;

		public ErrorPiece(UserInterfaceForm parentForm, string errorTitle, string errorMessage, string logFileLocation, string linkUrl, string linkUrlMessage, ManualResetEvent modalEvent)
		{
			_errorMessage = errorMessage;
			_logFileLocation = logFileLocation;
			_linkUrl = linkUrl;
			_linkUrlMessage = linkUrlMessage;
			_modalResult = UserInterfaceModalResult.Ok;
			_modalEvent = modalEvent;
			SuspendLayout();
			InitializeComponent();
			InitializeContent();
			ResumeLayout(performLayout: false);
			parentForm.SuspendLayout();
			parentForm.SwitchUserInterfacePiece(this);
			parentForm.Text = errorTitle;
			parentForm.MinimizeBox = false;
			parentForm.MaximizeBox = false;
			parentForm.ControlBox = true;
			parentForm.ActiveControl = btnOk;
			parentForm.ResumeLayout(performLayout: false);
			parentForm.PerformLayout();
			parentForm.Visible = true;
			if (Form.ActiveForm != parentForm)
			{
				parentForm.Activate();
			}
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.Deployment.Application.ErrorPiece));
			this.lblMessage = new System.Windows.Forms.Label();
			this.pictureIcon = new System.Windows.Forms.PictureBox();
			this.btnOk = new System.Windows.Forms.Button();
			this.btnSupport = new System.Windows.Forms.Button();
			this.okDetailsTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.overarchingTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.errorLink = new System.Windows.Forms.LinkLabel();
			((System.ComponentModel.ISupportInitialize)this.pictureIcon).BeginInit();
			this.okDetailsTableLayoutPanel.SuspendLayout();
			this.overarchingTableLayoutPanel.SuspendLayout();
			base.SuspendLayout();
			resources.ApplyResources(this.lblMessage, "lblMessage");
			this.lblMessage.Name = "lblMessage";
			resources.ApplyResources(this.pictureIcon, "pictureIcon");
			this.pictureIcon.Name = "pictureIcon";
			this.pictureIcon.TabStop = false;
			resources.ApplyResources(this.btnOk, "btnOk");
			this.btnOk.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnOk.Name = "btnOk";
			this.btnOk.Click += new System.EventHandler(btnOk_Click);
			resources.ApplyResources(this.btnSupport, "btnSupport");
			this.btnSupport.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnSupport.Name = "btnSupport";
			this.btnSupport.Click += new System.EventHandler(btnSupport_Click);
			resources.ApplyResources(this.okDetailsTableLayoutPanel, "okDetailsTableLayoutPanel");
			this.overarchingTableLayoutPanel.SetColumnSpan(this.okDetailsTableLayoutPanel, 2);
			this.okDetailsTableLayoutPanel.Controls.Add(this.btnOk, 0, 0);
			this.okDetailsTableLayoutPanel.Controls.Add(this.btnSupport, 1, 0);
			this.okDetailsTableLayoutPanel.Name = "okDetailsTableLayoutPanel";
			resources.ApplyResources(this.overarchingTableLayoutPanel, "overarchingTableLayoutPanel");
			this.overarchingTableLayoutPanel.Controls.Add(this.pictureIcon, 0, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.okDetailsTableLayoutPanel, 0, 2);
			this.overarchingTableLayoutPanel.Controls.Add(this.lblMessage, 1, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.errorLink, 1, 1);
			this.overarchingTableLayoutPanel.MinimumSize = new System.Drawing.Size(348, 99);
			this.overarchingTableLayoutPanel.Name = "overarchingTableLayoutPanel";
			resources.ApplyResources(this.errorLink, "errorLink");
			this.errorLink.MinimumSize = new System.Drawing.Size(300, 32);
			this.errorLink.Name = "errorLink";
			this.errorLink.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(errorLink_LinkClicked);
			resources.ApplyResources(this, "$this");
			base.Controls.Add(this.overarchingTableLayoutPanel);
			this.MinimumSize = new System.Drawing.Size(373, 124);
			base.Name = "ErrorPiece";
			((System.ComponentModel.ISupportInitialize)this.pictureIcon).EndInit();
			this.okDetailsTableLayoutPanel.ResumeLayout(false);
			this.okDetailsTableLayoutPanel.PerformLayout();
			this.overarchingTableLayoutPanel.ResumeLayout(false);
			this.overarchingTableLayoutPanel.PerformLayout();
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		private void InitializeContent()
		{
			Bitmap bitmap = (Bitmap)Resources.GetImage("information.bmp");
			bitmap.MakeTransparent();
			pictureIcon.Image = bitmap;
			lblMessage.Text = _errorMessage;
			if (_linkUrl != null && _linkUrlMessage != null)
			{
				string @string = Resources.GetString("UI_ErrorClickHereHere");
				errorLink.Text = _linkUrlMessage;
				int start = _linkUrlMessage.LastIndexOf(@string, StringComparison.Ordinal);
				errorLink.Links.Add(start, @string.Length, _linkUrl);
			}
			else
			{
				errorLink.Text = string.Empty;
				errorLink.Links.Clear();
			}
			if (_logFileLocation == null)
			{
				btnSupport.Enabled = false;
			}
		}

		private void errorLink_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
		{
			errorLink.Links[errorLink.Links.IndexOf(e.Link)].Visited = true;
			if (_linkUrl != null && UserInterface.IsValidHttpUrl(_linkUrl))
			{
				UserInterface.LaunchUrlInBrowser(e.Link.LinkData.ToString());
			}
		}

		private void btnOk_Click(object sender, EventArgs e)
		{
			_modalResult = UserInterfaceModalResult.Ok;
			_modalEvent.Set();
			base.Enabled = false;
		}

		private void btnSupport_Click(object sender, EventArgs e)
		{
			try
			{
				Process.Start("notepad.exe", _logFileLocation);
			}
			catch (Win32Exception)
			{
			}
		}
	}
	internal enum ExceptionTypes
	{
		Unknown,
		Activation,
		ComponentStore,
		ActivationInProgress,
		InvalidShortcut,
		InvalidARPEntry,
		LockTimeout,
		Subscription,
		SubscriptionState,
		ActivationLimitExceeded,
		DiskIsFull,
		GroupMultipleMatch,
		InvalidManifest,
		Manifest,
		ManifestLoad,
		ManifestParse,
		ManifestSemanticValidation,
		ManifestComponentSemanticValidation,
		UnsupportedElevetaionRequest,
		SubscriptionSemanticValidation,
		UriSchemeNotSupported,
		Zone,
		DeploymentUriDifferent,
		SizeLimitForPartialTrustOnlineAppExceeded,
		Validation,
		HashValidation,
		SignatureValidation,
		RefDefValidation,
		ClrValidation,
		StronglyNamedAssemblyVerification,
		IdentityMatchValidationForMixedModeAssembly,
		AppFileLocationValidation,
		FileSizeValidation
	}
	[Serializable]
	public class DeploymentException : SystemException
	{
		private ExceptionTypes _type;

		internal ExceptionTypes SubType => _type;

		public DeploymentException()
			: this(Resources.GetString("Ex_DeploymentException"))
		{
		}

		public DeploymentException(string message)
			: base(message)
		{
			_type = ExceptionTypes.Unknown;
		}

		public DeploymentException(string message, Exception innerException)
			: base(message, innerException)
		{
			_type = ExceptionTypes.Unknown;
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
			info.AddValue("_type", _type);
		}

		internal DeploymentException(ExceptionTypes exceptionType, string message)
			: base(message)
		{
			_type = exceptionType;
		}

		internal DeploymentException(ExceptionTypes exceptionType, string message, Exception innerException)
			: base(message, innerException)
		{
			_type = exceptionType;
		}

		protected DeploymentException(SerializationInfo serializationInfo, StreamingContext streamingContext)
			: base(serializationInfo, streamingContext)
		{
			_type = (ExceptionTypes)serializationInfo.GetValue("_type", typeof(ExceptionTypes));
		}
	}
	[Serializable]
	public class InvalidDeploymentException : DeploymentException
	{
		public InvalidDeploymentException()
			: this(Resources.GetString("Ex_InvalidDeploymentException"))
		{
		}

		public InvalidDeploymentException(string message)
			: base(message)
		{
		}

		public InvalidDeploymentException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		internal InvalidDeploymentException(ExceptionTypes exceptionType, string message)
			: base(exceptionType, message)
		{
		}

		internal InvalidDeploymentException(ExceptionTypes exceptionType, string message, Exception innerException)
			: base(exceptionType, message, innerException)
		{
		}

		protected InvalidDeploymentException(SerializationInfo serializationInfo, StreamingContext streamingContext)
			: base(serializationInfo, streamingContext)
		{
		}
	}
	[Serializable]
	public class DeploymentDownloadException : DeploymentException
	{
		public DeploymentDownloadException()
			: this(Resources.GetString("Ex_DeploymentDownloadException"))
		{
		}

		public DeploymentDownloadException(string message)
			: base(message)
		{
		}

		public DeploymentDownloadException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		internal DeploymentDownloadException(ExceptionTypes exceptionType, string message)
			: base(exceptionType, message)
		{
		}

		internal DeploymentDownloadException(ExceptionTypes exceptionType, string message, Exception innerException)
			: base(exceptionType, message, innerException)
		{
		}

		protected DeploymentDownloadException(SerializationInfo serializationInfo, StreamingContext streamingContext)
			: base(serializationInfo, streamingContext)
		{
		}
	}
	[Serializable]
	public class TrustNotGrantedException : DeploymentException
	{
		public TrustNotGrantedException()
			: this(Resources.GetString("Ex_TrustNotGrantedException"))
		{
		}

		public TrustNotGrantedException(string message)
			: base(message)
		{
		}

		public TrustNotGrantedException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		internal TrustNotGrantedException(ExceptionTypes exceptionType, string message)
			: base(exceptionType, message)
		{
		}

		internal TrustNotGrantedException(ExceptionTypes exceptionType, string message, Exception innerException)
			: base(exceptionType, message, innerException)
		{
		}

		protected TrustNotGrantedException(SerializationInfo serializationInfo, StreamingContext streamingContext)
			: base(serializationInfo, streamingContext)
		{
		}
	}
	[Serializable]
	public class DependentPlatformMissingException : DeploymentException
	{
		private Uri _supportUrl;

		internal Uri SupportUrl => _supportUrl;

		public DependentPlatformMissingException()
			: this(Resources.GetString("Ex_DependentPlatformMissingException"))
		{
		}

		public DependentPlatformMissingException(string message)
			: base(message)
		{
		}

		public DependentPlatformMissingException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected DependentPlatformMissingException(SerializationInfo serializationInfo, StreamingContext streamingContext)
			: base(serializationInfo, streamingContext)
		{
			_supportUrl = (Uri)serializationInfo.GetValue("_supportUrl", typeof(Uri));
		}

		public DependentPlatformMissingException(string message, Uri supportUrl)
			: base(message)
		{
			_supportUrl = supportUrl;
		}

		internal DependentPlatformMissingException(ExceptionTypes exceptionType, string message)
			: base(exceptionType, message)
		{
		}

		internal DependentPlatformMissingException(ExceptionTypes exceptionType, string message, Exception innerException)
			: base(exceptionType, message, innerException)
		{
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
			info.AddValue("_supportUrl", _supportUrl);
		}
	}
	[Serializable]
	internal class DownloadCancelledException : DeploymentDownloadException
	{
		public DownloadCancelledException()
			: this(Resources.GetString("Ex_DownloadCancelledException"))
		{
		}

		public DownloadCancelledException(string message)
			: base(message)
		{
		}

		public DownloadCancelledException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected DownloadCancelledException(SerializationInfo serializationInfo, StreamingContext streamingContext)
			: base(serializationInfo, streamingContext)
		{
		}
	}
	internal class DownloadEventArgs : EventArgs
	{
		internal int _progress;

		internal int _filesCompleted;

		internal int _filesTotal;

		internal long _bytesCompleted;

		internal long _bytesTotal;

		internal Uri _fileSourceUri;

		internal Uri _fileResponseUri;

		internal string _fileLocalPath;

		internal object _cookie;

		public int Progress => _progress;

		public long BytesCompleted => _bytesCompleted;

		public long BytesTotal => _bytesTotal;

		public Uri FileSourceUri => _fileSourceUri;

		public Uri FileResponseUri => _fileResponseUri;

		internal string FileLocalPath
		{
			get
			{
				return _fileLocalPath;
			}
			set
			{
				_fileLocalPath = value;
			}
		}

		internal object Cookie
		{
			get
			{
				return _cookie;
			}
			set
			{
				_cookie = value;
			}
		}
	}
	internal class DownloadOptions
	{
		public bool Background;

		public bool EnforceSizeLimit;

		public ulong SizeLimit;

		public ulong Size;
	}
	internal class ServerInformation
	{
		private string _server;

		private string _poweredBy;

		private string _aspNetVersion;

		public string Server
		{
			get
			{
				return _server;
			}
			set
			{
				_server = value;
			}
		}

		public string PoweredBy
		{
			get
			{
				return _poweredBy;
			}
			set
			{
				_poweredBy = value;
			}
		}

		public string AspNetVersion
		{
			get
			{
				return _aspNetVersion;
			}
			set
			{
				_aspNetVersion = value;
			}
		}
	}
	internal class DownloadResult
	{
		private Uri _responseUri;

		private ServerInformation _serverInformation = new ServerInformation();

		public Uri ResponseUri
		{
			get
			{
				return _responseUri;
			}
			set
			{
				_responseUri = value;
			}
		}

		public ServerInformation ServerInformation => _serverInformation;
	}
	internal abstract class FileDownloader
	{
		public delegate void DownloadModifiedEventHandler(object sender, DownloadEventArgs e);

		public delegate void DownloadCompletedEventHandler(object sender, DownloadEventArgs e);

		protected class DownloadQueueItem
		{
			public const int FileOfAnySize = -1;

			public Uri _sourceUri;

			public string _targetPath;

			public object _cookie;

			public HashCollection _hashCollection;

			public int _maxFileSize;
		}

		protected Queue _fileQueue;

		protected DownloadEventArgs _eventArgs;

		protected DownloadOptions _options = new DownloadOptions();

		protected ArrayList _downloadResults;

		protected long _accumulatedBytesTotal;

		protected long _expectedBytesTotal;

		protected ComponentVerifier _componentVerifier = new ComponentVerifier();

		protected bool _fCancelPending;

		protected byte[] _buffer;

		public DownloadOptions Options
		{
			set
			{
				_options = value;
			}
		}

		public ComponentVerifier ComponentVerifier => _componentVerifier;

		public DownloadResult[] DownloadResults => (DownloadResult[])_downloadResults.ToArray(typeof(DownloadResult));

		public event DownloadModifiedEventHandler DownloadModified;

		public event DownloadCompletedEventHandler DownloadCompleted;

		protected FileDownloader()
		{
			_fileQueue = new Queue();
			_eventArgs = new DownloadEventArgs();
			_downloadResults = new ArrayList();
			_buffer = new byte[4096];
		}

		public static FileDownloader Create()
		{
			return new SystemNetDownloader();
		}

		public void AddNotification(IDownloadNotification notification)
		{
			this.DownloadCompleted = (DownloadCompletedEventHandler)Delegate.Combine(this.DownloadCompleted, new DownloadCompletedEventHandler(notification.DownloadCompleted));
			this.DownloadModified = (DownloadModifiedEventHandler)Delegate.Combine(this.DownloadModified, new DownloadModifiedEventHandler(notification.DownloadModified));
		}

		public void RemoveNotification(IDownloadNotification notification)
		{
			this.DownloadModified = (DownloadModifiedEventHandler)Delegate.Remove(this.DownloadModified, new DownloadModifiedEventHandler(notification.DownloadModified));
			this.DownloadCompleted = (DownloadCompletedEventHandler)Delegate.Remove(this.DownloadCompleted, new DownloadCompletedEventHandler(notification.DownloadCompleted));
		}

		protected void OnModified()
		{
			if (this.DownloadModified != null)
			{
				this.DownloadModified(this, _eventArgs);
			}
		}

		protected void OnCompleted()
		{
			if (this.DownloadCompleted != null)
			{
				this.DownloadCompleted(this, _eventArgs);
			}
		}

		public void AddFile(Uri sourceUri, string targetFilePath)
		{
			AddFile(sourceUri, targetFilePath, null, null);
		}

		public void AddFile(Uri sourceUri, string targetFilePath, int maxFileSize)
		{
			AddFile(sourceUri, targetFilePath, null, null, maxFileSize);
		}

		public void AddFile(Uri sourceUri, string targetFilePath, object cookie, HashCollection hashCollection)
		{
			AddFile(sourceUri, targetFilePath, cookie, hashCollection, -1);
		}

		public void AddFile(Uri sourceUri, string targetFilePath, object cookie, HashCollection hashCollection, int maxFileSize)
		{
			UriHelper.ValidateSupportedScheme(sourceUri);
			DownloadQueueItem downloadQueueItem = new DownloadQueueItem();
			downloadQueueItem._sourceUri = sourceUri;
			downloadQueueItem._targetPath = targetFilePath;
			downloadQueueItem._cookie = cookie;
			downloadQueueItem._hashCollection = hashCollection;
			downloadQueueItem._maxFileSize = maxFileSize;
			lock (_fileQueue)
			{
				_fileQueue.Enqueue(downloadQueueItem);
				_eventArgs._filesTotal++;
			}
		}

		private static FileStream GetPatchSourceStream(string filePath)
		{
			FileStream result = null;
			try
			{
				result = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
				return result;
			}
			catch (IOException exception)
			{
				Logger.AddErrorInformation(exception, Resources.GetString("Ex_PatchSourceOpenFailed"), Path.GetFileName(filePath));
				return result;
			}
			catch (UnauthorizedAccessException exception2)
			{
				Logger.AddErrorInformation(exception2, Resources.GetString("Ex_PatchSourceOpenFailed"), Path.GetFileName(filePath));
				return result;
			}
		}

		private static FileStream GetPatchTargetStream(string filePath)
		{
			return new FileStream(filePath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
		}

		private static bool FileHashVerified(HashCollection hashCollection, string location)
		{
			try
			{
				ComponentVerifier.VerifyFileHash(location, hashCollection);
			}
			catch (InvalidDeploymentException ex)
			{
				if (ex.SubType == ExceptionTypes.HashValidation)
				{
					return false;
				}
				throw;
			}
			return true;
		}

		private static bool AddSingleFileInHashtable(Hashtable hashtable, HashCollection hashCollection, string location)
		{
			bool result = false;
			if (System.IO.File.Exists(location) && FileHashVerified(hashCollection, location))
			{
				foreach (Hash item in hashCollection)
				{
					string compositString = item.CompositString;
					if (!hashtable.Contains(compositString))
					{
						hashtable.Add(compositString, location);
						result = true;
					}
				}
				return result;
			}
			return result;
		}

		private static void AddFilesInHashtable(Hashtable hashtable, AssemblyManifest applicationManifest, string applicationFolder)
		{
			string text = null;
			System.Deployment.Application.Manifest.File[] files = applicationManifest.Files;
			System.Deployment.Application.Manifest.File[] array = files;
			foreach (System.Deployment.Application.Manifest.File file in array)
			{
				text = Path.Combine(applicationFolder, file.NameFS);
				try
				{
					AddSingleFileInHashtable(hashtable, file.HashCollection, text);
				}
				catch (IOException exception)
				{
					Logger.AddErrorInformation(exception, Resources.GetString("Ex_PatchDependencyFailed"), Path.GetFileName(text));
				}
			}
			DependentAssembly[] dependentAssemblies = applicationManifest.DependentAssemblies;
			foreach (DependentAssembly dependentAssembly in dependentAssemblies)
			{
				if (dependentAssembly.IsPreRequisite)
				{
					continue;
				}
				text = Path.Combine(applicationFolder, dependentAssembly.Codebase);
				try
				{
					if (AddSingleFileInHashtable(hashtable, dependentAssembly.HashCollection, text))
					{
						AssemblyManifest assemblyManifest = new AssemblyManifest(text);
						System.Deployment.Application.Manifest.File[] files2 = assemblyManifest.Files;
						for (int k = 0; k < files2.Length; k++)
						{
							string location = Path.Combine(Path.GetDirectoryName(text), files2[k].NameFS);
							AddSingleFileInHashtable(hashtable, files2[k].HashCollection, location);
						}
					}
				}
				catch (InvalidDeploymentException exception2)
				{
					Logger.AddErrorInformation(exception2, Resources.GetString("Ex_PatchDependencyFailed"), Path.GetFileName(text));
				}
				catch (IOException exception3)
				{
					Logger.AddErrorInformation(exception3, Resources.GetString("Ex_PatchDependencyFailed"), Path.GetFileName(text));
				}
			}
		}

		private bool PatchSingleFile(DownloadQueueItem item, Hashtable dependencyTable)
		{
			if (item._hashCollection == null)
			{
				return false;
			}
			string text = null;
			foreach (Hash item2 in item._hashCollection)
			{
				string compositString = item2.CompositString;
				if (dependencyTable.Contains(compositString))
				{
					text = (string)dependencyTable[compositString];
					break;
				}
			}
			if (text == null)
			{
				return false;
			}
			if (_fCancelPending)
			{
				return false;
			}
			FileStream fileStream = null;
			FileStream fileStream2 = null;
			try
			{
				fileStream = GetPatchSourceStream(text);
				if (fileStream == null)
				{
					return false;
				}
				Directory.CreateDirectory(Path.GetDirectoryName(item._targetPath));
				fileStream2 = GetPatchTargetStream(item._targetPath);
				if (fileStream2 == null)
				{
					return false;
				}
				_eventArgs._fileSourceUri = item._sourceUri;
				_eventArgs.FileLocalPath = item._targetPath;
				_eventArgs.Cookie = null;
				_eventArgs._fileResponseUri = null;
				CheckForSizeLimit((ulong)fileStream.Length, addToSize: true);
				_accumulatedBytesTotal += fileStream.Length;
				SetBytesTotal();
				OnModified();
				int num = 0;
				int lastTick = Environment.TickCount;
				fileStream2.SetLength(fileStream.Length);
				fileStream2.Position = 0L;
				do
				{
					if (_fCancelPending)
					{
						return false;
					}
					num = fileStream.Read(_buffer, 0, _buffer.Length);
					if (num > 0)
					{
						fileStream2.Write(_buffer, 0, num);
					}
					_eventArgs._bytesCompleted += num;
					_eventArgs._progress = (int)(_eventArgs._bytesCompleted * 100 / _eventArgs._bytesTotal);
					OnModifiedWithThrottle(ref lastTick);
				}
				while (num > 0);
			}
			finally
			{
				fileStream?.Close();
				fileStream2?.Close();
			}
			_eventArgs.Cookie = item._cookie;
			_eventArgs._filesCompleted++;
			OnModified();
			DownloadResult downloadResult = new DownloadResult();
			downloadResult.ResponseUri = null;
			_downloadResults.Add(downloadResult);
			return true;
		}

		private void PatchFiles(SubscriptionState subState)
		{
			if (!subState.IsInstalled)
			{
				return;
			}
			System.Deployment.Internal.Isolation.Store.IPathLock pathLock = null;
			System.Deployment.Internal.Isolation.Store.IPathLock pathLock2 = null;
			using (subState.SubscriptionStore.AcquireSubscriptionReaderLock(subState))
			{
				if (!subState.IsInstalled)
				{
					return;
				}
				Hashtable hashtable = new Hashtable();
				try
				{
					pathLock = subState.SubscriptionStore.LockApplicationPath(subState.CurrentBind);
					AddFilesInHashtable(hashtable, subState.CurrentApplicationManifest, pathLock.Path);
					try
					{
						if (subState.PreviousBind != null)
						{
							pathLock2 = subState.SubscriptionStore.LockApplicationPath(subState.PreviousBind);
							AddFilesInHashtable(hashtable, subState.PreviousApplicationManifest, pathLock2.Path);
						}
						Queue queue = new Queue();
						do
						{
							DownloadQueueItem downloadQueueItem = null;
							lock (_fileQueue)
							{
								if (_fileQueue.Count > 0)
								{
									downloadQueueItem = (DownloadQueueItem)_fileQueue.Dequeue();
								}
							}
							if (downloadQueueItem == null)
							{
								break;
							}
							if (!PatchSingleFile(downloadQueueItem, hashtable))
							{
								queue.Enqueue(downloadQueueItem);
							}
						}
						while (!_fCancelPending);
						lock (_fileQueue)
						{
							while (_fileQueue.Count > 0)
							{
								queue.Enqueue(_fileQueue.Dequeue());
							}
							_fileQueue = queue;
						}
					}
					finally
					{
						pathLock2?.Dispose();
					}
				}
				finally
				{
					pathLock?.Dispose();
				}
			}
			if (!_fCancelPending)
			{
				return;
			}
			throw new DownloadCancelledException();
		}

		public void Download(SubscriptionState subState)
		{
			try
			{
				OnModified();
				if (subState != null)
				{
					CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfCopyBegin);
					PatchFiles(subState);
					CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfCopyEnd);
				}
				DownloadAllFiles();
			}
			finally
			{
				OnCompleted();
			}
		}

		public void SetExpectedBytesTotal(long total)
		{
			_expectedBytesTotal = total;
		}

		protected void SetBytesTotal()
		{
			if (_expectedBytesTotal < _accumulatedBytesTotal)
			{
				_eventArgs._bytesTotal = _accumulatedBytesTotal;
			}
			else
			{
				_eventArgs._bytesTotal = _expectedBytesTotal;
			}
		}

		internal void CheckForSizeLimit(ulong bytesDownloaded, bool addToSize)
		{
			if (_options != null && _options.EnforceSizeLimit)
			{
				ulong num = ((_options.SizeLimit > _options.Size) ? (_options.SizeLimit - _options.Size) : 0);
				if (bytesDownloaded > num)
				{
					throw new DeploymentDownloadException(ExceptionTypes.SizeLimitForPartialTrustOnlineAppExceeded, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_OnlineSemiTrustAppSizeLimitExceeded"), _options.SizeLimit));
				}
				if (addToSize && bytesDownloaded != 0)
				{
					_options.Size += bytesDownloaded;
				}
			}
		}

		protected void OnModifiedWithThrottle(ref int lastTick)
		{
			int tickCount = Environment.TickCount;
			int num = tickCount - lastTick;
			if (num < 0)
			{
				num += int.MaxValue;
			}
			if (num >= 100)
			{
				OnModified();
				lastTick = tickCount;
			}
		}

		public virtual void Cancel()
		{
			_fCancelPending = true;
		}

		protected abstract void DownloadAllFiles();
	}
	[SecurityPermission(SecurityAction.Demand, Unrestricted = true)]
	public class InPlaceHostingManager : IDisposable
	{
		private enum State
		{
			Ready,
			GettingManifest,
			GetManifestSucceeded,
			VerifyingRequirements,
			VerifyRequirementsSucceeded,
			DownloadingApplication,
			DownloadApplicationSucceeded,
			Done
		}

		private DeploymentManager _deploymentManager;

		private ApplicationIdentity _applicationId;

		private State _state;

		private bool _isCached;

		private bool _isLaunchInHostProcess;

		private object _lock;

		private AppType _appType;

		public event EventHandler<GetManifestCompletedEventArgs> GetManifestCompleted;

		public event EventHandler<DownloadProgressChangedEventArgs> DownloadProgressChanged;

		public event EventHandler<DownloadApplicationCompletedEventArgs> DownloadApplicationCompleted;

		public InPlaceHostingManager(Uri deploymentManifest, bool launchInHostProcess)
		{
			if (!PlatformSpecific.OnXPOrAbove)
			{
				throw new PlatformNotSupportedException(Resources.GetString("Ex_RequiresXPOrHigher"));
			}
			if (deploymentManifest == null)
			{
				throw new ArgumentNullException("deploymentManifest");
			}
			UriHelper.ValidateSupportedSchemeInArgument(deploymentManifest, "deploymentSource");
			_deploymentManager = new DeploymentManager(deploymentManifest, isUpdate: false, isConfirmed: true, null, null);
			_isLaunchInHostProcess = launchInHostProcess;
			_Initialize();
		}

		public InPlaceHostingManager(Uri deploymentManifest)
			: this(deploymentManifest, launchInHostProcess: true)
		{
		}

		private void _Initialize()
		{
			_lock = new object();
			_deploymentManager.BindCompleted += OnBindCompleted;
			_deploymentManager.SynchronizeCompleted += OnSynchronizeCompleted;
			_deploymentManager.ProgressChanged += OnProgressChanged;
			_state = State.Ready;
		}

		public void GetManifestAsync()
		{
			lock (_lock)
			{
				AssertState(State.Ready);
				try
				{
					ChangeState(State.GettingManifest);
					_deploymentManager.BindAsync();
				}
				catch
				{
					ChangeState(State.Done);
					throw;
				}
			}
		}

		public void AssertApplicationRequirements()
		{
			lock (_lock)
			{
				if (_appType == AppType.CustomHostSpecified)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_CannotCallAssertApplicationRequirements"));
				}
				AssertApplicationRequirements(grantApplicationTrust: false);
			}
		}

		public void AssertApplicationRequirements(bool grantApplicationTrust)
		{
			lock (_lock)
			{
				if (_appType == AppType.CustomHostSpecified)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_CannotCallAssertApplicationRequirements"));
				}
				AssertState(State.GetManifestSucceeded, State.DownloadingApplication);
				try
				{
					ChangeState(State.VerifyingRequirements);
					if (grantApplicationTrust)
					{
						_deploymentManager.PersistTrustWithoutEvaluation();
					}
					else
					{
						TrustParams trustParams = new TrustParams();
						trustParams.NoPrompt = true;
						_deploymentManager.DetermineTrust(trustParams);
					}
					_deploymentManager.DeterminePlatformRequirements();
					ChangeState(State.VerifyRequirementsSucceeded);
				}
				catch
				{
					ChangeState(State.Done);
					throw;
				}
			}
		}

		public void DownloadApplicationAsync()
		{
			lock (_lock)
			{
				if (_appType == AppType.CustomHostSpecified)
				{
					AssertState(State.GetManifestSucceeded);
				}
				else if (_isCached)
				{
					AssertState(State.GetManifestSucceeded, State.VerifyRequirementsSucceeded);
				}
				else
				{
					AssertState(State.GetManifestSucceeded, State.VerifyRequirementsSucceeded);
				}
				try
				{
					ChangeState(State.DownloadingApplication);
					_deploymentManager.SynchronizeAsync();
				}
				catch
				{
					ChangeState(State.Done);
					throw;
				}
			}
		}

		public ObjectHandle Execute()
		{
			lock (_lock)
			{
				AssertState(State.DownloadApplicationSucceeded);
				ChangeState(State.Done);
				return _deploymentManager.ExecuteNewDomain();
			}
		}

		public void CancelAsync()
		{
			lock (_lock)
			{
				ChangeState(State.Done);
				_deploymentManager.CancelAsync();
			}
		}

		public void Dispose()
		{
			lock (_lock)
			{
				ChangeState(State.Done);
				_deploymentManager.BindCompleted -= OnBindCompleted;
				_deploymentManager.SynchronizeCompleted -= OnSynchronizeCompleted;
				_deploymentManager.ProgressChanged -= OnProgressChanged;
				_deploymentManager.Dispose();
			}
		}

		public static void UninstallCustomUXApplication(string subscriptionId)
		{
			DefinitionIdentity definitionIdentity = null;
			definitionIdentity = GetSubIdAndValidate(subscriptionId);
			SubscriptionStore currentUser = SubscriptionStore.CurrentUser;
			currentUser.RefreshStorePointer();
			SubscriptionState subscriptionState = currentUser.GetSubscriptionState(definitionIdentity);
			subscriptionState.SubscriptionStore.UninstallCustomUXSubscription(subscriptionState);
		}

		public static void UninstallCustomAddIn(string subscriptionId)
		{
			DefinitionIdentity definitionIdentity = null;
			definitionIdentity = GetSubIdAndValidate(subscriptionId);
			SubscriptionStore currentUser = SubscriptionStore.CurrentUser;
			currentUser.RefreshStorePointer();
			SubscriptionState subscriptionState = currentUser.GetSubscriptionState(definitionIdentity);
			subscriptionState.SubscriptionStore.UninstallCustomHostSpecifiedSubscription(subscriptionState);
		}

		private static DefinitionIdentity GetSubIdAndValidate(string subscriptionId)
		{
			if (subscriptionId == null)
			{
				throw new ArgumentNullException("subscriptionId", Resources.GetString("Ex_ComArgSubIdentityNull"));
			}
			DefinitionIdentity definitionIdentity = null;
			try
			{
				definitionIdentity = new DefinitionIdentity(subscriptionId);
			}
			catch (COMException innerException)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), subscriptionId), innerException);
			}
			catch (SEHException innerException2)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), subscriptionId), innerException2);
			}
			catch (ArgumentException innerException3)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), subscriptionId), innerException3);
			}
			if (definitionIdentity.Name == null)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), subscriptionId));
			}
			if (definitionIdentity.PublicKeyToken == null)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), subscriptionId));
			}
			if (definitionIdentity.ProcessorArchitecture == null)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.GetString("Ex_ComArgSubIdentityNotValid"), subscriptionId));
			}
			if (definitionIdentity.Version != null)
			{
				throw new ArgumentException(Resources.GetString("Ex_ComArgSubIdentityWithVersion"));
			}
			return definitionIdentity;
		}

		private void OnBindCompleted(object sender, BindCompletedEventArgs e)
		{
			lock (_lock)
			{
				AssertState(State.GettingManifest, State.Done);
				GetManifestCompletedEventArgs getManifestCompletedEventArgs = null;
				try
				{
					if (_state != State.Done)
					{
						if (e.Cancelled || e.Error != null)
						{
							ChangeState(State.Done);
						}
						else
						{
							ChangeState(State.GetManifestSucceeded, e);
						}
					}
					if (this.GetManifestCompleted == null)
					{
						return;
					}
					if (e.Error != null || e.Cancelled)
					{
						getManifestCompletedEventArgs = new GetManifestCompletedEventArgs(e, _deploymentManager.LogFilePath);
					}
					else
					{
						_isCached = e.IsCached;
						_applicationId = e.ActivationContext.Identity;
						bool install = _deploymentManager.ActivationDescription.DeployManifest.Deployment.Install;
						bool hostInBrowser = _deploymentManager.ActivationDescription.AppManifest.EntryPoints[0].HostInBrowser;
						_appType = _deploymentManager.ActivationDescription.appType;
						bool useManifestForTrust = _deploymentManager.ActivationDescription.AppManifest.UseManifestForTrust;
						Uri providerCodebaseUri = _deploymentManager.ActivationDescription.DeployManifest.Deployment.ProviderCodebaseUri;
						getManifestCompletedEventArgs = ((_isLaunchInHostProcess && _appType != AppType.CustomHostSpecified && !hostInBrowser) ? new GetManifestCompletedEventArgs(e, new InvalidOperationException(Resources.GetString("Ex_HostInBrowserFlagMustBeTrue")), _deploymentManager.LogFilePath) : ((install && (_isLaunchInHostProcess || _appType == AppType.CustomHostSpecified)) ? new GetManifestCompletedEventArgs(e, new InvalidOperationException(Resources.GetString("Ex_InstallFlagMustBeFalse")), _deploymentManager.LogFilePath) : ((useManifestForTrust && _appType == AppType.CustomHostSpecified) ? new GetManifestCompletedEventArgs(e, new InvalidOperationException(Resources.GetString("Ex_CannotHaveUseManifestForTrustFlag")), _deploymentManager.LogFilePath) : ((providerCodebaseUri != null && _appType == AppType.CustomHostSpecified) ? new GetManifestCompletedEventArgs(e, new InvalidOperationException(Resources.GetString("Ex_CannotHaveDeploymentProvider")), _deploymentManager.LogFilePath) : ((!hostInBrowser || _appType != AppType.CustomUX) ? new GetManifestCompletedEventArgs(e, _deploymentManager.ActivationDescription, _deploymentManager.LogFilePath) : new GetManifestCompletedEventArgs(e, new InvalidOperationException(Resources.GetString("Ex_CannotHaveCustomUXFlag")), _deploymentManager.LogFilePath))))));
					}
				}
				catch
				{
					ChangeState(State.Done);
					throw;
				}
				this.GetManifestCompleted(this, getManifestCompletedEventArgs);
			}
		}

		private void OnSynchronizeCompleted(object sender, SynchronizeCompletedEventArgs e)
		{
			lock (_lock)
			{
				AssertState(State.DownloadingApplication, State.VerifyRequirementsSucceeded, State.Done);
				if (_state != State.Done)
				{
					if (e.Cancelled || e.Error != null)
					{
						ChangeState(State.Done);
					}
					else
					{
						ChangeState(State.DownloadApplicationSucceeded, e);
					}
				}
				if ((!_isLaunchInHostProcess || _appType == AppType.CustomHostSpecified) && _appType != AppType.CustomUX)
				{
					ChangeState(State.Done);
				}
				if (this.DownloadApplicationCompleted != null)
				{
					DownloadApplicationCompletedEventArgs e2 = new DownloadApplicationCompletedEventArgs(e, _deploymentManager.LogFilePath, _deploymentManager.ShortcutAppId);
					this.DownloadApplicationCompleted(this, e2);
				}
			}
		}

		private void OnProgressChanged(object sender, DeploymentProgressChangedEventArgs e)
		{
			lock (_lock)
			{
				if (this.DownloadProgressChanged != null)
				{
					DownloadProgressChangedEventArgs e2 = new DownloadProgressChangedEventArgs(e.ProgressPercentage, e.UserState, e.BytesCompleted, e.BytesTotal, e.State);
					this.DownloadProgressChanged(this, e2);
				}
			}
		}

		private void AssertState(State validState)
		{
			if (_state == State.Done)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_NoFurtherOperations"));
			}
			if (validState != _state)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_InvalidSequence"));
			}
		}

		private void AssertState(State validState0, State validState1)
		{
			if (_state == State.Done && validState0 != _state && validState1 != _state)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_NoFurtherOperations"));
			}
			if (validState0 != _state && validState1 != _state)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_InvalidSequence"));
			}
		}

		private void AssertState(State validState0, State validState1, State validState2)
		{
			if (_state == State.Done && validState0 != _state && validState1 != _state && validState2 != _state)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_NoFurtherOperations"));
			}
			if (validState0 != _state && validState1 != _state && validState2 != _state)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_InvalidSequence"));
			}
		}

		private void ChangeState(State nextState, AsyncCompletedEventArgs e)
		{
			if (e.Cancelled || e.Error != null)
			{
				_state = State.Done;
			}
			else
			{
				_state = nextState;
			}
		}

		private void ChangeState(State nextState)
		{
			_state = nextState;
		}
	}
	public class GetManifestCompletedEventArgs : AsyncCompletedEventArgs
	{
		private ActivationDescription _activationDescription;

		private Version _version;

		private ApplicationIdentity _applicationIdentity;

		private DefinitionIdentity _subId;

		private bool _isCached;

		private string _name;

		private Uri _support;

		private string _logFilePath;

		private byte[] _rawApplicationManifest;

		private byte[] _rawDeploymentManifest;

		private ActivationContext _actContext;

		public ApplicationIdentity ApplicationIdentity
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _applicationIdentity;
			}
		}

		public Version Version
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _version;
			}
		}

		public bool IsCached
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _isCached;
			}
		}

		public string ProductName
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _name;
			}
		}

		public Uri SupportUri
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _support;
			}
		}

		public string LogFilePath => _logFilePath;

		public XmlReader DeploymentManifest
		{
			get
			{
				RaiseExceptionIfNecessary();
				return ManifestToXml(RawDeploymentManifest);
			}
		}

		public XmlReader ApplicationManifest
		{
			get
			{
				RaiseExceptionIfNecessary();
				return ManifestToXml(RawApplicationManifest);
			}
		}

		public ActivationContext ActivationContext
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _actContext;
			}
		}

		public string SubscriptionIdentity
		{
			get
			{
				RaiseExceptionIfNecessary();
				return _subId.ToString();
			}
		}

		private byte[] RawDeploymentManifest
		{
			get
			{
				if (_rawDeploymentManifest == null)
				{
					_rawDeploymentManifest = _activationDescription.DeployManifest.RawXmlBytes;
				}
				return _rawDeploymentManifest;
			}
		}

		private byte[] RawApplicationManifest
		{
			get
			{
				if (_rawApplicationManifest == null)
				{
					_rawApplicationManifest = _activationDescription.AppManifest.RawXmlBytes;
				}
				return _rawApplicationManifest;
			}
		}

		internal GetManifestCompletedEventArgs(BindCompletedEventArgs e, ActivationDescription activationDescription, string logFilePath)
			: base(e.Error, e.Cancelled, e.UserState)
		{
			_applicationIdentity = ((e.ActivationContext != null) ? e.ActivationContext.Identity : null);
			string text = _applicationIdentity.ToString();
			DefinitionAppId definitionAppId = new DefinitionAppId(text);
			DefinitionIdentity deploymentIdentity = definitionAppId.DeploymentIdentity;
			_subId = deploymentIdentity.ToSubscriptionId();
			_logFilePath = logFilePath;
			_isCached = e.IsCached;
			_name = e.FriendlyName;
			_actContext = e.ActivationContext;
			if (_isCached)
			{
				_rawDeploymentManifest = e.ActivationContext.DeploymentManifestBytes;
				_rawApplicationManifest = e.ActivationContext.ApplicationManifestBytes;
			}
			_activationDescription = activationDescription;
			_version = _activationDescription.AppId.DeploymentIdentity.Version;
			_support = _activationDescription.DeployManifest.Description.SupportUri;
		}

		internal GetManifestCompletedEventArgs(BindCompletedEventArgs e, Exception error, string logFilePath)
			: base(error, e.Cancelled, e.UserState)
		{
			_logFilePath = logFilePath;
		}

		internal GetManifestCompletedEventArgs(BindCompletedEventArgs e, string logFilePath)
			: base(e.Error, e.Cancelled, e.UserState)
		{
			_logFilePath = logFilePath;
		}

		private static XmlReader ManifestToXml(byte[] rawManifest)
		{
			if (rawManifest == null)
			{
				return null;
			}
			return new XmlTextReader(new MemoryStream(rawManifest));
		}
	}
	public class DownloadProgressChangedEventArgs : ProgressChangedEventArgs
	{
		private long _bytesCompleted;

		private long _bytesTotal;

		private DeploymentProgressState _deploymentProgressState;

		public long BytesDownloaded => _bytesCompleted;

		public long TotalBytesToDownload => _bytesTotal;

		public DeploymentProgressState State => _deploymentProgressState;

		internal DownloadProgressChangedEventArgs(int progressPercentage, object userState, long bytesCompleted, long bytesTotal, DeploymentProgressState downloadProgressState)
			: base(progressPercentage, userState)
		{
			_bytesCompleted = bytesCompleted;
			_bytesTotal = bytesTotal;
			_deploymentProgressState = downloadProgressState;
		}
	}
	public class DownloadApplicationCompletedEventArgs : AsyncCompletedEventArgs
	{
		private string _logFilePath;

		private string _shortcutAppId;

		public string LogFilePath => _logFilePath;

		public string ShortcutAppId => _shortcutAppId;

		internal DownloadApplicationCompletedEventArgs(AsyncCompletedEventArgs e, string logFilePath, string shortcutAppId)
			: base(e.Error, e.Cancelled, e.UserState)
		{
			_logFilePath = logFilePath;
			_shortcutAppId = shortcutAppId;
		}
	}
	internal static class LifetimeManager
	{
		private static ManualResetEvent _lifetimeEndedEvent;

		private static System.Threading.Timer _periodicTimer;

		private static int _operationsInProgress;

		private static bool _lifetimeExtended;

		private static bool _lifetimeEnded;

		private static bool _immediate;

		static LifetimeManager()
		{
			_lifetimeEndedEvent = new ManualResetEvent(initialState: false);
			TimeSpan timeSpan = new TimeSpan(0, 0, 10, 0);
			_periodicTimer = new System.Threading.Timer(PeriodicTimerCallback, null, timeSpan, timeSpan);
		}

		public static void StartOperation()
		{
			lock (_periodicTimer)
			{
				CheckAlive();
				_operationsInProgress++;
			}
		}

		public static void EndOperation()
		{
			lock (_periodicTimer)
			{
				CheckAlive();
				_operationsInProgress--;
				_lifetimeExtended = true;
			}
		}

		public static void ExtendLifetime()
		{
			lock (_periodicTimer)
			{
				CheckAlive();
				_lifetimeExtended = true;
			}
		}

		public static bool WaitForEnd()
		{
			_lifetimeEndedEvent.WaitOne();
			return _immediate;
		}

		public static void EndImmediately()
		{
			lock (_periodicTimer)
			{
				if (_operationsInProgress != 0)
				{
					Logger.StartCurrentThreadLogging();
					Logger.AddPhaseInformation(Resources.GetString("Life_OperationsInProgress"), _operationsInProgress);
					Logger.EndCurrentThreadLogging();
				}
				_lifetimeEndedEvent.Set();
				_lifetimeEnded = true;
				_immediate = true;
			}
		}

		private static void CheckAlive()
		{
			if (_lifetimeEnded)
			{
				throw new InvalidOperationException(Resources.GetString("Ex_LifetimeEnded"));
			}
		}

		private static void PeriodicTimerCallback(object state)
		{
			lock (_periodicTimer)
			{
				if (_operationsInProgress == 0 && !_lifetimeExtended)
				{
					_lifetimeEndedEvent.Set();
					_lifetimeEnded = true;
				}
				else
				{
					_lifetimeExtended = false;
				}
			}
		}
	}
	internal static class LockedFile
	{
		private class LockedFileHandle : IDisposable
		{
			private SafeFileHandle _handle;

			private string _path;

			private FileAccess _access;

			private bool _disposed;

			public LockedFileHandle()
			{
			}

			public LockedFileHandle(SafeFileHandle handle, string path, FileAccess access)
			{
				if (handle == null)
				{
					throw new ArgumentNullException("handle");
				}
				_handle = handle;
				_path = path;
				_access = access;
				Hashtable hashtable = ((_access == FileAccess.Read) ? ThreadReaderLocks : ThreadWriterLocks);
				hashtable.Add(_path, this);
			}

			public void Dispose()
			{
				if (!_disposed)
				{
					if (_handle != null)
					{
						Hashtable hashtable = ((_access == FileAccess.Read) ? ThreadReaderLocks : ThreadWriterLocks);
						hashtable.Remove(_path);
						_handle.Dispose();
					}
					GC.SuppressFinalize(this);
					_disposed = true;
				}
			}
		}

		[ThreadStatic]
		private static Hashtable _threadReaderLocks;

		[ThreadStatic]
		private static Hashtable _threadWriterLocks;

		private static Hashtable ThreadReaderLocks
		{
			get
			{
				if (_threadReaderLocks == null)
				{
					_threadReaderLocks = new Hashtable();
				}
				return _threadReaderLocks;
			}
		}

		private static Hashtable ThreadWriterLocks
		{
			get
			{
				if (_threadWriterLocks == null)
				{
					_threadWriterLocks = new Hashtable();
				}
				return _threadWriterLocks;
			}
		}

		public static IDisposable AcquireLock(string path, TimeSpan timeout, bool writer)
		{
			LockedFileHandle lockedFileHandle = LockHeldByThread(path, writer);
			if (lockedFileHandle != null)
			{
				return lockedFileHandle;
			}
			DateTime dateTime = DateTime.UtcNow + timeout;
			FileAccess access;
			NativeMethods.GenericAccess dwDesiredAccess;
			NativeMethods.ShareMode dwShareMode;
			if (writer)
			{
				access = FileAccess.Write;
				dwDesiredAccess = NativeMethods.GenericAccess.GENERIC_WRITE;
				dwShareMode = NativeMethods.ShareMode.FILE_SHARE_NONE;
			}
			else
			{
				access = FileAccess.Read;
				dwDesiredAccess = NativeMethods.GenericAccess.GENERIC_READ;
				dwShareMode = (PlatformSpecific.OnWin9x ? NativeMethods.ShareMode.FILE_SHARE_READ : (NativeMethods.ShareMode.FILE_SHARE_READ | NativeMethods.ShareMode.FILE_SHARE_DELETE));
			}
			while (true)
			{
				SafeFileHandle safeFileHandle = NativeMethods.CreateFile(path, (uint)dwDesiredAccess, (uint)dwShareMode, IntPtr.Zero, 4u, 67108864u, IntPtr.Zero);
				int lastWin32Error = Marshal.GetLastWin32Error();
				if (!safeFileHandle.IsInvalid)
				{
					return new LockedFileHandle(safeFileHandle, path, access);
				}
				if (lastWin32Error != 32 && lastWin32Error != 5)
				{
					Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
				}
				if (DateTime.UtcNow > dateTime)
				{
					break;
				}
				Thread.Sleep(1);
			}
			throw new DeploymentException(ExceptionTypes.LockTimeout, Resources.GetString("Ex_LockTimeoutException"));
		}

		private static LockedFileHandle LockHeldByThread(string path, bool writer)
		{
			LockedFileHandle lockedFileHandle = (LockedFileHandle)ThreadWriterLocks[path];
			if (lockedFileHandle != null)
			{
				return new LockedFileHandle();
			}
			LockedFileHandle lockedFileHandle2 = (LockedFileHandle)ThreadReaderLocks[path];
			if (lockedFileHandle2 != null)
			{
				if (!writer)
				{
					return new LockedFileHandle();
				}
				throw new NotImplementedException();
			}
			return null;
		}
	}
	internal class Logger
	{
		protected class LogInformation
		{
			protected string _message = "";

			protected DateTime _time = DateTime.Now;

			public string Message => _message;

			public DateTime Time => _time;

			public LogInformation()
			{
			}

			public LogInformation(string message, DateTime time)
			{
				if (message != null)
				{
					_message = message;
				}
				_time = time;
			}
		}

		protected class ErrorInformation : LogInformation
		{
			protected Exception _exception;

			public string Summary
			{
				get
				{
					StringBuilder stringBuilder = new StringBuilder();
					stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_IndividualErrorSummary"), _message);
					for (Exception ex = _exception; ex != null; ex = ex.InnerException)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_IndividualErrorSummaryBullets"), ex.Message);
					}
					return stringBuilder.ToString();
				}
			}

			public ErrorInformation(string message, Exception exception, DateTime time)
				: base(message, time)
			{
				_exception = exception;
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				for (Exception ex = _exception; ex != null; ex = ex.InnerException)
				{
					string text = null;
					if (ex.StackTrace != null)
					{
						text = ex.StackTrace.Replace("   ", "\t\t\t");
					}
					if (ex == _exception)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_IndividualErrorOutermostException"), base.Time.ToString(DateTimeFormatInfo.CurrentInfo), GetExceptionType(ex), ex.Message, ex.Source, text);
					}
					else
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_IndividualErrorInnerException"), GetExceptionType(ex), ex.Message, ex.Source, text);
					}
				}
				return stringBuilder.ToString();
			}

			private static string GetExceptionType(Exception exception)
			{
				if (exception is DeploymentException)
				{
					DeploymentException ex = (DeploymentException)exception;
					if (ex.SubType != 0)
					{
						return string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_ExceptionType"), ex.GetType().ToString(), ex.SubType.ToString());
					}
					return string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_ExceptionTypeUnknown"), ex.GetType().ToString());
				}
				return exception.GetType().ToString();
			}
		}

		protected class TransactionInformation : LogInformation
		{
			public class TransactionOperation
			{
				protected bool _failed;

				protected string _message = "";

				protected string _failureMessage = "";

				public bool Failed => _failed;

				public string FailureMessage => _failureMessage;

				public TransactionOperation(System.Deployment.Internal.Isolation.StoreTransactionOperation operation, uint disposition, int hresult)
				{
					AnalyzeTransactionOperation(operation, disposition, hresult);
				}

				public override string ToString()
				{
					return _message;
				}

				protected void AnalyzeTransactionOperation(System.Deployment.Internal.Isolation.StoreTransactionOperation operation, uint dispositionValue, int hresult)
				{
					string text = "";
					try
					{
						if (operation.Operation == System.Deployment.Internal.Isolation.StoreTransactionOperationType.StageComponent)
						{
							System.Deployment.Internal.Isolation.StoreOperationStageComponent storeOperationStageComponent = (System.Deployment.Internal.Isolation.StoreOperationStageComponent)Marshal.PtrToStructure(operation.Data.DataPtr, typeof(System.Deployment.Internal.Isolation.StoreOperationStageComponent));
							text = ((System.Deployment.Internal.Isolation.StoreOperationStageComponent.Disposition)dispositionValue).ToString();
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionStageComponent"), storeOperationStageComponent.GetType().ToString(), text, hresult, Path.GetFileName(storeOperationStageComponent.ManifestPath));
							if (dispositionValue == 0)
							{
								_failureMessage = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionStageComponentFailure"), Path.GetFileName(storeOperationStageComponent.ManifestPath));
								_failed = true;
							}
						}
						else if (operation.Operation == System.Deployment.Internal.Isolation.StoreTransactionOperationType.PinDeployment)
						{
							System.Deployment.Internal.Isolation.StoreOperationPinDeployment storeOperationPinDeployment = (System.Deployment.Internal.Isolation.StoreOperationPinDeployment)Marshal.PtrToStructure(operation.Data.DataPtr, typeof(System.Deployment.Internal.Isolation.StoreOperationPinDeployment));
							text = ((System.Deployment.Internal.Isolation.StoreOperationPinDeployment.Disposition)dispositionValue).ToString();
							DefinitionAppId definitionAppId = new DefinitionAppId(storeOperationPinDeployment.Application);
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionPinDeployment"), storeOperationPinDeployment.GetType().ToString(), text, hresult, definitionAppId.ToString());
							if (dispositionValue == 0)
							{
								_failureMessage = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionPinDeploymentFailure"), definitionAppId.ToString());
								_failed = true;
							}
						}
						else if (operation.Operation == System.Deployment.Internal.Isolation.StoreTransactionOperationType.UnpinDeployment)
						{
							System.Deployment.Internal.Isolation.StoreOperationUnpinDeployment storeOperationUnpinDeployment = (System.Deployment.Internal.Isolation.StoreOperationUnpinDeployment)Marshal.PtrToStructure(operation.Data.DataPtr, typeof(System.Deployment.Internal.Isolation.StoreOperationUnpinDeployment));
							text = ((System.Deployment.Internal.Isolation.StoreOperationUnpinDeployment.Disposition)dispositionValue).ToString();
							DefinitionAppId definitionAppId2 = new DefinitionAppId(storeOperationUnpinDeployment.Application);
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionUnPinDeployment"), storeOperationUnpinDeployment.GetType().ToString(), text, hresult, definitionAppId2.ToString());
							if (dispositionValue == 0)
							{
								_failureMessage = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionUnPinDeploymentFailure"), definitionAppId2.ToString());
								_failed = true;
							}
						}
						else if (operation.Operation == System.Deployment.Internal.Isolation.StoreTransactionOperationType.InstallDeployment)
						{
							System.Deployment.Internal.Isolation.StoreOperationInstallDeployment storeOperationInstallDeployment = (System.Deployment.Internal.Isolation.StoreOperationInstallDeployment)Marshal.PtrToStructure(operation.Data.DataPtr, typeof(System.Deployment.Internal.Isolation.StoreOperationInstallDeployment));
							text = ((System.Deployment.Internal.Isolation.StoreOperationInstallDeployment.Disposition)dispositionValue).ToString();
							DefinitionAppId definitionAppId3 = new DefinitionAppId(storeOperationInstallDeployment.Application);
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionInstallDeployment"), storeOperationInstallDeployment.GetType().ToString(), text, hresult, definitionAppId3.ToString());
							if (dispositionValue == 0)
							{
								_failureMessage = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionInstallDeploymentFailure"), definitionAppId3.ToString());
								_failed = true;
							}
						}
						else if (operation.Operation == System.Deployment.Internal.Isolation.StoreTransactionOperationType.UninstallDeployment)
						{
							System.Deployment.Internal.Isolation.StoreOperationUninstallDeployment storeOperationUninstallDeployment = (System.Deployment.Internal.Isolation.StoreOperationUninstallDeployment)Marshal.PtrToStructure(operation.Data.DataPtr, typeof(System.Deployment.Internal.Isolation.StoreOperationUninstallDeployment));
							text = ((System.Deployment.Internal.Isolation.StoreOperationUninstallDeployment.Disposition)dispositionValue).ToString();
							DefinitionAppId definitionAppId4 = new DefinitionAppId(storeOperationUninstallDeployment.Application);
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionUninstallDeployment"), storeOperationUninstallDeployment.GetType().ToString(), text, hresult, definitionAppId4.ToString());
							if (dispositionValue == 0)
							{
								_failureMessage = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionUninstallDeploymentFailure"), definitionAppId4.ToString());
								_failed = true;
							}
						}
						else if (operation.Operation == System.Deployment.Internal.Isolation.StoreTransactionOperationType.SetDeploymentMetadata)
						{
							System.Deployment.Internal.Isolation.StoreOperationSetDeploymentMetadata storeOperationSetDeploymentMetadata = (System.Deployment.Internal.Isolation.StoreOperationSetDeploymentMetadata)Marshal.PtrToStructure(operation.Data.DataPtr, typeof(System.Deployment.Internal.Isolation.StoreOperationSetDeploymentMetadata));
							text = ((System.Deployment.Internal.Isolation.StoreOperationSetDeploymentMetadata.Disposition)dispositionValue).ToString();
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionSetDeploymentMetadata"), storeOperationSetDeploymentMetadata.GetType().ToString(), text, hresult);
							if (dispositionValue == 0)
							{
								_failureMessage = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionSetDeploymentMetadataFailure"));
								_failed = true;
							}
						}
						else if (operation.Operation == System.Deployment.Internal.Isolation.StoreTransactionOperationType.StageComponentFile)
						{
							System.Deployment.Internal.Isolation.StoreOperationStageComponentFile storeOperationStageComponentFile = (System.Deployment.Internal.Isolation.StoreOperationStageComponentFile)Marshal.PtrToStructure(operation.Data.DataPtr, typeof(System.Deployment.Internal.Isolation.StoreOperationStageComponentFile));
							text = ((System.Deployment.Internal.Isolation.StoreOperationStageComponentFile.Disposition)dispositionValue).ToString();
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionStageComponentFile"), storeOperationStageComponentFile.GetType().ToString(), text, hresult, storeOperationStageComponentFile.ComponentRelativePath);
							if (dispositionValue == 0)
							{
								_failureMessage = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionStageComponentFileFailure"), storeOperationStageComponentFile.ComponentRelativePath);
								_failed = true;
							}
						}
						else
						{
							_message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionUnknownOperation"), operation.Operation.GetType().ToString(), (uint)operation.Operation, hresult);
						}
					}
					catch (FormatException)
					{
					}
					catch (ArgumentException)
					{
					}
				}
			}

			protected ArrayList _operations = new ArrayList();

			protected bool _failed;

			public bool Failed => _failed;

			public string FailureSummary
			{
				get
				{
					if (Failed)
					{
						StringBuilder stringBuilder = new StringBuilder();
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionFailureSummaryItem"), base.Time.ToString(DateTimeFormatInfo.CurrentInfo));
						foreach (TransactionOperation operation in _operations)
						{
							if (operation.Failed)
							{
								stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionFailureSummaryBullets"), operation.FailureMessage);
							}
						}
						return stringBuilder.ToString();
					}
					return Resources.GetString("LogFile_TransactionFailureSummaryNoFailure");
				}
			}

			public TransactionInformation(System.Deployment.Internal.Isolation.StoreTransactionOperation[] storeOperations, uint[] rgDispositions, int[] rgResults, DateTime time)
				: base(null, time)
			{
				int num = Math.Min(Math.Min(storeOperations.Length, rgDispositions.Length), rgResults.Length);
				int num2 = 0;
				for (num2 = 0; num2 < num; num2++)
				{
					TransactionOperation transactionOperation = new TransactionOperation(storeOperations[num2], rgDispositions[num2], rgResults[num2]);
					_operations.Add(transactionOperation);
					if (transactionOperation.Failed)
					{
						_failed = true;
					}
				}
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionItem"), base.Time.ToString(DateTimeFormatInfo.CurrentInfo));
				foreach (TransactionOperation operation in _operations)
				{
					stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_TransactionBullets"), operation);
				}
				return stringBuilder.ToString();
			}
		}

		protected class HeaderSection : LogInformation
		{
			public HeaderSection()
			{
				_message = GenerateLogHeaderText();
			}

			public override string ToString()
			{
				return _message;
			}

			protected static string GetModulePathInSystemFolder(string moduleName)
			{
				try
				{
					return Path.Combine(Environment.SystemDirectory, moduleName);
				}
				catch (ArgumentException)
				{
					return null;
				}
			}

			protected static string GetModulePathInClrFolder(string moduleName)
			{
				string result = null;
				string loadedModulePath = NativeMethods.GetLoadedModulePath("dfsvc.exe");
				try
				{
					if (loadedModulePath != null)
					{
						string directoryName = Path.GetDirectoryName(loadedModulePath);
						return Path.Combine(directoryName, moduleName);
					}
					return result;
				}
				catch (ArgumentException)
				{
					return null;
				}
			}

			protected static string GetModulePath(string moduleName)
			{
				string text = NativeMethods.GetLoadedModulePath(moduleName);
				if (text == null)
				{
					text = GetModulePathInClrFolder(moduleName);
					if (text == null)
					{
						text = GetModulePathInSystemFolder(moduleName);
					}
				}
				return text;
			}

			protected static string GetExecutingAssemblyPath()
			{
				Assembly executingAssembly = Assembly.GetExecutingAssembly();
				return executingAssembly.Location;
			}

			protected static FileVersionInfo GetVersionInfo(string modulePath)
			{
				FileVersionInfo result = null;
				if (modulePath != null && System.IO.File.Exists(modulePath))
				{
					try
					{
						result = FileVersionInfo.GetVersionInfo(modulePath);
						return result;
					}
					catch (FileNotFoundException)
					{
						return result;
					}
				}
				return result;
			}

			protected static string GenerateLogHeaderText()
			{
				string executingAssemblyPath = GetExecutingAssemblyPath();
				string modulePath = GetModulePath("mscorwks.dll");
				string modulePath2 = GetModulePath("dfdll.dll");
				string modulePath3 = GetModulePath("dfshim.dll");
				FileVersionInfo versionInfo = GetVersionInfo(executingAssemblyPath);
				if (versionInfo == null)
				{
					executingAssemblyPath = GetModulePathInClrFolder("system.deployment.dll");
					versionInfo = GetVersionInfo(executingAssemblyPath);
				}
				FileVersionInfo versionInfo2 = GetVersionInfo(modulePath);
				FileVersionInfo versionInfo3 = GetVersionInfo(modulePath2);
				FileVersionInfo versionInfo4 = GetVersionInfo(modulePath3);
				StringBuilder stringBuilder = new StringBuilder();
				try
				{
					stringBuilder.Append(Resources.GetString("LogFile_Header"));
					stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_HeaderOSVersion"), Environment.OSVersion.Platform.ToString(), Environment.OSVersion.Version.ToString());
					stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_HeaderCLRVersion"), Environment.Version.ToString());
					if (versionInfo != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_HeaderSystemDeploymentVersion"), versionInfo.FileVersion);
					}
					if (versionInfo2 != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_HeaderMscorwksVersion"), versionInfo2.FileVersion);
					}
					if (versionInfo3 != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_HeaderDfdllVersion"), versionInfo3.FileVersion);
					}
					if (versionInfo4 != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_HeaderDfshimVersion"), versionInfo4.FileVersion);
					}
				}
				catch (ArgumentException)
				{
				}
				catch (FormatException)
				{
				}
				return stringBuilder.ToString();
			}
		}

		protected class SourceSection : LogInformation
		{
			protected Uri _subscriptonUri;

			protected Uri _deploymentProviderUri;

			protected Uri _applicationUri;

			protected ServerInformation _subscriptionServerInformation;

			protected ServerInformation _deploymentProviderServerInformation;

			protected ServerInformation _applicationServerInformation;

			public Uri SubscriptionUri
			{
				set
				{
					_subscriptonUri = value;
				}
			}

			public Uri DeploymentProviderUri
			{
				set
				{
					_deploymentProviderUri = value;
				}
			}

			public Uri ApplicationUri
			{
				set
				{
					_applicationUri = value;
				}
			}

			public ServerInformation SubscriptionServerInformation
			{
				set
				{
					_subscriptionServerInformation = value;
				}
			}

			public ServerInformation DeploymentProviderServerInformation
			{
				set
				{
					_deploymentProviderServerInformation = value;
				}
			}

			public ServerInformation ApplicationServerInformation
			{
				set
				{
					_applicationServerInformation = value;
				}
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				if (_subscriptonUri != null || _deploymentProviderUri != null || _applicationUri != null)
				{
					stringBuilder.Append(Resources.GetString("LogFile_Source"));
					if (_subscriptonUri != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_SourceDeploymentUrl"), _subscriptonUri.AbsoluteUri);
					}
					if (_subscriptionServerInformation != null)
					{
						AppendServerInformation(stringBuilder, _subscriptionServerInformation);
					}
					if (_deploymentProviderUri != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_SourceDeploymentProviderUrl"), _deploymentProviderUri.AbsoluteUri);
					}
					if (_deploymentProviderServerInformation != null)
					{
						AppendServerInformation(stringBuilder, _deploymentProviderServerInformation);
					}
					if (_applicationUri != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_SourceApplicationUrl"), _applicationUri.AbsoluteUri);
					}
					if (_applicationServerInformation != null)
					{
						AppendServerInformation(stringBuilder, _applicationServerInformation);
					}
					stringBuilder.Append(Environment.NewLine);
				}
				return stringBuilder.ToString();
			}

			private static void AppendServerInformation(StringBuilder destination, ServerInformation serverInformation)
			{
				if (!string.IsNullOrEmpty(serverInformation.Server))
				{
					destination.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_ServerInformationServer"), serverInformation.Server);
				}
				if (!string.IsNullOrEmpty(serverInformation.PoweredBy))
				{
					destination.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_ServerInformationPoweredBy"), serverInformation.PoweredBy);
				}
				if (!string.IsNullOrEmpty(serverInformation.AspNetVersion))
				{
					destination.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_ServerInformationAspNetVersion"), serverInformation.AspNetVersion);
				}
			}
		}

		protected class IdentitySection : LogInformation
		{
			protected DefinitionIdentity _deploymentIdentity;

			protected DefinitionIdentity _applicationIdentity;

			public DefinitionIdentity DeploymentIdentity
			{
				get
				{
					return _deploymentIdentity;
				}
				set
				{
					_deploymentIdentity = value;
				}
			}

			public DefinitionIdentity ApplicationIdentity
			{
				set
				{
					_applicationIdentity = value;
				}
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				if (_deploymentIdentity != null || _applicationIdentity != null)
				{
					stringBuilder.Append(Resources.GetString("LogFile_Identity"));
					if (_deploymentIdentity != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_IdentityDeploymentIdentity"), _deploymentIdentity.ToString());
					}
					if (_applicationIdentity != null)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_IdentityApplicationIdentity"), _applicationIdentity.ToString());
					}
					stringBuilder.Append(Environment.NewLine);
				}
				return stringBuilder.ToString();
			}
		}

		protected class SummarySection : LogInformation
		{
			protected AssemblyManifest _deploymentManifest;

			protected AssemblyManifest _applicationManifest;

			public AssemblyManifest DeploymentManifest
			{
				set
				{
					_deploymentManifest = value;
				}
			}

			public AssemblyManifest ApplicationManifest
			{
				set
				{
					_applicationManifest = value;
				}
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				if (_deploymentManifest != null)
				{
					stringBuilder.Append(Resources.GetString("LogFile_Summary"));
					if (_deploymentManifest.Deployment.Install)
					{
						stringBuilder.Append(Resources.GetString("LogFile_SummaryInstallableApp"));
					}
					else
					{
						stringBuilder.Append(Resources.GetString("LogFile_SummaryOnlineOnlyApp"));
					}
					if (_deploymentManifest.Deployment.TrustURLParameters)
					{
						stringBuilder.Append(Resources.GetString("LogFile_SummaryTrustUrlParameterSet"));
					}
					if (_applicationManifest != null && _applicationManifest.EntryPoints[0].HostInBrowser)
					{
						stringBuilder.Append(Resources.GetString("LogFile_SummaryBrowserHostedApp"));
					}
					stringBuilder.Append(Environment.NewLine);
				}
				return stringBuilder.ToString();
			}
		}

		protected class ErrorSection : LogInformation
		{
			protected ArrayList _errors = new ArrayList();

			public string ErrorSummary
			{
				get
				{
					StringBuilder stringBuilder = new StringBuilder();
					stringBuilder.Append(Resources.GetString("LogFile_ErrorSummary"));
					if (_errors.Count > 0)
					{
						stringBuilder.Append(Resources.GetString("LogFile_ErrorSummaryStatusError"));
						foreach (ErrorInformation error in _errors)
						{
							stringBuilder.Append(error.Summary);
						}
					}
					else
					{
						stringBuilder.Append(Resources.GetString("LogFile_ErrorSummaryStatusNoError"));
					}
					return stringBuilder.ToString();
				}
			}

			public void AddError(string message, Exception exception, DateTime time)
			{
				ErrorInformation value = new ErrorInformation(message, exception, time);
				_errors.Add(value);
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(Resources.GetString("LogFile_Error"));
				if (_errors.Count > 0)
				{
					stringBuilder.Append(Resources.GetString("LogFile_ErrorStatusError"));
					foreach (ErrorInformation error in _errors)
					{
						stringBuilder.Append(error.ToString());
					}
				}
				else
				{
					stringBuilder.Append(Resources.GetString("LogFile_ErrorStatusNoError"));
				}
				return stringBuilder.ToString();
			}
		}

		protected class WarningSection : LogInformation
		{
			protected ArrayList _warnings = new ArrayList();

			public void AddWarning(string message, DateTime time)
			{
				LogInformation value = new LogInformation(message, time);
				_warnings.Add(value);
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(Resources.GetString("LogFile_Warning"));
				if (_warnings.Count > 0)
				{
					foreach (LogInformation warning in _warnings)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_WarningStatusIndivualWarning"), warning.Message);
					}
				}
				else
				{
					stringBuilder.Append(Resources.GetString("LogFile_WarningStatusNoWarning"));
				}
				return stringBuilder.ToString();
			}
		}

		protected class PhaseSection : LogInformation
		{
			protected ArrayList _phaseInformations = new ArrayList();

			public void AddPhaseInformation(string phaseMessage, DateTime time)
			{
				LogInformation value = new LogInformation(phaseMessage, time);
				_phaseInformations.Add(value);
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(Resources.GetString("LogFile_PhaseInformation"));
				if (_phaseInformations.Count > 0)
				{
					foreach (LogInformation phaseInformation in _phaseInformations)
					{
						stringBuilder.AppendFormat(CultureInfo.CurrentUICulture, Resources.GetString("LogFile_PhaseInformationStatusIndivualPhaseInformation"), phaseInformation.Time.ToString(DateTimeFormatInfo.CurrentInfo), phaseInformation.Message);
					}
				}
				else
				{
					stringBuilder.Append(Resources.GetString("LogFile_PhaseInformationStatusNoPhaseInformation"));
				}
				return stringBuilder.ToString();
			}
		}

		protected class TransactionSection : LogInformation
		{
			protected ArrayList _transactionInformations = new ArrayList();

			protected ArrayList _failedTransactionInformations = new ArrayList();

			public string FailureSummary
			{
				get
				{
					StringBuilder stringBuilder = new StringBuilder();
					stringBuilder.Append(Resources.GetString("LogFile_TransactionFailureSummary"));
					if (_failedTransactionInformations.Count > 0)
					{
						foreach (TransactionInformation failedTransactionInformation in _failedTransactionInformations)
						{
							stringBuilder.Append(failedTransactionInformation.FailureSummary);
						}
					}
					else
					{
						stringBuilder.Append(Resources.GetString("LogFile_TransactionFailureSummaryNoError"));
					}
					return stringBuilder.ToString();
				}
			}

			public void AddTransactionInformation(System.Deployment.Internal.Isolation.StoreTransactionOperation[] storeOperations, uint[] rgDispositions, int[] rgResults, DateTime time)
			{
				TransactionInformation transactionInformation = new TransactionInformation(storeOperations, rgDispositions, rgResults, time);
				_transactionInformations.Add(transactionInformation);
				if (transactionInformation.Failed)
				{
					_failedTransactionInformations.Add(transactionInformation);
				}
			}

			public override string ToString()
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(Resources.GetString("LogFile_Transaction"));
				if (_transactionInformations.Count > 0)
				{
					foreach (TransactionInformation transactionInformation in _transactionInformations)
					{
						stringBuilder.Append(transactionInformation.ToString());
					}
				}
				else
				{
					stringBuilder.Append(Resources.GetString("LogFile_TransactionNoTransaction"));
				}
				return stringBuilder.ToString();
			}
		}

		public class LogIdentity
		{
			protected readonly long _ticks = DateTime.Now.Ticks;

			protected readonly uint _threadId = NativeMethods.GetCurrentThreadId();

			protected string _logIdentityStringForm;

			public uint ThreadId => _threadId;

			public override string ToString()
			{
				if (_logIdentityStringForm == null)
				{
					_logIdentityStringForm = string.Format(CultureInfo.InvariantCulture, "{0:x8}{1:x16}", _threadId, _ticks);
				}
				return _logIdentityStringForm;
			}
		}

		protected enum LogFileLocation
		{
			NoLogFile,
			RegistryBased,
			WinInetCache
		}

		protected SourceSection _sources = new SourceSection();

		protected IdentitySection _identities = new IdentitySection();

		protected SummarySection _summary = new SummarySection();

		protected ErrorSection _errors = new ErrorSection();

		protected WarningSection _warnings = new WarningSection();

		protected PhaseSection _phases = new PhaseSection();

		protected TransactionSection _transactions = new TransactionSection();

		protected LogIdentity _logIdentity = new LogIdentity();

		protected string _logFilePath;

		protected string _urlName;

		protected LogFileLocation _logFileLocation;

		protected static object _logFileEncoding;

		protected static Hashtable _loggerCollection = new Hashtable();

		protected static Hashtable _threadLogIdTable = new Hashtable();

		protected static object _logAccessLock = new object();

		protected static object _header = null;

		protected TransactionSection Transactions => _transactions;

		protected ErrorSection Errors => _errors;

		protected WarningSection Warnings => _warnings;

		protected PhaseSection Phases => _phases;

		protected SourceSection Sources => _sources;

		protected IdentitySection Identities => _identities;

		protected SummarySection Summary => _summary;

		protected LogIdentity Identity => _logIdentity;

		protected string LogFilePath
		{
			get
			{
				if (_logFilePath == null)
				{
					_logFilePath = GetRegitsryBasedLogFilePath();
					if (_logFilePath == null)
					{
						_logFilePath = GetWinInetBasedLogFilePath();
						if (_logFilePath != null)
						{
							_logFileLocation = LogFileLocation.WinInetCache;
						}
					}
					else
					{
						_logFileLocation = LogFileLocation.RegistryBased;
					}
				}
				return _logFilePath;
			}
		}

		protected static Encoding LogFileEncoding
		{
			get
			{
				if (_logFileEncoding == null)
				{
					Encoding encoding = null;
					encoding = ((!PlatformSpecific.OnWin9x) ? Encoding.Unicode : Encoding.Default);
					Interlocked.CompareExchange(ref _logFileEncoding, encoding, null);
				}
				return (Encoding)_logFileEncoding;
			}
		}

		protected static HeaderSection Header
		{
			get
			{
				if (_header == null)
				{
					object value = new HeaderSection();
					Interlocked.CompareExchange(ref _header, value, null);
				}
				return (HeaderSection)_header;
			}
		}

		protected Logger()
		{
		}

		protected string GetRegitsryBasedLogFilePath()
		{
			string result = null;
			try
			{
				using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Classes\\Software\\Microsoft\\Windows\\CurrentVersion\\Deployment");
				if (registryKey != null)
				{
					result = registryKey.GetValue("LogFilePath") as string;
					return result;
				}
				return result;
			}
			catch (ArgumentException)
			{
				return result;
			}
			catch (ObjectDisposedException)
			{
				return result;
			}
		}

		protected string GetWinInetBasedLogFilePath()
		{
			try
			{
				string text = "System_Deployment_Log_";
				if (Identities.DeploymentIdentity != null)
				{
					text += Identities.DeploymentIdentity.KeyForm;
				}
				text = string.Format(CultureInfo.InvariantCulture, "{0}_{1}", text, Identity.ToString());
				StringBuilder stringBuilder = new StringBuilder(261);
				if (!NativeMethods.CreateUrlCacheEntry(text, 0, "log", stringBuilder, 0))
				{
					return null;
				}
				_urlName = text;
				return stringBuilder.ToString();
			}
			catch (COMException)
			{
				return null;
			}
			catch (SEHException)
			{
				return null;
			}
			catch (FormatException)
			{
				return null;
			}
		}

		protected FileStream CreateLogFileStream()
		{
			FileStream result = null;
			string logFilePath = LogFilePath;
			for (uint num = 0u; num < 1000; num++)
			{
				try
				{
					if (_logFileLocation == LogFileLocation.RegistryBased)
					{
						result = new FileStream(logFilePath, FileMode.Append, FileAccess.Write, FileShare.None);
						return result;
					}
					result = new FileStream(logFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
					return result;
				}
				catch (IOException)
				{
					if (num == 1000)
					{
						throw;
					}
				}
				Thread.Sleep(20);
			}
			return result;
		}

		protected bool FlushLogs()
		{
			FileStream fileStream = null;
			try
			{
				fileStream = CreateLogFileStream();
				if (fileStream == null)
				{
					return false;
				}
			}
			catch (IOException)
			{
				return false;
			}
			catch (SecurityException)
			{
				return false;
			}
			catch (UnauthorizedAccessException)
			{
				return false;
			}
			StreamWriter streamWriter = new StreamWriter(fileStream, LogFileEncoding);
			streamWriter.WriteLine(Header);
			streamWriter.Write(Sources);
			streamWriter.Write(Identities);
			streamWriter.Write(Summary);
			streamWriter.WriteLine(Errors.ErrorSummary);
			streamWriter.WriteLine(Transactions.FailureSummary);
			streamWriter.WriteLine(Warnings);
			streamWriter.WriteLine(Phases);
			streamWriter.WriteLine(Errors);
			streamWriter.WriteLine(Transactions);
			streamWriter.Close();
			fileStream.Close();
			return true;
		}

		protected void EndLogOperation()
		{
			if (FlushLogs() && _logFileLocation == LogFileLocation.WinInetCache)
			{
				NativeMethods.CommitUrlCacheEntry(_urlName, _logFilePath, 0L, 0L, 4u, null, 0, null, null);
			}
		}

		protected static uint GetCurrentLogThreadId()
		{
			return NativeMethods.GetCurrentThreadId();
		}

		protected static Logger GetCurrentThreadLogger()
		{
			Logger result = null;
			uint currentLogThreadId = GetCurrentLogThreadId();
			lock (_logAccessLock)
			{
				if (_threadLogIdTable.Contains(currentLogThreadId))
				{
					LogIdentity logIdentity = (LogIdentity)_threadLogIdTable[currentLogThreadId];
					if (_loggerCollection.Contains(logIdentity.ToString()))
					{
						return (Logger)_loggerCollection[logIdentity.ToString()];
					}
					return result;
				}
				return result;
			}
		}

		protected static Logger GetLogger(LogIdentity logIdentity)
		{
			Logger result = null;
			lock (_logAccessLock)
			{
				if (_loggerCollection.Contains(logIdentity.ToString()))
				{
					return (Logger)_loggerCollection[logIdentity.ToString()];
				}
				return result;
			}
		}

		protected static void AddLogger(Logger logger)
		{
			lock (_logAccessLock)
			{
				if (!_loggerCollection.Contains(logger.Identity.ToString()))
				{
					_loggerCollection.Add(logger.Identity.ToString(), logger);
				}
			}
		}

		protected static void AddCurrentThreadLogger(Logger logger)
		{
			lock (_logAccessLock)
			{
				if (_threadLogIdTable.Contains(logger.Identity.ThreadId))
				{
					_threadLogIdTable.Remove(logger.Identity.ThreadId);
				}
				_threadLogIdTable.Add(logger.Identity.ThreadId, logger.Identity);
				if (!_loggerCollection.Contains(logger.Identity.ToString()))
				{
					_loggerCollection.Add(logger.Identity.ToString(), logger);
				}
			}
		}

		protected static void RemoveLogger(LogIdentity logIdentity)
		{
			lock (_logAccessLock)
			{
				if (_loggerCollection.Contains(logIdentity.ToString()))
				{
					_loggerCollection.Remove(logIdentity.ToString());
				}
			}
		}

		protected static void RemoveCurrentThreadLogger()
		{
			lock (_logAccessLock)
			{
				uint currentLogThreadId = GetCurrentLogThreadId();
				if (_threadLogIdTable.Contains(currentLogThreadId))
				{
					LogIdentity logIdentity = (LogIdentity)_threadLogIdTable[currentLogThreadId];
					_threadLogIdTable.Remove(currentLogThreadId);
					if (_loggerCollection.Contains(logIdentity.ToString()))
					{
						_loggerCollection.Remove(logIdentity.ToString());
					}
				}
			}
		}

		internal static LogIdentity StartCurrentThreadLogging()
		{
			EndCurrentThreadLogging();
			Logger logger = new Logger();
			AddCurrentThreadLogger(logger);
			return logger.Identity;
		}

		internal static void EndCurrentThreadLogging()
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.EndLogOperation();
				}
				RemoveCurrentThreadLogger();
			}
		}

		internal static LogIdentity StartLogging()
		{
			Logger logger = new Logger();
			AddLogger(logger);
			return logger.Identity;
		}

		internal static void EndLogging(LogIdentity logIdentity)
		{
			try
			{
				Logger logger = GetLogger(logIdentity);
				if (logger != null)
				{
					lock (logger)
					{
						logger.EndLogOperation();
					}
				}
				RemoveLogger(logIdentity);
			}
			catch (Exception)
			{
			}
		}

		internal static void SetSubscriptionUrl(Uri subscriptionUri)
		{
			GetCurrentThreadLogger()?.SetSubscriptionUri(subscriptionUri);
		}

		internal static void SetSubscriptionUrl(LogIdentity log, Uri subscriptionUri)
		{
			GetLogger(log)?.SetSubscriptionUri(subscriptionUri);
		}

		private void SetSubscriptionUri(Uri subscriptionUri)
		{
			lock (this)
			{
				Sources.SubscriptionUri = subscriptionUri;
			}
		}

		internal static void SetSubscriptionServerInformation(ServerInformation serverInformation)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Sources.SubscriptionServerInformation = serverInformation;
				}
			}
		}

		internal static void SetSubscriptionUrl(string subscrioptionUrl)
		{
			try
			{
				Uri subscriptionUrl = new Uri(subscrioptionUrl);
				SetSubscriptionUrl(subscriptionUrl);
			}
			catch (UriFormatException)
			{
			}
		}

		internal static void SetDeploymentProviderUrl(Uri deploymentProviderUri)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Sources.DeploymentProviderUri = deploymentProviderUri;
				}
			}
		}

		internal static void SetDeploymentProviderServerInformation(ServerInformation serverInformation)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Sources.DeploymentProviderServerInformation = serverInformation;
				}
			}
		}

		internal static void SetApplicationUrl(Uri applicationUri)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Sources.ApplicationUri = applicationUri;
				}
			}
		}

		internal static void SetApplicationUrl(LogIdentity log, Uri applicationUri)
		{
			Logger logger = GetLogger(log);
			if (logger != null)
			{
				lock (logger)
				{
					logger.Sources.ApplicationUri = applicationUri;
				}
			}
		}

		internal static void SetApplicationServerInformation(ServerInformation serverInformation)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Sources.ApplicationServerInformation = serverInformation;
				}
			}
		}

		internal static void SetTextualSubscriptionIdentity(string textualIdentity)
		{
			try
			{
				GetCurrentThreadLogger()?.SetTextualSubscriptionIdentity(new DefinitionIdentity(textualIdentity));
			}
			catch (COMException)
			{
			}
			catch (SEHException)
			{
			}
		}

		internal static void SetTextualSubscriptionIdentity(LogIdentity log, string textualIdentity)
		{
			try
			{
				GetLogger(log)?.SetTextualSubscriptionIdentity(new DefinitionIdentity(textualIdentity));
			}
			catch (COMException)
			{
			}
			catch (SEHException)
			{
			}
		}

		internal void SetTextualSubscriptionIdentity(DefinitionIdentity definitionIdentity)
		{
			lock (this)
			{
				Identities.DeploymentIdentity = definitionIdentity;
			}
		}

		internal static void SetDeploymentManifest(AssemblyManifest deploymentManifest)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger == null)
			{
				return;
			}
			lock (currentThreadLogger)
			{
				if (deploymentManifest.Identity != null)
				{
					currentThreadLogger.Identities.DeploymentIdentity = deploymentManifest.Identity;
				}
				currentThreadLogger.Summary.DeploymentManifest = deploymentManifest;
			}
		}

		internal static void SetDeploymentManifest(LogIdentity log, AssemblyManifest deploymentManifest)
		{
			Logger logger = GetLogger(log);
			if (logger == null)
			{
				return;
			}
			lock (logger)
			{
				if (deploymentManifest.Identity != null)
				{
					logger.Identities.DeploymentIdentity = deploymentManifest.Identity;
				}
				logger.Summary.DeploymentManifest = deploymentManifest;
			}
		}

		internal static void SetApplicationManifest(AssemblyManifest applicationManifest)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger == null)
			{
				return;
			}
			lock (currentThreadLogger)
			{
				if (applicationManifest.Identity != null)
				{
					currentThreadLogger.Identities.ApplicationIdentity = applicationManifest.Identity;
				}
				currentThreadLogger.Summary.ApplicationManifest = applicationManifest;
			}
		}

		internal static void SetApplicationManifest(LogIdentity log, AssemblyManifest applicationManifest)
		{
			Logger logger = GetLogger(log);
			if (logger == null)
			{
				return;
			}
			lock (logger)
			{
				if (applicationManifest.Identity != null)
				{
					logger.Identities.ApplicationIdentity = applicationManifest.Identity;
				}
				logger.Summary.ApplicationManifest = applicationManifest;
			}
		}

		internal static void AddErrorInformation(string message, Exception exception, DateTime time)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Errors.AddError(message, exception, time);
				}
			}
		}

		internal static void AddErrorInformation(LogIdentity log, string message, Exception exception, DateTime time)
		{
			Logger logger = GetLogger(log);
			if (logger != null)
			{
				lock (logger)
				{
					logger.Errors.AddError(message, exception, time);
				}
			}
		}

		internal static void AddWarningInformation(string message, DateTime time)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Warnings.AddWarning(message, time);
				}
			}
		}

		internal static void AddPhaseInformation(string message, DateTime time)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Phases.AddPhaseInformation(message, time);
				}
			}
		}

		internal static void AddTransactionInformation(System.Deployment.Internal.Isolation.StoreTransactionOperation[] storeOperations, uint[] rgDispositions, int[] rgResults, DateTime time)
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					currentThreadLogger.Transactions.AddTransactionInformation(storeOperations, rgDispositions, rgResults, time);
				}
			}
		}

		internal static void AddErrorInformation(string message, Exception exception)
		{
			AddErrorInformation(message, exception, DateTime.Now);
		}

		internal static void AddErrorInformation(LogIdentity log, string message, Exception exception)
		{
			AddErrorInformation(log, message, exception, DateTime.Now);
		}

		internal static void AddErrorInformation(Exception exception, string messageFormat, params object[] args)
		{
			try
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendFormat(messageFormat, args);
				AddErrorInformation(stringBuilder.ToString(), exception, DateTime.Now);
			}
			catch (FormatException)
			{
			}
		}

		internal static void AddWarningInformation(string message)
		{
			AddWarningInformation(message, DateTime.Now);
		}

		internal static void AddPhaseInformation(string message)
		{
			AddPhaseInformation(message, DateTime.Now);
		}

		internal static void AddPhaseInformation(string messageFormat, params object[] args)
		{
			try
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendFormat(messageFormat, args);
				AddPhaseInformation(stringBuilder.ToString(), DateTime.Now);
			}
			catch (FormatException)
			{
			}
		}

		internal static void AddTransactionInformation(System.Deployment.Internal.Isolation.StoreTransactionOperation[] storeOperations, uint[] rgDispositions, int[] rgResults)
		{
			AddTransactionInformation(storeOperations, rgDispositions, rgResults, DateTime.Now);
		}

		internal static string GetLogFilePath()
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				return GetLogFilePath(currentThreadLogger);
			}
			return null;
		}

		internal static string GetLogFilePath(LogIdentity log)
		{
			Logger logger = GetLogger(log);
			if (logger != null)
			{
				return GetLogFilePath(logger);
			}
			return null;
		}

		internal static string GetLogFilePath(Logger logger)
		{
			if (logger == null)
			{
				return null;
			}
			lock (logger)
			{
				return logger.LogFilePath;
			}
		}

		internal static bool FlushCurrentThreadLogs()
		{
			Logger currentThreadLogger = GetCurrentThreadLogger();
			if (currentThreadLogger != null)
			{
				lock (currentThreadLogger)
				{
					return currentThreadLogger.FlushLogs();
				}
			}
			return false;
		}

		internal static bool FlushLog(LogIdentity log)
		{
			Logger logger = GetLogger(log);
			if (logger != null)
			{
				lock (logger)
				{
					return logger.FlushLogs();
				}
			}
			return false;
		}
	}
	internal class MaintenancePiece : ModalPiece
	{
		private Label lblHeader;

		private Label lblSubHeader;

		private PictureBox pictureDesktop;

		private PictureBox pictureRestore;

		private PictureBox pictureRemove;

		private RadioButton radioRestore;

		private RadioButton radioRemove;

		private GroupBox groupRule;

		private GroupBox groupDivider;

		private Button btnOk;

		private Button btnCancel;

		private Button btnHelp;

		private TableLayoutPanel okCancelHelpTableLayoutPanel;

		private TableLayoutPanel contentTableLayoutPanel;

		private TableLayoutPanel topTableLayoutPanel;

		private TableLayoutPanel overarchingTableLayoutPanel;

		private UserInterfaceInfo _info;

		private MaintenanceInfo _maintenanceInfo;

		public MaintenancePiece(UserInterfaceForm parentForm, UserInterfaceInfo info, MaintenanceInfo maintenanceInfo, ManualResetEvent modalEvent)
		{
			_modalResult = UserInterfaceModalResult.Cancel;
			_info = info;
			_maintenanceInfo = maintenanceInfo;
			_modalEvent = modalEvent;
			SuspendLayout();
			InitializeComponent();
			InitializeContent();
			ResumeLayout(performLayout: false);
			parentForm.SuspendLayout();
			parentForm.SwitchUserInterfacePiece(this);
			parentForm.Text = _info.formTitle;
			parentForm.MinimizeBox = false;
			parentForm.MaximizeBox = false;
			parentForm.ControlBox = true;
			lblHeader.Font = new Font(lblHeader.Font, lblHeader.Font.Style | FontStyle.Bold);
			parentForm.ActiveControl = btnCancel;
			parentForm.ResumeLayout(performLayout: false);
			parentForm.PerformLayout();
			parentForm.Visible = true;
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.Deployment.Application.MaintenancePiece));
			this.lblHeader = new System.Windows.Forms.Label();
			this.lblSubHeader = new System.Windows.Forms.Label();
			this.pictureRestore = new System.Windows.Forms.PictureBox();
			this.pictureRemove = new System.Windows.Forms.PictureBox();
			this.radioRestore = new System.Windows.Forms.RadioButton();
			this.radioRemove = new System.Windows.Forms.RadioButton();
			this.groupRule = new System.Windows.Forms.GroupBox();
			this.groupDivider = new System.Windows.Forms.GroupBox();
			this.btnOk = new System.Windows.Forms.Button();
			this.btnCancel = new System.Windows.Forms.Button();
			this.btnHelp = new System.Windows.Forms.Button();
			this.topTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.pictureDesktop = new System.Windows.Forms.PictureBox();
			this.okCancelHelpTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.contentTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.overarchingTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			((System.ComponentModel.ISupportInitialize)this.pictureRestore).BeginInit();
			((System.ComponentModel.ISupportInitialize)this.pictureRemove).BeginInit();
			this.topTableLayoutPanel.SuspendLayout();
			((System.ComponentModel.ISupportInitialize)this.pictureDesktop).BeginInit();
			this.okCancelHelpTableLayoutPanel.SuspendLayout();
			this.contentTableLayoutPanel.SuspendLayout();
			this.overarchingTableLayoutPanel.SuspendLayout();
			base.SuspendLayout();
			this.lblHeader.AutoEllipsis = true;
			resources.ApplyResources(this.lblHeader, "lblHeader");
			this.lblHeader.Margin = new System.Windows.Forms.Padding(10, 11, 3, 0);
			this.lblHeader.Name = "lblHeader";
			this.lblHeader.UseMnemonic = false;
			resources.ApplyResources(this.lblSubHeader, "lblSubHeader");
			this.lblSubHeader.Margin = new System.Windows.Forms.Padding(29, 3, 3, 8);
			this.lblSubHeader.Name = "lblSubHeader";
			resources.ApplyResources(this.pictureRestore, "pictureRestore");
			this.pictureRestore.Margin = new System.Windows.Forms.Padding(0, 0, 3, 0);
			this.pictureRestore.Name = "pictureRestore";
			this.pictureRestore.TabStop = false;
			resources.ApplyResources(this.pictureRemove, "pictureRemove");
			this.pictureRemove.Margin = new System.Windows.Forms.Padding(0, 0, 3, 0);
			this.pictureRemove.Name = "pictureRemove";
			this.pictureRemove.TabStop = false;
			resources.ApplyResources(this.radioRestore, "radioRestore");
			this.radioRestore.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
			this.radioRestore.Name = "radioRestore";
			this.radioRestore.CheckedChanged += new System.EventHandler(radioRestore_CheckedChanged);
			resources.ApplyResources(this.radioRemove, "radioRemove");
			this.radioRemove.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
			this.radioRemove.Name = "radioRemove";
			this.radioRemove.CheckedChanged += new System.EventHandler(radioRemove_CheckedChanged);
			resources.ApplyResources(this.groupRule, "groupRule");
			this.groupRule.Margin = new System.Windows.Forms.Padding(0);
			this.groupRule.BackColor = System.Drawing.SystemColors.ControlDark;
			this.groupRule.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.groupRule.Name = "groupRule";
			this.groupRule.TabStop = false;
			resources.ApplyResources(this.groupDivider, "groupDivider");
			this.groupDivider.Margin = new System.Windows.Forms.Padding(0, 3, 0, 3);
			this.groupDivider.BackColor = System.Drawing.SystemColors.ControlDark;
			this.groupDivider.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.groupDivider.Name = "groupDivider";
			this.groupDivider.TabStop = false;
			resources.ApplyResources(this.btnOk, "btnOk");
			this.btnOk.Margin = new System.Windows.Forms.Padding(0, 0, 4, 0);
			this.btnOk.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnOk.Name = "btnOk";
			this.btnOk.Padding = new System.Windows.Forms.Padding(10, 0, 10, 0);
			this.btnOk.Click += new System.EventHandler(btnOk_Click);
			resources.ApplyResources(this.btnCancel, "btnCancel");
			this.btnCancel.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
			this.btnCancel.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnCancel.Name = "btnCancel";
			this.btnCancel.Padding = new System.Windows.Forms.Padding(10, 0, 10, 0);
			this.btnCancel.Click += new System.EventHandler(btnCancel_Click);
			resources.ApplyResources(this.btnHelp, "btnHelp");
			this.btnHelp.Margin = new System.Windows.Forms.Padding(4, 0, 0, 0);
			this.btnHelp.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnHelp.Name = "btnHelp";
			this.btnHelp.Padding = new System.Windows.Forms.Padding(10, 0, 10, 0);
			this.btnHelp.Click += new System.EventHandler(btnHelp_Click);
			resources.ApplyResources(this.topTableLayoutPanel, "topTableLayoutPanel");
			this.topTableLayoutPanel.BackColor = System.Drawing.SystemColors.Window;
			this.topTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 87.2f));
			this.topTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 12.8f));
			this.topTableLayoutPanel.Controls.Add(this.pictureDesktop, 1, 0);
			this.topTableLayoutPanel.Controls.Add(this.lblHeader, 0, 0);
			this.topTableLayoutPanel.Controls.Add(this.lblSubHeader, 0, 1);
			this.topTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0);
			this.topTableLayoutPanel.Name = "topTableLayoutPanel";
			this.topTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.topTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			resources.ApplyResources(this.pictureDesktop, "pictureDesktop");
			this.pictureDesktop.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
			this.pictureDesktop.Name = "pictureDesktop";
			this.topTableLayoutPanel.SetRowSpan(this.pictureDesktop, 2);
			this.pictureDesktop.TabStop = false;
			resources.ApplyResources(this.okCancelHelpTableLayoutPanel, "okCancelHelpTableLayoutPanel");
			this.okCancelHelpTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.okCancelHelpTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.okCancelHelpTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.okCancelHelpTableLayoutPanel.Controls.Add(this.btnOk, 0, 0);
			this.okCancelHelpTableLayoutPanel.Controls.Add(this.btnCancel, 1, 0);
			this.okCancelHelpTableLayoutPanel.Controls.Add(this.btnHelp, 2, 0);
			this.okCancelHelpTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0, 9, 8, 8);
			this.okCancelHelpTableLayoutPanel.Name = "okCancelHelpTableLayoutPanel";
			this.okCancelHelpTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			resources.ApplyResources(this.contentTableLayoutPanel, "contentTableLayoutPanel");
			this.contentTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.contentTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100f));
			this.contentTableLayoutPanel.Controls.Add(this.pictureRestore, 0, 0);
			this.contentTableLayoutPanel.Controls.Add(this.pictureRemove, 0, 1);
			this.contentTableLayoutPanel.Controls.Add(this.radioRemove, 1, 1);
			this.contentTableLayoutPanel.Controls.Add(this.radioRestore, 1, 0);
			this.contentTableLayoutPanel.Margin = new System.Windows.Forms.Padding(20, 22, 12, 22);
			this.contentTableLayoutPanel.Name = "contentTableLayoutPanel";
			this.contentTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.contentTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			resources.ApplyResources(this.overarchingTableLayoutPanel, "overarchingTableLayoutPanel");
			this.overarchingTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100f));
			this.overarchingTableLayoutPanel.Controls.Add(this.topTableLayoutPanel, 0, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.okCancelHelpTableLayoutPanel, 0, 4);
			this.overarchingTableLayoutPanel.Controls.Add(this.contentTableLayoutPanel, 0, 2);
			this.overarchingTableLayoutPanel.Controls.Add(this.groupDivider, 0, 3);
			this.overarchingTableLayoutPanel.Controls.Add(this.groupRule, 0, 1);
			this.overarchingTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0);
			this.overarchingTableLayoutPanel.Name = "overarchingTableLayoutPanel";
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			resources.ApplyResources(this, "$this");
			base.Controls.Add(this.overarchingTableLayoutPanel);
			base.Name = "MaintenancePiece";
			((System.ComponentModel.ISupportInitialize)this.pictureRestore).EndInit();
			((System.ComponentModel.ISupportInitialize)this.pictureRemove).EndInit();
			this.topTableLayoutPanel.ResumeLayout(false);
			this.topTableLayoutPanel.PerformLayout();
			((System.ComponentModel.ISupportInitialize)this.pictureDesktop).EndInit();
			this.okCancelHelpTableLayoutPanel.ResumeLayout(false);
			this.okCancelHelpTableLayoutPanel.PerformLayout();
			this.contentTableLayoutPanel.ResumeLayout(false);
			this.contentTableLayoutPanel.PerformLayout();
			this.overarchingTableLayoutPanel.ResumeLayout(false);
			this.overarchingTableLayoutPanel.PerformLayout();
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		private void InitializeContent()
		{
			pictureDesktop.Image = Resources.GetImage("setup.bmp");
			pictureRestore.Enabled = (_maintenanceInfo.maintenanceFlags & MaintenanceFlags.RestorationPossible) != 0;
			Bitmap bitmap = (Bitmap)Resources.GetImage("restore.bmp");
			bitmap.MakeTransparent();
			pictureRestore.Image = bitmap;
			Bitmap bitmap2 = (Bitmap)Resources.GetImage("remove.bmp");
			bitmap2.MakeTransparent();
			pictureRemove.Image = bitmap2;
			lblHeader.Text = _info.productName;
			radioRestore.Checked = (_maintenanceInfo.maintenanceFlags & MaintenanceFlags.RestorationPossible) != 0;
			radioRestore.Enabled = (_maintenanceInfo.maintenanceFlags & MaintenanceFlags.RestorationPossible) != 0;
			radioRemove.Checked = (_maintenanceInfo.maintenanceFlags & MaintenanceFlags.RestorationPossible) == 0;
			btnHelp.Enabled = UserInterface.IsValidHttpUrl(_info.supportUrl);
		}

		private void btnOk_Click(object sender, EventArgs e)
		{
			_modalResult = UserInterfaceModalResult.Ok;
			_modalEvent.Set();
			base.Enabled = false;
		}

		private void btnCancel_Click(object sender, EventArgs e)
		{
			_modalResult = UserInterfaceModalResult.Cancel;
			_modalEvent.Set();
			base.Enabled = false;
		}

		private void btnHelp_Click(object sender, EventArgs e)
		{
			if (UserInterface.IsValidHttpUrl(_info.supportUrl))
			{
				UserInterface.LaunchUrlInBrowser(_info.supportUrl);
			}
		}

		private void radioRestore_CheckedChanged(object sender, EventArgs e)
		{
			if (radioRestore.Checked)
			{
				_maintenanceInfo.maintenanceFlags |= MaintenanceFlags.RestoreSelected;
			}
			else
			{
				_maintenanceInfo.maintenanceFlags &= ~MaintenanceFlags.RestoreSelected;
			}
		}

		private void radioRemove_CheckedChanged(object sender, EventArgs e)
		{
			if (radioRemove.Checked)
			{
				_maintenanceInfo.maintenanceFlags |= MaintenanceFlags.RemoveSelected;
			}
			else
			{
				_maintenanceInfo.maintenanceFlags &= ~MaintenanceFlags.RemoveSelected;
			}
		}
	}
	[Flags]
	internal enum MaintenanceFlags
	{
		ClearFlag = 0,
		RestorationPossible = 1,
		RestoreSelected = 2,
		RemoveSelected = 4
	}
	internal class MaintenanceInfo
	{
		public MaintenanceFlags maintenanceFlags;
	}
	internal static class ManifestGenerator
	{
		private const string AssemblyTemplateResource = "AssemblyTemplate.xml";

		private static object assemblyTemplateDoc;

		private static object GACDetectionTempManifestAsmId;

		public static DefinitionIdentity GenerateManifest(ReferenceIdentity suggestedReferenceIdentity, AssemblyManifest manifest, string outputManifest)
		{
			DefinitionIdentity identity = manifest.Identity;
			if (manifest.RawXmlBytes != null)
			{
				using (FileStream fileStream = System.IO.File.Open(outputManifest, FileMode.CreateNew, FileAccess.Write))
				{
					fileStream.Write(manifest.RawXmlBytes, 0, manifest.RawXmlBytes.Length);
					return identity;
				}
			}
			XmlDocument xmlDocument = CloneAssemblyTemplate();
			identity = new DefinitionIdentity(suggestedReferenceIdentity);
			InjectIdentityXml(xmlDocument, identity);
			AddFiles(xmlDocument, manifest.Files);
			AddDependencies(xmlDocument, manifest.DependentAssemblies);
			using FileStream outStream = System.IO.File.Open(outputManifest, FileMode.CreateNew, FileAccess.Write);
			xmlDocument.Save(outStream);
			return identity;
		}

		public static void GenerateGACDetectionManifest(ReferenceIdentity refId, string outputManifest)
		{
			XmlDocument xmlDocument = CloneAssemblyTemplate();
			if (GACDetectionTempManifestAsmId == null)
			{
				Interlocked.CompareExchange(ref GACDetectionTempManifestAsmId, new DefinitionIdentity("GACDetectionTempManifest, version=1.0.0.0, type=win32"), null);
			}
			InjectIdentityXml(xmlDocument, (DefinitionIdentity)GACDetectionTempManifestAsmId);
			AddDependencies(xmlDocument, new DependentAssembly[1]
			{
				new DependentAssembly(refId)
			});
			using FileStream outStream = System.IO.File.Open(outputManifest, FileMode.CreateNew, FileAccess.Write);
			xmlDocument.Save(outStream);
		}

		private static void AddFiles(XmlDocument document, System.Deployment.Application.Manifest.File[] files)
		{
			XmlNamespaceManager namespaceMgr = GetNamespaceMgr(document);
			XmlElement assemblyNode = (XmlElement)document.SelectSingleNode("/asmv1:assembly", namespaceMgr);
			foreach (System.Deployment.Application.Manifest.File file in files)
			{
				AddFile(document, assemblyNode, file);
			}
		}

		private static void AddFile(XmlDocument document, XmlElement assemblyNode, System.Deployment.Application.Manifest.File file)
		{
			XmlElement xmlElement = document.CreateElement("file", "urn:schemas-microsoft-com:asm.v1");
			assemblyNode.AppendChild(xmlElement);
			XmlAttribute xmlAttribute = xmlElement.SetAttributeNode("name", null);
			xmlAttribute.Value = file.Name;
		}

		private static void AddDependencies(XmlDocument document, DependentAssembly[] dependentAssemblies)
		{
			Hashtable hashtable = new Hashtable();
			XmlNamespaceManager namespaceMgr = GetNamespaceMgr(document);
			XmlElement xmlElement = (XmlElement)document.SelectSingleNode("/asmv1:assembly", namespaceMgr);
			foreach (DependentAssembly dependentAssembly in dependentAssemblies)
			{
				if (!hashtable.Contains(dependentAssembly.Identity))
				{
					XmlElement xmlElement2 = document.CreateElement("dependency", "urn:schemas-microsoft-com:asm.v1");
					xmlElement.AppendChild(xmlElement2);
					XmlElement xmlElement3 = document.CreateElement("dependentAssembly", "urn:schemas-microsoft-com:asm.v1");
					xmlElement2.AppendChild(xmlElement3);
					ReferenceIdentity identity = dependentAssembly.Identity;
					DefinitionIdentity definitionIdentity = new DefinitionIdentity(identity);
					XmlElement newChild = CreateAssemblyIdentityElement(document, definitionIdentity);
					xmlElement3.AppendChild(newChild);
					hashtable.Add(identity, definitionIdentity);
				}
			}
		}

		private static void InjectIdentityXml(XmlDocument document, DefinitionIdentity asmId)
		{
			XmlElement newChild = CreateAssemblyIdentityElement(document, asmId);
			document.DocumentElement.AppendChild(newChild);
		}

		private static XmlElement CreateAssemblyIdentityElement(XmlDocument document, DefinitionIdentity asmId)
		{
			XmlElement xmlElement = document.CreateElement("assemblyIdentity", "urn:schemas-microsoft-com:asm.v1");
			System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] attributes = asmId.Attributes;
			StringComparison comparisonType = StringComparison.InvariantCultureIgnoreCase;
			System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE[] array = attributes;
			for (int i = 0; i < array.Length; i++)
			{
				System.Deployment.Internal.Isolation.IDENTITY_ATTRIBUTE iDENTITY_ATTRIBUTE = array[i];
				string @namespace = iDENTITY_ATTRIBUTE.Namespace;
				string text = iDENTITY_ATTRIBUTE.Name;
				if (@namespace == null)
				{
					if (text.Equals("name", comparisonType))
					{
						text = "name";
					}
					else if (text.Equals("version", comparisonType))
					{
						text = "version";
					}
					else if (text.Equals("processorArchitecture", comparisonType))
					{
						text = "processorArchitecture";
					}
					else if (text.Equals("publicKeyToken", comparisonType))
					{
						text = "publicKeyToken";
					}
					else if (text.Equals("type", comparisonType))
					{
						text = "type";
					}
					else if (text.Equals("culture", comparisonType))
					{
						text = "language";
					}
				}
				xmlElement.SetAttribute(text, @namespace, iDENTITY_ATTRIBUTE.Value);
			}
			return xmlElement;
		}

		private static XmlDocument CloneAssemblyTemplate()
		{
			if (assemblyTemplateDoc == null)
			{
				Assembly executingAssembly = Assembly.GetExecutingAssembly();
				Stream manifestResourceStream = executingAssembly.GetManifestResourceStream("AssemblyTemplate.xml");
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.Load(manifestResourceStream);
				Interlocked.CompareExchange(ref assemblyTemplateDoc, xmlDocument, null);
			}
			return (XmlDocument)((XmlDocument)assemblyTemplateDoc).Clone();
		}

		private static XmlNamespaceManager GetNamespaceMgr(XmlDocument document)
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(document.NameTable);
			xmlNamespaceManager.AddNamespace("asmv1", "urn:schemas-microsoft-com:asm.v1");
			xmlNamespaceManager.AddNamespace("asmv2", "urn:schemas-microsoft-com:asm.v2");
			xmlNamespaceManager.AddNamespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
			return xmlNamespaceManager;
		}
	}
	internal class AssemblyModule
	{
		private string _name;

		private byte[] _hash;

		public string Name => _name;

		public byte[] Hash => _hash;

		public AssemblyModule(string name, byte[] hash)
		{
			_name = name;
			_hash = hash;
		}
	}
	internal class AssemblyReference
	{
		private AssemblyName _name;

		public AssemblyName Name => _name;

		public AssemblyReference(AssemblyName name)
		{
			_name = name;
		}
	}
	internal class AssemblyMetaDataImport : DisposableBase
	{
		private const int GENMAN_STRING_BUF_SIZE = 1024;

		private const int GENMAN_LOCALE_BUF_SIZE = 64;

		private const int GENMAN_ENUM_TOKEN_BUF_SIZE = 16;

		private AssemblyModule[] _modules;

		private AssemblyName _name;

		private AssemblyReference[] _asmRefs;

		private IMetaDataDispenser _metaDispenser;

		private IMetaDataAssemblyImport _assemblyImport;

		private static Guid _importerGuid = new Guid(((GuidAttribute)Attribute.GetCustomAttribute(typeof(IMetaDataImport), typeof(GuidAttribute), inherit: false)).Value);

		public AssemblyModule[] Files
		{
			get
			{
				if (_modules == null)
				{
					lock (this)
					{
						if (_modules == null)
						{
							_modules = ImportAssemblyFiles();
						}
					}
				}
				return _modules;
			}
		}

		public AssemblyName Name
		{
			get
			{
				if (_name == null)
				{
					lock (this)
					{
						if (_name == null)
						{
							_name = ImportIdentity();
						}
					}
				}
				return _name;
			}
		}

		public AssemblyReference[] References
		{
			get
			{
				if (_asmRefs == null)
				{
					lock (this)
					{
						if (_asmRefs == null)
						{
							_asmRefs = ImportAssemblyReferences();
						}
					}
				}
				return _asmRefs;
			}
		}

		public AssemblyMetaDataImport(string sourceFile)
		{
			_metaDispenser = (IMetaDataDispenser)new CorMetaDataDispenser();
			_assemblyImport = (IMetaDataAssemblyImport)_metaDispenser.OpenScope(sourceFile, 0u, ref _importerGuid);
		}

		protected override void DisposeUnmanagedResources()
		{
			if (_assemblyImport != null)
			{
				Marshal.ReleaseComObject(_assemblyImport);
			}
			if (_metaDispenser != null)
			{
				Marshal.ReleaseComObject(_metaDispenser);
			}
		}

		private AssemblyModule[] ImportAssemblyFiles()
		{
			ArrayList arrayList = new ArrayList();
			IntPtr phEnum = IntPtr.Zero;
			uint[] array = new uint[16];
			char[] array2 = new char[1024];
			try
			{
				uint iFetched;
				do
				{
					_assemblyImport.EnumFiles(ref phEnum, array, (uint)array.Length, out iFetched);
					for (uint num = 0u; num < iFetched; num++)
					{
						_assemblyImport.GetFileProps(array[num], array2, (uint)array2.Length, out var cchNameRequired, out var bHashData, out var cchHashBytes, out var _);
						byte[] array3 = new byte[cchHashBytes];
						Marshal.Copy(bHashData, array3, 0, (int)cchHashBytes);
						arrayList.Add(new AssemblyModule(new string(array2, 0, (int)(cchNameRequired - 1)), array3));
					}
				}
				while (iFetched != 0);
			}
			finally
			{
				if (phEnum != IntPtr.Zero)
				{
					_assemblyImport.CloseEnum(phEnum);
				}
			}
			return (AssemblyModule[])arrayList.ToArray(typeof(AssemblyModule));
		}

		private AssemblyName ImportIdentity()
		{
			_assemblyImport.GetAssemblyFromScope(out var mdAsm);
			_assemblyImport.GetAssemblyProps(mdAsm, out var pPublicKeyPtr, out var ucbPublicKeyPtr, out var uHashAlg, null, 0u, out var cchNameRequired, IntPtr.Zero, out var dwFlags);
			char[] array = new char[cchNameRequired + 1];
			IntPtr intPtr = IntPtr.Zero;
			try
			{
				intPtr = AllocAsmMeta();
				_assemblyImport.GetAssemblyProps(mdAsm, out pPublicKeyPtr, out ucbPublicKeyPtr, out uHashAlg, array, (uint)array.Length, out cchNameRequired, intPtr, out dwFlags);
				return ConstructAssemblyName(intPtr, array, cchNameRequired, pPublicKeyPtr, ucbPublicKeyPtr, dwFlags);
			}
			finally
			{
				FreeAsmMeta(intPtr);
			}
		}

		private AssemblyReference[] ImportAssemblyReferences()
		{
			ArrayList arrayList = new ArrayList();
			IntPtr phEnum = IntPtr.Zero;
			uint[] array = new uint[16];
			try
			{
				uint iFetched;
				do
				{
					_assemblyImport.EnumAssemblyRefs(ref phEnum, array, (uint)array.Length, out iFetched);
					for (uint num = 0u; num < iFetched; num++)
					{
						_assemblyImport.GetAssemblyRefProps(array[num], out var ppbPublicKeyOrToken, out var pcbPublicKeyOrToken, null, 0u, out var pchNameOut, IntPtr.Zero, out var ppbHashValue, out var pcbHashValue, out var pdwAssemblyRefFlags);
						char[] array2 = new char[pchNameOut + 1];
						IntPtr intPtr = IntPtr.Zero;
						try
						{
							intPtr = AllocAsmMeta();
							_assemblyImport.GetAssemblyRefProps(array[num], out ppbPublicKeyOrToken, out pcbPublicKeyOrToken, array2, (uint)array2.Length, out pchNameOut, intPtr, out ppbHashValue, out pcbHashValue, out pdwAssemblyRefFlags);
							AssemblyName name = ConstructAssemblyName(intPtr, array2, pchNameOut, ppbPublicKeyOrToken, pcbPublicKeyOrToken, pdwAssemblyRefFlags);
							arrayList.Add(new AssemblyReference(name));
						}
						finally
						{
							FreeAsmMeta(intPtr);
						}
					}
				}
				while (iFetched != 0);
			}
			finally
			{
				if (phEnum != IntPtr.Zero)
				{
					_assemblyImport.CloseEnum(phEnum);
				}
			}
			return (AssemblyReference[])arrayList.ToArray(typeof(AssemblyReference));
		}

		private IntPtr AllocAsmMeta()
		{
			ASSEMBLYMETADATA aSSEMBLYMETADATA = default(ASSEMBLYMETADATA);
			aSSEMBLYMETADATA.usMajorVersion = (aSSEMBLYMETADATA.usMinorVersion = (aSSEMBLYMETADATA.usBuildNumber = (aSSEMBLYMETADATA.usRevisionNumber = 0)));
			aSSEMBLYMETADATA.cOses = (aSSEMBLYMETADATA.cProcessors = 0u);
			aSSEMBLYMETADATA.rOses = (aSSEMBLYMETADATA.rpProcessors = IntPtr.Zero);
			aSSEMBLYMETADATA.rpLocale = Marshal.AllocCoTaskMem(128);
			aSSEMBLYMETADATA.cchLocale = 64u;
			int cb = Marshal.SizeOf(typeof(ASSEMBLYMETADATA));
			IntPtr intPtr = Marshal.AllocCoTaskMem(cb);
			Marshal.StructureToPtr(aSSEMBLYMETADATA, intPtr, fDeleteOld: false);
			return intPtr;
		}

		private AssemblyName ConstructAssemblyName(IntPtr asmMetaPtr, char[] asmNameBuf, uint asmNameLength, IntPtr pubKeyPtr, uint pubKeyBytes, uint flags)
		{
			ASSEMBLYMETADATA aSSEMBLYMETADATA = (ASSEMBLYMETADATA)Marshal.PtrToStructure(asmMetaPtr, typeof(ASSEMBLYMETADATA));
			AssemblyName assemblyName = new AssemblyName();
			assemblyName.Name = new string(asmNameBuf, 0, (int)(asmNameLength - 1));
			assemblyName.Version = new Version(aSSEMBLYMETADATA.usMajorVersion, aSSEMBLYMETADATA.usMinorVersion, aSSEMBLYMETADATA.usBuildNumber, aSSEMBLYMETADATA.usRevisionNumber);
			string name = Marshal.PtrToStringUni(aSSEMBLYMETADATA.rpLocale);
			assemblyName.CultureInfo = new CultureInfo(name);
			if (pubKeyBytes != 0)
			{
				byte[] array = new byte[pubKeyBytes];
				Marshal.Copy(pubKeyPtr, array, 0, (int)pubKeyBytes);
				if ((flags & (true ? 1u : 0u)) != 0)
				{
					assemblyName.SetPublicKey(array);
				}
				else
				{
					assemblyName.SetPublicKeyToken(array);
				}
			}
			return assemblyName;
		}

		private void FreeAsmMeta(IntPtr asmMetaPtr)
		{
			if (asmMetaPtr != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(((ASSEMBLYMETADATA)Marshal.PtrToStructure(asmMetaPtr, typeof(ASSEMBLYMETADATA))).rpLocale);
				Marshal.DestroyStructure(asmMetaPtr, typeof(ASSEMBLYMETADATA));
				Marshal.FreeCoTaskMem(asmMetaPtr);
			}
		}
	}
	[Flags]
	internal enum CorAssemblyFlags : uint
	{
		afPublicKey = 1u
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[TypeLibType(TypeLibTypeFlags.FRestricted)]
	[Guid("809c652e-7396-11d2-9771-00a0c9b4d50c")]
	internal interface IMetaDataDispenser
	{
		[return: MarshalAs(UnmanagedType.Interface)]
		object DefineScope([In] ref Guid rclsid, [In] uint dwCreateFlags, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.Interface)]
		object OpenScope([In][MarshalAs(UnmanagedType.LPWStr)] string szScope, [In] uint dwOpenFlags, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.Interface)]
		object OpenScopeOnMemory([In] IntPtr pData, [In] uint cbData, [In] uint dwOpenFlags, [In] ref Guid riid);
	}
	internal struct ASSEMBLYMETADATA
	{
		public ushort usMajorVersion;

		public ushort usMinorVersion;

		public ushort usBuildNumber;

		public ushort usRevisionNumber;

		public IntPtr rpLocale;

		public uint cchLocale;

		public IntPtr rpProcessors;

		public uint cProcessors;

		public IntPtr rOses;

		public uint cOses;
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("7DAC8207-D3AE-4c75-9B67-92801A497D44")]
	internal interface IMetaDataImport
	{
		[PreserveSig]
		void CloseEnum();

		void CountEnum(IntPtr iRef, ref uint ulCount);

		void ResetEnum();

		void EnumTypeDefs();

		void EnumInterfaceImpls();

		void EnumTypeRefs();

		void FindTypeDefByName();

		void GetScopeProps();

		void GetModuleFromScope();

		void GetTypeDefProps();

		void GetInterfaceImplProps();

		void GetTypeRefProps();

		void ResolveTypeRef();

		void EnumMembers();

		void EnumMembersWithName();

		void EnumMethods();

		void EnumMethodsWithName();

		void EnumFields();

		void EnumFieldsWithName();

		void EnumParams();

		void EnumMemberRefs();

		void EnumMethodImpls();

		void EnumPermissionSets();

		void FindMember();

		void FindMethod();

		void FindField();

		void FindMemberRef();

		void GetMethodProps();

		void GetMemberRefProps();

		void EnumProperties();

		void EnumEvents();

		void GetEventProps();

		void EnumMethodSemantics();

		void GetMethodSemantics();

		void GetClassLayout();

		void GetFieldMarshal();

		void GetRVA();

		void GetPermissionSetProps();

		void GetSigFromToken();

		void GetModuleRefProps();

		void EnumModuleRefs();

		void GetTypeSpecFromToken();

		void GetNameFromToken();

		void EnumUnresolvedMethods();

		void GetUserString();

		void GetPinvokeMap();

		void EnumSignatures();

		void EnumTypeSpecs();

		void EnumUserStrings();

		void GetParamForMethodIndex();

		void EnumCustomAttributes();

		void GetCustomAttributeProps();

		void FindTypeRef();

		void GetMemberProps();

		void GetFieldProps();

		void GetPropertyProps();

		void GetParamProps();

		void GetCustomAttributeByName();

		void IsValidToken();

		void GetNestedClassProps();

		void GetNativeCallConvFromSig();

		void IsGlobal();
	}
	[ComImport]
	[ClassInterface(ClassInterfaceType.None)]
	[Guid("E5CB7A31-7512-11d2-89CE-0080C792E5D8")]
	[TypeLibType(TypeLibTypeFlags.FCanCreate)]
	internal class CorMetaDataDispenser
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		public extern CorMetaDataDispenser();
	}
	[ComImport]
	[Guid("EE62470B-E94B-424e-9B7C-2F00C9249F93")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IMetaDataAssemblyImport
	{
		void GetAssemblyProps(uint mdAsm, out IntPtr pPublicKeyPtr, out uint ucbPublicKeyPtr, out uint uHashAlg, [MarshalAs(UnmanagedType.LPArray)] char[] strName, uint cchNameIn, out uint cchNameRequired, IntPtr amdInfo, out uint dwFlags);

		void GetAssemblyRefProps(uint mdAsmRef, out IntPtr ppbPublicKeyOrToken, out uint pcbPublicKeyOrToken, [MarshalAs(UnmanagedType.LPArray)] char[] strName, uint cchNameIn, out uint pchNameOut, IntPtr amdInfo, out IntPtr ppbHashValue, out uint pcbHashValue, out uint pdwAssemblyRefFlags);

		void GetFileProps([In] uint mdFile, [MarshalAs(UnmanagedType.LPArray)] char[] strName, uint cchName, out uint cchNameRequired, out IntPtr bHashData, out uint cchHashBytes, out uint dwFileFlags);

		void GetExportedTypeProps();

		void GetManifestResourceProps();

		void EnumAssemblyRefs([In][Out] ref IntPtr phEnum, [Out][MarshalAs(UnmanagedType.LPArray)] uint[] asmRefs, uint asmRefCount, out uint iFetched);

		void EnumFiles([In][Out] ref IntPtr phEnum, [Out][MarshalAs(UnmanagedType.LPArray)] uint[] fileRefs, uint fileRefCount, out uint iFetched);

		void EnumExportedTypes();

		void EnumManifestResources();

		void GetAssemblyFromScope(out uint mdAsm);

		void FindExportedTypeByName();

		void FindManifestResourceByName();

		[PreserveSig]
		void CloseEnum([In] IntPtr phEnum);

		void FindAssembliesByName();
	}
	internal static class ManifestReader
	{
		internal static AssemblyManifest FromDocument(string localPath, AssemblyManifest.ManifestType manifestType, Uri sourceUri)
		{
			CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfParseBegin);
			FileInfo fileInfo = new FileInfo(localPath);
			if (fileInfo.Length > 16777216)
			{
				throw new DeploymentException(Resources.GetString("Ex_ManifestFileTooLarge"));
			}
			AssemblyManifest assemblyManifest;
			using (FileStream fileStream = new FileStream(localPath, FileMode.Open, FileAccess.Read))
			{
				try
				{
					XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
					xmlReaderSettings.ProhibitDtd = true;
					xmlReaderSettings.XmlResolver = null;
					XmlReader xmlReader = (PolicyKeys.SkipSchemaValidation() ? XmlReader.Create(fileStream, xmlReaderSettings) : ManifestValidatingReader.Create(fileStream));
					while (xmlReader.Read())
					{
					}
					assemblyManifest = new AssemblyManifest(fileStream);
					if (!PolicyKeys.SkipSemanticValidation())
					{
						assemblyManifest.ValidateSemantics(manifestType);
					}
					if (!PolicyKeys.SkipSignatureValidation())
					{
						fileStream.Position = 0L;
						assemblyManifest.ValidateSignature(fileStream);
					}
				}
				catch (XmlException innerException)
				{
					string message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestFromDocument"), (sourceUri != null) ? sourceUri.AbsoluteUri : Path.GetFileName(localPath));
					throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, message, innerException);
				}
				catch (XmlSchemaValidationException innerException2)
				{
					string message2 = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestFromDocument"), (sourceUri != null) ? sourceUri.AbsoluteUri : Path.GetFileName(localPath));
					throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, message2, innerException2);
				}
				catch (InvalidDeploymentException innerException3)
				{
					string message3 = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ManifestFromDocument"), (sourceUri != null) ? sourceUri.AbsoluteUri : Path.GetFileName(localPath));
					throw new InvalidDeploymentException(ExceptionTypes.ManifestParse, message3, innerException3);
				}
			}
			CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfParseEnd);
			return assemblyManifest;
		}

		internal static AssemblyManifest FromDocumentNoValidation(string localPath)
		{
			CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfParseBegin);
			FileInfo fileInfo = new FileInfo(localPath);
			if (fileInfo.Length > 16777216)
			{
				throw new DeploymentException(Resources.GetString("Ex_ManifestFileTooLarge"));
			}
			AssemblyManifest result;
			using (FileStream fileStream = new FileStream(localPath, FileMode.Open, FileAccess.Read))
			{
				result = new AssemblyManifest(fileStream);
			}
			CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfParseEnd);
			return result;
		}
	}
	internal static class ManifestValidatingReader
	{
		private class ResourceResolver : XmlUrlResolver
		{
			private const string Prefix = "df://resources/";

			private Assembly _assembly;

			public ResourceResolver(Assembly assembly)
			{
				_assembly = assembly;
			}

			public override Uri ResolveUri(Uri baseUri, string relativeUri)
			{
				if (baseUri == null || baseUri.ToString() == string.Empty || (baseUri.IsAbsoluteUri && baseUri.AbsoluteUri.StartsWith("df://resources/", StringComparison.Ordinal)))
				{
					return new Uri("df://resources/" + relativeUri);
				}
				return base.ResolveUri(baseUri, relativeUri);
			}

			public override object GetEntity(Uri absoluteUri, string role, Type ofObjectToReturn)
			{
				if (absoluteUri.AbsoluteUri.StartsWith("df://resources/", StringComparison.Ordinal))
				{
					if (ofObjectToReturn != null && ofObjectToReturn != typeof(Stream))
					{
						throw new XmlException(Resources.GetString("Ex_OnlyStreamTypeSupported"));
					}
					if (absoluteUri.ToString() == "df://resources/-//W3C//DTD XMLSCHEMA 200102//EN")
					{
						return _assembly.GetManifestResourceStream("XMLSchema.dtd");
					}
					if (absoluteUri.ToString() == "df://resources/xs-datatypes")
					{
						return _assembly.GetManifestResourceStream("datatypes.dtd");
					}
					string name = absoluteUri.AbsoluteUri.Remove(0, "df://resources/".Length);
					return _assembly.GetManifestResourceStream(name);
				}
				return base.GetEntity(absoluteUri, role, ofObjectToReturn);
			}
		}

		private class XmlFilteredReader : XmlTextReader
		{
			private static StringCollection KnownNamespaces;

			static XmlFilteredReader()
			{
				KnownNamespaces = new StringCollection();
				KnownNamespaces.Add("urn:schemas-microsoft-com:asm.v1");
				KnownNamespaces.Add("urn:schemas-microsoft-com:asm.v2");
				KnownNamespaces.Add("http://www.w3.org/2000/09/xmldsig#");
			}

			public XmlFilteredReader(Stream stream)
				: base(stream)
			{
				base.ProhibitDtd = true;
			}

			public override bool Read()
			{
				bool result = base.Read();
				XmlNodeType nodeType = base.NodeType;
				if (nodeType == XmlNodeType.Element && !KnownNamespaces.Contains(base.NamespaceURI))
				{
					Skip();
				}
				return result;
			}
		}

		private static string[] _manifestSchemas = new string[1] { "manifest.2.0.0.15-pre.adaptive.xsd" };

		private static XmlSchemaSet _manifestSchemaSet = null;

		private static object _manifestSchemaSetLock = new object();

		private static XmlSchemaSet ManifestSchemaSet
		{
			get
			{
				if (_manifestSchemaSet == null)
				{
					lock (_manifestSchemaSetLock)
					{
						if (_manifestSchemaSet == null)
						{
							_manifestSchemaSet = MakeSchemaSet(_manifestSchemas);
						}
					}
				}
				return _manifestSchemaSet;
			}
		}

		public static XmlReader Create(Stream stream)
		{
			return Create(stream, ManifestSchemaSet);
		}

		private static XmlReader Create(Stream stream, XmlSchemaSet schemaSet)
		{
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			xmlReaderSettings.Schemas = schemaSet;
			xmlReaderSettings.ValidationType = ValidationType.Schema;
			xmlReaderSettings.ProhibitDtd = true;
			xmlReaderSettings.XmlResolver = null;
			XmlFilteredReader reader = new XmlFilteredReader(stream);
			return XmlReader.Create(reader, xmlReaderSettings);
		}

		private static XmlSchemaSet MakeSchemaSet(string[] schemas)
		{
			XmlSchemaSet xmlSchemaSet = new XmlSchemaSet();
			Assembly executingAssembly = Assembly.GetExecutingAssembly();
			xmlSchemaSet.XmlResolver = new ResourceResolver(executingAssembly);
			for (int i = 0; i < schemas.Length; i++)
			{
				using Stream input = executingAssembly.GetManifestResourceStream(schemas[i]);
				xmlSchemaSet.Add(null, new XmlTextReader(input));
			}
			return xmlSchemaSet;
		}
	}
	internal static class NativeMethods
	{
		public struct SYSTEM_INFO
		{
			internal _PROCESSOR_INFO_UNION uProcessorInfo;

			public uint dwPageSize;

			public IntPtr lpMinimumApplicationAddress;

			public IntPtr lpMaximumApplicationAddress;

			public IntPtr dwActiveProcessorMask;

			public uint dwNumberOfProcessors;

			public uint dwProcessorType;

			public uint dwAllocationGranularity;

			public uint dwProcessorLevel;

			public uint dwProcessorRevision;
		}

		[StructLayout(LayoutKind.Explicit)]
		public struct _PROCESSOR_INFO_UNION
		{
			[FieldOffset(0)]
			internal uint dwOemId;

			[FieldOffset(0)]
			internal ushort wProcessorArchitecture;

			[FieldOffset(2)]
			internal ushort wReserved;
		}

		[StructLayout(LayoutKind.Sequential)]
		public class OSVersionInfoEx
		{
			public uint dwOSVersionInfoSize;

			public uint dwMajorVersion;

			public uint dwMinorVersion;

			public uint dwBuildNumber;

			public uint dwPlatformId;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string szCSDVersion;

			public ushort wServicePackMajor;

			public ushort wServicePackMinor;

			public ushort wSuiteMask;

			public byte bProductType;

			public byte bReserved;
		}

		[Flags]
		internal enum GenericAccess : uint
		{
			GENERIC_READ = 0x80000000u,
			GENERIC_WRITE = 0x40000000u,
			GENERIC_EXECUTE = 0x20000000u,
			GENERIC_ALL = 0x10000000u
		}

		internal enum CreationDisposition : uint
		{
			CREATE_NEW = 1u,
			CREATE_ALWAYS,
			OPEN_EXISTING,
			OPEN_ALWAYS,
			TRUNCATE_EXISTING
		}

		[Flags]
		internal enum ShareMode : uint
		{
			FILE_SHARE_NONE = 0u,
			FILE_SHARE_READ = 1u,
			FILE_SHARE_WRITE = 2u,
			FILE_SHARE_DELETE = 4u
		}

		[Flags]
		internal enum FlagsAndAttributes : uint
		{
			FILE_FLAG_WRITE_THROUGH = 0x80000000u,
			FILE_FLAG_OVERLAPPED = 0x40000000u,
			FILE_FLAG_NO_BUFFERING = 0x20000000u,
			FILE_FLAG_RANDOM_ACCESS = 0x10000000u,
			FILE_FLAG_SEQUENTIAL_SCAN = 0x8000000u,
			FILE_FLAG_DELETE_ON_CLOSE = 0x4000000u,
			FILE_FLAG_BACKUP_SEMANTICS = 0x2000000u,
			FILE_FLAG_POSIX_SEMANTICS = 0x1000000u,
			FILE_FLAG_OPEN_REPARSE_POINT = 0x200000u,
			FILE_FLAG_OPEN_NO_RECALL = 0x100000u,
			FILE_FLAG_FIRST_PIPE_INSTANCE = 0x80000u,
			FILE_ATTRIBUTE_READONLY = 1u,
			FILE_ATTRIBUTE_HIDDEN = 2u,
			FILE_ATTRIBUTE_SYSTEM = 4u,
			FILE_ATTRIBUTE_DIRECTORY = 0x10u,
			FILE_ATTRIBUTE_ARCHIVE = 0x20u,
			FILE_ATTRIBUTE_DEVICE = 0x40u,
			FILE_ATTRIBUTE_NORMAL = 0x80u,
			FILE_ATTRIBUTE_TEMPORARY = 0x100u,
			FILE_ATTRIBUTE_SPARSE_FILE = 0x200u,
			FILE_ATTRIBUTE_REPARSE_POINT = 0x400u,
			FILE_ATTRIBUTE_COMPRESSED = 0x800u,
			FILE_ATTRIBUTE_OFFLINE = 0x1000u,
			FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000u,
			FILE_ATTRIBUTE_ENCRYPTED = 0x4000u
		}

		internal enum Win32Error
		{
			ERROR_SUCCESS = 0,
			ERROR_INVALID_FUNCTION = 1,
			ERROR_FILE_NOT_FOUND = 2,
			ERROR_PATH_NOT_FOUND = 3,
			ERROR_TOO_MANY_OPEN_FILES = 4,
			ERROR_ACCESS_DENIED = 5,
			ERROR_INVALID_HANDLE = 6,
			ERROR_NO_MORE_FILES = 18,
			ERROR_NOT_READY = 21,
			ERROR_SHARING_VIOLATION = 32,
			ERROR_FILE_EXISTS = 80,
			ERROR_INVALID_PARAMETER = 87,
			ERROR_CALL_NOT_IMPLEMENTED = 120,
			ERROR_ALREADY_EXISTS = 183,
			ERROR_FILENAME_EXCED_RANGE = 206
		}

		internal enum HResults
		{
			HRESULT_ERROR_REVISION_MISMATCH = -2147023590
		}

		[StructLayout(LayoutKind.Sequential)]
		[SuppressUnmanagedCodeSecurity]
		internal class PROCESS_INFORMATION
		{
			public IntPtr hProcess = IntPtr.Zero;

			public IntPtr hThread = IntPtr.Zero;

			public int dwProcessId;

			public int dwThreadId;

			~PROCESS_INFORMATION()
			{
				Close();
			}

			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			internal void Close()
			{
				if (hProcess != IntPtr.Zero && hProcess != INVALID_HANDLE_VALUE)
				{
					CloseHandle(new HandleRef(this, hProcess));
					hProcess = INVALID_HANDLE_VALUE;
				}
				if (hThread != IntPtr.Zero && hThread != INVALID_HANDLE_VALUE)
				{
					CloseHandle(new HandleRef(this, hThread));
					hThread = INVALID_HANDLE_VALUE;
				}
			}
		}

		internal struct AssemblyInfoInternal
		{
			internal const int MaxPath = 1024;

			internal int cbAssemblyInfo;

			internal int assemblyFlags;

			internal long assemblySizeInKB;

			internal IntPtr currentAssemblyPathBuf;

			internal int cchBuf;
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("e707dcde-d1cd-11d2-bab9-00c04f8eceae")]
		internal interface IAssemblyCache
		{
			void UninstallAssembly();

			void QueryAssemblyInfo(int flags, [MarshalAs(UnmanagedType.LPWStr)] string assemblyName, ref AssemblyInfoInternal assemblyInfo);

			void CreateAssemblyCacheItem();

			void CreateAssemblyScavenger();

			void InstallAssembly();
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("21b8916c-f28e-11d2-a473-00c04f8ef448")]
		internal interface IAssemblyEnum
		{
			[PreserveSig]
			int GetNextAssembly(IApplicationContext ppAppCtx, out IAssemblyName ppName, uint dwFlags);

			[PreserveSig]
			int Reset();

			[PreserveSig]
			int Clone(out IAssemblyEnum ppEnum);
		}

		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("7c23ff90-33af-11d3-95da-00a024a85b51")]
		internal interface IApplicationContext
		{
			void SetContextNameObject(IAssemblyName pName);

			void GetContextNameObject(out IAssemblyName ppName);

			void Set([MarshalAs(UnmanagedType.LPWStr)] string szName, int pvValue, uint cbValue, uint dwFlags);

			void Get([MarshalAs(UnmanagedType.LPWStr)] string szName, out int pvValue, ref uint pcbValue, uint dwFlags);

			void GetDynamicDirectory(out int wzDynamicDir, ref uint pdwSize);
		}

		[ComImport]
		[Guid("CD193BC0-B4BC-11d2-9833-00C04FC31D2E")]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
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

		internal enum ASM_CACHE : uint
		{
			ZAP = 1u,
			GAC = 2u,
			DOWNLOAD = 4u
		}

		internal enum CreateAssemblyNameObjectFlags : uint
		{
			CANOF_DEFAULT,
			CANOF_PARSE_DISPLAY_NAME
		}

		[StructLayout(LayoutKind.Sequential)]
		internal class ACTCTXW
		{
			public uint cbSize;

			public uint dwFlags;

			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpSource;

			public ushort wProcessorArchitecture;

			public ushort wLangId;

			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpAssemblyDirectory;

			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpResourceName;

			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpApplicationName;

			public IntPtr hModule;

			public ACTCTXW(string manifestPath)
			{
				cbSize = (uint)Marshal.SizeOf(typeof(ACTCTXW));
				dwFlags = 0u;
				lpSource = manifestPath;
			}
		}

		public enum CacheEntryFlags : uint
		{
			Normal = 1u,
			Sticky = 4u,
			Edited = 8u,
			TrackOffline = 0x10u,
			TrackOnline = 0x20u,
			Sparse = 0x10000u,
			Cookie = 0x100000u,
			UrlHistory = 0x200000u
		}

		public enum SHChangeNotifyEventID
		{
			SHCNE_ASSOCCHANGED = 0x8000000
		}

		public enum SHChangeNotifyFlags : uint
		{
			SHCNF_IDLIST
		}

		internal enum SIGDN : uint
		{
			NORMALDISPLAY = 0u,
			PARENTRELATIVEPARSING = 2147581953u,
			DESKTOPABSOLUTEPARSING = 2147647488u,
			PARENTRELATIVEEDITING = 2147684353u,
			DESKTOPABSOLUTEEDITING = 2147794944u,
			FILESYSPATH = 2147844096u,
			URL = 2147909632u,
			PARENTRELATIVEFORADDRESSBAR = 2147991553u,
			PARENTRELATIVE = 2148007937u
		}

		[ComImport]
		[Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe")]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		public interface IShellItem
		{
			void BindToHandler(IntPtr pbc, [MarshalAs(UnmanagedType.LPStruct)] Guid bhid, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);

			void GetParent(out IShellItem ppsi);

			void GetDisplayName(SIGDN sigdnName, out IntPtr ppszName);

			void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);

			void Compare(IShellItem psi, uint hint, out int piOrder);
		}

		[ComImport]
		[Guid("4CD19ADA-25A5-4A32-B3B7-347BEE5BE36B")]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		public interface IStartMenuPinnedList
		{
			void RemoveFromList(IShellItem psi);
		}

		public const ushort PROCESSOR_ARCHITECTURE_INTEL = 0;

		public const ushort PROCESSOR_ARCHITECTURE_IA64 = 6;

		public const ushort PROCESSOR_ARCHITECTURE_AMD64 = 9;

		internal static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

		[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
		public static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO sysInfo);

		[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
		public static extern void GetNativeSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO sysInfo);

		[DllImport("kernel32.dll", BestFitMapping = false, SetLastError = true)]
		public static extern bool VerifyVersionInfo([In][Out] OSVersionInfoEx osvi, [In] uint dwTypeMask, [In] ulong dwConditionMask);

		[DllImport("kernel32.dll")]
		public static extern ulong VerSetConditionMask([In] ulong ConditionMask, [In] uint TypeMask, [In] byte Condition);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		public static extern IntPtr LoadLibraryEx(string lpModuleName, IntPtr hFile, uint dwFlags);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		public static extern IntPtr LoadLibrary(string lpModuleName);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Ansi, SetLastError = true)]
		public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool FreeLibrary(IntPtr hModule);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		public static extern IntPtr FindResource(IntPtr hModule, string lpName, string lpType);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr LoadResource(IntPtr hModule, IntPtr handle);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr LockResource(IntPtr hglobal);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern uint SizeofResource(IntPtr hModule, IntPtr handle);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
		internal static extern bool CloseHandle(HandleRef handle);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int GetShortPathName(string LongPath, [Out] StringBuilder ShortPath, int BufferSize);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

		[DllImport("mscorwks.dll", BestFitMapping = false, CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
		internal static extern void CorLaunchApplication(uint hostType, string applicationFullName, int manifestPathsCount, string[] manifestPaths, int activationDataCount, string[] activationData, PROCESS_INFORMATION processInformation);

		[DllImport("mscorwks.dll", PreserveSig = false)]
		internal static extern void CreateAssemblyCache(out IAssemblyCache ppAsmCache, int reserved);

		[DllImport("mscorwks.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.IUnknown)]
		internal static extern object GetAssemblyIdentityFromFile([In][MarshalAs(UnmanagedType.LPWStr)] string filePath, [In] ref Guid riid);

		[DllImport("mscorwks.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
		internal static extern void CreateAssemblyNameObject(out IAssemblyName ppEnum, string szAssemblyName, uint dwFlags, IntPtr pvReserved);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, PreserveSig = false)]
		internal static extern void CreateAssemblyEnum(out IAssemblyEnum ppEnum, IApplicationContext pAppCtx, IAssemblyName pName, uint dwFlags, IntPtr pvReserved);

		[DllImport("mscoree.dll")]
		internal static extern byte StrongNameSignatureVerificationEx([MarshalAs(UnmanagedType.LPWStr)] string filePath, byte forceVerification, out byte wasVerified);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		internal static extern IntPtr CreateActCtxW([In] ACTCTXW actCtx);

		[DllImport("kernel32.dll", ExactSpelling = true)]
		internal static extern void ReleaseActCtx([In] IntPtr hActCtx);

		internal static string GetLoadedModulePath(string moduleName)
		{
			string result = null;
			IntPtr moduleHandle = GetModuleHandle(moduleName);
			if (moduleHandle != IntPtr.Zero)
			{
				StringBuilder stringBuilder = new StringBuilder(260);
				int moduleFileName = GetModuleFileName(moduleHandle, stringBuilder, stringBuilder.Capacity);
				if (moduleFileName > 0)
				{
					result = stringBuilder.ToString();
				}
			}
			return result;
		}

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		public static extern IntPtr GetModuleHandle(string moduleName);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		public static extern int GetModuleFileName(IntPtr module, [Out] StringBuilder fileName, int size);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern uint GetCurrentThreadId();

		[DllImport("wininet.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool CreateUrlCacheEntry([In] string urlName, [In] int expectedFileSize, [In] string fileExtension, [Out] StringBuilder fileName, [In] int dwReserved);

		[DllImport("wininet.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool CommitUrlCacheEntry([In] string lpszUrlName, [In] string lpszLocalFileName, [In] long ExpireTime, [In] long LastModifiedTime, [In] uint CacheEntryType, [In] string lpHeaderInfo, [In] int dwHeaderSize, [In] string lpszFileExtension, [In] string lpszOriginalUrl);

		[DllImport("mscoree.dll", PreserveSig = false)]
		private static extern IntPtr LoadLibraryShim([MarshalAs(UnmanagedType.LPWStr)] string dllName, [MarshalAs(UnmanagedType.LPWStr)] string szVersion, IntPtr reserved);

		[DllImport("mscoree.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
		public static extern void GetFileVersion(string szFileName, StringBuilder szBuffer, uint cchBuffer, out uint dwLength);

		[DllImport("mscoree.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
		public static extern void GetRequestedRuntimeInfo(string pExe, string pwszVersion, string pConfigurationFile, uint startupFlags, uint runtimeInfoFlags, StringBuilder pDirectory, uint dwDirectory, out uint dwDirectoryLength, StringBuilder pVersion, uint cchBuffer, out uint dwLength);

		[DllImport("mscoree.dll", ExactSpelling = true, PreserveSig = false)]
		internal static extern void StrongNameTokenFromPublicKey(byte[] publicKeyBlob, uint publicKeyBlobCount, ref IntPtr strongNameTokenArray, ref uint strongNameTokenCount);

		[DllImport("mscoree.dll", ExactSpelling = true, PreserveSig = false)]
		internal static extern void StrongNameFreeBuffer(IntPtr buffer);

		[DllImport("wininet.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		public static extern bool InternetGetCookieW([In] string url, [In] string cookieName, [Out] StringBuilder cookieData, [In][Out] ref uint bytes);

		[DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
		public static extern void SHChangeNotify(int eventID, uint flags, IntPtr item1, IntPtr item2);

		[DllImport("shell32.dll", CharSet = CharSet.Unicode)]
		public static extern uint SHCreateItemFromParsingName([In][MarshalAs(UnmanagedType.LPWStr)] string pszPath, [In] IntPtr pbc, [In][MarshalAs(UnmanagedType.LPStruct)] Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ppv);

		[DllImport("Ole32.dll")]
		public static extern uint CoCreateInstance([In] ref Guid clsid, [MarshalAs(UnmanagedType.IUnknown)] object punkOuter, int context, [In] ref Guid iid, [MarshalAs(UnmanagedType.IUnknown)] out object o);
	}
	internal class PEStream : Stream
	{
		protected class StreamComponentList : ArrayList
		{
			public int Add(PEComponent peComponent)
			{
				if (peComponent.Size > 0)
				{
					return Add((object)peComponent);
				}
				return -1;
			}
		}

		protected class PEComponentComparer : IComparer
		{
			public int Compare(object a, object b)
			{
				PEComponent pEComponent = (PEComponent)a;
				PEComponent pEComponent2 = (PEComponent)b;
				if (pEComponent.Address > pEComponent2.Address)
				{
					return 1;
				}
				if (pEComponent.Address < pEComponent2.Address)
				{
					return -1;
				}
				return 0;
			}
		}

		protected struct IMAGE_DOS_HEADER
		{
			public ushort e_magic;

			public ushort e_cblp;

			public ushort e_cp;

			public ushort e_crlc;

			public ushort e_cparhdr;

			public ushort e_minalloc;

			public ushort e_maxalloc;

			public ushort e_ss;

			public ushort e_sp;

			public ushort e_csum;

			public ushort e_ip;

			public ushort e_cs;

			public ushort e_lfarlc;

			public ushort e_ovno;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public ushort[] e_res;

			public ushort e_oemid;

			public ushort e_oeminfo;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
			public ushort[] e_res2;

			public uint e_lfanew;
		}

		protected struct IMAGE_FILE_HEADER
		{
			public ushort Machine;

			public ushort NumberOfSections;

			public uint TimeDateStamp;

			public uint PointerToSymbolTable;

			public uint NumberOfSymbols;

			public ushort SizeOfOptionalHeader;

			public ushort Characteristics;
		}

		protected struct IMAGE_OPTIONAL_HEADER32
		{
			public ushort Magic;

			public byte MajorLinkerVersion;

			public byte MinorLinkerVersion;

			public uint SizeOfCode;

			public uint SizeOfInitializedData;

			public uint SizeOfUninitializedData;

			public uint AddressOfEntryPoint;

			public uint BaseOfCode;

			public uint BaseOfData;

			public uint ImageBase;

			public uint SectionAlignment;

			public uint FileAlignment;

			public ushort MajorOperatingSystemVersion;

			public ushort MinorOperatingSystemVersion;

			public ushort MajorImageVersion;

			public ushort MinorImageVersion;

			public ushort MajorSubsystemVersion;

			public ushort MinorSubsystemVersion;

			public uint Win32VersionValue;

			public uint SizeOfImage;

			public uint SizeOfHeaders;

			public uint CheckSum;

			public ushort Subsystem;

			public ushort DllCharacteristics;

			public uint SizeOfStackReserve;

			public uint SizeOfStackCommit;

			public uint SizeOfHeapReserve;

			public uint SizeOfHeapCommit;

			public uint LoaderFlags;

			public uint NumberOfRvaAndSizes;
		}

		[Serializable]
		protected struct IMAGE_OPTIONAL_HEADER64
		{
			internal ushort Magic;

			internal byte MajorLinkerVersion;

			internal byte MinorLinkerVersion;

			internal uint SizeOfCode;

			internal uint SizeOfInitializedData;

			internal uint SizeOfUninitializedData;

			internal uint AddressOfEntryPoint;

			internal uint BaseOfCode;

			internal ulong ImageBase;

			internal uint SectionAlignment;

			internal uint FileAlignment;

			internal ushort MajorOperatingSystemVersion;

			internal ushort MinorOperatingSystemVersion;

			internal ushort MajorImageVersion;

			internal ushort MinorImageVersion;

			internal ushort MajorSubsystemVersion;

			internal ushort MinorSubsystemVersion;

			internal uint Win32VersionValue;

			internal uint SizeOfImage;

			internal uint SizeOfHeaders;

			internal uint CheckSum;

			internal ushort Subsystem;

			internal ushort DllCharacteristics;

			internal ulong SizeOfStackReserve;

			internal ulong SizeOfStackCommit;

			internal ulong SizeOfHeapReserve;

			internal ulong SizeOfHeapCommit;

			internal uint LoaderFlags;

			internal uint NumberOfRvaAndSizes;
		}

		[Serializable]
		protected struct IMAGE_DATA_DIRECTORY
		{
			public uint VirtualAddress;

			public uint Size;
		}

		[Serializable]
		protected struct IMAGE_SECTION_HEADER
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public byte[] Name;

			public uint VirtualSize;

			public uint VirtualAddress;

			public uint SizeOfRawData;

			public uint PointerToRawData;

			public uint PointerToRelocations;

			public uint PointerToLinenumbers;

			public ushort NumberOfRelocations;

			public ushort NumberOfLinenumbers;

			public uint Characteristics;
		}

		[Serializable]
		protected struct IMAGE_RESOURCE_DIRECTORY
		{
			public uint Characteristics;

			public uint TimeDateStamp;

			public ushort MajorVersion;

			public ushort MinorVersion;

			public ushort NumberOfNamedEntries;

			public ushort NumberOfIdEntries;
		}

		[Serializable]
		protected struct IMAGE_RESOURCE_DATA_ENTRY
		{
			public uint OffsetToData;

			public uint Size;

			public uint CodePage;

			public uint Reserved;
		}

		[Serializable]
		protected struct IMAGE_RESOURCE_DIRECTORY_ENTRY
		{
			public uint Name;

			public uint OffsetToData;
		}

		protected class PEComponent
		{
			protected long _address;

			protected long _size;

			protected object _data;

			public long Address => _address;

			public long Size => _size;

			public PEComponent()
			{
				_address = 0L;
				_size = 0L;
				_data = null;
			}

			public PEComponent(FileStream file, long address, long size)
			{
				_address = address;
				_size = size;
				_data = new DiskDataBlock(file, address, size);
			}

			public virtual int Read(byte[] buffer, int bufferOffset, long sourceOffset, int count)
			{
				int num = 0;
				if (_data is DataComponent)
				{
					DataComponent dataComponent = (DataComponent)_data;
					long num2 = Math.Min(count, _size - sourceOffset);
					if (num2 < 0)
					{
						throw new ArgumentException(Resources.GetString("Ex_InvalidCopyRequest"));
					}
					return dataComponent.Read(buffer, bufferOffset, sourceOffset, (int)num2);
				}
				byte[] array = ToByteArray(_data);
				long num3 = Math.Min(count, array.Length - sourceOffset);
				if (num3 < 0)
				{
					throw new ArgumentException(Resources.GetString("Ex_InvalidCopyRequest"));
				}
				Array.Copy(array, (int)sourceOffset, buffer, bufferOffset, (int)num3);
				return (int)num3;
			}

			protected static byte[] ToByteArray(object data)
			{
				int num = Marshal.SizeOf(data);
				IntPtr intPtr = Marshal.AllocCoTaskMem(num);
				Marshal.StructureToPtr(data, intPtr, fDeleteOld: false);
				byte[] array = new byte[num];
				Marshal.Copy(intPtr, array, 0, array.Length);
				Marshal.FreeCoTaskMem(intPtr);
				return array;
			}

			protected static object ReadData(FileStream file, long position, Type dataType)
			{
				int num = Marshal.SizeOf(dataType);
				byte[] array = new byte[num];
				long num2 = file.Seek(position, SeekOrigin.Begin);
				if (num2 != position)
				{
					throw new IOException(Resources.GetString("Ex_NotEnoughDataInFile"));
				}
				int num3 = file.Read(array, 0, array.Length);
				if (num3 < num)
				{
					throw new IOException(Resources.GetString("Ex_NotEnoughDataInFile"));
				}
				IntPtr intPtr = Marshal.AllocCoTaskMem(num);
				Marshal.Copy(array, 0, intPtr, num);
				object result = Marshal.PtrToStructure(intPtr, dataType);
				Marshal.FreeCoTaskMem(intPtr);
				return result;
			}

			protected long CalculateSize(object data)
			{
				return Marshal.SizeOf(data);
			}
		}

		protected class DosHeader : PEComponent
		{
			protected IMAGE_DOS_HEADER _dosHeader;

			public uint NtHeaderPosition => _dosHeader.e_lfanew;

			public DosHeader(FileStream file)
			{
				file.Seek(0L, SeekOrigin.Begin);
				_dosHeader = (IMAGE_DOS_HEADER)PEComponent.ReadData(file, 0L, _dosHeader.GetType());
				if (_dosHeader.e_magic != 23117)
				{
					throw new Win32Exception(11, Resources.GetString("Ex_InvalidPEImage"));
				}
				_data = _dosHeader;
				_address = 0L;
				_size = CalculateSize(_dosHeader);
			}
		}

		protected class DosStub : PEComponent
		{
			public DosStub(FileStream file, long startAddress, long size)
			{
				_address = startAddress;
				_size = size;
				_data = new DiskDataBlock(file, _address, _size);
			}
		}

		protected class NtSignature : PEComponent
		{
			public NtSignature(FileStream file, long address)
			{
				uint num = 0u;
				num = (uint)PEComponent.ReadData(file, address, num.GetType());
				if (num != 17744)
				{
					throw new Win32Exception(11, Resources.GetString("Ex_InvalidPEFormat"));
				}
				_address = address;
				_size = CalculateSize(num);
				_data = num;
			}
		}

		protected class FileHeader : PEComponent
		{
			protected IMAGE_FILE_HEADER _fileHeader;

			public ushort SizeOfOptionalHeader => _fileHeader.SizeOfOptionalHeader;

			public ushort NumberOfSections => _fileHeader.NumberOfSections;

			public bool IsImageFileDll => (_fileHeader.Characteristics & 0x2000) != 0;

			public FileHeader(FileStream file, long address)
			{
				_fileHeader = (IMAGE_FILE_HEADER)PEComponent.ReadData(file, address, _fileHeader.GetType());
				_address = address;
				_size = CalculateSize(_fileHeader);
				_data = _fileHeader;
			}
		}

		protected class OptionalHeader : PEComponent
		{
			protected IMAGE_OPTIONAL_HEADER32 _optionalHeader32;

			protected IMAGE_OPTIONAL_HEADER64 _optionalHeader64;

			protected bool _is64Bit;

			public uint CheckSum
			{
				set
				{
					if (_is64Bit)
					{
						_optionalHeader64.CheckSum = value;
						_data = _optionalHeader64;
					}
					else
					{
						_optionalHeader32.CheckSum = value;
						_data = _optionalHeader32;
					}
				}
			}

			public uint NumberOfRvaAndSizes
			{
				get
				{
					if (_is64Bit)
					{
						return _optionalHeader64.NumberOfRvaAndSizes;
					}
					return _optionalHeader32.NumberOfRvaAndSizes;
				}
			}

			public OptionalHeader(FileStream file, long address)
			{
				_optionalHeader32 = (IMAGE_OPTIONAL_HEADER32)PEComponent.ReadData(file, address, _optionalHeader32.GetType());
				if (_optionalHeader32.Magic == 523)
				{
					_is64Bit = true;
					_optionalHeader64 = (IMAGE_OPTIONAL_HEADER64)PEComponent.ReadData(file, address, _optionalHeader64.GetType());
					_size = CalculateSize(_optionalHeader64);
					_data = _optionalHeader64;
				}
				else
				{
					if (_optionalHeader32.Magic != 267)
					{
						throw new NotSupportedException(Resources.GetString("Ex_PEImageTypeNotSupported"));
					}
					_is64Bit = false;
					_size = CalculateSize(_optionalHeader32);
					_data = _optionalHeader32;
				}
				_address = address;
			}
		}

		protected class DataDirectory : PEComponent
		{
			private IMAGE_DATA_DIRECTORY _dataDirectory;

			public uint VirtualAddress => _dataDirectory.VirtualAddress;

			public DataDirectory(FileStream file, long address)
			{
				_dataDirectory = (IMAGE_DATA_DIRECTORY)PEComponent.ReadData(file, address, _dataDirectory.GetType());
				_address = address;
				_size = CalculateSize(_dataDirectory);
				_data = _dataDirectory;
			}
		}

		protected class SectionHeader : PEComponent
		{
			protected IMAGE_SECTION_HEADER _imageSectionHeader;

			protected Section _section;

			public Section Section
			{
				set
				{
					_section = value;
				}
			}

			public uint VirtualAddress => _imageSectionHeader.VirtualAddress;

			public uint PointerToRawData => _imageSectionHeader.PointerToRawData;

			public uint SizeOfRawData => _imageSectionHeader.SizeOfRawData;

			public SectionHeader(FileStream file, long address)
			{
				_imageSectionHeader = (IMAGE_SECTION_HEADER)PEComponent.ReadData(file, address, _imageSectionHeader.GetType());
				_address = address;
				_size = CalculateSize(_imageSectionHeader);
				_data = _imageSectionHeader;
			}
		}

		protected class Section : PEComponent
		{
			public SectionHeader _sectionHeader;

			public Section(FileStream file, SectionHeader sectionHeader)
			{
				_address = sectionHeader.PointerToRawData;
				_size = sectionHeader.SizeOfRawData;
				_data = new DiskDataBlock(file, _address, _size);
				_sectionHeader = sectionHeader;
			}

			public virtual void AddComponentsToStream(StreamComponentList stream)
			{
				stream.Add(this);
			}
		}

		protected class ResourceComponent : PEComponent
		{
			public virtual void AddComponentsToStream(StreamComponentList stream)
			{
				stream.Add(this);
			}
		}

		protected class ResourceDirectory : ResourceComponent
		{
			protected IMAGE_RESOURCE_DIRECTORY _imageResourceDirectory;

			protected Hashtable _resourceDirectoryItems = new Hashtable();

			protected ArrayList _resourceDirectoryEntries = new ArrayList();

			public ResourceComponent this[object key]
			{
				get
				{
					if (_resourceDirectoryItems.Contains(key))
					{
						return (ResourceComponent)_resourceDirectoryItems[key];
					}
					return null;
				}
			}

			public int ResourceComponentCount => _resourceDirectoryItems.Count;

			public ResourceDirectory(ResourceSection resourceSection, FileStream file, long rootResourceAddress, long resourceAddress, long addressDelta, bool partialConstruct)
			{
				_imageResourceDirectory = (IMAGE_RESOURCE_DIRECTORY)PEComponent.ReadData(file, resourceAddress, _imageResourceDirectory.GetType());
				_address = resourceAddress;
				_size = CalculateSize(_imageResourceDirectory);
				_data = _imageResourceDirectory;
				long num = _address + _size;
				int num2 = 0;
				for (num2 = 0; num2 < _imageResourceDirectory.NumberOfIdEntries; num2++)
				{
					ResourceDirectoryEntry resourceDirectoryEntry = new ResourceDirectoryEntry(file, num);
					_resourceDirectoryEntries.Add(resourceDirectoryEntry);
					num += resourceDirectoryEntry.Size;
				}
				for (num2 = 0; num2 < _imageResourceDirectory.NumberOfNamedEntries; num2++)
				{
					ResourceDirectoryEntry resourceDirectoryEntry2 = new ResourceDirectoryEntry(file, num);
					_resourceDirectoryEntries.Add(resourceDirectoryEntry2);
					num += resourceDirectoryEntry2.Size;
				}
				foreach (ResourceDirectoryEntry resourceDirectoryEntry3 in _resourceDirectoryEntries)
				{
					bool flag = false;
					object obj = null;
					if (resourceDirectoryEntry3.NameIsString)
					{
						ResourceDirectoryString resourceDirectoryString = resourceSection.CreateResourceDirectoryString(file, rootResourceAddress + resourceDirectoryEntry3.NameOffset);
						obj = resourceDirectoryString.NameString;
					}
					else
					{
						obj = resourceDirectoryEntry3.Id;
						if (rootResourceAddress == resourceAddress && resourceDirectoryEntry3.Id == 24)
						{
							flag = true;
						}
					}
					resourceDirectoryEntry3.Key = obj;
					object obj2 = null;
					if (resourceDirectoryEntry3.IsDirectory)
					{
						if (!partialConstruct || (partialConstruct && flag))
						{
							obj2 = new ResourceDirectory(resourceSection, file, rootResourceAddress, rootResourceAddress + resourceDirectoryEntry3.OffsetToData, addressDelta, partialConstruct: false);
						}
					}
					else
					{
						obj2 = new ResourceData(file, rootResourceAddress, rootResourceAddress + resourceDirectoryEntry3.OffsetToData, addressDelta);
					}
					if (obj2 != null)
					{
						_resourceDirectoryItems.Add(obj, obj2);
					}
				}
			}

			public override void AddComponentsToStream(StreamComponentList stream)
			{
				stream.Add(this);
				foreach (ResourceDirectoryEntry resourceDirectoryEntry in _resourceDirectoryEntries)
				{
					resourceDirectoryEntry.AddComponentsToStream(stream);
				}
				foreach (ResourceComponent value in _resourceDirectoryItems.Values)
				{
					value.AddComponentsToStream(stream);
				}
			}

			public ResourceComponent GetResourceComponent(int index)
			{
				ResourceDirectoryEntry resourceDirectoryEntry = (ResourceDirectoryEntry)_resourceDirectoryEntries[index];
				return this[resourceDirectoryEntry.Key];
			}
		}

		protected class ResourceDirectoryEntry : ResourceComponent
		{
			protected IMAGE_RESOURCE_DIRECTORY_ENTRY _imageResourceDirectoryEntry;

			protected object _key;

			public long NameOffset => _imageResourceDirectoryEntry.Name & 0x7FFFFFFF;

			public bool NameIsString => (_imageResourceDirectoryEntry.Name & 0x80000000u) != 0;

			public ushort Id => (ushort)(_imageResourceDirectoryEntry.Name & 0xFFFFu);

			public long OffsetToData => _imageResourceDirectoryEntry.OffsetToData & 0x7FFFFFFF;

			public bool IsDirectory => (_imageResourceDirectoryEntry.OffsetToData & 0x80000000u) != 0;

			public object Key
			{
				get
				{
					return _key;
				}
				set
				{
					_key = value;
				}
			}

			public ResourceDirectoryEntry(FileStream file, long address)
			{
				_imageResourceDirectoryEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY)PEComponent.ReadData(file, address, _imageResourceDirectoryEntry.GetType());
				_address = address;
				_size = CalculateSize(_imageResourceDirectoryEntry);
				_data = _imageResourceDirectoryEntry;
			}
		}

		protected class ResourceDirectoryString : ResourceComponent
		{
			protected ushort _length;

			protected byte[] _nameStringBuffer;

			protected string _nameString;

			public string NameString => _nameString;

			public ResourceDirectoryString(FileStream file, long offset)
			{
				_length = (ushort)PEComponent.ReadData(file, offset, _length.GetType());
				if (_length > 0)
				{
					long num = _length * Marshal.SizeOf(typeof(ushort));
					_nameStringBuffer = new byte[num];
					long num2 = offset + CalculateSize(_length);
					long num3 = file.Seek(num2, SeekOrigin.Begin);
					if (num3 != num2)
					{
						throw new IOException(Resources.GetString("Ex_NotEnoughDataInFile"));
					}
					int num4 = file.Read(_nameStringBuffer, 0, _nameStringBuffer.Length);
					if (num4 < num)
					{
						throw new IOException(Resources.GetString("Ex_NotEnoughDataInFile"));
					}
					_nameString = Encoding.Unicode.GetString(_nameStringBuffer);
					_address = offset;
					_size = num + CalculateSize(_length);
				}
				else
				{
					_nameStringBuffer = null;
					_nameString = null;
					_address = offset;
					_size = CalculateSize(_length);
				}
				_data = new DiskDataBlock(file, _address, _size);
			}
		}

		protected class ResourceData : ResourceComponent
		{
			protected IMAGE_RESOURCE_DATA_ENTRY _resourceDataEntry;

			protected ResourceRawData _resourceRawData;

			public byte[] Data => _resourceRawData.Data;

			public ResourceData(FileStream file, long rootResourceAddress, long address, long addressDelta)
			{
				_resourceDataEntry = (IMAGE_RESOURCE_DATA_ENTRY)PEComponent.ReadData(file, address, _resourceDataEntry.GetType());
				_resourceRawData = new ResourceRawData(file, _resourceDataEntry.OffsetToData - addressDelta, _resourceDataEntry.Size);
				_address = address;
				_size = CalculateSize(_resourceDataEntry);
				_data = _resourceDataEntry;
			}

			public override void AddComponentsToStream(StreamComponentList stream)
			{
				stream.Add(this);
				stream.Add(_resourceRawData);
			}

			public void ZeroData()
			{
				_resourceRawData.ZeroData();
			}
		}

		protected class ResourceRawData : ResourceComponent
		{
			public byte[] Data
			{
				get
				{
					byte[] array = new byte[_size];
					if (_data is DataComponent)
					{
						((DataComponent)_data).Read(array, 0, 0L, array.Length);
						return array;
					}
					throw new NotSupportedException();
				}
			}

			public ResourceRawData(FileStream file, long address, long size)
			{
				_address = address;
				_size = size;
				_data = new DiskDataBlock(file, address, size);
			}

			public void ZeroData()
			{
				_data = new BlankDataBlock(_size);
			}
		}

		protected class ResourceSection : Section
		{
			protected ResourceDirectory _resourceDirectory;

			protected ArrayList _resourceDirectoryStrings = new ArrayList();

			public ResourceDirectory RootResourceDirectory => _resourceDirectory;

			public ResourceSection(FileStream file, SectionHeader sectionHeader, bool partialConstruct)
				: base(file, sectionHeader)
			{
				_resourceDirectory = new ResourceDirectory(this, file, sectionHeader.PointerToRawData, sectionHeader.PointerToRawData, (long)sectionHeader.VirtualAddress - (long)sectionHeader.PointerToRawData, partialConstruct);
				_address = 0L;
				_size = 0L;
				_data = null;
			}

			public ResourceDirectoryString CreateResourceDirectoryString(FileStream file, long offset)
			{
				foreach (ResourceDirectoryString resourceDirectoryString3 in _resourceDirectoryStrings)
				{
					if (resourceDirectoryString3.Address == offset)
					{
						return resourceDirectoryString3;
					}
				}
				ResourceDirectoryString resourceDirectoryString2 = new ResourceDirectoryString(file, offset);
				_resourceDirectoryStrings.Add(resourceDirectoryString2);
				return resourceDirectoryString2;
			}

			public override void AddComponentsToStream(StreamComponentList stream)
			{
				_resourceDirectory.AddComponentsToStream(stream);
				foreach (ResourceDirectoryString resourceDirectoryString in _resourceDirectoryStrings)
				{
					resourceDirectoryString.AddComponentsToStream(stream);
				}
			}
		}

		protected abstract class DataComponent
		{
			public abstract int Read(byte[] buffer, int bufferOffset, long sourceOffset, int count);
		}

		protected class DiskDataBlock : DataComponent
		{
			public long _address;

			public long _size;

			public FileStream _file;

			public DiskDataBlock(FileStream file, long address, long size)
			{
				_address = address;
				_size = size;
				_file = file;
			}

			public override int Read(byte[] buffer, int bufferOffset, long sourceOffset, int count)
			{
				int num = 0;
				num = (int)Math.Min(count, _size - sourceOffset);
				if (num < 0)
				{
					throw new ArgumentException(Resources.GetString("Ex_InvalidCopyRequest"));
				}
				_file.Seek(_address + sourceOffset, SeekOrigin.Begin);
				return _file.Read(buffer, bufferOffset, num);
			}
		}

		protected class BlankDataBlock : DataComponent
		{
			public long _size;

			public BlankDataBlock(long size)
			{
				_size = size;
			}

			public override int Read(byte[] buffer, int bufferOffset, long sourceOffset, int count)
			{
				int num = 0;
				num = (int)Math.Min(count, _size - sourceOffset);
				if (num < 0)
				{
					throw new ArgumentException(Resources.GetString("Ex_InvalidCopyRequest"));
				}
				int num2 = 0;
				for (num2 = 0; num2 < num; num2++)
				{
					buffer[bufferOffset + num2] = 0;
				}
				return num;
			}
		}

		protected const ushort _id1ManifestId = 1;

		protected const ushort _id1ManifestLanguageId = 1033;

		internal const ushort IMAGE_DOS_SIGNATURE = 23117;

		internal const uint IMAGE_NT_SIGNATURE = 17744u;

		internal const uint IMAGE_NT_OPTIONAL_HDR32_MAGIC = 267u;

		internal const uint IMAGE_NT_OPTIONAL_HDR64_MAGIC = 523u;

		internal const uint IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16u;

		internal const uint IMAGE_FILE_DLL = 8192u;

		protected const uint IMAGE_DIRECTORY_ENTRY_EXPORT = 0u;

		protected const uint IMAGE_DIRECTORY_ENTRY_IMPORT = 1u;

		protected const uint IMAGE_DIRECTORY_ENTRY_RESOURCE = 2u;

		protected const uint IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3u;

		protected const uint IMAGE_DIRECTORY_ENTRY_SECURITY = 4u;

		protected const uint IMAGE_DIRECTORY_ENTRY_BASERELOC = 5u;

		protected const uint IMAGE_DIRECTORY_ENTRY_DEBUG = 6u;

		protected const uint IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7u;

		protected const uint IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8u;

		protected const uint IMAGE_DIRECTORY_ENTRY_TLS = 9u;

		protected const uint IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10u;

		protected const uint IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11u;

		protected const uint IMAGE_DIRECTORY_ENTRY_IAT = 12u;

		protected const uint IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13u;

		protected const uint IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14u;

		protected const uint IMAGE_RESOURCE_NAME_IS_STRING = 2147483648u;

		protected const uint IMAGE_RESOURCE_DATA_IS_DIRECTORY = 2147483648u;

		protected const ushort ManifestDirId = 24;

		protected const int ErrorBadFormat = 11;

		protected bool _canRead;

		protected bool _canSeek;

		protected FileStream _peFile;

		protected long _length;

		protected long _position;

		protected StreamComponentList _streamComponents = new StreamComponentList();

		protected DosHeader _dosHeader;

		protected DosStub _dosStub;

		protected NtSignature _ntSignature;

		protected FileHeader _fileHeader;

		protected OptionalHeader _optionalHeader;

		protected ArrayList _dataDirectories = new ArrayList();

		protected ArrayList _sectionHeaders = new ArrayList();

		protected ArrayList _sections = new ArrayList();

		protected ResourceSection _resourceSection;

		protected bool _partialConstruct;

		public override bool CanRead => _canRead;

		public override bool CanSeek => _canSeek;

		public override bool CanWrite => false;

		public override long Length => _length;

		public override long Position
		{
			get
			{
				return _position;
			}
			set
			{
				Seek(value, SeekOrigin.Begin);
			}
		}

		public bool IsImageFileDll => _fileHeader.IsImageFileDll;

		public static ushort Id1ManifestId => 1;

		public static ushort Id1ManifestLanguageId => 1033;

		public PEStream(string filePath)
		{
			ConstructFromFile(filePath, partialConstruct: true);
		}

		public PEStream(string filePath, bool partialConstruct)
		{
			ConstructFromFile(filePath, partialConstruct);
		}

		private void ConstructFromFile(string filePath, bool partialConstruct)
		{
			string fileName = Path.GetFileName(filePath);
			bool flag = false;
			try
			{
				_peFile = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
				ConstructPEImage(_peFile, partialConstruct);
				flag = true;
			}
			catch (IOException innerException)
			{
				throw new IOException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidPEImage"), fileName), innerException);
			}
			catch (Win32Exception innerException2)
			{
				throw new IOException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidPEImage"), fileName), innerException2);
			}
			catch (NotSupportedException innerException3)
			{
				throw new IOException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidPEImage"), fileName), innerException3);
			}
			finally
			{
				if (!flag && _peFile != null)
				{
					_peFile.Close();
				}
			}
		}

		public override void Flush()
		{
			throw new NotImplementedException();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			bool flag = false;
			long num = 0L;
			int num2 = 0;
			int num3 = count;
			long num4 = 0L;
			int num5 = offset;
			foreach (PEComponent streamComponent in _streamComponents)
			{
				if (!flag)
				{
					num = streamComponent.Address + streamComponent.Size - 1;
					if (_position <= num)
					{
						num4 = _position - streamComponent.Address;
						if (num4 < 0)
						{
							throw new Win32Exception(11, Resources.GetString("Ex_InvalidPEImage"));
						}
						flag = true;
					}
				}
				if (flag)
				{
					num2 = streamComponent.Read(buffer, num5, num4, num3);
					num5 += num2;
					_position += num2;
					num3 -= num2;
					num4 = 0L;
				}
				if (num3 <= 0)
				{
					break;
				}
			}
			return count - num3;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			switch (origin)
			{
			case SeekOrigin.Begin:
				_position = offset;
				break;
			case SeekOrigin.Current:
				_position += offset;
				break;
			case SeekOrigin.End:
				_position = _length + offset;
				break;
			}
			if (_position < 0)
			{
				_position = 0L;
			}
			if (_position > _length)
			{
				_position = _length;
			}
			return _position;
		}

		public override void SetLength(long value)
		{
			throw new NotImplementedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing && _peFile != null)
				{
					_peFile.Close();
				}
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public void ZeroOutOptionalHeaderCheckSum()
		{
			_optionalHeader.CheckSum = 0u;
		}

		public void ZeroOutManifestResource(ushort manifestId, ushort languageId)
		{
			ResourceComponent resourceComponent = RetrieveResource(new object[3]
			{
				(ushort)24,
				manifestId,
				languageId
			});
			if (resourceComponent != null && resourceComponent is ResourceData)
			{
				((ResourceData)resourceComponent).ZeroData();
			}
		}

		public byte[] GetManifestResource(ushort manifestId, ushort languageId)
		{
			ResourceComponent resourceComponent = RetrieveResource(new object[3]
			{
				(ushort)24,
				manifestId,
				languageId
			});
			if (resourceComponent != null && resourceComponent is ResourceData)
			{
				return ((ResourceData)resourceComponent).Data;
			}
			return null;
		}

		public byte[] GetDefaultId1ManifestResource()
		{
			return GetId1ManifestResource()?.Data;
		}

		public void ZeroOutDefaultId1ManifestResource()
		{
			GetId1ManifestResource()?.ZeroData();
		}

		protected ResourceData GetId1ManifestResource()
		{
			ResourceComponent resourceComponent = RetrieveResource(new object[2]
			{
				(ushort)24,
				Id1ManifestId
			});
			if (resourceComponent != null && resourceComponent is ResourceDirectory)
			{
				ResourceDirectory resourceDirectory = (ResourceDirectory)resourceComponent;
				if (resourceDirectory.ResourceComponentCount > 1)
				{
					throw new Win32Exception(11, Resources.GetString("Ex_MultipleId1Manifest"));
				}
				if (resourceDirectory.ResourceComponentCount == 1)
				{
					ResourceComponent resourceComponent2 = resourceDirectory.GetResourceComponent(0);
					if (resourceComponent2 != null && resourceComponent2 is ResourceData)
					{
						return (ResourceData)resourceComponent2;
					}
				}
			}
			return null;
		}

		protected ResourceComponent RetrieveResource(object[] keys)
		{
			if (_resourceSection == null)
			{
				return null;
			}
			ResourceDirectory rootResourceDirectory = _resourceSection.RootResourceDirectory;
			if (rootResourceDirectory == null)
			{
				return null;
			}
			return RetrieveResource(rootResourceDirectory, keys, 0u);
		}

		protected ResourceComponent RetrieveResource(ResourceDirectory resourcesDirectory, object[] keys, uint keyIndex)
		{
			ResourceComponent resourceComponent = resourcesDirectory[keys[keyIndex]];
			if (keyIndex == keys.Length - 1)
			{
				return resourceComponent;
			}
			if (resourceComponent is ResourceDirectory)
			{
				return RetrieveResource((ResourceDirectory)resourceComponent, keys, keyIndex + 1);
			}
			return null;
		}

		protected void ConstructPEImage(FileStream file, bool partialConstruct)
		{
			_partialConstruct = partialConstruct;
			_dosHeader = new DosHeader(file);
			long num = _dosHeader.NtHeaderPosition - (_dosHeader.Address + _dosHeader.Size);
			if (num < 0)
			{
				throw new Win32Exception(11, Resources.GetString("Ex_InvalidPEFormat"));
			}
			_dosStub = new DosStub(file, _dosHeader.Address + _dosHeader.Size, num);
			_ntSignature = new NtSignature(file, _dosHeader.NtHeaderPosition);
			_fileHeader = new FileHeader(file, _ntSignature.Address + _ntSignature.Size);
			_optionalHeader = new OptionalHeader(file, _fileHeader.Address + _fileHeader.Size);
			long num2 = _optionalHeader.Address + _optionalHeader.Size;
			int num3 = 0;
			for (num3 = 0; num3 < _optionalHeader.NumberOfRvaAndSizes; num3++)
			{
				DataDirectory dataDirectory = new DataDirectory(file, num2);
				num2 += dataDirectory.Size;
				_dataDirectories.Add(dataDirectory);
			}
			if (_fileHeader.SizeOfOptionalHeader < _optionalHeader.Size + _optionalHeader.NumberOfRvaAndSizes * Marshal.SizeOf(typeof(IMAGE_DATA_DIRECTORY)))
			{
				throw new Win32Exception(11, Resources.GetString("Ex_InvalidPEFormat"));
			}
			bool flag = false;
			uint num4 = 0u;
			if (_optionalHeader.NumberOfRvaAndSizes > 2)
			{
				num4 = ((DataDirectory)_dataDirectories[2]).VirtualAddress;
				flag = true;
			}
			long num5 = _optionalHeader.Address + _fileHeader.SizeOfOptionalHeader;
			for (num3 = 0; num3 < _fileHeader.NumberOfSections; num3++)
			{
				SectionHeader sectionHeader = new SectionHeader(file, num5);
				Section section = null;
				section = (sectionHeader.Section = ((!flag || sectionHeader.VirtualAddress != num4) ? new Section(file, sectionHeader) : (_resourceSection = new ResourceSection(file, sectionHeader, partialConstruct))));
				_sectionHeaders.Add(sectionHeader);
				_sections.Add(section);
				num5 += sectionHeader.Size;
			}
			ConstructStream();
			ArrayList arrayList = new ArrayList();
			long num6 = 0L;
			foreach (PEComponent streamComponent in _streamComponents)
			{
				if (streamComponent.Address < num6)
				{
					throw new Win32Exception(11, Resources.GetString("Ex_InvalidPEFormat"));
				}
				if (streamComponent.Address > num6)
				{
					PEComponent value = new PEComponent(file, num6, streamComponent.Address - num6);
					arrayList.Add(value);
				}
				num6 = streamComponent.Address + streamComponent.Size;
			}
			if (num6 < file.Length)
			{
				PEComponent value2 = new PEComponent(file, num6, file.Length - num6);
				arrayList.Add(value2);
			}
			_streamComponents.AddRange(arrayList);
			_streamComponents.Sort(new PEComponentComparer());
			_canRead = true;
			_canSeek = true;
			_length = file.Length;
			_position = 0L;
		}

		protected void ConstructStream()
		{
			_streamComponents.Clear();
			_streamComponents.Add(_dosHeader);
			_streamComponents.Add(_dosStub);
			_streamComponents.Add(_ntSignature);
			_streamComponents.Add(_fileHeader);
			_streamComponents.Add(_optionalHeader);
			foreach (DataDirectory dataDirectory in _dataDirectories)
			{
				_streamComponents.Add(dataDirectory);
			}
			foreach (SectionHeader sectionHeader in _sectionHeaders)
			{
				_streamComponents.Add(sectionHeader);
			}
			foreach (Section section in _sections)
			{
				section.AddComponentsToStream(_streamComponents);
			}
			_streamComponents.Sort(new PEComponentComparer());
		}
	}
	internal static class PlatformDetector
	{
		private enum NetFX35SP1SKU
		{
			No35SP1,
			Client35SP1,
			Full35SP1
		}

		public class OSDependency
		{
			public uint dwMajorVersion;

			public uint dwMinorVersion;

			public uint dwBuildNumber;

			public ushort wServicePackMajor;

			public ushort wServicePackMinor;

			public string suiteName;

			public string productName;

			public OSDependency()
			{
			}

			public OSDependency(uint dwMajorVersion, uint dwMinorVersion, uint dwBuildNumber, ushort wServicePackMajor, ushort wServicePackMinor, string suiteName, string productName)
			{
				this.dwMajorVersion = dwMajorVersion;
				this.dwMinorVersion = dwMinorVersion;
				this.dwBuildNumber = dwBuildNumber;
				this.wServicePackMajor = wServicePackMajor;
				this.wServicePackMinor = wServicePackMinor;
				this.suiteName = suiteName;
				this.productName = productName;
			}

			public OSDependency(NativeMethods.OSVersionInfoEx osvi)
			{
				dwMajorVersion = osvi.dwMajorVersion;
				dwMinorVersion = osvi.dwMinorVersion;
				dwMajorVersion = osvi.dwBuildNumber;
				dwMajorVersion = osvi.wServicePackMajor;
				dwMajorVersion = osvi.wServicePackMinor;
				suiteName = NameMap.MapMaskToName(osvi.wSuiteMask, Suites);
				productName = NameMap.MapMaskToName(osvi.bProductType, Products);
			}
		}

		public class NameMap
		{
			public string name;

			public uint mask;

			public NameMap(string Name, uint Mask)
			{
				name = Name;
				mask = Mask;
			}

			public static uint MapNameToMask(string name, NameMap[] nmArray)
			{
				foreach (NameMap nameMap in nmArray)
				{
					if (nameMap.name == name)
					{
						return nameMap.mask;
					}
				}
				return 0u;
			}

			public static string MapMaskToName(uint mask, NameMap[] nmArray)
			{
				foreach (NameMap nameMap in nmArray)
				{
					if (nameMap.mask == mask)
					{
						return nameMap.name;
					}
				}
				return null;
			}
		}

		public class Suite : NameMap
		{
			public Suite(string Name, uint Mask)
				: base(Name, Mask)
			{
			}
		}

		public class Product : NameMap
		{
			public Product(string Name, uint Mask)
				: base(Name, Mask)
			{
			}
		}

		private const int MAX_PATH = 260;

		private const byte VER_EQUAL = 1;

		private const byte VER_GREATER = 2;

		private const byte VER_GREATER_EQUAL = 3;

		private const byte VER_LESS = 4;

		private const byte VER_LESS_EQUAL = 5;

		private const byte VER_AND = 6;

		private const byte VER_OR = 7;

		private const uint VER_MINORVERSION = 1u;

		private const uint VER_MAJORVERSION = 2u;

		private const uint VER_BUILDNUMBER = 4u;

		private const uint VER_PLATFORMID = 8u;

		private const uint VER_SERVICEPACKMINOR = 16u;

		private const uint VER_SERVICEPACKMAJOR = 32u;

		private const uint VER_SUITENAME = 64u;

		private const uint VER_PRODUCT_TYPE = 128u;

		private const uint VER_SERVER_NT = 2147483648u;

		private const uint VER_WORKSTATION_NT = 1073741824u;

		private const uint VER_SUITE_SMALLBUSINESS = 1u;

		private const uint VER_SUITE_ENTERPRISE = 2u;

		private const uint VER_SUITE_BACKOFFICE = 4u;

		private const uint VER_SUITE_COMMUNICATIONS = 8u;

		private const uint VER_SUITE_TERMINAL = 16u;

		private const uint VER_SUITE_SMALLBUSINESS_RESTRICTED = 32u;

		private const uint VER_SUITE_EMBEDDEDNT = 64u;

		private const uint VER_SUITE_DATACENTER = 128u;

		private const uint VER_SUITE_SINGLEUSERTS = 256u;

		private const uint VER_SUITE_PERSONAL = 512u;

		private const uint VER_SUITE_BLADE = 1024u;

		private const uint VER_SUITE_EMBEDDED_RESTRICTED = 2048u;

		private const uint VER_NT_WORKSTATION = 1u;

		private const uint VER_NT_DOMAIN_CONTROLLER = 2u;

		private const uint VER_NT_SERVER = 3u;

		private const uint Windows9XMajorVersion = 4u;

		private const uint RUNTIME_INFO_UPGRADE_VERSION = 1u;

		private const uint RUNTIME_INFO_REQUEST_IA64 = 2u;

		private const uint RUNTIME_INFO_REQUEST_AMD64 = 4u;

		private const uint RUNTIME_INFO_REQUEST_X86 = 8u;

		private const uint RUNTIME_INFO_DONT_RETURN_DIRECTORY = 16u;

		private const uint RUNTIME_INFO_DONT_RETURN_VERSION = 32u;

		private const uint RUNTIME_INFO_DONT_SHOW_ERROR_DIALOG = 64u;

		private static Suite[] Suites = new Suite[14]
		{
			new Suite("server", 2147483648u),
			new Suite("workstation", 1073741824u),
			new Suite("smallbusiness", 1u),
			new Suite("enterprise", 2u),
			new Suite("backoffice", 4u),
			new Suite("communications", 8u),
			new Suite("terminal", 16u),
			new Suite("smallbusinessRestricted", 32u),
			new Suite("embeddednt", 64u),
			new Suite("datacenter", 128u),
			new Suite("singleuserts", 256u),
			new Suite("personal", 512u),
			new Suite("blade", 1024u),
			new Suite("embeddedrestricted", 2048u)
		};

		private static Product[] Products = new Product[3]
		{
			new Product("workstation", 1u),
			new Product("domainController", 2u),
			new Product("server", 3u)
		};

		public static bool VerifyCLRVersionInfo(Version v, string procArch)
		{
			bool result = true;
			NameMap[] nmArray = new NameMap[3]
			{
				new NameMap("x86", 8u),
				new Product("ia64", 2u),
				new Product("amd64", 4u)
			};
			uint num = NameMap.MapNameToMask(procArch, nmArray);
			num |= 0x41u;
			StringBuilder stringBuilder = new StringBuilder(260);
			StringBuilder stringBuilder2 = new StringBuilder("v65535.65535.65535".Length);
			uint dwDirectoryLength = 0u;
			uint dwLength = 0u;
			string text = v.ToString(3);
			text = "v" + text;
			try
			{
				NativeMethods.GetRequestedRuntimeInfo(null, text, null, 0u, num, stringBuilder, (uint)stringBuilder.Capacity, out dwDirectoryLength, stringBuilder2, (uint)stringBuilder2.Capacity, out dwLength);
				return result;
			}
			catch (COMException ex)
			{
				result = false;
				if (ex.ErrorCode != -2146232576)
				{
					throw;
				}
				return result;
			}
		}

		public static bool IsCLRDependencyText(string clrTextName)
		{
			if (string.Compare(clrTextName, "Microsoft-Windows-CLRCoreComp", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(clrTextName, "Microsoft.Windows.CommonLanguageRuntime", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return true;
			}
			return false;
		}

		public static bool IsSupportedProcessorArchitecture(string arch)
		{
			if (string.Compare(arch, "msil", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(arch, "x86", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return true;
			}
			NativeMethods.SYSTEM_INFO sysInfo = default(NativeMethods.SYSTEM_INFO);
			bool flag = false;
			try
			{
				NativeMethods.GetNativeSystemInfo(ref sysInfo);
				flag = true;
			}
			catch (EntryPointNotFoundException)
			{
				flag = false;
			}
			if (!flag)
			{
				NativeMethods.GetSystemInfo(ref sysInfo);
			}
			return sysInfo.uProcessorInfo.wProcessorArchitecture switch
			{
				6 => string.Compare(arch, "ia64", StringComparison.OrdinalIgnoreCase) == 0, 
				9 => string.Compare(arch, "amd64", StringComparison.OrdinalIgnoreCase) == 0, 
				_ => false, 
			};
		}

		public static bool VerifyOSDependency(ref OSDependency osd)
		{
			OperatingSystem oSVersion = Environment.OSVersion;
			if ((long)oSVersion.Version.Major == 4)
			{
				if (oSVersion.Version.Major < osd.dwMajorVersion)
				{
					return false;
				}
				return true;
			}
			NativeMethods.OSVersionInfoEx oSVersionInfoEx = new NativeMethods.OSVersionInfoEx();
			oSVersionInfoEx.dwOSVersionInfoSize = (uint)Marshal.SizeOf(oSVersionInfoEx);
			oSVersionInfoEx.dwMajorVersion = osd.dwMajorVersion;
			oSVersionInfoEx.dwMinorVersion = osd.dwMinorVersion;
			oSVersionInfoEx.dwBuildNumber = osd.dwBuildNumber;
			oSVersionInfoEx.dwPlatformId = 0u;
			oSVersionInfoEx.szCSDVersion = null;
			oSVersionInfoEx.wServicePackMajor = osd.wServicePackMajor;
			oSVersionInfoEx.wServicePackMinor = osd.wServicePackMinor;
			oSVersionInfoEx.wSuiteMask = (ushort)((osd.suiteName != null) ? NameMap.MapNameToMask(osd.suiteName, Suites) : 0u);
			oSVersionInfoEx.bProductType = (byte)((osd.productName != null) ? NameMap.MapNameToMask(osd.productName, Products) : 0u);
			oSVersionInfoEx.bReserved = 0;
			ulong conditionMask = 0uL;
			uint dwTypeMask = 2u | ((osd.dwMinorVersion != 0) ? 1u : 0u) | ((osd.dwBuildNumber != 0) ? 4u : 0u) | ((osd.suiteName != null) ? 64u : 0u) | ((osd.productName != null) ? 128u : 0u) | ((osd.wServicePackMajor != 0) ? 32u : 0u) | ((osd.wServicePackMinor != 0) ? 16u : 0u);
			conditionMask = NativeMethods.VerSetConditionMask(conditionMask, 2u, 3);
			if (osd.dwMinorVersion != 0)
			{
				conditionMask = NativeMethods.VerSetConditionMask(conditionMask, 1u, 3);
			}
			if (osd.dwBuildNumber != 0)
			{
				conditionMask = NativeMethods.VerSetConditionMask(conditionMask, 4u, 3);
			}
			if (osd.suiteName != null)
			{
				conditionMask = NativeMethods.VerSetConditionMask(conditionMask, 64u, 6);
			}
			if (osd.productName != null)
			{
				conditionMask = NativeMethods.VerSetConditionMask(conditionMask, 128u, 1);
			}
			if (osd.wServicePackMajor != 0)
			{
				conditionMask = NativeMethods.VerSetConditionMask(conditionMask, 32u, 3);
			}
			if (osd.wServicePackMinor != 0)
			{
				conditionMask = NativeMethods.VerSetConditionMask(conditionMask, 16u, 3);
			}
			bool flag = NativeMethods.VerifyVersionInfo(oSVersionInfoEx, dwTypeMask, conditionMask);
			if (!flag)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if (lastWin32Error != 1150)
				{
					throw new Win32Exception(lastWin32Error);
				}
			}
			return flag;
		}

		public static bool VerifyGACDependency(ReferenceIdentity refId, string tempDir)
		{
			if (string.Compare(refId.ProcessorArchitecture, "msil", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return VerifyGACDependencyWhidbey(refId);
			}
			if (!VerifyGACDependencyXP(refId, tempDir))
			{
				return VerifyGACDependencyWhidbey(refId);
			}
			return true;
		}

		public static bool VerifyGACDependencyWhidbey(ReferenceIdentity refId)
		{
			string assemblyName = refId.ToString();
			string text = null;
			try
			{
				text = AppDomain.CurrentDomain.ApplyPolicy(assemblyName);
			}
			catch (ArgumentException)
			{
				return false;
			}
			catch (COMException)
			{
				return false;
			}
			ReferenceIdentity referenceIdentity = new ReferenceIdentity(text);
			referenceIdentity.ProcessorArchitecture = refId.ProcessorArchitecture;
			string assemblyName2 = referenceIdentity.ToString();
			SystemUtils.AssemblyInfo assemblyInfo = null;
			assemblyInfo = SystemUtils.QueryAssemblyInfo(SystemUtils.QueryAssemblyInfoFlags.All, assemblyName2);
			if (assemblyInfo == null && referenceIdentity.ProcessorArchitecture == null)
			{
				NativeMethods.CreateAssemblyNameObject(out var ppEnum, referenceIdentity.ToString(), 1u, IntPtr.Zero);
				NativeMethods.CreateAssemblyEnum(out var ppEnum2, null, ppEnum, 2u, IntPtr.Zero);
				if (ppEnum2.GetNextAssembly(null, out ppEnum, 0u) == 0)
				{
					return true;
				}
				return false;
			}
			return assemblyInfo != null;
		}

		public static bool VerifyGACDependencyXP(ReferenceIdentity refId, string tempDir)
		{
			if (!PlatformSpecific.OnXPOrAbove)
			{
				return false;
			}
			using TempFile tempFile = new TempFile(tempDir, ".manifest");
			ManifestGenerator.GenerateGACDetectionManifest(refId, tempFile.Path);
			NativeMethods.ACTCTXW actCtx = new NativeMethods.ACTCTXW(tempFile.Path);
			IntPtr intPtr = NativeMethods.CreateActCtxW(actCtx);
			if (intPtr != NativeMethods.INVALID_HANDLE_VALUE)
			{
				NativeMethods.ReleaseActCtx(intPtr);
				return true;
			}
			return false;
		}

		public static void VerifyPlatformDependencies(AssemblyManifest appManifest, Uri deploySupportUri, string tempDir)
		{
			string text = null;
			Uri uri = null;
			uri = deploySupportUri;
			DependentOS dependentOS = appManifest.DependentOS;
			if (dependentOS != null)
			{
				OSDependency osd = new OSDependency(dependentOS.MajorVersion, dependentOS.MinorVersion, dependentOS.BuildNumber, dependentOS.ServicePackMajor, dependentOS.ServicePackMinor, null, null);
				if (!VerifyOSDependency(ref osd))
				{
					StringBuilder stringBuilder = new StringBuilder();
					string arg = dependentOS.MajorVersion + "." + dependentOS.MinorVersion + "." + dependentOS.BuildNumber + "." + dependentOS.ServicePackMajor + dependentOS.ServicePackMinor;
					stringBuilder.AppendFormat(Resources.GetString("PlatformMicrosoftWindowsOperatingSystem"), arg);
					text = stringBuilder.ToString();
					if (dependentOS.SupportUrl != null)
					{
						uri = dependentOS.SupportUrl;
					}
					throw new DependentPlatformMissingException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("ErrorMessage_PlatformDetectionFailed"), text), uri);
				}
			}
			bool flag = false;
			bool flag2 = false;
			DependentAssembly[] dependentAssemblies = appManifest.DependentAssemblies;
			foreach (DependentAssembly dependentAssembly in dependentAssemblies)
			{
				if (dependentAssembly.IsPreRequisite && IsCLRDependencyText(dependentAssembly.Identity.Name))
				{
					Version version = dependentAssembly.Identity.Version;
					string processorArchitecture = dependentAssembly.Identity.ProcessorArchitecture;
					if (!VerifyCLRVersionInfo(version, processorArchitecture))
					{
						StringBuilder stringBuilder2 = new StringBuilder();
						stringBuilder2.AppendFormat(Resources.GetString("PlatformMicrosoftCommonLanguageRuntime"), version.ToString());
						text = stringBuilder2.ToString();
						if (dependentAssembly.SupportUrl != null)
						{
							uri = dependentAssembly.SupportUrl;
						}
						throw new DependentPlatformMissingException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("ErrorMessage_PlatformDetectionFailed"), text), uri);
					}
				}
				if (dependentAssembly.IsPreRequisite && IsNetFX35SP1ClientSignatureAsm(dependentAssembly.Identity))
				{
					flag = true;
				}
				if (dependentAssembly.IsPreRequisite && IsNetFX35SP1FullSignatureAsm(dependentAssembly.Identity))
				{
					flag2 = true;
				}
			}
			if (!PolicyKeys.SkipSKUDetection())
			{
				NetFX35SP1SKU netFX35SP1SKU = NetFX35SP1SKU.No35SP1;
				netFX35SP1SKU = GetPlatformNetFx35SKU(tempDir);
				if (netFX35SP1SKU == NetFX35SP1SKU.Client35SP1 && !flag && !flag2)
				{
					text = ".NET Framework 3.5 SP1";
					throw new DependentPlatformMissingException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("ErrorMessage_PlatformDetectionFailed"), text));
				}
			}
			DependentAssembly[] dependentAssemblies2 = appManifest.DependentAssemblies;
			foreach (DependentAssembly dependentAssembly2 in dependentAssemblies2)
			{
				if (dependentAssembly2.IsPreRequisite && !IsCLRDependencyText(dependentAssembly2.Identity.Name) && !VerifyGACDependency(dependentAssembly2.Identity, tempDir))
				{
					if (dependentAssembly2.Description != null)
					{
						text = dependentAssembly2.Description;
					}
					else
					{
						ReferenceIdentity identity = dependentAssembly2.Identity;
						StringBuilder stringBuilder3 = new StringBuilder();
						stringBuilder3.AppendFormat(Resources.GetString("PlatformDependentAssemblyVersion"), identity.Name, identity.Version);
						text = stringBuilder3.ToString();
					}
					if (dependentAssembly2.SupportUrl != null)
					{
						uri = dependentAssembly2.SupportUrl;
					}
					throw new DependentPlatformMissingException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("ErrorMessage_PlatformGACDetectionFailed"), text), uri);
				}
			}
		}

		private static bool IsNetFX35SP1ClientSignatureAsm(ReferenceIdentity ra)
		{
			DefinitionIdentity definitionIdentity = new DefinitionIdentity("Sentinel.v3.5Client, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a,processorArchitecture=msil");
			if (definitionIdentity.Matches(ra, exact: true))
			{
				return true;
			}
			return false;
		}

		private static bool IsNetFX35SP1FullSignatureAsm(ReferenceIdentity ra)
		{
			DefinitionIdentity definitionIdentity = new DefinitionIdentity("System.Data.Entity, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089,processorArchitecture=msil");
			if (definitionIdentity.Matches(ra, exact: true))
			{
				return true;
			}
			return false;
		}

		private static NetFX35SP1SKU GetPlatformNetFx35SKU(string tempDir)
		{
			ReferenceIdentity refId = new ReferenceIdentity("Sentinel.v3.5Client, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a,processorArchitecture=msil");
			ReferenceIdentity refId2 = new ReferenceIdentity("System.Data.Entity, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089,processorArchitecture=msil");
			bool flag = false;
			bool flag2 = false;
			if (VerifyGACDependency(refId, tempDir))
			{
				flag = true;
			}
			if (VerifyGACDependency(refId2, tempDir))
			{
				flag2 = true;
			}
			if (flag && !flag2)
			{
				return NetFX35SP1SKU.Client35SP1;
			}
			if (flag && flag2)
			{
				return NetFX35SP1SKU.Full35SP1;
			}
			return NetFX35SP1SKU.No35SP1;
		}
	}
	internal class PlatformPiece : ModalPiece
	{
		private Label lblMessage;

		private PictureBox pictureIcon;

		private LinkLabel linkSupport;

		private Button btnOk;

		private TableLayoutPanel overarchingTableLayoutPanel;

		private string _errorMessage;

		private Uri _supportUrl;

		public PlatformPiece(UserInterfaceForm parentForm, string platformDetectionErrorMsg, Uri supportUrl, ManualResetEvent modalEvent)
		{
			_errorMessage = platformDetectionErrorMsg;
			_supportUrl = supportUrl;
			_modalResult = UserInterfaceModalResult.Ok;
			_modalEvent = modalEvent;
			SuspendLayout();
			InitializeComponent();
			InitializeContent();
			ResumeLayout(performLayout: false);
			parentForm.SuspendLayout();
			parentForm.SwitchUserInterfacePiece(this);
			parentForm.Text = Resources.GetString("UI_PlatformDetectionFailedTitle");
			parentForm.MinimizeBox = false;
			parentForm.MaximizeBox = false;
			parentForm.ControlBox = true;
			parentForm.ActiveControl = btnOk;
			parentForm.ResumeLayout(performLayout: false);
			parentForm.PerformLayout();
			parentForm.Visible = true;
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.Deployment.Application.PlatformPiece));
			this.lblMessage = new System.Windows.Forms.Label();
			this.pictureIcon = new System.Windows.Forms.PictureBox();
			this.btnOk = new System.Windows.Forms.Button();
			this.linkSupport = new System.Windows.Forms.LinkLabel();
			this.overarchingTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			((System.ComponentModel.ISupportInitialize)this.pictureIcon).BeginInit();
			this.overarchingTableLayoutPanel.SuspendLayout();
			base.SuspendLayout();
			resources.ApplyResources(this.lblMessage, "lblMessage");
			this.lblMessage.Name = "lblMessage";
			resources.ApplyResources(this.pictureIcon, "pictureIcon");
			this.pictureIcon.Name = "pictureIcon";
			this.pictureIcon.TabStop = false;
			resources.ApplyResources(this.btnOk, "btnOk");
			this.overarchingTableLayoutPanel.SetColumnSpan(this.btnOk, 2);
			this.btnOk.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnOk.Name = "btnOk";
			this.btnOk.Click += new System.EventHandler(btnOk_Click);
			resources.ApplyResources(this.linkSupport, "linkSupport");
			this.linkSupport.Name = "linkSupport";
			this.linkSupport.TabStop = true;
			this.linkSupport.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(linkSupport_LinkClicked);
			resources.ApplyResources(this.overarchingTableLayoutPanel, "overarchingTableLayoutPanel");
			this.overarchingTableLayoutPanel.Controls.Add(this.pictureIcon, 0, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.btnOk, 0, 2);
			this.overarchingTableLayoutPanel.Controls.Add(this.linkSupport, 1, 1);
			this.overarchingTableLayoutPanel.Controls.Add(this.lblMessage, 1, 0);
			this.overarchingTableLayoutPanel.MinimumSize = new System.Drawing.Size(349, 88);
			this.overarchingTableLayoutPanel.Name = "overarchingTableLayoutPanel";
			resources.ApplyResources(this, "$this");
			base.Controls.Add(this.overarchingTableLayoutPanel);
			this.MinimumSize = new System.Drawing.Size(373, 112);
			base.Name = "PlatformPiece";
			((System.ComponentModel.ISupportInitialize)this.pictureIcon).EndInit();
			this.overarchingTableLayoutPanel.ResumeLayout(false);
			this.overarchingTableLayoutPanel.PerformLayout();
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		private void InitializeContent()
		{
			Bitmap bitmap = (Bitmap)Resources.GetImage("information.bmp");
			bitmap.MakeTransparent();
			pictureIcon.Image = bitmap;
			linkSupport.Links.Clear();
			if (_supportUrl == null)
			{
				linkSupport.Text = Resources.GetString("UI_PlatformContactAdmin");
			}
			else
			{
				string @string = Resources.GetString("UI_PlatformClickHere");
				string string2 = Resources.GetString("UI_PlatformClickHereHere");
				int start = @string.LastIndexOf(string2, StringComparison.Ordinal);
				linkSupport.Text = @string;
				linkSupport.Links.Add(start, string2.Length, _supportUrl.AbsoluteUri);
			}
			lblMessage.Text = _errorMessage;
		}

		private void btnOk_Click(object sender, EventArgs e)
		{
			_modalResult = UserInterfaceModalResult.Ok;
			_modalEvent.Set();
			base.Enabled = false;
		}

		private void linkSupport_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
		{
			linkSupport.Links[linkSupport.Links.IndexOf(e.Link)].Visited = true;
			if (_supportUrl != null && UserInterface.IsValidHttpUrl(_supportUrl.AbsoluteUri))
			{
				UserInterface.LaunchUrlInBrowser(e.Link.LinkData.ToString());
			}
		}
	}
	internal static class PlatformSpecific
	{
		public static bool OnWin9x
		{
			get
			{
				OperatingSystem oSVersion = Environment.OSVersion;
				return oSVersion.Platform == PlatformID.Win32Windows;
			}
		}

		public static bool OnWinMe
		{
			get
			{
				OperatingSystem oSVersion = Environment.OSVersion;
				if (oSVersion.Platform == PlatformID.Win32Windows && oSVersion.Version.Major == 4 && oSVersion.Version.Minor == 90)
				{
					return true;
				}
				return false;
			}
		}

		public static bool OnXPOrAbove
		{
			get
			{
				OperatingSystem oSVersion = Environment.OSVersion;
				if (oSVersion.Platform == PlatformID.Win32NT)
				{
					if (oSVersion.Version.Major != 5 || oSVersion.Version.Minor < 1)
					{
						return oSVersion.Version.Major >= 6;
					}
					return true;
				}
				return false;
			}
		}

		public static bool OnVistaOrAbove
		{
			get
			{
				OperatingSystem oSVersion = Environment.OSVersion;
				if (oSVersion.Platform == PlatformID.Win32NT)
				{
					return oSVersion.Version.Major >= 6;
				}
				return false;
			}
		}
	}
	internal class ProgressPiece : FormPiece, IDownloadNotification
	{
		private Label lblHeader;

		private Label lblSubHeader;

		private PictureBox pictureDesktop;

		private PictureBox pictureAppIcon;

		private Label lblApplication;

		private LinkLabel linkAppId;

		private Label lblFrom;

		private Label lblFromId;

		private ProgressBar progress;

		private Label lblProgressText;

		private GroupBox groupRule;

		private GroupBox groupDivider;

		private Button btnCancel;

		private TableLayoutPanel topTextTableLayoutPanel;

		private TableLayoutPanel overarchingTableLayoutPanel;

		private TableLayoutPanel contentTableLayoutPanel;

		private UserInterfaceInfo _info;

		private bool _userCancelling;

		private DownloadEventArgs _downloadData;

		private Bitmap _appIconBitmap;

		private bool _appIconShown;

		private MethodInvoker disableMethodInvoker;

		private MethodInvoker updateUIMethodInvoker;

		private static long[] _bytesFormatRanges = new long[9] { 1024L, 10240L, 102400L, 1048576L, 10485760L, 104857600L, 1073741824L, 10737418240L, 107374182400L };

		private static string[] _bytesFormatStrings = new string[10] { "UI_ProgressBytesInBytes", "UI_ProgressBytesIn1KB", "UI_ProgressBytesIn10KB", "UI_ProgressBytesIn100KB", "UI_ProgressBytesIn1MB", "UI_ProgressBytesIn10MB", "UI_ProgressBytesIn100MB", "UI_ProgressBytesIn1GB", "UI_ProgressBytesIn10GB", "UI_ProgressBytesIn100GB" };

		public ProgressPiece(UserInterfaceForm parentForm, UserInterfaceInfo info)
		{
			_info = info;
			SuspendLayout();
			InitializeComponent();
			InitializeContent();
			ResumeLayout(performLayout: false);
			parentForm.SuspendLayout();
			parentForm.SwitchUserInterfacePiece(this);
			parentForm.Text = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_ProgressTitle"), 0, _info.formTitle);
			parentForm.MinimizeBox = true;
			parentForm.MaximizeBox = false;
			parentForm.ControlBox = true;
			lblHeader.Font = new Font(lblHeader.Font, lblHeader.Font.Style | FontStyle.Bold);
			linkAppId.Font = new Font(linkAppId.Font, linkAppId.Font.Style | FontStyle.Bold);
			lblFromId.Font = new Font(lblFromId.Font, lblFromId.Font.Style | FontStyle.Bold);
			parentForm.ActiveControl = btnCancel;
			parentForm.ResumeLayout(performLayout: false);
			parentForm.PerformLayout();
			parentForm.Visible = true;
			updateUIMethodInvoker = UpdateUI;
			disableMethodInvoker = Disable;
		}

		public void DownloadModified(object sender, DownloadEventArgs e)
		{
			if (_userCancelling)
			{
				FileDownloader fileDownloader = (FileDownloader)sender;
				fileDownloader.Cancel();
				return;
			}
			_downloadData = e;
			if (_info.iconFilePath != null && _appIconBitmap == null && e.Cookie != null && System.IO.File.Exists(_info.iconFilePath))
			{
				using Icon icon = Icon.ExtractAssociatedIcon(_info.iconFilePath);
				_appIconBitmap = TryGet32x32Bitmap(icon);
			}
			BeginInvoke(updateUIMethodInvoker);
		}

		public void DownloadCompleted(object sender, DownloadEventArgs e)
		{
			BeginInvoke(disableMethodInvoker);
		}

		public override bool OnClosing()
		{
			bool result = base.OnClosing();
			if (!base.Enabled)
			{
				return false;
			}
			_userCancelling = true;
			return result;
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.Deployment.Application.ProgressPiece));
			this.topTextTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.pictureDesktop = new System.Windows.Forms.PictureBox();
			this.lblSubHeader = new System.Windows.Forms.Label();
			this.lblHeader = new System.Windows.Forms.Label();
			this.pictureAppIcon = new System.Windows.Forms.PictureBox();
			this.lblApplication = new System.Windows.Forms.Label();
			this.linkAppId = new System.Windows.Forms.LinkLabel();
			this.lblFrom = new System.Windows.Forms.Label();
			this.lblFromId = new System.Windows.Forms.Label();
			this.progress = new System.Windows.Forms.ProgressBar();
			this.lblProgressText = new System.Windows.Forms.Label();
			this.groupRule = new System.Windows.Forms.GroupBox();
			this.groupDivider = new System.Windows.Forms.GroupBox();
			this.btnCancel = new System.Windows.Forms.Button();
			this.overarchingTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.contentTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.topTextTableLayoutPanel.SuspendLayout();
			((System.ComponentModel.ISupportInitialize)this.pictureDesktop).BeginInit();
			((System.ComponentModel.ISupportInitialize)this.pictureAppIcon).BeginInit();
			this.overarchingTableLayoutPanel.SuspendLayout();
			this.contentTableLayoutPanel.SuspendLayout();
			base.SuspendLayout();
			resources.ApplyResources(this.topTextTableLayoutPanel, "topTextTableLayoutPanel");
			this.topTextTableLayoutPanel.BackColor = System.Drawing.SystemColors.Window;
			this.topTextTableLayoutPanel.Controls.Add(this.pictureDesktop, 1, 0);
			this.topTextTableLayoutPanel.Controls.Add(this.lblSubHeader, 0, 1);
			this.topTextTableLayoutPanel.Controls.Add(this.lblHeader, 0, 0);
			this.topTextTableLayoutPanel.MinimumSize = new System.Drawing.Size(498, 61);
			this.topTextTableLayoutPanel.Name = "topTextTableLayoutPanel";
			resources.ApplyResources(this.pictureDesktop, "pictureDesktop");
			this.pictureDesktop.MinimumSize = new System.Drawing.Size(61, 61);
			this.pictureDesktop.Name = "pictureDesktop";
			this.topTextTableLayoutPanel.SetRowSpan(this.pictureDesktop, 2);
			this.pictureDesktop.TabStop = false;
			resources.ApplyResources(this.lblSubHeader, "lblSubHeader");
			this.lblSubHeader.Name = "lblSubHeader";
			resources.ApplyResources(this.lblHeader, "lblHeader");
			this.lblHeader.AutoEllipsis = true;
			this.lblHeader.Name = "lblHeader";
			this.lblHeader.UseMnemonic = false;
			resources.ApplyResources(this.pictureAppIcon, "pictureAppIcon");
			this.pictureAppIcon.Name = "pictureAppIcon";
			this.pictureAppIcon.TabStop = false;
			resources.ApplyResources(this.lblApplication, "lblApplication");
			this.lblApplication.Name = "lblApplication";
			resources.ApplyResources(this.linkAppId, "linkAppId");
			this.linkAppId.AutoEllipsis = true;
			this.linkAppId.Name = "linkAppId";
			this.linkAppId.UseMnemonic = false;
			this.linkAppId.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(linkAppId_LinkClicked);
			resources.ApplyResources(this.lblFrom, "lblFrom");
			this.lblFrom.Name = "lblFrom";
			resources.ApplyResources(this.lblFromId, "lblFromId");
			this.lblFromId.AutoEllipsis = true;
			this.lblFromId.MinimumSize = new System.Drawing.Size(384, 32);
			this.lblFromId.Name = "lblFromId";
			this.lblFromId.UseMnemonic = false;
			resources.ApplyResources(this.progress, "progress");
			this.contentTableLayoutPanel.SetColumnSpan(this.progress, 2);
			this.progress.Name = "progress";
			this.progress.TabStop = false;
			resources.ApplyResources(this.lblProgressText, "lblProgressText");
			this.contentTableLayoutPanel.SetColumnSpan(this.lblProgressText, 2);
			this.lblProgressText.Name = "lblProgressText";
			resources.ApplyResources(this.groupRule, "groupRule");
			this.groupRule.BackColor = System.Drawing.SystemColors.ControlDark;
			this.groupRule.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.groupRule.Name = "groupRule";
			this.groupRule.TabStop = false;
			resources.ApplyResources(this.groupDivider, "groupDivider");
			this.groupDivider.BackColor = System.Drawing.SystemColors.ControlDark;
			this.groupDivider.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.groupDivider.Name = "groupDivider";
			this.groupDivider.TabStop = false;
			resources.ApplyResources(this.btnCancel, "btnCancel");
			this.btnCancel.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnCancel.Name = "btnCancel";
			this.btnCancel.Click += new System.EventHandler(btnCancel_Click);
			resources.ApplyResources(this.overarchingTableLayoutPanel, "overarchingTableLayoutPanel");
			this.overarchingTableLayoutPanel.Controls.Add(this.contentTableLayoutPanel, 0, 2);
			this.overarchingTableLayoutPanel.Controls.Add(this.topTextTableLayoutPanel, 0, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.groupRule, 0, 1);
			this.overarchingTableLayoutPanel.Controls.Add(this.btnCancel, 0, 4);
			this.overarchingTableLayoutPanel.Controls.Add(this.groupDivider, 0, 3);
			this.overarchingTableLayoutPanel.MinimumSize = new System.Drawing.Size(498, 240);
			this.overarchingTableLayoutPanel.Name = "overarchingTableLayoutPanel";
			resources.ApplyResources(this.contentTableLayoutPanel, "contentTableLayoutPanel");
			this.contentTableLayoutPanel.Controls.Add(this.pictureAppIcon, 0, 0);
			this.contentTableLayoutPanel.Controls.Add(this.lblApplication, 1, 0);
			this.contentTableLayoutPanel.Controls.Add(this.lblFrom, 1, 1);
			this.contentTableLayoutPanel.Controls.Add(this.lblProgressText, 1, 3);
			this.contentTableLayoutPanel.Controls.Add(this.linkAppId, 2, 0);
			this.contentTableLayoutPanel.Controls.Add(this.progress, 1, 2);
			this.contentTableLayoutPanel.Controls.Add(this.lblFromId, 2, 1);
			this.contentTableLayoutPanel.MinimumSize = new System.Drawing.Size(466, 123);
			this.contentTableLayoutPanel.Name = "contentTableLayoutPanel";
			resources.ApplyResources(this, "$this");
			base.Controls.Add(this.overarchingTableLayoutPanel);
			this.MinimumSize = new System.Drawing.Size(498, 240);
			base.Name = "ProgressPiece";
			this.topTextTableLayoutPanel.ResumeLayout(false);
			this.topTextTableLayoutPanel.PerformLayout();
			((System.ComponentModel.ISupportInitialize)this.pictureDesktop).EndInit();
			((System.ComponentModel.ISupportInitialize)this.pictureAppIcon).EndInit();
			this.overarchingTableLayoutPanel.ResumeLayout(false);
			this.overarchingTableLayoutPanel.PerformLayout();
			this.contentTableLayoutPanel.ResumeLayout(false);
			this.contentTableLayoutPanel.PerformLayout();
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		private void InitializeContent()
		{
			pictureDesktop.Image = Resources.GetImage("setup.bmp");
			lblHeader.Text = _info.formTitle;
			using (Icon icon = Resources.GetIcon("defaultappicon.ico"))
			{
				pictureAppIcon.Image = TryGet32x32Bitmap(icon);
			}
			linkAppId.Text = _info.productName;
			linkAppId.Links.Clear();
			if (UserInterface.IsValidHttpUrl(_info.supportUrl))
			{
				linkAppId.Links.Add(0, _info.productName.Length, _info.supportUrl);
			}
			lblFromId.Text = _info.sourceSite;
		}

		private void linkAppId_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
		{
			linkAppId.LinkVisited = true;
			UserInterface.LaunchUrlInBrowser(e.Link.LinkData.ToString());
		}

		private void btnCancel_Click(object sender, EventArgs e)
		{
			_userCancelling = true;
			Disable();
		}

		private void Disable()
		{
			lblProgressText.Text = Resources.GetString("UI_ProgressDone");
			base.Enabled = false;
		}

		private Bitmap TryGet32x32Bitmap(Icon icon)
		{
			using Icon icon2 = new Icon(icon, 32, 32);
			Bitmap bitmap = icon2.ToBitmap();
			bitmap.MakeTransparent();
			return bitmap;
		}

		private void UpdateUI()
		{
			if (!base.IsDisposed)
			{
				SuspendLayout();
				lblProgressText.Text = FormatProgressText(_downloadData.BytesCompleted, _downloadData.BytesTotal);
				progress.Minimum = 0;
				int num = 0;
				int num2 = 0;
				long bytesTotal = _downloadData.BytesTotal;
				if (bytesTotal > int.MaxValue)
				{
					float num3 = 1f;
					num3 = (float)bytesTotal / 2.14748365E+09f;
					num = (int)((float)_downloadData.BytesCompleted / num3);
					num2 = int.MaxValue;
				}
				else
				{
					num = (int)_downloadData.BytesCompleted;
					num2 = (int)bytesTotal;
				}
				progress.Maximum = num2;
				progress.Value = num;
				Form form = FindForm();
				form.Text = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_ProgressTitle"), _downloadData.Progress, _info.formTitle);
				if (!_appIconShown && _appIconBitmap != null)
				{
					pictureAppIcon.Image = _appIconBitmap;
					_appIconShown = true;
				}
				ResumeLayout(performLayout: false);
			}
		}

		private static string FormatProgressText(long completed, long total)
		{
			return string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_ProgressText"), FormatBytes(completed), FormatBytes(total));
		}

		private static string FormatBytes(long bytes)
		{
			int num = Array.BinarySearch(_bytesFormatRanges, bytes);
			num = ((num >= 0) ? (num + 1) : (~num));
			return string.Format(CultureInfo.CurrentUICulture, Resources.GetString(_bytesFormatStrings[num]), (num == 0) ? ((float)bytes) : ((float)bytes / (float)_bytesFormatRanges[(num - 1) / 3 * 3]));
		}
	}
	internal static class ShellExposure
	{
		public class ShellExposureInformation
		{
			private string _applicationFolderPath;

			private string _applicationRootFolderPath;

			private string _applicationShortcutPath;

			private string _desktopShortcutPath;

			private string _supportShortcutPath;

			private string _appVendor;

			private string _appProduct;

			private string _appSuiteName;

			private string _appSupportShortcut;

			private string _shortcutAppId;

			public string ApplicationFolderPath => _applicationFolderPath;

			public string ApplicationRootFolderPath => _applicationRootFolderPath;

			public string ApplicationShortcutPath => _applicationShortcutPath;

			public string SupportShortcutPath => _supportShortcutPath;

			public string DesktopShortcutPath => _desktopShortcutPath;

			public string ARPDisplayName
			{
				get
				{
					StringBuilder stringBuilder = new StringBuilder();
					stringBuilder.Append(_appProduct);
					if (PlatformSpecific.OnWin9x && stringBuilder.Length > 63)
					{
						stringBuilder.Length = 60;
						stringBuilder.Append("...");
					}
					return stringBuilder.ToString();
				}
			}

			public string AppVendor => _appVendor;

			public string AppProduct => _appProduct;

			public string AppSuiteName => _appSuiteName;

			public string AppSupportShortcut => _appSupportShortcut;

			public string ShortcutAppId
			{
				get
				{
					return _shortcutAppId;
				}
				set
				{
					_shortcutAppId = value;
				}
			}

			public static ShellExposureInformation CreateShellExposureInformation(DefinitionIdentity subscriptionIdentity)
			{
				ShellExposureInformation shellExposureInformation = null;
				string text = null;
				string text2 = null;
				string text3 = null;
				string text4 = null;
				string shortcutAppId = "";
				using (RegistryKey registryKey = UninstallRoot.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"))
				{
					if (registryKey != null)
					{
						using RegistryKey registryKey2 = registryKey.OpenSubKey(GenerateArpKeyName(subscriptionIdentity));
						if (registryKey2 != null)
						{
							text = registryKey2.GetValue("ShortcutFolderName") as string;
							text2 = registryKey2.GetValue("ShortcutFileName") as string;
							text3 = ((registryKey2.GetValue("ShortcutSuiteName") == null) ? "" : (registryKey2.GetValue("ShortcutSuiteName") as string));
							text4 = registryKey2.GetValue("SupportShortcutFileName") as string;
							shortcutAppId = ((registryKey2.GetValue("ShortcutAppId") == null) ? "" : (registryKey2.GetValue("ShortcutAppId") as string));
						}
					}
				}
				if (text != null && text2 != null && text4 != null)
				{
					shellExposureInformation = new ShellExposureInformation();
					shellExposureInformation._applicationRootFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), text);
					if (string.IsNullOrEmpty(text3))
					{
						shellExposureInformation._applicationFolderPath = shellExposureInformation._applicationRootFolderPath;
					}
					else
					{
						shellExposureInformation._applicationFolderPath = Path.Combine(shellExposureInformation._applicationRootFolderPath, text3);
					}
					shellExposureInformation._applicationShortcutPath = Path.Combine(shellExposureInformation._applicationFolderPath, text2 + ".appref-ms");
					shellExposureInformation._supportShortcutPath = Path.Combine(shellExposureInformation._applicationFolderPath, text4 + ".url");
					shellExposureInformation._desktopShortcutPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), text2 + ".appref-ms");
					shellExposureInformation._appVendor = text;
					shellExposureInformation._appProduct = text2;
					shellExposureInformation._appSupportShortcut = text4;
					shellExposureInformation._shortcutAppId = shortcutAppId;
					shellExposureInformation._appSuiteName = text3;
				}
				return shellExposureInformation;
			}

			public static ShellExposureInformation CreateShellExposureInformation(string publisher, string suiteName, string product, string shortcutAppId)
			{
				ShellExposureInformation shellExposureInformation = new ShellExposureInformation();
				string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), publisher);
				string text2 = text;
				if (!string.IsNullOrEmpty(suiteName))
				{
					text2 = Path.Combine(text, suiteName);
				}
				string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
				string text3 = null;
				string text4 = null;
				string text5 = null;
				int num = 0;
				num = 0;
				while (true)
				{
					text3 = num switch
					{
						int.MaxValue => throw new OverflowException(), 
						0 => string.Format(CultureInfo.CurrentUICulture, Resources.GetString("ShellExposure_DisplayStringNoIndex"), product), 
						_ => string.Format(CultureInfo.CurrentUICulture, Resources.GetString("ShellExposure_DisplayStringWithIndex"), product, num), 
					};
					text4 = Path.Combine(text2, text3 + ".appref-ms");
					text5 = Path.Combine(folderPath, text3 + ".appref-ms");
					if (!System.IO.File.Exists(text4) && !System.IO.File.Exists(text5))
					{
						break;
					}
					num++;
				}
				shellExposureInformation._appVendor = publisher;
				shellExposureInformation._appProduct = text3;
				shellExposureInformation._appSuiteName = suiteName;
				shellExposureInformation._applicationFolderPath = text2;
				shellExposureInformation._applicationRootFolderPath = text;
				shellExposureInformation._applicationShortcutPath = text4;
				shellExposureInformation._desktopShortcutPath = text5;
				shellExposureInformation._appSupportShortcut = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("SupportUrlFormatter"), text3);
				shellExposureInformation._supportShortcutPath = Path.Combine(text2, shellExposureInformation._appSupportShortcut + ".url");
				shellExposureInformation._shortcutAppId = shortcutAppId;
				return shellExposureInformation;
			}

			protected ShellExposureInformation()
			{
			}
		}

		private static RegistryKey UninstallRoot
		{
			get
			{
				if (!PlatformSpecific.OnWin9x)
				{
					return Registry.CurrentUser;
				}
				return Registry.LocalMachine;
			}
		}

		public static void UpdateSubscriptionShellExposure(SubscriptionState subState)
		{
			using (subState.SubscriptionStore.AcquireStoreWriterLock())
			{
				ShellExposureInformation shellExposureInformation = ShellExposureInformation.CreateShellExposureInformation(subState.SubscriptionId);
				UpdateShortcuts(subState, ref shellExposureInformation);
				UpdateShellExtensions(subState, ref shellExposureInformation);
				UpdateArpEntry(subState, shellExposureInformation);
			}
		}

		public static void RemoveSubscriptionShellExposure(SubscriptionState subState)
		{
			using (subState.SubscriptionStore.AcquireStoreWriterLock())
			{
				DefinitionIdentity subscriptionId = subState.SubscriptionId;
				bool flag = false;
				ShellExposureInformation shellExposureInformation = ShellExposureInformation.CreateShellExposureInformation(subscriptionId);
				if (shellExposureInformation == null)
				{
					flag = true;
				}
				else
				{
					RemoveShortcuts(shellExposureInformation);
				}
				RemoveArpEntry(subscriptionId);
				if (flag)
				{
					throw new DeploymentException(ExceptionTypes.Subscription, Resources.GetString("Ex_ShortcutRemovalFailureDueToInvalidPublisherProduct"));
				}
			}
		}

		public static void RemoveShellExtensions(DefinitionIdentity subId, AssemblyManifest appManifest, string productName)
		{
			FileAssociation[] fileAssociations = appManifest.FileAssociations;
			foreach (FileAssociation fileAssociation in fileAssociations)
			{
				RemoveFileAssociation(fileAssociation, subId, productName);
			}
			NativeMethods.SHChangeNotify(134217728, 0u, IntPtr.Zero, IntPtr.Zero);
		}

		public static void ParseAppShortcut(string shortcutFile, out DefinitionIdentity subId, out Uri providerUri)
		{
			FileInfo fileInfo = new FileInfo(shortcutFile);
			if (fileInfo.Length > 65536)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_ShortcutTooLarge"));
			}
			using StreamReader streamReader = new StreamReader(shortcutFile, Encoding.Unicode);
			string text;
			try
			{
				text = streamReader.ReadToEnd();
			}
			catch (IOException innerException)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_InvalidShortcutFormat"), innerException);
			}
			if (text == null)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_InvalidShortcutFormat"));
			}
			int num = text.IndexOf('#');
			if (num < 0)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_InvalidShortcutFormat"));
			}
			try
			{
				subId = new DefinitionIdentity(text.Substring(num + 1));
			}
			catch (COMException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_InvalidShortcutFormat"), innerException2);
			}
			catch (SEHException innerException3)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_InvalidShortcutFormat"), innerException3);
			}
			try
			{
				providerUri = new Uri(text.Substring(0, num));
			}
			catch (UriFormatException innerException4)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_InvalidShortcutFormat"), innerException4);
			}
		}

		private static void MoveDeleteFile(string filePath)
		{
			if (!System.IO.File.Exists(filePath))
			{
				return;
			}
			string path = filePath;
			string text = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
			try
			{
				System.IO.File.Move(filePath, text);
				path = text;
			}
			catch (IOException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
			try
			{
				System.IO.File.Delete(path);
			}
			catch (IOException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
		}

		private static void MoveDeleteEmptyFolder(string folderPath)
		{
			if (!Directory.Exists(folderPath))
			{
				return;
			}
			string[] files = Directory.GetFiles(folderPath);
			if (files.Length > 0)
			{
				return;
			}
			string path = folderPath;
			string text = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
			try
			{
				Directory.Move(folderPath, text);
				path = text;
			}
			catch (IOException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
			try
			{
				Directory.Delete(path);
			}
			catch (IOException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
		}

		private static void UpdateShortcuts(SubscriptionState subState, ref ShellExposureInformation shellExposureInformation)
		{
			string text = $"{subState.DeploymentProviderUri.AbsoluteUri}#{subState.SubscriptionId.ToString()}";
			Description effectiveDescription = subState.EffectiveDescription;
			if (shellExposureInformation != null)
			{
				bool flag = true;
				bool flag2 = true;
				bool flag3 = true;
				bool flag4 = true;
				if (string.Compare(effectiveDescription.FilteredPublisher, shellExposureInformation.AppVendor, StringComparison.Ordinal) == 0)
				{
					flag = false;
					if (Utilities.CompareWithNullEqEmpty(effectiveDescription.FilteredSuiteName, shellExposureInformation.AppSuiteName, StringComparison.Ordinal) == 0)
					{
						flag2 = false;
						if (string.Compare(effectiveDescription.FilteredProduct, shellExposureInformation.AppProduct, StringComparison.Ordinal) == 0)
						{
							flag3 = false;
							if (string.Compare(text, shellExposureInformation.ShortcutAppId, StringComparison.Ordinal) == 0)
							{
								flag4 = false;
							}
						}
					}
				}
				if (!flag && !flag2 && !flag3 && !flag4 && System.IO.File.Exists(shellExposureInformation.ApplicationShortcutPath))
				{
					return;
				}
				if (flag3)
				{
					UnpinShortcut(shellExposureInformation.ApplicationShortcutPath);
					MoveDeleteFile(shellExposureInformation.ApplicationShortcutPath);
					MoveDeleteFile(shellExposureInformation.SupportShortcutPath);
					MoveDeleteFile(shellExposureInformation.DesktopShortcutPath);
				}
				if (flag2)
				{
					MoveDeleteEmptyFolder(shellExposureInformation.ApplicationFolderPath);
				}
				if (flag)
				{
					MoveDeleteEmptyFolder(shellExposureInformation.ApplicationRootFolderPath);
				}
				if (flag || flag2 || flag3)
				{
					shellExposureInformation = ShellExposureInformation.CreateShellExposureInformation(effectiveDescription.FilteredPublisher, effectiveDescription.FilteredSuiteName, effectiveDescription.FilteredProduct, text);
				}
				else
				{
					shellExposureInformation.ShortcutAppId = text;
				}
			}
			else
			{
				shellExposureInformation = ShellExposureInformation.CreateShellExposureInformation(effectiveDescription.FilteredPublisher, effectiveDescription.FilteredSuiteName, effectiveDescription.FilteredProduct, text);
			}
			try
			{
				Directory.CreateDirectory(shellExposureInformation.ApplicationFolderPath);
				GenerateAppShortcut(subState, shellExposureInformation);
				GenerateSupportShortcut(subState, shellExposureInformation);
			}
			catch (Exception)
			{
				RemoveShortcuts(shellExposureInformation);
				throw;
			}
		}

		private static void GenerateAppShortcut(SubscriptionState subState, ShellExposureInformation shellExposureInformation)
		{
			using (StreamWriter streamWriter = new StreamWriter(shellExposureInformation.ApplicationShortcutPath, append: false, Encoding.Unicode))
			{
				streamWriter.Write("{0}#{1}", subState.DeploymentProviderUri.AbsoluteUri, subState.SubscriptionId.ToString());
			}
			if (subState.CurrentDeploymentManifest.Deployment.CreateDesktopShortcut)
			{
				using (StreamWriter streamWriter2 = new StreamWriter(shellExposureInformation.DesktopShortcutPath, append: false, Encoding.Unicode))
				{
					streamWriter2.Write("{0}#{1}", subState.DeploymentProviderUri.AbsoluteUri, subState.SubscriptionId.ToString());
				}
			}
		}

		private static void GenerateSupportShortcut(SubscriptionState subState, ShellExposureInformation shellExposureInformation)
		{
			Description effectiveDescription = subState.EffectiveDescription;
			if (effectiveDescription.SupportUri != null)
			{
				using (StreamWriter streamWriter = new StreamWriter(shellExposureInformation.SupportShortcutPath, append: false, Encoding.ASCII))
				{
					streamWriter.WriteLine("[Default]");
					streamWriter.WriteLine("BASEURL=" + effectiveDescription.SupportUri.AbsoluteUri);
					streamWriter.WriteLine("[InternetShortcut]");
					streamWriter.WriteLine("URL=" + effectiveDescription.SupportUri.AbsoluteUri);
					streamWriter.WriteLine();
					streamWriter.WriteLine("IconFile=" + PathHelper.ShortShimDllPath);
					streamWriter.WriteLine("IconIndex=" + 0.ToString(CultureInfo.InvariantCulture));
					streamWriter.WriteLine();
				}
			}
		}

		private static void RemoveShortcuts(ShellExposureInformation shellExposureInformation)
		{
			try
			{
				if (System.IO.File.Exists(shellExposureInformation.ApplicationShortcutPath))
				{
					System.IO.File.Delete(shellExposureInformation.ApplicationShortcutPath);
				}
				if (System.IO.File.Exists(shellExposureInformation.SupportShortcutPath))
				{
					System.IO.File.Delete(shellExposureInformation.SupportShortcutPath);
				}
				if (System.IO.File.Exists(shellExposureInformation.DesktopShortcutPath))
				{
					System.IO.File.Delete(shellExposureInformation.DesktopShortcutPath);
				}
				if (Directory.Exists(shellExposureInformation.ApplicationFolderPath))
				{
					string[] files = Directory.GetFiles(shellExposureInformation.ApplicationFolderPath);
					string[] directories = Directory.GetDirectories(shellExposureInformation.ApplicationFolderPath);
					if (files.Length == 0 && directories.Length == 0)
					{
						Directory.Delete(shellExposureInformation.ApplicationFolderPath);
					}
				}
				if (Directory.Exists(shellExposureInformation.ApplicationRootFolderPath))
				{
					string[] files2 = Directory.GetFiles(shellExposureInformation.ApplicationRootFolderPath);
					string[] directories2 = Directory.GetDirectories(shellExposureInformation.ApplicationRootFolderPath);
					if (files2.Length == 0 && directories2.Length == 0)
					{
						Directory.Delete(shellExposureInformation.ApplicationRootFolderPath);
					}
				}
			}
			catch (IOException innerException)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_ShortcutRemovalFailure"), innerException);
			}
			catch (UnauthorizedAccessException innerException2)
			{
				throw new DeploymentException(ExceptionTypes.InvalidShortcut, Resources.GetString("Ex_ShortcutRemovalFailure"), innerException2);
			}
		}

		internal static void RemovePins(SubscriptionState subState)
		{
			DefinitionIdentity subscriptionId = subState.SubscriptionId;
			ShellExposureInformation shellExposureInformation = ShellExposureInformation.CreateShellExposureInformation(subscriptionId);
			if (shellExposureInformation != null && System.IO.File.Exists(shellExposureInformation.ApplicationShortcutPath))
			{
				UnpinShortcut(shellExposureInformation.ApplicationShortcutPath);
			}
		}

		public static void UpdateShellExtensions(SubscriptionState subState, ref ShellExposureInformation shellExposureInformation)
		{
			string text = null;
			if (shellExposureInformation != null)
			{
				text = shellExposureInformation.AppProduct;
			}
			if (text == null)
			{
				text = subState.SubscriptionId.Name;
			}
			if (subState.PreviousBind != null)
			{
				RemoveShellExtensions(subState.SubscriptionId, subState.PreviousApplicationManifest, text);
			}
			AddShellExtensions(subState.SubscriptionId, subState.DeploymentProviderUri, subState.CurrentApplicationManifest);
			NativeMethods.SHChangeNotify(134217728, 0u, IntPtr.Zero, IntPtr.Zero);
		}

		private static void UnpinShortcut(string shortcutPath)
		{
			uint num = 0u;
			NativeMethods.IShellItem shellItem = null;
			NativeMethods.IStartMenuPinnedList startMenuPinnedList = null;
			try
			{
				object ppv = null;
				object o = null;
				if (NativeMethods.SHCreateItemFromParsingName(shortcutPath, IntPtr.Zero, Constants.uuid, out ppv) == 0)
				{
					shellItem = ppv as NativeMethods.IShellItem;
					if (NativeMethods.CoCreateInstance(ref Constants.CLSID_StartMenuPin, null, 1, ref Constants.IID_IUnknown, out o) == 0)
					{
						startMenuPinnedList = o as NativeMethods.IStartMenuPinnedList;
						startMenuPinnedList.RemoveFromList(shellItem);
					}
				}
			}
			catch (EntryPointNotFoundException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
			finally
			{
				if (shellItem != null)
				{
					Marshal.ReleaseComObject(shellItem);
				}
				if (startMenuPinnedList != null)
				{
					Marshal.ReleaseComObject(startMenuPinnedList);
				}
			}
		}

		private static void AddShellExtensions(DefinitionIdentity subId, Uri deploymentProviderUri, AssemblyManifest appManifest)
		{
			FileAssociation[] fileAssociations = appManifest.FileAssociations;
			foreach (FileAssociation fileAssociation in fileAssociations)
			{
				AddFileAssociation(fileAssociation, subId, deploymentProviderUri);
			}
		}

		private static void AddFileAssociation(FileAssociation fileAssociation, DefinitionIdentity subId, Uri deploymentProviderUri)
		{
			RegistryKey registryKey = Registry.ClassesRoot.OpenSubKey(fileAssociation.Extension);
			RegistryKey registryKey2 = Registry.ClassesRoot.OpenSubKey(fileAssociation.ProgID);
			if (registryKey != null || registryKey2 != null)
			{
				Logger.AddWarningInformation(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("SkippedFileAssoc"), fileAssociation.Extension));
				return;
			}
			string text = Guid.NewGuid().ToString("B");
			string value = subId.ToString();
			using RegistryKey registryKey3 = Registry.CurrentUser.CreateSubKey("Software\\Classes");
			using (RegistryKey registryKey4 = registryKey3.CreateSubKey(fileAssociation.Extension))
			{
				registryKey4.SetValue(null, fileAssociation.ProgID);
				registryKey4.SetValue("AppId", value);
				registryKey4.SetValue("Guid", text);
				registryKey4.SetValue("DeploymentProviderUrl", deploymentProviderUri.AbsoluteUri);
			}
			using (RegistryKey registryKey5 = registryKey3.CreateSubKey(fileAssociation.ProgID))
			{
				registryKey5.SetValue(null, fileAssociation.Description);
				registryKey5.SetValue("AppId", value);
				registryKey5.SetValue("Guid", text);
				registryKey5.SetValue("DeploymentProviderUrl", deploymentProviderUri.AbsoluteUri);
				using RegistryKey registryKey6 = registryKey5.CreateSubKey("shell");
				registryKey6.SetValue(null, "open");
				using (RegistryKey registryKey7 = registryKey6.CreateSubKey("open\\command"))
				{
					registryKey7.SetValue(null, "rundll32.exe dfshim.dll, ShOpenVerbExtension " + text + " %1");
				}
				using RegistryKey registryKey8 = registryKey5.CreateSubKey("shellex\\IconHandler");
				registryKey8.SetValue(null, text);
			}
			using RegistryKey registryKey9 = registryKey3.CreateSubKey("CLSID");
			using RegistryKey registryKey10 = registryKey9.CreateSubKey(text);
			registryKey10.SetValue(null, "Shell Icon Handler For " + fileAssociation.Description);
			registryKey10.SetValue("AppId", value);
			registryKey10.SetValue("DeploymentProviderUrl", deploymentProviderUri.AbsoluteUri);
			registryKey10.SetValue("IconFile", fileAssociation.DefaultIcon);
			using RegistryKey registryKey11 = registryKey10.CreateSubKey("InProcServer32");
			registryKey11.SetValue(null, "dfshim.dll");
			registryKey11.SetValue("ThreadingModel", "Apartment");
		}

		private static void RemoveFileAssociation(FileAssociation fileAssociation, DefinitionIdentity subId, string productName)
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Classes", writable: true);
			if (registryKey != null)
			{
				RemoveFileAssociationExtentionInfo(fileAssociation, subId, registryKey, productName);
				string text = RemoveFileAssociationProgIDInfo(fileAssociation, subId, registryKey, productName);
				if (text != null)
				{
					RemoveFileAssociationCLSIDInfo(fileAssociation, subId, registryKey, text, productName);
				}
			}
		}

		private static void RemoveFileAssociationExtentionInfo(FileAssociation fileAssociation, DefinitionIdentity subId, RegistryKey classesKey, string productName)
		{
			using RegistryKey registryKey = classesKey.OpenSubKey(fileAssociation.Extension, writable: true);
			if (registryKey == null)
			{
				return;
			}
			object value = registryKey.GetValue("AppId");
			if (!(value is string))
			{
				return;
			}
			string a = (string)value;
			if (!string.Equals(a, subId.ToString(), StringComparison.Ordinal))
			{
				return;
			}
			try
			{
				classesKey.DeleteSubKeyTree(fileAssociation.Extension);
			}
			catch (ArgumentException innerException)
			{
				throw new DeploymentException(ExceptionTypes.InvalidARPEntry, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileAssocExtDeleteFailed"), fileAssociation.Extension, productName), innerException);
			}
		}

		private static string RemoveFileAssociationProgIDInfo(FileAssociation fileAssociation, DefinitionIdentity subId, RegistryKey classesKey, string productName)
		{
			string text = null;
			using RegistryKey registryKey = classesKey.OpenSubKey(fileAssociation.ProgID, writable: true);
			if (registryKey == null)
			{
				return null;
			}
			object value = registryKey.GetValue("AppId");
			if (!(value is string))
			{
				return null;
			}
			string a = (string)value;
			if (!string.Equals(a, subId.ToString(), StringComparison.Ordinal))
			{
				return null;
			}
			text = (string)registryKey.GetValue("Guid");
			try
			{
				classesKey.DeleteSubKeyTree(fileAssociation.ProgID);
				return text;
			}
			catch (ArgumentException innerException)
			{
				throw new DeploymentException(ExceptionTypes.InvalidARPEntry, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileAssocProgIdDeleteFailed"), fileAssociation.ProgID, productName), innerException);
			}
		}

		private static void RemoveFileAssociationCLSIDInfo(FileAssociation fileAssociation, DefinitionIdentity subId, RegistryKey classesKey, string clsIdString, string productName)
		{
			using RegistryKey registryKey = classesKey.OpenSubKey("CLSID", writable: true);
			if (registryKey == null)
			{
				return;
			}
			using RegistryKey registryKey2 = registryKey.OpenSubKey(clsIdString);
			object value = registryKey2.GetValue("AppId");
			if (!(value is string))
			{
				return;
			}
			string a = (string)value;
			if (!string.Equals(a, subId.ToString(), StringComparison.Ordinal))
			{
				return;
			}
			try
			{
				registryKey.DeleteSubKeyTree(clsIdString);
			}
			catch (ArgumentException innerException)
			{
				throw new DeploymentException(ExceptionTypes.InvalidARPEntry, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileAssocCLSIDDeleteFailed"), clsIdString, productName), innerException);
			}
		}

		private static void UpdateArpEntry(SubscriptionState subState, ShellExposureInformation shellExposureInformation)
		{
			DefinitionIdentity subscriptionId = subState.SubscriptionId;
			string text = string.Format(CultureInfo.InvariantCulture, "rundll32.exe dfshim.dll,ShArpMaintain {0}", subscriptionId.ToString());
			string text2 = string.Format(CultureInfo.InvariantCulture, "dfshim.dll,2");
			AssemblyManifest currentDeploymentManifest = subState.CurrentDeploymentManifest;
			Description effectiveDescription = subState.EffectiveDescription;
			using RegistryKey registryKey = UninstallRoot.CreateSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
			using RegistryKey registryKey2 = registryKey.CreateSubKey(GenerateArpKeyName(subscriptionId));
			string[] array = new string[24]
			{
				"DisplayName",
				shellExposureInformation.ARPDisplayName,
				"DisplayIcon",
				text2,
				"DisplayVersion",
				currentDeploymentManifest.Identity.Version.ToString(),
				"Publisher",
				effectiveDescription.FilteredPublisher,
				"UninstallString",
				text,
				"HelpLink",
				effectiveDescription.SupportUrl,
				"UrlUpdateInfo",
				subState.DeploymentProviderUri.AbsoluteUri,
				"ShortcutFolderName",
				shellExposureInformation.AppVendor,
				"ShortcutFileName",
				shellExposureInformation.AppProduct,
				"ShortcutSuiteName",
				shellExposureInformation.AppSuiteName,
				"SupportShortcutFileName",
				shellExposureInformation.AppSupportShortcut,
				"ShortcutAppId",
				shellExposureInformation.ShortcutAppId
			};
			for (int num = array.Length - 2; num >= 0; num -= 2)
			{
				string name = array[num];
				string text3 = array[num + 1];
				if (text3 != null)
				{
					registryKey2.SetValue(name, text3);
				}
				else
				{
					registryKey2.DeleteValue(name, throwOnMissingValue: false);
				}
			}
		}

		private static void RemoveArpEntry(DefinitionIdentity subId)
		{
			using RegistryKey registryKey = UninstallRoot.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", writable: true);
			string text = null;
			try
			{
				if (registryKey != null)
				{
					text = GenerateArpKeyName(subId);
					registryKey.DeleteSubKeyTree(text);
				}
			}
			catch (ArgumentException innerException)
			{
				throw new DeploymentException(ExceptionTypes.InvalidARPEntry, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ArpEntryRemovalFailure"), text), innerException);
			}
		}

		private static string GenerateArpKeyName(DefinitionIdentity subId)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0:x16}", subId.Hash);
		}
	}
	internal class SplashPiece : FormPiece
	{
		private const int initialDelay = 2500;

		private const int showDelay = 1000;

		private PictureBox pictureWait;

		private Label lblNote;

		private System.Windows.Forms.Timer splashTimer;

		private TableLayoutPanel overarchingTableLayoutPanel;

		private SplashInfo info;

		public SplashPiece(UserInterfaceForm parentForm, SplashInfo info)
		{
			this.info = info;
			SuspendLayout();
			InitializeComponent();
			InitializeContent();
			ResumeLayout(performLayout: false);
			parentForm.SuspendLayout();
			parentForm.Text = Resources.GetString("UI_SplashTitle");
			parentForm.MinimizeBox = false;
			parentForm.MaximizeBox = false;
			parentForm.ControlBox = true;
			parentForm.ResumeLayout(performLayout: false);
			splashTimer = new System.Windows.Forms.Timer();
			splashTimer.Tick += SplashTimer_Tick;
			if (info.initializedAsWait)
			{
				splashTimer.Interval = 2500;
				splashTimer.Tag = null;
				splashTimer.Enabled = true;
			}
			else
			{
				ShowSplash(parentForm);
			}
		}

		public override bool OnClosing()
		{
			bool result = base.OnClosing();
			info.cancelled = true;
			End();
			return result;
		}

		protected override void Dispose(bool disposing)
		{
			base.Dispose(disposing);
			if (disposing)
			{
				End();
			}
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.Deployment.Application.SplashPiece));
			this.pictureWait = new System.Windows.Forms.PictureBox();
			this.lblNote = new System.Windows.Forms.Label();
			this.overarchingTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			((System.ComponentModel.ISupportInitialize)this.pictureWait).BeginInit();
			this.overarchingTableLayoutPanel.SuspendLayout();
			base.SuspendLayout();
			resources.ApplyResources(this.pictureWait, "pictureWait");
			this.pictureWait.Name = "pictureWait";
			this.pictureWait.TabStop = false;
			resources.ApplyResources(this.lblNote, "lblNote");
			this.lblNote.Name = "lblNote";
			resources.ApplyResources(this.overarchingTableLayoutPanel, "overarchingTableLayoutPanel");
			this.overarchingTableLayoutPanel.Controls.Add(this.pictureWait, 0, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.lblNote, 0, 1);
			this.overarchingTableLayoutPanel.Name = "overarchingTableLayoutPanel";
			resources.ApplyResources(this, "$this");
			base.Controls.Add(this.overarchingTableLayoutPanel);
			base.Name = "SplashPiece";
			((System.ComponentModel.ISupportInitialize)this.pictureWait).EndInit();
			this.overarchingTableLayoutPanel.ResumeLayout(false);
			this.overarchingTableLayoutPanel.PerformLayout();
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		private void InitializeContent()
		{
			pictureWait.Image = Resources.GetImage("splash.gif");
		}

		private void End()
		{
			info.initializedAsWait = false;
			splashTimer.Tag = this;
			splashTimer.Dispose();
			info.pieceReady.Set();
		}

		private void ShowSplash(Form parentForm)
		{
			info.initializedAsWait = false;
			parentForm.Visible = true;
			splashTimer.Interval = 1000;
			splashTimer.Tag = this;
			splashTimer.Enabled = true;
			info.pieceReady.Reset();
		}

		private void SplashTimer_Tick(object sender, EventArgs e)
		{
			if (splashTimer.Enabled)
			{
				splashTimer.Enabled = false;
				if (splashTimer.Tag != null)
				{
					info.pieceReady.Set();
				}
				else
				{
					ShowSplash(FindForm());
				}
			}
		}
	}
	internal class SubscriptionState
	{
		private SubscriptionStore _subStore;

		private DefinitionIdentity _subId;

		private bool _stateIsValid;

		private SubscriptionStateInternal state;

		public DefinitionIdentity SubscriptionId => _subId;

		public SubscriptionStore SubscriptionStore => _subStore;

		public bool IsInstalled
		{
			get
			{
				Validate();
				return state.IsInstalled;
			}
		}

		public bool IsShellVisible
		{
			get
			{
				Validate();
				return state.IsShellVisible;
			}
		}

		public DefinitionAppId CurrentBind
		{
			get
			{
				Validate();
				return state.CurrentBind;
			}
		}

		public DefinitionAppId PreviousBind
		{
			get
			{
				Validate();
				return state.PreviousBind;
			}
		}

		public DefinitionAppId PendingBind
		{
			get
			{
				Validate();
				return state.PendingBind;
			}
		}

		public DefinitionIdentity PendingDeployment
		{
			get
			{
				Validate();
				return state.PendingDeployment;
			}
		}

		public DefinitionIdentity ExcludedDeployment
		{
			get
			{
				Validate();
				return state.ExcludedDeployment;
			}
		}

		public Uri DeploymentProviderUri
		{
			get
			{
				Validate();
				return state.DeploymentProviderUri;
			}
		}

		public Version MinimumRequiredVersion
		{
			get
			{
				Validate();
				return state.MinimumRequiredVersion;
			}
		}

		public DateTime LastCheckTime
		{
			get
			{
				Validate();
				return state.LastCheckTime;
			}
		}

		public DefinitionIdentity UpdateSkippedDeployment
		{
			get
			{
				Validate();
				return state.UpdateSkippedDeployment;
			}
		}

		public DateTime UpdateSkipTime
		{
			get
			{
				Validate();
				return state.UpdateSkipTime;
			}
		}

		public AppType appType
		{
			get
			{
				Validate();
				return state.appType;
			}
		}

		public DefinitionIdentity CurrentDeployment
		{
			get
			{
				Validate();
				return state.CurrentDeployment;
			}
		}

		public DefinitionIdentity RollbackDeployment
		{
			get
			{
				Validate();
				return state.RollbackDeployment;
			}
		}

		public AssemblyManifest CurrentDeploymentManifest
		{
			get
			{
				Validate();
				return state.CurrentDeploymentManifest;
			}
		}

		public Uri CurrentDeploymentSourceUri
		{
			get
			{
				Validate();
				return state.CurrentDeploymentSourceUri;
			}
		}

		public AssemblyManifest CurrentApplicationManifest
		{
			get
			{
				Validate();
				return state.CurrentApplicationManifest;
			}
		}

		public Uri CurrentApplicationSourceUri
		{
			get
			{
				Validate();
				return state.CurrentApplicationSourceUri;
			}
		}

		public AssemblyManifest PreviousApplicationManifest
		{
			get
			{
				Validate();
				return state.PreviousApplicationManifest;
			}
		}

		public DefinitionIdentity PKTGroupId
		{
			get
			{
				DefinitionIdentity definitionIdentity = (DefinitionIdentity)_subId.Clone();
				definitionIdentity["publicKeyToken"] = null;
				return definitionIdentity;
			}
		}

		public Description EffectiveDescription
		{
			get
			{
				if (CurrentApplicationManifest != null && CurrentApplicationManifest.UseManifestForTrust)
				{
					return CurrentApplicationManifest.Description;
				}
				if (CurrentDeploymentManifest == null)
				{
					return null;
				}
				return CurrentDeploymentManifest.Description;
			}
		}

		public string EffectiveCertificatePublicKeyToken
		{
			get
			{
				if (CurrentApplicationManifest != null && CurrentApplicationManifest.UseManifestForTrust)
				{
					return CurrentApplicationManifest.Identity.PublicKeyToken;
				}
				if (CurrentDeploymentManifest == null)
				{
					return null;
				}
				return CurrentDeploymentManifest.Identity.PublicKeyToken;
			}
		}

		public SubscriptionState(SubscriptionStore subStore, DefinitionIdentity subId)
		{
			Initialize(subStore, subId);
		}

		public SubscriptionState(SubscriptionStore subStore, AssemblyManifest deployment)
		{
			Initialize(subStore, deployment.Identity.ToSubscriptionId());
		}

		public void Invalidate()
		{
			_stateIsValid = false;
		}

		private void Validate()
		{
			if (!_stateIsValid)
			{
				state = _subStore.GetSubscriptionStateInternal(this);
				_stateIsValid = true;
			}
		}

		private void Initialize(SubscriptionStore subStore, DefinitionIdentity subId)
		{
			_subStore = subStore;
			_subId = subId;
			Invalidate();
		}
	}
	internal class SubscriptionStore
	{
		private static SubscriptionStore _userStore;

		private string _deployPath;

		private string _tempPath;

		private ComponentStore _compStore;

		private object _subscriptionStoreLock;

		private static object _currentUserLock = new object();

		public static SubscriptionStore CurrentUser
		{
			get
			{
				if (_userStore == null)
				{
					lock (_currentUserLock)
					{
						if (_userStore == null)
						{
							string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
							string deployPath = Path.Combine(folderPath, "Deployment");
							string tempPath = Path.Combine(Path.GetTempPath(), "Deployment");
							_userStore = new SubscriptionStore(deployPath, tempPath, ComponentStoreType.UserStore);
						}
					}
				}
				return _userStore;
			}
		}

		private DefinitionIdentity SubscriptionStoreLock
		{
			get
			{
				if (_subscriptionStoreLock == null)
				{
					Interlocked.CompareExchange(ref _subscriptionStoreLock, new DefinitionIdentity("__SubscriptionStoreLock__"), null);
				}
				return (DefinitionIdentity)_subscriptionStoreLock;
			}
		}

		private SubscriptionStore(string deployPath, string tempPath, ComponentStoreType storeType)
		{
			_deployPath = deployPath;
			_tempPath = tempPath;
			Directory.CreateDirectory(_deployPath);
			Directory.CreateDirectory(_tempPath);
			using (AcquireStoreWriterLock())
			{
				_compStore = ComponentStore.GetStore(storeType, this);
			}
		}

		public void RefreshStorePointer()
		{
			using (AcquireStoreWriterLock())
			{
				_compStore.RefreshStorePointer();
			}
		}

		public void CleanOnlineAppCache()
		{
			using (AcquireStoreWriterLock())
			{
				_compStore.RefreshStorePointer();
				_compStore.CleanOnlineAppCache();
			}
		}

		public void CommitApplication(ref SubscriptionState subState, CommitApplicationParams commitParams)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				if (commitParams.CommitDeploy)
				{
					UriHelper.ValidateSupportedScheme(commitParams.DeploySourceUri);
					CheckDeploymentSubscriptionState(subState, commitParams.DeployManifest);
					ValidateFileAssoctiation(subState, commitParams);
					if (commitParams.IsUpdate)
					{
						CheckInstalled(subState);
					}
				}
				if (commitParams.CommitApp)
				{
					UriHelper.ValidateSupportedScheme(commitParams.AppSourceUri);
					if (commitParams.AppGroup != null)
					{
						CheckInstalled(subState);
					}
					CheckApplicationPayload(commitParams);
				}
				bool flag = false;
				bool identityGroupFound = false;
				bool locationGroupFound = false;
				string identityGroupProductName = "";
				ArrayList arrayList = _compStore.CollectCrossGroupApplications(commitParams.DeploySourceUri, commitParams.DeployManifest.Identity, ref identityGroupFound, ref locationGroupFound, ref identityGroupProductName);
				if (arrayList.Count > 0)
				{
					flag = true;
				}
				if (subState.IsShellVisible && identityGroupFound && locationGroupFound)
				{
					throw new DeploymentException(ExceptionTypes.GroupMultipleMatch, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_GroupMultipleMatch"), identityGroupProductName));
				}
				subState = GetSubscriptionState(commitParams.DeployManifest);
				_compStore.CommitApplication(subState, commitParams);
				if (flag)
				{
					System.Deployment.Internal.Isolation.IActContext actContext = System.Deployment.Internal.Isolation.IsolationInterop.CreateActContext(subState.CurrentBind.ComPointer);
					actContext.PrepareForExecution(IntPtr.Zero, IntPtr.Zero);
					actContext.SetApplicationRunningState(0u, 1u, out var ulDisposition);
					actContext.SetApplicationRunningState(0u, 2u, out ulDisposition);
					foreach (ComponentStore.CrossGroupApplicationData item in arrayList)
					{
						if (item.CrossGroupType == ComponentStore.CrossGroupApplicationData.GroupType.LocationGroup)
						{
							if (item.SubState.IsShellVisible)
							{
								UninstallSubscription(item.SubState);
							}
							else if (item.SubState.appType == AppType.CustomHostSpecified)
							{
								UninstallCustomHostSpecifiedSubscription(item.SubState);
							}
							else if (item.SubState.appType == AppType.CustomUX)
							{
								UninstallCustomUXSubscription(item.SubState);
							}
						}
						else
						{
							_ = item.CrossGroupType;
							_ = 2;
						}
					}
				}
				if (commitParams.IsConfirmed && subState.IsInstalled && subState.IsShellVisible && commitParams.appType != AppType.CustomUX)
				{
					UpdateSubscriptionExposure(subState);
				}
				if (commitParams.appType == AppType.CustomUX)
				{
					ShellExposure.ShellExposureInformation shellExposureInformation = ShellExposure.ShellExposureInformation.CreateShellExposureInformation(subState.SubscriptionId);
					ShellExposure.UpdateShellExtensions(subState, ref shellExposureInformation);
				}
				OnDeploymentAdded(subState);
			}
		}

		public void RollbackSubscription(SubscriptionState subState)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				CheckInstalledAndShellVisible(subState);
				if (subState.RollbackDeployment == null)
				{
					throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_SubNoRollbackDeployment"));
				}
				if (subState.CurrentApplicationManifest != null)
				{
					string text = null;
					if (subState.CurrentDeploymentManifest != null && subState.CurrentDeploymentManifest.Description != null)
					{
						text = subState.CurrentDeploymentManifest.Description.Product;
					}
					if (text == null)
					{
						text = subState.SubscriptionId.Name;
					}
					ShellExposure.RemoveShellExtensions(subState.SubscriptionId, subState.CurrentApplicationManifest, text);
				}
				_compStore.RollbackSubscription(subState);
				UpdateSubscriptionExposure(subState);
				OnDeploymentRemoved(subState);
			}
		}

		public void UninstallSubscription(SubscriptionState subState)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				CheckInstalledAndShellVisible(subState);
				if (subState.CurrentApplicationManifest != null)
				{
					string text = null;
					if (subState.CurrentDeploymentManifest != null && subState.CurrentDeploymentManifest.Description != null)
					{
						text = subState.CurrentDeploymentManifest.Description.Product;
					}
					if (text == null)
					{
						text = subState.SubscriptionId.Name;
					}
					ShellExposure.RemoveShellExtensions(subState.SubscriptionId, subState.CurrentApplicationManifest, text);
					ShellExposure.RemovePins(subState);
				}
				_compStore.RemoveSubscription(subState);
				RemoveSubscriptionExposure(subState);
				OnDeploymentRemoved(subState);
			}
		}

		public void UninstallCustomUXSubscription(SubscriptionState subState)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				CheckInstalled(subState);
				if (subState.appType != AppType.CustomUX)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_CannotCallUninstallCustomUXApplication"));
				}
				if (subState.CurrentApplicationManifest != null)
				{
					string text = null;
					if (subState.CurrentDeploymentManifest != null && subState.CurrentDeploymentManifest.Description != null)
					{
						text = subState.CurrentDeploymentManifest.Description.Product;
					}
					if (text == null)
					{
						text = subState.SubscriptionId.Name;
					}
					ShellExposure.RemoveShellExtensions(subState.SubscriptionId, subState.CurrentApplicationManifest, text);
				}
				_compStore.RemoveSubscription(subState);
				OnDeploymentRemoved(subState);
			}
		}

		public void UninstallCustomHostSpecifiedSubscription(SubscriptionState subState)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				CheckInstalled(subState);
				if (subState.appType != AppType.CustomHostSpecified)
				{
					throw new InvalidOperationException(Resources.GetString("Ex_CannotCallUninstallCustomAddIn"));
				}
				_compStore.RemoveSubscription(subState);
				OnDeploymentRemoved(subState);
			}
		}

		public void SetPendingDeployment(SubscriptionState subState, DefinitionIdentity deployId, DateTime checkTime)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				CheckInstalledAndShellVisible(subState);
				_compStore.SetPendingDeployment(subState, deployId, checkTime);
			}
		}

		public void SetLastCheckTimeToNow(SubscriptionState subState)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				CheckInstalled(subState);
				_compStore.SetPendingDeployment(subState, null, DateTime.UtcNow);
			}
		}

		public void SetUpdateSkipTime(SubscriptionState subState, DefinitionIdentity updateSkippedDeployment, DateTime updateSkipTime)
		{
			using (AcquireSubscriptionWriterLock(subState))
			{
				CheckInstalledAndShellVisible(subState);
				_compStore.SetUpdateSkipTime(subState, updateSkippedDeployment, updateSkipTime);
			}
		}

		public bool CheckAndReferenceApplication(SubscriptionState subState, DefinitionAppId appId, long transactionId)
		{
			DefinitionIdentity deploymentIdentity = appId.DeploymentIdentity;
			DefinitionIdentity applicationIdentity = appId.ApplicationIdentity;
			if (subState.IsInstalled && IsAssemblyInstalled(deploymentIdentity))
			{
				if (IsAssemblyInstalled(applicationIdentity))
				{
					if (!appId.Equals(subState.CurrentBind))
					{
						return appId.Equals(subState.PreviousBind);
					}
					return true;
				}
				throw new DeploymentException(ExceptionTypes.Subscription, Resources.GetString("Ex_IllegalApplicationId"));
			}
			return false;
		}

		public void ActivateApplication(DefinitionAppId appId, string activationParameter, bool useActivationParameter)
		{
			using (AcquireStoreReaderLock())
			{
				_compStore.ActivateApplication(appId, activationParameter, useActivationParameter);
			}
		}

		public FileStream AcquireReferenceTransaction(out long transactionId)
		{
			transactionId = 0L;
			return null;
		}

		public SubscriptionState GetSubscriptionState(DefinitionIdentity subId)
		{
			return new SubscriptionState(this, subId);
		}

		public SubscriptionState GetSubscriptionState(AssemblyManifest deployment)
		{
			return new SubscriptionState(this, deployment);
		}

		public SubscriptionStateInternal GetSubscriptionStateInternal(SubscriptionState subState)
		{
			using (AcquireSubscriptionReaderLock(subState))
			{
				return _compStore.GetSubscriptionStateInternal(subState);
			}
		}

		public void CheckForDeploymentUpdate(SubscriptionState subState)
		{
			CheckInstalledAndShellVisible(subState);
			Uri sourceUri = subState.DeploymentProviderUri;
			TempFile tempFile = null;
			try
			{
				AssemblyManifest assemblyManifest = DownloadManager.DownloadDeploymentManifest(subState.SubscriptionStore, ref sourceUri, out tempFile);
				Version version = CheckUpdateInManifest(subState, sourceUri, assemblyManifest, subState.CurrentDeployment.Version);
				DefinitionIdentity deployId = ((version != null) ? assemblyManifest.Identity : null);
				SetPendingDeployment(subState, deployId, DateTime.UtcNow);
				if (version != null && assemblyManifest.Identity.Equals(subState.PendingDeployment))
				{
					Logger.AddPhaseInformation(Resources.GetString("Upd_FoundUpdate"), subState.SubscriptionId.ToString(), assemblyManifest.Identity.Version.ToString(), sourceUri.AbsoluteUri);
				}
			}
			finally
			{
				tempFile?.Dispose();
			}
		}

		public Version CheckUpdateInManifest(SubscriptionState subState, Uri updateCodebaseUri, AssemblyManifest deployment, Version currentVersion)
		{
			CheckOnlineShellVisibleConflict(subState, deployment);
			CheckInstalledAndUpdateableConflict(subState, deployment);
			CheckMinimumRequiredVersion(subState, deployment);
			SubscriptionState subscriptionState = GetSubscriptionState(deployment);
			if (!subscriptionState.SubscriptionId.Equals(subState.SubscriptionId) && (!updateCodebaseUri.Equals(subState.DeploymentProviderUri) || !subState.PKTGroupId.Equals(subscriptionState.PKTGroupId)))
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_DeploymentIdentityNotInSubscription"));
			}
			Version version = deployment.Identity.Version;
			if (version.CompareTo(currentVersion) == 0)
			{
				return null;
			}
			return version;
		}

		public void CheckDeploymentSubscriptionState(SubscriptionState subState, AssemblyManifest deployment)
		{
			if (subState.IsInstalled)
			{
				CheckOnlineShellVisibleConflict(subState, deployment);
				CheckInstalledAndUpdateableConflict(subState, deployment);
				CheckMinimumRequiredVersion(subState, deployment);
			}
		}

		public void CheckCustomUXFlag(SubscriptionState subState, AssemblyManifest application)
		{
			if (subState.IsInstalled)
			{
				if (application.EntryPoints[0].CustomUX && subState.appType != AppType.CustomUX)
				{
					throw new DeploymentException(Resources.GetString("Ex_CustomUXAlready"));
				}
				if (!application.EntryPoints[0].CustomUX && subState.appType == AppType.CustomUX)
				{
					throw new DeploymentException(Resources.GetString("Ex_NotCustomUXAlready"));
				}
			}
		}

		public void ValidateFileAssoctiation(SubscriptionState subState, CommitApplicationParams commitParams)
		{
			if (commitParams.DeployManifest != null && commitParams.AppManifest != null && !commitParams.DeployManifest.Deployment.Install && commitParams.AppManifest.FileAssociations.Length > 0)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_OnlineAppWithFileAssociation"));
			}
		}

		public void CheckInstalledAndShellVisible(SubscriptionState subState)
		{
			CheckInstalled(subState);
			CheckShellVisible(subState);
		}

		public static void CheckInstalled(SubscriptionState subState)
		{
			if (!subState.IsInstalled)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_SubNotInstalled"));
			}
		}

		public static void CheckShellVisible(SubscriptionState subState)
		{
			if (!subState.IsShellVisible)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_SubNotShellVisible"));
			}
		}

		public bool CheckGroupInstalled(SubscriptionState subState, DefinitionAppId appId, string groupName)
		{
			using (AcquireSubscriptionReaderLock(subState))
			{
				return _compStore.CheckGroupInstalled(appId, groupName);
			}
		}

		public bool CheckGroupInstalled(SubscriptionState subState, DefinitionAppId appId, AssemblyManifest appManifest, string groupName)
		{
			using (AcquireSubscriptionReaderLock(subState))
			{
				return _compStore.CheckGroupInstalled(appId, appManifest, groupName);
			}
		}

		public IDisposable AcquireSubscriptionReaderLock(SubscriptionState subState)
		{
			subState.Invalidate();
			return AcquireStoreReaderLock();
		}

		public IDisposable AcquireSubscriptionWriterLock(SubscriptionState subState)
		{
			subState.Invalidate();
			return AcquireStoreWriterLock();
		}

		public IDisposable AcquireStoreReaderLock()
		{
			return AcquireLock(SubscriptionStoreLock, writer: false);
		}

		public IDisposable AcquireStoreWriterLock()
		{
			return AcquireLock(SubscriptionStoreLock, writer: true);
		}

		public TempDirectory AcquireTempDirectory()
		{
			return new TempDirectory(_tempPath);
		}

		public TempFile AcquireTempFile(string suffix)
		{
			return new TempFile(_tempPath, suffix);
		}

		internal ulong GetPrivateSize(DefinitionAppId appId)
		{
			ArrayList arrayList = new ArrayList();
			arrayList.Add(appId);
			using (AcquireStoreReaderLock())
			{
				return _compStore.GetPrivateSize(arrayList);
			}
		}

		internal ulong GetSharedSize(DefinitionAppId appId)
		{
			ArrayList arrayList = new ArrayList();
			arrayList.Add(appId);
			using (AcquireStoreReaderLock())
			{
				return _compStore.GetSharedSize(arrayList);
			}
		}

		internal ulong GetOnlineAppQuotaInBytes()
		{
			return _compStore.GetOnlineAppQuotaInBytes();
		}

		internal ulong GetSizeLimitInBytesForSemiTrustApps()
		{
			ulong onlineAppQuotaInBytes = GetOnlineAppQuotaInBytes();
			return onlineAppQuotaInBytes / 2uL;
		}

		internal System.Deployment.Internal.Isolation.Store.IPathLock LockApplicationPath(DefinitionAppId definitionAppId)
		{
			using (AcquireStoreReaderLock())
			{
				return _compStore.LockApplicationPath(definitionAppId);
			}
		}

		private static void CheckOnlineShellVisibleConflict(SubscriptionState subState, AssemblyManifest deployment)
		{
			if (!deployment.Deployment.Install && subState.IsShellVisible)
			{
				throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_OnlineAlreadyShellVisible"));
			}
		}

		private static void CheckInstalledAndUpdateableConflict(SubscriptionState subState, AssemblyManifest deployment)
		{
		}

		private static void CheckMinimumRequiredVersion(SubscriptionState subState, AssemblyManifest deployment)
		{
			if (subState.MinimumRequiredVersion != null)
			{
				if (deployment.Identity.Version < subState.MinimumRequiredVersion)
				{
					throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_DeploymentBelowMinimumRequiredVersion"));
				}
				if (deployment.Deployment.MinimumRequiredVersion != null && deployment.Deployment.MinimumRequiredVersion < subState.MinimumRequiredVersion)
				{
					throw new DeploymentException(ExceptionTypes.SubscriptionState, Resources.GetString("Ex_DecreasingMinimumRequiredVersion"));
				}
			}
		}

		private void CheckApplicationPayload(CommitApplicationParams commitParams)
		{
			if (commitParams.AppGroup == null && commitParams.appType != AppType.CustomHostSpecified)
			{
				string path = Path.Combine(commitParams.AppPayloadPath, commitParams.AppManifest.EntryPoints[0].CommandFile);
				SystemUtils.CheckSupportedImageAndCLRVersions(path);
			}
			string text = null;
			System.Deployment.Internal.Isolation.Store.IPathLock pathLock = null;
			try
			{
				pathLock = _compStore.LockAssemblyPath(commitParams.AppManifest.Identity);
				text = Path.GetDirectoryName(pathLock.Path);
				text = Path.Combine(text, "manifests");
				text = Path.Combine(text, Path.GetFileName(pathLock.Path) + ".manifest");
			}
			catch (DeploymentException)
			{
			}
			catch (COMException)
			{
			}
			finally
			{
				pathLock?.Dispose();
			}
			if (string.IsNullOrEmpty(text) || !System.IO.File.Exists(text) || string.IsNullOrEmpty(commitParams.AppManifestPath) || !System.IO.File.Exists(commitParams.AppManifestPath))
			{
				return;
			}
			byte[] array = ComponentVerifier.GenerateDigestValue(text, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA1, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_IDENTITY);
			byte[] array2 = ComponentVerifier.GenerateDigestValue(commitParams.AppManifestPath, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_DIGESTMETHOD.CMS_HASH_DIGESTMETHOD_SHA1, System.Deployment.Internal.Isolation.Manifest.CMS_HASH_TRANSFORM.CMS_HASH_TRANSFORM_IDENTITY);
			bool flag = false;
			if (array.Length == array2.Length)
			{
				int i;
				for (i = 0; i < array.Length && array[i] == array2[i]; i++)
				{
				}
				if (i >= array.Length)
				{
					flag = true;
				}
			}
			if (!flag)
			{
				throw new DeploymentException(ExceptionTypes.Subscription, Resources.GetString("Ex_ApplicationInplaceUpdate"));
			}
		}

		private void UpdateSubscriptionExposure(SubscriptionState subState)
		{
			CheckInstalledAndShellVisible(subState);
			ShellExposure.UpdateSubscriptionShellExposure(subState);
		}

		private static void RemoveSubscriptionExposure(SubscriptionState subState)
		{
			ShellExposure.RemoveSubscriptionShellExposure(subState);
		}

		private bool IsAssemblyInstalled(DefinitionIdentity asmId)
		{
			using (AcquireStoreReaderLock())
			{
				return _compStore.IsAssemblyInstalled(asmId);
			}
		}

		private IDisposable AcquireLock(DefinitionIdentity asmId, bool writer)
		{
			string keyForm = asmId.KeyForm;
			Directory.CreateDirectory(_deployPath);
			return LockedFile.AcquireLock(Path.Combine(_deployPath, keyForm), Constants.LockTimeout, writer);
		}

		private static void OnDeploymentAdded(SubscriptionState subState)
		{
		}

		private static void OnDeploymentRemoved(SubscriptionState subState)
		{
		}
	}
	internal enum AppType
	{
		None,
		Installed,
		Online,
		CustomHostSpecified,
		CustomUX
	}
	internal class SystemNetDownloader : FileDownloader
	{
		private static Stream GetOutputFileStream(string targetPath)
		{
			return new FileStream(targetPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
		}

		protected void DownloadSingleFile(DownloadQueueItem next)
		{
			WebRequest webRequest = WebRequest.Create(next._sourceUri);
			webRequest.Credentials = CredentialCache.DefaultCredentials;
			RequestCachePolicy requestCachePolicy2 = (webRequest.CachePolicy = new RequestCachePolicy(RequestCacheLevel.BypassCache));
			if (webRequest is HttpWebRequest httpWebRequest)
			{
				httpWebRequest.UnsafeAuthenticatedConnectionSharing = true;
				httpWebRequest.AutomaticDecompression = DecompressionMethods.GZip;
				httpWebRequest.CookieContainer = GetUriCookieContainer(httpWebRequest.RequestUri);
				IWebProxy defaultWebProxy = WebRequest.DefaultWebProxy;
				if (defaultWebProxy != null)
				{
					defaultWebProxy.Credentials = CredentialCache.DefaultCredentials;
				}
			}
			if (_fCancelPending)
			{
				return;
			}
			WebResponse webResponse = null;
			try
			{
				webResponse = webRequest.GetResponse();
				UriHelper.ValidateSupportedScheme(webResponse.ResponseUri);
				if (_fCancelPending)
				{
					return;
				}
				_eventArgs._fileSourceUri = next._sourceUri;
				_eventArgs._fileResponseUri = webResponse.ResponseUri;
				_eventArgs.FileLocalPath = next._targetPath;
				_eventArgs.Cookie = null;
				if (webResponse.ContentLength > 0)
				{
					CheckForSizeLimit((ulong)webResponse.ContentLength, addToSize: false);
					_accumulatedBytesTotal += webResponse.ContentLength;
				}
				SetBytesTotal();
				OnModified();
				Stream stream = null;
				Stream stream2 = null;
				int lastTick = Environment.TickCount;
				try
				{
					stream = webResponse.GetResponseStream();
					Directory.CreateDirectory(Path.GetDirectoryName(next._targetPath));
					stream2 = GetOutputFileStream(next._targetPath);
					if (stream2 != null)
					{
						long num = 0L;
						if (webResponse.ContentLength > 0)
						{
							stream2.SetLength(webResponse.ContentLength);
						}
						int num2;
						do
						{
							if (_fCancelPending)
							{
								return;
							}
							num2 = stream.Read(_buffer, 0, _buffer.Length);
							if (num2 > 0)
							{
								stream2.Write(_buffer, 0, num2);
							}
							_eventArgs._bytesCompleted += num2;
							if (webResponse.ContentLength <= 0)
							{
								_accumulatedBytesTotal += num2;
								SetBytesTotal();
							}
							num += num2;
							if (next._maxFileSize != -1 && num > next._maxFileSize)
							{
								throw new InvalidDeploymentException(ExceptionTypes.FileSizeValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FileBeingDownloadedTooLarge"), next._sourceUri.ToString(), next._maxFileSize));
							}
							CheckForSizeLimit((ulong)num2, addToSize: true);
							if (_eventArgs._bytesTotal > 0)
							{
								_eventArgs._progress = (int)(_eventArgs._bytesCompleted * 100 / _eventArgs._bytesTotal);
							}
							OnModifiedWithThrottle(ref lastTick);
						}
						while (num2 > 0);
						if (webResponse.ContentLength != num)
						{
							stream2.SetLength(num);
						}
					}
				}
				finally
				{
					stream?.Close();
					stream2?.Close();
				}
				_eventArgs.Cookie = next._cookie;
				_eventArgs._filesCompleted++;
				OnModified();
				DownloadResult downloadResult = new DownloadResult();
				downloadResult.ResponseUri = webResponse.ResponseUri;
				downloadResult.ServerInformation.Server = webResponse.Headers["Server"];
				downloadResult.ServerInformation.PoweredBy = webResponse.Headers["X-Powered-By"];
				downloadResult.ServerInformation.AspNetVersion = webResponse.Headers["X-AspNet-Version"];
				_downloadResults.Add(downloadResult);
			}
			catch (InvalidOperationException innerException)
			{
				string message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FailedWhileDownloading"), next._sourceUri);
				throw new DeploymentDownloadException(message, innerException);
			}
			catch (IOException innerException2)
			{
				string message2 = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FailedWhileDownloading"), next._sourceUri);
				throw new DeploymentDownloadException(message2, innerException2);
			}
			catch (UnauthorizedAccessException innerException3)
			{
				string message3 = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_FailedWhileDownloading"), next._sourceUri);
				throw new DeploymentDownloadException(message3, innerException3);
			}
			finally
			{
				webResponse?.Close();
			}
		}

		protected override void DownloadAllFiles()
		{
			do
			{
				DownloadQueueItem downloadQueueItem = null;
				lock (_fileQueue)
				{
					if (_fileQueue.Count > 0)
					{
						downloadQueueItem = (DownloadQueueItem)_fileQueue.Dequeue();
					}
				}
				if (downloadQueueItem == null)
				{
					break;
				}
				DownloadSingleFile(downloadQueueItem);
			}
			while (!_fCancelPending);
			if (_fCancelPending)
			{
				throw new DownloadCancelledException();
			}
		}

		private static CookieContainer GetUriCookieContainer(Uri uri)
		{
			CookieContainer result = null;
			uint bytes = 0u;
			if (NativeMethods.InternetGetCookieW(uri.ToString(), null, null, ref bytes))
			{
				StringBuilder stringBuilder = new StringBuilder((int)(bytes / 2u));
				if (NativeMethods.InternetGetCookieW(uri.ToString(), null, stringBuilder, ref bytes) && stringBuilder.Length > 0)
				{
					try
					{
						result = new CookieContainer();
						result.SetCookies(uri, stringBuilder.ToString().Replace(';', ','));
						return result;
					}
					catch (CookieException)
					{
						return null;
					}
				}
			}
			return result;
		}
	}
	internal class TempDirectory : DisposableBase
	{
		private const uint _directorySegmentCount = 2u;

		private string _thePath;

		public string Path => _thePath;

		public TempDirectory()
			: this(System.IO.Path.GetTempPath())
		{
		}

		public TempDirectory(string basePath)
		{
			do
			{
				_thePath = System.IO.Path.Combine(basePath, PathHelper.GenerateRandomPath(2u));
			}
			while (Directory.Exists(_thePath) || System.IO.File.Exists(_thePath));
			Directory.CreateDirectory(_thePath);
		}

		protected override void DisposeUnmanagedResources()
		{
			string rootSegmentPath = PathHelper.GetRootSegmentPath(_thePath, 2u);
			if (!Directory.Exists(rootSegmentPath))
			{
				return;
			}
			try
			{
				Directory.Delete(rootSegmentPath, recursive: true);
			}
			catch (IOException)
			{
				Thread.Sleep(10);
				try
				{
					Directory.Delete(rootSegmentPath, recursive: true);
				}
				catch (IOException)
				{
				}
			}
		}
	}
	internal class TempFile : DisposableBase
	{
		private const uint _filePathSegmentCount = 2u;

		private string _thePath;

		public string Path => _thePath;

		public TempFile()
			: this(System.IO.Path.GetTempPath())
		{
		}

		public TempFile(string basePath)
			: this(basePath, string.Empty)
		{
		}

		public TempFile(string basePath, string suffix)
		{
			do
			{
				_thePath = System.IO.Path.Combine(basePath, PathHelper.GenerateRandomPath(2u) + suffix);
			}
			while (System.IO.File.Exists(_thePath) || Directory.Exists(_thePath));
			string directoryName = System.IO.Path.GetDirectoryName(_thePath);
			Directory.CreateDirectory(directoryName);
		}

		protected override void DisposeUnmanagedResources()
		{
			string rootSegmentPath = PathHelper.GetRootSegmentPath(_thePath, 2u);
			if (!Directory.Exists(rootSegmentPath))
			{
				return;
			}
			try
			{
				Directory.Delete(rootSegmentPath, recursive: true);
			}
			catch (IOException)
			{
				Thread.Sleep(10);
				try
				{
					Directory.Delete(rootSegmentPath, recursive: true);
				}
				catch (IOException)
				{
				}
			}
		}
	}
	internal class UpdatePiece : ModalPiece
	{
		private Label lblHeader;

		private Label lblSubHeader;

		private PictureBox pictureDesktop;

		private Label lblApplication;

		private LinkLabel linkAppId;

		private Label lblFrom;

		private Label lblFromId;

		private GroupBox groupRule;

		private GroupBox groupDivider;

		private Button btnOk;

		private Button btnSkip;

		private TableLayoutPanel contentTableLayoutPanel;

		private TableLayoutPanel descriptionTableLayoutPanel;

		private TableLayoutPanel okSkipTableLayoutPanel;

		private TableLayoutPanel overarchingTableLayoutPanel;

		private UserInterfaceInfo _info;

		public UpdatePiece(UserInterfaceForm parentForm, UserInterfaceInfo info, ManualResetEvent modalEvent)
		{
			_info = info;
			_modalEvent = modalEvent;
			_modalResult = UserInterfaceModalResult.Cancel;
			SuspendLayout();
			InitializeComponent();
			InitializeContent();
			ResumeLayout(performLayout: false);
			parentForm.SuspendLayout();
			parentForm.SwitchUserInterfacePiece(this);
			parentForm.Text = _info.formTitle;
			parentForm.MinimizeBox = false;
			parentForm.MaximizeBox = false;
			parentForm.ControlBox = true;
			lblHeader.Font = new Font(lblHeader.Font, lblHeader.Font.Style | FontStyle.Bold);
			linkAppId.Font = new Font(linkAppId.Font, linkAppId.Font.Style | FontStyle.Bold);
			lblFromId.Font = new Font(lblFromId.Font, lblFromId.Font.Style | FontStyle.Bold);
			parentForm.ActiveControl = btnOk;
			parentForm.ResumeLayout(performLayout: false);
			parentForm.PerformLayout();
			parentForm.Visible = true;
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.Deployment.Application.UpdatePiece));
			this.descriptionTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.pictureDesktop = new System.Windows.Forms.PictureBox();
			this.lblSubHeader = new System.Windows.Forms.Label();
			this.lblHeader = new System.Windows.Forms.Label();
			this.lblApplication = new System.Windows.Forms.Label();
			this.linkAppId = new System.Windows.Forms.LinkLabel();
			this.lblFrom = new System.Windows.Forms.Label();
			this.lblFromId = new System.Windows.Forms.Label();
			this.groupRule = new System.Windows.Forms.GroupBox();
			this.groupDivider = new System.Windows.Forms.GroupBox();
			this.btnOk = new System.Windows.Forms.Button();
			this.btnSkip = new System.Windows.Forms.Button();
			this.contentTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.okSkipTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.overarchingTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
			this.descriptionTableLayoutPanel.SuspendLayout();
			((System.ComponentModel.ISupportInitialize)this.pictureDesktop).BeginInit();
			this.contentTableLayoutPanel.SuspendLayout();
			this.okSkipTableLayoutPanel.SuspendLayout();
			this.overarchingTableLayoutPanel.SuspendLayout();
			base.SuspendLayout();
			resources.ApplyResources(this.descriptionTableLayoutPanel, "descriptionTableLayoutPanel");
			this.descriptionTableLayoutPanel.BackColor = System.Drawing.SystemColors.Window;
			this.descriptionTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Absolute, 400f));
			this.descriptionTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Absolute, 60f));
			this.descriptionTableLayoutPanel.Controls.Add(this.pictureDesktop, 1, 0);
			this.descriptionTableLayoutPanel.Controls.Add(this.lblSubHeader, 0, 1);
			this.descriptionTableLayoutPanel.Controls.Add(this.lblHeader, 0, 0);
			this.descriptionTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0);
			this.descriptionTableLayoutPanel.Name = "descriptionTableLayoutPanel";
			this.descriptionTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.descriptionTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			resources.ApplyResources(this.pictureDesktop, "pictureDesktop");
			this.pictureDesktop.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
			this.pictureDesktop.Name = "pictureDesktop";
			this.descriptionTableLayoutPanel.SetRowSpan(this.pictureDesktop, 2);
			this.pictureDesktop.TabStop = false;
			resources.ApplyResources(this.lblSubHeader, "lblSubHeader");
			this.lblSubHeader.Margin = new System.Windows.Forms.Padding(29, 3, 3, 8);
			this.lblSubHeader.Name = "lblSubHeader";
			resources.ApplyResources(this.lblHeader, "lblHeader");
			this.lblHeader.Margin = new System.Windows.Forms.Padding(10, 11, 3, 0);
			this.lblHeader.Name = "lblHeader";
			resources.ApplyResources(this.lblApplication, "lblApplication");
			this.lblApplication.Margin = new System.Windows.Forms.Padding(0, 0, 3, 3);
			this.lblApplication.Name = "lblApplication";
			resources.ApplyResources(this.linkAppId, "linkAppId");
			this.linkAppId.AutoEllipsis = true;
			this.linkAppId.Margin = new System.Windows.Forms.Padding(3, 0, 0, 3);
			this.linkAppId.Name = "linkAppId";
			this.linkAppId.TabStop = true;
			this.linkAppId.UseMnemonic = false;
			this.linkAppId.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(linkAppId_LinkClicked);
			resources.ApplyResources(this.lblFrom, "lblFrom");
			this.lblFrom.Margin = new System.Windows.Forms.Padding(0, 3, 3, 0);
			this.lblFrom.Name = "lblFrom";
			resources.ApplyResources(this.lblFromId, "lblFromId");
			this.lblFromId.AutoEllipsis = true;
			this.lblFromId.Margin = new System.Windows.Forms.Padding(3, 3, 0, 0);
			this.lblFromId.Name = "lblFromId";
			this.lblFromId.UseMnemonic = false;
			resources.ApplyResources(this.groupRule, "groupRule");
			this.groupRule.Margin = new System.Windows.Forms.Padding(0, 0, 0, 3);
			this.groupRule.BackColor = System.Drawing.SystemColors.ControlDark;
			this.groupRule.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.groupRule.Name = "groupRule";
			this.groupRule.TabStop = false;
			resources.ApplyResources(this.groupDivider, "groupDivider");
			this.groupDivider.Margin = new System.Windows.Forms.Padding(0, 3, 0, 3);
			this.groupDivider.BackColor = System.Drawing.SystemColors.ControlDark;
			this.groupDivider.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.groupDivider.Name = "groupDivider";
			this.groupDivider.TabStop = false;
			resources.ApplyResources(this.btnOk, "btnOk");
			this.btnOk.Margin = new System.Windows.Forms.Padding(0, 0, 3, 0);
			this.btnOk.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnOk.Name = "btnOk";
			this.btnOk.Padding = new System.Windows.Forms.Padding(10, 0, 10, 0);
			this.btnOk.Click += new System.EventHandler(btnOk_Click);
			resources.ApplyResources(this.btnSkip, "btnSkip");
			this.btnSkip.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
			this.btnSkip.MinimumSize = new System.Drawing.Size(75, 23);
			this.btnSkip.Name = "btnSkip";
			this.btnSkip.Padding = new System.Windows.Forms.Padding(10, 0, 10, 0);
			this.btnSkip.Click += new System.EventHandler(btnSkip_Click);
			resources.ApplyResources(this.contentTableLayoutPanel, "contentTableLayoutPanel");
			this.contentTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.contentTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50f));
			this.contentTableLayoutPanel.Controls.Add(this.lblApplication, 0, 0);
			this.contentTableLayoutPanel.Controls.Add(this.lblFrom, 0, 1);
			this.contentTableLayoutPanel.Controls.Add(this.linkAppId, 1, 0);
			this.contentTableLayoutPanel.Controls.Add(this.lblFromId, 1, 1);
			this.contentTableLayoutPanel.Margin = new System.Windows.Forms.Padding(20, 15, 12, 18);
			this.contentTableLayoutPanel.Name = "contentTableLayoutPanel";
			this.contentTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.contentTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			resources.ApplyResources(this.okSkipTableLayoutPanel, "okSkipTableLayoutPanel");
			this.okSkipTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50f));
			this.okSkipTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50f));
			this.okSkipTableLayoutPanel.Controls.Add(this.btnOk, 0, 0);
			this.okSkipTableLayoutPanel.Controls.Add(this.btnSkip, 1, 0);
			this.okSkipTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0, 7, 8, 6);
			this.okSkipTableLayoutPanel.Name = "okSkipTableLayoutPanel";
			this.okSkipTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50f));
			resources.ApplyResources(this.overarchingTableLayoutPanel, "overarchingTableLayoutPanel");
			this.overarchingTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100f));
			this.overarchingTableLayoutPanel.Controls.Add(this.descriptionTableLayoutPanel, 0, 0);
			this.overarchingTableLayoutPanel.Controls.Add(this.okSkipTableLayoutPanel, 0, 4);
			this.overarchingTableLayoutPanel.Controls.Add(this.contentTableLayoutPanel, 0, 2);
			this.overarchingTableLayoutPanel.Controls.Add(this.groupRule, 0, 1);
			this.overarchingTableLayoutPanel.Controls.Add(this.groupDivider, 0, 3);
			this.overarchingTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0);
			this.overarchingTableLayoutPanel.Name = "overarchingTableLayoutPanel";
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.overarchingTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
			resources.ApplyResources(this, "$this");
			base.Controls.Add(this.overarchingTableLayoutPanel);
			base.Name = "UpdatePiece";
			this.descriptionTableLayoutPanel.ResumeLayout(false);
			this.descriptionTableLayoutPanel.PerformLayout();
			((System.ComponentModel.ISupportInitialize)this.pictureDesktop).EndInit();
			this.contentTableLayoutPanel.ResumeLayout(false);
			this.contentTableLayoutPanel.PerformLayout();
			this.okSkipTableLayoutPanel.ResumeLayout(false);
			this.okSkipTableLayoutPanel.PerformLayout();
			this.overarchingTableLayoutPanel.ResumeLayout(false);
			this.overarchingTableLayoutPanel.PerformLayout();
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		private void InitializeContent()
		{
			pictureDesktop.Image = Resources.GetImage("setup.bmp");
			lblSubHeader.Text = string.Format(CultureInfo.CurrentUICulture, Resources.GetString("UI_UpdateSubHeader"), UserInterface.LimitDisplayTextLength(_info.productName));
			linkAppId.Text = _info.productName;
			linkAppId.Links.Clear();
			if (UserInterface.IsValidHttpUrl(_info.supportUrl))
			{
				linkAppId.Links.Add(0, _info.productName.Length, _info.supportUrl);
			}
			lblFromId.Text = _info.sourceSite;
		}

		private void linkAppId_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
		{
			linkAppId.LinkVisited = true;
			UserInterface.LaunchUrlInBrowser(e.Link.LinkData.ToString());
		}

		private void btnOk_Click(object sender, EventArgs e)
		{
			_modalResult = UserInterfaceModalResult.Ok;
			_modalEvent.Set();
			base.Enabled = false;
		}

		private void btnSkip_Click(object sender, EventArgs e)
		{
			_modalResult = UserInterfaceModalResult.Skip;
			_modalEvent.Set();
			base.Enabled = false;
		}
	}
	internal static class UriHelper
	{
		private static object _invalidRelativePathChars;

		private static char[] _directorySeparators = new char[2]
		{
			Path.DirectorySeparatorChar,
			Path.AltDirectorySeparatorChar
		};

		private static char[] InvalidRelativePathChars
		{
			get
			{
				if (_invalidRelativePathChars == null)
				{
					char[] invalidPathChars = Path.GetInvalidPathChars();
					char[] array = new char[invalidPathChars.Length + 3];
					invalidPathChars.CopyTo(array, 0);
					int num = invalidPathChars.Length;
					array[num++] = Path.VolumeSeparatorChar;
					array[num++] = '*';
					array[num++] = '?';
					Interlocked.CompareExchange(ref _invalidRelativePathChars, array, null);
				}
				return (char[])_invalidRelativePathChars;
			}
		}

		public static void ValidateSupportedScheme(Uri uri)
		{
			if (!IsSupportedScheme(uri))
			{
				throw new InvalidDeploymentException(ExceptionTypes.UriSchemeNotSupported, Resources.GetString("Ex_NotSupportedUriScheme"));
			}
		}

		public static void ValidateSupportedSchemeInArgument(Uri uri, string argumentName)
		{
			if (!IsSupportedScheme(uri))
			{
				throw new ArgumentException(Resources.GetString("Ex_NotSupportedUriScheme"), argumentName);
			}
		}

		public static bool IsSupportedScheme(Uri uri)
		{
			if (!(uri.Scheme == Uri.UriSchemeFile) && !(uri.Scheme == Uri.UriSchemeHttp))
			{
				return uri.Scheme == Uri.UriSchemeHttps;
			}
			return true;
		}

		public static Uri UriFromRelativeFilePath(Uri baseUri, string path)
		{
			if (!IsValidRelativeFilePath(path))
			{
				throw new ArgumentException(Resources.GetString("Ex_InvalidRelativePath"));
			}
			if (path.IndexOf('%') >= 0)
			{
				path = path.Replace("%", Uri.HexEscape('%'));
			}
			if (path.IndexOf('#') >= 0)
			{
				path = path.Replace("#", Uri.HexEscape('#'));
			}
			Uri uri = new Uri(baseUri, path);
			ValidateSupportedScheme(uri);
			return uri;
		}

		public static bool IsValidRelativeFilePath(string path)
		{
			if (path == null || path.Length == 0 || path.IndexOfAny(InvalidRelativePathChars) >= 0)
			{
				return false;
			}
			if (Path.IsPathRooted(path))
			{
				return false;
			}
			string text = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
			string path2 = Path.Combine(Path.DirectorySeparatorChar.ToString(), text);
			string fullPath = Path.GetFullPath(path2);
			string pathRoot = Path.GetPathRoot(fullPath);
			string text2 = fullPath.Substring(pathRoot.Length);
			if (text2.Length > 0 && text2[0] == '\\')
			{
				text2 = text2.Substring(1);
			}
			if (string.Compare(text2, text, StringComparison.Ordinal) == 0)
			{
				return true;
			}
			return false;
		}

		public static string NormalizePathDirectorySeparators(string path)
		{
			return path?.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
		}

		public static bool PathContainDirectorySeparators(string path)
		{
			if (path == null)
			{
				return false;
			}
			return path.IndexOfAny(_directorySeparators) >= 0;
		}
	}
	internal class UserInterface : IDisposable
	{
		private UserInterfaceForm _uiForm;

		private ApplicationContext _appctx;

		private ManualResetEvent _appctxExitThreadFinished = new ManualResetEvent(initialState: false);

		private Thread _uiThread;

		private ManualResetEvent _uiConstructed = new ManualResetEvent(initialState: false);

		private ManualResetEvent _uiReady = new ManualResetEvent(initialState: false);

		private SplashInfo _splashInfo;

		private bool _disposed;

		private static string DefaultBrowserExePath
		{
			get
			{
				string result = null;
				RegistryKey registryKey = Registry.ClassesRoot.OpenSubKey("http\\shell\\open\\command");
				if (registryKey != null)
				{
					string text = (string)registryKey.GetValue(string.Empty);
					if (text != null)
					{
						text = text.Trim();
						if (text.Length != 0)
						{
							if (text[0] == '"')
							{
								int num = text.IndexOf('"', 1);
								if (num != -1)
								{
									result = text.Substring(1, num - 1);
								}
							}
							else
							{
								int num2 = text.IndexOf(' ');
								result = ((num2 == -1) ? text : text.Substring(0, num2));
							}
						}
					}
				}
				return result;
			}
		}

		public UserInterface(bool wait)
		{
			_splashInfo = new SplashInfo();
			_splashInfo.initializedAsWait = wait;
			_uiThread = new Thread(UIThread);
			_uiThread.Name = "UIThread";
			_uiThread.Start();
		}

		public UserInterface()
			: this(wait: true)
		{
		}

		public void Dispose()
		{
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		public ProgressPiece ShowProgress(UserInterfaceInfo info)
		{
			WaitReady();
			return (ProgressPiece)_uiForm.Invoke(new UserInterfaceForm.ConstructProgressPieceDelegate(_uiForm.ConstructProgressPiece), info);
		}

		public UserInterfaceModalResult ShowUpdate(UserInterfaceInfo info)
		{
			WaitReady();
			ManualResetEvent manualResetEvent = new ManualResetEvent(initialState: false);
			UpdatePiece updatePiece = (UpdatePiece)_uiForm.Invoke(new UserInterfaceForm.ConstructUpdatePieceDelegate(_uiForm.ConstructUpdatePiece), info, manualResetEvent);
			manualResetEvent.WaitOne();
			return updatePiece.ModalResult;
		}

		public UserInterfaceModalResult ShowMaintenance(UserInterfaceInfo info, MaintenanceInfo maintenanceInfo)
		{
			WaitReady();
			ManualResetEvent manualResetEvent = new ManualResetEvent(initialState: false);
			MaintenancePiece maintenancePiece = (MaintenancePiece)_uiForm.Invoke(new UserInterfaceForm.ConstructMaintenancePieceDelegate(_uiForm.ConstructMaintenancePiece), info, maintenanceInfo, manualResetEvent);
			manualResetEvent.WaitOne();
			return maintenancePiece.ModalResult;
		}

		public void ShowMessage(string message, string caption)
		{
			WaitReady();
			_uiForm.Invoke(new UserInterfaceForm.ShowSimpleMessageBoxDelegate(_uiForm.ShowSimpleMessageBox), message, caption);
		}

		public void ShowPlatform(string platformDetectionErrorMsg, Uri supportUrl)
		{
			WaitReady();
			ManualResetEvent manualResetEvent = new ManualResetEvent(initialState: false);
			_uiForm.BeginInvoke(new UserInterfaceForm.ConstructPlatformPieceDelegate(_uiForm.ConstructPlatformPiece), platformDetectionErrorMsg, supportUrl, manualResetEvent);
			manualResetEvent.WaitOne();
		}

		public void ShowError(string title, string message, string logFileLocation, string linkUrl, string linkUrlMessage)
		{
			WaitReady();
			ManualResetEvent manualResetEvent = new ManualResetEvent(initialState: false);
			_uiForm.BeginInvoke(new UserInterfaceForm.ConstructErrorPieceDelegate(_uiForm.ConstructErrorPiece), title, message, logFileLocation, linkUrl, linkUrlMessage, manualResetEvent);
			manualResetEvent.WaitOne();
		}

		public void Hide()
		{
			WaitReady();
			_uiForm.BeginInvoke(new MethodInvoker(_uiForm.Hide));
		}

		public void Activate()
		{
			WaitReady();
			_uiForm.BeginInvoke(new MethodInvoker(_uiForm.Activate));
		}

		public bool SplashCancelled()
		{
			return _splashInfo.cancelled;
		}

		private void WaitReady()
		{
			_uiConstructed.WaitOne();
			_uiReady.WaitOne();
			_splashInfo.pieceReady.WaitOne();
		}

		private void UIThread()
		{
			System.Windows.Forms.Application.EnableVisualStyles();
			System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(defaultValue: false);
			using (_uiForm = new UserInterfaceForm(_uiReady, _splashInfo))
			{
				_uiConstructed.Set();
				_appctx = new ApplicationContext(_uiForm);
				System.Windows.Forms.Application.Run(_appctx);
				_appctxExitThreadFinished.WaitOne();
				System.Windows.Forms.Application.ExitThread();
			}
		}

		private void Dispose(bool disposing)
		{
			if (!_disposed)
			{
				if (disposing)
				{
					WaitReady();
					_appctx.ExitThread();
					_appctxExitThreadFinished.Set();
				}
				_disposed = true;
			}
		}

		public static string GetDisplaySite(Uri sourceUri)
		{
			string result = null;
			if (sourceUri.IsUnc)
			{
				try
				{
					result = Path.GetDirectoryName(sourceUri.LocalPath);
					return result;
				}
				catch (ArgumentException)
				{
					return result;
				}
			}
			result = sourceUri.Host;
			if (string.IsNullOrEmpty(result))
			{
				try
				{
					result = Path.GetDirectoryName(sourceUri.LocalPath);
					return result;
				}
				catch (ArgumentException)
				{
					return result;
				}
			}
			return result;
		}

		public static string LimitDisplayTextLength(string displayText)
		{
			if (displayText.Length > 50)
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.Append(displayText, 0, 47);
				stringBuilder.Append("...");
				return stringBuilder.ToString();
			}
			return displayText;
		}

		public static bool IsValidHttpUrl(string url)
		{
			bool result = false;
			if (url != null && url.Length > 0 && (url.StartsWith(Uri.UriSchemeHttp + Uri.SchemeDelimiter, StringComparison.Ordinal) || url.StartsWith(Uri.UriSchemeHttps + Uri.SchemeDelimiter, StringComparison.Ordinal)))
			{
				result = true;
			}
			return result;
		}

		public static void LaunchUrlInBrowser(string url)
		{
			try
			{
				Process.Start(DefaultBrowserExePath, url);
			}
			catch (Win32Exception)
			{
			}
		}
	}
	internal class UserInterfaceForm : Form
	{
		public delegate ProgressPiece ConstructProgressPieceDelegate(UserInterfaceInfo info);

		public delegate UpdatePiece ConstructUpdatePieceDelegate(UserInterfaceInfo info, ManualResetEvent modalEvent);

		public delegate ErrorPiece ConstructErrorPieceDelegate(string title, string message, string logFileLocation, string linkUrl, string linkUrlMessage, ManualResetEvent modalEvent);

		public delegate PlatformPiece ConstructPlatformPieceDelegate(string platformDetectionErrorMsg, Uri supportUrl, ManualResetEvent modalEvent);

		public delegate MaintenancePiece ConstructMaintenancePieceDelegate(UserInterfaceInfo info, MaintenanceInfo maintenanceInfo, ManualResetEvent modalEvent);

		public delegate void ShowSimpleMessageBoxDelegate(string messsage, string caption);

		private FormPiece currentPiece;

		private SplashInfo splashPieceInfo;

		private ManualResetEvent onLoadEvent;

		public UserInterfaceForm(ManualResetEvent readyEvent, SplashInfo splashInfo)
		{
			onLoadEvent = readyEvent;
			splashPieceInfo = splashInfo;
			SuspendLayout();
			InitializeComponent();
			InitializeContent();
			ResumeLayout(performLayout: false);
			PerformLayout();
		}

		public ProgressPiece ConstructProgressPiece(UserInterfaceInfo info)
		{
			return new ProgressPiece(this, info);
		}

		public UpdatePiece ConstructUpdatePiece(UserInterfaceInfo info, ManualResetEvent modalEvent)
		{
			return new UpdatePiece(this, info, modalEvent);
		}

		public ErrorPiece ConstructErrorPiece(string title, string message, string logFileLocation, string linkUrl, string linkUrlMessage, ManualResetEvent modalEvent)
		{
			return new ErrorPiece(this, title, message, logFileLocation, linkUrl, linkUrlMessage, modalEvent);
		}

		public PlatformPiece ConstructPlatformPiece(string platformDetectionErrorMsg, Uri supportUrl, ManualResetEvent modalEvent)
		{
			return new PlatformPiece(this, platformDetectionErrorMsg, supportUrl, modalEvent);
		}

		public MaintenancePiece ConstructMaintenancePiece(UserInterfaceInfo info, MaintenanceInfo maintenanceInfo, ManualResetEvent modalEvent)
		{
			return new MaintenancePiece(this, info, maintenanceInfo, modalEvent);
		}

		public void ShowSimpleMessageBox(string message, string caption)
		{
			MessageBoxOptions messageBoxOptions = (MessageBoxOptions)0;
			if (IsRightToLeft(this))
			{
				messageBoxOptions |= MessageBoxOptions.RightAlign | MessageBoxOptions.RtlReading;
			}
			MessageBox.Show(this, message, caption, MessageBoxButtons.OK, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1, messageBoxOptions);
		}

		public void SwitchUserInterfacePiece(FormPiece piece)
		{
			FormPiece formPiece = null;
			formPiece = currentPiece;
			currentPiece = piece;
			currentPiece.Dock = DockStyle.Fill;
			SuspendLayout();
			base.Controls.Add(currentPiece);
			if (formPiece != null)
			{
				base.Controls.Remove(formPiece);
				formPiece.Dispose();
			}
			base.ClientSize = currentPiece.ClientSize;
			ResumeLayout(performLayout: false);
			PerformLayout();
		}

		protected override void OnLoad(EventArgs e)
		{
			base.OnLoad(e);
			onLoadEvent.Set();
		}

		protected override void OnVisibleChanged(EventArgs e)
		{
			base.OnVisibleChanged(e);
			if (base.Visible && Form.ActiveForm != this)
			{
				Activate();
			}
		}

		protected override void OnClosing(CancelEventArgs e)
		{
			base.OnClosing(e);
			if (!currentPiece.OnClosing())
			{
				e.Cancel = true;
				return;
			}
			e.Cancel = true;
			Hide();
		}

		protected override void SetVisibleCore(bool value)
		{
			if (splashPieceInfo.initializedAsWait)
			{
				base.SetVisibleCore(value: false);
			}
			else
			{
				base.SetVisibleCore(value);
			}
		}

		protected override void Dispose(bool disposing)
		{
			base.Dispose(disposing);
			if (disposing)
			{
				base.Icon.Dispose();
				base.Icon = null;
				if (currentPiece != null)
				{
					currentPiece.Dispose();
				}
			}
		}

		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(System.Deployment.Application.UserInterfaceForm));
			base.SuspendLayout();
			resources.ApplyResources(this, "$this");
			base.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			base.ControlBox = false;
			base.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			base.MaximizeBox = false;
			base.MinimizeBox = false;
			base.Name = "UserInterfaceForm";
			base.ShowIcon = false;
			base.ResumeLayout(false);
		}

		private void InitializeContent()
		{
			base.Icon = Resources.GetIcon("form.ico");
			Font = SystemFonts.MessageBoxFont;
			currentPiece = new SplashPiece(this, splashPieceInfo);
			base.Controls.Add(currentPiece);
		}

		private bool IsRightToLeft(Control control)
		{
			if (control.RightToLeft == RightToLeft.Yes)
			{
				return true;
			}
			if (control.RightToLeft == RightToLeft.No)
			{
				return false;
			}
			if (control.RightToLeft == RightToLeft.Inherit && control.Parent != null)
			{
				return IsRightToLeft(control.Parent);
			}
			return false;
		}
	}
	internal enum UserInterfaceModalResult
	{
		Unknown,
		Ok,
		Cancel,
		Skip
	}
	internal class UserInterfaceInfo
	{
		public string formTitle;

		public string productName;

		public string sourceSite;

		public string supportUrl;

		public string iconFilePath;
	}
	internal class SplashInfo
	{
		public bool initializedAsWait = true;

		public ManualResetEvent pieceReady = new ManualResetEvent(initialState: true);

		public bool cancelled;
	}
	internal static class DFServiceEntryPoint
	{
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		internal delegate IManagedDeploymentServiceCom CreateDeploymentServiceComDelegate();

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		private delegate int RegisterDeploymentServiceComDelegate([MarshalAs(UnmanagedType.FunctionPtr)] CreateDeploymentServiceComDelegate createDeploymentServiceComDelegate);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		private delegate int UnregisterDeploymentServiceComDelegate();

		private class DfsvcForm : Form
		{
			public delegate void CloseFormDelegate(bool lifetimeManagerAlreadyTerminated);

			private Container components;

			private bool _lifetimeManagerTerminated;

			private bool _formClosed;

			public DfsvcForm()
			{
				InitializeComponent();
			}

			protected override void Dispose(bool disposing)
			{
				if (disposing && components != null)
				{
					components.Dispose();
				}
				base.Dispose(disposing);
			}

			private void InitializeComponent()
			{
				base.ClientSize = new System.Drawing.Size(292, 266);
				base.ShowInTaskbar = false;
				base.WindowState = System.Windows.Forms.FormWindowState.Minimized;
				base.TopMost = true;
				base.Closing += new System.ComponentModel.CancelEventHandler(DfsvcForm_Closing);
				base.Closed += new System.EventHandler(DfsvcForm_Closed);
			}

			private void DfsvcForm_Closing(object sender, CancelEventArgs e)
			{
				e.Cancel = false;
				TerminateLifetimeManager(formAlreadyClosed: true);
			}

			private void DfsvcForm_Closed(object sender, EventArgs e)
			{
				TerminateLifetimeManager(formAlreadyClosed: true);
			}

			public void SessionEndedEventHandler(object sender, SessionEndedEventArgs e)
			{
				TerminateLifetimeManager(formAlreadyClosed: false);
			}

			public void SessionEndingEventHandler(object sender, SessionEndingEventArgs e)
			{
				e.Cancel = false;
				TerminateLifetimeManager(formAlreadyClosed: false);
			}

			public void CloseForm(bool lifetimeManagerAlreadyTerminated)
			{
				if (_formClosed)
				{
					return;
				}
				lock (this)
				{
					if (lifetimeManagerAlreadyTerminated)
					{
						_lifetimeManagerTerminated = true;
					}
					if (!_formClosed)
					{
						_formClosed = true;
						Close();
					}
				}
			}

			private void TerminateLifetimeManager(bool formAlreadyClosed)
			{
				if (_lifetimeManagerTerminated)
				{
					return;
				}
				lock (this)
				{
					if (formAlreadyClosed)
					{
						_formClosed = true;
					}
					if (!_lifetimeManagerTerminated)
					{
						_lifetimeManagerTerminated = true;
						LifetimeManager.EndImmediately();
					}
				}
			}
		}

		private static CreateDeploymentServiceComDelegate s_createDeploymentServiceComDelegate;

		private static RegisterDeploymentServiceComDelegate RegisterDeploymentServiceCom;

		private static UnregisterDeploymentServiceComDelegate UnregisterDeploymentServiceCom;

		private static IntPtr DfdllHandle;

		private static DfsvcForm _dfsvcForm;

		[CompilerGenerated]
		private static CreateDeploymentServiceComDelegate _003C_003E9__CachedAnonymousMethodDelegate1;

		private static void MessageLoopThread()
		{
			if (_dfsvcForm == null)
			{
				_dfsvcForm = new DfsvcForm();
				SystemEvents.SessionEnded += _dfsvcForm.SessionEndedEventHandler;
				SystemEvents.SessionEnding += _dfsvcForm.SessionEndingEventHandler;
				System.Windows.Forms.Application.Run(_dfsvcForm);
			}
		}

		private static object GetMethodDelegate(IntPtr handle, string methodName, Type methodDelegateType)
		{
			IntPtr procAddress = NativeMethods.GetProcAddress(handle, methodName);
			if (procAddress == IntPtr.Zero)
			{
				throw new Win32Exception(Marshal.GetLastWin32Error());
			}
			return Marshal.GetDelegateForFunctionPointer(procAddress, methodDelegateType);
		}

		private static void ObtainDfdllExports()
		{
			DfdllHandle = NativeMethods.LoadLibrary(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "dfdll.dll"));
			if (DfdllHandle == IntPtr.Zero)
			{
				throw new Win32Exception(Marshal.GetLastWin32Error());
			}
			RegisterDeploymentServiceCom = (RegisterDeploymentServiceComDelegate)GetMethodDelegate(DfdllHandle, "RegisterDeploymentServiceCom", typeof(RegisterDeploymentServiceComDelegate));
			UnregisterDeploymentServiceCom = (UnregisterDeploymentServiceComDelegate)GetMethodDelegate(DfdllHandle, "UnregisterDeploymentServiceCom", typeof(UnregisterDeploymentServiceComDelegate));
		}

		public static void Initialize(string[] args)
		{
			CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfNewTaskBegin);
			if (PlatformSpecific.OnWin9x)
			{
				Thread thread = new Thread(MessageLoopThread);
				thread.Start();
			}
			ObtainDfdllExports();
			s_createDeploymentServiceComDelegate = () => new DeploymentServiceComWrapper();
			int num = RegisterDeploymentServiceCom(s_createDeploymentServiceComDelegate);
			if (num < 0)
			{
				throw Marshal.GetExceptionForHR(num);
			}
			CodeMarker_Singleton.Instance.CodeMarker(CodeMarkerEvent.perfNewTaskEnd);
			bool flag = LifetimeManager.WaitForEnd();
			if (_dfsvcForm != null)
			{
				_dfsvcForm.Invoke(new DfsvcForm.CloseFormDelegate(_dfsvcForm.CloseForm), true);
			}
			UnregisterDeploymentServiceCom();
			if (!flag && PlatformSpecific.OnWin9x)
			{
				Thread.Sleep(5000);
			}
			CodeMarker_Singleton.Instance.UninitializePerformanceDLL(CodeMarkerApp.CLICKONCEPERF);
			Environment.Exit(0);
		}
	}
	internal static class CodeMarker_Singleton
	{
		private static CodeMarkers codemarkers = null;

		private static object syncObject = new object();

		public static CodeMarkers Instance
		{
			get
			{
				if (codemarkers == null)
				{
					lock (syncObject)
					{
						if (codemarkers == null)
						{
							CodeMarkers instance = CodeMarkers.Instance;
							instance.InitPerformanceDll(CodeMarkerApp.CLICKONCEPERF, "Software\\Microsoft\\VisualStudio\\8.0");
							Thread.MemoryBarrier();
							codemarkers = instance;
						}
					}
				}
				return codemarkers;
			}
		}
	}
	internal static class PathTwiddler
	{
		private static object _invalidFileDirNameChars;

		private static char[] InvalidFileDirNameChars
		{
			get
			{
				if (_invalidFileDirNameChars == null)
				{
					Interlocked.CompareExchange(ref _invalidFileDirNameChars, Path.GetInvalidFileNameChars(), null);
				}
				return (char[])_invalidFileDirNameChars;
			}
		}

		public static string FilterString(string input, char chReplace, bool fMultiReplace)
		{
			return FilterString(input, InvalidFileDirNameChars, chReplace, fMultiReplace);
		}

		private static string FilterString(string input, char[] toFilter, char chReplacement, bool fMultiReplace)
		{
			int num = 0;
			bool flag = false;
			bool flag2 = false;
			if (input == null)
			{
				return null;
			}
			char[] array = input.ToCharArray();
			char[] array2 = new char[array.Length];
			Array.Sort(toFilter);
			for (int i = 0; i < array.Length; i++)
			{
				int num2 = Array.BinarySearch(toFilter, array[i]);
				if (num2 < 0)
				{
					array2[num++] = array[i];
					flag2 = true;
					if (flag)
					{
						flag = false;
					}
				}
				else if (fMultiReplace || !flag)
				{
					array2[num++] = chReplacement;
					flag = true;
				}
			}
			if (!flag2 || num <= 0)
			{
				return null;
			}
			return new string(array2, 0, num);
		}
	}
	internal static class PathHelper
	{
		private const int MAX_PATH = 260;

		private const int ERROR_FILE_NOT_FOUND = 2;

		private const int ERROR_INVALID_PARAMETER = 87;

		private static object _shortShimDllPath;

		public static string ShortShimDllPath
		{
			get
			{
				if (_shortShimDllPath == null)
				{
					string longPath = Path.Combine(Environment.SystemDirectory, "dfshim.dll");
					Interlocked.CompareExchange(ref _shortShimDllPath, GetShortPath(longPath), null);
				}
				return (string)_shortShimDllPath;
			}
		}

		public static string GetShortPath(string longPath)
		{
			StringBuilder stringBuilder = new StringBuilder(260);
			int shortPathName = NativeMethods.GetShortPathName(longPath, stringBuilder, stringBuilder.Capacity);
			if (shortPathName == 0)
			{
				GetShortPathNameThrowExceptionForLastError(longPath);
			}
			if (shortPathName >= stringBuilder.Capacity)
			{
				stringBuilder.Capacity = shortPathName + 1;
				if (NativeMethods.GetShortPathName(longPath, stringBuilder, stringBuilder.Capacity) == 0)
				{
					GetShortPathNameThrowExceptionForLastError(longPath);
				}
			}
			return stringBuilder.ToString();
		}

		public static string GenerateRandomPath(uint segmentCount)
		{
			if (segmentCount == 0)
			{
				return null;
			}
			uint num = 11 * segmentCount;
			uint num2 = (uint)Math.Ceiling((double)num * 0.625);
			byte[] array = new byte[num2];
			RNGCryptoServiceProvider rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
			rNGCryptoServiceProvider.GetBytes(array);
			string text = Base32String.FromBytes(array);
			if (text.Length < num)
			{
				throw new DeploymentException(Resources.GetString("Ex_TempPathRandomStringTooShort"));
			}
			if (text.IndexOf('\\') >= 0)
			{
				throw new DeploymentException(Resources.GetString("Ex_TempPathRandomStringInvalid"));
			}
			for (int num3 = (int)(segmentCount - 1); num3 > 0; num3--)
			{
				int num4 = num3 * 11;
				if (num4 >= text.Length)
				{
					throw new DeploymentException(Resources.GetString("Ex_TempPathRandomStringInvalid"));
				}
				text = text.Insert(num4, "\\");
			}
			string[] array2 = text.Split('\\');
			if (array2.Length < segmentCount)
			{
				throw new DeploymentException(Resources.GetString("Ex_TempPathRandomStringInvalid"));
			}
			string text2 = null;
			for (uint num5 = 0u; num5 < segmentCount; num5++)
			{
				if (array2[num5].Length < 11)
				{
					throw new DeploymentException(Resources.GetString("Ex_TempPathRandomStringInvalid"));
				}
				string text3 = array2[num5].Substring(0, 11);
				text3 = text3.Insert(8, ".");
				text2 = ((text2 != null) ? Path.Combine(text2, text3) : text3);
			}
			return text2;
		}

		public static string GetRootSegmentPath(string path, uint segmentCount)
		{
			return segmentCount switch
			{
				0u => throw new ArgumentException("segmentCount"), 
				1u => path, 
				_ => GetRootSegmentPath(Path.GetDirectoryName(path), segmentCount - 1), 
			};
		}

		private static void GetShortPathNameThrowExceptionForLastError(string path)
		{
			int lastWin32Error = Marshal.GetLastWin32Error();
			switch (lastWin32Error)
			{
			case 2:
				throw new FileNotFoundException(path);
			case 87:
				throw new InvalidOperationException(Resources.GetString("Ex_ShortFileNameNotSupported"));
			default:
				throw new Win32Exception(lastWin32Error);
			}
		}
	}
	internal static class HexString
	{
		public static string FromBytes(byte[] bytes)
		{
			StringBuilder stringBuilder = new StringBuilder(bytes.Length * 2);
			for (int i = 0; i < bytes.Length; i++)
			{
				stringBuilder.AppendFormat(CultureInfo.InvariantCulture, "{0:x2}", bytes[i]);
			}
			return stringBuilder.ToString();
		}
	}
	internal class Base32String
	{
		protected static char[] charList = new char[32]
		{
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'A', 'B', 'C', 'D', 'E', 'G', 'H', 'J', 'K', 'L',
			'M', 'N', 'O', 'P', 'Q', 'R', 'T', 'V', 'W', 'X',
			'Y', 'Z'
		};

		public static string FromBytes(byte[] bytes)
		{
			int num = bytes.Length;
			if (num <= 0)
			{
				return null;
			}
			int num2 = num << 3;
			int num3 = num2 / 5 << 3;
			if (num2 % 5 != 0)
			{
				num3 += 8;
			}
			int capacity = num3 >> 3;
			StringBuilder stringBuilder = new StringBuilder(capacity);
			int num4 = 0;
			int num5 = 0;
			int num6 = 0;
			for (num4 = 0; num4 < num; num4++)
			{
				num6 = (num6 << 8) | bytes[num4];
				num5 += 8;
				while (num5 >= 5)
				{
					num5 -= 5;
					stringBuilder.Append(charList[(num6 >> num5) & 0x1F]);
				}
			}
			if (num5 > 0)
			{
				stringBuilder.Append(charList[(num6 << 5 - num5) & 0x1F]);
			}
			return stringBuilder.ToString();
		}
	}
	internal static class Resources
	{
		private static object lockObject = new object();

		private static ResourceManager _resources = null;

		private static Assembly _assembly = null;

		public static string GetString(string s)
		{
			if (_resources == null)
			{
				lock (lockObject)
				{
					if (_resources == null)
					{
						InitializeReferenceToAssembly();
						_resources = new ResourceManager("System.Deployment", _assembly);
					}
				}
			}
			return _resources.GetString(s);
		}

		public static Image GetImage(string imageName)
		{
			InitializeReferenceToAssembly();
			Stream stream = null;
			try
			{
				stream = _assembly.GetManifestResourceStream(imageName);
				return Image.FromStream(stream);
			}
			catch
			{
				stream?.Close();
				throw;
			}
		}

		public static Icon GetIcon(string iconName)
		{
			InitializeReferenceToAssembly();
			using Stream stream = _assembly.GetManifestResourceStream(iconName);
			return new Icon(stream);
		}

		private static void InitializeReferenceToAssembly()
		{
			if (_assembly != null)
			{
				return;
			}
			lock (lockObject)
			{
				if (_assembly == null)
				{
					_assembly = Assembly.GetExecutingAssembly();
				}
			}
		}
	}
	internal static class Utilities
	{
		public static int CompareWithNullEqEmpty(string s1, string s2, StringComparison comparisonType)
		{
			if (string.IsNullOrEmpty(s1) && string.IsNullOrEmpty(s2))
			{
				return 0;
			}
			return string.Compare(s1, s2, comparisonType);
		}
	}
	internal static class PolicyKeys
	{
		public enum HostType
		{
			Default,
			AppLaunch,
			Cor
		}

		public static bool RequireSignedManifests()
		{
			if (CheckDeploymentBoolString("RequireSignedManifests", compare: true, defaultIfNotSet: false))
			{
				return true;
			}
			return false;
		}

		public static bool RequireHashInManifests()
		{
			if (CheckDeploymentBoolString("RequireHashInManifests", compare: true, defaultIfNotSet: false))
			{
				return true;
			}
			return false;
		}

		public static bool SkipDeploymentProvider()
		{
			if (CheckDeploymentBoolString("SkipDeploymentProvider", compare: true, defaultIfNotSet: false))
			{
				Logger.AddWarningInformation(Resources.GetString("SkipDeploymentProvider"));
				return true;
			}
			return false;
		}

		public static bool SkipApplicationDependencyHashCheck()
		{
			if (CheckDeploymentBoolString("SkipApplicationDependencyHashCheck", compare: true, defaultIfNotSet: false))
			{
				Logger.AddWarningInformation(Resources.GetString("SkipApplicationDependencyHashCheck"));
				return true;
			}
			return false;
		}

		public static bool SkipSignatureValidation()
		{
			if (CheckDeploymentBoolString("SkipSignatureValidation", compare: true, defaultIfNotSet: false))
			{
				Logger.AddWarningInformation(Resources.GetString("SkipAllSigValidation"));
				return true;
			}
			return false;
		}

		public static bool SkipSchemaValidation()
		{
			if (CheckDeploymentBoolString("SkipSchemaValidation", compare: true, defaultIfNotSet: false))
			{
				Logger.AddWarningInformation(Resources.GetString("SkipSchemaValidation"));
				return true;
			}
			return false;
		}

		public static bool SkipSemanticValidation()
		{
			if (CheckDeploymentBoolString("SkipSemanticValidation", compare: true, defaultIfNotSet: false))
			{
				Logger.AddWarningInformation(Resources.GetString("SkipAllSemanticValidation"));
				return true;
			}
			return false;
		}

		public static bool SuppressLimitOnNumberOfActivations()
		{
			if (CheckDeploymentBoolString("SuppressLimitOnNumberOfActivations", compare: true, defaultIfNotSet: false))
			{
				Logger.AddWarningInformation(Resources.GetString("SuppressLimitOnNumberOfActivations"));
				return true;
			}
			return false;
		}

		public static bool DisableGenericExceptionHandler()
		{
			if (CheckDeploymentBoolString("DisableGenericExceptionHandler", compare: true, defaultIfNotSet: false))
			{
				Logger.AddWarningInformation(Resources.GetString("DisableGenericExceptionHandler"));
				return true;
			}
			return false;
		}

		public static HostType ClrHostType()
		{
			int num = 0;
			using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\.NETFramework\\DeploymentFramework", writable: false))
			{
				if (registryKey != null)
				{
					object value = registryKey.GetValue("ClickOnceHost");
					num = ((value != null) ? ((int)value) : 0);
				}
			}
			switch (num)
			{
			case 1:
				Logger.AddWarningInformation(Resources.GetString("ForceAppLaunch"));
				break;
			case 2:
				Logger.AddWarningInformation(Resources.GetString("ForceCor"));
				break;
			}
			return (HostType)num;
		}

		private static bool CheckDeploymentBoolString(string keyName, bool compare, bool defaultIfNotSet)
		{
			bool flag = false;
			bool flag2 = false;
			using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\.NETFramework\\DeploymentFramework", writable: false))
			{
				if (registryKey != null && registryKey.GetValue(keyName) is string @string)
				{
					flag2 = true;
					CompareInfo compareInfo = CultureInfo.InvariantCulture.CompareInfo;
					if (compareInfo.Compare(@string, "true", CompareOptions.IgnoreCase) == 0)
					{
						flag = true;
					}
					else if (compareInfo.Compare(@string, "false", CompareOptions.IgnoreCase) == 0)
					{
						flag = false;
					}
				}
			}
			if (!flag2)
			{
				return defaultIfNotSet;
			}
			return flag == compare;
		}

		public static bool SkipSKUDetection()
		{
			bool result = false;
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Fusion", writable: false);
				if (registryKey != null)
				{
					object value = registryKey.GetValue("NoClientChecks");
					if (value != null)
					{
						if (Convert.ToUInt32(value) != 0)
						{
							Logger.AddWarningInformation(Resources.GetString("SkippedSKUDetection"));
							return true;
						}
						return result;
					}
					return result;
				}
				return result;
			}
			catch (OverflowException)
			{
				return false;
			}
			catch (InvalidCastException)
			{
				return false;
			}
			catch (IOException)
			{
				return false;
			}
		}
	}
}
namespace System.Deployment.Application.Win32InterOp
{
	internal class SystemUtils
	{
		private enum RUNTIME_INFO_FLAGS : uint
		{
			RUNTIME_INFO_UPGRADE_VERSION = 1u,
			RUNTIME_INFO_REQUEST_IA64 = 2u,
			RUNTIME_INFO_REQUEST_AMD64 = 4u,
			RUNTIME_INFO_REQUEST_X86 = 8u,
			RUNTIME_INFO_DONT_RETURN_DIRECTORY = 0x10u,
			RUNTIME_INFO_DONT_RETURN_VERSION = 0x20u,
			RUNTIME_INFO_DONT_SHOW_ERROR_DIALOG = 0x40u
		}

		internal enum AssemblyInfoFlags
		{
			Installed = 1,
			PayLoadResident
		}

		[Flags]
		internal enum QueryAssemblyInfoFlags
		{
			Validate = 1,
			GetSize = 2,
			GetCurrentPath = 4,
			All = 7
		}

		internal class AssemblyInfo
		{
			private int assemblyInfoSizeInByte;

			private AssemblyInfoFlags assemblyFlags;

			private long assemblySizeInKB;

			private string currentAssemblyPath;

			internal int AssemblyInfoSizeInByte
			{
				set
				{
					assemblyInfoSizeInByte = value;
				}
			}

			internal AssemblyInfoFlags AssemblyFlags
			{
				set
				{
					assemblyFlags = value;
				}
			}

			internal long AssemblySizeInKB
			{
				set
				{
					assemblySizeInKB = value;
				}
			}

			internal string CurrentAssemblyPath
			{
				set
				{
					currentAssemblyPath = value;
				}
			}
		}

		private const int MAX_CLR_VERSION_LENGTH = 24;

		public static byte[] GetManifestFromPEResources(string filePath)
		{
			IntPtr zero = IntPtr.Zero;
			IntPtr intPtr = IntPtr.Zero;
			IntPtr zero2 = IntPtr.Zero;
			IntPtr zero3 = IntPtr.Zero;
			IntPtr hFile = new IntPtr(0);
			uint dwFlags = 2u;
			byte[] result = null;
			int num = 0;
			try
			{
				intPtr = NativeMethods.LoadLibraryEx(filePath, hFile, dwFlags);
				num = Marshal.GetLastWin32Error();
				if (intPtr == IntPtr.Zero)
				{
					Win32LoadExceptionHelper(num, "Ex_Win32LoadException", filePath);
				}
				zero = NativeMethods.FindResource(intPtr, "#1", "#24");
				if (zero != IntPtr.Zero)
				{
					uint num2 = NativeMethods.SizeofResource(intPtr, zero);
					num = Marshal.GetLastWin32Error();
					if (num2 == 0)
					{
						Win32LoadExceptionHelper(num, "Ex_Win32ResourceLoadException", filePath);
					}
					zero2 = NativeMethods.LoadResource(intPtr, zero);
					num = Marshal.GetLastWin32Error();
					if (zero2 == IntPtr.Zero)
					{
						Win32LoadExceptionHelper(num, "Ex_Win32ResourceLoadException", filePath);
					}
					zero3 = NativeMethods.LockResource(zero2);
					if (zero3 == IntPtr.Zero)
					{
						throw new Win32Exception(33);
					}
					result = new byte[num2];
					Marshal.Copy(zero3, result, 0, (int)num2);
					return result;
				}
				return result;
			}
			finally
			{
				if (intPtr != IntPtr.Zero)
				{
					bool flag = NativeMethods.FreeLibrary(intPtr);
					num = Marshal.GetLastWin32Error();
					if (!flag)
					{
						throw new Win32Exception(num);
					}
				}
			}
		}

		private static void Win32LoadExceptionHelper(int win32ErrorCode, string resourceId, string filePath)
		{
			string fileName = Path.GetFileName(filePath);
			string message = string.Format(CultureInfo.CurrentUICulture, Resources.GetString(resourceId), fileName, Convert.ToString(win32ErrorCode, 16));
			throw new Win32Exception(win32ErrorCode, message);
		}

		internal static AssemblyInfo QueryAssemblyInfo(QueryAssemblyInfoFlags flags, string assemblyName)
		{
			AssemblyInfo assemblyInfo = new AssemblyInfo();
			NativeMethods.AssemblyInfoInternal assemblyInfo2 = default(NativeMethods.AssemblyInfoInternal);
			if ((flags & QueryAssemblyInfoFlags.GetCurrentPath) != 0)
			{
				assemblyInfo2.cchBuf = 1024;
				assemblyInfo2.currentAssemblyPathBuf = Marshal.AllocHGlobal(assemblyInfo2.cchBuf * 2);
			}
			else
			{
				assemblyInfo2.cchBuf = 0;
				assemblyInfo2.currentAssemblyPathBuf = (IntPtr)0;
			}
			NativeMethods.IAssemblyCache ppAsmCache = null;
			NativeMethods.CreateAssemblyCache(out ppAsmCache, 0);
			try
			{
				ppAsmCache.QueryAssemblyInfo((int)flags, assemblyName, ref assemblyInfo2);
			}
			catch (FileNotFoundException)
			{
				assemblyInfo = null;
			}
			if (assemblyInfo != null)
			{
				assemblyInfo.AssemblyInfoSizeInByte = assemblyInfo2.cbAssemblyInfo;
				assemblyInfo.AssemblyFlags = (AssemblyInfoFlags)assemblyInfo2.assemblyFlags;
				assemblyInfo.AssemblySizeInKB = assemblyInfo2.assemblySizeInKB;
				if ((flags & QueryAssemblyInfoFlags.GetCurrentPath) != 0)
				{
					assemblyInfo.CurrentAssemblyPath = Marshal.PtrToStringUni(assemblyInfo2.currentAssemblyPathBuf);
					Marshal.FreeHGlobal(assemblyInfo2.currentAssemblyPathBuf);
				}
			}
			return assemblyInfo;
		}

		internal static DefinitionIdentity GetDefinitionIdentityFromManagedAssembly(string filePath)
		{
			Guid riid = System.Deployment.Internal.Isolation.IsolationInterop.GetGuidOfType(typeof(System.Deployment.Internal.Isolation.IReferenceIdentity));
			System.Deployment.Internal.Isolation.IReferenceIdentity idComPtr = (System.Deployment.Internal.Isolation.IReferenceIdentity)NativeMethods.GetAssemblyIdentityFromFile(filePath, ref riid);
			ReferenceIdentity referenceIdentity = new ReferenceIdentity(idComPtr);
			string processorArchitecture = referenceIdentity.ProcessorArchitecture;
			if (processorArchitecture != null)
			{
				referenceIdentity.ProcessorArchitecture = processorArchitecture.ToLower(CultureInfo.InvariantCulture);
			}
			return new DefinitionIdentity(referenceIdentity);
		}

		internal static void CheckSupportedImageAndCLRVersions(string path)
		{
			StringBuilder stringBuilder = new StringBuilder(24);
			uint dwLength;
			try
			{
				NativeMethods.GetFileVersion(path, stringBuilder, (uint)stringBuilder.Capacity, out dwLength);
			}
			catch (BadImageFormatException)
			{
				throw;
			}
			if (stringBuilder[0] != 'v')
			{
				throw new InvalidDeploymentException(ExceptionTypes.ClrValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidCLRVersionInFile"), stringBuilder, Path.GetFileName(path)));
			}
			Version version = new Version(stringBuilder.ToString(1, stringBuilder.Length - 1));
			if ((long)version.Major < 2L)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ClrValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_ImageVersionCLRNotSupported"), version, Path.GetFileName(path)));
			}
			uint runtimeInfoFlags = 81u;
			NativeMethods.GetRequestedRuntimeInfo(path, null, null, 0u, runtimeInfoFlags, null, 0u, out var _, stringBuilder, (uint)stringBuilder.Capacity, out dwLength);
			if (stringBuilder[0] != 'v')
			{
				throw new FormatException(string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_InvalidCLRVersionInFile"), stringBuilder, Path.GetFileName(path)));
			}
			string text = stringBuilder.ToString(1, stringBuilder.Length - 1);
			int num = text.IndexOf(".", StringComparison.Ordinal);
			uint num2 = uint.Parse((num >= 0) ? text.Substring(0, num) : text, CultureInfo.InvariantCulture);
			if (num2 < 2)
			{
				throw new InvalidDeploymentException(ExceptionTypes.ClrValidation, string.Format(CultureInfo.CurrentUICulture, Resources.GetString("Ex_RuntimeVersionCLRNotSupported"), text, Path.GetFileName(path)));
			}
		}
	}
}
namespace System.Deployment.Internal.Isolation
{
	internal struct BLOB : IDisposable
	{
		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr BlobData;

		public void Dispose()
		{
			if (BlobData != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(BlobData);
				BlobData = IntPtr.Zero;
			}
		}
	}
	internal struct IDENTITY_ATTRIBUTE
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Namespace;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Value;
	}
	[Flags]
	internal enum STORE_ASSEMBLY_STATUS_FLAGS
	{
		STORE_ASSEMBLY_STATUS_MANIFEST_ONLY = 1,
		STORE_ASSEMBLY_STATUS_PAYLOAD_RESIDENT = 2,
		STORE_ASSEMBLY_STATUS_PARTIAL_INSTALL = 4
	}
	internal struct STORE_ASSEMBLY
	{
		public uint Status;

		public IDefinitionIdentity DefinitionIdentity;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ManifestPath;

		public ulong AssemblySize;

		public ulong ChangeId;
	}
	[Flags]
	internal enum STORE_ASSEMBLY_FILE_STATUS_FLAGS
	{
		STORE_ASSEMBLY_FILE_STATUS_FLAG_PRESENT = 1
	}
	internal struct STORE_ASSEMBLY_FILE
	{
		public uint Size;

		public uint Flags;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string FileName;

		public uint FileStatusFlags;
	}
	internal struct STORE_CATEGORY
	{
		public IDefinitionIdentity DefinitionIdentity;
	}
	internal struct STORE_CATEGORY_SUBCATEGORY
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Subcategory;
	}
	internal struct STORE_CATEGORY_INSTANCE
	{
		public IDefinitionAppId DefinitionAppId_Application;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string XMLSnippet;
	}
	internal struct CATEGORY
	{
		public IDefinitionIdentity DefinitionIdentity;
	}
	internal struct CATEGORY_SUBCATEGORY
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Subcategory;
	}
	internal struct CATEGORY_INSTANCE
	{
		public IDefinitionAppId DefinitionAppId_Application;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string XMLSnippet;
	}
	[ComImport]
	[Guid("d8b1aacb-5142-4abb-bcc1-e9dc9052a89e")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEnumSTORE_ASSEMBLY_INSTALLATION_REFERENCE
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] StoreApplicationReference[] rgelt);

		void Skip([In] uint celt);

		void Reset();

		IEnumSTORE_ASSEMBLY_INSTALLATION_REFERENCE Clone();
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("f9fd4090-93db-45c0-af87-624940f19cff")]
	internal interface IEnumSTORE_DEPLOYMENT_METADATA
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] IDefinitionAppId[] AppIds);

		void Skip([In] uint celt);

		void Reset();

		IEnumSTORE_DEPLOYMENT_METADATA Clone();
	}
	internal class StoreDeploymentMetadataEnumeration : IEnumerator
	{
		private IEnumSTORE_DEPLOYMENT_METADATA _enum;

		private bool _fValid;

		private IDefinitionAppId _current;

		object IEnumerator.Current => GetCurrent();

		public IDefinitionAppId Current => GetCurrent();

		public StoreDeploymentMetadataEnumeration(IEnumSTORE_DEPLOYMENT_METADATA pI)
		{
			_enum = pI;
		}

		private IDefinitionAppId GetCurrent()
		{
			if (!_fValid)
			{
				throw new InvalidOperationException();
			}
			return _current;
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		public bool MoveNext()
		{
			IDefinitionAppId[] array = new IDefinitionAppId[1];
			uint num = _enum.Next(1u, array);
			if (num == 1)
			{
				_current = array[0];
			}
			return _fValid = num == 1;
		}

		public void Reset()
		{
			_fValid = false;
			_enum.Reset();
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("5fa4f590-a416-4b22-ac79-7c3f0d31f303")]
	internal interface IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] StoreOperationMetadataProperty[] AppIds);

		void Skip([In] uint celt);

		void Reset();

		IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY Clone();
	}
	internal class StoreDeploymentMetadataPropertyEnumeration : IEnumerator
	{
		private IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY _enum;

		private bool _fValid;

		private StoreOperationMetadataProperty _current;

		object IEnumerator.Current => GetCurrent();

		public StoreOperationMetadataProperty Current => GetCurrent();

		public StoreDeploymentMetadataPropertyEnumeration(IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY pI)
		{
			_enum = pI;
		}

		private StoreOperationMetadataProperty GetCurrent()
		{
			if (!_fValid)
			{
				throw new InvalidOperationException();
			}
			return _current;
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		public bool MoveNext()
		{
			StoreOperationMetadataProperty[] array = new StoreOperationMetadataProperty[1];
			uint num = _enum.Next(1u, array);
			if (num == 1)
			{
				_current = array[0];
			}
			return _fValid = num == 1;
		}

		public void Reset()
		{
			_fValid = false;
			_enum.Reset();
		}
	}
	[ComImport]
	[Guid("a5c637bf-6eaa-4e5f-b535-55299657e33e")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEnumSTORE_ASSEMBLY
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] STORE_ASSEMBLY[] rgelt);

		void Skip([In] uint celt);

		void Reset();

		IEnumSTORE_ASSEMBLY Clone();
	}
	internal class StoreAssemblyEnumeration : IEnumerator
	{
		private IEnumSTORE_ASSEMBLY _enum;

		private bool _fValid;

		private STORE_ASSEMBLY _current;

		object IEnumerator.Current => GetCurrent();

		public STORE_ASSEMBLY Current => GetCurrent();

		public StoreAssemblyEnumeration(IEnumSTORE_ASSEMBLY pI)
		{
			_enum = pI;
		}

		private STORE_ASSEMBLY GetCurrent()
		{
			if (!_fValid)
			{
				throw new InvalidOperationException();
			}
			return _current;
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		public bool MoveNext()
		{
			STORE_ASSEMBLY[] array = new STORE_ASSEMBLY[1];
			uint num = _enum.Next(1u, array);
			if (num == 1)
			{
				_current = array[0];
			}
			return _fValid = num == 1;
		}

		public void Reset()
		{
			_fValid = false;
			_enum.Reset();
		}
	}
	[ComImport]
	[Guid("a5c6aaa3-03e4-478d-b9f5-2e45908d5e4f")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEnumSTORE_ASSEMBLY_FILE
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] STORE_ASSEMBLY_FILE[] rgelt);

		void Skip([In] uint celt);

		void Reset();

		IEnumSTORE_ASSEMBLY_FILE Clone();
	}
	internal class StoreAssemblyFileEnumeration : IEnumerator
	{
		private IEnumSTORE_ASSEMBLY_FILE _enum;

		private bool _fValid;

		private STORE_ASSEMBLY_FILE _current;

		object IEnumerator.Current => GetCurrent();

		public STORE_ASSEMBLY_FILE Current => GetCurrent();

		public StoreAssemblyFileEnumeration(IEnumSTORE_ASSEMBLY_FILE pI)
		{
			_enum = pI;
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		private STORE_ASSEMBLY_FILE GetCurrent()
		{
			if (!_fValid)
			{
				throw new InvalidOperationException();
			}
			return _current;
		}

		public bool MoveNext()
		{
			STORE_ASSEMBLY_FILE[] array = new STORE_ASSEMBLY_FILE[1];
			uint num = _enum.Next(1u, array);
			if (num == 1)
			{
				_current = array[0];
			}
			return _fValid = num == 1;
		}

		public void Reset()
		{
			_fValid = false;
			_enum.Reset();
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("b840a2f5-a497-4a6d-9038-cd3ec2fbd222")]
	internal interface IEnumSTORE_CATEGORY
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] STORE_CATEGORY[] rgElements);

		void Skip([In] uint ulElements);

		void Reset();

		IEnumSTORE_CATEGORY Clone();
	}
	internal class StoreCategoryEnumeration : IEnumerator
	{
		private IEnumSTORE_CATEGORY _enum;

		private bool _fValid;

		private STORE_CATEGORY _current;

		object IEnumerator.Current => GetCurrent();

		public STORE_CATEGORY Current => GetCurrent();

		public StoreCategoryEnumeration(IEnumSTORE_CATEGORY pI)
		{
			_enum = pI;
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		private STORE_CATEGORY GetCurrent()
		{
			if (!_fValid)
			{
				throw new InvalidOperationException();
			}
			return _current;
		}

		public bool MoveNext()
		{
			STORE_CATEGORY[] array = new STORE_CATEGORY[1];
			uint num = _enum.Next(1u, array);
			if (num == 1)
			{
				_current = array[0];
			}
			return _fValid = num == 1;
		}

		public void Reset()
		{
			_fValid = false;
			_enum.Reset();
		}
	}
	[ComImport]
	[Guid("19be1967-b2fc-4dc1-9627-f3cb6305d2a7")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEnumSTORE_CATEGORY_SUBCATEGORY
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] STORE_CATEGORY_SUBCATEGORY[] rgElements);

		void Skip([In] uint ulElements);

		void Reset();

		IEnumSTORE_CATEGORY_SUBCATEGORY Clone();
	}
	internal class StoreSubcategoryEnumeration : IEnumerator
	{
		private IEnumSTORE_CATEGORY_SUBCATEGORY _enum;

		private bool _fValid;

		private STORE_CATEGORY_SUBCATEGORY _current;

		object IEnumerator.Current => GetCurrent();

		public STORE_CATEGORY_SUBCATEGORY Current => GetCurrent();

		public StoreSubcategoryEnumeration(IEnumSTORE_CATEGORY_SUBCATEGORY pI)
		{
			_enum = pI;
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		private STORE_CATEGORY_SUBCATEGORY GetCurrent()
		{
			if (!_fValid)
			{
				throw new InvalidOperationException();
			}
			return _current;
		}

		public bool MoveNext()
		{
			STORE_CATEGORY_SUBCATEGORY[] array = new STORE_CATEGORY_SUBCATEGORY[1];
			uint num = _enum.Next(1u, array);
			if (num == 1)
			{
				_current = array[0];
			}
			return _fValid = num == 1;
		}

		public void Reset()
		{
			_fValid = false;
			_enum.Reset();
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("5ba7cb30-8508-4114-8c77-262fcda4fadb")]
	internal interface IEnumSTORE_CATEGORY_INSTANCE
	{
		uint Next([In] uint ulElements, [Out][MarshalAs(UnmanagedType.LPArray)] STORE_CATEGORY_INSTANCE[] rgInstances);

		void Skip([In] uint ulElements);

		void Reset();

		IEnumSTORE_CATEGORY_INSTANCE Clone();
	}
	internal class StoreCategoryInstanceEnumeration : IEnumerator
	{
		private IEnumSTORE_CATEGORY_INSTANCE _enum;

		private bool _fValid;

		private STORE_CATEGORY_INSTANCE _current;

		object IEnumerator.Current => GetCurrent();

		public STORE_CATEGORY_INSTANCE Current => GetCurrent();

		public StoreCategoryInstanceEnumeration(IEnumSTORE_CATEGORY_INSTANCE pI)
		{
			_enum = pI;
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		private STORE_CATEGORY_INSTANCE GetCurrent()
		{
			if (!_fValid)
			{
				throw new InvalidOperationException();
			}
			return _current;
		}

		public bool MoveNext()
		{
			STORE_CATEGORY_INSTANCE[] array = new STORE_CATEGORY_INSTANCE[1];
			uint num = _enum.Next(1u, array);
			if (num == 1)
			{
				_current = array[0];
			}
			return _fValid = num == 1;
		}

		public void Reset()
		{
			_fValid = false;
			_enum.Reset();
		}
	}
	internal sealed class ReferenceIdentity
	{
		internal IReferenceIdentity _id;

		internal ReferenceIdentity(IReferenceIdentity i)
		{
			if (i == null)
			{
				throw new ArgumentNullException();
			}
			_id = i;
		}

		private string GetAttribute(string ns, string n)
		{
			return _id.GetAttribute(ns, n);
		}

		private string GetAttribute(string n)
		{
			return _id.GetAttribute(null, n);
		}

		private void SetAttribute(string ns, string n, string v)
		{
			_id.SetAttribute(ns, n, v);
		}

		private void SetAttribute(string n, string v)
		{
			SetAttribute(null, n, v);
		}

		private void DeleteAttribute(string ns, string n)
		{
			SetAttribute(ns, n, null);
		}

		private void DeleteAttribute(string n)
		{
			SetAttribute(null, n, null);
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("6eaf5ace-7917-4f3c-b129-e046a9704766")]
	internal interface IReferenceIdentity
	{
		[return: MarshalAs(UnmanagedType.LPWStr)]
		string GetAttribute([In][MarshalAs(UnmanagedType.LPWStr)] string Namespace, [In][MarshalAs(UnmanagedType.LPWStr)] string Name);

		void SetAttribute([In][MarshalAs(UnmanagedType.LPWStr)] string Namespace, [In][MarshalAs(UnmanagedType.LPWStr)] string Name, [In][MarshalAs(UnmanagedType.LPWStr)] string Value);

		IEnumIDENTITY_ATTRIBUTE EnumAttributes();

		IReferenceIdentity Clone([In] IntPtr cDeltas, [In][MarshalAs(UnmanagedType.LPArray)] IDENTITY_ATTRIBUTE[] Deltas);
	}
	[ComImport]
	[Guid("587bf538-4d90-4a3c-9ef1-58a200a8a9e7")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IDefinitionIdentity
	{
		[return: MarshalAs(UnmanagedType.LPWStr)]
		string GetAttribute([In][MarshalAs(UnmanagedType.LPWStr)] string Namespace, [In][MarshalAs(UnmanagedType.LPWStr)] string Name);

		void SetAttribute([In][MarshalAs(UnmanagedType.LPWStr)] string Namespace, [In][MarshalAs(UnmanagedType.LPWStr)] string Name, [In][MarshalAs(UnmanagedType.LPWStr)] string Value);

		IEnumIDENTITY_ATTRIBUTE EnumAttributes();

		IDefinitionIdentity Clone([In] IntPtr cDeltas, [In][MarshalAs(UnmanagedType.LPArray)] IDENTITY_ATTRIBUTE[] Deltas);
	}
	internal sealed class DefinitionIdentity
	{
		internal IDefinitionIdentity _id;

		internal DefinitionIdentity(IDefinitionIdentity i)
		{
			if (i == null)
			{
				throw new ArgumentNullException();
			}
			_id = i;
		}

		private string GetAttribute(string ns, string n)
		{
			return _id.GetAttribute(ns, n);
		}

		private string GetAttribute(string n)
		{
			return _id.GetAttribute(null, n);
		}

		private void SetAttribute(string ns, string n, string v)
		{
			_id.SetAttribute(ns, n, v);
		}

		private void SetAttribute(string n, string v)
		{
			SetAttribute(null, n, v);
		}

		private void DeleteAttribute(string ns, string n)
		{
			SetAttribute(ns, n, null);
		}

		private void DeleteAttribute(string n)
		{
			SetAttribute(null, n, null);
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("9cdaae75-246e-4b00-a26d-b9aec137a3eb")]
	internal interface IEnumIDENTITY_ATTRIBUTE
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] IDENTITY_ATTRIBUTE[] rgAttributes);

		IntPtr CurrentIntoBuffer([In] IntPtr Available, [Out][MarshalAs(UnmanagedType.LPArray)] byte[] Data);

		void Skip([In] uint celt);

		void Reset();

		IEnumIDENTITY_ATTRIBUTE Clone();
	}
	[ComImport]
	[Guid("f3549d9c-fc73-4793-9c00-1cd204254c0c")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEnumDefinitionIdentity
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] IDefinitionIdentity[] DefinitionIdentity);

		void Skip([In] uint celt);

		void Reset();

		IEnumDefinitionIdentity Clone();
	}
	internal sealed class EnumDefinitionIdentity : IEnumerator
	{
		private IEnumDefinitionIdentity _enum;

		private IDefinitionIdentity _current;

		private IDefinitionIdentity[] _fetchList = new IDefinitionIdentity[1];

		object IEnumerator.Current => GetCurrent();

		public DefinitionIdentity Current => GetCurrent();

		internal EnumDefinitionIdentity(IEnumDefinitionIdentity e)
		{
			if (e == null)
			{
				throw new ArgumentNullException();
			}
			_enum = e;
		}

		private DefinitionIdentity GetCurrent()
		{
			if (_current == null)
			{
				throw new InvalidOperationException();
			}
			return new DefinitionIdentity(_current);
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		public bool MoveNext()
		{
			if (_enum.Next(1u, _fetchList) == 1)
			{
				_current = _fetchList[0];
				return true;
			}
			_current = null;
			return false;
		}

		public void Reset()
		{
			_current = null;
			_enum.Reset();
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("b30352cf-23da-4577-9b3f-b4e6573be53b")]
	internal interface IEnumReferenceIdentity
	{
		uint Next([In] uint celt, [Out][MarshalAs(UnmanagedType.LPArray)] IReferenceIdentity[] ReferenceIdentity);

		void Skip(uint celt);

		void Reset();

		IEnumReferenceIdentity Clone();
	}
	internal sealed class EnumReferenceIdentity : IEnumerator
	{
		private IEnumReferenceIdentity _enum;

		private IReferenceIdentity _current;

		private IReferenceIdentity[] _fetchList = new IReferenceIdentity[1];

		object IEnumerator.Current => GetCurrent();

		public ReferenceIdentity Current => GetCurrent();

		internal EnumReferenceIdentity(IEnumReferenceIdentity e)
		{
			_enum = e;
		}

		private ReferenceIdentity GetCurrent()
		{
			if (_current == null)
			{
				throw new InvalidOperationException();
			}
			return new ReferenceIdentity(_current);
		}

		public IEnumerator GetEnumerator()
		{
			return this;
		}

		public bool MoveNext()
		{
			if (_enum.Next(1u, _fetchList) == 1)
			{
				_current = _fetchList[0];
				return true;
			}
			_current = null;
			return false;
		}

		public void Reset()
		{
			_current = null;
			_enum.Reset();
		}
	}
	[ComImport]
	[Guid("d91e12d8-98ed-47fa-9936-39421283d59b")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IDefinitionAppId
	{
		[return: MarshalAs(UnmanagedType.LPWStr)]
		string get_SubscriptionId();

		void put_SubscriptionId([In][MarshalAs(UnmanagedType.LPWStr)] string Subscription);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string get_Codebase();

		void put_Codebase([In][MarshalAs(UnmanagedType.LPWStr)] string CodeBase);

		IEnumDefinitionIdentity EnumAppPath();

		void SetAppPath([In] uint cIDefinitionIdentity, [In][MarshalAs(UnmanagedType.LPArray)] IDefinitionIdentity[] DefinitionIdentity);
	}
	internal sealed class DefinitionAppId
	{
		internal IDefinitionAppId _id;

		public string SubscriptionId
		{
			get
			{
				return _id.get_SubscriptionId();
			}
			set
			{
				_id.put_SubscriptionId(value);
			}
		}

		public string Codebase
		{
			get
			{
				return _id.get_Codebase();
			}
			set
			{
				_id.put_Codebase(value);
			}
		}

		public EnumDefinitionIdentity AppPath => new EnumDefinitionIdentity(_id.EnumAppPath());

		internal DefinitionAppId(IDefinitionAppId id)
		{
			if (id == null)
			{
				throw new ArgumentNullException();
			}
			_id = id;
		}

		private void SetAppPath(IDefinitionIdentity[] Ids)
		{
			_id.SetAppPath((uint)Ids.Length, Ids);
		}
	}
	[ComImport]
	[Guid("054f0bef-9e45-4363-8f5a-2f8e142d9a3b")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IReferenceAppId
	{
		[return: MarshalAs(UnmanagedType.LPWStr)]
		string get_SubscriptionId();

		void put_SubscriptionId([In][MarshalAs(UnmanagedType.LPWStr)] string Subscription);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string get_Codebase();

		void put_Codebase([In][MarshalAs(UnmanagedType.LPWStr)] string CodeBase);

		IEnumReferenceIdentity EnumAppPath();
	}
	internal sealed class ReferenceAppId
	{
		internal IReferenceAppId _id;

		public string SubscriptionId
		{
			get
			{
				return _id.get_SubscriptionId();
			}
			set
			{
				_id.put_SubscriptionId(value);
			}
		}

		public string Codebase
		{
			get
			{
				return _id.get_Codebase();
			}
			set
			{
				_id.put_Codebase(value);
			}
		}

		public EnumReferenceIdentity AppPath => new EnumReferenceIdentity(_id.EnumAppPath());

		internal ReferenceAppId(IReferenceAppId id)
		{
			if (id == null)
			{
				throw new ArgumentNullException();
			}
			_id = id;
		}
	}
	internal enum IIDENTITYAUTHORITY_DEFINITION_IDENTITY_TO_TEXT_FLAGS
	{
		IIDENTITYAUTHORITY_DEFINITION_IDENTITY_TO_TEXT_FLAG_CANONICAL = 1
	}
	internal enum IIDENTITYAUTHORITY_REFERENCE_IDENTITY_TO_TEXT_FLAGS
	{
		IIDENTITYAUTHORITY_REFERENCE_IDENTITY_TO_TEXT_FLAG_CANONICAL = 1
	}
	internal enum IIDENTITYAUTHORITY_DOES_DEFINITION_MATCH_REFERENCE_FLAGS
	{
		IIDENTITYAUTHORITY_DOES_DEFINITION_MATCH_REFERENCE_FLAG_EXACT_MATCH_REQUIRED = 1
	}
	[ComImport]
	[Guid("261a6983-c35d-4d0d-aa5b-7867259e77bc")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IIdentityAuthority
	{
		IDefinitionIdentity TextToDefinition([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string Identity);

		IReferenceIdentity TextToReference([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string Identity);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string DefinitionToText([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity);

		uint DefinitionToTextBuffer([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity, [In] uint BufferSize, [Out][MarshalAs(UnmanagedType.LPArray)] char[] Buffer);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string ReferenceToText([In] uint Flags, [In] IReferenceIdentity ReferenceIdentity);

		uint ReferenceToTextBuffer([In] uint Flags, [In] IReferenceIdentity ReferenceIdentity, [In] uint BufferSize, [Out][MarshalAs(UnmanagedType.LPArray)] char[] Buffer);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreDefinitionsEqual([In] uint Flags, [In] IDefinitionIdentity Definition1, [In] IDefinitionIdentity Definition2);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreReferencesEqual([In] uint Flags, [In] IReferenceIdentity Reference1, [In] IReferenceIdentity Reference2);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreTextualDefinitionsEqual([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string IdentityLeft, [In][MarshalAs(UnmanagedType.LPWStr)] string IdentityRight);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreTextualReferencesEqual([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string IdentityLeft, [In][MarshalAs(UnmanagedType.LPWStr)] string IdentityRight);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool DoesDefinitionMatchReference([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity, [In] IReferenceIdentity ReferenceIdentity);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool DoesTextualDefinitionMatchTextualReference([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string Definition, [In][MarshalAs(UnmanagedType.LPWStr)] string Reference);

		ulong HashReference([In] uint Flags, [In] IReferenceIdentity ReferenceIdentity);

		ulong HashDefinition([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string GenerateDefinitionKey([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string GenerateReferenceKey([In] uint Flags, [In] IReferenceIdentity ReferenceIdentity);

		IDefinitionIdentity CreateDefinition();

		IReferenceIdentity CreateReference();
	}
	[Flags]
	internal enum IAPPIDAUTHORITY_ARE_DEFINITIONS_EQUAL_FLAGS
	{
		IAPPIDAUTHORITY_ARE_DEFINITIONS_EQUAL_FLAG_IGNORE_VERSION = 1
	}
	[Flags]
	internal enum IAPPIDAUTHORITY_ARE_REFERENCES_EQUAL_FLAGS
	{
		IAPPIDAUTHORITY_ARE_REFERENCES_EQUAL_FLAG_IGNORE_VERSION = 1
	}
	[ComImport]
	[Guid("8c87810c-2541-4f75-b2d0-9af515488e23")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IAppIdAuthority
	{
		IDefinitionAppId TextToDefinition([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string Identity);

		IReferenceAppId TextToReference([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string Identity);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string DefinitionToText([In] uint Flags, [In] IDefinitionAppId DefinitionAppId);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string ReferenceToText([In] uint Flags, [In] IReferenceAppId ReferenceAppId);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreDefinitionsEqual([In] uint Flags, [In] IDefinitionAppId Definition1, [In] IDefinitionAppId Definition2);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreReferencesEqual([In] uint Flags, [In] IReferenceAppId Reference1, [In] IReferenceAppId Reference2);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreTextualDefinitionsEqual([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string AppIdLeft, [In][MarshalAs(UnmanagedType.LPWStr)] string AppIdRight);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool AreTextualReferencesEqual([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string AppIdLeft, [In][MarshalAs(UnmanagedType.LPWStr)] string AppIdRight);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool DoesDefinitionMatchReference([In] uint Flags, [In] IDefinitionAppId DefinitionIdentity, [In] IReferenceAppId ReferenceIdentity);

		[return: MarshalAs(UnmanagedType.Bool)]
		bool DoesTextualDefinitionMatchTextualReference([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string Definition, [In][MarshalAs(UnmanagedType.LPWStr)] string Reference);

		ulong HashReference([In] uint Flags, [In] IReferenceAppId ReferenceIdentity);

		ulong HashDefinition([In] uint Flags, [In] IDefinitionAppId DefinitionIdentity);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string GenerateDefinitionKey([In] uint Flags, [In] IDefinitionAppId DefinitionIdentity);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string GenerateReferenceKey([In] uint Flags, [In] IReferenceAppId ReferenceIdentity);

		IDefinitionAppId CreateDefinition();

		IReferenceAppId CreateReference();
	}
	[Flags]
	internal enum ISTORE_BIND_REFERENCE_TO_ASSEMBLY_FLAGS
	{
		ISTORE_BIND_REFERENCE_TO_ASSEMBLY_FLAG_FORCE_LIBRARY_SEMANTICS = 1
	}
	[Flags]
	internal enum ISTORE_ENUM_ASSEMBLIES_FLAGS
	{
		ISTORE_ENUM_ASSEMBLIES_FLAG_LIMIT_TO_VISIBLE_ONLY = 1,
		ISTORE_ENUM_ASSEMBLIES_FLAG_MATCH_SERVICING = 2,
		ISTORE_ENUM_ASSEMBLIES_FLAG_FORCE_LIBRARY_SEMANTICS = 4
	}
	[Flags]
	internal enum ISTORE_ENUM_FILES_FLAGS
	{
		ISTORE_ENUM_FILES_FLAG_INCLUDE_INSTALLED_FILES = 1,
		ISTORE_ENUM_FILES_FLAG_INCLUDE_MISSING_FILES = 2
	}
	internal struct StoreOperationStageComponent
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0
		}

		public enum Disposition
		{
			Failed,
			Installed,
			Refreshed,
			AlreadyInstalled
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionAppId Application;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionIdentity Component;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ManifestPath;

		public void Destroy()
		{
		}

		public StoreOperationStageComponent(IDefinitionAppId app, string Manifest)
			: this(app, null, Manifest)
		{
		}

		public StoreOperationStageComponent(IDefinitionAppId app, IDefinitionIdentity comp, string Manifest)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationStageComponent));
			Flags = OpFlags.Nothing;
			Application = app;
			Component = comp;
			ManifestPath = Manifest;
		}
	}
	internal struct StoreOperationStageComponentFile
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0
		}

		public enum Disposition
		{
			Failed,
			Installed,
			Refreshed,
			AlreadyInstalled
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionAppId Application;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionIdentity Component;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ComponentRelativePath;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string SourceFilePath;

		public StoreOperationStageComponentFile(IDefinitionAppId App, string CompRelPath, string SrcFile)
			: this(App, null, CompRelPath, SrcFile)
		{
		}

		public StoreOperationStageComponentFile(IDefinitionAppId App, IDefinitionIdentity Component, string CompRelPath, string SrcFile)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationStageComponentFile));
			Flags = OpFlags.Nothing;
			Application = App;
			this.Component = Component;
			ComponentRelativePath = CompRelPath;
			SourceFilePath = SrcFile;
		}

		public void Destroy()
		{
		}
	}
	internal struct StoreApplicationReference
	{
		[Flags]
		public enum RefFlags
		{
			Nothing = 0
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public RefFlags Flags;

		public Guid GuidScheme;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Identifier;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string NonCanonicalData;

		public StoreApplicationReference(Guid RefScheme, string Id, string NcData)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreApplicationReference));
			Flags = RefFlags.Nothing;
			GuidScheme = RefScheme;
			Identifier = Id;
			NonCanonicalData = NcData;
		}

		public IntPtr ToIntPtr()
		{
			IntPtr intPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(this));
			Marshal.StructureToPtr(this, intPtr, fDeleteOld: false);
			return intPtr;
		}

		public static void Destroy(IntPtr ip)
		{
			if (ip != IntPtr.Zero)
			{
				Marshal.DestroyStructure(ip, typeof(StoreApplicationReference));
				Marshal.FreeCoTaskMem(ip);
			}
		}
	}
	internal struct StoreOperationPinDeployment
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0,
			NeverExpires = 1
		}

		public enum Disposition
		{
			Failed,
			Pinned
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionAppId Application;

		[MarshalAs(UnmanagedType.I8)]
		public long ExpirationTime;

		public IntPtr Reference;

		public StoreOperationPinDeployment(IDefinitionAppId AppId, StoreApplicationReference Ref)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationPinDeployment));
			Flags = OpFlags.NeverExpires;
			Application = AppId;
			Reference = Ref.ToIntPtr();
			ExpirationTime = 0L;
		}

		public StoreOperationPinDeployment(IDefinitionAppId AppId, DateTime Expiry, StoreApplicationReference Ref)
			: this(AppId, Ref)
		{
			Flags |= OpFlags.NeverExpires;
		}

		public void Destroy()
		{
			StoreApplicationReference.Destroy(Reference);
		}
	}
	internal struct StoreOperationUnpinDeployment
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0
		}

		public enum Disposition
		{
			Failed,
			Unpinned
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionAppId Application;

		public IntPtr Reference;

		public StoreOperationUnpinDeployment(IDefinitionAppId app, StoreApplicationReference reference)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationUnpinDeployment));
			Flags = OpFlags.Nothing;
			Application = app;
			Reference = reference.ToIntPtr();
		}

		public void Destroy()
		{
			StoreApplicationReference.Destroy(Reference);
		}
	}
	internal struct StoreOperationInstallDeployment
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0,
			UninstallOthers = 1
		}

		public enum Disposition
		{
			Failed,
			AlreadyInstalled,
			Installed
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionAppId Application;

		public IntPtr Reference;

		public StoreOperationInstallDeployment(IDefinitionAppId App, StoreApplicationReference reference)
			: this(App, UninstallOthers: true, reference)
		{
		}

		public StoreOperationInstallDeployment(IDefinitionAppId App, bool UninstallOthers, StoreApplicationReference reference)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationInstallDeployment));
			Flags = OpFlags.Nothing;
			Application = App;
			if (UninstallOthers)
			{
				Flags |= OpFlags.UninstallOthers;
			}
			Reference = reference.ToIntPtr();
		}

		public void Destroy()
		{
			StoreApplicationReference.Destroy(Reference);
		}
	}
	internal struct StoreOperationUninstallDeployment
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0
		}

		public enum Disposition
		{
			Failed,
			DidNotExist,
			Uninstalled
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionAppId Application;

		public IntPtr Reference;

		public StoreOperationUninstallDeployment(IDefinitionAppId appid, StoreApplicationReference AppRef)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationUninstallDeployment));
			Flags = OpFlags.Nothing;
			Application = appid;
			Reference = AppRef.ToIntPtr();
		}

		public void Destroy()
		{
			StoreApplicationReference.Destroy(Reference);
		}
	}
	internal struct StoreOperationMetadataProperty
	{
		public Guid GuidPropertySet;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		[MarshalAs(UnmanagedType.SysUInt)]
		public IntPtr ValueSize;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Value;

		public StoreOperationMetadataProperty(Guid PropertySet, string Name)
			: this(PropertySet, Name, null)
		{
		}

		public StoreOperationMetadataProperty(Guid PropertySet, string Name, string Value)
		{
			GuidPropertySet = PropertySet;
			this.Name = Name;
			this.Value = Value;
			ValueSize = ((Value != null) ? new IntPtr((Value.Length + 1) * 2) : IntPtr.Zero);
		}
	}
	internal struct StoreOperationSetDeploymentMetadata
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0
		}

		public enum Disposition
		{
			Failed = 0,
			Set = 2
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.Interface)]
		public IDefinitionAppId Deployment;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr InstallerReference;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr cPropertiesToTest;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr PropertiesToTest;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr cPropertiesToSet;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr PropertiesToSet;

		public StoreOperationSetDeploymentMetadata(IDefinitionAppId Deployment, StoreApplicationReference Reference, StoreOperationMetadataProperty[] SetProperties)
			: this(Deployment, Reference, SetProperties, null)
		{
		}

		public StoreOperationSetDeploymentMetadata(IDefinitionAppId Deployment, StoreApplicationReference Reference, StoreOperationMetadataProperty[] SetProperties, StoreOperationMetadataProperty[] TestProperties)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationSetDeploymentMetadata));
			Flags = OpFlags.Nothing;
			this.Deployment = Deployment;
			if (SetProperties != null)
			{
				PropertiesToSet = MarshalProperties(SetProperties);
				cPropertiesToSet = new IntPtr(SetProperties.Length);
			}
			else
			{
				PropertiesToSet = IntPtr.Zero;
				cPropertiesToSet = IntPtr.Zero;
			}
			if (TestProperties != null)
			{
				PropertiesToTest = MarshalProperties(TestProperties);
				cPropertiesToTest = new IntPtr(TestProperties.Length);
			}
			else
			{
				PropertiesToTest = IntPtr.Zero;
				cPropertiesToTest = IntPtr.Zero;
			}
			InstallerReference = Reference.ToIntPtr();
		}

		public void Destroy()
		{
			if (PropertiesToSet != IntPtr.Zero)
			{
				DestroyProperties(PropertiesToSet, (ulong)cPropertiesToSet.ToInt64());
				PropertiesToSet = IntPtr.Zero;
				cPropertiesToSet = IntPtr.Zero;
			}
			if (PropertiesToTest != IntPtr.Zero)
			{
				DestroyProperties(PropertiesToTest, (ulong)cPropertiesToTest.ToInt64());
				PropertiesToTest = IntPtr.Zero;
				cPropertiesToTest = IntPtr.Zero;
			}
			if (InstallerReference != IntPtr.Zero)
			{
				StoreApplicationReference.Destroy(InstallerReference);
				InstallerReference = IntPtr.Zero;
			}
		}

		private static void DestroyProperties(IntPtr rgItems, ulong iItems)
		{
			if (rgItems != IntPtr.Zero)
			{
				ulong num = (ulong)Marshal.SizeOf(typeof(StoreOperationMetadataProperty));
				for (ulong num2 = 0uL; num2 < iItems; num2++)
				{
					Marshal.DestroyStructure(new IntPtr((long)(num2 * num) + rgItems.ToInt64()), typeof(StoreOperationMetadataProperty));
				}
				Marshal.FreeCoTaskMem(rgItems);
			}
		}

		private static IntPtr MarshalProperties(StoreOperationMetadataProperty[] Props)
		{
			if (Props == null || Props.Length == 0)
			{
				return IntPtr.Zero;
			}
			int num = Marshal.SizeOf(typeof(StoreOperationMetadataProperty));
			IntPtr result = Marshal.AllocCoTaskMem(num * Props.Length);
			for (int i = 0; i != Props.Length; i++)
			{
				Marshal.StructureToPtr(Props[i], new IntPtr(i * num + result.ToInt64()), fDeleteOld: false);
			}
			return result;
		}
	}
	internal struct StoreOperationSetCanonicalizationContext
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string BaseAddressFilePath;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ExportsFilePath;

		public StoreOperationSetCanonicalizationContext(string Bases, string Exports)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationSetCanonicalizationContext));
			Flags = OpFlags.Nothing;
			BaseAddressFilePath = Bases;
			ExportsFilePath = Exports;
		}

		public void Destroy()
		{
		}
	}
	internal struct StoreOperationScavenge
	{
		[Flags]
		public enum OpFlags
		{
			Nothing = 0,
			Light = 1,
			LimitSize = 2,
			LimitTime = 4,
			LimitCount = 8
		}

		[MarshalAs(UnmanagedType.U4)]
		public uint Size;

		[MarshalAs(UnmanagedType.U4)]
		public OpFlags Flags;

		[MarshalAs(UnmanagedType.U8)]
		public ulong SizeReclaimationLimit;

		[MarshalAs(UnmanagedType.U8)]
		public ulong RuntimeLimit;

		[MarshalAs(UnmanagedType.U4)]
		public uint ComponentCountLimit;

		public StoreOperationScavenge(bool Light, ulong SizeLimit, ulong RunLimit, uint ComponentLimit)
		{
			Size = (uint)Marshal.SizeOf(typeof(StoreOperationScavenge));
			Flags = OpFlags.Nothing;
			if (Light)
			{
				Flags |= OpFlags.Light;
			}
			SizeReclaimationLimit = SizeLimit;
			if (SizeLimit != 0)
			{
				Flags |= OpFlags.LimitSize;
			}
			RuntimeLimit = RunLimit;
			if (RunLimit != 0)
			{
				Flags |= OpFlags.LimitTime;
			}
			ComponentCountLimit = ComponentLimit;
			if (ComponentLimit != 0)
			{
				Flags |= OpFlags.LimitCount;
			}
		}

		public StoreOperationScavenge(bool Light)
			: this(Light, 0uL, 0uL, 0u)
		{
		}

		public void Destroy()
		{
		}
	}
	internal enum StoreTransactionOperationType
	{
		Invalid = 0,
		SetCanonicalizationContext = 14,
		StageComponent = 20,
		PinDeployment = 21,
		UnpinDeployment = 22,
		StageComponentFile = 23,
		InstallDeployment = 24,
		UninstallDeployment = 25,
		SetDeploymentMetadata = 26,
		Scavenge = 27
	}
	internal struct StoreTransactionOperation
	{
		[MarshalAs(UnmanagedType.U4)]
		public StoreTransactionOperationType Operation;

		public StoreTransactionData Data;
	}
	internal struct StoreTransactionData
	{
		public IntPtr DataPtr;
	}
	internal class Store
	{
		[Flags]
		public enum EnumAssembliesFlags
		{
			Nothing = 0,
			VisibleOnly = 1,
			MatchServicing = 2,
			ForceLibrarySemantics = 4
		}

		[Flags]
		public enum EnumAssemblyFilesFlags
		{
			Nothing = 0,
			IncludeInstalled = 1,
			IncludeMissing = 2
		}

		[Flags]
		public enum EnumApplicationPrivateFiles
		{
			Nothing = 0,
			IncludeInstalled = 1,
			IncludeMissing = 2
		}

		[Flags]
		public enum EnumAssemblyInstallReferenceFlags
		{
			Nothing = 0
		}

		public interface IPathLock : IDisposable
		{
			string Path { get; }
		}

		private class AssemblyPathLock : IPathLock, IDisposable
		{
			private IStore _pSourceStore;

			private IntPtr _pLockCookie = IntPtr.Zero;

			private string _path;

			public string Path => _path;

			public AssemblyPathLock(IStore s, IntPtr c, string path)
			{
				_pSourceStore = s;
				_pLockCookie = c;
				_path = path;
			}

			private void Dispose(bool fDisposing)
			{
				if (fDisposing)
				{
					GC.SuppressFinalize(this);
				}
				if (_pLockCookie != IntPtr.Zero)
				{
					_pSourceStore.ReleaseAssemblyPath(_pLockCookie);
					_pLockCookie = IntPtr.Zero;
				}
			}

			~AssemblyPathLock()
			{
				Dispose(fDisposing: false);
			}

			void IDisposable.Dispose()
			{
				Dispose(fDisposing: true);
			}
		}

		private class ApplicationPathLock : IPathLock, IDisposable
		{
			private IStore _pSourceStore;

			private IntPtr _pLockCookie = IntPtr.Zero;

			private string _path;

			public string Path => _path;

			public ApplicationPathLock(IStore s, IntPtr c, string path)
			{
				_pSourceStore = s;
				_pLockCookie = c;
				_path = path;
			}

			private void Dispose(bool fDisposing)
			{
				if (fDisposing)
				{
					GC.SuppressFinalize(this);
				}
				if (_pLockCookie != IntPtr.Zero)
				{
					_pSourceStore.ReleaseApplicationPath(_pLockCookie);
					_pLockCookie = IntPtr.Zero;
				}
			}

			~ApplicationPathLock()
			{
				Dispose(fDisposing: false);
			}

			void IDisposable.Dispose()
			{
				Dispose(fDisposing: true);
			}
		}

		[Flags]
		public enum EnumCategoriesFlags
		{
			Nothing = 0
		}

		[Flags]
		public enum EnumSubcategoriesFlags
		{
			Nothing = 0
		}

		[Flags]
		public enum EnumCategoryInstancesFlags
		{
			Nothing = 0
		}

		[Flags]
		public enum GetPackagePropertyFlags
		{
			Nothing = 0
		}

		private IStore _pStore;

		public IStore InternalStore => _pStore;

		public Store(IStore pStore)
		{
			if (pStore == null)
			{
				throw new ArgumentNullException("pStore");
			}
			_pStore = pStore;
		}

		public uint[] Transact(StoreTransactionOperation[] operations)
		{
			if (operations == null || operations.Length == 0)
			{
				throw new ArgumentException("operations");
			}
			uint[] array = new uint[operations.Length];
			int[] rgResults = new int[operations.Length];
			_pStore.Transact(new IntPtr(operations.Length), operations, array, rgResults);
			return array;
		}

		public void Transact(StoreTransactionOperation[] operations, uint[] rgDispositions, int[] rgResults)
		{
			if (operations == null || operations.Length == 0)
			{
				throw new ArgumentException("operations");
			}
			_pStore.Transact(new IntPtr(operations.Length), operations, rgDispositions, rgResults);
		}

		public IDefinitionIdentity BindReferenceToAssemblyIdentity(uint Flags, IReferenceIdentity ReferenceIdentity, uint cDeploymentsToIgnore, IDefinitionIdentity[] DefinitionIdentity_DeploymentsToIgnore)
		{
			Guid riid = IsolationInterop.IID_IDefinitionIdentity;
			object obj = _pStore.BindReferenceToAssembly(Flags, ReferenceIdentity, cDeploymentsToIgnore, DefinitionIdentity_DeploymentsToIgnore, ref riid);
			return (IDefinitionIdentity)obj;
		}

		public void CalculateDelimiterOfDeploymentsBasedOnQuota(uint dwFlags, uint cDeployments, IDefinitionAppId[] rgpIDefinitionAppId_Deployments, ref StoreApplicationReference InstallerReference, ulong ulonglongQuota, ref uint Delimiter, ref ulong SizeSharedWithExternalDeployment, ref ulong SizeConsumedByInputDeploymentArray)
		{
			IntPtr Delimiter2 = IntPtr.Zero;
			_pStore.CalculateDelimiterOfDeploymentsBasedOnQuota(dwFlags, new IntPtr(cDeployments), rgpIDefinitionAppId_Deployments, ref InstallerReference, ulonglongQuota, ref Delimiter2, ref SizeSharedWithExternalDeployment, ref SizeConsumedByInputDeploymentArray);
			Delimiter = (uint)Delimiter2.ToInt64();
		}

		public System.Deployment.Internal.Isolation.Manifest.ICMS BindReferenceToAssemblyManifest(uint Flags, IReferenceIdentity ReferenceIdentity, uint cDeploymentsToIgnore, IDefinitionIdentity[] DefinitionIdentity_DeploymentsToIgnore)
		{
			Guid riid = IsolationInterop.IID_ICMS;
			object obj = _pStore.BindReferenceToAssembly(Flags, ReferenceIdentity, cDeploymentsToIgnore, DefinitionIdentity_DeploymentsToIgnore, ref riid);
			return (System.Deployment.Internal.Isolation.Manifest.ICMS)obj;
		}

		public System.Deployment.Internal.Isolation.Manifest.ICMS GetAssemblyManifest(uint Flags, IDefinitionIdentity DefinitionIdentity)
		{
			Guid riid = IsolationInterop.IID_ICMS;
			object assemblyInformation = _pStore.GetAssemblyInformation(Flags, DefinitionIdentity, ref riid);
			return (System.Deployment.Internal.Isolation.Manifest.ICMS)assemblyInformation;
		}

		public IDefinitionIdentity GetAssemblyIdentity(uint Flags, IDefinitionIdentity DefinitionIdentity)
		{
			Guid riid = IsolationInterop.IID_IDefinitionIdentity;
			object assemblyInformation = _pStore.GetAssemblyInformation(Flags, DefinitionIdentity, ref riid);
			return (IDefinitionIdentity)assemblyInformation;
		}

		public StoreAssemblyEnumeration EnumAssemblies(EnumAssembliesFlags Flags)
		{
			return EnumAssemblies(Flags, null);
		}

		public StoreAssemblyEnumeration EnumAssemblies(EnumAssembliesFlags Flags, IReferenceIdentity refToMatch)
		{
			Guid riid = IsolationInterop.GetGuidOfType(typeof(IEnumSTORE_ASSEMBLY));
			object obj = _pStore.EnumAssemblies((uint)Flags, refToMatch, ref riid);
			return new StoreAssemblyEnumeration((IEnumSTORE_ASSEMBLY)obj);
		}

		public StoreAssemblyFileEnumeration EnumFiles(EnumAssemblyFilesFlags Flags, IDefinitionIdentity Assembly)
		{
			Guid riid = IsolationInterop.GetGuidOfType(typeof(IEnumSTORE_ASSEMBLY_FILE));
			object obj = _pStore.EnumFiles((uint)Flags, Assembly, ref riid);
			return new StoreAssemblyFileEnumeration((IEnumSTORE_ASSEMBLY_FILE)obj);
		}

		public StoreAssemblyFileEnumeration EnumPrivateFiles(EnumApplicationPrivateFiles Flags, IDefinitionAppId Application, IDefinitionIdentity Assembly)
		{
			Guid riid = IsolationInterop.GetGuidOfType(typeof(IEnumSTORE_ASSEMBLY_FILE));
			object obj = _pStore.EnumPrivateFiles((uint)Flags, Application, Assembly, ref riid);
			return new StoreAssemblyFileEnumeration((IEnumSTORE_ASSEMBLY_FILE)obj);
		}

		public IEnumSTORE_ASSEMBLY_INSTALLATION_REFERENCE EnumInstallationReferences(EnumAssemblyInstallReferenceFlags Flags, IDefinitionIdentity Assembly)
		{
			Guid riid = IsolationInterop.GetGuidOfType(typeof(IEnumSTORE_ASSEMBLY_INSTALLATION_REFERENCE));
			object obj = _pStore.EnumInstallationReferences((uint)Flags, Assembly, ref riid);
			return (IEnumSTORE_ASSEMBLY_INSTALLATION_REFERENCE)obj;
		}

		public IPathLock LockAssemblyPath(IDefinitionIdentity asm)
		{
			IntPtr Cookie;
			string path = _pStore.LockAssemblyPath(0u, asm, out Cookie);
			return new AssemblyPathLock(_pStore, Cookie, path);
		}

		public IPathLock LockApplicationPath(IDefinitionAppId app)
		{
			IntPtr Cookie;
			string path = _pStore.LockApplicationPath(0u, app, out Cookie);
			return new ApplicationPathLock(_pStore, Cookie, path);
		}

		public ulong QueryChangeID(IDefinitionIdentity asm)
		{
			return _pStore.QueryChangeID(asm);
		}

		public StoreCategoryEnumeration EnumCategories(EnumCategoriesFlags Flags, IReferenceIdentity CategoryMatch)
		{
			Guid riid = IsolationInterop.GetGuidOfType(typeof(IEnumSTORE_CATEGORY));
			object obj = _pStore.EnumCategories((uint)Flags, CategoryMatch, ref riid);
			return new StoreCategoryEnumeration((IEnumSTORE_CATEGORY)obj);
		}

		public StoreSubcategoryEnumeration EnumSubcategories(EnumSubcategoriesFlags Flags, IDefinitionIdentity CategoryMatch)
		{
			return EnumSubcategories(Flags, CategoryMatch, null);
		}

		public StoreSubcategoryEnumeration EnumSubcategories(EnumSubcategoriesFlags Flags, IDefinitionIdentity Category, string SearchPattern)
		{
			Guid riid = IsolationInterop.GetGuidOfType(typeof(IEnumSTORE_CATEGORY_SUBCATEGORY));
			object obj = _pStore.EnumSubcategories((uint)Flags, Category, SearchPattern, ref riid);
			return new StoreSubcategoryEnumeration((IEnumSTORE_CATEGORY_SUBCATEGORY)obj);
		}

		public StoreCategoryInstanceEnumeration EnumCategoryInstances(EnumCategoryInstancesFlags Flags, IDefinitionIdentity Category, string SubCat)
		{
			Guid riid = IsolationInterop.GetGuidOfType(typeof(IEnumSTORE_CATEGORY_INSTANCE));
			object obj = _pStore.EnumCategoryInstances((uint)Flags, Category, SubCat, ref riid);
			return new StoreCategoryInstanceEnumeration((IEnumSTORE_CATEGORY_INSTANCE)obj);
		}

		public byte[] GetDeploymentProperty(GetPackagePropertyFlags Flags, IDefinitionAppId Deployment, StoreApplicationReference Reference, Guid PropertySet, string PropertyName)
		{
			BLOB blob = default(BLOB);
			byte[] array = null;
			try
			{
				_pStore.GetDeploymentProperty((uint)Flags, Deployment, ref Reference, ref PropertySet, PropertyName, out blob);
				array = new byte[blob.Size];
				Marshal.Copy(blob.BlobData, array, 0, (int)blob.Size);
				return array;
			}
			finally
			{
				blob.Dispose();
			}
		}

		public StoreDeploymentMetadataEnumeration EnumInstallerDeployments(Guid InstallerId, string InstallerName, string InstallerMetadata, IReferenceAppId DeploymentFilter)
		{
			object obj = null;
			StoreApplicationReference Reference = new StoreApplicationReference(InstallerId, InstallerName, InstallerMetadata);
			obj = _pStore.EnumInstallerDeploymentMetadata(0u, ref Reference, DeploymentFilter, ref IsolationInterop.IID_IEnumSTORE_DEPLOYMENT_METADATA);
			return new StoreDeploymentMetadataEnumeration((IEnumSTORE_DEPLOYMENT_METADATA)obj);
		}

		public StoreDeploymentMetadataPropertyEnumeration EnumInstallerDeploymentProperties(Guid InstallerId, string InstallerName, string InstallerMetadata, IDefinitionAppId Deployment)
		{
			object obj = null;
			StoreApplicationReference Reference = new StoreApplicationReference(InstallerId, InstallerName, InstallerMetadata);
			obj = _pStore.EnumInstallerDeploymentMetadataProperties(0u, ref Reference, Deployment, ref IsolationInterop.IID_IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY);
			return new StoreDeploymentMetadataPropertyEnumeration((IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY)obj);
		}
	}
	internal struct IStore_BindingResult_BoundVersion
	{
		[MarshalAs(UnmanagedType.U2)]
		public ushort Revision;

		[MarshalAs(UnmanagedType.U2)]
		public ushort Build;

		[MarshalAs(UnmanagedType.U2)]
		public ushort Minor;

		[MarshalAs(UnmanagedType.U2)]
		public ushort Major;
	}
	internal struct IStore_BindingResult
	{
		[MarshalAs(UnmanagedType.U4)]
		public uint Flags;

		[MarshalAs(UnmanagedType.U4)]
		public uint Disposition;

		public IStore_BindingResult_BoundVersion Component;

		public Guid CacheCoherencyGuid;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr Reserved;
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("a5c62f6d-5e3e-4cd9-b345-6b281d7a1d1e")]
	internal interface IStore
	{
		void Transact([In] IntPtr cOperation, [In][MarshalAs(UnmanagedType.LPArray)] StoreTransactionOperation[] rgOperations, [Out][MarshalAs(UnmanagedType.LPArray)] uint[] rgDispositions, [Out][MarshalAs(UnmanagedType.LPArray)] int[] rgResults);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object BindReferenceToAssembly([In] uint Flags, [In] IReferenceIdentity ReferenceIdentity, [In] uint cDeploymentsToIgnore, [In][MarshalAs(UnmanagedType.LPArray)] IDefinitionIdentity[] DefinitionIdentity_DeploymentsToIgnore, [In] ref Guid riid);

		void CalculateDelimiterOfDeploymentsBasedOnQuota([In] uint dwFlags, [In] IntPtr cDeployments, [In][MarshalAs(UnmanagedType.LPArray)] IDefinitionAppId[] rgpIDefinitionAppId_Deployments, [In] ref StoreApplicationReference InstallerReference, [In] ulong ulonglongQuota, [In][Out] ref IntPtr Delimiter, [In][Out] ref ulong SizeSharedWithExternalDeployment, [In][Out] ref ulong SizeConsumedByInputDeploymentArray);

		IntPtr BindDefinitions([In] uint Flags, [In][MarshalAs(UnmanagedType.SysInt)] IntPtr Count, [In][MarshalAs(UnmanagedType.LPArray)] IDefinitionIdentity[] DefsToBind, [In] uint DeploymentsToIgnore, [In][MarshalAs(UnmanagedType.LPArray)] IDefinitionIdentity[] DefsToIgnore);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object GetAssemblyInformation([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumAssemblies([In] uint Flags, [In] IReferenceIdentity ReferenceIdentity_ToMatch, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumFiles([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumInstallationReferences([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string LockAssemblyPath([In] uint Flags, [In] IDefinitionIdentity DefinitionIdentity, out IntPtr Cookie);

		void ReleaseAssemblyPath([In] IntPtr Cookie);

		ulong QueryChangeID([In] IDefinitionIdentity DefinitionIdentity);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumCategories([In] uint Flags, [In] IReferenceIdentity ReferenceIdentity_ToMatch, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumSubcategories([In] uint Flags, [In] IDefinitionIdentity CategoryId, [In][MarshalAs(UnmanagedType.LPWStr)] string SubcategoryPathPattern, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumCategoryInstances([In] uint Flags, [In] IDefinitionIdentity CategoryId, [In][MarshalAs(UnmanagedType.LPWStr)] string SubcategoryPath, [In] ref Guid riid);

		void GetDeploymentProperty([In] uint Flags, [In] IDefinitionAppId DeploymentInPackage, [In] ref StoreApplicationReference Reference, [In] ref Guid PropertySet, [In][MarshalAs(UnmanagedType.LPWStr)] string pcwszPropertyName, out BLOB blob);

		[return: MarshalAs(UnmanagedType.LPWStr)]
		string LockApplicationPath([In] uint Flags, [In] IDefinitionAppId ApId, out IntPtr Cookie);

		void ReleaseApplicationPath([In] IntPtr Cookie);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumPrivateFiles([In] uint Flags, [In] IDefinitionAppId Application, [In] IDefinitionIdentity DefinitionIdentity, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumInstallerDeploymentMetadata([In] uint Flags, [In] ref StoreApplicationReference Reference, [In] IReferenceAppId Filter, [In] ref Guid riid);

		[return: MarshalAs(UnmanagedType.IUnknown)]
		object EnumInstallerDeploymentMetadataProperties([In] uint Flags, [In] ref StoreApplicationReference Reference, [In] IDefinitionAppId Filter, [In] ref Guid riid);
	}
	internal static class IsolationInterop
	{
		internal struct CreateActContextParameters
		{
			[Flags]
			public enum CreateFlags
			{
				Nothing = 0,
				StoreListValid = 1,
				CultureListValid = 2,
				ProcessorFallbackListValid = 4,
				ProcessorValid = 8,
				SourceValid = 0x10,
				IgnoreVisibility = 0x20
			}

			[MarshalAs(UnmanagedType.U4)]
			public uint Size;

			[MarshalAs(UnmanagedType.U4)]
			public uint Flags;

			[MarshalAs(UnmanagedType.SysInt)]
			public IntPtr CustomStoreList;

			[MarshalAs(UnmanagedType.SysInt)]
			public IntPtr CultureFallbackList;

			[MarshalAs(UnmanagedType.SysInt)]
			public IntPtr ProcessorArchitectureList;

			[MarshalAs(UnmanagedType.SysInt)]
			public IntPtr Source;

			[MarshalAs(UnmanagedType.U2)]
			public ushort ProcArch;
		}

		internal struct CreateActContextParametersSource
		{
			[Flags]
			public enum SourceFlags
			{
				Definition = 1,
				Reference = 2
			}

			[MarshalAs(UnmanagedType.U4)]
			public uint Size;

			[MarshalAs(UnmanagedType.U4)]
			public uint Flags;

			[MarshalAs(UnmanagedType.U4)]
			public uint SourceType;

			[MarshalAs(UnmanagedType.SysInt)]
			public IntPtr Data;

			public IntPtr ToIntPtr()
			{
				IntPtr intPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(this));
				Marshal.StructureToPtr(this, intPtr, fDeleteOld: false);
				return intPtr;
			}

			public static void Destroy(IntPtr p)
			{
				Marshal.DestroyStructure(p, typeof(CreateActContextParametersSource));
				Marshal.FreeCoTaskMem(p);
			}
		}

		internal struct CreateActContextParametersSourceReferenceAppid
		{
			[MarshalAs(UnmanagedType.U4)]
			public uint Size;

			[MarshalAs(UnmanagedType.U4)]
			public uint Flags;

			public IReferenceAppId AppId;

			public IntPtr ToIntPtr()
			{
				IntPtr intPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(this));
				Marshal.StructureToPtr(this, intPtr, fDeleteOld: false);
				return intPtr;
			}

			public static void Destroy(IntPtr p)
			{
				Marshal.DestroyStructure(p, typeof(CreateActContextParametersSourceReferenceAppid));
				Marshal.FreeCoTaskMem(p);
			}
		}

		internal struct CreateActContextParametersSourceDefinitionAppid
		{
			[MarshalAs(UnmanagedType.U4)]
			public uint Size;

			[MarshalAs(UnmanagedType.U4)]
			public uint Flags;

			public IDefinitionAppId AppId;

			public IntPtr ToIntPtr()
			{
				IntPtr intPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(this));
				Marshal.StructureToPtr(this, intPtr, fDeleteOld: false);
				return intPtr;
			}

			public static void Destroy(IntPtr p)
			{
				Marshal.DestroyStructure(p, typeof(CreateActContextParametersSourceDefinitionAppid));
				Marshal.FreeCoTaskMem(p);
			}
		}

		public const string IsolationDllName = "mscorwks.dll";

		private static object _synchObject = new object();

		private static Store _userStore = null;

		private static Store _systemStore = null;

		private static IIdentityAuthority _idAuth = null;

		private static IAppIdAuthority _appIdAuth = null;

		public static Guid IID_ICMS = GetGuidOfType(typeof(System.Deployment.Internal.Isolation.Manifest.ICMS));

		public static Guid IID_IDefinitionIdentity = GetGuidOfType(typeof(IDefinitionIdentity));

		public static Guid IID_IManifestInformation = GetGuidOfType(typeof(IManifestInformation));

		public static Guid IID_IEnumSTORE_ASSEMBLY = GetGuidOfType(typeof(IEnumSTORE_ASSEMBLY));

		public static Guid IID_IEnumSTORE_ASSEMBLY_FILE = GetGuidOfType(typeof(IEnumSTORE_ASSEMBLY_FILE));

		public static Guid IID_IEnumSTORE_CATEGORY = GetGuidOfType(typeof(IEnumSTORE_CATEGORY));

		public static Guid IID_IEnumSTORE_CATEGORY_INSTANCE = GetGuidOfType(typeof(IEnumSTORE_CATEGORY_INSTANCE));

		public static Guid IID_IEnumSTORE_DEPLOYMENT_METADATA = GetGuidOfType(typeof(IEnumSTORE_DEPLOYMENT_METADATA));

		public static Guid IID_IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY = GetGuidOfType(typeof(IEnumSTORE_DEPLOYMENT_METADATA_PROPERTY));

		public static Guid IID_IStore = GetGuidOfType(typeof(IStore));

		public static Guid GUID_SXS_INSTALL_REFERENCE_SCHEME_OPAQUESTRING = new Guid("2ec93463-b0c3-45e1-8364-327e96aea856");

		public static Guid SXS_INSTALL_REFERENCE_SCHEME_SXS_STRONGNAME_SIGNED_PRIVATE_ASSEMBLY = new Guid("3ab20ac0-67e8-4512-8385-a487e35df3da");

		public static Store UserStore
		{
			get
			{
				if (_userStore == null)
				{
					lock (_synchObject)
					{
						if (_userStore == null)
						{
							_userStore = new Store(GetUserStore(0u, IntPtr.Zero, ref IID_IStore) as IStore);
						}
					}
				}
				return _userStore;
			}
		}

		public static Store SystemStore
		{
			get
			{
				if (_systemStore == null)
				{
					lock (_synchObject)
					{
						if (_systemStore == null)
						{
							_systemStore = new Store(GetSystemStore(0u, ref IID_IStore) as IStore);
						}
					}
				}
				return _systemStore;
			}
		}

		public static IIdentityAuthority IdentityAuthority
		{
			get
			{
				if (_idAuth == null)
				{
					lock (_synchObject)
					{
						if (_idAuth == null)
						{
							_idAuth = GetIdentityAuthority();
						}
					}
				}
				return _idAuth;
			}
		}

		public static IAppIdAuthority AppIdAuthority
		{
			get
			{
				if (_appIdAuth == null)
				{
					lock (_synchObject)
					{
						if (_appIdAuth == null)
						{
							_appIdAuth = GetAppIdAuthority();
						}
					}
				}
				return _appIdAuth;
			}
		}

		public static Store GetUserStore()
		{
			return new Store(GetUserStore(0u, IntPtr.Zero, ref IID_IStore) as IStore);
		}

		internal static IActContext CreateActContext(IDefinitionAppId AppId)
		{
			CreateActContextParameters Params = default(CreateActContextParameters);
			Params.Size = (uint)Marshal.SizeOf(typeof(CreateActContextParameters));
			Params.Flags = 16u;
			Params.CustomStoreList = IntPtr.Zero;
			Params.CultureFallbackList = IntPtr.Zero;
			Params.ProcessorArchitectureList = IntPtr.Zero;
			Params.Source = IntPtr.Zero;
			Params.ProcArch = 0;
			CreateActContextParametersSource createActContextParametersSource = default(CreateActContextParametersSource);
			createActContextParametersSource.Size = (uint)Marshal.SizeOf(typeof(CreateActContextParametersSource));
			createActContextParametersSource.Flags = 0u;
			createActContextParametersSource.SourceType = 1u;
			createActContextParametersSource.Data = IntPtr.Zero;
			CreateActContextParametersSourceDefinitionAppid createActContextParametersSourceDefinitionAppid = default(CreateActContextParametersSourceDefinitionAppid);
			createActContextParametersSourceDefinitionAppid.Size = (uint)Marshal.SizeOf(typeof(CreateActContextParametersSourceDefinitionAppid));
			createActContextParametersSourceDefinitionAppid.Flags = 0u;
			createActContextParametersSourceDefinitionAppid.AppId = AppId;
			try
			{
				createActContextParametersSource.Data = createActContextParametersSourceDefinitionAppid.ToIntPtr();
				Params.Source = createActContextParametersSource.ToIntPtr();
				return CreateActContext(ref Params) as IActContext;
			}
			finally
			{
				if (createActContextParametersSource.Data != IntPtr.Zero)
				{
					CreateActContextParametersSourceDefinitionAppid.Destroy(createActContextParametersSource.Data);
					createActContextParametersSource.Data = IntPtr.Zero;
				}
				if (Params.Source != IntPtr.Zero)
				{
					CreateActContextParametersSource.Destroy(Params.Source);
					Params.Source = IntPtr.Zero;
				}
			}
		}

		internal static IActContext CreateActContext(IReferenceAppId AppId)
		{
			CreateActContextParameters Params = default(CreateActContextParameters);
			Params.Size = (uint)Marshal.SizeOf(typeof(CreateActContextParameters));
			Params.Flags = 16u;
			Params.CustomStoreList = IntPtr.Zero;
			Params.CultureFallbackList = IntPtr.Zero;
			Params.ProcessorArchitectureList = IntPtr.Zero;
			Params.Source = IntPtr.Zero;
			Params.ProcArch = 0;
			CreateActContextParametersSource createActContextParametersSource = default(CreateActContextParametersSource);
			createActContextParametersSource.Size = (uint)Marshal.SizeOf(typeof(CreateActContextParametersSource));
			createActContextParametersSource.Flags = 0u;
			createActContextParametersSource.SourceType = 2u;
			createActContextParametersSource.Data = IntPtr.Zero;
			CreateActContextParametersSourceReferenceAppid createActContextParametersSourceReferenceAppid = default(CreateActContextParametersSourceReferenceAppid);
			createActContextParametersSourceReferenceAppid.Size = (uint)Marshal.SizeOf(typeof(CreateActContextParametersSourceReferenceAppid));
			createActContextParametersSourceReferenceAppid.Flags = 0u;
			createActContextParametersSourceReferenceAppid.AppId = AppId;
			try
			{
				createActContextParametersSource.Data = createActContextParametersSourceReferenceAppid.ToIntPtr();
				Params.Source = createActContextParametersSource.ToIntPtr();
				return CreateActContext(ref Params) as IActContext;
			}
			finally
			{
				if (createActContextParametersSource.Data != IntPtr.Zero)
				{
					CreateActContextParametersSourceDefinitionAppid.Destroy(createActContextParametersSource.Data);
					createActContextParametersSource.Data = IntPtr.Zero;
				}
				if (Params.Source != IntPtr.Zero)
				{
					CreateActContextParametersSource.Destroy(Params.Source);
					Params.Source = IntPtr.Zero;
				}
			}
		}

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.IUnknown)]
		internal static extern object CreateActContext(ref CreateActContextParameters Params);

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.IUnknown)]
		internal static extern object CreateCMSFromXml([In] byte[] buffer, [In] uint bufferSize, [In] IManifestParseErrorCallback Callback, [In] ref Guid riid);

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.IUnknown)]
		internal static extern object ParseManifest([In][MarshalAs(UnmanagedType.LPWStr)] string pszManifestPath, [In] IManifestParseErrorCallback pIManifestParseErrorCallback, [In] ref Guid riid);

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.IUnknown)]
		private static extern object GetUserStore([In] uint Flags, [In] IntPtr hToken, [In] ref Guid riid);

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.IUnknown)]
		private static extern object GetSystemStore([In] uint Flags, [In] ref Guid riid);

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.Interface)]
		private static extern IIdentityAuthority GetIdentityAuthority();

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.Interface)]
		private static extern IAppIdAuthority GetAppIdAuthority();

		[DllImport("mscorwks.dll", PreserveSig = false)]
		[return: MarshalAs(UnmanagedType.IUnknown)]
		internal static extern object GetUserStateManager([In] uint Flags, [In] IntPtr hToken, [In] ref Guid riid);

		internal static Guid GetGuidOfType(Type type)
		{
			GuidAttribute guidAttribute = (GuidAttribute)Attribute.GetCustomAttribute(type, typeof(GuidAttribute), inherit: false);
			return new Guid(guidAttribute.Value);
		}
	}
	internal class ApplicationContext
	{
		public enum ApplicationState
		{
			Undefined,
			Starting,
			Running
		}

		public enum ApplicationStateDisposition
		{
			Undefined = 0,
			Starting = 1,
			Starting_Migrated = 65537,
			Running = 2,
			Running_FirstTime = 131074
		}

		private IActContext _appcontext;

		public DefinitionAppId Identity
		{
			get
			{
				_appcontext.GetAppId(out var AppId);
				return new DefinitionAppId(AppId as IDefinitionAppId);
			}
		}

		public string BasePath
		{
			get
			{
				_appcontext.ApplicationBasePath(0u, out var ApplicationPath);
				return ApplicationPath;
			}
		}

		public EnumDefinitionIdentity Components
		{
			get
			{
				_appcontext.EnumComponents(0u, out var ppIdentityEnum);
				return new EnumDefinitionIdentity(ppIdentityEnum as IEnumDefinitionIdentity);
			}
		}

		public string StateLocation
		{
			get
			{
				_appcontext.GetApplicationStateFilesystemLocation(0u, UIntPtr.Zero, IntPtr.Zero, out var ppszPath);
				return ppszPath;
			}
		}

		internal ApplicationContext(IActContext a)
		{
			if (a == null)
			{
				throw new ArgumentNullException();
			}
			_appcontext = a;
		}

		public ApplicationContext(DefinitionAppId appid)
		{
			if (appid == null)
			{
				throw new ArgumentNullException();
			}
			_appcontext = IsolationInterop.CreateActContext(appid._id);
		}

		public ApplicationContext(ReferenceAppId appid)
		{
			if (appid == null)
			{
				throw new ArgumentNullException();
			}
			_appcontext = IsolationInterop.CreateActContext(appid._id);
		}

		public string ReplaceStrings(string culture, string toreplace)
		{
			_appcontext.ReplaceStringMacros(0u, culture, toreplace, out var Replaced);
			return Replaced;
		}

		internal System.Deployment.Internal.Isolation.Manifest.ICMS GetComponentManifest(DefinitionIdentity component)
		{
			_appcontext.GetComponentManifest(0u, component._id, ref IsolationInterop.IID_ICMS, out var ManifestInteface);
			return ManifestInteface as System.Deployment.Internal.Isolation.Manifest.ICMS;
		}

		internal string GetComponentManifestPath(DefinitionIdentity component)
		{
			_appcontext.GetComponentManifest(0u, component._id, ref IsolationInterop.IID_IManifestInformation, out var ManifestInteface);
			((IManifestInformation)ManifestInteface).get_FullPath(out var FullPath);
			return FullPath;
		}

		public string GetComponentPath(DefinitionIdentity component)
		{
			_appcontext.GetComponentPayloadPath(0u, component._id, out var PayloadPath);
			return PayloadPath;
		}

		public DefinitionIdentity MatchReference(ReferenceIdentity TheRef)
		{
			_appcontext.FindReferenceInContext(0u, TheRef._id, out var MatchedDefinition);
			return new DefinitionIdentity(MatchedDefinition as IDefinitionIdentity);
		}

		public void PrepareForExecution()
		{
			_appcontext.PrepareForExecution(IntPtr.Zero, IntPtr.Zero);
		}

		public ApplicationStateDisposition SetApplicationState(ApplicationState s)
		{
			_appcontext.SetApplicationRunningState(0u, (uint)s, out var ulDisposition);
			return (ApplicationStateDisposition)ulDisposition;
		}
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("81c85208-fe61-4c15-b5bb-ff5ea66baad9")]
	internal interface IManifestInformation
	{
		void get_FullPath([MarshalAs(UnmanagedType.LPWStr)] out string FullPath);
	}
	[ComImport]
	[Guid("0af57545-a72a-4fbe-813c-8554ed7d4528")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IActContext
	{
		void GetAppId([MarshalAs(UnmanagedType.Interface)] out object AppId);

		void EnumCategories([In] uint Flags, [In] IReferenceIdentity CategoryToMatch, [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object EnumOut);

		void EnumSubcategories([In] uint Flags, [In] IDefinitionIdentity CategoryId, [In][MarshalAs(UnmanagedType.LPWStr)] string SubcategoryPattern, [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object EnumOut);

		void EnumCategoryInstances([In] uint Flags, [In] IDefinitionIdentity CategoryId, [In][MarshalAs(UnmanagedType.LPWStr)] string Subcategory, [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object EnumOut);

		void ReplaceStringMacros([In] uint Flags, [In][MarshalAs(UnmanagedType.LPWStr)] string Culture, [In][MarshalAs(UnmanagedType.LPWStr)] string ReplacementPattern, [MarshalAs(UnmanagedType.LPWStr)] out string Replaced);

		void GetComponentStringTableStrings([In] uint Flags, [In][MarshalAs(UnmanagedType.SysUInt)] IntPtr ComponentIndex, [In][MarshalAs(UnmanagedType.SysUInt)] IntPtr StringCount, [Out][MarshalAs(UnmanagedType.LPArray)] string[] SourceStrings, [MarshalAs(UnmanagedType.LPArray)] out string[] DestinationStrings, [In][MarshalAs(UnmanagedType.SysUInt)] IntPtr CultureFallbacks);

		void GetApplicationProperties([In] uint Flags, [In] UIntPtr cProperties, [In][MarshalAs(UnmanagedType.LPArray)] string[] PropertyNames, [MarshalAs(UnmanagedType.LPArray)] out string[] PropertyValues, [MarshalAs(UnmanagedType.LPArray)] out UIntPtr[] ComponentIndicies);

		void ApplicationBasePath([In] uint Flags, [MarshalAs(UnmanagedType.LPWStr)] out string ApplicationPath);

		void GetComponentManifest([In] uint Flags, [In] IDefinitionIdentity ComponentId, [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ManifestInteface);

		void GetComponentPayloadPath([In] uint Flags, [In] IDefinitionIdentity ComponentId, [MarshalAs(UnmanagedType.LPWStr)] out string PayloadPath);

		void FindReferenceInContext([In] uint dwFlags, [In] IReferenceIdentity Reference, [MarshalAs(UnmanagedType.Interface)] out object MatchedDefinition);

		void CreateActContextFromCategoryInstance([In] uint dwFlags, [In] ref CATEGORY_INSTANCE CategoryInstance, [MarshalAs(UnmanagedType.Interface)] out object ppCreatedAppContext);

		void EnumComponents([In] uint dwFlags, [MarshalAs(UnmanagedType.Interface)] out object ppIdentityEnum);

		void PrepareForExecution([In][MarshalAs(UnmanagedType.SysInt)] IntPtr Inputs, [In][MarshalAs(UnmanagedType.SysInt)] IntPtr Outputs);

		void SetApplicationRunningState([In] uint dwFlags, [In] uint ulState, out uint ulDisposition);

		void GetApplicationStateFilesystemLocation([In] uint dwFlags, [In] UIntPtr Component, [In][MarshalAs(UnmanagedType.SysInt)] IntPtr pCoordinateList, [MarshalAs(UnmanagedType.LPWStr)] out string ppszPath);

		void FindComponentsByDefinition([In] uint dwFlags, [In] UIntPtr ComponentCount, [In][MarshalAs(UnmanagedType.LPArray)] IDefinitionIdentity[] Components, [Out][MarshalAs(UnmanagedType.LPArray)] UIntPtr[] Indicies, [Out][MarshalAs(UnmanagedType.LPArray)] uint[] Dispositions);

		void FindComponentsByReference([In] uint dwFlags, [In] UIntPtr Components, [In][MarshalAs(UnmanagedType.LPArray)] IReferenceIdentity[] References, [Out][MarshalAs(UnmanagedType.LPArray)] UIntPtr[] Indicies, [Out][MarshalAs(UnmanagedType.LPArray)] uint[] Dispositions);
	}
	internal enum StateManager_RunningState
	{
		Undefined,
		Starting,
		Running
	}
	[ComImport]
	[Guid("07662534-750b-4ed5-9cfb-1c5bc5acfd07")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IStateManager
	{
		void PrepareApplicationState([In] UIntPtr Inputs, ref UIntPtr Outputs);

		void SetApplicationRunningState([In] uint Flags, [In] IActContext Context, [In] uint RunningState, out uint Disposition);

		void GetApplicationStateFilesystemLocation([In] uint Flags, [In] IDefinitionAppId Appidentity, [In] IDefinitionIdentity ComponentIdentity, [In] UIntPtr Coordinates, [MarshalAs(UnmanagedType.LPWStr)] out string Path);

		void Scavenge([In] uint Flags, out uint Disposition);
	}
}
namespace System.Deployment.Internal.Isolation.Manifest
{
	internal enum CMSSECTIONID
	{
		CMSSECTIONID_FILE_SECTION = 1,
		CMSSECTIONID_CATEGORY_INSTANCE_SECTION = 2,
		CMSSECTIONID_COM_REDIRECTION_SECTION = 3,
		CMSSECTIONID_PROGID_REDIRECTION_SECTION = 4,
		CMSSECTIONID_CLR_SURROGATE_SECTION = 5,
		CMSSECTIONID_ASSEMBLY_REFERENCE_SECTION = 6,
		CMSSECTIONID_WINDOW_CLASS_SECTION = 8,
		CMSSECTIONID_STRING_SECTION = 9,
		CMSSECTIONID_ENTRYPOINT_SECTION = 10,
		CMSSECTIONID_PERMISSION_SET_SECTION = 11,
		CMSSECTIONENTRYID_METADATA = 12,
		CMSSECTIONID_ASSEMBLY_REQUEST_SECTION = 13,
		CMSSECTIONID_REGISTRY_KEY_SECTION = 16,
		CMSSECTIONID_DIRECTORY_SECTION = 17,
		CMSSECTIONID_FILE_ASSOCIATION_SECTION = 18,
		CMSSECTIONID_EVENT_SECTION = 101,
		CMSSECTIONID_EVENT_MAP_SECTION = 102,
		CMSSECTIONID_EVENT_TAG_SECTION = 103,
		CMSSECTIONID_COUNTERSET_SECTION = 110,
		CMSSECTIONID_COUNTER_SECTION = 111
	}
	internal enum CMS_ASSEMBLY_DEPLOYMENT_FLAG
	{
		CMS_ASSEMBLY_DEPLOYMENT_FLAG_BEFORE_APPLICATION_STARTUP = 4,
		CMS_ASSEMBLY_DEPLOYMENT_FLAG_RUN_AFTER_INSTALL = 0x10,
		CMS_ASSEMBLY_DEPLOYMENT_FLAG_INSTALL = 0x20,
		CMS_ASSEMBLY_DEPLOYMENT_FLAG_TRUST_URL_PARAMETERS = 0x40,
		CMS_ASSEMBLY_DEPLOYMENT_FLAG_DISALLOW_URL_ACTIVATION = 0x80,
		CMS_ASSEMBLY_DEPLOYMENT_FLAG_MAP_FILE_EXTENSIONS = 0x100,
		CMS_ASSEMBLY_DEPLOYMENT_FLAG_CREATE_DESKTOP_SHORTCUT = 0x200
	}
	internal enum CMS_ASSEMBLY_REFERENCE_FLAG
	{
		CMS_ASSEMBLY_REFERENCE_FLAG_OPTIONAL = 1,
		CMS_ASSEMBLY_REFERENCE_FLAG_VISIBLE = 2,
		CMS_ASSEMBLY_REFERENCE_FLAG_FOLLOW = 4,
		CMS_ASSEMBLY_REFERENCE_FLAG_IS_PLATFORM = 8,
		CMS_ASSEMBLY_REFERENCE_FLAG_CULTURE_WILDCARDED = 0x10,
		CMS_ASSEMBLY_REFERENCE_FLAG_PROCESSOR_ARCHITECTURE_WILDCARDED = 0x20,
		CMS_ASSEMBLY_REFERENCE_FLAG_PREREQUISITE = 0x80
	}
	internal enum CMS_ASSEMBLY_REFERENCE_DEPENDENT_ASSEMBLY_FLAG
	{
		CMS_ASSEMBLY_REFERENCE_DEPENDENT_ASSEMBLY_FLAG_OPTIONAL = 1,
		CMS_ASSEMBLY_REFERENCE_DEPENDENT_ASSEMBLY_FLAG_VISIBLE = 2,
		CMS_ASSEMBLY_REFERENCE_DEPENDENT_ASSEMBLY_FLAG_PREREQUISITE = 4,
		CMS_ASSEMBLY_REFERENCE_DEPENDENT_ASSEMBLY_FLAG_RESOURCE_FALLBACK_CULTURE_INTERNAL = 8,
		CMS_ASSEMBLY_REFERENCE_DEPENDENT_ASSEMBLY_FLAG_INSTALL = 0x10,
		CMS_ASSEMBLY_REFERENCE_DEPENDENT_ASSEMBLY_FLAG_ALLOW_DELAYED_BINDING = 0x20
	}
	internal enum CMS_FILE_FLAG
	{
		CMS_FILE_FLAG_OPTIONAL = 1
	}
	internal enum CMS_ENTRY_POINT_FLAG
	{
		CMS_ENTRY_POINT_FLAG_HOST_IN_BROWSER = 1,
		CMS_ENTRY_POINT_FLAG_CUSTOMHOSTSPECIFIED = 2,
		CMS_ENTRY_POINT_FLAG_CUSTOMUX = 4
	}
	internal enum CMS_COM_SERVER_FLAG
	{
		CMS_COM_SERVER_FLAG_IS_CLR_CLASS = 1
	}
	internal enum CMS_REGISTRY_KEY_FLAG
	{
		CMS_REGISTRY_KEY_FLAG_OWNER = 1,
		CMS_REGISTRY_KEY_FLAG_LEAF_IN_MANIFEST
	}
	internal enum CMS_REGISTRY_VALUE_FLAG
	{
		CMS_REGISTRY_VALUE_FLAG_OWNER = 1
	}
	internal enum CMS_DIRECTORY_FLAG
	{
		CMS_DIRECTORY_FLAG_OWNER = 1
	}
	internal enum CMS_MANIFEST_FLAG
	{
		CMS_MANIFEST_FLAG_ASSEMBLY = 1,
		CMS_MANIFEST_FLAG_CATEGORY = 2,
		CMS_MANIFEST_FLAG_FEATURE = 3,
		CMS_MANIFEST_FLAG_APPLICATION = 4,
		CMS_MANIFEST_FLAG_USEMANIFESTFORTRUST = 8
	}
	internal enum CMS_USAGE_PATTERN
	{
		CMS_USAGE_PATTERN_SCOPE_APPLICATION = 1,
		CMS_USAGE_PATTERN_SCOPE_PROCESS = 2,
		CMS_USAGE_PATTERN_SCOPE_MACHINE = 3,
		CMS_USAGE_PATTERN_SCOPE_MASK = 7
	}
	internal enum CMS_SCHEMA_VERSION
	{
		CMS_SCHEMA_VERSION_V1 = 1
	}
	internal enum CMS_FILE_HASH_ALGORITHM
	{
		CMS_FILE_HASH_ALGORITHM_SHA1 = 1,
		CMS_FILE_HASH_ALGORITHM_SHA256,
		CMS_FILE_HASH_ALGORITHM_SHA384,
		CMS_FILE_HASH_ALGORITHM_SHA512,
		CMS_FILE_HASH_ALGORITHM_MD5,
		CMS_FILE_HASH_ALGORITHM_MD4,
		CMS_FILE_HASH_ALGORITHM_MD2
	}
	internal enum CMS_TIME_UNIT_TYPE
	{
		CMS_TIME_UNIT_TYPE_HOURS = 1,
		CMS_TIME_UNIT_TYPE_DAYS,
		CMS_TIME_UNIT_TYPE_WEEKS,
		CMS_TIME_UNIT_TYPE_MONTHS
	}
	internal enum CMS_REGISTRY_VALUE_TYPE
	{
		CMS_REGISTRY_VALUE_TYPE_NONE,
		CMS_REGISTRY_VALUE_TYPE_SZ,
		CMS_REGISTRY_VALUE_TYPE_EXPAND_SZ,
		CMS_REGISTRY_VALUE_TYPE_MULTI_SZ,
		CMS_REGISTRY_VALUE_TYPE_BINARY,
		CMS_REGISTRY_VALUE_TYPE_DWORD,
		CMS_REGISTRY_VALUE_TYPE_DWORD_LITTLE_ENDIAN,
		CMS_REGISTRY_VALUE_TYPE_DWORD_BIG_ENDIAN,
		CMS_REGISTRY_VALUE_TYPE_LINK,
		CMS_REGISTRY_VALUE_TYPE_RESOURCE_LIST,
		CMS_REGISTRY_VALUE_TYPE_FULL_RESOURCE_DESCRIPTOR,
		CMS_REGISTRY_VALUE_TYPE_RESOURCE_REQUIREMENTS_LIST,
		CMS_REGISTRY_VALUE_TYPE_QWORD,
		CMS_REGISTRY_VALUE_TYPE_QWORD_LITTLE_ENDIAN
	}
	internal enum CMS_REGISTRY_VALUE_HINT
	{
		CMS_REGISTRY_VALUE_HINT_REPLACE = 1,
		CMS_REGISTRY_VALUE_HINT_APPEND,
		CMS_REGISTRY_VALUE_HINT_PREPEND
	}
	internal enum CMS_SYSTEM_PROTECTION
	{
		CMS_SYSTEM_PROTECTION_READ_ONLY_IGNORE_WRITES = 1,
		CMS_SYSTEM_PROTECTION_READ_ONLY_FAIL_WRITES,
		CMS_SYSTEM_PROTECTION_OS_ONLY_IGNORE_WRITES,
		CMS_SYSTEM_PROTECTION_OS_ONLY_FAIL_WRITES,
		CMS_SYSTEM_PROTECTION_TRANSACTED,
		CMS_SYSTEM_PROTECTION_APPLICATION_VIRTUALIZED,
		CMS_SYSTEM_PROTECTION_USER_VIRTUALIZED,
		CMS_SYSTEM_PROTECTION_APPLICATION_AND_USER_VIRTUALIZED,
		CMS_SYSTEM_PROTECTION_INHERIT,
		CMS_SYSTEM_PROTECTION_NOT_PROTECTED
	}
	internal enum CMS_FILE_WRITABLE_TYPE
	{
		CMS_FILE_WRITABLE_TYPE_NOT_WRITABLE = 1,
		CMS_FILE_WRITABLE_TYPE_APPLICATION_DATA
	}
	internal enum CMS_HASH_TRANSFORM
	{
		CMS_HASH_TRANSFORM_IDENTITY = 1,
		CMS_HASH_TRANSFORM_MANIFESTINVARIANT
	}
	internal enum CMS_HASH_DIGESTMETHOD
	{
		CMS_HASH_DIGESTMETHOD_SHA1 = 1,
		CMS_HASH_DIGESTMETHOD_SHA256,
		CMS_HASH_DIGESTMETHOD_SHA384,
		CMS_HASH_DIGESTMETHOD_SHA512
	}
	[ComImport]
	[Guid("a504e5b0-8ccf-4cb4-9902-c9d1b9abd033")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ICMS
	{
		IDefinitionIdentity Identity { get; }

		ISection FileSection { get; }

		ISection CategoryMembershipSection { get; }

		ISection COMRedirectionSection { get; }

		ISection ProgIdRedirectionSection { get; }

		ISection CLRSurrogateSection { get; }

		ISection AssemblyReferenceSection { get; }

		ISection WindowClassSection { get; }

		ISection StringSection { get; }

		ISection EntryPointSection { get; }

		ISection PermissionSetSection { get; }

		ISectionEntry MetadataSectionEntry { get; }

		ISection AssemblyRequestSection { get; }

		ISection RegistryKeySection { get; }

		ISection DirectorySection { get; }

		ISection FileAssociationSection { get; }

		ISection EventSection { get; }

		ISection EventMapSection { get; }

		ISection EventTagSection { get; }

		ISection CounterSetSection { get; }

		ISection CounterSection { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class MuiResourceIdLookupMapEntry
	{
		public uint Count;
	}
	internal enum MuiResourceIdLookupMapEntryFieldId
	{
		MuiResourceIdLookupMap_Count
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("24abe1f7-a396-4a03-9adf-1d5b86a5569f")]
	internal interface IMuiResourceIdLookupMapEntry
	{
		MuiResourceIdLookupMapEntry AllData { get; }

		uint Count { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class MuiResourceTypeIdStringEntry : IDisposable
	{
		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr StringIds;

		public uint StringIdsSize;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr IntegerIds;

		public uint IntegerIdsSize;

		~MuiResourceTypeIdStringEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (StringIds != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(StringIds);
				StringIds = IntPtr.Zero;
			}
			if (IntegerIds != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(IntegerIds);
				IntegerIds = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum MuiResourceTypeIdStringEntryFieldId
	{
		MuiResourceTypeIdString_StringIds,
		MuiResourceTypeIdString_StringIdsSize,
		MuiResourceTypeIdString_IntegerIds,
		MuiResourceTypeIdString_IntegerIdsSize
	}
	[ComImport]
	[Guid("11df5cad-c183-479b-9a44-3842b71639ce")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IMuiResourceTypeIdStringEntry
	{
		MuiResourceTypeIdStringEntry AllData { get; }

		object StringIds
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		object IntegerIds
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class MuiResourceTypeIdIntEntry : IDisposable
	{
		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr StringIds;

		public uint StringIdsSize;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr IntegerIds;

		public uint IntegerIdsSize;

		~MuiResourceTypeIdIntEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (StringIds != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(StringIds);
				StringIds = IntPtr.Zero;
			}
			if (IntegerIds != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(IntegerIds);
				IntegerIds = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum MuiResourceTypeIdIntEntryFieldId
	{
		MuiResourceTypeIdInt_StringIds,
		MuiResourceTypeIdInt_StringIdsSize,
		MuiResourceTypeIdInt_IntegerIds,
		MuiResourceTypeIdInt_IntegerIdsSize
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("55b2dec1-d0f6-4bf4-91b1-30f73ad8e4df")]
	internal interface IMuiResourceTypeIdIntEntry
	{
		MuiResourceTypeIdIntEntry AllData { get; }

		object StringIds
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		object IntegerIds
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class MuiResourceMapEntry : IDisposable
	{
		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr ResourceTypeIdInt;

		public uint ResourceTypeIdIntSize;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr ResourceTypeIdString;

		public uint ResourceTypeIdStringSize;

		~MuiResourceMapEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (ResourceTypeIdInt != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(ResourceTypeIdInt);
				ResourceTypeIdInt = IntPtr.Zero;
			}
			if (ResourceTypeIdString != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(ResourceTypeIdString);
				ResourceTypeIdString = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum MuiResourceMapEntryFieldId
	{
		MuiResourceMap_ResourceTypeIdInt,
		MuiResourceMap_ResourceTypeIdIntSize,
		MuiResourceMap_ResourceTypeIdString,
		MuiResourceMap_ResourceTypeIdStringSize
	}
	[ComImport]
	[Guid("397927f5-10f2-4ecb-bfe1-3c264212a193")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IMuiResourceMapEntry
	{
		MuiResourceMapEntry AllData { get; }

		object ResourceTypeIdInt
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		object ResourceTypeIdString
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class HashElementEntry : IDisposable
	{
		public uint index;

		public byte Transform;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr TransformMetadata;

		public uint TransformMetadataSize;

		public byte DigestMethod;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr DigestValue;

		public uint DigestValueSize;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Xml;

		~HashElementEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (TransformMetadata != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(TransformMetadata);
				TransformMetadata = IntPtr.Zero;
			}
			if (DigestValue != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(DigestValue);
				DigestValue = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum HashElementEntryFieldId
	{
		HashElement_Transform,
		HashElement_TransformMetadata,
		HashElement_TransformMetadataSize,
		HashElement_DigestMethod,
		HashElement_DigestValue,
		HashElement_DigestValueSize,
		HashElement_Xml
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("9D46FB70-7B54-4f4f-9331-BA9E87833FF5")]
	internal interface IHashElementEntry
	{
		HashElementEntry AllData { get; }

		uint index { get; }

		byte Transform { get; }

		object TransformMetadata
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		byte DigestMethod { get; }

		object DigestValue
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		string Xml
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class FileEntry : IDisposable
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		public uint HashAlgorithm;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string LoadFrom;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string SourcePath;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ImportPath;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string SourceName;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Location;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr HashValue;

		public uint HashValueSize;

		public ulong Size;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Group;

		public uint Flags;

		public MuiResourceMapEntry MuiMapping;

		public uint WritableType;

		public ISection HashElements;

		~FileEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (HashValue != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(HashValue);
				HashValue = IntPtr.Zero;
			}
			if (fDisposing)
			{
				if (MuiMapping != null)
				{
					MuiMapping.Dispose(fDisposing: true);
					MuiMapping = null;
				}
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum FileEntryFieldId
	{
		File_HashAlgorithm,
		File_LoadFrom,
		File_SourcePath,
		File_ImportPath,
		File_SourceName,
		File_Location,
		File_HashValue,
		File_HashValueSize,
		File_Size,
		File_Group,
		File_Flags,
		File_MuiMapping,
		File_WritableType,
		File_HashElements
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("A2A55FAD-349B-469b-BF12-ADC33D14A937")]
	internal interface IFileEntry
	{
		FileEntry AllData { get; }

		string Name
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint HashAlgorithm { get; }

		string LoadFrom
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string SourcePath
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string ImportPath
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string SourceName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Location
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		object HashValue
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		ulong Size { get; }

		string Group
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint Flags { get; }

		IMuiResourceMapEntry MuiMapping { get; }

		uint WritableType { get; }

		ISection HashElements { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class FileAssociationEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Extension;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Description;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ProgID;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string DefaultIcon;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Parameter;
	}
	internal enum FileAssociationEntryFieldId
	{
		FileAssociation_Description,
		FileAssociation_ProgID,
		FileAssociation_DefaultIcon,
		FileAssociation_Parameter
	}
	[ComImport]
	[Guid("0C66F299-E08E-48c5-9264-7CCBEB4D5CBB")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IFileAssociationEntry
	{
		FileAssociationEntry AllData { get; }

		string Extension
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Description
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string ProgID
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string DefaultIcon
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Parameter
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class CategoryMembershipDataEntry
	{
		public uint index;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Xml;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Description;
	}
	internal enum CategoryMembershipDataEntryFieldId
	{
		CategoryMembershipData_Xml,
		CategoryMembershipData_Description
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("DA0C3B27-6B6B-4b80-A8F8-6CE14F4BC0A4")]
	internal interface ICategoryMembershipDataEntry
	{
		CategoryMembershipDataEntry AllData { get; }

		uint index { get; }

		string Xml
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Description
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class SubcategoryMembershipEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Subcategory;

		public ISection CategoryMembershipData;
	}
	internal enum SubcategoryMembershipEntryFieldId
	{
		SubcategoryMembership_CategoryMembershipData
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("5A7A54D7-5AD5-418e-AB7A-CF823A8D48D0")]
	internal interface ISubcategoryMembershipEntry
	{
		SubcategoryMembershipEntry AllData { get; }

		string Subcategory
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		ISection CategoryMembershipData { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class CategoryMembershipEntry
	{
		public IDefinitionIdentity Identity;

		public ISection SubcategoryMembership;
	}
	internal enum CategoryMembershipEntryFieldId
	{
		CategoryMembership_SubcategoryMembership
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("97FDCA77-B6F2-4718-A1EB-29D0AECE9C03")]
	internal interface ICategoryMembershipEntry
	{
		CategoryMembershipEntry AllData { get; }

		IDefinitionIdentity Identity { get; }

		ISection SubcategoryMembership { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class COMServerEntry
	{
		public Guid Clsid;

		public uint Flags;

		public Guid ConfiguredGuid;

		public Guid ImplementedClsid;

		public Guid TypeLibrary;

		public uint ThreadingModel;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string RuntimeVersion;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string HostFile;
	}
	internal enum COMServerEntryFieldId
	{
		COMServer_Flags,
		COMServer_ConfiguredGuid,
		COMServer_ImplementedClsid,
		COMServer_TypeLibrary,
		COMServer_ThreadingModel,
		COMServer_RuntimeVersion,
		COMServer_HostFile
	}
	[ComImport]
	[Guid("3903B11B-FBE8-477c-825F-DB828B5FD174")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ICOMServerEntry
	{
		COMServerEntry AllData { get; }

		Guid Clsid { get; }

		uint Flags { get; }

		Guid ConfiguredGuid { get; }

		Guid ImplementedClsid { get; }

		Guid TypeLibrary { get; }

		uint ThreadingModel { get; }

		string RuntimeVersion
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string HostFile
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class ProgIdRedirectionEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string ProgId;

		public Guid RedirectedGuid;
	}
	internal enum ProgIdRedirectionEntryFieldId
	{
		ProgIdRedirection_RedirectedGuid
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("54F198EC-A63A-45ea-A984-452F68D9B35B")]
	internal interface IProgIdRedirectionEntry
	{
		ProgIdRedirectionEntry AllData { get; }

		string ProgId
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		Guid RedirectedGuid { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class CLRSurrogateEntry
	{
		public Guid Clsid;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string RuntimeVersion;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ClassName;
	}
	internal enum CLRSurrogateEntryFieldId
	{
		CLRSurrogate_RuntimeVersion,
		CLRSurrogate_ClassName
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("1E0422A1-F0D2-44ae-914B-8A2DECCFD22B")]
	internal interface ICLRSurrogateEntry
	{
		CLRSurrogateEntry AllData { get; }

		Guid Clsid { get; }

		string RuntimeVersion
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string ClassName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class AssemblyReferenceDependentAssemblyEntry : IDisposable
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Group;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Codebase;

		public ulong Size;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr HashValue;

		public uint HashValueSize;

		public uint HashAlgorithm;

		public uint Flags;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ResourceFallbackCulture;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Description;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string SupportUrl;

		public ISection HashElements;

		~AssemblyReferenceDependentAssemblyEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (HashValue != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(HashValue);
				HashValue = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum AssemblyReferenceDependentAssemblyEntryFieldId
	{
		AssemblyReferenceDependentAssembly_Group,
		AssemblyReferenceDependentAssembly_Codebase,
		AssemblyReferenceDependentAssembly_Size,
		AssemblyReferenceDependentAssembly_HashValue,
		AssemblyReferenceDependentAssembly_HashValueSize,
		AssemblyReferenceDependentAssembly_HashAlgorithm,
		AssemblyReferenceDependentAssembly_Flags,
		AssemblyReferenceDependentAssembly_ResourceFallbackCulture,
		AssemblyReferenceDependentAssembly_Description,
		AssemblyReferenceDependentAssembly_SupportUrl,
		AssemblyReferenceDependentAssembly_HashElements
	}
	[ComImport]
	[Guid("C31FF59E-CD25-47b8-9EF3-CF4433EB97CC")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IAssemblyReferenceDependentAssemblyEntry
	{
		AssemblyReferenceDependentAssemblyEntry AllData { get; }

		string Group
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Codebase
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		ulong Size { get; }

		object HashValue
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		uint HashAlgorithm { get; }

		uint Flags { get; }

		string ResourceFallbackCulture
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Description
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string SupportUrl
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		ISection HashElements { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class AssemblyReferenceEntry
	{
		public IReferenceIdentity ReferenceIdentity;

		public uint Flags;

		public AssemblyReferenceDependentAssemblyEntry DependentAssembly;
	}
	internal enum AssemblyReferenceEntryFieldId
	{
		AssemblyReference_Flags,
		AssemblyReference_DependentAssembly
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("FD47B733-AFBC-45e4-B7C2-BBEB1D9F766C")]
	internal interface IAssemblyReferenceEntry
	{
		AssemblyReferenceEntry AllData { get; }

		IReferenceIdentity ReferenceIdentity { get; }

		uint Flags { get; }

		IAssemblyReferenceDependentAssemblyEntry DependentAssembly { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class WindowClassEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string ClassName;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string HostDll;

		public bool fVersioned;
	}
	internal enum WindowClassEntryFieldId
	{
		WindowClass_HostDll,
		WindowClass_fVersioned
	}
	[ComImport]
	[Guid("8AD3FC86-AFD3-477a-8FD5-146C291195BA")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IWindowClassEntry
	{
		WindowClassEntry AllData { get; }

		string ClassName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string HostDll
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		bool fVersioned { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class ResourceTableMappingEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string id;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string FinalStringMapped;
	}
	internal enum ResourceTableMappingEntryFieldId
	{
		ResourceTableMapping_FinalStringMapped
	}
	[ComImport]
	[Guid("70A4ECEE-B195-4c59-85BF-44B6ACA83F07")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IResourceTableMappingEntry
	{
		ResourceTableMappingEntry AllData { get; }

		string id
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string FinalStringMapped
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class EntryPointEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string CommandLine_File;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string CommandLine_Parameters;

		public IReferenceIdentity Identity;

		public uint Flags;
	}
	internal enum EntryPointEntryFieldId
	{
		EntryPoint_CommandLine_File,
		EntryPoint_CommandLine_Parameters,
		EntryPoint_Identity,
		EntryPoint_Flags
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("1583EFE9-832F-4d08-B041-CAC5ACEDB948")]
	internal interface IEntryPointEntry
	{
		EntryPointEntry AllData { get; }

		string Name
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string CommandLine_File
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string CommandLine_Parameters
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		IReferenceIdentity Identity { get; }

		uint Flags { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class PermissionSetEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Id;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string XmlSegment;
	}
	internal enum PermissionSetEntryFieldId
	{
		PermissionSet_XmlSegment
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("EBE5A1ED-FEBC-42c4-A9E1-E087C6E36635")]
	internal interface IPermissionSetEntry
	{
		PermissionSetEntry AllData { get; }

		string Id
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string XmlSegment
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class AssemblyRequestEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string permissionSetID;
	}
	internal enum AssemblyRequestEntryFieldId
	{
		AssemblyRequest_permissionSetID
	}
	[ComImport]
	[Guid("2474ECB4-8EFD-4410-9F31-B3E7C4A07731")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IAssemblyRequestEntry
	{
		AssemblyRequestEntry AllData { get; }

		string Name
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string permissionSetID
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class DescriptionMetadataEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Publisher;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Product;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string SupportUrl;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string IconFile;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ErrorReportUrl;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string SuiteName;
	}
	internal enum DescriptionMetadataEntryFieldId
	{
		DescriptionMetadata_Publisher,
		DescriptionMetadata_Product,
		DescriptionMetadata_SupportUrl,
		DescriptionMetadata_IconFile,
		DescriptionMetadata_ErrorReportUrl,
		DescriptionMetadata_SuiteName
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("CB73147E-5FC2-4c31-B4E6-58D13DBE1A08")]
	internal interface IDescriptionMetadataEntry
	{
		DescriptionMetadataEntry AllData { get; }

		string Publisher
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Product
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string SupportUrl
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string IconFile
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string ErrorReportUrl
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string SuiteName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class DeploymentMetadataEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string DeploymentProviderCodebase;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string MinimumRequiredVersion;

		public ushort MaximumAge;

		public byte MaximumAge_Unit;

		public uint DeploymentFlags;
	}
	internal enum DeploymentMetadataEntryFieldId
	{
		DeploymentMetadata_DeploymentProviderCodebase,
		DeploymentMetadata_MinimumRequiredVersion,
		DeploymentMetadata_MaximumAge,
		DeploymentMetadata_MaximumAge_Unit,
		DeploymentMetadata_DeploymentFlags
	}
	[ComImport]
	[Guid("CFA3F59F-334D-46bf-A5A5-5D11BB2D7EBC")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IDeploymentMetadataEntry
	{
		DeploymentMetadataEntry AllData { get; }

		string DeploymentProviderCodebase
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string MinimumRequiredVersion
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		ushort MaximumAge { get; }

		byte MaximumAge_Unit { get; }

		uint DeploymentFlags { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class DependentOSMetadataEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string SupportUrl;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Description;

		public ushort MajorVersion;

		public ushort MinorVersion;

		public ushort BuildNumber;

		public byte ServicePackMajor;

		public byte ServicePackMinor;
	}
	internal enum DependentOSMetadataEntryFieldId
	{
		DependentOSMetadata_SupportUrl,
		DependentOSMetadata_Description,
		DependentOSMetadata_MajorVersion,
		DependentOSMetadata_MinorVersion,
		DependentOSMetadata_BuildNumber,
		DependentOSMetadata_ServicePackMajor,
		DependentOSMetadata_ServicePackMinor
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("CF168CF4-4E8F-4d92-9D2A-60E5CA21CF85")]
	internal interface IDependentOSMetadataEntry
	{
		DependentOSMetadataEntry AllData { get; }

		string SupportUrl
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Description
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		ushort MajorVersion { get; }

		ushort MinorVersion { get; }

		ushort BuildNumber { get; }

		byte ServicePackMajor { get; }

		byte ServicePackMinor { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class MetadataSectionEntry : IDisposable
	{
		public uint SchemaVersion;

		public uint ManifestFlags;

		public uint UsagePatterns;

		public IDefinitionIdentity CdfIdentity;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string LocalPath;

		public uint HashAlgorithm;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr ManifestHash;

		public uint ManifestHashSize;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string ContentType;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string RuntimeImageVersion;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr MvidValue;

		public uint MvidValueSize;

		public DescriptionMetadataEntry DescriptionData;

		public DeploymentMetadataEntry DeploymentData;

		public DependentOSMetadataEntry DependentOSData;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string defaultPermissionSetID;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string RequestedExecutionLevel;

		public bool RequestedExecutionLevelUIAccess;

		public IReferenceIdentity ResourceTypeResourcesDependency;

		public IReferenceIdentity ResourceTypeManifestResourcesDependency;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string KeyInfoElement;

		~MetadataSectionEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (ManifestHash != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(ManifestHash);
				ManifestHash = IntPtr.Zero;
			}
			if (MvidValue != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(MvidValue);
				MvidValue = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum MetadataSectionEntryFieldId
	{
		MetadataSection_SchemaVersion,
		MetadataSection_ManifestFlags,
		MetadataSection_UsagePatterns,
		MetadataSection_CdfIdentity,
		MetadataSection_LocalPath,
		MetadataSection_HashAlgorithm,
		MetadataSection_ManifestHash,
		MetadataSection_ManifestHashSize,
		MetadataSection_ContentType,
		MetadataSection_RuntimeImageVersion,
		MetadataSection_MvidValue,
		MetadataSection_MvidValueSize,
		MetadataSection_DescriptionData,
		MetadataSection_DeploymentData,
		MetadataSection_DependentOSData,
		MetadataSection_defaultPermissionSetID,
		MetadataSection_RequestedExecutionLevel,
		MetadataSection_RequestedExecutionLevelUIAccess,
		MetadataSection_ResourceTypeResourcesDependency,
		MetadataSection_ResourceTypeManifestResourcesDependency,
		MetadataSection_KeyInfoElement
	}
	[ComImport]
	[Guid("AB1ED79F-943E-407d-A80B-0744E3A95B28")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IMetadataSectionEntry
	{
		MetadataSectionEntry AllData { get; }

		uint SchemaVersion { get; }

		uint ManifestFlags { get; }

		uint UsagePatterns { get; }

		IDefinitionIdentity CdfIdentity { get; }

		string LocalPath
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint HashAlgorithm { get; }

		object ManifestHash
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		string ContentType
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string RuntimeImageVersion
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		object MvidValue
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		IDescriptionMetadataEntry DescriptionData { get; }

		IDeploymentMetadataEntry DeploymentData { get; }

		IDependentOSMetadataEntry DependentOSData { get; }

		string defaultPermissionSetID
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string RequestedExecutionLevel
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		bool RequestedExecutionLevelUIAccess { get; }

		IReferenceIdentity ResourceTypeResourcesDependency { get; }

		IReferenceIdentity ResourceTypeManifestResourcesDependency { get; }

		string KeyInfoElement
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class EventEntry
	{
		public uint EventID;

		public uint Level;

		public uint Version;

		public Guid Guid;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string SubTypeName;

		public uint SubTypeValue;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string DisplayName;

		public uint EventNameMicrodomIndex;
	}
	internal enum EventEntryFieldId
	{
		Event_Level,
		Event_Version,
		Event_Guid,
		Event_SubTypeName,
		Event_SubTypeValue,
		Event_DisplayName,
		Event_EventNameMicrodomIndex
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("8AD3FC86-AFD3-477a-8FD5-146C291195BB")]
	internal interface IEventEntry
	{
		EventEntry AllData { get; }

		uint EventID { get; }

		uint Level { get; }

		uint Version { get; }

		Guid Guid { get; }

		string SubTypeName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint SubTypeValue { get; }

		string DisplayName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint EventNameMicrodomIndex { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class EventMapEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string MapName;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		public uint Value;

		public bool IsValueMap;
	}
	internal enum EventMapEntryFieldId
	{
		EventMap_Name,
		EventMap_Value,
		EventMap_IsValueMap
	}
	[ComImport]
	[Guid("8AD3FC86-AFD3-477a-8FD5-146C291195BC")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEventMapEntry
	{
		EventMapEntry AllData { get; }

		string MapName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Name
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint Value { get; }

		bool IsValueMap { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class EventTagEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string TagData;

		public uint EventID;
	}
	internal enum EventTagEntryFieldId
	{
		EventTag_EventID
	}
	[ComImport]
	[Guid("8AD3FC86-AFD3-477a-8FD5-146C291195BD")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEventTagEntry
	{
		EventTagEntry AllData { get; }

		string TagData
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint EventID { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class RegistryValueEntry
	{
		public uint Flags;

		public uint OperationHint;

		public uint Type;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Value;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string BuildFilter;
	}
	internal enum RegistryValueEntryFieldId
	{
		RegistryValue_Flags,
		RegistryValue_OperationHint,
		RegistryValue_Type,
		RegistryValue_Value,
		RegistryValue_BuildFilter
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("49e1fe8d-ebb8-4593-8c4e-3e14c845b142")]
	internal interface IRegistryValueEntry
	{
		RegistryValueEntry AllData { get; }

		uint Flags { get; }

		uint OperationHint { get; }

		uint Type { get; }

		string Value
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string BuildFilter
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class RegistryKeyEntry : IDisposable
	{
		public uint Flags;

		public uint Protection;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string BuildFilter;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr SecurityDescriptor;

		public uint SecurityDescriptorSize;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr Values;

		public uint ValuesSize;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr Keys;

		public uint KeysSize;

		~RegistryKeyEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (SecurityDescriptor != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(SecurityDescriptor);
				SecurityDescriptor = IntPtr.Zero;
			}
			if (Values != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(Values);
				Values = IntPtr.Zero;
			}
			if (Keys != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(Keys);
				Keys = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum RegistryKeyEntryFieldId
	{
		RegistryKey_Flags,
		RegistryKey_Protection,
		RegistryKey_BuildFilter,
		RegistryKey_SecurityDescriptor,
		RegistryKey_SecurityDescriptorSize,
		RegistryKey_Values,
		RegistryKey_ValuesSize,
		RegistryKey_Keys,
		RegistryKey_KeysSize
	}
	[ComImport]
	[Guid("186685d1-6673-48c3-bc83-95859bb591df")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IRegistryKeyEntry
	{
		RegistryKeyEntry AllData { get; }

		uint Flags { get; }

		uint Protection { get; }

		string BuildFilter
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		object SecurityDescriptor
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		object Values
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		object Keys
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class DirectoryEntry : IDisposable
	{
		public uint Flags;

		public uint Protection;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string BuildFilter;

		[MarshalAs(UnmanagedType.SysInt)]
		public IntPtr SecurityDescriptor;

		public uint SecurityDescriptorSize;

		~DirectoryEntry()
		{
			Dispose(fDisposing: false);
		}

		void IDisposable.Dispose()
		{
			Dispose(fDisposing: true);
		}

		public void Dispose(bool fDisposing)
		{
			if (SecurityDescriptor != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(SecurityDescriptor);
				SecurityDescriptor = IntPtr.Zero;
			}
			if (fDisposing)
			{
				GC.SuppressFinalize(this);
			}
		}
	}
	internal enum DirectoryEntryFieldId
	{
		Directory_Flags,
		Directory_Protection,
		Directory_BuildFilter,
		Directory_SecurityDescriptor,
		Directory_SecurityDescriptorSize
	}
	[ComImport]
	[Guid("9f27c750-7dfb-46a1-a673-52e53e2337a9")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IDirectoryEntry
	{
		DirectoryEntry AllData { get; }

		uint Flags { get; }

		uint Protection { get; }

		string BuildFilter
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		object SecurityDescriptor
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class SecurityDescriptorReferenceEntry
	{
		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string BuildFilter;
	}
	internal enum SecurityDescriptorReferenceEntryFieldId
	{
		SecurityDescriptorReference_Name,
		SecurityDescriptorReference_BuildFilter
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("a75b74e9-2c00-4ebb-b3f9-62a670aaa07e")]
	internal interface ISecurityDescriptorReferenceEntry
	{
		SecurityDescriptorReferenceEntry AllData { get; }

		string Name
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string BuildFilter
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class CounterSetEntry
	{
		public Guid CounterSetGuid;

		public Guid ProviderGuid;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Description;

		public bool InstanceType;
	}
	internal enum CounterSetEntryFieldId
	{
		CounterSet_ProviderGuid,
		CounterSet_Name,
		CounterSet_Description,
		CounterSet_InstanceType
	}
	[ComImport]
	[Guid("8CD3FC85-AFD3-477a-8FD5-146C291195BB")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ICounterSetEntry
	{
		CounterSetEntry AllData { get; }

		Guid CounterSetGuid { get; }

		Guid ProviderGuid { get; }

		string Name
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Description
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		bool InstanceType { get; }
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class CounterEntry
	{
		public Guid CounterSetGuid;

		public uint CounterId;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Name;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string Description;

		public uint CounterType;

		public ulong Attributes;

		public uint BaseId;

		public uint DefaultScale;
	}
	internal enum CounterEntryFieldId
	{
		Counter_CounterId,
		Counter_Name,
		Counter_Description,
		Counter_CounterType,
		Counter_Attributes,
		Counter_BaseId,
		Counter_DefaultScale
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("8CD3FC86-AFD3-477a-8FD5-146C291195BB")]
	internal interface ICounterEntry
	{
		CounterEntry AllData { get; }

		Guid CounterSetGuid { get; }

		uint CounterId { get; }

		string Name
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		string Description
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}

		uint CounterType { get; }

		ulong Attributes { get; }

		uint BaseId { get; }

		uint DefaultScale { get; }
	}
}
namespace System.Deployment.Internal.Isolation
{
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("285a8862-c84a-11d7-850f-005cd062464f")]
	internal interface ISection
	{
		object _NewEnum
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		uint Count { get; }

		uint SectionID { get; }

		string SectionName
		{
			[return: MarshalAs(UnmanagedType.LPWStr)]
			get;
		}
	}
	[ComImport]
	[Guid("285a8871-c84a-11d7-850f-005cd062464f")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ISectionWithStringKey
	{
		bool IsCaseInsensitive { get; }

		void Lookup([MarshalAs(UnmanagedType.LPWStr)] string wzStringKey, [MarshalAs(UnmanagedType.Interface)] out object ppUnknown);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("285a8876-c84a-11d7-850f-005cd062464f")]
	internal interface ISectionWithReferenceIdentityKey
	{
		void Lookup(IReferenceIdentity ReferenceIdentityKey, [MarshalAs(UnmanagedType.Interface)] out object ppUnknown);
	}
	[ComImport]
	[Guid("285a8861-c84a-11d7-850f-005cd062464f")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface ISectionEntry
	{
		object GetField(uint fieldId);

		string GetFieldName(uint fieldId);
	}
	[ComImport]
	[Guid("00000100-0000-0000-C000-000000000046")]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	internal interface IEnumUnknown
	{
		[PreserveSig]
		int Next(uint celt, [Out][MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.IUnknown)] object[] rgelt, ref uint celtFetched);

		[PreserveSig]
		int Skip(uint celt);

		[PreserveSig]
		int Reset();

		[PreserveSig]
		int Clone(out IEnumUnknown enumUnknown);
	}
	[ComImport]
	[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	[Guid("285a8860-c84a-11d7-850f-005cd062464f")]
	internal interface ICDF
	{
		object _NewEnum
		{
			[return: MarshalAs(UnmanagedType.Interface)]
			get;
		}

		uint Count { get; }

		ISection GetRootSection(uint SectionId);

		ISectionEntry GetRootSectionEntry(uint SectionId);

		object GetItem(uint SectionId);
	}
}
namespace System.Deployment.Internal.CodeSigning
{
	internal static class Win32
	{
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_DATA_BLOB
		{
			internal uint cbData;

			internal IntPtr pbData;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct AXL_SIGNER_INFO
		{
			internal uint cbSize;

			internal uint dwError;

			internal uint algHash;

			internal IntPtr pwszHash;

			internal IntPtr pwszDescription;

			internal IntPtr pwszDescriptionUrl;

			internal IntPtr pChainContext;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct AXL_TIMESTAMPER_INFO
		{
			internal uint cbSize;

			internal uint dwError;

			internal uint algHash;

			internal System.Runtime.InteropServices.ComTypes.FILETIME ftTimestamp;

			internal IntPtr pChainContext;
		}

		internal const string KERNEL32 = "kernel32.dll";

		internal const string MSCORWKS = "mscorwks.dll";

		internal const int S_OK = 0;

		internal const int NTE_BAD_KEY = -2146893821;

		internal const int TRUST_E_SYSTEM_ERROR = -2146869247;

		internal const int TRUST_E_NO_SIGNER_CERT = -2146869246;

		internal const int TRUST_E_COUNTER_SIGNER = -2146869245;

		internal const int TRUST_E_CERT_SIGNATURE = -2146869244;

		internal const int TRUST_E_TIME_STAMP = -2146869243;

		internal const int TRUST_E_BAD_DIGEST = -2146869232;

		internal const int TRUST_E_BASIC_CONSTRAINTS = -2146869223;

		internal const int TRUST_E_FINANCIAL_CRITERIA = -2146869218;

		internal const int TRUST_E_PROVIDER_UNKNOWN = -2146762751;

		internal const int TRUST_E_ACTION_UNKNOWN = -2146762750;

		internal const int TRUST_E_SUBJECT_FORM_UNKNOWN = -2146762749;

		internal const int TRUST_E_SUBJECT_NOT_TRUSTED = -2146762748;

		internal const int TRUST_E_NOSIGNATURE = -2146762496;

		internal const int CERT_E_UNTRUSTEDROOT = -2146762487;

		internal const int TRUST_E_FAIL = -2146762485;

		internal const int TRUST_E_EXPLICIT_DISTRUST = -2146762479;

		internal const int CERT_E_CHAINING = -2146762486;

		internal const int AXL_REVOCATION_NO_CHECK = 1;

		internal const int AXL_REVOCATION_CHECK_END_CERT_ONLY = 2;

		internal const int AXL_REVOCATION_CHECK_ENTIRE_CHAIN = 4;

		internal const int AXL_URL_CACHE_ONLY_RETRIEVAL = 8;

		internal const int AXL_LIFETIME_SIGNING = 16;

		internal const int AXL_TRUST_MICROSOFT_ROOT_ONLY = 32;

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern IntPtr GetProcessHeap();

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool HeapFree([In] IntPtr hHeap, [In] uint dwFlags, [In] IntPtr lpMem);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int CertTimestampAuthenticodeLicense([In] ref CRYPT_DATA_BLOB pSignedLicenseBlob, [In] string pwszTimestampURI, [In][Out] ref CRYPT_DATA_BLOB pTimestampSignatureBlob);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int CertVerifyAuthenticodeLicense([In] ref CRYPT_DATA_BLOB pLicenseBlob, [In] uint dwFlags, [In][Out] ref AXL_SIGNER_INFO pSignerInfo, [In][Out] ref AXL_TIMESTAMPER_INFO pTimestamperInfo);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int CertFreeAuthenticodeSignerInfo([In] ref AXL_SIGNER_INFO pSignerInfo);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int CertFreeAuthenticodeTimestamperInfo([In] ref AXL_TIMESTAMPER_INFO pTimestamperInfo);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int _AxlGetIssuerPublicKeyHash([In] IntPtr pCertContext, [In][Out] ref IntPtr ppwszPublicKeyHash);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int _AxlRSAKeyValueToPublicKeyToken([In] ref CRYPT_DATA_BLOB pModulusBlob, [In] ref CRYPT_DATA_BLOB pExponentBlob, [In][Out] ref IntPtr ppwszPublicKeyToken);

		[DllImport("mscorwks.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int _AxlPublicKeyBlobToPublicKeyToken([In] ref CRYPT_DATA_BLOB pCspPublicKeyBlob, [In][Out] ref IntPtr ppwszPublicKeyToken);
	}
	internal class ManifestSignedXml : SignedXml
	{
		private bool m_verify;

		internal ManifestSignedXml()
		{
		}

		internal ManifestSignedXml(XmlElement elem)
			: base(elem)
		{
		}

		internal ManifestSignedXml(XmlDocument document)
			: base(document)
		{
		}

		internal ManifestSignedXml(XmlDocument document, bool verify)
			: base(document)
		{
			m_verify = verify;
		}

		private static XmlElement FindIdElement(XmlElement context, string idValue)
		{
			if (context == null)
			{
				return null;
			}
			if (context.SelectSingleNode("//*[@Id=\"" + idValue + "\"]") is XmlElement result)
			{
				return result;
			}
			if (context.SelectSingleNode("//*[@id=\"" + idValue + "\"]") is XmlElement result2)
			{
				return result2;
			}
			return context.SelectSingleNode("//*[@ID=\"" + idValue + "\"]") as XmlElement;
		}

		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			if (m_verify)
			{
				return base.GetIdElement(document, idValue);
			}
			KeyInfo keyInfo = base.KeyInfo;
			if (keyInfo.Id != idValue)
			{
				return null;
			}
			return keyInfo.GetXml();
		}
	}
	internal class SignedCmiManifest
	{
		private const string AssemblyNamespaceUri = "urn:schemas-microsoft-com:asm.v1";

		private const string AssemblyV2NamespaceUri = "urn:schemas-microsoft-com:asm.v2";

		private const string MSRelNamespaceUri = "http://schemas.microsoft.com/windows/rel/2005/reldata";

		private const string LicenseNamespaceUri = "urn:mpeg:mpeg21:2003:01-REL-R-NS";

		private const string AuthenticodeNamespaceUri = "http://schemas.microsoft.com/windows/pki/2005/Authenticode";

		private const string licenseTemplate = "<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" xmlns:as=\"http://schemas.microsoft.com/windows/pki/2005/Authenticode\"><r:grant><as:ManifestInformation><as:assemblyIdentity /></as:ManifestInformation><as:SignedBy/><as:AuthenticodePublisher><as:X509SubjectName>CN=dummy</as:X509SubjectName></as:AuthenticodePublisher></r:grant><r:issuer></r:issuer></r:license>";

		private XmlDocument m_manifestDom;

		private CmiStrongNameSignerInfo m_strongNameSignerInfo;

		private CmiAuthenticodeSignerInfo m_authenticodeSignerInfo;

		private static readonly char[] hexValues = new char[16]
		{
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f'
		};

		internal CmiStrongNameSignerInfo StrongNameSignerInfo => m_strongNameSignerInfo;

		internal CmiAuthenticodeSignerInfo AuthenticodeSignerInfo => m_authenticodeSignerInfo;

		private SignedCmiManifest()
		{
		}

		internal SignedCmiManifest(XmlDocument manifestDom)
		{
			if (manifestDom == null)
			{
				throw new ArgumentNullException("manifestDom");
			}
			m_manifestDom = manifestDom;
		}

		internal void Sign(CmiManifestSigner signer)
		{
			Sign(signer, null);
		}

		internal void Sign(CmiManifestSigner signer, string timeStampUrl)
		{
			m_strongNameSignerInfo = null;
			m_authenticodeSignerInfo = null;
			if (signer == null || signer.StrongNameKey == null)
			{
				throw new ArgumentNullException("signer");
			}
			RemoveExistingSignature(m_manifestDom);
			if ((signer.Flag & CmiManifestSignerFlag.DontReplacePublicKeyToken) == 0)
			{
				ReplacePublicKeyToken(m_manifestDom, signer.StrongNameKey);
			}
			XmlDocument licenseDom = null;
			if (signer.Certificate != null)
			{
				InsertPublisherIdentity(m_manifestDom, signer.Certificate);
				licenseDom = CreateLicenseDom(signer, ExtractPrincipalFromManifest(), ComputeHashFromManifest(m_manifestDom));
				AuthenticodeSignLicenseDom(licenseDom, signer, timeStampUrl);
			}
			StrongNameSignManifestDom(m_manifestDom, licenseDom, signer);
		}

		internal void Verify(CmiManifestVerifyFlags verifyFlags)
		{
			m_strongNameSignerInfo = null;
			m_authenticodeSignerInfo = null;
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(m_manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			if (!(m_manifestDom.SelectSingleNode("//ds:Signature", xmlNamespaceManager) is XmlElement xmlElement))
			{
				throw new CryptographicException(-2146762496);
			}
			string name = "Id";
			if (!xmlElement.HasAttribute(name))
			{
				name = "id";
				if (!xmlElement.HasAttribute(name))
				{
					name = "ID";
					if (!xmlElement.HasAttribute(name))
					{
						throw new CryptographicException(-2146762749);
					}
				}
			}
			string attribute = xmlElement.GetAttribute(name);
			if (attribute == null || string.Compare(attribute, "StrongNameSignature", StringComparison.Ordinal) != 0)
			{
				throw new CryptographicException(-2146762749);
			}
			bool oldFormat = false;
			bool flag = false;
			XmlNodeList xmlNodeList = xmlElement.SelectNodes("ds:SignedInfo/ds:Reference", xmlNamespaceManager);
			foreach (XmlNode item in xmlNodeList)
			{
				if (!(item is XmlElement xmlElement2) || !xmlElement2.HasAttribute("URI"))
				{
					continue;
				}
				string attribute2 = xmlElement2.GetAttribute("URI");
				if (attribute2 == null)
				{
					continue;
				}
				if (attribute2.Length == 0)
				{
					XmlNode xmlNode2 = xmlElement2.SelectSingleNode("ds:Transforms", xmlNamespaceManager);
					if (xmlNode2 == null)
					{
						throw new CryptographicException(-2146762749);
					}
					XmlNodeList xmlNodeList2 = xmlNode2.SelectNodes("ds:Transform", xmlNamespaceManager);
					if (xmlNodeList2.Count < 2)
					{
						throw new CryptographicException(-2146762749);
					}
					bool flag2 = false;
					bool flag3 = false;
					for (int i = 0; i < xmlNodeList2.Count; i++)
					{
						XmlElement xmlElement3 = xmlNodeList2[i] as XmlElement;
						string attribute3 = xmlElement3.GetAttribute("Algorithm");
						if (attribute3 == null)
						{
							break;
						}
						if (string.Compare(attribute3, "http://www.w3.org/2001/10/xml-exc-c14n#", StringComparison.Ordinal) != 0)
						{
							flag2 = true;
							if (flag3)
							{
								flag = true;
								break;
							}
						}
						else if (string.Compare(attribute3, "http://www.w3.org/2000/09/xmldsig#enveloped-signature", StringComparison.Ordinal) != 0)
						{
							flag3 = true;
							if (flag2)
							{
								flag = true;
								break;
							}
						}
					}
				}
				else
				{
					if (string.Compare(attribute2, "#StrongNameKeyInfo", StringComparison.Ordinal) != 0)
					{
						continue;
					}
					oldFormat = true;
					XmlNode xmlNode3 = item.SelectSingleNode("ds:Transforms", xmlNamespaceManager);
					if (xmlNode3 == null)
					{
						throw new CryptographicException(-2146762749);
					}
					XmlNodeList xmlNodeList3 = xmlNode3.SelectNodes("ds:Transform", xmlNamespaceManager);
					if (xmlNodeList3.Count < 1)
					{
						throw new CryptographicException(-2146762749);
					}
					for (int j = 0; j < xmlNodeList3.Count; j++)
					{
						XmlElement xmlElement4 = xmlNodeList3[j] as XmlElement;
						string attribute4 = xmlElement4.GetAttribute("Algorithm");
						if (attribute4 == null)
						{
							break;
						}
						if (string.Compare(attribute4, "http://www.w3.org/2001/10/xml-exc-c14n#", StringComparison.Ordinal) != 0)
						{
							flag = true;
							break;
						}
					}
				}
			}
			if (!flag)
			{
				throw new CryptographicException(-2146762749);
			}
			string publicKeyToken = VerifyPublicKeyToken();
			m_strongNameSignerInfo = new CmiStrongNameSignerInfo(-2146762485, publicKeyToken);
			ManifestSignedXml manifestSignedXml = new ManifestSignedXml(m_manifestDom, verify: true);
			manifestSignedXml.LoadXml(xmlElement);
			AsymmetricAlgorithm signingKey = null;
			bool flag4 = manifestSignedXml.CheckSignatureReturningKey(out signingKey);
			m_strongNameSignerInfo.PublicKey = signingKey;
			if (!flag4)
			{
				m_strongNameSignerInfo.ErrorCode = -2146869232;
				throw new CryptographicException(-2146869232);
			}
			if ((verifyFlags & CmiManifestVerifyFlags.StrongNameOnly) != CmiManifestVerifyFlags.StrongNameOnly)
			{
				VerifyLicense(verifyFlags, oldFormat);
			}
		}

		private unsafe void VerifyLicense(CmiManifestVerifyFlags verifyFlags, bool oldFormat)
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(m_manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			xmlNamespaceManager.AddNamespace("asm2", "urn:schemas-microsoft-com:asm.v2");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			xmlNamespaceManager.AddNamespace("msrel", "http://schemas.microsoft.com/windows/rel/2005/reldata");
			xmlNamespaceManager.AddNamespace("r", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
			xmlNamespaceManager.AddNamespace("as", "http://schemas.microsoft.com/windows/pki/2005/Authenticode");
			if (!(m_manifestDom.SelectSingleNode("asm:assembly/ds:Signature/ds:KeyInfo/msrel:RelData/r:license", xmlNamespaceManager) is XmlElement xmlElement))
			{
				return;
			}
			VerifyAssemblyIdentity(xmlNamespaceManager);
			m_authenticodeSignerInfo = new CmiAuthenticodeSignerInfo(-2146762485);
			byte[] bytes = Encoding.UTF8.GetBytes(xmlElement.OuterXml);
			fixed (byte* value = bytes)
			{
				Win32.AXL_SIGNER_INFO pSignerInfo = default(Win32.AXL_SIGNER_INFO);
				pSignerInfo.cbSize = (uint)Marshal.SizeOf(typeof(Win32.AXL_SIGNER_INFO));
				Win32.AXL_TIMESTAMPER_INFO pTimestamperInfo = default(Win32.AXL_TIMESTAMPER_INFO);
				pTimestamperInfo.cbSize = (uint)Marshal.SizeOf(typeof(Win32.AXL_TIMESTAMPER_INFO));
				Win32.CRYPT_DATA_BLOB pLicenseBlob = default(Win32.CRYPT_DATA_BLOB);
				IntPtr pbData = new IntPtr(value);
				pLicenseBlob.cbData = (uint)bytes.Length;
				pLicenseBlob.pbData = pbData;
				int num = Win32.CertVerifyAuthenticodeLicense(ref pLicenseBlob, (uint)verifyFlags, ref pSignerInfo, ref pTimestamperInfo);
				if (-2146762496 != (int)pSignerInfo.dwError)
				{
					m_authenticodeSignerInfo = new CmiAuthenticodeSignerInfo(pSignerInfo, pTimestamperInfo);
				}
				Win32.CertFreeAuthenticodeSignerInfo(ref pSignerInfo);
				Win32.CertFreeAuthenticodeTimestamperInfo(ref pTimestamperInfo);
				if (num != 0)
				{
					throw new CryptographicException(num);
				}
			}
			if (!oldFormat)
			{
				VerifyPublisherIdentity(xmlNamespaceManager);
			}
		}

		private XmlElement ExtractPrincipalFromManifest()
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(m_manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			XmlNode xmlNode = m_manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", xmlNamespaceManager);
			if (xmlNode == null)
			{
				throw new CryptographicException(-2146762749);
			}
			return xmlNode as XmlElement;
		}

		private void VerifyAssemblyIdentity(XmlNamespaceManager nsm)
		{
			XmlElement xmlElement = m_manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", nsm) as XmlElement;
			XmlElement xmlElement2 = m_manifestDom.SelectSingleNode("asm:assembly/ds:Signature/ds:KeyInfo/msrel:RelData/r:license/r:grant/as:ManifestInformation/as:assemblyIdentity", nsm) as XmlElement;
			if (xmlElement == null || xmlElement2 == null || !xmlElement.HasAttributes || !xmlElement2.HasAttributes)
			{
				throw new CryptographicException(-2146762749);
			}
			XmlAttributeCollection attributes = xmlElement.Attributes;
			if (attributes.Count == 0 || attributes.Count != xmlElement2.Attributes.Count)
			{
				throw new CryptographicException(-2146762749);
			}
			foreach (XmlAttribute item in attributes)
			{
				if (!xmlElement2.HasAttribute(item.LocalName) || item.Value != xmlElement2.GetAttribute(item.LocalName))
				{
					throw new CryptographicException(-2146762749);
				}
			}
			VerifyHash(nsm);
		}

		private void VerifyPublisherIdentity(XmlNamespaceManager nsm)
		{
			if (m_authenticodeSignerInfo.ErrorCode != -2146762496)
			{
				X509Certificate2 certificate = m_authenticodeSignerInfo.SignerChain.ChainElements[0].Certificate;
				if (!(m_manifestDom.SelectSingleNode("asm:assembly/asm2:publisherIdentity", nsm) is XmlElement xmlElement) || !xmlElement.HasAttributes)
				{
					throw new CryptographicException(-2146762749);
				}
				if (!xmlElement.HasAttribute("name") || !xmlElement.HasAttribute("issuerKeyHash"))
				{
					throw new CryptographicException(-2146762749);
				}
				string attribute = xmlElement.GetAttribute("name");
				string attribute2 = xmlElement.GetAttribute("issuerKeyHash");
				IntPtr ppwszPublicKeyHash = default(IntPtr);
				int num = Win32._AxlGetIssuerPublicKeyHash(certificate.Handle, ref ppwszPublicKeyHash);
				if (num != 0)
				{
					throw new CryptographicException(num);
				}
				string strB = Marshal.PtrToStringUni(ppwszPublicKeyHash);
				Win32.HeapFree(Win32.GetProcessHeap(), 0u, ppwszPublicKeyHash);
				if (string.Compare(attribute, certificate.SubjectName.Name, StringComparison.Ordinal) != 0 || string.Compare(attribute2, strB, StringComparison.Ordinal) != 0)
				{
					throw new CryptographicException(-2146762485);
				}
			}
		}

		private void VerifyHash(XmlNamespaceManager nsm)
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			xmlDocument = (XmlDocument)m_manifestDom.Clone();
			if (!(xmlDocument.SelectSingleNode("asm:assembly/ds:Signature/ds:KeyInfo/msrel:RelData/r:license/r:grant/as:ManifestInformation", nsm) is XmlElement xmlElement))
			{
				throw new CryptographicException(-2146762749);
			}
			if (!xmlElement.HasAttribute("Hash"))
			{
				throw new CryptographicException(-2146762749);
			}
			string attribute = xmlElement.GetAttribute("Hash");
			if (attribute == null || attribute.Length == 0)
			{
				throw new CryptographicException(-2146762749);
			}
			if (!(xmlDocument.SelectSingleNode("asm:assembly/ds:Signature", nsm) is XmlElement xmlElement2))
			{
				throw new CryptographicException(-2146762749);
			}
			xmlElement2.ParentNode.RemoveChild(xmlElement2);
			byte[] array = HexStringToBytes(xmlElement.GetAttribute("Hash"));
			byte[] array2 = ComputeHashFromManifest(xmlDocument);
			if (array.Length == 0 || array.Length != array2.Length)
			{
				byte[] array3 = ComputeHashFromManifest(xmlDocument, oldFormat: true);
				if (array.Length == 0 || array.Length != array3.Length)
				{
					throw new CryptographicException(-2146869232);
				}
				for (int i = 0; i < array.Length; i++)
				{
					if (array[i] != array3[i])
					{
						throw new CryptographicException(-2146869232);
					}
				}
			}
			for (int j = 0; j < array.Length; j++)
			{
				if (array[j] == array2[j])
				{
					continue;
				}
				byte[] array4 = ComputeHashFromManifest(xmlDocument, oldFormat: true);
				if (array.Length == 0 || array.Length != array4.Length)
				{
					throw new CryptographicException(-2146869232);
				}
				for (j = 0; j < array.Length; j++)
				{
					if (array[j] != array4[j])
					{
						throw new CryptographicException(-2146869232);
					}
				}
			}
		}

		private unsafe string VerifyPublicKeyToken()
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(m_manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			XmlElement xmlElement = m_manifestDom.SelectSingleNode("asm:assembly/ds:Signature/ds:KeyInfo/ds:KeyValue/ds:RSAKeyValue/ds:Modulus", xmlNamespaceManager) as XmlElement;
			XmlElement xmlElement2 = m_manifestDom.SelectSingleNode("asm:assembly/ds:Signature/ds:KeyInfo/ds:KeyValue/ds:RSAKeyValue/ds:Exponent", xmlNamespaceManager) as XmlElement;
			if (xmlElement == null || xmlElement2 == null)
			{
				throw new CryptographicException(-2146762749);
			}
			byte[] bytes = Encoding.UTF8.GetBytes(xmlElement.InnerXml);
			byte[] bytes2 = Encoding.UTF8.GetBytes(xmlElement2.InnerXml);
			string publicKeyToken = GetPublicKeyToken(m_manifestDom);
			byte[] array = HexStringToBytes(publicKeyToken);
			byte[] array2;
			fixed (byte* value = bytes)
			{
				fixed (byte* value2 = bytes2)
				{
					Win32.CRYPT_DATA_BLOB pModulusBlob = default(Win32.CRYPT_DATA_BLOB);
					Win32.CRYPT_DATA_BLOB pExponentBlob = default(Win32.CRYPT_DATA_BLOB);
					IntPtr ppwszPublicKeyToken = default(IntPtr);
					pModulusBlob.cbData = (uint)bytes.Length;
					pModulusBlob.pbData = new IntPtr(value);
					pExponentBlob.cbData = (uint)bytes2.Length;
					pExponentBlob.pbData = new IntPtr(value2);
					int num = Win32._AxlRSAKeyValueToPublicKeyToken(ref pModulusBlob, ref pExponentBlob, ref ppwszPublicKeyToken);
					if (num != 0)
					{
						throw new CryptographicException(num);
					}
					array2 = HexStringToBytes(Marshal.PtrToStringUni(ppwszPublicKeyToken));
					Win32.HeapFree(Win32.GetProcessHeap(), 0u, ppwszPublicKeyToken);
				}
			}
			if (array.Length == 0 || array.Length != array2.Length)
			{
				throw new CryptographicException(-2146762485);
			}
			for (int i = 0; i < array.Length; i++)
			{
				if (array[i] != array2[i])
				{
					throw new CryptographicException(-2146762485);
				}
			}
			return publicKeyToken;
		}

		private static void InsertPublisherIdentity(XmlDocument manifestDom, X509Certificate2 signerCert)
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			xmlNamespaceManager.AddNamespace("asm2", "urn:schemas-microsoft-com:asm.v2");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			XmlElement xmlElement = manifestDom.SelectSingleNode("asm:assembly", xmlNamespaceManager) as XmlElement;
			if (!(manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", xmlNamespaceManager) is XmlElement))
			{
				throw new CryptographicException(-2146762749);
			}
			if (manifestDom.SelectSingleNode("asm:assembly/asm2:publisherIdentity", xmlNamespaceManager) == null)
			{
				IntPtr ppwszPublicKeyHash = default(IntPtr);
				int num = Win32._AxlGetIssuerPublicKeyHash(signerCert.Handle, ref ppwszPublicKeyHash);
				if (num != 0)
				{
					throw new CryptographicException(num);
				}
				string value = Marshal.PtrToStringUni(ppwszPublicKeyHash);
				Win32.HeapFree(Win32.GetProcessHeap(), 0u, ppwszPublicKeyHash);
				XmlElement xmlElement3 = manifestDom.CreateElement("publisherIdentity", "urn:schemas-microsoft-com:asm.v2");
				xmlElement3.SetAttribute("name", signerCert.SubjectName.Name);
				xmlElement3.SetAttribute("issuerKeyHash", value);
				if (manifestDom.SelectSingleNode("asm:assembly/ds:Signature", xmlNamespaceManager) is XmlElement refChild)
				{
					xmlElement.InsertBefore(xmlElement3, refChild);
				}
				else
				{
					xmlElement.AppendChild(xmlElement3);
				}
			}
		}

		private static void RemoveExistingSignature(XmlDocument manifestDom)
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			XmlNode xmlNode = manifestDom.SelectSingleNode("asm:assembly/ds:Signature", xmlNamespaceManager);
			xmlNode?.ParentNode.RemoveChild(xmlNode);
		}

		private unsafe static void ReplacePublicKeyToken(XmlDocument manifestDom, AsymmetricAlgorithm snKey)
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			if (!(manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", xmlNamespaceManager) is XmlElement xmlElement))
			{
				throw new CryptographicException(-2146762749);
			}
			if (!xmlElement.HasAttribute("publicKeyToken"))
			{
				throw new CryptographicException(-2146762749);
			}
			byte[] array = ((RSACryptoServiceProvider)snKey).ExportCspBlob(includePrivateParameters: false);
			if (array == null || array.Length == 0)
			{
				throw new CryptographicException(-2146893821);
			}
			fixed (byte* value = array)
			{
				Win32.CRYPT_DATA_BLOB pCspPublicKeyBlob = default(Win32.CRYPT_DATA_BLOB);
				pCspPublicKeyBlob.cbData = (uint)array.Length;
				pCspPublicKeyBlob.pbData = new IntPtr(value);
				IntPtr ppwszPublicKeyToken = default(IntPtr);
				int num = Win32._AxlPublicKeyBlobToPublicKeyToken(ref pCspPublicKeyBlob, ref ppwszPublicKeyToken);
				if (num != 0)
				{
					throw new CryptographicException(num);
				}
				string value2 = Marshal.PtrToStringUni(ppwszPublicKeyToken);
				Win32.HeapFree(Win32.GetProcessHeap(), 0u, ppwszPublicKeyToken);
				xmlElement.SetAttribute("publicKeyToken", value2);
			}
		}

		private static string GetPublicKeyToken(XmlDocument manifestDom)
		{
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			if (!(manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", xmlNamespaceManager) is XmlElement xmlElement) || !xmlElement.HasAttribute("publicKeyToken"))
			{
				throw new CryptographicException(-2146762749);
			}
			return xmlElement.GetAttribute("publicKeyToken");
		}

		private static byte[] ComputeHashFromManifest(XmlDocument manifestDom)
		{
			return ComputeHashFromManifest(manifestDom, oldFormat: false);
		}

		private static byte[] ComputeHashFromManifest(XmlDocument manifestDom, bool oldFormat)
		{
			if (oldFormat)
			{
				XmlDsigExcC14NTransform xmlDsigExcC14NTransform = new XmlDsigExcC14NTransform();
				xmlDsigExcC14NTransform.LoadInput(manifestDom);
				using SHA1CryptoServiceProvider sHA1CryptoServiceProvider = new SHA1CryptoServiceProvider();
				byte[] array = sHA1CryptoServiceProvider.ComputeHash(xmlDsigExcC14NTransform.GetOutput() as MemoryStream);
				if (array == null)
				{
					throw new CryptographicException(-2146869232);
				}
				return array;
			}
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			using (TextReader input = new StringReader(manifestDom.OuterXml))
			{
				XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
				xmlReaderSettings.ProhibitDtd = false;
				XmlReader reader = XmlReader.Create(input, xmlReaderSettings, manifestDom.BaseURI);
				xmlDocument.Load(reader);
			}
			XmlDsigExcC14NTransform xmlDsigExcC14NTransform2 = new XmlDsigExcC14NTransform();
			xmlDsigExcC14NTransform2.LoadInput(xmlDocument);
			using SHA1CryptoServiceProvider sHA1CryptoServiceProvider2 = new SHA1CryptoServiceProvider();
			byte[] array2 = sHA1CryptoServiceProvider2.ComputeHash(xmlDsigExcC14NTransform2.GetOutput() as MemoryStream);
			if (array2 == null)
			{
				throw new CryptographicException(-2146869232);
			}
			return array2;
		}

		private static XmlDocument CreateLicenseDom(CmiManifestSigner signer, XmlElement principal, byte[] hash)
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			xmlDocument.LoadXml("<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" xmlns:as=\"http://schemas.microsoft.com/windows/pki/2005/Authenticode\"><r:grant><as:ManifestInformation><as:assemblyIdentity /></as:ManifestInformation><as:SignedBy/><as:AuthenticodePublisher><as:X509SubjectName>CN=dummy</as:X509SubjectName></as:AuthenticodePublisher></r:grant><r:issuer></r:issuer></r:license>");
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
			xmlNamespaceManager.AddNamespace("r", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
			xmlNamespaceManager.AddNamespace("as", "http://schemas.microsoft.com/windows/pki/2005/Authenticode");
			XmlElement xmlElement = xmlDocument.SelectSingleNode("r:license/r:grant/as:ManifestInformation/as:assemblyIdentity", xmlNamespaceManager) as XmlElement;
			xmlElement.RemoveAllAttributes();
			foreach (XmlAttribute attribute in principal.Attributes)
			{
				xmlElement.SetAttribute(attribute.Name, attribute.Value);
			}
			XmlElement xmlElement2 = xmlDocument.SelectSingleNode("r:license/r:grant/as:ManifestInformation", xmlNamespaceManager) as XmlElement;
			xmlElement2.SetAttribute("Hash", (hash.Length == 0) ? "" : BytesToHexString(hash, 0, hash.Length));
			xmlElement2.SetAttribute("Description", (signer.Description == null) ? "" : signer.Description);
			xmlElement2.SetAttribute("Url", (signer.DescriptionUrl == null) ? "" : signer.DescriptionUrl);
			XmlElement xmlElement3 = xmlDocument.SelectSingleNode("r:license/r:grant/as:AuthenticodePublisher/as:X509SubjectName", xmlNamespaceManager) as XmlElement;
			xmlElement3.InnerText = signer.Certificate.SubjectName.Name;
			return xmlDocument;
		}

		private static void AuthenticodeSignLicenseDom(XmlDocument licenseDom, CmiManifestSigner signer, string timeStampUrl)
		{
			if (signer.Certificate.PublicKey.Key.GetType() != typeof(RSACryptoServiceProvider))
			{
				throw new NotSupportedException();
			}
			ManifestSignedXml manifestSignedXml = new ManifestSignedXml(licenseDom);
			manifestSignedXml.SigningKey = signer.Certificate.PrivateKey;
			manifestSignedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
			manifestSignedXml.KeyInfo.AddClause(new RSAKeyValue(signer.Certificate.PublicKey.Key as RSA));
			manifestSignedXml.KeyInfo.AddClause(new KeyInfoX509Data(signer.Certificate, signer.IncludeOption));
			Reference reference = new Reference();
			reference.Uri = "";
			reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			reference.AddTransform(new XmlDsigExcC14NTransform());
			manifestSignedXml.AddReference(reference);
			manifestSignedXml.ComputeSignature();
			XmlElement xml = manifestSignedXml.GetXml();
			xml.SetAttribute("Id", "AuthenticodeSignature");
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(licenseDom.NameTable);
			xmlNamespaceManager.AddNamespace("r", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
			XmlElement xmlElement = licenseDom.SelectSingleNode("r:license/r:issuer", xmlNamespaceManager) as XmlElement;
			xmlElement.AppendChild(licenseDom.ImportNode(xml, deep: true));
			if (timeStampUrl != null && timeStampUrl.Length != 0)
			{
				TimestampSignedLicenseDom(licenseDom, timeStampUrl);
			}
			licenseDom.DocumentElement.ParentNode.InnerXml = "<msrel:RelData xmlns:msrel=\"http://schemas.microsoft.com/windows/rel/2005/reldata\">" + licenseDom.OuterXml + "</msrel:RelData>";
		}

		private unsafe static void TimestampSignedLicenseDom(XmlDocument licenseDom, string timeStampUrl)
		{
			Win32.CRYPT_DATA_BLOB pTimestampSignatureBlob = default(Win32.CRYPT_DATA_BLOB);
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(licenseDom.NameTable);
			xmlNamespaceManager.AddNamespace("r", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
			xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			xmlNamespaceManager.AddNamespace("as", "http://schemas.microsoft.com/windows/pki/2005/Authenticode");
			byte[] bytes = Encoding.UTF8.GetBytes(licenseDom.OuterXml);
			fixed (byte* value = bytes)
			{
				Win32.CRYPT_DATA_BLOB pSignedLicenseBlob = default(Win32.CRYPT_DATA_BLOB);
				IntPtr pbData = new IntPtr(value);
				pSignedLicenseBlob.cbData = (uint)bytes.Length;
				pSignedLicenseBlob.pbData = pbData;
				int num = Win32.CertTimestampAuthenticodeLicense(ref pSignedLicenseBlob, timeStampUrl, ref pTimestampSignatureBlob);
				if (num != 0)
				{
					throw new CryptographicException(num);
				}
			}
			byte[] array = new byte[pTimestampSignatureBlob.cbData];
			Marshal.Copy(pTimestampSignatureBlob.pbData, array, 0, array.Length);
			Win32.HeapFree(Win32.GetProcessHeap(), 0u, pTimestampSignatureBlob.pbData);
			XmlElement xmlElement = licenseDom.CreateElement("as", "Timestamp", "http://schemas.microsoft.com/windows/pki/2005/Authenticode");
			xmlElement.InnerText = Encoding.UTF8.GetString(array);
			XmlElement xmlElement2 = licenseDom.CreateElement("Object", "http://www.w3.org/2000/09/xmldsig#");
			xmlElement2.AppendChild(xmlElement);
			XmlElement xmlElement3 = licenseDom.SelectSingleNode("r:license/r:issuer/ds:Signature", xmlNamespaceManager) as XmlElement;
			xmlElement3.AppendChild(xmlElement2);
		}

		private static void StrongNameSignManifestDom(XmlDocument manifestDom, XmlDocument licenseDom, CmiManifestSigner signer)
		{
			if (!(signer.StrongNameKey is RSA key))
			{
				throw new NotSupportedException();
			}
			XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(manifestDom.NameTable);
			xmlNamespaceManager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
			if (!(manifestDom.SelectSingleNode("asm:assembly", xmlNamespaceManager) is XmlElement xmlElement))
			{
				throw new CryptographicException(-2146762749);
			}
			ManifestSignedXml manifestSignedXml = new ManifestSignedXml(xmlElement);
			manifestSignedXml.SigningKey = signer.StrongNameKey;
			manifestSignedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
			manifestSignedXml.KeyInfo.AddClause(new RSAKeyValue(key));
			if (licenseDom != null)
			{
				manifestSignedXml.KeyInfo.AddClause(new KeyInfoNode(licenseDom.DocumentElement));
			}
			manifestSignedXml.KeyInfo.Id = "StrongNameKeyInfo";
			Reference reference = new Reference();
			reference.Uri = "";
			reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			reference.AddTransform(new XmlDsigExcC14NTransform());
			manifestSignedXml.AddReference(reference);
			manifestSignedXml.ComputeSignature();
			XmlElement xml = manifestSignedXml.GetXml();
			xml.SetAttribute("Id", "StrongNameSignature");
			xmlElement.AppendChild(xml);
		}

		private static string BytesToHexString(byte[] array, int start, int end)
		{
			string result = null;
			if (array != null)
			{
				char[] array2 = new char[(end - start) * 2];
				int num = end;
				int num2 = 0;
				while (num-- > start)
				{
					int num3 = (array[num] & 0xF0) >> 4;
					array2[num2++] = hexValues[num3];
					num3 = array[num] & 0xF;
					array2[num2++] = hexValues[num3];
				}
				result = new string(array2);
			}
			return result;
		}

		private static byte[] HexStringToBytes(string hexString)
		{
			uint num = (uint)hexString.Length / 2u;
			byte[] array = new byte[num];
			int num2 = hexString.Length - 2;
			for (int i = 0; i < num; i++)
			{
				array[i] = (byte)((HexToByte(hexString[num2]) << 4) | HexToByte(hexString[num2 + 1]));
				num2 -= 2;
			}
			return array;
		}

		private static byte HexToByte(char val)
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
	}
	[Flags]
	internal enum CmiManifestSignerFlag
	{
		None = 0,
		DontReplacePublicKeyToken = 1
	}
	[Flags]
	internal enum CmiManifestVerifyFlags
	{
		None = 0,
		RevocationNoCheck = 1,
		RevocationCheckEndCertOnly = 2,
		RevocationCheckEntireChain = 4,
		UrlCacheOnlyRetrieval = 8,
		LifetimeSigning = 0x10,
		TrustMicrosoftRootOnly = 0x20,
		StrongNameOnly = 0x10000
	}
	internal class CmiManifestSigner
	{
		internal const uint CimManifestSignerFlagMask = 1u;

		private AsymmetricAlgorithm m_strongNameKey;

		private X509Certificate2 m_certificate;

		private string m_description;

		private string m_url;

		private X509Certificate2Collection m_certificates;

		private X509IncludeOption m_includeOption;

		private CmiManifestSignerFlag m_signerFlag;

		internal AsymmetricAlgorithm StrongNameKey => m_strongNameKey;

		internal X509Certificate2 Certificate => m_certificate;

		internal string Description
		{
			get
			{
				return m_description;
			}
			set
			{
				m_description = value;
			}
		}

		internal string DescriptionUrl
		{
			get
			{
				return m_url;
			}
			set
			{
				m_url = value;
			}
		}

		internal X509Certificate2Collection ExtraStore => m_certificates;

		internal X509IncludeOption IncludeOption
		{
			get
			{
				return m_includeOption;
			}
			set
			{
				if (value < X509IncludeOption.None || value > X509IncludeOption.WholeChain)
				{
					throw new ArgumentException("value");
				}
				if (m_includeOption == X509IncludeOption.None)
				{
					throw new NotSupportedException();
				}
				m_includeOption = value;
			}
		}

		internal CmiManifestSignerFlag Flag
		{
			get
			{
				return m_signerFlag;
			}
			set
			{
				if (((uint)value & 0xFFFFFFFEu) != 0)
				{
					throw new ArgumentException("value");
				}
				m_signerFlag = value;
			}
		}

		private CmiManifestSigner()
		{
		}

		internal CmiManifestSigner(AsymmetricAlgorithm strongNameKey)
			: this(strongNameKey, null)
		{
		}

		internal CmiManifestSigner(AsymmetricAlgorithm strongNameKey, X509Certificate2 certificate)
		{
			if (strongNameKey == null)
			{
				throw new ArgumentNullException("strongNameKey");
			}
			if (!(strongNameKey is RSA))
			{
				throw new ArgumentNullException("strongNameKey");
			}
			m_strongNameKey = strongNameKey;
			m_certificate = certificate;
			m_certificates = new X509Certificate2Collection();
			m_includeOption = X509IncludeOption.ExcludeRoot;
			m_signerFlag = CmiManifestSignerFlag.None;
		}
	}
	internal class CmiStrongNameSignerInfo
	{
		private int m_error;

		private string m_publicKeyToken;

		private AsymmetricAlgorithm m_snKey;

		internal int ErrorCode
		{
			get
			{
				return m_error;
			}
			set
			{
				m_error = value;
			}
		}

		internal string PublicKeyToken
		{
			get
			{
				return m_publicKeyToken;
			}
			set
			{
				m_publicKeyToken = value;
			}
		}

		internal AsymmetricAlgorithm PublicKey
		{
			get
			{
				return m_snKey;
			}
			set
			{
				m_snKey = value;
			}
		}

		internal CmiStrongNameSignerInfo()
		{
		}

		internal CmiStrongNameSignerInfo(int errorCode, string publicKeyToken)
		{
			m_error = errorCode;
			m_publicKeyToken = publicKeyToken;
		}
	}
	internal class CmiAuthenticodeSignerInfo
	{
		private int m_error;

		private X509Chain m_signerChain;

		private uint m_algHash;

		private string m_hash;

		private string m_description;

		private string m_descriptionUrl;

		private CmiAuthenticodeTimestamperInfo m_timestamperInfo;

		internal int ErrorCode => m_error;

		internal uint HashAlgId => m_algHash;

		internal string Hash => m_hash;

		internal string Description => m_description;

		internal string DescriptionUrl => m_descriptionUrl;

		internal CmiAuthenticodeTimestamperInfo TimestamperInfo => m_timestamperInfo;

		internal X509Chain SignerChain => m_signerChain;

		internal CmiAuthenticodeSignerInfo()
		{
		}

		internal CmiAuthenticodeSignerInfo(int errorCode)
		{
			m_error = errorCode;
		}

		internal CmiAuthenticodeSignerInfo(Win32.AXL_SIGNER_INFO signerInfo, Win32.AXL_TIMESTAMPER_INFO timestamperInfo)
		{
			m_error = (int)signerInfo.dwError;
			if (signerInfo.pChainContext != IntPtr.Zero)
			{
				m_signerChain = new X509Chain(signerInfo.pChainContext);
			}
			m_algHash = signerInfo.algHash;
			if (signerInfo.pwszHash != IntPtr.Zero)
			{
				m_hash = Marshal.PtrToStringUni(signerInfo.pwszHash);
			}
			if (signerInfo.pwszDescription != IntPtr.Zero)
			{
				m_description = Marshal.PtrToStringUni(signerInfo.pwszDescription);
			}
			if (signerInfo.pwszDescriptionUrl != IntPtr.Zero)
			{
				m_descriptionUrl = Marshal.PtrToStringUni(signerInfo.pwszDescriptionUrl);
			}
			if (timestamperInfo.dwError != 2148204800u)
			{
				m_timestamperInfo = new CmiAuthenticodeTimestamperInfo(timestamperInfo);
			}
		}
	}
	internal class CmiAuthenticodeTimestamperInfo
	{
		private int m_error;

		private X509Chain m_timestamperChain;

		private DateTime m_timestampTime;

		private uint m_algHash;

		internal int ErrorCode => m_error;

		internal uint HashAlgId => m_algHash;

		internal DateTime TimestampTime => m_timestampTime;

		internal X509Chain TimestamperChain => m_timestamperChain;

		private CmiAuthenticodeTimestamperInfo()
		{
		}

		internal CmiAuthenticodeTimestamperInfo(Win32.AXL_TIMESTAMPER_INFO timestamperInfo)
		{
			m_error = (int)timestamperInfo.dwError;
			m_algHash = timestamperInfo.algHash;
			long fileTime = (long)(((ulong)(uint)timestamperInfo.ftTimestamp.dwHighDateTime << 32) | (uint)timestamperInfo.ftTimestamp.dwLowDateTime);
			m_timestampTime = DateTime.FromFileTime(fileTime);
			if (timestamperInfo.pChainContext != IntPtr.Zero)
			{
				m_timestamperChain = new X509Chain(timestamperInfo.pChainContext);
			}
		}
	}
}
namespace Microsoft.Internal.Performance
{
	internal sealed class CodeMarkers
	{
		internal class NativeMethods
		{
			[DllImport("Microsoft.Internal.Performance.CodeMarkers.dll", EntryPoint = "InitPerf")]
			public static extern void DllInitPerf(int iApp);

			[DllImport("Microsoft.Internal.Performance.CodeMarkers.dll", EntryPoint = "UnInitPerf")]
			public static extern void DllUnInitPerf(int iApp);

			[DllImport("Microsoft.Internal.Performance.CodeMarkers.dll", EntryPoint = "PerfCodeMarker")]
			public static extern void DllPerfCodeMarker(int nTimerID, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] aUserParams, int cbParams);

			[DllImport("kernel32.dll")]
			public static extern ushort FindAtom(string lpString);

			[DllImport("kernel32.dll")]
			public static extern ushort AddAtom(string lpString);

			[DllImport("kernel32.dll")]
			public static extern ushort DeleteAtom(ushort atom);
		}

		private const string AtomName = "VSCodeMarkersEnabled";

		private const string DllName = "Microsoft.Internal.Performance.CodeMarkers.dll";

		public static readonly CodeMarkers Instance = new CodeMarkers();

		private bool fUseCodeMarkers;

		private CodeMarkers()
		{
			fUseCodeMarkers = NativeMethods.FindAtom("VSCodeMarkersEnabled") != 0;
		}

		public void CodeMarker(CodeMarkerEvent nTimerID)
		{
			if (!fUseCodeMarkers)
			{
				return;
			}
			try
			{
				NativeMethods.DllPerfCodeMarker((int)nTimerID, null, 0);
			}
			catch (DllNotFoundException)
			{
				fUseCodeMarkers = false;
			}
		}

		public void CodeMarkerEx(CodeMarkerEvent nTimerID, byte[] aBuff)
		{
			if (aBuff == null)
			{
				throw new ArgumentNullException("aBuff");
			}
			if (!fUseCodeMarkers)
			{
				return;
			}
			try
			{
				NativeMethods.DllPerfCodeMarker((int)nTimerID, aBuff, aBuff.Length);
			}
			catch (DllNotFoundException)
			{
				fUseCodeMarkers = false;
			}
		}

		[Obsolete("Please use InitPerformanceDll(CodeMarkerApp, string) instead to specify a registry root")]
		public void InitPerformanceDll(CodeMarkerApp iApp)
		{
			InitPerformanceDll(iApp, "Software\\Microsoft\\VisualStudio\\8.0");
		}

		public void InitPerformanceDll(CodeMarkerApp iApp, string strRegRoot)
		{
			fUseCodeMarkers = false;
			if (!UseCodeMarkers(strRegRoot))
			{
				return;
			}
			try
			{
				NativeMethods.AddAtom("VSCodeMarkersEnabled");
				NativeMethods.DllInitPerf((int)iApp);
				fUseCodeMarkers = true;
			}
			catch (DllNotFoundException)
			{
			}
		}

		[Obsolete("Second parameter is ignored. Please use InitPerformanceDll(CodeMarkerApp, string) instead to specify a registry root")]
		public void InitPerformanceDll(CodeMarkerApp iApp, bool bEndBoot)
		{
			InitPerformanceDll(iApp);
		}

		private bool UseCodeMarkers(string strRegRoot)
		{
			return !string.IsNullOrEmpty(GetPerformanceSubKey(Registry.LocalMachine, strRegRoot));
		}

		private string GetPerformanceSubKey(RegistryKey hKey, string strRegRoot)
		{
			if (hKey == null)
			{
				return null;
			}
			string result = null;
			using RegistryKey registryKey = hKey.OpenSubKey(strRegRoot + "\\Performance");
			if (registryKey != null)
			{
				return registryKey.GetValue("").ToString();
			}
			return result;
		}

		public void UninitializePerformanceDLL(CodeMarkerApp iApp)
		{
			if (!fUseCodeMarkers)
			{
				return;
			}
			fUseCodeMarkers = false;
			ushort num = NativeMethods.FindAtom("VSCodeMarkersEnabled");
			if (num != 0)
			{
				NativeMethods.DeleteAtom(num);
			}
			try
			{
				NativeMethods.DllUnInitPerf((int)iApp);
			}
			catch (DllNotFoundException)
			{
			}
		}
	}
	internal enum CodeMarkerApp
	{
		UNDEFINEDPERF = 50,
		WORDPERF = 1,
		EXCELPERF = 2,
		ACCESSPERF = 3,
		PPTPERF = 4,
		OUTLOOKPERF = 5,
		ZENPERF = 6,
		SBTPERF = 7,
		GRAPHPERF = 8,
		MSOPERF = 9,
		PROJECTPERF = 12,
		WEBSERVERPERF = 18,
		IEPERF = 27,
		FRONTPAGEPERF = 30,
		PUBLISHERPERF = 31,
		PHOTODRAWPERF = 32,
		HELPPERF = 33,
		NSEPERF = 34,
		VISIOPERF = 35,
		DESIGNERPERF = 36,
		XDOCSPERF = 37,
		VSDEVENVPERF = 51,
		VSMSDNPERF = 52,
		VSVSAENVPERF = 53,
		VSDBGPERF = 54,
		VSMODPERF = 55,
		VSFOXPROPERF = 56,
		VSSEXPPERF = 57,
		VWDEXPRESSPERF = 58,
		VBEXPRESSPERF = 59,
		VCEXPRESSPERF = 60,
		VCSEXPRESSPERF = 61,
		VJSEXPRESSPERF = 62,
		CLICKONCEPERF = 63,
		DEVEMULATORPERF = 65,
		MBFDEPLOYMENT = 70
	}
	internal enum CodeMarkerEvent
	{
		perfBeginSession = 1,
		perfSeatBeltEndSession = 2,
		perfCPUFrequency = 3,
		perfInitOverheadStart = 4,
		perfInitOverheadStop = 5,
		perfUnInitOverheadStart = 6,
		perfUnInitOverheadStop = 7,
		perfCalibrate1 = 8,
		perfCalibrate2 = 9,
		perfREBOOT = 10,
		perfBootStart = 500,
		perfBootStop = 501,
		perfIdle = 502,
		perfOpenStart = 503,
		perfOpenEnd = 504,
		perfPrintStart = 505,
		perfPrintEnd = 506,
		perfSaveStart = 507,
		perfSaveEnd = 508,
		perfNextSlide = 509,
		perfSlideShowBegin = 510,
		perfNewFileBegin = 511,
		perfDialogBegin = 512,
		perfPrintReturnControl = 513,
		perfSlideShowBackSlide = 514,
		perfOLEInsertBegin = 515,
		perfSlideViewScrollBegin = 516,
		perfNewMessageBegin = 517,
		perfNewMessageEnd = 518,
		perfNewAddrBegin = 519,
		perfNewAddrEnd = 520,
		perfNewNoteBegin = 521,
		perfNewNoteEnd = 522,
		perfNewTaskBegin = 523,
		perfNewTaskEnd = 524,
		perfNewApptBegin = 525,
		perfNewApptEnd = 526,
		perfNewDistListBegin = 527,
		perfNewDistListEnd = 528,
		perfOnDeliverMailStart = 529,
		perfOnDeliverMailStop = 530,
		perfSelectTopItemBegin = 531,
		perfSelectTopItemEnd = 532,
		perfReplyToItemBegin = 533,
		perfReplyToItemEnd = 534,
		perfOnMailSendBegin = 535,
		perfOnMailSendEnd = 536,
		perfDeleteItemBegin = 537,
		perfDeleteItemEnd = 538,
		perfOpenAttachBegin = 539,
		perfOpenAttachEnd = 540,
		perfDeleteItemInspectorBegin = 541,
		perfDeleteItemInspectorEnd = 542,
		perfCheckNameBegin = 543,
		perfCheckNameEnd = 544,
		perfEndBootAtInit = 545,
		perfChangeFolderBegin = 546,
		perfChangeFolderEnd = 547,
		perfExitBegin = 548,
		perfExitEnd = 549,
		perfMoveItemtoFolderBegin = 550,
		perfMoveItemtoFolderEnd = 551,
		perfEmptyDelItemsBegin = 552,
		perfEmptyDelItemsEnd = 553,
		perfAcceptMRBegin = 554,
		perfAcceptMREnd = 555,
		perfGoToDateBegin = 556,
		perfGoToDateEnd = 557,
		perfFindOrgBegin = 558,
		perfFindOrgEnd = 559,
		perfOutlookTodayBegin = 560,
		perfOutlookTodayEnd = 561,
		perfExcelRecalcBegin = 562,
		perfExcelRecalcEnd = 563,
		perfCopyBegin = 564,
		perfCopyEnd = 565,
		perfPasteBegin = 566,
		perfPasteEnd = 567,
		perfExcelPivotTableWizardBegin = 568,
		perfExcelPivotTableWizardEnd = 569,
		perfWordRepagStart = 570,
		perfWordRepagStop = 571,
		perfWordScrollStart = 572,
		perfWordScrollStop = 573,
		perfCutBegin = 574,
		perfCutEnd = 575,
		perfInsertBegin = 576,
		perfInsertEnd = 577,
		perfExcelRunMacroBegin = 578,
		perfExcelRunMacroEnd = 579,
		perfExcelClearAllBegin = 580,
		perfExcelClearAllEnd = 581,
		perfGroupObjBegin = 582,
		perfGroupObjEnd = 583,
		perfUngroupObjBegin = 584,
		perfUngroupObjEnd = 585,
		perfExcelScrollPaneBegin = 586,
		perfExcelScrollPaneEnd = 587,
		perfExcelColBestFitBegin = 588,
		perfExcelColBestFitEnd = 589,
		perfExcelDrawPaneBegin = 590,
		perfExcelDrawPaneEnd = 591,
		perfExcelDrawingCommandBegin = 592,
		perfExcelDrawingCommandEnd = 593,
		perfShowVBEBegin = 594,
		perfShowVBEEnd = 595,
		perfExcelDrawChartBegin = 596,
		perfExcelDrawChartEnd = 597,
		perfNewDatabaseBegin = 598,
		perfNewDatabaseEnd = 599,
		perfOpenDatabaseBegin = 600,
		perfOpenDatabaseEnd = 601,
		perfOpenObjectBegin = 602,
		perfOpenObjectEnd = 603,
		perfWizardBegin = 604,
		perfWizardEnd = 605,
		perfWizardReady = 606,
		perfBuilderBegin = 607,
		perfBuilderEnd = 608,
		perfBuilderReady = 609,
		perfFrontPageNewWebBegin = 610,
		perfFrontPageNewWebEnd = 611,
		perfFrontPageOpenWebBegin = 612,
		perfFrontPageOpenWebEnd = 613,
		perfFrontPageCloseWebBegin = 614,
		perfFrontPageCloseWebEnd = 615,
		perfFrontPageReportsViewBegin = 616,
		perfFrontPageReportsViewEnd = 617,
		perfFrontPageReportsSummaryBegin = 618,
		perfFrontPageReportsSummaryEnd = 619,
		perfOutlookForwardItemBegin = 620,
		perfOutlookForwardItemEnd = 621,
		perfOutlookCloseItemBegin = 622,
		perfOutlookCloseItemEnd = 623,
		perfOwcCreateObjectBegin = 624,
		perfOwcCreateObjectEnd = 625,
		perfOwcFreezeEventsBegin = 626,
		perfOwcFreezeEventsEnd = 627,
		perfAtlPersistPropBagLoadBegin = 628,
		perfAtlPersistPropBagLoadEnd = 629,
		perfOwcLoadObjectBegin = 630,
		perfOwcLoadObjectEnd = 631,
		perfAtlQuickActivateBegin = 632,
		perfAtlQuickActivateEnd = 633,
		perfOwcGenericEventInvokeBegin = 634,
		perfOwcGenericEventInvokeEnd = 635,
		perfAtlPersistPropBagSaveBegin = 636,
		perfAtlPersistPropBagSaveEnd = 637,
		perfAtlViewObjectDrawBegin = 638,
		perfAtlViewObjectDrawEnd = 639,
		perfOwcFinalReleaseBegin = 640,
		perfOwcFinalReleaseEnd = 641,
		perfOutlookReplyForwardOnItemBegin = 642,
		perfOutlookReplyForwardOnItemEnd = 643,
		perfExcelMoveCopySheetBegin = 644,
		perfExcelMoveCopySheetEnd = 645,
		perfWordNewStart = 646,
		perfWordNewEnd = 647,
		perfWordCountStart = 648,
		perfWordCountEnd = 649,
		perfWordOutlineViewStart = 650,
		perfWordOutlineViewEnd = 651,
		perfWordPageViewStart = 652,
		perfWordPageViewEnd = 653,
		perfWordNormalViewStart = 654,
		perfWordNormalViewEnd = 655,
		perfWordWebViewStart = 656,
		perfWordWebViewEnd = 657,
		perfWordFindNextStart = 658,
		perfWordFindNextEnd = 659,
		perfWordFindAllStart = 660,
		perfWordFindAllEnd = 661,
		perfWordReplaceAllStart = 662,
		perfWordReplaceAllEnd = 663,
		perfWordAutoFormatStart = 664,
		perfWordAutoFormatEnd = 665,
		perfWordInsPictureStart = 666,
		perfWordInsPictureEnd = 667,
		perfWordInsBookmarkStart = 668,
		perfWordInsBookmarkEnd = 669,
		perfWordInsSymbolStart = 670,
		perfWordInsSymbolEnd = 671,
		perfWordInsObjectStart = 672,
		perfWordInsObjectEnd = 673,
		perfWordInsTocStart = 674,
		perfWordInsTocEnd = 675,
		perfWordSpellStart = 676,
		perfWordSpellEnd = 677,
		perfWordGrammarStart = 678,
		perfWordGrammarEnd = 679,
		perfWordInsCommentStart = 680,
		perfWordInsCommentEnd = 681,
		perfIOLDocUploadStart = 682,
		perfIOLDocUploadEnd = 683,
		perfIOLDocDownloadStart = 684,
		perfIOLDocDownloadEnd = 685,
		perfHlinkDownloadStart = 686,
		perfHlinkDownloadEnd = 687,
		perfPostNavigateStart = 688,
		perfPostNavigateEnd = 689,
		perfNavigateStart = 690,
		perfNavigateEnd = 691,
		perfNSEDeleteStart = 692,
		perfNSEDeleteEnd = 693,
		perfNSEDragDropStart = 694,
		perfNSEDragDropEnd = 695,
		perfNSEEnumStart = 696,
		perfNSEEnumEnd = 697,
		perfOutlookSaveCloseStart = 698,
		perfOutlookSaveCloseEnd = 699,
		perfExcelBkgndErrChkStart = 700,
		perfExcelBkgndErrChkEnd = 701,
		perfOutlookSyncOSTStart = 702,
		perfOutlookSyncOSTEnd = 703,
		perfAccessCompileBegin = 704,
		perfAccessCompileEnd = 705,
		perfAccessSaveProjectBegin = 706,
		perfAccessSaveProjectEnd = 707,
		perfPhdSolidColorFillStart = 708,
		perfPhdFadeStart = 709,
		perfPhdBlurSharpStart = 710,
		perfPhdPhotoCorrectionStart = 711,
		perfPhdDesignerEffectStart = 712,
		perfPhdDrawAutoShapeStart = 713,
		perfPhdPhotoArtisticBrushStart = 714,
		perfPhdDesignerEdgeStart = 715,
		perfPhdColorCorrectStart = 716,
		perfPhdMoveStart = 717,
		perfPhdResizeStart = 718,
		perfPhdRotateStart = 719,
		perfPhd3DStart = 720,
		perfPhdInsertTextStart = 721,
		perfPhdUpdateTextStart = 722,
		perfPhdTemplatesStart = 723,
		perfPhdDocSwitchStart = 724,
		perfPhdWorkpaneStart = 725,
		perfPhdZoomStart = 726,
		perfPhdCropStart = 727,
		perfPhdCutOutStart = 728,
		perfPPTApplyTemplateStart = 729,
		perfPPTChangeView = 730,
		perfPPTAddMaster = 731,
		perfPPTDeleteMaster = 732,
		perfFrontPageWebProvisionBegin = 733,
		perfFrontPageWebProvisionEnd = 734,
		perfFrontPageEnsureFolderBegin = 735,
		perfFrontPageEnsureFolderEnd = 736,
		perfFrontPageDownloadFileBegin = 737,
		perfFrontPageDownloadFileEnd = 738,
		perfFrontPageBrowserOpBegin = 739,
		perfFrontPageBrowserOpEnd = 740,
		perfFrontPageUploadFileBegin = 741,
		perfFrontPageUploadFileEnd = 742,
		perfOfficeHlinkDialogBootBegin = 743,
		perfOfficeHlinkDialogBootEnd = 744,
		perfOfficeHlinkDialogBegin = 745,
		perfOfficeHlinkDialogReady = 746,
		perfOwcPageInteractive = 747,
		perfOutlookContactQuickFindBegin = 748,
		perfOutlookContactQuickFindEnd = 749,
		perfOfficeFileSaveDlgBegin = 750,
		perfSCPCodeVerBegin = 751,
		perfSCPCodeVerEnd = 752,
		perfFrontPageBlockingRpcBegin = 753,
		perfFrontPageBlockingRpcEnd = 754,
		perfFrontPageListUrlsBegin = 755,
		perfFrontPageListUrlsEnd = 756,
		perfFrontPageEnsureFullListBegin = 757,
		perfFrontPageEnsureFullListEnd = 758,
		perfFrontPageFolderViewBegin = 759,
		perfFrontPageFolderViewEnd = 760,
		perfFrontPageStructureViewBegin = 761,
		perfFrontPageStructureViewEnd = 762,
		perfFrontPagePageViewBegin = 763,
		perfFrontPagePageViewEnd = 764,
		perfFrontPageTodoViewBegin = 765,
		perfFrontPageTodoViewEnd = 766,
		perfFrontPageUsageViewBegin = 767,
		perfFrontPageUsageViewEnd = 768,
		perfFrontPageHyperLinkViewBegin = 769,
		perfFrontPageHyperLinkViewEnd = 770,
		perfFrontPageSaveStructureBegin = 771,
		perfFrontPageSaveStructureEnd = 772,
		perfFrontPagePutDocMetaBegin = 773,
		perfFrontPagePutDocMetaEnd = 774,
		perfFrontPageRecalcBegin = 775,
		perfFrontPageRecalcEnd = 776,
		perfFrontPageFolderExpandBegin = 777,
		perfFrontPageFolderExpandEnd = 778,
		perfFrontPageFolderContractBegin = 779,
		perfFrontPageFolderContractEnd = 780,
		perfFrontPageCrossWebFindBegin = 781,
		perfFrontPageCrossWebFindEnd = 782,
		perfFrontPageNewPageBegin = 783,
		perfFrontPageNewPageEnd = 784,
		perfFrontPageSharedBorderBegin = 785,
		perfFrontPageSharedBorderEnd = 786,
		perfFrontPageThemeBegin = 787,
		perfFrontPageThemeEnd = 788,
		perfFrontPageStructureDeletePageBegin = 789,
		perfFrontPageStructureDeletePageEnd = 790,
		perfOLViewAllProposeBegin = 791,
		perfOLViewAllProposeEnd = 792,
		perfOfficeArtZoomBegin = 793,
		perfOfficeArtZoomEnd = 794,
		PerfOfficeArtScrollBegin = 795,
		PerfOfficeArtScrollEnd = 796,
		PerfOfficeArtPasteBegin = 799,
		PerfOfficeArtPasteEnd = 800,
		PerfOfficeArtRotateSelectionBegin = 801,
		PerfOfficeArtRotateSelectionEnd = 802,
		PerfOfficeArtEditSelectionBegin = 803,
		PerfOfficeArtEditSelectionEnd = 804,
		PerfOfficeArtNudgeBegin = 805,
		PerfOfficeArtNudgeEnd = 806,
		PerfOfficeArtResizeBegin = 807,
		PerfOfficeArtResizeEnd = 808,
		PerfOLProposeNTBegin = 809,
		PerfOLProposeNTEnd = 810,
		perfFrontPageEditBegin = 811,
		perfFrontPageEditEnd = 812,
		perfFrontPageScrollBegin = 813,
		perfFrontPageScrollEnd = 814,
		perfFrontPageTimerBegin = 815,
		perfFrontPageTimerEnd = 816,
		perfFrontPageRenameBegin = 817,
		perfFrontPageRenameEnd = 818,
		perfFrontPagePublishBegin = 819,
		perfFrontPagePublishEnd = 820,
		perfFrontPageResizeBegin = 821,
		perfFrontPageResizeEnd = 822,
		perfOutlookSyncGroupBegin = 823,
		perfOutlookSyncGroupEnd = 824,
		perfOutlookSyncSubmitBegin = 825,
		perfOutlookSyncSubmitEnd = 826,
		perfOwcPostPerfInit = 827,
		perfFrontPageClosePageBegin = 828,
		perfFrontPageClosePageEnd = 829,
		perfDatapageOpenStart = 830,
		perfVisioZoomStart = 831,
		perfVisioZoomEnd = 832,
		perfVisioGroupStart = 833,
		perfVisioGroupEnd = 834,
		perfVisioPrintPreviewStart = 835,
		perfVisioPrintPreviewEnd = 836,
		perfVisioUndo = 837,
		perfVisioRedo = 838,
		perfVisioSelectAllBegin = 839,
		perfVisioSelectAllEnd = 840,
		perfVisioBatchLayoutBegin = 841,
		perfVisioBatchLayoutEnd = 842,
		perfVisioAddonStart = 843,
		perfVisioAddonEnd = 844,
		perfVisioVDXParseINodeStart = 845,
		perfVisioVDXParseINodeEnd = 846,
		perfVisioVDXParseDOMStart = 847,
		perfVisioVDXParseDOMEnd = 848,
		perfVisioUnionStart = 849,
		perfVisioUnionEnd = 850,
		perfVisioFragmentStart = 851,
		perfVisioFragmentEnd = 852,
		perfVisioCombineStart = 853,
		perfVisioCombineEnd = 854,
		perfVisioSetTextANSIStart = 855,
		perfVisioSetTextANSIEnd = 856,
		perfVisioInitInsertControlDlgStart = 857,
		perfVisioInitInsertControlDlgEnd = 858,
		perfVisioDropOnPageStart = 859,
		perfVisioDropOnPageEnd = 860,
		perfVisioRefreshViewStart = 861,
		perfVisioRefreshViewEnd = 862,
		perfVisioMoveObject = 863,
		perfVisioMoveObjectEnd = 864,
		perfVisioRefreshROMStart = 865,
		perfVisioRefreshROMEnd = 866,
		perfIERenderComplete = 867,
		perfIEDone = 868,
		perfOutlookViewChangedStart = 869,
		perfOutlookViewChangedEnd = 870,
		perfDesignerNewElementStart = 871,
		perfDesignerNewElementStop = 872,
		perfDesignerOpenFormStart = 873,
		perfDesignerOpenFormStop = 874,
		perfDesignerCreateFieldStart = 875,
		perfDesignerCreateFieldStop = 876,
		perfDesignerOpenEditorStart = 877,
		perfDesignerOpenEditorStop = 878,
		perfDesignerNewAppStart = 879,
		perfDesignerNewAppStop = 880,
		perfOutlookSearchFolderSearchStart = 881,
		perfOutlookSearchFolderSearchEnd = 882,
		perfWordSmartTagBkgCheckStart = 883,
		perfWordSmartTagBkgCheckEnd = 884,
		perfWordSmartTagFrgCheckStart = 885,
		perfWordSmartTagFrgCheckEnd = 886,
		perfDesignerCreateProjectStart = 887,
		perfDesignerCreateProjectEnd = 888,
		perfDesignerOpenProjectStart = 889,
		perfDesignerOpenProjectEnd = 890,
		perfOutlookViewSortStart = 891,
		perfOutlookViewSortEnd = 892,
		perfOutlookViewScrollStart = 893,
		perfOutlookViewScrollEnd = 894,
		perfDesignerAddFieldStart = 895,
		perfDesignerAddFieldStop = 896,
		perfDesignerBootWithProjectStop = 897,
		perfDesignerUpdateFieldStart = 898,
		perfDesignerUpdateFieldStop = 899,
		perfDesignerLoadFieldChooserStart = 900,
		perfDesignerLoadFieldChooserStop = 901,
		perfDesignerUpdateFormRegStart = 902,
		perfDesignerUpdateFormRegStop = 903,
		perfDesignerSyncProjectStart = 904,
		perfDesignerSyncProjectStop = 905,
		perfDesignerToggleOfflineStart = 906,
		perfDesignerToggleOfflineStop = 907,
		perfAccessSUINavBegin = 908,
		perfAccessSUINavEnd = 909,
		perfCloseObjectBegin = 910,
		perfCloseObjectEnd = 911,
		perfOwcPivotInsertFieldSetBegin = 912,
		perfOwcPivotInsertFieldSetEnd = 913,
		perfOutlookItemViewNextPrevBegin = 914,
		perfOutlookItemViewNextPrevEnd = 915,
		perfNewClientBegin = 916,
		perfNewClientEnd = 917,
		perfNewFileEnd = 918,
		perfNewFrameBegin = 919,
		perfNewFrameEnd = 920,
		perfSubmitFormBegin = 921,
		perfSubmitFormEnd = 922,
		perfBLgcScriptLoadBegin = 923,
		perfBLgcScriptLoadEnd = 924,
		perfBLgcScriptRunBegin = 925,
		perfBLgcScriptRunEnd = 926,
		PerfBLgcNodeValidationBegin = 927,
		PerfBLgcNodeValidationEnd = 928,
		perfGITreeGenBegin = 929,
		perfGITreeGenEnd = 930,
		perfSolutionLoadBegin = 931,
		perfSolutionLoadEnd = 932,
		perfXMLUndoBegin = 933,
		perfXMLUndoEnd = 934,
		perfXMLRedoBegin = 935,
		perfXMLRedoEnd = 936,
		perfIncrementalUpdateBegin = 937,
		perfIncrementalUpdateEnd = 938,
		perfMSOXEVIconBegin = 939,
		perfMSOXEVIconEnd = 940,
		perfMSOXEVLaunchBegin = 941,
		perfMSOXEVLaunchEnd = 942,
		perfViewChangeBegin = 943,
		perfViewChangeEnd = 944,
		perfLoadGIIntoViewBegin = 945,
		perfLoadGIIntoViewEnd = 946,
		perfXSLReapplyHTMLUpdateBegin = 947,
		perfXSLReapplyHTMLUpdateEnd = 948,
		perfCalculateTokenCurrentHTMLBegin = 949,
		perfCalculateTokenCurrentHTMLEnd = 950,
		perfCalculateTokenNewHTMLBegin = 951,
		perfCalculateTokenNewHTMLEnd = 952,
		perfCalculateHTMLDifferenceBegin = 953,
		perfCalculateHTMLDifferenceEnd = 954,
		perfChangeDifferenceScopeBegin = 955,
		perfChangeDifferenceScopeEnd = 956,
		perfGenerateDeltaChangeLogsBegin = 957,
		perfGenerateDeltaChangeLogsEnd = 958,
		perfCanvasDecodeBegin = 959,
		perfCanvasDecodeEnd = 960,
		perfCanvasExecBegin = 961,
		perfCanvasExecEnd = 962,
		perfComponentInsertBegin = 963,
		perfComponentInsertEnd = 964,
		perfSolutionComponentLoadBegin = 965,
		perfSolutionComponentLoadEnd = 966,
		perfSolutionComponentUnloadBegin = 967,
		perfSolutionComponentUnloadEnd = 968,
		perfSolutionComponentPaneLaunchBegin = 969,
		perfSolutionComponentPaneLaunchEnd = 970,
		perfXMLToXSDBegin = 971,
		perfXMLToXSDEnd = 972,
		perfXMLToXSDBuildDataStructuresBegin = 973,
		perfXMLToXSDBuildDataStructuresEnd = 974,
		perfXMLToXSDGenerateXSDBegin = 975,
		perfXMLToXSDGenerateXSDEnd = 976,
		perfApplyXSLReapplyBegin = 977,
		perfApplyXSLReapplyEnd = 978,
		perfOpen_NewCtrlLoadBegin = 979,
		perfOpen_NewCtrlLoadEnd = 980,
		perfOpen_DocSurfaceBegin = 981,
		perfOpen_DocSurfaceEnd = 982,
		perfOpen_ContextWorkBegin = 983,
		perfOpen_ContextWorkEnd = 984,
		perfSaveAsStart = 985,
		perfSaveAsEnd = 986,
		perfDataObjectLoadFromURLBegin = 987,
		perfDataObjectLoadFromURLEnd = 988,
		perfDataObjectSaveFromURLBegin = 989,
		perfDataObjectSaveFromURLEnd = 990,
		perfSubmitPreCheckBegin = 991,
		perfSubmitPreCheckEnd = 992,
		perfDataObjectCloseBegin = 993,
		perfDataObjectCloseEnd = 994,
		perfDataObjectSubmitBegin = 995,
		perfDataObjectSubmitEnd = 996,
		perfDataObjectLoadFromDocBegin = 997,
		perfDataObjectLoadFromDocEnd = 998,
		perfDataObjectSaveFromDocBegin = 999,
		perfDataObjectSaveFromDocEnd = 1000,
		perfXDocsBootBegin = 1001,
		perfXDocsBootEnd = 1002,
		perfBoldBegin = 1003,
		perfBoldEnd = 1004,
		perfItalicsBegin = 1005,
		perfItalicsEnd = 1006,
		perfHTMLUndoBegin = 1007,
		perfHTMLUndoEnd = 1008,
		perfHTMLRedoBegin = 1009,
		perfHTMLRedoEnd = 1010,
		perfInsertTableBegin = 1011,
		perfInsertTableEnd = 1012,
		perfInsertInternalTableBegin = 1013,
		perfInsertInternalTableEnd = 1014,
		perfInternalTableMoveBegin = 1015,
		perfInternalTableMoveEnd = 1016,
		perfInsertRowBegin = 1017,
		perfInsertRowEnd = 1018,
		perfInsertColBegin = 1019,
		perfInsertColEnd = 1020,
		perfInsertRowInternalBegin = 1021,
		perfInsertRowInternalEnd = 1022,
		perfInsertColInternalBegin = 1023,
		perfInsertColInternalEnd = 1024,
		perfInsertListBegin = 1025,
		perfInsertListEnd = 1026,
		perfRecalcBegin = 1027,
		perfRecalcEnd = 1028,
		perfInsertFFFBegin = 1029,
		perfInsertFFFEnd = 1030,
		perfCanvasActionBegin = 1031,
		perfCanvasActionEnd = 1032,
		perfVSShowMainWindow = 7000,
		perfVSStatusBarReady = 7001,
		perfVSLoadPropertyBrowserBegin = 7002,
		perfVSLoadPropertyBrowserEnd = 7003,
		perfVSInVStudioMain = 7004,
		perfVSStartPageCreated = 7005,
		perfVSDynamicHelpUpdate = 7006,
		perfVSLoadUIBegin = 7007,
		perfVSLoadUIEnd = 7008,
		perfVSBrowserDocumentComplete = 7009,
		perfVSInitThread = 7010,
		perfVSFindInFilesBegin = 7011,
		perfVSFindInFilesEnd = 7012,
		perfVSStatusBarBuildSucceeded = 7013,
		perfVSStatusBarRebuildSucceeded = 7014,
		perfVSDebuggerEnterBreakState = 7015,
		perfVSDebuggerSessionEnd = 7016,
		perfVSDebuggerReceivesLoadCompleteEvent = 7017,
		perfVSDebuggerReceivesEntryPointEvent = 7018,
		perfVSDebuggerReceivesGoCommand = 7019,
		perfVSDebuggerReceivesStartNoDebugCommand = 7020,
		perfVSDebuggerReceivesStepIntoCommand = 7021,
		perfVSDebuggerReceivesStepOverCommand = 7022,
		perfVSDebuggerReceivesStepOutCommand = 7023,
		perfVSDebuggerReceivesBreakCommand = 7024,
		perfVSDebuggerReceivesStopCommand = 7025,
		perfVSDebuggerReceivesRestartCommand = 7026,
		perfVSDebuggerLaunchesAllTargets = 7027,
		perfVSDebuggerSendsStartDebuggingRequest = 7028,
		perfVSDebuggerLaunchesSingleTarget = 7029,
		perfVSDebuggerAutoAttachComplete = 7030,
		perfVSDebuggerAddBreakpoint = 7031,
		perfVSDebuggerToggleBreakpoint = 7032,
		perfVSDebuggerInsertBreakpoint = 7033,
		perfVSEditorNavigate = 7034,
		perfVSEditorPasteBegin = 7035,
		perfVSEditorPasteEnd = 7036,
		perfVSEditorFileLoadBegin = 7037,
		perfVSEditorFileLoadEnd = 7038,
		perfVSEditorToolTipPaint = 7039,
		perfVSEditorStatementCompletionPaint = 7040,
		perfVSEditorCutBegin = 7041,
		perfVSEditorCutEnd = 7042,
		perfVSEditorWordWrapBegin = 7043,
		perfVSEditorWordWrapEnd = 7044,
		perfVSEditorStatementCompletionWordInsert = 7045,
		perfVSEditorCommit = 7046,
		perfVSProjectLoad = 7047,
		perfVSFileOpen = 7048,
		perfVSExternalToolComplete = 7049,
		perfVSTaskListPopulated = 7050,
		perfVSCVExpanded = 7051,
		perfVSUIHierExpanded = 7052,
		perfVSClassViewPopulated = 7053,
		perfVSEditGoToDeclaration = 7054,
		perfVSEditGoToDefinition = 7055,
		perfVSEditorDropDownDropped = 7056,
		perfVSSolutionExplorerNavigation = 7057,
		perfVSSolutionExplorerSolutionPopulated = 7058,
		perfVSUIHierCollapsed = 7059,
		perfVSHelpFilterUpdated = 7060,
		perfVSHelpFilterCacheRecomputed = 7061,
		perfVSHelpFilterIndexUIUpdated = 7062,
		perfVSHelpFilterContentsUIUpdated = 7063,
		perfVSHelpFilterFTSResultsUIUpdated = 7064,
		perfVSHelpSearchCompleted = 7065,
		perfVSCloseSolution = 7066,
		perfVSSaveAll = 7067,
		perfVSDebuggingFinishedLoadingPackage = 7068,
		perfVSSolutionBeginDeploy = 7069,
		perfVSSolutionEndDeploy = 7070,
		perfVSStartPageLoadDownloadService = 7071,
		perfVSMacrosExplorerShowEnd = 7080,
		perfVSMacrosIDEShowEnd = 7081,
		perfVSMacrosMacroRunEnd = 7082,
		perfVSStatusBarBuildFailed = 7090,
		perfVSStatusBarRebuildFailed = 7091,
		perfVSStatusBarBuildCanceled = 7092,
		perfVSStatusBarRebuildCanceled = 7093,
		perfVSToolboxSupportedCheckStart = 7094,
		perfVSToolboxSupportedCheckStop = 7095,
		perfVSToolboxResetDone = 7096,
		perfVSPrimeCLRNotScheduled = 7097,
		perfVSHelpIndexLoadComplete = 7100,
		perfVSPrimeCLRBegin = 7101,
		perfVSPrimeCLREnd = 7102,
		perfVSFinishedBooting = 7103,
		perfVSNewProjectDlgComplete = 7104,
		perfVSBrowserDocumentNavigateStart = 7105,
		perfVSNewProjectDlgOpened = 7106,
		perfVSHelpF1CommandHandler = 7110,
		perfVSHelpF1ContextPacking = 7111,
		perfVSHelpF1RemoteF1Call = 7112,
		perfVSHelpF1ContextUnpacking = 7113,
		perfVSHelpF1LocalDataLookup = 7114,
		perfVSHelpF1LocalDataFound = 7115,
		perfVSHelpF1ShowURL = 7116,
		perfVSHelpWBLogTopicId = 7117,
		perfVSHelpStartLoadHxSession = 7120,
		perfVSHelpCompleteLoadHxSession = 7121,
		perfVSHelpStartLoadHxCollection = 7122,
		perfVSHelpCompleteLoadHxCollection = 7123,
		perfVSHelpStartLoadHxIndex = 7124,
		perfVSHelpCompleteLoadHxIndex = 7125,
		perfVSHelpStartLoadHxTOC = 7126,
		perfVSHelpCompleteLoadHxTOC = 7127,
		perfVSHelpStartLoadHxFIndex = 7128,
		perfVSHelpCompleteLoadHxFIndex = 7129,
		perfVSHelpStartLoadHxKIndex = 7130,
		perfVSHelpCompleteLoadHxKIndex = 7131,
		perfVSHelpStartLoadHxAIndex = 7132,
		perfVSHelpCompleteLoadHxAIndex = 7133,
		perfVSHelpStartLocalSearch = 7141,
		perfVSHelpStartHHQuery = 7142,
		perfVSHelpCompleteHHQuery = 7143,
		perfVSHelpCompleteLocalSearch = 7144,
		perfHxInitializeSession = 7160,
		perfHxCollectionCreated = 7161,
		perfHxCollectionFileLoaded = 7162,
		perfHxExCollectionLoaded = 7163,
		perfHxCollectionInitialized = 7164,
		perfHxExCollectionStartInit = 7165,
		perfHxExCollNSpaceListInit = 7166,
		perfHxExCollCtrlNSpaceInit = 7167,
		perfHxExCollNSpaceInit = 7168,
		perfHxExCollNSpaceCollLoad = 7169,
		perfHxExCollTitleListBuilt = 7170,
		perfHxExCollTopicsCounted = 7171,
		perfHxExCollGotTitleInfo = 7172,
		perfHxExCollMergeValidated = 7173,
		perfHxExCollInitFTSKeyword = 7174,
		perfHxExCollBTLStart = 7175,
		perfHxExCollBTLBuiltFileList = 7176,
		perfHxExCollBTLValidatedColl = 7177,
		perfHxExCollBTLHelpFileChanged = 7178,
		perfHxExCollBTLGotHelpFilesInfo = 7179,
		perfHxExCollBTLValidatedFastInfo = 7180,
		perfHxExCollBTLPersistedValidation = 7181,
		perfHxExCollBTLHelpFileNotChanged = 7182,
		perfHxExCollBTLPulledFastInfoData = 7183,
		perfVSProfilerAttached = 7198,
		perfVSClientRunStart = 7199,
		perfVBCompilerPrettyListBegin = 7200,
		perfVBCompilerPrettyListEnd = 7201,
		perfVBCompilerStartOutliningBegin = 7202,
		perfVBCompilerStartOutliningEnd = 7203,
		perfVBCompilerUpdateLineSeparatorsBegin = 7204,
		perfVBCompilerUpdateLineSeparatorsEnd = 7205,
		perfVBCompilerEditClassifyBegin = 7206,
		perfVBCompilerEditClassifyEnd = 7207,
		perfVBCompilerEditFilterBegin = 7208,
		perfVBCompilerEditFilterEnd = 7209,
		perfVBCompilerSymbolLocationUpdateBegin = 7210,
		perfVBCompilerSymbolLocationUpdateEnd = 7211,
		perfVBCompilerBackgroundThreadStop = 7212,
		perfVBCompilerBackgroundThreadStart = 7213,
		perfVBCompilerCodeModelLoadFileBegin = 7214,
		perfVBCompilerCodeModelLoadFileEnd = 7215,
		perfVBCompilerDropDownLoadBegin = 7216,
		perfVBCompilerDropDownLoadEnd = 7217,
		perfVBCompilerClassViewObjectRefreshBegin = 7218,
		perfVBCompilerClassViewObjectRefreshEnd = 7219,
		perfVBCompilerIntellisenseBegin = 7220,
		perfVBCompilerIntellisenseEnd = 7221,
		perfVBCompilerReachedBoundState = 7222,
		perfVBCompilerReachedCompiledState = 7223,
		perfVBCompilerCompilationAborted = 7224,
		perfVBCompilerFileChanged = 7225,
		perfVBDebuggerENCDeltaGenBegin = 7226,
		perfVBDebuggerENCDeltaGenEnd = 7227,
		perfVBDebuggerENCEnterBreak = 7228,
		perfVBDebuggerENCExitBreak = 7229,
		perfVBCompilerRegisterDesignViewAttributeBegin = 7230,
		perfVBCompilerRegisterDesignViewAttributeEnd = 7231,
		perfVBCompilerCommitBegin = 7232,
		perfVBCompilerCommitEnd = 7233,
		perfViewSwitchBegin = 7300,
		perfViewSwitchEnd = 7301,
		perfParseBegin = 7302,
		perfParseEnd = 7303,
		perfSecondaryBufferCodeGenerationBegin = 7304,
		perfSecondaryBufferCodeGenerationEnd = 7305,
		perfIntellisenseWindowPopulationBegin = 7306,
		perfIntellisenseWindowPopulationEnd = 7307,
		perfSchemaLoadBegin = 7308,
		perfSchemaLoadEnd = 7309,
		perfValidationBegin = 7310,
		perfValidationEnd = 7311,
		perfSCPBegin = 7312,
		perfSCPEnd = 7313,
		perfEditorReady = 7314,
		perfEditorStartupBegin = 7316,
		perfEditorStartupEnd = 7317,
		perfWebFormTagIntellisenseReady = 7318,
		perfWebFormCodeIntellisenseReady = 7319,
		qaTaskListReady = 7320,
		qaMarkupOutlineReady = 7321,
		perfWebFormEventNavigationBegin = 7322,
		perfWebFormEventNavigationEnd = 7323,
		perfWebFormLoadComplete = 7324,
		perfWebFormFirstIdleInView = 7325,
		perfIntellisenseParseBegin = 7326,
		perfIntellisenseParseEnd = 7327,
		perfVCDTParseOnMainThreadBegin = 7350,
		perfVCDTParseOnParserThreadBegin = 7351,
		perfVCDTParseEnd = 7352,
		perfVCDTParseAbort = 7353,
		perfVSProjShowCodeBegin = 7400,
		perfVSProjShowCodeEnd = 7401,
		perfVSProjShowDesignerBegin = 7402,
		perfVSProjShowDesignerEnd = 7403,
		perfVSProjFactoryCreateProjectBegin = 7404,
		perfVSProjFactoryCreateProjectEnd = 7405,
		perfVSProjCreateProjectBegin = 7406,
		perfVSProjCreateProjectEnd = 7407,
		perfVSProjLoadProjectFileBegin = 7408,
		perfVSProjLoadProjectFileEnd = 7409,
		perfVSProjPublishBegin = 7410,
		perfVSProjPublishEnd = 7411,
		perfVSProjLoadMSBuildProjectFileBegin = 7412,
		perfVSProjLoadMSBuildProjectFileEnd = 7413,
		perfVSProjSetCmdUIContextBegin = 7414,
		perfVSProjSetCmdUIContextEnd = 7415,
		perfVSSolutionOnAfterOpenSolutionBegin = 7416,
		perfVSSolutionOnAfterOpenSolutionEnd = 7417,
		perfVSProjPOGRefreshBegin = 7418,
		perfVSProjPOGRefreshEnd = 7419,
		perfVSProjOnAfterManagedProjectCreate = 7420,
		perfVSProjOnStartHostingProcess = 7421,
		perfVSProjOnHostingProcessNotUsed = 7422,
		perfEditorReplaceInFilesStart = 7423,
		perfEditorReplaceInFilesEnd = 7424,
		perfEditorPaintStart = 7425,
		perfEditorPaintEnd = 7426,
		perfEditorLoadTextImageFromMemoryStart = 7427,
		perfEditorLoadTextImageFromMemoryEnd = 7428,
		perfEditorSaveTextImageToMemoryStart = 7429,
		perfEditorSaveTextImageToMemoryEnd = 7430,
		perfEditorSaveTextReplaceLinesExStart = 7431,
		perfEditorSaveTextReplaceLinesExEnd = 7432,
		perfEditorSaveTextReplaceStreamExStart = 7433,
		perfEditorSaveTextReplaceStreamExEnd = 7434,
		perfEditorSaveTextVerticalScrollStart = 7435,
		perfEditorSaveTextVerticalScrollEnd = 7436,
		perfEditorCreateEditorInstance = 7437,
		perfVSWebMigrationBegin = 7450,
		perfVSWebMigrationEnd = 7451,
		perfVSWebAfterFirstIdle = 7452,
		perfVSWebOpenStarts = 7453,
		perfVSWebOpenEnds = 7454,
		perfVSWebInitialProcessingComplete = 7455,
		perfVSWebBuildWebsiteBegins = 7456,
		perfVSWebBuildWebsiteEnds = 7457,
		perfVSWebCodeMarkerControl = 7458,
		perfVSTProjectPackageSetSiteStart = 8000,
		perfVSTProjectPrecreateForOuterStart = 8001,
		perfVSTProjectSetInnerProjectEnd = 8002,
		perfVSTProjectInitializeForOuterStart = 8003,
		perfVSTProjectInitializeForOuterEnd = 8004,
		perfVSTProjectSyncWithHostStart = 8005,
		perfVSTProjectSyncWithHostEnd = 8006,
		perfVSTProjectSetProjectClientStart = 8007,
		perfVSTProjectSetProjectClientEnd = 8008,
		perfVSTProjectOnProjectCreatedStart = 8009,
		perfVSTProjectOnProjectCreatedEnd = 8010,
		perfVSTProjectAddExtensibleItemStart = 8011,
		perfVSTProjectAddExtensibleItemEnd = 8012,
		perfVSTProjectRefreshBufferContentStart = 8013,
		perfVSTProjectRefreshBufferContentEnd = 8014,
		perfVSTInteractiveProjectCreateStart = 8015,
		perfVSTInteractiveProjectCreateEnd = 8016,
		perfVSTInteractiveProjectResetAllStart = 8017,
		perfVSTInteractiveProjectResetAllEnd = 8018,
		perfVSTProjectWizard = 8019,
		perfVSTProjectWizardOnFinish = 8020,
		perfVSTProjectWizardOnBeforeCreateProjectStart = 8021,
		perfVSTProjectWizardOnBeforeCreateProjectEnd = 8022,
		perfVSTProjectWizardProjectFinishedGeneratingStart = 8023,
		perfVSTProjectWizardProjectFinishedGeneratingEnd = 8024,
		perfVSTProjectBlueprintInitStart = 8025,
		perfVSTProjectBlueprintInitEnd = 8026,
		perfVSTDesignerCreateLoaderStart = 8028,
		perfVSTDesignerCreateLoaderEnd = 8029,
		perfVSTDesignerDoVerbStart = 8030,
		perfVSTDesignerDoVerbEnd = 8031,
		perfVSTDesignerSetSiteStart = 8032,
		perfVSTDesignerSetSiteEnd = 8033,
		perfVSTDesignerInitDocDesignerStart = 8034,
		perfVSTDesignerInitDocDesignerEnd = 8035,
		perfVSTDesignerOnViewChangedStart = 8036,
		perfVSTDesignerOnViewChangedEnd = 8037,
		perfVSTDesignerCoCreateStart = 8038,
		perfVSTDesignerCoCreateEnd = 8039,
		perfVSTDesignerBeginLoadStart = 8040,
		perfVSTDesignerBeginLoadEnd = 8041,
		perfVSTDSWDropStart = 8042,
		perfVSTDSWDropEnd = 8043,
		perfVSTClientUpdateProjectStart = 8044,
		perfVSTClientUpdateProjectEnd = 8045,
		perfVSTClientHostSideAdaptorStart = 8046,
		perfVSTClientHostSideAdaptorEnd = 8047,
		perfVSTClientOleRunStart = 8048,
		perfVSTClientOleRunEnd = 8049,
		perfVSTClientInstantiateDocumentStart = 8050,
		perfVSTClientInstantiateDocumentEnd = 8051,
		perfVSTClientRefreshProgrammingModelStart = 8052,
		perfVSTClientRefreshProgrammingModelEnd = 8053,
		perfVSTClientShowDocumentStart = 8054,
		perfVSTClientShowDocumentEnd = 8055,
		perfVSTClientBindStart = 8056,
		perfVSTClientBindEnd = 8057,
		perfVSTClientCoCreateHostInstanceStart = 8058,
		perfVSTClientCoCreateHostInstanceEnd = 8059,
		perfAppInfoTaskStart = 8060,
		perfAppInfoTaskEnd = 8061,
		perfCustomizeFirstStart = 8062,
		perfCustomizeFirstEnd = 8063,
		perfCustomizeStartupInfoStart = 8064,
		perfCustomizeStartupInfoEnd = 8065,
		perfCustomizeAppAsmDependStart = 8066,
		perfCustomizeAppAsmDependEnd = 8067,
		perfCustomizeRefAsmDependStart = 8068,
		perfCustomizeRefAsmDependEnd = 8069,
		perfCustomizeEntryPointsStart = 8070,
		perfCustomizeEntryPointsEnd = 8071,
		perfCustomizePersistStart = 8072,
		perfCustomizePersistEnd = 8073,
		perfCustomizeLastStart = 8074,
		perfCustomizeLastEnd = 8075,
		perfPersisterGetObjectStart = 8076,
		perfPersisterGetObjectEnd = 8077,
		perfPersisterWriteStart = 8080,
		perfPersisterWriteEnd = 8081,
		perfPersisterFinishedStart = 8082,
		perfPersisterFinishedEnd = 8083,
		perfOfficePersistenceObjectIsOpenedStart = 8084,
		perfOfficePersistenceObjectIsOpenedEnd = 8085,
		perfOfficePersistenceObjectCoCreateStart = 8086,
		perfOfficePersistenceObjectCoCreateEnd = 8087,
		perfOfficePersistenceObjectDeletePropsStart = 8088,
		perfOfficePersistenceObjectDeletePropsEnd = 8089,
		perfOfficePersistenceObjectOpenDocStart = 8090,
		perfOfficePersistenceObjectOpenDocEnd = 8091,
		perfOfficePersistenceObjectAddCtrlStart = 8092,
		perfOfficePersistenceObjectAddCtrlEnd = 8093,
		perfOfficePersistenceObjectSetProtectionStart = 8094,
		perfOfficePersistenceObjectSetProtectionEnd = 8095,
		perfVSTSecurityTaskStart = 8096,
		perfVSTSecurityTaskEnd = 8097,
		perfCustomizeDataCacheStart = 8098,
		perfCustomizeDataCacheEnd = 8099,
		perfReadCachedDataManifestStart = 8100,
		perfReadCachedDataManifestEnd = 8101,
		perfOpenEventStart = 8104,
		perfOpenEventEnd = 8105,
		perfFindControlStart = 8106,
		perfFindControlEnd = 8107,
		perfCreateEvidenceStart = 8110,
		perfCreateEvidenceEnd = 8111,
		perfStartCLRStart = 8114,
		perfStartCLREnd = 8115,
		perfCreateDomainStart = 8116,
		perfCreateDomainEnd = 8117,
		perfConfigDomainStart = 8120,
		perfConfigDomainEnd = 8121,
		perfExecManifestStart = 8122,
		perfExecManifestEnd = 8123,
		perfExecManifestParseManifestStart = 8126,
		perfExecManifestParseManifestEnd = 8127,
		perfExecManifestUpdateStart = 8128,
		perfExecManifestUpdateEnd = 8129,
		perfExecManifestSetPolicyStart = 8130,
		perfExecManifestSetPolicyEnd = 8131,
		perfExecManifestConfigStart = 8132,
		perfExecManifestConfigEnd = 8133,
		perfExecManifestConfigLoadStartupAsmStart = 8136,
		perfExecManifestConfigLoadStartupAsmEnd = 8137,
		perfExecManifestConfigCreateStartupObjAsmGetTypeStart = 8138,
		perfExecManifestConfigCreateStartupObjAsmGetTypeEnd = 8139,
		perfExecManifestConfigCreateStartupObjInvokeStart = 8142,
		perfExecManifestConfigCreateStartupObjInvokeEnd = 8143,
		perfExecManifestCompleteStartupObjectInitializationStart = 8144,
		perfExecManifestCompleteStartupObjectInitializationEnd = 8145,
		perfCreateForClientNewStart = 8146,
		perfCreateForClientNewEnd = 8147,
		perfCreateForClientStartupStart = 8148,
		perfCreateForClientStartupEnd = 8149,
		perfCreateForClientMyAppStart = 8150,
		perfCreateForClientMyAppEnd = 8151,
		perfCreateForClientInitializeViewComponentsStart = 8152,
		perfCreateForClientInitializeViewComponentsEnd = 8153,
		perfCreateForClientInitializeComponentsStart = 8154,
		perfCreateForClientInitializeComponentsEnd = 8155,
		perfCreateForClientInitializeDataComponentsStart = 8156,
		perfCreateForClientInitializeDataComponentsEnd = 8157,
		perfCreateForClientBindStart = 8158,
		perfCreateForClientBindEnd = 8159,
		perfCreateForClientInitCompleteStart = 8160,
		perfCreateForClientInitCompleteEnd = 8161,
		perfVSTOLoaderLoadStart = 8162,
		perfVSTOLoaderLoadEnd = 8163,
		perfGetDefaultDomainStart = 8168,
		perfGetDefaultDomainEnd = 8169,
		perfGetAppbaseStart = 8170,
		perfGetAppbaseEnd = 8171,
		perfCreateCustomizationDomainInteropStart = 8172,
		perfCreateCustomizationDomainInteropEnd = 8173,
		perfCreateUrisStart = 8174,
		perfCreateUrisEnd = 8175,
		perfGetConfigStringsStart = 8176,
		perfGetConfigStringsEnd = 8177,
		perfReflectOnADMStart = 8178,
		perfReflectOnADMEnd = 8179,
		perfCreateDictionariesStart = 8180,
		perfCreateDictionariesEnd = 8181,
		perfCallbackHostStart = 8182,
		perfCallbackHostEnd = 8183,
		perfCompleteInitializationStart = 8184,
		perfCompleteInitializationEnd = 8185,
		perfVSHelpExternalHelpInitializing = 9000,
		perfVSHelpExternalObjectCreated = 9001,
		perfVSHelpExternalGotInitData = 9002,
		perfVSHelpExternalPutHelpOwner = 9003,
		perfVSHelpExternalGotSettingsManager = 9004,
		perfVSHelpPutSettingsTokenStart = 9005,
		perfVSHelpPutSettingsTokenComplete = 9006,
		perfVSHelpPutSettingsTokenFireSettingsChanged = 9007,
		perfVSHelpSetCollectionBegin = 9008,
		perfVSHelpSetCollectionReInitStart = 9009,
		perfVSHelpSetCollectionReleasedObjects = 9010,
		perfVSHelpSetCollectionFiredSettingsChanged = 9011,
		perfVSHelpSetCollectionFiredCollectionChanged = 9012,
		perfVSHelpExternalHelpInitialized = 9013,
		perfVSHelpExternalCommunicatedHelpToken = 9014,
		perfVSHelpServiceF1Begin = 9015,
		perfVSHelpGotShellContextService = 9016,
		perfVSHelpGotBrowserWindow = 9017,
		perfVSHelpGetBrowserWindowFoundModalState = 9018,
		perfVSHelpGetBrowserWindowGotWBService = 9019,
		perfVSHelpGetBrowserWindowCreatedWB = 9020,
		perfVSCreateWebBrowserExStart = 9021,
		perfVSCreateWebBrowserExNeedCreate = 9022,
		perfVSCreateWebBrowserExDocDataCreated = 9023,
		perfVSCreateWebBrowserExPrepareCreateToolWin = 9024,
		perfVSCreateWebBrowserExCreatedToolWin = 9025,
		perfVSCreateWebBrowserExToolWinInitialized = 9026,
		perfVSCreateWebBrowserExDocDataInitialized = 9027,
		perfVSWebBrowserNavigateComplete2 = 9028,
		perfHxInitFTSKeywordBegin = 9030,
		perfHxInitFTSKeywordCreateFTS = 9031,
		perfHxInitFTSKeywordCreateFTI = 9032,
		perfHxInitFTSKeywordInitFTI = 9033,
		perfHxInitFTSInitTitleArray = 9034,
		perfHxInitFTSInitTitleArrayInitTitlesBegin = 9035,
		perfHxInitFTSInitTitleArrayInitTitlesEnd = 9036,
		perfHxInitFTSInitTitleArrayInitFreeHxSEnd = 9037,
		perfHxInitFTSInitTitleArrayInitHxQEnd = 9038,
		perfHxInitFTSInitTitleArrayInitHxQ = 9039,
		perfHxInitFTSInitTitleArrayComputeTopicCount = 9040,
		perfHxInitFTSInitTitleArrayOutputMapInfo = 9041,
		perfHxIndexQueryBegin = 9042,
		perfHxIndexInitializeMergedFileBegin = 9043,
		perfHxIndexQueryGotOffset = 9044,
		perfHxIndexQueryFoundMatchingKeyword = 9045,
		perfHxIndexQueryAddedTopicsForKeyword = 9046,
		perfHxIndexQueryFoundAllTopics = 9047,
		perfHxIndexQueryAddedAllTopics = 9048,
		perfVSHelpIndexPutFilter = 9050,
		perfVSHelpIndexInitBegin = 9051,
		perfVSHelpIndexMerged = 9052,
		perfVSHelpIndexGotXLinkInfo = 9053,
		perfVSHelpIndexInitWithXLinkInfo = 9054,
		perfVSHelpMergeIndexBegin = 9055,
		perfVSHelpMergeIndexDoneCount = 9056,
		perfVSHelpMergeIndexParsedHxK = 9057,
		perfVSHelpMergeIndexGotLock = 9058,
		perfVSHelpMergeIndexInitializedValidator = 9059,
		perfVSHelpMergeIndexRoundZero = 9060,
		perfVSHelpMergeIndexRoundOne = 9061,
		perfVSHelpMergeIndexRoundTwo = 9062,
		perfVSHelpMergeIndexDoneRounds = 9063,
		perfVSHelpMergeIndexPersistedHxD = 9064,
		perfVSHelpMergeIndexComplete = 9065,
		perfVSHelpInitValidatorBegin = 9066,
		perfVSHelpInitValidatorGotAccess = 9067,
		perfVSHelpInitValidatorWithFileBegin = 9068,
		perfVSHelpInitValidatorOpenedFS = 9069,
		perfVSHelpInitValidatorCheckedSig = 9070,
		perfVSHelpInitValidatorOpenedContentTVD = 9071,
		perfVSHelpInitValidatorOpenedContentFN = 9072,
		perfVSHelpInitValidatorOpenedMergedTVD = 9073,
		perfVSHelpInitValidatorOpenedMergedFN = 9074,
		perfVSHelpInitValidatorLoadedMergedFileData = 9075,
		perfVSHelpInitValidatorContentsChanged = 9076,
		perfVSHelpInitValidatorCheckedMergedFileValidity = 9077,
		perfVSHelpUserSettingsLoadManagedStart = 9090,
		perfVSHelpUserSettingsLoadManagedComplete = 9091,
		perfVSWebPackageLoaded = 9092,
		perfVSContextServiceStart = 9093,
		perfVSContextServiceCreated = 9094,
		perfVSContextServiceLoaded = 9095,
		perfVSDexploreRun = 9096,
		perfVSDexploreInitializedPaths = 9097,
		perfVSDexploreCreatedAppid = 9098,
		perfVSDexploreDisplayedSplashScreen = 9099,
		perfVSDexploreStartSetSite = 9100,
		perfVSDexploreEnsuredAppName = 9101,
		perfVSDexploreInitializedUserContext = 9102,
		perfVSDexploreInitAppNameStart = 9103,
		perfVSDexploreInitAppNameGotBaseName = 9104,
		perfVSDexploreGotHxSession = 9105,
		perfVSDexploreGotHxCollection = 9106,
		perfVSDexploreGotCollectionTitle = 9107,
		perfVSHelpIndexOnSettingsRootChanged = 9108,
		perfVSHelpIndexOSRCInitializedUI = 9109,
		perfVSHelpTocOnSettingsRootChanged = 9110,
		perfVSHelpTocOSRCInitializedUI = 9111,
		perfVSHelpXLinkIndexSetFilterBegin = 9112,
		perfVSHelpXLinkIndexInitialized = 9113,
		perfVSHelpXLinkIndexFilterSet = 9114,
		perfVSHelpXLinkIndexInitializeMergedFile = 9115,
		perfVSHelpXLinkIndexInitializeMergedFileOpenedFS = 9116,
		perfVSHelpXLinkIndexInitializeMergedFileInitializedLeaves = 9117,
		perfVSHelpXLinkIndexInitializeMergedFileCachedBranches = 9118,
		perfVSHelpXLinkIndexInitializeMergedFileCachedPageSlots = 9119,
		perfVSHelpF1FoundTargetItems = 9120,
		perfVSHelpF1InitializedDisambiguationData = 9121,
		perfVSHelpKeywordLookupBegin = 9122,
		perfVSHelpKeywordLookupGotCWHService = 9123,
		perfVSHelpKeywordLookupSetIndex = 9124,
		perfVSHelpKeywordLookupGotTopics = 9125,
		perfVSHelpKeywordLookupInitializedAttrFilter = 9126,
		perfVSHelpKeywordLookupLoadedTopicsForKeyword = 9127,
		perfVSHelpKeywordLookupStartXmlTopics = 9128,
		perfVSHelpGetTopicsFromKeywordStart = 9128,
		perfVSHelpGetTopicsFromKeywordSetIndex = 9129,
		perfVSHelpGetTopicsFromKeywordGotTopics = 9130,
		perfVSHelpGetTopicsFromKeywordGotVsTopicList = 9131,
		perfVSHelpKeywordLookupFoundXmlTopics = 9132,
		perfVSHelpExternalSetCollection = 9133,
		perfVSContextWindowInitCreateContents = 9135,
		perfVSContextWindowInitGetMonitorService = 9136,
		perfVSContextWindowInitGetAppContext = 9137,
		perfVSContextWindowInitReadRegistry = 9138,
		perfVSContextWindowInitGetShellContextService = 9139,
		perfVSContextWindowInitCmdUIContexts = 9140,
		perfVSContextWindowInitSelection = 9141,
		perfVSDexploreSetMDIOption = 9142,
		perfVSDexploreInitCheckLoadPackage = 9143,
		perfVSHelpInitTocLoadedFilters = 9144,
		perfVSHelpInitTocCreatedControl = 9145,
		perfVSHelpInitTocInitControlProperties = 9146,
		perfVSHelpInitTocStart = 9147,
		perfVSHelpF1LookupEnsureContextInit = 9148,
		perfVSHelpF1LookupGotHelp = 9149,
		perfVSHelpF1LookupGotHelp2 = 9150,
		perfVSHelpF1LookupGotFirstTimeDlg = 9151,
		perfVSHelpF1LookupGotContextMonitor = 9152,
		perfVSHelpF1LookupGotAppCtx = 9153,
		perfVSHelpF1LookupUpdatedAppCtx = 9154,
		perfVSHelpF1LookupGotContextAsSafeArray = 9155,
		perfVSContextWindowCreated = 9156,
		perfVSLoadContextFilesInitStrings = 9157,
		perfVSLoadContextFilesFoundFile = 9158,
		perfVSLoadContextFilesParsedFile = 9159,
		perfVSDexploreWinMain = 9160,
		perfVSHelpILocalRegistry = 9161,
		perfVSDexploreInitParams = 9162,
		perfVSDexploreInitGuids = 9163,
		perfVSDexploreInitOle = 9164,
		perfVSHelpFilterToolInitGotHelpService = 9165,
		perfVSHelpFilterToolInitGotFilters = 9166,
		perfVSHelpFilterToolInitAddedFilters = 9167,
		perfVSHelpFilterToolInitPutFilter = 9168,
		perfVSHelpFilterToolInitFillComplete = 9169,
		perfVSHelpFilterToolInitFillBegin = 9170,
		perfVSHelpHrDoLocalF1LookupBegin = 9171,
		perfVSHelpHrDoLocalF1LookupContextInit = 9172,
		perfVSHelpHrDoLocalF1LookupGetContextMonitor = 9173,
		perfVSHelpHrDoLocalF1LookupUnpackContext = 9174,
		perfVSHelpHrDoLocalF1LookupGetAppCtx = 9175,
		perfVSHelpItemLoadKeywordGotTopicAt = 9176,
		perfVSHelpItemLoadKeywordFilteredTopic = 9177,
		perfVSHelpGetHelpSettings = 9178,
		perfVSHelpSettingsInitialized = 9179,
		perfVSHelpGetF1Preference = 9180,
		perfVSHelpF1PreferenceFound = 9181,
		perfVSHelpHrDoLocalF1Begin = 9182,
		perfVSHelpHrDoOnlineF1Begin = 9183,
		perfVSHelpHrDoLocalF1Failover = 9184,
		perfVSHelpOnlineF1Callback = 9185,
		perfVSHelpGetAllAttrValuesBegin = 9186,
		perfVSHelpGetAllAttrValuesComplete = 9187,
		perfVSHelpGetAllAttrValuesGotCollection = 9188,
		perfVSHelpGetAllAttrValuesGotAttrNames = 9189,
		perfVSHelpGetAllAttrValuesGotAttrValues = 9190,
		perfVSHelpF1LookupLoadKeywordBegin = 9191,
		perfVSHelpF1LookupGetNameBegin = 9192,
		perfVSHelpF1LookupGetNameComplete = 9193,
		perfVSHelpF1LookupGetUrlBegin = 9194,
		perfVSHelpF1LookupGetUrlComplete = 9195,
		perfVSHelpF1PrepareHeaders = 9196,
		perfVSHelpF1NavigateWithDisambiguation = 9197,
		perfVSHelpF1FoundTopicURL = 9198,
		perfVSInitFMain = 9220,
		perfVSInitializedAppIdGlobals = 9221,
		perfVSInitializedBase = 9222,
		perfVSInitializedGlobal = 9223,
		perfVSCheckedTimeBomb = 9224,
		perfVSSitedAppid = 9225,
		perfVSCheckedLicensing = 9226,
		perfVSCheckedActivation = 9227,
		perfVSInitUIThread = 9228,
		perfVSInitUIInitializedThemes = 9229,
		perfVSInitUIInitializedBrushes = 9230,
		perfVSInitUIInitializedBubble = 9231,
		perfVSInitUIInitializedMainMenuWin = 9232,
		perfVSInitUIInitializedDisasterRecovery = 9233,
		perfVSInitUIModeInitComplete = 9234,
		perfVSInitUIPreloadedPackages = 9235,
		perfVSInitUIRegisteredCF = 9236,
		perfVSInitUIInitializedAppId = 9237,
		perfVSInitUILoadedInitialProject = 9238,
		perfVSInitUIOnIDEInitialized = 9239,
		perfVSInitUICheckedBadAddins = 9240,
		perfVSInitUIThreadComplete = 9241,
		perfVSPbrsUpdateFixer = 9242,
		perfVSMainLoggedPushingMsgLoop = 9243,
		perfVSCallVsMainFoundMsenv = 9244,
		perfVSCallVsMainLoadedMsenv = 9245,
		perfVSCallVsMainFoundVStudioMainProc = 9246,
		perfVSInitMainMenuWindowInitCommonControls = 9247,
		perfVSInitMainMenuWindowCreatedHwnd = 9248,
		perfVSInitMainMenuWindowInitOffice = 9249,
		perfVSInitMainMenuWindowPrefInitPart2 = 9250,
		perfVSInitMainMenuWindowCreateVSShellMenu = 9251,
		perfVSInitMainMenuWindowInitializeCmdbars = 9252,
		perfVSInitMainMenuWindowSetupCmdUIcontexts = 9253,
		perfVSInitMainMenuWindowInitDebugMgr = 9254,
		perfVSInitMainMenuWindowResetContextGuids = 9255,
		perfVSInitMainMenuWindowInitHierWindow = 9256,
		perfVSInitMainMenuWindowExtIDEInit = 9257,
		perfVSInitMainMenuWindowAliases = 9258,
		perfVSPreloadPackagesLoadedPackage = 9259,
		perfVSInitMainMenuWindowInitializeMSODialogs = 9260,
		perfVSLocalRegistryCreateInstanceBegin = 9261,
		perfVSLocalRegistryVsLoaderCoCreateInstance = 9262,
		perfVSLocalRegistryGetClassObjectOfClsid = 9263,
		perfVSLocalRegistryCFCreateInstance = 9264,
		perfVSInitGlobalLoadLangDLLMain = 9274,
		perfVSInitGlobalInitOle = 9275,
		perfVSInitGlobalInitRegValues = 9276,
		perfVSInitGlobalCheckDllVersions = 9277,
		perfVSInitGlobalInitShellFromRegistry = 9278,
		perfVSInitGlobalInitDirectories = 9280,
		perfVSInitGlobalInitShellFromRegistry2 = 9281,
		perfVSInitGlobalCreateIdeFonts = 9282,
		perfVSInitGlobalCreateTheSolution = 9283,
		perfVSInitGlobalEnsureDDEAtoms = 9284,
		perfVSInitGlobalSVsAppid = 9285,
		perfVSInitGlobalRegisterJITDebugger = 9286,
		perfVSInitGlobalInitMRUs = 9287,
		perfVSInitGlobalMergeExternalTools = 9288,
		perfVSInitGlobalVsUIProjWinHierarchyInitClass = 9289,
		perfVSInitGlobalRestoreFileAssociations = 9290,
		perfVSMainMenuWindowShown = 9291,
		perfVSInitMainMenuWindowExtIDEWins = 9292,
		perfVSInitMainMenuWindowShowDockableWins = 9293,
		perfVSInitMainMenuWindowFixedPaneWins = 9294,
		perfVSInitMainMenuWindowResizedAllDocks = 9295,
		perfVSInitMainMenuWindowComplete = 9296,
		perfVSSettingsStartupCheckBegin = 9300,
		perfVSSettingsStartupCheckComplete = 9301,
		perfVSSettingsImportStart = 9302,
		perfVSSettingsImportComplete = 9303,
		perfVSSettingsExportStart = 9304,
		perfVSSettingsExportComplete = 9305,
		perfVSSettingsLoadBegin = 9306,
		perfVSSettingsLoadComplete = 9307,
		perfVSSettingsSaveBegin = 9308,
		perfVSSettingsSaveComplete = 9309,
		perfVSInitDelayLoadOfUIDLLsBegin = 9350,
		perfVSInitDelayLoadOfUIDLLsEndIteration = 9351,
		perfVSInitDelayLoadOfUIDLLsEnd = 9352,
		perfHxProtocolInitBegin = 9400,
		perfHxProtocolInitComplete = 9401,
		perfHxProtocolInternalStartBegin = 9402,
		perfHxProtocolInternalStartGotPhysicalUrl = 9403,
		perfHxProtocolInternalStartItsProtocolInitialized = 9404,
		perfHxProtocolInternalItsStartComplete = 9405,
		perfHxProtocolInternalIECacheCleared = 9406,
		perfHxIndexTopicId2TopicArrayBegin = 9407,
		perfHxTitleInformationInitializeBegin = 9408,
		perfHxTitleInformationInitializeOpenedTxt = 9409,
		perfHxTitleInformationInitializeVersionCorrect = 9410,
		perfHxTitleInformationInitializeComplete = 9411,
		perfHxTitleGetTopicURLBegin = 9412,
		perfHxTitleGotTopicData = 9413,
		perfHxTitleGotUrlOffset = 9414,
		perfHxInitTitleBegin = 9415,
		perfHxInitTitleOpenedSubFiles = 9416,
		perfHxInitTitleComplete = 9417,
		perfVSWebPkgCreated = 9430,
		perfVSWebPkgSetSiteBegin = 9431,
		perfVSWebPkgSetModuleSite = 9432,
		perfVSWebPkgSetSiteUILibraryLoaded = 9433,
		perfVSWebPkgSetSitePrefsLoaded = 9434,
		perfVSWebPkgSetSiteServicesProffered1 = 9435,
		perfVSWebPkgSetSiteContextTrackerCreated = 9436,
		perfVSWebPkgSetSiteServicesProffered2 = 9437
	}
}
