
// C:\WINDOWS\assembly\GAC_MSIL\System.Runtime.Remoting\2.0.0.0__b77a5c561934e089\System.Runtime.Remoting.dll
// System.Runtime.Remoting, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 00000000000000000400000000000000

using System;
using System.CodeDom.Compiler;
using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.DirectoryServices;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Cache;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;
using System.Runtime.Remoting.Channels.Tcp;
using System.Runtime.Remoting.Configuration;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Remoting.Metadata;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Runtime.Remoting.MetadataServices;
using System.Runtime.Remoting.Services;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.SessionState;
using System.Web.UI;
using System.Xml;
using Microsoft.CSharp;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: CompilationRelaxations(8)]
[assembly: TypeLibVersion(2, 0)]
[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\EcmaPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDefaultAlias("System.Runtime.Remoting.dll")]
[assembly: AssemblyDescription("System.Runtime.Remoting.dll")]
[assembly: AssemblyTitle("System.Runtime.Remoting.dll")]
[assembly: CLSCompliant(false)]
[assembly: ComVisible(false)]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
internal static class FXAssembly
{
	internal const string Version = "2.0.0.0";
}
internal static class ThisAssembly
{
	internal const string Title = "System.Runtime.Remoting.dll";

	internal const string Description = "System.Runtime.Remoting.dll";

	internal const string DefaultAlias = "System.Runtime.Remoting.dll";

	internal const string Copyright = "© Microsoft Corporation.  All rights reserved.";

	internal const string Version = "2.0.0.0";

	internal const string InformationalVersion = "2.0.50727.9149";

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
namespace System.Runtime.Remoting.Channels
{
	[Serializable]
	internal class BaseTransportHeaders : ITransportHeaders
	{
		internal const int WellknownHeaderCount = 4;

		private object _connectionId;

		private object _ipAddress;

		private string _requestUri;

		private string _contentType;

		private ITransportHeaders _otherHeaders;

		public string RequestUri
		{
			get
			{
				return _requestUri;
			}
			set
			{
				_requestUri = value;
			}
		}

		public string ContentType
		{
			get
			{
				return _contentType;
			}
			set
			{
				_contentType = value;
			}
		}

		public object ConnectionId
		{
			set
			{
				_connectionId = value;
			}
		}

		public IPAddress IPAddress
		{
			set
			{
				_ipAddress = value;
			}
		}

		public object this[object key]
		{
			get
			{
				if (key is string headerName)
				{
					int num = MapHeaderNameToIndex(headerName);
					if (num != -1)
					{
						return GetValueFromHeaderIndex(num);
					}
				}
				if (_otherHeaders != null)
				{
					return _otherHeaders[key];
				}
				return null;
			}
			set
			{
				bool flag = false;
				if (key is string headerName)
				{
					int num = MapHeaderNameToIndex(headerName);
					if (num != -1)
					{
						SetValueFromHeaderIndex(num, value);
						flag = true;
					}
				}
				if (!flag)
				{
					if (_otherHeaders == null)
					{
						_otherHeaders = new TransportHeaders();
					}
					_otherHeaders[key] = value;
				}
			}
		}

		public BaseTransportHeaders()
		{
			_otherHeaders = null;
		}

		public IEnumerator GetEnumerator()
		{
			return new BaseTransportHeadersEnumerator(this);
		}

		internal IEnumerator GetOtherHeadersEnumerator()
		{
			if (_otherHeaders == null)
			{
				return null;
			}
			return _otherHeaders.GetEnumerator();
		}

		internal int MapHeaderNameToIndex(string headerName)
		{
			if (string.Compare(headerName, "__ConnectionId", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return 0;
			}
			if (string.Compare(headerName, "__IPAddress", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return 1;
			}
			if (string.Compare(headerName, "__RequestUri", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return 2;
			}
			if (string.Compare(headerName, "Content-Type", StringComparison.OrdinalIgnoreCase) == 0)
			{
				return 3;
			}
			return -1;
		}

		internal string MapHeaderIndexToName(int index)
		{
			return index switch
			{
				0 => "__ConnectionId", 
				1 => "__IPAddress", 
				2 => "__RequestUri", 
				3 => "Content-Type", 
				_ => null, 
			};
		}

		internal object GetValueFromHeaderIndex(int index)
		{
			return index switch
			{
				0 => _connectionId, 
				1 => _ipAddress, 
				2 => _requestUri, 
				3 => _contentType, 
				_ => null, 
			};
		}

		internal void SetValueFromHeaderIndex(int index, object value)
		{
			switch (index)
			{
			case 0:
				_connectionId = value;
				break;
			case 1:
				_ipAddress = value;
				break;
			case 2:
				_requestUri = (string)value;
				break;
			case 3:
				_contentType = (string)value;
				break;
			}
		}
	}
	internal class BaseTransportHeadersEnumerator : IEnumerator
	{
		private BaseTransportHeaders _headers;

		private bool _bStarted;

		private int _currentIndex;

		private IEnumerator _otherHeadersEnumerator;

		public object Current
		{
			get
			{
				if (!_bStarted)
				{
					return null;
				}
				if (_currentIndex != -1)
				{
					return new DictionaryEntry(_headers.MapHeaderIndexToName(_currentIndex), _headers.GetValueFromHeaderIndex(_currentIndex));
				}
				if (_otherHeadersEnumerator != null)
				{
					return _otherHeadersEnumerator.Current;
				}
				return null;
			}
		}

		public BaseTransportHeadersEnumerator(BaseTransportHeaders headers)
		{
			_headers = headers;
			Reset();
		}

		public bool MoveNext()
		{
			if (_currentIndex != -1)
			{
				if (_bStarted)
				{
					_currentIndex++;
				}
				else
				{
					_bStarted = true;
				}
				while (_currentIndex != -1)
				{
					if (_currentIndex >= 4)
					{
						_otherHeadersEnumerator = _headers.GetOtherHeadersEnumerator();
						_currentIndex = -1;
						continue;
					}
					if (_headers.GetValueFromHeaderIndex(_currentIndex) != null)
					{
						return true;
					}
					_currentIndex++;
				}
			}
			if (_otherHeadersEnumerator != null)
			{
				if (!_otherHeadersEnumerator.MoveNext())
				{
					_otherHeadersEnumerator = null;
					return false;
				}
				return true;
			}
			return false;
		}

		public void Reset()
		{
			_bStarted = false;
			_currentIndex = 0;
			_otherHeadersEnumerator = null;
		}
	}
	internal class BasicAsyncResult : IAsyncResult
	{
		private AsyncCallback _asyncCallback;

		private object _asyncState;

		private object _returnValue;

		private Exception _exception;

		private bool _bIsComplete;

		private ManualResetEvent _manualResetEvent;

		public object AsyncState => _asyncState;

		public WaitHandle AsyncWaitHandle
		{
			get
			{
				bool bIsComplete = _bIsComplete;
				if (_manualResetEvent == null)
				{
					lock (this)
					{
						if (_manualResetEvent == null)
						{
							_manualResetEvent = new ManualResetEvent(bIsComplete);
						}
					}
				}
				if (!bIsComplete && _bIsComplete)
				{
					_manualResetEvent.Set();
				}
				return _manualResetEvent;
			}
		}

		public bool CompletedSynchronously => false;

		public bool IsCompleted => _bIsComplete;

		internal Exception Exception => _exception;

		internal BasicAsyncResult(AsyncCallback callback, object state)
		{
			_asyncCallback = callback;
			_asyncState = state;
		}

		internal void SetComplete(object returnValue, Exception exception)
		{
			_returnValue = returnValue;
			_exception = exception;
			CleanupOnComplete();
			_bIsComplete = true;
			try
			{
				if (_manualResetEvent != null)
				{
					_manualResetEvent.Set();
				}
			}
			catch (Exception exception2)
			{
				if (_exception == null)
				{
					_exception = exception2;
				}
			}
			catch
			{
				if (_exception == null)
				{
					_exception = new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException"));
				}
			}
			if (_asyncCallback != null)
			{
				_asyncCallback(this);
			}
		}

		internal virtual void CleanupOnComplete()
		{
		}
	}
}
namespace System.IO
{
	internal interface IByteBufferPool
	{
		byte[] GetBuffer();

		void ReturnBuffer(byte[] buffer);
	}
	internal class ByteBufferAllocator : IByteBufferPool
	{
		private int _bufferSize;

		public ByteBufferAllocator(int bufferSize)
		{
			_bufferSize = bufferSize;
		}

		public byte[] GetBuffer()
		{
			return new byte[_bufferSize];
		}

		public void ReturnBuffer(byte[] buffer)
		{
		}
	}
	internal class ByteBufferPool : IByteBufferPool
	{
		private byte[][] _bufferPool;

		private int _current;

		private int _last;

		private int _max;

		private int _bufferSize;

		private object _controlCookie = "cookie object";

		public ByteBufferPool(int maxBuffers, int bufferSize)
		{
			_max = maxBuffers;
			_bufferPool = new byte[_max][];
			_bufferSize = bufferSize;
			_current = -1;
			_last = -1;
		}

		public byte[] GetBuffer()
		{
			object obj = null;
			try
			{
				obj = Interlocked.Exchange(ref _controlCookie, null);
				if (obj != null)
				{
					if (_current == -1)
					{
						_controlCookie = obj;
						return new byte[_bufferSize];
					}
					byte[] result = _bufferPool[_current];
					_bufferPool[_current] = null;
					if (_current == _last)
					{
						_current = -1;
					}
					else
					{
						_current = (_current + 1) % _max;
					}
					_controlCookie = obj;
					return result;
				}
				return new byte[_bufferSize];
			}
			catch (ThreadAbortException)
			{
				if (obj != null)
				{
					_current = -1;
					_last = -1;
					_controlCookie = obj;
				}
				throw;
			}
		}

		public void ReturnBuffer(byte[] buffer)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer");
			}
			object obj = null;
			try
			{
				obj = Interlocked.Exchange(ref _controlCookie, null);
				if (obj == null)
				{
					return;
				}
				if (_current == -1)
				{
					_bufferPool[0] = buffer;
					_current = 0;
					_last = 0;
				}
				else
				{
					int num = (_last + 1) % _max;
					if (num != _current)
					{
						_last = num;
						_bufferPool[_last] = buffer;
					}
				}
				_controlCookie = obj;
			}
			catch (ThreadAbortException)
			{
				if (obj != null)
				{
					_current = -1;
					_last = -1;
					_controlCookie = obj;
				}
				throw;
			}
		}
	}
}
namespace System.Runtime.Remoting.Channels
{
	internal class ChunkedMemoryStream : Stream
	{
		private class MemoryChunk
		{
			public byte[] Buffer;

			public MemoryChunk Next;
		}

		private static IByteBufferPool s_defaultBufferPool = new ByteBufferAllocator(1024);

		private MemoryChunk _chunks;

		private IByteBufferPool _bufferPool;

		private bool _bClosed;

		private MemoryChunk _writeChunk;

		private int _writeOffset;

		private MemoryChunk _readChunk;

		private int _readOffset;

		public override bool CanRead => true;

		public override bool CanSeek => true;

		public override bool CanWrite => true;

		public override long Length
		{
			get
			{
				if (_bClosed)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
				}
				int num = 0;
				MemoryChunk memoryChunk = _chunks;
				while (memoryChunk != null)
				{
					MemoryChunk next = memoryChunk.Next;
					num = ((next == null) ? (num + _writeOffset) : (num + memoryChunk.Buffer.Length));
					memoryChunk = next;
				}
				return num;
			}
		}

		public override long Position
		{
			get
			{
				if (_bClosed)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
				}
				if (_readChunk == null)
				{
					return 0L;
				}
				int num = 0;
				for (MemoryChunk memoryChunk = _chunks; memoryChunk != _readChunk; memoryChunk = memoryChunk.Next)
				{
					num += memoryChunk.Buffer.Length;
				}
				num += _readOffset;
				return num;
			}
			set
			{
				if (_bClosed)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
				}
				if (value < 0)
				{
					throw new ArgumentOutOfRangeException("value");
				}
				MemoryChunk readChunk = _readChunk;
				int readOffset = _readOffset;
				_readChunk = null;
				_readOffset = 0;
				int num = (int)value;
				for (MemoryChunk memoryChunk = _chunks; memoryChunk != null; memoryChunk = memoryChunk.Next)
				{
					if (num < memoryChunk.Buffer.Length || (num == memoryChunk.Buffer.Length && memoryChunk.Next == null))
					{
						_readChunk = memoryChunk;
						_readOffset = num;
						break;
					}
					num -= memoryChunk.Buffer.Length;
				}
				if (_readChunk == null)
				{
					_readChunk = readChunk;
					_readOffset = readOffset;
					throw new ArgumentOutOfRangeException("value");
				}
			}
		}

		public ChunkedMemoryStream(IByteBufferPool bufferPool)
		{
			_bufferPool = bufferPool;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			if (_bClosed)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
			}
			switch (origin)
			{
			case SeekOrigin.Begin:
				Position = offset;
				break;
			case SeekOrigin.Current:
				Position += offset;
				break;
			case SeekOrigin.End:
				Position = Length + offset;
				break;
			}
			return Position;
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				_bClosed = true;
				if (disposing)
				{
					ReleaseMemoryChunks(_chunks);
				}
				_chunks = null;
				_writeChunk = null;
				_readChunk = null;
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override void Flush()
		{
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			if (_bClosed)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
			}
			if (_readChunk == null)
			{
				if (_chunks == null)
				{
					return 0;
				}
				_readChunk = _chunks;
				_readOffset = 0;
			}
			byte[] buffer2 = _readChunk.Buffer;
			int num = buffer2.Length;
			if (_readChunk.Next == null)
			{
				num = _writeOffset;
			}
			int num2 = 0;
			while (count > 0)
			{
				if (_readOffset == num)
				{
					if (_readChunk.Next == null)
					{
						break;
					}
					_readChunk = _readChunk.Next;
					_readOffset = 0;
					buffer2 = _readChunk.Buffer;
					num = buffer2.Length;
					if (_readChunk.Next == null)
					{
						num = _writeOffset;
					}
				}
				int num3 = Math.Min(count, num - _readOffset);
				Buffer.BlockCopy(buffer2, _readOffset, buffer, offset, num3);
				offset += num3;
				count -= num3;
				_readOffset += num3;
				num2 += num3;
			}
			return num2;
		}

		public override int ReadByte()
		{
			if (_bClosed)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
			}
			if (_readChunk == null)
			{
				if (_chunks == null)
				{
					return 0;
				}
				_readChunk = _chunks;
				_readOffset = 0;
			}
			byte[] buffer = _readChunk.Buffer;
			int num = buffer.Length;
			if (_readChunk.Next == null)
			{
				num = _writeOffset;
			}
			if (_readOffset == num)
			{
				if (_readChunk.Next == null)
				{
					return -1;
				}
				_readChunk = _readChunk.Next;
				_readOffset = 0;
				buffer = _readChunk.Buffer;
				num = buffer.Length;
				if (_readChunk.Next == null)
				{
					num = _writeOffset;
				}
			}
			return buffer[_readOffset++];
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			if (_bClosed)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
			}
			if (_chunks == null)
			{
				_chunks = AllocateMemoryChunk();
				_writeChunk = _chunks;
				_writeOffset = 0;
			}
			byte[] buffer2 = _writeChunk.Buffer;
			int num = buffer2.Length;
			while (count > 0)
			{
				if (_writeOffset == num)
				{
					_writeChunk.Next = AllocateMemoryChunk();
					_writeChunk = _writeChunk.Next;
					_writeOffset = 0;
					buffer2 = _writeChunk.Buffer;
					num = buffer2.Length;
				}
				int num2 = Math.Min(count, num - _writeOffset);
				Buffer.BlockCopy(buffer, offset, buffer2, _writeOffset, num2);
				offset += num2;
				count -= num2;
				_writeOffset += num2;
			}
		}

		public override void WriteByte(byte value)
		{
			if (_bClosed)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
			}
			if (_chunks == null)
			{
				_chunks = AllocateMemoryChunk();
				_writeChunk = _chunks;
				_writeOffset = 0;
			}
			byte[] buffer = _writeChunk.Buffer;
			int num = buffer.Length;
			if (_writeOffset == num)
			{
				_writeChunk.Next = AllocateMemoryChunk();
				_writeChunk = _writeChunk.Next;
				_writeOffset = 0;
				buffer = _writeChunk.Buffer;
				num = buffer.Length;
			}
			buffer[_writeOffset++] = value;
		}

		public virtual byte[] ToArray()
		{
			int count = (int)Length;
			byte[] array = new byte[Length];
			MemoryChunk readChunk = _readChunk;
			int readOffset = _readOffset;
			_readChunk = _chunks;
			_readOffset = 0;
			Read(array, 0, count);
			_readChunk = readChunk;
			_readOffset = readOffset;
			return array;
		}

		public virtual void WriteTo(Stream stream)
		{
			if (_bClosed)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_StreamIsClosed"));
			}
			if (stream == null)
			{
				throw new ArgumentNullException("stream");
			}
			if (_readChunk == null)
			{
				if (_chunks == null)
				{
					return;
				}
				_readChunk = _chunks;
				_readOffset = 0;
			}
			byte[] buffer = _readChunk.Buffer;
			int num = buffer.Length;
			if (_readChunk.Next == null)
			{
				num = _writeOffset;
			}
			while (true)
			{
				if (_readOffset == num)
				{
					if (_readChunk.Next == null)
					{
						break;
					}
					_readChunk = _readChunk.Next;
					_readOffset = 0;
					buffer = _readChunk.Buffer;
					num = buffer.Length;
					if (_readChunk.Next == null)
					{
						num = _writeOffset;
					}
				}
				int count = num - _readOffset;
				stream.Write(buffer, _readOffset, count);
				_readOffset = num;
			}
		}

		private MemoryChunk AllocateMemoryChunk()
		{
			MemoryChunk memoryChunk = new MemoryChunk();
			memoryChunk.Buffer = _bufferPool.GetBuffer();
			memoryChunk.Next = null;
			return memoryChunk;
		}

		private void ReleaseMemoryChunks(MemoryChunk chunk)
		{
			if (!(_bufferPool is ByteBufferAllocator))
			{
				while (chunk != null)
				{
					_bufferPool.ReturnBuffer(chunk.Buffer);
					chunk = chunk.Next;
				}
			}
		}
	}
	public class CommonTransportKeys
	{
		public const string IPAddress = "__IPAddress";

		public const string ConnectionId = "__ConnectionId";

		public const string RequestUri = "__RequestUri";
	}
	internal enum SinkChannelProtocol
	{
		Http,
		Other
	}
	internal static class CoreChannel
	{
		private class UriHeaderHandler
		{
			private string _uri;

			internal UriHeaderHandler(string uri)
			{
				_uri = uri;
			}

			public object HeaderHandler(Header[] Headers)
			{
				return _uri;
			}
		}

		internal const int MaxStringLen = 512;

		internal const string SOAPMimeType = "text/xml";

		internal const string BinaryMimeType = "application/octet-stream";

		internal const string SOAPContentType = "text/xml; charset=\"utf-8\"";

		internal const int CLIENT_MSG_GEN = 1;

		internal const int CLIENT_MSG_SINK_CHAIN = 2;

		internal const int CLIENT_MSG_SER = 3;

		internal const int CLIENT_MSG_SEND = 4;

		internal const int SERVER_MSG_RECEIVE = 5;

		internal const int SERVER_MSG_DESER = 6;

		internal const int SERVER_MSG_SINK_CHAIN = 7;

		internal const int SERVER_MSG_STACK_BUILD = 8;

		internal const int SERVER_DISPATCH = 9;

		internal const int SERVER_RET_STACK_BUILD = 10;

		internal const int SERVER_RET_SINK_CHAIN = 11;

		internal const int SERVER_RET_SER = 12;

		internal const int SERVER_RET_SEND = 13;

		internal const int SERVER_RET_END = 14;

		internal const int CLIENT_RET_RECEIVE = 15;

		internal const int CLIENT_RET_DESER = 16;

		internal const int CLIENT_RET_SINK_CHAIN = 17;

		internal const int CLIENT_RET_PROPAGATION = 18;

		internal const int CLIENT_END_CALL = 19;

		internal const int TIMING_DATA_EOF = 99;

		private static IByteBufferPool _bufferPool = new ByteBufferPool(10, 4096);

		private static RequestQueue _requestQueue = new RequestQueue(8, 4, 250);

		private static string s_hostName = null;

		private static string s_MachineName = null;

		private static string s_MachineIp = null;

		private static IPAddress s_MachineIpAddress = null;

		private static bool s_isClientSKUInstallationInitialized = false;

		private static bool s_isClientSKUInstallation = false;

		internal static ResourceManager SystemResMgr;

		internal static IByteBufferPool BufferPool => _bufferPool;

		internal static RequestQueue RequestQueue => _requestQueue;

		internal static bool IsClientSKUInstallation
		{
			get
			{
				if (!s_isClientSKUInstallationInitialized)
				{
					bool flag = false;
					string text = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727";
					new RegistryPermission(RegistryPermissionAccess.Read, "HKEY_LOCAL_MACHINE\\" + text).Assert();
					try
					{
						RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(text);
						if (registryKey != null)
						{
							object value = registryKey.GetValue("Install");
							if (value is int)
							{
								flag = (int)value == 1;
							}
						}
					}
					finally
					{
						CodeAccessPermission.RevertAssert();
					}
					bool flag2 = false;
					if (!flag)
					{
						string text2 = "SOFTWARE\\Microsoft\\NET Framework Setup\\DotNetClient\\v3.5";
						new RegistryPermission(RegistryPermissionAccess.Read, "HKEY_LOCAL_MACHINE\\" + text2).Assert();
						try
						{
							RegistryKey registryKey2 = Registry.LocalMachine.OpenSubKey(text2);
							if (registryKey2 != null)
							{
								object value2 = registryKey2.GetValue("Install");
								if (value2 is int)
								{
									flag2 = (int)value2 == 1;
								}
							}
						}
						finally
						{
							CodeAccessPermission.RevertAssert();
						}
					}
					s_isClientSKUInstallation = flag2;
					s_isClientSKUInstallationInitialized = true;
				}
				return s_isClientSKUInstallation;
			}
		}

		internal static string GetHostName()
		{
			if (s_hostName == null)
			{
				s_hostName = Dns.GetHostName();
				if (s_hostName == null)
				{
					throw new ArgumentNullException("hostName");
				}
			}
			return s_hostName;
		}

		internal static string GetMachineName()
		{
			if (s_MachineName == null)
			{
				string hostName = GetHostName();
				if (hostName != null)
				{
					IPHostEntry hostEntry = Dns.GetHostEntry(hostName);
					if (hostEntry != null)
					{
						s_MachineName = hostEntry.HostName;
					}
				}
				if (s_MachineName == null)
				{
					throw new ArgumentNullException("machine");
				}
			}
			return s_MachineName;
		}

		internal static bool IsLocalIpAddress(IPAddress remoteAddress)
		{
			if (s_MachineIpAddress == null)
			{
				string machineName = GetMachineName();
				IPHostEntry hostEntry = Dns.GetHostEntry(machineName);
				if (hostEntry == null || hostEntry.AddressList.Length != 1)
				{
					return IsLocalIpAddress(hostEntry, remoteAddress.AddressFamily, remoteAddress);
				}
				if (Socket.SupportsIPv4)
				{
					s_MachineIpAddress = GetMachineAddress(hostEntry, AddressFamily.InterNetwork);
				}
				else
				{
					s_MachineIpAddress = GetMachineAddress(hostEntry, AddressFamily.InterNetworkV6);
				}
			}
			return s_MachineIpAddress.Equals(remoteAddress);
		}

		internal static bool IsLocalIpAddress(IPHostEntry host, AddressFamily addressFamily, IPAddress remoteAddress)
		{
			if (host != null)
			{
				IPAddress[] addressList = host.AddressList;
				for (int i = 0; i < addressList.Length; i++)
				{
					if (addressList[i].AddressFamily == addressFamily && addressList[i].Equals(remoteAddress))
					{
						return true;
					}
				}
			}
			return false;
		}

		internal static string DecodeMachineName(string machineName)
		{
			if (machineName.Equals("$hostName"))
			{
				return GetHostName();
			}
			return machineName;
		}

		internal static string GetMachineIp()
		{
			if (s_MachineIp == null)
			{
				string machineName = GetMachineName();
				IPHostEntry hostEntry = Dns.GetHostEntry(machineName);
				AddressFamily addressFamily = (Socket.SupportsIPv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6);
				IPAddress machineAddress = GetMachineAddress(hostEntry, addressFamily);
				if (machineAddress != null)
				{
					s_MachineIp = machineAddress.ToString();
				}
				if (s_MachineIp == null)
				{
					throw new ArgumentNullException("ip");
				}
			}
			return s_MachineIp;
		}

		internal static IPAddress GetMachineAddress(IPHostEntry host, AddressFamily addressFamily)
		{
			IPAddress result = null;
			if (host != null)
			{
				IPAddress[] addressList = host.AddressList;
				for (int i = 0; i < addressList.Length; i++)
				{
					if (addressList[i].AddressFamily == addressFamily)
					{
						result = addressList[i];
						break;
					}
				}
			}
			return result;
		}

		internal static Header[] GetMessagePropertiesAsSoapHeader(IMessage reqMsg)
		{
			IDictionary properties = reqMsg.Properties;
			if (properties == null)
			{
				return null;
			}
			int count = properties.Count;
			if (count == 0)
			{
				return null;
			}
			IDictionaryEnumerator enumerator = properties.GetEnumerator();
			bool[] array = new bool[count];
			int num = 0;
			int num2 = 0;
			IMethodMessage methodMessage = (IMethodMessage)reqMsg;
			while (enumerator.MoveNext())
			{
				string text = (string)enumerator.Key;
				if (text.Length >= 2 && string.CompareOrdinal(text, 0, "__", 0, 2) == 0 && (text.Equals("__Args") || text.Equals("__OutArgs") || text.Equals("__Return") || text.Equals("__Uri") || text.Equals("__MethodName") || (text.Equals("__MethodSignature") && !RemotingServices.IsMethodOverloaded(methodMessage) && !methodMessage.HasVarArgs) || text.Equals("__TypeName") || text.Equals("__Fault") || (text.Equals("__CallContext") && (enumerator.Value == null || !((LogicalCallContext)enumerator.Value).HasInfo))))
				{
					num2++;
					continue;
				}
				array[num2] = true;
				num2++;
				num++;
			}
			if (num == 0)
			{
				return null;
			}
			Header[] array2 = new Header[num];
			enumerator.Reset();
			int num3 = 0;
			num2 = 0;
			while (enumerator.MoveNext())
			{
				object key = enumerator.Key;
				if (!array[num3])
				{
					num3++;
					continue;
				}
				Header header = enumerator.Value as Header;
				if (header == null)
				{
					header = new Header((string)key, enumerator.Value, _MustUnderstand: false, "http://schemas.microsoft.com/clr/soap/messageProperties");
				}
				if (num2 == array2.Length)
				{
					Header[] array3 = new Header[num2 + 1];
					Array.Copy(array2, array3, num2);
					array2 = array3;
				}
				array2[num2] = header;
				num2++;
				num3++;
			}
			return array2;
		}

		internal static Header[] GetSoapHeaders(IMessage reqMsg)
		{
			return GetMessagePropertiesAsSoapHeader(reqMsg);
		}

		internal static SoapFormatter CreateSoapFormatter(bool serialize, bool includeVersions)
		{
			SoapFormatter soapFormatter = new SoapFormatter();
			if (serialize)
			{
				RemotingSurrogateSelector remotingSurrogateSelector = (RemotingSurrogateSelector)(soapFormatter.SurrogateSelector = new RemotingSurrogateSelector());
				remotingSurrogateSelector.UseSoapFormat();
			}
			else
			{
				soapFormatter.SurrogateSelector = null;
			}
			soapFormatter.Context = new StreamingContext(StreamingContextStates.Other);
			soapFormatter.AssemblyFormat = (includeVersions ? FormatterAssemblyStyle.Full : FormatterAssemblyStyle.Simple);
			return soapFormatter;
		}

		internal static BinaryFormatter CreateBinaryFormatter(bool serialize, bool includeVersionsOrStrictBinding)
		{
			BinaryFormatter binaryFormatter = new BinaryFormatter();
			if (serialize)
			{
				RemotingSurrogateSelector remotingSurrogateSelector = (RemotingSurrogateSelector)(binaryFormatter.SurrogateSelector = new RemotingSurrogateSelector());
			}
			else
			{
				binaryFormatter.SurrogateSelector = null;
			}
			binaryFormatter.Context = new StreamingContext(StreamingContextStates.Other);
			binaryFormatter.AssemblyFormat = (includeVersionsOrStrictBinding ? FormatterAssemblyStyle.Full : FormatterAssemblyStyle.Simple);
			return binaryFormatter;
		}

		internal static void SerializeSoapMessage(IMessage msg, Stream outputStream, bool includeVersions)
		{
			SoapFormatter soapFormatter = CreateSoapFormatter(serialize: true, includeVersions);
			if (msg is IMethodMessage methodMessage)
			{
				MethodBase methodBase = methodMessage.MethodBase;
				if (methodBase != null)
				{
					Type declaringType = methodMessage.MethodBase.DeclaringType;
					SoapTypeAttribute soapTypeAttribute = (SoapTypeAttribute)InternalRemotingServices.GetCachedSoapAttribute(declaringType);
					if ((soapTypeAttribute.SoapOptions & SoapOption.AlwaysIncludeTypes) == SoapOption.AlwaysIncludeTypes)
					{
						soapFormatter.TypeFormat |= FormatterTypeStyle.TypesAlways;
					}
					if ((soapTypeAttribute.SoapOptions & SoapOption.XsdString) == SoapOption.XsdString)
					{
						soapFormatter.TypeFormat |= FormatterTypeStyle.XsdString;
					}
				}
			}
			Header[] soapHeaders = GetSoapHeaders(msg);
			((RemotingSurrogateSelector)soapFormatter.SurrogateSelector).SetRootObject(msg);
			soapFormatter.Serialize(outputStream, msg, soapHeaders);
		}

		internal static Stream SerializeSoapMessage(IMessage msg, bool includeVersions)
		{
			MemoryStream memoryStream = new MemoryStream();
			SerializeSoapMessage(msg, memoryStream, includeVersions);
			memoryStream.Position = 0L;
			return memoryStream;
		}

		internal static void SerializeBinaryMessage(IMessage msg, Stream outputStream, bool includeVersions)
		{
			BinaryFormatter binaryFormatter = CreateBinaryFormatter(serialize: true, includeVersions);
			binaryFormatter.Serialize(outputStream, msg, null);
		}

		internal static Stream SerializeBinaryMessage(IMessage msg, bool includeVersions)
		{
			MemoryStream memoryStream = new MemoryStream();
			SerializeBinaryMessage(msg, memoryStream, includeVersions);
			memoryStream.Position = 0L;
			return memoryStream;
		}

		internal static IMessage DeserializeSoapRequestMessage(Stream inputStream, Header[] h, bool bStrictBinding, TypeFilterLevel securityLevel)
		{
			SoapFormatter soapFormatter = CreateSoapFormatter(serialize: false, bStrictBinding);
			soapFormatter.FilterLevel = securityLevel;
			MethodCall methodCall = new MethodCall(h);
			soapFormatter.Deserialize(inputStream, methodCall.HeaderHandler);
			return methodCall;
		}

		internal static IMessage DeserializeSoapResponseMessage(Stream inputStream, IMessage requestMsg, Header[] h, bool bStrictBinding)
		{
			SoapFormatter soapFormatter = CreateSoapFormatter(serialize: false, bStrictBinding);
			IMethodCallMessage mcm = (IMethodCallMessage)requestMsg;
			MethodResponse methodResponse = new MethodResponse(h, mcm);
			soapFormatter.Deserialize(inputStream, methodResponse.HeaderHandler);
			return methodResponse;
		}

		internal static IMessage DeserializeBinaryRequestMessage(string objectUri, Stream inputStream, bool bStrictBinding, TypeFilterLevel securityLevel)
		{
			BinaryFormatter binaryFormatter = CreateBinaryFormatter(serialize: false, bStrictBinding);
			binaryFormatter.FilterLevel = securityLevel;
			UriHeaderHandler @object = new UriHeaderHandler(objectUri);
			return (IMessage)binaryFormatter.UnsafeDeserialize(inputStream, @object.HeaderHandler);
		}

		internal static IMessage DeserializeBinaryResponseMessage(Stream inputStream, IMethodCallMessage reqMsg, bool bStrictBinding)
		{
			BinaryFormatter binaryFormatter = CreateBinaryFormatter(serialize: false, bStrictBinding);
			return (IMessage)binaryFormatter.UnsafeDeserializeMethodResponse(inputStream, null, reqMsg);
		}

		internal static Stream SerializeMessage(string mimeType, IMessage msg, bool includeVersions)
		{
			Stream stream = new MemoryStream();
			SerializeMessage(mimeType, msg, stream, includeVersions);
			stream.Position = 0L;
			return stream;
		}

		internal static void SerializeMessage(string mimeType, IMessage msg, Stream outputStream, bool includeVersions)
		{
			if (string.Compare(mimeType, "text/xml", StringComparison.Ordinal) == 0)
			{
				SerializeSoapMessage(msg, outputStream, includeVersions);
			}
			else if (string.Compare(mimeType, "application/octet-stream", StringComparison.Ordinal) == 0)
			{
				SerializeBinaryMessage(msg, outputStream, includeVersions);
			}
		}

		internal static IMessage DeserializeMessage(string mimeType, Stream xstm, bool methodRequest, IMessage msg)
		{
			return DeserializeMessage(mimeType, xstm, methodRequest, msg, null);
		}

		internal static IMessage DeserializeMessage(string mimeType, Stream xstm, bool methodRequest, IMessage msg, Header[] h)
		{
			Stream stream = null;
			bool flag = false;
			bool flag2 = true;
			if (string.Compare(mimeType, "application/octet-stream", StringComparison.Ordinal) == 0)
			{
				flag2 = true;
			}
			if (string.Compare(mimeType, "text/xml", StringComparison.Ordinal) == 0)
			{
				flag2 = false;
			}
			if (!flag)
			{
				stream = xstm;
			}
			else
			{
				long position = xstm.Position;
				MemoryStream memoryStream = (MemoryStream)xstm;
				byte[] array = memoryStream.ToArray();
				xstm.Position = position;
				string @string = Encoding.ASCII.GetString(array, 0, array.Length);
				byte[] buffer = Convert.FromBase64String(@string);
				MemoryStream memoryStream2 = new MemoryStream(buffer);
				stream = memoryStream2;
			}
			IRemotingFormatter remotingFormatter = MimeTypeToFormatter(mimeType, serialize: false);
			object obj;
			if (flag2)
			{
				obj = ((BinaryFormatter)remotingFormatter).UnsafeDeserializeMethodResponse(stream, null, (IMethodCallMessage)msg);
			}
			else if (methodRequest)
			{
				MethodCall methodCall = new MethodCall(h);
				remotingFormatter.Deserialize(stream, methodCall.HeaderHandler);
				obj = methodCall;
			}
			else
			{
				IMethodCallMessage mcm = (IMethodCallMessage)msg;
				MethodResponse methodResponse = new MethodResponse(h, mcm);
				remotingFormatter.Deserialize(stream, methodResponse.HeaderHandler);
				obj = methodResponse;
			}
			return (IMessage)obj;
		}

		internal static IRemotingFormatter MimeTypeToFormatter(string mimeType, bool serialize)
		{
			if (string.Compare(mimeType, "text/xml", StringComparison.Ordinal) == 0)
			{
				return CreateSoapFormatter(serialize, includeVersions: true);
			}
			if (string.Compare(mimeType, "application/octet-stream", StringComparison.Ordinal) == 0)
			{
				return CreateBinaryFormatter(serialize, includeVersionsOrStrictBinding: true);
			}
			return null;
		}

		internal static string RemoveApplicationNameFromUri(string uri)
		{
			if (uri == null)
			{
				return null;
			}
			string applicationName = RemotingConfiguration.ApplicationName;
			if (applicationName == null || applicationName.Length == 0)
			{
				return uri;
			}
			if (uri.Length < applicationName.Length + 2)
			{
				return uri;
			}
			if (string.Compare(applicationName, 0, uri, 0, applicationName.Length, StringComparison.OrdinalIgnoreCase) == 0 && uri[applicationName.Length] == '/')
			{
				uri = uri.Substring(applicationName.Length + 1);
			}
			return uri;
		}

		internal static void AppendProviderToClientProviderChain(IClientChannelSinkProvider providerChain, IClientChannelSinkProvider provider)
		{
			if (providerChain == null)
			{
				throw new ArgumentNullException("providerChain");
			}
			while (providerChain.Next != null)
			{
				providerChain = providerChain.Next;
			}
			providerChain.Next = provider;
		}

		internal static void CollectChannelDataFromServerSinkProviders(ChannelDataStore channelData, IServerChannelSinkProvider provider)
		{
			while (provider != null)
			{
				provider.GetChannelData(channelData);
				provider = provider.Next;
			}
		}

		internal static void VerifyNoProviderData(string providerTypeName, ICollection providerData)
		{
			if (providerData != null && providerData.Count > 0)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, GetResourceString("Remoting_Providers_Config_NotExpectingProviderData"), providerTypeName));
			}
		}

		internal static void ReportUnknownProviderConfigProperty(string providerTypeName, string propertyName)
		{
			throw new RemotingException(string.Format(CultureInfo.CurrentCulture, GetResourceString("Remoting_Providers_Config_UnknownProperty"), providerTypeName, propertyName));
		}

		internal static SinkChannelProtocol DetermineChannelProtocol(IChannel channel)
		{
			string objectURI;
			string text = channel.Parse("http://foo.com/foo", out objectURI);
			if (text != null)
			{
				return SinkChannelProtocol.Http;
			}
			return SinkChannelProtocol.Other;
		}

		internal static bool SetupUrlBashingForIisSslIfNecessary()
		{
			if (IsClientSKUInstallation)
			{
				return false;
			}
			return SetupUrlBashingForIisSslIfNecessaryWorker();
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		internal static bool SetupUrlBashingForIisSslIfNecessaryWorker()
		{
			HttpContext current = HttpContext.Current;
			bool result = false;
			if (current != null && current.Request.IsSecureConnection)
			{
				Uri url = current.Request.Url;
				StringBuilder stringBuilder = new StringBuilder(100);
				stringBuilder.Append("https://");
				stringBuilder.Append(url.Host);
				stringBuilder.Append(":");
				stringBuilder.Append(url.Port);
				stringBuilder.Append("/");
				stringBuilder.Append(RemotingConfiguration.ApplicationName);
				CallContext.SetData("__bashChannelUrl", new string[2]
				{
					IisHelper.ApplicationUrl,
					stringBuilder.ToString()
				});
				result = true;
			}
			return result;
		}

		internal static void CleanupUrlBashingForIisSslIfNecessary(bool bBashedUrl)
		{
			if (bBashedUrl)
			{
				CallContext.FreeNamedDataSlot("__bashChannelUrl");
			}
		}

		internal static string GetCurrentSidString()
		{
			return WindowsIdentity.GetCurrent().User.ToString();
		}

		internal static string SidToString(IntPtr sidPointer)
		{
			if (!NativeMethods.IsValidSid(sidPointer))
			{
				throw new RemotingException(GetResourceString("Remoting_InvalidSid"));
			}
			StringBuilder stringBuilder = new StringBuilder();
			IntPtr sidIdentifierAuthority = NativeMethods.GetSidIdentifierAuthority(sidPointer);
			int lastWin32Error = Marshal.GetLastWin32Error();
			if (lastWin32Error != 0)
			{
				throw new Win32Exception(lastWin32Error);
			}
			byte[] array = new byte[6];
			Marshal.Copy(sidIdentifierAuthority, array, 0, 6);
			IntPtr sidSubAuthorityCount = NativeMethods.GetSidSubAuthorityCount(sidPointer);
			lastWin32Error = Marshal.GetLastWin32Error();
			if (lastWin32Error != 0)
			{
				throw new Win32Exception(lastWin32Error);
			}
			uint num = Marshal.ReadByte(sidSubAuthorityCount);
			if (array[0] != 0 && array[1] != 0)
			{
				stringBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{0:x2}{1:x2}{2:x2}{3:x2}{4:x2}{5:x2}", array[0], array[1], array[2], array[3], array[4], array[5]));
			}
			else
			{
				uint num2 = (uint)(array[5] + (array[4] << 8) + (array[3] << 16) + (array[2] << 24));
				stringBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{0:x12}", num2));
			}
			for (int i = 0; i < num; i++)
			{
				IntPtr sidSubAuthority = NativeMethods.GetSidSubAuthority(sidPointer, i);
				lastWin32Error = Marshal.GetLastWin32Error();
				if (lastWin32Error != 0)
				{
					throw new Win32Exception(lastWin32Error);
				}
				uint num3 = (uint)Marshal.ReadInt32(sidSubAuthority);
				stringBuilder.Append(string.Format(CultureInfo.CurrentCulture, "-{0:x12}", num3));
			}
			return stringBuilder.ToString();
		}

		private static ResourceManager InitResourceManager()
		{
			if (SystemResMgr == null)
			{
				SystemResMgr = new ResourceManager("System.Runtime.Remoting", typeof(CoreChannel).Module.Assembly);
			}
			return SystemResMgr;
		}

		internal static string GetResourceString(string key)
		{
			if (SystemResMgr == null)
			{
				InitResourceManager();
			}
			return SystemResMgr.GetString(key, null);
		}

		[Conditional("_DEBUG")]
		internal static void DebugOut(string s)
		{
		}

		[Conditional("_DEBUG")]
		internal static void DebugOutXMLStream(Stream stm, string tag)
		{
		}

		[Conditional("_DEBUG")]
		internal static void DebugMessage(IMessage msg)
		{
		}

		[Conditional("_DEBUG")]
		internal static void DebugException(string name, Exception e)
		{
		}

		[Conditional("_DEBUG")]
		internal static void DebugStream(Stream stm)
		{
		}
	}
	internal static class IisHelper
	{
		private static bool _bIsSslRequired;

		private static string _iisAppUrl;

		internal static bool IsSslRequired => _bIsSslRequired;

		internal static string ApplicationUrl
		{
			get
			{
				return _iisAppUrl;
			}
			set
			{
				_iisAppUrl = value;
			}
		}

		internal static void Initialize()
		{
			try
			{
				HttpRequest request = HttpContext.Current.Request;
				string text = request.ServerVariables["APPL_MD_PATH"];
				bool bIsSslRequired = false;
				if (text.StartsWith("/LM/", StringComparison.Ordinal))
				{
					text = "IIS://localhost/" + text.Substring(4);
					DirectoryEntry directoryEntry = new DirectoryEntry(text);
					bIsSslRequired = (bool)directoryEntry.Properties["AccessSSL"][0];
				}
				_bIsSslRequired = bIsSslRequired;
			}
			catch
			{
			}
		}
	}
	internal class ExclusiveTcpListener : TcpListener
	{
		internal bool IsListening => base.Active;

		internal ExclusiveTcpListener(IPAddress localaddr, int port)
			: base(localaddr, port)
		{
		}

		internal void Start(bool exclusiveAddressUse)
		{
			bool flag = exclusiveAddressUse && Environment.OSVersion.Platform == PlatformID.Win32NT && base.Server != null && !base.Active;
			if (flag)
			{
				base.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, 1);
			}
			try
			{
				Start();
			}
			catch (SocketException)
			{
				if (flag)
				{
					base.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, 0);
					Start();
					return;
				}
				throw;
			}
		}
	}
	internal class RequestQueue
	{
		private const int _workItemLimit = 2;

		private int _minExternFreeThreads;

		private int _minLocalFreeThreads;

		private int _queueLimit;

		private Queue _localQueue = new Queue();

		private Queue _externQueue = new Queue();

		private int _count;

		private WaitCallback _workItemCallback;

		private int _workItemCount;

		private static bool IsLocal(SocketHandler sh)
		{
			return sh.IsLocal();
		}

		private void QueueRequest(SocketHandler sh, bool isLocal)
		{
			lock (this)
			{
				if (isLocal)
				{
					_localQueue.Enqueue(sh);
				}
				else
				{
					_externQueue.Enqueue(sh);
				}
				_count++;
			}
		}

		private SocketHandler DequeueRequest(bool localOnly)
		{
			object obj = null;
			if (_count > 0)
			{
				lock (this)
				{
					if (_localQueue.Count > 0)
					{
						obj = _localQueue.Dequeue();
						_count--;
					}
					else if (!localOnly && _externQueue.Count > 0)
					{
						obj = _externQueue.Dequeue();
						_count--;
					}
				}
			}
			return (SocketHandler)obj;
		}

		internal RequestQueue(int minExternFreeThreads, int minLocalFreeThreads, int queueLimit)
		{
			_minExternFreeThreads = minExternFreeThreads;
			_minLocalFreeThreads = minLocalFreeThreads;
			_queueLimit = queueLimit;
			_workItemCallback = WorkItemCallback;
		}

		internal void ProcessNextRequest(SocketHandler sh)
		{
			sh = GetRequestToExecute(sh);
			sh?.ProcessRequestNow();
		}

		internal SocketHandler GetRequestToExecute(SocketHandler sh)
		{
			ThreadPool.GetAvailableThreads(out var workerThreads, out var completionPortThreads);
			int num = ((completionPortThreads > workerThreads) ? workerThreads : completionPortThreads);
			if (num >= _minExternFreeThreads && _count == 0)
			{
				return sh;
			}
			bool flag = IsLocal(sh);
			if (flag && num >= _minLocalFreeThreads && _count == 0)
			{
				return sh;
			}
			if (_count >= _queueLimit)
			{
				sh.RejectRequestNowSinceServerIsBusy();
				return null;
			}
			QueueRequest(sh, flag);
			sh = ((num >= _minExternFreeThreads) ? DequeueRequest(localOnly: false) : ((num < _minLocalFreeThreads) ? null : DequeueRequest(localOnly: true)));
			if (sh == null)
			{
				ScheduleMoreWorkIfNeeded();
			}
			return sh;
		}

		internal void ScheduleMoreWorkIfNeeded()
		{
			if (_count != 0 && _workItemCount < 2)
			{
				Interlocked.Increment(ref _workItemCount);
				ThreadPool.UnsafeQueueUserWorkItem(_workItemCallback, null);
			}
		}

		private void WorkItemCallback(object state)
		{
			Interlocked.Decrement(ref _workItemCount);
			if (_count == 0)
			{
				return;
			}
			ThreadPool.GetAvailableThreads(out var workerThreads, out var _);
			bool flag = false;
			if (workerThreads >= _minLocalFreeThreads)
			{
				SocketHandler socketHandler = DequeueRequest(workerThreads < _minExternFreeThreads);
				if (socketHandler != null)
				{
					socketHandler.ProcessRequestNow();
					flag = true;
				}
			}
			if (!flag)
			{
				Thread.Sleep(250);
				ScheduleMoreWorkIfNeeded();
			}
		}
	}
	internal delegate SocketHandler SocketHandlerFactory(Socket socket, SocketCache socketCache, string machineAndPort);
	internal class RemoteConnection
	{
		private static char[] colonSep = new char[1] { ':' };

		private CachedSocketList _cachedSocketList;

		private SocketCache _socketCache;

		private string _machineAndPort;

		private IPAddress[] _addressList;

		private int _port;

		private EndPoint _lkgIPEndPoint;

		private bool connectIPv6;

		internal RemoteConnection(SocketCache socketCache, string machineAndPort)
		{
			_socketCache = socketCache;
			_cachedSocketList = new CachedSocketList(socketCache.SocketTimeout, socketCache.CachePolicy);
			Uri uri = new Uri("dummy://" + machineAndPort);
			_port = uri.Port;
			_machineAndPort = machineAndPort;
			_addressList = Dns.GetHostAddresses(uri.DnsSafeHost);
			connectIPv6 = Socket.OSSupportsIPv6 && HasIPv6Address(_addressList);
		}

		internal SocketHandler GetSocket()
		{
			SocketHandler socket = _cachedSocketList.GetSocket();
			if (socket != null)
			{
				return socket;
			}
			return CreateNewSocket();
		}

		internal void ReleaseSocket(SocketHandler socket)
		{
			socket.ReleaseControl();
			_cachedSocketList.ReturnSocket(socket);
		}

		private bool HasIPv6Address(IPAddress[] addressList)
		{
			foreach (IPAddress iPAddress in addressList)
			{
				if (iPAddress.AddressFamily == AddressFamily.InterNetworkV6)
				{
					return true;
				}
			}
			return false;
		}

		private void DisableNagleDelays(Socket socket)
		{
			socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.Debug, 1);
		}

		private SocketHandler CreateNewSocket()
		{
			if (_addressList.Length == 1)
			{
				return CreateNewSocket(new IPEndPoint(_addressList[0], _port));
			}
			if (_lkgIPEndPoint != null)
			{
				try
				{
					return CreateNewSocket(_lkgIPEndPoint);
				}
				catch (Exception)
				{
					_lkgIPEndPoint = null;
				}
			}
			if (connectIPv6)
			{
				try
				{
					return CreateNewSocket(AddressFamily.InterNetworkV6);
				}
				catch (Exception)
				{
				}
			}
			return CreateNewSocket(AddressFamily.InterNetwork);
		}

		private SocketHandler CreateNewSocket(EndPoint ipEndPoint)
		{
			Socket socket = new Socket(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
			DisableNagleDelays(socket);
			socket.Connect(ipEndPoint);
			_lkgIPEndPoint = socket.RemoteEndPoint;
			return _socketCache.CreateSocketHandler(socket, _machineAndPort);
		}

		private SocketHandler CreateNewSocket(AddressFamily family)
		{
			Socket socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
			DisableNagleDelays(socket);
			socket.Connect(_addressList, _port);
			_lkgIPEndPoint = socket.RemoteEndPoint;
			return _socketCache.CreateSocketHandler(socket, _machineAndPort);
		}

		internal void TimeoutSockets(DateTime currentTime)
		{
			_cachedSocketList.TimeoutSockets(currentTime, _socketCache.SocketTimeout);
		}
	}
	internal class CachedSocket
	{
		private SocketHandler _socket;

		private DateTime _socketLastUsed;

		private CachedSocket _next;

		internal SocketHandler Handler => _socket;

		internal DateTime LastUsed => _socketLastUsed;

		internal CachedSocket Next
		{
			get
			{
				return _next;
			}
			set
			{
				_next = value;
			}
		}

		internal CachedSocket(SocketHandler socket, CachedSocket next)
		{
			_socket = socket;
			_socketLastUsed = DateTime.UtcNow;
			_next = next;
		}
	}
	internal class CachedSocketList
	{
		private int _socketCount;

		private TimeSpan _socketLifetime;

		private SocketCachePolicy _socketCachePolicy;

		private CachedSocket _socketList;

		internal CachedSocketList(TimeSpan socketLifetime, SocketCachePolicy socketCachePolicy)
		{
			_socketCount = 0;
			_socketLifetime = socketLifetime;
			_socketCachePolicy = socketCachePolicy;
			_socketList = null;
		}

		internal SocketHandler GetSocket()
		{
			if (_socketCount == 0)
			{
				return null;
			}
			lock (this)
			{
				if (_socketList != null)
				{
					SocketHandler handler = _socketList.Handler;
					_socketList = _socketList.Next;
					handler.RaceForControl();
					_socketCount--;
					return handler;
				}
			}
			return null;
		}

		internal void ReturnSocket(SocketHandler socket)
		{
			TimeSpan timeSpan = DateTime.UtcNow - socket.CreationTime;
			bool flag = false;
			lock (this)
			{
				if (_socketCachePolicy != SocketCachePolicy.AbsoluteTimeout || timeSpan < _socketLifetime)
				{
					for (CachedSocket cachedSocket = _socketList; cachedSocket != null; cachedSocket = cachedSocket.Next)
					{
						if (socket == cachedSocket.Handler)
						{
							return;
						}
					}
					_socketList = new CachedSocket(socket, _socketList);
					_socketCount++;
				}
				else
				{
					flag = true;
				}
			}
			if (flag)
			{
				socket.Close();
			}
		}

		internal void TimeoutSockets(DateTime currentTime, TimeSpan socketLifetime)
		{
			lock (this)
			{
				CachedSocket cachedSocket = null;
				CachedSocket cachedSocket2 = _socketList;
				while (cachedSocket2 != null)
				{
					if ((_socketCachePolicy == SocketCachePolicy.AbsoluteTimeout && currentTime - cachedSocket2.Handler.CreationTime > socketLifetime) || currentTime - cachedSocket2.LastUsed > socketLifetime)
					{
						cachedSocket2.Handler.Close();
						if (cachedSocket != null)
						{
							cachedSocket2 = (cachedSocket.Next = cachedSocket2.Next);
						}
						else
						{
							_socketList = cachedSocket2.Next;
							cachedSocket2 = _socketList;
						}
						_socketCount--;
					}
					else
					{
						cachedSocket = cachedSocket2;
						cachedSocket2 = cachedSocket2.Next;
					}
				}
			}
		}
	}
	internal class SocketCache
	{
		private static Hashtable _connections;

		private SocketHandlerFactory _handlerFactory;

		private static RegisteredWaitHandle _registeredWaitHandle;

		private static WaitOrTimerCallback _socketTimeoutDelegate;

		private static AutoResetEvent _socketTimeoutWaitHandle;

		private static TimeSpan _socketTimeoutPollTime;

		private SocketCachePolicy _socketCachePolicy;

		private TimeSpan _socketTimeout;

		private int _receiveTimeout;

		internal TimeSpan SocketTimeout
		{
			get
			{
				return _socketTimeout;
			}
			set
			{
				_socketTimeout = value;
			}
		}

		internal int ReceiveTimeout
		{
			get
			{
				return _receiveTimeout;
			}
			set
			{
				_receiveTimeout = value;
			}
		}

		internal SocketCachePolicy CachePolicy
		{
			get
			{
				return _socketCachePolicy;
			}
			set
			{
				_socketCachePolicy = value;
			}
		}

		static SocketCache()
		{
			_connections = new Hashtable();
			_socketTimeoutPollTime = TimeSpan.FromSeconds(10.0);
			InitializeSocketTimeoutHandler();
		}

		internal SocketCache(SocketHandlerFactory handlerFactory, SocketCachePolicy socketCachePolicy, TimeSpan socketTimeout)
		{
			_handlerFactory = handlerFactory;
			_socketCachePolicy = socketCachePolicy;
			_socketTimeout = socketTimeout;
		}

		private static void InitializeSocketTimeoutHandler()
		{
			_socketTimeoutDelegate = TimeoutSockets;
			_socketTimeoutWaitHandle = new AutoResetEvent(initialState: false);
			_registeredWaitHandle = ThreadPool.UnsafeRegisterWaitForSingleObject(_socketTimeoutWaitHandle, _socketTimeoutDelegate, "TcpChannelSocketTimeout", _socketTimeoutPollTime, executeOnlyOnce: true);
		}

		private static void TimeoutSockets(object state, bool wasSignalled)
		{
			DateTime utcNow = DateTime.UtcNow;
			lock (_connections)
			{
				foreach (DictionaryEntry connection in _connections)
				{
					RemoteConnection remoteConnection = (RemoteConnection)connection.Value;
					remoteConnection.TimeoutSockets(utcNow);
				}
			}
			_registeredWaitHandle.Unregister(null);
			_registeredWaitHandle = ThreadPool.UnsafeRegisterWaitForSingleObject(_socketTimeoutWaitHandle, _socketTimeoutDelegate, "TcpChannelSocketTimeout", _socketTimeoutPollTime, executeOnlyOnce: true);
		}

		internal SocketHandler CreateSocketHandler(Socket socket, string machineAndPort)
		{
			socket.ReceiveTimeout = _receiveTimeout;
			return _handlerFactory(socket, this, machineAndPort);
		}

		public SocketHandler GetSocket(string machinePortAndSid, bool openNew)
		{
			RemoteConnection remoteConnection = (RemoteConnection)_connections[machinePortAndSid];
			if (openNew || remoteConnection == null)
			{
				remoteConnection = new RemoteConnection(this, machinePortAndSid);
				lock (_connections)
				{
					_connections[machinePortAndSid] = remoteConnection;
				}
			}
			return remoteConnection.GetSocket();
		}

		public void ReleaseSocket(string machinePortAndSid, SocketHandler socket)
		{
			RemoteConnection remoteConnection = (RemoteConnection)_connections[machinePortAndSid];
			if (remoteConnection != null)
			{
				remoteConnection.ReleaseSocket(socket);
			}
			else
			{
				socket.Close();
			}
		}
	}
	internal delegate bool ValidateByteDelegate(byte b);
	internal abstract class SocketHandler
	{
		protected Socket NetSocket;

		protected Stream NetStream;

		private DateTime _creationTime;

		private RequestQueue _requestQueue;

		private byte[] _dataBuffer;

		private int _dataBufferSize;

		private int _dataOffset;

		private int _dataCount;

		private AsyncCallback _beginReadCallback;

		private IAsyncResult _beginReadAsyncResult;

		private WaitCallback _dataArrivedCallback;

		private object _dataArrivedCallbackState;

		private WindowsIdentity _impersonationIdentity;

		private byte[] _byteBuffer = new byte[4];

		private int _controlCookie = 1;

		public DateTime CreationTime => _creationTime;

		public WaitCallback DataArrivedCallback
		{
			set
			{
				_dataArrivedCallback = value;
			}
		}

		public object DataArrivedCallbackState
		{
			get
			{
				return _dataArrivedCallbackState;
			}
			set
			{
				_dataArrivedCallbackState = value;
			}
		}

		public WindowsIdentity ImpersonationIdentity
		{
			get
			{
				return _impersonationIdentity;
			}
			set
			{
				_impersonationIdentity = value;
			}
		}

		private SocketHandler()
		{
		}

		public SocketHandler(Socket socket, Stream netStream)
		{
			_beginReadCallback = BeginReadMessageCallback;
			_creationTime = DateTime.UtcNow;
			NetSocket = socket;
			NetStream = netStream;
			_dataBuffer = CoreChannel.BufferPool.GetBuffer();
			_dataBufferSize = _dataBuffer.Length;
			_dataOffset = 0;
			_dataCount = 0;
		}

		internal SocketHandler(Socket socket, RequestQueue requestQueue, Stream netStream)
			: this(socket, netStream)
		{
			_requestQueue = requestQueue;
		}

		public bool RaceForControl()
		{
			if (1 == Interlocked.Exchange(ref _controlCookie, 0))
			{
				return true;
			}
			return false;
		}

		public void ReleaseControl()
		{
			_controlCookie = 1;
		}

		internal bool IsLocalhost()
		{
			if (NetSocket == null || NetSocket.RemoteEndPoint == null)
			{
				return true;
			}
			IPAddress address = ((IPEndPoint)NetSocket.RemoteEndPoint).Address;
			if (!IPAddress.IsLoopback(address))
			{
				return CoreChannel.IsLocalIpAddress(address);
			}
			return true;
		}

		internal bool IsLocal()
		{
			if (NetSocket == null)
			{
				return true;
			}
			IPAddress address = ((IPEndPoint)NetSocket.RemoteEndPoint).Address;
			return IPAddress.IsLoopback(address);
		}

		internal bool CustomErrorsEnabled()
		{
			try
			{
				return RemotingConfiguration.CustomErrorsEnabled(IsLocalhost());
			}
			catch
			{
				return true;
			}
		}

		protected abstract void PrepareForNewMessage();

		protected virtual void SendErrorMessageIfPossible(Exception e)
		{
		}

		public virtual void OnInputStreamClosed()
		{
		}

		public virtual void Close()
		{
			if (_requestQueue != null)
			{
				_requestQueue.ScheduleMoreWorkIfNeeded();
			}
			if (NetStream != null)
			{
				NetStream.Close();
				NetStream = null;
			}
			if (NetSocket != null)
			{
				NetSocket.Close();
				NetSocket = null;
			}
			if (_dataBuffer != null)
			{
				CoreChannel.BufferPool.ReturnBuffer(_dataBuffer);
				_dataBuffer = null;
			}
		}

		public void BeginReadMessage()
		{
			bool flag = false;
			try
			{
				if (_requestQueue != null)
				{
					_requestQueue.ScheduleMoreWorkIfNeeded();
				}
				PrepareForNewMessage();
				if (_dataCount == 0)
				{
					_beginReadAsyncResult = NetStream.BeginRead(_dataBuffer, 0, _dataBufferSize, _beginReadCallback, null);
				}
				else
				{
					flag = true;
				}
			}
			catch (Exception e)
			{
				CloseOnFatalError(e);
			}
			catch
			{
				CloseOnFatalError(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
			}
			if (flag)
			{
				if (_requestQueue != null)
				{
					_requestQueue.ProcessNextRequest(this);
				}
				else
				{
					ProcessRequestNow();
				}
				_beginReadAsyncResult = null;
			}
		}

		public void BeginReadMessageCallback(IAsyncResult ar)
		{
			bool flag = false;
			try
			{
				_beginReadAsyncResult = null;
				_dataOffset = 0;
				_dataCount = NetStream.EndRead(ar);
				if (_dataCount <= 0)
				{
					Close();
				}
				else
				{
					flag = true;
				}
			}
			catch (Exception e)
			{
				CloseOnFatalError(e);
			}
			catch
			{
				CloseOnFatalError(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
			}
			if (flag)
			{
				if (_requestQueue != null)
				{
					_requestQueue.ProcessNextRequest(this);
				}
				else
				{
					ProcessRequestNow();
				}
			}
		}

		internal void CloseOnFatalError(Exception e)
		{
			try
			{
				SendErrorMessageIfPossible(e);
				Close();
			}
			catch
			{
				try
				{
					Close();
				}
				catch
				{
				}
			}
		}

		internal void ProcessRequestNow()
		{
			try
			{
				_dataArrivedCallback?.Invoke(this);
			}
			catch (Exception e)
			{
				CloseOnFatalError(e);
			}
			catch
			{
				CloseOnFatalError(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
			}
		}

		internal void RejectRequestNowSinceServerIsBusy()
		{
			CloseOnFatalError(new RemotingException(CoreChannel.GetResourceString("Remoting_ServerIsBusy")));
		}

		public int ReadByte()
		{
			if (Read(_byteBuffer, 0, 1) != -1)
			{
				return _byteBuffer[0];
			}
			return -1;
		}

		public void WriteByte(byte value, Stream outputStream)
		{
			_byteBuffer[0] = value;
			outputStream.Write(_byteBuffer, 0, 1);
		}

		public ushort ReadUInt16()
		{
			Read(_byteBuffer, 0, 2);
			return (ushort)((_byteBuffer[0] & 0xFFu) | (uint)(_byteBuffer[1] << 8));
		}

		public void WriteUInt16(ushort value, Stream outputStream)
		{
			_byteBuffer[0] = (byte)value;
			_byteBuffer[1] = (byte)(value >> 8);
			outputStream.Write(_byteBuffer, 0, 2);
		}

		public int ReadInt32()
		{
			Read(_byteBuffer, 0, 4);
			return (_byteBuffer[0] & 0xFF) | (_byteBuffer[1] << 8) | (_byteBuffer[2] << 16) | (_byteBuffer[3] << 24);
		}

		public void WriteInt32(int value, Stream outputStream)
		{
			_byteBuffer[0] = (byte)value;
			_byteBuffer[1] = (byte)(value >> 8);
			_byteBuffer[2] = (byte)(value >> 16);
			_byteBuffer[3] = (byte)(value >> 24);
			outputStream.Write(_byteBuffer, 0, 4);
		}

		protected bool ReadAndMatchFourBytes(byte[] buffer)
		{
			Read(_byteBuffer, 0, 4);
			return _byteBuffer[0] == buffer[0] && _byteBuffer[1] == buffer[1] && _byteBuffer[2] == buffer[2] && _byteBuffer[3] == buffer[3];
		}

		public int Read(byte[] buffer, int offset, int count)
		{
			int num = 0;
			if (_dataCount > 0)
			{
				int num2 = Math.Min(_dataCount, count);
				StreamHelper.BufferCopy(_dataBuffer, _dataOffset, buffer, offset, num2);
				_dataCount -= num2;
				_dataOffset += num2;
				count -= num2;
				offset += num2;
				num += num2;
			}
			while (count > 0)
			{
				if (count < 256)
				{
					BufferMoreData();
					int num3 = Math.Min(_dataCount, count);
					StreamHelper.BufferCopy(_dataBuffer, _dataOffset, buffer, offset, num3);
					_dataCount -= num3;
					_dataOffset += num3;
					count -= num3;
					offset += num3;
					num += num3;
				}
				else
				{
					int num4 = ReadFromSocket(buffer, offset, count);
					count -= num4;
					offset += num4;
					num += num4;
				}
			}
			return num;
		}

		private int BufferMoreData()
		{
			int num = ReadFromSocket(_dataBuffer, 0, _dataBufferSize);
			_dataOffset = 0;
			_dataCount = num;
			return num;
		}

		private int ReadFromSocket(byte[] buffer, int offset, int count)
		{
			int num = NetStream.Read(buffer, offset, count);
			if (num <= 0)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Socket_UnderlyingSocketClosed"));
			}
			return num;
		}

		protected byte[] ReadToByte(byte b)
		{
			return ReadToByte(b, null);
		}

		protected byte[] ReadToByte(byte b, ValidateByteDelegate validator)
		{
			byte[] array = null;
			if (_dataCount == 0)
			{
				BufferMoreData();
			}
			int num = _dataOffset + _dataCount;
			int dataOffset = _dataOffset;
			int num2 = dataOffset;
			bool flag = false;
			while (!flag)
			{
				bool flag2 = num2 == num;
				flag = !flag2 && _dataBuffer[num2] == b;
				if (validator != null && !flag2 && !flag && !validator(_dataBuffer[num2]))
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_InvalidDataReceived"));
				}
				if (flag2 || flag)
				{
					int num3 = num2 - dataOffset;
					if (array == null)
					{
						array = new byte[num3];
						StreamHelper.BufferCopy(_dataBuffer, dataOffset, array, 0, num3);
					}
					else
					{
						int num4 = array.Length;
						byte[] array2 = new byte[num4 + num3];
						StreamHelper.BufferCopy(array, 0, array2, 0, num4);
						StreamHelper.BufferCopy(_dataBuffer, dataOffset, array2, num4, num3);
						array = array2;
					}
					_dataOffset += num3;
					_dataCount -= num3;
					if (flag2)
					{
						BufferMoreData();
						num = _dataOffset + _dataCount;
						dataOffset = _dataOffset;
						num2 = dataOffset;
					}
					else if (flag)
					{
						_dataOffset++;
						_dataCount--;
					}
				}
				else
				{
					num2++;
				}
			}
			return array;
		}

		protected string ReadToChar(char ch)
		{
			return ReadToChar(ch, null);
		}

		protected string ReadToChar(char ch, ValidateByteDelegate validator)
		{
			byte[] array = ReadToByte((byte)ch, validator);
			if (array == null)
			{
				return null;
			}
			if (array.Length == 0)
			{
				return string.Empty;
			}
			return Encoding.ASCII.GetString(array);
		}

		public string ReadToEndOfLine()
		{
			string result = ReadToChar('\r');
			if (ReadByte() == 10)
			{
				return result;
			}
			return null;
		}
	}
	internal sealed class SocketStream : Stream
	{
		private const int maxSocketWrite = 65536;

		private const int maxSocketRead = 4194304;

		private Socket _socket;

		private int _timeout;

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override long Position
		{
			get
			{
				throw new NotSupportedException();
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public SocketStream(Socket socket)
		{
			if (socket == null)
			{
				throw new ArgumentNullException("socket");
			}
			_socket = socket;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override int Read(byte[] buffer, int offset, int size)
		{
			if (_timeout <= 0)
			{
				return _socket.Receive(buffer, offset, Math.Min(size, 4194304), SocketFlags.None);
			}
			IAsyncResult asyncResult = _socket.BeginReceive(buffer, offset, Math.Min(size, 4194304), SocketFlags.None, null, null);
			if (_timeout > 0 && !asyncResult.IsCompleted)
			{
				asyncResult.AsyncWaitHandle.WaitOne(_timeout, exitContext: false);
				if (!asyncResult.IsCompleted)
				{
					throw new RemotingTimeoutException();
				}
			}
			return _socket.EndReceive(asyncResult);
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			int num = count;
			while (num > 0)
			{
				count = Math.Min(num, 65536);
				_socket.Send(buffer, offset, count, SocketFlags.None);
				num -= count;
				offset += count;
			}
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing)
				{
					_socket.Close();
				}
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override void Flush()
		{
		}

		public override IAsyncResult BeginRead(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
		{
			return _socket.BeginReceive(buffer, offset, Math.Min(size, 4194304), SocketFlags.None, callback, state);
		}

		public override int EndRead(IAsyncResult asyncResult)
		{
			return _socket.EndReceive(asyncResult);
		}

		public override IAsyncResult BeginWrite(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
		{
			return _socket.BeginSend(buffer, offset, size, SocketFlags.None, callback, state);
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
			_socket.EndSend(asyncResult);
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}
	}
	internal static class StreamHelper
	{
		private static AsyncCallback _asyncCopyStreamReadCallback = AsyncCopyStreamReadCallback;

		private static AsyncCallback _asyncCopyStreamWriteCallback = AsyncCopyStreamWriteCallback;

		internal static void CopyStream(Stream source, Stream target)
		{
			if (source == null)
			{
				return;
			}
			if (source is ChunkedMemoryStream chunkedMemoryStream)
			{
				chunkedMemoryStream.WriteTo(target);
				return;
			}
			if (source is MemoryStream memoryStream)
			{
				memoryStream.WriteTo(target);
				return;
			}
			byte[] buffer = CoreChannel.BufferPool.GetBuffer();
			int count = buffer.Length;
			for (int num = source.Read(buffer, 0, count); num > 0; num = source.Read(buffer, 0, count))
			{
				target.Write(buffer, 0, num);
			}
			CoreChannel.BufferPool.ReturnBuffer(buffer);
		}

		internal static void BufferCopy(byte[] source, int srcOffset, byte[] dest, int destOffset, int count)
		{
			if (count > 8)
			{
				Buffer.BlockCopy(source, srcOffset, dest, destOffset, count);
				return;
			}
			for (int i = 0; i < count; i++)
			{
				dest[destOffset + i] = source[srcOffset + i];
			}
		}

		internal static IAsyncResult BeginAsyncCopyStream(Stream source, Stream target, bool asyncRead, bool asyncWrite, bool closeSource, bool closeTarget, AsyncCallback callback, object state)
		{
			AsyncCopyStreamResult asyncCopyStreamResult = new AsyncCopyStreamResult(callback, state);
			byte[] buffer = CoreChannel.BufferPool.GetBuffer();
			asyncCopyStreamResult.Source = source;
			asyncCopyStreamResult.Target = target;
			asyncCopyStreamResult.Buffer = buffer;
			asyncCopyStreamResult.AsyncRead = asyncRead;
			asyncCopyStreamResult.AsyncWrite = asyncWrite;
			asyncCopyStreamResult.CloseSource = closeSource;
			asyncCopyStreamResult.CloseTarget = closeTarget;
			try
			{
				AsyncCopyReadHelper(asyncCopyStreamResult);
				return asyncCopyStreamResult;
			}
			catch (Exception exception)
			{
				asyncCopyStreamResult.SetComplete(null, exception);
				return asyncCopyStreamResult;
			}
			catch
			{
				asyncCopyStreamResult.SetComplete(null, new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
				return asyncCopyStreamResult;
			}
		}

		internal static void EndAsyncCopyStream(IAsyncResult iar)
		{
			AsyncCopyStreamResult asyncCopyStreamResult = (AsyncCopyStreamResult)iar;
			if (!iar.IsCompleted)
			{
				iar.AsyncWaitHandle.WaitOne();
			}
			if (asyncCopyStreamResult.Exception != null)
			{
				throw asyncCopyStreamResult.Exception;
			}
		}

		private static void AsyncCopyReadHelper(AsyncCopyStreamResult streamState)
		{
			if (streamState.AsyncRead)
			{
				byte[] buffer = streamState.Buffer;
				streamState.Source.BeginRead(buffer, 0, buffer.Length, _asyncCopyStreamReadCallback, streamState);
				return;
			}
			byte[] buffer2 = streamState.Buffer;
			int num = streamState.Source.Read(buffer2, 0, buffer2.Length);
			if (num == 0)
			{
				streamState.SetComplete(null, null);
				return;
			}
			if (num < 0)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_UnknownReadError"));
			}
			AsyncCopyWriteHelper(streamState, num);
		}

		private static void AsyncCopyWriteHelper(AsyncCopyStreamResult streamState, int bytesRead)
		{
			if (streamState.AsyncWrite)
			{
				byte[] buffer = streamState.Buffer;
				streamState.Target.BeginWrite(buffer, 0, bytesRead, _asyncCopyStreamWriteCallback, streamState);
			}
			else
			{
				byte[] buffer2 = streamState.Buffer;
				streamState.Target.Write(buffer2, 0, bytesRead);
				AsyncCopyReadHelper(streamState);
			}
		}

		private static void AsyncCopyStreamReadCallback(IAsyncResult iar)
		{
			AsyncCopyStreamResult asyncCopyStreamResult = (AsyncCopyStreamResult)iar.AsyncState;
			try
			{
				Stream source = asyncCopyStreamResult.Source;
				int num = source.EndRead(iar);
				if (num == 0)
				{
					asyncCopyStreamResult.SetComplete(null, null);
					return;
				}
				if (num < 0)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Stream_UnknownReadError"));
				}
				AsyncCopyWriteHelper(asyncCopyStreamResult, num);
			}
			catch (Exception exception)
			{
				asyncCopyStreamResult.SetComplete(null, exception);
			}
			catch
			{
				asyncCopyStreamResult.SetComplete(null, new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
			}
		}

		private static void AsyncCopyStreamWriteCallback(IAsyncResult iar)
		{
			AsyncCopyStreamResult asyncCopyStreamResult = (AsyncCopyStreamResult)iar.AsyncState;
			try
			{
				asyncCopyStreamResult.Target.EndWrite(iar);
				AsyncCopyReadHelper(asyncCopyStreamResult);
			}
			catch (Exception exception)
			{
				asyncCopyStreamResult.SetComplete(null, exception);
			}
			catch
			{
				asyncCopyStreamResult.SetComplete(null, new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
			}
		}
	}
	internal class AsyncCopyStreamResult : BasicAsyncResult
	{
		internal Stream Source;

		internal Stream Target;

		internal byte[] Buffer;

		internal bool AsyncRead;

		internal bool AsyncWrite;

		internal bool CloseSource;

		internal bool CloseTarget;

		internal AsyncCopyStreamResult(AsyncCallback callback, object state)
			: base(callback, state)
		{
		}

		internal override void CleanupOnComplete()
		{
			if (Buffer != null)
			{
				CoreChannel.BufferPool.ReturnBuffer(Buffer);
			}
			if (CloseSource)
			{
				Source.Close();
			}
			if (CloseTarget)
			{
				Target.Close();
			}
		}
	}
	internal static class StringHelper
	{
		internal static bool StartsWithDoubleUnderscore(string str)
		{
			if (str.Length < 2)
			{
				return false;
			}
			if (str[0] == '_')
			{
				return str[1] == '_';
			}
			return false;
		}

		internal static bool StartsWithAsciiIgnoreCasePrefixLower(string str, string asciiPrefix)
		{
			int length = asciiPrefix.Length;
			if (str.Length < length)
			{
				return false;
			}
			for (int i = 0; i < length; i++)
			{
				if (ToLowerAscii(str[i]) != asciiPrefix[i])
				{
					return false;
				}
			}
			return true;
		}

		private static char ToLowerAscii(char ch)
		{
			if (ch >= 'A' && ch <= 'Z')
			{
				return (char)(ch + 32);
			}
			return ch;
		}
	}
	internal static class NativeMethods
	{
		internal enum TokenInformationClass
		{
			TokenUser = 1,
			TokenGroups,
			TokenPrivileges,
			TokenOwner,
			TokenPrimaryGroup,
			TokenDefaultDacl,
			TokenSource,
			TokenType,
			TokenImpersonationLevel,
			TokenStatistics,
			TokenRestrictedSids,
			TokenSessionId,
			TokenGroupsAndPrivileges,
			TokenSessionReference,
			TokenSandBoxInert
		}

		private const string ADVAPI32 = "advapi32.dll";

		internal const int ThreadTokenAllAccess = 983551;

		internal const int BufferTooSmall = 122;

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool IsValidSid(IntPtr sidPointer);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern IntPtr GetSidIdentifierAuthority(IntPtr sidPointer);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sidPointer);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern IntPtr GetSidSubAuthority(IntPtr sidPointer, int count);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, IntPtr sidAndAttributesPointer, int tokenInformationLength, ref int returnLength);
	}
	public enum SocketCachePolicy
	{
		Default,
		AbsoluteTimeout
	}
	public interface IAuthorizeRemotingConnection
	{
		bool IsConnectingEndPointAuthorized(EndPoint endPoint);

		bool IsConnectingIdentityAuthorized(IIdentity identity);
	}
}
namespace System.Runtime.Remoting.Channels.Http
{
	public class HttpChannel : BaseChannelWithProperties, IChannelReceiver, IChannelSender, IChannel, IChannelReceiverHook, ISecurableChannel
	{
		private static ICollection s_keySet;

		private HttpClientChannel _clientChannel;

		private HttpServerChannel _serverChannel;

		private int _channelPriority = 1;

		private string _channelName = "http";

		private bool _secure;

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (_clientChannel != null)
				{
					return _clientChannel.IsSecured;
				}
				if (_serverChannel != null)
				{
					return _serverChannel.IsSecured;
				}
				return false;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				if (((IList)ChannelServices.RegisteredChannels).Contains((object)this))
				{
					throw new InvalidOperationException(CoreChannel.GetResourceString("Remoting_InvalidOperation_IsSecuredCannotBeChangedOnRegisteredChannels"));
				}
				if (_clientChannel != null)
				{
					_clientChannel.IsSecured = value;
				}
				if (_serverChannel != null)
				{
					_serverChannel.IsSecured = value;
				}
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public object ChannelData
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _serverChannel.ChannelData;
			}
		}

		public string ChannelScheme
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return "http";
			}
		}

		public bool WantsToListen
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _serverChannel.WantsToListen;
			}
			set
			{
				_serverChannel.WantsToListen = value;
			}
		}

		public IServerChannelSink ChannelSinkChain
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _serverChannel.ChannelSinkChain;
			}
		}

		public override IDictionary Properties
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				ArrayList arrayList = new ArrayList(2);
				arrayList.Add(_clientChannel.Properties);
				arrayList.Add(_serverChannel.Properties);
				return new AggregateDictionary(arrayList);
			}
		}

		public override object this[object key]
		{
			get
			{
				if (_clientChannel.Contains(key))
				{
					return _clientChannel[key];
				}
				if (_serverChannel.Contains(key))
				{
					return _serverChannel[key];
				}
				return null;
			}
			set
			{
				if (_clientChannel.Contains(key))
				{
					_clientChannel[key] = value;
				}
				else if (_serverChannel.Contains(key))
				{
					_serverChannel[key] = value;
				}
			}
		}

		public override ICollection Keys
		{
			get
			{
				if (s_keySet == null)
				{
					ICollection keys = _clientChannel.Keys;
					ICollection keys2 = _serverChannel.Keys;
					int capacity = keys.Count + keys2.Count;
					ArrayList arrayList = new ArrayList(capacity);
					foreach (object item in keys)
					{
						arrayList.Add(item);
					}
					foreach (object item2 in keys2)
					{
						arrayList.Add(item2);
					}
					s_keySet = arrayList;
				}
				return s_keySet;
			}
		}

		public HttpChannel()
		{
			_clientChannel = new HttpClientChannel();
			_serverChannel = new HttpServerChannel();
		}

		public HttpChannel(int port)
		{
			_clientChannel = new HttpClientChannel();
			_serverChannel = new HttpServerChannel(port);
		}

		public HttpChannel(IDictionary properties, IClientChannelSinkProvider clientSinkProvider, IServerChannelSinkProvider serverSinkProvider)
		{
			Hashtable hashtable = new Hashtable();
			Hashtable hashtable2 = new Hashtable();
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "priority":
						_channelPriority = Convert.ToInt32((string)property.Value, CultureInfo.InvariantCulture);
						break;
					case "secure":
						_secure = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						hashtable["secure"] = property.Value;
						hashtable2["secure"] = property.Value;
						break;
					default:
						hashtable[property.Key] = property.Value;
						hashtable2[property.Key] = property.Value;
						break;
					}
				}
			}
			_clientChannel = new HttpClientChannel(hashtable, clientSinkProvider);
			_serverChannel = new HttpServerChannel(hashtable2, serverSinkProvider);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return HttpChannelHelper.ParseURL(url, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IMessageSink CreateMessageSink(string url, object remoteChannelData, out string objectURI)
		{
			return _clientChannel.CreateMessageSink(url, remoteChannelData, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string[] GetUrlsForUri(string objectURI)
		{
			return _serverChannel.GetUrlsForUri(objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StartListening(object data)
		{
			_serverChannel.StartListening(data);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StopListening(object data)
		{
			_serverChannel.StopListening(data);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AddHookChannelUri(string channelUri)
		{
			_serverChannel.AddHookChannelUri(channelUri);
		}
	}
	internal class DictionaryEnumeratorByKeys : IDictionaryEnumerator, IEnumerator
	{
		private IDictionary _properties;

		private IEnumerator _keyEnum;

		public object Current => Entry;

		public DictionaryEntry Entry => new DictionaryEntry(Key, Value);

		public object Key => _keyEnum.Current;

		public object Value => _properties[Key];

		public DictionaryEnumeratorByKeys(IDictionary properties)
		{
			_properties = properties;
			_keyEnum = properties.Keys.GetEnumerator();
		}

		public bool MoveNext()
		{
			return _keyEnum.MoveNext();
		}

		public void Reset()
		{
			_keyEnum.Reset();
		}
	}
	internal class AggregateDictionary : IDictionary, ICollection, IEnumerable
	{
		private ICollection _dictionaries;

		public virtual object this[object key]
		{
			get
			{
				foreach (IDictionary dictionary in _dictionaries)
				{
					if (dictionary.Contains(key))
					{
						return dictionary[key];
					}
				}
				return null;
			}
			set
			{
				foreach (IDictionary dictionary in _dictionaries)
				{
					if (dictionary.Contains(key))
					{
						dictionary[key] = value;
					}
				}
			}
		}

		public virtual ICollection Keys
		{
			get
			{
				ArrayList arrayList = new ArrayList();
				foreach (IDictionary dictionary in _dictionaries)
				{
					ICollection keys = dictionary.Keys;
					if (keys == null)
					{
						continue;
					}
					foreach (object item in keys)
					{
						arrayList.Add(item);
					}
				}
				return arrayList;
			}
		}

		public virtual ICollection Values
		{
			get
			{
				ArrayList arrayList = new ArrayList();
				foreach (IDictionary dictionary in _dictionaries)
				{
					ICollection values = dictionary.Values;
					if (values == null)
					{
						continue;
					}
					foreach (object item in values)
					{
						arrayList.Add(item);
					}
				}
				return arrayList;
			}
		}

		public virtual bool IsReadOnly => false;

		public virtual bool IsFixedSize => true;

		public virtual int Count
		{
			get
			{
				int num = 0;
				foreach (IDictionary dictionary in _dictionaries)
				{
					num += dictionary.Count;
				}
				return num;
			}
		}

		public virtual object SyncRoot => this;

		public virtual bool IsSynchronized => false;

		public AggregateDictionary(ICollection dictionaries)
		{
			_dictionaries = dictionaries;
		}

		public virtual bool Contains(object key)
		{
			foreach (IDictionary dictionary in _dictionaries)
			{
				if (dictionary.Contains(key))
				{
					return true;
				}
			}
			return false;
		}

		public virtual void Add(object key, object value)
		{
			throw new NotSupportedException();
		}

		public virtual void Clear()
		{
			throw new NotSupportedException();
		}

		public virtual void Remove(object key)
		{
			throw new NotSupportedException();
		}

		public virtual IDictionaryEnumerator GetEnumerator()
		{
			return new DictionaryEnumeratorByKeys(this);
		}

		public virtual void CopyTo(Array array, int index)
		{
			throw new NotSupportedException();
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return new DictionaryEnumeratorByKeys(this);
		}
	}
	internal static class HttpChannelHelper
	{
		private const string _http = "http://";

		private const string _https = "https://";

		private static char[] s_semicolonSeparator = new char[1] { ';' };

		internal static int StartsWithHttp(string url)
		{
			_ = url.Length;
			if (StringHelper.StartsWithAsciiIgnoreCasePrefixLower(url, "http://"))
			{
				return "http://".Length;
			}
			if (StringHelper.StartsWithAsciiIgnoreCasePrefixLower(url, "https://"))
			{
				return "https://".Length;
			}
			return -1;
		}

		internal static string ParseURL(string url, out string objectURI)
		{
			objectURI = null;
			int num = StartsWithHttp(url);
			if (num == -1)
			{
				return null;
			}
			num = url.IndexOf('/', num);
			if (-1 == num)
			{
				return url;
			}
			string result = url.Substring(0, num);
			objectURI = url.Substring(num);
			return result;
		}

		internal static string GetObjectUriFromRequestUri(string uri)
		{
			int num = 0;
			int num2 = uri.Length;
			num = StartsWithHttp(uri);
			int num3;
			if (num != -1)
			{
				num3 = uri.IndexOf('/', num);
				num = ((num3 == -1) ? num2 : (num3 + 1));
			}
			else
			{
				num = 0;
				if (uri[num] == '/')
				{
					num++;
				}
			}
			num3 = uri.IndexOf('?');
			if (num3 != -1)
			{
				num2 = num3;
			}
			if (num < num2)
			{
				return CoreChannel.RemoveApplicationNameFromUri(uri.Substring(num, num2 - num));
			}
			return "";
		}

		internal static void ParseContentType(string contentType, out string value, out string charset)
		{
			charset = null;
			if (contentType == null)
			{
				value = null;
				return;
			}
			string[] array = contentType.Split(s_semicolonSeparator);
			value = array[0];
			if (array.Length <= 0)
			{
				return;
			}
			string[] array2 = array;
			foreach (string text in array2)
			{
				int num = text.IndexOf('=');
				if (num == -1)
				{
					continue;
				}
				string strA = text.Substring(0, num).Trim();
				if (string.Compare(strA, "charset", StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (num + 1 < text.Length)
					{
						charset = text.Substring(num + 1);
					}
					else
					{
						charset = null;
					}
					break;
				}
			}
		}

		internal static string ReplaceChannelUriWithThisString(string url, string channelUri)
		{
			ParseURL(url, out var objectURI);
			return channelUri + objectURI;
		}

		internal static string ReplaceMachineNameWithThisString(string url, string newMachineName)
		{
			string objectURI;
			string text = ParseURL(url, out objectURI);
			int num = StartsWithHttp(url);
			if (num == -1)
			{
				return url;
			}
			int num2 = text.IndexOf(':', num);
			if (num2 == -1)
			{
				num2 = text.Length;
			}
			return url.Substring(0, num) + newMachineName + url.Substring(num2);
		}

		internal static void DecodeUriInPlace(byte[] uriBytes, out int length)
		{
			int num = 0;
			int num2 = (length = uriBytes.Length);
			int num3 = 0;
			while (num3 < num2)
			{
				if (uriBytes[num3] == 37)
				{
					int num4 = num3 - num * 2;
					uriBytes[num4] = (byte)(16 * CharacterHexDigitToDecimal(uriBytes[num3 + 1]) + CharacterHexDigitToDecimal(uriBytes[num3 + 2]));
					num++;
					length -= 2;
					num3 += 3;
				}
				else
				{
					if (num != 0)
					{
						int num5 = num3 - num * 2;
						uriBytes[num5] = uriBytes[num3];
					}
					num3++;
				}
			}
		}

		internal static int CharacterHexDigitToDecimal(byte b)
		{
			switch (b)
			{
			case 70:
			case 102:
				return 15;
			case 69:
			case 101:
				return 14;
			case 68:
			case 100:
				return 13;
			case 67:
			case 99:
				return 12;
			case 66:
			case 98:
				return 11;
			case 65:
			case 97:
				return 10;
			default:
				return b - 48;
			}
		}

		internal static char DecimalToCharacterHexDigit(int i)
		{
			return i switch
			{
				15 => 'F', 
				14 => 'E', 
				13 => 'D', 
				12 => 'C', 
				11 => 'B', 
				10 => 'A', 
				_ => (char)(i + 48), 
			};
		}
	}
	internal static class HttpEncodingHelper
	{
		internal static string EncodeUriAsXLinkHref(string uri)
		{
			if (uri == null)
			{
				return null;
			}
			byte[] bytes = Encoding.UTF8.GetBytes(uri);
			StringBuilder stringBuilder = new StringBuilder(uri.Length);
			byte[] array = bytes;
			foreach (byte b in array)
			{
				if (!EscapeInXLinkHref(b))
				{
					stringBuilder.Append((char)b);
					continue;
				}
				stringBuilder.Append('%');
				stringBuilder.Append(HttpChannelHelper.DecimalToCharacterHexDigit(b >> 4));
				stringBuilder.Append(HttpChannelHelper.DecimalToCharacterHexDigit(b & 0xF));
			}
			return stringBuilder.ToString();
		}

		internal static bool EscapeInXLinkHref(byte ch)
		{
			if (ch <= 32 || ch >= 128 || ch == 60 || ch == 62 || ch == 34)
			{
				return true;
			}
			return false;
		}

		internal static string DecodeUri(string uri)
		{
			byte[] bytes = Encoding.UTF8.GetBytes(uri);
			HttpChannelHelper.DecodeUriInPlace(bytes, out var length);
			return Encoding.UTF8.GetString(bytes, 0, length);
		}
	}
	public class HttpClientChannel : BaseChannelWithProperties, IChannelSender, IChannel, ISecurableChannel
	{
		private const string ProxyNameKey = "proxyname";

		private const string ProxyPortKey = "proxyport";

		private static ICollection s_keySet;

		private int _channelPriority = 1;

		private string _channelName = "http client";

		private IWebProxy _proxyObject;

		private string _proxyName;

		private int _proxyPort = -1;

		private int _timeout = -1;

		private int _clientConnectionLimit;

		private bool _bUseDefaultCredentials;

		private bool _bAuthenticatedConnectionSharing = true;

		private bool _secure;

		private IClientChannelSinkProvider _sinkProvider;

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _secure;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_secure = value;
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public override object this[object key]
		{
			get
			{
				if (!(key is string text))
				{
					return null;
				}
				return text.ToLower(CultureInfo.InvariantCulture) switch
				{
					"proxyname" => _proxyName, 
					"proxyport" => _proxyPort, 
					_ => null, 
				};
			}
			set
			{
				if (key is string text)
				{
					switch (text.ToLower(CultureInfo.InvariantCulture))
					{
					case "proxyname":
						_proxyName = (string)value;
						UpdateProxy();
						break;
					case "proxyport":
						_proxyPort = Convert.ToInt32(value, CultureInfo.InvariantCulture);
						UpdateProxy();
						break;
					}
				}
			}
		}

		public override ICollection Keys
		{
			get
			{
				if (s_keySet == null)
				{
					ArrayList arrayList = new ArrayList(2);
					arrayList.Add("proxyname");
					arrayList.Add("proxyport");
					s_keySet = arrayList;
				}
				return s_keySet;
			}
		}

		internal IWebProxy ProxyObject => _proxyObject;

		internal bool UseDefaultCredentials
		{
			get
			{
				if (!_secure)
				{
					return _bUseDefaultCredentials;
				}
				return true;
			}
		}

		internal bool UseAuthenticatedConnectionSharing => _bAuthenticatedConnectionSharing;

		public HttpClientChannel()
		{
			SetupChannel();
		}

		public HttpClientChannel(string name, IClientChannelSinkProvider sinkProvider)
		{
			_channelName = name;
			_sinkProvider = sinkProvider;
			SetupChannel();
		}

		public HttpClientChannel(IDictionary properties, IClientChannelSinkProvider sinkProvider)
		{
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "priority":
						_channelPriority = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "proxyName":
						this["proxyName"] = property.Value;
						break;
					case "proxyPort":
						this["proxyPort"] = property.Value;
						break;
					case "timeout":
						_timeout = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "clientConnectionLimit":
						_clientConnectionLimit = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "useDefaultCredentials":
						_bUseDefaultCredentials = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "useAuthenticatedConnectionSharing":
						_bAuthenticatedConnectionSharing = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
			_sinkProvider = sinkProvider;
			SetupChannel();
		}

		private void SetupChannel()
		{
			if (_sinkProvider != null)
			{
				CoreChannel.AppendProviderToClientProviderChain(_sinkProvider, new HttpClientTransportSinkProvider(_timeout));
			}
			else
			{
				_sinkProvider = CreateDefaultClientProviderChain();
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return HttpChannelHelper.ParseURL(url, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public virtual IMessageSink CreateMessageSink(string url, object remoteChannelData, out string objectURI)
		{
			objectURI = null;
			string text = null;
			if (url != null)
			{
				text = Parse(url, out objectURI);
			}
			else if (remoteChannelData != null && remoteChannelData is IChannelDataStore)
			{
				IChannelDataStore channelDataStore = (IChannelDataStore)remoteChannelData;
				string text2 = Parse(channelDataStore.ChannelUris[0], out objectURI);
				if (text2 != null)
				{
					text = channelDataStore.ChannelUris[0];
				}
			}
			if (text != null)
			{
				if (url == null)
				{
					url = text;
				}
				if (_clientConnectionLimit > 0)
				{
					ServicePoint servicePoint = ServicePointManager.FindServicePoint(new Uri(text));
					if (servicePoint.ConnectionLimit < _clientConnectionLimit)
					{
						servicePoint.ConnectionLimit = _clientConnectionLimit;
					}
				}
				IClientChannelSink clientChannelSink = _sinkProvider.CreateSink(this, url, remoteChannelData);
				IMessageSink messageSink = clientChannelSink as IMessageSink;
				if (clientChannelSink != null && messageSink == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Channels_ChannelSinkNotMsgSink"));
				}
				return messageSink;
			}
			return null;
		}

		private IClientChannelSinkProvider CreateDefaultClientProviderChain()
		{
			IClientChannelSinkProvider clientChannelSinkProvider = new SoapClientFormatterSinkProvider();
			IClientChannelSinkProvider clientChannelSinkProvider2 = clientChannelSinkProvider;
			clientChannelSinkProvider2.Next = new HttpClientTransportSinkProvider(_timeout);
			return clientChannelSinkProvider;
		}

		private void UpdateProxy()
		{
			if (_proxyName != null && _proxyName.Length > 0 && _proxyPort > 0)
			{
				WebProxy webProxy = new WebProxy(_proxyName, _proxyPort);
				webProxy.BypassProxyOnLocal = true;
				string[] array2 = (webProxy.BypassList = new string[1] { CoreChannel.GetMachineIp() });
				_proxyObject = webProxy;
			}
			else
			{
				_proxyObject = new WebProxy();
			}
		}
	}
	internal class HttpClientTransportSinkProvider : IClientChannelSinkProvider
	{
		private int _timeout;

		public IClientChannelSinkProvider Next
		{
			get
			{
				return null;
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		internal HttpClientTransportSinkProvider(int timeout)
		{
			_timeout = timeout;
		}

		public IClientChannelSink CreateSink(IChannelSender channel, string url, object remoteChannelData)
		{
			HttpClientTransportSink httpClientTransportSink = new HttpClientTransportSink((HttpClientChannel)channel, url);
			httpClientTransportSink["timeout"] = _timeout;
			return httpClientTransportSink;
		}
	}
	internal class HttpClientTransportSink : BaseChannelSinkWithProperties, IClientChannelSink, IChannelSinkBase
	{
		private class AsyncHttpClientRequestState
		{
			private static AsyncCallback s_processGetRequestStreamCompletionCallback = ProcessGetRequestStreamCompletion;

			private static AsyncCallback s_processAsyncCopyRequestStreamCompletionCallback = ProcessAsyncCopyRequestStreamCompletion;

			private static AsyncCallback s_processGetResponseCompletionCallback = ProcessGetResponseCompletion;

			private static AsyncCallback s_processAsyncCopyRequestStreamCompletion = ProcessAsyncCopyResponseStreamCompletion;

			internal HttpWebRequest WebRequest;

			internal HttpWebResponse WebResponse;

			internal IClientChannelSinkStack SinkStack;

			internal Stream RequestStream;

			internal Stream ActualResponseStream;

			private HttpClientTransportSink _transportSink;

			private int _retryCount;

			private long _initialStreamPosition;

			private IMessage _msg;

			private ITransportHeaders _requestHeaders;

			internal AsyncHttpClientRequestState(HttpClientTransportSink transportSink, IClientChannelSinkStack sinkStack, IMessage msg, ITransportHeaders headers, Stream stream, int retryCount)
			{
				_transportSink = transportSink;
				SinkStack = sinkStack;
				_msg = msg;
				_requestHeaders = headers;
				RequestStream = stream;
				_retryCount = retryCount;
				if (RequestStream.CanSeek)
				{
					_initialStreamPosition = RequestStream.Position;
				}
			}

			internal void StartRequest()
			{
				WebRequest = _transportSink.SetupWebRequest(_msg, _requestHeaders);
				if (!_transportSink._useChunked)
				{
					try
					{
						WebRequest.ContentLength = (int)RequestStream.Length;
					}
					catch
					{
					}
				}
				WebRequest.BeginGetRequestStream(s_processGetRequestStreamCompletionCallback, this);
			}

			internal void RetryOrDispatchException(Exception e)
			{
				bool flag = false;
				try
				{
					if (_retryCount > 0)
					{
						_retryCount--;
						if (RequestStream.CanSeek)
						{
							RequestStream.Position = _initialStreamPosition;
							StartRequest();
							flag = true;
						}
					}
				}
				catch
				{
				}
				if (!flag)
				{
					RequestStream.Close();
					SinkStack.DispatchException(e);
				}
			}

			private static void ProcessGetRequestStreamCompletion(IAsyncResult iar)
			{
				AsyncHttpClientRequestState asyncHttpClientRequestState = (AsyncHttpClientRequestState)iar.AsyncState;
				try
				{
					HttpWebRequest webRequest = asyncHttpClientRequestState.WebRequest;
					Stream requestStream = asyncHttpClientRequestState.RequestStream;
					Stream target = webRequest.EndGetRequestStream(iar);
					StreamHelper.BeginAsyncCopyStream(requestStream, target, asyncRead: false, asyncWrite: true, closeSource: false, closeTarget: true, s_processAsyncCopyRequestStreamCompletionCallback, asyncHttpClientRequestState);
				}
				catch (Exception e)
				{
					asyncHttpClientRequestState.RetryOrDispatchException(e);
				}
				catch
				{
					asyncHttpClientRequestState.RetryOrDispatchException(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
				}
			}

			private static void ProcessAsyncCopyRequestStreamCompletion(IAsyncResult iar)
			{
				AsyncHttpClientRequestState asyncHttpClientRequestState = (AsyncHttpClientRequestState)iar.AsyncState;
				try
				{
					StreamHelper.EndAsyncCopyStream(iar);
					asyncHttpClientRequestState.WebRequest.BeginGetResponse(s_processGetResponseCompletionCallback, asyncHttpClientRequestState);
				}
				catch (Exception e)
				{
					asyncHttpClientRequestState.RetryOrDispatchException(e);
				}
				catch
				{
					asyncHttpClientRequestState.RetryOrDispatchException(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
				}
			}

			private static void ProcessGetResponseCompletion(IAsyncResult iar)
			{
				AsyncHttpClientRequestState asyncHttpClientRequestState = (AsyncHttpClientRequestState)iar.AsyncState;
				try
				{
					asyncHttpClientRequestState.RequestStream.Close();
					HttpWebResponse response = null;
					HttpWebRequest webRequest = asyncHttpClientRequestState.WebRequest;
					try
					{
						response = (HttpWebResponse)webRequest.EndGetResponse(iar);
					}
					catch (WebException webException)
					{
						ProcessResponseException(webException, out response);
					}
					asyncHttpClientRequestState.WebResponse = response;
					StreamHelper.BeginAsyncCopyStream(target: asyncHttpClientRequestState.ActualResponseStream = new ChunkedMemoryStream(CoreChannel.BufferPool), source: response.GetResponseStream(), asyncRead: true, asyncWrite: false, closeSource: true, closeTarget: false, callback: s_processAsyncCopyRequestStreamCompletion, state: asyncHttpClientRequestState);
				}
				catch (Exception e)
				{
					asyncHttpClientRequestState.SinkStack.DispatchException(e);
				}
				catch
				{
					asyncHttpClientRequestState.SinkStack.DispatchException(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
				}
			}

			private static void ProcessAsyncCopyResponseStreamCompletion(IAsyncResult iar)
			{
				AsyncHttpClientRequestState asyncHttpClientRequestState = (AsyncHttpClientRequestState)iar.AsyncState;
				try
				{
					StreamHelper.EndAsyncCopyStream(iar);
					HttpWebResponse webResponse = asyncHttpClientRequestState.WebResponse;
					Stream actualResponseStream = asyncHttpClientRequestState.ActualResponseStream;
					ITransportHeaders headers = CollectResponseHeaders(webResponse);
					asyncHttpClientRequestState.SinkStack.AsyncProcessResponse(headers, actualResponseStream);
				}
				catch (Exception e)
				{
					asyncHttpClientRequestState.SinkStack.DispatchException(e);
				}
				catch
				{
					asyncHttpClientRequestState.SinkStack.DispatchException(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
				}
			}
		}

		private const string s_defaultVerb = "POST";

		private const string UserNameKey = "username";

		private const string PasswordKey = "password";

		private const string DomainKey = "domain";

		private const string PreAuthenticateKey = "preauthenticate";

		private const string CredentialsKey = "credentials";

		private const string ClientCertificatesKey = "clientcertificates";

		private const string ProxyNameKey = "proxyname";

		private const string ProxyPortKey = "proxyport";

		private const string TimeoutKey = "timeout";

		private const string AllowAutoRedirectKey = "allowautoredirect";

		private const string UnsafeAuthenticatedConnectionSharingKey = "unsafeauthenticatedconnectionsharing";

		private const string ConnectionGroupNameKey = "connectiongroupname";

		private static string s_userAgent = string.Concat("Mozilla/4.0+(compatible; MSIE 6.0; Windows ", Environment.OSVersion.Version, "; MS .NET Remoting; MS .NET CLR ", Environment.Version.ToString(), " )");

		private static ICollection s_keySet = null;

		private string _securityUserName;

		private string _securityPassword;

		private string _securityDomain;

		private bool _bSecurityPreAuthenticate;

		private bool _bUnsafeAuthenticatedConnectionSharing;

		private string _connectionGroupName;

		private ICredentials _credentials;

		private X509CertificateCollection _certificates;

		private int _timeout = -1;

		private bool _bAllowAutoRedirect;

		private IWebProxy _proxyObject;

		private string _proxyName;

		private int _proxyPort = -1;

		private static RequestCachePolicy s_requestCachePolicy = new RequestCachePolicy(RequestCacheLevel.BypassCache);

		private HttpClientChannel _channel;

		private string _channelURI;

		private bool _useChunked;

		private bool _useKeepAlive = true;

		public IClientChannelSink NextChannelSink => null;

		public override object this[object key]
		{
			get
			{
				if (!(key is string text))
				{
					return null;
				}
				return text.ToLower(CultureInfo.InvariantCulture) switch
				{
					"username" => _securityUserName, 
					"password" => null, 
					"domain" => _securityDomain, 
					"preauthenticate" => _bSecurityPreAuthenticate, 
					"credentials" => _credentials, 
					"clientcertificates" => null, 
					"proxyname" => _proxyName, 
					"proxyport" => _proxyPort, 
					"timeout" => _timeout, 
					"allowautoredirect" => _bAllowAutoRedirect, 
					"unsafeauthenticatedconnectionsharing" => _bUnsafeAuthenticatedConnectionSharing, 
					"connectiongroupname" => _connectionGroupName, 
					_ => null, 
				};
			}
			set
			{
				if (!(key is string text))
				{
					return;
				}
				switch (text.ToLower(CultureInfo.InvariantCulture))
				{
				case "username":
					_securityUserName = (string)value;
					break;
				case "password":
					_securityPassword = (string)value;
					break;
				case "domain":
					_securityDomain = (string)value;
					break;
				case "preauthenticate":
					_bSecurityPreAuthenticate = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
					break;
				case "credentials":
					_credentials = (ICredentials)value;
					break;
				case "clientcertificates":
					_certificates = (X509CertificateCollection)value;
					break;
				case "proxyname":
					_proxyName = (string)value;
					UpdateProxy();
					break;
				case "proxyport":
					_proxyPort = Convert.ToInt32(value, CultureInfo.InvariantCulture);
					UpdateProxy();
					break;
				case "timeout":
					if (value is TimeSpan)
					{
						_timeout = (int)((TimeSpan)value).TotalMilliseconds;
					}
					else
					{
						_timeout = Convert.ToInt32(value, CultureInfo.InvariantCulture);
					}
					break;
				case "allowautoredirect":
					_bAllowAutoRedirect = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
					break;
				case "unsafeauthenticatedconnectionsharing":
					_bUnsafeAuthenticatedConnectionSharing = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
					break;
				case "connectiongroupname":
					_connectionGroupName = (string)value;
					break;
				}
			}
		}

		public override ICollection Keys
		{
			get
			{
				if (s_keySet == null)
				{
					ArrayList arrayList = new ArrayList(6);
					arrayList.Add("username");
					arrayList.Add("password");
					arrayList.Add("domain");
					arrayList.Add("preauthenticate");
					arrayList.Add("credentials");
					arrayList.Add("clientcertificates");
					arrayList.Add("proxyname");
					arrayList.Add("proxyport");
					arrayList.Add("timeout");
					arrayList.Add("allowautoredirect");
					arrayList.Add("unsafeauthenticatedconnectionsharing");
					arrayList.Add("connectiongroupname");
					s_keySet = arrayList;
				}
				return s_keySet;
			}
		}

		internal static string UserAgent => s_userAgent;

		internal HttpClientTransportSink(HttpClientChannel channel, string channelURI)
		{
			_channel = channel;
			_channelURI = channelURI;
			if (_channelURI.EndsWith("/", StringComparison.Ordinal))
			{
				_channelURI = _channelURI.Substring(0, _channelURI.Length - 1);
			}
		}

		public void ProcessMessage(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			HttpWebRequest httpWebRequest = ProcessAndSend(msg, requestHeaders, requestStream);
			HttpWebResponse response = null;
			try
			{
				response = (HttpWebResponse)httpWebRequest.GetResponse();
			}
			catch (WebException webException)
			{
				ProcessResponseException(webException, out response);
			}
			ReceiveAndProcess(response, out responseHeaders, out responseStream);
		}

		public void AsyncProcessRequest(IClientChannelSinkStack sinkStack, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			AsyncHttpClientRequestState asyncHttpClientRequestState = new AsyncHttpClientRequestState(this, sinkStack, msg, headers, stream, 1);
			asyncHttpClientRequestState.StartRequest();
		}

		private static void ProcessResponseException(WebException webException, out HttpWebResponse response)
		{
			if (webException.Status == WebExceptionStatus.Timeout)
			{
				throw new RemotingTimeoutException(CoreChannel.GetResourceString("Remoting_Channels_RequestTimedOut"), webException);
			}
			response = webException.Response as HttpWebResponse;
			if (response == null)
			{
				throw webException;
			}
			int statusCode = (int)response.StatusCode;
			if (statusCode < 500 || statusCode > 599)
			{
				throw webException;
			}
		}

		public void AsyncProcessResponse(IClientResponseChannelSinkStack sinkStack, object state, ITransportHeaders headers, Stream stream)
		{
		}

		public Stream GetRequestStream(IMessage msg, ITransportHeaders headers)
		{
			return null;
		}

		private HttpWebRequest SetupWebRequest(IMessage msg, ITransportHeaders headers)
		{
			IMethodCallMessage methodCallMessage = msg as IMethodCallMessage;
			string text = (string)headers["__RequestUri"];
			if (text == null)
			{
				text = ((methodCallMessage == null) ? ((string)msg.Properties["__Uri"]) : methodCallMessage.Uri);
			}
			string requestUriString;
			if (HttpChannelHelper.StartsWithHttp(text) != -1)
			{
				requestUriString = text;
			}
			else
			{
				if (!text.StartsWith("/", StringComparison.Ordinal))
				{
					text = "/" + text;
				}
				requestUriString = _channelURI + text;
			}
			string text2 = (string)headers["__RequestVerb"];
			if (text2 == null)
			{
				text2 = "POST";
			}
			HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(requestUriString);
			httpWebRequest.AllowAutoRedirect = _bAllowAutoRedirect;
			httpWebRequest.Method = text2;
			httpWebRequest.SendChunked = _useChunked;
			httpWebRequest.KeepAlive = _useKeepAlive;
			httpWebRequest.Pipelined = false;
			httpWebRequest.UserAgent = s_userAgent;
			httpWebRequest.Timeout = _timeout;
			httpWebRequest.CachePolicy = s_requestCachePolicy;
			IWebProxy proxyObject = _proxyObject;
			if (proxyObject == null)
			{
				proxyObject = _channel.ProxyObject;
			}
			if (proxyObject != null)
			{
				httpWebRequest.Proxy = proxyObject;
			}
			if (_credentials != null)
			{
				httpWebRequest.Credentials = _credentials;
				httpWebRequest.PreAuthenticate = _bSecurityPreAuthenticate;
				httpWebRequest.UnsafeAuthenticatedConnectionSharing = _bUnsafeAuthenticatedConnectionSharing;
				if (_connectionGroupName != null)
				{
					httpWebRequest.ConnectionGroupName = _connectionGroupName;
				}
			}
			else if (_securityUserName != null)
			{
				if (_securityDomain == null)
				{
					httpWebRequest.Credentials = new NetworkCredential(_securityUserName, _securityPassword);
				}
				else
				{
					httpWebRequest.Credentials = new NetworkCredential(_securityUserName, _securityPassword, _securityDomain);
				}
				httpWebRequest.PreAuthenticate = _bSecurityPreAuthenticate;
				httpWebRequest.UnsafeAuthenticatedConnectionSharing = _bUnsafeAuthenticatedConnectionSharing;
				if (_connectionGroupName != null)
				{
					httpWebRequest.ConnectionGroupName = _connectionGroupName;
				}
			}
			else if (_channel.UseDefaultCredentials)
			{
				if (_channel.UseAuthenticatedConnectionSharing)
				{
					httpWebRequest.ConnectionGroupName = CoreChannel.GetCurrentSidString();
					httpWebRequest.UnsafeAuthenticatedConnectionSharing = true;
				}
				httpWebRequest.Credentials = CredentialCache.DefaultCredentials;
				httpWebRequest.PreAuthenticate = _bSecurityPreAuthenticate;
			}
			if (_certificates != null)
			{
				foreach (X509Certificate certificate in _certificates)
				{
					httpWebRequest.ClientCertificates.Add(certificate);
				}
				httpWebRequest.PreAuthenticate = _bSecurityPreAuthenticate;
			}
			foreach (DictionaryEntry header in headers)
			{
				if (header.Key is string text3 && !text3.StartsWith("__", StringComparison.Ordinal))
				{
					if (text3.Equals("Content-Type"))
					{
						httpWebRequest.ContentType = header.Value.ToString();
					}
					else
					{
						httpWebRequest.Headers[text3] = header.Value.ToString();
					}
				}
			}
			return httpWebRequest;
		}

		private HttpWebRequest ProcessAndSend(IMessage msg, ITransportHeaders headers, Stream inputStream)
		{
			long position = 0L;
			bool flag = false;
			if (inputStream != null)
			{
				flag = inputStream.CanSeek;
				if (flag)
				{
					position = inputStream.Position;
				}
			}
			HttpWebRequest httpWebRequest = null;
			Stream stream = null;
			try
			{
				httpWebRequest = SetupWebRequest(msg, headers);
				if (inputStream != null)
				{
					if (!_useChunked)
					{
						httpWebRequest.ContentLength = (int)inputStream.Length;
					}
					stream = httpWebRequest.GetRequestStream();
					StreamHelper.CopyStream(inputStream, stream);
				}
			}
			catch
			{
				if (flag)
				{
					httpWebRequest = SetupWebRequest(msg, headers);
					if (inputStream != null)
					{
						inputStream.Position = position;
						if (!_useChunked)
						{
							httpWebRequest.ContentLength = (int)inputStream.Length;
						}
						stream = httpWebRequest.GetRequestStream();
						StreamHelper.CopyStream(inputStream, stream);
					}
				}
			}
			inputStream?.Close();
			stream?.Close();
			return httpWebRequest;
		}

		private void ReceiveAndProcess(HttpWebResponse response, out ITransportHeaders returnHeaders, out Stream returnStream)
		{
			int bufferSize;
			if (response == null)
			{
				bufferSize = 4096;
			}
			else
			{
				int num = (int)response.ContentLength;
				bufferSize = ((num == -1 || num == 0) ? 4096 : ((num > 16000) ? 16000 : num));
			}
			returnStream = new BufferedStream(response.GetResponseStream(), bufferSize);
			returnHeaders = CollectResponseHeaders(response);
		}

		private static ITransportHeaders CollectResponseHeaders(HttpWebResponse response)
		{
			TransportHeaders transportHeaders = new TransportHeaders();
			foreach (object header in response.Headers)
			{
				string text = header.ToString();
				transportHeaders[text] = response.Headers[text];
			}
			return transportHeaders;
		}

		private void UpdateProxy()
		{
			if (_proxyName != null && _proxyPort > 0)
			{
				WebProxy webProxy = new WebProxy(_proxyName, _proxyPort);
				webProxy.BypassProxyOnLocal = true;
				_proxyObject = webProxy;
			}
		}
	}
	public class HttpServerChannel : BaseChannelWithProperties, IChannelReceiver, IChannel, IChannelReceiverHook
	{
		private int _channelPriority = 1;

		private string _channelName = "http server";

		private string _machineName;

		private int _port = -1;

		private ChannelDataStore _channelData;

		private string _forcedMachineName;

		private bool _bUseIpAddress = true;

		private IPAddress _bindToAddr = (Socket.SupportsIPv4 ? IPAddress.Any : IPAddress.IPv6Any);

		private bool _bSuppressChannelData;

		private IServerChannelSinkProvider _sinkProvider;

		private HttpServerTransportSink _transportSink;

		private IServerChannelSink _sinkChain;

		private bool _wantsToListen = true;

		private bool _bHooked;

		private ExclusiveTcpListener _tcpListener;

		private bool _bExclusiveAddressUse = true;

		private Thread _listenerThread;

		private bool _bListening;

		private Exception _startListeningException;

		private AutoResetEvent _waitForStartListening = new AutoResetEvent(initialState: false);

		internal bool IsSecured
		{
			get
			{
				return false;
			}
			set
			{
				if (_port >= 0 && value)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_UseIISToSecureHttpServer"));
				}
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public object ChannelData
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (!_bSuppressChannelData && (_bListening || _bHooked))
				{
					return _channelData;
				}
				return null;
			}
		}

		public string ChannelScheme
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure)]
			get
			{
				return "http";
			}
		}

		public bool WantsToListen
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _wantsToListen;
			}
			set
			{
				_wantsToListen = value;
			}
		}

		public IServerChannelSink ChannelSinkChain
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure)]
			get
			{
				return _sinkChain;
			}
		}

		public override object this[object key]
		{
			get
			{
				return null;
			}
			set
			{
			}
		}

		public override ICollection Keys => new ArrayList();

		public HttpServerChannel()
		{
			SetupMachineName();
			SetupChannel();
		}

		public HttpServerChannel(int port)
		{
			_port = port;
			SetupMachineName();
			SetupChannel();
		}

		public HttpServerChannel(string name, int port)
		{
			_channelName = name;
			_port = port;
			SetupMachineName();
			SetupChannel();
		}

		public HttpServerChannel(string name, int port, IServerChannelSinkProvider sinkProvider)
		{
			_channelName = name;
			_port = port;
			_sinkProvider = sinkProvider;
			SetupMachineName();
			SetupChannel();
		}

		public HttpServerChannel(IDictionary properties, IServerChannelSinkProvider sinkProvider)
		{
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "bindTo":
						_bindToAddr = IPAddress.Parse((string)property.Value);
						break;
					case "listen":
						_wantsToListen = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "machineName":
						_forcedMachineName = (string)property.Value;
						break;
					case "port":
						_port = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "priority":
						_channelPriority = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "suppressChannelData":
						_bSuppressChannelData = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "useIpAddress":
						_bUseIpAddress = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "exclusiveAddressUse":
						_bExclusiveAddressUse = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
			_sinkProvider = sinkProvider;
			SetupMachineName();
			SetupChannel();
		}

		private void SetupMachineName()
		{
			if (_forcedMachineName != null)
			{
				_machineName = CoreChannel.DecodeMachineName(_forcedMachineName);
				return;
			}
			if (!_bUseIpAddress)
			{
				_machineName = CoreChannel.GetMachineName();
				return;
			}
			if (_bindToAddr == IPAddress.Any || _bindToAddr == IPAddress.IPv6Any)
			{
				_machineName = CoreChannel.GetMachineIp();
			}
			else
			{
				_machineName = _bindToAddr.ToString();
			}
			if (_bindToAddr.AddressFamily == AddressFamily.InterNetworkV6)
			{
				_machineName = "[" + _machineName + "]";
			}
		}

		private void SetupChannel()
		{
			_channelData = new ChannelDataStore(null);
			if (_port > 0)
			{
				string channelUri = GetChannelUri();
				_channelData.ChannelUris = new string[1];
				_channelData.ChannelUris[0] = channelUri;
				_wantsToListen = false;
			}
			if (_sinkProvider == null)
			{
				_sinkProvider = CreateDefaultServerProviderChain();
			}
			CoreChannel.CollectChannelDataFromServerSinkProviders(_channelData, _sinkProvider);
			_sinkChain = ChannelServices.CreateServerChannelSinkChain(_sinkProvider, this);
			_transportSink = new HttpServerTransportSink(_sinkChain);
			SinksWithProperties = _sinkChain;
			if (_port >= 0)
			{
				_tcpListener = new ExclusiveTcpListener(_bindToAddr, _port);
				ThreadStart start = Listen;
				_listenerThread = new Thread(start);
				_listenerThread.IsBackground = true;
				StartListening(null);
			}
		}

		private IServerChannelSinkProvider CreateDefaultServerProviderChain()
		{
			IServerChannelSinkProvider serverChannelSinkProvider = new SdlChannelSinkProvider();
			IServerChannelSinkProvider serverChannelSinkProvider2 = serverChannelSinkProvider;
			serverChannelSinkProvider2.Next = new SoapServerFormatterSinkProvider();
			serverChannelSinkProvider2 = serverChannelSinkProvider2.Next;
			serverChannelSinkProvider2.Next = new BinaryServerFormatterSinkProvider();
			return serverChannelSinkProvider;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return HttpChannelHelper.ParseURL(url, out objectURI);
		}

		public string GetChannelUri()
		{
			if (_channelData != null && _channelData.ChannelUris != null)
			{
				return _channelData.ChannelUris[0];
			}
			return "http://" + _machineName + ":" + _port;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public virtual string[] GetUrlsForUri(string objectUri)
		{
			string[] array = new string[1];
			if (!objectUri.StartsWith("/", StringComparison.Ordinal))
			{
				objectUri = "/" + objectUri;
			}
			array[0] = GetChannelUri() + objectUri;
			return array;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StartListening(object data)
		{
			if (_port < 0 || _listenerThread.IsAlive)
			{
				return;
			}
			_listenerThread.Start();
			_waitForStartListening.WaitOne();
			if (_startListeningException != null)
			{
				Exception startListeningException = _startListeningException;
				_startListeningException = null;
				throw startListeningException;
			}
			_bListening = true;
			if (_port == 0)
			{
				_port = ((IPEndPoint)_tcpListener.LocalEndpoint).Port;
				if (_channelData != null)
				{
					string channelUri = GetChannelUri();
					_channelData.ChannelUris = new string[1];
					_channelData.ChannelUris[0] = channelUri;
				}
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StopListening(object data)
		{
			if (_port > 0)
			{
				_bListening = false;
				if (_tcpListener != null)
				{
					_tcpListener.Stop();
				}
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AddHookChannelUri(string channelUri)
		{
			if (_channelData.ChannelUris != null)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_LimitListenerOfOne"));
			}
			if (_forcedMachineName != null)
			{
				channelUri = HttpChannelHelper.ReplaceMachineNameWithThisString(channelUri, _forcedMachineName);
			}
			else if (_bUseIpAddress)
			{
				channelUri = HttpChannelHelper.ReplaceMachineNameWithThisString(channelUri, CoreChannel.GetMachineIp());
			}
			_channelData.ChannelUris = new string[1] { channelUri };
			_wantsToListen = false;
			_bHooked = true;
		}

		private void Listen()
		{
			bool flag = false;
			try
			{
				_tcpListener.Start(_bExclusiveAddressUse);
				flag = true;
			}
			catch (Exception startListeningException)
			{
				Exception ex = (_startListeningException = startListeningException);
			}
			catch
			{
				_startListeningException = new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException"));
			}
			_waitForStartListening.Set();
			while (flag)
			{
				try
				{
					Socket socket = _tcpListener.AcceptSocket();
					if (socket == null)
					{
						throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Socket_Accept"), Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture)));
					}
					socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.Debug, 1);
					socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, 1);
					LingerOption optionValue = new LingerOption(enable: true, 3);
					socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Linger, optionValue);
					Stream stream = new SocketStream(socket);
					HttpServerSocketHandler httpServerSocketHandler = null;
					httpServerSocketHandler = new HttpServerSocketHandler(socket, CoreChannel.RequestQueue, stream);
					httpServerSocketHandler.DataArrivedCallback = _transportSink.ServiceRequest;
					httpServerSocketHandler.BeginReadMessage();
				}
				catch (Exception ex2)
				{
					if (!_bListening)
					{
						flag = false;
					}
					else
					{
						_ = ex2 is SocketException;
					}
				}
				catch
				{
					if (!_bListening)
					{
						flag = false;
					}
				}
			}
		}
	}
	internal class HttpServerTransportSink : IServerChannelSink, IChannelSinkBase
	{
		private static string s_serverHeader = "MS .NET Remoting, MS .NET CLR " + Environment.Version.ToString();

		private IServerChannelSink _nextSink;

		public IServerChannelSink NextChannelSink => _nextSink;

		public IDictionary Properties => null;

		internal static string ServerHeader => s_serverHeader;

		public HttpServerTransportSink(IServerChannelSink nextSink)
		{
			_nextSink = nextSink;
		}

		internal void ServiceRequest(object state)
		{
			HttpServerSocketHandler httpServerSocketHandler = (HttpServerSocketHandler)state;
			ITransportHeaders transportHeaders = httpServerSocketHandler.ReadHeaders();
			Stream requestStream = httpServerSocketHandler.GetRequestStream();
			transportHeaders["__CustomErrorsEnabled"] = httpServerSocketHandler.CustomErrorsEnabled();
			ServerChannelSinkStack serverChannelSinkStack = new ServerChannelSinkStack();
			serverChannelSinkStack.Push(this, httpServerSocketHandler);
			IMessage responseMsg;
			ITransportHeaders responseHeaders;
			Stream responseStream;
			ServerProcessing serverProcessing = _nextSink.ProcessMessage(serverChannelSinkStack, null, transportHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
			switch (serverProcessing)
			{
			case ServerProcessing.Complete:
				serverChannelSinkStack.Pop(this);
				httpServerSocketHandler.SendResponse(responseStream, "200", "OK", responseHeaders);
				break;
			case ServerProcessing.OneWay:
				httpServerSocketHandler.SendResponse(null, "202", "Accepted", responseHeaders);
				break;
			case ServerProcessing.Async:
				serverChannelSinkStack.StoreAndDispatch(this, httpServerSocketHandler);
				break;
			}
			if (serverProcessing != ServerProcessing.Async)
			{
				if (httpServerSocketHandler.CanServiceAnotherRequest())
				{
					httpServerSocketHandler.BeginReadMessage();
				}
				else
				{
					httpServerSocketHandler.Close();
				}
			}
		}

		public ServerProcessing ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, out IMessage responseMsg, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			throw new NotSupportedException();
		}

		public void AsyncProcessResponse(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			HttpServerSocketHandler httpServerSocketHandler = null;
			httpServerSocketHandler = (HttpServerSocketHandler)state;
			httpServerSocketHandler.SendResponse(stream, "200", "OK", headers);
			if (httpServerSocketHandler.CanServiceAnotherRequest())
			{
				httpServerSocketHandler.BeginReadMessage();
			}
			else
			{
				httpServerSocketHandler.Close();
			}
		}

		public Stream GetResponseStream(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers)
		{
			HttpServerSocketHandler httpServerSocketHandler = (HttpServerSocketHandler)state;
			if (httpServerSocketHandler.AllowChunkedResponse)
			{
				return httpServerSocketHandler.GetResponseStream("200", "OK", headers);
			}
			return null;
		}
	}
	internal class ErrorMessage : IMethodCallMessage, IMethodMessage, IMessage
	{
		private string m_URI = "Exception";

		private string m_MethodName = "Unknown";

		private string m_TypeName = "Unknown";

		private object m_MethodSignature;

		private int m_ArgCount;

		private string m_ArgName = "Unknown";

		public IDictionary Properties => null;

		public string Uri => m_URI;

		public string MethodName => m_MethodName;

		public string TypeName => m_TypeName;

		public object MethodSignature => m_MethodSignature;

		public MethodBase MethodBase => null;

		public int ArgCount => m_ArgCount;

		public object[] Args => null;

		public bool HasVarArgs => false;

		public LogicalCallContext LogicalCallContext => null;

		public int InArgCount => m_ArgCount;

		public object[] InArgs => null;

		public string GetArgName(int index)
		{
			return m_ArgName;
		}

		public object GetArg(int argNum)
		{
			return null;
		}

		public string GetInArgName(int index)
		{
			return null;
		}

		public object GetInArg(int argNum)
		{
			return null;
		}
	}
	internal abstract class HttpSocketHandler : SocketHandler
	{
		private static byte[] s_httpVersion = Encoding.ASCII.GetBytes("HTTP/1.1");

		private static byte[] s_httpVersionAndSpace = Encoding.ASCII.GetBytes("HTTP/1.1 ");

		private static byte[] s_headerSeparator = new byte[2] { 58, 32 };

		private static byte[] s_endOfLine = new byte[2] { 13, 10 };

		public HttpSocketHandler(Socket socket, RequestQueue requestQueue, Stream stream)
			: base(socket, requestQueue, stream)
		{
		}

		protected void ReadToEndOfHeaders(BaseTransportHeaders headers, out bool bChunked, out int contentLength, ref bool bKeepAlive, ref bool bSendContinue)
		{
			bChunked = false;
			contentLength = 0;
			while (true)
			{
				string text = ReadToEndOfLine();
				if (text.Length == 0)
				{
					break;
				}
				int num = text.IndexOf(":");
				string text2 = text.Substring(0, num);
				string text3 = text.Substring(num + 1 + 1);
				if (string.Compare(text2, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (string.Compare(text3, "chunked", StringComparison.OrdinalIgnoreCase) == 0)
					{
						bChunked = true;
					}
				}
				else if (string.Compare(text2, "Connection", StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (string.Compare(text3, "Keep-Alive", StringComparison.OrdinalIgnoreCase) == 0)
					{
						bKeepAlive = true;
					}
					else if (string.Compare(text3, "Close", StringComparison.OrdinalIgnoreCase) == 0)
					{
						bKeepAlive = false;
					}
				}
				else if (string.Compare(text2, "Expect", StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (string.Compare(text3, "100-continue", StringComparison.OrdinalIgnoreCase) == 0)
					{
						bSendContinue = true;
					}
				}
				else if (string.Compare(text2, "Content-Length", StringComparison.OrdinalIgnoreCase) == 0)
				{
					contentLength = int.Parse(text3, CultureInfo.InvariantCulture);
				}
				else
				{
					headers[text2] = text3;
				}
			}
		}

		protected void WriteHeaders(ITransportHeaders headers, Stream outputStream)
		{
			if (headers == null)
			{
				return;
			}
			foreach (DictionaryEntry header in headers)
			{
				string text = (string)header.Key;
				if (!text.StartsWith("__", StringComparison.Ordinal))
				{
					WriteHeader(text, (string)header.Value, outputStream);
				}
			}
			outputStream.Write(s_endOfLine, 0, s_endOfLine.Length);
		}

		private void WriteHeader(string name, string value, Stream outputStream)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(name);
			byte[] bytes2 = Encoding.ASCII.GetBytes(value);
			outputStream.Write(bytes, 0, bytes.Length);
			outputStream.Write(s_headerSeparator, 0, s_headerSeparator.Length);
			outputStream.Write(bytes2, 0, bytes2.Length);
			outputStream.Write(s_endOfLine, 0, s_endOfLine.Length);
		}

		protected void WriteResponseFirstLine(string statusCode, string reasonPhrase, Stream outputStream)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(statusCode);
			byte[] bytes2 = Encoding.ASCII.GetBytes(reasonPhrase);
			outputStream.Write(s_httpVersionAndSpace, 0, s_httpVersionAndSpace.Length);
			outputStream.Write(bytes, 0, bytes.Length);
			outputStream.WriteByte(32);
			outputStream.Write(bytes2, 0, bytes2.Length);
			outputStream.Write(s_endOfLine, 0, s_endOfLine.Length);
		}
	}
	internal abstract class HttpServerResponseStream : Stream
	{
		public override bool CanRead => false;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override long Position
		{
			get
			{
				throw new NotSupportedException();
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}
	}
	internal sealed class HttpFixedLengthResponseStream : HttpServerResponseStream
	{
		private Stream _outputStream;

		private static int _length;

		internal HttpFixedLengthResponseStream(Stream outputStream, int length)
		{
			_outputStream = outputStream;
			_length = length;
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing)
				{
					_outputStream.Flush();
				}
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override void Flush()
		{
			_outputStream.Flush();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			_outputStream.Write(buffer, offset, count);
		}

		public override void WriteByte(byte value)
		{
			_outputStream.WriteByte(value);
		}
	}
	internal sealed class HttpChunkedResponseStream : HttpServerResponseStream
	{
		private static byte[] _trailer = Encoding.ASCII.GetBytes("0\r\n\r\n");

		private static byte[] _endChunk = Encoding.ASCII.GetBytes("\r\n");

		private Stream _outputStream;

		private byte[] _chunk;

		private int _chunkSize;

		private int _chunkOffset;

		private byte[] _byteBuffer = new byte[1];

		internal HttpChunkedResponseStream(Stream outputStream)
		{
			_outputStream = outputStream;
			_chunk = CoreChannel.BufferPool.GetBuffer();
			_chunkSize = _chunk.Length - 2;
			_chunkOffset = 0;
			_chunk[_chunkSize - 2] = 13;
			_chunk[_chunkSize - 1] = 10;
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing)
				{
					if (_chunkOffset > 0)
					{
						FlushChunk();
					}
					_outputStream.Write(_trailer, 0, _trailer.Length);
					_outputStream.Flush();
				}
				CoreChannel.BufferPool.ReturnBuffer(_chunk);
				_chunk = null;
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override void Flush()
		{
			if (_chunkOffset > 0)
			{
				FlushChunk();
			}
			_outputStream.Flush();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			while (count > 0)
			{
				if (_chunkOffset == 0 && count >= _chunkSize)
				{
					WriteChunk(buffer, offset, count);
					break;
				}
				int num = Math.Min(_chunkSize - _chunkOffset, count);
				Array.Copy(buffer, offset, _chunk, _chunkOffset, num);
				_chunkOffset += num;
				count -= num;
				offset += num;
				if (_chunkOffset == _chunkSize)
				{
					FlushChunk();
				}
			}
		}

		public override void WriteByte(byte value)
		{
			_byteBuffer[0] = value;
			Write(_byteBuffer, 0, 1);
		}

		private void FlushChunk()
		{
			WriteChunk(_chunk, 0, _chunkOffset);
			_chunkOffset = 0;
		}

		private void WriteChunk(byte[] buffer, int offset, int count)
		{
			byte[] array = IntToHexChars(count);
			_outputStream.Write(array, 0, array.Length);
			if (buffer == _chunk)
			{
				_outputStream.Write(_chunk, offset, count + 2);
				return;
			}
			_outputStream.Write(buffer, offset, count);
			_outputStream.Write(_endChunk, 0, _endChunk.Length);
		}

		private byte[] IntToHexChars(int i)
		{
			string text = "";
			while (i > 0)
			{
				int num = i % 16;
				text = num switch
				{
					15 => 'F' + text, 
					14 => 'E' + text, 
					13 => 'D' + text, 
					12 => 'C' + text, 
					11 => 'B' + text, 
					10 => 'A' + text, 
					_ => (char)(num + 48) + text, 
				};
				i /= 16;
			}
			text += "\r\n";
			return Encoding.ASCII.GetBytes(text);
		}
	}
	internal abstract class HttpReadingStream : Stream
	{
		public virtual bool FoundEnd => false;

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => false;

		public override long Length
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override long Position
		{
			get
			{
				throw new NotSupportedException();
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public virtual bool ReadToEnd()
		{
			byte[] buffer = new byte[16];
			int num = 0;
			do
			{
				num = Read(buffer, 0, 16);
			}
			while (num > 0);
			return num == 0;
		}

		public override void Flush()
		{
			throw new NotSupportedException();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}
	}
	internal sealed class HttpFixedLengthReadingStream : HttpReadingStream
	{
		private HttpSocketHandler _inputStream;

		private int _bytesLeft;

		public override bool FoundEnd => _bytesLeft == 0;

		internal HttpFixedLengthReadingStream(HttpSocketHandler inputStream, int contentLength)
		{
			_inputStream = inputStream;
			_bytesLeft = contentLength;
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			if (_bytesLeft == 0)
			{
				return 0;
			}
			int num = _inputStream.Read(buffer, offset, Math.Min(_bytesLeft, count));
			if (num > 0)
			{
				_bytesLeft -= num;
			}
			return num;
		}

		public override int ReadByte()
		{
			if (_bytesLeft == 0)
			{
				return -1;
			}
			_bytesLeft--;
			return _inputStream.ReadByte();
		}
	}
	internal sealed class HttpChunkedReadingStream : HttpReadingStream
	{
		private static byte[] _trailer = Encoding.ASCII.GetBytes("0\r\n\r\n\r\n");

		private static byte[] _endChunk = Encoding.ASCII.GetBytes("\r\n");

		private HttpSocketHandler _inputStream;

		private int _bytesLeft;

		private bool _bFoundEnd;

		private byte[] _byteBuffer = new byte[1];

		public override bool FoundEnd => _bFoundEnd;

		internal HttpChunkedReadingStream(HttpSocketHandler inputStream)
		{
			_inputStream = inputStream;
			_bytesLeft = 0;
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			int num = 0;
			while (!_bFoundEnd && count > 0)
			{
				if (_bytesLeft == 0)
				{
					while (true)
					{
						byte b = (byte)_inputStream.ReadByte();
						if (b == 13)
						{
							break;
						}
						int num2 = HttpChannelHelper.CharacterHexDigitToDecimal(b);
						if (num2 < 0 || num2 > 15)
						{
							throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_ChunkedEncodingError"));
						}
						_bytesLeft = _bytesLeft * 16 + num2;
					}
					if ((ushort)_inputStream.ReadByte() != 10)
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_ChunkedEncodingError"));
					}
					if (_bytesLeft == 0)
					{
						string text;
						do
						{
							text = _inputStream.ReadToEndOfLine();
						}
						while (text.Length != 0);
						_bFoundEnd = true;
					}
				}
				if (_bFoundEnd)
				{
					continue;
				}
				int count2 = Math.Min(_bytesLeft, count);
				int num3 = _inputStream.Read(buffer, offset, count2);
				if (num3 <= 0)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_ChunkedEncodingError"));
				}
				_bytesLeft -= num3;
				count -= num3;
				offset += num3;
				num += num3;
				if (_bytesLeft == 0)
				{
					char c = (char)_inputStream.ReadByte();
					if (c != '\r')
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_ChunkedEncodingError"));
					}
					c = (char)_inputStream.ReadByte();
					if (c != '\n')
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_ChunkedEncodingError"));
					}
				}
			}
			return num;
		}

		public override int ReadByte()
		{
			if (Read(_byteBuffer, 0, 1) == 0)
			{
				return -1;
			}
			return _byteBuffer[0];
		}
	}
	[Serializable]
	internal enum HttpVersion
	{
		V1_0,
		V1_1
	}
	internal sealed class HttpServerSocketHandler : HttpSocketHandler
	{
		private static ValidateByteDelegate s_validateVerbDelegate = ValidateVerbCharacter;

		private static long _connectionIdCounter = 0L;

		private static byte[] _bufferhttpContinue = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");

		private HttpReadingStream _requestStream;

		private HttpServerResponseStream _responseStream;

		private long _connectionId;

		private HttpVersion _version;

		private int _contentLength;

		private bool _chunkedEncoding;

		private bool _keepAlive;

		public bool AllowChunkedResponse => false;

		internal HttpServerSocketHandler(Socket socket, RequestQueue requestQueue, Stream stream)
			: base(socket, requestQueue, stream)
		{
			_connectionId = Interlocked.Increment(ref _connectionIdCounter);
		}

		public bool CanServiceAnotherRequest()
		{
			if (_keepAlive && _requestStream != null && (_requestStream.FoundEnd || _requestStream.ReadToEnd()))
			{
				return true;
			}
			return false;
		}

		protected override void PrepareForNewMessage()
		{
			_requestStream = null;
			_responseStream = null;
			_contentLength = 0;
			_chunkedEncoding = false;
			_keepAlive = false;
		}

		private string GenerateFaultString(Exception e)
		{
			if (!CustomErrorsEnabled())
			{
				return e.ToString();
			}
			return CoreChannel.GetResourceString("Remoting_InternalError");
		}

		protected override void SendErrorMessageIfPossible(Exception e)
		{
			if (_responseStream == null && !(e is SocketException))
			{
				Stream stream = new MemoryStream();
				StreamWriter streamWriter = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
				streamWriter.WriteLine(GenerateFaultString(e));
				streamWriter.Flush();
				SendResponse(stream, "500", CoreChannel.GetResourceString("Remoting_InternalError"), null);
			}
		}

		private static bool ValidateVerbCharacter(byte b)
		{
			if (char.IsLetter((char)b) || b == 45)
			{
				return true;
			}
			return false;
		}

		public BaseTransportHeaders ReadHeaders()
		{
			bool bSendContinue = false;
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			ReadFirstLine(out var verb, out var requestURI, out var version);
			if (verb == null || requestURI == null || version == null)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_UnableToReadFirstLine"));
			}
			if (version.Equals("HTTP/1.1"))
			{
				_version = HttpVersion.V1_1;
			}
			else if (version.Equals("HTTP/1.0"))
			{
				_version = HttpVersion.V1_0;
			}
			else
			{
				_version = HttpVersion.V1_1;
			}
			if (_version == HttpVersion.V1_1)
			{
				_keepAlive = true;
			}
			else
			{
				_keepAlive = false;
			}
			string objectURI;
			string text = HttpChannelHelper.ParseURL(requestURI, out objectURI);
			if (text == null)
			{
				objectURI = requestURI;
			}
			baseTransportHeaders["__RequestVerb"] = verb;
			baseTransportHeaders.RequestUri = objectURI;
			baseTransportHeaders["__HttpVersion"] = version;
			if (_version == HttpVersion.V1_1 && (verb.Equals("POST") || verb.Equals("PUT")))
			{
				bSendContinue = true;
			}
			ReadToEndOfHeaders(baseTransportHeaders, out _chunkedEncoding, out _contentLength, ref _keepAlive, ref bSendContinue);
			if (bSendContinue && _version != 0)
			{
				SendContinue();
			}
			baseTransportHeaders["__IPAddress"] = ((IPEndPoint)NetSocket.RemoteEndPoint).Address;
			baseTransportHeaders["__ConnectionId"] = _connectionId;
			return baseTransportHeaders;
		}

		public Stream GetRequestStream()
		{
			if (_chunkedEncoding)
			{
				_requestStream = new HttpChunkedReadingStream(this);
			}
			else
			{
				_requestStream = new HttpFixedLengthReadingStream(this, _contentLength);
			}
			return _requestStream;
		}

		public Stream GetResponseStream(string statusCode, string reasonPhrase, ITransportHeaders headers)
		{
			bool flag = false;
			bool flag2 = false;
			int length = 0;
			object obj = headers["__HttpStatusCode"];
			string text = headers["__HttpReasonPhrase"] as string;
			if (obj != null)
			{
				statusCode = obj.ToString();
			}
			if (text != null)
			{
				reasonPhrase = text;
			}
			if (!CanServiceAnotherRequest())
			{
				headers["Connection"] = "Close";
			}
			object obj2 = headers["Content-Length"];
			if (obj2 != null)
			{
				flag = true;
				length = ((!(obj2 is int)) ? Convert.ToInt32(obj2, CultureInfo.InvariantCulture) : ((int)obj2));
			}
			flag2 = AllowChunkedResponse && !flag;
			if (flag2)
			{
				headers["Transfer-Encoding"] = "chunked";
			}
			ChunkedMemoryStream chunkedMemoryStream = new ChunkedMemoryStream(CoreChannel.BufferPool);
			WriteResponseFirstLine(statusCode, reasonPhrase, chunkedMemoryStream);
			WriteHeaders(headers, chunkedMemoryStream);
			chunkedMemoryStream.WriteTo(NetStream);
			chunkedMemoryStream.Close();
			if (flag2)
			{
				_responseStream = new HttpChunkedResponseStream(NetStream);
			}
			else
			{
				_responseStream = new HttpFixedLengthResponseStream(NetStream, length);
			}
			return _responseStream;
		}

		private bool ReadFirstLine(out string verb, out string requestURI, out string version)
		{
			verb = null;
			requestURI = null;
			version = null;
			verb = ReadToChar(' ', s_validateVerbDelegate);
			byte[] array = ReadToByte(32);
			HttpChannelHelper.DecodeUriInPlace(array, out var length);
			requestURI = Encoding.UTF8.GetString(array, 0, length);
			version = ReadToEndOfLine();
			return true;
		}

		private void SendContinue()
		{
			NetStream.Write(_bufferhttpContinue, 0, _bufferhttpContinue.Length);
		}

		public void SendResponse(Stream httpContentStream, string statusCode, string reasonPhrase, ITransportHeaders headers)
		{
			if (_responseStream != null)
			{
				_responseStream.Close();
				if (_responseStream != httpContentStream)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Http_WrongResponseStream"));
				}
				_responseStream = null;
				return;
			}
			if (headers == null)
			{
				headers = new TransportHeaders();
			}
			string text = (string)headers["Server"];
			text = (string)(headers["Server"] = ((text == null) ? HttpServerTransportSink.ServerHeader : (HttpServerTransportSink.ServerHeader + ", " + text)));
			if (!AllowChunkedResponse && httpContentStream != null)
			{
				headers["Content-Length"] = httpContentStream.Length.ToString(CultureInfo.InvariantCulture);
			}
			else if (httpContentStream == null)
			{
				headers["Content-Length"] = "0";
			}
			GetResponseStream(statusCode, reasonPhrase, headers);
			if (httpContentStream != null)
			{
				StreamHelper.CopyStream(httpContentStream, _responseStream);
				_responseStream.Close();
				httpContentStream.Close();
			}
			_responseStream = null;
		}
	}
	public class HttpRemotingHandler : IHttpHandler
	{
		private static string ApplicationConfigurationFile = "web.config";

		private static bool bLoadedConfiguration = false;

		private static HttpHandlerTransportSink s_transportSink = null;

		private static Exception s_fatalException = null;

		public bool IsReusable => true;

		public HttpRemotingHandler()
		{
		}

		public HttpRemotingHandler(Type type, object srvID)
		{
		}

		public void ProcessRequest(HttpContext context)
		{
			InternalProcessRequest(context);
		}

		private void InternalProcessRequest(HttpContext context)
		{
			try
			{
				HttpRequest request = context.Request;
				if (!bLoadedConfiguration)
				{
					lock (ApplicationConfigurationFile)
					{
						if (!bLoadedConfiguration)
						{
							IisHelper.Initialize();
							if (RemotingConfiguration.ApplicationName == null)
							{
								RemotingConfiguration.ApplicationName = request.ApplicationPath;
							}
							string text = request.PhysicalApplicationPath + ApplicationConfigurationFile;
							if (File.Exists(text))
							{
								try
								{
									RemotingConfiguration.Configure(text, ensureSecurity: false);
								}
								catch (Exception ex)
								{
									WriteException(context, s_fatalException = ex);
									return;
								}
								catch
								{
									WriteException(context, s_fatalException = new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
									return;
								}
							}
							try
							{
								IChannelReceiverHook channelReceiverHook = null;
								IChannel[] registeredChannels = ChannelServices.RegisteredChannels;
								IChannel[] array = registeredChannels;
								foreach (IChannel channel in array)
								{
									if (channel is IChannelReceiverHook channelReceiverHook2 && string.Compare(channelReceiverHook2.ChannelScheme, "http", StringComparison.OrdinalIgnoreCase) == 0 && channelReceiverHook2.WantsToListen)
									{
										channelReceiverHook = channelReceiverHook2;
										break;
									}
								}
								if (channelReceiverHook == null)
								{
									HttpChannel httpChannel = new HttpChannel();
									ChannelServices.RegisterChannel(httpChannel, ensureSecurity: false);
									channelReceiverHook = httpChannel;
								}
								string text2 = null;
								text2 = ((!IisHelper.IsSslRequired) ? "http" : "https");
								string text3 = text2 + "://" + CoreChannel.GetMachineIp();
								int port = context.Request.Url.Port;
								string text4 = ":" + port + "/" + RemotingConfiguration.ApplicationName;
								text3 += text4;
								channelReceiverHook.AddHookChannelUri(text3);
								if (((IChannelReceiver)channelReceiverHook).ChannelData is ChannelDataStore channelDataStore)
								{
									text3 = channelDataStore.ChannelUris[0];
								}
								IisHelper.ApplicationUrl = text3;
								ChannelServices.UnregisterChannel(null);
								s_transportSink = new HttpHandlerTransportSink(channelReceiverHook.ChannelSinkChain);
							}
							catch (Exception ex2)
							{
								WriteException(context, s_fatalException = ex2);
								return;
							}
							catch
							{
								WriteException(context, s_fatalException = new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
								return;
							}
							bLoadedConfiguration = true;
						}
					}
				}
				if (s_fatalException == null)
				{
					if (!CanServiceRequest(context))
					{
						WriteException(context, new RemotingException(CoreChannel.GetResourceString("Remoting_ChnlSink_UriNotPublished")));
					}
					else
					{
						s_transportSink.HandleRequest(context);
					}
				}
				else
				{
					WriteException(context, s_fatalException);
				}
			}
			catch (Exception e)
			{
				WriteException(context, e);
			}
			catch
			{
				WriteException(context, new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
			}
		}

		private string ComposeContentType(string contentType, Encoding encoding)
		{
			if (encoding != null)
			{
				StringBuilder stringBuilder = new StringBuilder(contentType);
				stringBuilder.Append("; charset=");
				stringBuilder.Append(encoding.WebName);
				return stringBuilder.ToString();
			}
			return contentType;
		}

		private bool CanServiceRequest(HttpContext context)
		{
			string text = GetRequestUriForCurrentRequest(context);
			string objectUriFromRequestUri = HttpChannelHelper.GetObjectUriFromRequestUri(text);
			context.Items["__requestUri"] = text;
			if (string.Compare(context.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase) != 0)
			{
				if (RemotingServices.GetServerTypeForUri(text) != null)
				{
					return true;
				}
			}
			else
			{
				if (context.Request.QueryString.Count != 1)
				{
					return false;
				}
				string[] values = context.Request.QueryString.GetValues(0);
				if (values.Length != 1 || string.Compare(values[0], "wsdl", StringComparison.OrdinalIgnoreCase) != 0)
				{
					return false;
				}
				if (string.Compare(objectUriFromRequestUri, "RemoteApplicationMetadata.rem", StringComparison.OrdinalIgnoreCase) == 0)
				{
					return true;
				}
				int num = text.LastIndexOf('?');
				if (num != -1)
				{
					text = text.Substring(0, num);
				}
				if (RemotingServices.GetServerTypeForUri(text) != null)
				{
					return true;
				}
			}
			if (File.Exists(context.Request.PhysicalPath))
			{
				return true;
			}
			return false;
		}

		private string GetRequestUriForCurrentRequest(HttpContext context)
		{
			string rawUrl = context.Request.RawUrl;
			string objectURI;
			string text = HttpChannelHelper.ParseURL(rawUrl, out objectURI);
			if (text == null)
			{
				objectURI = rawUrl;
			}
			string applicationName = RemotingConfiguration.ApplicationName;
			if (applicationName != null && applicationName.Length > 0 && objectURI.Length > applicationName.Length)
			{
				objectURI = objectURI.Substring(applicationName.Length + 1);
			}
			return objectURI;
		}

		private string GenerateFaultString(HttpContext context, Exception e)
		{
			if (!CustomErrorsEnabled(context))
			{
				return e.ToString();
			}
			return CoreChannel.GetResourceString("Remoting_InternalError");
		}

		private void WriteException(HttpContext context, Exception e)
		{
			Stream outputStream = context.Response.OutputStream;
			context.Response.Clear();
			context.Response.ClearHeaders();
			context.Response.ContentType = ComposeContentType("text/plain", Encoding.UTF8);
			SetHttpResponseStatusCode(context.Response, 500);
			context.Response.StatusDescription = CoreChannel.GetResourceString("Remoting_InternalError");
			StreamWriter streamWriter = new StreamWriter(outputStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			streamWriter.WriteLine(GenerateFaultString(context, e));
			streamWriter.Flush();
		}

		internal static bool IsLocal(HttpContext context)
		{
			string text = context.Request.ServerVariables["LOCAL_ADDR"];
			string userHostAddress = context.Request.UserHostAddress;
			if (!context.Request.Url.IsLoopback)
			{
				if (text != null && userHostAddress != null)
				{
					return text == userHostAddress;
				}
				return false;
			}
			return true;
		}

		internal static bool CustomErrorsEnabled(HttpContext context)
		{
			try
			{
				if (!context.IsCustomErrorEnabled)
				{
					return false;
				}
				return RemotingConfiguration.CustomErrorsEnabled(IsLocal(context));
			}
			catch
			{
				return true;
			}
		}

		internal static void SetHttpResponseStatusCode(HttpResponse httpResponse, int statusCode)
		{
			httpResponse.TrySkipIisCustomErrors = true;
			httpResponse.StatusCode = statusCode;
		}
	}
	public class HttpRemotingHandlerFactory : IHttpHandlerFactory
	{
		internal object _webServicesFactory;

		internal static Type s_webServicesFactoryType = null;

		internal static object s_configLock = new object();

		internal static Hashtable s_registeredDynamicTypeTable = Hashtable.Synchronized(new Hashtable());

		private IHttpHandlerFactory WebServicesFactory
		{
			get
			{
				if (_webServicesFactory == null)
				{
					lock (this)
					{
						if (_webServicesFactory == null)
						{
							_webServicesFactory = Activator.CreateInstance(WebServicesFactoryType);
						}
					}
				}
				return (IHttpHandlerFactory)_webServicesFactory;
			}
		}

		private static Type WebServicesFactoryType
		{
			get
			{
				if (s_webServicesFactoryType == null)
				{
					Assembly assembly = Assembly.Load("System.Web.Services, Version=2.0.0.0, Culture=neutral, PublicKeyToken= b03f5f7f11d50a3a");
					if (assembly == null)
					{
						throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_AssemblyLoadFailed"), "System.Web.Services"));
					}
					s_webServicesFactoryType = assembly.GetType("System.Web.Services.Protocols.WebServiceHandlerFactory");
				}
				return s_webServicesFactoryType;
			}
		}

		private void DumpRequest(HttpContext context)
		{
			_ = context.Request;
		}

		private void ConfigureAppName(HttpRequest httpRequest)
		{
			if (RemotingConfiguration.ApplicationName != null)
			{
				return;
			}
			lock (s_configLock)
			{
				if (RemotingConfiguration.ApplicationName == null)
				{
					RemotingConfiguration.ApplicationName = httpRequest.ApplicationPath;
				}
			}
		}

		public IHttpHandler GetHandler(HttpContext context, string verb, string url, string filePath)
		{
			DumpRequest(context);
			HttpRequest request = context.Request;
			ConfigureAppName(request);
			string text = request.QueryString[null];
			bool flag = string.Compare(request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase) == 0;
			bool flag2 = File.Exists(request.PhysicalPath);
			if (flag && flag2 && text == null)
			{
				return WebServicesFactory.GetHandler(context, verb, url, filePath);
			}
			if (flag2)
			{
				Type compiledType = WebServiceParser.GetCompiledType(url, context);
				string machineAndAppName = Dns.GetHostName() + request.ApplicationPath;
				string[] array = request.PhysicalPath.Split('\\');
				string text2 = array[array.Length - 1];
				Type type = (Type)s_registeredDynamicTypeTable[text2];
				if (type != compiledType)
				{
					RegistrationHelper.RegisterType(machineAndAppName, compiledType, text2);
					s_registeredDynamicTypeTable[text2] = compiledType;
				}
				return new HttpRemotingHandler();
			}
			return new HttpRemotingHandler();
		}

		public void ReleaseHandler(IHttpHandler handler)
		{
			if (_webServicesFactory != null)
			{
				((IHttpHandlerFactory)_webServicesFactory).ReleaseHandler(handler);
				_webServicesFactory = null;
			}
		}
	}
	internal static class RegistrationHelper
	{
		public static void RegisterType(string machineAndAppName, Type type, string uri)
		{
			RemotingConfiguration.RegisterWellKnownServiceType(type, uri, WellKnownObjectMode.SingleCall);
			Type[] types = type.Assembly.GetTypes();
			Type[] array = types;
			foreach (Type type2 in array)
			{
				RegisterSingleType(machineAndAppName, type2);
			}
		}

		private static void RegisterSingleType(string machineAndAppName, Type type)
		{
			string name = type.Name;
			string text = "http://" + machineAndAppName + "/" + type.FullName;
			SoapServices.RegisterInteropXmlElement(name, text, type);
			SoapServices.RegisterInteropXmlType(name, text, type);
			if (typeof(MarshalByRefObject).IsAssignableFrom(type))
			{
				MethodInfo[] methods = type.GetMethods();
				MethodInfo[] array = methods;
				foreach (MethodInfo methodInfo in array)
				{
					SoapServices.RegisterSoapActionForMethodBase(methodInfo, text + "#" + methodInfo.Name);
				}
			}
		}
	}
	internal class HttpHandlerTransportSink : IServerChannelSink, IChannelSinkBase
	{
		private const int _defaultChunkSize = 2048;

		public IServerChannelSink _nextSink;

		public IServerChannelSink NextChannelSink => _nextSink;

		public IDictionary Properties => null;

		public HttpHandlerTransportSink(IServerChannelSink nextSink)
		{
			_nextSink = nextSink;
		}

		public void HandleRequest(HttpContext context)
		{
			HttpRequest request = context.Request;
			HttpResponse response = context.Response;
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			baseTransportHeaders["__RequestVerb"] = request.HttpMethod;
			baseTransportHeaders["__CustomErrorsEnabled"] = HttpRemotingHandler.CustomErrorsEnabled(context);
			baseTransportHeaders.RequestUri = (string)context.Items["__requestUri"];
			NameValueCollection headers = request.Headers;
			string[] allKeys = headers.AllKeys;
			foreach (string text in allKeys)
			{
				string text3 = (string)(baseTransportHeaders[text] = headers[text]);
			}
			baseTransportHeaders.IPAddress = IPAddress.Parse(request.UserHostAddress);
			Stream inputStream = request.InputStream;
			ServerChannelSinkStack serverChannelSinkStack = new ServerChannelSinkStack();
			serverChannelSinkStack.Push(this, null);
			IMessage responseMsg;
			ITransportHeaders responseHeaders;
			Stream responseStream;
			switch (_nextSink.ProcessMessage(serverChannelSinkStack, null, baseTransportHeaders, inputStream, out responseMsg, out responseHeaders, out responseStream))
			{
			case ServerProcessing.Complete:
				SendResponse(response, 200, responseHeaders, responseStream);
				break;
			case ServerProcessing.OneWay:
				SendResponse(response, 202, responseHeaders, responseStream);
				break;
			case ServerProcessing.Async:
				break;
			}
		}

		private void SendResponse(HttpResponse httpResponse, int statusCode, ITransportHeaders responseHeaders, Stream httpContentStream)
		{
			if (responseHeaders != null)
			{
				string text = (string)responseHeaders["Server"];
				text = (string)(responseHeaders["Server"] = ((text == null) ? HttpServerTransportSink.ServerHeader : (HttpServerTransportSink.ServerHeader + ", " + text)));
				object obj2 = responseHeaders["__HttpStatusCode"];
				if (obj2 != null)
				{
					statusCode = Convert.ToInt32(obj2, CultureInfo.InvariantCulture);
				}
				if (httpContentStream != null)
				{
					int num = -1;
					try
					{
						if (httpContentStream != null)
						{
							num = (int)httpContentStream.Length;
						}
					}
					catch
					{
					}
					if (num != -1)
					{
						responseHeaders["Content-Length"] = num;
					}
				}
				else
				{
					responseHeaders["Content-Length"] = 0;
				}
				foreach (DictionaryEntry responseHeader in responseHeaders)
				{
					string text2 = (string)responseHeader.Key;
					if (!text2.StartsWith("__", StringComparison.Ordinal))
					{
						httpResponse.AppendHeader(text2, responseHeader.Value.ToString());
					}
				}
			}
			HttpRemotingHandler.SetHttpResponseStatusCode(httpResponse, statusCode);
			Stream outputStream = httpResponse.OutputStream;
			if (httpContentStream != null)
			{
				StreamHelper.CopyStream(httpContentStream, outputStream);
				httpContentStream.Close();
			}
		}

		public ServerProcessing ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, out IMessage responseMsg, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			throw new NotSupportedException();
		}

		public void AsyncProcessResponse(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			throw new NotSupportedException();
		}

		public Stream GetResponseStream(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers)
		{
			return null;
		}
	}
}
namespace System.Runtime.Remoting.Channels.Tcp
{
	public class TcpChannel : IChannelReceiver, IChannelSender, IChannel, ISecurableChannel
	{
		private TcpClientChannel _clientChannel;

		private TcpServerChannel _serverChannel;

		private int _channelPriority = 1;

		private string _channelName = "tcp";

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (_clientChannel != null)
				{
					return _clientChannel.IsSecured;
				}
				if (_serverChannel != null)
				{
					return _serverChannel.IsSecured;
				}
				return false;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				if (((IList)ChannelServices.RegisteredChannels).Contains((object)this))
				{
					throw new InvalidOperationException(CoreChannel.GetResourceString("Remoting_InvalidOperation_IsSecuredCannotBeChangedOnRegisteredChannels"));
				}
				if (_clientChannel != null)
				{
					_clientChannel.IsSecured = value;
				}
				if (_serverChannel != null)
				{
					_serverChannel.IsSecured = value;
				}
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public object ChannelData
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (_serverChannel != null)
				{
					return _serverChannel.ChannelData;
				}
				return null;
			}
		}

		public TcpChannel()
		{
			_clientChannel = new TcpClientChannel();
		}

		public TcpChannel(int port)
			: this()
		{
			_serverChannel = new TcpServerChannel(port);
		}

		public TcpChannel(IDictionary properties, IClientChannelSinkProvider clientSinkProvider, IServerChannelSinkProvider serverSinkProvider)
		{
			Hashtable hashtable = new Hashtable();
			Hashtable hashtable2 = new Hashtable();
			bool flag = false;
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "priority":
						_channelPriority = Convert.ToInt32((string)property.Value, CultureInfo.InvariantCulture);
						break;
					case "port":
						hashtable2["port"] = property.Value;
						flag = true;
						break;
					default:
						hashtable[property.Key] = property.Value;
						hashtable2[property.Key] = property.Value;
						break;
					}
				}
			}
			_clientChannel = new TcpClientChannel(hashtable, clientSinkProvider);
			if (flag)
			{
				_serverChannel = new TcpServerChannel(hashtable2, serverSinkProvider);
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return TcpChannelHelper.ParseURL(url, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IMessageSink CreateMessageSink(string url, object remoteChannelData, out string objectURI)
		{
			return _clientChannel.CreateMessageSink(url, remoteChannelData, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string[] GetUrlsForUri(string objectURI)
		{
			if (_serverChannel != null)
			{
				return _serverChannel.GetUrlsForUri(objectURI);
			}
			return null;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StartListening(object data)
		{
			if (_serverChannel != null)
			{
				_serverChannel.StartListening(data);
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StopListening(object data)
		{
			if (_serverChannel != null)
			{
				_serverChannel.StopListening(data);
			}
		}
	}
	internal static class TcpChannelHelper
	{
		private const string _tcp = "tcp://";

		internal static string ParseURL(string url, out string objectURI)
		{
			objectURI = null;
			if (StringHelper.StartsWithAsciiIgnoreCasePrefixLower(url, "tcp://"))
			{
				int length = "tcp://".Length;
				length = url.IndexOf('/', length);
				if (-1 == length)
				{
					return url;
				}
				string result = url.Substring(0, length);
				objectURI = url.Substring(length);
				return result;
			}
			return null;
		}
	}
	public class TcpClientChannel : IChannelSender, IChannel, ISecurableChannel
	{
		private int _channelPriority = 1;

		private string _channelName = "tcp";

		private bool _secure;

		private IDictionary _prop;

		private IClientChannelSinkProvider _sinkProvider;

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _secure;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_secure = value;
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public TcpClientChannel()
		{
			SetupChannel();
		}

		public TcpClientChannel(string name, IClientChannelSinkProvider sinkProvider)
		{
			_channelName = name;
			_sinkProvider = sinkProvider;
			SetupChannel();
		}

		public TcpClientChannel(IDictionary properties, IClientChannelSinkProvider sinkProvider)
		{
			if (properties != null)
			{
				_prop = properties;
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "priority":
						_channelPriority = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "secure":
						_secure = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
			_sinkProvider = sinkProvider;
			SetupChannel();
		}

		private void SetupChannel()
		{
			if (_sinkProvider != null)
			{
				CoreChannel.AppendProviderToClientProviderChain(_sinkProvider, new TcpClientTransportSinkProvider(_prop));
			}
			else
			{
				_sinkProvider = CreateDefaultClientProviderChain();
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return TcpChannelHelper.ParseURL(url, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public virtual IMessageSink CreateMessageSink(string url, object remoteChannelData, out string objectURI)
		{
			objectURI = null;
			string text = null;
			if (url != null)
			{
				text = Parse(url, out objectURI);
			}
			else if (remoteChannelData != null && remoteChannelData is IChannelDataStore)
			{
				IChannelDataStore channelDataStore = (IChannelDataStore)remoteChannelData;
				string text2 = Parse(channelDataStore.ChannelUris[0], out objectURI);
				if (text2 != null)
				{
					text = channelDataStore.ChannelUris[0];
				}
			}
			if (text != null)
			{
				if (url == null)
				{
					url = text;
				}
				IClientChannelSink clientChannelSink = _sinkProvider.CreateSink(this, url, remoteChannelData);
				IMessageSink messageSink = clientChannelSink as IMessageSink;
				if (clientChannelSink != null && messageSink == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Channels_ChannelSinkNotMsgSink"));
				}
				return messageSink;
			}
			return null;
		}

		private IClientChannelSinkProvider CreateDefaultClientProviderChain()
		{
			IClientChannelSinkProvider clientChannelSinkProvider = new BinaryClientFormatterSinkProvider();
			IClientChannelSinkProvider clientChannelSinkProvider2 = clientChannelSinkProvider;
			clientChannelSinkProvider2.Next = new TcpClientTransportSinkProvider(_prop);
			return clientChannelSinkProvider;
		}
	}
	internal class TcpClientTransportSinkProvider : IClientChannelSinkProvider
	{
		private IDictionary _prop;

		public IClientChannelSinkProvider Next
		{
			get
			{
				return null;
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		internal TcpClientTransportSinkProvider(IDictionary properties)
		{
			_prop = properties;
		}

		public IClientChannelSink CreateSink(IChannelSender channel, string url, object remoteChannelData)
		{
			TcpClientTransportSink tcpClientTransportSink = new TcpClientTransportSink(url, (TcpClientChannel)channel);
			if (_prop != null)
			{
				foreach (object key in _prop.Keys)
				{
					tcpClientTransportSink[key] = _prop[key];
				}
				return tcpClientTransportSink;
			}
			return tcpClientTransportSink;
		}
	}
	internal class TcpClientTransportSink : BaseChannelSinkWithProperties, IClientChannelSink, IChannelSinkBase
	{
		private const string UserNameKey = "username";

		private const string PasswordKey = "password";

		private const string DomainKey = "domain";

		private const string ProtectionLevelKey = "protectionlevel";

		private const string ConnectionGroupNameKey = "connectiongroupname";

		private const string TokenImpersonationLevelKey = "tokenimpersonationlevel";

		private const string SocketCacheTimeoutKey = "socketcachetimeout";

		private const string ReceiveTimeoutKey = "timeout";

		private const string SocketCachePolicyKey = "socketcachepolicy";

		private const string SPNKey = "serviceprincipalname";

		private const string RetryCountKey = "retrycount";

		internal SocketCache ClientSocketCache;

		private bool authSet;

		private string m_machineName;

		private int m_port;

		private TcpClientChannel _channel;

		private string _machineAndPort;

		private string _securityUserName;

		private string _securityPassword;

		private string _securityDomain;

		private string _connectionGroupName;

		private TimeSpan _socketCacheTimeout = TimeSpan.FromSeconds(10.0);

		private int _receiveTimeout;

		private SocketCachePolicy _socketCachePolicy;

		private string _spn = string.Empty;

		private int _retryCount = 1;

		private TokenImpersonationLevel _tokenImpersonationLevel = TokenImpersonationLevel.Identification;

		private ProtectionLevel _protectionLevel = ProtectionLevel.EncryptAndSign;

		private static ICollection s_keySet;

		public IClientChannelSink NextChannelSink => null;

		public override object this[object key]
		{
			get
			{
				if (!(key is string text))
				{
					return null;
				}
				switch (text.ToLower(CultureInfo.InvariantCulture))
				{
				case "username":
					return _securityUserName;
				case "password":
					return null;
				case "domain":
					return _securityDomain;
				case "socketcachetimeout":
					return _socketCacheTimeout;
				case "timeout":
					return _receiveTimeout;
				case "socketcachepolicy":
					return _socketCachePolicy.ToString();
				case "retrycount":
					return _retryCount;
				case "connectiongroupname":
					return _connectionGroupName;
				case "tokenimpersonationlevel":
					if (authSet)
					{
						return _tokenImpersonationLevel.ToString();
					}
					break;
				case "protectionlevel":
					if (authSet)
					{
						return _protectionLevel.ToString();
					}
					break;
				}
				return null;
			}
			set
			{
				if (!(key is string text))
				{
					return;
				}
				switch (text.ToLower(CultureInfo.InvariantCulture))
				{
				case "username":
					_securityUserName = (string)value;
					break;
				case "password":
					_securityPassword = (string)value;
					break;
				case "domain":
					_securityDomain = (string)value;
					break;
				case "socketcachetimeout":
				{
					int num = Convert.ToInt32(value, CultureInfo.InvariantCulture);
					if (num < 0)
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_SocketTimeoutNegative"));
					}
					_socketCacheTimeout = TimeSpan.FromSeconds(num);
					ClientSocketCache.SocketTimeout = _socketCacheTimeout;
					break;
				}
				case "timeout":
					_receiveTimeout = Convert.ToInt32(value, CultureInfo.InvariantCulture);
					ClientSocketCache.ReceiveTimeout = _receiveTimeout;
					break;
				case "socketcachepolicy":
					_socketCachePolicy = (SocketCachePolicy)((value is SocketCachePolicy) ? value : Enum.Parse(typeof(SocketCachePolicy), (string)value, ignoreCase: true));
					ClientSocketCache.CachePolicy = _socketCachePolicy;
					break;
				case "retrycount":
					_retryCount = Convert.ToInt32(value, CultureInfo.InvariantCulture);
					break;
				case "connectiongroupname":
					_connectionGroupName = (string)value;
					break;
				case "tokenimpersonationlevel":
					_tokenImpersonationLevel = (TokenImpersonationLevel)((value is TokenImpersonationLevel) ? value : Enum.Parse(typeof(TokenImpersonationLevel), (string)value, ignoreCase: true));
					authSet = true;
					break;
				case "protectionlevel":
					_protectionLevel = (ProtectionLevel)((value is ProtectionLevel) ? value : Enum.Parse(typeof(ProtectionLevel), (string)value, ignoreCase: true));
					authSet = true;
					break;
				case "serviceprincipalname":
					_spn = (string)value;
					authSet = true;
					break;
				}
			}
		}

		public override ICollection Keys
		{
			get
			{
				if (s_keySet == null)
				{
					ArrayList arrayList = new ArrayList(6);
					arrayList.Add("username");
					arrayList.Add("password");
					arrayList.Add("domain");
					arrayList.Add("socketcachetimeout");
					arrayList.Add("socketcachepolicy");
					arrayList.Add("retrycount");
					arrayList.Add("tokenimpersonationlevel");
					arrayList.Add("protectionlevel");
					arrayList.Add("connectiongroupname");
					arrayList.Add("timeout");
					s_keySet = arrayList;
				}
				return s_keySet;
			}
		}

		private SocketHandler CreateSocketHandler(Socket socket, SocketCache socketCache, string machinePortAndSid)
		{
			Stream stream = new SocketStream(socket);
			if (_channel.IsSecured)
			{
				stream = CreateAuthenticatedStream(stream, machinePortAndSid);
			}
			return new TcpClientSocketHandler(socket, machinePortAndSid, stream, this);
		}

		private Stream CreateAuthenticatedStream(Stream netStream, string machinePortAndSid)
		{
			NetworkCredential networkCredential = null;
			NegotiateStream negotiateStream = null;
			networkCredential = ((_securityUserName == null) ? ((NetworkCredential)CredentialCache.DefaultCredentials) : new NetworkCredential(_securityUserName, _securityPassword, _securityDomain));
			try
			{
				negotiateStream = new NegotiateStream(netStream);
				negotiateStream.AuthenticateAsClient(networkCredential, _spn, _protectionLevel, _tokenImpersonationLevel);
				return negotiateStream;
			}
			catch (IOException innerException)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_AuthenticationFailed")), innerException);
			}
		}

		private string GetSid()
		{
			if (_connectionGroupName != null)
			{
				return _connectionGroupName;
			}
			return CoreChannel.GetCurrentSidString();
		}

		internal TcpClientTransportSink(string channelURI, TcpClientChannel channel)
		{
			_channel = channel;
			string objectURI;
			string uriString = TcpChannelHelper.ParseURL(channelURI, out objectURI);
			ClientSocketCache = new SocketCache(CreateSocketHandler, _socketCachePolicy, _socketCacheTimeout);
			Uri uri = new Uri(uriString);
			if (uri.IsDefaultPort)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_UrlMustHavePort"), channelURI));
			}
			m_machineName = uri.Host;
			IPAddress address = null;
			IPAddress.TryParse(m_machineName, out address);
			if (address != null && (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal))
			{
				m_machineName = "[" + uri.DnsSafeHost + "]";
			}
			m_port = uri.Port;
			_machineAndPort = m_machineName + ":" + m_port;
		}

		public void ProcessMessage(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			TcpClientSocketHandler tcpClientSocketHandler = SendRequestWithRetry(msg, requestHeaders, requestStream);
			responseHeaders = tcpClientSocketHandler.ReadHeaders();
			responseStream = tcpClientSocketHandler.GetResponseStream();
		}

		public void AsyncProcessRequest(IClientChannelSinkStack sinkStack, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			TcpClientSocketHandler tcpClientSocketHandler = SendRequestWithRetry(msg, headers, stream);
			if (tcpClientSocketHandler.OneWayRequest)
			{
				tcpClientSocketHandler.ReturnToCache();
				return;
			}
			tcpClientSocketHandler.DataArrivedCallback = ReceiveCallback;
			tcpClientSocketHandler.DataArrivedCallbackState = sinkStack;
			tcpClientSocketHandler.BeginReadMessage();
		}

		public void AsyncProcessResponse(IClientResponseChannelSinkStack sinkStack, object state, ITransportHeaders headers, Stream stream)
		{
			throw new NotSupportedException();
		}

		public Stream GetRequestStream(IMessage msg, ITransportHeaders headers)
		{
			return null;
		}

		private TcpClientSocketHandler SendRequestWithRetry(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream)
		{
			long position = 0L;
			bool flag = true;
			bool canSeek = requestStream.CanSeek;
			if (canSeek)
			{
				position = requestStream.Position;
			}
			TcpClientSocketHandler tcpClientSocketHandler = null;
			string machinePortAndSid = _machineAndPort + (_channel.IsSecured ? ("/" + GetSid()) : null);
			if (authSet && !_channel.IsSecured)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_AuthenticationConfigClient"));
			}
			bool openNew = _channel.IsSecured && _securityUserName != null && _connectionGroupName == null;
			try
			{
				tcpClientSocketHandler = (TcpClientSocketHandler)ClientSocketCache.GetSocket(machinePortAndSid, openNew);
				tcpClientSocketHandler.SendRequest(msg, requestHeaders, requestStream);
			}
			catch (SocketException)
			{
				for (int i = 0; i < _retryCount; i++)
				{
					if (!canSeek)
					{
						break;
					}
					if (!flag)
					{
						break;
					}
					try
					{
						requestStream.Position = position;
						tcpClientSocketHandler = (TcpClientSocketHandler)ClientSocketCache.GetSocket(machinePortAndSid, openNew);
						tcpClientSocketHandler.SendRequest(msg, requestHeaders, requestStream);
						flag = false;
					}
					catch (SocketException)
					{
					}
				}
				if (flag)
				{
					throw;
				}
			}
			requestStream.Close();
			return tcpClientSocketHandler;
		}

		private void ReceiveCallback(object state)
		{
			TcpClientSocketHandler tcpClientSocketHandler = null;
			IClientChannelSinkStack clientChannelSinkStack = null;
			try
			{
				tcpClientSocketHandler = (TcpClientSocketHandler)state;
				clientChannelSinkStack = (IClientChannelSinkStack)tcpClientSocketHandler.DataArrivedCallbackState;
				ITransportHeaders headers = tcpClientSocketHandler.ReadHeaders();
				Stream responseStream = tcpClientSocketHandler.GetResponseStream();
				clientChannelSinkStack.AsyncProcessResponse(headers, responseStream);
			}
			catch (Exception e)
			{
				try
				{
					clientChannelSinkStack?.DispatchException(e);
				}
				catch
				{
				}
			}
			catch
			{
				try
				{
					clientChannelSinkStack?.DispatchException(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
				}
				catch
				{
				}
			}
		}
	}
	internal abstract class TcpSocketHandler : SocketHandler
	{
		private static byte[] s_protocolPreamble = Encoding.ASCII.GetBytes(".NET");

		private static byte[] s_protocolVersion1_0 = new byte[2] { 1, 0 };

		public TcpSocketHandler(Socket socket, Stream stream)
			: this(socket, null, stream)
		{
		}

		public TcpSocketHandler(Socket socket, RequestQueue requestQueue, Stream stream)
			: base(socket, requestQueue, stream)
		{
		}

		private void ReadAndMatchPreamble()
		{
			if (!ReadAndMatchFourBytes(s_protocolPreamble))
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_ExpectingPreamble"));
			}
		}

		protected void WritePreambleAndVersion(Stream outputStream)
		{
			outputStream.Write(s_protocolPreamble, 0, s_protocolPreamble.Length);
			outputStream.Write(s_protocolVersion1_0, 0, s_protocolVersion1_0.Length);
		}

		protected void ReadVersionAndOperation(out ushort operation)
		{
			ReadAndMatchPreamble();
			byte b = (byte)ReadByte();
			byte b2 = (byte)ReadByte();
			if (b != 1 || b2 != 0)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_UnknownProtocolVersion"), b.ToString(CultureInfo.CurrentCulture) + "." + b2.ToString(CultureInfo.CurrentCulture)));
			}
			operation = ReadUInt16();
		}

		protected void ReadContentLength(out bool chunked, out int contentLength)
		{
			contentLength = -1;
			ushort num = ReadUInt16();
			switch (num)
			{
			case 1:
				chunked = true;
				break;
			case 0:
				chunked = false;
				contentLength = ReadInt32();
				break;
			default:
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_ExpectingContentLengthHeader"), num.ToString(CultureInfo.CurrentCulture)));
			}
		}

		protected void ReadToEndOfHeaders(BaseTransportHeaders headers)
		{
			bool flag = false;
			string text = null;
			ushort num = ReadUInt16();
			while (true)
			{
				switch (num)
				{
				case 1:
				{
					string key = ReadCountedString();
					string text5 = (string)(headers[key] = ReadCountedString());
					break;
				}
				case 4:
				{
					ReadAndVerifyHeaderFormat("RequestUri", 1);
					string text2 = ReadCountedString();
					string objectURI;
					string text3 = TcpChannelHelper.ParseURL(text2, out objectURI);
					if (text3 == null)
					{
						objectURI = text2;
					}
					headers.RequestUri = objectURI;
					break;
				}
				case 2:
					ReadAndVerifyHeaderFormat("StatusCode", 3);
					if (ReadUInt16() != 0)
					{
						flag = true;
					}
					break;
				case 3:
					ReadAndVerifyHeaderFormat("StatusPhrase", 1);
					text = ReadCountedString();
					break;
				case 6:
				{
					ReadAndVerifyHeaderFormat("Content-Type", 1);
					string text7 = (headers.ContentType = ReadCountedString());
					break;
				}
				default:
				{
					byte b = (byte)ReadByte();
					switch (b)
					{
					case 1:
						ReadCountedString();
						break;
					case 2:
						ReadByte();
						break;
					case 3:
						ReadUInt16();
						break;
					case 4:
						ReadInt32();
						break;
					default:
						throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_UnknownHeaderType"), num, b));
					case 0:
						break;
					}
					break;
				}
				case 0:
					if (flag)
					{
						if (text == null)
						{
							text = "";
						}
						throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_GenericServerError"), text));
					}
					return;
				}
				num = ReadUInt16();
			}
		}

		protected void WriteHeaders(ITransportHeaders headers, Stream outputStream)
		{
			IEnumerator enumerator = null;
			BaseTransportHeaders baseTransportHeaders = headers as BaseTransportHeaders;
			if (baseTransportHeaders != null)
			{
				if (baseTransportHeaders.ContentType != null)
				{
					WriteContentTypeHeader(baseTransportHeaders.ContentType, outputStream);
				}
				enumerator = baseTransportHeaders.GetOtherHeadersEnumerator();
			}
			else
			{
				enumerator = headers.GetEnumerator();
			}
			if (enumerator != null)
			{
				while (enumerator.MoveNext())
				{
					DictionaryEntry dictionaryEntry = (DictionaryEntry)enumerator.Current;
					string text = (string)dictionaryEntry.Key;
					if (!StringHelper.StartsWithDoubleUnderscore(text))
					{
						string value = dictionaryEntry.Value.ToString();
						if (baseTransportHeaders == null && string.Compare(text, "Content-Type", StringComparison.OrdinalIgnoreCase) == 0)
						{
							WriteContentTypeHeader(value, outputStream);
						}
						else
						{
							WriteCustomHeader(text, value, outputStream);
						}
					}
				}
			}
			WriteUInt16(0, outputStream);
		}

		private void WriteContentTypeHeader(string value, Stream outputStream)
		{
			WriteUInt16(6, outputStream);
			WriteByte(1, outputStream);
			WriteCountedString(value, outputStream);
		}

		private void WriteCustomHeader(string name, string value, Stream outputStream)
		{
			WriteUInt16(1, outputStream);
			WriteCountedString(name, outputStream);
			WriteCountedString(value, outputStream);
		}

		protected string ReadCountedString()
		{
			byte b = (byte)ReadByte();
			int num = ReadInt32();
			if (num > 0)
			{
				byte[] array = new byte[num];
				Read(array, 0, num);
				return b switch
				{
					0 => Encoding.Unicode.GetString(array), 
					1 => Encoding.UTF8.GetString(array), 
					_ => throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_UnrecognizedStringFormat"), b.ToString(CultureInfo.CurrentCulture))), 
				};
			}
			return null;
		}

		protected void WriteCountedString(string str, Stream outputStream)
		{
			int num = 0;
			if (str != null)
			{
				num = str.Length;
			}
			if (num > 0)
			{
				byte[] bytes = Encoding.UTF8.GetBytes(str);
				WriteByte(1, outputStream);
				WriteInt32(bytes.Length, outputStream);
				outputStream.Write(bytes, 0, bytes.Length);
			}
			else
			{
				WriteByte(0, outputStream);
				WriteInt32(0, outputStream);
			}
		}

		private void ReadAndVerifyHeaderFormat(string headerName, byte expectedFormat)
		{
			byte b = (byte)ReadByte();
			if (b != expectedFormat)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_IncorrectHeaderFormat"), expectedFormat, headerName));
			}
		}
	}
	internal class TcpClientSocketHandler : TcpSocketHandler
	{
		private static byte[] s_endOfLineBytes = Encoding.ASCII.GetBytes("\r\n");

		private string _machinePortAndSid;

		private bool _bOneWayRequest;

		private bool _bChunked;

		private int _contentLength;

		private Stream _requestStream;

		private TcpReadingStream _responseStream;

		private TcpClientTransportSink _sink;

		public bool OneWayRequest => _bOneWayRequest;

		public TcpClientSocketHandler(Socket socket, string machinePortAndSid, Stream stream, TcpClientTransportSink sink)
			: base(socket, stream)
		{
			_machinePortAndSid = machinePortAndSid;
			_sink = sink;
		}

		protected override void PrepareForNewMessage()
		{
			_requestStream = null;
			_responseStream = null;
		}

		public override void OnInputStreamClosed()
		{
			if (_responseStream != null)
			{
				_responseStream.ReadToEnd();
				_responseStream = null;
			}
			ReturnToCache();
		}

		public BaseTransportHeaders ReadHeaders()
		{
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			ReadVersionAndOperation(out var operation);
			if (operation != 2)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_ExpectingReplyOp"), operation.ToString(CultureInfo.CurrentCulture)));
			}
			ReadContentLength(out _bChunked, out _contentLength);
			ReadToEndOfHeaders(baseTransportHeaders);
			return baseTransportHeaders;
		}

		public Stream GetRequestStream(IMessage msg, int contentLength, ITransportHeaders headers)
		{
			IMethodCallMessage methodCallMessage = (IMethodCallMessage)msg;
			string uri = methodCallMessage.Uri;
			_bOneWayRequest = RemotingServices.IsOneWay(methodCallMessage.MethodBase);
			ChunkedMemoryStream chunkedMemoryStream = new ChunkedMemoryStream(CoreChannel.BufferPool);
			WritePreambleAndVersion(chunkedMemoryStream);
			if (!_bOneWayRequest)
			{
				WriteUInt16(0, chunkedMemoryStream);
			}
			else
			{
				WriteUInt16(1, chunkedMemoryStream);
			}
			WriteUInt16(0, chunkedMemoryStream);
			WriteInt32(contentLength, chunkedMemoryStream);
			WriteUInt16(4, chunkedMemoryStream);
			WriteByte(1, chunkedMemoryStream);
			WriteCountedString(uri, chunkedMemoryStream);
			WriteHeaders(headers, chunkedMemoryStream);
			chunkedMemoryStream.WriteTo(NetStream);
			chunkedMemoryStream.Close();
			_requestStream = NetStream;
			return _requestStream;
		}

		public void SendRequest(IMessage msg, ITransportHeaders headers, Stream contentStream)
		{
			int contentLength = (int)contentStream.Length;
			GetRequestStream(msg, contentLength, headers);
			StreamHelper.CopyStream(contentStream, NetStream);
			contentStream.Close();
		}

		public Stream GetResponseStream()
		{
			if (!_bChunked)
			{
				_responseStream = new TcpFixedLengthReadingStream(this, _contentLength);
			}
			else
			{
				_responseStream = new TcpChunkedReadingStream(this);
			}
			return _responseStream;
		}

		public void ReturnToCache()
		{
			_sink.ClientSocketCache.ReleaseSocket(_machinePortAndSid, this);
		}
	}
	public class TcpServerChannel : IChannelReceiver, IChannel, ISecurableChannel
	{
		private int _channelPriority = 1;

		private string _channelName = "tcp";

		private string _machineName;

		private int _port = -1;

		private ChannelDataStore _channelData;

		private string _forcedMachineName;

		private bool _bUseIpAddress = true;

		private IPAddress _bindToAddr = (Socket.SupportsIPv4 ? IPAddress.Any : IPAddress.IPv6Any);

		private bool _bSuppressChannelData;

		private bool _impersonate;

		private ProtectionLevel _protectionLevel = ProtectionLevel.EncryptAndSign;

		private bool _secure;

		private AsyncCallback _acceptSocketCallback;

		private IAuthorizeRemotingConnection _authorizeRemotingConnection;

		private bool authSet;

		private IServerChannelSinkProvider _sinkProvider;

		private TcpServerTransportSink _transportSink;

		private ExclusiveTcpListener _tcpListener;

		private bool _bExclusiveAddressUse = true;

		private bool _bListening;

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _secure;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_secure = value;
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public object ChannelData
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (_bSuppressChannelData || !_bListening)
				{
					return null;
				}
				return _channelData;
			}
		}

		public TcpServerChannel(int port)
		{
			_port = port;
			SetupMachineName();
			SetupChannel();
		}

		public TcpServerChannel(string name, int port)
		{
			_channelName = name;
			_port = port;
			SetupMachineName();
			SetupChannel();
		}

		public TcpServerChannel(string name, int port, IServerChannelSinkProvider sinkProvider)
		{
			_channelName = name;
			_port = port;
			_sinkProvider = sinkProvider;
			SetupMachineName();
			SetupChannel();
		}

		public TcpServerChannel(IDictionary properties, IServerChannelSinkProvider sinkProvider)
			: this(properties, sinkProvider, null)
		{
		}

		public TcpServerChannel(IDictionary properties, IServerChannelSinkProvider sinkProvider, IAuthorizeRemotingConnection authorizeCallback)
		{
			_authorizeRemotingConnection = authorizeCallback;
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "bindTo":
						_bindToAddr = IPAddress.Parse((string)property.Value);
						break;
					case "port":
						_port = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "priority":
						_channelPriority = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "secure":
						_secure = Convert.ToBoolean(property.Value);
						break;
					case "impersonate":
						_impersonate = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						authSet = true;
						break;
					case "protectionLevel":
						_protectionLevel = (ProtectionLevel)((property.Value is ProtectionLevel) ? property.Value : Enum.Parse(typeof(ProtectionLevel), (string)property.Value, ignoreCase: true));
						authSet = true;
						break;
					case "machineName":
						_forcedMachineName = (string)property.Value;
						break;
					case "rejectRemoteRequests":
						if (Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture))
						{
							if (Socket.SupportsIPv4)
							{
								_bindToAddr = IPAddress.Loopback;
							}
							else
							{
								_bindToAddr = IPAddress.IPv6Loopback;
							}
						}
						break;
					case "suppressChannelData":
						_bSuppressChannelData = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "useIpAddress":
						_bUseIpAddress = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "exclusiveAddressUse":
						_bExclusiveAddressUse = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "authorizationModule":
						_authorizeRemotingConnection = (IAuthorizeRemotingConnection)Activator.CreateInstance(Type.GetType((string)property.Value, throwOnError: true));
						break;
					}
				}
			}
			_sinkProvider = sinkProvider;
			SetupMachineName();
			SetupChannel();
		}

		private void SetupMachineName()
		{
			if (_forcedMachineName != null)
			{
				_machineName = CoreChannel.DecodeMachineName(_forcedMachineName);
				return;
			}
			if (!_bUseIpAddress)
			{
				_machineName = CoreChannel.GetMachineName();
				return;
			}
			if (_bindToAddr == IPAddress.Any || _bindToAddr == IPAddress.IPv6Any)
			{
				_machineName = CoreChannel.GetMachineIp();
			}
			else
			{
				_machineName = _bindToAddr.ToString();
			}
			if (_bindToAddr.AddressFamily == AddressFamily.InterNetworkV6)
			{
				_machineName = "[" + _machineName + "]";
			}
		}

		private void SetupChannel()
		{
			if (authSet && !_secure)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_AuthenticationConfigServer"));
			}
			_channelData = new ChannelDataStore(null);
			if (_port > 0)
			{
				_channelData.ChannelUris = new string[1];
				_channelData.ChannelUris[0] = GetChannelUri();
			}
			if (_sinkProvider == null)
			{
				_sinkProvider = CreateDefaultServerProviderChain();
			}
			CoreChannel.CollectChannelDataFromServerSinkProviders(_channelData, _sinkProvider);
			IServerChannelSink nextSink = ChannelServices.CreateServerChannelSinkChain(_sinkProvider, this);
			_transportSink = new TcpServerTransportSink(nextSink, _impersonate);
			_acceptSocketCallback = AcceptSocketCallbackHelper;
			if (_port >= 0)
			{
				_tcpListener = new ExclusiveTcpListener(_bindToAddr, _port);
				StartListening(null);
			}
		}

		private IServerChannelSinkProvider CreateDefaultServerProviderChain()
		{
			IServerChannelSinkProvider serverChannelSinkProvider = new BinaryServerFormatterSinkProvider();
			IServerChannelSinkProvider serverChannelSinkProvider2 = serverChannelSinkProvider;
			serverChannelSinkProvider2.Next = new SoapServerFormatterSinkProvider();
			return serverChannelSinkProvider;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return TcpChannelHelper.ParseURL(url, out objectURI);
		}

		public string GetChannelUri()
		{
			return "tcp://" + _machineName + ":" + _port;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public virtual string[] GetUrlsForUri(string objectUri)
		{
			string[] array = new string[1];
			if (!objectUri.StartsWith("/", StringComparison.Ordinal))
			{
				objectUri = "/" + objectUri;
			}
			array[0] = GetChannelUri() + objectUri;
			return array;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StartListening(object data)
		{
			if (_port < 0)
			{
				return;
			}
			_tcpListener.Start(_bExclusiveAddressUse);
			_bListening = true;
			if (_port == 0)
			{
				_port = ((IPEndPoint)_tcpListener.LocalEndpoint).Port;
				if (_channelData != null)
				{
					_channelData.ChannelUris = new string[1];
					_channelData.ChannelUris[0] = GetChannelUri();
				}
			}
			_tcpListener.BeginAcceptSocket(_acceptSocketCallback, null);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StopListening(object data)
		{
			if (_port > 0)
			{
				_bListening = false;
				if (_tcpListener != null)
				{
					_tcpListener.Stop();
				}
			}
		}

		private void AcceptSocketCallbackHelper(IAsyncResult ar)
		{
			if (ar.CompletedSynchronously)
			{
				ThreadPool.QueueUserWorkItem(AcceptSocketCallbackAsync, ar);
			}
			else
			{
				AcceptSocketCallback(ar);
			}
		}

		private void AcceptSocketCallbackAsync(object state)
		{
			AcceptSocketCallback((IAsyncResult)state);
		}

		private void AcceptSocketCallback(IAsyncResult ar)
		{
			Socket socket = null;
			TcpServerSocketHandler tcpServerSocketHandler = null;
			bool flag = true;
			try
			{
				if (_tcpListener.IsListening)
				{
					_tcpListener.BeginAcceptSocket(_acceptSocketCallback, null);
				}
				socket = _tcpListener.EndAcceptSocket(ar);
				if (socket == null)
				{
					throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Socket_Accept"), Marshal.GetLastWin32Error().ToString(CultureInfo.CurrentCulture)));
				}
				if (_authorizeRemotingConnection != null && !_authorizeRemotingConnection.IsConnectingEndPointAuthorized(socket.RemoteEndPoint))
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_ServerAuthorizationEndpointFailed"));
				}
				socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.Debug, 1);
				socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, 1);
				LingerOption optionValue = new LingerOption(enable: true, 3);
				socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Linger, optionValue);
				Stream netStream = new SocketStream(socket);
				tcpServerSocketHandler = new TcpServerSocketHandler(socket, CoreChannel.RequestQueue, netStream);
				WindowsIdentity windowsIdentity = null;
				flag = false;
				if (_secure)
				{
					windowsIdentity = Authenticate(ref netStream, tcpServerSocketHandler);
					tcpServerSocketHandler = new TcpServerSocketHandler(socket, CoreChannel.RequestQueue, netStream);
					if (_authorizeRemotingConnection != null && !_authorizeRemotingConnection.IsConnectingIdentityAuthorized(windowsIdentity))
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_ServerAuthorizationIdentityFailed"));
					}
				}
				tcpServerSocketHandler.ImpersonationIdentity = windowsIdentity;
				tcpServerSocketHandler.DataArrivedCallback = _transportSink.ServiceRequest;
				tcpServerSocketHandler.BeginReadMessage();
			}
			catch (Exception ex)
			{
				try
				{
					tcpServerSocketHandler?.SendErrorResponse(ex, bCloseConnection: false);
					if (socket != null)
					{
						if (flag)
						{
							socket.Close(0);
						}
						else
						{
							socket.Close();
						}
					}
				}
				catch (Exception)
				{
				}
				if (_bListening)
				{
					_ = ex is SocketException;
				}
			}
		}

		private WindowsIdentity Authenticate(ref Stream netStream, TcpServerSocketHandler streamManager)
		{
			NegotiateStream negotiateStream = null;
			try
			{
				negotiateStream = new NegotiateStream(netStream);
				TokenImpersonationLevel requiredImpersonationLevel = TokenImpersonationLevel.Identification;
				if (_impersonate)
				{
					requiredImpersonationLevel = TokenImpersonationLevel.Impersonation;
				}
				negotiateStream.AuthenticateAsServer((NetworkCredential)CredentialCache.DefaultCredentials, _protectionLevel, requiredImpersonationLevel);
				netStream = negotiateStream;
				return (WindowsIdentity)negotiateStream.RemoteIdentity;
			}
			catch
			{
				streamManager.SendErrorResponse(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_ServerAuthenticationFailed")), bCloseConnection: false);
				negotiateStream?.Close();
				throw;
			}
		}
	}
	internal class TcpServerTransportSink : IServerChannelSink, IChannelSinkBase
	{
		private const int s_MaxSize = 33554432;

		private IServerChannelSink _nextSink;

		private bool _impersonate;

		public IServerChannelSink NextChannelSink => _nextSink;

		public IDictionary Properties => null;

		internal TcpServerTransportSink(IServerChannelSink nextSink, bool impersonate)
		{
			_nextSink = nextSink;
			_impersonate = impersonate;
		}

		internal void ServiceRequest(object state)
		{
			TcpServerSocketHandler tcpServerSocketHandler = (TcpServerSocketHandler)state;
			ITransportHeaders transportHeaders = tcpServerSocketHandler.ReadHeaders();
			Stream requestStream = tcpServerSocketHandler.GetRequestStream();
			transportHeaders["__CustomErrorsEnabled"] = tcpServerSocketHandler.CustomErrorsEnabled();
			ServerChannelSinkStack serverChannelSinkStack = new ServerChannelSinkStack();
			serverChannelSinkStack.Push(this, tcpServerSocketHandler);
			WindowsIdentity impersonationIdentity = tcpServerSocketHandler.ImpersonationIdentity;
			WindowsImpersonationContext windowsImpersonationContext = null;
			IPrincipal currentPrincipal = null;
			bool flag = false;
			if (impersonationIdentity != null)
			{
				currentPrincipal = Thread.CurrentPrincipal;
				flag = true;
				if (_impersonate)
				{
					Thread.CurrentPrincipal = new WindowsPrincipal(impersonationIdentity);
					windowsImpersonationContext = impersonationIdentity.Impersonate();
				}
				else
				{
					Thread.CurrentPrincipal = new GenericPrincipal(impersonationIdentity, null);
				}
			}
			ServerProcessing serverProcessing;
			ITransportHeaders responseHeaders;
			Stream responseStream;
			try
			{
				try
				{
					serverProcessing = _nextSink.ProcessMessage(serverChannelSinkStack, null, transportHeaders, requestStream, out var _, out responseHeaders, out responseStream);
				}
				finally
				{
					if (flag)
					{
						Thread.CurrentPrincipal = currentPrincipal;
					}
					if (_impersonate)
					{
						windowsImpersonationContext.Undo();
					}
				}
			}
			catch
			{
				throw;
			}
			switch (serverProcessing)
			{
			case ServerProcessing.Complete:
				serverChannelSinkStack.Pop(this);
				tcpServerSocketHandler.SendResponse(responseHeaders, responseStream);
				break;
			case ServerProcessing.OneWay:
				tcpServerSocketHandler.SendResponse(responseHeaders, responseStream);
				break;
			case ServerProcessing.Async:
				serverChannelSinkStack.StoreAndDispatch(this, tcpServerSocketHandler);
				break;
			}
			if (serverProcessing != ServerProcessing.Async)
			{
				if (tcpServerSocketHandler.CanServiceAnotherRequest())
				{
					tcpServerSocketHandler.BeginReadMessage();
				}
				else
				{
					tcpServerSocketHandler.Close();
				}
			}
		}

		public ServerProcessing ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, out IMessage responseMsg, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			throw new NotSupportedException();
		}

		public void AsyncProcessResponse(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			TcpServerSocketHandler tcpServerSocketHandler = null;
			tcpServerSocketHandler = (TcpServerSocketHandler)state;
			tcpServerSocketHandler.SendResponse(headers, stream);
			if (tcpServerSocketHandler.CanServiceAnotherRequest())
			{
				tcpServerSocketHandler.BeginReadMessage();
			}
			else
			{
				tcpServerSocketHandler.Close();
			}
		}

		public Stream GetResponseStream(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers)
		{
			return null;
		}
	}
	internal abstract class TcpReadingStream : Stream
	{
		public virtual bool FoundEnd => false;

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => false;

		public override long Length
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override long Position
		{
			get
			{
				throw new NotSupportedException();
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public void ReadToEnd()
		{
			byte[] buffer = new byte[64];
			int num;
			do
			{
				num = Read(buffer, 0, 64);
			}
			while (num > 0);
		}

		public override void Flush()
		{
			throw new NotSupportedException();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}
	}
	internal sealed class TcpFixedLengthReadingStream : TcpReadingStream
	{
		private SocketHandler _inputStream;

		private int _bytesLeft;

		public override bool FoundEnd => _bytesLeft == 0;

		internal TcpFixedLengthReadingStream(SocketHandler inputStream, int contentLength)
		{
			_inputStream = inputStream;
			_bytesLeft = contentLength;
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing)
				{
					_inputStream.OnInputStreamClosed();
				}
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			if (_bytesLeft == 0)
			{
				return 0;
			}
			int num = _inputStream.Read(buffer, offset, Math.Min(_bytesLeft, count));
			if (num > 0)
			{
				_bytesLeft -= num;
			}
			return num;
		}

		public override int ReadByte()
		{
			if (_bytesLeft == 0)
			{
				return -1;
			}
			_bytesLeft--;
			return _inputStream.ReadByte();
		}
	}
	internal sealed class TcpChunkedReadingStream : TcpReadingStream
	{
		private SocketHandler _inputStream;

		private int _bytesLeft;

		private bool _bFoundEnd;

		private byte[] _byteBuffer = new byte[1];

		public override bool FoundEnd => _bFoundEnd;

		internal TcpChunkedReadingStream(SocketHandler inputStream)
		{
			_inputStream = inputStream;
			_bytesLeft = 0;
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			int num = 0;
			while (!_bFoundEnd && count > 0)
			{
				if (_bytesLeft == 0)
				{
					_bytesLeft = _inputStream.ReadInt32();
					if (_bytesLeft == 0)
					{
						ReadTrailer();
						_bFoundEnd = true;
					}
				}
				if (!_bFoundEnd)
				{
					int count2 = Math.Min(_bytesLeft, count);
					int num2 = _inputStream.Read(buffer, offset, count2);
					if (num2 <= 0)
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_ChunkedEncodingError"));
					}
					_bytesLeft -= num2;
					count -= num2;
					offset += num2;
					num += num2;
					if (_bytesLeft == 0)
					{
						ReadTrailer();
					}
				}
			}
			return num;
		}

		public override int ReadByte()
		{
			if (Read(_byteBuffer, 0, 1) == 0)
			{
				return -1;
			}
			return _byteBuffer[0];
		}

		private void ReadTrailer()
		{
			int num = _inputStream.ReadByte();
			if (num != 13)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_ChunkedEncodingError"));
			}
			num = _inputStream.ReadByte();
			if (num != 10)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Tcp_ChunkedEncodingError"));
			}
		}
	}
	internal sealed class TcpServerSocketHandler : TcpSocketHandler
	{
		private static byte[] s_endOfLineBytes = Encoding.ASCII.GetBytes("\r\n");

		private static long _connectionIdCounter = 0L;

		private long _connectionId;

		private bool _bOneWayRequest;

		private bool _bChunked;

		private int _contentLength;

		private TcpReadingStream _requestStream;

		internal TcpServerSocketHandler(Socket socket, RequestQueue requestQueue, Stream stream)
			: base(socket, requestQueue, stream)
		{
			_connectionId = Interlocked.Increment(ref _connectionIdCounter);
		}

		public bool CanServiceAnotherRequest()
		{
			return true;
		}

		protected override void PrepareForNewMessage()
		{
			if (_requestStream != null)
			{
				if (!_requestStream.FoundEnd)
				{
					_requestStream.ReadToEnd();
				}
				_requestStream = null;
			}
		}

		protected override void SendErrorMessageIfPossible(Exception e)
		{
			try
			{
				SendErrorResponse(e, bCloseConnection: true);
			}
			catch
			{
			}
		}

		public ITransportHeaders ReadHeaders()
		{
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			ReadVersionAndOperation(out var operation);
			switch (operation)
			{
			case 0:
				_bOneWayRequest = false;
				break;
			case 1:
				_bOneWayRequest = true;
				break;
			default:
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_ExpectingRequestOp"), operation.ToString(CultureInfo.CurrentCulture)));
			}
			ReadContentLength(out _bChunked, out _contentLength);
			ReadToEndOfHeaders(baseTransportHeaders);
			baseTransportHeaders.IPAddress = ((IPEndPoint)NetSocket.RemoteEndPoint).Address;
			baseTransportHeaders.ConnectionId = _connectionId;
			return baseTransportHeaders;
		}

		public Stream GetRequestStream()
		{
			if (!_bChunked)
			{
				_requestStream = new TcpFixedLengthReadingStream(this, _contentLength);
			}
			else
			{
				_requestStream = new TcpChunkedReadingStream(this);
			}
			return _requestStream;
		}

		public void SendResponse(ITransportHeaders headers, Stream contentStream)
		{
			if (!_bOneWayRequest)
			{
				ChunkedMemoryStream chunkedMemoryStream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				WritePreambleAndVersion(chunkedMemoryStream);
				WriteUInt16(2, chunkedMemoryStream);
				WriteUInt16(0, chunkedMemoryStream);
				WriteInt32((int)contentStream.Length, chunkedMemoryStream);
				WriteHeaders(headers, chunkedMemoryStream);
				chunkedMemoryStream.WriteTo(NetStream);
				chunkedMemoryStream.Close();
				StreamHelper.CopyStream(contentStream, NetStream);
				contentStream.Close();
			}
		}

		private string GenerateFaultString(Exception e)
		{
			if (!CustomErrorsEnabled())
			{
				return e.ToString();
			}
			return CoreChannel.GetResourceString("Remoting_InternalError");
		}

		public void SendErrorResponse(Exception e, bool bCloseConnection)
		{
			SendErrorResponse(GenerateFaultString(e), bCloseConnection);
		}

		public void SendErrorResponse(string e, bool bCloseConnection)
		{
			if (!_bOneWayRequest)
			{
				ChunkedMemoryStream chunkedMemoryStream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				WritePreambleAndVersion(chunkedMemoryStream);
				WriteUInt16(2, chunkedMemoryStream);
				WriteUInt16(0, chunkedMemoryStream);
				WriteInt32(0, chunkedMemoryStream);
				WriteUInt16(2, chunkedMemoryStream);
				WriteByte(3, chunkedMemoryStream);
				WriteUInt16(1, chunkedMemoryStream);
				WriteUInt16(3, chunkedMemoryStream);
				WriteByte(1, chunkedMemoryStream);
				WriteCountedString(e, chunkedMemoryStream);
				WriteUInt16(5, chunkedMemoryStream);
				WriteByte(0, chunkedMemoryStream);
				WriteUInt16(0, chunkedMemoryStream);
				chunkedMemoryStream.WriteTo(NetStream);
				chunkedMemoryStream.Close();
			}
		}
	}
	internal static class TcpOperations
	{
		internal const ushort Request = 0;

		internal const ushort OneWayRequest = 1;

		internal const ushort Reply = 2;
	}
	internal static class TcpContentDelimiter
	{
		internal const ushort ContentLength = 0;

		internal const ushort Chunked = 1;
	}
	internal static class TcpHeaders
	{
		internal const ushort EndOfHeaders = 0;

		internal const ushort Custom = 1;

		internal const ushort StatusCode = 2;

		internal const ushort StatusPhrase = 3;

		internal const ushort RequestUri = 4;

		internal const ushort CloseConnection = 5;

		internal const ushort ContentType = 6;
	}
	internal static class TcpHeaderFormat
	{
		internal const byte Void = 0;

		internal const byte CountedString = 1;

		internal const byte Byte = 2;

		internal const byte UInt16 = 3;

		internal const byte Int32 = 4;
	}
	internal static class TcpStatusCode
	{
		internal const ushort Success = 0;

		internal const ushort GenericError = 1;
	}
	internal static class TcpStringFormat
	{
		internal const byte Unicode = 0;

		internal const byte UTF8 = 1;
	}
}
namespace System.Runtime.Remoting.Channels.Ipc
{
	public class IpcChannel : IChannelReceiver, IChannelSender, IChannel, ISecurableChannel
	{
		private IpcClientChannel _clientChannel;

		private IpcServerChannel _serverChannel;

		private int _channelPriority = 20;

		private string _channelName = "ipc";

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (_clientChannel != null)
				{
					return _clientChannel.IsSecured;
				}
				if (_serverChannel != null)
				{
					return _serverChannel.IsSecured;
				}
				return false;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				if (((IList)ChannelServices.RegisteredChannels).Contains((object)this))
				{
					throw new InvalidOperationException(CoreChannel.GetResourceString("Remoting_InvalidOperation_IsSecuredCannotBeChangedOnRegisteredChannels"));
				}
				if (_clientChannel != null)
				{
					_clientChannel.IsSecured = value;
				}
				if (_serverChannel != null)
				{
					_serverChannel.IsSecured = value;
				}
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public object ChannelData
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (_serverChannel != null)
				{
					return _serverChannel.ChannelData;
				}
				return null;
			}
		}

		public IpcChannel()
		{
			_clientChannel = new IpcClientChannel();
		}

		public IpcChannel(string portName)
			: this()
		{
			_serverChannel = new IpcServerChannel(portName);
		}

		public IpcChannel(IDictionary properties, IClientChannelSinkProvider clientSinkProvider, IServerChannelSinkProvider serverSinkProvider)
		{
			Hashtable hashtable = new Hashtable();
			Hashtable hashtable2 = new Hashtable();
			bool flag = false;
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "priority":
						_channelPriority = Convert.ToInt32((string)property.Value, CultureInfo.InvariantCulture);
						break;
					case "portName":
						hashtable2["portName"] = property.Value;
						flag = true;
						break;
					default:
						hashtable[property.Key] = property.Value;
						hashtable2[property.Key] = property.Value;
						break;
					}
				}
			}
			_clientChannel = new IpcClientChannel(hashtable, clientSinkProvider);
			if (flag)
			{
				_serverChannel = new IpcServerChannel(hashtable2, serverSinkProvider, null);
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return IpcChannelHelper.ParseURL(url, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IMessageSink CreateMessageSink(string url, object remoteChannelData, out string objectURI)
		{
			return _clientChannel.CreateMessageSink(url, remoteChannelData, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string[] GetUrlsForUri(string objectURI)
		{
			if (_serverChannel != null)
			{
				return _serverChannel.GetUrlsForUri(objectURI);
			}
			return null;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StartListening(object data)
		{
			if (_serverChannel != null)
			{
				_serverChannel.StartListening(data);
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StopListening(object data)
		{
			if (_serverChannel != null)
			{
				_serverChannel.StopListening(data);
			}
		}
	}
	public class IpcServerChannel : IChannelReceiver, IChannel, ISecurableChannel
	{
		private int _channelPriority = 20;

		private string _channelName = "ipc server";

		private string _portName;

		private ChannelDataStore _channelData;

		private IpcPort _port;

		private bool _bSuppressChannelData;

		private bool _secure;

		private bool _impersonate;

		private string _authorizedGroup;

		private CommonSecurityDescriptor _securityDescriptor;

		private bool authSet;

		private bool _bExclusiveAddressUse = true;

		private IServerChannelSinkProvider _sinkProvider;

		private IpcServerTransportSink _transportSink;

		private Thread _listenerThread;

		private bool _bListening;

		private Exception _startListeningException;

		private AutoResetEvent _waitForStartListening = new AutoResetEvent(initialState: false);

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _secure;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_secure = value;
				if (_transportSink != null)
				{
					_transportSink.IsSecured = value;
				}
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public object ChannelData
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				if (_bSuppressChannelData || !_bListening)
				{
					return null;
				}
				return _channelData;
			}
		}

		public IpcServerChannel(string portName)
		{
			if (portName == null)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Ipc_NoPortNameSpecified"));
			}
			_portName = portName;
			SetupChannel();
		}

		public IpcServerChannel(string name, string portName)
		{
			if (portName == null)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Ipc_NoPortNameSpecified"));
			}
			_channelName = name;
			_portName = portName;
			SetupChannel();
		}

		public IpcServerChannel(string name, string portName, IServerChannelSinkProvider sinkProvider)
		{
			if (portName == null)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Ipc_NoPortNameSpecified"));
			}
			_channelName = name;
			_portName = portName;
			_sinkProvider = sinkProvider;
			SetupChannel();
		}

		public IpcServerChannel(IDictionary properties, IServerChannelSinkProvider sinkProvider)
			: this(properties, sinkProvider, null)
		{
		}

		public IpcServerChannel(IDictionary properties, IServerChannelSinkProvider sinkProvider, CommonSecurityDescriptor securityDescriptor)
		{
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "portName":
						_portName = (string)property.Value;
						break;
					case "priority":
						_channelPriority = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "secure":
						_secure = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "impersonate":
						_impersonate = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						authSet = true;
						break;
					case "suppressChannelData":
						_bSuppressChannelData = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "authorizedGroup":
						_authorizedGroup = (string)property.Value;
						break;
					case "exclusiveAddressUse":
						_bExclusiveAddressUse = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
			if (_portName == null)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Ipc_NoPortNameSpecified"));
			}
			_sinkProvider = sinkProvider;
			_securityDescriptor = securityDescriptor;
			SetupChannel();
		}

		private void SetupChannel()
		{
			if (authSet && !_secure)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Ipc_AuthenticationConfig"));
			}
			_channelData = new ChannelDataStore(null);
			_channelData.ChannelUris = new string[1];
			_channelData.ChannelUris[0] = GetChannelUri();
			if (_sinkProvider == null)
			{
				_sinkProvider = CreateDefaultServerProviderChain();
			}
			CoreChannel.CollectChannelDataFromServerSinkProviders(_channelData, _sinkProvider);
			IServerChannelSink nextSink = ChannelServices.CreateServerChannelSinkChain(_sinkProvider, this);
			_transportSink = new IpcServerTransportSink(nextSink, _secure, _impersonate);
			ThreadStart start = Listen;
			_listenerThread = new Thread(start);
			_listenerThread.IsBackground = true;
			StartListening(null);
		}

		private IServerChannelSinkProvider CreateDefaultServerProviderChain()
		{
			IServerChannelSinkProvider serverChannelSinkProvider = new BinaryServerFormatterSinkProvider();
			IServerChannelSinkProvider serverChannelSinkProvider2 = serverChannelSinkProvider;
			serverChannelSinkProvider2.Next = new SoapServerFormatterSinkProvider();
			return serverChannelSinkProvider;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return IpcChannelHelper.ParseURL(url, out objectURI);
		}

		public string GetChannelUri()
		{
			return "ipc://" + _portName;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public virtual string[] GetUrlsForUri(string objectUri)
		{
			if (objectUri == null)
			{
				throw new ArgumentNullException("objectUri");
			}
			string[] array = new string[1];
			if (!objectUri.StartsWith("/", StringComparison.Ordinal))
			{
				objectUri = "/" + objectUri;
			}
			array[0] = GetChannelUri() + objectUri;
			return array;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StartListening(object data)
		{
			if (!_listenerThread.IsAlive)
			{
				_listenerThread.Start();
				_waitForStartListening.WaitOne();
				if (_startListeningException != null)
				{
					Exception startListeningException = _startListeningException;
					_startListeningException = null;
					throw startListeningException;
				}
				_bListening = true;
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void StopListening(object data)
		{
			_bListening = false;
			_port.Dispose();
		}

		private void Listen()
		{
			bool flag = true;
			_ = IntPtr.Zero;
			bool flag2 = false;
			CommonSecurityDescriptor commonSecurityDescriptor = _securityDescriptor;
			if (flag)
			{
				try
				{
					if (commonSecurityDescriptor == null && _authorizedGroup != null)
					{
						NTAccount nTAccount = new NTAccount(_authorizedGroup);
						commonSecurityDescriptor = IpcPort.CreateSecurityDescriptor((SecurityIdentifier)nTAccount.Translate(typeof(SecurityIdentifier)));
					}
					_port = IpcPort.Create(_portName, commonSecurityDescriptor, _bExclusiveAddressUse);
				}
				catch (Exception startListeningException)
				{
					Exception ex = (_startListeningException = startListeningException);
				}
				catch
				{
					_startListeningException = new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException"));
				}
				finally
				{
					_waitForStartListening.Set();
				}
				if (_port != null)
				{
					flag2 = _port.WaitForConnect();
					flag = _bListening;
				}
			}
			while (flag && _startListeningException == null)
			{
				IpcPort port = IpcPort.Create(_portName, commonSecurityDescriptor, exclusive: false);
				if (flag2)
				{
					IpcServerHandler ipcServerHandler = new IpcServerHandler(_port, CoreChannel.RequestQueue, new PipeStream(_port));
					ipcServerHandler.DataArrivedCallback = _transportSink.ServiceRequest;
					ipcServerHandler.BeginReadMessage();
				}
				_port = port;
				flag2 = _port.WaitForConnect();
				flag = _bListening;
			}
		}
	}
	internal class IpcServerTransportSink : IServerChannelSink, IChannelSinkBase
	{
		private const int s_MaxSize = 33554432;

		private IServerChannelSink _nextSink;

		private bool _secure;

		private bool _impersonate;

		internal bool IsSecured
		{
			get
			{
				return _secure;
			}
			set
			{
				_secure = value;
			}
		}

		public IServerChannelSink NextChannelSink => _nextSink;

		public IDictionary Properties => null;

		public IpcServerTransportSink(IServerChannelSink nextSink, bool secure, bool impersonate)
		{
			_nextSink = nextSink;
			_secure = secure;
			_impersonate = impersonate;
		}

		internal void ServiceRequest(object state)
		{
			IpcServerHandler ipcServerHandler = (IpcServerHandler)state;
			ITransportHeaders transportHeaders = ipcServerHandler.ReadHeaders();
			Stream requestStream = ipcServerHandler.GetRequestStream();
			transportHeaders["__CustomErrorsEnabled"] = false;
			ServerChannelSinkStack serverChannelSinkStack = new ServerChannelSinkStack();
			serverChannelSinkStack.Push(this, ipcServerHandler);
			IMessage responseMsg = null;
			ITransportHeaders responseHeaders = null;
			Stream responseStream = null;
			WindowsIdentity windowsIdentity = null;
			IPrincipal currentPrincipal = null;
			bool flag = false;
			bool flag2 = false;
			ServerProcessing serverProcessing = ServerProcessing.Complete;
			try
			{
				if (_secure)
				{
					IpcPort port = ipcServerHandler.Port;
					port.ImpersonateClient();
					currentPrincipal = Thread.CurrentPrincipal;
					flag2 = true;
					flag = true;
					windowsIdentity = WindowsIdentity.GetCurrent();
					if (!_impersonate)
					{
						NativePipe.RevertToSelf();
						Thread.CurrentPrincipal = new GenericPrincipal(windowsIdentity, null);
						flag = false;
					}
					else
					{
						if (windowsIdentity.ImpersonationLevel != TokenImpersonationLevel.Impersonation && windowsIdentity.ImpersonationLevel != TokenImpersonationLevel.Delegation)
						{
							throw new RemotingException(CoreChannel.GetResourceString("Remoting_Ipc_TokenImpersonationFailure"));
						}
						Thread.CurrentPrincipal = new WindowsPrincipal(windowsIdentity);
					}
				}
				serverProcessing = _nextSink.ProcessMessage(serverChannelSinkStack, null, transportHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
			}
			catch (Exception e)
			{
				ipcServerHandler.CloseOnFatalError(e);
			}
			catch
			{
				ipcServerHandler.CloseOnFatalError(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
			}
			finally
			{
				if (flag2)
				{
					Thread.CurrentPrincipal = currentPrincipal;
				}
				if (flag)
				{
					NativePipe.RevertToSelf();
					flag = false;
				}
			}
			switch (serverProcessing)
			{
			case ServerProcessing.Complete:
				serverChannelSinkStack.Pop(this);
				ipcServerHandler.SendResponse(responseHeaders, responseStream);
				break;
			case ServerProcessing.OneWay:
				ipcServerHandler.SendResponse(responseHeaders, responseStream);
				break;
			case ServerProcessing.Async:
				serverChannelSinkStack.StoreAndDispatch(this, ipcServerHandler);
				break;
			}
			if (serverProcessing != ServerProcessing.Async)
			{
				ipcServerHandler.BeginReadMessage();
			}
		}

		public ServerProcessing ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, out IMessage responseMsg, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			throw new NotSupportedException();
		}

		public void AsyncProcessResponse(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			IpcServerHandler ipcServerHandler = null;
			ipcServerHandler = (IpcServerHandler)state;
			ipcServerHandler.SendResponse(headers, stream);
		}

		public Stream GetResponseStream(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers)
		{
			return null;
		}
	}
	internal delegate IClientChannelSinkStack AsyncMessageDelegate(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream, IClientChannelSinkStack sinkStack);
	public class IpcClientChannel : IChannelSender, IChannel, ISecurableChannel
	{
		private int _channelPriority = 1;

		private string _channelName = "ipc client";

		private bool _secure;

		private IDictionary _prop;

		private IClientChannelSinkProvider _sinkProvider;

		public bool IsSecured
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _secure;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_secure = value;
			}
		}

		public int ChannelPriority
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelPriority;
			}
		}

		public string ChannelName
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _channelName;
			}
		}

		public IpcClientChannel()
		{
			SetupChannel();
		}

		public IpcClientChannel(string name, IClientChannelSinkProvider sinkProvider)
		{
			_channelName = name;
			_sinkProvider = sinkProvider;
			SetupChannel();
		}

		public IpcClientChannel(IDictionary properties, IClientChannelSinkProvider sinkProvider)
		{
			if (properties != null)
			{
				_prop = properties;
				foreach (DictionaryEntry property in properties)
				{
					switch ((string)property.Key)
					{
					case "name":
						_channelName = (string)property.Value;
						break;
					case "priority":
						_channelPriority = Convert.ToInt32(property.Value, CultureInfo.InvariantCulture);
						break;
					case "secure":
						_secure = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
			_sinkProvider = sinkProvider;
			SetupChannel();
		}

		private void SetupChannel()
		{
			if (_sinkProvider != null)
			{
				CoreChannel.AppendProviderToClientProviderChain(_sinkProvider, new IpcClientTransportSinkProvider(_prop));
			}
			else
			{
				_sinkProvider = CreateDefaultClientProviderChain();
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public string Parse(string url, out string objectURI)
		{
			return IpcChannelHelper.ParseURL(url, out objectURI);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public virtual IMessageSink CreateMessageSink(string url, object remoteChannelData, out string objectURI)
		{
			objectURI = null;
			string text = null;
			if (url != null)
			{
				text = Parse(url, out objectURI);
			}
			else if (remoteChannelData != null && remoteChannelData is IChannelDataStore)
			{
				IChannelDataStore channelDataStore = (IChannelDataStore)remoteChannelData;
				string text2 = Parse(channelDataStore.ChannelUris[0], out objectURI);
				if (text2 != null)
				{
					text = channelDataStore.ChannelUris[0];
				}
			}
			if (text != null)
			{
				if (url == null)
				{
					url = text;
				}
				IClientChannelSink clientChannelSink = _sinkProvider.CreateSink(this, url, remoteChannelData);
				IMessageSink messageSink = clientChannelSink as IMessageSink;
				if (clientChannelSink != null && messageSink == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_Channels_ChannelSinkNotMsgSink"));
				}
				return messageSink;
			}
			return null;
		}

		private IClientChannelSinkProvider CreateDefaultClientProviderChain()
		{
			IClientChannelSinkProvider clientChannelSinkProvider = new BinaryClientFormatterSinkProvider();
			IClientChannelSinkProvider clientChannelSinkProvider2 = clientChannelSinkProvider;
			clientChannelSinkProvider2.Next = new IpcClientTransportSinkProvider(_prop);
			return clientChannelSinkProvider;
		}
	}
	internal class IpcClientTransportSinkProvider : IClientChannelSinkProvider
	{
		private IDictionary _prop;

		public IClientChannelSinkProvider Next
		{
			get
			{
				return null;
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		internal IpcClientTransportSinkProvider(IDictionary properties)
		{
			_prop = properties;
		}

		public IClientChannelSink CreateSink(IChannelSender channel, string url, object remoteChannelData)
		{
			IpcClientTransportSink ipcClientTransportSink = new IpcClientTransportSink(url, (IpcClientChannel)channel);
			if (_prop != null)
			{
				foreach (object key in _prop.Keys)
				{
					ipcClientTransportSink[key] = _prop[key];
				}
				return ipcClientTransportSink;
			}
			return ipcClientTransportSink;
		}
	}
	internal class IpcClientTransportSink : BaseChannelSinkWithProperties, IClientChannelSink, IChannelSinkBase
	{
		private const string TokenImpersonationLevelKey = "tokenimpersonationlevel";

		private const string ConnectionTimeoutKey = "connectiontimeout";

		private ConnectionCache portCache = new ConnectionCache();

		private IpcClientChannel _channel;

		private string _portName;

		private bool authSet;

		private TokenImpersonationLevel _tokenImpersonationLevel = TokenImpersonationLevel.Identification;

		private int _timeout = 1000;

		private static ICollection s_keySet;

		internal ConnectionCache Cache => portCache;

		public IClientChannelSink NextChannelSink => null;

		public override object this[object key]
		{
			get
			{
				if (!(key is string text))
				{
					return null;
				}
				return text.ToLower(CultureInfo.InvariantCulture) switch
				{
					"tokenimpersonationlevel" => _tokenImpersonationLevel.ToString(), 
					"connectiontimeout" => _timeout, 
					_ => null, 
				};
			}
			set
			{
				if (key is string text)
				{
					switch (text.ToLower(CultureInfo.InvariantCulture))
					{
					case "tokenimpersonationlevel":
						_tokenImpersonationLevel = (TokenImpersonationLevel)((value is TokenImpersonationLevel) ? value : Enum.Parse(typeof(TokenImpersonationLevel), (string)value, ignoreCase: true));
						authSet = true;
						break;
					case "connectiontimeout":
						_timeout = Convert.ToInt32(value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
		}

		public override ICollection Keys
		{
			get
			{
				_ = s_keySet;
				return s_keySet;
			}
		}

		internal IpcClientTransportSink(string channelURI, IpcClientChannel channel)
		{
			_channel = channel;
			string objectURI;
			string text = IpcChannelHelper.ParseURL(channelURI, out objectURI);
			int num = text.IndexOf("://");
			num += 3;
			_portName = text.Substring(num);
		}

		public void ProcessMessage(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			IpcPort ipcPort = null;
			if (authSet && !_channel.IsSecured)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Ipc_AuthenticationConfig"));
			}
			ipcPort = portCache.GetConnection(_portName, _channel.IsSecured, _tokenImpersonationLevel, _timeout);
			_ = (IMethodCallMessage)msg;
			_ = requestStream.Length;
			Stream stream = new PipeStream(ipcPort);
			IpcClientHandler ipcClientHandler = new IpcClientHandler(ipcPort, stream, this);
			ipcClientHandler.SendRequest(msg, requestHeaders, requestStream);
			responseHeaders = ipcClientHandler.ReadHeaders();
			responseStream = ipcClientHandler.GetResponseStream();
		}

		private IClientChannelSinkStack AsyncProcessMessage(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream, IClientChannelSinkStack sinkStack)
		{
			ProcessMessage(msg, requestHeaders, requestStream, out responseHeaders, out responseStream);
			return sinkStack;
		}

		public void AsyncProcessRequest(IClientChannelSinkStack sinkStack, IMessage msg, ITransportHeaders headers, Stream requestStream)
		{
			AsyncCallback callback = AsyncFinishedCallback;
			AsyncMessageDelegate asyncMessageDelegate = AsyncProcessMessage;
			asyncMessageDelegate.BeginInvoke(msg, headers, requestStream, out var _, out var _, sinkStack, callback, null);
		}

		private void AsyncFinishedCallback(IAsyncResult ar)
		{
			IClientChannelSinkStack clientChannelSinkStack = null;
			try
			{
				AsyncMessageDelegate asyncMessageDelegate = (AsyncMessageDelegate)((AsyncResult)ar).AsyncDelegate;
				clientChannelSinkStack = asyncMessageDelegate.EndInvoke(out var responseHeaders, out var responseStream, ar);
				clientChannelSinkStack.AsyncProcessResponse(responseHeaders, responseStream);
			}
			catch (Exception e)
			{
				try
				{
					clientChannelSinkStack?.DispatchException(e);
				}
				catch
				{
				}
			}
			catch
			{
				try
				{
					clientChannelSinkStack?.DispatchException(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")));
				}
				catch
				{
				}
			}
		}

		public void AsyncProcessResponse(IClientResponseChannelSinkStack sinkStack, object state, ITransportHeaders headers, Stream stream)
		{
			throw new NotSupportedException();
		}

		public Stream GetRequestStream(IMessage msg, ITransportHeaders headers)
		{
			return null;
		}
	}
	internal static class IpcChannelHelper
	{
		private const string _ipc = "ipc://";

		internal static bool StartsWithIpc(string url)
		{
			return StringHelper.StartsWithAsciiIgnoreCasePrefixLower(url, "ipc://");
		}

		internal static string ParseURL(string url, out string objectURI)
		{
			if (url == null)
			{
				throw new ArgumentNullException("url");
			}
			objectURI = null;
			if (StartsWithIpc(url))
			{
				int length = "ipc://".Length;
				length = url.IndexOf('/', length);
				if (-1 == length)
				{
					return url;
				}
				string result = url.Substring(0, length);
				objectURI = url.Substring(length);
				return result;
			}
			return null;
		}
	}
	internal class IpcServerHandler : TcpSocketHandler
	{
		private Stream _stream;

		protected Stream _requestStream;

		protected IpcPort _port;

		private RequestQueue _requestQueue;

		private bool _bOneWayRequest;

		private int _contentLength;

		internal IpcPort Port => _port;

		internal IpcServerHandler(IpcPort port, RequestQueue requestQueue, Stream stream)
			: base(null, requestQueue, stream)
		{
			_requestQueue = requestQueue;
			_port = port;
			_stream = stream;
		}

		internal Stream GetRequestStream()
		{
			_requestStream = new TcpFixedLengthReadingStream(this, _contentLength);
			return _requestStream;
		}

		internal ITransportHeaders ReadHeaders()
		{
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			ReadVersionAndOperation(out var operation);
			if (operation == 1)
			{
				_bOneWayRequest = true;
			}
			bool chunked = false;
			ReadContentLength(out chunked, out _contentLength);
			ReadToEndOfHeaders(baseTransportHeaders);
			return baseTransportHeaders;
		}

		protected new void ReadToEndOfHeaders(BaseTransportHeaders headers)
		{
			bool flag = false;
			string text = null;
			ushort num = ReadUInt16();
			while (true)
			{
				switch (num)
				{
				case 1:
				{
					string key = ReadCountedString();
					string text5 = (string)(headers[key] = ReadCountedString());
					break;
				}
				case 4:
				{
					ReadAndVerifyHeaderFormat("RequestUri", 1);
					string text2 = ReadCountedString();
					string objectURI;
					string text3 = IpcChannelHelper.ParseURL(text2, out objectURI);
					if (text3 == null)
					{
						objectURI = text2;
					}
					headers.RequestUri = objectURI;
					break;
				}
				case 2:
					ReadAndVerifyHeaderFormat("StatusCode", 3);
					if (ReadUInt16() != 0)
					{
						flag = true;
					}
					break;
				case 3:
					ReadAndVerifyHeaderFormat("StatusPhrase", 1);
					text = ReadCountedString();
					break;
				case 6:
				{
					ReadAndVerifyHeaderFormat("Content-Type", 1);
					string text7 = (headers.ContentType = ReadCountedString());
					break;
				}
				default:
				{
					byte b = (byte)ReadByte();
					switch (b)
					{
					case 1:
						ReadCountedString();
						break;
					case 2:
						ReadByte();
						break;
					case 3:
						ReadUInt16();
						break;
					case 4:
						ReadInt32();
						break;
					default:
						throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_UnknownHeaderType"), num, b));
					case 0:
						break;
					}
					break;
				}
				case 0:
					if (flag)
					{
						if (text == null)
						{
							text = "";
						}
						throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_GenericServerError"), text));
					}
					return;
				}
				num = ReadUInt16();
			}
		}

		private void ReadAndVerifyHeaderFormat(string headerName, byte expectedFormat)
		{
			byte b = (byte)ReadByte();
			if (b != expectedFormat)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_IncorrectHeaderFormat"), expectedFormat, headerName));
			}
		}

		protected override void PrepareForNewMessage()
		{
		}

		protected override void SendErrorMessageIfPossible(Exception e)
		{
			if (!_bOneWayRequest)
			{
				ChunkedMemoryStream chunkedMemoryStream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				WritePreambleAndVersion(chunkedMemoryStream);
				WriteUInt16(2, chunkedMemoryStream);
				WriteUInt16(0, chunkedMemoryStream);
				WriteInt32(0, chunkedMemoryStream);
				WriteUInt16(2, chunkedMemoryStream);
				WriteByte(3, chunkedMemoryStream);
				WriteUInt16(1, chunkedMemoryStream);
				WriteUInt16(3, chunkedMemoryStream);
				WriteByte(1, chunkedMemoryStream);
				WriteCountedString(e.ToString(), chunkedMemoryStream);
				WriteUInt16(5, chunkedMemoryStream);
				WriteByte(0, chunkedMemoryStream);
				WriteUInt16(0, chunkedMemoryStream);
				chunkedMemoryStream.WriteTo(NetStream);
				chunkedMemoryStream.Close();
			}
		}

		internal void SendResponse(ITransportHeaders headers, Stream contentStream)
		{
			if (!_bOneWayRequest)
			{
				ChunkedMemoryStream chunkedMemoryStream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				WritePreambleAndVersion(chunkedMemoryStream);
				WriteUInt16(2, chunkedMemoryStream);
				WriteUInt16(0, chunkedMemoryStream);
				WriteInt32((int)contentStream.Length, chunkedMemoryStream);
				WriteHeaders(headers, chunkedMemoryStream);
				chunkedMemoryStream.WriteTo(NetStream);
				chunkedMemoryStream.Close();
				StreamHelper.CopyStream(contentStream, NetStream);
				contentStream.Close();
			}
		}
	}
	internal class IpcClientHandler : IpcServerHandler
	{
		private bool _bOneWayRequest;

		private TcpReadingStream _responseStream;

		private int _contentLength;

		private bool _bChunked;

		private IpcClientTransportSink _sink;

		internal IpcClientHandler(IpcPort port, Stream stream, IpcClientTransportSink sink)
			: base(port, null, stream)
		{
			_sink = sink;
		}

		internal Stream GetResponseStream()
		{
			_responseStream = new TcpFixedLengthReadingStream(this, _contentLength);
			return _responseStream;
		}

		public new BaseTransportHeaders ReadHeaders()
		{
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			ReadVersionAndOperation(out var operation);
			if (operation != 2)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Tcp_ExpectingReplyOp"), operation.ToString(CultureInfo.CurrentCulture)));
			}
			ReadContentLength(out _bChunked, out _contentLength);
			ReadToEndOfHeaders(baseTransportHeaders);
			return baseTransportHeaders;
		}

		public override void OnInputStreamClosed()
		{
			if (_responseStream != null)
			{
				_responseStream.ReadToEnd();
				_responseStream = null;
			}
			ReturnToCache();
		}

		internal void ReturnToCache()
		{
			_sink.Cache.ReleaseConnection(_port);
		}

		internal void SendRequest(IMessage msg, ITransportHeaders headers, Stream contentStream)
		{
			IMethodCallMessage methodCallMessage = (IMethodCallMessage)msg;
			int value = (int)contentStream.Length;
			string uri = methodCallMessage.Uri;
			_bOneWayRequest = RemotingServices.IsOneWay(methodCallMessage.MethodBase);
			ChunkedMemoryStream chunkedMemoryStream = new ChunkedMemoryStream(CoreChannel.BufferPool);
			WritePreambleAndVersion(chunkedMemoryStream);
			if (!_bOneWayRequest)
			{
				WriteUInt16(0, chunkedMemoryStream);
			}
			else
			{
				WriteUInt16(1, chunkedMemoryStream);
			}
			WriteUInt16(0, chunkedMemoryStream);
			WriteInt32(value, chunkedMemoryStream);
			WriteUInt16(4, chunkedMemoryStream);
			WriteByte(1, chunkedMemoryStream);
			WriteCountedString(uri, chunkedMemoryStream);
			WriteHeaders(headers, chunkedMemoryStream);
			chunkedMemoryStream.WriteTo(NetStream);
			chunkedMemoryStream.Close();
			StreamHelper.CopyStream(contentStream, NetStream);
			contentStream.Close();
		}
	}
	internal class IpcPort : IDisposable
	{
		private const string prefix = "\\\\.\\pipe\\";

		private const string networkSidSddlForm = "S-1-5-2";

		private const string authenticatedUserSidSddlForm = "S-1-5-11";

		private PipeHandle _handle;

		private string _portName;

		private bool _cacheable;

		private static CommonSecurityDescriptor s_securityDescriptor = CreateSecurityDescriptor(null);

		private static readonly IOCompletionCallback IOCallback = AsyncFSCallback;

		private bool isDisposed;

		internal string Name => _portName;

		internal bool Cacheable
		{
			get
			{
				return _cacheable;
			}
			set
			{
				_cacheable = value;
			}
		}

		public bool IsDisposed => isDisposed;

		private IpcPort(string portName, PipeHandle handle)
		{
			_portName = portName;
			_handle = handle;
			_cacheable = true;
			ThreadPool.BindHandle(_handle.Handle);
		}

		internal static CommonSecurityDescriptor CreateSecurityDescriptor(SecurityIdentifier userSid)
		{
			SecurityIdentifier sid = new SecurityIdentifier("S-1-5-2");
			DiscretionaryAcl discretionaryAcl = new DiscretionaryAcl(isContainer: false, isDS: false, 1);
			discretionaryAcl.AddAccess(AccessControlType.Deny, sid, -1, InheritanceFlags.None, PropagationFlags.None);
			if (userSid != null)
			{
				discretionaryAcl.AddAccess(AccessControlType.Allow, userSid, -1, InheritanceFlags.None, PropagationFlags.None);
			}
			discretionaryAcl.AddAccess(AccessControlType.Allow, WindowsIdentity.GetCurrent().User, -1, InheritanceFlags.None, PropagationFlags.None);
			return new CommonSecurityDescriptor(isContainer: false, isDS: false, ControlFlags.OwnerDefaulted | ControlFlags.GroupDefaulted | ControlFlags.DiscretionaryAclPresent, null, null, null, discretionaryAcl);
		}

		internal static IpcPort Create(string portName, CommonSecurityDescriptor securityDescriptor, bool exclusive)
		{
			if (Environment.OSVersion.Platform != PlatformID.Win32NT)
			{
				throw new NotSupportedException(CoreChannel.GetResourceString("Remoting_Ipc_Win9x"));
			}
			PipeHandle pipeHandle = null;
			string lpName = "\\\\.\\pipe\\" + portName;
			SECURITY_ATTRIBUTES sECURITY_ATTRIBUTES = new SECURITY_ATTRIBUTES();
			sECURITY_ATTRIBUTES.nLength = Marshal.SizeOf(sECURITY_ATTRIBUTES);
			byte[] array = null;
			if (securityDescriptor == null)
			{
				securityDescriptor = s_securityDescriptor;
			}
			array = new byte[securityDescriptor.BinaryLength];
			securityDescriptor.GetBinaryForm(array, 0);
			GCHandle gCHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
			sECURITY_ATTRIBUTES.lpSecurityDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(array, 0);
			pipeHandle = NativePipe.CreateNamedPipe(lpName, 0x40000003u | (exclusive ? 524288u : 0u), 0u, 255u, 8192u, 8192u, uint.MaxValue, sECURITY_ATTRIBUTES);
			gCHandle.Free();
			if (pipeHandle.Handle.ToInt32() == -1)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_CreateIpcFailed"), GetMessage(lastWin32Error)));
			}
			return new IpcPort(portName, pipeHandle);
		}

		public bool WaitForConnect()
		{
			if (!NativePipe.ConnectNamedPipe(_handle, null))
			{
				return (long)Marshal.GetLastWin32Error() == 535;
			}
			return true;
		}

		internal static IpcPort Connect(string portName, bool secure, TokenImpersonationLevel impersonationLevel, int timeout)
		{
			string text = "\\\\.\\pipe\\" + portName;
			uint num = 1048576u;
			if (secure)
			{
				switch (impersonationLevel)
				{
				case TokenImpersonationLevel.None:
					num = 1048576u;
					break;
				case TokenImpersonationLevel.Identification:
					num = 1114112u;
					break;
				case TokenImpersonationLevel.Impersonation:
					num = 1179648u;
					break;
				case TokenImpersonationLevel.Delegation:
					num = 1245184u;
					break;
				}
			}
			int lastWin32Error;
			do
			{
				PipeHandle pipeHandle = NativePipe.CreateFile(text, 3221225472u, 3u, IntPtr.Zero, 3u, 0x40000080u | num, IntPtr.Zero);
				if (pipeHandle.Handle.ToInt32() != -1)
				{
					return new IpcPort(portName, pipeHandle);
				}
				lastWin32Error = Marshal.GetLastWin32Error();
				if ((long)lastWin32Error != 231)
				{
					throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_ConnectIpcFailed"), GetMessage(lastWin32Error)));
				}
			}
			while (NativePipe.WaitNamedPipe(text, timeout));
			throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_Busy"), GetMessage(lastWin32Error)));
		}

		internal static string GetMessage(int errorCode)
		{
			StringBuilder stringBuilder = new StringBuilder(512);
			if (NativePipe.FormatMessage(12800, NativePipe.NULL, errorCode, 0, stringBuilder, stringBuilder.Capacity, NativePipe.NULL) != 0)
			{
				return stringBuilder.ToString();
			}
			return string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_UnknownError_Num"), errorCode.ToString(CultureInfo.InvariantCulture));
		}

		internal void ImpersonateClient()
		{
			if (!NativePipe.ImpersonateNamedPipeClient(_handle))
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_ImpersonationFailed"), GetMessage(lastWin32Error)));
			}
		}

		internal unsafe int Read(byte[] data, int offset, int length)
		{
			bool flag = false;
			int lpNumberOfBytesRead = 0;
			fixed (byte* ptr = data)
			{
				flag = NativePipe.ReadFile(_handle, ptr + offset, length, ref lpNumberOfBytesRead, IntPtr.Zero);
			}
			if (!flag)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_ReadFailure"), GetMessage(lastWin32Error)));
			}
			return lpNumberOfBytesRead;
		}

		internal unsafe IAsyncResult BeginRead(byte[] data, int offset, int size, AsyncCallback callback, object state)
		{
			PipeAsyncResult pipeAsyncResult = new PipeAsyncResult(callback);
			Overlapped overlapped = new Overlapped(0, 0, IntPtr.Zero, pipeAsyncResult);
			NativeOverlapped* lpOverlapped = (pipeAsyncResult._overlapped = overlapped.UnsafePack(IOCallback, data));
			bool flag;
			fixed (byte* ptr = data)
			{
				flag = NativePipe.ReadFile(_handle, ptr + offset, size, IntPtr.Zero, lpOverlapped);
			}
			if (!flag)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if ((long)lastWin32Error == 109)
				{
					pipeAsyncResult.CallUserCallback();
				}
				else if ((long)lastWin32Error != 997)
				{
					throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_ReadFailure"), GetMessage(lastWin32Error)));
				}
			}
			return pipeAsyncResult;
		}

		private unsafe static void AsyncFSCallback(uint errorCode, uint numBytes, NativeOverlapped* pOverlapped)
		{
			Overlapped overlapped = Overlapped.Unpack(pOverlapped);
			PipeAsyncResult pipeAsyncResult = (PipeAsyncResult)overlapped.AsyncResult;
			pipeAsyncResult._numBytes = (int)numBytes;
			if ((ulong)errorCode == 109)
			{
				errorCode = 0u;
			}
			pipeAsyncResult._errorCode = (int)errorCode;
			AsyncCallback userCallback = pipeAsyncResult._userCallback;
			userCallback(pipeAsyncResult);
		}

		internal unsafe int EndRead(IAsyncResult iar)
		{
			PipeAsyncResult pipeAsyncResult = iar as PipeAsyncResult;
			NativeOverlapped* overlapped = pipeAsyncResult._overlapped;
			if (overlapped != null)
			{
				Overlapped.Free(overlapped);
			}
			if (pipeAsyncResult._errorCode != 0)
			{
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_ReadFailure"), GetMessage(pipeAsyncResult._errorCode)));
			}
			return pipeAsyncResult._numBytes;
		}

		internal unsafe void Write(byte[] data, int offset, int size)
		{
			int lpNumberOfBytesWritten = 0;
			bool flag = false;
			fixed (byte* ptr = data)
			{
				flag = NativePipe.WriteFile(_handle, ptr + offset, size, ref lpNumberOfBytesWritten, IntPtr.Zero);
			}
			if (!flag)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Ipc_WriteFailure"), GetMessage(lastWin32Error)));
			}
		}

		~IpcPort()
		{
			Dispose();
		}

		public void Dispose()
		{
			if (!isDisposed)
			{
				_handle.Close();
				isDisposed = true;
				GC.SuppressFinalize(this);
			}
		}
	}
	internal class PipeAsyncResult : IAsyncResult
	{
		internal unsafe NativeOverlapped* _overlapped;

		internal AsyncCallback _userCallback;

		internal int _numBytes;

		internal int _errorCode;

		public bool IsCompleted
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public WaitHandle AsyncWaitHandle
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public object AsyncState
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public bool CompletedSynchronously => false;

		internal PipeAsyncResult(AsyncCallback callback)
		{
			_userCallback = callback;
		}

		internal void CallUserCallback()
		{
			ThreadPool.QueueUserWorkItem(CallUserCallbackWorker);
		}

		private void CallUserCallbackWorker(object callbackState)
		{
			_userCallback(this);
		}
	}
	internal sealed class PipeStream : Stream
	{
		private IpcPort _port;

		private int _timeout;

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override long Position
		{
			get
			{
				throw new NotSupportedException();
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public PipeStream(IpcPort port)
		{
			if (port == null)
			{
				throw new ArgumentNullException("port");
			}
			_port = port;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override int Read(byte[] buffer, int offset, int size)
		{
			if (_timeout <= 0)
			{
				return _port.Read(buffer, offset, size);
			}
			IAsyncResult asyncResult = _port.BeginRead(buffer, offset, size, null, null);
			if (_timeout > 0 && !asyncResult.IsCompleted)
			{
				asyncResult.AsyncWaitHandle.WaitOne(_timeout, exitContext: false);
				if (!asyncResult.IsCompleted)
				{
					throw new RemotingTimeoutException();
				}
			}
			return _port.EndRead(asyncResult);
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			_port.Write(buffer, offset, count);
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing)
				{
					_port.Dispose();
				}
			}
			finally
			{
				base.Dispose(disposing);
			}
		}

		public override void Flush()
		{
		}

		public override IAsyncResult BeginRead(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
		{
			return _port.BeginRead(buffer, offset, size, callback, state);
		}

		public override int EndRead(IAsyncResult asyncResult)
		{
			return _port.EndRead(asyncResult);
		}

		public override IAsyncResult BeginWrite(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
		{
			throw new NotSupportedException();
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}
	}
	internal class PortConnection
	{
		private IpcPort _port;

		private DateTime _socketLastUsed;

		internal IpcPort Port => _port;

		internal DateTime LastUsed => _socketLastUsed;

		internal PortConnection(IpcPort port)
		{
			_port = port;
			_socketLastUsed = DateTime.Now;
		}
	}
	internal class ConnectionCache
	{
		private static Hashtable _connections;

		private static RegisteredWaitHandle _registeredWaitHandle;

		private static WaitOrTimerCallback _socketTimeoutDelegate;

		private static AutoResetEvent _socketTimeoutWaitHandle;

		private static TimeSpan _socketTimeoutPollTime;

		private static TimeSpan _portLifetime;

		static ConnectionCache()
		{
			_connections = new Hashtable();
			_socketTimeoutPollTime = TimeSpan.FromSeconds(10.0);
			_portLifetime = TimeSpan.FromSeconds(10.0);
			InitializeConnectionTimeoutHandler();
		}

		private static void InitializeConnectionTimeoutHandler()
		{
			_socketTimeoutDelegate = TimeoutConnections;
			_socketTimeoutWaitHandle = new AutoResetEvent(initialState: false);
			_registeredWaitHandle = ThreadPool.UnsafeRegisterWaitForSingleObject(_socketTimeoutWaitHandle, _socketTimeoutDelegate, "IpcConnectionTimeout", _socketTimeoutPollTime, executeOnlyOnce: true);
		}

		private static void TimeoutConnections(object state, bool wasSignalled)
		{
			_ = DateTime.UtcNow;
			lock (_connections)
			{
				foreach (DictionaryEntry connection in _connections)
				{
					PortConnection portConnection = (PortConnection)connection.Value;
					if (DateTime.Now - portConnection.LastUsed > _portLifetime)
					{
						portConnection.Port.Dispose();
					}
				}
			}
			_registeredWaitHandle.Unregister(null);
			_registeredWaitHandle = ThreadPool.UnsafeRegisterWaitForSingleObject(_socketTimeoutWaitHandle, _socketTimeoutDelegate, "IpcConnectionTimeout", _socketTimeoutPollTime, executeOnlyOnce: true);
		}

		public IpcPort GetConnection(string portName, bool secure, TokenImpersonationLevel level, int timeout)
		{
			PortConnection portConnection = null;
			lock (_connections)
			{
				bool flag = true;
				if (secure)
				{
					try
					{
						WindowsIdentity current = WindowsIdentity.GetCurrent(ifImpersonating: true);
						if (current != null)
						{
							flag = false;
							current.Dispose();
						}
					}
					catch (Exception)
					{
						flag = false;
					}
				}
				if (flag)
				{
					portConnection = (PortConnection)_connections[portName];
				}
				if (portConnection == null || portConnection.Port.IsDisposed)
				{
					portConnection = new PortConnection(IpcPort.Connect(portName, secure, level, timeout));
					portConnection.Port.Cacheable = flag;
				}
				else
				{
					_connections.Remove(portName);
				}
			}
			return portConnection.Port;
		}

		public void ReleaseConnection(IpcPort port)
		{
			string name = port.Name;
			PortConnection portConnection = (PortConnection)_connections[name];
			if (port.Cacheable && (portConnection == null || portConnection.Port.IsDisposed))
			{
				lock (_connections)
				{
					_connections[name] = new PortConnection(port);
					return;
				}
			}
			port.Dispose();
		}
	}
	internal class PipeHandle : CriticalHandleMinusOneIsInvalid
	{
		public IntPtr Handle => handle;

		internal PipeHandle()
		{
		}

		internal PipeHandle(IntPtr handle)
		{
			SetHandle(handle);
		}

		protected override bool ReleaseHandle()
		{
			return NativePipe.CloseHandle(handle) != 0;
		}
	}
	[StructLayout(LayoutKind.Sequential)]
	internal class SECURITY_ATTRIBUTES
	{
		internal int nLength;

		internal IntPtr lpSecurityDescriptor = IntPtr.Zero;

		internal int bInheritHandle;
	}
	[SuppressUnmanagedCodeSecurity]
	internal static class NativePipe
	{
		private const string Kernel32 = "kernel32.dll";

		private const string AdvApi32 = "advapi32.dll";

		public const uint PIPE_ACCESS_OUTBOUND = 2u;

		public const uint PIPE_ACCESS_DUPLEX = 3u;

		public const uint PIPE_ACCESS_INBOUND = 1u;

		public const uint PIPE_WAIT = 0u;

		public const uint PIPE_NOWAIT = 1u;

		public const uint PIPE_READMODE_BYTE = 0u;

		public const uint PIPE_READMODE_MESSAGE = 2u;

		public const uint PIPE_TYPE_BYTE = 0u;

		public const uint PIPE_TYPE_MESSAGE = 4u;

		public const uint PIPE_CLIENT_END = 0u;

		public const uint PIPE_SERVER_END = 1u;

		public const uint FILE_FLAG_OVERLAPPED = 1073741824u;

		public const uint FILE_ATTRIBUTE_NORMAL = 128u;

		public const uint FILE_SHARE_READ = 1u;

		public const uint FILE_SHARE_WRITE = 2u;

		public const uint PIPE_UNLIMITED_INSTANCES = 255u;

		public const uint SECURITY_SQOS_PRESENT = 1048576u;

		public const uint SECURITY_ANONYMOUS = 0u;

		public const uint SECURITY_IDENTIFICATION = 65536u;

		public const uint SECURITY_IMPERSONATION = 131072u;

		public const uint SECURITY_DELEGATION = 196608u;

		internal const int FORMAT_MESSAGE_IGNORE_INSERTS = 512;

		internal const int FORMAT_MESSAGE_FROM_SYSTEM = 4096;

		internal const int FORMAT_MESSAGE_ARGUMENT_ARRAY = 8192;

		public const uint NMPWAIT_WAIT_FOREVER = uint.MaxValue;

		public const uint NMPWAIT_NOWAIT = 1u;

		public const uint NMPWAIT_USE_DEFAULT_WAIT = 0u;

		public const uint GENERIC_READ = 2147483648u;

		public const uint GENERIC_WRITE = 1073741824u;

		public const uint GENERIC_EXECUTE = 536870912u;

		public const uint GENERIC_ALL = 268435456u;

		public const uint CREATE_NEW = 1u;

		public const uint CREATE_ALWAYS = 2u;

		public const uint OPEN_EXISTING = 3u;

		public const uint OPEN_ALWAYS = 4u;

		public const uint TRUNCATE_EXISTING = 5u;

		public const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 524288u;

		public const int INVALID_HANDLE_VALUE = -1;

		public const long ERROR_BROKEN_PIPE = 109L;

		public const long ERROR_IO_PENDING = 997L;

		public const long ERROR_PIPE_BUSY = 231L;

		public const long ERROR_NO_DATA = 232L;

		public const long ERROR_PIPE_NOT_CONNECTED = 233L;

		public const long ERROR_PIPE_CONNECTED = 535L;

		public const long ERROR_PIPE_LISTENING = 536L;

		internal static readonly IntPtr NULL = IntPtr.Zero;

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern PipeHandle CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, SECURITY_ATTRIBUTES pipeSecurityDescriptor);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool ConnectNamedPipe(PipeHandle hNamedPipe, Overlapped lpOverlapped);

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool ImpersonateNamedPipeClient(PipeHandle hNamedPipe);

		[DllImport("advapi32.dll")]
		public static extern bool RevertToSelf();

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern PipeHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr attr, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

		[DllImport("kernel32.dll", SetLastError = true)]
		public unsafe static extern bool ReadFile(PipeHandle hFile, byte* lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr mustBeZero);

		[DllImport("kernel32.dll", SetLastError = true)]
		public unsafe static extern bool ReadFile(PipeHandle hFile, byte* lpBuffer, int nNumberOfBytesToRead, IntPtr numBytesRead_mustBeZero, NativeOverlapped* lpOverlapped);

		[DllImport("kernel32.dll", SetLastError = true)]
		public unsafe static extern bool WriteFile(PipeHandle hFile, byte* lpBuffer, int nNumberOfBytesToWrite, ref int lpNumberOfBytesWritten, IntPtr lpOverlapped);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool WaitNamedPipe(string name, int timeout);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern int FormatMessage(int dwFlags, IntPtr lpSource, int dwMessageId, int dwLanguageId, StringBuilder lpBuffer, int nSize, IntPtr va_list_arguments);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern int CloseHandle(IntPtr hObject);
	}
}
namespace System.Runtime.Remoting.Channels
{
	public class BinaryClientFormatterSinkProvider : IClientFormatterSinkProvider, IClientChannelSinkProvider
	{
		private IClientChannelSinkProvider _next;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		public IClientChannelSinkProvider Next
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _next;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_next = value;
			}
		}

		public BinaryClientFormatterSinkProvider()
		{
		}

		public BinaryClientFormatterSinkProvider(IDictionary properties, ICollection providerData)
		{
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch (property.Key.ToString())
					{
					case "includeVersions":
						_includeVersioning = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "strictBinding":
						_strictBinding = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
			CoreChannel.VerifyNoProviderData(GetType().Name, providerData);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IClientChannelSink CreateSink(IChannelSender channel, string url, object remoteChannelData)
		{
			IClientChannelSink clientChannelSink = null;
			if (_next != null)
			{
				clientChannelSink = _next.CreateSink(channel, url, remoteChannelData);
				if (clientChannelSink == null)
				{
					return null;
				}
			}
			SinkChannelProtocol channelProtocol = CoreChannel.DetermineChannelProtocol(channel);
			BinaryClientFormatterSink binaryClientFormatterSink = new BinaryClientFormatterSink(clientChannelSink);
			binaryClientFormatterSink.IncludeVersioning = _includeVersioning;
			binaryClientFormatterSink.StrictBinding = _strictBinding;
			binaryClientFormatterSink.ChannelProtocol = channelProtocol;
			return binaryClientFormatterSink;
		}
	}
	public class BinaryClientFormatterSink : IClientFormatterSink, IMessageSink, IClientChannelSink, IChannelSinkBase
	{
		private IClientChannelSink _nextSink;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		private SinkChannelProtocol _channelProtocol = SinkChannelProtocol.Other;

		internal bool IncludeVersioning
		{
			set
			{
				_includeVersioning = value;
			}
		}

		internal bool StrictBinding
		{
			set
			{
				_strictBinding = value;
			}
		}

		internal SinkChannelProtocol ChannelProtocol
		{
			set
			{
				_channelProtocol = value;
			}
		}

		public IMessageSink NextSink
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				throw new NotSupportedException();
			}
		}

		public IClientChannelSink NextChannelSink
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _nextSink;
			}
		}

		public IDictionary Properties
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return null;
			}
		}

		public BinaryClientFormatterSink(IClientChannelSink nextSink)
		{
			_nextSink = nextSink;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IMessage SyncProcessMessage(IMessage msg)
		{
			IMethodCallMessage mcm = msg as IMethodCallMessage;
			try
			{
				SerializeMessage(msg, out var headers, out var stream);
				_nextSink.ProcessMessage(msg, headers, stream, out var responseHeaders, out var responseStream);
				if (responseHeaders == null)
				{
					throw new ArgumentNullException("returnHeaders");
				}
				return DeserializeMessage(mcm, responseHeaders, responseStream);
			}
			catch (Exception e)
			{
				return new ReturnMessage(e, mcm);
			}
			catch
			{
				return new ReturnMessage(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")), mcm);
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IMessageCtrl AsyncProcessMessage(IMessage msg, IMessageSink replySink)
		{
			IMethodCallMessage mcm = (IMethodCallMessage)msg;
			try
			{
				SerializeMessage(msg, out var headers, out var stream);
				ClientChannelSinkStack clientChannelSinkStack = new ClientChannelSinkStack(replySink);
				clientChannelSinkStack.Push(this, msg);
				_nextSink.AsyncProcessRequest(clientChannelSinkStack, msg, headers, stream);
			}
			catch (Exception e)
			{
				IMessage msg2 = new ReturnMessage(e, mcm);
				replySink?.SyncProcessMessage(msg2);
			}
			catch
			{
				IMessage msg2 = new ReturnMessage(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")), mcm);
				replySink?.SyncProcessMessage(msg2);
			}
			return null;
		}

		private void SerializeMessage(IMessage msg, out ITransportHeaders headers, out Stream stream)
		{
			((BaseTransportHeaders)(headers = new BaseTransportHeaders())).ContentType = "application/octet-stream";
			if (_channelProtocol == SinkChannelProtocol.Http)
			{
				headers["__RequestVerb"] = "POST";
			}
			bool flag = false;
			stream = _nextSink.GetRequestStream(msg, headers);
			if (stream == null)
			{
				stream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				flag = true;
			}
			CoreChannel.SerializeBinaryMessage(msg, stream, _includeVersioning);
			if (flag)
			{
				stream.Position = 0L;
			}
		}

		private IMessage DeserializeMessage(IMethodCallMessage mcm, ITransportHeaders headers, Stream stream)
		{
			IMessage result = CoreChannel.DeserializeBinaryResponseMessage(stream, mcm, _strictBinding);
			stream.Close();
			return result;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void ProcessMessage(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			throw new NotSupportedException();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AsyncProcessRequest(IClientChannelSinkStack sinkStack, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			throw new NotSupportedException();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AsyncProcessResponse(IClientResponseChannelSinkStack sinkStack, object state, ITransportHeaders headers, Stream stream)
		{
			IMethodCallMessage mcm = (IMethodCallMessage)state;
			IMessage msg = DeserializeMessage(mcm, headers, stream);
			sinkStack.DispatchReplyMessage(msg);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public Stream GetRequestStream(IMessage msg, ITransportHeaders headers)
		{
			throw new NotSupportedException();
		}
	}
	public class BinaryServerFormatterSinkProvider : IServerFormatterSinkProvider, IServerChannelSinkProvider
	{
		private IServerChannelSinkProvider _next;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		private TypeFilterLevel _formatterSecurityLevel = TypeFilterLevel.Low;

		public IServerChannelSinkProvider Next
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _next;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_next = value;
			}
		}

		[ComVisible(false)]
		public TypeFilterLevel TypeFilterLevel
		{
			get
			{
				return _formatterSecurityLevel;
			}
			set
			{
				_formatterSecurityLevel = value;
			}
		}

		public BinaryServerFormatterSinkProvider()
		{
		}

		public BinaryServerFormatterSinkProvider(IDictionary properties, ICollection providerData)
		{
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch (property.Key.ToString())
					{
					case "includeVersions":
						_includeVersioning = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "strictBinding":
						_strictBinding = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "typeFilterLevel":
						_formatterSecurityLevel = (TypeFilterLevel)Enum.Parse(typeof(TypeFilterLevel), (string)property.Value);
						break;
					}
				}
			}
			CoreChannel.VerifyNoProviderData(GetType().Name, providerData);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void GetChannelData(IChannelDataStore channelData)
		{
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IServerChannelSink CreateSink(IChannelReceiver channel)
		{
			if (channel == null)
			{
				throw new ArgumentNullException("channel");
			}
			IServerChannelSink nextSink = null;
			if (_next != null)
			{
				nextSink = _next.CreateSink(channel);
			}
			BinaryServerFormatterSink.Protocol protocol = BinaryServerFormatterSink.Protocol.Other;
			string strB = channel.GetUrlsForUri("")[0];
			if (string.Compare("http", 0, strB, 0, 4, StringComparison.OrdinalIgnoreCase) == 0)
			{
				protocol = BinaryServerFormatterSink.Protocol.Http;
			}
			BinaryServerFormatterSink binaryServerFormatterSink = new BinaryServerFormatterSink(protocol, nextSink, channel);
			binaryServerFormatterSink.TypeFilterLevel = _formatterSecurityLevel;
			binaryServerFormatterSink.IncludeVersioning = _includeVersioning;
			binaryServerFormatterSink.StrictBinding = _strictBinding;
			return binaryServerFormatterSink;
		}
	}
	public class BinaryServerFormatterSink : IServerChannelSink, IChannelSinkBase
	{
		[Serializable]
		public enum Protocol
		{
			Http,
			Other
		}

		private IServerChannelSink _nextSink;

		private Protocol _protocol;

		private IChannelReceiver _receiver;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		private TypeFilterLevel _formatterSecurityLevel = TypeFilterLevel.Full;

		private string lastUri;

		internal bool IncludeVersioning
		{
			set
			{
				_includeVersioning = value;
			}
		}

		internal bool StrictBinding
		{
			set
			{
				_strictBinding = value;
			}
		}

		[ComVisible(false)]
		public TypeFilterLevel TypeFilterLevel
		{
			get
			{
				return _formatterSecurityLevel;
			}
			set
			{
				_formatterSecurityLevel = value;
			}
		}

		public IServerChannelSink NextChannelSink
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _nextSink;
			}
		}

		public IDictionary Properties
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return null;
			}
		}

		public BinaryServerFormatterSink(Protocol protocol, IServerChannelSink nextSink, IChannelReceiver receiver)
		{
			if (receiver == null)
			{
				throw new ArgumentNullException("receiver");
			}
			_nextSink = nextSink;
			_protocol = protocol;
			_receiver = receiver;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public ServerProcessing ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, out IMessage responseMsg, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			if (requestMsg != null)
			{
				return _nextSink.ProcessMessage(sinkStack, requestMsg, requestHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
			}
			if (requestHeaders == null)
			{
				throw new ArgumentNullException("requestHeaders");
			}
			BaseTransportHeaders baseTransportHeaders = requestHeaders as BaseTransportHeaders;
			responseHeaders = null;
			responseStream = null;
			string text = null;
			string value = null;
			bool flag = true;
			string text2 = null;
			text2 = ((baseTransportHeaders == null) ? (requestHeaders["Content-Type"] as string) : baseTransportHeaders.ContentType);
			if (text2 != null)
			{
				HttpChannelHelper.ParseContentType(text2, out value, out var _);
			}
			if (value != null && string.CompareOrdinal(value, "application/octet-stream") != 0)
			{
				flag = false;
			}
			if (_protocol == Protocol.Http)
			{
				text = (string)requestHeaders["__RequestVerb"];
				if (!text.Equals("POST") && !text.Equals("M-POST"))
				{
					flag = false;
				}
			}
			if (!flag)
			{
				if (_nextSink != null)
				{
					return _nextSink.ProcessMessage(sinkStack, null, requestHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
				}
				if (_protocol == Protocol.Http)
				{
					responseHeaders = new TransportHeaders();
					responseHeaders["__HttpStatusCode"] = "400";
					responseHeaders["__HttpReasonPhrase"] = "Bad Request";
					responseStream = null;
					responseMsg = null;
					return ServerProcessing.Complete;
				}
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Channels_InvalidRequestFormat"));
			}
			try
			{
				string text3 = null;
				bool flag2 = true;
				object obj = requestHeaders["__CustomErrorsEnabled"];
				if (obj != null && obj is bool)
				{
					flag2 = (bool)obj;
				}
				CallContext.SetData("__CustomErrorsEnabled", flag2);
				text3 = ((baseTransportHeaders == null) ? ((string)requestHeaders["__RequestUri"]) : baseTransportHeaders.RequestUri);
				if (text3 != lastUri && RemotingServices.GetServerTypeForUri(text3) == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_ChnlSink_UriNotPublished"));
				}
				lastUri = text3;
				PermissionSet permissionSet = null;
				if (TypeFilterLevel != TypeFilterLevel.Full)
				{
					permissionSet = new PermissionSet(PermissionState.None);
					permissionSet.SetPermission(new SecurityPermission(SecurityPermissionFlag.SerializationFormatter));
				}
				try
				{
					permissionSet?.PermitOnly();
					requestMsg = CoreChannel.DeserializeBinaryRequestMessage(text3, requestStream, _strictBinding, TypeFilterLevel);
				}
				finally
				{
					if (permissionSet != null)
					{
						CodeAccessPermission.RevertPermitOnly();
					}
				}
				requestStream.Close();
				if (requestMsg == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_DeserializeMessage"));
				}
				if (requestMsg is MarshalByRefObject && !AppSettings.AllowTransparentProxyMessage)
				{
					requestMsg = null;
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_DeserializeMessage"), new NotSupportedException(AppSettings.AllowTransparentProxyMessageFwLink));
				}
				sinkStack.Push(this, null);
				ServerProcessing serverProcessing = _nextSink.ProcessMessage(sinkStack, requestMsg, requestHeaders, null, out responseMsg, out responseHeaders, out responseStream);
				if (responseStream != null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_ChnlSink_WantNullResponseStream"));
				}
				switch (serverProcessing)
				{
				case ServerProcessing.Complete:
					if (responseMsg == null)
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_DispatchMessage"));
					}
					sinkStack.Pop(this);
					SerializeResponse(sinkStack, responseMsg, ref responseHeaders, out responseStream);
					return serverProcessing;
				case ServerProcessing.OneWay:
					sinkStack.Pop(this);
					return serverProcessing;
				case ServerProcessing.Async:
					sinkStack.Store(this, null);
					return serverProcessing;
				default:
					return serverProcessing;
				}
			}
			catch (Exception e)
			{
				ServerProcessing serverProcessing = ServerProcessing.Complete;
				responseMsg = new ReturnMessage(e, (IMethodCallMessage)((requestMsg == null) ? new ErrorMessage() : requestMsg));
				CallContext.SetData("__ClientIsClr", true);
				responseStream = (MemoryStream)CoreChannel.SerializeBinaryMessage(responseMsg, _includeVersioning);
				CallContext.FreeNamedDataSlot("__ClientIsClr");
				responseStream.Position = 0L;
				responseHeaders = new TransportHeaders();
				if (_protocol == Protocol.Http)
				{
					responseHeaders["Content-Type"] = "application/octet-stream";
					return serverProcessing;
				}
				return serverProcessing;
			}
			catch
			{
				ServerProcessing serverProcessing = ServerProcessing.Complete;
				responseMsg = new ReturnMessage(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")), (IMethodCallMessage)((requestMsg == null) ? new ErrorMessage() : requestMsg));
				CallContext.SetData("__ClientIsClr", true);
				responseStream = (MemoryStream)CoreChannel.SerializeBinaryMessage(responseMsg, _includeVersioning);
				CallContext.FreeNamedDataSlot("__ClientIsClr");
				responseStream.Position = 0L;
				responseHeaders = new TransportHeaders();
				if (_protocol == Protocol.Http)
				{
					responseHeaders["Content-Type"] = "application/octet-stream";
					return serverProcessing;
				}
				return serverProcessing;
			}
			finally
			{
				CallContext.FreeNamedDataSlot("__CustomErrorsEnabled");
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AsyncProcessResponse(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			SerializeResponse(sinkStack, msg, ref headers, out stream);
			sinkStack.AsyncProcessResponse(msg, headers, stream);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		private void SerializeResponse(IServerResponseChannelSinkStack sinkStack, IMessage msg, ref ITransportHeaders headers, out Stream stream)
		{
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			if (headers != null)
			{
				foreach (DictionaryEntry header in headers)
				{
					baseTransportHeaders[header.Key] = header.Value;
				}
			}
			headers = baseTransportHeaders;
			if (_protocol == Protocol.Http)
			{
				baseTransportHeaders.ContentType = "application/octet-stream";
			}
			bool flag = false;
			stream = sinkStack.GetResponseStream(msg, headers);
			if (stream == null)
			{
				stream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				flag = true;
			}
			bool bBashedUrl = CoreChannel.SetupUrlBashingForIisSslIfNecessary();
			try
			{
				CallContext.SetData("__ClientIsClr", true);
				CoreChannel.SerializeBinaryMessage(msg, stream, _includeVersioning);
			}
			finally
			{
				CallContext.FreeNamedDataSlot("__ClientIsClr");
				CoreChannel.CleanupUrlBashingForIisSslIfNecessary(bBashedUrl);
			}
			if (flag)
			{
				stream.Position = 0L;
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public Stream GetResponseStream(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers)
		{
			throw new NotSupportedException();
		}
	}
	public class SoapClientFormatterSinkProvider : IClientFormatterSinkProvider, IClientChannelSinkProvider
	{
		private IClientChannelSinkProvider _next;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		public IClientChannelSinkProvider Next
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _next;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_next = value;
			}
		}

		public SoapClientFormatterSinkProvider()
		{
		}

		public SoapClientFormatterSinkProvider(IDictionary properties, ICollection providerData)
		{
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch (property.Key.ToString())
					{
					case "includeVersions":
						_includeVersioning = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "strictBinding":
						_strictBinding = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					}
				}
			}
			CoreChannel.VerifyNoProviderData(GetType().Name, providerData);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IClientChannelSink CreateSink(IChannelSender channel, string url, object remoteChannelData)
		{
			IClientChannelSink clientChannelSink = null;
			if (_next != null)
			{
				clientChannelSink = _next.CreateSink(channel, url, remoteChannelData);
				if (clientChannelSink == null)
				{
					return null;
				}
			}
			SinkChannelProtocol channelProtocol = CoreChannel.DetermineChannelProtocol(channel);
			SoapClientFormatterSink soapClientFormatterSink = new SoapClientFormatterSink(clientChannelSink);
			soapClientFormatterSink.IncludeVersioning = _includeVersioning;
			soapClientFormatterSink.StrictBinding = _strictBinding;
			soapClientFormatterSink.ChannelProtocol = channelProtocol;
			return soapClientFormatterSink;
		}
	}
	public class SoapClientFormatterSink : IClientFormatterSink, IMessageSink, IClientChannelSink, IChannelSinkBase
	{
		private IClientChannelSink _nextSink;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		private SinkChannelProtocol _channelProtocol = SinkChannelProtocol.Other;

		internal bool IncludeVersioning
		{
			set
			{
				_includeVersioning = value;
			}
		}

		internal bool StrictBinding
		{
			set
			{
				_strictBinding = value;
			}
		}

		internal SinkChannelProtocol ChannelProtocol
		{
			set
			{
				_channelProtocol = value;
			}
		}

		public IMessageSink NextSink
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				throw new NotSupportedException();
			}
		}

		public IClientChannelSink NextChannelSink
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _nextSink;
			}
		}

		public IDictionary Properties
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return null;
			}
		}

		public SoapClientFormatterSink(IClientChannelSink nextSink)
		{
			_nextSink = nextSink;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IMessage SyncProcessMessage(IMessage msg)
		{
			IMethodCallMessage mcm = (IMethodCallMessage)msg;
			try
			{
				SerializeMessage(mcm, out var headers, out var stream);
				_nextSink.ProcessMessage(msg, headers, stream, out var responseHeaders, out var responseStream);
				if (responseHeaders == null)
				{
					throw new ArgumentNullException("returnHeaders");
				}
				return DeserializeMessage(mcm, responseHeaders, responseStream);
			}
			catch (Exception e)
			{
				return new ReturnMessage(e, mcm);
			}
			catch
			{
				return new ReturnMessage(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")), mcm);
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IMessageCtrl AsyncProcessMessage(IMessage msg, IMessageSink replySink)
		{
			IMethodCallMessage methodCallMessage = (IMethodCallMessage)msg;
			try
			{
				SerializeMessage(methodCallMessage, out var headers, out var stream);
				ClientChannelSinkStack clientChannelSinkStack = new ClientChannelSinkStack(replySink);
				clientChannelSinkStack.Push(this, methodCallMessage);
				_nextSink.AsyncProcessRequest(clientChannelSinkStack, msg, headers, stream);
			}
			catch (Exception e)
			{
				IMessage msg2 = new ReturnMessage(e, methodCallMessage);
				replySink?.SyncProcessMessage(msg2);
			}
			catch
			{
				IMessage msg2 = new ReturnMessage(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")), methodCallMessage);
				replySink?.SyncProcessMessage(msg2);
			}
			return null;
		}

		private void SerializeMessage(IMethodCallMessage mcm, out ITransportHeaders headers, out Stream stream)
		{
			BaseTransportHeaders baseTransportHeaders = (BaseTransportHeaders)(headers = new BaseTransportHeaders());
			MethodBase methodBase = mcm.MethodBase;
			headers["SOAPAction"] = '"' + HttpEncodingHelper.EncodeUriAsXLinkHref(SoapServices.GetSoapActionFromMethodBase(methodBase)) + '"';
			baseTransportHeaders.ContentType = "text/xml; charset=\"utf-8\"";
			if (_channelProtocol == SinkChannelProtocol.Http)
			{
				headers["__RequestVerb"] = "POST";
			}
			bool flag = false;
			stream = _nextSink.GetRequestStream(mcm, headers);
			if (stream == null)
			{
				stream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				flag = true;
			}
			CoreChannel.SerializeSoapMessage(mcm, stream, _includeVersioning);
			if (flag)
			{
				stream.Position = 0L;
			}
		}

		private IMessage DeserializeMessage(IMethodCallMessage mcm, ITransportHeaders headers, Stream stream)
		{
			Header[] h = new Header[3]
			{
				new Header("__TypeName", mcm.TypeName),
				new Header("__MethodName", mcm.MethodName),
				new Header("__MethodSignature", mcm.MethodSignature)
			};
			string contentType = headers["Content-Type"] as string;
			HttpChannelHelper.ParseContentType(contentType, out var value, out var _);
			IMessage result;
			if (string.Compare(value, "text/xml", StringComparison.Ordinal) == 0)
			{
				result = CoreChannel.DeserializeSoapResponseMessage(stream, mcm, h, _strictBinding);
			}
			else
			{
				int num = 1024;
				byte[] array = new byte[num];
				StringBuilder stringBuilder = new StringBuilder();
				for (int num2 = stream.Read(array, 0, num); num2 > 0; num2 = stream.Read(array, 0, num))
				{
					stringBuilder.Append(Encoding.ASCII.GetString(array, 0, num2));
				}
				result = new ReturnMessage(new RemotingException(stringBuilder.ToString()), mcm);
			}
			stream.Close();
			return result;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void ProcessMessage(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			throw new NotSupportedException();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AsyncProcessRequest(IClientChannelSinkStack sinkStack, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			throw new NotSupportedException();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AsyncProcessResponse(IClientResponseChannelSinkStack sinkStack, object state, ITransportHeaders headers, Stream stream)
		{
			IMethodCallMessage mcm = (IMethodCallMessage)state;
			IMessage msg = DeserializeMessage(mcm, headers, stream);
			sinkStack.DispatchReplyMessage(msg);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public Stream GetRequestStream(IMessage msg, ITransportHeaders headers)
		{
			throw new NotSupportedException();
		}
	}
	public class SoapServerFormatterSinkProvider : IServerFormatterSinkProvider, IServerChannelSinkProvider
	{
		private IServerChannelSinkProvider _next;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		private TypeFilterLevel _formatterSecurityLevel = TypeFilterLevel.Low;

		public IServerChannelSinkProvider Next
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _next;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_next = value;
			}
		}

		[ComVisible(false)]
		public TypeFilterLevel TypeFilterLevel
		{
			get
			{
				return _formatterSecurityLevel;
			}
			set
			{
				_formatterSecurityLevel = value;
			}
		}

		public SoapServerFormatterSinkProvider()
		{
		}

		public SoapServerFormatterSinkProvider(IDictionary properties, ICollection providerData)
		{
			if (properties != null)
			{
				foreach (DictionaryEntry property in properties)
				{
					switch (property.Key.ToString())
					{
					case "includeVersions":
						_includeVersioning = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "strictBinding":
						_strictBinding = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
						break;
					case "typeFilterLevel":
						_formatterSecurityLevel = (TypeFilterLevel)Enum.Parse(typeof(TypeFilterLevel), (string)property.Value);
						break;
					}
				}
			}
			CoreChannel.VerifyNoProviderData(GetType().Name, providerData);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void GetChannelData(IChannelDataStore channelData)
		{
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IServerChannelSink CreateSink(IChannelReceiver channel)
		{
			if (channel == null)
			{
				throw new ArgumentNullException("channel");
			}
			IServerChannelSink nextSink = null;
			if (_next != null)
			{
				nextSink = _next.CreateSink(channel);
			}
			SoapServerFormatterSink.Protocol protocol = SoapServerFormatterSink.Protocol.Other;
			string strB = channel.GetUrlsForUri("")[0];
			if (string.Compare("http", 0, strB, 0, 4, StringComparison.OrdinalIgnoreCase) == 0)
			{
				protocol = SoapServerFormatterSink.Protocol.Http;
			}
			SoapServerFormatterSink soapServerFormatterSink = new SoapServerFormatterSink(protocol, nextSink, channel);
			soapServerFormatterSink.IncludeVersioning = _includeVersioning;
			soapServerFormatterSink.StrictBinding = _strictBinding;
			soapServerFormatterSink.TypeFilterLevel = _formatterSecurityLevel;
			return soapServerFormatterSink;
		}
	}
	public class SoapServerFormatterSink : IServerChannelSink, IChannelSinkBase
	{
		[Serializable]
		public enum Protocol
		{
			Http,
			Other
		}

		private IServerChannelSink _nextSink;

		private Protocol _protocol;

		private IChannelReceiver _receiver;

		private bool _includeVersioning = true;

		private bool _strictBinding;

		private TypeFilterLevel _formatterSecurityLevel = TypeFilterLevel.Full;

		internal bool IncludeVersioning
		{
			set
			{
				_includeVersioning = value;
			}
		}

		internal bool StrictBinding
		{
			set
			{
				_strictBinding = value;
			}
		}

		[ComVisible(false)]
		public TypeFilterLevel TypeFilterLevel
		{
			get
			{
				return _formatterSecurityLevel;
			}
			set
			{
				_formatterSecurityLevel = value;
			}
		}

		public IServerChannelSink NextChannelSink
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _nextSink;
			}
		}

		public IDictionary Properties
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return null;
			}
		}

		public SoapServerFormatterSink(Protocol protocol, IServerChannelSink nextSink, IChannelReceiver receiver)
		{
			if (receiver == null)
			{
				throw new ArgumentNullException("receiver");
			}
			_nextSink = nextSink;
			_protocol = protocol;
			_receiver = receiver;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public ServerProcessing ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, out IMessage responseMsg, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			if (requestMsg != null)
			{
				return _nextSink.ProcessMessage(sinkStack, requestMsg, requestHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
			}
			if (requestHeaders == null)
			{
				throw new ArgumentNullException("requestHeaders");
			}
			BaseTransportHeaders baseTransportHeaders = requestHeaders as BaseTransportHeaders;
			responseHeaders = null;
			responseStream = null;
			string text = null;
			string value = null;
			bool flag = true;
			string text2 = null;
			text2 = ((baseTransportHeaders == null) ? (requestHeaders["Content-Type"] as string) : baseTransportHeaders.ContentType);
			if (text2 != null)
			{
				HttpChannelHelper.ParseContentType(text2, out value, out var _);
			}
			if (value != null && string.Compare(value, "text/xml", StringComparison.Ordinal) != 0)
			{
				flag = false;
			}
			if (_protocol == Protocol.Http)
			{
				text = (string)requestHeaders["__RequestVerb"];
				if (!text.Equals("POST") && !text.Equals("M-POST"))
				{
					flag = false;
				}
			}
			if (!flag)
			{
				if (_nextSink != null)
				{
					return _nextSink.ProcessMessage(sinkStack, null, requestHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
				}
				if (_protocol == Protocol.Http)
				{
					responseHeaders = new TransportHeaders();
					responseHeaders["__HttpStatusCode"] = "400";
					responseHeaders["__HttpReasonPhrase"] = "Bad Request";
					responseStream = null;
					responseMsg = null;
					return ServerProcessing.Complete;
				}
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_Channels_InvalidRequestFormat"));
			}
			bool flag2 = true;
			try
			{
				string text3 = null;
				text3 = ((baseTransportHeaders == null) ? ((string)requestHeaders["__RequestUri"]) : baseTransportHeaders.RequestUri);
				if (RemotingServices.GetServerTypeForUri(text3) == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_ChnlSink_UriNotPublished"));
				}
				if (_protocol == Protocol.Http)
				{
					string text4 = (string)requestHeaders["User-Agent"];
					if (text4 != null)
					{
						if (text4.IndexOf("MS .NET Remoting") == -1)
						{
							flag2 = false;
						}
					}
					else
					{
						flag2 = false;
					}
				}
				bool flag3 = true;
				object obj = requestHeaders["__CustomErrorsEnabled"];
				if (obj != null && obj is bool)
				{
					flag3 = (bool)obj;
				}
				CallContext.SetData("__CustomErrorsEnabled", flag3);
				string soapActionToVerify;
				Header[] channelHeaders = GetChannelHeaders(requestHeaders, out soapActionToVerify);
				PermissionSet permissionSet = null;
				if (TypeFilterLevel != TypeFilterLevel.Full)
				{
					permissionSet = new PermissionSet(PermissionState.None);
					permissionSet.SetPermission(new SecurityPermission(SecurityPermissionFlag.SerializationFormatter));
				}
				try
				{
					permissionSet?.PermitOnly();
					requestMsg = CoreChannel.DeserializeSoapRequestMessage(requestStream, channelHeaders, _strictBinding, TypeFilterLevel);
				}
				finally
				{
					if (permissionSet != null)
					{
						CodeAccessPermission.RevertPermitOnly();
					}
				}
				requestStream.Close();
				if (requestMsg == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_DeserializeMessage"));
				}
				if (soapActionToVerify != null && !SoapServices.IsSoapActionValidForMethodBase(soapActionToVerify, ((IMethodMessage)requestMsg).MethodBase))
				{
					throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Soap_InvalidSoapAction"), soapActionToVerify));
				}
				sinkStack.Push(this, null);
				ServerProcessing serverProcessing = _nextSink.ProcessMessage(sinkStack, requestMsg, requestHeaders, null, out responseMsg, out responseHeaders, out responseStream);
				if (responseStream != null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_ChnlSink_WantNullResponseStream"));
				}
				switch (serverProcessing)
				{
				case ServerProcessing.Complete:
					if (responseMsg == null)
					{
						throw new RemotingException(CoreChannel.GetResourceString("Remoting_DispatchMessage"));
					}
					sinkStack.Pop(this);
					SerializeResponse(sinkStack, responseMsg, flag2, ref responseHeaders, out responseStream);
					return serverProcessing;
				case ServerProcessing.OneWay:
					sinkStack.Pop(this);
					return serverProcessing;
				case ServerProcessing.Async:
					sinkStack.Store(this, null);
					return serverProcessing;
				default:
					return serverProcessing;
				}
			}
			catch (Exception e)
			{
				ServerProcessing serverProcessing = ServerProcessing.Complete;
				responseMsg = new ReturnMessage(e, (IMethodCallMessage)((requestMsg == null) ? new ErrorMessage() : requestMsg));
				CallContext.SetData("__ClientIsClr", flag2);
				responseStream = (MemoryStream)CoreChannel.SerializeSoapMessage(responseMsg, _includeVersioning);
				CallContext.FreeNamedDataSlot("__ClientIsClr");
				responseStream.Position = 0L;
				responseHeaders = new TransportHeaders();
				if (_protocol == Protocol.Http)
				{
					responseHeaders["__HttpStatusCode"] = "500";
					responseHeaders["__HttpReasonPhrase"] = "Internal Server Error";
					responseHeaders["Content-Type"] = "text/xml; charset=\"utf-8\"";
					return serverProcessing;
				}
				return serverProcessing;
			}
			catch
			{
				ServerProcessing serverProcessing = ServerProcessing.Complete;
				responseMsg = new ReturnMessage(new Exception(CoreChannel.GetResourceString("Remoting_nonClsCompliantException")), (IMethodCallMessage)((requestMsg == null) ? new ErrorMessage() : requestMsg));
				CallContext.SetData("__ClientIsClr", flag2);
				responseStream = (MemoryStream)CoreChannel.SerializeSoapMessage(responseMsg, _includeVersioning);
				CallContext.FreeNamedDataSlot("__ClientIsClr");
				responseStream.Position = 0L;
				responseHeaders = new TransportHeaders();
				if (_protocol == Protocol.Http)
				{
					responseHeaders["__HttpStatusCode"] = "500";
					responseHeaders["__HttpReasonPhrase"] = "Internal Server Error";
					responseHeaders["Content-Type"] = "text/xml; charset=\"utf-8\"";
					return serverProcessing;
				}
				return serverProcessing;
			}
			finally
			{
				CallContext.FreeNamedDataSlot("__CustomErrorsEnabled");
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AsyncProcessResponse(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers, Stream stream)
		{
			SerializeResponse(sinkStack, msg, bClientIsClr: true, ref headers, out stream);
			sinkStack.AsyncProcessResponse(msg, headers, stream);
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		private void SerializeResponse(IServerResponseChannelSinkStack sinkStack, IMessage msg, bool bClientIsClr, ref ITransportHeaders headers, out Stream stream)
		{
			BaseTransportHeaders baseTransportHeaders = new BaseTransportHeaders();
			if (headers != null)
			{
				foreach (DictionaryEntry header in headers)
				{
					baseTransportHeaders[header.Key] = header.Value;
				}
			}
			headers = baseTransportHeaders;
			baseTransportHeaders.ContentType = "text/xml; charset=\"utf-8\"";
			if (_protocol == Protocol.Http && msg is IMethodReturnMessage methodReturnMessage && methodReturnMessage.Exception != null)
			{
				headers["__HttpStatusCode"] = "500";
				headers["__HttpReasonPhrase"] = "Internal Server Error";
			}
			bool flag = false;
			stream = sinkStack.GetResponseStream(msg, headers);
			if (stream == null)
			{
				stream = new ChunkedMemoryStream(CoreChannel.BufferPool);
				flag = true;
			}
			bool bBashedUrl = CoreChannel.SetupUrlBashingForIisSslIfNecessary();
			CallContext.SetData("__ClientIsClr", bClientIsClr);
			try
			{
				CoreChannel.SerializeSoapMessage(msg, stream, _includeVersioning);
			}
			finally
			{
				CallContext.FreeNamedDataSlot("__ClientIsClr");
				CoreChannel.CleanupUrlBashingForIisSslIfNecessary(bBashedUrl);
			}
			if (flag)
			{
				stream.Position = 0L;
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public Stream GetResponseStream(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers)
		{
			throw new NotSupportedException();
		}

		private Header[] GetChannelHeaders(ITransportHeaders requestHeaders, out string soapActionToVerify)
		{
			soapActionToVerify = null;
			string text = (string)requestHeaders["__RequestUri"];
			string text2 = (string)requestHeaders["SOAPAction"];
			if (text2 == null)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_SoapActionMissing"));
			}
			if (!SoapServices.GetTypeAndMethodNameFromSoapAction(soapActionToVerify = HttpEncodingHelper.DecodeUri(text2), out var typeName, out var _))
			{
				Type serverTypeForUri = RemotingServices.GetServerTypeForUri(text);
				if (serverTypeForUri == null)
				{
					throw new RemotingException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_TypeNotFoundFromUri"), text));
				}
				typeName = "clr:" + serverTypeForUri.FullName + ", " + serverTypeForUri.Assembly.GetName().Name;
			}
			else
			{
				typeName = "clr:" + typeName;
			}
			int num = 2;
			Header[] array = new Header[num];
			array[0] = new Header("__Uri", text);
			array[1] = new Header("__TypeName", typeName);
			return array;
		}
	}
}
namespace System.Runtime.Remoting.Configuration
{
	internal static class AppSettings
	{
		internal static readonly string AllowTransparentProxyMessageKeyName = "microsoft:Remoting:AllowTransparentProxyMessage";

		internal static readonly bool AllowTransparentProxyMessageDefaultValue = false;

		internal static readonly string AllowTransparentProxyMessageFwLink = "http://go.microsoft.com/fwlink/?LinkId=390633";

		private static bool allowTransparentProxyMessageValue = AllowTransparentProxyMessageDefaultValue;

		private static volatile bool settingsInitialized = false;

		private static object appSettingsLock = new object();

		internal static bool AllowTransparentProxyMessage
		{
			get
			{
				EnsureSettingsLoaded();
				return allowTransparentProxyMessageValue;
			}
		}

		private static void EnsureSettingsLoaded()
		{
			if (settingsInitialized)
			{
				return;
			}
			lock (appSettingsLock)
			{
				if (settingsInitialized)
				{
					return;
				}
				try
				{
					AppSettingsReader appSettingsReader = new AppSettingsReader();
					object value = null;
					if (TryGetValue(appSettingsReader, AllowTransparentProxyMessageKeyName, typeof(bool), out value))
					{
						allowTransparentProxyMessageValue = (bool)value;
					}
					else
					{
						allowTransparentProxyMessageValue = AllowTransparentProxyMessageDefaultValue;
					}
				}
				catch
				{
				}
				finally
				{
					settingsInitialized = true;
				}
			}
		}

		private static bool TryGetValue(AppSettingsReader appSettingsReader, string key, Type type, out object value)
		{
			try
			{
				value = appSettingsReader.GetValue(key, type);
				return true;
			}
			catch
			{
				value = null;
				return false;
			}
		}
	}
}
namespace System.Runtime.Remoting.MetadataServices
{
	public class MetaData
	{
		public static void ConvertTypesToSchemaToFile(Type[] types, SdlType sdlType, string path)
		{
			ConvertTypesToSchemaToStream(types, sdlType, File.Create(path));
		}

		public static void ConvertTypesToSchemaToStream(Type[] types, SdlType sdlType, Stream outputStream)
		{
			ServiceType[] array = new ServiceType[types.Length];
			for (int i = 0; i < types.Length; i++)
			{
				array[i] = new ServiceType(types[i]);
			}
			ConvertTypesToSchemaToStream(array, sdlType, outputStream);
		}

		public static void ConvertTypesToSchemaToFile(ServiceType[] types, SdlType sdlType, string path)
		{
			ConvertTypesToSchemaToStream(types, sdlType, File.Create(path));
		}

		public static void ConvertTypesToSchemaToStream(ServiceType[] serviceTypes, SdlType sdlType, Stream outputStream)
		{
			if (sdlType == SdlType.Sdl)
			{
				throw new NotSupportedException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Sdl generation is not supported")));
			}
			TextWriter textWriter = new StreamWriter(outputStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true));
			SUDSGenerator sUDSGenerator = new SUDSGenerator(serviceTypes, sdlType, textWriter);
			sUDSGenerator.Generate();
			textWriter.Flush();
		}

		public static void RetrieveSchemaFromUrlToStream(string url, Stream outputStream)
		{
			TextWriter textWriter = new StreamWriter(outputStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true));
			WebRequest webRequest = WebRequest.Create(url);
			WebResponse response = webRequest.GetResponse();
			Stream responseStream = response.GetResponseStream();
			StreamReader streamReader = new StreamReader(responseStream);
			textWriter.Write(streamReader.ReadToEnd());
			textWriter.Flush();
		}

		public static void RetrieveSchemaFromUrlToFile(string url, string path)
		{
			RetrieveSchemaFromUrlToStream(url, File.Create(path));
		}

		public static void ConvertSchemaStreamToCodeSourceStream(bool clientProxy, string outputDirectory, Stream inputStream, ArrayList outCodeStreamList, string proxyUrl, string proxyNamespace)
		{
			TextReader input = new StreamReader(inputStream);
			SUDSParser sUDSParser = new SUDSParser(input, outputDirectory, outCodeStreamList, proxyUrl, clientProxy, proxyNamespace);
			sUDSParser.Parse();
		}

		public static void ConvertSchemaStreamToCodeSourceStream(bool clientProxy, string outputDirectory, Stream inputStream, ArrayList outCodeStreamList, string proxyUrl)
		{
			ConvertSchemaStreamToCodeSourceStream(clientProxy, outputDirectory, inputStream, outCodeStreamList, proxyUrl, "");
		}

		public static void ConvertSchemaStreamToCodeSourceStream(bool clientProxy, string outputDirectory, Stream inputStream, ArrayList outCodeStreamList)
		{
			ConvertSchemaStreamToCodeSourceStream(clientProxy, outputDirectory, inputStream, outCodeStreamList, "", "");
		}

		public static void ConvertCodeSourceStreamToAssemblyFile(ArrayList outCodeStreamList, string assemblyPath, string strongNameFilename)
		{
			CompilerResults compilerResults = null;
			string text = "__Sn.cs";
			try
			{
				if (strongNameFilename != null)
				{
					if (assemblyPath != null)
					{
						int num = assemblyPath.LastIndexOf("\\");
						if (num > 0)
						{
							text = assemblyPath.Substring(0, num + 1) + text;
						}
					}
					FileStream fileStream = new FileStream(text, FileMode.Create, FileAccess.ReadWrite);
					StreamWriter streamWriter = new StreamWriter(fileStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true));
					streamWriter.WriteLine("// CLR Remoting Autogenerated Key file (to create a key file use: sn -k tmp.key)");
					streamWriter.WriteLine("using System;");
					streamWriter.WriteLine("using System.Reflection;");
					streamWriter.WriteLine("[assembly: AssemblyKeyFile(@\"" + strongNameFilename + "\")]");
					streamWriter.WriteLine("[assembly: AssemblyVersion(@\"1.0.0.1\")]");
					streamWriter.Flush();
					streamWriter.Close();
					fileStream.Close();
					outCodeStreamList.Add(text);
				}
				string[] array = new string[outCodeStreamList.Count];
				string[] array2 = new string[outCodeStreamList.Count];
				int num2 = 0;
				for (int i = 0; i < outCodeStreamList.Count; i++)
				{
					bool flag = false;
					Stream stream;
					if (outCodeStreamList[i] is string)
					{
						stream = File.OpenRead(array2[i] = (string)outCodeStreamList[i]);
						flag = true;
					}
					else
					{
						if (!(outCodeStreamList[i] is Stream))
						{
							throw new RemotingException(CoreChannel.GetResourceString("Remoting_UnknownObjectInCodeStreamList"));
						}
						stream = (Stream)outCodeStreamList[i];
						array2[i] = "Stream" + num2++;
					}
					StreamReader streamReader = new StreamReader(stream);
					array[i] = streamReader.ReadToEnd();
					if (flag)
					{
						stream.Close();
					}
				}
				string[] assemblyNames = new string[5] { "System.dll", "System.Runtime.Remoting.dll", "System.Data.dll", "System.Xml.dll", "System.Web.Services.dll" };
				if (array.Length > 0)
				{
					CodeDomProvider codeDomProvider = new CSharpCodeProvider();
					CompilerParameters compilerParameters = new CompilerParameters(assemblyNames, assemblyPath, includeDebugInformation: true);
					compilerParameters.GenerateExecutable = false;
					compilerResults = codeDomProvider.CompileAssemblyFromSource(compilerParameters, array);
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.ToString());
			}
			catch
			{
			}
			finally
			{
				File.Delete(text);
			}
			if (!compilerResults.Errors.HasErrors)
			{
				return;
			}
			CompilerErrorCollection errors = compilerResults.Errors;
			if (errors.Count <= 0)
			{
				return;
			}
			foreach (CompilerError item in errors)
			{
				Console.WriteLine(item.ToString());
			}
		}

		public static void ConvertCodeSourceFileToAssemblyFile(string codePath, string assemblyPath, string strongNameFilename)
		{
			ArrayList arrayList = new ArrayList();
			arrayList.Add(codePath);
			ConvertCodeSourceStreamToAssemblyFile(arrayList, assemblyPath, strongNameFilename);
		}

		public static void SaveStreamToFile(Stream inputStream, string path)
		{
			Stream stream = File.Create(path);
			TextWriter textWriter = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true));
			StreamReader streamReader = new StreamReader(inputStream);
			textWriter.Write(streamReader.ReadToEnd());
			textWriter.Flush();
			textWriter.Close();
			stream.Close();
		}
	}
	public class ServiceType
	{
		private Type _type;

		private string _url;

		public Type ObjectType => _type;

		public string Url => _url;

		public ServiceType(Type type)
		{
			_type = type;
			_url = null;
		}

		public ServiceType(Type type, string url)
		{
			_type = type;
			_url = url;
		}
	}
	public class SdlChannelSinkProvider : IServerChannelSinkProvider
	{
		private IServerChannelSinkProvider _next;

		private bool _bRemoteApplicationMetadataEnabled;

		private bool _bMetadataEnabled = true;

		public IServerChannelSinkProvider Next
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _next;
			}
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			set
			{
				_next = value;
			}
		}

		public SdlChannelSinkProvider()
		{
		}

		public SdlChannelSinkProvider(IDictionary properties, ICollection providerData)
		{
			if (properties == null)
			{
				return;
			}
			foreach (DictionaryEntry property in properties)
			{
				switch ((string)property.Key)
				{
				case "remoteApplicationMetadataEnabled":
					_bRemoteApplicationMetadataEnabled = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
					break;
				case "metadataEnabled":
					_bMetadataEnabled = Convert.ToBoolean(property.Value, CultureInfo.InvariantCulture);
					break;
				default:
					CoreChannel.ReportUnknownProviderConfigProperty(GetType().Name, (string)property.Key);
					break;
				}
			}
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void GetChannelData(IChannelDataStore localChannelData)
		{
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public IServerChannelSink CreateSink(IChannelReceiver channel)
		{
			IServerChannelSink nextSink = null;
			if (_next != null)
			{
				nextSink = _next.CreateSink(channel);
			}
			SdlChannelSink sdlChannelSink = new SdlChannelSink(channel, nextSink);
			sdlChannelSink.RemoteApplicationMetadataEnabled = _bRemoteApplicationMetadataEnabled;
			sdlChannelSink.MetadataEnabled = _bMetadataEnabled;
			return sdlChannelSink;
		}
	}
	public class SdlChannelSink : IServerChannelSink, IChannelSinkBase
	{
		private IChannelReceiver _receiver;

		private IServerChannelSink _nextSink;

		private bool _bRemoteApplicationMetadataEnabled;

		private bool _bMetadataEnabled;

		internal bool RemoteApplicationMetadataEnabled
		{
			get
			{
				return _bRemoteApplicationMetadataEnabled;
			}
			set
			{
				_bRemoteApplicationMetadataEnabled = value;
			}
		}

		internal bool MetadataEnabled
		{
			get
			{
				return _bMetadataEnabled;
			}
			set
			{
				_bMetadataEnabled = value;
			}
		}

		public IServerChannelSink NextChannelSink
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return _nextSink;
			}
		}

		public IDictionary Properties
		{
			[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
			get
			{
				return null;
			}
		}

		public SdlChannelSink(IChannelReceiver receiver, IServerChannelSink nextSink)
		{
			_receiver = receiver;
			_nextSink = nextSink;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public ServerProcessing ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, out IMessage responseMsg, out ITransportHeaders responseHeaders, out Stream responseStream)
		{
			if (requestMsg != null)
			{
				return _nextSink.ProcessMessage(sinkStack, requestMsg, requestHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
			}
			if (!ShouldIntercept(requestHeaders, out var sdlType))
			{
				return _nextSink.ProcessMessage(sinkStack, null, requestHeaders, requestStream, out responseMsg, out responseHeaders, out responseStream);
			}
			responseHeaders = new TransportHeaders();
			GenerateSdl(sdlType, sinkStack, requestHeaders, responseHeaders, out responseStream);
			responseMsg = null;
			return ServerProcessing.Complete;
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public void AsyncProcessResponse(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers, Stream stream)
		{
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.Infrastructure, Infrastructure = true)]
		public Stream GetResponseStream(IServerResponseChannelSinkStack sinkStack, object state, IMessage msg, ITransportHeaders headers)
		{
			throw new NotSupportedException();
		}

		private bool ShouldIntercept(ITransportHeaders requestHeaders, out SdlType sdlType)
		{
			sdlType = SdlType.Sdl;
			string text = requestHeaders["__RequestVerb"] as string;
			if (!(requestHeaders["__RequestUri"] is string text2) || text == null || !text.Equals("GET"))
			{
				return false;
			}
			int num = text2.LastIndexOf('?');
			if (num == -1)
			{
				return false;
			}
			string strA = text2.Substring(num).ToLower(CultureInfo.InvariantCulture);
			if (string.CompareOrdinal(strA, "?sdl") == 0 || string.CompareOrdinal(strA, "?sdlx") == 0)
			{
				sdlType = SdlType.Sdl;
				return true;
			}
			if (string.CompareOrdinal(strA, "?wsdl") == 0)
			{
				sdlType = SdlType.Wsdl;
				return true;
			}
			return false;
		}

		private void GenerateSdl(SdlType sdlType, IServerResponseChannelSinkStack sinkStack, ITransportHeaders requestHeaders, ITransportHeaders responseHeaders, out Stream outputStream)
		{
			if (!MetadataEnabled)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_MetadataNotEnabled"));
			}
			string uri = requestHeaders["__RequestUri"] as string;
			string objectUriFromRequestUri = HttpChannelHelper.GetObjectUriFromRequestUri(uri);
			if (!RemoteApplicationMetadataEnabled && string.Compare(objectUriFromRequestUri, "RemoteApplicationMetadata.rem", StringComparison.OrdinalIgnoreCase) == 0)
			{
				throw new RemotingException(CoreChannel.GetResourceString("Remoting_RemoteApplicationMetadataNotEnabled"));
			}
			string text = (string)requestHeaders["Host"];
			if (text != null)
			{
				int num = text.IndexOf(':');
				if (num != -1)
				{
					text = text.Substring(0, num);
				}
			}
			string text2 = SetupUrlBashingForIisIfNecessary(text);
			ServiceType[] array = null;
			if (string.Compare(objectUriFromRequestUri, "RemoteApplicationMetadata.rem", StringComparison.OrdinalIgnoreCase) == 0)
			{
				ActivatedServiceTypeEntry[] registeredActivatedServiceTypes = RemotingConfiguration.GetRegisteredActivatedServiceTypes();
				WellKnownServiceTypeEntry[] registeredWellKnownServiceTypes = RemotingConfiguration.GetRegisteredWellKnownServiceTypes();
				int num2 = 0;
				if (registeredActivatedServiceTypes != null)
				{
					num2 += registeredActivatedServiceTypes.Length;
				}
				if (registeredWellKnownServiceTypes != null)
				{
					num2 += registeredWellKnownServiceTypes.Length;
				}
				array = new ServiceType[num2];
				int num3 = 0;
				if (registeredActivatedServiceTypes != null)
				{
					ActivatedServiceTypeEntry[] array2 = registeredActivatedServiceTypes;
					foreach (ActivatedServiceTypeEntry activatedServiceTypeEntry in array2)
					{
						array[num3++] = new ServiceType(activatedServiceTypeEntry.ObjectType, null);
					}
				}
				if (registeredWellKnownServiceTypes != null)
				{
					WellKnownServiceTypeEntry[] array3 = registeredWellKnownServiceTypes;
					foreach (WellKnownServiceTypeEntry wellKnownServiceTypeEntry in array3)
					{
						string[] urlsForUri = _receiver.GetUrlsForUri(wellKnownServiceTypeEntry.ObjectUri);
						string url = urlsForUri[0];
						if (text2 != null)
						{
							url = HttpChannelHelper.ReplaceChannelUriWithThisString(url, text2);
						}
						else if (text != null)
						{
							url = HttpChannelHelper.ReplaceMachineNameWithThisString(url, text);
						}
						array[num3++] = new ServiceType(wellKnownServiceTypeEntry.ObjectType, url);
					}
				}
			}
			else
			{
				Type serverTypeForUri = RemotingServices.GetServerTypeForUri(objectUriFromRequestUri);
				if (serverTypeForUri == null)
				{
					throw new RemotingException(string.Format(CultureInfo.CurrentCulture, "Object with uri '{0}' does not exist at server.", objectUriFromRequestUri));
				}
				string[] urlsForUri2 = _receiver.GetUrlsForUri(objectUriFromRequestUri);
				string url2 = urlsForUri2[0];
				if (text2 != null)
				{
					url2 = HttpChannelHelper.ReplaceChannelUriWithThisString(url2, text2);
				}
				else if (text != null)
				{
					url2 = HttpChannelHelper.ReplaceMachineNameWithThisString(url2, text);
				}
				array = new ServiceType[1]
				{
					new ServiceType(serverTypeForUri, url2)
				};
			}
			responseHeaders["Content-Type"] = "text/xml";
			bool flag = false;
			outputStream = sinkStack.GetResponseStream(null, responseHeaders);
			if (outputStream == null)
			{
				outputStream = new MemoryStream(1024);
				flag = true;
			}
			MetaData.ConvertTypesToSchemaToStream(array, sdlType, outputStream);
			if (flag)
			{
				outputStream.Position = 0L;
			}
		}

		internal static string SetupUrlBashingForIisIfNecessary(string hostName)
		{
			string result = null;
			if (!CoreChannel.IsClientSKUInstallation)
			{
				result = SetupUrlBashingForIisIfNecessaryWorker(hostName);
			}
			return result;
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		private static string SetupUrlBashingForIisIfNecessaryWorker(string hostName)
		{
			string result = null;
			HttpContext current = HttpContext.Current;
			if (current != null)
			{
				HttpRequest request = current.Request;
				string text = null;
				text = ((!request.IsSecureConnection) ? "http" : "https");
				int port = current.Request.Url.Port;
				StringBuilder stringBuilder = new StringBuilder(100);
				stringBuilder.Append(text);
				stringBuilder.Append("://");
				if (hostName != null)
				{
					stringBuilder.Append(hostName);
				}
				else
				{
					stringBuilder.Append(CoreChannel.GetMachineName());
				}
				stringBuilder.Append(":");
				stringBuilder.Append(port.ToString(CultureInfo.InvariantCulture));
				result = stringBuilder.ToString();
			}
			return result;
		}
	}
	[Serializable]
	public class SUDSParserException : Exception
	{
		internal SUDSParserException(string message)
			: base(message)
		{
		}

		protected SUDSParserException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	[Serializable]
	internal enum SchemaBlockType
	{
		ALL,
		SEQUENCE,
		CHOICE,
		ComplexContent
	}
	internal class SUDSParser
	{
		private WsdlParser wsdlParser;

		internal SUDSParser(TextReader input, string outputDir, ArrayList outCodeStreamList, string locationURL, bool bWrappedProxy, string proxyNamespace)
		{
			wsdlParser = new WsdlParser(input, outputDir, outCodeStreamList, locationURL, bWrappedProxy, proxyNamespace);
		}

		internal void Parse()
		{
			wsdlParser.Parse();
		}
	}
	[Serializable]
	public class SUDSGeneratorException : Exception
	{
		internal SUDSGeneratorException(string msg)
			: base(msg)
		{
		}

		protected SUDSGeneratorException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
	internal class SUDSGenerator
	{
		private WsdlGenerator wsdlGenerator;

		private SdlType sdlType;

		internal SUDSGenerator(Type[] types, SdlType sdlType, TextWriter output)
		{
			wsdlGenerator = new WsdlGenerator(types, sdlType, output);
			this.sdlType = sdlType;
		}

		internal SUDSGenerator(ServiceType[] serviceTypes, SdlType sdlType, TextWriter output)
		{
			wsdlGenerator = new WsdlGenerator(serviceTypes, sdlType, output);
			this.sdlType = sdlType;
		}

		internal void Generate()
		{
			wsdlGenerator.Generate();
		}
	}
	[Serializable]
	public enum SdlType
	{
		Sdl,
		Wsdl
	}
	[Serializable]
	internal enum UrtType
	{
		None,
		Interop,
		UrtSystem,
		UrtUser,
		Xsd
	}
	[Serializable]
	internal enum SUDSType
	{
		None,
		ClientProxy,
		MarshalByRef
	}
	[Serializable]
	internal enum XsdVersion
	{
		V1999,
		V2000,
		V2001
	}
	internal static class SudsConverter
	{
		internal static string Xsd1999 = "http://www.w3.org/1999/XMLSchema";

		internal static string Xsi1999 = "http://www.w3.org/1999/XMLSchema-instance";

		internal static string Xsd2000 = "http://www.w3.org/2000/10/XMLSchema";

		internal static string Xsi2000 = "http://www.w3.org/2000/10/XMLSchema-instance";

		internal static string Xsd2001 = "http://www.w3.org/2001/XMLSchema";

		internal static string Xsi2001 = "http://www.w3.org/2001/XMLSchema-instance";

		internal static Type typeofByte = typeof(byte);

		internal static Type typeofSByte = typeof(sbyte);

		internal static Type typeofBoolean = typeof(bool);

		internal static Type typeofChar = typeof(char);

		internal static Type typeofDouble = typeof(double);

		internal static Type typeofSingle = typeof(float);

		internal static Type typeofDecimal = typeof(decimal);

		internal static Type typeofInt16 = typeof(short);

		internal static Type typeofInt32 = typeof(int);

		internal static Type typeofInt64 = typeof(long);

		internal static Type typeofUInt16 = typeof(ushort);

		internal static Type typeofUInt32 = typeof(uint);

		internal static Type typeofUInt64 = typeof(ulong);

		internal static Type typeofSoapTime = typeof(SoapTime);

		internal static Type typeofSoapDate = typeof(SoapDate);

		internal static Type typeofSoapYearMonth = typeof(SoapYearMonth);

		internal static Type typeofSoapYear = typeof(SoapYear);

		internal static Type typeofSoapMonthDay = typeof(SoapMonthDay);

		internal static Type typeofSoapDay = typeof(SoapDay);

		internal static Type typeofSoapMonth = typeof(SoapMonth);

		internal static Type typeofSoapHexBinary = typeof(SoapHexBinary);

		internal static Type typeofSoapBase64Binary = typeof(SoapBase64Binary);

		internal static Type typeofSoapInteger = typeof(SoapInteger);

		internal static Type typeofSoapPositiveInteger = typeof(SoapPositiveInteger);

		internal static Type typeofSoapNonPositiveInteger = typeof(SoapNonPositiveInteger);

		internal static Type typeofSoapNonNegativeInteger = typeof(SoapNonNegativeInteger);

		internal static Type typeofSoapNegativeInteger = typeof(SoapNegativeInteger);

		internal static Type typeofSoapAnyUri = typeof(SoapAnyUri);

		internal static Type typeofSoapQName = typeof(SoapQName);

		internal static Type typeofSoapNotation = typeof(SoapNotation);

		internal static Type typeofSoapNormalizedString = typeof(SoapNormalizedString);

		internal static Type typeofSoapToken = typeof(SoapToken);

		internal static Type typeofSoapLanguage = typeof(SoapLanguage);

		internal static Type typeofSoapName = typeof(SoapName);

		internal static Type typeofSoapIdrefs = typeof(SoapIdrefs);

		internal static Type typeofSoapEntities = typeof(SoapEntities);

		internal static Type typeofSoapNmtoken = typeof(SoapNmtoken);

		internal static Type typeofSoapNmtokens = typeof(SoapNmtokens);

		internal static Type typeofSoapNcName = typeof(SoapNcName);

		internal static Type typeofSoapId = typeof(SoapId);

		internal static Type typeofSoapIdref = typeof(SoapIdref);

		internal static Type typeofSoapEntity = typeof(SoapEntity);

		internal static Type typeofString = typeof(string);

		internal static Type typeofObject = typeof(object);

		internal static Type typeofVoid = typeof(void);

		internal static Type typeofDateTime = typeof(DateTime);

		internal static Type typeofTimeSpan = typeof(TimeSpan);

		internal static Type typeofISoapXsd = typeof(ISoapXsd);

		internal static string GetXsdVersion(XsdVersion xsdVersion)
		{
			string text = null;
			return xsdVersion switch
			{
				XsdVersion.V1999 => Xsd1999, 
				XsdVersion.V2000 => Xsd2000, 
				_ => Xsd2001, 
			};
		}

		internal static string GetXsiVersion(XsdVersion xsdVersion)
		{
			string text = null;
			return xsdVersion switch
			{
				XsdVersion.V1999 => Xsi1999, 
				XsdVersion.V2000 => Xsi2000, 
				_ => Xsi2001, 
			};
		}

		internal static string MapClrTypeToXsdType(Type clrType)
		{
			string text = null;
			if (clrType == typeofChar)
			{
				return null;
			}
			if (clrType.IsPrimitive)
			{
				if (clrType == typeofByte)
				{
					text = "xsd:unsignedByte";
				}
				else if (clrType == typeofSByte)
				{
					text = "xsd:byte";
				}
				else if (clrType == typeofBoolean)
				{
					text = "xsd:boolean";
				}
				else if (clrType == typeofChar)
				{
					text = "xsd:char";
				}
				else if (clrType == typeofDouble)
				{
					text = "xsd:double";
				}
				else if (clrType == typeofSingle)
				{
					text = "xsd:float";
				}
				else if (clrType == typeofDecimal)
				{
					text = "xsd:decimal";
				}
				else if (clrType == typeofDateTime)
				{
					text = "xsd:dateTime";
				}
				else if (clrType == typeofInt16)
				{
					text = "xsd:short";
				}
				else if (clrType == typeofInt32)
				{
					text = "xsd:int";
				}
				else if (clrType == typeofInt64)
				{
					text = "xsd:long";
				}
				else if (clrType == typeofUInt16)
				{
					text = "xsd:unsignedShort";
				}
				else if (clrType == typeofUInt32)
				{
					text = "xsd:unsignedInt";
				}
				else if (clrType == typeofUInt64)
				{
					text = "xsd:unsignedLong";
				}
				else if (clrType == typeofTimeSpan)
				{
					text = "xsd:duration";
				}
			}
			else if (typeofISoapXsd.IsAssignableFrom(clrType))
			{
				if (clrType == typeofSoapTime)
				{
					text = SoapTime.XsdType;
				}
				else if (clrType == typeofSoapDate)
				{
					text = SoapDate.XsdType;
				}
				else if (clrType == typeofSoapYearMonth)
				{
					text = SoapYearMonth.XsdType;
				}
				else if (clrType == typeofSoapYear)
				{
					text = SoapYear.XsdType;
				}
				else if (clrType == typeofSoapMonthDay)
				{
					text = SoapMonthDay.XsdType;
				}
				else if (clrType == typeofSoapDay)
				{
					text = SoapDay.XsdType;
				}
				else if (clrType == typeofSoapMonth)
				{
					text = SoapMonth.XsdType;
				}
				else if (clrType == typeofSoapHexBinary)
				{
					text = SoapHexBinary.XsdType;
				}
				else if (clrType == typeofSoapBase64Binary)
				{
					text = SoapBase64Binary.XsdType;
				}
				else if (clrType == typeofSoapInteger)
				{
					text = SoapInteger.XsdType;
				}
				else if (clrType == typeofSoapPositiveInteger)
				{
					text = SoapPositiveInteger.XsdType;
				}
				else if (clrType == typeofSoapNonPositiveInteger)
				{
					text = SoapNonPositiveInteger.XsdType;
				}
				else if (clrType == typeofSoapNonNegativeInteger)
				{
					text = SoapNonNegativeInteger.XsdType;
				}
				else if (clrType == typeofSoapNegativeInteger)
				{
					text = SoapNegativeInteger.XsdType;
				}
				else if (clrType == typeofSoapAnyUri)
				{
					text = SoapAnyUri.XsdType;
				}
				else if (clrType == typeofSoapQName)
				{
					text = SoapQName.XsdType;
				}
				else if (clrType == typeofSoapNotation)
				{
					text = SoapNotation.XsdType;
				}
				else if (clrType == typeofSoapNormalizedString)
				{
					text = SoapNormalizedString.XsdType;
				}
				else if (clrType == typeofSoapToken)
				{
					text = SoapToken.XsdType;
				}
				else if (clrType == typeofSoapLanguage)
				{
					text = SoapLanguage.XsdType;
				}
				else if (clrType == typeofSoapName)
				{
					text = SoapName.XsdType;
				}
				else if (clrType == typeofSoapIdrefs)
				{
					text = SoapIdrefs.XsdType;
				}
				else if (clrType == typeofSoapEntities)
				{
					text = SoapEntities.XsdType;
				}
				else if (clrType == typeofSoapNmtoken)
				{
					text = SoapNmtoken.XsdType;
				}
				else if (clrType == typeofSoapNmtokens)
				{
					text = SoapNmtokens.XsdType;
				}
				else if (clrType == typeofSoapNcName)
				{
					text = SoapNcName.XsdType;
				}
				else if (clrType == typeofSoapId)
				{
					text = SoapId.XsdType;
				}
				else if (clrType == typeofSoapIdref)
				{
					text = SoapIdref.XsdType;
				}
				else if (clrType == typeofSoapEntity)
				{
					text = SoapEntity.XsdType;
				}
				text = "xsd:" + text;
			}
			else if (clrType == typeofString)
			{
				text = "xsd:string";
			}
			else if (clrType == typeofDecimal)
			{
				text = "xsd:decimal";
			}
			else if (clrType == typeofObject)
			{
				text = "xsd:anyType";
			}
			else if (clrType == typeofVoid)
			{
				text = "void";
			}
			else if (clrType == typeofDateTime)
			{
				text = "xsd:dateTime";
			}
			else if (clrType == typeofTimeSpan)
			{
				text = "xsd:duration";
			}
			return text;
		}

		internal static string MapXsdToClrTypes(string xsdType)
		{
			string text = xsdType.ToLower(CultureInfo.InvariantCulture);
			string result = null;
			if (xsdType == null || xsdType.Length == 0)
			{
				return null;
			}
			switch (text[0])
			{
			case 'a':
				switch (text)
				{
				case "anyuri":
					result = "SoapAnyUri";
					break;
				case "anytype":
				case "ur-type":
					result = "Object";
					break;
				}
				break;
			case 'b':
				switch (text)
				{
				case "boolean":
					result = "Boolean";
					break;
				case "byte":
					result = "SByte";
					break;
				case "base64binary":
					result = "SoapBase64Binary";
					break;
				}
				break;
			case 'c':
				if (text == "char")
				{
					result = "Char";
				}
				break;
			case 'd':
				switch (text)
				{
				case "double":
					result = "Double";
					break;
				case "datetime":
					result = "DateTime";
					break;
				case "decimal":
					result = "Decimal";
					break;
				case "duration":
					result = "TimeSpan";
					break;
				case "date":
					result = "SoapDate";
					break;
				}
				break;
			case 'e':
				if (text == "entities")
				{
					result = "SoapEntities";
				}
				else if (text == "entity")
				{
					result = "SoapEntity";
				}
				break;
			case 'f':
				if (text == "float")
				{
					result = "Single";
				}
				break;
			case 'g':
				switch (text)
				{
				case "gyearmonth":
					result = "SoapYearMonth";
					break;
				case "gyear":
					result = "SoapYear";
					break;
				case "gmonthday":
					result = "SoapMonthDay";
					break;
				case "gday":
					result = "SoapDay";
					break;
				case "gmonth":
					result = "SoapMonth";
					break;
				}
				break;
			case 'h':
				if (text == "hexbinary")
				{
					result = "SoapHexBinary";
				}
				break;
			case 'i':
				switch (text)
				{
				case "int":
					result = "Int32";
					break;
				case "integer":
					result = "SoapInteger";
					break;
				case "idrefs":
					result = "SoapIdrefs";
					break;
				case "id":
					result = "SoapId";
					break;
				case "idref":
					result = "SoapIdref";
					break;
				}
				break;
			case 'l':
				if (text == "long")
				{
					result = "Int64";
				}
				else if (text == "language")
				{
					result = "SoapLanguage";
				}
				break;
			case 'n':
				switch (text)
				{
				case "number":
					result = "Decimal";
					break;
				case "normalizedstring":
					result = "SoapNormalizedString";
					break;
				case "nonpositiveinteger":
					result = "SoapNonPositiveInteger";
					break;
				case "negativeinteger":
					result = "SoapNegativeInteger";
					break;
				case "nonnegativeinteger":
					result = "SoapNonNegativeInteger";
					break;
				case "notation":
					result = "SoapNotation";
					break;
				case "nmtoken":
					result = "SoapNmtoken";
					break;
				case "nmtokens":
					result = "SoapNmtokens";
					break;
				case "name":
					result = "SoapName";
					break;
				case "ncname":
					result = "SoapNcName";
					break;
				}
				break;
			case 'p':
				if (text == "positiveinteger")
				{
					result = "SoapPositiveInteger";
				}
				break;
			case 'q':
				if (text == "qname")
				{
					result = "SoapQName";
				}
				break;
			case 's':
				if (text == "string")
				{
					result = "String";
				}
				else if (text == "short")
				{
					result = "Int16";
				}
				break;
			case 't':
				if (text == "time")
				{
					result = "SoapTime";
				}
				else if (text == "token")
				{
					result = "SoapToken";
				}
				break;
			case 'u':
				switch (text)
				{
				case "unsignedlong":
					result = "UInt64";
					break;
				case "unsignedint":
					result = "UInt32";
					break;
				case "unsignedshort":
					result = "UInt16";
					break;
				case "unsignedbyte":
					result = "Byte";
					break;
				}
				break;
			}
			return result;
		}
	}
	internal static class Util
	{
		internal static StreamWriter writer;

		[Conditional("_LOGGING")]
		internal static void Log(string message)
		{
		}

		[Conditional("_LOGGING")]
		internal static void LogInput(ref TextReader input)
		{
			if (InternalRM.SoapCheckEnabled())
			{
				string s = input.ReadToEnd();
				input = new StringReader(s);
			}
		}

		[Conditional("_LOGGING")]
		internal static void LogString(string strbuffer)
		{
		}
	}
	internal class WsdlParser
	{
		internal class ReaderStream
		{
			private string _location;

			private string _name;

			private string _targetNS;

			private URTNamespace _uniqueNS;

			private TextReader _reader;

			private ReaderStream _next;

			private Uri _uri;

			internal string Location
			{
				get
				{
					return _location;
				}
				set
				{
					_location = value;
				}
			}

			internal string Name
			{
				set
				{
					_name = value;
				}
			}

			internal string TargetNS
			{
				get
				{
					return _targetNS;
				}
				set
				{
					_targetNS = value;
				}
			}

			internal URTNamespace UniqueNS
			{
				get
				{
					return _uniqueNS;
				}
				set
				{
					_uniqueNS = value;
				}
			}

			internal TextReader InputStream
			{
				get
				{
					return _reader;
				}
				set
				{
					_reader = value;
				}
			}

			internal Uri Uri
			{
				get
				{
					return _uri;
				}
				set
				{
					_uri = value;
				}
			}

			internal ReaderStream(string location)
			{
				_location = location;
				_name = string.Empty;
				_targetNS = string.Empty;
				_uniqueNS = null;
				_reader = null;
				_next = null;
			}

			internal static void GetReaderStream(ReaderStream inputStreams, ReaderStream newStream)
			{
				ReaderStream readerStream = inputStreams;
				ReaderStream readerStream2;
				do
				{
					if (readerStream._location == newStream.Location)
					{
						return;
					}
					readerStream2 = readerStream;
					readerStream = readerStream._next;
				}
				while (readerStream != null);
				readerStream = (readerStream2._next = newStream);
			}

			internal static ReaderStream GetNextReaderStream(ReaderStream input)
			{
				return input._next;
			}
		}

		internal class WriterStream
		{
			private string _fileName;

			private TextWriter _writer;

			private WriterStream _next;

			private bool _bWrittenTo;

			internal TextWriter OutputStream => _writer;

			private WriterStream(string fileName, TextWriter writer)
			{
				_fileName = fileName;
				_writer = writer;
			}

			internal bool GetWrittenTo()
			{
				return _bWrittenTo;
			}

			internal void SetWrittenTo()
			{
				_bWrittenTo = true;
			}

			internal static void Flush(WriterStream writerStream)
			{
				while (writerStream != null)
				{
					writerStream._writer.Flush();
					writerStream = writerStream._next;
				}
			}

			internal static WriterStream GetWriterStream(ref WriterStream outputStreams, string outputDir, string fileName, ref string completeFileName)
			{
				WriterStream writerStream;
				for (writerStream = outputStreams; writerStream != null; writerStream = writerStream._next)
				{
					if (writerStream._fileName == fileName)
					{
						return writerStream;
					}
				}
				string text = fileName;
				if (text.EndsWith(".exe", StringComparison.Ordinal) || text.EndsWith(".dll", StringComparison.Ordinal))
				{
					text = text.Substring(0, text.Length - 4);
				}
				TextWriter writer = new StreamWriter(completeFileName = outputDir + text + ".cs", append: false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
				writerStream = new WriterStream(fileName, writer);
				writerStream._next = outputStreams;
				outputStreams = writerStream;
				return writerStream;
			}

			internal static void Close(WriterStream outputStreams)
			{
				for (WriterStream writerStream = outputStreams; writerStream != null; writerStream = writerStream._next)
				{
					writerStream._writer.Close();
				}
			}
		}

		[Serializable]
		internal enum URTParamType
		{
			IN,
			OUT,
			REF
		}

		internal class URTParam
		{
			private static string[] PTypeString = new string[3] { "", "out ", "ref " };

			private string _name;

			private string _typeName;

			private string _typeNS;

			private string _encodedNS;

			private URTParamType _pType;

			private bool _embeddedParam;

			private URTNamespace _urtNamespace;

			private WsdlParser _parser;

			internal URTParamType ParamType
			{
				get
				{
					return _pType;
				}
				set
				{
					_pType = value;
				}
			}

			internal string Name => _name;

			internal string TypeName => _typeName;

			internal string TypeNS => _typeNS;

			internal URTParam(string name, string typeName, string typeNS, string encodedNS, URTParamType pType, bool bEmbedded, WsdlParser parser, URTNamespace urtNamespace)
			{
				_name = name;
				_typeName = typeName;
				_typeNS = typeNS;
				_encodedNS = encodedNS;
				_pType = pType;
				_embeddedParam = bEmbedded;
				_parser = parser;
				_urtNamespace = urtNamespace;
			}

			public override bool Equals(object obj)
			{
				URTParam uRTParam = (URTParam)obj;
				if (_pType == uRTParam._pType && MatchingStrings(_typeName, uRTParam._typeName) && MatchingStrings(_typeNS, uRTParam._typeNS))
				{
					return true;
				}
				return false;
			}

			public override int GetHashCode()
			{
				return base.GetHashCode();
			}

			internal string GetTypeString(string curNS, bool bNS)
			{
				return _parser.GetTypeString(curNS, bNS, _urtNamespace, _typeName, _encodedNS);
			}

			internal void PrintCSC(StringBuilder sb, string curNS)
			{
				sb.Append(PTypeString[(int)_pType]);
				sb.Append(GetTypeString(curNS, bNS: true));
				sb.Append(' ');
				sb.Append(IsValidCS(_name));
			}

			internal void PrintCSC(StringBuilder sb)
			{
				sb.Append(PTypeString[(int)_pType]);
				sb.Append(IsValidCS(_name));
			}
		}

		[Flags]
		internal enum MethodPrintEnum
		{
			PrintBody = 1,
			InterfaceMethods = 2,
			InterfaceInClass = 4
		}

		[Flags]
		internal enum MethodFlags
		{
			None = 0,
			Public = 1,
			Protected = 2,
			Override = 4,
			New = 8,
			Virtual = 0x10,
			Internal = 0x20
		}

		internal abstract class URTMethod
		{
			private string _methodName;

			private string _soapAction;

			private URTParam _methodType;

			internal URTComplexType _complexType;

			protected string[] _paramNamesOrder;

			protected ArrayList _params = new ArrayList();

			protected ArrayList _paramPosition = new ArrayList();

			private MethodFlags _methodFlags;

			private WsdlMethodInfo _wsdlMethodInfo;

			internal string Name => _methodName;

			internal string SoapAction => _soapAction;

			internal MethodFlags MethodFlags
			{
				get
				{
					return _methodFlags;
				}
				set
				{
					_methodFlags = value;
				}
			}

			protected URTParam MethodType => _methodType;

			internal static bool FlagTest(MethodPrintEnum flag, MethodPrintEnum target)
			{
				if ((flag & target) == target)
				{
					return true;
				}
				return false;
			}

			internal static bool MethodFlagsTest(MethodFlags flag, MethodFlags target)
			{
				if ((flag & target) == target)
				{
					return true;
				}
				return false;
			}

			internal URTMethod(string name, string soapAction, string methodAttributes, URTComplexType complexType)
			{
				_methodName = name;
				_soapAction = soapAction;
				_methodType = null;
				_complexType = complexType;
				name.IndexOf('.');
				_methodFlags = MethodFlags.None;
				if (methodAttributes == null || methodAttributes.Length <= 0)
				{
					return;
				}
				string[] array = methodAttributes.Split(' ');
				string[] array2 = array;
				foreach (string text in array2)
				{
					if (text == "virtual")
					{
						_methodFlags |= MethodFlags.Virtual;
					}
					if (text == "new")
					{
						_methodFlags |= MethodFlags.New;
					}
					if (text == "override")
					{
						_methodFlags |= MethodFlags.Override;
					}
					if (text == "public")
					{
						_methodFlags |= MethodFlags.Public;
					}
					if (text == "protected")
					{
						_methodFlags |= MethodFlags.Protected;
					}
					if (text == "internal")
					{
						_methodFlags |= MethodFlags.Internal;
					}
				}
			}

			internal string GetTypeString(string curNS, bool bNS)
			{
				if (_methodType == null)
				{
					return "void";
				}
				return _methodType.GetTypeString(curNS, bNS);
			}

			public override int GetHashCode()
			{
				return base.GetHashCode();
			}

			public override bool Equals(object obj)
			{
				URTMethod uRTMethod = (URTMethod)obj;
				if (MatchingStrings(_methodName, uRTMethod._methodName) && _params.Count == uRTMethod._params.Count)
				{
					for (int i = 0; i < _params.Count; i++)
					{
						if (!_params[i].Equals(uRTMethod._params[i]))
						{
							return false;
						}
					}
					return true;
				}
				return false;
			}

			internal MethodFlags GetMethodFlags(MethodInfo method)
			{
				return _methodFlags;
			}

			internal void AddParam(URTParam newParam)
			{
				for (int i = 0; i < _params.Count; i++)
				{
					URTParam uRTParam = (URTParam)_params[i];
					if (MatchingStrings(uRTParam.Name, newParam.Name))
					{
						if (uRTParam.ParamType == URTParamType.IN && newParam.ParamType == URTParamType.OUT && MatchingStrings(uRTParam.TypeName, newParam.TypeName) && MatchingStrings(uRTParam.TypeNS, newParam.TypeNS))
						{
							uRTParam.ParamType = URTParamType.REF;
							return;
						}
						throw new SUDSParserException(CoreChannel.GetResourceString("Remoting_Suds_DuplicateParameter"));
					}
				}
				int num = -1;
				if (_paramNamesOrder != null)
				{
					for (int j = 0; j < _paramNamesOrder.Length; j++)
					{
						if (_paramNamesOrder[j] == newParam.Name)
						{
							num = j;
							break;
						}
					}
					if (num == -1)
					{
						_methodType = newParam;
						return;
					}
					_params.Add(newParam);
					_paramPosition.Add(num);
				}
				else if (_methodType == null && newParam.ParamType == URTParamType.OUT)
				{
					_methodType = newParam;
				}
				else
				{
					_params.Add(newParam);
				}
			}

			internal void ResolveMethodAttributes()
			{
				if (!MethodFlagsTest(_methodFlags, MethodFlags.Override) && !MethodFlagsTest(_methodFlags, MethodFlags.New))
				{
					FindMethodAttributes();
				}
			}

			private void FindMethodAttributes()
			{
				if (_complexType == null)
				{
					return;
				}
				ArrayList arrayList = _complexType.Inherit;
				Type type = null;
				if (arrayList == null)
				{
					arrayList = new ArrayList();
					if (_complexType.SUDSType == SUDSType.ClientProxy)
					{
						type = typeof(RemotingClientProxy);
					}
					else if (_complexType.SudsUse == SudsUse.MarshalByRef)
					{
						type = typeof(MarshalByRefObject);
					}
					else if (_complexType.SudsUse == SudsUse.ServicedComponent)
					{
						type = typeof(MarshalByRefObject);
					}
					if (type == null)
					{
						return;
					}
					while (type != null)
					{
						arrayList.Add(type);
						type = type.BaseType;
					}
					_complexType.Inherit = arrayList;
				}
				BindingFlags bindingAttr = BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
				bool flag = MethodFlagsTest(_methodFlags, MethodFlags.Virtual);
				bool flag2 = false;
				for (int i = 0; i < arrayList.Count; i++)
				{
					type = (Type)arrayList[i];
					MethodInfo[] array = null;
					try
					{
						MethodInfo method = type.GetMethod(Name, bindingAttr);
						if (method != null)
						{
							array = new MethodInfo[1] { method };
						}
					}
					catch
					{
						array = type.GetMethods(bindingAttr);
					}
					if (array != null)
					{
						MethodInfo[] array2 = array;
						foreach (MethodBase methodBase in array2)
						{
							if (methodBase == null || !(methodBase.Name == Name) || (!methodBase.IsFamily && !methodBase.IsPublic && !methodBase.IsAssembly) || !IsSignature(methodBase))
							{
								continue;
							}
							flag2 = true;
							if (!methodBase.IsPublic)
							{
								if (methodBase.IsAssembly)
								{
									_methodFlags &= ~MethodFlags.Public;
									_methodFlags |= MethodFlags.Internal;
								}
								else if (methodBase.IsFamily)
								{
									_methodFlags &= ~MethodFlags.Public;
									_methodFlags |= MethodFlags.Protected;
								}
							}
							if (methodBase.IsFinal)
							{
								_methodFlags |= MethodFlags.New;
							}
							else if (methodBase.IsVirtual && flag)
							{
								_methodFlags |= MethodFlags.Override;
							}
							else
							{
								_methodFlags |= MethodFlags.New;
							}
							break;
						}
					}
					if (flag2)
					{
						break;
					}
				}
			}

			private bool IsSignature(MethodBase baseInfo)
			{
				ParameterInfo[] parameters = baseInfo.GetParameters();
				if (_params.Count != parameters.Length)
				{
					return false;
				}
				bool result = true;
				for (int i = 0; i < parameters.Length; i++)
				{
					URTParam uRTParam = (URTParam)_params[i];
					if (uRTParam.GetTypeString(null, bNS: true) != parameters[i].ParameterType.FullName)
					{
						result = false;
						break;
					}
				}
				return result;
			}

			internal void PrintSignature(StringBuilder sb, string curNS)
			{
				for (int i = 0; i < _params.Count; i++)
				{
					if (i != 0)
					{
						sb.Append(", ");
					}
					((URTParam)_params[i]).PrintCSC(sb, curNS);
				}
			}

			internal virtual void PrintCSC(TextWriter textWriter, string indentation, string namePrefix, string curNS, MethodPrintEnum methodPrintEnum, bool bURTType, string bodyPrefix, StringBuilder sb)
			{
				sb.Length = 0;
				sb.Append(indentation);
				if (Name == "Finalize")
				{
					return;
				}
				if (FlagTest(methodPrintEnum, MethodPrintEnum.InterfaceInClass))
				{
					sb.Append("public ");
				}
				else if (MethodFlagsTest(_methodFlags, MethodFlags.Public))
				{
					sb.Append("public ");
				}
				else if (MethodFlagsTest(_methodFlags, MethodFlags.Protected))
				{
					sb.Append("protected ");
				}
				else if (MethodFlagsTest(_methodFlags, MethodFlags.Internal))
				{
					sb.Append("internal ");
				}
				if (MethodFlagsTest(_methodFlags, MethodFlags.Override))
				{
					sb.Append("override ");
				}
				else if (MethodFlagsTest(_methodFlags, MethodFlags.Virtual))
				{
					sb.Append("virtual ");
				}
				if (MethodFlagsTest(_methodFlags, MethodFlags.New))
				{
					sb.Append("new ");
				}
				sb.Append(IsValidCSAttr(GetTypeString(curNS, bNS: true)));
				if (FlagTest(methodPrintEnum, MethodPrintEnum.InterfaceInClass))
				{
					sb.Append(" ");
				}
				else
				{
					sb.Append(IsValidCSAttr(namePrefix));
				}
				if (_wsdlMethodInfo.bProperty)
				{
					sb.Append(IsValidCS(_wsdlMethodInfo.propertyName));
				}
				else
				{
					sb.Append(IsValidCS(_methodName));
					sb.Append('(');
					if (_params.Count > 0)
					{
						((URTParam)_params[0]).PrintCSC(sb, curNS);
						for (int i = 1; i < _params.Count; i++)
						{
							sb.Append(", ");
							((URTParam)_params[i]).PrintCSC(sb, curNS);
						}
					}
					sb.Append(')');
				}
				if (_wsdlMethodInfo.bProperty && FlagTest(methodPrintEnum, MethodPrintEnum.InterfaceMethods))
				{
					sb.Append("{");
					if (_wsdlMethodInfo.bGet)
					{
						sb.Append(" get; ");
					}
					if (_wsdlMethodInfo.bSet)
					{
						sb.Append(" set; ");
					}
					sb.Append("}");
				}
				else if (!FlagTest(methodPrintEnum, MethodPrintEnum.PrintBody))
				{
					sb.Append(';');
				}
				textWriter.WriteLine(sb);
				if (_wsdlMethodInfo.bProperty && FlagTest(methodPrintEnum, MethodPrintEnum.PrintBody))
				{
					PrintPropertyBody(textWriter, indentation, sb, bodyPrefix);
				}
				else
				{
					if (!FlagTest(methodPrintEnum, MethodPrintEnum.PrintBody))
					{
						return;
					}
					sb.Length = 0;
					sb.Append(indentation);
					sb.Append('{');
					textWriter.WriteLine(sb);
					string value = indentation + "    ";
					if (bodyPrefix == null)
					{
						for (int j = 0; j < _params.Count; j++)
						{
							URTParam uRTParam = (URTParam)_params[j];
							if (uRTParam.ParamType == URTParamType.OUT)
							{
								sb.Length = 0;
								sb.Append(value);
								sb.Append(IsValidCS(uRTParam.Name));
								sb.Append(" = ");
								sb.Append(ValueString(uRTParam.GetTypeString(curNS, bNS: true)));
								sb.Append(';');
								textWriter.WriteLine(sb);
							}
						}
						sb.Length = 0;
						sb.Append(value);
						sb.Append("return");
						string text = ValueString(GetTypeString(curNS, bNS: true));
						if (text != null)
						{
							sb.Append('(');
							sb.Append(text);
							sb.Append(')');
						}
						sb.Append(';');
					}
					else
					{
						sb.Length = 0;
						sb.Append(value);
						if (ValueString(GetTypeString(curNS, bNS: true)) != null)
						{
							sb.Append("return ");
						}
						PrintMethodName(sb, bodyPrefix, _methodName);
						sb.Append('(');
						if (_params.Count > 0)
						{
							((URTParam)_params[0]).PrintCSC(sb);
							for (int k = 1; k < _params.Count; k++)
							{
								sb.Append(", ");
								((URTParam)_params[k]).PrintCSC(sb);
							}
						}
						sb.Append(");");
					}
					textWriter.WriteLine(sb);
					textWriter.Write(indentation);
					textWriter.WriteLine('}');
				}
			}

			private void PrintSoapAction(string action, StringBuilder sb)
			{
				sb.Append("[SoapMethod(SoapAction=");
				sb.Append(IsValidUrl(action));
				sb.Append(")]");
			}

			private void PrintPropertyBody(TextWriter textWriter, string indentation, StringBuilder sb, string bodyPrefix)
			{
				sb.Length = 0;
				sb.Append(indentation);
				sb.Append('{');
				textWriter.WriteLine(sb);
				string value = indentation + "    ";
				sb.Length = 0;
				sb.Append(value);
				if (_wsdlMethodInfo.bGet)
				{
					sb.Length = 0;
					sb.Append(value);
					PrintSoapAction(_wsdlMethodInfo.soapActionGet, sb);
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(value);
					sb.Append("get{return ");
					PrintMethodName(sb, bodyPrefix, _wsdlMethodInfo.propertyName);
					sb.Append(";}");
					textWriter.WriteLine(sb);
				}
				if (_wsdlMethodInfo.bSet)
				{
					if (_wsdlMethodInfo.bGet)
					{
						textWriter.WriteLine();
					}
					sb.Length = 0;
					sb.Append(value);
					PrintSoapAction(_wsdlMethodInfo.soapActionSet, sb);
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(value);
					sb.Append("set{");
					PrintMethodName(sb, bodyPrefix, _wsdlMethodInfo.propertyName);
					sb.Append("= value;}");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append(indentation);
				sb.Append('}');
				textWriter.WriteLine(sb);
			}

			private void PrintMethodName(StringBuilder sb, string bodyPrefix, string name)
			{
				int num = name.LastIndexOf('.');
				if (num < 0)
				{
					sb.Append(bodyPrefix);
					sb.Append(IsValidCS(name));
					return;
				}
				string identifier = name.Substring(0, num);
				string identifier2 = name.Substring(num + 1);
				if (bodyPrefix == null)
				{
					sb.Append("(");
					sb.Append(IsValidCS(identifier));
					sb.Append(")");
					sb.Append(IsValidCS(identifier2));
				}
				else
				{
					sb.Append("((");
					sb.Append(IsValidCS(identifier));
					sb.Append(") _tp).");
					sb.Append(IsValidCS(identifier2));
				}
			}

			internal static string ValueString(string paramType)
			{
				switch (paramType)
				{
				case "void":
					return null;
				case "bool":
					return "false";
				case "string":
					return "null";
				case "sbyte":
				case "byte":
				case "short":
				case "ushort":
				case "int":
				case "uint":
				case "long":
				case "ulong":
					return "1";
				case "float":
				case "exfloat":
					return "(float)1.0";
				case "double":
				case "exdouble":
					return "1.0";
				default:
				{
					StringBuilder stringBuilder = new StringBuilder(50);
					stringBuilder.Append('(');
					stringBuilder.Append(IsValidCS(paramType));
					stringBuilder.Append(") (Object) null");
					return stringBuilder.ToString();
				}
				}
			}

			internal abstract void ResolveTypes(WsdlParser parser);

			protected void ResolveWsdlParams(WsdlParser parser, string targetNS, string targetName, bool bRequest, WsdlMethodInfo wsdlMethodInfo)
			{
				_wsdlMethodInfo = wsdlMethodInfo;
				_paramNamesOrder = _wsdlMethodInfo.paramNamesOrder;
				int num = (_wsdlMethodInfo.bProperty ? 1 : ((!bRequest) ? wsdlMethodInfo.outputNames.Length : wsdlMethodInfo.inputNames.Length));
				for (int i = 0; i < num; i++)
				{
					string text = null;
					string text2 = null;
					string name = null;
					string text3 = null;
					string text4 = null;
					URTParamType pType;
					if (_wsdlMethodInfo.bProperty)
					{
						text3 = wsdlMethodInfo.propertyType;
						text4 = wsdlMethodInfo.propertyNs;
						pType = URTParamType.OUT;
					}
					else if (bRequest && !_wsdlMethodInfo.bProperty)
					{
						text = wsdlMethodInfo.inputElements[i];
						text2 = wsdlMethodInfo.inputElementsNs[i];
						name = wsdlMethodInfo.inputNames[i];
						_ = wsdlMethodInfo.inputNamesNs[i];
						text3 = wsdlMethodInfo.inputTypes[i];
						text4 = wsdlMethodInfo.inputTypesNs[i];
						pType = URTParamType.IN;
					}
					else
					{
						text = wsdlMethodInfo.outputElements[i];
						text2 = wsdlMethodInfo.outputElementsNs[i];
						name = wsdlMethodInfo.outputNames[i];
						_ = wsdlMethodInfo.outputNamesNs[i];
						text3 = wsdlMethodInfo.outputTypes[i];
						text4 = wsdlMethodInfo.outputTypesNs[i];
						pType = URTParamType.OUT;
					}
					string text5;
					string text6;
					if (text == null || text.Length == 0)
					{
						text5 = text3;
						text6 = text4;
					}
					else
					{
						text5 = text;
						text6 = text2;
					}
					URTNamespace uRTNamespace = parser.LookupNamespace(text6);
					if (uRTNamespace == null)
					{
						throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveSchemaNS"), text6, text5));
					}
					URTComplexType uRTComplexType = uRTNamespace.LookupComplexType(text5);
					if (uRTComplexType != null && uRTComplexType.IsArray())
					{
						if (uRTComplexType.GetArray() == null)
						{
							uRTComplexType.ResolveArray();
						}
						string array = uRTComplexType.GetArray();
						URTNamespace arrayNS = uRTComplexType.GetArrayNS();
						AddParam(new URTParam(name, array, arrayNS.Name, arrayNS.EncodedNS, pType, bEmbedded: true, parser, arrayNS));
					}
					else if (uRTNamespace.UrtType == UrtType.Xsd)
					{
						string typeName = parser.MapSchemaTypesToCSharpTypes(text5);
						AddParam(new URTParam(name, typeName, uRTNamespace.Namespace, uRTNamespace.EncodedNS, pType, bEmbedded: true, parser, uRTNamespace));
					}
					else
					{
						string text7 = null;
						if (uRTComplexType != null)
						{
							text7 = uRTComplexType.Name;
						}
						else
						{
							URTSimpleType uRTSimpleType = uRTNamespace.LookupSimpleType(text5);
							text7 = ((uRTSimpleType == null) ? text5 : uRTSimpleType.Name);
						}
						AddParam(new URTParam(name, text7, uRTNamespace.Namespace, uRTNamespace.EncodedNS, pType, bEmbedded: true, parser, uRTNamespace));
					}
				}
			}
		}

		internal class RRMethod : URTMethod
		{
			private string _requestElementName;

			private string _requestElementNS;

			private string _responseElementName;

			private string _responseElementNS;

			private WsdlMethodInfo _wsdlMethodInfo;

			internal RRMethod(WsdlMethodInfo wsdlMethodInfo, URTComplexType complexType)
				: base(wsdlMethodInfo.methodName, wsdlMethodInfo.soapAction, wsdlMethodInfo.methodAttributes, complexType)
			{
				_wsdlMethodInfo = wsdlMethodInfo;
				_requestElementName = null;
				_requestElementNS = null;
				_responseElementName = null;
				_responseElementNS = null;
			}

			internal void AddRequest(string name, string ns)
			{
				_requestElementName = name;
				_requestElementNS = ns;
			}

			internal void AddResponse(string name, string ns)
			{
				_responseElementName = name;
				_responseElementNS = ns;
			}

			internal override void ResolveTypes(WsdlParser parser)
			{
				ResolveWsdlParams(parser, _requestElementNS, _requestElementName, bRequest: true, _wsdlMethodInfo);
				ResolveWsdlParams(parser, _responseElementNS, _responseElementName, bRequest: false, _wsdlMethodInfo);
				if (_paramNamesOrder != null)
				{
					object[] array = new object[_params.Count];
					for (int i = 0; i < _params.Count; i++)
					{
						array[(int)_paramPosition[i]] = _params[i];
					}
					_params = new ArrayList(array);
				}
				ResolveMethodAttributes();
			}

			internal override void PrintCSC(TextWriter textWriter, string indentation, string namePrefix, string curNS, MethodPrintEnum methodPrintEnum, bool bURTType, string bodyPrefix, StringBuilder sb)
			{
				if (base.Name == "Finalize")
				{
					return;
				}
				bool flag = false;
				if (base.SoapAction != null)
				{
					flag = true;
				}
				if ((flag || !bURTType) && !_wsdlMethodInfo.bProperty)
				{
					sb.Length = 0;
					sb.Append(indentation);
					sb.Append("[SoapMethod(");
					if (flag)
					{
						sb.Append("SoapAction=");
						sb.Append(IsValidUrl(base.SoapAction));
					}
					if (!bURTType)
					{
						if (flag)
						{
							sb.Append(",");
						}
						sb.Append("ResponseXmlElementName=");
						sb.Append(IsValidUrl(_responseElementName));
						if (base.MethodType != null)
						{
							sb.Append(", ReturnXmlElementName=");
							sb.Append(IsValidUrl(base.MethodType.Name));
						}
						sb.Append(", XmlNamespace=");
						sb.Append(IsValidUrl(_wsdlMethodInfo.inputMethodNameNs));
						sb.Append(", ResponseXmlNamespace=");
						sb.Append(IsValidUrl(_wsdlMethodInfo.outputMethodNameNs));
					}
					sb.Append(")]");
					textWriter.WriteLine(sb);
				}
				base.PrintCSC(textWriter, indentation, namePrefix, curNS, methodPrintEnum, bURTType, bodyPrefix, sb);
			}
		}

		internal class OnewayMethod : URTMethod
		{
			private string _messageElementName;

			private string _messageElementNS;

			private WsdlMethodInfo _wsdlMethodInfo;

			internal OnewayMethod(string name, string soapAction, URTComplexType complexType)
				: base(name, soapAction, null, complexType)
			{
				_messageElementName = null;
				_messageElementNS = null;
			}

			internal OnewayMethod(WsdlMethodInfo wsdlMethodInfo, URTComplexType complexType)
				: base(wsdlMethodInfo.methodName, wsdlMethodInfo.soapAction, wsdlMethodInfo.methodAttributes, complexType)
			{
				_wsdlMethodInfo = wsdlMethodInfo;
				_messageElementName = null;
				_messageElementNS = null;
			}

			internal void AddMessage(string name, string ns)
			{
				_messageElementName = name;
				_messageElementNS = ns;
			}

			internal override void ResolveTypes(WsdlParser parser)
			{
				ResolveWsdlParams(parser, _messageElementNS, _messageElementName, bRequest: true, _wsdlMethodInfo);
				if (_paramNamesOrder != null)
				{
					object[] array = new object[_params.Count];
					for (int i = 0; i < _params.Count; i++)
					{
						array[(int)_paramPosition[i]] = _params[i];
					}
					_params = new ArrayList(array);
				}
				ResolveMethodAttributes();
			}

			internal override void PrintCSC(TextWriter textWriter, string indentation, string namePrefix, string curNS, MethodPrintEnum methodPrintEnum, bool bURTType, string bodyPrefix, StringBuilder sb)
			{
				if (base.Name == "Finalize")
				{
					return;
				}
				bool flag = false;
				if (base.SoapAction != null)
				{
					flag = true;
				}
				if (!flag && bURTType)
				{
					textWriter.Write(indentation);
					textWriter.WriteLine("[OneWay]");
				}
				else
				{
					sb.Length = 0;
					sb.Append(indentation);
					sb.Append("[OneWay, SoapMethod(");
					if (flag)
					{
						sb.Append("SoapAction=");
						sb.Append(IsValidUrl(base.SoapAction));
					}
					if (!bURTType)
					{
						if (flag)
						{
							sb.Append(",");
						}
						sb.Append("XmlNamespace=");
						sb.Append(IsValidUrl(_wsdlMethodInfo.inputMethodNameNs));
					}
					sb.Append(")]");
					textWriter.WriteLine(sb);
				}
				base.PrintCSC(textWriter, indentation, namePrefix, curNS, methodPrintEnum, bURTType, bodyPrefix, sb);
			}
		}

		internal abstract class BaseInterface
		{
			private string _name;

			private string _urlNS;

			private string _namespace;

			private string _encodedNS;

			private WsdlParser _parser;

			internal string Name => _name;

			internal string UrlNS => _urlNS;

			internal string Namespace => _namespace;

			internal bool IsURTInterface => (object)_namespace == _encodedNS;

			internal BaseInterface(string name, string urlNS, string ns, string encodedNS, WsdlParser parser)
			{
				_name = name;
				_urlNS = urlNS;
				_namespace = ns;
				_encodedNS = encodedNS;
				_parser = parser;
			}

			internal string GetName(string curNS)
			{
				if (_parser.Qualify(_namespace, curNS))
				{
					StringBuilder stringBuilder = new StringBuilder(_encodedNS, 50);
					stringBuilder.Append('.');
					stringBuilder.Append(IsValidCS(_name));
					return stringBuilder.ToString();
				}
				return _name;
			}

			internal abstract void PrintClassMethods(TextWriter textWriter, string indentation, string curNS, ArrayList printedIFaces, bool bProxy, StringBuilder sb);
		}

		internal class SystemInterface : BaseInterface
		{
			private Type _type;

			internal SystemInterface(string name, string urlNS, string ns, WsdlParser parser, string assemName)
				: base(name, urlNS, ns, ns, parser)
			{
				string name2 = ns + '.' + name;
				Assembly assembly = null;
				assembly = ((assemName != null) ? Assembly.LoadWithPartialName(assemName, null) : typeof(string).Assembly);
				if (assembly == null)
				{
					throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_AssemblyNotFound"), assemName));
				}
				_type = assembly.GetType(name2, throwOnError: true);
			}

			internal override void PrintClassMethods(TextWriter textWriter, string indentation, string curNS, ArrayList printedIFaces, bool bProxy, StringBuilder sb)
			{
				int i;
				for (i = 0; i < printedIFaces.Count; i++)
				{
					if (printedIFaces[i] is SystemInterface)
					{
						SystemInterface systemInterface = (SystemInterface)printedIFaces[i];
						if (systemInterface._type == _type)
						{
							return;
						}
					}
				}
				printedIFaces.Add(this);
				BindingFlags bindingAttr = BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Public;
				ArrayList arrayList = new ArrayList();
				sb.Length = 0;
				arrayList.Add(_type);
				i = 0;
				for (int num = 1; i < num; i++)
				{
					Type type = (Type)arrayList[i];
					MethodInfo[] methods = type.GetMethods(bindingAttr);
					Type[] interfaces = type.GetInterfaces();
					for (int j = 0; j < interfaces.Length; j++)
					{
						int num2 = 0;
						while (true)
						{
							if (num2 < num)
							{
								if (arrayList[i] == interfaces[j])
								{
									break;
								}
								num2++;
								continue;
							}
							arrayList.Add(interfaces[j]);
							num++;
							break;
						}
					}
					foreach (MethodInfo methodInfo in methods)
					{
						sb.Length = 0;
						sb.Append(indentation);
						sb.Append(CSharpTypeString(methodInfo.ReturnType.FullName));
						sb.Append(' ');
						sb.Append(IsValidCS(type.FullName));
						sb.Append('.');
						sb.Append(IsValidCS(methodInfo.Name));
						sb.Append('(');
						ParameterInfo[] parameters = methodInfo.GetParameters();
						for (int l = 0; l < parameters.Length; l++)
						{
							if (l != 0)
							{
								sb.Append(", ");
							}
							ParameterInfo parameterInfo = parameters[l];
							Type type2 = parameterInfo.ParameterType;
							if (parameterInfo.IsIn)
							{
								sb.Append("in ");
							}
							else if (parameterInfo.IsOut)
							{
								sb.Append("out ");
							}
							else if (type2.IsByRef)
							{
								sb.Append("ref ");
								type2 = type2.GetElementType();
							}
							sb.Append(CSharpTypeString(type2.FullName));
							sb.Append(' ');
							sb.Append(IsValidCS(parameterInfo.Name));
						}
						sb.Append(')');
						textWriter.WriteLine(sb);
						textWriter.Write(indentation);
						textWriter.WriteLine('{');
						string value = indentation + "    ";
						if (!bProxy)
						{
							foreach (ParameterInfo parameterInfo2 in parameters)
							{
								_ = parameterInfo2.ParameterType;
								if (parameterInfo2.IsOut)
								{
									sb.Length = 0;
									sb.Append(value);
									sb.Append(IsValidCS(parameterInfo2.Name));
									sb.Append(URTMethod.ValueString(CSharpTypeString(parameterInfo2.ParameterType.FullName)));
									sb.Append(';');
									textWriter.WriteLine(sb);
								}
							}
							sb.Length = 0;
							sb.Append(value);
							sb.Append("return");
							string text = URTMethod.ValueString(CSharpTypeString(methodInfo.ReturnType.FullName));
							if (text != null)
							{
								sb.Append('(');
								sb.Append(text);
								sb.Append(')');
							}
							sb.Append(';');
						}
						else
						{
							sb.Length = 0;
							sb.Append(value);
							sb.Append("return((");
							sb.Append(IsValidCS(type.FullName));
							sb.Append(") _tp).");
							sb.Append(IsValidCS(methodInfo.Name));
							sb.Append('(');
							if (parameters.Length > 0)
							{
								int num3 = parameters.Length - 1;
								for (int n = 0; n < parameters.Length; n++)
								{
									ParameterInfo parameterInfo3 = parameters[0];
									Type parameterType = parameterInfo3.ParameterType;
									if (parameterInfo3.IsIn)
									{
										sb.Append("in ");
									}
									else if (parameterInfo3.IsOut)
									{
										sb.Append("out ");
									}
									else if (parameterType.IsByRef)
									{
										sb.Append("ref ");
									}
									sb.Append(IsValidCS(parameterInfo3.Name));
									if (n < num3)
									{
										sb.Append(", ");
									}
								}
							}
							sb.Append(");");
						}
						textWriter.WriteLine(sb);
						textWriter.Write(indentation);
						textWriter.WriteLine('}');
					}
				}
			}

			private static string CSharpTypeString(string typeName)
			{
				string identifier = typeName;
				if (typeName == "System.SByte")
				{
					identifier = "sbyte";
				}
				else
				{
					switch (typeName)
					{
					case "System.byte":
						identifier = "byte";
						break;
					case "System.Int16":
						identifier = "short";
						break;
					case "System.UInt16":
						identifier = "ushort";
						break;
					case "System.Int32":
						identifier = "int";
						break;
					case "System.UInt32":
						identifier = "uint";
						break;
					case "System.Int64":
						identifier = "long";
						break;
					case "System.UInt64":
						identifier = "ulong";
						break;
					case "System.Char":
						identifier = "char";
						break;
					case "System.Single":
						identifier = "float";
						break;
					case "System.Double":
						identifier = "double";
						break;
					case "System.Boolean":
						identifier = "boolean";
						break;
					case "System.Void":
						identifier = "void";
						break;
					case "System.String":
						identifier = "String";
						break;
					}
				}
				return IsValidCSAttr(identifier);
			}
		}

		internal class URTInterface : BaseInterface
		{
			private WsdlParser _parser;

			private ArrayList _baseIFaces;

			private ArrayList _baseIFaceNames;

			private ArrayList _methods;

			private ArrayList _extendsInterface;

			internal URTInterface(string name, string urlNS, string ns, string encodedNS, WsdlParser parser)
				: base(name, urlNS, ns, encodedNS, parser)
			{
				_baseIFaces = new ArrayList();
				_baseIFaceNames = new ArrayList();
				_extendsInterface = new ArrayList();
				_methods = new ArrayList();
				_parser = parser;
			}

			internal void Extends(string baseName, string baseNS, WsdlParser parser)
			{
				_baseIFaceNames.Add(baseName);
				_baseIFaceNames.Add(baseNS);
				URTNamespace uRTNamespace = parser.AddNewNamespace(baseNS);
				URTInterface uRTInterface = uRTNamespace.LookupInterface(baseName);
				if (uRTInterface == null)
				{
					uRTInterface = new URTInterface(baseName, uRTNamespace.Name, uRTNamespace.Namespace, uRTNamespace.EncodedNS, parser);
					uRTNamespace.AddInterface(uRTInterface);
				}
				_extendsInterface.Add(uRTInterface);
			}

			internal void AddMethod(URTMethod method)
			{
				_methods.Add(method);
				method.MethodFlags = MethodFlags.None;
			}

			internal void NewNeeded(URTMethod method)
			{
				foreach (URTInterface item in _extendsInterface)
				{
					item.CheckIfNewNeeded(method);
					if (URTMethod.MethodFlagsTest(method.MethodFlags, MethodFlags.New))
					{
						break;
					}
				}
			}

			private void CheckIfNewNeeded(URTMethod method)
			{
				foreach (URTMethod method2 in _methods)
				{
					if (method2.Name == method.Name)
					{
						method.MethodFlags |= MethodFlags.New;
						break;
					}
				}
				if (URTMethod.MethodFlagsTest(method.MethodFlags, MethodFlags.New))
				{
					NewNeeded(method);
				}
			}

			internal void ResolveTypes(WsdlParser parser)
			{
				for (int i = 0; i < _baseIFaceNames.Count; i += 2)
				{
					string text = (string)_baseIFaceNames[i];
					string text2 = (string)_baseIFaceNames[i + 1];
					string ns;
					string assemName;
					UrtType urtType = parser.IsURTExportedType(text2, out ns, out assemName);
					BaseInterface baseInterface;
					if (urtType != UrtType.Interop && ns.StartsWith("System", StringComparison.Ordinal))
					{
						baseInterface = new SystemInterface(text, text2, ns, _parser, assemName);
					}
					else
					{
						URTNamespace uRTNamespace = parser.LookupNamespace(text2);
						if (uRTNamespace == null)
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveSchemaNS"), text2, text));
						}
						baseInterface = uRTNamespace.LookupInterface(text);
						if (baseInterface == null)
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveTypeInNS"), text, text2));
						}
					}
					_baseIFaces.Add(baseInterface);
				}
				for (int j = 0; j < _methods.Count; j++)
				{
					((URTMethod)_methods[j]).ResolveTypes(parser);
				}
			}

			internal void PrintCSC(TextWriter textWriter, string indentation, string curNS, StringBuilder sb)
			{
				bool isURTInterface = base.IsURTInterface;
				sb.Length = 0;
				sb.Append("\n");
				sb.Append(indentation);
				sb.Append("[SoapType(");
				if (_parser._xsdVersion == XsdVersion.V1999)
				{
					sb.Append("SoapOptions=SoapOption.Option1|SoapOption.AlwaysIncludeTypes|SoapOption.XsdString|SoapOption.EmbedAll,");
				}
				else if (_parser._xsdVersion == XsdVersion.V2000)
				{
					sb.Append("SoapOptions=SoapOption.Option2|SoapOption.AlwaysIncludeTypes|SoapOption.XsdString|SoapOption.EmbedAll,");
				}
				if (!isURTInterface)
				{
					sb.Append("XmlElementName=");
					sb.Append(IsValidUrl(base.Name));
					sb.Append(", XmlNamespace=");
					sb.Append(IsValidUrl(base.Namespace));
					sb.Append(", XmlTypeName=");
					sb.Append(IsValidUrl(base.Name));
					sb.Append(", XmlTypeNamespace=");
					sb.Append(IsValidUrl(base.Namespace));
				}
				else
				{
					sb.Append("XmlNamespace=");
					sb.Append(IsValidUrl(base.UrlNS));
					sb.Append(", XmlTypeNamespace=");
					sb.Append(IsValidUrl(base.UrlNS));
				}
				sb.Append(")]");
				sb.Append("[ComVisible(true)]");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(indentation);
				sb.Append("public interface ");
				sb.Append(IsValidCS(base.Name));
				if (_baseIFaces.Count > 0)
				{
					sb.Append(" : ");
				}
				if (_baseIFaces.Count > 0)
				{
					sb.Append(IsValidCSAttr(((BaseInterface)_baseIFaces[0]).GetName(curNS)));
					for (int i = 1; i < _baseIFaces.Count; i++)
					{
						sb.Append(", ");
						sb.Append(IsValidCSAttr(((BaseInterface)_baseIFaces[i]).GetName(curNS)));
					}
				}
				textWriter.WriteLine(sb);
				textWriter.Write(indentation);
				textWriter.WriteLine('{');
				string indentation2 = indentation + "    ";
				string namePrefix = " ";
				for (int j = 0; j < _methods.Count; j++)
				{
					NewNeeded((URTMethod)_methods[j]);
					((URTMethod)_methods[j]).PrintCSC(textWriter, indentation2, namePrefix, curNS, MethodPrintEnum.InterfaceMethods, isURTInterface, null, sb);
				}
				textWriter.Write(indentation);
				textWriter.WriteLine('}');
			}

			internal override void PrintClassMethods(TextWriter textWriter, string indentation, string curNS, ArrayList printedIFaces, bool bProxy, StringBuilder sb)
			{
				for (int i = 0; i < printedIFaces.Count; i++)
				{
					if (printedIFaces[i] == this)
					{
						return;
					}
				}
				printedIFaces.Add(this);
				sb.Length = 0;
				sb.Append(indentation);
				if (_methods.Count > 0)
				{
					sb.Append("// ");
					sb.Append(IsValidCS(base.Name));
					sb.Append(" interface Methods");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(' ');
					string name = GetName(curNS);
					sb.Append(IsValidCS(name));
					sb.Append('.');
					string namePrefix = sb.ToString();
					string bodyPrefix = null;
					if (bProxy)
					{
						sb.Length = 0;
						sb.Append("((");
						sb.Append(IsValidCS(name));
						sb.Append(") _tp).");
						bodyPrefix = sb.ToString();
					}
					MethodPrintEnum methodPrintEnum = MethodPrintEnum.PrintBody | MethodPrintEnum.InterfaceInClass;
					for (int j = 0; j < _methods.Count; j++)
					{
						((URTMethod)_methods[j]).PrintCSC(textWriter, indentation, namePrefix, curNS, methodPrintEnum, bURTType: true, bodyPrefix, sb);
					}
				}
				for (int k = 0; k < _baseIFaces.Count; k++)
				{
					((BaseInterface)_baseIFaces[k]).PrintClassMethods(textWriter, indentation, curNS, printedIFaces, bProxy, sb);
				}
			}
		}

		internal class URTField
		{
			private string _name;

			private string _typeName;

			private string _typeNS;

			private string _encodedNS;

			private bool _primitiveField;

			private bool _embeddedField;

			private bool _attributeField;

			private bool _optionalField;

			private bool _arrayField;

			private string _arraySize;

			private WsdlParser _parser;

			private URTNamespace _urtNamespace;

			internal string TypeName
			{
				get
				{
					if (_arrayField)
					{
						return _typeName + "[]";
					}
					return _typeName;
				}
			}

			internal string TypeNS => _typeNS;

			internal bool IsPrimitive => _primitiveField;

			internal bool IsArray => _arrayField;

			internal URTField(string name, string typeName, string xmlNS, WsdlParser parser, bool bPrimitive, bool bEmbedded, bool bAttribute, bool bOptional, bool bArray, string arraySize, URTNamespace urtNamespace)
			{
				_name = name;
				_typeName = typeName;
				_parser = parser;
				string assemName;
				UrtType urtType = parser.IsURTExportedType(xmlNS, out _typeNS, out assemName);
				if (urtType == UrtType.Interop)
				{
					_encodedNS = urtNamespace.EncodedNS;
				}
				else
				{
					_encodedNS = _typeNS;
				}
				_primitiveField = bPrimitive;
				_embeddedField = bEmbedded;
				_attributeField = bAttribute;
				_optionalField = bOptional;
				_arrayField = bArray;
				_arraySize = arraySize;
				_urtNamespace = urtNamespace;
			}

			internal string GetTypeString(string curNS, bool bNS)
			{
				return _parser.GetTypeString(curNS, bNS, _urtNamespace, TypeName, _typeNS);
			}

			internal void PrintCSC(TextWriter textWriter, string indentation, string curNS, StringBuilder sb)
			{
				if (_embeddedField)
				{
					textWriter.Write(indentation);
					textWriter.WriteLine("[SoapField(Embedded=true)]");
				}
				sb.Length = 0;
				sb.Append(indentation);
				sb.Append("public ");
				sb.Append(IsValidCSAttr(GetTypeString(curNS, bNS: true)));
				sb.Append(' ');
				sb.Append(IsValidCS(_name));
				sb.Append(';');
				textWriter.WriteLine(sb);
			}
		}

		internal abstract class SchemaFacet
		{
			internal virtual void ResolveTypes(WsdlParser parser)
			{
			}

			internal abstract void PrintCSC(TextWriter textWriter, string newIndentation, string curNS, StringBuilder sb);
		}

		internal class EnumFacet : SchemaFacet
		{
			private string _valueString;

			private int _value;

			internal EnumFacet(string valueString, int value)
			{
				_valueString = valueString;
				_value = value;
			}

			internal override void PrintCSC(TextWriter textWriter, string newIndentation, string curNS, StringBuilder sb)
			{
				sb.Length = 0;
				sb.Append(newIndentation);
				sb.Append(IsValidCS(_valueString));
				sb.Append(" = ");
				sb.Append(_value);
				sb.Append(',');
				textWriter.WriteLine(sb);
			}
		}

		internal abstract class BaseType
		{
			private string _name;

			private string _searchName;

			private string _urlNS;

			private string _namespace;

			private string _elementName;

			private string _elementNS;

			private string _encodedNS;

			internal ArrayList _nestedTypes;

			internal string _nestedTypeName;

			internal string _fullNestedTypeName;

			internal string _outerTypeName;

			internal bool _bNestedType;

			internal bool _bNestedTypePrint;

			internal string Name
			{
				get
				{
					return _name;
				}
				set
				{
					_name = value;
				}
			}

			internal string SearchName
			{
				get
				{
					return _searchName;
				}
				set
				{
					_searchName = value;
				}
			}

			internal string OuterTypeName
			{
				set
				{
					_outerTypeName = value;
				}
			}

			internal string NestedTypeName
			{
				get
				{
					return _nestedTypeName;
				}
				set
				{
					_nestedTypeName = value;
				}
			}

			internal string FullNestedTypeName
			{
				set
				{
					_fullNestedTypeName = value;
				}
			}

			internal bool bNestedType
			{
				get
				{
					return _bNestedType;
				}
				set
				{
					_bNestedType = value;
				}
			}

			internal bool bNestedTypePrint
			{
				get
				{
					return _bNestedTypePrint;
				}
				set
				{
					_bNestedTypePrint = value;
				}
			}

			internal string UrlNS => _urlNS;

			internal string Namespace => _namespace;

			internal string ElementName
			{
				set
				{
					_elementName = value;
				}
			}

			internal string ElementNS
			{
				set
				{
					_elementNS = value;
				}
			}

			internal bool IsURTType => (object)_namespace == _encodedNS;

			internal abstract bool IsEmittableFieldType { get; }

			internal abstract string FieldName { get; }

			internal abstract string FieldNamespace { get; }

			internal abstract bool PrimitiveField { get; }

			internal BaseType(string name, string urlNS, string ns, string encodedNS)
			{
				_searchName = name;
				_name = name;
				_urlNS = urlNS;
				_namespace = ns;
				_elementName = _name;
				_elementNS = ns;
				_encodedNS = encodedNS;
			}

			internal virtual string GetName(string curNS)
			{
				if (MatchingStrings(_namespace, curNS))
				{
					return _name;
				}
				StringBuilder stringBuilder = new StringBuilder(_encodedNS, 50);
				stringBuilder.Append('.');
				stringBuilder.Append(IsValidCS(_name));
				return stringBuilder.ToString();
			}

			internal abstract MethodFlags GetMethodFlags(URTMethod method);
		}

		internal class SystemType : BaseType
		{
			private Type _type;

			internal override bool IsEmittableFieldType => true;

			internal override string FieldName => null;

			internal override string FieldNamespace => null;

			internal override bool PrimitiveField => false;

			internal SystemType(string name, string urlNS, string ns, string assemName)
				: base(name, urlNS, ns, ns)
			{
				string name2 = ns + '.' + name;
				Assembly assembly = null;
				assembly = ((assemName != null) ? Assembly.LoadWithPartialName(assemName, null) : typeof(string).Assembly);
				if (assembly == null)
				{
					throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_AssemblyNotFound"), assemName));
				}
				_type = assembly.GetType(name2, throwOnError: true);
			}

			internal override MethodFlags GetMethodFlags(URTMethod method)
			{
				BindingFlags bindingAttr = BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
				for (Type type = _type; type != null; type = type.BaseType)
				{
					MethodInfo[] methods = type.GetMethods(bindingAttr);
					for (int i = 0; i < methods.Length; i++)
					{
						MethodFlags methodFlags = method.GetMethodFlags(methods[i]);
						if (methodFlags != 0)
						{
							return methodFlags;
						}
					}
				}
				return MethodFlags.None;
			}
		}

		internal class URTSimpleType : BaseType
		{
			private string _baseTypeName;

			private string _baseTypeXmlNS;

			private BaseType _baseType;

			private string _fieldString;

			private bool _bEnum;

			private bool _bAnonymous;

			private string _encoding;

			private ArrayList _facets;

			private string _enumType;

			private WsdlParser _parser;

			internal bool IsEnum
			{
				get
				{
					return _bEnum;
				}
				set
				{
					_bEnum = value;
				}
			}

			internal string EnumType
			{
				set
				{
					string qname = value;
					_parser.ParseQName(ref qname);
					if (qname != null && qname.Length > 0)
					{
						_enumType = MapToEnumType(_parser.MapSchemaTypesToCSharpTypes(qname));
					}
				}
			}

			internal override bool IsEmittableFieldType
			{
				get
				{
					if (_fieldString == null)
					{
						if (_bAnonymous && _facets.Count == 0 && _encoding != null && _baseTypeName == "binary" && _parser.MatchingSchemaStrings(_baseTypeXmlNS))
						{
							_fieldString = "byte[]";
						}
						else
						{
							_fieldString = string.Empty;
						}
					}
					return _fieldString != string.Empty;
				}
			}

			internal override string FieldName => _fieldString;

			internal override string FieldNamespace
			{
				get
				{
					string result = null;
					if (_parser._xsdVersion == XsdVersion.V1999)
					{
						result = s_schemaNamespaceString1999;
					}
					else if (_parser._xsdVersion == XsdVersion.V2000)
					{
						result = s_schemaNamespaceString2000;
					}
					else if (_parser._xsdVersion == XsdVersion.V2001)
					{
						result = s_schemaNamespaceString;
					}
					return result;
				}
			}

			internal override bool PrimitiveField => true;

			internal URTSimpleType(string name, string urlNS, string ns, string encodedNS, bool bAnonymous, WsdlParser parser)
				: base(name, urlNS, ns, encodedNS)
			{
				_baseTypeName = null;
				_baseTypeXmlNS = null;
				_baseType = null;
				_fieldString = null;
				_facets = new ArrayList();
				_bEnum = false;
				_bAnonymous = bAnonymous;
				_encoding = null;
				_parser = parser;
			}

			internal void Extends(string baseTypeName, string baseTypeNS)
			{
				_baseTypeName = baseTypeName;
				_baseTypeXmlNS = baseTypeNS;
			}

			private string MapToEnumType(string type)
			{
				string text = null;
				return type switch
				{
					"Byte" => "byte", 
					"SByte" => "sbyte", 
					"Int16" => "short", 
					"UInt16" => "ushort", 
					"Int32" => "int", 
					"UInt32" => "uint", 
					"Int64" => "long", 
					"UInt64" => "ulong", 
					_ => throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_InvalidEnumType"), type)), 
				};
			}

			internal void AddFacet(SchemaFacet facet)
			{
				_facets.Add(facet);
			}

			internal override string GetName(string curNS)
			{
				if (_fieldString != null && _fieldString != string.Empty)
				{
					return _fieldString;
				}
				return base.GetName(curNS);
			}

			internal void PrintCSC(TextWriter textWriter, string indentation, string curNS, StringBuilder sb)
			{
				if (!IsEmittableFieldType && (!base.bNestedType || base.bNestedTypePrint))
				{
					_ = _encoding;
					sb.Length = 0;
					sb.Append("\n");
					sb.Append(indentation);
					sb.Append("[");
					sb.Append("Serializable, ");
					sb.Append("SoapType(");
					if (_parser._xsdVersion == XsdVersion.V1999)
					{
						sb.Append("SoapOptions=SoapOption.Option1|SoapOption.AlwaysIncludeTypes|SoapOption.XsdString|SoapOption.EmbedAll,");
					}
					else if (_parser._xsdVersion == XsdVersion.V2000)
					{
						sb.Append("SoapOptions=SoapOption.Option2|SoapOption.AlwaysIncludeTypes|SoapOption.XsdString|SoapOption.EmbedAll,");
					}
					sb.Append("XmlNamespace=");
					sb.Append(IsValidUrl(base.UrlNS));
					sb.Append(", XmlTypeNamespace=");
					sb.Append(IsValidUrl(base.UrlNS));
					sb.Append(")]");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(indentation);
					if (IsEnum)
					{
						sb.Append("public enum ");
					}
					else
					{
						sb.Append("public class ");
					}
					if (_bNestedType)
					{
						sb.Append(IsValidCS(base.NestedTypeName));
					}
					else
					{
						sb.Append(IsValidCS(base.Name));
					}
					if (_baseType != null)
					{
						sb.Append(" : ");
						sb.Append(IsValidCSAttr(_baseType.GetName(curNS)));
					}
					else if (IsEnum && _enumType != null && _enumType.Length > 0)
					{
						sb.Append(" : ");
						sb.Append(IsValidCSAttr(_enumType));
					}
					textWriter.WriteLine(sb);
					textWriter.Write(indentation);
					textWriter.WriteLine('{');
					string newIndentation = indentation + "    ";
					for (int i = 0; i < _facets.Count; i++)
					{
						((SchemaFacet)_facets[i]).PrintCSC(textWriter, newIndentation, curNS, sb);
					}
					textWriter.Write(indentation);
					textWriter.WriteLine('}');
				}
			}

			internal override MethodFlags GetMethodFlags(URTMethod method)
			{
				return MethodFlags.None;
			}
		}

		internal class URTComplexType : BaseType
		{
			private string _baseTypeName;

			private string _baseTypeXmlNS;

			private BaseType _baseType;

			private ArrayList _connectURLs;

			private bool _bStruct;

			private SchemaBlockType _blockType;

			private bool _bSUDSType;

			private bool _bAnonymous;

			private string _wireType;

			private ArrayList _inherit;

			private string _fieldString;

			private ArrayList _implIFaceNames;

			private ArrayList _implIFaces;

			private ArrayList _fields;

			private ArrayList _methods;

			private SUDSType _sudsType;

			private SudsUse _sudsUse;

			private bool _bValueType;

			private WsdlParser _parser;

			private string _arrayType;

			private URTNamespace _arrayNS;

			private string _clrarray;

			private bool _bprint = true;

			private bool _bNameMethodConflict;

			internal ArrayList ConnectURLs
			{
				set
				{
					_connectURLs = value;
				}
			}

			internal bool IsStruct
			{
				set
				{
					_bStruct = value;
				}
			}

			internal bool IsSUDSType
			{
				get
				{
					return _bSUDSType;
				}
				set
				{
					_bSUDSType = value;
					_bStruct = !value;
				}
			}

			internal SUDSType SUDSType
			{
				get
				{
					return _sudsType;
				}
				set
				{
					_sudsType = value;
				}
			}

			internal SudsUse SudsUse
			{
				get
				{
					return _sudsUse;
				}
				set
				{
					_sudsUse = value;
				}
			}

			internal bool IsValueType
			{
				set
				{
					_bValueType = value;
				}
			}

			internal SchemaBlockType BlockType
			{
				set
				{
					_blockType = value;
				}
			}

			internal string WireType => _wireType;

			internal ArrayList Inherit
			{
				get
				{
					return _inherit;
				}
				set
				{
					_inherit = value;
				}
			}

			internal bool IsPrint
			{
				get
				{
					return _bprint;
				}
				set
				{
					_bprint = value;
				}
			}

			internal override bool IsEmittableFieldType
			{
				get
				{
					if (_fieldString == null)
					{
						if (_bAnonymous && _fields.Count == 1)
						{
							URTField uRTField = (URTField)_fields[0];
							if (uRTField.IsArray)
							{
								_fieldString = uRTField.TypeName;
								return true;
							}
						}
						_fieldString = string.Empty;
					}
					return _fieldString != string.Empty;
				}
			}

			internal override string FieldName => _fieldString;

			internal override string FieldNamespace => ((URTField)_fields[0]).TypeNS;

			internal override bool PrimitiveField => ((URTField)_fields[0]).IsPrimitive;

			internal ArrayList Fields => _fields;

			internal URTComplexType(string name, string urlNS, string ns, string encodedNS, SchemaBlockType blockDefault, bool bSUDSType, bool bAnonymous, WsdlParser parser, URTNamespace xns)
				: base(name, urlNS, ns, encodedNS)
			{
				_baseTypeName = null;
				_baseTypeXmlNS = null;
				_baseType = null;
				_connectURLs = null;
				_bStruct = !bSUDSType;
				_blockType = blockDefault;
				_bSUDSType = bSUDSType;
				_bAnonymous = bAnonymous;
				_fieldString = null;
				_fields = new ArrayList();
				_methods = new ArrayList();
				_implIFaces = new ArrayList();
				_implIFaceNames = new ArrayList();
				_sudsType = SUDSType.None;
				_parser = parser;
				int num = name.IndexOf('+');
				if (num > 0)
				{
					string text = parser.Atomize(name.Substring(0, num));
					URTComplexType uRTComplexType = xns.LookupComplexType(text);
					if (uRTComplexType == null)
					{
						URTComplexType type = new URTComplexType(text, urlNS, ns, encodedNS, blockDefault, bSUDSType, bAnonymous, parser, xns);
						xns.AddComplexType(type);
					}
				}
				if (xns.UrtType == UrtType.Interop)
				{
					num = name.LastIndexOf('.');
					if (num > -1)
					{
						_wireType = name;
						base.Name = name.Replace(".", "_");
						base.SearchName = name;
					}
				}
			}

			internal void AddNestedType(BaseType ct)
			{
				if (_nestedTypes == null)
				{
					_nestedTypes = new ArrayList(10);
				}
				_nestedTypes.Add(ct);
			}

			internal void Extends(string baseTypeName, string baseTypeNS)
			{
				_baseTypeName = baseTypeName;
				_baseTypeXmlNS = baseTypeNS;
			}

			internal void Implements(string iFaceName, string iFaceNS, WsdlParser parser)
			{
				_implIFaceNames.Add(iFaceName);
				_implIFaceNames.Add(iFaceNS);
				URTNamespace uRTNamespace = parser.AddNewNamespace(iFaceNS);
				URTInterface uRTInterface = uRTNamespace.LookupInterface(iFaceName);
				if (uRTInterface == null)
				{
					uRTInterface = new URTInterface(iFaceName, uRTNamespace.Name, uRTNamespace.Namespace, uRTNamespace.EncodedNS, _parser);
					uRTNamespace.AddInterface(uRTInterface);
				}
			}

			internal bool IsArray()
			{
				if (_arrayType != null)
				{
					return true;
				}
				return false;
			}

			internal string GetArray()
			{
				return _clrarray;
			}

			internal URTNamespace GetArrayNS()
			{
				return _arrayNS;
			}

			internal string GetClassName()
			{
				string text = null;
				if (_bNameMethodConflict)
				{
					return "C" + base.Name;
				}
				return base.Name;
			}

			internal override string GetName(string curNS)
			{
				if (_fieldString != null && _fieldString != string.Empty)
				{
					return _fieldString;
				}
				return base.GetName(curNS);
			}

			internal void AddField(URTField field)
			{
				_fields.Add(field);
			}

			internal void AddMethod(URTMethod method)
			{
				if (method.Name == base.Name)
				{
					_bNameMethodConflict = true;
				}
				_methods.Add(method);
				int num = method.Name.IndexOf('.');
				if (num > 0)
				{
					method.MethodFlags = MethodFlags.None;
				}
				else
				{
					method.MethodFlags = (method.MethodFlags |= MethodFlags.Public);
				}
			}

			private URTMethod GetMethod(string name)
			{
				for (int i = 0; i < _methods.Count; i++)
				{
					URTMethod uRTMethod = (URTMethod)_methods[i];
					if (uRTMethod.Name == name)
					{
						return uRTMethod;
					}
				}
				return null;
			}

			internal void ResolveTypes(WsdlParser parser)
			{
				string ns = null;
				string assemName = null;
				if (IsArray())
				{
					ResolveArray();
					return;
				}
				if (IsSUDSType && _sudsType == SUDSType.None)
				{
					if (_parser._bWrappedProxy)
					{
						_sudsType = SUDSType.ClientProxy;
					}
					else
					{
						_sudsType = SUDSType.MarshalByRef;
					}
				}
				if (_baseTypeName != null)
				{
					UrtType urtType = parser.IsURTExportedType(_baseTypeXmlNS, out ns, out assemName);
					if (urtType == UrtType.UrtSystem || ns.StartsWith("System", StringComparison.Ordinal))
					{
						_baseType = new SystemType(_baseTypeName, _baseTypeXmlNS, ns, assemName);
					}
					else
					{
						URTNamespace uRTNamespace = parser.LookupNamespace(_baseTypeXmlNS);
						if (uRTNamespace == null)
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveSchemaNS"), _baseTypeXmlNS, _baseTypeName));
						}
						_baseType = uRTNamespace.LookupComplexType(_baseTypeName);
						if (_baseType == null)
						{
							_baseType = new SystemType(_baseTypeName, _baseTypeXmlNS, ns, assemName);
						}
					}
				}
				if (IsSUDSType)
				{
					if (_parser._bWrappedProxy)
					{
						if (_baseTypeName == null || _baseType is SystemType)
						{
							_baseTypeName = "RemotingClientProxy";
							_baseTypeXmlNS = SoapServices.CodeXmlNamespaceForClrTypeNamespace("System.Runtime.Remoting", "System.Runtime.Remoting");
							ns = "System.Runtime.Remoting.Services";
							assemName = "System.Runtime.Remoting";
							_baseType = new SystemType(_baseTypeName, _baseTypeXmlNS, ns, assemName);
						}
					}
					else if (_baseTypeName == null)
					{
						_baseTypeName = "MarshalByRefObject";
						_baseTypeXmlNS = SoapServices.CodeXmlNamespaceForClrTypeNamespace("System", null);
						ns = "System";
						assemName = null;
						_baseType = new SystemType(_baseTypeName, _baseTypeXmlNS, ns, assemName);
					}
				}
				else if (_baseType == null)
				{
					_baseType = new SystemType("Object", SoapServices.CodeXmlNamespaceForClrTypeNamespace("System", null), "System", null);
				}
				for (int i = 0; i < _implIFaceNames.Count; i += 2)
				{
					string text = (string)_implIFaceNames[i];
					string text2 = (string)_implIFaceNames[i + 1];
					string ns2;
					string assemName2;
					UrtType urtType2 = parser.IsURTExportedType(text2, out ns2, out assemName2);
					BaseInterface baseInterface;
					if (urtType2 == UrtType.UrtSystem)
					{
						baseInterface = new SystemInterface(text, text2, ns2, parser, assemName2);
					}
					else
					{
						URTNamespace uRTNamespace2 = parser.LookupNamespace(text2);
						if (uRTNamespace2 == null)
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveSchemaNS"), text2, text));
						}
						baseInterface = uRTNamespace2.LookupInterface(text);
						if (baseInterface == null)
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveTypeInNS"), text, text2));
						}
					}
					_implIFaces.Add(baseInterface);
				}
				for (int j = 0; j < _methods.Count; j++)
				{
					((URTMethod)_methods[j]).ResolveTypes(parser);
				}
			}

			internal void ResolveMethods()
			{
				for (int i = 0; i < _methods.Count; i++)
				{
					_ = (URTMethod)_methods[i];
				}
			}

			internal override MethodFlags GetMethodFlags(URTMethod method)
			{
				return method.MethodFlags;
			}

			internal void PrintCSC(TextWriter textWriter, string indentation, string curNS, StringBuilder sb)
			{
				if (IsEmittableFieldType || (base.bNestedType && !base.bNestedTypePrint))
				{
					return;
				}
				sb.Length = 0;
				sb.Append(indentation);
				if (_baseTypeName != null)
				{
					string name = _baseType.GetName(curNS);
					if (name == "System.Delegate" || name == "System.MulticastDelegate")
					{
						sb.Append("public delegate ");
						URTMethod method = GetMethod("Invoke");
						if (method == null)
						{
							throw new SUDSParserException(CoreChannel.GetResourceString("Remoting_Suds_DelegateWithoutInvoke"));
						}
						string typeString = method.GetTypeString(curNS, bNS: true);
						sb.Append(IsValidCSAttr(typeString));
						sb.Append(' ');
						string text = base.Name;
						int num = text.IndexOf('.');
						if (num > 0)
						{
							text = text.Substring(num + 1);
						}
						sb.Append(IsValidCS(text));
						sb.Append('(');
						method.PrintSignature(sb, curNS);
						sb.Append(");");
						textWriter.WriteLine(sb);
						return;
					}
				}
				bool isURTType = base.IsURTType;
				sb.Length = 0;
				sb.Append("\n");
				sb.Append(indentation);
				sb.Append("[");
				if (_sudsType != SUDSType.ClientProxy)
				{
					sb.Append("Serializable, ");
				}
				sb.Append("SoapType(");
				if (_parser._xsdVersion == XsdVersion.V1999)
				{
					sb.Append("SoapOptions=SoapOption.Option1|SoapOption.AlwaysIncludeTypes|SoapOption.XsdString|SoapOption.EmbedAll,");
				}
				else if (_parser._xsdVersion == XsdVersion.V2000)
				{
					sb.Append("SoapOptions=SoapOption.Option2|SoapOption.AlwaysIncludeTypes|SoapOption.XsdString|SoapOption.EmbedAll,");
				}
				if (!isURTType)
				{
					sb.Append("XmlElementName=");
					sb.Append(IsValidUrl(GetClassName()));
					sb.Append(", XmlNamespace=");
					sb.Append(IsValidUrl(base.Namespace));
					sb.Append(", XmlTypeName=");
					if (WireType != null)
					{
						sb.Append(IsValidUrl(WireType));
					}
					else
					{
						sb.Append(IsValidUrl(GetClassName()));
					}
					sb.Append(", XmlTypeNamespace=");
					sb.Append(IsValidUrl(base.Namespace));
				}
				else
				{
					sb.Append("XmlNamespace=");
					sb.Append(IsValidUrl(base.UrlNS));
					sb.Append(", XmlTypeNamespace=");
					sb.Append(IsValidUrl(base.UrlNS));
					if (WireType != null)
					{
						sb.Append(", XmlTypeName=");
						sb.Append(IsValidUrl(WireType));
					}
				}
				sb.Append(")]");
				sb.Append("[ComVisible(true)]");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(indentation);
				if (_sudsUse == SudsUse.Struct)
				{
					sb.Append("public struct ");
				}
				else
				{
					sb.Append("public class ");
				}
				if (_bNestedType)
				{
					sb.Append(IsValidCS(base.NestedTypeName));
				}
				else
				{
					sb.Append(IsValidCS(GetClassName()));
				}
				if (_baseTypeName != null || _sudsUse == SudsUse.ISerializable || _implIFaces.Count > 0)
				{
					sb.Append(" : ");
				}
				string text2 = null;
				bool flag = false;
				bool flag2 = ((_baseTypeName == "RemotingClientProxy") ? true : false);
				if (flag2)
				{
					sb.Append("System.Runtime.Remoting.Services.RemotingClientProxy");
					flag = true;
				}
				else if (_baseTypeName != null)
				{
					_ = _baseType.IsURTType;
					text2 = _baseType.GetName(curNS);
					if (text2 == "System.__ComObject")
					{
						sb.Append("System.MarshalByRefObject");
						flag = true;
					}
					else
					{
						sb.Append(IsValidCSAttr(text2));
						flag = true;
					}
				}
				else if (_sudsUse == SudsUse.ISerializable)
				{
					sb.Append("System.Runtime.Serialization.ISerializable");
					flag = true;
				}
				if (_implIFaces.Count > 0)
				{
					for (int i = 0; i < _implIFaces.Count; i++)
					{
						if (flag)
						{
							sb.Append(", ");
						}
						sb.Append(IsValidCS(((BaseInterface)_implIFaces[i]).GetName(curNS)));
						flag = true;
					}
				}
				textWriter.WriteLine(sb);
				textWriter.Write(indentation);
				textWriter.WriteLine('{');
				string text3 = indentation + "    ";
				_ = text3.Length;
				if (flag2)
				{
					PrintClientProxy(textWriter, indentation, curNS, sb);
				}
				if (_methods.Count > 0)
				{
					string bodyPrefix = null;
					if (_parser._bWrappedProxy)
					{
						sb.Length = 0;
						sb.Append("((");
						sb.Append(IsValidCS(GetClassName()));
						sb.Append(") _tp).");
						bodyPrefix = sb.ToString();
					}
					for (int j = 0; j < _methods.Count; j++)
					{
						((URTMethod)_methods[j]).PrintCSC(textWriter, text3, " ", curNS, MethodPrintEnum.PrintBody, isURTType, bodyPrefix, sb);
					}
					textWriter.WriteLine();
				}
				if (_fields.Count > 0)
				{
					textWriter.Write(text3);
					textWriter.WriteLine("// Class Fields");
					for (int k = 0; k < _fields.Count; k++)
					{
						((URTField)_fields[k]).PrintCSC(textWriter, text3, curNS, sb);
					}
				}
				if (_nestedTypes != null && _nestedTypes.Count > 0)
				{
					foreach (BaseType nestedType in _nestedTypes)
					{
						nestedType.bNestedTypePrint = true;
						if (nestedType is URTSimpleType)
						{
							((URTSimpleType)nestedType).PrintCSC(textWriter, text3, curNS, sb);
						}
						else
						{
							((URTComplexType)nestedType).PrintCSC(textWriter, text3, curNS, sb);
						}
						nestedType.bNestedTypePrint = false;
					}
				}
				if (_sudsUse == SudsUse.ISerializable)
				{
					PrintISerializable(textWriter, indentation, curNS, sb, text2);
				}
				sb.Length = 0;
				sb.Append(indentation);
				sb.Append("}");
				textWriter.WriteLine(sb);
			}

			private void PrintClientProxy(TextWriter textWriter, string indentation, string curNS, StringBuilder sb)
			{
				string text = indentation + "    ";
				string value = text + "    ";
				sb.Length = 0;
				sb.Append(text);
				sb.Append("// Constructor");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text);
				sb.Append("public ");
				sb.Append(IsValidCS(GetClassName()));
				sb.Append("()");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text);
				sb.Append('{');
				textWriter.WriteLine(sb);
				if (_connectURLs != null)
				{
					for (int i = 0; i < _connectURLs.Count; i++)
					{
						sb.Length = 0;
						sb.Append(value);
						if (i == 0)
						{
							sb.Append("base.ConfigureProxy(this.GetType(), ");
							sb.Append(IsValidUrl((string)_connectURLs[i]));
							sb.Append(");");
						}
						else
						{
							sb.Append("//base.ConfigureProxy(this.GetType(), ");
							sb.Append(IsValidUrl((string)_connectURLs[i]));
							sb.Append(");");
						}
						textWriter.WriteLine(sb);
					}
				}
				foreach (URTNamespace uRTNamespace3 in _parser._URTNamespaces)
				{
					foreach (URTComplexType uRTComplexType in uRTNamespace3._URTComplexTypes)
					{
						if (uRTComplexType._sudsType != SUDSType.ClientProxy && !uRTComplexType.IsArray())
						{
							sb.Length = 0;
							sb.Append(value);
							sb.Append("System.Runtime.Remoting.SoapServices.PreLoad(typeof(");
							sb.Append(IsValidCS(uRTNamespace3.EncodedNS));
							if (uRTNamespace3.EncodedNS != null && uRTNamespace3.EncodedNS.Length > 0)
							{
								sb.Append(".");
							}
							sb.Append(IsValidCS(uRTComplexType.Name));
							sb.Append("));");
							textWriter.WriteLine(sb);
						}
					}
				}
				foreach (URTNamespace uRTNamespace4 in _parser._URTNamespaces)
				{
					foreach (URTSimpleType uRTSimpleType in uRTNamespace4._URTSimpleTypes)
					{
						if (uRTSimpleType.IsEnum)
						{
							sb.Length = 0;
							sb.Append(value);
							sb.Append("System.Runtime.Remoting.SoapServices.PreLoad(typeof(");
							sb.Append(IsValidCS(uRTNamespace4.EncodedNS));
							if (uRTNamespace4.EncodedNS != null && uRTNamespace4.EncodedNS.Length > 0)
							{
								sb.Append(".");
							}
							sb.Append(IsValidCS(uRTSimpleType.Name));
							sb.Append("));");
							textWriter.WriteLine(sb);
						}
					}
				}
				sb.Length = 0;
				sb.Append(text);
				sb.Append('}');
				textWriter.WriteLine(sb);
				textWriter.WriteLine();
				sb.Length = 0;
				sb.Append(text);
				sb.Append("public Object RemotingReference");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text);
				sb.Append("{");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(value);
				sb.Append("get{return(_tp);}");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text);
				sb.Append("}");
				textWriter.WriteLine(sb);
				textWriter.WriteLine();
			}

			private void PrintISerializable(TextWriter textWriter, string indentation, string curNS, StringBuilder sb, string baseString)
			{
				string text = indentation + "    ";
				string value = text + "    ";
				if (baseString == null || baseString.StartsWith("System.", StringComparison.Ordinal))
				{
					sb.Length = 0;
					sb.Append(text);
					sb.Append("public System.Runtime.Serialization.SerializationInfo info;");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(text);
					sb.Append("public System.Runtime.Serialization.StreamingContext context; \n");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append(text);
				if (_baseTypeName == null)
				{
					sb.Append("public ");
				}
				else
				{
					sb.Append("protected ");
				}
				if (_bNestedType)
				{
					sb.Append(IsValidCS(base.NestedTypeName));
				}
				else
				{
					sb.Append(IsValidCS(GetClassName()));
				}
				sb.Append("(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)");
				if (_baseTypeName != null)
				{
					sb.Append(" : base(info, context)");
				}
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text);
				sb.Append("{");
				textWriter.WriteLine(sb);
				if (baseString == null || baseString.StartsWith("System.", StringComparison.Ordinal))
				{
					sb.Length = 0;
					sb.Append(value);
					sb.Append("this.info = info;");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(value);
					sb.Append("this.context = context;");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append(text);
				sb.Append("}");
				textWriter.WriteLine(sb);
				if (_baseTypeName == null)
				{
					sb.Length = 0;
					sb.Append(text);
					sb.Append("public void GetObjectData(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(text);
					sb.Append("{");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(text);
					sb.Append("}");
					textWriter.WriteLine(sb);
				}
			}

			internal void AddArray(string arrayType, URTNamespace arrayNS)
			{
				_arrayType = arrayType;
				_arrayNS = arrayNS;
			}

			internal void ResolveArray()
			{
				if (_clrarray == null)
				{
					string text = null;
					string arrayType = _arrayType;
					int num = _arrayType.IndexOf("[");
					if (num < 0)
					{
						throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlInvalidArraySyntax"), _arrayType));
					}
					arrayType = _arrayType.Substring(0, num);
					switch (_arrayNS.UrtType)
					{
					case UrtType.Xsd:
						text = _parser.MapSchemaTypesToCSharpTypes(arrayType);
						break;
					case UrtType.UrtSystem:
					case UrtType.UrtUser:
						text = arrayType;
						break;
					case UrtType.Interop:
						text = arrayType;
						break;
					}
					_clrarray = text + FilterDimensions(_arrayType.Substring(num));
				}
			}

			private string FilterDimensions(string value)
			{
				char[] array = new char[value.Length];
				for (int i = 0; i < value.Length; i++)
				{
					if (char.IsDigit(value[i]))
					{
						array[i] = ' ';
					}
					else
					{
						array[i] = value[i];
					}
				}
				return new string(array);
			}
		}

		internal class ElementDecl
		{
			private string _elmName;

			private string _elmNS;

			private string _typeName;

			private string _typeNS;

			private bool _bPrimitive;

			internal string Name => _elmName;

			internal string Namespace => _elmNS;

			internal string TypeName => _typeName;

			internal string TypeNS => _typeNS;

			internal ElementDecl(string elmName, string elmNS, string typeName, string typeNS, bool bPrimitive)
			{
				_elmName = elmName;
				_elmNS = elmNS;
				_typeName = typeName;
				_typeNS = typeNS;
				_bPrimitive = bPrimitive;
			}

			internal bool Resolve(WsdlParser parser)
			{
				if (_bPrimitive)
				{
					return true;
				}
				URTNamespace uRTNamespace = parser.LookupNamespace(TypeNS);
				if (uRTNamespace == null)
				{
					throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveSchemaNS"), TypeNS, TypeName));
				}
				BaseType baseType = uRTNamespace.LookupType(TypeName);
				if (baseType == null)
				{
					return false;
				}
				baseType.ElementName = Name;
				baseType.ElementNS = Namespace;
				return true;
			}
		}

		internal class URTNamespace
		{
			private string _name;

			private UrtType _nsType;

			private WsdlParser _parser;

			private string _namespace;

			private string _encodedNS;

			private string _assemName;

			private int _anonymousSeqNum;

			private ArrayList _elmDecls;

			internal ArrayList _URTComplexTypes;

			private int _numURTComplexTypes;

			internal ArrayList _URTSimpleTypes;

			private int _numURTSimpleTypes;

			private ArrayList _URTInterfaces;

			private bool _bReferenced;

			internal string Namespace => _namespace;

			internal bool IsSystem
			{
				get
				{
					if (_namespace != null && _namespace.StartsWith("System", StringComparison.Ordinal))
					{
						return true;
					}
					return false;
				}
			}

			internal string EncodedNS
			{
				get
				{
					return _encodedNS;
				}
				set
				{
					_encodedNS = value;
				}
			}

			internal bool bReferenced
			{
				get
				{
					return _bReferenced;
				}
				set
				{
					_bReferenced = value;
				}
			}

			internal string Name => _name;

			internal string AssemName => _assemName;

			internal UrtType UrtType => _nsType;

			internal bool IsURTNamespace => (object)_namespace == _encodedNS;

			internal bool IsEmpty
			{
				get
				{
					bool flag = true;
					if (ComplexTypeOnlyArrayorEmpty() && _URTInterfaces.Count == 0 && _numURTSimpleTypes == 0)
					{
						return true;
					}
					return false;
				}
			}

			internal URTNamespace(string name, WsdlParser parser)
			{
				_name = name;
				_parser = parser;
				_nsType = parser.IsURTExportedType(name, out _namespace, out _assemName);
				if (_nsType == UrtType.Interop)
				{
					_encodedNS = EncodeInterop(_namespace, parser);
				}
				else
				{
					_encodedNS = _namespace;
				}
				_elmDecls = new ArrayList();
				_URTComplexTypes = new ArrayList();
				_numURTComplexTypes = 0;
				_URTSimpleTypes = new ArrayList();
				_numURTSimpleTypes = 0;
				_URTInterfaces = new ArrayList();
				_anonymousSeqNum = 0;
				parser.AddNamespace(this);
			}

			internal static string EncodeInterop(string name, WsdlParser parser)
			{
				string text = name;
				if (parser.ProxyNamespace != null && parser.ProxyNamespace.Length > 0)
				{
					string text2 = "";
					if (parser.ProxyNamespaceCount > 0)
					{
						text2 = parser.ProxyNamespaceCount.ToString(CultureInfo.InvariantCulture);
					}
					parser.ProxyNamespaceCount++;
					return parser.ProxyNamespace + text2;
				}
				int num = name.IndexOf(":");
				if (num > 0)
				{
					text = text.Substring(num + 1);
				}
				if (text.StartsWith("//", StringComparison.Ordinal))
				{
					text = text.Substring(2);
				}
				return text.Replace('/', '_');
			}

			internal string GetNextAnonymousName()
			{
				_anonymousSeqNum++;
				return "AnonymousType" + _anonymousSeqNum;
			}

			internal void AddElementDecl(ElementDecl elmDecl)
			{
				_elmDecls.Add(elmDecl);
			}

			internal void AddComplexType(URTComplexType type)
			{
				_URTComplexTypes.Add(type);
				_numURTComplexTypes++;
			}

			internal void AddSimpleType(URTSimpleType type)
			{
				_URTSimpleTypes.Add(type);
				_numURTSimpleTypes++;
			}

			internal void AddInterface(URTInterface iface)
			{
				_URTInterfaces.Add(iface);
			}

			internal bool ComplexTypeOnlyArrayorEmpty()
			{
				bool result = true;
				for (int i = 0; i < _URTComplexTypes.Count; i++)
				{
					URTComplexType uRTComplexType = (URTComplexType)_URTComplexTypes[i];
					if (uRTComplexType != null && !uRTComplexType.IsArray())
					{
						result = false;
						break;
					}
				}
				return result;
			}

			internal URTComplexType LookupComplexType(string typeName)
			{
				URTComplexType result = null;
				for (int i = 0; i < _URTComplexTypes.Count; i++)
				{
					URTComplexType uRTComplexType = (URTComplexType)_URTComplexTypes[i];
					if (uRTComplexType != null && MatchingStrings(uRTComplexType.SearchName, typeName))
					{
						result = uRTComplexType;
						break;
					}
				}
				return result;
			}

			internal URTComplexType LookupComplexTypeEqual(string typeName)
			{
				URTComplexType result = null;
				for (int i = 0; i < _URTComplexTypes.Count; i++)
				{
					URTComplexType uRTComplexType = (URTComplexType)_URTComplexTypes[i];
					if (uRTComplexType != null && uRTComplexType.SearchName == typeName)
					{
						result = uRTComplexType;
						break;
					}
				}
				return result;
			}

			internal URTSimpleType LookupSimpleType(string typeName)
			{
				for (int i = 0; i < _URTSimpleTypes.Count; i++)
				{
					URTSimpleType uRTSimpleType = (URTSimpleType)_URTSimpleTypes[i];
					if (uRTSimpleType != null && MatchingStrings(uRTSimpleType.Name, typeName))
					{
						return uRTSimpleType;
					}
				}
				return null;
			}

			internal BaseType LookupType(string typeName)
			{
				BaseType baseType = LookupComplexType(typeName);
				if (baseType == null)
				{
					baseType = LookupSimpleType(typeName);
				}
				return baseType;
			}

			internal void RemoveComplexType(URTComplexType type)
			{
				for (int i = 0; i < _URTComplexTypes.Count; i++)
				{
					if (_URTComplexTypes[i] == type)
					{
						_URTComplexTypes[i] = null;
						_numURTComplexTypes--;
						return;
					}
				}
				throw new SUDSParserException(CoreChannel.GetResourceString("Remoting_Suds_TriedToRemoveNonexistentType"));
			}

			internal void RemoveSimpleType(URTSimpleType type)
			{
				for (int i = 0; i < _URTSimpleTypes.Count; i++)
				{
					if (_URTSimpleTypes[i] == type)
					{
						_URTSimpleTypes[i] = null;
						_numURTSimpleTypes--;
						return;
					}
				}
				throw new SUDSParserException(CoreChannel.GetResourceString("Remoting_Suds_TriedToRemoveNonexistentType"));
			}

			internal URTInterface LookupInterface(string iFaceName)
			{
				for (int i = 0; i < _URTInterfaces.Count; i++)
				{
					URTInterface uRTInterface = (URTInterface)_URTInterfaces[i];
					if (MatchingStrings(uRTInterface.Name, iFaceName))
					{
						return uRTInterface;
					}
				}
				return null;
			}

			internal void ResolveElements(WsdlParser parser)
			{
				for (int i = 0; i < _elmDecls.Count; i++)
				{
					((ElementDecl)_elmDecls[i]).Resolve(parser);
				}
			}

			internal void ResolveTypes(WsdlParser parser)
			{
				for (int i = 0; i < _URTComplexTypes.Count; i++)
				{
					if (_URTComplexTypes[i] != null)
					{
						((URTComplexType)_URTComplexTypes[i]).ResolveTypes(parser);
					}
				}
				for (int j = 0; j < _URTInterfaces.Count; j++)
				{
					((URTInterface)_URTInterfaces[j]).ResolveTypes(parser);
				}
			}

			internal void ResolveMethods()
			{
				for (int i = 0; i < _URTComplexTypes.Count; i++)
				{
					if (_URTComplexTypes[i] != null)
					{
						((URTComplexType)_URTComplexTypes[i]).ResolveMethods();
					}
				}
			}

			internal void PrintCSC(WriterStream writerStream)
			{
				TextWriter outputStream = writerStream.OutputStream;
				bool flag = false;
				if (_numURTComplexTypes > 0)
				{
					for (int i = 0; i < _URTComplexTypes.Count; i++)
					{
						URTComplexType uRTComplexType = (URTComplexType)_URTComplexTypes[i];
						if (uRTComplexType != null && uRTComplexType.IsPrint)
						{
							flag = true;
						}
					}
				}
				if (_numURTSimpleTypes > 0)
				{
					for (int j = 0; j < _URTSimpleTypes.Count; j++)
					{
						URTSimpleType uRTSimpleType = (URTSimpleType)_URTSimpleTypes[j];
						if (uRTSimpleType != null)
						{
							flag = true;
						}
					}
				}
				if (_URTInterfaces.Count > 0)
				{
					flag = true;
				}
				if (!flag)
				{
					return;
				}
				string indentation = string.Empty;
				_ = ((StreamWriter)outputStream).BaseStream;
				if (!writerStream.GetWrittenTo())
				{
					outputStream.WriteLine("using System;");
					outputStream.WriteLine("using System.Runtime.Remoting.Messaging;");
					outputStream.WriteLine("using System.Runtime.Remoting.Metadata;");
					outputStream.WriteLine("using System.Runtime.Remoting.Metadata.W3cXsd2001;");
					outputStream.WriteLine("using System.Runtime.InteropServices;");
					writerStream.SetWrittenTo();
				}
				if (Namespace != null && Namespace.Length != 0)
				{
					outputStream.Write("namespace ");
					outputStream.Write(IsValidCS(EncodedNS));
					outputStream.WriteLine(" {");
					indentation = "    ";
				}
				StringBuilder sb = new StringBuilder(256);
				if (_numURTComplexTypes > 0)
				{
					for (int k = 0; k < _URTComplexTypes.Count; k++)
					{
						URTComplexType uRTComplexType2 = (URTComplexType)_URTComplexTypes[k];
						if (uRTComplexType2 != null && uRTComplexType2.IsPrint)
						{
							uRTComplexType2.PrintCSC(outputStream, indentation, _encodedNS, sb);
						}
					}
				}
				if (_numURTSimpleTypes > 0)
				{
					for (int l = 0; l < _URTSimpleTypes.Count; l++)
					{
						((URTSimpleType)_URTSimpleTypes[l])?.PrintCSC(outputStream, indentation, _encodedNS, sb);
					}
				}
				for (int m = 0; m < _URTInterfaces.Count; m++)
				{
					((URTInterface)_URTInterfaces[m]).PrintCSC(outputStream, indentation, _encodedNS, sb);
				}
				if (Namespace != null && Namespace.Length != 0)
				{
					outputStream.WriteLine('}');
				}
			}
		}

		internal interface IDump
		{
			void Dump();
		}

		internal interface INamespaces
		{
			void UsedNamespace(Hashtable namespaces);
		}

		internal class WsdlMessage : IDump, INamespaces
		{
			internal string name;

			internal string nameNs;

			internal ArrayList parts = new ArrayList(10);

			public void UsedNamespace(Hashtable namespaces)
			{
				for (int i = 0; i < parts.Count; i++)
				{
					((INamespaces)parts[i]).UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				for (int i = 0; i < parts.Count; i++)
				{
					((IDump)parts[i]).Dump();
				}
			}
		}

		internal class WsdlMessagePart : IDump, INamespaces
		{
			internal string name;

			internal string nameNs;

			internal string element;

			internal string elementNs;

			internal string typeName;

			internal string typeNameNs;

			public void UsedNamespace(Hashtable namespaces)
			{
				if (nameNs != null)
				{
					namespaces[nameNs] = 1;
				}
				if (elementNs != null)
				{
					namespaces[elementNs] = 1;
				}
			}

			public void Dump()
			{
			}
		}

		internal class WsdlPortType : IDump, INamespaces
		{
			internal string name;

			internal ArrayList operations = new ArrayList(10);

			internal Hashtable sections = new Hashtable(10);

			public void UsedNamespace(Hashtable namespaces)
			{
				foreach (INamespaces operation in operations)
				{
					operation.UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				foreach (DictionaryEntry section in sections)
				{
					_ = section;
				}
				foreach (IDump operation in operations)
				{
					operation.Dump();
				}
			}
		}

		internal class WsdlPortTypeOperation : IDump, INamespaces
		{
			internal string name;

			internal string nameNs;

			internal string parameterOrder;

			internal ArrayList contents = new ArrayList(3);

			public void UsedNamespace(Hashtable namespaces)
			{
				foreach (INamespaces content in contents)
				{
					content.UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				foreach (IDump content in contents)
				{
					content.Dump();
				}
			}
		}

		internal class WsdlPortTypeOperationContent : IDump, INamespaces
		{
			internal string element;

			internal string name;

			internal string nameNs;

			internal string message;

			internal string messageNs;

			public void UsedNamespace(Hashtable namespaces)
			{
			}

			public void Dump()
			{
			}
		}

		internal class WsdlBinding : IDump, INamespaces
		{
			internal URTNamespace parsingNamespace;

			internal string name;

			internal string type;

			internal string typeNs;

			internal ArrayList suds = new ArrayList(10);

			internal WsdlBindingSoapBinding soapBinding;

			internal ArrayList operations = new ArrayList(10);

			public void UsedNamespace(Hashtable namespaces)
			{
				if (soapBinding != null)
				{
					soapBinding.UsedNamespace(namespaces);
				}
				foreach (INamespaces sud in suds)
				{
					sud.UsedNamespace(namespaces);
				}
				foreach (INamespaces operation in operations)
				{
					operation.UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				if (soapBinding != null)
				{
					soapBinding.Dump();
				}
				foreach (IDump sud in suds)
				{
					sud.Dump();
				}
				foreach (IDump operation in operations)
				{
					operation.Dump();
				}
			}
		}

		internal class WsdlBindingOperation : IDump, INamespaces
		{
			internal string name;

			internal string nameNs;

			internal string methodAttributes;

			internal WsdlBindingSoapOperation soapOperation;

			internal ArrayList sections = new ArrayList(10);

			public void UsedNamespace(Hashtable namespaces)
			{
				soapOperation.UsedNamespace(namespaces);
				foreach (INamespaces section in sections)
				{
					section.UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				soapOperation.Dump();
				foreach (IDump section in sections)
				{
					section.Dump();
				}
			}
		}

		internal class WsdlBindingOperationSection : IDump, INamespaces
		{
			internal string name;

			internal string elementName;

			internal ArrayList extensions = new ArrayList(10);

			public void UsedNamespace(Hashtable namespaces)
			{
				foreach (INamespaces extension in extensions)
				{
					extension.UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				foreach (IDump extension in extensions)
				{
					extension.Dump();
				}
			}
		}

		internal class WsdlBindingSoapBinding : IDump, INamespaces
		{
			internal string style;

			internal string transport;

			public void UsedNamespace(Hashtable namespaces)
			{
			}

			public void Dump()
			{
			}
		}

		internal class WsdlBindingSoapBody : IDump, INamespaces
		{
			internal string parts;

			internal string use;

			internal string encodingStyle;

			internal string namespaceUri;

			public void UsedNamespace(Hashtable namespaces)
			{
			}

			public void Dump()
			{
			}
		}

		internal class WsdlBindingSoapHeader : IDump, INamespaces
		{
			internal string message;

			internal string messageNs;

			internal string part;

			internal string use;

			internal string encodingStyle;

			internal string namespaceUri;

			public void UsedNamespace(Hashtable namespaces)
			{
			}

			public void Dump()
			{
			}
		}

		internal class WsdlBindingSoapOperation : IDump, INamespaces
		{
			internal string soapAction;

			internal string style;

			public void UsedNamespace(Hashtable namespaces)
			{
			}

			public void Dump()
			{
			}
		}

		internal class WsdlBindingSoapFault : IDump, INamespaces
		{
			internal string name;

			internal string use;

			internal string encodingStyle;

			internal string namespaceUri;

			public void UsedNamespace(Hashtable namespaces)
			{
			}

			public void Dump()
			{
			}
		}

		internal enum SudsUse
		{
			Class,
			ISerializable,
			Struct,
			Interface,
			MarshalByRef,
			Delegate,
			ServicedComponent
		}

		internal class WsdlBindingSuds : IDump, INamespaces
		{
			internal string elementName;

			internal string typeName;

			internal string ns;

			internal string extendsTypeName;

			internal string extendsNs;

			internal SudsUse sudsUse;

			internal ArrayList implements = new ArrayList(10);

			internal ArrayList nestedTypes = new ArrayList(10);

			public void UsedNamespace(Hashtable namespaces)
			{
				if (ns != null)
				{
					namespaces[ns] = 1;
				}
				if (extendsNs != null)
				{
					namespaces[extendsNs] = 1;
				}
				foreach (INamespaces implement in implements)
				{
					implement.UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				foreach (IDump implement in implements)
				{
					implement.Dump();
				}
				foreach (IDump nestedType in nestedTypes)
				{
					nestedType.Dump();
				}
			}
		}

		internal class WsdlBindingSudsImplements : IDump, INamespaces
		{
			internal string typeName;

			internal string ns;

			public void UsedNamespace(Hashtable namespaces)
			{
				if (ns != null)
				{
					namespaces[ns] = 1;
				}
			}

			public void Dump()
			{
			}
		}

		internal class WsdlBindingSudsNestedType : IDump
		{
			internal string name;

			internal string typeName;

			internal string ns;

			public void Dump()
			{
			}
		}

		internal class WsdlService : IDump, INamespaces
		{
			internal string name;

			internal Hashtable ports = new Hashtable(10);

			public void UsedNamespace(Hashtable namespaces)
			{
				foreach (DictionaryEntry port in ports)
				{
					((INamespaces)port.Value).UsedNamespace(namespaces);
				}
			}

			public void Dump()
			{
				foreach (DictionaryEntry port in ports)
				{
					((IDump)port.Value).Dump();
				}
			}
		}

		internal class WsdlServicePort : IDump, INamespaces
		{
			internal string name;

			internal string nameNs;

			internal string binding;

			internal string bindingNs;

			internal ArrayList locations;

			public void UsedNamespace(Hashtable namespaces)
			{
			}

			public void Dump()
			{
				if (locations == null)
				{
					return;
				}
				foreach (string location in locations)
				{
					_ = location;
				}
			}
		}

		internal class WsdlMethodInfo : IDump
		{
			internal string soapAction;

			internal string methodName;

			internal string methodNameNs;

			internal string methodAttributes;

			internal string[] paramNamesOrder;

			internal string inputMethodName;

			internal string inputMethodNameNs;

			internal string outputMethodName;

			internal string outputMethodNameNs;

			internal string[] inputNames;

			internal string[] inputNamesNs;

			internal string[] inputElements;

			internal string[] inputElementsNs;

			internal string[] inputTypes;

			internal string[] inputTypesNs;

			internal string[] outputNames;

			internal string[] outputNamesNs;

			internal string[] outputElements;

			internal string[] outputElementsNs;

			internal string[] outputTypes;

			internal string[] outputTypesNs;

			internal string propertyName;

			internal bool bProperty;

			internal bool bGet;

			internal bool bSet;

			internal string propertyType;

			internal string propertyNs;

			internal string soapActionGet;

			internal string soapActionSet;

			public void Dump()
			{
				if (paramNamesOrder != null)
				{
					string[] array = paramNamesOrder;
					for (int i = 0; i < array.Length; i++)
					{
						_ = array[i];
					}
				}
				if (inputNames != null)
				{
					for (int j = 0; j < inputNames.Length; j++)
					{
					}
				}
				if (outputNames != null)
				{
					for (int k = 0; k < outputNames.Length; k++)
					{
					}
				}
				_ = bProperty;
			}
		}

		private static StringBuilder vsb = new StringBuilder();

		private static Hashtable cSharpKeywords;

		private XmlTextReader _XMLReader;

		private ArrayList _URTNamespaces;

		private ReaderStream _parsingInput;

		internal bool _bWrappedProxy;

		private string _proxyNamespace;

		private int _proxyNamespaceCount;

		private ReaderStream _readerStreamsWsdl;

		private ReaderStream _readerStreamsXsd;

		private string _outputDir;

		private ArrayList _outCodeStreamList;

		private WriterStream _writerStreams;

		private SchemaBlockType _blockDefault;

		private XsdVersion _xsdVersion;

		private Hashtable wsdlMessages = new Hashtable(10);

		private Hashtable wsdlPortTypes = new Hashtable(10);

		private ArrayList wsdlBindings = new ArrayList(10);

		private ArrayList wsdlServices = new ArrayList(10);

		private Stack _currentReaderStack = new Stack(5);

		private Stack _currentSchemaReaderStack = new Stack(5);

		private XmlNameTable _primedNametable;

		private static string s_emptyString;

		private static string s_complexTypeString;

		private static string s_simpleTypeString;

		private static string s_elementString;

		private static string s_enumerationString;

		private static string s_encodingString;

		private static string s_attributeString;

		private static string s_attributesString;

		private static string s_allString;

		private static string s_sequenceString;

		private static string s_choiceString;

		private static string s_minOccursString;

		private static string s_maxOccursString;

		private static string s_unboundedString;

		private static string s_oneString;

		private static string s_zeroString;

		private static string s_nameString;

		private static string s_enumTypeString;

		private static string s_typeString;

		private static string s_baseString;

		private static string s_valueString;

		private static string s_interfaceString;

		private static string s_serviceString;

		private static string s_extendsString;

		private static string s_addressesString;

		private static string s_addressString;

		private static string s_uriString;

		private static string s_implementsString;

		private static string s_nestedTypeString;

		private static string s_requestString;

		private static string s_responseString;

		private static string s_requestResponseString;

		private static string s_messageString;

		private static string s_locationString;

		private static string s_schemaLocationString;

		private static string s_importString;

		private static string s_includeString;

		private static string s_onewayString;

		private static string s_refString;

		private static string s_refTypeString;

		private static string s_referenceString;

		private static string s_arrayString;

		private static string s_objectString;

		private static string s_urTypeString;

		private static string s_methodString;

		private static string s_sudsString;

		private static string s_useString;

		private static string s_rootTypeString;

		private static string s_soapString;

		private static string s_serviceDescString;

		private static string s_schemaString;

		private static string s_targetNamespaceString;

		private static string s_namespaceString;

		private static string s_idString;

		private static string s_soapActionString;

		private static string s_instanceNamespaceString;

		private static string s_schemaNamespaceString;

		private static string s_instanceNamespaceString1999;

		private static string s_schemaNamespaceString1999;

		private static string s_instanceNamespaceString2000;

		private static string s_schemaNamespaceString2000;

		private static string s_soapNamespaceString;

		private static string s_sudsNamespaceString;

		private static string s_serviceNamespaceString;

		private static string s_definitionsString;

		private static string s_wsdlNamespaceString;

		private static string s_wsdlSoapNamespaceString;

		private static string s_wsdlSudsNamespaceString;

		private static string s_typesString;

		private static string s_partString;

		private static string s_portTypeString;

		private static string s_operationString;

		private static string s_inputString;

		private static string s_outputString;

		private static string s_bindingString;

		private static string s_classString;

		private static string s_structString;

		private static string s_ISerializableString;

		private static string s_marshalByRefString;

		private static string s_delegateString;

		private static string s_servicedComponentString;

		private static string s_comObjectString;

		private static string s_portString;

		private static string s_styleString;

		private static string s_transportString;

		private static string s_encodedString;

		private static string s_faultString;

		private static string s_bodyString;

		private static string s_partsString;

		private static string s_headerString;

		private static string s_encodingStyleString;

		private static string s_restrictionString;

		private static string s_complexContentString;

		private static string s_soapEncodingString;

		private static string s_arrayTypeString;

		private static string s_parameterOrderString;

		internal string SchemaNamespaceString
		{
			get
			{
				string result = null;
				switch (_xsdVersion)
				{
				case XsdVersion.V1999:
					result = s_schemaNamespaceString1999;
					break;
				case XsdVersion.V2000:
					result = s_schemaNamespaceString2000;
					break;
				case XsdVersion.V2001:
					result = s_schemaNamespaceString;
					break;
				}
				return result;
			}
		}

		internal string ProxyNamespace => _proxyNamespace;

		internal int ProxyNamespaceCount
		{
			get
			{
				return _proxyNamespaceCount;
			}
			set
			{
				_proxyNamespaceCount = value;
			}
		}

		internal XmlTextReader XMLReader => _XMLReader;

		internal WsdlParser(TextReader input, string outputDir, ArrayList outCodeStreamList, string locationURL, bool bWrappedProxy, string proxyNamespace)
		{
			_XMLReader = null;
			_readerStreamsWsdl = new ReaderStream(locationURL);
			_readerStreamsWsdl.InputStream = input;
			_writerStreams = null;
			_outputDir = outputDir;
			_outCodeStreamList = outCodeStreamList;
			_bWrappedProxy = bWrappedProxy;
			if (proxyNamespace == null || proxyNamespace.Length == 0)
			{
				_proxyNamespace = "InteropNS";
			}
			else
			{
				_proxyNamespace = proxyNamespace;
			}
			if (outputDir == null)
			{
				outputDir = ".";
			}
			int length = outputDir.Length;
			if (length > 0)
			{
				char c = outputDir[length - 1];
				if (c != '\\' && c != '/')
				{
					_outputDir += '\\';
				}
			}
			_URTNamespaces = new ArrayList();
			_blockDefault = SchemaBlockType.ALL;
			_primedNametable = CreatePrimedNametable();
		}

		private bool SkipXmlElement()
		{
			_XMLReader.Skip();
			XmlNodeType xmlNodeType = _XMLReader.MoveToContent();
			while (xmlNodeType == XmlNodeType.EndElement)
			{
				_XMLReader.Read();
				xmlNodeType = _XMLReader.MoveToContent();
				if (xmlNodeType == XmlNodeType.None)
				{
					break;
				}
			}
			return xmlNodeType != XmlNodeType.None;
		}

		private bool ReadNextXmlElement()
		{
			_XMLReader.Read();
			XmlNodeType xmlNodeType = _XMLReader.MoveToContent();
			while (xmlNodeType == XmlNodeType.EndElement)
			{
				_XMLReader.Read();
				xmlNodeType = _XMLReader.MoveToContent();
				if (xmlNodeType == XmlNodeType.None)
				{
					break;
				}
			}
			return xmlNodeType != XmlNodeType.None;
		}

		private URTComplexType ParseComplexType(URTNamespace parsingNamespace, string typeName)
		{
			if (typeName == null)
			{
				typeName = LookupAttribute(s_nameString, null, throwExp: true);
			}
			URTNamespace returnNS = null;
			ParseQName(ref typeName, parsingNamespace, out returnNS);
			URTComplexType uRTComplexType = returnNS.LookupComplexType(typeName);
			if (uRTComplexType == null)
			{
				uRTComplexType = new URTComplexType(typeName, returnNS.Name, returnNS.Namespace, returnNS.EncodedNS, _blockDefault, bSUDSType: false, typeName != null, this, returnNS);
				returnNS.AddComplexType(uRTComplexType);
			}
			string qname = LookupAttribute(s_baseString, null, throwExp: false);
			if (!MatchingStrings(qname, s_emptyString))
			{
				string baseTypeNS = ParseQName(ref qname, parsingNamespace);
				uRTComplexType.Extends(qname, baseTypeNS);
			}
			if (uRTComplexType.Fields.Count > 0)
			{
				SkipXmlElement();
			}
			else
			{
				int depth = _XMLReader.Depth;
				ReadNextXmlElement();
				int num = 0;
				while (_XMLReader.Depth > depth)
				{
					string localName = _XMLReader.LocalName;
					if (MatchingStrings(localName, s_elementString))
					{
						ParseElementField(returnNS, uRTComplexType, num);
						num++;
						continue;
					}
					if (MatchingStrings(localName, s_attributeString))
					{
						ParseAttributeField(returnNS, uRTComplexType);
						continue;
					}
					if (MatchingStrings(localName, s_allString))
					{
						uRTComplexType.BlockType = SchemaBlockType.ALL;
					}
					else if (MatchingStrings(localName, s_sequenceString))
					{
						uRTComplexType.BlockType = SchemaBlockType.SEQUENCE;
					}
					else if (MatchingStrings(localName, s_choiceString))
					{
						uRTComplexType.BlockType = SchemaBlockType.CHOICE;
					}
					else
					{
						if (!MatchingStrings(localName, s_complexContentString))
						{
							if (MatchingStrings(localName, s_restrictionString))
							{
								ParseRestrictionField(returnNS, uRTComplexType);
							}
							else
							{
								SkipXmlElement();
							}
							continue;
						}
						uRTComplexType.BlockType = SchemaBlockType.ComplexContent;
					}
					ReadNextXmlElement();
				}
			}
			return uRTComplexType;
		}

		private URTSimpleType ParseSimpleType(URTNamespace parsingNamespace, string typeName)
		{
			if (typeName == null)
			{
				typeName = LookupAttribute(s_nameString, null, throwExp: true);
			}
			string text = LookupAttribute(s_enumTypeString, s_wsdlSudsNamespaceString, throwExp: false);
			URTSimpleType uRTSimpleType = parsingNamespace.LookupSimpleType(typeName);
			if (uRTSimpleType == null)
			{
				uRTSimpleType = new URTSimpleType(typeName, parsingNamespace.Name, parsingNamespace.Namespace, parsingNamespace.EncodedNS, typeName != null, this);
				string qname = LookupAttribute(s_baseString, null, throwExp: false);
				if (!MatchingStrings(qname, s_emptyString))
				{
					string baseTypeNS = ParseQName(ref qname, parsingNamespace);
					uRTSimpleType.Extends(qname, baseTypeNS);
				}
				parsingNamespace.AddSimpleType(uRTSimpleType);
				int depth = _XMLReader.Depth;
				ReadNextXmlElement();
				while (_XMLReader.Depth > depth)
				{
					string localName = _XMLReader.LocalName;
					if (MatchingStrings(localName, s_restrictionString))
					{
						ParseRestrictionField(parsingNamespace, uRTSimpleType);
					}
					else
					{
						SkipXmlElement();
					}
				}
			}
			else
			{
				SkipXmlElement();
			}
			if (text != null)
			{
				uRTSimpleType.EnumType = text;
			}
			return uRTSimpleType;
		}

		private void ParseEnumeration(URTSimpleType parsingSimpleType, int enumFacetNum)
		{
			if (_XMLReader.IsEmptyElement)
			{
				string valueString = LookupAttribute(s_valueString, null, throwExp: true);
				parsingSimpleType.IsEnum = true;
				parsingSimpleType.AddFacet(new EnumFacet(valueString, enumFacetNum));
				return;
			}
			throw new SUDSParserException(CoreChannel.GetResourceString("Remoting_Suds_EnumMustBeEmpty"));
		}

		private void ParseElementField(URTNamespace parsingNamespace, URTComplexType parsingComplexType, int fieldNum)
		{
			string name = LookupAttribute(s_nameString, null, throwExp: true);
			string left = LookupAttribute(s_minOccursString, null, throwExp: false);
			string text = LookupAttribute(s_maxOccursString, null, throwExp: false);
			bool bOptional = false;
			if (MatchingStrings(left, s_zeroString))
			{
				bOptional = true;
			}
			bool bArray = false;
			string arraySize = null;
			if (!MatchingStrings(text, s_emptyString) && !MatchingStrings(text, s_oneString))
			{
				arraySize = ((!MatchingStrings(text, s_unboundedString)) ? text : string.Empty);
				bArray = true;
			}
			string typeName;
			string typeNS;
			bool bEmbedded;
			bool bPrimitive;
			if (_XMLReader.IsEmptyElement)
			{
				typeName = LookupAttribute(s_typeString, null, throwExp: false);
				ResolveTypeAttribute(ref typeName, out typeNS, out bEmbedded, out bPrimitive);
				ReadNextXmlElement();
			}
			else
			{
				typeNS = parsingNamespace.Namespace;
				typeName = parsingNamespace.GetNextAnonymousName();
				bPrimitive = false;
				bEmbedded = true;
				int depth = _XMLReader.Depth;
				ReadNextXmlElement();
				while (_XMLReader.Depth > depth)
				{
					string localName = _XMLReader.LocalName;
					if (MatchingStrings(localName, s_complexTypeString))
					{
						URTComplexType uRTComplexType = ParseComplexType(parsingNamespace, typeName);
						if (uRTComplexType.IsEmittableFieldType)
						{
							typeNS = uRTComplexType.FieldNamespace;
							typeName = uRTComplexType.FieldName;
							bPrimitive = uRTComplexType.PrimitiveField;
							parsingNamespace.RemoveComplexType(uRTComplexType);
						}
					}
					else if (MatchingStrings(localName, s_simpleTypeString))
					{
						URTSimpleType uRTSimpleType = ParseSimpleType(parsingNamespace, typeName);
						if (uRTSimpleType.IsEmittableFieldType)
						{
							typeNS = uRTSimpleType.FieldNamespace;
							typeName = uRTSimpleType.FieldName;
							bPrimitive = uRTSimpleType.PrimitiveField;
							parsingNamespace.RemoveSimpleType(uRTSimpleType);
						}
					}
					else
					{
						SkipXmlElement();
					}
				}
			}
			parsingComplexType.AddField(new URTField(name, typeName, typeNS, this, bPrimitive, bEmbedded, bAttribute: false, bOptional, bArray, arraySize, parsingNamespace));
		}

		private void ParseAttributeField(URTNamespace parsingNamespace, URTComplexType parsingComplexType)
		{
			string name = LookupAttribute(s_nameString, null, throwExp: true);
			bool bOptional = false;
			string left = LookupAttribute(s_minOccursString, null, throwExp: false);
			if (MatchingStrings(left, s_zeroString))
			{
				bOptional = true;
			}
			string typeName;
			string typeNS;
			bool bEmbedded;
			bool bPrimitive;
			if (_XMLReader.IsEmptyElement)
			{
				typeName = LookupAttribute(s_typeString, null, throwExp: true);
				ResolveTypeAttribute(ref typeName, out typeNS, out bEmbedded, out bPrimitive);
				ReadNextXmlElement();
				if (MatchingStrings(typeName, s_idString) && MatchingSchemaStrings(typeNS))
				{
					parsingComplexType.IsStruct = false;
					return;
				}
			}
			else
			{
				typeNS = parsingNamespace.Namespace;
				typeName = parsingNamespace.GetNextAnonymousName();
				bPrimitive = false;
				bEmbedded = true;
				int depth = _XMLReader.Depth;
				ReadNextXmlElement();
				while (_XMLReader.Depth > depth)
				{
					string localName = _XMLReader.LocalName;
					if (MatchingStrings(localName, s_simpleTypeString))
					{
						URTSimpleType uRTSimpleType = ParseSimpleType(parsingNamespace, typeName);
						if (uRTSimpleType.IsEmittableFieldType)
						{
							typeNS = uRTSimpleType.FieldNamespace;
							typeName = uRTSimpleType.FieldName;
							bPrimitive = uRTSimpleType.PrimitiveField;
							parsingNamespace.RemoveSimpleType(uRTSimpleType);
						}
					}
					else
					{
						SkipXmlElement();
					}
				}
			}
			parsingComplexType.AddField(new URTField(name, typeName, typeNS, this, bPrimitive, bEmbedded, bAttribute: true, bOptional, bArray: false, null, parsingNamespace));
		}

		private void ParseRestrictionField(URTNamespace parsingNamespace, BaseType parsingType)
		{
			string qname = LookupAttribute(s_baseString, null, throwExp: true);
			ParseQName(ref qname, parsingNamespace);
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			int num = 0;
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingStrings(localName, s_attributeString))
				{
					string qname2 = LookupAttribute(s_refString, null, throwExp: true);
					string left = ParseQName(ref qname2, parsingNamespace);
					if (MatchingStrings(left, s_soapEncodingString) && MatchingStrings(qname2, s_arrayTypeString))
					{
						URTComplexType uRTComplexType = (URTComplexType)parsingType;
						string qname3 = LookupAttribute(s_arrayTypeString, s_wsdlNamespaceString, throwExp: true);
						URTNamespace returnNS = null;
						ParseQName(ref qname3, null, out returnNS);
						uRTComplexType.AddArray(qname3, returnNS);
						returnNS.AddComplexType(uRTComplexType);
						uRTComplexType.IsPrint = false;
					}
				}
				else if (MatchingStrings(localName, s_enumerationString))
				{
					URTSimpleType parsingSimpleType = (URTSimpleType)parsingType;
					ParseEnumeration(parsingSimpleType, num);
					num++;
				}
				else
				{
					SkipXmlElement();
				}
				ReadNextXmlElement();
			}
		}

		private void ParseElementDecl(URTNamespace parsingNamespace)
		{
			string elmName = LookupAttribute(s_nameString, null, throwExp: true);
			string name = parsingNamespace.Name;
			string typeName = LookupAttribute(s_typeString, null, throwExp: false);
			string typeNS;
			bool bPrimitive;
			if (_XMLReader.IsEmptyElement)
			{
				ResolveTypeAttribute(ref typeName, out typeNS, out var _, out bPrimitive);
				ReadNextXmlElement();
			}
			else
			{
				typeNS = parsingNamespace.Name;
				typeName = parsingNamespace.GetNextAnonymousName();
				bool bEmbedded = true;
				bPrimitive = false;
				int depth = _XMLReader.Depth;
				ReadNextXmlElement();
				while (_XMLReader.Depth > depth)
				{
					string localName = _XMLReader.LocalName;
					if (MatchingStrings(localName, s_complexTypeString))
					{
						ParseComplexType(parsingNamespace, typeName);
					}
					else if (MatchingStrings(localName, s_simpleTypeString))
					{
						ParseSimpleType(parsingNamespace, typeName);
					}
					else
					{
						SkipXmlElement();
					}
				}
			}
			parsingNamespace.AddElementDecl(new ElementDecl(elmName, name, typeName, typeNS, bPrimitive));
		}

		private void ResolveTypeNames(ref string typeNS, ref string typeName, out bool bEmbedded, out bool bPrimitive)
		{
			bEmbedded = true;
			bool flag = false;
			if (MatchingStrings(typeNS, s_wsdlSoapNamespaceString))
			{
				if (MatchingStrings(typeName, s_referenceString))
				{
					bEmbedded = false;
				}
				else if (MatchingStrings(typeName, s_arrayString))
				{
					flag = true;
				}
			}
			if (!bEmbedded || flag)
			{
				typeName = LookupAttribute(s_refTypeString, s_wsdlSudsNamespaceString, throwExp: true);
				typeNS = ParseQName(ref typeName);
			}
			bPrimitive = IsPrimitiveType(typeNS, typeName);
			if (bPrimitive)
			{
				typeName = MapSchemaTypesToCSharpTypes(typeName);
				bEmbedded = false;
			}
			else if (MatchingStrings(typeName, s_urTypeString) && MatchingSchemaStrings(typeNS))
			{
				typeName = s_objectString;
			}
		}

		private URTNamespace ParseNamespace()
		{
			string text = LookupAttribute(s_targetNamespaceString, null, throwExp: false);
			bool flag = false;
			if (MatchingStrings(text, s_emptyString) && MatchingStrings(_XMLReader.LocalName, s_sudsString) && _parsingInput.UniqueNS == null)
			{
				text = _parsingInput.TargetNS;
				flag = true;
			}
			URTNamespace uRTNamespace = LookupNamespace(text);
			if (uRTNamespace == null)
			{
				uRTNamespace = new URTNamespace(text, this);
			}
			if (flag)
			{
				_parsingInput.UniqueNS = uRTNamespace;
			}
			ReadNextXmlElement();
			return uRTNamespace;
		}

		private void ParseReaderStreamLocation(ReaderStream reader, ReaderStream currentReaderStream)
		{
			string text = reader.Location;
			int num = text.IndexOf(':');
			if (num == -1)
			{
				if (currentReaderStream == null || currentReaderStream.Location == null)
				{
					throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_Import"), reader.Location));
				}
				if (currentReaderStream.Uri == null)
				{
					currentReaderStream.Uri = new Uri(currentReaderStream.Location);
				}
				Uri uri2 = (reader.Uri = new Uri(currentReaderStream.Uri, text));
				text = uri2.ToString();
				num = text.IndexOf(':');
				if (num == -1)
				{
					return;
				}
				reader.Location = text;
			}
			string text2 = text.Substring(0, num).ToLower(CultureInfo.InvariantCulture);
			string path = text.Substring(num + 1);
			if (text2 == "file")
			{
				reader.InputStream = new StreamReader(path);
			}
			else if (text2.StartsWith("http", StringComparison.Ordinal))
			{
				WebRequest webRequest = WebRequest.Create(text);
				WebResponse response = webRequest.GetResponse();
				Stream responseStream = response.GetResponseStream();
				reader.InputStream = new StreamReader(responseStream);
			}
		}

		private void ParseImport()
		{
			LookupAttribute(s_namespaceString, null, throwExp: true);
			string text = null;
			text = LookupAttribute(s_locationString, null, throwExp: false);
			if (text != null && text.Length > 0)
			{
				ReaderStream readerStream = new ReaderStream(text);
				ParseReaderStreamLocation(readerStream, (ReaderStream)_currentReaderStack.Peek());
				ReaderStream.GetReaderStream(_readerStreamsWsdl, readerStream);
			}
			ReadNextXmlElement();
		}

		internal void Parse()
		{
			ReaderStream readerStream = _readerStreamsWsdl;
			do
			{
				_XMLReader = new XmlTextReader(readerStream.InputStream, _primedNametable);
				_XMLReader.WhitespaceHandling = WhitespaceHandling.None;
				_XMLReader.XmlResolver = null;
				ParseInput(readerStream);
				readerStream = ReaderStream.GetNextReaderStream(readerStream);
			}
			while (readerStream != null);
			StartWsdlResolution();
			if (_writerStreams != null)
			{
				WriterStream.Close(_writerStreams);
			}
		}

		private void ParseInput(ReaderStream input)
		{
			_parsingInput = input;
			try
			{
				ReadNextXmlElement();
				string localName = _XMLReader.LocalName;
				if (MatchingNamespace(s_wsdlNamespaceString) && MatchingStrings(localName, s_definitionsString))
				{
					_currentReaderStack.Push(input);
					ParseWsdl();
					_currentReaderStack.Pop();
					return;
				}
				if (MatchingNamespace(s_wsdlNamespaceString) && MatchingStrings(localName, s_typesString))
				{
					_currentReaderStack.Push(input);
					ParseWsdlTypes();
					_currentReaderStack.Pop();
					return;
				}
				if (MatchingSchemaNamespace() && MatchingStrings(localName, s_schemaString))
				{
					_currentReaderStack.Push(input);
					ParseSchema();
					_currentReaderStack.Pop();
					return;
				}
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_UnknownElementAtRootLevel"), localName));
			}
			finally
			{
				WriterStream.Flush(_writerStreams);
			}
		}

		private void ParseWsdl()
		{
			int depth = _XMLReader.Depth;
			_parsingInput.Name = LookupAttribute(s_nameString, null, throwExp: false);
			_parsingInput.TargetNS = LookupAttribute(s_targetNamespaceString, null, throwExp: false);
			URTNamespace inparsingNamespace = ParseNamespace();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingNamespace(s_wsdlNamespaceString))
				{
					if (MatchingStrings(localName, s_typesString))
					{
						ParseWsdlTypes();
						continue;
					}
					if (MatchingStrings(localName, s_messageString))
					{
						ParseWsdlMessage();
						continue;
					}
					if (MatchingStrings(localName, s_portTypeString))
					{
						ParseWsdlPortType();
						continue;
					}
					if (MatchingStrings(localName, s_bindingString))
					{
						ParseWsdlBinding(inparsingNamespace);
						continue;
					}
					if (MatchingStrings(localName, s_serviceString))
					{
						ParseWsdlService();
						continue;
					}
					if (MatchingStrings(localName, s_importString))
					{
						ParseImport();
						continue;
					}
				}
				SkipXmlElement();
			}
		}

		private void StartWsdlResolution()
		{
			ResolveWsdl();
			Resolve();
			PruneNamespaces();
			PrintCSC();
		}

		private void PruneNamespaces()
		{
			ArrayList arrayList = new ArrayList(10);
			for (int i = 0; i < _URTNamespaces.Count; i++)
			{
				URTNamespace uRTNamespace = (URTNamespace)_URTNamespaces[i];
				if (uRTNamespace.bReferenced)
				{
					arrayList.Add(uRTNamespace);
				}
			}
			_URTNamespaces = arrayList;
		}

		[Conditional("_LOGGING")]
		private void DumpWsdl()
		{
			foreach (DictionaryEntry wsdlMessage in wsdlMessages)
			{
				((IDump)wsdlMessage.Value).Dump();
			}
			foreach (DictionaryEntry wsdlPortType in wsdlPortTypes)
			{
				((IDump)wsdlPortType.Value).Dump();
			}
			foreach (WsdlBinding wsdlBinding in wsdlBindings)
			{
				wsdlBinding.Dump();
			}
			foreach (WsdlService wsdlService in wsdlServices)
			{
				wsdlService.Dump();
			}
		}

		private void ParseWsdlTypes()
		{
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			_currentSchemaReaderStack.Push(_currentReaderStack.Peek());
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingSchemaNamespace() && MatchingStrings(localName, s_schemaString))
				{
					ParseSchema();
					if (_readerStreamsXsd != null)
					{
						ParseImportedSchemaController();
					}
				}
				else
				{
					SkipXmlElement();
				}
			}
			_currentSchemaReaderStack.Pop();
		}

		private void ParseSchemaIncludeElement()
		{
			ParseSchemaImportElement(bImport: false);
		}

		private void ParseSchemaImportElement()
		{
			ParseSchemaImportElement(bImport: true);
		}

		private void ParseSchemaImportElement(bool bImport)
		{
			if (bImport)
			{
				LookupAttribute(s_namespaceString, null, throwExp: true);
			}
			string text = null;
			text = LookupAttribute(s_schemaLocationString, null, throwExp: false);
			if (text != null && text.Length > 0)
			{
				if (_readerStreamsXsd == null)
				{
					_readerStreamsXsd = new ReaderStream(text);
					ParseReaderStreamLocation(_readerStreamsXsd, (ReaderStream)_currentSchemaReaderStack.Peek());
				}
				else
				{
					ReaderStream readerStream = new ReaderStream(text);
					ParseReaderStreamLocation(readerStream, (ReaderStream)_currentSchemaReaderStack.Peek());
					ReaderStream.GetReaderStream(_readerStreamsWsdl, readerStream);
				}
			}
			ReadNextXmlElement();
		}

		internal void ParseImportedSchemaController()
		{
			CreatePrimedNametable();
			ReaderStream readerStream = _readerStreamsXsd;
			XmlTextReader xMLReader = _XMLReader;
			ReaderStream parsingInput = _parsingInput;
			do
			{
				_XMLReader = new XmlTextReader(readerStream.InputStream, _primedNametable);
				_XMLReader.WhitespaceHandling = WhitespaceHandling.None;
				_XMLReader.XmlResolver = null;
				_parsingInput = readerStream;
				ParseImportedSchema(readerStream);
				readerStream = ReaderStream.GetNextReaderStream(readerStream);
			}
			while (readerStream != null);
			_readerStreamsXsd = null;
			_XMLReader = xMLReader;
			_parsingInput = parsingInput;
		}

		private void ParseImportedSchema(ReaderStream input)
		{
			try
			{
				_ = _XMLReader.LocalName;
				_currentSchemaReaderStack.Push(input);
				ReadNextXmlElement();
				ParseSchema();
				_currentSchemaReaderStack.Pop();
			}
			finally
			{
				WriterStream.Flush(_writerStreams);
			}
		}

		private void ParseWsdlMessage()
		{
			WsdlMessage wsdlMessage = new WsdlMessage();
			wsdlMessage.name = LookupAttribute(s_nameString, null, throwExp: true);
			wsdlMessage.nameNs = _parsingInput.TargetNS;
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingStrings(localName, s_partString))
				{
					WsdlMessagePart wsdlMessagePart = new WsdlMessagePart();
					wsdlMessagePart.name = LookupAttribute(s_nameString, null, throwExp: true);
					wsdlMessagePart.nameNs = _parsingInput.TargetNS;
					wsdlMessagePart.element = LookupAttribute(s_elementString, null, throwExp: false);
					wsdlMessagePart.typeName = LookupAttribute(s_typeString, null, throwExp: false);
					if (wsdlMessagePart.element != null)
					{
						wsdlMessagePart.elementNs = ParseQName(ref wsdlMessagePart.element);
					}
					if (wsdlMessagePart.typeName != null)
					{
						wsdlMessagePart.typeNameNs = ParseQName(ref wsdlMessagePart.typeName);
					}
					wsdlMessage.parts.Add(wsdlMessagePart);
					ReadNextXmlElement();
				}
				else
				{
					SkipXmlElement();
				}
			}
			wsdlMessages[wsdlMessage.name] = wsdlMessage;
		}

		private void ParseWsdlPortType()
		{
			WsdlPortType wsdlPortType = new WsdlPortType();
			wsdlPortType.name = LookupAttribute(s_nameString, null, throwExp: true);
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingStrings(localName, s_operationString))
				{
					WsdlPortTypeOperation wsdlPortTypeOperation = new WsdlPortTypeOperation();
					wsdlPortTypeOperation.name = LookupAttribute(s_nameString, null, throwExp: true);
					wsdlPortTypeOperation.nameNs = ParseQName(ref wsdlPortTypeOperation.nameNs);
					wsdlPortTypeOperation.parameterOrder = LookupAttribute(s_parameterOrderString, null, throwExp: false);
					ParseWsdlPortTypeOperationContent(wsdlPortType, wsdlPortTypeOperation);
					wsdlPortType.operations.Add(wsdlPortTypeOperation);
				}
				else
				{
					SkipXmlElement();
				}
			}
			wsdlPortTypes[wsdlPortType.name] = wsdlPortType;
		}

		private void ParseWsdlPortTypeOperationContent(WsdlPortType portType, WsdlPortTypeOperation portTypeOperation)
		{
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingStrings(localName, s_inputString))
				{
					WsdlPortTypeOperationContent wsdlPortTypeOperationContent = new WsdlPortTypeOperationContent();
					wsdlPortTypeOperationContent.element = Atomize("input");
					wsdlPortTypeOperationContent.name = LookupAttribute(s_nameString, null, throwExp: false);
					if (MatchingStrings(wsdlPortTypeOperationContent.name, s_emptyString))
					{
						wsdlPortTypeOperationContent.name = Atomize(portTypeOperation.name + "Request");
						if (portType.sections.ContainsKey(wsdlPortTypeOperationContent.name))
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_DuplicatePortTypesOperationName"), portTypeOperation.name));
						}
						portType.sections[wsdlPortTypeOperationContent.name] = portTypeOperation;
						portType.sections[portTypeOperation.name] = portTypeOperation;
					}
					else
					{
						if (portType.sections.ContainsKey(wsdlPortTypeOperationContent.name))
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_DuplicatePortSectionName"), wsdlPortTypeOperationContent.name));
						}
						portType.sections[wsdlPortTypeOperationContent.name] = portTypeOperation;
					}
					wsdlPortTypeOperationContent.message = LookupAttribute(s_messageString, null, throwExp: true);
					wsdlPortTypeOperationContent.messageNs = ParseQName(ref wsdlPortTypeOperationContent.message);
					portTypeOperation.contents.Add(wsdlPortTypeOperationContent);
					ReadNextXmlElement();
				}
				else if (MatchingStrings(localName, s_outputString))
				{
					WsdlPortTypeOperationContent wsdlPortTypeOperationContent2 = new WsdlPortTypeOperationContent();
					wsdlPortTypeOperationContent2.element = Atomize("output");
					wsdlPortTypeOperationContent2.name = LookupAttribute(s_nameString, null, throwExp: false);
					wsdlPortTypeOperationContent2.nameNs = ParseQName(ref wsdlPortTypeOperationContent2.name);
					if (MatchingStrings(wsdlPortTypeOperationContent2.name, s_emptyString))
					{
						wsdlPortTypeOperationContent2.name = Atomize(portTypeOperation.name + "Response");
					}
					if (!portType.sections.ContainsKey(wsdlPortTypeOperationContent2.name))
					{
						portType.sections[wsdlPortTypeOperationContent2.name] = portTypeOperation;
					}
					wsdlPortTypeOperationContent2.message = LookupAttribute(s_messageString, null, throwExp: true);
					wsdlPortTypeOperationContent2.messageNs = ParseQName(ref wsdlPortTypeOperationContent2.message);
					portTypeOperation.contents.Add(wsdlPortTypeOperationContent2);
					ReadNextXmlElement();
				}
				else
				{
					SkipXmlElement();
				}
			}
		}

		private void ParseWsdlBinding(URTNamespace inparsingNamespace)
		{
			WsdlBinding wsdlBinding = new WsdlBinding();
			wsdlBinding.name = LookupAttribute(s_nameString, null, throwExp: true);
			wsdlBinding.type = LookupAttribute(s_typeString, null, throwExp: true);
			wsdlBinding.typeNs = ParseQName(ref wsdlBinding.type);
			URTNamespace uRTNamespace = LookupNamespace(wsdlBinding.typeNs);
			if (uRTNamespace == null)
			{
				uRTNamespace = new URTNamespace(wsdlBinding.typeNs, this);
			}
			wsdlBinding.parsingNamespace = uRTNamespace;
			bool flag = false;
			bool bRpcBinding = false;
			bool bSoapEncoded = false;
			bool flag2 = false;
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingNamespace(s_wsdlSoapNamespaceString) && MatchingStrings(localName, s_bindingString))
				{
					flag = true;
					WsdlBindingSoapBinding wsdlBindingSoapBinding = new WsdlBindingSoapBinding();
					wsdlBindingSoapBinding.style = LookupAttribute(s_styleString, null, throwExp: true);
					if (wsdlBindingSoapBinding.style == "rpc")
					{
						bRpcBinding = true;
					}
					wsdlBindingSoapBinding.transport = LookupAttribute(s_transportString, null, throwExp: true);
					wsdlBinding.soapBinding = wsdlBindingSoapBinding;
					ReadNextXmlElement();
					continue;
				}
				if (MatchingNamespace(s_wsdlSudsNamespaceString))
				{
					flag2 = true;
					if (MatchingStrings(localName, s_classString) || MatchingStrings(localName, s_structString))
					{
						WsdlBindingSuds wsdlBindingSuds = new WsdlBindingSuds();
						wsdlBindingSuds.elementName = localName;
						wsdlBindingSuds.typeName = LookupAttribute(s_typeString, null, throwExp: true);
						wsdlBindingSuds.ns = ParseQName(ref wsdlBindingSuds.typeName);
						wsdlBindingSuds.extendsTypeName = LookupAttribute(s_extendsString, null, throwExp: false);
						string use = LookupAttribute(s_rootTypeString, null, throwExp: false);
						wsdlBindingSuds.sudsUse = ProcessSudsUse(use, localName);
						if (!MatchingStrings(wsdlBindingSuds.extendsTypeName, s_emptyString))
						{
							wsdlBindingSuds.extendsNs = ParseQName(ref wsdlBindingSuds.extendsTypeName);
						}
						ParseWsdlBindingSuds(wsdlBindingSuds);
						wsdlBinding.suds.Add(wsdlBindingSuds);
						continue;
					}
					if (MatchingStrings(localName, s_interfaceString))
					{
						WsdlBindingSuds wsdlBindingSuds2 = new WsdlBindingSuds();
						wsdlBindingSuds2.elementName = localName;
						wsdlBindingSuds2.typeName = LookupAttribute(s_typeString, null, throwExp: true);
						wsdlBindingSuds2.ns = ParseQName(ref wsdlBindingSuds2.typeName);
						string use2 = LookupAttribute(s_rootTypeString, null, throwExp: false);
						wsdlBindingSuds2.sudsUse = ProcessSudsUse(use2, localName);
						ParseWsdlBindingSuds(wsdlBindingSuds2);
						wsdlBinding.suds.Add(wsdlBindingSuds2);
						continue;
					}
				}
				else if (MatchingNamespace(s_wsdlNamespaceString) && MatchingStrings(localName, s_operationString))
				{
					WsdlBindingOperation wsdlBindingOperation = new WsdlBindingOperation();
					wsdlBindingOperation.name = LookupAttribute(s_nameString, null, throwExp: true);
					wsdlBindingOperation.nameNs = _parsingInput.TargetNS;
					ParseWsdlBindingOperation(wsdlBindingOperation, ref bRpcBinding, ref bSoapEncoded);
					wsdlBinding.operations.Add(wsdlBindingOperation);
					continue;
				}
				SkipXmlElement();
			}
			if ((flag && bRpcBinding && bSoapEncoded) || flag2)
			{
				wsdlBindings.Add(wsdlBinding);
			}
		}

		private void ParseWsdlBindingSuds(WsdlBindingSuds suds)
		{
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingStrings(localName, s_implementsString) || MatchingStrings(localName, s_extendsString))
				{
					WsdlBindingSudsImplements wsdlBindingSudsImplements = new WsdlBindingSudsImplements();
					wsdlBindingSudsImplements.typeName = LookupAttribute(s_typeString, null, throwExp: true);
					wsdlBindingSudsImplements.ns = ParseQName(ref wsdlBindingSudsImplements.typeName);
					suds.implements.Add(wsdlBindingSudsImplements);
					ReadNextXmlElement();
				}
				else if (MatchingStrings(localName, s_nestedTypeString))
				{
					WsdlBindingSudsNestedType wsdlBindingSudsNestedType = new WsdlBindingSudsNestedType();
					wsdlBindingSudsNestedType.name = LookupAttribute(s_nameString, null, throwExp: true);
					wsdlBindingSudsNestedType.typeName = LookupAttribute(s_typeString, null, throwExp: true);
					wsdlBindingSudsNestedType.ns = ParseQName(ref wsdlBindingSudsNestedType.typeName);
					suds.nestedTypes.Add(wsdlBindingSudsNestedType);
					ReadNextXmlElement();
				}
				else
				{
					SkipXmlElement();
				}
			}
		}

		private SudsUse ProcessSudsUse(string use, string elementName)
		{
			SudsUse result = SudsUse.Class;
			if (use == null || use.Length == 0)
			{
				use = elementName;
			}
			if (MatchingStrings(use, s_interfaceString))
			{
				result = SudsUse.Interface;
			}
			else if (MatchingStrings(use, s_classString))
			{
				result = SudsUse.Class;
			}
			else if (MatchingStrings(use, s_structString))
			{
				result = SudsUse.Struct;
			}
			else if (MatchingStrings(use, s_ISerializableString))
			{
				result = SudsUse.ISerializable;
			}
			else if (MatchingStrings(use, s_marshalByRefString))
			{
				result = SudsUse.MarshalByRef;
			}
			else if (MatchingStrings(use, s_delegateString))
			{
				result = SudsUse.Delegate;
			}
			else if (MatchingStrings(use, s_servicedComponentString))
			{
				result = SudsUse.ServicedComponent;
			}
			return result;
		}

		private void ParseWsdlBindingOperation(WsdlBindingOperation op, ref bool bRpcBinding, ref bool bSoapEncoded)
		{
			int depth = _XMLReader.Depth;
			bool flag = false;
			bool flag2 = false;
			WsdlBindingOperationSection wsdlBindingOperationSection = null;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingNamespace(s_wsdlSudsNamespaceString) && MatchingStrings(localName, s_methodString))
				{
					op.methodAttributes = LookupAttribute(s_attributesString, null, throwExp: true);
					ReadNextXmlElement();
					continue;
				}
				if (MatchingNamespace(s_wsdlSoapNamespaceString) && MatchingStrings(localName, s_operationString))
				{
					WsdlBindingSoapOperation wsdlBindingSoapOperation = new WsdlBindingSoapOperation();
					wsdlBindingSoapOperation.soapAction = LookupAttribute(s_soapActionString, null, throwExp: false);
					wsdlBindingSoapOperation.style = LookupAttribute(s_styleString, null, throwExp: false);
					if (wsdlBindingSoapOperation.style == "rpc")
					{
						bRpcBinding = true;
					}
					op.soapOperation = wsdlBindingSoapOperation;
					ReadNextXmlElement();
					continue;
				}
				if (MatchingNamespace(s_wsdlNamespaceString))
				{
					if (MatchingStrings(localName, s_inputString))
					{
						flag = true;
						wsdlBindingOperationSection = ParseWsdlBindingOperationSection(op, localName, ref bSoapEncoded);
						continue;
					}
					if (MatchingStrings(localName, s_outputString))
					{
						flag2 = true;
						ParseWsdlBindingOperationSection(op, localName, ref bSoapEncoded);
						continue;
					}
					if (MatchingStrings(localName, s_faultString))
					{
						ParseWsdlBindingOperationSection(op, localName, ref bSoapEncoded);
						continue;
					}
				}
				SkipXmlElement();
			}
			if (wsdlBindingOperationSection != null && flag && !flag2)
			{
				wsdlBindingOperationSection.name = op.name;
			}
		}

		private WsdlBindingOperationSection ParseWsdlBindingOperationSection(WsdlBindingOperation op, string inputElementName, ref bool bSoapEncoded)
		{
			bool flag = false;
			WsdlBindingOperationSection wsdlBindingOperationSection = new WsdlBindingOperationSection();
			op.sections.Add(wsdlBindingOperationSection);
			wsdlBindingOperationSection.name = LookupAttribute(s_nameString, null, throwExp: false);
			if (MatchingStrings(wsdlBindingOperationSection.name, s_emptyString))
			{
				if (MatchingStrings(inputElementName, s_inputString))
				{
					flag = true;
					wsdlBindingOperationSection.name = Atomize(op.name + "Request");
				}
				else if (MatchingStrings(inputElementName, s_outputString))
				{
					wsdlBindingOperationSection.name = Atomize(op.name + "Response");
				}
			}
			wsdlBindingOperationSection.elementName = inputElementName;
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingNamespace(s_wsdlSoapNamespaceString))
				{
					if (MatchingStrings(localName, s_bodyString))
					{
						WsdlBindingSoapBody wsdlBindingSoapBody = new WsdlBindingSoapBody();
						wsdlBindingOperationSection.extensions.Add(wsdlBindingSoapBody);
						wsdlBindingSoapBody.parts = LookupAttribute(s_partsString, null, throwExp: false);
						wsdlBindingSoapBody.use = LookupAttribute(s_useString, null, throwExp: true);
						if (wsdlBindingSoapBody.use == "encoded")
						{
							bSoapEncoded = true;
						}
						wsdlBindingSoapBody.encodingStyle = LookupAttribute(s_encodingStyleString, null, throwExp: false);
						wsdlBindingSoapBody.namespaceUri = LookupAttribute(s_namespaceString, null, throwExp: false);
						ReadNextXmlElement();
						continue;
					}
					if (MatchingStrings(localName, s_headerString))
					{
						WsdlBindingSoapHeader wsdlBindingSoapHeader = new WsdlBindingSoapHeader();
						wsdlBindingOperationSection.extensions.Add(wsdlBindingSoapHeader);
						wsdlBindingSoapHeader.message = LookupAttribute(s_messageString, null, throwExp: true);
						wsdlBindingSoapHeader.messageNs = ParseQName(ref wsdlBindingSoapHeader.message);
						wsdlBindingSoapHeader.part = LookupAttribute(s_partString, null, throwExp: true);
						wsdlBindingSoapHeader.use = LookupAttribute(s_useString, null, throwExp: true);
						wsdlBindingSoapHeader.encodingStyle = LookupAttribute(s_encodingStyleString, null, throwExp: false);
						wsdlBindingSoapHeader.namespaceUri = LookupAttribute(s_namespaceString, null, throwExp: false);
						ReadNextXmlElement();
						continue;
					}
					if (MatchingStrings(localName, s_faultString))
					{
						WsdlBindingSoapFault wsdlBindingSoapFault = new WsdlBindingSoapFault();
						wsdlBindingOperationSection.extensions.Add(wsdlBindingSoapFault);
						wsdlBindingSoapFault.name = LookupAttribute(s_nameString, null, throwExp: true);
						wsdlBindingSoapFault.use = LookupAttribute(s_useString, null, throwExp: true);
						wsdlBindingSoapFault.encodingStyle = LookupAttribute(s_encodingStyleString, null, throwExp: false);
						wsdlBindingSoapFault.namespaceUri = LookupAttribute(s_namespaceString, null, throwExp: false);
						ReadNextXmlElement();
						continue;
					}
				}
				SkipXmlElement();
			}
			if (flag)
			{
				return wsdlBindingOperationSection;
			}
			return null;
		}

		private void ParseWsdlService()
		{
			WsdlService wsdlService = new WsdlService();
			wsdlService.name = LookupAttribute(s_nameString, null, throwExp: true);
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingNamespace(s_wsdlNamespaceString) && MatchingStrings(localName, s_portString))
				{
					WsdlServicePort wsdlServicePort = new WsdlServicePort();
					wsdlServicePort.name = LookupAttribute(s_nameString, null, throwExp: true);
					wsdlServicePort.nameNs = ParseQName(ref wsdlServicePort.nameNs);
					wsdlServicePort.binding = LookupAttribute(s_bindingString, null, throwExp: true);
					wsdlServicePort.bindingNs = ParseQName(ref wsdlServicePort.binding);
					ParseWsdlServicePort(wsdlServicePort);
					wsdlService.ports[wsdlServicePort.binding] = wsdlServicePort;
				}
				else
				{
					SkipXmlElement();
				}
			}
			wsdlServices.Add(wsdlService);
		}

		private void ParseWsdlServicePort(WsdlServicePort port)
		{
			int depth = _XMLReader.Depth;
			ReadNextXmlElement();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingNamespace(s_wsdlSoapNamespaceString) && MatchingStrings(localName, s_addressString))
				{
					if (port.locations == null)
					{
						port.locations = new ArrayList(10);
					}
					port.locations.Add(LookupAttribute(s_locationString, null, throwExp: true));
					ReadNextXmlElement();
				}
				else
				{
					SkipXmlElement();
				}
			}
		}

		private void ResolveWsdl()
		{
			if (wsdlBindings.Count == 0)
			{
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_RpcBindingsMissing")));
			}
			foreach (WsdlBinding wsdlBinding in wsdlBindings)
			{
				if (wsdlBinding.soapBinding == null)
				{
					continue;
				}
				if (wsdlBinding.suds != null && wsdlBinding.suds.Count > 0)
				{
					bool bFirstSuds = true;
					foreach (WsdlBindingSuds sud in wsdlBinding.suds)
					{
						if (MatchingStrings(sud.elementName, s_classString) || MatchingStrings(sud.elementName, s_structString))
						{
							ResolveWsdlClass(wsdlBinding, sud, bFirstSuds);
							bFirstSuds = false;
							continue;
						}
						if (MatchingStrings(sud.elementName, s_interfaceString))
						{
							ResolveWsdlInterface(wsdlBinding, sud);
							continue;
						}
						throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveElementInNS"), sud.elementName, s_wsdlSudsNamespaceString));
					}
				}
				else
				{
					ResolveWsdlClass(wsdlBinding, null, bFirstSuds: true);
				}
			}
		}

		private void ResolveWsdlClass(WsdlBinding binding, WsdlBindingSuds suds, bool bFirstSuds)
		{
			URTComplexType uRTComplexType;
			if (suds != null)
			{
				URTNamespace uRTNamespace = AddNewNamespace(suds.ns);
				uRTComplexType = uRTNamespace.LookupComplexType(suds.typeName);
				if (uRTComplexType == null)
				{
					uRTComplexType = new URTComplexType(suds.typeName, uRTNamespace.Name, uRTNamespace.Namespace, uRTNamespace.EncodedNS, _blockDefault, bSUDSType: false, bAnonymous: false, this, uRTNamespace);
					uRTNamespace.AddComplexType(uRTComplexType);
				}
				if (MatchingStrings(suds.elementName, s_structString))
				{
					uRTComplexType.IsValueType = true;
				}
				uRTComplexType.SudsUse = suds.sudsUse;
				if (suds.sudsUse == SudsUse.MarshalByRef || suds.sudsUse == SudsUse.ServicedComponent)
				{
					uRTComplexType.IsSUDSType = true;
					if (_bWrappedProxy)
					{
						uRTComplexType.SUDSType = SUDSType.ClientProxy;
					}
					else
					{
						uRTComplexType.SUDSType = SUDSType.MarshalByRef;
					}
					if (suds.extendsTypeName != null && suds.extendsTypeName.Length > 0)
					{
						URTNamespace uRTNamespace2 = AddNewNamespace(suds.extendsNs);
						URTComplexType uRTComplexType2 = uRTNamespace2.LookupComplexType(suds.extendsTypeName);
						if (uRTComplexType2 == null)
						{
							uRTComplexType2 = new URTComplexType(suds.extendsTypeName, uRTNamespace2.Name, uRTNamespace2.Namespace, uRTNamespace2.EncodedNS, _blockDefault, bSUDSType: true, bAnonymous: false, this, uRTNamespace2);
							uRTNamespace2.AddComplexType(uRTComplexType2);
						}
						else
						{
							uRTComplexType2.IsSUDSType = true;
						}
						if (_bWrappedProxy)
						{
							uRTComplexType2.SUDSType = SUDSType.ClientProxy;
						}
						else
						{
							uRTComplexType2.SUDSType = SUDSType.MarshalByRef;
						}
						uRTComplexType2.SudsUse = suds.sudsUse;
					}
				}
				foreach (WsdlBindingSudsNestedType nestedType in suds.nestedTypes)
				{
					ResolveWsdlNestedType(binding, suds, nestedType);
				}
			}
			else
			{
				URTNamespace uRTNamespace = AddNewNamespace(binding.typeNs);
				string text = binding.name;
				int num = binding.name.IndexOf("Binding");
				if (num > 0)
				{
					text = binding.name.Substring(0, num);
				}
				uRTComplexType = uRTNamespace.LookupComplexTypeEqual(text);
				if (uRTComplexType == null)
				{
					uRTComplexType = new URTComplexType(text, uRTNamespace.Name, uRTNamespace.Namespace, uRTNamespace.EncodedNS, _blockDefault, bSUDSType: true, bAnonymous: false, this, uRTNamespace);
					uRTNamespace.AddComplexType(uRTComplexType);
				}
				else
				{
					uRTComplexType.IsSUDSType = true;
				}
				if (_bWrappedProxy)
				{
					uRTComplexType.SUDSType = SUDSType.ClientProxy;
				}
				else
				{
					uRTComplexType.SUDSType = SUDSType.MarshalByRef;
				}
				uRTComplexType.SudsUse = SudsUse.MarshalByRef;
			}
			uRTComplexType.ConnectURLs = ResolveWsdlAddress(binding);
			if (suds != null)
			{
				if (!MatchingStrings(suds.extendsTypeName, s_emptyString))
				{
					uRTComplexType.Extends(suds.extendsTypeName, suds.extendsNs);
				}
				foreach (WsdlBindingSudsImplements implement in suds.implements)
				{
					uRTComplexType.Implements(implement.typeName, implement.ns, this);
				}
			}
			if (!bFirstSuds || (uRTComplexType.SudsUse != SudsUse.MarshalByRef && uRTComplexType.SudsUse != SudsUse.ServicedComponent && uRTComplexType.SudsUse != SudsUse.Delegate && uRTComplexType.SudsUse != SudsUse.Interface))
			{
				return;
			}
			ArrayList arrayList = ResolveWsdlMethodInfo(binding);
			foreach (WsdlMethodInfo item in arrayList)
			{
				if (item.inputMethodName != null && item.outputMethodName != null)
				{
					RRMethod rRMethod = new RRMethod(item, uRTComplexType);
					rRMethod.AddRequest(item.methodName, item.methodNameNs);
					rRMethod.AddResponse(item.methodName, item.methodNameNs);
					uRTComplexType.AddMethod(rRMethod);
					continue;
				}
				if (item.inputMethodName != null)
				{
					OnewayMethod onewayMethod = new OnewayMethod(item, uRTComplexType);
					uRTComplexType.AddMethod(onewayMethod);
					onewayMethod.AddMessage(item.methodName, item.methodNameNs);
					continue;
				}
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlInvalidMessage"), item.methodName));
			}
		}

		private void ResolveWsdlInterface(WsdlBinding binding, WsdlBindingSuds suds)
		{
			_ = binding.parsingNamespace;
			URTNamespace uRTNamespace = AddNewNamespace(suds.ns);
			URTInterface uRTInterface = uRTNamespace.LookupInterface(suds.typeName);
			if (uRTInterface == null)
			{
				uRTInterface = new URTInterface(suds.typeName, uRTNamespace.Name, uRTNamespace.Namespace, uRTNamespace.EncodedNS, this);
				uRTNamespace.AddInterface(uRTInterface);
			}
			if (suds.extendsTypeName != null)
			{
				uRTInterface.Extends(suds.extendsTypeName, suds.extendsNs, this);
			}
			foreach (WsdlBindingSudsImplements implement in suds.implements)
			{
				uRTInterface.Extends(implement.typeName, implement.ns, this);
			}
			ArrayList arrayList = ResolveWsdlMethodInfo(binding);
			foreach (WsdlMethodInfo item in arrayList)
			{
				if (item.inputMethodName != null && item.outputMethodName != null)
				{
					RRMethod rRMethod = new RRMethod(item, null);
					rRMethod.AddRequest(item.methodName, item.methodNameNs);
					rRMethod.AddResponse(item.methodName, item.methodNameNs);
					uRTInterface.AddMethod(rRMethod);
					continue;
				}
				if (item.inputMethodName != null)
				{
					OnewayMethod onewayMethod = new OnewayMethod(item.methodName, item.soapAction, null);
					onewayMethod.AddMessage(item.methodName, item.methodNameNs);
					uRTInterface.AddMethod(onewayMethod);
					continue;
				}
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlInvalidMessage"), item.methodName));
			}
		}

		private void ResolveWsdlNestedType(WsdlBinding binding, WsdlBindingSuds suds, WsdlBindingSudsNestedType nested)
		{
			_ = suds.typeName;
			string ns = nested.ns;
			_ = nested.name;
			_ = nested.typeName;
			if (suds.ns != ns)
			{
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveNestedTypeNS"), suds.typeName, suds.ns));
			}
			URTNamespace uRTNamespace = AddNewNamespace(suds.ns);
			URTComplexType uRTComplexType = uRTNamespace.LookupComplexType(suds.typeName);
			if (uRTComplexType == null)
			{
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveNestedType"), suds.typeName, suds.ns));
			}
			BaseType baseType = uRTNamespace.LookupType(nested.typeName);
			if (baseType == null)
			{
				baseType = uRTNamespace.LookupComplexType(nested.typeName);
				if (baseType == null)
				{
					baseType = new URTComplexType(nested.typeName, uRTNamespace.Name, uRTNamespace.Namespace, uRTNamespace.EncodedNS, _blockDefault, bSUDSType: false, bAnonymous: false, this, uRTNamespace);
					uRTNamespace.AddComplexType((URTComplexType)baseType);
				}
			}
			baseType.bNestedType = true;
			baseType.NestedTypeName = nested.name;
			baseType.FullNestedTypeName = nested.typeName;
			baseType.OuterTypeName = suds.typeName;
			uRTComplexType.AddNestedType(baseType);
		}

		private ArrayList ResolveWsdlAddress(WsdlBinding binding)
		{
			ArrayList arrayList = null;
			if (_bWrappedProxy)
			{
				foreach (WsdlService wsdlService in wsdlServices)
				{
					WsdlServicePort wsdlServicePort = (WsdlServicePort)wsdlService.ports[binding.name];
					if (wsdlServicePort != null)
					{
						return wsdlServicePort.locations;
					}
					if (arrayList != null)
					{
						return arrayList;
					}
				}
				return arrayList;
			}
			return arrayList;
		}

		private ArrayList ResolveWsdlMethodInfo(WsdlBinding binding)
		{
			ArrayList arrayList = new ArrayList(10);
			Hashtable hashtable = new Hashtable(3);
			for (int i = 0; i < binding.operations.Count; i++)
			{
				bool flag = false;
				bool flag2 = false;
				WsdlBindingOperation wsdlBindingOperation = (WsdlBindingOperation)binding.operations[i];
				if (wsdlBindingOperation.soapOperation == null)
				{
					continue;
				}
				WsdlMethodInfo wsdlMethodInfo = new WsdlMethodInfo();
				wsdlMethodInfo.methodName = wsdlBindingOperation.name;
				wsdlMethodInfo.methodNameNs = wsdlBindingOperation.nameNs;
				wsdlMethodInfo.methodAttributes = wsdlBindingOperation.methodAttributes;
				AddNewNamespace(wsdlBindingOperation.nameNs);
				WsdlBindingSoapOperation soapOperation = wsdlBindingOperation.soapOperation;
				if (wsdlMethodInfo.methodName.StartsWith("get_", StringComparison.Ordinal) && wsdlMethodInfo.methodName.Length > 4)
				{
					flag = true;
				}
				else if (wsdlMethodInfo.methodName.StartsWith("set_", StringComparison.Ordinal) && wsdlMethodInfo.methodName.Length > 4)
				{
					flag2 = true;
				}
				if (flag || flag2)
				{
					bool flag3 = false;
					string text = wsdlMethodInfo.methodName.Substring(4);
					WsdlMethodInfo wsdlMethodInfo2 = (WsdlMethodInfo)hashtable[text];
					if (wsdlMethodInfo2 == null)
					{
						hashtable[text] = wsdlMethodInfo;
						arrayList.Add(wsdlMethodInfo);
						wsdlMethodInfo2 = wsdlMethodInfo;
						wsdlMethodInfo.propertyName = text;
						wsdlMethodInfo.bProperty = true;
						flag3 = true;
					}
					if (flag)
					{
						wsdlMethodInfo2.bGet = true;
						wsdlMethodInfo2.soapActionGet = soapOperation.soapAction;
					}
					else
					{
						wsdlMethodInfo2.bSet = true;
						wsdlMethodInfo2.soapActionSet = soapOperation.soapAction;
					}
					if (!flag3)
					{
						continue;
					}
				}
				else
				{
					arrayList.Add(wsdlMethodInfo);
				}
				wsdlMethodInfo.soapAction = soapOperation.soapAction;
				WsdlPortType wsdlPortType = (WsdlPortType)wsdlPortTypes[binding.type];
				if (wsdlPortType == null || wsdlPortType.operations.Count != binding.operations.Count)
				{
					throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlInvalidPortType"), binding.type));
				}
				WsdlPortTypeOperation wsdlPortTypeOperation = null;
				foreach (WsdlBindingOperationSection section in wsdlBindingOperation.sections)
				{
					if (MatchingStrings(section.elementName, s_inputString))
					{
						wsdlPortTypeOperation = (WsdlPortTypeOperation)wsdlPortType.sections[section.name];
						if (wsdlPortTypeOperation == null)
						{
							int num = section.name.LastIndexOf("Request");
							if (num > 0)
							{
								string key = section.name.Substring(0, num);
								wsdlPortTypeOperation = (WsdlPortTypeOperation)wsdlPortType.sections[key];
							}
						}
						if (wsdlPortTypeOperation != null && wsdlPortTypeOperation.parameterOrder != null && wsdlPortTypeOperation.parameterOrder.Length > 0)
						{
							wsdlMethodInfo.paramNamesOrder = wsdlPortTypeOperation.parameterOrder.Split(' ');
						}
						foreach (WsdlBindingSoapBody extension in section.extensions)
						{
							if (extension.namespaceUri != null || extension.namespaceUri.Length > 0)
							{
								wsdlMethodInfo.inputMethodNameNs = extension.namespaceUri;
							}
						}
					}
					else
					{
						if (!MatchingStrings(section.elementName, s_outputString))
						{
							continue;
						}
						foreach (WsdlBindingSoapBody extension2 in section.extensions)
						{
							if (extension2.namespaceUri != null || extension2.namespaceUri.Length > 0)
							{
								wsdlMethodInfo.outputMethodNameNs = extension2.namespaceUri;
							}
						}
					}
				}
				if (wsdlPortTypeOperation == null)
				{
					continue;
				}
				foreach (WsdlPortTypeOperationContent content in wsdlPortTypeOperation.contents)
				{
					if (MatchingStrings(content.element, s_inputString))
					{
						wsdlMethodInfo.inputMethodName = content.message;
						if (wsdlMethodInfo.inputMethodNameNs == null)
						{
							wsdlMethodInfo.inputMethodNameNs = content.messageNs;
						}
						WsdlMessage wsdlMessage = (WsdlMessage)wsdlMessages[content.message];
						if (wsdlMessage == null)
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlMissingMessage"), content.message));
						}
						if (wsdlMessage.parts == null)
						{
							continue;
						}
						wsdlMethodInfo.inputNames = new string[wsdlMessage.parts.Count];
						wsdlMethodInfo.inputNamesNs = new string[wsdlMessage.parts.Count];
						wsdlMethodInfo.inputElements = new string[wsdlMessage.parts.Count];
						wsdlMethodInfo.inputElementsNs = new string[wsdlMessage.parts.Count];
						wsdlMethodInfo.inputTypes = new string[wsdlMessage.parts.Count];
						wsdlMethodInfo.inputTypesNs = new string[wsdlMessage.parts.Count];
						for (int j = 0; j < wsdlMessage.parts.Count; j++)
						{
							wsdlMethodInfo.inputNames[j] = ((WsdlMessagePart)wsdlMessage.parts[j]).name;
							wsdlMethodInfo.inputNamesNs[j] = ((WsdlMessagePart)wsdlMessage.parts[j]).nameNs;
							AddNewNamespace(wsdlMethodInfo.inputNamesNs[j]);
							wsdlMethodInfo.inputElements[j] = ((WsdlMessagePart)wsdlMessage.parts[j]).element;
							wsdlMethodInfo.inputElementsNs[j] = ((WsdlMessagePart)wsdlMessage.parts[j]).elementNs;
							AddNewNamespace(wsdlMethodInfo.inputElementsNs[j]);
							wsdlMethodInfo.inputTypes[j] = ((WsdlMessagePart)wsdlMessage.parts[j]).typeName;
							wsdlMethodInfo.inputTypesNs[j] = ((WsdlMessagePart)wsdlMessage.parts[j]).typeNameNs;
							AddNewNamespace(wsdlMethodInfo.inputTypesNs[j]);
							if (wsdlMethodInfo.bProperty && wsdlMethodInfo.inputTypes[j] != null && wsdlMethodInfo.propertyType == null)
							{
								wsdlMethodInfo.propertyType = wsdlMethodInfo.inputTypes[j];
								wsdlMethodInfo.propertyNs = wsdlMethodInfo.inputTypesNs[j];
								AddNewNamespace(wsdlMethodInfo.propertyNs);
							}
						}
						continue;
					}
					if (MatchingStrings(content.element, s_outputString))
					{
						wsdlMethodInfo.outputMethodName = content.message;
						if (wsdlMethodInfo.outputMethodNameNs == null)
						{
							wsdlMethodInfo.outputMethodNameNs = content.messageNs;
						}
						WsdlMessage wsdlMessage2 = (WsdlMessage)wsdlMessages[content.message];
						if (wsdlMessage2 == null)
						{
							throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlMissingMessage"), content.message));
						}
						if (wsdlMessage2.parts == null)
						{
							continue;
						}
						wsdlMethodInfo.outputNames = new string[wsdlMessage2.parts.Count];
						wsdlMethodInfo.outputNamesNs = new string[wsdlMessage2.parts.Count];
						wsdlMethodInfo.outputElements = new string[wsdlMessage2.parts.Count];
						wsdlMethodInfo.outputElementsNs = new string[wsdlMessage2.parts.Count];
						wsdlMethodInfo.outputTypes = new string[wsdlMessage2.parts.Count];
						wsdlMethodInfo.outputTypesNs = new string[wsdlMessage2.parts.Count];
						for (int k = 0; k < wsdlMessage2.parts.Count; k++)
						{
							wsdlMethodInfo.outputNames[k] = ((WsdlMessagePart)wsdlMessage2.parts[k]).name;
							wsdlMethodInfo.outputNamesNs[k] = ((WsdlMessagePart)wsdlMessage2.parts[k]).nameNs;
							AddNewNamespace(wsdlMethodInfo.outputNamesNs[k]);
							wsdlMethodInfo.outputElements[k] = ((WsdlMessagePart)wsdlMessage2.parts[k]).element;
							wsdlMethodInfo.outputElementsNs[k] = ((WsdlMessagePart)wsdlMessage2.parts[k]).elementNs;
							AddNewNamespace(wsdlMethodInfo.outputElementsNs[k]);
							wsdlMethodInfo.outputTypes[k] = ((WsdlMessagePart)wsdlMessage2.parts[k]).typeName;
							wsdlMethodInfo.outputTypesNs[k] = ((WsdlMessagePart)wsdlMessage2.parts[k]).typeNameNs;
							AddNewNamespace(wsdlMethodInfo.outputTypesNs[k]);
							if (wsdlMethodInfo.bProperty && wsdlMethodInfo.outputTypes[k] != null && wsdlMethodInfo.propertyType == null)
							{
								wsdlMethodInfo.propertyType = wsdlMethodInfo.outputTypes[k];
								wsdlMethodInfo.propertyNs = wsdlMethodInfo.outputTypesNs[k];
								AddNewNamespace(wsdlMethodInfo.outputTypesNs[k]);
							}
						}
						continue;
					}
					throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlInvalidPortType"), content.element));
				}
			}
			return arrayList;
		}

		private void ParseSchema()
		{
			int depth = _XMLReader.Depth;
			URTNamespace parsingNamespace = ParseNamespace();
			while (_XMLReader.Depth > depth)
			{
				string localName = _XMLReader.LocalName;
				if (MatchingStrings(localName, s_complexTypeString))
				{
					ParseComplexType(parsingNamespace, null);
				}
				else if (MatchingStrings(localName, s_simpleTypeString))
				{
					ParseSimpleType(parsingNamespace, null);
				}
				else if (MatchingStrings(localName, s_schemaString))
				{
					ParseSchema();
				}
				else if (MatchingStrings(localName, s_elementString))
				{
					ParseElementDecl(parsingNamespace);
				}
				else if (MatchingStrings(localName, s_importString))
				{
					ParseSchemaImportElement();
				}
				else if (MatchingStrings(localName, s_includeString))
				{
					ParseSchemaIncludeElement();
				}
				else
				{
					SkipXmlElement();
				}
			}
		}

		private void Resolve()
		{
			for (int i = 0; i < _URTNamespaces.Count; i++)
			{
				((URTNamespace)_URTNamespaces[i]).ResolveElements(this);
			}
			for (int j = 0; j < _URTNamespaces.Count; j++)
			{
				((URTNamespace)_URTNamespaces[j]).ResolveTypes(this);
			}
			for (int k = 0; k < _URTNamespaces.Count; k++)
			{
				((URTNamespace)_URTNamespaces[k]).ResolveMethods();
			}
		}

		private string LookupAttribute(string attrName, string attrNS, bool throwExp)
		{
			string result = s_emptyString;
			bool flag = ((attrNS == null) ? _XMLReader.MoveToAttribute(attrName) : _XMLReader.MoveToAttribute(attrName, attrNS));
			if (flag)
			{
				result = Atomize(_XMLReader.Value.Trim());
			}
			_XMLReader.MoveToElement();
			if (!flag && throwExp)
			{
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_AttributeNotFound"), attrName, XMLReader.LineNumber, XMLReader.LinePosition, XMLReader.Name));
			}
			return result;
		}

		private void ResolveTypeAttribute(ref string typeName, out string typeNS, out bool bEmbedded, out bool bPrimitive)
		{
			if (MatchingStrings(typeName, s_emptyString))
			{
				typeName = s_objectString;
				typeNS = SchemaNamespaceString;
				bEmbedded = true;
				bPrimitive = false;
			}
			else
			{
				typeNS = ParseQName(ref typeName);
				ResolveTypeNames(ref typeNS, ref typeName, out bEmbedded, out bPrimitive);
			}
		}

		private string ParseQName(ref string qname)
		{
			return ParseQName(ref qname, null);
		}

		private string ParseQName(ref string qname, URTNamespace defaultNS)
		{
			URTNamespace returnNS = null;
			return ParseQName(ref qname, defaultNS, out returnNS);
		}

		private string ParseQName(ref string qname, URTNamespace defaultNS, out URTNamespace returnNS)
		{
			string text = null;
			returnNS = null;
			if (qname == null || qname.Length == 0)
			{
				return null;
			}
			int num = qname.IndexOf(":");
			if (num == -1)
			{
				returnNS = defaultNS;
				text = ((defaultNS != null) ? defaultNS.Name : _XMLReader.LookupNamespace(""));
			}
			else
			{
				string prefix = qname.Substring(0, num);
				qname = Atomize(qname.Substring(num + 1));
				text = _XMLReader.LookupNamespace(prefix);
			}
			text = Atomize(text);
			URTNamespace uRTNamespace = LookupNamespace(text);
			if (uRTNamespace == null)
			{
				uRTNamespace = new URTNamespace(text, this);
			}
			returnNS = uRTNamespace;
			return text;
		}

		private bool Qualify(string typeNS, string curNS)
		{
			if (MatchingSchemaStrings(typeNS) || MatchingStrings(typeNS, s_soapNamespaceString) || MatchingStrings(typeNS, s_wsdlSoapNamespaceString) || MatchingStrings(typeNS, "System") || MatchingStrings(typeNS, curNS))
			{
				return false;
			}
			return true;
		}

		private bool MatchingNamespace(string elmNS)
		{
			if (MatchingStrings(_XMLReader.NamespaceURI, elmNS))
			{
				return true;
			}
			return false;
		}

		private bool MatchingSchemaNamespace()
		{
			if (MatchingNamespace(s_schemaNamespaceString))
			{
				return true;
			}
			if (MatchingNamespace(s_schemaNamespaceString1999))
			{
				_xsdVersion = XsdVersion.V1999;
				return true;
			}
			if (MatchingNamespace(s_schemaNamespaceString2000))
			{
				_xsdVersion = XsdVersion.V2000;
				return true;
			}
			if (MatchingNamespace(s_schemaNamespaceString))
			{
				_xsdVersion = XsdVersion.V2001;
				return true;
			}
			return false;
		}

		internal static string IsValidUrl(string value)
		{
			if (value == null)
			{
				return "\"\"";
			}
			vsb.Length = 0;
			vsb.Append("@\"");
			for (int i = 0; i < value.Length; i++)
			{
				if (value[i] == '"')
				{
					vsb.Append("\"\"");
				}
				else
				{
					vsb.Append(value[i]);
				}
			}
			vsb.Append("\"");
			return vsb.ToString();
		}

		private static bool IsCSharpKeyword(string value)
		{
			if (cSharpKeywords == null)
			{
				InitKeywords();
			}
			return cSharpKeywords.ContainsKey(value);
		}

		private static void InitKeywords()
		{
			Hashtable hashtable = new Hashtable(75);
			object obj76 = (hashtable["while"] = (hashtable["void"] = (hashtable["virtual"] = (hashtable["using"] = (hashtable["ushort"] = (hashtable["unsafe"] = (hashtable["unchecked"] = (hashtable["ulong"] = (hashtable["uint"] = (hashtable["typeof"] = (hashtable["try"] = (hashtable["true"] = (hashtable["throw"] = (hashtable["this"] = (hashtable["switch"] = (hashtable["struct"] = (hashtable["string"] = (hashtable["static"] = (hashtable["sizeof"] = (hashtable["short"] = (hashtable["sealed"] = (hashtable["sbyte"] = (hashtable["return"] = (hashtable["ref"] = (hashtable["readonly"] = (hashtable["public"] = (hashtable["protected"] = (hashtable["private"] = (hashtable["override"] = (hashtable["out"] = (hashtable["operator"] = (hashtable["object"] = (hashtable["null"] = (hashtable["new"] = (hashtable["namespace"] = (hashtable["long"] = (hashtable["lock"] = (hashtable["is"] = (hashtable["internal"] = (hashtable["interface"] = (hashtable["int"] = (hashtable["in"] = (hashtable["implicit"] = (hashtable["if"] = (hashtable["goto"] = (hashtable["foreach"] = (hashtable["for"] = (hashtable["float"] = (hashtable["fixed"] = (hashtable["finally"] = (hashtable["false"] = (hashtable["extern"] = (hashtable["explicit"] = (hashtable["exfloat"] = (hashtable["exdouble"] = (hashtable["event"] = (hashtable["enum"] = (hashtable["else"] = (hashtable["double"] = (hashtable["do"] = (hashtable["delegate"] = (hashtable["default"] = (hashtable["decimal"] = (hashtable["continue"] = (hashtable["const"] = (hashtable["class"] = (hashtable["checked"] = (hashtable["char"] = (hashtable["catch"] = (hashtable["case"] = (hashtable["byte"] = (hashtable["break"] = (hashtable["bool"] = (hashtable["base"] = (hashtable["abstract"] = new object())))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))));
			cSharpKeywords = hashtable;
		}

		private static bool IsValidLanguageIndependentIdentifier(string ident)
		{
			foreach (char c in ident)
			{
				switch (char.GetUnicodeCategory(c))
				{
				case UnicodeCategory.EnclosingMark:
				case UnicodeCategory.LetterNumber:
				case UnicodeCategory.OtherNumber:
				case UnicodeCategory.SpaceSeparator:
				case UnicodeCategory.LineSeparator:
				case UnicodeCategory.ParagraphSeparator:
				case UnicodeCategory.Control:
				case UnicodeCategory.Format:
				case UnicodeCategory.Surrogate:
				case UnicodeCategory.PrivateUse:
				case UnicodeCategory.DashPunctuation:
				case UnicodeCategory.OpenPunctuation:
				case UnicodeCategory.ClosePunctuation:
				case UnicodeCategory.InitialQuotePunctuation:
				case UnicodeCategory.FinalQuotePunctuation:
				case UnicodeCategory.OtherPunctuation:
				case UnicodeCategory.MathSymbol:
				case UnicodeCategory.CurrencySymbol:
				case UnicodeCategory.ModifierSymbol:
				case UnicodeCategory.OtherSymbol:
				case UnicodeCategory.OtherNotAssigned:
					return false;
				default:
					return false;
				case UnicodeCategory.UppercaseLetter:
				case UnicodeCategory.LowercaseLetter:
				case UnicodeCategory.TitlecaseLetter:
				case UnicodeCategory.ModifierLetter:
				case UnicodeCategory.OtherLetter:
				case UnicodeCategory.NonSpacingMark:
				case UnicodeCategory.SpacingCombiningMark:
				case UnicodeCategory.DecimalDigitNumber:
				case UnicodeCategory.ConnectorPunctuation:
					break;
				}
			}
			return true;
		}

		internal static void CheckValidIdentifier(string ident)
		{
			if (!IsValidLanguageIndependentIdentifier(ident))
			{
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlInvalidStringSyntax"), ident));
			}
		}

		internal static string IsValidCSAttr(string identifier)
		{
			string text = IsValidCS(identifier);
			if (text.Length > 0 && text[0] == '@')
			{
				return text.Substring(1);
			}
			return text;
		}

		internal static string IsValidCS(string identifier)
		{
			if (identifier == null || identifier.Length == 0 || identifier == " ")
			{
				return identifier;
			}
			string result = identifier;
			int num = identifier.IndexOf('[');
			string text = null;
			if (num > -1)
			{
				text = identifier.Substring(num);
				identifier = identifier.Substring(0, num);
				for (int i = 0; i < text.Length; i++)
				{
					switch (text[i])
					{
					case ' ':
					case ',':
					case '[':
					case ']':
						continue;
					}
					throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_WsdlInvalidStringSyntax"), identifier));
				}
			}
			string[] array = identifier.Split('.');
			bool flag = false;
			StringBuilder stringBuilder = new StringBuilder();
			for (int j = 0; j < array.Length; j++)
			{
				if (j > 0)
				{
					stringBuilder.Append(".");
				}
				if (IsCSharpKeyword(array[j]))
				{
					stringBuilder.Append("@");
					flag = true;
				}
				CheckValidIdentifier(array[j]);
				stringBuilder.Append(array[j]);
			}
			if (flag)
			{
				if (text != null)
				{
					stringBuilder.Append(text);
				}
				return stringBuilder.ToString();
			}
			return result;
		}

		private static bool MatchingStrings(string left, string right)
		{
			return (object)left == right;
		}

		private bool MatchingSchemaStrings(string left)
		{
			if (MatchingStrings(left, s_schemaNamespaceString1999))
			{
				_xsdVersion = XsdVersion.V1999;
				return true;
			}
			if (MatchingStrings(left, s_schemaNamespaceString2000))
			{
				_xsdVersion = XsdVersion.V2000;
				return true;
			}
			if (MatchingStrings(left, s_schemaNamespaceString))
			{
				_xsdVersion = XsdVersion.V2001;
				return true;
			}
			return false;
		}

		internal string Atomize(string str)
		{
			return _XMLReader.NameTable.Add(str);
		}

		private string MapSchemaTypesToCSharpTypes(string xsdType)
		{
			string xsdType2 = xsdType;
			int num = xsdType.IndexOf('[');
			if (num != -1)
			{
				xsdType2 = xsdType.Substring(0, num);
			}
			string text = SudsConverter.MapXsdToClrTypes(xsdType2);
			if (text == null)
			{
				throw new SUDSParserException(string.Format(CultureInfo.CurrentCulture, CoreChannel.GetResourceString("Remoting_Suds_CantResolveTypeInNS"), xsdType, s_schemaNamespaceString));
			}
			if (num != -1)
			{
				text += xsdType.Substring(num);
			}
			return text;
		}

		private bool IsPrimitiveType(string typeNS, string typeName)
		{
			bool result = false;
			if (MatchingSchemaStrings(typeNS) && !MatchingStrings(typeName, s_urTypeString))
			{
				result = true;
			}
			return result;
		}

		private URTNamespace LookupNamespace(string name)
		{
			for (int i = 0; i < _URTNamespaces.Count; i++)
			{
				URTNamespace uRTNamespace = (URTNamespace)_URTNamespaces[i];
				if (MatchingStrings(uRTNamespace.Name, name))
				{
					return uRTNamespace;
				}
			}
			return null;
		}

		internal URTNamespace AddNewNamespace(string ns)
		{
			if (ns == null)
			{
				return null;
			}
			URTNamespace uRTNamespace = LookupNamespace(ns);
			if (uRTNamespace == null)
			{
				uRTNamespace = new URTNamespace(ns, this);
			}
			if (!uRTNamespace.IsSystem)
			{
				uRTNamespace.bReferenced = true;
			}
			return uRTNamespace;
		}

		internal void AddNamespace(URTNamespace xns)
		{
			_URTNamespaces.Add(xns);
		}

		private void PrintCSC()
		{
			int num = 0;
			for (int i = 0; i < _URTNamespaces.Count; i++)
			{
				URTNamespace uRTNamespace = (URTNamespace)_URTNamespaces[i];
				if (!uRTNamespace.IsEmpty && uRTNamespace.UrtType == UrtType.Interop)
				{
					if (num == 0)
					{
						uRTNamespace.EncodedNS = _proxyNamespace;
					}
					else
					{
						uRTNamespace.EncodedNS = _proxyNamespace + num;
					}
					num++;
				}
			}
			for (int j = 0; j < _URTNamespaces.Count; j++)
			{
				URTNamespace uRTNamespace2 = (URTNamespace)_URTNamespaces[j];
				if (!uRTNamespace2.IsEmpty && uRTNamespace2.UrtType != UrtType.UrtSystem && uRTNamespace2.UrtType != UrtType.Xsd && uRTNamespace2.UrtType != 0)
				{
					string text = (uRTNamespace2.IsURTNamespace ? uRTNamespace2.AssemName : uRTNamespace2.EncodedNS);
					int num2 = text.IndexOf(',');
					if (num2 > -1)
					{
						text = text.Substring(0, num2);
					}
					string completeFileName = "";
					WriterStream writerStream = WriterStream.GetWriterStream(ref _writerStreams, _outputDir, text, ref completeFileName);
					if (completeFileName.Length > 0)
					{
						_outCodeStreamList.Add(completeFileName);
					}
					uRTNamespace2.PrintCSC(writerStream);
				}
			}
		}

		internal UrtType IsURTExportedType(string name, out string ns, out string assemName)
		{
			UrtType urtType = UrtType.None;
			ns = null;
			assemName = null;
			if (MatchingSchemaStrings(name))
			{
				urtType = UrtType.Xsd;
			}
			else
			{
				if (SoapServices.IsClrTypeNamespace(name))
				{
					SoapServices.DecodeXmlNamespaceForClrTypeNamespace(name, out ns, out assemName);
					if (assemName == null)
					{
						assemName = typeof(string).Assembly.GetName().Name;
						urtType = UrtType.UrtSystem;
					}
					else
					{
						urtType = UrtType.UrtUser;
					}
				}
				if (urtType == UrtType.None)
				{
					ns = name;
					assemName = ns;
					urtType = UrtType.Interop;
				}
				ns = Atomize(ns);
				assemName = Atomize(assemName);
			}
			return urtType;
		}

		internal string GetTypeString(string curNS, bool bNS, URTNamespace urtNS, string typeName, string typeNS)
		{
			URTComplexType uRTComplexType = urtNS.LookupComplexType(typeName);
			string text;
			if (uRTComplexType != null && uRTComplexType.IsArray())
			{
				if (uRTComplexType.GetArray() == null)
				{
					uRTComplexType.ResolveArray();
				}
				string array = uRTComplexType.GetArray();
				URTNamespace arrayNS = uRTComplexType.GetArrayNS();
				StringBuilder stringBuilder = new StringBuilder(50);
				if (arrayNS.EncodedNS != null && Qualify(urtNS.EncodedNS, arrayNS.EncodedNS))
				{
					stringBuilder.Append(IsValidCSAttr(arrayNS.EncodedNS));
					stringBuilder.Append('.');
				}
				stringBuilder.Append(IsValidCSAttr(array));
				text = stringBuilder.ToString();
			}
			else
			{
				string text2 = null;
				text2 = ((urtNS.UrtType != UrtType.Interop) ? typeNS : urtNS.EncodedNS);
				if (bNS && Qualify(text2, curNS))
				{
					StringBuilder stringBuilder2 = new StringBuilder(50);
					if (text2 != null)
					{
						stringBuilder2.Append(IsValidCSAttr(text2));
						stringBuilder2.Append('.');
					}
					stringBuilder2.Append(IsValidCSAttr(typeName));
					text = stringBuilder2.ToString();
				}
				else
				{
					text = typeName;
				}
			}
			int num = text.IndexOf('+');
			if (num > 0)
			{
				text = ((!bNS) ? text.Substring(0, num) : text.Replace('+', '.'));
			}
			return text;
		}

		private static XmlNameTable CreatePrimedNametable()
		{
			NameTable nameTable = new NameTable();
			s_emptyString = nameTable.Add(string.Empty);
			s_complexTypeString = nameTable.Add("complexType");
			s_simpleTypeString = nameTable.Add("simpleType");
			s_elementString = nameTable.Add("element");
			s_enumerationString = nameTable.Add("enumeration");
			s_encodingString = nameTable.Add("encoding");
			s_attributeString = nameTable.Add("attribute");
			s_attributesString = nameTable.Add("attributes");
			s_allString = nameTable.Add("all");
			s_sequenceString = nameTable.Add("sequence");
			s_choiceString = nameTable.Add("choice");
			s_minOccursString = nameTable.Add("minOccurs");
			s_maxOccursString = nameTable.Add("maxOccurs");
			s_unboundedString = nameTable.Add("unbounded");
			s_oneString = nameTable.Add("1");
			s_zeroString = nameTable.Add("0");
			s_nameString = nameTable.Add("name");
			s_typeString = nameTable.Add("type");
			s_baseString = nameTable.Add("base");
			s_valueString = nameTable.Add("value");
			s_interfaceString = nameTable.Add("interface");
			s_serviceString = nameTable.Add("service");
			s_extendsString = nameTable.Add("extends");
			s_addressesString = nameTable.Add("addresses");
			s_addressString = nameTable.Add("address");
			s_uriString = nameTable.Add("uri");
			s_implementsString = nameTable.Add("implements");
			s_nestedTypeString = nameTable.Add("nestedType");
			s_requestString = nameTable.Add("request");
			s_responseString = nameTable.Add("response");
			s_requestResponseString = nameTable.Add("requestResponse");
			s_messageString = nameTable.Add("message");
			s_locationString = nameTable.Add("location");
			s_schemaLocationString = nameTable.Add("schemaLocation");
			s_importString = nameTable.Add("import");
			s_onewayString = nameTable.Add("oneway");
			s_includeString = nameTable.Add("include");
			s_refString = nameTable.Add("ref");
			s_refTypeString = nameTable.Add("refType");
			s_referenceString = nameTable.Add("Reference");
			s_objectString = nameTable.Add("Object");
			s_urTypeString = nameTable.Add("anyType");
			s_arrayString = nameTable.Add("Array");
			s_sudsString = nameTable.Add("suds");
			s_methodString = nameTable.Add("method");
			s_useString = nameTable.Add("use");
			s_rootTypeString = nameTable.Add("rootType");
			s_soapString = nameTable.Add("soap");
			s_serviceDescString = nameTable.Add("serviceDescription");
			s_schemaString = nameTable.Add("schema");
			s_targetNamespaceString = nameTable.Add("targetNamespace");
			s_namespaceString = nameTable.Add("namespace");
			s_idString = nameTable.Add("ID");
			s_soapActionString = nameTable.Add("soapAction");
			s_schemaNamespaceString1999 = nameTable.Add(SudsConverter.Xsd1999);
			s_instanceNamespaceString1999 = nameTable.Add(SudsConverter.Xsi1999);
			s_schemaNamespaceString2000 = nameTable.Add(SudsConverter.Xsd2000);
			s_instanceNamespaceString2000 = nameTable.Add(SudsConverter.Xsi2000);
			s_schemaNamespaceString = nameTable.Add(SudsConverter.Xsd2001);
			s_instanceNamespaceString = nameTable.Add(SudsConverter.Xsi2001);
			s_soapNamespaceString = nameTable.Add("urn:schemas-xmlsoap-org:soap.v1");
			s_sudsNamespaceString = nameTable.Add("urn:schemas-xmlsoap-org:soap-sdl-2000-01-25");
			s_serviceNamespaceString = nameTable.Add("urn:schemas-xmlsoap-org:sdl.2000-01-25");
			s_definitionsString = nameTable.Add("definitions");
			s_wsdlNamespaceString = nameTable.Add("http://schemas.xmlsoap.org/wsdl/");
			s_wsdlSoapNamespaceString = nameTable.Add("http://schemas.xmlsoap.org/wsdl/soap/");
			s_wsdlSudsNamespaceString = nameTable.Add("http://www.w3.org/2000/wsdl/suds");
			s_enumTypeString = nameTable.Add("enumType");
			s_typesString = nameTable.Add("types");
			s_partString = nameTable.Add("part");
			s_portTypeString = nameTable.Add("portType");
			s_operationString = nameTable.Add("operation");
			s_inputString = nameTable.Add("input");
			s_outputString = nameTable.Add("output");
			s_bindingString = nameTable.Add("binding");
			s_classString = nameTable.Add("class");
			s_structString = nameTable.Add("struct");
			s_ISerializableString = nameTable.Add("ISerializable");
			s_marshalByRefString = nameTable.Add("MarshalByRefObject");
			s_delegateString = nameTable.Add("Delegate");
			s_servicedComponentString = nameTable.Add("ServicedComponent");
			s_comObjectString = nameTable.Add("__ComObject");
			s_portString = nameTable.Add("port");
			s_styleString = nameTable.Add("style");
			s_transportString = nameTable.Add("transport");
			s_encodedString = nameTable.Add("encoded");
			s_faultString = nameTable.Add("fault");
			s_bodyString = nameTable.Add("body");
			s_partsString = nameTable.Add("parts");
			s_headerString = nameTable.Add("header");
			s_encodingStyleString = nameTable.Add("encodingStyle");
			s_restrictionString = nameTable.Add("restriction");
			s_complexContentString = nameTable.Add("complexContent");
			s_soapEncodingString = nameTable.Add("http://schemas.xmlsoap.org/soap/encoding/");
			s_arrayTypeString = nameTable.Add("arrayType");
			s_parameterOrderString = nameTable.Add("parameterOrder");
			return nameTable;
		}
	}
	internal class WsdlGenerator
	{
		private interface IAbstractElement
		{
			void Print(TextWriter textWriter, StringBuilder sb, string indent);
		}

		private class EnumElement : IAbstractElement
		{
			private string _value;

			internal EnumElement(string value)
			{
				_value = value;
			}

			public void Print(TextWriter textWriter, StringBuilder sb, string indent)
			{
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("<enumeration value='");
				sb.Append(_value);
				sb.Append("'/>");
				textWriter.WriteLine(sb);
			}
		}

		private abstract class Particle : IAbstractElement
		{
			public abstract string Name();

			public abstract void Print(TextWriter textWriter, StringBuilder sb, string indent);
		}

		private class Restriction : Particle
		{
			internal enum RestrictionType
			{
				None,
				Array,
				Enum
			}

			private string _baseName;

			private XMLNamespace _baseNS;

			internal RestrictionType _rtype;

			private SchemaAttribute _attribute;

			internal ArrayList _abstractElms = new ArrayList();

			internal Restriction()
			{
			}

			internal Restriction(string baseName, XMLNamespace baseNS)
			{
				_baseName = baseName;
				_baseNS = baseNS;
			}

			internal void AddArray(SchemaAttribute attribute)
			{
				_rtype = RestrictionType.Array;
				_attribute = attribute;
			}

			public override string Name()
			{
				return _baseName;
			}

			public override void Print(TextWriter textWriter, StringBuilder sb, string indent)
			{
				string indentStr = IndentP(indent);
				sb.Length = 0;
				sb.Append(indent);
				if (_rtype == RestrictionType.Array)
				{
					sb.Append("<restriction base='soapenc:Array'>");
				}
				else if (_rtype == RestrictionType.Enum)
				{
					sb.Append("<restriction base='xsd:string'>");
				}
				else
				{
					sb.Append("<restriction base='");
					sb.Append(_baseNS.Prefix);
					sb.Append(':');
					sb.Append(_baseName);
					sb.Append("'>");
				}
				textWriter.WriteLine(sb);
				foreach (IAbstractElement abstractElm in _abstractElms)
				{
					abstractElm.Print(textWriter, sb, IndentP(indentStr));
				}
				if (_attribute != null)
				{
					_attribute.Print(textWriter, sb, IndentP(indentStr));
				}
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("</restriction>");
				textWriter.WriteLine(sb);
			}
		}

		private class SchemaAttribute : IAbstractElement
		{
			private string _wireQname;

			internal SchemaAttribute()
			{
			}

			internal void AddArray(string wireQname)
			{
				_wireQname = wireQname;
			}

			public void Print(TextWriter textWriter, StringBuilder sb, string indent)
			{
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("<attribute ref='soapenc:arrayType'");
				sb.Append(" wsdl:arrayType ='");
				sb.Append(_wireQname);
				sb.Append("'/>");
				textWriter.WriteLine(sb);
			}
		}

		private class SchemaElement : Particle
		{
			private string _name;

			private string _typeString;

			private SchemaType _schemaType;

			internal SchemaElement(string name, Type type, bool bEmbedded, XMLNamespace xns)
			{
				_name = name;
				_typeString = null;
				_schemaType = SimpleSchemaType.GetSimpleSchemaType(type, xns, fInline: true);
				_typeString = RealSchemaType.TypeName(type, bEmbedded, xns);
			}

			public override string Name()
			{
				return _name;
			}

			public override void Print(TextWriter textWriter, StringBuilder sb, string indent)
			{
				string indentStr = IndentP(indent);
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("<element name='");
				sb.Append(_name);
				if (_schemaType != null && (!(_schemaType is SimpleSchemaType) || !((SimpleSchemaType)_schemaType).Type.IsEnum))
				{
					sb.Append("'>");
					textWriter.WriteLine(sb);
					_schemaType.PrintSchemaType(textWriter, sb, IndentP(indentStr), bAnonymous: true);
					sb.Length = 0;
					sb.Append(indent);
					sb.Append("</element>");
				}
				else
				{
					if (_typeString != null)
					{
						sb.Append("' type='");
						sb.Append(_typeString);
						sb.Append('\'');
					}
					sb.Append("/>");
				}
				textWriter.WriteLine(sb);
			}
		}

		private abstract class SchemaType
		{
			internal abstract void PrintSchemaType(TextWriter textWriter, StringBuilder sb, string indent, bool bAnonymous);
		}

		private class SimpleSchemaType : SchemaType
		{
			private Type _type;

			internal string _baseName;

			private XMLNamespace _xns;

			internal Restriction _restriction;

			private string _fullRefName;

			private ArrayList _abstractElms = new ArrayList();

			internal Type Type => _type;

			internal string FullRefName => _fullRefName;

			internal string BaseName => _baseName;

			private SimpleSchemaType(Type type, XMLNamespace xns)
			{
				_type = type;
				_xns = xns;
				_abstractElms = new ArrayList();
				_fullRefName = RefName(type);
			}

			internal override void PrintSchemaType(TextWriter textWriter, StringBuilder sb, string indent, bool bAnonymous)
			{
				sb.Length = 0;
				sb.Append(indent);
				if (!bAnonymous)
				{
					sb.Append("<simpleType name='");
					sb.Append(FullRefName);
					sb.Append("'");
					if (BaseName != null)
					{
						sb.Append(" base='");
						sb.Append(BaseName);
						sb.Append("'");
					}
					if (_restriction._rtype == Restriction.RestrictionType.Enum)
					{
						sb.Append(" suds:enumType='");
						sb.Append(_restriction.Name());
						sb.Append("'");
					}
				}
				else if (BaseName != null)
				{
					sb.Append("<simpleType base='");
					sb.Append(BaseName);
					sb.Append("'");
				}
				else
				{
					sb.Append("<simpleType");
				}
				bool flag = _abstractElms.Count == 0 && _restriction == null;
				if (flag)
				{
					sb.Append("/>");
				}
				else
				{
					sb.Append(">");
				}
				textWriter.WriteLine(sb);
				if (flag)
				{
					return;
				}
				if (_abstractElms.Count > 0)
				{
					for (int i = 0; i < _abstractElms.Count; i++)
					{
						((IAbstractElement)_abstractElms[i]).Print(textWriter, sb, IndentP(indent));
					}
				}
				if (_restriction != null)
				{
					_restriction.Print(textWriter, sb, IndentP(indent));
				}
				textWriter.Write(indent);
				textWriter.WriteLine("</simpleType>");
			}

			internal static SimpleSchemaType GetSimpleSchemaType(Type type, XMLNamespace xns, bool fInline)
			{
				SimpleSchemaType simpleSchemaType = null;
				if (type.IsEnum)
				{
					simpleSchemaType = new SimpleSchemaType(type, xns);
					string baseName = RealSchemaType.TypeName(Enum.GetUnderlyingType(type), bEmbedded: true, xns);
					simpleSchemaType._restriction = new Restriction(baseName, xns);
					string[] names = Enum.GetNames(type);
					for (int i = 0; i < names.Length; i++)
					{
						simpleSchemaType._restriction._abstractElms.Add(new EnumElement(names[i]));
					}
					simpleSchemaType._restriction._rtype = Restriction.RestrictionType.Enum;
				}
				return simpleSchemaType;
			}
		}

		private abstract class ComplexSchemaType : SchemaType
		{
			private string _name;

			private Type _type;

			private string _fullRefName;

			private string _baseName;

			private string _elementName;

			private bool _bSealed;

			private SchemaBlockType _blockType;

			private ArrayList _particles;

			private ArrayList _abstractElms;

			private static string[] schemaBlockBegin = new string[4] { "<all>", "<sequence>", "<choice>", "<complexContent>" };

			private static string[] schemaBlockEnd = new string[4] { "</all>", "</sequence>", "</choice>", "</complexContent>" };

			internal string Name => _name;

			internal string FullRefName => _fullRefName;

			protected string BaseName
			{
				get
				{
					return _baseName;
				}
				set
				{
					_baseName = value;
				}
			}

			internal string ElementName
			{
				get
				{
					return _elementName;
				}
				set
				{
					_elementName = value;
				}
			}

			protected bool IsSealed => _bSealed;

			protected bool IsEmpty
			{
				get
				{
					if (_abstractElms.Count == 0)
					{
						return _particles.Count == 0;
					}
					return false;
				}
			}

			internal ComplexSchemaType(string name, bool bSealed)
			{
				_name = name;
				_fullRefName = _name;
				_blockType = SchemaBlockType.ALL;
				_baseName = null;
				_elementName = name;
				_bSealed = bSealed;
				_particles = new ArrayList();
				_abstractElms = new ArrayList();
			}

			internal ComplexSchemaType(string name, SchemaBlockType blockType, bool bSealed)
			{
				_name = name;
				_fullRefName = _name;
				_blockType = blockType;
				_baseName = null;
				_elementName = name;
				_bSealed = bSealed;
				_particles = new ArrayList();
				_abstractElms = new ArrayList();
			}

			internal ComplexSchemaType(Type type)
			{
				_blockType = SchemaBlockType.ALL;
				_type = type;
				Init();
			}

			private void Init()
			{
				_name = _type.Name;
				_bSealed = _type.IsSealed;
				_baseName = null;
				_elementName = _name;
				_particles = new ArrayList();
				_abstractElms = new ArrayList();
				_fullRefName = RefName(_type);
			}

			internal void AddParticle(Particle particle)
			{
				_particles.Add(particle);
			}

			protected void PrintBody(TextWriter textWriter, StringBuilder sb, string indent)
			{
				int count = _particles.Count;
				string text = IndentP(indent);
				string indentStr = IndentP(text);
				if (count > 0)
				{
					bool flag = blockDefault != _blockType;
					if (flag)
					{
						sb.Length = 0;
						sb.Append(text);
						sb.Append(schemaBlockBegin[(int)_blockType]);
						textWriter.WriteLine(sb);
					}
					for (int i = 0; i < count; i++)
					{
						((Particle)_particles[i]).Print(textWriter, sb, IndentP(indentStr));
					}
					if (flag)
					{
						sb.Length = 0;
						sb.Append(text);
						sb.Append(schemaBlockEnd[(int)_blockType]);
						textWriter.WriteLine(sb);
					}
				}
				int count2 = _abstractElms.Count;
				for (int j = 0; j < count2; j++)
				{
					((IAbstractElement)_abstractElms[j]).Print(textWriter, sb, IndentP(indent));
				}
			}
		}

		private class PhonySchemaType : ComplexSchemaType
		{
			private int _numOverloadedTypes;

			internal ArrayList _inParamTypes;

			internal ArrayList _inParamNames;

			internal ArrayList _outParamTypes;

			internal ArrayList _outParamNames;

			internal ArrayList _paramNamesOrder;

			internal string _returnType;

			internal string _returnName;

			internal PhonySchemaType(string name)
				: base(name, bSealed: true)
			{
				_numOverloadedTypes = 0;
			}

			internal int OverloadedType()
			{
				return ++_numOverloadedTypes;
			}

			internal override void PrintSchemaType(TextWriter textWriter, StringBuilder sb, string indent, bool bAnonymous)
			{
			}
		}

		private class ArraySchemaType : ComplexSchemaType
		{
			private Type _type;

			internal Type Type => _type;

			internal ArraySchemaType(Type type, string name, SchemaBlockType blockType, bool bSealed)
				: base(name, blockType, bSealed)
			{
				_type = type;
			}

			internal override void PrintSchemaType(TextWriter textWriter, StringBuilder sb, string indent, bool bAnonymous)
			{
				string indent2 = IndentP(indent);
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("<complexType name='");
				sb.Append(base.FullRefName);
				sb.Append("'>");
				textWriter.WriteLine(sb);
				PrintBody(textWriter, sb, indent2);
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("</complexType>");
				textWriter.WriteLine(sb);
			}
		}

		private class RealSchemaType : ComplexSchemaType
		{
			private WsdlGenerator _WsdlGenerator;

			private Type _type;

			private string _serviceEndpoint;

			private Hashtable _typeToServiceEndpoint;

			private bool _bUnique;

			private XMLNamespace _xns;

			private bool _bStruct;

			private string[] _implIFaces;

			private Type[] _iFaces;

			private MethodInfo[] _methods;

			private string[] _methodAttributes;

			private string[] _methodTypes;

			private FieldInfo[] _fields;

			private PhonySchemaType[] _phony;

			internal Type[] _nestedTypes;

			private static Type[] emptyTypeSet = new Type[0];

			private static MethodInfo[] emptyMethodSet = new MethodInfo[0];

			private static FieldInfo[] emptyFieldSet = new FieldInfo[0];

			internal Type Type => _type;

			internal XMLNamespace XNS => _xns;

			internal bool IsUnique => _bUnique;

			internal bool IsSUDSType
			{
				get
				{
					if ((_iFaces == null || _iFaces.Length <= 0) && (_methods == null || _methods.Length <= 0) && (_type == null || !_type.IsInterface))
					{
						if (s_delegateType != null)
						{
							return s_delegateType.IsAssignableFrom(_type);
						}
						return false;
					}
					return true;
				}
			}

			internal RealSchemaType(Type type, XMLNamespace xns, string serviceEndpoint, Hashtable typeToServiceEndpoint, bool bUnique, WsdlGenerator WsdlGenerator)
				: base(type)
			{
				_type = type;
				_serviceEndpoint = serviceEndpoint;
				_typeToServiceEndpoint = typeToServiceEndpoint;
				_bUnique = bUnique;
				_WsdlGenerator = WsdlGenerator;
				_bStruct = type.IsValueType;
				_xns = xns;
				_implIFaces = null;
				_iFaces = null;
				_methods = null;
				_fields = null;
				_methodTypes = null;
				_nestedTypes = type.GetNestedTypes();
				if (_nestedTypes != null)
				{
					Type[] nestedTypes = _nestedTypes;
					foreach (Type type2 in nestedTypes)
					{
						_WsdlGenerator.AddType(type2, xns);
					}
				}
			}

			internal Type[] GetIntroducedInterfaces()
			{
				_iFaces = GetIntroducedInterfaces(_type);
				return _iFaces;
			}

			internal MethodInfo[] GetIntroducedMethods()
			{
				_methods = GetIntroducedMethods(_type, ref _methodAttributes);
				_methodTypes = new string[2 * _methods.Length];
				return _methods;
			}

			internal FieldInfo[] GetInstanceFields()
			{
				_fields = GetInstanceFields(_type);
				return _fields;
			}

			private bool IsNotSystemDefinedRoot(Type type, Type baseType)
			{
				if (!type.IsInterface && !type.IsValueType && baseType != null && baseType.BaseType != null && baseType != s_marshalByRefType && baseType != s_valueType && baseType != s_objectType && baseType != s_contextBoundType && baseType != s_remotingClientProxyType && baseType.FullName != "System.EnterpriseServices.ServicedComponent" && baseType.FullName != "System.__ComObject")
				{
					return true;
				}
				return false;
			}

			internal void Resolve(StringBuilder sb)
			{
				sb.Length = 0;
				bool isSUDSType = IsSUDSType;
				Type baseType = _type.BaseType;
				if (IsNotSystemDefinedRoot(_type, baseType))
				{
					XMLNamespace @namespace = _WsdlGenerator.GetNamespace(baseType);
					sb.Append(@namespace.Prefix);
					sb.Append(':');
					sb.Append(baseType.Name);
					base.BaseName = sb.ToString();
					if (isSUDSType)
					{
						_xns.DependsOnSUDSNS(@namespace);
					}
					Type type = _type;
					Type baseType2 = type.BaseType;
					while (baseType2 != null && IsNotSystemDefinedRoot(type, baseType2))
					{
						if (_typeToServiceEndpoint != null && !_typeToServiceEndpoint.ContainsKey(baseType2.Name) && _typeToServiceEndpoint.ContainsKey(type.Name))
						{
							_typeToServiceEndpoint[baseType2.Name] = _typeToServiceEndpoint[type.Name];
						}
						type = baseType2;
						baseType2 = type.BaseType;
					}
				}
				_xns.DependsOnSchemaNS(_xns, bImport: false);
				if (isSUDSType)
				{
					_xns.AddRealSUDSType(this);
					if (_iFaces.Length > 0)
					{
						_implIFaces = new string[_iFaces.Length];
						for (int i = 0; i < _iFaces.Length; i++)
						{
							GetNSAndAssembly(_iFaces[i], out var ns, out var assem);
							XMLNamespace xMLNamespace = _xns.LookupSchemaNamespace(ns, assem);
							sb.Length = 0;
							sb.Append(xMLNamespace.Prefix);
							sb.Append(':');
							sb.Append(_iFaces[i].Name);
							_implIFaces[i] = sb.ToString();
							_xns.DependsOnSUDSNS(xMLNamespace);
						}
					}
					if (_methods.Length > 0)
					{
						string text = null;
						if (_xns.IsInteropType)
						{
							text = _xns.Name;
						}
						else
						{
							sb.Length = 0;
							QualifyName(sb, _xns.Name, base.Name);
							text = sb.ToString();
						}
						XMLNamespace xMLNamespace2 = _xns.LookupSchemaNamespace(text, _xns.Assem);
						_xns.DependsOnSUDSNS(xMLNamespace2);
						_phony = new PhonySchemaType[_methods.Length];
						for (int j = 0; j < _methods.Length; j++)
						{
							MethodInfo methodInfo = _methods[j];
							string name = methodInfo.Name;
							ParameterInfo[] parameters = methodInfo.GetParameters();
							PhonySchemaType phonySchemaType = new PhonySchemaType(name);
							phonySchemaType._inParamTypes = new ArrayList(10);
							phonySchemaType._inParamNames = new ArrayList(10);
							phonySchemaType._outParamTypes = new ArrayList(10);
							phonySchemaType._outParamNames = new ArrayList(10);
							phonySchemaType._paramNamesOrder = new ArrayList(10);
							int num = 0;
							ParameterInfo[] array = parameters;
							foreach (ParameterInfo parameterInfo in array)
							{
								bool bMarshalIn = false;
								bool bMarshalOut = false;
								phonySchemaType._paramNamesOrder.Add(parameterInfo.Name);
								ParamInOut(parameterInfo, out bMarshalIn, out bMarshalOut);
								Type parameterType = parameterInfo.ParameterType;
								string text2 = parameterInfo.Name;
								if (text2 == null || text2.Length == 0)
								{
									text2 = "param" + num++;
								}
								string value = TypeName(parameterType, bEmbedded: true, xMLNamespace2);
								if (bMarshalIn)
								{
									phonySchemaType._inParamNames.Add(text2);
									phonySchemaType._inParamTypes.Add(value);
								}
								if (bMarshalOut)
								{
									phonySchemaType._outParamNames.Add(text2);
									phonySchemaType._outParamTypes.Add(value);
								}
							}
							xMLNamespace2.AddPhonySchemaType(phonySchemaType);
							_phony[j] = phonySchemaType;
							_methodTypes[2 * j] = phonySchemaType.ElementName;
							if (!RemotingServices.IsOneWay(methodInfo))
							{
								string text3 = null;
								SoapMethodAttribute soapMethodAttribute = (SoapMethodAttribute)InternalRemotingServices.GetCachedSoapAttribute(methodInfo);
								text3 = ((soapMethodAttribute.ReturnXmlElementName == null) ? "return" : soapMethodAttribute.ReturnXmlElementName);
								string text4 = null;
								text4 = ((soapMethodAttribute.ResponseXmlElementName == null) ? (name + "Response") : soapMethodAttribute.ResponseXmlElementName);
								PhonySchemaType phonySchemaType2 = new PhonySchemaType(text4);
								phonySchemaType._returnName = text3;
								Type returnType = methodInfo.ReturnType;
								if (returnType != null && returnType != typeof(void))
								{
									phonySchemaType._returnType = TypeName(returnType, bEmbedded: true, xMLNamespace2);
								}
								xMLNamespace2.AddPhonySchemaType(phonySchemaType2);
								_methodTypes[2 * j + 1] = phonySchemaType2.ElementName;
							}
						}
					}
				}
				if (_fields == null)
				{
					return;
				}
				for (int l = 0; l < _fields.Length; l++)
				{
					FieldInfo fieldInfo = _fields[l];
					Type type2 = fieldInfo.FieldType;
					if (type2 == null)
					{
						type2 = typeof(object);
					}
					AddParticle(new SchemaElement(fieldInfo.Name, type2, bEmbedded: false, _xns));
				}
			}

			private void ParamInOut(ParameterInfo param, out bool bMarshalIn, out bool bMarshalOut)
			{
				bool isIn = param.IsIn;
				bool isOut = param.IsOut;
				bool isByRef = param.ParameterType.IsByRef;
				bMarshalIn = false;
				bMarshalOut = false;
				if (isByRef)
				{
					if (isIn == isOut)
					{
						bMarshalIn = true;
						bMarshalOut = true;
					}
					else
					{
						bMarshalIn = isIn;
						bMarshalOut = isOut;
					}
				}
				else
				{
					bMarshalIn = true;
					bMarshalOut = isOut;
				}
			}

			internal override void PrintSchemaType(TextWriter textWriter, StringBuilder sb, string indent, bool bAnonymous)
			{
				if (!bAnonymous)
				{
					sb.Length = 0;
					sb.Append(indent);
					sb.Append("<element name='");
					sb.Append(base.ElementName);
					sb.Append("' type='");
					sb.Append(_xns.Prefix);
					sb.Append(':');
					sb.Append(base.FullRefName);
					sb.Append("'/>");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append(indent);
				if (!bAnonymous)
				{
					sb.Append("<complexType name='");
					sb.Append(base.FullRefName);
					sb.Append('\'');
				}
				else
				{
					sb.Append("<complexType ");
				}
				if (base.BaseName != null)
				{
					sb.Append(" base='");
					sb.Append(base.BaseName);
					sb.Append('\'');
				}
				if (base.IsSealed && !bAnonymous)
				{
					sb.Append(" final='#all'");
				}
				bool isEmpty = base.IsEmpty;
				if (isEmpty)
				{
					sb.Append("/>");
				}
				else
				{
					sb.Append('>');
				}
				textWriter.WriteLine(sb);
				if (!isEmpty)
				{
					PrintBody(textWriter, sb, indent);
					textWriter.Write(indent);
					textWriter.WriteLine("</complexType>");
				}
			}

			internal void PrintMessageWsdl(TextWriter textWriter, StringBuilder sb, string indent, ArrayList refNames)
			{
				string text = IndentP(indent);
				string text2 = IndentP(text);
				string value = IndentP(text2);
				string value2 = null;
				MethodInfo methodInfo = null;
				string text3 = null;
				string text4 = null;
				bool flag = false;
				string text5 = null;
				if (_xns.IsInteropType)
				{
					text5 = _xns.Name;
				}
				else
				{
					sb.Length = 0;
					QualifyName(sb, _xns.Name, base.Name);
					text5 = sb.ToString();
				}
				XMLNamespace xMLNamespace = _xns.LookupSchemaNamespace(text5, _xns.Assem);
				int num = 0;
				if (_methods != null)
				{
					num = _methods.Length;
				}
				if (num > 0)
				{
					value2 = xMLNamespace.Namespace;
					_ = xMLNamespace.Prefix;
				}
				refNames.Add(base.Name);
				for (int i = 0; i < num; i++)
				{
					methodInfo = _methods[i];
					flag = RemotingServices.IsOneWay(methodInfo);
					text3 = PrintMethodName(methodInfo);
					sb.Length = 0;
					QualifyName(sb, base.Name, _methodTypes[2 * i]);
					text4 = sb.ToString();
					sb.Length = 0;
					sb.Append("\n");
					sb.Append(indent);
					sb.Append("<message name='");
					sb.Append(text4 + "Input");
					sb.Append("'>");
					textWriter.WriteLine(sb);
					PhonySchemaType phonySchemaType = _phony[i];
					if (phonySchemaType._inParamTypes == null)
					{
						continue;
					}
					for (int j = 0; j < phonySchemaType._inParamTypes.Count; j++)
					{
						sb.Length = 0;
						sb.Append(text);
						sb.Append("<part name='");
						sb.Append(phonySchemaType._inParamNames[j]);
						sb.Append("' type='");
						sb.Append(phonySchemaType._inParamTypes[j]);
						sb.Append("'/>");
						textWriter.WriteLine(sb);
					}
					sb.Length = 0;
					sb.Append(indent);
					sb.Append("</message>");
					textWriter.WriteLine(sb);
					if (flag)
					{
						continue;
					}
					sb.Length = 0;
					sb.Append(indent);
					sb.Append("<message name='");
					sb.Append(text4 + "Output");
					sb.Append("'>");
					textWriter.WriteLine(sb);
					if (phonySchemaType._returnType != null || phonySchemaType._outParamTypes != null)
					{
						if (phonySchemaType._returnType != null)
						{
							sb.Length = 0;
							sb.Append(text);
							sb.Append("<part name='");
							sb.Append(phonySchemaType._returnName);
							sb.Append("' type='");
							sb.Append(phonySchemaType._returnType);
							sb.Append("'/>");
							textWriter.WriteLine(sb);
						}
						if (phonySchemaType._outParamTypes != null)
						{
							for (int k = 0; k < phonySchemaType._outParamTypes.Count; k++)
							{
								sb.Length = 0;
								sb.Append(text);
								sb.Append("<part name='");
								sb.Append(phonySchemaType._outParamNames[k]);
								sb.Append("' type='");
								sb.Append(phonySchemaType._outParamTypes[k]);
								sb.Append("'/>");
								textWriter.WriteLine(sb);
							}
						}
					}
					sb.Length = 0;
					sb.Append(indent);
					sb.Append("</message>");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append("\n");
				sb.Append(indent);
				sb.Append("<portType name='");
				sb.Append(base.Name);
				sb.Append("PortType");
				sb.Append("'>");
				textWriter.WriteLine(sb);
				for (int l = 0; l < num; l++)
				{
					methodInfo = _methods[l];
					PhonySchemaType phonySchemaType2 = _phony[l];
					flag = RemotingServices.IsOneWay(methodInfo);
					text3 = PrintMethodName(methodInfo);
					sb.Length = 0;
					sb.Append("tns:");
					QualifyName(sb, base.Name, _methodTypes[2 * l]);
					text4 = sb.ToString();
					sb.Length = 0;
					sb.Append(text);
					sb.Append("<operation name='");
					sb.Append(text3);
					sb.Append("'");
					if (phonySchemaType2 != null && phonySchemaType2._paramNamesOrder.Count > 0)
					{
						sb.Append(" parameterOrder='");
						bool flag2 = true;
						foreach (string item in phonySchemaType2._paramNamesOrder)
						{
							if (!flag2)
							{
								sb.Append(" ");
							}
							sb.Append(item);
							flag2 = false;
						}
						sb.Append("'");
					}
					sb.Append(">");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(text2);
					sb.Append("<input name='");
					sb.Append(_methodTypes[2 * l]);
					sb.Append("Request' ");
					sb.Append("message='");
					sb.Append(text4);
					sb.Append("Input");
					sb.Append("'/>");
					textWriter.WriteLine(sb);
					if (!flag)
					{
						sb.Length = 0;
						sb.Append(text2);
						sb.Append("<output name='");
						sb.Append(_methodTypes[2 * l]);
						sb.Append("Response' ");
						sb.Append("message='");
						sb.Append(text4);
						sb.Append("Output");
						sb.Append("'/>");
						textWriter.WriteLine(sb);
					}
					sb.Length = 0;
					sb.Append(text);
					sb.Append("</operation>");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("</portType>");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append("\n");
				sb.Append(indent);
				sb.Append("<binding name='");
				sb.Append(base.Name);
				sb.Append("Binding");
				sb.Append("' ");
				sb.Append("type='tns:");
				sb.Append(base.Name);
				sb.Append("PortType");
				sb.Append("'>");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text);
				sb.Append("<soap:binding style='rpc' transport='http://schemas.xmlsoap.org/soap/http'/>");
				textWriter.WriteLine(sb);
				if (_type.IsInterface || IsSUDSType)
				{
					PrintSuds(_type, _implIFaces, _nestedTypes, textWriter, sb, indent);
				}
				if (!_xns.IsClassesPrinted)
				{
					for (int m = 0; m < _xns._realSchemaTypes.Count; m++)
					{
						RealSchemaType realSchemaType = (RealSchemaType)_xns._realSchemaTypes[m];
						Type type = realSchemaType._type;
						if (realSchemaType.Type.IsInterface || realSchemaType.IsSUDSType)
						{
							continue;
						}
						Type[] introducedInterfaces = GetIntroducedInterfaces(realSchemaType._type);
						string[] array = null;
						bool flag3 = false;
						if (introducedInterfaces.Length > 0)
						{
							array = new string[introducedInterfaces.Length];
							int num2 = 0;
							for (; m < introducedInterfaces.Length; m++)
							{
								GetNSAndAssembly(introducedInterfaces[num2], out var ns, out var assem);
								XMLNamespace xMLNamespace2 = _xns.LookupSchemaNamespace(ns, assem);
								sb.Length = 0;
								sb.Append(xMLNamespace2.Prefix);
								sb.Append(':');
								sb.Append(introducedInterfaces[num2].Name);
								array[num2] = sb.ToString();
								if (array[num2].Length > 0)
								{
									flag3 = true;
								}
							}
						}
						if (!flag3)
						{
							array = null;
						}
						PrintSuds(type, array, realSchemaType._nestedTypes, textWriter, sb, indent);
					}
					_xns.IsClassesPrinted = true;
				}
				for (int n = 0; n < num; n++)
				{
					methodInfo = _methods[n];
					text3 = PrintMethodName(methodInfo);
					flag = RemotingServices.IsOneWay(methodInfo);
					sb.Length = 0;
					sb.Append(text);
					sb.Append("<operation name='");
					sb.Append(text3);
					sb.Append("'>");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(text2);
					sb.Append("<soap:operation soapAction='");
					string soapActionFromMethodBase = SoapServices.GetSoapActionFromMethodBase(methodInfo);
					if (soapActionFromMethodBase != null || soapActionFromMethodBase.Length > 0)
					{
						sb.Append(soapActionFromMethodBase);
					}
					else
					{
						sb.Append(value2);
						sb.Append('#');
						sb.Append(text3);
					}
					sb.Append("'/>");
					textWriter.WriteLine(sb);
					if (_methodAttributes != null && n < _methodAttributes.Length && _methodAttributes[n] != null)
					{
						sb.Length = 0;
						sb.Append(text2);
						sb.Append("<suds:method attributes='");
						sb.Append(_methodAttributes[n]);
						sb.Append("'/>");
						textWriter.WriteLine(sb);
					}
					sb.Length = 0;
					sb.Append(text2);
					sb.Append("<input name='");
					sb.Append(_methodTypes[2 * n]);
					sb.Append("Request'>");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(value);
					sb.Append("<soap:body use='encoded' encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' namespace='");
					string xmlNamespaceForMethodCall = SoapServices.GetXmlNamespaceForMethodCall(methodInfo);
					if (xmlNamespaceForMethodCall == null)
					{
						sb.Append(value2);
					}
					else
					{
						sb.Append(xmlNamespaceForMethodCall);
					}
					sb.Append("'/>");
					textWriter.WriteLine(sb);
					sb.Length = 0;
					sb.Append(text2);
					sb.Append("</input>");
					textWriter.WriteLine(sb);
					if (!flag)
					{
						sb.Length = 0;
						sb.Append(text2);
						sb.Append("<output name='");
						sb.Append(_methodTypes[2 * n]);
						sb.Append("Response'>");
						textWriter.WriteLine(sb);
						sb.Length = 0;
						sb.Append(value);
						sb.Append("<soap:body use='encoded' encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' namespace='");
						xmlNamespaceForMethodCall = SoapServices.GetXmlNamespaceForMethodResponse(methodInfo);
						if (xmlNamespaceForMethodCall == null)
						{
							sb.Append(value2);
						}
						else
						{
							sb.Append(xmlNamespaceForMethodCall);
						}
						sb.Append("'/>");
						textWriter.WriteLine(sb);
						sb.Length = 0;
						sb.Append(text2);
						sb.Append("</output>");
						textWriter.WriteLine(sb);
					}
					sb.Length = 0;
					sb.Append(text);
					sb.Append("</operation>");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("</binding>");
				textWriter.WriteLine(sb);
			}

			private void PrintSuds(Type type, string[] implIFaces, Type[] nestedTypes, TextWriter textWriter, StringBuilder sb, string indent)
			{
				string text = IndentP(indent);
				string text2 = IndentP(text);
				IndentP(text2);
				string text3 = null;
				sb.Length = 0;
				sb.Append(text);
				if (type.IsInterface)
				{
					sb.Append("<suds:interface type='");
					text3 = "</suds:interface>";
				}
				else if (type.IsValueType)
				{
					sb.Append("<suds:struct type='");
					text3 = "</suds:struct>";
				}
				else
				{
					sb.Append("<suds:class type='");
					text3 = "</suds:class>";
				}
				sb.Append(_xns.Prefix);
				sb.Append(':');
				sb.Append(RefName(type));
				sb.Append("'");
				Type baseType = type.BaseType;
				if (IsNotSystemDefinedRoot(type, baseType))
				{
					XMLNamespace @namespace = _WsdlGenerator.GetNamespace(baseType);
					sb.Append(" extends='");
					sb.Append(@namespace.Prefix);
					sb.Append(':');
					sb.Append(baseType.Name);
					sb.Append("'");
				}
				if (baseType != null && baseType.FullName == "System.EnterpriseServices.ServicedComponent")
				{
					sb.Append(" rootType='ServicedComponent'");
				}
				else if (typeof(Delegate).IsAssignableFrom(type) || typeof(MulticastDelegate).IsAssignableFrom(type))
				{
					sb.Append(" rootType='Delegate'");
				}
				else if (typeof(MarshalByRefObject).IsAssignableFrom(type))
				{
					sb.Append(" rootType='MarshalByRefObject'");
				}
				else if (typeof(ISerializable).IsAssignableFrom(type))
				{
					sb.Append(" rootType='ISerializable'");
				}
				if (implIFaces == null && nestedTypes == null)
				{
					sb.Append("/>");
				}
				else
				{
					sb.Append(">");
				}
				textWriter.WriteLine(sb);
				string text4 = null;
				text4 = ((!type.IsInterface) ? "<suds:implements type='" : "<suds:extends type='");
				if (implIFaces != null)
				{
					for (int i = 0; i < implIFaces.Length; i++)
					{
						if (implIFaces[i] != null && !(implIFaces[i] == string.Empty))
						{
							sb.Length = 0;
							sb.Append(text2);
							sb.Append(text4);
							sb.Append(implIFaces[i]);
							sb.Append("'/>");
							textWriter.WriteLine(sb);
						}
					}
				}
				if (nestedTypes != null)
				{
					for (int j = 0; j < nestedTypes.Length; j++)
					{
						sb.Length = 0;
						sb.Append(text2);
						sb.Append("<suds:nestedType name='");
						sb.Append(nestedTypes[j].Name);
						sb.Append("' type='");
						sb.Append(_xns.Prefix);
						sb.Append(':');
						sb.Append(RefName(nestedTypes[j]));
						sb.Append("'/>");
						textWriter.WriteLine(sb);
					}
				}
				if (implIFaces != null || nestedTypes != null)
				{
					sb.Length = 0;
					sb.Append(text);
					sb.Append(text3);
					textWriter.WriteLine(sb);
				}
			}

			private static string ProcessArray(Type type, XMLNamespace xns)
			{
				string text = null;
				bool flag = false;
				Type elementType = type.GetElementType();
				string text2 = "ArrayOf";
				while (elementType.IsArray)
				{
					text2 += "ArrayOf";
					elementType = elementType.GetElementType();
				}
				text = TypeName(elementType, bEmbedded: true, xns);
				int num = text.IndexOf(":");
				text.Substring(0, num);
				string text3 = text.Substring(num + 1);
				int arrayRank = type.GetArrayRank();
				string text4 = "";
				if (arrayRank > 1)
				{
					text4 = arrayRank.ToString(CultureInfo.InvariantCulture);
				}
				string text5 = text2 + text3.Substring(0, 1).ToUpper(CultureInfo.InvariantCulture) + text3.Substring(1) + text4;
				text5 = text5.Replace('+', 'N');
				ArraySchemaType arraySchemaType = xns.LookupArraySchemaType(text5);
				if (arraySchemaType == null)
				{
					ArraySchemaType arraySchemaType2 = new ArraySchemaType(type, text5, SchemaBlockType.ComplexContent, bSealed: false);
					Restriction restriction = new Restriction();
					SchemaAttribute schemaAttribute = new SchemaAttribute();
					if (flag)
					{
						schemaAttribute.AddArray(text);
					}
					else
					{
						string name = type.Name;
						num = name.IndexOf("[");
						schemaAttribute.AddArray(text + name.Substring(num));
					}
					restriction.AddArray(schemaAttribute);
					arraySchemaType2.AddParticle(restriction);
					xns.AddArraySchemaType(arraySchemaType2);
				}
				return xns.Prefix + ":" + text5;
			}

			internal static string TypeName(Type type, bool bEmbedded, XMLNamespace thisxns)
			{
				string text = null;
				if (type.IsArray)
				{
					return ProcessArray(type, thisxns);
				}
				string value = RefName(type);
				Type type2 = type;
				if (type.IsByRef)
				{
					type2 = type.GetElementType();
					value = RefName(type2);
					if (type2.IsArray)
					{
						return ProcessArray(type2, thisxns);
					}
				}
				text = SudsConverter.MapClrTypeToXsdType(type2);
				if (text == null)
				{
					string @namespace = type.Namespace;
					Assembly assembly = type.Module.Assembly;
					XMLNamespace xMLNamespace = null;
					xMLNamespace = (XMLNamespace)thisxns.Generator._typeToInteropNS[type];
					if (xMLNamespace == null)
					{
						xMLNamespace = thisxns.LookupSchemaNamespace(@namespace, assembly);
						if (xMLNamespace == null)
						{
							xMLNamespace = thisxns.Generator.LookupNamespace(@namespace, assembly);
							if (xMLNamespace == null)
							{
								xMLNamespace = thisxns.Generator.AddNamespace(@namespace, assembly);
							}
							thisxns.DependsOnSchemaNS(xMLNamespace, bImport: false);
						}
					}
					StringBuilder stringBuilder = new StringBuilder(256);
					stringBuilder.Append(xMLNamespace.Prefix);
					stringBuilder.Append(':');
					stringBuilder.Append(value);
					text = stringBuilder.ToString();
				}
				return text;
			}

			private static Type[] GetIntroducedInterfaces(Type type)
			{
				ArrayList arrayList = new ArrayList();
				Type[] interfaces = type.GetInterfaces();
				Type[] array = interfaces;
				foreach (Type type2 in array)
				{
					if (!type2.FullName.StartsWith("System."))
					{
						arrayList.Add(type2);
					}
				}
				Type[] array2 = new Type[arrayList.Count];
				for (int j = 0; j < arrayList.Count; j++)
				{
					array2[j] = (Type)arrayList[j];
				}
				return array2;
			}

			private static void FindMethodAttributes(Type type, MethodInfo[] infos, ref string[] methodAttributes, BindingFlags bFlags)
			{
				Type type2 = type;
				ArrayList arrayList = new ArrayList();
				while (true)
				{
					type2 = type2.BaseType;
					if (type2 == null || type2.FullName.StartsWith("System."))
					{
						break;
					}
					arrayList.Add(type2);
				}
				StringBuilder stringBuilder = new StringBuilder();
				for (int i = 0; i < infos.Length; i++)
				{
					MethodBase methodBase = infos[i];
					stringBuilder.Length = 0;
					MethodAttributes attributes = methodBase.Attributes;
					bool isVirtual = methodBase.IsVirtual;
					bool flag = (attributes & MethodAttributes.VtableLayoutMask) == MethodAttributes.VtableLayoutMask;
					if (methodBase.IsPublic)
					{
						stringBuilder.Append("public");
					}
					else if (methodBase.IsFamily)
					{
						stringBuilder.Append("protected");
					}
					else if (methodBase.IsAssembly)
					{
						stringBuilder.Append("internal");
					}
					bool flag2 = false;
					for (int j = 0; j < arrayList.Count; j++)
					{
						type2 = (Type)arrayList[j];
						ParameterInfo[] parameters = methodBase.GetParameters();
						Type[] array = new Type[parameters.Length];
						for (int k = 0; k < array.Length; k++)
						{
							array[k] = parameters[k].ParameterType;
						}
						MethodInfo method = type2.GetMethod(methodBase.Name, array);
						if (method != null)
						{
							if (stringBuilder.Length > 0)
							{
								stringBuilder.Append(" ");
							}
							if (flag || method.IsFinal)
							{
								stringBuilder.Append("new");
							}
							else if (method.IsVirtual && isVirtual)
							{
								stringBuilder.Append("override");
							}
							else
							{
								stringBuilder.Append("new");
							}
							flag2 = true;
							break;
						}
					}
					if (!flag2 && isVirtual)
					{
						if (stringBuilder.Length > 0)
						{
							stringBuilder.Append(" ");
						}
						stringBuilder.Append("virtual");
					}
					if (stringBuilder.Length > 0)
					{
						methodAttributes[i] = stringBuilder.ToString();
					}
				}
			}

			private static MethodInfo[] GetIntroducedMethods(Type type, ref string[] methodAttributes)
			{
				BindingFlags bindingFlags = BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Public;
				MethodInfo[] methods = type.GetMethods(bindingFlags);
				if (type.IsInterface)
				{
					return methods;
				}
				methodAttributes = new string[methods.Length];
				FindMethodAttributes(type, methods, ref methodAttributes, bindingFlags);
				ArrayList arrayList = new ArrayList();
				Type[] interfaces = type.GetInterfaces();
				Type[] array = interfaces;
				foreach (Type interfaceType in array)
				{
					MethodInfo[] targetMethods = type.GetInterfaceMap(interfaceType).TargetMethods;
					foreach (MethodInfo methodInfo in targetMethods)
					{
						if (!methodInfo.IsPublic && type.GetMethod(methodInfo.Name, bindingFlags | BindingFlags.NonPublic) != null)
						{
							arrayList.Add(methodInfo);
						}
					}
				}
				MethodInfo[] array2 = null;
				if (arrayList.Count > 0)
				{
					array2 = new MethodInfo[methods.Length + arrayList.Count];
					for (int k = 0; k < methods.Length; k++)
					{
						array2[k] = methods[k];
					}
					for (int l = 0; l < arrayList.Count; l++)
					{
						array2[methods.Length + l] = (MethodInfo)arrayList[l];
					}
				}
				else
				{
					array2 = methods;
				}
				return array2;
			}

			internal static string PrintMethodName(MethodInfo methodInfo)
			{
				string name = methodInfo.Name;
				int num = 0;
				int num2 = 0;
				for (int i = 0; i < name.Length; i++)
				{
					if (name[i] == '.')
					{
						num2 = num;
						num = i;
					}
				}
				string result = name;
				if (num2 > 0)
				{
					result = name.Substring(num2 + 1);
				}
				return result;
			}

			private static FieldInfo[] GetInstanceFields(Type type)
			{
				BindingFlags bindingFlags = BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Public;
				if (!s_marshalByRefType.IsAssignableFrom(type))
				{
					bindingFlags |= BindingFlags.NonPublic;
				}
				FieldInfo[] fields = type.GetFields(bindingFlags);
				int num = fields.Length;
				if (num == 0)
				{
					return emptyFieldSet;
				}
				for (int i = 0; i < fields.Length; i++)
				{
					if (fields[i].IsStatic)
					{
						num--;
						fields[i] = fields[num];
						fields[num] = null;
					}
				}
				if (num < fields.Length)
				{
					FieldInfo[] array = new FieldInfo[num];
					Array.Copy(fields, array, num);
					return array;
				}
				return fields;
			}
		}

		private class XMLNamespace
		{
			private string _name;

			private Assembly _assem;

			private string _namespace;

			private string _prefix;

			internal bool _bUnique;

			private ArrayList _dependsOnSUDSNS;

			private ArrayList _realSUDSTypes;

			private ArrayList _dependsOnSchemaNS;

			internal ArrayList _realSchemaTypes;

			private ArrayList _phonySchemaTypes;

			private ArrayList _simpleSchemaTypes;

			private ArrayList _arraySchemaTypes;

			private bool _bInteropType;

			private string _serviceEndpoint;

			private Hashtable _typeToServiceEndpoint;

			private WsdlGenerator _generator;

			private ArrayList _xnsImports;

			private bool _bClassesPrinted;

			internal string Name => _name;

			internal Assembly Assem => _assem;

			internal string Prefix => _prefix;

			internal string Namespace => _namespace;

			internal bool IsInteropType => _bInteropType;

			internal WsdlGenerator Generator => _generator;

			internal bool IsClassesPrinted
			{
				get
				{
					return _bClassesPrinted;
				}
				set
				{
					_bClassesPrinted = value;
				}
			}

			internal XMLNamespace(string name, Assembly assem, string serviceEndpoint, Hashtable typeToServiceEndpoint, string prefix, bool bInteropType, WsdlGenerator generator)
			{
				_name = name;
				_assem = assem;
				_bUnique = false;
				_bInteropType = bInteropType;
				_generator = generator;
				StringBuilder stringBuilder = new StringBuilder(256);
				Assembly assembly = typeof(string).Module.Assembly;
				if (!_bInteropType)
				{
					if (assem == assembly)
					{
						stringBuilder.Append(SoapServices.CodeXmlNamespaceForClrTypeNamespace(name, null));
					}
					else if (assem != null)
					{
						stringBuilder.Append(SoapServices.CodeXmlNamespaceForClrTypeNamespace(name, assem.FullName));
					}
				}
				else
				{
					stringBuilder.Append(name);
				}
				_namespace = stringBuilder.ToString();
				_prefix = prefix;
				_dependsOnSchemaNS = new ArrayList();
				_realSUDSTypes = new ArrayList();
				_dependsOnSUDSNS = new ArrayList();
				_realSchemaTypes = new ArrayList();
				_phonySchemaTypes = new ArrayList();
				_simpleSchemaTypes = new ArrayList();
				_arraySchemaTypes = new ArrayList();
				_xnsImports = new ArrayList();
				_serviceEndpoint = serviceEndpoint;
				_typeToServiceEndpoint = typeToServiceEndpoint;
			}

			internal Type LookupSchemaType(string name)
			{
				Type result = null;
				RealSchemaType realSchemaType = LookupRealSchemaType(name);
				if (realSchemaType != null)
				{
					result = realSchemaType.Type;
				}
				SimpleSchemaType simpleSchemaType = LookupSimpleSchemaType(name);
				if (simpleSchemaType != null)
				{
					result = simpleSchemaType.Type;
				}
				ArraySchemaType arraySchemaType = LookupArraySchemaType(name);
				if (arraySchemaType != null)
				{
					result = arraySchemaType.Type;
				}
				return result;
			}

			internal SimpleSchemaType LookupSimpleSchemaType(string name)
			{
				for (int i = 0; i < _simpleSchemaTypes.Count; i++)
				{
					SimpleSchemaType simpleSchemaType = (SimpleSchemaType)_simpleSchemaTypes[i];
					if (simpleSchemaType.FullRefName == name)
					{
						return simpleSchemaType;
					}
				}
				return null;
			}

			internal bool CheckForSchemaContent()
			{
				if (_arraySchemaTypes.Count > 0 || _simpleSchemaTypes.Count > 0)
				{
					return true;
				}
				if (_realSchemaTypes.Count == 0)
				{
					return false;
				}
				bool flag = false;
				for (int i = 0; i < _realSchemaTypes.Count; i++)
				{
					RealSchemaType realSchemaType = (RealSchemaType)_realSchemaTypes[i];
					if (!realSchemaType.Type.IsInterface && !realSchemaType.IsSUDSType)
					{
						flag = true;
						break;
					}
				}
				if (flag)
				{
					return true;
				}
				return false;
			}

			internal RealSchemaType LookupRealSchemaType(string name)
			{
				for (int i = 0; i < _realSchemaTypes.Count; i++)
				{
					RealSchemaType realSchemaType = (RealSchemaType)_realSchemaTypes[i];
					if (realSchemaType.FullRefName == name)
					{
						return realSchemaType;
					}
				}
				return null;
			}

			internal ArraySchemaType LookupArraySchemaType(string name)
			{
				for (int i = 0; i < _arraySchemaTypes.Count; i++)
				{
					ArraySchemaType arraySchemaType = (ArraySchemaType)_arraySchemaTypes[i];
					if (arraySchemaType.Name == name)
					{
						return arraySchemaType;
					}
				}
				return null;
			}

			internal void AddRealSUDSType(RealSchemaType rsType)
			{
				_realSUDSTypes.Add(rsType);
			}

			internal void AddRealSchemaType(RealSchemaType rsType)
			{
				_realSchemaTypes.Add(rsType);
				if (rsType.IsUnique)
				{
					_bUnique = true;
				}
			}

			internal void AddArraySchemaType(ArraySchemaType asType)
			{
				_arraySchemaTypes.Add(asType);
			}

			internal void AddSimpleSchemaType(SimpleSchemaType ssType)
			{
				_simpleSchemaTypes.Add(ssType);
			}

			internal PhonySchemaType LookupPhonySchemaType(string name)
			{
				for (int i = 0; i < _phonySchemaTypes.Count; i++)
				{
					PhonySchemaType phonySchemaType = (PhonySchemaType)_phonySchemaTypes[i];
					if (phonySchemaType.Name == name)
					{
						return phonySchemaType;
					}
				}
				return null;
			}

			internal void AddPhonySchemaType(PhonySchemaType phType)
			{
				PhonySchemaType phonySchemaType = LookupPhonySchemaType(phType.Name);
				if (phonySchemaType != null)
				{
					phType.ElementName = phType.Name + phonySchemaType.OverloadedType();
				}
				_phonySchemaTypes.Add(phType);
			}

			internal XMLNamespace LookupSchemaNamespace(string ns, Assembly assem)
			{
				for (int i = 0; i < _dependsOnSchemaNS.Count; i++)
				{
					XMLNamespace xMLNamespace = (XMLNamespace)_dependsOnSchemaNS[i];
					if (xMLNamespace.Name == ns && xMLNamespace.Assem == assem)
					{
						return xMLNamespace;
					}
				}
				return null;
			}

			internal void DependsOnSchemaNS(XMLNamespace xns, bool bImport)
			{
				if (LookupSchemaNamespace(xns.Name, xns.Assem) == null)
				{
					_dependsOnSchemaNS.Add(xns);
					if (bImport && Namespace != xns.Namespace)
					{
						_xnsImports.Add(xns);
					}
				}
			}

			private XMLNamespace LookupSUDSNamespace(string ns, Assembly assem)
			{
				for (int i = 0; i < _dependsOnSUDSNS.Count; i++)
				{
					XMLNamespace xMLNamespace = (XMLNamespace)_dependsOnSUDSNS[i];
					if (xMLNamespace.Name == ns && xMLNamespace.Assem == assem)
					{
						return xMLNamespace;
					}
				}
				return null;
			}

			internal void DependsOnSUDSNS(XMLNamespace xns)
			{
				if (LookupSUDSNamespace(xns.Name, xns.Assem) == null)
				{
					_dependsOnSUDSNS.Add(xns);
				}
			}

			internal void Resolve()
			{
				StringBuilder sb = new StringBuilder(256);
				for (int i = 0; i < _realSchemaTypes.Count; i++)
				{
					((RealSchemaType)_realSchemaTypes[i]).Resolve(sb);
				}
			}

			internal void PrintDependsOnWsdl(TextWriter textWriter, StringBuilder sb, string indent, Hashtable usedNames)
			{
				if (_dependsOnSchemaNS.Count <= 0)
				{
					return;
				}
				for (int i = 0; i < _dependsOnSchemaNS.Count; i++)
				{
					XMLNamespace xMLNamespace = (XMLNamespace)_dependsOnSchemaNS[i];
					if (!usedNames.ContainsKey(xMLNamespace.Prefix))
					{
						usedNames[xMLNamespace.Prefix] = null;
						sb.Length = 0;
						sb.Append(indent);
						sb.Append("xmlns:");
						sb.Append(xMLNamespace.Prefix);
						sb.Append("='");
						sb.Append(xMLNamespace.Namespace);
						sb.Append("'");
						textWriter.WriteLine(sb);
					}
				}
			}

			internal void PrintSchemaWsdl(TextWriter textWriter, StringBuilder sb, string indent)
			{
				bool flag = false;
				if (_simpleSchemaTypes.Count > 0 || _realSchemaTypes.Count > 0 || _arraySchemaTypes.Count > 0)
				{
					flag = true;
				}
				if (!flag)
				{
					return;
				}
				string text = IndentP(indent);
				string text2 = IndentP(text);
				string indentStr = IndentP(text2);
				IndentP(indentStr);
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("<schema ");
				sb.Append("targetNamespace='");
				sb.Append(Namespace);
				sb.Append("'");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text2);
				sb.Append("xmlns='");
				sb.Append(SudsConverter.GetXsdVersion(_generator._xsdVersion));
				sb.Append("'");
				textWriter.WriteLine(sb);
				sb.Length = 0;
				sb.Append(text2);
				sb.Append("elementFormDefault='unqualified' attributeFormDefault='unqualified'>");
				textWriter.WriteLine(sb);
				foreach (XMLNamespace xnsImport in _xnsImports)
				{
					sb.Length = 0;
					sb.Append(text);
					sb.Append("<import namespace='");
					sb.Append(xnsImport.Namespace);
					sb.Append("'/>");
					textWriter.WriteLine(sb);
				}
				for (int i = 0; i < _simpleSchemaTypes.Count; i++)
				{
					SimpleSchemaType simpleSchemaType = (SimpleSchemaType)_simpleSchemaTypes[i];
					simpleSchemaType.PrintSchemaType(textWriter, sb, text, bAnonymous: false);
				}
				for (int j = 0; j < _realSchemaTypes.Count; j++)
				{
					RealSchemaType realSchemaType = (RealSchemaType)_realSchemaTypes[j];
					if (!realSchemaType.Type.IsInterface && !realSchemaType.IsSUDSType)
					{
						realSchemaType.PrintSchemaType(textWriter, sb, text, bAnonymous: false);
					}
				}
				for (int k = 0; k < _arraySchemaTypes.Count; k++)
				{
					ArraySchemaType arraySchemaType = (ArraySchemaType)_arraySchemaTypes[k];
					arraySchemaType.PrintSchemaType(textWriter, sb, text, bAnonymous: false);
				}
				sb.Length = 0;
				sb.Append(indent);
				sb.Append("</schema>");
				textWriter.WriteLine(sb);
			}

			internal void PrintMessageWsdl(TextWriter textWriter, StringBuilder sb, string indent, ArrayList refNames)
			{
				for (int i = 0; i < _realSUDSTypes.Count; i++)
				{
					((RealSchemaType)_realSUDSTypes[i]).PrintMessageWsdl(textWriter, sb, indent, refNames);
				}
				if (_realSUDSTypes.Count == 0 && _realSchemaTypes.Count > 0)
				{
					((RealSchemaType)_realSchemaTypes[0]).PrintMessageWsdl(textWriter, sb, indent, new ArrayList());
				}
			}
		}

		private TextWriter _textWriter;

		internal Queue _queue;

		private string _name;

		private string _targetNS;

		private string _targetNSPrefix;

		private ArrayList _namespaces;

		private Assembly _dynamicAssembly;

		private string _serviceEndpoint;

		private XsdVersion _xsdVersion;

		internal Hashtable _typeToServiceEndpoint;

		internal Hashtable _typeToInteropNS = new Hashtable();

		private static Type s_marshalByRefType = typeof(MarshalByRefObject);

		private static Type s_contextBoundType = typeof(ContextBoundObject);

		private static Type s_delegateType = typeof(Delegate);

		private static Type s_valueType = typeof(ValueType);

		private static Type s_objectType = typeof(object);

		private static Type s_charType = typeof(char);

		private static Type s_voidType = typeof(void);

		private static Type s_remotingClientProxyType = typeof(RemotingClientProxy);

		private static SchemaBlockType blockDefault = SchemaBlockType.SEQUENCE;

		internal WsdlGenerator(Type[] types, TextWriter output)
		{
			_textWriter = output;
			_queue = new Queue();
			_name = null;
			_namespaces = new ArrayList();
			_dynamicAssembly = null;
			_serviceEndpoint = null;
			for (int i = 0; i < types.Length; i++)
			{
				if (types[i] != null && types[i].BaseType != null)
				{
					ProcessTypeAttributes(types[i]);
					_queue.Enqueue(types[i]);
				}
			}
		}

		internal WsdlGenerator(Type[] types, SdlType sdlType, TextWriter output)
		{
			_textWriter = output;
			_queue = new Queue();
			_name = null;
			_namespaces = new ArrayList();
			_dynamicAssembly = null;
			_serviceEndpoint = null;
			for (int i = 0; i < types.Length; i++)
			{
				if (types[i] != null && types[i].BaseType != null)
				{
					ProcessTypeAttributes(types[i]);
					_queue.Enqueue(types[i]);
				}
			}
		}

		internal WsdlGenerator(Type[] types, TextWriter output, Assembly assembly, string url)
			: this(types, output)
		{
			_dynamicAssembly = assembly;
			_serviceEndpoint = url;
		}

		internal WsdlGenerator(Type[] types, SdlType sdlType, TextWriter output, Assembly assembly, string url)
			: this(types, output)
		{
			_dynamicAssembly = assembly;
			_serviceEndpoint = url;
		}

		internal WsdlGenerator(ServiceType[] serviceTypes, SdlType sdlType, TextWriter output)
		{
			_textWriter = output;
			_queue = new Queue();
			_name = null;
			_namespaces = new ArrayList();
			_dynamicAssembly = null;
			_serviceEndpoint = null;
			for (int i = 0; i < serviceTypes.Length; i++)
			{
				if (serviceTypes[i] != null && serviceTypes[i].ObjectType.BaseType != null)
				{
					ProcessTypeAttributes(serviceTypes[i].ObjectType);
					_queue.Enqueue(serviceTypes[i].ObjectType);
				}
				if (serviceTypes[i].Url != null)
				{
					if (_typeToServiceEndpoint == null)
					{
						_typeToServiceEndpoint = new Hashtable(10);
					}
					if (_typeToServiceEndpoint.ContainsKey(serviceTypes[i].ObjectType.Name))
					{
						ArrayList arrayList = (ArrayList)_typeToServiceEndpoint[serviceTypes[i].ObjectType.Name];
						arrayList.Add(serviceTypes[i].Url);
					}
					else
					{
						ArrayList value = new ArrayList(10) { serviceTypes[i].Url };
						_typeToServiceEndpoint[serviceTypes[i].ObjectType.Name] = value;
					}
				}
			}
		}

		internal static void QualifyName(StringBuilder sb, string ns, string name)
		{
			if (ns != null && ns.Length != 0)
			{
				sb.Append(ns);
				sb.Append('.');
			}
			sb.Append(name);
		}

		internal static string RefName(Type type)
		{
			string result = type.Name;
			if (!type.IsPublic && !type.IsNotPublic)
			{
				result = type.FullName;
				int num = result.LastIndexOf('.');
				if (num > 0)
				{
					result = result.Substring(num + 1);
				}
				result = result.Replace('+', '.');
			}
			return result;
		}

		internal void ProcessTypeAttributes(Type type)
		{
			if (InternalRemotingServices.GetCachedSoapAttribute(type) is SoapTypeAttribute soapTypeAttribute)
			{
				SoapOption soapOptions = soapTypeAttribute.SoapOptions;
				if ((soapOptions &= SoapOption.Option1) == SoapOption.Option1)
				{
					_xsdVersion = XsdVersion.V1999;
				}
				else if ((soapOptions &= SoapOption.Option2) == SoapOption.Option2)
				{
					_xsdVersion = XsdVersion.V2000;
				}
				else
				{
					_xsdVersion = XsdVersion.V2001;
				}
			}
		}

		internal void Generate()
		{
			while (_queue.Count > 0)
			{
				Type type = (Type)_queue.Dequeue();
				ProcessType(type);
			}
			Resolve();
			PrintWsdl();
			_textWriter.Flush();
		}

		internal void ProcessType(Type type)
		{
			string ns;
			Assembly assem;
			bool nSAndAssembly = GetNSAndAssembly(type, out ns, out assem);
			XMLNamespace xMLNamespace = LookupNamespace(ns, assem);
			if (xMLNamespace != null)
			{
				string name = RefName(type);
				if (xMLNamespace.LookupSchemaType(name) != null)
				{
					return;
				}
			}
			else
			{
				xMLNamespace = AddNamespace(ns, assem, nSAndAssembly);
			}
			_typeToInteropNS[type] = xMLNamespace;
			if (type.IsArray)
			{
				return;
			}
			SimpleSchemaType simpleSchemaType = SimpleSchemaType.GetSimpleSchemaType(type, xMLNamespace, fInline: false);
			if (simpleSchemaType != null)
			{
				xMLNamespace.AddSimpleSchemaType(simpleSchemaType);
				return;
			}
			bool bUnique = false;
			string serviceEndpoint = null;
			Hashtable typeToServiceEndpoint = null;
			if (_name == null && s_marshalByRefType.IsAssignableFrom(type))
			{
				_name = type.Name;
				_targetNS = xMLNamespace.Namespace;
				_targetNSPrefix = xMLNamespace.Prefix;
				serviceEndpoint = _serviceEndpoint;
				typeToServiceEndpoint = _typeToServiceEndpoint;
				bUnique = true;
			}
			RealSchemaType rsType = new RealSchemaType(type, xMLNamespace, serviceEndpoint, typeToServiceEndpoint, bUnique, this);
			xMLNamespace.AddRealSchemaType(rsType);
			EnqueueReachableTypes(rsType);
		}

		private void EnqueueReachableTypes(RealSchemaType rsType)
		{
			XMLNamespace xNS = rsType.XNS;
			if (rsType.Type.BaseType != null && (rsType.Type.BaseType != s_valueType || rsType.Type.BaseType != s_objectType))
			{
				AddType(rsType.Type.BaseType, GetNamespace(rsType.Type.BaseType));
			}
			if (rsType.Type.IsInterface || s_marshalByRefType.IsAssignableFrom(rsType.Type) || s_delegateType.IsAssignableFrom(rsType.Type))
			{
				FieldInfo[] instanceFields = rsType.GetInstanceFields();
				for (int i = 0; i < instanceFields.Length; i++)
				{
					if (instanceFields[i].FieldType != null)
					{
						AddType(instanceFields[i].FieldType, xNS);
					}
				}
				Type[] introducedInterfaces = rsType.GetIntroducedInterfaces();
				if (introducedInterfaces.Length > 0)
				{
					for (int j = 0; j < introducedInterfaces.Length; j++)
					{
						AddType(introducedInterfaces[j], xNS);
					}
				}
				ProcessMethods(rsType);
				return;
			}
			FieldInfo[] instanceFields2 = rsType.GetInstanceFields();
			for (int k = 0; k < instanceFields2.Length; k++)
			{
				if (instanceFields2[k].FieldType != null)
				{
					AddType(instanceFields2[k].FieldType, xNS);
				}
			}
		}

		private void ProcessMethods(RealSchemaType rsType)
		{
			XMLNamespace xNS = rsType.XNS;
			MethodInfo[] introducedMethods = rsType.GetIntroducedMethods();
			if (introducedMethods.Length <= 0)
			{
				return;
			}
			string text = null;
			XMLNamespace xMLNamespace = null;
			if (xNS.IsInteropType)
			{
				text = xNS.Name;
				xMLNamespace = xNS;
			}
			else
			{
				StringBuilder stringBuilder = new StringBuilder();
				QualifyName(stringBuilder, xNS.Name, rsType.Name);
				text = stringBuilder.ToString();
				xMLNamespace = AddNamespace(text, xNS.Assem);
				xNS.DependsOnSchemaNS(xMLNamespace, bImport: false);
			}
			foreach (MethodInfo methodInfo in introducedMethods)
			{
				AddType(methodInfo.ReturnType, xMLNamespace);
				ParameterInfo[] parameters = methodInfo.GetParameters();
				for (int j = 0; j < parameters.Length; j++)
				{
					AddType(parameters[j].ParameterType, xMLNamespace);
				}
			}
		}

		private void AddType(Type type, XMLNamespace xns)
		{
			Type type2 = type.GetElementType();
			Type type3 = type2;
			while (type3 != null)
			{
				type3 = type2.GetElementType();
				if (type3 != null)
				{
					type2 = type3;
				}
			}
			if (type2 != null)
			{
				EnqueueType(type2, xns);
			}
			if (!type.IsArray && !type.IsByRef)
			{
				EnqueueType(type, xns);
			}
			if (!type.IsPublic && !type.IsNotPublic)
			{
				string fullName = type.FullName;
				int num = fullName.IndexOf("+");
				if (num > 0)
				{
					string name = fullName.Substring(0, num);
					Assembly assembly = type.Module.Assembly;
					Type type4 = assembly.GetType(name, throwOnError: true);
					EnqueueType(type4, xns);
				}
			}
		}

		private void EnqueueType(Type type, XMLNamespace xns)
		{
			if (!type.IsPrimitive || type == s_charType)
			{
				XMLNamespace xMLNamespace = null;
				string ns;
				Assembly assem;
				bool nSAndAssembly = GetNSAndAssembly(type, out ns, out assem);
				xMLNamespace = LookupNamespace(ns, assem);
				if (xMLNamespace == null)
				{
					xMLNamespace = AddNamespace(ns, assem, nSAndAssembly);
				}
				string text = SudsConverter.MapClrTypeToXsdType(type);
				if (type.IsInterface || text != null || type == s_voidType)
				{
					xns.DependsOnSchemaNS(xMLNamespace, bImport: false);
				}
				else
				{
					xns.DependsOnSchemaNS(xMLNamespace, bImport: true);
				}
				if (!type.FullName.StartsWith("System."))
				{
					_queue.Enqueue(type);
				}
			}
		}

		private static bool GetNSAndAssembly(Type type, out string ns, out Assembly assem)
		{
			string xmlNamespace = null;
			string xmlElement = null;
			bool flag = false;
			SoapServices.GetXmlElementForInteropType(type, out xmlElement, out xmlNamespace);
			if (xmlNamespace != null)
			{
				ns = xmlNamespace;
				assem = type.Module.Assembly;
				return true;
			}
			ns = type.Namespace;
			assem = type.Module.Assembly;
			return false;
		}

		private XMLNamespace LookupNamespace(string name, Assembly assem)
		{
			for (int i = 0; i < _namespaces.Count; i++)
			{
				XMLNamespace xMLNamespace = (XMLNamespace)_namespaces[i];
				if (name == xMLNamespace.Name)
				{
					return xMLNamespace;
				}
			}
			return null;
		}

		private XMLNamespace AddNamespace(string name, Assembly assem)
		{
			return AddNamespace(name, assem, bInteropType: false);
		}

		private XMLNamespace AddNamespace(string name, Assembly assem, bool bInteropType)
		{
			XMLNamespace xMLNamespace = new XMLNamespace(name, assem, _serviceEndpoint, _typeToServiceEndpoint, "ns" + _namespaces.Count, bInteropType, this);
			_namespaces.Add(xMLNamespace);
			return xMLNamespace;
		}

		private XMLNamespace GetNamespace(Type type)
		{
			string ns = null;
			Assembly assem = null;
			bool nSAndAssembly = GetNSAndAssembly(type, out ns, out assem);
			XMLNamespace xMLNamespace = LookupNamespace(ns, assem);
			if (xMLNamespace == null)
			{
				xMLNamespace = AddNamespace(ns, assem, nSAndAssembly);
			}
			return xMLNamespace;
		}

		private void Resolve()
		{
			for (int i = 0; i < _namespaces.Count; i++)
			{
				((XMLNamespace)_namespaces[i]).Resolve();
			}
		}

		private void PrintWsdl()
		{
			if (_targetNS == null || _targetNS.Length == 0)
			{
				if (_namespaces.Count > 0)
				{
					_targetNS = ((XMLNamespace)_namespaces[0]).Namespace;
				}
				else
				{
					_targetNS = "http://schemas.xmlsoap.org/wsdl/";
				}
			}
			string indentStr = "";
			string text = IndentP(indentStr);
			string text2 = IndentP(text);
			string text3 = IndentP(text2);
			IndentP(text3);
			StringBuilder stringBuilder = new StringBuilder(256);
			_textWriter.WriteLine("<?xml version='1.0' encoding='UTF-8'?>");
			stringBuilder.Length = 0;
			stringBuilder.Append("<definitions ");
			if (_name != null)
			{
				stringBuilder.Append("name='");
				stringBuilder.Append(_name);
				stringBuilder.Append("' ");
			}
			stringBuilder.Append("targetNamespace='");
			stringBuilder.Append(_targetNS);
			stringBuilder.Append("'");
			_textWriter.WriteLine(stringBuilder);
			PrintWsdlNamespaces(_textWriter, stringBuilder, text3);
			bool flag = false;
			for (int i = 0; i < _namespaces.Count; i++)
			{
				if (((XMLNamespace)_namespaces[i]).CheckForSchemaContent())
				{
					flag = true;
					break;
				}
			}
			if (flag)
			{
				PrintTypesBeginWsdl(_textWriter, stringBuilder, text);
				for (int j = 0; j < _namespaces.Count; j++)
				{
					if (((XMLNamespace)_namespaces[j]).CheckForSchemaContent())
					{
						((XMLNamespace)_namespaces[j]).PrintSchemaWsdl(_textWriter, stringBuilder, text2);
					}
				}
				PrintTypesEndWsdl(_textWriter, stringBuilder, text);
			}
			ArrayList refNames = new ArrayList(25);
			for (int k = 0; k < _namespaces.Count; k++)
			{
				((XMLNamespace)_namespaces[k]).PrintMessageWsdl(_textWriter, stringBuilder, text, refNames);
			}
			PrintServiceWsdl(_textWriter, stringBuilder, text, refNames);
			_textWriter.WriteLine("</definitions>");
		}

		private void PrintWsdlNamespaces(TextWriter textWriter, StringBuilder sb, string indent)
		{
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns='http://schemas.xmlsoap.org/wsdl/'");
			textWriter.WriteLine(sb);
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns:tns='");
			sb.Append(_targetNS);
			sb.Append("'");
			textWriter.WriteLine(sb);
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns:xsd='");
			sb.Append(SudsConverter.GetXsdVersion(_xsdVersion));
			sb.Append("'");
			textWriter.WriteLine(sb);
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns:xsi='");
			sb.Append(SudsConverter.GetXsiVersion(_xsdVersion));
			sb.Append("'");
			textWriter.WriteLine(sb);
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns:suds='http://www.w3.org/2000/wsdl/suds'");
			textWriter.WriteLine(sb);
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns:wsdl='http://schemas.xmlsoap.org/wsdl/'");
			textWriter.WriteLine(sb);
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns:soapenc='http://schemas.xmlsoap.org/soap/encoding/'");
			textWriter.WriteLine(sb);
			Hashtable usedNames = new Hashtable(10);
			for (int i = 0; i < _namespaces.Count; i++)
			{
				((XMLNamespace)_namespaces[i]).PrintDependsOnWsdl(_textWriter, sb, indent, usedNames);
			}
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("xmlns:soap='http://schemas.xmlsoap.org/wsdl/soap/'>");
			textWriter.WriteLine(sb);
		}

		private void PrintTypesBeginWsdl(TextWriter textWriter, StringBuilder sb, string indent)
		{
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("<types>");
			textWriter.WriteLine(sb);
		}

		private void PrintTypesEndWsdl(TextWriter textWriter, StringBuilder sb, string indent)
		{
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("</types>");
			textWriter.WriteLine(sb);
		}

		internal void PrintServiceWsdl(TextWriter textWriter, StringBuilder sb, string indent, ArrayList refNames)
		{
			string text = IndentP(indent);
			string text2 = IndentP(text);
			IndentP(text2);
			sb.Length = 0;
			sb.Append("\n");
			sb.Append(indent);
			sb.Append("<service name='");
			sb.Append(_name);
			sb.Append("Service'");
			sb.Append(">");
			textWriter.WriteLine(sb);
			for (int i = 0; i < refNames.Count; i++)
			{
				if ((_typeToServiceEndpoint == null || !_typeToServiceEndpoint.ContainsKey(refNames[i])) && _serviceEndpoint == null)
				{
					continue;
				}
				sb.Length = 0;
				sb.Append(text);
				sb.Append("<port name='");
				sb.Append(refNames[i]);
				sb.Append("Port'");
				sb.Append(" ");
				sb.Append("binding='tns:");
				sb.Append(refNames[i]);
				sb.Append("Binding");
				sb.Append("'>");
				textWriter.WriteLine(sb);
				if (_typeToServiceEndpoint != null && _typeToServiceEndpoint.ContainsKey(refNames[i]))
				{
					foreach (string item in (ArrayList)_typeToServiceEndpoint[refNames[i]])
					{
						sb.Length = 0;
						sb.Append(text2);
						sb.Append("<soap:address location='");
						sb.Append(UrlEncode(item));
						sb.Append("'/>");
						textWriter.WriteLine(sb);
					}
				}
				else if (_serviceEndpoint != null)
				{
					sb.Length = 0;
					sb.Append(text2);
					sb.Append("<soap:address location='");
					sb.Append(_serviceEndpoint);
					sb.Append("'/>");
					textWriter.WriteLine(sb);
				}
				sb.Length = 0;
				sb.Append(text);
				sb.Append("</port>");
				textWriter.WriteLine(sb);
			}
			sb.Length = 0;
			sb.Append(indent);
			sb.Append("</service>");
			textWriter.WriteLine(sb);
		}

		private string UrlEncode(string url)
		{
			if (url == null || url.Length == 0)
			{
				return url;
			}
			int num = url.IndexOf("&amp;");
			if (num > -1)
			{
				return url;
			}
			num = url.IndexOf('&');
			if (num > -1)
			{
				return url.Replace("&", "&amp;");
			}
			return url;
		}

		internal static string IndentP(string indentStr)
		{
			return indentStr + "    ";
		}
	}
}
namespace System.Runtime.Remoting.Services
{
	[ComVisible(true)]
	public abstract class RemotingClientProxy : Component
	{
		protected Type _type;

		protected object _tp;

		protected string _url;

		public bool AllowAutoRedirect
		{
			get
			{
				return (bool)ChannelServices.GetChannelSinkProperties(_tp)["allowautoredirect"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["allowautoredirect"] = value;
			}
		}

		public object Cookies => null;

		public bool EnableCookies
		{
			get
			{
				return false;
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public bool PreAuthenticate
		{
			get
			{
				return (bool)ChannelServices.GetChannelSinkProperties(_tp)["preauthenticate"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["preauthenticate"] = value;
			}
		}

		public string Path
		{
			get
			{
				return Url;
			}
			set
			{
				Url = value;
			}
		}

		public int Timeout
		{
			get
			{
				return (int)ChannelServices.GetChannelSinkProperties(_tp)["timeout"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["timeout"] = value;
			}
		}

		public string Url
		{
			get
			{
				return _url;
			}
			set
			{
				lock (this)
				{
					_url = value;
				}
				ConnectProxy();
				ChannelServices.GetChannelSinkProperties(_tp)["url"] = value;
			}
		}

		public string UserAgent
		{
			get
			{
				return HttpClientTransportSink.UserAgent;
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public string Username
		{
			get
			{
				return (string)ChannelServices.GetChannelSinkProperties(_tp)["username"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["username"] = value;
			}
		}

		public string Password
		{
			get
			{
				return (string)ChannelServices.GetChannelSinkProperties(_tp)["password"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["password"] = value;
			}
		}

		public string Domain
		{
			get
			{
				return (string)ChannelServices.GetChannelSinkProperties(_tp)["domain"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["domain"] = value;
			}
		}

		public string ProxyName
		{
			get
			{
				return (string)ChannelServices.GetChannelSinkProperties(_tp)["proxyname"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["Proxyname"] = value;
			}
		}

		public int ProxyPort
		{
			get
			{
				return (int)ChannelServices.GetChannelSinkProperties(_tp)["proxyport"];
			}
			set
			{
				ChannelServices.GetChannelSinkProperties(_tp)["proxyport"] = value;
			}
		}

		protected void ConfigureProxy(Type type, string url)
		{
			lock (this)
			{
				_type = type;
				Url = url;
			}
		}

		protected void ConnectProxy()
		{
			lock (this)
			{
				_tp = null;
				_tp = Activator.GetObject(_type, _url);
			}
		}
	}
	public class RemotingService : Component
	{
		public HttpApplicationState Application => Context.Application;

		public HttpContext Context
		{
			get
			{
				HttpContext current = HttpContext.Current;
				if (current == null)
				{
					throw new RemotingException(CoreChannel.GetResourceString("Remoting_HttpContextNotAvailable"));
				}
				return current;
			}
		}

		public HttpSessionState Session => Context.Session;

		public HttpServerUtility Server => Context.Server;

		public IPrincipal User => Context.User;
	}
}
