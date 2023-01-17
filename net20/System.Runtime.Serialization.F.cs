
// C:\WINDOWS\assembly\GAC_MSIL\System.Runtime.Serialization.Formatters.Soap\2.0.0.0__b03f5f7f11d50a3a\System.Runtime.Serialization.Formatters.Soap.dll
// System.Runtime.Serialization.Formatters.Soap, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
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
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Activation;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Remoting.Metadata;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security;
using System.Security.Permissions;
using System.Text;
using System.Xml;

[assembly: ComVisible(true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: CompilationRelaxations(8)]
[assembly: CLSCompliant(true)]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyInformationalVersion("2.0.50727.9149")]
[assembly: AssemblyTitle("System.Runtime.Serialization.Formatters.Soap.dll")]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: AssemblyFileVersion("2.0.50727.9149")]
[assembly: AssemblyCopyright("© Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyProduct("Microsoft® .NET Framework")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyDefaultAlias("System.Runtime.Serialization.Formatters.Soap.dll")]
[assembly: AssemblyDescription("System.Runtime.Serialization.Formatters.Soap.dll")]
[assembly: AssemblyVersion("2.0.0.0")]
namespace System.Runtime.Serialization.Formatters.Soap
{
	public sealed class SoapFormatter : IRemotingFormatter, IFormatter
	{
		private SoapParser soapParser;

		private ISurrogateSelector m_surrogates;

		private StreamingContext m_context;

		private FormatterTypeStyle m_typeFormat;

		private ISoapMessage m_topObject;

		private FormatterAssemblyStyle m_assemblyFormat = FormatterAssemblyStyle.Full;

		private TypeFilterLevel m_securityLevel = TypeFilterLevel.Full;

		private SerializationBinder m_binder;

		private Stream currentStream;

		public ISoapMessage TopObject
		{
			get
			{
				return m_topObject;
			}
			set
			{
				m_topObject = value;
			}
		}

		public FormatterTypeStyle TypeFormat
		{
			get
			{
				return m_typeFormat;
			}
			set
			{
				if (value == FormatterTypeStyle.TypesWhenNeeded)
				{
					m_typeFormat = FormatterTypeStyle.TypesWhenNeeded;
				}
				else
				{
					m_typeFormat |= value;
				}
			}
		}

		public FormatterAssemblyStyle AssemblyFormat
		{
			get
			{
				return m_assemblyFormat;
			}
			set
			{
				m_assemblyFormat = value;
			}
		}

		public TypeFilterLevel FilterLevel
		{
			get
			{
				return m_securityLevel;
			}
			set
			{
				m_securityLevel = value;
			}
		}

		public ISurrogateSelector SurrogateSelector
		{
			get
			{
				return m_surrogates;
			}
			set
			{
				m_surrogates = value;
			}
		}

		public SerializationBinder Binder
		{
			get
			{
				return m_binder;
			}
			set
			{
				m_binder = value;
			}
		}

		public StreamingContext Context
		{
			get
			{
				return m_context;
			}
			set
			{
				m_context = value;
			}
		}

		public SoapFormatter()
		{
			m_surrogates = null;
			m_context = new StreamingContext(StreamingContextStates.All);
		}

		public SoapFormatter(ISurrogateSelector selector, StreamingContext context)
		{
			m_surrogates = selector;
			m_context = context;
		}

		public object Deserialize(Stream serializationStream)
		{
			return Deserialize(serializationStream, null);
		}

		public object Deserialize(Stream serializationStream, HeaderHandler handler)
		{
			if (serializationStream == null)
			{
				throw new ArgumentNullException("serializationStream");
			}
			if (serializationStream.CanSeek && serializationStream.Length == 0)
			{
				throw new SerializationException(SoapUtil.GetResourceString("Serialization_Stream"));
			}
			InternalFE internalFE = new InternalFE();
			internalFE.FEtypeFormat = m_typeFormat;
			internalFE.FEtopObject = m_topObject;
			internalFE.FEserializerTypeEnum = InternalSerializerTypeE.Soap;
			internalFE.FEassemblyFormat = m_assemblyFormat;
			internalFE.FEsecurityLevel = m_securityLevel;
			ObjectReader objectReader = new ObjectReader(serializationStream, m_surrogates, m_context, internalFE, m_binder);
			if (soapParser == null || serializationStream != currentStream)
			{
				soapParser = new SoapParser(serializationStream);
				currentStream = serializationStream;
			}
			soapParser.Init(objectReader);
			return objectReader.Deserialize(handler, soapParser);
		}

		public void Serialize(Stream serializationStream, object graph)
		{
			Serialize(serializationStream, graph, null);
		}

		public void Serialize(Stream serializationStream, object graph, Header[] headers)
		{
			if (serializationStream == null)
			{
				throw new ArgumentNullException("serializationStream");
			}
			InternalFE internalFE = new InternalFE();
			internalFE.FEtypeFormat = m_typeFormat;
			internalFE.FEtopObject = m_topObject;
			internalFE.FEserializerTypeEnum = InternalSerializerTypeE.Soap;
			internalFE.FEassemblyFormat = m_assemblyFormat;
			ObjectWriter objectWriter = new ObjectWriter(serializationStream, m_surrogates, m_context, internalFE);
			objectWriter.Serialize(graph, headers, new SoapWriter(serializationStream));
		}
	}
	internal interface ISerParser
	{
		void Run();
	}
	internal sealed class SoapParser : ISerParser
	{
		internal XmlTextReader xmlReader;

		internal SoapHandler soapHandler;

		internal ObjectReader objectReader;

		internal bool bStop;

		private int depth;

		private bool bDebug;

		private TextReader textReader;

		internal SoapParser(Stream stream)
		{
			if (bDebug)
			{
				xmlReader = new XmlTextReader(textReader);
			}
			else
			{
				xmlReader = new XmlTextReader(stream);
			}
			xmlReader.XmlResolver = null;
			xmlReader.ProhibitDtd = true;
			soapHandler = new SoapHandler(this);
		}

		[Conditional("_LOGGING")]
		private void TraceStream(Stream stream)
		{
			bDebug = true;
			TextReader textReader = new StreamReader(stream);
			string s = textReader.ReadToEnd();
			this.textReader = new StringReader(s);
		}

		internal void Init(ObjectReader objectReader)
		{
			this.objectReader = objectReader;
			soapHandler.Init(objectReader);
			bStop = false;
			depth = 0;
			xmlReader.ResetState();
		}

		public void Run()
		{
			try
			{
				soapHandler.Start(xmlReader);
				ParseXml();
			}
			catch (EndOfStreamException)
			{
			}
		}

		internal void Stop()
		{
			bStop = true;
		}

		private void ParseXml()
		{
			while (!bStop && xmlReader.Read())
			{
				if (depth < xmlReader.Depth)
				{
					soapHandler.StartChildren();
					depth = xmlReader.Depth;
				}
				else if (depth > xmlReader.Depth)
				{
					soapHandler.FinishChildren(xmlReader.Prefix, xmlReader.LocalName, xmlReader.NamespaceURI);
					depth = xmlReader.Depth;
				}
				switch (xmlReader.NodeType)
				{
				case XmlNodeType.Element:
					soapHandler.StartElement(xmlReader.Prefix, xmlReader.LocalName, xmlReader.NamespaceURI);
					_ = xmlReader.AttributeCount;
					while (xmlReader.MoveToNextAttribute())
					{
						soapHandler.Attribute(xmlReader.Prefix, xmlReader.LocalName, xmlReader.NamespaceURI, xmlReader.Value);
					}
					xmlReader.MoveToElement();
					if (xmlReader.IsEmptyElement)
					{
						soapHandler.EndElement(xmlReader.Prefix, xmlReader.LocalName, xmlReader.NamespaceURI);
					}
					break;
				case XmlNodeType.EndElement:
					soapHandler.EndElement(xmlReader.Prefix, xmlReader.LocalName, xmlReader.NamespaceURI);
					break;
				case XmlNodeType.Text:
					soapHandler.Text(xmlReader.Value);
					break;
				case XmlNodeType.SignificantWhitespace:
					soapHandler.Text(xmlReader.Value);
					break;
				case XmlNodeType.Whitespace:
					soapHandler.Text(xmlReader.Value);
					break;
				case XmlNodeType.CDATA:
					soapHandler.Text(xmlReader.Value);
					break;
				case XmlNodeType.Comment:
					soapHandler.Comment(xmlReader.Value);
					break;
				}
			}
		}

		[Conditional("SER_LOGGING")]
		private static void Dump(string name, XmlReader xmlReader)
		{
		}
	}
	internal sealed class SoapHandler
	{
		internal class AttributeValueEntry
		{
			internal string prefix;

			internal string key;

			internal string value;

			internal string urn;

			internal AttributeValueEntry(string prefix, string key, string value, string urn)
			{
				this.prefix = prefix;
				this.key = key;
				this.value = value;
				this.urn = urn;
			}
		}

		[Serializable]
		private enum HeaderStateEnum
		{
			None,
			FirstHeaderRecord,
			HeaderRecord,
			NestedObject,
			TopLevelObject
		}

		private SerStack stack = new SerStack("SoapParser Stack");

		private XmlTextReader xmlTextReader;

		private SoapParser soapParser;

		private string textValue = "";

		private ObjectReader objectReader;

		internal Hashtable keyToNamespaceTable;

		private InternalParseStateE currentState;

		private bool isEnvelope;

		private bool isBody;

		private bool isTopFound;

		private HeaderStateEnum headerState;

		private SerStack attributeValues = new SerStack("AttributePrefix");

		private SerStack prPool = new SerStack("prPool");

		private Hashtable assemKeyToAssemblyTable;

		private Hashtable assemKeyToNameSpaceTable;

		private Hashtable assemKeyToInteropAssemblyTable;

		private Hashtable nameSpaceToKey;

		private string soapKey = "SOAP-ENC";

		private string urtKey = "urt";

		private string soapEnvKey = "SOAP-ENV";

		private string xsiKey = "xsi";

		private string xsdKey = "xsd";

		private int nextPrefix;

		private StringBuilder sburi = new StringBuilder(50);

		private StringBuilder stringBuffer = new StringBuilder(120);

		private NameCache nameCache = new NameCache();

		private ArrayList xmlAttributeList;

		private ArrayList headerList;

		private int headerArrayLength;

		internal SoapHandler(SoapParser soapParser)
		{
			this.soapParser = soapParser;
		}

		internal void Init(ObjectReader objectReader)
		{
			this.objectReader = objectReader;
			objectReader.soapHandler = this;
			isEnvelope = false;
			isBody = false;
			isTopFound = false;
			attributeValues.Clear();
			assemKeyToAssemblyTable = new Hashtable(10);
			assemKeyToAssemblyTable[urtKey] = new SoapAssemblyInfo(SoapUtil.urtAssemblyString, SoapUtil.urtAssembly);
			assemKeyToNameSpaceTable = new Hashtable(10);
			assemKeyToInteropAssemblyTable = new Hashtable(10);
			nameSpaceToKey = new Hashtable(5);
			keyToNamespaceTable = new Hashtable(10);
		}

		private string NextPrefix()
		{
			nextPrefix++;
			return "_P" + nextPrefix;
		}

		private ParseRecord GetPr()
		{
			ParseRecord parseRecord = null;
			if (!prPool.IsEmpty())
			{
				parseRecord = (ParseRecord)prPool.Pop();
				parseRecord.Init();
			}
			else
			{
				parseRecord = new ParseRecord();
			}
			return parseRecord;
		}

		private void PutPr(ParseRecord pr)
		{
			prPool.Push(pr);
		}

		private static string SerTraceString(string handler, ParseRecord pr, string value, InternalParseStateE currentState, HeaderStateEnum headerState)
		{
			string text = "";
			if (value != null)
			{
				text = value;
			}
			string text2 = "";
			if (pr != null)
			{
				text2 = pr.PRparseStateEnum.ToString();
			}
			return handler + " - " + text + ", State " + currentState.ToString() + ", PushState " + text2;
		}

		private void MarshalError(string handler, ParseRecord pr, string value, InternalParseStateE currentState)
		{
			string text = SerTraceString(handler, pr, value, currentState, headerState);
			throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Syntax"), text));
		}

		internal void Start(XmlTextReader p)
		{
			currentState = InternalParseStateE.Object;
			xmlTextReader = p;
		}

		internal void StartElement(string prefix, string name, string urn)
		{
			string text = NameFilter(name);
			string text2 = prefix;
			ParseRecord parseRecord = null;
			if (urn != null && urn.Length != 0 && (prefix == null || prefix.Length == 0))
			{
				if (nameSpaceToKey.ContainsKey(urn))
				{
					text2 = (string)nameSpaceToKey[urn];
				}
				else
				{
					text2 = NextPrefix();
					nameSpaceToKey[urn] = text2;
				}
			}
			switch (currentState)
			{
			case InternalParseStateE.Object:
				parseRecord = GetPr();
				parseRecord.PRname = text;
				parseRecord.PRnameXmlKey = text2;
				parseRecord.PRxmlNameSpace = urn;
				parseRecord.PRparseStateEnum = InternalParseStateE.Object;
				if (string.Compare(name, "Array", StringComparison.OrdinalIgnoreCase) == 0 && text2.Equals(soapKey))
				{
					parseRecord.PRparseTypeEnum = InternalParseTypeE.Object;
				}
				else if ((string.Compare(name, "anyType", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(name, "ur-type", StringComparison.OrdinalIgnoreCase) == 0) && text2.Equals(xsdKey))
				{
					parseRecord.PRname = "System.Object";
					parseRecord.PRnameXmlKey = urtKey;
					parseRecord.PRxmlNameSpace = urn;
					parseRecord.PRparseTypeEnum = InternalParseTypeE.Object;
				}
				else if (string.Compare(urn, "http://schemas.xmlsoap.org/soap/envelope/", StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (string.Compare(name, "Envelope", StringComparison.OrdinalIgnoreCase) == 0)
					{
						if (isEnvelope)
						{
							throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Parser_Envelope"), prefix + ":" + name));
						}
						isEnvelope = true;
						parseRecord.PRparseTypeEnum = InternalParseTypeE.Envelope;
					}
					else if (string.Compare(name, "Body", StringComparison.OrdinalIgnoreCase) == 0)
					{
						if (!isEnvelope)
						{
							throw new SerializationException(SoapUtil.GetResourceString("Serialization_Parser_BodyChild"));
						}
						if (isBody)
						{
							throw new SerializationException(SoapUtil.GetResourceString("Serialization_Parser_BodyOnce"));
						}
						isBody = true;
						headerState = HeaderStateEnum.None;
						isTopFound = false;
						parseRecord.PRparseTypeEnum = InternalParseTypeE.Body;
					}
					else if (string.Compare(name, "Header", StringComparison.OrdinalIgnoreCase) == 0)
					{
						if (!isEnvelope)
						{
							throw new SerializationException(SoapUtil.GetResourceString("Serialization_Parser_Header"));
						}
						parseRecord.PRparseTypeEnum = InternalParseTypeE.Headers;
						headerState = HeaderStateEnum.FirstHeaderRecord;
					}
					else
					{
						parseRecord.PRparseTypeEnum = InternalParseTypeE.Object;
					}
				}
				else
				{
					parseRecord.PRparseTypeEnum = InternalParseTypeE.Object;
				}
				stack.Push(parseRecord);
				break;
			case InternalParseStateE.Member:
			{
				parseRecord = GetPr();
				ParseRecord objectPr = (ParseRecord)stack.Peek();
				parseRecord.PRname = text;
				parseRecord.PRnameXmlKey = text2;
				parseRecord.PRxmlNameSpace = urn;
				parseRecord.PRparseTypeEnum = InternalParseTypeE.Member;
				parseRecord.PRparseStateEnum = InternalParseStateE.Member;
				stack.Push(parseRecord);
				break;
			}
			case InternalParseStateE.MemberChild:
			{
				ParseRecord objectPr = (ParseRecord)stack.PeekPeek();
				parseRecord = (ParseRecord)stack.Peek();
				parseRecord.PRmemberValueEnum = InternalMemberValueE.Nested;
				ProcessAttributes(parseRecord, objectPr);
				switch (headerState)
				{
				case HeaderStateEnum.None:
				case HeaderStateEnum.TopLevelObject:
					objectReader.Parse(parseRecord);
					parseRecord.PRisParsed = true;
					break;
				case HeaderStateEnum.HeaderRecord:
				case HeaderStateEnum.NestedObject:
					ProcessHeaderMember(parseRecord);
					break;
				}
				ParseRecord pr = GetPr();
				pr.PRparseTypeEnum = InternalParseTypeE.Member;
				pr.PRparseStateEnum = InternalParseStateE.Member;
				pr.PRname = text;
				pr.PRnameXmlKey = text2;
				parseRecord.PRxmlNameSpace = urn;
				currentState = InternalParseStateE.Member;
				stack.Push(pr);
				break;
			}
			default:
				MarshalError("StartElement", (ParseRecord)stack.Peek(), text, currentState);
				break;
			}
		}

		internal void EndElement(string prefix, string name, string urn)
		{
			string value = NameFilter(name);
			ParseRecord parseRecord = null;
			ParseRecord parseRecord2 = null;
			switch (currentState)
			{
			case InternalParseStateE.Object:
				parseRecord2 = (ParseRecord)stack.Pop();
				if (parseRecord2.PRparseTypeEnum == InternalParseTypeE.Envelope)
				{
					parseRecord2.PRparseTypeEnum = InternalParseTypeE.EnvelopeEnd;
				}
				else if (parseRecord2.PRparseTypeEnum == InternalParseTypeE.Body)
				{
					parseRecord2.PRparseTypeEnum = InternalParseTypeE.BodyEnd;
				}
				else if (parseRecord2.PRparseTypeEnum == InternalParseTypeE.Headers)
				{
					parseRecord2.PRparseTypeEnum = InternalParseTypeE.HeadersEnd;
					headerState = HeaderStateEnum.HeaderRecord;
				}
				else if (parseRecord2.PRarrayTypeEnum != InternalArrayTypeE.Base64)
				{
					parseRecord = (ParseRecord)stack.Peek();
					if (!isTopFound && parseRecord != null && parseRecord.PRparseTypeEnum == InternalParseTypeE.Body)
					{
						parseRecord2.PRobjectPositionEnum = InternalObjectPositionE.Top;
						isTopFound = true;
					}
					if (!parseRecord2.PRisParsed)
					{
						if (!parseRecord2.PRisProcessAttributes && (parseRecord2.PRobjectPositionEnum != InternalObjectPositionE.Top || !objectReader.IsFakeTopObject))
						{
							ProcessAttributes(parseRecord2, parseRecord);
						}
						objectReader.Parse(parseRecord2);
						parseRecord2.PRisParsed = true;
					}
					parseRecord2.PRparseTypeEnum = InternalParseTypeE.ObjectEnd;
				}
				switch (headerState)
				{
				case HeaderStateEnum.None:
				case HeaderStateEnum.TopLevelObject:
					objectReader.Parse(parseRecord2);
					break;
				case HeaderStateEnum.HeaderRecord:
				case HeaderStateEnum.NestedObject:
					ProcessHeaderEnd(parseRecord2);
					break;
				}
				if (parseRecord2.PRparseTypeEnum == InternalParseTypeE.EnvelopeEnd)
				{
					soapParser.Stop();
				}
				PutPr(parseRecord2);
				break;
			case InternalParseStateE.Member:
				parseRecord2 = (ParseRecord)stack.Peek();
				parseRecord = (ParseRecord)stack.PeekPeek();
				ProcessAttributes(parseRecord2, parseRecord);
				_ = xmlAttributeList;
				if (xmlAttributeList != null && xmlAttributeList.Count > 0)
				{
					for (int i = 0; i < xmlAttributeList.Count; i++)
					{
						objectReader.Parse((ParseRecord)xmlAttributeList[i]);
					}
					xmlAttributeList.Clear();
				}
				parseRecord2 = (ParseRecord)stack.Pop();
				if (headerState == HeaderStateEnum.TopLevelObject && parseRecord2.PRarrayTypeEnum == InternalArrayTypeE.Base64)
				{
					objectReader.Parse(parseRecord2);
					parseRecord2.PRisParsed = true;
				}
				else if (parseRecord2.PRmemberValueEnum != InternalMemberValueE.Nested)
				{
					if (parseRecord2.PRobjectTypeEnum == InternalObjectTypeE.Array && parseRecord2.PRmemberValueEnum != InternalMemberValueE.Null)
					{
						parseRecord2.PRmemberValueEnum = InternalMemberValueE.Nested;
						objectReader.Parse(parseRecord2);
						parseRecord2.PRisParsed = true;
						parseRecord2.PRparseTypeEnum = InternalParseTypeE.MemberEnd;
					}
					else if (parseRecord2.PRidRef > 0)
					{
						parseRecord2.PRmemberValueEnum = InternalMemberValueE.Reference;
					}
					else if (parseRecord2.PRmemberValueEnum != InternalMemberValueE.Null)
					{
						parseRecord2.PRmemberValueEnum = InternalMemberValueE.InlineValue;
					}
					switch (headerState)
					{
					case HeaderStateEnum.None:
					case HeaderStateEnum.TopLevelObject:
						if (parseRecord2.PRparseTypeEnum == InternalParseTypeE.Object)
						{
							if (!parseRecord2.PRisParsed)
							{
								objectReader.Parse(parseRecord2);
							}
							parseRecord2.PRparseTypeEnum = InternalParseTypeE.ObjectEnd;
						}
						objectReader.Parse(parseRecord2);
						parseRecord2.PRisParsed = true;
						break;
					case HeaderStateEnum.HeaderRecord:
					case HeaderStateEnum.NestedObject:
						ProcessHeaderMember(parseRecord2);
						break;
					}
				}
				else
				{
					parseRecord2.PRparseTypeEnum = InternalParseTypeE.MemberEnd;
					switch (headerState)
					{
					case HeaderStateEnum.None:
					case HeaderStateEnum.TopLevelObject:
						objectReader.Parse(parseRecord2);
						parseRecord2.PRisParsed = true;
						break;
					case HeaderStateEnum.HeaderRecord:
					case HeaderStateEnum.NestedObject:
						ProcessHeaderMemberEnd(parseRecord2);
						break;
					}
				}
				PutPr(parseRecord2);
				break;
			case InternalParseStateE.MemberChild:
				parseRecord2 = (ParseRecord)stack.Peek();
				if (parseRecord2.PRmemberValueEnum != InternalMemberValueE.Null)
				{
					MarshalError("EndElement", (ParseRecord)stack.Peek(), value, currentState);
				}
				break;
			default:
				MarshalError("EndElement", (ParseRecord)stack.Peek(), value, currentState);
				break;
			}
		}

		internal void StartChildren()
		{
			ParseRecord parseRecord = null;
			switch (currentState)
			{
			case InternalParseStateE.Object:
			{
				parseRecord = (ParseRecord)stack.Peek();
				ParseRecord parseRecord2 = (ParseRecord)stack.PeekPeek();
				ProcessAttributes(parseRecord, parseRecord2);
				if (parseRecord.PRarrayTypeEnum == InternalArrayTypeE.Base64)
				{
					break;
				}
				if (parseRecord.PRparseTypeEnum != InternalParseTypeE.Envelope && parseRecord.PRparseTypeEnum != InternalParseTypeE.Body)
				{
					currentState = InternalParseStateE.Member;
				}
				switch (headerState)
				{
				case HeaderStateEnum.None:
				case HeaderStateEnum.TopLevelObject:
					if (!isTopFound && parseRecord2 != null && parseRecord2.PRparseTypeEnum == InternalParseTypeE.Body)
					{
						parseRecord.PRobjectPositionEnum = InternalObjectPositionE.Top;
						isTopFound = true;
					}
					objectReader.Parse(parseRecord);
					parseRecord.PRisParsed = true;
					break;
				case HeaderStateEnum.FirstHeaderRecord:
				case HeaderStateEnum.HeaderRecord:
				case HeaderStateEnum.NestedObject:
					ProcessHeader(parseRecord);
					break;
				}
				break;
			}
			case InternalParseStateE.Member:
				parseRecord = (ParseRecord)stack.Peek();
				currentState = InternalParseStateE.MemberChild;
				break;
			default:
				MarshalError("StartChildren", (ParseRecord)stack.Peek(), null, currentState);
				break;
			}
		}

		internal void FinishChildren(string prefix, string name, string urn)
		{
			ParseRecord parseRecord = null;
			switch (currentState)
			{
			case InternalParseStateE.Member:
				parseRecord = (ParseRecord)stack.Peek();
				currentState = parseRecord.PRparseStateEnum;
				parseRecord.PRvalue = textValue;
				textValue = "";
				break;
			case InternalParseStateE.MemberChild:
				parseRecord = (ParseRecord)stack.Peek();
				currentState = parseRecord.PRparseStateEnum;
				_ = (ParseRecord)stack.PeekPeek();
				parseRecord.PRvalue = textValue;
				textValue = "";
				break;
			case InternalParseStateE.Object:
				parseRecord = (ParseRecord)stack.Peek();
				if (parseRecord.PRarrayTypeEnum == InternalArrayTypeE.Base64)
				{
					parseRecord.PRvalue = textValue;
					textValue = "";
				}
				break;
			default:
				MarshalError("FinishChildren", (ParseRecord)stack.Peek(), name, currentState);
				break;
			}
		}

		internal void Attribute(string prefix, string name, string urn, string value)
		{
			switch (currentState)
			{
			case InternalParseStateE.Object:
			case InternalParseStateE.Member:
			{
				_ = (ParseRecord)stack.Peek();
				string text = name;
				if (urn != null && urn.Length != 0 && (prefix == null || prefix.Length == 0))
				{
					if (nameSpaceToKey.ContainsKey(urn))
					{
						text = (string)nameSpaceToKey[urn];
					}
					else
					{
						text = NextPrefix();
						nameSpaceToKey[urn] = text;
					}
				}
				if (prefix != null && text != null && value != null && urn != null)
				{
					attributeValues.Push(new AttributeValueEntry(prefix, text, value, urn));
				}
				break;
			}
			default:
				MarshalError("EndAttribute, Unknown State ", (ParseRecord)stack.Peek(), name, currentState);
				break;
			}
		}

		internal void Text(string text)
		{
			textValue = text;
		}

		internal void Comment(string body)
		{
		}

		private void ProcessAttributes(ParseRecord pr, ParseRecord objectPr)
		{
			string text = null;
			string text2 = null;
			string text3 = null;
			pr.PRisProcessAttributes = true;
			string text4 = "http://schemas.xmlsoap.org/soap/encoding/";
			int length = text4.Length;
			string text5 = "http://schemas.microsoft.com/clr/id";
			int length2 = text5.Length;
			string text6 = "http://schemas.xmlsoap.org/soap/envelope/";
			int length3 = text6.Length;
			string text7 = "http://www.w3.org/2001/XMLSchema-instance";
			int length4 = text7.Length;
			string text8 = "http://www.w3.org/2000/10/XMLSchema-instance";
			int length5 = text8.Length;
			string text9 = "http://www.w3.org/1999/XMLSchema-instance";
			int length6 = text9.Length;
			string text10 = "http://www.w3.org/1999/XMLSchema";
			int length7 = text10.Length;
			string text11 = "http://www.w3.org/2000/10/XMLSchema";
			int length8 = text11.Length;
			string text12 = "http://www.w3.org/2001/XMLSchema";
			int length9 = text12.Length;
			string text13 = "http://schemas.microsoft.com/soap/encoding/clr/1.0";
			int length10 = text13.Length;
			for (int i = 0; i < attributeValues.Count(); i++)
			{
				AttributeValueEntry attributeValueEntry = (AttributeValueEntry)attributeValues.GetItem(i);
				string prefix = attributeValueEntry.prefix;
				string text14 = attributeValueEntry.key;
				if (text14 == null || text14.Length == 0)
				{
					text14 = pr.PRnameXmlKey;
				}
				string value = attributeValueEntry.value;
				bool flag = false;
				string urn = attributeValueEntry.urn;
				int length11 = text14.Length;
				int length12 = value.Length;
				if (text14 == null || length11 == 0)
				{
					keyToNamespaceTable[prefix] = value;
				}
				else
				{
					keyToNamespaceTable[prefix + ":" + text14] = value;
				}
				if (length11 == 2 && string.Compare(text14, "id", StringComparison.OrdinalIgnoreCase) == 0)
				{
					pr.PRobjectId = objectReader.GetId(value);
				}
				else if (length11 == 8 && string.Compare(text14, "position", StringComparison.OrdinalIgnoreCase) == 0)
				{
					text = value;
				}
				else if (length11 == 6 && string.Compare(text14, "offset", StringComparison.OrdinalIgnoreCase) == 0)
				{
					text2 = value;
				}
				else if (length11 == 14 && string.Compare(text14, "MustUnderstand", StringComparison.OrdinalIgnoreCase) == 0)
				{
					text3 = value;
				}
				else if (length11 == 4 && string.Compare(text14, "null", StringComparison.OrdinalIgnoreCase) == 0)
				{
					pr.PRmemberValueEnum = InternalMemberValueE.Null;
					pr.PRvalue = null;
				}
				else if (length11 == 4 && string.Compare(text14, "root", StringComparison.OrdinalIgnoreCase) == 0)
				{
					if (value.Equals("1"))
					{
						pr.PRisHeaderRoot = true;
					}
				}
				else if (length11 == 4 && string.Compare(text14, "href", StringComparison.OrdinalIgnoreCase) == 0)
				{
					pr.PRidRef = objectReader.GetId(value);
				}
				else if (length11 == 4 && string.Compare(text14, "type", StringComparison.OrdinalIgnoreCase) == 0)
				{
					string pRtypeXmlKey = pr.PRtypeXmlKey;
					string pRkeyDt = pr.PRkeyDt;
					Type pRdtType = pr.PRdtType;
					string text15 = value;
					int num = value.IndexOf(":");
					if (num > 0)
					{
						pr.PRtypeXmlKey = value.Substring(0, num);
						text15 = value.Substring(++num);
					}
					else
					{
						pr.PRtypeXmlKey = prefix;
					}
					if (string.Compare(text15, "anyType", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(text15, "ur-type", StringComparison.OrdinalIgnoreCase) == 0)
					{
						pr.PRkeyDt = "System.Object";
						pr.PRdtType = SoapUtil.typeofObject;
						pr.PRtypeXmlKey = urtKey;
					}
					if (pr.PRtypeXmlKey == soapKey && text15 == "Array")
					{
						pr.PRtypeXmlKey = pRtypeXmlKey;
						pr.PRkeyDt = pRkeyDt;
						pr.PRdtType = pRdtType;
					}
					else
					{
						pr.PRkeyDt = text15;
					}
				}
				else if (length11 == 9 && string.Compare(text14, "arraytype", StringComparison.OrdinalIgnoreCase) == 0)
				{
					string text16 = value;
					int num2 = value.IndexOf(":");
					if (num2 > 0)
					{
						pr.PRtypeXmlKey = value.Substring(0, num2);
						text16 = (pr.PRkeyDt = value.Substring(++num2));
					}
					if (text16.StartsWith("ur_type[", StringComparison.Ordinal))
					{
						pr.PRkeyDt = "System.Object" + text16.Substring(6);
						pr.PRtypeXmlKey = urtKey;
					}
				}
				else if (SoapServices.IsClrTypeNamespace(value))
				{
					if (assemKeyToAssemblyTable.ContainsKey(text14))
					{
						continue;
					}
					string typeNamespace = null;
					string assemblyName = null;
					SoapServices.DecodeXmlNamespaceForClrTypeNamespace(value, out typeNamespace, out assemblyName);
					if (assemblyName == null)
					{
						assemKeyToAssemblyTable[text14] = new SoapAssemblyInfo(SoapUtil.urtAssemblyString, SoapUtil.urtAssembly);
						assemKeyToNameSpaceTable[text14] = typeNamespace;
						continue;
					}
					assemKeyToAssemblyTable[text14] = new SoapAssemblyInfo(assemblyName);
					if (typeNamespace != null)
					{
						assemKeyToNameSpaceTable[text14] = typeNamespace;
					}
				}
				else if ((flag = prefix.Equals("xmlns")) && length12 == length && string.Compare(value, text4, StringComparison.OrdinalIgnoreCase) == 0)
				{
					soapKey = text14;
				}
				else if (flag && length12 == length2 && string.Compare(value, text5, StringComparison.OrdinalIgnoreCase) == 0)
				{
					urtKey = text14;
					assemKeyToAssemblyTable[urtKey] = new SoapAssemblyInfo(SoapUtil.urtAssemblyString, SoapUtil.urtAssembly);
				}
				else if (flag && length12 == length3 && string.Compare(value, text6, StringComparison.OrdinalIgnoreCase) == 0)
				{
					soapEnvKey = text14;
				}
				else if (!(text14 == "encodingStyle"))
				{
					if (flag && ((length12 == length4 && string.Compare(value, text7, StringComparison.OrdinalIgnoreCase) == 0) || (length12 == length6 && string.Compare(value, text9, StringComparison.OrdinalIgnoreCase) == 0) || (length12 == length5 && string.Compare(value, text8, StringComparison.OrdinalIgnoreCase) == 0)))
					{
						xsiKey = text14;
					}
					else if ((flag && length12 == length9 && string.Compare(value, text12, StringComparison.OrdinalIgnoreCase) == 0) || (length12 == length7 && string.Compare(value, text10, StringComparison.OrdinalIgnoreCase) == 0) || (length12 == length8 && string.Compare(value, text11, StringComparison.OrdinalIgnoreCase) == 0))
					{
						xsdKey = text14;
					}
					else if (flag && length12 == length10 && string.Compare(value, text13, StringComparison.OrdinalIgnoreCase) == 0)
					{
						objectReader.SetVersion(1, 0);
					}
					else if (flag)
					{
						assemKeyToInteropAssemblyTable[text14] = value;
					}
					else if (string.Compare(prefix, soapKey, StringComparison.OrdinalIgnoreCase) != 0 && assemKeyToInteropAssemblyTable.ContainsKey(prefix) && ((string)assemKeyToInteropAssemblyTable[prefix]).Equals(urn))
					{
						ProcessXmlAttribute(prefix, text14, value, objectPr);
					}
				}
			}
			attributeValues.Clear();
			if (headerState != 0)
			{
				if (objectPr.PRparseTypeEnum == InternalParseTypeE.Headers)
				{
					if (pr.PRisHeaderRoot || headerState == HeaderStateEnum.FirstHeaderRecord)
					{
						headerState = HeaderStateEnum.HeaderRecord;
					}
					else
					{
						headerState = HeaderStateEnum.TopLevelObject;
						currentState = InternalParseStateE.Object;
						pr.PRobjectTypeEnum = InternalObjectTypeE.Object;
						pr.PRparseTypeEnum = InternalParseTypeE.Object;
						pr.PRparseStateEnum = InternalParseStateE.Object;
						pr.PRmemberTypeEnum = InternalMemberTypeE.Empty;
						pr.PRmemberValueEnum = InternalMemberValueE.Empty;
					}
				}
				else if (objectPr.PRisHeaderRoot)
				{
					headerState = HeaderStateEnum.NestedObject;
				}
			}
			if (!isTopFound && objectPr != null && objectPr.PRparseTypeEnum == InternalParseTypeE.Body)
			{
				pr.PRobjectPositionEnum = InternalObjectPositionE.Top;
				isTopFound = true;
			}
			else if (pr.PRobjectPositionEnum != InternalObjectPositionE.Top)
			{
				pr.PRobjectPositionEnum = InternalObjectPositionE.Child;
			}
			if (pr.PRparseTypeEnum != InternalParseTypeE.Envelope && pr.PRparseTypeEnum != InternalParseTypeE.Body && pr.PRparseTypeEnum != InternalParseTypeE.Headers && (pr.PRobjectPositionEnum != InternalObjectPositionE.Top || !objectReader.IsFakeTopObject || pr.PRnameXmlKey.Equals(soapEnvKey)))
			{
				ProcessType(pr, objectPr);
			}
			if (text != null)
			{
				pr.PRpositionA = ParseArrayDimensions(text, out var _, out var _, out var _);
			}
			if (text2 != null)
			{
				pr.PRlowerBoundA = ParseArrayDimensions(text2, out var _, out var _, out var _);
			}
			if (text3 != null)
			{
				if (text3.Equals("1"))
				{
					pr.PRisMustUnderstand = true;
				}
				else
				{
					if (!text3.Equals("0"))
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_MustUnderstand"), text3));
					}
					pr.PRisMustUnderstand = false;
				}
			}
			if (pr.PRparseTypeEnum == InternalParseTypeE.Member)
			{
				if (objectPr.PRparseTypeEnum == InternalParseTypeE.Headers)
				{
					pr.PRmemberTypeEnum = InternalMemberTypeE.Header;
				}
				else if (objectPr.PRobjectTypeEnum == InternalObjectTypeE.Array)
				{
					pr.PRmemberTypeEnum = InternalMemberTypeE.Item;
				}
				else
				{
					pr.PRmemberTypeEnum = InternalMemberTypeE.Field;
				}
			}
		}

		private void ProcessType(ParseRecord pr, ParseRecord objectPr)
		{
			if (pr.PRdtType != null)
			{
				return;
			}
			if (pr.PRnameXmlKey.Equals(soapEnvKey) && string.Compare(pr.PRname, "Fault", StringComparison.OrdinalIgnoreCase) == 0)
			{
				pr.PRdtType = SoapUtil.typeofSoapFault;
				pr.PRparseTypeEnum = InternalParseTypeE.Object;
			}
			else if (pr.PRname != null)
			{
				string text = null;
				if (pr.PRnameXmlKey != null && pr.PRnameXmlKey.Length > 0)
				{
					text = (string)assemKeyToInteropAssemblyTable[pr.PRnameXmlKey];
				}
				Type type = null;
				string name = null;
				if (objectPr != null)
				{
					if (pr.PRisXmlAttribute)
					{
						SoapServices.GetInteropFieldTypeAndNameFromXmlAttribute(objectPr.PRdtType, pr.PRname, text, out type, out name);
					}
					else
					{
						SoapServices.GetInteropFieldTypeAndNameFromXmlElement(objectPr.PRdtType, pr.PRname, text, out type, out name);
					}
				}
				if (type != null)
				{
					pr.PRdtType = type;
					pr.PRname = name;
					pr.PRdtTypeCode = Converter.SoapToCode(pr.PRdtType);
				}
				else
				{
					if (text != null)
					{
						pr.PRdtType = objectReader.Bind(text, pr.PRname);
					}
					if (pr.PRdtType == null)
					{
						pr.PRdtType = SoapServices.GetInteropTypeFromXmlElement(pr.PRname, text);
					}
					if (pr.PRkeyDt == null && pr.PRnameXmlKey != null && pr.PRnameXmlKey.Length > 0 && objectPr.PRobjectTypeEnum == InternalObjectTypeE.Array && objectPr.PRarrayElementType == Converter.typeofObject)
					{
						pr.PRdtType = ProcessGetType(pr.PRname, pr.PRnameXmlKey, out pr.PRassemblyName);
						pr.PRdtTypeCode = Converter.SoapToCode(pr.PRdtType);
					}
				}
			}
			if (pr.PRdtType != null)
			{
				return;
			}
			if (pr.PRtypeXmlKey != null && pr.PRtypeXmlKey.Length > 0 && pr.PRkeyDt != null && pr.PRkeyDt.Length > 0 && assemKeyToInteropAssemblyTable.ContainsKey(pr.PRtypeXmlKey))
			{
				int num = pr.PRkeyDt.IndexOf("[");
				if (num > 0)
				{
					ProcessArray(pr, num, IsInterop: true);
					return;
				}
				string text2 = (string)assemKeyToInteropAssemblyTable[pr.PRtypeXmlKey];
				pr.PRdtType = objectReader.Bind(text2, pr.PRkeyDt);
				if (pr.PRdtType == null)
				{
					pr.PRdtType = SoapServices.GetInteropTypeFromXmlType(pr.PRkeyDt, text2);
					if (pr.PRdtType == null)
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TypeElement"), pr.PRname + " " + pr.PRkeyDt));
					}
				}
				if (pr.PRdtType == null)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TypeElement"), pr.PRname + " " + pr.PRkeyDt + ", " + text2));
				}
			}
			else if (pr.PRkeyDt != null)
			{
				if (string.Compare(pr.PRkeyDt, "Base64", StringComparison.OrdinalIgnoreCase) == 0)
				{
					pr.PRobjectTypeEnum = InternalObjectTypeE.Array;
					pr.PRarrayTypeEnum = InternalArrayTypeE.Base64;
					return;
				}
				if (string.Compare(pr.PRkeyDt, "String", StringComparison.OrdinalIgnoreCase) == 0)
				{
					pr.PRdtType = SoapUtil.typeofString;
					return;
				}
				if (string.Compare(pr.PRkeyDt, "methodSignature", StringComparison.OrdinalIgnoreCase) == 0)
				{
					try
					{
						pr.PRdtType = typeof(Type[]);
						char[] separator = new char[2] { ' ', ':' };
						string[] array = null;
						if (pr.PRvalue != null)
						{
							array = pr.PRvalue.Split(separator);
						}
						Type[] array2 = null;
						if (array == null || (array.Length == 1 && array[0].Length == 0))
						{
							array2 = new Type[0];
						}
						else
						{
							array2 = new Type[array.Length / 2];
							for (int i = 0; i < array.Length; i += 2)
							{
								string xmlKey = array[i];
								string value = array[i + 1];
								array2[i / 2] = ProcessGetType(value, xmlKey, out pr.PRassemblyName);
							}
						}
						pr.PRvarValue = array2;
						return;
					}
					catch
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_MethodSignature"), pr.PRvalue));
					}
				}
				pr.PRdtTypeCode = Converter.ToCode(pr.PRkeyDt);
				if (pr.PRdtTypeCode != 0)
				{
					pr.PRdtType = Converter.SoapToType(pr.PRdtTypeCode);
					return;
				}
				int num2 = pr.PRkeyDt.IndexOf("[");
				if (num2 > 0)
				{
					ProcessArray(pr, num2, IsInterop: false);
					return;
				}
				pr.PRobjectTypeEnum = InternalObjectTypeE.Object;
				pr.PRdtType = ProcessGetType(pr.PRkeyDt, pr.PRtypeXmlKey, out pr.PRassemblyName);
				if (pr.PRdtType == null && pr.PRobjectPositionEnum != InternalObjectPositionE.Top)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TypeElement"), pr.PRname + " " + pr.PRkeyDt));
				}
			}
			else if (pr.PRparseTypeEnum == InternalParseTypeE.Object && (!objectReader.IsFakeTopObject || pr.PRobjectPositionEnum != InternalObjectPositionE.Top))
			{
				if (string.Compare(pr.PRname, "Array", StringComparison.OrdinalIgnoreCase) == 0)
				{
					pr.PRdtType = ProcessGetType(pr.PRkeyDt, pr.PRtypeXmlKey, out pr.PRassemblyName);
				}
				else
				{
					pr.PRdtType = ProcessGetType(pr.PRname, pr.PRnameXmlKey, out pr.PRassemblyName);
				}
			}
		}

		private Type ProcessGetType(string value, string xmlKey, out string assemblyString)
		{
			Type type = null;
			string text = null;
			assemblyString = null;
			string text2 = (string)keyToNamespaceTable["xmlns:" + xmlKey];
			if (text2 != null)
			{
				type = GetInteropType(value, text2);
				if (type != null)
				{
					return type;
				}
			}
			if ((string.Compare(value, "anyType", StringComparison.OrdinalIgnoreCase) == 0 || string.Compare(value, "ur-type", StringComparison.OrdinalIgnoreCase) == 0) && xmlKey.Equals(xsdKey))
			{
				type = SoapUtil.typeofObject;
			}
			else if (xmlKey.Equals(xsdKey) || xmlKey.Equals(soapKey))
			{
				if (string.Compare(value, "string", StringComparison.OrdinalIgnoreCase) == 0)
				{
					type = SoapUtil.typeofString;
				}
				else
				{
					InternalPrimitiveTypeE internalPrimitiveTypeE = Converter.ToCode(value);
					if (internalPrimitiveTypeE == InternalPrimitiveTypeE.Invalid)
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Parser_xsd"), value));
					}
					type = Converter.SoapToType(internalPrimitiveTypeE);
				}
			}
			else
			{
				if (xmlKey == null)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Parser_xml"), value));
				}
				string text3 = (string)assemKeyToNameSpaceTable[xmlKey];
				text = null;
				text = ((text3 != null && text3.Length != 0) ? (text3 + "." + value) : value);
				SoapAssemblyInfo soapAssemblyInfo = (SoapAssemblyInfo)assemKeyToAssemblyTable[xmlKey];
				if (soapAssemblyInfo == null)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Parser_xmlAssembly"), xmlKey + " " + value));
				}
				assemblyString = soapAssemblyInfo.assemblyString;
				if (assemblyString != null)
				{
					type = objectReader.Bind(assemblyString, text);
					if (type == null)
					{
						type = objectReader.FastBindToType(assemblyString, text);
					}
				}
				if (type == null)
				{
					Assembly assembly = null;
					try
					{
						assembly = soapAssemblyInfo.GetAssembly(objectReader);
					}
					catch
					{
					}
					if (assembly == null)
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Parser_xmlAssembly"), xmlKey + ":" + text2 + " " + value));
					}
					type = FormatterServices.GetTypeFromAssembly(assembly, text);
				}
			}
			if (type == null)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Parser_xmlType"), xmlKey + " " + text + " " + assemblyString));
			}
			return type;
		}

		private Type GetInteropType(string value, string httpstring)
		{
			Type interopTypeFromXmlType = SoapServices.GetInteropTypeFromXmlType(value, httpstring);
			if (interopTypeFromXmlType == null)
			{
				int num = httpstring.IndexOf("%2C");
				if (num > 0)
				{
					string xmlTypeNamespace = httpstring.Substring(0, num);
					interopTypeFromXmlType = SoapServices.GetInteropTypeFromXmlType(value, xmlTypeNamespace);
				}
			}
			return interopTypeFromXmlType;
		}

		private void ProcessArray(ParseRecord pr, int firstIndex, bool IsInterop)
		{
			string pRtypeXmlKey = pr.PRtypeXmlKey;
			InternalPrimitiveTypeE internalPrimitiveTypeE = InternalPrimitiveTypeE.Invalid;
			pr.PRobjectTypeEnum = InternalObjectTypeE.Array;
			pr.PRmemberTypeEnum = InternalMemberTypeE.Item;
			pr.PRprimitiveArrayTypeString = pr.PRkeyDt.Substring(0, firstIndex);
			pr.PRkeyDt.Substring(firstIndex);
			if (IsInterop)
			{
				string text = (string)assemKeyToInteropAssemblyTable[pr.PRtypeXmlKey];
				pr.PRarrayElementType = objectReader.Bind(text, pr.PRprimitiveArrayTypeString);
				if (pr.PRarrayElementType == null)
				{
					pr.PRarrayElementType = SoapServices.GetInteropTypeFromXmlType(pr.PRprimitiveArrayTypeString, text);
				}
				if (pr.PRarrayElementType == null)
				{
					pr.PRarrayElementType = SoapServices.GetInteropTypeFromXmlElement(pr.PRprimitiveArrayTypeString, text);
				}
				if (pr.PRarrayElementType == null)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TypeElement"), pr.PRname + " " + pr.PRkeyDt));
				}
				pr.PRprimitiveArrayTypeString = pr.PRarrayElementType.FullName;
			}
			else
			{
				internalPrimitiveTypeE = Converter.ToCode(pr.PRprimitiveArrayTypeString);
				if (internalPrimitiveTypeE != 0)
				{
					pr.PRprimitiveArrayTypeString = Converter.SoapToComType(internalPrimitiveTypeE);
					pRtypeXmlKey = urtKey;
				}
				else if (string.Compare(pr.PRprimitiveArrayTypeString, "string", StringComparison.Ordinal) == 0)
				{
					pr.PRprimitiveArrayTypeString = "System.String";
					pRtypeXmlKey = urtKey;
				}
				else if (string.Compare(pr.PRprimitiveArrayTypeString, "anyType", StringComparison.Ordinal) == 0 || string.Compare(pr.PRprimitiveArrayTypeString, "ur-type", StringComparison.Ordinal) == 0)
				{
					pr.PRprimitiveArrayTypeString = "System.Object";
					pRtypeXmlKey = urtKey;
				}
			}
			int num = firstIndex;
			int num2 = pr.PRkeyDt.IndexOf(']', num + 1);
			if (num2 < 1)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ArrayDimensions"), pr.PRkeyDt));
			}
			int rank = 0;
			int[] array = null;
			string dimSignature = null;
			InternalArrayTypeE arrayTypeEnum = InternalArrayTypeE.Empty;
			int num3 = 0;
			StringBuilder stringBuilder = new StringBuilder(10);
			while (true)
			{
				num3++;
				array = ParseArrayDimensions(pr.PRkeyDt.Substring(num, num2 - num + 1), out rank, out dimSignature, out arrayTypeEnum);
				if (num2 + 1 == pr.PRkeyDt.Length)
				{
					break;
				}
				stringBuilder.Append(dimSignature);
				num = num2 + 1;
				num2 = pr.PRkeyDt.IndexOf(']', num);
			}
			pr.PRlengthA = array;
			pr.PRrank = rank;
			if (num3 == 1)
			{
				pr.PRarrayElementTypeCode = internalPrimitiveTypeE;
				pr.PRarrayTypeEnum = arrayTypeEnum;
				pr.PRarrayElementTypeString = pr.PRprimitiveArrayTypeString;
			}
			else
			{
				pr.PRarrayElementTypeCode = InternalPrimitiveTypeE.Invalid;
				pr.PRarrayTypeEnum = InternalArrayTypeE.Rectangular;
				pr.PRarrayElementTypeString = pr.PRprimitiveArrayTypeString + stringBuilder.ToString();
			}
			if (!IsInterop || num3 > 1)
			{
				pr.PRarrayElementType = ProcessGetType(pr.PRarrayElementTypeString, pRtypeXmlKey, out pr.PRassemblyName);
				if (pr.PRarrayElementType == null)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ArrayType"), pr.PRarrayElementType));
				}
				if (pr.PRarrayElementType == SoapUtil.typeofObject)
				{
					pr.PRisArrayVariant = true;
					pRtypeXmlKey = urtKey;
				}
			}
		}

		private int[] ParseArrayDimensions(string dimString, out int rank, out string dimSignature, out InternalArrayTypeE arrayTypeEnum)
		{
			char[] array = dimString.ToCharArray();
			int num = 0;
			int num2 = 0;
			int num3 = 0;
			int[] array2 = new int[array.Length];
			StringBuilder stringBuilder = new StringBuilder(10);
			StringBuilder stringBuilder2 = new StringBuilder(10);
			for (int i = 0; i < array.Length; i++)
			{
				if (array[i] == '[')
				{
					num++;
					stringBuilder2.Append(array[i]);
				}
				else if (array[i] == ']')
				{
					if (stringBuilder.Length > 0)
					{
						array2[num3++] = int.Parse(stringBuilder.ToString(), CultureInfo.InvariantCulture);
						stringBuilder.Length = 0;
					}
					stringBuilder2.Append(array[i]);
				}
				else if (array[i] == ',')
				{
					num2++;
					if (stringBuilder.Length > 0)
					{
						array2[num3++] = int.Parse(stringBuilder.ToString(), CultureInfo.InvariantCulture);
						stringBuilder.Length = 0;
					}
					stringBuilder2.Append(array[i]);
				}
				else
				{
					if (array[i] != '-' && !char.IsDigit(array[i]))
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ArrayDimensions"), dimString));
					}
					stringBuilder.Append(array[i]);
				}
			}
			rank = num3;
			dimSignature = stringBuilder2.ToString();
			int[] array3 = new int[rank];
			for (int j = 0; j < rank; j++)
			{
				array3[j] = array2[j];
			}
			InternalArrayTypeE internalArrayTypeE = InternalArrayTypeE.Empty;
			internalArrayTypeE = (arrayTypeEnum = ((num2 <= 0) ? InternalArrayTypeE.Single : InternalArrayTypeE.Rectangular));
			return array3;
		}

		private string NameFilter(string name)
		{
			string text = nameCache.GetCachedValue(name) as string;
			if (text == null)
			{
				text = XmlConvert.DecodeName(name);
				nameCache.SetCachedValue(text);
			}
			return text;
		}

		private void ProcessXmlAttribute(string prefix, string key, string value, ParseRecord objectPr)
		{
			if (xmlAttributeList == null)
			{
				xmlAttributeList = new ArrayList(10);
			}
			ParseRecord pr = GetPr();
			pr.PRparseTypeEnum = InternalParseTypeE.Member;
			pr.PRmemberTypeEnum = InternalMemberTypeE.Field;
			pr.PRmemberValueEnum = InternalMemberValueE.InlineValue;
			pr.PRname = key;
			pr.PRvalue = value;
			pr.PRnameXmlKey = prefix;
			pr.PRisXmlAttribute = true;
			ProcessType(pr, objectPr);
			xmlAttributeList.Add(pr);
		}

		private void ProcessHeader(ParseRecord pr)
		{
			if (headerList == null)
			{
				headerList = new ArrayList(10);
			}
			ParseRecord pr2 = GetPr();
			pr2.PRparseTypeEnum = InternalParseTypeE.Object;
			pr2.PRobjectTypeEnum = InternalObjectTypeE.Array;
			pr2.PRobjectPositionEnum = InternalObjectPositionE.Headers;
			pr2.PRarrayTypeEnum = InternalArrayTypeE.Single;
			pr2.PRarrayElementType = typeof(Header);
			pr2.PRisArrayVariant = false;
			pr2.PRarrayElementTypeCode = InternalPrimitiveTypeE.Invalid;
			pr2.PRrank = 1;
			pr2.PRlengthA = new int[1];
			headerList.Add(pr2);
		}

		private void ProcessHeaderMember(ParseRecord pr)
		{
			if (headerState == HeaderStateEnum.NestedObject)
			{
				ParseRecord value = pr.Copy();
				headerList.Add(value);
				return;
			}
			ParseRecord pr2 = GetPr();
			pr2.PRparseTypeEnum = InternalParseTypeE.Member;
			pr2.PRmemberTypeEnum = InternalMemberTypeE.Item;
			pr2.PRmemberValueEnum = InternalMemberValueE.Nested;
			pr2.PRisHeaderRoot = true;
			headerArrayLength++;
			headerList.Add(pr2);
			pr2 = GetPr();
			pr2.PRparseTypeEnum = InternalParseTypeE.Member;
			pr2.PRmemberTypeEnum = InternalMemberTypeE.Field;
			pr2.PRmemberValueEnum = InternalMemberValueE.InlineValue;
			pr2.PRisHeaderRoot = true;
			pr2.PRname = "Name";
			pr2.PRvalue = pr.PRname;
			pr2.PRdtType = SoapUtil.typeofString;
			pr2.PRdtTypeCode = InternalPrimitiveTypeE.Invalid;
			headerList.Add(pr2);
			pr2 = GetPr();
			pr2.PRparseTypeEnum = InternalParseTypeE.Member;
			pr2.PRmemberTypeEnum = InternalMemberTypeE.Field;
			pr2.PRmemberValueEnum = InternalMemberValueE.InlineValue;
			pr2.PRisHeaderRoot = true;
			pr2.PRname = "HeaderNamespace";
			pr2.PRvalue = pr.PRxmlNameSpace;
			pr2.PRdtType = SoapUtil.typeofString;
			pr2.PRdtTypeCode = InternalPrimitiveTypeE.Invalid;
			headerList.Add(pr2);
			pr2 = GetPr();
			pr2.PRparseTypeEnum = InternalParseTypeE.Member;
			pr2.PRmemberTypeEnum = InternalMemberTypeE.Field;
			pr2.PRmemberValueEnum = InternalMemberValueE.InlineValue;
			pr2.PRisHeaderRoot = true;
			pr2.PRname = "MustUnderstand";
			if (pr.PRisMustUnderstand)
			{
				pr2.PRvarValue = true;
			}
			else
			{
				pr2.PRvarValue = false;
			}
			pr2.PRdtType = SoapUtil.typeofBoolean;
			pr2.PRdtTypeCode = InternalPrimitiveTypeE.Boolean;
			headerList.Add(pr2);
			pr2 = GetPr();
			pr2.PRparseTypeEnum = InternalParseTypeE.Member;
			pr2.PRmemberTypeEnum = InternalMemberTypeE.Field;
			pr2.PRmemberValueEnum = pr.PRmemberValueEnum;
			pr2.PRisHeaderRoot = true;
			pr2.PRname = "Value";
			switch (pr.PRmemberValueEnum)
			{
			case InternalMemberValueE.Null:
				headerList.Add(pr2);
				ProcessHeaderMemberEnd(pr);
				break;
			case InternalMemberValueE.Reference:
				pr2.PRidRef = pr.PRidRef;
				headerList.Add(pr2);
				ProcessHeaderMemberEnd(pr);
				break;
			case InternalMemberValueE.Nested:
				pr2.PRdtType = pr.PRdtType;
				pr2.PRdtTypeCode = pr.PRdtTypeCode;
				pr2.PRkeyDt = pr.PRkeyDt;
				headerList.Add(pr2);
				break;
			case InternalMemberValueE.InlineValue:
				pr2.PRvalue = pr.PRvalue;
				pr2.PRvarValue = pr.PRvarValue;
				pr2.PRdtType = pr.PRdtType;
				pr2.PRdtTypeCode = pr.PRdtTypeCode;
				pr2.PRkeyDt = pr.PRkeyDt;
				headerList.Add(pr2);
				ProcessHeaderMemberEnd(pr);
				break;
			}
		}

		private void ProcessHeaderMemberEnd(ParseRecord pr)
		{
			ParseRecord parseRecord = null;
			if (headerState == HeaderStateEnum.NestedObject)
			{
				ParseRecord value = pr.Copy();
				headerList.Add(value);
				return;
			}
			parseRecord = GetPr();
			parseRecord.PRparseTypeEnum = InternalParseTypeE.MemberEnd;
			parseRecord.PRmemberTypeEnum = InternalMemberTypeE.Field;
			parseRecord.PRmemberValueEnum = pr.PRmemberValueEnum;
			parseRecord.PRisHeaderRoot = true;
			headerList.Add(parseRecord);
			parseRecord = GetPr();
			parseRecord.PRparseTypeEnum = InternalParseTypeE.MemberEnd;
			parseRecord.PRmemberTypeEnum = InternalMemberTypeE.Item;
			parseRecord.PRmemberValueEnum = InternalMemberValueE.Nested;
			parseRecord.PRisHeaderRoot = true;
			headerList.Add(parseRecord);
		}

		private void ProcessHeaderEnd(ParseRecord pr)
		{
			if (headerList != null)
			{
				ParseRecord pr2 = GetPr();
				pr2.PRparseTypeEnum = InternalParseTypeE.ObjectEnd;
				pr2.PRobjectTypeEnum = InternalObjectTypeE.Array;
				headerList.Add(pr2);
				pr2 = (ParseRecord)headerList[0];
				pr2 = (ParseRecord)headerList[0];
				pr2.PRlengthA[0] = headerArrayLength;
				pr2.PRobjectPositionEnum = InternalObjectPositionE.Headers;
				for (int i = 0; i < headerList.Count; i++)
				{
					objectReader.Parse((ParseRecord)headerList[i]);
				}
				for (int j = 0; j < headerList.Count; j++)
				{
					PutPr((ParseRecord)headerList[j]);
				}
			}
		}
	}
	internal sealed class AttributeList
	{
		private SerStack nameA = new SerStack("AttributeName");

		private SerStack valueA = new SerStack("AttributeValue");

		internal int Count => nameA.Count();

		internal void Clear()
		{
			nameA.Clear();
			valueA.Clear();
		}

		internal void Put(string name, string value)
		{
			nameA.Push(name);
			valueA.Push(value);
		}

		internal void Get(int index, out string name, out string value)
		{
			name = (string)nameA.Next();
			value = (string)valueA.Next();
		}

		[Conditional("SER_LOGGING")]
		internal void Dump()
		{
		}
	}
	internal sealed class SerStack
	{
		internal object[] objects = new object[10];

		internal string stackId;

		internal int top = -1;

		internal int next;

		internal SerStack(string stackId)
		{
			this.stackId = stackId;
		}

		internal object GetItem(int index)
		{
			return objects[index];
		}

		internal void Clear()
		{
			top = -1;
			next = 0;
		}

		internal void Push(object obj)
		{
			if (top == objects.Length - 1)
			{
				IncreaseCapacity();
			}
			objects[++top] = obj;
		}

		internal object Pop()
		{
			if (top < 0)
			{
				return null;
			}
			object result = objects[top];
			objects[top--] = null;
			return result;
		}

		internal object Next()
		{
			if (next > top)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_StackRange"), stackId));
			}
			return objects[next++];
		}

		internal void IncreaseCapacity()
		{
			int num = objects.Length * 2;
			object[] destinationArray = new object[num];
			Array.Copy(objects, 0, destinationArray, 0, objects.Length);
			objects = destinationArray;
		}

		internal object Peek()
		{
			if (top < 0)
			{
				return null;
			}
			return objects[top];
		}

		internal object PeekPeek()
		{
			if (top < 1)
			{
				return null;
			}
			return objects[top - 1];
		}

		internal int Count()
		{
			return top + 1;
		}

		internal bool IsEmpty()
		{
			if (top > 0)
			{
				return false;
			}
			return true;
		}

		internal void Reverse()
		{
			Array.Reverse(objects, 0, Count());
		}

		[Conditional("SER_LOGGING")]
		internal void Dump()
		{
			for (int i = 0; i < Count(); i++)
			{
				_ = objects[i];
			}
		}
	}
	internal sealed class NameCacheEntry
	{
		internal string name;

		internal object value;
	}
	internal sealed class NameCache
	{
		private const int MAX_CACHE_ENTRIES = 353;

		private static NameCacheEntry[] nameCache = new NameCacheEntry[353];

		private int probe;

		private string name;

		internal object GetCachedValue(string name)
		{
			this.name = name;
			probe = Math.Abs(name.GetHashCode()) % 353;
			NameCacheEntry nameCacheEntry = nameCache[probe];
			if (nameCacheEntry == null)
			{
				nameCacheEntry = new NameCacheEntry();
				nameCacheEntry.name = name;
				return null;
			}
			if (nameCacheEntry.name == name)
			{
				return nameCacheEntry.value;
			}
			return null;
		}

		internal void SetCachedValue(object value)
		{
			NameCacheEntry nameCacheEntry = new NameCacheEntry();
			nameCacheEntry.name = name;
			nameCacheEntry.value = value;
			nameCache[probe] = nameCacheEntry;
		}
	}
	internal static class SoapUtil
	{
		internal static Type typeofString = typeof(string);

		internal static Type typeofBoolean = typeof(bool);

		internal static Type typeofObject = typeof(object);

		internal static Type typeofSoapFault = typeof(SoapFault);

		internal static Assembly urtAssembly = Assembly.GetAssembly(typeofString);

		internal static string urtAssemblyString = urtAssembly.FullName;

		internal static ResourceManager SystemResMgr;

		[Conditional("SER_LOGGING")]
		internal static void DumpHash(string tag, Hashtable hashTable)
		{
			IDictionaryEnumerator enumerator = hashTable.GetEnumerator();
			while (enumerator.MoveNext())
			{
			}
		}

		private static ResourceManager InitResourceManager()
		{
			if (SystemResMgr == null)
			{
				SystemResMgr = new ResourceManager("SoapFormatter", typeof(SoapParser).Module.Assembly);
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

		internal static string GetResourceString(string key, params object[] values)
		{
			if (SystemResMgr == null)
			{
				InitResourceManager();
			}
			string @string = SystemResMgr.GetString(key, null);
			return string.Format(CultureInfo.CurrentCulture, @string, values);
		}
	}
	internal sealed class SoapAssemblyInfo
	{
		internal string assemblyString;

		private Assembly assembly;

		internal SoapAssemblyInfo(string assemblyString)
		{
			this.assemblyString = assemblyString;
		}

		internal SoapAssemblyInfo(string assemblyString, Assembly assembly)
		{
			this.assemblyString = assemblyString;
			this.assembly = assembly;
		}

		internal Assembly GetAssembly(ObjectReader objectReader)
		{
			if (assembly == null)
			{
				assembly = objectReader.LoadAssemblyFromString(assemblyString);
				if (assembly == null)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_AssemblyString"), assemblyString));
				}
			}
			return assembly;
		}
	}
	internal interface ITrace
	{
		string Trace();
	}
	internal sealed class ParseRecord : ITrace
	{
		internal static int parseRecordIdCount = 1;

		internal int PRparseRecordId;

		internal InternalParseTypeE PRparseTypeEnum;

		internal InternalObjectTypeE PRobjectTypeEnum;

		internal InternalArrayTypeE PRarrayTypeEnum;

		internal InternalMemberTypeE PRmemberTypeEnum;

		internal InternalMemberValueE PRmemberValueEnum;

		internal InternalObjectPositionE PRobjectPositionEnum;

		internal string PRname;

		internal string PRnameXmlKey;

		internal string PRxmlNameSpace;

		internal bool PRisParsed;

		internal bool PRisProcessAttributes;

		internal string PRvalue;

		internal object PRvarValue;

		internal string PRkeyDt;

		internal string PRtypeXmlKey;

		internal Type PRdtType;

		internal string PRassemblyName;

		internal InternalPrimitiveTypeE PRdtTypeCode;

		internal bool PRisVariant;

		internal bool PRisEnum;

		internal long PRobjectId;

		internal long PRidRef;

		internal string PRarrayElementTypeString;

		internal Type PRarrayElementType;

		internal bool PRisArrayVariant;

		internal InternalPrimitiveTypeE PRarrayElementTypeCode;

		internal string PRprimitiveArrayTypeString;

		internal int PRrank;

		internal int[] PRlengthA;

		internal int[] PRpositionA;

		internal int[] PRlowerBoundA;

		internal int[] PRupperBoundA;

		internal int[] PRindexMap;

		internal int PRmemberIndex;

		internal int PRlinearlength;

		internal int[] PRrectangularMap;

		internal bool PRisLowerBound;

		internal long PRtopId;

		internal long PRheaderId;

		internal bool PRisHeaderRoot;

		internal bool PRisAttributesProcessed;

		internal bool PRisMustUnderstand;

		internal InternalParseStateE PRparseStateEnum;

		internal bool PRisWaitingForNestedObject;

		internal ReadObjectInfo PRobjectInfo;

		internal bool PRisValueTypeFixup;

		internal object PRnewObj;

		internal object[] PRobjectA;

		internal PrimitiveArray PRprimitiveArray;

		internal bool PRisRegistered;

		internal bool PRisXmlAttribute;

		internal ParseRecord()
		{
			Counter();
		}

		private void Counter()
		{
			lock (typeof(ParseRecord))
			{
				PRparseRecordId = parseRecordIdCount++;
			}
		}

		public string Trace()
		{
			return "ParseRecord" + PRparseRecordId + " ParseType " + PRparseTypeEnum.ToString() + " name " + PRname + " keyDt " + Util.PString(PRkeyDt);
		}

		internal void Init()
		{
			PRparseTypeEnum = InternalParseTypeE.Empty;
			PRobjectTypeEnum = InternalObjectTypeE.Empty;
			PRarrayTypeEnum = InternalArrayTypeE.Empty;
			PRmemberTypeEnum = InternalMemberTypeE.Empty;
			PRmemberValueEnum = InternalMemberValueE.Empty;
			PRobjectPositionEnum = InternalObjectPositionE.Empty;
			PRname = null;
			PRnameXmlKey = null;
			PRxmlNameSpace = null;
			PRisParsed = false;
			PRisProcessAttributes = false;
			PRvalue = null;
			PRkeyDt = null;
			PRdtType = null;
			PRassemblyName = null;
			PRdtTypeCode = InternalPrimitiveTypeE.Invalid;
			PRisEnum = false;
			PRobjectId = 0L;
			PRidRef = 0L;
			PRarrayElementTypeString = null;
			PRarrayElementType = null;
			PRisArrayVariant = false;
			PRarrayElementTypeCode = InternalPrimitiveTypeE.Invalid;
			PRprimitiveArrayTypeString = null;
			PRrank = 0;
			PRlengthA = null;
			PRpositionA = null;
			PRlowerBoundA = null;
			PRupperBoundA = null;
			PRindexMap = null;
			PRmemberIndex = 0;
			PRlinearlength = 0;
			PRrectangularMap = null;
			PRisLowerBound = false;
			PRtopId = 0L;
			PRheaderId = 0L;
			PRisHeaderRoot = false;
			PRisAttributesProcessed = false;
			PRisMustUnderstand = false;
			PRparseStateEnum = InternalParseStateE.Initial;
			PRisWaitingForNestedObject = false;
			PRisValueTypeFixup = false;
			PRnewObj = null;
			PRobjectA = null;
			PRprimitiveArray = null;
			PRobjectInfo = null;
			PRisRegistered = false;
			PRisXmlAttribute = false;
		}

		internal ParseRecord Copy()
		{
			ParseRecord parseRecord = new ParseRecord();
			parseRecord.PRparseTypeEnum = PRparseTypeEnum;
			parseRecord.PRobjectTypeEnum = PRobjectTypeEnum;
			parseRecord.PRarrayTypeEnum = PRarrayTypeEnum;
			parseRecord.PRmemberTypeEnum = PRmemberTypeEnum;
			parseRecord.PRmemberValueEnum = PRmemberValueEnum;
			parseRecord.PRobjectPositionEnum = PRobjectPositionEnum;
			parseRecord.PRname = PRname;
			parseRecord.PRisParsed = PRisParsed;
			parseRecord.PRisProcessAttributes = PRisProcessAttributes;
			parseRecord.PRnameXmlKey = PRnameXmlKey;
			parseRecord.PRxmlNameSpace = PRxmlNameSpace;
			parseRecord.PRvalue = PRvalue;
			parseRecord.PRkeyDt = PRkeyDt;
			parseRecord.PRdtType = PRdtType;
			parseRecord.PRassemblyName = PRassemblyName;
			parseRecord.PRdtTypeCode = PRdtTypeCode;
			parseRecord.PRisEnum = PRisEnum;
			parseRecord.PRobjectId = PRobjectId;
			parseRecord.PRidRef = PRidRef;
			parseRecord.PRarrayElementTypeString = PRarrayElementTypeString;
			parseRecord.PRarrayElementType = PRarrayElementType;
			parseRecord.PRisArrayVariant = PRisArrayVariant;
			parseRecord.PRarrayElementTypeCode = PRarrayElementTypeCode;
			parseRecord.PRprimitiveArrayTypeString = PRprimitiveArrayTypeString;
			parseRecord.PRrank = PRrank;
			parseRecord.PRlengthA = PRlengthA;
			parseRecord.PRpositionA = PRpositionA;
			parseRecord.PRlowerBoundA = PRlowerBoundA;
			parseRecord.PRupperBoundA = PRupperBoundA;
			parseRecord.PRindexMap = PRindexMap;
			parseRecord.PRmemberIndex = PRmemberIndex;
			parseRecord.PRlinearlength = PRlinearlength;
			parseRecord.PRrectangularMap = PRrectangularMap;
			parseRecord.PRisLowerBound = PRisLowerBound;
			parseRecord.PRtopId = PRtopId;
			parseRecord.PRheaderId = PRheaderId;
			parseRecord.PRisHeaderRoot = PRisHeaderRoot;
			parseRecord.PRisAttributesProcessed = PRisAttributesProcessed;
			parseRecord.PRisMustUnderstand = PRisMustUnderstand;
			parseRecord.PRparseStateEnum = PRparseStateEnum;
			parseRecord.PRisWaitingForNestedObject = PRisWaitingForNestedObject;
			parseRecord.PRisValueTypeFixup = PRisValueTypeFixup;
			parseRecord.PRnewObj = PRnewObj;
			parseRecord.PRobjectA = PRobjectA;
			parseRecord.PRprimitiveArray = PRprimitiveArray;
			parseRecord.PRobjectInfo = PRobjectInfo;
			parseRecord.PRisRegistered = PRisRegistered;
			parseRecord.PRisXmlAttribute = PRisXmlAttribute;
			return parseRecord;
		}

		[Conditional("SER_LOGGING")]
		internal void Dump()
		{
		}
	}
	internal static class Util
	{
		internal static string PString(string value)
		{
			if (value == null)
			{
				return "";
			}
			return value;
		}

		[Conditional("SER_LOGGING")]
		internal static void NVTrace(string name, string value)
		{
		}

		[Conditional("SER_LOGGING")]
		internal static void NVTrace(string name, object value)
		{
		}

		[Conditional("_LOGGING")]
		internal static void NVTraceI(string name, string value)
		{
		}

		[Conditional("_LOGGING")]
		internal static void NVTraceI(string name, object value)
		{
		}
	}
	internal class ValueFixup : ITrace
	{
		internal ValueFixupEnum valueFixupEnum;

		internal Array arrayObj;

		internal int[] indexMap;

		internal object memberObject;

		internal ReadObjectInfo objectInfo;

		internal string memberName;

		internal ValueFixup(Array arrayObj, int[] indexMap)
		{
			valueFixupEnum = ValueFixupEnum.Array;
			this.arrayObj = arrayObj;
			this.indexMap = indexMap;
		}

		internal ValueFixup(object memberObject, string memberName, ReadObjectInfo objectInfo)
		{
			valueFixupEnum = ValueFixupEnum.Member;
			this.memberObject = memberObject;
			this.memberName = memberName;
			this.objectInfo = objectInfo;
		}

		internal virtual void Fixup(ParseRecord record, ParseRecord parent)
		{
			object pRnewObj = record.PRnewObj;
			switch (valueFixupEnum)
			{
			case ValueFixupEnum.Array:
				arrayObj.SetValue(pRnewObj, indexMap);
				break;
			case ValueFixupEnum.Member:
			{
				if (objectInfo.isSi)
				{
					objectInfo.objectManager.RecordDelayedFixup(parent.PRobjectId, memberName, record.PRobjectId);
					break;
				}
				MemberInfo memberInfo = objectInfo.GetMemberInfo(memberName);
				objectInfo.objectManager.RecordFixup(parent.PRobjectId, memberInfo, record.PRobjectId);
				break;
			}
			case ValueFixupEnum.Header:
				break;
			}
		}

		public virtual string Trace()
		{
			return "ValueFixup" + valueFixupEnum;
		}
	}
	internal sealed class InternalFE
	{
		internal FormatterTypeStyle FEtypeFormat;

		internal FormatterAssemblyStyle FEassemblyFormat;

		internal ISoapMessage FEtopObject;

		internal TypeFilterLevel FEsecurityLevel;

		internal InternalSerializerTypeE FEserializerTypeEnum;
	}
	[Serializable]
	internal sealed class InternalSoapMessage : ISerializable, IFieldInfo
	{
		internal string methodName;

		internal string xmlNameSpace;

		internal string[] paramNames;

		internal object[] paramValues;

		internal Type[] paramTypes;

		internal Hashtable keyToNamespaceTable;

		public string[] FieldNames
		{
			get
			{
				return paramNames;
			}
			set
			{
				paramNames = value;
			}
		}

		public Type[] FieldTypes
		{
			get
			{
				return paramTypes;
			}
			set
			{
				paramTypes = value;
			}
		}

		internal InternalSoapMessage()
		{
		}

		internal InternalSoapMessage(string methodName, string xmlNameSpace, string[] paramNames, object[] paramValues, Type[] paramTypes)
		{
			this.methodName = methodName;
			this.xmlNameSpace = xmlNameSpace;
			this.paramNames = paramNames;
			this.paramValues = paramValues;
			this.paramTypes = paramTypes;
		}

		internal InternalSoapMessage(SerializationInfo info, StreamingContext context)
		{
			SetObjectData(info, context);
		}

		public void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			if (paramValues != null)
			{
				_ = paramValues.Length;
			}
			info.FullTypeName = methodName;
			if (xmlNameSpace != null)
			{
				info.AssemblyName = xmlNameSpace;
			}
			string text = null;
			if (paramValues != null)
			{
				for (int i = 0; i < paramValues.Length; i++)
				{
					text = ((paramNames == null || paramNames[i] != null) ? paramNames[i] : ("param" + i));
					info.AddValue(text, paramValues[i], typeof(object));
				}
			}
		}

		internal void SetObjectData(SerializationInfo info, StreamingContext context)
		{
			ArrayList arrayList = new ArrayList(20);
			methodName = info.GetString("__methodName");
			keyToNamespaceTable = (Hashtable)info.GetValue("__keyToNamespaceTable", typeof(Hashtable));
			ArrayList arrayList2 = (ArrayList)info.GetValue("__paramNameList", typeof(ArrayList));
			xmlNameSpace = info.GetString("__xmlNameSpace");
			for (int i = 0; i < arrayList2.Count; i++)
			{
				arrayList.Add(info.GetValue((string)arrayList2[i], Converter.typeofObject));
			}
			paramNames = new string[arrayList2.Count];
			paramValues = new object[arrayList.Count];
			for (int j = 0; j < arrayList2.Count; j++)
			{
				paramNames[j] = (string)arrayList2[j];
				paramValues[j] = arrayList[j];
			}
		}
	}
	internal sealed class SoapAttributeInfo
	{
		internal SoapAttributeType m_attributeType;

		internal string m_nameSpace;

		internal string m_elementName;

		internal string m_typeName;

		internal string m_typeNamespace;

		internal string AttributeElementName => m_elementName;

		internal string AttributeTypeName => m_typeName;

		internal bool IsEmbedded()
		{
			if ((m_attributeType & SoapAttributeType.Embedded) > SoapAttributeType.None)
			{
				return true;
			}
			return false;
		}

		internal bool IsXmlElement()
		{
			if ((m_attributeType & SoapAttributeType.XmlElement) > SoapAttributeType.None)
			{
				return true;
			}
			return false;
		}

		internal bool IsXmlAttribute()
		{
			if ((m_attributeType & SoapAttributeType.XmlAttribute) > SoapAttributeType.None)
			{
				return true;
			}
			return false;
		}

		internal bool IsXmlType()
		{
			if ((m_attributeType & SoapAttributeType.XmlType) > SoapAttributeType.None)
			{
				return true;
			}
			return false;
		}

		[Conditional("SER_LOGGING")]
		internal void Dump(string id)
		{
			IsXmlType();
			IsEmbedded();
			IsXmlElement();
			IsXmlAttribute();
		}
	}
	internal sealed class NameInfo
	{
		internal InternalNameSpaceE NInameSpaceEnum;

		internal string NIname;

		internal long NIobjectId;

		internal long NIassemId;

		internal InternalPrimitiveTypeE NIprimitiveTypeEnum;

		internal Type NItype;

		internal bool NIisSealed;

		internal bool NIisMustUnderstand;

		internal string NInamespace;

		internal string NIheaderPrefix;

		internal string NIitemName;

		internal bool NIisArray;

		internal bool NIisArrayItem;

		internal bool NIisTopLevelObject;

		internal bool NIisNestedObject;

		internal bool NItransmitTypeOnObject;

		internal bool NItransmitTypeOnMember;

		internal bool NIisParentTypeOnObject;

		internal bool NIisHeader;

		internal bool NIisRemoteRecord;

		internal SoapAttributeInfo NIattributeInfo;

		internal void Init()
		{
			NInameSpaceEnum = InternalNameSpaceE.None;
			NIname = null;
			NIobjectId = 0L;
			NIassemId = 0L;
			NIprimitiveTypeEnum = InternalPrimitiveTypeE.Invalid;
			NItype = null;
			NIisSealed = false;
			NItransmitTypeOnObject = false;
			NItransmitTypeOnMember = false;
			NIisParentTypeOnObject = false;
			NIisMustUnderstand = false;
			NInamespace = null;
			NIheaderPrefix = null;
			NIitemName = null;
			NIisArray = false;
			NIisArrayItem = false;
			NIisTopLevelObject = false;
			NIisNestedObject = false;
			NIisHeader = false;
			NIisRemoteRecord = false;
			NIattributeInfo = null;
		}

		[Conditional("SER_LOGGING")]
		internal void Dump(string value)
		{
			_ = NIattributeInfo;
		}
	}
	internal sealed class PrimitiveArray
	{
		private InternalPrimitiveTypeE code;

		private bool[] booleanA;

		private char[] charA;

		private double[] doubleA;

		private short[] int16A;

		private int[] int32A;

		private long[] int64A;

		private sbyte[] sbyteA;

		private float[] singleA;

		private ushort[] uint16A;

		private uint[] uint32A;

		private ulong[] uint64A;

		internal PrimitiveArray(InternalPrimitiveTypeE code, Array array)
		{
			Init(code, array);
		}

		internal void Init(InternalPrimitiveTypeE code, Array array)
		{
			this.code = code;
			switch (code)
			{
			case InternalPrimitiveTypeE.Boolean:
				booleanA = (bool[])array;
				break;
			case InternalPrimitiveTypeE.Char:
				charA = (char[])array;
				break;
			case InternalPrimitiveTypeE.Double:
				doubleA = (double[])array;
				break;
			case InternalPrimitiveTypeE.Int16:
				int16A = (short[])array;
				break;
			case InternalPrimitiveTypeE.Int32:
				int32A = (int[])array;
				break;
			case InternalPrimitiveTypeE.Int64:
				int64A = (long[])array;
				break;
			case InternalPrimitiveTypeE.SByte:
				sbyteA = (sbyte[])array;
				break;
			case InternalPrimitiveTypeE.Single:
				singleA = (float[])array;
				break;
			case InternalPrimitiveTypeE.UInt16:
				uint16A = (ushort[])array;
				break;
			case InternalPrimitiveTypeE.UInt32:
				uint32A = (uint[])array;
				break;
			case InternalPrimitiveTypeE.UInt64:
				uint64A = (ulong[])array;
				break;
			case InternalPrimitiveTypeE.Byte:
			case InternalPrimitiveTypeE.Currency:
			case InternalPrimitiveTypeE.Decimal:
			case InternalPrimitiveTypeE.TimeSpan:
			case InternalPrimitiveTypeE.DateTime:
				break;
			}
		}

		internal string GetValue(int index)
		{
			string result = null;
			switch (code)
			{
			case InternalPrimitiveTypeE.Boolean:
				result = booleanA[index].ToString();
				break;
			case InternalPrimitiveTypeE.Char:
				result = ((charA[index] != 0) ? char.ToString(charA[index]) : "_0x00_");
				break;
			case InternalPrimitiveTypeE.Double:
				result = ((!double.IsPositiveInfinity(doubleA[index])) ? ((!double.IsNegativeInfinity(doubleA[index])) ? doubleA[index].ToString("R", CultureInfo.InvariantCulture) : "-INF") : "INF");
				break;
			case InternalPrimitiveTypeE.Int16:
				result = int16A[index].ToString(CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.Int32:
				result = int32A[index].ToString(CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.Int64:
				result = int64A[index].ToString(CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.SByte:
				result = sbyteA[index].ToString(CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.Single:
				result = ((!float.IsPositiveInfinity(singleA[index])) ? ((!float.IsNegativeInfinity(singleA[index])) ? singleA[index].ToString("R", CultureInfo.InvariantCulture) : "-INF") : "INF");
				break;
			case InternalPrimitiveTypeE.UInt16:
				result = uint16A[index].ToString(CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.UInt32:
				result = uint32A[index].ToString(CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.UInt64:
				result = uint64A[index].ToString(CultureInfo.InvariantCulture);
				break;
			}
			return result;
		}

		internal void SetValue(string value, int index)
		{
			switch (code)
			{
			case InternalPrimitiveTypeE.Boolean:
				booleanA[index] = bool.Parse(value);
				break;
			case InternalPrimitiveTypeE.Char:
				if (value[0] == '_' && value.Equals("_0x00_"))
				{
					charA[index] = '\0';
				}
				else
				{
					charA[index] = char.Parse(value);
				}
				break;
			case InternalPrimitiveTypeE.Double:
				if (value == "INF")
				{
					doubleA[index] = double.PositiveInfinity;
				}
				else if (value == "-INF")
				{
					doubleA[index] = double.NegativeInfinity;
				}
				else
				{
					doubleA[index] = double.Parse(value, CultureInfo.InvariantCulture);
				}
				break;
			case InternalPrimitiveTypeE.Int16:
				int16A[index] = short.Parse(value, CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.Int32:
				int32A[index] = int.Parse(value, CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.Int64:
				int64A[index] = long.Parse(value, CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.SByte:
				sbyteA[index] = sbyte.Parse(value, CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.Single:
				if (value == "INF")
				{
					singleA[index] = float.PositiveInfinity;
				}
				else if (value == "-INF")
				{
					singleA[index] = float.NegativeInfinity;
				}
				else
				{
					singleA[index] = float.Parse(value, CultureInfo.InvariantCulture);
				}
				break;
			case InternalPrimitiveTypeE.UInt16:
				uint16A[index] = ushort.Parse(value, CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.UInt32:
				uint32A[index] = uint.Parse(value, CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.UInt64:
				uint64A[index] = ulong.Parse(value, CultureInfo.InvariantCulture);
				break;
			case InternalPrimitiveTypeE.Byte:
			case InternalPrimitiveTypeE.Currency:
			case InternalPrimitiveTypeE.Decimal:
			case InternalPrimitiveTypeE.TimeSpan:
			case InternalPrimitiveTypeE.DateTime:
				break;
			}
		}
	}
	[Serializable]
	internal enum InternalSerializerTypeE
	{
		Soap = 1,
		Binary
	}
	[Serializable]
	internal enum InternalElementTypeE
	{
		ObjectBegin,
		ObjectEnd,
		Member
	}
	[Serializable]
	internal enum InternalParseTypeE
	{
		Empty,
		SerializedStreamHeader,
		Object,
		Member,
		ObjectEnd,
		MemberEnd,
		Headers,
		HeadersEnd,
		SerializedStreamHeaderEnd,
		Envelope,
		EnvelopeEnd,
		Body,
		BodyEnd
	}
	[Serializable]
	internal enum InternalObjectTypeE
	{
		Empty,
		Object,
		Array
	}
	[Serializable]
	internal enum InternalObjectPositionE
	{
		Empty,
		Top,
		Child,
		Headers
	}
	[Serializable]
	internal enum InternalArrayTypeE
	{
		Empty,
		Single,
		Jagged,
		Rectangular,
		Base64
	}
	[Serializable]
	internal enum InternalMemberTypeE
	{
		Empty,
		Header,
		Field,
		Item
	}
	[Serializable]
	internal enum InternalMemberValueE
	{
		Empty,
		InlineValue,
		Nested,
		Reference,
		Null
	}
	[Serializable]
	internal enum InternalParseStateE
	{
		Initial,
		Object,
		Member,
		MemberChild
	}
	[Serializable]
	internal enum InternalPrimitiveTypeE
	{
		Invalid,
		Boolean,
		Byte,
		Char,
		Currency,
		Decimal,
		Double,
		Int16,
		Int32,
		Int64,
		SByte,
		Single,
		TimeSpan,
		DateTime,
		UInt16,
		UInt32,
		UInt64,
		Time,
		Date,
		YearMonth,
		Year,
		MonthDay,
		Day,
		Month,
		HexBinary,
		Base64Binary,
		Integer,
		PositiveInteger,
		NonPositiveInteger,
		NonNegativeInteger,
		NegativeInteger,
		AnyUri,
		QName,
		Notation,
		NormalizedString,
		Token,
		Language,
		Name,
		Idrefs,
		Entities,
		Nmtoken,
		Nmtokens,
		NcName,
		Id,
		Idref,
		Entity
	}
	[Serializable]
	internal enum ValueFixupEnum
	{
		Empty,
		Array,
		Header,
		Member
	}
	[Serializable]
	internal enum InternalNameSpaceE
	{
		None,
		Soap,
		XdrPrimitive,
		XdrString,
		UrtSystem,
		UrtUser,
		UserNameSpace,
		MemberName,
		Interop,
		CallElement
	}
	[Serializable]
	internal enum SoapAttributeType
	{
		None = 0,
		Embedded = 1,
		XmlElement = 2,
		XmlAttribute = 4,
		XmlType = 8
	}
	[Serializable]
	internal enum XsdVersion
	{
		V1999,
		V2000,
		V2001
	}
	internal sealed class Converter
	{
		private static int primitiveTypeEnumLength = 46;

		private static Type[] typeA;

		private static string[] valueA;

		private static string[] valueB;

		private static TypeCode[] typeCodeA;

		private static InternalPrimitiveTypeE[] codeA;

		private static bool[] escapeA;

		private static StringBuilder sb = new StringBuilder(30);

		internal static Type typeofISerializable = typeof(ISerializable);

		internal static Type typeofString = typeof(string);

		internal static Type typeofConverter = typeof(Converter);

		internal static Type typeofBoolean = typeof(bool);

		internal static Type typeofByte = typeof(byte);

		internal static Type typeofChar = typeof(char);

		internal static Type typeofDecimal = typeof(decimal);

		internal static Type typeofDouble = typeof(double);

		internal static Type typeofInt16 = typeof(short);

		internal static Type typeofInt32 = typeof(int);

		internal static Type typeofInt64 = typeof(long);

		internal static Type typeofSByte = typeof(sbyte);

		internal static Type typeofSingle = typeof(float);

		internal static Type typeofTimeSpan = typeof(TimeSpan);

		internal static Type typeofDateTime = typeof(DateTime);

		internal static Type typeofUInt16 = typeof(ushort);

		internal static Type typeofUInt32 = typeof(uint);

		internal static Type typeofUInt64 = typeof(ulong);

		internal static Type typeofSoapTime = typeof(SoapTime);

		internal static Type typeofSoapDate = typeof(SoapDate);

		internal static Type typeofSoapYear = typeof(SoapYear);

		internal static Type typeofSoapMonthDay = typeof(SoapMonthDay);

		internal static Type typeofSoapYearMonth = typeof(SoapYearMonth);

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

		internal static Type typeofISoapXsd = typeof(ISoapXsd);

		internal static Type typeofObject = typeof(object);

		internal static Type typeofSoapFault = typeof(SoapFault);

		internal static Type typeofTypeArray = typeof(Type[]);

		internal static Type typeofIConstructionCallMessage = typeof(IConstructionCallMessage);

		internal static Type typeofIMethodCallMessage = typeof(IMethodCallMessage);

		internal static Type typeofReturnMessage = typeof(ReturnMessage);

		internal static Type typeofSystemVoid = typeof(void);

		internal static Type typeofInternalSoapMessage = typeof(InternalSoapMessage);

		internal static Type typeofHeader = typeof(Header);

		internal static Type typeofMarshalByRefObject = typeof(MarshalByRefObject);

		internal static Assembly urtAssembly = Assembly.GetAssembly(typeofString);

		internal static string urtAssemblyString = urtAssembly.FullName;

		private Converter()
		{
		}

		internal static InternalPrimitiveTypeE SoapToCode(Type type)
		{
			return ToCode(type);
		}

		internal static InternalPrimitiveTypeE ToCode(Type type)
		{
			InternalPrimitiveTypeE result = InternalPrimitiveTypeE.Invalid;
			if (type.IsEnum)
			{
				return result = InternalPrimitiveTypeE.Invalid;
			}
			TypeCode typeCode = Type.GetTypeCode(type);
			if (typeCode == TypeCode.Object)
			{
				if (!typeofISoapXsd.IsAssignableFrom(type))
				{
					result = ((type == typeofTimeSpan) ? InternalPrimitiveTypeE.TimeSpan : InternalPrimitiveTypeE.Invalid);
				}
				else if (type == typeofSoapTime)
				{
					result = InternalPrimitiveTypeE.Time;
				}
				else if (type == typeofSoapDate)
				{
					result = InternalPrimitiveTypeE.Date;
				}
				else if (type == typeofSoapYearMonth)
				{
					result = InternalPrimitiveTypeE.YearMonth;
				}
				else if (type == typeofSoapYear)
				{
					result = InternalPrimitiveTypeE.Year;
				}
				else if (type == typeofSoapMonthDay)
				{
					result = InternalPrimitiveTypeE.MonthDay;
				}
				else if (type == typeofSoapDay)
				{
					result = InternalPrimitiveTypeE.Day;
				}
				else if (type == typeofSoapMonth)
				{
					result = InternalPrimitiveTypeE.Month;
				}
				else if (type == typeofSoapHexBinary)
				{
					result = InternalPrimitiveTypeE.HexBinary;
				}
				else if (type == typeofSoapBase64Binary)
				{
					result = InternalPrimitiveTypeE.Base64Binary;
				}
				else if (type == typeofSoapInteger)
				{
					result = InternalPrimitiveTypeE.Integer;
				}
				else if (type == typeofSoapPositiveInteger)
				{
					result = InternalPrimitiveTypeE.PositiveInteger;
				}
				else if (type == typeofSoapNonPositiveInteger)
				{
					result = InternalPrimitiveTypeE.NonPositiveInteger;
				}
				else if (type == typeofSoapNonNegativeInteger)
				{
					result = InternalPrimitiveTypeE.NonNegativeInteger;
				}
				else if (type == typeofSoapNegativeInteger)
				{
					result = InternalPrimitiveTypeE.NegativeInteger;
				}
				else if (type == typeofSoapAnyUri)
				{
					result = InternalPrimitiveTypeE.AnyUri;
				}
				else if (type == typeofSoapQName)
				{
					result = InternalPrimitiveTypeE.QName;
				}
				else if (type == typeofSoapNotation)
				{
					result = InternalPrimitiveTypeE.Notation;
				}
				else if (type == typeofSoapNormalizedString)
				{
					result = InternalPrimitiveTypeE.NormalizedString;
				}
				else if (type == typeofSoapToken)
				{
					result = InternalPrimitiveTypeE.Token;
				}
				else if (type == typeofSoapLanguage)
				{
					result = InternalPrimitiveTypeE.Language;
				}
				else if (type == typeofSoapName)
				{
					result = InternalPrimitiveTypeE.Name;
				}
				else if (type == typeofSoapIdrefs)
				{
					result = InternalPrimitiveTypeE.Idrefs;
				}
				else if (type == typeofSoapEntities)
				{
					result = InternalPrimitiveTypeE.Entities;
				}
				else if (type == typeofSoapNmtoken)
				{
					result = InternalPrimitiveTypeE.Nmtoken;
				}
				else if (type == typeofSoapNmtokens)
				{
					result = InternalPrimitiveTypeE.Nmtokens;
				}
				else if (type == typeofSoapNcName)
				{
					result = InternalPrimitiveTypeE.NcName;
				}
				else if (type == typeofSoapId)
				{
					result = InternalPrimitiveTypeE.Id;
				}
				else if (type == typeofSoapIdref)
				{
					result = InternalPrimitiveTypeE.Idref;
				}
				else if (type == typeofSoapEntity)
				{
					result = InternalPrimitiveTypeE.Entity;
				}
			}
			else
			{
				result = ToPrimitiveTypeEnum(typeCode);
			}
			return result;
		}

		internal static InternalPrimitiveTypeE ToCode(string value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("serParser", string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("ArgumentNull_WithParamName"), value));
			}
			string text = value.ToLower(CultureInfo.InvariantCulture);
			char c = text[0];
			InternalPrimitiveTypeE result = InternalPrimitiveTypeE.Invalid;
			switch (c)
			{
			case 'a':
				if (text == "anyuri")
				{
					result = InternalPrimitiveTypeE.AnyUri;
				}
				break;
			case 'b':
				switch (text)
				{
				case "boolean":
					result = InternalPrimitiveTypeE.Boolean;
					break;
				case "byte":
					result = InternalPrimitiveTypeE.SByte;
					break;
				case "base64binary":
					result = InternalPrimitiveTypeE.Base64Binary;
					break;
				case "base64":
					result = InternalPrimitiveTypeE.Base64Binary;
					break;
				}
				break;
			case 'c':
				if (text == "char" || text == "character")
				{
					result = InternalPrimitiveTypeE.Char;
				}
				break;
			case 'd':
				if (text == "double")
				{
					result = InternalPrimitiveTypeE.Double;
				}
				switch (text)
				{
				case "datetime":
					result = InternalPrimitiveTypeE.DateTime;
					break;
				case "duration":
					result = InternalPrimitiveTypeE.TimeSpan;
					break;
				case "date":
					result = InternalPrimitiveTypeE.Date;
					break;
				case "decimal":
					result = InternalPrimitiveTypeE.Decimal;
					break;
				}
				break;
			case 'e':
				if (text == "entities")
				{
					result = InternalPrimitiveTypeE.Entities;
				}
				else if (text == "entity")
				{
					result = InternalPrimitiveTypeE.Entity;
				}
				break;
			case 'f':
				if (text == "float")
				{
					result = InternalPrimitiveTypeE.Single;
				}
				break;
			case 'g':
				switch (text)
				{
				case "gyearmonth":
					result = InternalPrimitiveTypeE.YearMonth;
					break;
				case "gyear":
					result = InternalPrimitiveTypeE.Year;
					break;
				case "gmonthday":
					result = InternalPrimitiveTypeE.MonthDay;
					break;
				case "gday":
					result = InternalPrimitiveTypeE.Day;
					break;
				case "gmonth":
					result = InternalPrimitiveTypeE.Month;
					break;
				}
				break;
			case 'h':
				if (text == "hexbinary")
				{
					result = InternalPrimitiveTypeE.HexBinary;
				}
				break;
			case 'i':
				if (text == "int")
				{
					result = InternalPrimitiveTypeE.Int32;
				}
				switch (text)
				{
				case "integer":
					result = InternalPrimitiveTypeE.Integer;
					break;
				case "idrefs":
					result = InternalPrimitiveTypeE.Idrefs;
					break;
				case "id":
					result = InternalPrimitiveTypeE.Id;
					break;
				case "idref":
					result = InternalPrimitiveTypeE.Idref;
					break;
				}
				break;
			case 'l':
				if (text == "long")
				{
					result = InternalPrimitiveTypeE.Int64;
				}
				else if (text == "language")
				{
					result = InternalPrimitiveTypeE.Language;
				}
				break;
			case 'n':
				switch (text)
				{
				case "number":
					result = InternalPrimitiveTypeE.Decimal;
					break;
				case "normalizedstring":
					result = InternalPrimitiveTypeE.NormalizedString;
					break;
				case "nonpositiveinteger":
					result = InternalPrimitiveTypeE.NonPositiveInteger;
					break;
				case "negativeinteger":
					result = InternalPrimitiveTypeE.NegativeInteger;
					break;
				case "nonnegativeinteger":
					result = InternalPrimitiveTypeE.NonNegativeInteger;
					break;
				case "notation":
					result = InternalPrimitiveTypeE.Notation;
					break;
				case "nmtoken":
					result = InternalPrimitiveTypeE.Nmtoken;
					break;
				case "nmtokens":
					result = InternalPrimitiveTypeE.Nmtokens;
					break;
				case "name":
					result = InternalPrimitiveTypeE.Name;
					break;
				case "ncname":
					result = InternalPrimitiveTypeE.NcName;
					break;
				}
				break;
			case 'p':
				if (text == "positiveinteger")
				{
					result = InternalPrimitiveTypeE.PositiveInteger;
				}
				break;
			case 'q':
				if (text == "qname")
				{
					result = InternalPrimitiveTypeE.QName;
				}
				break;
			case 's':
				switch (text)
				{
				case "short":
					result = InternalPrimitiveTypeE.Int16;
					break;
				case "system.byte":
					result = InternalPrimitiveTypeE.Byte;
					break;
				case "system.sbyte":
					result = InternalPrimitiveTypeE.SByte;
					break;
				case "system":
					result = ToCode(value.Substring(7));
					break;
				case "system.runtime.remoting.metadata":
					result = ToCode(value.Substring(33));
					break;
				}
				break;
			case 't':
				switch (text)
				{
				case "time":
					result = InternalPrimitiveTypeE.Time;
					break;
				case "token":
					result = InternalPrimitiveTypeE.Token;
					break;
				case "timeinstant":
					result = InternalPrimitiveTypeE.DateTime;
					break;
				case "timeduration":
					result = InternalPrimitiveTypeE.TimeSpan;
					break;
				}
				break;
			case 'u':
				switch (text)
				{
				case "unsignedlong":
					result = InternalPrimitiveTypeE.UInt64;
					break;
				case "unsignedint":
					result = InternalPrimitiveTypeE.UInt32;
					break;
				case "unsignedshort":
					result = InternalPrimitiveTypeE.UInt16;
					break;
				case "unsignedbyte":
					result = InternalPrimitiveTypeE.Byte;
					break;
				}
				break;
			default:
				result = InternalPrimitiveTypeE.Invalid;
				break;
			}
			return result;
		}

		internal static bool IsWriteAsByteArray(InternalPrimitiveTypeE code)
		{
			bool result = false;
			switch (code)
			{
			case InternalPrimitiveTypeE.Boolean:
			case InternalPrimitiveTypeE.Byte:
			case InternalPrimitiveTypeE.Char:
			case InternalPrimitiveTypeE.Double:
			case InternalPrimitiveTypeE.Int16:
			case InternalPrimitiveTypeE.Int32:
			case InternalPrimitiveTypeE.Int64:
			case InternalPrimitiveTypeE.SByte:
			case InternalPrimitiveTypeE.Single:
			case InternalPrimitiveTypeE.UInt16:
			case InternalPrimitiveTypeE.UInt32:
			case InternalPrimitiveTypeE.UInt64:
				result = true;
				break;
			}
			return result;
		}

		internal static InternalNameSpaceE GetNameSpaceEnum(InternalPrimitiveTypeE code, Type type, WriteObjectInfo objectInfo, out string typeName)
		{
			InternalNameSpaceE internalNameSpaceE = InternalNameSpaceE.None;
			typeName = null;
			switch (code)
			{
			case InternalPrimitiveTypeE.Char:
				internalNameSpaceE = InternalNameSpaceE.UrtSystem;
				typeName = "System.Char";
				break;
			default:
				internalNameSpaceE = InternalNameSpaceE.XdrPrimitive;
				typeName = ToXmlDataType(code);
				break;
			case InternalPrimitiveTypeE.Invalid:
				break;
			}
			if (internalNameSpaceE == InternalNameSpaceE.None && type != null)
			{
				if (type == typeofString)
				{
					internalNameSpaceE = InternalNameSpaceE.XdrString;
				}
				else if (objectInfo == null)
				{
					typeName = type.FullName;
					internalNameSpaceE = ((type.Module.Assembly != urtAssembly) ? InternalNameSpaceE.UrtUser : InternalNameSpaceE.UrtSystem);
				}
				else
				{
					typeName = objectInfo.GetTypeFullName();
					internalNameSpaceE = ((!objectInfo.GetAssemblyString().Equals(urtAssemblyString)) ? InternalNameSpaceE.UrtUser : InternalNameSpaceE.UrtSystem);
				}
			}
			if (objectInfo != null)
			{
				if (!objectInfo.isSi && (objectInfo.IsAttributeNameSpace() || objectInfo.IsCustomXmlAttribute() || objectInfo.IsCustomXmlElement()))
				{
					internalNameSpaceE = InternalNameSpaceE.Interop;
				}
				else if (objectInfo.IsCallElement())
				{
					internalNameSpaceE = InternalNameSpaceE.CallElement;
				}
			}
			return internalNameSpaceE;
		}

		internal static bool IsSiTransmitType(InternalPrimitiveTypeE code)
		{
			switch (code)
			{
			case InternalPrimitiveTypeE.Invalid:
			case InternalPrimitiveTypeE.TimeSpan:
			case InternalPrimitiveTypeE.DateTime:
			case InternalPrimitiveTypeE.Time:
			case InternalPrimitiveTypeE.Date:
			case InternalPrimitiveTypeE.YearMonth:
			case InternalPrimitiveTypeE.Year:
			case InternalPrimitiveTypeE.MonthDay:
			case InternalPrimitiveTypeE.Day:
			case InternalPrimitiveTypeE.Month:
			case InternalPrimitiveTypeE.HexBinary:
			case InternalPrimitiveTypeE.Base64Binary:
			case InternalPrimitiveTypeE.Integer:
			case InternalPrimitiveTypeE.PositiveInteger:
			case InternalPrimitiveTypeE.NonPositiveInteger:
			case InternalPrimitiveTypeE.NonNegativeInteger:
			case InternalPrimitiveTypeE.NegativeInteger:
			case InternalPrimitiveTypeE.AnyUri:
			case InternalPrimitiveTypeE.QName:
			case InternalPrimitiveTypeE.Notation:
			case InternalPrimitiveTypeE.NormalizedString:
			case InternalPrimitiveTypeE.Token:
			case InternalPrimitiveTypeE.Language:
			case InternalPrimitiveTypeE.Name:
			case InternalPrimitiveTypeE.Idrefs:
			case InternalPrimitiveTypeE.Entities:
			case InternalPrimitiveTypeE.Nmtoken:
			case InternalPrimitiveTypeE.Nmtokens:
			case InternalPrimitiveTypeE.NcName:
			case InternalPrimitiveTypeE.Id:
			case InternalPrimitiveTypeE.Idref:
			case InternalPrimitiveTypeE.Entity:
				return true;
			default:
				return false;
			}
		}

		private static void InitTypeA()
		{
			typeA = new Type[primitiveTypeEnumLength];
			typeA[0] = null;
			typeA[1] = typeofBoolean;
			typeA[2] = typeofByte;
			typeA[3] = typeofChar;
			typeA[5] = typeofDecimal;
			typeA[6] = typeofDouble;
			typeA[7] = typeofInt16;
			typeA[8] = typeofInt32;
			typeA[9] = typeofInt64;
			typeA[10] = typeofSByte;
			typeA[11] = typeofSingle;
			typeA[12] = typeofTimeSpan;
			typeA[13] = typeofDateTime;
			typeA[14] = typeofUInt16;
			typeA[15] = typeofUInt32;
			typeA[16] = typeofUInt64;
			typeA[17] = typeofSoapTime;
			typeA[18] = typeofSoapDate;
			typeA[19] = typeofSoapYearMonth;
			typeA[20] = typeofSoapYear;
			typeA[21] = typeofSoapMonthDay;
			typeA[22] = typeofSoapDay;
			typeA[23] = typeofSoapMonth;
			typeA[24] = typeofSoapHexBinary;
			typeA[25] = typeofSoapBase64Binary;
			typeA[26] = typeofSoapInteger;
			typeA[27] = typeofSoapPositiveInteger;
			typeA[28] = typeofSoapNonPositiveInteger;
			typeA[29] = typeofSoapNonNegativeInteger;
			typeA[30] = typeofSoapNegativeInteger;
			typeA[31] = typeofSoapAnyUri;
			typeA[32] = typeofSoapQName;
			typeA[33] = typeofSoapNotation;
			typeA[34] = typeofSoapNormalizedString;
			typeA[35] = typeofSoapToken;
			typeA[36] = typeofSoapLanguage;
			typeA[37] = typeofSoapName;
			typeA[38] = typeofSoapIdrefs;
			typeA[39] = typeofSoapEntities;
			typeA[40] = typeofSoapNmtoken;
			typeA[41] = typeofSoapNmtokens;
			typeA[42] = typeofSoapNcName;
			typeA[43] = typeofSoapId;
			typeA[44] = typeofSoapIdref;
			typeA[45] = typeofSoapEntity;
		}

		internal static Type SoapToType(InternalPrimitiveTypeE code)
		{
			return ToType(code);
		}

		internal static Type ToType(InternalPrimitiveTypeE code)
		{
			lock (typeofConverter)
			{
				if (typeA == null)
				{
					InitTypeA();
				}
			}
			return typeA[(int)code];
		}

		private static void InitValueA()
		{
			valueA = new string[primitiveTypeEnumLength];
			valueA[0] = null;
			valueA[1] = "System.Boolean";
			valueA[2] = "System.Byte";
			valueA[3] = "System.Char";
			valueA[5] = "System.Decimal";
			valueA[6] = "System.Double";
			valueA[7] = "System.Int16";
			valueA[8] = "System.Int32";
			valueA[9] = "System.Int64";
			valueA[10] = "System.SByte";
			valueA[11] = "System.Single";
			valueA[12] = "System.TimeSpan";
			valueA[13] = "System.DateTime";
			valueA[14] = "System.UInt16";
			valueA[15] = "System.UInt32";
			valueA[16] = "System.UInt64";
			valueA[17] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapTime";
			valueA[18] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapDate";
			valueA[19] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapYearMonth";
			valueA[20] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapYear";
			valueA[21] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapMonthDay";
			valueA[22] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapDay";
			valueA[23] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapMonth";
			valueA[24] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary";
			valueA[25] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapBase64Binary";
			valueA[26] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapInteger";
			valueA[27] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapPositiveInteger";
			valueA[28] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNonPositiveInteger";
			valueA[29] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNonNegativeInteger";
			valueA[30] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNegativeInteger";
			valueA[31] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapAnyUri";
			valueA[32] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapQName";
			valueA[33] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNotation";
			valueA[34] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNormalizedString";
			valueA[35] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapToken";
			valueA[36] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapLanguage";
			valueA[37] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapName";
			valueA[38] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapIdrefs";
			valueA[39] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapEntities";
			valueA[40] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNmtoken";
			valueA[41] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNmtokens";
			valueA[42] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapNcName";
			valueA[43] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapId";
			valueA[44] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapIdref";
			valueA[45] = "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapEntity";
		}

		internal static string SoapToComType(InternalPrimitiveTypeE code)
		{
			return ToComType(code);
		}

		internal static string ToComType(InternalPrimitiveTypeE code)
		{
			lock (typeofConverter)
			{
				if (valueA == null)
				{
					InitValueA();
				}
			}
			return valueA[(int)code];
		}

		private static void InitValueB()
		{
			valueB = new string[primitiveTypeEnumLength];
			valueB[0] = null;
			valueB[1] = "boolean";
			valueB[2] = "unsignedByte";
			valueB[3] = "char";
			valueB[5] = "decimal";
			valueB[6] = "double";
			valueB[7] = "short";
			valueB[8] = "int";
			valueB[9] = "long";
			valueB[10] = "byte";
			valueB[11] = "float";
			valueB[12] = "duration";
			valueB[13] = "dateTime";
			valueB[14] = "unsignedShort";
			valueB[15] = "unsignedInt";
			valueB[16] = "unsignedLong";
			valueB[17] = SoapTime.XsdType;
			valueB[18] = SoapDate.XsdType;
			valueB[19] = SoapYearMonth.XsdType;
			valueB[20] = SoapYear.XsdType;
			valueB[21] = SoapMonthDay.XsdType;
			valueB[22] = SoapDay.XsdType;
			valueB[23] = SoapMonth.XsdType;
			valueB[24] = SoapHexBinary.XsdType;
			valueB[25] = SoapBase64Binary.XsdType;
			valueB[26] = SoapInteger.XsdType;
			valueB[27] = SoapPositiveInteger.XsdType;
			valueB[28] = SoapNonPositiveInteger.XsdType;
			valueB[29] = SoapNonNegativeInteger.XsdType;
			valueB[30] = SoapNegativeInteger.XsdType;
			valueB[31] = SoapAnyUri.XsdType;
			valueB[32] = SoapQName.XsdType;
			valueB[33] = SoapNotation.XsdType;
			valueB[34] = SoapNormalizedString.XsdType;
			valueB[35] = SoapToken.XsdType;
			valueB[36] = SoapLanguage.XsdType;
			valueB[37] = SoapName.XsdType;
			valueB[38] = SoapIdrefs.XsdType;
			valueB[39] = SoapEntities.XsdType;
			valueB[40] = SoapNmtoken.XsdType;
			valueB[41] = SoapNmtokens.XsdType;
			valueB[42] = SoapNcName.XsdType;
			valueB[43] = SoapId.XsdType;
			valueB[44] = SoapIdref.XsdType;
			valueB[45] = SoapEntity.XsdType;
		}

		internal static string ToXmlDataType(InternalPrimitiveTypeE code)
		{
			lock (typeofConverter)
			{
				if (valueB == null)
				{
					InitValueB();
				}
			}
			return valueB[(int)code];
		}

		private static void InitTypeCodeA()
		{
			typeCodeA = new TypeCode[primitiveTypeEnumLength];
			typeCodeA[0] = TypeCode.Object;
			typeCodeA[1] = TypeCode.Boolean;
			typeCodeA[2] = TypeCode.Byte;
			typeCodeA[3] = TypeCode.Char;
			typeCodeA[5] = TypeCode.Decimal;
			typeCodeA[6] = TypeCode.Double;
			typeCodeA[7] = TypeCode.Int16;
			typeCodeA[8] = TypeCode.Int32;
			typeCodeA[9] = TypeCode.Int64;
			typeCodeA[10] = TypeCode.SByte;
			typeCodeA[11] = TypeCode.Single;
			typeCodeA[12] = TypeCode.Object;
			typeCodeA[13] = TypeCode.DateTime;
			typeCodeA[14] = TypeCode.UInt16;
			typeCodeA[15] = TypeCode.UInt32;
			typeCodeA[16] = TypeCode.UInt64;
			typeCodeA[17] = TypeCode.Object;
			typeCodeA[18] = TypeCode.Object;
			typeCodeA[19] = TypeCode.Object;
			typeCodeA[20] = TypeCode.Object;
			typeCodeA[21] = TypeCode.Object;
			typeCodeA[22] = TypeCode.Object;
			typeCodeA[23] = TypeCode.Object;
			typeCodeA[24] = TypeCode.Object;
			typeCodeA[25] = TypeCode.Object;
			typeCodeA[26] = TypeCode.Object;
			typeCodeA[27] = TypeCode.Object;
			typeCodeA[28] = TypeCode.Object;
			typeCodeA[29] = TypeCode.Object;
			typeCodeA[30] = TypeCode.Object;
			typeCodeA[31] = TypeCode.Object;
			typeCodeA[32] = TypeCode.Object;
			typeCodeA[33] = TypeCode.Object;
			typeCodeA[34] = TypeCode.Object;
			typeCodeA[35] = TypeCode.Object;
			typeCodeA[36] = TypeCode.Object;
			typeCodeA[37] = TypeCode.Object;
			typeCodeA[38] = TypeCode.Object;
			typeCodeA[39] = TypeCode.Object;
			typeCodeA[40] = TypeCode.Object;
			typeCodeA[41] = TypeCode.Object;
			typeCodeA[42] = TypeCode.Object;
			typeCodeA[43] = TypeCode.Object;
			typeCodeA[44] = TypeCode.Object;
			typeCodeA[45] = TypeCode.Object;
		}

		internal static TypeCode ToTypeCode(InternalPrimitiveTypeE code)
		{
			lock (typeofConverter)
			{
				if (typeCodeA == null)
				{
					InitTypeCodeA();
				}
			}
			return typeCodeA[(int)code];
		}

		private static void InitCodeA()
		{
			codeA = new InternalPrimitiveTypeE[19];
			codeA[0] = InternalPrimitiveTypeE.Invalid;
			codeA[1] = InternalPrimitiveTypeE.Invalid;
			codeA[2] = InternalPrimitiveTypeE.Invalid;
			codeA[3] = InternalPrimitiveTypeE.Boolean;
			codeA[4] = InternalPrimitiveTypeE.Char;
			codeA[5] = InternalPrimitiveTypeE.SByte;
			codeA[6] = InternalPrimitiveTypeE.Byte;
			codeA[7] = InternalPrimitiveTypeE.Int16;
			codeA[8] = InternalPrimitiveTypeE.UInt16;
			codeA[9] = InternalPrimitiveTypeE.Int32;
			codeA[10] = InternalPrimitiveTypeE.UInt32;
			codeA[11] = InternalPrimitiveTypeE.Int64;
			codeA[12] = InternalPrimitiveTypeE.UInt64;
			codeA[13] = InternalPrimitiveTypeE.Single;
			codeA[14] = InternalPrimitiveTypeE.Double;
			codeA[15] = InternalPrimitiveTypeE.Decimal;
			codeA[16] = InternalPrimitiveTypeE.DateTime;
			codeA[17] = InternalPrimitiveTypeE.Invalid;
			codeA[18] = InternalPrimitiveTypeE.Invalid;
		}

		internal static InternalPrimitiveTypeE ToPrimitiveTypeEnum(TypeCode typeCode)
		{
			lock (typeofConverter)
			{
				if (codeA == null)
				{
					InitCodeA();
				}
			}
			return codeA[(int)typeCode];
		}

		private static void InitEscapeA()
		{
			escapeA = new bool[primitiveTypeEnumLength];
			escapeA[0] = true;
			escapeA[1] = false;
			escapeA[2] = false;
			escapeA[3] = true;
			escapeA[5] = false;
			escapeA[6] = false;
			escapeA[7] = false;
			escapeA[8] = false;
			escapeA[9] = false;
			escapeA[10] = false;
			escapeA[11] = false;
			escapeA[12] = false;
			escapeA[13] = false;
			escapeA[14] = false;
			escapeA[15] = false;
			escapeA[16] = false;
			escapeA[17] = false;
			escapeA[18] = false;
			escapeA[19] = false;
			escapeA[20] = false;
			escapeA[21] = false;
			escapeA[22] = false;
			escapeA[23] = false;
			escapeA[24] = false;
			escapeA[25] = false;
			escapeA[26] = false;
			escapeA[27] = false;
			escapeA[28] = false;
			escapeA[29] = false;
			escapeA[30] = false;
			escapeA[31] = true;
			escapeA[32] = true;
			escapeA[33] = true;
			escapeA[34] = false;
			escapeA[35] = true;
			escapeA[36] = true;
			escapeA[37] = true;
			escapeA[38] = true;
			escapeA[39] = true;
			escapeA[40] = true;
			escapeA[41] = true;
			escapeA[42] = true;
			escapeA[43] = true;
			escapeA[44] = true;
			escapeA[45] = true;
		}

		internal static bool IsEscaped(InternalPrimitiveTypeE code)
		{
			lock (typeofConverter)
			{
				if (escapeA == null)
				{
					InitEscapeA();
				}
			}
			return escapeA[(int)code];
		}

		internal static string SoapToString(object data, InternalPrimitiveTypeE code)
		{
			return ToString(data, code);
		}

		internal static string ToString(object data, InternalPrimitiveTypeE code)
		{
			switch (code)
			{
			case InternalPrimitiveTypeE.Boolean:
				if ((bool)data)
				{
					return "true";
				}
				return "false";
			case InternalPrimitiveTypeE.TimeSpan:
				return SoapDuration.ToString((TimeSpan)data);
			case InternalPrimitiveTypeE.DateTime:
				return SoapDateTime.ToString((DateTime)data);
			case InternalPrimitiveTypeE.Invalid:
				return data.ToString();
			case InternalPrimitiveTypeE.Double:
			{
				double d = (double)data;
				if (double.IsPositiveInfinity(d))
				{
					return "INF";
				}
				if (double.IsNegativeInfinity(d))
				{
					return "-INF";
				}
				return d.ToString("R", CultureInfo.InvariantCulture);
			}
			case InternalPrimitiveTypeE.Single:
			{
				float f = (float)data;
				if (float.IsPositiveInfinity(f))
				{
					return "INF";
				}
				if (float.IsNegativeInfinity(f))
				{
					return "-INF";
				}
				return f.ToString("R", CultureInfo.InvariantCulture);
			}
			case InternalPrimitiveTypeE.Time:
			case InternalPrimitiveTypeE.Date:
			case InternalPrimitiveTypeE.YearMonth:
			case InternalPrimitiveTypeE.Year:
			case InternalPrimitiveTypeE.MonthDay:
			case InternalPrimitiveTypeE.Day:
			case InternalPrimitiveTypeE.Month:
			case InternalPrimitiveTypeE.HexBinary:
			case InternalPrimitiveTypeE.Base64Binary:
			case InternalPrimitiveTypeE.Integer:
			case InternalPrimitiveTypeE.PositiveInteger:
			case InternalPrimitiveTypeE.NonPositiveInteger:
			case InternalPrimitiveTypeE.NonNegativeInteger:
			case InternalPrimitiveTypeE.NegativeInteger:
			case InternalPrimitiveTypeE.AnyUri:
			case InternalPrimitiveTypeE.QName:
			case InternalPrimitiveTypeE.Notation:
			case InternalPrimitiveTypeE.NormalizedString:
			case InternalPrimitiveTypeE.Token:
			case InternalPrimitiveTypeE.Language:
			case InternalPrimitiveTypeE.Name:
			case InternalPrimitiveTypeE.Idrefs:
			case InternalPrimitiveTypeE.Entities:
			case InternalPrimitiveTypeE.Nmtoken:
			case InternalPrimitiveTypeE.Nmtokens:
			case InternalPrimitiveTypeE.NcName:
			case InternalPrimitiveTypeE.Id:
			case InternalPrimitiveTypeE.Idref:
			case InternalPrimitiveTypeE.Entity:
				return data.ToString();
			default:
				return (string)Convert.ChangeType(data, typeofString, CultureInfo.InvariantCulture);
			}
		}

		internal static object FromString(string value, InternalPrimitiveTypeE code)
		{
			switch (code)
			{
			case InternalPrimitiveTypeE.Boolean:
				switch (value)
				{
				case "1":
				case "true":
					return true;
				case "0":
				case "false":
					return false;
				default:
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_typeCoercion"), value, "Boolean"));
				}
			case InternalPrimitiveTypeE.TimeSpan:
				return SoapDuration.Parse(value);
			case InternalPrimitiveTypeE.DateTime:
				return SoapDateTime.Parse(value);
			case InternalPrimitiveTypeE.Double:
				if (value == "INF")
				{
					return double.PositiveInfinity;
				}
				if (value == "-INF")
				{
					return double.NegativeInfinity;
				}
				return double.Parse(value, CultureInfo.InvariantCulture);
			case InternalPrimitiveTypeE.Single:
				if (value == "INF")
				{
					return float.PositiveInfinity;
				}
				if (value == "-INF")
				{
					return float.NegativeInfinity;
				}
				return float.Parse(value, CultureInfo.InvariantCulture);
			case InternalPrimitiveTypeE.Time:
				return SoapTime.Parse(value);
			case InternalPrimitiveTypeE.Date:
				return SoapDate.Parse(value);
			case InternalPrimitiveTypeE.YearMonth:
				return SoapYearMonth.Parse(value);
			case InternalPrimitiveTypeE.Year:
				return SoapYear.Parse(value);
			case InternalPrimitiveTypeE.MonthDay:
				return SoapMonthDay.Parse(value);
			case InternalPrimitiveTypeE.Day:
				return SoapDay.Parse(value);
			case InternalPrimitiveTypeE.Month:
				return SoapMonth.Parse(value);
			case InternalPrimitiveTypeE.HexBinary:
				return SoapHexBinary.Parse(value);
			case InternalPrimitiveTypeE.Base64Binary:
				return SoapBase64Binary.Parse(value);
			case InternalPrimitiveTypeE.Integer:
				return SoapInteger.Parse(value);
			case InternalPrimitiveTypeE.PositiveInteger:
				return SoapPositiveInteger.Parse(value);
			case InternalPrimitiveTypeE.NonPositiveInteger:
				return SoapNonPositiveInteger.Parse(value);
			case InternalPrimitiveTypeE.NonNegativeInteger:
				return SoapNonNegativeInteger.Parse(value);
			case InternalPrimitiveTypeE.NegativeInteger:
				return SoapNegativeInteger.Parse(value);
			case InternalPrimitiveTypeE.AnyUri:
				return SoapAnyUri.Parse(value);
			case InternalPrimitiveTypeE.QName:
				return SoapQName.Parse(value);
			case InternalPrimitiveTypeE.Notation:
				return SoapNotation.Parse(value);
			case InternalPrimitiveTypeE.NormalizedString:
				return SoapNormalizedString.Parse(value);
			case InternalPrimitiveTypeE.Token:
				return SoapToken.Parse(value);
			case InternalPrimitiveTypeE.Language:
				return SoapLanguage.Parse(value);
			case InternalPrimitiveTypeE.Name:
				return SoapName.Parse(value);
			case InternalPrimitiveTypeE.Idrefs:
				return SoapIdrefs.Parse(value);
			case InternalPrimitiveTypeE.Entities:
				return SoapEntities.Parse(value);
			case InternalPrimitiveTypeE.Nmtoken:
				return SoapNmtoken.Parse(value);
			case InternalPrimitiveTypeE.Nmtokens:
				return SoapNmtokens.Parse(value);
			case InternalPrimitiveTypeE.NcName:
				return SoapNcName.Parse(value);
			case InternalPrimitiveTypeE.Id:
				return SoapId.Parse(value);
			case InternalPrimitiveTypeE.Idref:
				return SoapIdref.Parse(value);
			case InternalPrimitiveTypeE.Entity:
				return SoapEntity.Parse(value);
			default:
				if (code != 0)
				{
					return Convert.ChangeType(value, ToTypeCode(code), CultureInfo.InvariantCulture);
				}
				return value;
			}
		}
	}
	internal sealed class SoapWriter
	{
		internal struct DottedInfo
		{
			internal string dottedAssemblyName;

			internal string name;

			internal string nameSpace;

			internal int assemId;
		}

		internal sealed class AssemblyInfo
		{
			internal int id;

			internal string name;

			internal string prefix;

			internal bool isInteropType;

			internal bool isUsed;

			internal AssemblyInfo(int id, string name, bool isInteropType)
			{
				this.id = id;
				this.name = name;
				this.isInteropType = isInteropType;
				isUsed = false;
			}
		}

		private const int StringBuilderSize = 1024;

		private static string _soapStartStr;

		private static string _soapStart1999Str;

		private static string _soapStart2000Str;

		private static byte[] _soapStart;

		private static byte[] _soapStart1999;

		private static byte[] _soapStart2000;

		public static Dictionary<char, string> encodingTable;

		private AttributeList attrList = new AttributeList();

		private AttributeList attrValueList = new AttributeList();

		private int lineIndent = 4;

		private int instanceIndent = 1;

		private StringBuilder stringBuffer = new StringBuilder(120);

		private StringBuilder sb = new StringBuilder(120);

		private int topId;

		private int headerId;

		private Hashtable assemblyInfos = new Hashtable(10);

		private StreamWriter writer;

		private Stream stream;

		private Hashtable typeNameToDottedInfoTable;

		private Hashtable dottedAssemToAssemIdTable;

		private Hashtable assemblyInfoUsed = new Hashtable(10);

		private int dottedAssemId = 1;

		internal bool isUsedEnc;

		private XsdVersion xsdVersion = XsdVersion.V2001;

		private NameCache nameCache = new NameCache();

		private StringBuilder traceBuffer;

		private StringBuilder sbOffset = new StringBuilder(10);

		private StringBuilder sb1 = new StringBuilder("ref-", 15);

		private StringBuilder sb2 = new StringBuilder("a-", 15);

		private StringBuilder sb3 = new StringBuilder("i-", 15);

		private StringBuilder sb4 = new StringBuilder("#ref-", 16);

		static SoapWriter()
		{
			_soapStartStr = "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"";
			_soapStart1999Str = "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/1999/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/1999/XMLSchema\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"";
			_soapStart2000Str = "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2000/10/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2000/10/XMLSchema\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"";
			_soapStart = Encoding.UTF8.GetBytes(_soapStartStr);
			_soapStart1999 = Encoding.UTF8.GetBytes(_soapStart1999Str);
			_soapStart2000 = Encoding.UTF8.GetBytes(_soapStart2000Str);
			encodingTable = new Dictionary<char, string>();
			encodingTable.Add('&', "&#38;");
			encodingTable.Add('"', "&#34;");
			encodingTable.Add('\'', "&#39;");
			encodingTable.Add('<', "&#60;");
			encodingTable.Add('>', "&#62;");
			encodingTable.Add('\0', "&#0;");
			encodingTable.Add('\v', "&#xB;");
			encodingTable.Add('\f', "&#xC;");
			for (int i = 1; i < 9; i++)
			{
				encodingTable.Add(((IConvertible)i).ToChar((IFormatProvider)NumberFormatInfo.InvariantInfo), "&#x" + i.ToString("X", CultureInfo.InvariantCulture) + ";");
			}
			for (int j = 14; j < 32; j++)
			{
				encodingTable.Add(((IConvertible)j).ToChar((IFormatProvider)NumberFormatInfo.InvariantInfo), "&#x" + j.ToString("X", CultureInfo.InvariantCulture) + ";");
			}
			for (int k = 127; k < 133; k++)
			{
				encodingTable.Add(((IConvertible)k).ToChar((IFormatProvider)NumberFormatInfo.InvariantInfo), "&#x" + k.ToString("X", CultureInfo.InvariantCulture) + ";");
			}
			for (int l = 134; l < 160; l++)
			{
				encodingTable.Add(((IConvertible)l).ToChar((IFormatProvider)NumberFormatInfo.InvariantInfo), "&#x" + l.ToString("X", CultureInfo.InvariantCulture) + ";");
			}
		}

		internal SoapWriter(Stream stream)
		{
			this.stream = stream;
			UTF8Encoding encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
			writer = new StreamWriter(stream, encoding, 1024);
			typeNameToDottedInfoTable = new Hashtable(20);
			dottedAssemToAssemIdTable = new Hashtable(20);
		}

		[Conditional("_DEBUG")]
		private void EmitIndent(int count)
		{
			while (--count >= 0)
			{
				for (int i = 0; i < lineIndent; i++)
				{
					writer.Write(' ');
				}
			}
		}

		[Conditional("_DEBUG")]
		private void EmitLine(int indent, string value)
		{
			writer.Write(value);
			EmitLine();
		}

		private void EmitLine()
		{
			writer.Write("\r\n");
		}

		private string Escape(string value)
		{
			stringBuffer.Length = 0;
			foreach (char c in value)
			{
				if (encodingTable.ContainsKey(c))
				{
					stringBuffer.Append(encodingTable[c]);
				}
				else
				{
					stringBuffer.Append(c);
				}
			}
			string text = null;
			if (stringBuffer.Length > 0)
			{
				return stringBuffer.ToString();
			}
			return value;
		}

		private string NameEscape(string name)
		{
			string text = (string)nameCache.GetCachedValue(name);
			if (text == null)
			{
				text = XmlConvert.EncodeName(name);
				nameCache.SetCachedValue(text);
			}
			return text;
		}

		internal void Reset()
		{
			writer = null;
			stringBuffer = null;
		}

		internal void InternalWrite(string s)
		{
			writer.Write(s);
		}

		[Conditional("_LOGGING")]
		internal void TraceSoap(string s)
		{
			if (traceBuffer == null)
			{
				traceBuffer = new StringBuilder();
			}
			traceBuffer.Append(s);
		}

		[Conditional("_LOGGING")]
		internal void WriteTraceSoap()
		{
			traceBuffer.Length = 0;
		}

		internal void Write(InternalElementTypeE use, string name, AttributeList attrList, string value, bool isNameEscape, bool isValueEscape)
		{
			string s = name;
			if (isNameEscape)
			{
				s = NameEscape(name);
			}
			if (use == InternalElementTypeE.ObjectEnd)
			{
				instanceIndent--;
			}
			InternalWrite("<");
			if (use == InternalElementTypeE.ObjectEnd)
			{
				InternalWrite("/");
			}
			InternalWrite(s);
			WriteAttributeList(attrList);
			switch (use)
			{
			case InternalElementTypeE.ObjectBegin:
				InternalWrite(">");
				instanceIndent++;
				break;
			case InternalElementTypeE.ObjectEnd:
				InternalWrite(">");
				break;
			case InternalElementTypeE.Member:
				if (value == null)
				{
					InternalWrite("/>");
					break;
				}
				InternalWrite(">");
				if (isValueEscape)
				{
					InternalWrite(Escape(value));
				}
				else
				{
					InternalWrite(value);
				}
				InternalWrite("</");
				InternalWrite(s);
				InternalWrite(">");
				break;
			default:
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_UseCode"), use.ToString()));
			}
			EmitLine();
		}

		private void WriteAttributeList(AttributeList attrList)
		{
			for (int i = 0; i < attrList.Count; i++)
			{
				attrList.Get(i, out var name, out var value);
				InternalWrite(" ");
				InternalWrite(name);
				InternalWrite("=");
				InternalWrite("\"");
				InternalWrite(value);
				InternalWrite("\"");
			}
		}

		internal void WriteBegin()
		{
		}

		internal void WriteEnd()
		{
			writer.Flush();
			Reset();
		}

		internal void WriteXsdVersion(XsdVersion xsdVersion)
		{
			this.xsdVersion = xsdVersion;
		}

		internal void WriteObjectEnd(NameInfo memberNameInfo, NameInfo typeNameInfo)
		{
			attrList.Clear();
			Write(InternalElementTypeE.ObjectEnd, MemberElementName(memberNameInfo, typeNameInfo), attrList, null, isNameEscape: true, isValueEscape: false);
			assemblyInfoUsed.Clear();
		}

		internal void WriteSerializationHeaderEnd()
		{
			attrList.Clear();
			Write(InternalElementTypeE.ObjectEnd, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			Write(InternalElementTypeE.ObjectEnd, "SOAP-ENV:Envelope", attrList, null, isNameEscape: false, isValueEscape: false);
			writer.Flush();
		}

		internal void WriteHeaderArrayEnd()
		{
		}

		internal void WriteHeaderSectionEnd()
		{
			attrList.Clear();
			Write(InternalElementTypeE.ObjectEnd, "SOAP-ENV:Header", attrList, null, isNameEscape: false, isValueEscape: false);
		}

		internal void WriteSerializationHeader(int topId, int headerId, int minorVersion, int majorVersion)
		{
			this.topId = topId;
			this.headerId = headerId;
			switch (xsdVersion)
			{
			case XsdVersion.V1999:
				stream.Write(_soapStart1999, 0, _soapStart1999.Length);
				break;
			case XsdVersion.V2000:
				stream.Write(_soapStart1999, 0, _soapStart2000.Length);
				break;
			case XsdVersion.V2001:
				stream.Write(_soapStart, 0, _soapStart.Length);
				break;
			}
			writer.Write(">\r\n");
		}

		internal void WriteObject(NameInfo nameInfo, NameInfo typeNameInfo, int numMembers, string[] memberNames, Type[] memberTypes, WriteObjectInfo[] objectInfos)
		{
			int num = (int)nameInfo.NIobjectId;
			attrList.Clear();
			if (num == topId)
			{
				Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			}
			if (num > 0)
			{
				attrList.Put("id", IdToString((int)nameInfo.NIobjectId));
			}
			if ((nameInfo.NItransmitTypeOnObject || nameInfo.NItransmitTypeOnMember) && (nameInfo.NIisNestedObject || nameInfo.NIisArrayItem))
			{
				attrList.Put("xsi:type", TypeNameTagResolver(typeNameInfo, isXsiAppended: true));
			}
			if (nameInfo.NIisMustUnderstand)
			{
				attrList.Put("SOAP-ENV:mustUnderstand", "1");
				isUsedEnc = true;
			}
			if (nameInfo.NIisHeader)
			{
				attrList.Put("xmlns:" + nameInfo.NIheaderPrefix, nameInfo.NInamespace);
				attrList.Put("SOAP-ENC:root", "1");
			}
			if (attrValueList.Count > 0)
			{
				for (int i = 0; i < attrValueList.Count; i++)
				{
					attrValueList.Get(i, out var name, out var value);
					attrList.Put(name, value);
				}
				attrValueList.Clear();
			}
			string name2 = MemberElementName(nameInfo, typeNameInfo);
			NamespaceAttribute();
			Write(InternalElementTypeE.ObjectBegin, name2, attrList, null, isNameEscape: true, isValueEscape: false);
		}

		internal void WriteAttributeValue(NameInfo memberNameInfo, NameInfo typeNameInfo, object value)
		{
			string text = null;
			text = ((!(value is string)) ? Converter.SoapToString(value, typeNameInfo.NIprimitiveTypeEnum) : ((string)value));
			attrValueList.Put(MemberElementName(memberNameInfo, typeNameInfo), text);
		}

		internal void WriteObjectString(NameInfo nameInfo, string value)
		{
			attrList.Clear();
			if (nameInfo.NIobjectId == topId)
			{
				Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			}
			if (nameInfo.NIobjectId > 0)
			{
				attrList.Put("id", IdToString((int)nameInfo.NIobjectId));
			}
			string text = null;
			if (nameInfo.NIobjectId > 0)
			{
				text = "SOAP-ENC:string";
				isUsedEnc = true;
			}
			else
			{
				text = "xsd:string";
			}
			Write(InternalElementTypeE.Member, text, attrList, value, isNameEscape: false, Converter.IsEscaped(nameInfo.NIprimitiveTypeEnum));
		}

		internal void WriteTopPrimitive(NameInfo nameInfo, object value)
		{
			attrList.Clear();
			Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			if (nameInfo.NIobjectId > 0)
			{
				attrList.Put("id", IdToString((int)nameInfo.NIobjectId));
			}
			string text = null;
			Write(value: (!(value is string)) ? Converter.SoapToString(value, nameInfo.NIprimitiveTypeEnum) : ((string)value), use: InternalElementTypeE.Member, name: "xsd:" + Converter.ToXmlDataType(nameInfo.NIprimitiveTypeEnum), attrList: attrList, isNameEscape: true, isValueEscape: false);
		}

		internal void WriteObjectByteArray(NameInfo memberNameInfo, NameInfo arrayNameInfo, WriteObjectInfo objectInfo, NameInfo arrayElemTypeNameInfo, int length, int lowerBound, byte[] byteA)
		{
			string value = Convert.ToBase64String(byteA);
			attrList.Clear();
			if (memberNameInfo.NIobjectId == topId)
			{
				Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			}
			if (arrayNameInfo.NIobjectId > 1)
			{
				attrList.Put("id", IdToString((int)arrayNameInfo.NIobjectId));
			}
			attrList.Put("xsi:type", "SOAP-ENC:base64");
			isUsedEnc = true;
			string name = MemberElementName(memberNameInfo, null);
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, name, attrList, value, isNameEscape: true, isValueEscape: false);
		}

		internal void WriteMember(NameInfo memberNameInfo, NameInfo typeNameInfo, object value)
		{
			attrList.Clear();
			if (typeNameInfo.NItype != null && (memberNameInfo.NItransmitTypeOnMember || (memberNameInfo.NItransmitTypeOnObject && !memberNameInfo.NIisArrayItem)))
			{
				attrList.Put("xsi:type", TypeNameTagResolver(typeNameInfo, isXsiAppended: true));
			}
			string value2 = null;
			if (value != null)
			{
				if (typeNameInfo.NIprimitiveTypeEnum != InternalPrimitiveTypeE.QName)
				{
					value2 = ((!(value is string)) ? Converter.SoapToString(value, typeNameInfo.NIprimitiveTypeEnum) : ((string)value));
				}
				else
				{
					SoapQName soapQName = (SoapQName)value;
					if (soapQName.Key == null || soapQName.Key.Length == 0)
					{
						attrList.Put("xmlns", "");
					}
					else
					{
						attrList.Put("xmlns:" + soapQName.Key, soapQName.Namespace);
					}
					value2 = soapQName.ToString();
				}
			}
			NameInfo typeNameInfo2 = null;
			if (typeNameInfo.NInameSpaceEnum == InternalNameSpaceE.Interop)
			{
				typeNameInfo2 = typeNameInfo;
			}
			string name = MemberElementName(memberNameInfo, typeNameInfo2);
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, name, attrList, value2, isNameEscape: true, Converter.IsEscaped(typeNameInfo.NIprimitiveTypeEnum));
		}

		internal void WriteNullMember(NameInfo memberNameInfo, NameInfo typeNameInfo)
		{
			attrList.Clear();
			if (typeNameInfo.NItype != null && (memberNameInfo.NItransmitTypeOnMember || (memberNameInfo.NItransmitTypeOnObject && !memberNameInfo.NIisArrayItem)))
			{
				attrList.Put("xsi:type", TypeNameTagResolver(typeNameInfo, isXsiAppended: true));
			}
			attrList.Put("xsi:null", "1");
			string name = MemberElementName(memberNameInfo, null);
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, name, attrList, null, isNameEscape: true, isValueEscape: false);
		}

		internal void WriteMemberObjectRef(NameInfo memberNameInfo, NameInfo typeNameInfo, int idRef)
		{
			attrList.Clear();
			attrList.Put("href", RefToString(idRef));
			NameInfo typeNameInfo2 = null;
			if (typeNameInfo.NInameSpaceEnum == InternalNameSpaceE.Interop)
			{
				typeNameInfo2 = typeNameInfo;
			}
			string name = MemberElementName(memberNameInfo, typeNameInfo2);
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, name, attrList, null, isNameEscape: true, isValueEscape: false);
		}

		internal void WriteMemberNested(NameInfo memberNameInfo)
		{
		}

		internal void WriteMemberString(NameInfo memberNameInfo, NameInfo typeNameInfo, string value)
		{
			int num = (int)typeNameInfo.NIobjectId;
			attrList.Clear();
			if (num > 0)
			{
				attrList.Put("id", IdToString((int)typeNameInfo.NIobjectId));
			}
			if (typeNameInfo.NItype != null && (memberNameInfo.NItransmitTypeOnMember || (memberNameInfo.NItransmitTypeOnObject && !memberNameInfo.NIisArrayItem)))
			{
				if (typeNameInfo.NIobjectId > 0)
				{
					attrList.Put("xsi:type", "SOAP-ENC:string");
					isUsedEnc = true;
				}
				else
				{
					attrList.Put("xsi:type", "xsd:string");
				}
			}
			NameInfo typeNameInfo2 = null;
			if (typeNameInfo.NInameSpaceEnum == InternalNameSpaceE.Interop)
			{
				typeNameInfo2 = typeNameInfo;
			}
			string name = MemberElementName(memberNameInfo, typeNameInfo2);
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, name, attrList, value, isNameEscape: true, Converter.IsEscaped(typeNameInfo.NIprimitiveTypeEnum));
		}

		internal void WriteSingleArray(NameInfo memberNameInfo, NameInfo arrayNameInfo, WriteObjectInfo objectInfo, NameInfo arrayElemTypeNameInfo, int length, int lowerBound, Array array)
		{
			attrList.Clear();
			if (memberNameInfo.NIobjectId == topId)
			{
				Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			}
			if (arrayNameInfo.NIobjectId > 1)
			{
				attrList.Put("id", IdToString((int)arrayNameInfo.NIobjectId));
			}
			arrayElemTypeNameInfo.NIitemName = NameTagResolver(arrayElemTypeNameInfo, isXsiAppended: true);
			attrList.Put("SOAP-ENC:arrayType", NameTagResolver(arrayNameInfo, isXsiAppended: true, memberNameInfo.NIname));
			isUsedEnc = true;
			if (lowerBound != 0)
			{
				attrList.Put("SOAP-ENC:offset", "[" + lowerBound + "]");
			}
			string name = MemberElementName(memberNameInfo, null);
			NamespaceAttribute();
			Write(InternalElementTypeE.ObjectBegin, name, attrList, null, isNameEscape: false, isValueEscape: false);
		}

		internal void WriteJaggedArray(NameInfo memberNameInfo, NameInfo arrayNameInfo, WriteObjectInfo objectInfo, NameInfo arrayElemTypeNameInfo, int length, int lowerBound)
		{
			attrList.Clear();
			if (memberNameInfo.NIobjectId == topId)
			{
				Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			}
			if (arrayNameInfo.NIobjectId > 1)
			{
				attrList.Put("id", IdToString((int)arrayNameInfo.NIobjectId));
			}
			arrayElemTypeNameInfo.NIitemName = "SOAP-ENC:Array";
			isUsedEnc = true;
			attrList.Put("SOAP-ENC:arrayType", TypeArrayNameTagResolver(memberNameInfo, arrayNameInfo, isXsiAppended: true));
			if (lowerBound != 0)
			{
				attrList.Put("SOAP-ENC:offset", "[" + lowerBound + "]");
			}
			string name = MemberElementName(memberNameInfo, null);
			NamespaceAttribute();
			Write(InternalElementTypeE.ObjectBegin, name, attrList, null, isNameEscape: false, isValueEscape: false);
		}

		internal void WriteRectangleArray(NameInfo memberNameInfo, NameInfo arrayNameInfo, WriteObjectInfo objectInfo, NameInfo arrayElemTypeNameInfo, int rank, int[] lengthA, int[] lowerBoundA)
		{
			sbOffset.Length = 0;
			sbOffset.Append("[");
			bool flag = true;
			for (int i = 0; i < rank; i++)
			{
				if (lowerBoundA[i] != 0)
				{
					flag = false;
				}
				if (i > 0)
				{
					sbOffset.Append(",");
				}
				sbOffset.Append(lowerBoundA[i]);
			}
			sbOffset.Append("]");
			attrList.Clear();
			if (memberNameInfo.NIobjectId == topId)
			{
				Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Body", attrList, null, isNameEscape: false, isValueEscape: false);
			}
			if (arrayNameInfo.NIobjectId > 1)
			{
				attrList.Put("id", IdToString((int)arrayNameInfo.NIobjectId));
			}
			arrayElemTypeNameInfo.NIitemName = NameTagResolver(arrayElemTypeNameInfo, isXsiAppended: true);
			attrList.Put("SOAP-ENC:arrayType", TypeArrayNameTagResolver(memberNameInfo, arrayNameInfo, isXsiAppended: true));
			isUsedEnc = true;
			if (!flag)
			{
				attrList.Put("SOAP-ENC:offset", sbOffset.ToString());
			}
			string name = MemberElementName(memberNameInfo, null);
			NamespaceAttribute();
			Write(InternalElementTypeE.ObjectBegin, name, attrList, null, isNameEscape: false, isValueEscape: false);
		}

		internal void WriteItem(NameInfo itemNameInfo, NameInfo typeNameInfo, object value)
		{
			attrList.Clear();
			if (itemNameInfo.NItransmitTypeOnMember)
			{
				attrList.Put("xsi:type", TypeNameTagResolver(typeNameInfo, isXsiAppended: true));
			}
			string value2 = null;
			if (typeNameInfo.NIprimitiveTypeEnum == InternalPrimitiveTypeE.QName)
			{
				if (value != null)
				{
					SoapQName soapQName = (SoapQName)value;
					if (soapQName.Key == null || soapQName.Key.Length == 0)
					{
						attrList.Put("xmlns", "");
					}
					else
					{
						attrList.Put("xmlns:" + soapQName.Key, soapQName.Namespace);
					}
					value2 = soapQName.ToString();
				}
			}
			else
			{
				value2 = Converter.SoapToString(value, typeNameInfo.NIprimitiveTypeEnum);
			}
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, "item", attrList, value2, isNameEscape: false, typeNameInfo.NIprimitiveTypeEnum == InternalPrimitiveTypeE.Invalid);
		}

		internal void WriteNullItem(NameInfo memberNameInfo, NameInfo typeNameInfo)
		{
			string nIname = typeNameInfo.NIname;
			attrList.Clear();
			if (typeNameInfo.NItransmitTypeOnMember && !nIname.Equals("System.Object") && !nIname.Equals("Object") && !nIname.Equals("System.Empty") && !nIname.Equals("ur-type") && !nIname.Equals("anyType"))
			{
				attrList.Put("xsi:type", TypeNameTagResolver(typeNameInfo, isXsiAppended: true));
			}
			attrList.Put("xsi:null", "1");
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, "item", attrList, null, isNameEscape: false, isValueEscape: false);
		}

		internal void WriteItemObjectRef(NameInfo itemNameInfo, int arrayId)
		{
			attrList.Clear();
			attrList.Put("href", RefToString(arrayId));
			Write(InternalElementTypeE.Member, "item", attrList, null, isNameEscape: false, isValueEscape: false);
		}

		internal void WriteItemString(NameInfo itemNameInfo, NameInfo typeNameInfo, string value)
		{
			attrList.Clear();
			if (typeNameInfo.NIobjectId > 0)
			{
				attrList.Put("id", IdToString((int)typeNameInfo.NIobjectId));
			}
			if (itemNameInfo.NItransmitTypeOnMember)
			{
				if (typeNameInfo.NItype == SoapUtil.typeofString)
				{
					if (typeNameInfo.NIobjectId > 0)
					{
						attrList.Put("xsi:type", "SOAP-ENC:string");
						isUsedEnc = true;
					}
					else
					{
						attrList.Put("xsi:type", "xsd:string");
					}
				}
				else
				{
					attrList.Put("xsi:type", TypeNameTagResolver(typeNameInfo, isXsiAppended: true));
				}
			}
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, "item", attrList, value, isNameEscape: false, Converter.IsEscaped(typeNameInfo.NIprimitiveTypeEnum));
		}

		internal void WriteHeader(int objectId, int numMembers)
		{
			attrList.Clear();
			Write(InternalElementTypeE.ObjectBegin, "SOAP-ENV:Header", attrList, null, isNameEscape: false, isValueEscape: false);
		}

		internal void WriteHeaderEntry(NameInfo nameInfo, NameInfo typeNameInfo, object value)
		{
			attrList.Clear();
			if (value == null)
			{
				attrList.Put("xsi:null", "1");
			}
			else
			{
				attrList.Put("xsi:type", TypeNameTagResolver(typeNameInfo, isXsiAppended: true));
			}
			if (nameInfo.NIisMustUnderstand)
			{
				attrList.Put("SOAP-ENV:mustUnderstand", "1");
				isUsedEnc = true;
			}
			attrList.Put("xmlns:" + nameInfo.NIheaderPrefix, nameInfo.NInamespace);
			attrList.Put("SOAP-ENC:root", "1");
			string value2 = null;
			if (value != null)
			{
				if (typeNameInfo != null && typeNameInfo.NIprimitiveTypeEnum == InternalPrimitiveTypeE.QName)
				{
					SoapQName soapQName = (SoapQName)value;
					if (soapQName.Key == null || soapQName.Key.Length == 0)
					{
						attrList.Put("xmlns", "");
					}
					else
					{
						attrList.Put("xmlns:" + soapQName.Key, soapQName.Namespace);
					}
					value2 = soapQName.ToString();
				}
				else
				{
					value2 = Converter.SoapToString(value, typeNameInfo.NIprimitiveTypeEnum);
				}
			}
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, nameInfo.NIheaderPrefix + ":" + nameInfo.NIname, attrList, value2, isNameEscape: true, isValueEscape: true);
		}

		internal void WriteHeaderObjectRef(NameInfo nameInfo)
		{
			attrList.Clear();
			attrList.Put("href", RefToString((int)nameInfo.NIobjectId));
			if (nameInfo.NIisMustUnderstand)
			{
				attrList.Put("SOAP-ENV:mustUnderstand", "1");
				isUsedEnc = true;
			}
			attrList.Put("xmlns:" + nameInfo.NIheaderPrefix, nameInfo.NInamespace);
			attrList.Put("SOAP-ENC:root", "1");
			Write(InternalElementTypeE.Member, nameInfo.NIheaderPrefix + ":" + nameInfo.NIname, attrList, null, isNameEscape: true, isValueEscape: true);
		}

		internal void WriteHeaderString(NameInfo nameInfo, string value)
		{
			attrList.Clear();
			attrList.Put("xsi:type", "SOAP-ENC:string");
			isUsedEnc = true;
			if (nameInfo.NIisMustUnderstand)
			{
				attrList.Put("SOAP-ENV:mustUnderstand", "1");
			}
			attrList.Put("xmlns:" + nameInfo.NIheaderPrefix, nameInfo.NInamespace);
			attrList.Put("SOAP-ENC:root", "1");
			Write(InternalElementTypeE.Member, nameInfo.NIheaderPrefix + ":" + nameInfo.NIname, attrList, value, isNameEscape: true, isValueEscape: true);
		}

		internal void WriteHeaderMethodSignature(NameInfo nameInfo, NameInfo[] typeNameInfos)
		{
			attrList.Clear();
			attrList.Put("xsi:type", "SOAP-ENC:methodSignature");
			isUsedEnc = true;
			if (nameInfo.NIisMustUnderstand)
			{
				attrList.Put("SOAP-ENV:mustUnderstand", "1");
			}
			attrList.Put("xmlns:" + nameInfo.NIheaderPrefix, nameInfo.NInamespace);
			attrList.Put("SOAP-ENC:root", "1");
			StringBuilder stringBuilder = new StringBuilder();
			for (int i = 0; i < typeNameInfos.Length; i++)
			{
				if (i > 0)
				{
					stringBuilder.Append(' ');
				}
				stringBuilder.Append(NameTagResolver(typeNameInfos[i], isXsiAppended: true));
			}
			NamespaceAttribute();
			Write(InternalElementTypeE.Member, nameInfo.NIheaderPrefix + ":" + nameInfo.NIname, attrList, stringBuilder.ToString(), isNameEscape: true, isValueEscape: true);
		}

		internal void WriteAssembly(string typeFullName, Type type, string assemName, int assemId, bool isNew, bool isInteropType)
		{
			if (isNew && isInteropType)
			{
				assemblyInfos[InteropAssemIdToString(assemId)] = new AssemblyInfo(assemId, assemName, isInteropType);
			}
			if (!isInteropType)
			{
				ParseAssemblyName(typeFullName, assemName);
			}
		}

		private DottedInfo ParseAssemblyName(string typeFullName, string assemName)
		{
			string text = null;
			string text2 = null;
			string text3 = null;
			if (typeNameToDottedInfoTable.ContainsKey(typeFullName))
			{
				return (DottedInfo)typeNameToDottedInfoTable[typeFullName];
			}
			int num = typeFullName.LastIndexOf('.');
			text = ((num <= 0) ? "" : typeFullName.Substring(0, num));
			text3 = SoapServices.CodeXmlNamespaceForClrTypeNamespace(text, assemName);
			text2 = typeFullName.Substring(num + 1);
			int num2;
			if (dottedAssemToAssemIdTable.ContainsKey(text3))
			{
				num2 = (int)dottedAssemToAssemIdTable[text3];
			}
			else
			{
				num2 = dottedAssemId++;
				assemblyInfos[AssemIdToString(num2)] = new AssemblyInfo(num2, text3, isInteropType: false);
				dottedAssemToAssemIdTable[text3] = num2;
			}
			DottedInfo dottedInfo = default(DottedInfo);
			dottedInfo.dottedAssemblyName = text3;
			dottedInfo.name = text2;
			dottedInfo.nameSpace = text;
			dottedInfo.assemId = num2;
			typeNameToDottedInfoTable[typeFullName] = dottedInfo;
			return dottedInfo;
		}

		private string IdToString(int objectId)
		{
			sb1.Length = 4;
			sb1.Append(objectId);
			return sb1.ToString();
		}

		private string AssemIdToString(int assemId)
		{
			sb2.Length = 1;
			sb2.Append(assemId);
			return sb2.ToString();
		}

		private string InteropAssemIdToString(int assemId)
		{
			sb3.Length = 1;
			sb3.Append(assemId);
			return sb3.ToString();
		}

		private string RefToString(int objectId)
		{
			sb4.Length = 5;
			sb4.Append(objectId);
			return sb4.ToString();
		}

		private string MemberElementName(NameInfo memberNameInfo, NameInfo typeNameInfo)
		{
			string result = memberNameInfo.NIname;
			if (memberNameInfo.NIisHeader)
			{
				result = memberNameInfo.NIheaderPrefix + ":" + memberNameInfo.NIname;
			}
			else if (typeNameInfo != null && typeNameInfo.NItype == SoapUtil.typeofSoapFault)
			{
				result = "SOAP-ENV:Fault";
			}
			else if (memberNameInfo.NIisArray && !memberNameInfo.NIisNestedObject)
			{
				result = "SOAP-ENC:Array";
				isUsedEnc = true;
			}
			else if (memberNameInfo.NIisArrayItem)
			{
				result = "item";
			}
			else if (!memberNameInfo.NIisNestedObject && (!memberNameInfo.NIisRemoteRecord || memberNameInfo.NIisTopLevelObject) && typeNameInfo != null)
			{
				result = NameTagResolver(typeNameInfo, isXsiAppended: true);
			}
			return result;
		}

		private string TypeNameTagResolver(NameInfo typeNameInfo, bool isXsiAppended)
		{
			string text = null;
			if (typeNameInfo.NIassemId > 0 && typeNameInfo.NIattributeInfo != null && typeNameInfo.NIattributeInfo.AttributeTypeName != null)
			{
				string text2 = InteropAssemIdToString((int)typeNameInfo.NIassemId);
				text = text2 + ":" + typeNameInfo.NIattributeInfo.AttributeTypeName;
				AssemblyInfo assemblyInfo = (AssemblyInfo)assemblyInfos[text2];
				assemblyInfo.isUsed = true;
				assemblyInfo.prefix = text2;
				assemblyInfoUsed[assemblyInfo] = 1;
			}
			else
			{
				text = NameTagResolver(typeNameInfo, isXsiAppended);
			}
			return text;
		}

		private string NameTagResolver(NameInfo typeNameInfo, bool isXsiAppended)
		{
			return NameTagResolver(typeNameInfo, isXsiAppended, null);
		}

		private string NameTagResolver(NameInfo typeNameInfo, bool isXsiAppended, string arrayItemName)
		{
			string text = typeNameInfo.NIname;
			switch (typeNameInfo.NInameSpaceEnum)
			{
			case InternalNameSpaceE.Soap:
				text = "SOAP-ENC:" + typeNameInfo.NIname;
				isUsedEnc = true;
				break;
			case InternalNameSpaceE.XdrPrimitive:
				if (isXsiAppended)
				{
					text = "xsd:" + typeNameInfo.NIname;
				}
				break;
			case InternalNameSpaceE.XdrString:
				if (isXsiAppended)
				{
					text = "xsd:" + typeNameInfo.NIname;
				}
				break;
			case InternalNameSpaceE.UrtSystem:
				if (typeNameInfo.NItype == SoapUtil.typeofObject)
				{
					text = "xsd:anyType";
				}
				else if (arrayItemName == null)
				{
					DottedInfo dottedInfo = ((!typeNameToDottedInfoTable.ContainsKey(typeNameInfo.NIname)) ? ParseAssemblyName(typeNameInfo.NIname, null) : ((DottedInfo)typeNameToDottedInfoTable[typeNameInfo.NIname]));
					string text4 = AssemIdToString(dottedInfo.assemId);
					text = text4 + ":" + dottedInfo.name;
					AssemblyInfo assemblyInfo3 = (AssemblyInfo)assemblyInfos[text4];
					assemblyInfo3.isUsed = true;
					assemblyInfo3.prefix = text4;
					assemblyInfoUsed[assemblyInfo3] = 1;
				}
				else
				{
					DottedInfo dottedInfo2 = ((!typeNameToDottedInfoTable.ContainsKey(arrayItemName)) ? ParseAssemblyName(arrayItemName, null) : ((DottedInfo)typeNameToDottedInfoTable[arrayItemName]));
					string text5 = AssemIdToString(dottedInfo2.assemId);
					text = text5 + ":" + DottedDimensionName(dottedInfo2.name, typeNameInfo.NIname);
					AssemblyInfo assemblyInfo4 = (AssemblyInfo)assemblyInfos[text5];
					assemblyInfo4.isUsed = true;
					assemblyInfo4.prefix = text5;
					assemblyInfoUsed[assemblyInfo4] = 1;
				}
				break;
			case InternalNameSpaceE.UrtUser:
				if (typeNameInfo.NIassemId <= 0)
				{
					break;
				}
				if (arrayItemName == null)
				{
					if (!typeNameToDottedInfoTable.ContainsKey(typeNameInfo.NIname))
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Assembly"), typeNameInfo.NIname));
					}
					DottedInfo dottedInfo3 = (DottedInfo)typeNameToDottedInfoTable[typeNameInfo.NIname];
					string text6 = AssemIdToString(dottedInfo3.assemId);
					text = text6 + ":" + dottedInfo3.name;
					AssemblyInfo assemblyInfo5 = (AssemblyInfo)assemblyInfos[text6];
					assemblyInfo5.isUsed = true;
					assemblyInfo5.prefix = text6;
					assemblyInfoUsed[assemblyInfo5] = 1;
				}
				else
				{
					if (!typeNameToDottedInfoTable.ContainsKey(arrayItemName))
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Assembly"), typeNameInfo.NIname));
					}
					DottedInfo dottedInfo4 = (DottedInfo)typeNameToDottedInfoTable[arrayItemName];
					string text7 = AssemIdToString(dottedInfo4.assemId);
					text = text7 + ":" + DottedDimensionName(dottedInfo4.name, typeNameInfo.NIname);
					AssemblyInfo assemblyInfo6 = (AssemblyInfo)assemblyInfos[text7];
					assemblyInfo6.isUsed = true;
					assemblyInfo6.prefix = text7;
					assemblyInfoUsed[assemblyInfo6] = 1;
				}
				break;
			case InternalNameSpaceE.CallElement:
				if (typeNameInfo.NIassemId > 0)
				{
					string text3 = InteropAssemIdToString((int)typeNameInfo.NIassemId);
					AssemblyInfo assemblyInfo2 = (AssemblyInfo)assemblyInfos[text3];
					if (assemblyInfo2 == null)
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_NameSpaceEnum"), typeNameInfo.NInameSpaceEnum));
					}
					text = text3 + ":" + typeNameInfo.NIname;
					assemblyInfo2.isUsed = true;
					assemblyInfo2.prefix = text3;
					assemblyInfoUsed[assemblyInfo2] = 1;
				}
				break;
			case InternalNameSpaceE.Interop:
				if (typeNameInfo.NIattributeInfo == null || typeNameInfo.NIattributeInfo.AttributeElementName == null)
				{
					break;
				}
				if (typeNameInfo.NIassemId > 0)
				{
					string text2 = InteropAssemIdToString((int)typeNameInfo.NIassemId);
					text = text2 + ":" + typeNameInfo.NIattributeInfo.AttributeElementName;
					if (arrayItemName != null)
					{
						int startIndex = typeNameInfo.NIname.IndexOf("[");
						text += typeNameInfo.NIname.Substring(startIndex);
					}
					AssemblyInfo assemblyInfo = (AssemblyInfo)assemblyInfos[text2];
					assemblyInfo.isUsed = true;
					assemblyInfo.prefix = text2;
					assemblyInfoUsed[assemblyInfo] = 1;
				}
				else
				{
					text = typeNameInfo.NIattributeInfo.AttributeElementName;
				}
				break;
			default:
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_NameSpaceEnum"), typeNameInfo.NInameSpaceEnum));
			case InternalNameSpaceE.None:
			case InternalNameSpaceE.UserNameSpace:
			case InternalNameSpaceE.MemberName:
				break;
			}
			return text;
		}

		private string TypeArrayNameTagResolver(NameInfo memberNameInfo, NameInfo typeNameInfo, bool isXsiAppended)
		{
			string text = null;
			if (typeNameInfo.NIassemId > 0 && typeNameInfo.NIattributeInfo != null && typeNameInfo.NIattributeInfo.AttributeTypeName != null)
			{
				return InteropAssemIdToString((int)typeNameInfo.NIassemId) + ":" + typeNameInfo.NIattributeInfo.AttributeTypeName;
			}
			return NameTagResolver(typeNameInfo, isXsiAppended, memberNameInfo.NIname);
		}

		private void NamespaceAttribute()
		{
			IDictionaryEnumerator enumerator = assemblyInfoUsed.GetEnumerator();
			while (enumerator.MoveNext())
			{
				AssemblyInfo assemblyInfo = (AssemblyInfo)enumerator.Key;
				attrList.Put("xmlns:" + assemblyInfo.prefix, assemblyInfo.name);
			}
			assemblyInfoUsed.Clear();
		}

		private string DottedDimensionName(string dottedName, string dimensionName)
		{
			string text = null;
			int length = dottedName.IndexOf('[');
			int startIndex = dimensionName.IndexOf('[');
			return dottedName.Substring(0, length) + dimensionName.Substring(startIndex);
		}
	}
	internal sealed class ObjectReader
	{
		internal class TypeNAssembly
		{
			public Type type;

			public string assemblyName;
		}

		internal ObjectIDGenerator m_idGenerator;

		internal Stream m_stream;

		internal ISurrogateSelector m_surrogates;

		internal StreamingContext m_context;

		internal ObjectManager m_objectManager;

		internal InternalFE formatterEnums;

		internal SerializationBinder m_binder;

		internal SoapHandler soapHandler;

		internal long topId;

		internal SerStack topStack;

		internal bool isTopObjectSecondPass;

		internal bool isTopObjectResolved = true;

		internal bool isHeaderHandlerCalled;

		internal Exception deserializationSecurityException;

		internal object handlerObject;

		internal object topObject;

		internal long soapFaultId;

		internal Header[] headers;

		internal Header[] newheaders;

		internal bool IsFakeTopObject;

		internal HeaderHandler handler;

		internal SerObjectInfoInit serObjectInfoInit;

		internal IFormatterConverter m_formatterConverter;

		internal SerStack stack = new SerStack("ObjectReader Object Stack");

		internal SerStack valueFixupStack = new SerStack("ValueType Fixup Stack");

		internal Hashtable objectIdTable = new Hashtable(25);

		internal long objectIds;

		internal int paramPosition;

		internal int majorVersion;

		internal int minorVersion;

		internal string faultString;

		internal static SecurityPermission serializationPermission = new SecurityPermission(SecurityPermissionFlag.SerializationFormatter);

		private static FileIOPermission sfileIOPermission = new FileIOPermission(PermissionState.Unrestricted);

		private string inKeyId;

		private long outKeyId;

		private NameCache typeCache = new NameCache();

		private StringBuilder sbf = new StringBuilder();

		private bool IsRemoting => IsFakeTopObject;

		internal ObjectReader(Stream stream, ISurrogateSelector selector, StreamingContext context, InternalFE formatterEnums, SerializationBinder binder)
		{
			if (stream == null)
			{
				throw new ArgumentNullException("stream", SoapUtil.GetResourceString("ArgumentNull_Stream"));
			}
			m_stream = stream;
			m_surrogates = selector;
			m_context = context;
			m_binder = binder;
			this.formatterEnums = formatterEnums;
			if (formatterEnums.FEtopObject != null)
			{
				IsFakeTopObject = true;
			}
			else
			{
				IsFakeTopObject = false;
			}
			m_formatterConverter = new FormatterConverter();
		}

		private ObjectManager GetObjectManager()
		{
			new SecurityPermission(SecurityPermissionFlag.SerializationFormatter).Assert();
			return new ObjectManager(m_surrogates, m_context);
		}

		internal object Deserialize(HeaderHandler handler, ISerParser serParser)
		{
			if (serParser == null)
			{
				throw new ArgumentNullException("serParser", string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("ArgumentNull_WithParamName"), serParser));
			}
			deserializationSecurityException = null;
			try
			{
				serializationPermission.Demand();
			}
			catch (Exception ex)
			{
				Exception ex2 = (deserializationSecurityException = ex);
			}
			catch
			{
				deserializationSecurityException = new Exception(SoapUtil.GetResourceString("Serialization_NonClsCompliantException"));
			}
			this.handler = handler;
			isTopObjectSecondPass = false;
			isHeaderHandlerCalled = false;
			if (handler != null)
			{
				IsFakeTopObject = true;
			}
			m_idGenerator = new ObjectIDGenerator();
			m_objectManager = GetObjectManager();
			serObjectInfoInit = new SerObjectInfoInit();
			objectIdTable.Clear();
			objectIds = 0L;
			serParser.Run();
			if (handler != null)
			{
				m_objectManager.DoFixups();
				if (handlerObject == null)
				{
					handlerObject = handler(newheaders);
				}
				if (soapFaultId > 0 && handlerObject != null)
				{
					topStack = new SerStack("Top ParseRecords");
					ParseRecord parseRecord = new ParseRecord();
					parseRecord.PRparseTypeEnum = InternalParseTypeE.Object;
					parseRecord.PRobjectPositionEnum = InternalObjectPositionE.Top;
					parseRecord.PRparseStateEnum = InternalParseStateE.Object;
					parseRecord.PRname = "Response";
					topStack.Push(parseRecord);
					parseRecord = new ParseRecord();
					parseRecord.PRparseTypeEnum = InternalParseTypeE.Member;
					parseRecord.PRobjectPositionEnum = InternalObjectPositionE.Child;
					parseRecord.PRmemberTypeEnum = InternalMemberTypeE.Field;
					parseRecord.PRmemberValueEnum = InternalMemberValueE.Reference;
					parseRecord.PRparseStateEnum = InternalParseStateE.Member;
					parseRecord.PRname = "__fault";
					parseRecord.PRidRef = soapFaultId;
					topStack.Push(parseRecord);
					parseRecord = new ParseRecord();
					parseRecord.PRparseTypeEnum = InternalParseTypeE.ObjectEnd;
					parseRecord.PRobjectPositionEnum = InternalObjectPositionE.Top;
					parseRecord.PRparseStateEnum = InternalParseStateE.Object;
					parseRecord.PRname = "Response";
					topStack.Push(parseRecord);
					isTopObjectResolved = false;
				}
			}
			if (!isTopObjectResolved)
			{
				isTopObjectSecondPass = true;
				topStack.Reverse();
				int num = topStack.Count();
				ParseRecord parseRecord2 = null;
				for (int i = 0; i < num; i++)
				{
					parseRecord2 = (ParseRecord)topStack.Pop();
					Parse(parseRecord2);
				}
			}
			m_objectManager.DoFixups();
			if (topObject == null)
			{
				throw new SerializationException(SoapUtil.GetResourceString("Serialization_TopObject"));
			}
			if (HasSurrogate(topObject.GetType()) && topId != 0)
			{
				topObject = m_objectManager.GetObject(topId);
			}
			if (topObject is IObjectReference)
			{
				topObject = ((IObjectReference)topObject).GetRealObject(m_context);
			}
			m_objectManager.RaiseDeserializationEvent();
			if (formatterEnums.FEtopObject != null && topObject is InternalSoapMessage)
			{
				InternalSoapMessage internalSoapMessage = (InternalSoapMessage)topObject;
				ISoapMessage fEtopObject = formatterEnums.FEtopObject;
				fEtopObject.MethodName = internalSoapMessage.methodName;
				fEtopObject.XmlNameSpace = internalSoapMessage.xmlNameSpace;
				fEtopObject.ParamNames = internalSoapMessage.paramNames;
				fEtopObject.ParamValues = internalSoapMessage.paramValues;
				fEtopObject.Headers = headers;
				topObject = fEtopObject;
				isTopObjectResolved = true;
			}
			return topObject;
		}

		private bool HasSurrogate(Type t)
		{
			if (m_surrogates == null)
			{
				return false;
			}
			ISurrogateSelector selector;
			return m_surrogates.GetSurrogate(t, m_context, out selector) != null;
		}

		private void CheckSerializable(Type t)
		{
			if (!t.IsSerializable && !HasSurrogate(t))
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_NonSerType"), t.FullName, t.Module.Assembly.FullName));
			}
		}

		internal ReadObjectInfo CreateReadObjectInfo(Type objectType, string assemblyName)
		{
			ReadObjectInfo readObjectInfo = ReadObjectInfo.Create(objectType, m_surrogates, m_context, m_objectManager, serObjectInfoInit, m_formatterConverter, assemblyName);
			readObjectInfo.SetVersion(majorVersion, minorVersion);
			return readObjectInfo;
		}

		internal ReadObjectInfo CreateReadObjectInfo(Type objectType, string[] memberNames, Type[] memberTypes, string assemblyName)
		{
			ReadObjectInfo readObjectInfo = ReadObjectInfo.Create(objectType, memberNames, memberTypes, m_surrogates, m_context, m_objectManager, serObjectInfoInit, m_formatterConverter, assemblyName);
			readObjectInfo.SetVersion(majorVersion, minorVersion);
			return readObjectInfo;
		}

		internal void Parse(ParseRecord pr)
		{
			switch (pr.PRparseTypeEnum)
			{
			case InternalParseTypeE.SerializedStreamHeader:
				ParseSerializedStreamHeader(pr);
				break;
			case InternalParseTypeE.SerializedStreamHeaderEnd:
				ParseSerializedStreamHeaderEnd(pr);
				break;
			case InternalParseTypeE.Object:
				ParseObject(pr);
				break;
			case InternalParseTypeE.ObjectEnd:
				ParseObjectEnd(pr);
				break;
			case InternalParseTypeE.Member:
				ParseMember(pr);
				break;
			case InternalParseTypeE.MemberEnd:
				ParseMemberEnd(pr);
				break;
			default:
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_XMLElement"), pr.PRname));
			case InternalParseTypeE.Envelope:
			case InternalParseTypeE.EnvelopeEnd:
			case InternalParseTypeE.Body:
			case InternalParseTypeE.BodyEnd:
				break;
			}
		}

		private void ParseError(ParseRecord processing, ParseRecord onStack)
		{
			throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ParseError"), onStack.PRname + " " + onStack.PRparseTypeEnum.ToString() + " " + processing.PRname + " " + processing.PRparseTypeEnum));
		}

		private void ParseSerializedStreamHeader(ParseRecord pr)
		{
			stack.Push(pr);
		}

		private void ParseSerializedStreamHeaderEnd(ParseRecord pr)
		{
			stack.Pop();
		}

		private void CheckSecurity(ParseRecord pr)
		{
			Type pRdtType = pr.PRdtType;
			if (pRdtType != null && IsRemoting)
			{
				if (typeof(MarshalByRefObject).IsAssignableFrom(pRdtType))
				{
					throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_MBRAsMBV"), pRdtType.FullName));
				}
				FormatterServices.CheckTypeSecurity(pRdtType, formatterEnums.FEsecurityLevel);
			}
			if (deserializationSecurityException == null)
			{
				return;
			}
			if (pRdtType != null)
			{
				if (pRdtType.IsPrimitive || pRdtType == Converter.typeofString || typeof(Enum).IsAssignableFrom(pRdtType))
				{
					return;
				}
				if (pRdtType.IsArray)
				{
					Type elementType = pRdtType.GetElementType();
					if (elementType.IsPrimitive || elementType == Converter.typeofString)
					{
						return;
					}
				}
			}
			throw deserializationSecurityException;
		}

		private void ParseObject(ParseRecord pr)
		{
			if (pr.PRobjectPositionEnum == InternalObjectPositionE.Top)
			{
				topId = pr.PRobjectId;
			}
			if (pr.PRparseTypeEnum == InternalParseTypeE.Object)
			{
				stack.Push(pr);
			}
			if (pr.PRobjectTypeEnum == InternalObjectTypeE.Array)
			{
				ParseArray(pr);
				return;
			}
			if (pr.PRdtType == null && !IsFakeTopObject)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TopObjectInstantiate"), pr.PRname));
			}
			if (pr.PRobjectPositionEnum == InternalObjectPositionE.Top && IsFakeTopObject && pr.PRdtType != Converter.typeofSoapFault)
			{
				if (handler != null)
				{
					if (!isHeaderHandlerCalled)
					{
						newheaders = null;
						isHeaderHandlerCalled = true;
						if (headers == null)
						{
							newheaders = new Header[1];
						}
						else
						{
							newheaders = new Header[headers.Length + 1];
							Array.Copy(headers, 0, newheaders, 1, headers.Length);
						}
						Header header = new Header("__methodName", pr.PRname, _MustUnderstand: false, pr.PRnameXmlKey);
						newheaders[0] = header;
						handlerObject = handler(newheaders);
					}
					if (!isHeaderHandlerCalled)
					{
						isTopObjectResolved = false;
						topStack = new SerStack("Top ParseRecords");
						topStack.Push(pr.Copy());
						return;
					}
					pr.PRnewObj = handlerObject;
					pr.PRdtType = handlerObject.GetType();
					CheckSecurity(pr);
					if (pr.PRnewObj is IFieldInfo)
					{
						IFieldInfo fieldInfo = (IFieldInfo)pr.PRnewObj;
						if (fieldInfo.FieldTypes != null && fieldInfo.FieldTypes.Length > 0)
						{
							pr.PRobjectInfo = CreateReadObjectInfo(pr.PRdtType, fieldInfo.FieldNames, fieldInfo.FieldTypes, pr.PRassemblyName);
						}
					}
				}
				else if (formatterEnums.FEtopObject != null)
				{
					if (!isTopObjectSecondPass)
					{
						isTopObjectResolved = false;
						topStack = new SerStack("Top ParseRecords");
						topStack.Push(pr.Copy());
						return;
					}
					pr.PRnewObj = new InternalSoapMessage();
					pr.PRdtType = typeof(InternalSoapMessage);
					CheckSecurity(pr);
					if (formatterEnums.FEtopObject != null)
					{
						ISoapMessage fEtopObject = formatterEnums.FEtopObject;
						pr.PRobjectInfo = CreateReadObjectInfo(pr.PRdtType, fEtopObject.ParamNames, fEtopObject.ParamTypes, pr.PRassemblyName);
					}
				}
			}
			else
			{
				if (pr.PRdtType == Converter.typeofString)
				{
					if (pr.PRvalue != null)
					{
						pr.PRnewObj = pr.PRvalue;
						if (pr.PRobjectPositionEnum == InternalObjectPositionE.Top)
						{
							isTopObjectResolved = true;
							topObject = pr.PRnewObj;
						}
						else
						{
							stack.Pop();
							RegisterObject(pr.PRnewObj, pr, (ParseRecord)stack.Peek());
						}
					}
					return;
				}
				if (pr.PRdtType == null)
				{
					ParseRecord parseRecord = (ParseRecord)stack.Peek();
					if (parseRecord.PRdtType == Converter.typeofSoapFault)
					{
						throw new ServerException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_SoapFault"), faultString));
					}
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TypeElement"), pr.PRname));
				}
				CheckSerializable(pr.PRdtType);
				if (IsRemoting && formatterEnums.FEsecurityLevel != TypeFilterLevel.Full)
				{
					pr.PRnewObj = FormatterServices.GetSafeUninitializedObject(pr.PRdtType);
				}
				else
				{
					pr.PRnewObj = FormatterServices.GetUninitializedObject(pr.PRdtType);
				}
				CheckSecurity(pr);
				m_objectManager.RaiseOnDeserializingEvent(pr.PRnewObj);
			}
			if (pr.PRnewObj == null)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TopObjectInstantiate"), pr.PRdtType));
			}
			long pRobjectId = pr.PRobjectId;
			if (pRobjectId < 1)
			{
				pr.PRobjectId = GetId("GenId-" + objectIds);
			}
			if (IsFakeTopObject && pr.PRobjectPositionEnum == InternalObjectPositionE.Top)
			{
				isTopObjectResolved = true;
				topObject = pr.PRnewObj;
			}
			if (pr.PRobjectInfo == null)
			{
				pr.PRobjectInfo = CreateReadObjectInfo(pr.PRdtType, pr.PRassemblyName);
			}
			pr.PRobjectInfo.obj = pr.PRnewObj;
			if (IsFakeTopObject && pr.PRobjectPositionEnum == InternalObjectPositionE.Top)
			{
				pr.PRobjectInfo.AddValue("__methodName", pr.PRname);
				pr.PRobjectInfo.AddValue("__keyToNamespaceTable", soapHandler.keyToNamespaceTable);
				pr.PRobjectInfo.AddValue("__paramNameList", pr.PRobjectInfo.SetFakeObject());
				if (formatterEnums.FEtopObject != null)
				{
					pr.PRobjectInfo.AddValue("__xmlNameSpace", pr.PRxmlNameSpace);
				}
			}
		}

		private bool IsWhiteSpace(string value)
		{
			for (int i = 0; i < value.Length; i++)
			{
				if (value[i] != ' ' && value[i] != '\n' && value[i] != '\r')
				{
					return false;
				}
			}
			return true;
		}

		private void ParseObjectEnd(ParseRecord pr)
		{
			ParseRecord parseRecord = (ParseRecord)stack.Peek();
			if (parseRecord == null)
			{
				parseRecord = pr;
			}
			if (parseRecord.PRobjectPositionEnum == InternalObjectPositionE.Top)
			{
				if (parseRecord.PRdtType == Converter.typeofString)
				{
					if (parseRecord.PRvalue == null)
					{
						parseRecord.PRvalue = string.Empty;
					}
					parseRecord.PRnewObj = parseRecord.PRvalue;
					CheckSecurity(parseRecord);
					isTopObjectResolved = true;
					topObject = parseRecord.PRnewObj;
					return;
				}
				if (parseRecord.PRdtType != null && parseRecord.PRvalue != null && !IsWhiteSpace(parseRecord.PRvalue) && (parseRecord.PRdtType.IsPrimitive || parseRecord.PRdtType == Converter.typeofTimeSpan))
				{
					parseRecord.PRnewObj = Converter.FromString(parseRecord.PRvalue, Converter.ToCode(parseRecord.PRdtType));
					CheckSecurity(parseRecord);
					isTopObjectResolved = true;
					topObject = parseRecord.PRnewObj;
					return;
				}
				if (!isTopObjectResolved && parseRecord.PRdtType != Converter.typeofSoapFault)
				{
					topStack.Push(pr.Copy());
					if (parseRecord.PRparseRecordId == pr.PRparseRecordId)
					{
						stack.Pop();
					}
					return;
				}
			}
			stack.Pop();
			ParseRecord parseRecord2 = (ParseRecord)stack.Peek();
			if (parseRecord.PRobjectTypeEnum == InternalObjectTypeE.Array)
			{
				if (parseRecord.PRobjectPositionEnum == InternalObjectPositionE.Top)
				{
					isTopObjectResolved = true;
					topObject = parseRecord.PRnewObj;
				}
				RegisterObject(parseRecord.PRnewObj, parseRecord, parseRecord2);
				return;
			}
			if (parseRecord.PRobjectInfo != null)
			{
				parseRecord.PRobjectInfo.PopulateObjectMembers();
			}
			if (parseRecord.PRnewObj == null)
			{
				if (parseRecord.PRdtType != Converter.typeofString)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ObjectMissing"), pr.PRname));
				}
				if (parseRecord.PRvalue == null)
				{
					parseRecord.PRvalue = string.Empty;
				}
				parseRecord.PRnewObj = parseRecord.PRvalue;
				CheckSecurity(parseRecord);
			}
			if (!parseRecord.PRisRegistered && parseRecord.PRobjectId > 0)
			{
				RegisterObject(parseRecord.PRnewObj, parseRecord, parseRecord2);
			}
			if (parseRecord.PRisValueTypeFixup)
			{
				ValueFixup valueFixup = (ValueFixup)valueFixupStack.Pop();
				valueFixup.Fixup(parseRecord, parseRecord2);
			}
			if (parseRecord.PRobjectPositionEnum == InternalObjectPositionE.Top)
			{
				isTopObjectResolved = true;
				topObject = parseRecord.PRnewObj;
			}
			if (parseRecord.PRnewObj is SoapFault)
			{
				soapFaultId = parseRecord.PRobjectId;
			}
			if (parseRecord.PRobjectInfo != null)
			{
				if (parseRecord.PRobjectInfo.bfake && !parseRecord.PRobjectInfo.bSoapFault)
				{
					parseRecord.PRobjectInfo.AddValue("__fault", null);
				}
				parseRecord.PRobjectInfo.ObjectEnd();
			}
		}

		private void ParseArray(ParseRecord pr)
		{
			long pRobjectId = pr.PRobjectId;
			if (pRobjectId < 1)
			{
				pr.PRobjectId = GetId("GenId-" + objectIds);
			}
			if (pr.PRarrayElementType != null && pr.PRarrayElementType.IsEnum)
			{
				pr.PRisEnum = true;
			}
			if (pr.PRarrayTypeEnum == InternalArrayTypeE.Base64)
			{
				if (pr.PRvalue == null)
				{
					pr.PRnewObj = new byte[0];
					CheckSecurity(pr);
				}
				else if (pr.PRdtType == Converter.typeofSoapBase64Binary)
				{
					pr.PRnewObj = SoapBase64Binary.Parse(pr.PRvalue);
					CheckSecurity(pr);
				}
				else if (pr.PRvalue.Length > 0)
				{
					pr.PRnewObj = Convert.FromBase64String(FilterBin64(pr.PRvalue));
					CheckSecurity(pr);
				}
				else
				{
					pr.PRnewObj = new byte[0];
					CheckSecurity(pr);
				}
				if (stack.Peek() == pr)
				{
					stack.Pop();
				}
				if (pr.PRobjectPositionEnum == InternalObjectPositionE.Top)
				{
					topObject = pr.PRnewObj;
					isTopObjectResolved = true;
				}
				ParseRecord objectPr = (ParseRecord)stack.Peek();
				RegisterObject(pr.PRnewObj, pr, objectPr);
				return;
			}
			if (pr.PRnewObj != null && Converter.IsWriteAsByteArray(pr.PRarrayElementTypeCode))
			{
				if (pr.PRobjectPositionEnum == InternalObjectPositionE.Top)
				{
					topObject = pr.PRnewObj;
					isTopObjectResolved = true;
				}
				ParseRecord objectPr2 = (ParseRecord)stack.Peek();
				RegisterObject(pr.PRnewObj, pr, objectPr2);
				return;
			}
			if (pr.PRarrayTypeEnum == InternalArrayTypeE.Jagged || pr.PRarrayTypeEnum == InternalArrayTypeE.Single)
			{
				if (pr.PRlowerBoundA == null || pr.PRlowerBoundA[0] == 0)
				{
					pr.PRnewObj = Array.CreateInstance(pr.PRarrayElementType, (pr.PRrank > 0) ? pr.PRlengthA[0] : 0);
					pr.PRisLowerBound = false;
				}
				else
				{
					pr.PRnewObj = Array.CreateInstance(pr.PRarrayElementType, pr.PRlengthA, pr.PRlowerBoundA);
					pr.PRisLowerBound = true;
				}
				if (pr.PRarrayTypeEnum == InternalArrayTypeE.Single)
				{
					if (!pr.PRisLowerBound && Converter.IsWriteAsByteArray(pr.PRarrayElementTypeCode))
					{
						pr.PRprimitiveArray = new PrimitiveArray(pr.PRarrayElementTypeCode, (Array)pr.PRnewObj);
					}
					else if (!pr.PRarrayElementType.IsValueType && pr.PRlowerBoundA == null)
					{
						pr.PRobjectA = (object[])pr.PRnewObj;
					}
				}
				CheckSecurity(pr);
				if (pr.PRobjectPositionEnum == InternalObjectPositionE.Headers)
				{
					headers = (Header[])pr.PRnewObj;
				}
				pr.PRindexMap = new int[1];
				return;
			}
			if (pr.PRarrayTypeEnum == InternalArrayTypeE.Rectangular)
			{
				pr.PRisLowerBound = false;
				if (pr.PRlowerBoundA != null)
				{
					for (int i = 0; i < pr.PRrank; i++)
					{
						if (pr.PRlowerBoundA[i] != 0)
						{
							pr.PRisLowerBound = true;
						}
					}
				}
				if (!pr.PRisLowerBound)
				{
					pr.PRnewObj = Array.CreateInstance(pr.PRarrayElementType, pr.PRlengthA);
				}
				else
				{
					pr.PRnewObj = Array.CreateInstance(pr.PRarrayElementType, pr.PRlengthA, pr.PRlowerBoundA);
				}
				CheckSecurity(pr);
				int num = 1;
				for (int j = 0; j < pr.PRrank; j++)
				{
					num *= pr.PRlengthA[j];
				}
				pr.PRindexMap = new int[pr.PRrank];
				pr.PRrectangularMap = new int[pr.PRrank];
				pr.PRlinearlength = num;
				return;
			}
			throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ArrayType"), pr.PRarrayTypeEnum.ToString()));
		}

		private void NextRectangleMap(ParseRecord pr)
		{
			for (int num = pr.PRrank - 1; num > -1; num--)
			{
				if (pr.PRrectangularMap[num] < pr.PRlengthA[num] - 1)
				{
					pr.PRrectangularMap[num]++;
					if (num < pr.PRrank - 1)
					{
						for (int i = num + 1; i < pr.PRrank; i++)
						{
							pr.PRrectangularMap[i] = 0;
						}
					}
					Array.Copy(pr.PRrectangularMap, pr.PRindexMap, pr.PRrank);
					break;
				}
			}
		}

		private void ParseArrayMember(ParseRecord pr)
		{
			ParseRecord parseRecord = (ParseRecord)stack.Peek();
			if (parseRecord.PRarrayTypeEnum == InternalArrayTypeE.Rectangular)
			{
				if (pr.PRpositionA != null)
				{
					Array.Copy(pr.PRpositionA, parseRecord.PRindexMap, parseRecord.PRindexMap.Length);
					if (parseRecord.PRlowerBoundA == null)
					{
						Array.Copy(pr.PRpositionA, parseRecord.PRrectangularMap, parseRecord.PRrectangularMap.Length);
					}
					else
					{
						for (int i = 0; i < parseRecord.PRrectangularMap.Length; i++)
						{
							parseRecord.PRrectangularMap[i] = pr.PRpositionA[i] - parseRecord.PRlowerBoundA[i];
						}
					}
				}
				else
				{
					if (parseRecord.PRmemberIndex > 0)
					{
						NextRectangleMap(parseRecord);
					}
					for (int j = 0; j < parseRecord.PRrank; j++)
					{
						int num = 0;
						if (parseRecord.PRlowerBoundA != null)
						{
							num = parseRecord.PRlowerBoundA[j];
						}
						parseRecord.PRindexMap[j] = parseRecord.PRrectangularMap[j] + num;
					}
				}
			}
			else if (!parseRecord.PRisLowerBound)
			{
				if (pr.PRpositionA == null)
				{
					parseRecord.PRindexMap[0] = parseRecord.PRmemberIndex;
				}
				else
				{
					parseRecord.PRindexMap[0] = (parseRecord.PRmemberIndex = pr.PRpositionA[0]);
				}
			}
			else if (pr.PRpositionA == null)
			{
				parseRecord.PRindexMap[0] = parseRecord.PRmemberIndex + parseRecord.PRlowerBoundA[0];
			}
			else
			{
				parseRecord.PRindexMap[0] = pr.PRpositionA[0];
				parseRecord.PRmemberIndex = pr.PRpositionA[0] - parseRecord.PRlowerBoundA[0];
			}
			if (pr.PRmemberValueEnum == InternalMemberValueE.Reference)
			{
				object @object = m_objectManager.GetObject(pr.PRidRef);
				if (@object == null)
				{
					int[] array = new int[parseRecord.PRrank];
					Array.Copy(parseRecord.PRindexMap, 0, array, 0, parseRecord.PRrank);
					m_objectManager.RecordArrayElementFixup(parseRecord.PRobjectId, array, pr.PRidRef);
				}
				else if (parseRecord.PRobjectA != null)
				{
					parseRecord.PRobjectA[parseRecord.PRindexMap[0]] = @object;
				}
				else
				{
					((Array)parseRecord.PRnewObj).SetValue(@object, parseRecord.PRindexMap);
				}
			}
			else if (pr.PRmemberValueEnum == InternalMemberValueE.Nested)
			{
				if (pr.PRdtType == null)
				{
					pr.PRdtType = parseRecord.PRarrayElementType;
				}
				ParseObject(pr);
				stack.Push(pr);
				if (parseRecord.PRarrayElementType.IsValueType && pr.PRarrayElementTypeCode == InternalPrimitiveTypeE.Invalid)
				{
					pr.PRisValueTypeFixup = true;
					valueFixupStack.Push(new ValueFixup((Array)parseRecord.PRnewObj, parseRecord.PRindexMap));
				}
				else if (parseRecord.PRobjectA != null)
				{
					parseRecord.PRobjectA[parseRecord.PRindexMap[0]] = pr.PRnewObj;
				}
				else
				{
					((Array)parseRecord.PRnewObj).SetValue(pr.PRnewObj, parseRecord.PRindexMap);
				}
			}
			else if (pr.PRmemberValueEnum == InternalMemberValueE.InlineValue)
			{
				if (parseRecord.PRarrayElementType == Converter.typeofString)
				{
					ParseString(pr, parseRecord);
					if (parseRecord.PRobjectA != null)
					{
						parseRecord.PRobjectA[parseRecord.PRindexMap[0]] = pr.PRvalue;
					}
					else
					{
						((Array)parseRecord.PRnewObj).SetValue(pr.PRvalue, parseRecord.PRindexMap);
					}
				}
				else if (parseRecord.PRisEnum)
				{
					object obj = Enum.Parse(parseRecord.PRarrayElementType, pr.PRvalue);
					if (parseRecord.PRobjectA != null)
					{
						parseRecord.PRobjectA[parseRecord.PRindexMap[0]] = (Enum)obj;
					}
					else
					{
						((Array)parseRecord.PRnewObj).SetValue((Enum)obj, parseRecord.PRindexMap);
					}
				}
				else if (parseRecord.PRisArrayVariant)
				{
					if (pr.PRdtType == null && pr.PRkeyDt == null)
					{
						throw new SerializationException(SoapUtil.GetResourceString("Serialization_ArrayTypeObject"));
					}
					object obj2 = null;
					if (pr.PRdtType == Converter.typeofString)
					{
						ParseString(pr, parseRecord);
						obj2 = pr.PRvalue;
					}
					else if (pr.PRdtType.IsEnum)
					{
						obj2 = Enum.Parse(pr.PRdtType, pr.PRvalue);
					}
					else if (pr.PRdtTypeCode != 0)
					{
						obj2 = ((pr.PRvarValue == null) ? Converter.FromString(pr.PRvalue, pr.PRdtTypeCode) : pr.PRvarValue);
					}
					else
					{
						CheckSerializable(pr.PRdtType);
						obj2 = ((!IsRemoting || formatterEnums.FEsecurityLevel == TypeFilterLevel.Full) ? FormatterServices.GetUninitializedObject(pr.PRdtType) : FormatterServices.GetSafeUninitializedObject(pr.PRdtType));
					}
					if (parseRecord.PRobjectA != null)
					{
						parseRecord.PRobjectA[parseRecord.PRindexMap[0]] = obj2;
					}
					else
					{
						((Array)parseRecord.PRnewObj).SetValue(obj2, parseRecord.PRindexMap);
					}
				}
				else if (parseRecord.PRprimitiveArray != null)
				{
					parseRecord.PRprimitiveArray.SetValue(pr.PRvalue, parseRecord.PRindexMap[0]);
				}
				else
				{
					object obj3 = null;
					obj3 = ((pr.PRvarValue == null) ? Converter.FromString(pr.PRvalue, parseRecord.PRarrayElementTypeCode) : pr.PRvarValue);
					if (parseRecord.PRarrayElementTypeCode == InternalPrimitiveTypeE.QName)
					{
						SoapQName soapQName = (SoapQName)obj3;
						if (soapQName.Key.Length == 0)
						{
							soapQName.Namespace = (string)soapHandler.keyToNamespaceTable["xmlns"];
						}
						else
						{
							soapQName.Namespace = (string)soapHandler.keyToNamespaceTable["xmlns:" + soapQName.Key];
						}
					}
					if (parseRecord.PRobjectA != null)
					{
						parseRecord.PRobjectA[parseRecord.PRindexMap[0]] = obj3;
					}
					else
					{
						((Array)parseRecord.PRnewObj).SetValue(obj3, parseRecord.PRindexMap);
					}
				}
			}
			else if (pr.PRmemberValueEnum != InternalMemberValueE.Null)
			{
				ParseError(pr, parseRecord);
			}
			parseRecord.PRmemberIndex++;
		}

		private void ParseArrayMemberEnd(ParseRecord pr)
		{
			if (pr.PRmemberValueEnum == InternalMemberValueE.Nested)
			{
				ParseObjectEnd(pr);
			}
		}

		private void ParseMember(ParseRecord pr)
		{
			ParseRecord parseRecord = (ParseRecord)stack.Peek();
			_ = parseRecord?.PRname;
			if (parseRecord.PRdtType == Converter.typeofSoapFault && pr.PRname.ToLower(CultureInfo.InvariantCulture) == "faultstring")
			{
				faultString = pr.PRvalue;
			}
			if (parseRecord.PRobjectPositionEnum == InternalObjectPositionE.Top && !isTopObjectResolved)
			{
				if (pr.PRdtType == Converter.typeofString)
				{
					ParseString(pr, parseRecord);
				}
				topStack.Push(pr.Copy());
				return;
			}
			switch (pr.PRmemberTypeEnum)
			{
			case InternalMemberTypeE.Item:
				ParseArrayMember(pr);
				return;
			}
			if (parseRecord.PRobjectInfo != null)
			{
				parseRecord.PRobjectInfo.AddMemberSeen();
			}
			bool flag = IsFakeTopObject && parseRecord.PRobjectPositionEnum == InternalObjectPositionE.Top && parseRecord.PRobjectInfo != null && parseRecord.PRdtType != Converter.typeofSoapFault;
			if (pr.PRdtType == null && parseRecord.PRobjectInfo.isTyped)
			{
				if (flag)
				{
					pr.PRdtType = parseRecord.PRobjectInfo.GetType(paramPosition++);
				}
				else
				{
					pr.PRdtType = parseRecord.PRobjectInfo.GetType(pr.PRname);
				}
				if (pr.PRdtType == null)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_TypeResolved"), string.Concat(parseRecord.PRnewObj, " ", pr.PRname)));
				}
				pr.PRdtTypeCode = Converter.ToCode(pr.PRdtType);
			}
			else if (flag)
			{
				paramPosition++;
			}
			if (pr.PRmemberValueEnum == InternalMemberValueE.Null)
			{
				parseRecord.PRobjectInfo.AddValue(pr.PRname, null);
			}
			else if (pr.PRmemberValueEnum == InternalMemberValueE.Nested)
			{
				ParseObject(pr);
				stack.Push(pr);
				if (pr.PRobjectInfo != null && pr.PRobjectInfo.objectType.IsValueType)
				{
					if (IsFakeTopObject)
					{
						parseRecord.PRobjectInfo.AddParamName(pr.PRname);
					}
					pr.PRisValueTypeFixup = true;
					valueFixupStack.Push(new ValueFixup(parseRecord.PRnewObj, pr.PRname, parseRecord.PRobjectInfo));
				}
				else
				{
					parseRecord.PRobjectInfo.AddValue(pr.PRname, pr.PRnewObj);
				}
			}
			else if (pr.PRmemberValueEnum == InternalMemberValueE.Reference)
			{
				object @object = m_objectManager.GetObject(pr.PRidRef);
				if (@object == null)
				{
					parseRecord.PRobjectInfo.AddValue(pr.PRname, null);
					parseRecord.PRobjectInfo.RecordFixup(parseRecord.PRobjectId, pr.PRname, pr.PRidRef);
				}
				else
				{
					parseRecord.PRobjectInfo.AddValue(pr.PRname, @object);
				}
			}
			else if (pr.PRmemberValueEnum == InternalMemberValueE.InlineValue)
			{
				if (pr.PRdtType == Converter.typeofString)
				{
					ParseString(pr, parseRecord);
					parseRecord.PRobjectInfo.AddValue(pr.PRname, pr.PRvalue);
					return;
				}
				if (pr.PRdtTypeCode == InternalPrimitiveTypeE.Invalid)
				{
					if (pr.PRarrayTypeEnum == InternalArrayTypeE.Base64)
					{
						parseRecord.PRobjectInfo.AddValue(pr.PRname, Convert.FromBase64String(FilterBin64(pr.PRvalue)));
						return;
					}
					if (pr.PRdtType == Converter.typeofObject && pr.PRvalue != null)
					{
						if (parseRecord != null && parseRecord.PRdtType == Converter.typeofHeader)
						{
							pr.PRdtType = Converter.typeofString;
							ParseString(pr, parseRecord);
							parseRecord.PRobjectInfo.AddValue(pr.PRname, pr.PRvalue);
						}
						return;
					}
					if (pr.PRdtType != null && pr.PRdtType.IsEnum)
					{
						object value = Enum.Parse(pr.PRdtType, pr.PRvalue);
						parseRecord.PRobjectInfo.AddValue(pr.PRname, value);
						return;
					}
					if (pr.PRdtType != null && pr.PRdtType == Converter.typeofTypeArray)
					{
						parseRecord.PRobjectInfo.AddValue(pr.PRname, pr.PRvarValue);
						return;
					}
					if (!pr.PRisRegistered && pr.PRobjectId > 0)
					{
						if (pr.PRvalue == null)
						{
							pr.PRvalue = "";
						}
						RegisterObject(pr.PRvalue, pr, parseRecord);
					}
					if (pr.PRdtType == Converter.typeofSystemVoid)
					{
						parseRecord.PRobjectInfo.AddValue(pr.PRname, pr.PRdtType);
					}
					else if (parseRecord.PRobjectInfo.isSi)
					{
						parseRecord.PRobjectInfo.AddValue(pr.PRname, pr.PRvalue);
					}
					return;
				}
				object obj = null;
				obj = ((pr.PRvarValue == null) ? Converter.FromString(pr.PRvalue, pr.PRdtTypeCode) : pr.PRvarValue);
				if (pr.PRdtTypeCode == InternalPrimitiveTypeE.QName && obj != null)
				{
					SoapQName soapQName = (SoapQName)obj;
					if (soapQName.Key != null)
					{
						if (soapQName.Key.Length == 0)
						{
							soapQName.Namespace = (string)soapHandler.keyToNamespaceTable["xmlns"];
						}
						else
						{
							soapQName.Namespace = (string)soapHandler.keyToNamespaceTable["xmlns:" + soapQName.Key];
						}
					}
				}
				parseRecord.PRobjectInfo.AddValue(pr.PRname, obj);
			}
			else
			{
				ParseError(pr, parseRecord);
			}
		}

		private void ParseMemberEnd(ParseRecord pr)
		{
			switch (pr.PRmemberTypeEnum)
			{
			case InternalMemberTypeE.Item:
				ParseArrayMemberEnd(pr);
				break;
			case InternalMemberTypeE.Field:
				if (pr.PRmemberValueEnum == InternalMemberValueE.Nested)
				{
					ParseObjectEnd(pr);
				}
				break;
			default:
				if (pr.PRmemberValueEnum == InternalMemberValueE.Nested)
				{
					ParseObjectEnd(pr);
				}
				else
				{
					ParseError(pr, (ParseRecord)stack.Peek());
				}
				break;
			}
		}

		private void ParseString(ParseRecord pr, ParseRecord parentPr)
		{
			if (pr.PRvalue == null)
			{
				pr.PRvalue = "";
			}
			if (!pr.PRisRegistered && pr.PRobjectId > 0)
			{
				RegisterObject(pr.PRvalue, pr, parentPr);
			}
		}

		private void RegisterObject(object obj, ParseRecord pr, ParseRecord objectPr)
		{
			if (pr.PRisRegistered)
			{
				return;
			}
			pr.PRisRegistered = true;
			SerializationInfo info = null;
			long idOfContainingObj = 0L;
			MemberInfo member = null;
			int[] arrayIndex = null;
			if (objectPr != null)
			{
				arrayIndex = objectPr.PRindexMap;
				idOfContainingObj = objectPr.PRobjectId;
				if (objectPr.PRobjectInfo != null && !objectPr.PRobjectInfo.isSi)
				{
					member = objectPr.PRobjectInfo.GetMemberInfo(pr.PRname);
				}
			}
			if (pr.PRobjectInfo != null)
			{
				info = pr.PRobjectInfo.si;
			}
			m_objectManager.RegisterObject(obj, pr.PRobjectId, info, idOfContainingObj, member, arrayIndex);
		}

		internal void SetVersion(int major, int minor)
		{
			if (formatterEnums.FEassemblyFormat != 0)
			{
				majorVersion = major;
				minorVersion = minor;
			}
		}

		internal long GetId(string keyId)
		{
			if (keyId == null)
			{
				throw new ArgumentNullException("keyId", string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("ArgumentNull_WithParamName"), "keyId"));
			}
			if (keyId != inKeyId)
			{
				inKeyId = keyId;
				string text = null;
				text = ((keyId[0] != '#') ? keyId : keyId.Substring(1));
				object obj = objectIdTable[text];
				if (obj == null)
				{
					outKeyId = ++objectIds;
					objectIdTable[text] = outKeyId;
				}
				else
				{
					outKeyId = (long)obj;
				}
			}
			return outKeyId;
		}

		[Conditional("SER_LOGGING")]
		private void IndexTraceMessage(string message, int[] index)
		{
			StringBuilder stringBuilder = new StringBuilder(10);
			stringBuilder.Append("[");
			for (int i = 0; i < index.Length; i++)
			{
				stringBuilder.Append(index[i]);
				if (i != index.Length - 1)
				{
					stringBuilder.Append(",");
				}
			}
			stringBuilder.Append("]");
		}

		internal Assembly LoadAssemblyFromString(string assemblyString)
		{
			Assembly result = null;
			if (formatterEnums.FEassemblyFormat == FormatterAssemblyStyle.Simple)
			{
				try
				{
					sfileIOPermission.Assert();
					try
					{
						result = Assembly.LoadWithPartialName(assemblyString, null);
						return result;
					}
					finally
					{
						CodeAccessPermission.RevertAssert();
					}
				}
				catch (Exception)
				{
					return result;
				}
				catch
				{
					return result;
				}
			}
			try
			{
				sfileIOPermission.Assert();
				try
				{
					result = Assembly.Load(assemblyString);
					return result;
				}
				finally
				{
					CodeAccessPermission.RevertAssert();
				}
			}
			catch (Exception)
			{
				return result;
			}
			catch
			{
				return result;
			}
		}

		internal Type Bind(string assemblyString, string typeString)
		{
			Type result = null;
			if (m_binder != null && !IsInternalType(assemblyString, typeString))
			{
				result = m_binder.BindToType(assemblyString, typeString);
			}
			return result;
		}

		private bool IsInternalType(string assemblyString, string typeString)
		{
			if (assemblyString == Converter.urtAssemblyString)
			{
				if (!(typeString == "System.DelegateSerializationHolder") && !(typeString == "System.UnitySerializationHolder"))
				{
					return typeString == "System.MemberInfoSerializationHolder";
				}
				return true;
			}
			return false;
		}

		internal Type FastBindToType(string assemblyName, string typeName)
		{
			Type type = null;
			TypeNAssembly typeNAssembly = typeCache.GetCachedValue(typeName) as TypeNAssembly;
			if (typeNAssembly == null || typeNAssembly.assemblyName != assemblyName)
			{
				Assembly assembly = LoadAssemblyFromString(assemblyName);
				if (assembly == null)
				{
					return null;
				}
				type = FormatterServices.GetTypeFromAssembly(assembly, typeName);
				if (type == null)
				{
					return null;
				}
				typeNAssembly = new TypeNAssembly();
				typeNAssembly.type = type;
				typeNAssembly.assemblyName = assemblyName;
				typeCache.SetCachedValue(typeNAssembly);
			}
			return typeNAssembly.type;
		}

		internal string FilterBin64(string value)
		{
			sbf.Length = 0;
			for (int i = 0; i < value.Length; i++)
			{
				if (value[i] != ' ' && value[i] != '\n' && value[i] != '\r')
				{
					sbf.Append(value[i]);
				}
			}
			return sbf.ToString();
		}
	}
	internal sealed class ObjectWriter
	{
		private Queue m_objectQueue;

		private ObjectIDGenerator m_idGenerator;

		private Stream m_stream;

		private ISurrogateSelector m_surrogates;

		private StreamingContext m_context;

		private SoapWriter serWriter;

		private SerializationObjectManager m_objectManager;

		private Hashtable m_serializedTypeTable;

		private long topId;

		private string topName;

		private Header[] headers;

		private InternalFE formatterEnums;

		private SerObjectInfoInit serObjectInfoInit;

		private IFormatterConverter m_formatterConverter;

		private string headerNamespace = "http://schemas.microsoft.com/clr/soap";

		private bool bRemoting;

		internal static SecurityPermission serializationPermission = new SecurityPermission(SecurityPermissionFlag.SerializationFormatter);

		private PrimitiveArray primitiveArray;

		private object previousObj;

		private long previousId;

		private Hashtable assemblyToIdTable = new Hashtable(20);

		private StringBuilder sburi = new StringBuilder(50);

		private SerStack niPool = new SerStack("NameInfo Pool");

		internal SerializationObjectManager ObjectManager => m_objectManager;

		internal ObjectWriter(Stream stream, ISurrogateSelector selector, StreamingContext context, InternalFE formatterEnums)
		{
			if (stream == null)
			{
				throw new ArgumentNullException("stream", SoapUtil.GetResourceString("ArgumentNull_Stream"));
			}
			m_stream = stream;
			m_surrogates = selector;
			m_context = context;
			this.formatterEnums = formatterEnums;
			m_objectManager = new SerializationObjectManager(context);
			m_formatterConverter = new FormatterConverter();
		}

		internal void Serialize(object graph, Header[] inHeaders, SoapWriter serWriter)
		{
			serializationPermission.Demand();
			if (graph == null)
			{
				throw new ArgumentNullException("graph", SoapUtil.GetResourceString("ArgumentNull_Graph"));
			}
			if (serWriter == null)
			{
				throw new ArgumentNullException("serWriter", string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("ArgumentNull_WithParamName"), "serWriter"));
			}
			serObjectInfoInit = new SerObjectInfoInit();
			this.serWriter = serWriter;
			headers = inHeaders;
			if (graph is IMethodMessage)
			{
				bRemoting = true;
				MethodBase methodBase = ((IMethodMessage)graph).MethodBase;
				if (methodBase != null)
				{
					serWriter.WriteXsdVersion(ProcessTypeAttributes(methodBase.ReflectedType));
				}
				else
				{
					serWriter.WriteXsdVersion(XsdVersion.V2001);
				}
			}
			else
			{
				serWriter.WriteXsdVersion(XsdVersion.V2001);
			}
			m_idGenerator = new ObjectIDGenerator();
			m_objectQueue = new Queue();
			if (graph is ISoapMessage)
			{
				bRemoting = true;
				ISoapMessage soapMessage = (ISoapMessage)graph;
				graph = new InternalSoapMessage(soapMessage.MethodName, soapMessage.XmlNameSpace, soapMessage.ParamNames, soapMessage.ParamValues, soapMessage.ParamTypes);
				headers = soapMessage.Headers;
			}
			m_serializedTypeTable = new Hashtable();
			serWriter.WriteBegin();
			long num = 0L;
			topId = m_idGenerator.GetId(graph, out var firstTime);
			num = ((headers == null) ? (-1) : m_idGenerator.GetId(headers, out firstTime));
			WriteSerializedStreamHeader(topId, num);
			if (headers != null && headers.Length != 0)
			{
				ProcessHeaders(num);
			}
			m_objectQueue.Enqueue(graph);
			object next;
			long objID;
			while ((next = GetNext(out objID)) != null)
			{
				WriteObjectInfo writeObjectInfo = null;
				if (next is WriteObjectInfo)
				{
					writeObjectInfo = (WriteObjectInfo)next;
				}
				else
				{
					writeObjectInfo = WriteObjectInfo.Serialize(next, m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, null, this);
					writeObjectInfo.assemId = GetAssemblyId(writeObjectInfo);
				}
				writeObjectInfo.objectId = objID;
				NameInfo nameInfo = TypeToNameInfo(writeObjectInfo);
				nameInfo.NIisTopLevelObject = true;
				if (bRemoting && next == graph)
				{
					nameInfo.NIisRemoteRecord = true;
				}
				Write(writeObjectInfo, nameInfo, nameInfo);
				PutNameInfo(nameInfo);
				writeObjectInfo.ObjectEnd();
			}
			serWriter.WriteSerializationHeaderEnd();
			serWriter.WriteEnd();
			m_idGenerator = new ObjectIDGenerator();
			m_serializedTypeTable = new Hashtable();
			m_objectManager.RaiseOnSerializedEvent();
		}

		private XsdVersion ProcessTypeAttributes(Type type)
		{
			SoapTypeAttribute soapTypeAttribute = InternalRemotingServices.GetCachedSoapAttribute(type) as SoapTypeAttribute;
			XsdVersion result = XsdVersion.V2001;
			if (soapTypeAttribute != null)
			{
				SoapOption soapOptions = soapTypeAttribute.SoapOptions;
				if ((soapOptions &= SoapOption.Option1) == SoapOption.Option1)
				{
					result = XsdVersion.V1999;
				}
				else if ((soapOptions &= SoapOption.Option1) == SoapOption.Option2)
				{
					result = XsdVersion.V2000;
				}
			}
			return result;
		}

		private void ProcessHeaders(long headerId)
		{
			serWriter.WriteHeader((int)headerId, headers.Length);
			for (int i = 0; i < headers.Length; i++)
			{
				Type type = null;
				if (headers[i].Value != null)
				{
					type = GetType(headers[i].Value);
				}
				if (type != null && type == Converter.typeofString)
				{
					NameInfo nameInfo = GetNameInfo();
					nameInfo.NInameSpaceEnum = InternalNameSpaceE.UserNameSpace;
					nameInfo.NIname = headers[i].Name;
					nameInfo.NIisMustUnderstand = headers[i].MustUnderstand;
					nameInfo.NIobjectId = -1L;
					HeaderNamespace(headers[i], nameInfo);
					serWriter.WriteHeaderString(nameInfo, headers[i].Value.ToString());
					PutNameInfo(nameInfo);
					continue;
				}
				if (headers[i].Name.Equals("__MethodSignature"))
				{
					if (!(headers[i].Value is Type[]))
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_MethodSignature"), type));
					}
					Type[] array = (Type[])headers[i].Value;
					NameInfo[] array2 = new NameInfo[array.Length];
					WriteObjectInfo[] array3 = new WriteObjectInfo[array.Length];
					for (int j = 0; j < array.Length; j++)
					{
						array3[j] = WriteObjectInfo.Serialize(array[j], m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, null);
						array3[j].objectId = -1L;
						array3[j].assemId = GetAssemblyId(array3[j]);
						array2[j] = TypeToNameInfo(array3[j]);
					}
					NameInfo nameInfo2 = MemberToNameInfo(headers[i].Name);
					nameInfo2.NIisMustUnderstand = headers[i].MustUnderstand;
					nameInfo2.NItransmitTypeOnMember = true;
					nameInfo2.NIisNestedObject = true;
					nameInfo2.NIisHeader = true;
					HeaderNamespace(headers[i], nameInfo2);
					serWriter.WriteHeaderMethodSignature(nameInfo2, array2);
					for (int k = 0; k < array.Length; k++)
					{
						PutNameInfo(array2[k]);
						array3[k].ObjectEnd();
					}
					PutNameInfo(nameInfo2);
					continue;
				}
				InternalPrimitiveTypeE internalPrimitiveTypeE = InternalPrimitiveTypeE.Invalid;
				if (type != null)
				{
					internalPrimitiveTypeE = Converter.ToCode(type);
				}
				if (type != null && internalPrimitiveTypeE == InternalPrimitiveTypeE.Invalid)
				{
					long num = Schedule(headers[i].Value, type);
					if (num == -1)
					{
						WriteObjectInfo writeObjectInfo = WriteObjectInfo.Serialize(headers[i].Value, m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, null, this);
						writeObjectInfo.objectId = -1L;
						writeObjectInfo.assemId = GetAssemblyId(writeObjectInfo);
						NameInfo nameInfo3 = TypeToNameInfo(writeObjectInfo);
						NameInfo nameInfo4 = MemberToNameInfo(headers[i].Name);
						nameInfo4.NIisMustUnderstand = headers[i].MustUnderstand;
						nameInfo4.NItransmitTypeOnMember = true;
						nameInfo4.NIisNestedObject = true;
						nameInfo4.NIisHeader = true;
						HeaderNamespace(headers[i], nameInfo4);
						Write(writeObjectInfo, nameInfo4, nameInfo3);
						PutNameInfo(nameInfo3);
						PutNameInfo(nameInfo4);
						writeObjectInfo.ObjectEnd();
					}
					else
					{
						NameInfo nameInfo5 = MemberToNameInfo(headers[i].Name);
						nameInfo5.NIisMustUnderstand = headers[i].MustUnderstand;
						nameInfo5.NIobjectId = num;
						nameInfo5.NItransmitTypeOnMember = true;
						nameInfo5.NIisNestedObject = true;
						HeaderNamespace(headers[i], nameInfo5);
						serWriter.WriteHeaderObjectRef(nameInfo5);
						PutNameInfo(nameInfo5);
					}
				}
				else
				{
					NameInfo nameInfo6 = GetNameInfo();
					nameInfo6.NInameSpaceEnum = InternalNameSpaceE.UserNameSpace;
					nameInfo6.NIname = headers[i].Name;
					nameInfo6.NIisMustUnderstand = headers[i].MustUnderstand;
					nameInfo6.NIprimitiveTypeEnum = internalPrimitiveTypeE;
					HeaderNamespace(headers[i], nameInfo6);
					NameInfo nameInfo7 = null;
					if (type != null)
					{
						nameInfo7 = TypeToNameInfo(type);
						nameInfo7.NItransmitTypeOnMember = true;
					}
					serWriter.WriteHeaderEntry(nameInfo6, nameInfo7, headers[i].Value);
					PutNameInfo(nameInfo6);
					if (type != null)
					{
						PutNameInfo(nameInfo7);
					}
				}
			}
			serWriter.WriteHeaderArrayEnd();
			object next;
			long objID;
			while ((next = GetNext(out objID)) != null)
			{
				WriteObjectInfo writeObjectInfo2 = null;
				if (next is WriteObjectInfo)
				{
					writeObjectInfo2 = (WriteObjectInfo)next;
				}
				else
				{
					writeObjectInfo2 = WriteObjectInfo.Serialize(next, m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, null, this);
					writeObjectInfo2.assemId = GetAssemblyId(writeObjectInfo2);
				}
				writeObjectInfo2.objectId = objID;
				NameInfo nameInfo8 = TypeToNameInfo(writeObjectInfo2);
				Write(writeObjectInfo2, nameInfo8, nameInfo8);
				PutNameInfo(nameInfo8);
				writeObjectInfo2.ObjectEnd();
			}
			serWriter.WriteHeaderSectionEnd();
		}

		private void HeaderNamespace(Header header, NameInfo nameInfo)
		{
			if (header.HeaderNamespace == null)
			{
				nameInfo.NInamespace = headerNamespace;
			}
			else
			{
				nameInfo.NInamespace = header.HeaderNamespace;
			}
			bool isNew = false;
			nameInfo.NIheaderPrefix = "h" + InternalGetId(nameInfo.NInamespace, Converter.typeofString, out isNew);
		}

		private void Write(WriteObjectInfo objectInfo, NameInfo memberNameInfo, NameInfo typeNameInfo)
		{
			object obj = objectInfo.obj;
			if (obj == null)
			{
				throw new ArgumentNullException("objectInfo.obj", string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ArgumentNull_Obj"), objectInfo.objectType));
			}
			if (objectInfo.objectType.IsGenericType)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_SoapNoGenericsSupport"), objectInfo.objectType));
			}
			Type objectType = objectInfo.objectType;
			long objectId = objectInfo.objectId;
			if (objectType == Converter.typeofString)
			{
				memberNameInfo.NIobjectId = objectId;
				serWriter.WriteObjectString(memberNameInfo, obj.ToString());
				return;
			}
			if (objectType == Converter.typeofTimeSpan)
			{
				serWriter.WriteTopPrimitive(memberNameInfo, obj);
				return;
			}
			if (objectType.IsArray)
			{
				WriteArray(objectInfo, null, null);
			}
			else
			{
				objectInfo.GetMemberInfo(out var outMemberNames, out var outMemberTypes, out var outMemberData, out var outAttributeInfo);
				if (CheckTypeFormat(formatterEnums.FEtypeFormat, FormatterTypeStyle.TypesAlways))
				{
					memberNameInfo.NItransmitTypeOnObject = true;
					memberNameInfo.NIisParentTypeOnObject = true;
					typeNameInfo.NItransmitTypeOnObject = true;
					typeNameInfo.NIisParentTypeOnObject = true;
				}
				WriteObjectInfo[] array = new WriteObjectInfo[outMemberNames.Length];
				for (int i = 0; i < outMemberTypes.Length; i++)
				{
					if (Nullable.GetUnderlyingType(outMemberTypes[i]) != null)
					{
						throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_SoapNoGenericsSupport"), outMemberTypes[i]));
					}
					Type type = null;
					type = ((outMemberData[i] == null) ? typeof(object) : GetType(outMemberData[i]));
					if ((Converter.ToCode(type) == InternalPrimitiveTypeE.Invalid && type != Converter.typeofString) || (objectInfo.cache.memberAttributeInfos != null && objectInfo.cache.memberAttributeInfos[i] != null && (objectInfo.cache.memberAttributeInfos[i].IsXmlAttribute() || objectInfo.cache.memberAttributeInfos[i].IsXmlElement())))
					{
						if (outMemberData[i] != null)
						{
							array[i] = WriteObjectInfo.Serialize(outMemberData[i], m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, (outAttributeInfo == null) ? null : outAttributeInfo[i], this);
							array[i].assemId = GetAssemblyId(array[i]);
						}
						else
						{
							array[i] = WriteObjectInfo.Serialize(outMemberTypes[i], m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, (outAttributeInfo == null) ? null : outAttributeInfo[i]);
							array[i].assemId = GetAssemblyId(array[i]);
						}
					}
				}
				Write(objectInfo, memberNameInfo, typeNameInfo, outMemberNames, outMemberTypes, outMemberData, array);
			}
			if (!m_serializedTypeTable.ContainsKey(objectType))
			{
				m_serializedTypeTable.Add(objectType, objectType);
			}
		}

		private void Write(WriteObjectInfo objectInfo, NameInfo memberNameInfo, NameInfo typeNameInfo, string[] memberNames, Type[] memberTypes, object[] memberData, WriteObjectInfo[] memberObjectInfos)
		{
			int num = memberNames.Length;
			NameInfo nameInfo = null;
			if (objectInfo.cache.memberAttributeInfos != null)
			{
				for (int i = 0; i < objectInfo.cache.memberAttributeInfos.Length; i++)
				{
					if (objectInfo.cache.memberAttributeInfos[i] != null && objectInfo.cache.memberAttributeInfos[i].IsXmlAttribute())
					{
						WriteMemberSetup(objectInfo, memberNameInfo, typeNameInfo, memberNames[i], memberTypes[i], memberData[i], memberObjectInfos[i], isAttribute: true);
					}
				}
			}
			if (memberNameInfo != null)
			{
				memberNameInfo.NIobjectId = objectInfo.objectId;
				serWriter.WriteObject(memberNameInfo, typeNameInfo, num, memberNames, memberTypes, memberObjectInfos);
			}
			else if (objectInfo.objectId == topId && topName != null)
			{
				nameInfo = MemberToNameInfo(topName);
				nameInfo.NIobjectId = objectInfo.objectId;
				serWriter.WriteObject(nameInfo, typeNameInfo, num, memberNames, memberTypes, memberObjectInfos);
			}
			else if (objectInfo.objectType != Converter.typeofString)
			{
				typeNameInfo.NIobjectId = objectInfo.objectId;
				serWriter.WriteObject(typeNameInfo, null, num, memberNames, memberTypes, memberObjectInfos);
			}
			if (memberNameInfo.NIisParentTypeOnObject)
			{
				memberNameInfo.NItransmitTypeOnObject = true;
				memberNameInfo.NIisParentTypeOnObject = false;
			}
			else
			{
				memberNameInfo.NItransmitTypeOnObject = false;
			}
			for (int j = 0; j < num; j++)
			{
				if (objectInfo.cache.memberAttributeInfos == null || objectInfo.cache.memberAttributeInfos[j] == null || !objectInfo.cache.memberAttributeInfos[j].IsXmlAttribute())
				{
					WriteMemberSetup(objectInfo, memberNameInfo, typeNameInfo, memberNames[j], memberTypes[j], memberData[j], memberObjectInfos[j], isAttribute: false);
				}
			}
			if (memberNameInfo != null)
			{
				memberNameInfo.NIobjectId = objectInfo.objectId;
				serWriter.WriteObjectEnd(memberNameInfo, typeNameInfo);
			}
			else if (objectInfo.objectId == topId && topName != null)
			{
				serWriter.WriteObjectEnd(nameInfo, typeNameInfo);
				PutNameInfo(nameInfo);
			}
			else if (objectInfo.objectType != Converter.typeofString)
			{
				objectInfo.GetTypeFullName();
				serWriter.WriteObjectEnd(typeNameInfo, typeNameInfo);
			}
		}

		private void WriteMemberSetup(WriteObjectInfo objectInfo, NameInfo memberNameInfo, NameInfo typeNameInfo, string memberName, Type memberType, object memberData, WriteObjectInfo memberObjectInfo, bool isAttribute)
		{
			NameInfo nameInfo = MemberToNameInfo(memberName);
			if (memberObjectInfo != null)
			{
				nameInfo.NIassemId = memberObjectInfo.assemId;
			}
			nameInfo.NItype = memberType;
			NameInfo nameInfo2 = null;
			nameInfo2 = ((memberObjectInfo != null) ? TypeToNameInfo(memberObjectInfo) : TypeToNameInfo(memberType));
			nameInfo.NIisRemoteRecord = typeNameInfo.NIisRemoteRecord;
			nameInfo.NItransmitTypeOnObject = memberNameInfo.NItransmitTypeOnObject;
			nameInfo.NIisParentTypeOnObject = memberNameInfo.NIisParentTypeOnObject;
			WriteMembers(nameInfo, nameInfo2, memberData, objectInfo, typeNameInfo, memberObjectInfo, isAttribute);
			PutNameInfo(nameInfo);
			PutNameInfo(nameInfo2);
		}

		private void WriteMembers(NameInfo memberNameInfo, NameInfo memberTypeNameInfo, object memberData, WriteObjectInfo objectInfo, NameInfo typeNameInfo, WriteObjectInfo memberObjectInfo, bool isAttribute)
		{
			Type type = memberNameInfo.NItype;
			if (type == Converter.typeofObject || (type.IsValueType && objectInfo.isSi && Converter.IsSiTransmitType(memberTypeNameInfo.NIprimitiveTypeEnum)))
			{
				memberTypeNameInfo.NItransmitTypeOnMember = true;
				memberNameInfo.NItransmitTypeOnMember = true;
			}
			if (CheckTypeFormat(formatterEnums.FEtypeFormat, FormatterTypeStyle.TypesAlways))
			{
				memberTypeNameInfo.NItransmitTypeOnObject = true;
				memberNameInfo.NItransmitTypeOnObject = true;
				memberNameInfo.NIisParentTypeOnObject = true;
			}
			if (CheckForNull(objectInfo, memberNameInfo, memberTypeNameInfo, memberData))
			{
				return;
			}
			Type type2 = null;
			if (memberTypeNameInfo.NIprimitiveTypeEnum == InternalPrimitiveTypeE.Invalid)
			{
				if (RemotingServices.IsTransparentProxy(memberData))
				{
					type2 = Converter.typeofMarshalByRefObject;
				}
				else
				{
					type2 = GetType(memberData);
					if (type != type2)
					{
						memberTypeNameInfo.NItransmitTypeOnMember = true;
						memberNameInfo.NItransmitTypeOnMember = true;
					}
				}
			}
			if (type == Converter.typeofObject)
			{
				type = GetType(memberData);
				if (memberObjectInfo == null)
				{
					TypeToNameInfo(type, memberTypeNameInfo);
				}
				else
				{
					TypeToNameInfo(memberObjectInfo, memberTypeNameInfo);
				}
			}
			if (memberObjectInfo != null && memberObjectInfo.isArray)
			{
				long num = 0L;
				if (!objectInfo.IsEmbeddedAttribute(memberNameInfo.NIname) && !IsEmbeddedAttribute(type))
				{
					num = Schedule(memberData, type2, memberObjectInfo);
				}
				if (num > 0)
				{
					memberNameInfo.NIobjectId = num;
					WriteObjectRef(memberNameInfo, memberTypeNameInfo, num);
					return;
				}
				serWriter.WriteMemberNested(memberNameInfo);
				memberObjectInfo.objectId = num;
				memberNameInfo.NIobjectId = num;
				memberNameInfo.NIisNestedObject = true;
				WriteArray(memberObjectInfo, memberNameInfo, memberObjectInfo);
			}
			else
			{
				if (WriteKnownValueClass(memberNameInfo, memberTypeNameInfo, memberData, isAttribute))
				{
					return;
				}
				if (memberTypeNameInfo.NItype.IsEnum)
				{
					WriteEnum(memberNameInfo, memberTypeNameInfo, memberData, isAttribute);
					return;
				}
				if (isAttribute)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_NonPrimitive_XmlAttribute"), memberNameInfo.NIname));
				}
				if (type.IsValueType || objectInfo.IsEmbeddedAttribute(memberNameInfo.NIname) || IsEmbeddedAttribute(type2))
				{
					serWriter.WriteMemberNested(memberNameInfo);
					memberObjectInfo.objectId = -1L;
					NameInfo nameInfo = TypeToNameInfo(memberObjectInfo);
					nameInfo.NIobjectId = -1L;
					memberNameInfo.NIisNestedObject = true;
					if (objectInfo.isSi)
					{
						memberTypeNameInfo.NItransmitTypeOnMember = true;
						memberNameInfo.NItransmitTypeOnMember = true;
					}
					Write(memberObjectInfo, memberNameInfo, nameInfo);
					PutNameInfo(nameInfo);
					memberObjectInfo.ObjectEnd();
					return;
				}
				long num2 = 0L;
				num2 = Schedule(memberData, type2, memberObjectInfo);
				if (num2 < 0)
				{
					serWriter.WriteMemberNested(memberNameInfo);
					memberObjectInfo.objectId = -1L;
					NameInfo nameInfo2 = TypeToNameInfo(memberObjectInfo);
					nameInfo2.NIobjectId = -1L;
					memberNameInfo.NIisNestedObject = true;
					Write(memberObjectInfo, memberNameInfo, nameInfo2);
					PutNameInfo(nameInfo2);
					memberObjectInfo.ObjectEnd();
				}
				else
				{
					memberNameInfo.NIobjectId = num2;
					WriteObjectRef(memberNameInfo, memberTypeNameInfo, num2);
				}
			}
		}

		private void WriteArray(WriteObjectInfo objectInfo, NameInfo memberNameInfo, WriteObjectInfo memberObjectInfo)
		{
			bool flag = false;
			if (memberNameInfo == null)
			{
				memberNameInfo = TypeToNameInfo(objectInfo);
				memberNameInfo.NIisTopLevelObject = true;
				flag = true;
			}
			memberNameInfo.NIisArray = true;
			long objectId = objectInfo.objectId;
			memberNameInfo.NIobjectId = objectInfo.objectId;
			Array array = (Array)objectInfo.obj;
			Type objectType = objectInfo.objectType;
			Type elementType = objectType.GetElementType();
			if (Nullable.GetUnderlyingType(elementType) != null)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_SoapNoGenericsSupport"), elementType));
			}
			WriteObjectInfo writeObjectInfo = WriteObjectInfo.Serialize(elementType, m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, memberObjectInfo?.typeAttributeInfo);
			writeObjectInfo.assemId = GetAssemblyId(writeObjectInfo);
			NameInfo arrayElemTypeNameInfo = null;
			NameInfo nameInfo = ArrayTypeToNameInfo(objectInfo, out arrayElemTypeNameInfo);
			nameInfo.NIobjectId = objectId;
			nameInfo.NIisArray = true;
			arrayElemTypeNameInfo.NIobjectId = objectId;
			arrayElemTypeNameInfo.NItransmitTypeOnMember = memberNameInfo.NItransmitTypeOnMember;
			arrayElemTypeNameInfo.NItransmitTypeOnObject = memberNameInfo.NItransmitTypeOnObject;
			arrayElemTypeNameInfo.NIisParentTypeOnObject = memberNameInfo.NIisParentTypeOnObject;
			int rank = array.Rank;
			int[] array2 = new int[rank];
			int[] array3 = new int[rank];
			int[] array4 = new int[rank];
			for (int i = 0; i < rank; i++)
			{
				array2[i] = array.GetLength(i);
				array3[i] = array.GetLowerBound(i);
				array4[i] = array.GetUpperBound(i);
			}
			InternalArrayTypeE internalArrayTypeE = (elementType.IsArray ? ((rank != 1) ? InternalArrayTypeE.Rectangular : InternalArrayTypeE.Jagged) : ((rank == 1) ? InternalArrayTypeE.Single : InternalArrayTypeE.Rectangular));
			if (elementType == Converter.typeofByte && rank == 1 && array3[0] == 0)
			{
				serWriter.WriteObjectByteArray(memberNameInfo, nameInfo, writeObjectInfo, arrayElemTypeNameInfo, array2[0], array3[0], (byte[])array);
				return;
			}
			if (elementType == Converter.typeofObject)
			{
				memberNameInfo.NItransmitTypeOnMember = true;
				arrayElemTypeNameInfo.NItransmitTypeOnMember = true;
			}
			if (CheckTypeFormat(formatterEnums.FEtypeFormat, FormatterTypeStyle.TypesAlways))
			{
				memberNameInfo.NItransmitTypeOnObject = true;
				arrayElemTypeNameInfo.NItransmitTypeOnObject = true;
			}
			switch (internalArrayTypeE)
			{
			case InternalArrayTypeE.Single:
			{
				nameInfo.NIname = arrayElemTypeNameInfo.NIname + "[" + array2[0] + "]";
				serWriter.WriteSingleArray(memberNameInfo, nameInfo, writeObjectInfo, arrayElemTypeNameInfo, array2[0], array3[0], array);
				if (Converter.IsWriteAsByteArray(arrayElemTypeNameInfo.NIprimitiveTypeEnum) && array3[0] == 0)
				{
					arrayElemTypeNameInfo.NIobjectId = 0L;
					if (primitiveArray == null)
					{
						primitiveArray = new PrimitiveArray(arrayElemTypeNameInfo.NIprimitiveTypeEnum, array);
					}
					else
					{
						primitiveArray.Init(arrayElemTypeNameInfo.NIprimitiveTypeEnum, array);
					}
					int num = array4[0] + 1;
					for (int l = array3[0]; l < num; l++)
					{
						serWriter.WriteItemString(arrayElemTypeNameInfo, arrayElemTypeNameInfo, primitiveArray.GetValue(l));
					}
					break;
				}
				object[] array5 = null;
				if (!elementType.IsValueType)
				{
					array5 = (object[])array;
				}
				int num2 = array4[0] + 1;
				if (array5 != null)
				{
					int num3 = array3[0] - 1;
					for (int m = array3[0]; m < num2; m++)
					{
						if (array5[m] != null)
						{
							num3 = m;
						}
					}
					num2 = num3 + 1;
				}
				for (int n = array3[0]; n < num2; n++)
				{
					if (array5 == null)
					{
						WriteArrayMember(objectInfo, arrayElemTypeNameInfo, array.GetValue(n));
					}
					else
					{
						WriteArrayMember(objectInfo, arrayElemTypeNameInfo, array5[n]);
					}
				}
				break;
			}
			case InternalArrayTypeE.Jagged:
			{
				int num4 = nameInfo.NIname.IndexOf('[');
				if (num4 < 0)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Dimensions"), arrayElemTypeNameInfo.NIname));
				}
				nameInfo.NIname.Substring(num4);
				nameInfo.NIname = arrayElemTypeNameInfo.NIname + "[" + array2[0] + "]";
				nameInfo.NIobjectId = objectId;
				serWriter.WriteJaggedArray(memberNameInfo, nameInfo, writeObjectInfo, arrayElemTypeNameInfo, array2[0], array3[0]);
				object[] array6 = (object[])array;
				for (int num5 = array3[0]; num5 < array4[0] + 1; num5++)
				{
					WriteArrayMember(objectInfo, arrayElemTypeNameInfo, array6[num5]);
				}
				break;
			}
			default:
			{
				nameInfo.NIname.IndexOf('[');
				StringBuilder stringBuilder = new StringBuilder(10);
				stringBuilder.Append(arrayElemTypeNameInfo.NIname);
				stringBuilder.Append('[');
				for (int j = 0; j < rank; j++)
				{
					stringBuilder.Append(array2[j]);
					if (j < rank - 1)
					{
						stringBuilder.Append(',');
					}
				}
				stringBuilder.Append(']');
				nameInfo.NIname = stringBuilder.ToString();
				nameInfo.NIobjectId = objectId;
				serWriter.WriteRectangleArray(memberNameInfo, nameInfo, writeObjectInfo, arrayElemTypeNameInfo, rank, array2, array3);
				bool flag2 = false;
				for (int k = 0; k < rank; k++)
				{
					if (array2[k] == 0)
					{
						flag2 = true;
						break;
					}
				}
				if (!flag2)
				{
					WriteRectangle(objectInfo, rank, array2, array, arrayElemTypeNameInfo, array3);
				}
				break;
			}
			}
			serWriter.WriteObjectEnd(memberNameInfo, nameInfo);
			PutNameInfo(arrayElemTypeNameInfo);
			PutNameInfo(nameInfo);
			if (flag)
			{
				PutNameInfo(memberNameInfo);
			}
		}

		private void WriteArrayMember(WriteObjectInfo objectInfo, NameInfo arrayElemTypeNameInfo, object data)
		{
			arrayElemTypeNameInfo.NIisArrayItem = true;
			if (CheckForNull(objectInfo, arrayElemTypeNameInfo, arrayElemTypeNameInfo, data))
			{
				return;
			}
			NameInfo nameInfo = null;
			Type type = null;
			bool flag = false;
			if (arrayElemTypeNameInfo.NItransmitTypeOnMember)
			{
				flag = true;
			}
			if (!flag && !arrayElemTypeNameInfo.NIisSealed)
			{
				type = GetType(data);
				if (arrayElemTypeNameInfo.NItype != type)
				{
					flag = true;
				}
			}
			if (flag)
			{
				if (type == null)
				{
					type = GetType(data);
				}
				nameInfo = TypeToNameInfo(type);
				nameInfo.NItransmitTypeOnMember = true;
				nameInfo.NIobjectId = arrayElemTypeNameInfo.NIobjectId;
				nameInfo.NIassemId = arrayElemTypeNameInfo.NIassemId;
				nameInfo.NIisArrayItem = true;
				nameInfo.NIitemName = arrayElemTypeNameInfo.NIitemName;
			}
			else
			{
				nameInfo = arrayElemTypeNameInfo;
				nameInfo.NIisArrayItem = true;
			}
			if (!WriteKnownValueClass(arrayElemTypeNameInfo, nameInfo, data, isAttribute: false))
			{
				if (nameInfo.NItype.IsEnum)
				{
					WriteObjectInfo objectInfo2 = WriteObjectInfo.Serialize(data, m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, null, this);
					nameInfo.NIassemId = GetAssemblyId(objectInfo2);
					WriteEnum(arrayElemTypeNameInfo, nameInfo, data, isAttribute: false);
				}
				else
				{
					long num = (nameInfo.NIobjectId = (arrayElemTypeNameInfo.NIobjectId = Schedule(data, nameInfo.NItype)));
					if (num < 1)
					{
						WriteObjectInfo writeObjectInfo = WriteObjectInfo.Serialize(data, m_surrogates, m_context, serObjectInfoInit, m_formatterConverter, null, this);
						writeObjectInfo.objectId = num;
						writeObjectInfo.assemId = GetAssemblyId(writeObjectInfo);
						if (type == null)
						{
							type = GetType(data);
						}
						if (data != null && type.IsArray)
						{
							WriteArray(writeObjectInfo, nameInfo, null);
						}
						else
						{
							nameInfo.NIisNestedObject = true;
							NameInfo nameInfo2 = TypeToNameInfo(writeObjectInfo);
							nameInfo2.NIobjectId = num;
							writeObjectInfo.objectId = num;
							Write(writeObjectInfo, nameInfo, nameInfo2);
						}
						writeObjectInfo.ObjectEnd();
					}
					else
					{
						serWriter.WriteItemObjectRef(arrayElemTypeNameInfo, (int)num);
					}
				}
			}
			if (arrayElemTypeNameInfo.NItransmitTypeOnMember)
			{
				PutNameInfo(nameInfo);
			}
		}

		private void WriteRectangle(WriteObjectInfo objectInfo, int rank, int[] maxA, Array array, NameInfo arrayElemNameTypeInfo, int[] lowerBoundA)
		{
			int[] array2 = new int[rank];
			int[] array3 = null;
			bool flag = false;
			if (lowerBoundA != null)
			{
				for (int i = 0; i < rank; i++)
				{
					if (lowerBoundA[i] != 0)
					{
						flag = true;
					}
				}
			}
			if (flag)
			{
				array3 = new int[rank];
			}
			bool flag2 = true;
			while (flag2)
			{
				flag2 = false;
				if (flag)
				{
					for (int j = 0; j < rank; j++)
					{
						array3[j] = array2[j] + lowerBoundA[j];
					}
					WriteArrayMember(objectInfo, arrayElemNameTypeInfo, array.GetValue(array3));
				}
				else
				{
					WriteArrayMember(objectInfo, arrayElemNameTypeInfo, array.GetValue(array2));
				}
				for (int num = rank - 1; num > -1; num--)
				{
					if (array2[num] < maxA[num] - 1)
					{
						array2[num]++;
						if (num < rank - 1)
						{
							for (int k = num + 1; k < rank; k++)
							{
								array2[k] = 0;
							}
						}
						flag2 = true;
						break;
					}
				}
			}
		}

		[Conditional("SER_LOGGING")]
		private void IndexTraceMessage(string message, int[] index)
		{
			StringBuilder stringBuilder = new StringBuilder(10);
			stringBuilder.Append("[");
			for (int i = 0; i < index.Length; i++)
			{
				stringBuilder.Append(index[i]);
				if (i != index.Length - 1)
				{
					stringBuilder.Append(",");
				}
			}
			stringBuilder.Append("]");
		}

		private object GetNext(out long objID)
		{
			if (m_objectQueue.Count == 0)
			{
				objID = 0L;
				return null;
			}
			object obj = m_objectQueue.Dequeue();
			object obj2 = null;
			obj2 = ((!(obj is WriteObjectInfo)) ? obj : ((WriteObjectInfo)obj).obj);
			objID = m_idGenerator.HasId(obj2, out var firstTime);
			if (firstTime)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ObjNoID"), obj));
			}
			return obj;
		}

		private long InternalGetId(object obj, Type type, out bool isNew)
		{
			if (obj == previousObj)
			{
				isNew = false;
				return previousId;
			}
			if (type.IsValueType)
			{
				isNew = false;
				previousObj = obj;
				previousId = -1L;
				return -1L;
			}
			long id = m_idGenerator.GetId(obj, out isNew);
			previousObj = obj;
			previousId = id;
			return id;
		}

		private long Schedule(object obj, Type type)
		{
			return Schedule(obj, type, null);
		}

		private long Schedule(object obj, Type type, WriteObjectInfo objectInfo)
		{
			if (obj == null)
			{
				return 0L;
			}
			bool isNew;
			long result = InternalGetId(obj, type, out isNew);
			if (isNew)
			{
				if (objectInfo == null)
				{
					m_objectQueue.Enqueue(obj);
				}
				else
				{
					m_objectQueue.Enqueue(objectInfo);
				}
			}
			return result;
		}

		private bool WriteKnownValueClass(NameInfo memberNameInfo, NameInfo typeNameInfo, object data, bool isAttribute)
		{
			if (typeNameInfo.NItype == Converter.typeofString)
			{
				if (isAttribute)
				{
					serWriter.WriteAttributeValue(memberNameInfo, typeNameInfo, (string)data);
				}
				else
				{
					WriteString(memberNameInfo, typeNameInfo, data);
				}
			}
			else
			{
				if (typeNameInfo.NIprimitiveTypeEnum == InternalPrimitiveTypeE.Invalid)
				{
					return false;
				}
				if (typeNameInfo.NIisArray)
				{
					serWriter.WriteItem(memberNameInfo, typeNameInfo, data);
				}
				else if (isAttribute)
				{
					serWriter.WriteAttributeValue(memberNameInfo, typeNameInfo, data);
				}
				else
				{
					serWriter.WriteMember(memberNameInfo, typeNameInfo, data);
				}
			}
			return true;
		}

		private void WriteObjectRef(NameInfo nameInfo, NameInfo typeNameInfo, long objectId)
		{
			serWriter.WriteMemberObjectRef(nameInfo, typeNameInfo, (int)objectId);
		}

		private void WriteString(NameInfo memberNameInfo, NameInfo typeNameInfo, object stringObject)
		{
			bool isNew = true;
			long num = -1L;
			if (!CheckTypeFormat(formatterEnums.FEtypeFormat, FormatterTypeStyle.XsdString))
			{
				num = InternalGetId(stringObject, typeNameInfo.NItype, out isNew);
			}
			typeNameInfo.NIobjectId = num;
			if (isNew || num < 0)
			{
				if (typeNameInfo.NIisArray)
				{
					serWriter.WriteItemString(memberNameInfo, typeNameInfo, (string)stringObject);
				}
				else
				{
					serWriter.WriteMemberString(memberNameInfo, typeNameInfo, (string)stringObject);
				}
			}
			else
			{
				WriteObjectRef(memberNameInfo, typeNameInfo, num);
			}
		}

		private bool CheckForNull(WriteObjectInfo objectInfo, NameInfo memberNameInfo, NameInfo typeNameInfo, object data)
		{
			bool flag = false;
			if (data == null)
			{
				flag = true;
			}
			if (flag)
			{
				if (typeNameInfo.NItype.IsArray)
				{
					ArrayNameToDisplayName(objectInfo, typeNameInfo);
				}
				if (typeNameInfo.NIisArrayItem)
				{
					serWriter.WriteNullItem(memberNameInfo, typeNameInfo);
				}
				else
				{
					serWriter.WriteNullMember(memberNameInfo, typeNameInfo);
				}
			}
			return flag;
		}

		private void WriteSerializedStreamHeader(long topId, long headerId)
		{
			serWriter.WriteSerializationHeader((int)topId, (int)headerId, 1, 0);
		}

		private NameInfo TypeToNameInfo(Type type, WriteObjectInfo objectInfo, InternalPrimitiveTypeE code, NameInfo nameInfo)
		{
			if (nameInfo == null)
			{
				nameInfo = GetNameInfo();
			}
			else
			{
				nameInfo.Init();
			}
			nameInfo.NIisSealed = type.IsSealed;
			string typeName = null;
			nameInfo.NInameSpaceEnum = Converter.GetNameSpaceEnum(code, type, objectInfo, out typeName);
			nameInfo.NIprimitiveTypeEnum = code;
			nameInfo.NItype = type;
			nameInfo.NIname = typeName;
			if (objectInfo != null)
			{
				nameInfo.NIattributeInfo = objectInfo.typeAttributeInfo;
				nameInfo.NIassemId = objectInfo.assemId;
			}
			switch (nameInfo.NInameSpaceEnum)
			{
			case InternalNameSpaceE.XdrString:
				nameInfo.NIname = "string";
				break;
			case InternalNameSpaceE.UrtUser:
				if (type.Module.Assembly == Converter.urtAssembly)
				{
				}
				break;
			}
			return nameInfo;
		}

		private NameInfo TypeToNameInfo(Type type)
		{
			return TypeToNameInfo(type, null, Converter.ToCode(type), null);
		}

		private NameInfo TypeToNameInfo(WriteObjectInfo objectInfo)
		{
			return TypeToNameInfo(objectInfo.objectType, objectInfo, Converter.ToCode(objectInfo.objectType), null);
		}

		private NameInfo TypeToNameInfo(WriteObjectInfo objectInfo, NameInfo nameInfo)
		{
			return TypeToNameInfo(objectInfo.objectType, objectInfo, Converter.ToCode(objectInfo.objectType), nameInfo);
		}

		private void TypeToNameInfo(Type type, NameInfo nameInfo)
		{
			TypeToNameInfo(type, null, Converter.ToCode(type), nameInfo);
		}

		private NameInfo ArrayTypeToNameInfo(WriteObjectInfo objectInfo, out NameInfo arrayElemTypeNameInfo)
		{
			NameInfo nameInfo = TypeToNameInfo(objectInfo);
			arrayElemTypeNameInfo = TypeToNameInfo(objectInfo.arrayElemObjectInfo);
			ArrayNameToDisplayName(objectInfo, arrayElemTypeNameInfo);
			nameInfo.NInameSpaceEnum = arrayElemTypeNameInfo.NInameSpaceEnum;
			arrayElemTypeNameInfo.NIisArray = arrayElemTypeNameInfo.NItype.IsArray;
			return nameInfo;
		}

		private NameInfo MemberToNameInfo(string name)
		{
			NameInfo nameInfo = GetNameInfo();
			nameInfo.NInameSpaceEnum = InternalNameSpaceE.MemberName;
			nameInfo.NIname = name;
			return nameInfo;
		}

		private void ArrayNameToDisplayName(WriteObjectInfo objectInfo, NameInfo arrayElemTypeNameInfo)
		{
			string nIname = arrayElemTypeNameInfo.NIname;
			int num = nIname.IndexOf('[');
			if (num > 0)
			{
				string text = nIname.Substring(0, num);
				InternalPrimitiveTypeE internalPrimitiveTypeE = Converter.ToCode(text);
				string text2 = null;
				bool flag = false;
				switch (internalPrimitiveTypeE)
				{
				case InternalPrimitiveTypeE.Char:
					text2 = text;
					arrayElemTypeNameInfo.NInameSpaceEnum = InternalNameSpaceE.UrtSystem;
					break;
				default:
				{
					flag = true;
					text2 = Converter.ToXmlDataType(internalPrimitiveTypeE);
					string typeName = null;
					arrayElemTypeNameInfo.NInameSpaceEnum = Converter.GetNameSpaceEnum(internalPrimitiveTypeE, null, objectInfo, out typeName);
					break;
				}
				case InternalPrimitiveTypeE.Invalid:
					if (text.Equals("String") || text.Equals("System.String"))
					{
						flag = true;
						text2 = "string";
						arrayElemTypeNameInfo.NInameSpaceEnum = InternalNameSpaceE.XdrString;
					}
					else if (text.Equals("System.Object"))
					{
						flag = true;
						text2 = "anyType";
						arrayElemTypeNameInfo.NInameSpaceEnum = InternalNameSpaceE.XdrPrimitive;
					}
					else
					{
						text2 = text;
					}
					break;
				}
				if (flag)
				{
					arrayElemTypeNameInfo.NIname = text2 + nIname.Substring(num);
				}
			}
			else if (nIname.Equals("System.Object"))
			{
				arrayElemTypeNameInfo.NIname = "anyType";
				arrayElemTypeNameInfo.NInameSpaceEnum = InternalNameSpaceE.XdrPrimitive;
			}
		}

		private long GetAssemblyId(WriteObjectInfo objectInfo)
		{
			long num = 0L;
			bool firstTime = false;
			string assemblyString = objectInfo.GetAssemblyString();
			string assemName = assemblyString;
			if (assemblyString.Length == 0)
			{
				num = 0L;
			}
			else if (assemblyString.Equals(Converter.urtAssemblyString))
			{
				num = 0L;
				firstTime = false;
				serWriter.WriteAssembly(objectInfo.GetTypeFullName(), objectInfo.objectType, null, (int)num, firstTime, objectInfo.IsAttributeNameSpace());
			}
			else
			{
				if (assemblyToIdTable.ContainsKey(assemblyString))
				{
					num = (long)assemblyToIdTable[assemblyString];
					firstTime = false;
				}
				else
				{
					num = m_idGenerator.GetId("___AssemblyString___" + assemblyString, out firstTime);
					assemblyToIdTable[assemblyString] = num;
				}
				if (assemblyString != null && !objectInfo.IsInteropNameSpace() && formatterEnums.FEassemblyFormat == FormatterAssemblyStyle.Simple)
				{
					int num2 = assemblyString.IndexOf(',');
					if (num2 > 0)
					{
						assemName = assemblyString.Substring(0, num2);
					}
				}
				serWriter.WriteAssembly(objectInfo.GetTypeFullName(), objectInfo.objectType, assemName, (int)num, firstTime, objectInfo.IsInteropNameSpace());
			}
			return num;
		}

		private bool IsEmbeddedAttribute(Type type)
		{
			bool flag = false;
			if (type.IsValueType)
			{
				return true;
			}
			SoapTypeAttribute soapTypeAttribute = (SoapTypeAttribute)InternalRemotingServices.GetCachedSoapAttribute(type);
			return soapTypeAttribute.Embedded;
		}

		private void WriteEnum(NameInfo memberNameInfo, NameInfo typeNameInfo, object data, bool isAttribute)
		{
			if (isAttribute)
			{
				serWriter.WriteAttributeValue(memberNameInfo, typeNameInfo, ((Enum)data).ToString());
			}
			else
			{
				serWriter.WriteMember(memberNameInfo, typeNameInfo, ((Enum)data).ToString());
			}
		}

		private Type GetType(object obj)
		{
			Type type = null;
			if (RemotingServices.IsTransparentProxy(obj))
			{
				return Converter.typeofMarshalByRefObject;
			}
			return obj.GetType();
		}

		private NameInfo GetNameInfo()
		{
			NameInfo nameInfo = null;
			if (!niPool.IsEmpty())
			{
				nameInfo = (NameInfo)niPool.Pop();
				nameInfo.Init();
			}
			else
			{
				nameInfo = new NameInfo();
			}
			return nameInfo;
		}

		private bool CheckTypeFormat(FormatterTypeStyle test, FormatterTypeStyle want)
		{
			return (test & want) == want;
		}

		private void PutNameInfo(NameInfo nameInfo)
		{
			niPool.Push(nameInfo);
		}
	}
	internal sealed class WriteObjectInfo
	{
		internal int objectInfoId;

		internal object obj;

		internal Type objectType;

		internal bool isSi;

		internal bool isNamed;

		internal bool isTyped;

		internal SerializationInfo si;

		internal SerObjectInfoCache cache;

		internal object[] memberData;

		internal ISerializationSurrogate serializationSurrogate;

		internal ISurrogateSelector surrogateSelector;

		internal IFormatterConverter converter;

		internal StreamingContext context;

		internal SerObjectInfoInit serObjectInfoInit;

		internal long objectId;

		internal long assemId;

		private int lastPosition;

		private SoapAttributeInfo parentMemberAttributeInfo;

		internal bool isArray;

		internal SoapAttributeInfo typeAttributeInfo;

		internal WriteObjectInfo arrayElemObjectInfo;

		internal WriteObjectInfo()
		{
		}

		internal void ObjectEnd()
		{
			PutObjectInfo(serObjectInfoInit, this);
		}

		private void InternalInit()
		{
			obj = null;
			objectType = null;
			isSi = false;
			isNamed = false;
			isTyped = false;
			si = null;
			cache = null;
			memberData = null;
			isArray = false;
			objectId = 0L;
			assemId = 0L;
			lastPosition = 0;
			typeAttributeInfo = null;
			parentMemberAttributeInfo = null;
			arrayElemObjectInfo = null;
		}

		internal static WriteObjectInfo Serialize(object obj, ISurrogateSelector surrogateSelector, StreamingContext context, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, SoapAttributeInfo attributeInfo, ObjectWriter objectWriter)
		{
			WriteObjectInfo objectInfo = GetObjectInfo(serObjectInfoInit);
			objectInfo.InitSerialize(obj, surrogateSelector, context, serObjectInfoInit, converter, attributeInfo, objectWriter);
			return objectInfo;
		}

		internal void InitSerialize(object obj, ISurrogateSelector surrogateSelector, StreamingContext context, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, SoapAttributeInfo attributeInfo, ObjectWriter objectWriter)
		{
			this.context = context;
			this.obj = obj;
			this.serObjectInfoInit = serObjectInfoInit;
			parentMemberAttributeInfo = attributeInfo;
			this.surrogateSelector = surrogateSelector;
			this.converter = converter;
			if (RemotingServices.IsTransparentProxy(obj))
			{
				objectType = Converter.typeofMarshalByRefObject;
			}
			else
			{
				objectType = obj.GetType();
			}
			if (objectType.IsArray)
			{
				arrayElemObjectInfo = Serialize(objectType.GetElementType(), surrogateSelector, context, serObjectInfoInit, converter, null);
				typeAttributeInfo = GetTypeAttributeInfo();
				isArray = true;
				InitNoMembers();
				return;
			}
			typeAttributeInfo = GetTypeAttributeInfo();
			objectWriter.ObjectManager.RegisterObject(obj);
			if (surrogateSelector != null && (serializationSurrogate = surrogateSelector.GetSurrogate(objectType, context, out var _)) != null)
			{
				si = new SerializationInfo(objectType, converter);
				if (!objectType.IsPrimitive)
				{
					serializationSurrogate.GetObjectData(obj, si, context);
				}
				InitSiWrite(objectWriter);
			}
			else if (obj is ISerializable)
			{
				if (!objectType.IsSerializable)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_NonSerType"), objectType.FullName, objectType.Module.Assembly.FullName));
				}
				si = new SerializationInfo(objectType, converter);
				((ISerializable)obj).GetObjectData(si, context);
				InitSiWrite(objectWriter);
			}
			else
			{
				InitMemberInfo();
			}
		}

		[Conditional("SER_LOGGING")]
		private void DumpMemberInfo()
		{
			for (int i = 0; i < cache.memberInfos.Length; i++)
			{
			}
		}

		internal static WriteObjectInfo Serialize(Type objectType, ISurrogateSelector surrogateSelector, StreamingContext context, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, SoapAttributeInfo attributeInfo)
		{
			WriteObjectInfo objectInfo = GetObjectInfo(serObjectInfoInit);
			objectInfo.InitSerialize(objectType, surrogateSelector, context, serObjectInfoInit, converter, attributeInfo);
			return objectInfo;
		}

		internal void InitSerialize(Type objectType, ISurrogateSelector surrogateSelector, StreamingContext context, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, SoapAttributeInfo attributeInfo)
		{
			this.objectType = objectType;
			this.context = context;
			this.serObjectInfoInit = serObjectInfoInit;
			parentMemberAttributeInfo = attributeInfo;
			this.surrogateSelector = surrogateSelector;
			this.converter = converter;
			if (objectType.IsArray)
			{
				arrayElemObjectInfo = Serialize(objectType.GetElementType(), surrogateSelector, context, serObjectInfoInit, converter, null);
				typeAttributeInfo = GetTypeAttributeInfo();
				InitNoMembers();
				return;
			}
			typeAttributeInfo = GetTypeAttributeInfo();
			ISurrogateSelector selector = null;
			if (surrogateSelector != null)
			{
				serializationSurrogate = surrogateSelector.GetSurrogate(objectType, context, out selector);
			}
			if (serializationSurrogate != null)
			{
				isSi = true;
			}
			else if (objectType != Converter.typeofObject && Converter.typeofISerializable.IsAssignableFrom(objectType))
			{
				isSi = true;
			}
			if (isSi)
			{
				si = new SerializationInfo(objectType, converter);
				cache = new SerObjectInfoCache();
				cache.fullTypeName = si.FullTypeName;
				cache.assemblyString = si.AssemblyName;
			}
			else
			{
				InitMemberInfo();
			}
		}

		private void InitSiWrite(ObjectWriter objectWriter)
		{
			if (si.FullTypeName.Equals("FormatterWrapper"))
			{
				obj = si.GetValue("__WrappedObject", Converter.typeofObject);
				InitSerialize(obj, surrogateSelector, context, serObjectInfoInit, converter, null, objectWriter);
				return;
			}
			SerializationInfoEnumerator serializationInfoEnumerator = null;
			isSi = true;
			serializationInfoEnumerator = si.GetEnumerator();
			int num = 0;
			num = si.MemberCount;
			int num2 = num;
			cache = new SerObjectInfoCache();
			cache.memberNames = new string[num2];
			cache.memberTypes = new Type[num2];
			memberData = new object[num2];
			cache.fullTypeName = si.FullTypeName;
			cache.assemblyString = si.AssemblyName;
			serializationInfoEnumerator = si.GetEnumerator();
			int num3 = 0;
			while (serializationInfoEnumerator.MoveNext())
			{
				cache.memberNames[num3] = serializationInfoEnumerator.Name;
				cache.memberTypes[num3] = serializationInfoEnumerator.ObjectType;
				memberData[num3] = serializationInfoEnumerator.Value;
				num3++;
			}
			isNamed = true;
			isTyped = false;
		}

		private void InitNoMembers()
		{
			cache = (SerObjectInfoCache)serObjectInfoInit.seenBeforeTable[objectType];
			if (cache == null)
			{
				cache = new SerObjectInfoCache();
				cache.fullTypeName = objectType.FullName;
				cache.assemblyString = objectType.Module.Assembly.FullName;
				serObjectInfoInit.seenBeforeTable.Add(objectType, cache);
			}
		}

		private void InitMemberInfo()
		{
			cache = (SerObjectInfoCache)serObjectInfoInit.seenBeforeTable[objectType];
			if (cache == null)
			{
				cache = new SerObjectInfoCache();
				int num = 0;
				if (!objectType.IsByRef)
				{
					cache.memberInfos = FormatterServices.GetSerializableMembers(objectType, context);
					num = cache.memberInfos.Length;
				}
				cache.memberNames = new string[num];
				cache.memberTypes = new Type[num];
				cache.memberAttributeInfos = new SoapAttributeInfo[num];
				for (int i = 0; i < num; i++)
				{
					cache.memberNames[i] = cache.memberInfos[i].Name;
					cache.memberTypes[i] = GetMemberType(cache.memberInfos[i]);
					cache.memberAttributeInfos[i] = Attr.GetMemberAttributeInfo(cache.memberInfos[i], cache.memberNames[i], cache.memberTypes[i]);
				}
				cache.fullTypeName = objectType.FullName;
				cache.assemblyString = objectType.Module.Assembly.FullName;
				serObjectInfoInit.seenBeforeTable.Add(objectType, cache);
			}
			if (obj != null)
			{
				memberData = FormatterServices.GetObjectData(obj, cache.memberInfos);
			}
			isTyped = true;
			isNamed = true;
		}

		internal string GetTypeFullName()
		{
			return cache.fullTypeName;
		}

		internal string GetAssemblyString()
		{
			string text = null;
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.GetAssemblyString();
			}
			if (IsAttributeNameSpace())
			{
				return typeAttributeInfo.m_nameSpace;
			}
			return cache.assemblyString;
		}

		internal Type GetMemberType(MemberInfo objMember)
		{
			Type type = null;
			if (objMember is FieldInfo)
			{
				return ((FieldInfo)objMember).FieldType;
			}
			if (objMember is PropertyInfo)
			{
				return ((PropertyInfo)objMember).PropertyType;
			}
			throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_SerMemberInfo"), objMember.GetType()));
		}

		internal void GetMemberInfo(out string[] outMemberNames, out Type[] outMemberTypes, out object[] outMemberData, out SoapAttributeInfo[] outAttributeInfo)
		{
			outMemberNames = cache.memberNames;
			outMemberTypes = cache.memberTypes;
			outMemberData = memberData;
			outAttributeInfo = cache.memberAttributeInfos;
			if (isSi && !isNamed)
			{
				throw new SerializationException(SoapUtil.GetResourceString("Serialization_ISerializableMemberInfo"));
			}
		}

		private static WriteObjectInfo GetObjectInfo(SerObjectInfoInit serObjectInfoInit)
		{
			WriteObjectInfo writeObjectInfo = null;
			if (!serObjectInfoInit.oiPool.IsEmpty())
			{
				writeObjectInfo = (WriteObjectInfo)serObjectInfoInit.oiPool.Pop();
				writeObjectInfo.InternalInit();
			}
			else
			{
				writeObjectInfo = new WriteObjectInfo();
				writeObjectInfo.objectInfoId = serObjectInfoInit.objectInfoIdCount++;
			}
			return writeObjectInfo;
		}

		private int Position(string name)
		{
			if (cache.memberNames[lastPosition].Equals(name))
			{
				return lastPosition;
			}
			if (++lastPosition < cache.memberNames.Length && cache.memberNames[lastPosition].Equals(name))
			{
				return lastPosition;
			}
			for (int i = 0; i < cache.memberNames.Length; i++)
			{
				if (cache.memberNames[i].Equals(name))
				{
					lastPosition = i;
					return lastPosition;
				}
			}
			throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Position"), string.Concat(objectType, " ", name)));
		}

		private static void PutObjectInfo(SerObjectInfoInit serObjectInfoInit, WriteObjectInfo objectInfo)
		{
			serObjectInfoInit.oiPool.Push(objectInfo);
		}

		internal bool IsInteropNameSpace()
		{
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.IsInteropNameSpace();
			}
			if (IsAttributeNameSpace() || IsCallElement())
			{
				return true;
			}
			return false;
		}

		internal bool IsCallElement()
		{
			if ((objectType != Converter.typeofObject && Converter.typeofIMethodCallMessage.IsAssignableFrom(objectType) && !Converter.typeofIConstructionCallMessage.IsAssignableFrom(objectType)) || objectType == Converter.typeofReturnMessage || objectType == Converter.typeofInternalSoapMessage)
			{
				return true;
			}
			return false;
		}

		internal bool IsCustomXmlAttribute()
		{
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.IsCustomXmlAttribute();
			}
			if (typeAttributeInfo != null && (typeAttributeInfo.m_attributeType & SoapAttributeType.XmlAttribute) != 0)
			{
				return true;
			}
			return false;
		}

		internal bool IsCustomXmlElement()
		{
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.IsCustomXmlElement();
			}
			if (typeAttributeInfo != null && (typeAttributeInfo.m_attributeType & SoapAttributeType.XmlElement) != 0)
			{
				return true;
			}
			return false;
		}

		internal bool IsAttributeNameSpace()
		{
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.IsAttributeNameSpace();
			}
			if (typeAttributeInfo != null && typeAttributeInfo.m_nameSpace != null)
			{
				return true;
			}
			return false;
		}

		private SoapAttributeInfo GetTypeAttributeInfo()
		{
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.GetTypeAttributeInfo();
			}
			SoapAttributeInfo soapAttributeInfo = null;
			soapAttributeInfo = ((parentMemberAttributeInfo == null) ? new SoapAttributeInfo() : parentMemberAttributeInfo);
			Attr.ProcessTypeAttribute(objectType, soapAttributeInfo);
			return soapAttributeInfo;
		}

		internal bool IsEmbeddedAttribute(string name)
		{
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.IsEmbeddedAttribute(name);
			}
			bool result = false;
			if (cache.memberAttributeInfos != null && cache.memberAttributeInfos.Length > 0)
			{
				SoapAttributeInfo soapAttributeInfo = cache.memberAttributeInfos[Position(name)];
				result = soapAttributeInfo.IsEmbedded();
			}
			return result;
		}
	}
	internal sealed class ReadObjectInfo
	{
		internal int objectInfoId;

		internal object obj;

		internal Type objectType;

		internal ObjectManager objectManager;

		internal int count;

		internal bool isSi;

		internal bool isNamed;

		internal bool isTyped;

		internal SerializationInfo si;

		internal SerObjectInfoCache cache;

		internal string[] wireMemberNames;

		internal Type[] wireMemberTypes;

		internal object[] memberData;

		internal string[] memberNames;

		private int lastPosition;

		internal ISurrogateSelector surrogateSelector;

		internal ISerializationSurrogate serializationSurrogate;

		internal StreamingContext context;

		internal ArrayList memberTypesList;

		internal SerObjectInfoInit serObjectInfoInit;

		internal IFormatterConverter formatterConverter;

		internal bool bfake;

		internal bool bSoapFault;

		internal ArrayList paramNameList;

		private int majorVersion;

		private int minorVersion;

		internal SoapAttributeInfo typeAttributeInfo;

		private ReadObjectInfo arrayElemObjectInfo;

		private int numberMembersSeen;

		internal ReadObjectInfo()
		{
		}

		internal void ObjectEnd()
		{
			PutObjectInfo(serObjectInfoInit, this);
		}

		private void InternalInit()
		{
			obj = null;
			objectType = null;
			count = 0;
			isSi = false;
			isNamed = false;
			isTyped = false;
			si = null;
			wireMemberNames = null;
			wireMemberTypes = null;
			cache = null;
			lastPosition = 0;
			numberMembersSeen = 0;
			bfake = false;
			bSoapFault = false;
			majorVersion = 0;
			minorVersion = 0;
			typeAttributeInfo = null;
			arrayElemObjectInfo = null;
			if (memberTypesList != null)
			{
				memberTypesList.Clear();
			}
		}

		internal static ReadObjectInfo Create(Type objectType, ISurrogateSelector surrogateSelector, StreamingContext context, ObjectManager objectManager, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, string assemblyName)
		{
			ReadObjectInfo objectInfo = GetObjectInfo(serObjectInfoInit);
			objectInfo.Init(objectType, surrogateSelector, context, objectManager, serObjectInfoInit, converter, assemblyName);
			return objectInfo;
		}

		internal void Init(Type objectType, ISurrogateSelector surrogateSelector, StreamingContext context, ObjectManager objectManager, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, string assemblyName)
		{
			this.objectType = objectType;
			this.objectManager = objectManager;
			this.context = context;
			this.serObjectInfoInit = serObjectInfoInit;
			formatterConverter = converter;
			InitReadConstructor(objectType, surrogateSelector, context, assemblyName);
		}

		internal static ReadObjectInfo Create(Type objectType, string[] memberNames, Type[] memberTypes, ISurrogateSelector surrogateSelector, StreamingContext context, ObjectManager objectManager, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, string assemblyName)
		{
			ReadObjectInfo objectInfo = GetObjectInfo(serObjectInfoInit);
			objectInfo.Init(objectType, memberNames, memberTypes, surrogateSelector, context, objectManager, serObjectInfoInit, converter, assemblyName);
			return objectInfo;
		}

		internal void Init(Type objectType, string[] memberNames, Type[] memberTypes, ISurrogateSelector surrogateSelector, StreamingContext context, ObjectManager objectManager, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, string assemblyName)
		{
			this.objectType = objectType;
			this.objectManager = objectManager;
			wireMemberNames = memberNames;
			wireMemberTypes = memberTypes;
			this.context = context;
			this.serObjectInfoInit = serObjectInfoInit;
			formatterConverter = converter;
			if (memberNames != null)
			{
				isNamed = true;
			}
			if (memberTypes != null)
			{
				isTyped = true;
			}
			InitReadConstructor(objectType, surrogateSelector, context, assemblyName);
		}

		private void InitReadConstructor(Type objectType, ISurrogateSelector surrogateSelector, StreamingContext context, string assemblyName)
		{
			if (objectType.IsArray)
			{
				arrayElemObjectInfo = Create(objectType.GetElementType(), surrogateSelector, context, objectManager, serObjectInfoInit, formatterConverter, assemblyName);
				typeAttributeInfo = GetTypeAttributeInfo();
				InitNoMembers();
				return;
			}
			ISurrogateSelector selector = null;
			if (surrogateSelector != null)
			{
				serializationSurrogate = surrogateSelector.GetSurrogate(objectType, context, out selector);
			}
			if (serializationSurrogate != null)
			{
				isSi = true;
			}
			else if (objectType != Converter.typeofObject && Converter.typeofISerializable.IsAssignableFrom(objectType))
			{
				isSi = true;
			}
			if (isSi)
			{
				si = new SerializationInfo(objectType, formatterConverter);
				InitSiRead(assemblyName);
			}
			else
			{
				InitMemberInfo();
			}
		}

		private void InitSiRead(string assemblyName)
		{
			if (assemblyName != null)
			{
				si.AssemblyName = assemblyName;
			}
			cache = new SerObjectInfoCache();
			cache.fullTypeName = si.FullTypeName;
			cache.assemblyString = si.AssemblyName;
			cache.memberNames = wireMemberNames;
			cache.memberTypes = wireMemberTypes;
			if (memberTypesList != null)
			{
				memberTypesList = new ArrayList(20);
			}
			if (wireMemberNames != null && wireMemberTypes != null)
			{
				isTyped = true;
			}
		}

		private void InitNoMembers()
		{
			cache = (SerObjectInfoCache)serObjectInfoInit.seenBeforeTable[objectType];
			if (cache == null)
			{
				cache = new SerObjectInfoCache();
				cache.fullTypeName = objectType.FullName;
				cache.assemblyString = objectType.Module.Assembly.FullName;
				serObjectInfoInit.seenBeforeTable.Add(objectType, cache);
			}
		}

		private void InitMemberInfo()
		{
			cache = (SerObjectInfoCache)serObjectInfoInit.seenBeforeTable[objectType];
			if (cache == null)
			{
				cache = new SerObjectInfoCache();
				cache.memberInfos = FormatterServices.GetSerializableMembers(objectType, context);
				count = cache.memberInfos.Length;
				cache.memberNames = new string[count];
				cache.memberTypes = new Type[count];
				cache.memberAttributeInfos = new SoapAttributeInfo[count];
				for (int i = 0; i < count; i++)
				{
					cache.memberNames[i] = cache.memberInfos[i].Name;
					cache.memberTypes[i] = GetMemberType(cache.memberInfos[i]);
					cache.memberAttributeInfos[i] = Attr.GetMemberAttributeInfo(cache.memberInfos[i], cache.memberNames[i], cache.memberTypes[i]);
				}
				cache.fullTypeName = objectType.FullName;
				cache.assemblyString = objectType.Module.Assembly.FullName;
				serObjectInfoInit.seenBeforeTable.Add(objectType, cache);
			}
			memberData = new object[cache.memberNames.Length];
			memberNames = new string[cache.memberNames.Length];
			isTyped = true;
			isNamed = true;
		}

		internal MemberInfo GetMemberInfo(string name)
		{
			if (isSi)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_MemberInfo"), string.Concat(objectType, " ", name)));
			}
			if (cache.memberInfos == null)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_NoMemberInfo"), string.Concat(objectType, " ", name)));
			}
			return cache.memberInfos[Position(name)];
		}

		internal Type GetMemberType(MemberInfo objMember)
		{
			Type type = null;
			if (objMember is FieldInfo)
			{
				return ((FieldInfo)objMember).FieldType;
			}
			if (objMember is PropertyInfo)
			{
				return ((PropertyInfo)objMember).PropertyType;
			}
			throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_SerMemberInfo"), objMember.GetType()));
		}

		internal Type GetType(string name)
		{
			Type type = null;
			type = ((!isTyped) ? ((Type)memberTypesList[Position(name)]) : cache.memberTypes[Position(name)]);
			if (type == null)
			{
				throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ISerializableTypes"), string.Concat(objectType, " ", name)));
			}
			return type;
		}

		internal Type GetType(int position)
		{
			Type result = null;
			if (isTyped)
			{
				if (position >= cache.memberTypes.Length)
				{
					throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_ISerializableTypes"), string.Concat(objectType, " ", position)));
				}
				result = cache.memberTypes[position];
			}
			return result;
		}

		internal void AddParamName(string name)
		{
			if (!bfake)
			{
				return;
			}
			if (name[0] == '_' && name[1] == '_')
			{
				switch (name)
				{
				case "__fault":
					bSoapFault = true;
					return;
				case "__methodName":
					return;
				case "__keyToNamespaceTable":
					return;
				case "__paramNameList":
					return;
				case "__xmlNameSpace":
					return;
				}
			}
			paramNameList.Add(name);
		}

		internal void AddValue(string name, object value)
		{
			if (isSi)
			{
				if (bfake)
				{
					AddParamName(name);
				}
				si.AddValue(name, value);
			}
			else
			{
				int num = Position(name);
				memberData[num] = value;
				memberNames[num] = name;
			}
		}

		internal void AddMemberSeen()
		{
			numberMembersSeen++;
		}

		internal ArrayList SetFakeObject()
		{
			bfake = true;
			paramNameList = new ArrayList(10);
			return paramNameList;
		}

		internal void SetVersion(int major, int minor)
		{
			majorVersion = major;
			minorVersion = minor;
		}

		internal void RecordFixup(long objectId, string name, long idRef)
		{
			if (isSi)
			{
				objectManager.RecordDelayedFixup(objectId, name, idRef);
			}
			else
			{
				objectManager.RecordFixup(objectId, cache.memberInfos[Position(name)], idRef);
			}
		}

		internal void PopulateObjectMembers()
		{
			if (isSi)
			{
				return;
			}
			MemberInfo[] array = null;
			object[] array2 = null;
			int num = 0;
			if (numberMembersSeen < memberNames.Length)
			{
				array = new MemberInfo[numberMembersSeen];
				array2 = new object[numberMembersSeen];
				for (int i = 0; i < memberNames.Length; i++)
				{
					if (memberNames[i] == null)
					{
						object[] customAttributes = cache.memberInfos[i].GetCustomAttributes(typeof(OptionalFieldAttribute), inherit: false);
						if ((customAttributes == null || customAttributes.Length == 0) && majorVersion >= 1 && minorVersion >= 0)
						{
							throw new SerializationException(SoapUtil.GetResourceString("Serialization_WrongNumberOfMembers", objectType, cache.memberInfos.Length, numberMembersSeen));
						}
						continue;
					}
					if (memberNames[i] != cache.memberInfos[i].Name)
					{
						throw new SerializationException(SoapUtil.GetResourceString("Serialization_WrongNumberOfMembers", objectType, cache.memberInfos.Length, numberMembersSeen));
					}
					array[num] = cache.memberInfos[i];
					array2[num] = memberData[i];
					num++;
				}
			}
			else
			{
				array = cache.memberInfos;
				array2 = memberData;
			}
			FormatterServices.PopulateObjectMembers(obj, array, array2);
			numberMembersSeen = 0;
		}

		[Conditional("SER_LOGGING")]
		private void DumpPopulate(MemberInfo[] memberInfos, object[] memberData)
		{
			for (int i = 0; i < memberInfos.Length; i++)
			{
			}
		}

		[Conditional("SER_LOGGING")]
		private void DumpPopulateSi()
		{
			SerializationInfoEnumerator enumerator = si.GetEnumerator();
			int num = 0;
			while (enumerator.MoveNext())
			{
				num++;
			}
		}

		private int Position(string name)
		{
			if (cache.memberNames[lastPosition].Equals(name))
			{
				return lastPosition;
			}
			if (++lastPosition < cache.memberNames.Length && cache.memberNames[lastPosition].Equals(name))
			{
				return lastPosition;
			}
			for (int i = 0; i < cache.memberNames.Length; i++)
			{
				if (cache.memberNames[i].Equals(name))
				{
					lastPosition = i;
					return lastPosition;
				}
			}
			throw new SerializationException(string.Format(CultureInfo.CurrentCulture, SoapUtil.GetResourceString("Serialization_Position"), string.Concat(objectType, " ", name)));
		}

		private static ReadObjectInfo GetObjectInfo(SerObjectInfoInit serObjectInfoInit)
		{
			ReadObjectInfo readObjectInfo = null;
			if (!serObjectInfoInit.oiPool.IsEmpty())
			{
				readObjectInfo = (ReadObjectInfo)serObjectInfoInit.oiPool.Pop();
				readObjectInfo.InternalInit();
			}
			else
			{
				readObjectInfo = new ReadObjectInfo();
				readObjectInfo.objectInfoId = serObjectInfoInit.objectInfoIdCount++;
			}
			return readObjectInfo;
		}

		private static void PutObjectInfo(SerObjectInfoInit serObjectInfoInit, ReadObjectInfo objectInfo)
		{
			serObjectInfoInit.oiPool.Push(objectInfo);
		}

		private SoapAttributeInfo GetTypeAttributeInfo()
		{
			if (arrayElemObjectInfo != null)
			{
				return arrayElemObjectInfo.GetTypeAttributeInfo();
			}
			SoapAttributeInfo soapAttributeInfo = null;
			soapAttributeInfo = new SoapAttributeInfo();
			Attr.ProcessTypeAttribute(objectType, soapAttributeInfo);
			return soapAttributeInfo;
		}
	}
	internal sealed class SerObjectInfoCache
	{
		internal string fullTypeName;

		internal string assemblyString;

		internal MemberInfo[] memberInfos;

		internal string[] memberNames;

		internal Type[] memberTypes;

		internal SoapAttributeInfo[] memberAttributeInfos;
	}
	internal sealed class SerObjectInfoInit
	{
		internal Hashtable seenBeforeTable = new Hashtable();

		internal int objectInfoIdCount = 1;

		internal SerStack oiPool = new SerStack("SerObjectInfo Pool");
	}
	internal static class Attr
	{
		internal static SoapAttributeInfo GetMemberAttributeInfo(MemberInfo memberInfo, string name, Type type)
		{
			SoapAttributeInfo soapAttributeInfo = new SoapAttributeInfo();
			ProcessTypeAttribute(type, soapAttributeInfo);
			ProcessMemberInfoAttribute(memberInfo, soapAttributeInfo);
			return soapAttributeInfo;
		}

		internal static void ProcessTypeAttribute(Type type, SoapAttributeInfo attributeInfo)
		{
			SoapTypeAttribute soapTypeAttribute = (SoapTypeAttribute)InternalRemotingServices.GetCachedSoapAttribute(type);
			if (soapTypeAttribute.Embedded)
			{
				attributeInfo.m_attributeType |= SoapAttributeType.Embedded;
			}
			if (SoapServices.GetXmlElementForInteropType(type, out var xmlElement, out var xmlNamespace))
			{
				attributeInfo.m_attributeType |= SoapAttributeType.XmlElement;
				attributeInfo.m_elementName = xmlElement;
				attributeInfo.m_nameSpace = xmlNamespace;
			}
			if (SoapServices.GetXmlTypeForInteropType(type, out xmlElement, out xmlNamespace))
			{
				attributeInfo.m_attributeType |= SoapAttributeType.XmlType;
				attributeInfo.m_typeName = xmlElement;
				attributeInfo.m_typeNamespace = xmlNamespace;
			}
		}

		internal static void ProcessMemberInfoAttribute(MemberInfo memberInfo, SoapAttributeInfo attributeInfo)
		{
			SoapAttribute cachedSoapAttribute = InternalRemotingServices.GetCachedSoapAttribute(memberInfo);
			if (cachedSoapAttribute.Embedded)
			{
				attributeInfo.m_attributeType |= SoapAttributeType.Embedded;
			}
			if (cachedSoapAttribute is SoapFieldAttribute)
			{
				SoapFieldAttribute soapFieldAttribute = (SoapFieldAttribute)cachedSoapAttribute;
				if (soapFieldAttribute.UseAttribute)
				{
					attributeInfo.m_attributeType |= SoapAttributeType.XmlAttribute;
					attributeInfo.m_elementName = soapFieldAttribute.XmlElementName;
					attributeInfo.m_nameSpace = soapFieldAttribute.XmlNamespace;
				}
				else if (soapFieldAttribute.IsInteropXmlElement())
				{
					attributeInfo.m_attributeType |= SoapAttributeType.XmlElement;
					attributeInfo.m_elementName = soapFieldAttribute.XmlElementName;
					attributeInfo.m_nameSpace = soapFieldAttribute.XmlNamespace;
				}
			}
		}
	}
}
