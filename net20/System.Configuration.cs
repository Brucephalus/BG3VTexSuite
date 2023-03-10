
// C:\WINDOWS\assembly\GAC_MSIL\System.Configuration\2.0.0.0__b03f5f7f11d50a3a\System.Configuration.dll
// System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: v2.0.50727
// This assembly is signed with a strong name key.
// Hash algorithm: SHA1
// Public key: 002400000480000094000000060200000024000052534131000400000100010007d1fa57c4aed9f0a32e84aa0faefd0de9e8fd6aec8f87fb03766c834c99921eb23be79ad9d5dcc1dd9ad236132102900b723cf980957fc4e177108fc607774f29e8320e92ea05ece4e821c0a5efe8f1645c4c0c93c1ab99285d622caa652c1dfad63d745d6f2de5f17e5eaf0fc4963d261c8a12436518206dc093344d5ad293

using System;
using System.CodeDom.Compiler;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Internal;
using System.Configuration.Provider;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Reflection.Emit;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Permissions;
using System.Security.Policy;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;
using System.Xml;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyTitle("System.Configuration.dll")]
[assembly: CLSCompliant(true)]
[assembly: AssemblyDescription("System.Configuration.dll")]
[assembly: AllowPartiallyTrustedCallers]
[assembly: ComVisible(false)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: NeutralResourcesLanguage("en-US")]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: ComCompatibleVersion(1, 0, 3300, 0)]
[assembly: AssemblyKeyFile("f:\\dd\\Tools\\devdiv\\FinalPublicKey.snk")]
[assembly: AssemblyDelaySign(true)]
[assembly: AssemblyFileVersion("2.0.50727.9153")]
[assembly: SatelliteContractVersion("2.0.0.0")]
[assembly: AssemblyInformationalVersion("2.0.50727.9153")]
[assembly: AssemblyProduct("Microsoft?? .NET Framework")]
[assembly: AssemblyDefaultAlias("System.Configuration.dll")]
[assembly: AssemblyCopyright("?? Microsoft Corporation.  All rights reserved.")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]
[assembly: AssemblyVersion("2.0.0.0")]
[module: UnverifiableCode]
internal static class FXAssembly
{
	internal const string Version = "2.0.0.0";
}
internal static class ThisAssembly
{
	internal const string Title = "System.Configuration.dll";

	internal const string Description = "System.Configuration.dll";

	internal const string DefaultAlias = "System.Configuration.dll";

	internal const string Copyright = "?? Microsoft Corporation.  All rights reserved.";

	internal const string Version = "2.0.0.0";

	internal const string InformationalVersion = "2.0.50727.9153";

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
namespace System.Configuration
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
		internal const string Parameter_Invalid = "Parameter_Invalid";

		internal const string Parameter_NullOrEmpty = "Parameter_NullOrEmpty";

		internal const string Property_NullOrEmpty = "Property_NullOrEmpty";

		internal const string Property_Invalid = "Property_Invalid";

		internal const string Unexpected_Error = "Unexpected_Error";

		internal const string Wrapped_exception_message = "Wrapped_exception_message";

		internal const string Config_error_loading_XML_file = "Config_error_loading_XML_file";

		internal const string Config_exception_creating_section_handler = "Config_exception_creating_section_handler";

		internal const string Config_exception_creating_section = "Config_exception_creating_section";

		internal const string Config_tag_name_invalid = "Config_tag_name_invalid";

		internal const string Argument_AddingDuplicate = "Argument_AddingDuplicate";

		internal const string Config_add_configurationsection_already_added = "Config_add_configurationsection_already_added";

		internal const string Config_add_configurationsection_already_exists = "Config_add_configurationsection_already_exists";

		internal const string Config_add_configurationsection_in_location_config = "Config_add_configurationsection_in_location_config";

		internal const string Config_add_configurationsectiongroup_already_added = "Config_add_configurationsectiongroup_already_added";

		internal const string Config_add_configurationsectiongroup_already_exists = "Config_add_configurationsectiongroup_already_exists";

		internal const string Config_add_configurationsectiongroup_in_location_config = "Config_add_configurationsectiongroup_in_location_config";

		internal const string Config_allow_exedefinition_error_application = "Config_allow_exedefinition_error_application";

		internal const string Config_allow_exedefinition_error_machine = "Config_allow_exedefinition_error_machine";

		internal const string Config_allow_exedefinition_error_roaminguser = "Config_allow_exedefinition_error_roaminguser";

		internal const string Config_appsettings_declaration_invalid = "Config_appsettings_declaration_invalid";

		internal const string Config_base_attribute_locked = "Config_base_attribute_locked";

		internal const string Config_base_collection_item_locked_cannot_clear = "Config_base_collection_item_locked_cannot_clear";

		internal const string Config_base_collection_item_locked = "Config_base_collection_item_locked";

		internal const string Config_base_cannot_add_items_above_inherited_items = "Config_base_cannot_add_items_above_inherited_items";

		internal const string Config_base_cannot_add_items_below_inherited_items = "Config_base_cannot_add_items_below_inherited_items";

		internal const string Config_base_cannot_remove_inherited_items = "Config_base_cannot_remove_inherited_items";

		internal const string Config_base_collection_elements_may_not_be_removed = "Config_base_collection_elements_may_not_be_removed";

		internal const string Config_base_collection_entry_already_exists = "Config_base_collection_entry_already_exists";

		internal const string Config_base_collection_entry_already_removed = "Config_base_collection_entry_already_removed";

		internal const string Config_base_collection_entry_not_found = "Config_base_collection_entry_not_found";

		internal const string Config_base_element_cannot_have_multiple_child_elements = "Config_base_element_cannot_have_multiple_child_elements";

		internal const string Config_base_element_default_collection_cannot_be_locked = "Config_base_element_default_collection_cannot_be_locked";

		internal const string Config_base_element_locked = "Config_base_element_locked";

		internal const string Config_base_expected_enum = "Config_base_expected_enum";

		internal const string Config_base_expected_to_find_element = "Config_base_expected_to_find_element";

		internal const string Config_base_invalid_attribute_to_lock = "Config_base_invalid_attribute_to_lock";

		internal const string Config_base_invalid_attribute_to_lock_by_add = "Config_base_invalid_attribute_to_lock_by_add";

		internal const string Config_base_invalid_element_key = "Config_base_invalid_element_key";

		internal const string Config_base_invalid_element_to_lock = "Config_base_invalid_element_to_lock";

		internal const string Config_base_invalid_element_to_lock_by_add = "Config_base_invalid_element_to_lock_by_add";

		internal const string Config_base_property_is_not_a_configuration_element = "Config_base_property_is_not_a_configuration_element";

		internal const string Config_base_read_only = "Config_base_read_only";

		internal const string Config_base_required_attribute_locked = "Config_base_required_attribute_locked";

		internal const string Config_base_required_attribute_lock_attempt = "Config_base_required_attribute_lock_attempt";

		internal const string Config_base_required_attribute_missing = "Config_base_required_attribute_missing";

		internal const string Config_base_section_cannot_contain_cdata = "Config_base_section_cannot_contain_cdata";

		internal const string Config_base_section_invalid_content = "Config_base_section_invalid_content";

		internal const string Config_base_unrecognized_attribute = "Config_base_unrecognized_attribute";

		internal const string Config_base_unrecognized_element = "Config_base_unrecognized_element";

		internal const string Config_base_unrecognized_element_name = "Config_base_unrecognized_element_name";

		internal const string Config_base_value_cannot_contain = "Config_base_value_cannot_contain";

		internal const string Config_cannot_edit_configurationsection_in_location_config = "Config_cannot_edit_configurationsection_in_location_config";

		internal const string Config_cannot_edit_configurationsection_parentsection = "Config_cannot_edit_configurationsection_parentsection";

		internal const string Config_cannot_edit_configurationsection_when_location_locked = "Config_cannot_edit_configurationsection_when_location_locked";

		internal const string Config_cannot_edit_configurationsection_when_locked = "Config_cannot_edit_configurationsection_when_locked";

		internal const string Config_cannot_edit_configurationsection_when_not_attached = "Config_cannot_edit_configurationsection_when_not_attached";

		internal const string Config_cannot_edit_configurationsection_when_it_is_implicit = "Config_cannot_edit_configurationsection_when_it_is_implicit";

		internal const string Config_cannot_edit_configurationsection_when_it_is_undeclared = "Config_cannot_edit_configurationsection_when_it_is_undeclared";

		internal const string Config_cannot_edit_configurationsectiongroup_in_location_config = "Config_cannot_edit_configurationsectiongroup_in_location_config";

		internal const string Config_cannot_edit_configurationsectiongroup_when_not_attached = "Config_cannot_edit_configurationsectiongroup_when_not_attached";

		internal const string Config_cannot_edit_locationattriubtes = "Config_cannot_edit_locationattriubtes";

		internal const string Config_cannot_open_config_source = "Config_cannot_open_config_source";

		internal const string Config_client_config_init_error = "Config_client_config_init_error";

		internal const string Config_client_config_init_security = "Config_client_config_init_security";

		internal const string Config_client_config_too_many_configsections_elements = "Config_client_config_too_many_configsections_elements";

		internal const string Config_configmanager_open_noexe = "Config_configmanager_open_noexe";

		internal const string Config_configsection_parentnotvalid = "Config_configsection_parentnotvalid";

		internal const string Config_connectionstrings_declaration_invalid = "Config_connectionstrings_declaration_invalid";

		internal const string Config_data_read_count_mismatch = "Config_data_read_count_mismatch";

		internal const string Config_element_no_context = "Config_element_no_context";

		internal const string Config_empty_lock_attributes_except = "Config_empty_lock_attributes_except";

		internal const string Config_empty_lock_attributes_except_effective = "Config_empty_lock_attributes_except_effective";

		internal const string Config_empty_lock_element_except = "Config_empty_lock_element_except";

		internal const string Config_exception_in_config_section_handler = "Config_exception_in_config_section_handler";

		internal const string Config_file_doesnt_have_root_configuration = "Config_file_doesnt_have_root_configuration";

		internal const string Config_file_has_changed = "Config_file_has_changed";

		internal const string Config_getparentconfigurationsection_first_instance = "Config_getparentconfigurationsection_first_instance";

		internal const string Config_inconsistent_location_attributes = "Config_inconsistent_location_attributes";

		internal const string Config_invalid_attributes_for_write = "Config_invalid_attributes_for_write";

		internal const string Config_invalid_boolean_attribute = "Config_invalid_boolean_attribute";

		internal const string Config_invalid_configurationsection_constructor = "Config_invalid_configurationsection_constructor";

		internal const string Config_invalid_node_type = "Config_invalid_node_type";

		internal const string Config_location_location_not_allowed = "Config_location_location_not_allowed";

		internal const string Config_location_path_invalid_character = "Config_location_path_invalid_character";

		internal const string Config_location_path_invalid_first_character = "Config_location_path_invalid_first_character";

		internal const string Config_location_path_invalid_last_character = "Config_location_path_invalid_last_character";

		internal const string Config_missing_required_attribute = "Config_missing_required_attribute";

		internal const string Config_more_data_than_expected = "Config_more_data_than_expected";

		internal const string Config_name_value_file_section_file_invalid_root = "Config_name_value_file_section_file_invalid_root";

		internal const string Config_namespace_invalid = "Config_namespace_invalid";

		internal const string Config_no_stream_to_write = "Config_no_stream_to_write";

		internal const string Config_not_allowed_to_encrypt_this_section = "Config_not_allowed_to_encrypt_this_section";

		internal const string Config_object_is_null = "Config_object_is_null";

		internal const string Config_operation_not_runtime = "Config_operation_not_runtime";

		internal const string Config_properties_may_not_be_derived_from_configuration_section = "Config_properties_may_not_be_derived_from_configuration_section";

		internal const string Config_protection_section_not_found = "Config_protection_section_not_found";

		internal const string Config_provider_must_implement_type = "Config_provider_must_implement_type";

		internal const string Config_root_section_group_cannot_be_edited = "Config_root_section_group_cannot_be_edited";

		internal const string Config_section_allow_definition_attribute_invalid = "Config_section_allow_definition_attribute_invalid";

		internal const string Config_section_allow_exe_definition_attribute_invalid = "Config_section_allow_exe_definition_attribute_invalid";

		internal const string Config_section_cannot_be_used_in_location = "Config_section_cannot_be_used_in_location";

		internal const string Config_section_group_missing_public_constructor = "Config_section_group_missing_public_constructor";

		internal const string Config_section_locked = "Config_section_locked";

		internal const string Config_sections_must_be_unique = "Config_sections_must_be_unique";

		internal const string Config_source_cannot_be_shared = "Config_source_cannot_be_shared";

		internal const string Config_source_parent_conflict = "Config_source_parent_conflict";

		internal const string Config_source_file_format = "Config_source_file_format";

		internal const string Config_source_invalid_format = "Config_source_invalid_format";

		internal const string Config_source_invalid_chars = "Config_source_invalid_chars";

		internal const string Config_source_requires_file = "Config_source_requires_file";

		internal const string Config_source_syntax_error = "Config_source_syntax_error";

		internal const string Config_system_already_set = "Config_system_already_set";

		internal const string Config_tag_name_already_defined = "Config_tag_name_already_defined";

		internal const string Config_tag_name_already_defined_at_this_level = "Config_tag_name_already_defined_at_this_level";

		internal const string Config_tag_name_cannot_be_location = "Config_tag_name_cannot_be_location";

		internal const string Config_tag_name_cannot_begin_with_config = "Config_tag_name_cannot_begin_with_config";

		internal const string Config_type_doesnt_inherit_from_type = "Config_type_doesnt_inherit_from_type";

		internal const string Config_unexpected_element_end = "Config_unexpected_element_end";

		internal const string Config_unexpected_element_name = "Config_unexpected_element_name";

		internal const string Config_unexpected_node_type = "Config_unexpected_node_type";

		internal const string Config_unrecognized_configuration_section = "Config_unrecognized_configuration_section";

		internal const string Config_write_failed = "Config_write_failed";

		internal const string Converter_timespan_not_in_second = "Converter_timespan_not_in_second";

		internal const string Converter_unsupported_value_type = "Converter_unsupported_value_type";

		internal const string Decryption_failed = "Decryption_failed";

		internal const string Default_value_conversion_error_from_string = "Default_value_conversion_error_from_string";

		internal const string Default_value_wrong_type = "Default_value_wrong_type";

		internal const string DPAPI_bad_data = "DPAPI_bad_data";

		internal const string Empty_attribute = "Empty_attribute";

		internal const string EncryptedNode_not_found = "EncryptedNode_not_found";

		internal const string EncryptedNode_is_in_invalid_format = "EncryptedNode_is_in_invalid_format";

		internal const string Encryption_failed = "Encryption_failed";

		internal const string Expect_bool_value_for_DoNotShowUI = "Expect_bool_value_for_DoNotShowUI";

		internal const string Expect_bool_value_for_useMachineProtection = "Expect_bool_value_for_useMachineProtection";

		internal const string IndexOutOfRange = "IndexOutOfRange";

		internal const string Invalid_enum_value = "Invalid_enum_value";

		internal const string Key_container_doesnt_exist_or_access_denied = "Key_container_doesnt_exist_or_access_denied";

		internal const string Must_add_to_config_before_protecting_it = "Must_add_to_config_before_protecting_it";

		internal const string No_converter = "No_converter";

		internal const string No_exception_information_available = "No_exception_information_available";

		internal const string Property_name_reserved = "Property_name_reserved";

		internal const string Item_name_reserved = "Item_name_reserved";

		internal const string Basicmap_item_name_reserved = "Basicmap_item_name_reserved";

		internal const string ProtectedConfigurationProvider_not_found = "ProtectedConfigurationProvider_not_found";

		internal const string Regex_validator_error = "Regex_validator_error";

		internal const string String_null_or_empty = "String_null_or_empty";

		internal const string Subclass_validator_error = "Subclass_validator_error";

		internal const string Top_level_conversion_error_from_string = "Top_level_conversion_error_from_string";

		internal const string Top_level_conversion_error_to_string = "Top_level_conversion_error_to_string";

		internal const string Top_level_validation_error = "Top_level_validation_error";

		internal const string Type_cannot_be_resolved = "Type_cannot_be_resolved";

		internal const string TypeNotPublic = "TypeNotPublic";

		internal const string Unrecognized_initialization_value = "Unrecognized_initialization_value";

		internal const string UseMachineContainer_must_be_bool = "UseMachineContainer_must_be_bool";

		internal const string UseOAEP_must_be_bool = "UseOAEP_must_be_bool";

		internal const string Validation_scalar_range_violation_not_different = "Validation_scalar_range_violation_not_different";

		internal const string Validation_scalar_range_violation_not_equal = "Validation_scalar_range_violation_not_equal";

		internal const string Validation_scalar_range_violation_not_in_range = "Validation_scalar_range_violation_not_in_range";

		internal const string Validation_scalar_range_violation_not_outside_range = "Validation_scalar_range_violation_not_outside_range";

		internal const string Validator_Attribute_param_not_validator = "Validator_Attribute_param_not_validator";

		internal const string Validator_does_not_support_elem_type = "Validator_does_not_support_elem_type";

		internal const string Validator_does_not_support_prop_type = "Validator_does_not_support_prop_type";

		internal const string Validator_element_not_valid = "Validator_element_not_valid";

		internal const string Validator_method_not_found = "Validator_method_not_found";

		internal const string Validator_min_greater_than_max = "Validator_min_greater_than_max";

		internal const string Validator_scalar_resolution_violation = "Validator_scalar_resolution_violation";

		internal const string Validator_string_invalid_chars = "Validator_string_invalid_chars";

		internal const string Validator_string_max_length = "Validator_string_max_length";

		internal const string Validator_string_min_length = "Validator_string_min_length";

		internal const string Validator_value_type_invalid = "Validator_value_type_invalid";

		internal const string Validator_multiple_validator_attributes = "Validator_multiple_validator_attributes";

		internal const string Validator_timespan_value_must_be_positive = "Validator_timespan_value_must_be_positive";

		internal const string WrongType_of_Protected_provider = "WrongType_of_Protected_provider";

		internal const string Type_from_untrusted_assembly = "Type_from_untrusted_assembly";

		internal const string Config_element_locking_not_supported = "Config_element_locking_not_supported";

		internal const string Config_element_null_instance = "Config_element_null_instance";

		internal const string ConfigurationPermissionBadXml = "ConfigurationPermissionBadXml";

		internal const string ConfigurationPermission_Denied = "ConfigurationPermission_Denied";

		internal const string Section_from_untrusted_assembly = "Section_from_untrusted_assembly";

		internal const string Protection_provider_syntax_error = "Protection_provider_syntax_error";

		internal const string Protection_provider_invalid_format = "Protection_provider_invalid_format";

		internal const string Cannot_declare_or_remove_implicit_section = "Cannot_declare_or_remove_implicit_section";

		internal const string Config_reserved_attribute = "Config_reserved_attribute";

		internal const string Filename_in_SaveAs_is_used_already = "Filename_in_SaveAs_is_used_already";

		internal const string Provider_Already_Initialized = "Provider_Already_Initialized";

		internal const string Config_provider_name_null_or_empty = "Config_provider_name_null_or_empty";

		internal const string CollectionReadOnly = "CollectionReadOnly";

		internal const string Config_source_not_under_config_dir = "Config_source_not_under_config_dir";

		internal const string Config_source_invalid = "Config_source_invalid";

		internal const string Location_invalid_inheritInChildApplications_in_machine_or_root_web_config = "Location_invalid_inheritInChildApplications_in_machine_or_root_web_config";

		internal const string Cannot_change_both_AllowOverride_and_OverrideMode = "Cannot_change_both_AllowOverride_and_OverrideMode";

		internal const string Config_section_override_mode_attribute_invalid = "Config_section_override_mode_attribute_invalid";

		internal const string Invalid_override_mode_declaration = "Invalid_override_mode_declaration";

		internal const string Config_cannot_edit_locked_configurationsection_when_mode_is_not_allow = "Config_cannot_edit_locked_configurationsection_when_mode_is_not_allow";

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
			resources = new ResourceManager("System.Configuration", GetType().Assembly);
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
	internal static class HResults
	{
		internal const int Configuration = -2146232062;

		internal const int Xml = -2146232000;

		internal const int XmlSchema = -2146231999;

		internal const int XmlXslt = -2146231998;

		internal const int XmlXPath = -2146231997;

		internal const int Data = -2146232032;

		internal const int DataDeletedRowInaccessible = -2146232031;

		internal const int DataDuplicateName = -2146232030;

		internal const int DataInRowChangingEvent = -2146232029;

		internal const int DataInvalidConstraint = -2146232028;

		internal const int DataMissingPrimaryKey = -2146232027;

		internal const int DataNoNullAllowed = -2146232026;

		internal const int DataReadOnly = -2146232025;

		internal const int DataRowNotInTable = -2146232024;

		internal const int DataVersionNotFound = -2146232023;

		internal const int DataConstraint = -2146232022;

		internal const int StrongTyping = -2146232021;

		internal const int SqlType = -2146232016;

		internal const int SqlNullValue = -2146232015;

		internal const int SqlTruncate = -2146232014;

		internal const int AdapterMapping = -2146232013;

		internal const int DataAdapter = -2146232012;

		internal const int DBConcurrency = -2146232011;

		internal const int OperationAborted = -2146232010;

		internal const int InvalidUdt = -2146232009;

		internal const int SqlException = -2146232060;

		internal const int OdbcException = -2146232009;

		internal const int OracleException = -2146232008;

		internal const int NteBadKeySet = -2146893802;

		internal const int Win32AccessDenied = -2147024891;

		internal const int Win32InvalidHandle = -2147024890;

		internal const int License = -2146232063;

		internal const int InternalBufferOverflow = -2146232059;

		internal const int ServiceControllerTimeout = -2146232058;

		internal const int Install = -2146232057;

		internal const int EFail = -2147467259;
	}
}
namespace System.Configuration
{
	internal static class ConfigPathUtility
	{
		private const char SeparatorChar = '/';

		internal static bool IsValid(string configPath)
		{
			if (string.IsNullOrEmpty(configPath))
			{
				return false;
			}
			int num = -1;
			for (int i = 0; i <= configPath.Length; i++)
			{
				switch ((i >= configPath.Length) ? '/' : configPath[i])
				{
				case '\\':
					return false;
				case '/':
					if (i == num + 1)
					{
						return false;
					}
					if (i == num + 2 && configPath[num + 1] == '.')
					{
						return false;
					}
					if (i == num + 3 && configPath[num + 1] == '.' && configPath[num + 2] == '.')
					{
						return false;
					}
					num = i;
					break;
				}
			}
			return true;
		}

		internal static string Combine(string parentConfigPath, string childConfigPath)
		{
			if (string.IsNullOrEmpty(parentConfigPath))
			{
				return childConfigPath;
			}
			if (string.IsNullOrEmpty(childConfigPath))
			{
				return parentConfigPath;
			}
			return parentConfigPath + "/" + childConfigPath;
		}

		internal static string[] GetParts(string configPath)
		{
			return configPath.Split('/');
		}

		internal static string GetName(string configPath)
		{
			if (string.IsNullOrEmpty(configPath))
			{
				return configPath;
			}
			int num = configPath.LastIndexOf('/');
			if (num == -1)
			{
				return configPath;
			}
			return configPath.Substring(num + 1);
		}
	}
	[ConfigurationPermission(SecurityAction.Assert, Unrestricted = true)]
	internal static class PrivilegedConfigurationManager
	{
		internal static ConnectionStringSettingsCollection ConnectionStrings => ConfigurationManager.ConnectionStrings;

		internal static object GetSection(string sectionName)
		{
			return ConfigurationManager.GetSection(sectionName);
		}
	}
	public abstract class ConfigurationElement
	{
		private const string LockAttributesKey = "lockAttributes";

		private const string LockAllAttributesExceptKey = "lockAllAttributesExcept";

		private const string LockElementsKey = "lockElements";

		private const string LockAll = "*";

		private const string LockAllElementsExceptKey = "lockAllElementsExcept";

		private const string LockItemKey = "lockItem";

		internal const string DefaultCollectionPropertyName = "";

		private static string[] s_lockAttributeNames = new string[5] { "lockAttributes", "lockAllAttributesExcept", "lockElements", "lockAllElementsExcept", "lockItem" };

		private static Hashtable s_propertyBags = new Hashtable();

		private static Dictionary<Type, ConfigurationValidatorBase> s_perTypeValidators;

		internal static readonly object s_nullPropertyValue = new object();

		private static ConfigurationElementProperty s_ElementProperty = new ConfigurationElementProperty(new DefaultValidator());

		private bool _bDataToWrite;

		private bool _bModified;

		private bool _bReadOnly;

		private bool _bElementPresent;

		private bool _bInited;

		internal ConfigurationLockCollection _lockedAttributesList;

		internal ConfigurationLockCollection _lockedAllExceptAttributesList;

		internal ConfigurationLockCollection _lockedElementsList;

		internal ConfigurationLockCollection _lockedAllExceptElementsList;

		private ConfigurationValues _values;

		private string _elementTagName;

		private ElementInformation _evaluationElement;

		private ConfigurationElementProperty _elementProperty = s_ElementProperty;

		internal ConfigurationValueFlags _fItemLocked;

		internal ContextInformation _evalContext;

		internal BaseConfigurationRecord _configRecord;

		internal bool DataToWriteInternal
		{
			get
			{
				return _bDataToWrite;
			}
			set
			{
				_bDataToWrite = value;
			}
		}

		internal bool ElementPresent
		{
			get
			{
				return _bElementPresent;
			}
			set
			{
				_bElementPresent = value;
			}
		}

		internal string ElementTagName => _elementTagName;

		internal ConfigurationLockCollection LockedAttributesList => _lockedAttributesList;

		internal ConfigurationLockCollection LockedAllExceptAttributesList => _lockedAllExceptAttributesList;

		internal ConfigurationValueFlags ItemLocked => _fItemLocked;

		public ConfigurationLockCollection LockAttributes
		{
			get
			{
				if (_lockedAttributesList == null)
				{
					_lockedAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedAttributes);
				}
				return _lockedAttributesList;
			}
		}

		public ConfigurationLockCollection LockAllAttributesExcept
		{
			get
			{
				if (_lockedAllExceptAttributesList == null)
				{
					_lockedAllExceptAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedExceptionList, _elementTagName);
				}
				return _lockedAllExceptAttributesList;
			}
		}

		public ConfigurationLockCollection LockElements
		{
			get
			{
				if (_lockedElementsList == null)
				{
					_lockedElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElements);
				}
				return _lockedElementsList;
			}
		}

		public ConfigurationLockCollection LockAllElementsExcept
		{
			get
			{
				if (_lockedAllExceptElementsList == null)
				{
					_lockedAllExceptElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElementsExceptionList, _elementTagName);
				}
				return _lockedAllExceptElementsList;
			}
		}

		public bool LockItem
		{
			get
			{
				return (_fItemLocked & ConfigurationValueFlags.Locked) != 0;
			}
			set
			{
				if ((_fItemLocked & ConfigurationValueFlags.Inherited) == 0)
				{
					_fItemLocked = (value ? ConfigurationValueFlags.Locked : ConfigurationValueFlags.Default);
					_fItemLocked |= ConfigurationValueFlags.Modified;
					return;
				}
				throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", "lockItem"));
			}
		}

		protected internal object this[ConfigurationProperty prop]
		{
			get
			{
				object obj = _values[prop.Name];
				if (obj == null)
				{
					lock (_values.SyncRoot)
					{
						obj = _values[prop.Name];
						if (obj == null)
						{
							if (typeof(ConfigurationElement).IsAssignableFrom(prop.Type))
							{
								ConfigurationElement configurationElement = CreateElement(prop.Type);
								if (_bReadOnly)
								{
									configurationElement.SetReadOnly();
								}
								if (typeof(ConfigurationElementCollection).IsAssignableFrom(prop.Type))
								{
									ConfigurationElementCollection configurationElementCollection = configurationElement as ConfigurationElementCollection;
									if (prop.AddElementName != null)
									{
										configurationElementCollection.AddElementName = prop.AddElementName;
									}
									if (prop.RemoveElementName != null)
									{
										configurationElementCollection.RemoveElementName = prop.RemoveElementName;
									}
									if (prop.ClearElementName != null)
									{
										configurationElementCollection.ClearElementName = prop.ClearElementName;
									}
								}
								_values.SetValue(prop.Name, configurationElement, ConfigurationValueFlags.Inherited, null);
								obj = configurationElement;
							}
							else
							{
								obj = prop.DefaultValue;
							}
						}
					}
				}
				else if (obj == s_nullPropertyValue)
				{
					obj = null;
				}
				if (obj is InvalidPropValue)
				{
					throw ((InvalidPropValue)obj).Error;
				}
				return obj;
			}
			set
			{
				SetPropertyValue(prop, value, ignoreLocks: false);
			}
		}

		protected internal object this[string propertyName]
		{
			get
			{
				ConfigurationProperty configurationProperty = Properties[propertyName];
				if (configurationProperty == null)
				{
					configurationProperty = Properties[""];
					if (configurationProperty.ProvidedName != propertyName)
					{
						return null;
					}
				}
				return this[configurationProperty];
			}
			set
			{
				SetPropertyValue(Properties[propertyName], value, ignoreLocks: false);
			}
		}

		protected internal virtual ConfigurationPropertyCollection Properties
		{
			get
			{
				ConfigurationPropertyCollection result = null;
				if (PropertiesFromType(GetType(), out result))
				{
					ApplyInstanceAttributes(this);
					ApplyValidatorsRecursive(this);
				}
				return result;
			}
		}

		internal ConfigurationValues Values => _values;

		public ElementInformation ElementInformation
		{
			get
			{
				if (_evaluationElement == null)
				{
					_evaluationElement = new ElementInformation(this);
				}
				return _evaluationElement;
			}
		}

		protected ContextInformation EvaluationContext
		{
			get
			{
				if (_evalContext == null)
				{
					if (_configRecord == null)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_element_no_context"));
					}
					_evalContext = new ContextInformation(_configRecord);
				}
				return _evalContext;
			}
		}

		protected internal virtual ConfigurationElementProperty ElementProperty => _elementProperty;

		internal ConfigurationElement CreateElement(Type type)
		{
			ConfigurationElement configurationElement = (ConfigurationElement)TypeUtil.CreateInstanceRestricted(GetType(), type);
			configurationElement.CallInit();
			return configurationElement;
		}

		protected ConfigurationElement()
		{
			_values = new ConfigurationValues();
			ApplyValidator(this);
		}

		protected internal virtual void Init()
		{
			_bInited = true;
		}

		internal void CallInit()
		{
			if (!_bInited)
			{
				Init();
				_bInited = true;
			}
		}

		internal void MergeLocks(ConfigurationElement source)
		{
			if (source == null)
			{
				return;
			}
			_fItemLocked = (((source._fItemLocked & ConfigurationValueFlags.Locked) != 0) ? (ConfigurationValueFlags.Inherited | source._fItemLocked) : _fItemLocked);
			if (source._lockedAttributesList != null)
			{
				if (_lockedAttributesList == null)
				{
					_lockedAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedAttributes);
				}
				foreach (string lockedAttributes in source._lockedAttributesList)
				{
					_lockedAttributesList.Add(lockedAttributes, ConfigurationValueFlags.Inherited);
				}
			}
			if (source._lockedAllExceptAttributesList != null)
			{
				if (_lockedAllExceptAttributesList == null)
				{
					_lockedAllExceptAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedExceptionList, string.Empty, source._lockedAllExceptAttributesList);
				}
				StringCollection stringCollection = IntersectLockCollections(_lockedAllExceptAttributesList, source._lockedAllExceptAttributesList);
				_lockedAllExceptAttributesList.ClearInternal(useSeedIfAvailble: false);
				StringEnumerator enumerator2 = stringCollection.GetEnumerator();
				try
				{
					while (enumerator2.MoveNext())
					{
						string current = enumerator2.Current;
						_lockedAllExceptAttributesList.Add(current, ConfigurationValueFlags.Default);
					}
				}
				finally
				{
					if (enumerator2 is IDisposable disposable)
					{
						disposable.Dispose();
					}
				}
			}
			if (source._lockedElementsList != null)
			{
				if (_lockedElementsList == null)
				{
					_lockedElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElements);
				}
				ConfigurationElementCollection configurationElementCollection = null;
				if (Properties.DefaultCollectionProperty != null)
				{
					configurationElementCollection = this[Properties.DefaultCollectionProperty] as ConfigurationElementCollection;
					if (configurationElementCollection != null)
					{
						configurationElementCollection.internalElementTagName = source.ElementTagName;
						if (configurationElementCollection._lockedElementsList == null)
						{
							configurationElementCollection._lockedElementsList = _lockedElementsList;
						}
					}
				}
				foreach (string lockedElements in source._lockedElementsList)
				{
					_lockedElementsList.Add(lockedElements, ConfigurationValueFlags.Inherited);
					configurationElementCollection?._lockedElementsList.Add(lockedElements, ConfigurationValueFlags.Inherited);
				}
			}
			if (source._lockedAllExceptElementsList == null)
			{
				return;
			}
			if (_lockedAllExceptElementsList == null || _lockedAllExceptElementsList.Count == 0)
			{
				_lockedAllExceptElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElementsExceptionList, source._elementTagName, source._lockedAllExceptElementsList);
			}
			StringCollection stringCollection2 = IntersectLockCollections(_lockedAllExceptElementsList, source._lockedAllExceptElementsList);
			ConfigurationElementCollection configurationElementCollection2 = null;
			if (Properties.DefaultCollectionProperty != null && this[Properties.DefaultCollectionProperty] is ConfigurationElementCollection configurationElementCollection3 && configurationElementCollection3._lockedAllExceptElementsList == null)
			{
				configurationElementCollection3._lockedAllExceptElementsList = _lockedAllExceptElementsList;
			}
			_lockedAllExceptElementsList.ClearInternal(useSeedIfAvailble: false);
			StringEnumerator enumerator4 = stringCollection2.GetEnumerator();
			try
			{
				while (enumerator4.MoveNext())
				{
					string current2 = enumerator4.Current;
					if (!_lockedAllExceptElementsList.Contains(current2) || current2 == ElementTagName)
					{
						_lockedAllExceptElementsList.Add(current2, ConfigurationValueFlags.Default);
					}
				}
			}
			finally
			{
				if (enumerator4 is IDisposable disposable2)
				{
					disposable2.Dispose();
				}
			}
			if (!_lockedAllExceptElementsList.HasParentElements)
			{
				return;
			}
			foreach (ConfigurationProperty property in Properties)
			{
				if (!_lockedAllExceptElementsList.Contains(property.Name) && typeof(ConfigurationElement).IsAssignableFrom(property.Type))
				{
					((ConfigurationElement)this[property]).SetLocked();
				}
			}
		}

		internal void HandleLockedAttributes(ConfigurationElement source)
		{
			if (source == null || (source._lockedAttributesList == null && source._lockedAllExceptAttributesList == null))
			{
				return;
			}
			foreach (PropertyInformation property2 in source.ElementInformation.Properties)
			{
				if (((source._lockedAttributesList == null || (!source._lockedAttributesList.Contains(property2.Name) && !source._lockedAttributesList.Contains("*"))) && (source._lockedAllExceptAttributesList == null || source._lockedAllExceptAttributesList.Contains(property2.Name))) || !(property2.Name != "lockAttributes") || !(property2.Name != "lockAllAttributesExcept"))
				{
					continue;
				}
				if (ElementInformation.Properties[property2.Name] == null)
				{
					ConfigurationPropertyCollection properties = Properties;
					ConfigurationProperty property = source.Properties[property2.Name];
					properties.Add(property);
					_evaluationElement = null;
					ConfigurationValueFlags valueFlags = ConfigurationValueFlags.Inherited | ConfigurationValueFlags.Locked;
					_values.SetValue(property2.Name, property2.Value, valueFlags, source.PropertyInfoInternal(property2.Name));
				}
				else
				{
					if (ElementInformation.Properties[property2.Name].ValueOrigin == PropertyValueOrigin.SetHere)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", property2.Name));
					}
					ElementInformation.Properties[property2.Name].Value = property2.Value;
				}
			}
		}

		internal virtual void AssociateContext(BaseConfigurationRecord configRecord)
		{
			_configRecord = configRecord;
			Values.AssociateContext(configRecord);
		}

		protected internal virtual bool IsModified()
		{
			if (_bModified)
			{
				return true;
			}
			if (_lockedAttributesList != null && _lockedAttributesList.IsModified)
			{
				return true;
			}
			if (_lockedAllExceptAttributesList != null && _lockedAllExceptAttributesList.IsModified)
			{
				return true;
			}
			if (_lockedElementsList != null && _lockedElementsList.IsModified)
			{
				return true;
			}
			if (_lockedAllExceptElementsList != null && _lockedAllExceptElementsList.IsModified)
			{
				return true;
			}
			if ((_fItemLocked & ConfigurationValueFlags.Modified) != 0)
			{
				return true;
			}
			foreach (ConfigurationElement configurationElement in _values.ConfigurationElements)
			{
				if (configurationElement.IsModified())
				{
					return true;
				}
			}
			return false;
		}

		protected internal virtual void ResetModified()
		{
			_bModified = false;
			if (_lockedAttributesList != null)
			{
				_lockedAttributesList.ResetModified();
			}
			if (_lockedAllExceptAttributesList != null)
			{
				_lockedAllExceptAttributesList.ResetModified();
			}
			if (_lockedElementsList != null)
			{
				_lockedElementsList.ResetModified();
			}
			if (_lockedAllExceptElementsList != null)
			{
				_lockedAllExceptElementsList.ResetModified();
			}
			foreach (ConfigurationElement configurationElement in _values.ConfigurationElements)
			{
				configurationElement.ResetModified();
			}
		}

		public virtual bool IsReadOnly()
		{
			return _bReadOnly;
		}

		protected internal virtual void SetReadOnly()
		{
			_bReadOnly = true;
			foreach (ConfigurationElement configurationElement in _values.ConfigurationElements)
			{
				configurationElement.SetReadOnly();
			}
		}

		internal void SetLocked()
		{
			_fItemLocked = ConfigurationValueFlags.Locked | ConfigurationValueFlags.XMLParentInherited;
			foreach (ConfigurationProperty property in Properties)
			{
				if (!(this[property] is ConfigurationElement configurationElement))
				{
					continue;
				}
				if (configurationElement.GetType() != GetType())
				{
					configurationElement.SetLocked();
				}
				if (!(this[property] is ConfigurationElementCollection configurationElementCollection))
				{
					continue;
				}
				foreach (object item in configurationElementCollection)
				{
					if (item is ConfigurationElement configurationElement2)
					{
						configurationElement2.SetLocked();
					}
				}
			}
		}

		internal ArrayList GetErrorsList()
		{
			ArrayList arrayList = new ArrayList();
			ListErrors(arrayList);
			return arrayList;
		}

		internal ConfigurationErrorsException GetErrors()
		{
			ArrayList errorsList = GetErrorsList();
			if (errorsList.Count == 0)
			{
				return null;
			}
			return new ConfigurationErrorsException(errorsList);
		}

		protected virtual void ListErrors(IList errorList)
		{
			foreach (InvalidPropValue invalidValue in _values.InvalidValues)
			{
				errorList.Add(invalidValue.Error);
			}
			foreach (ConfigurationElement configurationElement3 in _values.ConfigurationElements)
			{
				configurationElement3.ListErrors(errorList);
				if (!(configurationElement3 is ConfigurationElementCollection configurationElementCollection))
				{
					continue;
				}
				foreach (ConfigurationElement item in configurationElementCollection)
				{
					item.ListErrors(errorList);
				}
			}
		}

		protected internal virtual void InitializeDefault()
		{
		}

		internal void CheckLockedElement(string elementName, XmlReader reader)
		{
			if (elementName != null && ((_lockedElementsList != null && (_lockedElementsList.DefinedInParent("*") || _lockedElementsList.DefinedInParent(elementName))) || (_lockedAllExceptElementsList != null && _lockedAllExceptElementsList.Count != 0 && _lockedAllExceptElementsList.HasParentElements && !_lockedAllExceptElementsList.DefinedInParent(elementName)) || (_fItemLocked & ConfigurationValueFlags.Inherited) != 0))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_element_locked", elementName), reader);
			}
		}

		internal void RemoveAllInheritedLocks()
		{
			if (_lockedAttributesList != null)
			{
				_lockedAttributesList.RemoveInheritedLocks();
			}
			if (_lockedElementsList != null)
			{
				_lockedElementsList.RemoveInheritedLocks();
			}
			if (_lockedAllExceptAttributesList != null)
			{
				_lockedAllExceptAttributesList.RemoveInheritedLocks();
			}
			if (_lockedAllExceptElementsList != null)
			{
				_lockedAllExceptElementsList.RemoveInheritedLocks();
			}
		}

		internal void ResetLockLists(ConfigurationElement parentElement)
		{
			_lockedAttributesList = null;
			_lockedAllExceptAttributesList = null;
			_lockedElementsList = null;
			_lockedAllExceptElementsList = null;
			if (parentElement == null)
			{
				return;
			}
			_fItemLocked = (((parentElement._fItemLocked & ConfigurationValueFlags.Locked) != 0) ? (ConfigurationValueFlags.Inherited | parentElement._fItemLocked) : ConfigurationValueFlags.Default);
			if (parentElement._lockedAttributesList != null)
			{
				_lockedAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedAttributes);
				foreach (string lockedAttributes in parentElement._lockedAttributesList)
				{
					_lockedAttributesList.Add(lockedAttributes, ConfigurationValueFlags.Inherited);
				}
			}
			if (parentElement._lockedAllExceptAttributesList != null)
			{
				_lockedAllExceptAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedExceptionList, string.Empty, parentElement._lockedAllExceptAttributesList);
			}
			if (parentElement._lockedElementsList != null)
			{
				_lockedElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElements);
				ConfigurationElementCollection configurationElementCollection = null;
				if (Properties.DefaultCollectionProperty != null && this[Properties.DefaultCollectionProperty] is ConfigurationElementCollection configurationElementCollection2)
				{
					configurationElementCollection2.internalElementTagName = parentElement.ElementTagName;
					if (configurationElementCollection2._lockedElementsList == null)
					{
						configurationElementCollection2._lockedElementsList = _lockedElementsList;
					}
				}
				foreach (string lockedElements in parentElement._lockedElementsList)
				{
					_lockedElementsList.Add(lockedElements, ConfigurationValueFlags.Inherited);
				}
			}
			if (parentElement._lockedAllExceptElementsList != null)
			{
				_lockedAllExceptElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElementsExceptionList, parentElement._elementTagName, parentElement._lockedAllExceptElementsList);
				ConfigurationElementCollection configurationElementCollection3 = null;
				if (Properties.DefaultCollectionProperty != null && this[Properties.DefaultCollectionProperty] is ConfigurationElementCollection configurationElementCollection4 && configurationElementCollection4._lockedAllExceptElementsList == null)
				{
					configurationElementCollection4._lockedAllExceptElementsList = _lockedAllExceptElementsList;
				}
			}
		}

		protected internal virtual void Reset(ConfigurationElement parentElement)
		{
			Values.Clear();
			ResetLockLists(parentElement);
			ConfigurationPropertyCollection properties = Properties;
			_bElementPresent = false;
			if (parentElement == null)
			{
				InitializeDefault();
				return;
			}
			bool flag = false;
			ConfigurationPropertyCollection configurationPropertyCollection = null;
			for (int i = 0; i < parentElement.Values.Count; i++)
			{
				string key = parentElement.Values.GetKey(i);
				ConfigurationValue configValue = parentElement.Values.GetConfigValue(i);
				object obj = configValue?.Value;
				PropertySourceInfo sourceInfo = configValue?.SourceInfo;
				ConfigurationProperty configurationProperty = parentElement.Properties[key];
				if (configurationProperty == null || (configurationPropertyCollection != null && !configurationPropertyCollection.Contains(configurationProperty.Name)))
				{
					continue;
				}
				if (typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
				{
					flag = true;
					continue;
				}
				ConfigurationValueFlags valueFlags = ConfigurationValueFlags.Inherited | (((_lockedAttributesList != null && (_lockedAttributesList.Contains(key) || _lockedAttributesList.Contains("*"))) || (_lockedAllExceptAttributesList != null && !_lockedAllExceptAttributesList.Contains(key))) ? ConfigurationValueFlags.Locked : ConfigurationValueFlags.Default);
				if (obj != s_nullPropertyValue)
				{
					_values.SetValue(key, obj, valueFlags, sourceInfo);
				}
				if (!properties.Contains(key))
				{
					properties.Add(configurationProperty);
					_values.SetValue(key, obj, valueFlags, sourceInfo);
				}
			}
			if (!flag)
			{
				return;
			}
			for (int j = 0; j < parentElement.Values.Count; j++)
			{
				string key2 = parentElement.Values.GetKey(j);
				object obj2 = parentElement.Values[j];
				ConfigurationProperty configurationProperty2 = parentElement.Properties[key2];
				if (configurationProperty2 != null && typeof(ConfigurationElement).IsAssignableFrom(configurationProperty2.Type))
				{
					ConfigurationElement configurationElement = (ConfigurationElement)this[configurationProperty2];
					configurationElement.Reset((ConfigurationElement)obj2);
				}
			}
		}

		public override bool Equals(object compareTo)
		{
			if (!(compareTo is ConfigurationElement configurationElement) || compareTo.GetType() != GetType() || (configurationElement != null && configurationElement.Properties.Count != Properties.Count))
			{
				return false;
			}
			foreach (ConfigurationProperty property in Properties)
			{
				if (!object.Equals(Values[property.Name], configurationElement.Values[property.Name]) && ((Values[property.Name] != null && Values[property.Name] != s_nullPropertyValue) || !object.Equals(configurationElement.Values[property.Name], property.DefaultValue)) && ((configurationElement.Values[property.Name] != null && configurationElement.Values[property.Name] != s_nullPropertyValue) || !object.Equals(Values[property.Name], property.DefaultValue)))
				{
					return false;
				}
			}
			return true;
		}

		public override int GetHashCode()
		{
			int num = 0;
			foreach (ConfigurationProperty property in Properties)
			{
				object obj = this[property];
				if (obj != null)
				{
					num ^= this[property].GetHashCode();
				}
			}
			return num;
		}

		private static void ApplyInstanceAttributes(object instance)
		{
			Type type = instance.GetType();
			PropertyInfo[] properties = type.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			foreach (PropertyInfo propertyInfo in properties)
			{
				if (!(Attribute.GetCustomAttribute(propertyInfo, typeof(ConfigurationPropertyAttribute)) is ConfigurationPropertyAttribute configurationPropertyAttribute))
				{
					continue;
				}
				Type propertyType = propertyInfo.PropertyType;
				if (typeof(ConfigurationElementCollection).IsAssignableFrom(propertyType))
				{
					ConfigurationCollectionAttribute configurationCollectionAttribute = Attribute.GetCustomAttribute(propertyInfo, typeof(ConfigurationCollectionAttribute)) as ConfigurationCollectionAttribute;
					if (configurationCollectionAttribute == null)
					{
						configurationCollectionAttribute = Attribute.GetCustomAttribute(propertyType, typeof(ConfigurationCollectionAttribute)) as ConfigurationCollectionAttribute;
					}
					if (!(propertyInfo.GetValue(instance, null) is ConfigurationElementCollection configurationElementCollection))
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_element_null_instance", propertyInfo.Name, configurationPropertyAttribute.Name));
					}
					if (configurationCollectionAttribute != null)
					{
						if (configurationCollectionAttribute.AddItemName.IndexOf(',') == -1)
						{
							configurationElementCollection.AddElementName = configurationCollectionAttribute.AddItemName;
						}
						configurationElementCollection.RemoveElementName = configurationCollectionAttribute.RemoveItemName;
						configurationElementCollection.ClearElementName = configurationCollectionAttribute.ClearItemsName;
					}
				}
				else if (typeof(ConfigurationElement).IsAssignableFrom(propertyType))
				{
					object value = propertyInfo.GetValue(instance, null);
					if (value == null)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_element_null_instance", propertyInfo.Name, configurationPropertyAttribute.Name));
					}
					ApplyInstanceAttributes(value);
				}
			}
		}

		private static bool PropertiesFromType(Type type, out ConfigurationPropertyCollection result)
		{
			ConfigurationPropertyCollection configurationPropertyCollection = (ConfigurationPropertyCollection)s_propertyBags[type];
			result = null;
			bool result2 = false;
			if (configurationPropertyCollection == null)
			{
				lock (s_propertyBags.SyncRoot)
				{
					configurationPropertyCollection = (ConfigurationPropertyCollection)s_propertyBags[type];
					if (configurationPropertyCollection == null)
					{
						configurationPropertyCollection = CreatePropertyBagFromType(type);
						s_propertyBags[type] = configurationPropertyCollection;
						result2 = true;
					}
				}
			}
			result = configurationPropertyCollection;
			return result2;
		}

		private static ConfigurationPropertyCollection CreatePropertyBagFromType(Type type)
		{
			if (typeof(ConfigurationElement).IsAssignableFrom(type) && Attribute.GetCustomAttribute(type, typeof(ConfigurationValidatorAttribute)) is ConfigurationValidatorAttribute configurationValidatorAttribute)
			{
				configurationValidatorAttribute.SetDeclaringType(type);
				ConfigurationValidatorBase validatorInstance = configurationValidatorAttribute.ValidatorInstance;
				if (validatorInstance != null)
				{
					CachePerTypeValidator(type, validatorInstance);
				}
			}
			ConfigurationPropertyCollection configurationPropertyCollection = new ConfigurationPropertyCollection();
			PropertyInfo[] properties = type.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			foreach (PropertyInfo propertyInformation in properties)
			{
				ConfigurationProperty configurationProperty = CreateConfigurationPropertyFromAttributes(propertyInformation);
				if (configurationProperty != null)
				{
					configurationPropertyCollection.Add(configurationProperty);
				}
			}
			return configurationPropertyCollection;
		}

		private static ConfigurationProperty CreateConfigurationPropertyFromAttributes(PropertyInfo propertyInformation)
		{
			ConfigurationProperty configurationProperty = null;
			if (Attribute.GetCustomAttribute(propertyInformation, typeof(ConfigurationPropertyAttribute)) is ConfigurationPropertyAttribute)
			{
				configurationProperty = new ConfigurationProperty(propertyInformation);
			}
			if (configurationProperty != null && typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
			{
				ConfigurationPropertyCollection result = null;
				PropertiesFromType(configurationProperty.Type, out result);
			}
			return configurationProperty;
		}

		private static void CachePerTypeValidator(Type type, ConfigurationValidatorBase validator)
		{
			if (s_perTypeValidators == null)
			{
				s_perTypeValidators = new Dictionary<Type, ConfigurationValidatorBase>();
			}
			if (!validator.CanValidate(type))
			{
				throw new ConfigurationErrorsException(SR.GetString("Validator_does_not_support_elem_type", type.Name));
			}
			s_perTypeValidators.Add(type, validator);
		}

		private static void ApplyValidatorsRecursive(ConfigurationElement root)
		{
			ApplyValidator(root);
			foreach (ConfigurationElement configurationElement in root._values.ConfigurationElements)
			{
				ApplyValidatorsRecursive(configurationElement);
			}
		}

		private static void ApplyValidator(ConfigurationElement elem)
		{
			if (s_perTypeValidators != null && s_perTypeValidators.ContainsKey(elem.GetType()))
			{
				elem._elementProperty = new ConfigurationElementProperty(s_perTypeValidators[elem.GetType()]);
			}
		}

		protected void SetPropertyValue(ConfigurationProperty prop, object value, bool ignoreLocks)
		{
			if (IsReadOnly())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
			if (!ignoreLocks && ((_lockedAllExceptAttributesList != null && _lockedAllExceptAttributesList.HasParentElements && !_lockedAllExceptAttributesList.DefinedInParent(prop.Name)) || (_lockedAttributesList != null && (_lockedAttributesList.DefinedInParent(prop.Name) || _lockedAttributesList.DefinedInParent("*"))) || ((_fItemLocked & ConfigurationValueFlags.Locked) != 0 && (_fItemLocked & ConfigurationValueFlags.Inherited) != 0)))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", prop.Name));
			}
			_bModified = true;
			if (value != null)
			{
				prop.Validate(value);
			}
			_values[prop.Name] = ((value != null) ? value : s_nullPropertyValue);
		}

		internal PropertySourceInfo PropertyInfoInternal(string propertyName)
		{
			return _values.GetSourceInfo(propertyName);
		}

		internal string PropertyFileName(string propertyName)
		{
			PropertySourceInfo propertySourceInfo = PropertyInfoInternal(propertyName);
			if (propertySourceInfo == null)
			{
				propertySourceInfo = PropertyInfoInternal(string.Empty);
			}
			if (propertySourceInfo == null)
			{
				return string.Empty;
			}
			return propertySourceInfo.FileName;
		}

		internal int PropertyLineNumber(string propertyName)
		{
			PropertySourceInfo propertySourceInfo = PropertyInfoInternal(propertyName);
			if (propertySourceInfo == null)
			{
				propertySourceInfo = PropertyInfoInternal(string.Empty);
			}
			return propertySourceInfo?.LineNumber ?? 0;
		}

		internal virtual void Dump(TextWriter tw)
		{
			tw.WriteLine("Type: " + GetType().FullName);
			PropertyInfo[] properties = GetType().GetProperties();
			foreach (PropertyInfo propertyInfo in properties)
			{
				tw.WriteLine("{0}: {1}", propertyInfo.Name, propertyInfo.GetValue(this, null));
			}
		}

		protected internal virtual void Unmerge(ConfigurationElement sourceElement, ConfigurationElement parentElement, ConfigurationSaveMode saveMode)
		{
			if (sourceElement == null)
			{
				return;
			}
			bool flag = false;
			_lockedAllExceptAttributesList = sourceElement._lockedAllExceptAttributesList;
			_lockedAllExceptElementsList = sourceElement._lockedAllExceptElementsList;
			_fItemLocked = sourceElement._fItemLocked;
			_lockedAttributesList = sourceElement._lockedAttributesList;
			_lockedElementsList = sourceElement._lockedElementsList;
			AssociateContext(sourceElement._configRecord);
			if (parentElement != null)
			{
				if (parentElement._lockedAttributesList != null)
				{
					_lockedAttributesList = UnMergeLockList(sourceElement._lockedAttributesList, parentElement._lockedAttributesList, saveMode);
				}
				if (parentElement._lockedElementsList != null)
				{
					_lockedElementsList = UnMergeLockList(sourceElement._lockedElementsList, parentElement._lockedElementsList, saveMode);
				}
				if (parentElement._lockedAllExceptAttributesList != null)
				{
					_lockedAllExceptAttributesList = UnMergeLockList(sourceElement._lockedAllExceptAttributesList, parentElement._lockedAllExceptAttributesList, saveMode);
				}
				if (parentElement._lockedAllExceptElementsList != null)
				{
					_lockedAllExceptElementsList = UnMergeLockList(sourceElement._lockedAllExceptElementsList, parentElement._lockedAllExceptElementsList, saveMode);
				}
			}
			ConfigurationPropertyCollection properties = Properties;
			ConfigurationPropertyCollection configurationPropertyCollection = null;
			for (int i = 0; i < sourceElement.Values.Count; i++)
			{
				string key = sourceElement.Values.GetKey(i);
				object obj = sourceElement.Values[i];
				ConfigurationProperty configurationProperty = sourceElement.Properties[key];
				if (configurationProperty != null && (configurationPropertyCollection == null || configurationPropertyCollection.Contains(configurationProperty.Name)))
				{
					if (typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
					{
						flag = true;
					}
					else if (obj != s_nullPropertyValue && !properties.Contains(key))
					{
						ConfigurationValueFlags valueFlags = sourceElement.Values.RetrieveFlags(key);
						_values.SetValue(key, obj, valueFlags, null);
						properties.Add(configurationProperty);
					}
				}
			}
			foreach (ConfigurationProperty property in Properties)
			{
				if (property == null || (configurationPropertyCollection != null && !configurationPropertyCollection.Contains(property.Name)))
				{
					continue;
				}
				if (typeof(ConfigurationElement).IsAssignableFrom(property.Type))
				{
					flag = true;
					continue;
				}
				object obj2 = sourceElement.Values[property.Name];
				if ((property.IsRequired || saveMode == ConfigurationSaveMode.Full) && (obj2 == null || obj2 == s_nullPropertyValue) && property.DefaultValue != null)
				{
					obj2 = property.DefaultValue;
				}
				if (obj2 == null || obj2 == s_nullPropertyValue)
				{
					continue;
				}
				object obj3 = null;
				if (parentElement != null)
				{
					obj3 = parentElement.Values[property.Name];
				}
				if (obj3 == null)
				{
					obj3 = property.DefaultValue;
				}
				switch (saveMode)
				{
				case ConfigurationSaveMode.Minimal:
					if (!object.Equals(obj2, obj3) || property.IsRequired)
					{
						_values[property.Name] = obj2;
					}
					break;
				case ConfigurationSaveMode.Modified:
				{
					bool flag2 = sourceElement.Values.IsModified(property.Name);
					bool flag3 = sourceElement.Values.IsInherited(property.Name);
					if (property.IsRequired || flag2 || !flag3 || (parentElement == null && flag3 && !object.Equals(obj2, obj3)))
					{
						_values[property.Name] = obj2;
					}
					break;
				}
				case ConfigurationSaveMode.Full:
					if (obj2 != null && obj2 != s_nullPropertyValue)
					{
						_values[property.Name] = obj2;
					}
					else
					{
						_values[property.Name] = obj3;
					}
					break;
				}
			}
			if (!flag)
			{
				return;
			}
			foreach (ConfigurationProperty property2 in Properties)
			{
				if (typeof(ConfigurationElement).IsAssignableFrom(property2.Type))
				{
					ConfigurationElement parentElement2 = (ConfigurationElement)(parentElement?[property2]);
					ConfigurationElement configurationElement = (ConfigurationElement)this[property2];
					if ((ConfigurationElement)sourceElement[property2] != null)
					{
						configurationElement.Unmerge((ConfigurationElement)sourceElement[property2], parentElement2, saveMode);
					}
				}
			}
		}

		protected internal virtual bool SerializeToXmlElement(XmlWriter writer, string elementName)
		{
			bool flag = _bDataToWrite;
			if ((_lockedElementsList != null && _lockedElementsList.DefinedInParent(elementName)) || (_lockedAllExceptElementsList != null && _lockedAllExceptElementsList.HasParentElements && !_lockedAllExceptElementsList.DefinedInParent(elementName)))
			{
				return flag;
			}
			if (SerializeElement(null, serializeCollectionKey: false))
			{
				writer?.WriteStartElement(elementName);
				flag |= SerializeElement(writer, serializeCollectionKey: false);
				writer?.WriteEndElement();
			}
			return flag;
		}

		protected internal virtual bool SerializeElement(XmlWriter writer, bool serializeCollectionKey)
		{
			PreSerialize(writer);
			bool flag = _bDataToWrite;
			bool flag2 = false;
			bool flag3 = false;
			ConfigurationPropertyCollection properties = Properties;
			ConfigurationPropertyCollection configurationPropertyCollection = null;
			for (int i = 0; i < _values.Count; i++)
			{
				string key = _values.GetKey(i);
				object obj = _values[i];
				ConfigurationProperty configurationProperty = properties[key];
				if (configurationProperty == null || (configurationPropertyCollection != null && !configurationPropertyCollection.Contains(configurationProperty.Name)))
				{
					continue;
				}
				if (typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
				{
					flag2 = true;
					continue;
				}
				if ((_lockedAllExceptAttributesList != null && _lockedAllExceptAttributesList.HasParentElements && !_lockedAllExceptAttributesList.DefinedInParent(configurationProperty.Name)) || (_lockedAttributesList != null && _lockedAttributesList.DefinedInParent(configurationProperty.Name)))
				{
					if (configurationProperty.IsRequired)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_base_required_attribute_locked", configurationProperty.Name));
					}
					obj = s_nullPropertyValue;
				}
				if (obj != s_nullPropertyValue && (!serializeCollectionKey || configurationProperty.IsKey))
				{
					string text = null;
					if (obj is InvalidPropValue)
					{
						text = ((InvalidPropValue)obj).Value;
					}
					else
					{
						configurationProperty.Validate(obj);
						text = configurationProperty.ConvertToString(obj);
					}
					if (text != null)
					{
						writer?.WriteAttributeString(configurationProperty.Name, text);
					}
					flag = flag || text != null;
				}
			}
			if (!serializeCollectionKey)
			{
				flag |= SerializeLockList(_lockedAttributesList, "lockAttributes", writer);
				flag |= SerializeLockList(_lockedAllExceptAttributesList, "lockAllAttributesExcept", writer);
				flag |= SerializeLockList(_lockedElementsList, "lockElements", writer);
				flag |= SerializeLockList(_lockedAllExceptElementsList, "lockAllElementsExcept", writer);
				if ((_fItemLocked & ConfigurationValueFlags.Locked) != 0 && (_fItemLocked & ConfigurationValueFlags.Inherited) == 0 && (_fItemLocked & ConfigurationValueFlags.XMLParentInherited) == 0)
				{
					flag = true;
					writer?.WriteAttributeString("lockItem", true.ToString().ToLower(CultureInfo.InvariantCulture));
				}
			}
			if (flag2)
			{
				for (int j = 0; j < _values.Count; j++)
				{
					string key2 = _values.GetKey(j);
					object obj2 = _values[j];
					ConfigurationProperty configurationProperty2 = properties[key2];
					if ((serializeCollectionKey && !configurationProperty2.IsKey) || !(obj2 is ConfigurationElement) || (_lockedElementsList != null && _lockedElementsList.DefinedInParent(key2)) || (_lockedAllExceptElementsList != null && _lockedAllExceptElementsList.HasParentElements && !_lockedAllExceptElementsList.DefinedInParent(key2)))
					{
						continue;
					}
					ConfigurationElement configurationElement = (ConfigurationElement)obj2;
					if (configurationProperty2.Name != ConfigurationProperty.DefaultCollectionPropertyName)
					{
						flag |= configurationElement.SerializeToXmlElement(writer, configurationProperty2.Name);
						continue;
					}
					if (!flag3)
					{
						configurationElement._lockedAttributesList = null;
						configurationElement._lockedAllExceptAttributesList = null;
						configurationElement._lockedElementsList = null;
						configurationElement._lockedAllExceptElementsList = null;
						flag |= configurationElement.SerializeElement(writer, serializeCollectionKey: false);
						flag3 = true;
						continue;
					}
					throw new ConfigurationErrorsException(SR.GetString("Config_base_element_cannot_have_multiple_child_elements", configurationProperty2.Name));
				}
			}
			return flag;
		}

		private bool SerializeLockList(ConfigurationLockCollection list, string elementKey, XmlWriter writer)
		{
			StringBuilder stringBuilder = new StringBuilder();
			if (list != null)
			{
				foreach (string item in list)
				{
					if (!list.DefinedInParent(item))
					{
						if (stringBuilder.Length != 0)
						{
							stringBuilder.Append(',');
						}
						stringBuilder.Append(item);
					}
				}
			}
			if (writer != null && stringBuilder.Length != 0)
			{
				writer.WriteAttributeString(elementKey, stringBuilder.ToString());
			}
			return stringBuilder.Length != 0;
		}

		internal void ReportInvalidLock(string attribToLockTrim, ConfigurationLockCollectionType lockedType, ConfigurationValue value, string collectionProperties)
		{
			StringBuilder stringBuilder = new StringBuilder();
			if (!string.IsNullOrEmpty(collectionProperties) && (lockedType == ConfigurationLockCollectionType.LockedElements || lockedType == ConfigurationLockCollectionType.LockedElementsExceptionList))
			{
				if (stringBuilder.Length != 0)
				{
					stringBuilder.Append(',');
				}
				stringBuilder.Append(collectionProperties);
			}
			foreach (object property in Properties)
			{
				ConfigurationProperty configurationProperty = (ConfigurationProperty)property;
				if (!(configurationProperty.Name != "lockAttributes") || !(configurationProperty.Name != "lockAllAttributesExcept") || !(configurationProperty.Name != "lockElements") || !(configurationProperty.Name != "lockAllElementsExcept"))
				{
					continue;
				}
				if (lockedType == ConfigurationLockCollectionType.LockedElements || lockedType == ConfigurationLockCollectionType.LockedElementsExceptionList)
				{
					if (typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
					{
						if (stringBuilder.Length != 0)
						{
							stringBuilder.Append(", ");
						}
						stringBuilder.Append("'");
						stringBuilder.Append(configurationProperty.Name);
						stringBuilder.Append("'");
					}
				}
				else if (!typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
				{
					if (stringBuilder.Length != 0)
					{
						stringBuilder.Append(", ");
					}
					stringBuilder.Append("'");
					stringBuilder.Append(configurationProperty.Name);
					stringBuilder.Append("'");
				}
			}
			string text = null;
			text = ((lockedType == ConfigurationLockCollectionType.LockedElements || lockedType == ConfigurationLockCollectionType.LockedElementsExceptionList) ? ((value == null) ? SR.GetString("Config_base_invalid_element_to_lock_by_add") : SR.GetString("Config_base_invalid_element_to_lock")) : ((value == null) ? SR.GetString("Config_base_invalid_attribute_to_lock_by_add") : SR.GetString("Config_base_invalid_attribute_to_lock")));
			if (value != null)
			{
				throw new ConfigurationErrorsException(string.Format(CultureInfo.CurrentCulture, text, attribToLockTrim, stringBuilder.ToString()), value.SourceInfo.FileName, value.SourceInfo.LineNumber);
			}
			throw new ConfigurationErrorsException(string.Format(CultureInfo.CurrentCulture, text, attribToLockTrim, stringBuilder.ToString()));
		}

		private ConfigurationLockCollection ParseLockedAttributes(ConfigurationValue value, ConfigurationLockCollectionType lockType)
		{
			ConfigurationLockCollection configurationLockCollection = new ConfigurationLockCollection(this, lockType);
			string text = (string)value.Value;
			if (string.IsNullOrEmpty(text))
			{
				switch (lockType)
				{
				case ConfigurationLockCollectionType.LockedAttributes:
					throw new ConfigurationErrorsException(SR.GetString("Empty_attribute", "lockAttributes"), value.SourceInfo.FileName, value.SourceInfo.LineNumber);
				case ConfigurationLockCollectionType.LockedElements:
					throw new ConfigurationErrorsException(SR.GetString("Empty_attribute", "lockElements"), value.SourceInfo.FileName, value.SourceInfo.LineNumber);
				case ConfigurationLockCollectionType.LockedExceptionList:
					throw new ConfigurationErrorsException(SR.GetString("Config_empty_lock_attributes_except", "lockAllAttributesExcept", "lockAttributes"), value.SourceInfo.FileName, value.SourceInfo.LineNumber);
				case ConfigurationLockCollectionType.LockedElementsExceptionList:
					throw new ConfigurationErrorsException(SR.GetString("Config_empty_lock_element_except", "lockAllElementsExcept", "lockElements"), value.SourceInfo.FileName, value.SourceInfo.LineNumber);
				}
			}
			string[] array = text.Split(',', ':', ';');
			string[] array2 = array;
			foreach (string text2 in array2)
			{
				string text3 = text2.Trim();
				if (string.IsNullOrEmpty(text3))
				{
					continue;
				}
				ConfigurationProperty configurationProperty;
				if ((lockType != ConfigurationLockCollectionType.LockedElements && lockType != ConfigurationLockCollectionType.LockedAttributes) || !(text3 == "*"))
				{
					configurationProperty = Properties[text3];
					if (configurationProperty != null)
					{
						switch (text3)
						{
						case "lockAttributes":
						case "lockAllAttributesExcept":
						case "lockElements":
							goto IL_01f8;
						}
						if ((lockType == ConfigurationLockCollectionType.LockedElements || lockType == ConfigurationLockCollectionType.LockedElementsExceptionList || !typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type)) && ((lockType != ConfigurationLockCollectionType.LockedElements && lockType != ConfigurationLockCollectionType.LockedElementsExceptionList) || typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type)))
						{
							goto IL_025e;
						}
					}
					goto IL_01f8;
				}
				goto IL_0290;
				IL_0290:
				configurationLockCollection.Add(text3, ConfigurationValueFlags.Default);
				continue;
				IL_025e:
				if (configurationProperty != null && configurationProperty.IsRequired)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_required_attribute_lock_attempt", configurationProperty.Name));
				}
				goto IL_0290;
				IL_01f8:
				ConfigurationElementCollection configurationElementCollection = this as ConfigurationElementCollection;
				if (configurationElementCollection == null && Properties.DefaultCollectionProperty != null)
				{
					configurationElementCollection = this[Properties.DefaultCollectionProperty] as ConfigurationElementCollection;
				}
				if (configurationElementCollection == null || lockType == ConfigurationLockCollectionType.LockedAttributes || lockType == ConfigurationLockCollectionType.LockedExceptionList)
				{
					ReportInvalidLock(text3, lockType, value, null);
				}
				else if (!configurationElementCollection.IsLockableElement(text3))
				{
					ReportInvalidLock(text3, lockType, value, configurationElementCollection.LockableElements);
				}
				goto IL_025e;
			}
			return configurationLockCollection;
		}

		private StringCollection IntersectLockCollections(ConfigurationLockCollection Collection1, ConfigurationLockCollection Collection2)
		{
			ConfigurationLockCollection configurationLockCollection = ((Collection1.Count < Collection2.Count) ? Collection1 : Collection2);
			ConfigurationLockCollection configurationLockCollection2 = ((Collection1.Count >= Collection2.Count) ? Collection1 : Collection2);
			StringCollection stringCollection = new StringCollection();
			foreach (string item in configurationLockCollection)
			{
				if (configurationLockCollection2.Contains(item) || item == ElementTagName)
				{
					stringCollection.Add(item);
				}
			}
			return stringCollection;
		}

		protected internal virtual void DeserializeElement(XmlReader reader, bool serializeCollectionKey)
		{
			ConfigurationPropertyCollection properties = Properties;
			ConfigurationValue configurationValue = null;
			ConfigurationValue configurationValue2 = null;
			ConfigurationValue configurationValue3 = null;
			ConfigurationValue configurationValue4 = null;
			bool flag = false;
			_bElementPresent = true;
			ConfigurationElement configurationElement = null;
			ConfigurationProperty configurationProperty = properties?.DefaultCollectionProperty;
			if (configurationProperty != null)
			{
				configurationElement = (ConfigurationElement)this[configurationProperty];
			}
			_elementTagName = reader.Name;
			PropertySourceInfo sourceInfo = new PropertySourceInfo(reader);
			_values.SetValue(reader.Name, null, ConfigurationValueFlags.Modified, sourceInfo);
			_values.SetValue("", configurationElement, ConfigurationValueFlags.Modified, sourceInfo);
			if ((_lockedElementsList != null && (_lockedElementsList.Contains(reader.Name) || (_lockedElementsList.Contains("*") && reader.Name != ElementTagName))) || (_lockedAllExceptElementsList != null && _lockedAllExceptElementsList.Count != 0 && !_lockedAllExceptElementsList.Contains(reader.Name)) || ((_fItemLocked & ConfigurationValueFlags.Locked) != 0 && (_fItemLocked & ConfigurationValueFlags.Inherited) != 0))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_element_locked", reader.Name), reader);
			}
			if (reader.AttributeCount > 0)
			{
				while (reader.MoveToNextAttribute())
				{
					string name = reader.Name;
					if (((_lockedAttributesList != null && (_lockedAttributesList.Contains(name) || _lockedAttributesList.Contains("*"))) || (_lockedAllExceptAttributesList != null && !_lockedAllExceptAttributesList.Contains(name))) && name != "lockAttributes" && name != "lockAllAttributesExcept")
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", name), reader);
					}
					ConfigurationProperty configurationProperty2 = properties?[name];
					if (configurationProperty2 != null)
					{
						if (serializeCollectionKey && !configurationProperty2.IsKey)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_attribute", name), reader);
						}
						_values.SetValue(name, DeserializePropertyValue(configurationProperty2, reader), ConfigurationValueFlags.Modified, new PropertySourceInfo(reader));
						continue;
					}
					switch (name)
					{
					case "lockItem":
						try
						{
							flag = bool.Parse(reader.Value);
						}
						catch
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_invalid_boolean_attribute", name), reader);
						}
						break;
					case "lockAttributes":
						configurationValue = new ConfigurationValue(reader.Value, ConfigurationValueFlags.Default, new PropertySourceInfo(reader));
						break;
					case "lockAllAttributesExcept":
						configurationValue2 = new ConfigurationValue(reader.Value, ConfigurationValueFlags.Default, new PropertySourceInfo(reader));
						break;
					case "lockElements":
						configurationValue3 = new ConfigurationValue(reader.Value, ConfigurationValueFlags.Default, new PropertySourceInfo(reader));
						break;
					case "lockAllElementsExcept":
						configurationValue4 = new ConfigurationValue(reader.Value, ConfigurationValueFlags.Default, new PropertySourceInfo(reader));
						break;
					default:
						if (serializeCollectionKey || !OnDeserializeUnrecognizedAttribute(name, reader.Value))
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_attribute", name), reader);
						}
						break;
					}
				}
			}
			reader.MoveToElement();
			try
			{
				HybridDictionary hybridDictionary = new HybridDictionary();
				if (!reader.IsEmptyElement)
				{
					while (reader.Read())
					{
						if (reader.NodeType == XmlNodeType.Element)
						{
							string name2 = reader.Name;
							CheckLockedElement(name2, null);
							ConfigurationProperty configurationProperty3 = properties?[name2];
							if (configurationProperty3 != null)
							{
								if (!typeof(ConfigurationElement).IsAssignableFrom(configurationProperty3.Type))
								{
									throw new ConfigurationErrorsException(SR.GetString("Config_base_property_is_not_a_configuration_element", name2), reader);
								}
								if (hybridDictionary.Contains(name2))
								{
									throw new ConfigurationErrorsException(SR.GetString("Config_base_element_cannot_have_multiple_child_elements", name2), reader);
								}
								hybridDictionary.Add(name2, name2);
								ConfigurationElement configurationElement2 = (ConfigurationElement)this[configurationProperty3];
								configurationElement2.DeserializeElement(reader, serializeCollectionKey);
								ValidateElement(configurationElement2, configurationProperty3.Validator, recursive: false);
							}
							else if (!OnDeserializeUnrecognizedElement(name2, reader) && (configurationElement == null || !configurationElement.OnDeserializeUnrecognizedElement(name2, reader)))
							{
								throw new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_element_name", name2), reader);
							}
						}
						else
						{
							if (reader.NodeType == XmlNodeType.EndElement)
							{
								break;
							}
							if (reader.NodeType == XmlNodeType.CDATA || reader.NodeType == XmlNodeType.Text)
							{
								throw new ConfigurationErrorsException(SR.GetString("Config_base_section_invalid_content"), reader);
							}
						}
					}
				}
				EnsureRequiredProperties(serializeCollectionKey);
				ValidateElement(this, null, recursive: false);
			}
			catch (ConfigurationException ex)
			{
				if (ex.Filename == null || ex.Filename.Length == 0)
				{
					throw new ConfigurationErrorsException(ex.Message, reader);
				}
				throw ex;
			}
			if (flag)
			{
				SetLocked();
				_fItemLocked = ConfigurationValueFlags.Locked;
			}
			if (configurationValue != null)
			{
				if (_lockedAttributesList == null)
				{
					_lockedAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedAttributes);
				}
				foreach (string item in ParseLockedAttributes(configurationValue, ConfigurationLockCollectionType.LockedAttributes))
				{
					if (!_lockedAttributesList.Contains(item))
					{
						_lockedAttributesList.Add(item, ConfigurationValueFlags.Default);
					}
					else
					{
						_lockedAttributesList.Add(item, ConfigurationValueFlags.Inherited | ConfigurationValueFlags.Modified);
					}
				}
			}
			if (configurationValue2 != null)
			{
				ConfigurationLockCollection configurationLockCollection = ParseLockedAttributes(configurationValue2, ConfigurationLockCollectionType.LockedExceptionList);
				if (_lockedAllExceptAttributesList == null)
				{
					_lockedAllExceptAttributesList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedExceptionList, string.Empty, configurationLockCollection);
					_lockedAllExceptAttributesList.ClearSeedList();
				}
				StringCollection stringCollection = IntersectLockCollections(_lockedAllExceptAttributesList, configurationLockCollection);
				_lockedAllExceptAttributesList.ClearInternal(useSeedIfAvailble: false);
				StringEnumerator enumerator2 = stringCollection.GetEnumerator();
				try
				{
					while (enumerator2.MoveNext())
					{
						string current = enumerator2.Current;
						_lockedAllExceptAttributesList.Add(current, ConfigurationValueFlags.Default);
					}
				}
				finally
				{
					if (enumerator2 is IDisposable disposable)
					{
						disposable.Dispose();
					}
				}
			}
			if (configurationValue3 != null)
			{
				if (_lockedElementsList == null)
				{
					_lockedElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElements);
				}
				ConfigurationLockCollection configurationLockCollection2 = ParseLockedAttributes(configurationValue3, ConfigurationLockCollectionType.LockedElements);
				ConfigurationElementCollection configurationElementCollection = null;
				if (properties.DefaultCollectionProperty != null && this[properties.DefaultCollectionProperty] is ConfigurationElementCollection configurationElementCollection2 && configurationElementCollection2._lockedElementsList == null)
				{
					configurationElementCollection2._lockedElementsList = _lockedElementsList;
				}
				foreach (string item2 in configurationLockCollection2)
				{
					if (_lockedElementsList.Contains(item2))
					{
						continue;
					}
					_lockedElementsList.Add(item2, ConfigurationValueFlags.Default);
					ConfigurationProperty configurationProperty4 = Properties[item2];
					if (configurationProperty4 != null && typeof(ConfigurationElement).IsAssignableFrom(configurationProperty4.Type))
					{
						((ConfigurationElement)this[item2]).SetLocked();
					}
					if (!(item2 == "*"))
					{
						continue;
					}
					foreach (ConfigurationProperty property in Properties)
					{
						if (!string.IsNullOrEmpty(property.Name) && typeof(ConfigurationElement).IsAssignableFrom(property.Type))
						{
							((ConfigurationElement)this[property]).SetLocked();
						}
					}
				}
			}
			if (configurationValue4 != null)
			{
				ConfigurationLockCollection configurationLockCollection3 = ParseLockedAttributes(configurationValue4, ConfigurationLockCollectionType.LockedElementsExceptionList);
				if (_lockedAllExceptElementsList == null)
				{
					_lockedAllExceptElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElementsExceptionList, _elementTagName, configurationLockCollection3);
					_lockedAllExceptElementsList.ClearSeedList();
				}
				StringCollection stringCollection2 = IntersectLockCollections(_lockedAllExceptElementsList, configurationLockCollection3);
				ConfigurationElementCollection configurationElementCollection3 = null;
				if (properties.DefaultCollectionProperty != null && this[properties.DefaultCollectionProperty] is ConfigurationElementCollection configurationElementCollection4 && configurationElementCollection4._lockedAllExceptElementsList == null)
				{
					configurationElementCollection4._lockedAllExceptElementsList = _lockedAllExceptElementsList;
				}
				_lockedAllExceptElementsList.ClearInternal(useSeedIfAvailble: false);
				StringEnumerator enumerator5 = stringCollection2.GetEnumerator();
				try
				{
					while (enumerator5.MoveNext())
					{
						string current2 = enumerator5.Current;
						if (!_lockedAllExceptElementsList.Contains(current2) || current2 == ElementTagName)
						{
							_lockedAllExceptElementsList.Add(current2, ConfigurationValueFlags.Default);
						}
					}
				}
				finally
				{
					if (enumerator5 is IDisposable disposable2)
					{
						disposable2.Dispose();
					}
				}
				foreach (ConfigurationProperty property2 in Properties)
				{
					if (!string.IsNullOrEmpty(property2.Name) && !_lockedAllExceptElementsList.Contains(property2.Name) && typeof(ConfigurationElement).IsAssignableFrom(property2.Type))
					{
						((ConfigurationElement)this[property2]).SetLocked();
					}
				}
			}
			if (configurationProperty != null)
			{
				configurationElement = (ConfigurationElement)this[configurationProperty];
				if (_lockedElementsList == null)
				{
					_lockedElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElements);
				}
				configurationElement._lockedElementsList = _lockedElementsList;
				if (_lockedAllExceptElementsList == null)
				{
					_lockedAllExceptElementsList = new ConfigurationLockCollection(this, ConfigurationLockCollectionType.LockedElementsExceptionList, reader.Name);
					_lockedAllExceptElementsList.ClearSeedList();
				}
				configurationElement._lockedAllExceptElementsList = _lockedAllExceptElementsList;
			}
			PostDeserialize();
		}

		private object DeserializePropertyValue(ConfigurationProperty prop, XmlReader reader)
		{
			string value = reader.Value;
			object obj = null;
			try
			{
				obj = prop.ConvertFromString(value);
				prop.Validate(obj);
				return obj;
			}
			catch (ConfigurationException ex)
			{
				if (string.IsNullOrEmpty(ex.Filename))
				{
					ex = new ConfigurationErrorsException(ex.Message, reader);
				}
				return new InvalidPropValue(value, ex);
			}
			catch
			{
				return obj;
			}
		}

		internal static void ValidateElement(ConfigurationElement elem, ConfigurationValidatorBase propValidator, bool recursive)
		{
			ConfigurationValidatorBase configurationValidatorBase = propValidator;
			if (configurationValidatorBase == null && elem.ElementProperty != null)
			{
				configurationValidatorBase = elem.ElementProperty.Validator;
				if (configurationValidatorBase != null && !configurationValidatorBase.CanValidate(elem.GetType()))
				{
					throw new ConfigurationErrorsException(SR.GetString("Validator_does_not_support_elem_type", elem.GetType().Name));
				}
			}
			try
			{
				configurationValidatorBase?.Validate(elem);
			}
			catch (ConfigurationException)
			{
				throw;
			}
			catch (Exception ex2)
			{
				throw new ConfigurationErrorsException(SR.GetString("Validator_element_not_valid", elem._elementTagName, ex2.Message));
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Validator_element_not_valid", elem._elementTagName, ExceptionUtil.NoExceptionInformation));
			}
			if (!recursive)
			{
				return;
			}
			if (elem is ConfigurationElementCollection && elem is ConfigurationElementCollection)
			{
				IEnumerator elementsEnumerator = ((ConfigurationElementCollection)elem).GetElementsEnumerator();
				while (elementsEnumerator.MoveNext())
				{
					ValidateElement((ConfigurationElement)elementsEnumerator.Current, null, recursive: true);
				}
			}
			for (int i = 0; i < elem.Values.Count; i++)
			{
				if (elem.Values[i] is ConfigurationElement elem2)
				{
					ValidateElement(elem2, null, recursive: true);
				}
			}
		}

		private void EnsureRequiredProperties(bool ensureKeysOnly)
		{
			ConfigurationPropertyCollection properties = Properties;
			if (properties == null)
			{
				return;
			}
			foreach (ConfigurationProperty item in properties)
			{
				if (item.IsRequired && !_values.Contains(item.Name) && (!ensureKeysOnly || item.IsKey))
				{
					_values[item.Name] = OnRequiredPropertyNotFound(item.Name);
				}
			}
		}

		protected virtual object OnRequiredPropertyNotFound(string name)
		{
			throw new ConfigurationErrorsException(SR.GetString("Config_base_required_attribute_missing", name), PropertyFileName(name), PropertyLineNumber(name));
		}

		protected virtual void PostDeserialize()
		{
		}

		protected virtual void PreSerialize(XmlWriter writer)
		{
		}

		protected virtual bool OnDeserializeUnrecognizedAttribute(string name, string value)
		{
			return false;
		}

		protected virtual bool OnDeserializeUnrecognizedElement(string elementName, XmlReader reader)
		{
			return false;
		}

		internal ConfigurationLockCollection UnMergeLockList(ConfigurationLockCollection sourceLockList, ConfigurationLockCollection parentLockList, ConfigurationSaveMode saveMode)
		{
			if (!sourceLockList.ExceptionList)
			{
				switch (saveMode)
				{
				case ConfigurationSaveMode.Modified:
				{
					ConfigurationLockCollection configurationLockCollection2 = new ConfigurationLockCollection(this, sourceLockList.LockType);
					{
						foreach (string sourceLock in sourceLockList)
						{
							if (!parentLockList.Contains(sourceLock) || sourceLockList.IsValueModified(sourceLock))
							{
								configurationLockCollection2.Add(sourceLock, ConfigurationValueFlags.Default);
							}
						}
						return configurationLockCollection2;
					}
				}
				case ConfigurationSaveMode.Minimal:
				{
					ConfigurationLockCollection configurationLockCollection = new ConfigurationLockCollection(this, sourceLockList.LockType);
					{
						foreach (string sourceLock2 in sourceLockList)
						{
							if (!parentLockList.Contains(sourceLock2))
							{
								configurationLockCollection.Add(sourceLock2, ConfigurationValueFlags.Default);
							}
						}
						return configurationLockCollection;
					}
				}
				}
			}
			else if (saveMode == ConfigurationSaveMode.Modified || saveMode == ConfigurationSaveMode.Minimal)
			{
				bool flag = false;
				if (sourceLockList.Count == parentLockList.Count)
				{
					flag = true;
					foreach (string sourceLock3 in sourceLockList)
					{
						if (!parentLockList.Contains(sourceLock3) || (sourceLockList.IsValueModified(sourceLock3) && saveMode == ConfigurationSaveMode.Modified))
						{
							flag = false;
						}
					}
				}
				if (flag)
				{
					return null;
				}
			}
			return sourceLockList;
		}

		internal static bool IsLockAttributeName(string name)
		{
			if (!StringUtil.StartsWith(name, "lock"))
			{
				return false;
			}
			string[] array = s_lockAttributeNames;
			foreach (string text in array)
			{
				if (name == text)
				{
					return true;
				}
			}
			return false;
		}
	}
	public abstract class ConfigurationSection : ConfigurationElement
	{
		private SectionInformation _section;

		public SectionInformation SectionInformation => _section;

		protected ConfigurationSection()
		{
			_section = new SectionInformation(this);
		}

		protected internal virtual object GetRuntimeObject()
		{
			return this;
		}

		protected internal override bool IsModified()
		{
			if (!SectionInformation.IsModifiedFlags())
			{
				return base.IsModified();
			}
			return true;
		}

		protected internal override void ResetModified()
		{
			SectionInformation.ResetModifiedFlags();
			base.ResetModified();
		}

		protected internal virtual void DeserializeSection(XmlReader reader)
		{
			if (!reader.Read() || reader.NodeType != XmlNodeType.Element)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_expected_to_find_element"), reader);
			}
			DeserializeElement(reader, serializeCollectionKey: false);
		}

		protected internal virtual string SerializeSection(ConfigurationElement parentElement, string name, ConfigurationSaveMode saveMode)
		{
			ConfigurationElement.ValidateElement(this, null, recursive: true);
			ConfigurationElement configurationElement = CreateElement(GetType());
			configurationElement.Unmerge(this, parentElement, saveMode);
			StringWriter stringWriter = new StringWriter(CultureInfo.InvariantCulture);
			XmlTextWriter xmlTextWriter = new XmlTextWriter(stringWriter);
			xmlTextWriter.Formatting = Formatting.Indented;
			xmlTextWriter.Indentation = 4;
			xmlTextWriter.IndentChar = ' ';
			configurationElement.DataToWriteInternal = saveMode != ConfigurationSaveMode.Minimal;
			configurationElement.SerializeToXmlElement(xmlTextWriter, name);
			xmlTextWriter.Flush();
			return stringWriter.ToString();
		}
	}
	public sealed class AppSettingsSection : ConfigurationSection
	{
		private static ConfigurationPropertyCollection s_properties;

		private static ConfigurationProperty s_propAppSettings;

		private static ConfigurationProperty s_propFile;

		private KeyValueInternalCollection _KeyValueCollection;

		protected internal override ConfigurationPropertyCollection Properties => EnsureStaticPropertyBag();

		internal NameValueCollection InternalSettings
		{
			get
			{
				if (_KeyValueCollection == null)
				{
					_KeyValueCollection = new KeyValueInternalCollection(this);
				}
				return _KeyValueCollection;
			}
		}

		[ConfigurationProperty("", IsDefaultCollection = true)]
		public KeyValueConfigurationCollection Settings => (KeyValueConfigurationCollection)base[s_propAppSettings];

		[ConfigurationProperty("file", DefaultValue = "")]
		public string File
		{
			get
			{
				string text = (string)base[s_propFile];
				if (text == null)
				{
					return string.Empty;
				}
				return text;
			}
			set
			{
				base[s_propFile] = value;
			}
		}

		private static ConfigurationPropertyCollection EnsureStaticPropertyBag()
		{
			if (s_properties == null)
			{
				s_propAppSettings = new ConfigurationProperty(null, typeof(KeyValueConfigurationCollection), null, ConfigurationPropertyOptions.IsDefaultCollection);
				s_propFile = new ConfigurationProperty("file", typeof(string), string.Empty, ConfigurationPropertyOptions.None);
				ConfigurationPropertyCollection configurationPropertyCollection = new ConfigurationPropertyCollection();
				configurationPropertyCollection.Add(s_propAppSettings);
				configurationPropertyCollection.Add(s_propFile);
				s_properties = configurationPropertyCollection;
			}
			return s_properties;
		}

		public AppSettingsSection()
		{
			EnsureStaticPropertyBag();
		}

		protected internal override object GetRuntimeObject()
		{
			SetReadOnly();
			return InternalSettings;
		}

		protected internal override void Reset(ConfigurationElement parentSection)
		{
			_KeyValueCollection = null;
			base.Reset(parentSection);
			if (!string.IsNullOrEmpty((string)base[s_propFile]))
			{
				SetPropertyValue(s_propFile, null, ignoreLocks: true);
			}
		}

		protected internal override bool IsModified()
		{
			return base.IsModified();
		}

		protected internal override string SerializeSection(ConfigurationElement parentElement, string name, ConfigurationSaveMode saveMode)
		{
			return base.SerializeSection(parentElement, name, saveMode);
		}

		protected internal override void DeserializeElement(XmlReader reader, bool serializeCollectionKey)
		{
			string name = reader.Name;
			base.DeserializeElement(reader, serializeCollectionKey);
			if (File == null || File.Length <= 0)
			{
				return;
			}
			string source = base.ElementInformation.Source;
			string text;
			if (string.IsNullOrEmpty(source))
			{
				text = File;
			}
			else
			{
				string directoryName = Path.GetDirectoryName(source);
				text = Path.Combine(directoryName, File);
			}
			if (!System.IO.File.Exists(text))
			{
				return;
			}
			int lineOffset = 0;
			string rawXml = null;
			using (Stream stream = new FileStream(text, FileMode.Open, FileAccess.Read, FileShare.Read))
			{
				using XmlUtil xmlUtil = new XmlUtil(stream, text, readToFirstElement: true);
				if (xmlUtil.Reader.Name != name)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_name_value_file_section_file_invalid_root", name), xmlUtil);
				}
				lineOffset = xmlUtil.Reader.LineNumber;
				rawXml = xmlUtil.CopySection();
				while (!xmlUtil.Reader.EOF)
				{
					XmlNodeType nodeType = xmlUtil.Reader.NodeType;
					if (nodeType != XmlNodeType.Comment)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_source_file_format"), xmlUtil);
					}
					xmlUtil.Reader.Read();
				}
			}
			ConfigXmlReader configXmlReader = new ConfigXmlReader(rawXml, text, lineOffset);
			configXmlReader.Read();
			if (configXmlReader.MoveToNextAttribute())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_attribute", configXmlReader.Name), (XmlReader)configXmlReader);
			}
			configXmlReader.MoveToElement();
			base.DeserializeElement(configXmlReader, serializeCollectionKey);
		}
	}
}
namespace System.Configuration.Internal
{
	[ComVisible(false)]
	public interface IInternalConfigRecord
	{
		string ConfigPath { get; }

		string StreamName { get; }

		bool HasInitErrors { get; }

		void ThrowIfInitErrors();

		object GetSection(string configKey);

		object GetLkgSection(string configKey);

		void RefreshSection(string configKey);

		void Remove();
	}
}
namespace System.Configuration
{
	[DebuggerDisplay("ConfigPath = {ConfigPath}")]
	internal abstract class BaseConfigurationRecord : IInternalConfigRecord
	{
		protected class ConfigRecordStreamInfo
		{
			private bool _hasStream;

			private string _streamname;

			private object _streamVersion;

			private Encoding _encoding;

			private StreamChangeCallback _callbackDelegate;

			private HybridDictionary _streamInfos;

			internal bool HasStream
			{
				get
				{
					return _hasStream;
				}
				set
				{
					_hasStream = value;
				}
			}

			internal string StreamName
			{
				get
				{
					return _streamname;
				}
				set
				{
					_streamname = value;
				}
			}

			internal object StreamVersion
			{
				get
				{
					return _streamVersion;
				}
				set
				{
					_streamVersion = value;
				}
			}

			internal Encoding StreamEncoding
			{
				get
				{
					return _encoding;
				}
				set
				{
					_encoding = value;
				}
			}

			internal StreamChangeCallback CallbackDelegate
			{
				get
				{
					return _callbackDelegate;
				}
				set
				{
					_callbackDelegate = value;
				}
			}

			internal HybridDictionary StreamInfos
			{
				get
				{
					if (_streamInfos == null)
					{
						_streamInfos = new HybridDictionary(caseInsensitive: true);
					}
					return _streamInfos;
				}
			}

			internal bool HasStreamInfos => _streamInfos != null;

			internal ConfigRecordStreamInfo()
			{
				_encoding = Encoding.UTF8;
			}

			internal void ClearStreamInfos()
			{
				_streamInfos = null;
			}
		}

		private class IndirectLocationInputComparer : IComparer<SectionInput>
		{
			public int Compare(SectionInput x, SectionInput y)
			{
				if (object.ReferenceEquals(x, y))
				{
					return 0;
				}
				string targetConfigPath = x.SectionXmlInfo.TargetConfigPath;
				string targetConfigPath2 = y.SectionXmlInfo.TargetConfigPath;
				if (UrlPath.IsSubpath(targetConfigPath, targetConfigPath2))
				{
					return 1;
				}
				if (UrlPath.IsSubpath(targetConfigPath2, targetConfigPath))
				{
					return -1;
				}
				string definitionConfigPath = x.SectionXmlInfo.DefinitionConfigPath;
				string definitionConfigPath2 = y.SectionXmlInfo.DefinitionConfigPath;
				if (UrlPath.IsSubpath(definitionConfigPath, definitionConfigPath2))
				{
					return 1;
				}
				if (UrlPath.IsSubpath(definitionConfigPath2, definitionConfigPath))
				{
					return -1;
				}
				return 0;
			}
		}

		protected const string NL = "\r\n";

		internal const string KEYWORD_TRUE = "true";

		internal const string KEYWORD_FALSE = "false";

		protected const string KEYWORD_CONFIGURATION = "configuration";

		protected const string KEYWORD_CONFIGURATION_NAMESPACE = "http://schemas.microsoft.com/.NetConfiguration/v2.0";

		protected const string KEYWORD_CONFIGSECTIONS = "configSections";

		protected const string KEYWORD_SECTION = "section";

		protected const string KEYWORD_SECTION_NAME = "name";

		protected const string KEYWORD_SECTION_TYPE = "type";

		protected const string KEYWORD_SECTION_ALLOWLOCATION = "allowLocation";

		protected const string KEYWORD_SECTION_ALLOWDEFINITION = "allowDefinition";

		protected const string KEYWORD_SECTION_ALLOWDEFINITION_EVERYWHERE = "Everywhere";

		protected const string KEYWORD_SECTION_ALLOWDEFINITION_MACHINEONLY = "MachineOnly";

		protected const string KEYWORD_SECTION_ALLOWDEFINITION_MACHINETOAPPLICATION = "MachineToApplication";

		protected const string KEYWORD_SECTION_ALLOWDEFINITION_MACHINETOWEBROOT = "MachineToWebRoot";

		protected const string KEYWORD_SECTION_ALLOWEXEDEFINITION = "allowExeDefinition";

		protected const string KEYWORD_SECTION_ALLOWEXEDEFINITION_MACHTOROAMING = "MachineToRoamingUser";

		protected const string KEYWORD_SECTION_ALLOWEXEDEFINITION_MACHTOLOCAL = "MachineToLocalUser";

		protected const string KEYWORD_SECTION_RESTARTONEXTERNALCHANGES = "restartOnExternalChanges";

		protected const string KEYWORD_SECTION_REQUIREPERMISSION = "requirePermission";

		protected const string KEYWORD_SECTIONGROUP = "sectionGroup";

		protected const string KEYWORD_SECTIONGROUP_NAME = "name";

		protected const string KEYWORD_SECTIONGROUP_TYPE = "type";

		protected const string KEYWORD_REMOVE = "remove";

		protected const string KEYWORD_CLEAR = "clear";

		protected const string KEYWORD_LOCATION = "location";

		protected const string KEYWORD_LOCATION_PATH = "path";

		internal const string KEYWORD_LOCATION_ALLOWOVERRIDE = "allowOverride";

		protected const string KEYWORD_LOCATION_INHERITINCHILDAPPLICATIONS = "inheritInChildApplications";

		protected const string KEYWORD_CONFIGSOURCE = "configSource";

		protected const string KEYWORD_XMLNS = "xmlns";

		internal const string KEYWORD_PROTECTION_PROVIDER = "configProtectionProvider";

		protected const string FORMAT_NEWCONFIGFILE = "<?xml version=\"1.0\" encoding=\"{0}\"?>\r\n";

		protected const string FORMAT_CONFIGURATION = "<configuration>\r\n";

		protected const string FORMAT_CONFIGURATION_NAMESPACE = "<configuration xmlns=\"{0}\">\r\n";

		protected const string FORMAT_CONFIGURATION_ENDELEMENT = "</configuration>";

		internal const string KEYWORD_SECTION_OVERRIDEMODEDEFAULT = "overrideModeDefault";

		internal const string KEYWORD_LOCATION_OVERRIDEMODE = "overrideMode";

		internal const string KEYWORD_OVERRIDEMODE_INHERIT = "Inherit";

		internal const string KEYWORD_OVERRIDEMODE_ALLOW = "Allow";

		internal const string KEYWORD_OVERRIDEMODE_DENY = "Deny";

		protected const string FORMAT_LOCATION_NOPATH = "<location {0} inheritInChildApplications=\"{1}\">\r\n";

		protected const string FORMAT_LOCATION_PATH = "<location path=\"{2}\" {0} inheritInChildApplications=\"{1}\">\r\n";

		protected const string FORMAT_LOCATION_ENDELEMENT = "</location>";

		internal const string KEYWORD_LOCATION_OVERRIDEMODE_STRING = "{0}=\"{1}\"";

		protected const string FORMAT_SECTION_CONFIGSOURCE = "<{0} configSource=\"{1}\" />";

		protected const string FORMAT_CONFIGSOURCE_FILE = "<?xml version=\"1.0\" encoding=\"{0}\"?>\r\n";

		protected const string FORMAT_SECTIONGROUP_ENDELEMENT = "</sectionGroup>";

		protected const int ClassSupportsChangeNotifications = 1;

		protected const int ClassSupportsRefresh = 2;

		protected const int ClassSupportsImpersonation = 4;

		protected const int ClassSupportsRestrictedPermissions = 8;

		protected const int ClassSupportsKeepInputs = 16;

		protected const int ClassSupportsDelayedInit = 32;

		protected const int ClassIgnoreLocalErrors = 64;

		protected const int ProtectedDataInitialized = 1;

		protected const int Closed = 2;

		protected const int PrefetchAll = 8;

		protected const int IsAboveApplication = 32;

		private const int ContextEvaluated = 128;

		private const int IsLocationListResolved = 256;

		protected const int NamespacePresentInFile = 512;

		private const int RestrictedPermissionsResolved = 2048;

		protected const int IsTrusted = 8192;

		protected const int SupportsChangeNotifications = 65536;

		protected const int SupportsRefresh = 131072;

		protected const int SupportsPath = 262144;

		protected const int SupportsKeepInputs = 524288;

		protected const int SupportsLocation = 1048576;

		protected const int ForceLocationWritten = 16777216;

		protected const int SuggestLocationRemoval = 33554432;

		protected const int NamespacePresentCurrent = 67108864;

		internal const char ConfigPathSeparatorChar = '/';

		internal const string ConfigPathSeparatorString = "/";

		private const string invalidFirstSubPathCharacters = "\\./";

		private const string invalidLastSubPathCharacters = "\\./";

		private const string invalidSubPathCharactersString = "\\?:*\"<>|";

		private const string ProtectedConfigurationSectionTypeName = "System.Configuration.ProtectedConfigurationSection, System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

		internal const string RESERVED_SECTION_PROTECTED_CONFIGURATION = "configProtectedData";

		internal static readonly char[] ConfigPathSeparatorParams = new char[1] { '/' };

		private static ConfigurationPermission s_unrestrictedConfigPermission;

		protected SafeBitVector32 _flags;

		protected BaseConfigurationRecord _parent;

		protected Hashtable _children;

		protected InternalConfigRoot _configRoot;

		protected string _configName;

		protected string _configPath;

		protected string _locationSubPath;

		private ConfigRecordStreamInfo _configStreamInfo;

		private object _configContext;

		private ProtectedConfigurationSection _protectedConfig;

		private PermissionSet _restrictedPermissions;

		private ConfigurationSchemaErrors _initErrors;

		private BaseConfigurationRecord _initDelayedRoot;

		protected Hashtable _factoryRecords;

		protected Hashtable _sectionRecords;

		protected ArrayList _locationSections;

		private static string s_appConfigPath;

		private static IComparer<SectionInput> s_indirectInputsComparer = new IndirectLocationInputComparer();

		private static bool s_allowDataSetSectionToLoadUserConfig;

		private static volatile bool s_allowDataSetSectionToLoadUserConfigValueInitialized;

		private static char[] s_invalidSubPathCharactersArray = "\\?:*\"<>|".ToCharArray();

		protected abstract SimpleBitVector32 ClassFlags { get; }

		public string ConfigPath => _configPath;

		public string StreamName => ConfigStreamInfo.StreamName;

		public bool HasInitErrors => _initErrors.HasErrors(ClassFlags[64]);

		internal bool HasStream => ConfigStreamInfo.HasStream;

		private bool IsInitDelayed => _initDelayedRoot != null;

		internal IInternalConfigHost Host => _configRoot.Host;

		internal BaseConfigurationRecord Parent => _parent;

		internal bool IsRootConfig => _parent == null;

		internal bool IsMachineConfig => _parent == _configRoot.RootConfigRecord;

		internal string LocationSubPath => _locationSubPath;

		internal bool IsLocationConfig => _locationSubPath != null;

		protected ConfigRecordStreamInfo ConfigStreamInfo
		{
			get
			{
				if (IsLocationConfig)
				{
					return _parent._configStreamInfo;
				}
				return _configStreamInfo;
			}
		}

		private static ConfigurationPermission UnrestrictedConfigPermission
		{
			get
			{
				if (s_unrestrictedConfigPermission == null)
				{
					s_unrestrictedConfigPermission = new ConfigurationPermission(PermissionState.Unrestricted);
				}
				return s_unrestrictedConfigPermission;
			}
		}

		internal string DefaultProviderName => ProtectedConfig.DefaultProvider;

		private ProtectedConfigurationSection ProtectedConfig
		{
			get
			{
				if (!_flags[1])
				{
					InitProtectedConfigurationSection();
				}
				return _protectedConfig;
			}
		}

		private bool HasFactoryRecords => _factoryRecords != null;

		internal bool IsEmpty
		{
			get
			{
				if (_parent != null && !_initErrors.HasErrors(ignoreLocal: false) && (_sectionRecords == null || _sectionRecords.Count == 0) && (_factoryRecords == null || _factoryRecords.Count == 0))
				{
					if (_locationSections != null)
					{
						return _locationSections.Count == 0;
					}
					return true;
				}
				return false;
			}
		}

		internal object ConfigContext
		{
			get
			{
				if (!_flags[128])
				{
					_configContext = Host.CreateConfigurationContext(ConfigPath, LocationSubPath);
					_flags[128] = true;
				}
				return _configContext;
			}
		}

		internal bool RecordSupportsLocation
		{
			get
			{
				if (!_flags[1048576])
				{
					return IsMachineConfig;
				}
				return true;
			}
		}

		internal BaseConfigurationRecord()
		{
			_flags = default(SafeBitVector32);
		}

		protected abstract object CreateSectionFactory(FactoryRecord factoryRecord);

		protected abstract object CreateSection(bool inputIsTrusted, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader);

		protected abstract object UseParentResult(string configKey, object parentResult, SectionRecord sectionRecord);

		protected abstract object GetRuntimeObject(object result);

		public void ThrowIfInitErrors()
		{
			ThrowIfParseErrors(_initErrors);
		}

		public object GetSection(string configKey)
		{
			return GetSection(configKey, getLkg: false, checkPermission: true);
		}

		public object GetLkgSection(string configKey)
		{
			return GetSection(configKey, getLkg: true, checkPermission: true);
		}

		public void RefreshSection(string configKey)
		{
			_configRoot.ClearResult(this, configKey, forceEvaluation: true);
		}

		public void Remove()
		{
			_configRoot.RemoveConfigRecord(this);
		}

		private bool ShouldPrefetchRawXml(FactoryRecord factoryRecord)
		{
			if (_flags[8])
			{
				return true;
			}
			switch (factoryRecord.ConfigKey)
			{
			case "configProtectedData":
			case "system.diagnostics":
			case "appSettings":
			case "connectionStrings":
				return true;
			default:
				return Host.PrefetchSection(factoryRecord.Group, factoryRecord.Name);
			}
		}

		protected IDisposable Impersonate()
		{
			IDisposable disposable = null;
			if (ClassFlags[4])
			{
				disposable = Host.Impersonate();
			}
			if (disposable == null)
			{
				disposable = EmptyImpersonationContext.GetStaticInstance();
			}
			return disposable;
		}

		internal PermissionSet GetRestrictedPermissions()
		{
			if (!_flags[2048])
			{
				Host.GetRestrictedPermissions(this, out var permissionSet, out var isHostReady);
				if (isHostReady)
				{
					_restrictedPermissions = permissionSet;
					_flags[2048] = true;
				}
			}
			return _restrictedPermissions;
		}

		internal void Init(IInternalConfigRoot configRoot, BaseConfigurationRecord parent, string configPath, string locationSubPath)
		{
			_initErrors = new ConfigurationSchemaErrors();
			try
			{
				_configRoot = (InternalConfigRoot)configRoot;
				_parent = parent;
				_configPath = configPath;
				_locationSubPath = locationSubPath;
				_configName = ConfigPathUtility.GetName(configPath);
				if (IsLocationConfig)
				{
					_configStreamInfo = _parent.ConfigStreamInfo;
				}
				else
				{
					_configStreamInfo = new ConfigRecordStreamInfo();
				}
				if (IsRootConfig)
				{
					return;
				}
				_flags[65536] = ClassFlags[1] && Host.SupportsChangeNotifications;
				_flags[131072] = ClassFlags[2] && Host.SupportsRefresh;
				_flags[524288] = ClassFlags[16] || _flags[131072];
				_flags[262144] = Host.SupportsPath;
				_flags[1048576] = Host.SupportsLocation;
				if (_flags[1048576])
				{
					_flags[32] = Host.IsAboveApplication(_configPath);
				}
				_flags[8192] = Host.IsTrustedConfigPath(_configPath);
				ArrayList arrayList = null;
				if (_flags[1048576])
				{
					if (IsLocationConfig && _parent._locationSections != null)
					{
						_parent.ResolveLocationSections();
						int num = 0;
						while (num < _parent._locationSections.Count)
						{
							LocationSectionRecord locationSectionRecord = (LocationSectionRecord)_parent._locationSections[num];
							if (!StringUtil.EqualsIgnoreCase(locationSectionRecord.SectionXmlInfo.TargetConfigPath, ConfigPath))
							{
								num++;
								continue;
							}
							_parent._locationSections.RemoveAt(num);
							if (arrayList == null)
							{
								arrayList = new ArrayList();
							}
							arrayList.Add(locationSectionRecord);
						}
					}
					if (IsLocationConfig && Host.IsLocationApplicable(_configPath))
					{
						Dictionary<string, List<SectionInput>> dictionary = null;
						BaseConfigurationRecord parent2 = _parent;
						while (!parent2.IsRootConfig)
						{
							if (parent2._locationSections != null)
							{
								parent2.ResolveLocationSections();
								foreach (LocationSectionRecord locationSection in parent2._locationSections)
								{
									if (IsLocationConfig && UrlPath.IsSubpath(locationSection.SectionXmlInfo.TargetConfigPath, ConfigPath) && UrlPath.IsSubpath(parent.ConfigPath, locationSection.SectionXmlInfo.TargetConfigPath) && !ShouldSkipDueToInheritInChildApplications(locationSection.SectionXmlInfo.SkipInChildApps, locationSection.SectionXmlInfo.TargetConfigPath))
									{
										if (dictionary == null)
										{
											dictionary = new Dictionary<string, List<SectionInput>>(1);
										}
										string configKey = locationSection.SectionXmlInfo.ConfigKey;
										if (!((IDictionary)dictionary).Contains((object)configKey))
										{
											dictionary.Add(configKey, new List<SectionInput>(1));
										}
										dictionary[configKey].Add(new SectionInput(locationSection.SectionXmlInfo, locationSection.ErrorsList));
										if (locationSection.HasErrors)
										{
											_initErrors.AddSavedLocalErrors(locationSection.Errors);
										}
									}
								}
							}
							parent2 = parent2._parent;
						}
						if (dictionary != null)
						{
							foreach (KeyValuePair<string, List<SectionInput>> item in dictionary)
							{
								List<SectionInput> value = item.Value;
								string key = item.Key;
								value.Sort(s_indirectInputsComparer);
								SectionRecord sectionRecord = EnsureSectionRecord(key, permitErrors: true);
								foreach (SectionInput item2 in value)
								{
									sectionRecord.AddIndirectLocationInput(item2);
								}
							}
						}
					}
					if (Host.IsLocationApplicable(_configPath))
					{
						BaseConfigurationRecord parent3 = _parent;
						while (!parent3.IsRootConfig)
						{
							if (parent3._locationSections != null)
							{
								parent3.ResolveLocationSections();
								foreach (LocationSectionRecord locationSection2 in parent3._locationSections)
								{
									if (StringUtil.EqualsIgnoreCase(locationSection2.SectionXmlInfo.TargetConfigPath, _configPath) && !ShouldSkipDueToInheritInChildApplications(locationSection2.SectionXmlInfo.SkipInChildApps))
									{
										SectionRecord sectionRecord2 = EnsureSectionRecord(locationSection2.ConfigKey, permitErrors: true);
										SectionInput sectionInput = new SectionInput(locationSection2.SectionXmlInfo, locationSection2.ErrorsList);
										sectionRecord2.AddLocationInput(sectionInput);
										if (locationSection2.HasErrors)
										{
											_initErrors.AddSavedLocalErrors(locationSection2.Errors);
										}
									}
								}
							}
							parent3 = parent3._parent;
						}
					}
				}
				if (!IsLocationConfig)
				{
					InitConfigFromFile();
				}
				else
				{
					if (arrayList == null)
					{
						return;
					}
					{
						foreach (LocationSectionRecord item3 in arrayList)
						{
							SectionRecord sectionRecord3 = EnsureSectionRecord(item3.ConfigKey, permitErrors: true);
							SectionInput sectionInput2 = new SectionInput(item3.SectionXmlInfo, item3.ErrorsList);
							sectionRecord3.AddFileInput(sectionInput2);
							if (item3.HasErrors)
							{
								_initErrors.AddSavedLocalErrors(item3.Errors);
							}
						}
						return;
					}
				}
			}
			catch (Exception e)
			{
				string filename = ((ConfigStreamInfo != null) ? ConfigStreamInfo.StreamName : null);
				_initErrors.AddError(ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), e, filename, 0), ExceptionAction.Global);
			}
			catch
			{
				string filename2 = ((ConfigStreamInfo != null) ? ConfigStreamInfo.StreamName : null);
				_initErrors.AddError(ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), null, filename2, 0), ExceptionAction.Global);
			}
		}

		private void InitConfigFromFile()
		{
			bool flag = false;
			try
			{
				if (ClassFlags[32] && Host.IsInitDelayed(this))
				{
					if (_parent._initDelayedRoot == null)
					{
						_initDelayedRoot = this;
					}
					else
					{
						_initDelayedRoot = _parent._initDelayedRoot;
					}
				}
				else
				{
					using (Impersonate())
					{
						ConfigStreamInfo.StreamName = Host.GetStreamName(_configPath);
						if (!string.IsNullOrEmpty(ConfigStreamInfo.StreamName))
						{
							ConfigStreamInfo.StreamVersion = MonitorStream(null, null, ConfigStreamInfo.StreamName);
							using Stream stream = Host.OpenStreamForRead(ConfigStreamInfo.StreamName);
							if (stream == null)
							{
								return;
							}
							ConfigStreamInfo.HasStream = true;
							_flags[8] = Host.PrefetchAll(_configPath, ConfigStreamInfo.StreamName);
							using XmlUtil xmlUtil = new XmlUtil(stream, ConfigStreamInfo.StreamName, readToFirstElement: true, _initErrors);
							ConfigStreamInfo.StreamEncoding = xmlUtil.Reader.Encoding;
							Hashtable hashtable = (_factoryRecords = ScanFactories(xmlUtil));
							AddImplicitSections(null);
							flag = true;
							if (xmlUtil.Reader.Depth == 1)
							{
								ScanSections(xmlUtil);
							}
						}
					}
				}
			}
			catch (XmlException e)
			{
				_initErrors.SetSingleGlobalError(ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), e, ConfigStreamInfo.StreamName, 0));
			}
			catch (Exception e2)
			{
				_initErrors.AddError(ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), e2, ConfigStreamInfo.StreamName, 0), ExceptionAction.Global);
			}
			catch
			{
				_initErrors.AddError(ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), null, ConfigStreamInfo.StreamName, 0), ExceptionAction.Global);
			}
			if (_initErrors.HasGlobalErrors)
			{
				_initErrors.ResetLocalErrors();
				HybridDictionary hybridDictionary = null;
				lock (this)
				{
					if (ConfigStreamInfo.HasStreamInfos)
					{
						hybridDictionary = ConfigStreamInfo.StreamInfos;
						ConfigStreamInfo.ClearStreamInfos();
						if (!string.IsNullOrEmpty(ConfigStreamInfo.StreamName))
						{
							StreamInfo streamInfo = (StreamInfo)hybridDictionary[ConfigStreamInfo.StreamName];
							if (streamInfo != null)
							{
								hybridDictionary.Remove(ConfigStreamInfo.StreamName);
								ConfigStreamInfo.StreamInfos.Add(ConfigStreamInfo.StreamName, streamInfo);
							}
						}
					}
				}
				if (hybridDictionary != null)
				{
					foreach (StreamInfo value in hybridDictionary.Values)
					{
						if (value.IsMonitored)
						{
							Host.StopMonitoringStreamForChanges(value.StreamName, ConfigStreamInfo.CallbackDelegate);
						}
					}
				}
				if (_sectionRecords != null)
				{
					List<SectionRecord> list = null;
					foreach (SectionRecord value2 in _sectionRecords.Values)
					{
						if (value2.HasLocationInputs)
						{
							value2.RemoveFileInput();
							continue;
						}
						if (list == null)
						{
							list = new List<SectionRecord>();
						}
						list.Add(value2);
					}
					if (list != null)
					{
						foreach (SectionRecord item in list)
						{
							_sectionRecords.Remove(item.ConfigKey);
						}
					}
				}
				if (_locationSections != null)
				{
					_locationSections.Clear();
				}
				if (_factoryRecords != null)
				{
					_factoryRecords.Clear();
				}
			}
			if (!flag)
			{
				AddImplicitSections(null);
			}
		}

		private void RefreshFactoryRecord(string configKey)
		{
			Hashtable hashtable = null;
			FactoryRecord factoryRecord = null;
			ConfigurationSchemaErrors configurationSchemaErrors = new ConfigurationSchemaErrors();
			int line = 0;
			try
			{
				using (Impersonate())
				{
					using Stream stream = Host.OpenStreamForRead(ConfigStreamInfo.StreamName);
					if (stream != null)
					{
						ConfigStreamInfo.HasStream = true;
						using XmlUtil xmlUtil = new XmlUtil(stream, ConfigStreamInfo.StreamName, readToFirstElement: true, configurationSchemaErrors);
						try
						{
							hashtable = ScanFactories(xmlUtil);
							ThrowIfParseErrors(xmlUtil.SchemaErrors);
						}
						catch
						{
							line = xmlUtil.LineNumber;
							throw;
						}
					}
				}
				if (hashtable == null)
				{
					hashtable = new Hashtable();
				}
				AddImplicitSections(hashtable);
				if (hashtable != null)
				{
					factoryRecord = (FactoryRecord)hashtable[configKey];
				}
			}
			catch (Exception e)
			{
				configurationSchemaErrors.AddError(ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), e, ConfigStreamInfo.StreamName, line), ExceptionAction.Global);
			}
			catch
			{
				configurationSchemaErrors.AddError(ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), null, ConfigStreamInfo.StreamName, line), ExceptionAction.Global);
			}
			if (factoryRecord != null || HasFactoryRecords)
			{
				EnsureFactories()[configKey] = factoryRecord;
			}
			ThrowIfParseErrors(configurationSchemaErrors);
		}

		private object GetSection(string configKey, bool getLkg, bool checkPermission)
		{
			GetSectionRecursive(configKey, getLkg, checkPermission, getRuntimeObject: true, requestIsHere: true, out var _, out var resultRuntimeObject);
			return resultRuntimeObject;
		}

		private void GetSectionRecursive(string configKey, bool getLkg, bool checkPermission, bool getRuntimeObject, bool requestIsHere, out object result, out object resultRuntimeObject)
		{
			result = null;
			resultRuntimeObject = null;
			object result2 = null;
			object resultRuntimeObject2 = null;
			bool requirePermission = true;
			bool flag = true;
			if (!getLkg)
			{
				ThrowIfInitErrors();
			}
			bool flag2 = false;
			SectionRecord sectionRecord = GetSectionRecord(configKey, getLkg);
			if (sectionRecord != null && sectionRecord.HasResult)
			{
				if (getRuntimeObject && !sectionRecord.HasResultRuntimeObject)
				{
					try
					{
						sectionRecord.ResultRuntimeObject = GetRuntimeObject(sectionRecord.Result);
					}
					catch
					{
						if (!getLkg)
						{
							throw;
						}
					}
				}
				if (!getRuntimeObject || sectionRecord.HasResultRuntimeObject)
				{
					requirePermission = sectionRecord.RequirePermission;
					flag = sectionRecord.IsResultTrustedWithoutAptca;
					result2 = sectionRecord.Result;
					if (getRuntimeObject)
					{
						resultRuntimeObject2 = sectionRecord.ResultRuntimeObject;
					}
					flag2 = true;
				}
			}
			if (!flag2)
			{
				FactoryRecord factoryRecord = null;
				bool flag3 = sectionRecord?.HasInput ?? false;
				bool flag4 = requestIsHere || flag3;
				try
				{
					bool isRootDeclaredHere;
					if (requestIsHere)
					{
						factoryRecord = FindAndEnsureFactoryRecord(configKey, out isRootDeclaredHere);
						if (IsInitDelayed && (factoryRecord == null || _initDelayedRoot.IsDefinitionAllowed(factoryRecord.AllowDefinition, factoryRecord.AllowExeDefinition)))
						{
							if (factoryRecord != null || !NeverLoadUserConfigFilesDuringFactorySearch(configKey))
							{
								string configPath = _configPath;
								InternalConfigRoot configRoot = _configRoot;
								Host.RequireCompleteInit(_initDelayedRoot);
								_initDelayedRoot.Remove();
								BaseConfigurationRecord baseConfigurationRecord = (BaseConfigurationRecord)configRoot.GetConfigRecord(configPath);
								baseConfigurationRecord.GetSectionRecursive(configKey, getLkg, checkPermission, getRuntimeObject, requestIsHere, out result, out resultRuntimeObject);
							}
							return;
						}
						if (factoryRecord == null || factoryRecord.IsGroup)
						{
							return;
						}
						configKey = factoryRecord.ConfigKey;
					}
					else if (flag3)
					{
						factoryRecord = FindAndEnsureFactoryRecord(configKey, out isRootDeclaredHere);
					}
					else
					{
						factoryRecord = GetFactoryRecord(configKey, permitErrors: false);
						if (factoryRecord == null)
						{
							isRootDeclaredHere = false;
						}
						else
						{
							factoryRecord = FindAndEnsureFactoryRecord(configKey, out isRootDeclaredHere);
						}
					}
					if (isRootDeclaredHere)
					{
						flag4 = true;
					}
					if (sectionRecord == null && flag4)
					{
						sectionRecord = EnsureSectionRecord(configKey, permitErrors: true);
					}
					bool getRuntimeObject2 = getRuntimeObject && !flag3;
					object result3 = null;
					object resultRuntimeObject3 = null;
					if (isRootDeclaredHere)
					{
						SectionRecord sectionRecord2 = (flag3 ? null : sectionRecord);
						CreateSectionDefault(configKey, getRuntimeObject2, factoryRecord, sectionRecord2, out result3, out resultRuntimeObject3);
					}
					else
					{
						_parent.GetSectionRecursive(configKey, getLkg: false, checkPermission: false, getRuntimeObject2, requestIsHere: false, out result3, out resultRuntimeObject3);
					}
					if (flag3)
					{
						if (!Evaluate(factoryRecord, sectionRecord, result3, getLkg, getRuntimeObject, out result2, out resultRuntimeObject2))
						{
							flag4 = false;
						}
					}
					else if (sectionRecord != null)
					{
						result2 = UseParentResult(configKey, result3, sectionRecord);
						if (getRuntimeObject)
						{
							resultRuntimeObject2 = ((!object.ReferenceEquals(result3, resultRuntimeObject3)) ? UseParentResult(configKey, resultRuntimeObject3, sectionRecord) : result2);
						}
					}
					else
					{
						result2 = result3;
						resultRuntimeObject2 = resultRuntimeObject3;
					}
					if (flag4 || checkPermission)
					{
						requirePermission = factoryRecord.RequirePermission;
						flag = factoryRecord.IsFactoryTrustedWithoutAptca;
						if (flag4)
						{
							if (sectionRecord == null)
							{
								sectionRecord = EnsureSectionRecord(configKey, permitErrors: true);
							}
							sectionRecord.Result = result2;
							if (getRuntimeObject)
							{
								sectionRecord.ResultRuntimeObject = resultRuntimeObject2;
							}
							sectionRecord.RequirePermission = requirePermission;
							sectionRecord.IsResultTrustedWithoutAptca = flag;
						}
					}
					flag2 = true;
				}
				catch
				{
					if (!getLkg)
					{
						throw;
					}
				}
				if (!flag2)
				{
					_parent.GetSectionRecursive(configKey, getLkg: true, checkPermission, getRuntimeObject: true, requestIsHere: true, out result, out resultRuntimeObject);
					return;
				}
			}
			if (checkPermission)
			{
				CheckPermissionAllowed(configKey, requirePermission, flag);
			}
			result = result2;
			if (getRuntimeObject)
			{
				resultRuntimeObject = resultRuntimeObject2;
			}
		}

		private static bool NeverLoadUserConfigFilesDuringFactorySearch(string configKey)
		{
			if (!CanLoadUserConfigFilesWhenSearchingForDatasetSerializationAllowedTypes() && configKey == "system.data.dataset.serialization/allowedTypes")
			{
				return true;
			}
			return false;
		}

		[SecurityTreatAsSafe]
		[SecurityCritical]
		[RegistryPermission(SecurityAction.Assert, Unrestricted = true)]
		private static bool CanLoadUserConfigFilesWhenSearchingForDatasetSerializationAllowedTypes()
		{
			if (!s_allowDataSetSectionToLoadUserConfigValueInitialized)
			{
				s_allowDataSetSectionToLoadUserConfig = ReadUserConfigFileLoadRegistrySetting("Switch.System.Configuration.AllowUserConfigFilesToLoadWhenSearchingForDatasetSerializationAllowedTypes");
				s_allowDataSetSectionToLoadUserConfigValueInitialized = true;
			}
			return s_allowDataSetSectionToLoadUserConfig;
		}

		private static bool ReadUserConfigFileLoadRegistrySetting(string switchName)
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\.NETFramework\\AppContext", writable: false);
				if (registryKey != null && registryKey.GetValueKind(switchName) == RegistryValueKind.String && "true".Equals((string)registryKey.GetValue(switchName), StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			catch
			{
			}
			return false;
		}

		protected void CreateSectionDefault(string configKey, bool getRuntimeObject, FactoryRecord factoryRecord, SectionRecord sectionRecord, out object result, out object resultRuntimeObject)
		{
			result = null;
			resultRuntimeObject = null;
			SectionRecord sectionRecord2 = ((sectionRecord == null) ? new SectionRecord(configKey) : sectionRecord);
			object obj = CallCreateSection(inputIsTrusted: true, factoryRecord, sectionRecord2, null, null, null, -1);
			object obj2 = ((!getRuntimeObject) ? null : GetRuntimeObject(obj));
			result = obj;
			resultRuntimeObject = obj2;
		}

		private bool ShouldSkipDueToInheritInChildApplications(bool skipInChildApps)
		{
			if (skipInChildApps)
			{
				return _flags[32];
			}
			return false;
		}

		private bool ShouldSkipDueToInheritInChildApplications(bool skipInChildApps, string configPath)
		{
			if (skipInChildApps)
			{
				return Host.IsAboveApplication(configPath);
			}
			return false;
		}

		private bool Evaluate(FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentResult, bool getLkg, bool getRuntimeObject, out object result, out object resultRuntimeObject)
		{
			result = null;
			resultRuntimeObject = null;
			object obj = null;
			object obj2 = null;
			List<SectionInput> locationInputs = sectionRecord.LocationInputs;
			List<SectionInput> indirectLocationInputs = sectionRecord.IndirectLocationInputs;
			SectionInput fileInput = sectionRecord.FileInput;
			bool flag = false;
			if (sectionRecord.HasResult)
			{
				if (getRuntimeObject && !sectionRecord.HasResultRuntimeObject)
				{
					try
					{
						sectionRecord.ResultRuntimeObject = GetRuntimeObject(sectionRecord.Result);
					}
					catch
					{
						if (!getLkg)
						{
							throw;
						}
					}
				}
				if (!getRuntimeObject || sectionRecord.HasResultRuntimeObject)
				{
					obj = sectionRecord.Result;
					if (getRuntimeObject)
					{
						obj2 = sectionRecord.ResultRuntimeObject;
					}
					flag = true;
				}
			}
			if (!flag)
			{
				Exception ex = null;
				try
				{
					string configKey = factoryRecord.ConfigKey;
					string[] keys = configKey.Split(ConfigPathSeparatorParams);
					object parentResult2 = parentResult;
					if (indirectLocationInputs != null)
					{
						foreach (SectionInput item in indirectLocationInputs)
						{
							if (!item.HasResult)
							{
								item.ThrowOnErrors();
								bool isTrusted = Host.IsTrustedConfigPath(item.SectionXmlInfo.DefinitionConfigPath);
								item.Result = EvaluateOne(keys, item, isTrusted, factoryRecord, sectionRecord, parentResult2);
							}
							parentResult2 = item.Result;
						}
					}
					if (locationInputs != null)
					{
						foreach (SectionInput item2 in locationInputs)
						{
							if (!item2.HasResult)
							{
								item2.ThrowOnErrors();
								bool isTrusted2 = Host.IsTrustedConfigPath(item2.SectionXmlInfo.DefinitionConfigPath);
								item2.Result = EvaluateOne(keys, item2, isTrusted2, factoryRecord, sectionRecord, parentResult2);
							}
							parentResult2 = item2.Result;
						}
					}
					if (fileInput != null)
					{
						if (!fileInput.HasResult)
						{
							fileInput.ThrowOnErrors();
							bool isTrusted3 = _flags[8192];
							fileInput.Result = EvaluateOne(keys, fileInput, isTrusted3, factoryRecord, sectionRecord, parentResult2);
						}
						parentResult2 = fileInput.Result;
					}
					else
					{
						parentResult2 = UseParentResult(configKey, parentResult2, sectionRecord);
					}
					if (getRuntimeObject)
					{
						obj2 = GetRuntimeObject(parentResult2);
					}
					obj = parentResult2;
					flag = true;
				}
				catch (Exception ex2)
				{
					if (!getLkg || locationInputs == null)
					{
						throw;
					}
					ex = ex2;
				}
				if (!flag)
				{
					int num = locationInputs.Count;
					while (--num >= 0)
					{
						SectionInput sectionInput = locationInputs[num];
						if (!sectionInput.HasResult)
						{
							continue;
						}
						if (getRuntimeObject && !sectionInput.HasResultRuntimeObject)
						{
							try
							{
								sectionInput.ResultRuntimeObject = GetRuntimeObject(sectionInput.Result);
							}
							catch
							{
							}
						}
						if (!getRuntimeObject || sectionInput.HasResultRuntimeObject)
						{
							obj = sectionInput.Result;
							if (getRuntimeObject)
							{
								obj2 = sectionInput.ResultRuntimeObject;
							}
							break;
						}
					}
					if (num < 0)
					{
						throw ex;
					}
				}
			}
			if (flag && !_flags[524288])
			{
				sectionRecord.ClearRawXml();
			}
			result = obj;
			if (getRuntimeObject)
			{
				resultRuntimeObject = obj2;
			}
			return flag;
		}

		private object EvaluateOne(string[] keys, SectionInput input, bool isTrusted, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentResult)
		{
			try
			{
				ConfigXmlReader sectionXmlReader = GetSectionXmlReader(keys, input);
				if (sectionXmlReader == null)
				{
					return UseParentResult(factoryRecord.ConfigKey, parentResult, sectionRecord);
				}
				return CallCreateSection(isTrusted, factoryRecord, sectionRecord, parentResult, sectionXmlReader, input.SectionXmlInfo.Filename, input.SectionXmlInfo.LineNumber);
			}
			catch (Exception e)
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_exception_creating_section", factoryRecord.ConfigKey), e, input.SectionXmlInfo);
			}
			catch
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_exception_creating_section", factoryRecord.ConfigKey), null, input.SectionXmlInfo);
			}
		}

		private void CheckPermissionAllowed(string configKey, bool requirePermission, bool isTrustedWithoutAptca)
		{
			if (requirePermission)
			{
				try
				{
					UnrestrictedConfigPermission.Demand();
				}
				catch (SecurityException inner)
				{
					throw new SecurityException(SR.GetString("ConfigurationPermission_Denied", configKey), inner);
				}
			}
			if (isTrustedWithoutAptca && !Host.IsFullTrustSectionWithoutAptcaAllowed(this))
			{
				throw new ConfigurationErrorsException(SR.GetString("Section_from_untrusted_assembly", configKey));
			}
		}

		private ConfigXmlReader FindSection(string[] keys, SectionXmlInfo sectionXmlInfo, out int lineNumber)
		{
			lineNumber = 0;
			ConfigXmlReader configXmlReader = null;
			try
			{
				using (Impersonate())
				{
					using Stream stream = Host.OpenStreamForRead(sectionXmlInfo.Filename);
					if (!_flags[131072] && (stream == null || HasStreamChanged(sectionXmlInfo.Filename, sectionXmlInfo.StreamVersion)))
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_file_has_changed"), sectionXmlInfo.Filename, 0);
					}
					if (stream != null)
					{
						using (XmlUtil xmlUtil = new XmlUtil(stream, sectionXmlInfo.Filename, readToFirstElement: true))
						{
							if (sectionXmlInfo.SubPath == null)
							{
								configXmlReader = FindSectionRecursive(keys, 0, xmlUtil, ref lineNumber);
							}
							else
							{
								xmlUtil.ReadToNextElement();
								while (xmlUtil.Reader.Depth > 0)
								{
									if (xmlUtil.Reader.Name == "location")
									{
										bool flag = false;
										string text = xmlUtil.Reader.GetAttribute("path");
										try
										{
											text = NormalizeLocationSubPath(text, xmlUtil);
											flag = true;
										}
										catch (ConfigurationException ce)
										{
											xmlUtil.SchemaErrors.AddError(ce, ExceptionAction.NonSpecific);
										}
										if (flag && StringUtil.EqualsIgnoreCase(sectionXmlInfo.SubPath, text))
										{
											configXmlReader = FindSectionRecursive(keys, 0, xmlUtil, ref lineNumber);
											if (configXmlReader != null)
											{
												break;
											}
										}
									}
									xmlUtil.SkipToNextElement();
								}
							}
							ThrowIfParseErrors(xmlUtil.SchemaErrors);
							return configXmlReader;
						}
					}
					return configXmlReader;
				}
			}
			catch
			{
				throw;
			}
		}

		private ConfigXmlReader FindSectionRecursive(string[] keys, int iKey, XmlUtil xmlUtil, ref int lineNumber)
		{
			string text = keys[iKey];
			ConfigXmlReader configXmlReader = null;
			int depth = xmlUtil.Reader.Depth;
			xmlUtil.ReadToNextElement();
			while (xmlUtil.Reader.Depth > depth)
			{
				if (xmlUtil.Reader.Name == text)
				{
					if (iKey < keys.Length - 1)
					{
						configXmlReader = FindSectionRecursive(keys, iKey + 1, xmlUtil, ref lineNumber);
						if (configXmlReader != null)
						{
							break;
						}
						continue;
					}
					string filename = ((IConfigErrorInfo)xmlUtil).Filename;
					int lineNumber2 = xmlUtil.Reader.LineNumber;
					string rawXml = xmlUtil.CopySection();
					configXmlReader = new ConfigXmlReader(rawXml, filename, lineNumber2);
					break;
				}
				if (iKey == 0 && xmlUtil.Reader.Name == "location")
				{
					string text2 = xmlUtil.Reader.GetAttribute("path");
					bool flag = false;
					try
					{
						text2 = NormalizeLocationSubPath(text2, xmlUtil);
						flag = true;
					}
					catch (ConfigurationException ce)
					{
						xmlUtil.SchemaErrors.AddError(ce, ExceptionAction.NonSpecific);
					}
					if (flag && text2 == null)
					{
						configXmlReader = FindSectionRecursive(keys, iKey, xmlUtil, ref lineNumber);
						if (configXmlReader != null)
						{
							break;
						}
						continue;
					}
				}
				xmlUtil.SkipToNextElement();
			}
			return configXmlReader;
		}

		private ConfigXmlReader LoadConfigSource(string name, SectionXmlInfo sectionXmlInfo)
		{
			string configSourceStreamName = sectionXmlInfo.ConfigSourceStreamName;
			try
			{
				using (Impersonate())
				{
					using Stream stream = Host.OpenStreamForRead(configSourceStreamName);
					if (stream == null)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_cannot_open_config_source", sectionXmlInfo.ConfigSource), sectionXmlInfo);
					}
					using XmlUtil xmlUtil = new XmlUtil(stream, configSourceStreamName, readToFirstElement: true);
					if (xmlUtil.Reader.Name != name)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_source_file_format"), xmlUtil);
					}
					string attribute = xmlUtil.Reader.GetAttribute("configProtectionProvider");
					if (attribute != null)
					{
						if (xmlUtil.Reader.AttributeCount != 1)
						{
							throw new ConfigurationErrorsException(SR.GetString("Protection_provider_syntax_error"), xmlUtil);
						}
						sectionXmlInfo.ProtectionProviderName = ValidateProtectionProviderAttribute(attribute, xmlUtil);
					}
					int lineNumber = xmlUtil.Reader.LineNumber;
					string rawXml = xmlUtil.CopySection();
					while (!xmlUtil.Reader.EOF)
					{
						XmlNodeType nodeType = xmlUtil.Reader.NodeType;
						if (nodeType != XmlNodeType.Comment)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_source_file_format"), xmlUtil);
						}
						xmlUtil.Reader.Read();
					}
					return new ConfigXmlReader(rawXml, configSourceStreamName, lineNumber);
				}
			}
			catch
			{
				throw;
			}
		}

		protected ConfigXmlReader GetSectionXmlReader(string[] keys, SectionInput input)
		{
			ConfigXmlReader configXmlReader = null;
			string filename = input.SectionXmlInfo.Filename;
			int lineNumber = input.SectionXmlInfo.LineNumber;
			try
			{
				string name = keys[keys.Length - 1];
				string rawXml = input.SectionXmlInfo.RawXml;
				if (rawXml != null)
				{
					configXmlReader = new ConfigXmlReader(rawXml, input.SectionXmlInfo.Filename, input.SectionXmlInfo.LineNumber);
				}
				else if (!string.IsNullOrEmpty(input.SectionXmlInfo.ConfigSource))
				{
					filename = input.SectionXmlInfo.ConfigSourceStreamName;
					lineNumber = 0;
					configXmlReader = LoadConfigSource(name, input.SectionXmlInfo);
				}
				else
				{
					lineNumber = 0;
					configXmlReader = FindSection(keys, input.SectionXmlInfo, out lineNumber);
				}
				if (configXmlReader != null)
				{
					if (!input.IsProtectionProviderDetermined)
					{
						input.ProtectionProvider = GetProtectionProviderFromName(input.SectionXmlInfo.ProtectionProviderName, throwIfNotFound: false);
					}
					if (input.ProtectionProvider != null)
					{
						return DecryptConfigSection(configXmlReader, input.ProtectionProvider);
					}
					return configXmlReader;
				}
				return configXmlReader;
			}
			catch (Exception e)
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), e, filename, lineNumber);
			}
			catch
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), null, filename, lineNumber);
			}
		}

		internal ProtectedConfigurationProvider GetProtectionProviderFromName(string providerName, bool throwIfNotFound)
		{
			ProtectedConfigurationProvider protectedConfigurationProvider = null;
			if (string.IsNullOrEmpty(providerName))
			{
				if (throwIfNotFound)
				{
					throw new ConfigurationErrorsException(SR.GetString("ProtectedConfigurationProvider_not_found", providerName));
				}
				return null;
			}
			return ProtectedConfig.GetProviderFromName(providerName);
		}

		internal void InitProtectedConfigurationSection()
		{
			if (!_flags[1])
			{
				_protectedConfig = GetSection("configProtectedData", getLkg: false, checkPermission: false) as ProtectedConfigurationSection;
				_flags[1] = true;
			}
		}

		protected object CallCreateSection(bool inputIsTrusted, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader, string filename, int line)
		{
			try
			{
				using (Impersonate())
				{
					object obj = CreateSection(inputIsTrusted, factoryRecord, sectionRecord, parentConfig, reader);
					if (obj == null)
					{
						if (parentConfig != null)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_object_is_null"), filename, line);
						}
						return obj;
					}
					return obj;
				}
			}
			catch (ThreadAbortException)
			{
				throw;
			}
			catch (Exception e)
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_exception_creating_section_handler", factoryRecord.ConfigKey), e, filename, line);
			}
			catch
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_exception_creating_section_handler", factoryRecord.ConfigKey), null, filename, line);
			}
		}

		internal bool IsRootDeclaration(string configKey, bool implicitIsRooted)
		{
			if (!implicitIsRooted && IsImplicitSection(configKey))
			{
				return false;
			}
			if (!_parent.IsRootConfig)
			{
				return _parent.FindFactoryRecord(configKey, permitErrors: true) == null;
			}
			return true;
		}

		internal FactoryRecord FindFactoryRecord(string configKey, bool permitErrors, out BaseConfigurationRecord configRecord)
		{
			configRecord = null;
			BaseConfigurationRecord baseConfigurationRecord = this;
			while (!baseConfigurationRecord.IsRootConfig)
			{
				FactoryRecord factoryRecord = baseConfigurationRecord.GetFactoryRecord(configKey, permitErrors);
				if (factoryRecord != null)
				{
					configRecord = baseConfigurationRecord;
					return factoryRecord;
				}
				baseConfigurationRecord = baseConfigurationRecord._parent;
			}
			return null;
		}

		internal FactoryRecord FindFactoryRecord(string configKey, bool permitErrors)
		{
			BaseConfigurationRecord configRecord;
			return FindFactoryRecord(configKey, permitErrors, out configRecord);
		}

		private FactoryRecord FindAndEnsureFactoryRecord(string configKey, out bool isRootDeclaredHere)
		{
			isRootDeclaredHere = false;
			BaseConfigurationRecord configRecord;
			FactoryRecord factoryRecord = FindFactoryRecord(configKey, permitErrors: false, out configRecord);
			if (factoryRecord != null && !factoryRecord.IsGroup)
			{
				FactoryRecord factoryRecord2 = factoryRecord;
				BaseConfigurationRecord baseConfigurationRecord = configRecord;
				BaseConfigurationRecord parent = configRecord._parent;
				while (!parent.IsRootConfig)
				{
					BaseConfigurationRecord configRecord2;
					FactoryRecord factoryRecord3 = parent.FindFactoryRecord(configKey, permitErrors: false, out configRecord2);
					if (factoryRecord3 == null)
					{
						break;
					}
					factoryRecord2 = factoryRecord3;
					baseConfigurationRecord = configRecord2;
					parent = configRecord2.Parent;
				}
				if (factoryRecord2.Factory == null)
				{
					try
					{
						object obj = baseConfigurationRecord.CreateSectionFactory(factoryRecord2);
						bool isFactoryTrustedWithoutAptca = TypeUtil.IsTypeFromTrustedAssemblyWithoutAptca(obj.GetType());
						factoryRecord2.Factory = obj;
						factoryRecord2.IsFactoryTrustedWithoutAptca = isFactoryTrustedWithoutAptca;
					}
					catch (Exception e)
					{
						throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_exception_creating_section_handler", factoryRecord.ConfigKey), e, factoryRecord);
					}
					catch
					{
						throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_exception_creating_section_handler", factoryRecord.ConfigKey), null, factoryRecord);
					}
				}
				if (factoryRecord.Factory == null)
				{
					factoryRecord.Factory = factoryRecord2.Factory;
					factoryRecord.IsFactoryTrustedWithoutAptca = factoryRecord2.IsFactoryTrustedWithoutAptca;
				}
				isRootDeclaredHere = object.ReferenceEquals(this, baseConfigurationRecord);
			}
			return factoryRecord;
		}

		private Hashtable ScanFactories(XmlUtil xmlUtil)
		{
			Hashtable hashtable = new Hashtable();
			if (xmlUtil.Reader.NodeType != XmlNodeType.Element || xmlUtil.Reader.Name != "configuration")
			{
				string text = ConfigurationErrorsException.AlwaysSafeFilename(((IConfigErrorInfo)xmlUtil).Filename);
				throw new ConfigurationErrorsException(SR.GetString("Config_file_doesnt_have_root_configuration", text), xmlUtil);
			}
			while (xmlUtil.Reader.MoveToNextAttribute())
			{
				string name;
				if ((name = xmlUtil.Reader.Name) != null && name == "xmlns")
				{
					if (xmlUtil.Reader.Value == "http://schemas.microsoft.com/.NetConfiguration/v2.0")
					{
						_flags[512] = true;
						_flags[67108864] = true;
						continue;
					}
					ConfigurationErrorsException ce = new ConfigurationErrorsException(SR.GetString("Config_namespace_invalid", xmlUtil.Reader.Value, "http://schemas.microsoft.com/.NetConfiguration/v2.0"), xmlUtil);
					xmlUtil.SchemaErrors.AddError(ce, ExceptionAction.Global);
				}
				else
				{
					xmlUtil.AddErrorUnrecognizedAttribute(ExceptionAction.NonSpecific);
				}
			}
			xmlUtil.StrictReadToNextElement(ExceptionAction.NonSpecific);
			if (xmlUtil.Reader.Depth == 1 && xmlUtil.Reader.Name == "configSections")
			{
				xmlUtil.VerifyNoUnrecognizedAttributes(ExceptionAction.NonSpecific);
				ScanFactoriesRecursive(xmlUtil, string.Empty, hashtable);
			}
			return hashtable;
		}

		private void ScanFactoriesRecursive(XmlUtil xmlUtil, string parentConfigKey, Hashtable factoryList)
		{
			xmlUtil.SchemaErrors.ResetLocalErrors();
			int depth = xmlUtil.Reader.Depth;
			xmlUtil.StrictReadToNextElement(ExceptionAction.NonSpecific);
			while (xmlUtil.Reader.Depth == depth + 1)
			{
				bool flag = false;
				switch (xmlUtil.Reader.Name)
				{
				case "sectionGroup":
				{
					string text2 = null;
					string newValue = null;
					int lineNumber = xmlUtil.Reader.LineNumber;
					while (xmlUtil.Reader.MoveToNextAttribute())
					{
						switch (xmlUtil.Reader.Name)
						{
						case "name":
							text2 = xmlUtil.Reader.Value;
							VerifySectionName(text2, xmlUtil, ExceptionAction.Local, allowImplicit: false);
							break;
						case "type":
							xmlUtil.VerifyAndGetNonEmptyStringAttribute(ExceptionAction.Local, out newValue);
							break;
						default:
							xmlUtil.AddErrorUnrecognizedAttribute(ExceptionAction.Local);
							break;
						}
					}
					xmlUtil.Reader.MoveToElement();
					if (!xmlUtil.VerifyRequiredAttribute(text2, "name", ExceptionAction.NonSpecific))
					{
						xmlUtil.SchemaErrors.RetrieveAndResetLocalErrors(keepLocalErrors: true);
						xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
						continue;
					}
					string text3 = CombineConfigKey(parentConfigKey, text2);
					FactoryRecord factoryRecord = (FactoryRecord)factoryList[text3];
					if (factoryRecord != null)
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined_at_this_level", text2), xmlUtil), ExceptionAction.Local);
					}
					else
					{
						FactoryRecord factoryRecord2 = _parent.FindFactoryRecord(text3, permitErrors: true);
						if (factoryRecord2 != null)
						{
							text3 = factoryRecord2.ConfigKey;
							if (factoryRecord2 != null && (!factoryRecord2.IsGroup || !factoryRecord2.IsEquivalentSectionGroupFactory(Host, newValue)))
							{
								xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", text2), xmlUtil), ExceptionAction.Local);
								factoryRecord2 = null;
							}
						}
						factoryRecord = (FactoryRecord)(factoryList[text3] = ((factoryRecord2 == null) ? new FactoryRecord(text3, parentConfigKey, text2, newValue, xmlUtil.Filename, lineNumber) : factoryRecord2.CloneSectionGroup(newValue, xmlUtil.Filename, lineNumber)));
					}
					factoryRecord.AddErrors(xmlUtil.SchemaErrors.RetrieveAndResetLocalErrors(keepLocalErrors: true));
					ScanFactoriesRecursive(xmlUtil, text3, factoryList);
					continue;
				}
				case "section":
				{
					string text4 = null;
					string newValue2 = null;
					ConfigurationAllowDefinition allowDefinition = ConfigurationAllowDefinition.Everywhere;
					ConfigurationAllowExeDefinition allowExeDefinition = ConfigurationAllowExeDefinition.MachineToApplication;
					OverrideModeSetting overrideModeDefault = OverrideModeSetting.SectionDefault;
					bool newValue3 = true;
					bool newValue4 = true;
					bool newValue5 = true;
					bool flag2 = false;
					int lineNumber2 = xmlUtil.Reader.LineNumber;
					while (xmlUtil.Reader.MoveToNextAttribute())
					{
						switch (xmlUtil.Reader.Name)
						{
						case "name":
							text4 = xmlUtil.Reader.Value;
							VerifySectionName(text4, xmlUtil, ExceptionAction.Local, allowImplicit: false);
							break;
						case "type":
							xmlUtil.VerifyAndGetNonEmptyStringAttribute(ExceptionAction.Local, out newValue2);
							flag2 = true;
							break;
						case "allowLocation":
							xmlUtil.VerifyAndGetBooleanAttribute(ExceptionAction.Local, defaultValue: true, out newValue3);
							break;
						case "allowExeDefinition":
							try
							{
								allowExeDefinition = AllowExeDefinitionToEnum(xmlUtil.Reader.Value, xmlUtil);
							}
							catch (ConfigurationException ce3)
							{
								xmlUtil.SchemaErrors.AddError(ce3, ExceptionAction.Local);
							}
							break;
						case "allowDefinition":
							try
							{
								allowDefinition = AllowDefinitionToEnum(xmlUtil.Reader.Value, xmlUtil);
							}
							catch (ConfigurationException ce2)
							{
								xmlUtil.SchemaErrors.AddError(ce2, ExceptionAction.Local);
							}
							break;
						case "restartOnExternalChanges":
							xmlUtil.VerifyAndGetBooleanAttribute(ExceptionAction.Local, defaultValue: true, out newValue4);
							break;
						case "requirePermission":
							xmlUtil.VerifyAndGetBooleanAttribute(ExceptionAction.Local, defaultValue: true, out newValue5);
							break;
						case "overrideModeDefault":
							try
							{
								overrideModeDefault = OverrideModeSetting.CreateFromXmlReadValue(OverrideModeSetting.ParseOverrideModeXmlValue(xmlUtil.Reader.Value, xmlUtil));
								if (overrideModeDefault.OverrideMode == OverrideMode.Inherit)
								{
									overrideModeDefault.ChangeModeInternal(OverrideMode.Allow);
								}
							}
							catch (ConfigurationException ce)
							{
								xmlUtil.SchemaErrors.AddError(ce, ExceptionAction.Local);
							}
							break;
						default:
							xmlUtil.AddErrorUnrecognizedAttribute(ExceptionAction.Local);
							break;
						}
					}
					xmlUtil.Reader.MoveToElement();
					if (!xmlUtil.VerifyRequiredAttribute(text4, "name", ExceptionAction.NonSpecific))
					{
						xmlUtil.SchemaErrors.RetrieveAndResetLocalErrors(keepLocalErrors: true);
						break;
					}
					if (!flag2)
					{
						xmlUtil.AddErrorRequiredAttribute("type", ExceptionAction.Local);
					}
					string text5 = CombineConfigKey(parentConfigKey, text4);
					FactoryRecord factoryRecord3 = (FactoryRecord)factoryList[text5];
					if (factoryRecord3 != null)
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined_at_this_level", text4), xmlUtil), ExceptionAction.Local);
					}
					else
					{
						FactoryRecord factoryRecord4 = _parent.FindFactoryRecord(text5, permitErrors: true);
						if (factoryRecord4 != null)
						{
							text5 = factoryRecord4.ConfigKey;
							if (factoryRecord4.IsGroup)
							{
								xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", text4), xmlUtil), ExceptionAction.Local);
								factoryRecord4 = null;
							}
							else if (!factoryRecord4.IsEquivalentSectionFactory(Host, newValue2, newValue3, allowDefinition, allowExeDefinition, newValue4, newValue5))
							{
								xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", text4), xmlUtil), ExceptionAction.Local);
								factoryRecord4 = null;
							}
						}
						factoryRecord3 = (FactoryRecord)(factoryList[text5] = ((factoryRecord4 == null) ? new FactoryRecord(text5, parentConfigKey, text4, newValue2, newValue3, allowDefinition, allowExeDefinition, overrideModeDefault, newValue4, newValue5, _flags[8192], isUndeclared: false, xmlUtil.Filename, lineNumber2) : factoryRecord4.CloneSection(xmlUtil.Filename, lineNumber2)));
					}
					factoryRecord3.AddErrors(xmlUtil.SchemaErrors.RetrieveAndResetLocalErrors(keepLocalErrors: true));
					break;
				}
				case "remove":
				{
					string text = null;
					while (xmlUtil.Reader.MoveToNextAttribute())
					{
						if (xmlUtil.Reader.Name != "name")
						{
							xmlUtil.AddErrorUnrecognizedAttribute(ExceptionAction.NonSpecific);
						}
						text = xmlUtil.Reader.Value;
						_ = xmlUtil.Reader.LineNumber;
					}
					xmlUtil.Reader.MoveToElement();
					if (xmlUtil.VerifyRequiredAttribute(text, "name", ExceptionAction.NonSpecific))
					{
						VerifySectionName(text, xmlUtil, ExceptionAction.NonSpecific, allowImplicit: false);
					}
					break;
				}
				case "clear":
					xmlUtil.VerifyNoUnrecognizedAttributes(ExceptionAction.NonSpecific);
					break;
				default:
					xmlUtil.AddErrorUnrecognizedElement(ExceptionAction.NonSpecific);
					xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
					flag = true;
					break;
				}
				if (flag)
				{
					continue;
				}
				xmlUtil.StrictReadToNextElement(ExceptionAction.NonSpecific);
				if (xmlUtil.Reader.Depth > depth + 1)
				{
					xmlUtil.AddErrorUnrecognizedElement(ExceptionAction.NonSpecific);
					while (xmlUtil.Reader.Depth > depth + 1)
					{
						xmlUtil.ReadToNextElement();
					}
				}
			}
		}

		internal static ConfigurationAllowExeDefinition AllowExeDefinitionToEnum(string allowExeDefinition, XmlUtil xmlUtil)
		{
			return allowExeDefinition switch
			{
				"MachineOnly" => ConfigurationAllowExeDefinition.MachineOnly, 
				"MachineToApplication" => ConfigurationAllowExeDefinition.MachineToApplication, 
				"MachineToRoamingUser" => ConfigurationAllowExeDefinition.MachineToRoamingUser, 
				"MachineToLocalUser" => ConfigurationAllowExeDefinition.MachineToLocalUser, 
				_ => throw new ConfigurationErrorsException(SR.GetString("Config_section_allow_exe_definition_attribute_invalid"), xmlUtil), 
			};
		}

		internal static ConfigurationAllowDefinition AllowDefinitionToEnum(string allowDefinition, XmlUtil xmlUtil)
		{
			return xmlUtil.Reader.Value switch
			{
				"Everywhere" => ConfigurationAllowDefinition.Everywhere, 
				"MachineOnly" => ConfigurationAllowDefinition.MachineOnly, 
				"MachineToApplication" => ConfigurationAllowDefinition.MachineToApplication, 
				"MachineToWebRoot" => ConfigurationAllowDefinition.MachineToWebRoot, 
				_ => throw new ConfigurationErrorsException(SR.GetString("Config_section_allow_definition_attribute_invalid"), xmlUtil), 
			};
		}

		internal static string CombineConfigKey(string parentConfigKey, string tagName)
		{
			if (string.IsNullOrEmpty(parentConfigKey))
			{
				return tagName;
			}
			if (string.IsNullOrEmpty(tagName))
			{
				return parentConfigKey;
			}
			return parentConfigKey + "/" + tagName;
		}

		internal static void SplitConfigKey(string configKey, out string group, out string name)
		{
			int num = configKey.LastIndexOf('/');
			if (num == -1)
			{
				group = string.Empty;
				name = configKey;
			}
			else
			{
				group = configKey.Substring(0, num);
				name = configKey.Substring(num + 1);
			}
		}

		[Conditional("DBG")]
		private void DebugValidateIndirectInputs(SectionRecord sectionRecord)
		{
			if (!_parent.IsRootConfig)
			{
				for (int num = sectionRecord.IndirectLocationInputs.Count - 1; num >= 0; num--)
				{
					_ = sectionRecord.IndirectLocationInputs[num];
				}
			}
		}

		private OverrideMode ResolveOverrideModeFromParent(string configKey, out OverrideMode childLockMode)
		{
			OverrideMode overrideMode = OverrideMode.Inherit;
			BaseConfigurationRecord parent = Parent;
			BaseConfigurationRecord parent2 = Parent;
			childLockMode = OverrideMode.Inherit;
			while (!parent.IsRootConfig && overrideMode == OverrideMode.Inherit)
			{
				SectionRecord sectionRecord = parent.GetSectionRecord(configKey, permitErrors: true);
				if (sectionRecord != null)
				{
					if (!IsLocationConfig || !object.ReferenceEquals(parent2, parent))
					{
						overrideMode = (childLockMode = ((!sectionRecord.LockChildren) ? OverrideMode.Allow : OverrideMode.Deny));
					}
					else
					{
						overrideMode = ((!sectionRecord.Locked) ? OverrideMode.Allow : OverrideMode.Deny);
						childLockMode = ((!sectionRecord.LockChildren) ? OverrideMode.Allow : OverrideMode.Deny);
					}
				}
				parent = parent._parent;
			}
			if (overrideMode == OverrideMode.Inherit)
			{
				bool flag = false;
				OverrideMode overrideMode2 = FindFactoryRecord(configKey, permitErrors: true).OverrideModeDefault.OverrideMode;
				if (!((!IsLocationConfig) ? (GetFactoryRecord(configKey, permitErrors: true) != null) : (Parent.GetFactoryRecord(configKey, permitErrors: true) != null)))
				{
					overrideMode = (childLockMode = overrideMode2);
				}
				else
				{
					overrideMode = OverrideMode.Allow;
					childLockMode = overrideMode2;
				}
			}
			return overrideMode;
		}

		protected OverrideMode GetSectionLockedMode(string configKey)
		{
			OverrideMode childLockMode = OverrideMode.Inherit;
			return GetSectionLockedMode(configKey, out childLockMode);
		}

		protected OverrideMode GetSectionLockedMode(string configKey, out OverrideMode childLockMode)
		{
			OverrideMode overrideMode = OverrideMode.Inherit;
			SectionRecord sectionRecord = GetSectionRecord(configKey, permitErrors: true);
			if (sectionRecord != null)
			{
				overrideMode = ((!sectionRecord.Locked) ? OverrideMode.Allow : OverrideMode.Deny);
				childLockMode = ((!sectionRecord.LockChildren) ? OverrideMode.Allow : OverrideMode.Deny);
			}
			else
			{
				overrideMode = ResolveOverrideModeFromParent(configKey, out childLockMode);
			}
			return overrideMode;
		}

		private void ScanSections(XmlUtil xmlUtil)
		{
			ScanSectionsRecursive(xmlUtil, string.Empty, inLocation: false, null, OverrideModeSetting.LocationDefault, skipInChildApps: false);
		}

		private void ScanSectionsRecursive(XmlUtil xmlUtil, string parentConfigKey, bool inLocation, string locationSubPath, OverrideModeSetting overrideMode, bool skipInChildApps)
		{
			xmlUtil.SchemaErrors.ResetLocalErrors();
			int num;
			if (parentConfigKey.Length == 0 && !inLocation)
			{
				num = 0;
			}
			else
			{
				num = xmlUtil.Reader.Depth;
				xmlUtil.StrictReadToNextElement(ExceptionAction.NonSpecific);
			}
			while (xmlUtil.Reader.Depth == num + 1)
			{
				string name = xmlUtil.Reader.Name;
				if (name == "configSections")
				{
					xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_client_config_too_many_configsections_elements", name), xmlUtil), ExceptionAction.NonSpecific);
					xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
					continue;
				}
				if (name == "location")
				{
					if (parentConfigKey.Length > 0 || inLocation)
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_location_location_not_allowed"), xmlUtil), ExceptionAction.Global);
						xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
					}
					else
					{
						ScanLocationSection(xmlUtil);
					}
					continue;
				}
				string text = CombineConfigKey(parentConfigKey, name);
				FactoryRecord factoryRecord = FindFactoryRecord(text, permitErrors: true);
				if (factoryRecord == null)
				{
					if (!ClassFlags[64])
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_unrecognized_configuration_section", text), xmlUtil), ExceptionAction.Local);
					}
					VerifySectionName(name, xmlUtil, ExceptionAction.Local, allowImplicit: false);
					factoryRecord = new FactoryRecord(text, parentConfigKey, name, typeof(DefaultSection).AssemblyQualifiedName, allowLocation: true, ConfigurationAllowDefinition.Everywhere, ConfigurationAllowExeDefinition.MachineToRoamingUser, OverrideModeSetting.SectionDefault, restartOnExternalChanges: true, requirePermission: true, _flags[8192], isUndeclared: true, null, -1);
					factoryRecord.AddErrors(xmlUtil.SchemaErrors.RetrieveAndResetLocalErrors(keepLocalErrors: true));
					EnsureFactories()[text] = factoryRecord;
				}
				if (factoryRecord.IsGroup)
				{
					if (factoryRecord.HasErrors)
					{
						xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
						continue;
					}
					if (xmlUtil.Reader.AttributeCount > 0)
					{
						while (xmlUtil.Reader.MoveToNextAttribute())
						{
							if (IsReservedAttributeName(xmlUtil.Reader.Name))
							{
								xmlUtil.AddErrorReservedAttribute(ExceptionAction.NonSpecific);
							}
						}
						xmlUtil.Reader.MoveToElement();
					}
					ScanSectionsRecursive(xmlUtil, text, inLocation, locationSubPath, overrideMode, skipInChildApps);
					continue;
				}
				text = factoryRecord.ConfigKey;
				string filename = xmlUtil.Filename;
				int lineNumber = xmlUtil.LineNumber;
				string rawXml = null;
				string text2 = null;
				string text3 = null;
				object configSourceStreamVersion = null;
				string protectionProviderName = null;
				OverrideMode overrideMode2 = OverrideMode.Inherit;
				OverrideMode childLockMode = OverrideMode.Inherit;
				bool flag = false;
				bool flag2 = locationSubPath == null;
				if (!factoryRecord.HasErrors)
				{
					if (inLocation && !factoryRecord.AllowLocation)
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_section_cannot_be_used_in_location"), xmlUtil), ExceptionAction.Local);
					}
					if (flag2)
					{
						SectionRecord sectionRecord = GetSectionRecord(text, permitErrors: true);
						if (sectionRecord != null && sectionRecord.HasFileInput && !factoryRecord.IsIgnorable())
						{
							xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_sections_must_be_unique"), xmlUtil), ExceptionAction.Local);
						}
						try
						{
							VerifyDefinitionAllowed(factoryRecord, _configPath, xmlUtil);
						}
						catch (ConfigurationException ce)
						{
							xmlUtil.SchemaErrors.AddError(ce, ExceptionAction.Local);
						}
					}
					overrideMode2 = GetSectionLockedMode(text, out childLockMode);
					if (overrideMode2 == OverrideMode.Deny)
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_section_locked"), xmlUtil), ExceptionAction.Local);
					}
					if (xmlUtil.Reader.AttributeCount >= 1)
					{
						string attribute = xmlUtil.Reader.GetAttribute("configSource");
						if (attribute != null)
						{
							try
							{
								text2 = NormalizeConfigSource(attribute, xmlUtil);
							}
							catch (ConfigurationException ce2)
							{
								xmlUtil.SchemaErrors.AddError(ce2, ExceptionAction.Local);
							}
							if (xmlUtil.Reader.AttributeCount != 1)
							{
								xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_source_syntax_error"), xmlUtil), ExceptionAction.Local);
							}
						}
						string attribute2 = xmlUtil.Reader.GetAttribute("configProtectionProvider");
						if (attribute2 != null)
						{
							try
							{
								protectionProviderName = ValidateProtectionProviderAttribute(attribute2, xmlUtil);
							}
							catch (ConfigurationException ce3)
							{
								xmlUtil.SchemaErrors.AddError(ce3, ExceptionAction.Local);
							}
							if (xmlUtil.Reader.AttributeCount != 1)
							{
								xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Protection_provider_syntax_error"), xmlUtil), ExceptionAction.Local);
							}
						}
						if (attribute != null && !xmlUtil.Reader.IsEmptyElement)
						{
							while (xmlUtil.Reader.Read())
							{
								XmlNodeType nodeType = xmlUtil.Reader.NodeType;
								if (nodeType == XmlNodeType.EndElement)
								{
									break;
								}
								if (nodeType != XmlNodeType.Comment)
								{
									xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Config_source_syntax_error"), xmlUtil), ExceptionAction.Local);
									if (nodeType == XmlNodeType.Element)
									{
										xmlUtil.StrictSkipToOurParentsEndElement(ExceptionAction.NonSpecific);
									}
									else
									{
										xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
									}
									flag = true;
									break;
								}
							}
						}
					}
					if (text2 != null)
					{
						try
						{
							try
							{
								text3 = Host.GetStreamNameForConfigSource(ConfigStreamInfo.StreamName, text2);
							}
							catch (Exception e)
							{
								throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_source_invalid"), e, xmlUtil);
							}
							ValidateUniqueConfigSource(text, text3, text2, xmlUtil);
							configSourceStreamVersion = MonitorStream(text, text2, text3);
						}
						catch (ConfigurationException ce4)
						{
							xmlUtil.SchemaErrors.AddError(ce4, ExceptionAction.Local);
						}
					}
					if (!xmlUtil.SchemaErrors.HasLocalErrors && text2 == null && ShouldPrefetchRawXml(factoryRecord))
					{
						rawXml = xmlUtil.CopySection();
						if (xmlUtil.Reader.NodeType != XmlNodeType.Element)
						{
							xmlUtil.VerifyIgnorableNodeType(ExceptionAction.NonSpecific);
							xmlUtil.StrictReadToNextElement(ExceptionAction.NonSpecific);
						}
						flag = true;
					}
				}
				List<ConfigurationException> errors = xmlUtil.SchemaErrors.RetrieveAndResetLocalErrors(flag2);
				if (!flag)
				{
					xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
				}
				bool flag3 = true;
				if (flag2)
				{
					if (ShouldSkipDueToInheritInChildApplications(skipInChildApps))
					{
						flag3 = false;
					}
				}
				else if (!_flags[1048576])
				{
					flag3 = false;
				}
				if (flag3)
				{
					string targetConfigPath = ((locationSubPath == null) ? _configPath : null);
					SectionXmlInfo sectionXmlInfo = new SectionXmlInfo(text, _configPath, targetConfigPath, locationSubPath, filename, lineNumber, ConfigStreamInfo.StreamVersion, rawXml, text2, text3, configSourceStreamVersion, protectionProviderName, overrideMode, skipInChildApps);
					if (locationSubPath == null)
					{
						SectionRecord sectionRecord2 = EnsureSectionRecordUnsafe(text, permitErrors: true);
						sectionRecord2.ChangeLockSettings(overrideMode2, childLockMode);
						SectionInput sectionInput = new SectionInput(sectionXmlInfo, errors);
						sectionRecord2.AddFileInput(sectionInput);
					}
					else
					{
						LocationSectionRecord value = new LocationSectionRecord(sectionXmlInfo, errors);
						EnsureLocationSections().Add(value);
					}
				}
			}
		}

		private void ScanLocationSection(XmlUtil xmlUtil)
		{
			string text = null;
			bool newValue = true;
			int globalErrorCount = xmlUtil.SchemaErrors.GlobalErrorCount;
			OverrideModeSetting overrideMode = OverrideModeSetting.LocationDefault;
			bool flag = false;
			while (xmlUtil.Reader.MoveToNextAttribute())
			{
				switch (xmlUtil.Reader.Name)
				{
				case "path":
					text = xmlUtil.Reader.Value;
					break;
				case "allowOverride":
				{
					if (flag)
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Invalid_override_mode_declaration"), xmlUtil), ExceptionAction.Global);
						break;
					}
					bool newValue2 = true;
					xmlUtil.VerifyAndGetBooleanAttribute(ExceptionAction.Global, defaultValue: true, out newValue2);
					overrideMode = OverrideModeSetting.CreateFromXmlReadValue(newValue2);
					flag = true;
					break;
				}
				case "overrideMode":
					if (flag)
					{
						xmlUtil.SchemaErrors.AddError(new ConfigurationErrorsException(SR.GetString("Invalid_override_mode_declaration"), xmlUtil), ExceptionAction.Global);
						break;
					}
					overrideMode = OverrideModeSetting.CreateFromXmlReadValue(OverrideModeSetting.ParseOverrideModeXmlValue(xmlUtil.Reader.Value, xmlUtil));
					flag = true;
					break;
				case "inheritInChildApplications":
					xmlUtil.VerifyAndGetBooleanAttribute(ExceptionAction.Global, defaultValue: true, out newValue);
					break;
				default:
					xmlUtil.AddErrorUnrecognizedAttribute(ExceptionAction.Global);
					break;
				}
			}
			xmlUtil.Reader.MoveToElement();
			try
			{
				text = NormalizeLocationSubPath(text, xmlUtil);
				if (text == null && !newValue && Host.IsDefinitionAllowed(_configPath, ConfigurationAllowDefinition.MachineToWebRoot, ConfigurationAllowExeDefinition.MachineOnly))
				{
					throw new ConfigurationErrorsException(SR.GetString("Location_invalid_inheritInChildApplications_in_machine_or_root_web_config"), xmlUtil);
				}
			}
			catch (ConfigurationErrorsException ce)
			{
				xmlUtil.SchemaErrors.AddError(ce, ExceptionAction.Global);
			}
			if (xmlUtil.SchemaErrors.GlobalErrorCount > globalErrorCount)
			{
				xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
				return;
			}
			if (text == null)
			{
				ScanSectionsRecursive(xmlUtil, string.Empty, inLocation: true, null, overrideMode, !newValue);
				return;
			}
			if (!_flags[1048576])
			{
				xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
				return;
			}
			IInternalConfigHost host = Host;
			if (this is RuntimeConfigurationRecord && host != null && text.Length != 0 && text[0] != '.')
			{
				if (s_appConfigPath == null)
				{
					object configContext = ConfigContext;
					if (configContext != null)
					{
						string value = configContext.ToString();
						Interlocked.CompareExchange(ref s_appConfigPath, value, null);
					}
				}
				string configPathFromLocationSubPath = host.GetConfigPathFromLocationSubPath(_configPath, text);
				if (!StringUtil.StartsWithIgnoreCase(s_appConfigPath, configPathFromLocationSubPath) && !StringUtil.StartsWithIgnoreCase(configPathFromLocationSubPath, s_appConfigPath))
				{
					xmlUtil.StrictSkipToNextElement(ExceptionAction.NonSpecific);
					return;
				}
			}
			AddLocation(text);
			ScanSectionsRecursive(xmlUtil, string.Empty, inLocation: true, text, overrideMode, !newValue);
		}

		protected virtual void AddLocation(string LocationSubPath)
		{
		}

		private void ResolveLocationSections()
		{
			if (_flags[256])
			{
				return;
			}
			if (!_parent.IsRootConfig)
			{
				_parent.ResolveLocationSections();
			}
			lock (this)
			{
				if (!_flags[256] && _locationSections != null)
				{
					HybridDictionary hybridDictionary = new HybridDictionary(caseInsensitive: true);
					foreach (LocationSectionRecord locationSection in _locationSections)
					{
						string configPathFromLocationSubPath = Host.GetConfigPathFromLocationSubPath(_configPath, locationSection.SectionXmlInfo.SubPath);
						locationSection.SectionXmlInfo.TargetConfigPath = configPathFromLocationSubPath;
						HybridDictionary hybridDictionary2 = (HybridDictionary)hybridDictionary[configPathFromLocationSubPath];
						if (hybridDictionary2 == null)
						{
							hybridDictionary2 = new HybridDictionary(caseInsensitive: false);
							hybridDictionary.Add(configPathFromLocationSubPath, hybridDictionary2);
						}
						LocationSectionRecord locationSectionRecord2 = (LocationSectionRecord)hybridDictionary2[locationSection.ConfigKey];
						FactoryRecord factoryRecord = null;
						if (locationSectionRecord2 == null)
						{
							hybridDictionary2.Add(locationSection.ConfigKey, locationSection);
						}
						else
						{
							factoryRecord = FindFactoryRecord(locationSection.ConfigKey, permitErrors: true);
							if (factoryRecord == null || !factoryRecord.IsIgnorable())
							{
								if (!locationSectionRecord2.HasErrors)
								{
									locationSectionRecord2.AddError(new ConfigurationErrorsException(SR.GetString("Config_sections_must_be_unique"), locationSectionRecord2.SectionXmlInfo));
								}
								locationSection.AddError(new ConfigurationErrorsException(SR.GetString("Config_sections_must_be_unique"), locationSection.SectionXmlInfo));
							}
						}
						if (factoryRecord == null)
						{
							factoryRecord = FindFactoryRecord(locationSection.ConfigKey, permitErrors: true);
						}
						if (!factoryRecord.HasErrors)
						{
							try
							{
								VerifyDefinitionAllowed(factoryRecord, configPathFromLocationSubPath, locationSection.SectionXmlInfo);
							}
							catch (ConfigurationException e)
							{
								locationSection.AddError(e);
							}
						}
					}
					BaseConfigurationRecord parent = _parent;
					while (!parent.IsRootConfig)
					{
						foreach (LocationSectionRecord locationSection2 in _locationSections)
						{
							bool flag = false;
							SectionRecord sectionRecord = parent.GetSectionRecord(locationSection2.ConfigKey, permitErrors: true);
							if (sectionRecord != null && (sectionRecord.LockChildren || sectionRecord.Locked))
							{
								flag = true;
							}
							else if (parent._locationSections != null)
							{
								string targetConfigPath = locationSection2.SectionXmlInfo.TargetConfigPath;
								foreach (LocationSectionRecord locationSection3 in parent._locationSections)
								{
									string targetConfigPath2 = locationSection3.SectionXmlInfo.TargetConfigPath;
									if (locationSection3.SectionXmlInfo.OverrideModeSetting.IsLocked && locationSection2.ConfigKey == locationSection3.ConfigKey && UrlPath.IsEqualOrSubpath(targetConfigPath, targetConfigPath2))
									{
										flag = true;
										break;
									}
								}
							}
							if (flag)
							{
								locationSection2.AddError(new ConfigurationErrorsException(SR.GetString("Config_section_locked"), locationSection2.SectionXmlInfo));
							}
						}
						parent = parent._parent;
					}
				}
				_flags[256] = true;
			}
		}

		private void VerifyDefinitionAllowed(FactoryRecord factoryRecord, string configPath, IConfigErrorInfo errorInfo)
		{
			Host.VerifyDefinitionAllowed(configPath, factoryRecord.AllowDefinition, factoryRecord.AllowExeDefinition, errorInfo);
		}

		internal bool IsDefinitionAllowed(ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition)
		{
			return Host.IsDefinitionAllowed(_configPath, allowDefinition, allowExeDefinition);
		}

		protected static void VerifySectionName(string name, XmlUtil xmlUtil, ExceptionAction action, bool allowImplicit)
		{
			try
			{
				VerifySectionName(name, xmlUtil, allowImplicit);
			}
			catch (ConfigurationErrorsException ce)
			{
				xmlUtil.SchemaErrors.AddError(ce, action);
			}
		}

		protected static void VerifySectionName(string name, IConfigErrorInfo errorInfo, bool allowImplicit)
		{
			if (string.IsNullOrEmpty(name))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_invalid"), errorInfo);
			}
			try
			{
				XmlConvert.VerifyName(name);
			}
			catch (Exception e)
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_tag_name_invalid"), e, errorInfo);
			}
			catch
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_tag_name_invalid"), null, errorInfo);
			}
			if (IsImplicitSection(name))
			{
				if (!allowImplicit)
				{
					throw new ConfigurationErrorsException(SR.GetString("Cannot_declare_or_remove_implicit_section", name), errorInfo);
				}
				return;
			}
			if (StringUtil.StartsWith(name, "config"))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_cannot_begin_with_config"), errorInfo);
			}
			if (name == "location")
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_cannot_be_location"), errorInfo);
			}
		}

		internal static string NormalizeLocationSubPath(string subPath, IConfigErrorInfo errorInfo)
		{
			if (string.IsNullOrEmpty(subPath))
			{
				return null;
			}
			if (subPath == ".")
			{
				return null;
			}
			string text = subPath.TrimStart();
			if (text.Length != subPath.Length)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_location_path_invalid_first_character"), errorInfo);
			}
			if ("\\./".IndexOf(subPath[0]) != -1)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_location_path_invalid_first_character"), errorInfo);
			}
			text = subPath.TrimEnd();
			if (text.Length != subPath.Length)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_location_path_invalid_last_character"), errorInfo);
			}
			if ("\\./".IndexOf(subPath[subPath.Length - 1]) != -1)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_location_path_invalid_last_character"), errorInfo);
			}
			if (subPath.IndexOfAny(s_invalidSubPathCharactersArray) != -1)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_location_path_invalid_character"), errorInfo);
			}
			return subPath;
		}

		protected SectionRecord GetSectionRecord(string configKey, bool permitErrors)
		{
			SectionRecord sectionRecord = ((_sectionRecords == null) ? null : ((SectionRecord)_sectionRecords[configKey]));
			if (sectionRecord != null && !permitErrors)
			{
				sectionRecord.ThrowOnErrors();
			}
			return sectionRecord;
		}

		protected SectionRecord EnsureSectionRecord(string configKey, bool permitErrors)
		{
			return EnsureSectionRecordImpl(configKey, permitErrors, setLockSettings: true);
		}

		protected SectionRecord EnsureSectionRecordUnsafe(string configKey, bool permitErrors)
		{
			return EnsureSectionRecordImpl(configKey, permitErrors, setLockSettings: false);
		}

		private SectionRecord EnsureSectionRecordImpl(string configKey, bool permitErrors, bool setLockSettings)
		{
			SectionRecord sectionRecord = GetSectionRecord(configKey, permitErrors);
			if (sectionRecord == null)
			{
				lock (this)
				{
					if (_sectionRecords == null)
					{
						_sectionRecords = new Hashtable();
					}
					else
					{
						sectionRecord = GetSectionRecord(configKey, permitErrors);
					}
					if (sectionRecord == null)
					{
						sectionRecord = new SectionRecord(configKey);
						_sectionRecords.Add(configKey, sectionRecord);
					}
				}
				if (setLockSettings)
				{
					OverrideMode overrideMode = OverrideMode.Inherit;
					OverrideMode childLockMode = OverrideMode.Inherit;
					overrideMode = ResolveOverrideModeFromParent(configKey, out childLockMode);
					sectionRecord.ChangeLockSettings(overrideMode, childLockMode);
				}
			}
			return sectionRecord;
		}

		internal FactoryRecord GetFactoryRecord(string configKey, bool permitErrors)
		{
			if (_factoryRecords == null)
			{
				return null;
			}
			FactoryRecord factoryRecord = (FactoryRecord)_factoryRecords[configKey];
			if (factoryRecord != null && !permitErrors)
			{
				factoryRecord.ThrowOnErrors();
			}
			return factoryRecord;
		}

		protected Hashtable EnsureFactories()
		{
			if (_factoryRecords == null)
			{
				_factoryRecords = new Hashtable();
			}
			return _factoryRecords;
		}

		private ArrayList EnsureLocationSections()
		{
			if (_locationSections == null)
			{
				_locationSections = new ArrayList();
			}
			return _locationSections;
		}

		internal static string NormalizeConfigSource(string configSource, IConfigErrorInfo errorInfo)
		{
			if (string.IsNullOrEmpty(configSource))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_source_invalid_format"), errorInfo);
			}
			string text = configSource.Trim();
			if (text.Length != configSource.Length)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_source_invalid_format"), errorInfo);
			}
			if (configSource.IndexOf('/') != -1)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_source_invalid_chars"), errorInfo);
			}
			if (string.IsNullOrEmpty(configSource) || Path.IsPathRooted(configSource))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_source_invalid_format"), errorInfo);
			}
			return configSource;
		}

		protected object MonitorStream(string configKey, string configSource, string streamname)
		{
			lock (this)
			{
				if (_flags[2])
				{
					return null;
				}
				StreamInfo streamInfo = (StreamInfo)ConfigStreamInfo.StreamInfos[streamname];
				if (streamInfo != null)
				{
					if (streamInfo.SectionName != configKey)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_source_cannot_be_shared", streamname));
					}
					if (streamInfo.IsMonitored)
					{
						return streamInfo.Version;
					}
				}
				else
				{
					streamInfo = new StreamInfo(configKey, configSource, streamname);
					ConfigStreamInfo.StreamInfos.Add(streamname, streamInfo);
				}
			}
			object streamVersion = Host.GetStreamVersion(streamname);
			StreamChangeCallback callback = null;
			lock (this)
			{
				if (_flags[2])
				{
					return null;
				}
				StreamInfo streamInfo2 = (StreamInfo)ConfigStreamInfo.StreamInfos[streamname];
				if (streamInfo2.IsMonitored)
				{
					return streamInfo2.Version;
				}
				streamInfo2.IsMonitored = true;
				streamInfo2.Version = streamVersion;
				if (_flags[65536])
				{
					if (ConfigStreamInfo.CallbackDelegate == null)
					{
						ConfigStreamInfo.CallbackDelegate = OnStreamChanged;
					}
					callback = ConfigStreamInfo.CallbackDelegate;
				}
			}
			if (_flags[65536])
			{
				Host.StartMonitoringStreamForChanges(streamname, callback);
			}
			return streamVersion;
		}

		private void OnStreamChanged(string streamname)
		{
			string sectionName;
			lock (this)
			{
				if (_flags[2])
				{
					return;
				}
				StreamInfo streamInfo = (StreamInfo)ConfigStreamInfo.StreamInfos[streamname];
				if (streamInfo == null || !streamInfo.IsMonitored)
				{
					return;
				}
				sectionName = streamInfo.SectionName;
			}
			bool flag;
			if (sectionName == null)
			{
				flag = true;
			}
			else
			{
				FactoryRecord factoryRecord = FindFactoryRecord(sectionName, permitErrors: false);
				flag = factoryRecord.RestartOnExternalChanges;
			}
			if (flag)
			{
				_configRoot.FireConfigChanged(_configPath);
			}
			else
			{
				_configRoot.ClearResult(this, sectionName, forceEvaluation: false);
			}
		}

		private void ValidateUniqueConfigSource(string configKey, string configSourceStreamName, string configSourceArg, IConfigErrorInfo errorInfo)
		{
			lock (this)
			{
				if (ConfigStreamInfo.HasStreamInfos)
				{
					StreamInfo streamInfo = (StreamInfo)ConfigStreamInfo.StreamInfos[configSourceStreamName];
					if (streamInfo != null && streamInfo.SectionName != configKey)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_source_cannot_be_shared", configSourceArg), errorInfo);
					}
				}
			}
			ValidateUniqueChildConfigSource(configKey, configSourceStreamName, configSourceArg, errorInfo);
		}

		protected void ValidateUniqueChildConfigSource(string configKey, string configSourceStreamName, string configSourceArg, IConfigErrorInfo errorInfo)
		{
			BaseConfigurationRecord baseConfigurationRecord = ((!IsLocationConfig) ? _parent : _parent._parent);
			while (!baseConfigurationRecord.IsRootConfig)
			{
				lock (baseConfigurationRecord)
				{
					if (baseConfigurationRecord.ConfigStreamInfo.HasStreamInfos)
					{
						StreamInfo streamInfo = (StreamInfo)baseConfigurationRecord.ConfigStreamInfo.StreamInfos[configSourceStreamName];
						if (streamInfo != null)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_source_parent_conflict", configSourceArg), errorInfo);
						}
					}
				}
				baseConfigurationRecord = baseConfigurationRecord.Parent;
			}
		}

		internal void hlClearResultRecursive(string configKey, bool forceEvaluatation)
		{
			RefreshFactoryRecord(configKey);
			SectionRecord sectionRecord = GetSectionRecord(configKey, permitErrors: false);
			if (sectionRecord != null)
			{
				sectionRecord.ClearResult();
				sectionRecord.ClearRawXml();
			}
			if (forceEvaluatation && !IsInitDelayed && !string.IsNullOrEmpty(ConfigStreamInfo.StreamName))
			{
				if (_flags[262144])
				{
					throw ExceptionUtil.UnexpectedError("BaseConfigurationRecord::hlClearResultRecursive");
				}
				FactoryRecord factoryRecord = FindFactoryRecord(configKey, permitErrors: false);
				if (factoryRecord != null && !factoryRecord.IsGroup)
				{
					configKey = factoryRecord.ConfigKey;
					sectionRecord = EnsureSectionRecord(configKey, permitErrors: false);
					if (!sectionRecord.HasFileInput)
					{
						SectionXmlInfo sectionXmlInfo = new SectionXmlInfo(configKey, _configPath, _configPath, null, ConfigStreamInfo.StreamName, 0, null, null, null, null, null, null, OverrideModeSetting.LocationDefault, skipInChildApps: false);
						SectionInput sectionInput = new SectionInput(sectionXmlInfo, null);
						sectionRecord.AddFileInput(sectionInput);
					}
				}
			}
			if (_children == null)
			{
				return;
			}
			IEnumerable values = _children.Values;
			foreach (BaseConfigurationRecord item in values)
			{
				item.hlClearResultRecursive(configKey, forceEvaluatation);
			}
		}

		internal BaseConfigurationRecord hlGetChild(string configName)
		{
			if (_children == null)
			{
				return null;
			}
			return (BaseConfigurationRecord)_children[configName];
		}

		internal void hlAddChild(string configName, BaseConfigurationRecord child)
		{
			if (_children == null)
			{
				_children = new Hashtable(StringComparer.OrdinalIgnoreCase);
			}
			_children.Add(configName, child);
		}

		internal void hlRemoveChild(string configName)
		{
			if (_children != null)
			{
				_children.Remove(configName);
			}
		}

		internal bool hlNeedsChildFor(string configName)
		{
			if (IsRootConfig)
			{
				return true;
			}
			if (HasInitErrors)
			{
				return false;
			}
			string text = ConfigPathUtility.Combine(_configPath, configName);
			try
			{
				using (Impersonate())
				{
					if (Host.IsConfigRecordRequired(text))
					{
						return true;
					}
				}
			}
			catch
			{
				throw;
			}
			if (_flags[1048576])
			{
				BaseConfigurationRecord baseConfigurationRecord = this;
				while (!baseConfigurationRecord.IsRootConfig)
				{
					if (baseConfigurationRecord._locationSections != null)
					{
						baseConfigurationRecord.ResolveLocationSections();
						foreach (LocationSectionRecord locationSection in baseConfigurationRecord._locationSections)
						{
							if (UrlPath.IsEqualOrSubpath(text, locationSection.SectionXmlInfo.TargetConfigPath))
							{
								return true;
							}
						}
					}
					baseConfigurationRecord = baseConfigurationRecord._parent;
				}
			}
			return false;
		}

		internal void CloseRecursive()
		{
			if (_flags[2])
			{
				return;
			}
			bool flag = false;
			HybridDictionary hybridDictionary = null;
			StreamChangeCallback callback = null;
			lock (this)
			{
				if (!_flags[2])
				{
					_flags[2] = true;
					flag = true;
					if (!IsLocationConfig && ConfigStreamInfo.HasStreamInfos)
					{
						callback = ConfigStreamInfo.CallbackDelegate;
						hybridDictionary = ConfigStreamInfo.StreamInfos;
						ConfigStreamInfo.CallbackDelegate = null;
						ConfigStreamInfo.ClearStreamInfos();
					}
				}
			}
			if (!flag)
			{
				return;
			}
			if (_children != null)
			{
				foreach (BaseConfigurationRecord value in _children.Values)
				{
					value.CloseRecursive();
				}
			}
			if (hybridDictionary == null)
			{
				return;
			}
			foreach (StreamInfo value2 in hybridDictionary.Values)
			{
				if (value2.IsMonitored)
				{
					Host.StopMonitoringStreamForChanges(value2.StreamName, callback);
					value2.IsMonitored = false;
				}
			}
		}

		internal string FindChangedConfigurationStream()
		{
			BaseConfigurationRecord baseConfigurationRecord = this;
			while (!baseConfigurationRecord.IsRootConfig)
			{
				lock (baseConfigurationRecord)
				{
					if (baseConfigurationRecord.ConfigStreamInfo.HasStreamInfos)
					{
						foreach (StreamInfo value in baseConfigurationRecord.ConfigStreamInfo.StreamInfos.Values)
						{
							if (value.IsMonitored && HasStreamChanged(value.StreamName, value.Version))
							{
								return value.StreamName;
							}
						}
					}
				}
				baseConfigurationRecord = baseConfigurationRecord._parent;
			}
			return null;
		}

		private bool HasStreamChanged(string streamname, object lastVersion)
		{
			object streamVersion = Host.GetStreamVersion(streamname);
			if (lastVersion != null)
			{
				if (streamVersion != null)
				{
					return !lastVersion.Equals(streamVersion);
				}
				return true;
			}
			return streamVersion != null;
		}

		protected virtual string CallHostDecryptSection(string encryptedXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfig)
		{
			return Host.DecryptSection(encryptedXml, protectionProvider, protectedConfig);
		}

		internal static string ValidateProtectionProviderAttribute(string protectionProvider, IConfigErrorInfo errorInfo)
		{
			if (string.IsNullOrEmpty(protectionProvider))
			{
				throw new ConfigurationErrorsException(SR.GetString("Protection_provider_invalid_format"), errorInfo);
			}
			return protectionProvider;
		}

		private ConfigXmlReader DecryptConfigSection(ConfigXmlReader reader, ProtectedConfigurationProvider protectionProvider)
		{
			ConfigXmlReader configXmlReader = reader.Clone();
			IConfigErrorInfo configErrorInfo = configXmlReader;
			string text = null;
			string text2 = null;
			configXmlReader.Read();
			string filename = configErrorInfo.Filename;
			int lineNumber = configErrorInfo.LineNumber;
			int lineOffset = lineNumber;
			if (configXmlReader.IsEmptyElement)
			{
				throw new ConfigurationErrorsException(SR.GetString("EncryptedNode_not_found"), filename, lineNumber);
			}
			while (true)
			{
				configXmlReader.Read();
				XmlNodeType nodeType = configXmlReader.NodeType;
				if (nodeType == XmlNodeType.Element && configXmlReader.Name == "EncryptedData")
				{
					break;
				}
				switch (nodeType)
				{
				case XmlNodeType.Comment:
				case XmlNodeType.Whitespace:
					break;
				case XmlNodeType.EndElement:
					throw new ConfigurationErrorsException(SR.GetString("EncryptedNode_not_found"), filename, lineNumber);
				default:
					throw new ConfigurationErrorsException(SR.GetString("EncryptedNode_is_in_invalid_format"), filename, lineNumber);
				}
			}
			lineNumber = configErrorInfo.LineNumber;
			text = configXmlReader.ReadOuterXml();
			try
			{
				text2 = CallHostDecryptSection(text, protectionProvider, ProtectedConfig);
			}
			catch (Exception ex)
			{
				throw new ConfigurationErrorsException(SR.GetString("Decryption_failed", protectionProvider.Name, ex.Message), ex, filename, lineNumber);
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Decryption_failed", protectionProvider.Name, ExceptionUtil.NoExceptionInformation), filename, lineNumber);
			}
			do
			{
				switch (configXmlReader.NodeType)
				{
				default:
					throw new ConfigurationErrorsException(SR.GetString("EncryptedNode_is_in_invalid_format"), filename, lineNumber);
				case XmlNodeType.Comment:
				case XmlNodeType.Whitespace:
					continue;
				case XmlNodeType.EndElement:
					break;
				}
				break;
			}
			while (configXmlReader.Read());
			return new ConfigXmlReader(text2, filename, lineOffset, lineNumberIsConstant: true);
		}

		private void ThrowIfParseErrors(ConfigurationSchemaErrors schemaErrors)
		{
			schemaErrors.ThrowIfErrors(ClassFlags[64]);
		}

		internal static bool IsImplicitSection(string configKey)
		{
			if (configKey == "configProtectedData")
			{
				return true;
			}
			return false;
		}

		private void AddImplicitSections(Hashtable factoryList)
		{
			if (_parent.IsRootConfig)
			{
				if (factoryList == null)
				{
					factoryList = EnsureFactories();
				}
				FactoryRecord factoryRecord = (FactoryRecord)factoryList["configProtectedData"];
				if (factoryRecord == null)
				{
					factoryList["configProtectedData"] = new FactoryRecord("configProtectedData", string.Empty, "configProtectedData", "System.Configuration.ProtectedConfigurationSection, System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", allowLocation: true, ConfigurationAllowDefinition.Everywhere, ConfigurationAllowExeDefinition.MachineToApplication, OverrideModeSetting.SectionDefault, restartOnExternalChanges: true, requirePermission: true, isFromTrustedConfigRecord: true, isUndeclared: true, null, -1);
				}
			}
		}

		internal static bool IsReservedAttributeName(string name)
		{
			if (StringUtil.StartsWith(name, "config") || StringUtil.StartsWith(name, "lock"))
			{
				return true;
			}
			return false;
		}
	}
	public abstract class ConfigurationValidatorBase
	{
		public virtual bool CanValidate(Type type)
		{
			return false;
		}

		public abstract void Validate(object value);
	}
	public sealed class CallbackValidator : ConfigurationValidatorBase
	{
		private Type _type;

		private ValidatorCallback _callback;

		public CallbackValidator(Type type, ValidatorCallback callback)
			: this(callback)
		{
			if (type == null)
			{
				throw new ArgumentNullException("type");
			}
			_type = type;
		}

		internal CallbackValidator(ValidatorCallback callback)
		{
			if (callback == null)
			{
				throw new ArgumentNullException("callback");
			}
			_type = null;
			_callback = callback;
		}

		public override bool CanValidate(Type type)
		{
			if (type != _type)
			{
				return _type == null;
			}
			return true;
		}

		public override void Validate(object value)
		{
			_callback(value);
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public class ConfigurationValidatorAttribute : Attribute
	{
		internal Type _declaringType;

		private readonly Type _validator;

		public virtual ConfigurationValidatorBase ValidatorInstance => (ConfigurationValidatorBase)TypeUtil.CreateInstanceRestricted(_declaringType, _validator);

		public Type ValidatorType => _validator;

		protected ConfigurationValidatorAttribute()
		{
		}

		public ConfigurationValidatorAttribute(Type validator)
		{
			if (validator == null)
			{
				throw new ArgumentNullException("validator");
			}
			if (!typeof(ConfigurationValidatorBase).IsAssignableFrom(validator))
			{
				throw new ArgumentException(SR.GetString("Validator_Attribute_param_not_validator", "ConfigurationValidatorBase"));
			}
			_validator = validator;
		}

		internal void SetDeclaringType(Type declaringType)
		{
			if (declaringType != null)
			{
				if (_declaringType == null)
				{
					_declaringType = declaringType;
				}
				else if (_declaringType == declaringType)
				{
				}
			}
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class CallbackValidatorAttribute : ConfigurationValidatorAttribute
	{
		private Type _type;

		private string _callbackMethodName = string.Empty;

		private ValidatorCallback _callbackMethod;

		public override ConfigurationValidatorBase ValidatorInstance
		{
			get
			{
				if (_callbackMethod == null)
				{
					if (_type == null)
					{
						throw new ArgumentNullException("Type");
					}
					if (!string.IsNullOrEmpty(_callbackMethodName))
					{
						MethodInfo method = _type.GetMethod(_callbackMethodName, BindingFlags.Static | BindingFlags.Public);
						if (method != null)
						{
							ParameterInfo[] parameters = method.GetParameters();
							if (parameters.Length == 1 && parameters[0].ParameterType == typeof(object))
							{
								_callbackMethod = (ValidatorCallback)TypeUtil.CreateDelegateRestricted(_declaringType, typeof(ValidatorCallback), method);
							}
						}
					}
				}
				if (_callbackMethod == null)
				{
					throw new ArgumentException(SR.GetString("Validator_method_not_found", _callbackMethodName));
				}
				return new CallbackValidator(_callbackMethod);
			}
		}

		public Type Type
		{
			get
			{
				return _type;
			}
			set
			{
				_type = value;
				_callbackMethod = null;
			}
		}

		public string CallbackMethodName
		{
			get
			{
				return _callbackMethodName;
			}
			set
			{
				_callbackMethodName = value;
				_callbackMethod = null;
			}
		}
	}
	internal class ClientConfigPaths
	{
		internal const string UserConfigFilename = "user.config";

		private const string ClickOnceDataDirectory = "DataDirectory";

		private const string ConfigExtension = ".config";

		private const int MAX_PATH = 260;

		private const int MAX_LENGTH_TO_USE = 25;

		private const string FILE_URI_LOCAL = "file:///";

		private const string FILE_URI_UNC = "file://";

		private const string FILE_URI = "file:";

		private const string HTTP_URI = "http://";

		private const string StrongNameDesc = "StrongName";

		private const string UrlDesc = "Url";

		private const string PathDesc = "Path";

		private static char[] s_Base32Char = new char[32]
		{
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
			'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
			'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
			'4', '5'
		};

		private static volatile ClientConfigPaths s_current;

		private static volatile bool s_currentIncludesUserConfig;

		private static SecurityPermission s_serializationPerm;

		private static SecurityPermission s_controlEvidencePerm;

		private bool _hasEntryAssembly;

		private bool _includesUserConfig;

		private string _applicationUri;

		private string _applicationConfigUri;

		private string _roamingConfigDirectory;

		private string _roamingConfigFilename;

		private string _localConfigDirectory;

		private string _localConfigFilename;

		private string _companyName;

		private string _productName;

		private string _productVersion;

		internal static ClientConfigPaths Current => GetPaths(null, includeUserConfig: true);

		internal bool HasEntryAssembly => _hasEntryAssembly;

		internal string ApplicationUri => _applicationUri;

		internal string ApplicationConfigUri => _applicationConfigUri;

		internal string RoamingConfigFilename => _roamingConfigFilename;

		internal string RoamingConfigDirectory => _roamingConfigDirectory;

		internal bool HasRoamingConfig
		{
			get
			{
				if (RoamingConfigFilename == null)
				{
					return !_includesUserConfig;
				}
				return true;
			}
		}

		internal string LocalConfigFilename => _localConfigFilename;

		internal string LocalConfigDirectory => _localConfigDirectory;

		internal bool HasLocalConfig
		{
			get
			{
				if (LocalConfigFilename == null)
				{
					return !_includesUserConfig;
				}
				return true;
			}
		}

		internal string ProductName => _productName;

		internal string ProductVersion => _productVersion;

		private static SecurityPermission ControlEvidencePermission
		{
			get
			{
				if (s_controlEvidencePerm == null)
				{
					s_controlEvidencePerm = new SecurityPermission(SecurityPermissionFlag.ControlEvidence);
				}
				return s_controlEvidencePerm;
			}
		}

		private static SecurityPermission SerializationFormatterPermission
		{
			get
			{
				if (s_serializationPerm == null)
				{
					s_serializationPerm = new SecurityPermission(SecurityPermissionFlag.SerializationFormatter);
				}
				return s_serializationPerm;
			}
		}

		[SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
		[FileIOPermission(SecurityAction.Assert, AllFiles = (FileIOPermissionAccess.Read | FileIOPermissionAccess.PathDiscovery))]
		private ClientConfigPaths(string exePath, bool includeUserConfig)
		{
			_includesUserConfig = includeUserConfig;
			Assembly assembly = null;
			string text = null;
			string applicationFilename = null;
			if (exePath == null)
			{
				AppDomain currentDomain = AppDomain.CurrentDomain;
				AppDomainSetup setupInformation = currentDomain.SetupInformation;
				_applicationConfigUri = setupInformation.ConfigurationFile;
				assembly = Assembly.GetEntryAssembly();
				if (assembly != null)
				{
					_hasEntryAssembly = true;
					text = assembly.CodeBase;
					bool flag = false;
					if (StringUtil.StartsWithIgnoreCase(text, "file:///"))
					{
						flag = true;
						text = text.Substring("file:///".Length);
					}
					else if (StringUtil.StartsWithIgnoreCase(text, "file://"))
					{
						flag = true;
						text = text.Substring("file:".Length);
					}
					if (flag)
					{
						text = text.Replace('/', '\\');
						applicationFilename = text;
					}
					else
					{
						text = assembly.EscapedCodeBase;
					}
				}
				else
				{
					StringBuilder stringBuilder = new StringBuilder(260);
					Microsoft.Win32.UnsafeNativeMethods.GetModuleFileName(new HandleRef(null, IntPtr.Zero), stringBuilder, stringBuilder.Capacity);
					text = Path.GetFullPath(stringBuilder.ToString());
					applicationFilename = text;
				}
			}
			else
			{
				text = Path.GetFullPath(exePath);
				if (!FileUtil.FileExists(text, trueOnError: false))
				{
					throw ExceptionUtil.ParameterInvalid("exePath");
				}
				applicationFilename = text;
			}
			if (_applicationConfigUri == null)
			{
				_applicationConfigUri = text + ".config";
			}
			_applicationUri = text;
			if (exePath != null || !_includesUserConfig)
			{
				return;
			}
			bool flag2 = StringUtil.StartsWithIgnoreCase(_applicationConfigUri, "http://");
			SetNamesAndVersion(applicationFilename, assembly, flag2);
			if (IsClickOnceDeployed(AppDomain.CurrentDomain))
			{
				string text2 = AppDomain.CurrentDomain.GetData("DataDirectory") as string;
				string path = Validate(_productVersion, limitSize: false);
				if (Path.IsPathRooted(text2))
				{
					_localConfigDirectory = CombineIfValid(text2, path);
					_localConfigFilename = CombineIfValid(_localConfigDirectory, "user.config");
				}
			}
			else if (!flag2)
			{
				string path2 = Validate(_companyName, limitSize: true);
				string text3 = Validate(AppDomain.CurrentDomain.FriendlyName, limitSize: true);
				string exePath2 = ((!string.IsNullOrEmpty(_applicationUri)) ? _applicationUri.ToLower(CultureInfo.InvariantCulture) : null);
				string text4 = ((!string.IsNullOrEmpty(text3)) ? text3 : Validate(_productName, limitSize: true));
				string typeAndHashSuffix = GetTypeAndHashSuffix(AppDomain.CurrentDomain, exePath2);
				string path3 = ((!string.IsNullOrEmpty(text4) && !string.IsNullOrEmpty(typeAndHashSuffix)) ? (text4 + typeAndHashSuffix) : null);
				string path4 = Validate(_productVersion, limitSize: false);
				string path5 = CombineIfValid(CombineIfValid(path2, path3), path4);
				string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
				if (Path.IsPathRooted(folderPath))
				{
					_roamingConfigDirectory = CombineIfValid(folderPath, path5);
					_roamingConfigFilename = CombineIfValid(_roamingConfigDirectory, "user.config");
				}
				string folderPath2 = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
				if (Path.IsPathRooted(folderPath2))
				{
					_localConfigDirectory = CombineIfValid(folderPath2, path5);
					_localConfigFilename = CombineIfValid(_localConfigDirectory, "user.config");
				}
			}
		}

		internal static ClientConfigPaths GetPaths(string exePath, bool includeUserConfig)
		{
			ClientConfigPaths clientConfigPaths = null;
			if (exePath == null)
			{
				if (s_current == null || (includeUserConfig && !s_currentIncludesUserConfig))
				{
					s_current = new ClientConfigPaths(null, includeUserConfig);
					s_currentIncludesUserConfig = includeUserConfig;
				}
				return s_current;
			}
			return new ClientConfigPaths(exePath, includeUserConfig);
		}

		internal static void RefreshCurrent()
		{
			s_currentIncludesUserConfig = false;
			s_current = null;
		}

		private string CombineIfValid(string path1, string path2)
		{
			string result = null;
			if (path1 != null && path2 != null)
			{
				try
				{
					string text = Path.Combine(path1, path2);
					if (text.Length >= 260)
					{
						return result;
					}
					result = text;
					return result;
				}
				catch
				{
					return result;
				}
			}
			return result;
		}

		private string GetTypeAndHashSuffix(AppDomain appDomain, string exePath)
		{
			string result = null;
			string typeName = null;
			object obj = null;
			obj = GetEvidenceInfo(appDomain, exePath, out typeName);
			if (obj != null && !string.IsNullOrEmpty(typeName))
			{
				MemoryStream memoryStream = new MemoryStream();
				BinaryFormatter binaryFormatter = new BinaryFormatter();
				SerializationFormatterPermission.Assert();
				binaryFormatter.Serialize(memoryStream, obj);
				memoryStream.Position = 0L;
				string hash = GetHash(memoryStream);
				if (!string.IsNullOrEmpty(hash))
				{
					result = "_" + typeName + "_" + hash;
				}
			}
			return result;
		}

		private static object GetEvidenceInfo(AppDomain appDomain, string exePath, out string typeName)
		{
			ControlEvidencePermission.Assert();
			Evidence evidence = appDomain.Evidence;
			StrongName strongName = null;
			Url url = null;
			if (evidence != null)
			{
				IEnumerator hostEnumerator = evidence.GetHostEnumerator();
				object obj = null;
				while (hostEnumerator.MoveNext())
				{
					obj = hostEnumerator.Current;
					if (obj is StrongName)
					{
						strongName = (StrongName)obj;
						break;
					}
					if (obj is Url)
					{
						url = (Url)obj;
					}
				}
			}
			object result = null;
			if (strongName != null)
			{
				result = MakeVersionIndependent(strongName);
				typeName = "StrongName";
			}
			else if (url != null)
			{
				result = url.Value.ToUpperInvariant();
				typeName = "Url";
			}
			else if (exePath != null)
			{
				result = exePath;
				typeName = "Path";
			}
			else
			{
				typeName = null;
			}
			return result;
		}

		private static string GetHash(Stream s)
		{
			byte[] buff;
			using (SHA1 sHA = new SHA1CryptoServiceProvider())
			{
				buff = sHA.ComputeHash(s);
			}
			return ToBase32StringSuitableForDirName(buff);
		}

		private bool IsClickOnceDeployed(AppDomain appDomain)
		{
			ActivationContext activationContext = appDomain.ActivationContext;
			if (activationContext != null && activationContext.Form == ActivationContext.ContextForm.StoreBounded)
			{
				string fullName = activationContext.Identity.FullName;
				if (!string.IsNullOrEmpty(fullName))
				{
					return true;
				}
			}
			return false;
		}

		private static StrongName MakeVersionIndependent(StrongName sn)
		{
			return new StrongName(sn.PublicKey, sn.Name, new Version(0, 0, 0, 0));
		}

		private void SetNamesAndVersion(string applicationFilename, Assembly exeAssembly, bool isHttp)
		{
			Type type = null;
			if (exeAssembly != null)
			{
				object[] customAttributes = exeAssembly.GetCustomAttributes(typeof(AssemblyCompanyAttribute), inherit: false);
				if (customAttributes != null && customAttributes.Length > 0)
				{
					_companyName = ((AssemblyCompanyAttribute)customAttributes[0]).Company;
					if (_companyName != null)
					{
						_companyName = _companyName.Trim();
					}
				}
				customAttributes = exeAssembly.GetCustomAttributes(typeof(AssemblyProductAttribute), inherit: false);
				if (customAttributes != null && customAttributes.Length > 0)
				{
					_productName = ((AssemblyProductAttribute)customAttributes[0]).Product;
					if (_productName != null)
					{
						_productName = _productName.Trim();
					}
				}
				_productVersion = exeAssembly.GetName().Version.ToString();
				if (_productVersion != null)
				{
					_productVersion = _productVersion.Trim();
				}
			}
			if (!isHttp && (string.IsNullOrEmpty(_companyName) || string.IsNullOrEmpty(_productName) || string.IsNullOrEmpty(_productVersion)))
			{
				string text = null;
				if (exeAssembly != null)
				{
					MethodInfo entryPoint = exeAssembly.EntryPoint;
					if (entryPoint != null)
					{
						type = entryPoint.ReflectedType;
						if (type != null)
						{
							text = type.Module.FullyQualifiedName;
						}
					}
				}
				if (text == null)
				{
					text = applicationFilename;
				}
				if (text != null)
				{
					FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(text);
					if (versionInfo != null)
					{
						if (string.IsNullOrEmpty(_companyName))
						{
							_companyName = versionInfo.CompanyName;
							if (_companyName != null)
							{
								_companyName = _companyName.Trim();
							}
						}
						if (string.IsNullOrEmpty(_productName))
						{
							_productName = versionInfo.ProductName;
							if (_productName != null)
							{
								_productName = _productName.Trim();
							}
						}
						if (string.IsNullOrEmpty(_productVersion))
						{
							_productVersion = versionInfo.ProductVersion;
							if (_productVersion != null)
							{
								_productVersion = _productVersion.Trim();
							}
						}
					}
				}
			}
			if (string.IsNullOrEmpty(_companyName) || string.IsNullOrEmpty(_productName))
			{
				string text2 = null;
				if (type != null)
				{
					text2 = type.Namespace;
				}
				if (string.IsNullOrEmpty(_productName))
				{
					if (text2 != null)
					{
						int num = text2.LastIndexOf(".", StringComparison.Ordinal);
						if (num != -1 && num < text2.Length - 1)
						{
							_productName = text2.Substring(num + 1);
						}
						else
						{
							_productName = text2;
						}
						_productName = _productName.Trim();
					}
					if (string.IsNullOrEmpty(_productName) && type != null)
					{
						_productName = type.Name.Trim();
					}
					if (_productName == null)
					{
						_productName = string.Empty;
					}
				}
				if (string.IsNullOrEmpty(_companyName))
				{
					if (text2 != null)
					{
						int num2 = text2.IndexOf(".", StringComparison.Ordinal);
						if (num2 != -1)
						{
							_companyName = text2.Substring(0, num2);
						}
						else
						{
							_companyName = text2;
						}
						_companyName = _companyName.Trim();
					}
					if (string.IsNullOrEmpty(_companyName))
					{
						_companyName = _productName;
					}
				}
			}
			if (string.IsNullOrEmpty(_productVersion))
			{
				_productVersion = "1.0.0.0";
			}
		}

		private static string ToBase32StringSuitableForDirName(byte[] buff)
		{
			StringBuilder stringBuilder = new StringBuilder();
			int num = buff.Length;
			int num2 = 0;
			do
			{
				byte b = (byte)((num2 < num) ? buff[num2++] : 0);
				byte b2 = (byte)((num2 < num) ? buff[num2++] : 0);
				byte b3 = (byte)((num2 < num) ? buff[num2++] : 0);
				byte b4 = (byte)((num2 < num) ? buff[num2++] : 0);
				byte b5 = (byte)((num2 < num) ? buff[num2++] : 0);
				stringBuilder.Append(s_Base32Char[b & 0x1F]);
				stringBuilder.Append(s_Base32Char[b2 & 0x1F]);
				stringBuilder.Append(s_Base32Char[b3 & 0x1F]);
				stringBuilder.Append(s_Base32Char[b4 & 0x1F]);
				stringBuilder.Append(s_Base32Char[b5 & 0x1F]);
				stringBuilder.Append(s_Base32Char[((b & 0xE0) >> 5) | ((b4 & 0x60) >> 2)]);
				stringBuilder.Append(s_Base32Char[((b2 & 0xE0) >> 5) | ((b5 & 0x60) >> 2)]);
				b3 = (byte)(b3 >> 5);
				if ((b4 & 0x80u) != 0)
				{
					b3 = (byte)(b3 | 8u);
				}
				if ((b5 & 0x80u) != 0)
				{
					b3 = (byte)(b3 | 0x10u);
				}
				stringBuilder.Append(s_Base32Char[b3]);
			}
			while (num2 < num);
			return stringBuilder.ToString();
		}

		private string Validate(string str, bool limitSize)
		{
			string text = str;
			if (!string.IsNullOrEmpty(text))
			{
				char[] invalidFileNameChars = Path.GetInvalidFileNameChars();
				foreach (char oldChar in invalidFileNameChars)
				{
					text = text.Replace(oldChar, '_');
				}
				text = text.Replace(' ', '_');
				if (limitSize)
				{
					text = ((text.Length > 25) ? text.Substring(0, 25) : text);
				}
			}
			return text;
		}
	}
}
namespace System.Configuration.Internal
{
	[ComVisible(false)]
	public interface IInternalConfigHost
	{
		bool SupportsChangeNotifications { get; }

		bool SupportsRefresh { get; }

		bool SupportsPath { get; }

		bool SupportsLocation { get; }

		bool IsRemote { get; }

		void Init(IInternalConfigRoot configRoot, params object[] hostInitParams);

		void InitForConfiguration(ref string locationSubPath, out string configPath, out string locationConfigPath, IInternalConfigRoot configRoot, params object[] hostInitConfigurationParams);

		bool IsConfigRecordRequired(string configPath);

		bool IsInitDelayed(IInternalConfigRecord configRecord);

		void RequireCompleteInit(IInternalConfigRecord configRecord);

		bool IsSecondaryRoot(string configPath);

		string GetStreamName(string configPath);

		string GetStreamNameForConfigSource(string streamName, string configSource);

		object GetStreamVersion(string streamName);

		Stream OpenStreamForRead(string streamName);

		Stream OpenStreamForRead(string streamName, bool assertPermissions);

		Stream OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext);

		Stream OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext, bool assertPermissions);

		void WriteCompleted(string streamName, bool success, object writeContext);

		void WriteCompleted(string streamName, bool success, object writeContext, bool assertPermissions);

		void DeleteStream(string streamName);

		bool IsFile(string streamName);

		object StartMonitoringStreamForChanges(string streamName, StreamChangeCallback callback);

		void StopMonitoringStreamForChanges(string streamName, StreamChangeCallback callback);

		bool IsAboveApplication(string configPath);

		string GetConfigPathFromLocationSubPath(string configPath, string locationSubPath);

		bool IsLocationApplicable(string configPath);

		bool IsDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition);

		void VerifyDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition, IConfigErrorInfo errorInfo);

		bool IsTrustedConfigPath(string configPath);

		bool IsFullTrustSectionWithoutAptcaAllowed(IInternalConfigRecord configRecord);

		void GetRestrictedPermissions(IInternalConfigRecord configRecord, out PermissionSet permissionSet, out bool isHostReady);

		IDisposable Impersonate();

		bool PrefetchAll(string configPath, string streamName);

		bool PrefetchSection(string sectionGroupName, string sectionName);

		object CreateDeprecatedConfigContext(string configPath);

		object CreateConfigurationContext(string configPath, string locationSubPath);

		string DecryptSection(string encryptedXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfigSection);

		string EncryptSection(string clearTextXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfigSection);

		Type GetConfigType(string typeName, bool throwOnError);

		string GetConfigTypeName(Type t);
	}
	public class DelegatingConfigHost : IInternalConfigHost
	{
		private IInternalConfigHost _host;

		protected IInternalConfigHost Host
		{
			get
			{
				return _host;
			}
			set
			{
				_host = value;
			}
		}

		public virtual bool SupportsChangeNotifications => Host.SupportsChangeNotifications;

		public virtual bool SupportsRefresh => Host.SupportsRefresh;

		public virtual bool SupportsPath => Host.SupportsPath;

		public virtual bool SupportsLocation => Host.SupportsLocation;

		public virtual bool IsRemote => Host.IsRemote;

		protected DelegatingConfigHost()
		{
		}

		public virtual void Init(IInternalConfigRoot configRoot, params object[] hostInitParams)
		{
			Host.Init(configRoot, hostInitParams);
		}

		public virtual void InitForConfiguration(ref string locationSubPath, out string configPath, out string locationConfigPath, IInternalConfigRoot configRoot, params object[] hostInitConfigurationParams)
		{
			Host.InitForConfiguration(ref locationSubPath, out configPath, out locationConfigPath, configRoot, hostInitConfigurationParams);
		}

		public virtual bool IsConfigRecordRequired(string configPath)
		{
			return Host.IsConfigRecordRequired(configPath);
		}

		public virtual bool IsInitDelayed(IInternalConfigRecord configRecord)
		{
			return Host.IsInitDelayed(configRecord);
		}

		public virtual void RequireCompleteInit(IInternalConfigRecord configRecord)
		{
			Host.RequireCompleteInit(configRecord);
		}

		public virtual bool IsSecondaryRoot(string configPath)
		{
			return Host.IsSecondaryRoot(configPath);
		}

		public virtual string GetStreamName(string configPath)
		{
			return Host.GetStreamName(configPath);
		}

		public virtual string GetStreamNameForConfigSource(string streamName, string configSource)
		{
			return Host.GetStreamNameForConfigSource(streamName, configSource);
		}

		public virtual object GetStreamVersion(string streamName)
		{
			return Host.GetStreamVersion(streamName);
		}

		public virtual Stream OpenStreamForRead(string streamName)
		{
			return Host.OpenStreamForRead(streamName);
		}

		public virtual Stream OpenStreamForRead(string streamName, bool assertPermissions)
		{
			return Host.OpenStreamForRead(streamName, assertPermissions);
		}

		public virtual Stream OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext)
		{
			return Host.OpenStreamForWrite(streamName, templateStreamName, ref writeContext);
		}

		public virtual Stream OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext, bool assertPermissions)
		{
			return Host.OpenStreamForWrite(streamName, templateStreamName, ref writeContext, assertPermissions);
		}

		public virtual void WriteCompleted(string streamName, bool success, object writeContext)
		{
			Host.WriteCompleted(streamName, success, writeContext);
		}

		public virtual void WriteCompleted(string streamName, bool success, object writeContext, bool assertPermissions)
		{
			Host.WriteCompleted(streamName, success, writeContext, assertPermissions);
		}

		public virtual void DeleteStream(string streamName)
		{
			Host.DeleteStream(streamName);
		}

		public virtual bool IsFile(string streamName)
		{
			return Host.IsFile(streamName);
		}

		public virtual object StartMonitoringStreamForChanges(string streamName, StreamChangeCallback callback)
		{
			return Host.StartMonitoringStreamForChanges(streamName, callback);
		}

		public virtual void StopMonitoringStreamForChanges(string streamName, StreamChangeCallback callback)
		{
			Host.StopMonitoringStreamForChanges(streamName, callback);
		}

		public virtual bool IsAboveApplication(string configPath)
		{
			return Host.IsAboveApplication(configPath);
		}

		public virtual bool IsDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition)
		{
			return Host.IsDefinitionAllowed(configPath, allowDefinition, allowExeDefinition);
		}

		public virtual void VerifyDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition, IConfigErrorInfo errorInfo)
		{
			Host.VerifyDefinitionAllowed(configPath, allowDefinition, allowExeDefinition, errorInfo);
		}

		public virtual string GetConfigPathFromLocationSubPath(string configPath, string locationSubPath)
		{
			return Host.GetConfigPathFromLocationSubPath(configPath, locationSubPath);
		}

		public virtual bool IsLocationApplicable(string configPath)
		{
			return Host.IsLocationApplicable(configPath);
		}

		public virtual bool IsTrustedConfigPath(string configPath)
		{
			return Host.IsTrustedConfigPath(configPath);
		}

		public virtual bool IsFullTrustSectionWithoutAptcaAllowed(IInternalConfigRecord configRecord)
		{
			return Host.IsFullTrustSectionWithoutAptcaAllowed(configRecord);
		}

		public virtual void GetRestrictedPermissions(IInternalConfigRecord configRecord, out PermissionSet permissionSet, out bool isHostReady)
		{
			Host.GetRestrictedPermissions(configRecord, out permissionSet, out isHostReady);
		}

		public virtual IDisposable Impersonate()
		{
			return Host.Impersonate();
		}

		public virtual bool PrefetchAll(string configPath, string streamName)
		{
			return Host.PrefetchAll(configPath, streamName);
		}

		public virtual bool PrefetchSection(string sectionGroupName, string sectionName)
		{
			return Host.PrefetchSection(sectionGroupName, sectionName);
		}

		public virtual object CreateDeprecatedConfigContext(string configPath)
		{
			return Host.CreateDeprecatedConfigContext(configPath);
		}

		public virtual object CreateConfigurationContext(string configPath, string locationSubPath)
		{
			return Host.CreateConfigurationContext(configPath, locationSubPath);
		}

		public virtual string DecryptSection(string encryptedXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfigSection)
		{
			return Host.DecryptSection(encryptedXml, protectionProvider, protectedConfigSection);
		}

		public virtual string EncryptSection(string clearTextXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfigSection)
		{
			return Host.EncryptSection(clearTextXml, protectionProvider, protectedConfigSection);
		}

		public virtual Type GetConfigType(string typeName, bool throwOnError)
		{
			return Host.GetConfigType(typeName, throwOnError);
		}

		public virtual string GetConfigTypeName(Type t)
		{
			return Host.GetConfigTypeName(t);
		}
	}
	[ComVisible(false)]
	public interface IInternalConfigClientHost
	{
		bool IsExeConfig(string configPath);

		bool IsRoamingUserConfig(string configPath);

		bool IsLocalUserConfig(string configPath);

		string GetExeConfigPath();

		string GetRoamingUserConfigPath();

		string GetLocalUserConfigPath();
	}
}
namespace System.Configuration
{
	internal sealed class ClientConfigurationHost : DelegatingConfigHost, IInternalConfigClientHost
	{
		internal const string MachineConfigName = "MACHINE";

		internal const string ExeConfigName = "EXE";

		internal const string RoamingUserConfigName = "ROAMING_USER";

		internal const string LocalUserConfigName = "LOCAL_USER";

		internal const string MachineConfigPath = "MACHINE";

		internal const string ExeConfigPath = "MACHINE/EXE";

		internal const string RoamingUserConfigPath = "MACHINE/EXE/ROAMING_USER";

		internal const string LocalUserConfigPath = "MACHINE/EXE/ROAMING_USER/LOCAL_USER";

		private const string ConfigExtension = ".config";

		private const string MachineConfigFilename = "machine.config";

		private const string MachineConfigSubdirectory = "Config";

		private static object s_init = new object();

		private static object s_version = new object();

		private static string s_machineConfigFilePath;

		private string _exePath;

		private ClientConfigPaths _configPaths;

		private ExeConfigurationFileMap _fileMap;

		private bool _initComplete;

		internal ClientConfigPaths ConfigPaths
		{
			get
			{
				if (_configPaths == null)
				{
					_configPaths = ClientConfigPaths.GetPaths(_exePath, _initComplete);
				}
				return _configPaths;
			}
		}

		internal static string MachineConfigFilePath
		{
			[FileIOPermission(SecurityAction.Assert, AllFiles = FileIOPermissionAccess.PathDiscovery)]
			get
			{
				if (s_machineConfigFilePath == null)
				{
					string runtimeDirectory = RuntimeEnvironment.GetRuntimeDirectory();
					s_machineConfigFilePath = Path.Combine(Path.Combine(runtimeDirectory, "Config"), "machine.config");
				}
				return s_machineConfigFilePath;
			}
		}

		internal bool HasRoamingConfig
		{
			get
			{
				if (_fileMap != null)
				{
					return !string.IsNullOrEmpty(_fileMap.RoamingUserConfigFilename);
				}
				return ConfigPaths.HasRoamingConfig;
			}
		}

		internal bool HasLocalConfig
		{
			get
			{
				if (_fileMap != null)
				{
					return !string.IsNullOrEmpty(_fileMap.LocalUserConfigFilename);
				}
				return ConfigPaths.HasLocalConfig;
			}
		}

		internal bool IsAppConfigHttp => !IsFile(GetStreamName("MACHINE/EXE"));

		public override bool SupportsRefresh => true;

		public override bool SupportsPath => false;

		public override bool SupportsLocation => false;

		internal ClientConfigurationHost()
		{
			base.Host = new InternalConfigHost();
		}

		internal void RefreshConfigPaths()
		{
			if (_configPaths != null && !_configPaths.HasEntryAssembly && _exePath == null)
			{
				ClientConfigPaths.RefreshCurrent();
				_configPaths = null;
			}
		}

		bool IInternalConfigClientHost.IsExeConfig(string configPath)
		{
			return StringUtil.EqualsIgnoreCase(configPath, "MACHINE/EXE");
		}

		bool IInternalConfigClientHost.IsRoamingUserConfig(string configPath)
		{
			return StringUtil.EqualsIgnoreCase(configPath, "MACHINE/EXE/ROAMING_USER");
		}

		bool IInternalConfigClientHost.IsLocalUserConfig(string configPath)
		{
			return StringUtil.EqualsIgnoreCase(configPath, "MACHINE/EXE/ROAMING_USER/LOCAL_USER");
		}

		private bool IsUserConfig(string configPath)
		{
			if (!StringUtil.EqualsIgnoreCase(configPath, "MACHINE/EXE/ROAMING_USER"))
			{
				return StringUtil.EqualsIgnoreCase(configPath, "MACHINE/EXE/ROAMING_USER/LOCAL_USER");
			}
			return true;
		}

		string IInternalConfigClientHost.GetExeConfigPath()
		{
			return "MACHINE/EXE";
		}

		string IInternalConfigClientHost.GetRoamingUserConfigPath()
		{
			return "MACHINE/EXE/ROAMING_USER";
		}

		string IInternalConfigClientHost.GetLocalUserConfigPath()
		{
			return "MACHINE/EXE/ROAMING_USER/LOCAL_USER";
		}

		public override void Init(IInternalConfigRoot configRoot, params object[] hostInitParams)
		{
			try
			{
				ConfigurationFileMap configurationFileMap = (ConfigurationFileMap)hostInitParams[0];
				_exePath = (string)hostInitParams[1];
				base.Host.Init(configRoot, hostInitParams);
				_initComplete = configRoot.IsDesignTime;
				if (configurationFileMap != null && !string.IsNullOrEmpty(_exePath))
				{
					throw ExceptionUtil.UnexpectedError("ClientConfigurationHost::Init");
				}
				if (string.IsNullOrEmpty(_exePath))
				{
					_exePath = null;
				}
				if (configurationFileMap == null)
				{
					return;
				}
				_fileMap = new ExeConfigurationFileMap();
				if (!string.IsNullOrEmpty(configurationFileMap.MachineConfigFilename))
				{
					_fileMap.MachineConfigFilename = Path.GetFullPath(configurationFileMap.MachineConfigFilename);
				}
				if (configurationFileMap is ExeConfigurationFileMap exeConfigurationFileMap)
				{
					if (!string.IsNullOrEmpty(exeConfigurationFileMap.ExeConfigFilename))
					{
						_fileMap.ExeConfigFilename = Path.GetFullPath(exeConfigurationFileMap.ExeConfigFilename);
					}
					if (!string.IsNullOrEmpty(exeConfigurationFileMap.RoamingUserConfigFilename))
					{
						_fileMap.RoamingUserConfigFilename = Path.GetFullPath(exeConfigurationFileMap.RoamingUserConfigFilename);
					}
					if (!string.IsNullOrEmpty(exeConfigurationFileMap.LocalUserConfigFilename))
					{
						_fileMap.LocalUserConfigFilename = Path.GetFullPath(exeConfigurationFileMap.LocalUserConfigFilename);
					}
				}
			}
			catch (SecurityException)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_client_config_init_security"));
			}
			catch
			{
				throw ExceptionUtil.UnexpectedError("ClientConfigurationHost::Init");
			}
		}

		public override void InitForConfiguration(ref string locationSubPath, out string configPath, out string locationConfigPath, IInternalConfigRoot configRoot, params object[] hostInitConfigurationParams)
		{
			locationSubPath = null;
			configPath = (string)hostInitConfigurationParams[2];
			locationConfigPath = null;
			Init(configRoot, hostInitConfigurationParams);
		}

		public override bool IsInitDelayed(IInternalConfigRecord configRecord)
		{
			if (!_initComplete)
			{
				return IsUserConfig(configRecord.ConfigPath);
			}
			return false;
		}

		public override void RequireCompleteInit(IInternalConfigRecord record)
		{
			lock (this)
			{
				if (!_initComplete)
				{
					_initComplete = true;
					ClientConfigPaths.RefreshCurrent();
					_configPaths = null;
					_ = ConfigPaths;
				}
			}
		}

		public override bool IsConfigRecordRequired(string configPath)
		{
			switch (ConfigPathUtility.GetName(configPath))
			{
			default:
				return false;
			case "MACHINE":
			case "EXE":
				return true;
			case "ROAMING_USER":
				if (!HasRoamingConfig)
				{
					return HasLocalConfig;
				}
				return true;
			case "LOCAL_USER":
				return HasLocalConfig;
			}
		}

		public override string GetStreamName(string configPath)
		{
			string name = ConfigPathUtility.GetName(configPath);
			if (_fileMap != null)
			{
				return name switch
				{
					"EXE" => _fileMap.ExeConfigFilename, 
					"ROAMING_USER" => _fileMap.RoamingUserConfigFilename, 
					"LOCAL_USER" => _fileMap.LocalUserConfigFilename, 
					_ => _fileMap.MachineConfigFilename, 
				};
			}
			return name switch
			{
				"EXE" => ConfigPaths.ApplicationConfigUri, 
				"ROAMING_USER" => ConfigPaths.RoamingConfigFilename, 
				"LOCAL_USER" => ConfigPaths.LocalConfigFilename, 
				_ => MachineConfigFilePath, 
			};
		}

		public override string GetStreamNameForConfigSource(string streamName, string configSource)
		{
			if (IsFile(streamName))
			{
				return base.Host.GetStreamNameForConfigSource(streamName, configSource);
			}
			int num = streamName.LastIndexOf('/');
			if (num < 0)
			{
				return null;
			}
			string text = streamName.Substring(0, num + 1);
			return text + configSource.Replace('\\', '/');
		}

		public override object GetStreamVersion(string streamName)
		{
			if (IsFile(streamName))
			{
				return base.Host.GetStreamVersion(streamName);
			}
			return s_version;
		}

		public override Stream OpenStreamForRead(string streamName)
		{
			if (IsFile(streamName))
			{
				return base.Host.OpenStreamForRead(streamName);
			}
			if (streamName == null)
			{
				return null;
			}
			WebClient webClient = new WebClient();
			try
			{
				webClient.Credentials = CredentialCache.DefaultCredentials;
			}
			catch
			{
			}
			byte[] array = null;
			try
			{
				array = webClient.DownloadData(streamName);
			}
			catch
			{
			}
			if (array == null)
			{
				return null;
			}
			return new MemoryStream(array);
		}

		public override Stream OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext)
		{
			if (!IsFile(streamName))
			{
				throw ExceptionUtil.UnexpectedError("ClientConfigurationHost::OpenStreamForWrite");
			}
			return base.Host.OpenStreamForWrite(streamName, templateStreamName, ref writeContext);
		}

		public override void DeleteStream(string streamName)
		{
			if (!IsFile(streamName))
			{
				throw ExceptionUtil.UnexpectedError("ClientConfigurationHost::Delete");
			}
			base.Host.DeleteStream(streamName);
		}

		public override bool IsDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition)
		{
			string text;
			switch (allowExeDefinition)
			{
			case ConfigurationAllowExeDefinition.MachineOnly:
				text = "MACHINE";
				break;
			case ConfigurationAllowExeDefinition.MachineToApplication:
				text = "MACHINE/EXE";
				break;
			case ConfigurationAllowExeDefinition.MachineToRoamingUser:
				text = "MACHINE/EXE/ROAMING_USER";
				break;
			case ConfigurationAllowExeDefinition.MachineToLocalUser:
				return true;
			default:
				throw ExceptionUtil.UnexpectedError("ClientConfigurationHost::IsDefinitionAllowed");
			}
			return configPath.Length <= text.Length;
		}

		public override void VerifyDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition, IConfigErrorInfo errorInfo)
		{
			if (!IsDefinitionAllowed(configPath, allowDefinition, allowExeDefinition))
			{
				switch (allowExeDefinition)
				{
				case ConfigurationAllowExeDefinition.MachineOnly:
					throw new ConfigurationErrorsException(SR.GetString("Config_allow_exedefinition_error_machine"), errorInfo);
				case ConfigurationAllowExeDefinition.MachineToApplication:
					throw new ConfigurationErrorsException(SR.GetString("Config_allow_exedefinition_error_application"), errorInfo);
				case ConfigurationAllowExeDefinition.MachineToRoamingUser:
					throw new ConfigurationErrorsException(SR.GetString("Config_allow_exedefinition_error_roaminguser"), errorInfo);
				default:
					throw ExceptionUtil.UnexpectedError("ClientConfigurationHost::VerifyDefinitionAllowed");
				}
			}
		}

		public override bool PrefetchAll(string configPath, string streamName)
		{
			return !IsFile(streamName);
		}

		public override bool PrefetchSection(string sectionGroupName, string sectionName)
		{
			return sectionGroupName == "system.net";
		}

		public override bool IsTrustedConfigPath(string configPath)
		{
			return configPath == "MACHINE";
		}

		[SecurityPermission(SecurityAction.Assert, ControlEvidence = true)]
		public override void GetRestrictedPermissions(IInternalConfigRecord configRecord, out PermissionSet permissionSet, out bool isHostReady)
		{
			bool flag = IsFile(configRecord.StreamName);
			string text = ((!flag) ? configRecord.StreamName : UrlPath.ConvertFileNameToUrl(configRecord.StreamName));
			Evidence evidence = new Evidence();
			evidence.AddHost(new Url(text));
			evidence.AddHost(Zone.CreateFromUrl(text));
			if (!flag)
			{
				evidence.AddHost(Site.CreateFromUrl(text));
			}
			permissionSet = SecurityManager.ResolvePolicy(evidence);
			isHostReady = true;
		}

		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.ControlPrincipal)]
		public override IDisposable Impersonate()
		{
			return WindowsIdentity.Impersonate(IntPtr.Zero);
		}

		public override object CreateDeprecatedConfigContext(string configPath)
		{
			return null;
		}

		public override object CreateConfigurationContext(string configPath, string locationSubPath)
		{
			return new ExeContext(GetUserLevel(configPath), ConfigPaths.ApplicationUri);
		}

		private ConfigurationUserLevel GetUserLevel(string configPath)
		{
			return ConfigPathUtility.GetName(configPath) switch
			{
				"MACHINE" => ConfigurationUserLevel.None, 
				"EXE" => ConfigurationUserLevel.None, 
				"LOCAL_USER" => ConfigurationUserLevel.PerUserRoamingAndLocal, 
				"ROAMING_USER" => ConfigurationUserLevel.PerUserRoaming, 
				_ => ConfigurationUserLevel.None, 
			};
		}

		internal static Configuration OpenExeConfiguration(ConfigurationFileMap fileMap, bool isMachine, ConfigurationUserLevel userLevel, string exePath)
		{
			if (userLevel != 0 && userLevel != ConfigurationUserLevel.PerUserRoaming && userLevel != ConfigurationUserLevel.PerUserRoamingAndLocal)
			{
				throw ExceptionUtil.ParameterInvalid("userLevel");
			}
			if (fileMap != null)
			{
				if (string.IsNullOrEmpty(fileMap.MachineConfigFilename))
				{
					throw ExceptionUtil.ParameterNullOrEmpty("fileMap.MachineConfigFilename");
				}
				if (fileMap is ExeConfigurationFileMap exeConfigurationFileMap)
				{
					if (userLevel != 0)
					{
						if (userLevel != ConfigurationUserLevel.PerUserRoaming)
						{
							if (userLevel != ConfigurationUserLevel.PerUserRoamingAndLocal)
							{
								goto IL_00a1;
							}
							if (string.IsNullOrEmpty(exeConfigurationFileMap.LocalUserConfigFilename))
							{
								throw ExceptionUtil.ParameterNullOrEmpty("fileMap.LocalUserConfigFilename");
							}
						}
						if (string.IsNullOrEmpty(exeConfigurationFileMap.RoamingUserConfigFilename))
						{
							throw ExceptionUtil.ParameterNullOrEmpty("fileMap.RoamingUserConfigFilename");
						}
					}
					if (string.IsNullOrEmpty(exeConfigurationFileMap.ExeConfigFilename))
					{
						throw ExceptionUtil.ParameterNullOrEmpty("fileMap.ExeConfigFilename");
					}
				}
			}
			goto IL_00a1;
			IL_00a1:
			string text = null;
			if (isMachine)
			{
				text = "MACHINE";
			}
			else
			{
				switch (userLevel)
				{
				case ConfigurationUserLevel.None:
					text = "MACHINE/EXE";
					break;
				case ConfigurationUserLevel.PerUserRoaming:
					text = "MACHINE/EXE/ROAMING_USER";
					break;
				case ConfigurationUserLevel.PerUserRoamingAndLocal:
					text = "MACHINE/EXE/ROAMING_USER/LOCAL_USER";
					break;
				}
			}
			return new Configuration(null, typeof(ClientConfigurationHost), fileMap, exePath, text);
		}
	}
}
namespace System.Configuration.Internal
{
	[ComVisible(false)]
	public interface IInternalConfigSystem
	{
		bool SupportsUserConfig { get; }

		object GetSection(string configKey);

		void RefreshConfig(string sectionName);
	}
}
namespace System.Configuration
{
	internal sealed class ClientConfigurationSystem : IInternalConfigSystem
	{
		private const string SystemDiagnosticsConfigKey = "system.diagnostics";

		private const string SystemNetGroupKey = "system.net/";

		private IConfigSystem _configSystem;

		private IInternalConfigRoot _configRoot;

		private ClientConfigurationHost _configHost;

		private IInternalConfigRecord _machineConfigRecord;

		private IInternalConfigRecord _completeConfigRecord;

		private Exception _initError;

		private bool _isInitInProgress;

		private bool _isMachineConfigInited;

		private bool _isUserConfigInited;

		private bool _isAppConfigHttp;

		bool IInternalConfigSystem.SupportsUserConfig => true;

		internal ClientConfigurationSystem()
		{
			_configSystem = new ConfigSystem();
			IConfigSystem configSystem = _configSystem;
			Type typeFromHandle = typeof(ClientConfigurationHost);
			object[] hostInitParams = new object[2];
			configSystem.Init(typeFromHandle, hostInitParams);
			_configHost = (ClientConfigurationHost)_configSystem.Host;
			_configRoot = _configSystem.Root;
			_configRoot.ConfigRemoved += OnConfigRemoved;
			_isAppConfigHttp = _configHost.IsAppConfigHttp;
			_ = Uri.SchemeDelimiter;
		}

		private bool IsSectionUsedInInit(string configKey)
		{
			if (!(configKey == "system.diagnostics"))
			{
				if (_isAppConfigHttp)
				{
					return configKey.StartsWith("system.net/", StringComparison.Ordinal);
				}
				return false;
			}
			return true;
		}

		private bool DoesSectionOnlyUseMachineConfig(string configKey)
		{
			if (_isAppConfigHttp)
			{
				return configKey.StartsWith("system.net/", StringComparison.Ordinal);
			}
			return false;
		}

		private void EnsureInit(string configKey)
		{
			bool flag = false;
			lock (this)
			{
				if (!_isUserConfigInited)
				{
					if (!_isInitInProgress)
					{
						_isInitInProgress = true;
						flag = true;
					}
					else if (!IsSectionUsedInInit(configKey))
					{
						Monitor.Wait(this);
					}
				}
			}
			if (!flag)
			{
				return;
			}
			try
			{
				try
				{
					_machineConfigRecord = _configRoot.GetConfigRecord("MACHINE");
					_machineConfigRecord.ThrowIfInitErrors();
					_isMachineConfigInited = true;
					if (_isAppConfigHttp)
					{
						ConfigurationManagerHelperFactory.Instance.EnsureNetConfigLoaded();
					}
					_configHost.RefreshConfigPaths();
					string configPath = (_configHost.HasLocalConfig ? "MACHINE/EXE/ROAMING_USER/LOCAL_USER" : ((!_configHost.HasRoamingConfig) ? "MACHINE/EXE" : "MACHINE/EXE/ROAMING_USER"));
					_completeConfigRecord = _configRoot.GetConfigRecord(configPath);
					_completeConfigRecord.ThrowIfInitErrors();
					_isUserConfigInited = true;
				}
				catch (Exception inner)
				{
					_initError = new ConfigurationErrorsException(SR.GetString("Config_client_config_init_error"), inner);
					throw _initError;
				}
				catch
				{
					_initError = new ConfigurationErrorsException(SR.GetString("Config_client_config_init_error"));
					throw _initError;
				}
			}
			catch
			{
				ConfigurationManager.SetInitError(_initError);
				_isMachineConfigInited = true;
				_isUserConfigInited = true;
				throw;
			}
			finally
			{
				lock (this)
				{
					try
					{
						ConfigurationManager.CompleteConfigInit();
						_isInitInProgress = false;
					}
					finally
					{
						Monitor.PulseAll(this);
					}
				}
			}
		}

		private void PrepareClientConfigSystem(string sectionName)
		{
			if (!_isUserConfigInited)
			{
				EnsureInit(sectionName);
			}
			if (_initError != null)
			{
				throw _initError;
			}
		}

		private void OnConfigRemoved(object sender, InternalConfigEventArgs e)
		{
			try
			{
				IInternalConfigRecord internalConfigRecord = (_completeConfigRecord = _configRoot.GetConfigRecord(_completeConfigRecord.ConfigPath));
				_completeConfigRecord.ThrowIfInitErrors();
			}
			catch (Exception inner)
			{
				_initError = new ConfigurationErrorsException(SR.GetString("Config_client_config_init_error"), inner);
				ConfigurationManager.SetInitError(_initError);
				throw _initError;
			}
			catch
			{
				_initError = new ConfigurationErrorsException(SR.GetString("Config_client_config_init_error"));
				ConfigurationManager.SetInitError(_initError);
				throw _initError;
			}
		}

		object IInternalConfigSystem.GetSection(string sectionName)
		{
			PrepareClientConfigSystem(sectionName);
			IInternalConfigRecord internalConfigRecord = null;
			if (DoesSectionOnlyUseMachineConfig(sectionName))
			{
				if (_isMachineConfigInited)
				{
					internalConfigRecord = _machineConfigRecord;
				}
			}
			else if (_isUserConfigInited)
			{
				internalConfigRecord = _completeConfigRecord;
			}
			return internalConfigRecord?.GetSection(sectionName);
		}

		void IInternalConfigSystem.RefreshConfig(string sectionName)
		{
			PrepareClientConfigSystem(sectionName);
			if (_isMachineConfigInited)
			{
				_machineConfigRecord.RefreshSection(sectionName);
			}
		}
	}
	public abstract class ConfigurationConverterBase : TypeConverter
	{
		public override bool CanConvertTo(ITypeDescriptorContext ctx, Type type)
		{
			return type == typeof(string);
		}

		public override bool CanConvertFrom(ITypeDescriptorContext ctx, Type type)
		{
			return type == typeof(string);
		}

		internal void ValidateType(object value, Type expected)
		{
			if (value != null && value.GetType() != expected)
			{
				throw new ArgumentException(SR.GetString("Converter_unsupported_value_type", expected.Name));
			}
		}
	}
	public sealed class CommaDelimitedStringCollectionConverter : ConfigurationConverterBase
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(CommaDelimitedStringCollection));
			if (value is CommaDelimitedStringCollection commaDelimitedStringCollection)
			{
				return commaDelimitedStringCollection.ToString();
			}
			return null;
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			CommaDelimitedStringCollection commaDelimitedStringCollection = new CommaDelimitedStringCollection();
			commaDelimitedStringCollection.FromString((string)data);
			return commaDelimitedStringCollection;
		}
	}
	internal class ConfigDefinitionUpdates
	{
		private ArrayList _locationUpdatesList;

		private bool _requireLocationWritten;

		internal ArrayList LocationUpdatesList => _locationUpdatesList;

		internal bool RequireLocation
		{
			get
			{
				return _requireLocationWritten;
			}
			set
			{
				_requireLocationWritten = value;
			}
		}

		internal ConfigDefinitionUpdates()
		{
			_locationUpdatesList = new ArrayList();
		}

		internal LocationUpdates FindLocationUpdates(OverrideModeSetting overrideMode, bool inheritInChildApps)
		{
			foreach (LocationUpdates locationUpdates in _locationUpdatesList)
			{
				if (OverrideModeSetting.CanUseSameLocationTag(locationUpdates.OverrideMode, overrideMode) && locationUpdates.InheritInChildApps == inheritInChildApps)
				{
					return locationUpdates;
				}
			}
			return null;
		}

		internal DefinitionUpdate AddUpdate(OverrideModeSetting overrideMode, bool inheritInChildApps, bool moved, string updatedXml, SectionRecord sectionRecord)
		{
			LocationUpdates locationUpdates = FindLocationUpdates(overrideMode, inheritInChildApps);
			if (locationUpdates == null)
			{
				locationUpdates = new LocationUpdates(overrideMode, inheritInChildApps);
				_locationUpdatesList.Add(locationUpdates);
			}
			DefinitionUpdate definitionUpdate = new DefinitionUpdate(sectionRecord.ConfigKey, moved, updatedXml, sectionRecord);
			locationUpdates.SectionUpdates.AddSection(definitionUpdate);
			return definitionUpdate;
		}

		internal void CompleteUpdates()
		{
			foreach (LocationUpdates locationUpdates in _locationUpdatesList)
			{
				locationUpdates.CompleteUpdates();
			}
		}

		internal void FlagLocationWritten()
		{
			_requireLocationWritten = false;
		}
	}
	public sealed class Configuration
	{
		private Type _typeConfigHost;

		private object[] _hostInitConfigurationParams;

		private IInternalConfigRoot _configRoot;

		private MgmtConfigurationRecord _configRecord;

		private ConfigurationSectionGroup _rootSectionGroup;

		private ConfigurationLocationCollection _locations;

		private ContextInformation _evalContext;

		public AppSettingsSection AppSettings => (AppSettingsSection)GetSection("appSettings");

		public ConnectionStringsSection ConnectionStrings => (ConnectionStringsSection)GetSection("connectionStrings");

		public string FilePath => _configRecord.ConfigurationFilePath;

		public bool HasFile => _configRecord.HasStream;

		public ConfigurationLocationCollection Locations
		{
			get
			{
				if (_locations == null)
				{
					_locations = _configRecord.GetLocationCollection(this);
				}
				return _locations;
			}
		}

		public ContextInformation EvaluationContext
		{
			get
			{
				if (_evalContext == null)
				{
					_evalContext = new ContextInformation(_configRecord);
				}
				return _evalContext;
			}
		}

		public ConfigurationSectionGroup RootSectionGroup
		{
			get
			{
				if (_rootSectionGroup == null)
				{
					_rootSectionGroup = new ConfigurationSectionGroup();
					_rootSectionGroup.RootAttachToConfigurationRecord(_configRecord);
				}
				return _rootSectionGroup;
			}
		}

		public ConfigurationSectionCollection Sections => RootSectionGroup.Sections;

		public ConfigurationSectionGroupCollection SectionGroups => RootSectionGroup.SectionGroups;

		public bool NamespaceDeclared
		{
			get
			{
				return _configRecord.NamespacePresent;
			}
			set
			{
				_configRecord.NamespacePresent = value;
			}
		}

		internal Configuration(string locationSubPath, Type typeConfigHost, params object[] hostInitConfigurationParams)
		{
			_typeConfigHost = typeConfigHost;
			_hostInitConfigurationParams = hostInitConfigurationParams;
			_configRoot = new InternalConfigRoot();
			IInternalConfigHost internalConfigHost = (IInternalConfigHost)TypeUtil.CreateInstanceWithReflectionPermission(typeConfigHost);
			IInternalConfigHost internalConfigHost2 = new UpdateConfigHost(internalConfigHost);
			_configRoot.Init(internalConfigHost2, isDesignTime: true);
			internalConfigHost.InitForConfiguration(ref locationSubPath, out var configPath, out var locationConfigPath, _configRoot, hostInitConfigurationParams);
			if (!string.IsNullOrEmpty(locationSubPath) && !internalConfigHost2.SupportsLocation)
			{
				throw ExceptionUtil.UnexpectedError("Configuration::ctor");
			}
			if (string.IsNullOrEmpty(locationSubPath) != string.IsNullOrEmpty(locationConfigPath))
			{
				throw ExceptionUtil.UnexpectedError("Configuration::ctor");
			}
			_configRecord = (MgmtConfigurationRecord)_configRoot.GetConfigRecord(configPath);
			if (!string.IsNullOrEmpty(locationSubPath))
			{
				_configRecord = MgmtConfigurationRecord.Create(_configRoot, _configRecord, locationConfigPath, locationSubPath);
			}
			_configRecord.ThrowIfInitErrors();
		}

		internal Configuration OpenLocationConfiguration(string locationSubPath)
		{
			return new Configuration(locationSubPath, _typeConfigHost, _hostInitConfigurationParams);
		}

		public ConfigurationSection GetSection(string sectionName)
		{
			return (ConfigurationSection)_configRecord.GetSection(sectionName);
		}

		public ConfigurationSectionGroup GetSectionGroup(string sectionGroupName)
		{
			return _configRecord.GetSectionGroup(sectionGroupName);
		}

		public void Save()
		{
			SaveAsImpl(null, ConfigurationSaveMode.Modified, forceSaveAll: false);
		}

		public void Save(ConfigurationSaveMode saveMode)
		{
			SaveAsImpl(null, saveMode, forceSaveAll: false);
		}

		public void Save(ConfigurationSaveMode saveMode, bool forceSaveAll)
		{
			SaveAsImpl(null, saveMode, forceSaveAll);
		}

		public void SaveAs(string filename)
		{
			SaveAs(filename, ConfigurationSaveMode.Modified, forceSaveAll: false);
		}

		public void SaveAs(string filename, ConfigurationSaveMode saveMode)
		{
			SaveAs(filename, saveMode, forceSaveAll: false);
		}

		public void SaveAs(string filename, ConfigurationSaveMode saveMode, bool forceSaveAll)
		{
			if (string.IsNullOrEmpty(filename))
			{
				throw ExceptionUtil.ParameterNullOrEmpty("filename");
			}
			SaveAsImpl(filename, saveMode, forceSaveAll);
		}

		private void SaveAsImpl(string filename, ConfigurationSaveMode saveMode, bool forceSaveAll)
		{
			filename = ((!string.IsNullOrEmpty(filename)) ? Path.GetFullPath(filename) : null);
			if (forceSaveAll)
			{
				ForceGroupsRecursive(RootSectionGroup);
			}
			_configRecord.SaveAs(filename, saveMode, forceSaveAll);
		}

		private void ForceGroupsRecursive(ConfigurationSectionGroup group)
		{
			foreach (ConfigurationSection section in group.Sections)
			{
				_ = group.Sections[section.SectionInformation.Name];
			}
			foreach (ConfigurationSectionGroup sectionGroup in group.SectionGroups)
			{
				ForceGroupsRecursive(group.SectionGroups[sectionGroup.Name]);
			}
		}
	}
	public enum ConfigurationAllowDefinition
	{
		MachineOnly = 0,
		MachineToWebRoot = 100,
		MachineToApplication = 200,
		Everywhere = 300
	}
	public enum ConfigurationAllowExeDefinition
	{
		MachineOnly = 0,
		MachineToApplication = 100,
		MachineToRoamingUser = 200,
		MachineToLocalUser = 300
	}
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Property)]
	public sealed class ConfigurationCollectionAttribute : Attribute
	{
		private string _addItemName;

		private string _removeItemName;

		private string _clearItemsName;

		private Type _itemType;

		private ConfigurationElementCollectionType _collectionType = ConfigurationElementCollectionType.AddRemoveClearMap;

		public Type ItemType => _itemType;

		public string AddItemName
		{
			get
			{
				if (_addItemName == null)
				{
					return "add";
				}
				return _addItemName;
			}
			set
			{
				if (string.IsNullOrEmpty(value))
				{
					value = null;
				}
				_addItemName = value;
			}
		}

		public string RemoveItemName
		{
			get
			{
				if (_removeItemName == null)
				{
					return "remove";
				}
				return _removeItemName;
			}
			set
			{
				if (string.IsNullOrEmpty(value))
				{
					value = null;
				}
				_removeItemName = value;
			}
		}

		public string ClearItemsName
		{
			get
			{
				if (_clearItemsName == null)
				{
					return "clear";
				}
				return _clearItemsName;
			}
			set
			{
				if (string.IsNullOrEmpty(value))
				{
					value = null;
				}
				_clearItemsName = value;
			}
		}

		public ConfigurationElementCollectionType CollectionType
		{
			get
			{
				return _collectionType;
			}
			set
			{
				_collectionType = value;
			}
		}

		public ConfigurationCollectionAttribute(Type itemType)
		{
			if (itemType == null)
			{
				throw new ArgumentNullException("itemType");
			}
			_itemType = itemType;
		}
	}
	[DebuggerDisplay("Count = {Count}")]
	public abstract class ConfigurationElementCollection : ConfigurationElement, ICollection, IEnumerable
	{
		private enum InheritedType
		{
			inNeither,
			inParent,
			inSelf,
			inBothSame,
			inBothDiff,
			inBothCopyNoRemove
		}

		private enum EntryType
		{
			Inherited,
			Replaced,
			Removed,
			Added
		}

		private class Entry
		{
			internal EntryType _entryType;

			internal object _key;

			internal ConfigurationElement _value;

			internal object GetKey(ConfigurationElementCollection ThisCollection)
			{
				if (_value != null)
				{
					return ThisCollection.GetElementKeyInternal(_value);
				}
				return _key;
			}

			internal Entry(EntryType type, object key, ConfigurationElement value)
			{
				_entryType = type;
				_key = key;
				_value = value;
			}
		}

		private class Enumerator : IDictionaryEnumerator, IEnumerator
		{
			private IEnumerator _itemsEnumerator;

			private DictionaryEntry _current = default(DictionaryEntry);

			private ConfigurationElementCollection ThisCollection;

			object IEnumerator.Current => _current.Value;

			DictionaryEntry IDictionaryEnumerator.Entry => _current;

			object IDictionaryEnumerator.Key => _current.Key;

			object IDictionaryEnumerator.Value => _current.Value;

			internal Enumerator(ArrayList items, ConfigurationElementCollection collection)
			{
				_itemsEnumerator = items.GetEnumerator();
				ThisCollection = collection;
			}

			bool IEnumerator.MoveNext()
			{
				while (_itemsEnumerator.MoveNext())
				{
					Entry entry = (Entry)_itemsEnumerator.Current;
					if (entry._entryType != EntryType.Removed)
					{
						_current.Key = ((entry.GetKey(ThisCollection) != null) ? entry.GetKey(ThisCollection) : "key");
						_current.Value = entry._value;
						return true;
					}
				}
				return false;
			}

			void IEnumerator.Reset()
			{
				_itemsEnumerator.Reset();
			}
		}

		internal const string DefaultAddItemName = "add";

		internal const string DefaultRemoveItemName = "remove";

		internal const string DefaultClearItemsName = "clear";

		private int _removedItemCount;

		private int _inheritedCount;

		private ArrayList _items = new ArrayList();

		private string _addElement = "add";

		private string _removeElement = "remove";

		private string _clearElement = "clear";

		private bool bEmitClearTag;

		private bool bCollectionCleared;

		private bool bModified;

		private bool bReadOnly;

		private IComparer _comparer;

		internal bool internalAddToEnd;

		internal string internalElementTagName = string.Empty;

		private ArrayList Items => _items;

		protected internal string AddElementName
		{
			get
			{
				return _addElement;
			}
			set
			{
				_addElement = value;
				if (BaseConfigurationRecord.IsReservedAttributeName(value))
				{
					throw new ArgumentException(SR.GetString("Item_name_reserved", "add", value));
				}
			}
		}

		protected internal string RemoveElementName
		{
			get
			{
				return _removeElement;
			}
			set
			{
				if (BaseConfigurationRecord.IsReservedAttributeName(value))
				{
					throw new ArgumentException(SR.GetString("Item_name_reserved", "remove", value));
				}
				_removeElement = value;
			}
		}

		protected internal string ClearElementName
		{
			get
			{
				return _clearElement;
			}
			set
			{
				if (BaseConfigurationRecord.IsReservedAttributeName(value))
				{
					throw new ArgumentException(SR.GetString("Item_name_reserved", "clear", value));
				}
				_clearElement = value;
			}
		}

		public int Count => _items.Count - _removedItemCount;

		public bool EmitClear
		{
			get
			{
				return bEmitClearTag;
			}
			set
			{
				if (IsReadOnly())
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
				}
				if (value)
				{
					CheckLockedElement(_clearElement, null);
					CheckLockedElement(_removeElement, null);
				}
				bModified = true;
				bEmitClearTag = value;
			}
		}

		public bool IsSynchronized => false;

		public object SyncRoot => null;

		protected virtual string ElementName => "";

		internal string LockableElements
		{
			get
			{
				if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
				{
					string text = "'" + AddElementName + "'";
					if (RemoveElementName.Length != 0)
					{
						text = text + ", '" + RemoveElementName + "'";
					}
					if (ClearElementName.Length != 0)
					{
						text = text + ", '" + ClearElementName + "'";
					}
					return text;
				}
				if (!string.IsNullOrEmpty(ElementName))
				{
					return "'" + ElementName + "'";
				}
				return string.Empty;
			}
		}

		protected virtual bool ThrowOnDuplicate
		{
			get
			{
				if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
				{
					return true;
				}
				return false;
			}
		}

		public virtual ConfigurationElementCollectionType CollectionType => ConfigurationElementCollectionType.AddRemoveClearMap;

		protected ConfigurationElementCollection()
		{
		}

		protected ConfigurationElementCollection(IComparer comparer)
		{
			if (comparer == null)
			{
				throw new ArgumentNullException("comparer");
			}
			_comparer = comparer;
		}

		internal override void AssociateContext(BaseConfigurationRecord configRecord)
		{
			base.AssociateContext(configRecord);
			foreach (Entry item in _items)
			{
				if (item._value != null)
				{
					item._value.AssociateContext(configRecord);
				}
			}
		}

		protected internal override bool IsModified()
		{
			if (bModified)
			{
				return true;
			}
			if (base.IsModified())
			{
				return true;
			}
			foreach (Entry item in _items)
			{
				if (item._entryType != EntryType.Removed)
				{
					ConfigurationElement value = item._value;
					if (value.IsModified())
					{
						return true;
					}
				}
			}
			return false;
		}

		protected internal override void ResetModified()
		{
			bModified = false;
			base.ResetModified();
			foreach (Entry item in _items)
			{
				if (item._entryType != EntryType.Removed)
				{
					ConfigurationElement value = item._value;
					value.ResetModified();
				}
			}
		}

		public override bool IsReadOnly()
		{
			return bReadOnly;
		}

		protected internal override void SetReadOnly()
		{
			bReadOnly = true;
			foreach (Entry item in _items)
			{
				if (item._entryType != EntryType.Removed)
				{
					ConfigurationElement value = item._value;
					value.SetReadOnly();
				}
			}
		}

		internal virtual IEnumerator GetEnumeratorImpl()
		{
			return new Enumerator(_items, this);
		}

		internal IEnumerator GetElementsEnumerator()
		{
			return new Enumerator(_items, this);
		}

		public override bool Equals(object compareTo)
		{
			if (compareTo.GetType() == GetType())
			{
				ConfigurationElementCollection configurationElementCollection = (ConfigurationElementCollection)compareTo;
				if (Count != configurationElementCollection.Count)
				{
					return false;
				}
				foreach (Entry item in Items)
				{
					bool flag = false;
					foreach (Entry item2 in configurationElementCollection.Items)
					{
						if (object.Equals(item._value, item2._value))
						{
							flag = true;
							break;
						}
					}
					if (!flag)
					{
						return false;
					}
				}
				return true;
			}
			return false;
		}

		public override int GetHashCode()
		{
			int num = 0;
			foreach (Entry item in Items)
			{
				ConfigurationElement value = item._value;
				num ^= value.GetHashCode();
			}
			return num;
		}

		protected internal override void Unmerge(ConfigurationElement sourceElement, ConfigurationElement parentElement, ConfigurationSaveMode saveMode)
		{
			base.Unmerge(sourceElement, parentElement, saveMode);
			if (sourceElement == null)
			{
				return;
			}
			ConfigurationElementCollection configurationElementCollection = parentElement as ConfigurationElementCollection;
			ConfigurationElementCollection configurationElementCollection2 = sourceElement as ConfigurationElementCollection;
			Hashtable hashtable = new Hashtable();
			_lockedAllExceptAttributesList = sourceElement._lockedAllExceptAttributesList;
			_lockedAllExceptElementsList = sourceElement._lockedAllExceptElementsList;
			_fItemLocked = sourceElement._fItemLocked;
			_lockedAttributesList = sourceElement._lockedAttributesList;
			_lockedElementsList = sourceElement._lockedElementsList;
			AssociateContext(sourceElement._configRecord);
			if (parentElement != null)
			{
				if (parentElement._lockedAttributesList != null)
				{
					_lockedAttributesList = UnMergeLockList(sourceElement._lockedAttributesList, parentElement._lockedAttributesList, saveMode);
				}
				if (parentElement._lockedElementsList != null)
				{
					_lockedElementsList = UnMergeLockList(sourceElement._lockedElementsList, parentElement._lockedElementsList, saveMode);
				}
				if (parentElement._lockedAllExceptAttributesList != null)
				{
					_lockedAllExceptAttributesList = UnMergeLockList(sourceElement._lockedAllExceptAttributesList, parentElement._lockedAllExceptAttributesList, saveMode);
				}
				if (parentElement._lockedAllExceptElementsList != null)
				{
					_lockedAllExceptElementsList = UnMergeLockList(sourceElement._lockedAllExceptElementsList, parentElement._lockedAllExceptElementsList, saveMode);
				}
			}
			if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
			{
				bCollectionCleared = configurationElementCollection2.bCollectionCleared;
				EmitClear = (saveMode == ConfigurationSaveMode.Full && _clearElement.Length != 0) || (saveMode == ConfigurationSaveMode.Modified && bCollectionCleared) || configurationElementCollection2.EmitClear;
				if (configurationElementCollection != null && !EmitClear)
				{
					foreach (Entry item in configurationElementCollection.Items)
					{
						if (item._entryType != EntryType.Removed)
						{
							hashtable[item.GetKey(this)] = InheritedType.inParent;
						}
					}
				}
				foreach (Entry item2 in configurationElementCollection2.Items)
				{
					if (item2._entryType == EntryType.Removed)
					{
						continue;
					}
					if (hashtable.Contains(item2.GetKey(this)))
					{
						Entry entry3 = (Entry)configurationElementCollection.Items[configurationElementCollection.RealIndexOf(item2._value)];
						ConfigurationElement value = item2._value;
						if (value.Equals(entry3._value))
						{
							hashtable[item2.GetKey(this)] = InheritedType.inBothSame;
							if (saveMode == ConfigurationSaveMode.Modified)
							{
								if (value.IsModified())
								{
									hashtable[item2.GetKey(this)] = InheritedType.inBothDiff;
								}
								else if (value.ElementPresent)
								{
									hashtable[item2.GetKey(this)] = InheritedType.inBothCopyNoRemove;
								}
							}
						}
						else
						{
							hashtable[item2.GetKey(this)] = InheritedType.inBothDiff;
							if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate && item2._entryType == EntryType.Added)
							{
								hashtable[item2.GetKey(this)] = InheritedType.inBothCopyNoRemove;
							}
						}
					}
					else
					{
						hashtable[item2.GetKey(this)] = InheritedType.inSelf;
					}
				}
				if (configurationElementCollection != null && !EmitClear)
				{
					foreach (Entry item3 in configurationElementCollection.Items)
					{
						if (item3._entryType != EntryType.Removed)
						{
							InheritedType inheritedType = (InheritedType)hashtable[item3.GetKey(this)];
							if (inheritedType == InheritedType.inParent || inheritedType == InheritedType.inBothDiff)
							{
								ConfigurationElement configurationElement = CallCreateNewElement(item3.GetKey(this).ToString());
								configurationElement.Reset(item3._value);
								BaseAdd(configurationElement, ThrowOnDuplicate, ignoreLocks: true);
								BaseRemove(item3.GetKey(this), throwIfMissing: false);
							}
						}
					}
				}
				{
					foreach (Entry item4 in configurationElementCollection2.Items)
					{
						if (item4._entryType == EntryType.Removed)
						{
							continue;
						}
						InheritedType inheritedType2 = (InheritedType)hashtable[item4.GetKey(this)];
						if (inheritedType2 == InheritedType.inSelf || inheritedType2 == InheritedType.inBothDiff || inheritedType2 == InheritedType.inBothCopyNoRemove)
						{
							ConfigurationElement configurationElement2 = CallCreateNewElement(item4.GetKey(this).ToString());
							configurationElement2.Unmerge(item4._value, null, saveMode);
							if (inheritedType2 == InheritedType.inSelf)
							{
								configurationElement2.RemoveAllInheritedLocks();
							}
							BaseAdd(configurationElement2, ThrowOnDuplicate, ignoreLocks: true);
						}
					}
					return;
				}
			}
			if (CollectionType != 0 && CollectionType != ConfigurationElementCollectionType.BasicMapAlternate)
			{
				return;
			}
			foreach (Entry item5 in configurationElementCollection2.Items)
			{
				bool flag = false;
				Entry entry7 = null;
				if (item5._entryType != EntryType.Added && item5._entryType != EntryType.Replaced)
				{
					continue;
				}
				bool flag2 = false;
				if (configurationElementCollection != null)
				{
					foreach (Entry item6 in configurationElementCollection.Items)
					{
						if (object.Equals(item5.GetKey(this), item6.GetKey(this)) && !IsElementName(item5.GetKey(this).ToString()))
						{
							flag = true;
							entry7 = item6;
						}
						if (object.Equals(item5._value, item6._value))
						{
							flag = true;
							flag2 = true;
							entry7 = item6;
							break;
						}
					}
				}
				ConfigurationElement configurationElement3 = CallCreateNewElement(item5.GetKey(this).ToString());
				if (!flag)
				{
					configurationElement3.Unmerge(item5._value, null, saveMode);
					BaseAdd(-1, configurationElement3, ignoreLocks: true);
					continue;
				}
				ConfigurationElement value2 = item5._value;
				if (!flag2 || (saveMode == ConfigurationSaveMode.Modified && value2.IsModified()) || saveMode == ConfigurationSaveMode.Full)
				{
					configurationElement3.Unmerge(item5._value, entry7._value, saveMode);
					BaseAdd(-1, configurationElement3, ignoreLocks: true);
				}
			}
		}

		protected internal override void Reset(ConfigurationElement parentElement)
		{
			ConfigurationElementCollection configurationElementCollection = parentElement as ConfigurationElementCollection;
			ResetLockLists(parentElement);
			if (configurationElementCollection == null)
			{
				return;
			}
			foreach (Entry item in configurationElementCollection.Items)
			{
				ConfigurationElement configurationElement = CallCreateNewElement(item.GetKey(this).ToString());
				configurationElement.Reset(item._value);
				if ((CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate) && (item._entryType == EntryType.Added || item._entryType == EntryType.Replaced))
				{
					BaseAdd(configurationElement, throwIfExists: true, ignoreLocks: true);
				}
				else if (CollectionType == ConfigurationElementCollectionType.BasicMap || CollectionType == ConfigurationElementCollectionType.BasicMapAlternate)
				{
					BaseAdd(-1, configurationElement, ignoreLocks: true);
				}
			}
			_inheritedCount = Count;
		}

		public void CopyTo(ConfigurationElement[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}

		void ICollection.CopyTo(Array arr, int index)
		{
			foreach (Entry item in _items)
			{
				if (item._entryType != EntryType.Removed)
				{
					arr.SetValue(item._value, index++);
				}
			}
		}

		public IEnumerator GetEnumerator()
		{
			return GetEnumeratorImpl();
		}

		protected virtual void BaseAdd(ConfigurationElement element)
		{
			BaseAdd(element, ThrowOnDuplicate);
		}

		protected internal void BaseAdd(ConfigurationElement element, bool throwIfExists)
		{
			BaseAdd(element, throwIfExists, ignoreLocks: false);
		}

		private void BaseAdd(ConfigurationElement element, bool throwIfExists, bool ignoreLocks)
		{
			bool flagAsReplaced = false;
			bool flag = internalAddToEnd;
			if (IsReadOnly())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
			if (base.LockItem && !ignoreLocks)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_element_locked", _addElement));
			}
			object elementKeyInternal = GetElementKeyInternal(element);
			int num = -1;
			for (int i = 0; i < _items.Count; i++)
			{
				Entry entry = (Entry)_items[i];
				if (!CompareKeys(elementKeyInternal, entry.GetKey(this)))
				{
					continue;
				}
				if (entry._value != null && entry._value.LockItem && !ignoreLocks)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_item_locked"));
				}
				if (entry._entryType != EntryType.Removed && throwIfExists)
				{
					if (!element.Equals(entry._value))
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_already_exists", elementKeyInternal), element.PropertyFileName(""), element.PropertyLineNumber(""));
					}
					entry._value = element;
					return;
				}
				if (entry._entryType != EntryType.Added)
				{
					if ((CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate) && entry._entryType == EntryType.Removed && _removedItemCount > 0)
					{
						_removedItemCount--;
					}
					entry._entryType = EntryType.Replaced;
					flagAsReplaced = true;
				}
				if (flag || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
				{
					num = i;
					if (entry._entryType == EntryType.Added)
					{
						flag = true;
					}
					break;
				}
				if (!ignoreLocks)
				{
					element.HandleLockedAttributes(entry._value);
					element.MergeLocks(entry._value);
				}
				entry._value = element;
				bModified = true;
				return;
			}
			if (num >= 0)
			{
				_items.RemoveAt(num);
				if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate && num > Count + _removedItemCount - _inheritedCount)
				{
					_inheritedCount--;
				}
			}
			BaseAddInternal(flag ? (-1) : num, element, flagAsReplaced, ignoreLocks);
			bModified = true;
		}

		protected int BaseIndexOf(ConfigurationElement element)
		{
			int num = 0;
			object elementKeyInternal = GetElementKeyInternal(element);
			foreach (Entry item in _items)
			{
				if (item._entryType != EntryType.Removed)
				{
					if (CompareKeys(elementKeyInternal, item.GetKey(this)))
					{
						return num;
					}
					num++;
				}
			}
			return -1;
		}

		internal int RealIndexOf(ConfigurationElement element)
		{
			int num = 0;
			object elementKeyInternal = GetElementKeyInternal(element);
			foreach (Entry item in _items)
			{
				if (CompareKeys(elementKeyInternal, item.GetKey(this)))
				{
					return num;
				}
				num++;
			}
			return -1;
		}

		private void BaseAddInternal(int index, ConfigurationElement element, bool flagAsReplaced, bool ignoreLocks)
		{
			element.AssociateContext(_configRecord);
			element?.CallInit();
			if (IsReadOnly())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
			if (!ignoreLocks)
			{
				if (CollectionType == ConfigurationElementCollectionType.BasicMap || CollectionType == ConfigurationElementCollectionType.BasicMapAlternate)
				{
					if (BaseConfigurationRecord.IsReservedAttributeName(ElementName))
					{
						throw new ArgumentException(SR.GetString("Basicmap_item_name_reserved", ElementName));
					}
					CheckLockedElement(ElementName, null);
				}
				if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
				{
					CheckLockedElement(_addElement, null);
				}
			}
			if (CollectionType == ConfigurationElementCollectionType.BasicMapAlternate || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
			{
				if (index == -1)
				{
					index = Count + _removedItemCount - _inheritedCount;
				}
				else if (index > Count + _removedItemCount - _inheritedCount && !flagAsReplaced)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_cannot_add_items_below_inherited_items"));
				}
			}
			if (CollectionType == ConfigurationElementCollectionType.BasicMap && index >= 0 && index < _inheritedCount)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_cannot_add_items_above_inherited_items"));
			}
			EntryType type = (flagAsReplaced ? EntryType.Replaced : EntryType.Added);
			object elementKeyInternal = GetElementKeyInternal(element);
			if (index >= 0)
			{
				if (index > _items.Count)
				{
					throw new ConfigurationErrorsException(SR.GetString("IndexOutOfRange", index));
				}
				_items.Insert(index, new Entry(type, elementKeyInternal, element));
			}
			else
			{
				_items.Add(new Entry(type, elementKeyInternal, element));
			}
			bModified = true;
		}

		protected virtual void BaseAdd(int index, ConfigurationElement element)
		{
			BaseAdd(index, element, ignoreLocks: false);
		}

		private void BaseAdd(int index, ConfigurationElement element, bool ignoreLocks)
		{
			if (IsReadOnly())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
			if (index < -1)
			{
				throw new ConfigurationErrorsException(SR.GetString("IndexOutOfRange", index));
			}
			if (index != -1 && (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate))
			{
				int num = 0;
				if (index > 0)
				{
					foreach (Entry item in _items)
					{
						if (item._entryType != EntryType.Removed)
						{
							index--;
						}
						if (index != 0)
						{
							num++;
							continue;
						}
						break;
					}
					index = ++num;
				}
				object elementKeyInternal = GetElementKeyInternal(element);
				foreach (Entry item2 in _items)
				{
					if (CompareKeys(elementKeyInternal, item2.GetKey(this)) && item2._entryType != EntryType.Removed)
					{
						if (!element.Equals(item2._value))
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_already_exists", elementKeyInternal), element.PropertyFileName(""), element.PropertyLineNumber(""));
						}
						return;
					}
				}
			}
			BaseAddInternal(index, element, flagAsReplaced: false, ignoreLocks);
		}

		protected internal void BaseRemove(object key)
		{
			BaseRemove(key, throwIfMissing: false);
		}

		private void BaseRemove(object key, bool throwIfMissing)
		{
			if (IsReadOnly())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
			int num = 0;
			bool flag = false;
			foreach (Entry item in _items)
			{
				if (CompareKeys(key, item.GetKey(this)))
				{
					flag = true;
					if (item._value == null)
					{
						if (throwIfMissing)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_not_found", key));
						}
						return;
					}
					if (item._value.LockItem)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", key));
					}
					if (!item._value.ElementPresent)
					{
						CheckLockedElement(_removeElement, null);
					}
					switch (item._entryType)
					{
					case EntryType.Added:
						if (CollectionType != ConfigurationElementCollectionType.AddRemoveClearMap && CollectionType != ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
						{
							if (CollectionType == ConfigurationElementCollectionType.BasicMapAlternate && num >= Count - _inheritedCount)
							{
								throw new ConfigurationErrorsException(SR.GetString("Config_base_cannot_remove_inherited_items"));
							}
							if (CollectionType == ConfigurationElementCollectionType.BasicMap && num < _inheritedCount)
							{
								throw new ConfigurationErrorsException(SR.GetString("Config_base_cannot_remove_inherited_items"));
							}
							_items.RemoveAt(num);
						}
						else
						{
							item._entryType = EntryType.Removed;
							_removedItemCount++;
						}
						break;
					case EntryType.Removed:
						if (throwIfMissing)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_already_removed"));
						}
						break;
					default:
						if (CollectionType != ConfigurationElementCollectionType.AddRemoveClearMap && CollectionType != ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_elements_may_not_be_removed"));
						}
						item._entryType = EntryType.Removed;
						_removedItemCount++;
						break;
					}
					bModified = true;
					return;
				}
				num++;
			}
			if (flag)
			{
				return;
			}
			if (throwIfMissing)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_not_found", key));
			}
			if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
			{
				if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
				{
					_items.Insert(Count + _removedItemCount - _inheritedCount, new Entry(EntryType.Removed, key, null));
				}
				else
				{
					_items.Add(new Entry(EntryType.Removed, key, null));
				}
				_removedItemCount++;
			}
		}

		protected internal ConfigurationElement BaseGet(object key)
		{
			foreach (Entry item in _items)
			{
				if (item._entryType != EntryType.Removed && CompareKeys(key, item.GetKey(this)))
				{
					return item._value;
				}
			}
			return null;
		}

		protected internal bool BaseIsRemoved(object key)
		{
			foreach (Entry item in _items)
			{
				if (CompareKeys(key, item.GetKey(this)))
				{
					if (item._entryType == EntryType.Removed)
					{
						return true;
					}
					return false;
				}
			}
			return false;
		}

		protected internal ConfigurationElement BaseGet(int index)
		{
			if (index < 0)
			{
				throw new ConfigurationErrorsException(SR.GetString("IndexOutOfRange", index));
			}
			int num = 0;
			Entry entry = null;
			foreach (Entry item in _items)
			{
				if (num == index && item._entryType != EntryType.Removed)
				{
					entry = item;
					break;
				}
				if (item._entryType != EntryType.Removed)
				{
					num++;
				}
			}
			if (entry != null)
			{
				return entry._value;
			}
			throw new ConfigurationErrorsException(SR.GetString("IndexOutOfRange", index));
		}

		protected internal object[] BaseGetAllKeys()
		{
			object[] array = new object[Count];
			int num = 0;
			foreach (Entry item in _items)
			{
				if (item._entryType != EntryType.Removed)
				{
					array[num] = item.GetKey(this);
					num++;
				}
			}
			return array;
		}

		protected internal object BaseGetKey(int index)
		{
			int num = 0;
			Entry entry = null;
			if (index < 0)
			{
				throw new ConfigurationErrorsException(SR.GetString("IndexOutOfRange", index));
			}
			foreach (Entry item in _items)
			{
				if (num == index && item._entryType != EntryType.Removed)
				{
					entry = item;
					break;
				}
				if (item._entryType != EntryType.Removed)
				{
					num++;
				}
			}
			if (entry != null)
			{
				return entry.GetKey(this);
			}
			throw new ConfigurationErrorsException(SR.GetString("IndexOutOfRange", index));
		}

		protected internal void BaseClear()
		{
			if (IsReadOnly())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
			CheckLockedElement(_clearElement, null);
			CheckLockedElement(_removeElement, null);
			bModified = true;
			bCollectionCleared = true;
			if ((CollectionType == ConfigurationElementCollectionType.BasicMap || CollectionType == ConfigurationElementCollectionType.BasicMapAlternate) && _inheritedCount > 0)
			{
				int index = 0;
				if (CollectionType == ConfigurationElementCollectionType.BasicMapAlternate)
				{
					index = 0;
				}
				if (CollectionType == ConfigurationElementCollectionType.BasicMap)
				{
					index = _inheritedCount;
				}
				while (Count - _inheritedCount > 0)
				{
					_items.RemoveAt(index);
				}
				return;
			}
			int num = 0;
			int num2 = 0;
			int count = Count;
			for (int i = 0; i < _items.Count; i++)
			{
				Entry entry = (Entry)_items[i];
				if (entry._value != null && entry._value.LockItem)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_item_locked_cannot_clear"));
				}
			}
			for (int num3 = _items.Count - 1; num3 >= 0; num3--)
			{
				Entry entry2 = (Entry)_items[num3];
				if ((CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap && num3 < _inheritedCount) || (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate && num3 >= count - _inheritedCount))
				{
					num++;
				}
				if (entry2._entryType == EntryType.Removed)
				{
					num2++;
				}
				_items.RemoveAt(num3);
			}
			_inheritedCount -= num;
			_removedItemCount -= num2;
		}

		protected internal void BaseRemoveAt(int index)
		{
			if (IsReadOnly())
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
			int num = 0;
			Entry entry = null;
			foreach (Entry item in _items)
			{
				if (num == index && item._entryType != EntryType.Removed)
				{
					entry = item;
					break;
				}
				if (item._entryType != EntryType.Removed)
				{
					num++;
				}
			}
			if (entry == null)
			{
				throw new ConfigurationErrorsException(SR.GetString("IndexOutOfRange", index));
			}
			if (entry._value.LockItem)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", entry.GetKey(this)));
			}
			if (!entry._value.ElementPresent)
			{
				CheckLockedElement(_removeElement, null);
			}
			switch (entry._entryType)
			{
			case EntryType.Added:
				if (CollectionType != ConfigurationElementCollectionType.AddRemoveClearMap && CollectionType != ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
				{
					if (CollectionType == ConfigurationElementCollectionType.BasicMapAlternate && index >= Count - _inheritedCount)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_base_cannot_remove_inherited_items"));
					}
					if (CollectionType == ConfigurationElementCollectionType.BasicMap && index < _inheritedCount)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_base_cannot_remove_inherited_items"));
					}
					_items.RemoveAt(index);
				}
				else
				{
					if (!entry._value.ElementPresent)
					{
						CheckLockedElement(_removeElement, null);
					}
					entry._entryType = EntryType.Removed;
					_removedItemCount++;
				}
				break;
			case EntryType.Removed:
				throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_already_removed"));
			default:
				if (CollectionType != ConfigurationElementCollectionType.AddRemoveClearMap && CollectionType != ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_elements_may_not_be_removed"));
				}
				entry._entryType = EntryType.Removed;
				_removedItemCount++;
				break;
			}
			bModified = true;
		}

		protected internal override bool SerializeElement(XmlWriter writer, bool serializeCollectionKey)
		{
			ConfigurationElementCollectionType collectionType = CollectionType;
			bool flag = false;
			flag |= base.SerializeElement(writer, serializeCollectionKey);
			if ((collectionType == ConfigurationElementCollectionType.AddRemoveClearMap || collectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate) && bEmitClearTag && _clearElement.Length != 0)
			{
				if (writer != null)
				{
					writer.WriteStartElement(_clearElement);
					writer.WriteEndElement();
				}
				flag = true;
			}
			foreach (Entry item in _items)
			{
				switch (collectionType)
				{
				case ConfigurationElementCollectionType.BasicMap:
				case ConfigurationElementCollectionType.BasicMapAlternate:
					if (item._entryType != EntryType.Added && item._entryType != EntryType.Replaced)
					{
						break;
					}
					if (ElementName != null && ElementName.Length != 0)
					{
						if (BaseConfigurationRecord.IsReservedAttributeName(ElementName))
						{
							throw new ArgumentException(SR.GetString("Basicmap_item_name_reserved", ElementName));
						}
						flag |= item._value.SerializeToXmlElement(writer, ElementName);
					}
					else
					{
						flag |= item._value.SerializeElement(writer, serializeCollectionKey: false);
					}
					break;
				case ConfigurationElementCollectionType.AddRemoveClearMap:
				case ConfigurationElementCollectionType.AddRemoveClearMapAlternate:
					if ((item._entryType == EntryType.Removed || item._entryType == EntryType.Replaced) && item._value != null)
					{
						writer?.WriteStartElement(_removeElement);
						flag |= item._value.SerializeElement(writer, serializeCollectionKey: true);
						writer?.WriteEndElement();
						flag = true;
					}
					if (item._entryType == EntryType.Added || item._entryType == EntryType.Replaced)
					{
						flag |= item._value.SerializeToXmlElement(writer, _addElement);
					}
					break;
				}
			}
			return flag;
		}

		protected override bool OnDeserializeUnrecognizedElement(string elementName, XmlReader reader)
		{
			bool result = false;
			if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
			{
				if (elementName == _addElement)
				{
					ConfigurationElement configurationElement = CallCreateNewElement();
					configurationElement.ResetLockLists(this);
					configurationElement.DeserializeElement(reader, serializeCollectionKey: false);
					BaseAdd(configurationElement);
					result = true;
				}
				else if (elementName == _removeElement)
				{
					ConfigurationElement configurationElement2 = CallCreateNewElement();
					configurationElement2.ResetLockLists(this);
					configurationElement2.DeserializeElement(reader, serializeCollectionKey: true);
					if (IsElementRemovable(configurationElement2))
					{
						BaseRemove(GetElementKeyInternal(configurationElement2), throwIfMissing: false);
					}
					result = true;
				}
				else if (elementName == _clearElement)
				{
					if (reader.AttributeCount > 0 && reader.MoveToNextAttribute())
					{
						string name = reader.Name;
						throw new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_attribute", name), reader);
					}
					CheckLockedElement(elementName, reader);
					reader.MoveToElement();
					BaseClear();
					bEmitClearTag = true;
					result = true;
				}
			}
			else if (elementName == ElementName)
			{
				if (BaseConfigurationRecord.IsReservedAttributeName(elementName))
				{
					throw new ArgumentException(SR.GetString("Basicmap_item_name_reserved", elementName));
				}
				ConfigurationElement configurationElement3 = CallCreateNewElement();
				configurationElement3.ResetLockLists(this);
				configurationElement3.DeserializeElement(reader, serializeCollectionKey: false);
				BaseAdd(configurationElement3);
				result = true;
			}
			else if (IsElementName(elementName))
			{
				if (BaseConfigurationRecord.IsReservedAttributeName(elementName))
				{
					throw new ArgumentException(SR.GetString("Basicmap_item_name_reserved", elementName));
				}
				ConfigurationElement configurationElement4 = CallCreateNewElement(elementName);
				configurationElement4.ResetLockLists(this);
				configurationElement4.DeserializeElement(reader, serializeCollectionKey: false);
				BaseAdd(-1, configurationElement4);
				result = true;
			}
			return result;
		}

		private ConfigurationElement CallCreateNewElement(string elementName)
		{
			ConfigurationElement configurationElement = CreateNewElement(elementName);
			configurationElement.AssociateContext(_configRecord);
			configurationElement.CallInit();
			return configurationElement;
		}

		private ConfigurationElement CallCreateNewElement()
		{
			ConfigurationElement configurationElement = CreateNewElement();
			configurationElement.AssociateContext(_configRecord);
			configurationElement.CallInit();
			return configurationElement;
		}

		protected virtual ConfigurationElement CreateNewElement(string elementName)
		{
			return CreateNewElement();
		}

		protected abstract ConfigurationElement CreateNewElement();

		protected abstract object GetElementKey(ConfigurationElement element);

		internal object GetElementKeyInternal(ConfigurationElement element)
		{
			object elementKey = GetElementKey(element);
			if (elementKey == null)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_invalid_element_key"));
			}
			return elementKey;
		}

		protected virtual bool IsElementRemovable(ConfigurationElement element)
		{
			return true;
		}

		private bool CompareKeys(object key1, object key2)
		{
			if (_comparer != null)
			{
				return _comparer.Compare(key1, key2) == 0;
			}
			return key1.Equals(key2);
		}

		protected virtual bool IsElementName(string elementName)
		{
			return false;
		}

		internal bool IsLockableElement(string elementName)
		{
			if (CollectionType == ConfigurationElementCollectionType.AddRemoveClearMap || CollectionType == ConfigurationElementCollectionType.AddRemoveClearMapAlternate)
			{
				if (!(elementName == AddElementName) && !(elementName == RemoveElementName))
				{
					return elementName == ClearElementName;
				}
				return true;
			}
			if (!(elementName == ElementName))
			{
				return IsElementName(elementName);
			}
			return true;
		}
	}
	public enum ConfigurationElementCollectionType
	{
		BasicMap,
		AddRemoveClearMap,
		BasicMapAlternate,
		AddRemoveClearMapAlternate
	}
	public sealed class ConfigurationElementProperty
	{
		private ConfigurationValidatorBase _validator;

		public ConfigurationValidatorBase Validator => _validator;

		public ConfigurationElementProperty(ConfigurationValidatorBase validator)
		{
			if (validator == null)
			{
				throw new ArgumentNullException("validator");
			}
			_validator = validator;
		}
	}
	[Serializable]
	public class ConfigurationErrorsException : ConfigurationException
	{
		private const string HTTP_PREFIX = "http:";

		private const string SERIALIZATION_PARAM_FILENAME = "firstFilename";

		private const string SERIALIZATION_PARAM_LINE = "firstLine";

		private const string SERIALIZATION_PARAM_ERROR_COUNT = "count";

		private const string SERIALIZATION_PARAM_ERROR_DATA = "_errors";

		private const string SERIALIZATION_PARAM_ERROR_TYPE = "_errors_type";

		private string _firstFilename;

		private int _firstLine;

		private ConfigurationException[] _errors;

		public override string Message
		{
			get
			{
				string filename = Filename;
				if (!string.IsNullOrEmpty(filename))
				{
					if (Line != 0)
					{
						return BareMessage + " (" + filename + " line " + Line.ToString(CultureInfo.CurrentCulture) + ")";
					}
					return BareMessage + " (" + filename + ")";
				}
				if (Line != 0)
				{
					return BareMessage + " (line " + Line.ToString("G", CultureInfo.CurrentCulture) + ")";
				}
				return BareMessage;
			}
		}

		public override string BareMessage => base.BareMessage;

		public override string Filename => SafeFilename(_firstFilename);

		public override int Line => _firstLine;

		public ICollection Errors
		{
			get
			{
				if (_errors != null)
				{
					return _errors;
				}
				ConfigurationErrorsException ex = new ConfigurationErrorsException(BareMessage, base.InnerException, _firstFilename, _firstLine);
				return new ConfigurationException[1] { ex };
			}
		}

		internal ICollection<ConfigurationException> ErrorsGeneric => (ICollection<ConfigurationException>)Errors;

		private void Init(string filename, int line)
		{
			base.HResult = -2146232062;
			if (line == -1)
			{
				line = 0;
			}
			_firstFilename = filename;
			_firstLine = line;
		}

		public ConfigurationErrorsException(string message, Exception inner, string filename, int line)
			: base(message, inner)
		{
			Init(filename, line);
		}

		public ConfigurationErrorsException()
			: this(null, null, null, 0)
		{
		}

		public ConfigurationErrorsException(string message)
			: this(message, null, null, 0)
		{
		}

		public ConfigurationErrorsException(string message, Exception inner)
			: this(message, inner, null, 0)
		{
		}

		public ConfigurationErrorsException(string message, string filename, int line)
			: this(message, null, filename, line)
		{
		}

		public ConfigurationErrorsException(string message, XmlNode node)
			: this(message, null, GetUnsafeFilename(node), GetLineNumber(node))
		{
		}

		public ConfigurationErrorsException(string message, Exception inner, XmlNode node)
			: this(message, inner, GetUnsafeFilename(node), GetLineNumber(node))
		{
		}

		public ConfigurationErrorsException(string message, XmlReader reader)
			: this(message, null, GetUnsafeFilename(reader), GetLineNumber(reader))
		{
		}

		public ConfigurationErrorsException(string message, Exception inner, XmlReader reader)
			: this(message, inner, GetUnsafeFilename(reader), GetLineNumber(reader))
		{
		}

		internal ConfigurationErrorsException(string message, IConfigErrorInfo errorInfo)
			: this(message, null, GetUnsafeConfigErrorInfoFilename(errorInfo), GetConfigErrorInfoLineNumber(errorInfo))
		{
		}

		internal ConfigurationErrorsException(string message, Exception inner, IConfigErrorInfo errorInfo)
			: this(message, inner, GetUnsafeConfigErrorInfoFilename(errorInfo), GetConfigErrorInfoLineNumber(errorInfo))
		{
		}

		internal ConfigurationErrorsException(ConfigurationException e)
			: this(GetBareMessage(e), GetInnerException(e), GetUnsafeFilename(e), GetLineNumber(e))
		{
		}

		internal ConfigurationErrorsException(ICollection<ConfigurationException> coll)
			: this(GetFirstException(coll))
		{
			if (coll.Count > 1)
			{
				_errors = new ConfigurationException[coll.Count];
				coll.CopyTo(_errors, 0);
			}
		}

		internal ConfigurationErrorsException(ArrayList coll)
			: this((ConfigurationException)((coll.Count > 0) ? coll[0] : null))
		{
			if (coll.Count > 1)
			{
				_errors = new ConfigurationException[coll.Count];
				coll.CopyTo(_errors, 0);
				ConfigurationException[] errors = _errors;
				foreach (object obj in errors)
				{
					_ = (ConfigurationException)obj;
				}
			}
		}

		private static ConfigurationException GetFirstException(ICollection<ConfigurationException> coll)
		{
			using (IEnumerator<ConfigurationException> enumerator = coll.GetEnumerator())
			{
				if (enumerator.MoveNext())
				{
					return enumerator.Current;
				}
			}
			return null;
		}

		private static string GetBareMessage(ConfigurationException e)
		{
			return e?.BareMessage;
		}

		private static Exception GetInnerException(ConfigurationException e)
		{
			return e?.InnerException;
		}

		[FileIOPermission(SecurityAction.Assert, AllFiles = FileIOPermissionAccess.PathDiscovery)]
		private static string GetUnsafeFilename(ConfigurationException e)
		{
			return e?.Filename;
		}

		private static int GetLineNumber(ConfigurationException e)
		{
			return e?.Line ?? 0;
		}

		protected ConfigurationErrorsException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
			string @string = info.GetString("firstFilename");
			int @int = info.GetInt32("firstLine");
			Init(@string, @int);
			int int2 = info.GetInt32("count");
			if (int2 == 0)
			{
				return;
			}
			_errors = new ConfigurationException[int2];
			for (int i = 0; i < int2; i++)
			{
				string text = i.ToString(CultureInfo.InvariantCulture);
				string string2 = info.GetString(text + "_errors_type");
				Type type = Type.GetType(string2, throwOnError: true);
				if (type != typeof(ConfigurationException) && type != typeof(ConfigurationErrorsException))
				{
					throw ExceptionUtil.UnexpectedError("ConfigurationErrorsException");
				}
				_errors[i] = (ConfigurationException)info.GetValue(text + "_errors", type);
			}
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			int value = 0;
			base.GetObjectData(info, context);
			info.AddValue("firstFilename", Filename);
			info.AddValue("firstLine", Line);
			if (_errors != null && _errors.Length > 1)
			{
				value = _errors.Length;
				for (int i = 0; i < _errors.Length; i++)
				{
					string text = i.ToString(CultureInfo.InvariantCulture);
					info.AddValue(text + "_errors", _errors[i]);
					info.AddValue(text + "_errors_type", _errors[i].GetType());
				}
			}
			info.AddValue("count", value);
		}

		public static int GetLineNumber(XmlNode node)
		{
			return GetConfigErrorInfoLineNumber(node as IConfigErrorInfo);
		}

		public static string GetFilename(XmlNode node)
		{
			return SafeFilename(GetUnsafeFilename(node));
		}

		private static string GetUnsafeFilename(XmlNode node)
		{
			return GetUnsafeConfigErrorInfoFilename(node as IConfigErrorInfo);
		}

		public static int GetLineNumber(XmlReader reader)
		{
			return GetConfigErrorInfoLineNumber(reader as IConfigErrorInfo);
		}

		public static string GetFilename(XmlReader reader)
		{
			return SafeFilename(GetUnsafeFilename(reader));
		}

		private static string GetUnsafeFilename(XmlReader reader)
		{
			return GetUnsafeConfigErrorInfoFilename(reader as IConfigErrorInfo);
		}

		private static int GetConfigErrorInfoLineNumber(IConfigErrorInfo errorInfo)
		{
			return errorInfo?.LineNumber ?? 0;
		}

		private static string GetUnsafeConfigErrorInfoFilename(IConfigErrorInfo errorInfo)
		{
			return errorInfo?.Filename;
		}

		[FileIOPermission(SecurityAction.Assert, AllFiles = FileIOPermissionAccess.PathDiscovery)]
		private static string FullPathWithAssert(string filename)
		{
			string result = null;
			try
			{
				result = Path.GetFullPath(filename);
				return result;
			}
			catch
			{
				return result;
			}
		}

		internal static string SafeFilename(string filename)
		{
			if (string.IsNullOrEmpty(filename))
			{
				return filename;
			}
			if (StringUtil.StartsWithIgnoreCase(filename, "http:"))
			{
				return filename;
			}
			try
			{
				if (!Path.IsPathRooted(filename))
				{
					return filename;
				}
			}
			catch
			{
				return null;
			}
			try
			{
				Path.GetFullPath(filename);
				return filename;
			}
			catch (SecurityException)
			{
				try
				{
					string path = FullPathWithAssert(filename);
					filename = Path.GetFileName(path);
					return filename;
				}
				catch
				{
					filename = null;
					return filename;
				}
			}
			catch
			{
				filename = null;
				return filename;
			}
		}

		internal static string AlwaysSafeFilename(string filename)
		{
			if (string.IsNullOrEmpty(filename))
			{
				return filename;
			}
			if (StringUtil.StartsWithIgnoreCase(filename, "http:"))
			{
				return filename;
			}
			try
			{
				if (!Path.IsPathRooted(filename))
				{
					return filename;
				}
			}
			catch
			{
				return null;
			}
			try
			{
				string path = FullPathWithAssert(filename);
				filename = Path.GetFileName(path);
				return filename;
			}
			catch
			{
				filename = null;
				return filename;
			}
		}
	}
	public class ConfigurationFileMap : ICloneable
	{
		private string _machineConfigFilename;

		private bool _requirePathDiscovery;

		public string MachineConfigFilename
		{
			get
			{
				string machineConfigFilename = _machineConfigFilename;
				if (_requirePathDiscovery)
				{
					new FileIOPermission(FileIOPermissionAccess.PathDiscovery, machineConfigFilename).Demand();
				}
				return machineConfigFilename;
			}
			set
			{
				_requirePathDiscovery = false;
				_machineConfigFilename = value;
			}
		}

		public ConfigurationFileMap()
		{
			_machineConfigFilename = ClientConfigurationHost.MachineConfigFilePath;
			_requirePathDiscovery = true;
		}

		public ConfigurationFileMap(string machineConfigFilename)
		{
			_machineConfigFilename = machineConfigFilename;
		}

		public virtual object Clone()
		{
			return new ConfigurationFileMap(_machineConfigFilename);
		}
	}
	public class ConfigurationLocation
	{
		private Configuration _config;

		private string _locationSubPath;

		public string Path => _locationSubPath;

		internal ConfigurationLocation(Configuration config, string locationSubPath)
		{
			_config = config;
			_locationSubPath = locationSubPath;
		}

		public Configuration OpenConfiguration()
		{
			return _config.OpenLocationConfiguration(_locationSubPath);
		}
	}
	public class ConfigurationLocationCollection : ReadOnlyCollectionBase
	{
		public ConfigurationLocation this[int index] => (ConfigurationLocation)base.InnerList[index];

		internal ConfigurationLocationCollection(ICollection col)
		{
			base.InnerList.AddRange(col);
		}
	}
	public sealed class ConfigurationLockCollection : ICollection, IEnumerable
	{
		private const string LockAll = "*";

		private HybridDictionary internalDictionary;

		private ArrayList internalArraylist;

		private bool _bModified;

		private bool _bExceptionList;

		private string _ignoreName = string.Empty;

		private ConfigurationElement _thisElement;

		private ConfigurationLockCollectionType _lockType;

		private string SeedList = string.Empty;

		internal ConfigurationLockCollectionType LockType => _lockType;

		public int Count => internalDictionary.Count;

		public bool IsSynchronized => false;

		public object SyncRoot => this;

		public bool IsModified => _bModified;

		internal bool ExceptionList => _bExceptionList;

		public string AttributeList
		{
			get
			{
				StringBuilder stringBuilder = new StringBuilder();
				foreach (DictionaryEntry item in internalDictionary)
				{
					if (stringBuilder.Length != 0)
					{
						stringBuilder.Append(',');
					}
					stringBuilder.Append(item.Key);
				}
				return stringBuilder.ToString();
			}
		}

		public bool HasParentElements
		{
			get
			{
				bool result = false;
				if (ExceptionList && internalDictionary.Count == 0 && !string.IsNullOrEmpty(SeedList))
				{
					return true;
				}
				foreach (DictionaryEntry item in internalDictionary)
				{
					if (((ConfigurationValueFlags)item.Value & ConfigurationValueFlags.Inherited) != 0)
					{
						return true;
					}
				}
				return result;
			}
		}

		internal ConfigurationLockCollection(ConfigurationElement thisElement)
			: this(thisElement, ConfigurationLockCollectionType.LockedAttributes)
		{
		}

		internal ConfigurationLockCollection(ConfigurationElement thisElement, ConfigurationLockCollectionType lockType)
			: this(thisElement, lockType, string.Empty)
		{
		}

		internal ConfigurationLockCollection(ConfigurationElement thisElement, ConfigurationLockCollectionType lockType, string ignoreName)
			: this(thisElement, lockType, ignoreName, null)
		{
		}

		internal ConfigurationLockCollection(ConfigurationElement thisElement, ConfigurationLockCollectionType lockType, string ignoreName, ConfigurationLockCollection parentCollection)
		{
			_thisElement = thisElement;
			_lockType = lockType;
			internalDictionary = new HybridDictionary();
			internalArraylist = new ArrayList();
			_bModified = false;
			_bExceptionList = _lockType == ConfigurationLockCollectionType.LockedExceptionList || _lockType == ConfigurationLockCollectionType.LockedElementsExceptionList;
			_ignoreName = ignoreName;
			if (parentCollection == null)
			{
				return;
			}
			foreach (string item in parentCollection)
			{
				Add(item, ConfigurationValueFlags.Inherited);
				if (_bExceptionList)
				{
					if (SeedList.Length != 0)
					{
						SeedList += ",";
					}
					SeedList += item;
				}
			}
		}

		internal void ClearSeedList()
		{
			SeedList = string.Empty;
		}

		public void Add(string name)
		{
			if ((_thisElement.ItemLocked & ConfigurationValueFlags.Locked) != 0 && (_thisElement.ItemLocked & ConfigurationValueFlags.Inherited) != 0)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", name));
			}
			ConfigurationValueFlags configurationValueFlags = ConfigurationValueFlags.Modified;
			string text = name.Trim();
			ConfigurationProperty configurationProperty = _thisElement.Properties[text];
			if (configurationProperty == null && text != "*")
			{
				ConfigurationElementCollection configurationElementCollection = _thisElement as ConfigurationElementCollection;
				if (configurationElementCollection == null && _thisElement.Properties.DefaultCollectionProperty != null)
				{
					configurationElementCollection = _thisElement[_thisElement.Properties.DefaultCollectionProperty] as ConfigurationElementCollection;
				}
				if (configurationElementCollection == null || _lockType == ConfigurationLockCollectionType.LockedAttributes || _lockType == ConfigurationLockCollectionType.LockedExceptionList)
				{
					_thisElement.ReportInvalidLock(text, _lockType, null, null);
				}
				else if (!configurationElementCollection.IsLockableElement(text))
				{
					_thisElement.ReportInvalidLock(text, _lockType, null, configurationElementCollection.LockableElements);
				}
			}
			else
			{
				if (configurationProperty != null && configurationProperty.IsRequired)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_required_attribute_lock_attempt", configurationProperty.Name));
				}
				if (text != "*")
				{
					if (_lockType == ConfigurationLockCollectionType.LockedElements || _lockType == ConfigurationLockCollectionType.LockedElementsExceptionList)
					{
						if (!typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
						{
							_thisElement.ReportInvalidLock(text, _lockType, null, null);
						}
					}
					else if (typeof(ConfigurationElement).IsAssignableFrom(configurationProperty.Type))
					{
						_thisElement.ReportInvalidLock(text, _lockType, null, null);
					}
				}
			}
			if (internalDictionary.Contains(name))
			{
				configurationValueFlags = ConfigurationValueFlags.Modified | (ConfigurationValueFlags)internalDictionary[name];
				internalDictionary.Remove(name);
				internalArraylist.Remove(name);
			}
			internalDictionary.Add(name, configurationValueFlags);
			internalArraylist.Add(name);
			_bModified = true;
		}

		internal void Add(string name, ConfigurationValueFlags flags)
		{
			if (flags != ConfigurationValueFlags.Inherited && internalDictionary.Contains(name))
			{
				flags = ConfigurationValueFlags.Modified | (ConfigurationValueFlags)internalDictionary[name];
				internalDictionary.Remove(name);
				internalArraylist.Remove(name);
			}
			internalDictionary.Add(name, flags);
			internalArraylist.Add(name);
		}

		internal bool DefinedInParent(string name)
		{
			if (name == null)
			{
				return false;
			}
			if (_bExceptionList)
			{
				string text = "," + SeedList + ",";
				if (name.Equals(_ignoreName) || text.IndexOf("," + name + ",", StringComparison.Ordinal) >= 0)
				{
					return true;
				}
			}
			if (internalDictionary.Contains(name))
			{
				return ((ConfigurationValueFlags)internalDictionary[name] & ConfigurationValueFlags.Inherited) != 0;
			}
			return false;
		}

		internal bool IsValueModified(string name)
		{
			if (internalDictionary.Contains(name))
			{
				return ((ConfigurationValueFlags)internalDictionary[name] & ConfigurationValueFlags.Modified) != 0;
			}
			return false;
		}

		internal void RemoveInheritedLocks()
		{
			StringCollection stringCollection = new StringCollection();
			IEnumerator enumerator = GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					string text = (string)enumerator.Current;
					if (DefinedInParent(text))
					{
						stringCollection.Add(text);
					}
				}
			}
			finally
			{
				IDisposable disposable2 = enumerator as IDisposable;
				if (disposable2 != null)
				{
					disposable2.Dispose();
				}
			}
			StringEnumerator enumerator2 = stringCollection.GetEnumerator();
			try
			{
				while (enumerator2.MoveNext())
				{
					string current = enumerator2.Current;
					internalDictionary.Remove(current);
					internalArraylist.Remove(current);
				}
			}
			finally
			{
				if (enumerator2 is IDisposable disposable)
				{
					disposable.Dispose();
				}
			}
		}

		public void Remove(string name)
		{
			if (!internalDictionary.Contains(name))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_not_found", name));
			}
			if (!_bExceptionList && ((ConfigurationValueFlags)internalDictionary[name] & ConfigurationValueFlags.Inherited) != 0)
			{
				if (((ConfigurationValueFlags)internalDictionary[name] & ConfigurationValueFlags.Modified) == 0)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_base_attribute_locked", name));
				}
				ConfigurationValueFlags configurationValueFlags = (ConfigurationValueFlags)internalDictionary[name];
				configurationValueFlags &= ~ConfigurationValueFlags.Modified;
				internalDictionary[name] = configurationValueFlags;
				_bModified = true;
			}
			else
			{
				internalDictionary.Remove(name);
				internalArraylist.Remove(name);
				_bModified = true;
			}
		}

		public IEnumerator GetEnumerator()
		{
			return internalArraylist.GetEnumerator();
		}

		internal void ClearInternal(bool useSeedIfAvailble)
		{
			ArrayList arrayList = new ArrayList();
			foreach (DictionaryEntry item in internalDictionary)
			{
				if (((ConfigurationValueFlags)item.Value & ConfigurationValueFlags.Inherited) == 0 || _bExceptionList)
				{
					arrayList.Add(item.Key);
				}
			}
			foreach (object item2 in arrayList)
			{
				internalDictionary.Remove(item2);
				internalArraylist.Remove(item2);
			}
			if (useSeedIfAvailble && !string.IsNullOrEmpty(SeedList))
			{
				string[] array = SeedList.Split(',');
				string[] array2 = array;
				foreach (string name in array2)
				{
					Add(name, ConfigurationValueFlags.Inherited);
				}
			}
			_bModified = true;
		}

		public void Clear()
		{
			ClearInternal(useSeedIfAvailble: true);
		}

		public bool Contains(string name)
		{
			if (_bExceptionList && name.Equals(_ignoreName))
			{
				return true;
			}
			return internalDictionary.Contains(name);
		}

		public void CopyTo(string[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}

		void ICollection.CopyTo(Array array, int index)
		{
			internalArraylist.CopyTo(array, index);
		}

		internal void ResetModified()
		{
			_bModified = false;
		}

		public bool IsReadOnly(string name)
		{
			if (!internalDictionary.Contains(name))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_collection_entry_not_found", name));
			}
			return ((ConfigurationValueFlags)internalDictionary[name] & ConfigurationValueFlags.Inherited) != 0;
		}

		public void SetFromList(string attributeList)
		{
			string[] array = attributeList.Split(',', ';', ':');
			Clear();
			string[] array2 = array;
			foreach (string text in array2)
			{
				string name = text.Trim();
				if (!Contains(name))
				{
					Add(name);
				}
			}
		}
	}
	internal enum ConfigurationLockCollectionType
	{
		LockedAttributes = 1,
		LockedExceptionList,
		LockedElements,
		LockedElementsExceptionList
	}
	public static class ConfigurationManager
	{
		private enum InitState
		{
			NotStarted,
			Started,
			Usable,
			Completed
		}

		private static IInternalConfigSystem s_configSystem;

		private static InitState s_initState;

		private static object s_initLock;

		private static Exception s_initError;

		internal static bool SetConfigurationSystemInProgress
		{
			get
			{
				if (InitState.NotStarted < s_initState)
				{
					return s_initState < InitState.Completed;
				}
				return false;
			}
		}

		internal static bool SupportsUserConfig
		{
			get
			{
				PrepareConfigSystem();
				return s_configSystem.SupportsUserConfig;
			}
		}

		public static NameValueCollection AppSettings
		{
			get
			{
				object section = GetSection("appSettings");
				if (section == null || !(section is NameValueCollection))
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_appsettings_declaration_invalid"));
				}
				return (NameValueCollection)section;
			}
		}

		public static ConnectionStringSettingsCollection ConnectionStrings
		{
			get
			{
				object section = GetSection("connectionStrings");
				if (section == null || section.GetType() != typeof(ConnectionStringsSection))
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_connectionstrings_declaration_invalid"));
				}
				ConnectionStringsSection connectionStringsSection = (ConnectionStringsSection)section;
				return connectionStringsSection.ConnectionStrings;
			}
		}

		static ConfigurationManager()
		{
			s_initState = InitState.NotStarted;
			s_initLock = new object();
		}

		internal static void SetConfigurationSystem(IInternalConfigSystem configSystem, bool initComplete)
		{
			lock (s_initLock)
			{
				if (s_initState != 0)
				{
					throw new InvalidOperationException(SR.GetString("Config_system_already_set"));
				}
				s_configSystem = configSystem;
				if (initComplete)
				{
					s_initState = InitState.Completed;
				}
				else
				{
					s_initState = InitState.Usable;
				}
			}
		}

		private static void EnsureConfigurationSystem()
		{
			lock (s_initLock)
			{
				if (s_initState >= InitState.Usable)
				{
					return;
				}
				s_initState = InitState.Started;
				try
				{
					try
					{
						s_configSystem = new ClientConfigurationSystem();
						s_initState = InitState.Usable;
					}
					catch (Exception inner)
					{
						s_initError = new ConfigurationErrorsException(SR.GetString("Config_client_config_init_error"), inner);
						throw s_initError;
					}
					catch
					{
						s_initError = new ConfigurationErrorsException(SR.GetString("Config_client_config_init_error"));
						throw s_initError;
					}
				}
				catch
				{
					s_initState = InitState.Completed;
					throw;
				}
			}
		}

		internal static void SetInitError(Exception initError)
		{
			s_initError = initError;
		}

		internal static void CompleteConfigInit()
		{
			lock (s_initLock)
			{
				s_initState = InitState.Completed;
			}
		}

		private static void PrepareConfigSystem()
		{
			if (s_initState < InitState.Usable)
			{
				EnsureConfigurationSystem();
			}
			if (s_initError != null)
			{
				throw s_initError;
			}
		}

		public static object GetSection(string sectionName)
		{
			if (string.IsNullOrEmpty(sectionName))
			{
				return null;
			}
			PrepareConfigSystem();
			return s_configSystem.GetSection(sectionName);
		}

		public static void RefreshSection(string sectionName)
		{
			if (!string.IsNullOrEmpty(sectionName))
			{
				PrepareConfigSystem();
				s_configSystem.RefreshConfig(sectionName);
			}
		}

		public static Configuration OpenMachineConfiguration()
		{
			return OpenExeConfigurationImpl(null, isMachine: true, ConfigurationUserLevel.None, null);
		}

		public static Configuration OpenMappedMachineConfiguration(ConfigurationFileMap fileMap)
		{
			return OpenExeConfigurationImpl(fileMap, isMachine: true, ConfigurationUserLevel.None, null);
		}

		public static Configuration OpenExeConfiguration(ConfigurationUserLevel userLevel)
		{
			return OpenExeConfigurationImpl(null, isMachine: false, userLevel, null);
		}

		public static Configuration OpenExeConfiguration(string exePath)
		{
			return OpenExeConfigurationImpl(null, isMachine: false, ConfigurationUserLevel.None, exePath);
		}

		public static Configuration OpenMappedExeConfiguration(ExeConfigurationFileMap fileMap, ConfigurationUserLevel userLevel)
		{
			return OpenExeConfigurationImpl(fileMap, isMachine: false, userLevel, null);
		}

		private static Configuration OpenExeConfigurationImpl(ConfigurationFileMap fileMap, bool isMachine, ConfigurationUserLevel userLevel, string exePath)
		{
			if (!isMachine && ((fileMap == null && exePath == null) || (fileMap != null && ((ExeConfigurationFileMap)fileMap).ExeConfigFilename == null)) && s_configSystem != null && s_configSystem.GetType() != typeof(ClientConfigurationSystem))
			{
				throw new ArgumentException(SR.GetString("Config_configmanager_open_noexe"));
			}
			return ClientConfigurationHost.OpenExeConfiguration(fileMap, isMachine, userLevel, exePath);
		}
	}
	internal static class ConfigurationManagerHelperFactory
	{
		private const string ConfigurationManagerHelperTypeString = "System.Configuration.Internal.ConfigurationManagerHelper, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

		private static IConfigurationManagerHelper s_instance;

		internal static IConfigurationManagerHelper Instance
		{
			get
			{
				if (s_instance == null)
				{
					s_instance = CreateConfigurationManagerHelper();
				}
				return s_instance;
			}
		}

		[ReflectionPermission(SecurityAction.Assert, Flags = ReflectionPermissionFlag.MemberAccess)]
		private static IConfigurationManagerHelper CreateConfigurationManagerHelper()
		{
			return TypeUtil.CreateInstance<IConfigurationManagerHelper>("System.Configuration.Internal.ConfigurationManagerHelper, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
		}
	}
	[Serializable]
	[AttributeUsage(AttributeTargets.All, AllowMultiple = true, Inherited = false)]
	public sealed class ConfigurationPermissionAttribute : CodeAccessSecurityAttribute
	{
		public ConfigurationPermissionAttribute(SecurityAction action)
			: base(action)
		{
		}

		public override IPermission CreatePermission()
		{
			PermissionState state = (base.Unrestricted ? PermissionState.Unrestricted : PermissionState.None);
			return new ConfigurationPermission(state);
		}
	}
	[Serializable]
	public sealed class ConfigurationPermission : CodeAccessPermission, IUnrestrictedPermission
	{
		private PermissionState _permissionState;

		public ConfigurationPermission(PermissionState state)
		{
			switch (state)
			{
			case PermissionState.None:
			case PermissionState.Unrestricted:
				_permissionState = state;
				break;
			default:
				throw ExceptionUtil.ParameterInvalid("state");
			}
		}

		public bool IsUnrestricted()
		{
			return _permissionState == PermissionState.Unrestricted;
		}

		public override IPermission Copy()
		{
			return new ConfigurationPermission(_permissionState);
		}

		public override IPermission Union(IPermission target)
		{
			if (target == null)
			{
				return Copy();
			}
			if (target.GetType() != typeof(ConfigurationPermission))
			{
				throw ExceptionUtil.ParameterInvalid("target");
			}
			if (_permissionState == PermissionState.Unrestricted)
			{
				return new ConfigurationPermission(PermissionState.Unrestricted);
			}
			ConfigurationPermission configurationPermission = (ConfigurationPermission)target;
			return new ConfigurationPermission(configurationPermission._permissionState);
		}

		public override IPermission Intersect(IPermission target)
		{
			if (target == null)
			{
				return null;
			}
			if (target.GetType() != typeof(ConfigurationPermission))
			{
				throw ExceptionUtil.ParameterInvalid("target");
			}
			if (_permissionState == PermissionState.None)
			{
				return new ConfigurationPermission(PermissionState.None);
			}
			ConfigurationPermission configurationPermission = (ConfigurationPermission)target;
			return new ConfigurationPermission(configurationPermission._permissionState);
		}

		public override bool IsSubsetOf(IPermission target)
		{
			if (target == null)
			{
				return _permissionState == PermissionState.None;
			}
			if (target.GetType() != typeof(ConfigurationPermission))
			{
				throw ExceptionUtil.ParameterInvalid("target");
			}
			ConfigurationPermission configurationPermission = (ConfigurationPermission)target;
			if (_permissionState != 0)
			{
				return configurationPermission._permissionState == PermissionState.Unrestricted;
			}
			return true;
		}

		public override void FromXml(SecurityElement securityElement)
		{
			if (securityElement == null)
			{
				throw new ArgumentNullException(SR.GetString("ConfigurationPermissionBadXml", "securityElement"));
			}
			if (!securityElement.Tag.Equals("IPermission"))
			{
				throw new ArgumentException(SR.GetString("ConfigurationPermissionBadXml", "securityElement"));
			}
			string text = securityElement.Attribute("class");
			if (text == null)
			{
				throw new ArgumentException(SR.GetString("ConfigurationPermissionBadXml", "securityElement"));
			}
			if (text.IndexOf(GetType().FullName, StringComparison.Ordinal) < 0)
			{
				throw new ArgumentException(SR.GetString("ConfigurationPermissionBadXml", "securityElement"));
			}
			string text2 = securityElement.Attribute("version");
			if (text2 != "1")
			{
				throw new ArgumentException(SR.GetString("ConfigurationPermissionBadXml", "version"));
			}
			string text3 = securityElement.Attribute("Unrestricted");
			if (text3 == null)
			{
				_permissionState = PermissionState.None;
				return;
			}
			switch (text3)
			{
			case "true":
				_permissionState = PermissionState.Unrestricted;
				break;
			case "false":
				_permissionState = PermissionState.None;
				break;
			default:
				throw new ArgumentException(SR.GetString("ConfigurationPermissionBadXml", "Unrestricted"));
			}
		}

		public override SecurityElement ToXml()
		{
			SecurityElement securityElement = new SecurityElement("IPermission");
			securityElement.AddAttribute("class", GetType().FullName + ", " + GetType().Module.Assembly.FullName.Replace('"', '\''));
			securityElement.AddAttribute("version", "1");
			if (IsUnrestricted())
			{
				securityElement.AddAttribute("Unrestricted", "true");
			}
			return securityElement;
		}
	}
	public sealed class ConfigurationProperty
	{
		internal static readonly ConfigurationValidatorBase NonEmptyStringValidator = new StringValidator(1);

		private static readonly ConfigurationValidatorBase DefaultValidatorInstance = new DefaultValidator();

		internal static readonly string DefaultCollectionPropertyName = "";

		private string _name;

		private string _providedName;

		private string _description;

		private Type _type;

		private object _defaultValue;

		private TypeConverter _converter;

		private ConfigurationPropertyOptions _options;

		private ConfigurationValidatorBase _validator;

		private string _addElementName;

		private string _removeElementName;

		private string _clearElementName;

		public string Name => _name;

		public string Description => _description;

		internal string ProvidedName => _providedName;

		public Type Type => _type;

		public object DefaultValue => _defaultValue;

		public bool IsRequired => (_options & ConfigurationPropertyOptions.IsRequired) != 0;

		public bool IsKey => (_options & ConfigurationPropertyOptions.IsKey) != 0;

		public bool IsDefaultCollection => (_options & ConfigurationPropertyOptions.IsDefaultCollection) != 0;

		public TypeConverter Converter
		{
			get
			{
				CreateConverter();
				return _converter;
			}
		}

		public ConfigurationValidatorBase Validator => _validator;

		internal string AddElementName => _addElementName;

		internal string RemoveElementName => _removeElementName;

		internal string ClearElementName => _clearElementName;

		public ConfigurationProperty(string name, Type type)
		{
			object defaultValue = null;
			ConstructorInit(name, type, ConfigurationPropertyOptions.None, null, null);
			if (type == typeof(string))
			{
				defaultValue = string.Empty;
			}
			else if (type.IsValueType)
			{
				defaultValue = TypeUtil.CreateInstanceWithReflectionPermission(type);
			}
			SetDefaultValue(defaultValue);
		}

		public ConfigurationProperty(string name, Type type, object defaultValue)
			: this(name, type, defaultValue, ConfigurationPropertyOptions.None)
		{
		}

		public ConfigurationProperty(string name, Type type, object defaultValue, ConfigurationPropertyOptions options)
			: this(name, type, defaultValue, null, null, options)
		{
		}

		public ConfigurationProperty(string name, Type type, object defaultValue, TypeConverter typeConverter, ConfigurationValidatorBase validator, ConfigurationPropertyOptions options)
			: this(name, type, defaultValue, typeConverter, validator, options, null)
		{
		}

		public ConfigurationProperty(string name, Type type, object defaultValue, TypeConverter typeConverter, ConfigurationValidatorBase validator, ConfigurationPropertyOptions options, string description)
		{
			ConstructorInit(name, type, options, validator, typeConverter);
			SetDefaultValue(defaultValue);
		}

		internal ConfigurationProperty(PropertyInfo info)
		{
			TypeConverterAttribute typeConverterAttribute = null;
			ConfigurationPropertyAttribute configurationPropertyAttribute = null;
			ConfigurationValidatorAttribute configurationValidatorAttribute = null;
			DescriptionAttribute descriptionAttribute = null;
			DefaultValueAttribute attribStdDefault = null;
			TypeConverter converter = null;
			ConfigurationValidatorBase configurationValidatorBase = null;
			Attribute[] customAttributes = Attribute.GetCustomAttributes(info);
			foreach (Attribute attribute in customAttributes)
			{
				if (attribute is TypeConverterAttribute)
				{
					typeConverterAttribute = (TypeConverterAttribute)attribute;
					converter = TypeUtil.CreateInstanceRestricted<TypeConverter>(info.DeclaringType, typeConverterAttribute.ConverterTypeName);
				}
				else if (attribute is ConfigurationPropertyAttribute)
				{
					configurationPropertyAttribute = (ConfigurationPropertyAttribute)attribute;
				}
				else if (attribute is ConfigurationValidatorAttribute)
				{
					if (configurationValidatorBase != null)
					{
						throw new ConfigurationErrorsException(SR.GetString("Validator_multiple_validator_attributes", info.Name));
					}
					configurationValidatorAttribute = (ConfigurationValidatorAttribute)attribute;
					configurationValidatorAttribute.SetDeclaringType(info.DeclaringType);
					configurationValidatorBase = configurationValidatorAttribute.ValidatorInstance;
				}
				else if (attribute is DescriptionAttribute)
				{
					descriptionAttribute = (DescriptionAttribute)attribute;
				}
				else if (attribute is DefaultValueAttribute)
				{
					attribStdDefault = (DefaultValueAttribute)attribute;
				}
			}
			Type propertyType = info.PropertyType;
			if (typeof(ConfigurationElementCollection).IsAssignableFrom(propertyType))
			{
				ConfigurationCollectionAttribute configurationCollectionAttribute = Attribute.GetCustomAttribute(info, typeof(ConfigurationCollectionAttribute)) as ConfigurationCollectionAttribute;
				if (configurationCollectionAttribute == null)
				{
					configurationCollectionAttribute = Attribute.GetCustomAttribute(propertyType, typeof(ConfigurationCollectionAttribute)) as ConfigurationCollectionAttribute;
				}
				if (configurationCollectionAttribute != null)
				{
					if (configurationCollectionAttribute.AddItemName.IndexOf(',') == -1)
					{
						_addElementName = configurationCollectionAttribute.AddItemName;
					}
					_removeElementName = configurationCollectionAttribute.RemoveItemName;
					_clearElementName = configurationCollectionAttribute.ClearItemsName;
				}
			}
			ConstructorInit(configurationPropertyAttribute.Name, info.PropertyType, configurationPropertyAttribute.Options, configurationValidatorBase, converter);
			InitDefaultValueFromTypeInfo(configurationPropertyAttribute, attribStdDefault);
			if (descriptionAttribute != null && !string.IsNullOrEmpty(descriptionAttribute.Description))
			{
				_description = descriptionAttribute.Description;
			}
		}

		private void ConstructorInit(string name, Type type, ConfigurationPropertyOptions options, ConfigurationValidatorBase validator, TypeConverter converter)
		{
			if (typeof(ConfigurationSection).IsAssignableFrom(type))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_properties_may_not_be_derived_from_configuration_section", name));
			}
			_providedName = name;
			if ((options & ConfigurationPropertyOptions.IsDefaultCollection) != 0 && string.IsNullOrEmpty(name))
			{
				name = DefaultCollectionPropertyName;
			}
			else
			{
				ValidatePropertyName(name);
			}
			_name = name;
			_type = type;
			_options = options;
			_validator = validator;
			_converter = converter;
			if (_validator == null)
			{
				_validator = DefaultValidatorInstance;
			}
			else if (!_validator.CanValidate(_type))
			{
				throw new ConfigurationErrorsException(SR.GetString("Validator_does_not_support_prop_type", _name));
			}
		}

		private void ValidatePropertyName(string name)
		{
			if (string.IsNullOrEmpty(name))
			{
				throw new ArgumentException(SR.GetString("String_null_or_empty"), "name");
			}
			if (BaseConfigurationRecord.IsReservedAttributeName(name))
			{
				throw new ArgumentException(SR.GetString("Property_name_reserved", name));
			}
		}

		private void SetDefaultValue(object value)
		{
			if (value != null && value != ConfigurationElement.s_nullPropertyValue)
			{
				bool flag = _type.IsAssignableFrom(value.GetType());
				if (!flag && Converter.CanConvertFrom(value.GetType()))
				{
					value = Converter.ConvertFrom(value);
				}
				else if (!flag)
				{
					throw new ConfigurationErrorsException(SR.GetString("Default_value_wrong_type", _name));
				}
				Validate(value);
				_defaultValue = value;
			}
		}

		private void InitDefaultValueFromTypeInfo(ConfigurationPropertyAttribute attribProperty, DefaultValueAttribute attribStdDefault)
		{
			object obj = attribProperty.DefaultValue;
			if ((obj == null || obj == ConfigurationElement.s_nullPropertyValue) && attribStdDefault != null)
			{
				obj = attribStdDefault.Value;
			}
			if (obj != null && obj is string && _type != typeof(string))
			{
				try
				{
					obj = Converter.ConvertFromInvariantString((string)obj);
				}
				catch (Exception ex)
				{
					throw new ConfigurationErrorsException(SR.GetString("Default_value_conversion_error_from_string", _name, ex.Message));
				}
				catch
				{
					throw new ConfigurationErrorsException(SR.GetString("Default_value_conversion_error_from_string", _name, ExceptionUtil.NoExceptionInformation));
				}
			}
			if (obj == null || obj == ConfigurationElement.s_nullPropertyValue)
			{
				if (_type == typeof(string))
				{
					obj = string.Empty;
				}
				else if (_type.IsValueType)
				{
					obj = TypeUtil.CreateInstanceWithReflectionPermission(_type);
				}
			}
			SetDefaultValue(obj);
		}

		internal object ConvertFromString(string value)
		{
			object obj = null;
			try
			{
				return Converter.ConvertFromInvariantString(value);
			}
			catch (Exception ex)
			{
				throw new ConfigurationErrorsException(SR.GetString("Top_level_conversion_error_from_string", _name, ex.Message));
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Top_level_conversion_error_from_string", _name, ExceptionUtil.NoExceptionInformation));
			}
		}

		internal string ConvertToString(object value)
		{
			string text = null;
			try
			{
				if (_type == typeof(bool))
				{
					return ((bool)value) ? "true" : "false";
				}
				return Converter.ConvertToInvariantString(value);
			}
			catch (Exception ex)
			{
				throw new ConfigurationErrorsException(SR.GetString("Top_level_conversion_error_to_string", _name, ex.Message));
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Top_level_conversion_error_to_string", _name, ExceptionUtil.NoExceptionInformation));
			}
		}

		internal void Validate(object value)
		{
			try
			{
				_validator.Validate(value);
			}
			catch (Exception ex)
			{
				throw new ConfigurationErrorsException(SR.GetString("Top_level_validation_error", _name, ex.Message), ex);
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Top_level_validation_error", _name, ExceptionUtil.NoExceptionInformation));
			}
		}

		private void CreateConverter()
		{
			if (_converter != null)
			{
				return;
			}
			if (_type.IsEnum)
			{
				_converter = new GenericEnumConverter(_type);
			}
			else if (!_type.IsSubclassOf(typeof(ConfigurationElement)))
			{
				_converter = TypeDescriptor.GetConverter(_type);
				if (_converter == null || !_converter.CanConvertFrom(typeof(string)) || !_converter.CanConvertTo(typeof(string)))
				{
					throw new ConfigurationErrorsException(SR.GetString("No_converter", _name, _type.Name));
				}
			}
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class ConfigurationPropertyAttribute : Attribute
	{
		internal static readonly string DefaultCollectionPropertyName = "";

		private string _Name;

		private object _DefaultValue = ConfigurationElement.s_nullPropertyValue;

		private ConfigurationPropertyOptions _Flags;

		public string Name => _Name;

		public object DefaultValue
		{
			get
			{
				return _DefaultValue;
			}
			set
			{
				_DefaultValue = value;
			}
		}

		public ConfigurationPropertyOptions Options
		{
			get
			{
				return _Flags;
			}
			set
			{
				_Flags = value;
			}
		}

		public bool IsDefaultCollection
		{
			get
			{
				return (Options & ConfigurationPropertyOptions.IsDefaultCollection) != 0;
			}
			set
			{
				if (value)
				{
					Options |= ConfigurationPropertyOptions.IsDefaultCollection;
				}
				else
				{
					Options &= ~ConfigurationPropertyOptions.IsDefaultCollection;
				}
			}
		}

		public bool IsRequired
		{
			get
			{
				return (Options & ConfigurationPropertyOptions.IsRequired) != 0;
			}
			set
			{
				if (value)
				{
					Options |= ConfigurationPropertyOptions.IsRequired;
				}
				else
				{
					Options &= ~ConfigurationPropertyOptions.IsRequired;
				}
			}
		}

		public bool IsKey
		{
			get
			{
				return (Options & ConfigurationPropertyOptions.IsKey) != 0;
			}
			set
			{
				if (value)
				{
					Options |= ConfigurationPropertyOptions.IsKey;
				}
				else
				{
					Options &= ~ConfigurationPropertyOptions.IsKey;
				}
			}
		}

		public ConfigurationPropertyAttribute(string name)
		{
			_Name = name;
		}
	}
	public class ConfigurationPropertyCollection : ICollection, IEnumerable
	{
		private ArrayList _items = new ArrayList();

		public int Count => _items.Count;

		public bool IsSynchronized => false;

		public object SyncRoot => _items;

		internal ConfigurationProperty DefaultCollectionProperty => this[ConfigurationProperty.DefaultCollectionPropertyName];

		public ConfigurationProperty this[string name]
		{
			get
			{
				for (int i = 0; i < _items.Count; i++)
				{
					ConfigurationProperty configurationProperty = (ConfigurationProperty)_items[i];
					if (configurationProperty.Name == name)
					{
						return (ConfigurationProperty)_items[i];
					}
				}
				return null;
			}
		}

		void ICollection.CopyTo(Array array, int index)
		{
			_items.CopyTo(array, index);
		}

		public void CopyTo(ConfigurationProperty[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}

		public IEnumerator GetEnumerator()
		{
			return _items.GetEnumerator();
		}

		public bool Contains(string name)
		{
			for (int i = 0; i < _items.Count; i++)
			{
				ConfigurationProperty configurationProperty = (ConfigurationProperty)_items[i];
				if (configurationProperty.Name == name)
				{
					return true;
				}
			}
			return false;
		}

		public void Add(ConfigurationProperty property)
		{
			if (!Contains(property.Name))
			{
				_items.Add(property);
			}
		}

		public bool Remove(string name)
		{
			for (int i = 0; i < _items.Count; i++)
			{
				ConfigurationProperty configurationProperty = (ConfigurationProperty)_items[i];
				if (configurationProperty.Name == name)
				{
					_items.RemoveAt(i);
					return true;
				}
			}
			return false;
		}

		public void Clear()
		{
			_items.Clear();
		}
	}
	[Flags]
	public enum ConfigurationPropertyOptions
	{
		None = 0,
		IsDefaultCollection = 1,
		IsRequired = 2,
		IsKey = 4
	}
	public enum ConfigurationSaveMode
	{
		Modified,
		Minimal,
		Full
	}
	internal class ConfigurationSchemaErrors
	{
		private List<ConfigurationException> _errorsLocal;

		private List<ConfigurationException> _errorsGlobal;

		private List<ConfigurationException> _errorsAll;

		internal bool HasLocalErrors => ErrorsHelper.GetHasErrors(_errorsLocal);

		internal bool HasGlobalErrors => ErrorsHelper.GetHasErrors(_errorsGlobal);

		private bool HasAllErrors => ErrorsHelper.GetHasErrors(_errorsAll);

		internal int GlobalErrorCount => ErrorsHelper.GetErrorCount(_errorsGlobal);

		internal ConfigurationSchemaErrors()
		{
		}

		internal void AddError(ConfigurationException ce, ExceptionAction action)
		{
			switch (action)
			{
			case ExceptionAction.Global:
				ErrorsHelper.AddError(ref _errorsAll, ce);
				ErrorsHelper.AddError(ref _errorsGlobal, ce);
				break;
			case ExceptionAction.NonSpecific:
				ErrorsHelper.AddError(ref _errorsAll, ce);
				break;
			case ExceptionAction.Local:
				ErrorsHelper.AddError(ref _errorsLocal, ce);
				break;
			}
		}

		internal void SetSingleGlobalError(ConfigurationException ce)
		{
			_errorsAll = null;
			_errorsLocal = null;
			_errorsGlobal = null;
			AddError(ce, ExceptionAction.Global);
		}

		internal bool HasErrors(bool ignoreLocal)
		{
			if (ignoreLocal)
			{
				return HasGlobalErrors;
			}
			return HasAllErrors;
		}

		internal void ThrowIfErrors(bool ignoreLocal)
		{
			if (HasErrors(ignoreLocal))
			{
				if (HasGlobalErrors)
				{
					throw new ConfigurationErrorsException(_errorsGlobal);
				}
				throw new ConfigurationErrorsException(_errorsAll);
			}
		}

		internal List<ConfigurationException> RetrieveAndResetLocalErrors(bool keepLocalErrors)
		{
			List<ConfigurationException> errorsLocal = _errorsLocal;
			_errorsLocal = null;
			if (keepLocalErrors)
			{
				ErrorsHelper.AddErrors(ref _errorsAll, errorsLocal);
			}
			return errorsLocal;
		}

		internal void AddSavedLocalErrors(ICollection<ConfigurationException> coll)
		{
			ErrorsHelper.AddErrors(ref _errorsAll, coll);
		}

		internal void ResetLocalErrors()
		{
			RetrieveAndResetLocalErrors(keepLocalErrors: false);
		}
	}
	[Serializable]
	public sealed class ConfigurationSectionCollection : NameObjectCollectionBase
	{
		private MgmtConfigurationRecord _configRecord;

		private ConfigurationSectionGroup _configSectionGroup;

		public ConfigurationSection this[string name] => Get(name);

		public ConfigurationSection this[int index] => Get(index);

		public override int Count => base.Count;

		public override KeysCollection Keys => base.Keys;

		internal ConfigurationSectionCollection(MgmtConfigurationRecord configRecord, ConfigurationSectionGroup configSectionGroup)
			: base(StringComparer.Ordinal)
		{
			_configRecord = configRecord;
			_configSectionGroup = configSectionGroup;
			foreach (DictionaryEntry sectionFactory in _configRecord.SectionFactories)
			{
				FactoryId factoryId = (FactoryId)sectionFactory.Value;
				if (factoryId.Group == _configSectionGroup.SectionGroupName)
				{
					BaseAdd(factoryId.Name, factoryId.Name);
				}
			}
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
		}

		internal void DetachFromConfigurationRecord()
		{
			_configRecord = null;
			BaseClear();
		}

		private void VerifyIsAttachedToConfigRecord()
		{
			if (_configRecord == null)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsectiongroup_when_not_attached"));
			}
		}

		public void Add(string name, ConfigurationSection section)
		{
			VerifyIsAttachedToConfigRecord();
			_configRecord.AddConfigurationSection(_configSectionGroup.SectionGroupName, name, section);
			BaseAdd(name, name);
		}

		public void Clear()
		{
			VerifyIsAttachedToConfigRecord();
			string[] array = BaseGetAllKeys();
			string[] array2 = array;
			foreach (string name in array2)
			{
				Remove(name);
			}
		}

		public void CopyTo(ConfigurationSection[] array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			int count = Count;
			if (array.Length < count + index)
			{
				throw new ArgumentOutOfRangeException("index");
			}
			int num = 0;
			int num2 = index;
			while (num < count)
			{
				array[num2] = Get(num);
				num++;
				num2++;
			}
		}

		public ConfigurationSection Get(int index)
		{
			return Get(GetKey(index));
		}

		public ConfigurationSection Get(string name)
		{
			VerifyIsAttachedToConfigRecord();
			if (string.IsNullOrEmpty(name))
			{
				throw ExceptionUtil.ParameterNullOrEmpty("name");
			}
			if (name.IndexOf('/') >= 0)
			{
				return null;
			}
			string configKey = BaseConfigurationRecord.CombineConfigKey(_configSectionGroup.SectionGroupName, name);
			return (ConfigurationSection)_configRecord.GetSection(configKey);
		}

		public override IEnumerator GetEnumerator()
		{
			int c = Count;
			for (int i = 0; i < c; i++)
			{
				yield return this[i];
			}
		}

		public string GetKey(int index)
		{
			return BaseGetKey(index);
		}

		public void Remove(string name)
		{
			VerifyIsAttachedToConfigRecord();
			_configRecord.RemoveConfigurationSection(_configSectionGroup.SectionGroupName, name);
			string key = BaseConfigurationRecord.CombineConfigKey(_configSectionGroup.SectionGroupName, name);
			if (!_configRecord.SectionFactories.Contains(key))
			{
				BaseRemove(name);
			}
		}

		public void RemoveAt(int index)
		{
			VerifyIsAttachedToConfigRecord();
			Remove(GetKey(index));
		}
	}
	public class ConfigurationSectionGroup
	{
		private string _configKey = string.Empty;

		private string _group = string.Empty;

		private string _name = string.Empty;

		private ConfigurationSectionCollection _configSections;

		private ConfigurationSectionGroupCollection _configSectionGroups;

		private MgmtConfigurationRecord _configRecord;

		private string _typeName;

		private bool _declared;

		private bool _declarationRequired;

		private bool _isRoot;

		internal bool Attached => _configRecord != null;

		public bool IsDeclared => _declared;

		public bool IsDeclarationRequired => _declarationRequired;

		public string SectionGroupName => _configKey;

		public string Name => _name;

		public string Type
		{
			get
			{
				return _typeName;
			}
			set
			{
				if (_isRoot)
				{
					throw new InvalidOperationException(SR.GetString("Config_root_section_group_cannot_be_edited"));
				}
				string text = value;
				if (string.IsNullOrEmpty(text))
				{
					text = null;
				}
				if (_configRecord != null)
				{
					if (_configRecord.IsLocationConfig)
					{
						throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsectiongroup_in_location_config"));
					}
					if (text != null)
					{
						FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
						if (factoryRecord != null && !factoryRecord.IsEquivalentType(_configRecord.Host, text))
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
						}
					}
				}
				_typeName = text;
			}
		}

		public ConfigurationSectionCollection Sections
		{
			get
			{
				if (_configSections == null)
				{
					VerifyIsAttachedToConfigRecord();
					_configSections = new ConfigurationSectionCollection(_configRecord, this);
				}
				return _configSections;
			}
		}

		public ConfigurationSectionGroupCollection SectionGroups
		{
			get
			{
				if (_configSectionGroups == null)
				{
					VerifyIsAttachedToConfigRecord();
					_configSectionGroups = new ConfigurationSectionGroupCollection(_configRecord, this);
				}
				return _configSectionGroups;
			}
		}

		internal bool IsRoot => _isRoot;

		internal void AttachToConfigurationRecord(MgmtConfigurationRecord configRecord, FactoryRecord factoryRecord)
		{
			_configRecord = configRecord;
			_configKey = factoryRecord.ConfigKey;
			_group = factoryRecord.Group;
			_name = factoryRecord.Name;
			_typeName = factoryRecord.FactoryTypeName;
			if (_typeName != null)
			{
				FactoryRecord factoryRecord2 = null;
				if (!configRecord.Parent.IsRootConfig)
				{
					factoryRecord2 = configRecord.Parent.FindFactoryRecord(factoryRecord.ConfigKey, permitErrors: true);
				}
				_declarationRequired = factoryRecord2 == null || factoryRecord2.FactoryTypeName == null;
				_declared = configRecord.GetFactoryRecord(factoryRecord.ConfigKey, permitErrors: true) != null;
			}
		}

		internal void RootAttachToConfigurationRecord(MgmtConfigurationRecord configRecord)
		{
			_configRecord = configRecord;
			_isRoot = true;
		}

		internal void DetachFromConfigurationRecord()
		{
			if (_configSections != null)
			{
				_configSections.DetachFromConfigurationRecord();
			}
			if (_configSectionGroups != null)
			{
				_configSectionGroups.DetachFromConfigurationRecord();
			}
			_configRecord = null;
		}

		private FactoryRecord FindParentFactoryRecord(bool permitErrors)
		{
			FactoryRecord result = null;
			if (_configRecord != null && !_configRecord.Parent.IsRootConfig)
			{
				result = _configRecord.Parent.FindFactoryRecord(_configKey, permitErrors);
			}
			return result;
		}

		private void VerifyIsAttachedToConfigRecord()
		{
			if (_configRecord == null)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsectiongroup_when_not_attached"));
			}
		}

		public void ForceDeclaration()
		{
			ForceDeclaration(force: true);
		}

		public void ForceDeclaration(bool force)
		{
			if (_isRoot)
			{
				throw new InvalidOperationException(SR.GetString("Config_root_section_group_cannot_be_edited"));
			}
			if (_configRecord != null && _configRecord.IsLocationConfig)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsectiongroup_in_location_config"));
			}
			if (force || !_declarationRequired)
			{
				_declared = force;
			}
		}
	}
	[Serializable]
	public sealed class ConfigurationSectionGroupCollection : NameObjectCollectionBase
	{
		private MgmtConfigurationRecord _configRecord;

		private ConfigurationSectionGroup _configSectionGroup;

		public ConfigurationSectionGroup this[string name] => Get(name);

		public ConfigurationSectionGroup this[int index] => Get(index);

		public override int Count => base.Count;

		public override KeysCollection Keys => base.Keys;

		internal ConfigurationSectionGroupCollection(MgmtConfigurationRecord configRecord, ConfigurationSectionGroup configSectionGroup)
			: base(StringComparer.Ordinal)
		{
			_configRecord = configRecord;
			_configSectionGroup = configSectionGroup;
			foreach (DictionaryEntry sectionGroupFactory in _configRecord.SectionGroupFactories)
			{
				FactoryId factoryId = (FactoryId)sectionGroupFactory.Value;
				if (factoryId.Group == _configSectionGroup.SectionGroupName)
				{
					BaseAdd(factoryId.Name, factoryId.Name);
				}
			}
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
		}

		internal void DetachFromConfigurationRecord()
		{
			_configRecord = null;
			BaseClear();
		}

		private void VerifyIsAttachedToConfigRecord()
		{
			if (_configRecord == null)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsectiongroup_when_not_attached"));
			}
		}

		public void Add(string name, ConfigurationSectionGroup sectionGroup)
		{
			VerifyIsAttachedToConfigRecord();
			_configRecord.AddConfigurationSectionGroup(_configSectionGroup.SectionGroupName, name, sectionGroup);
			BaseAdd(name, name);
		}

		public void Clear()
		{
			VerifyIsAttachedToConfigRecord();
			if (_configSectionGroup.IsRoot)
			{
				_configRecord.RemoveLocationWriteRequirement();
			}
			string[] array = BaseGetAllKeys();
			string[] array2 = array;
			foreach (string name in array2)
			{
				Remove(name);
			}
		}

		public void CopyTo(ConfigurationSectionGroup[] array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			int count = Count;
			if (array.Length < count + index)
			{
				throw new ArgumentOutOfRangeException("index");
			}
			int num = 0;
			int num2 = index;
			while (num < count)
			{
				array[num2] = Get(num);
				num++;
				num2++;
			}
		}

		public ConfigurationSectionGroup Get(int index)
		{
			return Get(GetKey(index));
		}

		public ConfigurationSectionGroup Get(string name)
		{
			VerifyIsAttachedToConfigRecord();
			if (string.IsNullOrEmpty(name))
			{
				throw ExceptionUtil.ParameterNullOrEmpty("name");
			}
			if (name.IndexOf('/') >= 0)
			{
				return null;
			}
			string configKey = BaseConfigurationRecord.CombineConfigKey(_configSectionGroup.SectionGroupName, name);
			return _configRecord.GetSectionGroup(configKey);
		}

		public override IEnumerator GetEnumerator()
		{
			int c = Count;
			for (int i = 0; i < c; i++)
			{
				yield return this[i];
			}
		}

		public string GetKey(int index)
		{
			return BaseGetKey(index);
		}

		public void Remove(string name)
		{
			VerifyIsAttachedToConfigRecord();
			_configRecord.RemoveConfigurationSectionGroup(_configSectionGroup.SectionGroupName, name);
			string key = BaseConfigurationRecord.CombineConfigKey(_configSectionGroup.SectionGroupName, name);
			if (!_configRecord.SectionFactories.Contains(key))
			{
				BaseRemove(name);
			}
		}

		public void RemoveAt(int index)
		{
			VerifyIsAttachedToConfigRecord();
			Remove(GetKey(index));
		}
	}
	public enum ConfigurationUserLevel
	{
		None = 0,
		PerUserRoaming = 10,
		PerUserRoamingAndLocal = 20
	}
	internal class ConfigurationValue
	{
		internal ConfigurationValueFlags ValueFlags;

		internal object Value;

		internal PropertySourceInfo SourceInfo;

		internal ConfigurationValue(object value, ConfigurationValueFlags valueFlags, PropertySourceInfo sourceInfo)
		{
			Value = value;
			ValueFlags = valueFlags;
			SourceInfo = sourceInfo;
		}
	}
	[Flags]
	internal enum ConfigurationValueFlags
	{
		Default = 0,
		Inherited = 1,
		Modified = 2,
		Locked = 4,
		XMLParentInherited = 8
	}
	internal class ConfigurationValues : NameObjectCollectionBase
	{
		private class EmptyCollection : IEnumerable
		{
			private class EmptyCollectionEnumerator : IEnumerator
			{
				object IEnumerator.Current => null;

				bool IEnumerator.MoveNext()
				{
					return false;
				}

				void IEnumerator.Reset()
				{
				}
			}

			private IEnumerator _emptyEnumerator;

			internal EmptyCollection()
			{
				_emptyEnumerator = new EmptyCollectionEnumerator();
			}

			IEnumerator IEnumerable.GetEnumerator()
			{
				return _emptyEnumerator;
			}
		}

		private class ConfigurationElementsCollection : IEnumerable
		{
			private ConfigurationValues _values;

			internal ConfigurationElementsCollection(ConfigurationValues values)
			{
				_values = values;
			}

			IEnumerator IEnumerable.GetEnumerator()
			{
				if (!_values._containsElement)
				{
					yield break;
				}
				for (int index = 0; index < _values.Count; index++)
				{
					object value = _values[index];
					if (value is ConfigurationElement)
					{
						yield return value;
					}
				}
			}
		}

		private class InvalidValuesCollection : IEnumerable
		{
			private ConfigurationValues _values;

			internal InvalidValuesCollection(ConfigurationValues values)
			{
				_values = values;
			}

			IEnumerator IEnumerable.GetEnumerator()
			{
				if (!_values._containsInvalidValue)
				{
					yield break;
				}
				for (int index = 0; index < _values.Count; index++)
				{
					object value = _values[index];
					if (value is InvalidPropValue)
					{
						yield return value;
					}
				}
			}
		}

		private BaseConfigurationRecord _configRecord;

		private bool _containsElement;

		private bool _containsInvalidValue;

		private static IEnumerable s_emptyCollection;

		internal object this[string key]
		{
			get
			{
				return GetConfigValue(key)?.Value;
			}
			set
			{
				SetValue(key, value, ConfigurationValueFlags.Modified, null);
			}
		}

		internal object this[int index] => GetConfigValue(index)?.Value;

		internal object SyncRoot => this;

		internal IEnumerable ConfigurationElements
		{
			get
			{
				if (_containsElement)
				{
					return new ConfigurationElementsCollection(this);
				}
				return EmptyCollectionInstance;
			}
		}

		internal IEnumerable InvalidValues
		{
			get
			{
				if (_containsInvalidValue)
				{
					return new InvalidValuesCollection(this);
				}
				return EmptyCollectionInstance;
			}
		}

		private static IEnumerable EmptyCollectionInstance
		{
			get
			{
				if (s_emptyCollection == null)
				{
					s_emptyCollection = new EmptyCollection();
				}
				return s_emptyCollection;
			}
		}

		internal ConfigurationValues()
			: base(StringComparer.Ordinal)
		{
		}

		internal void AssociateContext(BaseConfigurationRecord configRecord)
		{
			_configRecord = configRecord;
			foreach (ConfigurationElement configurationElement in ConfigurationElements)
			{
				configurationElement.AssociateContext(_configRecord);
			}
		}

		internal bool Contains(string key)
		{
			return BaseGet(key) != null;
		}

		internal string GetKey(int index)
		{
			return BaseGetKey(index);
		}

		internal ConfigurationValue GetConfigValue(string key)
		{
			return (ConfigurationValue)BaseGet(key);
		}

		internal ConfigurationValue GetConfigValue(int index)
		{
			return (ConfigurationValue)BaseGet(index);
		}

		internal PropertySourceInfo GetSourceInfo(string key)
		{
			return GetConfigValue(key)?.SourceInfo;
		}

		internal void ChangeSourceInfo(string key, PropertySourceInfo sourceInfo)
		{
			ConfigurationValue configValue = GetConfigValue(key);
			if (configValue != null)
			{
				configValue.SourceInfo = sourceInfo;
			}
		}

		private ConfigurationValue CreateConfigValue(object value, ConfigurationValueFlags valueFlags, PropertySourceInfo sourceInfo)
		{
			if (value != null)
			{
				if (value is ConfigurationElement)
				{
					_containsElement = true;
					((ConfigurationElement)value).AssociateContext(_configRecord);
				}
				else if (value is InvalidPropValue)
				{
					_containsInvalidValue = true;
				}
			}
			return new ConfigurationValue(value, valueFlags, sourceInfo);
		}

		internal void SetValue(string key, object value, ConfigurationValueFlags valueFlags, PropertySourceInfo sourceInfo)
		{
			ConfigurationValue value2 = CreateConfigValue(value, valueFlags, sourceInfo);
			BaseSet(key, value2);
		}

		internal void Clear()
		{
			BaseClear();
		}

		internal ConfigurationValueFlags RetrieveFlags(string key)
		{
			return ((ConfigurationValue)BaseGet(key))?.ValueFlags ?? ConfigurationValueFlags.Default;
		}

		internal bool IsModified(string key)
		{
			ConfigurationValue configurationValue = (ConfigurationValue)BaseGet(key);
			if (configurationValue != null)
			{
				return (configurationValue.ValueFlags & ConfigurationValueFlags.Modified) != 0;
			}
			return false;
		}

		internal bool IsInherited(string key)
		{
			ConfigurationValue configurationValue = (ConfigurationValue)BaseGet(key);
			if (configurationValue != null)
			{
				return (configurationValue.ValueFlags & ConfigurationValueFlags.Inherited) != 0;
			}
			return false;
		}
	}
}
namespace System.Configuration.Internal
{
	public interface IConfigErrorInfo
	{
		string Filename { get; }

		int LineNumber { get; }
	}
}
namespace System.Configuration
{
	internal sealed class ConfigXmlAttribute : XmlAttribute, IConfigErrorInfo
	{
		private int _line;

		private string _filename;

		int IConfigErrorInfo.LineNumber => _line;

		string IConfigErrorInfo.Filename => _filename;

		public ConfigXmlAttribute(string filename, int line, string prefix, string localName, string namespaceUri, XmlDocument doc)
			: base(prefix, localName, namespaceUri, doc)
		{
			_line = line;
			_filename = filename;
		}

		public override XmlNode CloneNode(bool deep)
		{
			XmlNode xmlNode = base.CloneNode(deep);
			if (xmlNode is ConfigXmlAttribute configXmlAttribute)
			{
				configXmlAttribute._line = _line;
				configXmlAttribute._filename = _filename;
			}
			return xmlNode;
		}
	}
	internal sealed class ConfigXmlCDataSection : XmlCDataSection, IConfigErrorInfo
	{
		private int _line;

		private string _filename;

		int IConfigErrorInfo.LineNumber => _line;

		string IConfigErrorInfo.Filename => _filename;

		public ConfigXmlCDataSection(string filename, int line, string data, XmlDocument doc)
			: base(data, doc)
		{
			_line = line;
			_filename = filename;
		}

		public override XmlNode CloneNode(bool deep)
		{
			XmlNode xmlNode = base.CloneNode(deep);
			if (xmlNode is ConfigXmlCDataSection configXmlCDataSection)
			{
				configXmlCDataSection._line = _line;
				configXmlCDataSection._filename = _filename;
			}
			return xmlNode;
		}
	}
	internal sealed class ConfigXmlComment : XmlComment, IConfigErrorInfo
	{
		private int _line;

		private string _filename;

		int IConfigErrorInfo.LineNumber => _line;

		string IConfigErrorInfo.Filename => _filename;

		public ConfigXmlComment(string filename, int line, string comment, XmlDocument doc)
			: base(comment, doc)
		{
			_line = line;
			_filename = filename;
		}

		public override XmlNode CloneNode(bool deep)
		{
			XmlNode xmlNode = base.CloneNode(deep);
			if (xmlNode is ConfigXmlComment configXmlComment)
			{
				configXmlComment._line = _line;
				configXmlComment._filename = _filename;
			}
			return xmlNode;
		}
	}
	internal sealed class ConfigXmlElement : XmlElement, IConfigErrorInfo
	{
		private int _line;

		private string _filename;

		int IConfigErrorInfo.LineNumber => _line;

		string IConfigErrorInfo.Filename => _filename;

		public ConfigXmlElement(string filename, int line, string prefix, string localName, string namespaceUri, XmlDocument doc)
			: base(prefix, localName, namespaceUri, doc)
		{
			_line = line;
			_filename = filename;
		}

		public override XmlNode CloneNode(bool deep)
		{
			XmlNode xmlNode = base.CloneNode(deep);
			if (xmlNode is ConfigXmlElement configXmlElement)
			{
				configXmlElement._line = _line;
				configXmlElement._filename = _filename;
			}
			return xmlNode;
		}
	}
	internal sealed class ConfigXmlReader : XmlTextReader, IConfigErrorInfo
	{
		private string _rawXml;

		private int _lineOffset;

		private string _filename;

		private bool _lineNumberIsConstant;

		int IConfigErrorInfo.LineNumber
		{
			get
			{
				if (_lineNumberIsConstant)
				{
					return _lineOffset;
				}
				if (_lineOffset > 0)
				{
					return base.LineNumber + (_lineOffset - 1);
				}
				return base.LineNumber;
			}
		}

		string IConfigErrorInfo.Filename => _filename;

		internal string RawXml => _rawXml;

		internal ConfigXmlReader(string rawXml, string filename, int lineOffset)
			: this(rawXml, filename, lineOffset, lineNumberIsConstant: false)
		{
		}

		internal ConfigXmlReader(string rawXml, string filename, int lineOffset, bool lineNumberIsConstant)
			: base(new StringReader(rawXml))
		{
			_rawXml = rawXml;
			_filename = filename;
			_lineOffset = lineOffset;
			_lineNumberIsConstant = lineNumberIsConstant;
		}

		internal ConfigXmlReader Clone()
		{
			return new ConfigXmlReader(_rawXml, _filename, _lineOffset, _lineNumberIsConstant);
		}
	}
	internal sealed class ConfigXmlSignificantWhitespace : XmlSignificantWhitespace, IConfigErrorInfo
	{
		private int _line;

		private string _filename;

		int IConfigErrorInfo.LineNumber => _line;

		string IConfigErrorInfo.Filename => _filename;

		public ConfigXmlSignificantWhitespace(string filename, int line, string strData, XmlDocument doc)
			: base(strData, doc)
		{
			_line = line;
			_filename = filename;
		}

		public override XmlNode CloneNode(bool deep)
		{
			XmlNode xmlNode = base.CloneNode(deep);
			if (xmlNode is ConfigXmlSignificantWhitespace configXmlSignificantWhitespace)
			{
				configXmlSignificantWhitespace._line = _line;
				configXmlSignificantWhitespace._filename = _filename;
			}
			return xmlNode;
		}
	}
	internal sealed class ConfigXmlText : XmlText, IConfigErrorInfo
	{
		private int _line;

		private string _filename;

		int IConfigErrorInfo.LineNumber => _line;

		string IConfigErrorInfo.Filename => _filename;

		public ConfigXmlText(string filename, int line, string strData, XmlDocument doc)
			: base(strData, doc)
		{
			_line = line;
			_filename = filename;
		}

		public override XmlNode CloneNode(bool deep)
		{
			XmlNode xmlNode = base.CloneNode(deep);
			if (xmlNode is ConfigXmlText configXmlText)
			{
				configXmlText._line = _line;
				configXmlText._filename = _filename;
			}
			return xmlNode;
		}
	}
	internal sealed class ConfigXmlWhitespace : XmlWhitespace, IConfigErrorInfo
	{
		private int _line;

		private string _filename;

		int IConfigErrorInfo.LineNumber => _line;

		string IConfigErrorInfo.Filename => _filename;

		public ConfigXmlWhitespace(string filename, int line, string comment, XmlDocument doc)
			: base(comment, doc)
		{
			_line = line;
			_filename = filename;
		}

		public override XmlNode CloneNode(bool deep)
		{
			XmlNode xmlNode = base.CloneNode(deep);
			if (xmlNode is ConfigXmlWhitespace configXmlWhitespace)
			{
				configXmlWhitespace._line = _line;
				configXmlWhitespace._filename = _filename;
			}
			return xmlNode;
		}
	}
	public sealed class ConnectionStringSettings : ConfigurationElement
	{
		private static ConfigurationPropertyCollection _properties;

		private static readonly ConfigurationProperty _propName;

		private static readonly ConfigurationProperty _propConnectionString;

		private static readonly ConfigurationProperty _propProviderName;

		internal string Key => Name;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		[ConfigurationProperty("name", Options = (ConfigurationPropertyOptions.IsRequired | ConfigurationPropertyOptions.IsKey), DefaultValue = "")]
		public string Name
		{
			get
			{
				return (string)base[_propName];
			}
			set
			{
				base[_propName] = value;
			}
		}

		[ConfigurationProperty("connectionString", Options = ConfigurationPropertyOptions.IsRequired, DefaultValue = "")]
		public string ConnectionString
		{
			get
			{
				return (string)base[_propConnectionString];
			}
			set
			{
				base[_propConnectionString] = value;
			}
		}

		[ConfigurationProperty("providerName", DefaultValue = "System.Data.SqlClient")]
		public string ProviderName
		{
			get
			{
				return (string)base[_propProviderName];
			}
			set
			{
				base[_propProviderName] = value;
			}
		}

		static ConnectionStringSettings()
		{
			_propName = new ConfigurationProperty("name", typeof(string), null, null, ConfigurationProperty.NonEmptyStringValidator, ConfigurationPropertyOptions.IsRequired | ConfigurationPropertyOptions.IsKey);
			_propConnectionString = new ConfigurationProperty("connectionString", typeof(string), "", ConfigurationPropertyOptions.IsRequired);
			_propProviderName = new ConfigurationProperty("providerName", typeof(string), string.Empty, ConfigurationPropertyOptions.None);
			_properties = new ConfigurationPropertyCollection();
			_properties.Add(_propName);
			_properties.Add(_propConnectionString);
			_properties.Add(_propProviderName);
		}

		public ConnectionStringSettings()
		{
		}

		public ConnectionStringSettings(string name, string connectionString)
			: this()
		{
			Name = name;
			ConnectionString = connectionString;
		}

		public ConnectionStringSettings(string name, string connectionString, string providerName)
			: this()
		{
			Name = name;
			ConnectionString = connectionString;
			ProviderName = providerName;
		}

		public override string ToString()
		{
			return ConnectionString;
		}
	}
	[ConfigurationCollection(typeof(ConnectionStringSettings))]
	public sealed class ConnectionStringSettingsCollection : ConfigurationElementCollection
	{
		private static ConfigurationPropertyCollection _properties;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		public ConnectionStringSettings this[int index]
		{
			get
			{
				return (ConnectionStringSettings)BaseGet(index);
			}
			set
			{
				if (BaseGet(index) != null)
				{
					BaseRemoveAt(index);
				}
				BaseAdd(index, value);
			}
		}

		public new ConnectionStringSettings this[string name] => (ConnectionStringSettings)BaseGet(name);

		static ConnectionStringSettingsCollection()
		{
			_properties = new ConfigurationPropertyCollection();
		}

		public ConnectionStringSettingsCollection()
			: base(StringComparer.OrdinalIgnoreCase)
		{
		}

		public int IndexOf(ConnectionStringSettings settings)
		{
			return BaseIndexOf(settings);
		}

		protected override void BaseAdd(int index, ConfigurationElement element)
		{
			if (index == -1)
			{
				BaseAdd(element, throwIfExists: false);
			}
			else
			{
				base.BaseAdd(index, element);
			}
		}

		public void Add(ConnectionStringSettings settings)
		{
			BaseAdd(settings);
		}

		public void Remove(ConnectionStringSettings settings)
		{
			if (BaseIndexOf(settings) >= 0)
			{
				BaseRemove(settings.Key);
			}
		}

		public void RemoveAt(int index)
		{
			BaseRemoveAt(index);
		}

		public void Remove(string name)
		{
			BaseRemove(name);
		}

		protected override ConfigurationElement CreateNewElement()
		{
			return new ConnectionStringSettings();
		}

		protected override object GetElementKey(ConfigurationElement element)
		{
			return ((ConnectionStringSettings)element).Key;
		}

		public void Clear()
		{
			BaseClear();
		}
	}
	public sealed class ConnectionStringsSection : ConfigurationSection
	{
		private static ConfigurationPropertyCollection _properties;

		private static readonly ConfigurationProperty _propConnectionStrings;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		[ConfigurationProperty("", Options = ConfigurationPropertyOptions.IsDefaultCollection)]
		public ConnectionStringSettingsCollection ConnectionStrings => (ConnectionStringSettingsCollection)base[_propConnectionStrings];

		static ConnectionStringsSection()
		{
			_propConnectionStrings = new ConfigurationProperty(null, typeof(ConnectionStringSettingsCollection), null, ConfigurationPropertyOptions.IsDefaultCollection);
			_properties = new ConfigurationPropertyCollection();
			_properties.Add(_propConnectionStrings);
		}

		protected internal override object GetRuntimeObject()
		{
			SetReadOnly();
			return this;
		}
	}
	public sealed class ContextInformation
	{
		private bool _hostingContextEvaluated;

		private object _hostingContext;

		private BaseConfigurationRecord _configRecord;

		public object HostingContext
		{
			get
			{
				if (!_hostingContextEvaluated)
				{
					_hostingContext = _configRecord.ConfigContext;
					_hostingContextEvaluated = true;
				}
				return _hostingContext;
			}
		}

		public bool IsMachineLevel => _configRecord.IsMachineConfig;

		internal ContextInformation(BaseConfigurationRecord configRecord)
		{
			_hostingContextEvaluated = false;
			_hostingContext = null;
			_configRecord = configRecord;
		}

		public object GetSection(string sectionName)
		{
			return _configRecord.GetSection(sectionName);
		}
	}
	internal struct CRYPTPROTECT_PROMPTSTRUCT : IDisposable
	{
		public int cbSize;

		public int dwPromptFlags;

		public IntPtr hwndApp;

		public string szPrompt;

		void IDisposable.Dispose()
		{
			hwndApp = IntPtr.Zero;
		}
	}
	internal struct DATA_BLOB : IDisposable
	{
		public int cbData;

		public IntPtr pbData;

		void IDisposable.Dispose()
		{
			if (pbData != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(pbData);
				pbData = IntPtr.Zero;
			}
		}
	}
	internal static class Debug
	{
		internal const string TAG_INTERNAL = "Internal";

		internal const string TAG_EXTERNAL = "External";

		internal const string TAG_ALL = "*";

		internal const string DATE_FORMAT = "yyyy/MM/dd HH:mm:ss.ffff";

		internal const string TIME_FORMAT = "HH:mm:ss:ffff";

		[Conditional("DBG")]
		internal static void Trace(string tagName, string message)
		{
		}

		[Conditional("DBG")]
		internal static void Trace(string tagName, string message, bool includePrefix)
		{
		}

		[Conditional("DBG")]
		internal static void Trace(string tagName, string message, Exception e)
		{
		}

		[Conditional("DBG")]
		internal static void Trace(string tagName, Exception e)
		{
		}

		[Conditional("DBG")]
		internal static void Trace(string tagName, string message, Exception e, bool includePrefix)
		{
		}

		[Conditional("DBG")]
		internal static void Assert(bool assertion, string message)
		{
		}

		[Conditional("DBG")]
		internal static void Assert(bool assertion)
		{
		}

		[Conditional("DBG")]
		internal static void Fail(string message)
		{
		}

		internal static bool IsTagEnabled(string tagName)
		{
			return false;
		}

		internal static bool IsTagPresent(string tagName)
		{
			return false;
		}

		[Conditional("DBG")]
		internal static void Break()
		{
		}

		[Conditional("DBG")]
		internal static void AlwaysValidate(string tagName)
		{
		}

		[Conditional("DBG")]
		internal static void CheckValid(bool assertion, string message)
		{
		}

		[Conditional("DBG")]
		internal static void Validate(object obj)
		{
		}

		[Conditional("DBG")]
		internal static void Validate(string tagName, object obj)
		{
		}

		[Conditional("DBG")]
		internal static void Dump(string tagName, object obj)
		{
		}
	}
	internal abstract class Update
	{
		private bool _moved;

		private bool _retrieved;

		private string _configKey;

		private string _updatedXml;

		internal string ConfigKey => _configKey;

		internal bool Moved => _moved;

		internal string UpdatedXml => _updatedXml;

		internal bool Retrieved
		{
			get
			{
				return _retrieved;
			}
			set
			{
				_retrieved = value;
			}
		}

		internal Update(string configKey, bool moved, string updatedXml)
		{
			_configKey = configKey;
			_moved = moved;
			_updatedXml = updatedXml;
		}
	}
	internal class DeclarationUpdate : Update
	{
		internal DeclarationUpdate(string configKey, bool moved, string updatedXml)
			: base(configKey, moved, updatedXml)
		{
		}
	}
	public sealed class DefaultSection : ConfigurationSection
	{
		private static ConfigurationPropertyCollection s_properties;

		private string _rawXml = string.Empty;

		private bool _isModified;

		protected internal override ConfigurationPropertyCollection Properties => EnsureStaticPropertyBag();

		private static ConfigurationPropertyCollection EnsureStaticPropertyBag()
		{
			if (s_properties == null)
			{
				ConfigurationPropertyCollection configurationPropertyCollection = (s_properties = new ConfigurationPropertyCollection());
			}
			return s_properties;
		}

		public DefaultSection()
		{
			EnsureStaticPropertyBag();
		}

		protected internal override bool IsModified()
		{
			return _isModified;
		}

		protected internal override void ResetModified()
		{
			_isModified = false;
		}

		protected internal override void Reset(ConfigurationElement parentSection)
		{
			_rawXml = string.Empty;
			_isModified = false;
		}

		protected internal override void DeserializeSection(XmlReader xmlReader)
		{
			if (!xmlReader.Read() || xmlReader.NodeType != XmlNodeType.Element)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_expected_to_find_element"), xmlReader);
			}
			_rawXml = xmlReader.ReadOuterXml();
			_isModified = true;
		}

		protected internal override string SerializeSection(ConfigurationElement parentSection, string name, ConfigurationSaveMode saveMode)
		{
			return _rawXml;
		}
	}
	public sealed class DefaultValidator : ConfigurationValidatorBase
	{
		public override bool CanValidate(Type type)
		{
			return true;
		}

		public override void Validate(object value)
		{
		}
	}
	internal class DefinitionUpdate : Update
	{
		private SectionRecord _sectionRecord;

		internal SectionRecord SectionRecord => _sectionRecord;

		internal DefinitionUpdate(string configKey, bool moved, string updatedXml, SectionRecord sectionRecord)
			: base(configKey, moved, updatedXml)
		{
			_sectionRecord = sectionRecord;
		}
	}
}
namespace System.Configuration.Provider
{
	public abstract class ProviderBase
	{
		private string _name;

		private string _Description;

		private bool _Initialized;

		public virtual string Name => _name;

		public virtual string Description
		{
			get
			{
				if (!string.IsNullOrEmpty(_Description))
				{
					return _Description;
				}
				return Name;
			}
		}

		public virtual void Initialize(string name, NameValueCollection config)
		{
			lock (this)
			{
				if (_Initialized)
				{
					throw new InvalidOperationException(SR.GetString("Provider_Already_Initialized"));
				}
				_Initialized = true;
			}
			if (name == null)
			{
				throw new ArgumentNullException("name");
			}
			if (name.Length == 0)
			{
				throw new ArgumentException(SR.GetString("Config_provider_name_null_or_empty"), "name");
			}
			_name = name;
			if (config != null)
			{
				_Description = config["description"];
				config.Remove("description");
			}
		}
	}
}
namespace System.Configuration
{
	public abstract class ProtectedConfigurationProvider : ProviderBase
	{
		public abstract XmlNode Encrypt(XmlNode node);

		public abstract XmlNode Decrypt(XmlNode encryptedNode);
	}
	[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
	public sealed class DpapiProtectedConfigurationProvider : ProtectedConfigurationProvider
	{
		private const int CRYPTPROTECT_UI_FORBIDDEN = 1;

		private const int CRYPTPROTECT_LOCAL_MACHINE = 4;

		private bool _UseMachineProtection = true;

		private string _KeyEntropy;

		public bool UseMachineProtection => _UseMachineProtection;

		public override XmlNode Decrypt(XmlNode encryptedNode)
		{
			if (encryptedNode.NodeType != XmlNodeType.Element || encryptedNode.Name != "EncryptedData")
			{
				throw new ConfigurationErrorsException(SR.GetString("DPAPI_bad_data"));
			}
			XmlNode xmlNode = TraverseToChild(encryptedNode, "CipherData", onlyChild: false);
			if (xmlNode == null)
			{
				throw new ConfigurationErrorsException(SR.GetString("DPAPI_bad_data"));
			}
			XmlNode xmlNode2 = TraverseToChild(xmlNode, "CipherValue", onlyChild: true);
			if (xmlNode2 == null)
			{
				throw new ConfigurationErrorsException(SR.GetString("DPAPI_bad_data"));
			}
			string innerText = xmlNode2.InnerText;
			if (innerText == null)
			{
				throw new ConfigurationErrorsException(SR.GetString("DPAPI_bad_data"));
			}
			string xml = DecryptText(innerText);
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			xmlDocument.LoadXml(xml);
			return xmlDocument.DocumentElement;
		}

		public override XmlNode Encrypt(XmlNode node)
		{
			string outerXml = node.OuterXml;
			string text = EncryptText(outerXml);
			string text2 = "<EncryptedData><CipherData><CipherValue>";
			string text3 = "</CipherValue></CipherData></EncryptedData>";
			string xml = text2 + text + text3;
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			xmlDocument.LoadXml(xml);
			return xmlDocument.DocumentElement;
		}

		private string EncryptText(string clearText)
		{
			if (clearText == null || clearText.Length < 1)
			{
				return clearText;
			}
			SafeNativeMemoryHandle safeNativeMemoryHandle = new SafeNativeMemoryHandle();
			SafeNativeMemoryHandle safeNativeMemoryHandle2 = new SafeNativeMemoryHandle(useLocalFree: true);
			SafeNativeMemoryHandle safeNativeMemoryHandle3 = new SafeNativeMemoryHandle();
			DATA_BLOB inputData = default(DATA_BLOB);
			DATA_BLOB entropy = default(DATA_BLOB);
			DATA_BLOB outputData = default(DATA_BLOB);
			inputData.pbData = (entropy.pbData = (outputData.pbData = IntPtr.Zero));
			inputData.cbData = (entropy.cbData = (outputData.cbData = 0));
			try
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					inputData = PrepareDataBlob(clearText);
					safeNativeMemoryHandle.SetDataHandle(inputData.pbData);
					entropy = PrepareDataBlob(_KeyEntropy);
					safeNativeMemoryHandle3.SetDataHandle(entropy.pbData);
				}
				CRYPTPROTECT_PROMPTSTRUCT promptStruct = PreparePromptStructure();
				uint num = 1u;
				if (UseMachineProtection)
				{
					num |= 4u;
				}
				bool flag = false;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					flag = Microsoft.Win32.UnsafeNativeMethods.CryptProtectData(ref inputData, "", ref entropy, IntPtr.Zero, ref promptStruct, num, ref outputData);
					safeNativeMemoryHandle2.SetDataHandle(outputData.pbData);
				}
				if (!flag || outputData.pbData == IntPtr.Zero)
				{
					outputData.pbData = IntPtr.Zero;
					Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
				}
				byte[] array = new byte[outputData.cbData];
				Marshal.Copy(outputData.pbData, array, 0, array.Length);
				return Convert.ToBase64String(array);
			}
			finally
			{
				if (safeNativeMemoryHandle2 != null && !safeNativeMemoryHandle2.IsInvalid)
				{
					safeNativeMemoryHandle2.Dispose();
					outputData.pbData = IntPtr.Zero;
				}
				if (safeNativeMemoryHandle3 != null && !safeNativeMemoryHandle3.IsInvalid)
				{
					safeNativeMemoryHandle3.Dispose();
					entropy.pbData = IntPtr.Zero;
				}
				if (safeNativeMemoryHandle != null && !safeNativeMemoryHandle.IsInvalid)
				{
					safeNativeMemoryHandle.Dispose();
					inputData.pbData = IntPtr.Zero;
				}
			}
		}

		private string DecryptText(string encText)
		{
			if (encText == null || encText.Length < 1)
			{
				return encText;
			}
			SafeNativeMemoryHandle safeNativeMemoryHandle = new SafeNativeMemoryHandle();
			SafeNativeMemoryHandle safeNativeMemoryHandle2 = new SafeNativeMemoryHandle(useLocalFree: true);
			SafeNativeMemoryHandle safeNativeMemoryHandle3 = new SafeNativeMemoryHandle();
			DATA_BLOB inputData = default(DATA_BLOB);
			DATA_BLOB entropy = default(DATA_BLOB);
			DATA_BLOB outputData = default(DATA_BLOB);
			inputData.pbData = (entropy.pbData = (outputData.pbData = IntPtr.Zero));
			inputData.cbData = (entropy.cbData = (outputData.cbData = 0));
			try
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					inputData = PrepareDataBlob(Convert.FromBase64String(encText));
					safeNativeMemoryHandle.SetDataHandle(inputData.pbData);
					entropy = PrepareDataBlob(_KeyEntropy);
					safeNativeMemoryHandle3.SetDataHandle(entropy.pbData);
				}
				CRYPTPROTECT_PROMPTSTRUCT promptStruct = PreparePromptStructure();
				uint num = 1u;
				string description = "";
				if (UseMachineProtection)
				{
					num |= 4u;
				}
				bool flag = false;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
					flag = Microsoft.Win32.UnsafeNativeMethods.CryptUnprotectData(ref inputData, ref description, ref entropy, IntPtr.Zero, ref promptStruct, num, ref outputData);
					safeNativeMemoryHandle2.SetDataHandle(outputData.pbData);
				}
				if (!flag || outputData.pbData == IntPtr.Zero)
				{
					outputData.pbData = IntPtr.Zero;
					Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
				}
				byte[] array = new byte[outputData.cbData];
				Marshal.Copy(outputData.pbData, array, 0, array.Length);
				return Encoding.Unicode.GetString(array);
			}
			finally
			{
				if (safeNativeMemoryHandle2 != null && !safeNativeMemoryHandle2.IsInvalid)
				{
					safeNativeMemoryHandle2.Dispose();
					outputData.pbData = IntPtr.Zero;
				}
				if (safeNativeMemoryHandle3 != null && !safeNativeMemoryHandle3.IsInvalid)
				{
					safeNativeMemoryHandle3.Dispose();
					entropy.pbData = IntPtr.Zero;
				}
				if (safeNativeMemoryHandle != null && !safeNativeMemoryHandle.IsInvalid)
				{
					safeNativeMemoryHandle.Dispose();
					inputData.pbData = IntPtr.Zero;
				}
			}
		}

		public override void Initialize(string name, NameValueCollection configurationValues)
		{
			base.Initialize(name, configurationValues);
			_UseMachineProtection = GetBooleanValue(configurationValues, "useMachineProtection", defaultValue: true);
			_KeyEntropy = configurationValues["keyEntropy"];
			configurationValues.Remove("keyEntropy");
			if (configurationValues.Count > 0)
			{
				throw new ConfigurationErrorsException(SR.GetString("Unrecognized_initialization_value", configurationValues.GetKey(0)));
			}
		}

		private static XmlNode TraverseToChild(XmlNode node, string name, bool onlyChild)
		{
			foreach (XmlNode childNode in node.ChildNodes)
			{
				if (childNode.NodeType == XmlNodeType.Element)
				{
					if (childNode.Name == name)
					{
						return childNode;
					}
					if (onlyChild)
					{
						return null;
					}
				}
			}
			return null;
		}

		private static DATA_BLOB PrepareDataBlob(byte[] buf)
		{
			if (buf == null)
			{
				buf = new byte[0];
			}
			DATA_BLOB result = default(DATA_BLOB);
			result.cbData = buf.Length;
			result.pbData = Marshal.AllocHGlobal(result.cbData);
			Marshal.Copy(buf, 0, result.pbData, result.cbData);
			return result;
		}

		private static DATA_BLOB PrepareDataBlob(string s)
		{
			return PrepareDataBlob((s != null) ? Encoding.Unicode.GetBytes(s) : new byte[0]);
		}

		private static CRYPTPROTECT_PROMPTSTRUCT PreparePromptStructure()
		{
			CRYPTPROTECT_PROMPTSTRUCT result = default(CRYPTPROTECT_PROMPTSTRUCT);
			result.cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT));
			result.dwPromptFlags = 0;
			result.hwndApp = IntPtr.Zero;
			result.szPrompt = null;
			return result;
		}

		private static bool GetBooleanValue(NameValueCollection configurationValues, string valueName, bool defaultValue)
		{
			string text = configurationValues[valueName];
			if (text == null)
			{
				return defaultValue;
			}
			configurationValues.Remove(valueName);
			if (text == "true")
			{
				return true;
			}
			if (text == "false")
			{
				return false;
			}
			throw new ConfigurationErrorsException(SR.GetString("Config_invalid_boolean_attribute", valueName));
		}
	}
	public sealed class ElementInformation
	{
		private ConfigurationElement _thisElement;

		private PropertyInformationCollection _internalProperties;

		private ConfigurationException[] _errors;

		public PropertyInformationCollection Properties
		{
			get
			{
				if (_internalProperties == null)
				{
					_internalProperties = new PropertyInformationCollection(_thisElement);
				}
				return _internalProperties;
			}
		}

		public bool IsPresent => _thisElement.ElementPresent;

		public bool IsLocked
		{
			get
			{
				if ((_thisElement.ItemLocked & ConfigurationValueFlags.Locked) != 0)
				{
					return (_thisElement.ItemLocked & ConfigurationValueFlags.Inherited) != 0;
				}
				return false;
			}
		}

		public bool IsCollection
		{
			get
			{
				ConfigurationElementCollection configurationElementCollection = _thisElement as ConfigurationElementCollection;
				if (configurationElementCollection == null && _thisElement.Properties.DefaultCollectionProperty != null)
				{
					configurationElementCollection = _thisElement[_thisElement.Properties.DefaultCollectionProperty] as ConfigurationElementCollection;
				}
				return configurationElementCollection != null;
			}
		}

		public string Source => _thisElement.Values.GetSourceInfo(_thisElement.ElementTagName)?.FileName;

		public int LineNumber => _thisElement.Values.GetSourceInfo(_thisElement.ElementTagName)?.LineNumber ?? 0;

		public Type Type => _thisElement.GetType();

		public ConfigurationValidatorBase Validator => _thisElement.ElementProperty.Validator;

		public ICollection Errors
		{
			get
			{
				if (_errors == null)
				{
					_errors = GetReadOnlyErrorsList();
				}
				return _errors;
			}
		}

		internal ElementInformation(ConfigurationElement thisElement)
		{
			_thisElement = thisElement;
		}

		internal PropertySourceInfo PropertyInfoInternal()
		{
			return _thisElement.PropertyInfoInternal(_thisElement.ElementTagName);
		}

		internal void ChangeSourceAndLineNumber(PropertySourceInfo sourceInformation)
		{
			_thisElement.Values.ChangeSourceInfo(_thisElement.ElementTagName, sourceInformation);
		}

		private ConfigurationException[] GetReadOnlyErrorsList()
		{
			ArrayList errorsList = _thisElement.GetErrorsList();
			int count = errorsList.Count;
			ConfigurationException[] array = new ConfigurationException[errorsList.Count];
			if (count != 0)
			{
				errorsList.CopyTo(array, 0);
			}
			return array;
		}
	}
	internal class EmptyImpersonationContext : IDisposable
	{
		private static IDisposable s_emptyImpersonationContext;

		internal static IDisposable GetStaticInstance()
		{
			if (s_emptyImpersonationContext == null)
			{
				s_emptyImpersonationContext = new EmptyImpersonationContext();
			}
			return s_emptyImpersonationContext;
		}

		public void Dispose()
		{
		}
	}
	internal sealed class ErrorInfoXmlDocument : XmlDocument, IConfigErrorInfo
	{
		private XmlTextReader _reader;

		private int _lineOffset;

		private string _filename;

		int IConfigErrorInfo.LineNumber
		{
			get
			{
				if (_reader == null)
				{
					return 0;
				}
				if (_lineOffset > 0)
				{
					return _reader.LineNumber + _lineOffset - 1;
				}
				return _reader.LineNumber;
			}
		}

		internal int LineNumber => ((IConfigErrorInfo)this).LineNumber;

		string IConfigErrorInfo.Filename => _filename;

		public override void Load(string filename)
		{
			_filename = filename;
			try
			{
				_reader = new XmlTextReader(filename);
				_reader.XmlResolver = null;
				base.Load(_reader);
			}
			finally
			{
				if (_reader != null)
				{
					_reader.Close();
					_reader = null;
				}
			}
		}

		private void LoadFromConfigXmlReader(ConfigXmlReader reader)
		{
			_filename = ((IConfigErrorInfo)reader).Filename;
			_lineOffset = ((IConfigErrorInfo)reader).LineNumber + 1;
			try
			{
				_reader = reader;
				base.Load(_reader);
			}
			finally
			{
				if (_reader != null)
				{
					_reader.Close();
					_reader = null;
				}
			}
		}

		internal static XmlNode CreateSectionXmlNode(ConfigXmlReader reader)
		{
			ErrorInfoXmlDocument errorInfoXmlDocument = new ErrorInfoXmlDocument();
			errorInfoXmlDocument.LoadFromConfigXmlReader(reader);
			return errorInfoXmlDocument.DocumentElement;
		}

		public override XmlAttribute CreateAttribute(string prefix, string localName, string namespaceUri)
		{
			return new ConfigXmlAttribute(_filename, LineNumber, prefix, localName, namespaceUri, this);
		}

		public override XmlElement CreateElement(string prefix, string localName, string namespaceUri)
		{
			return new ConfigXmlElement(_filename, LineNumber, prefix, localName, namespaceUri, this);
		}

		public override XmlText CreateTextNode(string text)
		{
			return new ConfigXmlText(_filename, LineNumber, text, this);
		}

		public override XmlCDataSection CreateCDataSection(string data)
		{
			return new ConfigXmlCDataSection(_filename, LineNumber, data, this);
		}

		public override XmlComment CreateComment(string data)
		{
			return new ConfigXmlComment(_filename, LineNumber, data, this);
		}

		public override XmlSignificantWhitespace CreateSignificantWhitespace(string data)
		{
			return new ConfigXmlSignificantWhitespace(_filename, LineNumber, data, this);
		}

		public override XmlWhitespace CreateWhitespace(string data)
		{
			return new ConfigXmlWhitespace(_filename, LineNumber, data, this);
		}
	}
	internal static class ErrorsHelper
	{
		internal static int GetErrorCount(List<ConfigurationException> errors)
		{
			return errors?.Count ?? 0;
		}

		internal static bool GetHasErrors(List<ConfigurationException> errors)
		{
			return GetErrorCount(errors) > 0;
		}

		internal static void AddError(ref List<ConfigurationException> errors, ConfigurationException e)
		{
			if (errors == null)
			{
				errors = new List<ConfigurationException>();
			}
			if (!(e is ConfigurationErrorsException ex))
			{
				errors.Add(e);
				return;
			}
			ICollection<ConfigurationException> errorsGeneric = ex.ErrorsGeneric;
			if (errorsGeneric.Count == 1)
			{
				errors.Add(e);
			}
			else
			{
				errors.AddRange(errorsGeneric);
			}
		}

		internal static void AddErrors(ref List<ConfigurationException> errors, ICollection<ConfigurationException> coll)
		{
			if (coll == null || coll.Count == 0)
			{
				return;
			}
			foreach (ConfigurationException item in coll)
			{
				AddError(ref errors, item);
			}
		}

		internal static ConfigurationErrorsException GetErrorsException(List<ConfigurationException> errors)
		{
			if (errors == null)
			{
				return null;
			}
			return new ConfigurationErrorsException(errors);
		}

		internal static void ThrowOnErrors(List<ConfigurationException> errors)
		{
			ConfigurationErrorsException errorsException = GetErrorsException(errors);
			if (errorsException != null)
			{
				throw errorsException;
			}
		}
	}
	internal enum ExceptionAction
	{
		NonSpecific,
		Local,
		Global
	}
	internal static class ExceptionUtil
	{
		internal static string NoExceptionInformation => SR.GetString("No_exception_information_available");

		internal static ArgumentException ParameterInvalid(string parameter)
		{
			return new ArgumentException(SR.GetString("Parameter_Invalid", parameter), parameter);
		}

		internal static ArgumentException ParameterNullOrEmpty(string parameter)
		{
			return new ArgumentException(SR.GetString("Parameter_NullOrEmpty", parameter), parameter);
		}

		internal static ArgumentException PropertyInvalid(string property)
		{
			return new ArgumentException(SR.GetString("Property_Invalid", property), property);
		}

		internal static ArgumentException PropertyNullOrEmpty(string property)
		{
			return new ArgumentException(SR.GetString("Property_NullOrEmpty", property), property);
		}

		internal static InvalidOperationException UnexpectedError(string methodName)
		{
			return new InvalidOperationException(SR.GetString("Unexpected_Error", methodName));
		}

		internal static ConfigurationErrorsException WrapAsConfigException(string outerMessage, Exception e, IConfigErrorInfo errorInfo)
		{
			if (errorInfo != null)
			{
				return WrapAsConfigException(outerMessage, e, errorInfo.Filename, errorInfo.LineNumber);
			}
			return WrapAsConfigException(outerMessage, e, null, 0);
		}

		internal static ConfigurationErrorsException WrapAsConfigException(string outerMessage, Exception e, string filename, int line)
		{
			if (e is ConfigurationErrorsException result)
			{
				return result;
			}
			if (e is ConfigurationException e2)
			{
				return new ConfigurationErrorsException(e2);
			}
			if (e is XmlException ex)
			{
				if (ex.LineNumber != 0)
				{
					line = ex.LineNumber;
				}
				return new ConfigurationErrorsException(ex.Message, ex, filename, line);
			}
			if (e != null)
			{
				return new ConfigurationErrorsException(SR.GetString("Wrapped_exception_message", outerMessage, e.Message), e, filename, line);
			}
			return new ConfigurationErrorsException(SR.GetString("Wrapped_exception_message", outerMessage, NoExceptionInformation), filename, line);
		}
	}
	public sealed class ExeConfigurationFileMap : ConfigurationFileMap
	{
		private string _exeConfigFilename;

		private string _roamingUserConfigFilename;

		private string _localUserConfigFilename;

		public string ExeConfigFilename
		{
			get
			{
				return _exeConfigFilename;
			}
			set
			{
				_exeConfigFilename = value;
			}
		}

		public string RoamingUserConfigFilename
		{
			get
			{
				return _roamingUserConfigFilename;
			}
			set
			{
				_roamingUserConfigFilename = value;
			}
		}

		public string LocalUserConfigFilename
		{
			get
			{
				return _localUserConfigFilename;
			}
			set
			{
				_localUserConfigFilename = value;
			}
		}

		public ExeConfigurationFileMap()
		{
			_exeConfigFilename = string.Empty;
			_roamingUserConfigFilename = string.Empty;
			_localUserConfigFilename = string.Empty;
		}

		private ExeConfigurationFileMap(string machineConfigFilename, string exeConfigFilename, string roamingUserConfigFilename, string localUserConfigFilename)
			: base(machineConfigFilename)
		{
			_exeConfigFilename = exeConfigFilename;
			_roamingUserConfigFilename = roamingUserConfigFilename;
			_localUserConfigFilename = localUserConfigFilename;
		}

		public override object Clone()
		{
			return new ExeConfigurationFileMap(base.MachineConfigFilename, _exeConfigFilename, _roamingUserConfigFilename, _localUserConfigFilename);
		}
	}
	public sealed class ExeContext
	{
		private ConfigurationUserLevel _userContext;

		private string _exePath;

		public ConfigurationUserLevel UserLevel => _userContext;

		public string ExePath => _exePath;

		internal ExeContext(ConfigurationUserLevel userContext, string exePath)
		{
			_userContext = userContext;
			_exePath = exePath;
		}
	}
	[DebuggerDisplay("FactoryId {ConfigKey}")]
	internal class FactoryId
	{
		private string _configKey;

		private string _group;

		private string _name;

		internal string ConfigKey => _configKey;

		internal string Group => _group;

		internal string Name => _name;

		internal FactoryId(string configKey, string group, string name)
		{
			_configKey = configKey;
			_group = group;
			_name = name;
		}
	}
	[DebuggerDisplay("FactoryRecord {ConfigKey}")]
	internal class FactoryRecord : IConfigErrorInfo
	{
		private const int Flag_AllowLocation = 1;

		private const int Flag_RestartOnExternalChanges = 2;

		private const int Flag_RequirePermission = 4;

		private const int Flag_IsGroup = 8;

		private const int Flag_IsFromTrustedConfigRecord = 16;

		private const int Flag_IsFactoryTrustedWithoutAptca = 32;

		private const int Flag_IsUndeclared = 64;

		private string _configKey;

		private string _group;

		private string _name;

		private SimpleBitVector32 _flags;

		private string _factoryTypeName;

		private ConfigurationAllowDefinition _allowDefinition;

		private ConfigurationAllowExeDefinition _allowExeDefinition;

		private OverrideModeSetting _overrideModeDefault;

		private string _filename;

		private int _lineNumber;

		private object _factory;

		private List<ConfigurationException> _errors;

		internal string ConfigKey => _configKey;

		internal string Group => _group;

		internal string Name => _name;

		internal object Factory
		{
			get
			{
				return _factory;
			}
			set
			{
				_factory = value;
			}
		}

		internal string FactoryTypeName
		{
			get
			{
				return _factoryTypeName;
			}
			set
			{
				_factoryTypeName = value;
			}
		}

		internal ConfigurationAllowDefinition AllowDefinition
		{
			get
			{
				return _allowDefinition;
			}
			set
			{
				_allowDefinition = value;
			}
		}

		internal ConfigurationAllowExeDefinition AllowExeDefinition
		{
			get
			{
				return _allowExeDefinition;
			}
			set
			{
				_allowExeDefinition = value;
			}
		}

		internal OverrideModeSetting OverrideModeDefault => _overrideModeDefault;

		internal bool AllowLocation
		{
			get
			{
				return _flags[1];
			}
			set
			{
				_flags[1] = value;
			}
		}

		internal bool RestartOnExternalChanges
		{
			get
			{
				return _flags[2];
			}
			set
			{
				_flags[2] = value;
			}
		}

		internal bool RequirePermission
		{
			get
			{
				return _flags[4];
			}
			set
			{
				_flags[4] = value;
			}
		}

		internal bool IsGroup
		{
			get
			{
				return _flags[8];
			}
			set
			{
				_flags[8] = value;
			}
		}

		internal bool IsFromTrustedConfigRecord
		{
			get
			{
				return _flags[16];
			}
			set
			{
				_flags[16] = value;
			}
		}

		internal bool IsUndeclared
		{
			get
			{
				return _flags[64];
			}
			set
			{
				_flags[64] = value;
			}
		}

		internal bool IsFactoryTrustedWithoutAptca
		{
			get
			{
				return _flags[32];
			}
			set
			{
				_flags[32] = value;
			}
		}

		public string Filename
		{
			get
			{
				return _filename;
			}
			set
			{
				_filename = value;
			}
		}

		public int LineNumber
		{
			get
			{
				return _lineNumber;
			}
			set
			{
				_lineNumber = value;
			}
		}

		internal bool HasFile => _lineNumber >= 0;

		internal List<ConfigurationException> Errors => _errors;

		internal bool HasErrors => ErrorsHelper.GetHasErrors(_errors);

		private FactoryRecord(string configKey, string group, string name, object factory, string factoryTypeName, SimpleBitVector32 flags, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition, OverrideModeSetting overrideModeDefault, string filename, int lineNumber, ICollection<ConfigurationException> errors)
		{
			_configKey = configKey;
			_group = group;
			_name = name;
			_factory = factory;
			_factoryTypeName = factoryTypeName;
			_flags = flags;
			_allowDefinition = allowDefinition;
			_allowExeDefinition = allowExeDefinition;
			_overrideModeDefault = overrideModeDefault;
			_filename = filename;
			_lineNumber = lineNumber;
			AddErrors(errors);
		}

		internal FactoryRecord(string configKey, string group, string name, string factoryTypeName, string filename, int lineNumber)
		{
			_configKey = configKey;
			_group = group;
			_name = name;
			_factoryTypeName = factoryTypeName;
			IsGroup = true;
			_filename = filename;
			_lineNumber = lineNumber;
		}

		internal FactoryRecord(string configKey, string group, string name, string factoryTypeName, bool allowLocation, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition, OverrideModeSetting overrideModeDefault, bool restartOnExternalChanges, bool requirePermission, bool isFromTrustedConfigRecord, bool isUndeclared, string filename, int lineNumber)
		{
			_configKey = configKey;
			_group = group;
			_name = name;
			_factoryTypeName = factoryTypeName;
			_allowDefinition = allowDefinition;
			_allowExeDefinition = allowExeDefinition;
			_overrideModeDefault = overrideModeDefault;
			AllowLocation = allowLocation;
			RestartOnExternalChanges = restartOnExternalChanges;
			RequirePermission = requirePermission;
			IsFromTrustedConfigRecord = isFromTrustedConfigRecord;
			IsUndeclared = isUndeclared;
			_filename = filename;
			_lineNumber = lineNumber;
		}

		internal FactoryRecord CloneSection(string filename, int lineNumber)
		{
			return new FactoryRecord(_configKey, _group, _name, _factory, _factoryTypeName, _flags, _allowDefinition, _allowExeDefinition, _overrideModeDefault, filename, lineNumber, Errors);
		}

		internal FactoryRecord CloneSectionGroup(string factoryTypeName, string filename, int lineNumber)
		{
			if (_factoryTypeName != null)
			{
				factoryTypeName = _factoryTypeName;
			}
			return new FactoryRecord(_configKey, _group, _name, _factory, factoryTypeName, _flags, _allowDefinition, _allowExeDefinition, _overrideModeDefault, filename, lineNumber, Errors);
		}

		internal bool IsEquivalentType(IInternalConfigHost host, string typeName)
		{
			try
			{
				if (_factoryTypeName == typeName)
				{
					return true;
				}
				Type typeWithReflectionPermission;
				Type typeWithReflectionPermission2;
				if (host != null)
				{
					typeWithReflectionPermission = TypeUtil.GetTypeWithReflectionPermission(host, typeName, throwOnError: false);
					typeWithReflectionPermission2 = TypeUtil.GetTypeWithReflectionPermission(host, _factoryTypeName, throwOnError: false);
				}
				else
				{
					typeWithReflectionPermission = TypeUtil.GetTypeWithReflectionPermission(typeName, throwOnError: false);
					typeWithReflectionPermission2 = TypeUtil.GetTypeWithReflectionPermission(_factoryTypeName, throwOnError: false);
				}
				return typeWithReflectionPermission != null && typeWithReflectionPermission == typeWithReflectionPermission2;
			}
			catch
			{
			}
			return false;
		}

		internal bool IsEquivalentSectionGroupFactory(IInternalConfigHost host, string typeName)
		{
			if (typeName == null || _factoryTypeName == null)
			{
				return true;
			}
			return IsEquivalentType(host, typeName);
		}

		internal bool IsEquivalentSectionFactory(IInternalConfigHost host, string typeName, bool allowLocation, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition, bool restartOnExternalChanges, bool requirePermission)
		{
			if (allowLocation != AllowLocation || allowDefinition != AllowDefinition || allowExeDefinition != AllowExeDefinition || restartOnExternalChanges != RestartOnExternalChanges || requirePermission != RequirePermission)
			{
				return false;
			}
			return IsEquivalentType(host, typeName);
		}

		internal void AddErrors(ICollection<ConfigurationException> coll)
		{
			ErrorsHelper.AddErrors(ref _errors, coll);
		}

		internal void ThrowOnErrors()
		{
			ErrorsHelper.ThrowOnErrors(_errors);
		}

		internal bool IsIgnorable()
		{
			if (_factory != null)
			{
				return _factory is IgnoreSectionHandler;
			}
			if (_factoryTypeName != null)
			{
				return _factoryTypeName.Contains("System.Configuration.IgnoreSection");
			}
			return false;
		}
	}
	internal static class FileUtil
	{
		private const int HRESULT_WIN32_FILE_NOT_FOUND = -2147024894;

		private const int HRESULT_WIN32_PATH_NOT_FOUND = -2147024893;

		internal static bool FileExists(string filename, bool trueOnError)
		{
			if (Microsoft.Win32.UnsafeNativeMethods.GetFileAttributesEx(filename, 0, out var data))
			{
				return (data.fileAttributes & 0x10) != 16;
			}
			if (!trueOnError)
			{
				return false;
			}
			int hRForLastWin32Error = Marshal.GetHRForLastWin32Error();
			if (hRForLastWin32Error == -2147024894 || hRForLastWin32Error == -2147024893)
			{
				return false;
			}
			return true;
		}
	}
	public sealed class GenericEnumConverter : ConfigurationConverterBase
	{
		private Type _enumType;

		public GenericEnumConverter(Type typeEnum)
		{
			if (typeEnum == null)
			{
				throw new ArgumentNullException("typeEnum");
			}
			_enumType = typeEnum;
		}

		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			return value.ToString();
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			object obj = null;
			try
			{
				string text = (string)data;
				if (string.IsNullOrEmpty(text))
				{
					throw new Exception();
				}
				if (!string.IsNullOrEmpty(text) && (char.IsDigit(text[0]) || text[0] == '-' || text[0] == '+'))
				{
					throw new Exception();
				}
				if (text != text.Trim())
				{
					throw new Exception();
				}
				return Enum.Parse(_enumType, text);
			}
			catch
			{
				StringBuilder stringBuilder = new StringBuilder();
				string[] names = Enum.GetNames(_enumType);
				foreach (string value in names)
				{
					if (stringBuilder.Length != 0)
					{
						stringBuilder.Append(", ");
					}
					stringBuilder.Append(value);
				}
				throw new ArgumentException(SR.GetString("Invalid_enum_value", stringBuilder.ToString()));
			}
		}
	}
	public sealed class IgnoreSection : ConfigurationSection
	{
		private static ConfigurationPropertyCollection s_properties;

		private string _rawXml = string.Empty;

		private bool _isModified;

		protected internal override ConfigurationPropertyCollection Properties => EnsureStaticPropertyBag();

		private static ConfigurationPropertyCollection EnsureStaticPropertyBag()
		{
			if (s_properties == null)
			{
				ConfigurationPropertyCollection configurationPropertyCollection = (s_properties = new ConfigurationPropertyCollection());
			}
			return s_properties;
		}

		public IgnoreSection()
		{
			EnsureStaticPropertyBag();
		}

		protected internal override bool IsModified()
		{
			return _isModified;
		}

		protected internal override void ResetModified()
		{
			_isModified = false;
		}

		protected internal override void Reset(ConfigurationElement parentSection)
		{
			_rawXml = string.Empty;
			_isModified = false;
		}

		protected internal override void DeserializeSection(XmlReader xmlReader)
		{
			if (!xmlReader.Read() || xmlReader.NodeType != XmlNodeType.Element)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_expected_to_find_element"), xmlReader);
			}
			_rawXml = xmlReader.ReadOuterXml();
			_isModified = true;
		}

		protected internal override string SerializeSection(ConfigurationElement parentSection, string name, ConfigurationSaveMode saveMode)
		{
			return _rawXml;
		}
	}
	public sealed class InfiniteIntConverter : ConfigurationConverterBase
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(int));
			if ((int)value == int.MaxValue)
			{
				return "Infinite";
			}
			return ((int)value).ToString(CultureInfo.InvariantCulture);
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			if ((string)data == "Infinite")
			{
				return int.MaxValue;
			}
			return Convert.ToInt32((string)data, 10);
		}
	}
	public sealed class InfiniteTimeSpanConverter : ConfigurationConverterBase
	{
		private static readonly TypeConverter s_TimeSpanConverter = TypeDescriptor.GetConverter(typeof(TimeSpan));

		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(TimeSpan));
			if ((TimeSpan)value == TimeSpan.MaxValue)
			{
				return "Infinite";
			}
			return s_TimeSpanConverter.ConvertToInvariantString(value);
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			if ((string)data == "Infinite")
			{
				return TimeSpan.MaxValue;
			}
			return s_TimeSpanConverter.ConvertFromInvariantString((string)data);
		}
	}
	public class IntegerValidator : ConfigurationValidatorBase
	{
		private enum ValidationFlags
		{
			None,
			ExclusiveRange
		}

		private ValidationFlags _flags;

		private int _minValue = int.MinValue;

		private int _maxValue = int.MaxValue;

		private int _resolution = 1;

		public IntegerValidator(int minValue, int maxValue)
			: this(minValue, maxValue, rangeIsExclusive: false, 1)
		{
		}

		public IntegerValidator(int minValue, int maxValue, bool rangeIsExclusive)
			: this(minValue, maxValue, rangeIsExclusive, 1)
		{
		}

		public IntegerValidator(int minValue, int maxValue, bool rangeIsExclusive, int resolution)
		{
			if (resolution <= 0)
			{
				throw new ArgumentOutOfRangeException("resolution");
			}
			if (minValue > maxValue)
			{
				throw new ArgumentOutOfRangeException("minValue", SR.GetString("Validator_min_greater_than_max"));
			}
			_minValue = minValue;
			_maxValue = maxValue;
			_resolution = resolution;
			_flags = (rangeIsExclusive ? ValidationFlags.ExclusiveRange : ValidationFlags.None);
		}

		public override bool CanValidate(Type type)
		{
			return type == typeof(int);
		}

		public override void Validate(object value)
		{
			ValidatorUtils.HelperParamValidation(value, typeof(int));
			ValidatorUtils.ValidateScalar((int)value, _minValue, _maxValue, _resolution, _flags == ValidationFlags.ExclusiveRange);
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class IntegerValidatorAttribute : ConfigurationValidatorAttribute
	{
		private int _min = int.MinValue;

		private int _max = int.MaxValue;

		private bool _excludeRange;

		public override ConfigurationValidatorBase ValidatorInstance => new IntegerValidator(_min, _max, _excludeRange);

		public int MinValue
		{
			get
			{
				return _min;
			}
			set
			{
				if (_max < value)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_min = value;
			}
		}

		public int MaxValue
		{
			get
			{
				return _max;
			}
			set
			{
				if (_min > value)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_max = value;
			}
		}

		public bool ExcludeRange
		{
			get
			{
				return _excludeRange;
			}
			set
			{
				_excludeRange = value;
			}
		}
	}
	internal sealed class InvalidPropValue
	{
		private string _value;

		private ConfigurationException _error;

		internal ConfigurationException Error => _error;

		internal string Value => _value;

		internal InvalidPropValue(string value, ConfigurationException error)
		{
			_value = value;
			_error = error;
		}
	}
	[ConfigurationCollection(typeof(KeyValueConfigurationElement))]
	public class KeyValueConfigurationCollection : ConfigurationElementCollection
	{
		private static ConfigurationPropertyCollection _properties;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		protected override bool ThrowOnDuplicate => false;

		public new KeyValueConfigurationElement this[string key] => (KeyValueConfigurationElement)BaseGet(key);

		public string[] AllKeys => StringUtil.ObjectArrayToStringArray(BaseGetAllKeys());

		static KeyValueConfigurationCollection()
		{
			_properties = new ConfigurationPropertyCollection();
		}

		public KeyValueConfigurationCollection()
			: base(StringComparer.OrdinalIgnoreCase)
		{
			internalAddToEnd = true;
		}

		public void Add(KeyValueConfigurationElement keyValue)
		{
			keyValue.Init();
			KeyValueConfigurationElement keyValueConfigurationElement = (KeyValueConfigurationElement)BaseGet(keyValue.Key);
			if (keyValueConfigurationElement == null)
			{
				BaseAdd(keyValue);
				return;
			}
			keyValueConfigurationElement.Value = keyValueConfigurationElement.Value + "," + keyValue.Value;
			int index = BaseIndexOf(keyValueConfigurationElement);
			BaseRemoveAt(index);
			BaseAdd(index, keyValueConfigurationElement);
		}

		public void Add(string key, string value)
		{
			KeyValueConfigurationElement keyValue = new KeyValueConfigurationElement(key, value);
			Add(keyValue);
		}

		public void Remove(string key)
		{
			BaseRemove(key);
		}

		public void Clear()
		{
			BaseClear();
		}

		protected override ConfigurationElement CreateNewElement()
		{
			return new KeyValueConfigurationElement();
		}

		protected override object GetElementKey(ConfigurationElement element)
		{
			return ((KeyValueConfigurationElement)element).Key;
		}
	}
	public class KeyValueConfigurationElement : ConfigurationElement
	{
		private static ConfigurationPropertyCollection _properties;

		private static readonly ConfigurationProperty _propKey;

		private static readonly ConfigurationProperty _propValue;

		private bool _needsInit;

		private string _initKey;

		private string _initValue;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		[ConfigurationProperty("key", Options = ConfigurationPropertyOptions.IsKey, DefaultValue = "")]
		public string Key => (string)base[_propKey];

		[ConfigurationProperty("value", DefaultValue = "")]
		public string Value
		{
			get
			{
				return (string)base[_propValue];
			}
			set
			{
				base[_propValue] = value;
			}
		}

		static KeyValueConfigurationElement()
		{
			_propKey = new ConfigurationProperty("key", typeof(string), string.Empty, ConfigurationPropertyOptions.IsRequired | ConfigurationPropertyOptions.IsKey);
			_propValue = new ConfigurationProperty("value", typeof(string), string.Empty, ConfigurationPropertyOptions.None);
			_properties = new ConfigurationPropertyCollection();
			_properties.Add(_propKey);
			_properties.Add(_propValue);
		}

		internal KeyValueConfigurationElement()
		{
		}

		public KeyValueConfigurationElement(string key, string value)
		{
			_needsInit = true;
			_initKey = key;
			_initValue = value;
		}

		protected internal override void Init()
		{
			base.Init();
			if (_needsInit)
			{
				_needsInit = false;
				base[_propKey] = _initKey;
				Value = _initValue;
			}
		}
	}
	internal class KeyValueInternalCollection : NameValueCollection
	{
		private AppSettingsSection _root;

		public KeyValueInternalCollection(AppSettingsSection root)
		{
			_root = root;
			foreach (KeyValueConfigurationElement setting in _root.Settings)
			{
				base.Add(setting.Key, setting.Value);
			}
		}

		public override void Add(string key, string value)
		{
			_root.Settings.Add(new KeyValueConfigurationElement(key, value));
			base.Add(key, value);
		}

		public override void Clear()
		{
			_root.Settings.Clear();
			base.Clear();
		}

		public override void Remove(string key)
		{
			_root.Settings.Remove(key);
			base.Remove(key);
		}
	}
	[DebuggerDisplay("LocationSectionRecord {ConfigKey}")]
	internal class LocationSectionRecord
	{
		private SectionXmlInfo _sectionXmlInfo;

		private List<ConfigurationException> _errors;

		internal string ConfigKey => _sectionXmlInfo.ConfigKey;

		internal SectionXmlInfo SectionXmlInfo => _sectionXmlInfo;

		internal ICollection<ConfigurationException> Errors => _errors;

		internal List<ConfigurationException> ErrorsList => _errors;

		internal bool HasErrors => ErrorsHelper.GetHasErrors(_errors);

		internal LocationSectionRecord(SectionXmlInfo sectionXmlInfo, List<ConfigurationException> errors)
		{
			_sectionXmlInfo = sectionXmlInfo;
			_errors = errors;
		}

		internal void AddError(ConfigurationException e)
		{
			ErrorsHelper.AddError(ref _errors, e);
		}
	}
	internal class LocationUpdates
	{
		private OverrideModeSetting _overrideMode;

		private bool _inheritInChildApps;

		private SectionUpdates _sectionUpdates;

		internal OverrideModeSetting OverrideMode => _overrideMode;

		internal bool InheritInChildApps => _inheritInChildApps;

		internal SectionUpdates SectionUpdates => _sectionUpdates;

		internal bool IsDefault
		{
			get
			{
				if (_overrideMode.IsDefaultForLocationTag)
				{
					return _inheritInChildApps;
				}
				return false;
			}
		}

		internal LocationUpdates(OverrideModeSetting overrideMode, bool inheritInChildApps)
		{
			_overrideMode = overrideMode;
			_inheritInChildApps = inheritInChildApps;
			_sectionUpdates = new SectionUpdates(string.Empty);
		}

		internal void CompleteUpdates()
		{
			_sectionUpdates.CompleteUpdates();
		}
	}
	public class LongValidator : ConfigurationValidatorBase
	{
		private enum ValidationFlags
		{
			None,
			ExclusiveRange
		}

		private ValidationFlags _flags;

		private long _minValue = long.MinValue;

		private long _maxValue = long.MaxValue;

		private long _resolution = 1L;

		public LongValidator(long minValue, long maxValue)
			: this(minValue, maxValue, rangeIsExclusive: false, 1L)
		{
		}

		public LongValidator(long minValue, long maxValue, bool rangeIsExclusive)
			: this(minValue, maxValue, rangeIsExclusive, 1L)
		{
		}

		public LongValidator(long minValue, long maxValue, bool rangeIsExclusive, long resolution)
		{
			if (resolution <= 0)
			{
				throw new ArgumentOutOfRangeException("resolution");
			}
			if (minValue > maxValue)
			{
				throw new ArgumentOutOfRangeException("minValue", SR.GetString("Validator_min_greater_than_max"));
			}
			_minValue = minValue;
			_maxValue = maxValue;
			_resolution = resolution;
			_flags = (rangeIsExclusive ? ValidationFlags.ExclusiveRange : ValidationFlags.None);
		}

		public override bool CanValidate(Type type)
		{
			return type == typeof(long);
		}

		public override void Validate(object value)
		{
			ValidatorUtils.HelperParamValidation(value, typeof(long));
			ValidatorUtils.ValidateScalar((long)value, _minValue, _maxValue, _resolution, _flags == ValidationFlags.ExclusiveRange);
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class LongValidatorAttribute : ConfigurationValidatorAttribute
	{
		private long _min = long.MinValue;

		private long _max = long.MaxValue;

		private bool _excludeRange;

		public override ConfigurationValidatorBase ValidatorInstance => new LongValidator(_min, _max, _excludeRange);

		public long MinValue
		{
			get
			{
				return _min;
			}
			set
			{
				if (_max < value)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_min = value;
			}
		}

		public long MaxValue
		{
			get
			{
				return _max;
			}
			set
			{
				if (_min > value)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_max = value;
			}
		}

		public bool ExcludeRange
		{
			get
			{
				return _excludeRange;
			}
			set
			{
				_excludeRange = value;
			}
		}
	}
	internal sealed class MgmtConfigurationRecord : BaseConfigurationRecord
	{
		private const int DEFAULT_INDENT = 4;

		private const int MAX_INDENT = 10;

		private Hashtable _sectionGroups;

		private Hashtable _sectionFactories;

		private Hashtable _sectionGroupFactories;

		private Hashtable _removedSections;

		private Hashtable _removedSectionGroups;

		private Hashtable _locationTags;

		private HybridDictionary _streamInfoUpdates;

		private static readonly SimpleBitVector32 MgmtClassFlags = new SimpleBitVector32(80);

		private MgmtConfigurationRecord MgmtParent => (MgmtConfigurationRecord)_parent;

		private UpdateConfigHost UpdateConfigHost => (UpdateConfigHost)base.Host;

		protected override SimpleBitVector32 ClassFlags => MgmtClassFlags;

		private Hashtable SectionGroups
		{
			get
			{
				if (_sectionGroups == null)
				{
					_sectionGroups = new Hashtable();
				}
				return _sectionGroups;
			}
		}

		private Hashtable RemovedSections
		{
			get
			{
				if (_removedSections == null)
				{
					_removedSections = new Hashtable();
				}
				return _removedSections;
			}
		}

		private Hashtable RemovedSectionGroups
		{
			get
			{
				if (_removedSectionGroups == null)
				{
					_removedSectionGroups = new Hashtable();
				}
				return _removedSectionGroups;
			}
		}

		internal Hashtable SectionFactories
		{
			get
			{
				if (_sectionFactories == null)
				{
					_sectionFactories = GetAllFactories(isGroup: false);
				}
				return _sectionFactories;
			}
		}

		internal Hashtable SectionGroupFactories
		{
			get
			{
				if (_sectionGroupFactories == null)
				{
					_sectionGroupFactories = GetAllFactories(isGroup: true);
				}
				return _sectionGroupFactories;
			}
		}

		internal string ConfigurationFilePath
		{
			get
			{
				string text = UpdateConfigHost.GetNewStreamname(base.ConfigStreamInfo.StreamName);
				if (text == null)
				{
					text = string.Empty;
				}
				if (!string.IsNullOrEmpty(text))
				{
					new FileIOPermission(FileIOPermissionAccess.PathDiscovery, text).Demand();
				}
				return text;
			}
		}

		private bool HasRemovedSectionsOrGroups
		{
			get
			{
				if (_removedSections == null || _removedSections.Count <= 0)
				{
					if (_removedSectionGroups != null)
					{
						return _removedSectionGroups.Count > 0;
					}
					return false;
				}
				return true;
			}
		}

		private bool HasRemovedSections
		{
			get
			{
				if (_removedSections != null)
				{
					return _removedSections.Count > 0;
				}
				return false;
			}
		}

		internal bool NamespacePresent
		{
			get
			{
				return _flags[67108864];
			}
			set
			{
				_flags[67108864] = value;
			}
		}

		private NamespaceChange NamespaceChangeNeeded
		{
			get
			{
				if (_flags[67108864] == _flags[512])
				{
					return NamespaceChange.None;
				}
				if (_flags[67108864])
				{
					return NamespaceChange.Add;
				}
				return NamespaceChange.Remove;
			}
		}

		private bool RecordItselfRequiresUpdates => NamespaceChangeNeeded != NamespaceChange.None;

		internal static MgmtConfigurationRecord Create(IInternalConfigRoot configRoot, IInternalConfigRecord parent, string configPath, string locationSubPath)
		{
			MgmtConfigurationRecord mgmtConfigurationRecord = new MgmtConfigurationRecord();
			mgmtConfigurationRecord.Init(configRoot, parent, configPath, locationSubPath);
			return mgmtConfigurationRecord;
		}

		private MgmtConfigurationRecord()
		{
		}

		private void Init(IInternalConfigRoot configRoot, IInternalConfigRecord parent, string configPath, string locationSubPath)
		{
			base.Init(configRoot, (BaseConfigurationRecord)parent, configPath, locationSubPath);
			if (base.IsLocationConfig && (MgmtParent._locationTags == null || !MgmtParent._locationTags.Contains(_locationSubPath)))
			{
				_flags[16777216] = true;
			}
			InitStreamInfoUpdates();
		}

		private void InitStreamInfoUpdates()
		{
			_streamInfoUpdates = new HybridDictionary(caseInsensitive: true);
			if (!base.ConfigStreamInfo.HasStreamInfos)
			{
				return;
			}
			foreach (StreamInfo value in base.ConfigStreamInfo.StreamInfos.Values)
			{
				_streamInfoUpdates.Add(value.StreamName, value.Clone());
			}
		}

		protected override object CreateSectionFactory(FactoryRecord factoryRecord)
		{
			Type type = TypeUtil.GetTypeWithReflectionPermission(base.Host, factoryRecord.FactoryTypeName, throwOnError: true);
			if (!typeof(ConfigurationSection).IsAssignableFrom(type))
			{
				TypeUtil.VerifyAssignableType(typeof(IConfigurationSectionHandler), type, throwOnError: true);
				type = typeof(DefaultSection);
			}
			return TypeUtil.GetConstructorWithReflectionPermission(type, typeof(ConfigurationSection), throwOnError: true);
		}

		protected override object CreateSection(bool inputIsTrusted, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader)
		{
			ConstructorInfo ctor = (ConstructorInfo)factoryRecord.Factory;
			ConfigurationSection configurationSection = (ConfigurationSection)TypeUtil.InvokeCtorWithReflectionPermission(ctor);
			configurationSection.SectionInformation.AttachToConfigurationRecord(this, factoryRecord, sectionRecord);
			configurationSection.CallInit();
			ConfigurationSection parentElement = (ConfigurationSection)parentConfig;
			configurationSection.Reset(parentElement);
			if (reader != null)
			{
				configurationSection.DeserializeSection(reader);
			}
			configurationSection.ResetModified();
			return configurationSection;
		}

		private ConstructorInfo CreateSectionGroupFactory(FactoryRecord factoryRecord)
		{
			Type type = ((!string.IsNullOrEmpty(factoryRecord.FactoryTypeName)) ? TypeUtil.GetTypeWithReflectionPermission(base.Host, factoryRecord.FactoryTypeName, throwOnError: true) : typeof(ConfigurationSectionGroup));
			return TypeUtil.GetConstructorWithReflectionPermission(type, typeof(ConfigurationSectionGroup), throwOnError: true);
		}

		private ConstructorInfo EnsureSectionGroupFactory(FactoryRecord factoryRecord)
		{
			ConstructorInfo constructorInfo = (ConstructorInfo)factoryRecord.Factory;
			if (constructorInfo == null)
			{
				constructorInfo = (ConstructorInfo)(factoryRecord.Factory = CreateSectionGroupFactory(factoryRecord));
			}
			return constructorInfo;
		}

		protected override object UseParentResult(string configKey, object parentResult, SectionRecord sectionRecord)
		{
			FactoryRecord factoryRecord = FindFactoryRecord(configKey, permitErrors: false);
			if (factoryRecord == null)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_unrecognized_configuration_section", configKey));
			}
			return CallCreateSection(inputIsTrusted: false, factoryRecord, sectionRecord, parentResult, null, null, -1);
		}

		protected override object GetRuntimeObject(object result)
		{
			return result;
		}

		private ConfigurationSection GetConfigSection(string configKey)
		{
			SectionRecord sectionRecord = GetSectionRecord(configKey, permitErrors: false);
			if (sectionRecord != null && sectionRecord.HasResult)
			{
				return (ConfigurationSection)sectionRecord.Result;
			}
			return null;
		}

		internal ConfigurationSectionGroup LookupSectionGroup(string configKey)
		{
			ConfigurationSectionGroup result = null;
			if (_sectionGroups != null)
			{
				result = (ConfigurationSectionGroup)_sectionGroups[configKey];
			}
			return result;
		}

		internal ConfigurationSectionGroup GetSectionGroup(string configKey)
		{
			ConfigurationSectionGroup configurationSectionGroup = LookupSectionGroup(configKey);
			if (configurationSectionGroup == null)
			{
				BaseConfigurationRecord configRecord;
				FactoryRecord factoryRecord = FindFactoryRecord(configKey, permitErrors: false, out configRecord);
				if (factoryRecord == null)
				{
					return null;
				}
				if (!factoryRecord.IsGroup)
				{
					throw ExceptionUtil.ParameterInvalid("sectionGroupName");
				}
				if (factoryRecord.FactoryTypeName == null)
				{
					configurationSectionGroup = new ConfigurationSectionGroup();
				}
				else
				{
					ConstructorInfo ctor = EnsureSectionGroupFactory(factoryRecord);
					try
					{
						configurationSectionGroup = (ConfigurationSectionGroup)TypeUtil.InvokeCtorWithReflectionPermission(ctor);
					}
					catch (Exception inner)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_exception_creating_section_handler", factoryRecord.ConfigKey), inner, factoryRecord);
					}
					catch
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_exception_creating_section_handler", factoryRecord.ConfigKey), factoryRecord);
					}
				}
				configurationSectionGroup.AttachToConfigurationRecord(this, factoryRecord);
				SectionGroups[configKey] = configurationSectionGroup;
			}
			return configurationSectionGroup;
		}

		internal ConfigurationLocationCollection GetLocationCollection(Configuration config)
		{
			ArrayList arrayList = new ArrayList();
			if (_locationTags != null)
			{
				foreach (string value in _locationTags.Values)
				{
					arrayList.Add(new ConfigurationLocation(config, value));
				}
			}
			return new ConfigurationLocationCollection(arrayList);
		}

		protected override void AddLocation(string locationSubPath)
		{
			if (_locationTags == null)
			{
				_locationTags = new Hashtable(StringComparer.OrdinalIgnoreCase);
			}
			_locationTags[locationSubPath] = locationSubPath;
		}

		private Hashtable GetAllFactories(bool isGroup)
		{
			Hashtable hashtable = new Hashtable();
			MgmtConfigurationRecord mgmtConfigurationRecord = this;
			do
			{
				if (mgmtConfigurationRecord._factoryRecords != null)
				{
					foreach (FactoryRecord value in mgmtConfigurationRecord._factoryRecords.Values)
					{
						if (value.IsGroup == isGroup)
						{
							string configKey = value.ConfigKey;
							hashtable[configKey] = new FactoryId(value.ConfigKey, value.Group, value.Name);
						}
					}
				}
				mgmtConfigurationRecord = mgmtConfigurationRecord.MgmtParent;
			}
			while (!mgmtConfigurationRecord.IsRootConfig);
			return hashtable;
		}

		internal ConfigurationSection FindImmediateParentSection(ConfigurationSection section)
		{
			ConfigurationSection configurationSection = null;
			string sectionName = section.SectionInformation.SectionName;
			SectionRecord sectionRecord = GetSectionRecord(sectionName, permitErrors: false);
			if (sectionRecord.HasLocationInputs)
			{
				SectionInput lastLocationInput = sectionRecord.LastLocationInput;
				configurationSection = (ConfigurationSection)lastLocationInput.Result;
			}
			else if (sectionRecord.HasIndirectLocationInputs)
			{
				SectionInput lastIndirectLocationInput = sectionRecord.LastIndirectLocationInput;
				configurationSection = (ConfigurationSection)lastIndirectLocationInput.Result;
			}
			else if (IsRootDeclaration(sectionName, implicitIsRooted: true))
			{
				FactoryRecord factoryRecord = GetFactoryRecord(sectionName, permitErrors: false);
				CreateSectionDefault(sectionName, getRuntimeObject: false, factoryRecord, null, out var result, out var _);
				configurationSection = (ConfigurationSection)result;
			}
			else
			{
				MgmtConfigurationRecord mgmtParent = MgmtParent;
				while (!mgmtParent.IsRootConfig)
				{
					sectionRecord = mgmtParent.GetSectionRecord(sectionName, permitErrors: false);
					if (sectionRecord != null && sectionRecord.HasResult)
					{
						configurationSection = (ConfigurationSection)sectionRecord.Result;
						break;
					}
					mgmtParent = mgmtParent.MgmtParent;
				}
			}
			if (!configurationSection.IsReadOnly())
			{
				configurationSection.SetReadOnly();
			}
			return configurationSection;
		}

		internal ConfigurationSection FindAndCloneImmediateParentSection(ConfigurationSection configSection)
		{
			string configKey = configSection.SectionInformation.ConfigKey;
			ConfigurationSection parentResult = FindImmediateParentSection(configSection);
			SectionRecord sectionRecord = GetSectionRecord(configKey, permitErrors: false);
			return (ConfigurationSection)UseParentResult(configKey, parentResult, sectionRecord);
		}

		internal void RevertToParent(ConfigurationSection configSection)
		{
			configSection.SectionInformation.RawXml = null;
			try
			{
				ConfigurationSection parentElement = FindImmediateParentSection(configSection);
				configSection.Reset(parentElement);
				configSection.ResetModified();
			}
			catch (Exception inner)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configSection.SectionInformation.SectionName), inner, base.ConfigStreamInfo.StreamName, 0);
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configSection.SectionInformation.SectionName), null, base.ConfigStreamInfo.StreamName, 0);
			}
			configSection.SectionInformation.Removed = true;
		}

		internal string GetRawXml(string configKey)
		{
			SectionRecord sectionRecord = GetSectionRecord(configKey, permitErrors: false);
			if (sectionRecord == null || !sectionRecord.HasFileInput)
			{
				return null;
			}
			string[] keys = configKey.Split(BaseConfigurationRecord.ConfigPathSeparatorParams);
			ConfigXmlReader sectionXmlReader = GetSectionXmlReader(keys, sectionRecord.FileInput);
			return sectionXmlReader.RawXml;
		}

		internal void SetRawXml(ConfigurationSection configSection, string xmlElement)
		{
			if (string.IsNullOrEmpty(xmlElement))
			{
				RevertToParent(configSection);
				return;
			}
			ValidateSectionXml(xmlElement, configSection.SectionInformation.Name);
			ConfigurationSection parentElement = FindImmediateParentSection(configSection);
			ConfigXmlReader reader = new ConfigXmlReader(xmlElement, null, 0);
			configSection.SectionInformation.RawXml = xmlElement;
			try
			{
				try
				{
					bool elementPresent = configSection.ElementPresent;
					PropertySourceInfo sourceInformation = configSection.ElementInformation.PropertyInfoInternal();
					configSection.Reset(parentElement);
					configSection.DeserializeSection(reader);
					configSection.ResetModified();
					configSection.ElementPresent = elementPresent;
					configSection.ElementInformation.ChangeSourceAndLineNumber(sourceInformation);
				}
				catch
				{
					configSection.SectionInformation.RawXml = null;
					throw;
				}
			}
			catch (Exception inner)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configSection.SectionInformation.SectionName), inner, null, 0);
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configSection.SectionInformation.SectionName), null, null, 0);
			}
			configSection.SectionInformation.Removed = false;
		}

		private bool IsStreamUsed(string oldStreamName)
		{
			MgmtConfigurationRecord mgmtConfigurationRecord = this;
			if (base.IsLocationConfig)
			{
				mgmtConfigurationRecord = MgmtParent;
				if (mgmtConfigurationRecord._sectionRecords != null)
				{
					foreach (SectionRecord value in mgmtConfigurationRecord._sectionRecords.Values)
					{
						if (value.HasFileInput && StringUtil.EqualsIgnoreCase(value.FileInput.SectionXmlInfo.ConfigSourceStreamName, oldStreamName))
						{
							return true;
						}
					}
				}
			}
			if (mgmtConfigurationRecord._locationSections != null)
			{
				foreach (LocationSectionRecord locationSection in mgmtConfigurationRecord._locationSections)
				{
					if (StringUtil.EqualsIgnoreCase(locationSection.SectionXmlInfo.ConfigSourceStreamName, oldStreamName))
					{
						return true;
					}
				}
			}
			return false;
		}

		internal void ChangeConfigSource(SectionInformation sectionInformation, string oldConfigSource, string oldConfigSourceStreamName, string newConfigSource)
		{
			if (string.IsNullOrEmpty(oldConfigSource))
			{
				oldConfigSource = null;
			}
			if (string.IsNullOrEmpty(newConfigSource))
			{
				newConfigSource = null;
			}
			if (StringUtil.EqualsIgnoreCase(oldConfigSource, newConfigSource))
			{
				return;
			}
			if (string.IsNullOrEmpty(base.ConfigStreamInfo.StreamName))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_source_requires_file"));
			}
			string text = null;
			if (newConfigSource != null)
			{
				text = base.Host.GetStreamNameForConfigSource(base.ConfigStreamInfo.StreamName, newConfigSource);
			}
			if (text != null)
			{
				ValidateUniqueChildConfigSource(sectionInformation.ConfigKey, text, newConfigSource, null);
				StreamInfo streamInfo = (StreamInfo)_streamInfoUpdates[text];
				if (streamInfo != null)
				{
					if (streamInfo.SectionName != sectionInformation.ConfigKey)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_source_cannot_be_shared", newConfigSource));
					}
				}
				else
				{
					streamInfo = new StreamInfo(sectionInformation.ConfigKey, newConfigSource, text);
					_streamInfoUpdates.Add(text, streamInfo);
				}
			}
			if (oldConfigSourceStreamName != null && !IsStreamUsed(oldConfigSourceStreamName))
			{
				_streamInfoUpdates.Remove(oldConfigSourceStreamName);
			}
			sectionInformation.ConfigSourceStreamName = text;
		}

		private void ValidateSectionXml(string xmlElement, string configKey)
		{
			if (string.IsNullOrEmpty(xmlElement))
			{
				return;
			}
			XmlTextReader xmlTextReader = null;
			try
			{
				XmlParserContext context = new XmlParserContext(null, null, null, XmlSpace.Default, Encoding.Unicode);
				xmlTextReader = new XmlTextReader(xmlElement, XmlNodeType.Element, context);
				xmlTextReader.Read();
				if (xmlTextReader.NodeType != XmlNodeType.Element)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_unexpected_node_type", xmlTextReader.NodeType));
				}
				BaseConfigurationRecord.SplitConfigKey(configKey, out var _, out var name);
				if (xmlTextReader.Name != name)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_unexpected_element_name", xmlTextReader.Name));
				}
				while (true)
				{
					if (!xmlTextReader.Read())
					{
						if (xmlTextReader.Depth != 0)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_unexpected_element_end"), xmlTextReader);
						}
						break;
					}
					XmlNodeType nodeType = xmlTextReader.NodeType;
					if (nodeType == XmlNodeType.DocumentType || nodeType == XmlNodeType.XmlDeclaration)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_invalid_node_type"), xmlTextReader);
					}
					if (xmlTextReader.Depth <= 0 && xmlTextReader.NodeType != XmlNodeType.EndElement)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_more_data_than_expected"), xmlTextReader);
					}
				}
			}
			finally
			{
				xmlTextReader?.Close();
			}
		}

		internal void AddConfigurationSection(string group, string name, ConfigurationSection configSection)
		{
			if (base.IsLocationConfig)
			{
				throw new InvalidOperationException(SR.GetString("Config_add_configurationsection_in_location_config"));
			}
			BaseConfigurationRecord.VerifySectionName(name, null, allowImplicit: false);
			if (configSection == null)
			{
				throw new ArgumentNullException("configSection");
			}
			if (configSection.SectionInformation.Attached)
			{
				throw new InvalidOperationException(SR.GetString("Config_add_configurationsection_already_added"));
			}
			string text = BaseConfigurationRecord.CombineConfigKey(group, name);
			FactoryRecord factoryRecord = FindFactoryRecord(text, permitErrors: true);
			if (factoryRecord != null)
			{
				throw new ArgumentException(SR.GetString("Config_add_configurationsection_already_exists"));
			}
			if (!string.IsNullOrEmpty(configSection.SectionInformation.ConfigSource))
			{
				ChangeConfigSource(configSection.SectionInformation, null, null, configSection.SectionInformation.ConfigSource);
			}
			if (_sectionFactories != null)
			{
				_sectionFactories.Add(text, new FactoryId(text, group, name));
			}
			string text2 = configSection.SectionInformation.Type;
			if (text2 == null)
			{
				text2 = base.Host.GetConfigTypeName(configSection.GetType());
			}
			factoryRecord = new FactoryRecord(text, group, name, text2, configSection.SectionInformation.AllowLocation, configSection.SectionInformation.AllowDefinition, configSection.SectionInformation.AllowExeDefinition, configSection.SectionInformation.OverrideModeDefaultSetting, configSection.SectionInformation.RestartOnExternalChanges, configSection.SectionInformation.RequirePermission, _flags[8192], isUndeclared: false, base.ConfigStreamInfo.StreamName, -1);
			factoryRecord.Factory = TypeUtil.GetConstructorWithReflectionPermission(configSection.GetType(), typeof(ConfigurationSection), throwOnError: true);
			factoryRecord.IsFactoryTrustedWithoutAptca = TypeUtil.IsTypeFromTrustedAssemblyWithoutAptca(configSection.GetType());
			EnsureFactories()[text] = factoryRecord;
			SectionRecord sectionRecord = EnsureSectionRecordUnsafe(text, permitErrors: false);
			sectionRecord.Result = configSection;
			sectionRecord.ResultRuntimeObject = configSection;
			if (_removedSections != null)
			{
				_removedSections.Remove(text);
			}
			configSection.SectionInformation.AttachToConfigurationRecord(this, factoryRecord, sectionRecord);
			string rawXml = configSection.SectionInformation.RawXml;
			if (!string.IsNullOrEmpty(rawXml))
			{
				configSection.SectionInformation.RawXml = null;
				configSection.SectionInformation.SetRawXml(rawXml);
			}
		}

		internal void RemoveConfigurationSection(string group, string name)
		{
			bool flag = false;
			BaseConfigurationRecord.VerifySectionName(name, null, allowImplicit: true);
			string text = BaseConfigurationRecord.CombineConfigKey(group, name);
			if (RemovedSections.Contains(text) || FindFactoryRecord(text, permitErrors: true) == null)
			{
				return;
			}
			GetConfigSection(text)?.SectionInformation.DetachFromConfigurationRecord();
			bool flag2 = IsRootDeclaration(text, implicitIsRooted: false);
			if (_sectionFactories != null && flag2)
			{
				_sectionFactories.Remove(text);
			}
			if (!base.IsLocationConfig && _factoryRecords != null && _factoryRecords.Contains(text))
			{
				flag = true;
				_factoryRecords.Remove(text);
			}
			if (_sectionRecords != null && _sectionRecords.Contains(text))
			{
				flag = true;
				_sectionRecords.Remove(text);
			}
			if (_locationSections != null)
			{
				int num = 0;
				while (num < _locationSections.Count)
				{
					LocationSectionRecord locationSectionRecord = (LocationSectionRecord)_locationSections[num];
					if (locationSectionRecord.ConfigKey != text)
					{
						num++;
						continue;
					}
					flag = true;
					_locationSections.RemoveAt(num);
				}
			}
			if (flag)
			{
				RemovedSections.Add(text, text);
			}
			List<string> list = new List<string>();
			foreach (StreamInfo value in _streamInfoUpdates.Values)
			{
				if (value.SectionName == text)
				{
					list.Add(value.StreamName);
				}
			}
			foreach (string item in list)
			{
				_streamInfoUpdates.Remove(item);
			}
		}

		internal void AddConfigurationSectionGroup(string group, string name, ConfigurationSectionGroup configSectionGroup)
		{
			if (base.IsLocationConfig)
			{
				throw new InvalidOperationException(SR.GetString("Config_add_configurationsectiongroup_in_location_config"));
			}
			BaseConfigurationRecord.VerifySectionName(name, null, allowImplicit: false);
			if (configSectionGroup == null)
			{
				throw ExceptionUtil.ParameterInvalid("name");
			}
			if (configSectionGroup.Attached)
			{
				throw new InvalidOperationException(SR.GetString("Config_add_configurationsectiongroup_already_added"));
			}
			string text = BaseConfigurationRecord.CombineConfigKey(group, name);
			FactoryRecord factoryRecord = FindFactoryRecord(text, permitErrors: true);
			if (factoryRecord != null)
			{
				throw new ArgumentException(SR.GetString("Config_add_configurationsectiongroup_already_exists"));
			}
			if (_sectionGroupFactories != null)
			{
				_sectionGroupFactories.Add(text, new FactoryId(text, group, name));
			}
			string text2 = configSectionGroup.Type;
			if (text2 == null)
			{
				text2 = base.Host.GetConfigTypeName(configSectionGroup.GetType());
			}
			factoryRecord = new FactoryRecord(text, group, name, text2, base.ConfigStreamInfo.StreamName, -1);
			EnsureFactories()[text] = factoryRecord;
			SectionGroups[text] = configSectionGroup;
			if (_removedSectionGroups != null)
			{
				_removedSectionGroups.Remove(text);
			}
			configSectionGroup.AttachToConfigurationRecord(this, factoryRecord);
		}

		private ArrayList GetDescendentSectionFactories(string configKey)
		{
			ArrayList arrayList = new ArrayList();
			string s = ((configKey.Length != 0) ? (configKey + "/") : string.Empty);
			foreach (FactoryId value in SectionFactories.Values)
			{
				if (value.Group == configKey || StringUtil.StartsWith(value.Group, s))
				{
					arrayList.Add(value);
				}
			}
			return arrayList;
		}

		private ArrayList GetDescendentSectionGroupFactories(string configKey)
		{
			ArrayList arrayList = new ArrayList();
			string s = ((configKey.Length != 0) ? (configKey + "/") : string.Empty);
			foreach (FactoryId value in SectionGroupFactories.Values)
			{
				if (value.ConfigKey == configKey || StringUtil.StartsWith(value.ConfigKey, s))
				{
					arrayList.Add(value);
				}
			}
			return arrayList;
		}

		internal void RemoveConfigurationSectionGroup(string group, string name)
		{
			BaseConfigurationRecord.VerifySectionName(name, null, allowImplicit: false);
			string configKey = BaseConfigurationRecord.CombineConfigKey(group, name);
			if (FindFactoryRecord(configKey, permitErrors: true) == null)
			{
				return;
			}
			ArrayList descendentSectionFactories = GetDescendentSectionFactories(configKey);
			foreach (FactoryId item in descendentSectionFactories)
			{
				RemoveConfigurationSection(item.Group, item.Name);
			}
			ArrayList descendentSectionGroupFactories = GetDescendentSectionGroupFactories(configKey);
			foreach (FactoryId item2 in descendentSectionGroupFactories)
			{
				if (!RemovedSectionGroups.Contains(item2.ConfigKey))
				{
					LookupSectionGroup(item2.ConfigKey)?.DetachFromConfigurationRecord();
					bool flag = IsRootDeclaration(item2.ConfigKey, implicitIsRooted: false);
					if (_sectionGroupFactories != null && flag)
					{
						_sectionGroupFactories.Remove(item2.ConfigKey);
					}
					if (!base.IsLocationConfig && _factoryRecords != null)
					{
						_factoryRecords.Remove(item2.ConfigKey);
					}
					if (_sectionGroups != null)
					{
						_sectionGroups.Remove(item2.ConfigKey);
					}
					RemovedSectionGroups.Add(item2.ConfigKey, item2.ConfigKey);
				}
			}
		}

		internal void SaveAs(string filename, ConfigurationSaveMode saveMode, bool forceUpdateAll)
		{
			SectionUpdates configDeclarationUpdates = GetConfigDeclarationUpdates(saveMode, forceUpdateAll);
			bool flag = false;
			bool flag2 = filename != null;
			GetConfigDefinitionUpdates(flag2, saveMode, forceUpdateAll, out var definitionUpdates, out var configSourceUpdates);
			if (filename != null)
			{
				if (!base.Host.IsRemote && _streamInfoUpdates.Contains(filename))
				{
					throw new ArgumentException(SR.GetString("Filename_in_SaveAs_is_used_already", filename));
				}
				if (string.IsNullOrEmpty(base.ConfigStreamInfo.StreamName))
				{
					StreamInfo value = new StreamInfo(null, null, filename);
					_streamInfoUpdates.Add(filename, value);
					base.ConfigStreamInfo.StreamName = filename;
					base.ConfigStreamInfo.StreamVersion = MonitorStream(null, null, base.ConfigStreamInfo.StreamName);
				}
				UpdateConfigHost.AddStreamname(base.ConfigStreamInfo.StreamName, filename, base.Host.IsRemote);
				foreach (StreamInfo value2 in _streamInfoUpdates.Values)
				{
					if (!string.IsNullOrEmpty(value2.SectionName))
					{
						string newStreamname = InternalConfigHost.StaticGetStreamNameForConfigSource(filename, value2.ConfigSource);
						UpdateConfigHost.AddStreamname(value2.StreamName, newStreamname, base.Host.IsRemote);
					}
				}
			}
			if (!flag2)
			{
				flag2 = RecordItselfRequiresUpdates;
			}
			if (configDeclarationUpdates != null || definitionUpdates != null || flag2)
			{
				byte[] buffer = null;
				if (base.ConfigStreamInfo.HasStream)
				{
					using Stream stream = base.Host.OpenStreamForRead(base.ConfigStreamInfo.StreamName);
					if (stream == null)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_file_has_changed"), base.ConfigStreamInfo.StreamName, 0);
					}
					buffer = new byte[stream.Length];
					int num = stream.Read(buffer, 0, (int)stream.Length);
					if (num != stream.Length)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_data_read_count_mismatch"));
					}
				}
				string text = FindChangedConfigurationStream();
				if (text != null)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_file_has_changed"), text, 0);
				}
				flag = true;
				object writeContext = null;
				bool flag3 = false;
				try
				{
					try
					{
						using Stream stream2 = base.Host.OpenStreamForWrite(base.ConfigStreamInfo.StreamName, null, ref writeContext);
						flag3 = true;
						using StreamWriter writer = new StreamWriter(stream2);
						XmlUtilWriter utilWriter = new XmlUtilWriter(writer, trackPosition: true);
						if (base.ConfigStreamInfo.HasStream)
						{
							CopyConfig(configDeclarationUpdates, definitionUpdates, buffer, base.ConfigStreamInfo.StreamName, NamespaceChangeNeeded, utilWriter);
						}
						else
						{
							CreateNewConfig(configDeclarationUpdates, definitionUpdates, NamespaceChangeNeeded, utilWriter);
						}
					}
					catch
					{
						if (flag3)
						{
							base.Host.WriteCompleted(base.ConfigStreamInfo.StreamName, success: false, writeContext);
						}
						throw;
					}
				}
				catch (Exception e)
				{
					throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), e, base.ConfigStreamInfo.StreamName, 0);
				}
				catch
				{
					throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), null, base.ConfigStreamInfo.StreamName, 0);
				}
				base.Host.WriteCompleted(base.ConfigStreamInfo.StreamName, success: true, writeContext);
				base.ConfigStreamInfo.HasStream = true;
				base.ConfigStreamInfo.ClearStreamInfos();
				base.ConfigStreamInfo.StreamVersion = MonitorStream(null, null, base.ConfigStreamInfo.StreamName);
			}
			if (configSourceUpdates != null)
			{
				if (!flag)
				{
					string text2 = FindChangedConfigurationStream();
					if (text2 != null)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_file_has_changed"), text2, 0);
					}
				}
				foreach (DefinitionUpdate item in configSourceUpdates)
				{
					SaveConfigSource(item);
				}
			}
			UpdateRecords();
		}

		private bool AreDeclarationAttributesModified(FactoryRecord factoryRecord, ConfigurationSection configSection)
		{
			if (!(factoryRecord.FactoryTypeName != configSection.SectionInformation.Type) && factoryRecord.AllowLocation == configSection.SectionInformation.AllowLocation && factoryRecord.RestartOnExternalChanges == configSection.SectionInformation.RestartOnExternalChanges && factoryRecord.RequirePermission == configSection.SectionInformation.RequirePermission && factoryRecord.AllowDefinition == configSection.SectionInformation.AllowDefinition && factoryRecord.AllowExeDefinition == configSection.SectionInformation.AllowExeDefinition && factoryRecord.OverrideModeDefault.OverrideMode == configSection.SectionInformation.OverrideModeDefaultSetting.OverrideMode)
			{
				return configSection.SectionInformation.IsModifiedFlags();
			}
			return true;
		}

		private void AppendAttribute(StringBuilder sb, string key, string value)
		{
			sb.Append(key);
			sb.Append("=\"");
			sb.Append(value);
			sb.Append("\" ");
		}

		private string GetUpdatedSectionDeclarationXml(FactoryRecord factoryRecord, ConfigurationSection configSection, ConfigurationSaveMode saveMode)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append('<');
			stringBuilder.Append("section");
			stringBuilder.Append(' ');
			AppendAttribute(stringBuilder, "name", configSection.SectionInformation.Name);
			AppendAttribute(stringBuilder, "type", (configSection.SectionInformation.Type != null) ? configSection.SectionInformation.Type : factoryRecord.FactoryTypeName);
			if (!configSection.SectionInformation.AllowLocation || saveMode == ConfigurationSaveMode.Full || (saveMode == ConfigurationSaveMode.Modified && configSection.SectionInformation.AllowLocationModified))
			{
				AppendAttribute(stringBuilder, "allowLocation", configSection.SectionInformation.AllowLocation ? "true" : "false");
			}
			if (configSection.SectionInformation.AllowDefinition != ConfigurationAllowDefinition.Everywhere || saveMode == ConfigurationSaveMode.Full || (saveMode == ConfigurationSaveMode.Modified && configSection.SectionInformation.AllowDefinitionModified))
			{
				string value = null;
				switch (configSection.SectionInformation.AllowDefinition)
				{
				case ConfigurationAllowDefinition.Everywhere:
					value = "Everywhere";
					break;
				case ConfigurationAllowDefinition.MachineOnly:
					value = "MachineOnly";
					break;
				case ConfigurationAllowDefinition.MachineToWebRoot:
					value = "MachineToWebRoot";
					break;
				case ConfigurationAllowDefinition.MachineToApplication:
					value = "MachineToApplication";
					break;
				}
				AppendAttribute(stringBuilder, "allowDefinition", value);
			}
			if (configSection.SectionInformation.AllowExeDefinition != ConfigurationAllowExeDefinition.MachineToApplication || saveMode == ConfigurationSaveMode.Full || (saveMode == ConfigurationSaveMode.Modified && configSection.SectionInformation.AllowExeDefinitionModified))
			{
				AppendAttribute(stringBuilder, "allowExeDefinition", ExeDefinitionToString(configSection.SectionInformation.AllowExeDefinition));
			}
			if (!configSection.SectionInformation.OverrideModeDefaultSetting.IsDefaultForSection || saveMode == ConfigurationSaveMode.Full || (saveMode == ConfigurationSaveMode.Modified && configSection.SectionInformation.OverrideModeDefaultModified))
			{
				AppendAttribute(stringBuilder, "overrideModeDefault", configSection.SectionInformation.OverrideModeDefaultSetting.OverrideModeXmlValue);
			}
			if (!configSection.SectionInformation.RestartOnExternalChanges)
			{
				AppendAttribute(stringBuilder, "restartOnExternalChanges", "false");
			}
			else if (saveMode == ConfigurationSaveMode.Full || (saveMode == ConfigurationSaveMode.Modified && configSection.SectionInformation.RestartOnExternalChangesModified))
			{
				AppendAttribute(stringBuilder, "restartOnExternalChanges", "true");
			}
			if (!configSection.SectionInformation.RequirePermission)
			{
				AppendAttribute(stringBuilder, "requirePermission", "false");
			}
			else if (saveMode == ConfigurationSaveMode.Full || (saveMode == ConfigurationSaveMode.Modified && configSection.SectionInformation.RequirePermissionModified))
			{
				AppendAttribute(stringBuilder, "requirePermission", "true");
			}
			stringBuilder.Append("/>");
			return stringBuilder.ToString();
		}

		private string ExeDefinitionToString(ConfigurationAllowExeDefinition allowDefinition)
		{
			return allowDefinition switch
			{
				ConfigurationAllowExeDefinition.MachineOnly => "MachineOnly", 
				ConfigurationAllowExeDefinition.MachineToApplication => "MachineToApplication", 
				ConfigurationAllowExeDefinition.MachineToRoamingUser => "MachineToRoamingUser", 
				ConfigurationAllowExeDefinition.MachineToLocalUser => "MachineToLocalUser", 
				_ => throw ExceptionUtil.PropertyInvalid("AllowExeDefinition"), 
			};
		}

		private string GetUpdatedSectionGroupDeclarationXml(FactoryRecord factoryRecord, ConfigurationSectionGroup configSectionGroup)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append('<');
			stringBuilder.Append("sectionGroup");
			stringBuilder.Append(' ');
			AppendAttribute(stringBuilder, "name", configSectionGroup.Name);
			AppendAttribute(stringBuilder, "type", (configSectionGroup.Type != null) ? configSectionGroup.Type : factoryRecord.FactoryTypeName);
			stringBuilder.Append('>');
			return stringBuilder.ToString();
		}

		private SectionUpdates GetConfigDeclarationUpdates(ConfigurationSaveMode saveMode, bool forceUpdateAll)
		{
			if (base.IsLocationConfig)
			{
				return null;
			}
			bool flag = HasRemovedSectionsOrGroups;
			SectionUpdates sectionUpdates = new SectionUpdates(string.Empty);
			if (_factoryRecords != null)
			{
				foreach (FactoryRecord value in _factoryRecords.Values)
				{
					if (!value.IsGroup)
					{
						string updatedXml = null;
						if (value.IsUndeclared)
						{
							continue;
						}
						ConfigurationSection configSection = GetConfigSection(value.ConfigKey);
						if (configSection != null)
						{
							if (!configSection.SectionInformation.IsDeclared && !MgmtParent.IsRootConfig && MgmtParent.FindFactoryRecord(value.ConfigKey, permitErrors: false) != null)
							{
								if (value.HasFile)
								{
									flag = true;
								}
								continue;
							}
							if (AreDeclarationAttributesModified(value, configSection) || !value.HasFile)
							{
								flag = true;
								updatedXml = GetUpdatedSectionDeclarationXml(value, configSection, saveMode);
							}
						}
						DeclarationUpdate update = new DeclarationUpdate(value.ConfigKey, !value.HasFile, updatedXml);
						sectionUpdates.AddSection(update);
						continue;
					}
					bool flag2 = false;
					ConfigurationSectionGroup configurationSectionGroup = LookupSectionGroup(value.ConfigKey);
					if (!value.HasFile)
					{
						flag2 = true;
					}
					else if (configurationSectionGroup != null && configurationSectionGroup.IsDeclarationRequired)
					{
						flag2 = true;
					}
					else if (value.FactoryTypeName != null || configurationSectionGroup != null)
					{
						FactoryRecord factoryRecord2 = null;
						if (!MgmtParent.IsRootConfig)
						{
							factoryRecord2 = MgmtParent.FindFactoryRecord(value.ConfigKey, permitErrors: false);
						}
						flag2 = factoryRecord2 == null || factoryRecord2.FactoryTypeName == null;
					}
					if (flag2)
					{
						string updatedXml2 = null;
						if (!value.HasFile || (configurationSectionGroup != null && configurationSectionGroup.Type != value.FactoryTypeName))
						{
							flag = true;
							updatedXml2 = GetUpdatedSectionGroupDeclarationXml(value, configurationSectionGroup);
						}
						DeclarationUpdate update2 = new DeclarationUpdate(value.ConfigKey, !value.HasFile, updatedXml2);
						sectionUpdates.AddSectionGroup(update2);
					}
				}
			}
			if (_sectionRecords != null)
			{
				foreach (SectionRecord value2 in _sectionRecords.Values)
				{
					if (GetFactoryRecord(value2.ConfigKey, permitErrors: false) == null && value2.HasResult)
					{
						ConfigurationSection configurationSection = (ConfigurationSection)value2.Result;
						FactoryRecord factoryRecord3 = MgmtParent.FindFactoryRecord(value2.ConfigKey, permitErrors: false);
						if (configurationSection.SectionInformation.IsDeclared)
						{
							flag = true;
							string updatedSectionDeclarationXml = GetUpdatedSectionDeclarationXml(factoryRecord3, configurationSection, saveMode);
							DeclarationUpdate update3 = new DeclarationUpdate(factoryRecord3.ConfigKey, moved: true, updatedSectionDeclarationXml);
							sectionUpdates.AddSection(update3);
						}
					}
				}
			}
			if (_sectionGroups != null)
			{
				foreach (ConfigurationSectionGroup value3 in _sectionGroups.Values)
				{
					if (GetFactoryRecord(value3.SectionGroupName, permitErrors: false) == null)
					{
						FactoryRecord factoryRecord4 = MgmtParent.FindFactoryRecord(value3.SectionGroupName, permitErrors: false);
						if (value3.IsDeclared || (factoryRecord4 != null && value3.Type != factoryRecord4.FactoryTypeName))
						{
							flag = true;
							string updatedSectionGroupDeclarationXml = GetUpdatedSectionGroupDeclarationXml(factoryRecord4, value3);
							DeclarationUpdate update4 = new DeclarationUpdate(factoryRecord4.ConfigKey, moved: true, updatedSectionGroupDeclarationXml);
							sectionUpdates.AddSectionGroup(update4);
						}
					}
				}
			}
			if (flag)
			{
				return sectionUpdates;
			}
			return null;
		}

		private bool AreLocationAttributesModified(SectionRecord sectionRecord, ConfigurationSection configSection)
		{
			OverrideModeSetting x = OverrideModeSetting.LocationDefault;
			bool flag = true;
			if (sectionRecord.HasFileInput)
			{
				SectionXmlInfo sectionXmlInfo = sectionRecord.FileInput.SectionXmlInfo;
				x = sectionXmlInfo.OverrideModeSetting;
				flag = !sectionXmlInfo.SkipInChildApps;
			}
			if (OverrideModeSetting.CanUseSameLocationTag(x, configSection.SectionInformation.OverrideModeSetting))
			{
				return flag != configSection.SectionInformation.InheritInChildApplications;
			}
			return true;
		}

		private bool AreSectionAttributesModified(SectionRecord sectionRecord, ConfigurationSection configSection)
		{
			string s;
			string s2;
			if (sectionRecord.HasFileInput)
			{
				SectionXmlInfo sectionXmlInfo = sectionRecord.FileInput.SectionXmlInfo;
				s = sectionXmlInfo.ConfigSource;
				s2 = sectionXmlInfo.ProtectionProviderName;
			}
			else
			{
				s = null;
				s2 = null;
			}
			if (StringUtil.EqualsNE(s, configSection.SectionInformation.ConfigSource) && StringUtil.EqualsNE(s2, configSection.SectionInformation.ProtectionProviderName))
			{
				return AreLocationAttributesModified(sectionRecord, configSection);
			}
			return true;
		}

		private bool IsConfigSectionMoved(SectionRecord sectionRecord, ConfigurationSection configSection)
		{
			if (!sectionRecord.HasFileInput)
			{
				return true;
			}
			return AreLocationAttributesModified(sectionRecord, configSection);
		}

		private void GetConfigDefinitionUpdates(bool requireUpdates, ConfigurationSaveMode saveMode, bool forceSaveAll, out ConfigDefinitionUpdates definitionUpdates, out ArrayList configSourceUpdates)
		{
			definitionUpdates = new ConfigDefinitionUpdates();
			configSourceUpdates = null;
			bool flag = HasRemovedSections;
			if (_sectionRecords != null)
			{
				InitProtectedConfigurationSection();
				foreach (DictionaryEntry sectionRecord2 in _sectionRecords)
				{
					string text = (string)sectionRecord2.Key;
					SectionRecord sectionRecord = (SectionRecord)sectionRecord2.Value;
					sectionRecord.AddUpdate = false;
					bool flag2 = sectionRecord.HasFileInput;
					OverrideModeSetting overrideMode = OverrideModeSetting.LocationDefault;
					bool flag3 = true;
					bool flag4 = false;
					string text2 = null;
					bool flag5 = false;
					if (!sectionRecord.HasResult)
					{
						if (sectionRecord.HasFileInput)
						{
							SectionXmlInfo sectionXmlInfo = sectionRecord.FileInput.SectionXmlInfo;
							overrideMode = sectionXmlInfo.OverrideModeSetting;
							flag3 = !sectionXmlInfo.SkipInChildApps;
							flag5 = requireUpdates && !string.IsNullOrEmpty(sectionXmlInfo.ConfigSource);
						}
					}
					else
					{
						ConfigurationSection configurationSection = (ConfigurationSection)sectionRecord.Result;
						overrideMode = configurationSection.SectionInformation.OverrideModeSetting;
						flag3 = configurationSection.SectionInformation.InheritInChildApplications;
						if (!configurationSection.SectionInformation.AllowLocation && (!overrideMode.IsDefaultForLocationTag || !flag3))
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_inconsistent_location_attributes", text));
						}
						flag5 = requireUpdates && !string.IsNullOrEmpty(configurationSection.SectionInformation.ConfigSource);
						try
						{
							bool flag6 = configurationSection.SectionInformation.ForceSave || configurationSection.IsModified() || (forceSaveAll && !configurationSection.SectionInformation.IsLocked);
							bool flag7 = AreSectionAttributesModified(sectionRecord, configurationSection);
							bool flag8 = flag6 || configurationSection.SectionInformation.RawXml != null;
							if (flag8 || flag7)
							{
								configurationSection.SectionInformation.VerifyIsEditable();
								configurationSection.SectionInformation.Removed = false;
								flag2 = true;
								flag4 = IsConfigSectionMoved(sectionRecord, configurationSection);
								if (!flag5)
								{
									flag5 = !string.IsNullOrEmpty(configurationSection.SectionInformation.ConfigSource) && (flag8 || configurationSection.SectionInformation.ConfigSourceModified);
								}
								if (flag6 || configurationSection.SectionInformation.RawXml == null || saveMode == ConfigurationSaveMode.Full)
								{
									ConfigurationSection parentElement = FindImmediateParentSection(configurationSection);
									text2 = configurationSection.SerializeSection(parentElement, configurationSection.SectionInformation.Name, saveMode);
									ValidateSectionXml(text2, text);
								}
								else
								{
									text2 = configurationSection.SectionInformation.RawXml;
								}
								if (string.IsNullOrEmpty(text2) && (!string.IsNullOrEmpty(configurationSection.SectionInformation.ConfigSource) || !configurationSection.SectionInformation.LocationAttributesAreDefault || configurationSection.SectionInformation.ProtectionProvider != null))
								{
									text2 = WriteEmptyElement(configurationSection.SectionInformation.Name);
								}
								if (string.IsNullOrEmpty(text2))
								{
									configurationSection.SectionInformation.Removed = true;
									text2 = null;
									flag2 = false;
									if (sectionRecord.HasFileInput)
									{
										flag = true;
										sectionRecord.RemoveFileInput();
									}
								}
								else
								{
									if (flag7 || flag4 || string.IsNullOrEmpty(configurationSection.SectionInformation.ConfigSource))
									{
										flag = true;
									}
									if (configurationSection.SectionInformation.ProtectionProvider != null)
									{
										ProtectedConfigurationSection protectedConfigSection = GetSection("configProtectedData") as ProtectedConfigurationSection;
										try
										{
											string encryptedXml = base.Host.EncryptSection(text2, configurationSection.SectionInformation.ProtectionProvider, protectedConfigSection);
											text2 = ProtectedConfigurationSection.FormatEncryptedSection(encryptedXml, configurationSection.SectionInformation.Name, configurationSection.SectionInformation.ProtectionProvider.Name);
										}
										catch (Exception ex)
										{
											throw new ConfigurationErrorsException(SR.GetString("Encryption_failed", configurationSection.SectionInformation.SectionName, configurationSection.SectionInformation.ProtectionProvider.Name, ex.Message), ex);
										}
										catch
										{
											throw new ConfigurationErrorsException(SR.GetString("Encryption_failed", configurationSection.SectionInformation.SectionName, configurationSection.SectionInformation.ProtectionProvider.Name, ExceptionUtil.NoExceptionInformation));
										}
									}
								}
							}
							else if (configurationSection.SectionInformation.Removed)
							{
								flag2 = false;
								if (sectionRecord.HasFileInput)
								{
									flag = true;
								}
							}
						}
						catch (Exception inner)
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configurationSection.SectionInformation.SectionName), inner);
						}
						catch
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configurationSection.SectionInformation.SectionName));
						}
					}
					if (!flag2)
					{
						continue;
					}
					if (GetSectionLockedMode(sectionRecord.ConfigKey) == OverrideMode.Deny)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_section_locked"), (IConfigErrorInfo)null);
					}
					sectionRecord.AddUpdate = true;
					DefinitionUpdate value = definitionUpdates.AddUpdate(overrideMode, flag3, flag4, text2, sectionRecord);
					if (flag5)
					{
						if (configSourceUpdates == null)
						{
							configSourceUpdates = new ArrayList();
						}
						configSourceUpdates.Add(value);
					}
				}
			}
			if (_flags[16777216])
			{
				flag = true;
				definitionUpdates.RequireLocation = true;
			}
			if (_flags[33554432])
			{
				flag = true;
			}
			if (flag)
			{
				definitionUpdates.CompleteUpdates();
			}
			else
			{
				definitionUpdates = null;
			}
		}

		private string WriteEmptyElement(string ElementName)
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append('<');
			stringBuilder.Append(ElementName);
			stringBuilder.Append(" />");
			return stringBuilder.ToString();
		}

		private void UpdateRecords()
		{
			if (_factoryRecords != null)
			{
				foreach (FactoryRecord value in _factoryRecords.Values)
				{
					if (string.IsNullOrEmpty(value.Filename))
					{
						value.Filename = base.ConfigStreamInfo.StreamName;
					}
					value.LineNumber = 0;
					ConfigurationSection configSection = GetConfigSection(value.ConfigKey);
					if (configSection != null)
					{
						if (configSection.SectionInformation.Type != null)
						{
							value.FactoryTypeName = configSection.SectionInformation.Type;
						}
						value.AllowLocation = configSection.SectionInformation.AllowLocation;
						value.RestartOnExternalChanges = configSection.SectionInformation.RestartOnExternalChanges;
						value.RequirePermission = configSection.SectionInformation.RequirePermission;
						value.AllowDefinition = configSection.SectionInformation.AllowDefinition;
						value.AllowExeDefinition = configSection.SectionInformation.AllowExeDefinition;
					}
				}
			}
			if (_sectionRecords != null)
			{
				string definitionConfigPath = (base.IsLocationConfig ? _parent.ConfigPath : base.ConfigPath);
				foreach (SectionRecord value2 in _sectionRecords.Values)
				{
					ConfigurationSection configurationSection;
					string text;
					string text2;
					if (value2.HasResult)
					{
						configurationSection = (ConfigurationSection)value2.Result;
						text = configurationSection.SectionInformation.ConfigSource;
						if (string.IsNullOrEmpty(text))
						{
							text = null;
						}
						text2 = configurationSection.SectionInformation.ConfigSourceStreamName;
						if (string.IsNullOrEmpty(text2))
						{
							text2 = null;
						}
					}
					else
					{
						configurationSection = null;
						text = null;
						text2 = null;
						if (value2.HasFileInput)
						{
							SectionXmlInfo sectionXmlInfo = value2.FileInput.SectionXmlInfo;
							text = sectionXmlInfo.ConfigSource;
							text2 = sectionXmlInfo.ConfigSourceStreamName;
						}
					}
					object configSourceStreamVersion = (string.IsNullOrEmpty(text) ? null : MonitorStream(value2.ConfigKey, text, text2));
					if (!value2.HasResult)
					{
						if (value2.HasFileInput)
						{
							SectionXmlInfo sectionXmlInfo2 = value2.FileInput.SectionXmlInfo;
							sectionXmlInfo2.StreamVersion = base.ConfigStreamInfo.StreamVersion;
							sectionXmlInfo2.ConfigSourceStreamVersion = configSourceStreamVersion;
						}
						continue;
					}
					configurationSection.SectionInformation.RawXml = null;
					bool addUpdate = value2.AddUpdate;
					value2.AddUpdate = false;
					if (addUpdate)
					{
						SectionInput sectionInput = value2.FileInput;
						if (sectionInput == null)
						{
							SectionXmlInfo sectionXmlInfo3 = new SectionXmlInfo(value2.ConfigKey, definitionConfigPath, _configPath, _locationSubPath, base.ConfigStreamInfo.StreamName, 0, base.ConfigStreamInfo.StreamVersion, null, text, text2, configSourceStreamVersion, configurationSection.SectionInformation.ProtectionProviderName, configurationSection.SectionInformation.OverrideModeSetting, !configurationSection.SectionInformation.InheritInChildApplications);
							sectionInput = new SectionInput(sectionXmlInfo3, null);
							sectionInput.Result = configurationSection;
							sectionInput.ResultRuntimeObject = configurationSection;
							value2.AddFileInput(sectionInput);
						}
						else
						{
							SectionXmlInfo sectionXmlInfo4 = sectionInput.SectionXmlInfo;
							sectionXmlInfo4.LineNumber = 0;
							sectionXmlInfo4.StreamVersion = base.ConfigStreamInfo.StreamVersion;
							sectionXmlInfo4.RawXml = null;
							sectionXmlInfo4.ConfigSource = text;
							sectionXmlInfo4.ConfigSourceStreamName = text2;
							sectionXmlInfo4.ConfigSourceStreamVersion = configSourceStreamVersion;
							sectionXmlInfo4.ProtectionProviderName = configurationSection.SectionInformation.ProtectionProviderName;
							sectionXmlInfo4.OverrideModeSetting = configurationSection.SectionInformation.OverrideModeSetting;
							sectionXmlInfo4.SkipInChildApps = !configurationSection.SectionInformation.InheritInChildApplications;
						}
						sectionInput.ProtectionProvider = configurationSection.SectionInformation.ProtectionProvider;
					}
					try
					{
						configurationSection.ResetModified();
					}
					catch (Exception inner)
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", value2.ConfigKey), inner, base.ConfigStreamInfo.StreamName, 0);
					}
					catch
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", value2.ConfigKey), null, base.ConfigStreamInfo.StreamName, 0);
					}
				}
			}
			foreach (StreamInfo value3 in _streamInfoUpdates.Values)
			{
				if (!base.ConfigStreamInfo.StreamInfos.Contains(value3.StreamName))
				{
					MonitorStream(value3.SectionName, value3.ConfigSource, value3.StreamName);
				}
			}
			InitStreamInfoUpdates();
			_flags[512] = _flags[67108864];
			_flags[16777216] = false;
			_flags[33554432] = false;
			if (!base.IsLocationConfig && _locationSections != null && _removedSections != null && _removedSections.Count > 0)
			{
				int num = 0;
				while (num < _locationSections.Count)
				{
					LocationSectionRecord locationSectionRecord = (LocationSectionRecord)_locationSections[num];
					if (_removedSections.Contains(locationSectionRecord.ConfigKey))
					{
						_locationSections.RemoveAt(num);
					}
					else
					{
						num++;
					}
				}
			}
			_removedSections = null;
			_removedSectionGroups = null;
		}

		private void CreateNewConfig(SectionUpdates declarationUpdates, ConfigDefinitionUpdates definitionUpdates, NamespaceChange namespaceChange, XmlUtilWriter utilWriter)
		{
			int linePosition = 5;
			int indent = 4;
			utilWriter.Write(string.Format(CultureInfo.InvariantCulture, "<?xml version=\"1.0\" encoding=\"{0}\"?>\r\n", base.ConfigStreamInfo.StreamEncoding.WebName));
			if (namespaceChange == NamespaceChange.Add)
			{
				utilWriter.Write(string.Format(CultureInfo.InvariantCulture, "<configuration xmlns=\"{0}\">\r\n", "http://schemas.microsoft.com/.NetConfiguration/v2.0"));
			}
			else
			{
				utilWriter.Write("<configuration>\r\n");
			}
			if (declarationUpdates != null)
			{
				WriteNewConfigDeclarations(declarationUpdates, utilWriter, linePosition, indent, skipFirstIndent: false);
			}
			WriteNewConfigDefinitions(definitionUpdates, utilWriter, linePosition, indent);
			utilWriter.Write("</configuration>");
		}

		private void WriteNewConfigDeclarations(SectionUpdates declarationUpdates, XmlUtilWriter utilWriter, int linePosition, int indent, bool skipFirstIndent)
		{
			if (!skipFirstIndent)
			{
				utilWriter.AppendSpacesToLinePosition(linePosition);
			}
			utilWriter.Write("<configSections>\r\n");
			WriteUnwrittenConfigDeclarations(declarationUpdates, utilWriter, linePosition + indent, indent, skipFirstIndent: false);
			utilWriter.AppendSpacesToLinePosition(linePosition);
			utilWriter.Write("</configSections>\r\n");
			if (skipFirstIndent)
			{
				utilWriter.AppendSpacesToLinePosition(linePosition);
			}
		}

		private void WriteUnwrittenConfigDeclarations(SectionUpdates declarationUpdates, XmlUtilWriter utilWriter, int linePosition, int indent, bool skipFirstIndent)
		{
			WriteUnwrittenConfigDeclarationsRecursive(declarationUpdates, utilWriter, linePosition, indent, skipFirstIndent);
		}

		private void WriteUnwrittenConfigDeclarationsRecursive(SectionUpdates declarationUpdates, XmlUtilWriter utilWriter, int linePosition, int indent, bool skipFirstIndent)
		{
			string[] unretrievedSectionNames = declarationUpdates.GetUnretrievedSectionNames();
			if (unretrievedSectionNames != null)
			{
				string[] array = unretrievedSectionNames;
				foreach (string configKey in array)
				{
					if (!skipFirstIndent)
					{
						utilWriter.AppendSpacesToLinePosition(linePosition);
					}
					skipFirstIndent = false;
					DeclarationUpdate declarationUpdate = declarationUpdates.GetDeclarationUpdate(configKey);
					utilWriter.Write(declarationUpdate.UpdatedXml);
					utilWriter.AppendNewLine();
				}
			}
			string[] unretrievedGroupNames = declarationUpdates.GetUnretrievedGroupNames();
			if (unretrievedGroupNames == null)
			{
				return;
			}
			string[] array2 = unretrievedGroupNames;
			foreach (string text in array2)
			{
				if (!skipFirstIndent)
				{
					utilWriter.AppendSpacesToLinePosition(linePosition);
				}
				skipFirstIndent = false;
				SectionUpdates sectionUpdatesForGroup = declarationUpdates.GetSectionUpdatesForGroup(text);
				DeclarationUpdate sectionGroupUpdate = sectionUpdatesForGroup.GetSectionGroupUpdate();
				if (sectionGroupUpdate == null)
				{
					utilWriter.Write("<sectionGroup name=\"" + text + "\">");
				}
				else
				{
					utilWriter.Write(sectionGroupUpdate.UpdatedXml);
				}
				utilWriter.AppendNewLine();
				WriteUnwrittenConfigDeclarationsRecursive(sectionUpdatesForGroup, utilWriter, linePosition + indent, indent, skipFirstIndent: false);
				utilWriter.AppendSpacesToLinePosition(linePosition);
				utilWriter.Write("</sectionGroup>\r\n");
			}
		}

		private void WriteNewConfigDefinitions(ConfigDefinitionUpdates configDefinitionUpdates, XmlUtilWriter utilWriter, int linePosition, int indent)
		{
			if (configDefinitionUpdates == null)
			{
				return;
			}
			foreach (LocationUpdates locationUpdates in configDefinitionUpdates.LocationUpdatesList)
			{
				SectionUpdates sectionUpdates = locationUpdates.SectionUpdates;
				if (sectionUpdates.IsEmpty || !sectionUpdates.IsNew)
				{
					continue;
				}
				configDefinitionUpdates.FlagLocationWritten();
				bool flag = _locationSubPath != null || !locationUpdates.IsDefault;
				int num = linePosition;
				utilWriter.AppendSpacesToLinePosition(linePosition);
				if (flag)
				{
					if (_locationSubPath == null)
					{
						utilWriter.Write(string.Format(CultureInfo.InvariantCulture, "<location {0} inheritInChildApplications=\"{1}\">\r\n", locationUpdates.OverrideMode.LocationTagXmlString, BoolToString(locationUpdates.InheritInChildApps)));
					}
					else
					{
						utilWriter.Write(string.Format(CultureInfo.InvariantCulture, "<location path=\"{2}\" {0} inheritInChildApplications=\"{1}\">\r\n", locationUpdates.OverrideMode.LocationTagXmlString, BoolToString(locationUpdates.InheritInChildApps), _locationSubPath));
					}
					num += indent;
					utilWriter.AppendSpacesToLinePosition(num);
				}
				WriteNewConfigDefinitionsRecursive(utilWriter, locationUpdates.SectionUpdates, num, indent, skipFirstIndent: true);
				if (flag)
				{
					utilWriter.AppendSpacesToLinePosition(linePosition);
					utilWriter.Write("</location>");
					utilWriter.AppendNewLine();
				}
			}
			if (configDefinitionUpdates.RequireLocation)
			{
				configDefinitionUpdates.FlagLocationWritten();
				utilWriter.AppendSpacesToLinePosition(linePosition);
				utilWriter.Write(string.Format(CultureInfo.InvariantCulture, "<location path=\"{2}\" {0} inheritInChildApplications=\"{1}\">\r\n", OverrideModeSetting.LocationDefault.LocationTagXmlString, "true", _locationSubPath));
				utilWriter.AppendSpacesToLinePosition(linePosition);
				utilWriter.Write("</location>");
				utilWriter.AppendNewLine();
			}
		}

		private bool WriteNewConfigDefinitionsRecursive(XmlUtilWriter utilWriter, SectionUpdates sectionUpdates, int linePosition, int indent, bool skipFirstIndent)
		{
			bool result = false;
			string[] movedSectionNames = sectionUpdates.GetMovedSectionNames();
			if (movedSectionNames != null)
			{
				result = true;
				string[] array = movedSectionNames;
				foreach (string configKey in array)
				{
					DefinitionUpdate definitionUpdate = sectionUpdates.GetDefinitionUpdate(configKey);
					WriteSectionUpdate(utilWriter, definitionUpdate, linePosition, indent, skipFirstIndent);
					utilWriter.AppendNewLine();
					skipFirstIndent = false;
				}
			}
			string[] newGroupNames = sectionUpdates.GetNewGroupNames();
			if (newGroupNames != null)
			{
				string[] array2 = newGroupNames;
				foreach (string text in array2)
				{
					if (!skipFirstIndent)
					{
						utilWriter.AppendSpacesToLinePosition(linePosition);
					}
					skipFirstIndent = false;
					utilWriter.Write("<" + text + ">\r\n");
					if (WriteNewConfigDefinitionsRecursive(utilWriter, sectionUpdates.GetSectionUpdatesForGroup(text), linePosition + indent, indent, skipFirstIndent: false))
					{
						result = true;
					}
					utilWriter.AppendSpacesToLinePosition(linePosition);
					utilWriter.Write("</" + text + ">\r\n");
				}
			}
			sectionUpdates.IsNew = false;
			return result;
		}

		private void CheckPreamble(byte[] preamble, XmlUtilWriter utilWriter, byte[] buffer)
		{
			bool flag = false;
			using (Stream stream = new MemoryStream(buffer))
			{
				byte[] array = new byte[preamble.Length];
				if (stream.Read(array, 0, array.Length) == array.Length)
				{
					flag = true;
					for (int i = 0; i < array.Length; i++)
					{
						if (array[i] != preamble[i])
						{
							flag = false;
							break;
						}
					}
				}
			}
			if (!flag)
			{
				object o = utilWriter.CreateStreamCheckpoint();
				utilWriter.Write('x');
				utilWriter.RestoreStreamCheckpoint(o);
			}
		}

		private int UpdateIndent(int oldIndent, XmlUtil xmlUtil, XmlUtilWriter utilWriter, int parentLinePosition)
		{
			int result = oldIndent;
			if (xmlUtil.Reader.NodeType == XmlNodeType.Element && utilWriter.IsLastLineBlank)
			{
				int trueLinePosition = xmlUtil.TrueLinePosition;
				if (parentLinePosition < trueLinePosition && trueLinePosition <= parentLinePosition + 10)
				{
					result = trueLinePosition - parentLinePosition;
				}
			}
			return result;
		}

		private void CopyConfig(SectionUpdates declarationUpdates, ConfigDefinitionUpdates definitionUpdates, byte[] buffer, string filename, NamespaceChange namespaceChange, XmlUtilWriter utilWriter)
		{
			CheckPreamble(base.ConfigStreamInfo.StreamEncoding.GetPreamble(), utilWriter, buffer);
			using Stream stream = new MemoryStream(buffer);
			using XmlUtil xmlUtil = new XmlUtil(stream, filename, readToFirstElement: false);
			XmlTextReader reader = xmlUtil.Reader;
			reader.WhitespaceHandling = WhitespaceHandling.All;
			reader.Read();
			xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: false);
			int num = 4;
			int trueLinePosition = xmlUtil.TrueLinePosition;
			bool isEmptyElement = reader.IsEmptyElement;
			string updatedStartElement = namespaceChange switch
			{
				NamespaceChange.Add => string.Format(CultureInfo.InvariantCulture, "<configuration xmlns=\"{0}\">\r\n", "http://schemas.microsoft.com/.NetConfiguration/v2.0"), 
				NamespaceChange.Remove => "<configuration>\r\n", 
				_ => null, 
			};
			bool needsChildren = declarationUpdates != null || definitionUpdates != null;
			string text = xmlUtil.UpdateStartElement(utilWriter, updatedStartElement, needsChildren, trueLinePosition, num);
			bool flag = false;
			if (!isEmptyElement)
			{
				xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: true);
				num = UpdateIndent(num, xmlUtil, utilWriter, trueLinePosition);
				if (reader.NodeType == XmlNodeType.Element && reader.Name == "configSections")
				{
					flag = true;
					int trueLinePosition2 = xmlUtil.TrueLinePosition;
					bool isEmptyElement2 = reader.IsEmptyElement;
					if (declarationUpdates == null)
					{
						xmlUtil.CopyOuterXmlToNextElement(utilWriter, limitDepth: true);
					}
					else
					{
						string text2 = xmlUtil.UpdateStartElement(utilWriter, null, needsChildren: true, trueLinePosition2, num);
						if (!isEmptyElement2)
						{
							xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: true);
							CopyConfigDeclarationsRecursive(declarationUpdates, xmlUtil, utilWriter, string.Empty, trueLinePosition2, num);
						}
						if (declarationUpdates.HasUnretrievedSections())
						{
							int linePosition = 0;
							if (text2 == null)
							{
								linePosition = xmlUtil.TrueLinePosition;
							}
							if (!utilWriter.IsLastLineBlank)
							{
								utilWriter.AppendNewLine();
							}
							WriteUnwrittenConfigDeclarations(declarationUpdates, utilWriter, trueLinePosition2 + num, num, skipFirstIndent: false);
							if (text2 == null)
							{
								utilWriter.AppendSpacesToLinePosition(linePosition);
							}
						}
						if (text2 == null)
						{
							xmlUtil.CopyXmlNode(utilWriter);
						}
						else
						{
							utilWriter.Write(text2);
						}
						xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: true);
					}
				}
			}
			if (!flag && declarationUpdates != null)
			{
				bool flag2 = reader.Depth > 0 && reader.NodeType == XmlNodeType.Element;
				int linePosition2 = ((!flag2) ? (trueLinePosition + num) : xmlUtil.TrueLinePosition);
				WriteNewConfigDeclarations(declarationUpdates, utilWriter, linePosition2, num, flag2);
			}
			if (definitionUpdates != null)
			{
				bool locationPathApplies = false;
				LocationUpdates locationUpdates = null;
				SectionUpdates sectionUpdates = null;
				if (!base.IsLocationConfig)
				{
					locationPathApplies = true;
					locationUpdates = definitionUpdates.FindLocationUpdates(OverrideModeSetting.LocationDefault, inheritInChildApps: true);
					if (locationUpdates != null)
					{
						sectionUpdates = locationUpdates.SectionUpdates;
					}
				}
				CopyConfigDefinitionsRecursive(definitionUpdates, xmlUtil, utilWriter, locationPathApplies, locationUpdates, sectionUpdates, addNewSections: true, string.Empty, trueLinePosition, num);
				WriteNewConfigDefinitions(definitionUpdates, utilWriter, trueLinePosition + num, num);
			}
			if (text != null)
			{
				if (!utilWriter.IsLastLineBlank)
				{
					utilWriter.AppendNewLine();
				}
				utilWriter.Write(text);
			}
			while (xmlUtil.CopyXmlNode(utilWriter))
			{
			}
		}

		private bool CopyConfigDeclarationsRecursive(SectionUpdates declarationUpdates, XmlUtil xmlUtil, XmlUtilWriter utilWriter, string group, int parentLinePosition, int parentIndent)
		{
			bool result = false;
			XmlTextReader reader = xmlUtil.Reader;
			int num = UpdateIndent(parentIndent, xmlUtil, utilWriter, parentLinePosition);
			int linePosition;
			int num2;
			if (reader.NodeType == XmlNodeType.Element)
			{
				num2 = xmlUtil.TrueLinePosition;
				linePosition = num2;
			}
			else if (reader.NodeType == XmlNodeType.EndElement)
			{
				num2 = parentLinePosition + num;
				linePosition = ((!utilWriter.IsLastLineBlank) ? parentLinePosition : xmlUtil.TrueLinePosition);
			}
			else
			{
				num2 = parentLinePosition + num;
				linePosition = 0;
			}
			if (declarationUpdates != null)
			{
				string[] movedSectionNames = declarationUpdates.GetMovedSectionNames();
				if (movedSectionNames != null)
				{
					if (!utilWriter.IsLastLineBlank)
					{
						utilWriter.AppendNewLine();
					}
					string[] array = movedSectionNames;
					foreach (string configKey in array)
					{
						DeclarationUpdate declarationUpdate = declarationUpdates.GetDeclarationUpdate(configKey);
						utilWriter.AppendSpacesToLinePosition(num2);
						utilWriter.Write(declarationUpdate.UpdatedXml);
						utilWriter.AppendNewLine();
						result = true;
					}
					utilWriter.AppendSpacesToLinePosition(linePosition);
				}
			}
			if (reader.NodeType == XmlNodeType.Element)
			{
				int depth = reader.Depth;
				while (reader.Depth == depth)
				{
					bool flag = false;
					DeclarationUpdate declarationUpdate2 = null;
					DeclarationUpdate declarationUpdate3 = null;
					SectionUpdates sectionUpdates = null;
					SectionUpdates declarationUpdates2 = declarationUpdates;
					string group2 = group;
					num = UpdateIndent(num, xmlUtil, utilWriter, parentLinePosition);
					num2 = xmlUtil.TrueLinePosition;
					string name = reader.Name;
					string attribute = reader.GetAttribute("name");
					string text = BaseConfigurationRecord.CombineConfigKey(group, attribute);
					if (name == "sectionGroup")
					{
						sectionUpdates = declarationUpdates.GetSectionUpdatesForGroup(attribute);
						if (sectionUpdates != null)
						{
							declarationUpdate3 = sectionUpdates.GetSectionGroupUpdate();
							if (sectionUpdates.HasUnretrievedSections())
							{
								flag = true;
								group2 = text;
								declarationUpdates2 = sectionUpdates;
							}
						}
					}
					else
					{
						declarationUpdate2 = declarationUpdates.GetDeclarationUpdate(text);
					}
					bool flag2 = declarationUpdate3 != null && declarationUpdate3.UpdatedXml != null;
					if (flag)
					{
						object o = utilWriter.CreateStreamCheckpoint();
						string text2 = null;
						if (flag2)
						{
							utilWriter.Write(declarationUpdate3.UpdatedXml);
							reader.Read();
						}
						else
						{
							text2 = xmlUtil.UpdateStartElement(utilWriter, null, needsChildren: true, num2, num);
						}
						if (text2 == null)
						{
							xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: true);
						}
						bool flag3 = CopyConfigDeclarationsRecursive(declarationUpdates2, xmlUtil, utilWriter, group2, num2, num);
						if (text2 != null)
						{
							utilWriter.AppendSpacesToLinePosition(num2);
							utilWriter.Write(text2);
							utilWriter.AppendSpacesToLinePosition(parentLinePosition);
						}
						else
						{
							xmlUtil.CopyXmlNode(utilWriter);
						}
						if (flag3 || flag2)
						{
							result = true;
						}
						else
						{
							utilWriter.RestoreStreamCheckpoint(o);
						}
						xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: true);
						continue;
					}
					bool flag4 = false;
					bool flag5;
					if (declarationUpdate2 == null)
					{
						flag5 = true;
						if (flag2)
						{
							result = true;
							utilWriter.Write(declarationUpdate3.UpdatedXml);
							utilWriter.AppendNewLine();
							utilWriter.AppendSpacesToLinePosition(num2);
							utilWriter.Write("</sectionGroup>");
							utilWriter.AppendNewLine();
							utilWriter.AppendSpacesToLinePosition(num2);
						}
						else if (declarationUpdate3 != null)
						{
							result = true;
							flag5 = false;
							flag4 = true;
						}
					}
					else
					{
						result = true;
						if (declarationUpdate2.UpdatedXml == null)
						{
							flag5 = false;
						}
						else
						{
							flag5 = true;
							utilWriter.Write(declarationUpdate2.UpdatedXml);
						}
					}
					if (flag5)
					{
						xmlUtil.SkipAndCopyReaderToNextElement(utilWriter, limitDepth: true);
					}
					else if (flag4)
					{
						xmlUtil.SkipChildElementsAndCopyOuterXmlToNextElement(utilWriter);
					}
					else
					{
						xmlUtil.CopyOuterXmlToNextElement(utilWriter, limitDepth: true);
					}
				}
			}
			return result;
		}

		private bool CopyConfigDefinitionsRecursive(ConfigDefinitionUpdates configDefinitionUpdates, XmlUtil xmlUtil, XmlUtilWriter utilWriter, bool locationPathApplies, LocationUpdates locationUpdates, SectionUpdates sectionUpdates, bool addNewSections, string group, int parentLinePosition, int parentIndent)
		{
			bool result = false;
			XmlTextReader reader = xmlUtil.Reader;
			int num = UpdateIndent(parentIndent, xmlUtil, utilWriter, parentLinePosition);
			int num2;
			int linePosition;
			if (reader.NodeType == XmlNodeType.Element)
			{
				num2 = xmlUtil.TrueLinePosition;
				linePosition = num2;
			}
			else if (reader.NodeType == XmlNodeType.EndElement)
			{
				num2 = parentLinePosition + num;
				linePosition = ((!utilWriter.IsLastLineBlank) ? parentLinePosition : xmlUtil.TrueLinePosition);
			}
			else
			{
				num2 = parentLinePosition + num;
				linePosition = 0;
			}
			if (sectionUpdates != null && addNewSections)
			{
				sectionUpdates.IsNew = false;
				string[] movedSectionNames = sectionUpdates.GetMovedSectionNames();
				if (movedSectionNames != null)
				{
					if (!utilWriter.IsLastLineBlank)
					{
						utilWriter.AppendNewLine();
					}
					utilWriter.AppendSpacesToLinePosition(num2);
					bool skipFirstIndent = true;
					string[] array = movedSectionNames;
					foreach (string configKey in array)
					{
						DefinitionUpdate definitionUpdate = sectionUpdates.GetDefinitionUpdate(configKey);
						WriteSectionUpdate(utilWriter, definitionUpdate, num2, num, skipFirstIndent);
						skipFirstIndent = false;
						utilWriter.AppendNewLine();
						result = true;
					}
					utilWriter.AppendSpacesToLinePosition(linePosition);
				}
			}
			if (reader.NodeType == XmlNodeType.Element)
			{
				int depth = reader.Depth;
				while (reader.Depth == depth)
				{
					bool flag = false;
					DefinitionUpdate definitionUpdate2 = null;
					bool flag2 = locationPathApplies;
					LocationUpdates locationUpdates2 = locationUpdates;
					SectionUpdates sectionUpdates2 = sectionUpdates;
					bool addNewSections2 = addNewSections;
					string group2 = group;
					bool flag3 = false;
					num = UpdateIndent(num, xmlUtil, utilWriter, parentLinePosition);
					num2 = xmlUtil.TrueLinePosition;
					string name = reader.Name;
					if (name == "location")
					{
						string attribute = reader.GetAttribute("path");
						attribute = BaseConfigurationRecord.NormalizeLocationSubPath(attribute, xmlUtil);
						flag2 = false;
						OverrideModeSetting overrideMode = OverrideModeSetting.LocationDefault;
						bool inheritInChildApps = true;
						flag2 = ((!base.IsLocationConfig) ? (attribute == null) : (attribute != null && StringUtil.EqualsIgnoreCase(base.ConfigPath, base.Host.GetConfigPathFromLocationSubPath(base.Parent.ConfigPath, attribute))));
						if (flag2)
						{
							string attribute2 = reader.GetAttribute("allowOverride");
							if (attribute2 != null)
							{
								overrideMode = OverrideModeSetting.CreateFromXmlReadValue(bool.Parse(attribute2));
							}
							string attribute3 = reader.GetAttribute("overrideMode");
							if (attribute3 != null)
							{
								overrideMode = OverrideModeSetting.CreateFromXmlReadValue(OverrideModeSetting.ParseOverrideModeXmlValue(attribute3, null));
							}
							string attribute4 = reader.GetAttribute("inheritInChildApplications");
							if (attribute4 != null)
							{
								inheritInChildApps = bool.Parse(attribute4);
							}
							configDefinitionUpdates.FlagLocationWritten();
						}
						if (reader.IsEmptyElement)
						{
							flag2 = ((flag2 && configDefinitionUpdates.FindLocationUpdates(overrideMode, inheritInChildApps) != null) ? true : false);
						}
						else if (flag2)
						{
							if (configDefinitionUpdates != null)
							{
								locationUpdates2 = configDefinitionUpdates.FindLocationUpdates(overrideMode, inheritInChildApps);
								if (locationUpdates2 != null)
								{
									flag = true;
									sectionUpdates2 = locationUpdates2.SectionUpdates;
									if (_locationSubPath == null && locationUpdates2.IsDefault)
									{
										addNewSections2 = false;
									}
								}
							}
						}
						else if (HasRemovedSectionsOrGroups && !base.IsLocationConfig && base.Host.SupportsLocation)
						{
							flag = true;
							locationUpdates2 = null;
							sectionUpdates2 = null;
							addNewSections2 = false;
						}
					}
					else
					{
						string text = BaseConfigurationRecord.CombineConfigKey(group, name);
						FactoryRecord factoryRecord = FindFactoryRecord(text, permitErrors: false);
						if (factoryRecord == null)
						{
							if (!flag2 && !base.IsLocationConfig)
							{
								flag3 = true;
							}
						}
						else if (factoryRecord.IsGroup)
						{
							if (reader.IsEmptyElement)
							{
								if (!flag2 && !base.IsLocationConfig)
								{
									flag3 = true;
								}
							}
							else if (sectionUpdates != null)
							{
								SectionUpdates sectionUpdatesForGroup = sectionUpdates.GetSectionUpdatesForGroup(name);
								if (sectionUpdatesForGroup != null)
								{
									flag = true;
									group2 = text;
									sectionUpdates2 = sectionUpdatesForGroup;
								}
							}
							else if (!flag2 && !base.IsLocationConfig)
							{
								if (_removedSectionGroups != null && _removedSectionGroups.Contains(text))
								{
									flag3 = true;
								}
								else
								{
									flag = true;
									group2 = text;
									locationUpdates2 = null;
									sectionUpdates2 = null;
									addNewSections2 = false;
								}
							}
						}
						else if (sectionUpdates != null)
						{
							definitionUpdate2 = sectionUpdates.GetDefinitionUpdate(text);
						}
						else if (!flag2 && !base.IsLocationConfig && _removedSections != null && _removedSections.Contains(text))
						{
							flag3 = true;
						}
					}
					if (flag)
					{
						object o = utilWriter.CreateStreamCheckpoint();
						xmlUtil.CopyXmlNode(utilWriter);
						xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: true);
						bool flag4 = CopyConfigDefinitionsRecursive(configDefinitionUpdates, xmlUtil, utilWriter, flag2, locationUpdates2, sectionUpdates2, addNewSections2, group2, num2, num);
						xmlUtil.CopyXmlNode(utilWriter);
						if (flag4)
						{
							result = true;
						}
						else
						{
							utilWriter.RestoreStreamCheckpoint(o);
						}
						xmlUtil.CopyReaderToNextElement(utilWriter, limitDepth: true);
						continue;
					}
					bool flag5;
					if (definitionUpdate2 == null)
					{
						flag5 = flag2 || flag3;
					}
					else
					{
						flag5 = false;
						if (definitionUpdate2.UpdatedXml != null)
						{
							ConfigurationSection configurationSection = (ConfigurationSection)definitionUpdate2.SectionRecord.Result;
							if (string.IsNullOrEmpty(configurationSection.SectionInformation.ConfigSource) || configurationSection.SectionInformation.ConfigSourceModified)
							{
								flag5 = true;
								WriteSectionUpdate(utilWriter, definitionUpdate2, num2, num, skipFirstIndent: true);
								result = true;
							}
						}
					}
					if (flag5)
					{
						xmlUtil.SkipAndCopyReaderToNextElement(utilWriter, limitDepth: true);
						continue;
					}
					xmlUtil.CopyOuterXmlToNextElement(utilWriter, limitDepth: true);
					result = true;
				}
			}
			if (sectionUpdates != null && addNewSections && sectionUpdates.HasNewSectionGroups())
			{
				num2 = parentLinePosition + num;
				linePosition = ((reader.NodeType == XmlNodeType.EndElement) ? ((!utilWriter.IsLastLineBlank) ? parentLinePosition : xmlUtil.TrueLinePosition) : 0);
				utilWriter.AppendSpacesToLinePosition(num2);
				if (WriteNewConfigDefinitionsRecursive(utilWriter, sectionUpdates, num2, num, skipFirstIndent: true))
				{
					result = true;
				}
				utilWriter.AppendSpacesToLinePosition(linePosition);
			}
			return result;
		}

		private void WriteSectionUpdate(XmlUtilWriter utilWriter, DefinitionUpdate update, int linePosition, int indent, bool skipFirstIndent)
		{
			ConfigurationSection configurationSection = (ConfigurationSection)update.SectionRecord.Result;
			string xmlElement = (string.IsNullOrEmpty(configurationSection.SectionInformation.ConfigSource) ? update.UpdatedXml : string.Format(CultureInfo.InvariantCulture, "<{0} configSource=\"{1}\" />", configurationSection.SectionInformation.Name, configurationSection.SectionInformation.ConfigSource));
			string s = XmlUtil.FormatXmlElement(xmlElement, linePosition, indent, skipFirstIndent);
			utilWriter.Write(s);
		}

		private void SaveConfigSource(DefinitionUpdate update)
		{
			string configSourceStreamName;
			if (update.SectionRecord.HasResult)
			{
				ConfigurationSection configurationSection = (ConfigurationSection)update.SectionRecord.Result;
				configSourceStreamName = configurationSection.SectionInformation.ConfigSourceStreamName;
			}
			else
			{
				SectionInput fileInput = update.SectionRecord.FileInput;
				configSourceStreamName = fileInput.SectionXmlInfo.ConfigSourceStreamName;
			}
			byte[] array = null;
			using (Stream stream = base.Host.OpenStreamForRead(configSourceStreamName))
			{
				if (stream != null)
				{
					array = new byte[stream.Length];
					int num = stream.Read(array, 0, (int)stream.Length);
					if (num != stream.Length)
					{
						throw new ConfigurationErrorsException();
					}
				}
			}
			bool flag = array != null;
			object writeContext = null;
			bool flag2 = false;
			try
			{
				try
				{
					string templateStreamName = ((!base.Host.IsRemote) ? base.ConfigStreamInfo.StreamName : null);
					using Stream stream2 = base.Host.OpenStreamForWrite(configSourceStreamName, templateStreamName, ref writeContext);
					flag2 = true;
					if (update.UpdatedXml == null)
					{
						if (flag)
						{
							stream2.Write(array, 0, array.Length);
						}
					}
					else
					{
						using StreamWriter writer = new StreamWriter(stream2);
						XmlUtilWriter utilWriter = new XmlUtilWriter(writer, trackPosition: true);
						if (flag)
						{
							CopyConfigSource(utilWriter, update.UpdatedXml, configSourceStreamName, array);
						}
						else
						{
							CreateNewConfigSource(utilWriter, update.UpdatedXml, 4);
						}
					}
				}
				catch
				{
					if (flag2)
					{
						base.Host.WriteCompleted(configSourceStreamName, success: false, writeContext);
					}
					throw;
				}
			}
			catch (Exception e)
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), e, configSourceStreamName, 0);
			}
			catch
			{
				throw ExceptionUtil.WrapAsConfigException(SR.GetString("Config_error_loading_XML_file"), null, configSourceStreamName, 0);
			}
			base.Host.WriteCompleted(configSourceStreamName, success: true, writeContext);
		}

		private void CopyConfigSource(XmlUtilWriter utilWriter, string updatedXml, string configSourceStreamName, byte[] buffer)
		{
			byte[] preamble;
			using (Stream stream = new MemoryStream(buffer))
			{
				using (new XmlUtil(stream, configSourceStreamName, readToFirstElement: true))
				{
					preamble = base.ConfigStreamInfo.StreamEncoding.GetPreamble();
				}
			}
			CheckPreamble(preamble, utilWriter, buffer);
			using Stream stream2 = new MemoryStream(buffer);
			using XmlUtil xmlUtil2 = new XmlUtil(stream2, configSourceStreamName, readToFirstElement: false);
			XmlTextReader reader = xmlUtil2.Reader;
			reader.WhitespaceHandling = WhitespaceHandling.All;
			reader.Read();
			int indent = 4;
			int num = 1;
			bool flag = xmlUtil2.CopyReaderToNextElement(utilWriter, limitDepth: false);
			if (flag)
			{
				int lineNumber = reader.LineNumber;
				num = reader.LinePosition - 1;
				int num2 = 0;
				while (reader.MoveToNextAttribute())
				{
					if (reader.LineNumber > lineNumber)
					{
						num2 = reader.LinePosition - num;
						break;
					}
				}
				int num3 = 0;
				reader.Read();
				while (reader.Depth >= 1)
				{
					if (reader.NodeType == XmlNodeType.Element)
					{
						num3 = reader.LinePosition - 1 - num;
						break;
					}
					reader.Read();
				}
				if (num3 > 0)
				{
					indent = num3;
				}
				else if (num2 > 0)
				{
					indent = num2;
				}
			}
			string s = XmlUtil.FormatXmlElement(updatedXml, num, indent, skipFirstIndent: true);
			utilWriter.Write(s);
			if (flag)
			{
				while (reader.Depth > 0)
				{
					reader.Read();
				}
				if (reader.IsEmptyElement || reader.NodeType == XmlNodeType.EndElement)
				{
					reader.Read();
				}
				while (xmlUtil2.CopyXmlNode(utilWriter))
				{
				}
			}
		}

		private void CreateNewConfigSource(XmlUtilWriter utilWriter, string updatedXml, int indent)
		{
			string text = XmlUtil.FormatXmlElement(updatedXml, 0, indent, skipFirstIndent: true);
			utilWriter.Write(string.Format(CultureInfo.InvariantCulture, "<?xml version=\"1.0\" encoding=\"{0}\"?>\r\n", base.ConfigStreamInfo.StreamEncoding.WebName));
			utilWriter.Write(text + "\r\n");
		}

		private static string BoolToString(bool v)
		{
			if (!v)
			{
				return "false";
			}
			return "true";
		}

		internal void RemoveLocationWriteRequirement()
		{
			if (base.IsLocationConfig)
			{
				_flags[16777216] = false;
				_flags[33554432] = true;
			}
		}
	}
	internal enum NamespaceChange
	{
		None,
		Add,
		Remove
	}
	[ConfigurationCollection(typeof(NameValueConfigurationElement))]
	public sealed class NameValueConfigurationCollection : ConfigurationElementCollection
	{
		private static ConfigurationPropertyCollection _properties;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		public new NameValueConfigurationElement this[string name]
		{
			get
			{
				return (NameValueConfigurationElement)BaseGet(name);
			}
			set
			{
				int index = -1;
				NameValueConfigurationElement nameValueConfigurationElement = (NameValueConfigurationElement)BaseGet(name);
				if (nameValueConfigurationElement != null)
				{
					index = BaseIndexOf(nameValueConfigurationElement);
					BaseRemoveAt(index);
				}
				BaseAdd(index, value);
			}
		}

		public string[] AllKeys => StringUtil.ObjectArrayToStringArray(BaseGetAllKeys());

		static NameValueConfigurationCollection()
		{
			_properties = new ConfigurationPropertyCollection();
		}

		public void Add(NameValueConfigurationElement nameValue)
		{
			BaseAdd(nameValue);
		}

		public void Remove(NameValueConfigurationElement nameValue)
		{
			if (BaseIndexOf(nameValue) >= 0)
			{
				BaseRemove(nameValue.Name);
			}
		}

		public void Remove(string name)
		{
			BaseRemove(name);
		}

		public void Clear()
		{
			BaseClear();
		}

		protected override ConfigurationElement CreateNewElement()
		{
			return new NameValueConfigurationElement();
		}

		protected override object GetElementKey(ConfigurationElement element)
		{
			return ((NameValueConfigurationElement)element).Name;
		}
	}
	public sealed class NameValueConfigurationElement : ConfigurationElement
	{
		private static ConfigurationPropertyCollection _properties;

		private static readonly ConfigurationProperty _propName;

		private static readonly ConfigurationProperty _propValue;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		[ConfigurationProperty("name", IsKey = true, DefaultValue = "")]
		public string Name => (string)base[_propName];

		[ConfigurationProperty("value", DefaultValue = "")]
		public string Value
		{
			get
			{
				return (string)base[_propValue];
			}
			set
			{
				base[_propValue] = value;
			}
		}

		static NameValueConfigurationElement()
		{
			_propName = new ConfigurationProperty("name", typeof(string), string.Empty, ConfigurationPropertyOptions.IsKey);
			_propValue = new ConfigurationProperty("value", typeof(string), string.Empty, ConfigurationPropertyOptions.None);
			_properties = new ConfigurationPropertyCollection();
			_properties.Add(_propName);
			_properties.Add(_propValue);
		}

		internal NameValueConfigurationElement()
		{
		}

		public NameValueConfigurationElement(string name, string value)
		{
			base[_propName] = name;
			base[_propValue] = value;
		}
	}
	public enum OverrideMode
	{
		Inherit,
		Allow,
		Deny
	}
	internal struct OverrideModeSetting
	{
		private const byte ApiDefinedLegacy = 16;

		private const byte ApiDefinedNewMode = 32;

		private const byte ApiDefinedAny = 48;

		private const byte XmlDefinedLegacy = 64;

		private const byte XmlDefinedNewMode = 128;

		private const byte XmlDefinedAny = 192;

		private const byte ModeMask = 15;

		private byte _mode;

		internal static OverrideModeSetting SectionDefault;

		internal static OverrideModeSetting LocationDefault;

		internal bool IsDefaultForSection
		{
			get
			{
				OverrideMode overrideMode = OverrideMode;
				if (overrideMode != OverrideMode.Allow)
				{
					return overrideMode == OverrideMode.Inherit;
				}
				return true;
			}
		}

		internal bool IsDefaultForLocationTag
		{
			get
			{
				OverrideModeSetting locationDefault = LocationDefault;
				if (locationDefault.OverrideMode == OverrideMode && (_mode & 0x30) == 0)
				{
					return (_mode & 0xC0) == 0;
				}
				return false;
			}
		}

		internal bool IsLocked => OverrideMode == OverrideMode.Deny;

		internal string LocationTagXmlString
		{
			get
			{
				string result = string.Empty;
				string text = null;
				string text2 = null;
				bool flag = false;
				bool flag2 = false;
				if ((_mode & 0x30u) != 0)
				{
					flag2 = (_mode & 0x10) != 0;
					flag = true;
				}
				else if ((_mode & 0xC0u) != 0)
				{
					flag2 = (_mode & 0x40) != 0;
					flag = true;
				}
				if (flag)
				{
					if (flag2)
					{
						text2 = "allowOverride";
						text = (AllowOverride ? "true" : "false");
					}
					else
					{
						text2 = "overrideMode";
						text = OverrideModeXmlValue;
					}
					result = string.Format(CultureInfo.InvariantCulture, "{0}=\"{1}\"", text2, text);
				}
				return result;
			}
		}

		internal string OverrideModeXmlValue => OverrideMode switch
		{
			OverrideMode.Inherit => "Inherit", 
			OverrideMode.Allow => "Allow", 
			OverrideMode.Deny => "Deny", 
			_ => null, 
		};

		internal OverrideMode OverrideMode
		{
			get
			{
				return (OverrideMode)(_mode & 0xF);
			}
			set
			{
				VerifyConsistentChangeModel(32);
				SetMode(value);
				_mode |= 32;
			}
		}

		internal bool AllowOverride
		{
			get
			{
				bool result = true;
				switch (OverrideMode)
				{
				case OverrideMode.Inherit:
				case OverrideMode.Allow:
					result = true;
					break;
				case OverrideMode.Deny:
					result = false;
					break;
				}
				return result;
			}
			set
			{
				VerifyConsistentChangeModel(16);
				SetMode((!value) ? OverrideMode.Deny : OverrideMode.Inherit);
				_mode |= 16;
			}
		}

		static OverrideModeSetting()
		{
			SectionDefault = default(OverrideModeSetting);
			SectionDefault._mode = 1;
			LocationDefault = default(OverrideModeSetting);
			LocationDefault._mode = 0;
		}

		internal static OverrideModeSetting CreateFromXmlReadValue(bool allowOverride)
		{
			OverrideModeSetting result = default(OverrideModeSetting);
			result.SetMode((!allowOverride) ? OverrideMode.Deny : OverrideMode.Inherit);
			result._mode |= 64;
			return result;
		}

		internal static OverrideModeSetting CreateFromXmlReadValue(OverrideMode mode)
		{
			OverrideModeSetting result = default(OverrideModeSetting);
			result.SetMode(mode);
			result._mode |= 128;
			return result;
		}

		internal static OverrideMode ParseOverrideModeXmlValue(string value, XmlUtil xmlUtil)
		{
			return value switch
			{
				"Inherit" => OverrideMode.Inherit, 
				"Allow" => OverrideMode.Allow, 
				"Deny" => OverrideMode.Deny, 
				_ => throw new ConfigurationErrorsException(SR.GetString("Config_section_override_mode_attribute_invalid"), xmlUtil), 
			};
		}

		internal static bool CanUseSameLocationTag(OverrideModeSetting x, OverrideModeSetting y)
		{
			bool flag = false;
			flag = x.OverrideMode == y.OverrideMode;
			if (flag)
			{
				flag = false;
				flag = (((x._mode & 0x30u) != 0) ? IsMatchingApiChangedLocationTag(x, y) : (((y._mode & 0x30u) != 0) ? IsMatchingApiChangedLocationTag(y, x) : (((x._mode & 0xC0) == 0 && (y._mode & 0xC0) == 0) || (x._mode & 0xC0) == (y._mode & 0xC0))));
			}
			return flag;
		}

		private static bool IsMatchingApiChangedLocationTag(OverrideModeSetting x, OverrideModeSetting y)
		{
			bool result = false;
			if ((y._mode & 0x30u) != 0)
			{
				result = (x._mode & 0x30) == (y._mode & 0x30);
			}
			else if ((y._mode & 0xC0u) != 0)
			{
				result = ((x._mode & 0x10u) != 0 && (y._mode & 0x40u) != 0) || ((x._mode & 0x20u) != 0 && (y._mode & 0x80) != 0);
			}
			return result;
		}

		internal void ChangeModeInternal(OverrideMode mode)
		{
			SetMode(mode);
		}

		private void SetMode(OverrideMode mode)
		{
			_mode = (byte)mode;
		}

		private void VerifyConsistentChangeModel(byte required)
		{
			byte b = (byte)(_mode & 0x30u);
			if (b != 0 && b != required)
			{
				throw new ConfigurationErrorsException(SR.GetString("Cannot_change_both_AllowOverride_and_OverrideMode"));
			}
		}
	}
	public class PositiveTimeSpanValidator : ConfigurationValidatorBase
	{
		public override bool CanValidate(Type type)
		{
			return type == typeof(TimeSpan);
		}

		public override void Validate(object value)
		{
			if (value == null)
			{
				throw new ArgumentNullException("value");
			}
			if ((TimeSpan)value <= TimeSpan.Zero)
			{
				throw new ArgumentException(SR.GetString("Validator_timespan_value_must_be_positive"));
			}
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class PositiveTimeSpanValidatorAttribute : ConfigurationValidatorAttribute
	{
		public override ConfigurationValidatorBase ValidatorInstance => new PositiveTimeSpanValidator();
	}
	public sealed class PropertyInformation
	{
		private const string LockAll = "*";

		private ConfigurationElement ThisElement;

		private string PropertyName;

		private ConfigurationProperty _Prop;

		private ConfigurationProperty Prop
		{
			get
			{
				if (_Prop == null)
				{
					_Prop = ThisElement.Properties[PropertyName];
				}
				return _Prop;
			}
		}

		public string Name => PropertyName;

		internal string ProvidedName => Prop.ProvidedName;

		public object Value
		{
			get
			{
				return ThisElement[PropertyName];
			}
			set
			{
				ThisElement[PropertyName] = value;
			}
		}

		public object DefaultValue => Prop.DefaultValue;

		public PropertyValueOrigin ValueOrigin
		{
			get
			{
				if (ThisElement.Values[PropertyName] == null)
				{
					return PropertyValueOrigin.Default;
				}
				if (ThisElement.Values.IsInherited(PropertyName))
				{
					return PropertyValueOrigin.Inherited;
				}
				return PropertyValueOrigin.SetHere;
			}
		}

		public bool IsModified
		{
			get
			{
				if (ThisElement.Values[PropertyName] == null)
				{
					return false;
				}
				if (ThisElement.Values.IsModified(PropertyName))
				{
					return true;
				}
				return false;
			}
		}

		public bool IsKey => Prop.IsKey;

		public bool IsRequired => Prop.IsRequired;

		public bool IsLocked
		{
			get
			{
				if ((ThisElement.LockedAllExceptAttributesList == null || ThisElement.LockedAllExceptAttributesList.DefinedInParent(PropertyName)) && (ThisElement.LockedAttributesList == null || (!ThisElement.LockedAttributesList.DefinedInParent(PropertyName) && !ThisElement.LockedAttributesList.DefinedInParent("*"))))
				{
					if ((ThisElement.ItemLocked & ConfigurationValueFlags.Locked) != 0)
					{
						return (ThisElement.ItemLocked & ConfigurationValueFlags.Inherited) != 0;
					}
					return false;
				}
				return true;
			}
		}

		public string Source
		{
			get
			{
				PropertySourceInfo sourceInfo = ThisElement.Values.GetSourceInfo(PropertyName);
				if (sourceInfo == null)
				{
					sourceInfo = ThisElement.Values.GetSourceInfo(string.Empty);
				}
				if (sourceInfo == null)
				{
					return string.Empty;
				}
				return sourceInfo.FileName;
			}
		}

		public int LineNumber
		{
			get
			{
				PropertySourceInfo sourceInfo = ThisElement.Values.GetSourceInfo(PropertyName);
				if (sourceInfo == null)
				{
					sourceInfo = ThisElement.Values.GetSourceInfo(string.Empty);
				}
				return sourceInfo?.LineNumber ?? 0;
			}
		}

		public Type Type => Prop.Type;

		public ConfigurationValidatorBase Validator => Prop.Validator;

		public TypeConverter Converter => Prop.Converter;

		public string Description => Prop.Description;

		internal PropertyInformation(ConfigurationElement thisElement, string propertyName)
		{
			PropertyName = propertyName;
			ThisElement = thisElement;
		}
	}
	[Serializable]
	public sealed class PropertyInformationCollection : NameObjectCollectionBase
	{
		private ConfigurationElement ThisElement;

		public PropertyInformation this[string propertyName]
		{
			get
			{
				PropertyInformation propertyInformation = (PropertyInformation)BaseGet(propertyName);
				if (propertyInformation == null)
				{
					PropertyInformation propertyInformation2 = (PropertyInformation)BaseGet(ConfigurationProperty.DefaultCollectionPropertyName);
					if (propertyInformation2 != null && propertyInformation2.ProvidedName == propertyName)
					{
						propertyInformation = propertyInformation2;
					}
				}
				return propertyInformation;
			}
		}

		internal PropertyInformation this[int index] => (PropertyInformation)BaseGet(BaseGetKey(index));

		internal PropertyInformationCollection(ConfigurationElement thisElement)
			: base(StringComparer.Ordinal)
		{
			ThisElement = thisElement;
			foreach (ConfigurationProperty property in ThisElement.Properties)
			{
				if (property.Name != ThisElement.ElementTagName)
				{
					BaseAdd(property.Name, new PropertyInformation(thisElement, property.Name));
				}
			}
			base.IsReadOnly = true;
		}

		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
		}

		public void CopyTo(PropertyInformation[] array, int index)
		{
			if (array == null)
			{
				throw new ArgumentNullException("array");
			}
			if (array.Length < Count + index)
			{
				throw new ArgumentOutOfRangeException("index");
			}
			IEnumerator enumerator = GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					PropertyInformation propertyInformation = (PropertyInformation)enumerator.Current;
					array[index++] = propertyInformation;
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

		public override IEnumerator GetEnumerator()
		{
			int c = Count;
			for (int i = 0; i < c; i++)
			{
				yield return this[i];
			}
		}
	}
	internal class PropertySourceInfo
	{
		private string _fileName;

		private int _lineNumber;

		internal string FileName
		{
			get
			{
				string fileName = _fileName;
				try
				{
					new FileIOPermission(FileIOPermissionAccess.PathDiscovery, fileName).Demand();
					return fileName;
				}
				catch (SecurityException)
				{
					fileName = Path.GetFileName(_fileName);
					if (fileName == null)
					{
						return string.Empty;
					}
					return fileName;
				}
			}
		}

		internal int LineNumber => _lineNumber;

		internal PropertySourceInfo(XmlReader reader)
		{
			_fileName = GetFilename(reader);
			_lineNumber = GetLineNumber(reader);
		}

		private string GetFilename(XmlReader reader)
		{
			if (reader is IConfigErrorInfo configErrorInfo)
			{
				return configErrorInfo.Filename;
			}
			return "";
		}

		private int GetLineNumber(XmlReader reader)
		{
			if (reader is IConfigErrorInfo configErrorInfo)
			{
				return configErrorInfo.LineNumber;
			}
			return 0;
		}
	}
	public enum PropertyValueOrigin
	{
		Default,
		Inherited,
		SetHere
	}
	[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
	public static class ProtectedConfiguration
	{
		public const string RsaProviderName = "RsaProtectedConfigurationProvider";

		public const string DataProtectionProviderName = "DataProtectionConfigurationProvider";

		public const string ProtectedDataSectionName = "configProtectedData";

		public static ProtectedConfigurationProviderCollection Providers
		{
			get
			{
				if (!(PrivilegedConfigurationManager.GetSection("configProtectedData") is ProtectedConfigurationSection protectedConfigurationSection))
				{
					return new ProtectedConfigurationProviderCollection();
				}
				return protectedConfigurationSection.GetAllProviders();
			}
		}

		public static string DefaultProvider
		{
			get
			{
				if (PrivilegedConfigurationManager.GetSection("configProtectedData") is ProtectedConfigurationSection protectedConfigurationSection)
				{
					return protectedConfigurationSection.DefaultProvider;
				}
				return "";
			}
		}
	}
}
namespace System.Configuration.Provider
{
	public class ProviderCollection : ICollection, IEnumerable
	{
		private Hashtable _Hashtable;

		private bool _ReadOnly;

		public ProviderBase this[string name] => _Hashtable[name] as ProviderBase;

		public int Count => _Hashtable.Count;

		public bool IsSynchronized => false;

		public object SyncRoot => this;

		public ProviderCollection()
		{
			_Hashtable = new Hashtable(10, StringComparer.OrdinalIgnoreCase);
		}

		public virtual void Add(ProviderBase provider)
		{
			if (_ReadOnly)
			{
				throw new NotSupportedException(SR.GetString("CollectionReadOnly"));
			}
			if (provider == null)
			{
				throw new ArgumentNullException("provider");
			}
			if (provider.Name == null || provider.Name.Length < 1)
			{
				throw new ArgumentException(SR.GetString("Config_provider_name_null_or_empty"));
			}
			_Hashtable.Add(provider.Name, provider);
		}

		public void Remove(string name)
		{
			if (_ReadOnly)
			{
				throw new NotSupportedException(SR.GetString("CollectionReadOnly"));
			}
			_Hashtable.Remove(name);
		}

		public IEnumerator GetEnumerator()
		{
			return _Hashtable.Values.GetEnumerator();
		}

		public void SetReadOnly()
		{
			if (!_ReadOnly)
			{
				_ReadOnly = true;
			}
		}

		public void Clear()
		{
			if (_ReadOnly)
			{
				throw new NotSupportedException(SR.GetString("CollectionReadOnly"));
			}
			_Hashtable.Clear();
		}

		public void CopyTo(ProviderBase[] array, int index)
		{
			((ICollection)this).CopyTo((Array)array, index);
		}

		void ICollection.CopyTo(Array array, int index)
		{
			_Hashtable.Values.CopyTo(array, index);
		}
	}
}
namespace System.Configuration
{
	public class ProtectedConfigurationProviderCollection : ProviderCollection
	{
		public new ProtectedConfigurationProvider this[string name] => (ProtectedConfigurationProvider)base[name];

		public override void Add(ProviderBase provider)
		{
			if (provider == null)
			{
				throw new ArgumentNullException("provider");
			}
			if (!(provider is ProtectedConfigurationProvider))
			{
				throw new ArgumentException(SR.GetString("Config_provider_must_implement_type", typeof(ProtectedConfigurationProvider).ToString()), "provider");
			}
			base.Add(provider);
		}
	}
	public sealed class ProtectedConfigurationSection : ConfigurationSection
	{
		private const string EncryptedSectionTemplate = "<{0} {1}=\"{2}\"> {3} </{0}>";

		private static ConfigurationPropertyCollection _properties;

		private static readonly ConfigurationProperty _propProviders;

		private static readonly ConfigurationProperty _propDefaultProvider;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		private ProtectedProviderSettings _Providers => (ProtectedProviderSettings)base[_propProviders];

		[ConfigurationProperty("providers")]
		public ProviderSettingsCollection Providers => _Providers.Providers;

		[ConfigurationProperty("defaultProvider", DefaultValue = "RsaProtectedConfigurationProvider")]
		public string DefaultProvider
		{
			get
			{
				return (string)base[_propDefaultProvider];
			}
			set
			{
				base[_propDefaultProvider] = value;
			}
		}

		internal ProtectedConfigurationProvider GetProviderFromName(string providerName)
		{
			ProviderSettings providerSettings = Providers[providerName];
			if (providerSettings == null)
			{
				throw new Exception(SR.GetString("ProtectedConfigurationProvider_not_found", providerName));
			}
			return InstantiateProvider(providerSettings);
		}

		internal ProtectedConfigurationProviderCollection GetAllProviders()
		{
			ProtectedConfigurationProviderCollection protectedConfigurationProviderCollection = new ProtectedConfigurationProviderCollection();
			foreach (ProviderSettings provider in Providers)
			{
				protectedConfigurationProviderCollection.Add(InstantiateProvider(provider));
			}
			return protectedConfigurationProviderCollection;
		}

		[PermissionSet(SecurityAction.Assert, Unrestricted = true)]
		private ProtectedConfigurationProvider CreateAndInitializeProviderWithAssert(Type t, ProviderSettings pn)
		{
			ProtectedConfigurationProvider protectedConfigurationProvider = (ProtectedConfigurationProvider)TypeUtil.CreateInstanceWithReflectionPermission(t);
			NameValueCollection parameters = pn.Parameters;
			NameValueCollection nameValueCollection = new NameValueCollection(parameters.Count);
			foreach (string item in parameters)
			{
				nameValueCollection[item] = parameters[item];
			}
			protectedConfigurationProvider.Initialize(pn.Name, nameValueCollection);
			return protectedConfigurationProvider;
		}

		private ProtectedConfigurationProvider InstantiateProvider(ProviderSettings pn)
		{
			Type typeWithReflectionPermission = TypeUtil.GetTypeWithReflectionPermission(pn.Type, throwOnError: true);
			if (!typeof(ProtectedConfigurationProvider).IsAssignableFrom(typeWithReflectionPermission))
			{
				throw new Exception(SR.GetString("WrongType_of_Protected_provider"));
			}
			if (!TypeUtil.IsTypeAllowedInConfig(typeWithReflectionPermission))
			{
				throw new Exception(SR.GetString("Type_from_untrusted_assembly", typeWithReflectionPermission.FullName));
			}
			return CreateAndInitializeProviderWithAssert(typeWithReflectionPermission, pn);
		}

		internal static string DecryptSection(string encryptedXml, ProtectedConfigurationProvider provider)
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.LoadXml(encryptedXml);
			XmlNode xmlNode = provider.Decrypt(xmlDocument.DocumentElement);
			return xmlNode.OuterXml;
		}

		internal static string FormatEncryptedSection(string encryptedXml, string sectionName, string providerName)
		{
			return string.Format(CultureInfo.InvariantCulture, "<{0} {1}=\"{2}\"> {3} </{0}>", sectionName, "configProtectionProvider", providerName, encryptedXml);
		}

		internal static string EncryptSection(string clearXml, ProtectedConfigurationProvider provider)
		{
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			xmlDocument.LoadXml(clearXml);
			_ = xmlDocument.DocumentElement.Name;
			XmlNode xmlNode = provider.Encrypt(xmlDocument.DocumentElement);
			return xmlNode.OuterXml;
		}

		static ProtectedConfigurationSection()
		{
			_propProviders = new ConfigurationProperty("providers", typeof(ProtectedProviderSettings), new ProtectedProviderSettings(), ConfigurationPropertyOptions.None);
			_propDefaultProvider = new ConfigurationProperty("defaultProvider", typeof(string), "RsaProtectedConfigurationProvider", null, ConfigurationProperty.NonEmptyStringValidator, ConfigurationPropertyOptions.None);
			_properties = new ConfigurationPropertyCollection();
			_properties.Add(_propProviders);
			_properties.Add(_propDefaultProvider);
		}
	}
	public class ProtectedProviderSettings : ConfigurationElement
	{
		private ConfigurationPropertyCollection _properties;

		private readonly ConfigurationProperty _propProviders = new ConfigurationProperty(null, typeof(ProviderSettingsCollection), null, ConfigurationPropertyOptions.IsDefaultCollection);

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		[ConfigurationProperty("", IsDefaultCollection = true, Options = ConfigurationPropertyOptions.IsDefaultCollection)]
		public ProviderSettingsCollection Providers => (ProviderSettingsCollection)base[_propProviders];

		public ProtectedProviderSettings()
		{
			_properties = new ConfigurationPropertyCollection();
			_properties.Add(_propProviders);
		}
	}
}
namespace System.Configuration.Provider
{
	[Serializable]
	public class ProviderException : Exception
	{
		public ProviderException()
		{
		}

		public ProviderException(string message)
			: base(message)
		{
		}

		public ProviderException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected ProviderException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
namespace System.Configuration
{
	public sealed class ProviderSettings : ConfigurationElement
	{
		private readonly ConfigurationProperty _propName = new ConfigurationProperty("name", typeof(string), null, null, ConfigurationProperty.NonEmptyStringValidator, ConfigurationPropertyOptions.IsRequired | ConfigurationPropertyOptions.IsKey);

		private readonly ConfigurationProperty _propType = new ConfigurationProperty("type", typeof(string), "", ConfigurationPropertyOptions.IsRequired);

		private ConfigurationPropertyCollection _properties;

		private NameValueCollection _PropertyNameCollection;

		protected internal override ConfigurationPropertyCollection Properties
		{
			get
			{
				UpdatePropertyCollection();
				return _properties;
			}
		}

		[ConfigurationProperty("name", IsRequired = true, IsKey = true)]
		public string Name
		{
			get
			{
				return (string)base[_propName];
			}
			set
			{
				base[_propName] = value;
			}
		}

		[ConfigurationProperty("type", IsRequired = true)]
		public string Type
		{
			get
			{
				return (string)base[_propType];
			}
			set
			{
				base[_propType] = value;
			}
		}

		public NameValueCollection Parameters
		{
			get
			{
				if (_PropertyNameCollection == null)
				{
					lock (this)
					{
						if (_PropertyNameCollection == null)
						{
							_PropertyNameCollection = new NameValueCollection(StringComparer.Ordinal);
							foreach (object property in _properties)
							{
								ConfigurationProperty configurationProperty = (ConfigurationProperty)property;
								if (configurationProperty.Name != "name" && configurationProperty.Name != "type")
								{
									_PropertyNameCollection.Add(configurationProperty.Name, (string)base[configurationProperty]);
								}
							}
						}
					}
				}
				return _PropertyNameCollection;
			}
		}

		public ProviderSettings()
		{
			_properties = new ConfigurationPropertyCollection();
			_properties.Add(_propName);
			_properties.Add(_propType);
			_PropertyNameCollection = null;
		}

		public ProviderSettings(string name, string type)
			: this()
		{
			Name = name;
			Type = type;
		}

		protected internal override void Unmerge(ConfigurationElement sourceElement, ConfigurationElement parentElement, ConfigurationSaveMode saveMode)
		{
			if (parentElement is ProviderSettings providerSettings)
			{
				providerSettings.UpdatePropertyCollection();
			}
			if (sourceElement is ProviderSettings providerSettings2)
			{
				providerSettings2.UpdatePropertyCollection();
			}
			base.Unmerge(sourceElement, parentElement, saveMode);
			UpdatePropertyCollection();
		}

		protected internal override void Reset(ConfigurationElement parentElement)
		{
			if (parentElement is ProviderSettings providerSettings)
			{
				providerSettings.UpdatePropertyCollection();
			}
			base.Reset(parentElement);
		}

		internal bool UpdatePropertyCollection()
		{
			bool result = false;
			ArrayList arrayList = null;
			if (_PropertyNameCollection != null)
			{
				foreach (ConfigurationProperty property2 in _properties)
				{
					if (property2.Name != "name" && property2.Name != "type" && _PropertyNameCollection.Get(property2.Name) == null)
					{
						if (arrayList == null)
						{
							arrayList = new ArrayList();
						}
						if ((base.Values.GetConfigValue(property2.Name).ValueFlags & ConfigurationValueFlags.Locked) == 0)
						{
							arrayList.Add(property2.Name);
							result = true;
						}
					}
				}
				if (arrayList != null)
				{
					foreach (string item in arrayList)
					{
						_properties.Remove(item);
					}
				}
				foreach (string item2 in _PropertyNameCollection)
				{
					string text2 = _PropertyNameCollection[item2];
					string property = GetProperty(item2);
					if (property == null || text2 != property)
					{
						SetProperty(item2, text2);
						result = true;
					}
				}
			}
			_PropertyNameCollection = null;
			return result;
		}

		protected internal override bool IsModified()
		{
			if (!UpdatePropertyCollection())
			{
				return base.IsModified();
			}
			return true;
		}

		private string GetProperty(string PropName)
		{
			if (_properties.Contains(PropName))
			{
				ConfigurationProperty configurationProperty = _properties[PropName];
				if (configurationProperty != null)
				{
					return (string)base[configurationProperty];
				}
			}
			return null;
		}

		private bool SetProperty(string PropName, string value)
		{
			ConfigurationProperty configurationProperty = null;
			if (_properties.Contains(PropName))
			{
				configurationProperty = _properties[PropName];
			}
			else
			{
				configurationProperty = new ConfigurationProperty(PropName, typeof(string), null);
				_properties.Add(configurationProperty);
			}
			if (configurationProperty != null)
			{
				base[configurationProperty] = value;
				return true;
			}
			return false;
		}

		protected override bool OnDeserializeUnrecognizedAttribute(string name, string value)
		{
			ConfigurationProperty configurationProperty = new ConfigurationProperty(name, typeof(string), value);
			_properties.Add(configurationProperty);
			base[configurationProperty] = value;
			Parameters[name] = value;
			return true;
		}
	}
	[ConfigurationCollection(typeof(ProviderSettings))]
	public sealed class ProviderSettingsCollection : ConfigurationElementCollection
	{
		private static ConfigurationPropertyCollection _properties;

		protected internal override ConfigurationPropertyCollection Properties => _properties;

		public new ProviderSettings this[string key] => (ProviderSettings)BaseGet(key);

		public ProviderSettings this[int index]
		{
			get
			{
				return (ProviderSettings)BaseGet(index);
			}
			set
			{
				if (BaseGet(index) != null)
				{
					BaseRemoveAt(index);
				}
				BaseAdd(index, value);
			}
		}

		static ProviderSettingsCollection()
		{
			_properties = new ConfigurationPropertyCollection();
		}

		public ProviderSettingsCollection()
			: base(StringComparer.OrdinalIgnoreCase)
		{
		}

		public void Add(ProviderSettings provider)
		{
			if (provider != null)
			{
				provider.UpdatePropertyCollection();
				BaseAdd(provider);
			}
		}

		public void Remove(string name)
		{
			BaseRemove(name);
		}

		public void Clear()
		{
			BaseClear();
		}

		protected override ConfigurationElement CreateNewElement()
		{
			return new ProviderSettings();
		}

		protected override object GetElementKey(ConfigurationElement element)
		{
			return ((ProviderSettings)element).Name;
		}
	}
	public class RegexStringValidator : ConfigurationValidatorBase
	{
		private string _expression;

		private Regex _regex;

		public RegexStringValidator(string regex)
		{
			if (string.IsNullOrEmpty(regex))
			{
				throw ExceptionUtil.ParameterNullOrEmpty("regex");
			}
			_expression = regex;
			_regex = new Regex(regex, RegexOptions.Compiled);
		}

		public override bool CanValidate(Type type)
		{
			return type == typeof(string);
		}

		public override void Validate(object value)
		{
			ValidatorUtils.HelperParamValidation(value, typeof(string));
			if (value != null)
			{
				Match match = _regex.Match((string)value);
				if (!match.Success)
				{
					throw new ArgumentException(SR.GetString("Regex_validator_error", _expression));
				}
			}
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class RegexStringValidatorAttribute : ConfigurationValidatorAttribute
	{
		private string _regex;

		public override ConfigurationValidatorBase ValidatorInstance => new RegexStringValidator(_regex);

		public string Regex => _regex;

		public RegexStringValidatorAttribute(string regex)
		{
			_regex = regex;
		}
	}
	[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
	public sealed class RsaProtectedConfigurationProvider : ProtectedConfigurationProvider
	{
		private const string DefaultRsaKeyContainerName = "NetFrameworkConfigurationKey";

		private const uint PROV_Rsa_FULL = 1u;

		private const uint CRYPT_MACHINE_KEYSET = 32u;

		private string _KeyName;

		private string _KeyContainerName;

		private string _CspProviderName;

		private bool _UseMachineContainer;

		private bool _UseOAEP;

		public string KeyContainerName => _KeyContainerName;

		public string CspProviderName => _CspProviderName;

		public bool UseMachineContainer => _UseMachineContainer;

		public bool UseOAEP => _UseOAEP;

		public RSAParameters RsaPublicKey => GetCryptoServiceProvider(exportable: false, keyMustExist: false).ExportParameters(includePrivateParameters: false);

		public override XmlNode Decrypt(XmlNode encryptedNode)
		{
			XmlDocument xmlDocument = new XmlDocument();
			EncryptedXml encryptedXml = null;
			RSACryptoServiceProvider cryptoServiceProvider = GetCryptoServiceProvider(exportable: false, keyMustExist: true);
			xmlDocument.PreserveWhitespace = true;
			xmlDocument.LoadXml(encryptedNode.OuterXml);
			encryptedXml = new EncryptedXml(xmlDocument);
			encryptedXml.AddKeyNameMapping(_KeyName, cryptoServiceProvider);
			encryptedXml.DecryptDocument();
			cryptoServiceProvider.Clear();
			return xmlDocument.DocumentElement;
		}

		public override XmlNode Encrypt(XmlNode node)
		{
			RSACryptoServiceProvider cryptoServiceProvider = GetCryptoServiceProvider(exportable: false, keyMustExist: false);
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.PreserveWhitespace = true;
			xmlDocument.LoadXml("<foo>" + node.OuterXml + "</foo>");
			EncryptedXml encryptedXml = new EncryptedXml(xmlDocument);
			XmlElement documentElement = xmlDocument.DocumentElement;
			SymmetricAlgorithm symmetricAlgorithm = new TripleDESCryptoServiceProvider();
			byte[] array = (symmetricAlgorithm.Key = GetRandomKey());
			symmetricAlgorithm.Mode = CipherMode.ECB;
			symmetricAlgorithm.Padding = PaddingMode.PKCS7;
			byte[] cipherValue = encryptedXml.EncryptData(documentElement, symmetricAlgorithm, content: true);
			EncryptedData encryptedData = new EncryptedData();
			encryptedData.Type = "http://www.w3.org/2001/04/xmlenc#Element";
			encryptedData.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
			encryptedData.KeyInfo = new KeyInfo();
			EncryptedKey encryptedKey = new EncryptedKey();
			encryptedKey.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
			encryptedKey.KeyInfo = new KeyInfo();
			encryptedKey.CipherData = new CipherData();
			encryptedKey.CipherData.CipherValue = EncryptedXml.EncryptKey(symmetricAlgorithm.Key, cryptoServiceProvider, UseOAEP);
			KeyInfoName keyInfoName = new KeyInfoName();
			keyInfoName.Value = _KeyName;
			encryptedKey.KeyInfo.AddClause(keyInfoName);
			KeyInfoEncryptedKey clause = new KeyInfoEncryptedKey(encryptedKey);
			encryptedData.KeyInfo.AddClause(clause);
			encryptedData.CipherData = new CipherData();
			encryptedData.CipherData.CipherValue = cipherValue;
			EncryptedXml.ReplaceElement(documentElement, encryptedData, content: true);
			foreach (XmlNode childNode in xmlDocument.ChildNodes)
			{
				if (childNode.NodeType != XmlNodeType.Element)
				{
					continue;
				}
				foreach (XmlNode childNode2 in childNode.ChildNodes)
				{
					if (childNode2.NodeType == XmlNodeType.Element)
					{
						return childNode2;
					}
				}
			}
			return null;
		}

		public void AddKey(int keySize, bool exportable)
		{
			RSACryptoServiceProvider cryptoServiceProvider = GetCryptoServiceProvider(exportable, keyMustExist: false);
			cryptoServiceProvider.KeySize = keySize;
			cryptoServiceProvider.PersistKeyInCsp = true;
			cryptoServiceProvider.Clear();
		}

		public void DeleteKey()
		{
			RSACryptoServiceProvider cryptoServiceProvider = GetCryptoServiceProvider(exportable: false, keyMustExist: true);
			cryptoServiceProvider.PersistKeyInCsp = false;
			cryptoServiceProvider.Clear();
		}

		public void ImportKey(string xmlFileName, bool exportable)
		{
			RSACryptoServiceProvider cryptoServiceProvider = GetCryptoServiceProvider(exportable, keyMustExist: false);
			cryptoServiceProvider.FromXmlString(File.ReadAllText(xmlFileName));
			cryptoServiceProvider.PersistKeyInCsp = true;
			cryptoServiceProvider.Clear();
		}

		public void ExportKey(string xmlFileName, bool includePrivateParameters)
		{
			RSACryptoServiceProvider cryptoServiceProvider = GetCryptoServiceProvider(exportable: false, keyMustExist: false);
			string contents = cryptoServiceProvider.ToXmlString(includePrivateParameters);
			File.WriteAllText(xmlFileName, contents);
			cryptoServiceProvider.Clear();
		}

		public override void Initialize(string name, NameValueCollection configurationValues)
		{
			base.Initialize(name, configurationValues);
			_KeyName = "Rsa Key";
			_KeyContainerName = configurationValues["keyContainerName"];
			configurationValues.Remove("keyContainerName");
			if (_KeyContainerName == null || _KeyContainerName.Length < 1)
			{
				_KeyContainerName = "NetFrameworkConfigurationKey";
			}
			_CspProviderName = configurationValues["cspProviderName"];
			configurationValues.Remove("cspProviderName");
			_UseMachineContainer = GetBooleanValue(configurationValues, "useMachineContainer", defaultValue: true);
			_UseOAEP = GetBooleanValue(configurationValues, "useOAEP", defaultValue: false);
			if (configurationValues.Count > 0)
			{
				throw new ConfigurationErrorsException(SR.GetString("Unrecognized_initialization_value", configurationValues.GetKey(0)));
			}
		}

		private RSACryptoServiceProvider GetCryptoServiceProvider(bool exportable, bool keyMustExist)
		{
			try
			{
				CspParameters cspParameters = new CspParameters();
				cspParameters.KeyContainerName = KeyContainerName;
				cspParameters.KeyNumber = 1;
				cspParameters.ProviderType = 1;
				if (CspProviderName != null && CspProviderName.Length > 0)
				{
					cspParameters.ProviderName = CspProviderName;
				}
				if (UseMachineContainer)
				{
					cspParameters.Flags |= CspProviderFlags.UseMachineKeyStore;
				}
				if (!exportable && !keyMustExist)
				{
					cspParameters.Flags |= CspProviderFlags.UseNonExportableKey;
				}
				if (keyMustExist)
				{
					cspParameters.Flags |= CspProviderFlags.UseExistingKey;
				}
				return new RSACryptoServiceProvider(cspParameters);
			}
			catch
			{
				ThrowBetterException(keyMustExist);
				throw;
			}
		}

		private byte[] GetRandomKey()
		{
			byte[] array = new byte[24];
			new RNGCryptoServiceProvider().GetBytes(array);
			return array;
		}

		private void ThrowBetterException(bool keyMustExist)
		{
			SafeCryptContextHandle phProv = null;
			int num = 0;
			try
			{
				if (Microsoft.Win32.UnsafeNativeMethods.CryptAcquireContext(out phProv, KeyContainerName, CspProviderName, 1u, UseMachineContainer ? 32u : 0u) != 0)
				{
					return;
				}
				int hRForLastWin32Error = Marshal.GetHRForLastWin32Error();
				if (hRForLastWin32Error != -2146893802 || keyMustExist)
				{
					switch (hRForLastWin32Error)
					{
					case -2147024891:
					case -2147024890:
					case -2146893802:
						throw new ConfigurationErrorsException(SR.GetString("Key_container_doesnt_exist_or_access_denied"));
					}
					Marshal.ThrowExceptionForHR(hRForLastWin32Error);
				}
			}
			finally
			{
				if (phProv != null && !phProv.IsInvalid)
				{
					phProv.Dispose();
				}
			}
		}

		private static bool GetBooleanValue(NameValueCollection configurationValues, string valueName, bool defaultValue)
		{
			string text = configurationValues[valueName];
			if (text == null)
			{
				return defaultValue;
			}
			configurationValues.Remove(valueName);
			if (text == "true")
			{
				return true;
			}
			if (text == "false")
			{
				return false;
			}
			throw new ConfigurationErrorsException(SR.GetString("Config_invalid_boolean_attribute", valueName));
		}
	}
	internal sealed class RuntimeConfigurationRecord : BaseConfigurationRecord
	{
		private class RuntimeConfigurationFactory
		{
			private ConstructorInfo _sectionCtor;

			private IConfigurationSectionHandler _sectionHandler;

			internal RuntimeConfigurationFactory(RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord)
			{
				if (factoryRecord.IsFromTrustedConfigRecord)
				{
					InitWithFullTrust(configRecord, factoryRecord);
				}
				else
				{
					InitWithRestrictedPermissions(configRecord, factoryRecord);
				}
			}

			private void Init(RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord)
			{
				Type typeWithReflectionPermission = TypeUtil.GetTypeWithReflectionPermission(configRecord.Host, factoryRecord.FactoryTypeName, throwOnError: true);
				if (typeof(ConfigurationSection).IsAssignableFrom(typeWithReflectionPermission))
				{
					_sectionCtor = TypeUtil.GetConstructorWithReflectionPermission(typeWithReflectionPermission, typeof(ConfigurationSection), throwOnError: true);
					return;
				}
				TypeUtil.VerifyAssignableType(typeof(IConfigurationSectionHandler), typeWithReflectionPermission, throwOnError: true);
				_sectionHandler = (IConfigurationSectionHandler)TypeUtil.CreateInstanceWithReflectionPermission(typeWithReflectionPermission);
			}

			[PermissionSet(SecurityAction.Assert, Unrestricted = true)]
			private void InitWithFullTrust(RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord)
			{
				Init(configRecord, factoryRecord);
			}

			private void InitWithRestrictedPermissions(RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord)
			{
				bool flag = false;
				try
				{
					PermissionSet restrictedPermissions = configRecord.GetRestrictedPermissions();
					if (restrictedPermissions != null)
					{
						restrictedPermissions.PermitOnly();
						flag = true;
					}
					Init(configRecord, factoryRecord);
				}
				finally
				{
					if (flag)
					{
						CodeAccessPermission.RevertPermitOnly();
					}
				}
			}

			private static void CheckForLockAttributes(string sectionName, XmlNode xmlNode)
			{
				XmlAttributeCollection attributes = xmlNode.Attributes;
				if (attributes != null)
				{
					foreach (XmlAttribute item in attributes)
					{
						if (ConfigurationElement.IsLockAttributeName(item.Name))
						{
							throw new ConfigurationErrorsException(SR.GetString("Config_element_locking_not_supported", sectionName), item);
						}
					}
				}
				foreach (XmlNode childNode in xmlNode.ChildNodes)
				{
					if (xmlNode.NodeType == XmlNodeType.Element)
					{
						CheckForLockAttributes(sectionName, childNode);
					}
				}
			}

			private object CreateSectionImpl(RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader)
			{
				if (_sectionCtor != null)
				{
					ConfigurationSection configurationSection = (ConfigurationSection)TypeUtil.InvokeCtorWithReflectionPermission(_sectionCtor);
					configurationSection.SectionInformation.SetRuntimeConfigurationInformation(configRecord, factoryRecord, sectionRecord);
					configurationSection.CallInit();
					ConfigurationSection parentElement = (ConfigurationSection)parentConfig;
					configurationSection.Reset(parentElement);
					if (reader != null)
					{
						configurationSection.DeserializeSection(reader);
					}
					ConfigurationErrorsException errors = configurationSection.GetErrors();
					if (errors != null)
					{
						throw errors;
					}
					configurationSection.SetReadOnly();
					configurationSection.ResetModified();
					return configurationSection;
				}
				if (reader != null)
				{
					XmlNode xmlNode = ErrorInfoXmlDocument.CreateSectionXmlNode(reader);
					CheckForLockAttributes(factoryRecord.ConfigKey, xmlNode);
					object configContext = configRecord.Host.CreateDeprecatedConfigContext(configRecord.ConfigPath);
					return _sectionHandler.Create(parentConfig, configContext, xmlNode);
				}
				return null;
			}

			[PermissionSet(SecurityAction.Assert, Unrestricted = true)]
			private object CreateSectionWithFullTrust(RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader)
			{
				return CreateSectionImpl(configRecord, factoryRecord, sectionRecord, parentConfig, reader);
			}

			private object CreateSectionWithRestrictedPermissions(RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader)
			{
				bool flag = false;
				try
				{
					PermissionSet restrictedPermissions = configRecord.GetRestrictedPermissions();
					if (restrictedPermissions != null)
					{
						restrictedPermissions.PermitOnly();
						flag = true;
					}
					return CreateSectionImpl(configRecord, factoryRecord, sectionRecord, parentConfig, reader);
				}
				finally
				{
					if (flag)
					{
						CodeAccessPermission.RevertPermitOnly();
					}
				}
			}

			internal object CreateSection(bool inputIsTrusted, RuntimeConfigurationRecord configRecord, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader)
			{
				if (inputIsTrusted)
				{
					return CreateSectionWithFullTrust(configRecord, factoryRecord, sectionRecord, parentConfig, reader);
				}
				return CreateSectionWithRestrictedPermissions(configRecord, factoryRecord, sectionRecord, parentConfig, reader);
			}
		}

		private static readonly SimpleBitVector32 RuntimeClassFlags = new SimpleBitVector32(47);

		protected override SimpleBitVector32 ClassFlags => RuntimeClassFlags;

		internal static IInternalConfigRecord Create(InternalConfigRoot configRoot, IInternalConfigRecord parent, string configPath)
		{
			RuntimeConfigurationRecord runtimeConfigurationRecord = new RuntimeConfigurationRecord();
			runtimeConfigurationRecord.Init(configRoot, (BaseConfigurationRecord)parent, configPath, null);
			return runtimeConfigurationRecord;
		}

		private RuntimeConfigurationRecord()
		{
		}

		protected override object CreateSectionFactory(FactoryRecord factoryRecord)
		{
			return new RuntimeConfigurationFactory(this, factoryRecord);
		}

		protected override object CreateSection(bool inputIsTrusted, FactoryRecord factoryRecord, SectionRecord sectionRecord, object parentConfig, ConfigXmlReader reader)
		{
			RuntimeConfigurationFactory runtimeConfigurationFactory = (RuntimeConfigurationFactory)factoryRecord.Factory;
			return runtimeConfigurationFactory.CreateSection(inputIsTrusted, this, factoryRecord, sectionRecord, parentConfig, reader);
		}

		protected override object UseParentResult(string configKey, object parentResult, SectionRecord sectionRecord)
		{
			return parentResult;
		}

		[PermissionSet(SecurityAction.Assert, Unrestricted = true)]
		private object GetRuntimeObjectWithFullTrust(ConfigurationSection section)
		{
			return section.GetRuntimeObject();
		}

		private object GetRuntimeObjectWithRestrictedPermissions(ConfigurationSection section)
		{
			bool flag = false;
			try
			{
				PermissionSet restrictedPermissions = GetRestrictedPermissions();
				if (restrictedPermissions != null)
				{
					restrictedPermissions.PermitOnly();
					flag = true;
				}
				return section.GetRuntimeObject();
			}
			finally
			{
				if (flag)
				{
					CodeAccessPermission.RevertPermitOnly();
				}
			}
		}

		protected override object GetRuntimeObject(object result)
		{
			if (!(result is ConfigurationSection configurationSection))
			{
				return result;
			}
			try
			{
				using (Impersonate())
				{
					if (_flags[8192])
					{
						return GetRuntimeObjectWithFullTrust(configurationSection);
					}
					return GetRuntimeObjectWithRestrictedPermissions(configurationSection);
				}
			}
			catch (Exception inner)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configurationSection.SectionInformation.SectionName), inner);
			}
			catch
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_exception_in_config_section_handler", configurationSection.SectionInformation.SectionName));
			}
		}

		[PermissionSet(SecurityAction.Assert, Unrestricted = true)]
		protected override string CallHostDecryptSection(string encryptedXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfig)
		{
			return base.CallHostDecryptSection(encryptedXml, protectionProvider, protectedConfig);
		}
	}
	[Serializable]
	internal struct SafeBitVector32
	{
		private volatile int _data;

		internal bool this[int bit]
		{
			get
			{
				int data = _data;
				return (data & bit) == bit;
			}
			set
			{
				int data;
				int num;
				do
				{
					data = _data;
					int value2 = ((!value) ? (data & ~bit) : (data | bit));
					num = Interlocked.CompareExchange(ref _data, value2, data);
				}
				while (num != data);
			}
		}

		internal SafeBitVector32(int data)
		{
			_data = data;
		}
	}
	public sealed class SectionInformation
	{
		private const int Flag_Attached = 1;

		private const int Flag_Declared = 2;

		private const int Flag_DeclarationRequired = 4;

		private const int Flag_AllowLocation = 8;

		private const int Flag_RestartOnExternalChanges = 16;

		private const int Flag_RequirePermission = 32;

		private const int Flag_LocationLocked = 64;

		private const int Flag_ChildrenLocked = 128;

		private const int Flag_InheritInChildApps = 256;

		private const int Flag_IsParentSection = 512;

		private const int Flag_Removed = 1024;

		private const int Flag_ProtectionProviderDetermined = 2048;

		private const int Flag_ForceSave = 4096;

		private const int Flag_IsUndeclared = 8192;

		private const int Flag_ChildrenLockWithoutFileInput = 16384;

		private const int Flag_AllowExeDefinitionModified = 65536;

		private const int Flag_AllowDefinitionModified = 131072;

		private const int Flag_ConfigSourceModified = 262144;

		private const int Flag_ProtectionProviderModified = 524288;

		private const int Flag_OverrideModeDefaultModified = 1048576;

		private const int Flag_OverrideModeModified = 2097152;

		private ConfigurationSection _configurationSection;

		private SafeBitVector32 _flags;

		private SimpleBitVector32 _modifiedFlags;

		private ConfigurationAllowDefinition _allowDefinition;

		private ConfigurationAllowExeDefinition _allowExeDefinition;

		private MgmtConfigurationRecord _configRecord;

		private string _configKey;

		private string _group;

		private string _name;

		private string _typeName;

		private string _rawXml;

		private string _configSource;

		private string _configSourceStreamName;

		private ProtectedConfigurationProvider _protectionProvider;

		private string _protectionProviderName;

		private OverrideModeSetting _overrideModeDefault;

		private OverrideModeSetting _overrideMode;

		private bool IsRuntime
		{
			get
			{
				if (_flags[1])
				{
					return _configRecord == null;
				}
				return false;
			}
		}

		internal bool Attached => _flags[1];

		internal string ConfigKey => _configKey;

		internal bool Removed
		{
			get
			{
				return _flags[1024];
			}
			set
			{
				_flags[1024] = value;
			}
		}

		public string SectionName => _configKey;

		public string Name => _name;

		public ConfigurationAllowDefinition AllowDefinition
		{
			get
			{
				return _allowDefinition;
			}
			set
			{
				VerifyIsEditable();
				VerifyIsEditableFactory();
				FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
				if (factoryRecord != null && factoryRecord.AllowDefinition != value)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
				}
				_allowDefinition = value;
				_modifiedFlags[131072] = true;
			}
		}

		internal bool AllowDefinitionModified => _modifiedFlags[131072];

		public ConfigurationAllowExeDefinition AllowExeDefinition
		{
			get
			{
				return _allowExeDefinition;
			}
			set
			{
				VerifyIsEditable();
				VerifyIsEditableFactory();
				FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
				if (factoryRecord != null && factoryRecord.AllowExeDefinition != value)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
				}
				_allowExeDefinition = value;
				_modifiedFlags[65536] = true;
			}
		}

		internal bool AllowExeDefinitionModified => _modifiedFlags[65536];

		public OverrideMode OverrideModeDefault
		{
			get
			{
				return _overrideModeDefault.OverrideMode;
			}
			set
			{
				VerifyIsEditable();
				VerifyIsEditableFactory();
				FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
				if (factoryRecord != null && factoryRecord.OverrideModeDefault.OverrideMode != value)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
				}
				if (value == OverrideMode.Inherit)
				{
					value = OverrideMode.Allow;
				}
				_overrideModeDefault.OverrideMode = value;
				_modifiedFlags[1048576] = true;
			}
		}

		internal OverrideModeSetting OverrideModeDefaultSetting => _overrideModeDefault;

		internal bool OverrideModeDefaultModified => _modifiedFlags[1048576];

		public bool AllowLocation
		{
			get
			{
				return _flags[8];
			}
			set
			{
				VerifyIsEditable();
				VerifyIsEditableFactory();
				FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
				if (factoryRecord != null && factoryRecord.AllowLocation != value)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
				}
				_flags[8] = value;
				_modifiedFlags[8] = true;
			}
		}

		internal bool AllowLocationModified => _modifiedFlags[8];

		public bool AllowOverride
		{
			get
			{
				return _overrideMode.AllowOverride;
			}
			set
			{
				VerifyIsEditable();
				VerifySupportsLocation();
				_overrideMode.AllowOverride = value;
				_modifiedFlags[2097152] = true;
			}
		}

		public OverrideMode OverrideMode
		{
			get
			{
				return _overrideMode.OverrideMode;
			}
			set
			{
				VerifyIsEditable();
				VerifySupportsLocation();
				_overrideMode.OverrideMode = value;
				_modifiedFlags[2097152] = true;
				switch (value)
				{
				case OverrideMode.Inherit:
					_flags[128] = _flags[16384];
					break;
				case OverrideMode.Allow:
					_flags[128] = false;
					break;
				case OverrideMode.Deny:
					_flags[128] = true;
					break;
				}
			}
		}

		public OverrideMode OverrideModeEffective
		{
			get
			{
				if (!_flags[128])
				{
					return OverrideMode.Allow;
				}
				return OverrideMode.Deny;
			}
		}

		internal OverrideModeSetting OverrideModeSetting => _overrideMode;

		internal bool LocationAttributesAreDefault
		{
			get
			{
				if (_overrideMode.IsDefaultForLocationTag)
				{
					return _flags[256];
				}
				return false;
			}
		}

		public string ConfigSource
		{
			get
			{
				if (_configSource != null)
				{
					return _configSource;
				}
				return string.Empty;
			}
			set
			{
				VerifyIsEditable();
				string text = (string.IsNullOrEmpty(value) ? null : BaseConfigurationRecord.NormalizeConfigSource(value, null));
				if (!(text == _configSource))
				{
					if (_configRecord != null)
					{
						_configRecord.ChangeConfigSource(this, _configSource, _configSourceStreamName, text);
					}
					_configSource = text;
					_modifiedFlags[262144] = true;
				}
			}
		}

		internal bool ConfigSourceModified => _modifiedFlags[262144];

		internal string ConfigSourceStreamName
		{
			get
			{
				return _configSourceStreamName;
			}
			set
			{
				_configSourceStreamName = value;
			}
		}

		public bool InheritInChildApplications
		{
			get
			{
				return _flags[256];
			}
			set
			{
				VerifyIsEditable();
				VerifySupportsLocation();
				_flags[256] = value;
			}
		}

		public bool IsDeclared
		{
			get
			{
				VerifyNotParentSection();
				return _flags[2];
			}
		}

		public bool IsDeclarationRequired
		{
			get
			{
				VerifyNotParentSection();
				return _flags[4];
			}
		}

		private bool IsDefinitionAllowed
		{
			get
			{
				if (_configRecord == null)
				{
					return true;
				}
				return _configRecord.IsDefinitionAllowed(_allowDefinition, _allowExeDefinition);
			}
		}

		public bool IsLocked
		{
			get
			{
				if (!_flags[64] && IsDefinitionAllowed)
				{
					return _configurationSection.ElementInformation.IsLocked;
				}
				return true;
			}
		}

		public bool IsProtected => ProtectionProvider != null;

		public ProtectedConfigurationProvider ProtectionProvider
		{
			get
			{
				if (!_flags[2048] && _configRecord != null)
				{
					_protectionProvider = _configRecord.GetProtectionProviderFromName(_protectionProviderName, throwIfNotFound: false);
					_flags[2048] = true;
				}
				return _protectionProvider;
			}
		}

		internal string ProtectionProviderName => _protectionProviderName;

		public bool RestartOnExternalChanges
		{
			get
			{
				return _flags[16];
			}
			set
			{
				VerifyIsEditable();
				VerifyIsEditableFactory();
				FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
				if (factoryRecord != null && factoryRecord.RestartOnExternalChanges != value)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
				}
				_flags[16] = value;
				_modifiedFlags[16] = true;
			}
		}

		internal bool RestartOnExternalChangesModified => _modifiedFlags[16];

		public bool RequirePermission
		{
			get
			{
				return _flags[32];
			}
			set
			{
				VerifyIsEditable();
				VerifyIsEditableFactory();
				FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
				if (factoryRecord != null && factoryRecord.RequirePermission != value)
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
				}
				_flags[32] = value;
				_modifiedFlags[32] = true;
			}
		}

		internal bool RequirePermissionModified => _modifiedFlags[32];

		public string Type
		{
			get
			{
				return _typeName;
			}
			set
			{
				if (string.IsNullOrEmpty(value))
				{
					throw ExceptionUtil.PropertyNullOrEmpty("Type");
				}
				VerifyIsEditable();
				VerifyIsEditableFactory();
				FactoryRecord factoryRecord = FindParentFactoryRecord(permitErrors: false);
				if (factoryRecord != null)
				{
					IInternalConfigHost host = null;
					if (_configRecord != null)
					{
						host = _configRecord.Host;
					}
					if (!factoryRecord.IsEquivalentType(host, value))
					{
						throw new ConfigurationErrorsException(SR.GetString("Config_tag_name_already_defined", _configKey));
					}
				}
				_typeName = value;
			}
		}

		internal string RawXml
		{
			get
			{
				return _rawXml;
			}
			set
			{
				_rawXml = value;
			}
		}

		public bool ForceSave
		{
			get
			{
				return _flags[4096];
			}
			set
			{
				VerifyIsEditable();
				_flags[4096] = value;
			}
		}

		internal SectionInformation(ConfigurationSection associatedConfigurationSection)
		{
			_configKey = string.Empty;
			_group = string.Empty;
			_name = string.Empty;
			_configurationSection = associatedConfigurationSection;
			_allowDefinition = ConfigurationAllowDefinition.Everywhere;
			_allowExeDefinition = ConfigurationAllowExeDefinition.MachineToApplication;
			_overrideModeDefault = OverrideModeSetting.SectionDefault;
			_overrideMode = OverrideModeSetting.LocationDefault;
			_flags[8] = true;
			_flags[16] = true;
			_flags[32] = true;
			_flags[256] = true;
			_flags[4096] = false;
			_modifiedFlags = default(SimpleBitVector32);
		}

		internal void ResetModifiedFlags()
		{
			_modifiedFlags = default(SimpleBitVector32);
		}

		internal bool IsModifiedFlags()
		{
			return _modifiedFlags.Data != 0;
		}

		internal void AttachToConfigurationRecord(MgmtConfigurationRecord configRecord, FactoryRecord factoryRecord, SectionRecord sectionRecord)
		{
			SetRuntimeConfigurationInformation(configRecord, factoryRecord, sectionRecord);
			_configRecord = configRecord;
		}

		internal void SetRuntimeConfigurationInformation(BaseConfigurationRecord configRecord, FactoryRecord factoryRecord, SectionRecord sectionRecord)
		{
			_flags[1] = true;
			_configKey = factoryRecord.ConfigKey;
			_group = factoryRecord.Group;
			_name = factoryRecord.Name;
			_typeName = factoryRecord.FactoryTypeName;
			_allowDefinition = factoryRecord.AllowDefinition;
			_allowExeDefinition = factoryRecord.AllowExeDefinition;
			_flags[8] = factoryRecord.AllowLocation;
			_flags[16] = factoryRecord.RestartOnExternalChanges;
			_flags[32] = factoryRecord.RequirePermission;
			_overrideModeDefault = factoryRecord.OverrideModeDefault;
			if (factoryRecord.IsUndeclared)
			{
				_flags[8192] = true;
				_flags[2] = false;
				_flags[4] = false;
			}
			else
			{
				_flags[8192] = false;
				_flags[2] = configRecord.GetFactoryRecord(factoryRecord.ConfigKey, permitErrors: false) != null;
				_flags[4] = configRecord.IsRootDeclaration(factoryRecord.ConfigKey, implicitIsRooted: false);
			}
			_flags[64] = sectionRecord.Locked;
			_flags[128] = sectionRecord.LockChildren;
			_flags[16384] = sectionRecord.LockChildrenWithoutFileInput;
			if (sectionRecord.HasFileInput)
			{
				SectionInput fileInput = sectionRecord.FileInput;
				_flags[2048] = fileInput.IsProtectionProviderDetermined;
				_protectionProvider = fileInput.ProtectionProvider;
				SectionXmlInfo sectionXmlInfo = fileInput.SectionXmlInfo;
				_configSource = sectionXmlInfo.ConfigSource;
				_configSourceStreamName = sectionXmlInfo.ConfigSourceStreamName;
				_overrideMode = sectionXmlInfo.OverrideModeSetting;
				_flags[256] = !sectionXmlInfo.SkipInChildApps;
				_protectionProviderName = sectionXmlInfo.ProtectionProviderName;
			}
			else
			{
				_flags[2048] = false;
				_protectionProvider = null;
			}
			_configurationSection.AssociateContext(configRecord);
		}

		internal void DetachFromConfigurationRecord()
		{
			RevertToParent();
			_flags[1] = false;
			_configRecord = null;
		}

		private void VerifyDesigntime()
		{
			if (IsRuntime)
			{
				throw new InvalidOperationException(SR.GetString("Config_operation_not_runtime"));
			}
		}

		private void VerifyIsAttachedToConfigRecord()
		{
			if (_configRecord == null)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsection_when_not_attached"));
			}
		}

		internal void VerifyIsEditable()
		{
			VerifyDesigntime();
			if (IsLocked)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsection_when_locked"));
			}
			if (_flags[512])
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsection_parentsection"));
			}
			if (!_flags[8] && _configRecord != null && _configRecord.IsLocationConfig)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsection_when_location_locked"));
			}
		}

		private void VerifyNotParentSection()
		{
			if (_flags[512])
			{
				throw new InvalidOperationException(SR.GetString("Config_configsection_parentnotvalid"));
			}
		}

		private void VerifySupportsLocation()
		{
			if (_configRecord != null && !_configRecord.RecordSupportsLocation)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_locationattriubtes"));
			}
		}

		internal void VerifyIsEditableFactory()
		{
			if (_configRecord != null && _configRecord.IsLocationConfig)
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsection_in_location_config"));
			}
			if (BaseConfigurationRecord.IsImplicitSection(ConfigKey))
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsection_when_it_is_implicit"));
			}
			if (_flags[8192])
			{
				throw new InvalidOperationException(SR.GetString("Config_cannot_edit_configurationsection_when_it_is_undeclared"));
			}
		}

		private FactoryRecord FindParentFactoryRecord(bool permitErrors)
		{
			FactoryRecord result = null;
			if (_configRecord != null && !_configRecord.Parent.IsRootConfig)
			{
				result = _configRecord.Parent.FindFactoryRecord(_configKey, permitErrors);
			}
			return result;
		}

		public void ForceDeclaration()
		{
			ForceDeclaration(force: true);
		}

		public void ForceDeclaration(bool force)
		{
			VerifyIsEditable();
			if (force || !_flags[4])
			{
				if (force && BaseConfigurationRecord.IsImplicitSection(SectionName))
				{
					throw new ConfigurationErrorsException(SR.GetString("Cannot_declare_or_remove_implicit_section"));
				}
				if (force && _flags[8192])
				{
					throw new ConfigurationErrorsException(SR.GetString("Config_cannot_edit_configurationsection_when_it_is_undeclared"));
				}
				_flags[2] = force;
			}
		}

		public void ProtectSection(string protectionProvider)
		{
			ProtectedConfigurationProvider protectedConfigurationProvider = null;
			VerifyIsEditable();
			if (!AllowLocation || _configKey == "configProtectedData")
			{
				throw new InvalidOperationException(SR.GetString("Config_not_allowed_to_encrypt_this_section"));
			}
			if (_configRecord != null)
			{
				if (string.IsNullOrEmpty(protectionProvider))
				{
					protectionProvider = _configRecord.DefaultProviderName;
				}
				protectedConfigurationProvider = _configRecord.GetProtectionProviderFromName(protectionProvider, throwIfNotFound: true);
				_protectionProviderName = protectionProvider;
				_protectionProvider = protectedConfigurationProvider;
				_flags[2048] = true;
				_modifiedFlags[524288] = true;
				return;
			}
			throw new InvalidOperationException(SR.GetString("Must_add_to_config_before_protecting_it"));
		}

		public void UnprotectSection()
		{
			VerifyIsEditable();
			_protectionProvider = null;
			_protectionProviderName = null;
			_flags[2048] = true;
			_modifiedFlags[524288] = true;
		}

		public ConfigurationSection GetParentSection()
		{
			VerifyDesigntime();
			if (_flags[512])
			{
				throw new InvalidOperationException(SR.GetString("Config_getparentconfigurationsection_first_instance"));
			}
			ConfigurationSection configurationSection = null;
			if (_configRecord != null)
			{
				configurationSection = _configRecord.FindAndCloneImmediateParentSection(_configurationSection);
				if (configurationSection != null)
				{
					configurationSection.SectionInformation._flags[512] = true;
					configurationSection.SetReadOnly();
				}
			}
			return configurationSection;
		}

		public string GetRawXml()
		{
			VerifyDesigntime();
			VerifyNotParentSection();
			if (RawXml != null)
			{
				return RawXml;
			}
			if (_configRecord != null)
			{
				return _configRecord.GetRawXml(_configKey);
			}
			return null;
		}

		public void SetRawXml(string rawXml)
		{
			VerifyIsEditable();
			if (_configRecord != null)
			{
				_configRecord.SetRawXml(_configurationSection, rawXml);
			}
			else
			{
				RawXml = (string.IsNullOrEmpty(rawXml) ? null : rawXml);
			}
		}

		public void RevertToParent()
		{
			VerifyIsEditable();
			VerifyIsAttachedToConfigRecord();
			_configRecord.RevertToParent(_configurationSection);
		}
	}
	[DebuggerDisplay("SectionInput {_sectionXmlInfo.ConfigKey}")]
	internal class SectionInput
	{
		private static object s_unevaluated = new object();

		private SectionXmlInfo _sectionXmlInfo;

		private ProtectedConfigurationProvider _protectionProvider;

		private bool _isProtectionProviderDetermined;

		private object _result;

		private object _resultRuntimeObject;

		private List<ConfigurationException> _errors;

		internal SectionXmlInfo SectionXmlInfo => _sectionXmlInfo;

		internal bool HasResult => _result != s_unevaluated;

		internal bool HasResultRuntimeObject => _resultRuntimeObject != s_unevaluated;

		internal object Result
		{
			get
			{
				return _result;
			}
			set
			{
				_result = value;
			}
		}

		internal object ResultRuntimeObject
		{
			get
			{
				return _resultRuntimeObject;
			}
			set
			{
				_resultRuntimeObject = value;
			}
		}

		internal bool IsProtectionProviderDetermined => _isProtectionProviderDetermined;

		internal ProtectedConfigurationProvider ProtectionProvider
		{
			get
			{
				return _protectionProvider;
			}
			set
			{
				_protectionProvider = value;
				_isProtectionProviderDetermined = true;
			}
		}

		internal ICollection<ConfigurationException> Errors => _errors;

		internal bool HasErrors => ErrorsHelper.GetHasErrors(_errors);

		internal SectionInput(SectionXmlInfo sectionXmlInfo, List<ConfigurationException> errors)
		{
			_sectionXmlInfo = sectionXmlInfo;
			_errors = errors;
			_result = s_unevaluated;
			_resultRuntimeObject = s_unevaluated;
		}

		internal void ClearResult()
		{
			_result = s_unevaluated;
			_resultRuntimeObject = s_unevaluated;
		}

		internal void ThrowOnErrors()
		{
			ErrorsHelper.ThrowOnErrors(_errors);
		}
	}
	[DebuggerDisplay("SectionRecord {ConfigKey}")]
	internal class SectionRecord
	{
		private const int Flag_Locked = 1;

		private const int Flag_LockChildren = 2;

		private const int Flag_IsResultTrustedWithoutAptca = 4;

		private const int Flag_RequirePermission = 8;

		private const int Flag_LocationInputLockApplied = 16;

		private const int Flag_IndirectLocationInputLockApplied = 32;

		private const int Flag_ChildrenLockWithoutFileInput = 64;

		private const int Flag_AddUpdate = 65536;

		private static object s_unevaluated = new object();

		private SafeBitVector32 _flags;

		private string _configKey;

		private List<SectionInput> _locationInputs;

		private SectionInput _fileInput;

		private List<SectionInput> _indirectLocationInputs;

		private object _result;

		private object _resultRuntimeObject;

		private List<ConfigurationException> _errors;

		internal string ConfigKey => _configKey;

		internal bool Locked => _flags[1];

		internal bool LockChildren => _flags[2];

		internal bool LockChildrenWithoutFileInput
		{
			get
			{
				bool result = LockChildren;
				if (HasFileInput)
				{
					result = _flags[64];
				}
				return result;
			}
		}

		internal bool IsResultTrustedWithoutAptca
		{
			get
			{
				return _flags[4];
			}
			set
			{
				_flags[4] = value;
			}
		}

		internal bool RequirePermission
		{
			get
			{
				return _flags[8];
			}
			set
			{
				_flags[8] = value;
			}
		}

		internal bool AddUpdate
		{
			get
			{
				return _flags[65536];
			}
			set
			{
				_flags[65536] = value;
			}
		}

		internal bool HasLocationInputs
		{
			get
			{
				if (_locationInputs != null)
				{
					return _locationInputs.Count > 0;
				}
				return false;
			}
		}

		internal List<SectionInput> LocationInputs => _locationInputs;

		internal SectionInput LastLocationInput
		{
			get
			{
				if (HasLocationInputs)
				{
					return _locationInputs[_locationInputs.Count - 1];
				}
				return null;
			}
		}

		internal bool HasFileInput => _fileInput != null;

		internal SectionInput FileInput => _fileInput;

		internal bool HasIndirectLocationInputs
		{
			get
			{
				if (_indirectLocationInputs != null)
				{
					return _indirectLocationInputs.Count > 0;
				}
				return false;
			}
		}

		internal List<SectionInput> IndirectLocationInputs => _indirectLocationInputs;

		internal SectionInput LastIndirectLocationInput
		{
			get
			{
				if (HasIndirectLocationInputs)
				{
					return _indirectLocationInputs[_indirectLocationInputs.Count - 1];
				}
				return null;
			}
		}

		internal bool HasInput
		{
			get
			{
				if (!HasLocationInputs && !HasFileInput)
				{
					return HasIndirectLocationInputs;
				}
				return true;
			}
		}

		internal bool HasResult => _result != s_unevaluated;

		internal bool HasResultRuntimeObject => _resultRuntimeObject != s_unevaluated;

		internal object Result
		{
			get
			{
				return _result;
			}
			set
			{
				_result = value;
			}
		}

		internal object ResultRuntimeObject
		{
			get
			{
				return _resultRuntimeObject;
			}
			set
			{
				_resultRuntimeObject = value;
			}
		}

		internal bool HasErrors
		{
			get
			{
				if (ErrorsHelper.GetHasErrors(_errors))
				{
					return true;
				}
				if (HasLocationInputs)
				{
					foreach (SectionInput locationInput in LocationInputs)
					{
						if (locationInput.HasErrors)
						{
							return true;
						}
					}
				}
				if (HasIndirectLocationInputs)
				{
					foreach (SectionInput indirectLocationInput in IndirectLocationInputs)
					{
						if (indirectLocationInput.HasErrors)
						{
							return true;
						}
					}
				}
				if (HasFileInput && FileInput.HasErrors)
				{
					return true;
				}
				return false;
			}
		}

		internal SectionRecord(string configKey)
		{
			_configKey = configKey;
			_result = s_unevaluated;
			_resultRuntimeObject = s_unevaluated;
		}

		internal void AddLocationInput(SectionInput sectionInput)
		{
			AddLocationInputImpl(sectionInput, isIndirectLocation: false);
		}

		internal void ChangeLockSettings(OverrideMode forSelf, OverrideMode forChildren)
		{
			if (forSelf != 0)
			{
				_flags[1] = forSelf == OverrideMode.Deny;
				_flags[2] = forSelf == OverrideMode.Deny;
			}
			if (forChildren != 0)
			{
				_flags[2] = forSelf == OverrideMode.Deny || forChildren == OverrideMode.Deny;
			}
		}

		internal void AddFileInput(SectionInput sectionInput)
		{
			_fileInput = sectionInput;
			if (!sectionInput.HasErrors && sectionInput.SectionXmlInfo.OverrideModeSetting.OverrideMode != 0)
			{
				_flags[64] = LockChildren;
				ChangeLockSettings(OverrideMode.Inherit, sectionInput.SectionXmlInfo.OverrideModeSetting.OverrideMode);
			}
		}

		internal void RemoveFileInput()
		{
			if (_fileInput != null)
			{
				_fileInput = null;
				_flags[2] = Locked;
			}
		}

		internal void AddIndirectLocationInput(SectionInput sectionInput)
		{
			AddLocationInputImpl(sectionInput, isIndirectLocation: true);
		}

		private void AddLocationInputImpl(SectionInput sectionInput, bool isIndirectLocation)
		{
			List<SectionInput> list = (isIndirectLocation ? _indirectLocationInputs : _locationInputs);
			int bit = (isIndirectLocation ? 32 : 16);
			if (list == null)
			{
				list = new List<SectionInput>(1);
				if (isIndirectLocation)
				{
					_indirectLocationInputs = list;
				}
				else
				{
					_locationInputs = list;
				}
			}
			list.Insert(0, sectionInput);
			if (!sectionInput.HasErrors && !_flags[bit])
			{
				OverrideMode overrideMode = sectionInput.SectionXmlInfo.OverrideModeSetting.OverrideMode;
				if (overrideMode != 0)
				{
					ChangeLockSettings(overrideMode, overrideMode);
					_flags[bit] = true;
				}
			}
		}

		internal void ClearRawXml()
		{
			if (HasLocationInputs)
			{
				foreach (SectionInput locationInput in LocationInputs)
				{
					locationInput.SectionXmlInfo.RawXml = null;
				}
			}
			if (HasIndirectLocationInputs)
			{
				foreach (SectionInput indirectLocationInput in IndirectLocationInputs)
				{
					indirectLocationInput.SectionXmlInfo.RawXml = null;
				}
			}
			if (HasFileInput)
			{
				FileInput.SectionXmlInfo.RawXml = null;
			}
		}

		internal void ClearResult()
		{
			if (_fileInput != null)
			{
				_fileInput.ClearResult();
			}
			if (_locationInputs != null)
			{
				foreach (SectionInput locationInput in _locationInputs)
				{
					locationInput.ClearResult();
				}
			}
			_result = s_unevaluated;
			_resultRuntimeObject = s_unevaluated;
		}

		private List<ConfigurationException> GetAllErrors()
		{
			List<ConfigurationException> errors = null;
			ErrorsHelper.AddErrors(ref errors, _errors);
			if (HasLocationInputs)
			{
				foreach (SectionInput locationInput in LocationInputs)
				{
					ErrorsHelper.AddErrors(ref errors, locationInput.Errors);
				}
			}
			if (HasIndirectLocationInputs)
			{
				foreach (SectionInput indirectLocationInput in IndirectLocationInputs)
				{
					ErrorsHelper.AddErrors(ref errors, indirectLocationInput.Errors);
				}
			}
			if (HasFileInput)
			{
				ErrorsHelper.AddErrors(ref errors, FileInput.Errors);
			}
			return errors;
		}

		internal void ThrowOnErrors()
		{
			if (HasErrors)
			{
				throw new ConfigurationErrorsException(GetAllErrors());
			}
		}
	}
	internal class SectionUpdates
	{
		private string _name;

		private Hashtable _groups;

		private Hashtable _sections;

		private int _cUnretrieved;

		private int _cMoved;

		private Update _sectionGroupUpdate;

		private bool _isNew;

		internal bool IsNew
		{
			get
			{
				return _isNew;
			}
			set
			{
				_isNew = value;
			}
		}

		internal bool IsEmpty
		{
			get
			{
				if (_groups.Count == 0)
				{
					return _sections.Count == 0;
				}
				return false;
			}
		}

		internal SectionUpdates(string name)
		{
			_name = name;
			_groups = new Hashtable();
			_sections = new Hashtable();
		}

		private SectionUpdates FindSectionUpdates(string configKey, bool isGroup)
		{
			string group;
			if (isGroup)
			{
				group = configKey;
			}
			else
			{
				BaseConfigurationRecord.SplitConfigKey(configKey, out group, out var _);
			}
			SectionUpdates sectionUpdates = this;
			if (group.Length != 0)
			{
				string[] array = group.Split(BaseConfigurationRecord.ConfigPathSeparatorParams);
				string[] array2 = array;
				foreach (string text in array2)
				{
					SectionUpdates sectionUpdates2 = (SectionUpdates)sectionUpdates._groups[text];
					if (sectionUpdates2 == null)
					{
						sectionUpdates2 = new SectionUpdates(text);
						sectionUpdates._groups[text] = sectionUpdates2;
					}
					sectionUpdates = sectionUpdates2;
				}
			}
			return sectionUpdates;
		}

		internal void CompleteUpdates()
		{
			bool flag = true;
			foreach (SectionUpdates value in _groups.Values)
			{
				value.CompleteUpdates();
				if (!value.IsNew)
				{
					flag = false;
				}
			}
			_isNew = flag && _cMoved == _sections.Count;
		}

		internal void AddSection(Update update)
		{
			SectionUpdates sectionUpdates = FindSectionUpdates(update.ConfigKey, isGroup: false);
			sectionUpdates._sections.Add(update.ConfigKey, update);
			sectionUpdates._cUnretrieved++;
			if (update.Moved)
			{
				sectionUpdates._cMoved++;
			}
		}

		internal void AddSectionGroup(Update update)
		{
			SectionUpdates sectionUpdates = FindSectionUpdates(update.ConfigKey, isGroup: true);
			sectionUpdates._sectionGroupUpdate = update;
		}

		private Update GetUpdate(string configKey)
		{
			Update update = (Update)_sections[configKey];
			if (update != null)
			{
				if (update.Retrieved)
				{
					update = null;
				}
				else
				{
					update.Retrieved = true;
					_cUnretrieved--;
					if (update.Moved)
					{
						_cMoved--;
					}
				}
			}
			return update;
		}

		internal DeclarationUpdate GetSectionGroupUpdate()
		{
			if (_sectionGroupUpdate != null && !_sectionGroupUpdate.Retrieved)
			{
				_sectionGroupUpdate.Retrieved = true;
				return (DeclarationUpdate)_sectionGroupUpdate;
			}
			return null;
		}

		internal DefinitionUpdate GetDefinitionUpdate(string configKey)
		{
			return (DefinitionUpdate)GetUpdate(configKey);
		}

		internal DeclarationUpdate GetDeclarationUpdate(string configKey)
		{
			return (DeclarationUpdate)GetUpdate(configKey);
		}

		internal SectionUpdates GetSectionUpdatesForGroup(string group)
		{
			return (SectionUpdates)_groups[group];
		}

		internal bool HasUnretrievedSections()
		{
			if (_cUnretrieved > 0 || (_sectionGroupUpdate != null && !_sectionGroupUpdate.Retrieved))
			{
				return true;
			}
			foreach (SectionUpdates value in _groups.Values)
			{
				if (value.HasUnretrievedSections())
				{
					return true;
				}
			}
			return false;
		}

		internal bool HasNewSectionGroups()
		{
			foreach (SectionUpdates value in _groups.Values)
			{
				if (value.IsNew)
				{
					return true;
				}
			}
			return false;
		}

		internal string[] GetUnretrievedSectionNames()
		{
			if (_cUnretrieved == 0)
			{
				return null;
			}
			string[] array = new string[_cUnretrieved];
			int num = 0;
			foreach (Update value in _sections.Values)
			{
				if (!value.Retrieved)
				{
					array[num] = value.ConfigKey;
					num++;
				}
			}
			Array.Sort(array);
			return array;
		}

		internal string[] GetMovedSectionNames()
		{
			if (_cMoved == 0)
			{
				return null;
			}
			string[] array = new string[_cMoved];
			int num = 0;
			foreach (Update value in _sections.Values)
			{
				if (value.Moved && !value.Retrieved)
				{
					array[num] = value.ConfigKey;
					num++;
				}
			}
			Array.Sort(array);
			return array;
		}

		internal string[] GetUnretrievedGroupNames()
		{
			ArrayList arrayList = new ArrayList();
			foreach (DictionaryEntry group in _groups)
			{
				string value = (string)group.Key;
				SectionUpdates sectionUpdates = (SectionUpdates)group.Value;
				if (sectionUpdates.HasUnretrievedSections())
				{
					arrayList.Add(value);
				}
			}
			if (arrayList.Count == 0)
			{
				return null;
			}
			string[] array = new string[arrayList.Count];
			arrayList.CopyTo(array);
			Array.Sort(array);
			return array;
		}

		internal string[] GetNewGroupNames()
		{
			ArrayList arrayList = new ArrayList();
			foreach (DictionaryEntry group in _groups)
			{
				string value = (string)group.Key;
				SectionUpdates sectionUpdates = (SectionUpdates)group.Value;
				if (sectionUpdates.IsNew && sectionUpdates.HasUnretrievedSections())
				{
					arrayList.Add(value);
				}
			}
			if (arrayList.Count == 0)
			{
				return null;
			}
			string[] array = new string[arrayList.Count];
			arrayList.CopyTo(array);
			Array.Sort(array);
			return array;
		}
	}
	internal sealed class SectionXmlInfo : IConfigErrorInfo
	{
		private string _configKey;

		private string _definitionConfigPath;

		private string _targetConfigPath;

		private string _subPath;

		private string _filename;

		private int _lineNumber;

		private object _streamVersion;

		private string _configSource;

		private string _configSourceStreamName;

		private object _configSourceStreamVersion;

		private bool _skipInChildApps;

		private string _rawXml;

		private string _protectionProviderName;

		private OverrideModeSetting _overrideMode;

		public string Filename => _filename;

		public int LineNumber
		{
			get
			{
				return _lineNumber;
			}
			set
			{
				_lineNumber = value;
			}
		}

		internal object StreamVersion
		{
			get
			{
				return _streamVersion;
			}
			set
			{
				_streamVersion = value;
			}
		}

		internal string ConfigSource
		{
			get
			{
				return _configSource;
			}
			set
			{
				_configSource = value;
			}
		}

		internal string ConfigSourceStreamName
		{
			get
			{
				return _configSourceStreamName;
			}
			set
			{
				_configSourceStreamName = value;
			}
		}

		internal object ConfigSourceStreamVersion
		{
			set
			{
				_configSourceStreamVersion = value;
			}
		}

		internal string ConfigKey => _configKey;

		internal string DefinitionConfigPath => _definitionConfigPath;

		internal string TargetConfigPath
		{
			get
			{
				return _targetConfigPath;
			}
			set
			{
				_targetConfigPath = value;
			}
		}

		internal string SubPath => _subPath;

		internal string RawXml
		{
			get
			{
				return _rawXml;
			}
			set
			{
				_rawXml = value;
			}
		}

		internal string ProtectionProviderName
		{
			get
			{
				return _protectionProviderName;
			}
			set
			{
				_protectionProviderName = value;
			}
		}

		internal OverrideModeSetting OverrideModeSetting
		{
			get
			{
				return _overrideMode;
			}
			set
			{
				_overrideMode = value;
			}
		}

		internal bool SkipInChildApps
		{
			get
			{
				return _skipInChildApps;
			}
			set
			{
				_skipInChildApps = value;
			}
		}

		internal SectionXmlInfo(string configKey, string definitionConfigPath, string targetConfigPath, string subPath, string filename, int lineNumber, object streamVersion, string rawXml, string configSource, string configSourceStreamName, object configSourceStreamVersion, string protectionProviderName, OverrideModeSetting overrideMode, bool skipInChildApps)
		{
			_configKey = configKey;
			_definitionConfigPath = definitionConfigPath;
			_targetConfigPath = targetConfigPath;
			_subPath = subPath;
			_filename = filename;
			_lineNumber = lineNumber;
			_streamVersion = streamVersion;
			_rawXml = rawXml;
			_configSource = configSource;
			_configSourceStreamName = configSourceStreamName;
			_configSourceStreamVersion = configSourceStreamVersion;
			_protectionProviderName = protectionProviderName;
			_overrideMode = overrideMode;
			_skipInChildApps = skipInChildApps;
		}
	}
	[Serializable]
	internal struct SimpleBitVector32
	{
		private int data;

		internal int Data => data;

		internal bool this[int bit]
		{
			get
			{
				return (data & bit) == bit;
			}
			set
			{
				int num = data;
				if (value)
				{
					data = num | bit;
				}
				else
				{
					data = num & ~bit;
				}
			}
		}

		internal SimpleBitVector32(int data)
		{
			this.data = data;
		}
	}
	internal class StreamInfo
	{
		private string _sectionName;

		private string _configSource;

		private string _streamName;

		private bool _isMonitored;

		private object _version;

		internal string SectionName => _sectionName;

		internal string ConfigSource => _configSource;

		internal string StreamName => _streamName;

		internal bool IsMonitored
		{
			get
			{
				return _isMonitored;
			}
			set
			{
				_isMonitored = value;
			}
		}

		internal object Version
		{
			get
			{
				return _version;
			}
			set
			{
				_version = value;
			}
		}

		internal StreamInfo(string sectionName, string configSource, string streamName)
		{
			_sectionName = sectionName;
			_configSource = configSource;
			_streamName = streamName;
		}

		private StreamInfo()
		{
		}

		internal StreamInfo Clone()
		{
			StreamInfo streamInfo = new StreamInfo();
			streamInfo._sectionName = _sectionName;
			streamInfo._configSource = _configSource;
			streamInfo._streamName = _streamName;
			streamInfo._isMonitored = _isMonitored;
			streamInfo._version = _version;
			return streamInfo;
		}
	}
	internal class StreamUpdate
	{
		private string _newStreamname;

		private bool _writeCompleted;

		internal string NewStreamname => _newStreamname;

		internal bool WriteCompleted
		{
			get
			{
				return _writeCompleted;
			}
			set
			{
				_writeCompleted = value;
			}
		}

		internal StreamUpdate(string newStreamname)
		{
			_newStreamname = newStreamname;
		}
	}
	public sealed class CommaDelimitedStringCollection : StringCollection
	{
		private bool _Modified;

		private bool _ReadOnly;

		private string _OriginalString;

		public bool IsModified
		{
			get
			{
				if (!_Modified)
				{
					return ToString() != _OriginalString;
				}
				return true;
			}
		}

		public new bool IsReadOnly => _ReadOnly;

		public new string this[int index]
		{
			get
			{
				return base[index];
			}
			set
			{
				ThrowIfReadOnly();
				ThrowIfContainsDelimiter(value);
				_Modified = true;
				base[index] = value.Trim();
			}
		}

		public CommaDelimitedStringCollection()
		{
			_ReadOnly = false;
			_Modified = false;
			_OriginalString = ToString();
		}

		internal void FromString(string list)
		{
			char[] separator = new char[1] { ',' };
			if (list != null)
			{
				string[] array = list.Split(separator);
				string[] array2 = array;
				foreach (string text in array2)
				{
					string text2 = text.Trim();
					if (text2.Length != 0)
					{
						Add(text.Trim());
					}
				}
			}
			_OriginalString = ToString();
			_ReadOnly = false;
			_Modified = false;
		}

		public override string ToString()
		{
			string text = null;
			if (base.Count > 0)
			{
				StringBuilder stringBuilder = new StringBuilder();
				StringEnumerator enumerator = GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						string current = enumerator.Current;
						ThrowIfContainsDelimiter(current);
						stringBuilder.Append(current.Trim());
						stringBuilder.Append(',');
					}
				}
				finally
				{
					if (enumerator is IDisposable disposable)
					{
						disposable.Dispose();
					}
				}
				text = stringBuilder.ToString();
				if (text.Length > 0)
				{
					text = text.Substring(0, text.Length - 1);
				}
				if (text.Length == 0)
				{
					text = null;
				}
			}
			return text;
		}

		private void ThrowIfReadOnly()
		{
			if (IsReadOnly)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_read_only"));
			}
		}

		private void ThrowIfContainsDelimiter(string value)
		{
			if (value.Contains(","))
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_base_value_cannot_contain", ","));
			}
		}

		public void SetReadOnly()
		{
			_ReadOnly = true;
		}

		public new void Add(string value)
		{
			ThrowIfReadOnly();
			ThrowIfContainsDelimiter(value);
			_Modified = true;
			base.Add(value.Trim());
		}

		public new void AddRange(string[] range)
		{
			ThrowIfReadOnly();
			_Modified = true;
			foreach (string text in range)
			{
				ThrowIfContainsDelimiter(text);
				base.Add(text.Trim());
			}
		}

		public new void Clear()
		{
			ThrowIfReadOnly();
			_Modified = true;
			base.Clear();
		}

		public new void Insert(int index, string value)
		{
			ThrowIfReadOnly();
			ThrowIfContainsDelimiter(value);
			_Modified = true;
			base.Insert(index, value.Trim());
		}

		public new void Remove(string value)
		{
			ThrowIfReadOnly();
			ThrowIfContainsDelimiter(value);
			_Modified = true;
			base.Remove(value.Trim());
		}

		public CommaDelimitedStringCollection Clone()
		{
			CommaDelimitedStringCollection commaDelimitedStringCollection = new CommaDelimitedStringCollection();
			StringEnumerator enumerator = GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					string current = enumerator.Current;
					commaDelimitedStringCollection.Add(current);
				}
			}
			finally
			{
				if (enumerator is IDisposable disposable)
				{
					disposable.Dispose();
				}
			}
			commaDelimitedStringCollection._Modified = false;
			commaDelimitedStringCollection._ReadOnly = _ReadOnly;
			commaDelimitedStringCollection._OriginalString = _OriginalString;
			return commaDelimitedStringCollection;
		}
	}
	internal static class StringUtil
	{
		internal static bool EqualsNE(string s1, string s2)
		{
			if (s1 == null)
			{
				s1 = string.Empty;
			}
			if (s2 == null)
			{
				s2 = string.Empty;
			}
			return string.Equals(s1, s2, StringComparison.Ordinal);
		}

		internal static bool EqualsIgnoreCase(string s1, string s2)
		{
			return string.Equals(s1, s2, StringComparison.OrdinalIgnoreCase);
		}

		internal static bool StartsWith(string s1, string s2)
		{
			if (s2 == null)
			{
				return false;
			}
			return 0 == string.Compare(s1, 0, s2, 0, s2.Length, StringComparison.Ordinal);
		}

		internal static bool StartsWithIgnoreCase(string s1, string s2)
		{
			if (s2 == null)
			{
				return false;
			}
			return 0 == string.Compare(s1, 0, s2, 0, s2.Length, StringComparison.OrdinalIgnoreCase);
		}

		internal static string[] ObjectArrayToStringArray(object[] objectArray)
		{
			string[] array = new string[objectArray.Length];
			objectArray.CopyTo(array, 0);
			return array;
		}
	}
	public class StringValidator : ConfigurationValidatorBase
	{
		private int _minLength;

		private int _maxLength;

		private string _invalidChars;

		public StringValidator(int minLength)
			: this(minLength, int.MaxValue, null)
		{
		}

		public StringValidator(int minLength, int maxLength)
			: this(minLength, maxLength, null)
		{
		}

		public StringValidator(int minLength, int maxLength, string invalidCharacters)
		{
			_minLength = minLength;
			_maxLength = maxLength;
			_invalidChars = invalidCharacters;
		}

		public override bool CanValidate(Type type)
		{
			return type == typeof(string);
		}

		public override void Validate(object value)
		{
			ValidatorUtils.HelperParamValidation(value, typeof(string));
			string text = value as string;
			int num = text?.Length ?? 0;
			if (num < _minLength)
			{
				throw new ArgumentException(SR.GetString("Validator_string_min_length", _minLength));
			}
			if (num > _maxLength)
			{
				throw new ArgumentException(SR.GetString("Validator_string_max_length", _maxLength));
			}
			if (num > 0 && _invalidChars != null && _invalidChars.Length > 0)
			{
				char[] array = new char[_invalidChars.Length];
				_invalidChars.CopyTo(0, array, 0, _invalidChars.Length);
				if (text.IndexOfAny(array) != -1)
				{
					throw new ArgumentException(SR.GetString("Validator_string_invalid_chars", _invalidChars));
				}
			}
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class StringValidatorAttribute : ConfigurationValidatorAttribute
	{
		private int _minLength;

		private int _maxLength = int.MaxValue;

		private string _invalidChars;

		public override ConfigurationValidatorBase ValidatorInstance => new StringValidator(_minLength, _maxLength, _invalidChars);

		public int MinLength
		{
			get
			{
				return _minLength;
			}
			set
			{
				if (_maxLength < value)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_minLength = value;
			}
		}

		public int MaxLength
		{
			get
			{
				return _maxLength;
			}
			set
			{
				if (_minLength > value)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_maxLength = value;
			}
		}

		public string InvalidCharacters
		{
			get
			{
				return _invalidChars;
			}
			set
			{
				_invalidChars = value;
			}
		}
	}
	public sealed class SubclassTypeValidator : ConfigurationValidatorBase
	{
		private Type _base;

		public SubclassTypeValidator(Type baseClass)
		{
			if (baseClass == null)
			{
				throw new ArgumentNullException("baseClass");
			}
			_base = baseClass;
		}

		public override bool CanValidate(Type type)
		{
			return type == typeof(Type);
		}

		public override void Validate(object value)
		{
			if (value != null)
			{
				if (!(value is Type))
				{
					ValidatorUtils.HelperParamValidation(value, typeof(Type));
				}
				if (!_base.IsAssignableFrom((Type)value))
				{
					throw new ArgumentException(SR.GetString("Subclass_validator_error", ((Type)value).FullName, _base.FullName));
				}
			}
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class SubclassTypeValidatorAttribute : ConfigurationValidatorAttribute
	{
		private Type _baseClass;

		public override ConfigurationValidatorBase ValidatorInstance => new SubclassTypeValidator(_baseClass);

		public Type BaseClass => _baseClass;

		public SubclassTypeValidatorAttribute(Type baseClass)
		{
			_baseClass = baseClass;
		}
	}
	public class TimeSpanMinutesConverter : ConfigurationConverterBase
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(TimeSpan));
			return ((long)((TimeSpan)value).TotalMinutes).ToString(CultureInfo.InvariantCulture);
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			long num = long.Parse((string)data, CultureInfo.InvariantCulture);
			return TimeSpan.FromMinutes(num);
		}
	}
	public sealed class TimeSpanMinutesOrInfiniteConverter : TimeSpanMinutesConverter
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(TimeSpan));
			if ((TimeSpan)value == TimeSpan.MaxValue)
			{
				return "Infinite";
			}
			return base.ConvertTo(ctx, ci, value, type);
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			if ((string)data == "Infinite")
			{
				return TimeSpan.MaxValue;
			}
			return base.ConvertFrom(ctx, ci, data);
		}
	}
	public class TimeSpanSecondsConverter : ConfigurationConverterBase
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(TimeSpan));
			return ((long)((TimeSpan)value).TotalSeconds).ToString(CultureInfo.InvariantCulture);
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			long num = 0L;
			try
			{
				num = long.Parse((string)data, CultureInfo.InvariantCulture);
			}
			catch
			{
				throw new ArgumentException(SR.GetString("Converter_timespan_not_in_second"));
			}
			return TimeSpan.FromSeconds(num);
		}
	}
	public sealed class TimeSpanSecondsOrInfiniteConverter : TimeSpanSecondsConverter
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(TimeSpan));
			if ((TimeSpan)value == TimeSpan.MaxValue)
			{
				return "Infinite";
			}
			return base.ConvertTo(ctx, ci, value, type);
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			if ((string)data == "Infinite")
			{
				return TimeSpan.MaxValue;
			}
			return base.ConvertFrom(ctx, ci, data);
		}
	}
	public class TimeSpanValidator : ConfigurationValidatorBase
	{
		private enum ValidationFlags
		{
			None,
			ExclusiveRange
		}

		private ValidationFlags _flags;

		private TimeSpan _minValue = TimeSpan.MinValue;

		private TimeSpan _maxValue = TimeSpan.MaxValue;

		private long _resolution;

		public TimeSpanValidator(TimeSpan minValue, TimeSpan maxValue)
			: this(minValue, maxValue, rangeIsExclusive: false, 0L)
		{
		}

		public TimeSpanValidator(TimeSpan minValue, TimeSpan maxValue, bool rangeIsExclusive)
			: this(minValue, maxValue, rangeIsExclusive, 0L)
		{
		}

		public TimeSpanValidator(TimeSpan minValue, TimeSpan maxValue, bool rangeIsExclusive, long resolutionInSeconds)
		{
			if (resolutionInSeconds < 0)
			{
				throw new ArgumentOutOfRangeException("resolutionInSeconds");
			}
			if (minValue > maxValue)
			{
				throw new ArgumentOutOfRangeException("minValue", SR.GetString("Validator_min_greater_than_max"));
			}
			_minValue = minValue;
			_maxValue = maxValue;
			_resolution = resolutionInSeconds;
			_flags = (rangeIsExclusive ? ValidationFlags.ExclusiveRange : ValidationFlags.None);
		}

		public override bool CanValidate(Type type)
		{
			return type == typeof(TimeSpan);
		}

		public override void Validate(object value)
		{
			ValidatorUtils.HelperParamValidation(value, typeof(TimeSpan));
			ValidatorUtils.ValidateScalar((TimeSpan)value, _minValue, _maxValue, _resolution, _flags == ValidationFlags.ExclusiveRange);
		}
	}
	[AttributeUsage(AttributeTargets.Property)]
	public sealed class TimeSpanValidatorAttribute : ConfigurationValidatorAttribute
	{
		public const string TimeSpanMinValue = "-10675199.02:48:05.4775808";

		public const string TimeSpanMaxValue = "10675199.02:48:05.4775807";

		private TimeSpan _min = TimeSpan.MinValue;

		private TimeSpan _max = TimeSpan.MaxValue;

		private bool _excludeRange;

		public override ConfigurationValidatorBase ValidatorInstance => new TimeSpanValidator(_min, _max, _excludeRange);

		public TimeSpan MinValue => _min;

		public TimeSpan MaxValue => _max;

		public string MinValueString
		{
			get
			{
				return _min.ToString();
			}
			set
			{
				TimeSpan timeSpan = TimeSpan.Parse(value);
				if (_max < timeSpan)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_min = timeSpan;
			}
		}

		public string MaxValueString
		{
			get
			{
				return _max.ToString();
			}
			set
			{
				TimeSpan timeSpan = TimeSpan.Parse(value);
				if (_min > timeSpan)
				{
					throw new ArgumentOutOfRangeException("value", SR.GetString("Validator_min_greater_than_max"));
				}
				_max = timeSpan;
			}
		}

		public bool ExcludeRange
		{
			get
			{
				return _excludeRange;
			}
			set
			{
				_excludeRange = value;
			}
		}
	}
	public sealed class TypeNameConverter : ConfigurationConverterBase
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			if (!(value is Type))
			{
				ValidateType(value, typeof(Type));
			}
			string result = null;
			if (value != null)
			{
				result = ((Type)value).AssemblyQualifiedName;
			}
			return result;
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			Type typeWithReflectionPermission = TypeUtil.GetTypeWithReflectionPermission((string)data, throwOnError: false);
			if (typeWithReflectionPermission == null)
			{
				throw new ArgumentException(SR.GetString("Type_cannot_be_resolved", (string)data));
			}
			return typeWithReflectionPermission;
		}
	}
	internal static class TypeUtil
	{
		private delegate object CreateInstanceInvoker(Type type);

		private delegate Delegate CreateDelegateInvoker(Type type, MethodInfo method);

		private static PermissionSet s_fullTrustPermissionSet;

		private static readonly ReflectionPermission s_memberAccessPermission = new ReflectionPermission(ReflectionPermissionFlag.MemberAccess);

		private static readonly AspNetHostingPermission s_aspNetHostingPermission = new AspNetHostingPermission(AspNetHostingPermissionLevel.Minimal);

		internal static bool IsCallerFullTrust
		{
			get
			{
				bool result = false;
				try
				{
					if (s_fullTrustPermissionSet == null)
					{
						s_fullTrustPermissionSet = new PermissionSet(PermissionState.Unrestricted);
					}
					s_fullTrustPermissionSet.Demand();
					result = true;
					return result;
				}
				catch
				{
					return result;
				}
			}
		}

		private static Type GetLegacyType(string typeString)
		{
			Type result = null;
			try
			{
				Assembly assembly = typeof(ConfigurationException).Assembly;
				result = assembly.GetType(typeString, throwOnError: false);
				return result;
			}
			catch
			{
				return result;
			}
		}

		private static Type GetTypeImpl(string typeString, bool throwOnError)
		{
			Type type = null;
			Exception ex = null;
			try
			{
				type = Type.GetType(typeString, throwOnError);
			}
			catch (Exception ex2)
			{
				ex = ex2;
			}
			if (type == null)
			{
				type = GetLegacyType(typeString);
				if (type == null && ex != null)
				{
					throw ex;
				}
			}
			return type;
		}

		[ReflectionPermission(SecurityAction.Assert, Flags = ReflectionPermissionFlag.TypeInformation)]
		internal static Type GetTypeWithReflectionPermission(IInternalConfigHost host, string typeString, bool throwOnError)
		{
			Type type = null;
			Exception ex = null;
			try
			{
				type = host.GetConfigType(typeString, throwOnError);
			}
			catch (Exception ex2)
			{
				ex = ex2;
			}
			if (type == null)
			{
				type = GetLegacyType(typeString);
				if (type == null && ex != null)
				{
					throw ex;
				}
			}
			return type;
		}

		[ReflectionPermission(SecurityAction.Assert, Flags = ReflectionPermissionFlag.TypeInformation)]
		internal static Type GetTypeWithReflectionPermission(string typeString, bool throwOnError)
		{
			return GetTypeImpl(typeString, throwOnError);
		}

		internal static T CreateInstance<T>(string typeString)
		{
			return CreateInstanceRestricted<T>(null, typeString);
		}

		internal static T CreateInstanceRestricted<T>(Type callingType, string typeString)
		{
			Type typeImpl = GetTypeImpl(typeString, throwOnError: true);
			VerifyAssignableType(typeof(T), typeImpl, throwOnError: true);
			return (T)CreateInstanceRestricted(callingType, typeImpl);
		}

		[ReflectionPermission(SecurityAction.Assert, Flags = (ReflectionPermissionFlag.TypeInformation | ReflectionPermissionFlag.MemberAccess))]
		internal static object CreateInstanceWithReflectionPermission(Type type)
		{
			return Activator.CreateInstance(type, nonPublic: true);
		}

		internal static object CreateInstanceRestricted(Type callingType, Type targetType)
		{
			if (CallerHasMemberAccessOrAspNetPermission())
			{
				return CreateInstanceWithReflectionPermission(targetType);
			}
			DynamicMethod dynamicMethod = CreateDynamicMethod(callingType, typeof(object), new Type[1] { typeof(Type) });
			ILGenerator iLGenerator = dynamicMethod.GetILGenerator();
			iLGenerator.Emit(OpCodes.Ldarg_0);
			iLGenerator.Emit(OpCodes.Ldc_I4_1);
			iLGenerator.Emit(OpCodes.Call, typeof(Activator).GetMethod("CreateInstance", new Type[2]
			{
				typeof(Type),
				typeof(bool)
			}));
			iLGenerator.Emit(OpCodes.Ret);
			CreateInstanceInvoker createInstanceInvoker = (CreateInstanceInvoker)dynamicMethod.CreateDelegate(typeof(CreateInstanceInvoker));
			return createInstanceInvoker(targetType);
		}

		internal static Delegate CreateDelegateRestricted(Type callingType, Type delegateType, MethodInfo targetMethod)
		{
			if (CallerHasMemberAccessOrAspNetPermission())
			{
				return Delegate.CreateDelegate(delegateType, targetMethod);
			}
			DynamicMethod dynamicMethod = CreateDynamicMethod(callingType, typeof(Delegate), new Type[2]
			{
				typeof(Type),
				typeof(MethodInfo)
			});
			ILGenerator iLGenerator = dynamicMethod.GetILGenerator();
			iLGenerator.Emit(OpCodes.Ldarg_0);
			iLGenerator.Emit(OpCodes.Ldarg_1);
			iLGenerator.Emit(OpCodes.Call, typeof(Delegate).GetMethod("CreateDelegate", new Type[2]
			{
				typeof(Type),
				typeof(MethodInfo)
			}));
			iLGenerator.Emit(OpCodes.Ret);
			CreateDelegateInvoker createDelegateInvoker = (CreateDelegateInvoker)dynamicMethod.CreateDelegate(typeof(CreateDelegateInvoker));
			return createDelegateInvoker(delegateType, targetMethod);
		}

		private static DynamicMethod CreateDynamicMethod(Type owner, Type returnType, Type[] parameterTypes)
		{
			if (owner != null)
			{
				return CreateDynamicMethodWithUnrestrictedPermission(owner, returnType, parameterTypes);
			}
			return new DynamicMethod("temp-dynamic-method", returnType, parameterTypes);
		}

		[PermissionSet(SecurityAction.Assert, Unrestricted = true)]
		private static DynamicMethod CreateDynamicMethodWithUnrestrictedPermission(Type owner, Type returnType, Type[] parameterTypes)
		{
			return new DynamicMethod("temp-dynamic-method", returnType, parameterTypes, owner);
		}

		[ReflectionPermission(SecurityAction.Assert, Flags = ReflectionPermissionFlag.TypeInformation)]
		internal static ConstructorInfo GetConstructorWithReflectionPermission(Type type, Type baseType, bool throwOnError)
		{
			type = VerifyAssignableType(baseType, type, throwOnError);
			if (type == null)
			{
				return null;
			}
			BindingFlags bindingAttr = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
			ConstructorInfo constructor = type.GetConstructor(bindingAttr, null, CallingConventions.HasThis, Type.EmptyTypes, null);
			if (constructor == null && throwOnError)
			{
				throw new TypeLoadException(SR.GetString("TypeNotPublic", type.AssemblyQualifiedName));
			}
			return constructor;
		}

		[ReflectionPermission(SecurityAction.Assert, Flags = (ReflectionPermissionFlag.TypeInformation | ReflectionPermissionFlag.MemberAccess))]
		internal static object InvokeCtorWithReflectionPermission(ConstructorInfo ctor)
		{
			return ctor.Invoke(null);
		}

		internal static bool IsTypeFromTrustedAssemblyWithoutAptca(Type type)
		{
			Assembly assembly = type.Assembly;
			if (assembly.GlobalAssemblyCache)
			{
				return !HasAptcaBit(assembly);
			}
			return false;
		}

		internal static Type VerifyAssignableType(Type baseType, Type type, bool throwOnError)
		{
			if (baseType.IsAssignableFrom(type))
			{
				return type;
			}
			if (throwOnError)
			{
				throw new TypeLoadException(SR.GetString("Config_type_doesnt_inherit_from_type", type.FullName, baseType.FullName));
			}
			return null;
		}

		[ReflectionPermission(SecurityAction.Assert, Flags = (ReflectionPermissionFlag.TypeInformation | ReflectionPermissionFlag.MemberAccess))]
		private static bool HasAptcaBit(Assembly assembly)
		{
			object[] customAttributes = assembly.GetCustomAttributes(typeof(AllowPartiallyTrustedCallersAttribute), inherit: false);
			if (customAttributes != null)
			{
				return customAttributes.Length > 0;
			}
			return false;
		}

		private static bool CallerHasMemberAccessOrAspNetPermission()
		{
			try
			{
				s_memberAccessPermission.Demand();
				return true;
			}
			catch (SecurityException)
			{
			}
			try
			{
				s_aspNetHostingPermission.Demand();
				return true;
			}
			catch (SecurityException)
			{
			}
			return false;
		}

		internal static bool IsTypeAllowedInConfig(Type t)
		{
			if (IsCallerFullTrust)
			{
				return true;
			}
			Assembly assembly = t.Assembly;
			if (!assembly.GlobalAssemblyCache)
			{
				return true;
			}
			if (HasAptcaBit(assembly))
			{
				return true;
			}
			return false;
		}
	}
	internal class UpdateConfigHost : DelegatingConfigHost
	{
		private HybridDictionary _streams;

		internal UpdateConfigHost(IInternalConfigHost host)
		{
			base.Host = host;
		}

		internal void AddStreamname(string oldStreamname, string newStreamname, bool alwaysIntercept)
		{
			if (!string.IsNullOrEmpty(oldStreamname) && (alwaysIntercept || !StringUtil.EqualsIgnoreCase(oldStreamname, newStreamname)))
			{
				if (_streams == null)
				{
					_streams = new HybridDictionary(caseInsensitive: true);
				}
				_streams[oldStreamname] = new StreamUpdate(newStreamname);
			}
		}

		internal string GetNewStreamname(string oldStreamname)
		{
			StreamUpdate streamUpdate = GetStreamUpdate(oldStreamname, alwaysIntercept: false);
			if (streamUpdate != null)
			{
				return streamUpdate.NewStreamname;
			}
			return oldStreamname;
		}

		private StreamUpdate GetStreamUpdate(string oldStreamname, bool alwaysIntercept)
		{
			if (_streams == null)
			{
				return null;
			}
			StreamUpdate streamUpdate = (StreamUpdate)_streams[oldStreamname];
			if (streamUpdate != null && !alwaysIntercept && !streamUpdate.WriteCompleted)
			{
				streamUpdate = null;
			}
			return streamUpdate;
		}

		public override object GetStreamVersion(string streamName)
		{
			StreamUpdate streamUpdate = GetStreamUpdate(streamName, alwaysIntercept: false);
			if (streamUpdate != null)
			{
				return InternalConfigHost.StaticGetStreamVersion(streamUpdate.NewStreamname);
			}
			return base.Host.GetStreamVersion(streamName);
		}

		public override Stream OpenStreamForRead(string streamName)
		{
			StreamUpdate streamUpdate = GetStreamUpdate(streamName, alwaysIntercept: false);
			if (streamUpdate != null)
			{
				return InternalConfigHost.StaticOpenStreamForRead(streamUpdate.NewStreamname);
			}
			return base.Host.OpenStreamForRead(streamName);
		}

		public override Stream OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext)
		{
			StreamUpdate streamUpdate = GetStreamUpdate(streamName, alwaysIntercept: true);
			if (streamUpdate != null)
			{
				return InternalConfigHost.StaticOpenStreamForWrite(streamUpdate.NewStreamname, templateStreamName, ref writeContext, assertPermissions: false);
			}
			return base.Host.OpenStreamForWrite(streamName, templateStreamName, ref writeContext);
		}

		public override void WriteCompleted(string streamName, bool success, object writeContext)
		{
			StreamUpdate streamUpdate = GetStreamUpdate(streamName, alwaysIntercept: true);
			if (streamUpdate != null)
			{
				InternalConfigHost.StaticWriteCompleted(streamUpdate.NewStreamname, success, writeContext, assertPermissions: false);
				if (success)
				{
					streamUpdate.WriteCompleted = true;
				}
			}
			else
			{
				base.Host.WriteCompleted(streamName, success, writeContext);
			}
		}

		public override bool IsConfigRecordRequired(string configPath)
		{
			return true;
		}

		public override void DeleteStream(string streamName)
		{
			StreamUpdate streamUpdate = GetStreamUpdate(streamName, alwaysIntercept: false);
			if (streamUpdate != null)
			{
				InternalConfigHost.StaticDeleteStream(streamUpdate.NewStreamname);
			}
			else
			{
				base.Host.DeleteStream(streamName);
			}
		}

		public override bool IsFile(string streamName)
		{
			StreamUpdate streamUpdate = GetStreamUpdate(streamName, alwaysIntercept: false);
			if (streamUpdate != null)
			{
				return InternalConfigHost.StaticIsFile(streamUpdate.NewStreamname);
			}
			return base.Host.IsFile(streamName);
		}
	}
	internal static class UrlPath
	{
		private const string FILE_URL_LOCAL = "file:///";

		private const string FILE_URL_UNC = "file:";

		internal static string GetDirectoryOrRootName(string path)
		{
			string text = Path.GetDirectoryName(path);
			if (text == null)
			{
				text = Path.GetPathRoot(path);
			}
			return text;
		}

		internal static bool IsEqualOrSubdirectory(string dir, string subdir)
		{
			if (string.IsNullOrEmpty(dir))
			{
				return true;
			}
			if (string.IsNullOrEmpty(subdir))
			{
				return false;
			}
			int num = dir.Length;
			if (dir[num - 1] == '\\')
			{
				num--;
			}
			int num2 = subdir.Length;
			if (subdir[num2 - 1] == '\\')
			{
				num2--;
			}
			if (num2 < num)
			{
				return false;
			}
			if (string.Compare(dir, 0, subdir, 0, num, StringComparison.OrdinalIgnoreCase) != 0)
			{
				return false;
			}
			if (num2 > num && subdir[num] != '\\')
			{
				return false;
			}
			return true;
		}

		internal static bool IsEqualOrSubpath(string path, string subpath)
		{
			return IsEqualOrSubpathImpl(path, subpath, excludeEqual: false);
		}

		internal static bool IsSubpath(string path, string subpath)
		{
			return IsEqualOrSubpathImpl(path, subpath, excludeEqual: true);
		}

		private static bool IsEqualOrSubpathImpl(string path, string subpath, bool excludeEqual)
		{
			if (string.IsNullOrEmpty(path))
			{
				return true;
			}
			if (string.IsNullOrEmpty(subpath))
			{
				return false;
			}
			int num = path.Length;
			if (path[num - 1] == '/')
			{
				num--;
			}
			int num2 = subpath.Length;
			if (subpath[num2 - 1] == '/')
			{
				num2--;
			}
			if (num2 < num)
			{
				return false;
			}
			if (excludeEqual && num2 == num)
			{
				return false;
			}
			if (string.Compare(path, 0, subpath, 0, num, StringComparison.OrdinalIgnoreCase) != 0)
			{
				return false;
			}
			if (num2 > num && subpath[num] != '/')
			{
				return false;
			}
			return true;
		}

		private static bool IsDirectorySeparatorChar(char ch)
		{
			if (ch != '\\')
			{
				return ch == '/';
			}
			return true;
		}

		private static bool IsAbsoluteLocalPhysicalPath(string path)
		{
			if (path == null || path.Length < 3)
			{
				return false;
			}
			if (path[1] == ':')
			{
				return IsDirectorySeparatorChar(path[2]);
			}
			return false;
		}

		private static bool IsAbsoluteUNCPhysicalPath(string path)
		{
			if (path == null || path.Length < 3)
			{
				return false;
			}
			if (IsDirectorySeparatorChar(path[0]))
			{
				return IsDirectorySeparatorChar(path[1]);
			}
			return false;
		}

		internal static string ConvertFileNameToUrl(string fileName)
		{
			string text;
			if (IsAbsoluteLocalPhysicalPath(fileName))
			{
				text = "file:///";
			}
			else
			{
				if (!IsAbsoluteUNCPhysicalPath(fileName))
				{
					throw ExceptionUtil.ParameterInvalid("filename");
				}
				text = "file:";
			}
			return text + fileName.Replace('\\', '/');
		}
	}
	public delegate void ValidatorCallback(object value);
	internal static class ValidatorUtils
	{
		public static void HelperParamValidation(object value, Type allowedType)
		{
			if (value == null || value.GetType() == allowedType)
			{
				return;
			}
			throw new ArgumentException(SR.GetString("Validator_value_type_invalid"), string.Empty);
		}

		public static void ValidateScalar<T>(T value, T min, T max, T resolution, bool exclusiveRange) where T : IComparable<T>
		{
			ValidateRangeImpl(value, min, max, exclusiveRange);
			ValidateResolution(resolution.ToString(), Convert.ToInt64(value, CultureInfo.InvariantCulture), Convert.ToInt64(resolution, CultureInfo.InvariantCulture));
		}

		private static void ValidateRangeImpl<T>(T value, T min, T max, bool exclusiveRange) where T : IComparable<T>
		{
			IComparable<T> comparable = value;
			bool flag = false;
			if (comparable.CompareTo(min) >= 0)
			{
				flag = true;
			}
			if (flag && comparable.CompareTo(max) > 0)
			{
				flag = false;
			}
			if (!(flag ^ exclusiveRange))
			{
				string text = null;
				throw new ArgumentException(string.Format(format: min.Equals(max) ? ((!exclusiveRange) ? SR.GetString("Validation_scalar_range_violation_not_equal") : SR.GetString("Validation_scalar_range_violation_not_different")) : ((!exclusiveRange) ? SR.GetString("Validation_scalar_range_violation_not_in_range") : SR.GetString("Validation_scalar_range_violation_not_outside_range")), provider: CultureInfo.InvariantCulture, args: new object[2]
				{
					min.ToString(),
					max.ToString()
				}));
			}
		}

		private static void ValidateResolution(string resolutionAsString, long value, long resolution)
		{
			if (value % resolution != 0)
			{
				throw new ArgumentException(SR.GetString("Validator_scalar_resolution_violation", resolutionAsString));
			}
		}

		public static void ValidateScalar(TimeSpan value, TimeSpan min, TimeSpan max, long resolutionInSeconds, bool exclusiveRange)
		{
			ValidateRangeImpl(value, min, max, exclusiveRange);
			if (resolutionInSeconds > 0)
			{
				ValidateResolution(TimeSpan.FromSeconds(resolutionInSeconds).ToString(), value.Ticks, resolutionInSeconds * 10000000);
			}
		}
	}
	public sealed class WhiteSpaceTrimStringConverter : ConfigurationConverterBase
	{
		public override object ConvertTo(ITypeDescriptorContext ctx, CultureInfo ci, object value, Type type)
		{
			ValidateType(value, typeof(string));
			if (value == null)
			{
				return string.Empty;
			}
			return ((string)value).Trim();
		}

		public override object ConvertFrom(ITypeDescriptorContext ctx, CultureInfo ci, object data)
		{
			return ((string)data).Trim();
		}
	}
	internal sealed class XmlUtil : IDisposable, IConfigErrorInfo
	{
		private const int MAX_LINE_WIDTH = 60;

		private static readonly int[] s_positionOffset = new int[18]
		{
			0, 1, -1, 0, 9, 1, -1, 2, 4, -1,
			10, -1, -1, 0, 0, 2, -1, 2
		};

		private Stream _stream;

		private string _streamName;

		private XmlTextReader _reader;

		private StringWriter _cachedStringWriter;

		private ConfigurationSchemaErrors _schemaErrors;

		private int _lastLineNumber;

		private int _lastLinePosition;

		public string Filename => _streamName;

		public int LineNumber => Reader.LineNumber;

		internal int TrueLinePosition => Reader.LinePosition - GetPositionOffset(Reader.NodeType);

		internal XmlTextReader Reader => _reader;

		internal ConfigurationSchemaErrors SchemaErrors => _schemaErrors;

		private static int GetPositionOffset(XmlNodeType nodeType)
		{
			return s_positionOffset[(int)nodeType];
		}

		internal XmlUtil(Stream stream, string name, bool readToFirstElement)
			: this(stream, name, readToFirstElement, new ConfigurationSchemaErrors())
		{
		}

		internal XmlUtil(Stream stream, string name, bool readToFirstElement, ConfigurationSchemaErrors schemaErrors)
		{
			try
			{
				_streamName = name;
				_stream = stream;
				_reader = new XmlTextReader(_stream);
				_reader.XmlResolver = null;
				_schemaErrors = schemaErrors;
				_lastLineNumber = 1;
				_lastLinePosition = 1;
				if (!readToFirstElement)
				{
					return;
				}
				_reader.WhitespaceHandling = WhitespaceHandling.None;
				bool flag = false;
				while (!flag && _reader.Read())
				{
					switch (_reader.NodeType)
					{
					case XmlNodeType.Element:
						flag = true;
						break;
					default:
						throw new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_element"), this);
					case XmlNodeType.Comment:
					case XmlNodeType.DocumentType:
					case XmlNodeType.XmlDeclaration:
						break;
					}
				}
			}
			catch
			{
				ReleaseResources();
				throw;
			}
		}

		private void ReleaseResources()
		{
			if (_reader != null)
			{
				_reader.Close();
				_reader = null;
			}
			else if (_stream != null)
			{
				_stream.Close();
			}
			_stream = null;
			if (_cachedStringWriter != null)
			{
				_cachedStringWriter.Close();
				_cachedStringWriter = null;
			}
		}

		public void Dispose()
		{
			ReleaseResources();
		}

		internal void ReadToNextElement()
		{
			while (_reader.Read() && _reader.MoveToContent() != XmlNodeType.Element)
			{
			}
		}

		internal void SkipToNextElement()
		{
			_reader.Skip();
			_reader.MoveToContent();
			while (!_reader.EOF && _reader.NodeType != XmlNodeType.Element)
			{
				_reader.Read();
				_reader.MoveToContent();
			}
		}

		internal void StrictReadToNextElement(ExceptionAction action)
		{
			while (_reader.Read() && _reader.NodeType != XmlNodeType.Element)
			{
				VerifyIgnorableNodeType(action);
			}
		}

		internal void StrictSkipToNextElement(ExceptionAction action)
		{
			_reader.Skip();
			while (!_reader.EOF && _reader.NodeType != XmlNodeType.Element)
			{
				VerifyIgnorableNodeType(action);
				_reader.Read();
			}
		}

		internal void StrictSkipToOurParentsEndElement(ExceptionAction action)
		{
			int depth = _reader.Depth;
			while (_reader.Depth >= depth)
			{
				_reader.Skip();
			}
			while (!_reader.EOF && _reader.NodeType != XmlNodeType.EndElement)
			{
				VerifyIgnorableNodeType(action);
				_reader.Read();
			}
		}

		internal void VerifyIgnorableNodeType(ExceptionAction action)
		{
			XmlNodeType nodeType = _reader.NodeType;
			if (nodeType != XmlNodeType.Comment && nodeType != XmlNodeType.EndElement)
			{
				ConfigurationException ce = new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_element"), this);
				SchemaErrors.AddError(ce, action);
			}
		}

		internal void VerifyNoUnrecognizedAttributes(ExceptionAction action)
		{
			if (_reader.MoveToNextAttribute())
			{
				AddErrorUnrecognizedAttribute(action);
			}
		}

		internal bool VerifyRequiredAttribute(object o, string attrName, ExceptionAction action)
		{
			if (o == null)
			{
				AddErrorRequiredAttribute(attrName, action);
				return false;
			}
			return true;
		}

		internal void AddErrorUnrecognizedAttribute(ExceptionAction action)
		{
			ConfigurationErrorsException ce = new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_attribute", _reader.Name), this);
			SchemaErrors.AddError(ce, action);
		}

		internal void AddErrorRequiredAttribute(string attrib, ExceptionAction action)
		{
			ConfigurationErrorsException ce = new ConfigurationErrorsException(SR.GetString("Config_missing_required_attribute", attrib, _reader.Name), this);
			SchemaErrors.AddError(ce, action);
		}

		internal void AddErrorReservedAttribute(ExceptionAction action)
		{
			ConfigurationErrorsException ce = new ConfigurationErrorsException(SR.GetString("Config_reserved_attribute", _reader.Name), this);
			SchemaErrors.AddError(ce, action);
		}

		internal void AddErrorUnrecognizedElement(ExceptionAction action)
		{
			ConfigurationErrorsException ce = new ConfigurationErrorsException(SR.GetString("Config_base_unrecognized_element"), this);
			SchemaErrors.AddError(ce, action);
		}

		internal void VerifyAndGetNonEmptyStringAttribute(ExceptionAction action, out string newValue)
		{
			if (!string.IsNullOrEmpty(_reader.Value))
			{
				newValue = _reader.Value;
				return;
			}
			newValue = null;
			ConfigurationException ce = new ConfigurationErrorsException(SR.GetString("Empty_attribute", _reader.Name), this);
			SchemaErrors.AddError(ce, action);
		}

		internal void VerifyAndGetBooleanAttribute(ExceptionAction action, bool defaultValue, out bool newValue)
		{
			if (_reader.Value == "true")
			{
				newValue = true;
				return;
			}
			if (_reader.Value == "false")
			{
				newValue = false;
				return;
			}
			newValue = defaultValue;
			ConfigurationErrorsException ce = new ConfigurationErrorsException(SR.GetString("Config_invalid_boolean_attribute", _reader.Name), this);
			SchemaErrors.AddError(ce, action);
		}

		internal bool CopyOuterXmlToNextElement(XmlUtilWriter utilWriter, bool limitDepth)
		{
			CopyElement(utilWriter);
			return CopyReaderToNextElement(utilWriter, limitDepth);
		}

		internal bool SkipChildElementsAndCopyOuterXmlToNextElement(XmlUtilWriter utilWriter)
		{
			bool isEmptyElement = _reader.IsEmptyElement;
			int lineNumber = _reader.LineNumber;
			CopyXmlNode(utilWriter);
			if (!isEmptyElement)
			{
				while (_reader.NodeType != XmlNodeType.EndElement)
				{
					if (_reader.NodeType == XmlNodeType.Element)
					{
						_reader.Skip();
						if (_reader.NodeType == XmlNodeType.Whitespace)
						{
							_reader.Skip();
						}
					}
					else
					{
						CopyXmlNode(utilWriter);
					}
				}
				if (_reader.LineNumber != lineNumber)
				{
					utilWriter.AppendSpacesToLinePosition(TrueLinePosition);
				}
				CopyXmlNode(utilWriter);
			}
			return CopyReaderToNextElement(utilWriter, limitDepth: true);
		}

		internal bool CopyReaderToNextElement(XmlUtilWriter utilWriter, bool limitDepth)
		{
			bool flag = true;
			int num;
			if (limitDepth)
			{
				if (_reader.NodeType == XmlNodeType.EndElement)
				{
					return true;
				}
				num = _reader.Depth;
			}
			else
			{
				num = 0;
			}
			while (_reader.NodeType != XmlNodeType.Element && _reader.Depth >= num)
			{
				flag = CopyXmlNode(utilWriter);
				if (!flag)
				{
					break;
				}
			}
			return flag;
		}

		internal bool SkipAndCopyReaderToNextElement(XmlUtilWriter utilWriter, bool limitDepth)
		{
			if (!utilWriter.IsLastLineBlank)
			{
				_reader.Skip();
				return CopyReaderToNextElement(utilWriter, limitDepth);
			}
			int num = (limitDepth ? _reader.Depth : 0);
			_reader.Skip();
			int lineNumber = _reader.LineNumber;
			while (!_reader.EOF)
			{
				if (_reader.NodeType != XmlNodeType.Whitespace)
				{
					if (_reader.LineNumber > lineNumber)
					{
						utilWriter.SeekToLineStart();
						utilWriter.AppendWhiteSpace(lineNumber + 1, 1, LineNumber, TrueLinePosition);
					}
					break;
				}
				_reader.Read();
			}
			while (!_reader.EOF && _reader.NodeType != XmlNodeType.Element && _reader.Depth >= num)
			{
				CopyXmlNode(utilWriter);
			}
			return !_reader.EOF;
		}

		private void CopyElement(XmlUtilWriter utilWriter)
		{
			int depth = _reader.Depth;
			bool isEmptyElement = _reader.IsEmptyElement;
			CopyXmlNode(utilWriter);
			while (_reader.Depth > depth)
			{
				CopyXmlNode(utilWriter);
			}
			if (!isEmptyElement)
			{
				CopyXmlNode(utilWriter);
			}
		}

		internal bool CopyXmlNode(XmlUtilWriter utilWriter)
		{
			string text = null;
			int fromLineNumber = -1;
			int fromLinePosition = -1;
			int num = 0;
			int num2 = 0;
			int num3 = 0;
			int num4 = 0;
			if (utilWriter.TrackPosition)
			{
				num = _reader.LineNumber;
				num2 = _reader.LinePosition;
				num3 = utilWriter.LineNumber;
				num4 = utilWriter.LinePosition;
			}
			switch (_reader.NodeType)
			{
			case XmlNodeType.Whitespace:
				utilWriter.Write(_reader.Value);
				break;
			case XmlNodeType.Element:
				text = (_reader.IsEmptyElement ? "/>" : ">");
				fromLineNumber = _reader.LineNumber;
				fromLinePosition = _reader.LinePosition + _reader.Name.Length;
				utilWriter.Write('<');
				utilWriter.Write(_reader.Name);
				while (_reader.MoveToNextAttribute())
				{
					int lineNumber = _reader.LineNumber;
					int linePosition = _reader.LinePosition;
					utilWriter.AppendRequiredWhiteSpace(fromLineNumber, fromLinePosition, lineNumber, linePosition);
					int num6 = utilWriter.Write(_reader.Name);
					num6 += utilWriter.Write('=');
					num6 += utilWriter.AppendAttributeValue(_reader);
					fromLineNumber = lineNumber;
					fromLinePosition = linePosition + num6;
				}
				break;
			case XmlNodeType.EndElement:
				text = ">";
				fromLineNumber = _reader.LineNumber;
				fromLinePosition = _reader.LinePosition + _reader.Name.Length;
				utilWriter.Write("</");
				utilWriter.Write(_reader.Name);
				break;
			case XmlNodeType.Comment:
				utilWriter.AppendComment(_reader.Value);
				break;
			case XmlNodeType.Text:
				utilWriter.AppendEscapeTextString(_reader.Value);
				break;
			case XmlNodeType.XmlDeclaration:
				text = "?>";
				fromLineNumber = _reader.LineNumber;
				fromLinePosition = _reader.LinePosition + 3;
				utilWriter.Write("<?xml");
				while (_reader.MoveToNextAttribute())
				{
					int lineNumber2 = _reader.LineNumber;
					int linePosition2 = _reader.LinePosition;
					utilWriter.AppendRequiredWhiteSpace(fromLineNumber, fromLinePosition, lineNumber2, linePosition2);
					int num7 = utilWriter.Write(_reader.Name);
					num7 += utilWriter.Write('=');
					num7 += utilWriter.AppendAttributeValue(_reader);
					fromLineNumber = lineNumber2;
					fromLinePosition = linePosition2 + num7;
				}
				_reader.MoveToElement();
				break;
			case XmlNodeType.SignificantWhitespace:
				utilWriter.Write(_reader.Value);
				break;
			case XmlNodeType.ProcessingInstruction:
				utilWriter.AppendProcessingInstruction(_reader.Name, _reader.Value);
				break;
			case XmlNodeType.EntityReference:
				utilWriter.AppendEntityRef(_reader.Name);
				break;
			case XmlNodeType.CDATA:
				utilWriter.AppendCData(_reader.Value);
				break;
			case XmlNodeType.DocumentType:
			{
				int num5 = utilWriter.Write("<!DOCTYPE");
				utilWriter.AppendRequiredWhiteSpace(_lastLineNumber, _lastLinePosition + num5, _reader.LineNumber, _reader.LinePosition);
				utilWriter.Write(_reader.Name);
				string text2 = null;
				if (_reader.HasValue)
				{
					text2 = _reader.Value;
				}
				fromLineNumber = _reader.LineNumber;
				fromLinePosition = _reader.LinePosition + _reader.Name.Length;
				if (_reader.MoveToFirstAttribute())
				{
					utilWriter.AppendRequiredWhiteSpace(fromLineNumber, fromLinePosition, _reader.LineNumber, _reader.LinePosition);
					string name = _reader.Name;
					utilWriter.Write(name);
					utilWriter.AppendSpace();
					utilWriter.AppendAttributeValue(_reader);
					_reader.MoveToAttribute(0);
					if (name == "PUBLIC")
					{
						_reader.MoveToAttribute(1);
						utilWriter.AppendSpace();
						utilWriter.AppendAttributeValue(_reader);
						_reader.MoveToAttribute(1);
					}
				}
				if (text2 != null && text2.Length > 0)
				{
					utilWriter.Write(" [");
					utilWriter.Write(text2);
					utilWriter.Write(']');
				}
				utilWriter.Write('>');
				break;
			}
			}
			bool result = _reader.Read();
			XmlNodeType nodeType = _reader.NodeType;
			if (text != null)
			{
				int positionOffset = GetPositionOffset(nodeType);
				int lineNumber3 = _reader.LineNumber;
				int toLinePosition = _reader.LinePosition - positionOffset - text.Length;
				utilWriter.AppendWhiteSpace(fromLineNumber, fromLinePosition, lineNumber3, toLinePosition);
				utilWriter.Write(text);
			}
			if (utilWriter.TrackPosition)
			{
				_lastLineNumber = num - num3 + utilWriter.LineNumber;
				if (num3 == utilWriter.LineNumber)
				{
					_lastLinePosition = num2 - num4 + utilWriter.LinePosition;
				}
				else
				{
					_lastLinePosition = utilWriter.LinePosition;
				}
			}
			return result;
		}

		private string RetrieveFullOpenElementTag()
		{
			StringBuilder stringBuilder = new StringBuilder(64);
			stringBuilder.Append("<");
			stringBuilder.Append(_reader.Name);
			while (_reader.MoveToNextAttribute())
			{
				stringBuilder.Append(" ");
				stringBuilder.Append(_reader.Name);
				stringBuilder.Append("=");
				stringBuilder.Append('"');
				stringBuilder.Append(_reader.Value);
				stringBuilder.Append('"');
			}
			stringBuilder.Append(">");
			return stringBuilder.ToString();
		}

		internal string UpdateStartElement(XmlUtilWriter utilWriter, string updatedStartElement, bool needsChildren, int linePosition, int indent)
		{
			string result = null;
			bool flag = false;
			string name = _reader.Name;
			if (_reader.IsEmptyElement)
			{
				if (updatedStartElement == null && needsChildren)
				{
					updatedStartElement = RetrieveFullOpenElementTag();
				}
				flag = updatedStartElement != null;
			}
			if (updatedStartElement == null)
			{
				CopyXmlNode(utilWriter);
			}
			else
			{
				string text = "</" + name + ">";
				string xmlElement = updatedStartElement + text;
				string text2 = FormatXmlElement(xmlElement, linePosition, indent, skipFirstIndent: true);
				int num = text2.LastIndexOf('\n') + 1;
				string s;
				if (flag)
				{
					result = text2.Substring(num);
					s = text2.Substring(0, num);
				}
				else
				{
					s = text2.Substring(0, num - 2);
				}
				utilWriter.Write(s);
				_reader.Read();
			}
			return result;
		}

		private void ResetCachedStringWriter()
		{
			if (_cachedStringWriter == null)
			{
				_cachedStringWriter = new StringWriter(new StringBuilder(64), CultureInfo.InvariantCulture);
			}
			else
			{
				_cachedStringWriter.GetStringBuilder().Length = 0;
			}
		}

		internal string CopySection()
		{
			ResetCachedStringWriter();
			WhitespaceHandling whitespaceHandling = _reader.WhitespaceHandling;
			_reader.WhitespaceHandling = WhitespaceHandling.All;
			XmlUtilWriter xmlUtilWriter = new XmlUtilWriter(_cachedStringWriter, trackPosition: false);
			CopyElement(xmlUtilWriter);
			_reader.WhitespaceHandling = whitespaceHandling;
			if (whitespaceHandling == WhitespaceHandling.None && Reader.NodeType == XmlNodeType.Whitespace)
			{
				_reader.Read();
			}
			xmlUtilWriter.Flush();
			return ((StringWriter)xmlUtilWriter.Writer).ToString();
		}

		internal static string FormatXmlElement(string xmlElement, int linePosition, int indent, bool skipFirstIndent)
		{
			XmlParserContext context = new XmlParserContext(null, null, null, XmlSpace.Default, Encoding.Unicode);
			XmlTextReader xmlTextReader = new XmlTextReader(xmlElement, XmlNodeType.Element, context);
			StringWriter writer = new StringWriter(new StringBuilder(64), CultureInfo.InvariantCulture);
			XmlUtilWriter xmlUtilWriter = new XmlUtilWriter(writer, trackPosition: false);
			bool flag = false;
			bool flag2 = false;
			int num = 0;
			while (xmlTextReader.Read())
			{
				XmlNodeType nodeType = xmlTextReader.NodeType;
				int num2;
				if (flag2)
				{
					xmlUtilWriter.Flush();
					num2 = num - ((StringWriter)xmlUtilWriter.Writer).GetStringBuilder().Length;
				}
				else
				{
					num2 = 0;
				}
				switch (nodeType)
				{
				case XmlNodeType.Element:
				case XmlNodeType.CDATA:
				case XmlNodeType.Comment:
				case XmlNodeType.EndElement:
					if (!skipFirstIndent && !flag2)
					{
						xmlUtilWriter.AppendIndent(linePosition, indent, xmlTextReader.Depth, flag);
						if (flag)
						{
							xmlUtilWriter.Flush();
							num = ((StringWriter)xmlUtilWriter.Writer).GetStringBuilder().Length;
						}
					}
					break;
				}
				flag2 = false;
				switch (nodeType)
				{
				case XmlNodeType.SignificantWhitespace:
					xmlUtilWriter.Write(xmlTextReader.Value);
					break;
				case XmlNodeType.CDATA:
					xmlUtilWriter.AppendCData(xmlTextReader.Value);
					break;
				case XmlNodeType.ProcessingInstruction:
					xmlUtilWriter.AppendProcessingInstruction(xmlTextReader.Name, xmlTextReader.Value);
					break;
				case XmlNodeType.Comment:
					xmlUtilWriter.AppendComment(xmlTextReader.Value);
					break;
				case XmlNodeType.Text:
					xmlUtilWriter.AppendEscapeTextString(xmlTextReader.Value);
					flag2 = true;
					break;
				case XmlNodeType.Element:
				{
					xmlUtilWriter.Write('<');
					xmlUtilWriter.Write(xmlTextReader.Name);
					num2 += xmlTextReader.Name.Length + 2;
					int attributeCount = xmlTextReader.AttributeCount;
					for (int i = 0; i < attributeCount; i++)
					{
						bool flag3;
						if (num2 > 60)
						{
							xmlUtilWriter.AppendIndent(linePosition, indent, xmlTextReader.Depth - 1, newLine: true);
							num2 = indent;
							flag3 = false;
							xmlUtilWriter.Flush();
							num = ((StringWriter)xmlUtilWriter.Writer).GetStringBuilder().Length;
						}
						else
						{
							flag3 = true;
						}
						xmlTextReader.MoveToNextAttribute();
						xmlUtilWriter.Flush();
						int length = ((StringWriter)xmlUtilWriter.Writer).GetStringBuilder().Length;
						if (flag3)
						{
							xmlUtilWriter.AppendSpace();
						}
						xmlUtilWriter.Write(xmlTextReader.Name);
						xmlUtilWriter.Write('=');
						xmlUtilWriter.AppendAttributeValue(xmlTextReader);
						xmlUtilWriter.Flush();
						num2 += ((StringWriter)xmlUtilWriter.Writer).GetStringBuilder().Length - length;
					}
					xmlTextReader.MoveToElement();
					if (xmlTextReader.IsEmptyElement)
					{
						xmlUtilWriter.Write(" />");
					}
					else
					{
						xmlUtilWriter.Write('>');
					}
					break;
				}
				case XmlNodeType.EndElement:
					xmlUtilWriter.Write("</");
					xmlUtilWriter.Write(xmlTextReader.Name);
					xmlUtilWriter.Write('>');
					break;
				case XmlNodeType.EntityReference:
					xmlUtilWriter.AppendEntityRef(xmlTextReader.Name);
					break;
				}
				flag = true;
				skipFirstIndent = false;
			}
			xmlUtilWriter.Flush();
			return ((StringWriter)xmlUtilWriter.Writer).ToString();
		}
	}
	internal class XmlUtilWriter
	{
		private class StreamWriterCheckpoint
		{
			internal int _lineNumber;

			internal int _linePosition;

			internal bool _isLastLineBlank;

			internal long _streamLength;

			internal long _streamPosition;

			internal StreamWriterCheckpoint(XmlUtilWriter writer)
			{
				writer.Flush();
				_lineNumber = writer._lineNumber;
				_linePosition = writer._linePosition;
				_isLastLineBlank = writer._isLastLineBlank;
				writer._baseStream.Flush();
				_streamPosition = writer._baseStream.Position;
				_streamLength = writer._baseStream.Length;
			}
		}

		private const char SPACE = ' ';

		private const string NL = "\r\n";

		private static string SPACES_8;

		private static string SPACES_4;

		private static string SPACES_2;

		private TextWriter _writer;

		private Stream _baseStream;

		private bool _trackPosition;

		private int _lineNumber;

		private int _linePosition;

		private bool _isLastLineBlank;

		private object _lineStartCheckpoint;

		internal TextWriter Writer => _writer;

		internal bool TrackPosition => _trackPosition;

		internal int LineNumber => _lineNumber;

		internal int LinePosition => _linePosition;

		internal bool IsLastLineBlank => _isLastLineBlank;

		static XmlUtilWriter()
		{
			SPACES_8 = new string(' ', 8);
			SPACES_4 = new string(' ', 4);
			SPACES_2 = new string(' ', 2);
		}

		internal XmlUtilWriter(TextWriter writer, bool trackPosition)
		{
			_writer = writer;
			_trackPosition = trackPosition;
			_lineNumber = 1;
			_linePosition = 1;
			_isLastLineBlank = true;
			if (_trackPosition)
			{
				_baseStream = ((StreamWriter)_writer).BaseStream;
				_lineStartCheckpoint = CreateStreamCheckpoint();
			}
		}

		private void UpdatePosition(char ch)
		{
			switch (ch)
			{
			case '\r':
				_lineNumber++;
				_linePosition = 1;
				_isLastLineBlank = true;
				break;
			case '\n':
				_lineStartCheckpoint = CreateStreamCheckpoint();
				break;
			case '\t':
			case ' ':
				_linePosition++;
				break;
			default:
				_linePosition++;
				_isLastLineBlank = false;
				break;
			}
		}

		internal int Write(string s)
		{
			if (_trackPosition)
			{
				foreach (char c in s)
				{
					_writer.Write(c);
					UpdatePosition(c);
				}
			}
			else
			{
				_writer.Write(s);
			}
			return s.Length;
		}

		internal int Write(char ch)
		{
			_writer.Write(ch);
			if (_trackPosition)
			{
				UpdatePosition(ch);
			}
			return 1;
		}

		internal void Flush()
		{
			_writer.Flush();
		}

		internal int AppendEscapeTextString(string s)
		{
			return AppendEscapeXmlString(s, inAttribute: false, 'A');
		}

		internal int AppendEscapeXmlString(string s, bool inAttribute, char quoteChar)
		{
			int num = 0;
			foreach (char c in s)
			{
				bool flag = false;
				string text = null;
				if ((c < ' ' && c != '\t' && c != '\r' && c != '\n') || c > '\ufffd')
				{
					flag = true;
				}
				else
				{
					switch (c)
					{
					case '<':
						text = "lt";
						break;
					case '>':
						text = "gt";
						break;
					case '&':
						text = "amp";
						break;
					case '\'':
						if (inAttribute && quoteChar == c)
						{
							text = "apos";
						}
						break;
					case '"':
						if (inAttribute && quoteChar == c)
						{
							text = "quot";
						}
						break;
					case '\n':
					case '\r':
						flag = inAttribute;
						break;
					}
				}
				num = ((!flag) ? ((text == null) ? (num + Write(c)) : (num + AppendEntityRef(text))) : (num + AppendCharEntity(c)));
			}
			return num;
		}

		internal int AppendEntityRef(string entityRef)
		{
			Write('&');
			Write(entityRef);
			Write(';');
			return entityRef.Length + 2;
		}

		internal int AppendCharEntity(char ch)
		{
			int num = ch;
			string text = num.ToString("X", CultureInfo.InvariantCulture);
			Write('&');
			Write('#');
			Write('x');
			Write(text);
			Write(';');
			return text.Length + 4;
		}

		internal int AppendCData(string cdata)
		{
			Write("<![CDATA[");
			Write(cdata);
			Write("]]>");
			return cdata.Length + 12;
		}

		internal int AppendProcessingInstruction(string name, string value)
		{
			Write("<?");
			Write(name);
			AppendSpace();
			Write(value);
			Write("?>");
			return name.Length + value.Length + 5;
		}

		internal int AppendComment(string comment)
		{
			Write("<!--");
			Write(comment);
			Write("-->");
			return comment.Length + 7;
		}

		internal int AppendAttributeValue(XmlTextReader reader)
		{
			int num = 0;
			char c = reader.QuoteChar;
			if (c != '"' && c != '\'')
			{
				c = '"';
			}
			num += Write(c);
			while (reader.ReadAttributeValue())
			{
				num = ((reader.NodeType != XmlNodeType.Text) ? (num + AppendEntityRef(reader.Name)) : (num + AppendEscapeXmlString(reader.Value, inAttribute: true, c)));
			}
			return num + Write(c);
		}

		internal int AppendRequiredWhiteSpace(int fromLineNumber, int fromLinePosition, int toLineNumber, int toLinePosition)
		{
			int num = AppendWhiteSpace(fromLineNumber, fromLinePosition, toLineNumber, toLinePosition);
			if (num == 0)
			{
				num += AppendSpace();
			}
			return num;
		}

		internal int AppendWhiteSpace(int fromLineNumber, int fromLinePosition, int toLineNumber, int toLinePosition)
		{
			int num = 0;
			while (fromLineNumber++ < toLineNumber)
			{
				num += AppendNewLine();
				fromLinePosition = 1;
			}
			return num + AppendSpaces(toLinePosition - fromLinePosition);
		}

		internal int AppendIndent(int linePosition, int indent, int depth, bool newLine)
		{
			int num = 0;
			if (newLine)
			{
				num += AppendNewLine();
			}
			int count = linePosition - 1 + indent * depth;
			return num + AppendSpaces(count);
		}

		internal int AppendSpacesToLinePosition(int linePosition)
		{
			if (linePosition <= 0)
			{
				return 0;
			}
			int num = linePosition - _linePosition;
			if (num < 0 && IsLastLineBlank)
			{
				SeekToLineStart();
			}
			return AppendSpaces(linePosition - _linePosition);
		}

		internal int AppendNewLine()
		{
			return Write("\r\n");
		}

		internal int AppendSpaces(int count)
		{
			int num = count;
			while (num > 0)
			{
				if (num >= 8)
				{
					Write(SPACES_8);
					num -= 8;
					continue;
				}
				if (num >= 4)
				{
					Write(SPACES_4);
					num -= 4;
					continue;
				}
				if (num >= 2)
				{
					Write(SPACES_2);
					num -= 2;
					continue;
				}
				Write(' ');
				break;
			}
			if (count <= 0)
			{
				return 0;
			}
			return count;
		}

		internal int AppendSpace()
		{
			return Write(' ');
		}

		internal void SeekToLineStart()
		{
			RestoreStreamCheckpoint(_lineStartCheckpoint);
		}

		internal object CreateStreamCheckpoint()
		{
			return new StreamWriterCheckpoint(this);
		}

		internal void RestoreStreamCheckpoint(object o)
		{
			StreamWriterCheckpoint streamWriterCheckpoint = (StreamWriterCheckpoint)o;
			Flush();
			_lineNumber = streamWriterCheckpoint._lineNumber;
			_linePosition = streamWriterCheckpoint._linePosition;
			_isLastLineBlank = streamWriterCheckpoint._isLastLineBlank;
			_baseStream.Seek(streamWriterCheckpoint._streamPosition, SeekOrigin.Begin);
			_baseStream.SetLength(streamWriterCheckpoint._streamLength);
			_baseStream.Flush();
		}
	}
}
namespace System.Configuration.Internal
{
	public interface IConfigSystem
	{
		IInternalConfigHost Host { get; }

		IInternalConfigRoot Root { get; }

		void Init(Type typeConfigHost, params object[] hostInitParams);
	}
	internal class ConfigSystem : IConfigSystem
	{
		private IInternalConfigRoot _configRoot;

		private IInternalConfigHost _configHost;

		IInternalConfigHost IConfigSystem.Host => _configHost;

		IInternalConfigRoot IConfigSystem.Root => _configRoot;

		void IConfigSystem.Init(Type typeConfigHost, params object[] hostInitParams)
		{
			_configRoot = new InternalConfigRoot();
			_configHost = (IInternalConfigHost)TypeUtil.CreateInstanceWithReflectionPermission(typeConfigHost);
			_configRoot.Init(_configHost, isDesignTime: false);
			_configHost.Init(_configRoot, hostInitParams);
		}
	}
	[ComVisible(false)]
	public interface IConfigurationManagerInternal
	{
		bool SupportsUserConfig { get; }

		bool SetConfigurationSystemInProgress { get; }

		string MachineConfigPath { get; }

		string ApplicationConfigUri { get; }

		string ExeProductName { get; }

		string ExeProductVersion { get; }

		string ExeRoamingConfigDirectory { get; }

		string ExeRoamingConfigPath { get; }

		string ExeLocalConfigDirectory { get; }

		string ExeLocalConfigPath { get; }

		string UserConfigFilename { get; }
	}
	internal sealed class ConfigurationManagerInternal : IConfigurationManagerInternal
	{
		bool IConfigurationManagerInternal.SupportsUserConfig => ConfigurationManager.SupportsUserConfig;

		bool IConfigurationManagerInternal.SetConfigurationSystemInProgress => ConfigurationManager.SetConfigurationSystemInProgress;

		string IConfigurationManagerInternal.MachineConfigPath => ClientConfigurationHost.MachineConfigFilePath;

		string IConfigurationManagerInternal.ApplicationConfigUri => ClientConfigPaths.Current.ApplicationConfigUri;

		string IConfigurationManagerInternal.ExeProductName => ClientConfigPaths.Current.ProductName;

		string IConfigurationManagerInternal.ExeProductVersion => ClientConfigPaths.Current.ProductVersion;

		string IConfigurationManagerInternal.ExeRoamingConfigDirectory => ClientConfigPaths.Current.RoamingConfigDirectory;

		string IConfigurationManagerInternal.ExeRoamingConfigPath => ClientConfigPaths.Current.RoamingConfigFilename;

		string IConfigurationManagerInternal.ExeLocalConfigDirectory => ClientConfigPaths.Current.LocalConfigDirectory;

		string IConfigurationManagerInternal.ExeLocalConfigPath => ClientConfigPaths.Current.LocalConfigFilename;

		string IConfigurationManagerInternal.UserConfigFilename => "user.config";

		private ConfigurationManagerInternal()
		{
		}
	}
	internal class FileVersion
	{
		private bool _exists;

		private long _fileSize;

		private DateTime _utcCreationTime;

		private DateTime _utcLastWriteTime;

		internal FileVersion(bool exists, long fileSize, DateTime utcCreationTime, DateTime utcLastWriteTime)
		{
			_exists = exists;
			_fileSize = fileSize;
			_utcCreationTime = utcCreationTime;
			_utcLastWriteTime = utcLastWriteTime;
		}

		public override bool Equals(object obj)
		{
			if (obj is FileVersion fileVersion && _exists == fileVersion._exists && _fileSize == fileVersion._fileSize && _utcCreationTime == fileVersion._utcCreationTime)
			{
				return _utcLastWriteTime == fileVersion._utcLastWriteTime;
			}
			return false;
		}

		public override int GetHashCode()
		{
			return base.GetHashCode();
		}
	}
	[ComVisible(false)]
	public interface IConfigurationManagerHelper
	{
		void EnsureNetConfigLoaded();
	}
	[ComVisible(false)]
	public interface IInternalConfigConfigurationFactory
	{
		Configuration Create(Type typeConfigHost, params object[] hostInitConfigurationParams);

		string NormalizeLocationSubPath(string subPath, IConfigErrorInfo errorInfo);
	}
	[ComVisible(false)]
	public interface IInternalConfigRoot
	{
		bool IsDesignTime { get; }

		event InternalConfigEventHandler ConfigChanged;

		event InternalConfigEventHandler ConfigRemoved;

		void Init(IInternalConfigHost host, bool isDesignTime);

		object GetSection(string section, string configPath);

		string GetUniqueConfigPath(string configPath);

		IInternalConfigRecord GetUniqueConfigRecord(string configPath);

		IInternalConfigRecord GetConfigRecord(string configPath);

		void RemoveConfig(string configPath);
	}
	[ComVisible(false)]
	public interface IInternalConfigSettingsFactory
	{
		void SetConfigurationSystem(IInternalConfigSystem internalConfigSystem, bool initComplete);

		void CompleteInit();
	}
	internal sealed class InternalConfigConfigurationFactory : IInternalConfigConfigurationFactory
	{
		private InternalConfigConfigurationFactory()
		{
		}

		Configuration IInternalConfigConfigurationFactory.Create(Type typeConfigHost, params object[] hostInitConfigurationParams)
		{
			return new Configuration(null, typeConfigHost, hostInitConfigurationParams);
		}

		string IInternalConfigConfigurationFactory.NormalizeLocationSubPath(string subPath, IConfigErrorInfo errorInfo)
		{
			return BaseConfigurationRecord.NormalizeLocationSubPath(subPath, errorInfo);
		}
	}
	public sealed class InternalConfigEventArgs : EventArgs
	{
		private string _configPath;

		public string ConfigPath
		{
			get
			{
				return _configPath;
			}
			set
			{
				_configPath = value;
			}
		}

		public InternalConfigEventArgs(string configPath)
		{
			_configPath = configPath;
		}
	}
	public delegate void InternalConfigEventHandler(object sender, InternalConfigEventArgs e);
	internal sealed class InternalConfigHost : IInternalConfigHost
	{
		private const FileAttributes InvalidAttributesForWrite = FileAttributes.ReadOnly | FileAttributes.Hidden;

		private IInternalConfigRoot _configRoot;

		bool IInternalConfigHost.SupportsChangeNotifications => false;

		bool IInternalConfigHost.SupportsRefresh => false;

		bool IInternalConfigHost.SupportsPath => false;

		bool IInternalConfigHost.SupportsLocation => false;

		bool IInternalConfigHost.IsRemote => false;

		internal InternalConfigHost()
		{
		}

		void IInternalConfigHost.Init(IInternalConfigRoot configRoot, params object[] hostInitParams)
		{
			_configRoot = configRoot;
		}

		void IInternalConfigHost.InitForConfiguration(ref string locationSubPath, out string configPath, out string locationConfigPath, IInternalConfigRoot configRoot, params object[] hostInitConfigurationParams)
		{
			_configRoot = configRoot;
			configPath = null;
			locationConfigPath = null;
		}

		bool IInternalConfigHost.IsConfigRecordRequired(string configPath)
		{
			return true;
		}

		bool IInternalConfigHost.IsInitDelayed(IInternalConfigRecord configRecord)
		{
			return false;
		}

		void IInternalConfigHost.RequireCompleteInit(IInternalConfigRecord configRecord)
		{
		}

		public bool IsSecondaryRoot(string configPath)
		{
			return false;
		}

		string IInternalConfigHost.GetStreamName(string configPath)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.GetStreamName");
		}

		[FileIOPermission(SecurityAction.Assert, AllFiles = FileIOPermissionAccess.PathDiscovery)]
		internal static string StaticGetStreamNameForConfigSource(string streamName, string configSource)
		{
			if (!Path.IsPathRooted(streamName))
			{
				throw ExceptionUtil.ParameterInvalid("streamName");
			}
			streamName = Path.GetFullPath(streamName);
			string directoryOrRootName = UrlPath.GetDirectoryOrRootName(streamName);
			string path = Path.Combine(directoryOrRootName, configSource);
			path = Path.GetFullPath(path);
			string directoryOrRootName2 = UrlPath.GetDirectoryOrRootName(path);
			if (!UrlPath.IsEqualOrSubdirectory(directoryOrRootName, directoryOrRootName2))
			{
				throw new ArgumentException(SR.GetString("Config_source_not_under_config_dir", configSource));
			}
			return path;
		}

		string IInternalConfigHost.GetStreamNameForConfigSource(string streamName, string configSource)
		{
			return StaticGetStreamNameForConfigSource(streamName, configSource);
		}

		internal static object StaticGetStreamVersion(string streamName)
		{
			bool exists = false;
			long fileSize = 0L;
			DateTime utcCreationTime = DateTime.MinValue;
			DateTime utcLastWriteTime = DateTime.MinValue;
			if (Microsoft.Win32.UnsafeNativeMethods.GetFileAttributesEx(streamName, 0, out var data) && (data.fileAttributes & 0x10) == 0)
			{
				exists = true;
				fileSize = (long)(((ulong)data.fileSizeHigh << 32) | data.fileSizeLow);
				utcCreationTime = DateTime.FromFileTimeUtc((long)(((ulong)data.ftCreationTimeHigh << 32) | data.ftCreationTimeLow));
				utcLastWriteTime = DateTime.FromFileTimeUtc((long)(((ulong)data.ftLastWriteTimeHigh << 32) | data.ftLastWriteTimeLow));
			}
			return new FileVersion(exists, fileSize, utcCreationTime, utcLastWriteTime);
		}

		object IInternalConfigHost.GetStreamVersion(string streamName)
		{
			return StaticGetStreamVersion(streamName);
		}

		internal static Stream StaticOpenStreamForRead(string streamName)
		{
			if (string.IsNullOrEmpty(streamName))
			{
				throw ExceptionUtil.UnexpectedError("InternalConfigHost::StaticOpenStreamForRead");
			}
			if (!FileUtil.FileExists(streamName, trueOnError: true))
			{
				return null;
			}
			return new FileStream(streamName, FileMode.Open, FileAccess.Read, FileShare.Read);
		}

		Stream IInternalConfigHost.OpenStreamForRead(string streamName)
		{
			return ((IInternalConfigHost)this).OpenStreamForRead(streamName, assertPermissions: false);
		}

		Stream IInternalConfigHost.OpenStreamForRead(string streamName, bool assertPermissions)
		{
			Stream stream = null;
			bool flag = false;
			if (assertPermissions || !_configRoot.IsDesignTime)
			{
				new FileIOPermission(FileIOPermissionAccess.Read | FileIOPermissionAccess.PathDiscovery, streamName).Assert();
				flag = true;
			}
			try
			{
				return StaticOpenStreamForRead(streamName);
			}
			finally
			{
				if (flag)
				{
					CodeAccessPermission.RevertAssert();
				}
			}
		}

		internal static Stream StaticOpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext, bool assertPermissions)
		{
			bool flag = false;
			if (string.IsNullOrEmpty(streamName))
			{
				throw new ConfigurationException(SR.GetString("Config_no_stream_to_write"));
			}
			string directoryName = Path.GetDirectoryName(streamName);
			try
			{
				if (!Directory.Exists(directoryName))
				{
					if (assertPermissions)
					{
						new FileIOPermission(PermissionState.Unrestricted).Assert();
						flag = true;
					}
					Directory.CreateDirectory(directoryName);
				}
			}
			catch
			{
			}
			finally
			{
				if (flag)
				{
					CodeAccessPermission.RevertAssert();
				}
			}
			WriteFileContext writeFileContext = null;
			flag = false;
			if (assertPermissions)
			{
				new FileIOPermission(FileIOPermissionAccess.AllAccess, directoryName).Assert();
				flag = true;
			}
			Stream result;
			try
			{
				writeFileContext = new WriteFileContext(streamName, templateStreamName);
				if (File.Exists(streamName))
				{
					FileInfo fileInfo = new FileInfo(streamName);
					FileAttributes attributes = fileInfo.Attributes;
					if ((attributes & (FileAttributes.ReadOnly | FileAttributes.Hidden)) != 0)
					{
						throw new IOException(SR.GetString("Config_invalid_attributes_for_write", streamName));
					}
				}
				try
				{
					result = new FileStream(writeFileContext.TempNewFilename, FileMode.Create, FileAccess.Write, FileShare.Read);
				}
				catch (Exception inner)
				{
					throw new ConfigurationException(SR.GetString("Config_write_failed", streamName), inner);
				}
				catch
				{
					throw new ConfigurationException(SR.GetString("Config_write_failed", streamName));
				}
			}
			catch
			{
				writeFileContext?.Complete(streamName, success: false);
				throw;
			}
			finally
			{
				if (flag)
				{
					CodeAccessPermission.RevertAssert();
				}
			}
			writeContext = writeFileContext;
			return result;
		}

		Stream IInternalConfigHost.OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext)
		{
			return ((IInternalConfigHost)this).OpenStreamForWrite(streamName, templateStreamName, ref writeContext, assertPermissions: false);
		}

		Stream IInternalConfigHost.OpenStreamForWrite(string streamName, string templateStreamName, ref object writeContext, bool assertPermissions)
		{
			return StaticOpenStreamForWrite(streamName, templateStreamName, ref writeContext, assertPermissions);
		}

		internal static void StaticWriteCompleted(string streamName, bool success, object writeContext, bool assertPermissions)
		{
			WriteFileContext writeFileContext = (WriteFileContext)writeContext;
			bool flag = false;
			if (assertPermissions)
			{
				string directoryName = Path.GetDirectoryName(streamName);
				string[] pathList = new string[3] { streamName, writeFileContext.TempNewFilename, directoryName };
				FileIOPermission fileIOPermission = new FileIOPermission(FileIOPermissionAccess.AllAccess, AccessControlActions.View | AccessControlActions.Change, pathList);
				fileIOPermission.Assert();
				flag = true;
			}
			try
			{
				writeFileContext.Complete(streamName, success);
			}
			finally
			{
				if (flag)
				{
					CodeAccessPermission.RevertAssert();
				}
			}
		}

		void IInternalConfigHost.WriteCompleted(string streamName, bool success, object writeContext)
		{
			((IInternalConfigHost)this).WriteCompleted(streamName, success, writeContext, assertPermissions: false);
		}

		void IInternalConfigHost.WriteCompleted(string streamName, bool success, object writeContext, bool assertPermissions)
		{
			StaticWriteCompleted(streamName, success, writeContext, assertPermissions);
		}

		internal static void StaticDeleteStream(string streamName)
		{
			File.Delete(streamName);
		}

		void IInternalConfigHost.DeleteStream(string streamName)
		{
			StaticDeleteStream(streamName);
		}

		internal static bool StaticIsFile(string streamName)
		{
			return Path.IsPathRooted(streamName);
		}

		bool IInternalConfigHost.IsFile(string streamName)
		{
			return StaticIsFile(streamName);
		}

		object IInternalConfigHost.StartMonitoringStreamForChanges(string streamName, StreamChangeCallback callback)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.StartMonitoringStreamForChanges");
		}

		void IInternalConfigHost.StopMonitoringStreamForChanges(string streamName, StreamChangeCallback callback)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.StopMonitoringStreamForChanges");
		}

		bool IInternalConfigHost.IsDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition)
		{
			return true;
		}

		void IInternalConfigHost.VerifyDefinitionAllowed(string configPath, ConfigurationAllowDefinition allowDefinition, ConfigurationAllowExeDefinition allowExeDefinition, IConfigErrorInfo errorInfo)
		{
		}

		bool IInternalConfigHost.IsAboveApplication(string configPath)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.IsAboveApplication");
		}

		string IInternalConfigHost.GetConfigPathFromLocationSubPath(string configPath, string locationSubPath)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.GetConfigPathFromLocationSubPath");
		}

		bool IInternalConfigHost.IsLocationApplicable(string configPath)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.IsLocationApplicable");
		}

		bool IInternalConfigHost.IsTrustedConfigPath(string configPath)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.IsTrustedConfigPath");
		}

		bool IInternalConfigHost.IsFullTrustSectionWithoutAptcaAllowed(IInternalConfigRecord configRecord)
		{
			return TypeUtil.IsCallerFullTrust;
		}

		void IInternalConfigHost.GetRestrictedPermissions(IInternalConfigRecord configRecord, out PermissionSet permissionSet, out bool isHostReady)
		{
			permissionSet = null;
			isHostReady = true;
		}

		IDisposable IInternalConfigHost.Impersonate()
		{
			return null;
		}

		bool IInternalConfigHost.PrefetchAll(string configPath, string streamName)
		{
			return false;
		}

		bool IInternalConfigHost.PrefetchSection(string sectionGroupName, string sectionName)
		{
			return false;
		}

		object IInternalConfigHost.CreateDeprecatedConfigContext(string configPath)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.CreateDeprecatedConfigContext");
		}

		object IInternalConfigHost.CreateConfigurationContext(string configPath, string locationSubPath)
		{
			throw ExceptionUtil.UnexpectedError("IInternalConfigHost.CreateConfigurationContext");
		}

		string IInternalConfigHost.DecryptSection(string encryptedXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfigSection)
		{
			return ProtectedConfigurationSection.DecryptSection(encryptedXml, protectionProvider);
		}

		string IInternalConfigHost.EncryptSection(string clearTextXml, ProtectedConfigurationProvider protectionProvider, ProtectedConfigurationSection protectedConfigSection)
		{
			return ProtectedConfigurationSection.EncryptSection(clearTextXml, protectionProvider);
		}

		Type IInternalConfigHost.GetConfigType(string typeName, bool throwOnError)
		{
			return Type.GetType(typeName, throwOnError);
		}

		string IInternalConfigHost.GetConfigTypeName(Type t)
		{
			return t.AssemblyQualifiedName;
		}
	}
	internal sealed class InternalConfigRoot : IInternalConfigRoot
	{
		private IInternalConfigHost _host;

		private ReaderWriterLock _hierarchyLock;

		private BaseConfigurationRecord _rootConfigRecord;

		private bool _isDesignTime;

		internal IInternalConfigHost Host => _host;

		internal BaseConfigurationRecord RootConfigRecord => _rootConfigRecord;

		bool IInternalConfigRoot.IsDesignTime => _isDesignTime;

		public event InternalConfigEventHandler ConfigChanged;

		public event InternalConfigEventHandler ConfigRemoved;

		internal InternalConfigRoot()
		{
		}

		void IInternalConfigRoot.Init(IInternalConfigHost host, bool isDesignTime)
		{
			_host = host;
			_isDesignTime = isDesignTime;
			_hierarchyLock = new ReaderWriterLock();
			if (_isDesignTime)
			{
				_rootConfigRecord = MgmtConfigurationRecord.Create(this, null, string.Empty, null);
			}
			else
			{
				_rootConfigRecord = (BaseConfigurationRecord)RuntimeConfigurationRecord.Create(this, null, string.Empty);
			}
		}

		private void AcquireHierarchyLockForRead()
		{
			if (_hierarchyLock.IsReaderLockHeld)
			{
				throw ExceptionUtil.UnexpectedError("System.Configuration.Internal.InternalConfigRoot::AcquireHierarchyLockForRead - reader lock already held by this thread");
			}
			if (_hierarchyLock.IsWriterLockHeld)
			{
				throw ExceptionUtil.UnexpectedError("System.Configuration.Internal.InternalConfigRoot::AcquireHierarchyLockForRead - writer lock already held by this thread");
			}
			_hierarchyLock.AcquireReaderLock(-1);
		}

		private void ReleaseHierarchyLockForRead()
		{
			if (_hierarchyLock.IsReaderLockHeld)
			{
				_hierarchyLock.ReleaseReaderLock();
			}
		}

		private void AcquireHierarchyLockForWrite()
		{
			if (_hierarchyLock.IsReaderLockHeld)
			{
				throw ExceptionUtil.UnexpectedError("System.Configuration.Internal.InternalConfigRoot::AcquireHierarchyLockForWrite - reader lock already held by this thread");
			}
			if (_hierarchyLock.IsWriterLockHeld)
			{
				throw ExceptionUtil.UnexpectedError("System.Configuration.Internal.InternalConfigRoot::AcquireHierarchyLockForWrite - writer lock already held by this thread");
			}
			_hierarchyLock.AcquireWriterLock(-1);
		}

		private void ReleaseHierarchyLockForWrite()
		{
			if (_hierarchyLock.IsWriterLockHeld)
			{
				_hierarchyLock.ReleaseWriterLock();
			}
		}

		private void hlFindConfigRecord(string[] parts, out int nextIndex, out BaseConfigurationRecord currentRecord)
		{
			currentRecord = _rootConfigRecord;
			for (nextIndex = 0; nextIndex < parts.Length; nextIndex++)
			{
				BaseConfigurationRecord baseConfigurationRecord = currentRecord.hlGetChild(parts[nextIndex]);
				if (baseConfigurationRecord == null)
				{
					break;
				}
				currentRecord = baseConfigurationRecord;
			}
		}

		public object GetSection(string section, string configPath)
		{
			BaseConfigurationRecord baseConfigurationRecord = (BaseConfigurationRecord)GetUniqueConfigRecord(configPath);
			return baseConfigurationRecord.GetSection(section);
		}

		public string GetUniqueConfigPath(string configPath)
		{
			return GetUniqueConfigRecord(configPath)?.ConfigPath;
		}

		public IInternalConfigRecord GetUniqueConfigRecord(string configPath)
		{
			BaseConfigurationRecord baseConfigurationRecord = (BaseConfigurationRecord)GetConfigRecord(configPath);
			while (baseConfigurationRecord.IsEmpty)
			{
				BaseConfigurationRecord parent = baseConfigurationRecord.Parent;
				if (parent.IsRootConfig)
				{
					break;
				}
				baseConfigurationRecord = parent;
			}
			return baseConfigurationRecord;
		}

		public IInternalConfigRecord GetConfigRecord(string configPath)
		{
			if (!ConfigPathUtility.IsValid(configPath))
			{
				throw ExceptionUtil.ParameterInvalid("configPath");
			}
			string[] parts = ConfigPathUtility.GetParts(configPath);
			try
			{
				AcquireHierarchyLockForRead();
				hlFindConfigRecord(parts, out var nextIndex, out var currentRecord);
				if (nextIndex == parts.Length || !currentRecord.hlNeedsChildFor(parts[nextIndex]))
				{
					return currentRecord;
				}
			}
			finally
			{
				ReleaseHierarchyLockForRead();
			}
			try
			{
				AcquireHierarchyLockForWrite();
				hlFindConfigRecord(parts, out var nextIndex2, out var currentRecord2);
				if (nextIndex2 == parts.Length)
				{
					return currentRecord2;
				}
				string text = string.Join("/", parts, 0, nextIndex2);
				while (nextIndex2 < parts.Length && currentRecord2.hlNeedsChildFor(parts[nextIndex2]))
				{
					string text2 = parts[nextIndex2];
					text = ConfigPathUtility.Combine(text, text2);
					BaseConfigurationRecord baseConfigurationRecord = ((!_isDesignTime) ? ((BaseConfigurationRecord)RuntimeConfigurationRecord.Create(this, currentRecord2, text)) : MgmtConfigurationRecord.Create(this, currentRecord2, text, null));
					currentRecord2.hlAddChild(text2, baseConfigurationRecord);
					nextIndex2++;
					currentRecord2 = baseConfigurationRecord;
				}
				return currentRecord2;
			}
			finally
			{
				ReleaseHierarchyLockForWrite();
			}
		}

		private void RemoveConfigImpl(string configPath, BaseConfigurationRecord configRecord)
		{
			if (!ConfigPathUtility.IsValid(configPath))
			{
				throw ExceptionUtil.ParameterInvalid("configPath");
			}
			string[] parts = ConfigPathUtility.GetParts(configPath);
			BaseConfigurationRecord currentRecord;
			try
			{
				AcquireHierarchyLockForWrite();
				hlFindConfigRecord(parts, out var nextIndex, out currentRecord);
				if (nextIndex != parts.Length || (configRecord != null && !object.ReferenceEquals(configRecord, currentRecord)))
				{
					return;
				}
				currentRecord.Parent.hlRemoveChild(parts[parts.Length - 1]);
			}
			finally
			{
				ReleaseHierarchyLockForWrite();
			}
			OnConfigRemoved(new InternalConfigEventArgs(configPath));
			currentRecord.CloseRecursive();
		}

		public void RemoveConfig(string configPath)
		{
			RemoveConfigImpl(configPath, null);
		}

		public void RemoveConfigRecord(BaseConfigurationRecord configRecord)
		{
			RemoveConfigImpl(configRecord.ConfigPath, configRecord);
		}

		public void ClearResult(BaseConfigurationRecord configRecord, string configKey, bool forceEvaluation)
		{
			string[] parts = ConfigPathUtility.GetParts(configRecord.ConfigPath);
			try
			{
				AcquireHierarchyLockForRead();
				hlFindConfigRecord(parts, out var nextIndex, out var currentRecord);
				if (nextIndex == parts.Length && object.ReferenceEquals(configRecord, currentRecord))
				{
					currentRecord.hlClearResultRecursive(configKey, forceEvaluation);
				}
			}
			finally
			{
				ReleaseHierarchyLockForRead();
			}
		}

		private void OnConfigRemoved(InternalConfigEventArgs e)
		{
			this.ConfigRemoved?.Invoke(this, e);
		}

		internal void FireConfigChanged(string configPath)
		{
			OnConfigChanged(new InternalConfigEventArgs(configPath));
		}

		private void OnConfigChanged(InternalConfigEventArgs e)
		{
			this.ConfigChanged?.Invoke(this, e);
		}
	}
	internal sealed class InternalConfigSettingsFactory : IInternalConfigSettingsFactory
	{
		private InternalConfigSettingsFactory()
		{
		}

		void IInternalConfigSettingsFactory.SetConfigurationSystem(IInternalConfigSystem configSystem, bool initComplete)
		{
			ConfigurationManager.SetConfigurationSystem(configSystem, initComplete);
		}

		void IInternalConfigSettingsFactory.CompleteInit()
		{
			ConfigurationManager.CompleteConfigInit();
		}
	}
	public delegate void StreamChangeCallback(string streamName);
	internal class WriteFileContext
	{
		private const int SAVING_TIMEOUT = 10000;

		private const int SAVING_RETRY_INTERVAL = 100;

		private static bool _osPlatformDetermined;

		private static PlatformID _osPlatform;

		private TempFileCollection _tempFiles;

		private string _tempNewFilename;

		private string _templateFilename;

		internal string TempNewFilename => _tempNewFilename;

		private bool IsWinNT
		{
			get
			{
				if (!_osPlatformDetermined)
				{
					_osPlatform = Environment.OSVersion.Platform;
					_osPlatformDetermined = true;
				}
				return _osPlatform == PlatformID.Win32NT;
			}
		}

		internal WriteFileContext(string filename, string templateFilename)
		{
			string directoryOrRootName = UrlPath.GetDirectoryOrRootName(filename);
			_templateFilename = templateFilename;
			_tempFiles = new TempFileCollection(directoryOrRootName);
			try
			{
				_tempNewFilename = _tempFiles.AddExtension("newcfg");
			}
			catch
			{
				((IDisposable)_tempFiles).Dispose();
				_tempFiles = null;
				throw;
			}
		}

		static WriteFileContext()
		{
			_osPlatformDetermined = false;
		}

		internal void Complete(string filename, bool success)
		{
			try
			{
				if (success)
				{
					if (File.Exists(filename))
					{
						ValidateWriteAccess(filename);
						DuplicateFileAttributes(filename, _tempNewFilename);
					}
					else if (_templateFilename != null)
					{
						DuplicateTemplateAttributes(_templateFilename, _tempNewFilename);
					}
					ReplaceFile(_tempNewFilename, filename);
					_tempFiles.KeepFiles = true;
				}
			}
			finally
			{
				((IDisposable)_tempFiles).Dispose();
				_tempFiles = null;
			}
		}

		private void DuplicateFileAttributes(string source, string destination)
		{
			FileAttributes attributes = File.GetAttributes(source);
			File.SetAttributes(destination, attributes);
			DateTime creationTimeUtc = File.GetCreationTimeUtc(source);
			File.SetCreationTimeUtc(destination, creationTimeUtc);
			DuplicateTemplateAttributes(source, destination);
		}

		private void DuplicateTemplateAttributes(string source, string destination)
		{
			if (IsWinNT)
			{
				FileSecurity accessControl = File.GetAccessControl(source, AccessControlSections.Access);
				accessControl.SetAccessRuleProtection(accessControl.AreAccessRulesProtected, preserveInheritance: true);
				File.SetAccessControl(destination, accessControl);
			}
			else
			{
				FileAttributes attributes = File.GetAttributes(source);
				File.SetAttributes(destination, attributes);
			}
		}

		private void ValidateWriteAccess(string filename)
		{
			FileStream fileStream = null;
			try
			{
				fileStream = new FileStream(filename, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
			}
			catch (UnauthorizedAccessException)
			{
				throw;
			}
			catch (IOException)
			{
			}
			catch (Exception)
			{
				throw;
			}
			finally
			{
				fileStream?.Close();
			}
		}

		private void ReplaceFile(string Source, string Target)
		{
			bool flag = false;
			int num = 0;
			flag = AttemptMove(Source, Target);
			while (!flag && num < 10000 && File.Exists(Target) && !FileIsWriteLocked(Target))
			{
				Thread.Sleep(100);
				num += 100;
				flag = AttemptMove(Source, Target);
			}
			if (!flag)
			{
				throw new ConfigurationErrorsException(SR.GetString("Config_write_failed", Target));
			}
		}

		private bool AttemptMove(string Source, string Target)
		{
			bool flag = false;
			if (IsWinNT)
			{
				return Microsoft.Win32.UnsafeNativeMethods.MoveFileEx(Source, Target, 1);
			}
			try
			{
				File.Copy(Source, Target, overwrite: true);
				return true;
			}
			catch
			{
				return false;
			}
		}

		private bool FileIsWriteLocked(string FileName)
		{
			Stream stream = null;
			bool flag = true;
			if (!FileUtil.FileExists(FileName, trueOnError: true))
			{
				return false;
			}
			try
			{
				FileShare fileShare = FileShare.Read;
				if (IsWinNT)
				{
					fileShare |= FileShare.Delete;
				}
				stream = new FileStream(FileName, FileMode.Open, FileAccess.Read, fileShare);
				return false;
			}
			finally
			{
				if (stream != null)
				{
					stream.Close();
					stream = null;
				}
			}
		}
	}
}
namespace Microsoft.Win32
{
	[SuppressUnmanagedCodeSecurity]
	internal sealed class SafeCryptContextHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
		internal SafeCryptContextHandle()
			: base(ownsHandle: true)
		{
		}

		[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
		internal SafeCryptContextHandle(IntPtr handle, bool ownsHandle)
			: base(ownsHandle)
		{
			SetHandle(handle);
		}

		protected override bool ReleaseHandle()
		{
			if (handle != IntPtr.Zero)
			{
				UnsafeNativeMethods.CryptReleaseContext(this, 0u);
				return true;
			}
			return false;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal sealed class SafeNativeMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private bool _useLocalFree;

		[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
		internal SafeNativeMemoryHandle()
			: this(useLocalFree: false)
		{
		}

		internal SafeNativeMemoryHandle(bool useLocalFree)
			: base(ownsHandle: true)
		{
			_useLocalFree = useLocalFree;
		}

		[SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
		internal SafeNativeMemoryHandle(IntPtr handle, bool ownsHandle)
			: base(ownsHandle)
		{
			SetHandle(handle);
		}

		internal void SetDataHandle(IntPtr handle)
		{
			SetHandle(handle);
		}

		protected override bool ReleaseHandle()
		{
			if (handle != IntPtr.Zero)
			{
				if (_useLocalFree)
				{
					UnsafeNativeMethods.LocalFree(handle);
				}
				else
				{
					Marshal.FreeHGlobal(handle);
				}
				handle = IntPtr.Zero;
				return true;
			}
			return false;
		}
	}
	[SuppressUnmanagedCodeSecurity]
	internal static class SafeNativeMethods
	{
	}
	[SuppressUnmanagedCodeSecurity]
	internal static class UnsafeNativeMethods
	{
		internal struct WIN32_FILE_ATTRIBUTE_DATA
		{
			internal int fileAttributes;

			internal uint ftCreationTimeLow;

			internal uint ftCreationTimeHigh;

			internal uint ftLastAccessTimeLow;

			internal uint ftLastAccessTimeHigh;

			internal uint ftLastWriteTimeLow;

			internal uint ftLastWriteTimeHigh;

			internal uint fileSizeHigh;

			internal uint fileSizeLow;
		}

		internal const int GetFileExInfoStandard = 0;

		internal const int MOVEFILE_REPLACE_EXISTING = 1;

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool GetFileAttributesEx(string name, int fileInfoLevel, out WIN32_FILE_ATTRIBUTE_DATA data);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto)]
		internal static extern int GetModuleFileName(HandleRef hModule, StringBuilder buffer, int length);

		[DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool CryptProtectData(ref DATA_BLOB inputData, string description, ref DATA_BLOB entropy, IntPtr pReserved, ref CRYPTPROTECT_PROMPTSTRUCT promptStruct, uint flags, ref DATA_BLOB outputData);

		[DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool CryptUnprotectData(ref DATA_BLOB inputData, ref string description, ref DATA_BLOB entropy, IntPtr pReserved, ref CRYPTPROTECT_PROMPTSTRUCT promptStruct, uint flags, ref DATA_BLOB outputData);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern int CryptAcquireContext(out SafeCryptContextHandle phProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern int CryptReleaseContext(SafeCryptContextHandle hProv, uint dwFlags);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		internal static extern IntPtr LocalFree(IntPtr buf);

		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto)]
		internal static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
	}
}
