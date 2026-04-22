#include "PEParser.h"

PEParser::PEParser()
{
	this->pe_dos_header = nullptr;
	this->pe_nt_headers = nullptr;
	this->raw_pe_data = nullptr;
	this->pe_section_headers = nullptr;
	this->pe_imports = {};
	this->is_64bit = false;
}

DWORD PEParser::from_bytes(char* bytes)
{
	this->raw_pe_data = bytes;
	return this->parse();
}

DWORD PEParser::from_disk(char* path)
{
	OFSTRUCT pe_file_stat{};
	pe_file_stat.cBytes = sizeof(pe_file_stat);

	HFILE pe_file_h = OpenFile(
		path,
		&pe_file_stat,
		OF_READ
	);
	if (pe_file_h == HFILE_ERROR)
		return PE_FILE_OPEN_ERROR;

	LARGE_INTEGER pe_file_size;
	BOOL file_size_res = GetFileSizeEx(
		(HANDLE)pe_file_h,
		&pe_file_size
	);
	if (file_size_res == 0)
		return PE_FILE_SIZE_GET_ERROR;
	DWORD64 pe_file_size_quadpart = pe_file_size.QuadPart;

	char* pe_file_buffer = new char[pe_file_size_quadpart];
	DWORD pe_file_size_read = 0;
	BOOL pe_file_read = ReadFile(
		(HANDLE)pe_file_h,
		pe_file_buffer,
		pe_file_size_quadpart,
		&pe_file_size_read,
		NULL
	);
	if (pe_file_read == NULL)
		return PE_FILE_READ_ERROR;

	this->raw_pe_data = pe_file_buffer;

	return this->parse();
}

PIMAGE_DATA_DIRECTORY PEParser::get_data_directory(DWORD type)
{
	if (this->is_64bit)
	{
		IMAGE_NT_HEADERS64* nt64_h = (IMAGE_NT_HEADERS64*)this->pe_nt_headers;
		return &nt64_h->OptionalHeader.DataDirectory[type];
	}
	else
	{
		IMAGE_NT_HEADERS32* nt32_h = (IMAGE_NT_HEADERS32*)this->pe_nt_headers;
		return &nt32_h->OptionalHeader.DataDirectory[type];
	}
}

DWORD PEParser::rva_to_offset(DWORD rva) {
	PIMAGE_SECTION_HEADER section = this->pe_section_headers;
	WORD num_sections = this->pe_nt_headers->FileHeader.NumberOfSections;

	for (WORD i = 0; i < num_sections; i++) {
		if (rva >= section[i].VirtualAddress && rva < (section[i].VirtualAddress + section[i].Misc.VirtualSize)) {

			return (rva - section[i].VirtualAddress) + section[i].PointerToRawData;
		}
	}

	return 0;
}

DWORD PEParser::get_thunk_data_addr(char* thunk_ptr, int index)
{
	if (this->is_64bit) {
		PIMAGE_THUNK_DATA64 t64 = &((PIMAGE_THUNK_DATA64)thunk_ptr)[index];
		return t64->u1.AddressOfData;
	}
	else {
		PIMAGE_THUNK_DATA32 t32 = &((PIMAGE_THUNK_DATA32)thunk_ptr)[index];
		return t32->u1.AddressOfData;
	}
}

ImportedFunction PEParser::resolve_thunk_function(ULONGLONG func_ptr)
{
	ImportedFunction library{};
	ULONGLONG ordinal_flag = this->is_64bit ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;

	if (func_ptr & ordinal_flag) {
		library.name = std::to_string(func_ptr & 0xFFFF);
		library.is_ordinal = true;
	}
	else {
		DWORD name_offset = this->rva_to_offset((DWORD)func_ptr);
		PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(this->raw_pe_data + name_offset);

		library.name = std::string((char*)pName->Name);
		library.hint = pName->Hint;
		library.address = (uintptr_t)func_ptr;
		library.is_ordinal = false;
	}

	return library;
}

DWORD PEParser::parse_import_entries()
{
	PIMAGE_DATA_DIRECTORY import_directory = this->get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (!import_directory->VirtualAddress) return PE_FILE_SUCCESS;

	DWORD import_directory_offset = this->rva_to_offset(import_directory->VirtualAddress);
	IMAGE_IMPORT_DESCRIPTOR* import_entries = (IMAGE_IMPORT_DESCRIPTOR*)(this->raw_pe_data + import_directory_offset);

	for (int i = 0; import_entries[i].Name != 0; i++) {
		ImportedLibrary new_library{};
		new_library.dll_name = std::string(this->raw_pe_data + this->rva_to_offset(import_entries[i].Name));

		DWORD thunk_rva = import_entries[i].OriginalFirstThunk ? import_entries[i].OriginalFirstThunk : import_entries[i].FirstThunk;
		char* thunk_ptr = (this->raw_pe_data + this->rva_to_offset(thunk_rva));

		for (size_t j = 0; ; j++) {
			ULONGLONG raw_thunk_value = 0;
			raw_thunk_value = this->get_thunk_data_addr(thunk_ptr, j);
			if (raw_thunk_value == 0x0) break;

			ImportedFunction new_func = this->resolve_thunk_function(raw_thunk_value);
			new_library.functions.push_back(new_func);
		}
		this->pe_imports.push_back(new_library);
	}
	
	return PE_FILE_SUCCESS;
}

DWORD PEParser::parse_resource_entries()
{
	PIMAGE_DATA_DIRECTORY data_directory = this->get_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (!data_directory->VirtualAddress) return PE_FILE_SUCCESS;

	DWORD resource_directory_offset = this->rva_to_offset(data_directory->VirtualAddress);
	PIMAGE_RESOURCE_DIRECTORY resource_directory = (PIMAGE_RESOURCE_DIRECTORY)(this->raw_pe_data + resource_directory_offset);

	return PE_FILE_SUCCESS;
}

DWORD PEParser::parse()
{
	this->pe_dos_header = (IMAGE_DOS_HEADER*)this->raw_pe_data;
	if (this->pe_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return PE_FILE_INVALID_DOS_HEADER;

	this->pe_nt_headers = (IMAGE_NT_HEADERS*)(PCHAR(this->pe_dos_header) + this->pe_dos_header->e_lfanew);
	if (this->pe_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return PE_FILE_INVALID_NT_HEADER;

	this->is_64bit = this->pe_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	this->pe_section_headers = IMAGE_FIRST_SECTION(this->pe_nt_headers);
	this->parse_import_entries();
	this->parse_resource_entries();


	return PE_FILE_SUCCESS;
}