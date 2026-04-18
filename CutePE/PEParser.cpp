#include "PEParser.h"

PEParser::PEParser()
{
	this->pe_dos_header = nullptr;
	this->pe_nt_headers = nullptr;
	this->raw_pe_data = nullptr;
	this->pe_section_headers = nullptr;
	this->pe_imports = nullptr;
}

ResultCode PEParser::from_bytes(char* bytes)
{
	this->raw_pe_data = bytes;
	return this->parse();
}

ResultCode PEParser::from_disk(char* path)
{
	OFSTRUCT pe_file_stat{};
	pe_file_stat.cBytes = sizeof(pe_file_stat);

	HFILE pe_file_h = OpenFile(
		path,
		&pe_file_stat,
		OF_READ
	);
	if (pe_file_h == HFILE_ERROR)
		return ResultCode::READFILE_ERROR;

	LARGE_INTEGER pe_file_size;
	BOOL file_size_res = GetFileSizeEx(
		(HANDLE)pe_file_h,
		&pe_file_size
	);
	if (file_size_res == 0)
		return ResultCode::READFILE_ERROR;
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
		return ResultCode::READFILE_ERROR;

	this->raw_pe_data = pe_file_buffer;

	return this->parse();
}

ResultCode PEParser::parse()
{
	this->pe_dos_header = (IMAGE_DOS_HEADER*)this->raw_pe_data;
	if (this->pe_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return ResultCode::INVALID_DOS_HEADER;

	this->pe_nt_headers = (IMAGE_NT_HEADERS*)(PCHAR(this->pe_dos_header) + this->pe_dos_header->e_lfanew);
	if (this->pe_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return ResultCode::INVALID_NT_HEADER;

	this->pe_section_headers = IMAGE_FIRST_SECTION(this->pe_nt_headers);

	return ResultCode::SUCCESS;
}