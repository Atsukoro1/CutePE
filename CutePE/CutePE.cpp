#include <iostream>
#include <phnt_windows.h>
#include <phnt.h>

const char* EXE_PATH = "C:\\Users\\Jakub\\Desktop\\poopstub.exe";

int main()
{
    OFSTRUCT pe_file_stat{};
    pe_file_stat.cBytes = sizeof(pe_file_stat);

    HFILE pe_file_h = OpenFile(
        EXE_PATH,
        &pe_file_stat,
        OF_READ
    );
    
    if (pe_file_h == HFILE_ERROR)
    {
        std::cerr << "Failed to read the PE file, code: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }

    LARGE_INTEGER pe_file_size;
    BOOL file_size_res = GetFileSizeEx(
        (HANDLE)pe_file_h,
        &pe_file_size
    );
    if (file_size_res == 0) {
        std::cout << "[!] GetFileSizeEx failed, errro code: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    DWORD64 pe_file_size_quadpart = pe_file_size.QuadPart;

    
  
    std::cout << "Hello World!\n " << std::endl;
}