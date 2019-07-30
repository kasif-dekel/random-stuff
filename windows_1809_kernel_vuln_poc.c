#include <Windows.h>

#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef NTSTATUS(*NtDeleteValueKey)(HANDLE KeyHandle, PVOID ValueName);

int main() {

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	NtDeleteValueKey ndvk = (NtDeleteValueKey)GetProcAddress(ntdll, "NtDeleteValueKey");

	HKEY out = NULL;



	if (RegCreateKeyA(HKEY_CURRENT_USER, "test", &out) != ERROR_SUCCESS) {
		std::cout << "Could not create key: " << GetLastError() << std::endl;
		exit(1);
	}


	PUNICODE_STRING buffer = (PUNICODE_STRING)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);

	 
	memset(buffer, 0, 0x1000);
	memcpy(buffer, "test", 4);
	

	auto Status = ndvk(out, (PVOID)buffer);

	if (!NT_SUCCESS(Status)) {
		std::cout << "Didn't work: " << std::hex << Status << std::endl;
	}

	
}
