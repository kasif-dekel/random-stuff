//code from "xpect da bluz" challenge in ARKCON 2018
//not even sure if this is the latest version
//anyway this code is very messy, barely documented and full of self-notes
//some things/parts of the code are irrelevant or was intended to be used but wasnt so forgive it
//released for people to see and learn how it was built.
//kasif dekel

#include "ntddk.h"
#include <wdm.h>
#include <intrin.h>
#include "ntimage.h"


NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObj, IN PUNICODE_STRING registryPath);
ULONG getCPU();
typedef ULONG(*cgetCPU)();
VOID dpcfunc(struct _KDPC  *Dpc, PVOID  DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2);
VOID ProcessNotifyCallbackEx(PEPROCESS  Process, HANDLE  ProcessId, PPS_CREATE_NOTIFY_INFO  CreateInfo);
BOOLEAN  __stdcall MigrateDriver(PUCHAR DriverBase, ULONG  DriverSize, UINT32 NTOSKrnlBase);
typedef BOOLEAN(*mgrt)(PUCHAR DriverBase, ULONG  DriverSize, UINT32 NTOSKrnlBase);
//__declspec(naked) void getEIP();
typedef PVOID(*exallocwithtag)(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
typedef NTSTATUS(*psregisternotify)(PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove);
PVOID GetNTOSExport(PUCHAR ModuleBase, PCHAR  FunctionName, int size);
typedef PVOID(*getntos)(PUCHAR ModuleBase, PCHAR  FunctionName, int size);
PUCHAR FindNTOSBase(PUCHAR KiSystemCall64);
void is_bp(void *mem, size_t size, void *ssdt);
UINT32 crc32_for_byte(UINT32 r);
void crc32(const void *data, size_t n_bytes, UINT32* crc);
void __stdcall xorpw(unsigned char *text, int len);
typedef NTSTATUS(*ntwritedef)(HANDLE FileHandle, HANDLE Event,PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(*ObOpenObjectByPointer)(PVOID Object,ULONG HandleAttributes,PACCESS_STATE PassedAccessState,ACCESS_MASK DesiredAccess,POBJECT_TYPE ObjectType,KPROCESSOR_MODE AccessMode,PHANDLE Handle);
typedef NTSTATUS(*NtRequestWaitReplyPort)(HANDLE PortHandle, PVOID Request, PVOID IncomingReply);
typedef NTSTATUS(__stdcall *ExRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);
typedef BOOLEAN(__stdcall *rtleqauldef)(PCUNICODE_STRING String1, PCUNICODE_STRING String2, BOOLEAN CaseInSensitive);
typedef VOID(__stdcall *rtlinitdef)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(__stdcall *ZwClosedef)(HANDLE Handle);

#pragma intrinsic( memcmp )
#pragma intrinsic( strlen )


#pragma comment(linker,"/SECTION:.text,ERW")
/*#pragma comment(linker,"/SECTION:.data,ERW")
#pragma comment(linker,"/SECTION:.rdata,ERW")
#pragma comment(linker,"/SECTION:.reloc,ERW")*/




#pragma pack(1)
typedef struct _DESC {
	UINT16 offset00;
	UINT16 segsel;
	CHAR unused : 5;
	CHAR zeros : 3;
	CHAR type : 5;
	CHAR DPL : 2;
	CHAR P : 1;
	UINT16 offset16;
} DESC, *PDESC;
#pragma pack()

#pragma pack(1)
typedef struct _IDTR {
	UINT16 bytes;
	UINT32 addr;
} IDTR;
#pragma pack()

typedef enum _HARDERROR_RESPONSE_OPTION
{
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem,
	OptionOkNoWait,
	OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes,
	ResponseTryAgain,
	ResponseContinue
} HARDERROR_RESPONSE;

typedef struct _CONTEXT_DATA
{
	PUCHAR      OrgDriverBase;
	PUCHAR      NewDriverBase;
	ULONG       DriverSize;

	PVOID		oldMigrate;

	PVOID       getCPU;
	PVOID       dpcfunc;
	PVOID       notify_callback;
	PVOID       GetNTOSExport;
	PVOID       xorpw;
	PVOID		getEIP;

	PVOID		rtleqaul;
	PVOID		rtlinit;
	PVOID		exraise;
	PVOID		refobj;
	PVOID		zwread;
	PVOID		zwclose;

	UINT32      NTOSBase;
	UINT32		oldISRAddress;
	ULONG		dwProcNumber;
	PUCHAR      NewContext;
	UINT32		syscall;
	PUCHAR      lstar;

	EX_RUNDOWN_REF	g_RunDownRef;
	KDPC		g_Dpc;
} CONTEXT_DATA, *PCONTEXT_DATA;



//global
CONTEXT_DATA    g_ContextData = { 0 };

__declspec(naked) int getEIP() {
	__asm {
		mov eax, [esp];
		ret; //todo: check cleaning
	}
}

UINT32 crc32_for_byte(UINT32 r) {
	__try {
		_xbegin();
		_xabort(0); //anti IDA decompiler "bug"
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	for (int j = 0; j < 8; ++j)
		r = (r & 1 ? 0 : (UINT32)0xEDB88320L) ^ r >> 1;
	return r ^ (UINT32)0xFF000000L;
}

void crc32(const void *data, size_t n_bytes, UINT32* crc) {
	__try {
		_xbegin();
		_xabort(0); //anti IDA decompiler "bug"
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}

	static UINT32 table[0x100];
	if (!*table) {
		for (size_t i = 0; i < 0x100; ++i) {
			table[i] = crc32_for_byte(i);
		}
	}

	for (size_t i = 0; i < n_bytes; ++i) {
		*crc = table[(UINT8)*crc ^ ((UINT8*)data)[i]] ^ *crc >> 8;
	}
		
}

void is_bp(void *mem, size_t size, void *ssdt) {
	__try {
		_xbegin();
		_xabort(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	unsigned char *tmp = (unsigned char*)mem;
	__writecr8(0xffffffff); // fuck shit up, TODO: Check whether its better than just spraying shit..
	for (size_t i = 0; i < size; i++) {
		if (tmp[i] == 0xCC) {
			//corrupt shit
			//memset(ssdt, 0, 500);
			__writecr8(0xffffffff);
			return;
		}		
	}
	 
}

PUCHAR FindNTOSBase(PUCHAR kisystemstart) {
	__try {
		_xbegin();
		_xabort(0); //anti IDA decompiler "bug"
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	

	
	PUCHAR NTOSKrnlBase = kisystemstart;
#define PAGE_MASK (~((ULONG)(PAGE_SIZE - 1 )))
	NTOSKrnlBase = (PUCHAR)((ULONGLONG)NTOSKrnlBase & PAGE_MASK);

	// Search backwards from kisystemstart
	while (TRUE) {
		if ((NTOSKrnlBase[0] == 'M') &&
			(NTOSKrnlBase[1] == 'Z') &&
			(NTOSKrnlBase[2] == 0x90)) {
			break;
		}
		NTOSKrnlBase -= PAGE_SIZE;
	}
	return NTOSKrnlBase;
}

__declspec(naked) ULONG getCPU() {
	__asm {
		mov     edi, edi
		push    ebp
		mov     ebp, esp
		mov     eax, dword ptr fs : [00000020h]
		mov     eax, dword ptr[eax + 3CCh]
		pop     ebp
		ret
	}



}



IDTR GetIDTAddress() {
	__try {
		_xbegin();
		_xabort(0); //anti IDA decompiler "bug"
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	IDTR idtraddr;

	__asm {
		cli;
		sidt idtraddr;
		sti;
	}

	return idtraddr;
}



PDESC GetDescriptorAddress(UINT16 service) {
	__try {
		_xbegin();
		_xabort(0); //anti IDA decompiler "bug"
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}

	IDTR idtraddr;
	PDESC descaddr;

	idtraddr = GetIDTAddress();
	descaddr = idtraddr.addr + service * 0x8;

	return descaddr;
}

UINT32 GetISRAddress(UINT16 service) {
	__try {
		_xbegin();
		_xabort(0); //anti IDA decompiler "bug"
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	PDESC descaddr;
	UINT32 israddr;

	descaddr = GetDescriptorAddress(service);

	israddr = descaddr->offset16;
	israddr = israddr << 16;
	israddr += descaddr->offset00;
	//global
	g_ContextData.oldISRAddress = israddr;

	return israddr;
}


//div overflow INT hook func
__declspec(naked) void HookRoutine() { // REMEMBER TO LOWER IRQL IF NEEDED !!!!!
	
	__asm {
		cmp ECX, 0xdeadbeef;
		JNE offset g_ContextData.oldISRAddress;
		push EDX;
	}
	KeLowerIrql(PASSIVE_LEVEL); //2do: consider getting kelowerirql ptr dynmaically
	((mgrt)g_ContextData.oldMigrate)(g_ContextData.OrgDriverBase, g_ContextData.DriverSize, g_ContextData.NTOSBase);

	__asm {
		pop EDX;
		mov AX, 222;
		jmp EDX;
	}
}


//hook isr
void HookISR(UINT16 service, UINT32 hookaddr) {
	__try {
		_xbegin();
		_xabort(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	UINT32 israddr;
	UINT16 hookaddr_low;
	UINT16 hookaddr_high;
	PDESC descaddr;

	israddr = GetISRAddress(service);
	if (israddr == hookaddr) {
	}
	else {
		descaddr = GetDescriptorAddress(service);
		hookaddr_low = (UINT16)hookaddr;
		hookaddr = hookaddr >> 16;
		hookaddr_high = (UINT16)hookaddr;

		__asm { cli }
		descaddr->offset00 = hookaddr_low;
		descaddr->offset16 = hookaddr_high;
		__asm { sti }
	}
}




NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObj, IN PUNICODE_STRING registryPath) { 

	__try {
		_xbegin();
		_xabort(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}

	/*char lol_t[0x1000] = {0};
	for (int lol_i = 0; lol_i < 0x100; lol_i) {
		lol_t[lol_i] = lol_i ^ 12;
	}*/


	NTSTATUS NtStatus = STATUS_SUCCESS;

	RTL_OSVERSIONINFOW osinfo = { 0 };
	NtStatus = RtlGetVersion(&osinfo);
	if (!NT_SUCCESS(NtStatus) || (osinfo.dwBuildNumber != 0x1db1 && osinfo.dwBuildNumber != 0x1DB0)) {
		DbgPrint("This challenge is for windows 7 only.");
		goto Exit;
	}

	PUCHAR KiSystemCall = (PUCHAR)__readmsr(0x176);
	g_ContextData.NTOSBase = FindNTOSBase(KiSystemCall);

	g_ContextData.OrgDriverBase = (PUCHAR)driverObj->DriverStart;
	g_ContextData.DriverSize = driverObj->DriverSize;
	g_ContextData.oldMigrate = MigrateDriver; 
	g_ContextData.syscall = GetISRAddress((UINT16)0x2e); // SECOND ONE GETS THE oldISRAddress !!
	g_ContextData.dwProcNumber = getCPU();
	g_ContextData.lstar = KiSystemCall;
	HookISR(0x00, (UINT32)HookRoutine); // TODO: after migrate reload this function pointer in the IDT (Or - restore old one =\) else we gonna crash!

	SHORT dog = (SHORT)g_ContextData.dwProcNumber = getCPU();
	UINT32 vESI = NULL;
	__asm {
		mov AX, 0xffff;
		cwd;
		mov BX, dog;
		mov ECX, 0xdeadbeef; //might want to check the usage of ECX + ESI by DriverEntry
		mov edx, offset afterall;
		div BX; // check why switching CPU - (makes IDT hook not work)
	afterall:
		mov[dog], AX;
		add esp, 0xC; // muy importante - clean the hardware interrupt shit from the stack
	} 

	if (dog == 1337) {
		goto Exit;
	}
	else {
		//call donothing();
	}
	UNICODE_STRING usDriverName, usDosDeviceName;
	PDEVICE_OBJECT pDeviceObject = NULL;
	RtlInitUnicodeString(&usDriverName, L"\\Device\\xpectdabluz");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\xpectdabluz");

	NtStatus = IoCreateDevice(driverObj, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	pDeviceObject->Flags |= 0;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

	IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);

	/*__asm {
	mov AX, 0xffff
	cwd
	mov BX, 2
	div BX
	}


	//keinitializedpc imp
	g_ContextData.g_Dpc.DpcData = 0;
	g_ContextData.g_Dpc.ProcessorHistory = 0;
	g_ContextData.g_Dpc.DeferredRoutine = dpcfunc;
	g_ContextData.g_Dpc.TargetInfoAsUlong = 275;
	g_ContextData.g_Dpc.DeferredContext = driverObj;
	//KeInitializeDpc(&g_Dpc, dpcfunc, driverObj);

	KeSetTargetProcessorDpc(&g_ContextData.g_Dpc, (CCHAR)g_ContextData.dwProcNumber);

	KeInsertQueueDpc(&g_ContextData.g_Dpc, NULL, NULL);*/

	//continue the function to a fake path ? 
	// consider  creating an unsused IOCTL interface (and registering major functions) for static faking


Exit:
	return STATUS_UNSUCCESSFUL;
}


/*REMEMBER: check all status codes and error checks ..*/



VOID dpcfunc(struct _KDPC  *Dpc, PVOID  DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2) {
	__try {
		_xbegin();
		_xabort(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}

	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	ULONG cpuid = getCPU();

}


PVOID GetNTOSExport(PUCHAR ModuleBase, PCHAR  FunctionName, int size) {
	__try {
		_xbegin();
		_xabort(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}

	PIMAGE_DOS_HEADER           DosHeader;
	PIMAGE_NT_HEADERS32         NtHeader;
	PIMAGE_OPTIONAL_HEADER32    OptionalHeader;
	PIMAGE_DATA_DIRECTORY       DataDirectory;
	PIMAGE_EXPORT_DIRECTORY     ExportDirectory;
	PULONG                      FunctionTable;
	PULONG                      NameTable;
	PUSHORT                     NameOrdinalTable;
	ULONG                       FunctionNameLen;
	ULONG                       NameIdx;

	DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	NtHeader = (PIMAGE_NT_HEADERS32)(ModuleBase + DosHeader->e_lfanew);
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&NtHeader->OptionalHeader;
	DataDirectory = (PIMAGE_DATA_DIRECTORY)&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + DataDirectory->VirtualAddress);

	FunctionTable = (PULONG)(ModuleBase + ExportDirectory->AddressOfFunctions);
	NameTable = (PULONG)(ModuleBase + ExportDirectory->AddressOfNames);
	NameOrdinalTable = (PUSHORT)(ModuleBase + ExportDirectory->AddressOfNameOrdinals);

	FunctionNameLen = size;

	for (NameIdx = 0; NameIdx < ExportDirectory->NumberOfNames; NameIdx++) {
		PCHAR Name;
		Name = (PCHAR)(ModuleBase + NameTable[NameIdx]);
		if (memcmp(Name, FunctionName, FunctionNameLen) == 0) { // test whether after migrate memcmp still exists. .

			USHORT NameOrdinal;
			PVOID Address;
			NameOrdinal = NameOrdinalTable[NameIdx];
			Address = (PVOID)(ModuleBase + FunctionTable[NameOrdinal]);
			return Address;
		}
	}

	return NULL;
}


void __stdcall xorpw(unsigned char *text, int len) {
	__try {
		_xbegin();
		_xabort(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	const unsigned char enc[8] = { 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xeb, 0xda, 0xed };
	int i;
	for (i = 0; i < len; i++) {
		text[i] ^= enc[i % 8];
	}

	
}

VOID ProcessNotifyCallbackEx(PEPROCESS  Process, HANDLE  ProcessId, PPS_CREATE_NOTIFY_INFO  CreateInfo) {

	
	__try {
		_xbegin();
		_xabort(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}

	
	UNICODE_STRING ExecutableBlocked = RTL_CONSTANT_STRING(L"\\??\\C:\\k.d");

	PCONTEXT_DATA Data;
	_asm {
	mov Data, 0xCCCCCCCC;
	}
	UINT32 a = (ULONG)((cgetCPU)Data->getCPU)();
	
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Process);


	if (CreateInfo) {
		if (((rtleqauldef)Data->rtleqaul)(&ExecutableBlocked, CreateInfo->ImageFileName, TRUE) == TRUE) {
			UINT32 pth;
			__asm {
				mov eax, fs:0x124;
				mov[eax + 0x13a], byte ptr 0;
				mov eax, [eax + 0x88];
				mov eax, [eax + 0x30];
				mov eax, [eax + 0x10];
				mov eax, [eax + 0x1C];
				mov pth, eax;
			}

			UNICODE_STRING Title, Text;
			char buff[3];
			LARGE_INTEGER startoff = { 0 };
			startoff.LowPart = 0x24;
			IO_STATUS_BLOCK iostatus;
			ULONG Response;
			Title.Buffer = "";
			Title.Length = 0;
			Title.MaximumLength = 0;
			//((rtlinitdef)Data->rtlinit)(&Text, L"test");
			UINT32 fileh = NULL;
			((ObOpenObjectByPointer)Data->refobj)(CreateInfo->FileObject, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *IoFileObjectType, KernelMode, &fileh);

			((ntwritedef)Data->zwread)(fileh, NULL, NULL, NULL, &iostatus, &buff, 3, &startoff, 0);
			unsigned char grats[31] = { 0x75, 0x11, 0x25, 0x11, 0x73, 0x11, 0x25, 0x11, 0x4e, 0x11, 0x75, 0x11, 0x4e, 0x11, 0x75, 0x11, 0x25, 0x11, 0x73, 0x11, 0x25, 0x11, 0x4e, 0x11, 0x75, 0x11, 0x20, 0x11, 0x22, 0x11, 0x30 }; // this is BS, should've had more time to make it better lol

			int iterator;
			unsigned char *currIP;
			UINT32 getIP = Data->getEIP;
			__asm {
				call getIP;
				mov [currIP], eax;
			}
			while (1) {
				if ((currIP[0] == 0x90) && (currIP[1] == 0x90) && (currIP[2] == 0x90)) {
					break;
				} currIP++;
			}
			memcpy(currIP, &buff, 3);
			__asm {
				push eax;
				push ecx;
			}
			for (iterator = 0; iterator < 31; iterator++) {

				__asm {
					mov eax, dword ptr[iterator];
					movsx ecx, byte ptr grats[eax];
					nop;
					nop; //xor         ecx, 11h;
					nop;
					mov byte ptr grats[eax], cl;
				}

			}
			__asm {
				pop ecx;
				pop eax;
			}

			Text.Buffer = grats;
			Text.Length = 31;
			Text.MaximumLength = 32;
			ULONG_PTR p[] = { (ULONG_PTR)&Text,(ULONG_PTR)&Title,0x40 };
			((ExRaiseHardError)Data->exraise)(STATUS_SERVICE_NOTIFICATION, 3, 3, p, OptionOk, &Response);

			((ZwClosedef)Data->zwclose)(fileh);
			__asm {
				mov eax, fs:0x124;
				mov[eax + 0x13a], byte ptr 0;
			}

			CreateInfo->CreationStatus = STATUS_INSUFFICIENT_RESOURCES;
		}

	}


	return;
}

BOOLEAN  __stdcall MigrateDriver(PUCHAR DriverBase, ULONG  DriverSize, UINT32 NTOSKrnlBase) {

	__try {
		_xbegin();
		_xabort(0);
		
		
	}
	__except (EXCEPTION_EXECUTE_HANDLER ) {

	}
	
	goto a;
	__asm __emit(0xea);

	a:
	PCONTEXT_DATA Data = &g_ContextData;

	UINT32 crc_out = 0;

	crc32(ProcessNotifyCallbackEx, 25, &crc_out); 

	if (crc_out != 0x611a034e) {
		//__writecr8(0xffffffff); // TODO: Check if this works
	}

	if (g_ContextData.oldISRAddress != NULL) {
		HookISR(0x00, (UINT32)g_ContextData.oldISRAddress); //restore the motherfucking hook.
	}

	Data->OrgDriverBase = (PUCHAR)DriverBase;
	Data->DriverSize = DriverSize;

	//is_bp(DriverBase, DriverSize, g_ContextData.lstar);

	char ExAllocatePoolWithTag_enc[22] = { 0x9b, 0xd5, 0xff, 0x83, 0x92, 0x84, 0xb9, 0x8c, 0xaa, 0xc8, 0xee, 0x80, 0x91, 0x87, 0x8d, 0x84, 0xaa, 0xc5, 0xea, 0x8e, 0x99, 0xeb };
	int ExAllocatePoolWithTag_dec = 22;
	UINT32 ExAllocatePoolWithTag_adr = &ExAllocatePoolWithTag_enc;
	__asm {
		push eax;
		mov eax, DWORD PTR ExAllocatePoolWithTag_dec;
		push eax;
		push ExAllocatePoolWithTag_adr;
		push offset xalloc;
		jmp xorpw; //remember to disable security_cookie
		xalloc:
		pop eax;
	}


	PVOID ExAllocatePoolWithTag_ptr = GetNTOSExport(NTOSKrnlBase, ExAllocatePoolWithTag_enc, ExAllocatePoolWithTag_dec); // might want to change to stdcall too -
	Data->NewDriverBase = (PUCHAR)((exallocwithtag)ExAllocatePoolWithTag_ptr)(NonPagedPool, Data->DriverSize, '0000'); // check ret addr & validate all in code

	if (!Data->NewDriverBase) {
		goto Exit;
	}

	psregisternotify psfunc = NULL;
	char psregisternotify_enc[34] = { 0x8e, 0xde, 0xed, 0x8a, 0x8a, 0xa8, 0xa8, 0x88, 0xbf, 0xd9, 0xdb, 0xbf, 0x8c, 0x84, 0xb9, 0x88, 0xad, 0xde, 0xf0, 0x80, 0x8a, 0x82, 0xbc, 0x94, 0x8c, 0xc2, 0xcb, 0x9b, 0x97, 0x85, 0xbf, 0xa8, 0xa6, 0xad };
	xorpw(psregisternotify_enc, 34);
	psfunc = GetNTOSExport(NTOSKrnlBase, psregisternotify_enc, 33);

	char rtleqaul[22] = { 0x8c, 0xd9, 0xd2, 0xaa, 0x8f, 0x9e, 0xbb, 0x81, 0x8b, 0xc3, 0xd7, 0x8c, 0x91, 0x8f, 0xbf, 0xbe, 0xaa, 0xdf, 0xd7, 0x81, 0x99, 0xeb };
	xorpw(rtleqaul, 22);
	Data->rtleqaul = GetNTOSExport(NTOSKrnlBase, rtleqaul, 22);


	char rtlinit[23] = { 0x8c, 0xd9, 0xd2, 0xa6, 0x90, 0x82, 0xae, 0xb8, 0xb0, 0xc4, 0xdd, 0x80, 0x9a, 0x8e, 0x89, 0x99, 0xac, 0xc4, 0xd0, 0x88, 0xbb, 0x93, 0xda };
	xorpw(rtlinit, 23);
	Data->rtlinit = GetNTOSExport(NTOSKrnlBase, rtlinit, 23);

	char exraise[17] = { 0x9b, 0xd5, 0xec, 0x8e, 0x97, 0x98, 0xbf, 0xa5, 0xbf, 0xdf, 0xda, 0xaa, 0x8c, 0x99, 0xb5, 0x9f, 0xde };
	xorpw(exraise, 17);
	Data->exraise = GetNTOSExport(NTOSKrnlBase, exraise, 17);


	char refobj[22] = { 0x91, 0xcf, 0xf1, 0x9f, 0x9b, 0x85, 0x95, 0x8f, 0xb4, 0xc8, 0xdd, 0x9b, 0xbc, 0x92, 0x8a, 0x82, 0xb7, 0xc3, 0xca, 0x8a, 0x8c, 0xeb };
	xorpw(refobj, 22);
	Data->refobj = GetNTOSExport(NTOSKrnlBase, refobj, 22);

	char zwread[11] = { 0x84, 0xda, 0xec, 0x8a, 0x9f, 0x8f, 0x9c, 0x84, 0xb2, 0xc8, 0xbe };
	xorpw(zwread, 11);
	Data->zwread = GetNTOSExport(NTOSKrnlBase, zwread, 11);


	char zwclose[8] = { 0x84, 0xda, 0xfd, 0x83, 0x91, 0x98, 0xbf, 0xed };
	xorpw(zwclose, 8);
	Data->zwclose = GetNTOSExport(NTOSKrnlBase, zwclose, 8);

	if (!psfunc) {
		goto Exit;
	}


	//compute addresses in migrated area for migrated code usage
	#define GET_ADJUSTED_POINTER(g, p) ( (g)->NewDriverBase + ( ((PUCHAR)p) - (g)->OrgDriverBase ) )
	Data->NewContext = GET_ADJUSTED_POINTER(Data, &g_ContextData);
	Data->notify_callback = GET_ADJUSTED_POINTER(Data, ProcessNotifyCallbackEx);
	Data->getCPU = GET_ADJUSTED_POINTER(Data, getCPU);
	Data->dpcfunc = GET_ADJUSTED_POINTER(Data, dpcfunc);
	Data->GetNTOSExport = GET_ADJUSTED_POINTER(Data, GetNTOSExport);
	Data->xorpw = GET_ADJUSTED_POINTER(Data, xorpw);
	Data->getEIP = GET_ADJUSTED_POINTER(Data, getEIP);

	memcpy(Data->NewDriverBase, Data->OrgDriverBase, Data->DriverSize);

	char *funcaddr = NULL;
	funcaddr = (char *)Data->notify_callback;

	while (1) {
		if ((funcaddr[0] == -52) && (funcaddr[1] == -52) && (funcaddr[2] == -52) && (funcaddr[3] == -52)) {
			break;
		} funcaddr++;
	}


	unsigned char *psaddr = NULL; // THIS SHOULD BE CHECKED AGAINST ALL VERSIONS OF W7 
	// IT WORKS IN SEVERAL I ALREADY CHECKED....
	psaddr = (unsigned char *)psfunc;
	psaddr += 14;
	unsigned long tmp2 = 0;
	tmp2 = (unsigned long)psaddr[3] << 24 | (unsigned long)psaddr[2] << 16;
	tmp2 |= (unsigned long)psaddr[1] << 8 | (psaddr[0] + 5); // last part *should* overflow.

	//unsigned long tmp2 = (((unsigned long)psaddr[0] >> 24) + 5 & 0xff) | (((unsigned long)psaddr[1] << 8) & 0xff0000) | (((unsigned long)psaddr[] >> 8) & 0xff00) | (((unsigned long)tmp1 << 24) & 0xff000000);
	psaddr = (unsigned long)psaddr + tmp2 - 1;
	psaddr = (unsigned char *)psaddr;
	while (1) {
		if ((psaddr[0] == 0x85) && (psaddr[1] == 0xc0) && (psaddr[2] == 0x75) && (psaddr[3] == 0x07) && (psaddr[4] == 0xb8) && (psaddr[5] == 0x22) && (psaddr[6] == 0x00) && (psaddr[7] == 0x00) && (psaddr[8] == 0xc0)) {
			break;
		} psaddr++;
	}

	__asm {
		push edx;
		mov edx, cr0;
		push edx;
		and edx, 0xFFFEFFFF;
		mov cr0, edx;
		
	}
	psaddr[2] = 0x74;
	__asm {
		pop edx;
		mov cr0, edx;
		pop edx;
	}



	memcpy(funcaddr, &Data->NewContext, 4);

	if (!NT_SUCCESS(psfunc(Data->notify_callback, 0))) {
		goto Exit;
	}



	return TRUE;

Exit:
	return FALSE; // remember to handle FALSE !!!
}