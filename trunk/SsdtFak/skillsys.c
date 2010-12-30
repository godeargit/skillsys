#include <ntddk.h>

///////////////////////////////////////////////////////////
#define DEVICE L"\\Device\\SkillSys"
#define DOSDEVICE L"\\DosDevices\\SkillSys"
PDEVICE_OBJECT MSkillSys;
///////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////
typedef struct _tagSSDT {
	unsigned int *pvSSDTBase;
	unsigned int *pvServiceCounterTable;
	unsigned int ulNumberOfServices;
	unsigned char *pvParamTableBase;
}SSDT, *PSSDT;

__declspec(dllimport) SSDT KeServiceDescriptorTable;

PMDL g_pmdlSystemCall;
PVOID *MappedSystemCallTable;
///////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////
#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.pvSSDTBase[*(PULONG)((PUCHAR)_function + 1)]

#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function + 1)

#define HOOK_SYSCALL(_Function, _Hook, _Orig) _Orig = (PVOID)InterlockedExchange((PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig) InterlockedExchange((PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Orig)
///////////////////////////////////////////////////////////

VOID SeeUser()
{
	PEPROCESS pEprocess = PsGetCurrentProcess();

	PTSTR ProcessName = (PTSTR)((ULONG)pEprocess + 0x16c);

	DbgPrint("processname:%s  use", ProcessName);
}


#pragma region ZwOpenProcess
typedef NTSTATUS (*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

ZWOPENPROCESS OldZwOpenProcess = NULL;

NTSTATUS NewZwOpenProcess(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL)
{
	SeeUser();
	DbgPrint("ZwOpenProcess\n");
	return OldZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
}
#pragma endregion

#pragma region ZwAllocateLocallyUniqueId

typedef NTSTATUS  (*ZWALLOCATELOCALLYUNIQUEID)( OUT PLUID  LUID );

ZWALLOCATELOCALLYUNIQUEID OldZwAllocateLocallyUniqueId = NULL;

NTSTATUS  NewZwAllocateLocallyUniqueId( OUT PLUID  LUID)
{
	SeeUser();
	DbgPrint("ZwAllocateLocallyUniqueId\n");
	return OldZwAllocateLocallyUniqueId(LUID);
}

#pragma endregion

#pragma region ZwAllocateVirtualMemory

typedef NTSTATUS 
  (*ZWALLOCATEVIRTUALMEMORY)(
    __in HANDLE  ProcessHandle,
    __inout PVOID  *BaseAddress,
    __in ULONG_PTR  ZeroBits,
    __inout PSIZE_T  RegionSize,
    __in ULONG  AllocationType,
    __in ULONG  Protect
    ); 

ZWALLOCATEVIRTUALMEMORY OldZwAllocateVirtualMemory = NULL;

NTSTATUS NewZwAllocateVirtualMemory(__in HANDLE  ProcessHandle, __inout PVOID  *BaseAddress, __in ULONG_PTR  ZeroBits, __inout PSIZE_T  RegionSize, __in ULONG  AllocationType, __in ULONG  Protect)
{
	SeeUser();
	DbgPrint("ZwAllocateVirtualMemory\n");
	return OldZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

#pragma endregion

#pragma region ZwClose

typedef NTSTATUS (*ZWCLOSE)( IN HANDLE  Handle);

ZWCLOSE OldZwClose = NULL;

NTSTATUS NewZwClose(IN HANDLE  Handle)
{
	SeeUser();
	DbgPrint("ZwClose\n");
	return OldZwClose(Handle);
}

#pragma endregion

#pragma region ZwCommitComplete < vista

typedef NTSTATUS
  (*ZWCOMMITCOMPLETE)(
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    );

ZWCOMMITCOMPLETE OldZwCommitComplete = NULL;

NTSTATUS
  NewZwCommitComplete(
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    )
{
	SeeUser();
	DbgPrint("ZwCommitComplete\n");
	return OldZwCommitComplete(EnlistmentHandle, TmVirtualClock);
}

#pragma endregion

#pragma region ZwCommitEnlistment

typedef NTSTATUS
  (*ZWCOMMITENLISTMENT) (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    );

ZWCOMMITENLISTMENT OldZwCommitEnlistment = NULL;

NTSTATUS
  NewZwCommitEnlistment (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    )
{
	SeeUser();
	DbgPrint("ZwCommitEnlistment\n");
	return OldZwCommitEnlistment(EnlistmentHandle, TmVirtualClock);
}

#pragma endregion

#pragma region ZwCommitTransaction

typedef NTSTATUS 
  (*ZWCOMMITTRANSACTION)(
    IN PHANDLE  TransactionHandle,
    IN BOOLEAN  Wait
    );

ZWCOMMITTRANSACTION OldZwCommitTransaction = NULL;

NTSTATUS 
  NewZwCommitTransaction(
    IN PHANDLE  TransactionHandle,
    IN BOOLEAN  Wait
    )
{
	SeeUser();
	DbgPrint("ZwCommitTransaction\n");
	return OldZwCommitEnlistment(TransactionHandle, Wait);
}

#pragma endregion

#pragma region ZwCreateDirectoryObject

typedef NTSTATUS 
  (*ZWCREATEDIRECTORYOBJECT)(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

ZWCREATEDIRECTORYOBJECT OldZwCreateDirectoryObject = NULL;

NTSTATUS 
  NewZwCreateDirectoryObject(
    OUT PHANDLE  DirectoryHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwCreateDirectoryObject\n");
	return OldZwCreateDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
}

#pragma endregion

#pragma region ZwCreateEnlistment

typedef NTSTATUS
  (*ZWCREATEENLISTMENT)(
    __out PHANDLE  EnlistmentHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  ResourceManagerHandle,
    __in HANDLE  TransactionHandle,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt ULONG  CreateOptions,
    __in NOTIFICATION_MASK  NotificationMask,
    __in_opt PVOID  EnlistmentKey
    );

ZWCREATEENLISTMENT OldZwCreateEnlistment = NULL;

NTSTATUS
  NewZwCreateEnlistment (
    __out PHANDLE  EnlistmentHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  ResourceManagerHandle,
    __in HANDLE  TransactionHandle,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt ULONG  CreateOptions,
    __in NOTIFICATION_MASK  NotificationMask,
    __in_opt PVOID  EnlistmentKey
    )
{
	SeeUser();
	DbgPrint("ZwCreateEnlistment\n");
	return OldZwCreateEnlistment(
		EnlistmentHandle,
		DesiredAccess,
		ResourceManagerHandle,
		TransactionHandle,
		ObjectAttributes,
		CreateOptions,
		NotificationMask,
		EnlistmentKey
		);
}

#pragma endregion

#pragma region ZwCreateEvent

typedef NTSTATUS
  (*ZWCREATEEVENT)(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN EVENT_TYPE  EventType,
    IN BOOLEAN  InitialState
    );

ZWCREATEEVENT OldZwCreateEvent = NULL;

NTSTATUS
  NewZwCreateEvent(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN EVENT_TYPE  EventType,
    IN BOOLEAN  InitialState
    )
{
	SeeUser();
	DbgPrint("ZwCreateEvent\n");
	return OldZwCreateEvent(
		EventHandle,
		DesiredAccess,
		ObjectAttributes OPTIONAL,
		EventType,
		InitialState
		);
}

#pragma endregion

#pragma region ZwCreateFile

typedef NTSTATUS 
  (*ZWCREATEFILE)(
    __out PHANDLE  FileHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __in_opt PLARGE_INTEGER  AllocationSize,
    __in ULONG  FileAttributes,
    __in ULONG  ShareAccess,
    __in ULONG  CreateDisposition,
    __in ULONG  CreateOptions,
    __in_opt PVOID  EaBuffer,
    __in ULONG  EaLength
    );

ZWCREATEFILE OldZwCreateFile = NULL;

NTSTATUS NewZwCreateFile(
    __out PHANDLE  FileHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __in_opt PLARGE_INTEGER  AllocationSize,
    __in ULONG  FileAttributes,
    __in ULONG  ShareAccess,
    __in ULONG  CreateDisposition,
    __in ULONG  CreateOptions,
    __in_opt PVOID  EaBuffer,
    __in ULONG  EaLength
    )
{
	SeeUser();
	DbgPrint("ZwCreateFile\n");

	return  OldZwCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
    );
}

#pragma endregion

#pragma region ZwCreateKey

typedef NTSTATUS 
  (*ZWCREATEKEY)(
    OUT PHANDLE  KeyHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    IN ULONG  TitleIndex,
    IN PUNICODE_STRING  Class  OPTIONAL,
    IN ULONG  CreateOptions,
    OUT PULONG  Disposition  OPTIONAL
    );

ZWCREATEKEY OldZwCreateKey = NULL;

NTSTATUS NewZwCreateKey(
    OUT PHANDLE  KeyHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    IN ULONG  TitleIndex,
    IN PUNICODE_STRING  Class  OPTIONAL,
    IN ULONG  CreateOptions,
    OUT PULONG  Disposition  OPTIONAL
    )
{
	SeeUser();
	DbgPrint("ZwCreateKey\n");

	return OldZwCreateKey(
		KeyHandle,
		DesiredAccess,
		ObjectAttributes,
		TitleIndex,
		Class,
		CreateOptions,
		Disposition
		);
}

#pragma endregion

#pragma region ZwCreateKeyTransacted

typedef NTSTATUS
  (*ZWCREATEKEYTRANSACTED)(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __reserved ULONG  TitleIndex,
    __in_opt PUNICODE_STRING  Class,
    __in ULONG  CreateOptions,
    __in HANDLE  TransactionHandle,
    __out_opt PULONG  Disposition
    );

ZWCREATEKEYTRANSACTED OldZwCreateKeyTransacted = NULL;

NTSTATUS
  NewZwCreateKeyTransacted(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __reserved ULONG  TitleIndex,
    __in_opt PUNICODE_STRING  Class,
    __in ULONG  CreateOptions,
    __in HANDLE  TransactionHandle,
    __out_opt PULONG  Disposition
    )
{
	SeeUser();
	DbgPrint("ZwCreateKeyTransacted\n");
	return  OldZwCreateKeyTransacted(
		KeyHandle,
		DesiredAccess,
		ObjectAttributes,
		TitleIndex,
		Class,
		CreateOptions,
		TransactionHandle,
		Disposition
		);
}

#pragma endregion

#pragma region ZwCreateResourceManager

typedef NTSTATUS
  (*ZWCREATERESOURCEMANAGER)(
    __out PHANDLE  ResourceManagerHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  TmHandle,
    __in_opt LPGUID  ResourceManagerGuid,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt ULONG  CreateOptions,
    __in_opt PUNICODE_STRING  Description
    );

ZWCREATERESOURCEMANAGER OldZwCreateResourceManager = NULL;


NTSTATUS
  NewZwCreateResourceManager (
    __out PHANDLE  ResourceManagerHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  TmHandle,
    __in_opt LPGUID  ResourceManagerGuid,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt ULONG  CreateOptions,
    __in_opt PUNICODE_STRING  Description
    )
{
	SeeUser();
	DbgPrint("ZwCreateResourceManager\n");
	return  OldZwCreateResourceManager (
		ResourceManagerHandle,
		DesiredAccess,
		TmHandle,
		ResourceManagerGuid,
		ObjectAttributes,
		CreateOptions,
		Description
		);
}

#pragma endregion

#pragma region ZwCreateSection

typedef NTSTATUS 
  (*ZWCREATESECTION)(
    OUT PHANDLE  SectionHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes  OPTIONAL,
    IN PLARGE_INTEGER  MaximumSize  OPTIONAL,
    IN ULONG  SectionPageProtection,
    IN ULONG  AllocationAttributes,
    IN HANDLE  FileHandle  OPTIONAL
    );

ZWCREATESECTION OldZwCreateSection = NULL;

NTSTATUS 
  NewZwCreateSection(
    OUT PHANDLE  SectionHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes  OPTIONAL,
    IN PLARGE_INTEGER  MaximumSize  OPTIONAL,
    IN ULONG  SectionPageProtection,
    IN ULONG  AllocationAttributes,
    IN HANDLE  FileHandle  OPTIONAL
    )
{
	SeeUser();
	DbgPrint("ZwCreateSection\n ");
	return OldZwCreateSection(
		SectionHandle,
		DesiredAccess,
		ObjectAttributes,
		MaximumSize,
		SectionPageProtection,
		AllocationAttributes,
		FileHandle
		);
}

#pragma endregion

#pragma region ZwCreateTransaction

typedef NTSTATUS
  (*ZWCREATETRANSACTION) (
    __out PHANDLE  TransactionHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt LPGUID  Uow,
    __in_opt HANDLE  TmHandle,
    __in_opt ULONG  CreateOptions,
    __in_opt ULONG  IsolationLevel,
    __in_opt ULONG  IsolationFlags,
    __in_opt PLARGE_INTEGER  Timeout,
    __in_opt PUNICODE_STRING  Description 
    );

ZWCREATETRANSACTION OldZwCreateTransaction = NULL;

NTSTATUS
  NewZwCreateTransaction (
    __out PHANDLE  TransactionHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt LPGUID  Uow,
    __in_opt HANDLE  TmHandle,
    __in_opt ULONG  CreateOptions,
    __in_opt ULONG  IsolationLevel,
    __in_opt ULONG  IsolationFlags,
    __in_opt PLARGE_INTEGER  Timeout,
    __in_opt PUNICODE_STRING  Description 
    )
{
	SeeUser();
	DbgPrint("ZwCreateTransaction\n");
	return OldZwCreateTransaction (
		TransactionHandle,
		DesiredAccess,
		ObjectAttributes,
		Uow,
		TmHandle,
		CreateOptions,
		IsolationLevel,
		IsolationFlags,
		Timeout,
		Description 
    );
}

#pragma endregion

///////
//up all 大写
///////

/////////////////////////////////////

///////
//down all DEF
///////

#pragma region ZwCreateTransactionManager

typedef NTSTATUS
   (*DEFZwCreateTransactionManager)(
    __out PHANDLE  TmHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PUNICODE_STRING  LogFileName,
    __in_opt ULONG  CreateOptions,
    __in_opt ULONG  CommitStrength
    );

DEFZwCreateTransactionManager OldZwCreateTransactionManager = NULL;

NTSTATUS
   NewZwCreateTransactionManager(
    __out PHANDLE  TmHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PUNICODE_STRING  LogFileName,
    __in_opt ULONG  CreateOptions,
    __in_opt ULONG  CommitStrength
    )
{
	SeeUser();
	DbgPrint("ZwCreateTransactionManager\n");
	return OldZwCreateTransactionManager(
		TmHandle,
		DesiredAccess,
		ObjectAttributes,
		LogFileName,
		CreateOptions,
		CommitStrength
    );
}

#pragma endregion

#pragma region ZwCurrentProcess
/*
HANDLE
  ZwCurrentProcess(
    );

HANDLE
  ZwCurrentProcess(
    );

HANDLE
  ZwCurrentProcess(
    );
*/
#pragma endregion

#pragma region ZwCurrentThread

/*
The ZwCurrentThread macro returns a handle to the current thread.
*/

#pragma endregion

#pragma region ZwDeleteFile

typedef NTSTATUS
  (*DEFZwDeleteFile)(
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

DEFZwDeleteFile OldZwDeleteFile = NULL;

NTSTATUS
  NewZwDeleteFile(
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwDeleteFile\n");
	return OldZwDeleteFile(
		ObjectAttributes
    );
}
#pragma endregion

#pragma region ZwDeleteKey

typedef NTSTATUS 
  (*DEFZwDeleteKey)(
    IN HANDLE  KeyHandle
    );

DEFZwDeleteKey OldZwDeleteKey = NULL;

NTSTATUS 
  NewZwDeleteKey(
    IN HANDLE  KeyHandle
    )
{
	SeeUser();
	DbgPrint("ZwDeleteKey\n");
	return OldZwDeleteKey(
    KeyHandle
    );
}

#pragma endregion

#pragma region ZwDeleteValueKey

typedef NTSTATUS 
  (*DEFZwDeleteValueKey)(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName
    );

DEFZwDeleteValueKey OldZwDeleteValueKey = NULL;

NTSTATUS 
  NewZwDeleteValueKey(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName
    )
{
	SeeUser();
	return OldZwDeleteValueKey(
		KeyHandle,
		ValueName
    );
}

#pragma endregion

#pragma region FZwDeviceIoControlFile

typedef NTSTATUS 
  (*DEFZwDeviceIoControlFile)(
    IN HANDLE  FileHandle,
    IN HANDLE  Event,
    IN PIO_APC_ROUTINE  ApcRoutine,
    IN PVOID  ApcContext,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  IoControlCode,
    IN PVOID  InputBuffer,
    IN ULONG  InputBufferLength,
    OUT PVOID  OutputBuffer,
    IN ULONG  OutputBufferLength
    ); 

DEFZwDeviceIoControlFile OldZwDeviceIoControlFile = NULL;

NTSTATUS 
  NewZwDeviceIoControlFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event,
    IN PIO_APC_ROUTINE  ApcRoutine,
    IN PVOID  ApcContext,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  IoControlCode,
    IN PVOID  InputBuffer,
    IN ULONG  InputBufferLength,
    OUT PVOID  OutputBuffer,
    IN ULONG  OutputBufferLength
    )
{
	SeeUser();
	DbgPrint("ZwDeviceIoControlFile\n");
	return OldZwDeviceIoControlFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		IoControlCode,
		InputBuffer,
		InputBufferLength,
		OutputBuffer,
		OutputBufferLength
    ); 
}

#pragma endregion

#pragma region ZwDuplicateObject The ZwDuplicateObject routine is reserved for system use. 

typedef NTSTATUS
	(*DEFZwDuplicateObject)(
		IN HANDLE SourceProcessHandle,
		IN HANDLE SourceHandle,
		IN HANDLE TargetProcessHandle,
		OUT PHANDLE TargetHandle OPTIONAL,
		IN ACCESS_MASK DesiredAccess,
		IN ULONG Attributes,
		IN ULONG Options
	);

DEFZwDuplicateObject OldZwDuplicateObject = NULL;


NTSTATUS
	NewZwDuplicateObject(
IN HANDLE SourceProcessHandle,
IN HANDLE SourceHandle,
IN HANDLE TargetProcessHandle,
OUT PHANDLE TargetHandle OPTIONAL,
IN ACCESS_MASK DesiredAccess,
IN ULONG Attributes,
IN ULONG Options
)
{
	SeeUser();
	DbgPrint("ZwDuplicateObject\n");
	return OldZwDuplicateObject(
		SourceProcessHandle,
		SourceHandle,
		TargetProcessHandle,
		TargetHandle,
		DesiredAccess,
		Attributes,
		Options
		);
}

#pragma endregion

#pragma region ZwDuplicateToken

typedef enum _TOKEN_TYPE {
  TokenPrimary = 1,
  TokenImpersonation
} TOKEN_TYPE;
typedef TOKEN_TYPE *PTOKEN_TYPE;

typedef NTSTATUS
  (*DEFZwDuplicateToken)(
    __in HANDLE  ExistingTokenHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in BOOLEAN  EffectiveOnly,
    __in TOKEN_TYPE  TokenType,
    __out PHANDLE  NewTokenHandle
    );

DEFZwDuplicateToken OldZwDuplicateToken = NULL;

NTSTATUS
  ZwDuplicateToken(
    __in HANDLE  ExistingTokenHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in BOOLEAN  EffectiveOnly,
    __in TOKEN_TYPE  TokenType,
    __out PHANDLE  NewTokenHandle
    )
{
	SeeUser();
	DbgPrint("ZwDuplicateToken\n");
	return OldZwDuplicateToken(
		ExistingTokenHandle,
		DesiredAccess,
		ObjectAttributes,
		EffectiveOnly,
		TokenType,
		NewTokenHandle
    );
}

#pragma endregion

#pragma region ZwEnumerateKey

typedef NTSTATUS 
  (*DEFZwEnumerateKey)(
    IN HANDLE  KeyHandle,
    IN ULONG  Index,
    IN KEY_INFORMATION_CLASS  KeyInformationClass,
    OUT PVOID  KeyInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    );

DEFZwEnumerateKey OldZwEnumerateKey = NULL;

NTSTATUS 
  NewZwEnumerateKey(
    IN HANDLE  KeyHandle,
    IN ULONG  Index,
    IN KEY_INFORMATION_CLASS  KeyInformationClass,
    OUT PVOID  KeyInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    )
{
	SeeUser();
	DbgPrint("ZwEnumerateKey\n");
	return OldZwEnumerateKey(
		KeyHandle,
		Index,
		KeyInformationClass,
		KeyInformation,
		Length,
		ResultLength
    );
}

#pragma endregion

#pragma region ZwEnumerateTransactionObject

typedef NTSTATUS 
  (*DEFZwEnumerateTransactionObject) (
    __in_opt HANDLE  RootObjectHandle,
    __in KTMOBJECT_TYPE  QueryType,
    __inout PKTMOBJECT_CURSOR  ObjectCursor,
    __in ULONG  ObjectCursorLength,
    __out PULONG  ReturnLength
    );

DEFZwEnumerateTransactionObject OldZwEnumerateTransactionObject = NULL;


NTSTATUS 
  NewZwEnumerateTransactionObject (
    __in_opt HANDLE  RootObjectHandle,
    __in KTMOBJECT_TYPE  QueryType,
    __inout PKTMOBJECT_CURSOR  ObjectCursor,
    __in ULONG  ObjectCursorLength,
    __out PULONG  ReturnLength
    )
{
	SeeUser();
	DbgPrint("ZwEnumerateTransactionObject\n");
	return OldZwEnumerateTransactionObject (
		RootObjectHandle,
		QueryType,
		ObjectCursor,
		ObjectCursorLength,
		ReturnLength
    );
}

#pragma endregion

#pragma region ZwEnumerateValueKey

typedef NTSTATUS
  (*DEFZwEnumerateValueKey)(
    IN HANDLE  KeyHandle,
    IN ULONG  Index,
    IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
    OUT PVOID  KeyValueInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    );

DEFZwEnumerateValueKey OldZwEnumerateValueKey = NULL;

NTSTATUS
  NewZwEnumerateValueKey(
    IN HANDLE  KeyHandle,
    IN ULONG  Index,
    IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
    OUT PVOID  KeyValueInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    )
{
	SeeUser();
	DbgPrint("ZwEnumerateValueKey\n");
	return OldZwEnumerateValueKey(
		KeyHandle,
		Index,
		KeyValueInformationClass,
		KeyValueInformation,
		Length,
		ResultLength
    );
}

#pragma endregion



////////////

//从这里开始

////////////








////////////

//这里结束

////////////
INT MDLinitED = FALSE;

NTSTATUS initMDL()
{
	g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.pvSSDTBase, KeServiceDescriptorTable.ulNumberOfServices*4);
	if(!g_pmdlSystemCall)
	{
		return STATUS_UNSUCCESSFUL;
	}

	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);

	g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;
	MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);

	MDLinitED = TRUE;
	
	return STATUS_SUCCESS;
}

NTSTATUS Dispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	ULONG IoControlCode;
	NTSTATUS ntstatus;

	ntstatus = Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;

	switch(StackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLOSE:
		break;
	case IRP_MJ_READ:
		break;
	case IRP_MJ_WRITE:
		break;

	case IRP_MJ_DEVICE_CONTROL:
		break;
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntstatus;
}

VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING LinkName;
	RtlInitUnicodeString(&LinkName, DOSDEVICE);
	IoDeleteSymbolicLink(&LinkName);

	__asm cli;  //卸载钩子
	UNHOOK_SYSCALL(ZwOpenProcess, NewZwOpenProcess, OldZwOpenProcess);
	__asm sti;

	if(g_pmdlSystemCall)
	{
		MmUnmapLockedPages(MappedSystemCallTable, g_pmdlSystemCall);
		IoFreeMdl(g_pmdlSystemCall);
	}

	MDLinitED = FALSE;

	if(MSkillSys != NULL)
	{
		IoDeleteDevice(MSkillSys);
	}

	DbgPrint("del all\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntstatus;
	UNICODE_STRING DeviceName;
	UNICODE_STRING LinkName;

	DriverObject->DriverUnload = Unload;

	RtlInitUnicodeString(&DeviceName, DEVICE);
	RtlInitUnicodeString(&LinkName, DOSDEVICE);

	ntstatus = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &MSkillSys);

	if(!NT_SUCCESS(ntstatus))
	{
		DbgPrint("create device failed\n");
		return ntstatus;
	}
	else
	{
		DbgPrint("create device..\n");
	}

	ntstatus = IoCreateSymbolicLink(&LinkName, &DeviceName);
	if(!NT_SUCCESS(ntstatus))
	{
		IoDeleteDevice(MSkillSys);
		DbgPrint("create symbolic link failed\n");
		return ntstatus;
	}
	else
	{
		DbgPrint("create symbolic link..\n");
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Dispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Dispatch;
	DriverObject->MajorFunction[IRP_MJ_READ] = Dispatch;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = Dispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch;

	DbgPrint("hook_create\n");
	if(!NT_SUCCESS(initMDL()))
	{
		DbgPrint("initmdl faild\n");
		return ntstatus;
	}
	OldZwOpenProcess = (ZWOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess));

	__asm cli;
	HOOK_SYSCALL(ZwOpenProcess, NewZwOpenProcess, OldZwOpenProcess);
	__asm sti;
	DbgPrint("hook_create ok\n");

	return ntstatus;
}