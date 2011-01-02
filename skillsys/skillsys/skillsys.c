#include <ntddk.h>
#include "common.h"
#include "struct.h"
#include "ApiDefine.h"
///////////////////////////////////////////////////////////
#define DEVICE L"\\Device\\SkillSys"
#define DOSDEVICE L"\\DosDevices\\SkillSys"
PDEVICE_OBJECT MSkillSys;
///////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////
__declspec(dllimport) SSDT KeServiceDescriptorTable;

PMDL g_pmdlSystemCall;
PVOID *MappedSystemCallTable;
///////////////////////////////////////////////////////////

#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.pvSSDTBase[*(PULONG)((PUCHAR)_function + 1)]

#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function + 1)

#define HOOK_SYSCALL(_Function, _Hook, _Orig) _Orig= (PVOID)InterlockedExchange((PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig) InterlockedExchange((PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Orig)
///////////////////////////////////////////////////////////

VOID SeeUser()
{
	PEPROCESS pEprocess= PsGetCurrentProcess();
	PTSTR ProcessName= (PTSTR)((ULONG)pEprocess + 0x16c);
	DbgPrint("processname:%s  use", ProcessName);
}




#pragma region ZwAllocateLocallyUniqueId
DEFZwALLOCATELOCALLYUNIQUEID OldZwAllocateLocallyUniqueId= NULL;
NTSTATUS  NewZwAllocateLocallyUniqueId( OUT PLUID  LUID){
	SeeUser();
	DbgPrint("ZwAllocateLocallyUniqueId\n");
	return OldZwAllocateLocallyUniqueId(LUID);
}
#pragma endregion

#pragma region ZwAllocateVirtualMemory
DEFZwALLOCATEVIRTUALMEMORY OldZwAllocateVirtualMemory= NULL;
NTSTATUS NewZwAllocateVirtualMemory(__in HANDLE  ProcessHandle, __inout PVOID  *BaseAddress, __in ULONG_PTR  ZeroBits, __inout PSIZE_T  RegionSize, __in ULONG  AllocationType, __in ULONG  Protect){
	SeeUser();
	DbgPrint("ZwAllocateVirtualMemory\n");
	return OldZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

#pragma endregion

#pragma region ZwClose

DEFZwCLOSE OldZwClose= NULL;

NTSTATUS NewZwClose(IN HANDLE  Handle)
{
	SeeUser();
	DbgPrint("ZwClose\n");
	return OldZwClose(Handle);
}

#pragma endregion

#pragma region ZwCommitComplete < vista

DEFZwCOMMITCOMPLETE OldZwCommitComplete= NULL;
NTSTATUS
  NewZwCommitComplete(
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    ){
	SeeUser();
	DbgPrint("ZwCommitComplete\n");
	return OldZwCommitComplete(EnlistmentHandle, TmVirtualClock);
}
#pragma endregion

#pragma region ZwCommitEnlistment
DEFZwCOMMITENLISTMENT OldZwCommitEnlistment= NULL;

NTSTATUS
  NewZwCommitEnlistment (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    ){
	SeeUser();
	DbgPrint("ZwCommitEnlistment\n");
	return OldZwCommitEnlistment(EnlistmentHandle, TmVirtualClock);
}

#pragma endregion

#pragma region ZwCommitTransactio;
DEFZwCOMMITTRANSACTION OldZwCommitTransaction= NULL;

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
DEFZwCREATEDIRECTORYOBJECT OldZwCreateDirectoryObject= NULL;

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
DEFZwCREATEENLISTMENT OldZwCreateEnlistment= NULL;

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

DEFZwCREATEEVENT OldZwCreateEvent= NULL;

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

DEFZwCREATEFILE OldZwCreateFile= NULL;

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
DEFZwCREATEKEY OldZwCreateKey= NULL;

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
DEFZwCREATEKEYTRANSACTED OldZwCreateKeyTransacted= NULL;

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

DEFZwCREATERESOURCEMANAGER OldZwCreateResourceManager= NULL;


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
DEFZwCREATESECTION OldZwCreateSection= NULL;

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
DEFZwCREATETRANSACTION OldZwCreateTransaction= NULL;

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

#pragma region ZwCreateTransactionManager

DEFZwCreateTransactionManager OldZwCreateTransactionManager= NULL;

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

DEFZwDeleteFile OldZwDeleteFile= NULL;

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

DEFZwDeleteKey OldZwDeleteKey= NULL;

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
DEFZwDeleteValueKey OldZwDeleteValueKey= NULL;

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

DEFZwDeviceIoControlFile OldZwDeviceIoControlFile= NULL;

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
DEFZwDuplicateObject OldZwDuplicateObject= NULL;
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
DEFZwDuplicateToken OldZwDuplicateToken= NULL;

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
DEFZwEnumerateKey OldZwEnumerateKey= NULL;
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
DEFZwEnumerateTransactionObject OldZwEnumerateTransactionObject= NULL;

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
DEFZwEnumerateValueKey OldZwEnumerateValueKey= NULL;

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

#pragma region ZwFlushBuffersFile

DEFZwFlushBuffersFile OldZwFlushBuffersFile= NULL;

NTSTATUS
  NewZwFlushBuffersFile(
    IN HANDLE  FileHandle,
    IN PIO_STATUS_BLOCK  IoStatusBlock
    )
{
	SeeUser();
	DbgPrint("ZwFlushBuffersFile\n");
	return OldZwFlushBuffersFile(
		FileHandle,
		IoStatusBlock
    ); 
}

#pragma endregion

#pragma region ZwFlushKey

DEFZwFlushKey OldZwFlushKey= NULL;

NTSTATUS 
  NewZwFlushKey(
    IN HANDLE  KeyHandle
    )
{
	SeeUser();
	DbgPrint("ZwFlushKey\n");
	return OldZwFlushKey(
		KeyHandle
    );
}

#pragma endregion

#pragma region ZwFlushVirtualMemory

DEFZwFlushVirtualMemory OldZwFlushVirtualMemory= NULL;

NTSTATUS 
  ZwFlushVirtualMemory(
    IN HANDLE  ProcessHandle,
    IN OUT PVOID  *BaseAddress,
    IN OUT PSIZE_T  RegionSize,
    OUT PIO_STATUS_BLOCK  IoStatus 
    )
{
	SeeUser();
	DbgPrint("ZwFlushVirtualMemory\n");
	return OldZwFlushVirtualMemory(
		ProcessHandle,
		BaseAddress,
		RegionSize,
		IoStatus 
    ); 
}

#pragma endregion

#pragma region ZwFreeVirtualMemory

DEFZwFreeVirtualMemory OldZwFreeVirtualMemory= NULL;

NTSTATUS 
  NewZwFreeVirtualMemory(
    __in HANDLE  ProcessHandle,
    __inout PVOID  *BaseAddress,
    __inout PSIZE_T  RegionSize,
    __in ULONG  FreeType
    )
{
	SeeUser();
	DbgPrint("ZwFreeVirtualMemory\n");
	OldZwFreeVirtualMemory(
		ProcessHandle,
		BaseAddress,
		RegionSize,
		FreeType
    ); 
}

#pragma endregion

#pragma region ZwFsControlFile

DEFZwFsControlFile OldZwFsControlFile= NULL;

NTSTATUS
  ZwFsControlFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event OPTIONAL,
    IN PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
    IN PVOID  ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  FsControlCode,
    IN PVOID  InputBuffer OPTIONAL,
    IN ULONG  InputBufferLength,
    OUT PVOID  OutputBuffer OPTIONAL,
    IN ULONG  OutputBufferLength
    )
{
	return OldZwFsControlFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FsControlCode,
		InputBuffer,
		InputBufferLength,
		OutputBuffer,
		OutputBufferLength
    ); 
}

#pragma endregion

#pragma region ZwGetNotificationResourceManager

DEFZwGetNotificationResourceManager OldZwGetNotificationResourceManager= NULL;

NTSTATUS
  NewZwGetNotificationResourceManager (
    __in HANDLE  ResourceManagerHandle,
    __out PTRANSACTION_NOTIFICATION  TransactionNotification,
    __in ULONG  NotificationLength,
    __in PLARGE_INTEGER  Timeout,
    __out_opt PULONG  ReturnLength,
    __in ULONG  Asynchronous,
    __in_opt ULONG_PTR  AsynchronousContext
    )
{
	SeeUser();
	DbgPrint("ZwGetNotificationResourceManager\n");
	return OldZwGetNotificationResourceManager (
		ResourceManagerHandle,
		TransactionNotification,
		NotificationLength,
		Timeout,
		ReturnLength,
		Asynchronous,
		AsynchronousContext
    );
}
#pragma endregion

#pragma region ZwLoadDriver

DEFZwLoadDriver OldZwLoadDriver= NULL;

NTSTATUS 
  NewZwLoadDriver(
    IN PUNICODE_STRING  DriverServiceName
    )
{
	SeeUser();
	DbgPrint("ZwLoadDriver\n");
	return OldZwLoadDriver(
		DriverServiceName
    );
}

#pragma endregion

#pragma region ZwLockFile

DEFZwLockFile OldZwLockFile= NULL;

NTSTATUS 
  NewZwLockFile(
    __in HANDLE  FileHandle,
    __in_opt HANDLE  Event,
    __in_opt PIO_APC_ROUTINE  ApcRoutine,
    __in_opt PVOID  ApcContext,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __in PLARGE_INTEGER  ByteOffset,
    __in PLARGE_INTEGER  Length,
    __in ULONG  Key,
    __in BOOLEAN  FailImmediately,
    __in BOOLEAN  ExclusiveLock
    )
{
	SeeUser();
	DbgPrint("ZwLockFile\n");
	return OldZwLockFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		ByteOffset,
		Length,
		Key,
		FailImmediately,
		ExclusiveLock
    );
}

#pragma endregion

#pragma region ZwMakeTemporaryObject

DEFZwMakeTemporaryObject OldZwMakeTemporaryObject= NULL;

NTSTATUS 
  NewZwMakeTemporaryObject(
    IN HANDLE  Handle
    )
{
	SeeUser();
	DbgPrint("ZwMakeTemporaryObject\n");
	return OldZwMakeTemporaryObject(
		Handle
    );
}

#pragma endregion

#pragma region ZwMapViewOfSection

DEFZwMapViewOfSection OldZwMapViewOfSection= NULL;

NTSTATUS 
  NewZwMapViewOfSection(
    IN HANDLE  SectionHandle,
    IN HANDLE  ProcessHandle,
    IN OUT PVOID  *BaseAddress,
    IN ULONG_PTR  ZeroBits,
    IN SIZE_T  CommitSize,
    IN OUT PLARGE_INTEGER  SectionOffset  OPTIONAL,
    IN OUT PSIZE_T  ViewSize,
    IN SECTION_INHERIT  InheritDisposition,
    IN ULONG  AllocationType,
    IN ULONG  Win32Protect
    )
{
	SeeUser();
	DbgPrint("ZwMapViewOfSection\n");
	return OldZwMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Win32Protect
    );
}

#pragma endregion

#pragma region ZwNotifyChangeKey

DEFZwNotifyChangeKey OldZwNotifyChangeKey= NULL;

NTSTATUS
  NewZwNotifyChangeKey(
    __in HANDLE  KeyHandle,
    __in_opt HANDLE  Event,
    __in_opt PIO_APC_ROUTINE  ApcRoutine,
    __in_opt PVOID  ApcContext,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __in ULONG  CompletionFilter,
    __in BOOLEAN  WatchTree,
    __out_opt PVOID  Buffer,
    __in ULONG  BufferSize,
    __in BOOLEAN  Asynchronous
    )
{
	SeeUser();
	DbgPrint("ZwNotifyChangeKey\n");
	return OldZwNotifyChangeKey(
		KeyHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		CompletionFilter,
		WatchTree,
		Buffer,
		BufferSize,
		Asynchronous
    );
}

#pragma endregion

#pragma region ZwOpenDirectoryObject

DEFZwOpenDirectoryObject OldZwOpenDirectoryObject = NULL;

NTSTATUS
  NewZwOpenDirectoryObject(
    __out PHANDLE  DirectoryHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwOpenDirectoryObject\n");
	return OldZwOpenDirectoryObject(
		DirectoryHandle,
		DesiredAccess,
		ObjectAttributes
    );
}

#pragma endregion

#pragma region ZwOpenEnlistment

DEFZwOpenEnlistment OldZwOpenEnlistment= NULL;

NTSTATUS
  NewZwOpenEnlistment (
    __out PHANDLE  EnlistmentHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  RmHandle,
    __in LPGUID  EnlistmentGuid,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwOpenEnlistment\n");
	return OldZwOpenEnlistment (
		EnlistmentHandle,
		DesiredAccess,
		RmHandle,
		EnlistmentGuid,
		ObjectAttributes
    );
}

#pragma endregion

#pragma region ZwOpenEvent

DEFZwOpenEvent OldZwOpenEvent= NULL;

NTSTATUS 
  NewZwOpenEvent(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwOpenEvent\n");
	return OldZwOpenEvent(
		EventHandle,
		DesiredAccess,
		ObjectAttributes
    );
}

#pragma endregion

#pragma region ZwOpenFile

DEFZwOpenFile OldZwOpenFile= NULL;

NTSTATUS
  NewZwOpenFile(
    OUT PHANDLE  FileHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  ShareAccess,
    IN ULONG  OpenOptions
    )
{
	SeeUser();
	DbgPrint("ZwOpenFile\n");
	return OldZwOpenFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		ShareAccess,
		OpenOptions
    );
}

#pragma endregion

#pragma region ZwOpenKey

DEFZwOpenKey OldZwOpenKey= NULL;

NTSTATUS 
  NewZwOpenKey(
    OUT PHANDLE  KeyHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwOpenKey\n");
	return OldZwOpenKey(
		KeyHandle,
		DesiredAccess,
		ObjectAttributes
    );
}

#pragma endregion

#pragma region ZwOpenKeyEx

DEFZwOpenKeyEx OldZwOpenKeyEx= NULL;

NTSTATUS
  NewZwOpenKeyEx(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in ULONG  OpenOptions
    )
{
	SeeUser();
	DbgPrint("ZwOpenKeyEx\n");
	return OldZwOpenKeyEx(
		KeyHandle,
		DesiredAccess,
		ObjectAttributes,
		OpenOptions
    );
}

#pragma endregion

#pragma region ZwOpenKeyTransacted

DEFZwOpenKeyTransacted OldZwOpenKeyTransacted= NULL;

NTSTATUS
  NewZwOpenKeyTransacted(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in HANDLE  TransactionHandle
    )
{
	SeeUser();
	DbgPrint("ZwOpenKeyTransacted\n");
	return OldZwOpenKeyTransacted(
		KeyHandle,
		DesiredAccess,
		ObjectAttributes,
		TransactionHandle
    );
}

#pragma endregion

#pragma region ZwOpenKeyTransactedEx

DEFZwOpenKeyTransactedEx OldZwOpenKeyTransactedEx= NULL;

NTSTATUS
  ZwOpenKeyTransactedEx(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in ULONG  OpenOptions,
    __in HANDLE  TransactionHandle
    )
{
	SeeUser();
	DbgPrint("ZwOpenKeyTransactedEx\n");
	return OldZwOpenKeyTransactedEx(
		KeyHandle,
		DesiredAccess,
		ObjectAttributes,
		OpenOptions,
		TransactionHandle
    );
}

#pragma endregion

#pragma region ZwOpenProcess
DEFZwOpenProcess OldZwOpenProcess= NULL;

NTSTATUS NewZwOpenProcess(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL)
{
	SeeUser();
	DbgPrint("ZwOpenProcess\n");
	return OldZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
}
#pragma endregion

#pragma region ZwOpenProcessTokenEx
DEFZwOpenProcessTokenEx OldZwOpenProcessTokenEx= NULL;
NTSTATUS
  NewZwOpenProcessTokenEx(
    IN HANDLE  ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN ULONG  HandleAttributes,
    OUT PHANDLE  TokenHandle
    )
{
	SeeUser();
	DbgPrint("ZwOpenProcessTokenEx\n");
	return OldZwOpenProcessTokenEx(
		ProcessHandle,
		DesiredAccess,
		HandleAttributes,
		TokenHandle
    );
}

#pragma endregion

#pragma region ZwOpenResourceManager

DEFZwOpenResourceManager OldZwOpenResourceManager= NULL;

NTSTATUS
  NewZwOpenResourceManager (
    __out PHANDLE  ResourceManagerHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  TmHandle,
    __in LPGUID  ResourceManagerGuid,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwOpenResourceManager\n");
	return	OldZwOpenResourceManager (
		ResourceManagerHandle,
		DesiredAccess,
		TmHandle,
		ResourceManagerGuid,
		ObjectAttributes
    );
}

#pragma endregion

#pragma region ZwOpenSection

DEFZwOpenSection OldZwOpenSection= NULL;

NTSTATUS 
  NewZwOpenSection(
    OUT PHANDLE  SectionHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwOpenSection\n");
	return OldZwOpenSection(
		SectionHandle,
		DesiredAccess,
		ObjectAttributes
    );
}

#pragma endregion

#pragma region ZwOpenSymbolicLinkObject

DEFZwOpenSymbolicLinkObject OldZwOpenSymbolicLinkObject= NULL;

NTSTATUS
  NewZwOpenSymbolicLinkObject(
    OUT PHANDLE  LinkHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
	SeeUser();
	DbgPrint("ZwOpenSymbolicLinkObject\n");
	return OldZwOpenSymbolicLinkObject(
		LinkHandle,
		DesiredAccess,
		ObjectAttributes
    );
}

#pragma endregion

#pragma region ZwOpenThreadTokenEx

DEFZwOpenThreadTokenEx OldZwOpenThreadTokenEx= NULL;

NTSTATUS
  NewZwOpenThreadTokenEx(
    IN HANDLE  ThreadHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN BOOLEAN  OpenAsSelf,
    IN ULONG  HandleAttributes,
    OUT PHANDLE  TokenHandle
    )
{
	SeeUser();
	DbgPrint("ZwOpenThreadTokenEx\n");
	return OldZwOpenThreadTokenEx(
		ThreadHandle,
		DesiredAccess,
		OpenAsSelf,
		HandleAttributes,
		TokenHandle
    );
}

#pragma endregion

#pragma region ZwOpenTransaction

DEFZwOpenTransaction OldZwOpenTransaction= NULL;

NTSTATUS
  NewZwOpenTransaction (
    __out PHANDLE  TransactionHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in LPGUID  Uow,
    __in_opt HANDLE  TmHandle
    )
{
	SeeUser();
	DbgPrint("ZwOpenTransaction\n");
	return OldZwOpenTransaction (
		TransactionHandle,
		DesiredAccess,
		ObjectAttributes,
		Uow,
		TmHandle
    );
}

#pragma endregion

#pragma region ZwOpenTransactionManager

DEFZwOpenTransactionManager OldZwOpenTransactionManager= NULL;

NTSTATUS
  NewZwOpenTransactionManager(
    __out PHANDLE  TmHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PUNICODE_STRING  LogFileName,
    __in_opt LPGUID  TmIdentity,
    __in_opt ULONG  OpenOptions
    )
{
	SeeUser();
	DbgPrint("ZwOpenTransactionManager\n");
	return OldZwOpenTransactionManager(
		TmHandle,
		DesiredAccess,
		ObjectAttributes,
		LogFileName,
		TmIdentity,
		OpenOptions
    );
}

#pragma endregion

#pragma region ZwPrepareComplete

DEFZwPrepareComplete OldZwPrepareComplete = NULL;

NTSTATUS
  NewZwPrepareComplete (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    )
{
	SeeUser();
	DbgPrint("ZwPrepareComplete\n");
	return OldZwPrepareComplete (
		EnlistmentHandle,
		TmVirtualClock
    );
}

#pragma endregion

#pragma region ZwPrepareEnlistment

DEFZwPrepareEnlistment OldZwPrepareEnlistment= NULL;

NTSTATUS
  NewZwPrepareEnlistment (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    )
{
	SeeUser();
	DbgPrint("ZwPrepareEnlistment\n");
	return OldZwPrepareEnlistment (
		EnlistmentHandle,
		TmVirtualClock
    );
}

#pragma endregion

#pragma region ZwPrePrepareComplete

DEFZwPrePrepareComplete OldZwPrePrepareComplete = NULL;

NTSTATUS
  NewZwPrePrepareComplete (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    )
{
	SeeUser();
	DbgPrint("ZwPrePrepareComplete\n");
	return OldZwPrePrepareComplete (
		EnlistmentHandle,
		TmVirtualClock
    );
}

#pragma endregion

#pragma region ZwPrePrepareEnlistment

DEFZwPrePrepareEnlistment OldZwPrePrepareEnlistment= NULL;

NTSTATUS
  NewZwPrePrepareEnlistment (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    )
{
	SeeUser();
	DbgPrint("NewZwPrePrepareEnlistment");
	return OldZwPrePrepareEnlistment (
		EnlistmentHandle,
		TmVirtualClock
    );
}

#pragma endregion

#pragma region ZwQueryDirectoryFile

DEFZwQueryDirectoryFile OldZwQueryDirectoryFile = NULL;

NTSTATUS 
  NewZwQueryDirectoryFile(
    __in HANDLE  FileHandle,
    __in_opt HANDLE  Event,
    __in_opt PIO_APC_ROUTINE  ApcRoutine,
    __in_opt PVOID  ApcContext,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __out PVOID  FileInformation,
    __in ULONG  Length,
    __in FILE_INFORMATION_CLASS  FileInformationClass,
    __in BOOLEAN  ReturnSingleEntry,
    __in_opt PUNICODE_STRING  FileName,
    __in BOOLEAN  RestartScan
    )
{
	SeeUser();
	DbgPrint("ZwQueryDirectoryFile\n");
	return OldZwQueryDirectoryFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan
    );
}

#pragma endregion

#pragma region ZwQueryFullAttributesFile

DEFZwQueryFullAttributesFile OldZwQueryFullAttributesFile = NULL;

NTSTATUS
  ZwQueryFullAttributesFile(
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION  FileInformation
    )
{
	SeeUser();
	DbgPrint("ZwQueryFullAttributesFile\n");
	return OldZwQueryFullAttributesFile(
		ObjectAttributes,
		FileInformation
    );
}

#pragma endregion

#pragma region ZwQueryInformationEnlistment

DEFZwQueryInformationEnlistment OldZwQueryInformationEnlistment = NULL;

NTSTATUS
  NewZwQueryInformationEnlistment (
    __in HANDLE  EnlistmentHandle,
    __in ENLISTMENT_INFORMATION_CLASS  EnlistmentInformationClass,
    __out PVOID  EnlistmentInformation,
    __in ULONG  EnlistmentInformationLength,
    __out_opt PULONG  ReturnLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryInformationEnlistment\n");
	return OldZwQueryInformationEnlistment (
		EnlistmentHandle,
		EnlistmentInformationClass,
		EnlistmentInformation,
		EnlistmentInformationLength,
		ReturnLength
    );
}

#pragma endregion

#pragma region ZwQueryInformationFile

DEFZwQueryInformationFile OldZwQueryInformationFile = NULL;

NTSTATUS 
  NewZwQueryInformationFile(
    IN HANDLE  FileHandle,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  FileInformation,
    IN ULONG  Length,
    IN FILE_INFORMATION_CLASS  FileInformationClass
    )
{
	SeeUser();
	DbgPrint("ZwQueryInformationFile\n");
	return OldZwQueryInformationFile(
		FileHandle,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass
    );
}

#pragma endregion

#pragma region ZwQueryInformationResourceManager

DEFZwQueryInformationResourceManager OldZwQueryInformationResourceManager = NULL;

NTSTATUS
  NewZwQueryInformationResourceManager (
    __in HANDLE  ResourceManagerHandle,
    __in RESOURCEMANAGER_INFORMATION_CLASS  ResourceManagerInformationClass,
    __out PVOID  ResourceManagerInformation,
    __in ULONG  ResourceManagerInformationLength,
    __out_opt PULONG  ReturnLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryInformationResourceManager\n");
	return OldZwQueryInformationResourceManager (
		ResourceManagerHandle,
		ResourceManagerInformationClass,
		ResourceManagerInformation,
		ResourceManagerInformationLength,
		ReturnLength
    );
}

#pragma endregion

#pragma region ZwQueryInformationToken

DEFZwQueryInformationToken OldZwQueryInformationToken = NULL;

NTSTATUS
  NewZwQueryInformationToken(
    IN HANDLE  TokenHandle,
    IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
    OUT PVOID  TokenInformation,
    IN ULONG  TokenInformationLength,
    OUT PULONG  ReturnLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryInformationToken\n");
	return OldZwQueryInformationToken(
		TokenHandle,
		TokenInformationClass,
		TokenInformation,
		TokenInformationLength,
		ReturnLength
    ); 
}

#pragma endregion

#pragma region ZwQueryInformationTransaction

DEFZwQueryInformationTransaction OldZwQueryInformationTransaction = NULL;

NTSTATUS
  NewZwQueryInformationTransaction (
    __in HANDLE  TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS  TransactionInformationClass,
    __out PVOID  TransactionInformation,
    __in ULONG  TransactionInformationLength,
    __out_opt PULONG  ReturnLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryInformationTransaction\n");
	return OldZwQueryInformationTransaction (
		TransactionHandle,
		TransactionInformationClass,
		TransactionInformation,
		TransactionInformationLength,
		ReturnLength
    );
}

#pragma endregion

#pragma region ZwQueryInformationTransactionManager

DEFZwQueryInformationTransactionManager OldZwQueryInformationTransactionManager = NULL;

NTSTATUS
  NewZwQueryInformationTransactionManager(
    __in HANDLE  TransactionManagerHandle,
    __in TRANSACTIONMANAGER_INFORMATION_CLASS  TransactionManagerInformationClass,
    __out PVOID  TransactionManagerInformation,
    __in ULONG  TransactionManagerInformationLength,
    __out_opt PULONG  ReturnLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryInformationTransactionManager\n");
	return OldZwQueryInformationTransactionManager(
		TransactionManagerHandle,
		TransactionManagerInformationClass,
		TransactionManagerInformation,
		TransactionManagerInformationLength,
		ReturnLength
    );
}

#pragma endregion

#pragma region ZwQueryKey

DEFZwQueryKey OldZwQueryKey = NULL;

NTSTATUS 
  NewZwQueryKey(
    IN HANDLE  KeyHandle,
    IN KEY_INFORMATION_CLASS  KeyInformationClass,
    OUT PVOID  KeyInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryKey\n");
	return OldZwQueryKey(
		KeyHandle,
		KeyInformationClass,
		KeyInformation,
		Length,
		ResultLength
    );
}

#pragma endregion

#pragma region ZwQueryObject

DEFZwQueryObject OldZwQueryObject= NULL;

NTSTATUS
  NewZwQueryObject(
    __in_opt HANDLE  Handle,
    __in OBJECT_INFORMATION_CLASS  ObjectInformationClass,
    __out_bcount_opt(ObjectInformationLength) PVOID  ObjectInformation,
    __in ULONG  ObjectInformationLength,
    __out_opt PULONG  ReturnLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryObject\n");
	return OldZwQueryObject(
		Handle,
		ObjectInformationClass,
		ObjectInformation,
		ObjectInformationLength,
		ReturnLength
    );
}

#pragma endregion

#pragma region ZwQueryQuotaInformationFile

DEFZwQueryQuotaInformationFile OldZwQueryQuotaInformationFile = NULL;

NTSTATUS
  NewZwQueryQuotaInformationFile(
    __in HANDLE  FileHandle,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __out  PVOID Buffer,
    __in ULONG  Length,
    __in BOOLEAN  ReturnSingleEntry,
    __in_opt PVOID  SidList,
    __in ULONG  SidListLength,
    __in_opt PSID  StartSid OPTIONAL,
    __in BOOLEAN  RestartScan
)
{
	SeeUser();
	DbgPrint("ZwQueryQuotaInformationFile\n");
	return OldZwQueryQuotaInformationFile(
		FileHandle,
		IoStatusBlock,
		Buffer,
		Length,
		ReturnSingleEntry,
		SidList,
		SidListLength,
		StartSid,
		RestartScan
	);
}

#pragma endregion

#pragma region ZwQuerySecurityObject

DEFZwQuerySecurityObject OldZwQuerySecurityObject = NULL;

NTSTATUS
  NewZwQuerySecurityObject(
    IN HANDLE  Handle,
    IN SECURITY_INFORMATION  SecurityInformation,
    OUT PSECURITY_DESCRIPTOR  SecurityDescriptor,
    IN ULONG  Length,
    OUT PULONG  LengthNeeded
    )
{
	SeeUser();
	DbgPrint("ZwQuerySecurityObject\n");
	return OldZwQuerySecurityObject(
		Handle,
		SecurityInformation,
		SecurityDescriptor,
		Length,
		LengthNeeded
    ); 
}

#pragma endregion

#pragma region ZwQuerySymbolicLinkObject

DEFZwQuerySymbolicLinkObject OldZwQuerySymbolicLinkObject= NULL;
NTSTATUS
  NewZwQuerySymbolicLinkObject(
    IN HANDLE  LinkHandle,
    IN OUT PUNICODE_STRING  LinkTarget,
    OUT PULONG  ReturnedLength OPTIONAL
    )
{
	SeeUser();
	DbgPrint("ZwQuerySymbolicLinkObject\n");
	return OldZwQuerySymbolicLinkObject(
		LinkHandle,
		LinkTarget,
		ReturnedLength
    );
}

#pragma endregion

#pragma region ZwQueryValueKey

DEFZwQueryValueKey OldZwQueryValueKey = NULL;

NTSTATUS 
  NewZwQueryValueKey(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName,
    IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
    OUT PVOID  KeyValueInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    )
{
	SeeUser();
	DbgPrint("ZwQueryValueKey\n");
	return OldZwQueryValueKey(
		KeyHandle,
		ValueName,
		KeyValueInformationClass,
		KeyValueInformation,
		Length,
		ResultLength
    );
}

#pragma endregion

#pragma region ZwQueryVolumeInformationFile

DEFZwQueryVolumeInformationFile OldZwQueryVolumeInformationFile = NULL;

NTSTATUS
  NewZwQueryVolumeInformationFile(
    IN HANDLE  FileHandle,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  FsInformation,
    IN ULONG  Length,
    IN FS_INFORMATION_CLASS  FsInformationClass
    )
{
	SeeUser();
	DbgPrint("ZwQueryVolumeInformationFile\n");
	return OldZwQueryVolumeInformationFile(
		FileHandle,
		IoStatusBlock,
		FsInformation,
		Length,
		FsInformationClass
    );
}

#pragma endregion


/*
* 添加时间：2011年1月2日 23:44:50
* By:Cooolie
*/

DEFZwReadFile OldZwReadFile=NULL;
NTSTATUS 
NewZwReadFile(
		   IN HANDLE  FileHandle,
		   IN HANDLE  Event  OPTIONAL,
		   IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL,
		   IN PVOID  ApcContext  OPTIONAL,
		   OUT PIO_STATUS_BLOCK  IoStatusBlock,
		   OUT PVOID  Buffer,
		   IN ULONG  Length,
		   IN PLARGE_INTEGER  ByteOffset  OPTIONAL,
		   IN PULONG  Key  OPTIONAL
		   )
{
	   SeeUser();
	   DbgPrint("ZwReadFile\n");
	   return OldZwReadFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,Buffer,Length,ByteOffset,Key);
}

DEFZwSetEvent OldZwSetEvent=NULL; 
NTSTATUS
NewZwSetEvent(
		   __in HANDLE  EventHandle,
		   __out_opt PLONG  PreviousState 
		   )
{
	SeeUser();
	DbgPrint("NewZwSetEvent\n");
	return OldZwSetEvent(EventHandle,PreviousState);
}

DEFZwSetInformationFile OldZwSetInformationFile=NULL;
NTSTATUS 
NewZwSetInformationFile(
					 IN HANDLE  FileHandle,
					 OUT PIO_STATUS_BLOCK  IoStatusBlock,
					 IN PVOID  FileInformation,
					 IN ULONG  Length,
					 IN FILE_INFORMATION_CLASS  FileInformationClass
					 )
{
	SeeUser();
	DbgPrint("NewZwSetInformationFile\n");
	return OldZwSetInformationFile(FileHandle,IoStatusBlock,FileInformation,Length,FileInformationClass);
}

DEFZwSetInformationThread OldZwSetInfomationThread=NULL;
NTSTATUS 
NewZwSetInformationThread(
					   IN HANDLE  ThreadHandle,
					   IN THREADINFOCLASS  ThreadInformationClass,
					   IN PVOID  ThreadInformation,
					   IN ULONG  ThreadInformationLength
					   )
{
	SeeUser();
	DbgPrint("NewZwSetInformationThread\n");
	OldZwSetInfomationThread(ThreadHandle,ThreadInformationLength,ThreadInformation,ThreadInformationLength);
}

DEFZwSetInformationToken OldZwSetInformationToken=NULL;
NTSTATUS
NewZwSetInformationToken(
					  IN HANDLE  TokenHandle,
					  IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
					  IN PVOID  TokenInformation,
					  IN ULONG  TokenInformationLength
					  )
{
	SeeUser();
	DbgPrint("ZwSetInformationToken\n");
	return OldZwSetInformationToken(TokenHandle,TokenInformationClass,TokenInformation,TokenInformationLength);
}

/*Win7有效*/
DEFZwSetQuotaInformationFile OldZwSetQuotaInformationFile=NULL;
NTSTATUS
ZwSetQuotaInformationFile(
						  __in HANDLE  FileHandle,
						  __out PIO_STATUS_BLOCK  IoStatusBlock,
						  __in_bcount(Length) PVOID  Buffer,
						  __in ULONG  Length
						  )
{
	SeeUser();
	DbgPrint("ZwSetQuotaInformationFile\n");
	return OldZwSetQuotaInformationFile(FileHandle,IoStatusBlock,Buffer,Length);
}

/*>=Xp*/
DEFZwSetSecurityObject OldZwSetSecurityObject=NULL;
NTSTATUS
NewZwSetSecurityObject(
					IN HANDLE  Handle,
					IN SECURITY_INFORMATION  SecurityInformation,
					IN PSECURITY_DESCRIPTOR  SecurityDescriptor
					)
{
	SeeUser();
	DbgPrint("ZwSetSecurityObject\n");
	return OldZwSetSecurityObject(Handle,SecurityInformation,SecurityDescriptor);
}

DEFZwSetValueKey OldZwSetValueKey=NULL;
NTSTATUS 
NewZwSetValueKey(
			  IN HANDLE  KeyHandle,
			  IN PUNICODE_STRING  ValueName,
			  IN ULONG  TitleIndex  OPTIONAL,
			  IN ULONG  Type,
			  IN PVOID  Data,
			  IN ULONG  DataSize
			  )
{
	SeeUser();
	DbgPrint("ZwSetValueKey\n");
	OldZwSetValueKey(KeyHandle,ValueName,TitleIndex,Type,Data,DataSize);
}

/*>=2003*/
DEFZwSetVolumeInformationFile OldZwSetVolumeInformationFile=NULL;
NTSTATUS
NewZwSetVolumeInformationFile(
						   IN HANDLE  FileHandle,
						   OUT PIO_STATUS_BLOCK  IoStatusBlock,
						   IN PVOID  FsInformation,
						   IN ULONG  Length,
						   IN FS_INFORMATION_CLASS  FsInformationClass
						   )
{
	SeeUser();
	DbgPrint("ZwSetVolumeInformationFile\n");
	return OldZwSetVolumeInformationFile(FileHandle,IoStatusBlock,FsInformation,Length,FsInformationClass);
}

DEFZwTerminateProcess OldZwTerminateProcess=NULL;
NTSTATUS
NewZwTerminateProcess(
				   IN HANDLE  ProcessHandle,
				   IN NTSTATUS  ExitStatus
				   )
{
	SeeUser();
	DbgPrint("ZwTerminateProcess\n");
	return OldZwTerminateProcess(ProcessHandle,ExitStatus);
}

/*>=Xp*/
DEFZwUnloadDriver OldZwUnloadDriver=NULL;
NTSTATUS 
NewZwUnloadDriver(
			   IN PUNICODE_STRING  DriverServiceName
			   )
{
	SeeUser();
	DbgPrint("ZwUnloadDriver\n");
	OldZwUnloadDriver(DriverServiceName);
}

DEFZwUnmapViewOfSection OldZwUnmapViewOfSection=NULL;
NTSTATUS 
NewZwUnmapViewOfSection(
					 IN HANDLE  ProcessHandle,
					 IN PVOID  BaseAddress
					 )
{
	SeeUser();
	DbgPrint("ZwUnmapViewOfSection\n");
	OldZwUnmapViewOfSection(ProcessHandle,BaseAddress);
}

/*>=Xp*/
DEFZwWaitForSingleObject OldZwWaitForSingleObject=NULL;
NTSTATUS
NewZwWaitForSingleObject(
					  __in HANDLE  Handle,
					  __in BOOLEAN  Alertable,
					  __in_opt PLARGE_INTEGER  Timeout
					  )
{
	SeeUser();
	DbgPrint("ZwWaitForSingleObject\n");
	OldZwWaitForSingleObject(Handle,Alertable,Timeout);
}
DEFZwWriteFile OldZwWriteFile=NULL;
NTSTATUS 
NewZwWriteFile(
			IN HANDLE  FileHandle,
			IN HANDLE  Event  OPTIONAL,
			IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL,
			IN PVOID  ApcContext  OPTIONAL,
			OUT PIO_STATUS_BLOCK  IoStatusBlock,
			IN PVOID  Buffer,
			IN ULONG  Length,
			IN PLARGE_INTEGER  ByteOffset  OPTIONAL,
			IN PULONG  Key  OPTIONAL
			)
{
	SeeUser();
	DbgPrint("ZwWriteFile\n");
	OldZwWriteFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,Buffer,Length,ByteOffset,Key);
}



INT MDLinitED= FALSE;

NTSTATUS initMDL()
{
	g_pmdlSystemCall= MmCreateMdl(NULL, KeServiceDescriptorTable.pvSSDTBase, KeServiceDescriptorTable.ulNumberOfServices*4);
	if(!g_pmdlSystemCall)
	{
		return STATUS_UNSUCCESSFUL;
	}

	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);

	g_pmdlSystemCall->MdlFlags= g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;
	MappedSystemCallTable= MmMapLockedPages(g_pmdlSystemCall, KernelMode);

	MDLinitED= TRUE;
	
	return STATUS_SUCCESS;
}

NTSTATUS Dispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION StackLocation= IoGetCurrentIrpStackLocation(Irp);
	ULONG IoControlCode;
	NTSTATUS ntstatus;

	ntstatus= Irp->IoStatus.Status= STATUS_SUCCESS;
	Irp->IoStatus.Information= 0;

	IoControlCode= StackLocation->Parameters.DeviceIoControl.IoControlCode;

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

	MDLinitED= FALSE;

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

	DriverObject->DriverUnload= Unload;

	RtlInitUnicodeString(&DeviceName, DEVICE);
	RtlInitUnicodeString(&LinkName, DOSDEVICE);

	ntstatus= IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &MSkillSys);

	if(!NT_SUCCESS(ntstatus)){
		DbgPrint("create device failed\n");
		return ntstatus;
	}else{
		DbgPrint("create device..\n");
	}

	ntstatus= IoCreateSymbolicLink(&LinkName, &DeviceName);
	if(!NT_SUCCESS(ntstatus)){
		IoDeleteDevice(MSkillSys);
		DbgPrint("create symbolic link failed\n");
		return ntstatus;
	}else{
		DbgPrint("create symbolic link..\n");
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE]= Dispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]= Dispatch;
	DriverObject->MajorFunction[IRP_MJ_READ]= Dispatch;
	DriverObject->MajorFunction[IRP_MJ_WRITE]= Dispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]= Dispatch;

	DbgPrint("hook_create\n");
	if(!NT_SUCCESS(initMDL())){
		DbgPrint("initmdl faild\n");
		return ntstatus;
	}
	OldZwOpenProcess= (DEFZwOpenProcess)(SYSTEMSERVICE(ZwOpenProcess));

	__asm cli;
	HOOK_SYSCALL(ZwOpenProcess,NewZwOpenProcess,OldZwOpenProcess);
	__asm sti;
	DbgPrint("hook_create ok\n");

	return ntstatus;
}