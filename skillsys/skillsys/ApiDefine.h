#pragma once
#include <ntddk.h>

typedef NTSTATUS  (*ZWALLOCATELOCALLYUNIQUEID)( OUT PLUID  LUID );

typedef NTSTATUS 
(*ZWALLOCATEVIRTUALMEMORY)(
						   __in HANDLE  ProcessHandle,
						   __inout PVOID  *BaseAddress,
						   __in ULONG_PTR  ZeroBits,
						   __inout PSIZE_T  RegionSize,
						   __in ULONG  AllocationType,
						   __in ULONG  Protect
						   ); 

typedef NTSTATUS (*ZWCLOSE)( IN HANDLE  Handle);

typedef NTSTATUS
(*ZWCOMMITCOMPLETE)(
					__in HANDLE  EnlistmentHandle,
					__in_opt PLARGE_INTEGER  TmVirtualClock
					);

typedef NTSTATUS
(*ZWCOMMITENLISTMENT) (
					   __in HANDLE  EnlistmentHandle,
					   __in_opt PLARGE_INTEGER  TmVirtualClock
					   );

typedef NTSTATUS 
(*ZWCOMMITTRANSACTION)(
					   IN PHANDLE  TransactionHandle,
					   IN BOOLEAN  Wait
					   );

typedef NTSTATUS 
(*ZWCREATEDIRECTORYOBJECT)(
						   OUT PHANDLE  DirectoryHandle,
						   IN ACCESS_MASK  DesiredAccess,
						   IN POBJECT_ATTRIBUTES  ObjectAttributes
						   );

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

typedef NTSTATUS
(*ZWCREATEEVENT)(
				 OUT PHANDLE  EventHandle,
				 IN ACCESS_MASK  DesiredAccess,
				 IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
				 IN EVENT_TYPE  EventType,
				 IN BOOLEAN  InitialState
				 );


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

typedef NTSTATUS
(*DEFZwCreateTransactionManager)(
								 __out PHANDLE  TmHandle,
								 __in ACCESS_MASK  DesiredAccess,
								 __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
								 __in_opt PUNICODE_STRING  LogFileName,
								 __in_opt ULONG  CreateOptions,
								 __in_opt ULONG  CommitStrength
								 );


typedef NTSTATUS
(*DEFZwDeleteFile)(
				   IN POBJECT_ATTRIBUTES  ObjectAttributes
				   );


typedef NTSTATUS 
(*DEFZwDeleteKey)(
				  IN HANDLE  KeyHandle
				  );

typedef NTSTATUS 
(*DEFZwDeleteValueKey)(
					   IN HANDLE  KeyHandle,
					   IN PUNICODE_STRING  ValueName
					   );

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

typedef NTSTATUS 
(*DEFZwEnumerateKey)(
					 IN HANDLE  KeyHandle,
					 IN ULONG  Index,
					 IN KEY_INFORMATION_CLASS  KeyInformationClass,
					 OUT PVOID  KeyInformation,
					 IN ULONG  Length,
					 OUT PULONG  ResultLength
					 );

typedef NTSTATUS 
(*DEFZwEnumerateTransactionObject) (
									__in_opt HANDLE  RootObjectHandle,
									__in KTMOBJECT_TYPE  QueryType,
									__inout PKTMOBJECT_CURSOR  ObjectCursor,
									__in ULONG  ObjectCursorLength,
									__out PULONG  ReturnLength
									);

typedef NTSTATUS
(*DEFZwEnumerateValueKey)(
						  IN HANDLE  KeyHandle,
						  IN ULONG  Index,
						  IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
						  OUT PVOID  KeyValueInformation,
						  IN ULONG  Length,
						  OUT PULONG  ResultLength
						  );

typedef NTSTATUS
  (*DEFZwFlushBuffersFile)(
    IN HANDLE  FileHandle,
    IN PIO_STATUS_BLOCK  IoStatusBlock
    ); 

typedef NTSTATUS 
  (*DEFZwFlushKey)(
    IN HANDLE  KeyHandle
    );

typedef NTSTATUS 
  (*DEFZwFlushVirtualMemory)(
    IN HANDLE  ProcessHandle,
    IN OUT PVOID  *BaseAddress,
    IN OUT PSIZE_T  RegionSize,
    OUT PIO_STATUS_BLOCK  IoStatus 
    ); 

typedef NTSTATUS 
  (*DEFZwFreeVirtualMemory)(
    __in HANDLE  ProcessHandle,
    __inout PVOID  *BaseAddress,
    __inout PSIZE_T  RegionSize,
    __in ULONG  FreeType
    ); 

typedef NTSTATUS
  (*DEFZwFsControlFile)(
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
    ); 

typedef NTSTATUS
  (*DEFZwGetNotificationResourceManager) (
    __in HANDLE  ResourceManagerHandle,
    __out PTRANSACTION_NOTIFICATION  TransactionNotification,
    __in ULONG  NotificationLength,
    __in PLARGE_INTEGER  Timeout,
    __out_opt PULONG  ReturnLength,
    __in ULONG  Asynchronous,
    __in_opt ULONG_PTR  AsynchronousContext
    );

typedef NTSTATUS 
  (*DEFZwLoadDriver)(
    IN PUNICODE_STRING  DriverServiceName
    );

typedef NTSTATUS 
  (*DEFZwLockFile)(
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
    );

typedef NTSTATUS 
  (*DEFZwMakeTemporaryObject)(
    IN HANDLE  Handle
    );

typedef NTSTATUS 
  (*DEFZwMapViewOfSection)(
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
    );

typedef NTSTATUS
  (*DEFZwNotifyChangeKey)(
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
    );

typedef NTSTATUS
  (*DEFZwOpenDirectoryObject)(
    __out PHANDLE  DirectoryHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS
  (*DEFZwOpenEnlistment) (
    __out PHANDLE  EnlistmentHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  RmHandle,
    __in LPGUID  EnlistmentGuid,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS 
  (*DEFZwOpenEvent)(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS
  (*DEFZwOpenFile)(
    OUT PHANDLE  FileHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  ShareAccess,
    IN ULONG  OpenOptions
    );

typedef NTSTATUS 
  (*DEFZwOpenKey)(
    OUT PHANDLE  KeyHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS
  (*DEFZwOpenKeyEx)(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in ULONG  OpenOptions
    );

typedef NTSTATUS
  (*DEFZwOpenKeyTransacted)(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in HANDLE  TransactionHandle
    );

typedef NTSTATUS
  (*DEFZwOpenKeyTransactedEx)(
    __out PHANDLE  KeyHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in ULONG  OpenOptions,
    __in HANDLE  TransactionHandle
    );

typedef NTSTATUS (*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle,
								  IN ACCESS_MASK DesiredAccess,
								  IN POBJECT_ATTRIBUTES ObjectAttributes,
								  IN PCLIENT_ID ClientId OPTIONAL);

typedef NTSTATUS
  (*DEFZwOpenProcessTokenEx)(
    IN HANDLE  ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN ULONG  HandleAttributes,
    OUT PHANDLE  TokenHandle
    );

typedef NTSTATUS
  (*DEFZwOpenResourceManager) (
    __out PHANDLE  ResourceManagerHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in HANDLE  TmHandle,
    __in LPGUID  ResourceManagerGuid,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS 
  (*DEFZwOpenSection)(
    OUT PHANDLE  SectionHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS
  (*DEFZwOpenSymbolicLinkObject)(
    OUT PHANDLE  LinkHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

typedef NTSTATUS
  (*DEFZwOpenThreadTokenEx)(
    IN HANDLE  ThreadHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN BOOLEAN  OpenAsSelf,
    IN ULONG  HandleAttributes,
    OUT PHANDLE  TokenHandle
    );

typedef NTSTATUS
  (*DEFZwOpenTransaction) (
    __out PHANDLE  TransactionHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in LPGUID  Uow,
    __in_opt HANDLE  TmHandle
    );

typedef NTSTATUS
  (*DEFZwOpenTransactionManager)(
    __out PHANDLE  TmHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PUNICODE_STRING  LogFileName,
    __in_opt LPGUID  TmIdentity,
    __in_opt ULONG  OpenOptions
    );

typedef NTSTATUS
  (*DEFZwPrepareComplete) (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    );

typedef NTSTATUS
  (*DEFZwPrepareEnlistment) (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    );

typedef NTSTATUS
  (*DEFZwPrePrepareComplete) (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    );

typedef NTSTATUS
  (*DEFZwPrePrepareEnlistment) (
    __in HANDLE  EnlistmentHandle,
    __in_opt PLARGE_INTEGER  TmVirtualClock
    );

typedef NTSTATUS 
  (*DEFZwQueryDirectoryFile)(
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
    );

typedef NTSTATUS
  (*DEFZwQueryFullAttributesFile)(
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION  FileInformation
    );

typedef NTSTATUS
  (*DEFZwQueryInformationEnlistment) (
    __in HANDLE  EnlistmentHandle,
    __in ENLISTMENT_INFORMATION_CLASS  EnlistmentInformationClass,
    __out PVOID  EnlistmentInformation,
    __in ULONG  EnlistmentInformationLength,
    __out_opt PULONG  ReturnLength
    );

typedef NTSTATUS 
  (*DEFZwQueryInformationFile)(
    IN HANDLE  FileHandle,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  FileInformation,
    IN ULONG  Length,
    IN FILE_INFORMATION_CLASS  FileInformationClass
    );

typedef NTSTATUS
  (*DEFZwQueryInformationResourceManager) (
    __in HANDLE  ResourceManagerHandle,
    __in RESOURCEMANAGER_INFORMATION_CLASS  ResourceManagerInformationClass,
    __out PVOID  ResourceManagerInformation,
    __in ULONG  ResourceManagerInformationLength,
    __out_opt PULONG  ReturnLength
    );

typedef enum _TOKEN_INFORMATION_CLASS {
  TokenUser = 1,
  TokenGroups,
  TokenPrivileges,
  TokenOwner,
  TokenPrimaryGroup,
  TokenDefaultDacl,
  TokenSource,
  TokenType,
  TokenImpersonationLevel,
  TokenStatistics,
  TokenRestrictedSids,
  TokenSessionId,
  TokenGroupsAndPrivileges,
  TokenSessionReference,
  TokenSandBoxInert,
  TokenAuditPolicy,
  TokenOrigin
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

typedef NTSTATUS
  (*DEFZwQueryInformationToken)(
    IN HANDLE  TokenHandle,
    IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
    OUT PVOID  TokenInformation,
    IN ULONG  TokenInformationLength,
    OUT PULONG  ReturnLength
    ); 

typedef NTSTATUS
  (*DEFZwQueryInformationTransaction) (
    __in HANDLE  TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS  TransactionInformationClass,
    __out PVOID  TransactionInformation,
    __in ULONG  TransactionInformationLength,
    __out_opt PULONG  ReturnLength
    );

typedef NTSTATUS
  (*DEFZwQueryInformationTransactionManager)(
    __in HANDLE  TransactionManagerHandle,
    __in TRANSACTIONMANAGER_INFORMATION_CLASS  TransactionManagerInformationClass,
    __out PVOID  TransactionManagerInformation,
    __in ULONG  TransactionManagerInformationLength,
    __out_opt PULONG  ReturnLength
    );

typedef NTSTATUS 
  (*DEFZwQueryKey)(
    IN HANDLE  KeyHandle,
    IN KEY_INFORMATION_CLASS  KeyInformationClass,
    OUT PVOID  KeyInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    );

typedef NTSTATUS
  (*DEFZwQueryObject)(
    __in_opt HANDLE  Handle,
    __in OBJECT_INFORMATION_CLASS  ObjectInformationClass,
    __out_bcount_opt(ObjectInformationLength) PVOID  ObjectInformation,
    __in ULONG  ObjectInformationLength,
    __out_opt PULONG  ReturnLength
    );

typedef NTSTATUS
  (*DEFZwQueryQuotaInformationFile)(
    __in HANDLE  FileHandle,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __out  PVOID Buffer,
    __in ULONG  Length,
    __in BOOLEAN  ReturnSingleEntry,
    __in_opt PVOID  SidList,
    __in ULONG  SidListLength,
    __in_opt PSID  StartSid OPTIONAL,
    __in BOOLEAN  RestartScan
);

typedef NTSTATUS
  (*DEFZwQuerySecurityObject)(
    IN HANDLE  Handle,
    IN SECURITY_INFORMATION  SecurityInformation,
    OUT PSECURITY_DESCRIPTOR  SecurityDescriptor,
    IN ULONG  Length,
    OUT PULONG  LengthNeeded
    ); 

typedef NTSTATUS
  (*DEFZwQuerySymbolicLinkObject)(
    IN HANDLE  LinkHandle,
    IN OUT PUNICODE_STRING  LinkTarget,
    OUT PULONG  ReturnedLength OPTIONAL
    );

typedef NTSTATUS 
  (*DEFZwQueryValueKey)(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName,
    IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
    OUT PVOID  KeyValueInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    );

typedef NTSTATUS
  (*DEFZwQueryVolumeInformationFile)(
    IN HANDLE  FileHandle,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  FsInformation,
    IN ULONG  Length,
    IN FS_INFORMATION_CLASS  FsInformationClass
    );
