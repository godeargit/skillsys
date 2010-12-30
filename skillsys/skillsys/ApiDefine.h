#pragma once
#include <ntddk.h>

typedef NTSTATUS (*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle,
								  IN ACCESS_MASK DesiredAccess,
								  IN POBJECT_ATTRIBUTES ObjectAttributes,
								  IN PCLIENT_ID ClientId OPTIONAL);

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


