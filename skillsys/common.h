/**************************************************************************************
* AUTHOR : CoooLie
* DATE   : 2010-12-30
* MODULE : common.h
*
* Command: 
*	IOCTRL Common Header
*
* Description:
*	Common data for the IoCtrl driver and application
*
****************************************************************************************
* Copyright (C) 2010 CoooLie.
****************************************************************************************/

#pragma once 

//#######################################################################################
// D E F I N E S
//#######################################################################################

#if DBG
#define dprintf DbgPrint
#else
#define dprintf
#endif

//��֧�ַ��������û������
#define DEVICE_NAME                  L"\\Device\\devSsdtFak"             // Driver Name
#define SYMBOLIC_LINK_NAME           L"\\DosDevices\\SsdtFak"            // Symbolic Link Name
#define WIN32_LINK_NAME              "\\\\.\\SsdtFak"                    // Win32 Link Name

//֧�ַ��������û������
#define SYMBOLIC_LINK_GLOBAL_NAME    L"\\DosDevices\\Global\\SsdtFak"    // Symbolic Link Name

#define DATA_TO_APP                  "Hello World from Driver"

//
// Device IO Control Codes
//
#define IOCTL_BASE          0x800
#define MY_CTL_CODE(i)        \
    CTL_CODE                  \
    (                         \
        FILE_DEVICE_UNKNOWN,  \
        IOCTL_BASE + i,       \
        METHOD_BUFFERED,      \
        FILE_ANY_ACCESS       \
    )

#define IOCTL_HELLO_WORLD            MY_CTL_CODE(0)
#define IOCTRL_REC_FROM_APP          MY_CTL_CODE(1)
#define IOCTRL_SEND_TO_APP           MY_CTL_CODE(2)


//
// TODO: Add your IOCTL define here
//



//
// TODO: Add your struct,enum(public) define here
//



/* EOF */

