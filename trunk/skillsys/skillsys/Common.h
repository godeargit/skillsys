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
//
// Device IO Control Codes
//
//#define IOCTL_BASE          0x800
//#define MY_CTL_CODE(i)        \
    CTL_CODE                  \
    (                         \
        FILE_DEVICE_UNKNOWN,  \
        IOCTL_BASE + i,       \
        METHOD_BUFFERED,      \
        FILE_ANY_ACCESS       \
    )

//#define IOCTL_HELLO_WORLD            MY_CTL_CODE(0)
//#define IOCTRL_REC_FROM_APP          MY_CTL_CODE(1)
//#define IOCTRL_SEND_TO_APP           MY_CTL_CODE(2)


//
// TODO: Add your IOCTL define here
//



//
// TODO: Add your struct,enum(public) define here
//



/* EOF */

