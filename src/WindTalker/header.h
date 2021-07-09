// defines
#define DEVICE_NAME "\\\\.\\wdnisdrv"
#define SET_FILTERING_STATE 0x226005
#define IP_EXCLU_CODE 0x226015
#define CONN_NOTIF_CODE 0x22A00E
#define INJECT_CODE	0x226011
#define BUFSIZE 4096
#define FWPS_LAYER_STREAM_V4 0x14
#define FWPS_LAYER_STREAM_V6 0x16
#define FWPS_LAYER_DATAGRAM_DATA_V4 0x18
#define FWPS_LAYER_DATAGRAM_DATA_V6 0x1A

//enum
enum INJECTION_MODE {STREAMV4, STREAMV6, OOB_READ};
enum STREAM_FLAGS { SEND, RECEIVE, S_NODELAY_R_PUSH, EXPEDITED = 4, DISCONNECT = 8};
#pragma pack( push, 1 )
// structs
typedef struct {
	unsigned long long unk1;
	unsigned long long FlowId;
	unsigned short layer_id;
	unsigned int callout_id;
	unsigned char stream_flags;
	unsigned char pad1[3];
	unsigned int stream_size;
} _INJECT_HEADER;

typedef struct {
	unsigned int unk_type;
	unsigned char unk_stream[0x94];
	unsigned int size_extra_stream;
	unsigned int unk1;
} _INJECT_DATAGRAM;

typedef struct {
	_INJECT_HEADER header;
	union {
		_INJECT_DATAGRAM datagram;
		unsigned char stream;
	} Type;
}_IRP_INJECT;

enum {
	FLOW_CLASSIFY, FLOW_DATA, NOTIF_ERROR, FLOW_DELETE
};

typedef	struct {
	unsigned long long FlowHandle;
	unsigned short Layer;
	unsigned int CalloutId;
	unsigned int IpProtocol;
	unsigned char FilterFlag;
	union {
		SOCKADDR_IN IPv4;
		SOCKADDR_IN6 IPv6;
		SOCKADDR_STORAGE_LH IPvX;
	} LocalAddress;
	union {
		SOCKADDR_IN IPv4;
		SOCKADDR_IN6 IPv6;
		SOCKADDR_STORAGE_LH IPvX;
	} RemoteAddress;
	unsigned int ProcessId;
	unsigned long long ProcessCreationTime;
	unsigned char IsProcessExcluded;
	unsigned int ProcessPathLength;
} _FLOW_NOTIFICATION;

typedef struct {
	unsigned long long PktExchanged;
	unsigned long long FlowHandle;
	unsigned short Layer;
	unsigned int CalloutId;
	unsigned short StreamFlags;
	unsigned short IsStreamOutbound;
	unsigned int StreamSize;
} _STREAM_DATA_NOTIFICATION;

typedef struct {
	unsigned int NotificationSize;
} _ERROR_NOTIFICATION;

typedef struct {
	unsigned long long FlowHandle;
} _FLOW_DELETE_NOTIFICATION;

typedef	struct {
	unsigned long long CreationTime;
	unsigned long long NotificationType;
} _CONNECTION_NOTIFICATION_HEADER;

typedef struct {
	_CONNECTION_NOTIFICATION_HEADER Header;
	union {
		_FLOW_NOTIFICATION FlowNotification;
		_STREAM_DATA_NOTIFICATION StreamDataNotification;
		_ERROR_NOTIFICATION ErrorNotification;
		_FLOW_DELETE_NOTIFICATION FlowDeleteNotification;
	};
} _CONNECTION_NOTIFICATION;
#pragma pack (pop)