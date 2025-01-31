#include "stdafx.h"
#include "CRC.h"

/*******************************************************************/
/*
  �� �� �� ��:	BuildTable16
  �� �� �� ����	����CRC16����Ҫ��Table
  �� �� ˵ ����	aPoly[in]:����������Ҫ�Ķ���ʽ
				Table_CRC[in][out]:Table���buff

  ����ֵ ˵����	void

  �� �� �� �ڣ�	2003.12.19
/*******************************************************************/
static void BuildTable16( unsigned short aPoly , unsigned long* Table_CRC )
{
    unsigned short i, j;
    unsigned short nData;
    unsigned short nAccum;

    for ( i = 0; i < 256; i++ )
    {
        nData = ( unsigned short )( i << 8 );
        nAccum = 0;
        for ( j = 0; j < 8; j++ )
        {
            if ( ( nData ^ nAccum ) & 0x8000 )
                nAccum = ( nAccum << 1 ) ^ aPoly;
            else
                nAccum <<= 1;
            nData <<= 1;
        }
        Table_CRC[i] = ( unsigned long )nAccum;
    }
}




/*******************************************************************/
/*
	�� �� �� ��:	BuildTable32
	�� �� �� ����	����CRC32����Ҫ��Table
	�� �� ˵ ����	aPoly[in]:����������Ҫ�Ķ���ʽ
					Table_CRC[in][out]:Table���buff

	  ����ֵ ˵����	void

/*******************************************************************/
static void BuildTable32( unsigned long aPoly , unsigned long* Table_CRC )
{
    unsigned long i, j;
    unsigned long nData;
    unsigned long nAccum;

    for ( i = 0; i < 256; i++ )
    {
        nData = ( unsigned long )( i << 24 );
        nAccum = 0;
        for ( j = 0; j < 8; j++ )
        {
            if ( ( nData ^ nAccum ) & 0x80000000 )
                nAccum = ( nAccum << 1 ) ^ aPoly;
            else
                nAccum <<= 1;
            nData <<= 1;
        }
        Table_CRC[i] = nAccum;
    }
}





/*******************************************************************/
/*
	�� �� �� ��:	RunCRC16
	�� �� �� ����	ִ�ж����ݶε�CRC16ѭ������У��
	�� �� ˵ ����	aData[in]:��У������
					aSize[in]:��У�����ݳ���
					aPoly[in]:����������Ҫ�Ķ���ʽ
					
	  ����ֵ ˵����	ѭ������У����

/*******************************************************************/
unsigned short CCRC::RunCRC16( const  char * aData, unsigned long aSize, unsigned short aPoly )
{
    unsigned long Table_CRC[256]; // CRC ��
    unsigned long  i;
    unsigned short nAccum = 0;

	BuildTable16( aPoly, Table_CRC );
    
    for ( i = 0; i < aSize; i++ )
        nAccum = ( nAccum << 8 ) ^ ( unsigned short )Table_CRC[( nAccum >> 8 ) ^ *aData++];
    return nAccum;
}





/*******************************************************************/
/*
	�� �� �� ��:	RunCRC32
	�� �� �� ����	ִ�ж����ݶε�CRC32ѭ������У��
	�� �� ˵ ����	aData[in]:��У������
					aSize[in]:��У�����ݳ���
					aPoly[in]:����������Ҫ�Ķ���ʽ
					
	  ����ֵ ˵����	ѭ������У����

/*******************************************************************/
unsigned long CCRC::RunCRC32( const  char * aData, unsigned long aSize, unsigned long aPoly )
{
    unsigned long Table_CRC[256]; // CRC ��
    unsigned long i;
    unsigned long nAccum = 0;

	BuildTable32( aPoly, Table_CRC );
    
    for ( i = 0; i < aSize; i++ )
        nAccum = ( nAccum << 8 ) ^ Table_CRC[( nAccum >> 24 ) ^ *aData++];
    return nAccum;
}
