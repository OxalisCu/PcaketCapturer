#pragma once
#include "Global.h"

typedef struct Msg_Item
{
	QString name;
	QString desc;
	int value;		// default value is -1
	u_int offset;		// bit
	u_int length;		// bit
	QVector<Msg_Item*> children;
}Msg_Item;

typedef struct Protocol_Msg
{
	QString name;
	u_int offset;		// byte
	u_int length;		// byte
	u_int total_length;		// byte
	QVector<Msg_Item*> items;
}Protocol_Msg;

typedef struct Frame_Msg
{
	u_short num;		// start from 1
	QDateTime time;
	QString src;
	QString des;
	QString	protocol;
	u_int length;		// byte
	QString info;
	u_int stream_index;
}Frame_Msg;

typedef struct Stream_Msg
{
	QString client_addr;
	QString server_addr;
	u_int client_port;
	u_int server_port;
	QVector<u_int> index;
}Stream_Msg;