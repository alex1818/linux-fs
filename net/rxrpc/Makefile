#
# Makefile for Linux kernel RxRPC
#

af-rxrpc-y := \
	af_rxrpc.o \
	ar-accept.o \
	ar-ack.o \
	ar-call.o \
	ar-connection.o \
	ar-connevent.o \
	ar-input.o \
	ar-key.o \
	ar-output.o \
	ar-recvmsg.o \
	ar-security.o \
	ar-skbuff.o \
	ar-transport.o \
	local-event.o \
	local-object.o \
	objcache.o \
	peer-event.o \
	peer-object.o \
	utils.o

af-rxrpc-$(CONFIG_PROC_FS) += ar-proc.o
af-rxrpc-$(CONFIG_SYSCTL) += sysctl.o

obj-$(CONFIG_AF_RXRPC) += af-rxrpc.o

obj-$(CONFIG_RXKAD) += rxkad.o
