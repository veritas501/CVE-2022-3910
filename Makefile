.PHONY: all

all: poc exp_dirtyfile exp_dirtymm
	
poc: poc.c
	gcc poc.c -o poc -static -no-pie -s -luring \
	    -L ./liburing/ -I ./liburing/include

exp_dirtyfile: exp_dirtyfile.c
	gcc exp_dirtyfile.c -o exp_dirtyfile -static -no-pie -s -luring -lpthread \
	    -L ./liburing/ -I ./liburing/include

exp_dirtymm: exp_dirtymm.c
	gcc exp_dirtymm.c -o exp_dirtymm -no-pie -static -s -luring -lpthread \
	    -L ./liburing/ -I ./liburing/include

suid_dummy: suid_dummy.c
	gcc suid_dummy.c -o suid_dummy -static -no-pie -s
