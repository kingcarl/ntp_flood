# @author     carl guan (guanpeng06@baidu.com)
# @version    0.1
all:
	gcc -O ntp_flood.c -o ntp_flood -g -Wall
	
clean:
	rm -f ntp_flood