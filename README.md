ntp_flood
=========

ntp server performace testing tool 

# NTP SERVER PERFORMANCE TESTING TOOL

## 关于
ntp_flood 是一个运行在 Linux 平台的NTP服务器性能测试工具。

## 快速开始
下载源码：

    git clone https://github.com/kingcarl/ntp_flood/ntp_flood.git
    cd ntp_flood
    
编译源码：

    make
    
    
运行

    ./ntp_flood ntp_server_ip ips_list_filename is_linux ttl_begin/ttl_end sport_begin/sport_end ip_frag send_count send_pps repeat_num [debug] 
