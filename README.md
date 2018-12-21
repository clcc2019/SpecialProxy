SpecialProxy  
======  
用epoll多路复用io写的一个HTTP代理，轻快，自带DNS解析  
  
##### SpecialProxy有如下特性：  
    1.  普通HTTP代理通过请求头首行的host或者Host头域字段获得目标主机，  
        SpecialProxy不从首行获取目标主机，  
        它可以自定义代理头域（默认是Host）。  
  
    2.  普通HTTP代理SSL代理是判断CONNECT请求方法，  
        SpecialProxy可以通过自定义特定字符串进行SSL代理（默认是CONNECT）。  
  
    3.  普通HTTP代理如果遇到多个连续的HTTP请求头只重新拼接第一个请求头，  
        SpecialProxy可以开启严格模式（-a参数），对所以请求头都重新拼接。  
  
    4.  -L参数设置重定向到本地端口的头域，比如-L Local，  
    然后请求头中含有Local: 443，代理会将请求发送到127.0.0.1:443  
  
    5. -e设置数据编码的代码，
    对客户端uri Host Referer以及请求附带的数据编码，
    服务器的返回数据也编码
  
##### 启动参数：  
    -l [监听ip:]监听端口    默认监听IP为 "0.0.0.0"  
    -p 代理头域             默认为 "Host"  
    -L 本地代理头域         默认为 "Local"  
    -d DNS查询IP[:端口]     默认为 "114.114.114.114"  
    -s SSL代理字符串        默认为 "CONNECT"  
    -u 设置uid
    -a                      对所有HTTP请求重新拼接  
    -h 显示帮助  
    -w 工作进程数  
  
##### BUG：  
    待发现
  
##### 编译:  
~~~~~
Linux/Android:  
    make  
Android-ndk:  
    ndk-build  
~~~~~