#/bin/bash
Exit()
{
    echo -e "$1"
    exit $2
}

while true
do
    echo -n "Please input SpecialProxy server port: "
    read server_port
    [ "$server_port" -gt "0" -a "$server_port" -lt "65536" ] && break
    echo "Please input 1-65535."
done
echo -n "Please input SpecialProxy encode code(default is 0, no encode): "
read encodeCode
apt-get -y gcc make git || yum install -y gcc make git
git clone https://github.com/mmmdbybyd/SpecialProxy.git
[ ! -d SpecialProxy ] && Exit "\033[41;37mdownload SpecialProxy source code failed\033[0m"
cd SpecialProxy
make || Exit "\033[41;37mcompile tinyproxy failed\033[0m"
dnsip=`grep nameserver /etc/resolv.conf | grep -Eo '[1-9]{1,3}[0-9]{0,2}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1`
./SpecialProxy -l $server_port -p Meng -d ${dnsip:-114.114.114.114} -e ${encodeCode:-0} && \
Exit "\033[32mSpeciaoProxy is running.\033[0m" || \
Exit "\033[41;37mSpeciaoProxy is stopping.\033[0m"
