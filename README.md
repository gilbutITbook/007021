# <모던 리눅스 관리> 명령 모음

## 1장 리눅스의 기본
- `ls -lh /var/log /var/log/` 디렉터리에 있는 내용을 사람이 읽기 좋은 형태로 보여준다.
- `cd` 사용자 홈 디렉터리로 이동한다.
- `cp file1 newdir` file1 파일을 newdir 디렉터리에 복사한다.
- `mv file? /some/other/directory/` 파일명이 file이거나 file 뒤에 문자가 하나 더 있는 파일 모두를 대상 디렉터리로 이동한다.
- `rm -r *` 현재 디렉터리의 파일과 하위 디렉터리 모두를 삭제한다. 사용할 때 주의해야 한다.
- `man sudo sudo` 명령 사용에 관련된 매뉴얼 문서를 보여준다.

## 2장 리눅스 가상화: 리눅스 작업 환경 구축하기
- `apt install virtualbox` APT로 원격 저장소에서 버추얼박스 소프트웨어 패키지를 가져와 설치한다.
- `dpkg -i skypeforlinux-64.deb` 내려받은 데비안 패키지를 우분투/데비안 컴퓨터에 직접 설치한다.
- `wget https://example.com/document-to-download` 명령줄 프로그램인 wget으로 파일을 내려받는다.
- `dnf update, yum update, apt update` 로컬에 저장된 소프트웨어 인덱스를 온라인 저장소와 동기화한다.
- `shasum ubuntu-16.04.2-server-amd64.iso` 내려받은 파일의 체크섬을 계산한다. 계산한 값과 제공된 값을 비교해 두 값이 같으면 파일이 전송 중에 변경되거나 손상되지 않았음을 의미한다.
- `vboxmanage clone vmKali-Linux-template --name newkali` vboxmanage로 기존 VM을
복제한다.
- `lxc-start -d -n myContainer` 기존 LXC 컨테이너를 실행한다.
- `ip addr` 컴퓨터에 있는 각 네트워크 인터페이스에 대한 정보를I P 주소와 함께 출력한다.
-`exit` 컨테이너에서 이 명령으로 빠져나가면 컨테이너를 종료하지 않고 셸 세션만 종료한다.

## 3장 원격 연결: 네트워크에 연결된 서버에 안전하게 접근하기
- `dpkg -s openssh-client` APT 기반의 소프트웨어 패키지 상태를 검사한다.
- `systemctl status ssh` 시스템 프로세스(systemd)의 상태를 검사한다.
- `systemctl start ssh` 서비스를 시작한다.
- `ip addr` 컴퓨터에 있는 네트워크 인터페이스를 모두 나열한다.
- `ssh-keygen` SSH 키 쌍을 새로 생성한다.
- `cat .ssh/id_rsa.pub | ssh ubuntu@10.0.3.142 "cat >> .ssh/authorized_keys"` 원격 컴퓨터에 로컬 컴퓨터의 SSH 공개 키를 복사해 추가한다.
- `ssh-copy-id -i .ssh/id_rsa.pub ubuntu@10.0.3.142` 암호화 키를 안전하게 복사한다(권장 표준).
- `ssh -i .ssh/mykey.pemubuntu@10.0.3.142` 세션에 사용할 키 쌍을 지정한다.
- `scp myfile ubuntu@10.0.3.142:/home/ubuntu/myfile` 로컬 파일을 원격 컴퓨터에 안전하게 복사한다.
- `ssh -X ubuntu@10.0.3.142` 그래픽이 활성화된 세션을 열어 원격 컴퓨터에 로그인한다.
- `ps -ef | grep init` 현재 실행 중인 프로세스를 모두 나열한 후i nit 문자열을 담은 줄만 출력한다.
- `pstree -p` 현재 실행되는 모든 시스템 프로세스를 트리 모양으로 시각화해 출력한다.

## 4장 아카이브 관리: 전체 파일 시스템 백업 및 복사하기
- `df -h` 현재 활성화된 파티션을 사람이 읽기 쉬운 형식으로 보여준다.
- `tar czvf archivename.tar.gz /home/myuser/Videos/*.mp4` 특정 디렉터리에 있는 비디오 파일들의 압축된 아카이브를 생성한다.
- `split -b 1G archivename.tar.gz archivename.tar.gz.part` 큰 파일을 지정한 크기의 작은 파일 여러 개로 분할한다.
- `find /var/www/ -iname "*.mp4" -exec tar -rvf videos.tar {} \;` 지정한 기준에 맞는 파일들을 찾아 tar 명령에 전달해 아카이브에 추가한다.
- `chmod o-r /bin/zcat` 나머지 사용자의 읽기 권한을 제거한다.
- `dd if=/dev/sda2 of=/home/username/partition2.img` sda2 파티션의 이미지를 생성해 홈디렉터리에 저장한다.
- `dd if=/dev/urandom of=/dev/sda1` 파티션을 무작위 글자로 덮어써 이전 데이터를 알아볼수 없게 한다.

## 5장 관리 자동화: 자동화된 원격 사이트 백업 설정하기
- `#!/bin/bash`(‘#!’를 ‘쉬뱅’이라고 부른다) 어느 셸 인터프리터를 이용해 스크립트를 실행할지 리눅스에 알려준다.
- `이중 파이프(||)` 스크립트에서 '만약 실패하면'으로 해석된다. 따라서 왼쪽 명령이 만약 실패하면 오른쪽 명령이 실행된다.
- `이중 앰퍼샌드(&&)` 스크립트에서 '만약 성공하면'으로 해석된다. 따라서 왼쪽 명령이 성공하면 오른쪽 명령이 실행된다.
- `test -f /etc/filename` 지정한 파일이나 디렉터리가 존재하는지 검사한다.
- `chmod +x upgrade.sh` 스크립트 파일을 실행할 수 있게 권한을 부여한다.
- `pip3 install --upgrade --user awscli` 파이썬 pip 패키지 관리자로 AWS 명령줄 인터페이스를 설치한다.
- `aws s3 sync /home/username/dir2backup s3://linux-bucket3040` 로컬 디렉터리와 AWS S3 버킷을 동기화한다.
- `21 5 * * 1 root apt update && apt upgrade` 매주 월요일 아침 5시 21분에 apt 명령 두 개를 실행한다.
- `NOW=$(date +"%m_%d_%Y")` 스크립트에 이 코드가 있으면 현재 날짜를 변수에 할당한다.
- `systemctl start site-backup.timer` systemd 타이머를 활성화하는 명령이다.

## 6장 응급 도구: 시스템 복구 장치 구축하기
- `sha256sum systemrescuecd-x86-5.0.2.iso` ISO 파일의 SHA256 체크섬을 계산한다.
- `isohybrid systemrescuecd-x86-5.0.2.iso` USB에 맞는 MBR을 라이브 부트 이미지에 추가한다.
- `dd bs=4M if=systemrescuecd-x86-5.0.2.iso of=/dev/sdb && sync` 라이브 부트 이미지를 드라이브에 복사한다.
- `mount /dev/sdc1 /run/temp-directory` 파일 시스템의 디렉터리에 파티션을 마운트한다.
- `ddrescue -d /dev/sdc1 /run/usb-mount/sdc1-backup.img /run/usb-mount/sdc1-backup.logfile` 손상된 파티션에 있는 파일들을 sdc1-backup.img라는 이미지 파일에 저장하고, 이벤트들을 로그 파일에 저장한다.
- `chroot /run/mountdir/` 파일 시스템에서 루트 셸을 연다.

## 7장 웹 서버: 미디어위키 서버 구축하기
- `apt install lamp-server^` 우분투 컴퓨터에서 LAMP 서버에 필요한 모든 요소를 설치한다(메타패키지).
- `systemctl enable httpd CentOS` 시스템이 부팅될 때마다 아파치가 자동으로 실행된다.
- `firewall-cmd --add-service=http --permanent CentOS` 시스템으로 들어오는 HTTP 요청을 허용하는 방화벽 규칙을 추가한다.
- `mysql_secure_installation` 데이터베이스의 루트 패스워드를 재설정하고 보안을 강화
한다.
- `mysql -u root -p` MySQL이나 MariaDB에 루트 사용자로 로그인한다.
- `CREATE DATABASE newdbname;` MySQL이나 MariaDB에 데이터베이스를 새로 생성한다.
- `yum search php- | grep mysql` CentOS 온라인 저장소에서 MySQL과 관련된 PHP 모듈을 검색한다.
- `apt search mbstring` 멀티바이트 문자열 인코딩에 관련된 패키지를 검색한다.

## 8장 네트워크 파일 공유: Nextcloud로 파일 공유 서버 구축하기
- `a2enmod rewrite` 재저장 모듈을 활성화해 클라이언트와 서버가 통신 중일 때 아파치가U RL을 편집할 수 있다.
- `nano /etc/apache2/sites-available/nextcloud.conf Nextcloud` 환경 설정 파일을 생성하거나 편집할 수 있다.
- `chown -R www-data:www-data /var/www/nextcloud/` 모든 웹 사이트 파일의 소유자와 그룹을 www-data로 변경한다.
- `sudo -u www-data php occ list Nextcloud` CLI에서 사용할 수 있는 명령을 모두 나열한다.
- `aws s3 ls s3://nextcloud32327` S3 버킷에 있는 내용을 모두 나열한다.

## 9장 웹 서버 보안 강화하기
- `firewall-cmd --permanent --add-port=80/tcp` 80번 포트로 들어오는 HTTP 트래픽을 허용하며 부팅 때마다 로드한다.
- `firewall-cmd --list-services` 현재 firewalld 시스템에서 활성화된 규칙들을 나열한다.
- `ufw allow ssh` 우분투에서 UFW를 이용해 22번 포트로 들어오는 SSH 트래픽을 허용한다.
- `ufw delete 2 ufw status` 명령으로 나열된 규칙 중 두 번째 규칙을 삭제한다.
- `ssh -p53987<사용자 계정>@<서버 IP 주소 또는 도메인명>` 비표준 포트를 이용해 SSH 세션에 로그인한다.
- `certbot --apache 렛츠 인크립트(Let’s Encrypt)` 인증서를 사용하게 아파치 웹 서버를 설정한다.
- `selinux-activate` 우분투 컴퓨터에서 SELinux를 활성화한다.
- `setenforce 1` SELinux가 정책을 집행하게 한다.
- `ls -Z /var/www/html/` 지정한 디렉터리에 들어 있는 파일들의 보안 컨텍스트를 출력한다.
- `usermod -aG app-data-group otheruser otheruser` 사용자를 app-data-group 그룹에 추가한다.
- `netstat -npl` 현재 서버에서 열려 있는 네트워크 포트들을 나열한다.

## 10장 네트워크 연결: VPN과 DMZ로 보안 강화하기
- `hostname OpenVPN-Server` 어느 서버에 로그인하는지 명령 프롬프트로 쉽게 확인할 수 있다.
- `cp -r /usr/share/easy-rsa/ /etc/openvpn` easy-rsa 스크립트와 환경 설정 파일을
OpenVPN 환경 설정 디렉터리로 복사한다.
- `./build-key-server server` server라는 이름의 RSA 키 쌍을 생성한다.
- `./pkitool client` 공개 키 기반 구조에서 사용할 클라이언트 키 집합을 생성한다.
- `openvpn --tls-client --config /etc/openvpn/client.conf client.conf 파일에 설정된 내용을 이용해 OpenVPN 리눅스 클라이언트를 실행한다.
- `iptables -A FORWARD -i eth1 -o eth2 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT` eth1과 eth2 네트워크 인터페이스 간의 데이터 전송을 허용한다.
- `man shorewall-rules` Shorewall이 사용하는 rules 파일을 보여준다.
- `systemctl start shorewall` Shorewall 방화벽 서비스를 실행한다.
- `vboxmanage natnetwork add --netname dmz --network "10.0.1.0/24" --enable --dhcp on` 버추얼박스 CLI를 이용해 DHCP 서비스를 제공하는 가상 NAT 네트워크를 버추얼박스 VM에 추가한다.
- `vboxmanage natnetwork start --netname` dmz 가상 NAT 네트워크를 가동하게 한다.
- `dhclient enp0s3 enp0s3` 인터페이스가 연결된 네트워크의 IP 주소를 DHCP 서버에서 가져온다.

## 11장 시스템 모니터링: 로그 파일 이용하기
- `Alt + Fn` 텍스트 환경의 셸에서 가상 콘솔을 열 수 있다.
- `journalctl -n 20` 저널에서 최근 로그 항목 20개를 출력한다.
- `journalctl --since 15:50:00 --until 15:52:00` since에서 until까지의 이벤트만 출력한다.
- `systemd-tmpfiles --create --prefix /var/log/journal` 시스템을 부팅할 때마다 저널이 지워지지 않도록 영구 저장소에 보관하게 한다.
- `cat /var/log/auth.log | grep -B 1 -A 1 failure` 로그에서 failure가 기록된 로그 항목과 그 앞뒤 항목을 하나씩 출력하게 한다.
- `cat /var/log/mysql/error.log | awk '$3 ~/[Warning]/' | wc` MySQL 오류 로그에서
Warning으로 분류된 항목의 개수를 보여준다.
- `sed "s/^[0-9]//g" numbers.txt` 텍스트 파일에서 각 줄의 앞에 나오는 숫자를 제거한다.
- `tripwire --init` 트립와이어의 데이터베이스를 초기화한다.
- `twadmin --create-cfgfile --site-keyfile site.key twcfg.txt` 트립와이어용으로 암호화된 tw.cfg 설정 파일을 새로 생성한다.

## 12장 사설 네트워크에서 데이터 공유하기
- `/home 192.168.1.11(rw,sync)` 원격 클라이언트에 공유할 리소스를 정의한다(NFS 서버의 /etc/exports 파일에 있는 항목).
- `firewall-cmd --add-service=nfs` CentOS에서 NFS 클라이언트의 공유 접근을 허용하도록 방화벽을 설정한다.
- `192.168.1.23:/home /nfs/home nfs` 부팅할 때 NFS 공유 리소스를 마운트한다(NFS 클라이언트의 /etc/fstab 파일에 들어 있는 전형적인 항목)
- `smbpasswd -a sambauser` 기존 사용자 계정에 삼바 기능과 패스워드를 추가한다.
- `nano /etc/samba/smb.conf` 삼바 서버를 설정한다.
- `smbclient //localhost/sharehome` 로컬 삼바 서버에 접속한다.
- `ln -s /nfs/home/ /home/username/Desktop/` 데스크톱 아이콘을 더블 클릭해 NFS 공유 리소스에 접속할 수 있도록 바탕화면에 심볼릭 링크를 만든다.

## 13장 시스템 성능 문제 해결하기
- `uptime` 1, 5, 15분 동안 평균 CPU 부하를 보여준다.
- `cat /proc/cpuinfo | grep processor` CPU 개수를 반환한다.
- `top` 실행 중인 프로세스들의 상태를 실시간으로 보여준다.
- `killall yes` yes 명령으로 실행된 프로세스를 모두 종료한다.
- `nice --15 /var/scripts/mybackup.sh` mybackup.sh가 시스템 리소스를 사용하는 우선순위를 높인다.
- `free -h` 전체 램과 가용한 램의 크기를 보여준다.
- `df -i` 각 파일 시스템의 전체 inode와 가용한 inode를 보여준다.
- `find . -xdev -type f | cut -d "/" -f 2 | sort | uniq -c | sort -n` 현재 디렉터리에서 하위 디렉터리별로 저장된 파일의 개수를 보여준다.
- `apt autoremove` 사용되지 않는 예전 커널 헤더들을 제거한다.
- `nethogs eth0 eth0` 인터페이스를 통해 네트워크에 연결된 프로세스와 전송 데이터를 보여준다.
- `tc qdisc add dev eth0 root netem delay 100ms eth0` 인터페이스를 통해 전송되는 트래픽을 100밀리초 지연한다.
- `nmon -f -s 30 -c 120` nmon이 30초 단위로 1시간 동안 조사한 일련의 데이터를 파일에 저장한다.

## 14장 네트워크 문제 해결하기
- `ip addr` 명령은 리눅스 시스템에서 활성화된 인터페이스들을 나열한다. 짧게는 ip a, 길게 는 ip address로 사용할 수 있다.
- `lspci` 컴퓨터에 연결된 PCI 장치들을 나열한다.
- `dmesg | grep -A 2 Ethernet` dmesg 로그에서 Ethernet 단어가 나온 부분을 검색하고 찾아낸 로그와 바로 다음 로그 두 줄을 더 출력한다.
- `ip route add default via 192.168.1.1 dev eth0` 인터페이스에 네트워크 라우트를 수작업으로 지정한다.
- `dhclient enp0s3` DHCP를 통해 enp0s3 인터페이스에 동적 IP 주소를 요청한다.
- `ip addr add 192.168.1.10/24 dev eth0` eth0 인터페이스에 정적 IP 주소를 할당하지만 재부팅하면 이 설정은 사라진다.
- `ip link set dev enp0s3 up enp0s3` 인터페이스를 활성화하는데, 설정 파일을 변경한 후에 사용하면 새로운 설정이 적용된다.
- `netstat -l | grep http` 컴퓨터를 검사해 80번 포트를 듣고 있는 웹 서비스를 찾아낸다.
- `nc -z -v bootstrap-it.com 443 80` 원격 서버에서 443번과 80번 포트를 듣고 있는 서비스 를 검사한다.

## 15장 주변 장치 문제 해결하기
- `lshw -c memory(또는 lshw -class memory)` 시스템의 하드웨어 프로파일 중 메모리 항목을
보여준다.
- `ls /lib/modules/`uname -r`` /lib/modules/ 디렉터리 아래에 있는 현재 활성화된 커널의 모듈을 모두 나열한다.
- `lsmod` 활성화된 모듈을 모두 나열한다.
- `modprobe -c` 사용할 수 있는 모듈을 모두 나열한다.
- `find /lib/modules/$(uname -r) -type f -name ath9k*` 사용할 수 있는 커널 모듈 중 이름이 ath9k로 시작하는 파일을 모두 찾는다.
- `modprobe ath9k` 지정한 모듈을 커널에 로드한다.
- `GRUB_CMDLINE_LINUX_DEFAULT="systemd.unit=runlevel3.target"` /etc/default/grub 파일에 설정하면 다중 사용자, 텍스트 모드로 리눅스를 로드한다.
- `lp -H 11:30 -d Brother-DCP-7060D /home/user/myfile.pdf` UTC 시각으로 11시 30분에 브라더 프린터에서 인쇄하도록 작업을 스케줄링한다.

## 16장 데브옵스 도구: 앤서블로 서버 환경 배치하기
- `add-apt-repository ppa:ansible/ansible` 우분투/데비안 컴퓨터에 앤서블을 설치할 수 있게 앤서블 소프트웨어 저장소를 추가한다.
- `ansible webservers -m ping webservers` 호스트 그룹에 있는 모든 호스트의 네트워크 연결을 테스트한다.
- `ansible webservers -m copy -a "src=/home/ubuntu/stuff.html dest=/var/www/html/"` webservers 그룹에 있는 모든 호스트의 지정 위치에 로컬 파일을 복사한다.
- `ansible-doc apt` apt 모듈에 대한 구문과 사용법을 보여준다.
- `ansible-playbook site.yml` site.yml 플레이북을 기반으로 작업을 실행한다.
- `ansible-playbook site.yml --ask-vault-pass` 볼트 패스워드로 호스트에 인증하고 플레이북 작업을 실행한다
