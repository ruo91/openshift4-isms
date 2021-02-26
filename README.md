
# OpenShift v4.x - ISMS 인증을 위한 보안 취약점 설정
ISMS(Information Security Management System)가 의무대상인 기업에서는 필수로 조치 되어야 한다.  
조치 가이드는 KISA에서 제공하는 **'주요정보통신기반시설 기술적 취약점 분석 평가 상세 가이드'** [(Link 1)](https://www.kisa.or.kr/public/laws/laws3_View.jsp?cPage=6&mode=view&p_No=259&b_No=259&d_No=106&ST=T&SV=)를 통해 설정 한다.

해당 가이드가 현재 기준으로 2017년 12월 일자가 마지막이라 수정해야 할 부분이 많지만 어쩔수 없다.

고객사 마다 설정 값들에 대한 정책이 다를수 있으며, 자주 사용하는 부분에 대해서만 예제 형식으로 기록한다.  
해당 예제 파일은 아래 링크에서 확인 가능하다.  
https://github.com/ruo91/openshift4-isms

##  1. Redhat CoreOS 설정
RedHat CoreOS는 RHEL 8.x 버전을 기준으로 Container에 특화된 OS로써,  
파일 및 디렉토리 권한은 Read Only 시스템이 기본이다.

즉, 사용자가 RHCOS를 직접 개입하여 관리하지 않아도 되는 시스템이며,
OpenShift에서 Machine Config라는 기능을 사용하여 자동 관리가 되는 시스템이기 때문이다.

따라서, 기존 Legacy 시스템과 동일하게 생각하면 안된다.

그 이유는 다음과 같다.  
- SSH 접근  
  core 사용자를 통해 ssh key 기반의 접근만 허용 한다.  
  root 사용자를 허용하지 않으며, core 사용자로 root 계정에 스위칭하여 접근해야 한다.  


- 3rd party 소프트웨어  
  RHCOS는 제 3자 소프트웨어를 설치 할 수가 없다.  
  Container만을 위한 OS이므로, Package Manager가 없기 때문이며,  
  굳이 설치하겠다면, 3rd party 소프트웨어 제조회사가 직접 만들고,  
  Container 형태로 만들어 OpenShift 환경에 맞도록 배포해야 한다.  


- 설정 파일  
  최고 관리자 계정인 root 권한으로 파일이 설정 되어있으며,  
  OpenShift Machine Config 기능을 사용하여 파일에 대해 덮어쓰기(overwrite)해야 가능하다.  
  이 부분에 대해서는 OpenShift 엔지니어가 개입되어 고객과 협의 후 설정이 필요하다.  
  다만, RedHat 지원 범위를 넘어서는 부분에 대해서는 지원이 되지 않을 수 있다.


## 2. 설정 파일 디렉토리 생성
변경 되지 않은 RHCOS의 설정 파일을 복사할 디렉토리를 생성한다.

    [root@bastion ~]# mkdir -p /opt/isms/etc/{ssh,pam.d,security}

## 3. 패스워드 복잡성 설정 (U-02)
패스워드 복잡성 관련하여 비인가자의 공격에 대비하기 위한 설정이다.  
해당 내용은 KISA 가이드 21p~26p에서 확인 가능하다.

### 3.1. 설정 파일 복사
RHCOS에서 설정 파일을 복사 해온다.

    [root@bastion ~]# ssh core@master01 "cat /etc/login.defs" > /opt/isms/etc/login.defs
    [root@bastion ~]# ssh core@master01 "cat /etc/security/pwquality.conf" > /opt/isms/etc/security/pwquality.conf

### 3.2. 설정 파일 수정
#### 3.2.1. login.defs
패스워드 최대, 최소, 문자길이, 만료 경고 기간을 설정[(Link 2)](https://github.com/ruo91/openshift4-isms/blob/main/etc/login.defs#L25-L28) 한다.

    [root@bastion ~]# vi /opt/isms/etc/login.defs
    # Password aging controls:
    #
    #       PASS_MAX_DAYS   Maximum number of days a password may be used.
    #       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
    #       PASS_MIN_LEN    Minimum acceptable password length.
    #       PASS_WARN_AGE   Number of days warning given before a password expires.
    #
    PASS_MAX_DAYS   90
    PASS_MIN_DAYS   7
    PASS_MIN_LEN    15
    PASS_WARN_AGE   7

#### 3.2.2. pwquality.conf
패스워드 생성시 최소한의 숫자, 대소문자, 특수문자, 재시도 횟수에 대한 요구사항[(Link 3)](https://github.com/ruo91/openshift4-isms/blob/main/etc/security/pwquality.conf#L4-L36)을 설정한다.

    [root@bastion ~]# vi /opt/isms/etc/security/pwquality.conf
    # Number of characters in the new password that must not be present in the
    # old password.
    # difok = 1
    difok = 10
    
    # Minimum acceptable size for the new password (plus one if
    # credits are not disabled which is the default). (See pam_cracklib manual.)
    # Cannot be set to lower value than 6.
    # minlen = 8
    minlen = 15
    
    # The maximum credit for having digits in the new password. If less than 0
    # it is the minimum number of digits in the new password.
    # dcredit = 0
    dcredit = -1
    
    # The maximum credit for having uppercase characters in the new password.
    # If less than 0 it is the minimum number of uppercase characters in the new
    # password.
    # ucredit = 0
    ucredit = -1
    
    # The maximum credit for having lowercase characters in the new password.
    # If less than 0 it is the minimum number of lowercase characters in the new
    # password.
    # lcredit = 0
    lcredit = -1
    
    # The maximum credit for having other characters in the new password.
    # If less than 0 it is the minimum number of other characters in the new
    # password.
    # ocredit = 0
    ocredit = -1

## 4. 계정 잠금 임계값 설정 (U-03)
시스템 정책에 사용자 로그인 실패 임계값을 설정하여, 비인가자의 brute-force attack에 대한 방어 설정이다.  
즉, 특정 계정에 대해 패스워드를 임계값 이상 실패하면 계정 잠금 설정이 되도록 한다.

해당 내용은 KISA 가이드 27p~29p에서 확인 가능하다.

### 4.1. 설정 파일 복사

    [root@bastion ~]# ssh core@master01 "cat /etc/pam.d/system-auth" > /opt/isms/etc/pam.d/system-auth
    [root@bastion ~]# ssh core@master01 "cat /etc/pam.d/password-auth" > /opt/isms/etc/pam.d/password-auth

### 4.2. 설정 파일 수정
해당 설정은 PAM(Pluggable Authentication Modules)을 수정하는 부분이며, 라인에 유의하여 추가/수정 한다.

#### 4.2.1. system-auth [(Link 4)](https://github.com/ruo91/openshift4-isms/blob/main/etc/pam.d/system-auth#L2),[(Link 5)](https://github.com/ruo91/openshift4-isms/blob/main/etc/pam.d/system-auth#L8-L9),[(Link6)](https://github.com/ruo91/openshift4-isms/blob/main/etc/pam.d/system-auth#L21-L22)

    [root@bastion ~]# vi /opt/isms/etc/pam.d/system-auth
    auth        required                                     pam_env.so
    auth        required                                     pam_faillock.so preauth silent audit deny=5 unlock_time=900
    auth        [success=1 default=bad]                      pam_unix.so
    auth        required                                     pam_faildelay.so delay=2000000
    auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet
    auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
    auth        sufficient                                   pam_unix.so nullok try_first_pass
    auth        [default=die]                                pam_faillock.so authfail audit deny=5 unlock_time=900
    auth        sufficient                                   pam_faillock.so authsucc audit deny=5 unlock_time=900
    auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success
    auth        sufficient                                   pam_sss.so forward_pass
    auth        required                                     pam_deny.so
    
    account     required                                     pam_unix.so
    account     sufficient                                   pam_localuser.so
    account     sufficient                                   pam_succeed_if.so uid < 1000 quiet
    account     [default=bad success=ok user_unknown=ignore] pam_sss.so
    account     required                                     pam_permit.so
    account     required                                     pam_faillock.so
    
    password    requisite                                    pam_pwquality.so try_first_pass local_users_only retry=3
    password    sufficient                                   pam_unix.so sha512 shadow try_first_pass use_authtok remember=15
    password    sufficient                                   pam_sss.so use_authtok
    password    required                                     pam_deny.so
    
    session     optional                                     pam_keyinit.so revoke
    session     required                                     pam_limits.so
    -session    optional                                     pam_systemd.so
    session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
    session     required                                     pam_unix.so
    session     optional                                     pam_sss.so

#### 4.2.2. password-auth [(Link 7)](https://github.com/ruo91/openshift4-isms/blob/main/etc/pam.d/password-auth#L2),[(Link 8)](https://github.com/ruo91/openshift4-isms/blob/main/etc/pam.d/password-auth#L8-L9),[(Link 9)](https://github.com/ruo91/openshift4-isms/blob/main/etc/pam.d/password-auth#L21-L22)

    [root@bastion ~]# vi /opt/isms/etc/pam.d/password-auth
    auth        required                                     pam_env.so
    auth        required                                     pam_faillock.so preauth silent audit deny=5 unlock_time=900
    auth        [success=1 default=bad]                      pam_unix.so
    auth        required                                     pam_faildelay.so delay=2000000
    auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet
    auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
    auth        sufficient                                   pam_unix.so nullok try_first_pass
    auth        [default=die]                                pam_faillock.so authfail audit deny=5 unlock_time=900
    auth        sufficient                                   pam_faillock.so authsucc audit deny=5 unlock_time=900
    auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success
    auth        sufficient                                   pam_sss.so forward_pass
    auth        required                                     pam_deny.so
    
    account     required                                     pam_unix.so
    account     sufficient                                   pam_localuser.so
    account     sufficient                                   pam_succeed_if.so uid < 1000 quiet
    account     [default=bad success=ok user_unknown=ignore] pam_sss.so
    account     required                                     pam_permit.so
    account     required                                     pam_faillock.so
    
    password    requisite                                    pam_pwquality.so try_first_pass local_users_only retry=3
    password    sufficient                                   pam_unix.so sha512 shadow try_first_pass use_authtok remember=15
    password    sufficient                                   pam_sss.so use_authtok
    password    required                                     pam_deny.so
    
    session     optional                                     pam_keyinit.so revoke
    session     required                                     pam_limits.so
    -session    optional                                     pam_systemd.so
    session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
    session     required                                     pam_unix.so
    session     optional                                     pam_sss.so

## 5. root 계정 su 제한 (U-45)
su(substitute user or switch user) 권한을 가진 계정에서만 사용 가능하도록 비활성화 한다.  
이는 비인가자가 brute-force attack 또는 패스워드 추측 공격을 통해 계정을 탈취 후  
최고관리자 계정(root)를 유출 할 가능성을 배제 시키기 위함이다.

해당 내용은 KISA 가이드 103p~105p에서 확인 가능하다.

### 5.1. 설정 파일 복사

    [root@bastion ~]# ssh core@master01 "cat /etc/pam.d/su" > /opt/isms/etc/pam.d/su

### 5.2. 설정 파일 수정
해당 설정은 PAM(Pluggable Authentication Modules)을 수정하는 부분이며,
해당 라인[(Link 10)](https://github.com/ruo91/openshift4-isms/blob/main/etc/pam.d/su#L7)에 주석만 해제 한다.

    [root@bastion ~]# vi /opt/isms/etc/pam.d/su
    - before
    #auth            required        pam_wheel.so use_uid
    
    - after
    auth            required        pam_wheel.so use_uid

## 6. Session Timeout 설정 (U-54)
Sesstion Timeout 값이 설정되지 않은 경우 유휴 시간 내 비인가자가 시스템에 접근이 가능하기 때문에,  
이를 막기 위함이다.

해당 내용은 KISA 가이드 121p에서 확인 가능하다.

### 6.1. 설정 파일 복사
#### - sh(born shell), ksh(korn shell), bash(born again shell)

    [root@bastion ~]# ssh core@master01 "cat /etc/profile" > /opt/isms/etc/profile

#### - csh(C shell)

    [root@bastion ~]# ssh core@master01 "cat /etc/csh.login" > /opt/isms/etc/csh.login

### 6.2. 설정 파일 수정
Timeout 변수를 설정한다.
#### - sh(born shell), ksh(korn shell), bash(born again shell)
해당 내용에 TMOUT 변수를 추가 [(Link 11)](https://github.com/ruo91/openshift4-isms/blob/main/etc/profile#L48), [(Link 12)](https://github.com/ruo91/openshift4-isms/blob/main/etc/profile#L55)한다. 초(second) 단위 이다.

    [root@bastion ~]# vi /opt/isms/etc/profile
    HOSTNAME=`/usr/bin/hostname 2>/dev/null`
    HISTSIZE=1000
    HISTTIMEFORMAT="%F %T "
    TMOUT=300
    if [ "ignoredups" = "ignorespace" ] ; then
        export HISTCONTROL=ignoreboth
    else
        export HISTCONTROL=ignoredups
    fi
    
    export PATH USER LOGNAME MAIL HOSTNAME HISTSIZE HISTCONTROL HISTTIMEFORMAT TMOUT

#### - csh(C shell)
해당 내용에 set autologout=5를 추가[(Link 13)](https://github.com/ruo91/openshift4-isms/blob/main/etc/csh.login#L30) 한다. 분(minute) 단위이다.

    [root@bastion ~]# vi /opt/isms/etc/csh.login
    setenv HOSTNAME `/usr/bin/hostname`
    set history=1000
    set autologout=5

## 7. 로그인시 경고 메세지 제공 (U-69)
비인가자들에게 서버에 대한 불필요한 정보를 제공하지 않고,  
서버 접속시 관계자만 접속해야 한다는 경각심을 심어 주기위해 경고 메세지 설정을 한다.

해당 내용은 KISA 가이드 145p~147p에서 확인 가능하다.

### 7.1. 설정 파일 복사

    [root@bastion ~]# ssh core@master01 "cat /etc/ssh/sshd_config" > /opt/isms/etc/ssh/sshd_config

### 7.2. 설정 파일 수정
issue, motd 설정 파일은 따로 복사할 필요는 없으므로, 직접 생성한다.

#### - issue

    [root@bastion ~]# vi /opt/isms/etc/issue
    ##################################################################
    #   WARNNING!!   WARNNING!!   WARNNING!!                         #
    #                                                                #
    # Please Log-out IMMEDIATELY if you are NOT authorized to USE!!  #
    # This is authorized use ONLY!!!                                 #
    #                                                                #
    ##################################################################

#### - motd

    [root@bastion ~]# vi /opt/isms/etc/motd
    Warnning!! This system is not available to unauthorized users.

#### - sshd_config
해당 내용에서 Banner 부분을 주석 해제 한다.

    [root@bastion ~]# vi /opt/isms/etc/ssh/sshd_config
    - before
    #Banner /etc/issue
    
    - after
    Banner /etc/issue


## 8. Machine Config 설정
3~7번까지 생성한 파일들을 OpenShift의 Machine Config에 추가하려면  
해당 파일의 내용을 Base64로 인코딩하여 데이터를 삽입해야 한다.

그 이유는 Kubernetes 환경에서는 민감한 정보를 Basd64로 인코딩하여 관리하기 때문이다.
https://github.com/kubernetes/community/blob/master/contributors/design-proposals/auth/secrets.md

### 8.1. Base64 인코딩
설정한 파일이 많기 때문에, 예제로 /opt/isms/etc/motd 파일 기준으로 인코딩을 한다.

#### - before

    [root@bastion ~]# cat /opt/isms/etc/motd
    Warnning!! This system is not available to unauthorized users.

#### - after

    [root@bastion ~]# cat /opt/isms/etc/motd | base64 | awk '{printf $1}'
    V2Fybm5pbmchISBUaGlzIHN5c3RlbSBpcyBub3QgYXZhaWxhYmxlIHRvIHVuYXV0aG9yaXplZCB1c2Vycy4K

인코딩 된 내용이 무결성인 것을 확인 하려면 아래와 같이 디코딩을 통해 확인할 수 있다.

#### - base64 decode

    [root@bastion ~]# echo 'V2Fybm5pbmchISBUaGlzIHN5c3RlbSBpcyBub3QgYXZhaWxhYmxlIHRvIHVuYXV0aG9yaXplZCB1c2Vycy4K' | base64 -d
    Warnning!! This system is not available to unauthorized users.

### 8.2. Machine Config YAML 작성
OpenShift v4.x 버전부터 사용할 수 있는 machine config 파일을 생성한다.

#### - Control Plane Nodes

    [root@bastion ~]# vi /opt/isms/99-master-isms-machine-config.yaml
    apiVersion: machineconfiguration.openshift.io/v1
    kind: MachineConfig
    metadata:
      labels:
        machineconfiguration.openshift.io/role: master
      name: 99-master-etc-motd
    spec:
      config:
        ignition:
          version: 3.1.0
        storage:
          files:
          - contents:
              source: data:text/plain;charset=utf-8;base64,V2Fybm5pbmchISBUaGlzIHN5c3RlbSBpcyBub3QgYXZhaWxhYmxlIHRvIHVuYXV0aG9yaXplZCB1c2Vycy4K
            mode: 420
            overwrite: true
            filesystem: root
            path: /etc/motd

#### - Worker Nodes

    [root@bastion ~]# vi /opt/isms/99-worker-isms-machine-config.yaml
    apiVersion: machineconfiguration.openshift.io/v1
    kind: MachineConfig
    metadata:
      labels:
        machineconfiguration.openshift.io/role: worker
      name: 99-worker-etc-motd
    spec:
      config:
        ignition:
          version: 3.1.0
        storage:
          files:
          - contents:
              source: data:text/plain;charset=utf-8;base64,V2Fybm5pbmchISBUaGlzIHN5c3RlbSBpcyBub3QgYXZhaWxhYmxlIHRvIHVuYXV0aG9yaXplZCB1c2Vycy4K
            mode: 420
            overwrite: true
            filesystem: root
            path: /etc/motd

### 8.3. Machine Config 생성
수초 이내 Machine Config Operator가 생성 된 Machine Config 파일을 감지하여,  
Machine Config Pool에 자동 등록 후 클러스터 노드에 반영하기 위해 Rolling 방식으로 하나씩 재부팅을 한다.

    [root@bastion ~]# oc create -f /opt/isms/99-master-isms-machine-config.yaml
    [root@bastion ~]# oc create -f /opt/isms/99-worker-isms-machine-config.yaml

## 9. 설정 확인
RHCOS 노드에 SSH 접속하여 설정 확인을 한다.

### 9.1. SSH 접속 및 로그인 경고 메세지
/etc/issue, /etc/motd 수정 사항이 반영 되었다.

    [root@bastion ~]# ssh core@master01
    ##################################################################
    #   WARNNING!!   WARNNING!!   WARNNING!!                         #
    #                                                                #
    # Please Log-out IMMEDIATELY if you are NOT authorized to USE!!  #
    # This is authorized use ONLY!!!                                 #
    #                                                                #
    ##################################################################
    Warnning!! This system is not available to unauthorized users.
    Last login: Fri Feb 26 16:44:09 2021 from 7.7.7.2
    Warnning!! This system is not available to unauthorized users.
    [core@master01 ~]$

### 9.2. 계정 로그인 실패 테스트
일반 계정을 하나 생성 후 의도적으로 패스워드를 잘못 입력하도록 한다.  
이후 su 권한으로 실패한 계정을 확인 후 복구 한다.

#### - 사용자 생성 및 패스워드 설정
    [core@master01 ~]$ sudo -i
    [root@master01 ~]# adduser ybkim
    [root@master01 ~]# echo 'ybkim123' | passwd --stdin ybkim
    [root@master01 ~]# exit
    [core@master01 ~]$ exit

#### - 잘못된 패스워드로 계정 잠금 시도
총 5번 실패를 시도하여 계정이 잠기도록 한다.

    [root@bastion ~]# ssh ybkim@master01
    ybkim@master01's password:
    Permission denied, please try again.
    ybkim@master01's password:
    Permission denied, please try again.
    ybkim@master01's password:
    Permission denied, please try again.
    ybkim@master01's password:
    Permission denied, please try again.
    ybkim@master01's password:

#### - 잠금으로 설정된 계정 확인

    [root@bastion ~]# ssh core@master01
    [core@master01 ~]$ sudo -i
    [root@master01 ~]# faillock
    ybkim:
    When                Type  Source                                           Valid
    2021-02-26 21:32:14 RHOST 7.7.7.2                                              V
    2021-02-26 21:32:19 RHOST 7.7.7.2                                              V
    2021-02-26 21:32:26 RHOST 7.7.7.2                                              V
    2021-02-26 21:32:31 RHOST 7.7.7.2                                              V
    2021-02-26 21:33:05 RHOST 7.7.7.2                                              V

#### - 잠금 설정된 계정 초기화

    [root@master01 ~]# faillock --user ybkim --reset
    [root@master01 ~]# faillock
    ybkim:
    When                Type  Source                                           Valid

#### - 잠금 해제된 계정 접속 테스트
해당 계정으로 정상적으로 로그인 한다.

    [root@master01 ~]# exit
    [core@master01 ~]$ exit
    [root@bastion ~]# ssh ybkim@master01
    ##################################################################
    #   WARNNING!!   WARNNING!!   WARNNING!!                         #
    #                                                                #
    # Please Log-out IMMEDIATELY if you are NOT authorized to USE!!  #
    # This is authorized use ONLY!!!                                 #
    #                                                                #
    ##################################################################
    ybkim@master01's password:
    Warnning!! This system is not available to unauthorized users.
    Last failed login: Fri Feb 26 21:33:18 KST 2021 from 7.7.7.2 on ssh:notty
    There were 23 failed login attempts since the last successful login.
    Last login: Fri Feb 26 16:36:51 2021 from 7.7.7.2
    Warnning!! This system is not available to unauthorized users.

### 9.3. Session Timeout 테스트
유휴 시간내(300/sec) 이상 경과시 ssh session timeout이 정상 동작하는지 테스트 한다.

    [ybkim@master01 ~]$ timed out waiting for input: auto-logout
    Connection to master01 closed.

ISMS 기준에 맞게 설정이 모두 완료 되었다.
